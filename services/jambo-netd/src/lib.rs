//! Démon de pile réseau en espace utilisateur (jambo-netd, Ring 3, PID 5)
//!
//! Implémente la pile réseau minimale sans tas (`#![no_std]`, zéro allocation) :
//! - Ethernet II (EtherType 0x0806 ARP, 0x0800 IPv4)
//! - ARP (Address Resolution Protocol RFC 826)
//! - IPv4 (Internet Protocol RFC 791)
//! - ICMP (Internet Control Message Protocol RFC 792)
//! - Protocole IPC réseau (NetRequest, NetResponse, NetOpcode)
//! - Support des capacités réseau `NetworkCapability` (NetCap)

#![no_std]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::chunks_exact_to_as_chunks)]
#![allow(clippy::too_many_arguments)]

use jambo_abi::{Handle, SysError};
use virtio_drv::VirtioNetDriver;

// Constantes EtherType
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

// Constantes ARP
pub const ARP_HTYPE_ETHERNET: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_HLEN_ETHERNET: u8 = 6;
pub const ARP_PLEN_IPV4: u8 = 4;
pub const ARP_OPCODE_REQUEST: u16 = 1;
pub const ARP_OPCODE_REPLY: u16 = 2;

// Constantes Protocoles IP
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

// Constantes ICMP
pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_CODE_ECHO: u8 = 0;

// Configuration réseau par défaut sous QEMU SLIRP
pub const DEFAULT_IPV4: [u8; 4] = [10, 0, 2, 15];
pub const DEFAULT_NETMASK: [u8; 4] = [255, 255, 255, 0];
pub const DEFAULT_GATEWAY: [u8; 4] = [10, 0, 2, 2];
pub const DEFAULT_GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
pub const NETD_IPC_HANDLE: u64 = 5;

// =========================================================================
// Structures de paquets réseau (OASIS / RFC)
// =========================================================================

/// En-tête Ethernet II (14 octets)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

const _: () = assert!(core::mem::size_of::<EthernetHeader>() == 14);

impl EthernetHeader {
    pub const fn new(dst_mac: [u8; 6], src_mac: [u8; 6], ethertype: u16) -> Self {
        Self {
            dst_mac,
            src_mac,
            ethertype: ethertype.to_be(),
        }
    }

    #[inline]
    pub fn ethertype(&self) -> u16 {
        u16::from_be(self.ethertype)
    }

    pub fn to_bytes(&self) -> [u8; 14] {
        let mut bytes = [0u8; 14];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                14,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 14 {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Paquet ARP pour Ethernet et IPv4 (28 octets, RFC 826)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub opcode: u16,
    pub src_mac: [u8; 6],
    pub src_ip: [u8; 4],
    pub dst_mac: [u8; 6],
    pub dst_ip: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<ArpPacket>() == 28);

impl ArpPacket {
    pub const fn new_request(my_mac: [u8; 6], my_ip: [u8; 4], target_ip: [u8; 4]) -> Self {
        Self {
            htype: ARP_HTYPE_ETHERNET.to_be(),
            ptype: ARP_PTYPE_IPV4.to_be(),
            hlen: ARP_HLEN_ETHERNET,
            plen: ARP_PLEN_IPV4,
            opcode: ARP_OPCODE_REQUEST.to_be(),
            src_mac: my_mac,
            src_ip: my_ip,
            dst_mac: [0u8; 6],
            dst_ip: target_ip,
        }
    }

    pub const fn new_reply(
        my_mac: [u8; 6],
        my_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> Self {
        Self {
            htype: ARP_HTYPE_ETHERNET.to_be(),
            ptype: ARP_PTYPE_IPV4.to_be(),
            hlen: ARP_HLEN_ETHERNET,
            plen: ARP_PLEN_IPV4,
            opcode: ARP_OPCODE_REPLY.to_be(),
            src_mac: my_mac,
            src_ip: my_ip,
            dst_mac: target_mac,
            dst_ip: target_ip,
        }
    }

    #[inline]
    pub fn opcode(&self) -> u16 {
        u16::from_be(self.opcode)
    }

    #[inline]
    pub fn htype(&self) -> u16 {
        u16::from_be(self.htype)
    }

    #[inline]
    pub fn ptype(&self) -> u16 {
        u16::from_be(self.ptype)
    }

    pub fn to_bytes(&self) -> [u8; 28] {
        let mut bytes = [0u8; 28];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                28,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 28 {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// En-tête IPv4 standard (20 octets, RFC 791)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ipv4Header {
    pub ver_ihl: u8,
    pub tos: u8,
    pub len: u16,
    pub id: u16,
    pub flags_frag: u16,
    pub ttl: u8,
    pub proto: u8,
    pub checksum: u16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<Ipv4Header>() == 20);

impl Ipv4Header {
    pub fn new(proto: u8, src_ip: [u8; 4], dst_ip: [u8; 4], payload_len: u16) -> Self {
        let total_len = 20u16.saturating_add(payload_len);
        let mut hdr = Self {
            ver_ihl: 0x45, // Version 4, IHL 5 (5 * 4 = 20 octets)
            tos: 0,
            len: total_len.to_be(),
            id: 0,
            flags_frag: 0,
            ttl: 64,
            proto,
            checksum: 0,
            src_ip,
            dst_ip,
        };
        hdr.checksum = compute_ipv4_checksum(&hdr).to_be();
        hdr
    }

    #[inline]
    pub fn len(&self) -> u16 {
        u16::from_be(self.len)
    }

    #[inline]
    pub fn ihl_bytes(&self) -> usize {
        ((self.ver_ihl & 0x0F) as usize) * 4
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                20,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// En-tête ICMP (8 octets, RFC 792)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
}

const _: () = assert!(core::mem::size_of::<IcmpHeader>() == 8);

impl IcmpHeader {
    pub fn new_echo_request(id: u16, seq: u16, payload: &[u8]) -> Self {
        let mut hdr = Self {
            icmp_type: ICMP_TYPE_ECHO_REQUEST,
            code: ICMP_CODE_ECHO,
            checksum: 0,
            id: id.to_be(),
            seq: seq.to_be(),
        };
        hdr.checksum = compute_icmp_checksum(&hdr, payload).to_be();
        hdr
    }

    pub fn new_echo_reply(id: u16, seq: u16, payload: &[u8]) -> Self {
        let mut hdr = Self {
            icmp_type: ICMP_TYPE_ECHO_REPLY,
            code: ICMP_CODE_ECHO,
            checksum: 0,
            id: id.to_be(),
            seq: seq.to_be(),
        };
        hdr.checksum = compute_icmp_checksum(&hdr, payload).to_be();
        hdr
    }

    #[inline]
    pub fn id(&self) -> u16 {
        u16::from_be(self.id)
    }

    #[inline]
    pub fn seq(&self) -> u16 {
        u16::from_be(self.seq)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const Self as *const u8, bytes.as_mut_ptr(), 8);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

// =========================================================================
// Fonctions utilitaires de calcul de sommes de contrôle (RFC 1071)
// =========================================================================

/// Calcule la somme de contrôle standard (complément à un) selon la RFC 1071.
/// Retourne la valeur 16 bits en ordre machine.
pub fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(word as u32);
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let word = (remainder[0] as u32) << 8;
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Calcule la somme de contrôle de l'en-tête IPv4 (champ `checksum` fixé à 0).
pub fn compute_ipv4_checksum(header: &Ipv4Header) -> u16 {
    let mut hdr = *header;
    hdr.checksum = 0;
    let bytes = hdr.to_bytes();
    compute_checksum(&bytes)
}

/// Vérifie si la somme de contrôle d'un en-tête IPv4 reçu est valide (somme = 0).
pub fn verify_ipv4_checksum(header: &Ipv4Header) -> bool {
    let bytes = header.to_bytes();
    compute_checksum(&bytes) == 0
}

/// Calcule la somme de contrôle d'un message ICMP (en-tête + charge utile).
pub fn compute_icmp_checksum(header: &IcmpHeader, payload: &[u8]) -> u16 {
    let mut hdr = *header;
    hdr.checksum = 0;
    let hdr_bytes = hdr.to_bytes();

    let mut sum: u32 = 0;
    let mut chunks = hdr_bytes.chunks_exact(2);
    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(word as u32);
    }
    let mut payload_chunks = payload.chunks_exact(2);
    for chunk in &mut payload_chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(word as u32);
    }
    let remainder = payload_chunks.remainder();
    if !remainder.is_empty() {
        let word = (remainder[0] as u32) << 8;
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Vérifie si la somme de contrôle ICMP d'un paquet reçu est valide.
pub fn verify_icmp_checksum(header: &IcmpHeader, payload: &[u8]) -> bool {
    compute_icmp_checksum(header, payload) == u16::from_be(header.checksum)
}

// =========================================================================
// Forges de trames Ethernet (ARP & ICMP)
// =========================================================================

/// Construit une trame ARP Reply complète dans le tampon fourni (minimum 42 octets, complété à 60).
pub fn forge_arp_reply(
    my_mac: [u8; 6],
    my_ip: [u8; 4],
    req: &ArpPacket,
    out_frame: &mut [u8],
) -> Option<usize> {
    if out_frame.len() < 60 {
        return None;
    }
    // Remise à zéro pour le rembourrage Ethernet minimum (60 octets sans FCS)
    out_frame[..60].fill(0);

    let eth = EthernetHeader::new(req.src_mac, my_mac, ETHERTYPE_ARP);
    let reply = ArpPacket::new_reply(my_mac, my_ip, req.src_mac, req.src_ip);

    out_frame[..14].copy_from_slice(&eth.to_bytes());
    out_frame[14..42].copy_from_slice(&reply.to_bytes());

    Some(60)
}

/// Construit une trame ICMP Echo Reply en réponse à un Echo Request.
pub fn forge_icmp_echo_reply(
    my_mac: [u8; 6],
    my_ip: [u8; 4],
    req_eth: &EthernetHeader,
    req_ip: &Ipv4Header,
    req_icmp: &IcmpHeader,
    icmp_payload: &[u8],
    out_frame: &mut [u8],
) -> Option<usize> {
    let total_len = 14 + 20 + 8 + icmp_payload.len();
    if out_frame.len() < total_len {
        return None;
    }

    let eth = EthernetHeader::new(req_eth.src_mac, my_mac, ETHERTYPE_IPV4);
    let mut ip = Ipv4Header {
        ver_ihl: 0x45,
        tos: 0,
        len: ((20 + 8 + icmp_payload.len()) as u16).to_be(),
        id: req_ip.id,
        flags_frag: 0,
        ttl: 64,
        proto: IP_PROTO_ICMP,
        checksum: 0,
        src_ip: my_ip,
        dst_ip: req_ip.src_ip,
    };
    ip.checksum = compute_ipv4_checksum(&ip).to_be();

    let mut icmp = IcmpHeader {
        icmp_type: ICMP_TYPE_ECHO_REPLY,
        code: ICMP_CODE_ECHO,
        checksum: 0,
        id: req_icmp.id,
        seq: req_icmp.seq,
    };
    icmp.checksum = compute_icmp_checksum(&icmp, icmp_payload).to_be();

    out_frame[..14].copy_from_slice(&eth.to_bytes());
    out_frame[14..34].copy_from_slice(&ip.to_bytes());
    out_frame[34..42].copy_from_slice(&icmp.to_bytes());
    if !icmp_payload.is_empty() {
        out_frame[42..total_len].copy_from_slice(icmp_payload);
    }

    Some(total_len)
}

/// Construit une trame ICMP Echo Request vers une adresse IPv4 cible.
pub fn forge_icmp_echo_request(
    my_mac: [u8; 6],
    my_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    id: u16,
    seq: u16,
    payload: &[u8],
    out_frame: &mut [u8],
) -> Option<usize> {
    let total_len = 14 + 20 + 8 + payload.len();
    if out_frame.len() < total_len {
        return None;
    }

    let eth = EthernetHeader::new(dst_mac, my_mac, ETHERTYPE_IPV4);
    let mut ip = Ipv4Header {
        ver_ihl: 0x45,
        tos: 0,
        len: ((20 + 8 + payload.len()) as u16).to_be(),
        id: seq.to_be(),
        flags_frag: 0,
        ttl: 64,
        proto: IP_PROTO_ICMP,
        checksum: 0,
        src_ip: my_ip,
        dst_ip,
    };
    ip.checksum = compute_ipv4_checksum(&ip).to_be();

    let icmp = IcmpHeader::new_echo_request(id, seq, payload);

    out_frame[..14].copy_from_slice(&eth.to_bytes());
    out_frame[14..34].copy_from_slice(&ip.to_bytes());
    out_frame[34..42].copy_from_slice(&icmp.to_bytes());
    if !payload.is_empty() {
        out_frame[42..total_len].copy_from_slice(payload);
    }

    Some(total_len)
}

// =========================================================================
// Protocole IPC Réseau (NetRequest, NetResponse, NetOpcode)
// =========================================================================

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

/// Message IPC hybride échangé sur les canaux de communication
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [Handle; MAX_HANDLES],
    pub handle_count: usize,
}

impl Default for ChannelMessage {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
            handles: [Handle::NULL; MAX_HANDLES],
            handle_count: 0,
        }
    }
}

/// Opcodes d'opérations IPC pour le service réseau
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetOpcode {
    GetInfo = 1,
    SendPing = 2,
    PollRx = 3,
    ReloadBpfFilter = 4,
    GetFilterStats = 5,
}

/// Requête IPC transmise à `jambo-netd`
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetRequest {
    pub opcode: u32,
    pub target_ip: [u8; 4],
    pub payload_len: u32,
    pub payload: [u8; 64],
}

const _: () = assert!(core::mem::size_of::<NetRequest>() == 76);

impl NetRequest {
    pub const fn new(opcode: NetOpcode, target_ip: [u8; 4]) -> Self {
        Self {
            opcode: opcode as u32,
            target_ip,
            payload_len: 0,
            payload: [0u8; 64],
        }
    }

    pub fn to_bytes(&self) -> [u8; 76] {
        let mut bytes = [0u8; 76];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                76,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let opcode = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let target_ip = [bytes[4], bytes[5], bytes[6], bytes[7]];
        let payload_len = u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let mut payload = [0u8; 64];
        if bytes.len() > 12 {
            let copy_len = (bytes.len() - 12).min(64);
            payload[..copy_len].copy_from_slice(&bytes[12..12 + copy_len]);
        }
        Some(Self {
            opcode,
            target_ip,
            payload_len,
            payload,
        })
    }
}

/// Réponse IPC retournée par `jambo-netd` (40 octets, s'insère dans Fastpath 64 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetResponse {
    pub status: u32,
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub rtt_ms: u32,
}

const _: () = assert!(core::mem::size_of::<NetResponse>() == 40);

impl NetResponse {
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                40,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 40 {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Client IPC réseau léger pour les applications en espace utilisateur (`jsh`, etc.)
pub struct NetClient {
    pub endpoint: Handle,
}

impl NetClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    /// Récupère la configuration et les compteurs statistiques de l'interface
    pub fn get_info(&self) -> Result<NetResponse, SysError> {
        let req = NetRequest::new(NetOpcode::GetInfo, [0, 0, 0, 0]);
        self.call(&req)
    }

    /// Émet une requête ICMP Ping vers l'adresse IP cible
    pub fn ping(&self, target_ip: [u8; 4]) -> Result<NetResponse, SysError> {
        let req = NetRequest::new(NetOpcode::SendPing, target_ip);
        self.call(&req)
    }

    fn call(&self, req: &NetRequest) -> Result<NetResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

        // 1. Émission de la requête sur le canal IPC
        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.endpoint.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };

        if ret_send != 0 {
            return Err(SysError::InvalidHandle);
        }

        // 2. Attente active coopérative de la réponse
        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        while attempts < 100 {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.endpoint.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<NetResponse>() {
                return NetResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

// =========================================================================
// Capacités Réseau & Sockets (Modèle de Sécurité JamboOS)
// =========================================================================

pub const TCP_FLAG_FIN: u16 = 1 << 0;
pub const TCP_FLAG_SYN: u16 = 1 << 1;
pub const TCP_FLAG_RST: u16 = 1 << 2;
pub const TCP_FLAG_PSH: u16 = 1 << 3;
pub const TCP_FLAG_ACK: u16 = 1 << 4;
pub const TCP_FLAG_URG: u16 = 1 << 5;

/// Capacité réseau sécurisée accordée à un processus
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkCapability {
    pub handle: Handle,
    pub rights: u32,
    pub min_port: u16,
    pub max_port: u16,
    pub allow_all_ips: bool,
}

impl NetworkCapability {
    pub const fn new(handle: Handle, rights: u32, min_port: u16, max_port: u16) -> Self {
        Self {
            handle,
            rights,
            min_port,
            max_port,
            allow_all_ips: true,
        }
    }

    pub fn verify_access(&self, required_right: u32, port: u16) -> Result<(), SysError> {
        if (self.rights & required_right) == 0 {
            return Err(SysError::PermissionDenied);
        }
        if port != 0 && (port < self.min_port || port > self.max_port) {
            return Err(SysError::PermissionDenied);
        }
        Ok(())
    }
}

/// État de connexion TCP (RFC 9293)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Socket TCP géré par le démon réseau
#[derive(Debug, Clone, Copy)]
pub struct TcpSocket {
    pub local_port: u16,
    pub remote_port: u16,
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub state: TcpState,
    pub seq_num: u32,
    pub ack_num: u32,
}

impl TcpSocket {
    pub const fn new(local_port: u16) -> Self {
        Self {
            local_port,
            remote_port: 0,
            local_ip: DEFAULT_IPV4,
            remote_ip: [0, 0, 0, 0],
            state: TcpState::Closed,
            seq_num: 1000,
            ack_num: 0,
        }
    }
}

/// Cède volontairement le temps processeur au scheduler JamboKernel
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

/// Pile réseau principale en espace utilisateur
pub struct JamboNetd {
    pub net_driver: VirtioNetDriver,
    pub ipv4_addr: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway_ip: [u8; 4],
    pub sockets: [Option<TcpSocket>; 16],
}

impl Default for JamboNetd {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboNetd {
    pub const fn new() -> Self {
        const INIT_OPT: Option<TcpSocket> = None;
        Self {
            net_driver: VirtioNetDriver::new(0, 0, 0, 0),
            ipv4_addr: DEFAULT_IPV4,
            netmask: DEFAULT_NETMASK,
            gateway_ip: DEFAULT_GATEWAY,
            sockets: [INIT_OPT; 16],
        }
    }

    pub fn ip_config(&self) -> ([u8; 4], [u8; 6], [u8; 4]) {
        (self.ipv4_addr, self.net_driver.mac_address, self.gateway_ip)
    }

    pub fn active_sockets(&self) -> usize {
        self.sockets.iter().filter(|s| s.is_some()).count()
    }
}

// =========================================================================
// En-tête UDP & Gestion des Datagrammes (RFC 768)
// =========================================================================

/// En-tête UDP standard (RFC 768 - 8 octets)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

const _: () = assert!(core::mem::size_of::<UdpHeader>() == 8);

impl UdpHeader {
    pub const fn new(src_port: u16, dst_port: u16, payload_len: usize) -> Self {
        Self {
            src_port: src_port.to_be(),
            dst_port: dst_port.to_be(),
            length: ((8 + payload_len) as u16).to_be(),
            checksum: 0,
        }
    }

    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.src_port)
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.dst_port)
    }

    #[inline]
    pub fn length(&self) -> u16 {
        u16::from_be(self.length)
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be(self.checksum)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const Self as *const u8, bytes.as_mut_ptr(), 8);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Calcule la somme de contrôle UDP RFC 768 avec le pseudo-en-tête IPv4
pub fn compute_udp_checksum(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    udp_hdr: &UdpHeader,
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-en-tête IPv4 (12 octets)
    for chunk in src_ip.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst_ip.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += IP_PROTO_UDP as u32; // zero (8b) + protocol (8b)
    sum += udp_hdr.length() as u32; // UDP length

    // En-tête UDP (sans le champ checksum)
    sum += udp_hdr.src_port() as u32;
    sum += udp_hdr.dst_port() as u32;
    sum += udp_hdr.length() as u32;

    // Données de charge utile UDP
    let mut chunks = payload.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u16::from_be_bytes([last, 0]) as u32;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let inverted = !(sum as u16);
    if inverted == 0 {
        0xFFFF // RFC 768: une somme nulle est transmise comme 0xFFFF
    } else {
        inverted
    }
}

/// Forge une trame Ethernet/IPv4/UDP complète prête à être émise
pub fn forge_udp_packet(
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    out_buf: &mut [u8],
) -> Option<usize> {
    let total_len = 14 + 20 + 8 + payload.len();
    if out_buf.len() < total_len {
        return None;
    }

    let eth = EthernetHeader::new(dst_mac, src_mac, ETHERTYPE_IPV4);
    let ip = Ipv4Header::new(IP_PROTO_UDP, src_ip, dst_ip, (8 + payload.len()) as u16);
    let mut udp = UdpHeader::new(src_port, dst_port, payload.len());
    let csum = compute_udp_checksum(src_ip, dst_ip, &udp, payload);
    udp.checksum = csum.to_be();

    out_buf[..14].copy_from_slice(&eth.to_bytes());
    out_buf[14..34].copy_from_slice(&ip.to_bytes());
    out_buf[34..42].copy_from_slice(&udp.to_bytes());
    out_buf[42..total_len].copy_from_slice(payload);

    Some(total_len)
}

// =========================================================================
// Gestionnaire de Sockets Réseau Ring 3
// =========================================================================

/// Type de protocole de transport pour la socket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    Tcp,
    Udp,
    Raw,
}

/// État d'une socket gérée dans la table du démon réseau
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedSocket {
    pub protocol: SocketProtocol,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub is_bound: bool,
    pub is_connected: bool,
    pub is_listening: bool,
}

/// Gestionnaire de table de sockets sans allocation (#![no_std])
pub struct SocketTable {
    pub sockets: [Option<ManagedSocket>; 16],
    next_ephemeral: u16,
}

impl Default for SocketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketTable {
    pub const fn new() -> Self {
        const INIT_OPT: Option<ManagedSocket> = None;
        Self {
            sockets: [INIT_OPT; 16],
            next_ephemeral: 49152,
        }
    }

    /// Alloue un nouvel emplacement de socket
    pub fn alloc_socket(&mut self, protocol: SocketProtocol) -> Result<usize, SysError> {
        for (i, slot) in self.sockets.iter_mut().enumerate() {
            if slot.is_none() {
                let sock = ManagedSocket {
                    protocol,
                    local_port: 0,
                    remote_port: 0,
                    local_ip: DEFAULT_IPV4,
                    remote_ip: [0, 0, 0, 0],
                    is_bound: false,
                    is_connected: false,
                    is_listening: false,
                };
                *slot = Some(sock);
                return Ok(i);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Lie la socket à une adresse et un port local (bind)
    pub fn bind(&mut self, id: usize, ip: [u8; 4], port: u16) -> Result<(), SysError> {
        if id >= 16 {
            return Err(SysError::InvalidArgument);
        }
        let protocol = self.sockets[id]
            .as_ref()
            .ok_or(SysError::InvalidArgument)?
            .protocol;

        let allocated_port = if port == 0 {
            let ephem = self.next_ephemeral;
            self.next_ephemeral = if ephem == 65535 { 49152 } else { ephem + 1 };
            ephem
        } else {
            // Vérifie l'absence de conflit de port
            for (i, other) in self.sockets.iter().enumerate() {
                if i != id {
                    if let Some(s) = other {
                        if s.is_bound && s.local_port == port && s.protocol == protocol {
                            return Err(SysError::ResourceBusy);
                        }
                    }
                }
            }
            port
        };

        let sock = self.sockets[id].as_mut().ok_or(SysError::InvalidArgument)?;
        sock.local_ip = ip;
        sock.local_port = allocated_port;
        sock.is_bound = true;
        Ok(())
    }

    /// Connecte la socket à une adresse distante
    pub fn connect(
        &mut self,
        id: usize,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Result<(), SysError> {
        if id >= 16 {
            return Err(SysError::InvalidArgument);
        }
        let sock = self.sockets[id].as_mut().ok_or(SysError::InvalidArgument)?;

        if !sock.is_bound {
            let ephem = self.next_ephemeral;
            self.next_ephemeral = if ephem == 65535 { 49152 } else { ephem + 1 };
            sock.local_port = ephem;
            sock.is_bound = true;
        }

        sock.remote_ip = remote_ip;
        sock.remote_port = remote_port;
        sock.is_connected = true;
        Ok(())
    }

    /// Ferme la socket et libère son emplacement
    pub fn close(&mut self, id: usize) -> Result<(), SysError> {
        if id >= 16 {
            return Err(SysError::InvalidArgument);
        }
        if self.sockets[id].is_none() {
            return Err(SysError::InvalidArgument);
        }
        self.sockets[id] = None;
        Ok(())
    }

    /// Récupère la socket par son index
    pub fn get(&self, id: usize) -> Option<&ManagedSocket> {
        if id < 16 {
            self.sockets[id].as_ref()
        } else {
            None
        }
    }

    /// Recherche une socket par son port d'écoute et son protocole
    pub fn find_by_port(&self, port: u16, protocol: SocketProtocol) -> Option<usize> {
        for (i, slot) in self.sockets.iter().enumerate() {
            if let Some(sock) = slot {
                if sock.is_bound && sock.local_port == port && sock.protocol == protocol {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Recherche une socket UDP connectée correspondant exactement au 4-tuple (RFC 768)
    pub fn find_connected_udp(
        &self,
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Option<usize> {
        for (i, slot) in self.sockets.iter().enumerate() {
            if let Some(sock) = slot {
                if sock.is_bound
                    && sock.is_connected
                    && sock.protocol == SocketProtocol::Udp
                    && sock.local_port == local_port
                    && sock.remote_ip == remote_ip
                    && sock.remote_port == remote_port
                {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Résout la socket UDP destinataire d'un datagramme entrant :
    /// Priorité 1 : Socket connectée au 4-tuple exact
    /// Priorité 2 : Socket en écoute liée au port local sans connexion fixée
    pub fn find_udp(&self, local_port: u16, remote_ip: [u8; 4], remote_port: u16) -> Option<usize> {
        if let Some(id) = self.find_connected_udp(local_port, remote_ip, remote_port) {
            return Some(id);
        }
        for (i, slot) in self.sockets.iter().enumerate() {
            if let Some(sock) = slot {
                if sock.is_bound
                    && !sock.is_connected
                    && sock.protocol == SocketProtocol::Udp
                    && sock.local_port == local_port
                {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Déconnecte une socket UDP (dissocie l'adresse et le port distants)
    pub fn disconnect(&mut self, id: usize) -> Result<(), SysError> {
        if id >= 16 {
            return Err(SysError::InvalidArgument);
        }
        let sock = self.sockets[id].as_mut().ok_or(SysError::InvalidArgument)?;
        sock.is_connected = false;
        sock.remote_ip = [0, 0, 0, 0];
        sock.remote_port = 0;
        Ok(())
    }
}

// =========================================================================
// Moteur de Filtrage d'État Conntrack (Connection Tracking Ring 3)
// =========================================================================

pub const MAX_CONNTRACK_ENTRIES: usize = 32;

/// État de suivi de connexion d'un flux UDP ou TCP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackState {
    Unused,
    New,
    Established,
    Closed,
}

/// Entrée de table conntrack mémorisant un flux réseau bidirectionnel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConntrackEntry {
    pub state: ConntrackState,
    pub protocol: SocketProtocol,
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub expiry_ticks: u32,
}

impl ConntrackEntry {
    pub const fn empty() -> Self {
        Self {
            state: ConntrackState::Unused,
            protocol: SocketProtocol::Udp,
            local_ip: [0; 4],
            remote_ip: [0; 4],
            local_port: 0,
            remote_port: 0,
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            expiry_ticks: 0,
        }
    }
}

/// Table de suivi d'état des flux réseau sans allocation dynamique
pub struct ConntrackTable {
    pub entries: [ConntrackEntry; MAX_CONNTRACK_ENTRIES],
}

impl Default for ConntrackTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ConntrackTable {
    pub const fn new() -> Self {
        Self {
            entries: [ConntrackEntry::empty(); MAX_CONNTRACK_ENTRIES],
        }
    }

    /// Enregistre ou met à jour un flux sortant (datagramme UDP / paquet émis)
    pub fn track_outbound(
        &mut self,
        protocol: SocketProtocol,
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
        bytes: usize,
    ) -> Result<usize, SysError> {
        // 1. Mise à jour d'un flux existant
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if entry.state != ConntrackState::Unused
                && entry.protocol == protocol
                && entry.local_ip == local_ip
                && entry.local_port == local_port
                && entry.remote_ip == remote_ip
                && entry.remote_port == remote_port
            {
                entry.packets_sent += 1;
                entry.bytes_sent += bytes as u64;
                entry.expiry_ticks = 300;
                return Ok(i);
            }
        }

        // 2. Allocation d'une nouvelle entrée
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if entry.state == ConntrackState::Unused {
                *entry = ConntrackEntry {
                    state: ConntrackState::New,
                    protocol,
                    local_ip,
                    remote_ip,
                    local_port,
                    remote_port,
                    packets_sent: 1,
                    packets_recv: 0,
                    bytes_sent: bytes as u64,
                    bytes_recv: 0,
                    expiry_ticks: 300,
                };
                return Ok(i);
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Filtre et valide un flux entrant (Stateful Inspection : autorise si flux initié)
    pub fn filter_inbound(
        &mut self,
        protocol: SocketProtocol,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        bytes: usize,
    ) -> bool {
        for entry in self.entries.iter_mut() {
            if entry.state != ConntrackState::Unused
                && entry.protocol == protocol
                && entry.local_ip == dst_ip
                && entry.local_port == dst_port
                && entry.remote_ip == src_ip
                && entry.remote_port == src_port
            {
                // Flux correspondant : transition vers Established et mise à jour métriques
                entry.state = ConntrackState::Established;
                entry.packets_recv += 1;
                entry.bytes_recv += bytes as u64;
                entry.expiry_ticks = 300;
                return true;
            }
        }
        false
    }

    /// Avance le temps et purge les flux inactifs
    pub fn tick(&mut self, elapsed_ticks: u32) {
        for entry in self.entries.iter_mut() {
            if entry.state != ConntrackState::Unused {
                if entry.expiry_ticks <= elapsed_ticks {
                    *entry = ConntrackEntry::empty();
                } else {
                    entry.expiry_ticks -= elapsed_ticks;
                }
            }
        }
    }

    /// Compte les flux actifs
    pub fn active_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.state != ConntrackState::Unused)
            .count()
    }
}

// =========================================================================
// Table de Correspondance ARP & Protection Anti-Poisoning (RFC 826 / Ring 3)
// =========================================================================

pub const MAX_ARP_ENTRIES: usize = 32;
pub const ARP_DEFAULT_TTL_SECS: u32 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpEntryState {
    Free,
    Dynamic,
    Static,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub state: ArpEntryState,
    pub ttl_secs: u32,
    pub hits: u64,
}

impl ArpEntry {
    pub const fn empty() -> Self {
        Self {
            ip: [0; 4],
            mac: [0; 6],
            state: ArpEntryState::Free,
            ttl_secs: 0,
            hits: 0,
        }
    }
}

pub struct ArpTable {
    pub entries: [ArpEntry; MAX_ARP_ENTRIES],
    pub dynamic_count: usize,
    pub static_count: usize,
    pub spoofing_attempts_blocked: u64,
}

impl Default for ArpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpTable {
    pub const fn new() -> Self {
        Self {
            entries: [ArpEntry::empty(); MAX_ARP_ENTRIES],
            dynamic_count: 0,
            static_count: 0,
            spoofing_attempts_blocked: 0,
        }
    }

    /// Initialise la table avec la passerelle par défaut en tant qu'entrée statique protégée
    pub fn new_with_gateway(gw_ip: [u8; 4], gw_mac: [u8; 6]) -> Self {
        let mut table = Self::new();
        let _ = table.insert_static(gw_ip, gw_mac);
        table
    }

    /// Insère ou verrouille une entrée statique permanente (inviolable par ARP dynamique)
    pub fn insert_static(&mut self, ip: [u8; 4], mac: [u8; 6]) -> Result<(), SysError> {
        for entry in self.entries.iter_mut() {
            if entry.state != ArpEntryState::Free && entry.ip == ip {
                if entry.state == ArpEntryState::Dynamic {
                    self.dynamic_count = self.dynamic_count.saturating_sub(1);
                    self.static_count += 1;
                }
                entry.mac = mac;
                entry.state = ArpEntryState::Static;
                entry.ttl_secs = u32::MAX;
                return Ok(());
            }
        }

        for entry in self.entries.iter_mut() {
            if entry.state == ArpEntryState::Free {
                entry.ip = ip;
                entry.mac = mac;
                entry.state = ArpEntryState::Static;
                entry.ttl_secs = u32::MAX;
                self.static_count += 1;
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Résout une adresse IPv4 en adresse MAC
    pub fn lookup(&mut self, ip: [u8; 4]) -> Option<[u8; 6]> {
        for entry in self.entries.iter_mut() {
            if entry.state != ArpEntryState::Free && entry.ip == ip {
                entry.hits = entry.hits.saturating_add(1);
                return Some(entry.mac);
            }
        }
        None
    }

    /// Met à jour ou insère une correspondance dynamique apprise depuis une trame reçue
    /// Rejette les tentatives d'écrasement d'une entrée statique et les adresses invalides
    pub fn update_dynamic(&mut self, ip: [u8; 4], mac: [u8; 6]) -> Result<bool, SysError> {
        if mac == [0xFF; 6] || mac == [0x00; 6] {
            return Err(SysError::InvalidArgument);
        }
        if ip == [0, 0, 0, 0] || ip == [255, 255, 255, 255] {
            return Err(SysError::InvalidArgument);
        }

        for entry in self.entries.iter_mut() {
            if entry.state != ArpEntryState::Free && entry.ip == ip {
                if entry.state == ArpEntryState::Static {
                    if entry.mac != mac {
                        self.spoofing_attempts_blocked =
                            self.spoofing_attempts_blocked.saturating_add(1);
                        return Err(SysError::PermissionDenied);
                    }
                    return Ok(false);
                }

                entry.mac = mac;
                entry.ttl_secs = ARP_DEFAULT_TTL_SECS;
                return Ok(true);
            }
        }

        for entry in self.entries.iter_mut() {
            if entry.state == ArpEntryState::Free {
                entry.ip = ip;
                entry.mac = mac;
                entry.state = ArpEntryState::Dynamic;
                entry.ttl_secs = ARP_DEFAULT_TTL_SECS;
                self.dynamic_count += 1;
                return Ok(true);
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Avance le temps de `elapsed_secs` et purge les entrées dynamiques expirées
    pub fn tick(&mut self, elapsed_secs: u32) {
        for entry in self.entries.iter_mut() {
            if entry.state == ArpEntryState::Dynamic {
                if entry.ttl_secs <= elapsed_secs {
                    entry.state = ArpEntryState::Free;
                    self.dynamic_count = self.dynamic_count.saturating_sub(1);
                } else {
                    entry.ttl_secs -= elapsed_secs;
                }
            }
        }
    }
}

// =========================================================================
// Proxy ARP (RFC 1027) & Routage d'Adresses Virtuelles Ring 3
// =========================================================================

pub const MAX_PROXY_ARP_ENTRIES: usize = 16;

/// Règle de routage Proxy ARP pour une adresse IPv4 assignée à un microservice ou conteneur
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyArpRule {
    pub ip: [u8; 4],
    pub proxy_mac: [u8; 6],
    pub active: bool,
}

impl ProxyArpRule {
    pub const fn empty() -> Self {
        Self {
            ip: [0; 4],
            proxy_mac: [0; 6],
            active: false,
        }
    }
}

/// Table de correspondance Proxy ARP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyArpTable {
    pub rules: [ProxyArpRule; MAX_PROXY_ARP_ENTRIES],
    pub count: usize,
}

impl Default for ProxyArpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyArpTable {
    pub const fn new() -> Self {
        Self {
            rules: [ProxyArpRule::empty(); MAX_PROXY_ARP_ENTRIES],
            count: 0,
        }
    }

    /// Enregistre ou met à jour une adresse IPv4 proxifiée avec l'adresse MAC répondeur
    pub fn add_proxy(&mut self, ip: [u8; 4], mac: [u8; 6]) -> bool {
        // Recherche si la règle existe déjà
        for rule in self.rules.iter_mut() {
            if rule.active && rule.ip == ip {
                rule.proxy_mac = mac;
                return true;
            }
        }
        // Insertion dans un emplacement libre
        for rule in self.rules.iter_mut() {
            if !rule.active {
                rule.ip = ip;
                rule.proxy_mac = mac;
                rule.active = true;
                self.count += 1;
                return true;
            }
        }
        false
    }

    /// Supprime une adresse IPv4 proxifiée
    pub fn remove_proxy(&mut self, ip: [u8; 4]) -> bool {
        for rule in self.rules.iter_mut() {
            if rule.active && rule.ip == ip {
                rule.active = false;
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// Recherche si une adresse IP est proxifiée et retourne l'adresse MAC associée
    pub fn lookup(&self, ip: [u8; 4]) -> Option<[u8; 6]> {
        for rule in self.rules.iter() {
            if rule.active && rule.ip == ip {
                return Some(rule.proxy_mac);
            }
        }
        None
    }

    /// Indique si l'adresse IP fait partie des adresses proxifiées
    #[inline]
    pub fn is_proxied(&self, ip: [u8; 4]) -> bool {
        self.lookup(ip).is_some()
    }
}

/// Construit une trame ARP Reply pour une requête Proxy ARP (RFC 1027).
pub fn forge_arp_proxy_reply(
    proxy_mac: [u8; 6],
    proxied_ip: [u8; 4],
    req: &ArpPacket,
    out_frame: &mut [u8],
) -> Option<usize> {
    if out_frame.len() < 60 {
        return None;
    }
    out_frame[..60].fill(0);

    let eth = EthernetHeader::new(req.src_mac, proxy_mac, ETHERTYPE_ARP);
    let reply = ArpPacket::new_reply(proxy_mac, proxied_ip, req.src_mac, req.src_ip);

    out_frame[..14].copy_from_slice(&eth.to_bytes());
    out_frame[14..42].copy_from_slice(&reply.to_bytes());

    Some(60)
}

// =========================================================================
// Gestionnaire et Métriques Ping ICMP (RFC 792)
// =========================================================================

pub const MAX_PENDING_PINGS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingPing {
    pub id: u16,
    pub seq: u16,
    pub target_ip: [u8; 4],
    pub send_tick: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IcmpPingMetrics {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub min_rtt_ticks: u64,
    pub max_rtt_ticks: u64,
    pub last_rtt_ticks: u64,
    pub total_rtt_ticks: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct IcmpPingTracker {
    pub pending: [PendingPing; MAX_PENDING_PINGS],
    pub metrics: IcmpPingMetrics,
}

impl Default for IcmpPingTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl IcmpPingTracker {
    pub const fn new() -> Self {
        Self {
            pending: [PendingPing {
                id: 0,
                seq: 0,
                target_ip: [0; 4],
                send_tick: 0,
                active: false,
            }; MAX_PENDING_PINGS],
            metrics: IcmpPingMetrics {
                packets_sent: 0,
                packets_received: 0,
                packets_lost: 0,
                min_rtt_ticks: u64::MAX,
                max_rtt_ticks: 0,
                last_rtt_ticks: 0,
                total_rtt_ticks: 0,
            },
        }
    }

    /// Enregistre une émission ICMP Echo Request
    pub fn record_sent(&mut self, id: u16, seq: u16, target_ip: [u8; 4], tick: u64) {
        self.metrics.packets_sent = self.metrics.packets_sent.saturating_add(1);
        for p in self.pending.iter_mut() {
            if !p.active {
                p.id = id;
                p.seq = seq;
                p.target_ip = target_ip;
                p.send_tick = tick;
                p.active = true;
                return;
            }
        }
        self.pending[0] = PendingPing {
            id,
            seq,
            target_ip,
            send_tick: tick,
            active: true,
        };
    }

    /// Traite la réception d'un ICMP Echo Reply correspondant et calcule le RTT
    pub fn record_reply(&mut self, id: u16, seq: u16, tick: u64) -> Option<u64> {
        for p in self.pending.iter_mut() {
            if p.active && p.id == id && p.seq == seq {
                p.active = false;
                let rtt = tick.saturating_sub(p.send_tick);
                self.metrics.packets_received = self.metrics.packets_received.saturating_add(1);
                self.metrics.last_rtt_ticks = rtt;
                if rtt < self.metrics.min_rtt_ticks {
                    self.metrics.min_rtt_ticks = rtt;
                }
                if rtt > self.metrics.max_rtt_ticks {
                    self.metrics.max_rtt_ticks = rtt;
                }
                self.metrics.total_rtt_ticks = self.metrics.total_rtt_ticks.saturating_add(rtt);
                return Some(rtt);
            }
        }
        None
    }

    /// Purge les pings expirés (timeout)
    pub fn expire_older_than(&mut self, current_tick: u64, timeout_ticks: u64) -> usize {
        let mut expired = 0;
        for p in self.pending.iter_mut() {
            if p.active && current_tick.saturating_sub(p.send_tick) > timeout_ticks {
                p.active = false;
                self.metrics.packets_lost = self.metrics.packets_lost.saturating_add(1);
                expired += 1;
            }
        }
        expired
    }
}

// =========================================================================
// Protocole de Configuration Dynamique d'Hôte DHCP (RFC 2131)
// =========================================================================

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
pub const DHCP_OP_BOOTREQUEST: u8 = 1;
pub const DHCP_OP_BOOTREPLY: u8 = 2;

pub const DHCP_OPT_PAD: u8 = 0;
pub const DHCP_OPT_SUBNET_MASK: u8 = 1;
pub const DHCP_OPT_ROUTER: u8 = 3;
pub const DHCP_OPT_DNS_SERVER: u8 = 6;
pub const DHCP_OPT_LEASE_TIME: u8 = 51;
pub const DHCP_OPT_MESSAGE_TYPE: u8 = 53;
pub const DHCP_OPT_SERVER_IDENTIFIER: u8 = 54;
pub const DHCP_OPT_END: u8 = 255;

pub const DHCP_MSG_DISCOVER: u8 = 1;
pub const DHCP_MSG_OFFER: u8 = 2;
pub const DHCP_MSG_REQUEST: u8 = 3;
pub const DHCP_MSG_ACK: u8 = 5;
pub const DHCP_MSG_NAK: u8 = 6;

/// En-tête de trame DHCP/BOOTP (240 octets avec le magic cookie RFC 2131)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpPacketHeader {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub siaddr: [u8; 4],
    pub giaddr: [u8; 4],
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub magic_cookie: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<DhcpPacketHeader>() == 240);

/// Offre de bail réseau IP retournée par le serveur DHCP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DhcpOffer {
    pub yiaddr: [u8; 4],
    pub server_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub router: [u8; 4],
    pub dns_server: [u8; 4],
    pub lease_time_secs: u32,
}

/// Machine d'état du client DHCP Ring 3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpClientState {
    Init,
    Selecting { xid: u32 },
    Requesting { xid: u32, offer: DhcpOffer },
    Bound(DhcpOffer),
    Failed,
}

/// Construit un paquet DHCP DISCOVER conforme RFC 2131
pub fn build_dhcp_discover(client_mac: [u8; 6], xid: u32, out: &mut [u8]) -> usize {
    if out.len() < 240 + 4 {
        return 0;
    }

    let mut chaddr = [0u8; 16];
    chaddr[0..6].copy_from_slice(&client_mac);

    let hdr = DhcpPacketHeader {
        op: DHCP_OP_BOOTREQUEST,
        htype: 1, // Ethernet
        hlen: 6,
        hops: 0,
        xid: xid.to_be(),
        secs: 0,
        flags: 0x8000u16.to_be(), // Broadcast flag
        ciaddr: [0; 4],
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
        sname: [0; 64],
        file: [0; 128],
        magic_cookie: DHCP_MAGIC_COOKIE,
    };

    // SAFETY: DhcpPacketHeader est packed et fait 240 octets, out.len() >= 244
    unsafe {
        core::ptr::copy_nonoverlapping(
            &hdr as *const DhcpPacketHeader as *const u8,
            out.as_mut_ptr(),
            240,
        );
    }

    // Option 53: DHCP Message Type = Discover (longueur 1, valeur 1)
    out[240] = DHCP_OPT_MESSAGE_TYPE;
    out[241] = 1;
    out[242] = DHCP_MSG_DISCOVER;
    // Option 255: End
    out[243] = DHCP_OPT_END;

    244
}

/// Analyse un paquet DHCP OFFER retourné par un serveur DHCP
pub fn parse_dhcp_offer(payload: &[u8], expected_xid: u32) -> Result<DhcpOffer, SysError> {
    if payload.len() < 240 {
        return Err(SysError::InvalidArgument);
    }

    // SAFETY: payload.len() >= 240, read_unaligned accepte tout alignement
    let hdr = unsafe {
        let ptr = payload.as_ptr() as *const DhcpPacketHeader;
        ptr.read_unaligned()
    };

    if hdr.op != DHCP_OP_BOOTREPLY {
        return Err(SysError::InvalidArgument);
    }
    if u32::from_be(hdr.xid) != expected_xid {
        return Err(SysError::InvalidArgument);
    }
    if hdr.magic_cookie != DHCP_MAGIC_COOKIE {
        return Err(SysError::InvalidArgument);
    }

    let mut offer = DhcpOffer {
        yiaddr: hdr.yiaddr,
        server_ip: hdr.siaddr,
        subnet_mask: [255, 255, 255, 0],
        router: [0, 0, 0, 0],
        dns_server: [0, 0, 0, 0],
        lease_time_secs: 3600,
    };

    // Parcours sécurisé des options TLV
    let mut cursor = 240;
    while cursor < payload.len() {
        let opt_type = payload[cursor];
        if opt_type == DHCP_OPT_END {
            break;
        }
        if opt_type == DHCP_OPT_PAD {
            cursor += 1;
            continue;
        }

        if cursor + 1 >= payload.len() {
            break;
        }
        let opt_len = payload[cursor + 1] as usize;
        let data_start = cursor + 2;
        let data_end = data_start + opt_len;
        if data_end > payload.len() {
            break;
        }

        let opt_data = &payload[data_start..data_end];
        match opt_type {
            DHCP_OPT_SUBNET_MASK if opt_len == 4 => {
                offer.subnet_mask.copy_from_slice(opt_data);
            }
            DHCP_OPT_ROUTER if opt_len >= 4 => {
                offer.router.copy_from_slice(&opt_data[0..4]);
            }
            DHCP_OPT_DNS_SERVER if opt_len >= 4 => {
                offer.dns_server.copy_from_slice(&opt_data[0..4]);
            }
            DHCP_OPT_SERVER_IDENTIFIER if opt_len == 4 => {
                offer.server_ip.copy_from_slice(opt_data);
            }
            DHCP_OPT_LEASE_TIME if opt_len == 4 => {
                let bytes: [u8; 4] = opt_data.try_into().unwrap_or([0; 4]);
                offer.lease_time_secs = u32::from_be_bytes(bytes);
            }
            _ => {}
        }

        cursor = data_end;
    }

    Ok(offer)
}

// =========================================================================
// Protocole DNS Client (Domain Name System - RFC 1035)
// =========================================================================

pub const DNS_PORT: u16 = 53;
pub const DNS_TYPE_A: u16 = 1; // Enregistrement IPv4 hôte
pub const DNS_TYPE_CNAME: u16 = 5; // Canonical Name
pub const DNS_TYPE_AAAA: u16 = 28; // Enregistrement IPv6
pub const DNS_CLASS_IN: u16 = 1; // Classe Internet standard

pub const DNS_FLAG_QR_RESPONSE: u16 = 0x8000;
pub const DNS_FLAG_RD: u16 = 0x0100; // Recursion Desired
pub const DNS_FLAG_RA: u16 = 0x0080; // Recursion Available
pub const DNS_RCODE_MASK: u16 = 0x000F;
pub const DNS_RCODE_NO_ERROR: u16 = 0;
pub const DNS_RCODE_NAME_ERROR: u16 = 3; // NXDOMAIN

/// En-tête de message DNS (12 octets, RFC 1035 § 4.1.1)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

const _: () = assert!(core::mem::size_of::<DnsHeader>() == 12);

impl DnsHeader {
    #[inline]
    pub fn id(&self) -> u16 {
        u16::from_be(self.id)
    }

    #[inline]
    pub fn flags(&self) -> u16 {
        u16::from_be(self.flags)
    }

    #[inline]
    pub fn qdcount(&self) -> u16 {
        u16::from_be(self.qdcount)
    }

    #[inline]
    pub fn ancount(&self) -> u16 {
        u16::from_be(self.ancount)
    }

    #[inline]
    pub fn is_response(&self) -> bool {
        (self.flags() & DNS_FLAG_QR_RESPONSE) != 0
    }

    #[inline]
    pub fn rcode(&self) -> u16 {
        self.flags() & DNS_RCODE_MASK
    }
}

pub const MAX_DNS_CACHE_ENTRIES: usize = 8;
pub const MAX_DOMAIN_LEN: usize = 64;

/// Entrée du cache de résolution DNS Ring 3
#[derive(Clone, Copy)]
pub struct DnsCacheEntry {
    pub domain: [u8; MAX_DOMAIN_LEN],
    pub domain_len: usize,
    pub ip: [u8; 4],
    pub active: bool,
}

impl Default for DnsCacheEntry {
    fn default() -> Self {
        Self {
            domain: [0u8; MAX_DOMAIN_LEN],
            domain_len: 0,
            ip: [0; 4],
            active: false,
        }
    }
}

/// Client résolveur DNS local avec cache sans allocation mémoire
pub struct DnsClientResolver {
    pub dns_server_ip: [u8; 4],
    pub next_txid: u16,
    pub cache: [DnsCacheEntry; MAX_DNS_CACHE_ENTRIES],
}

impl Default for DnsClientResolver {
    fn default() -> Self {
        Self::new([10, 0, 2, 3]) // Serveur DNS SLIRP QEMU par défaut
    }
}

impl DnsClientResolver {
    pub const fn new(dns_server_ip: [u8; 4]) -> Self {
        const EMPTY_ENTRY: DnsCacheEntry = DnsCacheEntry {
            domain: [0u8; MAX_DOMAIN_LEN],
            domain_len: 0,
            ip: [0; 4],
            active: false,
        };
        Self {
            dns_server_ip,
            next_txid: 0x1234,
            cache: [EMPTY_ENTRY; MAX_DNS_CACHE_ENTRIES],
        }
    }

    /// Recherche une entrée dans le cache DNS local
    pub fn lookup_cache(&self, domain: &str) -> Option<[u8; 4]> {
        for entry in self.cache.iter() {
            if entry.active
                && entry.domain_len == domain.len()
                && &entry.domain[..entry.domain_len] == domain.as_bytes()
            {
                return Some(entry.ip);
            }
        }
        None
    }

    /// Enregistre une adresse IP résolue dans le cache DNS
    pub fn insert_cache(&mut self, domain: &str, ip: [u8; 4]) {
        let b = domain.as_bytes();
        let len = b.len().min(MAX_DOMAIN_LEN);
        // Remplacement d'une entrée existante ou premier slot libre
        for entry in self.cache.iter_mut() {
            if entry.active && entry.domain_len == len && entry.domain[..len] == b[..len] {
                entry.ip = ip;
                return;
            }
        }
        for entry in self.cache.iter_mut() {
            if !entry.active {
                entry.domain[..len].copy_from_slice(&b[..len]);
                entry.domain_len = len;
                entry.ip = ip;
                entry.active = true;
                return;
            }
        }
        // Éviction du premier slot si plein
        self.cache[0].domain[..len].copy_from_slice(&b[..len]);
        self.cache[0].domain_len = len;
        self.cache[0].ip = ip;
        self.cache[0].active = true;
    }

    /// Forge un paquet de requête DNS conforme RFC 1035
    pub fn forge_query(&mut self, domain: &str, out: &mut [u8]) -> Result<(usize, u16), SysError> {
        let txid = self.next_txid;
        self.next_txid = self.next_txid.wrapping_add(1);
        let len = build_dns_query(domain, txid, out)?;
        Ok((len, txid))
    }
}

/// Construit une trame DNS Query (RFC 1035) pour une résolution de nom d'hôte (Type A IPv4)
pub fn build_dns_query(domain: &str, txid: u16, out: &mut [u8]) -> Result<usize, SysError> {
    if domain.is_empty() || domain.len() > 255 {
        return Err(SysError::InvalidArgument);
    }

    // Taille minimale requise : 12 (en-tête) + domain.len() + 2 (labels) + 4 (QTYPE, QCLASS)
    let needed = 12 + domain.len() + 2 + 4;
    if out.len() < needed {
        return Err(SysError::BufferTooSmall);
    }

    // 1. En-tête DNS (12 octets)
    let hdr = DnsHeader {
        id: txid.to_be(),
        flags: DNS_FLAG_RD.to_be(), // Recursion Desired (0x0100)
        qdcount: 1u16.to_be(),      // 1 question
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    // SAFETY: out.len() >= needed >= 12 validé précédemment, DnsHeader a une taille fixe de 12 octets
    unsafe {
        core::ptr::copy_nonoverlapping(&hdr as *const DnsHeader as *const u8, out.as_mut_ptr(), 12);
    }

    // 2. Question section : Encodage QNAME par labels (ex: "jambo.local" -> \x05jambo\x05local\x00)
    let mut cursor = 12;
    for part in domain.split('.') {
        if part.is_empty() {
            continue;
        }
        let part_bytes = part.as_bytes();
        if part_bytes.len() > 63 {
            return Err(SysError::InvalidArgument);
        }
        out[cursor] = part_bytes.len() as u8;
        cursor += 1;
        out[cursor..cursor + part_bytes.len()].copy_from_slice(part_bytes);
        cursor += part_bytes.len();
    }
    // Terminaison du QNAME
    out[cursor] = 0;
    cursor += 1;

    // 3. QTYPE (Type A = 1) et QCLASS (Class IN = 1)
    let qtype = DNS_TYPE_A.to_be_bytes();
    out[cursor..cursor + 2].copy_from_slice(&qtype);
    cursor += 2;

    let qclass = DNS_CLASS_IN.to_be_bytes();
    out[cursor..cursor + 2].copy_from_slice(&qclass);
    cursor += 2;

    Ok(cursor)
}

/// Analyse une trame DNS Response (RFC 1035) et extrait la première adresse IPv4 résolue
pub fn parse_dns_response(packet: &[u8], expected_txid: u16) -> Result<[u8; 4], SysError> {
    if packet.len() < 12 {
        return Err(SysError::BufferTooSmall);
    }

    // SAFETY: packet.len() >= 12 validé précédemment, read_unaligned supporte tout alignement
    let hdr = unsafe {
        let ptr = packet.as_ptr() as *const DnsHeader;
        ptr.read_unaligned()
    };

    if hdr.id() != expected_txid {
        return Err(SysError::InvalidArgument);
    }

    if !hdr.is_response() {
        return Err(SysError::InvalidArgument);
    }

    if hdr.rcode() != DNS_RCODE_NO_ERROR {
        return Err(SysError::InvalidArgument);
    }

    let ancount = hdr.ancount();
    if ancount == 0 {
        return Err(SysError::InvalidArgument);
    }

    let mut cursor = 12;

    // Saute la section Question
    let qdcount = hdr.qdcount();
    for _ in 0..qdcount {
        while cursor < packet.len() {
            let len = packet[cursor];
            if len == 0 {
                cursor += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                // Pointeur de compression
                cursor += 2;
                break;
            }
            cursor += 1 + len as usize;
        }
        cursor += 4; // QTYPE + QCLASS
    }

    // Parcourt les enregistrements de la section Answer
    for _ in 0..ancount {
        if cursor >= packet.len() {
            break;
        }

        // Saute le champ NAME (pointeur ou labels)
        if (packet[cursor] & 0xC0) == 0xC0 {
            cursor += 2;
        } else {
            while cursor < packet.len() {
                let len = packet[cursor];
                if len == 0 {
                    cursor += 1;
                    break;
                }
                cursor += 1 + len as usize;
            }
        }

        if cursor + 10 > packet.len() {
            break;
        }

        let rtype = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        let _rclass = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
        let _ttl = u32::from_be_bytes([
            packet[cursor + 4],
            packet[cursor + 5],
            packet[cursor + 6],
            packet[cursor + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[cursor + 8], packet[cursor + 9]]) as usize;
        cursor += 10;

        if cursor + rdlength > packet.len() {
            break;
        }

        // Si enregistrement Type A (IPv4) avec longueur 4 octets
        if rtype == DNS_TYPE_A && rdlength == 4 {
            let ip = [
                packet[cursor],
                packet[cursor + 1],
                packet[cursor + 2],
                packet[cursor + 3],
            ];
            return Ok(ip);
        }

        cursor += rdlength;
    }

    Err(SysError::InvalidArgument)
}

// ============================================================================
// SOUS-SYSTÈME DE FILTRAGE RÉSEAU BPF & RECHARGEMENT DYNAMIQUE
// ============================================================================

/// Action de filtrage BPF
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfFilterAction {
    Pass = 0,
    Drop = 1,
}

/// Règle de filtrage réseau BPF
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfFilterRule {
    pub id: u32,
    pub proto: u8,
    pub _pad: [u8; 3],
    pub src_ip: [u8; 4],
    pub src_mask: [u8; 4],
    pub dst_ip: [u8; 4],
    pub dst_mask: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub action: BpfFilterAction,
    pub is_active: bool,
    pub _reserved: [u8; 6],
    pub hit_count: u64,
}

impl BpfFilterRule {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            proto: 0,
            _pad: [0; 3],
            src_ip: [0; 4],
            src_mask: [0; 4],
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port: 0,
            dst_port: 0,
            action: BpfFilterAction::Pass,
            is_active: false,
            _reserved: [0; 6],
            hit_count: 0,
        }
    }

    pub const fn new(
        id: u32,
        proto: u8,
        src_ip: [u8; 4],
        src_mask: [u8; 4],
        dst_port: u16,
        action: BpfFilterAction,
    ) -> Self {
        Self {
            id,
            proto,
            _pad: [0; 3],
            src_ip,
            src_mask,
            dst_ip: [0; 4],
            dst_mask: [0; 4],
            src_port: 0,
            dst_port,
            action,
            is_active: true,
            _reserved: [0; 6],
            hit_count: 0,
        }
    }

    pub fn matches(&self, proto: u8, src: [u8; 4], dst: [u8; 4], src_p: u16, dst_p: u16) -> bool {
        if !self.is_active {
            return false;
        }
        if self.proto != 0 && self.proto != proto {
            return false;
        }
        for i in 0..4 {
            if (src[i] & self.src_mask[i]) != (self.src_ip[i] & self.src_mask[i]) {
                return false;
            }
            if (dst[i] & self.dst_mask[i]) != (self.dst_ip[i] & self.dst_mask[i]) {
                return false;
            }
        }
        if self.src_port != 0 && self.src_port != src_p {
            return false;
        }
        if self.dst_port != 0 && self.dst_port != dst_p {
            return false;
        }
        true
    }
}

pub const MAX_BPF_RULES: usize = 16;

/// Table de filtrage réseau eBPF avec support du rechargement dynamique à chaud
#[derive(Debug, Clone, Copy)]
pub struct BpfFilterTable {
    pub rules: [BpfFilterRule; MAX_BPF_RULES],
    pub rule_count: usize,
    pub generation: u32,
    pub total_evaluated: u64,
    pub total_passed: u64,
    pub total_dropped: u64,
}

impl BpfFilterTable {
    pub const fn new() -> Self {
        Self {
            rules: [BpfFilterRule::empty(); MAX_BPF_RULES],
            rule_count: 0,
            generation: 1,
            total_evaluated: 0,
            total_passed: 0,
            total_dropped: 0,
        }
    }

    /// Rechargement dynamique et atomique des règles de filtrage (sans interruption de service)
    pub fn reload_rules(&mut self, new_rules: &[BpfFilterRule]) -> usize {
        let count = new_rules.len().min(MAX_BPF_RULES);
        for i in 0..count {
            self.rules[i] = new_rules[i];
            self.rules[i].hit_count = 0;
            self.rules[i].is_active = true;
        }
        for item in self.rules[count..MAX_BPF_RULES].iter_mut() {
            *item = BpfFilterRule::empty();
        }
        self.rule_count = count;
        self.generation = self.generation.wrapping_add(1);
        count
    }

    /// Ajout d'une règle individuelle
    pub fn add_rule(&mut self, rule: BpfFilterRule) -> Result<usize, SysError> {
        if self.rule_count >= MAX_BPF_RULES {
            return Err(SysError::OutOfMemory);
        }
        let idx = self.rule_count;
        self.rules[idx] = rule;
        self.rules[idx].is_active = true;
        self.rule_count += 1;
        self.generation = self.generation.wrapping_add(1);
        Ok(idx)
    }

    /// Réinitialisation des règles (politique par défaut Pass-All)
    pub fn clear_rules(&mut self) {
        for r in self.rules.iter_mut() {
            *r = BpfFilterRule::empty();
        }
        self.rule_count = 0;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Évalue un paquet Ethernet brut selon les règles BPF actives
    pub fn evaluate_packet(&mut self, packet: &[u8]) -> BpfFilterAction {
        self.total_evaluated += 1;

        if packet.len() < 14 {
            self.total_passed += 1;
            return BpfFilterAction::Pass;
        }

        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype != ETHERTYPE_IPV4 || packet.len() < 14 + 20 {
            self.total_passed += 1;
            return BpfFilterAction::Pass;
        }

        let ip_bytes = &packet[14..];
        let ihl = ((ip_bytes[0] & 0x0F) * 4) as usize;
        if ihl < 20 || packet.len() < 14 + ihl {
            self.total_passed += 1;
            return BpfFilterAction::Pass;
        }

        let proto = ip_bytes[9];
        let src_ip = [ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]];
        let dst_ip = [ip_bytes[16], ip_bytes[17], ip_bytes[18], ip_bytes[19]];

        let mut src_port = 0u16;
        let mut dst_port = 0u16;

        if (proto == IP_PROTO_TCP || proto == IP_PROTO_UDP) && packet.len() >= 14 + ihl + 4 {
            let l4 = &packet[14 + ihl..];
            src_port = u16::from_be_bytes([l4[0], l4[1]]);
            dst_port = u16::from_be_bytes([l4[2], l4[3]]);
        }

        for i in 0..self.rule_count {
            let rule = &mut self.rules[i];
            if rule.matches(proto, src_ip, dst_ip, src_port, dst_port) {
                rule.hit_count += 1;
                match rule.action {
                    BpfFilterAction::Pass => {
                        self.total_passed += 1;
                        return BpfFilterAction::Pass;
                    }
                    BpfFilterAction::Drop => {
                        self.total_dropped += 1;
                        return BpfFilterAction::Drop;
                    }
                }
            }
        }

        self.total_passed += 1;
        BpfFilterAction::Pass
    }
}

impl Default for BpfFilterTable {
    fn default() -> Self {
        Self::new()
    }
}

pub const MAX_NAT_BINDINGS: usize = 64;
pub const NAT_EPHEMERAL_PORT_MIN: u16 = 49152;
pub const NAT_EPHEMERAL_PORT_MAX: u16 = 65535;
pub const NAT_DEFAULT_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatProtocol {
    Udp,
    Tcp,
    Icmp,
}

/// Erreur de gestion de la table NAT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatError {
    TableFull,
    PortCollision,
}

/// Liaison de translation d'adresses et de ports réseau (NAPT RFC 3022)
#[derive(Debug, Clone, Copy)]
pub struct NatBinding {
    pub active: bool,
    pub proto: NatProtocol,
    pub internal_ip: [u8; 4],
    pub internal_port: u16,
    pub external_ip: [u8; 4],
    pub external_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub is_static_dnat: bool,
    pub last_activity_timestamp: u64,
    pub packets_translated: u64,
    pub bytes_translated: u64,
}

/// Table de Traduction d'Adresses Réseau NAT / Masquerading (Ring 3 IPv4/UDP/TCP)
#[derive(Debug, Clone)]
pub struct NatTable {
    pub bindings: [NatBinding; MAX_NAT_BINDINGS],
    pub active_count: usize,
    pub next_ephemeral_port: u16,
    pub public_ip: [u8; 4],
    pub total_translations: u64,
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new([10, 0, 2, 15])
    }
}

impl NatTable {
    pub const fn new(public_ip: [u8; 4]) -> Self {
        Self {
            bindings: [NatBinding {
                active: false,
                proto: NatProtocol::Udp,
                internal_ip: [0; 4],
                internal_port: 0,
                external_ip: [0; 4],
                external_port: 0,
                remote_ip: [0; 4],
                remote_port: 0,
                is_static_dnat: false,
                last_activity_timestamp: 0,
                packets_translated: 0,
                bytes_translated: 0,
            }; MAX_NAT_BINDINGS],
            active_count: 0,
            next_ephemeral_port: NAT_EPHEMERAL_PORT_MIN,
            public_ip,
            total_translations: 0,
        }
    }

    /// Alloue un port source externe unique pour SNAT / Masquerading
    fn allocate_ephemeral_port(&mut self, proto: NatProtocol) -> Option<u16> {
        let span = (NAT_EPHEMERAL_PORT_MAX - NAT_EPHEMERAL_PORT_MIN) as usize + 1;
        for _ in 0..span {
            let port = self.next_ephemeral_port;
            self.next_ephemeral_port = if self.next_ephemeral_port == NAT_EPHEMERAL_PORT_MAX {
                NAT_EPHEMERAL_PORT_MIN
            } else {
                self.next_ephemeral_port + 1
            };

            // Vérifie si ce port est déjà pris pour ce protocole
            let collision = self
                .bindings
                .iter()
                .any(|b| b.active && b.proto == proto && b.external_port == port);

            if !collision {
                return Some(port);
            }
        }
        None
    }

    /// Translater un paquet sortant (SNAT / Masquerade)
    /// Remplace (internal_ip, internal_port) par (public_ip, external_port)
    pub fn translate_outbound(
        &mut self,
        proto: NatProtocol,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        current_time: u64,
        payload_len: usize,
    ) -> Option<([u8; 4], u16)> {
        // 1. Chercher si une liaison active existe déjà
        for b in self.bindings.iter_mut() {
            if b.active
                && b.proto == proto
                && b.internal_ip == src_ip
                && b.internal_port == src_port
                && b.remote_ip == dst_ip
                && b.remote_port == dst_port
            {
                b.last_activity_timestamp = current_time;
                b.packets_translated += 1;
                b.bytes_translated += payload_len as u64;
                self.total_translations += 1;
                return Some((b.external_ip, b.external_port));
            }
        }

        // 2. Allouer un port éphémère et un slot
        let ext_port = self.allocate_ephemeral_port(proto)?;
        let slot_idx = self.bindings.iter().position(|b| !b.active)?;

        let b = &mut self.bindings[slot_idx];
        b.active = true;
        b.proto = proto;
        b.internal_ip = src_ip;
        b.internal_port = src_port;
        b.external_ip = self.public_ip;
        b.external_port = ext_port;
        b.remote_ip = dst_ip;
        b.remote_port = dst_port;
        b.is_static_dnat = false;
        b.last_activity_timestamp = current_time;
        b.packets_translated = 1;
        b.bytes_translated = payload_len as u64;

        self.active_count += 1;
        self.total_translations += 1;

        Some((self.public_ip, ext_port))
    }

    /// Translater un paquet entrant (Reverse SNAT ou DNAT / Port Forwarding)
    /// Remplace (public_ip, external_port) par (internal_ip, internal_port)
    pub fn translate_inbound(
        &mut self,
        proto: NatProtocol,
        dst_port: u16,
        src_ip: [u8; 4],
        src_port: u16,
        current_time: u64,
        payload_len: usize,
    ) -> Option<([u8; 4], u16)> {
        for b in self.bindings.iter_mut() {
            if b.active && b.proto == proto && b.external_port == dst_port {
                // Pour DNAT statique ou si les adresses distantes concordent
                if b.is_static_dnat || (b.remote_ip == src_ip && b.remote_port == src_port) {
                    b.last_activity_timestamp = current_time;
                    b.packets_translated += 1;
                    b.bytes_translated += payload_len as u64;
                    self.total_translations += 1;
                    return Some((b.internal_ip, b.internal_port));
                }
            }
        }
        None
    }

    /// Enregistre une règle de redirection de port statique (DNAT / Port Forwarding)
    pub fn add_port_forward(
        &mut self,
        proto: NatProtocol,
        external_port: u16,
        internal_ip: [u8; 4],
        internal_port: u16,
    ) -> Result<(), NatError> {
        // Vérifier collision
        if self
            .bindings
            .iter()
            .any(|b| b.active && b.proto == proto && b.external_port == external_port)
        {
            return Err(NatError::PortCollision);
        }

        let slot_idx = self
            .bindings
            .iter()
            .position(|b| !b.active)
            .ok_or(NatError::TableFull)?;
        let b = &mut self.bindings[slot_idx];
        b.active = true;
        b.proto = proto;
        b.internal_ip = internal_ip;
        b.internal_port = internal_port;
        b.external_ip = self.public_ip;
        b.external_port = external_port;
        b.remote_ip = [0; 4]; // wildcard
        b.remote_port = 0;
        b.is_static_dnat = true;
        b.last_activity_timestamp = 0;
        b.packets_translated = 0;
        b.bytes_translated = 0;

        self.active_count += 1;
        Ok(())
    }

    /// Purge les liaisons inactives ayant dépassé le délai imparti (timeout)
    pub fn expire_idle_bindings(&mut self, current_time: u64, timeout_secs: u64) -> usize {
        let mut expired = 0;
        for b in self.bindings.iter_mut() {
            if b.active
                && !b.is_static_dnat
                && current_time.saturating_sub(b.last_activity_timestamp) >= timeout_secs
            {
                b.active = false;
                expired += 1;
            }
        }
        self.active_count = self.active_count.saturating_sub(expired);
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_header() {
        let dst = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let src = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let eth = EthernetHeader::new(dst, src, ETHERTYPE_IPV4);
        assert_eq!(eth.ethertype(), ETHERTYPE_IPV4);
        let bytes = eth.to_bytes();
        let parsed = EthernetHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.dst_mac, dst);
        assert_eq!(parsed.src_mac, src);
        assert_eq!(parsed.ethertype(), ETHERTYPE_IPV4);
    }

    #[test]
    fn test_arp_packet_and_reply_forge() {
        let my_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let my_ip = [10, 0, 2, 15];
        let gw_mac = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
        let gw_ip = [10, 0, 2, 2];

        let req = ArpPacket::new_request(gw_mac, gw_ip, my_ip);
        assert_eq!(req.opcode(), ARP_OPCODE_REQUEST);

        let mut tx_buf = [0u8; 128];
        let len = forge_arp_reply(my_mac, my_ip, &req, &mut tx_buf).unwrap();
        assert_eq!(len, 60);

        let eth = EthernetHeader::from_bytes(&tx_buf[..14]).unwrap();
        assert_eq!(eth.dst_mac, gw_mac);
        assert_eq!(eth.src_mac, my_mac);
        assert_eq!(eth.ethertype(), ETHERTYPE_ARP);

        let arp_reply = ArpPacket::from_bytes(&tx_buf[14..42]).unwrap();
        assert_eq!(arp_reply.opcode(), ARP_OPCODE_REPLY);
        assert_eq!(arp_reply.src_mac, my_mac);
        assert_eq!(arp_reply.src_ip, my_ip);
        assert_eq!(arp_reply.dst_mac, gw_mac);
        assert_eq!(arp_reply.dst_ip, gw_ip);
    }

    #[test]
    fn test_ipv4_checksum_and_validation() {
        let src_ip = [10, 0, 2, 15];
        let dst_ip = [10, 0, 2, 2];
        let ip = Ipv4Header::new(IP_PROTO_ICMP, src_ip, dst_ip, 32);
        assert!(verify_ipv4_checksum(&ip));
        assert_eq!(ip.proto, IP_PROTO_ICMP);
        assert_eq!(ip.len(), 52);
    }

    #[test]
    fn test_icmp_echo_reply_forge() {
        let my_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let my_ip = [10, 0, 2, 15];
        let sender_mac = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let sender_ip = [10, 0, 2, 2];

        let req_eth = EthernetHeader::new(my_mac, sender_mac, ETHERTYPE_IPV4);
        let req_ip = Ipv4Header::new(IP_PROTO_ICMP, sender_ip, my_ip, 40);
        let payload = b"Hello JamboOS Ping!";
        let req_icmp = IcmpHeader::new_echo_request(0x1234, 1, payload);

        let mut tx_buf = [0u8; 128];
        let len = forge_icmp_echo_reply(
            my_mac,
            my_ip,
            &req_eth,
            &req_ip,
            &req_icmp,
            payload,
            &mut tx_buf,
        )
        .unwrap();

        assert_eq!(len, 14 + 20 + 8 + payload.len());
        let eth = EthernetHeader::from_bytes(&tx_buf[..14]).unwrap();
        assert_eq!(eth.dst_mac, sender_mac);
        assert_eq!(eth.src_mac, my_mac);

        let ip = Ipv4Header::from_bytes(&tx_buf[14..34]).unwrap();
        assert!(verify_ipv4_checksum(&ip));
        assert_eq!(ip.src_ip, my_ip);
        assert_eq!(ip.dst_ip, sender_ip);

        let icmp = IcmpHeader::from_bytes(&tx_buf[34..42]).unwrap();
        assert_eq!(icmp.icmp_type, ICMP_TYPE_ECHO_REPLY);
        assert_eq!(icmp.code, 0);
        assert_eq!(icmp.id(), 0x1234);
        assert_eq!(icmp.seq(), 1);
        assert!(verify_icmp_checksum(&icmp, &tx_buf[42..len]));
    }

    #[test]
    fn test_ipc_serialization() {
        let req = NetRequest::new(NetOpcode::SendPing, [10, 0, 2, 2]);
        let req_bytes = req.to_bytes();
        let parsed_req = NetRequest::from_bytes(&req_bytes).unwrap();
        assert_eq!(parsed_req.opcode, NetOpcode::SendPing as u32);
        assert_eq!(parsed_req.target_ip, [10, 0, 2, 2]);

        let resp = NetResponse {
            status: 0,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            ip: [10, 0, 2, 15],
            packets_rx: 42,
            packets_tx: 10,
            rtt_ms: 1,
        };
        let resp_bytes = resp.to_bytes();
        let parsed_resp = NetResponse::from_bytes(&resp_bytes).unwrap();
        assert_eq!(parsed_resp.status, 0);
        assert_eq!(parsed_resp.packets_rx, 42);
        assert_eq!(parsed_resp.packets_tx, 10);
        assert_eq!(parsed_resp.rtt_ms, 1);
        assert_eq!(parsed_resp.mac, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(parsed_resp.ip, [10, 0, 2, 15]);
    }

    #[test]
    fn test_udp_header_serialization() {
        let udp = UdpHeader::new(53, 1024, 64);
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 1024);
        assert_eq!(udp.length(), 72);

        let bytes = udp.to_bytes();
        let parsed = UdpHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.src_port(), 53);
        assert_eq!(parsed.dst_port(), 1024);
        assert_eq!(parsed.length(), 72);
    }

    #[test]
    fn test_udp_packet_forge_and_checksum() {
        let src_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let src_ip = [10, 0, 2, 15];
        let dst_mac = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
        let dst_ip = [10, 0, 2, 2];
        let payload = b"DNS Query: jamboos.dev";

        let mut out_buf = [0u8; 128];
        let total = forge_udp_packet(
            src_mac,
            src_ip,
            dst_mac,
            dst_ip,
            5353,
            53,
            payload,
            &mut out_buf,
        )
        .expect("Forge UDP réussi");

        assert_eq!(total, 14 + 20 + 8 + payload.len());

        let eth = EthernetHeader::from_bytes(&out_buf[..14]).unwrap();
        assert_eq!(eth.ethertype(), ETHERTYPE_IPV4);

        let ip = Ipv4Header::from_bytes(&out_buf[14..34]).unwrap();
        assert_eq!(ip.proto, IP_PROTO_UDP);
        assert!(verify_ipv4_checksum(&ip));

        let udp = UdpHeader::from_bytes(&out_buf[34..42]).unwrap();
        assert_eq!(udp.src_port(), 5353);
        assert_eq!(udp.dst_port(), 53);
        assert_eq!(udp.length(), (8 + payload.len()) as u16);
        assert_ne!(udp.checksum(), 0);
    }

    #[test]
    fn test_socket_table_lifecycle() {
        let mut table = SocketTable::new();

        // 1. Allouer socket UDP
        let s0 = table.alloc_socket(SocketProtocol::Udp).unwrap();
        assert_eq!(s0, 0);

        // 2. Bind sur port spécifique
        table.bind(s0, [10, 0, 2, 15], 8080).unwrap();
        let sock = table.get(s0).unwrap();
        assert!(sock.is_bound);
        assert_eq!(sock.local_port, 8080);

        // 3. Conflit de bind sur le même port/protocole
        let s1 = table.alloc_socket(SocketProtocol::Udp).unwrap();
        assert_eq!(
            table.bind(s1, [10, 0, 2, 15], 8080),
            Err(SysError::ResourceBusy)
        );

        // 4. Bind avec port éphémère automatique
        table.bind(s1, [10, 0, 2, 15], 0).unwrap();
        let sock1 = table.get(s1).unwrap();
        assert!(sock1.local_port >= 49152);

        // 5. Connect
        table.connect(s0, [10, 0, 2, 2], 53).unwrap();
        let sock0 = table.get(s0).unwrap();
        assert!(sock0.is_connected);
        assert_eq!(sock0.remote_ip, [10, 0, 2, 2]);
        assert_eq!(sock0.remote_port, 53);

        // 6. Close
        table.close(s0).unwrap();
        assert!(table.get(s0).is_none());
    }

    #[test]
    fn test_connected_udp_sockets_and_4tuple_dispatch() {
        let mut table = SocketTable::new();

        // Socket 0 : UDP lié au port 5000 (non connecté, écoute tous les flux vers 5000)
        let s0 = table.alloc_socket(SocketProtocol::Udp).unwrap();
        table.bind(s0, [10, 0, 2, 15], 5000).unwrap();

        // Socket 1 : UDP lié au port 5001 et connecté à 1.1.1.1:53
        let s1 = table.alloc_socket(SocketProtocol::Udp).unwrap();
        table.bind(s1, [10, 0, 2, 15], 5001).unwrap();
        table.connect(s1, [1, 1, 1, 1], 53).unwrap();

        // Test résolution 4-tuple :
        // 1. Paquet pour port 5001 venant de 1.1.1.1:53 -> doit matcher la socket connectée s1
        assert_eq!(table.find_udp(5001, [1, 1, 1, 1], 53), Some(s1));

        // 2. Paquet pour port 5001 venant d'une autre IP (ex: 8.8.8.8:53) -> s1 est connectée ailleurs, donc rejet/none
        assert_eq!(table.find_udp(5001, [8, 8, 8, 8], 53), None);

        // 3. Paquet pour port 5000 venant de n'importe où -> matche la socket non connectée s0
        assert_eq!(table.find_udp(5000, [8, 8, 8, 8], 53), Some(s0));
        assert_eq!(table.find_udp(5000, [1, 1, 1, 1], 53), Some(s0));

        // 4. Déconnexion de s1
        assert!(table.disconnect(s1).is_ok());
        let sock1 = table.get(s1).unwrap();
        assert!(!sock1.is_connected);
    }

    #[test]
    fn test_conntrack_stateful_filtering_new_established_timeout() {
        let mut ct = ConntrackTable::new();
        assert_eq!(ct.active_count(), 0);

        let local_ip = [10, 0, 2, 15];
        let remote_ip = [192, 168, 1, 1];
        let local_port = 54321;
        let remote_port = 8080;

        // 1. Un paquet entrant sans flux sortant préalable est rejeté par le pare-feu à état
        let allowed = ct.filter_inbound(
            SocketProtocol::Udp,
            remote_ip,
            remote_port,
            local_ip,
            local_port,
            64,
        );
        assert!(!allowed);

        // 2. Émission d'un datagramme sortant -> création de flux New
        let idx = ct
            .track_outbound(
                SocketProtocol::Udp,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                128,
            )
            .expect("track outbound");
        assert_eq!(ct.entries[idx].state, ConntrackState::New);
        assert_eq!(ct.entries[idx].packets_sent, 1);
        assert_eq!(ct.entries[idx].bytes_sent, 128);
        assert_eq!(ct.active_count(), 1);

        // 3. Paquet retour légitime -> autorisé et passage à Established
        let reply_allowed = ct.filter_inbound(
            SocketProtocol::Udp,
            remote_ip,
            remote_port,
            local_ip,
            local_port,
            256,
        );
        assert!(reply_allowed);
        assert_eq!(ct.entries[idx].state, ConntrackState::Established);
        assert_eq!(ct.entries[idx].packets_recv, 1);
        assert_eq!(ct.entries[idx].bytes_recv, 256);

        // 4. Écoulement du temps et purge après expiration
        ct.tick(301);
        assert_eq!(ct.active_count(), 0);
    }

    #[test]
    fn test_arp_table_and_spoofing_defense() {
        let gw_ip = [10, 0, 2, 2];
        let gw_mac = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
        let mut table = ArpTable::new_with_gateway(gw_ip, gw_mac);

        // 1. Consultation de la passerelle statique
        assert_eq!(table.lookup(gw_ip), Some(gw_mac));
        assert_eq!(table.static_count, 1);
        assert_eq!(table.dynamic_count, 0);

        // 2. Ajout dynamique d'un hôte légitime
        let host_ip = [10, 0, 2, 50];
        let host_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert!(table.update_dynamic(host_ip, host_mac).unwrap());
        assert_eq!(table.lookup(host_ip), Some(host_mac));
        assert_eq!(table.dynamic_count, 1);

        // 3. Tentative d'usurpation (ARP Spoofing) sur la passerelle -> Doit être bloquée !
        let rogue_mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let spoof_res = table.update_dynamic(gw_ip, rogue_mac);
        assert_eq!(spoof_res, Err(SysError::PermissionDenied));
        assert_eq!(table.spoofing_attempts_blocked, 1);
        // L'adresse de la passerelle n'a pas été altérée
        assert_eq!(table.lookup(gw_ip), Some(gw_mac));

        // 4. Rejet des adresses invalides
        assert_eq!(
            table.update_dynamic([10, 0, 2, 60], [0xFF; 6]),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            table.update_dynamic([0, 0, 0, 0], [0x12; 6]),
            Err(SysError::InvalidArgument)
        );

        // 5. Expiration TTL
        table.tick(301);
        assert_eq!(table.lookup(host_ip), None);
        assert_eq!(table.dynamic_count, 0);
        // La passerelle statique ne s'est pas évaporée
        assert_eq!(table.lookup(gw_ip), Some(gw_mac));
    }

    #[test]
    fn test_dhcp_discover_and_offer_parsing() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let xid = 0x12345678;

        // 1. Génération d'un DHCP Discover
        let mut buf = [0u8; 300];
        let len = build_dhcp_discover(mac, xid, &mut buf);
        assert_eq!(len, 244);
        assert_eq!(buf[0], DHCP_OP_BOOTREQUEST);
        assert_eq!(&buf[236..240], &DHCP_MAGIC_COOKIE);
        assert_eq!(buf[240], DHCP_OPT_MESSAGE_TYPE);
        assert_eq!(buf[242], DHCP_MSG_DISCOVER);
        assert_eq!(buf[243], DHCP_OPT_END);

        // 2. Forge d'une réponse DHCP Offer
        let mut offer_buf = [0u8; 300];
        let mut hdr = DhcpPacketHeader {
            op: DHCP_OP_BOOTREPLY,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: xid.to_be(),
            secs: 0,
            flags: 0,
            ciaddr: [0; 4],
            yiaddr: [10, 0, 2, 15],
            siaddr: [10, 0, 2, 2],
            giaddr: [0; 4],
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            magic_cookie: DHCP_MAGIC_COOKIE,
        };
        hdr.chaddr[0..6].copy_from_slice(&mac);

        // SAFETY: DhcpPacketHeader fait 240 octets, offer_buf en fait 300
        unsafe {
            core::ptr::copy_nonoverlapping(
                &hdr as *const DhcpPacketHeader as *const u8,
                offer_buf.as_mut_ptr(),
                240,
            );
        }

        // Options: Subnet Mask (10.0.2.0/24 -> 255.255.255.0)
        let mut opt_cursor = 240;
        offer_buf[opt_cursor] = DHCP_OPT_SUBNET_MASK;
        offer_buf[opt_cursor + 1] = 4;
        offer_buf[opt_cursor + 2..opt_cursor + 6].copy_from_slice(&[255, 255, 255, 0]);
        opt_cursor += 6;

        // Option: Router Gateway (10.0.2.2)
        offer_buf[opt_cursor] = DHCP_OPT_ROUTER;
        offer_buf[opt_cursor + 1] = 4;
        offer_buf[opt_cursor + 2..opt_cursor + 6].copy_from_slice(&[10, 0, 2, 2]);
        opt_cursor += 6;

        // Option: DNS Server (10.0.2.3)
        offer_buf[opt_cursor] = DHCP_OPT_DNS_SERVER;
        offer_buf[opt_cursor + 1] = 4;
        offer_buf[opt_cursor + 2..opt_cursor + 6].copy_from_slice(&[10, 0, 2, 3]);
        opt_cursor += 6;

        // Option: End
        offer_buf[opt_cursor] = DHCP_OPT_END;
        opt_cursor += 1;

        // 3. Analyse du DHCP Offer
        let parsed = parse_dhcp_offer(&offer_buf[..opt_cursor], xid).expect("parse_dhcp_offer");
        assert_eq!(parsed.yiaddr, [10, 0, 2, 15]);
        assert_eq!(parsed.server_ip, [10, 0, 2, 2]);
        assert_eq!(parsed.subnet_mask, [255, 255, 255, 0]);
        assert_eq!(parsed.router, [10, 0, 2, 2]);
        assert_eq!(parsed.dns_server, [10, 0, 2, 3]);

        // 4. Rejet avec XID erroné
        assert_eq!(
            parse_dhcp_offer(&offer_buf[..opt_cursor], 0xDEADBEEF),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn test_dns_query_encoding_and_response_parsing() {
        let domain = "gateway.local";
        let txid = 0x5678;

        // 1. Encodage d'une requête DNS (build_dns_query)
        let mut query_buf = [0u8; 128];
        let query_len = build_dns_query(domain, txid, &mut query_buf).expect("build query");

        let expected_hdr_len = 12;
        let expected_qname_len = 1 + 7 + 1 + 5 + 1; // \x07gateway\x05local\x00 = 15 octets
        let expected_tail_len = 4; // QTYPE + QCLASS
        assert_eq!(
            query_len,
            expected_hdr_len + expected_qname_len + expected_tail_len
        );

        // SAFETY: query_buf contient les 12 octets d'en-tête DNS
        let hdr = unsafe { (query_buf.as_ptr() as *const DnsHeader).read_unaligned() };
        assert_eq!(hdr.id(), txid);
        assert_eq!(hdr.flags(), DNS_FLAG_RD);
        assert_eq!(hdr.qdcount(), 1);
        assert_eq!(hdr.ancount(), 0);

        // 2. Forge d'une réponse DNS conforme RFC 1035 (1 Answer: gateway.local -> 10.0.2.2)
        let mut resp_buf = [0u8; 128];
        // En-tête (flags: QR=1, RD=1, RA=1, RCODE=0 -> 0x8180)
        let resp_hdr = DnsHeader {
            id: txid.to_be(),
            flags: (DNS_FLAG_QR_RESPONSE | DNS_FLAG_RD | DNS_FLAG_RA).to_be(),
            qdcount: 1u16.to_be(),
            ancount: 1u16.to_be(),
            nscount: 0,
            arcount: 0,
        };
        // SAFETY: Copie de l'en-tête de réponse DNS dans un tampon de taille suffisante
        unsafe {
            core::ptr::copy_nonoverlapping(
                &resp_hdr as *const DnsHeader as *const u8,
                resp_buf.as_mut_ptr(),
                12,
            );
        }

        // Copie de la section Question depuis la requête
        resp_buf[12..query_len].copy_from_slice(&query_buf[12..query_len]);
        let mut cur = query_len;

        // Section Answer :
        // Pointeur de compression vers le nom à l'offset 12 : 0xC00C
        resp_buf[cur] = 0xC0;
        resp_buf[cur + 1] = 12;
        cur += 2;

        // TYPE A (1), CLASS IN (1), TTL (300s), RDLENGTH (4)
        resp_buf[cur..cur + 2].copy_from_slice(&DNS_TYPE_A.to_be_bytes());
        cur += 2;
        resp_buf[cur..cur + 2].copy_from_slice(&DNS_CLASS_IN.to_be_bytes());
        cur += 2;
        resp_buf[cur..cur + 4].copy_from_slice(&300u32.to_be_bytes());
        cur += 4;
        resp_buf[cur..cur + 2].copy_from_slice(&4u16.to_be_bytes());
        cur += 2;

        // RDATA : 10.0.2.2
        resp_buf[cur..cur + 4].copy_from_slice(&[10, 0, 2, 2]);
        cur += 4;

        // 3. Décodage de la réponse DNS
        let resolved_ip = parse_dns_response(&resp_buf[..cur], txid).expect("parse_dns_response");
        assert_eq!(resolved_ip, [10, 0, 2, 2]);

        // 4. Test du client DNS avec cache
        let mut resolver = DnsClientResolver::new([10, 0, 2, 3]);
        assert_eq!(resolver.lookup_cache("gateway.local"), None);
        resolver.insert_cache("gateway.local", resolved_ip);
        assert_eq!(resolver.lookup_cache("gateway.local"), Some([10, 0, 2, 2]));
    }

    #[test]
    fn test_proxy_arp_lifecycle_and_forge() {
        let mut proxy_tbl = ProxyArpTable::new();
        let target_ip = [10, 0, 2, 50];
        let proxy_mac = [0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC];

        assert!(!proxy_tbl.is_proxied(target_ip));
        assert!(proxy_tbl.add_proxy(target_ip, proxy_mac));
        assert!(proxy_tbl.is_proxied(target_ip));
        assert_eq!(proxy_tbl.lookup(target_ip), Some(proxy_mac));

        // Forge ARP Request depuis un client
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client_ip = [10, 0, 2, 15];
        let req = ArpPacket::new_request(client_mac, client_ip, target_ip);

        let mut tx_buf = [0u8; 128];
        let reply_len = forge_arp_proxy_reply(proxy_mac, target_ip, &req, &mut tx_buf)
            .expect("proxy reply forged");
        assert_eq!(reply_len, 60);

        let eth = EthernetHeader::from_bytes(&tx_buf[..14]).unwrap();
        assert_eq!(eth.dst_mac, client_mac);
        assert_eq!(eth.src_mac, proxy_mac);

        let reply = ArpPacket::from_bytes(&tx_buf[14..42]).unwrap();
        assert_eq!(reply.opcode(), ARP_OPCODE_REPLY);
        assert_eq!(reply.src_ip, target_ip);
        assert_eq!(reply.src_mac, proxy_mac);
        assert_eq!(reply.dst_ip, client_ip);
        assert_eq!(reply.dst_mac, client_mac);

        // Suppression de la règle proxy
        assert!(proxy_tbl.remove_proxy(target_ip));
        assert!(!proxy_tbl.is_proxied(target_ip));
    }

    #[test]
    fn test_icmp_ping_tracker_rtt_and_expiry() {
        let mut tracker = IcmpPingTracker::new();
        let target_ip = [10, 0, 2, 2];

        // 1. Enregistrement de 2 requêtes
        tracker.record_sent(0x1337, 1, target_ip, 1000);
        tracker.record_sent(0x1337, 2, target_ip, 1010);
        assert_eq!(tracker.metrics.packets_sent, 2);

        // 2. Réception du reply pour seq 1 après 15 ticks
        let rtt1 = tracker
            .record_reply(0x1337, 1, 1015)
            .expect("valid reply seq 1");
        assert_eq!(rtt1, 15);
        assert_eq!(tracker.metrics.packets_received, 1);
        assert_eq!(tracker.metrics.min_rtt_ticks, 15);
        assert_eq!(tracker.metrics.max_rtt_ticks, 15);

        // 3. Expiration du seq 2 avec timeout de 50 ticks au temps 1100
        let expired = tracker.expire_older_than(1100, 50);
        assert_eq!(expired, 1);
        assert_eq!(tracker.metrics.packets_lost, 1);
    }

    #[test]
    fn test_bpf_filter_table_dynamic_reload_and_filtering() {
        let mut filter = BpfFilterTable::new();
        assert_eq!(filter.generation, 1);
        assert_eq!(filter.rule_count, 0);

        // Forge un paquet UDP vers 10.0.2.15 port 53 (DNS)
        let mut pkt_dns = [0u8; 42];
        // Ethernet header (14 bytes)
        pkt_dns[0..6].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        pkt_dns[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt_dns[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
                                                                   // IPv4 header (20 bytes)
        pkt_dns[14] = 0x45; // Version 4, IHL 5
        pkt_dns[23] = IP_PROTO_UDP; // Proto UDP
        pkt_dns[26..30].copy_from_slice(&[10, 0, 2, 2]); // src_ip
        pkt_dns[30..34].copy_from_slice(&[10, 0, 2, 15]); // dst_ip
                                                          // UDP header (8 bytes)
        pkt_dns[34..36].copy_from_slice(&5353u16.to_be_bytes()); // src_port
        pkt_dns[36..38].copy_from_slice(&53u16.to_be_bytes()); // dst_port = 53

        // 1. Initialement sans règles : Pass
        assert_eq!(filter.evaluate_packet(&pkt_dns), BpfFilterAction::Pass);
        assert_eq!(filter.total_passed, 1);
        assert_eq!(filter.total_dropped, 0);

        // 2. Ajout d'une règle de blocage UDP port 53
        let rule_block_dns = BpfFilterRule::new(
            1,
            IP_PROTO_UDP,
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            53,
            BpfFilterAction::Drop,
        );
        filter.add_rule(rule_block_dns).expect("add rule");
        assert_eq!(filter.rule_count, 1);
        assert_eq!(filter.generation, 2);

        // 3. Évaluation après règle : doit être DROP
        assert_eq!(filter.evaluate_packet(&pkt_dns), BpfFilterAction::Drop);
        assert_eq!(filter.total_dropped, 1);
        assert_eq!(filter.rules[0].hit_count, 1);

        // Paquet sur un autre port (ex: UDP 123 NTP) : doit PASS
        let mut pkt_ntp = pkt_dns;
        pkt_ntp[36..38].copy_from_slice(&123u16.to_be_bytes());
        assert_eq!(filter.evaluate_packet(&pkt_ntp), BpfFilterAction::Pass);

        // 4. Rechargement dynamique (remplacement par politique autorisant tout)
        let empty_rules: [BpfFilterRule; 0] = [];
        let reloaded = filter.reload_rules(&empty_rules);
        assert_eq!(reloaded, 0);
        assert_eq!(filter.generation, 3);
        assert_eq!(filter.rule_count, 0);

        // 5. Après rechargement : le paquet DNS passe à nouveau
        assert_eq!(filter.evaluate_packet(&pkt_dns), BpfFilterAction::Pass);
    }

    #[test]
    fn test_nat_table_snat_dnat_and_expiration() {
        let mut nat = NatTable::new([10, 0, 2, 15]);
        assert_eq!(nat.active_count, 0);
        assert_eq!(nat.total_translations, 0);

        // 1. SNAT Sortant : client local 192.168.1.50:12345 vers 8.8.8.8:53
        let out1 = nat.translate_outbound(
            NatProtocol::Udp,
            [192, 168, 1, 50],
            12345,
            [8, 8, 8, 8],
            53,
            1000,
            64,
        );
        assert!(out1.is_some());
        let (pub_ip, ext_port) = out1.unwrap();
        assert_eq!(pub_ip, [10, 0, 2, 15]);
        assert_eq!(ext_port, NAT_EPHEMERAL_PORT_MIN);
        assert_eq!(nat.active_count, 1);
        assert_eq!(nat.total_translations, 1);

        // 2. Deuxième paquet du même flux -> même port externe réutilisé
        let out2 = nat.translate_outbound(
            NatProtocol::Udp,
            [192, 168, 1, 50],
            12345,
            [8, 8, 8, 8],
            53,
            1005,
            128,
        );
        assert_eq!(out2, Some(([10, 0, 2, 15], NAT_EPHEMERAL_PORT_MIN)));
        assert_eq!(nat.active_count, 1);
        assert_eq!(nat.total_translations, 2);

        // 3. Translation entrante (Reverse SNAT) : réponse reçue depuis 8.8.8.8:53 vers 10.0.2.15:49152
        let in1 = nat.translate_inbound(
            NatProtocol::Udp,
            NAT_EPHEMERAL_PORT_MIN,
            [8, 8, 8, 8],
            53,
            1006,
            96,
        );
        assert_eq!(in1, Some(([192, 168, 1, 50], 12345)));
        assert_eq!(nat.total_translations, 3);

        // Réponse d'un serveur tiers non attendu -> rejet (None)
        let in_spoofed = nat.translate_inbound(
            NatProtocol::Udp,
            NAT_EPHEMERAL_PORT_MIN,
            [1, 1, 1, 1],
            53,
            1007,
            96,
        );
        assert_eq!(in_spoofed, None);

        // 4. DNAT Statique (Port Forwarding) : port externe 8080 vers serveur web 192.168.1.80:80
        assert!(nat
            .add_port_forward(NatProtocol::Tcp, 8080, [192, 168, 1, 80], 80)
            .is_ok());
        assert_eq!(nat.active_count, 2);

        // Connexion entrante sur le port redirigé depuis n'importe quel client Internet
        let dnat_in =
            nat.translate_inbound(NatProtocol::Tcp, 8080, [203, 0, 113, 4], 54321, 1010, 40);
        assert_eq!(dnat_in, Some(([192, 168, 1, 80], 80)));

        // 5. Expiration des liaisons inactives
        // À t = 1000 + 350 = 1350, le flux sortant (dernier t = 1006) est inactif depuis > 300s
        let expired = nat.expire_idle_bindings(1350, 300);
        assert_eq!(expired, 1);
        assert_eq!(nat.active_count, 1); // La règle DNAT statique reste active

        // Le port éphémère ne répond plus
        let in_expired = nat.translate_inbound(
            NatProtocol::Udp,
            NAT_EPHEMERAL_PORT_MIN,
            [8, 8, 8, 8],
            53,
            1351,
            96,
        );
        assert_eq!(in_expired, None);
    }
}

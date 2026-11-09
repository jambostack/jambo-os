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
}

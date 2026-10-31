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

        let mut rx_msg = ChannelMessage::default();
        let (ret, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.endpoint.0,
                &tx_msg as *const ChannelMessage as u64,
                &mut rx_msg as *mut ChannelMessage as u64,
                0,
                0,
                0,
            )
        };

        if ret != 0 {
            return Err(SysError::TimedOut);
        }

        NetResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]).ok_or(SysError::InvalidArgument)
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
}

//! Démon de Pare-Feu Distribué Dynamique & Synchronisation Conntrack (`jambo-walld`)
//!
//! Fournit un sous-système de pare-feu d'état (Stateful Firewall) haute performance en `#![no_std]`,
//! avec table de suivi de connexions (Conntrack) synchronisée entre les nœuds de la grappe,
//! filtrage adaptatif Zero-Trust, détection d'anomalies réseau (scans XMAS/NULL/SYN),
//! auto-blocage dynamique et contrôle d'accès capabilaire strict via `WallCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_CONNTRACK_ENTRIES: usize = 128;
pub const MAX_RULES: usize = 64;
pub const MAX_NAME_LEN: usize = 32;

pub const TIMEOUT_TCP_SYN_SENT: u64 = 60;
pub const TIMEOUT_TCP_ESTABLISHED: u64 = 3600;
pub const TIMEOUT_TCP_CLOSING: u64 = 120;
pub const TIMEOUT_UDP_GENERIC: u64 = 180;
pub const TIMEOUT_ICMP_GENERIC: u64 = 30;
pub const DYNAMIC_BLOCK_TIMEOUT: u64 = 600;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 & AUTHENTIFICATION DE MESSAGE (HMAC)
// ============================================================================

/// Implémentation SHA-256 standard `#![no_std]` sans allocation
#[derive(Clone, Copy)]
pub struct Sha256;

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn gamma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn gamma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = Self::gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(Self::gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut state = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let rem = data.len() - offset;
        for i in 0..rem {
            block[i] = data[offset + i];
        }
        block[rem] = 0x80;

        if rem + 1 <= 56 {
            for i in (rem + 1)..56 {
                block[i] = 0;
            }
            block[56..64].copy_from_slice(&bit_len.to_be_bytes());
            Self::process_block(&mut state, &block);
        } else {
            for i in (rem + 1)..64 {
                block[i] = 0;
            }
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
            block[56..64].copy_from_slice(&bit_len.to_be_bytes());
            Self::process_block(&mut state, &block);
        }

        let mut out = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Calcul d'étiquette d'intégrité HMAC-SHA256 tronquée à 16 octets
pub fn compute_hmac_tag(key: &[u8; 32], payload: &[u8]) -> [u8; 16] {
    let mut k_ipad = [0x36u8; 64];
    let mut k_opad = [0x5cu8; 64];

    for i in 0..32 {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    // Inner hash: SHA256(k_ipad || payload)
    let mut inner_buf = [0u8; 64 + 128];
    let plen = payload.len().min(128);
    inner_buf[..64].copy_from_slice(&k_ipad);
    inner_buf[64..64 + plen].copy_from_slice(&payload[..plen]);
    let inner_hash = Sha256::digest(&inner_buf[..64 + plen]);

    // Outer hash: SHA256(k_opad || inner_hash)
    let mut outer_buf = [0u8; 64 + 32];
    outer_buf[..64].copy_from_slice(&k_opad);
    outer_buf[64..96].copy_from_slice(&inner_hash);
    let outer_hash = Sha256::digest(&outer_buf);

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&outer_hash[..16]);
    tag
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (WallCap)
// ============================================================================

pub mod wall_rights {
    pub const WALL_INSPECT: u32 = 0x01;
    pub const WALL_RULE_MANAGE: u32 = 0x02;
    pub const WALL_CONNTRACK_SYNC: u32 = 0x04;
    pub const WALL_FILTER: u32 = 0x08;
    pub const WALL_ZONE_MANAGE: u32 = 0x10;
    pub const WALL_ADMIN: u32 = 0x80;
    pub const ALL: u32 = WALL_INSPECT
        | WALL_RULE_MANAGE
        | WALL_CONNTRACK_SYNC
        | WALL_FILTER
        | WALL_ZONE_MANAGE
        | WALL_ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallCap {
    pub handle: Handle,
    pub rights: u32,
}

impl WallCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(&self, new_rights: u32) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// PROTOCOLES, ZONES DE SÉCURITÉ ET ACTIONS
// ============================================================================

pub mod ip_proto {
    pub const ANY: u8 = 0;
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityZone {
    ClusterInternal = 0,
    WorkloadEdge = 1,
    HostKernel = 2,
    ExternalUntrusted = 3,
}

impl SecurityZone {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClusterInternal => "ClusterInternal",
            Self::WorkloadEdge => "WorkloadEdge",
            Self::HostKernel => "HostKernel",
            Self::ExternalUntrusted => "ExternalUntrusted",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "internal" | "ClusterInternal" => Some(Self::ClusterInternal),
            "edge" | "workload" | "WorkloadEdge" => Some(Self::WorkloadEdge),
            "kernel" | "host" | "HostKernel" => Some(Self::HostKernel),
            "external" | "untrusted" | "ExternalUntrusted" => Some(Self::ExternalUntrusted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallAction {
    Allow = 0,
    Drop = 1,
    Reject = 2,
    RateLimit = 3,
}

impl WallAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Drop => "DROP",
            Self::Reject => "REJECT",
            Self::RateLimit => "RATELIMIT",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "allow" | "ALLOW" => Some(Self::Allow),
            "drop" | "DROP" => Some(Self::Drop),
            "reject" | "REJECT" => Some(Self::Reject),
            "limit" | "ratelimit" => Some(Self::RateLimit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackState {
    New = 0,
    Established = 1,
    Related = 2,
    Closing = 3,
    Closed = 4,
    Invalid = 5,
}

impl ConntrackState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "NEW",
            Self::Established => "ESTABLISHED",
            Self::Related => "RELATED",
            Self::Closing => "CLOSING",
            Self::Closed => "CLOSED",
            Self::Invalid => "INVALID",
        }
    }

    pub fn to_mask(&self) -> u8 {
        match self {
            Self::New => 0x01,
            Self::Established => 0x02,
            Self::Related => 0x04,
            Self::Closing => 0x08,
            Self::Closed => 0x10,
            Self::Invalid => 0x20,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFsm {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait,
    CloseWait,
    TimeWait,
}

/// Valide les drapeaux TCP pour détecter les paquets malicieux (Scans XMAS, NULL, SYN/FIN)
pub fn is_valid_tcp_flags(flags: u8) -> bool {
    // NULL scan: aucun drapeau activé
    if flags == 0 {
        return false;
    }
    // SYN + FIN interdit
    if (flags & (tcp_flags::SYN | tcp_flags::FIN)) == (tcp_flags::SYN | tcp_flags::FIN) {
        return false;
    }
    // SYN + RST interdit
    if (flags & (tcp_flags::SYN | tcp_flags::RST)) == (tcp_flags::SYN | tcp_flags::RST) {
        return false;
    }
    // FIN + RST interdit
    if (flags & (tcp_flags::FIN | tcp_flags::RST)) == (tcp_flags::FIN | tcp_flags::RST) {
        return false;
    }
    // XMAS Scan : FIN + PSH + URG sans ACK
    if (flags & (tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG))
        == (tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG)
        && (flags & tcp_flags::ACK) == 0
    {
        return false;
    }
    true
}

// ============================================================================
// TABLE DE SUIVI DE CONNEXIONS (Conntrack)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConntrackTuple {
    pub proto: u8,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
}

impl ConntrackTuple {
    pub const fn new(
        proto: u8,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            proto,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            proto: self.proto,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.proto == other.proto
            && self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConntrackEntry {
    pub tuple: ConntrackTuple,
    pub state: ConntrackState,
    pub tcp_fsm: TcpFsm,
    pub src_zone: SecurityZone,
    pub dst_zone: SecurityZone,
    pub orig_packets: u64,
    pub orig_bytes: u64,
    pub reply_packets: u64,
    pub reply_bytes: u64,
    pub created_tick: u64,
    pub last_seen_tick: u64,
    pub timeout_ticks: u64,
    pub origin_node_id: u64,
    pub is_active: bool,
    pub synced_to_cluster: bool,
}

impl ConntrackEntry {
    pub const fn empty() -> Self {
        Self {
            tuple: ConntrackTuple::new(0, [0; 4], [0; 4], 0, 0),
            state: ConntrackState::Invalid,
            tcp_fsm: TcpFsm::Closed,
            src_zone: SecurityZone::ClusterInternal,
            dst_zone: SecurityZone::ClusterInternal,
            orig_packets: 0,
            orig_bytes: 0,
            reply_packets: 0,
            reply_bytes: 0,
            created_tick: 0,
            last_seen_tick: 0,
            timeout_ticks: 0,
            origin_node_id: 0,
            is_active: false,
            synced_to_cluster: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConntrackTable {
    pub entries: [ConntrackEntry; MAX_CONNTRACK_ENTRIES],
}

impl ConntrackTable {
    pub const fn new() -> Self {
        Self {
            entries: [ConntrackEntry::empty(); MAX_CONNTRACK_ENTRIES],
        }
    }

    pub fn active_count(&self) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < MAX_CONNTRACK_ENTRIES {
            if self.entries[i].is_active {
                count += 1;
            }
            i += 1;
        }
        count
    }

    pub fn lookup(&self, tuple: &ConntrackTuple) -> Option<(usize, bool /* is_reply */)> {
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.is_active {
                if entry.tuple.matches(tuple) {
                    return Some((idx, false));
                }
                if entry.tuple.reverse().matches(tuple) {
                    return Some((idx, true));
                }
            }
        }
        None
    }

    pub fn purge_expired(&mut self, current_tick: u64) -> usize {
        let mut purged = 0;
        for entry in self.entries.iter_mut() {
            if entry.is_active {
                if current_tick >= entry.last_seen_tick + entry.timeout_ticks {
                    entry.is_active = false;
                    purged += 1;
                }
            }
        }
        purged
    }

    pub fn allocate_slot(&mut self) -> Result<usize, SysError> {
        for (idx, entry) in self.entries.iter().enumerate() {
            if !entry.is_active {
                return Ok(idx);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Analyse et met à jour l'état de la connexion selon les paquets et drapeaux TCP
    pub fn process_packet(
        &mut self,
        tuple: &ConntrackTuple,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        tcp_flags: u8,
        payload_len: usize,
        tick: u64,
        node_id: u64,
    ) -> (
        ConntrackState,
        bool, /* is_reply */
        bool, /* state_changed */
    ) {
        if tuple.proto == ip_proto::TCP && !is_valid_tcp_flags(tcp_flags) {
            return (ConntrackState::Invalid, false, false);
        }

        if let Some((idx, is_reply)) = self.lookup(tuple) {
            let entry = &mut self.entries[idx];
            let mut state_changed = false;
            let prev_state = entry.state;

            if is_reply {
                entry.reply_packets += 1;
                entry.reply_bytes += payload_len as u64;
            } else {
                entry.orig_packets += 1;
                entry.orig_bytes += payload_len as u64;
            }
            entry.last_seen_tick = tick;

            if tuple.proto == ip_proto::TCP {
                let has_syn = (tcp_flags & tcp_flags::SYN) != 0;
                let has_ack = (tcp_flags & tcp_flags::ACK) != 0;
                let has_fin = (tcp_flags & tcp_flags::FIN) != 0;
                let has_rst = (tcp_flags & tcp_flags::RST) != 0;

                if has_rst {
                    entry.state = ConntrackState::Closed;
                    entry.tcp_fsm = TcpFsm::Closed;
                    entry.timeout_ticks = 10;
                } else if has_fin {
                    entry.state = ConntrackState::Closing;
                    entry.tcp_fsm = TcpFsm::FinWait;
                    entry.timeout_ticks = TIMEOUT_TCP_CLOSING;
                } else {
                    match entry.tcp_fsm {
                        TcpFsm::SynSent if is_reply && has_syn && has_ack => {
                            entry.tcp_fsm = TcpFsm::SynReceived;
                            entry.state = ConntrackState::New;
                        }
                        TcpFsm::SynReceived if !is_reply && has_ack => {
                            entry.tcp_fsm = TcpFsm::Established;
                            entry.state = ConntrackState::Established;
                            entry.timeout_ticks = TIMEOUT_TCP_ESTABLISHED;
                        }
                        TcpFsm::SynSent if !is_reply && has_ack => {
                            // Fast handshake
                            entry.tcp_fsm = TcpFsm::Established;
                            entry.state = ConntrackState::Established;
                            entry.timeout_ticks = TIMEOUT_TCP_ESTABLISHED;
                        }
                        _ => {}
                    }
                }
            } else if tuple.proto == ip_proto::UDP {
                if is_reply && entry.state == ConntrackState::New {
                    entry.state = ConntrackState::Established;
                }
            }

            if entry.state != prev_state {
                state_changed = true;
            }
            (entry.state, is_reply, state_changed)
        } else {
            // Nouvelle session
            let slot = match self.allocate_slot() {
                Ok(s) => s,
                Err(_) => return (ConntrackState::Invalid, false, false),
            };

            let (initial_state, fsm, timeout) = if tuple.proto == ip_proto::TCP {
                let has_syn = (tcp_flags & tcp_flags::SYN) != 0;
                if has_syn {
                    (ConntrackState::New, TcpFsm::SynSent, TIMEOUT_TCP_SYN_SENT)
                } else {
                    // Paquet hors session
                    return (ConntrackState::Invalid, false, false);
                }
            } else if tuple.proto == ip_proto::UDP {
                (
                    ConntrackState::New,
                    TcpFsm::Established,
                    TIMEOUT_UDP_GENERIC,
                )
            } else {
                (
                    ConntrackState::New,
                    TcpFsm::Established,
                    TIMEOUT_ICMP_GENERIC,
                )
            };

            self.entries[slot] = ConntrackEntry {
                tuple: *tuple,
                state: initial_state,
                tcp_fsm: fsm,
                src_zone,
                dst_zone,
                orig_packets: 1,
                orig_bytes: payload_len as u64,
                reply_packets: 0,
                reply_bytes: 0,
                created_tick: tick,
                last_seen_tick: tick,
                timeout_ticks: timeout,
                origin_node_id: node_id,
                is_active: true,
                synced_to_cluster: false,
            };

            (initial_state, false, true)
        }
    }
}

// ============================================================================
// SYNCHRONISATION D'ÉTATS INTER-NŒUDS (Cluster Sync)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncEventType {
    NewSession = 1,
    StateUpdate = 2,
    DestroySession = 3,
    Heartbeat = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct ConntrackSyncEvent {
    pub event_type: SyncEventType,
    pub tuple: ConntrackTuple,
    pub state: ConntrackState,
    pub src_zone: SecurityZone,
    pub dst_zone: SecurityZone,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub origin_node_id: u64,
    pub seq: u64,
    pub auth_tag: [u8; 16],
}

impl ConntrackSyncEvent {
    pub fn serialize_payload(&self, buf: &mut [u8; 64]) {
        buf[0] = self.event_type as u8;
        buf[1] = self.tuple.proto;
        buf[2..6].copy_from_slice(&self.tuple.src_ip);
        buf[6..10].copy_from_slice(&self.tuple.dst_ip);
        buf[10..12].copy_from_slice(&self.tuple.src_port.to_be_bytes());
        buf[12..14].copy_from_slice(&self.tuple.dst_port.to_be_bytes());
        buf[14] = self.state as u8;
        buf[15] = self.src_zone as u8;
        buf[16] = self.dst_zone as u8;
        buf[17..25].copy_from_slice(&self.packets_total.to_be_bytes());
        buf[25..33].copy_from_slice(&self.bytes_total.to_be_bytes());
        buf[33..41].copy_from_slice(&self.origin_node_id.to_be_bytes());
        buf[41..49].copy_from_slice(&self.seq.to_be_bytes());
    }

    pub fn compute_tag(&self, key: &[u8; 32]) -> [u8; 16] {
        let mut buf = [0u8; 64];
        self.serialize_payload(&mut buf);
        compute_hmac_tag(key, &buf[..49])
    }

    pub fn verify(&self, key: &[u8; 32]) -> bool {
        let expected = self.compute_tag(key);
        expected == self.auth_tag
    }
}

// ============================================================================
// RÈGLES DE PARE-FEU & FILTRAGE DYNAMIQUE ZERO-TRUST
// ============================================================================

fn ip_matches_cidr(ip: [u8; 4], prefix: [u8; 4], mask_len: u8) -> bool {
    if mask_len == 0 {
        return true;
    }
    let ip_u32 = u32::from_be_bytes(ip);
    let prefix_u32 = u32::from_be_bytes(prefix);
    let shift = 32 - mask_len.min(32);
    let mask = if shift >= 32 { 0 } else { (!0u32) << shift };
    (ip_u32 & mask) == (prefix_u32 & mask)
}

#[derive(Debug, Clone, Copy)]
pub struct WallRule {
    pub id: u32,
    pub priority: u16,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub src_zone: Option<SecurityZone>,
    pub dst_zone: Option<SecurityZone>,
    pub src_ip_prefix: Option<([u8; 4], u8)>,
    pub dst_ip_prefix: Option<([u8; 4], u8)>,
    pub proto: Option<u8>,
    pub src_port_range: Option<(u16, u16)>,
    pub dst_port_range: Option<(u16, u16)>,
    pub state_mask: u8,
    pub action: WallAction,
    pub hit_count: u64,
    pub byte_count: u64,
    pub is_dynamic_block: bool,
    pub expires_at_tick: Option<u64>,
    pub is_active: bool,
}

impl WallRule {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            priority: 100,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            src_zone: None,
            dst_zone: None,
            src_ip_prefix: None,
            dst_ip_prefix: None,
            proto: None,
            src_port_range: None,
            dst_port_range: None,
            state_mask: 0xFF,
            action: WallAction::Drop,
            hit_count: 0,
            byte_count: 0,
            is_dynamic_block: false,
            expires_at_tick: None,
            is_active: false,
        }
    }

    pub fn set_name(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }

    pub fn name_as_str(&self) -> &str {
        if self.name_len == 0 {
            "unnamed"
        } else {
            core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("invalid")
        }
    }

    pub fn matches(
        &self,
        tuple: &ConntrackTuple,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        state: ConntrackState,
        tick: u64,
    ) -> bool {
        if !self.is_active {
            return false;
        }
        if let Some(exp) = self.expires_at_tick {
            if tick >= exp {
                return false;
            }
        }
        if (self.state_mask & state.to_mask()) == 0 {
            return false;
        }
        if let Some(sz) = self.src_zone {
            if sz != src_zone {
                return false;
            }
        }
        if let Some(dz) = self.dst_zone {
            if dz != dst_zone {
                return false;
            }
        }
        if let Some((sip, mask)) = self.src_ip_prefix {
            if !ip_matches_cidr(tuple.src_ip, sip, mask) {
                return false;
            }
        }
        if let Some((dip, mask)) = self.dst_ip_prefix {
            if !ip_matches_cidr(tuple.dst_ip, dip, mask) {
                return false;
            }
        }
        if let Some(p) = self.proto {
            if p != tuple.proto && p != ip_proto::ANY {
                return false;
            }
        }
        if let Some((min_sp, max_sp)) = self.src_port_range {
            if tuple.src_port < min_sp || tuple.src_port > max_sp {
                return false;
            }
        }
        if let Some((min_dp, max_dp)) = self.dst_port_range {
            if tuple.dst_port < min_dp || tuple.dst_port > max_dp {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketFilterInput {
    pub tuple: ConntrackTuple,
    pub src_zone: SecurityZone,
    pub dst_zone: SecurityZone,
    pub tcp_flags: u8,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct WallStats {
    pub packets_evaluated: u64,
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub packets_rejected: u64,
    pub conntrack_fastpath_hits: u64,
    pub sync_events_sent: u64,
    pub sync_events_received: u64,
    pub threats_detected: u64,
    pub dynamic_blocks_created: u64,
}

// ============================================================================
// DÉMON DU PARE-FEU DISTRIBUÉ (JamboWallDaemon)
// ============================================================================

#[derive(Debug)]
pub struct JamboWallDaemon {
    pub node_id: u64,
    pub cap: WallCap,
    pub conntrack: ConntrackTable,
    pub rules: [WallRule; MAX_RULES],
    pub rule_count: usize,
    pub next_rule_id: u32,
    pub sync_key: [u8; 32],
    pub zero_trust_strict: bool,
    pub emergency_lockdown: bool,
    pub sync_seq: u64,
    pub stats: WallStats,
}

impl JamboWallDaemon {
    pub fn new(node_id: u64, cap: WallCap, sync_key: [u8; 32]) -> Self {
        Self {
            node_id,
            cap,
            conntrack: ConntrackTable::new(),
            rules: [WallRule::empty(); MAX_RULES],
            rule_count: 0,
            next_rule_id: 1,
            sync_key,
            zero_trust_strict: true,
            emergency_lockdown: false,
            sync_seq: 1,
            stats: WallStats {
                packets_evaluated: 0,
                packets_allowed: 0,
                packets_dropped: 0,
                packets_rejected: 0,
                conntrack_fastpath_hits: 0,
                sync_events_sent: 0,
                sync_events_received: 0,
                threats_detected: 0,
                dynamic_blocks_created: 0,
            },
        }
    }

    pub fn init_defaults(&mut self) {
        // Règle 1: Fast-path d'état pour ESTABLISHED et RELATED (Prio 10)
        let mut r1 = WallRule::empty();
        r1.id = self.next_rule_id;
        self.next_rule_id += 1;
        r1.priority = 10;
        r1.set_name("state_established_fastpath");
        r1.state_mask = ConntrackState::Established.to_mask() | ConntrackState::Related.to_mask();
        r1.action = WallAction::Allow;
        r1.is_active = true;
        self.rules[0] = r1;
        self.rule_count = 1;

        // Règle 2: Communication interne inter-nœuds du cluster (Prio 20)
        let mut r2 = WallRule::empty();
        r2.id = self.next_rule_id;
        self.next_rule_id += 1;
        r2.priority = 20;
        r2.set_name("allow_cluster_internal");
        r2.src_zone = Some(SecurityZone::ClusterInternal);
        r2.dst_zone = Some(SecurityZone::ClusterInternal);
        r2.action = WallAction::Allow;
        r2.is_active = true;
        self.rules[1] = r2;
        self.rule_count = 2;

        // Règle 3: Sortie Workload -> DNS & Services du Cluster (Prio 30)
        let mut r3 = WallRule::empty();
        r3.id = self.next_rule_id;
        self.next_rule_id += 1;
        r3.priority = 30;
        r3.set_name("workload_to_dns_rpc");
        r3.src_zone = Some(SecurityZone::WorkloadEdge);
        r3.dst_zone = Some(SecurityZone::ClusterInternal);
        r3.dst_port_range = Some((53, 7800));
        r3.action = WallAction::Allow;
        r3.is_active = true;
        self.rules[2] = r3;
        self.rule_count = 3;

        // Règle 4: Ingress externe vers Edge Web HTTP/HTTPS (Prio 40)
        let mut r4 = WallRule::empty();
        r4.id = self.next_rule_id;
        self.next_rule_id += 1;
        r4.priority = 40;
        r4.set_name("external_ingress_web");
        r4.src_zone = Some(SecurityZone::ExternalUntrusted);
        r4.dst_zone = Some(SecurityZone::WorkloadEdge);
        r4.proto = Some(ip_proto::TCP);
        r4.dst_port_range = Some((80, 443));
        r4.action = WallAction::Allow;
        r4.is_active = true;
        self.rules[3] = r4;
        self.rule_count = 4;

        // Règle 5: Noyau hôte vers n'importe quelle zone (Prio 50)
        let mut r5 = WallRule::empty();
        r5.id = self.next_rule_id;
        self.next_rule_id += 1;
        r5.priority = 50;
        r5.set_name("host_kernel_egress");
        r5.src_zone = Some(SecurityZone::HostKernel);
        r5.action = WallAction::Allow;
        r5.is_active = true;
        self.rules[4] = r5;
        self.rule_count = 5;
    }

    pub fn add_rule(&mut self, cap: &WallCap, mut rule: WallRule) -> Result<u32, SysError> {
        if !cap.has_right(wall_rights::WALL_RULE_MANAGE) {
            return Err(SysError::PermissionDenied);
        }
        if self.rule_count >= MAX_RULES {
            return Err(SysError::OutOfMemory);
        }

        let assigned_id = self.next_rule_id;
        self.next_rule_id += 1;
        rule.id = assigned_id;
        rule.is_active = true;

        // Insertion ordonnée par priorité croissante (0 = priorité absolue)
        let mut insert_pos = self.rule_count;
        for i in 0..self.rule_count {
            if rule.priority < self.rules[i].priority {
                insert_pos = i;
                break;
            }
        }

        let mut j = self.rule_count;
        while j > insert_pos {
            self.rules[j] = self.rules[j - 1];
            j -= 1;
        }

        self.rules[insert_pos] = rule;
        self.rule_count += 1;
        Ok(assigned_id)
    }

    pub fn delete_rule(&mut self, cap: &WallCap, rule_id: u32) -> Result<(), SysError> {
        if !cap.has_right(wall_rights::WALL_RULE_MANAGE) {
            return Err(SysError::PermissionDenied);
        }
        let mut found = None;
        for (i, r) in self.rules[..self.rule_count].iter().enumerate() {
            if r.id == rule_id {
                found = Some(i);
                break;
            }
        }

        if let Some(idx) = found {
            for j in idx..self.rule_count - 1 {
                self.rules[j] = self.rules[j + 1];
            }
            self.rules[self.rule_count - 1] = WallRule::empty();
            self.rule_count -= 1;
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    pub fn set_lockdown(&mut self, cap: &WallCap, enabled: bool) -> Result<(), SysError> {
        if !cap.has_right(wall_rights::WALL_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        self.emergency_lockdown = enabled;
        Ok(())
    }

    pub fn set_zero_trust(&mut self, cap: &WallCap, strict: bool) -> Result<(), SysError> {
        if !cap.has_right(wall_rights::WALL_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        self.zero_trust_strict = strict;
        Ok(())
    }

    pub fn trigger_dynamic_block(
        &mut self,
        malicious_ip: [u8; 4],
        reason: &str,
        current_tick: u64,
    ) -> Result<u32, SysError> {
        self.stats.threats_detected += 1;
        self.stats.dynamic_blocks_created += 1;

        let mut block_rule = WallRule::empty();
        block_rule.priority = 0; // Priorité maximale (outrepasse les autorisations)
        block_rule.set_name(reason);
        block_rule.src_ip_prefix = Some((malicious_ip, 32));
        block_rule.action = WallAction::Drop;
        block_rule.is_dynamic_block = true;
        block_rule.expires_at_tick = Some(current_tick + DYNAMIC_BLOCK_TIMEOUT);

        let cap = self.cap;
        self.add_rule(&cap, block_rule)
    }

    /// Filtre un paquet réseau en évaluant la table conntrack et les règles Zero-Trust
    pub fn filter_packet(
        &mut self,
        cap: &WallCap,
        pkt: &PacketFilterInput,
        tick: u64,
    ) -> Result<WallAction, SysError> {
        if !cap.has_right(wall_rights::WALL_FILTER) {
            return Err(SysError::PermissionDenied);
        }

        self.stats.packets_evaluated += 1;

        // 1. Verrouillage d'urgence (Emergency Lockdown)
        if self.emergency_lockdown {
            // Seul le trafic interne du noyau est toléré
            if pkt.src_zone != SecurityZone::HostKernel {
                self.stats.packets_dropped += 1;
                return Ok(WallAction::Drop);
            }
        }

        // 2. Évaluation de la table Conntrack
        let (conn_state, _is_reply, _state_changed) = self.conntrack.process_packet(
            &pkt.tuple,
            pkt.src_zone,
            pkt.dst_zone,
            pkt.tcp_flags,
            pkt.payload_len,
            tick,
            self.node_id,
        );

        // Si le paquet est invalide (Scan XMAS/NULL/Drapeaux illégaux) -> Blocage adaptatif immédiat
        if conn_state == ConntrackState::Invalid {
            let _ = self.trigger_dynamic_block(pkt.tuple.src_ip, "threat_invalid_tcp_flags", tick);
            self.stats.packets_dropped += 1;
            return Ok(WallAction::Drop);
        }

        // Fast-path : Si la connexion est déjà établie et reconnue, autoriser immédiatement
        if conn_state == ConntrackState::Established {
            self.stats.conntrack_fastpath_hits += 1;
            self.stats.packets_allowed += 1;
            return Ok(WallAction::Allow);
        }

        // 3. Évaluation déterministe des règles filtrantes
        for r in self.rules[..self.rule_count].iter_mut() {
            if r.matches(&pkt.tuple, pkt.src_zone, pkt.dst_zone, conn_state, tick) {
                r.hit_count += 1;
                r.byte_count += pkt.payload_len as u64;

                match r.action {
                    WallAction::Allow => {
                        self.stats.packets_allowed += 1;
                        return Ok(WallAction::Allow);
                    }
                    WallAction::Drop => {
                        self.stats.packets_dropped += 1;
                        return Ok(WallAction::Drop);
                    }
                    WallAction::Reject => {
                        self.stats.packets_rejected += 1;
                        return Ok(WallAction::Reject);
                    }
                    WallAction::RateLimit => {
                        self.stats.packets_allowed += 1;
                        return Ok(WallAction::RateLimit);
                    }
                }
            }
        }

        // 4. Décision Zero-Trust par défaut : Déni
        if self.zero_trust_strict {
            self.stats.packets_dropped += 1;
            Ok(WallAction::Drop)
        } else {
            self.stats.packets_allowed += 1;
            Ok(WallAction::Allow)
        }
    }

    /// Génère un événement de synchronisation cryptographiquement scellé pour la grappe
    pub fn generate_sync_event(
        &mut self,
        cap: &WallCap,
        tuple: &ConntrackTuple,
    ) -> Result<ConntrackSyncEvent, SysError> {
        if !cap.has_right(wall_rights::WALL_CONNTRACK_SYNC) {
            return Err(SysError::PermissionDenied);
        }

        let (idx, _) = self
            .conntrack
            .lookup(tuple)
            .ok_or(SysError::InvalidArgument)?;
        let entry = &self.conntrack.entries[idx];

        let mut event = ConntrackSyncEvent {
            event_type: SyncEventType::StateUpdate,
            tuple: entry.tuple,
            state: entry.state,
            src_zone: entry.src_zone,
            dst_zone: entry.dst_zone,
            packets_total: entry.orig_packets + entry.reply_packets,
            bytes_total: entry.orig_bytes + entry.reply_bytes,
            origin_node_id: self.node_id,
            seq: self.sync_seq,
            auth_tag: [0; 16],
        };
        self.sync_seq += 1;
        event.auth_tag = event.compute_tag(&self.sync_key);

        self.stats.sync_events_sent += 1;
        Ok(event)
    }

    /// Réception et injection d'un état de session distant répliqué
    pub fn receive_sync_event(
        &mut self,
        cap: &WallCap,
        event: &ConntrackSyncEvent,
        tick: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(wall_rights::WALL_CONNTRACK_SYNC) {
            return Err(SysError::PermissionDenied);
        }

        // Vérification de l'authenticité de l'étiquette HMAC
        if !event.verify(&self.sync_key) {
            self.stats.threats_detected += 1;
            return Err(SysError::PermissionDenied);
        }

        self.stats.sync_events_received += 1;

        if let Some((idx, _)) = self.conntrack.lookup(&event.tuple) {
            let entry = &mut self.conntrack.entries[idx];
            entry.state = event.state;
            entry.last_seen_tick = tick;
            entry.synced_to_cluster = true;
        } else {
            let slot = self.conntrack.allocate_slot()?;
            self.conntrack.entries[slot] = ConntrackEntry {
                tuple: event.tuple,
                state: event.state,
                tcp_fsm: if event.state == ConntrackState::Established {
                    TcpFsm::Established
                } else {
                    TcpFsm::SynSent
                },
                src_zone: event.src_zone,
                dst_zone: event.dst_zone,
                orig_packets: event.packets_total,
                orig_bytes: event.bytes_total,
                reply_packets: 0,
                reply_bytes: 0,
                created_tick: tick,
                last_seen_tick: tick,
                timeout_ticks: TIMEOUT_TCP_ESTABLISHED,
                origin_node_id: event.origin_node_id,
                is_active: true,
                synced_to_cluster: true,
            };
        }
        Ok(())
    }

    pub fn purge_expired(&mut self, cap: &WallCap, current_tick: u64) -> Result<usize, SysError> {
        if !cap.has_right(wall_rights::WALL_INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.conntrack.purge_expired(current_tick))
    }

    pub fn stats(&self, cap: &WallCap) -> Result<WallStats, SysError> {
        if !cap.has_right(wall_rights::WALL_INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.stats)
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] / std in test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_and_attenuation() {
        let admin_cap = WallCap::new(Handle::new(7901, 1), wall_rights::ALL);
        assert!(admin_cap.has_right(wall_rights::WALL_INSPECT));
        assert!(admin_cap.has_right(wall_rights::WALL_RULE_MANAGE));
        assert!(admin_cap.has_right(wall_rights::WALL_ADMIN));

        let inspect_cap = admin_cap.attenuate(wall_rights::WALL_INSPECT).unwrap();
        assert!(inspect_cap.has_right(wall_rights::WALL_INSPECT));
        assert!(!inspect_cap.has_right(wall_rights::WALL_RULE_MANAGE));

        // Rejet de tentative d'amplification
        assert_eq!(
            inspect_cap.attenuate(wall_rights::WALL_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_tcp_conntrack_handshake_and_fsm() {
        let admin_cap = WallCap::new(Handle::new(7901, 1), wall_rights::ALL);
        let key = [0x55u8; 32];
        let mut daemon = JamboWallDaemon::new(1, admin_cap, key);
        daemon.init_defaults();

        let tuple =
            ConntrackTuple::new(ip_proto::TCP, [192, 168, 1, 10], [10, 0, 0, 50], 54321, 80);

        // 1. SYN
        let pkt_syn = PacketFilterInput {
            tuple,
            src_zone: SecurityZone::ExternalUntrusted,
            dst_zone: SecurityZone::WorkloadEdge,
            tcp_flags: tcp_flags::SYN,
            payload_len: 40,
        };
        let act_syn = daemon.filter_packet(&admin_cap, &pkt_syn, 10).unwrap();
        assert_eq!(act_syn, WallAction::Allow);
        assert_eq!(daemon.conntrack.active_count(), 1);

        // 2. SYN-ACK (Reply)
        let pkt_synack = PacketFilterInput {
            tuple: tuple.reverse(),
            src_zone: SecurityZone::WorkloadEdge,
            dst_zone: SecurityZone::ExternalUntrusted,
            tcp_flags: tcp_flags::SYN | tcp_flags::ACK,
            payload_len: 40,
        };
        let _ = daemon.filter_packet(&admin_cap, &pkt_synack, 12).unwrap();

        // 3. ACK -> Established
        let pkt_ack = PacketFilterInput {
            tuple,
            src_zone: SecurityZone::ExternalUntrusted,
            dst_zone: SecurityZone::WorkloadEdge,
            tcp_flags: tcp_flags::ACK,
            payload_len: 0,
        };
        let _ = daemon.filter_packet(&admin_cap, &pkt_ack, 14).unwrap();

        let (idx, _) = daemon.conntrack.lookup(&tuple).unwrap();
        assert_eq!(
            daemon.conntrack.entries[idx].state,
            ConntrackState::Established
        );

        // 4. Data packet -> Fastpath hit
        let pkt_data = PacketFilterInput {
            tuple,
            src_zone: SecurityZone::ExternalUntrusted,
            dst_zone: SecurityZone::WorkloadEdge,
            tcp_flags: tcp_flags::PSH | tcp_flags::ACK,
            payload_len: 512,
        };
        let act_data = daemon.filter_packet(&admin_cap, &pkt_data, 16).unwrap();
        assert_eq!(act_data, WallAction::Allow);
        assert!(daemon.stats.conntrack_fastpath_hits >= 1);
    }

    #[test]
    fn test_cluster_conntrack_sync_and_hmac() {
        let admin_cap = WallCap::new(Handle::new(7901, 1), wall_rights::ALL);
        let key = [0x42u8; 32];
        let mut node1 = JamboWallDaemon::new(1, admin_cap, key);
        let mut node2 = JamboWallDaemon::new(2, admin_cap, key);

        let tuple = ConntrackTuple::new(ip_proto::TCP, [172, 16, 0, 2], [10, 0, 0, 8], 12345, 443);

        // Handshake sur Node 1
        let (s, _, _) = node1.conntrack.process_packet(
            &tuple,
            SecurityZone::ExternalUntrusted,
            SecurityZone::WorkloadEdge,
            tcp_flags::SYN,
            40,
            1,
            1,
        );
        assert_eq!(s, ConntrackState::New);

        let (s2, _, _) = node1.conntrack.process_packet(
            &tuple,
            SecurityZone::ExternalUntrusted,
            SecurityZone::WorkloadEdge,
            tcp_flags::ACK,
            40,
            2,
            1,
        );
        assert_eq!(s2, ConntrackState::Established);

        // Génération d'événement de synchro
        let sync_event = node1.generate_sync_event(&admin_cap, &tuple).unwrap();
        assert!(sync_event.verify(&key));

        // Rejet d'un HMAC falsifié
        let mut tampered = sync_event;
        tampered.auth_tag = [0xFFu8; 16];
        assert_eq!(
            node2.receive_sync_event(&admin_cap, &tampered, 10),
            Err(SysError::PermissionDenied)
        );

        // Acceptation sur le Nœud 2
        node2
            .receive_sync_event(&admin_cap, &sync_event, 10)
            .unwrap();
        assert_eq!(node2.conntrack.active_count(), 1);
        let (idx2, _) = node2.conntrack.lookup(&tuple).unwrap();
        assert_eq!(
            node2.conntrack.entries[idx2].state,
            ConntrackState::Established
        );
    }

    #[test]
    fn test_zero_trust_dynamic_block() {
        let admin_cap = WallCap::new(Handle::new(7901, 1), wall_rights::ALL);
        let key = [0x77u8; 32];
        let mut daemon = JamboWallDaemon::new(1, admin_cap, key);
        daemon.init_defaults();

        let attacker_ip = [203, 0, 113, 99];
        let tuple_attack =
            ConntrackTuple::new(ip_proto::TCP, attacker_ip, [10, 0, 0, 1], 40000, 80);

        // Drapeaux invalides (NULL scan)
        let pkt_null = PacketFilterInput {
            tuple: tuple_attack,
            src_zone: SecurityZone::ExternalUntrusted,
            dst_zone: SecurityZone::WorkloadEdge,
            tcp_flags: 0,
            payload_len: 0,
        };

        let act = daemon.filter_packet(&admin_cap, &pkt_null, 10).unwrap();
        assert_eq!(act, WallAction::Drop);
        assert_eq!(daemon.stats.threats_detected, 1);
        assert_eq!(daemon.stats.dynamic_blocks_created, 1);

        // Trafic subséquent immédiatement bloqué par la règle adaptative
        let pkt_normal = PacketFilterInput {
            tuple: tuple_attack,
            src_zone: SecurityZone::ExternalUntrusted,
            dst_zone: SecurityZone::WorkloadEdge,
            tcp_flags: tcp_flags::SYN,
            payload_len: 40,
        };
        let act2 = daemon.filter_packet(&admin_cap, &pkt_normal, 15).unwrap();
        assert_eq!(act2, WallAction::Drop);
    }
}

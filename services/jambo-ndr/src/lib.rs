//! Détection & Réponse Réseau Souveraine NDR (`jambo-ndr`)
//!
//! Phase 150 — Jalon v0.3.72 (Promotion PID 33)
//!
//! Fournit un système souverain de surveillance comportementale du trafic réseau en temps réel,
//! de détection de balisage périodique C2 (Command & Control), de détection d'exfiltration massive
//! de données (> 64 Kio), de détection de tunnels DNS à haute entropie, de microsegmentation
//! dynamique Zero-Trust (deny-by-default), d'isolation O(1) instantanée des hôtes compromis,
//! de scellement cryptographique d'audit SHA-256 et d'un protocole IPC déterministe à 64 octets
//! en environnement purement `#![no_std]` et sans allocation dynamique de mémoire.

#![no_std]

pub use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES SYSTÈME & LIMITES NDR
// ============================================================================

/// Identifiant d'endpoint IPC standard pour le service NDR (PID 33).
pub const NDR_ENDPOINT_ID: u32 = 33;

/// Magic bytes pour requête IPC NDR : "NDRD" = 0x4E445244
pub const NDR_MAGIC_REQ: u32 = 0x4E445244;

/// Magic bytes pour réponse IPC NDR : "NDRS" = 0x4E445253
pub const NDR_MAGIC_RESP: u32 = 0x4E445253;

/// Taille maximale du message IPC rapide (octets).
pub const MAX_FASTPATH_BYTES: usize = 64;

/// Nombre maximal de handles transmis dans un message IPC.
pub const MAX_HANDLES: usize = 4;

/// Taille d'un haché SHA-256 (octets).
pub const SHA256_LEN: usize = 32;

/// Capacité maximale de la table des flux réseau.
pub const MAX_FLOWS: usize = 64;

/// Capacité maximale de la table des règles de microsegmentation.
pub const MAX_RULES: usize = 32;

/// Capacité maximale de la table des hôtes en quarantaine.
pub const MAX_QUARANTINED: usize = 32;

/// Capacité maximale du registre des menaces détectées.
pub const MAX_THREATS: usize = 64;

/// Capacité maximale du registre d'audit cryptographique.
pub const MAX_AUDIT_ENTRIES: usize = 64;

/// Seuil de variance / gigue consécutive pour détection de balise C2 (50 millisecondes).
pub const C2_JITTER_THRESHOLD_MS: u64 = 50;

/// Seuil de burst d'exfiltration de données massives (64 Kio = 65 536 octets).
pub const EXFILTRATION_BURST_THRESHOLD: u64 = 65_536;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std], Zéro Alloc)
// ============================================================================

/// Implémentation autonome et déterministe de SHA-256 sans allocation
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

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

    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn transform_block(&mut self, block: &[u8; 64]) {
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
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    pub fn update(&mut self, input: &[u8]) {
        self.total_bytes += input.len() as u64;
        let mut offset = 0;
        while offset < input.len() {
            if self.buffer_len == 64 {
                let blk = self.buffer;
                self.transform_block(&blk);
                self.buffer_len = 0;
            }
            let to_copy = (64 - self.buffer_len).min(input.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&input[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes * 8;
        let mut pad = [0u8; 128];
        pad[0] = 0x80;
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };
        self.update(&pad[..pad_len]);
        let len_bytes = bit_len.to_be_bytes();
        self.update(&len_bytes);

        if self.buffer_len == 64 {
            let blk = self.buffer;
            self.transform_block(&blk);
        }

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ============================================================================
// GESTION DES CAPACITÉS NDR (NdrCap)
// ============================================================================

pub mod ndr_rights {
    pub const INSPECT_FLOW: u32 = 1 << 0; // 0x01: Inspection de paquets et suivi de flux
    pub const DETECT_ANOMALY: u32 = 1 << 1; // 0x02: Analyse comportementale (C2, exfiltration, DNS)
    pub const ENFORCE_MICROSEG: u32 = 1 << 2; // 0x04: Application des politiques de microsegmentation
    pub const QUARANTINE_FLOW: u32 = 1 << 3; // 0x08: Isolation et mise en quarantaine O(1)
    pub const CONFIGURE_POLICY: u32 = 1 << 4; // 0x10: Configuration des règles de filtrage
    pub const QUERY_METRICS: u32 = 1 << 5; // 0x20: Consultation des métriques et flux actifs
    pub const QUERY_AUDIT: u32 = 1 << 6; // 0x40: Lecture du registre d'audit et alertes
    pub const ADMIN: u32 = 1 << 7; // 0x80: Administration globale du démon NDR
    pub const ALL: u32 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdrError {
    AttenuationViolation,
    Unauthorized,
    Expired,
    Depleted,
    FlowNotFound,
    TableFull,
    InvalidParameter,
    IntegrityTampered,
    FlowBlocked,
    ThreatDetected,
    BadMagic,
    BadOpcode,
    SerializationError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl NdrCap {
    pub const fn new(
        handle: Handle,
        rights: u32,
        max_lifetime: u64,
        invocations_left: u32,
    ) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, NdrError> {
        if (new_rights & !self.rights) != 0 {
            return Err(NdrError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(NdrError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(NdrError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }
}

// ============================================================================
// MODÈLES DE DOMAINE RÉSEAU & TYPOLOGIES
// ============================================================================

/// Protocoles réseau inspectés
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolType {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Dns = 53,
    Unknown = 255,
}

impl ProtocolType {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            53 => Self::Dns,
            _ => Self::Unknown,
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "ICMP",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Dns => "DNS",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Zones de sécurité pour microsegmentation Zero-Trust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityZone {
    ZoneKernel = 0,
    ZoneCoreServices = 1,
    ZoneCryptographic = 2,
    ZoneUserApps = 3,
    ZoneExternalNetwork = 4,
    ZoneQuarantine = 5,
}

impl SecurityZone {
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::ZoneKernel),
            1 => Some(Self::ZoneCoreServices),
            2 => Some(Self::ZoneCryptographic),
            3 => Some(Self::ZoneUserApps),
            4 => Some(Self::ZoneExternalNetwork),
            5 => Some(Self::ZoneQuarantine),
            _ => None,
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZoneKernel => "Kernel",
            Self::ZoneCoreServices => "CoreServices",
            Self::ZoneCryptographic => "Cryptographic",
            Self::ZoneUserApps => "UserApps",
            Self::ZoneExternalNetwork => "ExternalNetwork",
            Self::ZoneQuarantine => "Quarantine",
        }
    }
}

/// État du cycle de vie d'un flux réseau
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FlowState {
    New = 0,
    Active = 1,
    Established = 2,
    Closing = 3,
    Closed = 4,
    Quarantined = 5,
    Blocked = 6,
}

/// Niveau de sévérité de menace
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ThreatSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl ThreatSeverity {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            4 => Self::Critical,
            _ => Self::Low,
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Types de menaces identifiées par les moteurs d'inspection NDR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NdrThreatType {
    None = 0,
    C2Beaconing = 1,
    DataExfiltration = 2,
    DnsTunneling = 3,
    MicrosegViolation = 4,
    QuarantineViolation = 5,
}

impl NdrThreatType {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::C2Beaconing,
            2 => Self::DataExfiltration,
            3 => Self::DnsTunneling,
            4 => Self::MicrosegViolation,
            5 => Self::QuarantineViolation,
            _ => Self::None,
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::C2Beaconing => "C2_BEACONING",
            Self::DataExfiltration => "DATA_EXFILTRATION",
            Self::DnsTunneling => "DNS_TUNNELING",
            Self::MicrosegViolation => "MICROSEG_VIOLATION",
            Self::QuarantineViolation => "QUARANTINE_VIOLATION",
        }
    }
}

/// Action de politique / filtrage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleAction {
    Allow = 0,
    Alert = 1,
    Drop = 2,
    Quarantine = 3,
}

impl RuleAction {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Allow,
            1 => Self::Alert,
            2 => Self::Drop,
            3 => Self::Quarantine,
            _ => Self::Drop,
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Alert => "ALERT",
            Self::Drop => "DROP",
            Self::Quarantine => "QUARANTINE",
        }
    }
}

/// Nœud de flux réseau suivi avec historique d'intervalles et volume
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkFlow {
    pub flow_id: u32,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: ProtocolType,
    pub src_zone: SecurityZone,
    pub dst_zone: SecurityZone,
    pub state: FlowState,
    pub byte_count: u64,
    pub packet_count: u32,
    pub start_epoch: u64,
    pub last_seen_epoch: u64,
    pub packet_timestamps: [u64; 8],
    pub timestamp_count: usize,
    pub burst_bytes: u64,
    pub burst_window_start: u64,
}

impl NetworkFlow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flow_id: u32,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: ProtocolType,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        start_epoch: u64,
    ) -> Self {
        Self {
            flow_id,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            src_zone,
            dst_zone,
            state: FlowState::New,
            byte_count: 0,
            packet_count: 0,
            start_epoch,
            last_seen_epoch: start_epoch,
            packet_timestamps: [0u64; 8],
            timestamp_count: 0,
            burst_bytes: 0,
            burst_window_start: start_epoch,
        }
    }

    pub fn matches_5tuple(
        &self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: ProtocolType,
    ) -> bool {
        (self.protocol == protocol)
            && ((self.src_ip == src_ip
                && self.dst_ip == dst_ip
                && self.src_port == src_port
                && self.dst_port == dst_port)
                || (self.src_ip == dst_ip
                    && self.dst_ip == src_ip
                    && self.src_port == dst_port
                    && self.dst_port == src_port))
    }

    pub fn ingest_packet(&mut self, bytes_len: usize, epoch: u64) {
        self.packet_count = self.packet_count.saturating_add(1);
        self.byte_count = self.byte_count.saturating_add(bytes_len as u64);
        self.last_seen_epoch = epoch;

        if self.state == FlowState::New {
            self.state = FlowState::Active;
        }

        // Suivi de burst temporel (fenêtre glissante de 5000 ms)
        if epoch.saturating_sub(self.burst_window_start) > 5000 {
            self.burst_bytes = bytes_len as u64;
            self.burst_window_start = epoch;
        } else {
            self.burst_bytes = self.burst_bytes.saturating_add(bytes_len as u64);
        }

        // Enregistrement des horodatages d'intervalles
        if self.timestamp_count < 8 {
            self.packet_timestamps[self.timestamp_count] = epoch;
            self.timestamp_count += 1;
        } else {
            for i in 0..7 {
                self.packet_timestamps[i] = self.packet_timestamps[i + 1];
            }
            self.packet_timestamps[7] = epoch;
        }
    }

    /// Détection de balisage périodique C2 (Command & Control)
    /// Exige au moins 4 paquets avec une faible gigue (< 50ms de variance entre intervalles consécutifs).
    pub fn is_c2_beaconing(&self) -> bool {
        if self.timestamp_count < 4 {
            return false;
        }
        let n_intervals = self.timestamp_count - 1;
        let mut intervals = [0u64; 7];

        for i in 0..n_intervals {
            if self.packet_timestamps[i + 1] <= self.packet_timestamps[i] {
                return false;
            }
            intervals[i] = self.packet_timestamps[i + 1] - self.packet_timestamps[i];
        }

        // L'intervalle moyen périodique doit être significatif (>= 50ms)
        let mut sum_intervals = 0u64;
        for &interval in intervals.iter().take(n_intervals) {
            sum_intervals += interval;
        }
        let mean_interval = sum_intervals / (n_intervals as u64);
        if mean_interval < 50 {
            return false;
        }

        // Contrôle strict de la variance de gigue consécutive (< 50ms)
        for i in 0..(n_intervals - 1) {
            let diff = intervals[i + 1].abs_diff(intervals[i]);
            if diff >= C2_JITTER_THRESHOLD_MS {
                return false;
            }
        }

        true
    }

    /// Détection d'exfiltration massive de données dépassant le seuil de 64 Kio
    pub fn is_massive_exfiltration(&self) -> bool {
        self.byte_count > EXFILTRATION_BURST_THRESHOLD
            || self.burst_bytes > EXFILTRATION_BURST_THRESHOLD
    }
}

/// Règle de politique de microsegmentation réseau
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficRule {
    pub rule_id: u32,
    pub src_zone: SecurityZone,
    pub dst_zone: SecurityZone,
    pub protocol: Option<ProtocolType>,
    pub dst_port: Option<u16>,
    pub action: RuleAction,
    pub enabled: bool,
}

impl TrafficRule {
    pub const fn new(
        rule_id: u32,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        protocol: Option<ProtocolType>,
        dst_port: Option<u16>,
        action: RuleAction,
    ) -> Self {
        Self {
            rule_id,
            src_zone,
            dst_zone,
            protocol,
            dst_port,
            action,
            enabled: true,
        }
    }
}

/// Menace identifiée enregistrée dans le registre NDR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrThreat {
    pub threat_id: u32,
    pub flow_id: u32,
    pub endpoint_ip: [u8; 4],
    pub threat_type: NdrThreatType,
    pub severity: ThreatSeverity,
    pub epoch: u64,
    pub description: [u8; 32],
    pub desc_len: usize,
}

impl NdrThreat {
    pub fn new(
        threat_id: u32,
        flow_id: u32,
        endpoint_ip: [u8; 4],
        threat_type: NdrThreatType,
        severity: ThreatSeverity,
        epoch: u64,
        desc: &str,
    ) -> Self {
        let mut d = [0u8; 32];
        let bytes = desc.as_bytes();
        let len = bytes.len().min(32);
        d[..len].copy_from_slice(&bytes[..len]);
        Self {
            threat_id,
            flow_id,
            endpoint_ip,
            threat_type,
            severity,
            epoch,
            description: d,
            desc_len: len,
        }
    }

    pub fn desc_as_str(&self) -> &str {
        core::str::from_utf8(&self.description[..self.desc_len]).unwrap_or("")
    }
}

/// Hôte ou adresse IP placé en quarantaine immédiate O(1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantinedEndpoint {
    pub ip: [u8; 4],
    pub reason: [u8; 32],
    pub reason_len: usize,
    pub quarantined_at: u64,
    pub active: bool,
}

impl QuarantinedEndpoint {
    pub fn new(ip: [u8; 4], reason: &str, quarantined_at: u64) -> Self {
        let mut r = [0u8; 32];
        let bytes = reason.as_bytes();
        let len = bytes.len().min(32);
        r[..len].copy_from_slice(&bytes[..len]);
        Self {
            ip,
            reason: r,
            reason_len: len,
            quarantined_at,
            active: true,
        }
    }

    pub fn reason_as_str(&self) -> &str {
        core::str::from_utf8(&self.reason[..self.reason_len]).unwrap_or("")
    }
}

/// Entrée du journal d'audit cryptographique inaltérable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrAuditEntry {
    pub index: u32,
    pub timestamp: u64,
    pub action_tag: [u8; 16],
    pub tag_len: usize,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl NdrAuditEntry {
    pub fn new(index: u32, timestamp: u64, tag: &str, prev_hash: [u8; 32]) -> Self {
        let mut action_tag = [0u8; 16];
        let b = tag.as_bytes();
        let tag_len = b.len().min(16);
        action_tag[..tag_len].copy_from_slice(&b[..tag_len]);

        let mut hasher = Sha256::new();
        hasher.update(&index.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&action_tag[..tag_len]);
        hasher.update(&prev_hash);
        let entry_hash = hasher.finalize();

        Self {
            index,
            timestamp,
            action_tag,
            tag_len,
            prev_hash,
            entry_hash,
        }
    }
}

/// Synthèse consolidée de l'état NDR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrSummary {
    pub active_flows: u32,
    pub total_flows_tracked: u64,
    pub quarantined_endpoints: u32,
    pub threats_detected: u32,
    pub c2_beacons_detected: u32,
    pub exfiltrations_detected: u32,
    pub dns_tunnels_detected: u32,
    pub microseg_violations: u32,
    pub audit_count: u32,
    pub ledger_valid: bool,
}

// ============================================================================
// DÉTECTEUR DE TUNNELING DNS (Entropie & Heuristiques Longueurs)
// ============================================================================

/// Approximation entière déterministe de log2(x) * 1024 sans virgule flottante
pub const fn log2_x1024(x: u32) -> u32 {
    if x <= 1 {
        return 0;
    }
    let k = 31 - x.leading_zeros();
    let base = k * 1024;
    let rem = x - (1 << k);
    let frac = (rem * 1024) >> k;
    base + frac
}

/// Calcule l'entropie de Shannon mise à l'échelle (x1024 bits) d'un flux d'octets
pub fn compute_shannon_entropy_x1024(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let n = data.len() as u32;
    let log2_n = log2_x1024(n);

    let mut sum = 0u32;
    for &c in &counts {
        if c > 0 {
            sum += c * log2_x1024(c);
        }
    }

    let avg_term = sum / n;
    log2_n.saturating_sub(avg_term)
}

/// Détecte un tunnel DNS en évaluant la longueur du domaine et l'entropie du sous-domaine
pub fn detect_dns_tunneling(query: &str) -> bool {
    let bytes = query.as_bytes();
    let len = bytes.len();

    // Règle 1: Les requêtes saines dépassent rarement 45 octets au total
    if len < 30 {
        return false;
    }

    // Extraction du premier label (sous-domaine de données)
    let first_dot = bytes.iter().position(|&b| b == b'.').unwrap_or(len);
    let subdomain = &bytes[..first_dot];

    let entropy = compute_shannon_entropy_x1024(subdomain);

    // Heuristiques de tunneling :
    // - Sous-domaine long (>= 28 octets) ET haute entropie (>= 3.3 bits = 3380)
    // - OU requête totale longue (>= 48 octets) ET haute entropie globale (>= 3.4 bits = 3480)
    (subdomain.len() >= 28 && entropy >= 3380) || (len >= 48 && entropy >= 3480)
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE À 64 OCTETS (PID 33)
// ============================================================================

/// Codes d'opérations IPC du démon NDR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NdrOpcode {
    GetStatus = 1,
    InspectFlow = 2,
    QuarantineEndpoint = 3,
    ReleaseEndpoint = 4,
    ConfigurePolicy = 5,
    QueryAudit = 6,
    GetThreats = 7,
}

impl NdrOpcode {
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::InspectFlow),
            3 => Some(Self::QuarantineEndpoint),
            4 => Some(Self::ReleaseEndpoint),
            5 => Some(Self::ConfigurePolicy),
            6 => Some(Self::QueryAudit),
            7 => Some(Self::GetThreats),
            _ => None,
        }
    }
}

/// Requête IPC calibrée à exactement 64 octets
#[repr(C, packed(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrRequest {
    pub magic: u32,           // 0..4: 0x4E445244 ("NDRD")
    pub opcode: u32,          // 4..8: Code d'opération
    pub handle_id: u32,       // 8..12: Handle de capacité émetteur
    pub rights: u32,          // 12..16: Droits de capacité
    pub flow_id: u32,         // 16..20: Identifiant de flux
    pub endpoint_ip: [u8; 4], // 20..24: Adresse IPv4
    pub action: u8,           // 24: Action demandée / règle
    pub zone: u8,             // 25: Zone de sécurité
    pub _reserved1: [u8; 2],  // 26..28: Alignement
    pub epoch: u64,           // 28..36: Horodatage
    pub reason: [u8; 28],     // 36..64: Raison ou chaîne de contexte
}

const _: () = assert!(core::mem::size_of::<NdrRequest>() == 64);

impl Default for NdrRequest {
    fn default() -> Self {
        Self {
            magic: NDR_MAGIC_REQ,
            opcode: NdrOpcode::GetStatus as u32,
            handle_id: NDR_ENDPOINT_ID,
            rights: ndr_rights::ALL,
            flow_id: 0,
            endpoint_ip: [0, 0, 0, 0],
            action: 0,
            zone: 0,
            _reserved1: [0, 0],
            epoch: 0,
            reason: [0u8; 28],
        }
    }
}

impl NdrRequest {
    pub const fn new(opcode: u32, handle_id: u32, rights: u32) -> Self {
        Self {
            magic: NDR_MAGIC_REQ,
            opcode,
            handle_id,
            rights,
            flow_id: 0,
            endpoint_ip: [0, 0, 0, 0],
            action: 0,
            zone: 0,
            _reserved1: [0, 0],
            epoch: 0,
            reason: [0u8; 28],
        }
    }

    pub fn new_status(handle_id: u32, rights: u32) -> Self {
        Self::new(NdrOpcode::GetStatus as u32, handle_id, rights)
    }

    pub fn new_inspect(
        handle_id: u32,
        rights: u32,
        flow_id: u32,
        ip: [u8; 4],
        zone: u8,
        epoch: u64,
    ) -> Self {
        let mut req = Self::new(NdrOpcode::InspectFlow as u32, handle_id, rights);
        req.flow_id = flow_id;
        req.endpoint_ip = ip;
        req.zone = zone;
        req.epoch = epoch;
        req
    }

    pub fn new_quarantine(
        handle_id: u32,
        rights: u32,
        ip: [u8; 4],
        reason: &str,
        epoch: u64,
    ) -> Self {
        let mut req = Self::new(NdrOpcode::QuarantineEndpoint as u32, handle_id, rights);
        req.endpoint_ip = ip;
        req.epoch = epoch;
        req.set_reason(reason);
        req
    }

    pub fn new_release(handle_id: u32, rights: u32, ip: [u8; 4], epoch: u64) -> Self {
        let mut req = Self::new(NdrOpcode::ReleaseEndpoint as u32, handle_id, rights);
        req.endpoint_ip = ip;
        req.epoch = epoch;
        req
    }

    pub fn new_configure_policy(
        handle_id: u32,
        rights: u32,
        zone: u8,
        action: u8,
        epoch: u64,
    ) -> Self {
        let mut req = Self::new(NdrOpcode::ConfigurePolicy as u32, handle_id, rights);
        req.zone = zone;
        req.action = action;
        req.epoch = epoch;
        req
    }

    pub fn new_query_audit(handle_id: u32, rights: u32) -> Self {
        Self::new(NdrOpcode::QueryAudit as u32, handle_id, rights)
    }

    pub fn new_get_threats(handle_id: u32, rights: u32) -> Self {
        Self::new(NdrOpcode::GetThreats as u32, handle_id, rights)
    }

    pub fn set_reason(&mut self, r: &str) {
        let bytes = r.as_bytes();
        let len = bytes.len().min(28);
        self.reason = [0u8; 28];
        self.reason[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn reason_as_str(&self) -> &str {
        let len = self.reason.iter().position(|&b| b == 0).unwrap_or(28);
        core::str::from_utf8(&self.reason[..len]).unwrap_or("")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const Self as *const u8, buf.as_mut_ptr(), 64);
        }
        buf
    }

    pub fn from_bytes(buf: &[u8; 64]) -> Result<Self, NdrError> {
        let req: Self = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Self) };
        if req.magic != NDR_MAGIC_REQ {
            return Err(NdrError::BadMagic);
        }
        Ok(req)
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrResponse {
    pub magic: u32,             // 0..4: 0x4E445253 ("NDRS")
    pub status: u32,            // 4..8: Code statut (0 = succès, >0 = erreur)
    pub active_flows: u32,      // 8..12: Nombre de flux actifs
    pub quarantined_count: u32, // 12..16: Nombre d'hôtes en quarantaine
    pub threats_detected: u32,  // 16..20: Nombre de menaces détectées
    pub flow_action: u8,        // 20: Action appliquée au flux
    pub threat_severity: u8,    // 21: Gravité de la menace
    pub _reserved1: [u8; 2],    // 22..24: Alignement
    pub flow_id: u32,           // 24..28: Identifiant de flux
    pub audit_hash: [u8; 16],   // 28..44: Échantillon d'audit SHA-256
    pub status_str: [u8; 20],   // 44..64: Message ASCII descriptif
}

const _: () = assert!(core::mem::size_of::<NdrResponse>() == 64);

impl Default for NdrResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl NdrResponse {
    pub const fn new() -> Self {
        Self {
            magic: NDR_MAGIC_RESP,
            status: 0,
            active_flows: 0,
            quarantined_count: 0,
            threats_detected: 0,
            flow_action: 0,
            threat_severity: 0,
            _reserved1: [0, 0],
            flow_id: 0,
            audit_hash: [0u8; 16],
            status_str: [0u8; 20],
        }
    }

    pub fn set_status_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(20);
        self.status_str = [0u8; 20];
        self.status_str[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn status_as_str(&self) -> &str {
        let len = self.status_str.iter().position(|&b| b == 0).unwrap_or(20);
        core::str::from_utf8(&self.status_str[..len]).unwrap_or("")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const Self as *const u8, buf.as_mut_ptr(), 64);
        }
        buf
    }

    pub fn from_bytes(buf: &[u8; 64]) -> Result<Self, NdrError> {
        let resp: Self = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Self) };
        if resp.magic != NDR_MAGIC_RESP {
            return Err(NdrError::BadMagic);
        }
        Ok(resp)
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`NdrClient`, `ChannelMessage`)
// ============================================================================

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

/// Client synchrone Ring 3 pour interagir avec le démon jambo-ndr (PID 33).
pub struct NdrClient {
    pub endpoint: Handle,
}

impl NdrClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn call(&self, req: &NdrRequest) -> Result<NdrResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<NdrResponse>() {
                let mut buf = [0u8; 64];
                buf.copy_from_slice(&rx_msg.bytes[..64]);
                return NdrResponse::from_bytes(&buf).map_err(|_| SysError::InvalidArgument);
            }

            attempts += 1;
            libjambo::syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }

    pub fn get_status(&self, cap: &NdrCap) -> Result<NdrResponse, SysError> {
        let req = NdrRequest::new_status(NDR_ENDPOINT_ID, cap.rights);
        self.call(&req)
    }

    pub fn quarantine_endpoint(
        &self,
        cap: &NdrCap,
        ip: [u8; 4],
        reason: &str,
        epoch: u64,
    ) -> Result<NdrResponse, SysError> {
        let req = NdrRequest::new_quarantine(NDR_ENDPOINT_ID, cap.rights, ip, reason, epoch);
        self.call(&req)
    }

    pub fn release_endpoint(
        &self,
        cap: &NdrCap,
        ip: [u8; 4],
        epoch: u64,
    ) -> Result<NdrResponse, SysError> {
        let req = NdrRequest::new_release(NDR_ENDPOINT_ID, cap.rights, ip, epoch);
        self.call(&req)
    }

    pub fn query_audit(&self, cap: &NdrCap) -> Result<NdrResponse, SysError> {
        let req = NdrRequest::new_query_audit(NDR_ENDPOINT_ID, cap.rights);
        self.call(&req)
    }

    pub fn get_threats(&self, cap: &NdrCap) -> Result<NdrResponse, SysError> {
        let req = NdrRequest::new_get_threats(NDR_ENDPOINT_ID, cap.rights);
        self.call(&req)
    }
}

// ============================================================================
// MOTEUR NDR & DÉMON CENTRAL (`JamboNdrDaemon`)
// ============================================================================

/// Démon principal souverain de détection & réponse réseau
pub struct JamboNdrDaemon {
    pub cap: NdrCap,
    pub flows: [Option<NetworkFlow>; MAX_FLOWS],
    pub flow_count: usize,
    pub quarantined: [Option<QuarantinedEndpoint>; MAX_QUARANTINED],
    pub quarantined_count: usize,
    pub rules: [Option<TrafficRule>; MAX_RULES],
    pub rule_count: usize,
    pub threats: [Option<NdrThreat>; MAX_THREATS],
    pub threat_count: usize,
    pub audit_ledger: [Option<NdrAuditEntry>; MAX_AUDIT_ENTRIES],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],
    pub total_flows_tracked: u64,
    pub c2_beacons_detected: u32,
    pub exfiltrations_detected: u32,
    pub dns_tunnels_detected: u32,
    pub microseg_violations: u32,
}

impl JamboNdrDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0x4Eu8; 32]; // 'N'

    pub fn new(cap: NdrCap) -> Self {
        Self {
            cap,
            flows: [None; MAX_FLOWS],
            flow_count: 0,
            quarantined: [None; MAX_QUARANTINED],
            quarantined_count: 0,
            rules: [None; MAX_RULES],
            rule_count: 0,
            threats: [None; MAX_THREATS],
            threat_count: 0,
            audit_ledger: [None; MAX_AUDIT_ENTRIES],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            total_flows_tracked: 0,
            c2_beacons_detected: 0,
            exfiltrations_detected: 0,
            dns_tunnels_detected: 0,
            microseg_violations: 0,
        }
    }

    /// Initialise les politiques par défaut de microsegmentation souveraine Zero-Trust
    pub fn init_defaults(&mut self) {
        // Règle 1: Kernel <-> CoreServices autorisé
        let _ = self.add_rule_internal(
            SecurityZone::ZoneKernel,
            SecurityZone::ZoneCoreServices,
            None,
            None,
            RuleAction::Allow,
        );
        let _ = self.add_rule_internal(
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneKernel,
            None,
            None,
            RuleAction::Allow,
        );

        // Règle 2: CoreServices <-> Cryptographic autorisé
        let _ = self.add_rule_internal(
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneCryptographic,
            None,
            None,
            RuleAction::Allow,
        );
        let _ = self.add_rule_internal(
            SecurityZone::ZoneCryptographic,
            SecurityZone::ZoneCoreServices,
            None,
            None,
            RuleAction::Allow,
        );

        // Règle 3: UserApps <-> CoreServices autorisé
        let _ = self.add_rule_internal(
            SecurityZone::ZoneUserApps,
            SecurityZone::ZoneCoreServices,
            None,
            None,
            RuleAction::Allow,
        );
        let _ = self.add_rule_internal(
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneUserApps,
            None,
            None,
            RuleAction::Allow,
        );

        // Règle 4: CoreServices <-> ExternalNetwork autorisé
        let _ = self.add_rule_internal(
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            None,
            None,
            RuleAction::Allow,
        );
        let _ = self.add_rule_internal(
            SecurityZone::ZoneExternalNetwork,
            SecurityZone::ZoneCoreServices,
            None,
            None,
            RuleAction::Allow,
        );

        let _ = self.record_audit_entry_internal("NDR_INIT", 1);
    }

    fn add_rule_internal(
        &mut self,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        protocol: Option<ProtocolType>,
        dst_port: Option<u16>,
        action: RuleAction,
    ) -> Result<u32, NdrError> {
        if self.rule_count >= MAX_RULES {
            return Err(NdrError::TableFull);
        }
        let rule_id = (self.rule_count as u32) + 1;
        let rule = TrafficRule::new(rule_id, src_zone, dst_zone, protocol, dst_port, action);
        self.rules[self.rule_count] = Some(rule);
        self.rule_count += 1;
        Ok(rule_id)
    }

    /// Ajout d'une règle de microsegmentation avec validation de capacité
    #[allow(clippy::too_many_arguments)]
    pub fn add_traffic_rule(
        &mut self,
        cap: &NdrCap,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        protocol: Option<ProtocolType>,
        dst_port: Option<u16>,
        action: RuleAction,
        epoch: u64,
    ) -> Result<u32, NdrError> {
        if !cap.has_right(ndr_rights::CONFIGURE_POLICY) && !cap.has_right(ndr_rights::ADMIN) {
            return Err(NdrError::Unauthorized);
        }
        let id = self.add_rule_internal(src_zone, dst_zone, protocol, dst_port, action)?;
        let _ = self.record_audit_entry_internal("POLICY_ADD", epoch);
        Ok(id)
    }

    /// Évaluation Zero-Trust deny-by-default de la politique de microsegmentation
    pub fn evaluate_flow_policy(
        &self,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        protocol: Option<ProtocolType>,
        dst_port: Option<u16>,
    ) -> RuleAction {
        // ZoneQuarantine est strictement isolée et rejetée
        if src_zone == SecurityZone::ZoneQuarantine || dst_zone == SecurityZone::ZoneQuarantine {
            return RuleAction::Drop;
        }

        // Parcours des règles explicites configurées
        for r in self.rules.iter().take(self.rule_count).flatten() {
            if r.enabled && r.src_zone == src_zone && r.dst_zone == dst_zone {
                let proto_match = r.protocol.is_none() || r.protocol == protocol;
                let port_match = r.dst_port.is_none() || r.dst_port == dst_port;
                if proto_match && port_match {
                    return r.action;
                }
            }
        }

        // Deny-by-default pour toute communication inter-zone non autorisée
        RuleAction::Drop
    }

    /// Vérification O(1) si une adresse IP est sous le coup d'une quarantaine active
    #[inline(always)]
    pub fn is_endpoint_quarantined(&self, ip: &[u8; 4]) -> bool {
        for q in self
            .quarantined
            .iter()
            .take(self.quarantined_count)
            .flatten()
        {
            if q.active && q.ip == *ip {
                return true;
            }
        }
        false
    }

    fn quarantine_endpoint_internal(
        &mut self,
        ip: [u8; 4],
        reason: &str,
        epoch: u64,
    ) -> Result<(), NdrError> {
        // Vérifie si déjà présent
        for q in self
            .quarantined
            .iter_mut()
            .take(self.quarantined_count)
            .flatten()
        {
            if q.ip == ip {
                q.active = true;
                return Ok(());
            }
        }

        if self.quarantined_count >= MAX_QUARANTINED {
            return Err(NdrError::TableFull);
        }

        let q = QuarantinedEndpoint::new(ip, reason, epoch);
        self.quarantined[self.quarantined_count] = Some(q);
        self.quarantined_count += 1;

        // Mise à jour immédiate de tous les flux actifs associés vers Quarantined
        for f in self.flows.iter_mut().take(self.flow_count).flatten() {
            if f.src_ip == ip || f.dst_ip == ip {
                f.state = FlowState::Quarantined;
            }
        }

        let _ = self.record_audit_entry_internal("QUARANTINE_IP", epoch);
        Ok(())
    }

    fn release_endpoint_internal(&mut self, ip: &[u8; 4], epoch: u64) -> Result<(), NdrError> {
        let mut found = false;
        for q in self
            .quarantined
            .iter_mut()
            .take(self.quarantined_count)
            .flatten()
        {
            if q.ip == *ip && q.active {
                q.active = false;
                found = true;
                break;
            }
        }

        if !found {
            return Err(NdrError::FlowNotFound);
        }

        let _ = self.record_audit_entry_internal("RELEASE_IP", epoch);
        Ok(())
    }

    /// Mise en quarantaine O(1) immédiate avec contrôle de capacité
    pub fn quarantine_endpoint(
        &mut self,
        cap: &NdrCap,
        ip: [u8; 4],
        reason: &str,
        epoch: u64,
    ) -> Result<(), NdrError> {
        if !cap.has_right(ndr_rights::QUARANTINE_FLOW) && !cap.has_right(ndr_rights::ADMIN) {
            return Err(NdrError::Unauthorized);
        }
        self.quarantine_endpoint_internal(ip, reason, epoch)
    }

    /// Levée de quarantaine avec contrôle de capacité
    pub fn release_endpoint(
        &mut self,
        cap: &NdrCap,
        ip: [u8; 4],
        epoch: u64,
    ) -> Result<(), NdrError> {
        if !cap.has_right(ndr_rights::QUARANTINE_FLOW) && !cap.has_right(ndr_rights::ADMIN) {
            return Err(NdrError::Unauthorized);
        }
        self.release_endpoint_internal(&ip, epoch)
    }

    /// Enregistre une alerte / menace dans le registre NDR
    pub fn record_threat(
        &mut self,
        flow_id: u32,
        endpoint_ip: [u8; 4],
        threat_type: NdrThreatType,
        severity: ThreatSeverity,
        epoch: u64,
        desc: &str,
    ) {
        match threat_type {
            NdrThreatType::C2Beaconing => self.c2_beacons_detected += 1,
            NdrThreatType::DataExfiltration => self.exfiltrations_detected += 1,
            NdrThreatType::DnsTunneling => self.dns_tunnels_detected += 1,
            NdrThreatType::MicrosegViolation => self.microseg_violations += 1,
            _ => {}
        }

        if self.threat_count < MAX_THREATS {
            let id = (self.threat_count as u32) + 1;
            let threat =
                NdrThreat::new(id, flow_id, endpoint_ip, threat_type, severity, epoch, desc);
            self.threats[self.threat_count] = Some(threat);
            self.threat_count += 1;
        }

        let _ = self.record_audit_entry_internal("NDR_THREAT", epoch);
    }

    /// Ingestion, inspection et filtrage dynamique d'un paquet réseau
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_packet(
        &mut self,
        cap: &NdrCap,
        flow_id: u32,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: ProtocolType,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        payload: &[u8],
        epoch: u64,
    ) -> Result<RuleAction, NdrError> {
        if !cap.has_right(ndr_rights::INSPECT_FLOW) && !cap.has_right(ndr_rights::ADMIN) {
            return Err(NdrError::Unauthorized);
        }

        // 1. Isolation O(1) immédiate : vérification d'adresse IP en quarantaine
        if self.is_endpoint_quarantined(&src_ip) || self.is_endpoint_quarantined(&dst_ip) {
            return Err(NdrError::FlowBlocked);
        }

        // 2. Évaluation de la politique de microsegmentation (deny-by-default)
        let policy_action =
            self.evaluate_flow_policy(src_zone, dst_zone, Some(protocol), Some(dst_port));
        if policy_action == RuleAction::Drop {
            self.record_threat(
                flow_id,
                src_ip,
                NdrThreatType::MicrosegViolation,
                ThreatSeverity::High,
                epoch,
                "Microsegmentation policy violation",
            );
            return Ok(RuleAction::Drop);
        }

        // 3. Détection de Tunneling DNS
        if (protocol == ProtocolType::Dns || dst_port == 53) && !payload.is_empty() {
            if let Ok(query_str) = core::str::from_utf8(payload) {
                if detect_dns_tunneling(query_str) {
                    self.record_threat(
                        flow_id,
                        src_ip,
                        NdrThreatType::DnsTunneling,
                        ThreatSeverity::Critical,
                        epoch,
                        "High-entropy DNS tunneling query",
                    );
                    self.quarantine_endpoint_internal(src_ip, "DNS Tunneling Detected", epoch)?;
                    return Err(NdrError::FlowBlocked);
                }
            }
        }

        // 4. Recherche ou enregistrement du flux réseau dans FlowTracker
        let mut slot_opt = None;
        for (i, flow_opt) in self.flows.iter().enumerate().take(self.flow_count) {
            if let Some(ref flow) = flow_opt {
                if flow.flow_id == flow_id
                    || flow.matches_5tuple(src_ip, dst_ip, src_port, dst_port, protocol)
                {
                    slot_opt = Some(i);
                    break;
                }
            }
        }

        let slot = match slot_opt {
            Some(idx) => idx,
            None => {
                if self.flow_count >= MAX_FLOWS {
                    return Err(NdrError::TableFull);
                }
                let idx = self.flow_count;
                self.flows[idx] = Some(NetworkFlow::new(
                    flow_id, src_ip, dst_ip, src_port, dst_port, protocol, src_zone, dst_zone,
                    epoch,
                ));
                self.flow_count += 1;
                self.total_flows_tracked += 1;
                idx
            }
        };

        // Ingestion du paquet dans le flux
        if let Some(ref mut flow) = self.flows[slot] {
            flow.ingest_packet(payload.len(), epoch);

            // 5. Détection d'exfiltration massive de données (> 64 Kio)
            if flow.is_massive_exfiltration() {
                self.record_threat(
                    flow_id,
                    src_ip,
                    NdrThreatType::DataExfiltration,
                    ThreatSeverity::Critical,
                    epoch,
                    "Data exfiltration exceeded 64KiB",
                );
                self.quarantine_endpoint_internal(
                    src_ip,
                    "Data Exfiltration Exceeded 64KiB",
                    epoch,
                )?;
                return Err(NdrError::FlowBlocked);
            }

            // 6. Détection de balisage périodique C2 (Command & Control, gigue < 50ms)
            if flow.is_c2_beaconing() {
                self.record_threat(
                    flow_id,
                    src_ip,
                    NdrThreatType::C2Beaconing,
                    ThreatSeverity::High,
                    epoch,
                    "Periodic C2 beaconing detected",
                );
                self.quarantine_endpoint_internal(src_ip, "C2 Beaconing Detected", epoch)?;
                return Err(NdrError::FlowBlocked);
            }
        }

        Ok(policy_action)
    }

    fn record_audit_entry_internal(
        &mut self,
        tag: &str,
        timestamp: u64,
    ) -> Result<[u8; 32], NdrError> {
        if self.audit_count >= MAX_AUDIT_ENTRIES {
            return Err(NdrError::TableFull);
        }
        let index = self.audit_count as u32;
        let entry = NdrAuditEntry::new(index, timestamp, tag, self.ledger_hash);
        self.ledger_hash = entry.entry_hash;
        self.audit_ledger[self.audit_count] = Some(entry);
        self.audit_count += 1;
        Ok(self.ledger_hash)
    }

    /// Enregistre une entrée d'audit cryptographique scellée avec vérification de capacité
    pub fn record_audit_entry(
        &mut self,
        cap: &NdrCap,
        tag: &str,
        timestamp: u64,
    ) -> Result<[u8; 32], NdrError> {
        if !cap.has_right(ndr_rights::QUERY_AUDIT) && !cap.has_right(ndr_rights::ADMIN) {
            return Err(NdrError::Unauthorized);
        }
        self.record_audit_entry_internal(tag, timestamp)
    }

    /// Vérifie formellement l'intégrité de la chaîne cryptographique SHA-256 du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut cur_hash = Self::GENESIS_HASH;
        for entry_opt in self.audit_ledger.iter().take(self.audit_count) {
            if let Some(ref entry) = entry_opt {
                if entry.prev_hash != cur_hash {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.index.to_le_bytes());
                hasher.update(&entry.timestamp.to_le_bytes());
                hasher.update(&entry.action_tag[..entry.tag_len]);
                hasher.update(&entry.prev_hash);
                let computed = hasher.finalize();

                if computed != entry.entry_hash {
                    return false;
                }
                cur_hash = entry.entry_hash;
            } else {
                return false;
            }
        }
        cur_hash == self.ledger_hash
    }

    /// Fournit un résumé consolidé de l'état du sous-système NDR
    pub fn summary(&self) -> NdrSummary {
        let mut active = 0u32;
        for f in self.flows.iter().take(self.flow_count).flatten() {
            if f.state == FlowState::Active || f.state == FlowState::Established {
                active += 1;
            }
        }

        let mut quarantined_count = 0u32;
        for q in self
            .quarantined
            .iter()
            .take(self.quarantined_count)
            .flatten()
        {
            if q.active {
                quarantined_count += 1;
            }
        }

        NdrSummary {
            active_flows: active,
            total_flows_tracked: self.total_flows_tracked,
            quarantined_endpoints: quarantined_count,
            threats_detected: self.threat_count as u32,
            c2_beacons_detected: self.c2_beacons_detected,
            exfiltrations_detected: self.exfiltrations_detected,
            dns_tunnels_detected: self.dns_tunnels_detected,
            microseg_violations: self.microseg_violations,
            audit_count: self.audit_count as u32,
            ledger_valid: self.verify_ledger_integrity(),
        }
    }

    pub fn get_flow(&self, flow_id: u32) -> Option<&NetworkFlow> {
        self.flows
            .iter()
            .take(self.flow_count)
            .flatten()
            .find(|f| f.flow_id == flow_id)
    }

    pub fn quarantined_active_count(&self) -> usize {
        let mut count = 0;
        for q in self
            .quarantined
            .iter()
            .take(self.quarantined_count)
            .flatten()
        {
            if q.active {
                count += 1;
            }
        }
        count
    }

    /// Traitement déterministe d'une requête IPC calibrée à 64 octets
    pub fn dispatch_ipc(&mut self, req: &NdrRequest) -> NdrResponse {
        let mut resp = NdrResponse::new();
        resp.flow_id = req.flow_id;
        resp.audit_hash.copy_from_slice(&self.ledger_hash[..16]);

        if req.magic != NDR_MAGIC_REQ {
            resp.status = 1;
            resp.set_status_str("BAD_MAGIC");
            return resp;
        }

        let opcode = match NdrOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                resp.status = 2;
                resp.set_status_str("BAD_OPCODE");
                return resp;
            }
        };

        let cap = NdrCap::new(Handle::new(req.handle_id, 1), req.rights, 10_000, 1000);

        match opcode {
            NdrOpcode::GetStatus => {
                if !cap.has_right(ndr_rights::QUERY_METRICS) && !cap.has_right(ndr_rights::ADMIN) {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let summary = self.summary();
                resp.status = 0;
                resp.active_flows = summary.active_flows;
                resp.quarantined_count = summary.quarantined_endpoints;
                resp.threats_detected = summary.threats_detected;
                resp.set_status_str("STATUS_OK");
            }
            NdrOpcode::InspectFlow => {
                if !cap.has_right(ndr_rights::INSPECT_FLOW) && !cap.has_right(ndr_rights::ADMIN) {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                if self.is_endpoint_quarantined(&req.endpoint_ip) {
                    resp.status = 4;
                    resp.flow_action = RuleAction::Drop as u8;
                    resp.threat_severity = ThreatSeverity::Critical as u8;
                    resp.set_status_str("FLOW_BLOCKED");
                    return resp;
                }
                let zone = SecurityZone::from_u8(req.zone).unwrap_or(SecurityZone::ZoneUserApps);
                let action = self.evaluate_flow_policy(
                    zone,
                    SecurityZone::ZoneCoreServices,
                    Some(ProtocolType::Tcp),
                    None,
                );
                resp.status = 0;
                resp.flow_action = action as u8;
                if action == RuleAction::Drop {
                    resp.threat_severity = ThreatSeverity::High as u8;
                    resp.set_status_str("FLOW_DROPPED");
                } else {
                    resp.set_status_str("FLOW_ALLOWED");
                }
            }
            NdrOpcode::QuarantineEndpoint => {
                if !cap.has_right(ndr_rights::QUARANTINE_FLOW) && !cap.has_right(ndr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let reason = req.reason_as_str();
                let epoch = if req.epoch != 0 { req.epoch } else { 1 };
                match self.quarantine_endpoint_internal(req.endpoint_ip, reason, epoch) {
                    Ok(_) => {
                        resp.status = 0;
                        resp.quarantined_count = self.quarantined_active_count() as u32;
                        resp.set_status_str("QUARANTINED");
                    }
                    Err(NdrError::TableFull) => {
                        resp.status = 5;
                        resp.set_status_str("TABLE_FULL");
                    }
                    Err(_) => {
                        resp.status = 6;
                        resp.set_status_str("QUARANTINE_ERR");
                    }
                }
            }
            NdrOpcode::ReleaseEndpoint => {
                if !cap.has_right(ndr_rights::QUARANTINE_FLOW) && !cap.has_right(ndr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let epoch = if req.epoch != 0 { req.epoch } else { 1 };
                match self.release_endpoint_internal(&req.endpoint_ip, epoch) {
                    Ok(_) => {
                        resp.status = 0;
                        resp.quarantined_count = self.quarantined_active_count() as u32;
                        resp.set_status_str("RELEASED");
                    }
                    Err(NdrError::FlowNotFound) => {
                        resp.status = 7;
                        resp.set_status_str("NOT_FOUND");
                    }
                    Err(_) => {
                        resp.status = 8;
                        resp.set_status_str("RELEASE_ERR");
                    }
                }
            }
            NdrOpcode::ConfigurePolicy => {
                if !cap.has_right(ndr_rights::CONFIGURE_POLICY) && !cap.has_right(ndr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let src_zone =
                    SecurityZone::from_u8(req.zone).unwrap_or(SecurityZone::ZoneUserApps);
                let action = RuleAction::from_u8(req.action);
                match self.add_rule_internal(
                    src_zone,
                    SecurityZone::ZoneCoreServices,
                    None,
                    None,
                    action,
                ) {
                    Ok(_) => {
                        resp.status = 0;
                        resp.set_status_str("POLICY_CONFIGURED");
                    }
                    Err(_) => {
                        resp.status = 9;
                        resp.set_status_str("CONFIG_ERR");
                    }
                }
            }
            NdrOpcode::QueryAudit => {
                if !cap.has_right(ndr_rights::QUERY_AUDIT) && !cap.has_right(ndr_rights::ADMIN) {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                resp.status = 0;
                resp.threats_detected = self.audit_count as u32;
                resp.set_status_str("AUDIT_OK");
            }
            NdrOpcode::GetThreats => {
                if !cap.has_right(ndr_rights::DETECT_ANOMALY)
                    && !cap.has_right(ndr_rights::QUERY_AUDIT)
                    && !cap.has_right(ndr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                resp.status = 0;
                resp.threats_detected = self.threat_count as u32;
                resp.set_status_str("THREATS_OK");
            }
        }

        resp.audit_hash.copy_from_slice(&self.ledger_hash[..16]);
        resp
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] COMPATIBLES)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ndr_capability_attenuation() {
        let root_cap = NdrCap::new(Handle::new(12000, 1), ndr_rights::ALL, 10000, 100);
        assert!(root_cap.has_right(ndr_rights::INSPECT_FLOW));
        assert!(root_cap.has_right(ndr_rights::DETECT_ANOMALY));
        assert!(root_cap.has_right(ndr_rights::ENFORCE_MICROSEG));
        assert!(root_cap.has_right(ndr_rights::QUARANTINE_FLOW));
        assert!(root_cap.has_right(ndr_rights::ADMIN));

        // Atténuation légitime
        let monitor_cap = root_cap
            .attenuate(
                ndr_rights::INSPECT_FLOW | ndr_rights::QUERY_METRICS | ndr_rights::QUERY_AUDIT,
                5000,
                50,
            )
            .expect("Atténuation monotone");
        assert!(monitor_cap.has_right(ndr_rights::INSPECT_FLOW));
        assert!(monitor_cap.has_right(ndr_rights::QUERY_METRICS));
        assert!(monitor_cap.has_right(ndr_rights::QUERY_AUDIT));
        assert!(!monitor_cap.has_right(ndr_rights::QUARANTINE_FLOW));
        assert!(!monitor_cap.has_right(ndr_rights::ADMIN));

        // Rejet d'amplification illégale de privilèges
        let invalid = monitor_cap.attenuate(ndr_rights::ALL, 5000, 50);
        assert_eq!(invalid, Err(NdrError::AttenuationViolation));
    }

    #[test]
    fn test_c2_beaconing_detection() {
        let admin_cap = NdrCap::new(Handle::new(12001, 1), ndr_rights::ALL, 10000, 100);
        let mut daemon = JamboNdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let src_ip = [192, 168, 1, 50];
        let dst_ip = [10, 0, 0, 99];

        // 1. Ingestion de paquets périodiques avec très faible gigue (< 50ms)
        // Intervalles : 1000ms, 1010ms, 1005ms (différences: 10ms, 5ms < 50ms)
        let _ = daemon.ingest_packet(
            &admin_cap,
            1,
            src_ip,
            dst_ip,
            49152,
            443,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            b"beacon-syn",
            1000,
        );
        let _ = daemon.ingest_packet(
            &admin_cap,
            1,
            src_ip,
            dst_ip,
            49152,
            443,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            b"beacon-ping",
            2000,
        );
        let _ = daemon.ingest_packet(
            &admin_cap,
            1,
            src_ip,
            dst_ip,
            49152,
            443,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            b"beacon-ping",
            3010,
        );
        // Le 4ème paquet consécutif avec faible variance déclenche la détection C2
        let res_c2 = daemon.ingest_packet(
            &admin_cap,
            1,
            src_ip,
            dst_ip,
            49152,
            443,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            b"beacon-ping",
            4015,
        );

        assert_eq!(res_c2, Err(NdrError::FlowBlocked));
        assert_eq!(daemon.c2_beacons_detected, 1);
        assert!(daemon.is_endpoint_quarantined(&src_ip));

        // Tout paquet ultérieur doit être rejeté instantanément O(1)
        let res_subsequent = daemon.ingest_packet(
            &admin_cap,
            2,
            src_ip,
            dst_ip,
            49153,
            80,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            b"data",
            5000,
        );
        assert_eq!(res_subsequent, Err(NdrError::FlowBlocked));
    }

    #[test]
    fn test_massive_data_exfiltration_detection() {
        let admin_cap = NdrCap::new(Handle::new(12002, 1), ndr_rights::ALL, 10000, 100);
        let mut daemon = JamboNdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let src_ip = [192, 168, 1, 60];
        let dst_ip = [10, 0, 0, 100];

        // Paquet normal de 1024 octets (autorisé)
        let chunk = [0x55u8; 1024];
        let r1 = daemon.ingest_packet(
            &admin_cap,
            10,
            src_ip,
            dst_ip,
            50000,
            443,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            &chunk,
            100,
        );
        assert_eq!(r1, Ok(RuleAction::Allow));

        // Simulation d'une rafale exfiltrant plus de 64 Kio (ex: 65 000 octets cumulés)
        let big_chunk = [0xAAu8; 65_000];
        let r2 = daemon.ingest_packet(
            &admin_cap,
            10,
            src_ip,
            dst_ip,
            50000,
            443,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            &big_chunk,
            200,
        );
        assert_eq!(r2, Err(NdrError::FlowBlocked));
        assert_eq!(daemon.exfiltrations_detected, 1);
        assert!(daemon.is_endpoint_quarantined(&src_ip));
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let admin_cap = NdrCap::new(Handle::new(12003, 1), ndr_rights::ALL, 10000, 100);
        let mut daemon = JamboNdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let src_ip = [192, 168, 1, 70];
        let dns_server = [8, 8, 8, 8];

        // 1. Requête DNS normale (saine)
        let clean_query = b"api.jambo.local";
        let r_clean = daemon.ingest_packet(
            &admin_cap,
            20,
            src_ip,
            dns_server,
            53535,
            53,
            ProtocolType::Dns,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            clean_query,
            100,
        );
        assert_eq!(r_clean, Ok(RuleAction::Allow));
        assert_eq!(daemon.dns_tunnels_detected, 0);

        // 2. Requête DNS de tunneling à haute entropie et longue charge utile exfiltrée
        let tunnel_query = b"b83ac79e4d21f8a9e701bc493a7d2e05fa813c9b7e12.tunnel.c2.net";
        let r_tunnel = daemon.ingest_packet(
            &admin_cap,
            21,
            src_ip,
            dns_server,
            53536,
            53,
            ProtocolType::Dns,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            tunnel_query,
            200,
        );
        assert_eq!(r_tunnel, Err(NdrError::FlowBlocked));
        assert_eq!(daemon.dns_tunnels_detected, 1);
        assert!(daemon.is_endpoint_quarantined(&src_ip));
    }

    #[test]
    fn test_dynamic_microsegmentation_matrix() {
        let admin_cap = NdrCap::new(Handle::new(12004, 1), ndr_rights::ALL, 10000, 100);
        let mut daemon = JamboNdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // 1. Kernel <-> CoreServices autorisé par défaut
        let a1 = daemon.evaluate_flow_policy(
            SecurityZone::ZoneKernel,
            SecurityZone::ZoneCoreServices,
            Some(ProtocolType::Tcp),
            None,
        );
        assert_eq!(a1, RuleAction::Allow);

        // 2. UserApps -> Kernel direct strictement rejeté (deny-by-default)
        let a2 = daemon.evaluate_flow_policy(
            SecurityZone::ZoneUserApps,
            SecurityZone::ZoneKernel,
            Some(ProtocolType::Tcp),
            None,
        );
        assert_eq!(a2, RuleAction::Drop);

        // 3. ExternalNetwork -> Cryptographic direct strictement rejeté
        let a3 = daemon.evaluate_flow_policy(
            SecurityZone::ZoneExternalNetwork,
            SecurityZone::ZoneCryptographic,
            Some(ProtocolType::Tcp),
            None,
        );
        assert_eq!(a3, RuleAction::Drop);

        // 4. ZoneQuarantine toujours rejetée
        let a4 = daemon.evaluate_flow_policy(
            SecurityZone::ZoneQuarantine,
            SecurityZone::ZoneCoreServices,
            Some(ProtocolType::Tcp),
            None,
        );
        assert_eq!(a4, RuleAction::Drop);

        // 5. Ajout d'une règle dynamique
        daemon
            .add_traffic_rule(
                &admin_cap,
                SecurityZone::ZoneUserApps,
                SecurityZone::ZoneCryptographic,
                Some(ProtocolType::Tcp),
                Some(8443),
                RuleAction::Allow,
                300,
            )
            .expect("Add rule");

        let a5 = daemon.evaluate_flow_policy(
            SecurityZone::ZoneUserApps,
            SecurityZone::ZoneCryptographic,
            Some(ProtocolType::Tcp),
            Some(8443),
        );
        assert_eq!(a5, RuleAction::Allow);
    }

    #[test]
    fn test_instant_isolation_o1() {
        let admin_cap = NdrCap::new(Handle::new(12005, 1), ndr_rights::ALL, 10000, 100);
        let mut daemon = JamboNdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let rogue_ip = [10, 1, 2, 3];
        assert!(!daemon.is_endpoint_quarantined(&rogue_ip));

        // Mise en quarantaine manuelle
        daemon
            .quarantine_endpoint(&admin_cap, rogue_ip, "Manual SOC Quarantine", 500)
            .expect("Quarantine IP");
        assert!(daemon.is_endpoint_quarantined(&rogue_ip));

        // Tentative de paquet -> Rejet immédiat O(1)
        let res = daemon.ingest_packet(
            &admin_cap,
            30,
            rogue_ip,
            [192, 168, 1, 1],
            4000,
            80,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            b"test",
            550,
        );
        assert_eq!(res, Err(NdrError::FlowBlocked));

        // Levée de quarantaine
        daemon
            .release_endpoint(&admin_cap, rogue_ip, 600)
            .expect("Release IP");
        assert!(!daemon.is_endpoint_quarantined(&rogue_ip));

        // Paquet à nouveau accepté
        let res2 = daemon.ingest_packet(
            &admin_cap,
            31,
            rogue_ip,
            [192, 168, 1, 1],
            4000,
            80,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            b"test",
            650,
        );
        assert_eq!(res2, Ok(RuleAction::Allow));
    }

    #[test]
    fn test_audit_ledger_cryptographic_integrity() {
        let admin_cap = NdrCap::new(Handle::new(12006, 1), ndr_rights::ALL, 10000, 100);
        let mut daemon = JamboNdrDaemon::new(admin_cap);
        daemon.init_defaults();

        assert!(daemon.verify_ledger_integrity());
        assert_ne!(daemon.ledger_hash, JamboNdrDaemon::GENESIS_HASH);

        // Ajout d'une entrée manuelle
        let new_hash = daemon
            .record_audit_entry(&admin_cap, "MANUAL_CHECK", 700)
            .expect("Record audit");
        assert_eq!(new_hash, daemon.ledger_hash);
        assert!(daemon.verify_ledger_integrity());

        // Simulation d'une altération malveillante
        if let Some(ref mut entry) = daemon.audit_ledger[0] {
            entry.action_tag[0] ^= 0xFF; // Corruption de données
        }
        assert!(!daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_ipc_request_response_serialization_64_bytes() {
        assert_eq!(core::mem::size_of::<NdrRequest>(), 64);
        assert_eq!(core::mem::size_of::<NdrResponse>(), 64);

        let req = NdrRequest::new_quarantine(
            NDR_ENDPOINT_ID,
            ndr_rights::QUARANTINE_FLOW,
            [172, 16, 0, 5],
            "C2 Beaconing Detected",
            12345678,
        );
        let req_bytes = req.to_bytes();
        assert_eq!(req_bytes.len(), 64);

        let parsed_req = NdrRequest::from_bytes(&req_bytes).expect("parse req");
        assert_eq!(parsed_req.magic, NDR_MAGIC_REQ);
        assert_eq!(parsed_req.opcode, NdrOpcode::QuarantineEndpoint as u32);
        assert_eq!(parsed_req.endpoint_ip, [172, 16, 0, 5]);
        assert_eq!(parsed_req.reason_as_str(), "C2 Beaconing Detected");
        let epoch = parsed_req.epoch;
        assert_eq!(epoch, 12345678);

        let mut resp = NdrResponse::new();
        resp.status = 0;
        resp.active_flows = 5;
        resp.quarantined_count = 2;
        resp.threats_detected = 3;
        resp.flow_action = RuleAction::Allow as u8;
        resp.threat_severity = ThreatSeverity::High as u8;
        resp.flow_id = 42;
        resp.audit_hash = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        resp.set_status_str("STATUS_OK");

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);

        let parsed_resp = NdrResponse::from_bytes(&resp_bytes).expect("parse resp");
        assert_eq!(parsed_resp.magic, NDR_MAGIC_RESP);
        assert_eq!(parsed_resp.status, 0);
        assert_eq!(parsed_resp.active_flows, 5);
        assert_eq!(parsed_resp.quarantined_count, 2);
        assert_eq!(parsed_resp.threats_detected, 3);
        assert_eq!(parsed_resp.flow_action, RuleAction::Allow as u8);
        assert_eq!(parsed_resp.threat_severity, ThreatSeverity::High as u8);
        assert_eq!(parsed_resp.flow_id, 42);
        assert_eq!(parsed_resp.status_as_str(), "STATUS_OK");
    }

    #[test]
    fn test_ipc_dispatch_operations() {
        let admin_cap = NdrCap::new(Handle::new(12007, 1), ndr_rights::ALL, 10000, 100);
        let mut daemon = JamboNdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // 1. GetStatus
        let req_status = NdrRequest::new_status(NDR_ENDPOINT_ID, ndr_rights::ALL);
        let resp_status = daemon.dispatch_ipc(&req_status);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.status_as_str(), "STATUS_OK");

        // 2. QuarantineEndpoint
        let req_quar = NdrRequest::new_quarantine(
            NDR_ENDPOINT_ID,
            ndr_rights::ALL,
            [10, 10, 10, 10],
            "IPC Quarantine",
            100,
        );
        let resp_quar = daemon.dispatch_ipc(&req_quar);
        assert_eq!(resp_quar.status, 0);
        assert_eq!(resp_quar.status_as_str(), "QUARANTINED");
        assert_eq!(resp_quar.quarantined_count, 1);

        // 3. InspectFlow (sur l'hôte en quarantaine -> rejeté)
        let req_inspect_blocked = NdrRequest::new_inspect(
            NDR_ENDPOINT_ID,
            ndr_rights::ALL,
            99,
            [10, 10, 10, 10],
            SecurityZone::ZoneUserApps as u8,
            150,
        );
        let resp_blocked = daemon.dispatch_ipc(&req_inspect_blocked);
        assert_eq!(resp_blocked.status, 4);
        assert_eq!(resp_blocked.status_as_str(), "FLOW_BLOCKED");

        // 4. ReleaseEndpoint
        let req_rel =
            NdrRequest::new_release(NDR_ENDPOINT_ID, ndr_rights::ALL, [10, 10, 10, 10], 200);
        let resp_rel = daemon.dispatch_ipc(&req_rel);
        assert_eq!(resp_rel.status, 0);
        assert_eq!(resp_rel.status_as_str(), "RELEASED");
        assert_eq!(resp_rel.quarantined_count, 0);

        // 5. QueryAudit
        let req_audit = NdrRequest::new_query_audit(NDR_ENDPOINT_ID, ndr_rights::ALL);
        let resp_audit = daemon.dispatch_ipc(&req_audit);
        assert_eq!(resp_audit.status, 0);
        assert_eq!(resp_audit.status_as_str(), "AUDIT_OK");

        // 6. GetThreats
        let req_threats = NdrRequest::new_get_threats(NDR_ENDPOINT_ID, ndr_rights::ALL);
        let resp_threats = daemon.dispatch_ipc(&req_threats);
        assert_eq!(resp_threats.status, 0);
        assert_eq!(resp_threats.status_as_str(), "THREATS_OK");

        // 7. Mauvais Magic
        let mut bad_req = req_status;
        bad_req.magic = 0x12345678;
        let resp_bad = daemon.dispatch_ipc(&bad_req);
        assert_eq!(resp_bad.status, 1);
        assert_eq!(resp_bad.status_as_str(), "BAD_MAGIC");

        // 8. Droit refusé
        let denied_req = NdrRequest::new_status(NDR_ENDPOINT_ID, ndr_rights::INSPECT_FLOW);
        let resp_denied = daemon.dispatch_ipc(&denied_req);
        assert_eq!(resp_denied.status, 13);
        assert_eq!(resp_denied.status_as_str(), "CAP_DENIED");
    }
}

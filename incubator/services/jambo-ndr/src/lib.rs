//! Détection Réseau & Micro-segmentation Souveraine (NDR - Network Detection & Sovereign Microsegmentation Resilience)
//!
//! Phase 143 — Jalon v0.3.10
//!
//! Fournit un sous-système souverain de détection réseau temps réel et de micro-segmentation dynamique Zero-Trust en `#![no_std]` :
//! 1. Surveillance active des flux réseau inter-services et périphériques (L2-L7).
//! 2. Détection d'anomalies de trafic (balisage C2 / jitter périodique, exfiltration massive, tunneling DNS, scan de ports).
//! 3. Micro-segmentation dynamique Zero-Trust (zones de sécurité, politiques fines par port/protocole, isolation Ring 0 / Ring 3).
//! 4. Confinement et coupure immédiate O(1) des flux suspects et des adresses réseau compromises (`quarantine_endpoint`).
//! 5. Contrôle d'accès capabilaire (`NdrCap`) avec atténuation monotone stricte.
//! 6. Registre d'audit SHA-256 inaltérable scellé par chaînage cryptographique.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation autonome et déterministe de SHA-256 pour micro-noyau et services réseau
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
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

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes += data.len() as u64;

        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
                self.process_block();
                data = &data[needed..];
                self.buffer_len = 0;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while data.len() >= 64 {
            self.buffer.copy_from_slice(&data[..64]);
            self.process_block();
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_bytes * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            self.process_block();
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        self.process_block();

        let mut output = [0u8; 32];
        for i in 0..8 {
            output[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        output
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                self.buffer[i * 4],
                self.buffer[i * 4 + 1],
                self.buffer[i * 4 + 2],
                self.buffer[i * 4 + 3],
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
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (NdrCap)
// ============================================================================

pub mod ndr_rights {
    pub const INSPECT_FLOW: u32 = 1 << 0;
    pub const DETECT_ANOMALY: u32 = 1 << 1;
    pub const ENFORCE_MICROSEG: u32 = 1 << 2;
    pub const QUARANTINE_FLOW: u32 = 1 << 3;
    pub const CONFIGURE_POLICY: u32 = 1 << 4;
    pub const QUERY_METRICS: u32 = 1 << 5;
    pub const QUERY_AUDIT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;
    pub const ALL: u32 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdrError {
    PermissionDenied,
    AttenuationViolation,
    FlowNotFound,
    FlowTableFull,
    RuleTableFull,
    ThreatTableFull,
    EndpointTableFull,
    AuditLogFull,
    InvalidParameter,
    EndpointAlreadyQuarantined,
    RuleNotFound,
    MicrosegmentViolation,
    FlowBlocked,
}

/// Capabilité de contrôle d'accès avec atténuation monotone stricte pour le moteur NDR
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

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone stricte : aucun privilège supplémentaire, plafonnement de durée et d'invocations
    pub fn attenuate(
        &self,
        requested_rights: u32,
        lifetime_limit: u64,
        max_invocations: u32,
    ) -> Result<Self, NdrError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(NdrError::AttenuationViolation);
        }
        if lifetime_limit > self.max_lifetime {
            return Err(NdrError::AttenuationViolation);
        }
        if max_invocations > self.invocations_left {
            return Err(NdrError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
            max_lifetime: lifetime_limit,
            invocations_left: max_invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), NdrError> {
        if self.invocations_left == 0 {
            return Err(NdrError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES RÉSEAU SOUVERAINES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    Any,
    Ethernet,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Dns,
    Tls,
    HttpIpc,
}

impl ProtocolType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolType::Any => "ANY",
            ProtocolType::Ethernet => "ETHERNET",
            ProtocolType::Ipv4 => "IPv4",
            ProtocolType::Ipv6 => "IPv6",
            ProtocolType::Tcp => "TCP",
            ProtocolType::Udp => "UDP",
            ProtocolType::Icmp => "ICMP",
            ProtocolType::Dns => "DNS",
            ProtocolType::Tls => "TLS",
            ProtocolType::HttpIpc => "HTTP/IPC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityZone {
    ZoneKernel,
    ZoneCoreServices,
    ZoneCryptographic,
    ZoneUserApps,
    ZoneExternalNetwork,
    ZoneQuarantine,
}

impl SecurityZone {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityZone::ZoneKernel => "Zone Kernel (Ring 0)",
            SecurityZone::ZoneCoreServices => "Zone Core Services (Ring 3 Privilégié)",
            SecurityZone::ZoneCryptographic => "Zone Cryptographique (KMS/HSM/TEE)",
            SecurityZone::ZoneUserApps => "Zone Applications Utilisateur",
            SecurityZone::ZoneExternalNetwork => "Zone Réseau Externe / WAN",
            SecurityZone::ZoneQuarantine => "Zone de Confinement O(1)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    Active,
    Monitored,
    Quarantined,
    Blocked,
    Terminated,
}

impl FlowState {
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowState::Active => "ACTIF",
            FlowState::Monitored => "SUPERVISÉ",
            FlowState::Quarantined => "CONFINÉ O(1)",
            FlowState::Blocked => "BLOQUÉ",
            FlowState::Terminated => "TERMINÉ",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatSeverity::Clean => "SAIN",
            ThreatSeverity::Low => "FAIBLE",
            ThreatSeverity::Medium => "MOYEN",
            ThreatSeverity::High => "ÉLEVÉ",
            ThreatSeverity::Critical => "CRITIQUE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdrThreatType {
    C2Beaconing,
    DataExfiltration,
    PortScanning,
    DnsTunneling,
    LateralMovement,
    ProtocolAnomaly,
    ZeroTrustViolation,
}

impl NdrThreatType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NdrThreatType::C2Beaconing => "Balisage C2 détecté (périodicité suspecte)",
            NdrThreatType::DataExfiltration => "Exfiltration massive de données",
            NdrThreatType::PortScanning => "Balayage de ports réseau / Reconnaissance",
            NdrThreatType::DnsTunneling => "Tunneling DNS / Exfiltration par canal covert",
            NdrThreatType::LateralMovement => "Mouvement latéral inter-services non autorisé",
            NdrThreatType::ProtocolAnomaly => "Anomalie protocolaire L4-L7",
            NdrThreatType::ZeroTrustViolation => {
                "Violation stricte de micro-segmentation Zero-Trust"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
    QuarantineOnSuspicion,
    DeepInspect,
}

impl RuleAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleAction::Allow => "AUTORISER",
            RuleAction::Deny => "REFUSER",
            RuleAction::QuarantineOnSuspicion => "CONFINER SI SUSPECT",
            RuleAction::DeepInspect => "INSPECTION APPROFONDIE",
        }
    }
}

/// Règle souveraine de micro-segmentation Zero-Trust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MicrosegmentRule {
    pub rule_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub src_zone: SecurityZone,
    pub dst_zone: SecurityZone,
    pub protocol: ProtocolType,
    pub dst_port: u16, // 0 = Tout port
    pub action: RuleAction,
    pub priority: u16,
    pub enforced: bool,
    pub hits: u64,
}

/// Modélisation d'un flux réseau supervisé en temps réel
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
    pub service_name: [u8; 32],
    pub service_name_len: usize,
    pub packets_count: u64,
    pub bytes_transferred: u64,
    pub state: FlowState,
    pub threat_level: ThreatSeverity,
    pub detected_threat: Option<NdrThreatType>,
    pub last_packet_time: u64,
    pub last_delta_ms: u64,
    pub beacon_count: u32,
    pub quarantined: bool,
}

/// Enregistrement d'un incident de sécurité réseau
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatIncident {
    pub incident_id: u32,
    pub flow_id: u32,
    pub threat_type: NdrThreatType,
    pub severity: ThreatSeverity,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub timestamp: u64,
    pub quarantined: bool,
    pub details: [u8; 48],
    pub details_len: usize,
}

/// Hôte ou adresse IP confiné(e) en O(1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantinedEndpoint {
    pub endpoint_id: u32,
    pub ip: [u8; 4],
    pub reason: [u8; 48],
    pub reason_len: usize,
    pub timestamp: u64,
    pub packets_blocked: u64,
    pub active: bool,
}

/// Entrée d'audit cryptographique inviolable SHA-256
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrAuditEntry {
    pub index: u32,
    pub timestamp: u64,
    pub event_code: u16,
    pub detail: [u8; 48],
    pub detail_len: usize,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

/// Bilan synthétique du démon NDR souverain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdrSummary {
    pub flows_count: usize,
    pub active_flows_count: usize,
    pub quarantined_flows_count: usize,
    pub rules_count: usize,
    pub threats_detected: usize,
    pub threats_blocked: usize,
    pub quarantined_endpoints_count: usize,
    pub audit_entries_count: usize,
    pub ledger_valid: bool,
}

// ============================================================================
// DÉMON SOUVERAIN DE DÉTECTION RÉSEAU (JamboNdrDaemon)
// ============================================================================

pub const MAX_FLOWS: usize = 32;
pub const MAX_RULES: usize = 16;
pub const MAX_THREATS: usize = 16;
pub const MAX_QUARANTINED: usize = 8;
pub const MAX_AUDIT: usize = 32;

pub const EXFILTRATION_BYTE_THRESHOLD: u64 = 65_536; // 64 Ko
pub const C2_BEACON_MIN_INTERVAL: u64 = 900; // ms
pub const C2_BEACON_MAX_INTERVAL: u64 = 1100; // ms (autour de 1s avec gigue)
pub const C2_BEACON_STRIKE_THRESHOLD: u32 = 3;

pub struct JamboNdrDaemon {
    pub cap: NdrCap,
    pub flows: [Option<NetworkFlow>; MAX_FLOWS],
    pub flow_count: usize,
    pub rules: [Option<MicrosegmentRule>; MAX_RULES],
    pub rule_count: usize,
    pub threats: [Option<ThreatIncident>; MAX_THREATS],
    pub threat_count: usize,
    pub quarantined_endpoints: [Option<QuarantinedEndpoint>; MAX_QUARANTINED],
    pub quarantined_count: usize,
    pub audit_log: [Option<NdrAuditEntry>; MAX_AUDIT],
    pub audit_count: usize,
    pub last_audit_hash: [u8; 32],
    pub next_flow_id: u32,
    pub next_rule_id: u32,
    pub next_threat_id: u32,
    pub next_endpoint_id: u32,
}

impl JamboNdrDaemon {
    pub fn new(cap: NdrCap) -> Self {
        let genesis_seed = b"JAMBO_SOVEREIGN_NDR_GENESIS_LEDGER_CHAIN_v0.3.10";
        let initial_hash = Sha256::digest(genesis_seed);

        Self {
            cap,
            flows: [None; MAX_FLOWS],
            flow_count: 0,
            rules: [None; MAX_RULES],
            rule_count: 0,
            threats: [None; MAX_THREATS],
            threat_count: 0,
            quarantined_endpoints: [None; MAX_QUARANTINED],
            quarantined_count: 0,
            audit_log: [None; MAX_AUDIT],
            audit_count: 0,
            last_audit_hash: initial_hash,
            next_flow_id: 1,
            next_rule_id: 1,
            next_threat_id: 1,
            next_endpoint_id: 1,
        }
    }

    /// Initialise la configuration et les règles de micro-segmentation Zero-Trust par défaut
    pub fn init_defaults(&mut self) {
        // Règles Zero-Trust par défaut
        // Règle 1 : Kernel <-> CoreServices (IPC Inter-Anneaux)
        let _ = self.add_microsegment_rule(
            "kernel-core-ipc",
            SecurityZone::ZoneKernel,
            SecurityZone::ZoneCoreServices,
            ProtocolType::HttpIpc,
            0,
            RuleAction::Allow,
            100,
        );

        // Règle 2 : CoreServices <-> Cryptographic (TEE, KMS, HSM)
        let _ = self.add_microsegment_rule(
            "core-crypto-auth",
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneCryptographic,
            ProtocolType::Tcp,
            8443,
            RuleAction::Allow,
            90,
        );

        // Règle 3 : UserApps <-> CoreServices (IPC Port 8080)
        let _ = self.add_microsegment_rule(
            "userapps-core-ipc",
            SecurityZone::ZoneUserApps,
            SecurityZone::ZoneCoreServices,
            ProtocolType::HttpIpc,
            8080,
            RuleAction::Allow,
            80,
        );

        // Règle 4 : UserApps <-> Cryptographique direct : INTERDIT / Confinement sur suspicion
        let _ = self.add_microsegment_rule(
            "userapps-crypto-deny",
            SecurityZone::ZoneUserApps,
            SecurityZone::ZoneCryptographic,
            ProtocolType::Any,
            0,
            RuleAction::QuarantineOnSuspicion,
            200, // Priorité forte
        );

        // Règle 5 : Réseau Externe <-> Kernel : INTERDIT ABSOLU
        let _ = self.add_microsegment_rule(
            "ext-kernel-block",
            SecurityZone::ZoneExternalNetwork,
            SecurityZone::ZoneKernel,
            ProtocolType::Any,
            0,
            RuleAction::Deny,
            250,
        );

        // Règle 6 : CoreServices -> Réseau Externe (HTTPS sortant supervisé)
        let _ = self.add_microsegment_rule(
            "core-ext-https",
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            ProtocolType::Tcp,
            443,
            RuleAction::Allow,
            60,
        );

        // Règle 7 : CoreServices -> Réseau Externe (Résolution DNS sortante)
        let _ = self.add_microsegment_rule(
            "core-ext-dns",
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            ProtocolType::Dns,
            53,
            RuleAction::Allow,
            60,
        );

        // Règle 8 : Réseau Externe -> CoreServices : Inspection approfondie
        let _ = self.add_microsegment_rule(
            "ext-core-deepinspect",
            SecurityZone::ZoneExternalNetwork,
            SecurityZone::ZoneCoreServices,
            ProtocolType::Tcp,
            443,
            RuleAction::DeepInspect,
            50,
        );

        // Flux réseau initiaux représentatifs
        let _ = self.register_flow(
            [127, 0, 0, 1],
            [127, 0, 0, 2],
            9000,
            9001,
            ProtocolType::HttpIpc,
            SecurityZone::ZoneKernel,
            SecurityZone::ZoneCoreServices,
            "kernel-sched-bus",
        );

        let _ = self.register_flow(
            [10, 0, 0, 10],
            [10, 0, 0, 20],
            45000,
            8443,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneCryptographic,
            "kms-auth-session",
        );

        let _ = self.register_flow(
            [192, 168, 1, 50],
            [192, 168, 1, 1],
            53535,
            53,
            ProtocolType::Dns,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            "jambo-dns-resolver",
        );

        self.append_audit_entry(
            1001,
            b"NDR Zero-Trust microsegmentation rules and baseline initialized",
            1735000000,
        );
    }

    /// Enregistre une règle de micro-segmentation Zero-Trust
    pub fn add_microsegment_rule(
        &mut self,
        name: &str,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        protocol: ProtocolType,
        dst_port: u16,
        action: RuleAction,
        priority: u16,
    ) -> Result<u32, NdrError> {
        if self.rule_count >= MAX_RULES {
            return Err(NdrError::RuleTableFull);
        }

        let mut name_buf = [0u8; 32];
        let bytes = name.as_bytes();
        let len = if bytes.len() > 32 { 32 } else { bytes.len() };
        name_buf[..len].copy_from_slice(&bytes[..len]);

        let rule_id = self.next_rule_id;
        self.next_rule_id += 1;

        let rule = MicrosegmentRule {
            rule_id,
            name: name_buf,
            name_len: len,
            src_zone,
            dst_zone,
            protocol,
            dst_port,
            action,
            priority,
            enforced: true,
            hits: 0,
        };

        for slot in self.rules.iter_mut() {
            if slot.is_none() {
                *slot = Some(rule);
                self.rule_count += 1;
                return Ok(rule_id);
            }
        }

        Err(NdrError::RuleTableFull)
    }

    /// Enregistre un flux réseau dans la matrice NDR
    pub fn register_flow(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: ProtocolType,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        service_name: &str,
    ) -> Result<u32, NdrError> {
        if self.flow_count >= MAX_FLOWS {
            return Err(NdrError::FlowTableFull);
        }

        let mut name_buf = [0u8; 32];
        let bytes = service_name.as_bytes();
        let len = if bytes.len() > 32 { 32 } else { bytes.len() };
        name_buf[..len].copy_from_slice(&bytes[..len]);

        let flow_id = self.next_flow_id;
        self.next_flow_id += 1;

        // Si l'une des adresses IP est déjà sous quarantaine, le flux est directement confiné
        let is_quarantined =
            self.is_endpoint_quarantined(&src_ip) || self.is_endpoint_quarantined(&dst_ip);

        let flow = NetworkFlow {
            flow_id,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            src_zone,
            dst_zone,
            service_name: name_buf,
            service_name_len: len,
            packets_count: 0,
            bytes_transferred: 0,
            state: if is_quarantined {
                FlowState::Quarantined
            } else {
                FlowState::Active
            },
            threat_level: if is_quarantined {
                ThreatSeverity::Critical
            } else {
                ThreatSeverity::Clean
            },
            detected_threat: if is_quarantined {
                Some(NdrThreatType::ZeroTrustViolation)
            } else {
                None
            },
            last_packet_time: 0,
            last_delta_ms: 0,
            beacon_count: 0,
            quarantined: is_quarantined,
        };

        for slot in self.flows.iter_mut() {
            if slot.is_none() {
                *slot = Some(flow);
                self.flow_count += 1;
                return Ok(flow_id);
            }
        }

        Err(NdrError::FlowTableFull)
    }

    /// Évalue la politique de micro-segmentation pour un flux donné
    pub fn evaluate_traffic_policy(
        &mut self,
        src_zone: SecurityZone,
        dst_zone: SecurityZone,
        dst_port: u16,
        protocol: ProtocolType,
    ) -> RuleAction {
        // Confinement strict : la zone de quarantaine ne peut communiquer nulle part
        if src_zone == SecurityZone::ZoneQuarantine || dst_zone == SecurityZone::ZoneQuarantine {
            return RuleAction::Deny;
        }

        let mut matched_action = RuleAction::Deny; // Zero-Trust : Deny par défaut
        let mut highest_priority: u16 = 0;

        for r_opt in self.rules.iter_mut() {
            if let Some(rule) = r_opt {
                if !rule.enforced {
                    continue;
                }

                let zone_match = rule.src_zone == src_zone && rule.dst_zone == dst_zone;
                let proto_match = rule.protocol == ProtocolType::Any || rule.protocol == protocol;
                let port_match = rule.dst_port == 0 || rule.dst_port == dst_port;

                if zone_match && proto_match && port_match && rule.priority >= highest_priority {
                    highest_priority = rule.priority;
                    matched_action = rule.action;
                    rule.hits += 1;
                }
            }
        }

        matched_action
    }

    /// Analyse et ingère un paquet réseau dans le moteur heuristique NDR
    pub fn ingest_packet(
        &mut self,
        flow_id: u32,
        packet_bytes_len: u64,
        timestamp_ms: u64,
        entropy_score: u8, // 0..100 (ex: 85+ indique chiffrement/tunneling suspect)
    ) -> Result<RuleAction, NdrError> {
        self.cap.consume()?;

        // 1. Recherche du flux
        let flow_idx = self
            .flows
            .iter()
            .position(|f| f.as_ref().map_or(false, |fl| fl.flow_id == flow_id))
            .ok_or(NdrError::FlowNotFound)?;

        let mut flow = self.flows[flow_idx].unwrap();

        // 2. Vérification immédiate du confinement O(1) de l'endpoint
        if self.is_endpoint_quarantined(&flow.src_ip) || flow.quarantined {
            flow.state = FlowState::Quarantined;
            flow.quarantined = true;
            self.flows[flow_idx] = Some(flow);
            self.increment_endpoint_blocked(&flow.src_ip);
            return Err(NdrError::FlowBlocked);
        }

        // 3. Évaluation de la politique de micro-segmentation Zero-Trust
        let policy_action = self.evaluate_traffic_policy(
            flow.src_zone,
            flow.dst_zone,
            flow.dst_port,
            flow.protocol,
        );

        if policy_action == RuleAction::Deny {
            flow.threat_level = ThreatSeverity::High;
            flow.detected_threat = Some(NdrThreatType::ZeroTrustViolation);
            flow.state = FlowState::Blocked;
            self.record_threat(
                flow_id,
                NdrThreatType::ZeroTrustViolation,
                ThreatSeverity::High,
                flow.src_ip,
                flow.dst_ip,
                timestamp_ms,
                false,
                b"Zero-Trust microsegmentation policy denied packet",
            );
            self.flows[flow_idx] = Some(flow);
            return Ok(RuleAction::Deny);
        }

        // 4. Analyse Heuristique : Détection d'Exfiltration massive
        flow.packets_count += 1;
        flow.bytes_transferred += packet_bytes_len;

        if flow.bytes_transferred > EXFILTRATION_BYTE_THRESHOLD
            && flow.dst_zone == SecurityZone::ZoneExternalNetwork
        {
            flow.threat_level = ThreatSeverity::Critical;
            flow.detected_threat = Some(NdrThreatType::DataExfiltration);
            flow.state = FlowState::Quarantined;
            flow.quarantined = true;

            self.record_threat(
                flow_id,
                NdrThreatType::DataExfiltration,
                ThreatSeverity::Critical,
                flow.src_ip,
                flow.dst_ip,
                timestamp_ms,
                true,
                b"Exfiltration threshold exceeded to external network",
            );

            // Confinement instantané O(1)
            let _ = self.quarantine_endpoint(
                flow.src_ip,
                b"Data exfiltration to untrusted WAN",
                timestamp_ms,
            );

            self.flows[flow_idx] = Some(flow);
            return Ok(RuleAction::QuarantineOnSuspicion);
        }

        // 5. Analyse Heuristique : Détection de Balisage C2 (Jitter périodique ~1000ms)
        if flow.last_packet_time > 0 {
            let delta = if timestamp_ms > flow.last_packet_time {
                timestamp_ms - flow.last_packet_time
            } else {
                0
            };
            flow.last_delta_ms = delta;

            if (C2_BEACON_MIN_INTERVAL..=C2_BEACON_MAX_INTERVAL).contains(&delta) {
                flow.beacon_count += 1;
                if flow.beacon_count >= C2_BEACON_STRIKE_THRESHOLD {
                    flow.threat_level = ThreatSeverity::High;
                    flow.detected_threat = Some(NdrThreatType::C2Beaconing);
                    flow.state = FlowState::Quarantined;
                    flow.quarantined = true;

                    self.record_threat(
                        flow_id,
                        NdrThreatType::C2Beaconing,
                        ThreatSeverity::High,
                        flow.src_ip,
                        flow.dst_ip,
                        timestamp_ms,
                        true,
                        b"C2 periodic beaconing detected with low jitter",
                    );

                    let _ = self.quarantine_endpoint(
                        flow.src_ip,
                        b"C2 beaconing behavior detected",
                        timestamp_ms,
                    );

                    self.flows[flow_idx] = Some(flow);
                    return Ok(RuleAction::QuarantineOnSuspicion);
                }
            } else {
                flow.beacon_count = 0;
            }
        }
        flow.last_packet_time = timestamp_ms;

        // 6. Analyse Heuristique : Tunneling DNS
        if flow.protocol == ProtocolType::Dns && entropy_score >= 85 {
            flow.threat_level = ThreatSeverity::Critical;
            flow.detected_threat = Some(NdrThreatType::DnsTunneling);
            flow.state = FlowState::Quarantined;
            flow.quarantined = true;

            self.record_threat(
                flow_id,
                NdrThreatType::DnsTunneling,
                ThreatSeverity::Critical,
                flow.src_ip,
                flow.dst_ip,
                timestamp_ms,
                true,
                b"High entropy encrypted payload in DNS query (Tunnel)",
            );

            let _ =
                self.quarantine_endpoint(flow.src_ip, b"Covert DNS tunnel detected", timestamp_ms);

            self.flows[flow_idx] = Some(flow);
            return Ok(RuleAction::QuarantineOnSuspicion);
        }

        // Action de micro-segmentation conditionnelle
        if policy_action == RuleAction::QuarantineOnSuspicion {
            // Tentative d'accès interdit non autorisée (ex: UserApps vers Cryptographic)
            flow.threat_level = ThreatSeverity::Critical;
            flow.detected_threat = Some(NdrThreatType::ZeroTrustViolation);
            flow.state = FlowState::Quarantined;
            flow.quarantined = true;

            self.record_threat(
                flow_id,
                NdrThreatType::ZeroTrustViolation,
                ThreatSeverity::Critical,
                flow.src_ip,
                flow.dst_ip,
                timestamp_ms,
                true,
                b"Direct unauthorized Ring 3 access to crypto enclave",
            );

            let _ = self.quarantine_endpoint(
                flow.src_ip,
                b"Ring 3 zero-trust isolation breach",
                timestamp_ms,
            );

            self.flows[flow_idx] = Some(flow);
            return Ok(RuleAction::QuarantineOnSuspicion);
        }

        self.flows[flow_idx] = Some(flow);
        Ok(policy_action)
    }

    /// Confinement et coupure immédiate O(1) d'un endpoint suspect
    pub fn quarantine_endpoint(
        &mut self,
        ip: [u8; 4],
        reason: &[u8],
        timestamp: u64,
    ) -> Result<u32, NdrError> {
        if self.is_endpoint_quarantined(&ip) {
            return Err(NdrError::EndpointAlreadyQuarantined);
        }

        if self.quarantined_count >= MAX_QUARANTINED {
            return Err(NdrError::EndpointTableFull);
        }

        let mut reason_buf = [0u8; 48];
        let len = if reason.len() > 48 { 48 } else { reason.len() };
        reason_buf[..len].copy_from_slice(&reason[..len]);

        let endpoint_id = self.next_endpoint_id;
        self.next_endpoint_id += 1;

        let quarantined = QuarantinedEndpoint {
            endpoint_id,
            ip,
            reason: reason_buf,
            reason_len: len,
            timestamp,
            packets_blocked: 0,
            active: true,
        };

        for slot in self.quarantined_endpoints.iter_mut() {
            if slot.is_none() {
                *slot = Some(quarantined);
                self.quarantined_count += 1;
                break;
            }
        }

        // Marquer tous les flux actifs associés à cet endpoint comme confinés
        for slot in self.flows.iter_mut() {
            if let Some(f) = slot {
                if f.src_ip == ip || f.dst_ip == ip {
                    f.quarantined = true;
                    f.state = FlowState::Quarantined;
                }
            }
        }

        self.append_audit_entry(2001, reason, timestamp);

        Ok(endpoint_id)
    }

    /// Vérifie si une adresse IP est confinée en O(1)
    pub fn is_endpoint_quarantined(&self, ip: &[u8; 4]) -> bool {
        for slot in self.quarantined_endpoints.iter() {
            if let Some(ep) = slot {
                if ep.active && ep.ip == *ip {
                    return true;
                }
            }
        }
        false
    }

    fn increment_endpoint_blocked(&mut self, ip: &[u8; 4]) {
        for slot in self.quarantined_endpoints.iter_mut() {
            if let Some(ep) = slot {
                if ep.active && ep.ip == *ip {
                    ep.packets_blocked += 1;
                    return;
                }
            }
        }
    }

    fn record_threat(
        &mut self,
        flow_id: u32,
        threat_type: NdrThreatType,
        severity: ThreatSeverity,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        timestamp: u64,
        quarantined: bool,
        details: &[u8],
    ) {
        if self.threat_count >= MAX_THREATS {
            return;
        }

        let mut det_buf = [0u8; 48];
        let len = if details.len() > 48 {
            48
        } else {
            details.len()
        };
        det_buf[..len].copy_from_slice(&details[..len]);

        let incident_id = self.next_threat_id;
        self.next_threat_id += 1;

        let incident = ThreatIncident {
            incident_id,
            flow_id,
            threat_type,
            severity,
            src_ip,
            dst_ip,
            timestamp,
            quarantined,
            details: det_buf,
            details_len: len,
        };

        for slot in self.threats.iter_mut() {
            if slot.is_none() {
                *slot = Some(incident);
                self.threat_count += 1;
                break;
            }
        }
    }

    /// Ajoute une entrée inaltérable scellée dans le registre d'audit SHA-256
    pub fn append_audit_entry(&mut self, event_code: u16, detail: &[u8], timestamp: u64) {
        if self.audit_count >= MAX_AUDIT {
            return;
        }

        let mut detail_buf = [0u8; 48];
        let len = if detail.len() > 48 { 48 } else { detail.len() };
        detail_buf[..len].copy_from_slice(&detail[..len]);

        let mut hasher = Sha256::new();
        hasher.update(&self.last_audit_hash);
        hasher.update(&event_code.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&detail_buf[..len]);
        let entry_hash = hasher.finalize();

        let entry = NdrAuditEntry {
            index: self.audit_count as u32,
            timestamp,
            event_code,
            detail: detail_buf,
            detail_len: len,
            prev_hash: self.last_audit_hash,
            entry_hash,
        };

        self.last_audit_hash = entry_hash;

        for slot in self.audit_log.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.audit_count += 1;
                break;
            }
        }
    }

    /// Vérification cryptographique formelle de l'intégrité de la chaîne SHA-256
    pub fn verify_ledger_integrity(&self) -> bool {
        let genesis_seed = b"JAMBO_SOVEREIGN_NDR_GENESIS_LEDGER_CHAIN_v0.3.10";
        let mut expected_prev = Sha256::digest(genesis_seed);

        for slot in self.audit_log.iter() {
            if let Some(entry) = slot {
                if entry.prev_hash != expected_prev {
                    return false;
                }

                let mut hasher = Sha256::new();
                hasher.update(&entry.prev_hash);
                hasher.update(&entry.event_code.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.detail[..entry.detail_len]);
                let computed = hasher.finalize();

                if computed != entry.entry_hash {
                    return false;
                }

                expected_prev = entry.entry_hash;
            }
        }

        true
    }

    /// Extrait une synthèse opérationnelle de l'état du sous-système NDR
    pub fn get_summary(&self) -> NdrSummary {
        let active_count = self
            .flows
            .iter()
            .flatten()
            .filter(|f| f.state == FlowState::Active)
            .count();
        let quar_flows = self
            .flows
            .iter()
            .flatten()
            .filter(|f| f.quarantined || f.state == FlowState::Quarantined)
            .count();
        let threats_blocked = self
            .threats
            .iter()
            .flatten()
            .filter(|t| t.quarantined)
            .count();

        NdrSummary {
            flows_count: self.flow_count,
            active_flows_count: active_count,
            quarantined_flows_count: quar_flows,
            rules_count: self.rule_count,
            threats_detected: self.threat_count,
            threats_blocked,
            quarantined_endpoints_count: self.quarantined_count,
            audit_entries_count: self.audit_count,
            ledger_valid: self.verify_ledger_integrity(),
        }
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] sous test harness)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_ndr_hasher() {
        let data = b"JAMBO_SOVEREIGN_NETWORK_DETECTION_AND_RESILIENCE_NDR";
        let digest = Sha256::digest(data);
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn test_ndr_capability_rights_and_attenuation() {
        let root_cap = NdrCap::new(Handle::new(14301, 1), ndr_rights::ALL, 10000, 500);
        assert!(root_cap.has_right(ndr_rights::INSPECT_FLOW));
        assert!(root_cap.has_right(ndr_rights::DETECT_ANOMALY));
        assert!(root_cap.has_right(ndr_rights::ENFORCE_MICROSEG));
        assert!(root_cap.has_right(ndr_rights::QUARANTINE_FLOW));
        assert!(root_cap.has_right(ndr_rights::ADMIN));

        let attenuated = root_cap
            .attenuate(
                ndr_rights::INSPECT_FLOW | ndr_rights::QUERY_METRICS,
                5000,
                200,
            )
            .expect("Atténuation monotone");

        assert!(attenuated.has_right(ndr_rights::INSPECT_FLOW));
        assert!(attenuated.has_right(ndr_rights::QUERY_METRICS));
        assert!(!attenuated.has_right(ndr_rights::ADMIN));
        assert!(!attenuated.has_right(ndr_rights::QUARANTINE_FLOW));

        // Rejet d'escalade de privilège
        assert_eq!(
            attenuated.attenuate(ndr_rights::ALL, 5000, 200),
            Err(NdrError::AttenuationViolation)
        );
    }

    #[test]
    fn test_daemon_initialization_defaults() {
        let cap = NdrCap::new(Handle::new(14302, 1), ndr_rights::ALL, 10000, 500);
        let mut daemon = JamboNdrDaemon::new(cap);
        daemon.init_defaults();

        let summary = daemon.get_summary();
        assert_eq!(summary.flows_count, 3);
        assert_eq!(summary.rules_count, 8);
        assert_eq!(summary.quarantined_endpoints_count, 0);
        assert_eq!(summary.threats_detected, 0);
        assert!(summary.ledger_valid);
    }

    #[test]
    fn test_zero_trust_microsegmentation_rules() {
        let cap = NdrCap::new(Handle::new(14303, 1), ndr_rights::ALL, 10000, 500);
        let mut daemon = JamboNdrDaemon::new(cap);
        daemon.init_defaults();

        // 1. Kernel vers CoreServices IPC : Autorisé
        let action1 = daemon.evaluate_traffic_policy(
            SecurityZone::ZoneKernel,
            SecurityZone::ZoneCoreServices,
            0,
            ProtocolType::HttpIpc,
        );
        assert_eq!(action1, RuleAction::Allow);

        // 2. UserApps vers Cryptographique direct : Confinement sur suspicion
        let action2 = daemon.evaluate_traffic_policy(
            SecurityZone::ZoneUserApps,
            SecurityZone::ZoneCryptographic,
            8443,
            ProtocolType::Tcp,
        );
        assert_eq!(action2, RuleAction::QuarantineOnSuspicion);

        // 3. Externe vers Kernel : Refus strict
        let action3 = daemon.evaluate_traffic_policy(
            SecurityZone::ZoneExternalNetwork,
            SecurityZone::ZoneKernel,
            22,
            ProtocolType::Tcp,
        );
        assert_eq!(action3, RuleAction::Deny);
    }

    #[test]
    fn test_heuristic_c2_beaconing_detection() {
        let cap = NdrCap::new(Handle::new(14304, 1), ndr_rights::ALL, 10000, 500);
        let mut daemon = JamboNdrDaemon::new(cap);
        daemon.init_defaults();

        let c2_flow_id = daemon
            .register_flow(
                [192, 168, 1, 100],
                [45, 33, 32, 1],
                49200,
                443,
                ProtocolType::Tcp,
                SecurityZone::ZoneCoreServices,
                SecurityZone::ZoneExternalNetwork,
                "covert-agent-c2",
            )
            .expect("Enregistrement flux suspect");

        // Paquet 1
        let _ = daemon.ingest_packet(c2_flow_id, 128, 10000, 20);
        // Paquet 2 à t=11000 (delta=1000ms -> strike 1)
        let _ = daemon.ingest_packet(c2_flow_id, 128, 11000, 20);
        // Paquet 3 à t=12020 (delta=1020ms -> strike 2)
        let _ = daemon.ingest_packet(c2_flow_id, 128, 12020, 20);
        // Paquet 4 à t=13010 (delta=990ms -> strike 3 -> Détection C2 Beaconing & Confinement)
        let action = daemon
            .ingest_packet(c2_flow_id, 128, 13010, 20)
            .expect("Ingestion paquet 4");

        assert_eq!(action, RuleAction::QuarantineOnSuspicion);
        assert!(daemon.is_endpoint_quarantined(&[192, 168, 1, 100]));

        let summary = daemon.get_summary();
        assert_eq!(summary.threats_detected, 1);
        assert_eq!(summary.quarantined_endpoints_count, 1);

        // Le paquet suivant sur cet endpoint doit être immédiatement bloqué en O(1)
        let blocked = daemon.ingest_packet(c2_flow_id, 128, 14000, 20);
        assert_eq!(blocked, Err(NdrError::FlowBlocked));
    }

    #[test]
    fn test_data_exfiltration_detection_and_quarantine() {
        let cap = NdrCap::new(Handle::new(14305, 1), ndr_rights::ALL, 10000, 500);
        let mut daemon = JamboNdrDaemon::new(cap);
        daemon.init_defaults();

        let exfil_flow_id = daemon
            .register_flow(
                [192, 168, 1, 105],
                [185, 220, 101, 5],
                55120,
                443,
                ProtocolType::Tcp,
                SecurityZone::ZoneCoreServices,
                SecurityZone::ZoneExternalNetwork,
                "data-exfil-stream",
            )
            .expect("Enregistrement flux exfiltration");

        // Envoi d'un volume massif dépassant le seuil souverain de 64 Ko
        let action = daemon
            .ingest_packet(exfil_flow_id, 70_000, 20000, 30)
            .expect("Ingestion paquet massif");

        assert_eq!(action, RuleAction::QuarantineOnSuspicion);
        assert!(daemon.is_endpoint_quarantined(&[192, 168, 1, 105]));

        let threat = daemon.threats[0].unwrap();
        assert_eq!(threat.threat_type, NdrThreatType::DataExfiltration);
        assert_eq!(threat.severity, ThreatSeverity::Critical);
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let cap = NdrCap::new(Handle::new(14306, 1), ndr_rights::ALL, 10000, 500);
        let mut daemon = JamboNdrDaemon::new(cap);
        daemon.init_defaults();

        let dns_flow_id = daemon
            .register_flow(
                [192, 168, 1, 120],
                [8, 8, 8, 8],
                53100,
                53,
                ProtocolType::Dns,
                SecurityZone::ZoneCoreServices,
                SecurityZone::ZoneExternalNetwork,
                "dns-tunnel-probe",
            )
            .expect("Enregistrement flux DNS");

        // Requête DNS à entropie anormale (score = 95)
        let action = daemon
            .ingest_packet(dns_flow_id, 512, 30000, 95)
            .expect("Ingestion DNS haute entropie");

        assert_eq!(action, RuleAction::QuarantineOnSuspicion);
        assert!(daemon.is_endpoint_quarantined(&[192, 168, 1, 120]));

        let threat = daemon.threats[0].unwrap();
        assert_eq!(threat.threat_type, NdrThreatType::DnsTunneling);
        assert_eq!(threat.severity, ThreatSeverity::Critical);
    }

    #[test]
    fn test_audit_ledger_integrity_and_tamper_detection() {
        let cap = NdrCap::new(Handle::new(14307, 1), ndr_rights::ALL, 10000, 500);
        let mut daemon = JamboNdrDaemon::new(cap);
        daemon.init_defaults();

        assert!(daemon.verify_ledger_integrity());
        assert!(daemon.audit_count > 0);

        // Altération d'un bloc d'audit
        daemon.audit_log[0].as_mut().unwrap().detail[0] ^= 0xAA;
        assert!(!daemon.verify_ledger_integrity());
    }
}

//! Détection et Réponse aux Menaces sur l'Identité (jambo-itdr, Ring 3, PID 37)
//!
//! Service souverain sans tas (`#![no_std]`, zéro allocation) :
//! 1. Modélisation et surveillance des identités souveraines (noyau, daemons système, rôles admin).
//! 2. Détection en temps réel des vecteurs avancés de menaces sur l'identité (TokenCompromise, PrivilegeEscalation, SessionReplay, PassTheCapability, etc.).
//! 3. Évaluation dynamique et déterministe du Trust Score (0..100) et indice de risque global.
//! 4. Orchestration autonome de remédiation proactive et confinement O(1).
//! 5. Registre d'audit inaltérable scellé cryptographiquement par SHA-256.
//! 6. Protocole IPC synchrone déterministe à 64 octets (endpoint 37).

#![no_std]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_flatten)]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation déterministe et autonome de SHA-256 pour micro-noyau et services
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

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes += data.len() as u64;
        let mut offset = 0;
        while offset < data.len() {
            let space = 64 - self.buffer_len;
            let chunk = (data.len() - offset).min(space);
            self.buffer[self.buffer_len..self.buffer_len + chunk]
                .copy_from_slice(&data[offset..offset + chunk]);
            self.buffer_len += chunk;
            offset += chunk;

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.transform_block(&block);
                self.buffer_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.transform_block(&block);
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.transform_block(&block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// ============================================================================
// DROITS ET CAPABILITÉ ITDR (ItdrCap)
// ============================================================================

pub mod itdr_rights {
    pub const MONITOR_IDENTITIES: u32 = 1 << 0;
    pub const INGEST_AUTH_EVENTS: u32 = 1 << 1;
    pub const ANALYZE_THREATS: u32 = 1 << 2;
    pub const TRIGGER_RESPONSE: u32 = 1 << 3;
    pub const REVOKE_CREDENTIALS: u32 = 1 << 4;
    pub const QUERY_POSTURE: u32 = 1 << 5;
    pub const SEAL_LEDGER: u32 = 1 << 6;
    pub const GENERATE_REPORT: u32 = 1 << 7;
    pub const AUTONOMOUS_CONFINEMENT: u32 = 1 << 8;
    pub const ADMIN: u32 = 1 << 9;

    pub const ALL: u32 = MONITOR_IDENTITIES
        | INGEST_AUTH_EVENTS
        | ANALYZE_THREATS
        | TRIGGER_RESPONSE
        | REVOKE_CREDENTIALS
        | QUERY_POSTURE
        | SEAL_LEDGER
        | GENERATE_REPORT
        | AUTONOMOUS_CONFINEMENT
        | ADMIN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItdrError {
    PermissionDenied,
    AttenuationViolation,
    CapacityExceeded,
    NotFound,
    InvalidState,
    Expired,
    LedgerCorrupted,
    InvalidSignature,
    InvalidRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItdrCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl ItdrCap {
    pub const fn new(handle: Handle, rights: u32, max_lifetime: u64, invocations: u32) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left: invocations,
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, ItdrError> {
        if (new_rights & !self.rights) != 0 {
            return Err(ItdrError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(ItdrError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(ItdrError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), ItdrError> {
        if self.invocations_left == 0 {
            return Err(ItdrError::Expired);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES DE DONNÉES ITDR
// ============================================================================

/// Typologie de l'identité surveillée
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityType {
    KernelService = 0,
    SystemDaemon = 1,
    DistributedPrincipal = 2,
    AdminRole = 3,
    EphemeralSession = 4,
}

impl IdentityType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::KernelService,
            1 => Self::SystemDaemon,
            2 => Self::DistributedPrincipal,
            3 => Self::AdminRole,
            _ => Self::EphemeralSession,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KernelService => "KernelService",
            Self::SystemDaemon => "SystemDaemon",
            Self::DistributedPrincipal => "DistributedPrincipal",
            Self::AdminRole => "AdminRole",
            Self::EphemeralSession => "EphemeralSession",
        }
    }
}

/// État opérationnel de l'identité
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityState {
    Active = 0,
    Suspicious = 1,
    Quarantined = 2,
    Revoked = 3,
}

impl IdentityState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Active,
            1 => Self::Suspicious,
            2 => Self::Quarantined,
            _ => Self::Revoked,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Suspicious => "Suspicious",
            Self::Quarantined => "Quarantined",
            Self::Revoked => "Revoked",
        }
    }
}

/// Typologie des vecteurs de menaces sur l'identité (ITDR)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityThreatType {
    TokenCompromise = 0,
    SessionReplay = 1,
    CapabilityUsurpation = 2,
    PrivilegeEscalation = 3,
    AnomalousAuthRate = 4,
    DivergentGeoMesh = 5,
    PassTheCapability = 6,
    LateralPrivilegeMovement = 7,
    ImpossibleTravel = 8,
    CredentialStuffing = 9,
    ForgedCapabilityToken = 10,
}

impl IdentityThreatType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::TokenCompromise,
            1 => Self::SessionReplay,
            2 => Self::CapabilityUsurpation,
            3 => Self::PrivilegeEscalation,
            4 => Self::AnomalousAuthRate,
            5 => Self::DivergentGeoMesh,
            6 => Self::PassTheCapability,
            7 => Self::LateralPrivilegeMovement,
            8 => Self::ImpossibleTravel,
            9 => Self::CredentialStuffing,
            _ => Self::ForgedCapabilityToken,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TokenCompromise => "TokenCompromise",
            Self::SessionReplay => "SessionReplay",
            Self::CapabilityUsurpation => "CapabilityUsurpation",
            Self::PrivilegeEscalation => "PrivilegeEscalation",
            Self::AnomalousAuthRate => "AnomalousAuthRate",
            Self::DivergentGeoMesh => "DivergentGeoMesh",
            Self::PassTheCapability => "PassTheCapability",
            Self::LateralPrivilegeMovement => "LateralPrivilegeMovement",
            Self::ImpossibleTravel => "ImpossibleTravel",
            Self::CredentialStuffing => "CredentialStuffing",
            Self::ForgedCapabilityToken => "ForgedCapabilityToken",
        }
    }
}

/// Sévérité intrinsèque d'une menace d'identité
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreatSeverity {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Info = 0,
}

impl ThreatSeverity {
    pub fn from_u8(val: u8) -> Self {
        match val {
            4 => Self::Critical,
            3 => Self::High,
            2 => Self::Medium,
            1 => Self::Low,
            _ => Self::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
        }
    }
}

/// Statut de traitement d'un incident de menace
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreatStatus {
    Detected = 0,
    Investigating = 1,
    Contained = 2,
    Remediated = 3,
    Dismissed = 4,
}

impl ThreatStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Detected => "Detected",
            Self::Investigating => "Investigating",
            Self::Contained => "Contained",
            Self::Remediated => "Remediated",
            Self::Dismissed => "Dismissed",
        }
    }
}

/// Action de remédiation proactive d'identité
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseActionType {
    RevokeToken = 0,
    QuarantineIdentity = 1,
    DowngradeCapabilities = 2,
    StepUpMfaChallenge = 3,
    AlertSecurityOfficer = 4,
    TerminateSession = 5,
    LeastPrivilegeRollback = 6,
}

impl ResponseActionType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::RevokeToken,
            1 => Self::QuarantineIdentity,
            2 => Self::DowngradeCapabilities,
            3 => Self::StepUpMfaChallenge,
            4 => Self::AlertSecurityOfficer,
            5 => Self::TerminateSession,
            _ => Self::LeastPrivilegeRollback,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RevokeToken => "RevokeToken",
            Self::QuarantineIdentity => "QuarantineIdentity",
            Self::DowngradeCapabilities => "DowngradeCapabilities",
            Self::StepUpMfaChallenge => "StepUpMfaChallenge",
            Self::AlertSecurityOfficer => "AlertSecurityOfficer",
            Self::TerminateSession => "TerminateSession",
            Self::LeastPrivilegeRollback => "LeastPrivilegeRollback",
        }
    }
}

/// Enregistrement d'une identité surveillée
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityRecord {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub id_type: IdentityType,
    pub trust_score: u8, // 0..100 (100 = confiance totale, 0 = compromis)
    pub state: IdentityState,
    pub assigned_caps: u32,
    pub failed_auth_count: u32,
    pub last_event_timestamp: u64,
}

impl IdentityRecord {
    pub fn new(
        id: u32,
        name_str: &str,
        id_type: IdentityType,
        trust_score: u8,
        assigned_caps: u32,
        timestamp: u64,
    ) -> Self {
        let mut name = [0u8; 32];
        let n_len = name_str.len().min(32);
        name[..n_len].copy_from_slice(&name_str.as_bytes()[..n_len]);

        Self {
            id,
            name,
            name_len: n_len,
            id_type,
            trust_score,
            state: IdentityState::Active,
            assigned_caps,
            failed_auth_count: 0,
            last_event_timestamp: timestamp,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }
}

/// Événement ou incident de menace d'identité
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityThreatEvent {
    pub id: u32,
    pub identity_id: u32,
    pub threat_type: IdentityThreatType,
    pub severity: ThreatSeverity,
    pub anomaly_score: u8, // 0..100
    pub details: [u8; 64],
    pub details_len: usize,
    pub timestamp: u64,
    pub status: ThreatStatus,
}

impl IdentityThreatEvent {
    pub fn new(
        id: u32,
        identity_id: u32,
        threat_type: IdentityThreatType,
        severity: ThreatSeverity,
        anomaly_score: u8,
        details_str: &str,
        timestamp: u64,
    ) -> Self {
        let mut details = [0u8; 64];
        let d_len = details_str.len().min(64);
        details[..d_len].copy_from_slice(&details_str.as_bytes()[..d_len]);

        Self {
            id,
            identity_id,
            threat_type,
            severity,
            anomaly_score,
            details,
            details_len: d_len,
            timestamp,
            status: ThreatStatus::Detected,
        }
    }

    pub fn details_as_str(&self) -> &str {
        core::str::from_utf8(&self.details[..self.details_len]).unwrap_or("<invalide>")
    }
}

/// Action de réponse orchestrée
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItdrResponseAction {
    pub id: u32,
    pub threat_id: u32,
    pub identity_id: u32,
    pub action_type: ResponseActionType,
    pub target_name: [u8; 32],
    pub target_len: usize,
    pub timestamp: u64,
    pub executed: bool,
}

impl ItdrResponseAction {
    pub fn new(
        id: u32,
        threat_id: u32,
        identity_id: u32,
        action_type: ResponseActionType,
        target_str: &str,
        timestamp: u64,
    ) -> Self {
        let mut target_name = [0u8; 32];
        let t_len = target_str.len().min(32);
        target_name[..t_len].copy_from_slice(&target_str.as_bytes()[..t_len]);

        Self {
            id,
            threat_id,
            identity_id,
            action_type,
            target_name,
            target_len: t_len,
            timestamp,
            executed: true,
        }
    }

    pub fn target_as_str(&self) -> &str {
        core::str::from_utf8(&self.target_name[..self.target_len]).unwrap_or("<invalide>")
    }
}

/// Entrée du registre d'audit cryptographique inviolable
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItdrAuditEntry {
    pub sequence: u32,
    pub timestamp: u64,
    pub action: [u8; 32],
    pub action_len: usize,
    pub identity_id: u32,
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
}

impl ItdrAuditEntry {
    pub fn action_as_str(&self) -> &str {
        core::str::from_utf8(&self.action[..self.action_len]).unwrap_or("<invalide>")
    }
}

/// Rapport de posture d'identité scellé cryptographiquement par SHA-256
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItdrAssessmentReport {
    pub report_id: u32,
    pub timestamp: u64,
    pub total_identities: usize,
    pub active_identities: usize,
    pub suspicious_identities: usize,
    pub quarantined_identities: usize,
    pub revoked_identities: usize,
    pub total_threats: usize,
    pub active_threats: usize,
    pub remediated_threats: usize,
    pub avg_trust_score: u8,
    pub global_identity_risk: u8,
    pub health_posture_score: u8,
    pub report_hash: [u8; 32],
}

/// Rapport de remédiation et confinement autonome d'identités scellé par SHA-256
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItdrRemediationReport {
    pub report_id: u32,
    pub timestamp: u64,
    pub remediated_count: usize,
    pub quarantined_count: usize,
    pub revoked_count: usize,
    pub risk_before: u8,
    pub score_after: u8,
    pub risk_reduction_pct: u8,
    pub avg_trust_before: u8,
    pub avg_trust_after: u8,
    pub report_hash: [u8; 32],
}

/// Synthèse complète de la posture ITDR
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItdrSummary {
    pub total_identities: u32,
    pub active_identities: u32,
    pub quarantined_identities: u32,
    pub total_threats: u32,
    pub active_threats: u32,
    pub mitigated_threats: u32,
    pub actions_count: u32,
    pub global_identity_risk: u8,
    pub ledger_valid: bool,
}

// ============================================================================
// DÉMON CENTRAL ITDR (JamboItdrDaemon)
// ============================================================================

pub const MAX_ITDR_IDENTITIES: usize = 16;
pub const MAX_ITDR_THREATS: usize = 32;
pub const MAX_ITDR_ACTIONS: usize = 32;
pub const MAX_ITDR_LEDGER: usize = 64;

pub struct JamboItdrDaemon {
    pub admin_cap: ItdrCap,
    pub identities: [Option<IdentityRecord>; MAX_ITDR_IDENTITIES],
    pub identity_count: usize,
    pub threats: [Option<IdentityThreatEvent>; MAX_ITDR_THREATS],
    pub threat_count: usize,
    pub actions: [Option<ItdrResponseAction>; MAX_ITDR_ACTIONS],
    pub action_count: usize,
    pub ledger: [Option<ItdrAuditEntry>; MAX_ITDR_LEDGER],
    pub ledger_count: usize,
    pub last_hash: [u8; 32],
    pub global_identity_risk: u8, // 0..100
    pub report_counter: u32,
}

impl JamboItdrDaemon {
    pub const fn new(admin_cap: ItdrCap) -> Self {
        Self {
            admin_cap,
            identities: [None; MAX_ITDR_IDENTITIES],
            identity_count: 0,
            threats: [None; MAX_ITDR_THREATS],
            threat_count: 0,
            actions: [None; MAX_ITDR_ACTIONS],
            action_count: 0,
            ledger: [None; MAX_ITDR_LEDGER],
            ledger_count: 0,
            last_hash: [0u8; 32],
            global_identity_risk: 0,
            report_counter: 0,
        }
    }

    /// Initialise le registre de référence avec des identités et événements de référence
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;
        let ts = 1000u64;

        // 1. Identités souveraines nominales
        let _ = self.register_identity(
            &cap,
            "kernel::jambo-authd",
            IdentityType::KernelService,
            98,
            0xFFFF,
            ts,
        );
        let _ = self.register_identity(
            &cap,
            "daemon::jambo-netd",
            IdentityType::SystemDaemon,
            92,
            0x00FF,
            ts + 1,
        );
        let _ = self.register_identity(
            &cap,
            "mesh::node-eu-west-1",
            IdentityType::DistributedPrincipal,
            85,
            0x003F,
            ts + 2,
        );
        let _ = self.register_identity(
            &cap,
            "admin::secops-sovereign",
            IdentityType::AdminRole,
            95,
            0x7FFF,
            ts + 3,
        );
        let _ = self.register_identity(
            &cap,
            "session::guest-rpc-99",
            IdentityType::EphemeralSession,
            70,
            0x0007,
            ts + 4,
        );

        // 2. Événements de menaces détectés
        let _ = self.ingest_threat_event(
            &cap,
            5, // guest-rpc-99
            IdentityThreatType::TokenCompromise,
            ThreatSeverity::High,
            82,
            "Out-of-order session epoch & signature mismatch on RPC",
            ts + 10,
        );

        let _ = self.ingest_threat_event(
            &cap,
            3, // node-eu-west-1
            IdentityThreatType::CapabilityUsurpation,
            ThreatSeverity::Critical,
            94,
            "Attempted Ring0 handle transfer from isolated CSpace",
            ts + 20,
        );

        let _ = self.ingest_threat_event(
            &cap,
            4, // secops-sovereign
            IdentityThreatType::SessionReplay,
            ThreatSeverity::Medium,
            55,
            "Duplicate nonce received across mesh partition",
            ts + 30,
        );

        // 3. Calcul du risque initial
        let _ = self.analyze_threats(&cap, ts + 40);
    }

    /// Enregistre une nouvelle identité sous contrôle d'accès capabilaire
    pub fn register_identity(
        &mut self,
        cap: &ItdrCap,
        name: &str,
        id_type: IdentityType,
        initial_trust: u8,
        caps: u32,
        timestamp: u64,
    ) -> Result<u32, ItdrError> {
        if !cap.has_right(itdr_rights::MONITOR_IDENTITIES) {
            return Err(ItdrError::PermissionDenied);
        }
        if self.identity_count >= MAX_ITDR_IDENTITIES {
            return Err(ItdrError::CapacityExceeded);
        }

        let new_id = (self.identity_count + 1) as u32;
        let record = IdentityRecord::new(new_id, name, id_type, initial_trust, caps, timestamp);
        self.identities[self.identity_count] = Some(record);
        self.identity_count += 1;

        let _ = self.record_audit(timestamp, "REGISTER_IDENTITY", new_id);
        self.recalculate_global_risk();
        Ok(new_id)
    }

    /// Ingestion d'un événement de menace sur une identité
    pub fn ingest_threat_event(
        &mut self,
        cap: &ItdrCap,
        identity_id: u32,
        threat_type: IdentityThreatType,
        severity: ThreatSeverity,
        anomaly_score: u8,
        details: &str,
        timestamp: u64,
    ) -> Result<u32, ItdrError> {
        if !cap.has_right(itdr_rights::INGEST_AUTH_EVENTS) {
            return Err(ItdrError::PermissionDenied);
        }
        if self.threat_count >= MAX_ITDR_THREATS {
            return Err(ItdrError::CapacityExceeded);
        }

        // Vérifier l'existence de l'identité cible
        let id_idx = (identity_id as usize).saturating_sub(1);
        if id_idx >= self.identity_count || self.identities[id_idx].is_none() {
            return Err(ItdrError::NotFound);
        }

        let event_id = (self.threat_count + 1) as u32;
        let event = IdentityThreatEvent::new(
            event_id,
            identity_id,
            threat_type,
            severity,
            anomaly_score,
            details,
            timestamp,
        );
        self.threats[self.threat_count] = Some(event);
        self.threat_count += 1;

        // Dégradation du score de confiance de l'identité
        if let Some(ref mut id_rec) = self.identities[id_idx] {
            let penalty = (anomaly_score / 3).max(10);
            id_rec.trust_score = id_rec.trust_score.saturating_sub(penalty);
            id_rec.failed_auth_count += 1;
            id_rec.last_event_timestamp = timestamp;
            if id_rec.trust_score < 40 && id_rec.state == IdentityState::Active {
                id_rec.state = IdentityState::Suspicious;
            }
        }

        let _ = self.record_audit(timestamp, "INGEST_THREAT", identity_id);
        self.recalculate_global_risk();
        Ok(event_id)
    }

    /// Analyse globale des menaces et corrélation des identités
    pub fn analyze_threats(&mut self, cap: &ItdrCap, timestamp: u64) -> Result<u32, ItdrError> {
        if !cap.has_right(itdr_rights::ANALYZE_THREATS) {
            return Err(ItdrError::PermissionDenied);
        }

        let mut analyzed_count = 0u32;
        for threat_opt in self.threats[..self.threat_count].iter_mut() {
            if let Some(ref mut threat) = threat_opt {
                if threat.status == ThreatStatus::Detected {
                    threat.status = ThreatStatus::Investigating;
                    analyzed_count += 1;

                    // Ajuster l'identité associée
                    let id_idx = (threat.identity_id as usize).saturating_sub(1);
                    if id_idx < self.identity_count {
                        if let Some(ref mut id_rec) = self.identities[id_idx] {
                            if threat.severity == ThreatSeverity::Critical {
                                id_rec.state = IdentityState::Suspicious;
                            }
                        }
                    }
                }
            }
        }

        self.recalculate_global_risk();
        let _ = self.record_audit(timestamp, "ANALYZE_THREATS", 0);
        Ok(analyzed_count)
    }

    /// Déclenche une réponse proactive à une menace identifiée
    pub fn respond_to_threat(
        &mut self,
        cap: &ItdrCap,
        threat_id: u32,
        action_type: ResponseActionType,
        timestamp: u64,
    ) -> Result<u32, ItdrError> {
        if !cap.has_right(itdr_rights::TRIGGER_RESPONSE) {
            return Err(ItdrError::PermissionDenied);
        }
        if self.action_count >= MAX_ITDR_ACTIONS {
            return Err(ItdrError::CapacityExceeded);
        }

        let t_idx = (threat_id as usize).saturating_sub(1);
        if t_idx >= self.threat_count || self.threats[t_idx].is_none() {
            return Err(ItdrError::NotFound);
        }

        let (target_id, target_name_buf, target_name_len) = {
            let threat = self.threats[t_idx].as_ref().unwrap();
            let id_idx = (threat.identity_id as usize).saturating_sub(1);
            let mut buf = [0u8; 32];
            let len;
            if id_idx < self.identity_count && self.identities[id_idx].is_some() {
                let rec = self.identities[id_idx].as_ref().unwrap();
                buf = rec.name;
                len = rec.name_len;
            } else {
                let unk = b"unknown";
                buf[..unk.len()].copy_from_slice(unk);
                len = unk.len();
            };
            (threat.identity_id, buf, len)
        };

        // Appliquer l'effet de l'action sur l'identité
        let id_idx = (target_id as usize).saturating_sub(1);
        if id_idx < self.identity_count {
            if let Some(ref mut id_rec) = self.identities[id_idx] {
                match action_type {
                    ResponseActionType::RevokeToken => {
                        id_rec.state = IdentityState::Revoked;
                        id_rec.assigned_caps = 0;
                        id_rec.trust_score = 0;
                    }
                    ResponseActionType::QuarantineIdentity => {
                        id_rec.state = IdentityState::Quarantined;
                        id_rec.assigned_caps &= 0x0001; // Lecture seule minimale de confinement
                        id_rec.trust_score = id_rec.trust_score.min(25);
                    }
                    ResponseActionType::DowngradeCapabilities => {
                        id_rec.assigned_caps >>= 2; // Atténuation monotone
                    }
                    ResponseActionType::StepUpMfaChallenge => {
                        if id_rec.state == IdentityState::Active {
                            id_rec.state = IdentityState::Suspicious;
                        }
                    }
                    ResponseActionType::AlertSecurityOfficer => {
                        // Alerte journalisée
                    }
                    ResponseActionType::TerminateSession => {
                        id_rec.state = IdentityState::Revoked;
                        id_rec.assigned_caps = 0;
                    }
                    ResponseActionType::LeastPrivilegeRollback => {
                        id_rec.assigned_caps = 0x0001;
                        if id_rec.state == IdentityState::Suspicious {
                            id_rec.state = IdentityState::Active;
                        }
                    }
                }
            }
        }

        // Marquer la menace comme contenue
        if let Some(ref mut threat) = self.threats[t_idx] {
            threat.status = ThreatStatus::Contained;
        }

        let act_id = (self.action_count + 1) as u32;
        let target_name_str =
            core::str::from_utf8(&target_name_buf[..target_name_len]).unwrap_or("unknown");
        let action = ItdrResponseAction::new(
            act_id,
            threat_id,
            target_id,
            action_type,
            target_name_str,
            timestamp,
        );
        self.actions[self.action_count] = Some(action);
        self.action_count += 1;

        let _ = self.record_audit(timestamp, "RESPOND_THREAT", target_id);
        self.recalculate_global_risk();
        Ok(act_id)
    }

    /// Isole et met en quarantaine une identité suspecte
    pub fn quarantine_identity(
        &mut self,
        cap: &ItdrCap,
        identity_id: u32,
        timestamp: u64,
    ) -> Result<(), ItdrError> {
        if !cap.has_right(itdr_rights::REVOKE_CREDENTIALS) {
            return Err(ItdrError::PermissionDenied);
        }

        let id_idx = (identity_id as usize).saturating_sub(1);
        if id_idx >= self.identity_count || self.identities[id_idx].is_none() {
            return Err(ItdrError::NotFound);
        }

        if let Some(ref mut id_rec) = self.identities[id_idx] {
            id_rec.state = IdentityState::Quarantined;
            id_rec.assigned_caps = 0;
            id_rec.trust_score = id_rec.trust_score.min(20);
        }

        let _ = self.record_audit(timestamp, "QUARANTINE_IDENTITY", identity_id);
        self.recalculate_global_risk();
        Ok(())
    }

    /// Révoque définitivement les identifiants d'une identité
    pub fn revoke_identity(
        &mut self,
        cap: &ItdrCap,
        identity_id: u32,
        timestamp: u64,
    ) -> Result<(), ItdrError> {
        if !cap.has_right(itdr_rights::REVOKE_CREDENTIALS) {
            return Err(ItdrError::PermissionDenied);
        }

        let id_idx = (identity_id as usize).saturating_sub(1);
        if id_idx >= self.identity_count || self.identities[id_idx].is_none() {
            return Err(ItdrError::NotFound);
        }

        if let Some(ref mut id_rec) = self.identities[id_idx] {
            id_rec.state = IdentityState::Revoked;
            id_rec.assigned_caps = 0;
            id_rec.trust_score = 0;
        }

        let _ = self.record_audit(timestamp, "REVOKE_IDENTITY", identity_id);
        self.recalculate_global_risk();
        Ok(())
    }

    /// Clôture et remédie un incident de menace
    pub fn remediate_threat(
        &mut self,
        cap: &ItdrCap,
        threat_id: u32,
        timestamp: u64,
    ) -> Result<(), ItdrError> {
        if !cap.has_right(itdr_rights::REVOKE_CREDENTIALS) {
            return Err(ItdrError::PermissionDenied);
        }

        let t_idx = (threat_id as usize).saturating_sub(1);
        if t_idx >= self.threat_count || self.threats[t_idx].is_none() {
            return Err(ItdrError::NotFound);
        }

        let identity_id = {
            let threat = self.threats[t_idx].as_mut().unwrap();
            threat.status = ThreatStatus::Remediated;
            threat.identity_id
        };

        // Rétablissement progressif du score de confiance
        let id_idx = (identity_id as usize).saturating_sub(1);
        if id_idx < self.identity_count {
            if let Some(ref mut id_rec) = self.identities[id_idx] {
                if id_rec.state != IdentityState::Revoked {
                    id_rec.state = IdentityState::Active;
                    id_rec.trust_score = (id_rec.trust_score + 30).min(90);
                }
            }
        }

        let _ = self.record_audit(timestamp, "REMEDIATE_THREAT", identity_id);
        self.recalculate_global_risk();
        Ok(())
    }

    /// Confinement autonome O(1) de toutes les identités compromises et remédiation des menaces
    pub fn remediate_all_compromised(
        &mut self,
        cap: &ItdrCap,
        timestamp: u64,
    ) -> Result<ItdrRemediationReport, ItdrError> {
        if !cap.has_right(itdr_rights::AUTONOMOUS_CONFINEMENT) {
            return Err(ItdrError::PermissionDenied);
        }

        let risk_before = self.global_identity_risk;
        let avg_trust_before = self.calculate_avg_trust_score();

        let mut remediated_threats = 0;
        let mut quarantined_ids = 0;
        let mut revoked_ids = 0;

        // 1. Remédier toutes les menaces actives ou en cours d'investigation
        for threat_opt in self.threats[..self.threat_count].iter_mut() {
            if let Some(ref mut threat) = threat_opt {
                if threat.status == ThreatStatus::Detected
                    || threat.status == ThreatStatus::Investigating
                    || threat.status == ThreatStatus::Contained
                {
                    threat.status = ThreatStatus::Remediated;
                    remediated_threats += 1;
                }
            }
        }

        // 2. Confinement autonome des identités suspectes ou compromises
        for id_opt in self.identities[..self.identity_count].iter_mut() {
            if let Some(ref mut id_rec) = id_opt {
                if id_rec.trust_score < 40 || id_rec.state == IdentityState::Suspicious {
                    if id_rec.trust_score < 20 {
                        id_rec.state = IdentityState::Revoked;
                        id_rec.assigned_caps = 0;
                        id_rec.trust_score = 0;
                        revoked_ids += 1;
                    } else {
                        id_rec.state = IdentityState::Quarantined;
                        id_rec.assigned_caps = 0x0001; // Droits minimaux restreints
                        id_rec.trust_score = id_rec.trust_score.max(30);
                        quarantined_ids += 1;
                    }
                }
            }
        }

        self.recalculate_global_risk();
        let risk_after = self.global_identity_risk;
        let avg_trust_after = self.calculate_avg_trust_score();

        let risk_reduction_pct = if risk_before > 0 {
            let diff = risk_before.saturating_sub(risk_after) as u32;
            ((diff * 100) / (risk_before as u32)).min(100) as u8
        } else {
            100
        };

        self.report_counter += 1;
        let report_id = self.report_counter;

        let mut hasher = Sha256::new();
        hasher.update(&report_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&(remediated_threats as u32).to_be_bytes());
        hasher.update(&(quarantined_ids as u32).to_be_bytes());
        hasher.update(&(revoked_ids as u32).to_be_bytes());
        hasher.update(&[
            risk_before,
            risk_after,
            risk_reduction_pct,
            avg_trust_before,
            avg_trust_after,
        ]);
        let report_hash = hasher.finalize();

        let _ = self.record_audit(timestamp, "AUTONOMOUS_CONFINEMENT", report_id);

        Ok(ItdrRemediationReport {
            report_id,
            timestamp,
            remediated_count: remediated_threats,
            quarantined_count: quarantined_ids,
            revoked_count: revoked_ids,
            risk_before,
            score_after: risk_after,
            risk_reduction_pct,
            avg_trust_before,
            avg_trust_after,
            report_hash,
        })
    }

    /// Génère un rapport complet de posture ITDR scellé cryptographiquement par SHA-256
    pub fn generate_assessment_report(
        &mut self,
        cap: &ItdrCap,
        timestamp: u64,
    ) -> Result<ItdrAssessmentReport, ItdrError> {
        if !cap.has_right(itdr_rights::GENERATE_REPORT) {
            return Err(ItdrError::PermissionDenied);
        }

        let mut active_id = 0;
        let mut suspicious_id = 0;
        let mut quarantined_id = 0;
        let mut revoked_id = 0;

        for id_opt in self.identities[..self.identity_count].iter() {
            if let Some(ref id_rec) = id_opt {
                match id_rec.state {
                    IdentityState::Active => active_id += 1,
                    IdentityState::Suspicious => suspicious_id += 1,
                    IdentityState::Quarantined => quarantined_id += 1,
                    IdentityState::Revoked => revoked_id += 1,
                }
            }
        }

        let mut active_th = 0;
        let mut remediated_th = 0;

        for th_opt in self.threats[..self.threat_count].iter() {
            if let Some(ref th) = th_opt {
                match th.status {
                    ThreatStatus::Detected | ThreatStatus::Investigating => active_th += 1,
                    ThreatStatus::Contained | ThreatStatus::Remediated => remediated_th += 1,
                    ThreatStatus::Dismissed => {}
                }
            }
        }

        let avg_trust = self.calculate_avg_trust_score();
        let health_score = 100u8.saturating_sub(self.global_identity_risk);

        self.report_counter += 1;
        let report_id = self.report_counter;

        let mut hasher = Sha256::new();
        hasher.update(&report_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&(self.identity_count as u32).to_be_bytes());
        hasher.update(&(active_id as u32).to_be_bytes());
        hasher.update(&(suspicious_id as u32).to_be_bytes());
        hasher.update(&(quarantined_id as u32).to_be_bytes());
        hasher.update(&(revoked_id as u32).to_be_bytes());
        hasher.update(&(self.threat_count as u32).to_be_bytes());
        hasher.update(&(active_th as u32).to_be_bytes());
        hasher.update(&(remediated_th as u32).to_be_bytes());
        hasher.update(&[avg_trust, self.global_identity_risk, health_score]);
        let report_hash = hasher.finalize();

        let _ = self.record_audit(timestamp, "GENERATE_ASSESSMENT_REPORT", report_id);

        Ok(ItdrAssessmentReport {
            report_id,
            timestamp,
            total_identities: self.identity_count,
            active_identities: active_id,
            suspicious_identities: suspicious_id,
            quarantined_identities: quarantined_id,
            revoked_identities: revoked_id,
            total_threats: self.threat_count,
            active_threats: active_th,
            remediated_threats: remediated_th,
            avg_trust_score: avg_trust,
            global_identity_risk: self.global_identity_risk,
            health_posture_score: health_score,
            report_hash,
        })
    }

    /// Calcule le score moyen de confiance des identités enregistrées (0..100)
    pub fn calculate_avg_trust_score(&self) -> u8 {
        if self.identity_count == 0 {
            return 100;
        }
        let mut sum = 0u32;
        for id_opt in self.identities[..self.identity_count].iter() {
            if let Some(ref id_rec) = id_opt {
                sum += id_rec.trust_score as u32;
            }
        }
        (sum / self.identity_count as u32).min(100) as u8
    }

    /// Exécute un cycle complet automatisé d'analyse et remédiation ITDR
    pub fn run_full_cycle(
        &mut self,
        cap: &ItdrCap,
        timestamp: u64,
    ) -> Result<ItdrSummary, ItdrError> {
        if !cap.has_right(itdr_rights::ADMIN) {
            return Err(ItdrError::PermissionDenied);
        }

        // 1. Analyse des menaces
        let _ = self.analyze_threats(cap, timestamp)?;

        // 2. Réponse automatique sur les menaces critiques et élevées
        for i in 0..self.threat_count {
            if let Some(ref threat) = self.threats[i] {
                if threat.status == ThreatStatus::Investigating {
                    let action = match threat.severity {
                        ThreatSeverity::Critical => ResponseActionType::QuarantineIdentity,
                        ThreatSeverity::High => ResponseActionType::RevokeToken,
                        ThreatSeverity::Medium => ResponseActionType::DowngradeCapabilities,
                        _ => ResponseActionType::AlertSecurityOfficer,
                    };
                    let tid = threat.id;
                    let _ = self.respond_to_threat(cap, tid, action, timestamp + 1);
                }
            }
        }

        self.recalculate_global_risk();
        self.get_summary(cap)
    }

    /// Recalcul de l'indice global de risque d'identité (0..100)
    pub fn recalculate_global_risk(&mut self) {
        if self.identity_count == 0 {
            self.global_identity_risk = 0;
            return;
        }

        let mut sum_risk = 0u32;
        for id_opt in self.identities[..self.identity_count].iter() {
            if let Some(ref id_rec) = id_opt {
                let id_risk = 100u32.saturating_sub(id_rec.trust_score as u32);
                let multiplier = match id_rec.state {
                    IdentityState::Active => {
                        if id_rec.trust_score < 50 {
                            3
                        } else {
                            1
                        }
                    }
                    IdentityState::Suspicious => 2,
                    IdentityState::Quarantined => 1,
                    IdentityState::Revoked => 0,
                };
                sum_risk += id_risk * multiplier;
            }
        }

        // Contribution des menaces actives non remédiées
        let mut active_threat_penalty = 0u32;
        for th_opt in self.threats[..self.threat_count].iter() {
            if let Some(ref th) = th_opt {
                if th.status == ThreatStatus::Detected || th.status == ThreatStatus::Investigating {
                    active_threat_penalty += match th.severity {
                        ThreatSeverity::Critical => 15,
                        ThreatSeverity::High => 10,
                        ThreatSeverity::Medium => 5,
                        _ => 2,
                    };
                }
            }
        }

        let base_risk = sum_risk / (self.identity_count as u32 * 2);
        self.global_identity_risk = (base_risk + active_threat_penalty).min(100) as u8;
    }

    /// Enregistre une entrée dans le registre d'audit cryptographique inviolable
    pub fn record_audit(
        &mut self,
        timestamp: u64,
        action: &str,
        identity_id: u32,
    ) -> Result<[u8; 32], ItdrError> {
        if self.ledger_count >= MAX_ITDR_LEDGER {
            return Err(ItdrError::CapacityExceeded);
        }

        let mut act_buf = [0u8; 32];
        let a_len = action.len().min(32);
        act_buf[..a_len].copy_from_slice(&action.as_bytes()[..a_len]);

        let seq = self.ledger_count as u32 + 1;
        let prev = self.last_hash;

        let mut hasher = Sha256::new();
        hasher.update(&seq.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&identity_id.to_be_bytes());
        hasher.update(&act_buf[..a_len]);
        hasher.update(&prev);
        let hash = hasher.finalize();

        let entry = ItdrAuditEntry {
            sequence: seq,
            timestamp,
            action: act_buf,
            action_len: a_len,
            identity_id,
            hash,
            prev_hash: prev,
        };

        self.ledger[self.ledger_count] = Some(entry);
        self.ledger_count += 1;
        self.last_hash = hash;

        Ok(hash)
    }

    /// Vérifie l'intégrité de la chaîne de hachage SHA-256 du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = [0u8; 32];
        for entry_opt in self.ledger[..self.ledger_count].iter() {
            if let Some(ref entry) = entry_opt {
                if entry.prev_hash != expected_prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.sequence.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.identity_id.to_be_bytes());
                hasher.update(&entry.action[..entry.action_len]);
                hasher.update(&expected_prev);
                let computed = hasher.finalize();

                if computed != entry.hash {
                    return false;
                }
                expected_prev = entry.hash;
            } else {
                return false;
            }
        }
        true
    }

    /// Fournit la synthèse globale des indicateurs ITDR
    pub fn get_summary(&self, cap: &ItdrCap) -> Result<ItdrSummary, ItdrError> {
        if !cap.has_right(itdr_rights::QUERY_POSTURE) {
            return Err(ItdrError::PermissionDenied);
        }

        let mut active_id = 0u32;
        let mut quar_id = 0u32;
        for id_opt in self.identities[..self.identity_count].iter() {
            if let Some(ref id_rec) = id_opt {
                match id_rec.state {
                    IdentityState::Active => active_id += 1,
                    IdentityState::Quarantined => quar_id += 1,
                    _ => {}
                }
            }
        }

        let mut act_th = 0u32;
        let mut mit_th = 0u32;
        for th_opt in self.threats[..self.threat_count].iter() {
            if let Some(ref th) = th_opt {
                match th.status {
                    ThreatStatus::Detected | ThreatStatus::Investigating => act_th += 1,
                    ThreatStatus::Contained | ThreatStatus::Remediated => mit_th += 1,
                    ThreatStatus::Dismissed => {}
                }
            }
        }

        let ledger_ok = self.verify_ledger_integrity();

        Ok(ItdrSummary {
            total_identities: self.identity_count as u32,
            active_identities: active_id,
            quarantined_identities: quar_id,
            total_threats: self.threat_count as u32,
            active_threats: act_th,
            mitigated_threats: mit_th,
            actions_count: self.action_count as u32,
            global_identity_risk: self.global_identity_risk,
            ledger_valid: ledger_ok,
        })
    }

    /// Traitement synchrone des requêtes IPC 64 octets
    pub fn dispatch_ipc(&mut self, req: &ItdrRequest) -> ItdrResponse {
        if req.magic != ITDR_REQ_MAGIC {
            return ItdrResponse::error(1, b"ERR: BAD_MAGIC\0\0");
        }

        let caller_cap = ItdrCap::new(Handle::new(req.handle_id, 1), req.rights, 100_000, 10_000);

        match req.opcode {
            1 => {
                // GetStatus / Summary
                match self.get_summary(&caller_cap) {
                    Ok(summary) => {
                        let mut resp = ItdrResponse::default();
                        resp.magic = ITDR_RESP_MAGIC;
                        resp.status = 0;
                        resp.total_identities = summary.total_identities;
                        resp.quarantined_identities = summary.quarantined_identities;
                        resp.total_threats = summary.total_threats;
                        resp.active_threats = summary.active_threats;
                        resp.avg_trust_score = self.calculate_avg_trust_score();
                        resp.global_identity_risk = summary.global_identity_risk;
                        resp.identity_state = 0;
                        resp.target_id = 0;
                        resp.audit_hash[..16].copy_from_slice(&self.last_hash[..16]);
                        let status_str = b"STATUS_OK\0\0\0\0\0\0\0";
                        resp.status_str.copy_from_slice(status_str);
                        resp
                    }
                    Err(_) => ItdrResponse::error(2, b"ERR: PERM_DENIED"),
                }
            }
            2 => {
                // RegisterIdentity
                let name = core::str::from_utf8(&req.target_name)
                    .unwrap_or("unknown")
                    .trim_matches('\0');
                let id_type = IdentityType::from_u8(req.threat_type);
                match self.register_identity(&caller_cap, name, id_type, 90, 0x00FF, req.epoch) {
                    Ok(new_id) => {
                        let mut resp = ItdrResponse::default();
                        resp.magic = ITDR_RESP_MAGIC;
                        resp.status = 0;
                        resp.target_id = new_id;
                        resp.total_identities = self.identity_count as u32;
                        resp.audit_hash[..16].copy_from_slice(&self.last_hash[..16]);
                        let status_str = b"IDENTITY_REG\0\0\0\0";
                        resp.status_str.copy_from_slice(status_str);
                        resp
                    }
                    Err(_) => ItdrResponse::error(3, b"ERR: REG_FAILED\0"),
                }
            }
            3 => {
                // IngestThreat
                let threat_type = IdentityThreatType::from_u8(req.threat_type);
                let severity = ThreatSeverity::from_u8(req.severity);
                let details = core::str::from_utf8(&req.target_name)
                    .unwrap_or("unknown")
                    .trim_matches('\0');
                match self.ingest_threat_event(
                    &caller_cap,
                    req.identity_id,
                    threat_type,
                    severity,
                    75,
                    details,
                    req.epoch,
                ) {
                    Ok(event_id) => {
                        let mut resp = ItdrResponse::default();
                        resp.magic = ITDR_RESP_MAGIC;
                        resp.status = 0;
                        resp.target_id = event_id;
                        resp.total_threats = self.threat_count as u32;
                        resp.global_identity_risk = self.global_identity_risk;
                        resp.audit_hash[..16].copy_from_slice(&self.last_hash[..16]);
                        let status_str = b"THREAT_INGESTED\0";
                        resp.status_str.copy_from_slice(status_str);
                        resp
                    }
                    Err(_) => ItdrResponse::error(4, b"ERR: INGEST_FAIL"),
                }
            }
            4 => {
                // AnalyzeThreats
                match self.analyze_threats(&caller_cap, req.epoch) {
                    Ok(analyzed) => {
                        let mut resp = ItdrResponse::default();
                        resp.magic = ITDR_RESP_MAGIC;
                        resp.status = 0;
                        resp.target_id = analyzed;
                        resp.global_identity_risk = self.global_identity_risk;
                        resp.audit_hash[..16].copy_from_slice(&self.last_hash[..16]);
                        let status_str = b"ANALYSIS_DONE\0\0\0";
                        resp.status_str.copy_from_slice(status_str);
                        resp
                    }
                    Err(_) => ItdrResponse::error(5, b"ERR: ANALYZE\0\0\0\0"),
                }
            }
            5 => {
                // RevokeIdentity
                match self.revoke_identity(&caller_cap, req.identity_id, req.epoch) {
                    Ok(()) => {
                        let mut resp = ItdrResponse::default();
                        resp.magic = ITDR_RESP_MAGIC;
                        resp.status = 0;
                        resp.target_id = req.identity_id;
                        resp.identity_state = IdentityState::Revoked as u8;
                        resp.global_identity_risk = self.global_identity_risk;
                        resp.audit_hash[..16].copy_from_slice(&self.last_hash[..16]);
                        let status_str = b"IDENTITY_REVOKED";
                        resp.status_str.copy_from_slice(status_str);
                        resp
                    }
                    Err(_) => ItdrResponse::error(6, b"ERR: REVOKE_FAIL"),
                }
            }
            6 => {
                // Isolate / Quarantine Identity
                match self.quarantine_identity(&caller_cap, req.identity_id, req.epoch) {
                    Ok(()) => {
                        let mut resp = ItdrResponse::default();
                        resp.magic = ITDR_RESP_MAGIC;
                        resp.status = 0;
                        resp.target_id = req.identity_id;
                        resp.identity_state = IdentityState::Quarantined as u8;
                        resp.global_identity_risk = self.global_identity_risk;
                        resp.audit_hash[..16].copy_from_slice(&self.last_hash[..16]);
                        let status_str = b"QUARANTINED\0\0\0\0\0";
                        resp.status_str.copy_from_slice(status_str);
                        resp
                    }
                    Err(_) => ItdrResponse::error(7, b"ERR: QUAR_FAIL\0\0"),
                }
            }
            7 => {
                // RemediateAllCompromised
                match self.remediate_all_compromised(&caller_cap, req.epoch) {
                    Ok(rep) => {
                        let mut resp = ItdrResponse::default();
                        resp.magic = ITDR_RESP_MAGIC;
                        resp.status = 0;
                        resp.total_identities = self.identity_count as u32;
                        resp.quarantined_identities = rep.quarantined_count as u32;
                        resp.total_threats = self.threat_count as u32;
                        resp.active_threats = 0;
                        resp.avg_trust_score = rep.avg_trust_after;
                        resp.global_identity_risk = rep.score_after;
                        resp.audit_hash[..16].copy_from_slice(&rep.report_hash[..16]);
                        let status_str = b"REMEDIATED_ALL\0\0";
                        resp.status_str.copy_from_slice(status_str);
                        resp
                    }
                    Err(_) => ItdrResponse::error(8, b"ERR: REMEDIATE\0\0"),
                }
            }
            8 => {
                // VerifyAudit
                let valid = self.verify_ledger_integrity();
                let mut resp = ItdrResponse::default();
                resp.magic = ITDR_RESP_MAGIC;
                resp.status = if valid { 0 } else { 1 };
                resp.audit_hash[..16].copy_from_slice(&self.last_hash[..16]);
                let status_str = if valid {
                    b"AUDIT_VALID\0\0\0\0\0"
                } else {
                    b"AUDIT_CORRUPT\0\0\0"
                };
                resp.status_str.copy_from_slice(status_str);
                resp
            }
            _ => ItdrResponse::error(9, b"ERR: BAD_OPCODE\0"),
        }
    }
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE 64 OCTETS
// ============================================================================

pub const ITDR_ENDPOINT_ID: u32 = 37;
pub const MAX_FASTPATH_BYTES: usize = 64;

pub const ITDR_REQ_MAGIC: u32 = 0x49544452; // "ITDR"
pub const ITDR_RESP_MAGIC: u32 = 0x49544453; // "ITDS"

/// Message de canal brut IPC (64 octets utiles)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
}

impl Default for ChannelMessage {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
        }
    }
}

/// Requête IPC ITDR déterministe (exactement 64 octets)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItdrRequest {
    pub magic: u32,            // 4
    pub opcode: u32,           // 4
    pub handle_id: u32,        // 4
    pub rights: u32,           // 4
    pub identity_id: u32,      // 4
    pub threat_type: u8,       // 1
    pub severity: u8,          // 1
    pub action_type: u8,       // 1
    pub _reserved1: u8,        // 1
    pub epoch: u64,            // 8
    pub target_name: [u8; 32], // 32
}

const _: () = assert!(core::mem::size_of::<ItdrRequest>() == 64);

impl Default for ItdrRequest {
    fn default() -> Self {
        Self {
            magic: ITDR_REQ_MAGIC,
            opcode: 0,
            handle_id: 0,
            rights: 0,
            identity_id: 0,
            threat_type: 0,
            severity: 0,
            action_type: 0,
            _reserved1: 0,
            epoch: 0,
            target_name: [0u8; 32],
        }
    }
}

impl ItdrRequest {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.opcode.to_le_bytes());
        buf[8..12].copy_from_slice(&self.handle_id.to_le_bytes());
        buf[12..16].copy_from_slice(&self.rights.to_le_bytes());
        buf[16..20].copy_from_slice(&self.identity_id.to_le_bytes());
        buf[20] = self.threat_type;
        buf[21] = self.severity;
        buf[22] = self.action_type;
        buf[23] = self._reserved1;
        buf[24..32].copy_from_slice(&self.epoch.to_le_bytes());
        buf[32..64].copy_from_slice(&self.target_name);
        buf
    }

    pub fn from_bytes(buf: &[u8; 64]) -> Result<Self, ItdrError> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != ITDR_REQ_MAGIC {
            return Err(ItdrError::InvalidRequest);
        }
        let opcode = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let handle_id = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let rights = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let identity_id = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let threat_type = buf[20];
        let severity = buf[21];
        let action_type = buf[22];
        let _reserved1 = buf[23];
        let epoch = u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]);
        let mut target_name = [0u8; 32];
        target_name.copy_from_slice(&buf[32..64]);

        Ok(Self {
            magic,
            opcode,
            handle_id,
            rights,
            identity_id,
            threat_type,
            severity,
            action_type,
            _reserved1,
            epoch,
            target_name,
        })
    }
}

/// Réponse IPC ITDR déterministe (exactement 64 octets)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItdrResponse {
    pub magic: u32,                  // 4
    pub status: u32,                 // 4
    pub total_identities: u32,       // 4
    pub quarantined_identities: u32, // 4
    pub total_threats: u32,          // 4
    pub active_threats: u32,         // 4
    pub avg_trust_score: u8,         // 1
    pub global_identity_risk: u8,    // 1
    pub identity_state: u8,          // 1
    pub _reserved1: u8,              // 1
    pub target_id: u32,              // 4
    pub audit_hash: [u8; 16],        // 16
    pub status_str: [u8; 16],        // 16
}

const _: () = assert!(core::mem::size_of::<ItdrResponse>() == 64);

impl Default for ItdrResponse {
    fn default() -> Self {
        Self {
            magic: ITDR_RESP_MAGIC,
            status: 0,
            total_identities: 0,
            quarantined_identities: 0,
            total_threats: 0,
            active_threats: 0,
            avg_trust_score: 0,
            global_identity_risk: 0,
            identity_state: 0,
            _reserved1: 0,
            target_id: 0,
            audit_hash: [0u8; 16],
            status_str: [0u8; 16],
        }
    }
}

impl ItdrResponse {
    pub fn error(code: u32, reason: &[u8; 16]) -> Self {
        let mut resp = Self::default();
        resp.magic = ITDR_RESP_MAGIC;
        resp.status = code;
        resp.status_str.copy_from_slice(reason);
        resp
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.status.to_le_bytes());
        buf[8..12].copy_from_slice(&self.total_identities.to_le_bytes());
        buf[12..16].copy_from_slice(&self.quarantined_identities.to_le_bytes());
        buf[16..20].copy_from_slice(&self.total_threats.to_le_bytes());
        buf[20..24].copy_from_slice(&self.active_threats.to_le_bytes());
        buf[24] = self.avg_trust_score;
        buf[25] = self.global_identity_risk;
        buf[26] = self.identity_state;
        buf[27] = self._reserved1;
        buf[28..32].copy_from_slice(&self.target_id.to_le_bytes());
        buf[32..48].copy_from_slice(&self.audit_hash);
        buf[48..64].copy_from_slice(&self.status_str);
        buf
    }

    pub fn from_bytes(buf: &[u8; 64]) -> Result<Self, ItdrError> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != ITDR_RESP_MAGIC {
            return Err(ItdrError::InvalidRequest);
        }
        let status = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let total_identities = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let quarantined_identities = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let total_threats = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let active_threats = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let avg_trust_score = buf[24];
        let global_identity_risk = buf[25];
        let identity_state = buf[26];
        let _reserved1 = buf[27];
        let target_id = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let mut audit_hash = [0u8; 16];
        audit_hash.copy_from_slice(&buf[32..48]);
        let mut status_str = [0u8; 16];
        status_str.copy_from_slice(&buf[48..64]);

        Ok(Self {
            magic,
            status,
            total_identities,
            quarantined_identities,
            total_threats,
            active_threats,
            avg_trust_score,
            global_identity_risk,
            identity_state,
            _reserved1,
            target_id,
            audit_hash,
            status_str,
        })
    }
}

/// Client IPC ITDR léger pour les services clients
pub struct ItdrClient {
    pub endpoint_handle: Handle,
}

impl ItdrClient {
    pub fn new(handle: Handle) -> Self {
        Self {
            endpoint_handle: handle,
        }
    }

    pub fn call(&self, req: &ItdrRequest) -> Result<ItdrResponse, ItdrError> {
        let req_bytes = req.to_bytes();
        let mut tx_msg = ChannelMessage::default();
        tx_msg.bytes[..64].copy_from_slice(&req_bytes);
        tx_msg.byte_count = 64;

        let mut rx_msg = ChannelMessage::default();

        let (ret, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.endpoint_handle.0,
                &tx_msg as *const ChannelMessage as u64,
                &mut rx_msg as *mut ChannelMessage as u64,
                0,
                0,
                0,
            )
        };

        if ret != 0 || rx_msg.byte_count < 64 {
            return Err(ItdrError::InvalidState);
        }

        let mut resp_buf = [0u8; 64];
        resp_buf.copy_from_slice(&rx_msg.bytes[..64]);
        ItdrResponse::from_bytes(&resp_buf)
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_itdr_sha256_deterministic() {
        let digest1 = Sha256::digest(b"jambo-itdr-deterministic-test");
        let digest2 = Sha256::digest(b"jambo-itdr-deterministic-test");
        assert_eq!(digest1, digest2);
        assert_ne!(digest1, [0u8; 32]);
    }

    #[test]
    fn test_itdr_cap_monotonic_attenuation() {
        let root = ItdrCap::new(Handle::new(1, 1), itdr_rights::ALL, 1000, 100);
        let attenuated = root
            .attenuate(
                itdr_rights::MONITOR_IDENTITIES | itdr_rights::INGEST_AUTH_EVENTS,
                500,
                50,
            )
            .expect("valid attenuation");
        assert!(attenuated.has_right(itdr_rights::MONITOR_IDENTITIES));
        assert!(attenuated.has_right(itdr_rights::INGEST_AUTH_EVENTS));
        assert!(!attenuated.has_right(itdr_rights::TRIGGER_RESPONSE));
        assert!(!attenuated.has_right(itdr_rights::ADMIN));

        // Tentative d'escalade interdite
        assert_eq!(
            attenuated.attenuate(itdr_rights::ALL, 1000, 100),
            Err(ItdrError::AttenuationViolation)
        );
    }

    #[test]
    fn test_itdr_defaults_and_analysis() {
        let admin_cap = ItdrCap::new(Handle::new(1, 1), itdr_rights::ALL, 1000, 100);
        let mut daemon = JamboItdrDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.identity_count, 5);
        assert_eq!(daemon.threat_count, 3);
        assert!(daemon.global_identity_risk > 0);

        let summary = daemon.get_summary(&admin_cap).expect("summary");
        assert_eq!(summary.total_identities, 5);
        assert_eq!(summary.total_threats, 3);
        assert!(summary.ledger_valid);
    }

    #[test]
    fn test_itdr_remediation_and_confinement() {
        let admin_cap = ItdrCap::new(Handle::new(1, 1), itdr_rights::ALL, 1000, 100);
        let mut daemon = JamboItdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let initial_risk = daemon.global_identity_risk;
        let rep = daemon
            .remediate_all_compromised(&admin_cap, 2000)
            .expect("remediate");
        assert!(rep.remediated_count >= 1);
        assert!(daemon.global_identity_risk < initial_risk);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_itdr_audit_ledger_integrity() {
        let admin_cap = ItdrCap::new(Handle::new(1, 1), itdr_rights::ALL, 1000, 100);
        let mut daemon = JamboItdrDaemon::new(admin_cap);
        daemon.init_defaults();
        assert!(daemon.verify_ledger_integrity());

        // Altération d'une entrée d'audit -> détection immédiate
        if let Some(ref mut entry) = daemon.ledger[0] {
            entry.action[0] ^= 0xFF;
        }
        assert!(!daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_itdr_ipc_message_sizes_64_bytes() {
        assert_eq!(core::mem::size_of::<ItdrRequest>(), 64);
        assert_eq!(core::mem::size_of::<ItdrResponse>(), 64);

        let req = ItdrRequest {
            magic: ITDR_REQ_MAGIC,
            opcode: 1,
            handle_id: 10,
            rights: itdr_rights::ALL,
            identity_id: 3,
            threat_type: 2,
            severity: 4,
            action_type: 1,
            _reserved1: 0,
            epoch: 1234567,
            target_name: [42u8; 32],
        };
        let b = req.to_bytes();
        assert_eq!(b.len(), 64);
        let req2 = ItdrRequest::from_bytes(&b).expect("valid parse");
        assert_eq!(req, req2);
    }

    #[test]
    fn test_itdr_ipc_dispatch() {
        let admin_cap = ItdrCap::new(Handle::new(1, 1), itdr_rights::ALL, 1000, 100);
        let mut daemon = JamboItdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let req = ItdrRequest {
            magic: ITDR_REQ_MAGIC,
            opcode: 1, // GetStatus
            handle_id: 1,
            rights: itdr_rights::ALL,
            ..Default::default()
        };
        let resp = daemon.dispatch_ipc(&req);
        assert_eq!(resp.magic, ITDR_RESP_MAGIC);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.total_identities, 5);
    }
}

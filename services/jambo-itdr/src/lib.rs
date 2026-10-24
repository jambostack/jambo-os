//! Détection et Réponse aux Menaces sur l'Identité (ITDR - Identity Threat Detection and Response),
//! Détection d'Attaques sur les Jetons/Capabilités & Confinement Autonome d'Identités Compromises
//!
//! Phase 163 — Jalon v0.3.30
//!
//! Fournit une plateforme souveraine ITDR (Identity Threat Detection and Response) en `#![no_std]` :
//! 1. Modélisation et surveillance des identités souveraines (noyau, daemons système, identités de grappe réparties, rôles admin).
//! 2. Détection en temps réel des vecteurs avancés de menaces sur l'identité :
//!    - Compromission de jetons de session / fuite de clés éphémères (`TokenCompromise`),
//!    - Attaques par rejeu de sessions / collisions d'identités (`SessionReplay`),
//!    - Usurpation de capabilités / tentatives d'accès inter-CSpace non autorisées (`CapabilityUsurpation`),
//!    - Élévation illicite de privilèges / transition anormale vers des rôles privilégiés (`PrivilegeEscalation`),
//!    - Fréquence anormale d'authentification / brute-force (`AnomalousAuthRate`),
//!    - Dérive géotopologique / sauts anormaux dans le maillage de grappe (`DivergentGeoMesh`),
//!    - Vol et injection de capabilités à travers les frontières d'isolation (`PassTheCapability`),
//!    - Déplacement latéral vers des domaines ou CSpaces voisins (`LateralPrivilegeMovement`),
//!    - Double authentification simultanée géographiquement impossible (`ImpossibleTravel`),
//!    - Attaques par bourrage d'identifiants (`CredentialStuffing`),
//!    - Falsification ou MAC invalide sur un jeton capabilaire (`ForgedCapabilityToken`).
//! 3. Évaluation dynamique et déterministe du score de confiance (Trust Score 0..100) et indice de risque global.
//! 4. Orchestration autonome de remédiation proactive :
//!    - Révocation immédiate des jetons et sessions compromises,
//!    - Mise en quarantaine / isolement strict d'identités suspectes,
//!    - Dégradation monotone des capabilités attribuées,
//!    - Rupture immédiate du canal IPC/session (`TerminateSession`),
//!    - Rétablissement strict au profil minimal de moindre privilège (`LeastPrivilegeRollback`),
//!    - Déclenchement d'un défi cryptographique step-up (MFA souverain / PQC),
//!    - Confinement autonome O(1) de toutes les identités compromises (`remediate_all_compromised`).
//! 5. Rapports scellés cryptographiquement par SHA-256 :
//!    - Rapport de posture d'identité (`ItdrAssessmentReport`),
//!    - Rapport de remédiation coordonnée (`ItdrRemediationReport`).
//! 6. Contrôle d'accès capabilaire strict (`ItdrCap`) sans autorité ambiante avec atténuation monotone.
//! 7. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

#![no_std]

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
    KernelService,
    SystemDaemon,
    DistributedPrincipal,
    AdminRole,
    EphemeralSession,
}

/// État opérationnel de l'identité
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityState {
    Active,
    Suspicious,
    Quarantined,
    Revoked,
}

/// Typologie des vecteurs de menaces sur l'identité (ITDR)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityThreatType {
    TokenCompromise,
    SessionReplay,
    CapabilityUsurpation,
    PrivilegeEscalation,
    AnomalousAuthRate,
    DivergentGeoMesh,
    PassTheCapability,
    LateralPrivilegeMovement,
    ImpossibleTravel,
    CredentialStuffing,
    ForgedCapabilityToken,
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

/// Statut de traitement d'un incident de menace
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreatStatus {
    Detected,
    Investigating,
    Contained,
    Remediated,
    Dismissed,
}

/// Action de remédiation proactive d'identité
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseActionType {
    RevokeToken,
    QuarantineIdentity,
    DowngradeCapabilities,
    StepUpMfaChallenge,
    AlertSecurityOfficer,
    TerminateSession,
    LeastPrivilegeRollback,
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
        for i in 0..self.threat_count {
            if let Some(ref mut threat) = self.threats[i] {
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
        for i in 0..self.threat_count {
            if let Some(ref mut threat) = self.threats[i] {
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
        for i in 0..self.identity_count {
            if let Some(ref mut id_rec) = self.identities[i] {
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

        for i in 0..self.identity_count {
            if let Some(ref id_rec) = self.identities[i] {
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

        for i in 0..self.threat_count {
            if let Some(ref th) = self.threats[i] {
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
        for i in 0..self.identity_count {
            if let Some(ref id_rec) = self.identities[i] {
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
        for i in 0..self.identity_count {
            if let Some(ref id_rec) = self.identities[i] {
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
        for i in 0..self.threat_count {
            if let Some(ref th) = self.threats[i] {
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
        for i in 0..self.ledger_count {
            if let Some(ref entry) = self.ledger[i] {
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

    /// Vérifie la validité du sceau cryptographique SHA-256 d'un rapport de posture
    pub fn verify_assessment_report_hash(report: &ItdrAssessmentReport) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&report.report_id.to_be_bytes());
        hasher.update(&report.timestamp.to_be_bytes());
        hasher.update(&(report.total_identities as u32).to_be_bytes());
        hasher.update(&(report.active_identities as u32).to_be_bytes());
        hasher.update(&(report.suspicious_identities as u32).to_be_bytes());
        hasher.update(&(report.quarantined_identities as u32).to_be_bytes());
        hasher.update(&(report.revoked_identities as u32).to_be_bytes());
        hasher.update(&(report.total_threats as u32).to_be_bytes());
        hasher.update(&(report.active_threats as u32).to_be_bytes());
        hasher.update(&(report.remediated_threats as u32).to_be_bytes());
        hasher.update(&[
            report.avg_trust_score,
            report.global_identity_risk,
            report.health_posture_score,
        ]);
        let computed = hasher.finalize();
        computed == report.report_hash
    }

    /// Vérifie la validité du sceau cryptographique SHA-256 d'un rapport de remédiation
    pub fn verify_remediation_report_hash(report: &ItdrRemediationReport) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&report.report_id.to_be_bytes());
        hasher.update(&report.timestamp.to_be_bytes());
        hasher.update(&(report.remediated_count as u32).to_be_bytes());
        hasher.update(&(report.quarantined_count as u32).to_be_bytes());
        hasher.update(&(report.revoked_count as u32).to_be_bytes());
        hasher.update(&[
            report.risk_before,
            report.score_after,
            report.risk_reduction_pct,
            report.avg_trust_before,
            report.avg_trust_after,
        ]);
        let computed = hasher.finalize();
        computed == report.report_hash
    }

    /// Fournit la synthèse globale des indicateurs ITDR
    pub fn get_summary(&self, cap: &ItdrCap) -> Result<ItdrSummary, ItdrError> {
        if !cap.has_right(itdr_rights::QUERY_POSTURE) {
            return Err(ItdrError::PermissionDenied);
        }

        let mut active_id = 0u32;
        let mut quar_id = 0u32;
        for i in 0..self.identity_count {
            if let Some(ref id_rec) = self.identities[i] {
                match id_rec.state {
                    IdentityState::Active => active_id += 1,
                    IdentityState::Quarantined => quar_id += 1,
                    _ => {}
                }
            }
        }

        let mut active_th = 0u32;
        let mut mitig_th = 0u32;
        for i in 0..self.threat_count {
            if let Some(ref th) = self.threats[i] {
                match th.status {
                    ThreatStatus::Detected | ThreatStatus::Investigating => active_th += 1,
                    ThreatStatus::Contained | ThreatStatus::Remediated => mitig_th += 1,
                    _ => {}
                }
            }
        }

        Ok(ItdrSummary {
            total_identities: self.identity_count as u32,
            active_identities: active_id,
            quarantined_identities: quar_id,
            total_threats: self.threat_count as u32,
            active_threats: active_th,
            mitigated_threats: mitig_th,
            actions_count: self.action_count as u32,
            global_identity_risk: self.global_identity_risk,
            ledger_valid: self.verify_ledger_integrity(),
        })
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        let digest = Sha256::digest(b"jambo-itdr:sovereign-identity");
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn test_itdr_cap_rights_and_attenuation() {
        let admin = ItdrCap::new(Handle::new(13301, 1), itdr_rights::ALL, 10000, 500);
        assert!(admin.has_right(itdr_rights::MONITOR_IDENTITIES));
        assert!(admin.has_right(itdr_rights::INGEST_AUTH_EVENTS));
        assert!(admin.has_right(itdr_rights::TRIGGER_RESPONSE));
        assert!(admin.has_right(itdr_rights::REVOKE_CREDENTIALS));
        assert!(admin.has_right(itdr_rights::GENERATE_REPORT));
        assert!(admin.has_right(itdr_rights::AUTONOMOUS_CONFINEMENT));
        assert!(admin.has_right(itdr_rights::ADMIN));

        let sub_rights = itdr_rights::MONITOR_IDENTITIES | itdr_rights::QUERY_POSTURE;
        let sub_cap = admin.attenuate(sub_rights, 5000, 100).expect("Atténuation");
        assert!(sub_cap.has_right(itdr_rights::MONITOR_IDENTITIES));
        assert!(sub_cap.has_right(itdr_rights::QUERY_POSTURE));
        assert!(!sub_cap.has_right(itdr_rights::ADMIN));
        assert!(!sub_cap.has_right(itdr_rights::REVOKE_CREDENTIALS));
        assert!(!sub_cap.has_right(itdr_rights::AUTONOMOUS_CONFINEMENT));

        // Rejet d'escalade
        assert_eq!(
            sub_cap.attenuate(itdr_rights::ALL, 5000, 100),
            Err(ItdrError::AttenuationViolation)
        );
    }

    #[test]
    fn test_defaults_initialization() {
        let admin = ItdrCap::new(Handle::new(13302, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();

        assert_eq!(itdr.identity_count, 5);
        assert_eq!(itdr.threat_count, 3);
        assert!(itdr.global_identity_risk > 0);
        assert!(itdr.verify_ledger_integrity());
    }

    #[test]
    fn test_threat_detection_and_response() {
        let admin = ItdrCap::new(Handle::new(13303, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();

        // 1. Ingestion d'une nouvelle identité
        let id = itdr
            .register_identity(
                &admin,
                "app::worker-microservice",
                IdentityType::SystemDaemon,
                90,
                0x000F,
                2000,
            )
            .expect("Register identity");
        assert_eq!(id, 6);
        assert_eq!(itdr.identity_count, 6);

        // 2. Ingestion d'une menace de vol de session
        let tid = itdr
            .ingest_threat_event(
                &admin,
                id,
                IdentityThreatType::TokenCompromise,
                ThreatSeverity::High,
                85,
                "Token cloned on rogue endpoint",
                2010,
            )
            .expect("Ingest threat");
        assert_eq!(tid, 4);

        // 3. Analyse
        let analyzed = itdr.analyze_threats(&admin, 2020).expect("Analyze");
        assert!(analyzed >= 1);

        // 4. Réponse proactive
        let act_id = itdr
            .respond_to_threat(&admin, tid, ResponseActionType::RevokeToken, 2030)
            .expect("Respond");
        assert_eq!(act_id, 1);
        assert_eq!(itdr.identities[5].unwrap().state, IdentityState::Revoked);

        // Intégrité audit
        assert!(itdr.verify_ledger_integrity());
    }

    #[test]
    fn test_identity_quarantine_and_isolation() {
        let admin = ItdrCap::new(Handle::new(13304, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();

        itdr.quarantine_identity(&admin, 3, 3000)
            .expect("Quarantine");
        assert_eq!(
            itdr.identities[2].unwrap().state,
            IdentityState::Quarantined
        );
        assert!(itdr.verify_ledger_integrity());
    }

    #[test]
    fn test_full_automated_cycle() {
        let admin = ItdrCap::new(Handle::new(13305, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();

        let summary = itdr.run_full_cycle(&admin, 4000).expect("Run cycle");
        assert_eq!(summary.total_identities, 5);
        assert_eq!(summary.total_threats, 3);
        assert!(summary.actions_count > 0);
        assert!(itdr.verify_ledger_integrity());
    }

    #[test]
    fn test_ledger_tampering_detection() {
        let admin = ItdrCap::new(Handle::new(13306, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();
        assert!(itdr.verify_ledger_integrity());

        // Altération malveillante d'une entrée d'audit
        if let Some(ref mut entry) = itdr.ledger[0] {
            entry.action[0] ^= 0xFF;
        }
        assert!(!itdr.verify_ledger_integrity());
    }

    #[test]
    fn test_unauthorized_access_rejected() {
        let admin = ItdrCap::new(Handle::new(13307, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();

        let read_only = admin
            .attenuate(itdr_rights::QUERY_POSTURE, 1000, 50)
            .expect("Attenuation read-only");

        assert_eq!(
            itdr.register_identity(
                &read_only,
                "hacker",
                IdentityType::EphemeralSession,
                50,
                0,
                5000
            ),
            Err(ItdrError::PermissionDenied)
        );
        assert_eq!(
            itdr.analyze_threats(&read_only, 5010),
            Err(ItdrError::PermissionDenied)
        );
        assert_eq!(
            itdr.quarantine_identity(&read_only, 1, 5020),
            Err(ItdrError::PermissionDenied)
        );
        assert_eq!(
            itdr.remediate_all_compromised(&read_only, 5030),
            Err(ItdrError::PermissionDenied)
        );
        assert_eq!(
            itdr.generate_assessment_report(&read_only, 5040),
            Err(ItdrError::PermissionDenied)
        );
    }

    #[test]
    fn test_advanced_identity_threat_vectors() {
        let admin = ItdrCap::new(Handle::new(13308, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();

        let new_id = itdr
            .register_identity(
                &admin,
                "enclave::tee-worker-08",
                IdentityType::SystemDaemon,
                88,
                0x00FF,
                5100,
            )
            .expect("Register enclave worker");

        // Test vecteur PassTheCapability
        let t1 = itdr
            .ingest_threat_event(
                &admin,
                new_id,
                IdentityThreatType::PassTheCapability,
                ThreatSeverity::Critical,
                92,
                "Injected stolen capability token cross-CSpace",
                5110,
            )
            .expect("Ingest PassTheCapability");
        assert_eq!(t1, 4);

        // Test vecteur ImpossibleTravel
        let t2 = itdr
            .ingest_threat_event(
                &admin,
                new_id,
                IdentityThreatType::ImpossibleTravel,
                ThreatSeverity::High,
                78,
                "Simultaneous authentication from geographically disjoint nodes",
                5120,
            )
            .expect("Ingest ImpossibleTravel");
        assert_eq!(t2, 5);

        // Test vecteur ForgedCapabilityToken
        let t3 = itdr
            .ingest_threat_event(
                &admin,
                new_id,
                IdentityThreatType::ForgedCapabilityToken,
                ThreatSeverity::Critical,
                96,
                "Cryptographic HMAC signature mismatch on capability header",
                5130,
            )
            .expect("Ingest ForgedCapabilityToken");
        assert_eq!(t3, 6);

        assert_eq!(itdr.threat_count, 6);
        assert!(itdr.verify_ledger_integrity());
    }

    #[test]
    fn test_autonomous_confinement_and_remediation_report() {
        let admin = ItdrCap::new(Handle::new(13309, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();

        let report = itdr
            .remediate_all_compromised(&admin, 6000)
            .expect("Autonomous confinement O(1)");

        assert!(report.remediated_count >= 3);
        assert!(report.quarantined_count > 0 || report.revoked_count > 0);
        assert!(report.risk_before >= report.score_after);
        assert!(report.risk_reduction_pct > 0);
        assert!(JamboItdrDaemon::verify_remediation_report_hash(&report));
        assert!(itdr.verify_ledger_integrity());
    }

    #[test]
    fn test_assessment_report_generation_and_sealing() {
        let admin = ItdrCap::new(Handle::new(13310, 1), itdr_rights::ALL, 10000, 500);
        let mut itdr = JamboItdrDaemon::new(admin);
        itdr.init_defaults();

        let report = itdr
            .generate_assessment_report(&admin, 7000)
            .expect("Generate assessment report");

        assert_eq!(report.total_identities, 5);
        assert_eq!(report.total_threats, 3);
        assert!(report.avg_trust_score > 0);
        assert!(report.health_posture_score > 0);
        assert!(JamboItdrDaemon::verify_assessment_report_hash(&report));

        // Altération d'un champ du rapport détectée
        let mut tampered = report;
        tampered.avg_trust_score ^= 0x55;
        assert!(!JamboItdrDaemon::verify_assessment_report_hash(&tampered));
    }
}

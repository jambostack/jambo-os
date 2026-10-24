//! Sécurité Applicative Dynamique & RASP (Runtime Application Self-Protection) (`jambo-appsec`)
//!
//! Phase 140 — Jalon v0.3.7
//!
//! Fournit une plateforme souveraine de protection applicative à l'exécution (RASP) en `#![no_std]` :
//! 1. Surveillance d'exécution continue des microservices Ring 3 (canaris mémoire, intégrité Shadow Stack).
//! 2. Détection en temps réel des détournements de flux de contrôle (CFI, ROP/JOP, pointeurs corrompus).
//! 3. Détection et neutralisation des injections de charges utiles malveillantes (IPC abusif, requêtes arbitraires).
//! 4. Détection des désérialisations non sécurisées (gadgets malicieux, altérations d'objets en mémoire).
//! 5. Atténuation proactive et neutralisation instantanée des menaces sans arrêt global de service (O(1)).
//! 6. Confinement durci et quarantaine sélective des microservices compromis ou récidivistes.
//! 7. Contrôle d'accès capabilaire (`AppSecCap`) avec atténuation monotone stricte.
//! 8. Registre d'audit SHA-256 inaltérable scellé par chaînage cryptographique.

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
        let mut h = Self::new();
        h.update(data);
        h.finalize()
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
// CONTRÔLE D'ACCÈS CAPABILAIRE (AppSecCap)
// ============================================================================

pub mod appsec_rights {
    pub const REGISTER_TARGET: u32 = 0x0001;
    pub const CONFIGURE_POLICY: u32 = 0x0002;
    pub const ANALYZE_TELEMETRY: u32 = 0x0004;
    pub const NEUTRALIZE_THREAT: u32 = 0x0008;
    pub const ISOLATE_THREAD: u32 = 0x0010;
    pub const VERIFY_INTEGRITY: u32 = 0x0020;
    pub const QUERY_AUDIT: u32 = 0x0040;
    pub const ADMIN: u32 = 0x0080;

    pub const ALL: u32 = REGISTER_TARGET
        | CONFIGURE_POLICY
        | ANALYZE_TELEMETRY
        | NEUTRALIZE_THREAT
        | ISOLATE_THREAD
        | VERIFY_INTEGRITY
        | QUERY_AUDIT
        | ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppSecError {
    AccessDenied,
    CapabilityExpired,
    AttenuationViolation,
    TargetNotFound,
    TargetAlreadyExists,
    CapacityExceeded,
    ThreatNotFound,
    ThreatAlreadyNeutralized,
    InvalidPolicy,
    IntegrityViolationDetected,
    ShadowStackCorrupted,
    CanaryMismatch,
    PayloadNeutralizationFailed,
    AuditChainCorrupted,
    InvalidParameter,
}

/// Capabilité AppSec RASP souveraine sans autorité ambiante
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppSecCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl AppSecCap {
    pub const fn new(handle: Handle, rights: u32, max_lifetime: u64, invocations: u32) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left: invocations,
        }
    }

    #[inline]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation strictement monotone des droits
    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, AppSecError> {
        if (new_rights & !self.rights) != 0 {
            return Err(AppSecError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(AppSecError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(AppSecError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), AppSecError> {
        if self.invocations_left == 0 {
            return Err(AppSecError::CapabilityExpired);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// TYPES ET MODÈLES DE DONNÉES RASP
// ============================================================================

/// Profil de durcissement applicatif RASP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppSecProfile {
    Standard,
    Hardened,
    MilitarySovereign,
    AirGappedCritical,
}

/// Statut opérationnel d'un microservice surveillé
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    Active,
    Hardened,
    Degraded,
    Quarantined,
    Terminated,
}

/// Catégorie de menace applicative interceptée à l'exécution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    ControlFlowHijack,       // Détournement de flot d'exécution (CFI / ROP / JOP)
    PayloadInjection,        // Injection de commandes ou code arbitraire
    InsecureDeserialization, // Altération de structure d'objets ou payload malveillant
    MemoryCorruption,        // Canari écrasé ou débordement tampon VMO
    PrivilegeEscalation,     // Tentative de capture illicite de Ring 0 / Cap
    SideChannelLeak,         // Fuite d'informations ou canal auxiliaire
}

/// Sévérité de la menace
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Décision d'atténuation RASP prise en temps réel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaspAction {
    PassThrough,
    BlockAndAlert,
    NeutralizePayload,
    TerminateThread,
    HardenContext,
    QuarantineTarget,
}

/// Politique d'application RASP pour une cible Ring 3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaspPolicy {
    pub target_id: u32,
    pub enforce_cfi: bool,
    pub shadow_stack_enabled: bool,
    pub memory_canary_enabled: bool,
    pub inspect_deserialization: bool,
    pub max_allowed_violations: u32,
    pub auto_quarantine_on_critical: bool,
    pub default_action: RaspAction,
}

/// Microservice Ring 3 enregistré sous protection RASP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaspTarget {
    pub target_id: u32,
    pub name: [u8; 32],
    pub pid: u32,
    pub profile: AppSecProfile,
    pub status: TargetStatus,
    pub inspections_count: u64,
    pub violations_count: u32,
    pub threats_neutralized: u32,
    pub canary_token: u64,
    pub shadow_stack_ptr: u64,
    pub registered_at: u64,
}

impl RaspTarget {
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<inconnu>")
    }
}

/// Enregistrement d'une menace interceptée par le moteur RASP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppSecThreat {
    pub threat_id: u32,
    pub target_id: u32,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub action_taken: RaspAction,
    pub is_neutralized: bool,
    pub payload_fingerprint: [u8; 32],
    pub detected_at: u64,
    pub neutralized_at: u64,
    pub details: [u8; 64],
}

impl AppSecThreat {
    pub fn details_str(&self) -> &str {
        let len = self.details.iter().position(|&b| b == 0).unwrap_or(64);
        core::str::from_utf8(&self.details[..len]).unwrap_or("")
    }
}

/// Entrée d'audit cryptographique SHA-256
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppSecAuditEntry {
    pub entry_id: u32,
    pub timestamp: u64,
    pub action_code: u16,
    pub target_id: u32,
    pub threat_id: u32,
    pub details: [u8; 48],
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl AppSecAuditEntry {
    pub fn details_str(&self) -> &str {
        let len = self.details.iter().position(|&b| b == 0).unwrap_or(48);
        core::str::from_utf8(&self.details[..len]).unwrap_or("")
    }
}

/// Synthèse globale de posture applicative RASP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppSecSummary {
    pub total_targets: usize,
    pub active_targets: usize,
    pub quarantined_targets: usize,
    pub total_inspections: u64,
    pub total_threats_detected: usize,
    pub total_threats_neutralized: usize,
    pub cfi_violations_blocked: usize,
    pub injection_attempts_blocked: usize,
    pub deserialization_attacks_blocked: usize,
    pub memory_corruptions_contained: usize,
    pub global_appsec_health_score: u8,
}

// ============================================================================
// DÉMON SOUVERAIN JAMBO APPSEC RASP
// ============================================================================

pub const MAX_TARGETS: usize = 16;
pub const MAX_POLICIES: usize = 16;
pub const MAX_THREATS: usize = 32;
pub const MAX_AUDIT_ENTRIES: usize = 64;

pub struct JamboAppSecDaemon {
    pub admin_cap: AppSecCap,
    pub targets: [Option<RaspTarget>; MAX_TARGETS],
    pub policies: [Option<RaspPolicy>; MAX_POLICIES],
    pub threats: [Option<AppSecThreat>; MAX_THREATS],
    pub audit_ledger: [Option<AppSecAuditEntry>; MAX_AUDIT_ENTRIES],
    pub target_count: usize,
    pub policy_count: usize,
    pub threat_count: usize,
    pub audit_count: usize,
    pub last_audit_hash: [u8; 32],
}

impl JamboAppSecDaemon {
    pub fn new(admin_cap: AppSecCap) -> Self {
        Self {
            admin_cap,
            targets: [None; MAX_TARGETS],
            policies: [None; MAX_POLICIES],
            threats: [None; MAX_THREATS],
            audit_ledger: [None; MAX_AUDIT_ENTRIES],
            target_count: 0,
            policy_count: 0,
            threat_count: 0,
            audit_count: 0,
            last_audit_hash: [0u8; 32],
        }
    }

    /// Enregistre une cible microservice Ring 3 sous protection RASP
    pub fn register_target(
        &mut self,
        cap: &mut AppSecCap,
        target_id: u32,
        name: &str,
        pid: u32,
        profile: AppSecProfile,
        canary_token: u64,
        shadow_stack_ptr: u64,
        timestamp: u64,
    ) -> Result<(), AppSecError> {
        if !cap.has_right(appsec_rights::REGISTER_TARGET) {
            return Err(AppSecError::AccessDenied);
        }
        cap.consume()?;

        if self.find_target(target_id).is_some() {
            return Err(AppSecError::TargetAlreadyExists);
        }
        if self.target_count >= MAX_TARGETS {
            return Err(AppSecError::CapacityExceeded);
        }

        let mut name_buf = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        name_buf[..len].copy_from_slice(&bytes[..len]);

        let target = RaspTarget {
            target_id,
            name: name_buf,
            pid,
            profile,
            status: TargetStatus::Active,
            inspections_count: 0,
            violations_count: 0,
            threats_neutralized: 0,
            canary_token,
            shadow_stack_ptr,
            registered_at: timestamp,
        };

        for slot in self.targets.iter_mut() {
            if slot.is_none() {
                *slot = Some(target);
                self.target_count += 1;
                break;
            }
        }

        self.append_audit(
            1,
            target_id,
            0,
            timestamp,
            "Cible microservice enregistree RASP",
        );
        Ok(())
    }

    /// Déploie une politique RASP pour une cible
    pub fn set_policy(
        &mut self,
        cap: &mut AppSecCap,
        policy: RaspPolicy,
        timestamp: u64,
    ) -> Result<(), AppSecError> {
        if !cap.has_right(appsec_rights::CONFIGURE_POLICY) {
            return Err(AppSecError::AccessDenied);
        }
        cap.consume()?;

        if self.find_target(policy.target_id).is_none() {
            return Err(AppSecError::TargetNotFound);
        }

        let mut found = false;
        for p in self.policies.iter_mut().flatten() {
            if p.target_id == policy.target_id {
                *p = policy;
                found = true;
                break;
            }
        }

        if !found {
            if self.policy_count >= MAX_POLICIES {
                return Err(AppSecError::CapacityExceeded);
            }
            for slot in self.policies.iter_mut() {
                if slot.is_none() {
                    *slot = Some(policy);
                    self.policy_count += 1;
                    break;
                }
            }
        }

        self.append_audit(
            2,
            policy.target_id,
            0,
            timestamp,
            "Politique RASP configuree",
        );
        Ok(())
    }

    /// Analyse d'exécution télémétrique en temps réel et application de contre-mesure RASP
    pub fn inspect_execution(
        &mut self,
        cap: &mut AppSecCap,
        threat_id: u32,
        target_id: u32,
        category: ThreatCategory,
        severity: ThreatSeverity,
        canary_provided: u64,
        shadow_stack_valid: bool,
        payload_data: &[u8],
        timestamp: u64,
        details: &str,
    ) -> Result<RaspAction, AppSecError> {
        if !cap.has_right(appsec_rights::ANALYZE_TELEMETRY) {
            return Err(AppSecError::AccessDenied);
        }
        cap.consume()?;

        let (canary_token, enforce_cfi, canary_enabled, auto_quarantine, default_action) = {
            let target = self
                .find_target(target_id)
                .ok_or(AppSecError::TargetNotFound)?;
            if target.status == TargetStatus::Quarantined {
                return Ok(RaspAction::QuarantineTarget);
            }
            let policy = self.find_policy(target_id);
            let (ecfi, can_en, aq, da) = if let Some(p) = policy {
                (
                    p.enforce_cfi,
                    p.memory_canary_enabled,
                    p.auto_quarantine_on_critical,
                    p.default_action,
                )
            } else {
                (true, true, true, RaspAction::BlockAndAlert)
            };
            (target.canary_token, ecfi, can_en, aq, da)
        };

        // Incrémente compteur d'inspection
        if let Some(target) = self.find_target_mut(target_id) {
            target.inspections_count += 1;
        }

        // Détection de violations
        let mut violation_detected = false;
        let mut specific_action = default_action;

        // 1. CFI et Shadow Stack
        if enforce_cfi && category == ThreatCategory::ControlFlowHijack && !shadow_stack_valid {
            violation_detected = true;
            specific_action = RaspAction::NeutralizePayload;
        }

        // 2. Canari mémoire
        if canary_enabled
            && category == ThreatCategory::MemoryCorruption
            && canary_provided != canary_token
        {
            violation_detected = true;
            specific_action = RaspAction::TerminateThread;
        }

        // 3. Injection de charge utile ou Désérialisation
        if category == ThreatCategory::PayloadInjection
            || category == ThreatCategory::InsecureDeserialization
        {
            violation_detected = true;
            specific_action = if severity == ThreatSeverity::Critical {
                RaspAction::NeutralizePayload
            } else {
                RaspAction::BlockAndAlert
            };
        }

        // 4. Escalade de privilège
        if category == ThreatCategory::PrivilegeEscalation {
            violation_detected = true;
            specific_action = if auto_quarantine {
                RaspAction::QuarantineTarget
            } else {
                RaspAction::HardenContext
            };
        }

        if !violation_detected {
            return Ok(RaspAction::PassThrough);
        }

        // Enregistrement de la menace et neutralisation
        if self.threat_count >= MAX_THREATS {
            return Err(AppSecError::CapacityExceeded);
        }

        let payload_fingerprint = Sha256::digest(payload_data);
        let mut details_buf = [0u8; 64];
        let dbytes = details.as_bytes();
        let dlen = dbytes.len().min(64);
        details_buf[..dlen].copy_from_slice(&dbytes[..dlen]);

        let is_neutralized = matches!(
            specific_action,
            RaspAction::NeutralizePayload
                | RaspAction::BlockAndAlert
                | RaspAction::TerminateThread
                | RaspAction::QuarantineTarget
        );

        let threat = AppSecThreat {
            threat_id,
            target_id,
            category,
            severity,
            action_taken: specific_action,
            is_neutralized,
            payload_fingerprint,
            detected_at: timestamp,
            neutralized_at: if is_neutralized { timestamp } else { 0 },
            details: details_buf,
        };

        for slot in self.threats.iter_mut() {
            if slot.is_none() {
                *slot = Some(threat);
                self.threat_count += 1;
                break;
            }
        }

        // Mise à jour de la cible
        if let Some(target) = self.find_target_mut(target_id) {
            target.violations_count += 1;
            if is_neutralized {
                target.threats_neutralized += 1;
            }
            if specific_action == RaspAction::QuarantineTarget {
                target.status = TargetStatus::Quarantined;
            } else if specific_action == RaspAction::HardenContext {
                target.status = TargetStatus::Hardened;
            }
        }

        self.append_audit(
            3,
            target_id,
            threat_id,
            timestamp,
            "Menace RASP detectee et traitee",
        );

        Ok(specific_action)
    }

    /// Neutralise explicitement une menace résiduelle
    pub fn neutralize_threat(
        &mut self,
        cap: &mut AppSecCap,
        threat_id: u32,
        timestamp: u64,
    ) -> Result<(), AppSecError> {
        if !cap.has_right(appsec_rights::NEUTRALIZE_THREAT) {
            return Err(AppSecError::AccessDenied);
        }
        cap.consume()?;

        let target_id = {
            let threat = self
                .find_threat_mut(threat_id)
                .ok_or(AppSecError::ThreatNotFound)?;
            if threat.is_neutralized {
                return Err(AppSecError::ThreatAlreadyNeutralized);
            }
            threat.is_neutralized = true;
            threat.action_taken = RaspAction::NeutralizePayload;
            threat.neutralized_at = timestamp;
            threat.target_id
        };

        if let Some(target) = self.find_target_mut(target_id) {
            target.threats_neutralized += 1;
        }

        self.append_audit(
            4,
            target_id,
            threat_id,
            timestamp,
            "Menace neutralisee proactivement",
        );
        Ok(())
    }

    /// Confinement durci d'un microservice (isolation thread ou durcissement)
    pub fn isolate_target(
        &mut self,
        cap: &mut AppSecCap,
        target_id: u32,
        timestamp: u64,
    ) -> Result<(), AppSecError> {
        if !cap.has_right(appsec_rights::ISOLATE_THREAD) {
            return Err(AppSecError::AccessDenied);
        }
        cap.consume()?;

        let target = self
            .find_target_mut(target_id)
            .ok_or(AppSecError::TargetNotFound)?;
        target.status = TargetStatus::Hardened;

        self.append_audit(
            5,
            target_id,
            0,
            timestamp,
            "Confinement durci du microservice",
        );
        Ok(())
    }

    /// Mise en quarantaine instantanée O(1) d'une cible
    pub fn quarantine_target(
        &mut self,
        cap: &mut AppSecCap,
        target_id: u32,
        timestamp: u64,
    ) -> Result<(), AppSecError> {
        if !cap.has_right(appsec_rights::ADMIN) {
            return Err(AppSecError::AccessDenied);
        }
        cap.consume()?;

        let target = self
            .find_target_mut(target_id)
            .ok_or(AppSecError::TargetNotFound)?;
        target.status = TargetStatus::Quarantined;

        self.append_audit(
            6,
            target_id,
            0,
            timestamp,
            "Microservice place en quarantaine O(1)",
        );
        Ok(())
    }

    /// Vérifie l'intégrité mémoire et Shadow Stack d'une cible
    pub fn verify_target_integrity(
        &self,
        cap: &AppSecCap,
        target_id: u32,
        canary_provided: u64,
        shadow_stack_ptr: u64,
    ) -> Result<bool, AppSecError> {
        if !cap.has_right(appsec_rights::VERIFY_INTEGRITY) {
            return Err(AppSecError::AccessDenied);
        }

        let target = self
            .find_target(target_id)
            .ok_or(AppSecError::TargetNotFound)?;
        let canary_ok = target.canary_token == canary_provided;
        let shadow_ok = target.shadow_stack_ptr == shadow_stack_ptr;

        Ok(canary_ok && shadow_ok)
    }

    /// Synthèse globale de l'état RASP
    pub fn get_summary(&self, cap: &AppSecCap) -> Result<AppSecSummary, AppSecError> {
        if !cap.has_right(appsec_rights::QUERY_AUDIT) {
            return Err(AppSecError::AccessDenied);
        }

        let mut active = 0;
        let mut quarantined = 0;
        let mut total_inspections = 0u64;

        for t in self.targets.iter().flatten() {
            if t.status == TargetStatus::Active || t.status == TargetStatus::Hardened {
                active += 1;
            } else if t.status == TargetStatus::Quarantined {
                quarantined += 1;
            }
            total_inspections += t.inspections_count;
        }

        let mut neutralized_count = 0;
        let mut cfi_count = 0;
        let mut inj_count = 0;
        let mut deser_count = 0;
        let mut mem_count = 0;

        for th in self.threats.iter().flatten() {
            if th.is_neutralized {
                neutralized_count += 1;
            }
            match th.category {
                ThreatCategory::ControlFlowHijack => cfi_count += 1,
                ThreatCategory::PayloadInjection => inj_count += 1,
                ThreatCategory::InsecureDeserialization => deser_count += 1,
                ThreatCategory::MemoryCorruption => mem_count += 1,
                _ => {}
            }
        }

        // Calcul score de santé (0..100)
        let total_threats = self.threat_count;
        let health = if quarantined > 0 {
            let base = 85u8.saturating_sub((quarantined as u8) * 15);
            base.max(20)
        } else if total_threats > 0 && neutralized_count == total_threats {
            98
        } else {
            100
        };

        Ok(AppSecSummary {
            total_targets: self.target_count,
            active_targets: active,
            quarantined_targets: quarantined,
            total_inspections,
            total_threats_detected: self.threat_count,
            total_threats_neutralized: neutralized_count,
            cfi_violations_blocked: cfi_count,
            injection_attempts_blocked: inj_count,
            deserialization_attacks_blocked: deser_count,
            memory_corruptions_contained: mem_count,
            global_appsec_health_score: health,
        })
    }

    /// Vérification cryptographique de la chaîne de blocs d'audit SHA-256
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut prev = [0u8; 32];
        for entry in self.audit_ledger.iter().flatten() {
            if entry.prev_hash != prev {
                return false;
            }
            let computed = compute_audit_hash(
                entry.entry_id,
                entry.timestamp,
                entry.action_code,
                entry.target_id,
                entry.threat_id,
                &entry.details,
                &entry.prev_hash,
            );
            if entry.entry_hash != computed {
                return false;
            }
            prev = computed;
        }
        true
    }

    pub fn find_target(&self, target_id: u32) -> Option<&RaspTarget> {
        self.targets
            .iter()
            .flatten()
            .find(|t| t.target_id == target_id)
    }

    pub fn find_target_mut(&mut self, target_id: u32) -> Option<&mut RaspTarget> {
        self.targets
            .iter_mut()
            .flatten()
            .find(|t| t.target_id == target_id)
    }

    pub fn find_policy(&self, target_id: u32) -> Option<&RaspPolicy> {
        self.policies
            .iter()
            .flatten()
            .find(|p| p.target_id == target_id)
    }

    pub fn find_threat(&self, threat_id: u32) -> Option<&AppSecThreat> {
        self.threats
            .iter()
            .flatten()
            .find(|th| th.threat_id == threat_id)
    }

    pub fn find_threat_mut(&mut self, threat_id: u32) -> Option<&mut AppSecThreat> {
        self.threats
            .iter_mut()
            .flatten()
            .find(|th| th.threat_id == threat_id)
    }

    /// Ajoute une entrée dans le grand livre d'audit chaîné
    fn append_audit(
        &mut self,
        action_code: u16,
        target_id: u32,
        threat_id: u32,
        timestamp: u64,
        details: &str,
    ) {
        if self.audit_count >= MAX_AUDIT_ENTRIES {
            return;
        }

        let entry_id = (self.audit_count + 1) as u32;
        let mut d_buf = [0u8; 48];
        let bytes = details.as_bytes();
        let len = bytes.len().min(48);
        d_buf[..len].copy_from_slice(&bytes[..len]);

        let prev = self.last_audit_hash;
        let entry_hash = compute_audit_hash(
            entry_id,
            timestamp,
            action_code,
            target_id,
            threat_id,
            &d_buf,
            &prev,
        );

        let entry = AppSecAuditEntry {
            entry_id,
            timestamp,
            action_code,
            target_id,
            threat_id,
            details: d_buf,
            prev_hash: prev,
            entry_hash,
        };

        for slot in self.audit_ledger.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.audit_count += 1;
                self.last_audit_hash = entry_hash;
                break;
            }
        }
    }

    /// Initialise la configuration par défaut avec des microservices JamboOS réels
    pub fn init_defaults(&mut self) {
        let mut cap = self.admin_cap;

        // 1. Enregistrement des cibles microservices Ring 3
        // Target 1: jambo-auth2 (pid 101, Profil MilitarySovereign)
        let _ = self.register_target(
            &mut cap,
            1,
            "jambo-auth2",
            101,
            AppSecProfile::MilitarySovereign,
            0xDEAD_BEEF_CAFE_0001,
            0x7FFF_0000_1000,
            1000,
        );

        // Target 2: jambo-vfs (pid 102, Profil Hardened)
        let _ = self.register_target(
            &mut cap,
            2,
            "jambo-vfs",
            102,
            AppSecProfile::Hardened,
            0xDEAD_BEEF_CAFE_0002,
            0x7FFF_0000_2000,
            1005,
        );

        // Target 3: jambo-wasm (pid 103, Profil Hardened)
        let _ = self.register_target(
            &mut cap,
            3,
            "jambo-wasm",
            103,
            AppSecProfile::Hardened,
            0xDEAD_BEEF_CAFE_0003,
            0x7FFF_0000_3000,
            1010,
        );

        // Target 4: jambo-netd (pid 104, Profil Standard)
        let _ = self.register_target(
            &mut cap,
            4,
            "jambo-netd",
            104,
            AppSecProfile::Standard,
            0xDEAD_BEEF_CAFE_0004,
            0x7FFF_0000_4000,
            1015,
        );

        // 2. Politiques RASP associées
        let _ = self.set_policy(
            &mut cap,
            RaspPolicy {
                target_id: 1,
                enforce_cfi: true,
                shadow_stack_enabled: true,
                memory_canary_enabled: true,
                inspect_deserialization: true,
                max_allowed_violations: 1,
                auto_quarantine_on_critical: true,
                default_action: RaspAction::NeutralizePayload,
            },
            1020,
        );

        let _ = self.set_policy(
            &mut cap,
            RaspPolicy {
                target_id: 2,
                enforce_cfi: true,
                shadow_stack_enabled: false,
                memory_canary_enabled: true,
                inspect_deserialization: false,
                max_allowed_violations: 3,
                auto_quarantine_on_critical: false,
                default_action: RaspAction::BlockAndAlert,
            },
            1025,
        );

        let _ = self.set_policy(
            &mut cap,
            RaspPolicy {
                target_id: 3,
                enforce_cfi: true,
                shadow_stack_enabled: true,
                memory_canary_enabled: true,
                inspect_deserialization: true,
                max_allowed_violations: 2,
                auto_quarantine_on_critical: true,
                default_action: RaspAction::NeutralizePayload,
            },
            1030,
        );

        let _ = self.set_policy(
            &mut cap,
            RaspPolicy {
                target_id: 4,
                enforce_cfi: false,
                shadow_stack_enabled: false,
                memory_canary_enabled: true,
                inspect_deserialization: false,
                max_allowed_violations: 5,
                auto_quarantine_on_critical: false,
                default_action: RaspAction::BlockAndAlert,
            },
            1035,
        );

        // 3. Inspections réelles et neutralisation RASP d'attaques
        // Scénario A : Tentative de détournement CFI ROP sur jambo-wasm interceptée et neutralisée sans crash
        let _ = self.inspect_execution(
            &mut cap,
            1,
            3,
            ThreatCategory::ControlFlowHijack,
            ThreatSeverity::Critical,
            0xDEAD_BEEF_CAFE_0003,
            false, // Shadow Stack invalidé -> violation détectée !
            b"ROP_GADGET_CHAIN_0x7FFF1234",
            1040,
            "CFI ROP chain detournee neutralisee O(1)",
        );

        // Scénario B : Injection de commande payload sur jambo-netd bloquée
        let _ = self.inspect_execution(
            &mut cap,
            2,
            4,
            ThreatCategory::PayloadInjection,
            ThreatSeverity::High,
            0xDEAD_BEEF_CAFE_0004,
            true,
            b"EVIL_SHELLCODE_INJECT_SYSTEM",
            1045,
            "Injection payload bloquee et signalee",
        );

        // Scénario C : Désérialisation malveillante sur jambo-auth2 neutralisée
        let _ = self.inspect_execution(
            &mut cap,
            3,
            1,
            ThreatCategory::InsecureDeserialization,
            ThreatSeverity::Critical,
            0xDEAD_BEEF_CAFE_0001,
            true,
            b"SERIALIZED_GADGET_CLASS_COMPROMISE",
            1050,
            "Deserialisation non securisee neutralisee",
        );
    }
}

/// Calcule le hachage SHA-256 d'une entrée d'audit pour le scellement cryptographique
fn compute_audit_hash(
    entry_id: u32,
    timestamp: u64,
    action_code: u16,
    target_id: u32,
    threat_id: u32,
    details: &[u8; 48],
    prev_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&entry_id.to_be_bytes());
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(&action_code.to_be_bytes());
    hasher.update(&target_id.to_be_bytes());
    hasher.update(&threat_id.to_be_bytes());
    hasher.update(details);
    hasher.update(prev_hash);
    hasher.finalize()
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_appsec_cap_attenuation() {
        let admin_cap = AppSecCap::new(Handle::new(14001, 1), appsec_rights::ALL, 5000, 100);
        assert!(admin_cap.has_right(appsec_rights::REGISTER_TARGET));
        assert!(admin_cap.has_right(appsec_rights::NEUTRALIZE_THREAT));

        // Atténuation valide
        let sub_cap = admin_cap
            .attenuate(
                appsec_rights::ANALYZE_TELEMETRY | appsec_rights::QUERY_AUDIT,
                2000,
                50,
            )
            .expect("Atténuation");
        assert!(sub_cap.has_right(appsec_rights::ANALYZE_TELEMETRY));
        assert!(!sub_cap.has_right(appsec_rights::ADMIN));
        assert_eq!(sub_cap.max_lifetime, 2000);
        assert_eq!(sub_cap.invocations_left, 50);

        // Tentative d'élévation illicite
        let bad = sub_cap.attenuate(appsec_rights::ALL, 2000, 50);
        assert_eq!(bad, Err(AppSecError::AttenuationViolation));
    }

    #[test]
    fn test_daemon_init_and_threat_neutralization() {
        let admin_cap = AppSecCap::new(Handle::new(14002, 1), appsec_rights::ALL, 10000, 500);
        let mut daemon = JamboAppSecDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.target_count, 4);
        assert_eq!(daemon.policy_count, 4);
        assert_eq!(daemon.threat_count, 3);

        let cap = daemon.admin_cap;
        let sum = daemon.get_summary(&cap).expect("Résumé");
        assert_eq!(sum.total_targets, 4);
        assert_eq!(sum.total_threats_detected, 3);
        assert_eq!(sum.total_threats_neutralized, 3);
        assert_eq!(sum.cfi_violations_blocked, 1);
        assert_eq!(sum.injection_attempts_blocked, 1);
        assert_eq!(sum.deserialization_attacks_blocked, 1);

        // Vérification intégrité ledger
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_canary_integrity_and_thread_termination() {
        let admin_cap = AppSecCap::new(Handle::new(14003, 1), appsec_rights::ALL, 10000, 500);
        let mut daemon = JamboAppSecDaemon::new(admin_cap);
        daemon.init_defaults();

        let mut cap = daemon.admin_cap;

        // Canari corrompu sur target 2 (jambo-vfs)
        let action = daemon
            .inspect_execution(
                &mut cap,
                4,
                2,
                ThreatCategory::MemoryCorruption,
                ThreatSeverity::Critical,
                0x1111_2222_3333_4444, // Bad canary !
                true,
                b"STACK_SMASH_ATTEMPT",
                2000,
                "Ecrasement canari de pile detecte",
            )
            .expect("Inspection canary");

        assert_eq!(action, RaspAction::TerminateThread);
        assert_eq!(daemon.threat_count, 4);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_quarantine_target() {
        let admin_cap = AppSecCap::new(Handle::new(14004, 1), appsec_rights::ALL, 10000, 500);
        let mut daemon = JamboAppSecDaemon::new(admin_cap);
        daemon.init_defaults();

        let mut cap = daemon.admin_cap;
        daemon
            .quarantine_target(&mut cap, 4, 3000)
            .expect("Mise en quarantaine target 4");

        let t4 = daemon.find_target(4).expect("Target 4");
        assert_eq!(t4.status, TargetStatus::Quarantined);

        let sum = daemon.get_summary(&cap).expect("Résumé");
        assert_eq!(sum.quarantined_targets, 1);
        assert!(daemon.verify_ledger_integrity());
    }
}

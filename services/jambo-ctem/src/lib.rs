//! Programme Continu de Gestion de l'Exposition aux Menaces (CTEM - Continuous Threat Exposure Management)
//! Fédérant CSPM, CIEM, CWPP, ASPM, BAS et EASM
//!
//! Phase 132 — Jalon v0.2.130
//!
//! Fournit une plateforme souveraine CTEM (Continuous Threat Exposure Management) en `#![no_std]` :
//! 1. Cycle souverain en 5 étapes itératives : Cadrage (Scoping), Découverte (Discovery),
//!    Hiérarchisation (Prioritization), Validation (Validation), Mobilisation (Mobilization).
//! 2. Fédère et unifie les expositions multi-domaines (CSPM, CIEM, CWPP, ASPM, BAS, EASM).
//! 3. Modélisation de chemins d'attaque contextuels et calcul prédictif d'exploitabilité (0..100).
//! 4. Validation empirique de l'exploitabilité via contre-mesures et émulation BAS.
//! 5. Orchestration de remédiation proactive (révocation de droits, durcissement WAF, mise en quarantaine).
//! 6. Contrôle d'accès capabilaire strict (`CtemCap`) sans autorité ambiante avec atténuation monotone.
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
        let mut offset = 0;
        self.total_bytes += data.len() as u64;

        while offset < data.len() {
            let space = 64 - self.buffer_len;
            let to_copy = if data.len() - offset < space {
                data.len() - offset
            } else {
                space
            };

            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

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
// DROITS ET CAPABILITÉ CTEM (CtemCap)
// ============================================================================

pub mod ctem_rights {
    pub const SCOPE_MANAGEMENT: u32 = 1 << 0;
    pub const DISCOVERY_FEED: u32 = 1 << 1;
    pub const PRIORITIZE_EXPOSURES: u32 = 1 << 2;
    pub const VALIDATE_EXPLOITABILITY: u32 = 1 << 3;
    pub const MOBILIZE_REMEDIATION: u32 = 1 << 4;
    pub const QUERY_POSTURE: u32 = 1 << 5;
    pub const SEAL_LEDGER: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = SCOPE_MANAGEMENT
        | DISCOVERY_FEED
        | PRIORITIZE_EXPOSURES
        | VALIDATE_EXPLOITABILITY
        | MOBILIZE_REMEDIATION
        | QUERY_POSTURE
        | SEAL_LEDGER
        | ADMIN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtemError {
    PermissionDenied,
    AttenuationViolation,
    CapacityExceeded,
    NotFound,
    InvalidState,
    Expired,
    LedgerCorrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtemCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl CtemCap {
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
    ) -> Result<Self, CtemError> {
        if (new_rights & !self.rights) != 0 {
            return Err(CtemError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(CtemError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(CtemError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), CtemError> {
        if self.invocations_left == 0 {
            return Err(CtemError::Expired);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES DE DONNÉES CTEM
// ============================================================================

/// Les 5 étapes fondamentales du cycle continu de gestion des menaces (CTEM)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtemPhase {
    Scoping,
    Discovery,
    Prioritization,
    Validation,
    Mobilization,
}

/// Source fédérée d'exposition
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExposureSource {
    Cspm,
    Ciem,
    Cwpp,
    Aspm,
    Bas,
    Easm,
    Custom,
}

/// Criticité métier du domaine ou de l'actif
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusinessCriticality {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
}

/// Sévérité intrinsèque de la vulnérabilité
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExposureSeverity {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Info = 0,
}

/// Statut d'une exposition dans le cycle de vie CTEM
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExposureStatus {
    Discovered,
    Prioritized,
    Validated,
    Mobilized,
    Remediated,
    Suppressed,
}

/// Type d'action de remédiation orchestrée
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MobilizationActionType {
    RevokeCap,
    ApplyPatch,
    EnforceWaf,
    QuarantineAsset,
    AdjustPolicy,
}

/// Définition d'un périmètre d'application / cadrage (Scoping)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtemScope {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub target_domain: [u8; 48],
    pub domain_len: usize,
    pub criticality: BusinessCriticality,
    pub active: bool,
    pub asset_count: u32,
}

impl CtemScope {
    pub fn new(
        id: u32,
        name_str: &str,
        domain_str: &str,
        criticality: BusinessCriticality,
        asset_count: u32,
    ) -> Self {
        let mut name = [0u8; 32];
        let n_len = name_str.len().min(32);
        name[..n_len].copy_from_slice(&name_str.as_bytes()[..n_len]);

        let mut target_domain = [0u8; 48];
        let d_len = domain_str.len().min(48);
        target_domain[..d_len].copy_from_slice(&domain_str.as_bytes()[..d_len]);

        Self {
            id,
            name,
            name_len: n_len,
            target_domain,
            domain_len: d_len,
            criticality,
            active: true,
            asset_count,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }

    pub fn domain_as_str(&self) -> &str {
        core::str::from_utf8(&self.target_domain[..self.domain_len]).unwrap_or("<invalide>")
    }
}

/// Exposition fédérée identifiée dans le système
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreatExposure {
    pub id: u32,
    pub title: [u8; 48],
    pub title_len: usize,
    pub source: ExposureSource,
    pub target_asset: [u8; 32],
    pub target_len: usize,
    pub criticality: BusinessCriticality,
    pub severity: ExposureSeverity,
    /// Score prédictif d'exploitabilité contextualisé (0..100)
    pub exploitability_score: u8,
    pub attack_vector: [u8; 64],
    pub vector_len: usize,
    pub validated_exploitable: bool,
    pub status: ExposureStatus,
    pub discovered_timestamp: u64,
    pub last_updated: u64,
}

impl ThreatExposure {
    pub fn new(
        id: u32,
        title_str: &str,
        source: ExposureSource,
        target_str: &str,
        criticality: BusinessCriticality,
        severity: ExposureSeverity,
        attack_vector_str: &str,
        discovered_timestamp: u64,
    ) -> Self {
        let mut title = [0u8; 48];
        let t_len = title_str.len().min(48);
        title[..t_len].copy_from_slice(&title_str.as_bytes()[..t_len]);

        let mut target_asset = [0u8; 32];
        let tgt_len = target_str.len().min(32);
        target_asset[..tgt_len].copy_from_slice(&target_str.as_bytes()[..tgt_len]);

        let mut attack_vector = [0u8; 64];
        let v_len = attack_vector_str.len().min(64);
        attack_vector[..v_len].copy_from_slice(&attack_vector_str.as_bytes()[..v_len]);

        Self {
            id,
            title,
            title_len: t_len,
            source,
            target_asset,
            target_len: tgt_len,
            criticality,
            severity,
            exploitability_score: 0,
            attack_vector,
            vector_len: v_len,
            validated_exploitable: false,
            status: ExposureStatus::Discovered,
            discovered_timestamp,
            last_updated: discovered_timestamp,
        }
    }

    pub fn title_as_str(&self) -> &str {
        core::str::from_utf8(&self.title[..self.title_len]).unwrap_or("<invalide>")
    }

    pub fn target_as_str(&self) -> &str {
        core::str::from_utf8(&self.target_asset[..self.target_len]).unwrap_or("<invalide>")
    }

    pub fn vector_as_str(&self) -> &str {
        core::str::from_utf8(&self.attack_vector[..self.vector_len]).unwrap_or("<invalide>")
    }
}

/// Action de mobilisation / remédiation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MobilizationAction {
    pub id: u32,
    pub exposure_id: u32,
    pub action_type: MobilizationActionType,
    pub target_service: [u8; 32],
    pub target_len: usize,
    pub executed: bool,
    pub timestamp: u64,
}

impl MobilizationAction {
    pub fn new(
        id: u32,
        exposure_id: u32,
        action_type: MobilizationActionType,
        service_str: &str,
        timestamp: u64,
    ) -> Self {
        let mut target_service = [0u8; 32];
        let s_len = service_str.len().min(32);
        target_service[..s_len].copy_from_slice(&service_str.as_bytes()[..s_len]);

        Self {
            id,
            exposure_id,
            action_type,
            target_service,
            target_len: s_len,
            executed: true,
            timestamp,
        }
    }

    pub fn service_as_str(&self) -> &str {
        core::str::from_utf8(&self.target_service[..self.target_len]).unwrap_or("<invalide>")
    }
}

/// Entrée du registre d'audit cryptographique inviolable
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub index: u32,
    pub timestamp: u64,
    pub action_id: u8,
    pub details: [u8; 48],
    pub details_len: usize,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl AuditEntry {
    pub fn new(
        index: u32,
        timestamp: u64,
        action_id: u8,
        details_str: &str,
        prev_hash: [u8; 32],
    ) -> Self {
        let mut details = [0u8; 48];
        let d_len = details_str.len().min(48);
        details[..d_len].copy_from_slice(&details_str.as_bytes()[..d_len]);

        let mut hasher = Sha256::new();
        hasher.update(&index.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[action_id]);
        hasher.update(&details[..d_len]);
        hasher.update(&prev_hash);
        let entry_hash = hasher.finalize();

        Self {
            index,
            timestamp,
            action_id,
            details,
            details_len: d_len,
            prev_hash,
            entry_hash,
        }
    }

    pub fn details_as_str(&self) -> &str {
        core::str::from_utf8(&self.details[..self.details_len]).unwrap_or("<invalide>")
    }
}

/// Synthèse d'un cycle CTEM
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtemCycleSummary {
    pub total_scopes: usize,
    pub total_exposures: usize,
    pub prioritized_count: usize,
    pub validated_count: usize,
    pub mobilized_count: usize,
    pub remediated_count: usize,
    pub overall_exposure_score: u8,
    pub current_phase: CtemPhase,
}

// ============================================================================
// DÉMON CENTRAL CTEM (JamboCtemDaemon)
// ============================================================================

pub struct JamboCtemDaemon {
    pub admin_cap: CtemCap,
    pub scopes: [Option<CtemScope>; 8],
    pub scope_count: usize,
    pub exposures: [Option<ThreatExposure>; 16],
    pub exposure_count: usize,
    pub actions: [Option<MobilizationAction>; 16],
    pub action_count: usize,
    pub audit_ledger: [Option<AuditEntry>; 32],
    pub audit_count: usize,
    pub current_phase: CtemPhase,
    pub overall_exposure_score: u8,
}

impl JamboCtemDaemon {
    pub const fn new(admin_cap: CtemCap) -> Self {
        Self {
            admin_cap,
            scopes: [None; 8],
            scope_count: 0,
            exposures: [None; 16],
            exposure_count: 0,
            actions: [None; 16],
            action_count: 0,
            audit_ledger: [None; 32],
            audit_count: 0,
            current_phase: CtemPhase::Scoping,
            overall_exposure_score: 0,
        }
    }

    /// Initialise le scénario de référence avec les 5 sources majeures fédérées
    pub fn init_defaults(&mut self) {
        // Cadrage (Scoping) initial : 4 domaines souverains
        self.scopes[0] = Some(CtemScope::new(
            1,
            "Core Identity & KMS",
            "kernel::auth,kms",
            BusinessCriticality::Critical,
            12,
        ));
        self.scopes[1] = Some(CtemScope::new(
            2,
            "External Ingress Gateways",
            "netd,gwd,vpn",
            BusinessCriticality::Critical,
            8,
        ));
        self.scopes[2] = Some(CtemScope::new(
            3,
            "Workload Containers Ring3",
            "vmm,wasm,sandd",
            BusinessCriticality::High,
            24,
        ));
        self.scopes[3] = Some(CtemScope::new(
            4,
            "Software Supply Chain",
            "pkgd,aspm,dynlinkd",
            BusinessCriticality::High,
            16,
        ));
        self.scope_count = 4;

        // Découverte (Discovery) : Expositions issues de CSPM, CIEM, CWPP, ASPM, EASM
        // 1. EASM : Interface de débogage exposée
        self.exposures[0] = Some(ThreatExposure::new(
            1,
            "Debug Gateway Endpoint Exposed",
            ExposureSource::Easm,
            "jambo-gwd:9090",
            BusinessCriticality::Critical,
            ExposureSeverity::Critical,
            "Internet -> EASM Shadow Port 9090 -> Unauth Admin",
            1000,
        ));

        // 2. ASPM : Vulnérabilité critique dans le runtime WASI
        self.exposures[1] = Some(ThreatExposure::new(
            2,
            "Outdated Wasm Component Buffer Overflow",
            ExposureSource::Aspm,
            "jambo-wasm:component-auth",
            BusinessCriticality::High,
            ExposureSeverity::High,
            "Untrusted Wasm Bytecode -> ROP Trigger",
            1010,
        ));

        // 3. CIEM : Capabilité d'audit avec droits excessifs dormants
        self.exposures[2] = Some(ThreatExposure::new(
            3,
            "Dormant Superuser Cap in Worker Token",
            ExposureSource::Ciem,
            "jambo-schedd:worker-cap",
            BusinessCriticality::High,
            ExposureSeverity::High,
            "Privilege Escalation via Stale Cap Handle",
            1020,
        ));

        // 4. CWPP : Mémoire W+X détectée dans un processus Ring 3
        self.exposures[3] = Some(ThreatExposure::new(
            4,
            "Writable & Executable Memory Mapping",
            ExposureSource::Cwpp,
            "jambo-linux:posix-layer",
            BusinessCriticality::Medium,
            ExposureSeverity::Medium,
            "RIP Divergence -> Anonymous Memory Exec",
            1030,
        ));

        // 5. CSPM : Dérive de configuration TLS sur passerelle
        self.exposures[4] = Some(ThreatExposure::new(
            5,
            "Missing Post-Quantum TLS Hybrid Handshake",
            ExposureSource::Cspm,
            "jambo-vpn:crypto-suite",
            BusinessCriticality::Medium,
            ExposureSeverity::Low,
            "Classical ECDHE without Kyber fallback",
            1040,
        ));

        self.exposure_count = 5;

        // Entrée d'audit initiale
        let zero_hash = [0u8; 32];
        let entry = AuditEntry::new(
            1,
            1000,
            0x01,
            "CTEM Platform Initialized with 4 Scopes & 5 Exposures",
            zero_hash,
        );
        self.audit_ledger[0] = Some(entry);
        self.audit_count = 1;

        // Calcul initial de l'indice d'exposition
        self.calculate_overall_score();
    }

    /// Enregistre une entrée dans le journal d'audit scellé SHA-256
    fn record_audit(
        &mut self,
        action_id: u8,
        details: &str,
        timestamp: u64,
    ) -> Result<(), CtemError> {
        if self.audit_count >= self.audit_ledger.len() {
            return Err(CtemError::CapacityExceeded);
        }

        let prev_hash = if self.audit_count == 0 {
            [0u8; 32]
        } else {
            self.audit_ledger[self.audit_count - 1].unwrap().entry_hash
        };

        let next_idx = (self.audit_count as u32) + 1;
        let entry = AuditEntry::new(next_idx, timestamp, action_id, details, prev_hash);
        self.audit_ledger[self.audit_count] = Some(entry);
        self.audit_count += 1;
        Ok(())
    }

    /// Recalcule l'indice global d'exposition CTEM (0..100)
    fn calculate_overall_score(&mut self) {
        if self.exposure_count == 0 {
            self.overall_exposure_score = 0;
            return;
        }

        let mut total_weighted_score: u32 = 0;
        let mut total_weight: u32 = 0;

        for i in 0..self.exposure_count {
            if let Some(ref e) = self.exposures[i] {
                if e.status == ExposureStatus::Remediated || e.status == ExposureStatus::Suppressed
                {
                    continue;
                }

                let weight = (e.criticality as u32) * (e.severity as u32);
                let score = if e.exploitability_score > 0 {
                    e.exploitability_score as u32
                } else {
                    (e.severity as u32) * 20
                };

                total_weighted_score += score * weight;
                total_weight += weight;
            }
        }

        if total_weight == 0 {
            self.overall_exposure_score = 0;
        } else {
            let res = total_weighted_score / total_weight;
            self.overall_exposure_score = res.min(100) as u8;
        }
    }

    /// Étape 1 : Ajout d'un périmètre d'exposition (Scoping)
    pub fn add_scope(
        &mut self,
        cap: &CtemCap,
        name: &str,
        domain: &str,
        criticality: BusinessCriticality,
        asset_count: u32,
        timestamp: u64,
    ) -> Result<u32, CtemError> {
        if !cap.has_right(ctem_rights::SCOPE_MANAGEMENT) {
            return Err(CtemError::PermissionDenied);
        }
        if self.scope_count >= self.scopes.len() {
            return Err(CtemError::CapacityExceeded);
        }

        let id = (self.scope_count as u32) + 1;
        let scope = CtemScope::new(id, name, domain, criticality, asset_count);
        self.scopes[self.scope_count] = Some(scope);
        self.scope_count += 1;

        let _ = self.record_audit(0x10, "New Scope Registered", timestamp);
        Ok(id)
    }

    /// Étape 2 : Ingestion d'une exposition (Discovery)
    pub fn ingest_exposure(
        &mut self,
        cap: &CtemCap,
        title: &str,
        source: ExposureSource,
        target_asset: &str,
        criticality: BusinessCriticality,
        severity: ExposureSeverity,
        attack_vector: &str,
        timestamp: u64,
    ) -> Result<u32, CtemError> {
        if !cap.has_right(ctem_rights::DISCOVERY_FEED) {
            return Err(CtemError::PermissionDenied);
        }
        if self.exposure_count >= self.exposures.len() {
            return Err(CtemError::CapacityExceeded);
        }

        let id = (self.exposure_count as u32) + 1;
        let exp = ThreatExposure::new(
            id,
            title,
            source,
            target_asset,
            criticality,
            severity,
            attack_vector,
            timestamp,
        );
        self.exposures[self.exposure_count] = Some(exp);
        self.exposure_count += 1;

        self.calculate_overall_score();
        let _ = self.record_audit(0x20, "Threat Exposure Ingested", timestamp);
        Ok(id)
    }

    /// Étape 3 : Hiérarchisation contextuelle & calcul d'exploitabilité (Prioritization)
    pub fn prioritize_exposures(
        &mut self,
        cap: &CtemCap,
        timestamp: u64,
    ) -> Result<u32, CtemError> {
        if !cap.has_right(ctem_rights::PRIORITIZE_EXPOSURES) {
            return Err(CtemError::PermissionDenied);
        }

        let mut prioritized = 0;
        for i in 0..self.exposure_count {
            if let Some(ref mut e) = self.exposures[i] {
                if e.status == ExposureStatus::Discovered {
                    // Calcul d'exploitabilité : Sévérité (1..4) * 15 + Criticité (1..4) * 8 + SourceFactor
                    let source_factor: u32 = match e.source {
                        ExposureSource::Easm => 20, // Exposition externe directe = très exploitable
                        ExposureSource::Bas => 18,  // Émulation active réussie
                        ExposureSource::Aspm => 14, // Composant logiciel altéré
                        ExposureSource::Ciem => 12, // Droits excessifs
                        ExposureSource::Cwpp => 10, // Anomalie d'exécution
                        ExposureSource::Cspm => 8,  // Configuration défaillante
                        ExposureSource::Custom => 5,
                    };

                    let raw_score =
                        (e.severity as u32) * 15 + (e.criticality as u32) * 8 + source_factor;
                    e.exploitability_score = raw_score.min(100) as u8;
                    e.status = ExposureStatus::Prioritized;
                    e.last_updated = timestamp;
                    prioritized += 1;
                }
            }
        }

        self.calculate_overall_score();
        let _ = self.record_audit(
            0x30,
            "Contextual Exposure Prioritization Computed",
            timestamp,
        );
        Ok(prioritized)
    }

    /// Étape 4 : Validation empirique de l'exploitabilité (Validation)
    pub fn validate_exposure(
        &mut self,
        cap: &CtemCap,
        exposure_id: u32,
        is_exploitable: bool,
        timestamp: u64,
    ) -> Result<(), CtemError> {
        if !cap.has_right(ctem_rights::VALIDATE_EXPLOITABILITY) {
            return Err(CtemError::PermissionDenied);
        }

        for i in 0..self.exposure_count {
            if let Some(ref mut e) = self.exposures[i] {
                if e.id == exposure_id {
                    e.validated_exploitable = is_exploitable;
                    e.status = ExposureStatus::Validated;
                    if is_exploitable {
                        // Majoration si validé par simulation active
                        e.exploitability_score =
                            (e.exploitability_score as u16 + 10).min(100) as u8;
                    } else {
                        // Minoration si neutralisé par contrôle compensatoire
                        e.exploitability_score =
                            (e.exploitability_score as u16).saturating_sub(25) as u8;
                    }
                    e.last_updated = timestamp;
                    self.calculate_overall_score();
                    let _ = self.record_audit(0x40, "Exposure Exploitability Validated", timestamp);
                    return Ok(());
                }
            }
        }

        Err(CtemError::NotFound)
    }

    /// Étape 5 : Mobilisation & Déclenchement de remédiation proactive (Mobilization)
    pub fn mobilize_remediation(
        &mut self,
        cap: &CtemCap,
        exposure_id: u32,
        action_type: MobilizationActionType,
        target_service: &str,
        timestamp: u64,
    ) -> Result<u32, CtemError> {
        if !cap.has_right(ctem_rights::MOBILIZE_REMEDIATION) {
            return Err(CtemError::PermissionDenied);
        }
        if self.action_count >= self.actions.len() {
            return Err(CtemError::CapacityExceeded);
        }

        let mut found = false;
        for i in 0..self.exposure_count {
            if let Some(ref mut e) = self.exposures[i] {
                if e.id == exposure_id {
                    e.status = ExposureStatus::Mobilized;
                    e.last_updated = timestamp;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(CtemError::NotFound);
        }

        let action_id = (self.action_count as u32) + 1;
        let action = MobilizationAction::new(
            action_id,
            exposure_id,
            action_type,
            target_service,
            timestamp,
        );
        self.actions[self.action_count] = Some(action);
        self.action_count += 1;

        let _ = self.record_audit(0x50, "Remediation Playbook Mobilized", timestamp);
        Ok(action_id)
    }

    /// Finalisation de la remédiation et réduction monotone de l'exposition
    pub fn remediate_exposure(
        &mut self,
        cap: &CtemCap,
        exposure_id: u32,
        timestamp: u64,
    ) -> Result<(), CtemError> {
        if !cap.has_right(ctem_rights::MOBILIZE_REMEDIATION) {
            return Err(CtemError::PermissionDenied);
        }

        for i in 0..self.exposure_count {
            if let Some(ref mut e) = self.exposures[i] {
                if e.id == exposure_id {
                    e.status = ExposureStatus::Remediated;
                    e.exploitability_score = 0;
                    e.last_updated = timestamp;
                    self.calculate_overall_score();
                    let _ =
                        self.record_audit(0x51, "Threat Exposure Remediated & Hardened", timestamp);
                    return Ok(());
                }
            }
        }

        Err(CtemError::NotFound)
    }

    /// Avance le cycle CTEM d'une phase (Scoping -> Discovery -> Prioritization -> Validation -> Mobilization -> Scoping)
    pub fn advance_phase(&mut self, cap: &CtemCap, timestamp: u64) -> Result<CtemPhase, CtemError> {
        if !cap.has_right(ctem_rights::ADMIN) {
            return Err(CtemError::PermissionDenied);
        }

        self.current_phase = match self.current_phase {
            CtemPhase::Scoping => CtemPhase::Discovery,
            CtemPhase::Discovery => CtemPhase::Prioritization,
            CtemPhase::Prioritization => CtemPhase::Validation,
            CtemPhase::Validation => CtemPhase::Mobilization,
            CtemPhase::Mobilization => CtemPhase::Scoping,
        };

        let _ = self.record_audit(0x60, "CTEM Cycle Phase Advanced", timestamp);
        Ok(self.current_phase)
    }

    /// Exécute un cycle complet automatisé d'orchestration CTEM
    pub fn run_full_cycle(
        &mut self,
        cap: &CtemCap,
        timestamp: u64,
    ) -> Result<CtemCycleSummary, CtemError> {
        if !cap.has_right(ctem_rights::ADMIN) {
            return Err(CtemError::PermissionDenied);
        }

        // 1. Priorisation
        let _ = self.prioritize_exposures(cap, timestamp);

        // 2. Validation automatique sur les expositions prioritaires
        let mut to_validate = [(0u32, false); 16];
        let mut validate_cnt = 0;
        for i in 0..self.exposure_count {
            if let Some(ref e) = self.exposures[i] {
                if e.status == ExposureStatus::Prioritized {
                    let is_crit = (e.severity as u8 >= ExposureSeverity::High as u8)
                        || (e.criticality as u8 >= BusinessCriticality::High as u8);
                    to_validate[validate_cnt] = (e.id, is_crit);
                    validate_cnt += 1;
                }
            }
        }
        for i in 0..validate_cnt {
            let (id, is_crit) = to_validate[i];
            let _ = self.validate_exposure(cap, id, is_crit, timestamp);
        }

        // 3. Mobilisation sur les expositions critiques validées
        let mut to_mobilize = [(0u32, [0u8; 32], 0usize); 16];
        let mut mobilize_cnt = 0;
        for i in 0..self.exposure_count {
            if let Some(ref e) = self.exposures[i] {
                if e.status == ExposureStatus::Validated && e.validated_exploitable {
                    let mut tgt = [0u8; 32];
                    tgt[..e.target_len].copy_from_slice(&e.target_asset[..e.target_len]);
                    to_mobilize[mobilize_cnt] = (e.id, tgt, e.target_len);
                    mobilize_cnt += 1;
                }
            }
        }
        for i in 0..mobilize_cnt {
            let (id, tgt_buf, tgt_len) = to_mobilize[i];
            let target = core::str::from_utf8(&tgt_buf[..tgt_len]).unwrap_or("target");
            let _ = self.mobilize_remediation(
                cap,
                id,
                MobilizationActionType::EnforceWaf,
                target,
                timestamp,
            );
        }

        self.get_summary(cap)
    }

    /// Récupère la synthèse générale du cycle CTEM
    pub fn get_summary(&self, cap: &CtemCap) -> Result<CtemCycleSummary, CtemError> {
        if !cap.has_right(ctem_rights::QUERY_POSTURE) {
            return Err(CtemError::PermissionDenied);
        }

        let mut prioritized = 0;
        let mut validated = 0;
        let mut mobilized = 0;
        let mut remediated = 0;

        for i in 0..self.exposure_count {
            if let Some(ref e) = self.exposures[i] {
                match e.status {
                    ExposureStatus::Prioritized => prioritized += 1,
                    ExposureStatus::Validated => validated += 1,
                    ExposureStatus::Mobilized => mobilized += 1,
                    ExposureStatus::Remediated => remediated += 1,
                    _ => {}
                }
            }
        }

        Ok(CtemCycleSummary {
            total_scopes: self.scope_count,
            total_exposures: self.exposure_count,
            prioritized_count: prioritized,
            validated_count: validated,
            mobilized_count: mobilized,
            remediated_count: remediated,
            overall_exposure_score: self.overall_exposure_score,
            current_phase: self.current_phase,
        })
    }

    /// Vérifie l'intégrité cryptographique SHA-256 de bout en bout du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut prev_hash = [0u8; 32];

        for i in 0..self.audit_count {
            if let Some(ref entry) = self.audit_ledger[i] {
                if entry.prev_hash != prev_hash {
                    return false;
                }

                let mut hasher = Sha256::new();
                hasher.update(&entry.index.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&[entry.action_id]);
                hasher.update(&entry.details[..entry.details_len]);
                hasher.update(&entry.prev_hash);
                let computed = hasher.finalize();

                if computed != entry.entry_hash {
                    return false;
                }

                prev_hash = entry.entry_hash;
            } else {
                return false;
            }
        }

        true
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] compatible avec cargo test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_monotonic_attenuation() {
        let admin = CtemCap::new(Handle::new(13201, 1), ctem_rights::ALL, 10000, 500);
        assert!(admin.has_right(ctem_rights::SCOPE_MANAGEMENT));
        assert!(admin.has_right(ctem_rights::DISCOVERY_FEED));
        assert!(admin.has_right(ctem_rights::PRIORITIZE_EXPOSURES));
        assert!(admin.has_right(ctem_rights::VALIDATE_EXPLOITABILITY));
        assert!(admin.has_right(ctem_rights::MOBILIZE_REMEDIATION));
        assert!(admin.has_right(ctem_rights::QUERY_POSTURE));
        assert!(admin.has_right(ctem_rights::SEAL_LEDGER));
        assert!(admin.has_right(ctem_rights::ADMIN));

        let sub_rights = ctem_rights::QUERY_POSTURE | ctem_rights::PRIORITIZE_EXPOSURES;
        let sub_cap = admin.attenuate(sub_rights, 5000, 100).expect("Atténuation");
        assert!(sub_cap.has_right(ctem_rights::QUERY_POSTURE));
        assert!(sub_cap.has_right(ctem_rights::PRIORITIZE_EXPOSURES));
        assert!(!sub_cap.has_right(ctem_rights::ADMIN));
        assert!(!sub_cap.has_right(ctem_rights::MOBILIZE_REMEDIATION));

        // Rejet d'escalade
        assert_eq!(
            sub_cap.attenuate(ctem_rights::ALL, 5000, 100),
            Err(CtemError::AttenuationViolation)
        );
    }

    #[test]
    fn test_defaults_initialization() {
        let admin = CtemCap::new(Handle::new(13202, 1), ctem_rights::ALL, 10000, 500);
        let mut ctem = JamboCtemDaemon::new(admin);
        ctem.init_defaults();

        assert_eq!(ctem.scope_count, 4);
        assert_eq!(ctem.exposure_count, 5);
        assert!(ctem.overall_exposure_score > 0);
        assert!(ctem.verify_ledger_integrity());
    }

    #[test]
    fn test_ctem_five_phase_cycle() {
        let admin = CtemCap::new(Handle::new(13203, 1), ctem_rights::ALL, 10000, 500);
        let mut ctem = JamboCtemDaemon::new(admin);
        ctem.init_defaults();

        // 1. Scoping : ajouter un 5e scope
        let s_id = ctem
            .add_scope(
                &admin,
                "Cluster Mesh Routing",
                "jambo-meshd,secroute",
                BusinessCriticality::Medium,
                10,
                2000,
            )
            .expect("Add Scope");
        assert_eq!(s_id, 5);
        assert_eq!(ctem.scope_count, 5);

        // 2. Discovery : ajouter une nouvelle exposition
        let exp_id = ctem
            .ingest_exposure(
                &admin,
                "Weak PQC Key Exchange Candidate",
                ExposureSource::Custom,
                "jambo-vpn:kyber",
                BusinessCriticality::Medium,
                ExposureSeverity::Medium,
                "Sidechannel Timing on Negacyclic Poly",
                2010,
            )
            .expect("Ingest exposure");
        assert_eq!(exp_id, 6);
        assert_eq!(ctem.exposure_count, 6);

        // 3. Prioritization
        let p_count = ctem.prioritize_exposures(&admin, 2020).expect("Prioritize");
        assert_eq!(p_count, 6);
        assert!(ctem.exposures[0].unwrap().exploitability_score > 50);

        // 4. Validation
        ctem.validate_exposure(&admin, 1, true, 2030)
            .expect("Validate #1");
        assert!(ctem.exposures[0].unwrap().validated_exploitable);

        // 5. Mobilization
        let act_id = ctem
            .mobilize_remediation(
                &admin,
                1,
                MobilizationActionType::EnforceWaf,
                "jambo-waf",
                2040,
            )
            .expect("Mobilize #1");
        assert_eq!(act_id, 1);
        assert_eq!(ctem.action_count, 1);

        // Remédiation finale
        let old_score = ctem.overall_exposure_score;
        ctem.remediate_exposure(&admin, 1, 2050)
            .expect("Remediate #1");
        assert!(ctem.overall_exposure_score < old_score);

        // Vérification audit ledger
        assert!(ctem.verify_ledger_integrity());
    }

    #[test]
    fn test_full_automated_cycle() {
        let admin = CtemCap::new(Handle::new(13204, 1), ctem_rights::ALL, 10000, 500);
        let mut ctem = JamboCtemDaemon::new(admin);
        ctem.init_defaults();

        let summary = ctem.run_full_cycle(&admin, 3000).expect("Run full cycle");
        assert_eq!(summary.total_scopes, 4);
        assert_eq!(summary.total_exposures, 5);
        assert!(summary.mobilized_count > 0);
        assert!(ctem.verify_ledger_integrity());
    }

    #[test]
    fn test_unauthorized_access_rejected() {
        let admin = CtemCap::new(Handle::new(13205, 1), ctem_rights::ALL, 10000, 500);
        let mut ctem = JamboCtemDaemon::new(admin);
        ctem.init_defaults();

        let read_only = admin
            .attenuate(ctem_rights::QUERY_POSTURE, 1000, 50)
            .expect("Attenuation read-only");

        assert_eq!(
            ctem.add_scope(
                &read_only,
                "Unauthorized",
                "target",
                BusinessCriticality::Low,
                1,
                4000
            ),
            Err(CtemError::PermissionDenied)
        );
        assert_eq!(
            ctem.prioritize_exposures(&read_only, 4005),
            Err(CtemError::PermissionDenied)
        );
        assert_eq!(
            ctem.validate_exposure(&read_only, 1, true, 4010),
            Err(CtemError::PermissionDenied)
        );
        assert_eq!(
            ctem.mobilize_remediation(
                &read_only,
                1,
                MobilizationActionType::RevokeCap,
                "target",
                4015
            ),
            Err(CtemError::PermissionDenied)
        );
    }
}

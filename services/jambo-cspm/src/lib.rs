//! Gestion de la Posture de Sécurité Cloud/Grappe (CSPM), Détection de Dérive (Drift) & Remédiation Autonome
//!
//! Phase 125 — Jalon v0.2.123
//!
//! Fournit un système souverain Cloud Security Posture Management (CSPM) en environnement `#![no_std]` :
//! 1. Moteur d'audit continu de conformité par rapport aux baselines souveraines durcies (CIS Microkernel, DISA STIG, ANSSI SecNumCloud).
//! 2. Détection de dérive de configuration (Configuration Drift) sur les scopes critiques (Noyau, TEE, VFS, Réseau, Bac à sable, Audit, Zero-Trust).
//! 3. Calcul de posture de sécurité (Score de Posture 0-100) et indice de risque de grappe (Risk Index 0-1000).
//! 4. Remédiation autonome en temps réel réalignant les paramètres déviants sur les valeurs nominales souveraines.
//! 5. Contrôle d'accès capabilaire (`CspmCap`) sans autorité ambiante et atténuation monotone.
//! 6. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

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
}

// ============================================================================
// DROITS & CAPABILITÉS CSPM (`CspmCap`)
// ============================================================================

pub mod cspm_rights {
    pub const AUDIT_CONFIG: u32 = 1 << 0;
    pub const SCAN_DRIFT: u32 = 1 << 1;
    pub const REMEDIATE_DRIFT: u32 = 1 << 2;
    pub const MANAGE_BASELINES: u32 = 1 << 3;
    pub const CONFIGURE_RULES: u32 = 1 << 4;
    pub const READ_METRICS: u32 = 1 << 5;
    pub const SEAL_LEDGER: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;
    pub const ALL: u32 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspmError {
    PermissionDenied,
    AttenuationViolation,
    CapabilityExpired,
    BaselineNotFound,
    RuleNotFound,
    LedgerCorrupted,
    InvalidParameter,
    CapacityExceeded,
}

/// Capabilité CSPM avec atténuation monotone et expiration bornée
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CspmCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl CspmCap {
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

    #[inline]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        desired_rights: u32,
        desired_lifetime: u64,
        desired_invocations: u32,
    ) -> Result<Self, CspmError> {
        if (desired_rights & !self.rights) != 0 {
            return Err(CspmError::AttenuationViolation);
        }
        if desired_lifetime > self.max_lifetime {
            return Err(CspmError::AttenuationViolation);
        }
        if desired_invocations > self.invocations_left {
            return Err(CspmError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: desired_rights,
            max_lifetime: desired_lifetime,
            invocations_left: desired_invocations,
        })
    }
}

// ============================================================================
// STANDARDS DE SÉCURITÉ, SEVÉRITÉS & DOMAINES D'APPLICATION
// ============================================================================

/// Standards et référentiels de sécurité durcis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineStandard {
    CisMicrokernel,
    DisaStig,
    JamboSovereign,
    AnssiSecNumCloud,
}

impl BaselineStandard {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CisMicrokernel => "CIS-Microkernel",
            Self::DisaStig => "DISA-STIG",
            Self::JamboSovereign => "JamboOS-Sovereign",
            Self::AnssiSecNumCloud => "ANSSI-SecNumCloud",
        }
    }
}

/// Sévérité d'une règle et coefficient d'impact sur le risque
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RuleSeverity {
    pub fn weight(&self) -> u32 {
        match self {
            Self::Info => 1,
            Self::Low => 5,
            Self::Medium => 15,
            Self::High => 35,
            Self::Critical => 75,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Statut de conformité d'un paramètre
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    DriftDetected,
    Remediated,
    Suppressed,
}

impl ComplianceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compliant => "COMPLIANT",
            Self::DriftDetected => "DRIFT_DETECTED",
            Self::Remediated => "REMEDIATED",
            Self::Suppressed => "SUPPRESSED",
        }
    }
}

/// Périmètres de configuration du micro-noyau et de la grappe
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    KernelCore,
    HardwareTee,
    StorageVfs,
    NetworkL4,
    ProcessSandbox,
    AuditLedger,
    IdentityZeroTrust,
}

impl ConfigScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KernelCore => "kernel_core",
            Self::HardwareTee => "hardware_tee",
            Self::StorageVfs => "storage_vfs",
            Self::NetworkL4 => "network_l4",
            Self::ProcessSandbox => "process_sandbox",
            Self::AuditLedger => "audit_ledger",
            Self::IdentityZeroTrust => "identity_zt",
        }
    }
}

// ============================================================================
// STRUCTURES DE RÈGLES, ÉTATS DE CONFIGURATION & DÉTECTIONS DE DÉRIVE
// ============================================================================

/// Règle de conformité de sécurité (Baseline Rule)
#[derive(Clone, Copy)]
pub struct CspmRule {
    pub rule_id: u32,
    pub standard: BaselineStandard,
    pub scope: ConfigScope,
    pub name: [u8; 48],
    pub name_len: usize,
    pub parameter_key: [u8; 32],
    pub key_len: usize,
    pub expected_value: [u8; 32],
    pub expected_len: usize,
    pub severity: RuleSeverity,
    pub auto_remediate: bool,
}

impl CspmRule {
    pub fn new(
        rule_id: u32,
        standard: BaselineStandard,
        scope: ConfigScope,
        name_str: &str,
        key_str: &str,
        expected_str: &str,
        severity: RuleSeverity,
        auto_remediate: bool,
    ) -> Self {
        let mut name = [0u8; 48];
        let n_len = name_str.len().min(48);
        name[..n_len].copy_from_slice(&name_str.as_bytes()[..n_len]);

        let mut parameter_key = [0u8; 32];
        let k_len = key_str.len().min(32);
        parameter_key[..k_len].copy_from_slice(&key_str.as_bytes()[..k_len]);

        let mut expected_value = [0u8; 32];
        let e_len = expected_str.len().min(32);
        expected_value[..e_len].copy_from_slice(&expected_str.as_bytes()[..e_len]);

        Self {
            rule_id,
            standard,
            scope,
            name,
            name_len: n_len,
            parameter_key,
            key_len: k_len,
            expected_value,
            expected_len: e_len,
            severity,
            auto_remediate,
        }
    }

    pub fn key_matches(&self, key: &[u8]) -> bool {
        &self.parameter_key[..self.key_len] == key
    }

    pub fn value_matches(&self, val: &[u8]) -> bool {
        &self.expected_value[..self.expected_len] == val
    }
}

/// Élément de configuration actif surveillé
#[derive(Clone, Copy)]
pub struct ConfigItem {
    pub resource_id: u32,
    pub scope: ConfigScope,
    pub component: [u8; 32],
    pub comp_len: usize,
    pub parameter_key: [u8; 32],
    pub key_len: usize,
    pub current_value: [u8; 32],
    pub val_len: usize,
    pub status: ComplianceStatus,
    pub last_scan: u64,
    pub last_remediated: u64,
}

impl ConfigItem {
    pub fn new(
        resource_id: u32,
        scope: ConfigScope,
        comp_str: &str,
        key_str: &str,
        val_str: &str,
    ) -> Self {
        let mut component = [0u8; 32];
        let c_len = comp_str.len().min(32);
        component[..c_len].copy_from_slice(&comp_str.as_bytes()[..c_len]);

        let mut parameter_key = [0u8; 32];
        let k_len = key_str.len().min(32);
        parameter_key[..k_len].copy_from_slice(&key_str.as_bytes()[..k_len]);

        let mut current_value = [0u8; 32];
        let v_len = val_str.len().min(32);
        current_value[..v_len].copy_from_slice(&val_str.as_bytes()[..v_len]);

        Self {
            resource_id,
            scope,
            component,
            comp_len: c_len,
            parameter_key,
            key_len: k_len,
            current_value,
            val_len: v_len,
            status: ComplianceStatus::Compliant,
            last_scan: 0,
            last_remediated: 0,
        }
    }

    pub fn set_value(&mut self, val_str: &str) {
        let mut new_val = [0u8; 32];
        let len = val_str.len().min(32);
        new_val[..len].copy_from_slice(&val_str.as_bytes()[..len]);
        self.current_value = new_val;
        self.val_len = len;
    }
}

/// Rapport d'anomalie de dérive détectée
#[derive(Clone, Copy)]
pub struct DriftReport {
    pub rule_id: u32,
    pub resource_id: u32,
    pub scope: ConfigScope,
    pub severity: RuleSeverity,
    pub current_val: [u8; 32],
    pub current_len: usize,
    pub expected_val: [u8; 32],
    pub expected_len: usize,
    pub auto_remediated: bool,
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ PAR SHA-256
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspmAuditAction {
    BaselineRegistered,
    ScanExecuted,
    DriftDetected,
    AutonomousRemediation,
    ManualOverride,
    LedgerCheckpoint,
}

#[derive(Clone, Copy)]
pub struct CspmAuditEntry {
    pub entry_id: u64,
    pub timestamp: u64,
    pub action: CspmAuditAction,
    pub resource_id: u32,
    pub rule_id: u32,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

// ============================================================================
// DÉMON CENTRAL CSPM (`JamboCspmDaemon`)
// ============================================================================

pub struct JamboCspmDaemon {
    pub admin_cap: CspmCap,
    pub rules: [Option<CspmRule>; 32],
    pub rule_count: usize,
    pub items: [Option<ConfigItem>; 48],
    pub item_count: usize,
    pub drifts: [Option<DriftReport>; 32],
    pub drift_count: usize,
    pub ledger: [Option<CspmAuditEntry>; 32],
    pub ledger_len: usize,
    pub next_entry_id: u64,
    pub ledger_hash: [u8; 32],

    // Métriques globales de posture
    pub total_scans: u64,
    pub total_drifts_detected: u64,
    pub total_remediations: u64,
    pub current_posture_score: u32, // 0..100
    pub current_risk_index: u32,    // 0..1000
}

impl JamboCspmDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0x5A; 32];

    pub fn new(admin_cap: CspmCap) -> Self {
        Self {
            admin_cap,
            rules: [None; 32],
            rule_count: 0,
            items: [None; 48],
            item_count: 0,
            drifts: [None; 32],
            drift_count: 0,
            ledger: [None; 32],
            ledger_len: 0,
            next_entry_id: 1,
            ledger_hash: Self::GENESIS_HASH,
            total_scans: 0,
            total_drifts_detected: 0,
            total_remediations: 0,
            current_posture_score: 100,
            current_risk_index: 0,
        }
    }

    /// Enregistre une entrée dans le journal cryptographique chaîné
    fn record_audit(
        &mut self,
        timestamp: u64,
        action: CspmAuditAction,
        resource_id: u32,
        rule_id: u32,
    ) {
        let mut hasher = Sha256::new();
        hasher.update(&self.ledger_hash);
        hasher.update(&self.next_entry_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[action as u8]);
        hasher.update(&resource_id.to_be_bytes());
        hasher.update(&rule_id.to_be_bytes());
        let new_hash = hasher.finalize();

        let entry = CspmAuditEntry {
            entry_id: self.next_entry_id,
            timestamp,
            action,
            resource_id,
            rule_id,
            prev_hash: self.ledger_hash,
            entry_hash: new_hash,
        };

        let slot = (self.next_entry_id as usize - 1) % 32;
        self.ledger[slot] = Some(entry);
        if self.ledger_len < 32 {
            self.ledger_len += 1;
        }

        self.ledger_hash = new_hash;
        self.next_entry_id += 1;
    }

    /// Vérifie l'intégrité de la chaîne de hachage du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        if self.ledger_len == 0 {
            return self.ledger_hash == Self::GENESIS_HASH;
        }

        let mut expected_prev = Self::GENESIS_HASH;
        let start_id = if self.next_entry_id > 32 {
            self.next_entry_id - 32
        } else {
            1
        };

        for id in start_id..self.next_entry_id {
            let slot = ((id - 1) % 32) as usize;
            if let Some(entry) = self.ledger[slot] {
                if id == start_id && start_id > 1 {
                    expected_prev = entry.prev_hash;
                }
                if entry.prev_hash != expected_prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.prev_hash);
                hasher.update(&entry.entry_id.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&[entry.action as u8]);
                hasher.update(&entry.resource_id.to_be_bytes());
                hasher.update(&entry.rule_id.to_be_bytes());
                let computed = hasher.finalize();
                if computed != entry.entry_hash {
                    return false;
                }
                expected_prev = entry.entry_hash;
            } else {
                return false;
            }
        }

        expected_prev == self.ledger_hash
    }

    /// Ajoute une règle de conformité dans la base active
    pub fn add_rule(&mut self, cap: &CspmCap, rule: CspmRule) -> Result<(), CspmError> {
        if !cap.has_right(cspm_rights::MANAGE_BASELINES) {
            return Err(CspmError::PermissionDenied);
        }
        if self.rule_count >= 32 {
            return Err(CspmError::CapacityExceeded);
        }

        self.rules[self.rule_count] = Some(rule);
        self.rule_count += 1;
        self.record_audit(0, CspmAuditAction::BaselineRegistered, 0, rule.rule_id);
        Ok(())
    }

    /// Enregistre ou met à jour un élément de configuration dans l'inventaire
    pub fn set_config_item(
        &mut self,
        cap: &CspmCap,
        item: ConfigItem,
        timestamp: u64,
    ) -> Result<u32, CspmError> {
        if !cap.has_right(cspm_rights::CONFIGURE_RULES) && !cap.has_right(cspm_rights::ADMIN) {
            return Err(CspmError::PermissionDenied);
        }

        for i in 0..self.item_count {
            if let Some(ref mut existing) = self.items[i] {
                if existing.resource_id == item.resource_id {
                    existing.current_value = item.current_value;
                    existing.val_len = item.val_len;
                    existing.status = item.status;
                    existing.last_scan = timestamp;
                    self.record_audit(
                        timestamp,
                        CspmAuditAction::ManualOverride,
                        item.resource_id,
                        0,
                    );
                    return Ok(item.resource_id);
                }
            }
        }

        if self.item_count >= 48 {
            return Err(CspmError::CapacityExceeded);
        }

        let id = item.resource_id;
        self.items[self.item_count] = Some(item);
        self.item_count += 1;
        self.record_audit(timestamp, CspmAuditAction::ManualOverride, id, 0);
        Ok(id)
    }

    /// Initialise les baselines durcies souveraines par défaut
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. MMU SMEP & SMAP durci (CIS-Microkernel 1.1)
        let _ = self.add_rule(
            &cap,
            CspmRule::new(
                101,
                BaselineStandard::CisMicrokernel,
                ConfigScope::KernelCore,
                "MMU SMEP/SMAP Hardware Isolation",
                "kernel.mmu.smep_smap",
                "enabled",
                RuleSeverity::Critical,
                true,
            ),
        );

        // 2. W^X Enforcing strict (DISA STIG KRN-001)
        let _ = self.add_rule(
            &cap,
            CspmRule::new(
                102,
                BaselineStandard::DisaStig,
                ConfigScope::KernelCore,
                "Strict W^X Executable Page Lockdown",
                "kernel.mmu.wx_enforcement",
                "strict",
                RuleSeverity::Critical,
                true,
            ),
        );

        // 3. TEE Attestation PCR Quotes (ANSSI-SecNumCloud TEE-04)
        let _ = self.add_rule(
            &cap,
            CspmRule::new(
                103,
                BaselineStandard::AnssiSecNumCloud,
                ConfigScope::HardwareTee,
                "Hardware Enclave PCR Attestation",
                "tee.enclave.attestation",
                "pcr_quote_required",
                RuleSeverity::High,
                true,
            ),
        );

        // 4. VFS Zero Ambient Authority (JamboOS-Sovereign VFS-01)
        let _ = self.add_rule(
            &cap,
            CspmRule::new(
                104,
                BaselineStandard::JamboSovereign,
                ConfigScope::StorageVfs,
                "Zero Ambient Authority File System",
                "vfs.ambient_authority",
                "disabled",
                RuleSeverity::Critical,
                true,
            ),
        );

        // 5. Réseau Chiffré WireGuard Obrigatoire (ANSSI-SecNumCloud NET-02)
        let _ = self.add_rule(
            &cap,
            CspmRule::new(
                105,
                BaselineStandard::AnssiSecNumCloud,
                ConfigScope::NetworkL4,
                "Cluster Transport Cryptographic WireGuard",
                "net.traffic.encryption",
                "wireguard_chachapoly",
                RuleSeverity::High,
                true,
            ),
        );

        // 6. Seccomp / Confinement Sandboxing (CIS-Microkernel 3.4)
        let _ = self.add_rule(
            &cap,
            CspmRule::new(
                106,
                BaselineStandard::CisMicrokernel,
                ConfigScope::ProcessSandbox,
                "Seccomp Default Monotonic Filter",
                "proc.seccomp.default_action",
                "kill_thread",
                RuleSeverity::High,
                true,
            ),
        );

        // 7. Scellement Inaltérable Audit SHA-256 (DISA STIG AUD-009)
        let _ = self.add_rule(
            &cap,
            CspmRule::new(
                107,
                BaselineStandard::DisaStig,
                ConfigScope::AuditLedger,
                "Tamper-Evident SHA-256 Chained Logging",
                "audit.ledger.immutable_seal",
                "sha256_chained",
                RuleSeverity::Critical,
                true,
            ),
        );

        // 8. ZTNA Micro-Périmètres Continus (JamboOS-Sovereign ZT-01)
        let _ = self.add_rule(
            &cap,
            CspmRule::new(
                108,
                BaselineStandard::JamboSovereign,
                ConfigScope::IdentityZeroTrust,
                "Continuous Subsecond Posture Evaluation",
                "ztna.continuous_eval",
                "enforced_subsecond",
                RuleSeverity::Medium,
                false, // Nécessite validation manuelle
            ),
        );

        // Configuration d'inventaire initial
        // Items conformes
        let _ = self.set_config_item(
            &cap,
            ConfigItem::new(
                1,
                ConfigScope::KernelCore,
                "microkernel_mmu",
                "kernel.mmu.smep_smap",
                "enabled",
            ),
            100,
        );
        let _ = self.set_config_item(
            &cap,
            ConfigItem::new(
                3,
                ConfigScope::HardwareTee,
                "jambo_tee",
                "tee.enclave.attestation",
                "pcr_quote_required",
            ),
            100,
        );
        let _ = self.set_config_item(
            &cap,
            ConfigItem::new(
                4,
                ConfigScope::StorageVfs,
                "jambo_fs",
                "vfs.ambient_authority",
                "disabled",
            ),
            100,
        );
        let _ = self.set_config_item(
            &cap,
            ConfigItem::new(
                7,
                ConfigScope::AuditLedger,
                "jambo_auditd",
                "audit.ledger.immutable_seal",
                "sha256_chained",
            ),
            100,
        );

        // Items présentant une dérive (Drift) simulant une attaque ou une défaillance de déploiement
        let _ = self.set_config_item(
            &cap,
            ConfigItem::new(
                2,
                ConfigScope::KernelCore,
                "microkernel_mmu",
                "kernel.mmu.wx_enforcement",
                "permissive", // Dérive critique !
            ),
            100,
        );
        let _ = self.set_config_item(
            &cap,
            ConfigItem::new(
                5,
                ConfigScope::NetworkL4,
                "jambo_netd",
                "net.traffic.encryption",
                "plaintext_fallback", // Dérive High !
            ),
            100,
        );
        let _ = self.set_config_item(
            &cap,
            ConfigItem::new(
                6,
                ConfigScope::ProcessSandbox,
                "jambo_seccomp",
                "proc.seccomp.default_action",
                "allow_all", // Dérive High !
            ),
            100,
        );
        let _ = self.set_config_item(
            &cap,
            ConfigItem::new(
                8,
                ConfigScope::IdentityZeroTrust,
                "jambo_ztna",
                "ztna.continuous_eval",
                "disabled_bypass", // Dérive Medium !
            ),
            100,
        );
    }

    /// Exécute un audit continu de conformité et détecte les dérives (Configuration Drift)
    pub fn scan_drift(
        &mut self,
        cap: &CspmCap,
        timestamp: u64,
    ) -> Result<(usize, usize, u32, u32), CspmError> {
        if !cap.has_right(cspm_rights::SCAN_DRIFT) {
            return Err(CspmError::PermissionDenied);
        }

        self.drift_count = 0;
        let mut total_checked = 0usize;
        let mut total_weight = 0u32;
        let mut penalty_weight = 0u32;

        for i in 0..self.rule_count {
            if let Some(rule) = self.rules[i] {
                // Recherche de l'élément de configuration correspondant
                let mut found = false;
                let mut drift_detected: Option<(u32, [u8; 32], usize)> = None;

                for j in 0..self.item_count {
                    if let Some(ref mut item) = self.items[j] {
                        if rule.key_matches(&item.parameter_key[..item.key_len]) {
                            found = true;
                            total_checked += 1;
                            total_weight += rule.severity.weight();
                            item.last_scan = timestamp;

                            if rule.value_matches(&item.current_value[..item.val_len]) {
                                item.status = ComplianceStatus::Compliant;
                            } else {
                                // Dérive détectée !
                                item.status = ComplianceStatus::DriftDetected;
                                penalty_weight += rule.severity.weight();
                                drift_detected =
                                    Some((item.resource_id, item.current_value, item.val_len));
                            }
                            break;
                        }
                    }
                }

                if let Some((res_id, cur_val, cur_len)) = drift_detected {
                    if self.drift_count < 32 {
                        self.drifts[self.drift_count] = Some(DriftReport {
                            rule_id: rule.rule_id,
                            resource_id: res_id,
                            scope: rule.scope,
                            severity: rule.severity,
                            current_val: cur_val,
                            current_len: cur_len,
                            expected_val: rule.expected_value,
                            expected_len: rule.expected_len,
                            auto_remediated: false,
                        });
                        self.drift_count += 1;
                    }

                    self.total_drifts_detected += 1;
                    self.record_audit(
                        timestamp,
                        CspmAuditAction::DriftDetected,
                        res_id,
                        rule.rule_id,
                    );
                }

                if !found {
                    // Règle sans paramètre correspondant
                    total_weight += rule.severity.weight();
                    penalty_weight += rule.severity.weight();
                }
            }
        }

        self.total_scans += 1;

        // Calcul du score de posture (0..100) et de l'indice de risque (0..1000)
        let posture = if total_weight == 0 {
            100
        } else {
            let compliant_weight = total_weight.saturating_sub(penalty_weight);
            (compliant_weight * 100) / total_weight
        };

        let risk = if total_weight == 0 {
            0
        } else {
            (penalty_weight * 1000) / total_weight
        };

        self.current_posture_score = posture;
        self.current_risk_index = risk;

        self.record_audit(timestamp, CspmAuditAction::ScanExecuted, 0, 0);

        Ok((total_checked, self.drift_count, posture, risk))
    }

    /// Corrige de manière autonome une dérive de configuration identifiée
    pub fn remediate_drift(
        &mut self,
        cap: &CspmCap,
        rule_id: u32,
        timestamp: u64,
    ) -> Result<bool, CspmError> {
        if !cap.has_right(cspm_rights::REMEDIATE_DRIFT) {
            return Err(CspmError::PermissionDenied);
        }

        // Recherche de la règle
        let rule = self
            .rules
            .iter()
            .flatten()
            .find(|r| r.rule_id == rule_id)
            .copied()
            .ok_or(CspmError::RuleNotFound)?;

        let mut remediated_res_id: Option<u32> = None;

        for j in 0..self.item_count {
            if let Some(ref mut item) = self.items[j] {
                if rule.key_matches(&item.parameter_key[..item.key_len]) {
                    // Application de la valeur attendue par la baseline durcie
                    item.current_value = rule.expected_value;
                    item.val_len = rule.expected_len;
                    item.status = ComplianceStatus::Remediated;
                    item.last_remediated = timestamp;
                    remediated_res_id = Some(item.resource_id);
                    break;
                }
            }
        }

        if let Some(res_id) = remediated_res_id {
            self.total_remediations += 1;
            self.record_audit(
                timestamp,
                CspmAuditAction::AutonomousRemediation,
                res_id,
                rule.rule_id,
            );

            // Mettre à jour les drift reports
            for d in self.drifts.iter_mut().flatten() {
                if d.rule_id == rule_id {
                    d.auto_remediated = true;
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remédie automatiquement à toutes les dérives éligibles (auto_remediate == true)
    pub fn remediate_all_auto(
        &mut self,
        cap: &CspmCap,
        timestamp: u64,
    ) -> Result<usize, CspmError> {
        if !cap.has_right(cspm_rights::REMEDIATE_DRIFT) {
            return Err(CspmError::PermissionDenied);
        }

        let mut fixed_items = [0u32; 32];
        let mut fixed_rules = [0u32; 32];
        let mut fixed_count = 0usize;

        for i in 0..self.rule_count {
            if let Some(rule) = self.rules[i] {
                if rule.auto_remediate {
                    for j in 0..self.item_count {
                        if let Some(ref mut item) = self.items[j] {
                            if rule.key_matches(&item.parameter_key[..item.key_len])
                                && !rule.value_matches(&item.current_value[..item.val_len])
                            {
                                item.current_value = rule.expected_value;
                                item.val_len = rule.expected_len;
                                item.status = ComplianceStatus::Remediated;
                                item.last_remediated = timestamp;
                                if fixed_count < 32 {
                                    fixed_items[fixed_count] = item.resource_id;
                                    fixed_rules[fixed_count] = rule.rule_id;
                                    fixed_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        for k in 0..fixed_count {
            self.total_remediations += 1;
            self.record_audit(
                timestamp,
                CspmAuditAction::AutonomousRemediation,
                fixed_items[k],
                fixed_rules[k],
            );
        }

        // Recalcul de posture post-remédiation
        let _ = self.scan_drift(cap, timestamp)?;

        Ok(fixed_count)
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash_deterministic() {
        let mut hasher = Sha256::new();
        hasher.update(b"jambo-os-cspm-posture-audit");
        let hash = hasher.finalize();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_cap_rights_and_monotonic_attenuation() {
        let root_cap = CspmCap::new(Handle::new(12501, 1), cspm_rights::ALL, 10000, 500);
        assert!(root_cap.has_right(cspm_rights::SCAN_DRIFT));
        assert!(root_cap.has_right(cspm_rights::REMEDIATE_DRIFT));
        assert!(root_cap.has_right(cspm_rights::ADMIN));

        let auditor_cap = root_cap
            .attenuate(
                cspm_rights::AUDIT_CONFIG | cspm_rights::SCAN_DRIFT | cspm_rights::READ_METRICS,
                5000,
                100,
            )
            .expect("Atténuation monotone");

        assert!(auditor_cap.has_right(cspm_rights::SCAN_DRIFT));
        assert!(!auditor_cap.has_right(cspm_rights::REMEDIATE_DRIFT));
        assert!(!auditor_cap.has_right(cspm_rights::ADMIN));

        // Escalade illégale rejetée
        assert_eq!(
            auditor_cap.attenuate(cspm_rights::ALL, 5000, 100),
            Err(CspmError::AttenuationViolation)
        );
    }

    #[test]
    fn test_cspm_defaults_and_drift_detection() {
        let root_cap = CspmCap::new(Handle::new(12502, 1), cspm_rights::ALL, 10000, 500);
        let mut daemon = JamboCspmDaemon::new(root_cap);
        daemon.init_defaults();

        assert_eq!(daemon.rule_count, 8);
        assert_eq!(daemon.item_count, 8);

        // Premier scan : 4 conformes, 4 dérives configurées
        let (checked, drifts, posture, risk) = daemon
            .scan_drift(&root_cap, 1000)
            .expect("Scan CSPM initial");
        assert_eq!(checked, 8);
        assert_eq!(drifts, 4);
        assert!(posture <= 65); // Posture dégradée due aux 4 dérives critiques/hautes
        assert!(risk >= 350); // Risque élevé

        // Intégrité du ledger
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_cspm_autonomous_remediation_and_posture_recovery() {
        let root_cap = CspmCap::new(Handle::new(12503, 1), cspm_rights::ALL, 10000, 500);
        let mut daemon = JamboCspmDaemon::new(root_cap);
        daemon.init_defaults();

        let (_, initial_drifts, initial_posture, initial_risk) =
            daemon.scan_drift(&root_cap, 1000).unwrap();
        assert_eq!(initial_drifts, 4);

        // Remédiation autonome de toutes les règles auto (3 sur 4 le sont : W^X, Net, Seccomp)
        let remediated = daemon.remediate_all_auto(&root_cap, 2000).unwrap();
        assert_eq!(remediated, 3);

        // Posture après remédiation autonome
        assert!(daemon.current_posture_score > initial_posture);
        assert!(daemon.current_risk_index < initial_risk);
        assert_eq!(daemon.drift_count, 1); // Seul ZTNA persiste car auto_remediate = false

        // Remédiation ciblée pour la règle 108
        let r108 = daemon.remediate_drift(&root_cap, 108, 3000).unwrap();
        assert!(r108);

        // Rescan complet
        let (_, final_drifts, final_posture, final_risk) =
            daemon.scan_drift(&root_cap, 4000).unwrap();
        assert_eq!(final_drifts, 0);
        assert_eq!(final_posture, 100);
        assert_eq!(final_risk, 0);

        // Vérification de la chaîne d'audit inaltérable SHA-256
        assert!(daemon.verify_ledger_integrity());
    }
}

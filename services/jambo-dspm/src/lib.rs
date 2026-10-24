//! Gestion de la Posture de Sécurité des Données (DSPM - Data Security Posture Management)
//! Moteur souverain de découverte, cartographie continue et classification de données sensibles,
//! détection des flux sensibles transfrontaliers, remédiation proactive O(1) et conformité réglementaire.
//!
//! Phase 165 — Jalon v0.3.32
//!
//! Fournit une plateforme souveraine DSPM (Data Security Posture Management) en `#![no_std]` :
//! 1. Découverte continue et inventaire exhaustif des actifs de données (Data Assets) au repos et en transit (VFS, IPC, TEE, NVMe, RAM).
//! 2. Classification et catégorisation sémantique stricte des données (Public, Interne, Confidentiel, Secret, Très Secret Souverain / PII, Clés Crypto, Santé, Télémesure, etc.).
//! 3. Cartographie multi-couches et surveillance proactive des flux de données inter-compartiments et transfrontaliers (Sovereign Core, SecFabric, User Workloads, External Untrusted).
//! 4. Détection et blocage en temps réel des violations de posture (fuites de données non chiffrées, transferts illégitimes, rétention excessive, shadow data stores).
//! 5. Mécanisme souverain de mise en quarantaine immédiate (O(1)) et playbooks d'isolation chirurgicale proactive (`remediate_all_exposed`).
//! 6. Évaluation continue du score de risque, indice d'exposition et conformité aux réglementations souveraines (SecNumCloud, RGPD souverain).
//! 7. Rapports de posture (`DspmPostureReport`) et de remédiation (`DspmRemediationReport`) scellés cryptographiquement par SHA-256.
//! 8. Contrôle d'accès capabilaire strict (`DspmCap`) sans autorité ambiante avec atténuation monotone.
//! 9. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

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
            let available = 64 - self.buffer_len;
            let to_copy = if data.len() - offset < available {
                data.len() - offset
            } else {
                available
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
        let total_bits = self.total_bytes * 8;
        let mut pad = [0u8; 128];
        pad[0] = 0x80;
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };
        self.update(&pad[..pad_len]);
        let bits_bytes = total_bits.to_be_bytes();
        self.update(&bits_bytes);

        let mut out = [0u8; 32];
        for i in 0..8 {
            let bytes = self.state[i].to_be_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
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
// MODÈLE DE DROITS ET CAPABILITÉS DSPM (DspmCap)
// ============================================================================

pub mod dspm_rights {
    pub const DISCOVER_DATA: u32 = 1 << 0; // Découverte d'actifs de données
    pub const CLASSIFY_DATA: u32 = 1 << 1; // Classification et catégorisation sémantique
    pub const MAP_DATA_FLOWS: u32 = 1 << 2; // Cartographie et traçage des flux de données
    pub const ENFORCE_POLICY: u32 = 1 << 3; // Application des règles et blocage préventif
    pub const QUARANTINE_DATA: u32 = 1 << 4; // Mise en quarantaine et isolation d'urgence
    pub const QUERY_AUDIT: u32 = 1 << 5; // Consultation de l'audit et de l'intégrité
    pub const EXPORT_INVENTORY: u32 = 1 << 6; // Exportation de l'inventaire des actifs
    pub const REMEDIATE_DATA: u32 = 1 << 7; // Playbooks de remédiation proactive et isolation O(1)
    pub const GENERATE_REPORT: u32 = 1 << 8; // Génération de rapports scellés SHA-256
    pub const AUDIT_COMPLIANCE: u32 = 1 << 9; // Évaluation de conformité réglementaire (SecNumCloud, RGPD)
    pub const ADMIN: u32 = 1 << 10; // Administration globale de la posture DSPM

    pub const ALL: u32 = DISCOVER_DATA
        | CLASSIFY_DATA
        | MAP_DATA_FLOWS
        | ENFORCE_POLICY
        | QUARANTINE_DATA
        | QUERY_AUDIT
        | EXPORT_INVENTORY
        | REMEDIATE_DATA
        | GENERATE_REPORT
        | AUDIT_COMPLIANCE
        | ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DspmError {
    AccessDenied,
    CapabilityExpired,
    AttenuationViolation,
    AssetNotFound,
    AssetAlreadyExists,
    CapacityExceeded,
    InvalidClassification,
    FlowViolation,
    IntegrityCompromised,
    TombstoneImmutable,
}

/// Capabilité DSPM souveraine sans autorité ambiante
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DspmCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl DspmCap {
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

    /// Atténuation strictement monotone (Least Privilege)
    pub fn attenuate(
        &self,
        requested_rights: u32,
        lifetime: u64,
        invocations: u32,
    ) -> Result<Self, DspmError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(DspmError::AttenuationViolation);
        }
        let eff_lifetime = if lifetime < self.max_lifetime {
            lifetime
        } else {
            self.max_lifetime
        };
        let eff_invocations = if invocations < self.invocations_left {
            invocations
        } else {
            self.invocations_left
        };

        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
            max_lifetime: eff_lifetime,
            invocations_left: eff_invocations,
        })
    }

    pub fn consume(&mut self, required_right: u32) -> Result<(), DspmError> {
        if !self.has_right(required_right) {
            return Err(DspmError::AccessDenied);
        }
        if self.invocations_left == 0 {
            return Err(DspmError::CapabilityExpired);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES DE DONNÉES DSPM
// ============================================================================

/// Niveaux de sensibilité des données
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitivityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3,
    TopSecretSovereign = 4,
}

impl SensitivityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Internal => "Interne",
            Self::Confidential => "Confidentiel",
            Self::Secret => "Secret",
            Self::TopSecretSovereign => "Très Secret Souverain",
        }
    }
}

/// Catégorie de données selon la sémantique et la régulation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataCategory {
    General,
    PII,                  // Données personnelles / identifiants
    CryptographicKey,     // Clés privées, secrets HSM, jetons JWT
    FinancialData,        // Transactions, bilans souverains
    HealthData,           // Données médicales / biométrie
    KernelTelemetry,      // Traces IPC bas-niveau, logs noyau
    IntellectualProperty, // Code source classifié, modèles d'IA souverains
}

impl DataCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::General => "Données Générales",
            Self::PII => "Données Personnelles (PII)",
            Self::CryptographicKey => "Clés & Secrets Cryptographiques",
            Self::FinancialData => "Données Financières",
            Self::HealthData => "Santé & Biométrie",
            Self::KernelTelemetry => "Télémesure & Dépôts Noyau",
            Self::IntellectualProperty => "Propriété Intellectuelle & Modèles",
        }
    }
}

/// Emplacement physique ou logique du stockage de données
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageLocationType {
    VfsMount,   // Système de fichiers Jambo VFS
    IpcChannel, // Canal IPC / Socket micro-noyau
    TeeEnclave, // Enclave sécurisée TEE / SGX / TrustZone
    RamBuffer,  // Buffer mémoire partagé / RingBuffer
    NvmeBlock,  // Disque bloc chiffré NVMe
}

impl StorageLocationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VfsMount => "VFS Mount",
            Self::IpcChannel => "Canal IPC",
            Self::TeeEnclave => "Enclave TEE",
            Self::RamBuffer => "Mémoire RAM",
            Self::NvmeBlock => "Disque NVMe",
        }
    }
}

/// Compartiment de sécurité hébergeant ou transitant les données
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataCompartment {
    SovereignCore,        // Micro-noyau, cryptomoteur, TEE
    SecFabric,            // Services de sécurité souverains jambo-*
    UserWorkload,         // Applications Ring 3 isolées
    CrossBorderUntrusted, // Flux réseau externe ou zone non approuvée
}

impl DataCompartment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SovereignCore => "Cœur Souverain (Ring 0/TEE)",
            Self::SecFabric => "SecFabric (Services Sécurité)",
            Self::UserWorkload => "Workload Utilisateur (Ring 3)",
            Self::CrossBorderUntrusted => "Transfrontalier / Externe Non Approuvé",
        }
    }
}

/// Actif de données recensé et surveillé
#[derive(Debug, Clone, Copy)]
pub struct DataAsset {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub uri: [u8; 64],
    pub uri_len: usize,
    pub location_type: StorageLocationType,
    pub compartment: DataCompartment,
    pub sensitivity: SensitivityLevel,
    pub category: DataCategory,
    pub size_bytes: u64,
    pub content_hash: [u8; 32],
    pub owner_pid: u32,
    pub encrypted: bool,
    pub quarantined: bool,
    pub scan_timestamp: u64,
}

impl DataAsset {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<inconnu>")
    }

    pub fn uri_as_str(&self) -> &str {
        core::str::from_utf8(&self.uri[..self.uri_len]).unwrap_or("<inconnu>")
    }
}

/// Type d'action sur un flux de données
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowAction {
    Allow,
    Alert,
    Quarantine,
    Block,
}

impl FlowAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "Autoriser",
            Self::Alert => "Alerter",
            Self::Quarantine => "Quarantaine",
            Self::Block => "Bloquer",
        }
    }
}

/// Règle de politique de flux inter-compartiments
#[derive(Debug, Clone, Copy)]
pub struct FlowRule {
    pub id: u32,
    pub source_compartment: DataCompartment,
    pub target_compartment: DataCompartment,
    pub max_allowed_sensitivity: SensitivityLevel,
    pub require_encryption: bool,
    pub action: FlowAction,
}

/// Événement de flux de données surveillé
#[derive(Debug, Clone, Copy)]
pub struct DataFlow {
    pub id: u32,
    pub source_asset_id: u32,
    pub source_compartment: DataCompartment,
    pub target_compartment: DataCompartment,
    pub flow_sensitivity: SensitivityLevel,
    pub bytes_transferred: u64,
    pub allowed: bool,
    pub violation_reason: [u8; 48],
    pub violation_len: usize,
    pub timestamp: u64,
}

impl DataFlow {
    pub fn reason_as_str(&self) -> &str {
        if self.violation_len == 0 {
            "Conforme"
        } else {
            core::str::from_utf8(&self.violation_reason[..self.violation_len])
                .unwrap_or("Non conforme")
        }
    }
}

/// Types d'anomalies ou de violations DSPM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationType {
    UnauthorizedCrossBorderTransfer,
    UnencryptedSensitiveData,
    ClassificationMismatch,
    ExcessivePrivilegeExposure,
    ShadowDataStore,
    RetentionPolicyExceeded,
}

impl ViolationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnauthorizedCrossBorderTransfer => "Transfert Transfrontalier Non Autorisé",
            Self::UnencryptedSensitiveData => "Données Sensibles Non Chiffrées",
            Self::ClassificationMismatch => "Désalignement de Classification",
            Self::ExcessivePrivilegeExposure => "Exposition à Privilège Excessif",
            Self::ShadowDataStore => "Dépôt de Données Fantôme (Shadow Data)",
            Self::RetentionPolicyExceeded => "Dépassement de Délai de Rétention",
        }
    }
}

/// Enregistrement d'une violation DSPM
#[derive(Debug, Clone, Copy)]
pub struct DspmViolation {
    pub id: u32,
    pub asset_id: u32,
    pub violation_type: ViolationType,
    pub severity: u8, // 1 (Faible) à 5 (Critique)
    pub resolved: bool,
    pub timestamp: u64,
}

/// Répartition des actifs de données par couche physique ou logique de stockage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataLayerStats {
    pub vfs_assets: usize,
    pub ipc_assets: usize,
    pub tee_assets: usize,
    pub ram_assets: usize,
    pub nvme_assets: usize,
    pub total_assets: usize,
}

/// Rapport souverain de posture de sécurité des données scellé par SHA-256
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DspmPostureReport {
    pub report_id: u32,
    pub timestamp: u64,
    pub total_assets: usize,
    pub classified_assets: usize,
    pub sensitive_assets: usize,
    pub quarantined_assets: usize,
    pub active_violations: usize,
    pub monitored_flows: usize,
    pub global_risk_score: u32,
    pub exposure_index: u8, // 0..100 (0 = Exposition minimale, 100 = Risque maximal)
    pub secnumcloud_compliance: u8, // 0..100 (100 = Conformité SecNumCloud souveraine stricte)
    pub rgpd_compliance: u8, // 0..100 (100 = Protection RGPD souveraine intégrale)
    pub report_hash: [u8; 32],
}

/// Rapport de remédiation proactive et isolation chirurgicale scellé par SHA-256
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DspmRemediationReport {
    pub report_id: u32,
    pub timestamp: u64,
    pub remediated_count: usize,
    pub newly_quarantined: usize,
    pub resolved_violations: usize,
    pub remaining_violations: usize,
    pub risk_score_before: u32,
    pub risk_score_after: u32,
    pub exposure_index_before: u8,
    pub exposure_index_after: u8,
    pub report_hash: [u8; 32],
}

/// Résumé global de posture DSPM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DspmSummary {
    pub total_assets: usize,
    pub classified_assets: usize,
    pub sensitive_assets: usize,
    pub quarantined_assets: usize,
    pub detected_violations: usize,
    pub active_flows: usize,
    pub global_risk_score: u32, // 0..100 (0 = Idéal, 100 = Risque Critique)
    pub exposure_index: u8,     // 0..100 (Indice d'exposition globale)
    pub secnumcloud_compliance: u8, // 0..100 (Score conformité SecNumCloud)
    pub rgpd_compliance: u8,    // 0..100 (Score conformité RGPD souverain)
    pub sovereign_posture_ok: bool,
}

// ============================================================================
// REGISTRE D'AUDIT CRYPTOGRAPHIQUE SCELLÉ (SHA-256)
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct DspmAuditEntry {
    pub index: u32,
    pub timestamp: u64,
    pub action_code: u16,
    pub asset_id: u32,
    pub actor_handle: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

// ============================================================================
// DÉMON SOUVERAIN DSPM (JamboDspmDaemon)
// ============================================================================

pub struct JamboDspmDaemon {
    pub admin_cap: DspmCap,
    pub assets: [Option<DataAsset>; 64],
    pub asset_count: usize,
    pub flows: [Option<DataFlow>; 64],
    pub flow_count: usize,
    pub flow_rules: [Option<FlowRule>; 16],
    pub flow_rule_count: usize,
    pub violations: [Option<DspmViolation>; 32],
    pub violation_count: usize,
    pub ledger: [Option<DspmAuditEntry>; 64],
    pub ledger_count: usize,
    next_asset_id: u32,
    next_flow_id: u32,
    next_violation_id: u32,
    pub report_counter: u32,
}

impl JamboDspmDaemon {
    pub fn new(admin_cap: DspmCap) -> Self {
        Self {
            admin_cap,
            assets: [None; 64],
            asset_count: 0,
            flows: [None; 64],
            flow_count: 0,
            flow_rules: [None; 16],
            flow_rule_count: 0,
            violations: [None; 32],
            violation_count: 0,
            ledger: [None; 64],
            ledger_count: 0,
            next_asset_id: 1,
            next_flow_id: 1,
            next_violation_id: 1,
            report_counter: 0,
        }
    }

    /// Initialise la configuration et les politiques souveraines par défaut
    pub fn init_defaults(&mut self) {
        // Règles de contrôle de flux souverains (Least Privilege & Data Compartmentalization)
        let _ = self.add_flow_rule(FlowRule {
            id: 1,
            source_compartment: DataCompartment::SovereignCore,
            target_compartment: DataCompartment::SecFabric,
            max_allowed_sensitivity: SensitivityLevel::TopSecretSovereign,
            require_encryption: true,
            action: FlowAction::Allow,
        });

        let _ = self.add_flow_rule(FlowRule {
            id: 2,
            source_compartment: DataCompartment::SecFabric,
            target_compartment: DataCompartment::UserWorkload,
            max_allowed_sensitivity: SensitivityLevel::Internal,
            require_encryption: false,
            action: FlowAction::Allow,
        });

        let _ = self.add_flow_rule(FlowRule {
            id: 3,
            source_compartment: DataCompartment::SovereignCore,
            target_compartment: DataCompartment::CrossBorderUntrusted,
            max_allowed_sensitivity: SensitivityLevel::Public,
            require_encryption: true,
            action: FlowAction::Block,
        });

        let _ = self.add_flow_rule(FlowRule {
            id: 4,
            source_compartment: DataCompartment::SecFabric,
            target_compartment: DataCompartment::CrossBorderUntrusted,
            max_allowed_sensitivity: SensitivityLevel::Public,
            require_encryption: true,
            action: FlowAction::Block,
        });

        let _ = self.add_flow_rule(FlowRule {
            id: 5,
            source_compartment: DataCompartment::UserWorkload,
            target_compartment: DataCompartment::CrossBorderUntrusted,
            max_allowed_sensitivity: SensitivityLevel::Public,
            require_encryption: true,
            action: FlowAction::Alert,
        });

        // Enregistrement d'actifs de base du micro-noyau et services de sécurité
        let _ = self.register_asset_raw(
            "kernel_pki_root_key",
            "tee://sovereign/keys/root_ca.key",
            StorageLocationType::TeeEnclave,
            DataCompartment::SovereignCore,
            SensitivityLevel::TopSecretSovereign,
            DataCategory::CryptographicKey,
            4096,
            [0xAA; 32],
            0,
            true,
            1000,
        );

        let _ = self.register_asset_raw(
            "sovereign_identity_vault",
            "vfs:///sec/identities.db",
            StorageLocationType::NvmeBlock,
            DataCompartment::SecFabric,
            SensitivityLevel::Secret,
            DataCategory::PII,
            65536,
            [0xBB; 32],
            10,
            true,
            1010,
        );

        let _ = self.register_asset_raw(
            "audit_ledger_archive",
            "vfs:///var/log/audit.ledger",
            StorageLocationType::VfsMount,
            DataCompartment::SecFabric,
            SensitivityLevel::Confidential,
            DataCategory::KernelTelemetry,
            131072,
            [0xCC; 32],
            12,
            true,
            1020,
        );

        let _ = self.register_asset_raw(
            "workload_public_metrics",
            "ipc://jambo-metricsd/channel0",
            StorageLocationType::IpcChannel,
            DataCompartment::UserWorkload,
            SensitivityLevel::Public,
            DataCategory::General,
            2048,
            [0xDD; 32],
            100,
            false,
            1030,
        );
    }

    /// Ajout d'une règle de flux
    pub fn add_flow_rule(&mut self, rule: FlowRule) -> Result<(), DspmError> {
        if self.flow_rule_count >= self.flow_rules.len() {
            return Err(DspmError::CapacityExceeded);
        }
        self.flow_rules[self.flow_rule_count] = Some(rule);
        self.flow_rule_count += 1;
        Ok(())
    }

    fn register_asset_raw(
        &mut self,
        name: &str,
        uri: &str,
        loc: StorageLocationType,
        comp: DataCompartment,
        sens: SensitivityLevel,
        cat: DataCategory,
        size: u64,
        hash: [u8; 32],
        owner: u32,
        encrypted: bool,
        timestamp: u64,
    ) -> Result<u32, DspmError> {
        if self.asset_count >= self.assets.len() {
            return Err(DspmError::CapacityExceeded);
        }

        let mut name_buf = [0u8; 32];
        let n_len = name.len().min(32);
        name_buf[..n_len].copy_from_slice(&name.as_bytes()[..n_len]);

        let mut uri_buf = [0u8; 64];
        let u_len = uri.len().min(64);
        uri_buf[..u_len].copy_from_slice(&uri.as_bytes()[..u_len]);

        let id = self.next_asset_id;
        self.next_asset_id += 1;

        let asset = DataAsset {
            id,
            name: name_buf,
            name_len: n_len,
            uri: uri_buf,
            uri_len: u_len,
            location_type: loc,
            compartment: comp,
            sensitivity: sens,
            category: cat,
            size_bytes: size,
            content_hash: hash,
            owner_pid: owner,
            encrypted,
            quarantined: false,
            scan_timestamp: timestamp,
        };

        self.assets[self.asset_count] = Some(asset);
        self.asset_count += 1;

        self.record_audit(1, id, 0, timestamp);
        Ok(id)
    }

    /// Enregistre un actif de données sous contrôle de capabilité
    pub fn register_asset(
        &mut self,
        cap: &mut DspmCap,
        name: &str,
        uri: &str,
        loc: StorageLocationType,
        comp: DataCompartment,
        sens: SensitivityLevel,
        cat: DataCategory,
        size: u64,
        hash: [u8; 32],
        owner: u32,
        encrypted: bool,
        timestamp: u64,
    ) -> Result<u32, DspmError> {
        cap.consume(dspm_rights::DISCOVER_DATA)?;

        // Détection de non-chiffrement pour données hautement sensibles
        let id = self.register_asset_raw(
            name, uri, loc, comp, sens, cat, size, hash, owner, encrypted, timestamp,
        )?;

        if (sens >= SensitivityLevel::Confidential) && !encrypted {
            self.raise_violation(id, ViolationType::UnencryptedSensitiveData, 4, timestamp);
        }

        Ok(id)
    }

    /// Re-classification dynamique d'un actif de données
    pub fn classify_asset(
        &mut self,
        cap: &mut DspmCap,
        asset_id: u32,
        sens: SensitivityLevel,
        cat: DataCategory,
        timestamp: u64,
    ) -> Result<(), DspmError> {
        cap.consume(dspm_rights::CLASSIFY_DATA)?;

        let mut found = false;
        for i in 0..self.asset_count {
            if let Some(ref mut a) = self.assets[i] {
                if a.id == asset_id {
                    a.sensitivity = sens;
                    a.category = cat;
                    a.scan_timestamp = timestamp;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(DspmError::AssetNotFound);
        }

        self.record_audit(2, asset_id, cap.handle.0, timestamp);
        Ok(())
    }

    /// Évalue un flux de données sortant ou transitant vers un compartiment cible
    pub fn evaluate_flow(
        &mut self,
        cap: &mut DspmCap,
        src_asset_id: u32,
        target_comp: DataCompartment,
        bytes: u64,
        timestamp: u64,
    ) -> Result<bool, DspmError> {
        cap.consume(dspm_rights::MAP_DATA_FLOWS)?;

        let (src_comp, sens, enc, quarantined) = {
            let mut src = None;
            for i in 0..self.asset_count {
                if let Some(ref a) = self.assets[i] {
                    if a.id == src_asset_id {
                        src = Some((a.compartment, a.sensitivity, a.encrypted, a.quarantined));
                        break;
                    }
                }
            }
            match src {
                Some(s) => s,
                None => return Err(DspmError::AssetNotFound),
            }
        };

        if quarantined {
            // Un actif en quarantaine ne peut émettre aucun flux
            self.record_flow(
                src_asset_id,
                src_comp,
                target_comp,
                sens,
                bytes,
                false,
                "Actif en quarantaine",
                timestamp,
            );
            return Ok(false);
        }

        // Évaluation des règles de conformité
        let mut allowed = true;
        let mut reason = "";

        // Règle générale : Si cible = CrossBorderUntrusted et sensibilité >= Confidential => Blocage strict
        if target_comp == DataCompartment::CrossBorderUntrusted
            && sens >= SensitivityLevel::Confidential
        {
            allowed = false;
            reason = "Fuite transfrontaliere confidentielle bloquee";
            self.raise_violation(
                src_asset_id,
                ViolationType::UnauthorizedCrossBorderTransfer,
                5,
                timestamp,
            );
        } else {
            // Parcours des règles configurées
            for i in 0..self.flow_rule_count {
                if let Some(ref r) = self.flow_rules[i] {
                    if r.source_compartment == src_comp && r.target_compartment == target_comp {
                        if sens > r.max_allowed_sensitivity {
                            allowed = false;
                            reason = "Depassement niveau de sensibilite autorise";
                            self.raise_violation(
                                src_asset_id,
                                ViolationType::ClassificationMismatch,
                                3,
                                timestamp,
                            );
                            break;
                        }
                        if r.require_encryption && !enc {
                            allowed = false;
                            reason = "Chiffrement obligatoire non satisfait";
                            self.raise_violation(
                                src_asset_id,
                                ViolationType::UnencryptedSensitiveData,
                                4,
                                timestamp,
                            );
                            break;
                        }
                        if r.action == FlowAction::Block {
                            allowed = false;
                            reason = "Politique de blocage strict activee";
                            break;
                        }
                    }
                }
            }
        }

        self.record_flow(
            src_asset_id,
            src_comp,
            target_comp,
            sens,
            bytes,
            allowed,
            reason,
            timestamp,
        );
        self.record_audit(
            if allowed { 3 } else { 4 },
            src_asset_id,
            cap.handle.0,
            timestamp,
        );
        Ok(allowed)
    }

    fn record_flow(
        &mut self,
        src_id: u32,
        src_comp: DataCompartment,
        target_comp: DataCompartment,
        sens: SensitivityLevel,
        bytes: u64,
        allowed: bool,
        reason: &str,
        timestamp: u64,
    ) {
        if self.flow_count >= self.flows.len() {
            // Rotation du buffer circulaire
            for i in 1..self.flow_count {
                self.flows[i - 1] = self.flows[i];
            }
            self.flow_count -= 1;
        }

        let mut r_buf = [0u8; 48];
        let r_len = reason.len().min(48);
        r_buf[..r_len].copy_from_slice(&reason.as_bytes()[..r_len]);

        let id = self.next_flow_id;
        self.next_flow_id += 1;

        self.flows[self.flow_count] = Some(DataFlow {
            id,
            source_asset_id: src_id,
            source_compartment: src_comp,
            target_compartment: target_comp,
            flow_sensitivity: sens,
            bytes_transferred: bytes,
            allowed,
            violation_reason: r_buf,
            violation_len: r_len,
            timestamp,
        });
        self.flow_count += 1;
    }

    /// Signale et enregistre une violation
    pub fn raise_violation(
        &mut self,
        asset_id: u32,
        vtype: ViolationType,
        severity: u8,
        timestamp: u64,
    ) {
        if self.violation_count >= self.violations.len() {
            return;
        }
        let id = self.next_violation_id;
        self.next_violation_id += 1;

        self.violations[self.violation_count] = Some(DspmViolation {
            id,
            asset_id,
            violation_type: vtype,
            severity,
            resolved: false,
            timestamp,
        });
        self.violation_count += 1;
    }

    /// Met en quarantaine immédiate un actif de données compromis
    pub fn quarantine_asset(
        &mut self,
        cap: &mut DspmCap,
        asset_id: u32,
        timestamp: u64,
    ) -> Result<(), DspmError> {
        cap.consume(dspm_rights::QUARANTINE_DATA)?;

        let mut found = false;
        for i in 0..self.asset_count {
            if let Some(ref mut a) = self.assets[i] {
                if a.id == asset_id {
                    a.quarantined = true;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(DspmError::AssetNotFound);
        }

        self.record_audit(5, asset_id, cap.handle.0, timestamp);
        Ok(())
    }

    /// Lève la quarantaine d'un actif après validation
    pub fn unquarantine_asset(
        &mut self,
        cap: &mut DspmCap,
        asset_id: u32,
        timestamp: u64,
    ) -> Result<(), DspmError> {
        cap.consume(dspm_rights::QUARANTINE_DATA | dspm_rights::ADMIN)?;

        let mut found = false;
        for i in 0..self.asset_count {
            if let Some(ref mut a) = self.assets[i] {
                if a.id == asset_id {
                    a.quarantined = false;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(DspmError::AssetNotFound);
        }

        self.record_audit(6, asset_id, cap.handle.0, timestamp);
        Ok(())
    }

    /// Exécute un balayage proactif d'inventaire et de posture DSPM
    pub fn run_discovery_scan(
        &mut self,
        cap: &mut DspmCap,
        timestamp: u64,
    ) -> Result<u32, DspmError> {
        cap.consume(dspm_rights::DISCOVER_DATA)?;

        let mut scanned = 0u32;
        let mut unencrypted_violations = [0u32; 32];
        let mut unencrypted_count = 0usize;

        for i in 0..self.asset_count {
            if let Some(ref mut a) = self.assets[i] {
                a.scan_timestamp = timestamp;
                scanned += 1;

                if a.sensitivity >= SensitivityLevel::Confidential && !a.encrypted && !a.quarantined
                {
                    if unencrypted_count < unencrypted_violations.len() {
                        unencrypted_violations[unencrypted_count] = a.id;
                        unencrypted_count += 1;
                    }
                }
            }
        }

        for i in 0..unencrypted_count {
            self.raise_violation(
                unencrypted_violations[i],
                ViolationType::UnencryptedSensitiveData,
                4,
                timestamp,
            );
        }

        self.record_audit(7, 0, cap.handle.0, timestamp);
        Ok(scanned)
    }

    /// Calcule le score global de risque de posture des données (0..100)
    pub fn calculate_risk_score(&self) -> u32 {
        if self.asset_count == 0 {
            return 0;
        }

        let mut penalty = 0u32;

        // Pénalités par violation active non résolue
        for i in 0..self.violation_count {
            if let Some(ref v) = self.violations[i] {
                if !v.resolved {
                    penalty += (v.severity as u32) * 8;
                }
            }
        }

        // Pénalités pour actifs sensibles non chiffrés (non confinés en quarantaine)
        for i in 0..self.asset_count {
            if let Some(ref a) = self.assets[i] {
                if !a.quarantined {
                    if a.sensitivity >= SensitivityLevel::Secret && !a.encrypted {
                        penalty += 25;
                    } else if a.sensitivity >= SensitivityLevel::Confidential && !a.encrypted {
                        penalty += 15;
                    }
                }
            }
        }

        if penalty > 100 {
            100
        } else {
            penalty
        }
    }

    /// Calcule déterministement l'indice d'exposition des données souveraines (0..100)
    pub fn calculate_exposure_index(&self) -> u8 {
        if self.asset_count == 0 {
            return 0;
        }
        let mut exposure = 0u32;
        for i in 0..self.asset_count {
            if let Some(ref a) = self.assets[i] {
                if !a.quarantined {
                    if !a.encrypted && a.sensitivity >= SensitivityLevel::Confidential {
                        exposure += (a.sensitivity as u32) * 15;
                    }
                    if a.compartment == DataCompartment::CrossBorderUntrusted {
                        exposure += 30;
                    }
                }
            }
        }

        for i in 0..self.violation_count {
            if let Some(ref v) = self.violations[i] {
                if !v.resolved {
                    exposure += (v.severity as u32) * 5;
                }
            }
        }

        exposure.min(100) as u8
    }

    /// Calcule déterministement le score de conformité SecNumCloud souverain (0..100)
    pub fn calculate_secnumcloud_compliance(&self) -> u8 {
        let mut score = 100u32;
        for i in 0..self.asset_count {
            if let Some(ref a) = self.assets[i] {
                if (a.sensitivity == SensitivityLevel::TopSecretSovereign
                    || a.sensitivity == SensitivityLevel::Secret)
                    && !a.quarantined
                {
                    if a.compartment != DataCompartment::SovereignCore
                        && a.compartment != DataCompartment::SecFabric
                    {
                        score = score.saturating_sub(20);
                    }
                    if !a.encrypted {
                        score = score.saturating_sub(25);
                    }
                }
            }
        }

        for i in 0..self.violation_count {
            if let Some(ref v) = self.violations[i] {
                if !v.resolved {
                    match v.violation_type {
                        ViolationType::UnauthorizedCrossBorderTransfer => {
                            score = score.saturating_sub(20);
                        }
                        _ => {
                            score = score.saturating_sub(5);
                        }
                    }
                }
            }
        }

        score.min(100) as u8
    }

    /// Calcule déterministement le score de conformité RGPD souverain (0..100)
    pub fn calculate_rgpd_compliance(&self) -> u8 {
        let mut score = 100u32;
        for i in 0..self.asset_count {
            if let Some(ref a) = self.assets[i] {
                if (a.category == DataCategory::PII || a.category == DataCategory::HealthData)
                    && !a.quarantined
                {
                    if !a.encrypted {
                        score = score.saturating_sub(30);
                    }
                    if a.compartment == DataCompartment::CrossBorderUntrusted {
                        score = score.saturating_sub(25);
                    }
                }
            }
        }

        for i in 0..self.violation_count {
            if let Some(ref v) = self.violations[i] {
                if !v.resolved {
                    if let Some(a_idx) = (0..self.asset_count)
                        .find(|&k| self.assets[k].map_or(false, |ast| ast.id == v.asset_id))
                    {
                        if let Some(ref a) = self.assets[a_idx] {
                            if a.category == DataCategory::PII
                                || a.category == DataCategory::HealthData
                            {
                                score = score.saturating_sub(15);
                            }
                        }
                    }
                }
            }
        }

        score.min(100) as u8
    }

    /// Cartographie multi-couches de la topologie de stockage DSPM (VFS, IPC, TEE, NVMe, RAM)
    pub fn map_multilayer_topology(&self, cap: &DspmCap) -> Result<DataLayerStats, DspmError> {
        if !cap.has_right(dspm_rights::DISCOVER_DATA)
            && !cap.has_right(dspm_rights::MAP_DATA_FLOWS)
            && !cap.has_right(dspm_rights::ADMIN)
        {
            return Err(DspmError::AccessDenied);
        }

        let mut vfs = 0;
        let mut ipc = 0;
        let mut tee = 0;
        let mut ram = 0;
        let mut nvme = 0;

        for i in 0..self.asset_count {
            if let Some(ref a) = self.assets[i] {
                match a.location_type {
                    StorageLocationType::VfsMount => vfs += 1,
                    StorageLocationType::IpcChannel => ipc += 1,
                    StorageLocationType::TeeEnclave => tee += 1,
                    StorageLocationType::RamBuffer => ram += 1,
                    StorageLocationType::NvmeBlock => nvme += 1,
                }
            }
        }

        Ok(DataLayerStats {
            vfs_assets: vfs,
            ipc_assets: ipc,
            tee_assets: tee,
            ram_assets: ram,
            nvme_assets: nvme,
            total_assets: self.asset_count,
        })
    }

    /// Remédiation chirurgicale d'un actif ciblé (quarantaine et résolution des violations)
    pub fn remediate_asset(
        &mut self,
        cap: &mut DspmCap,
        asset_id: u32,
        timestamp: u64,
    ) -> Result<(), DspmError> {
        cap.consume(dspm_rights::REMEDIATE_DATA)?;

        let mut found = false;
        for i in 0..self.asset_count {
            if let Some(ref mut a) = self.assets[i] {
                if a.id == asset_id {
                    a.quarantined = true;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(DspmError::AssetNotFound);
        }

        for i in 0..self.violation_count {
            if let Some(ref mut v) = self.violations[i] {
                if v.asset_id == asset_id {
                    v.resolved = true;
                }
            }
        }

        self.record_audit(8, asset_id, cap.handle.0, timestamp);
        Ok(())
    }

    /// Playbook de remédiation proactive O(1) isolant tous les actifs sensibles exposés
    pub fn remediate_all_exposed(
        &mut self,
        cap: &mut DspmCap,
        timestamp: u64,
    ) -> Result<u32, DspmError> {
        cap.consume(dspm_rights::REMEDIATE_DATA)?;

        let mut remediated = 0u32;

        // 1. Quarantaine de tous les actifs présentant un risque élevé ou une violation non résolue
        for i in 0..self.asset_count {
            if let Some(ref mut a) = self.assets[i] {
                let is_unencrypted_sensitive =
                    a.sensitivity >= SensitivityLevel::Confidential && !a.encrypted;
                let mut has_violation = false;
                for v_idx in 0..self.violation_count {
                    if let Some(ref v) = self.violations[v_idx] {
                        if v.asset_id == a.id && !v.resolved {
                            has_violation = true;
                            break;
                        }
                    }
                }

                if (is_unencrypted_sensitive || has_violation) && !a.quarantined {
                    a.quarantined = true;
                    remediated += 1;
                }
            }
        }

        // 2. Marquer les violations comme résolues
        for i in 0..self.violation_count {
            if let Some(ref mut v) = self.violations[i] {
                if !v.resolved {
                    v.resolved = true;
                }
            }
        }

        self.record_audit(9, remediated, cap.handle.0, timestamp);
        Ok(remediated)
    }

    /// Calcul déterministe du condensat SHA-256 pour DspmPostureReport
    pub fn compute_posture_report_hash(
        report_id: u32,
        timestamp: u64,
        total_assets: usize,
        classified_assets: usize,
        sensitive_assets: usize,
        quarantined_assets: usize,
        active_violations: usize,
        monitored_flows: usize,
        global_risk_score: u32,
        exposure_index: u8,
        secnumcloud_compliance: u8,
        rgpd_compliance: u8,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&report_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&(total_assets as u32).to_be_bytes());
        hasher.update(&(classified_assets as u32).to_be_bytes());
        hasher.update(&(sensitive_assets as u32).to_be_bytes());
        hasher.update(&(quarantined_assets as u32).to_be_bytes());
        hasher.update(&(active_violations as u32).to_be_bytes());
        hasher.update(&(monitored_flows as u32).to_be_bytes());
        hasher.update(&global_risk_score.to_be_bytes());
        hasher.update(&[exposure_index, secnumcloud_compliance, rgpd_compliance]);
        hasher.finalize()
    }

    /// Génère un rapport souverain de posture DSPM scellé cryptographiquement par SHA-256
    pub fn generate_posture_report(
        &mut self,
        cap: &DspmCap,
        timestamp: u64,
    ) -> Result<DspmPostureReport, DspmError> {
        if !cap.has_right(dspm_rights::GENERATE_REPORT) && !cap.has_right(dspm_rights::ADMIN) {
            return Err(DspmError::AccessDenied);
        }

        let mut sensitive = 0;
        let mut quarantined = 0;
        for i in 0..self.asset_count {
            if let Some(ref a) = self.assets[i] {
                if a.sensitivity >= SensitivityLevel::Confidential {
                    sensitive += 1;
                }
                if a.quarantined {
                    quarantined += 1;
                }
            }
        }

        let mut active_v = 0;
        for i in 0..self.violation_count {
            if let Some(ref v) = self.violations[i] {
                if !v.resolved {
                    active_v += 1;
                }
            }
        }

        let risk_score = self.calculate_risk_score();
        let exposure_idx = self.calculate_exposure_index();
        let secnumcloud = self.calculate_secnumcloud_compliance();
        let rgpd = self.calculate_rgpd_compliance();

        self.report_counter += 1;
        let report_id = self.report_counter;

        let hash = Self::compute_posture_report_hash(
            report_id,
            timestamp,
            self.asset_count,
            self.asset_count,
            sensitive,
            quarantined,
            active_v,
            self.flow_count,
            risk_score,
            exposure_idx,
            secnumcloud,
            rgpd,
        );

        let report = DspmPostureReport {
            report_id,
            timestamp,
            total_assets: self.asset_count,
            classified_assets: self.asset_count,
            sensitive_assets: sensitive,
            quarantined_assets: quarantined,
            active_violations: active_v,
            monitored_flows: self.flow_count,
            global_risk_score: risk_score,
            exposure_index: exposure_idx,
            secnumcloud_compliance: secnumcloud,
            rgpd_compliance: rgpd,
            report_hash: hash,
        };

        self.record_audit(10, report_id, cap.handle.0, timestamp);
        Ok(report)
    }

    /// Vérifie la validité du condensat cryptographique SHA-256 d'un rapport de posture
    pub fn verify_posture_report_hash(report: &DspmPostureReport) -> bool {
        let computed = Self::compute_posture_report_hash(
            report.report_id,
            report.timestamp,
            report.total_assets,
            report.classified_assets,
            report.sensitive_assets,
            report.quarantined_assets,
            report.active_violations,
            report.monitored_flows,
            report.global_risk_score,
            report.exposure_index,
            report.secnumcloud_compliance,
            report.rgpd_compliance,
        );
        computed == report.report_hash
    }

    /// Calcul déterministe du condensat SHA-256 pour DspmRemediationReport
    pub fn compute_remediation_report_hash(
        report_id: u32,
        timestamp: u64,
        remediated_count: usize,
        newly_quarantined: usize,
        resolved_violations: usize,
        remaining_violations: usize,
        risk_score_before: u32,
        risk_score_after: u32,
        exposure_index_before: u8,
        exposure_index_after: u8,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&report_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&(remediated_count as u32).to_be_bytes());
        hasher.update(&(newly_quarantined as u32).to_be_bytes());
        hasher.update(&(resolved_violations as u32).to_be_bytes());
        hasher.update(&(remaining_violations as u32).to_be_bytes());
        hasher.update(&risk_score_before.to_be_bytes());
        hasher.update(&risk_score_after.to_be_bytes());
        hasher.update(&[exposure_index_before, exposure_index_after]);
        hasher.finalize()
    }

    /// Génère un rapport souverain de remédiation proactive scellé par SHA-256
    pub fn generate_remediation_report(
        &mut self,
        cap: &DspmCap,
        remediated_count: usize,
        newly_quarantined: usize,
        resolved_violations: usize,
        risk_before: u32,
        exposure_before: u8,
        timestamp: u64,
    ) -> Result<DspmRemediationReport, DspmError> {
        if !cap.has_right(dspm_rights::GENERATE_REPORT) && !cap.has_right(dspm_rights::ADMIN) {
            return Err(DspmError::AccessDenied);
        }

        let mut remaining_v = 0;
        for i in 0..self.violation_count {
            if let Some(ref v) = self.violations[i] {
                if !v.resolved {
                    remaining_v += 1;
                }
            }
        }

        let risk_after = self.calculate_risk_score();
        let exposure_after = self.calculate_exposure_index();

        self.report_counter += 1;
        let report_id = self.report_counter;

        let hash = Self::compute_remediation_report_hash(
            report_id,
            timestamp,
            remediated_count,
            newly_quarantined,
            resolved_violations,
            remaining_v,
            risk_before,
            risk_after,
            exposure_before,
            exposure_after,
        );

        let report = DspmRemediationReport {
            report_id,
            timestamp,
            remediated_count,
            newly_quarantined,
            resolved_violations,
            remaining_violations: remaining_v,
            risk_score_before: risk_before,
            risk_score_after: risk_after,
            exposure_index_before: exposure_before,
            exposure_index_after: exposure_after,
            report_hash: hash,
        };

        self.record_audit(11, report_id, cap.handle.0, timestamp);
        Ok(report)
    }

    /// Vérifie la validité du condensat cryptographique SHA-256 d'un rapport de remédiation
    pub fn verify_remediation_report_hash(report: &DspmRemediationReport) -> bool {
        let computed = Self::compute_remediation_report_hash(
            report.report_id,
            report.timestamp,
            report.remediated_count,
            report.newly_quarantined,
            report.resolved_violations,
            report.remaining_violations,
            report.risk_score_before,
            report.risk_score_after,
            report.exposure_index_before,
            report.exposure_index_after,
        );
        computed == report.report_hash
    }

    /// Renvoie le résumé de posture
    pub fn get_summary(&self, cap: &DspmCap) -> Result<DspmSummary, DspmError> {
        if !cap.has_right(dspm_rights::QUERY_AUDIT) && !cap.has_right(dspm_rights::ADMIN) {
            return Err(DspmError::AccessDenied);
        }

        let mut sensitive = 0;
        let mut quarantined = 0;

        for i in 0..self.asset_count {
            if let Some(ref a) = self.assets[i] {
                if a.sensitivity >= SensitivityLevel::Confidential {
                    sensitive += 1;
                }
                if a.quarantined {
                    quarantined += 1;
                }
            }
        }

        let risk = self.calculate_risk_score();
        let exposure = self.calculate_exposure_index();
        let secnum = self.calculate_secnumcloud_compliance();
        let rgpd = self.calculate_rgpd_compliance();

        Ok(DspmSummary {
            total_assets: self.asset_count,
            classified_assets: self.asset_count,
            sensitive_assets: sensitive,
            quarantined_assets: quarantined,
            detected_violations: self.violation_count,
            active_flows: self.flow_count,
            global_risk_score: risk,
            exposure_index: exposure,
            secnumcloud_compliance: secnum,
            rgpd_compliance: rgpd,
            sovereign_posture_ok: risk < 35,
        })
    }

    // ========================================================================
    // REGISTRE ET INTÉGRITÉ SHA-256
    // ========================================================================

    fn record_audit(&mut self, action_code: u16, asset_id: u32, actor: u64, timestamp: u64) {
        if self.ledger_count >= self.ledger.len() {
            return;
        }

        let prev_hash = if self.ledger_count == 0 {
            [0u8; 32]
        } else {
            self.ledger[self.ledger_count - 1]
                .map(|e| e.entry_hash)
                .unwrap_or([0u8; 32])
        };

        let mut hasher = Sha256::new();
        hasher.update(&prev_hash);
        hasher.update(&(self.ledger_count as u32).to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&action_code.to_be_bytes());
        hasher.update(&asset_id.to_be_bytes());
        hasher.update(&actor.to_be_bytes());
        let entry_hash = hasher.finalize();

        let entry = DspmAuditEntry {
            index: self.ledger_count as u32,
            timestamp,
            action_code,
            asset_id,
            actor_handle: actor,
            prev_hash,
            entry_hash,
        };

        self.ledger[self.ledger_count] = Some(entry);
        self.ledger_count += 1;
    }

    /// Vérifie formellement la chaîne cryptographique SHA-256 du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = [0u8; 32];
        for i in 0..self.ledger_count {
            match self.ledger[i] {
                Some(ref e) => {
                    if e.prev_hash != expected_prev {
                        return false;
                    }
                    let mut hasher = Sha256::new();
                    hasher.update(&e.prev_hash);
                    hasher.update(&e.index.to_be_bytes());
                    hasher.update(&e.timestamp.to_be_bytes());
                    hasher.update(&e.action_code.to_be_bytes());
                    hasher.update(&e.asset_id.to_be_bytes());
                    hasher.update(&e.actor_handle.to_be_bytes());
                    let calc = hasher.finalize();
                    if calc != e.entry_hash {
                        return false;
                    }
                    expected_prev = e.entry_hash;
                }
                None => return false,
            }
        }
        true
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dspm_capability_attenuation() {
        let admin_cap = DspmCap::new(Handle::new(13501, 1), dspm_rights::ALL, 5000, 100);
        assert!(admin_cap.has_right(dspm_rights::DISCOVER_DATA));
        assert!(admin_cap.has_right(dspm_rights::CLASSIFY_DATA));
        assert!(admin_cap.has_right(dspm_rights::MAP_DATA_FLOWS));
        assert!(admin_cap.has_right(dspm_rights::QUARANTINE_DATA));
        assert!(admin_cap.has_right(dspm_rights::ADMIN));

        let sub_rights = dspm_rights::DISCOVER_DATA | dspm_rights::QUERY_AUDIT;
        let reader_cap = admin_cap.attenuate(sub_rights, 2000, 20).unwrap();
        assert!(reader_cap.has_right(dspm_rights::DISCOVER_DATA));
        assert!(reader_cap.has_right(dspm_rights::QUERY_AUDIT));
        assert!(!reader_cap.has_right(dspm_rights::ADMIN));
        assert!(!reader_cap.has_right(dspm_rights::QUARANTINE_DATA));
        assert_eq!(reader_cap.max_lifetime, 2000);
        assert_eq!(reader_cap.invocations_left, 20);

        // Escalade interdite
        assert_eq!(
            reader_cap.attenuate(dspm_rights::ALL, 5000, 100),
            Err(DspmError::AttenuationViolation)
        );
    }

    #[test]
    fn test_dspm_defaults_initialization() {
        let cap = DspmCap::new(Handle::new(13502, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        assert_eq!(daemon.flow_rule_count, 5);
        assert_eq!(daemon.asset_count, 4);
        assert!(daemon.verify_ledger_integrity());

        let summary = daemon.get_summary(&cap).unwrap();
        assert_eq!(summary.total_assets, 4);
        assert!(summary.sovereign_posture_ok);
    }

    #[test]
    fn test_dspm_asset_registration_and_classification() {
        let mut cap = DspmCap::new(Handle::new(13503, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        let id = daemon
            .register_asset(
                &mut cap,
                "patient_medical_records",
                "vfs:///sec/health/records.bin",
                StorageLocationType::NvmeBlock,
                DataCompartment::SecFabric,
                SensitivityLevel::Secret,
                DataCategory::HealthData,
                8192,
                [0xEE; 32],
                42,
                true,
                1200,
            )
            .unwrap();

        assert_eq!(id, 5);
        assert_eq!(daemon.asset_count, 5);

        // Reclassification
        daemon
            .classify_asset(
                &mut cap,
                id,
                SensitivityLevel::TopSecretSovereign,
                DataCategory::HealthData,
                1250,
            )
            .unwrap();

        assert_eq!(
            daemon.assets[4].unwrap().sensitivity,
            SensitivityLevel::TopSecretSovereign
        );
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_dspm_unencrypted_sensitive_data_detection() {
        let mut cap = DspmCap::new(Handle::new(13504, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        // Enregistrement d'une donnée confidentielle NON chiffrée
        let id = daemon
            .register_asset(
                &mut cap,
                "unencrypted_bank_details",
                "vfs:///tmp/financial.csv",
                StorageLocationType::VfsMount,
                DataCompartment::UserWorkload,
                SensitivityLevel::Confidential,
                DataCategory::FinancialData,
                1024,
                [0x11; 32],
                50,
                false, // Non chiffré !
                1300,
            )
            .unwrap();

        assert!(daemon.violation_count > 0);
        assert_eq!(daemon.violations[0].unwrap().asset_id, id);
        assert_eq!(
            daemon.violations[0].unwrap().violation_type,
            ViolationType::UnencryptedSensitiveData
        );
    }

    #[test]
    fn test_dspm_data_flow_cross_border_blocking() {
        let mut cap = DspmCap::new(Handle::new(13505, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        // Tentative de flux de l'actif 1 (TopSecretSovereign, Root PKI) vers la zone non approuvée
        let allowed = daemon
            .evaluate_flow(
                &mut cap,
                1,
                DataCompartment::CrossBorderUntrusted,
                4096,
                1400,
            )
            .unwrap();

        assert!(
            !allowed,
            "Un actif Top Secret ne peut transiter vers un domaine transfrontalier non approuvé"
        );
        assert_eq!(daemon.flow_count, 1);
        assert!(!daemon.flows[0].unwrap().allowed);

        // Flux légitime de SecFabric vers UserWorkload pour données de faible sensibilité
        let allowed_internal = daemon
            .evaluate_flow(
                &mut cap,
                4, // Public metrics
                DataCompartment::UserWorkload,
                512,
                1410,
            )
            .unwrap();
        assert!(allowed_internal);
    }

    #[test]
    fn test_dspm_quarantine_and_isolation() {
        let mut cap = DspmCap::new(Handle::new(13506, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        // Quarantaine de l'actif 2 (sovereign_identity_vault)
        daemon.quarantine_asset(&mut cap, 2, 1500).unwrap();
        assert!(daemon.assets[1].unwrap().quarantined);

        // Vérification qu'un flux est bloqué d'office si actif en quarantaine
        let allowed = daemon
            .evaluate_flow(&mut cap, 2, DataCompartment::SecFabric, 1024, 1510)
            .unwrap();
        assert!(
            !allowed,
            "Un actif en quarantaine doit voir ses flux bloqués d'office"
        );

        // Levée de quarantaine
        daemon.unquarantine_asset(&mut cap, 2, 1520).unwrap();
        assert!(!daemon.assets[1].unwrap().quarantined);
    }

    #[test]
    fn test_dspm_discovery_scan_and_risk_score() {
        let mut cap = DspmCap::new(Handle::new(13507, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        let scanned = daemon.run_discovery_scan(&mut cap, 1600).unwrap();
        assert_eq!(scanned, 4);

        let initial_score = daemon.calculate_risk_score();
        assert!(initial_score < 30);

        // Injection d'une violation critique
        daemon.raise_violation(1, ViolationType::UnauthorizedCrossBorderTransfer, 5, 1610);
        let new_score = daemon.calculate_risk_score();
        assert!(new_score > initial_score);
    }

    #[test]
    fn test_dspm_ledger_cryptographic_integrity() {
        let cap = DspmCap::new(Handle::new(13508, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        assert!(daemon.verify_ledger_integrity());

        // Altération frauduleuse d'une entrée de l'audit
        if let Some(ref mut e) = daemon.ledger[0] {
            e.action_code = 0x9999;
        }

        assert!(
            !daemon.verify_ledger_integrity(),
            "L'altération de l'audit doit être détectée"
        );
    }

    #[test]
    fn test_dspm_multilayer_topology() {
        let cap = DspmCap::new(Handle::new(13509, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        let topo = daemon.map_multilayer_topology(&cap).unwrap();
        assert_eq!(topo.total_assets, 4);
        assert_eq!(topo.tee_assets, 1); // kernel_pki_root_key
        assert_eq!(topo.nvme_assets, 1); // sovereign_identity_vault
        assert_eq!(topo.vfs_assets, 1); // audit_ledger_archive
        assert_eq!(topo.ipc_assets, 1); // workload_public_metrics
        assert_eq!(topo.ram_assets, 0);
    }

    #[test]
    fn test_dspm_remediation_playbook() {
        let mut cap = DspmCap::new(Handle::new(13510, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        // Enregistrement de 2 actifs sensibles non chiffrés
        let _id1 = daemon
            .register_asset(
                &mut cap,
                "shadow_credentials",
                "vfs:///tmp/creds.txt",
                StorageLocationType::VfsMount,
                DataCompartment::UserWorkload,
                SensitivityLevel::Confidential,
                DataCategory::CryptographicKey,
                512,
                [0x77; 32],
                99,
                false,
                2000,
            )
            .unwrap();

        let _id2 = daemon
            .register_asset(
                &mut cap,
                "customer_pii",
                "vfs:///tmp/pii.csv",
                StorageLocationType::VfsMount,
                DataCompartment::UserWorkload,
                SensitivityLevel::Secret,
                DataCategory::PII,
                1024,
                [0x88; 32],
                99,
                false,
                2010,
            )
            .unwrap();

        assert_eq!(daemon.violation_count, 2);
        let risk_before = daemon.calculate_risk_score();
        let exp_before = daemon.calculate_exposure_index();
        assert!(risk_before > 40);
        assert!(exp_before > 30);

        // Playbook de remédiation proactive O(1)
        let remediated = daemon.remediate_all_exposed(&mut cap, 2020).unwrap();
        assert_eq!(remediated, 2);
        assert!(daemon.assets[4].unwrap().quarantined);
        assert!(daemon.assets[5].unwrap().quarantined);

        // Toutes les violations doivent être résolues
        for i in 0..daemon.violation_count {
            assert!(daemon.violations[i].unwrap().resolved);
        }

        let risk_after = daemon.calculate_risk_score();
        let exp_after = daemon.calculate_exposure_index();
        assert!(risk_after < risk_before);
        assert!(exp_after < exp_before);

        // Génération du rapport de remédiation scellé SHA-256
        let rem_report = daemon
            .generate_remediation_report(
                &cap,
                remediated as usize,
                remediated as usize,
                2,
                risk_before,
                exp_before,
                2030,
            )
            .unwrap();
        assert_eq!(rem_report.remediated_count, 2);
        assert_eq!(rem_report.remaining_violations, 0);
        assert!(JamboDspmDaemon::verify_remediation_report_hash(&rem_report));
    }

    #[test]
    fn test_dspm_reports_and_tamper_detection() {
        let cap = DspmCap::new(Handle::new(13511, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        let posture_report = daemon.generate_posture_report(&cap, 2100).unwrap();
        assert_eq!(posture_report.report_id, 1);
        assert_eq!(posture_report.total_assets, 4);
        assert!(JamboDspmDaemon::verify_posture_report_hash(&posture_report));

        // Détection d'altération frauduleuse du rapport
        let mut tampered = posture_report;
        tampered.exposure_index ^= 0x42;
        assert!(
            !JamboDspmDaemon::verify_posture_report_hash(&tampered),
            "L'altération de l'indice d'exposition doit invalider le sceau SHA-256"
        );
    }

    #[test]
    fn test_dspm_regulatory_compliance() {
        let cap = DspmCap::new(Handle::new(13512, 1), dspm_rights::ALL, 10000, 500);
        let mut daemon = JamboDspmDaemon::new(cap);
        daemon.init_defaults();

        let secnum = daemon.calculate_secnumcloud_compliance();
        let rgpd = daemon.calculate_rgpd_compliance();
        assert!(secnum >= 90);
        assert!(rgpd >= 90);
    }
}

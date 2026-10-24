//! Évaluation Continue des Risques Fournisseurs & Dépendances Tierces (`jambo-tprm`)
//!
//! Phase 139 — Jalon v0.3.6
//!
//! Fournit une plateforme souveraine de gestion des risques tiers (Third-Party Risk Management - TPRM) en `#![no_std]` :
//! 1. Cartographie et inventaire des dépendances amont (Crates, bibliothèques C, modules Wasm, firmwares).
//! 2. Scoring dynamique multidimensionnel de réputation et de criticité des fournisseurs tiers.
//! 3. Surveillance continue des flux d'ingestion et barrière d'admission stricte.
//! 4. Vérification et validation des attestations de conformité tierces (SecNumCloud, SovereignDefense, ISO 27001, SOC 2).
//! 5. Détection proactive de facteurs de risque toxiques (scripts de build malveillants, typosquatting, CVE non corrigées, télémétrie occulte).
//! 6. Politique d'isolation et de quarantaine automatique instantanée O(1) des composants amont compromis.
//! 7. Contrôle d'accès capabilaire (`TprmCap`) avec atténuation monotone stricte.
//! 8. Registre d'audit SHA-256 inviolable scellé par chaînage cryptographique.

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
// CONTRÔLE D'ACCÈS CAPABILAIRE (TprmCap)
// ============================================================================

pub mod tprm_rights {
    pub const REGISTER_VENDOR: u32 = 0x0001;
    pub const MAP_DEPENDENCY: u32 = 0x0002;
    pub const EVALUATE_RISK: u32 = 0x0004;
    pub const VERIFY_COMPLIANCE: u32 = 0x0008;
    pub const INGESTION_GATE: u32 = 0x0010;
    pub const QUARANTINE_ACTION: u32 = 0x0020;
    pub const QUERY_AUDIT: u32 = 0x0040;
    pub const ADMIN: u32 = 0x0080;

    pub const ALL: u32 = REGISTER_VENDOR
        | MAP_DEPENDENCY
        | EVALUATE_RISK
        | VERIFY_COMPLIANCE
        | INGESTION_GATE
        | QUARANTINE_ACTION
        | QUERY_AUDIT
        | ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TprmError {
    AccessDenied,
    CapabilityExpired,
    AttenuationViolation,
    VendorNotFound,
    VendorAlreadyExists,
    CapacityExceeded,
    DependencyNotFound,
    DependencyAlreadyExists,
    ComplianceCertificationMissing,
    ToxicRiskFactorDetected,
    ReputationTooLow,
    IngestionRejected,
    IntegrityCompromised,
    InvalidParameter,
}

/// Capabilité TPRM souveraine sans autorité ambiante
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TprmCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl TprmCap {
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

    pub fn consume(&mut self) -> Result<(), TprmError> {
        if self.invocations_left == 0 {
            return Err(TprmError::CapabilityExpired);
        }
        self.invocations_left -= 1;
        Ok(())
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, TprmError> {
        if (new_rights & !self.rights) != 0 {
            return Err(TprmError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(TprmError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(TprmError::AttenuationViolation);
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
// MODÈLE DE DONNÉES TPRM & RISQUES FOURNISSEURS SOUVERAINS
// ============================================================================

pub const MAX_VENDORS: usize = 32;
pub const MAX_DEPENDENCIES: usize = 32;
pub const MAX_ATTESTATIONS: usize = 32;
pub const MAX_EVALUATIONS: usize = 32;
pub const MAX_LEDGER_ENTRIES: usize = 64;

/// Niveau de criticité / Tier du fournisseur tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VendorTier {
    Tier1SovereignCore = 1,      // Fondations critiques souveraines
    Tier2HighAssurance = 2,      // Fournisseurs certifiés haute assurance
    Tier3StandardEcosystem = 3,  // Écosystème tiers standard
    Tier4UntrustedCommunity = 4, // Paquets / sources non vérifiées
}

/// Standard de conformité et de certification d'audit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStandard {
    None,
    SecNumCloud,
    SovereignDefense,
    ISO27001,
    SOC2Type2,
}

/// Statut opérationnel d'un fournisseur tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorStatus {
    Active,
    UnderReview,
    Restricted,
    Quarantined,
    Revoked,
}

/// Type de composant / dépendance logicielle ou matérielle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyType {
    RustCrate,
    CSharedLib,
    WasmModule,
    HardwareFirmware,
    ContainerImage,
}

/// Facteur de risque toxique amont détecté
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToxicRiskFactor {
    None,
    MaliciousBuildScript,
    TyposquattingSuspect,
    UnknownMaintainer,
    CriticalCveUnpatched,
    BackdoorTelemetry,
    OutdatedCrypto,
}

/// Décision d'admission / ingestion du composant tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestionDecision {
    Approved,
    ConditionalSandbox,
    Quarantined,
    Rejected,
}

/// Descripteur de Fournisseur Tiers (Vendor)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorDescriptor {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub tier: VendorTier,
    pub reputation_score: u8,     // 0..100 (plus élevé = plus fiable)
    pub composite_risk_score: u8, // 0..100 (plus faible = moins de risque)
    pub active_dependencies_count: u32,
    pub compliance_certified: bool,
    pub status: VendorStatus,
    pub registered_at: u64,
    pub last_evaluated_at: u64,
}

impl VendorDescriptor {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }
}

/// Descripteur d'Artéfact / Dépendance Tierce
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyArtifact {
    pub id: u32,
    pub vendor_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub version_code: u32,
    pub dep_type: DependencyType,
    pub checksum: [u8; 32],
    pub cve_critical_count: u8,
    pub cve_high_count: u8,
    pub risk_factor: ToxicRiskFactor,
    pub is_quarantined: bool,
    pub ingested_at: u64,
}

impl DependencyArtifact {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }
}

/// Attestation de conformité délivrée par un auditeur tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThirdPartyAttestation {
    pub id: u32,
    pub vendor_id: u32,
    pub standard: ComplianceStandard,
    pub auditor_id: [u8; 32],
    pub auditor_id_len: usize,
    pub certificate_hash: [u8; 32],
    pub valid_until: u64,
    pub is_verified: bool,
}

impl ThirdPartyAttestation {
    pub fn auditor_as_str(&self) -> &str {
        core::str::from_utf8(&self.auditor_id[..self.auditor_id_len]).unwrap_or("<invalide>")
    }
}

/// Évaluation d'ingestion d'une dépendance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestionEvaluation {
    pub id: u32,
    pub dependency_id: u32,
    pub decision: IngestionDecision,
    pub risk_score: u8,
    pub isolation_required: bool,
    pub evaluated_at: u64,
}

/// Entrée du registre d'audit cryptographique SHA-256
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TprmLedgerEntry {
    pub entry_id: u32,
    pub timestamp: u64,
    pub action_code: u16,
    pub target_id: u32,
    pub status_code: u16,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

/// Synthèse globale de l'état TPRM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TprmSummary {
    pub total_vendors: usize,
    pub total_dependencies: usize,
    pub quarantined_dependencies: usize,
    pub verified_attestations: usize,
    pub average_reputation_score: u8,
    pub high_risk_vendors_count: usize,
    pub global_supply_chain_health: u8,
}

// ============================================================================
// DÉMON TPRM SOUVERAIN (JamboTprmDaemon)
// ============================================================================

pub struct JamboTprmDaemon {
    pub admin_cap: TprmCap,
    pub vendors: [Option<VendorDescriptor>; MAX_VENDORS],
    pub vendor_count: usize,
    pub dependencies: [Option<DependencyArtifact>; MAX_DEPENDENCIES],
    pub dependency_count: usize,
    pub attestations: [Option<ThirdPartyAttestation>; MAX_ATTESTATIONS],
    pub attestation_count: usize,
    pub evaluations: [Option<IngestionEvaluation>; MAX_EVALUATIONS],
    pub evaluation_count: usize,
    pub ledger: [Option<TprmLedgerEntry>; MAX_LEDGER_ENTRIES],
    pub ledger_count: usize,
    last_entry_hash: [u8; 32],
}

impl JamboTprmDaemon {
    pub fn new(admin_cap: TprmCap) -> Self {
        Self {
            admin_cap,
            vendors: [None; MAX_VENDORS],
            vendor_count: 0,
            dependencies: [None; MAX_DEPENDENCIES],
            dependency_count: 0,
            attestations: [None; MAX_ATTESTATIONS],
            attestation_count: 0,
            evaluations: [None; MAX_EVALUATIONS],
            evaluation_count: 0,
            ledger: [None; MAX_LEDGER_ENTRIES],
            ledger_count: 0,
            last_entry_hash: [0u8; 32],
        }
    }

    /// Initialise la configuration et les enregistrements souverains par défaut
    pub fn init_defaults(&mut self) {
        let mut cap = self.admin_cap;

        // 1. Enregistrement des fournisseurs de référence
        let _ = self.register_vendor(
            &mut cap,
            1,
            "Sovereign-Crypto-Foundry",
            VendorTier::Tier1SovereignCore,
            98,
            true,
            1000,
        );

        let _ = self.register_vendor(
            &mut cap,
            2,
            "Rust-Embedded-Labs",
            VendorTier::Tier2HighAssurance,
            92,
            true,
            1010,
        );

        let _ = self.register_vendor(
            &mut cap,
            3,
            "Community-Network-Ecosystem",
            VendorTier::Tier3StandardEcosystem,
            75,
            true,
            1020,
        );

        let _ = self.register_vendor(
            &mut cap,
            4,
            "Shadow-Telemetry-Vendor",
            VendorTier::Tier4UntrustedCommunity,
            28,
            false,
            1030,
        );

        // 2. Attestations de conformité
        let _ = self.record_attestation(
            &mut cap,
            1,
            1,
            ComplianceStandard::SecNumCloud,
            "ANSSI-Audit-Lab",
            &[0xA1; 32],
            200_000,
            1050,
        );

        let _ = self.record_attestation(
            &mut cap,
            2,
            2,
            ComplianceStandard::ISO27001,
            "BSI-Global-Cert",
            &[0xB2; 32],
            180_000,
            1060,
        );

        let _ = self.record_attestation(
            &mut cap,
            3,
            3,
            ComplianceStandard::SOC2Type2,
            "CloudTrust-Assurance",
            &[0xC3; 32],
            150_000,
            1070,
        );

        // 3. Cartographie et ingestion de dépendances amont
        let _ = self.map_dependency(
            &mut cap,
            1,
            1,
            "libcrypto-pqc-fast",
            30200, // 3.2.0
            DependencyType::RustCrate,
            &[0x11; 32],
            0,
            0,
            ToxicRiskFactor::None,
            1100,
        );

        let _ = self.map_dependency(
            &mut cap,
            2,
            2,
            "virtio-hal-sovereign",
            10800, // 1.8.0
            DependencyType::RustCrate,
            &[0x22; 32],
            0,
            0,
            ToxicRiskFactor::None,
            1110,
        );

        let _ = self.map_dependency(
            &mut cap,
            3,
            3,
            "fast-http-parser",
            20104, // 2.1.4
            DependencyType::CSharedLib,
            &[0x33; 32],
            0,
            1, // 1 high CVE
            ToxicRiskFactor::None,
            1120,
        );

        let _ = self.map_dependency(
            &mut cap,
            4,
            4,
            "ad-analytics-telemetry",
            50001, // 5.0.1
            DependencyType::WasmModule,
            &[0x44; 32],
            2, // 2 critical CVEs
            3, // 3 high CVEs
            ToxicRiskFactor::BackdoorTelemetry,
            1130,
        );

        // 4. Évaluations d'admission automatiques des dépendances
        let _ = self.evaluate_ingestion(&mut cap, 1, 1200);
        let _ = self.evaluate_ingestion(&mut cap, 2, 1210);
        let _ = self.evaluate_ingestion(&mut cap, 3, 1220);
        let _ = self.evaluate_ingestion(&mut cap, 4, 1230);
    }

    /// Enregistre un nouveau fournisseur tiers dans le catalogue souverain
    pub fn register_vendor(
        &mut self,
        cap: &mut TprmCap,
        id: u32,
        name: &str,
        tier: VendorTier,
        reputation_score: u8,
        compliance_certified: bool,
        timestamp: u64,
    ) -> Result<u32, TprmError> {
        if !cap.has_right(tprm_rights::REGISTER_VENDOR) {
            return Err(TprmError::AccessDenied);
        }
        cap.consume()?;

        if self.find_vendor(id).is_some() {
            return Err(TprmError::VendorAlreadyExists);
        }

        let mut name_buf = [0u8; 32];
        let copy_len = name.len().min(32);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        // Calcul initial du composite risk score
        let composite_risk =
            Self::compute_vendor_risk(tier, reputation_score, compliance_certified, 0, 0);

        let vendor = VendorDescriptor {
            id,
            name: name_buf,
            name_len: copy_len,
            tier,
            reputation_score: reputation_score.min(100),
            composite_risk_score: composite_risk,
            active_dependencies_count: 0,
            compliance_certified,
            status: if reputation_score < 40 {
                VendorStatus::Restricted
            } else {
                VendorStatus::Active
            },
            registered_at: timestamp,
            last_evaluated_at: timestamp,
        };

        for slot in self.vendors.iter_mut() {
            if slot.is_none() {
                *slot = Some(vendor);
                self.vendor_count += 1;
                self.append_ledger(timestamp, 0x0101, id, 0x0000);
                return Ok(id);
            }
        }

        Err(TprmError::CapacityExceeded)
    }

    /// Cartographie une nouvelle dépendance logicielle ou matérielle rattachée à un fournisseur
    pub fn map_dependency(
        &mut self,
        cap: &mut TprmCap,
        id: u32,
        vendor_id: u32,
        name: &str,
        version_code: u32,
        dep_type: DependencyType,
        checksum: &[u8; 32],
        cve_critical_count: u8,
        cve_high_count: u8,
        risk_factor: ToxicRiskFactor,
        timestamp: u64,
    ) -> Result<u32, TprmError> {
        if !cap.has_right(tprm_rights::MAP_DEPENDENCY) {
            return Err(TprmError::AccessDenied);
        }
        cap.consume()?;

        if self.find_dependency(id).is_some() {
            return Err(TprmError::DependencyAlreadyExists);
        }

        if self.find_vendor(vendor_id).is_none() {
            return Err(TprmError::VendorNotFound);
        }

        let mut name_buf = [0u8; 32];
        let copy_len = name.len().min(32);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        let is_quarantined = risk_factor != ToxicRiskFactor::None || cve_critical_count > 0;

        let artifact = DependencyArtifact {
            id,
            vendor_id,
            name: name_buf,
            name_len: copy_len,
            version_code,
            dep_type,
            checksum: *checksum,
            cve_critical_count,
            cve_high_count,
            risk_factor,
            is_quarantined,
            ingested_at: timestamp,
        };

        for slot in self.dependencies.iter_mut() {
            if slot.is_none() {
                *slot = Some(artifact);
                self.dependency_count += 1;

                // Mettre à jour le compteur du fournisseur et son score de risque
                self.update_vendor_dependency_stats(vendor_id, timestamp);

                self.append_ledger(
                    timestamp,
                    0x0102,
                    id,
                    if is_quarantined { 0x0001 } else { 0x0000 },
                );
                return Ok(id);
            }
        }

        Err(TprmError::CapacityExceeded)
    }

    /// Enregistre une attestation de conformité tierce pour un fournisseur
    pub fn record_attestation(
        &mut self,
        cap: &mut TprmCap,
        id: u32,
        vendor_id: u32,
        standard: ComplianceStandard,
        auditor_id: &str,
        cert_hash: &[u8; 32],
        valid_until: u64,
        timestamp: u64,
    ) -> Result<u32, TprmError> {
        if !cap.has_right(tprm_rights::VERIFY_COMPLIANCE) {
            return Err(TprmError::AccessDenied);
        }
        cap.consume()?;

        if self.find_vendor(vendor_id).is_none() {
            return Err(TprmError::VendorNotFound);
        }

        let mut auditor_buf = [0u8; 32];
        let copy_len = auditor_id.len().min(32);
        auditor_buf[..copy_len].copy_from_slice(&auditor_id.as_bytes()[..copy_len]);

        let is_verified = valid_until > timestamp;

        let attestation = ThirdPartyAttestation {
            id,
            vendor_id,
            standard,
            auditor_id: auditor_buf,
            auditor_id_len: copy_len,
            certificate_hash: *cert_hash,
            valid_until,
            is_verified,
        };

        for slot in self.attestations.iter_mut() {
            if slot.is_none() {
                *slot = Some(attestation);
                self.attestation_count += 1;

                if is_verified {
                    if let Some(vendor) = self.find_vendor_mut(vendor_id) {
                        vendor.compliance_certified = true;
                    }
                }

                self.append_ledger(
                    timestamp,
                    0x0103,
                    id,
                    if is_verified { 0x0000 } else { 0x0002 },
                );
                return Ok(id);
            }
        }

        Err(TprmError::CapacityExceeded)
    }

    /// Évalue l'ingestion d'une dépendance et applique les règles de barrière d'admission souveraine
    pub fn evaluate_ingestion(
        &mut self,
        cap: &mut TprmCap,
        dependency_id: u32,
        timestamp: u64,
    ) -> Result<IngestionDecision, TprmError> {
        if !cap.has_right(tprm_rights::INGESTION_GATE) {
            return Err(TprmError::AccessDenied);
        }
        cap.consume()?;

        let dep = self
            .find_dependency(dependency_id)
            .ok_or(TprmError::DependencyNotFound)?;
        let vendor = self
            .find_vendor(dep.vendor_id)
            .ok_or(TprmError::VendorNotFound)?;

        // Évaluation multi-critères
        let mut risk_score: u16 = vendor.composite_risk_score as u16;

        // Pénalités de sécurité
        if dep.cve_critical_count > 0 {
            risk_score += (dep.cve_critical_count as u16) * 35;
        }
        if dep.cve_high_count > 0 {
            risk_score += (dep.cve_high_count as u16) * 15;
        }

        let has_toxic_risk = dep.risk_factor != ToxicRiskFactor::None;
        if has_toxic_risk {
            risk_score += 60;
        }

        let bounded_risk = risk_score.min(100) as u8;

        let (decision, isolation_required) = if has_toxic_risk
            || dep.cve_critical_count > 0
            || vendor.status == VendorStatus::Quarantined
        {
            (IngestionDecision::Quarantined, true)
        } else if bounded_risk > 70 || vendor.tier == VendorTier::Tier4UntrustedCommunity {
            (IngestionDecision::Rejected, false)
        } else if bounded_risk > 30
            || dep.cve_high_count > 0
            || dep.dep_type == DependencyType::CSharedLib
        {
            (IngestionDecision::ConditionalSandbox, true)
        } else {
            (IngestionDecision::Approved, false)
        };

        // Si la décision est Quarantined, appliquer immédiatement la mise en quarantaine
        if decision == IngestionDecision::Quarantined {
            if let Some(d) = self.find_dependency_mut(dependency_id) {
                d.is_quarantined = true;
            }
        }

        let eval_id = (self.evaluation_count as u32) + 1;
        let evaluation = IngestionEvaluation {
            id: eval_id,
            dependency_id,
            decision,
            risk_score: bounded_risk,
            isolation_required,
            evaluated_at: timestamp,
        };

        // Mettre à jour ou ajouter l'évaluation
        let mut added = false;
        for slot in self.evaluations.iter_mut() {
            if let Some(existing) = slot {
                if existing.dependency_id == dependency_id {
                    *existing = evaluation;
                    added = true;
                    break;
                }
            } else if slot.is_none() {
                *slot = Some(evaluation);
                self.evaluation_count += 1;
                added = true;
                break;
            }
        }

        if !added {
            return Err(TprmError::CapacityExceeded);
        }

        self.append_ledger(
            timestamp,
            0x0104,
            dependency_id,
            match decision {
                IngestionDecision::Approved => 0x0000,
                IngestionDecision::ConditionalSandbox => 0x0001,
                IngestionDecision::Quarantined => 0x0002,
                IngestionDecision::Rejected => 0x0003,
            },
        );

        Ok(decision)
    }

    /// Mise en quarantaine instantanée O(1) d'une dépendance compromise
    pub fn quarantine_dependency(
        &mut self,
        cap: &mut TprmCap,
        dependency_id: u32,
        timestamp: u64,
    ) -> Result<(), TprmError> {
        if !cap.has_right(tprm_rights::QUARANTINE_ACTION) {
            return Err(TprmError::AccessDenied);
        }
        cap.consume()?;

        let dep = self
            .find_dependency_mut(dependency_id)
            .ok_or(TprmError::DependencyNotFound)?;
        dep.is_quarantined = true;

        let vendor_id = dep.vendor_id;

        // Mise à jour de l'évaluation correspondante
        for slot in self.evaluations.iter_mut().flatten() {
            if slot.dependency_id == dependency_id {
                slot.decision = IngestionDecision::Quarantined;
                slot.isolation_required = true;
                slot.risk_score = slot.risk_score.max(85);
            }
        }

        self.update_vendor_dependency_stats(vendor_id, timestamp);
        self.append_ledger(timestamp, 0x0105, dependency_id, 0x0000);
        Ok(())
    }

    /// Mise en quarantaine instantanée O(1) d'un fournisseur compromis et de tous ses composants
    pub fn quarantine_vendor(
        &mut self,
        cap: &mut TprmCap,
        vendor_id: u32,
        timestamp: u64,
    ) -> Result<(), TprmError> {
        if !cap.has_right(tprm_rights::QUARANTINE_ACTION) {
            return Err(TprmError::AccessDenied);
        }
        cap.consume()?;

        let vendor = self
            .find_vendor_mut(vendor_id)
            .ok_or(TprmError::VendorNotFound)?;
        vendor.status = VendorStatus::Quarantined;
        vendor.composite_risk_score = 99;
        vendor.last_evaluated_at = timestamp;

        // Quarantaine de toutes les dépendances issues de ce fournisseur
        let mut dep_ids = [0u32; MAX_DEPENDENCIES];
        let mut dep_count = 0usize;
        for slot in self.dependencies.iter_mut().flatten() {
            if slot.vendor_id == vendor_id {
                slot.is_quarantined = true;
                if dep_count < MAX_DEPENDENCIES {
                    dep_ids[dep_count] = slot.id;
                    dep_count += 1;
                }
            }
        }

        for slot in self.evaluations.iter_mut().flatten() {
            for &did in &dep_ids[..dep_count] {
                if slot.dependency_id == did {
                    slot.decision = IngestionDecision::Quarantined;
                    slot.isolation_required = true;
                    slot.risk_score = 99;
                    break;
                }
            }
        }

        self.append_ledger(timestamp, 0x0106, vendor_id, 0x0000);
        Ok(())
    }

    /// Calcule le score de risque composite d'un fournisseur
    fn compute_vendor_risk(
        tier: VendorTier,
        reputation: u8,
        certified: bool,
        critical_cves: u32,
        toxic_factors: u32,
    ) -> u8 {
        let base_risk: u16 = match tier {
            VendorTier::Tier1SovereignCore => 5,
            VendorTier::Tier2HighAssurance => 15,
            VendorTier::Tier3StandardEcosystem => 35,
            VendorTier::Tier4UntrustedCommunity => 65,
        };

        let reputation_penalty = (100 - reputation.min(100)) as u16 / 3;
        let cert_bonus: u16 = if certified { 0 } else { 15 };
        let cve_penalty = (critical_cves.min(5) as u16) * 15;
        let toxic_penalty = (toxic_factors.min(3) as u16) * 25;

        let total = base_risk + reputation_penalty + cert_bonus + cve_penalty + toxic_penalty;
        total.min(100) as u8
    }

    /// Met à jour les statistiques de dépendances et le risque du fournisseur
    fn update_vendor_dependency_stats(&mut self, vendor_id: u32, timestamp: u64) {
        let mut count = 0u32;
        let mut critical_cves = 0u32;
        let mut toxic_count = 0u32;

        for dep in self.dependencies.iter().flatten() {
            if dep.vendor_id == vendor_id {
                count += 1;
                critical_cves += dep.cve_critical_count as u32;
                if dep.risk_factor != ToxicRiskFactor::None {
                    toxic_count += 1;
                }
            }
        }

        if let Some(vendor) = self.find_vendor_mut(vendor_id) {
            vendor.active_dependencies_count = count;
            vendor.composite_risk_score = Self::compute_vendor_risk(
                vendor.tier,
                vendor.reputation_score,
                vendor.compliance_certified,
                critical_cves,
                toxic_count,
            );
            vendor.last_evaluated_at = timestamp;
        }
    }

    /// Génère la synthèse globale TPRM
    pub fn get_summary(&self, cap: &TprmCap) -> Result<TprmSummary, TprmError> {
        if !cap.has_right(tprm_rights::QUERY_AUDIT) {
            return Err(TprmError::AccessDenied);
        }

        let mut total_reputation = 0u32;
        let mut high_risk_vendors = 0usize;
        let active_vendors = self.vendor_count;

        for v in self.vendors.iter().flatten() {
            total_reputation += v.reputation_score as u32;
            if v.composite_risk_score > 60 || v.status == VendorStatus::Quarantined {
                high_risk_vendors += 1;
            }
        }

        let avg_reputation = if active_vendors > 0 {
            (total_reputation / active_vendors as u32) as u8
        } else {
            0
        };

        let mut quarantined_deps = 0usize;
        for d in self.dependencies.iter().flatten() {
            if d.is_quarantined {
                quarantined_deps += 1;
            }
        }

        let mut verified_certs = 0usize;
        for a in self.attestations.iter().flatten() {
            if a.is_verified {
                verified_certs += 1;
            }
        }

        // Calcul de la santé globale de la supply-chain (0..100)
        let total_deps = self.dependency_count;
        let health = if total_deps > 0 {
            let safe_deps = total_deps.saturating_sub(quarantined_deps);
            let dep_ratio = (safe_deps * 60) / total_deps;
            let rep_ratio = (avg_reputation as usize * 40) / 100;
            (dep_ratio + rep_ratio).min(100) as u8
        } else {
            avg_reputation
        };

        Ok(TprmSummary {
            total_vendors: self.vendor_count,
            total_dependencies: self.dependency_count,
            quarantined_dependencies: quarantined_deps,
            verified_attestations: verified_certs,
            average_reputation_score: avg_reputation,
            high_risk_vendors_count: high_risk_vendors,
            global_supply_chain_health: health,
        })
    }

    /// Vérifie l'intégrité cryptographique SHA-256 du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = [0u8; 32];

        for i in 0..self.ledger_count {
            if let Some(ref entry) = self.ledger[i] {
                if entry.prev_hash != expected_prev {
                    return false;
                }

                let mut hasher = Sha256::new();
                hasher.update(&entry.entry_id.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.action_code.to_be_bytes());
                hasher.update(&entry.target_id.to_be_bytes());
                hasher.update(&entry.status_code.to_be_bytes());
                hasher.update(&entry.prev_hash);

                let computed_hash = hasher.finalize();
                if computed_hash != entry.entry_hash {
                    return false;
                }

                expected_prev = entry.entry_hash;
            } else {
                return false;
            }
        }

        true
    }

    /// Ajoute une entrée dans le registre d'audit avec scellement SHA-256
    fn append_ledger(
        &mut self,
        timestamp: u64,
        action_code: u16,
        target_id: u32,
        status_code: u16,
    ) {
        if self.ledger_count >= MAX_LEDGER_ENTRIES {
            return;
        }

        let entry_id = (self.ledger_count as u32) + 1;
        let prev_hash = self.last_entry_hash;

        let mut hasher = Sha256::new();
        hasher.update(&entry_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&action_code.to_be_bytes());
        hasher.update(&target_id.to_be_bytes());
        hasher.update(&status_code.to_be_bytes());
        hasher.update(&prev_hash);

        let entry_hash = hasher.finalize();
        self.last_entry_hash = entry_hash;

        let entry = TprmLedgerEntry {
            entry_id,
            timestamp,
            action_code,
            target_id,
            status_code,
            prev_hash,
            entry_hash,
        };

        self.ledger[self.ledger_count] = Some(entry);
        self.ledger_count += 1;
    }

    pub fn find_vendor(&self, id: u32) -> Option<&VendorDescriptor> {
        self.vendors.iter().flatten().find(|v| v.id == id)
    }

    pub fn find_vendor_mut(&mut self, id: u32) -> Option<&mut VendorDescriptor> {
        self.vendors.iter_mut().flatten().find(|v| v.id == id)
    }

    pub fn find_dependency(&self, id: u32) -> Option<&DependencyArtifact> {
        self.dependencies.iter().flatten().find(|d| d.id == id)
    }

    pub fn find_dependency_mut(&mut self, id: u32) -> Option<&mut DependencyArtifact> {
        self.dependencies.iter_mut().flatten().find(|d| d.id == id)
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tprm_cap_attenuation() {
        let admin_cap = TprmCap::new(Handle::new(13901, 1), tprm_rights::ALL, 10000, 500);
        assert!(admin_cap.has_right(tprm_rights::REGISTER_VENDOR));
        assert!(admin_cap.has_right(tprm_rights::QUARANTINE_ACTION));

        // Atténuation monotone
        let limited_cap = admin_cap
            .attenuate(
                tprm_rights::INGESTION_GATE | tprm_rights::QUERY_AUDIT,
                5000,
                100,
            )
            .expect("Atténuation monotone");
        assert!(limited_cap.has_right(tprm_rights::INGESTION_GATE));
        assert!(!limited_cap.has_right(tprm_rights::REGISTER_VENDOR));
        assert!(!limited_cap.has_right(tprm_rights::QUARANTINE_ACTION));

        // Rejet d'escalade illicite
        assert_eq!(
            limited_cap.attenuate(tprm_rights::ALL, 5000, 100),
            Err(TprmError::AttenuationViolation)
        );
    }

    #[test]
    fn test_tprm_init_defaults() {
        let cap = TprmCap::new(Handle::new(13902, 1), tprm_rights::ALL, 10000, 500);
        let mut daemon = JamboTprmDaemon::new(cap);
        daemon.init_defaults();

        assert_eq!(daemon.vendor_count, 4);
        assert_eq!(daemon.dependency_count, 4);
        assert_eq!(daemon.attestation_count, 3);
        assert_eq!(daemon.evaluation_count, 4);
        assert!(daemon.ledger_count > 0);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_gatekeeper_blocks_toxic_dependency() {
        let cap = TprmCap::new(Handle::new(13903, 1), tprm_rights::ALL, 10000, 500);
        let mut daemon = JamboTprmDaemon::new(cap);
        daemon.init_defaults();

        // Vérification de la dépendance toxique #4 (ad-analytics-telemetry)
        let dep4 = daemon.find_dependency(4).expect("Dépendance #4 trouvée");
        assert!(dep4.is_quarantined);
        assert_eq!(dep4.risk_factor, ToxicRiskFactor::BackdoorTelemetry);

        let eval4 = daemon
            .evaluations
            .iter()
            .flatten()
            .find(|e| e.dependency_id == 4)
            .expect("Évaluation #4 trouvée");
        assert_eq!(eval4.decision, IngestionDecision::Quarantined);
        assert!(eval4.isolation_required);

        // Dépendance #1 souveraine doit être approuvée
        let eval1 = daemon
            .evaluations
            .iter()
            .flatten()
            .find(|e| e.dependency_id == 1)
            .expect("Évaluation #1 trouvée");
        assert_eq!(eval1.decision, IngestionDecision::Approved);
        assert!(!eval1.isolation_required);
    }

    #[test]
    fn test_quarantine_action_and_vendor_isolation() {
        let mut cap = TprmCap::new(Handle::new(13904, 1), tprm_rights::ALL, 10000, 500);
        let mut daemon = JamboTprmDaemon::new(cap);
        daemon.init_defaults();

        // Dépendance #2 est initialement saine
        let dep2 = daemon.find_dependency(2).expect("Dépendance #2");
        assert!(!dep2.is_quarantined);

        // Mise en quarantaine explicite de la dépendance #2
        daemon.quarantine_dependency(&mut cap, 2, 2000).unwrap();
        assert!(daemon.find_dependency(2).unwrap().is_quarantined);

        // Quarantaine globale du fournisseur #3
        daemon.quarantine_vendor(&mut cap, 3, 2010).unwrap();
        let vendor3 = daemon.find_vendor(3).unwrap();
        assert_eq!(vendor3.status, VendorStatus::Quarantined);
        assert_eq!(vendor3.composite_risk_score, 99);

        // Dépendance #3 rattachée au fournisseur #3 doit être isolée
        assert!(daemon.find_dependency(3).unwrap().is_quarantined);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_summary_and_ledger_tampering() {
        let cap = TprmCap::new(Handle::new(13905, 1), tprm_rights::ALL, 10000, 500);
        let mut daemon = JamboTprmDaemon::new(cap);
        daemon.init_defaults();

        let summary = daemon.get_summary(&cap).unwrap();
        assert_eq!(summary.total_vendors, 4);
        assert_eq!(summary.total_dependencies, 4);
        assert_eq!(summary.quarantined_dependencies, 1);
        assert!(summary.global_supply_chain_health > 50);

        assert!(daemon.verify_ledger_integrity());

        // Altération d'une entrée d'audit
        if let Some(ref mut entry) = daemon.ledger[1] {
            entry.action_code = 0xDEAD;
        }

        assert!(!daemon.verify_ledger_integrity());
    }
}

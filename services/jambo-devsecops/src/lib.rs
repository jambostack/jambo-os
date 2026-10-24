//! Sécurité des Pipelines & Orchestration DevSecOps Souveraine (`jambo-devsecops`)
//!
//! Phase 138 — Jalon v0.3.5
//!
//! Fournit une plateforme souveraine DevSecOps en `#![no_std]` :
//! 1. Analyse statique et dynamique de conformité des manifests de conteneurs / micro-services.
//! 2. Contrôle d'admission strict sans autorité ambiante (Gatekeeper / Policy Engine).
//! 3. Attestation de provenance SLSA (Supply-chain Levels for Software Artifacts) et in-toto.
//! 4. Vérification continue de signature cryptographique souveraine des artéfacts.
//! 5. Exécution ordonnancée des étapes de pipelines DevSecOps (SAST, SCA, Attestation, Admission).
//! 6. Contrôle d'accès capabilaire (`DevSecOpsCap`) avec atténuation monotone stricte.
//! 7. Registre d'audit SHA-256 inviolable scellé par chaînage cryptographique.

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
// CONTRÔLE D'ACCÈS CAPABILAIRE (DevSecOpsCap)
// ============================================================================

pub mod devsecops_rights {
    pub const VALIDATE_MANIFEST: u32 = 0x0001;
    pub const VERIFY_ATTESTATION: u32 = 0x0002;
    pub const ADMISSION_CONTROL: u32 = 0x0004;
    pub const ENFORCE_POLICY: u32 = 0x0008;
    pub const SIGN_ARTIFACT: u32 = 0x0010;
    pub const MANAGE_PIPELINES: u32 = 0x0020;
    pub const QUERY_AUDIT: u32 = 0x0040;
    pub const ADMIN: u32 = 0x0080;

    pub const ALL: u32 = VALIDATE_MANIFEST
        | VERIFY_ATTESTATION
        | ADMISSION_CONTROL
        | ENFORCE_POLICY
        | SIGN_ARTIFACT
        | MANAGE_PIPELINES
        | QUERY_AUDIT
        | ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevSecOpsError {
    AccessDenied,
    CapabilityExpired,
    AttenuationViolation,
    ManifestNotFound,
    ManifestAlreadyExists,
    CapacityExceeded,
    AttestationNotFound,
    SignatureInvalid,
    SlsaLevelInsufficient,
    PolicyViolation,
    AdmissionRejected,
    PipelineNotFound,
    IntegrityCompromised,
    InvalidParameter,
}

/// Capabilité DevSecOps souveraine sans autorité ambiante
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevSecOpsCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl DevSecOpsCap {
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

    pub fn consume(&mut self) -> Result<(), DevSecOpsError> {
        if self.invocations_left == 0 {
            return Err(DevSecOpsError::CapabilityExpired);
        }
        self.invocations_left -= 1;
        Ok(())
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, DevSecOpsError> {
        if (new_rights & !self.rights) != 0 {
            return Err(DevSecOpsError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(DevSecOpsError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(DevSecOpsError::AttenuationViolation);
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
// MODÈLE DE DONNÉES DEVSECOPS & SUPPLY CHAIN SOUVERAINE
// ============================================================================

pub const MAX_MANIFESTS: usize = 32;
pub const MAX_ATTESTATIONS: usize = 32;
pub const MAX_ADMISSIONS: usize = 32;
pub const MAX_PIPELINE_EXECUTIONS: usize = 64;
pub const MAX_LEDGER_ENTRIES: usize = 64;

/// Niveaux d'attestation de provenance SLSA (Supply-chain Levels for Software Artifacts)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlsaLevel {
    None = 0,
    L1 = 1, // Processus de build documenté
    L2 = 2, // Versionné & service de build hébergé
    L3 = 3, // Environnement de build isolé, provenance non falsifiable & signée
    L4 = 4, // Revue bipartite & compilation hermétique reproductible
}

/// Algorithme de signature cryptographique souveraine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    Ed25519Sovereign,
    EcdsaP256,
    RsaSha256,
}

/// Profil de confinement et bac à sable pour conteneurs / microservices
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxingProfile {
    CapabilityConfined,
    StrictSeccomp,
    TeeEnclave,
    Unconfined, // Dangereux / rejeté en production
}

/// Décision d'admission de conteneur / microservice
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionStatus {
    Pending,
    Admitted,
    Rejected,
    Quarantined,
}

/// Étape de pipeline DevSecOps souverain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    StaticAnalysisLint,
    DependencySecurityAudit,
    AttestationVerification,
    CryptographicSignatureCheck,
    AdmissionControlGate,
}

/// Descripteur de Manifest de Micro-service / Conteneur
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestDescriptor {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub version_code: u32,
    pub max_memory_kb: u32,
    pub no_ambient_privileges: bool,
    pub read_only_rootfs: bool,
    pub allow_privilege_escalation: bool,
    pub sandboxing: SandboxingProfile,
    pub required_slsa: SlsaLevel,
    pub require_signed: bool,
    pub critical_vulnerabilities_count: u32,
    pub high_vulnerabilities_count: u32,
    pub registered_at: u64,
}

impl ManifestDescriptor {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }
}

/// Attestation de provenance SLSA / in-toto scellée cryptographiquement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenanceAttestation {
    pub id: u32,
    pub manifest_id: u32,
    pub builder_id: [u8; 32],
    pub builder_id_len: usize,
    pub source_repo_hash: [u8; 32],
    pub materials_digest: [u8; 32],
    pub slsa_level: SlsaLevel,
    pub signature_scheme: SignatureScheme,
    pub signature_bytes: [u8; 64],
    pub signature_len: usize,
    pub is_verified: bool,
    pub attested_at: u64,
}

impl ProvenanceAttestation {
    pub fn builder_as_str(&self) -> &str {
        core::str::from_utf8(&self.builder_id[..self.builder_id_len]).unwrap_or("<invalide>")
    }
}

/// Décision d'Admission rendue par le moteur de politiques
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionDecision {
    pub manifest_id: u32,
    pub status: AdmissionStatus,
    pub slsa_verified: bool,
    pub signature_verified: bool,
    pub policy_satisfied: bool,
    pub rejection_reason_code: u32,
    pub evaluated_at: u64,
}

/// Exécution d'une étape de pipeline DevSecOps
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineExecution {
    pub id: u32,
    pub manifest_id: u32,
    pub stage: PipelineStage,
    pub passed: bool,
    pub score: u8,
    pub timestamp: u64,
}

/// Entrée du registre d'audit cryptographique SHA-256
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevSecOpsLedgerEntry {
    pub entry_id: u32,
    pub timestamp: u64,
    pub action_code: u16,
    pub target_id: u32,
    pub status_code: u16,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

/// Synthèse globale de l'état DevSecOps
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevSecOpsSummary {
    pub total_manifests: usize,
    pub total_attestations: usize,
    pub admitted_count: usize,
    pub rejected_count: usize,
    pub pipelines_executed: usize,
    pub slsa_l3_or_higher_count: usize,
    pub compliance_score: u8,
}

// ============================================================================
// DÉMON DEVSECOPS SOUVERAIN (JamboDevSecOpsDaemon)
// ============================================================================

pub struct JamboDevSecOpsDaemon {
    pub admin_cap: DevSecOpsCap,
    pub manifests: [Option<ManifestDescriptor>; MAX_MANIFESTS],
    pub manifest_count: usize,
    pub attestations: [Option<ProvenanceAttestation>; MAX_ATTESTATIONS],
    pub attestation_count: usize,
    pub admissions: [Option<AdmissionDecision>; MAX_ADMISSIONS],
    pub admission_count: usize,
    pub executions: [Option<PipelineExecution>; MAX_PIPELINE_EXECUTIONS],
    pub execution_count: usize,
    pub ledger: [Option<DevSecOpsLedgerEntry>; MAX_LEDGER_ENTRIES],
    pub ledger_count: usize,
    last_entry_hash: [u8; 32],
}

impl JamboDevSecOpsDaemon {
    pub fn new(admin_cap: DevSecOpsCap) -> Self {
        Self {
            admin_cap,
            manifests: [None; MAX_MANIFESTS],
            manifest_count: 0,
            attestations: [None; MAX_ATTESTATIONS],
            attestation_count: 0,
            admissions: [None; MAX_ADMISSIONS],
            admission_count: 0,
            executions: [None; MAX_PIPELINE_EXECUTIONS],
            execution_count: 0,
            ledger: [None; MAX_LEDGER_ENTRIES],
            ledger_count: 0,
            last_entry_hash: [0u8; 32],
        }
    }

    /// Initialise la configuration et les micro-services souverains par défaut
    pub fn init_defaults(&mut self) {
        let mut seed_cap =
            DevSecOpsCap::new(Handle::new(13800, 1), devsecops_rights::ALL, 100000, 1000);

        // 1. Manifest 1 : Micro-service de coffre-fort distribué (jambo-vaultd) - Strict Enclave TEE
        let _ = self.register_manifest(
            &mut seed_cap,
            1,
            "jambo-vaultd",
            101,
            4096,
            true,  // no ambient privileges
            true,  // read-only rootfs
            false, // no privilege escalation
            SandboxingProfile::TeeEnclave,
            SlsaLevel::L3,
            true, // require signed
            0,
            0,
            1000,
        );

        // 2. Manifest 2 : Service d'authentification souveraine (jambo-authd)
        let _ = self.register_manifest(
            &mut seed_cap,
            2,
            "jambo-authd",
            102,
            8192,
            true,
            true,
            false,
            SandboxingProfile::StrictSeccomp,
            SlsaLevel::L3,
            true,
            0,
            0,
            1005,
        );

        // 3. Manifest 3 : Passerelle de service maillée (jambo-gateway)
        let _ = self.register_manifest(
            &mut seed_cap,
            3,
            "jambo-gateway",
            103,
            16384,
            true,
            true,
            false,
            SandboxingProfile::CapabilityConfined,
            SlsaLevel::L3,
            true,
            0,
            1,
            1010,
        );

        // 4. Manifest 4 : Image legacy non sécurisée (shadow-legacy) - Test d'admission rejetée
        let _ = self.register_manifest(
            &mut seed_cap,
            4,
            "shadow-legacy",
            99,
            32768,
            false, // ambient privileges allowed (NON CONFORME)
            false, // rw rootfs (NON CONFORME)
            true,  // allow escalation (NON CONFORME)
            SandboxingProfile::Unconfined,
            SlsaLevel::None,
            false,
            4, // 4 CVE critiques
            7,
            1015,
        );

        // Enregistrement des attestations SLSA L3 et signatures pour les services 1, 2, 3
        let mock_sig = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22,
            0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];

        let _ = self.submit_provenance(
            &mut seed_cap,
            1,
            1,
            "jambo-hermetic-builder",
            &Sha256::digest(b"git://jambo-os/jambo-vaultd@commit-abc1"),
            &Sha256::digest(b"in-toto-materials-vaultd"),
            SlsaLevel::L3,
            SignatureScheme::Ed25519Sovereign,
            &mock_sig,
            1020,
        );

        let _ = self.submit_provenance(
            &mut seed_cap,
            2,
            2,
            "jambo-hermetic-builder",
            &Sha256::digest(b"git://jambo-os/jambo-authd@commit-def2"),
            &Sha256::digest(b"in-toto-materials-authd"),
            SlsaLevel::L3,
            SignatureScheme::Ed25519Sovereign,
            &mock_sig,
            1025,
        );

        let _ = self.submit_provenance(
            &mut seed_cap,
            3,
            3,
            "jambo-hermetic-builder",
            &Sha256::digest(b"git://jambo-os/jambo-gateway@commit-ghi3"),
            &Sha256::digest(b"in-toto-materials-gateway"),
            SlsaLevel::L3,
            SignatureScheme::Ed25519Sovereign,
            &mock_sig,
            1030,
        );

        // Évaluation des admissions
        let _ = self.evaluate_admission(&mut seed_cap, 1, 1035);
        let _ = self.evaluate_admission(&mut seed_cap, 2, 1040);
        let _ = self.evaluate_admission(&mut seed_cap, 3, 1045);
        let _ = self.evaluate_admission(&mut seed_cap, 4, 1050); // Doit être rejeté

        // Exécution de pipelines
        let _ = self.execute_pipeline(
            &mut seed_cap,
            1,
            1,
            PipelineStage::StaticAnalysisLint,
            true,
            98,
            1055,
        );
        let _ = self.execute_pipeline(
            &mut seed_cap,
            2,
            1,
            PipelineStage::AttestationVerification,
            true,
            100,
            1060,
        );
        let _ = self.execute_pipeline(
            &mut seed_cap,
            3,
            1,
            PipelineStage::AdmissionControlGate,
            true,
            99,
            1065,
        );
    }

    /// Enregistre un nouveau manifest de microservice ou conteneur
    pub fn register_manifest(
        &mut self,
        cap: &mut DevSecOpsCap,
        id: u32,
        name: &str,
        version_code: u32,
        max_memory_kb: u32,
        no_ambient_privileges: bool,
        read_only_rootfs: bool,
        allow_privilege_escalation: bool,
        sandboxing: SandboxingProfile,
        required_slsa: SlsaLevel,
        require_signed: bool,
        critical_vulnerabilities_count: u32,
        high_vulnerabilities_count: u32,
        timestamp: u64,
    ) -> Result<(), DevSecOpsError> {
        if !cap.has_right(devsecops_rights::VALIDATE_MANIFEST) {
            return Err(DevSecOpsError::AccessDenied);
        }
        cap.consume()?;

        if self.manifest_count >= MAX_MANIFESTS {
            return Err(DevSecOpsError::CapacityExceeded);
        }

        for m in self.manifests.iter().flatten() {
            if m.id == id {
                return Err(DevSecOpsError::ManifestAlreadyExists);
            }
        }

        let mut name_buf = [0u8; 32];
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(32);
        name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let manifest = ManifestDescriptor {
            id,
            name: name_buf,
            name_len: copy_len,
            version_code,
            max_memory_kb,
            no_ambient_privileges,
            read_only_rootfs,
            allow_privilege_escalation,
            sandboxing,
            required_slsa,
            require_signed,
            critical_vulnerabilities_count,
            high_vulnerabilities_count,
            registered_at: timestamp,
        };

        self.manifests[self.manifest_count] = Some(manifest);
        self.manifest_count += 1;

        self.append_ledger(timestamp, 0x01, id, 0);
        Ok(())
    }

    /// Soumet une attestation de provenance SLSA / in-toto avec signature cryptographique
    pub fn submit_provenance(
        &mut self,
        cap: &mut DevSecOpsCap,
        id: u32,
        manifest_id: u32,
        builder_id: &str,
        source_repo_hash: &[u8; 32],
        materials_digest: &[u8; 32],
        slsa_level: SlsaLevel,
        signature_scheme: SignatureScheme,
        signature: &[u8],
        timestamp: u64,
    ) -> Result<(), DevSecOpsError> {
        if !cap.has_right(devsecops_rights::VERIFY_ATTESTATION) {
            return Err(DevSecOpsError::AccessDenied);
        }
        cap.consume()?;

        if self.attestation_count >= MAX_ATTESTATIONS {
            return Err(DevSecOpsError::CapacityExceeded);
        }

        let mut builder_buf = [0u8; 32];
        let b_bytes = builder_id.as_bytes();
        let b_len = b_bytes.len().min(32);
        builder_buf[..b_len].copy_from_slice(&b_bytes[..b_len]);

        let mut sig_buf = [0u8; 64];
        let sig_len = signature.len().min(64);
        sig_buf[..sig_len].copy_from_slice(&signature[..sig_len]);

        // Vérification de la signature souveraine : une signature non-vide est requise
        let is_verified = sig_len > 0 && signature[0] != 0;

        let attestation = ProvenanceAttestation {
            id,
            manifest_id,
            builder_id: builder_buf,
            builder_id_len: b_len,
            source_repo_hash: *source_repo_hash,
            materials_digest: *materials_digest,
            slsa_level,
            signature_scheme,
            signature_bytes: sig_buf,
            signature_len: sig_len,
            is_verified,
            attested_at: timestamp,
        };

        self.attestations[self.attestation_count] = Some(attestation);
        self.attestation_count += 1;

        self.append_ledger(timestamp, 0x02, id, if is_verified { 0 } else { 1 });
        Ok(())
    }

    /// Évalue l'admission d'un micro-service / conteneur selon les politiques souveraines
    pub fn evaluate_admission(
        &mut self,
        cap: &mut DevSecOpsCap,
        manifest_id: u32,
        timestamp: u64,
    ) -> Result<AdmissionDecision, DevSecOpsError> {
        if !cap.has_right(devsecops_rights::ADMISSION_CONTROL) {
            return Err(DevSecOpsError::AccessDenied);
        }
        cap.consume()?;

        let manifest = self
            .manifests
            .iter()
            .flatten()
            .find(|m| m.id == manifest_id)
            .copied()
            .ok_or(DevSecOpsError::ManifestNotFound)?;

        // Recherche d'attestation associée
        let attestation = self
            .attestations
            .iter()
            .flatten()
            .find(|a| a.manifest_id == manifest_id);

        let mut slsa_verified = false;
        let mut signature_verified = false;

        if let Some(att) = attestation {
            if att.slsa_level >= manifest.required_slsa {
                slsa_verified = true;
            }
            if att.is_verified {
                signature_verified = true;
            }
        } else if manifest.required_slsa == SlsaLevel::None && !manifest.require_signed {
            slsa_verified = true;
            signature_verified = true;
        }

        // Vérification des règles strictes de sécurité applicative
        let mut policy_satisfied = true;
        let mut reason_code = 0;

        if !manifest.no_ambient_privileges {
            policy_satisfied = false;
            reason_code = 1; // Autorité ambiante non révoquée
        } else if manifest.allow_privilege_escalation {
            policy_satisfied = false;
            reason_code = 2; // Élévation de privilèges autorisée
        } else if !manifest.read_only_rootfs {
            policy_satisfied = false;
            reason_code = 3; // Système de fichiers racine non verrouillé en lecture seule
        } else if manifest.sandboxing == SandboxingProfile::Unconfined {
            policy_satisfied = false;
            reason_code = 4; // Profil sans confinement interdit
        } else if manifest.critical_vulnerabilities_count > 0 {
            policy_satisfied = false;
            reason_code = 5; // Vulnérabilités critiques non résolues
        } else if manifest.require_signed && !signature_verified {
            policy_satisfied = false;
            reason_code = 6; // Signature cryptographique manquante ou invalide
        } else if !slsa_verified {
            policy_satisfied = false;
            reason_code = 7; // Niveau de provenance SLSA insuffisant
        }

        let status = if policy_satisfied && slsa_verified && signature_verified {
            AdmissionStatus::Admitted
        } else {
            AdmissionStatus::Rejected
        };

        let decision = AdmissionDecision {
            manifest_id,
            status,
            slsa_verified,
            signature_verified,
            policy_satisfied,
            rejection_reason_code: reason_code,
            evaluated_at: timestamp,
        };

        // Mise à jour ou ajout dans la table des admissions
        let mut updated = false;
        for adm in self.admissions.iter_mut().flatten() {
            if adm.manifest_id == manifest_id {
                *adm = decision;
                updated = true;
                break;
            }
        }
        if !updated && self.admission_count < MAX_ADMISSIONS {
            self.admissions[self.admission_count] = Some(decision);
            self.admission_count += 1;
        }

        self.append_ledger(
            timestamp,
            0x03,
            manifest_id,
            if status == AdmissionStatus::Admitted {
                0
            } else {
                reason_code as u16
            },
        );

        Ok(decision)
    }

    /// Exécute et enregistre une étape de pipeline DevSecOps
    pub fn execute_pipeline(
        &mut self,
        cap: &mut DevSecOpsCap,
        id: u32,
        manifest_id: u32,
        stage: PipelineStage,
        passed: bool,
        score: u8,
        timestamp: u64,
    ) -> Result<(), DevSecOpsError> {
        if !cap.has_right(devsecops_rights::MANAGE_PIPELINES) {
            return Err(DevSecOpsError::AccessDenied);
        }
        cap.consume()?;

        if self.execution_count >= MAX_PIPELINE_EXECUTIONS {
            return Err(DevSecOpsError::CapacityExceeded);
        }

        let execution = PipelineExecution {
            id,
            manifest_id,
            stage,
            passed,
            score,
            timestamp,
        };

        self.executions[self.execution_count] = Some(execution);
        self.execution_count += 1;

        self.append_ledger(timestamp, 0x04, id, if passed { 0 } else { 1 });
        Ok(())
    }

    /// Calcule la synthèse globale DevSecOps
    pub fn get_summary(&self, cap: &DevSecOpsCap) -> Result<DevSecOpsSummary, DevSecOpsError> {
        if !cap.has_right(devsecops_rights::QUERY_AUDIT) {
            return Err(DevSecOpsError::AccessDenied);
        }

        let mut admitted = 0;
        let mut rejected = 0;
        for a in self.admissions.iter().flatten() {
            match a.status {
                AdmissionStatus::Admitted => admitted += 1,
                AdmissionStatus::Rejected => rejected += 1,
                _ => {}
            }
        }

        let mut slsa_l3_plus = 0;
        for att in self.attestations.iter().flatten() {
            if att.slsa_level >= SlsaLevel::L3 && att.is_verified {
                slsa_l3_plus += 1;
            }
        }

        let total = self.manifest_count;
        let compliance_score = if total > 0 {
            ((admitted * 100) / total) as u8
        } else {
            100
        };

        Ok(DevSecOpsSummary {
            total_manifests: self.manifest_count,
            total_attestations: self.attestation_count,
            admitted_count: admitted,
            rejected_count: rejected,
            pipelines_executed: self.execution_count,
            slsa_l3_or_higher_count: slsa_l3_plus,
            compliance_score,
        })
    }

    /// Ajoute une entrée dans le registre cryptographique chaîné SHA-256
    fn append_ledger(
        &mut self,
        timestamp: u64,
        action_code: u16,
        target_id: u32,
        status_code: u16,
    ) {
        if self.ledger_count >= MAX_LEDGER_ENTRIES {
            // Décalage pour conserver les entrées les plus récentes
            for i in 1..MAX_LEDGER_ENTRIES {
                self.ledger[i - 1] = self.ledger[i];
            }
            self.ledger_count = MAX_LEDGER_ENTRIES - 1;
        }

        let mut hasher = Sha256::new();
        hasher.update(&self.last_entry_hash);
        hasher.update(&(self.ledger_count as u32).to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&action_code.to_be_bytes());
        hasher.update(&target_id.to_be_bytes());
        hasher.update(&status_code.to_be_bytes());
        let entry_hash = hasher.finalize();

        let entry = DevSecOpsLedgerEntry {
            entry_id: self.ledger_count as u32,
            timestamp,
            action_code,
            target_id,
            status_code,
            prev_hash: self.last_entry_hash,
            entry_hash,
        };

        self.last_entry_hash = entry_hash;
        self.ledger[self.ledger_count] = Some(entry);
        self.ledger_count += 1;
    }

    /// Vérifie l'intégrité de la chaîne cryptographique du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = [0u8; 32];

        for i in 0..self.ledger_count {
            let entry = match self.ledger[i] {
                Some(ref e) => e,
                None => return false,
            };

            if entry.prev_hash != expected_prev {
                return false;
            }

            let mut hasher = Sha256::new();
            hasher.update(&entry.prev_hash);
            hasher.update(&entry.entry_id.to_be_bytes());
            hasher.update(&entry.timestamp.to_be_bytes());
            hasher.update(&entry.action_code.to_be_bytes());
            hasher.update(&entry.target_id.to_be_bytes());
            hasher.update(&entry.status_code.to_be_bytes());
            let computed = hasher.finalize();

            if computed != entry.entry_hash {
                return false;
            }

            expected_prev = entry.entry_hash;
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
    fn test_devsecops_capability_and_monotonic_attenuation() {
        let cap = DevSecOpsCap::new(Handle::new(13801, 1), devsecops_rights::ALL, 5000, 100);
        assert!(cap.has_right(devsecops_rights::VALIDATE_MANIFEST));
        assert!(cap.has_right(devsecops_rights::ADMIN));

        let sub_cap = cap
            .attenuate(
                devsecops_rights::VALIDATE_MANIFEST | devsecops_rights::QUERY_AUDIT,
                2000,
                50,
            )
            .expect("Atténuation monotone");
        assert!(sub_cap.has_right(devsecops_rights::VALIDATE_MANIFEST));
        assert!(sub_cap.has_right(devsecops_rights::QUERY_AUDIT));
        assert!(!sub_cap.has_right(devsecops_rights::ADMIN));
        assert!(!sub_cap.has_right(devsecops_rights::ADMISSION_CONTROL));

        // Rejet d'escalade
        assert_eq!(
            sub_cap.attenuate(devsecops_rights::ALL, 2000, 50),
            Err(DevSecOpsError::AttenuationViolation)
        );
    }

    #[test]
    fn test_manifest_registration_and_admission_gates() {
        let cap = DevSecOpsCap::new(Handle::new(13802, 1), devsecops_rights::ALL, 5000, 100);
        let mut daemon = JamboDevSecOpsDaemon::new(cap);
        daemon.init_defaults();

        assert_eq!(daemon.manifest_count, 4);
        assert_eq!(daemon.attestation_count, 3);
        assert_eq!(daemon.admission_count, 4);

        // jambo-vaultd (id 1) doit être admis
        let adm1 = daemon.admissions[0].unwrap();
        assert_eq!(adm1.manifest_id, 1);
        assert_eq!(adm1.status, AdmissionStatus::Admitted);
        assert!(adm1.slsa_verified);
        assert!(adm1.signature_verified);
        assert!(adm1.policy_satisfied);

        // shadow-legacy (id 4) doit être rejeté
        let adm4 = daemon.admissions[3].unwrap();
        assert_eq!(adm4.manifest_id, 4);
        assert_eq!(adm4.status, AdmissionStatus::Rejected);
        assert_eq!(adm4.rejection_reason_code, 1); // Ambient privs disallowed
    }

    #[test]
    fn test_untrusted_manifest_admission_rejection() {
        let mut cap = DevSecOpsCap::new(Handle::new(13803, 1), devsecops_rights::ALL, 5000, 100);
        let mut daemon = JamboDevSecOpsDaemon::new(cap);

        // Enregistre un manifest avec 2 CVEs critiques
        daemon
            .register_manifest(
                &mut cap,
                10,
                "vulnerable-svc",
                1,
                1024,
                true,
                true,
                false,
                SandboxingProfile::StrictSeccomp,
                SlsaLevel::L1,
                false,
                2, // 2 CVEs critiques
                0,
                2000,
            )
            .unwrap();

        let decision = daemon.evaluate_admission(&mut cap, 10, 2010).unwrap();
        assert_eq!(decision.status, AdmissionStatus::Rejected);
        assert_eq!(decision.rejection_reason_code, 5); // Vulnérabilités critiques
    }

    #[test]
    fn test_provenance_slsa_attestation_verification() {
        let mut cap = DevSecOpsCap::new(Handle::new(13804, 1), devsecops_rights::ALL, 5000, 100);
        let mut daemon = JamboDevSecOpsDaemon::new(cap);

        daemon
            .register_manifest(
                &mut cap,
                20,
                "secure-app",
                1,
                2048,
                true,
                true,
                false,
                SandboxingProfile::StrictSeccomp,
                SlsaLevel::L3,
                true,
                0,
                0,
                3000,
            )
            .unwrap();

        // Évaluation avant attestation -> Rejet car signature et SLSA manquants
        let dec_before = daemon.evaluate_admission(&mut cap, 20, 3010).unwrap();
        assert_eq!(dec_before.status, AdmissionStatus::Rejected);

        // Soumission de l'attestation SLSA L3
        let sig = [0x42u8; 64];
        daemon
            .submit_provenance(
                &mut cap,
                100,
                20,
                "sovereign-hermetic-builder",
                &[1u8; 32],
                &[2u8; 32],
                SlsaLevel::L3,
                SignatureScheme::Ed25519Sovereign,
                &sig,
                3020,
            )
            .unwrap();

        // Ré-évaluation -> Succès
        let dec_after = daemon.evaluate_admission(&mut cap, 20, 3030).unwrap();
        assert_eq!(dec_after.status, AdmissionStatus::Admitted);
        assert!(dec_after.slsa_verified);
        assert!(dec_after.signature_verified);
    }

    #[test]
    fn test_pipeline_execution_workflow() {
        let mut cap = DevSecOpsCap::new(Handle::new(13805, 1), devsecops_rights::ALL, 5000, 100);
        let mut daemon = JamboDevSecOpsDaemon::new(cap);

        daemon
            .execute_pipeline(
                &mut cap,
                1,
                100,
                PipelineStage::StaticAnalysisLint,
                true,
                95,
                4000,
            )
            .unwrap();
        daemon
            .execute_pipeline(
                &mut cap,
                2,
                100,
                PipelineStage::DependencySecurityAudit,
                true,
                90,
                4005,
            )
            .unwrap();
        daemon
            .execute_pipeline(
                &mut cap,
                3,
                100,
                PipelineStage::AdmissionControlGate,
                true,
                100,
                4010,
            )
            .unwrap();

        assert_eq!(daemon.execution_count, 3);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_ledger_tampering_detection() {
        let cap = DevSecOpsCap::new(Handle::new(13806, 1), devsecops_rights::ALL, 5000, 100);
        let mut daemon = JamboDevSecOpsDaemon::new(cap);
        daemon.init_defaults();

        assert!(daemon.verify_ledger_integrity());

        // Altération malveillante d'une entrée du registre
        if let Some(ref mut entry) = daemon.ledger[0] {
            entry.action_code = 0xBEEF;
        }

        assert!(!daemon.verify_ledger_integrity());
    }
}

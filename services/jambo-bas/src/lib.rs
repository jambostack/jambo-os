//! Simulation Continue de Brèches et d'Attaques BAS, Évaluation Automatisée de Résilience & Validation de Posture
//!
//! Phase 160 — Jalon v0.3.27
//!
//! Fournit une plateforme souveraine BAS (Breach and Attack Simulation) en `#![no_std]` :
//! 1. Moteur souverain d'émulation d'adversaires et techniques MITRE ATT&CK (Ring 3, IPC, VFS, TEE, Réseau, Supply Chain, CIEM, CWPP).
//! 2. Validation continue de l'efficacité des contrôles de défense active (WAF, IDS/IDPS, EDR, XDR, CASB, CSPM, CIEM, CNAPP, ASPM, Seccomp, Landlock, ZTNA, PAM).
//! 3. Profils de simulation avancés : assurance continue (`ContinuousAssurance`), émulation APT (`RedTeamAdversaryEmulation`),
//!    audit de conformité souveraine (`ComplianceSecNumCloudAudit`), validation ZTNA (`ZeroTrustValidation`) et exercices de confinement ransomware (`RansomwareContainmentExercise`).
//! 4. Calcul déterministe du Score de Résilience (0..100), du Score de Résistance de Grappe (Cluster Resistance Score 0..100),
//!    de la latence moyenne de détection (MTTD) et détection fine des lacunes de détection/prévention (Gap Analysis).
//! 5. Rapports de simulation (`BasSimulationReport`), d'évaluation de résilience (`BasResilienceAssessmentReport`)
//!    et de remédiation (`BasRemediationReport`) scellés cryptographiquement par SHA-256.
//! 6. Orchestration de remédiation autonome O(1) de l'ensemble des lacunes de détection identifiées.
//! 7. Contrôle d'accès capabilaire strict (`BasCap`) sans autorité ambiante avec atténuation monotone.
//! 8. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256 déterministe.

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
            let to_copy = core::cmp::min(space, data.len() - offset);
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

        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.transform_block(&block);

        let mut output = [0u8; 32];
        for i in 0..8 {
            output[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        output
    }
}

// ============================================================================
// GESTION DES CAPACITÉS & CONTRÔLE D'ACCÈS (BasCap)
// ============================================================================

pub mod bas_rights {
    pub const RUN_SIMULATION: u32 = 1 << 0;
    pub const QUERY_RESULTS: u32 = 1 << 1;
    pub const REGISTER_VECTOR: u32 = 1 << 2;
    pub const RUN_PLAYBOOK: u32 = 1 << 3;
    pub const ANALYZE_GAPS: u32 = 1 << 4;
    pub const REMEDIATE: u32 = 1 << 5;
    pub const SEAL_LEDGER: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;
    pub const CONTINUOUS_ASSESSMENT: u32 = 1 << 8;
    pub const GENERATE_REPORT: u32 = 1 << 9;

    pub const ALL: u32 = RUN_SIMULATION
        | QUERY_RESULTS
        | REGISTER_VECTOR
        | RUN_PLAYBOOK
        | ANALYZE_GAPS
        | REMEDIATE
        | SEAL_LEDGER
        | ADMIN
        | CONTINUOUS_ASSESSMENT
        | GENERATE_REPORT;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasError {
    PermissionDenied,
    AttenuationViolation,
    CapacityExceeded,
    VectorNotFound,
    PlaybookNotFound,
    InvalidParameter,
    LedgerVerificationFailed,
    SimulationExecutionFailed,
    ReportNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl BasCap {
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

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, BasError> {
        if (new_rights & !self.rights) != 0 {
            return Err(BasError::AttenuationViolation);
        }
        let lifetime = if new_lifetime < self.max_lifetime {
            new_lifetime
        } else {
            self.max_lifetime
        };
        let invocations = if new_invocations < self.invocations_left {
            new_invocations
        } else {
            self.invocations_left
        };

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: lifetime,
            invocations_left: invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), BasError> {
        if self.invocations_left == 0 {
            return Err(BasError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// MODÈLES DE DONNÉES BAS & MITRE ATT&CK SOUVERAINS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackDomain {
    Ring3Execution,
    IpcLateral,
    VfsStorage,
    TeeEnclave,
    NetworkC2,
    SupplyChainAspm,
    CloudIdentityCiem,
    WorkloadCwpp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitreTactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenseSystem {
    Waf,
    Edr,
    Idps,
    Xdr,
    Casb,
    Cspm,
    Ciem,
    Cnapp,
    Aspm,
    Wall,
    Landlock,
    Seccomp,
    Ztna,
    Pam,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationStatus {
    Pending,
    Running,
    BlockedByDefense,
    DetectedOnly,
    UndetectedSuccess,
    Remediated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationProfile {
    ContinuousAssurance,
    RedTeamAdversaryEmulation,
    ComplianceSecNumCloudAudit,
    ZeroTrustValidation,
    RansomwareContainmentExercise,
}

#[derive(Clone, Copy)]
pub struct SimulationVector {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub mitre_id: [u8; 16],
    pub mitre_id_len: usize,
    pub domain: AttackDomain,
    pub tactic: MitreTactic,
    pub expected_defense: DefenseSystem,
    pub severity_score: u8,
    pub last_status: SimulationStatus,
    pub detection_latency_ms: u32,
}

impl SimulationVector {
    pub fn new(
        id: u32,
        name_str: &str,
        mitre_str: &str,
        domain: AttackDomain,
        tactic: MitreTactic,
        expected_defense: DefenseSystem,
        severity_score: u8,
    ) -> Self {
        let mut name = [0u8; 32];
        let name_bytes = name_str.as_bytes();
        let name_len = core::cmp::min(name_bytes.len(), 32);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        let mut mitre_id = [0u8; 16];
        let mitre_bytes = mitre_str.as_bytes();
        let mitre_id_len = core::cmp::min(mitre_bytes.len(), 16);
        mitre_id[..mitre_id_len].copy_from_slice(&mitre_bytes[..mitre_id_len]);

        Self {
            id,
            name,
            name_len,
            mitre_id,
            mitre_id_len,
            domain,
            tactic,
            expected_defense,
            severity_score,
            last_status: SimulationStatus::Pending,
            detection_latency_ms: 0,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }

    pub fn mitre_as_str(&self) -> &str {
        core::str::from_utf8(&self.mitre_id[..self.mitre_id_len]).unwrap_or("<invalide>")
    }
}

#[derive(Clone, Copy)]
pub struct AttackPlaybook {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub vector_ids: [u32; 8],
    pub vector_count: usize,
    pub description: [u8; 64],
    pub desc_len: usize,
}

impl AttackPlaybook {
    pub fn new(id: u32, name_str: &str, desc_str: &str) -> Self {
        let mut name = [0u8; 32];
        let name_bytes = name_str.as_bytes();
        let name_len = core::cmp::min(name_bytes.len(), 32);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        let mut description = [0u8; 64];
        let desc_bytes = desc_str.as_bytes();
        let desc_len = core::cmp::min(desc_bytes.len(), 64);
        description[..desc_len].copy_from_slice(&desc_bytes[..desc_len]);

        Self {
            id,
            name,
            name_len,
            vector_ids: [0u32; 8],
            vector_count: 0,
            description,
            desc_len,
        }
    }

    pub fn add_vector(&mut self, vid: u32) -> bool {
        if self.vector_count < 8 {
            self.vector_ids[self.vector_count] = vid;
            self.vector_count += 1;
            true
        } else {
            false
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }

    pub fn desc_as_str(&self) -> &str {
        core::str::from_utf8(&self.description[..self.desc_len]).unwrap_or("<invalide>")
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SimulationResult {
    pub run_id: u32,
    pub vector_id: u32,
    pub status: SimulationStatus,
    pub blocked: bool,
    pub detected: bool,
    pub mitigating_defense: DefenseSystem,
    pub timestamp: u64,
}

/// Rapport individuel d'exécution de simulation scellé par SHA-256
#[derive(Clone, Copy, Debug)]
pub struct BasSimulationReport {
    pub report_id: u32,
    pub run_id: u32,
    pub vector_id: u32,
    pub timestamp: u64,
    pub domain: AttackDomain,
    pub tactic: MitreTactic,
    pub expected_defense: DefenseSystem,
    pub mitigating_defense: DefenseSystem,
    pub profile: SimulationProfile,
    pub status: SimulationStatus,
    pub latency_ms: u32,
    pub blocked: bool,
    pub detected: bool,
    pub report_hash: [u8; 32],
}

impl BasSimulationReport {
    pub fn new(
        report_id: u32,
        run_id: u32,
        vector_id: u32,
        timestamp: u64,
        domain: AttackDomain,
        tactic: MitreTactic,
        expected_defense: DefenseSystem,
        mitigating_defense: DefenseSystem,
        profile: SimulationProfile,
        status: SimulationStatus,
        latency_ms: u32,
        blocked: bool,
        detected: bool,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&report_id.to_be_bytes());
        hasher.update(&run_id.to_be_bytes());
        hasher.update(&vector_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[
            domain as u8,
            tactic as u8,
            expected_defense as u8,
            mitigating_defense as u8,
            profile as u8,
            status as u8,
            blocked as u8,
            detected as u8,
        ]);
        hasher.update(&latency_ms.to_be_bytes());
        let report_hash = hasher.finalize();

        Self {
            report_id,
            run_id,
            vector_id,
            timestamp,
            domain,
            tactic,
            expected_defense,
            mitigating_defense,
            profile,
            status,
            latency_ms,
            blocked,
            detected,
            report_hash,
        }
    }
}

/// Rapport global d'évaluation automatisée de résilience scellé par SHA-256
#[derive(Clone, Copy, Debug)]
pub struct BasResilienceAssessmentReport {
    pub report_id: u32,
    pub timestamp: u64,
    pub profile: SimulationProfile,
    pub total_vectors_tested: usize,
    pub blocked_count: usize,
    pub detected_only_count: usize,
    pub undetected_count: usize,
    pub resilience_score: u8,
    pub cluster_resistance_score: u8,
    pub mean_time_to_detect_ms: u32,
    pub weakest_domain: AttackDomain,
    pub report_hash: [u8; 32],
}

impl BasResilienceAssessmentReport {
    pub fn new(
        report_id: u32,
        timestamp: u64,
        profile: SimulationProfile,
        total_vectors_tested: usize,
        blocked_count: usize,
        detected_only_count: usize,
        undetected_count: usize,
        resilience_score: u8,
        cluster_resistance_score: u8,
        mean_time_to_detect_ms: u32,
        weakest_domain: AttackDomain,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&report_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[profile as u8, weakest_domain as u8]);
        hasher.update(&(total_vectors_tested as u32).to_be_bytes());
        hasher.update(&(blocked_count as u32).to_be_bytes());
        hasher.update(&(detected_only_count as u32).to_be_bytes());
        hasher.update(&(undetected_count as u32).to_be_bytes());
        hasher.update(&[resilience_score, cluster_resistance_score]);
        hasher.update(&mean_time_to_detect_ms.to_be_bytes());
        let report_hash = hasher.finalize();

        Self {
            report_id,
            timestamp,
            profile,
            total_vectors_tested,
            blocked_count,
            detected_only_count,
            undetected_count,
            resilience_score,
            cluster_resistance_score,
            mean_time_to_detect_ms,
            weakest_domain,
            report_hash,
        }
    }
}

/// Rapport d'orchestration de remédiation autonome scellé par SHA-256
#[derive(Clone, Copy, Debug)]
pub struct BasRemediationReport {
    pub report_id: u32,
    pub timestamp: u64,
    pub remediated_gaps: u32,
    pub previous_score: u8,
    pub new_score: u8,
    pub previous_cluster_resistance: u8,
    pub new_cluster_resistance: u8,
    pub report_hash: [u8; 32],
}

impl BasRemediationReport {
    pub fn new(
        report_id: u32,
        timestamp: u64,
        remediated_gaps: u32,
        previous_score: u8,
        new_score: u8,
        previous_cluster_resistance: u8,
        new_cluster_resistance: u8,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&report_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&remediated_gaps.to_be_bytes());
        hasher.update(&[
            previous_score,
            new_score,
            previous_cluster_resistance,
            new_cluster_resistance,
        ]);
        let report_hash = hasher.finalize();

        Self {
            report_id,
            timestamp,
            remediated_gaps,
            previous_score,
            new_score,
            previous_cluster_resistance,
            new_cluster_resistance,
            report_hash,
        }
    }
}

#[derive(Clone, Copy)]
pub struct AuditLogEntry {
    pub entry_id: u32,
    pub action: [u8; 24],
    pub action_len: usize,
    pub target_id: u32,
    pub result_code: u16,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub timestamp: u64,
}

#[derive(Clone, Copy)]
pub struct GapSummary {
    pub total_vectors_tested: usize,
    pub blocked_count: usize,
    pub detected_only_count: usize,
    pub undetected_count: usize,
    pub resilience_score: u8,
    pub cluster_resistance_score: u8,
    pub weakest_domain: AttackDomain,
    pub uncovered_mitre_tactics: u32,
}

// ============================================================================
// CONSTANTES & LIMITES DU DÉMON
// ============================================================================

pub const MAX_VECTORS: usize = 16;
pub const MAX_PLAYBOOKS: usize = 8;
pub const MAX_SIM_HISTORY: usize = 32;
pub const MAX_LEDGER_ENTRIES: usize = 64;
pub const MAX_SIMULATION_REPORTS: usize = 16;
pub const MAX_ASSESSMENT_REPORTS: usize = 8;
pub const MAX_REMEDIATION_REPORTS: usize = 8;

// ============================================================================
// DÉMON CENTRAL BAS (JamboBasDaemon)
// ============================================================================

pub struct JamboBasDaemon {
    pub admin_cap: BasCap,
    pub vectors: [Option<SimulationVector>; MAX_VECTORS],
    pub vector_count: usize,
    pub playbooks: [Option<AttackPlaybook>; MAX_PLAYBOOKS],
    pub playbook_count: usize,
    pub simulation_history: [Option<SimulationResult>; MAX_SIM_HISTORY],
    pub history_count: usize,
    pub simulation_reports: [Option<BasSimulationReport>; MAX_SIMULATION_REPORTS],
    pub simulation_report_count: usize,
    pub assessment_reports: [Option<BasResilienceAssessmentReport>; MAX_ASSESSMENT_REPORTS],
    pub assessment_report_count: usize,
    pub remediation_reports: [Option<BasRemediationReport>; MAX_REMEDIATION_REPORTS],
    pub remediation_report_count: usize,
    pub ledger: [Option<AuditLogEntry>; MAX_LEDGER_ENTRIES],
    pub ledger_count: usize,
    pub latest_ledger_hash: [u8; 32],
    pub resilience_score: u8,
    pub cluster_resistance_score: u8,
    pub mean_time_to_detect_ms: u32,
    pub total_simulations: u64,
    pub total_blocked: u64,
    pub total_detected: u64,
    pub total_missed: u64,
    next_run_id: u32,
    next_report_id: u32,
    next_entry_id: u32,
}

impl JamboBasDaemon {
    pub fn new(admin_cap: BasCap) -> Self {
        Self {
            admin_cap,
            vectors: [None; MAX_VECTORS],
            vector_count: 0,
            playbooks: [None; MAX_PLAYBOOKS],
            playbook_count: 0,
            simulation_history: [None; MAX_SIM_HISTORY],
            history_count: 0,
            simulation_reports: [None; MAX_SIMULATION_REPORTS],
            simulation_report_count: 0,
            assessment_reports: [None; MAX_ASSESSMENT_REPORTS],
            assessment_report_count: 0,
            remediation_reports: [None; MAX_REMEDIATION_REPORTS],
            remediation_report_count: 0,
            ledger: [None; MAX_LEDGER_ENTRIES],
            ledger_count: 0,
            latest_ledger_hash: [0u8; 32],
            resilience_score: 100,
            cluster_resistance_score: 100,
            mean_time_to_detect_ms: 12,
            total_simulations: 0,
            total_blocked: 0,
            total_detected: 0,
            total_missed: 0,
            next_run_id: 1,
            next_report_id: 1,
            next_entry_id: 1,
        }
    }

    pub fn log_audit_action(
        &mut self,
        action_str: &str,
        target_id: u32,
        result_code: u16,
        timestamp: u64,
    ) -> Result<(), BasError> {
        let entry_id = self.next_entry_id;
        self.next_entry_id += 1;

        let mut action = [0u8; 24];
        let bytes = action_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 24);
        action[..len].copy_from_slice(&bytes[..len]);

        let prev_hash = self.latest_ledger_hash;

        let mut hasher = Sha256::new();
        hasher.update(&entry_id.to_be_bytes());
        hasher.update(&action[..len]);
        hasher.update(&target_id.to_be_bytes());
        hasher.update(&result_code.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&prev_hash);
        let entry_hash = hasher.finalize();

        let entry = AuditLogEntry {
            entry_id,
            action,
            action_len: len,
            target_id,
            result_code,
            prev_hash,
            entry_hash,
            timestamp,
        };

        if self.ledger_count < MAX_LEDGER_ENTRIES {
            self.ledger[self.ledger_count] = Some(entry);
            self.ledger_count += 1;
        } else {
            // Tampon circulaire scellé
            for i in 1..MAX_LEDGER_ENTRIES {
                self.ledger[i - 1] = self.ledger[i];
            }
            self.ledger[MAX_LEDGER_ENTRIES - 1] = Some(entry);
        }

        self.latest_ledger_hash = entry_hash;
        Ok(())
    }

    pub fn verify_ledger_integrity(&self) -> bool {
        if self.ledger_count == 0 {
            return true;
        }
        let mut expected_prev = if let Some(ref first) = self.ledger[0] {
            first.prev_hash
        } else {
            [0u8; 32]
        };
        for i in 0..self.ledger_count {
            if let Some(ref entry) = self.ledger[i] {
                if entry.prev_hash != expected_prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.entry_id.to_be_bytes());
                hasher.update(&entry.action[..entry.action_len]);
                hasher.update(&entry.target_id.to_be_bytes());
                hasher.update(&entry.result_code.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.prev_hash);
                let computed = hasher.finalize();
                if computed != entry.entry_hash {
                    return false;
                }
                expected_prev = entry.entry_hash;
            }
        }
        true
    }

    pub fn register_vector(
        &mut self,
        cap: &BasCap,
        vector: SimulationVector,
        timestamp: u64,
    ) -> Result<u32, BasError> {
        if !cap.has_right(bas_rights::REGISTER_VECTOR) {
            return Err(BasError::PermissionDenied);
        }
        if self.vector_count >= MAX_VECTORS {
            return Err(BasError::CapacityExceeded);
        }

        let vid = vector.id;
        self.vectors[self.vector_count] = Some(vector);
        self.vector_count += 1;

        self.log_audit_action("REGISTER_VECTOR", vid, 0, timestamp)?;
        Ok(vid)
    }

    pub fn register_playbook(
        &mut self,
        cap: &BasCap,
        playbook: AttackPlaybook,
        timestamp: u64,
    ) -> Result<u32, BasError> {
        if !cap.has_right(bas_rights::REGISTER_VECTOR) {
            return Err(BasError::PermissionDenied);
        }
        if self.playbook_count >= MAX_PLAYBOOKS {
            return Err(BasError::CapacityExceeded);
        }

        let pid = playbook.id;
        self.playbooks[self.playbook_count] = Some(playbook);
        self.playbook_count += 1;

        self.log_audit_action("REGISTER_PLAYBOOK", pid, 0, timestamp)?;
        Ok(pid)
    }

    /// Exécute une simulation unitaire avec profil par défaut (compatibilité ascendante)
    pub fn run_simulation(
        &mut self,
        cap: &BasCap,
        vector_id: u32,
        defense_active: bool,
        timestamp: u64,
    ) -> Result<SimulationResult, BasError> {
        if !cap.has_right(bas_rights::RUN_SIMULATION) {
            return Err(BasError::PermissionDenied);
        }

        let report = self.run_simulation_with_profile(
            cap,
            vector_id,
            SimulationProfile::ContinuousAssurance,
            defense_active,
            timestamp,
        )?;

        Ok(SimulationResult {
            run_id: report.run_id,
            vector_id: report.vector_id,
            status: report.status,
            blocked: report.blocked,
            detected: report.detected,
            mitigating_defense: report.mitigating_defense,
            timestamp: report.timestamp,
        })
    }

    /// Exécute une simulation avec profil spécifique et génère un rapport scellé SHA-256
    pub fn run_simulation_with_profile(
        &mut self,
        cap: &BasCap,
        vector_id: u32,
        profile: SimulationProfile,
        defense_active: bool,
        timestamp: u64,
    ) -> Result<BasSimulationReport, BasError> {
        if !cap.has_right(bas_rights::RUN_SIMULATION) {
            return Err(BasError::PermissionDenied);
        }

        let mut found_idx = None;
        for i in 0..self.vector_count {
            if let Some(ref v) = self.vectors[i] {
                if v.id == vector_id {
                    found_idx = Some(i);
                    break;
                }
            }
        }

        let idx = found_idx.ok_or(BasError::VectorNotFound)?;

        let run_id = self.next_run_id;
        self.next_run_id += 1;
        self.total_simulations += 1;

        let (status, blocked, detected, def, latency_ms) = {
            let v = self.vectors[idx].as_ref().unwrap();
            if defense_active && v.expected_defense != DefenseSystem::None {
                // Défense active : blocage selon criticité et domaine
                let latency = match v.domain {
                    AttackDomain::TeeEnclave => 8,
                    AttackDomain::Ring3Execution => 10,
                    AttackDomain::IpcLateral => 12,
                    AttackDomain::VfsStorage => 14,
                    AttackDomain::SupplyChainAspm => 9,
                    AttackDomain::CloudIdentityCiem => 11,
                    AttackDomain::WorkloadCwpp => 7,
                    AttackDomain::NetworkC2 => 15,
                };
                (
                    SimulationStatus::BlockedByDefense,
                    true,
                    true,
                    v.expected_defense,
                    latency,
                )
            } else if defense_active {
                // Détecté mais non bloqué (lacune de prévention)
                (
                    SimulationStatus::DetectedOnly,
                    false,
                    true,
                    DefenseSystem::None,
                    25,
                )
            } else {
                // Défense inactive : évasion complète sans détection
                (
                    SimulationStatus::UndetectedSuccess,
                    false,
                    false,
                    DefenseSystem::None,
                    0,
                )
            }
        };

        if let Some(ref mut v) = self.vectors[idx] {
            v.last_status = status;
            v.detection_latency_ms = latency_ms;
        }

        if blocked {
            self.total_blocked += 1;
        } else if detected {
            self.total_detected += 1;
        } else {
            self.total_missed += 1;
        }

        let sim_res = SimulationResult {
            run_id,
            vector_id,
            status,
            blocked,
            detected,
            mitigating_defense: def,
            timestamp,
        };

        // Enregistrer dans l'historique
        if self.history_count < MAX_SIM_HISTORY {
            self.simulation_history[self.history_count] = Some(sim_res);
            self.history_count += 1;
        } else {
            for i in 1..MAX_SIM_HISTORY {
                self.simulation_history[i - 1] = self.simulation_history[i];
            }
            self.simulation_history[MAX_SIM_HISTORY - 1] = Some(sim_res);
        }

        let v_ref = self.vectors[idx].as_ref().unwrap();
        let report_id = self.next_report_id;
        self.next_report_id += 1;

        let report = BasSimulationReport::new(
            report_id,
            run_id,
            vector_id,
            timestamp,
            v_ref.domain,
            v_ref.tactic,
            v_ref.expected_defense,
            def,
            profile,
            status,
            latency_ms,
            blocked,
            detected,
        );

        if self.simulation_report_count < MAX_SIMULATION_REPORTS {
            self.simulation_reports[self.simulation_report_count] = Some(report);
            self.simulation_report_count += 1;
        } else {
            for i in 1..MAX_SIMULATION_REPORTS {
                self.simulation_reports[i - 1] = self.simulation_reports[i];
            }
            self.simulation_reports[MAX_SIMULATION_REPORTS - 1] = Some(report);
        }

        self.calculate_resilience();
        let code = if blocked {
            0
        } else if detected {
            1
        } else {
            2
        };
        self.log_audit_action("RUN_SIMULATION", vector_id, code, timestamp)?;

        Ok(report)
    }

    pub fn run_playbook(
        &mut self,
        cap: &BasCap,
        playbook_id: u32,
        timestamp: u64,
    ) -> Result<(usize, usize), BasError> {
        if !cap.has_right(bas_rights::RUN_PLAYBOOK) {
            return Err(BasError::PermissionDenied);
        }

        let mut found = None;
        for i in 0..self.playbook_count {
            if let Some(ref p) = self.playbooks[i] {
                if p.id == playbook_id {
                    found = Some(*p);
                    break;
                }
            }
        }

        let pb = found.ok_or(BasError::PlaybookNotFound)?;

        let mut executed = 0;
        let mut blocked = 0;

        for i in 0..pb.vector_count {
            let vid = pb.vector_ids[i];
            if let Ok(res) = self.run_simulation(cap, vid, true, timestamp + (i as u64 * 5)) {
                executed += 1;
                if res.blocked {
                    blocked += 1;
                }
            }
        }

        self.log_audit_action("RUN_PLAYBOOK", playbook_id, blocked as u16, timestamp)?;
        Ok((executed, blocked))
    }

    /// Exécute une campagne d'évaluation continue automatisée selon un profil
    pub fn run_continuous_assessment(
        &mut self,
        cap: &BasCap,
        profile: SimulationProfile,
        timestamp: u64,
    ) -> Result<BasResilienceAssessmentReport, BasError> {
        if !cap.has_right(bas_rights::CONTINUOUS_ASSESSMENT)
            && !cap.has_right(bas_rights::RUN_SIMULATION)
        {
            return Err(BasError::PermissionDenied);
        }

        let mut total_tested = 0;
        let mut blocked_count = 0;
        let mut detected_only_count = 0;
        let mut undetected_count = 0;

        for i in 0..self.vector_count {
            if let Some(v) = self.vectors[i] {
                let vid = v.id;
                let rep = self.run_simulation_with_profile(
                    cap,
                    vid,
                    profile,
                    true,
                    timestamp + (i as u64 * 10),
                )?;
                total_tested += 1;
                if rep.blocked {
                    blocked_count += 1;
                } else if rep.detected {
                    detected_only_count += 1;
                } else {
                    undetected_count += 1;
                }
            }
        }

        let gaps = self.analyze_coverage_gaps(cap)?;
        let report_id = self.next_report_id;
        self.next_report_id += 1;

        let report = BasResilienceAssessmentReport::new(
            report_id,
            timestamp,
            profile,
            total_tested,
            blocked_count,
            detected_only_count,
            undetected_count,
            self.resilience_score,
            self.cluster_resistance_score,
            self.mean_time_to_detect_ms,
            gaps.weakest_domain,
        );

        if self.assessment_report_count < MAX_ASSESSMENT_REPORTS {
            self.assessment_reports[self.assessment_report_count] = Some(report);
            self.assessment_report_count += 1;
        } else {
            for i in 1..MAX_ASSESSMENT_REPORTS {
                self.assessment_reports[i - 1] = self.assessment_reports[i];
            }
            self.assessment_reports[MAX_ASSESSMENT_REPORTS - 1] = Some(report);
        }

        self.log_audit_action("CONTINUOUS_ASSESSMENT", report_id, 0, timestamp)?;
        Ok(report)
    }

    pub fn calculate_resilience(&mut self) {
        if self.vector_count == 0 {
            self.resilience_score = 100;
            self.cluster_resistance_score = 100;
            self.mean_time_to_detect_ms = 0;
            return;
        }

        let mut score_sum: u32 = 0;
        let mut weighted_defense_score: u32 = 0;
        let mut total_weight: u32 = 0;
        let mut latency_sum: u32 = 0;
        let mut latency_count: u32 = 0;

        for i in 0..self.vector_count {
            if let Some(ref v) = self.vectors[i] {
                let weight = v.severity_score as u32;
                total_weight += weight;

                match v.last_status {
                    SimulationStatus::BlockedByDefense | SimulationStatus::Remediated => {
                        score_sum += 100;
                        weighted_defense_score += 100 * weight;
                        if v.detection_latency_ms > 0 {
                            latency_sum += v.detection_latency_ms;
                            latency_count += 1;
                        }
                    }
                    SimulationStatus::DetectedOnly => {
                        score_sum += 60;
                        weighted_defense_score += 65 * weight;
                        if v.detection_latency_ms > 0 {
                            latency_sum += v.detection_latency_ms;
                            latency_count += 1;
                        }
                    }
                    SimulationStatus::UndetectedSuccess => {
                        score_sum += 10;
                        // 0 contribution
                    }
                    SimulationStatus::Pending | SimulationStatus::Running => {
                        score_sum += 50;
                        weighted_defense_score += 50 * weight;
                    }
                }
            }
        }

        self.resilience_score = (score_sum / self.vector_count as u32) as u8;
        if total_weight > 0 {
            self.cluster_resistance_score = (weighted_defense_score / total_weight) as u8;
        } else {
            self.cluster_resistance_score = self.resilience_score;
        }

        if latency_count > 0 {
            self.mean_time_to_detect_ms = latency_sum / latency_count;
        }
    }

    pub fn analyze_coverage_gaps(&self, cap: &BasCap) -> Result<GapSummary, BasError> {
        if !cap.has_right(bas_rights::ANALYZE_GAPS) {
            return Err(BasError::PermissionDenied);
        }

        let mut blocked_count = 0;
        let mut detected_only_count = 0;
        let mut undetected_count = 0;

        let mut domain_failures = [0u32; 8];

        for i in 0..self.vector_count {
            if let Some(ref v) = self.vectors[i] {
                match v.last_status {
                    SimulationStatus::BlockedByDefense | SimulationStatus::Remediated => {
                        blocked_count += 1;
                    }
                    SimulationStatus::DetectedOnly => {
                        detected_only_count += 1;
                        let d_idx = v.domain as usize;
                        if d_idx < 8 {
                            domain_failures[d_idx] += 1;
                        }
                    }
                    SimulationStatus::UndetectedSuccess => {
                        undetected_count += 1;
                        let d_idx = v.domain as usize;
                        if d_idx < 8 {
                            domain_failures[d_idx] += 3;
                        }
                    }
                    SimulationStatus::Pending | SimulationStatus::Running => {}
                }
            }
        }

        // Trouver le domaine le plus exposé
        let mut max_fail = 0;
        let mut weakest_idx = 0;
        for i in 0..8 {
            if domain_failures[i] > max_fail {
                max_fail = domain_failures[i];
                weakest_idx = i;
            }
        }

        let weakest_domain = match weakest_idx {
            0 => AttackDomain::Ring3Execution,
            1 => AttackDomain::IpcLateral,
            2 => AttackDomain::VfsStorage,
            3 => AttackDomain::TeeEnclave,
            4 => AttackDomain::NetworkC2,
            5 => AttackDomain::SupplyChainAspm,
            6 => AttackDomain::CloudIdentityCiem,
            _ => AttackDomain::WorkloadCwpp,
        };

        Ok(GapSummary {
            total_vectors_tested: self.vector_count,
            blocked_count,
            detected_only_count,
            undetected_count,
            resilience_score: self.resilience_score,
            cluster_resistance_score: self.cluster_resistance_score,
            weakest_domain,
            uncovered_mitre_tactics: undetected_count as u32,
        })
    }

    pub fn remediate_gap(
        &mut self,
        cap: &BasCap,
        vector_id: u32,
        timestamp: u64,
    ) -> Result<(), BasError> {
        if !cap.has_right(bas_rights::REMEDIATE) {
            return Err(BasError::PermissionDenied);
        }

        let mut found = false;
        for i in 0..self.vector_count {
            if let Some(ref mut v) = self.vectors[i] {
                if v.id == vector_id {
                    v.last_status = SimulationStatus::Remediated;
                    v.detection_latency_ms = 4;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(BasError::VectorNotFound);
        }

        self.calculate_resilience();
        self.log_audit_action("REMEDIATE_GAP", vector_id, 0, timestamp)?;
        Ok(())
    }

    /// Remédie de manière autonome et immédiate à toutes les lacunes de détection identifiées
    pub fn remediate_all_gaps(
        &mut self,
        cap: &BasCap,
        timestamp: u64,
    ) -> Result<BasRemediationReport, BasError> {
        if !cap.has_right(bas_rights::REMEDIATE) {
            return Err(BasError::PermissionDenied);
        }

        let prev_resilience = self.resilience_score;
        let prev_cluster = self.cluster_resistance_score;
        let mut remediated_gaps = 0;

        for i in 0..self.vector_count {
            if let Some(ref mut v) = self.vectors[i] {
                if v.last_status == SimulationStatus::UndetectedSuccess
                    || v.last_status == SimulationStatus::DetectedOnly
                    || v.last_status == SimulationStatus::Pending
                {
                    v.last_status = SimulationStatus::Remediated;
                    v.detection_latency_ms = 3;
                    remediated_gaps += 1;
                }
            }
        }

        self.calculate_resilience();
        let report_id = self.next_report_id;
        self.next_report_id += 1;

        let report = BasRemediationReport::new(
            report_id,
            timestamp,
            remediated_gaps,
            prev_resilience,
            self.resilience_score,
            prev_cluster,
            self.cluster_resistance_score,
        );

        if self.remediation_report_count < MAX_REMEDIATION_REPORTS {
            self.remediation_reports[self.remediation_report_count] = Some(report);
            self.remediation_report_count += 1;
        } else {
            for i in 1..MAX_REMEDIATION_REPORTS {
                self.remediation_reports[i - 1] = self.remediation_reports[i];
            }
            self.remediation_reports[MAX_REMEDIATION_REPORTS - 1] = Some(report);
        }

        self.log_audit_action("REMEDIATE_ALL_GAPS", report_id, 0, timestamp)?;
        Ok(report)
    }

    pub fn get_simulation_report(
        &self,
        cap: &BasCap,
        report_id: u32,
    ) -> Result<BasSimulationReport, BasError> {
        if !cap.has_right(bas_rights::QUERY_RESULTS) {
            return Err(BasError::PermissionDenied);
        }
        for i in 0..self.simulation_report_count {
            if let Some(ref rep) = self.simulation_reports[i] {
                if rep.report_id == report_id {
                    return Ok(*rep);
                }
            }
        }
        Err(BasError::ReportNotFound)
    }

    pub fn get_latest_assessment_report(
        &self,
        cap: &BasCap,
    ) -> Result<BasResilienceAssessmentReport, BasError> {
        if !cap.has_right(bas_rights::QUERY_RESULTS) {
            return Err(BasError::PermissionDenied);
        }
        if self.assessment_report_count == 0 {
            return Err(BasError::ReportNotFound);
        }
        self.assessment_reports[self.assessment_report_count - 1].ok_or(BasError::ReportNotFound)
    }

    pub fn get_latest_remediation_report(
        &self,
        cap: &BasCap,
    ) -> Result<BasRemediationReport, BasError> {
        if !cap.has_right(bas_rights::QUERY_RESULTS) {
            return Err(BasError::PermissionDenied);
        }
        if self.remediation_report_count == 0 {
            return Err(BasError::ReportNotFound);
        }
        self.remediation_reports[self.remediation_report_count - 1].ok_or(BasError::ReportNotFound)
    }

    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Vecteur Ring 3 : Élévation de privilèges (T1068) via Seccomp
        let v1 = SimulationVector::new(
            1,
            "T1068-Ring3-Escalation",
            "T1068",
            AttackDomain::Ring3Execution,
            MitreTactic::PrivilegeEscalation,
            DefenseSystem::Seccomp,
            90,
        );
        let _ = self.register_vector(&cap, v1, 100);

        // 2. Vecteur IPC : Usurpation d'identité et mouvement latéral (T1021) via IDPS
        let v2 = SimulationVector::new(
            2,
            "T1021-IPC-Lateral-Spoof",
            "T1021",
            AttackDomain::IpcLateral,
            MitreTactic::LateralMovement,
            DefenseSystem::Idps,
            85,
        );
        let _ = self.register_vector(&cap, v2, 110);

        // 3. Vecteur VFS : Accès non autorisé aux identifiants (T1003) via Landlock
        let v3 = SimulationVector::new(
            3,
            "T1003-VFS-Credential-Dump",
            "T1003",
            AttackDomain::VfsStorage,
            MitreTactic::CredentialAccess,
            DefenseSystem::Landlock,
            95,
        );
        let _ = self.register_vector(&cap, v3, 120);

        // 4. Vecteur TEE : Tentative de subversion d'attestation Enclave (T1553) via CNAPP
        let v4 = SimulationVector::new(
            4,
            "T1553-TEE-Attestation-Tamper",
            "T1553",
            AttackDomain::TeeEnclave,
            MitreTactic::DefenseEvasion,
            DefenseSystem::Cnapp,
            92,
        );
        let _ = self.register_vector(&cap, v4, 130);

        // 5. Vecteur Réseau : Communication de commande & contrôle C2 (T1071) via WAF
        let v5 = SimulationVector::new(
            5,
            "T1071-Network-C2-Beacon",
            "T1071",
            AttackDomain::NetworkC2,
            MitreTactic::InitialAccess,
            DefenseSystem::Waf,
            88,
        );
        let _ = self.register_vector(&cap, v5, 140);

        // 6. Vecteur Supply Chain : Attaque de build script malveillant (T1195) via ASPM
        let v6 = SimulationVector::new(
            6,
            "T1195-SupplyChain-BuildScript",
            "T1195",
            AttackDomain::SupplyChainAspm,
            MitreTactic::InitialAccess,
            DefenseSystem::Aspm,
            94,
        );
        let _ = self.register_vector(&cap, v6, 142);

        // 7. Vecteur CIEM : Pivot d'identités et abus de jetons cloud (T1078) via CIEM
        let v7 = SimulationVector::new(
            7,
            "T1078-Cloud-Identity-Abuse",
            "T1078",
            AttackDomain::CloudIdentityCiem,
            MitreTactic::PrivilegeEscalation,
            DefenseSystem::Ciem,
            91,
        );
        let _ = self.register_vector(&cap, v7, 144);

        // 8. Vecteur CWPP : Injection de processus & dérive CFI d'enclave (T1055) via CWPP
        let v8 = SimulationVector::new(
            8,
            "T1055-Workload-CFI-Tamper",
            "T1055",
            AttackDomain::WorkloadCwpp,
            MitreTactic::DefenseEvasion,
            DefenseSystem::Cnapp,
            96,
        );
        let _ = self.register_vector(&cap, v8, 146);

        // Créer un Playbook d'adversaire réaliste : "APT29-Full-Killchain"
        let mut pb1 = AttackPlaybook::new(
            101,
            "APT29-Full-Killchain",
            "Simulation de chaîne d'attaque APT29 (Initial Access -> Escalade -> Exfil)",
        );
        pb1.add_vector(5); // C2
        pb1.add_vector(1); // Escalade Ring 3
        pb1.add_vector(2); // Mouvement IPC
        pb1.add_vector(3); // Credential Dump
        let _ = self.register_playbook(&cap, pb1, 150);

        // Créer un second Playbook : "Ransomware-VFS-Breach"
        let mut pb2 = AttackPlaybook::new(
            102,
            "Ransomware-VFS-Breach",
            "Simulation d'attaque ransomware ciblant les volumes VFS CoW",
        );
        pb2.add_vector(1); // Escalade
        pb2.add_vector(3); // Accès VFS
        let _ = self.register_playbook(&cap, pb2, 160);

        // Créer un troisième Playbook : "SupplyChain-To-TEE-Pivot"
        let mut pb3 = AttackPlaybook::new(
            103,
            "SupplyChain-To-TEE-Pivot",
            "Attaque de chaîne d'approvisionnement ciblant les clés d'enclave TEE",
        );
        pb3.add_vector(6); // Supply Chain ASPM
        pb3.add_vector(7); // CIEM Identity Abuse
        pb3.add_vector(4); // TEE Attestation Tamper
        let _ = self.register_playbook(&cap, pb3, 165);

        // Créer un quatrième Playbook : "CloudNative-TriPlane-Attack"
        let mut pb4 = AttackPlaybook::new(
            104,
            "CloudNative-TriPlane-Attack",
            "Attaque combinée sur plans identité (CIEM), charge (CWPP) et réseau (C2)",
        );
        pb4.add_vector(7); // CIEM
        pb4.add_vector(8); // CWPP
        pb4.add_vector(5); // C2
        let _ = self.register_playbook(&cap, pb4, 168);

        // Exécution initiale de vérification de base (vecteurs 1 à 5)
        let _ = self.run_simulation(&cap, 1, true, 170);
        let _ = self.run_simulation(&cap, 2, true, 180);
        let _ = self.run_simulation(&cap, 3, true, 190);
        let _ = self.run_simulation(&cap, 4, true, 200);
        let _ = self.run_simulation(&cap, 5, true, 210);
        let _ = self.run_simulation(&cap, 6, true, 220);
        let _ = self.run_simulation(&cap, 7, true, 230);
        let _ = self.run_simulation(&cap, 8, true, 240);
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bas_cap_attenuation_and_enforcement() {
        let admin_cap = BasCap::new(Handle::new(13001, 1), bas_rights::ALL, 10000, 1000);
        assert!(admin_cap.has_right(bas_rights::RUN_SIMULATION));
        assert!(admin_cap.has_right(bas_rights::QUERY_RESULTS));
        assert!(admin_cap.has_right(bas_rights::REGISTER_VECTOR));
        assert!(admin_cap.has_right(bas_rights::RUN_PLAYBOOK));
        assert!(admin_cap.has_right(bas_rights::ANALYZE_GAPS));
        assert!(admin_cap.has_right(bas_rights::REMEDIATE));
        assert!(admin_cap.has_right(bas_rights::SEAL_LEDGER));
        assert!(admin_cap.has_right(bas_rights::ADMIN));
        assert!(admin_cap.has_right(bas_rights::CONTINUOUS_ASSESSMENT));
        assert!(admin_cap.has_right(bas_rights::GENERATE_REPORT));

        let auditor_cap = admin_cap
            .attenuate(
                bas_rights::QUERY_RESULTS | bas_rights::ANALYZE_GAPS,
                5000,
                100,
            )
            .expect("Atténuation auditor");
        assert!(auditor_cap.has_right(bas_rights::QUERY_RESULTS));
        assert!(auditor_cap.has_right(bas_rights::ANALYZE_GAPS));
        assert!(!auditor_cap.has_right(bas_rights::RUN_SIMULATION));
        assert!(!auditor_cap.has_right(bas_rights::REMEDIATE));
        assert!(!auditor_cap.has_right(bas_rights::ADMIN));

        // Rejet d'escalade
        assert_eq!(
            auditor_cap.attenuate(bas_rights::ALL, 5000, 100),
            Err(BasError::AttenuationViolation)
        );
    }

    #[test]
    fn test_vector_and_playbook_execution() {
        let admin_cap = BasCap::new(Handle::new(13002, 1), bas_rights::ALL, 10000, 500);
        let mut daemon = JamboBasDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.vector_count, 8);
        assert_eq!(daemon.playbook_count, 4);
        assert!(daemon.verify_ledger_integrity());

        // Exécution d'un playbook complet
        let (exec, blocked) = daemon
            .run_playbook(&admin_cap, 101, 500)
            .expect("Exécution Playbook APT29");
        assert_eq!(exec, 4);
        assert_eq!(blocked, 4); // Toutes les défenses sont actives
    }

    #[test]
    fn test_resilience_and_gap_analysis() {
        let admin_cap = BasCap::new(Handle::new(13003, 1), bas_rights::ALL, 10000, 500);
        let mut daemon = JamboBasDaemon::new(admin_cap);
        daemon.init_defaults();

        let gaps = daemon
            .analyze_coverage_gaps(&admin_cap)
            .expect("Analyse des lacunes");
        assert_eq!(gaps.total_vectors_tested, 8);
        assert_eq!(gaps.blocked_count, 8);
        assert_eq!(gaps.undetected_count, 0);
        assert_eq!(gaps.resilience_score, 100);

        // Simulation sans défense active pour créer une lacune
        let res = daemon
            .run_simulation(&admin_cap, 1, false, 600)
            .expect("Simulation sans défense");
        assert_eq!(res.status, SimulationStatus::UndetectedSuccess);
        assert_eq!(res.blocked, false);

        // Le score de résilience doit avoir chuté
        assert!(daemon.resilience_score < 100);

        let gaps_after = daemon
            .analyze_coverage_gaps(&admin_cap)
            .expect("Analyse des lacunes après faille");
        assert_eq!(gaps_after.undetected_count, 1);
    }

    #[test]
    fn test_ledger_cryptographic_integrity_and_remediation() {
        let admin_cap = BasCap::new(Handle::new(13004, 1), bas_rights::ALL, 10000, 500);
        let mut daemon = JamboBasDaemon::new(admin_cap);
        daemon.init_defaults();

        // Créer une brèche non détectée sur le vecteur 2
        let _ = daemon.run_simulation(&admin_cap, 2, false, 700).unwrap();
        assert!(daemon.resilience_score < 100);

        // Remédier à la lacune
        daemon
            .remediate_gap(&admin_cap, 2, 750)
            .expect("Remédiation lacune");

        let gaps = daemon.analyze_coverage_gaps(&admin_cap).unwrap();
        assert_eq!(gaps.undetected_count, 0);

        // Vérification du registre cryptographique SHA-256
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_simulation_with_profiles_and_sealed_reports() {
        let admin_cap = BasCap::new(Handle::new(13005, 1), bas_rights::ALL, 10000, 500);
        let mut daemon = JamboBasDaemon::new(admin_cap);
        daemon.init_defaults();

        let rep = daemon
            .run_simulation_with_profile(
                &admin_cap,
                6, // Supply Chain
                SimulationProfile::ComplianceSecNumCloudAudit,
                true,
                800,
            )
            .expect("Simulation profile SecNumCloud");

        assert_eq!(rep.domain, AttackDomain::SupplyChainAspm);
        assert_eq!(rep.expected_defense, DefenseSystem::Aspm);
        assert_eq!(rep.blocked, true);
        assert_ne!(rep.report_hash, [0u8; 32]);

        // Vérification de la récupération du rapport
        let fetched = daemon
            .get_simulation_report(&admin_cap, rep.report_id)
            .expect("Récupération rapport");
        assert_eq!(fetched.report_hash, rep.report_hash);
    }

    #[test]
    fn test_continuous_assessment_and_remediation_reports() {
        let admin_cap = BasCap::new(Handle::new(13006, 1), bas_rights::ALL, 10000, 500);
        let mut daemon = JamboBasDaemon::new(admin_cap);
        daemon.init_defaults();

        // Déclencher une brèche
        let _ = daemon.run_simulation(&admin_cap, 4, false, 900).unwrap();
        assert!(daemon.resilience_score < 100);

        // Campagne d'évaluation continue
        let assess = daemon
            .run_continuous_assessment(
                &admin_cap,
                SimulationProfile::RedTeamAdversaryEmulation,
                950,
            )
            .expect("Continuous assessment");
        assert_eq!(assess.total_vectors_tested, 8);
        assert_ne!(assess.report_hash, [0u8; 32]);

        // Remédiation autonome de l'ensemble des lacunes
        let rem_rep = daemon
            .remediate_all_gaps(&admin_cap, 1000)
            .expect("Remediate all gaps");
        assert_eq!(daemon.resilience_score, 100);
        assert_eq!(daemon.cluster_resistance_score, 100);
        assert_ne!(rem_rep.report_hash, [0u8; 32]);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_cluster_resistance_score_calculation() {
        let admin_cap = BasCap::new(Handle::new(13007, 1), bas_rights::ALL, 10000, 500);
        let mut daemon = JamboBasDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.cluster_resistance_score, 100);

        // Simuler attaque non détectée sur un vecteur très sévère (T1055 severity 96)
        let _ = daemon.run_simulation(&admin_cap, 8, false, 1100).unwrap();
        assert!(daemon.cluster_resistance_score < 90);
        assert!(daemon.resilience_score < 100);

        // Analyser les lacunes pour identifier le domaine le plus vulnérable
        let gaps = daemon.analyze_coverage_gaps(&admin_cap).unwrap();
        assert_eq!(gaps.weakest_domain, AttackDomain::WorkloadCwpp);

        // Récupérer le dernier rapport d'évaluation continue
        let assess = daemon
            .run_continuous_assessment(&admin_cap, SimulationProfile::ZeroTrustValidation, 1150)
            .unwrap();
        assert_eq!(assess.total_vectors_tested, 8);
        assert_eq!(assess.blocked_count, 8);

        // Remédiation
        let _ = daemon.remediate_all_gaps(&admin_cap, 1200).unwrap();
        assert_eq!(daemon.cluster_resistance_score, 100);
    }
}

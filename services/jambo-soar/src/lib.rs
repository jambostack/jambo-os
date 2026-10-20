//! Orchestration de Sécurité, Automatisation & Réponse aux Incidents (`jambo-soar`)
//!
//! Phase 117 — Jalon v0.2.115
//!
//! Fournit un système souverain SOAR (Security Orchestration, Automation and Response)
//! entièrement `#![no_std]` :
//!
//! 1. Contrôle d'Accès Capabilaire Strict (`SoarCap`) :
//!    - Zéro autorité ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone sans amplification de privilèges.
//!    - Droits : `EXECUTE_PLAYBOOK`, `TRIGGER_INCIDENT`, `REGISTER_PLAYBOOK`,
//!      `MANAGE_INTEGRATIONS`, `ISOLATE_ENTITY`, `REVOKE_CAPABILITY`, `AUDIT_INSPECT`, `ADMIN`.
//!
//! 2. Gestion des Incidents de Sécurité & Fingerprinting SHA-256 :
//!    - Modélisation typée des incidents (`IncidentSeverity`, `IncidentCategory`, `IncidentStatus`).
//!    - Corrélation multi-sources (`jambo-waf`, `jambo-ddos`, `jambo-ids`, `jambo-siem`).
//!    - Empreinte cryptographique unique calculée par SHA-256.
//!
//! 3. Moteur de Workflows & Playbooks Conditionnels en Graphe Acyclique Dirigé (DAG) :
//!    - Définition d'étapes ordonnées avec dépendances explicites (`depends_on`).
//!    - Validation formelle anti-cycles et ordonnancement topologique.
//!    - Actions typées : `BlockIp`, `ApplyRateLimit`, `QuarantineWafPattern`, `RevokeCapability`,
//!      `IsolateProcess`, `CaptureMemoryForensics`, `NotifySecurityAdmin`, `EnforceMlsContainment`.
//!
//! 4. Intégrations Croisées Multi-Composants :
//!    - Répartition et exécution simulée/réelle d'actions vers `jambo-walld`, `jambo-ddos`, `jambo-waf`, `jambo-ids`.
//!    - Journal d'actions distribuées avec horodatage monotone et code retour.
//!
//! 5. Registre d'Audit Cryptographique Inaltérable SHA-256 en Chaîne de Hachage.

#![no_std]

use libjambo::Handle;

fn to_fixed_16(s: &str) -> [u8; 16] {
    let mut arr = [0u8; 16];
    let bytes = s.as_bytes();
    let len = bytes.len().min(16);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

fn to_fixed_48(s: &str) -> [u8; 48] {
    let mut arr = [0u8; 48];
    let bytes = s.as_bytes();
    let len = bytes.len().min(48);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

/// Droits granulaires pour la capacité `SoarCap`.
pub mod soar_rights {
    pub const EXECUTE_PLAYBOOK: u32 = 1 << 0;
    pub const TRIGGER_INCIDENT: u32 = 1 << 1;
    pub const REGISTER_PLAYBOOK: u32 = 1 << 2;
    pub const MANAGE_INTEGRATIONS: u32 = 1 << 3;
    pub const ISOLATE_ENTITY: u32 = 1 << 4;
    pub const REVOKE_CAPABILITY: u32 = 1 << 5;
    pub const AUDIT_INSPECT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = EXECUTE_PLAYBOOK
        | TRIGGER_INCIDENT
        | REGISTER_PLAYBOOK
        | MANAGE_INTEGRATIONS
        | ISOLATE_ENTITY
        | REVOKE_CAPABILITY
        | AUDIT_INSPECT
        | ADMIN;
}

/// Erreurs spécifiques au moteur SOAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoarError {
    PermissionDenied,
    PlaybookNotFound,
    IncidentNotFound,
    InvalidDagDependency,
    CyclicDependency,
    StepExecutionFailed,
    TableFull,
    AttenuationViolation,
    ExpiredCapability,
    InvocationsExhausted,
    DisabledPlaybook,
}

/// Capacité de sécurité SOAR respectant le principe de moindre privilège.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoarCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl SoarCap {
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
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, SoarError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SoarError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(SoarError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(SoarError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn consume_invocation(&mut self) -> Result<(), SoarError> {
        if self.invocations_left == 0 {
            return Err(SoarError::InvocationsExhausted);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

/// Sévérité normalisée d'un incident de sécurité.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Catégorie d'attaque ou anomalie opérationnelle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncidentCategory {
    DDoSFlood,
    SqlInjection,
    XssPayload,
    PathTraversal,
    RceAttempt,
    BruteForce,
    PrivilegeEscalation,
    LateralMovement,
    DataExfiltration,
    Ransomware,
    SystemAnomaly,
}

/// État du cycle de vie d'un incident de sécurité.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncidentStatus {
    New,
    Triaged,
    InProgress,
    Mitigated,
    Escalated,
    Resolved,
    FalsePositive,
}

/// Incident de sécurité orchestré par le moteur SOAR.
#[derive(Clone, Copy, Debug)]
pub struct Incident {
    pub id: u64,
    pub title: [u8; 64],
    pub title_len: usize,
    pub category: IncidentCategory,
    pub severity: IncidentSeverity,
    pub source_service: [u8; 32],
    pub source_len: usize,
    pub attacker_ip: [u8; 4],
    pub attacker_port: u16,
    pub target_pid: Option<u32>,
    pub target_handle: Option<u64>,
    pub timestamp: u64,
    pub status: IncidentStatus,
    pub fingerprint: [u8; 32],
    pub mitigated_by_playbook: Option<u32>,
}

impl Incident {
    pub fn new(
        id: u64,
        title_str: &str,
        category: IncidentCategory,
        severity: IncidentSeverity,
        source_str: &str,
        attacker_ip: [u8; 4],
        attacker_port: u16,
        target_pid: Option<u32>,
        target_handle: Option<u64>,
        timestamp: u64,
    ) -> Self {
        let mut title = [0u8; 64];
        let t_bytes = title_str.as_bytes();
        let title_len = t_bytes.len().min(64);
        title[..title_len].copy_from_slice(&t_bytes[..title_len]);

        let mut source_service = [0u8; 32];
        let s_bytes = source_str.as_bytes();
        let source_len = s_bytes.len().min(32);
        source_service[..source_len].copy_from_slice(&s_bytes[..source_len]);

        let mut incident = Self {
            id,
            title,
            title_len,
            category,
            severity,
            source_service,
            source_len,
            attacker_ip,
            attacker_port,
            target_pid,
            target_handle,
            timestamp,
            status: IncidentStatus::New,
            fingerprint: [0u8; 32],
            mitigated_by_playbook: None,
        };

        incident.recompute_fingerprint();
        incident
    }

    pub fn recompute_fingerprint(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(&self.id.to_be_bytes());
        hasher.update(&self.title[..self.title_len]);
        hasher.update(&[self.category as u8, self.severity as u8]);
        hasher.update(&self.source_service[..self.source_len]);
        hasher.update(&self.attacker_ip);
        hasher.update(&self.attacker_port.to_be_bytes());
        if let Some(pid) = self.target_pid {
            hasher.update(&pid.to_be_bytes());
        }
        if let Some(handle) = self.target_handle {
            hasher.update(&handle.to_be_bytes());
        }
        hasher.update(&self.timestamp.to_be_bytes());
        self.fingerprint = hasher.finalize();
    }
}

/// Cible de blocage réseau IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTarget {
    Walld,
    DdosBlackhole,
    Both,
}

/// Action unitaire SOAR pouvant être exécutée au sein d'une étape de playbook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoarAction {
    BlockIp {
        ip: [u8; 4],
        duration_secs: u32,
        target: BlockTarget,
    },
    ApplyRateLimit {
        ip: [u8; 4],
        token_rate: u32,
        bucket_size: u32,
    },
    QuarantineWafPattern {
        pattern: [u8; 32],
        pattern_len: usize,
    },
    RevokeCapability {
        handle_id: u64,
    },
    IsolateProcess {
        pid: u32,
    },
    CaptureMemoryForensics {
        pid: u32,
    },
    NotifySecurityAdmin {
        channel: [u8; 16],
        channel_len: usize,
        note: [u8; 48],
        note_len: usize,
    },
    EnforceMlsContainment {
        min_level: u8,
    },
}

/// État d'avancement d'une étape de playbook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

/// Étape individuelle d'un workflow de playbook avec dépendances DAG.
#[derive(Clone, Copy, Debug)]
pub struct PlaybookStep {
    pub step_id: u8,
    pub name: [u8; 32],
    pub name_len: usize,
    pub action: SoarAction,
    pub depends_on: [u8; 4],
    pub num_depends: usize,
    pub is_critical: bool,
    pub status: StepStatus,
}

impl PlaybookStep {
    pub fn new(step_id: u8, name_str: &str, action: SoarAction, is_critical: bool) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let name_len = bytes.len().min(32);
        name[..name_len].copy_from_slice(&bytes[..name_len]);

        Self {
            step_id,
            name,
            name_len,
            action,
            depends_on: [0u8; 4],
            num_depends: 0,
            is_critical,
            status: StepStatus::Pending,
        }
    }

    pub fn with_dependency(mut self, dep_id: u8) -> Self {
        if self.num_depends < 4 {
            self.depends_on[self.num_depends] = dep_id;
            self.num_depends += 1;
        }
        self
    }
}

pub const MAX_STEPS_PER_PLAYBOOK: usize = 8;
pub const MAX_PLAYBOOKS: usize = 16;
pub const MAX_INCIDENTS: usize = 64;
pub const MAX_DISPATCHED_ACTIONS: usize = 64;
pub const MAX_AUDIT_LOGS: usize = 64;

/// Playbook automatisé d'atténuation d'incidents.
#[derive(Clone, Copy, Debug)]
pub struct Playbook {
    pub id: u32,
    pub name: [u8; 48],
    pub name_len: usize,
    pub trigger_category: Option<IncidentCategory>,
    pub min_severity: IncidentSeverity,
    pub steps: [PlaybookStep; MAX_STEPS_PER_PLAYBOOK],
    pub steps_count: usize,
    pub is_enabled: bool,
    pub executions_count: u32,
    pub success_count: u32,
}

impl Playbook {
    pub fn new(
        id: u32,
        name_str: &str,
        trigger_category: Option<IncidentCategory>,
        min_severity: IncidentSeverity,
    ) -> Self {
        let mut name = [0u8; 48];
        let bytes = name_str.as_bytes();
        let name_len = bytes.len().min(48);
        name[..name_len].copy_from_slice(&bytes[..name_len]);

        let dummy_step = PlaybookStep::new(0, "", SoarAction::IsolateProcess { pid: 0 }, false);

        Self {
            id,
            name,
            name_len,
            trigger_category,
            min_severity,
            steps: [dummy_step; MAX_STEPS_PER_PLAYBOOK],
            steps_count: 0,
            is_enabled: true,
            executions_count: 0,
            success_count: 0,
        }
    }

    pub fn add_step(&mut self, step: PlaybookStep) -> Result<(), SoarError> {
        if self.steps_count >= MAX_STEPS_PER_PLAYBOOK {
            return Err(SoarError::TableFull);
        }
        self.steps[self.steps_count] = step;
        self.steps_count += 1;
        Ok(())
    }

    /// Valide l'absence de cycles et la conformité du graphe acyclique dirigé (DAG).
    pub fn validate_dag(&self) -> Result<(), SoarError> {
        for i in 0..self.steps_count {
            let step = &self.steps[i];
            for d in 0..step.num_depends {
                let dep_id = step.depends_on[d];
                if dep_id == step.step_id {
                    return Err(SoarError::CyclicDependency);
                }
                // Vérifier que la dépendance existe
                let exists = (0..self.steps_count).any(|idx| self.steps[idx].step_id == dep_id);
                if !exists {
                    return Err(SoarError::InvalidDagDependency);
                }
            }
        }

        // Vérification par élimination topologique (Kahn's algorithm sur tableau fixe)
        let mut in_degrees = [0u8; MAX_STEPS_PER_PLAYBOOK];
        for i in 0..self.steps_count {
            in_degrees[i] = self.steps[i].num_depends as u8;
        }

        let mut processed = 0usize;
        let mut queue = [0usize; MAX_STEPS_PER_PLAYBOOK];
        let mut q_head = 0usize;
        let mut q_tail = 0usize;

        for i in 0..self.steps_count {
            if in_degrees[i] == 0 {
                queue[q_tail] = i;
                q_tail += 1;
            }
        }

        while q_head < q_tail {
            let curr = queue[q_head];
            q_head += 1;
            processed += 1;
            let curr_id = self.steps[curr].step_id;

            // Décrémenter les étapes qui dépendent de curr_id
            for i in 0..self.steps_count {
                if in_degrees[i] > 0 {
                    for d in 0..self.steps[i].num_depends {
                        if self.steps[i].depends_on[d] == curr_id {
                            in_degrees[i] -= 1;
                            if in_degrees[i] == 0 {
                                queue[q_tail] = i;
                                q_tail += 1;
                            }
                        }
                    }
                }
            }
        }

        if processed != self.steps_count {
            return Err(SoarError::CyclicDependency);
        }

        Ok(())
    }
}

/// Sous-système cible d'une intégration de sécurité SOAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrationTarget {
    JamboWalld,
    JamboDdos,
    JamboWaf,
    JamboIds,
    JamboSiem,
}

/// Action distribuée exécutée auprès d'un sous-système externe.
#[derive(Clone, Copy, Debug)]
pub struct DispatchedAction {
    pub action_id: u64,
    pub timestamp: u64,
    pub target: IntegrationTarget,
    pub action_summary: [u8; 64],
    pub summary_len: usize,
    pub success: bool,
    pub response_code: u32,
}

/// Types d'événements du journal d'audit cryptographique.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoarAuditEventType {
    IncidentCreated = 1,
    PlaybookRegistered = 2,
    PlaybookExecuted = 3,
    ActionDispatched = 4,
    CapabilityRevoked = 5,
    NodeIsolated = 6,
    PolicyUpdated = 7,
}

/// Enregistrement inaltérable scellé par empreinte SHA-256.
#[derive(Clone, Copy, Debug)]
pub struct SoarAuditRecord {
    pub sequence: u64,
    pub timestamp: u64,
    pub event_type: SoarAuditEventType,
    pub incident_id: u64,
    pub playbook_id: u32,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

/// Résultat d'exécution d'un playbook SOAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoarExecutionResult {
    pub playbook_id: u32,
    pub incident_id: u64,
    pub steps_executed: usize,
    pub steps_succeeded: usize,
    pub steps_failed: usize,
    pub fully_mitigated: bool,
}

/// Implémentation souveraine de SHA-256 `#![no_std]` pour le scellement et les empreintes.
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
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

    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let buf_idx = (self.count % 64) as usize;
            self.buffer[buf_idx] = data[i];
            self.count += 1;
            if (self.count % 64) == 0 {
                self.transform();
            }
            i += 1;
        }
    }

    fn transform(&mut self) {
        let chunk = self.buffer;
        let mut w = [0u32; 64];
        let mut i = 0;
        while i < 16 {
            w[i] = ((chunk[i * 4] as u32) << 24)
                | ((chunk[i * 4 + 1] as u32) << 16)
                | ((chunk[i * 4 + 2] as u32) << 8)
                | (chunk[i * 4 + 3] as u32);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        let mut j = 0;
        while j < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[j])
                .wrapping_add(w[j]);
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
            j += 1;
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

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.count * 8;
        let buf_idx = (self.count % 64) as usize;
        self.buffer[buf_idx] = 0x80;

        if buf_idx >= 56 {
            let mut k = buf_idx + 1;
            while k < 64 {
                self.buffer[k] = 0;
                k += 1;
            }
            self.transform();
            let mut m = 0;
            while m < 56 {
                self.buffer[m] = 0;
                m += 1;
            }
        } else {
            let mut k = buf_idx + 1;
            while k < 56 {
                self.buffer[k] = 0;
                k += 1;
            }
        }

        let mut idx = 56;
        while idx < 64 {
            let shift = (63 - idx) * 8;
            self.buffer[idx] = (bit_len >> shift) as u8;
            idx += 1;
        }
        self.transform();

        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 8 {
            out[i * 4] = (self.state[i] >> 24) as u8;
            out[i * 4 + 1] = (self.state[i] >> 16) as u8;
            out[i * 4 + 2] = (self.state[i] >> 8) as u8;
            out[i * 4 + 3] = self.state[i] as u8;
            i += 1;
        }
        out
    }
}

/// Démon et moteur d'orchestration de sécurité SOAR souverain.
pub struct JamboSoarDaemon {
    pub admin_cap: SoarCap,
    pub incidents: [Option<Incident>; MAX_INCIDENTS],
    pub incident_count: usize,
    pub playbooks: [Option<Playbook>; MAX_PLAYBOOKS],
    pub playbook_count: usize,
    pub dispatched_actions: [Option<DispatchedAction>; MAX_DISPATCHED_ACTIONS],
    pub dispatched_count: usize,
    pub audit_records: [Option<SoarAuditRecord>; MAX_AUDIT_LOGS],
    pub audit_count: u64,
    pub audit_chain: [u8; 32],
}

impl JamboSoarDaemon {
    pub const GENESIS_HASH: [u8; 32] = [
        0x53, 0x4f, 0x41, 0x52, 0x2d, 0x4a, 0x41, 0x4d, 0x42, 0x4f, 0x2d, 0x4f, 0x53, 0x2d, 0x53,
        0x45, 0x43, 0x55, 0x52, 0x49, 0x54, 0x59, 0x2d, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53,
        0x45, 0x01,
    ];

    pub fn new(admin_cap: SoarCap) -> Self {
        Self {
            admin_cap,
            incidents: [None; MAX_INCIDENTS],
            incident_count: 0,
            playbooks: [None; MAX_PLAYBOOKS],
            playbook_count: 0,
            dispatched_actions: [None; MAX_DISPATCHED_ACTIONS],
            dispatched_count: 0,
            audit_records: [None; MAX_AUDIT_LOGS],
            audit_count: 0,
            audit_chain: Self::GENESIS_HASH,
        }
    }

    /// Initialise les playbooks par défaut pour les menaces courantes (DDoS, Injections WAF, Intrusion, Élévation).
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Playbook Anti-DDoS Automatisé
        let mut pb_ddos = Playbook::new(
            1,
            "PB-ANTI-DDOS-AUTO",
            Some(IncidentCategory::DDoSFlood),
            IncidentSeverity::High,
        );
        let s1 = PlaybookStep::new(
            1,
            "ApplyRateLimit",
            SoarAction::ApplyRateLimit {
                ip: [0, 0, 0, 0], // Sera surchargé dynamiquement avec l'IP de l'incident
                token_rate: 100,
                bucket_size: 50,
            },
            true,
        );
        let s2 = PlaybookStep::new(
            2,
            "BlackholeWalld",
            SoarAction::BlockIp {
                ip: [0, 0, 0, 0],
                duration_secs: 3600,
                target: BlockTarget::Both,
            },
            true,
        )
        .with_dependency(1);
        let s3 = PlaybookStep::new(
            3,
            "NotifySecOps",
            SoarAction::NotifySecurityAdmin {
                channel: to_fixed_16("secops-alerts"),
                channel_len: 13,
                note: to_fixed_48("Mitigation DDoS activee sur l'attaquant"),
                note_len: 39,
            },
            false,
        )
        .with_dependency(2);

        let _ = pb_ddos.add_step(s1);
        let _ = pb_ddos.add_step(s2);
        let _ = pb_ddos.add_step(s3);
        let _ = self.register_playbook(&cap, pb_ddos);

        // 2. Playbook Réponse Injection Applicative WAF (SQLi / RCE)
        let mut pb_waf = Playbook::new(
            2,
            "PB-WAF-INJECTION-RESPONSE",
            Some(IncidentCategory::SqlInjection),
            IncidentSeverity::High,
        );
        let w1 = PlaybookStep::new(
            1,
            "QuarantineWafPattern",
            SoarAction::QuarantineWafPattern {
                pattern: *b"UNION SELECT 1,2,3,4,table_name\0",
                pattern_len: 31,
            },
            true,
        );
        let w2 = PlaybookStep::new(
            2,
            "BlockAttackerIp",
            SoarAction::BlockIp {
                ip: [0, 0, 0, 0],
                duration_secs: 86400,
                target: BlockTarget::Walld,
            },
            true,
        )
        .with_dependency(1);
        let w3 = PlaybookStep::new(
            3,
            "CaptureForensics",
            SoarAction::CaptureMemoryForensics { pid: 0 },
            false,
        )
        .with_dependency(1);
        let w4 = PlaybookStep::new(
            4,
            "NotifySecAdmin",
            SoarAction::NotifySecurityAdmin {
                channel: to_fixed_16("waf-alerts"),
                channel_len: 10,
                note: to_fixed_48("Injection SQL neutralisee et IP bannie"),
                note_len: 38,
            },
            false,
        )
        .with_dependency(2)
        .with_dependency(3);

        let _ = pb_waf.add_step(w1);
        let _ = pb_waf.add_step(w2);
        let _ = pb_waf.add_step(w3);
        let _ = pb_waf.add_step(w4);
        let _ = self.register_playbook(&cap, pb_waf);

        // 3. Playbook Révocation Immédiate de Capacité Compromise & Confinement
        let mut pb_cap = Playbook::new(
            3,
            "PB-COMPROMISED-CAP-REVOCATION",
            Some(IncidentCategory::PrivilegeEscalation),
            IncidentSeverity::Critical,
        );
        let c1 = PlaybookStep::new(
            1,
            "RevokeCapability",
            SoarAction::RevokeCapability { handle_id: 0 },
            true,
        );
        let c2 = PlaybookStep::new(
            2,
            "IsolateProcess",
            SoarAction::IsolateProcess { pid: 0 },
            true,
        )
        .with_dependency(1);
        let c3 = PlaybookStep::new(
            3,
            "EnforceMlsContainment",
            SoarAction::EnforceMlsContainment { min_level: 3 },
            true,
        )
        .with_dependency(2);
        let c4 = PlaybookStep::new(
            4,
            "AlertSecOpsEmergency",
            SoarAction::NotifySecurityAdmin {
                channel: to_fixed_16("emergency-sec"),
                channel_len: 13,
                note: to_fixed_48("Escalade privilege stoppee : cap revoquee"),
                note_len: 41,
            },
            false,
        )
        .with_dependency(3);

        let _ = pb_cap.add_step(c1);
        let _ = pb_cap.add_step(c2);
        let _ = pb_cap.add_step(c3);
        let _ = pb_cap.add_step(c4);
        let _ = self.register_playbook(&cap, pb_cap);
    }

    /// Enregistre un playbook après vérification de la capacité et validation DAG.
    pub fn register_playbook(
        &mut self,
        cap: &SoarCap,
        playbook: Playbook,
    ) -> Result<u32, SoarError> {
        if !cap.has_right(soar_rights::REGISTER_PLAYBOOK) && !cap.has_right(soar_rights::ADMIN) {
            return Err(SoarError::PermissionDenied);
        }

        playbook.validate_dag()?;

        // Remplacement si existant
        for i in 0..self.playbook_count {
            if let Some(ref mut pb) = self.playbooks[i] {
                if pb.id == playbook.id {
                    *pb = playbook;
                    self.append_audit(SoarAuditEventType::PlaybookRegistered, 0, playbook.id, 100);
                    return Ok(playbook.id);
                }
            }
        }

        if self.playbook_count >= MAX_PLAYBOOKS {
            return Err(SoarError::TableFull);
        }

        let id = playbook.id;
        self.playbooks[self.playbook_count] = Some(playbook);
        self.playbook_count += 1;

        self.append_audit(SoarAuditEventType::PlaybookRegistered, 0, id, 100);
        Ok(id)
    }

    /// Crée et enregistre un nouvel incident de sécurité.
    pub fn create_incident(&mut self, cap: &SoarCap, incident: Incident) -> Result<u64, SoarError> {
        if !cap.has_right(soar_rights::TRIGGER_INCIDENT) && !cap.has_right(soar_rights::ADMIN) {
            return Err(SoarError::PermissionDenied);
        }

        if self.incident_count >= MAX_INCIDENTS {
            return Err(SoarError::TableFull);
        }

        let inc_id = incident.id;
        self.incidents[self.incident_count] = Some(incident);
        self.incident_count += 1;

        self.append_audit(
            SoarAuditEventType::IncidentCreated,
            inc_id,
            0,
            incident.timestamp,
        );
        Ok(inc_id)
    }

    /// Recherche le playbook le plus approprié pour un incident.
    pub fn find_matching_playbook(
        &self,
        category: IncidentCategory,
        severity: IncidentSeverity,
    ) -> Option<u32> {
        for i in 0..self.playbook_count {
            if let Some(ref pb) = self.playbooks[i] {
                if pb.is_enabled && pb.min_severity <= severity {
                    if let Some(cat) = pb.trigger_category {
                        if cat == category {
                            return Some(pb.id);
                        }
                    }
                }
            }
        }
        None
    }

    /// Exécute un playbook d'atténuation sur un incident identifié.
    pub fn execute_playbook(
        &mut self,
        cap: &SoarCap,
        playbook_id: u32,
        incident_id: u64,
        now: u64,
    ) -> Result<SoarExecutionResult, SoarError> {
        if !cap.has_right(soar_rights::EXECUTE_PLAYBOOK) && !cap.has_right(soar_rights::ADMIN) {
            return Err(SoarError::PermissionDenied);
        }

        // Trouver le playbook
        let pb_idx = (0..self.playbook_count)
            .find(|&i| {
                self.playbooks[i]
                    .as_ref()
                    .map_or(false, |p| p.id == playbook_id)
            })
            .ok_or(SoarError::PlaybookNotFound)?;

        let mut pb = self.playbooks[pb_idx].unwrap();
        if !pb.is_enabled {
            return Err(SoarError::DisabledPlaybook);
        }

        // Trouver l'incident
        let inc_idx = (0..self.incident_count)
            .find(|&i| {
                self.incidents[i]
                    .as_ref()
                    .map_or(false, |inc| inc.id == incident_id)
            })
            .ok_or(SoarError::IncidentNotFound)?;

        let mut incident = self.incidents[inc_idx].unwrap();
        incident.status = IncidentStatus::InProgress;

        let mut steps_executed = 0usize;
        let mut steps_succeeded = 0usize;
        let mut steps_failed = 0usize;
        let mut step_success_map = [false; MAX_STEPS_PER_PLAYBOOK];

        // Exécution ordonnée des étapes
        for i in 0..pb.steps_count {
            let mut step = pb.steps[i];

            // Vérifier que toutes les dépendances ont réussi
            let mut deps_ok = true;
            for d in 0..step.num_depends {
                let dep_id = step.depends_on[d];
                // Trouver le statut de la dépendance
                let dep_idx = (0..pb.steps_count).find(|&idx| pb.steps[idx].step_id == dep_id);
                if let Some(d_idx) = dep_idx {
                    if !step_success_map[d_idx] {
                        deps_ok = false;
                        break;
                    }
                } else {
                    deps_ok = false;
                    break;
                }
            }

            if !deps_ok {
                step.status = StepStatus::Skipped;
                pb.steps[i] = step;
                continue;
            }

            step.status = StepStatus::Running;
            steps_executed += 1;

            // Adapter l'action avec le contexte dynamique de l'incident si nécessaire
            let mut dynamic_action = step.action;
            match &mut dynamic_action {
                SoarAction::BlockIp { ip, .. } => {
                    if *ip == [0, 0, 0, 0] {
                        *ip = incident.attacker_ip;
                    }
                }
                SoarAction::ApplyRateLimit { ip, .. } => {
                    if *ip == [0, 0, 0, 0] {
                        *ip = incident.attacker_ip;
                    }
                }
                SoarAction::RevokeCapability { handle_id } => {
                    if *handle_id == 0 {
                        if let Some(h) = incident.target_handle {
                            *handle_id = h;
                        }
                    }
                }
                SoarAction::IsolateProcess { pid } => {
                    if *pid == 0 {
                        if let Some(p) = incident.target_pid {
                            *pid = p;
                        }
                    }
                }
                SoarAction::CaptureMemoryForensics { pid } => {
                    if *pid == 0 {
                        if let Some(p) = incident.target_pid {
                            *pid = p;
                        }
                    }
                }
                _ => {}
            }

            // Exécution / Dispatch de l'action
            let dispatch_res = self.dispatch_action(cap, dynamic_action, now);
            if dispatch_res.is_ok() {
                step.status = StepStatus::Completed;
                steps_succeeded += 1;
                step_success_map[i] = true;
            } else {
                step.status = StepStatus::Failed;
                steps_failed += 1;
                if step.is_critical {
                    pb.steps[i] = step;
                    break;
                }
            }
            pb.steps[i] = step;
        }

        pb.executions_count += 1;
        let fully_mitigated = steps_failed == 0 && steps_succeeded > 0;
        if fully_mitigated {
            pb.success_count += 1;
            incident.status = IncidentStatus::Mitigated;
            incident.mitigated_by_playbook = Some(playbook_id);
        } else {
            incident.status = IncidentStatus::Escalated;
        }

        self.playbooks[pb_idx] = Some(pb);
        self.incidents[inc_idx] = Some(incident);

        self.append_audit(
            SoarAuditEventType::PlaybookExecuted,
            incident_id,
            playbook_id,
            now,
        );

        Ok(SoarExecutionResult {
            playbook_id,
            incident_id,
            steps_executed,
            steps_succeeded,
            steps_failed,
            fully_mitigated,
        })
    }

    /// Dispatch d'une action unitaire vers un sous-système de sécurité cible.
    pub fn dispatch_action(
        &mut self,
        cap: &SoarCap,
        action: SoarAction,
        now: u64,
    ) -> Result<u64, SoarError> {
        // Contrôle de capacité selon l'action
        match action {
            SoarAction::RevokeCapability { .. } => {
                if !cap.has_right(soar_rights::REVOKE_CAPABILITY)
                    && !cap.has_right(soar_rights::ADMIN)
                {
                    return Err(SoarError::PermissionDenied);
                }
            }
            SoarAction::IsolateProcess { .. } | SoarAction::EnforceMlsContainment { .. } => {
                if !cap.has_right(soar_rights::ISOLATE_ENTITY) && !cap.has_right(soar_rights::ADMIN)
                {
                    return Err(SoarError::PermissionDenied);
                }
            }
            _ => {
                if !cap.has_right(soar_rights::MANAGE_INTEGRATIONS)
                    && !cap.has_right(soar_rights::EXECUTE_PLAYBOOK)
                    && !cap.has_right(soar_rights::ADMIN)
                {
                    return Err(SoarError::PermissionDenied);
                }
            }
        }

        let (target, summary_str) = match action {
            SoarAction::BlockIp { target, .. } => {
                let tgt = match target {
                    BlockTarget::Walld => IntegrationTarget::JamboWalld,
                    BlockTarget::DdosBlackhole => IntegrationTarget::JamboDdos,
                    BlockTarget::Both => IntegrationTarget::JamboWalld,
                };
                (tgt, "BlockIp dispatched")
            }
            SoarAction::ApplyRateLimit { .. } => {
                (IntegrationTarget::JamboDdos, "ApplyRateLimit dispatched")
            }
            SoarAction::QuarantineWafPattern { .. } => (
                IntegrationTarget::JamboWaf,
                "QuarantineWafPattern dispatched",
            ),
            SoarAction::RevokeCapability { .. } => {
                (IntegrationTarget::JamboIds, "RevokeCapability dispatched")
            }
            SoarAction::IsolateProcess { .. } => {
                (IntegrationTarget::JamboIds, "IsolateProcess dispatched")
            }
            SoarAction::CaptureMemoryForensics { .. } => {
                (IntegrationTarget::JamboSiem, "CaptureForensics dispatched")
            }
            SoarAction::NotifySecurityAdmin { .. } => (
                IntegrationTarget::JamboSiem,
                "NotifySecurityAdmin dispatched",
            ),
            SoarAction::EnforceMlsContainment { .. } => (
                IntegrationTarget::JamboIds,
                "EnforceMlsContainment dispatched",
            ),
        };

        let action_id = self.dispatched_count as u64 + 1;
        let mut summary = [0u8; 64];
        let bytes = summary_str.as_bytes();
        let summary_len = bytes.len().min(64);
        summary[..summary_len].copy_from_slice(&bytes[..summary_len]);

        let disp = DispatchedAction {
            action_id,
            timestamp: now,
            target,
            action_summary: summary,
            summary_len,
            success: true,
            response_code: 200,
        };

        let slot = self.dispatched_count % MAX_DISPATCHED_ACTIONS;
        self.dispatched_actions[slot] = Some(disp);
        self.dispatched_count += 1;

        self.append_audit(SoarAuditEventType::ActionDispatched, 0, 0, now);
        Ok(action_id)
    }

    /// Enregistre une entrée dans la chaîne de hachage SHA-256 inaltérable.
    pub fn append_audit(
        &mut self,
        event_type: SoarAuditEventType,
        incident_id: u64,
        playbook_id: u32,
        timestamp: u64,
    ) {
        let seq = self.audit_count + 1;
        let prev = self.audit_chain;

        let mut hasher = Sha256::new();
        hasher.update(&prev);
        hasher.update(&seq.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[event_type as u8]);
        hasher.update(&incident_id.to_be_bytes());
        hasher.update(&playbook_id.to_be_bytes());
        let entry_hash = hasher.finalize();

        let record = SoarAuditRecord {
            sequence: seq,
            timestamp,
            event_type,
            incident_id,
            playbook_id,
            prev_hash: prev,
            entry_hash,
        };

        let slot = (self.audit_count as usize) % MAX_AUDIT_LOGS;
        self.audit_records[slot] = Some(record);
        self.audit_chain = entry_hash;
        self.audit_count += 1;
    }

    /// Vérifie formellement l'intégrité de la chaîne de hachage d'audit.
    pub fn verify_audit_integrity(&self) -> bool {
        if self.audit_count == 0 {
            return self.audit_chain == Self::GENESIS_HASH;
        }

        let total = self.audit_count as usize;
        let start = if total > MAX_AUDIT_LOGS {
            total - MAX_AUDIT_LOGS
        } else {
            0
        };

        for i in start..total {
            let slot = i % MAX_AUDIT_LOGS;
            if let Some(ref rec) = self.audit_records[slot] {
                let mut hasher = Sha256::new();
                hasher.update(&rec.prev_hash);
                hasher.update(&rec.sequence.to_be_bytes());
                hasher.update(&rec.timestamp.to_be_bytes());
                hasher.update(&[rec.event_type as u8]);
                hasher.update(&rec.incident_id.to_be_bytes());
                hasher.update(&rec.playbook_id.to_be_bytes());
                let computed = hasher.finalize();
                if computed != rec.entry_hash {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cap() -> SoarCap {
        SoarCap::new(Handle::new(1, 0), soar_rights::ALL, 10000, 100)
    }

    #[test]
    fn test_soar_cap_monotonic_attenuation() {
        let root = create_test_cap();
        let att = root
            .attenuate(
                soar_rights::EXECUTE_PLAYBOOK | soar_rights::TRIGGER_INCIDENT,
                5000,
                50,
            )
            .expect("Atténuation valide");

        assert!(att.has_right(soar_rights::EXECUTE_PLAYBOOK));
        assert!(att.has_right(soar_rights::TRIGGER_INCIDENT));
        assert!(!att.has_right(soar_rights::ADMIN));
        assert!(!att.has_right(soar_rights::REVOKE_CAPABILITY));

        // Interdiction d'escalade de privilèges
        let err = att.attenuate(soar_rights::ALL, 5000, 50);
        assert_eq!(err, Err(SoarError::AttenuationViolation));

        // Interdiction d'augmentation de durée de vie
        let err_time = att.attenuate(soar_rights::EXECUTE_PLAYBOOK, 6000, 50);
        assert_eq!(err_time, Err(SoarError::AttenuationViolation));
    }

    #[test]
    fn test_playbook_dag_validation() {
        let mut pb = Playbook::new(1, "TestDAG", None, IncidentSeverity::Low);

        let s1 = PlaybookStep::new(1, "Step1", SoarAction::IsolateProcess { pid: 10 }, true);
        let s2 = PlaybookStep::new(2, "Step2", SoarAction::IsolateProcess { pid: 20 }, true)
            .with_dependency(1);
        let s3 = PlaybookStep::new(3, "Step3", SoarAction::IsolateProcess { pid: 30 }, false)
            .with_dependency(2);

        pb.add_step(s1).unwrap();
        pb.add_step(s2).unwrap();
        pb.add_step(s3).unwrap();

        assert_eq!(pb.validate_dag(), Ok(()));

        // Introduire un cycle
        let mut cyclic_pb = Playbook::new(2, "Cyclic", None, IncidentSeverity::Low);
        let c1 = PlaybookStep::new(1, "C1", SoarAction::IsolateProcess { pid: 1 }, true)
            .with_dependency(2);
        let c2 = PlaybookStep::new(2, "C2", SoarAction::IsolateProcess { pid: 2 }, true)
            .with_dependency(1);

        cyclic_pb.add_step(c1).unwrap();
        cyclic_pb.add_step(c2).unwrap();

        assert_eq!(cyclic_pb.validate_dag(), Err(SoarError::CyclicDependency));
    }

    #[test]
    fn test_incident_fingerprinting() {
        let inc1 = Incident::new(
            1001,
            "Attaque DDoS SYN Flood",
            IncidentCategory::DDoSFlood,
            IncidentSeverity::Critical,
            "jambo-ddos",
            [192, 168, 1, 100],
            443,
            None,
            None,
            12345678,
        );

        let inc2 = Incident::new(
            1002,
            "Attaque DDoS SYN Flood",
            IncidentCategory::DDoSFlood,
            IncidentSeverity::Critical,
            "jambo-ddos",
            [192, 168, 1, 101], // IP différente
            443,
            None,
            None,
            12345678,
        );

        assert_ne!(inc1.fingerprint, [0u8; 32]);
        assert_ne!(inc2.fingerprint, [0u8; 32]);
        assert_ne!(inc1.fingerprint, inc2.fingerprint);
    }

    #[test]
    fn test_soar_daemon_lifecycle() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        assert_eq!(daemon.playbook_count, 3);

        // Créer un incident
        let inc = Incident::new(
            1,
            "Flood DDoS massif détecté",
            IncidentCategory::DDoSFlood,
            IncidentSeverity::High,
            "jambo-ddos",
            [198, 51, 100, 42],
            80,
            None,
            None,
            1000,
        );

        let inc_id = daemon
            .create_incident(&cap, inc)
            .expect("Création incident");
        assert_eq!(inc_id, 1);

        // Détection de playbook correspondant
        let pb_id = daemon
            .find_matching_playbook(IncidentCategory::DDoSFlood, IncidentSeverity::High)
            .expect("Playbook trouvé");
        assert_eq!(pb_id, 1);

        // Exécution du playbook
        let result = daemon
            .execute_playbook(&cap, pb_id, inc_id, 1050)
            .expect("Exécution réussie");

        assert_eq!(result.playbook_id, 1);
        assert_eq!(result.incident_id, 1);
        assert!(result.fully_mitigated);
        assert_eq!(result.steps_succeeded, 3);
        assert_eq!(result.steps_failed, 0);

        let mitigated_inc = daemon.incidents[0].unwrap();
        assert_eq!(mitigated_inc.status, IncidentStatus::Mitigated);
        assert_eq!(mitigated_inc.mitigated_by_playbook, Some(1));

        // Intégrité de l'audit
        assert!(daemon.verify_audit_integrity());
        assert_ne!(daemon.audit_chain, JamboSoarDaemon::GENESIS_HASH);
    }

    #[test]
    fn test_unauthorized_execution() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        let no_exec_cap = cap
            .attenuate(soar_rights::AUDIT_INSPECT, 5000, 10)
            .expect("Atténuation");

        let inc = Incident::new(
            2,
            "Attaque SQL",
            IncidentCategory::SqlInjection,
            IncidentSeverity::High,
            "jambo-waf",
            [10, 0, 0, 5],
            80,
            None,
            None,
            2000,
        );

        // Incapable de créer incident sans droit TRIGGER_INCIDENT
        assert_eq!(
            daemon.create_incident(&no_exec_cap, inc),
            Err(SoarError::PermissionDenied)
        );

        daemon.create_incident(&cap, inc).unwrap();
        // Incapable d'exécuter playbook sans droit EXECUTE_PLAYBOOK
        assert_eq!(
            daemon.execute_playbook(&no_exec_cap, 2, 2, 2050),
            Err(SoarError::PermissionDenied)
        );
    }

    #[test]
    fn test_sql_injection_and_cap_revocation_playbooks() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        // 1. Test WAF SQL Injection Playbook
        let inc_waf = Incident::new(
            10,
            "SQL Injection detectee sur /api/login",
            IncidentCategory::SqlInjection,
            IncidentSeverity::High,
            "jambo-waf",
            [192, 168, 50, 10],
            443,
            Some(42),
            None,
            3000,
        );
        daemon.create_incident(&cap, inc_waf).unwrap();
        let res_waf = daemon.execute_playbook(&cap, 2, 10, 3010).unwrap();
        assert!(res_waf.fully_mitigated);
        assert_eq!(res_waf.steps_succeeded, 4);

        // 2. Test Escalade Privilege & Revocation de Capabilite
        let inc_priv = Incident::new(
            11,
            "Escalade de privilege Ring 3 illegitime",
            IncidentCategory::PrivilegeEscalation,
            IncidentSeverity::Critical,
            "jambo-ids",
            [127, 0, 0, 1],
            0,
            Some(105),
            Some(9999),
            4000,
        );
        daemon.create_incident(&cap, inc_priv).unwrap();
        let res_priv = daemon.execute_playbook(&cap, 3, 11, 4010).unwrap();
        assert!(res_priv.fully_mitigated);
        assert_eq!(res_priv.steps_succeeded, 4);

        assert!(daemon.verify_audit_integrity());
        assert!(daemon.audit_count >= 10);
    }

    #[test]
    fn test_disabled_playbook() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        // Désactiver le playbook 1
        if let Some(ref mut pb) = daemon.playbooks[0] {
            pb.is_enabled = false;
        }

        let inc = Incident::new(
            20,
            "DDoS",
            IncidentCategory::DDoSFlood,
            IncidentSeverity::High,
            "jambo-ddos",
            [1, 2, 3, 4],
            80,
            None,
            None,
            5000,
        );
        daemon.create_incident(&cap, inc).unwrap();

        let err = daemon.execute_playbook(&cap, 1, 20, 5010);
        assert_eq!(err, Err(SoarError::DisabledPlaybook));
    }
}

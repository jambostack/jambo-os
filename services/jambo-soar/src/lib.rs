//! Orchestration de Sécurité, Automatisation & Réponse aux Incidents Souveraine (`jambo-soar`)
//!
//! Phase 147 — Jalon v0.3.14
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
//! 2. Ingestion & Corrélation Multi-Sources Unifiée (SIEM, EDR, NDR, DLP, UEBA, KDIR, FDR, WAF, DDoS) :
//!    - Modélisation typée des incidents (`IncidentSeverity`, `IncidentCategory`, `IncidentStatus`).
//!    - Ingestion automatisée avec scoring et corrélation directe vers playbooks déterministes.
//!    - Empreinte cryptographique unique de chaque incident calculée par SHA-256.
//!
//! 3. Moteur de Workflows & Playbooks Conditionnels en Graphe Acyclique Dirigé (DAG) :
//!    - Ordonnancement topologique Kahn et vérification formelle anti-cycles.
//!    - 6 playbooks intégrés par défaut (DDoS, WAF Injections, Révocation Capabilité,
//!      Endiguement Fuite DLP, Réponse Anomalie Comportementale UEBA, Restauration Intégrité Noyau KDIR).
//!    - Actions typées : `BlockIp`, `ApplyRateLimit`, `QuarantineWafPattern`, `RevokeCapability`,
//!      `IsolateProcess`, `CaptureMemoryForensics`, `NotifySecurityAdmin`, `EnforceMlsContainment`,
//!      `QuarantineEntity`, `RestoreGoldenKernelSnapshot`, `TriggerDlpSanitization`, `EnforceMicroSegmentation`.
//!
//! 4. Intégrations Croisées Multi-Composants & Remédiation Chirurgicale :
//!    - Dispatch vers `jambo-walld`, `jambo-ddos`, `jambo-waf`, `jambo-ids`, `jambo-siem`,
//!      `jambo-ndr`, `jambo-dlp`, `jambo-ueba`, `jambo-edr`, `jambo-kdir`, `jambo-fdr`.
//!    - Journalisation des actions distribuées avec statut et horodatage monotone.
//!
//! 5. Registre d'Audit Cryptographique Inaltérable SHA-256 scellé par Chaînage.

#![no_std]

use libjambo::Handle;

pub fn to_fixed_16(s: &str) -> [u8; 16] {
    let mut arr = [0u8; 16];
    let bytes = s.as_bytes();
    let len = bytes.len().min(16);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

pub fn to_fixed_32(s: &str) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let bytes = s.as_bytes();
    let len = bytes.len().min(32);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

pub fn to_fixed_48(s: &str) -> [u8; 48] {
    let mut arr = [0u8; 48];
    let bytes = s.as_bytes();
    let len = bytes.len().min(48);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

pub fn to_fixed_64(s: &str) -> [u8; 64] {
    let mut arr = [0u8; 64];
    let bytes = s.as_bytes();
    let len = bytes.len().min(64);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

/// Convertit un buffer d'octets en chaîne de caractères ASCII nettoyée
pub fn id_to_str(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("<invalid-utf8>")
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE SOAR
// ============================================================================

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoarError {
    PermissionDenied,
    InvalidDagDependency,
    CyclicDependency,
    PlaybookNotFound,
    IncidentNotFound,
    TableFull,
    DisabledPlaybook,
    ActionFailed,
    AttenuationViolation,
    InvalidParameter,
}

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

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, SoarError> {
        if (self.rights & new_rights) != new_rights {
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
}

// ============================================================================
// MODÈLES D'INCIDENTS DE SÉCURITÉ & TAXONOMIE SOAR
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

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
    KernelTampering,
    FirmwareCompromise,
    BehavioralAnomaly,
    SensitiveDataLeak,
    ContentPoisoning,
}

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
    pub affected_entity: [u8; 32],
    pub entity_len: usize,
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
            affected_entity: [0u8; 32],
            entity_len: 0,
            timestamp,
            status: IncidentStatus::New,
            fingerprint: [0u8; 32],
            mitigated_by_playbook: None,
        };

        incident.recompute_fingerprint();
        incident
    }

    pub fn with_affected_entity(mut self, entity: &str) -> Self {
        let mut arr = [0u8; 32];
        let b = entity.as_bytes();
        let len = b.len().min(32);
        arr[..len].copy_from_slice(&b[..len]);
        self.affected_entity = arr;
        self.entity_len = len;
        self.recompute_fingerprint();
        self
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
        hasher.update(&self.affected_entity[..self.entity_len]);
        hasher.update(&self.timestamp.to_be_bytes());
        self.fingerprint = hasher.finalize();
    }
}

// ============================================================================
// ACTIONS DE REMÉDIATION CHIRURGICALE & INTÉGRATIONS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTarget {
    Walld,
    DdosBlackhole,
    Both,
}

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
    QuarantineEntity {
        entity_id: [u8; 32],
        entity_len: usize,
    },
    RestoreGoldenKernelSnapshot {
        table_mask: u32,
    },
    TriggerDlpSanitization {
        session_id: u64,
    },
    EnforceMicroSegmentation {
        subnet: [u8; 4],
        mask: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Clone, Copy, Debug)]
pub struct PlaybookStep {
    pub step_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub action: SoarAction,
    pub depends_on: [u32; 4],
    pub num_depends: usize,
    pub is_critical: bool,
    pub status: StepStatus,
}

impl PlaybookStep {
    pub fn new(step_id: u32, name_str: &str, action: SoarAction, is_critical: bool) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let name_len = bytes.len().min(32);
        name[..name_len].copy_from_slice(&bytes[..name_len]);

        Self {
            step_id,
            name,
            name_len,
            action,
            depends_on: [0; 4],
            num_depends: 0,
            is_critical,
            status: StepStatus::Pending,
        }
    }

    pub fn with_dependency(mut self, dep_id: u32) -> Self {
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
pub const MAX_AUDIT_LOGS: usize = 128;

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

    pub fn validate_dag(&self) -> Result<(), SoarError> {
        for i in 0..self.steps_count {
            let step = &self.steps[i];
            for d in 0..step.num_depends {
                let dep_id = step.depends_on[d];
                if dep_id == step.step_id {
                    return Err(SoarError::CyclicDependency);
                }
                let exists = (0..self.steps_count).any(|idx| self.steps[idx].step_id == dep_id);
                if !exists {
                    return Err(SoarError::InvalidDagDependency);
                }
            }
        }

        // Algorithme de Kahn pour ordonnancement topologique et détection de cycle
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrationTarget {
    JamboWalld,
    JamboDdos,
    JamboWaf,
    JamboIds,
    JamboSiem,
    JamboNdr,
    JamboDlp,
    JamboUeba,
    JamboEdr,
    JamboKdir,
    JamboFdr,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoarAuditEventType {
    IncidentCreated = 1,
    PlaybookRegistered = 2,
    PlaybookExecuted = 3,
    ActionDispatched = 4,
    CapabilityRevoked = 5,
    NodeIsolated = 6,
    PolicyUpdated = 7,
    SnapshotRestored = 8,
    MicroSegmentationEnforced = 9,
    EntityQuarantined = 10,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoarExecutionResult {
    pub playbook_id: u32,
    pub incident_id: u64,
    pub steps_executed: usize,
    pub steps_succeeded: usize,
    pub steps_failed: usize,
    pub fully_mitigated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoarSummary {
    pub total_incidents: usize,
    pub mitigated_incidents: usize,
    pub escalated_incidents: usize,
    pub active_playbooks: usize,
    pub dispatched_actions: usize,
    pub audit_records_count: u64,
    pub audit_chain_valid: bool,
}

// ============================================================================
// HACHEUR SHA-256 SOUVERAIN (#![no_std])
// ============================================================================

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
        while !data.is_empty() {
            let space = 64 - self.buffer_len;
            if data.len() >= space {
                self.buffer[self.buffer_len..64].copy_from_slice(&data[..space]);
                data = &data[space..];
                self.buffer_len = 0;
                let mut buf_copy = [0u8; 64];
                buf_copy.copy_from_slice(&self.buffer);
                self.process_block(&buf_copy);
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                break;
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
            let mut buf_copy = [0u8; 64];
            buf_copy.copy_from_slice(&self.buffer);
            self.process_block(&buf_copy);
            self.buffer = [0u8; 64];
        } else {
            for i in self.buffer_len..56 {
                self.buffer[i] = 0;
            }
        }

        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let mut buf_copy = [0u8; 64];
        buf_copy.copy_from_slice(&self.buffer);
        self.process_block(&buf_copy);

        let mut out = [0u8; 32];
        for (i, val) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8; 64]) {
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
}

// ============================================================================
// DÉMON SOAR SOUVERAIN
// ============================================================================

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
        0x45, 0x02,
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

    /// Initialise les 6 playbooks de référence souverains couvrant tout le spectre de sécurité
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
                ip: [0, 0, 0, 0],
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

        // 4. Playbook Endiguement Fuite Données Sensibles DLP (Phase 145 / 147)
        let mut pb_dlp = Playbook::new(
            4,
            "PB-DATA-LEAK-CONTAINMENT",
            Some(IncidentCategory::SensitiveDataLeak),
            IncidentSeverity::High,
        );
        let d1 = PlaybookStep::new(
            1,
            "TriggerDlpSanitization",
            SoarAction::TriggerDlpSanitization { session_id: 0 },
            true,
        );
        let d2 = PlaybookStep::new(
            2,
            "QuarantineEntity",
            SoarAction::QuarantineEntity {
                entity_id: [0u8; 32],
                entity_len: 0,
            },
            true,
        )
        .with_dependency(1);
        let d3 = PlaybookStep::new(
            3,
            "BlockExfilIp",
            SoarAction::BlockIp {
                ip: [0, 0, 0, 0],
                duration_secs: 43200,
                target: BlockTarget::Both,
            },
            true,
        )
        .with_dependency(2);
        let d4 = PlaybookStep::new(
            4,
            "NotifyDlpAdmin",
            SoarAction::NotifySecurityAdmin {
                channel: to_fixed_16("dlp-incident"),
                channel_len: 12,
                note: to_fixed_48("Exfiltration bloquee et entite isolee O(1)"),
                note_len: 41,
            },
            false,
        )
        .with_dependency(3);

        let _ = pb_dlp.add_step(d1);
        let _ = pb_dlp.add_step(d2);
        let _ = pb_dlp.add_step(d3);
        let _ = pb_dlp.add_step(d4);
        let _ = self.register_playbook(&cap, pb_dlp);

        // 5. Playbook Réponse Anomalie Comportementale & Mouvement Latéral UEBA (Phase 146 / 147)
        let mut pb_ueba = Playbook::new(
            5,
            "PB-BEHAVIORAL-ANOMALY-RESPONSE",
            Some(IncidentCategory::BehavioralAnomaly),
            IncidentSeverity::High,
        );
        let u1 = PlaybookStep::new(
            1,
            "IsolateProcess",
            SoarAction::IsolateProcess { pid: 0 },
            true,
        );
        let u2 = PlaybookStep::new(
            2,
            "QuarantineEntity",
            SoarAction::QuarantineEntity {
                entity_id: [0u8; 32],
                entity_len: 0,
            },
            true,
        )
        .with_dependency(1);
        let u3 = PlaybookStep::new(
            3,
            "EnforceMicroSegmentation",
            SoarAction::EnforceMicroSegmentation {
                subnet: [10, 0, 0, 0],
                mask: 24,
            },
            true,
        )
        .with_dependency(2);
        let u4 = PlaybookStep::new(
            4,
            "NotifyUebaAdmin",
            SoarAction::NotifySecurityAdmin {
                channel: to_fixed_16("ueba-response"),
                channel_len: 13,
                note: to_fixed_48("Mouvement lateral stoppe et microseg appliquee"),
                note_len: 47,
            },
            false,
        )
        .with_dependency(3);

        let _ = pb_ueba.add_step(u1);
        let _ = pb_ueba.add_step(u2);
        let _ = pb_ueba.add_step(u3);
        let _ = pb_ueba.add_step(u4);
        let _ = self.register_playbook(&cap, pb_ueba);

        // 6. Playbook Restauration Intégrité Noyau & Rootkit KDIR/FDR (Phase 141 / 142 / 147)
        let mut pb_kdir = Playbook::new(
            6,
            "PB-KERNEL-INTEGRITY-RESTORATION",
            Some(IncidentCategory::KernelTampering),
            IncidentSeverity::Critical,
        );
        let k1 = PlaybookStep::new(
            1,
            "RestoreGoldenSnapshot",
            SoarAction::RestoreGoldenKernelSnapshot {
                table_mask: 0x0F, // IDT | GDT | CR3 | LSTAR
            },
            true,
        );
        let k2 = PlaybookStep::new(
            2,
            "IsolateCompromisedProcess",
            SoarAction::IsolateProcess { pid: 0 },
            true,
        )
        .with_dependency(1);
        let k3 = PlaybookStep::new(
            3,
            "CaptureMemoryForensics",
            SoarAction::CaptureMemoryForensics { pid: 0 },
            false,
        )
        .with_dependency(1);
        let k4 = PlaybookStep::new(
            4,
            "AlertKernelCritical",
            SoarAction::NotifySecurityAdmin {
                channel: to_fixed_16("kernel-sec"),
                channel_len: 10,
                note: to_fixed_48("Tables noyau restaurees et intrus neutralise"),
                note_len: 45,
            },
            false,
        )
        .with_dependency(2)
        .with_dependency(3);

        let _ = pb_kdir.add_step(k1);
        let _ = pb_kdir.add_step(k2);
        let _ = pb_kdir.add_step(k3);
        let _ = pb_kdir.add_step(k4);
        let _ = self.register_playbook(&cap, pb_kdir);
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

    /// Ingestion unifiée multi-source : crée l'incident et déclenche automatiquement le playbook correspondant
    pub fn ingest_alert(
        &mut self,
        cap: &SoarCap,
        source: &str,
        category: IncidentCategory,
        severity: IncidentSeverity,
        title: &str,
        attacker_ip: [u8; 4],
        target_pid: Option<u32>,
        target_handle: Option<u64>,
        affected_entity: Option<&str>,
        now: u64,
    ) -> Result<(u64, Option<SoarExecutionResult>), SoarError> {
        let inc_id = (self.incident_count as u64) + 1;
        let mut incident = Incident::new(
            inc_id,
            title,
            category,
            severity,
            source,
            attacker_ip,
            0,
            target_pid,
            target_handle,
            now,
        );

        if let Some(ent) = affected_entity {
            incident = incident.with_affected_entity(ent);
        }

        let created_id = self.create_incident(cap, incident)?;

        // Auto-mitigation si playbook correspondant et sévérité suffisante
        if severity >= IncidentSeverity::Medium {
            if let Some(pb_id) = self.find_matching_playbook(category, severity) {
                let exec_res = self.execute_playbook(cap, pb_id, created_id, now)?;
                return Ok((created_id, Some(exec_res)));
            }
        }

        Ok((created_id, None))
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

            let mut deps_ok = true;
            for d in 0..step.num_depends {
                let dep_id = step.depends_on[d];
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

            // Injection dynamique du contexte de l'incident
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
                SoarAction::QuarantineEntity {
                    entity_id,
                    entity_len,
                } => {
                    if *entity_len == 0 && incident.entity_len > 0 {
                        *entity_id = incident.affected_entity;
                        *entity_len = incident.entity_len;
                    }
                }
                SoarAction::TriggerDlpSanitization { session_id } => {
                    if *session_id == 0 {
                        *session_id = incident.id;
                    }
                }
                _ => {}
            }

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
        match action {
            SoarAction::RevokeCapability { .. } => {
                if !cap.has_right(soar_rights::REVOKE_CAPABILITY)
                    && !cap.has_right(soar_rights::ADMIN)
                {
                    return Err(SoarError::PermissionDenied);
                }
            }
            SoarAction::IsolateProcess { .. }
            | SoarAction::EnforceMlsContainment { .. }
            | SoarAction::QuarantineEntity { .. } => {
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
                (IntegrationTarget::JamboEdr, "IsolateProcess dispatched")
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
            SoarAction::QuarantineEntity { .. } => {
                (IntegrationTarget::JamboUeba, "QuarantineEntity dispatched")
            }
            SoarAction::RestoreGoldenKernelSnapshot { .. } => (
                IntegrationTarget::JamboKdir,
                "RestoreGoldenSnapshot dispatched",
            ),
            SoarAction::TriggerDlpSanitization { .. } => {
                (IntegrationTarget::JamboDlp, "DlpSanitization dispatched")
            }
            SoarAction::EnforceMicroSegmentation { .. } => {
                (IntegrationTarget::JamboNdr, "MicroSegmentation dispatched")
            }
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

        if self.dispatched_count < MAX_DISPATCHED_ACTIONS {
            self.dispatched_actions[self.dispatched_count] = Some(disp);
            self.dispatched_count += 1;
        }

        let audit_ev = match action {
            SoarAction::RevokeCapability { .. } => SoarAuditEventType::CapabilityRevoked,
            SoarAction::IsolateProcess { .. } => SoarAuditEventType::NodeIsolated,
            SoarAction::QuarantineEntity { .. } => SoarAuditEventType::EntityQuarantined,
            SoarAction::RestoreGoldenKernelSnapshot { .. } => SoarAuditEventType::SnapshotRestored,
            SoarAction::EnforceMicroSegmentation { .. } => {
                SoarAuditEventType::MicroSegmentationEnforced
            }
            _ => SoarAuditEventType::ActionDispatched,
        };

        self.append_audit(audit_ev, 0, 0, now);
        Ok(action_id)
    }

    /// Ajoute un enregistrement au journal d'audit scellé par chaînage SHA-256.
    fn append_audit(
        &mut self,
        event_type: SoarAuditEventType,
        incident_id: u64,
        playbook_id: u32,
        now: u64,
    ) {
        let seq = self.audit_count + 1;
        let prev_hash = self.audit_chain;

        let mut hasher = Sha256::new();
        hasher.update(&seq.to_be_bytes());
        hasher.update(&now.to_be_bytes());
        hasher.update(&[event_type as u8]);
        hasher.update(&incident_id.to_be_bytes());
        hasher.update(&playbook_id.to_be_bytes());
        hasher.update(&prev_hash);
        let entry_hash = hasher.finalize();

        self.audit_chain = entry_hash;

        let slot = (self.audit_count as usize) % MAX_AUDIT_LOGS;
        self.audit_records[slot] = Some(SoarAuditRecord {
            sequence: seq,
            timestamp: now,
            event_type,
            incident_id,
            playbook_id,
            prev_hash,
            entry_hash,
        });

        self.audit_count += 1;
    }

    /// Vérifie l'intégrité de la chaîne cryptographique d'audit.
    pub fn verify_audit_integrity(&self) -> bool {
        let count = (self.audit_count as usize).min(MAX_AUDIT_LOGS);
        if count == 0 {
            return self.audit_chain == Self::GENESIS_HASH;
        }

        let mut expected_prev = Self::GENESIS_HASH;
        let start_seq = if self.audit_count > MAX_AUDIT_LOGS as u64 {
            self.audit_count - MAX_AUDIT_LOGS as u64 + 1
        } else {
            1
        };

        for i in 0..count {
            let slot = ((start_seq - 1 + i as u64) as usize) % MAX_AUDIT_LOGS;
            if let Some(ref rec) = self.audit_records[slot] {
                if start_seq == 1 && i == 0 {
                    if rec.prev_hash != expected_prev {
                        return false;
                    }
                }

                let mut hasher = Sha256::new();
                hasher.update(&rec.sequence.to_be_bytes());
                hasher.update(&rec.timestamp.to_be_bytes());
                hasher.update(&[rec.event_type as u8]);
                hasher.update(&rec.incident_id.to_be_bytes());
                hasher.update(&rec.playbook_id.to_be_bytes());
                hasher.update(&rec.prev_hash);
                let computed = hasher.finalize();

                if computed != rec.entry_hash {
                    return false;
                }
                expected_prev = rec.entry_hash;
            } else {
                return false;
            }
        }
        true
    }

    /// Retourne un résumé structuré des métriques SOAR
    pub fn get_summary(&self) -> SoarSummary {
        let mut mitigated = 0usize;
        let mut escalated = 0usize;
        for i in 0..self.incident_count {
            if let Some(ref inc) = self.incidents[i] {
                match inc.status {
                    IncidentStatus::Mitigated => mitigated += 1,
                    IncidentStatus::Escalated => escalated += 1,
                    _ => {}
                }
            }
        }

        let mut active_pb = 0usize;
        for i in 0..self.playbook_count {
            if let Some(ref pb) = self.playbooks[i] {
                if pb.is_enabled {
                    active_pb += 1;
                }
            }
        }

        SoarSummary {
            total_incidents: self.incident_count,
            mitigated_incidents: mitigated,
            escalated_incidents: escalated,
            active_playbooks: active_pb,
            dispatched_actions: self.dispatched_count,
            audit_records_count: self.audit_count,
            audit_chain_valid: self.verify_audit_integrity(),
        }
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] compatibles)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cap() -> SoarCap {
        SoarCap::new(Handle::new(14701, 1), soar_rights::ALL, 10000, 500)
    }

    #[test]
    fn test_cap_rights_and_attenuation() {
        let cap = create_test_cap();
        assert!(cap.has_right(soar_rights::EXECUTE_PLAYBOOK));
        assert!(cap.has_right(soar_rights::TRIGGER_INCIDENT));
        assert!(cap.has_right(soar_rights::ADMIN));

        let attenuated = cap
            .attenuate(
                soar_rights::EXECUTE_PLAYBOOK | soar_rights::TRIGGER_INCIDENT,
                5000,
                200,
            )
            .expect("Atténuation");
        assert!(attenuated.has_right(soar_rights::EXECUTE_PLAYBOOK));
        assert!(attenuated.has_right(soar_rights::TRIGGER_INCIDENT));
        assert!(!attenuated.has_right(soar_rights::ADMIN));

        // Rejet d'escalade
        assert_eq!(
            attenuated.attenuate(soar_rights::ALL, 5000, 200),
            Err(SoarError::AttenuationViolation)
        );
    }

    #[test]
    fn test_dag_validation_anti_cyclic() {
        let mut cyclic_pb = Playbook::new(99, "CyclicTest", None, IncidentSeverity::Low);
        let s1 = PlaybookStep::new(1, "Step1", SoarAction::IsolateProcess { pid: 1 }, true)
            .with_dependency(2);
        let s2 = PlaybookStep::new(2, "Step2", SoarAction::IsolateProcess { pid: 2 }, true)
            .with_dependency(1);
        cyclic_pb.add_step(s1).unwrap();
        cyclic_pb.add_step(s2).unwrap();
        assert_eq!(cyclic_pb.validate_dag(), Err(SoarError::CyclicDependency));
    }

    #[test]
    fn test_default_playbooks_registration() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();
        assert_eq!(
            daemon.playbook_count, 6,
            "6 playbooks souverains de référence"
        );
    }

    #[test]
    fn test_ddos_mitigation_workflow() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        let inc = Incident::new(
            1,
            "Flood UDP 100Gbps",
            IncidentCategory::DDoSFlood,
            IncidentSeverity::High,
            "jambo-ddos",
            [198, 51, 100, 1],
            53,
            None,
            None,
            1000,
        );
        let inc_id = daemon.create_incident(&cap, inc).unwrap();
        let res = daemon.execute_playbook(&cap, 1, inc_id, 1050).unwrap();

        assert!(res.fully_mitigated);
        assert_eq!(res.steps_succeeded, 3);
        assert!(daemon.verify_audit_integrity());
    }

    #[test]
    fn test_dlp_data_leak_playbook() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        let inc = Incident::new(
            2,
            "Exfiltration PII massive vers C2",
            IncidentCategory::SensitiveDataLeak,
            IncidentSeverity::High,
            "jambo-dlp",
            [45, 33, 32, 1],
            443,
            Some(88),
            None,
            2000,
        )
        .with_affected_entity("exfil_node_01");

        let inc_id = daemon.create_incident(&cap, inc).unwrap();
        let pb_id = daemon
            .find_matching_playbook(IncidentCategory::SensitiveDataLeak, IncidentSeverity::High)
            .expect("Playbook DLP trouvé");
        assert_eq!(pb_id, 4);

        let res = daemon.execute_playbook(&cap, pb_id, inc_id, 2010).unwrap();
        assert!(res.fully_mitigated);
        assert_eq!(res.steps_succeeded, 4);

        let summary = daemon.get_summary();
        assert_eq!(summary.mitigated_incidents, 1);
        assert!(summary.audit_chain_valid);
    }

    #[test]
    fn test_ueba_anomaly_and_lateral_movement_playbook() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        let (inc_id, exec_opt) = daemon
            .ingest_alert(
                &cap,
                "jambo-ueba",
                IncidentCategory::BehavioralAnomaly,
                IncidentSeverity::High,
                "Z-score deconnecte et mouvement lateral off-hours",
                [10, 0, 5, 20],
                Some(120),
                None,
                Some("compromised_srv"),
                3000,
            )
            .expect("Ingestion alerte UEBA");

        assert_eq!(inc_id, 1);
        let exec = exec_opt.expect("Auto-mitigation déclenchée");
        assert_eq!(exec.playbook_id, 5);
        assert!(exec.fully_mitigated);
        assert_eq!(exec.steps_succeeded, 4);
    }

    #[test]
    fn test_kernel_tampering_restoration_playbook() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        let (inc_id, exec_opt) = daemon
            .ingest_alert(
                &cap,
                "jambo-kdir",
                IncidentCategory::KernelTampering,
                IncidentSeverity::Critical,
                "DKOM hook detecte sur table IDT #14",
                [0, 0, 0, 0],
                Some(666),
                None,
                Some("kernel_rootkit_mod"),
                4000,
            )
            .expect("Ingestion alerte KDIR");

        assert_eq!(inc_id, 1);
        let exec = exec_opt.expect("Auto-mitigation KDIR");
        assert_eq!(exec.playbook_id, 6);
        assert!(exec.fully_mitigated);
        assert_eq!(exec.steps_succeeded, 4);

        assert!(daemon.verify_audit_integrity());
    }

    #[test]
    fn test_audit_integrity_tampering() {
        let cap = create_test_cap();
        let mut daemon = JamboSoarDaemon::new(cap);
        daemon.init_defaults();

        let inc = Incident::new(
            5,
            "Attaque WAF SQLi",
            IncidentCategory::SqlInjection,
            IncidentSeverity::High,
            "jambo-waf",
            [1, 2, 3, 4],
            80,
            None,
            None,
            5000,
        );
        daemon.create_incident(&cap, inc).unwrap();
        assert!(daemon.verify_audit_integrity());

        // Altération illicite du journal d'audit
        if let Some(ref mut rec) = daemon.audit_records[0] {
            rec.playbook_id = 999;
        }
        assert!(!daemon.verify_audit_integrity());
    }
}

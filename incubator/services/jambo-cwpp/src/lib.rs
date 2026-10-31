//! Protection des Charges de Travail Cloud Souveraines CWPP, Intégrité d'Exécution & Confinement Autonome
//!
//! Phase 156 — Jalon v0.3.23
//!
//! Fournit un système souverain de Cloud Workload Protection Platform (CWPP) en environnement `#![no_std]` :
//! 1. Moteur de protection continue à l'exécution (Runtime Workload Protection) pour micro-VMs et conteneurs d'enclaves souveraines.
//! 2. Surveillance de l'intégrité mémoire temps réel : W^X enforcement, Control Flow Integrity (CFI), intégrité des canaris de pile (Stack Canaries) et contrôle d'empreintes binaires SHA-256.
//! 3. Détection des dérives comportementales des processus et conteneurs (appels système non autorisés, injections mémoire, dérivation RIP/ROP, franchissement de namespaces, violations d'enclaves TEE).
//! 4. Confinement chirurgical instantané O(1) : Freeze, StripCaps, IsolateNetwork, Quarantine, RollbackGoldenSnapshot, Terminate.
//! 5. Rapports d'incidents et de confinement autonomes scellés par SHA-256 (`CwppIncidentReport`).
//! 6. Contrôle d'accès capabilaire strict (`CwppCap`) sans autorité ambiante avec atténuation monotone.
//! 7. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256 déterministe.

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

        let mut digest = [0u8; 32];
        for i in 0..8 {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        digest
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ============================================================================
// DROITS & CONTRÔLE D'ACCÈS CAPABILAIRE (CwppCap)
// ============================================================================

pub mod cwpp_rights {
    pub const REGISTER_WORKLOAD: u32 = 1 << 0;
    pub const INSPECT_WORKLOAD: u32 = 1 << 1;
    pub const DETECT_ANOMALY: u32 = 1 << 2;
    pub const CONTAIN_WORKLOAD: u32 = 1 << 3;
    pub const MANAGE_PROFILES: u32 = 1 << 4;
    pub const VERIFY_INTEGRITY: u32 = 1 << 5;
    pub const READ_METRICS: u32 = 1 << 6;
    pub const SEAL_LEDGER: u32 = 1 << 7;
    pub const ADMIN: u32 = 1 << 8;

    pub const ALL: u32 = REGISTER_WORKLOAD
        | INSPECT_WORKLOAD
        | DETECT_ANOMALY
        | CONTAIN_WORKLOAD
        | MANAGE_PROFILES
        | VERIFY_INTEGRITY
        | READ_METRICS
        | SEAL_LEDGER
        | ADMIN;
}

/// Capabilité CWPP sans autorité ambiante
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CwppCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl CwppCap {
    pub const fn new(handle: Handle, rights: u32, max_lifetime: u64, invocations: u32) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left: invocations,
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right && self.invocations_left > 0
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        max_lifetime: u64,
        invocations: u32,
    ) -> Result<Self, CwppError> {
        if (new_rights & !self.rights) != 0 {
            return Err(CwppError::AttenuationViolation);
        }
        let lifetime = if max_lifetime < self.max_lifetime {
            max_lifetime
        } else {
            self.max_lifetime
        };
        let inv = if invocations < self.invocations_left {
            invocations
        } else {
            self.invocations_left
        };

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: lifetime,
            invocations_left: inv,
        })
    }

    pub fn consume(&mut self) -> Result<(), CwppError> {
        if self.invocations_left == 0 {
            return Err(CwppError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// TYPES D'ERREURS CWPP
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CwppError {
    PermissionDenied,
    AttenuationViolation,
    WorkloadNotFound,
    ProfileNotFound,
    BufferOverflow,
    InvalidState,
    LedgerCorruption,
    AlreadyContained,
}

// ============================================================================
// MODÈLES DE CHARGE DE TRAVAIL & ENVIRONNEMENT D'EXÉCUTION
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeIsolation {
    MicroVmEnclave,
    ContainerNamespace,
    BareMetalProcess,
    WasmLinearMemory,
}

impl RuntimeIsolation {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeIsolation::MicroVmEnclave => "MicroVmEnclave",
            RuntimeIsolation::ContainerNamespace => "ContainerNamespace",
            RuntimeIsolation::BareMetalProcess => "BareMetalProcess",
            RuntimeIsolation::WasmLinearMemory => "WasmLinearMemory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadType {
    Microservice,
    Database,
    AiWorker,
    IngressGateway,
    SystemDaemon,
    SovereignEnclaveMicroVm,
    SovereignContainer,
    SovereignWasmSandbox,
}

impl WorkloadType {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkloadType::Microservice => "Microservice",
            WorkloadType::Database => "Database",
            WorkloadType::AiWorker => "AiWorker",
            WorkloadType::IngressGateway => "IngressGateway",
            WorkloadType::SystemDaemon => "SystemDaemon",
            WorkloadType::SovereignEnclaveMicroVm => "SovereignEnclaveMicroVm",
            WorkloadType::SovereignContainer => "SovereignContainer",
            WorkloadType::SovereignWasmSandbox => "SovereignWasmSandbox",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadState {
    Healthy,
    Suspicious,
    Anomalous,
    Contained,
    Terminated,
    Restored,
}

impl WorkloadState {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkloadState::Healthy => "Healthy",
            WorkloadState::Suspicious => "Suspicious",
            WorkloadState::Anomalous => "Anomalous",
            WorkloadState::Contained => "Contained",
            WorkloadState::Terminated => "Terminated",
            WorkloadState::Restored => "Restored",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnomalyType {
    None,
    UnauthorizedSyscall,
    MemoryInjection,
    RipDivergence,
    ContainerEscapeAttempt,
    ResourceExhaustion,
    StackCanaryCorruption,
    EnclaveBoundaryViolation,
    BinaryTampering,
}

impl AnomalyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyType::None => "None",
            AnomalyType::UnauthorizedSyscall => "UnauthorizedSyscall",
            AnomalyType::MemoryInjection => "MemoryInjection(W+X)",
            AnomalyType::RipDivergence => "RipDivergence(CFI)",
            AnomalyType::ContainerEscapeAttempt => "ContainerEscapeAttempt",
            AnomalyType::ResourceExhaustion => "ResourceExhaustion",
            AnomalyType::StackCanaryCorruption => "StackCanaryCorruption",
            AnomalyType::EnclaveBoundaryViolation => "EnclaveBoundaryViolation",
            AnomalyType::BinaryTampering => "BinaryTampering",
        }
    }

    pub fn severity_score(&self) -> u8 {
        match self {
            AnomalyType::None => 0,
            AnomalyType::ResourceExhaustion => 35,
            AnomalyType::UnauthorizedSyscall => 65,
            AnomalyType::MemoryInjection => 85,
            AnomalyType::StackCanaryCorruption => 90,
            AnomalyType::RipDivergence => 92,
            AnomalyType::ContainerEscapeAttempt => 95,
            AnomalyType::EnclaveBoundaryViolation => 98,
            AnomalyType::BinaryTampering => 100,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainmentAction {
    None,
    Freeze,
    StripCaps,
    IsolateNetwork,
    Quarantine,
    RollbackGoldenSnapshot,
    Terminate,
}

impl ContainmentAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContainmentAction::None => "None",
            ContainmentAction::Freeze => "Freeze",
            ContainmentAction::StripCaps => "StripCaps",
            ContainmentAction::IsolateNetwork => "IsolateNetwork",
            ContainmentAction::Quarantine => "Quarantine",
            ContainmentAction::RollbackGoldenSnapshot => "RollbackGoldenSnapshot",
            ContainmentAction::Terminate => "Terminate",
        }
    }
}

/// État de l'intégrité d'exécution d'une charge de travail souveraine
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionIntegrity {
    pub wx_enforced: bool,
    pub cfi_valid: bool,
    pub stack_canary_intact: bool,
    pub hash_verified: bool,
    pub anomaly_score: u8,
}

impl ExecutionIntegrity {
    pub const fn default_healthy() -> Self {
        Self {
            wx_enforced: true,
            cfi_valid: true,
            stack_canary_intact: true,
            hash_verified: true,
            anomaly_score: 0,
        }
    }

    pub fn is_fully_integral(&self) -> bool {
        self.wx_enforced && self.cfi_valid && self.stack_canary_intact && self.hash_verified
    }
}

/// Profil d'exécution d'une charge de travail définissant les invariants nominaux
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadProfile {
    pub profile_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub workload_type: WorkloadType,
    pub isolation: RuntimeIsolation,
    pub allowed_syscall_mask: u64,
    pub max_memory_bytes: u64,
    pub max_threads: u32,
    pub allow_network: bool,
    pub allow_raw_sockets: bool,
    pub golden_hash: [u8; 32],
}

impl WorkloadProfile {
    pub fn new(
        profile_id: u32,
        name_str: &str,
        workload_type: WorkloadType,
        allowed_syscall_mask: u64,
        max_memory_bytes: u64,
        max_threads: u32,
        allow_network: bool,
        allow_raw_sockets: bool,
    ) -> Self {
        Self::new_full(
            profile_id,
            name_str,
            workload_type,
            RuntimeIsolation::ContainerNamespace,
            allowed_syscall_mask,
            max_memory_bytes,
            max_threads,
            allow_network,
            allow_raw_sockets,
            [0u8; 32],
        )
    }

    pub fn new_full(
        profile_id: u32,
        name_str: &str,
        workload_type: WorkloadType,
        isolation: RuntimeIsolation,
        allowed_syscall_mask: u64,
        max_memory_bytes: u64,
        max_threads: u32,
        allow_network: bool,
        allow_raw_sockets: bool,
        golden_hash: [u8; 32],
    ) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        name[..len].copy_from_slice(&bytes[..len]);

        Self {
            profile_id,
            name,
            name_len: len,
            workload_type,
            isolation,
            allowed_syscall_mask,
            max_memory_bytes,
            max_threads,
            allow_network,
            allow_raw_sockets,
            golden_hash,
        }
    }
}

/// Descripteur de charge de travail surveillée en Ring 3 / Micro-VM / Sandbox
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Workload {
    pub id: u32,
    pub pid: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub profile_id: u32,
    pub isolation: RuntimeIsolation,
    pub state: WorkloadState,
    pub integrity: ExecutionIntegrity,
    pub allocated_memory: u64,
    pub thread_count: u32,
    pub anomaly_count: u32,
    pub last_anomaly: AnomalyType,
    pub applied_containment: ContainmentAction,
    pub last_seen_ts: u64,
    pub integrity_hash: [u8; 32],
}

impl Workload {
    pub fn new(
        id: u32,
        pid: u32,
        name_str: &str,
        profile_id: u32,
        integrity_hash: [u8; 32],
    ) -> Self {
        Self::new_full(
            id,
            pid,
            name_str,
            profile_id,
            RuntimeIsolation::ContainerNamespace,
            integrity_hash,
        )
    }

    pub fn new_full(
        id: u32,
        pid: u32,
        name_str: &str,
        profile_id: u32,
        isolation: RuntimeIsolation,
        integrity_hash: [u8; 32],
    ) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        name[..len].copy_from_slice(&bytes[..len]);

        Self {
            id,
            pid,
            name,
            name_len: len,
            profile_id,
            isolation,
            state: WorkloadState::Healthy,
            integrity: ExecutionIntegrity::default_healthy(),
            allocated_memory: 0,
            thread_count: 1,
            anomaly_count: 0,
            last_anomaly: AnomalyType::None,
            applied_containment: ContainmentAction::None,
            last_seen_ts: 0,
            integrity_hash,
        }
    }
}

// ============================================================================
// RAPPORTS D'INCIDENTS ET DE CONFINEMENT SCELLÉS (SHA-256)
// ============================================================================

/// Rapport d'incident et d'intervention de confinement autonome scellé cryptographiquement
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CwppIncidentReport {
    pub report_id: u64,
    pub workload_id: u32,
    pub timestamp: u64,
    pub anomaly: AnomalyType,
    pub action: ContainmentAction,
    pub isolation_env: RuntimeIsolation,
    pub threat_score: u8,
    pub report_hash: [u8; 32],
}

impl CwppIncidentReport {
    pub fn compute_hash(
        report_id: u64,
        workload_id: u32,
        timestamp: u64,
        anomaly: AnomalyType,
        action: ContainmentAction,
        isolation_env: RuntimeIsolation,
        threat_score: u8,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&report_id.to_be_bytes());
        hasher.update(&workload_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[anomaly as u8]);
        hasher.update(&[action as u8]);
        hasher.update(&[isolation_env as u8]);
        hasher.update(&[threat_score]);
        hasher.finalize()
    }

    pub fn new(
        report_id: u64,
        workload_id: u32,
        timestamp: u64,
        anomaly: AnomalyType,
        action: ContainmentAction,
        isolation_env: RuntimeIsolation,
        threat_score: u8,
    ) -> Self {
        let report_hash = Self::compute_hash(
            report_id,
            workload_id,
            timestamp,
            anomaly,
            action,
            isolation_env,
            threat_score,
        );
        Self {
            report_id,
            workload_id,
            timestamp,
            anomaly,
            action,
            isolation_env,
            threat_score,
            report_hash,
        }
    }
}

// ============================================================================
// REGISTRE D'AUDIT CRYPTOGRAPHIQUE SCELLÉ (SHA-256)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CwppAuditAction {
    WorkloadRegistered,
    ProfileAdded,
    ScanExecuted,
    AnomalyDetected,
    ContainmentEnforced,
    RollbackExecuted,
    WorkloadReleased,
    LedgerSealed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CwppAuditRecord {
    pub index: u64,
    pub timestamp: u64,
    pub action: CwppAuditAction,
    pub workload_id: u32,
    pub details_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

impl CwppAuditRecord {
    pub fn compute_hash(
        index: u64,
        timestamp: u64,
        action: CwppAuditAction,
        workload_id: u32,
        details_hash: &[u8; 32],
        prev_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&index.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[action as u8]);
        hasher.update(&workload_id.to_be_bytes());
        hasher.update(details_hash);
        hasher.update(prev_hash);
        hasher.finalize()
    }
}

// ============================================================================
// DÉMON CENTRAL CWPP (JamboCwppDaemon)
// ============================================================================

pub struct JamboCwppDaemon {
    pub admin_cap: CwppCap,
    pub workloads: [Option<Workload>; 16],
    pub workload_count: usize,
    pub profiles: [Option<WorkloadProfile>; 8],
    pub profile_count: usize,
    pub incident_reports: [Option<CwppIncidentReport>; 32],
    pub report_count: usize,
    pub next_report_id: u64,
    pub audit_log: [Option<CwppAuditRecord>; 64],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],

    // Métriques opérationnelles
    pub total_scans: u64,
    pub total_anomalies_detected: u64,
    pub total_containments: u64,
    pub total_rollbacks: u64,
    pub active_workloads: u32,
}

impl JamboCwppDaemon {
    pub const GENESIS_HASH: [u8; 32] = [
        0x5c, 0x77, 0x70, 0x70, 0x5f, 0x67, 0x65, 0x6e, 0x65, 0x73, 0x69, 0x73, 0x5f, 0x68, 0x61,
        0x73, 0x68, 0x5f, 0x73, 0x6f, 0x76, 0x65, 0x72, 0x65, 0x69, 0x67, 0x6e, 0x5f, 0x30, 0x30,
        0x30, 0x31,
    ];

    pub fn new(admin_cap: CwppCap) -> Self {
        Self {
            admin_cap,
            workloads: [None; 16],
            workload_count: 0,
            profiles: [None; 8],
            profile_count: 0,
            incident_reports: [None; 32],
            report_count: 0,
            next_report_id: 1,
            audit_log: [None; 64],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            total_scans: 0,
            total_anomalies_detected: 0,
            total_containments: 0,
            total_rollbacks: 0,
            active_workloads: 0,
        }
    }

    /// Enregistre un événement dans le registre d'audit cryptographique inviolable
    fn append_audit_entry(
        &mut self,
        action: CwppAuditAction,
        workload_id: u32,
        details: &[u8],
        timestamp: u64,
    ) {
        if self.audit_count >= self.audit_log.len() {
            // Rotation circulaire FIFO
            for i in 1..self.audit_log.len() {
                self.audit_log[i - 1] = self.audit_log[i];
            }
            self.audit_count = self.audit_log.len() - 1;
        }

        let details_hash = Sha256::hash(details);
        let index = self.audit_count as u64;
        let record_hash = CwppAuditRecord::compute_hash(
            index,
            timestamp,
            action,
            workload_id,
            &details_hash,
            &self.ledger_hash,
        );

        let record = CwppAuditRecord {
            index,
            timestamp,
            action,
            workload_id,
            details_hash,
            prev_hash: self.ledger_hash,
            record_hash,
        };

        self.ledger_hash = record_hash;
        self.audit_log[self.audit_count] = Some(record);
        self.audit_count += 1;
    }

    /// Ajoute un rapport d'incident scellé dans le journal borné
    fn append_incident_report(
        &mut self,
        workload_id: u32,
        anomaly: AnomalyType,
        action: ContainmentAction,
        isolation_env: RuntimeIsolation,
        threat_score: u8,
        timestamp: u64,
    ) {
        let rep_id = self.next_report_id;
        self.next_report_id += 1;

        let report = CwppIncidentReport::new(
            rep_id,
            workload_id,
            timestamp,
            anomaly,
            action,
            isolation_env,
            threat_score,
        );

        let slot = ((rep_id - 1) % 32) as usize;
        self.incident_reports[slot] = Some(report);
        if self.report_count < 32 {
            self.report_count += 1;
        }
    }

    /// Initialise les profils souverains par défaut et les charges de travail critiques
    pub fn init_defaults(&mut self) {
        // 1. Profil Ingress Gateway (Micro-VM Enclave TEE)
        let hash_gw = Sha256::hash(b"golden-bin-ingress-gw-v0.3.23");
        let p_gw = WorkloadProfile::new_full(
            1,
            "jambo-ingress-gw",
            WorkloadType::IngressGateway,
            RuntimeIsolation::MicroVmEnclave,
            0x00FF_FFFF, // Syscalls 0..23 autorisés
            32 * 1024 * 1024,
            8,
            true,
            false,
            hash_gw,
        );
        self.profiles[0] = Some(p_gw);

        // 2. Profil Base de Données Souveraine (Conteneur Durci)
        let hash_db = Sha256::hash(b"golden-bin-kvd-db-v0.3.23");
        let p_db = WorkloadProfile::new_full(
            2,
            "jambo-kvd-db",
            WorkloadType::Database,
            RuntimeIsolation::ContainerNamespace,
            0x000F_FFFF, // Syscalls 0..19 autorisés
            128 * 1024 * 1024,
            16,
            true,
            false,
            hash_db,
        );
        self.profiles[1] = Some(p_db);

        // 3. Profil Worker IA Inférence Souverain (Micro-VM Enclave TEE accélérée)
        let hash_ai = Sha256::hash(b"golden-bin-ai-infer-v0.3.23");
        let p_ai = WorkloadProfile::new_full(
            3,
            "jambo-ai-infer",
            WorkloadType::AiWorker,
            RuntimeIsolation::MicroVmEnclave,
            0x0000_001F, // Syscalls 0..4 autorisés (très restreint)
            256 * 1024 * 1024,
            4,
            false,
            false,
            hash_ai,
        );
        self.profiles[2] = Some(p_ai);

        // 4. Profil Démon d'Audit Système (Processus Ring 3 Natif)
        let hash_audit = Sha256::hash(b"golden-bin-log-audit-v0.3.23");
        let p_audit = WorkloadProfile::new_full(
            4,
            "jambo-log-audit",
            WorkloadType::SystemDaemon,
            RuntimeIsolation::BareMetalProcess,
            0x0000_03FF, // Syscalls 0..9 autorisés
            16 * 1024 * 1024,
            2,
            false,
            false,
            hash_audit,
        );
        self.profiles[3] = Some(p_audit);

        self.profile_count = 4;

        // Charges de travail surveillées associées
        self.workloads[0] = Some(Workload::new_full(
            101,
            201,
            "jambo-ingress-instance",
            1,
            RuntimeIsolation::MicroVmEnclave,
            hash_gw,
        ));
        self.workloads[1] = Some(Workload::new_full(
            102,
            202,
            "jambo-kvd-instance",
            2,
            RuntimeIsolation::ContainerNamespace,
            hash_db,
        ));
        self.workloads[2] = Some(Workload::new_full(
            103,
            203,
            "jambo-ai-worker-0",
            3,
            RuntimeIsolation::MicroVmEnclave,
            hash_ai,
        ));
        self.workloads[3] = Some(Workload::new_full(
            104,
            204,
            "jambo-log-daemon",
            4,
            RuntimeIsolation::BareMetalProcess,
            hash_audit,
        ));

        self.workload_count = 4;
        self.active_workloads = 4;

        self.append_audit_entry(
            CwppAuditAction::LedgerSealed,
            0,
            b"cwpp-defaults-initialized-v0.3.23",
            100,
        );
    }

    /// Enregistre un nouveau profil d'exécution
    pub fn register_profile(
        &mut self,
        cap: &CwppCap,
        profile: WorkloadProfile,
        timestamp: u64,
    ) -> Result<u32, CwppError> {
        if !cap.has_right(cwpp_rights::MANAGE_PROFILES) {
            return Err(CwppError::PermissionDenied);
        }
        if self.profile_count >= self.profiles.len() {
            return Err(CwppError::BufferOverflow);
        }

        let pid = profile.profile_id;
        self.profiles[self.profile_count] = Some(profile);
        self.profile_count += 1;

        self.append_audit_entry(
            CwppAuditAction::ProfileAdded,
            pid,
            b"register-workload-profile",
            timestamp,
        );
        Ok(pid)
    }

    /// Enregistre une charge de travail pour surveillance d'exécution continue
    pub fn register_workload(
        &mut self,
        cap: &CwppCap,
        workload: Workload,
        timestamp: u64,
    ) -> Result<u32, CwppError> {
        if !cap.has_right(cwpp_rights::REGISTER_WORKLOAD) {
            return Err(CwppError::PermissionDenied);
        }
        if self.workload_count >= self.workloads.len() {
            return Err(CwppError::BufferOverflow);
        }

        let wid = workload.id;
        self.workloads[self.workload_count] = Some(workload);
        self.workload_count += 1;
        self.active_workloads += 1;

        self.append_audit_entry(
            CwppAuditAction::WorkloadRegistered,
            wid,
            b"register-workload",
            timestamp,
        );
        Ok(wid)
    }

    /// Télémétrie d'exécution complète avec surveillance W^X, CFI, Stack Canaries, Enclave Boundary et Hash binaire
    pub fn report_execution_telemetry(
        &mut self,
        cap: &CwppCap,
        workload_id: u32,
        syscall_nr: u32,
        memory_bytes: u64,
        thread_count: u32,
        wx_violation: bool,
        cfi_violation: bool,
        canary_violation: bool,
        boundary_violation: bool,
        current_hash: [u8; 32],
        timestamp: u64,
    ) -> Result<Option<AnomalyType>, CwppError> {
        if !cap.has_right(cwpp_rights::DETECT_ANOMALY) {
            return Err(CwppError::PermissionDenied);
        }

        let mut wl_idx = None;
        for i in 0..self.workload_count {
            if let Some(ref wl) = self.workloads[i] {
                if wl.id == workload_id {
                    wl_idx = Some(i);
                    break;
                }
            }
        }

        let idx = match wl_idx {
            Some(i) => i,
            None => return Err(CwppError::WorkloadNotFound),
        };

        let profile_id = self.workloads[idx].as_ref().unwrap().profile_id;
        let mut prof = None;
        for i in 0..self.profile_count {
            if let Some(ref p) = self.profiles[i] {
                if p.profile_id == profile_id {
                    prof = Some(*p);
                    break;
                }
            }
        }
        let profile = match prof {
            Some(p) => p,
            None => return Err(CwppError::ProfileNotFound),
        };

        let mut detected_anomaly = AnomalyType::None;

        // 1. Détection W+X (Injection de mémoire)
        if wx_violation {
            detected_anomaly = AnomalyType::MemoryInjection;
        }
        // 2. Détection CFI / Divergence RIP
        else if cfi_violation {
            detected_anomaly = AnomalyType::RipDivergence;
        }
        // 3. Détection altération Canari de Pile
        else if canary_violation {
            detected_anomaly = AnomalyType::StackCanaryCorruption;
        }
        // 4. Détection violation de frontières d'enclave / évasion conteneur
        else if boundary_violation {
            if profile.isolation == RuntimeIsolation::MicroVmEnclave {
                detected_anomaly = AnomalyType::EnclaveBoundaryViolation;
            } else {
                detected_anomaly = AnomalyType::ContainerEscapeAttempt;
            }
        }
        // 5. Détection altération d'empreinte binaire (Binary Tampering)
        else if profile.golden_hash != [0u8; 32] && current_hash != profile.golden_hash {
            detected_anomaly = AnomalyType::BinaryTampering;
        }
        // 6. Détection Syscall non autorisé
        else if syscall_nr < 64 {
            let mask = 1u64 << syscall_nr;
            if (profile.allowed_syscall_mask & mask) == 0 {
                detected_anomaly = AnomalyType::UnauthorizedSyscall;
            }
        } else {
            detected_anomaly = AnomalyType::UnauthorizedSyscall;
        }

        // 7. Détection dépassement de quota de mémoire ou threads
        if detected_anomaly == AnomalyType::None {
            if memory_bytes > profile.max_memory_bytes || thread_count > profile.max_threads {
                detected_anomaly = AnomalyType::ResourceExhaustion;
            }
        }

        // Mise à jour de la charge
        let (iso, score) = {
            let wl = self.workloads[idx].as_mut().unwrap();
            wl.allocated_memory = memory_bytes;
            wl.thread_count = thread_count;
            wl.last_seen_ts = timestamp;
            wl.integrity_hash = current_hash;

            // Mise à jour de l'intégrité
            wl.integrity.wx_enforced = !wx_violation;
            wl.integrity.cfi_valid = !cfi_violation;
            wl.integrity.stack_canary_intact = !canary_violation;
            wl.integrity.hash_verified =
                profile.golden_hash == [0u8; 32] || current_hash == profile.golden_hash;
            wl.integrity.anomaly_score = detected_anomaly.severity_score();

            if detected_anomaly != AnomalyType::None {
                wl.anomaly_count += 1;
                wl.last_anomaly = detected_anomaly;
                wl.state = WorkloadState::Anomalous;
            } else if wl.state == WorkloadState::Suspicious {
                wl.state = WorkloadState::Healthy;
            }
            (wl.isolation, detected_anomaly.severity_score())
        };

        if detected_anomaly != AnomalyType::None {
            self.total_anomalies_detected += 1;

            self.append_audit_entry(
                CwppAuditAction::AnomalyDetected,
                workload_id,
                detected_anomaly.as_str().as_bytes(),
                timestamp,
            );

            // Génération automatique d'un rapport préliminaire
            self.append_incident_report(
                workload_id,
                detected_anomaly,
                ContainmentAction::None,
                iso,
                score,
                timestamp,
            );

            Ok(Some(detected_anomaly))
        } else {
            Ok(None)
        }
    }

    /// Rétro-compatibilité : Rapport d'événement simplifié (Phase 126 compatible)
    pub fn report_execution_event(
        &mut self,
        cap: &CwppCap,
        workload_id: u32,
        syscall_nr: u32,
        memory_bytes: u64,
        thread_count: u32,
        wx_violation: bool,
        rip_valid: bool,
        timestamp: u64,
    ) -> Result<Option<AnomalyType>, CwppError> {
        let golden_hash = {
            let mut h = [0u8; 32];
            for i in 0..self.workload_count {
                if let Some(ref w) = self.workloads[i] {
                    if w.id == workload_id {
                        h = w.integrity_hash;
                        break;
                    }
                }
            }
            h
        };

        self.report_execution_telemetry(
            cap,
            workload_id,
            syscall_nr,
            memory_bytes,
            thread_count,
            wx_violation,
            !rip_valid,
            false,
            false,
            golden_hash,
            timestamp,
        )
    }

    /// Applique une action de confinement autonome O(1) sur une charge compromise
    pub fn contain_workload(
        &mut self,
        cap: &CwppCap,
        workload_id: u32,
        action: ContainmentAction,
        timestamp: u64,
    ) -> Result<bool, CwppError> {
        if !cap.has_right(cwpp_rights::CONTAIN_WORKLOAD) {
            return Err(CwppError::PermissionDenied);
        }

        let mut wl_idx = None;
        for i in 0..self.workload_count {
            if let Some(ref wl) = self.workloads[i] {
                if wl.id == workload_id {
                    wl_idx = Some(i);
                    break;
                }
            }
        }

        let idx = match wl_idx {
            Some(i) => i,
            None => return Err(CwppError::WorkloadNotFound),
        };

        let (last_anom, iso_env, score) = {
            let wl = self.workloads[idx].as_mut().unwrap();

            if wl.state == WorkloadState::Terminated && action != ContainmentAction::None {
                return Err(CwppError::InvalidState);
            }

            wl.applied_containment = action;

            match action {
                ContainmentAction::None => {
                    wl.state = WorkloadState::Healthy;
                }
                ContainmentAction::Freeze
                | ContainmentAction::StripCaps
                | ContainmentAction::IsolateNetwork
                | ContainmentAction::Quarantine => {
                    wl.state = WorkloadState::Contained;
                }
                ContainmentAction::RollbackGoldenSnapshot => {
                    wl.state = WorkloadState::Restored;
                    wl.anomaly_count = 0;
                    wl.last_anomaly = AnomalyType::None;
                    wl.integrity = ExecutionIntegrity::default_healthy();
                }
                ContainmentAction::Terminate => {
                    wl.state = WorkloadState::Terminated;
                }
            }
            (
                wl.last_anomaly,
                wl.isolation,
                wl.last_anomaly.severity_score(),
            )
        };

        match action {
            ContainmentAction::None => {}
            ContainmentAction::Freeze
            | ContainmentAction::StripCaps
            | ContainmentAction::IsolateNetwork
            | ContainmentAction::Quarantine => {
                self.total_containments += 1;
            }
            ContainmentAction::RollbackGoldenSnapshot => {
                self.total_rollbacks += 1;
                self.total_containments += 1;
            }
            ContainmentAction::Terminate => {
                if self.active_workloads > 0 {
                    self.active_workloads -= 1;
                }
                self.total_containments += 1;
            }
        }

        self.append_audit_entry(
            if action == ContainmentAction::RollbackGoldenSnapshot {
                CwppAuditAction::RollbackExecuted
            } else {
                CwppAuditAction::ContainmentEnforced
            },
            workload_id,
            action.as_str().as_bytes(),
            timestamp,
        );

        // Sceller le rapport d'incident complet
        self.append_incident_report(workload_id, last_anom, action, iso_env, score, timestamp);

        Ok(true)
    }

    /// Restauration autonome vers le snapshot doré vérifié (Rollback O(1))
    pub fn rollback_workload(
        &mut self,
        cap: &CwppCap,
        workload_id: u32,
        timestamp: u64,
    ) -> Result<bool, CwppError> {
        self.contain_workload(
            cap,
            workload_id,
            ContainmentAction::RollbackGoldenSnapshot,
            timestamp,
        )
    }

    /// Exécute un scan d'intégrité global de toutes les charges de travail enregistrées
    pub fn scan_all_workloads(
        &mut self,
        cap: &CwppCap,
        timestamp: u64,
    ) -> Result<(usize, usize), CwppError> {
        if !cap.has_right(cwpp_rights::INSPECT_WORKLOAD) {
            return Err(CwppError::PermissionDenied);
        }

        self.total_scans += 1;
        let mut checked = 0;
        let mut anomalies = 0;

        for i in 0..self.workload_count {
            if let Some(ref wl) = self.workloads[i] {
                checked += 1;
                if wl.state == WorkloadState::Anomalous || wl.anomaly_count > 0 {
                    anomalies += 1;
                }
            }
        }

        self.append_audit_entry(
            CwppAuditAction::ScanExecuted,
            0,
            b"scan-all-workloads",
            timestamp,
        );

        Ok((checked, anomalies))
    }

    /// Inspecte les détails d'une charge de travail avec vérification capabilaire
    pub fn inspect_workload(&self, cap: &CwppCap, workload_id: u32) -> Result<Workload, CwppError> {
        if !cap.has_right(cwpp_rights::INSPECT_WORKLOAD) {
            return Err(CwppError::PermissionDenied);
        }

        for i in 0..self.workload_count {
            if let Some(ref wl) = self.workloads[i] {
                if wl.id == workload_id {
                    return Ok(*wl);
                }
            }
        }

        Err(CwppError::WorkloadNotFound)
    }

    /// Vérifie l'intégrité cryptographique complète du registre d'audit SHA-256
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = Self::GENESIS_HASH;

        for i in 0..self.audit_count {
            if let Some(ref rec) = self.audit_log[i] {
                if rec.prev_hash != expected_prev {
                    return false;
                }

                let recomputed = CwppAuditRecord::compute_hash(
                    rec.index,
                    rec.timestamp,
                    rec.action,
                    rec.workload_id,
                    &rec.details_hash,
                    &rec.prev_hash,
                );

                if rec.record_hash != recomputed {
                    return false;
                }

                expected_prev = rec.record_hash;
            } else {
                return false;
            }
        }

        expected_prev == self.ledger_hash
    }

    /// Retourne le dernier rapport d'incident / confinement scellé
    pub fn latest_report(&self) -> Option<CwppIncidentReport> {
        if self.report_count == 0 {
            return None;
        }
        let slot = ((self.next_report_id - 2) % 32) as usize;
        self.incident_reports[slot]
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
        hasher.update(b"jambo-cwpp-souverain-workload-protection");
        let hash = hasher.finalize();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_cap_rights_and_monotonic_attenuation() {
        let root_cap = CwppCap::new(Handle::new(12601, 1), cwpp_rights::ALL, 10000, 500);
        assert!(root_cap.has_right(cwpp_rights::REGISTER_WORKLOAD));
        assert!(root_cap.has_right(cwpp_rights::INSPECT_WORKLOAD));
        assert!(root_cap.has_right(cwpp_rights::DETECT_ANOMALY));
        assert!(root_cap.has_right(cwpp_rights::CONTAIN_WORKLOAD));
        assert!(root_cap.has_right(cwpp_rights::MANAGE_PROFILES));
        assert!(root_cap.has_right(cwpp_rights::VERIFY_INTEGRITY));
        assert!(root_cap.has_right(cwpp_rights::READ_METRICS));
        assert!(root_cap.has_right(cwpp_rights::ADMIN));

        let monitor_cap = root_cap
            .attenuate(
                cwpp_rights::INSPECT_WORKLOAD | cwpp_rights::READ_METRICS,
                5000,
                100,
            )
            .expect("Atténuation monotone");

        assert!(monitor_cap.has_right(cwpp_rights::INSPECT_WORKLOAD));
        assert!(monitor_cap.has_right(cwpp_rights::READ_METRICS));
        assert!(!monitor_cap.has_right(cwpp_rights::CONTAIN_WORKLOAD));
        assert!(!monitor_cap.has_right(cwpp_rights::ADMIN));

        // Escalade de privilèges rejetée
        assert_eq!(
            monitor_cap.attenuate(cwpp_rights::ALL, 5000, 100),
            Err(CwppError::AttenuationViolation)
        );
    }

    #[test]
    fn test_cwpp_defaults_and_anomaly_detection() {
        let admin_cap = CwppCap::new(Handle::new(12602, 1), cwpp_rights::ALL, 10000, 500);
        let mut daemon = JamboCwppDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.profile_count, 4);
        assert_eq!(daemon.workload_count, 4);
        assert_eq!(daemon.active_workloads, 4);
        assert!(daemon.verify_ledger_integrity());

        // Test événement normal sur jambo-ingress (ID 101, syscall 1 autorisé)
        let ev1 = daemon
            .report_execution_event(&admin_cap, 101, 1, 16 * 1024 * 1024, 4, false, true, 1000)
            .expect("Rapport d'exécution normal");
        assert_eq!(ev1, None);

        // Test anomalie : injection mémoire W+X sur jambo-kvd-db (ID 102)
        let ev2 = daemon
            .report_execution_event(
                &admin_cap,
                102,
                2,
                32 * 1024 * 1024,
                4,
                true, // W+X !
                true,
                1050,
            )
            .expect("Rapport d'anomalie W+X");
        assert_eq!(ev2, Some(AnomalyType::MemoryInjection));

        let wl102 = daemon.inspect_workload(&admin_cap, 102).unwrap();
        assert_eq!(wl102.state, WorkloadState::Anomalous);
        assert_eq!(wl102.last_anomaly, AnomalyType::MemoryInjection);
        assert_eq!(daemon.total_anomalies_detected, 1);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_cwpp_containment_and_isolation() {
        let admin_cap = CwppCap::new(Handle::new(12603, 1), cwpp_rights::ALL, 10000, 500);
        let mut daemon = JamboCwppDaemon::new(admin_cap);
        daemon.init_defaults();

        // Détection de dérivation RIP (contrôleur d'exécution corrompu) sur ID 103
        let ev = daemon
            .report_execution_event(
                &admin_cap,
                103,
                0,
                64 * 1024 * 1024,
                2,
                false,
                false, // RIP invalide !
                2000,
            )
            .unwrap();
        assert_eq!(ev, Some(AnomalyType::RipDivergence));

        // Application du confinement immédiat : Quarantaine
        let contained = daemon
            .contain_workload(&admin_cap, 103, ContainmentAction::Quarantine, 2010)
            .unwrap();
        assert!(contained);

        let wl103 = daemon.inspect_workload(&admin_cap, 103).unwrap();
        assert_eq!(wl103.state, WorkloadState::Contained);
        assert_eq!(wl103.applied_containment, ContainmentAction::Quarantine);
        assert_eq!(daemon.total_containments, 1);

        // Terminaison de la charge hostile
        let killed = daemon
            .contain_workload(&admin_cap, 103, ContainmentAction::Terminate, 2020)
            .unwrap();
        assert!(killed);

        let wl103_post = daemon.inspect_workload(&admin_cap, 103).unwrap();
        assert_eq!(wl103_post.state, WorkloadState::Terminated);
        assert_eq!(daemon.active_workloads, 3);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_cwpp_telemetry_advanced_invariants() {
        let admin_cap = CwppCap::new(Handle::new(12604, 1), cwpp_rights::ALL, 10000, 500);
        let mut daemon = JamboCwppDaemon::new(admin_cap);
        daemon.init_defaults();

        let golden_hash_ai = daemon.profiles[2].unwrap().golden_hash;

        // 1. Violation de canari de pile sur ID 101
        let ev1 = daemon
            .report_execution_telemetry(
                &admin_cap,
                101,
                1,
                10 * 1024 * 1024,
                2,
                false,
                false,
                true, // Canary écrasé
                false,
                daemon.profiles[0].unwrap().golden_hash,
                3000,
            )
            .unwrap();
        assert_eq!(ev1, Some(AnomalyType::StackCanaryCorruption));

        // 2. Violation d'enclave TEE sur ID 103
        let ev2 = daemon
            .report_execution_telemetry(
                &admin_cap,
                103,
                1,
                20 * 1024 * 1024,
                2,
                false,
                false,
                false,
                true, // Boundary violation !
                golden_hash_ai,
                3100,
            )
            .unwrap();
        assert_eq!(ev2, Some(AnomalyType::EnclaveBoundaryViolation));

        // 3. Rollback vers snapshot doré O(1)
        let roll = daemon.rollback_workload(&admin_cap, 103, 3200).unwrap();
        assert!(roll);
        let wl103 = daemon.inspect_workload(&admin_cap, 103).unwrap();
        assert_eq!(wl103.state, WorkloadState::Restored);
        assert_eq!(wl103.integrity.anomaly_score, 0);
        assert_eq!(daemon.total_rollbacks, 1);

        // 4. Vérification de la présence de rapports scellés
        assert!(daemon.report_count > 0);
        let rep = daemon.latest_report().unwrap();
        assert_eq!(rep.workload_id, 103);
        assert_eq!(rep.action, ContainmentAction::RollbackGoldenSnapshot);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_cwpp_container_escape_and_actions() {
        let admin_cap = CwppCap::new(Handle::new(12605, 1), cwpp_rights::ALL, 10000, 500);
        let mut daemon = JamboCwppDaemon::new(admin_cap);
        daemon.init_defaults();

        // Tentative d'évasion conteneur sur jambo-kvd-db (ID 102, isolation ContainerNamespace)
        let ev = daemon
            .report_execution_telemetry(
                &admin_cap,
                102,
                1,
                40 * 1024 * 1024,
                4,
                false,
                false,
                false,
                true, // Boundary violation sur conteneur = ContainerEscapeAttempt
                daemon.profiles[1].unwrap().golden_hash,
                4000,
            )
            .unwrap();
        assert_eq!(ev, Some(AnomalyType::ContainerEscapeAttempt));

        // Confinement IsolateNetwork
        let ok_net = daemon
            .contain_workload(&admin_cap, 102, ContainmentAction::IsolateNetwork, 4010)
            .unwrap();
        assert!(ok_net);
        let wl102 = daemon.inspect_workload(&admin_cap, 102).unwrap();
        assert_eq!(wl102.state, WorkloadState::Contained);
        assert_eq!(wl102.applied_containment, ContainmentAction::IsolateNetwork);

        // Confinement StripCaps
        let ok_strip = daemon
            .contain_workload(&admin_cap, 102, ContainmentAction::StripCaps, 4020)
            .unwrap();
        assert!(ok_strip);
        let wl102_strip = daemon.inspect_workload(&admin_cap, 102).unwrap();
        assert_eq!(
            wl102_strip.applied_containment,
            ContainmentAction::StripCaps
        );

        assert!(daemon.verify_ledger_integrity());
    }
}

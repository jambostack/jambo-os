//! Protection des Charges de Travail Cloud/Grappe (CWPP), Surveillance d'Intégrité en Exécution & Confinement
//!
//! Phase 126 — Jalon v0.2.124
//!
//! Fournit un système souverain de Cloud Workload Protection Platform (CWPP) en environnement `#![no_std]` :
//! 1. Surveillance en temps réel des charges de travail Ring 3 et détection d'anomalies d'exécution.
//! 2. Détection d'injections de mémoire anonyme (W+X), dérivations de pointeurs d'instructions (RIP Divergence), appels système non autorisés et évasions de conteneur.
//! 3. Confinement instantané O(1) (Freeze, StripCaps, IsolateNetwork, Quarantine, Terminate).
//! 4. Contrôle d'accès capabilaire (`CwppCap`) sans autorité ambiante et atténuation monotone.
//! 5. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

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
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
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
    pub const INSPECT_WORKLOAD: u32  = 1 << 1;
    pub const DETECT_ANOMALY: u32    = 1 << 2;
    pub const CONTAIN_WORKLOAD: u32  = 1 << 3;
    pub const MANAGE_PROFILES: u32   = 1 << 4;
    pub const READ_METRICS: u32      = 1 << 5;
    pub const SEAL_LEDGER: u32       = 1 << 6;
    pub const ADMIN: u32             = 1 << 7;

    pub const ALL: u32 = REGISTER_WORKLOAD
        | INSPECT_WORKLOAD
        | DETECT_ANOMALY
        | CONTAIN_WORKLOAD
        | MANAGE_PROFILES
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

    pub fn attenuate(&self, new_rights: u32, max_lifetime: u64, invocations: u32) -> Result<Self, CwppError> {
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
// MODÈLES DE CHARGE DE TRAVAIL & PROFILES
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadType {
    Microservice,
    Database,
    AiWorker,
    IngressGateway,
    SystemDaemon,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadState {
    Healthy,
    Suspicious,
    Anomalous,
    Contained,
    Terminated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnomalyType {
    None,
    UnauthorizedSyscall,
    MemoryInjection,
    RipDivergence,
    ContainerEscapeAttempt,
    ResourceExhaustion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainmentAction {
    None,
    Freeze,
    StripCaps,
    IsolateNetwork,
    Quarantine,
    Terminate,
}

/// Profil d'exécution d'une charge de travail définissant les invariants nominaux
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadProfile {
    pub profile_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub workload_type: WorkloadType,
    pub allowed_syscall_mask: u64,
    pub max_memory_bytes: u64,
    pub max_threads: u32,
    pub allow_network: bool,
    pub allow_raw_sockets: bool,
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
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        name[..len].copy_from_slice(&bytes[..len]);

        Self {
            profile_id,
            name,
            name_len: len,
            workload_type,
            allowed_syscall_mask,
            max_memory_bytes,
            max_threads,
            allow_network,
            allow_raw_sockets,
        }
    }
}

/// Descripteur de charge de travail surveillée en Ring 3
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Workload {
    pub id: u32,
    pub pid: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub profile_id: u32,
    pub state: WorkloadState,
    pub allocated_memory: u64,
    pub thread_count: u32,
    pub anomaly_count: u32,
    pub last_anomaly: AnomalyType,
    pub applied_containment: ContainmentAction,
    pub last_seen_ts: u64,
    pub integrity_hash: [u8; 32],
}

impl Workload {
    pub fn new(id: u32, pid: u32, name_str: &str, profile_id: u32, integrity_hash: [u8; 32]) -> Self {
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
            state: WorkloadState::Healthy,
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
// REGISTRE D'AUDIT CRYPTOGRAPHIQUE SCELLÉ (SHA-256)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CwppAuditAction {
    WorkloadRegistered,
    ProfileAdded,
    ScanExecuted,
    AnomalyDetected,
    ContainmentEnforced,
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
    pub audit_log: [Option<CwppAuditRecord>; 64],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],

    // Métriques opérationnelles
    pub total_scans: u64,
    pub total_anomalies_detected: u64,
    pub total_containments: u64,
    pub active_workloads: u32,
}

impl JamboCwppDaemon {
    pub const GENESIS_HASH: [u8; 32] = [
        0x5c, 0x77, 0x70, 0x70, 0x5f, 0x67, 0x65, 0x6e,
        0x65, 0x73, 0x69, 0x73, 0x5f, 0x68, 0x61, 0x73,
        0x68, 0x5f, 0x73, 0x6f, 0x76, 0x65, 0x72, 0x65,
        0x69, 0x67, 0x6e, 0x5f, 0x30, 0x30, 0x30, 0x31,
    ];

    pub fn new(admin_cap: CwppCap) -> Self {
        Self {
            admin_cap,
            workloads: [None; 16],
            workload_count: 0,
            profiles: [None; 8],
            profile_count: 0,
            audit_log: [None; 64],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            total_scans: 0,
            total_anomalies_detected: 0,
            total_containments: 0,
            active_workloads: 0,
        }
    }

    /// Initialise les profils souverains par défaut et les charges de travail critiques
    pub fn init_defaults(&mut self) {
        // 1. Profil Ingress Gateway
        let p_gw = WorkloadProfile::new(
            1,
            "ingress-gw",
            WorkloadType::IngressGateway,
            0x0000_0000_0000_003F, // syscalls réseau et lecture/écriture de base
            64 * 1024 * 1024,      // 64 MiB
            8,
            true,
            false,
        );

        // 2. Profil Base de Données Souveraine
        let p_db = WorkloadProfile::new(
            2,
            "sovereign-db",
            WorkloadType::Database,
            0x0000_0000_0000_00FF, // VFS, synchro mémoire, sockets locaux
            512 * 1024 * 1024,     // 512 MiB
            16,
            true,
            false,
        );

        // 3. Profil Moteur d'Inférence IA Isolée
        let p_ai = WorkloadProfile::new(
            3,
            "ai-worker",
            WorkloadType::AiWorker,
            0x0000_0000_0000_001F, // calcul intensif, VMO shm, 0 réseau
            1024 * 1024 * 1024,    // 1 GiB
            4,
            false,
            false,
        );

        // 4. Profil Démon Système Durci
        let p_sys = WorkloadProfile::new(
            4,
            "sys-daemon",
            WorkloadType::SystemDaemon,
            0x0000_0000_0000_03FF, // VFS, IPC, IPC caps
            128 * 1024 * 1024,     // 128 MiB
            12,
            false,
            false,
        );

        let cap = self.admin_cap;
        let _ = self.register_profile(&cap, p_gw, 100);
        let _ = self.register_profile(&cap, p_db, 110);
        let _ = self.register_profile(&cap, p_ai, 120);
        let _ = self.register_profile(&cap, p_sys, 130);

        // Enregistrement des 4 charges de travail initiales
        let hash_gw = Sha256::hash(b"elf64:jambo-gwd:v0.2.124");
        let hash_db = Sha256::hash(b"elf64:jambo-kvd:v0.2.124");
        let hash_ai = Sha256::hash(b"elf64:jambo-aid:v0.2.124");
        let hash_sys = Sha256::hash(b"elf64:jambo-logd:v0.2.124");

        let wl_gw = Workload::new(101, 1001, "jambo-ingress", 1, hash_gw);
        let wl_db = Workload::new(102, 1002, "jambo-kvd-db", 2, hash_db);
        let wl_ai = Workload::new(103, 1003, "jambo-ai-infer", 3, hash_ai);
        let wl_sys = Workload::new(104, 1004, "jambo-log-audit", 4, hash_sys);

        let _ = self.register_workload(&cap, wl_gw, 200);
        let _ = self.register_workload(&cap, wl_db, 210);
        let _ = self.register_workload(&cap, wl_ai, 220);
        let _ = self.register_workload(&cap, wl_sys, 230);
    }

    /// Enregistre un nouveau profil de charge de travail
    pub fn register_profile(
        &mut self,
        cap: &CwppCap,
        profile: WorkloadProfile,
        ts: u64,
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

        let details = Sha256::hash(&pid.to_be_bytes());
        self.append_audit(ts, CwppAuditAction::ProfileAdded, pid, details);

        Ok(pid)
    }

    /// Enregistre une nouvelle charge de travail surveillée
    pub fn register_workload(
        &mut self,
        cap: &CwppCap,
        wl: Workload,
        ts: u64,
    ) -> Result<u32, CwppError> {
        if !cap.has_right(cwpp_rights::REGISTER_WORKLOAD) {
            return Err(CwppError::PermissionDenied);
        }
        if self.workload_count >= self.workloads.len() {
            return Err(CwppError::BufferOverflow);
        }

        // Vérification de l'existence du profil associé
        let mut profile_found = false;
        for i in 0..self.profile_count {
            if let Some(ref p) = self.profiles[i] {
                if p.profile_id == wl.profile_id {
                    profile_found = true;
                    break;
                }
            }
        }
        if !profile_found {
            return Err(CwppError::ProfileNotFound);
        }

        let wid = wl.id;
        self.workloads[self.workload_count] = Some(wl);
        self.workload_count += 1;
        self.active_workloads += 1;

        self.append_audit(ts, CwppAuditAction::WorkloadRegistered, wid, wl.integrity_hash);

        Ok(wid)
    }

    /// Récupère l'état d'une charge de travail
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

    /// Signale un événement d'exécution Ring 3 et analyse les anomalies
    pub fn report_execution_event(
        &mut self,
        cap: &CwppCap,
        workload_id: u32,
        syscall_nr: u32,
        memory_bytes: u64,
        thread_cnt: u32,
        is_wx_mapping: bool,
        is_rip_valid: bool,
        ts: u64,
    ) -> Result<Option<AnomalyType>, CwppError> {
        if !cap.has_right(cwpp_rights::DETECT_ANOMALY) {
            return Err(CwppError::PermissionDenied);
        }

        let mut wl_idx = None;
        let mut profile_opt = None;

        for i in 0..self.workload_count {
            if let Some(ref wl) = self.workloads[i] {
                if wl.id == workload_id {
                    wl_idx = Some(i);
                    // Retrouve le profil
                    for j in 0..self.profile_count {
                        if let Some(ref p) = self.profiles[j] {
                            if p.profile_id == wl.profile_id {
                                profile_opt = Some(*p);
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }

        let idx = wl_idx.ok_or(CwppError::WorkloadNotFound)?;
        let profile = profile_opt.ok_or(CwppError::ProfileNotFound)?;

        // Détection d'anomalies par ordre de criticité
        let mut detected_anomaly = AnomalyType::None;

        if !is_rip_valid {
            detected_anomaly = AnomalyType::RipDivergence;
        } else if is_wx_mapping {
            detected_anomaly = AnomalyType::MemoryInjection;
        } else if syscall_nr < 64 && ((profile.allowed_syscall_mask & (1 << syscall_nr)) == 0) {
            detected_anomaly = AnomalyType::UnauthorizedSyscall;
        } else if memory_bytes > profile.max_memory_bytes || thread_cnt > profile.max_threads {
            detected_anomaly = AnomalyType::ResourceExhaustion;
        }

        if let Some(ref mut wl) = self.workloads[idx] {
            wl.allocated_memory = memory_bytes;
            wl.thread_count = thread_cnt;
            wl.last_seen_ts = ts;

            if detected_anomaly != AnomalyType::None {
                wl.anomaly_count += 1;
                wl.last_anomaly = detected_anomaly;
                wl.state = WorkloadState::Anomalous;
                self.total_anomalies_detected += 1;

                let mut hash_input = [0u8; 16];
                hash_input[..8].copy_from_slice(&ts.to_be_bytes());
                hash_input[8..12].copy_from_slice(&workload_id.to_be_bytes());
                hash_input[12] = detected_anomaly as u8;
                let details = Sha256::hash(&hash_input);

                self.append_audit(ts, CwppAuditAction::AnomalyDetected, workload_id, details);
                return Ok(Some(detected_anomaly));
            }
        }

        Ok(None)
    }

    /// Applique une mesure de confinement instantanée O(1) sur la charge déviante
    pub fn contain_workload(
        &mut self,
        cap: &CwppCap,
        workload_id: u32,
        action: ContainmentAction,
        ts: u64,
    ) -> Result<bool, CwppError> {
        if !cap.has_right(cwpp_rights::CONTAIN_WORKLOAD) {
            return Err(CwppError::PermissionDenied);
        }

        for i in 0..self.workload_count {
            if let Some(ref mut wl) = self.workloads[i] {
                if wl.id == workload_id {
                    if wl.state == WorkloadState::Terminated {
                        return Err(CwppError::InvalidState);
                    }

                    wl.applied_containment = action;
                    match action {
                        ContainmentAction::Terminate => {
                            wl.state = WorkloadState::Terminated;
                            if self.active_workloads > 0 {
                                self.active_workloads -= 1;
                            }
                        }
                        ContainmentAction::None => {
                            wl.state = WorkloadState::Healthy;
                        }
                        _ => {
                            wl.state = WorkloadState::Contained;
                        }
                    }

                    self.total_containments += 1;

                    let mut hash_buf = [0u8; 16];
                    hash_buf[..8].copy_from_slice(&ts.to_be_bytes());
                    hash_buf[8..12].copy_from_slice(&workload_id.to_be_bytes());
                    hash_buf[12] = action as u8;
                    let details = Sha256::hash(&hash_buf);

                    self.append_audit(ts, CwppAuditAction::ContainmentEnforced, workload_id, details);
                    return Ok(true);
                }
            }
        }

        Err(CwppError::WorkloadNotFound)
    }

    /// Scanne l'ensemble des charges de travail actives et renvoie (total_verifié, anomalies_trouvées)
    pub fn scan_all_workloads(&mut self, cap: &CwppCap, ts: u64) -> Result<(usize, usize), CwppError> {
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

        let mut hash_buf = [0u8; 16];
        hash_buf[..8].copy_from_slice(&ts.to_be_bytes());
        hash_buf[8..12].copy_from_slice(&(checked as u32).to_be_bytes());
        hash_buf[12..16].copy_from_slice(&(anomalies as u32).to_be_bytes());
        let details = Sha256::hash(&hash_buf);

        self.append_audit(ts, CwppAuditAction::ScanExecuted, 0, details);

        Ok((checked, anomalies))
    }

    /// Ajoute une entrée immuable au registre d'audit et recalcule le chaînage cryptographique
    fn append_audit(
        &mut self,
        timestamp: u64,
        action: CwppAuditAction,
        workload_id: u32,
        details_hash: [u8; 32],
    ) {
        if self.audit_count >= self.audit_log.len() {
            // Décalage FIFO pour conserver les entrées les plus récentes
            for i in 1..self.audit_log.len() {
                self.audit_log[i - 1] = self.audit_log[i];
            }
            self.audit_count = self.audit_log.len() - 1;
        }

        let index = self.audit_count as u64;
        let prev_hash = self.ledger_hash;
        let record_hash = CwppAuditRecord::compute_hash(
            index,
            timestamp,
            action,
            workload_id,
            &details_hash,
            &prev_hash,
        );

        let record = CwppAuditRecord {
            index,
            timestamp,
            action,
            workload_id,
            details_hash,
            prev_hash,
            record_hash,
        };

        self.audit_log[self.audit_count] = Some(record);
        self.audit_count += 1;
        self.ledger_hash = record_hash;
    }

    /// Vérifie l'intégrité cryptographique complète du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = Self::GENESIS_HASH;
        for i in 0..self.audit_count {
            if let Some(ref record) = self.audit_log[i] {
                if record.prev_hash != expected_prev {
                    return false;
                }
                let computed = CwppAuditRecord::compute_hash(
                    record.index,
                    record.timestamp,
                    record.action,
                    record.workload_id,
                    &record.details_hash,
                    &record.prev_hash,
                );
                if computed != record.record_hash {
                    return false;
                }
                expected_prev = record.record_hash;
            } else {
                return false;
            }
        }
        self.ledger_hash == expected_prev
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwpp_cap_attenuation() {
        let admin_cap = CwppCap::new(Handle::new(12601, 1), cwpp_rights::ALL, 10000, 500);
        assert!(admin_cap.has_right(cwpp_rights::REGISTER_WORKLOAD));
        assert!(admin_cap.has_right(cwpp_rights::DETECT_ANOMALY));
        assert!(admin_cap.has_right(cwpp_rights::CONTAIN_WORKLOAD));

        let monitor_cap = admin_cap
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
        let ev1 = daemon.report_execution_event(
            &admin_cap,
            101,
            1,
            16 * 1024 * 1024,
            4,
            false,
            true,
            1000,
        ).expect("Rapport d'exécution normal");
        assert_eq!(ev1, None);

        // Test anomalie : injection mémoire W+X sur jambo-kvd-db (ID 102)
        let ev2 = daemon.report_execution_event(
            &admin_cap,
            102,
            2,
            32 * 1024 * 1024,
            4,
            true, // W+X !
            true,
            1050,
        ).expect("Rapport d'anomalie W+X");
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
        let ev = daemon.report_execution_event(
            &admin_cap,
            103,
            0,
            64 * 1024 * 1024,
            2,
            false,
            false, // RIP invalide !
            2000,
        ).unwrap();
        assert_eq!(ev, Some(AnomalyType::RipDivergence));

        // Application du confinement immédiat : Quarantaine
        let contained = daemon.contain_workload(
            &admin_cap,
            103,
            ContainmentAction::Quarantine,
            2010,
        ).unwrap();
        assert!(contained);

        let wl103 = daemon.inspect_workload(&admin_cap, 103).unwrap();
        assert_eq!(wl103.state, WorkloadState::Contained);
        assert_eq!(wl103.applied_containment, ContainmentAction::Quarantine);
        assert_eq!(daemon.total_containments, 1);

        // Terminaison de la charge hostile
        let killed = daemon.contain_workload(
            &admin_cap,
            103,
            ContainmentAction::Terminate,
            2020,
        ).unwrap();
        assert!(killed);

        let wl103_post = daemon.inspect_workload(&admin_cap, 103).unwrap();
        assert_eq!(wl103_post.state, WorkloadState::Terminated);
        assert_eq!(daemon.active_workloads, 3);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_cwpp_scan_and_unauthorized_syscall() {
        let admin_cap = CwppCap::new(Handle::new(12604, 1), cwpp_rights::ALL, 10000, 500);
        let mut daemon = JamboCwppDaemon::new(admin_cap);
        daemon.init_defaults();

        // Syscall interdit (syscall nr 40 non autorisé pour profile 3 mask 0x1F)
        let ev = daemon.report_execution_event(
            &admin_cap,
            103,
            40,
            10 * 1024 * 1024,
            1,
            false,
            true,
            3000,
        ).unwrap();
        assert_eq!(ev, Some(AnomalyType::UnauthorizedSyscall));

        // Scan global
        let (checked, anomalies) = daemon.scan_all_workloads(&admin_cap, 3010).unwrap();
        assert_eq!(checked, 4);
        assert_eq!(anomalies, 1);
        assert!(daemon.verify_ledger_integrity());
    }
}

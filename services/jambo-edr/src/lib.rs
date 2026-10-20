//! Détection & Réponse sur les Terminaux (Endpoint Detection & Response - EDR)
//!
//! Phase 119 — Jalon v0.2.117
//!
//! Fournit une surveillance comportementale en temps réel, la détection d'intrusions,
//! l'interception d'injections dynamiques DLL/.jso, la protection contre les évasions
//! d'enclaves TEE et le scellement cryptographique d'audit SHA-256 en environnement `#![no_std]`.
//!
//! Fonctionnalités clés :
//! 1. Contrôle d'Accès Capabilaire Strict (`EdrCap`) :
//!    - Modèle Zero-Ambient Authority.
//!    - Atténuation monotone vérifiée sans amplification de privilèges.
//!    - Droits granulaires : `MONITOR_PROCESS`, `DETECT_INJECTION`, `ENCLAVE_GUARD`,
//!      `SYSTEM_HOOK_INSPECT`, `RESPOND_ISOLATE`, `SEAL_REPORT`, `AUDIT_READ`, `ADMIN`.
//!
//! 2. Surveillance Comportementale d'Arborescence de Processus :
//!    - Suivi des filiations parent-enfant (PID/PPID) et détection d'anomalies de lignage
//!      (ex: démon non-interactif engendrant un shell ou un outil de compilation).
//!    - Détection d'usurpation de noms système (masquerading).
//!    - Calcul d'indice de menace dynamique (0..100) par processus.
//!
//! 3. Moteur d'Interception d'Injections Dynamiques (.jso / DLL / GOT-PLT) :
//!    - Recensement des modules partagés chargés par processus.
//!    - Détection de modules tiers non-approuvés ou de segments W+X (Writable & Executable).
//!    - Détection de détournement de tables de saut GOT/PLT hors des bornes mémoires valides.
//!
//! 4. Garde-Fou d'Enclave Matérielle / TEE (`EnclaveGuard`) :
//!    - Détection heuristique de franchissement de frontière d'isolation d'enclave.
//!    - Blocage d'accès illicites aux MSRs privilégiés et tentatives d'extraction de clés scellées.
//!
//! 5. Inspection de Crochets Système & Intégrité Noyau (`HookInspector`) :
//!    - Détection d'injections de trampolines de saut (JMP 0xE9 / CALL indirect) dans les
//!      tables d'appels système ou gestionnaires de vecteurs d'interruptions IDT.
//!
//! 6. Moteur de Réponse & Confinement Automatisé :
//!    - Quarantaine immédiate, suspension de thread, révocation de capacités ou arrêt forcé.
//!
//! 7. Registre d'Audit Inaltérable Scellé SHA-256 :
//!    - Chaînage cryptographique inviolable de chaque alerte et action de remédiation.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation autonome et déterministe de SHA-256
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
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(Self::K[i]).wrapping_add(w[i]);
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

    pub fn update(&mut self, input: &[u8]) {
        self.total_bytes += input.len() as u64;
        let mut offset = 0;
        while offset < input.len() {
            if self.buffer_len == 64 {
                let blk = self.buffer;
                self.transform_block(&blk);
                self.buffer_len = 0;
            }
            let to_copy = (64 - self.buffer_len).min(input.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&input[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes * 8;
        let mut pad = [0u8; 128];
        pad[0] = 0x80;
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };
        self.update(&pad[..pad_len]);
        let len_bytes = bit_len.to_be_bytes();
        self.update(&len_bytes);

        if self.buffer_len == 64 {
            let blk = self.buffer;
            self.transform_block(&blk);
        }

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ============================================================================
// GESTION DES CAPACITÉS EDR (EdrCap)
// ============================================================================

pub mod edr_rights {
    pub const MONITOR_PROCESS: u32     = 1 << 0; // 0x01: Surveillance d'arborescence et filiations
    pub const DETECT_INJECTION: u32    = 1 << 1; // 0x02: Détection d'injections DLL/.jso et W+X
    pub const ENCLAVE_GUARD: u32       = 1 << 2; // 0x04: Détection d'évasion d'enclave TEE
    pub const SYSTEM_HOOK_INSPECT: u32 = 1 << 3; // 0x08: Inspection des crochets noyau/libc
    pub const RESPOND_ISOLATE: u32     = 1 << 4; // 0x10: Actions de remédiation et mise en quarantaine
    pub const SEAL_REPORT: u32         = 1 << 5; // 0x20: Scellement cryptographique des rapports
    pub const AUDIT_READ: u32          = 1 << 6; // 0x40: Lecture des alertes et du journal d'audit
    pub const ADMIN: u32               = 1 << 7; // 0x80: Administration globale du démon EDR
    pub const ALL: u32                 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdrError {
    AttenuationViolation,
    Unauthorized,
    Expired,
    Depleted,
    ProcessNotFound,
    TableFull,
    InvalidParameter,
    IntegrityTampered,
    EnclaveBreach,
    HookDetected,
    InjectionDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdrCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl EdrCap {
    pub const fn new(handle: Handle, rights: u32, max_lifetime: u64, invocations_left: u32) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, EdrError> {
        // Règle d'or des capacités monotones : aucun droit nouveau ne peut être créé
        if (new_rights & !self.rights) != 0 {
            return Err(EdrError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(EdrError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(EdrError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn check_and_consume(&mut self, required_right: u32) -> Result<(), EdrError> {
        if !self.has_right(required_right) {
            return Err(EdrError::Unauthorized);
        }
        if self.invocations_left == 0 {
            return Err(EdrError::Depleted);
        }
        self.invocations_left = self.invocations_left.saturating_sub(1);
        Ok(())
    }
}

// ============================================================================
// STRUCTURES DE SURVEILLANCE DES PROCESSUS & COMPORTEMENTS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    Running = 0,
    Suspended = 1,
    Quarantined = 2,
    Terminated = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAnomaly {
    None = 0,
    SuspiciousChildSpawn = 1,
    MasqueradingName = 2,
    PrivilegeEscalationAttempt = 3,
    ForkBombBurst = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessNode {
    pub pid: u64,
    pub ppid: u64,
    pub name: [u8; 32],
    pub name_len: usize,
    pub status: ProcessStatus,
    pub threat_score: u8, // 0 à 100
    pub spawn_timestamp: u64,
    pub cap_rights: u32,
    pub modules_count: usize,
    pub anomaly: ProcessAnomaly,
}

impl ProcessNode {
    pub fn new(pid: u64, ppid: u64, name_str: &str, cap_rights: u32, spawn_time: u64) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let copy_len = bytes.len().min(32);
        name[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Self {
            pid,
            ppid,
            name,
            name_len: copy_len,
            status: ProcessStatus::Running,
            threat_score: 0,
            spawn_timestamp: spawn_time,
            cap_rights,
            modules_count: 0,
            anomaly: ProcessAnomaly::None,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalid-utf8>")
    }
}

// ============================================================================
// STRUCTURES D'INJECTION DYNAMIQUE & MODULES PARTAGÉS (.jso)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionType {
    None = 0,
    RogueSharedObject = 1,
    WritableExecutableSegment = 2,
    GotPltRedirect = 3,
    RemoteThreadCreated = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct ModuleDescriptor {
    pub base_addr: u64,
    pub size: u64,
    pub path: [u8; 48],
    pub path_len: usize,
    pub is_trusted: bool,
    pub has_wx_segment: bool,
    pub checksum: [u8; 32],
}

impl ModuleDescriptor {
    pub fn new(base_addr: u64, size: u64, path_str: &str, is_trusted: bool, has_wx: bool) -> Self {
        let mut path = [0u8; 48];
        let bytes = path_str.as_bytes();
        let copy_len = bytes.len().min(48);
        path[..copy_len].copy_from_slice(&bytes[..copy_len]);

        // Empreinte SHA-256 déterministe basée sur le chemin et l'adresse
        let mut hasher = Sha256::new();
        hasher.update(&base_addr.to_le_bytes());
        hasher.update(&size.to_le_bytes());
        hasher.update(&path[..copy_len]);
        let checksum = hasher.finalize();

        Self {
            base_addr,
            size,
            path,
            path_len: copy_len,
            is_trusted,
            has_wx_segment: has_wx,
            checksum,
        }
    }

    pub fn path_as_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("<invalid>")
    }
}

// ============================================================================
// INSPECTION D'ENCLAVE TEE & CROCHETS SYSTÈME
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveAnomaly {
    None = 0,
    BoundaryViolation = 1,
    MsrTamperAttempt = 2,
    UnsealedKeyExtraction = 3,
    IllegalPagingRemap = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookTarget {
    SyscallTable = 1,
    IdtHandler = 2,
    LibjamboVtable = 3,
    TrampolinePatch = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct HookAnomaly {
    pub target: HookTarget,
    pub address: u64,
    pub original_opcode: [u8; 8],
    pub current_opcode: [u8; 8],
    pub is_hooked: bool,
}

// ============================================================================
// GESTIONNAIRE D'ALERTES & ACTIONS DE RÉPONSE AUTOMATISÉE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdrAction {
    LogAndPass = 0,
    SuspendProcess = 1,
    RevokeCapabilities = 2,
    QuarantineIsolate = 3,
    TerminateProcess = 4,
}

#[derive(Debug, Clone, Copy)]
pub struct EdrAlert {
    pub id: u64,
    pub timestamp: u64,
    pub pid: u64,
    pub severity: AlertSeverity,
    pub description: [u8; 64],
    pub desc_len: usize,
    pub action_taken: EdrAction,
    pub alert_hash: [u8; 32],
}

impl EdrAlert {
    pub fn new(
        id: u64,
        timestamp: u64,
        pid: u64,
        severity: AlertSeverity,
        desc: &str,
        action: EdrAction,
    ) -> Self {
        let mut description = [0u8; 64];
        let bytes = desc.as_bytes();
        let copy_len = bytes.len().min(64);
        description[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let mut hasher = Sha256::new();
        hasher.update(&id.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&pid.to_le_bytes());
        hasher.update(&[severity as u8, action as u8]);
        hasher.update(&description[..copy_len]);
        let alert_hash = hasher.finalize();

        Self {
            id,
            timestamp,
            pid,
            severity,
            description,
            desc_len: copy_len,
            action_taken: action,
            alert_hash,
        }
    }

    pub fn desc_as_str(&self) -> &str {
        core::str::from_utf8(&self.description[..self.desc_len]).unwrap_or("<invalid-utf8>")
    }
}

// ============================================================================
// REGISTRE D'AUDIT INALTÉRABLE SCISSELÉ (Audit Ledger)
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct EdrAuditEntry {
    pub index: u32,
    pub timestamp: u64,
    pub action_tag: [u8; 16],
    pub action_len: usize,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl EdrAuditEntry {
    pub fn new(index: u32, timestamp: u64, tag: &str, prev_hash: [u8; 32]) -> Self {
        let mut action_tag = [0u8; 16];
        let bytes = tag.as_bytes();
        let copy_len = bytes.len().min(16);
        action_tag[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let mut hasher = Sha256::new();
        hasher.update(&index.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&action_tag[..copy_len]);
        hasher.update(&prev_hash);
        let entry_hash = hasher.finalize();

        Self {
            index,
            timestamp,
            action_tag,
            action_len: copy_len,
            prev_hash,
            entry_hash,
        }
    }
}

// ============================================================================
// DÉMON CENTRAL EDR (`JamboEdrDaemon`)
// ============================================================================

pub struct JamboEdrDaemon {
    pub admin_cap: EdrCap,
    pub processes: [Option<ProcessNode>; 64],
    pub process_count: usize,
    pub modules: [[Option<ModuleDescriptor>; 8]; 64],
    pub alerts: [Option<EdrAlert>; 64],
    pub alert_count: usize,
    pub audit_ledger: [Option<EdrAuditEntry>; 64],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],
    pub enclave_escape_blocked_count: u32,
    pub injection_blocked_count: u32,
    pub hooks_detected_count: u32,
}

impl JamboEdrDaemon {
    pub const GENESIS_HASH: [u8; 32] = [
        0xee, 0xdd, 0xaa, 0x77, 0x11, 0x99, 0x33, 0x55,
        0xee, 0xdd, 0xaa, 0x77, 0x11, 0x99, 0x33, 0x55,
        0xee, 0xdd, 0xaa, 0x77, 0x11, 0x99, 0x33, 0x55,
        0xee, 0xdd, 0xaa, 0x77, 0x11, 0x99, 0x33, 0x55,
    ];

    pub fn new(admin_cap: EdrCap) -> Self {
        const NONE_PROC: Option<ProcessNode> = None;
        const NONE_MOD: Option<ModuleDescriptor> = None;
        const NONE_ALERT: Option<EdrAlert> = None;
        const NONE_AUDIT: Option<EdrAuditEntry> = None;

        Self {
            admin_cap,
            processes: [NONE_PROC; 64],
            process_count: 0,
            modules: [[NONE_MOD; 8]; 64],
            alerts: [NONE_ALERT; 64],
            alert_count: 0,
            audit_ledger: [NONE_AUDIT; 64],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            enclave_escape_blocked_count: 0,
            injection_blocked_count: 0,
            hooks_detected_count: 0,
        }
    }

    /// Initialise les processus système sains par défaut
    pub fn init_defaults(&mut self) {
        // Enregistre les processus fondamentaux de JamboOS
        let _ = self.register_process_internal(1, 0, "jambo-init", 0xFFFFFFFF, 10);
        let _ = self.register_process_internal(2, 1, "jambo-schedd", 0x000000FF, 20);
        let _ = self.register_process_internal(3, 1, "jambo-sh", 0x0000003F, 30);
        let _ = self.register_process_internal(4, 1, "jambo-netd", 0x0000001F, 40);

        // Modules de base sains pour PID 3 (jambo-sh)
        let _ = self.load_module_internal(3, 0x0040_0000, 0x20_000, "/lib/libjambo.jso", true, false);

        // Scellement initial du journal d'audit
        let _ = self.record_audit_entry_internal("EDR_BOOTSTRAP", 50);
    }

    fn find_proc_slot(&self, pid: u64) -> Option<usize> {
        for i in 0..self.process_count {
            if let Some(ref p) = self.processes[i] {
                if p.pid == pid {
                    return Some(i);
                }
            }
        }
        None
    }

    fn register_process_internal(
        &mut self,
        pid: u64,
        ppid: u64,
        name: &str,
        cap_rights: u32,
        timestamp: u64,
    ) -> Result<usize, EdrError> {
        if self.process_count >= 64 {
            return Err(EdrError::TableFull);
        }
        let slot = self.process_count;
        self.processes[slot] = Some(ProcessNode::new(pid, ppid, name, cap_rights, timestamp));
        self.process_count += 1;
        Ok(slot)
    }

    /// Enregistre un nouveau processus sous vérification capabilaire
    pub fn register_process(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        ppid: u64,
        name: &str,
        cap_rights: u32,
        timestamp: u64,
    ) -> Result<u64, EdrError> {
        if !cap.has_right(edr_rights::MONITOR_PROCESS) {
            return Err(EdrError::Unauthorized);
        }
        self.register_process_internal(pid, ppid, name, cap_rights, timestamp)
            .map(|_| pid)
    }

    /// Engendre un processus enfant avec détection heuristique d'anomalies de lignage
    pub fn spawn_child_process(
        &mut self,
        cap: &EdrCap,
        parent_pid: u64,
        child_pid: u64,
        child_name: &str,
        child_rights: u32,
        timestamp: u64,
    ) -> Result<ProcessAnomaly, EdrError> {
        if !cap.has_right(edr_rights::MONITOR_PROCESS) {
            return Err(EdrError::Unauthorized);
        }

        let parent_slot = self.find_proc_slot(parent_pid).ok_or(EdrError::ProcessNotFound)?;
        let parent = self.processes[parent_slot].as_ref().unwrap();

        let mut anomaly = ProcessAnomaly::None;
        let mut threat_increment = 0u8;

        // Règle 1 : Escalade de privilèges illicite (l'enfant tente d'acquérir plus de droits que le parent)
        if (child_rights & !parent.cap_rights) != 0 {
            anomaly = ProcessAnomaly::PrivilegeEscalationAttempt;
            threat_increment = 60;
        }

        // Règle 2 : Filiation suspecte (démon réseau non-interactif engendrant un interpréteur de commandes)
        if (parent.name_as_str() == "jambo-netd" || parent.name_as_str() == "jambo-waf")
            && (child_name == "jsh" || child_name == "sh" || child_name == "bash" || child_name == "zsh")
        {
            anomaly = ProcessAnomaly::SuspiciousChildSpawn;
            threat_increment = 85;
        }

        // Règle 3 : Usurpation de nom système (Masquerading / Fake kernel worker)
        if child_name.starts_with("kworker/")
            || child_name == "kthreadd"
            || child_name == "[jambo-core]"
        {
            if parent_pid != 1 {
                anomaly = ProcessAnomaly::MasqueradingName;
                threat_increment = 90;
            }
        }

        let slot = self.register_process_internal(child_pid, parent_pid, child_name, child_rights, timestamp)?;
        if let Some(ref mut child) = self.processes[slot] {
            child.anomaly = anomaly;
            child.threat_score = child.threat_score.saturating_add(threat_increment);
        }

        if anomaly != ProcessAnomaly::None {
            let mut desc_buf = [0u8; 64];
            let msg = if anomaly == ProcessAnomaly::SuspiciousChildSpawn {
                "Anomalous spawn: network daemon spawning interactive shell"
            } else if anomaly == ProcessAnomaly::PrivilegeEscalationAttempt {
                "Privilege escalation: child requested unattenuated rights"
            } else {
                "Masquerading detected: process impersonating kernel worker"
            };
            let b = msg.as_bytes();
            let l = b.len().min(64);
            desc_buf[..l].copy_from_slice(&b[..l]);

            let action = if threat_increment >= 80 {
                EdrAction::QuarantineIsolate
            } else {
                EdrAction::SuspendProcess
            };

            self.record_alert_internal(
                child_pid,
                timestamp,
                AlertSeverity::High,
                core::str::from_utf8(&desc_buf[..l]).unwrap_or("Anomaly"),
                action,
            );

            if action == EdrAction::QuarantineIsolate {
                if let Some(ref mut child) = self.processes[slot] {
                    child.status = ProcessStatus::Quarantined;
                    child.cap_rights = 0; // Révocation immédiate des capacités
                }
            }
        }

        Ok(anomaly)
    }

    fn load_module_internal(
        &mut self,
        pid: u64,
        base_addr: u64,
        size: u64,
        path: &str,
        is_trusted: bool,
        has_wx: bool,
    ) -> Result<(), EdrError> {
        let slot = self.find_proc_slot(pid).ok_or(EdrError::ProcessNotFound)?;
        let mut mod_idx = 0;
        while mod_idx < 8 && self.modules[slot][mod_idx].is_some() {
            mod_idx += 1;
        }
        if mod_idx >= 8 {
            return Err(EdrError::TableFull);
        }
        self.modules[slot][mod_idx] = Some(ModuleDescriptor::new(base_addr, size, path, is_trusted, has_wx));
        if let Some(ref mut proc) = self.processes[slot] {
            proc.modules_count += 1;
        }
        Ok(())
    }

    /// Charge et inspecte un module partagé (.jso) pour détecter des injections
    pub fn load_and_inspect_module(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        base_addr: u64,
        size: u64,
        path: &str,
        is_trusted: bool,
        has_wx: bool,
        timestamp: u64,
    ) -> Result<InjectionType, EdrError> {
        if !cap.has_right(edr_rights::DETECT_INJECTION) {
            return Err(EdrError::Unauthorized);
        }

        let mut inj_type = InjectionType::None;

        // Détection 1 : Segment W+X (Writable et Executable en même temps)
        if has_wx {
            inj_type = InjectionType::WritableExecutableSegment;
        } else if !is_trusted || path.starts_with("/tmp/") || path.contains("rogue") {
            // Détection 2 : Module tiers non fiable injecté depuis un répertoire non sécurisé
            inj_type = InjectionType::RogueSharedObject;
        }

        self.load_module_internal(pid, base_addr, size, path, is_trusted, has_wx)?;

        if inj_type != InjectionType::None {
            self.injection_blocked_count += 1;
            let slot = self.find_proc_slot(pid).unwrap();
            if let Some(ref mut proc) = self.processes[slot] {
                proc.threat_score = proc.threat_score.saturating_add(75);
                proc.status = ProcessStatus::Quarantined;
                proc.cap_rights = 0; // Confinement
            }

            self.record_alert_internal(
                pid,
                timestamp,
                AlertSeverity::Critical,
                if inj_type == InjectionType::WritableExecutableSegment {
                    "W+X memory segment injection detected in module space"
                } else {
                    "Rogue unauthorized .jso shared library injection attempt"
                },
                EdrAction::QuarantineIsolate,
            );
        }

        Ok(inj_type)
    }

    /// Inspecte un pointeur de saut de la table GOT/PLT pour vérifier qu'il pointe vers un module valide
    pub fn verify_got_plt_entry(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        target_jump_addr: u64,
        timestamp: u64,
    ) -> Result<bool, EdrError> {
        if !cap.has_right(edr_rights::DETECT_INJECTION) {
            return Err(EdrError::Unauthorized);
        }

        let slot = self.find_proc_slot(pid).ok_or(EdrError::ProcessNotFound)?;
        let mut address_valid = false;

        for i in 0..8 {
            if let Some(ref m) = self.modules[slot][i] {
                if target_jump_addr >= m.base_addr && target_jump_addr < (m.base_addr + m.size) {
                    address_valid = true;
                    break;
                }
            }
        }

        if !address_valid {
            self.injection_blocked_count += 1;
            if let Some(ref mut proc) = self.processes[slot] {
                proc.threat_score = 100;
                proc.status = ProcessStatus::Terminated;
                proc.cap_rights = 0;
            }

            self.record_alert_internal(
                pid,
                timestamp,
                AlertSeverity::Critical,
                "GOT/PLT redirection hijack detected pointing outside module space",
                EdrAction::TerminateProcess,
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Heuristique de détection d'évasion d'enclave TEE / sandbox
    pub fn inspect_enclave_access(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        is_in_enclave: bool,
        attempted_phys_addr: u64,
        is_msr_access: bool,
        timestamp: u64,
    ) -> Result<EnclaveAnomaly, EdrError> {
        if !cap.has_right(edr_rights::ENCLAVE_GUARD) {
            return Err(EdrError::Unauthorized);
        }

        if !is_in_enclave {
            return Ok(EnclaveAnomaly::None);
        }

        let mut anomaly = EnclaveAnomaly::None;

        if is_msr_access {
            anomaly = EnclaveAnomaly::MsrTamperAttempt;
        } else if attempted_phys_addr < 0x0010_0000 || attempted_phys_addr >= 0xFFFF_8000_0000_0000 {
            // Tentative de franchissement : lecture de la mémoire physique basse ou espace noyau
            anomaly = EnclaveAnomaly::BoundaryViolation;
        }

        if anomaly != EnclaveAnomaly::None {
            self.enclave_escape_blocked_count += 1;
            if let Some(slot) = self.find_proc_slot(pid) {
                if let Some(ref mut proc) = self.processes[slot] {
                    proc.threat_score = 100;
                    proc.status = ProcessStatus::Quarantined;
                    proc.cap_rights = 0;
                }
            }

            self.record_alert_internal(
                pid,
                timestamp,
                AlertSeverity::Critical,
                if anomaly == EnclaveAnomaly::MsrTamperAttempt {
                    "Enclave breach: illicit privileged MSR access attempt"
                } else {
                    "Enclave breach: unauthorized kernel memory boundary escape"
                },
                EdrAction::QuarantineIsolate,
            );
        }

        Ok(anomaly)
    }

    /// Inspection d'intégrité de tables système contre l'insertion de crochets (Hooks)
    pub fn inspect_hook_trampoline(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        target: HookTarget,
        address: u64,
        actual_bytes: &[u8; 8],
        expected_bytes: &[u8; 8],
        timestamp: u64,
    ) -> Result<HookAnomaly, EdrError> {
        if !cap.has_right(edr_rights::SYSTEM_HOOK_INSPECT) {
            return Err(EdrError::Unauthorized);
        }

        let is_hooked = actual_bytes != expected_bytes;

        let anomaly = HookAnomaly {
            target,
            address,
            original_opcode: *expected_bytes,
            current_opcode: *actual_bytes,
            is_hooked,
        };

        if is_hooked {
            self.hooks_detected_count += 1;
            if let Some(slot) = self.find_proc_slot(pid) {
                if let Some(ref mut proc) = self.processes[slot] {
                    proc.threat_score = proc.threat_score.saturating_add(80);
                    proc.status = ProcessStatus::Suspended;
                }
            }

            self.record_alert_internal(
                pid,
                timestamp,
                AlertSeverity::High,
                "System hook detected: trampoline opcode mismatch in syscall/IDT",
                EdrAction::SuspendProcess,
            );
        }

        Ok(anomaly)
    }

    /// Action manuelle ou automatique de mise en quarantaine / isolation d'un processus
    pub fn isolate_process(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        timestamp: u64,
    ) -> Result<(), EdrError> {
        if !cap.has_right(edr_rights::RESPOND_ISOLATE) {
            return Err(EdrError::Unauthorized);
        }

        let slot = self.find_proc_slot(pid).ok_or(EdrError::ProcessNotFound)?;
        if let Some(ref mut proc) = self.processes[slot] {
            proc.status = ProcessStatus::Quarantined;
            proc.cap_rights = 0;
            proc.threat_score = proc.threat_score.max(80);
        }

        self.record_alert_internal(
            pid,
            timestamp,
            AlertSeverity::High,
            "Operator manual EDR process isolation and capability revocation",
            EdrAction::QuarantineIsolate,
        );

        Ok(())
    }

    fn record_alert_internal(
        &mut self,
        pid: u64,
        timestamp: u64,
        severity: AlertSeverity,
        desc: &str,
        action: EdrAction,
    ) {
        if self.alert_count < 64 {
            let id = (self.alert_count as u64) + 1;
            let alert = EdrAlert::new(id, timestamp, pid, severity, desc, action);
            self.alerts[self.alert_count] = Some(alert);
            self.alert_count += 1;

            let _ = self.record_audit_entry_internal("EDR_ALERT_SEAL", timestamp);
        }
    }

    fn record_audit_entry_internal(&mut self, tag: &str, timestamp: u64) -> Result<[u8; 32], EdrError> {
        if self.audit_count >= 64 {
            return Err(EdrError::TableFull);
        }
        let index = self.audit_count as u32;
        let entry = EdrAuditEntry::new(index, timestamp, tag, self.ledger_hash);
        self.ledger_hash = entry.entry_hash;
        self.audit_ledger[self.audit_count] = Some(entry);
        self.audit_count += 1;
        Ok(self.ledger_hash)
    }

    /// Enregistre une entrée d'audit cryptographique scellée avec vérification de capacité
    pub fn record_audit_entry(&mut self, cap: &EdrCap, tag: &str, timestamp: u64) -> Result<[u8; 32], EdrError> {
        if !cap.has_right(edr_rights::SEAL_REPORT) {
            return Err(EdrError::Unauthorized);
        }
        self.record_audit_entry_internal(tag, timestamp)
    }

    /// Vérifie formellement l'intégrité de la chaîne cryptographique SHA-256 du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut cur_hash = Self::GENESIS_HASH;
        for i in 0..self.audit_count {
            if let Some(ref entry) = self.audit_ledger[i] {
                if entry.prev_hash != cur_hash {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.index.to_le_bytes());
                hasher.update(&entry.timestamp.to_le_bytes());
                hasher.update(&entry.action_tag[..entry.action_len]);
                hasher.update(&entry.prev_hash);
                let computed = hasher.finalize();

                if computed != entry.entry_hash {
                    return false;
                }
                cur_hash = entry.entry_hash;
            } else {
                return false;
            }
        }
        cur_hash == self.ledger_hash
    }

    pub fn get_process(&self, pid: u64) -> Option<&ProcessNode> {
        self.find_proc_slot(pid).and_then(|slot| self.processes[slot].as_ref())
    }

    pub fn get_process_mut(&mut self, pid: u64) -> Option<&mut ProcessNode> {
        self.find_proc_slot(pid).and_then(|slot| self.processes[slot].as_mut())
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] COMPATIBLES)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edr_capability_attenuation() {
        let root_cap = EdrCap::new(Handle::new(11900, 1), edr_rights::ALL, 10000, 100);
        assert!(root_cap.has_right(edr_rights::MONITOR_PROCESS));
        assert!(root_cap.has_right(edr_rights::DETECT_INJECTION));
        assert!(root_cap.has_right(edr_rights::ENCLAVE_GUARD));
        assert!(root_cap.has_right(edr_rights::ADMIN));

        // Atténuation légitime
        let monitor_cap = root_cap
            .attenuate(edr_rights::MONITOR_PROCESS | edr_rights::AUDIT_READ, 5000, 50)
            .expect("Atténuation monotone");
        assert!(monitor_cap.has_right(edr_rights::MONITOR_PROCESS));
        assert!(monitor_cap.has_right(edr_rights::AUDIT_READ));
        assert!(!monitor_cap.has_right(edr_rights::RESPOND_ISOLATE));
        assert!(!monitor_cap.has_right(edr_rights::ADMIN));

        // Rejet d'amplification illégale de privilèges
        let invalid = monitor_cap.attenuate(edr_rights::ALL, 5000, 50);
        assert_eq!(invalid, Err(EdrError::AttenuationViolation));
    }

    #[test]
    fn test_process_tree_anomaly_detection() {
        let admin_cap = EdrCap::new(Handle::new(11901, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // PID 4 (jambo-netd) engendre illicitement 'jsh'
        let anomaly = daemon
            .spawn_child_process(&admin_cap, 4, 10, "jsh", 0x1F, 100)
            .expect("Analyse spawn");
        assert_eq!(anomaly, ProcessAnomaly::SuspiciousChildSpawn);

        let child = daemon.get_process(10).expect("Child process present");
        assert_eq!(child.status, ProcessStatus::Quarantined);
        assert_eq!(child.cap_rights, 0); // Capabilités révoquées
        assert!(child.threat_score >= 80);
    }

    #[test]
    fn test_injection_detection_wx_and_rogue() {
        let admin_cap = EdrCap::new(Handle::new(11902, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // Tentative d'injection d'un segment W+X
        let res_wx = daemon.load_and_inspect_module(
            &admin_cap,
            3,
            0x7000_0000,
            0x1000,
            "/tmp/payload.jso",
            false,
            true,
            200,
        );
        assert_eq!(res_wx, Ok(InjectionType::WritableExecutableSegment));
        assert_eq!(daemon.injection_blocked_count, 1);

        let proc = daemon.get_process(3).unwrap();
        assert_eq!(proc.status, ProcessStatus::Quarantined);
    }

    #[test]
    fn test_got_plt_hijacking_detection() {
        let admin_cap = EdrCap::new(Handle::new(11903, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // Adresse de saut valide dans /lib/libjambo.jso (0x0040_0000 + 0x20_000)
        let valid = daemon
            .verify_got_plt_entry(&admin_cap, 3, 0x0040_1000, 300)
            .expect("GOT check");
        assert!(valid);

        // Adresse de saut détournée hors limites (ex: 0xDEAD_BEEF)
        let hijacked = daemon
            .verify_got_plt_entry(&admin_cap, 3, 0xDEAD_BEEF, 310)
            .expect("GOT check");
        assert!(!hijacked);

        let proc = daemon.get_process(3).unwrap();
        assert_eq!(proc.status, ProcessStatus::Terminated);
    }

    #[test]
    fn test_enclave_guard_escape_heuristic() {
        let admin_cap = EdrCap::new(Handle::new(11904, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // Enclave tentant d'accéder à la mémoire basse (IDT/BIOS physique 0x400)
        let anomaly = daemon
            .inspect_enclave_access(&admin_cap, 2, true, 0x400, false, 400)
            .expect("Enclave check");
        assert_eq!(anomaly, EnclaveAnomaly::BoundaryViolation);
        assert_eq!(daemon.enclave_escape_blocked_count, 1);

        let proc = daemon.get_process(2).unwrap();
        assert_eq!(proc.status, ProcessStatus::Quarantined);
    }

    #[test]
    fn test_system_hook_trampoline_inspection() {
        let admin_cap = EdrCap::new(Handle::new(11905, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let original_opcode = [0x0f, 0x05, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90]; // syscall; ret
        let hooked_opcode = [0xe9, 0x78, 0x56, 0x34, 0x12, 0x90, 0x90, 0x90];   // jmp relative

        let inspection = daemon
            .inspect_hook_trampoline(
                &admin_cap,
                1,
                HookTarget::SyscallTable,
                0xFFFF_8000_0010_0000,
                &hooked_opcode,
                &original_opcode,
                500,
            )
            .expect("Hook inspection");

        assert!(inspection.is_hooked);
        assert_eq!(daemon.hooks_detected_count, 1);

        let proc = daemon.get_process(1).unwrap();
        assert_eq!(proc.status, ProcessStatus::Suspended);
    }

    #[test]
    fn test_audit_ledger_cryptographic_integrity() {
        let admin_cap = EdrCap::new(Handle::new(11906, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        assert!(daemon.verify_ledger_integrity());
        assert_ne!(daemon.ledger_hash, JamboEdrDaemon::GENESIS_HASH);

        // Ajout d'une entrée manuelle
        let new_hash = daemon
            .record_audit_entry(&admin_cap, "MANUAL_CHECK", 600)
            .expect("Record audit");
        assert_eq!(new_hash, daemon.ledger_hash);
        assert!(daemon.verify_ledger_integrity());

        // Simulation d'une altération malveillante
        if let Some(ref mut entry) = daemon.audit_ledger[0] {
            entry.action_tag[0] ^= 0xFF; // Corruption de données
        }
        assert!(!daemon.verify_ledger_integrity());
    }
}

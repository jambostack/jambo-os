//! Détection et Réponse sur les Terminaux Souveraine EDR (`jambo-edr`)
//!
//! Phase 149 — Jalon v0.3.71 (Promotion PID 32)
//!
//! Fournit un système souverain complet de surveillance comportementale en temps réel,
//! d'interception d'injections dynamiques DLL/.jso/GOT-PLT, de protection contre les évasions
//! d'enclaves TEE, de neutralisation de shellcodes en mémoire, d'isolation O(1),
//! de scellement cryptographique d'audit SHA-256 et d'un protocole IPC déterministe à 64 octets
//! en environnement purement `#![no_std]` et sans allocation dynamique.
//!
//! Fonctionnalités clés :
//! 1. Contrôle d'Accès Capabilaire Strict (`EdrCap`) :
//!    - Modèle Zero-Ambient Authority (ZAA).
//!    - Atténuation monotone sans amplification de privilèges.
//!    - Droits granulaires : `MONITOR_PROCESS`, `DETECT_INJECTION`, `ENCLAVE_GUARD`,
//!      `SYSTEM_HOOK_INSPECT`, `RESPOND_ISOLATE`, `SEAL_REPORT`, `AUDIT_READ`,
//!      `SCAN_MEMORY`, `ADMIN`.
//!
//! 2. Surveillance Comportementale Avancée d'Arborescence & Télémétrie Syscalls :
//!    - Suivi des filiations parent-enfant (PID/PPID) et détection d'anomalies de lignage
//!      (démons réseau engendrant un shell interactif ou usurpation de workers noyau).
//!    - Détection de fork-bombs, déni de service et patterns d'appels système interdits.
//!    - Calcul d'indice de menace dynamique (0..100) par processus.
//!
//! 3. Moteur d'Interception d'Injections Dynamiques (.jso / GOT-PLT / W+X) :
//!    - Détection de modules tiers non-approuvés ou segments W+X (Writable & Executable).
//!    - Détection de détournement de tables de saut GOT/PLT hors des bornes mémoires valides.
//!    - Détection de Process Hollowing (altération d'en-tête / divergence du point d'entrée ELF).
//!
//! 4. Scanneur de Shellcode en Mémoire Vive (`scan_process_memory`) :
//!    - Détection d'atterrissages NOP sled (séries d'opcodes 0x90).
//!    - Détection de pièges INT3 (0xCC) et boucles de syscalls furtifs (0x0F 0x05).
//!    - Détection de pivots de pile ROP (`mov rsp, rbp` / `pop rsp; ret`).
//!
//! 5. Garde-Fou d'Enclave Matérielle / TEE (`EnclaveGuard`) :
//!    - Détection heuristique de franchissement de frontière d'isolation d'enclave.
//!    - Blocage d'accès illicites aux MSRs privilégiés (IA32_LSTAR, IA32_EFER) et mémoire basse.
//!    - Suivi d'état d'attestation d'enclave (Valid, Suspect, Quarantined).
//!
//! 6. Inspection de Crochets Système & Intégrité Noyau (`HookInspector`) :
//!    - Détection d'injections de trampolines de saut (JMP 0xE9 / CALL indirect) dans les
//!      tables d'appels système ou gestionnaires de vecteurs d'interruptions IDT.
//!
//! 7. Confinement O(1) Instantané & Remédiation Déterministe (`EdrRemediationReport`) :
//!    - Quarantaine immédiate, révocation instantanée des capabilités, suspension ou terminaison.
//!
//! 8. Registre d'Audit Inaltérable Scellé SHA-256 (`EdrSummary`) :
//!    - Chaînage cryptographique inviolable de chaque alerte et action de remédiation.
//!
//! 9. Protocole IPC Déterministe à 64 octets sous l'endpoint 32 (PID 32).

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES SYSTÈME & LIMITES EDR
// ============================================================================

/// Identifiant d'endpoint IPC standard pour le service EDR (PID 32).
pub const EDR_ENDPOINT_ID: u32 = 32;

/// Magic bytes pour requête IPC EDR : "EDRD" = 0x45445244
pub const EDR_MAGIC_REQ: u32 = 0x45445244;

/// Magic bytes pour réponse IPC EDR : "EDRS" = 0x45445253
pub const EDR_MAGIC_RESP: u32 = 0x45445253;

/// Taille maximale du message IPC rapide (octets).
pub const MAX_FASTPATH_BYTES: usize = 64;

/// Nombre maximal de handles transmis dans un message IPC.
pub const MAX_HANDLES: usize = 4;

/// Taille d'un haché SHA-256 (octets).
pub const SHA256_LEN: usize = 32;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std], Zéro Alloc)
// ============================================================================

/// Implémentation autonome et déterministe de SHA-256
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
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

    #[allow(clippy::needless_range_loop)]
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
    pub const MONITOR_PROCESS: u32 = 1 << 0; // 0x01: Surveillance d'arborescence et filiations
    pub const DETECT_INJECTION: u32 = 1 << 1; // 0x02: Détection d'injections DLL/.jso et W+X
    pub const ENCLAVE_GUARD: u32 = 1 << 2; // 0x04: Détection d'évasion d'enclave TEE
    pub const SYSTEM_HOOK_INSPECT: u32 = 1 << 3; // 0x08: Inspection des crochets noyau/libc
    pub const RESPOND_ISOLATE: u32 = 1 << 4; // 0x10: Actions de remédiation et mise en quarantaine
    pub const SEAL_REPORT: u32 = 1 << 5; // 0x20: Scellement cryptographique des rapports
    pub const AUDIT_READ: u32 = 1 << 6; // 0x40: Lecture des alertes et du journal d'audit
    pub const SCAN_MEMORY: u32 = 1 << 7; // 0x80: Analyse de mémoire vive et shellcodes
    pub const ADMIN: u32 = 1 << 8; // 0x100: Administration globale du démon EDR
    pub const ALL: u32 = 0x1FF;
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
    ShellcodeDetected,
    MemoryScanFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdrCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl EdrCap {
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
    ProcessHollowingAttempt = 5,
    RogueSyscallPattern = 6,
    ShellcodeInjected = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveStatus {
    NotEnclave = 0,
    EnclaveValid = 1,
    EnclaveSuspect = 2,
    EnclaveQuarantined = 3,
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
    pub is_enclave: bool,
    pub enclave_status: EnclaveStatus,
    pub syscall_count: u32,
    pub last_entry_point: u64,
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
            is_enclave: false,
            enclave_status: EnclaveStatus::NotEnclave,
            syscall_count: 0,
            last_entry_point: 0x0040_0000,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalid-utf8>")
    }
}

// ============================================================================
// STRUCTURES D'INJECTION DYNAMIQUE & SCANNEUR DE SHELLCODE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionType {
    None = 0,
    RogueSharedObject = 1,
    WritableExecutableSegment = 2,
    GotPltRedirect = 3,
    RemoteThreadCreated = 4,
    MemoryShellcode = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeScanResult {
    Clean = 0,
    NopSledDetected = 1,
    SyscallTrapLoop = 2,
    StackPivotDetected = 3,
    Int3TrapDetected = 4,
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
    SideChannelSpeculativeEscape = 5,
}

/// Garde-fou d'enclave matérielle TEE
#[derive(Debug, Clone, Copy)]
pub struct EnclaveGuard {
    pub enclave_id: u32,
    pub base_addr: u64,
    pub size: u64,
    pub status: EnclaveStatus,
}

impl EnclaveGuard {
    pub const fn new(enclave_id: u32, base_addr: u64, size: u64) -> Self {
        Self {
            enclave_id,
            base_addr,
            size,
            status: EnclaveStatus::EnclaveValid,
        }
    }

    pub fn inspect_access(&mut self, target_addr: u64, is_msr: bool) -> EnclaveAnomaly {
        if is_msr {
            self.status = EnclaveStatus::EnclaveQuarantined;
            EnclaveAnomaly::MsrTamperAttempt
        } else if !(0x0010_0000..0xFFFF_8000_0000_0000).contains(&target_addr) {
            self.status = EnclaveStatus::EnclaveQuarantined;
            EnclaveAnomaly::BoundaryViolation
        } else {
            EnclaveAnomaly::None
        }
    }
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

/// Inspecteur statique de crochets système (trampolines et IDT)
pub struct HookInspector;

impl HookInspector {
    pub fn inspect(
        target: HookTarget,
        address: u64,
        actual: &[u8; 8],
        expected: &[u8; 8],
    ) -> HookAnomaly {
        HookAnomaly {
            target,
            address,
            original_opcode: *expected,
            current_opcode: *actual,
            is_hooked: actual != expected,
        }
    }
}

// ============================================================================
// GESTIONNAIRE D'ALERTES & REMÉDIATION O(1)
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

/// Rapport d'action de remédiation déterministe O(1)
#[derive(Debug, Clone, Copy)]
pub struct EdrRemediationReport {
    pub pid: u64,
    pub action: EdrAction,
    pub threat_score: u8,
    pub reason: [u8; 64],
    pub reason_len: usize,
    pub revoked_rights: u32,
    pub timestamp: u64,
}

impl EdrRemediationReport {
    pub fn reason_as_str(&self) -> &str {
        core::str::from_utf8(&self.reason[..self.reason_len]).unwrap_or("<invalid-utf8>")
    }
}

// ============================================================================
// REGISTRE D'AUDIT INALTÉRABLE SCELLÉ (Audit Ledger) & RÉSUMÉ
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

/// Synthèse globale de l'état opérationnel EDR
#[derive(Debug, Clone, Copy)]
pub struct EdrSummary {
    pub total_processes: usize,
    pub running_processes: usize,
    pub quarantined_processes: usize,
    pub terminated_processes: usize,
    pub alert_count: usize,
    pub audit_count: usize,
    pub injections_blocked: u32,
    pub enclave_escapes_blocked: u32,
    pub hooks_detected: u32,
    pub shellcodes_intercepted: u32,
    pub ledger_valid: bool,
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE 64 OCTETS (`EdrOpcode`, `EdrRequest`, `EdrResponse`)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdrOpcode {
    GetStatus = 1,
    ScanProcess = 2,
    IsolateProcess = 3,
    GetProcessTree = 4,
    GetAlerts = 5,
    GetAudit = 6,
}

impl EdrOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::ScanProcess),
            3 => Some(Self::IsolateProcess),
            4 => Some(Self::GetProcessTree),
            5 => Some(Self::GetAlerts),
            6 => Some(Self::GetAudit),
            _ => None,
        }
    }
}

/// Requête IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdrRequest {
    pub magic: u32,        // 0..4: 0x45445244 ("EDRD")
    pub opcode: u32,       // 4..8: Code d'opération
    pub handle_id: u32,    // 8..12: Handle de capacité émetteur
    pub rights: u32,       // 12..16: Droits requis
    pub pid: u64,          // 16..24: PID cible
    pub param_u64: u64,    // 24..32: Paramètre scalaire ou horodatage
    pub payload: [u8; 32], // 32..64: Charge utile (mémoire à scanner, raison, etc.)
}

const _: () = assert!(core::mem::size_of::<EdrRequest>() == 64);

impl Default for EdrRequest {
    fn default() -> Self {
        Self {
            magic: EDR_MAGIC_REQ,
            opcode: EdrOpcode::GetStatus as u32,
            handle_id: EDR_ENDPOINT_ID,
            rights: edr_rights::ALL,
            pid: 0,
            param_u64: 0,
            payload: [0u8; 32],
        }
    }
}

impl EdrRequest {
    pub const fn new(opcode: EdrOpcode) -> Self {
        Self {
            magic: EDR_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: EDR_ENDPOINT_ID,
            rights: edr_rights::ALL,
            pid: 0,
            param_u64: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: EDR_MAGIC_REQ,
            opcode: EdrOpcode::GetStatus as u32,
            handle_id,
            rights,
            pid: 0,
            param_u64: 0,
            payload: [0u8; 32],
        }
    }

    pub fn new_scan(handle_id: u32, rights: u32, pid: u64, memory_snippet: &[u8]) -> Self {
        let mut payload = [0u8; 32];
        let copy_len = memory_snippet.len().min(32);
        payload[..copy_len].copy_from_slice(&memory_snippet[..copy_len]);
        Self {
            magic: EDR_MAGIC_REQ,
            opcode: EdrOpcode::ScanProcess as u32,
            handle_id,
            rights,
            pid,
            param_u64: 0,
            payload,
        }
    }

    pub fn new_isolate(handle_id: u32, rights: u32, pid: u64, reason: &str) -> Self {
        let mut payload = [0u8; 32];
        let bytes = reason.as_bytes();
        let copy_len = bytes.len().min(32);
        payload[..copy_len].copy_from_slice(&bytes[..copy_len]);
        Self {
            magic: EDR_MAGIC_REQ,
            opcode: EdrOpcode::IsolateProcess as u32,
            handle_id,
            rights,
            pid,
            param_u64: 0,
            payload,
        }
    }

    pub const fn new_process_tree(handle_id: u32, rights: u32, pid: u64) -> Self {
        Self {
            magic: EDR_MAGIC_REQ,
            opcode: EdrOpcode::GetProcessTree as u32,
            handle_id,
            rights,
            pid,
            param_u64: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_alerts(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: EDR_MAGIC_REQ,
            opcode: EdrOpcode::GetAlerts as u32,
            handle_id,
            rights,
            pid: 0,
            param_u64: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_audit(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: EDR_MAGIC_REQ,
            opcode: EdrOpcode::GetAudit as u32,
            handle_id,
            rights,
            pid: 0,
            param_u64: 0,
            payload: [0u8; 32],
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..8].copy_from_slice(&self.opcode.to_le_bytes());
        b[8..12].copy_from_slice(&self.handle_id.to_le_bytes());
        b[12..16].copy_from_slice(&self.rights.to_le_bytes());
        b[16..24].copy_from_slice(&self.pid.to_le_bytes());
        b[24..32].copy_from_slice(&self.param_u64.to_le_bytes());
        b[32..64].copy_from_slice(&self.payload);
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != EDR_MAGIC_REQ {
            return None;
        }
        let opcode = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let handle_id = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let rights = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let pid = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let param_u64 = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        let mut payload = [0u8; 32];
        payload.copy_from_slice(&bytes[32..64]);

        Some(Self {
            magic,
            opcode,
            handle_id,
            rights,
            pid,
            param_u64,
            payload,
        })
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdrResponse {
    pub magic: u32,             // 0..4: 0x45445253 ("EDRS")
    pub status: i32,            // 4..8: Code statut (0 = succès, <0 = erreur)
    pub threat_score: u32,      // 8..12: Score de menace (0..100)
    pub scan_result: u32,       // 12..16: Résultat de scan ou code d'action
    pub pid: u64,               // 16..24: PID concerné
    pub timestamp: u64,         // 24..32: Horodatage
    pub audit_preview: [u8; 8], // 32..40: Échantillon d'audit SHA-256
    pub status_str: [u8; 24],   // 40..64: Message ASCII descriptif
}

const _: () = assert!(core::mem::size_of::<EdrResponse>() == 64);

impl Default for EdrResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl EdrResponse {
    pub const fn new() -> Self {
        Self {
            magic: EDR_MAGIC_RESP,
            status: 0,
            threat_score: 0,
            scan_result: 0,
            pid: 0,
            timestamp: 0,
            audit_preview: [0u8; 8],
            status_str: [0u8; 24],
        }
    }

    pub fn set_status_str(&mut self, s: &str) {
        let mut buf = [0u8; 24];
        let bytes = s.as_bytes();
        let len = bytes.len().min(24);
        buf[..len].copy_from_slice(&bytes[..len]);
        self.status_str = buf;
    }

    pub fn status_as_str(&self) -> &str {
        let len = self.status_str.iter().position(|&b| b == 0).unwrap_or(24);
        core::str::from_utf8(&self.status_str[..len]).unwrap_or("<invalid-utf8>")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..8].copy_from_slice(&self.status.to_le_bytes());
        b[8..12].copy_from_slice(&self.threat_score.to_le_bytes());
        b[12..16].copy_from_slice(&self.scan_result.to_le_bytes());
        b[16..24].copy_from_slice(&self.pid.to_le_bytes());
        b[24..32].copy_from_slice(&self.timestamp.to_le_bytes());
        b[32..40].copy_from_slice(&self.audit_preview);
        b[40..64].copy_from_slice(&self.status_str);
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != EDR_MAGIC_RESP {
            return None;
        }
        let status = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let threat_score = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let scan_result = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let pid = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let timestamp = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        let mut audit_preview = [0u8; 8];
        audit_preview.copy_from_slice(&bytes[32..40]);
        let mut status_str = [0u8; 24];
        status_str.copy_from_slice(&bytes[40..64]);

        Some(Self {
            magic,
            status,
            threat_score,
            scan_result,
            pid,
            timestamp,
            audit_preview,
            status_str,
        })
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`EdrClient`, `ChannelMessage`)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [Handle; MAX_HANDLES],
    pub handle_count: usize,
}

impl Default for ChannelMessage {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
            handles: [Handle::NULL; MAX_HANDLES],
            handle_count: 0,
        }
    }
}

/// Client synchrone Ring 3 pour interagir avec le démon jambo-edr (PID 32).
pub struct EdrClient {
    pub endpoint: Handle,
}

impl EdrClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn call(&self, req: &EdrRequest) -> Result<EdrResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.endpoint.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };

        if ret_send != 0 {
            return Err(SysError::InvalidHandle);
        }

        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        while attempts < 100 {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.endpoint.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<EdrResponse>() {
                return EdrResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            libjambo::syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }

    pub fn get_status(&self, cap: &EdrCap) -> Result<EdrResponse, SysError> {
        let req = EdrRequest::new_status(EDR_ENDPOINT_ID, cap.rights);
        self.call(&req)
    }

    pub fn scan_process(
        &self,
        cap: &EdrCap,
        pid: u64,
        mem: &[u8],
    ) -> Result<EdrResponse, SysError> {
        let req = EdrRequest::new_scan(EDR_ENDPOINT_ID, cap.rights, pid, mem);
        self.call(&req)
    }

    pub fn isolate_process(
        &self,
        cap: &EdrCap,
        pid: u64,
        reason: &str,
    ) -> Result<EdrResponse, SysError> {
        let req = EdrRequest::new_isolate(EDR_ENDPOINT_ID, cap.rights, pid, reason);
        self.call(&req)
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
    pub shellcodes_intercepted_count: u32,
}

impl JamboEdrDaemon {
    pub const GENESIS_HASH: [u8; 32] = [
        0xee, 0xdd, 0xaa, 0x77, 0x11, 0x99, 0x33, 0x55, 0xee, 0xdd, 0xaa, 0x77, 0x11, 0x99, 0x33,
        0x55, 0xee, 0xdd, 0xaa, 0x77, 0x11, 0x99, 0x33, 0x55, 0xee, 0xdd, 0xaa, 0x77, 0x11, 0x99,
        0x33, 0x55,
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
            shellcodes_intercepted_count: 0,
        }
    }

    /// Initialise les processus système sains par défaut
    pub fn init_defaults(&mut self) {
        // Enregistre les processus fondamentaux de JamboOS
        let _ = self.register_process_internal(1, 0, "jambo-init", 0xFFFFFFFF, 10);
        let _ = self.register_process_internal(2, 1, "jambo-schedd", 0x000000FF, 20);
        let _ = self.register_process_internal(3, 1, "jambo-sh", 0x0000003F, 30);
        let _ = self.register_process_internal(4, 1, "jambo-netd", 0x0000001F, 40);

        // Enclave TEE matérielle pour PID 2 (jambo-schedd)
        if let Some(slot) = self.find_proc_slot(2) {
            if let Some(ref mut proc) = self.processes[slot] {
                proc.is_enclave = true;
                proc.enclave_status = EnclaveStatus::EnclaveValid;
            }
        }

        // Modules de base sains pour PID 3 (jambo-sh)
        let _ =
            self.load_module_internal(3, 0x0040_0000, 0x20_000, "/lib/libjambo.jso", true, false);

        // Scellement initial du journal d'audit
        let _ = self.record_audit_entry_internal("EDR_BOOTSTRAP", 50);
    }

    fn find_proc_slot(&self, pid: u64) -> Option<usize> {
        for (i, p_opt) in self.processes.iter().enumerate().take(self.process_count) {
            if let Some(ref p) = p_opt {
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

    /// Enregistre un processus dans une enclave matérielle TEE protégée
    pub fn register_enclave_process(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        _enclave_id: u32,
        timestamp: u64,
    ) -> Result<(), EdrError> {
        if !cap.has_right(edr_rights::ENCLAVE_GUARD) {
            return Err(EdrError::Unauthorized);
        }
        let slot = self.find_proc_slot(pid).ok_or(EdrError::ProcessNotFound)?;
        if let Some(ref mut proc) = self.processes[slot] {
            proc.is_enclave = true;
            proc.enclave_status = EnclaveStatus::EnclaveValid;
        }
        let _ = self.record_audit_entry_internal("ENCLAVE_REGISTER", timestamp);
        Ok(())
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

        let parent_slot = self
            .find_proc_slot(parent_pid)
            .ok_or(EdrError::ProcessNotFound)?;
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
            && (child_name == "jsh"
                || child_name == "sh"
                || child_name == "bash"
                || child_name == "zsh")
        {
            anomaly = ProcessAnomaly::SuspiciousChildSpawn;
            threat_increment = 85;
        }

        // Règle 3 : Usurpation de nom système (Masquerading / Fake kernel worker)
        if (child_name.starts_with("kworker/")
            || child_name == "kthreadd"
            || child_name == "[jambo-core]")
            && parent_pid != 1
        {
            anomaly = ProcessAnomaly::MasqueradingName;
            threat_increment = 90;
        }

        let slot = self.register_process_internal(
            child_pid,
            parent_pid,
            child_name,
            child_rights,
            timestamp,
        )?;
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
        self.modules[slot][mod_idx] = Some(ModuleDescriptor::new(
            base_addr, size, path, is_trusted, has_wx,
        ));
        if let Some(ref mut proc) = self.processes[slot] {
            proc.modules_count += 1;
        }
        Ok(())
    }

    /// Charge et inspecte un module partagé (.jso) pour détecter des injections
    #[allow(clippy::too_many_arguments)]
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

        if has_wx {
            inj_type = InjectionType::WritableExecutableSegment;
        } else if !is_trusted || path.starts_with("/tmp/") || path.contains("rogue") {
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

        for m in self.modules[slot].iter().flatten() {
            if target_jump_addr >= m.base_addr && target_jump_addr < (m.base_addr + m.size) {
                address_valid = true;
                break;
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

    /// Détection de Process Hollowing (altération d'en-tête / divergence du point d'entrée exécutable)
    pub fn detect_process_hollowing(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        expected_entry: u64,
        actual_entry: u64,
        timestamp: u64,
    ) -> Result<bool, EdrError> {
        if !cap.has_right(edr_rights::DETECT_INJECTION) {
            return Err(EdrError::Unauthorized);
        }

        let slot = self.find_proc_slot(pid).ok_or(EdrError::ProcessNotFound)?;
        if expected_entry != actual_entry {
            self.injection_blocked_count += 1;
            if let Some(ref mut proc) = self.processes[slot] {
                proc.threat_score = 100;
                proc.status = ProcessStatus::Terminated;
                proc.cap_rights = 0;
                proc.anomaly = ProcessAnomaly::ProcessHollowingAttempt;
            }

            self.record_alert_internal(
                pid,
                timestamp,
                AlertSeverity::Critical,
                "Process hollowing detected: entrypoint hijacked from binary spec",
                EdrAction::TerminateProcess,
            );
            return Ok(true);
        }

        Ok(false)
    }

    /// Analyse et scanneur de shellcode en mémoire vive (NOP sleds, INT3 loops, syscall loops, stack pivots)
    pub fn scan_process_memory(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        memory_buffer: &[u8],
        timestamp: u64,
    ) -> Result<ShellcodeScanResult, EdrError> {
        if !cap.has_right(edr_rights::SCAN_MEMORY) {
            return Err(EdrError::Unauthorized);
        }

        let slot = self.find_proc_slot(pid).ok_or(EdrError::ProcessNotFound)?;
        let mut scan_result = ShellcodeScanResult::Clean;

        // 1. Détection de NOP Sled (au moins 8 NOP consécutifs 0x90)
        let mut nop_run = 0usize;
        for &b in memory_buffer {
            if b == 0x90 {
                nop_run += 1;
                if nop_run >= 8 {
                    scan_result = ShellcodeScanResult::NopSledDetected;
                    break;
                }
            } else {
                nop_run = 0;
            }
        }

        // 2. Détection de pièges INT3 répétitifs (au moins 4 octets 0xCC consécutifs)
        if scan_result == ShellcodeScanResult::Clean {
            let mut int3_run = 0usize;
            for &b in memory_buffer {
                if b == 0xCC {
                    int3_run += 1;
                    if int3_run >= 4 {
                        scan_result = ShellcodeScanResult::Int3TrapDetected;
                        break;
                    }
                } else {
                    int3_run = 0;
                }
            }
        }

        // 3. Détection de motif de boucle de syscalls malveillante (0x0F 0x05)
        if scan_result == ShellcodeScanResult::Clean && memory_buffer.len() >= 2 {
            for i in 0..(memory_buffer.len() - 1) {
                if memory_buffer[i] == 0x0F && memory_buffer[i + 1] == 0x05 {
                    scan_result = ShellcodeScanResult::SyscallTrapLoop;
                    break;
                }
            }
        }

        // 4. Détection de pivot de pile ROP (ex: mov rsp, rbp: 0x48 0x89 0xEC ou pop rsp; ret: 0x5C 0xC3)
        if scan_result == ShellcodeScanResult::Clean && memory_buffer.len() >= 2 {
            for i in 0..(memory_buffer.len() - 1) {
                if (memory_buffer[i] == 0x5C && memory_buffer[i + 1] == 0xC3)
                    || (i + 2 < memory_buffer.len()
                        && memory_buffer[i] == 0x48
                        && memory_buffer[i + 1] == 0x89
                        && memory_buffer[i + 2] == 0xEC)
                {
                    scan_result = ShellcodeScanResult::StackPivotDetected;
                    break;
                }
            }
        }

        if scan_result != ShellcodeScanResult::Clean {
            self.shellcodes_intercepted_count += 1;
            if let Some(ref mut proc) = self.processes[slot] {
                proc.threat_score = 95;
                proc.status = ProcessStatus::Quarantined;
                proc.cap_rights = 0;
                proc.anomaly = ProcessAnomaly::ShellcodeInjected;
            }

            let desc = match scan_result {
                ShellcodeScanResult::NopSledDetected => {
                    "In-memory NOP sled payload pattern detected in process buffer"
                }
                ShellcodeScanResult::SyscallTrapLoop => {
                    "In-memory raw syscall 0x0F 0x05 opcode loop trap detected"
                }
                ShellcodeScanResult::StackPivotDetected => {
                    "In-memory ROP gadget stack-pivot sequence detected"
                }
                ShellcodeScanResult::Int3TrapDetected => {
                    "In-memory repetitive INT3 debug trap sequence detected"
                }
                ShellcodeScanResult::Clean => "Clean",
            };

            self.record_alert_internal(
                pid,
                timestamp,
                AlertSeverity::Critical,
                desc,
                EdrAction::QuarantineIsolate,
            );
        }

        Ok(scan_result)
    }

    /// Évaluation de la télémétrie des appels système (détection de fork bombs et numéros anormaux)
    pub fn evaluate_syscall_telemetry(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        syscall_nr: u32,
        call_rate_per_sec: u32,
        timestamp: u64,
    ) -> Result<ProcessAnomaly, EdrError> {
        if !cap.has_right(edr_rights::MONITOR_PROCESS) {
            return Err(EdrError::Unauthorized);
        }

        let slot = self.find_proc_slot(pid).ok_or(EdrError::ProcessNotFound)?;
        let mut anomaly = ProcessAnomaly::None;

        if call_rate_per_sec > 10_000 {
            // Burst excessif de syscalls (Fork bomb / flooding)
            anomaly = ProcessAnomaly::ForkBombBurst;
            if let Some(ref mut proc) = self.processes[slot] {
                proc.threat_score = proc.threat_score.saturating_add(85);
                proc.status = ProcessStatus::Quarantined;
                proc.cap_rights = 0;
                proc.anomaly = anomaly;
            }

            self.record_alert_internal(
                pid,
                timestamp,
                AlertSeverity::Critical,
                "Process syscall burst frequency exceeded threshold: fork bomb rate",
                EdrAction::QuarantineIsolate,
            );
        } else if syscall_nr == 0xDEAD || syscall_nr == 0xFFFF {
            // Numéro de syscall illicite ou corrompu
            anomaly = ProcessAnomaly::RogueSyscallPattern;
            if let Some(ref mut proc) = self.processes[slot] {
                proc.threat_score = proc.threat_score.saturating_add(70);
                proc.status = ProcessStatus::Suspended;
                proc.anomaly = anomaly;
            }

            self.record_alert_internal(
                pid,
                timestamp,
                AlertSeverity::High,
                "Rogue illegal syscall number intercepted: possible probe attack",
                EdrAction::SuspendProcess,
            );
        } else if let Some(ref mut proc) = self.processes[slot] {
            proc.syscall_count = proc.syscall_count.saturating_add(1);
        }

        Ok(anomaly)
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
        } else if !(0x0010_0000..0xFFFF_8000_0000_0000).contains(&attempted_phys_addr) {
            anomaly = EnclaveAnomaly::BoundaryViolation;
        }

        if anomaly != EnclaveAnomaly::None {
            self.enclave_escape_blocked_count += 1;
            if let Some(slot) = self.find_proc_slot(pid) {
                if let Some(ref mut proc) = self.processes[slot] {
                    proc.threat_score = 100;
                    proc.status = ProcessStatus::Quarantined;
                    proc.enclave_status = EnclaveStatus::EnclaveQuarantined;
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
    #[allow(clippy::too_many_arguments)]
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

        let anomaly = HookInspector::inspect(target, address, actual_bytes, expected_bytes);

        if anomaly.is_hooked {
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
        let _ = self.isolate_process_with_report(cap, pid, "Manual isolation", timestamp)?;
        Ok(())
    }

    /// Action de confinement instantané O(1) avec rapport structuré de remédiation
    pub fn isolate_process_with_report(
        &mut self,
        cap: &EdrCap,
        pid: u64,
        reason: &str,
        timestamp: u64,
    ) -> Result<EdrRemediationReport, EdrError> {
        if !cap.has_right(edr_rights::RESPOND_ISOLATE) {
            return Err(EdrError::Unauthorized);
        }

        let slot = self.find_proc_slot(pid).ok_or(EdrError::ProcessNotFound)?;
        let mut revoked_rights = 0u32;
        let mut final_threat = 80u8;

        if let Some(ref mut proc) = self.processes[slot] {
            revoked_rights = proc.cap_rights;
            proc.status = ProcessStatus::Quarantined;
            proc.cap_rights = 0;
            proc.threat_score = proc.threat_score.max(80);
            final_threat = proc.threat_score;
        }

        let mut r_buf = [0u8; 64];
        let bytes = reason.as_bytes();
        let copy_len = bytes.len().min(64);
        r_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        self.record_alert_internal(
            pid,
            timestamp,
            AlertSeverity::High,
            reason,
            EdrAction::QuarantineIsolate,
        );

        Ok(EdrRemediationReport {
            pid,
            action: EdrAction::QuarantineIsolate,
            threat_score: final_threat,
            reason: r_buf,
            reason_len: copy_len,
            revoked_rights,
            timestamp,
        })
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

    fn record_audit_entry_internal(
        &mut self,
        tag: &str,
        timestamp: u64,
    ) -> Result<[u8; 32], EdrError> {
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
    pub fn record_audit_entry(
        &mut self,
        cap: &EdrCap,
        tag: &str,
        timestamp: u64,
    ) -> Result<[u8; 32], EdrError> {
        if !cap.has_right(edr_rights::SEAL_REPORT) {
            return Err(EdrError::Unauthorized);
        }
        self.record_audit_entry_internal(tag, timestamp)
    }

    /// Fournit un résumé consolidé de l'état EDR
    pub fn summary(&self) -> EdrSummary {
        let mut running = 0usize;
        let mut quarantined = 0usize;
        let mut terminated = 0usize;

        for p in self.processes.iter().take(self.process_count).flatten() {
            match p.status {
                ProcessStatus::Running => running += 1,
                ProcessStatus::Quarantined => quarantined += 1,
                ProcessStatus::Terminated => terminated += 1,
                ProcessStatus::Suspended => {}
            }
        }

        EdrSummary {
            total_processes: self.process_count,
            running_processes: running,
            quarantined_processes: quarantined,
            terminated_processes: terminated,
            alert_count: self.alert_count,
            audit_count: self.audit_count,
            injections_blocked: self.injection_blocked_count,
            enclave_escapes_blocked: self.enclave_escape_blocked_count,
            hooks_detected: self.hooks_detected_count,
            shellcodes_intercepted: self.shellcodes_intercepted_count,
            ledger_valid: self.verify_ledger_integrity(),
        }
    }

    /// Vérifie formellement l'intégrité de la chaîne cryptographique SHA-256 du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut cur_hash = Self::GENESIS_HASH;
        for entry_opt in self.audit_ledger.iter().take(self.audit_count) {
            if let Some(ref entry) = entry_opt {
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
        self.find_proc_slot(pid)
            .and_then(|slot| self.processes[slot].as_ref())
    }

    pub fn get_process_mut(&mut self, pid: u64) -> Option<&mut ProcessNode> {
        self.find_proc_slot(pid)
            .and_then(|slot| self.processes[slot].as_mut())
    }

    /// Traitement déterministe d'une requête IPC calibrée à 64 octets
    pub fn dispatch_ipc(&mut self, req: &EdrRequest) -> EdrResponse {
        if req.magic != EDR_MAGIC_REQ {
            let mut resp = EdrResponse::new();
            resp.status = -1;
            resp.set_status_str("BAD_MAGIC");
            return resp;
        }

        let opcode = match EdrOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                let mut resp = EdrResponse::new();
                resp.status = -1;
                resp.set_status_str("BAD_OPCODE");
                return resp;
            }
        };

        let cap = EdrCap::new(Handle::new(req.handle_id, 1), req.rights, 10_000, 1000);
        let mut resp = EdrResponse::new();
        resp.audit_preview.copy_from_slice(&self.ledger_hash[..8]);

        match opcode {
            EdrOpcode::GetStatus => {
                if !cap.has_right(edr_rights::AUDIT_READ) && !cap.has_right(edr_rights::ADMIN) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let summary = self.summary();
                resp.status = 0;
                resp.threat_score = summary.quarantined_processes as u32;
                resp.scan_result = summary.total_processes as u32;
                resp.set_status_str("STATUS_OK");
            }
            EdrOpcode::ScanProcess => {
                if !cap.has_right(edr_rights::SCAN_MEMORY) && !cap.has_right(edr_rights::ADMIN) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let pid = req.pid;
                let ts = if req.param_u64 != 0 { req.param_u64 } else { 1 };
                match self.scan_process_memory(&cap, pid, &req.payload, ts) {
                    Ok(scan_res) => {
                        resp.status = 0;
                        resp.pid = pid;
                        resp.scan_result = scan_res as u32;
                        if let Some(proc) = self.get_process(pid) {
                            resp.threat_score = proc.threat_score as u32;
                        }
                        match scan_res {
                            ShellcodeScanResult::Clean => resp.set_status_str("SCAN_CLEAN"),
                            ShellcodeScanResult::NopSledDetected => resp.set_status_str("NOP_SLED"),
                            ShellcodeScanResult::SyscallTrapLoop => {
                                resp.set_status_str("SYSCALL_LOOP")
                            }
                            ShellcodeScanResult::StackPivotDetected => {
                                resp.set_status_str("STACK_PIVOT")
                            }
                            ShellcodeScanResult::Int3TrapDetected => {
                                resp.set_status_str("INT3_TRAP")
                            }
                        }
                    }
                    Err(EdrError::ProcessNotFound) => {
                        resp.status = -2;
                        resp.set_status_str("PROC_NOT_FOUND");
                    }
                    Err(_) => {
                        resp.status = -1;
                        resp.set_status_str("SCAN_ERR");
                    }
                }
            }
            EdrOpcode::IsolateProcess => {
                if !cap.has_right(edr_rights::RESPOND_ISOLATE) && !cap.has_right(edr_rights::ADMIN)
                {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let pid = req.pid;
                let ts = if req.param_u64 != 0 { req.param_u64 } else { 1 };
                let reason_len = req.payload.iter().position(|&b| b == 0).unwrap_or(32);
                let reason =
                    core::str::from_utf8(&req.payload[..reason_len]).unwrap_or("IPC Isolate");
                match self.isolate_process_with_report(&cap, pid, reason, ts) {
                    Ok(report) => {
                        resp.status = 0;
                        resp.pid = pid;
                        resp.threat_score = report.threat_score as u32;
                        resp.scan_result = report.revoked_rights;
                        resp.set_status_str("ISOLATE_OK");
                    }
                    Err(EdrError::ProcessNotFound) => {
                        resp.status = -2;
                        resp.set_status_str("PROC_NOT_FOUND");
                    }
                    Err(_) => {
                        resp.status = -1;
                        resp.set_status_str("ISOLATE_ERR");
                    }
                }
            }
            EdrOpcode::GetProcessTree => {
                if !cap.has_right(edr_rights::MONITOR_PROCESS) && !cap.has_right(edr_rights::ADMIN)
                {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let pid = req.pid;
                if let Some(proc) = self.get_process(pid) {
                    resp.status = 0;
                    resp.pid = proc.pid;
                    resp.threat_score = proc.threat_score as u32;
                    resp.scan_result = proc.status as u32;
                    resp.timestamp = proc.spawn_timestamp;
                    resp.set_status_str(proc.name_as_str());
                } else {
                    resp.status = -2;
                    resp.set_status_str("PROC_NOT_FOUND");
                }
            }
            EdrOpcode::GetAlerts => {
                if !cap.has_right(edr_rights::AUDIT_READ) && !cap.has_right(edr_rights::ADMIN) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                resp.status = 0;
                resp.scan_result = self.alert_count as u32;
                let idx = req.param_u64 as usize;
                if idx < self.alert_count && idx < 64 {
                    if let Some(alert) = self.alerts[idx] {
                        resp.pid = alert.pid;
                        resp.threat_score = alert.severity as u32;
                        resp.timestamp = alert.timestamp;
                    }
                }
                resp.set_status_str("ALERTS_OK");
            }
            EdrOpcode::GetAudit => {
                if !cap.has_right(edr_rights::AUDIT_READ) && !cap.has_right(edr_rights::ADMIN) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                resp.status = 0;
                resp.scan_result = self.audit_count as u32;
                resp.set_status_str("AUDIT_OK");
            }
        }

        resp.audit_preview.copy_from_slice(&self.ledger_hash[..8]);
        resp
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
        assert!(root_cap.has_right(edr_rights::SCAN_MEMORY));
        assert!(root_cap.has_right(edr_rights::ADMIN));

        // Atténuation légitime
        let monitor_cap = root_cap
            .attenuate(
                edr_rights::MONITOR_PROCESS | edr_rights::AUDIT_READ | edr_rights::SCAN_MEMORY,
                5000,
                50,
            )
            .expect("Atténuation monotone");
        assert!(monitor_cap.has_right(edr_rights::MONITOR_PROCESS));
        assert!(monitor_cap.has_right(edr_rights::AUDIT_READ));
        assert!(monitor_cap.has_right(edr_rights::SCAN_MEMORY));
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
    fn test_process_hollowing_detection() {
        let admin_cap = EdrCap::new(Handle::new(11904, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // Point d'entrée attendu 0x0040_0000 vs actuel détourné 0xCAFE_0000
        let hollowed = daemon
            .detect_process_hollowing(&admin_cap, 3, 0x0040_0000, 0xCAFE_0000, 350)
            .expect("Hollowing check");
        assert!(hollowed);

        let proc = daemon.get_process(3).unwrap();
        assert_eq!(proc.status, ProcessStatus::Terminated);
        assert_eq!(proc.anomaly, ProcessAnomaly::ProcessHollowingAttempt);
    }

    #[test]
    fn test_in_memory_shellcode_scanner() {
        let admin_cap = EdrCap::new(Handle::new(11905, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // 1. Buffer avec un NOP sled malveillant (10 octets 0x90)
        let mut nop_buffer = [0x90u8; 16];
        nop_buffer[10] = 0xC3;
        let scan_nop = daemon
            .scan_process_memory(&admin_cap, 3, &nop_buffer, 360)
            .expect("Memory scan");
        assert_eq!(scan_nop, ShellcodeScanResult::NopSledDetected);
        assert_eq!(daemon.shellcodes_intercepted_count, 1);

        // 2. Buffer avec un appel système brut (0x0F 0x05)
        let syscall_buf = [0x48, 0x31, 0xC0, 0x0F, 0x05, 0xC3];
        let scan_sys = daemon
            .scan_process_memory(&admin_cap, 4, &syscall_buf, 370)
            .expect("Memory scan");
        assert_eq!(scan_sys, ShellcodeScanResult::SyscallTrapLoop);
        assert_eq!(daemon.shellcodes_intercepted_count, 2);

        // 3. Buffer avec INT3 debug trap sequence (4x 0xCC)
        let int3_buf = [0xCC, 0xCC, 0xCC, 0xCC, 0xC3];
        let scan_int3 = daemon
            .scan_process_memory(&admin_cap, 1, &int3_buf, 375)
            .expect("Memory scan");
        assert_eq!(scan_int3, ShellcodeScanResult::Int3TrapDetected);
        assert_eq!(daemon.shellcodes_intercepted_count, 3);

        // 4. Buffer avec ROP gadget stack-pivot sequence (pop rsp; ret: 0x5C 0xC3)
        let rop_buf = [0x5C, 0xC3, 0x90, 0x90];
        let scan_rop = daemon
            .scan_process_memory(&admin_cap, 2, &rop_buf, 378)
            .expect("Memory scan");
        assert_eq!(scan_rop, ShellcodeScanResult::StackPivotDetected);
        assert_eq!(daemon.shellcodes_intercepted_count, 4);

        // 5. Buffer avec ROP gadget mov rsp, rbp (0x48 0x89 0xEC)
        let rop_mov_buf = [0x48, 0x89, 0xEC, 0xC3];
        let scan_rop_mov = daemon
            .scan_process_memory(&admin_cap, 2, &rop_mov_buf, 379)
            .expect("Memory scan");
        assert_eq!(scan_rop_mov, ShellcodeScanResult::StackPivotDetected);
        assert_eq!(daemon.shellcodes_intercepted_count, 5);
    }

    #[test]
    fn test_syscall_telemetry_forkbomb_and_rogue() {
        let admin_cap = EdrCap::new(Handle::new(11906, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // Syscall anormale avec cadence > 10000 / sec
        let anomaly = daemon
            .evaluate_syscall_telemetry(&admin_cap, 4, 1, 15_000, 380)
            .expect("Syscall telemetry check");
        assert_eq!(anomaly, ProcessAnomaly::ForkBombBurst);

        let proc = daemon.get_process(4).unwrap();
        assert_eq!(proc.status, ProcessStatus::Quarantined);
    }

    #[test]
    fn test_enclave_guard_escape_heuristic() {
        let admin_cap = EdrCap::new(Handle::new(11907, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // Test EnclaveGuard direct
        let mut guard = EnclaveGuard::new(1, 0x0040_0000, 0x10000);
        assert_eq!(guard.status, EnclaveStatus::EnclaveValid);
        let msr_anomaly = guard.inspect_access(0, true);
        assert_eq!(msr_anomaly, EnclaveAnomaly::MsrTamperAttempt);
        assert_eq!(guard.status, EnclaveStatus::EnclaveQuarantined);

        let mut guard2 = EnclaveGuard::new(2, 0x0040_0000, 0x10000);
        let bound_anomaly = guard2.inspect_access(0x500, false);
        assert_eq!(bound_anomaly, EnclaveAnomaly::BoundaryViolation);
        assert_eq!(guard2.status, EnclaveStatus::EnclaveQuarantined);

        // Enclave tentant d'accéder à la mémoire basse (IDT/BIOS physique 0x400) via le daemon
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
        let admin_cap = EdrCap::new(Handle::new(11908, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let original_opcode = [0x0f, 0x05, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90]; // syscall; ret
        let hooked_opcode = [0xe9, 0x78, 0x56, 0x34, 0x12, 0x90, 0x90, 0x90]; // jmp relative

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
    fn test_remediation_report_and_summary() {
        let admin_cap = EdrCap::new(Handle::new(11909, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        let report = daemon
            .isolate_process_with_report(&admin_cap, 3, "Compromise detected", 550)
            .expect("Isolation report");
        assert_eq!(report.pid, 3);
        assert_eq!(report.action, EdrAction::QuarantineIsolate);
        assert_eq!(report.reason_as_str(), "Compromise detected");

        let summary = daemon.summary();
        assert_eq!(summary.total_processes, 4);
        assert_eq!(summary.quarantined_processes, 1);
        assert!(summary.ledger_valid);
    }

    #[test]
    fn test_audit_ledger_cryptographic_integrity() {
        let admin_cap = EdrCap::new(Handle::new(11910, 1), edr_rights::ALL, 10000, 100);
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

    #[test]
    fn test_ipc_request_response_serialization_64_bytes() {
        assert_eq!(core::mem::size_of::<EdrRequest>(), 64);
        assert_eq!(core::mem::size_of::<EdrResponse>(), 64);

        let req = EdrRequest::new_scan(
            EDR_ENDPOINT_ID,
            edr_rights::SCAN_MEMORY,
            42,
            &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        );
        let req_bytes = req.to_bytes();
        assert_eq!(req_bytes.len(), 64);

        let parsed_req = EdrRequest::from_bytes(&req_bytes).expect("parse req");
        assert_eq!(parsed_req.magic, EDR_MAGIC_REQ);
        assert_eq!(parsed_req.opcode, EdrOpcode::ScanProcess as u32);
        assert_eq!(parsed_req.pid, 42);
        assert_eq!(parsed_req.payload[0], 0x90);

        let mut resp = EdrResponse::new();
        resp.status = 0;
        resp.threat_score = 75;
        resp.scan_result = ShellcodeScanResult::NopSledDetected as u32;
        resp.pid = 42;
        resp.timestamp = 12345678;
        resp.audit_preview = [1, 2, 3, 4, 5, 6, 7, 8];
        resp.set_status_str("NOP_SLED");

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);

        let parsed_resp = EdrResponse::from_bytes(&resp_bytes).expect("parse resp");
        assert_eq!(parsed_resp.magic, EDR_MAGIC_RESP);
        assert_eq!(parsed_resp.status, 0);
        assert_eq!(parsed_resp.threat_score, 75);
        assert_eq!(
            parsed_resp.scan_result,
            ShellcodeScanResult::NopSledDetected as u32
        );
        assert_eq!(parsed_resp.pid, 42);
        assert_eq!(parsed_resp.status_as_str(), "NOP_SLED");
    }

    #[test]
    fn test_ipc_dispatch_operations() {
        let admin_cap = EdrCap::new(Handle::new(11911, 1), edr_rights::ALL, 10000, 100);
        let mut daemon = JamboEdrDaemon::new(admin_cap);
        daemon.init_defaults();

        // 1. GetStatus
        let req_status = EdrRequest::new_status(EDR_ENDPOINT_ID, edr_rights::ALL);
        let resp_status = daemon.dispatch_ipc(&req_status);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.status_as_str(), "STATUS_OK");

        // 2. ScanProcess (clean)
        let clean_buf = [0x55, 0x48, 0x89, 0xE5, 0xC3];
        let req_scan = EdrRequest::new_scan(EDR_ENDPOINT_ID, edr_rights::ALL, 1, &clean_buf);
        let resp_scan = daemon.dispatch_ipc(&req_scan);
        assert_eq!(resp_scan.status, 0);
        assert_eq!(resp_scan.status_as_str(), "SCAN_CLEAN");

        // 3. ScanProcess (NOP sled)
        let nop_buf = [0x90u8; 16];
        let req_scan_nop = EdrRequest::new_scan(EDR_ENDPOINT_ID, edr_rights::ALL, 3, &nop_buf);
        let resp_scan_nop = daemon.dispatch_ipc(&req_scan_nop);
        assert_eq!(resp_scan_nop.status, 0);
        assert_eq!(resp_scan_nop.status_as_str(), "NOP_SLED");

        // 4. IsolateProcess
        let req_isolate =
            EdrRequest::new_isolate(EDR_ENDPOINT_ID, edr_rights::ALL, 4, "Quarantine Netd");
        let resp_isolate = daemon.dispatch_ipc(&req_isolate);
        assert_eq!(resp_isolate.status, 0);
        assert_eq!(resp_isolate.status_as_str(), "ISOLATE_OK");
        assert_eq!(resp_isolate.pid, 4);

        // 5. GetProcessTree
        let req_tree = EdrRequest::new_process_tree(EDR_ENDPOINT_ID, edr_rights::ALL, 1);
        let resp_tree = daemon.dispatch_ipc(&req_tree);
        assert_eq!(resp_tree.status, 0);
        assert_eq!(resp_tree.status_as_str(), "jambo-init");

        // 6. GetAlerts
        let req_alerts = EdrRequest::new_alerts(EDR_ENDPOINT_ID, edr_rights::ALL);
        let resp_alerts = daemon.dispatch_ipc(&req_alerts);
        assert_eq!(resp_alerts.status, 0);
        assert_eq!(resp_alerts.status_as_str(), "ALERTS_OK");

        // 7. GetAudit
        let req_audit = EdrRequest::new_audit(EDR_ENDPOINT_ID, edr_rights::ALL);
        let resp_audit = daemon.dispatch_ipc(&req_audit);
        assert_eq!(resp_audit.status, 0);
        assert_eq!(resp_audit.status_as_str(), "AUDIT_OK");

        // 8. Mauvais Magic
        let mut bad_req = req_status;
        bad_req.magic = 0x12345678;
        let resp_bad = daemon.dispatch_ipc(&bad_req);
        assert_eq!(resp_bad.status, -1);
        assert_eq!(resp_bad.status_as_str(), "BAD_MAGIC");

        // 9. Droit refusé
        let denied_req = EdrRequest::new_status(EDR_ENDPOINT_ID, edr_rights::SCAN_MEMORY);
        let resp_denied = daemon.dispatch_ipc(&denied_req);
        assert_eq!(resp_denied.status, -13);
        assert_eq!(resp_denied.status_as_str(), "CAP_DENIED");
    }
}

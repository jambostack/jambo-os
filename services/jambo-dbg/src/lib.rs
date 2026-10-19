//! Démon de Débogage Dynamique d'Espace Utilisateur (`jambo-dbg`)
//!
//! Fournit une infrastructure de débogage souveraine pour le micro-noyau JamboOS (`#![no_std]`) :
//! 1. Gestion des exceptions matérielles de débogage INT1 (#DB) et d'arrêt INT3 (#BP).
//! 2. Configuration et émulation des registres matériels x86-64 DR0..DR7 (Breakpoints & Watchpoints).
//! 3. Exécution pas à pas matérielle (*Single-Stepping*) via le drapeau Trap Flag (TF) dans RFLAGS.
//! 4. Introspection et modification sécurisée des registres de threads utilisateur.
//! 5. Introspection et modification de la mémoire virtuelle d'un processus cible avec désassemblage compact.
//! 6. Registre d'audit inviolable scellé par chaîne cryptographique SHA-256.
//! 7. Modèle de sécurité capabilaire strict (`DbgCap`) sans autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_SESSIONS: usize = 4;
pub const MAX_THREADS_PER_SESSION: usize = 8;
pub const MAX_BREAKPOINTS: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_MEM_REGIONS: usize = 4;
pub const MEM_REGION_SIZE: usize = 256;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 pure `#![no_std]` sans allocation
#[derive(Clone, Copy)]
pub struct Sha256;

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn gamma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn gamma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
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
            w[i] = Self::gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(Self::gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut state = [
            0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let rem = data.len() - offset;
        block[..rem].copy_from_slice(&data[offset..]);
        block[rem] = 0x80;
        for b in &mut block[rem + 1..] {
            *b = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
        }

        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut state, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// MODÈLE DE SÉCURITÉ CAPABILAIRE : DbgCap
// ============================================================================

pub mod dbg_rights {
    pub const DBG_INSPECT: u32    = 1 << 0;
    pub const DBG_ATTACH: u32     = 1 << 1;
    pub const DBG_BREAKPOINT: u32 = 1 << 2;
    pub const DBG_STEP: u32       = 1 << 3;
    pub const DBG_MEM_READ: u32   = 1 << 4;
    pub const DBG_MEM_WRITE: u32  = 1 << 5;
    pub const DBG_REG_READ: u32   = 1 << 6;
    pub const DBG_REG_WRITE: u32  = 1 << 7;
    pub const DBG_AUDIT: u32      = 1 << 8;
    pub const DBG_ADMIN: u32      = 1 << 9;

    pub const ALL: u32 = DBG_INSPECT
        | DBG_ATTACH
        | DBG_BREAKPOINT
        | DBG_STEP
        | DBG_MEM_READ
        | DBG_MEM_WRITE
        | DBG_REG_READ
        | DBG_REG_WRITE
        | DBG_AUDIT
        | DBG_ADMIN;
}

/// Capacité de contrôle d'accès pour le débogage dynamique d'espace utilisateur
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DbgCap {
    pub handle: Handle,
    pub rights: u32,
}

impl DbgCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits vers un sous-ensemble strict.
    /// Interdit formellement toute amplification de privilèges.
    pub fn attenuate(&self, new_rights: u32) -> Result<DbgCap, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(DbgCap {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// REGISTRES MATÉRIELS DE DÉBOGAGE x86-64 DR0..DR7 & ÉMULATION
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrSlot {
    Dr0 = 0,
    Dr1 = 1,
    Dr2 = 2,
    Dr3 = 3,
}

impl DrSlot {
    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Dr0),
            1 => Some(Self::Dr1),
            2 => Some(Self::Dr2),
            3 => Some(Self::Dr3),
            _ => None,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrCondition {
    Execute = 0b00,
    DataWrite = 0b01,
    IoPort = 0b10,
    DataReadWrite = 0b11,
}

impl DrCondition {
    pub fn name(self) -> &'static str {
        match self {
            Self::Execute => "exec",
            Self::DataWrite => "write",
            Self::IoPort => "io",
            Self::DataReadWrite => "rw",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrLength {
    Len1 = 0b00,
    Len2 = 0b01,
    Len8 = 0b10,
    Len4 = 0b11,
}

impl DrLength {
    pub fn bytes(self) -> usize {
        match self {
            Self::Len1 => 1,
            Self::Len2 => 2,
            Self::Len8 => 8,
            Self::Len4 => 4,
        }
    }
}

/// Décodage du registre DR6 (Debug Status Register)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Dr6Status {
    pub b0: bool,      // Condition DR0 détectée
    pub b1: bool,      // Condition DR1 détectée
    pub b2: bool,      // Condition DR2 détectée
    pub b3: bool,      // Condition DR3 détectée
    pub bd: bool,      // Détection d'accès au registre de débogage (GD)
    pub bs: bool,      // Single step (TF activé)
    pub bt: bool,      // Commutation de tâche (TSS)
}

impl Dr6Status {
    pub fn from_raw(raw: u64) -> Self {
        Self {
            b0: (raw & (1 << 0)) != 0,
            b1: (raw & (1 << 1)) != 0,
            b2: (raw & (1 << 2)) != 0,
            b3: (raw & (1 << 3)) != 0,
            bd: (raw & (1 << 13)) != 0,
            bs: (raw & (1 << 14)) != 0,
            bt: (raw & (1 << 15)) != 0,
        }
    }

    pub fn to_raw(self) -> u64 {
        let mut raw = 0xFFFF_0FF0u64; // Bits réservés à 1 selon architecture x86
        if self.b0 { raw |= 1 << 0; }
        if self.b1 { raw |= 1 << 1; }
        if self.b2 { raw |= 1 << 2; }
        if self.b3 { raw |= 1 << 3; }
        if self.bd { raw |= 1 << 13; }
        if self.bs { raw |= 1 << 14; }
        if self.bt { raw |= 1 << 15; }
        raw
    }

    pub fn has_any_breakpoint(&self) -> bool {
        self.b0 || self.b1 || self.b2 || self.b3
    }
}

/// Configuration des registres DR0..DR7 pour un thread
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareDrConfig {
    pub dr: [u64; 4],
    pub dr6: u64,
    pub dr7: u64,
}

impl Default for HardwareDrConfig {
    fn default() -> Self {
        Self {
            dr: [0; 4],
            dr6: 0xFFFF_0FF0,
            dr7: 0x0000_0400, // Bit 10 fixé à 1 sur x86-64
        }
    }
}

impl HardwareDrConfig {
    /// Configure un slot matériel DR0..DR3 et met à jour le registre DR7
    pub fn set_slot(
        &mut self,
        slot: DrSlot,
        addr: u64,
        cond: DrCondition,
        len: DrLength,
    ) {
        let idx = slot.index();
        self.dr[idx] = addr;

        // Configuration DR7
        // Enable bit (Local Enable L0..L3)
        let local_enable_bit = idx * 2;
        self.dr7 |= 1 << local_enable_bit;

        // Condition RW0..RW3 (bits 16 + idx * 4, 2 bits)
        let rw_shift = 16 + idx * 4;
        self.dr7 &= !(0b11 << rw_shift);
        self.dr7 |= (cond as u64) << rw_shift;

        // Length LEN0..LEN3 (bits 18 + idx * 4, 2 bits)
        let len_shift = 18 + idx * 4;
        self.dr7 &= !(0b11 << len_shift);
        self.dr7 |= (len as u64) << len_shift;
    }

    /// Désactive un slot matériel DR0..DR3
    pub fn clear_slot(&mut self, slot: DrSlot) {
        let idx = slot.index();
        self.dr[idx] = 0;
        let local_enable_bit = idx * 2;
        self.dr7 &= !(1 << local_enable_bit);
    }

    pub fn is_slot_enabled(&self, slot: DrSlot) -> bool {
        let idx = slot.index();
        (self.dr7 & (1 << (idx * 2))) != 0
    }
}

// ============================================================================
// CONTEXTE DES REGISTRES DE THREAD RING 3
// ============================================================================

pub const RFLAGS_TF: u64 = 1 << 8; // Trap Flag (Single-Stepping)
pub const RFLAGS_IF: u64 = 1 << 9; // Interrupt Enable Flag

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ThreadRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u64,
    pub ss: u64,
    pub cr2: u64,
}

impl ThreadRegisters {
    pub fn new_user(rip: u64, rsp: u64) -> Self {
        Self {
            rip,
            rsp,
            rbp: rsp,
            rflags: 0x0202, // IF et bit réservé activés
            cs: 0x23,       // Sélecteur User Code x86-64
            ss: 0x1B,       // Sélecteur User Data x86-64
            ..Default::default()
        }
    }

    #[inline]
    pub fn is_single_step_enabled(&self) -> bool {
        (self.rflags & RFLAGS_TF) != 0
    }

    #[inline]
    pub fn set_single_step(&mut self, enabled: bool) {
        if enabled {
            self.rflags |= RFLAGS_TF;
        } else {
            self.rflags &= !RFLAGS_TF;
        }
    }

    pub fn get_by_name(&self, name: &str) -> Option<u64> {
        match name {
            "rax" => Some(self.rax),
            "rbx" => Some(self.rbx),
            "rcx" => Some(self.rcx),
            "rdx" => Some(self.rdx),
            "rsi" => Some(self.rsi),
            "rdi" => Some(self.rdi),
            "rbp" => Some(self.rbp),
            "rsp" => Some(self.rsp),
            "r8"  => Some(self.r8),
            "r9"  => Some(self.r9),
            "r10" => Some(self.r10),
            "r11" => Some(self.r11),
            "r12" => Some(self.r12),
            "r13" => Some(self.r13),
            "r14" => Some(self.r14),
            "r15" => Some(self.r15),
            "rip" => Some(self.rip),
            "rflags" => Some(self.rflags),
            "cr2" => Some(self.cr2),
            _ => None,
        }
    }

    pub fn set_by_name(&mut self, name: &str, val: u64) -> Result<(), SysError> {
        match name {
            "rax" => { self.rax = val; Ok(()) }
            "rbx" => { self.rbx = val; Ok(()) }
            "rcx" => { self.rcx = val; Ok(()) }
            "rdx" => { self.rdx = val; Ok(()) }
            "rsi" => { self.rsi = val; Ok(()) }
            "rdi" => { self.rdi = val; Ok(()) }
            "rbp" => { self.rbp = val; Ok(()) }
            "rsp" => { self.rsp = val; Ok(()) }
            "r8"  => { self.r8 = val; Ok(()) }
            "r9"  => { self.r9 = val; Ok(()) }
            "r10" => { self.r10 = val; Ok(()) }
            "r11" => { self.r11 = val; Ok(()) }
            "r12" => { self.r12 = val; Ok(()) }
            "r13" => { self.r13 = val; Ok(()) }
            "r14" => { self.r14 = val; Ok(()) }
            "r15" => { self.r15 = val; Ok(()) }
            "rip" => { self.rip = val; Ok(()) }
            "rflags" => { self.rflags = val; Ok(()) }
            _ => Err(SysError::InvalidArgument),
        }
    }
}

// ============================================================================
// GESTION DES POINTS D'ARRÊT & WATCHPOINTS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakpointType {
    Hardware,
    SoftwareInt3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Breakpoint {
    pub id: u32,
    pub addr: u64,
    pub bp_type: BreakpointType,
    pub cond: DrCondition,
    pub len: DrLength,
    pub slot: Option<DrSlot>,
    pub saved_byte: u8,
    pub enabled: bool,
    pub hit_count: u64,
    pub last_hit_ts: u64,
    pub last_hit_tid: u64,
}

impl Breakpoint {
    pub fn new_software(id: u32, addr: u64, saved_byte: u8) -> Self {
        Self {
            id,
            addr,
            bp_type: BreakpointType::SoftwareInt3,
            cond: DrCondition::Execute,
            len: DrLength::Len1,
            slot: None,
            saved_byte,
            enabled: true,
            hit_count: 0,
            last_hit_ts: 0,
            last_hit_tid: 0,
        }
    }

    pub fn new_hardware(
        id: u32,
        addr: u64,
        slot: DrSlot,
        cond: DrCondition,
        len: DrLength,
    ) -> Self {
        Self {
            id,
            addr,
            bp_type: BreakpointType::Hardware,
            cond,
            len,
            slot: Some(slot),
            saved_byte: 0,
            enabled: true,
            hit_count: 0,
            last_hit_ts: 0,
            last_hit_tid: 0,
        }
    }
}

// ============================================================================
// ÉTATS ET CAUSES D'ARRÊT DE SESSION DE DÉBOGAGE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Detached,
    Attached,
    Running,
    Stopped,
    Stepping,
    Terminated,
}

impl SessionState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Detached => "detached",
            Self::Attached => "attached",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Stepping => "stepping",
            Self::Terminated => "terminated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    None,
    BreakpointHit(u32),
    HardwareWatchpoint(DrSlot, u64),
    SingleStepTrap,
    Int3Trap(u64),
    SegmentFault(u64),
}

impl StopReason {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BreakpointHit(_) => "breakpoint_hit",
            Self::HardwareWatchpoint(_, _) => "hardware_watchpoint",
            Self::SingleStepTrap => "single_step",
            Self::Int3Trap(_) => "int3_trap",
            Self::SegmentFault(_) => "segment_fault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebugThread {
    pub tid: u64,
    pub state: SessionState,
    pub stop_reason: StopReason,
    pub regs: ThreadRegisters,
    pub hw_dr: HardwareDrConfig,
}

impl DebugThread {
    pub fn new(tid: u64, entry_rip: u64, stack_rsp: u64) -> Self {
        Self {
            tid,
            state: SessionState::Stopped,
            stop_reason: StopReason::None,
            regs: ThreadRegisters::new_user(entry_rip, stack_rsp),
            hw_dr: HardwareDrConfig::default(),
        }
    }
}

// ============================================================================
// MÉMOIRE VIRTUELLE LOCALE / INTROSPECTION DE PROCESSUS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base_addr: u64,
    pub size: usize,
    pub is_executable: bool,
    pub is_writable: bool,
    pub bytes: [u8; MEM_REGION_SIZE],
}

impl MemoryRegion {
    pub fn new(base_addr: u64, is_executable: bool, is_writable: bool) -> Self {
        Self {
            base_addr,
            size: MEM_REGION_SIZE,
            is_executable,
            is_writable,
            bytes: [0x90; MEM_REGION_SIZE], // NOP par défaut
        }
    }

    pub fn contains(&self, addr: u64, len: usize) -> bool {
        addr >= self.base_addr && (addr + len as u64) <= (self.base_addr + self.size as u64)
    }

    pub fn read(&self, addr: u64, buf: &mut [u8]) -> Result<usize, SysError> {
        if !self.contains(addr, buf.len()) {
            return Err(SysError::OutOfMemory);
        }
        let offset = (addr - self.base_addr) as usize;
        buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
        Ok(buf.len())
    }

    pub fn write(&mut self, addr: u64, buf: &[u8]) -> Result<usize, SysError> {
        if !self.contains(addr, buf.len()) {
            return Err(SysError::OutOfMemory);
        }
        let offset = (addr - self.base_addr) as usize;
        self.bytes[offset..offset + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }
}

// ============================================================================
// DÉCODEUR COMPACT D'INSTRUCTIONS x86-64
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisasmInstruction {
    pub addr: u64,
    pub len: usize,
    pub mnemonic: &'static str,
    pub is_call: bool,
    pub is_ret: bool,
    pub is_int3: bool,
}

pub fn inspect_instruction(bytes: &[u8], addr: u64) -> DisasmInstruction {
    if bytes.is_empty() {
        return DisasmInstruction {
            addr,
            len: 1,
            mnemonic: "??",
            is_call: false,
            is_ret: false,
            is_int3: false,
        };
    }

    match bytes[0] {
        0xCC => DisasmInstruction {
            addr,
            len: 1,
            mnemonic: "int3",
            is_call: false,
            is_ret: false,
            is_int3: true,
        },
        0x90 => DisasmInstruction {
            addr,
            len: 1,
            mnemonic: "nop",
            is_call: false,
            is_ret: false,
            is_int3: false,
        },
        0xC3 => DisasmInstruction {
            addr,
            len: 1,
            mnemonic: "ret",
            is_call: false,
            is_ret: true,
            is_int3: false,
        },
        0xE8 => DisasmInstruction {
            addr,
            len: 5,
            mnemonic: "call rel32",
            is_call: true,
            is_ret: false,
            is_int3: false,
        },
        0xE9 => DisasmInstruction {
            addr,
            len: 5,
            mnemonic: "jmp rel32",
            is_call: false,
            is_ret: false,
            is_int3: false,
        },
        0xEB => DisasmInstruction {
            addr,
            len: 2,
            mnemonic: "jmp rel8",
            is_call: false,
            is_ret: false,
            is_int3: false,
        },
        0x0F if bytes.len() > 1 && bytes[1] == 0x05 => DisasmInstruction {
            addr,
            len: 2,
            mnemonic: "syscall",
            is_call: false,
            is_ret: false,
            is_int3: false,
        },
        0x48 => DisasmInstruction {
            addr,
            len: 3,
            mnemonic: "mov/rex.w",
            is_call: false,
            is_ret: false,
            is_int3: false,
        },
        _ => DisasmInstruction {
            addr,
            len: 1,
            mnemonic: "mov",
            is_call: false,
            is_ret: false,
            is_int3: false,
        },
    }
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SCELLÉ SHA-256
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    Attach,
    Detach,
    SetBreakpoint,
    ClearBreakpoint,
    StepInstruction,
    Resume,
    ReadMemory,
    WriteMemory,
    ReadRegisters,
    WriteRegisters,
    TrapInt1,
    TrapInt3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub entry_id: u32,
    pub timestamp: u64,
    pub action: AuditAction,
    pub pid: u64,
    pub tid: u64,
    pub addr: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

// ============================================================================
// SESSION DE DÉBOGAGE PROCESSUS
// ============================================================================

pub struct DebugSession {
    pub pid: u64,
    pub state: SessionState,
    pub threads: [Option<DebugThread>; MAX_THREADS_PER_SESSION],
    pub thread_count: usize,
    pub breakpoints: [Option<Breakpoint>; MAX_BREAKPOINTS],
    pub bp_count: usize,
    pub memory: [Option<MemoryRegion>; MAX_MEM_REGIONS],
    pub memory_count: usize,
}

impl DebugSession {
    pub fn new(pid: u64) -> Self {
        Self {
            pid,
            state: SessionState::Attached,
            threads: [None; MAX_THREADS_PER_SESSION],
            thread_count: 0,
            breakpoints: [None; MAX_BREAKPOINTS],
            bp_count: 0,
            memory: [None; MAX_MEM_REGIONS],
            memory_count: 0,
        }
    }

    pub fn add_thread(&mut self, thread: DebugThread) -> Result<(), SysError> {
        for slot in self.threads.iter_mut() {
            if slot.is_none() {
                *slot = Some(thread);
                self.thread_count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    pub fn get_thread_mut(&mut self, tid: u64) -> Option<&mut DebugThread> {
        for slot in self.threads.iter_mut() {
            if let Some(t) = slot {
                if t.tid == tid {
                    return Some(t);
                }
            }
        }
        None
    }

    pub fn get_thread(&self, tid: u64) -> Option<&DebugThread> {
        for slot in self.threads.iter() {
            if let Some(t) = slot {
                if t.tid == tid {
                    return Some(t);
                }
            }
        }
        None
    }

    pub fn add_memory_region(&mut self, region: MemoryRegion) -> Result<(), SysError> {
        for slot in self.memory.iter_mut() {
            if slot.is_none() {
                *slot = Some(region);
                self.memory_count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    pub fn read_memory(&self, addr: u64, buf: &mut [u8]) -> Result<usize, SysError> {
        for slot in self.memory.iter() {
            if let Some(reg) = slot {
                if reg.contains(addr, buf.len()) {
                    return reg.read(addr, buf);
                }
            }
        }
        Err(SysError::BadAddress)
    }

    pub fn write_memory(&mut self, addr: u64, buf: &[u8]) -> Result<usize, SysError> {
        for slot in self.memory.iter_mut() {
            if let Some(reg) = slot {
                if reg.contains(addr, buf.len()) {
                    return reg.write(addr, buf);
                }
            }
        }
        Err(SysError::BadAddress)
    }
}

// ============================================================================
// DÉMON DE DÉBOGAGE PRINCIPAL : JamboDebuggerDaemon
// ============================================================================

pub struct JamboDebuggerDaemon {
    pub daemon_id: u32,
    pub cap: DbgCap,
    pub sessions: [Option<DebugSession>; MAX_SESSIONS],
    pub session_count: usize,
    pub audit_log: [Option<AuditEntry>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub last_audit_hash: [u8; 32],
    pub next_bp_id: u32,
}

impl JamboDebuggerDaemon {
    pub fn new(daemon_id: u32, cap: DbgCap) -> Self {
        Self {
            daemon_id,
            cap,
            sessions: [None, None, None, None],
            session_count: 0,
            audit_log: [None; MAX_AUDIT_LOGS],
            audit_count: 0,
            last_audit_hash: [0u8; 32],
            next_bp_id: 1,
        }
    }

    /// Initialise une session par défaut pour PID 1 avec un thread d'espace utilisateur
    pub fn init_defaults(&mut self) {
        let mut session = DebugSession::new(1);
        
        // Région de code Ring 3 (0x0040_0000)
        let mut code_reg = MemoryRegion::new(0x0040_0000, true, true);
        // Séquence d'instructions x86-64 :
        // 0x0040_0000 : 0x90 (NOP)
        // 0x0040_0001 : 0x48, 0x89, 0xC3 (MOV RBX, RAX)
        // 0x0040_0004 : 0xE8, 0x10, 0x00, 0x00, 0x00 (CALL +16)
        // 0x0040_0009 : 0x0F, 0x05 (SYSCALL)
        // 0x0040_000B : 0xC3 (RET)
        code_reg.bytes[0] = 0x90;
        code_reg.bytes[1] = 0x48;
        code_reg.bytes[2] = 0x89;
        code_reg.bytes[3] = 0xC3;
        code_reg.bytes[4] = 0xE8;
        code_reg.bytes[5] = 0x10;
        code_reg.bytes[6] = 0x00;
        code_reg.bytes[7] = 0x00;
        code_reg.bytes[8] = 0x00;
        code_reg.bytes[9] = 0x0F;
        code_reg.bytes[10] = 0x05;
        code_reg.bytes[11] = 0xC3;

        // Région de pile Ring 3 (0x7FFF_0000)
        let stack_reg = MemoryRegion::new(0x7FFF_0000, false, true);

        let _ = session.add_memory_region(code_reg);
        let _ = session.add_memory_region(stack_reg);

        let thread = DebugThread::new(1, 0x0040_0000, 0x7FFF_00F0);
        let _ = session.add_thread(thread);

        self.sessions[0] = Some(session);
        self.session_count = 1;

        self.record_audit(AuditAction::Attach, 1, 1, 0x0040_0000, 1000);
    }

    fn record_audit(&mut self, action: AuditAction, pid: u64, tid: u64, addr: u64, ts: u64) {
        let entry_id = (self.audit_count as u32) + 1;
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&entry_id.to_be_bytes());
        data[4..12].copy_from_slice(&ts.to_be_bytes());
        data[12] = action as u8;
        data[13..21].copy_from_slice(&pid.to_be_bytes());
        data[21..29].copy_from_slice(&tid.to_be_bytes());
        data[29..37].copy_from_slice(&addr.to_be_bytes());
        data[37..64].copy_from_slice(&self.last_audit_hash[0..27]);

        let digest = Sha256::digest(&data);

        let entry = AuditEntry {
            entry_id,
            timestamp: ts,
            action,
            pid,
            tid,
            addr,
            prev_hash: self.last_audit_hash,
            entry_hash: digest,
        };

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_log[self.audit_count] = Some(entry);
            self.audit_count += 1;
        } else {
            // Tampon annulaire
            for i in 1..MAX_AUDIT_LOGS {
                self.audit_log[i - 1] = self.audit_log[i];
            }
            self.audit_log[MAX_AUDIT_LOGS - 1] = Some(entry);
        }

        self.last_audit_hash = digest;
    }

    pub fn get_session(&self, pid: u64) -> Option<&DebugSession> {
        for s in self.sessions.iter() {
            if let Some(session) = s {
                if session.pid == pid {
                    return Some(session);
                }
            }
        }
        None
    }

    pub fn get_session_mut(&mut self, pid: u64) -> Option<&mut DebugSession> {
        for s in self.sessions.iter_mut() {
            if let Some(session) = s {
                if session.pid == pid {
                    return Some(session);
                }
            }
        }
        None
    }

    // ========================================================================
    // OPÉRATIONS PRINCIPALES DU DÉBOGUEUR SOUS CONTRÔLE CAPABILAIRE
    // ========================================================================

    pub fn attach_process(&mut self, cap: &DbgCap, pid: u64, ts: u64) -> Result<(), SysError> {
        if !cap.has_right(dbg_rights::DBG_ATTACH) {
            return Err(SysError::PermissionDenied);
        }
        if self.get_session(pid).is_some() {
            return Err(SysError::ResourceBusy);
        }
        for slot in self.sessions.iter_mut() {
            if slot.is_none() {
                let session = DebugSession::new(pid);
                *slot = Some(session);
                self.session_count += 1;
                self.record_audit(AuditAction::Attach, pid, 0, 0, ts);
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    pub fn detach_process(&mut self, cap: &DbgCap, pid: u64, ts: u64) -> Result<(), SysError> {
        if !cap.has_right(dbg_rights::DBG_ATTACH) {
            return Err(SysError::PermissionDenied);
        }
        for slot in self.sessions.iter_mut() {
            if let Some(s) = slot {
                if s.pid == pid {
                    *slot = None;
                    self.session_count = self.session_count.saturating_sub(1);
                    self.record_audit(AuditAction::Detach, pid, 0, 0, ts);
                    return Ok(());
                }
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Ajoute un point d'arrêt logiciel (INT3 - 0xCC)
    pub fn add_software_breakpoint(
        &mut self,
        cap: &DbgCap,
        pid: u64,
        addr: u64,
        ts: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(dbg_rights::DBG_BREAKPOINT) || !cap.has_right(dbg_rights::DBG_MEM_WRITE) {
            return Err(SysError::PermissionDenied);
        }

        let id = self.next_bp_id;
        let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;

        if session.bp_count >= MAX_BREAKPOINTS {
            return Err(SysError::OutOfMemory);
        }

        // Lire l'octet original à l'adresse cible
        let mut original_byte = [0u8; 1];
        session.read_memory(addr, &mut original_byte)?;

        // Écrire 0xCC (opcode INT3) dans la mémoire du processus
        session.write_memory(addr, &[0xCC])?;

        let bp = Breakpoint::new_software(id, addr, original_byte[0]);

        for slot in session.breakpoints.iter_mut() {
            if slot.is_none() {
                *slot = Some(bp);
                session.bp_count += 1;
                self.next_bp_id += 1;
                self.record_audit(AuditAction::SetBreakpoint, pid, 0, addr, ts);
                return Ok(id);
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Ajoute un point d'arrêt matériel DR0..DR3 (exécution, écriture ou lecture/écriture)
    pub fn add_hardware_breakpoint(
        &mut self,
        cap: &DbgCap,
        pid: u64,
        addr: u64,
        cond: DrCondition,
        len: DrLength,
        ts: u64,
    ) -> Result<(u32, DrSlot), SysError> {
        if !cap.has_right(dbg_rights::DBG_BREAKPOINT) {
            return Err(SysError::PermissionDenied);
        }

        let id = self.next_bp_id;
        let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;
        if session.bp_count >= MAX_BREAKPOINTS {
            return Err(SysError::OutOfMemory);
        }

        // Trouver un slot DR0..DR3 disponible
        let mut free_slot = None;
        for i in 0..4 {
            let candidate_slot = DrSlot::from_index(i).unwrap();
            let mut used = false;
            for bp_slot in session.breakpoints.iter() {
                if let Some(bp) = bp_slot {
                    if bp.slot == Some(candidate_slot) {
                        used = true;
                        break;
                    }
                }
            }
            if !used {
                free_slot = Some(candidate_slot);
                break;
            }
        }

        let slot = free_slot.ok_or(SysError::OutOfMemory)?;

        // Configurer les registres DR de tous les threads de la session
        for t_slot in session.threads.iter_mut() {
            if let Some(thread) = t_slot {
                thread.hw_dr.set_slot(slot, addr, cond, len);
            }
        }

        let bp = Breakpoint::new_hardware(id, addr, slot, cond, len);

        for bp_slot in session.breakpoints.iter_mut() {
            if bp_slot.is_none() {
                *bp_slot = Some(bp);
                session.bp_count += 1;
                self.next_bp_id += 1;
                self.record_audit(AuditAction::SetBreakpoint, pid, 0, addr, ts);
                return Ok((id, slot));
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Supprime un point d'arrêt (logiciel ou matériel) et restaure l'état d'origine
    pub fn remove_breakpoint(&mut self, cap: &DbgCap, pid: u64, bp_id: u32, ts: u64) -> Result<(), SysError> {
        if !cap.has_right(dbg_rights::DBG_BREAKPOINT) {
            return Err(SysError::PermissionDenied);
        }

        let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;

        let mut found_idx = None;
        let mut bp_copy = None;

        for (i, slot) in session.breakpoints.iter().enumerate() {
            if let Some(bp) = slot {
                if bp.id == bp_id {
                    found_idx = Some(i);
                    bp_copy = Some(*bp);
                    break;
                }
            }
        }

        let idx = found_idx.ok_or(SysError::InvalidArgument)?;
        let bp = bp_copy.unwrap();

        match bp.bp_type {
            BreakpointType::SoftwareInt3 => {
                // Restaurer l'octet d'origine
                session.write_memory(bp.addr, &[bp.saved_byte])?;
            }
            BreakpointType::Hardware => {
                if let Some(slot) = bp.slot {
                    for t_slot in session.threads.iter_mut() {
                        if let Some(thread) = t_slot {
                            thread.hw_dr.clear_slot(slot);
                        }
                    }
                }
            }
        }

        session.breakpoints[idx] = None;
        session.bp_count = session.bp_count.saturating_sub(1);
        self.record_audit(AuditAction::ClearBreakpoint, pid, 0, bp.addr, ts);

        Ok(())
    }

    /// Lecture sécurisée de la mémoire virtuelle du processus cible
    pub fn read_memory(
        &mut self,
        cap: &DbgCap,
        pid: u64,
        addr: u64,
        buf: &mut [u8],
        ts: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(dbg_rights::DBG_MEM_READ) {
            return Err(SysError::PermissionDenied);
        }
        let session = self.get_session(pid).ok_or(SysError::InvalidArgument)?;
        let len = session.read_memory(addr, buf)?;
        self.record_audit(AuditAction::ReadMemory, pid, 0, addr, ts);
        Ok(len)
    }

    /// Écriture sécurisée dans la mémoire virtuelle du processus cible
    pub fn write_memory(
        &mut self,
        cap: &DbgCap,
        pid: u64,
        addr: u64,
        buf: &[u8],
        ts: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(dbg_rights::DBG_MEM_WRITE) {
            return Err(SysError::PermissionDenied);
        }
        let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;
        let len = session.write_memory(addr, buf)?;
        self.record_audit(AuditAction::WriteMemory, pid, 0, addr, ts);
        Ok(len)
    }

    /// Lecture des registres d'un thread cible
    pub fn read_registers(
        &mut self,
        cap: &DbgCap,
        pid: u64,
        tid: u64,
        ts: u64,
    ) -> Result<ThreadRegisters, SysError> {
        if !cap.has_right(dbg_rights::DBG_REG_READ) {
            return Err(SysError::PermissionDenied);
        }
        let session = self.get_session(pid).ok_or(SysError::InvalidArgument)?;
        let thread = session.get_thread(tid).ok_or(SysError::InvalidArgument)?;
        let regs = thread.regs;
        self.record_audit(AuditAction::ReadRegisters, pid, tid, regs.rip, ts);
        Ok(regs)
    }

    /// Modification des registres d'un thread cible
    pub fn write_registers(
        &mut self,
        cap: &DbgCap,
        pid: u64,
        tid: u64,
        regs: ThreadRegisters,
        ts: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(dbg_rights::DBG_REG_WRITE) {
            return Err(SysError::PermissionDenied);
        }
        let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;
        let thread = session.get_thread_mut(tid).ok_or(SysError::InvalidArgument)?;
        thread.regs = regs;
        self.record_audit(AuditAction::WriteRegisters, pid, tid, regs.rip, ts);
        Ok(())
    }

    /// Exécute un pas à pas matériel (*Single-Step*)
    pub fn step_instruction(
        &mut self,
        cap: &DbgCap,
        pid: u64,
        tid: u64,
        ts: u64,
    ) -> Result<DisasmInstruction, SysError> {
        if !cap.has_right(dbg_rights::DBG_STEP) {
            return Err(SysError::PermissionDenied);
        }

        let (_cur_rip, inst) = {
            let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;
            let thread = session.get_thread_mut(tid).ok_or(SysError::InvalidArgument)?;

            // Activer le Trap Flag (TF) dans RFLAGS
            thread.regs.set_single_step(true);
            thread.state = SessionState::Stepping;

            let cur_rip = thread.regs.rip;

            // Inspecter l'instruction courante à exécuter
            let mut inst_buf = [0u8; 16];
            let read_len = session.read_memory(cur_rip, &mut inst_buf).unwrap_or(0);
            let inst = inspect_instruction(&inst_buf[..read_len], cur_rip);
            (cur_rip, inst)
        };

        let rip_after = {
            let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;
            let thread = session.get_thread_mut(tid).ok_or(SysError::InvalidArgument)?;

            // Simuler le passage de l'instruction et l'interruption #DB (INT1)
            thread.regs.advance_rip(inst.len as u64);

            // Après le pas, le Trap Flag génère une exception INT1
            thread.regs.set_single_step(false);
            thread.state = SessionState::Stopped;
            thread.stop_reason = StopReason::SingleStepTrap;
            thread.regs.rip
        };

        self.record_audit(AuditAction::StepInstruction, pid, tid, rip_after, ts);

        Ok(inst)
    }

    /// Reprend l'exécution normale du thread
    pub fn resume_thread(&mut self, cap: &DbgCap, pid: u64, tid: u64, ts: u64) -> Result<(), SysError> {
        if !cap.has_right(dbg_rights::DBG_STEP) {
            return Err(SysError::PermissionDenied);
        }
        let rip = {
            let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;
            let thread = session.get_thread_mut(tid).ok_or(SysError::InvalidArgument)?;
            thread.state = SessionState::Running;
            thread.stop_reason = StopReason::None;
            thread.regs.rip
        };
        self.record_audit(AuditAction::Resume, pid, tid, rip, ts);
        Ok(())
    }

    /// Gestionnaire d'interruption INT3 (#BP - Breakpoint Exception)
    /// Rembobine automatiquement le RIP de 1 octet (l'instruction INT3 faisant 1 octet)
    pub fn handle_int3_exception(
        &mut self,
        pid: u64,
        tid: u64,
        fault_rip: u64,
        ts: u64,
    ) -> Result<u32, SysError> {
        let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;
        
        // Sur x86-64, l'exception INT3 laisse RIP pointé sur l'octet après le 0xCC
        let bp_addr = fault_rip.saturating_sub(1);

        // Chercher le point d'arrêt correspondant
        let mut matching_bp = None;
        for slot in session.breakpoints.iter_mut() {
            if let Some(bp) = slot {
                if bp.enabled && bp.addr == bp_addr {
                    bp.hit_count += 1;
                    bp.last_hit_ts = ts;
                    bp.last_hit_tid = tid;
                    matching_bp = Some(bp.id);
                    break;
                }
            }
        }

        let bp_id = matching_bp.ok_or(SysError::InvalidArgument)?;

        if let Some(thread) = session.get_thread_mut(tid) {
            thread.regs.rip = bp_addr; // Rembobinage automatique de RIP
            thread.state = SessionState::Stopped;
            thread.stop_reason = StopReason::BreakpointHit(bp_id);
        }

        self.record_audit(AuditAction::TrapInt3, pid, tid, bp_addr, ts);

        Ok(bp_id)
    }

    /// Gestionnaire d'interruption INT1 (#DB - Debug Exception)
    /// Traite les breakpoints matériels DR0..DR3 et le drapeau Single-Step BS
    pub fn handle_int1_exception(
        &mut self,
        pid: u64,
        tid: u64,
        dr6_raw: u64,
        ts: u64,
    ) -> Result<StopReason, SysError> {
        let (stop_reason, rip) = {
            let session = self.get_session_mut(pid).ok_or(SysError::InvalidArgument)?;
            let thread = session.get_thread_mut(tid).ok_or(SysError::InvalidArgument)?;

            let status = Dr6Status::from_raw(dr6_raw);
            thread.hw_dr.dr6 = dr6_raw;

            let stop_reason = if status.bs {
                StopReason::SingleStepTrap
            } else if status.b0 {
                StopReason::HardwareWatchpoint(DrSlot::Dr0, thread.hw_dr.dr[0])
            } else if status.b1 {
                StopReason::HardwareWatchpoint(DrSlot::Dr1, thread.hw_dr.dr[1])
            } else if status.b2 {
                StopReason::HardwareWatchpoint(DrSlot::Dr2, thread.hw_dr.dr[2])
            } else if status.b3 {
                StopReason::HardwareWatchpoint(DrSlot::Dr3, thread.hw_dr.dr[3])
            } else {
                StopReason::None
            };

            thread.state = SessionState::Stopped;
            thread.stop_reason = stop_reason;
            (stop_reason, thread.regs.rip)
        };

        // Si c'était un point d'arrêt matériel, incrémenter le compteur
        if let StopReason::HardwareWatchpoint(slot, addr) = stop_reason {
            if let Some(session) = self.get_session_mut(pid) {
                for bp_slot in session.breakpoints.iter_mut() {
                    if let Some(bp) = bp_slot {
                        if bp.slot == Some(slot) && bp.addr == addr {
                            bp.hit_count += 1;
                            bp.last_hit_ts = ts;
                            bp.last_hit_tid = tid;
                            break;
                        }
                    }
                }
            }
        }

        self.record_audit(AuditAction::TrapInt1, pid, tid, rip, ts);

        Ok(stop_reason)
    }

    /// Vérification formelle de l'intégrité de la chaîne d'audit SHA-256
    pub fn verify_audit_integrity(&self) -> bool {
        let mut current_hash = [0u8; 32];
        for slot in self.audit_log.iter() {
            if let Some(entry) = slot {
                if entry.prev_hash != current_hash {
                    return false;
                }

                let mut data = [0u8; 64];
                data[0..4].copy_from_slice(&entry.entry_id.to_be_bytes());
                data[4..12].copy_from_slice(&entry.timestamp.to_be_bytes());
                data[12] = entry.action as u8;
                data[13..21].copy_from_slice(&entry.pid.to_be_bytes());
                data[21..29].copy_from_slice(&entry.tid.to_be_bytes());
                data[29..37].copy_from_slice(&entry.addr.to_be_bytes());
                data[37..64].copy_from_slice(&entry.prev_hash[0..27]);

                let calc_hash = Sha256::digest(&data);
                if calc_hash != entry.entry_hash {
                    return false;
                }

                current_hash = entry.entry_hash;
            }
        }
        true
    }
}

impl ThreadRegisters {
    #[inline]
    pub fn advance_rip(&mut self, bytes: u64) {
        self.rip = self.rip.wrapping_add(bytes);
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] / cargo test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbg_cap_rights_and_strict_attenuation() {
        let admin_cap = DbgCap::new(Handle::new(8601, 1), dbg_rights::ALL);
        assert!(admin_cap.has_right(dbg_rights::DBG_INSPECT));
        assert!(admin_cap.has_right(dbg_rights::DBG_BREAKPOINT));
        assert!(admin_cap.has_right(dbg_rights::DBG_STEP));
        assert!(admin_cap.has_right(dbg_rights::DBG_ADMIN));

        let ro_cap = admin_cap.attenuate(dbg_rights::DBG_INSPECT | dbg_rights::DBG_MEM_READ).unwrap();
        assert!(ro_cap.has_right(dbg_rights::DBG_INSPECT));
        assert!(ro_cap.has_right(dbg_rights::DBG_MEM_READ));
        assert!(!ro_cap.has_right(dbg_rights::DBG_BREAKPOINT));
        assert!(!ro_cap.has_right(dbg_rights::DBG_MEM_WRITE));

        // Rejet de tentative d'amplification
        assert_eq!(
            ro_cap.attenuate(dbg_rights::DBG_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_dr0_dr7_hardware_breakpoint_encoding() {
        let mut dr_cfg = HardwareDrConfig::default();
        dr_cfg.set_slot(DrSlot::Dr0, 0x0040_1000, DrCondition::Execute, DrLength::Len1);
        dr_cfg.set_slot(DrSlot::Dr1, 0x7FFF_2000, DrCondition::DataWrite, DrLength::Len4);

        assert_eq!(dr_cfg.dr[0], 0x0040_1000);
        assert_eq!(dr_cfg.dr[1], 0x7FFF_2000);
        assert!(dr_cfg.is_slot_enabled(DrSlot::Dr0));
        assert!(dr_cfg.is_slot_enabled(DrSlot::Dr1));
        assert!(!dr_cfg.is_slot_enabled(DrSlot::Dr2));

        dr_cfg.clear_slot(DrSlot::Dr0);
        assert!(!dr_cfg.is_slot_enabled(DrSlot::Dr0));
    }

    #[test]
    fn test_software_int3_and_single_step() {
        let admin_cap = DbgCap::new(Handle::new(8601, 1), dbg_rights::ALL);
        let mut daemon = JamboDebuggerDaemon::new(1, admin_cap);
        daemon.init_defaults();

        // Ajout d'un point d'arrêt logiciel INT3
        let bp_id = daemon
            .add_software_breakpoint(&admin_cap, 1, 0x0040_0001, 1001)
            .expect("add INT3 bp");
        assert_eq!(bp_id, 1);

        // Vérifier que 0xCC est bien présent à 0x0040_0001
        let mut check_byte = [0u8; 1];
        daemon.read_memory(&admin_cap, 1, 0x0040_0001, &mut check_byte, 1002).unwrap();
        assert_eq!(check_byte[0], 0xCC);

        // Interception de l'exception INT3
        // RIP après INT3 est à 0x0040_0002
        let hit_id = daemon.handle_int3_exception(1, 1, 0x0040_0002, 1003).expect("handle INT3");
        assert_eq!(hit_id, bp_id);

        let regs = daemon.read_registers(&admin_cap, 1, 1, 1004).unwrap();
        assert_eq!(regs.rip, 0x0040_0001); // Rembobiné

        // Pas à pas
        let inst = daemon.step_instruction(&admin_cap, 1, 1, 1005).unwrap();
        assert_eq!(inst.mnemonic, "int3");

        // Retrait du breakpoint et restauration
        daemon.remove_breakpoint(&admin_cap, 1, bp_id, 1006).unwrap();
        daemon.read_memory(&admin_cap, 1, 0x0040_0001, &mut check_byte, 1007).unwrap();
        assert_eq!(check_byte[0], 0x48); // Octet d'origine restauré !

        // Vérification audit SHA-256
        assert!(daemon.verify_audit_integrity());
    }

    #[test]
    fn test_dr6_hardware_watchpoint_trap() {
        let admin_cap = DbgCap::new(Handle::new(8601, 1), dbg_rights::ALL);
        let mut daemon = JamboDebuggerDaemon::new(1, admin_cap);
        daemon.init_defaults();

        let (bp_id, slot) = daemon
            .add_hardware_breakpoint(&admin_cap, 1, 0x7FFF_0010, DrCondition::DataWrite, DrLength::Len8, 1010)
            .expect("add HW bp");
        assert_eq!(bp_id, 1);
        assert_eq!(slot, DrSlot::Dr0);

        // Simuler un accès mémoire déclenchant DR6 bit 0 (B0)
        let stop_reason = daemon.handle_int1_exception(1, 1, 1 << 0, 1011).unwrap();
        assert_eq!(stop_reason, StopReason::HardwareWatchpoint(DrSlot::Dr0, 0x7FFF_0010));

        let session = daemon.get_session(1).unwrap();
        let bp = session.breakpoints[0].unwrap();
        assert_eq!(bp.hit_count, 1);
        assert_eq!(bp.last_hit_ts, 1011);

        assert!(daemon.verify_audit_integrity());
    }
}

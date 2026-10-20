//! Démon et Moteur de Bytecode eBPF Souverain (`jambo-bpfd`)
//!
//! Fournit un interpréteur de bytecode eBPF sécurisé en `#![no_std]`, doté d'un
//! vérificateur formel de terminaison (graphe orienté acyclique / DAG sans boucles infinies),
//! d'un contrôle d'accès capabilaire strict (`BpfCap`), de structures de données partagées
//! (maps Array, HashMap, RingBuf) et de crochets de filtrage réseau XDP et d'instrumentation.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_INSTRUCTIONS: usize = 256;
pub const STACK_SIZE: usize = 512;
pub const MAX_REGISTERS: usize = 11;
pub const MAX_PROGRAMS: usize = 16;
pub const MAX_MAPS: usize = 8;
pub const MAX_MAP_ENTRIES: usize = 32;
pub const MAX_MAP_STORAGE: usize = 1024;
pub const MAX_ATTACHMENTS: usize = 8;
pub const MAX_PACKET_LEN: usize = 512;
pub const MAX_RINGBUF_SLOTS: usize = 32;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_CYCLES_PER_PROG: u64 = 10_000;

// ============================================================================
// OPCODES ET CLASSES D'INSTRUCTIONS eBPF STANDARD (RFC / Linux eBPF Compatible)
// ============================================================================

pub mod bpf_class {
    pub const BPF_LD: u8 = 0x00;
    pub const BPF_LDX: u8 = 0x01;
    pub const BPF_ST: u8 = 0x02;
    pub const BPF_STX: u8 = 0x03;
    pub const BPF_ALU: u8 = 0x04;
    pub const BPF_JMP: u8 = 0x05;
    pub const BPF_RET: u8 = 0x06;
    pub const BPF_ALU64: u8 = 0x07;
}

pub mod bpf_alu {
    pub const BPF_ADD: u8 = 0x00;
    pub const BPF_SUB: u8 = 0x10;
    pub const BPF_MUL: u8 = 0x20;
    pub const BPF_DIV: u8 = 0x30;
    pub const BPF_OR: u8 = 0x40;
    pub const BPF_AND: u8 = 0x50;
    pub const BPF_LSH: u8 = 0x60;
    pub const BPF_RSH: u8 = 0x70;
    pub const BPF_NEG: u8 = 0x80;
    pub const BPF_MOD: u8 = 0x90;
    pub const BPF_XOR: u8 = 0xa0;
    pub const BPF_MOV: u8 = 0xb0;
    pub const BPF_ARSH: u8 = 0xc0;
}

pub mod bpf_jmp {
    pub const BPF_JA: u8 = 0x00;
    pub const BPF_JEQ: u8 = 0x10;
    pub const BPF_JGT: u8 = 0x20;
    pub const BPF_JGE: u8 = 0x30;
    pub const BPF_JSET: u8 = 0x40;
    pub const BPF_JNE: u8 = 0x50;
    pub const BPF_JSGT: u8 = 0x60;
    pub const BPF_JSGE: u8 = 0x70;
    pub const BPF_CALL: u8 = 0x80;
    pub const BPF_EXIT: u8 = 0x90;
    pub const BPF_JLT: u8 = 0xa0;
    pub const BPF_JLE: u8 = 0xb0;
}

pub mod bpf_size {
    pub const BPF_W: u8 = 0x00; // 32 bits
    pub const BPF_H: u8 = 0x08; // 16 bits
    pub const BPF_B: u8 = 0x10; // 8 bits
    pub const BPF_DW: u8 = 0x18; // 64 bits
}

pub mod bpf_mode {
    pub const BPF_IMM: u8 = 0x00;
    pub const BPF_ABS: u8 = 0x20;
    pub const BPF_IND: u8 = 0x40;
    pub const BPF_MEM: u8 = 0x60;
}

pub mod bpf_src {
    pub const BPF_K: u8 = 0x00; // Constante immédiate
    pub const BPF_X: u8 = 0x08; // Registre source
}

pub mod bpf_helpers {
    pub const MAP_LOOKUP_ELEM: i32 = 1;
    pub const MAP_UPDATE_ELEM: i32 = 2;
    pub const KTIME_GET_NS: i32 = 3;
    pub const TRACE_PRINTK: i32 = 4;
    pub const PACKET_LEN: i32 = 5;
    pub const PACKET_READ_BYTE: i32 = 6;
    pub const PACKET_WRITE_BYTE: i32 = 7;
    pub const CSUM_DIFF: i32 = 8;
}

// ============================================================================
// STRUCTURE D'INSTRUCTION eBPF
// ============================================================================

/// Instruction standard eBPF de 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfInstruction {
    pub code: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInstruction {
    pub const fn empty() -> Self {
        Self {
            code: 0,
            dst_reg: 0,
            src_reg: 0,
            off: 0,
            imm: 0,
        }
    }

    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_reg: dst,
            src_reg: src,
            off,
            imm,
        }
    }

    /// Construit une instruction ALU64 immédiate (ex: r0 += 42).
    pub const fn alu64_imm(op: u8, dst: u8, imm: i32) -> Self {
        Self {
            code: bpf_class::BPF_ALU64 | bpf_src::BPF_K | op,
            dst_reg: dst,
            src_reg: 0,
            off: 0,
            imm,
        }
    }

    /// Construit une instruction ALU64 registre (ex: r0 += r1).
    pub const fn alu64_reg(op: u8, dst: u8, src: u8) -> Self {
        Self {
            code: bpf_class::BPF_ALU64 | bpf_src::BPF_X | op,
            dst_reg: dst,
            src_reg: src,
            off: 0,
            imm: 0,
        }
    }

    /// Affectation immédiate 64 bits (MOV).
    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::alu64_imm(bpf_alu::BPF_MOV, dst, imm)
    }

    /// Affectation de registre 64 bits (MOV).
    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::alu64_reg(bpf_alu::BPF_MOV, dst, src)
    }

    /// Addition immédiate 64 bits.
    pub const fn add64_imm(dst: u8, imm: i32) -> Self {
        Self::alu64_imm(bpf_alu::BPF_ADD, dst, imm)
    }

    /// Saut conditionnel immédiat (ex: if dst == imm goto +off).
    pub const fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> Self {
        Self {
            code: bpf_class::BPF_JMP | bpf_src::BPF_K | op,
            dst_reg: dst,
            src_reg: 0,
            off,
            imm,
        }
    }

    /// Saut conditionnel registre (ex: if dst == src goto +off).
    pub const fn jmp_reg(op: u8, dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: bpf_class::BPF_JMP | bpf_src::BPF_X | op,
            dst_reg: dst,
            src_reg: src,
            off,
            imm: 0,
        }
    }

    /// Saut inconditionnel vers l'avant (JA).
    pub const fn jmp_always(off: i16) -> Self {
        Self {
            code: bpf_class::BPF_JMP | bpf_src::BPF_K | bpf_jmp::BPF_JA,
            dst_reg: 0,
            src_reg: 0,
            off,
            imm: 0,
        }
    }

    /// Écriture immédiate dans la mémoire (pile ou tampon).
    pub const fn st_imm(size: u8, dst: u8, off: i16, imm: i32) -> Self {
        Self {
            code: bpf_class::BPF_ST | bpf_mode::BPF_MEM | size,
            dst_reg: dst,
            src_reg: 0,
            off,
            imm,
        }
    }

    /// Écriture d'un registre dans la mémoire (STX).
    pub const fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: bpf_class::BPF_STX | bpf_mode::BPF_MEM | size,
            dst_reg: dst,
            src_reg: src,
            off,
            imm: 0,
        }
    }

    /// Lecture de la mémoire vers un registre (LDX).
    pub const fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self {
            code: bpf_class::BPF_LDX | bpf_mode::BPF_MEM | size,
            dst_reg: dst,
            src_reg: src,
            off,
            imm: 0,
        }
    }

    /// Appel de fonction d'assistance (helper).
    pub const fn call(func_id: i32) -> Self {
        Self {
            code: bpf_class::BPF_JMP | bpf_src::BPF_K | bpf_jmp::BPF_CALL,
            dst_reg: 0,
            src_reg: 0,
            off: 0,
            imm: func_id,
        }
    }

    /// Sortie du programme eBPF (retourne r0).
    pub const fn exit() -> Self {
        Self {
            code: bpf_class::BPF_JMP | bpf_src::BPF_K | bpf_jmp::BPF_EXIT,
            dst_reg: 0,
            src_reg: 0,
            off: 0,
            imm: 0,
        }
    }
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (BpfCap)
// ============================================================================

pub mod bpf_rights {
    pub const BPF_PROG_LOAD: u32 = 0x01;
    pub const BPF_PROG_RUN: u32 = 0x02;
    pub const BPF_PROG_ATTACH: u32 = 0x04;
    pub const BPF_MAP_CREATE: u32 = 0x08;
    pub const BPF_MAP_READ: u32 = 0x10;
    pub const BPF_MAP_WRITE: u32 = 0x20;
    pub const BPF_ADMIN: u32 = 0x80;
    pub const ALL: u32 = BPF_PROG_LOAD
        | BPF_PROG_RUN
        | BPF_PROG_ATTACH
        | BPF_MAP_CREATE
        | BPF_MAP_READ
        | BPF_MAP_WRITE
        | BPF_ADMIN;
}

/// Jeton de capacité pour le sous-système eBPF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfCap {
    pub handle: Handle,
    pub rights: u32,
}

impl BpfCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    /// Atténuation stricte : interdiction formelle d'élargir les privilèges.
    pub fn attenuate(&self, new_rights: u32) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// TYPES DE PROGRAMMES ET VERDICTS XDP
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BpfProgramType {
    Xdp = 1,
    SocketFilter = 2,
    Tracepoint = 3,
    SchedClassifier = 4,
}

impl BpfProgramType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            BpfProgramType::Xdp => "XDP (eXpress Data Path)",
            BpfProgramType::SocketFilter => "Socket Filter",
            BpfProgramType::Tracepoint => "Kernel Tracepoint",
            BpfProgramType::SchedClassifier => "Traffic Classifier",
        }
    }
}

pub mod xdp_action {
    pub const XDP_PASS: u64 = 0;
    pub const XDP_DROP: u64 = 1;
    pub const XDP_TX: u64 = 2;
    pub const XDP_REDIRECT: u64 = 3;
}

// ============================================================================
// CONTEXTE D'EXÉCUTION RÉSEAU / PAQUET
// ============================================================================

/// Contexte transmis au programme eBPF via r1.
#[derive(Clone, Copy)]
pub struct BpfContext {
    pub packet_data: [u8; MAX_PACKET_LEN],
    pub packet_len: usize,
    pub ingress_ifindex: u32,
    pub protocol: u16,
    pub timestamp_ns: u64,
}

impl BpfContext {
    pub const fn empty() -> Self {
        Self {
            packet_data: [0u8; MAX_PACKET_LEN],
            packet_len: 0,
            ingress_ifindex: 0,
            protocol: 0,
            timestamp_ns: 0,
        }
    }

    pub fn new_packet(data: &[u8], ifindex: u32, protocol: u16, timestamp_ns: u64) -> Self {
        let mut ctx = Self::empty();
        let len = if data.len() > MAX_PACKET_LEN {
            MAX_PACKET_LEN
        } else {
            data.len()
        };
        let mut i = 0;
        while i < len {
            ctx.packet_data[i] = data[i];
            i += 1;
        }
        ctx.packet_len = len;
        ctx.ingress_ifindex = ifindex;
        ctx.protocol = protocol;
        ctx.timestamp_ns = timestamp_ns;
        ctx
    }
}

// ============================================================================
// STRUCTURES DE DONNÉES eBPF (MAPS)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BpfMapType {
    Array = 1,
    HashMap = 2,
    RingBuf = 3,
}

impl BpfMapType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            BpfMapType::Array => "ARRAY",
            BpfMapType::HashMap => "HASH_MAP",
            BpfMapType::RingBuf => "RING_BUFFER",
        }
    }
}

/// Carte de stockage en mémoire pour eBPF
#[derive(Clone)]
pub struct BpfMap {
    pub id: u32,
    pub map_type: BpfMapType,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub key_size: usize,
    pub val_size: usize,
    pub max_entries: usize,
    pub entry_count: usize,
    pub keys: [[u8; 16]; MAX_MAP_ENTRIES],
    pub values: [[u8; 32]; MAX_MAP_ENTRIES],
    pub occupied: [bool; MAX_MAP_ENTRIES],
    pub ring_head: usize,
    pub ring_tail: usize,
}

impl BpfMap {
    pub fn new(
        id: u32,
        name: &str,
        map_type: BpfMapType,
        key_size: usize,
        val_size: usize,
        max_entries: usize,
    ) -> Result<Self, SysError> {
        if key_size > 16 || val_size > 32 || max_entries > MAX_MAP_ENTRIES || max_entries == 0 {
            return Err(SysError::InvalidArgument);
        }
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        let mut i = 0;
        while i < len {
            name_buf[i] = bytes[i];
            i += 1;
        }

        let mut map = Self {
            id,
            map_type,
            name: name_buf,
            name_len: len,
            key_size,
            val_size,
            max_entries,
            entry_count: 0,
            keys: [[0u8; 16]; MAX_MAP_ENTRIES],
            values: [[0u8; 32]; MAX_MAP_ENTRIES],
            occupied: [false; MAX_MAP_ENTRIES],
            ring_head: 0,
            ring_tail: 0,
        };

        if map_type == BpfMapType::Array {
            let mut idx = 0;
            while idx < max_entries {
                map.occupied[idx] = true;
                let k_bytes = (idx as u32).to_ne_bytes();
                let mut b = 0;
                while b < 4 && b < key_size {
                    map.keys[idx][b] = k_bytes[b];
                    b += 1;
                }
                idx += 1;
            }
            map.entry_count = max_entries;
        }

        Ok(map)
    }

    pub fn lookup(&self, key: &[u8]) -> Option<&[u8]> {
        match self.map_type {
            BpfMapType::Array => {
                if key.len() < 4 {
                    return None;
                }
                let idx = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]) as usize;
                if idx < self.max_entries && self.occupied[idx] {
                    Some(&self.values[idx][..self.val_size])
                } else {
                    None
                }
            }
            BpfMapType::HashMap => {
                let mut i = 0;
                while i < self.max_entries {
                    if self.occupied[i] && &self.keys[i][..self.key_size] == key {
                        return Some(&self.values[i][..self.val_size]);
                    }
                    i += 1;
                }
                None
            }
            BpfMapType::RingBuf => {
                if self.entry_count > 0 {
                    Some(&self.values[self.ring_tail][..self.val_size])
                } else {
                    None
                }
            }
        }
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), SysError> {
        if key.len() != self.key_size || value.len() != self.val_size {
            return Err(SysError::InvalidArgument);
        }
        match self.map_type {
            BpfMapType::Array => {
                let idx = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]) as usize;
                if idx >= self.max_entries {
                    return Err(SysError::InvalidArgument);
                }
                self.values[idx][..self.val_size].copy_from_slice(value);
                self.occupied[idx] = true;
                Ok(())
            }
            BpfMapType::HashMap => {
                let mut slot = None;
                let mut free_slot = None;
                let mut i = 0;
                while i < self.max_entries {
                    if self.occupied[i] {
                        if &self.keys[i][..self.key_size] == key {
                            slot = Some(i);
                            break;
                        }
                    } else if free_slot.is_none() {
                        free_slot = Some(i);
                    }
                    i += 1;
                }

                let target = match slot {
                    Some(s) => s,
                    None => match free_slot {
                        Some(f) => {
                            self.occupied[f] = true;
                            self.keys[f][..self.key_size].copy_from_slice(key);
                            self.entry_count += 1;
                            f
                        }
                        None => return Err(SysError::OutOfMemory),
                    },
                };
                self.values[target][..self.val_size].copy_from_slice(value);
                Ok(())
            }
            BpfMapType::RingBuf => {
                self.values[self.ring_head][..self.val_size].copy_from_slice(value);
                self.occupied[self.ring_head] = true;
                self.ring_head = (self.ring_head + 1) % self.max_entries;
                if self.entry_count < self.max_entries {
                    self.entry_count += 1;
                } else {
                    self.ring_tail = (self.ring_tail + 1) % self.max_entries;
                }
                Ok(())
            }
        }
    }
}

// ============================================================================
// VÉRIFICATEUR FORMEL DE SÉCURITÉ ET TERMINAISON (BpfVerifier)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    EmptyProgram,
    ProgramTooLarge,
    InvalidRegister(u8),
    WriteToReadOnlyRegister,
    UninitializedRegister(u8),
    InvalidInstruction(u8),
    InvalidJumpOffset(i16),
    BackwardJumpForbidden(i16),
    JumpTargetOutOfBounds(usize),
    MissingExitInstruction,
    StackOutOfBounds(i16),
    InvalidHelperId(i32),
    MemoryAccessViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationReport {
    pub verified: bool,
    pub instruction_count: usize,
    pub branch_count: usize,
    pub max_stack_usage: usize,
    pub complexity_score: u32,
}

pub struct BpfVerifier;

impl BpfVerifier {
    /// Analyse formelle de sûreté et preuve de terminaison d'un programme eBPF.
    ///
    /// Propriétés vérifiées formellement :
    /// 1. Graphe Orienté Acyclique (DAG) : tout saut s'effectue strictement vers l'avant (off > 0),
    ///    garantissant mathématiquement l'absence de boucles infinies et la terminaison déterministe.
    /// 2. Bornes mémoire de pile : aucun débordement de pile au-delà de 512 octets.
    /// 3. Intégrité des registres : R10 (pointeur de trame) est strictement en lecture seule.
    /// 4. Validité des cibles de saut : toute cible atterrit sur une instruction légitime.
    /// 5. Validité de sortie : le programme se termine impérativement par une instruction EXIT.
    pub fn verify(
        instructions: &[BpfInstruction],
    ) -> Result<VerificationReport, VerificationError> {
        let len = instructions.len();
        if len == 0 {
            return Err(VerificationError::EmptyProgram);
        }
        if len > MAX_INSTRUCTIONS {
            return Err(VerificationError::ProgramTooLarge);
        }

        let mut branch_count = 0;
        let mut max_stack_offset: i16 = 0;
        let mut reg_initialized = [false; MAX_REGISTERS];
        reg_initialized[1] = true; // r1 = Context pointer
        reg_initialized[10] = true; // r10 = Read-only Stack pointer

        let mut has_exit = false;

        for (pc, ins) in instructions.iter().enumerate() {
            // 1. Vérification des indices de registre
            if ins.dst_reg >= MAX_REGISTERS as u8 {
                return Err(VerificationError::InvalidRegister(ins.dst_reg));
            }
            if ins.src_reg >= MAX_REGISTERS as u8 {
                return Err(VerificationError::InvalidRegister(ins.src_reg));
            }

            let class = ins.code & 0x07;
            let src_mode = ins.code & 0x08;

            // 2. Interdiction absolue d'écrire dans R10
            match class {
                bpf_class::BPF_ALU
                | bpf_class::BPF_ALU64
                | bpf_class::BPF_LD
                | bpf_class::BPF_LDX => {
                    if ins.dst_reg == 10 {
                        return Err(VerificationError::WriteToReadOnlyRegister);
                    }
                }
                _ => {}
            }

            // 3. Validation des sauts et preuve acyclique (DAG)
            if class == bpf_class::BPF_JMP {
                let op = ins.code & 0xf0;
                if op == bpf_jmp::BPF_EXIT {
                    has_exit = true;
                } else if op == bpf_jmp::BPF_CALL {
                    if ins.imm < 1 || ins.imm > 8 {
                        return Err(VerificationError::InvalidHelperId(ins.imm));
                    }
                    // R0 reçoit la valeur de retour du helper
                    reg_initialized[0] = true;
                } else {
                    // Saut conditionnel ou inconditionnel
                    branch_count += 1;
                    if ins.off <= 0 {
                        // PREUVE FORMELLE : interdiction des boucles arrière
                        return Err(VerificationError::BackwardJumpForbidden(ins.off));
                    }
                    let target = pc + 1 + (ins.off as usize);
                    if target >= len {
                        return Err(VerificationError::JumpTargetOutOfBounds(target));
                    }
                }
            }

            // 4. Validation des accès mémoire et pile
            if class == bpf_class::BPF_ST || class == bpf_class::BPF_STX {
                if ins.dst_reg == 10 {
                    // Accès pile via r10 : off doit être dans [-512, 0)
                    if ins.off >= 0 || ins.off < -(STACK_SIZE as i16) {
                        return Err(VerificationError::StackOutOfBounds(ins.off));
                    }
                    if -ins.off > max_stack_offset {
                        max_stack_offset = -ins.off;
                    }
                }
            } else if class == bpf_class::BPF_LDX {
                if ins.src_reg == 10 {
                    if ins.off >= 0 || ins.off < -(STACK_SIZE as i16) {
                        return Err(VerificationError::StackOutOfBounds(ins.off));
                    }
                }
                reg_initialized[ins.dst_reg as usize] = true;
            } else if class == bpf_class::BPF_ALU || class == bpf_class::BPF_ALU64 {
                if src_mode == bpf_src::BPF_X && !reg_initialized[ins.src_reg as usize] {
                    return Err(VerificationError::UninitializedRegister(ins.src_reg));
                }
                reg_initialized[ins.dst_reg as usize] = true;
            }
        }

        if !has_exit {
            return Err(VerificationError::MissingExitInstruction);
        }

        let complexity = (len as u32) + (branch_count as u32 * 5);
        Ok(VerificationReport {
            verified: true,
            instruction_count: len,
            branch_count,
            max_stack_usage: max_stack_offset as usize,
            complexity_score: complexity,
        })
    }
}

// ============================================================================
// MACHINE VIRTUELLE eBPF (BpfVm)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfError {
    VerificationFailed,
    InstructionLimitExceeded,
    DivisionByZero,
    SegmentationFault,
    InvalidHelper(i32),
    ProgramHaltedWithoutExit,
    MapNotFound(u32),
}

pub struct BpfVm {
    pub regs: [u64; MAX_REGISTERS],
    pub stack: [u8; STACK_SIZE],
    pub pc: usize,
    pub cycles: u64,
}

impl BpfVm {
    pub fn new() -> Self {
        Self {
            regs: [0u64; MAX_REGISTERS],
            stack: [0u8; STACK_SIZE],
            pc: 0,
            cycles: 0,
        }
    }

    /// Exécute un programme vérifié dans la machine virtuelle sandboxed.
    pub fn execute(
        &mut self,
        instructions: &[BpfInstruction],
        ctx: &mut BpfContext,
        maps: &mut [Option<BpfMap>; MAX_MAPS],
    ) -> Result<u64, BpfError> {
        self.regs = [0u64; MAX_REGISTERS];
        self.stack = [0u8; STACK_SIZE];
        self.pc = 0;
        self.cycles = 0;

        // Configuration des registres d'entrée eBPF standard :
        // r1 = pointeur contexte (ici mappé conceptuellement ou accessible via helper)
        self.regs[1] = 0x1000;
        // r10 = haut de la pile (décroissante)
        self.regs[10] = STACK_SIZE as u64;

        let len = instructions.len();

        while self.pc < len {
            if self.cycles >= MAX_CYCLES_PER_PROG {
                return Err(BpfError::InstructionLimitExceeded);
            }
            self.cycles += 1;

            let ins = &instructions[self.pc];
            let class = ins.code & 0x07;
            let src_mode = ins.code & 0x08;
            let op = ins.code & 0xf0;

            match class {
                bpf_class::BPF_ALU64 => {
                    let dst = ins.dst_reg as usize;
                    let src_val = if src_mode == bpf_src::BPF_X {
                        self.regs[ins.src_reg as usize]
                    } else {
                        ins.imm as i64 as u64
                    };

                    match op {
                        bpf_alu::BPF_ADD => self.regs[dst] = self.regs[dst].wrapping_add(src_val),
                        bpf_alu::BPF_SUB => self.regs[dst] = self.regs[dst].wrapping_sub(src_val),
                        bpf_alu::BPF_MUL => self.regs[dst] = self.regs[dst].wrapping_mul(src_val),
                        bpf_alu::BPF_DIV => {
                            if src_val == 0 {
                                return Err(BpfError::DivisionByZero);
                            }
                            self.regs[dst] /= src_val;
                        }
                        bpf_alu::BPF_OR => self.regs[dst] |= src_val,
                        bpf_alu::BPF_AND => self.regs[dst] &= src_val,
                        bpf_alu::BPF_LSH => self.regs[dst] <<= src_val & 63,
                        bpf_alu::BPF_RSH => self.regs[dst] >>= src_val & 63,
                        bpf_alu::BPF_NEG => self.regs[dst] = (-(self.regs[dst] as i64)) as u64,
                        bpf_alu::BPF_MOD => {
                            if src_val == 0 {
                                return Err(BpfError::DivisionByZero);
                            }
                            self.regs[dst] %= src_val;
                        }
                        bpf_alu::BPF_XOR => self.regs[dst] ^= src_val,
                        bpf_alu::BPF_MOV => self.regs[dst] = src_val,
                        _ => {}
                    }
                    self.pc += 1;
                }
                bpf_class::BPF_ALU => {
                    let dst = ins.dst_reg as usize;
                    let src_val = if src_mode == bpf_src::BPF_X {
                        (self.regs[ins.src_reg as usize] & 0xffff_ffff) as u32
                    } else {
                        ins.imm as u32
                    };
                    let dst_val = (self.regs[dst] & 0xffff_ffff) as u32;
                    let res = match op {
                        bpf_alu::BPF_ADD => dst_val.wrapping_add(src_val),
                        bpf_alu::BPF_SUB => dst_val.wrapping_sub(src_val),
                        bpf_alu::BPF_AND => dst_val & src_val,
                        bpf_alu::BPF_OR => dst_val | src_val,
                        bpf_alu::BPF_XOR => dst_val ^ src_val,
                        bpf_alu::BPF_MOV => src_val,
                        _ => dst_val,
                    };
                    self.regs[dst] = res as u64;
                    self.pc += 1;
                }
                bpf_class::BPF_JMP => {
                    if op == bpf_jmp::BPF_EXIT {
                        return Ok(self.regs[0]);
                    }
                    if op == bpf_jmp::BPF_CALL {
                        self.call_helper(ins.imm, ctx, maps)?;
                        self.pc += 1;
                        continue;
                    }

                    let dst_val = self.regs[ins.dst_reg as usize];
                    let src_val = if src_mode == bpf_src::BPF_X {
                        self.regs[ins.src_reg as usize]
                    } else {
                        ins.imm as i64 as u64
                    };

                    let take_jump = match op {
                        bpf_jmp::BPF_JA => true,
                        bpf_jmp::BPF_JEQ => dst_val == src_val,
                        bpf_jmp::BPF_JGT => dst_val > src_val,
                        bpf_jmp::BPF_JGE => dst_val >= src_val,
                        bpf_jmp::BPF_JSET => (dst_val & src_val) != 0,
                        bpf_jmp::BPF_JNE => dst_val != src_val,
                        bpf_jmp::BPF_JSGT => (dst_val as i64) > (src_val as i64),
                        bpf_jmp::BPF_JSGE => (dst_val as i64) >= (src_val as i64),
                        bpf_jmp::BPF_JLT => dst_val < src_val,
                        bpf_jmp::BPF_JLE => dst_val <= src_val,
                        _ => false,
                    };

                    if take_jump {
                        self.pc = (self.pc as isize + 1 + ins.off as isize) as usize;
                    } else {
                        self.pc += 1;
                    }
                }
                bpf_class::BPF_ST => {
                    let addr =
                        (self.regs[ins.dst_reg as usize] as isize + ins.off as isize) as usize;
                    if addr >= STACK_SIZE {
                        return Err(BpfError::SegmentationFault);
                    }
                    self.stack[addr] = (ins.imm & 0xff) as u8;
                    self.pc += 1;
                }
                bpf_class::BPF_STX => {
                    let addr =
                        (self.regs[ins.dst_reg as usize] as isize + ins.off as isize) as usize;
                    if addr >= STACK_SIZE {
                        return Err(BpfError::SegmentationFault);
                    }
                    self.stack[addr] = (self.regs[ins.src_reg as usize] & 0xff) as u8;
                    self.pc += 1;
                }
                bpf_class::BPF_LDX => {
                    let addr =
                        (self.regs[ins.src_reg as usize] as isize + ins.off as isize) as usize;
                    if addr >= STACK_SIZE {
                        return Err(BpfError::SegmentationFault);
                    }
                    self.regs[ins.dst_reg as usize] = self.stack[addr] as u64;
                    self.pc += 1;
                }
                _ => {
                    self.pc += 1;
                }
            }
        }

        Err(BpfError::ProgramHaltedWithoutExit)
    }

    /// Exécute les fonctions d'assistance eBPF (Helpers standard)
    fn call_helper(
        &mut self,
        helper_id: i32,
        ctx: &mut BpfContext,
        maps: &mut [Option<BpfMap>; MAX_MAPS],
    ) -> Result<(), BpfError> {
        match helper_id {
            bpf_helpers::MAP_LOOKUP_ELEM => {
                let map_id = self.regs[1] as u32;
                let key_val = (self.regs[2] as u32).to_ne_bytes();
                for m in maps.iter() {
                    if let Some(map) = m {
                        if map.id == map_id {
                            if let Some(val) = map.lookup(&key_val[..map.key_size]) {
                                let mut num = 0u64;
                                let mut i = 0;
                                while i < 8 && i < val.len() {
                                    num |= (val[i] as u64) << (i * 8);
                                    i += 1;
                                }
                                self.regs[0] = num;
                                return Ok(());
                            } else {
                                self.regs[0] = 0;
                                return Ok(());
                            }
                        }
                    }
                }
                self.regs[0] = 0;
                Ok(())
            }
            bpf_helpers::MAP_UPDATE_ELEM => {
                let map_id = self.regs[1] as u32;
                let key_bytes = (self.regs[2] as u32).to_ne_bytes();
                let val_bytes = self.regs[3].to_ne_bytes();
                for m in maps.iter_mut() {
                    if let Some(map) = m {
                        if map.id == map_id {
                            let _ =
                                map.update(&key_bytes[..map.key_size], &val_bytes[..map.val_size]);
                            self.regs[0] = 0;
                            return Ok(());
                        }
                    }
                }
                self.regs[0] = u64::MAX;
                Ok(())
            }
            bpf_helpers::KTIME_GET_NS => {
                self.regs[0] = ctx.timestamp_ns;
                Ok(())
            }
            bpf_helpers::PACKET_LEN => {
                self.regs[0] = ctx.packet_len as u64;
                Ok(())
            }
            bpf_helpers::PACKET_READ_BYTE => {
                let offset = self.regs[1] as usize;
                if offset < ctx.packet_len {
                    self.regs[0] = ctx.packet_data[offset] as u64;
                } else {
                    self.regs[0] = u64::MAX;
                }
                Ok(())
            }
            bpf_helpers::PACKET_WRITE_BYTE => {
                let offset = self.regs[1] as usize;
                let val = (self.regs[2] & 0xff) as u8;
                if offset < ctx.packet_len {
                    ctx.packet_data[offset] = val;
                    self.regs[0] = 0;
                } else {
                    self.regs[0] = u64::MAX;
                }
                Ok(())
            }
            bpf_helpers::CSUM_DIFF => {
                let mut sum: u32 = (self.regs[3] & 0xffff) as u32;
                sum = sum.wrapping_add((self.regs[1] & 0xffff) as u32);
                sum = sum.wrapping_add((self.regs[2] & 0xffff) as u32);
                self.regs[0] = (sum & 0xffff) as u64;
                Ok(())
            }
            _ => Err(BpfError::InvalidHelper(helper_id)),
        }
    }
}

// ============================================================================
// PROGRAMME ET ATTACHEMENT
// ============================================================================

#[derive(Clone)]
pub struct BpfProgram {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub prog_type: BpfProgramType,
    pub instructions: [BpfInstruction; MAX_INSTRUCTIONS],
    pub instruction_count: usize,
    pub report: VerificationReport,
    pub runs: u64,
}

#[derive(Clone, Copy)]
pub struct BpfAttachment {
    pub active: bool,
    pub prog_id: u32,
    pub hook_name: [u8; MAX_NAME_LEN],
    pub hook_name_len: usize,
}

// ============================================================================
// STATISTIQUES DU DÉMON
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
pub struct BpfDaemonStats {
    pub programs_loaded: u32,
    pub programs_verified: u32,
    pub maps_created: u32,
    pub packets_inspected: u64,
    pub packets_dropped: u64,
    pub packets_passed: u64,
    pub total_cycles: u64,
}

// ============================================================================
// DÉMON PRINCIPAL (JamboBpfDaemon)
// ============================================================================

pub struct JamboBpfDaemon {
    pub cap: BpfCap,
    pub next_prog_id: u32,
    pub next_map_id: u32,
    pub programs: [Option<BpfProgram>; MAX_PROGRAMS],
    pub maps: [Option<BpfMap>; MAX_MAPS],
    pub attachments: [BpfAttachment; MAX_ATTACHMENTS],
    pub stats: BpfDaemonStats,
    pub vm: BpfVm,
}

impl JamboBpfDaemon {
    pub fn new(cap: BpfCap) -> Self {
        Self {
            cap,
            next_prog_id: 1,
            next_map_id: 1,
            programs: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            maps: [None, None, None, None, None, None, None, None],
            attachments: [BpfAttachment {
                active: false,
                prog_id: 0,
                hook_name: [0u8; MAX_NAME_LEN],
                hook_name_len: 0,
            }; MAX_ATTACHMENTS],
            stats: BpfDaemonStats::default(),
            vm: BpfVm::new(),
        }
    }

    /// Charge, vérifie formellement et enregistre un programme eBPF.
    pub fn load_and_verify(
        &mut self,
        cap: &BpfCap,
        prog_type: BpfProgramType,
        name: &str,
        instructions: &[BpfInstruction],
    ) -> Result<u32, SysError> {
        if !cap.has_right(bpf_rights::BPF_PROG_LOAD) {
            return Err(SysError::PermissionDenied);
        }

        // Vérification formelle du bytecode eBPF (preuve DAG de terminaison)
        let report = BpfVerifier::verify(instructions).map_err(|_| SysError::InvalidArgument)?;

        let mut slot = None;
        let mut i = 0;
        while i < MAX_PROGRAMS {
            if self.programs[i].is_none() {
                slot = Some(i);
                break;
            }
            i += 1;
        }

        let idx = slot.ok_or(SysError::OutOfMemory)?;
        let id = self.next_prog_id;
        self.next_prog_id += 1;

        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        let mut j = 0;
        while j < len {
            name_buf[j] = bytes[j];
            j += 1;
        }

        let mut inst_buf = [BpfInstruction::empty(); MAX_INSTRUCTIONS];
        let mut k = 0;
        while k < instructions.len() {
            inst_buf[k] = instructions[k];
            k += 1;
        }

        self.programs[idx] = Some(BpfProgram {
            id,
            name: name_buf,
            name_len: len,
            prog_type,
            instructions: inst_buf,
            instruction_count: instructions.len(),
            report,
            runs: 0,
        });

        self.stats.programs_loaded += 1;
        self.stats.programs_verified += 1;

        Ok(id)
    }

    /// Crée une carte de stockage eBPF partagée.
    pub fn create_map(
        &mut self,
        cap: &BpfCap,
        name: &str,
        map_type: BpfMapType,
        key_size: usize,
        val_size: usize,
        max_entries: usize,
    ) -> Result<u32, SysError> {
        if !cap.has_right(bpf_rights::BPF_MAP_CREATE) {
            return Err(SysError::PermissionDenied);
        }

        let mut slot = None;
        let mut i = 0;
        while i < MAX_MAPS {
            if self.maps[i].is_none() {
                slot = Some(i);
                break;
            }
            i += 1;
        }

        let idx = slot.ok_or(SysError::OutOfMemory)?;
        let id = self.next_map_id;
        self.next_map_id += 1;

        let map = BpfMap::new(id, name, map_type, key_size, val_size, max_entries)?;
        self.maps[idx] = Some(map);
        self.stats.maps_created += 1;
        Ok(id)
    }

    /// Attache un programme à un crochet système / réseau (ex: "eth0_xdp").
    pub fn attach(&mut self, cap: &BpfCap, prog_id: u32, hook: &str) -> Result<(), SysError> {
        if !cap.has_right(bpf_rights::BPF_PROG_ATTACH) {
            return Err(SysError::PermissionDenied);
        }

        // Vérifie l'existence du programme
        let mut found = false;
        for p in self.programs.iter() {
            if let Some(prog) = p {
                if prog.id == prog_id {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(SysError::InvalidArgument);
        }

        let mut slot = None;
        let mut i = 0;
        while i < MAX_ATTACHMENTS {
            if !self.attachments[i].active {
                slot = Some(i);
                break;
            }
            i += 1;
        }

        let idx = slot.ok_or(SysError::OutOfMemory)?;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = hook.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        let mut j = 0;
        while j < len {
            name_buf[j] = bytes[j];
            j += 1;
        }

        self.attachments[idx] = BpfAttachment {
            active: true,
            prog_id,
            hook_name: name_buf,
            hook_name_len: len,
        };

        Ok(())
    }

    /// Filtre un paquet réseau arrivant sur un crochet (ex: XDP).
    pub fn filter_packet(
        &mut self,
        cap: &BpfCap,
        hook: &str,
        packet: &[u8],
        timestamp_ns: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(bpf_rights::BPF_PROG_RUN) {
            return Err(SysError::PermissionDenied);
        }

        let hook_bytes = hook.as_bytes();
        let mut attached_prog_id = None;
        for att in self.attachments.iter() {
            if att.active && &att.hook_name[..att.hook_name_len] == hook_bytes {
                attached_prog_id = Some(att.prog_id);
                break;
            }
        }

        let prog_id = match attached_prog_id {
            Some(id) => id,
            None => return Ok(xdp_action::XDP_PASS), // Pas de filtre attaché : passe par défaut
        };

        let mut ctx = BpfContext::new_packet(packet, 1, 0x0800, timestamp_ns);
        let verdict = self.run_program(cap, prog_id, &mut ctx)?;

        self.stats.packets_inspected += 1;
        if verdict == xdp_action::XDP_DROP {
            self.stats.packets_dropped += 1;
        } else {
            self.stats.packets_passed += 1;
        }

        Ok(verdict)
    }

    /// Exécute directement un programme eBPF par son identifiant.
    pub fn run_program(
        &mut self,
        cap: &BpfCap,
        prog_id: u32,
        ctx: &mut BpfContext,
    ) -> Result<u64, SysError> {
        if !cap.has_right(bpf_rights::BPF_PROG_RUN) {
            return Err(SysError::PermissionDenied);
        }

        let mut target_idx = None;
        let mut i = 0;
        while i < MAX_PROGRAMS {
            if let Some(ref prog) = self.programs[i] {
                if prog.id == prog_id {
                    target_idx = Some(i);
                    break;
                }
            }
            i += 1;
        }

        let idx = target_idx.ok_or(SysError::InvalidArgument)?;
        let instrs_count = self.programs[idx].as_ref().unwrap().instruction_count;
        let instrs = self.programs[idx].as_ref().unwrap().instructions;

        let verdict = self
            .vm
            .execute(&instrs[..instrs_count], ctx, &mut self.maps)
            .map_err(|_| SysError::InvalidArgument)?;

        self.stats.total_cycles += self.vm.cycles;
        if let Some(ref mut p) = self.programs[idx] {
            p.runs += 1;
        }

        Ok(verdict)
    }

    /// Récupère les métriques du sous-système eBPF.
    pub fn stats(&self, cap: &BpfCap) -> Result<BpfDaemonStats, SysError> {
        if !cap.has_right(bpf_rights::BPF_PROG_RUN) && !cap.has_right(bpf_rights::BPF_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_attenuation() {
        let admin = BpfCap::new(Handle::new(76, 1), bpf_rights::ALL);
        assert!(admin.has_right(bpf_rights::BPF_PROG_LOAD));
        assert!(admin.has_right(bpf_rights::BPF_PROG_RUN));
        assert!(admin.has_right(bpf_rights::BPF_ADMIN));

        let ro = admin
            .attenuate(bpf_rights::BPF_PROG_RUN)
            .expect("attenuate to run");
        assert!(ro.has_right(bpf_rights::BPF_PROG_RUN));
        assert!(!ro.has_right(bpf_rights::BPF_PROG_LOAD));
        assert!(!ro.has_right(bpf_rights::BPF_ADMIN));

        // Interdiction d'escalade
        assert_eq!(
            ro.attenuate(bpf_rights::BPF_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_verifier_acyclic_dag_and_loop_rejection() {
        // Programme avec boucle arrière (interdit)
        let loop_prog = [
            BpfInstruction::mov64_imm(0, 1),
            BpfInstruction::jmp_always(-1), // Saut arrière illégal
            BpfInstruction::exit(),
        ];
        assert_eq!(
            BpfVerifier::verify(&loop_prog),
            Err(VerificationError::BackwardJumpForbidden(-1))
        );

        // Programme valide sans boucle
        let valid_prog = [
            BpfInstruction::mov64_imm(0, xdp_action::XDP_PASS as i32),
            BpfInstruction::exit(),
        ];
        let rep = BpfVerifier::verify(&valid_prog).expect("verify valid prog");
        assert_eq!(rep.instruction_count, 2);
        assert_eq!(rep.branch_count, 0);
    }

    #[test]
    fn test_verifier_stack_and_register_safety() {
        // Tentative d'écriture dans r10
        let r10_write = [BpfInstruction::mov64_imm(10, 42), BpfInstruction::exit()];
        assert_eq!(
            BpfVerifier::verify(&r10_write),
            Err(VerificationError::WriteToReadOnlyRegister)
        );

        // Débordement de pile (offset hors de [-512, 0))
        let stack_overflow = [
            BpfInstruction::st_imm(bpf_size::BPF_W, 10, 16, 42), // Positif = hors-borne
            BpfInstruction::exit(),
        ];
        assert_eq!(
            BpfVerifier::verify(&stack_overflow),
            Err(VerificationError::StackOutOfBounds(16))
        );
    }

    #[test]
    fn test_packet_filter_xdp() {
        let admin = BpfCap::new(Handle::new(76, 1), bpf_rights::ALL);
        let mut daemon = JamboBpfDaemon::new(admin);

        // Programme XDP : lit l'octet 0 du paquet via helper PACKET_READ_BYTE
        // Si premier octet == 0x42 (ex: paquet suspect) -> DROP (1), sinon PASS (0)
        let filter_prog = [
            // r1 = 0 (offset 0)
            BpfInstruction::mov64_imm(1, 0),
            // call PACKET_READ_BYTE -> r0 contient l'octet
            BpfInstruction::call(bpf_helpers::PACKET_READ_BYTE),
            // if r0 == 0x42 goto +2 (vers DROP)
            BpfInstruction::jmp_imm(bpf_jmp::BPF_JEQ, 0, 0x42, 2),
            // Pass: r0 = XDP_PASS
            BpfInstruction::mov64_imm(0, xdp_action::XDP_PASS as i32),
            BpfInstruction::exit(),
            // Drop: r0 = XDP_DROP
            BpfInstruction::mov64_imm(0, xdp_action::XDP_DROP as i32),
            BpfInstruction::exit(),
        ];

        let prog_id = daemon
            .load_and_verify(&admin, BpfProgramType::Xdp, "xdp_firewall", &filter_prog)
            .expect("load xdp prog");

        daemon.attach(&admin, prog_id, "eth0_xdp").expect("attach");

        // Paquet légitime (octet 0 = 0xAA)
        let pkt_clean = [0xAA, 0x01, 0x02, 0x03];
        let v1 = daemon
            .filter_packet(&admin, "eth0_xdp", &pkt_clean, 1000)
            .expect("filter");
        assert_eq!(v1, xdp_action::XDP_PASS);

        // Paquet malveillant (octet 0 = 0x42)
        let pkt_bad = [0x42, 0x01, 0x02, 0x03];
        let v2 = daemon
            .filter_packet(&admin, "eth0_xdp", &pkt_bad, 1001)
            .expect("filter");
        assert_eq!(v2, xdp_action::XDP_DROP);

        let stats = daemon.stats(&admin).expect("stats");
        assert_eq!(stats.packets_inspected, 2);
        assert_eq!(stats.packets_passed, 1);
        assert_eq!(stats.packets_dropped, 1);
    }
}

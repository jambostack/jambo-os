//! Démon de Filtrage d'Appels Système BPF & Confinement Granulaire (`jambo-seccomp`)
//!
//! Fournit un sous-système de confinement par appel système inspiré de Linux seccomp-bpf
//! pour micro-noyau souverain `#![no_std]` :
//! 1. Filtres BPF (Classic BPF / cBPF étendu) compilés sous forme de graphes acycliques dirigés (DAG).
//! 2. Validateur formel garantissant la terminaison stricte en O(N) sans cycles, avec sauts positifs bornés.
//! 3. Modèle d'actions granulaires (ALLOW, KILL_PROCESS, KILL_THREAD, TRAP, ERRNO, LOG, USER_NOTIF).
//! 4. Empilement de filtres par thread avec sémantique de composition stricte (l'action la plus sévère prévaut).
//! 5. Synchronisation multi-threads atomique de processus (`SECCOMP_FILTER_FLAG_TSYNC`).
//! 6. Exigence formelle du bit `no_new_privs` pour interdire toute élévation de privilèges post-confinement.
//! 7. Registre d'audit cryptographique inviolable scellé par chaîne SHA-256.
//! 8. Contrôle d'accès capabilaire sans autorité ambiante via `SeccompCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_FILTERS: usize = 32;
pub const MAX_THREADS: usize = 64;
pub const MAX_BPF_INSTRUCTIONS: usize = 256;
pub const MAX_STACKED_FILTERS: usize = 8;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_SCRATCH_MEM: usize = 16;

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
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];

        let total_len = data.len();
        let mut offset = 0;
        let mut block = [0u8; 64];

        while offset + 64 <= total_len {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let rem = total_len - offset;
        block[..rem].copy_from_slice(&data[offset..]);
        block[rem] = 0x80;
        for b in &mut block[rem + 1..] {
            *b = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
        }

        let bit_len = (total_len as u64) * 8;
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
// MODÈLE CAPABILAIRE DE SÉCURITÉ (SeccompCap)
// ============================================================================

pub mod seccomp_rights {
    pub const SECCOMP_READ: u32 = 1 << 0;   // Consultation des filtres et audits
    pub const SECCOMP_LOAD: u32 = 1 << 1;   // Chargement & validation de filtres BPF
    pub const SECCOMP_ATTACH: u32 = 1 << 2; // Attachement de filtres à des threads
    pub const SECCOMP_TSYNC: u32 = 1 << 3;  // Synchronisation inter-threads (TSYNC)
    pub const SECCOMP_AUDIT: u32 = 1 << 4;  // Lecture du registre d'audit cryptographique
    pub const SECCOMP_ADMIN: u32 = 1 << 5;  // Administration globale du sous-système

    pub const ALL: u32 = SECCOMP_READ
        | SECCOMP_LOAD
        | SECCOMP_ATTACH
        | SECCOMP_TSYNC
        | SECCOMP_AUDIT
        | SECCOMP_ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompCap {
    pub handle: Handle,
    pub rights: u32,
}

impl SeccompCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

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
// CONSTANTES ARCHITECTURALES & SECCOMP
// ============================================================================

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

// Actions de retour de filtres Seccomp (POSIX / Linux compatible)
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD: u32  = 0x0000_0000;
pub const SECCOMP_RET_TRAP: u32         = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32        = 0x0005_0000;
pub const SECCOMP_RET_USER_NOTIF: u32   = 0x7fc0_0000;
pub const SECCOMP_RET_LOG: u32          = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW: u32        = 0x7fff_0000;

pub const SECCOMP_RET_ACTION_FULL: u32  = 0xffff_0000;
pub const SECCOMP_RET_DATA: u32         = 0x0000_ffff;

// Flags de configuration des filtres
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
pub const SECCOMP_FILTER_FLAG_LOG: u32   = 1 << 1;

// ============================================================================
// INSTRUCTIONS & JEU BPF CLASSIQUE ÉTENDU
// ============================================================================

// Classes d'instructions BPF
pub const BPF_LD: u16   = 0x00;
pub const BPF_LDX: u16  = 0x01;
pub const BPF_ST: u16   = 0x02;
pub const BPF_STX: u16  = 0x03;
pub const BPF_ALU: u16  = 0x04;
pub const BPF_JMP: u16  = 0x05;
pub const BPF_RET: u16  = 0x06;
pub const BPF_MISC: u16 = 0x07;

// Tailles d'opérandes
pub const BPF_W: u16 = 0x00; // 32 bits
pub const BPF_H: u16 = 0x08; // 16 bits
pub const BPF_B: u16 = 0x10; // 8 bits

// Modes d'adressage
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;

// Opérations ALU & JMP
pub const BPF_ADD: u16  = 0x00;
pub const BPF_SUB: u16  = 0x10;
pub const BPF_MUL: u16  = 0x20;
pub const BPF_DIV: u16  = 0x30;
pub const BPF_OR: u16   = 0x40;
pub const BPF_AND: u16  = 0x50;
pub const BPF_LSH: u16  = 0x60;
pub const BPF_RSH: u16  = 0x70;
pub const BPF_NEG: u16  = 0x80;
pub const BPF_MOD: u16  = 0x90;
pub const BPF_XOR: u16  = 0xa0;

pub const BPF_JA: u16   = 0x00;
pub const BPF_JEQ: u16  = 0x10;
pub const BPF_JGT: u16  = 0x20;
pub const BPF_JGE: u16  = 0x30;
pub const BPF_JSET: u16 = 0x40;

// Sources d'opérandes
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

// Instructions MISC
pub const BPF_TAX: u16 = 0x00;
pub const BPF_TXA: u16 = 0x80;

/// Instruction BPF classique (8 octets, standard struct sock_filter)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl BpfInsn {
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    pub const fn stmt(code: u16, k: u32) -> Self {
        Self { code, jt: 0, jf: 0, k }
    }

    pub const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// Structure de contexte d'appel système passée au filtre BPF
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompData {
    pub const fn new(nr: i32, arch: u32, instruction_pointer: u64, args: [u64; 6]) -> Self {
        Self {
            nr,
            arch,
            instruction_pointer,
            args,
        }
    }

    /// Charge un mot 32 bits selon l'offset conforme struct seccomp_data
    pub fn load_word(&self, offset: u32) -> Option<u32> {
        match offset {
            0 => Some(self.nr as u32),
            4 => Some(self.arch),
            8 => Some(self.instruction_pointer as u32),
            12 => Some((self.instruction_pointer >> 32) as u32),
            16 => Some(self.args[0] as u32),
            20 => Some((self.args[0] >> 32) as u32),
            24 => Some(self.args[1] as u32),
            28 => Some((self.args[1] >> 32) as u32),
            32 => Some(self.args[2] as u32),
            36 => Some((self.args[2] >> 32) as u32),
            40 => Some(self.args[3] as u32),
            44 => Some((self.args[3] >> 32) as u32),
            48 => Some(self.args[4] as u32),
            52 => Some((self.args[4] >> 32) as u32),
            56 => Some(self.args[5] as u32),
            60 => Some((self.args[5] >> 32) as u32),
            _ => None,
        }
    }
}

/// Programme BPF immuable et validé
#[derive(Clone, Copy)]
pub struct BpfProgram {
    pub len: usize,
    pub insns: [BpfInsn; MAX_BPF_INSTRUCTIONS],
}

impl Default for BpfProgram {
    fn default() -> Self {
        Self {
            len: 0,
            insns: [BpfInsn::default(); MAX_BPF_INSTRUCTIONS],
        }
    }
}

impl BpfProgram {
    /// Validation formelle DAG du programme BPF (Zéro boucle, sauts strictement positifs et bornés)
    pub fn validate(&self) -> Result<(), SysError> {
        if self.len == 0 || self.len > MAX_BPF_INSTRUCTIONS {
            return Err(SysError::InvalidArgument);
        }

        // Vérification de chaque instruction
        for i in 0..self.len {
            let insn = self.insns[i];
            let class = insn.code & 0x07;

            match class {
                BPF_LD => {
                    let mode = insn.code & 0xe0;
                    if mode == BPF_ABS {
                        if insn.k > 64 - 4 || insn.k % 4 != 0 {
                            return Err(SysError::InvalidArgument);
                        }
                    } else if mode != BPF_IMM && mode != BPF_MEM {
                        return Err(SysError::InvalidArgument);
                    }
                }
                BPF_LDX => {
                    let mode = insn.code & 0xe0;
                    if mode != BPF_IMM && mode != BPF_MEM {
                        return Err(SysError::InvalidArgument);
                    }
                }
                BPF_ST | BPF_STX => {
                    if insn.k as usize >= MAX_SCRATCH_MEM {
                        return Err(SysError::InvalidArgument);
                    }
                }
                BPF_ALU => {
                    let op = insn.code & 0xf0;
                    let src = insn.code & 0x08;
                    if (op == BPF_DIV || op == BPF_MOD) && src == BPF_K && insn.k == 0 {
                        // Division par zéro interdite
                        return Err(SysError::InvalidArgument);
                    }
                }
                BPF_JMP => {
                    let op = insn.code & 0xf0;
                    if op == BPF_JA {
                        let target = i + 1 + insn.k as usize;
                        if target >= self.len {
                            return Err(SysError::InvalidArgument);
                        }
                    } else {
                        let target_t = i + 1 + insn.jt as usize;
                        let target_f = i + 1 + insn.jf as usize;
                        if target_t >= self.len || target_f >= self.len {
                            return Err(SysError::InvalidArgument);
                        }
                    }
                }
                BPF_RET => {
                    // Instruction de sortie valide
                }
                BPF_MISC => {}
                _ => return Err(SysError::InvalidArgument),
            }
        }

        // La dernière instruction doit impérativement être un BPF_RET
        let last_class = self.insns[self.len - 1].code & 0x07;
        if last_class != BPF_RET {
            return Err(SysError::InvalidArgument);
        }

        Ok(())
    }

    /// Exécute le filtre BPF sur le contexte d'appel système donné
    pub fn execute(&self, data: &SeccompData) -> u32 {
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut mem = [0u32; MAX_SCRATCH_MEM];
        let mut pc: usize = 0;
        let mut steps: usize = 0;

        while pc < self.len && steps < 10000 {
            steps += 1;
            let insn = self.insns[pc];
            let class = insn.code & 0x07;

            match class {
                BPF_LD => {
                    let mode = insn.code & 0xe0;
                    if mode == BPF_ABS {
                        a = data.load_word(insn.k).unwrap_or(0);
                    } else if mode == BPF_IMM {
                        a = insn.k;
                    } else if mode == BPF_MEM {
                        if (insn.k as usize) < MAX_SCRATCH_MEM {
                            a = mem[insn.k as usize];
                        }
                    }
                    pc += 1;
                }
                BPF_LDX => {
                    let mode = insn.code & 0xe0;
                    if mode == BPF_IMM {
                        x = insn.k;
                    } else if mode == BPF_MEM {
                        if (insn.k as usize) < MAX_SCRATCH_MEM {
                            x = mem[insn.k as usize];
                        }
                    }
                    pc += 1;
                }
                BPF_ST => {
                    if (insn.k as usize) < MAX_SCRATCH_MEM {
                        mem[insn.k as usize] = a;
                    }
                    pc += 1;
                }
                BPF_STX => {
                    if (insn.k as usize) < MAX_SCRATCH_MEM {
                        mem[insn.k as usize] = x;
                    }
                    pc += 1;
                }
                BPF_ALU => {
                    let op = insn.code & 0xf0;
                    let src = insn.code & 0x08;
                    let operand = if src == BPF_X { x } else { insn.k };

                    match op {
                        BPF_ADD => a = a.wrapping_add(operand),
                        BPF_SUB => a = a.wrapping_sub(operand),
                        BPF_MUL => a = a.wrapping_mul(operand),
                        BPF_DIV => {
                            if operand != 0 {
                                a /= operand;
                            } else {
                                return SECCOMP_RET_KILL_PROCESS;
                            }
                        }
                        BPF_MOD => {
                            if operand != 0 {
                                a %= operand;
                            } else {
                                return SECCOMP_RET_KILL_PROCESS;
                            }
                        }
                        BPF_AND => a &= operand,
                        BPF_OR  => a |= operand,
                        BPF_XOR => a ^= operand,
                        BPF_LSH => a = a.wrapping_shl(operand),
                        BPF_RSH => a = a.wrapping_shr(operand),
                        BPF_NEG => a = (a as i32).wrapping_neg() as u32,
                        _ => {}
                    }
                    pc += 1;
                }
                BPF_JMP => {
                    let op = insn.code & 0xf0;
                    if op == BPF_JA {
                        pc += 1 + insn.k as usize;
                    } else {
                        let src = insn.code & 0x08;
                        let operand = if src == BPF_X { x } else { insn.k };
                        let cond = match op {
                            BPF_JEQ => a == operand,
                            BPF_JGT => a > operand,
                            BPF_JGE => a >= operand,
                            BPF_JSET => (a & operand) != 0,
                            _ => false,
                        };
                        if cond {
                            pc += 1 + insn.jt as usize;
                        } else {
                            pc += 1 + insn.jf as usize;
                        }
                    }
                }
                BPF_RET => {
                    let rtype = insn.code & 0x18;
                    if rtype == BPF_K {
                        return insn.k;
                    } else if rtype == BPF_X {
                        return a;
                    } else {
                        return insn.k;
                    }
                }
                BPF_MISC => {
                    let misc_op = insn.code & 0xf8;
                    if misc_op == BPF_TAX {
                        x = a;
                    } else if misc_op == BPF_TXA {
                        a = x;
                    }
                    pc += 1;
                }
                _ => return SECCOMP_RET_KILL_PROCESS,
            }
        }

        // Si la boucle s'interrompt sans retour explicite, tuer par précaution
        SECCOMP_RET_KILL_PROCESS
    }
}

/// Évalue la sévérité d'une action Seccomp (0 = le plus sévère, 6 = le moins sévère)
#[inline(always)]
pub fn action_severity(action: u32) -> u32 {
    match action & SECCOMP_RET_ACTION_FULL {
        SECCOMP_RET_KILL_PROCESS => 0,
        SECCOMP_RET_KILL_THREAD => 1,
        SECCOMP_RET_TRAP => 2,
        SECCOMP_RET_ERRNO => 3,
        SECCOMP_RET_USER_NOTIF => 4,
        SECCOMP_RET_LOG => 5,
        SECCOMP_RET_ALLOW => 6,
        _ => 0,
    }
}

// ============================================================================
// CONSTRUCTEUR DE FILTRES BPF DÉCLARATIFS (FilterBuilder)
// ============================================================================

pub struct FilterBuilder {
    insns: [BpfInsn; MAX_BPF_INSTRUCTIONS],
    count: usize,
    default_act: u32,
}

impl Default for FilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterBuilder {
    pub const fn new() -> Self {
        Self {
            insns: [BpfInsn { code: 0, jt: 0, jf: 0, k: 0 }; MAX_BPF_INSTRUCTIONS],
            count: 0,
            default_act: SECCOMP_RET_KILL_PROCESS,
        }
    }

    pub fn stmt(&mut self, code: u16, k: u32) -> &mut Self {
        if self.count < MAX_BPF_INSTRUCTIONS {
            self.insns[self.count] = BpfInsn::stmt(code, k);
            self.count += 1;
        }
        self
    }

    pub fn jump(&mut self, code: u16, k: u32, jt: u8, jf: u8) -> &mut Self {
        if self.count < MAX_BPF_INSTRUCTIONS {
            self.insns[self.count] = BpfInsn::jump(code, k, jt, jf);
            self.count += 1;
        }
        self
    }

    pub fn default_action(&mut self, action: u32) -> &mut Self {
        self.default_act = action;
        self
    }

    /// Vérification de l'architecture x86-64 ou AArch64
    pub fn check_arch(&mut self, expected_arch: u32) -> &mut Self {
        // [0] LD ABS arch (offset 4)
        self.stmt(BPF_LD | BPF_W | BPF_ABS, 4);
        // [1] JEQ expected_arch jt=1 jf=0 -> si égal saute l'échec
        self.jump(BPF_JMP | BPF_JEQ | BPF_K, expected_arch, 1, 0);
        // [2] RET KILL_PROCESS
        self.stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        self
    }

    /// Autorise un appel système particulier
    pub fn allow_syscall(&mut self, syscall_nr: i32) -> &mut Self {
        // Charge le numéro de syscall
        self.stmt(BPF_LD | BPF_W | BPF_ABS, 0);
        // Si égal, saute au retour ALLOW
        self.jump(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr as u32, 0, 1);
        self.stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        self
    }

    /// Finalise le programme en ajoutant l'action par défaut et valide le DAG
    pub fn build(&mut self) -> Result<BpfProgram, SysError> {
        if self.count >= MAX_BPF_INSTRUCTIONS {
            return Err(SysError::OutOfMemory);
        }
        self.stmt(BPF_RET | BPF_K, self.default_act);

        let prog = BpfProgram {
            len: self.count,
            insns: self.insns,
        };
        prog.validate()?;
        Ok(prog)
    }

    /// Profil standard 'Strict' : Seuls read (0), write (1), exit (60), rt_sigreturn (15) autorisés
    pub fn build_strict_filter() -> Result<BpfProgram, SysError> {
        let mut b = Self::new();
        b.check_arch(AUDIT_ARCH_X86_64);
        b.allow_syscall(0);   // sys_read
        b.allow_syscall(1);   // sys_write
        b.allow_syscall(15);  // sys_rt_sigreturn
        b.allow_syscall(60);  // sys_exit
        b.allow_syscall(231); // sys_exit_group
        b.default_action(SECCOMP_RET_KILL_PROCESS);
        b.build()
    }

    /// Profil standard 'Compute' : Strict + allocation mémoire brk (12), mmap (9), munmap (11), close (3)
    pub fn build_compute_filter() -> Result<BpfProgram, SysError> {
        let mut b = Self::new();
        b.check_arch(AUDIT_ARCH_X86_64);
        b.allow_syscall(0);   // read
        b.allow_syscall(1);   // write
        b.allow_syscall(3);   // close
        b.allow_syscall(9);   // mmap
        b.allow_syscall(11);  // munmap
        b.allow_syscall(12);  // brk
        b.allow_syscall(15);  // rt_sigreturn
        b.allow_syscall(60);  // exit
        b.allow_syscall(231); // exit_group
        b.default_action(SECCOMP_RET_ERRNO | 1); // EPERM
        b.build()
    }

    /// Profil standard 'Network' : read/write/close + sockets (41), connect (42), accept (43), sendto (44), recvfrom (45)
    pub fn build_network_filter() -> Result<BpfProgram, SysError> {
        let mut b = Self::new();
        b.check_arch(AUDIT_ARCH_X86_64);
        b.allow_syscall(0);   // read
        b.allow_syscall(1);   // write
        b.allow_syscall(3);   // close
        b.allow_syscall(15);  // rt_sigreturn
        b.allow_syscall(41);  // socket
        b.allow_syscall(42);  // connect
        b.allow_syscall(43);  // accept
        b.allow_syscall(44);  // sendto
        b.allow_syscall(45);  // recvfrom
        b.allow_syscall(60);  // exit
        b.allow_syscall(231); // exit_group
        b.default_action(SECCOMP_RET_ERRNO | 1); // EPERM
        b.build()
    }
}

// ============================================================================
// REGISTRE & ÉTATS DE CONFINEMENT
// ============================================================================

#[derive(Clone, Copy)]
pub struct RegisteredFilter {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub program: BpfProgram,
    pub flags: u32,
    pub owner_pid: u64,
    pub created_at: u64,
    pub use_count: u32,
}

impl RegisteredFilter {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<inconnu>")
    }
}

#[derive(Clone, Copy)]
pub struct ThreadConfinement {
    pub tid: u64,
    pub pid: u64,
    pub no_new_privs: bool,
    pub filter_count: usize,
    pub filter_ids: [u32; MAX_STACKED_FILTERS],
    pub evaluations: u64,
    pub violations: u64,
}

impl ThreadConfinement {
    pub fn new(tid: u64, pid: u64) -> Self {
        Self {
            tid,
            pid,
            no_new_privs: false,
            filter_count: 0,
            filter_ids: [0; MAX_STACKED_FILTERS],
            evaluations: 0,
            violations: 0,
        }
    }

    pub fn attach_filter(&mut self, fid: u32) -> Result<(), SysError> {
        if self.filter_count >= MAX_STACKED_FILTERS {
            return Err(SysError::OutOfMemory);
        }
        self.filter_ids[self.filter_count] = fid;
        self.filter_count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub tid: u64,
    pub pid: u64,
    pub syscall_nr: i32,
    pub action: u32,
    pub filter_id: u32,
}

// ============================================================================
// DÉMON PRINCIPAL (JamboSeccompDaemon)
// ============================================================================

pub struct JamboSeccompDaemon {
    pub node_id: u64,
    pub cap: SeccompCap,
    pub filters: [Option<RegisteredFilter>; MAX_FILTERS],
    pub filter_count: usize,
    pub threads: [Option<ThreadConfinement>; MAX_THREADS],
    pub thread_count: usize,
    pub audit_log: [Option<AuditEntry>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub last_audit_digest: [u8; 32],
    pub evaluations_count: u64,
    pub violations_count: u64,
    pub allowed_count: u64,
}

impl JamboSeccompDaemon {
    pub fn new(node_id: u64, cap: SeccompCap) -> Self {
        Self {
            node_id,
            cap,
            filters: [None; MAX_FILTERS],
            filter_count: 0,
            threads: [None; MAX_THREADS],
            thread_count: 0,
            audit_log: [None; MAX_AUDIT_LOGS],
            audit_count: 0,
            last_audit_digest: [0u8; 32],
            evaluations_count: 0,
            violations_count: 0,
            allowed_count: 0,
        }
    }

    /// Initialise les profils de sécurité par défaut
    pub fn init_defaults(&mut self) {
        let cap = self.cap;
        if let Ok(strict) = FilterBuilder::build_strict_filter() {
            let _ = self.load_named_filter(&cap, "Strict", strict, 0, 1, 100);
        }
        if let Ok(compute) = FilterBuilder::build_compute_filter() {
            let _ = self.load_named_filter(&cap, "Compute", compute, 0, 1, 101);
        }
        if let Ok(net) = FilterBuilder::build_network_filter() {
            let _ = self.load_named_filter(&cap, "Network", net, 0, 1, 102);
        }
    }

    /// Enregistre et valide un nouveau filtre BPF nommé
    pub fn load_named_filter(
        &mut self,
        cap: &SeccompCap,
        name: &str,
        program: BpfProgram,
        flags: u32,
        owner_pid: u64,
        timestamp: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(seccomp_rights::SECCOMP_LOAD) {
            return Err(SysError::PermissionDenied);
        }

        program.validate()?;

        if self.filter_count >= MAX_FILTERS {
            return Err(SysError::OutOfMemory);
        }

        let fid = (self.filter_count + 1) as u32;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let copy_len = if bytes.len() > MAX_NAME_LEN { MAX_NAME_LEN } else { bytes.len() };
        name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let filter = RegisteredFilter {
            id: fid,
            name: name_buf,
            name_len: copy_len,
            program,
            flags,
            owner_pid,
            created_at: timestamp,
            use_count: 0,
        };

        for slot in self.filters.iter_mut() {
            if slot.is_none() {
                *slot = Some(filter);
                self.filter_count += 1;
                self.record_audit(timestamp, 0, owner_pid, -1, SECCOMP_RET_ALLOW, fid);
                return Ok(fid);
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Enregistre un thread sous surveillance de confinement
    pub fn register_thread(&mut self, tid: u64, pid: u64) -> Result<(), SysError> {
        for t in self.threads.iter() {
            if let Some(th) = t {
                if th.tid == tid {
                    return Ok(()); // Déjà enregistré
                }
            }
        }

        for slot in self.threads.iter_mut() {
            if slot.is_none() {
                *slot = Some(ThreadConfinement::new(tid, pid));
                self.thread_count += 1;
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Active de manière irréversible le bit `no_new_privs` pour un thread
    pub fn set_no_new_privs(&mut self, tid: u64) -> Result<(), SysError> {
        for slot in self.threads.iter_mut() {
            if let Some(ref mut th) = slot {
                if th.tid == tid {
                    th.no_new_privs = true;
                    return Ok(());
                }
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Récupère un thread par son TID
    pub fn get_thread(&self, tid: u64) -> Option<&ThreadConfinement> {
        for slot in self.threads.iter() {
            if let Some(ref th) = slot {
                if th.tid == tid {
                    return Some(th);
                }
            }
        }
        None
    }

    /// Récupère un filtre par son ID
    pub fn get_filter(&self, fid: u32) -> Option<&RegisteredFilter> {
        for slot in self.filters.iter() {
            if let Some(ref f) = slot {
                if f.id == fid {
                    return Some(f);
                }
            }
        }
        None
    }

    /// Recherche un filtre par son nom
    pub fn find_filter_by_name(&self, name: &str) -> Option<&RegisteredFilter> {
        for slot in self.filters.iter() {
            if let Some(ref f) = slot {
                if f.name_str() == name {
                    return Some(f);
                }
            }
        }
        None
    }

    /// Attache un filtre validé à un thread cible
    pub fn attach_filter_to_thread(
        &mut self,
        cap: &SeccompCap,
        tid: u64,
        filter_id: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(seccomp_rights::SECCOMP_ATTACH) {
            return Err(SysError::PermissionDenied);
        }

        // Vérification de l'existence du filtre
        let filter_exists = self.get_filter(filter_id).is_some();
        if !filter_exists {
            return Err(SysError::InvalidArgument);
        }

        let mut target_pid = 0;
        let mut attached = false;

        for slot in self.threads.iter_mut() {
            if let Some(ref mut th) = slot {
                if th.tid == tid {
                    // Exigence POSIX/Linux : no_new_privs scellé requis
                    if !th.no_new_privs {
                        return Err(SysError::PermissionDenied);
                    }
                    th.attach_filter(filter_id)?;
                    target_pid = th.pid;
                    attached = true;
                    break;
                }
            }
        }

        if !attached {
            return Err(SysError::InvalidArgument);
        }

        // Incrémente le compteur d'utilisation
        for slot in self.filters.iter_mut() {
            if let Some(ref mut f) = slot {
                if f.id == filter_id {
                    f.use_count += 1;
                    break;
                }
            }
        }

        self.record_audit(timestamp, tid, target_pid, -1, SECCOMP_RET_ALLOW, filter_id);
        Ok(())
    }

    /// Synchronise un filtre sur tous les threads d'un même processus (TSYNC)
    pub fn sync_process_threads(
        &mut self,
        cap: &SeccompCap,
        pid: u64,
        filter_id: u32,
        timestamp: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(seccomp_rights::SECCOMP_TSYNC) {
            return Err(SysError::PermissionDenied);
        }

        if self.get_filter(filter_id).is_none() {
            return Err(SysError::InvalidArgument);
        }

        let mut synced_count = 0;

        for slot in self.threads.iter_mut() {
            if let Some(ref mut th) = slot {
                if th.pid == pid {
                    th.no_new_privs = true;
                    // Vérifie si le filtre n'est pas déjà présent
                    let mut already_present = false;
                    for i in 0..th.filter_count {
                        if th.filter_ids[i] == filter_id {
                            already_present = true;
                            break;
                        }
                    }
                    if !already_present {
                        th.attach_filter(filter_id)?;
                        synced_count += 1;
                    }
                }
            }
        }

        self.record_audit(timestamp, 0, pid, -1, SECCOMP_RET_ALLOW, filter_id);
        Ok(synced_count)
    }

    /// Évalue un appel système pour un thread donné selon l'ensemble de ses filtres empilés
    pub fn evaluate_syscall(&mut self, tid: u64, data: &SeccompData, timestamp: u64) -> u32 {
        self.evaluations_count += 1;

        // Trouver les filtres du thread
        let mut filter_ids = [0u32; MAX_STACKED_FILTERS];
        let mut count = 0;
        let mut pid = 0;

        for slot in self.threads.iter_mut() {
            if let Some(ref mut th) = slot {
                if th.tid == tid {
                    th.evaluations += 1;
                    pid = th.pid;
                    count = th.filter_count;
                    filter_ids[..count].copy_from_slice(&th.filter_ids[..count]);
                    break;
                }
            }
        }

        // Si aucun filtre n'est attaché, autoriser sans restriction
        if count == 0 {
            self.allowed_count += 1;
            return SECCOMP_RET_ALLOW;
        }

        let mut winning_action = SECCOMP_RET_ALLOW;
        let mut winning_severity = action_severity(SECCOMP_RET_ALLOW);

        // Exécution de tous les filtres empilés (l'action la plus sévère l'emporte)
        for i in 0..count {
            let fid = filter_ids[i];
            if let Some(f) = self.get_filter(fid) {
                let act = f.program.execute(data);
                let sev = action_severity(act);
                if sev < winning_severity {
                    winning_severity = sev;
                    winning_action = act;
                }
            }
        }

        let action_type = winning_action & SECCOMP_RET_ACTION_FULL;
        if action_type == SECCOMP_RET_ALLOW {
            self.allowed_count += 1;
        } else {
            self.violations_count += 1;
            for slot in self.threads.iter_mut() {
                if let Some(ref mut th) = slot {
                    if th.tid == tid {
                        th.violations += 1;
                        break;
                    }
                }
            }
            self.record_audit(timestamp, tid, pid, data.nr, winning_action, filter_ids[0]);
        }

        winning_action
    }

    /// Récupère les métriques globales du sous-système
    pub fn get_stats(&self, cap: &SeccompCap) -> Result<(u64, u64, u64), SysError> {
        if !cap.has_right(seccomp_rights::SECCOMP_READ) {
            return Err(SysError::PermissionDenied);
        }
        Ok((self.evaluations_count, self.violations_count, self.allowed_count))
    }

    /// Enregistre une entrée dans le journal d'audit et recalcule l'empreinte SHA-256
    fn record_audit(
        &mut self,
        timestamp: u64,
        tid: u64,
        pid: u64,
        syscall_nr: i32,
        action: u32,
        filter_id: u32,
    ) {
        let entry = AuditEntry {
            timestamp,
            tid,
            pid,
            syscall_nr,
            action,
            filter_id,
        };

        let idx = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_log[idx] = Some(entry);
        self.audit_count += 1;

        // Mise à jour de l'empreinte cryptographique SHA-256
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(&self.last_audit_digest);
        block[32..40].copy_from_slice(&timestamp.to_be_bytes());
        block[40..48].copy_from_slice(&tid.to_be_bytes());
        block[48..56].copy_from_slice(&pid.to_be_bytes());
        block[56..60].copy_from_slice(&(syscall_nr as u32).to_be_bytes());
        block[60..64].copy_from_slice(&action.to_be_bytes());

        self.last_audit_digest = Sha256::digest(&block);
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_capabilities() {
        let admin_cap = SeccompCap::new(Handle::new(8801, 1), seccomp_rights::ALL);
        assert!(admin_cap.has_right(seccomp_rights::SECCOMP_READ));
        assert!(admin_cap.has_right(seccomp_rights::SECCOMP_LOAD));
        assert!(admin_cap.has_right(seccomp_rights::SECCOMP_ATTACH));
        assert!(admin_cap.has_right(seccomp_rights::SECCOMP_TSYNC));
        assert!(admin_cap.has_right(seccomp_rights::SECCOMP_AUDIT));
        assert!(admin_cap.has_right(seccomp_rights::SECCOMP_ADMIN));

        let read_cap = admin_cap.attenuate(seccomp_rights::SECCOMP_READ).unwrap();
        assert!(read_cap.has_right(seccomp_rights::SECCOMP_READ));
        assert!(!read_cap.has_right(seccomp_rights::SECCOMP_LOAD));

        // Rejet de l'élévation de privilèges
        assert_eq!(
            read_cap.attenuate(seccomp_rights::SECCOMP_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_bpf_strict_filter_execution() {
        let prog = FilterBuilder::build_strict_filter().expect("build strict");
        assert!(prog.len > 0);

        // Appel autorisé (read: 0)
        let data_read = SeccompData::new(0, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
        assert_eq!(prog.execute(&data_read), SECCOMP_RET_ALLOW);

        // Appel autorisé (write: 1)
        let data_write = SeccompData::new(1, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
        assert_eq!(prog.execute(&data_write), SECCOMP_RET_ALLOW);

        // Appel interdit (execve: 59)
        let data_exec = SeccompData::new(59, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
        assert_eq!(prog.execute(&data_exec), SECCOMP_RET_KILL_PROCESS);

        // Mauvaise architecture
        let data_wrong_arch = SeccompData::new(0, AUDIT_ARCH_AARCH64, 0x400000, [0; 6]);
        assert_eq!(prog.execute(&data_wrong_arch), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_seccomp_daemon_lifecycle() {
        let cap = SeccompCap::new(Handle::new(8802, 1), seccomp_rights::ALL);
        let mut daemon = JamboSeccompDaemon::new(1, cap);
        daemon.init_defaults();

        // Enregistre un thread
        daemon.register_thread(101, 10).unwrap();
        assert_eq!(
            daemon.attach_filter_to_thread(&cap, 101, 1, 1000),
            Err(SysError::PermissionDenied),
            "no_new_privs requis"
        );

        daemon.set_no_new_privs(101).unwrap();
        daemon.attach_filter_to_thread(&cap, 101, 1, 1001).unwrap();

        let data_read = SeccompData::new(0, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
        let act = daemon.evaluate_syscall(101, &data_read, 1002);
        assert_eq!(act, SECCOMP_RET_ALLOW);

        let data_socket = SeccompData::new(41, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
        let act_kill = daemon.evaluate_syscall(101, &data_socket, 1003);
        assert_eq!(act_kill, SECCOMP_RET_KILL_PROCESS);
    }
}

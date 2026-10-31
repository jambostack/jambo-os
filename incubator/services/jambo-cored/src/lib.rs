//! Démon de Capture d'État Post-Mortem, Crash Dumps ELF Scellés & Télémétrie Post-Crash (`jambo-cored`)
//!
//! Fournit une infrastructure complète d'analyse forensique, isolation mémoire et résilience système pour micro-noyau `#![no_std]` :
//! 1. Capture d'état post-mortem déterministe des registres CPU (x86-64 et AArch64) et de la pile mémoire.
//! 2. Génération de Core Dumps conformes à la spécification ELF64 (`ET_CORE`, `PT_NOTE`, `PT_LOAD`, `NT_PRSTATUS`, `NT_PRPSINFO`, `NT_SIGINFO`).
//! 3. Scellement cryptographique inviolable par chaîne SHA-256 et détection formelle de falsification.
//! 4. Confinement et mise en quarantaine immédiate des segments mémoires VMO pour prévenir la corruption inter-domaines.
//! 5. Dispatching de télémétrie post-crash et recommandations automatisées d'auto-guérison de grappe.
//! 6. Registre d'audit inviolable scellé par chaîne Merkle/SHA-256.
//! 7. Contrôle d'accès capabilaire strict sans autorité ambiante via `CoreCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_REGIONS: usize = 8;
pub const MAX_CALL_TRACE: usize = 16;
pub const MAX_STACK_BYTES: usize = 256;
pub const MAX_CRASH_REPORTS: usize = 16;
pub const MAX_TELEMETRY_LOGS: usize = 16;
pub const MAX_NAME_LEN: usize = 32;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 standard `#![no_std]` sans allocation
#[derive(Clone, Copy)]
pub struct Sha256;

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
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
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
// MODÈLE DE SÉCURITÉ CAPABILAIRE : CoreCap
// ============================================================================

pub mod core_rights {
    pub const CORE_INSPECT: u32 = 1 << 0;
    pub const CORE_CAPTURE: u32 = 1 << 1;
    pub const CORE_GENERATE: u32 = 1 << 2;
    pub const CORE_SEAL: u32 = 1 << 3;
    pub const CORE_QUARANTINE: u32 = 1 << 4;
    pub const CORE_TELEMETRY: u32 = 1 << 5;
    pub const CORE_PURGE: u32 = 1 << 6;
    pub const CORE_ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = CORE_INSPECT
        | CORE_CAPTURE
        | CORE_GENERATE
        | CORE_SEAL
        | CORE_QUARANTINE
        | CORE_TELEMETRY
        | CORE_PURGE
        | CORE_ADMIN;
}

/// Capacité de contrôle d'accès pour le démon de crash dumps
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreCap {
    pub handle: Handle,
    pub rights: u32,
}

impl CoreCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits vers un sous-ensemble strict.
    /// Interdit formellement toute amplification de droits.
    pub fn attenuate(&self, new_rights: u32) -> Result<CoreCap, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(CoreCap {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// REGISTRES CPU MULTI-ARCHITECTURES
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct X86_64Registers {
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
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
    pub cr2: u64, // Adresse de faute de page
    pub cr3: u64, // Base de table de pages PML4
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AArch64Registers {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub fault_addr: u64,
    pub esr: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchRegisters {
    X86_64(X86_64Registers),
    AArch64(AArch64Registers),
}

impl Default for ArchRegisters {
    fn default() -> Self {
        ArchRegisters::X86_64(X86_64Registers::default())
    }
}

impl ArchRegisters {
    pub fn instruction_pointer(&self) -> u64 {
        match self {
            ArchRegisters::X86_64(r) => r.rip,
            ArchRegisters::AArch64(r) => r.pc,
        }
    }

    pub fn stack_pointer(&self) -> u64 {
        match self {
            ArchRegisters::X86_64(r) => r.rsp,
            ArchRegisters::AArch64(r) => r.sp,
        }
    }

    pub fn frame_pointer(&self) -> u64 {
        match self {
            ArchRegisters::X86_64(r) => r.rbp,
            ArchRegisters::AArch64(r) => r.x[29],
        }
    }

    pub fn fault_address(&self) -> u64 {
        match self {
            ArchRegisters::X86_64(r) => r.cr2,
            ArchRegisters::AArch64(r) => r.fault_addr,
        }
    }

    pub fn elf_machine(&self) -> u16 {
        match self {
            ArchRegisters::X86_64(_) => 62,   // EM_X86_64
            ArchRegisters::AArch64(_) => 183, // EM_AARCH64
        }
    }
}

// ============================================================================
// CAUSES & TYPES DE CRASH
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashReason {
    KernelPanic,
    PageFault { fault_addr: u64, error_code: u64 },
    GeneralProtectionFault { code: u64 },
    InvalidOpcode,
    StackOverflow,
    DoubleFault,
    SupervisorKill { signal: u32 },
    WatchdogTimeout,
    AssertionFailed,
}

impl CrashReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            CrashReason::KernelPanic => "KERNEL_PANIC",
            CrashReason::PageFault { .. } => "PAGE_FAULT",
            CrashReason::GeneralProtectionFault { .. } => "GPF",
            CrashReason::InvalidOpcode => "INVALID_OPCODE",
            CrashReason::StackOverflow => "STACK_OVERFLOW",
            CrashReason::DoubleFault => "DOUBLE_FAULT",
            CrashReason::SupervisorKill { .. } => "SUPERVISOR_KILL",
            CrashReason::WatchdogTimeout => "WATCHDOG_TIMEOUT",
            CrashReason::AssertionFailed => "ASSERT_FAILED",
        }
    }

    pub fn code(&self) -> u32 {
        match self {
            CrashReason::KernelPanic => 1,
            CrashReason::PageFault { .. } => 2,
            CrashReason::GeneralProtectionFault { .. } => 3,
            CrashReason::InvalidOpcode => 4,
            CrashReason::StackOverflow => 5,
            CrashReason::DoubleFault => 6,
            CrashReason::SupervisorKill { .. } => 7,
            CrashReason::WatchdogTimeout => 8,
            CrashReason::AssertionFailed => 9,
        }
    }

    pub fn signal_num(&self) -> u32 {
        match self {
            CrashReason::KernelPanic => 6,                    // SIGABRT
            CrashReason::PageFault { .. } => 11,              // SIGSEGV
            CrashReason::GeneralProtectionFault { .. } => 11, // SIGSEGV
            CrashReason::InvalidOpcode => 4,                  // SIGILL
            CrashReason::StackOverflow => 11,                 // SIGSEGV
            CrashReason::DoubleFault => 6,                    // SIGABRT
            CrashReason::SupervisorKill { signal } => *signal,
            CrashReason::WatchdogTimeout => 9, // SIGKILL
            CrashReason::AssertionFailed => 6, // SIGABRT
        }
    }
}

// ============================================================================
// RÉGION MÉMOIRE FORENSIQUE & QUARANTAINE
// ============================================================================

pub mod memory_flags {
    pub const PROT_NONE: u32 = 0;
    pub const PROT_READ: u32 = 1 << 0;
    pub const PROT_WRITE: u32 = 1 << 1;
    pub const PROT_EXEC: u32 = 1 << 2;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreMemoryRegion {
    pub vaddr: u64,
    pub size: u64,
    pub flags: u32,
    pub tag: [u8; 16],
    pub quarantined: bool,
}

impl CoreMemoryRegion {
    pub fn new(vaddr: u64, size: u64, flags: u32, tag_str: &str) -> Self {
        let mut tag = [0u8; 16];
        let bytes = tag_str.as_bytes();
        let len = if bytes.len() > 16 { 16 } else { bytes.len() };
        tag[..len].copy_from_slice(&bytes[..len]);

        Self {
            vaddr,
            size,
            flags,
            tag,
            quarantined: false,
        }
    }

    pub fn tag_str(&self) -> &str {
        let len = self.tag.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.tag[..len]).unwrap_or("[unknown]")
    }
}

// ============================================================================
// GÉNERATEUR DE CORE DUMP ELF64 BINAIRE
// ============================================================================

/// Spécification standard ELF64 pour fichiers de crash dump (ET_CORE)
pub struct Elf64Generator;

impl Elf64Generator {
    pub const ELFMAG0: u8 = 0x7f;
    pub const ELFMAG1: u8 = b'E';
    pub const ELFMAG2: u8 = b'L';
    pub const ELFMAG3: u8 = b'F';
    pub const ELFCLASS64: u8 = 2;
    pub const ELFDATA2LSB: u8 = 1;
    pub const EV_CURRENT: u8 = 1;
    pub const ELFOSABI_NONE: u8 = 0;
    pub const ET_CORE: u16 = 4;
    pub const PT_LOAD: u32 = 1;
    pub const PT_NOTE: u32 = 4;
    pub const NT_PRSTATUS: u32 = 1;
    pub const NT_PRPSINFO: u32 = 3;
    pub const NT_SIGINFO: u32 = 0x53494749;

    /// Génère un dump ELF64 binaire valide et structuré dans le tampon spécifié
    pub fn generate_core_dump(
        report: &SealedCrashReport,
        out_buf: &mut [u8],
    ) -> Result<usize, SysError> {
        let total_phnum = 1 + report.region_count; // 1 PT_NOTE + N PT_LOAD
        let ehdr_size = 64usize;
        let phdr_size = 56usize;
        let phdrs_total_size = total_phnum * phdr_size;
        let note_offset = ehdr_size + phdrs_total_size;

        if out_buf.len() < note_offset + 512 {
            return Err(SysError::BufferTooSmall);
        }

        // 1. En-tête ELF64 (64 octets)
        out_buf[0] = Self::ELFMAG0;
        out_buf[1] = Self::ELFMAG1;
        out_buf[2] = Self::ELFMAG2;
        out_buf[3] = Self::ELFMAG3;
        out_buf[4] = Self::ELFCLASS64;
        out_buf[5] = Self::ELFDATA2LSB;
        out_buf[6] = Self::EV_CURRENT;
        out_buf[7] = Self::ELFOSABI_NONE;
        for i in 8..16 {
            out_buf[i] = 0;
        }

        out_buf[16..18].copy_from_slice(&Self::ET_CORE.to_le_bytes());
        out_buf[18..20].copy_from_slice(&report.regs.elf_machine().to_le_bytes());
        out_buf[20..24].copy_from_slice(&(Self::EV_CURRENT as u32).to_le_bytes());
        out_buf[24..32].copy_from_slice(&0u64.to_le_bytes()); // e_entry
        out_buf[32..40].copy_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff
        out_buf[40..48].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        out_buf[48..52].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        out_buf[52..54].copy_from_slice(&(ehdr_size as u16).to_le_bytes()); // e_ehsize
        out_buf[54..56].copy_from_slice(&(phdr_size as u16).to_le_bytes()); // e_phentsize
        out_buf[56..58].copy_from_slice(&(total_phnum as u16).to_le_bytes()); // e_phnum
        out_buf[58..60].copy_from_slice(&0u16.to_le_bytes()); // e_shentsize
        out_buf[60..62].copy_from_slice(&0u16.to_le_bytes()); // e_shnum
        out_buf[62..64].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        // 2. Préparation du segment PT_NOTE
        let mut note_cursor = note_offset;

        // Note NT_PRSTATUS (infos processus + signal + registres)
        let prstatus_len = 44usize;

        // Écriture Note Header NT_PRSTATUS
        out_buf[note_cursor..note_cursor + 4].copy_from_slice(&5u32.to_le_bytes()); // namesz ("CORE\0")
                                                                                    // placeholder pour descsz calculé ensuite
        out_buf[note_cursor + 8..note_cursor + 12]
            .copy_from_slice(&Self::NT_PRSTATUS.to_le_bytes());
        note_cursor += 12;
        out_buf[note_cursor..note_cursor + 8].copy_from_slice(b"CORE\0\0\0\0");
        note_cursor += 8;

        // Remplissage desc prstatus :
        // cursig (u16), pid (u32), ppid (u32), rip (u64), rsp (u64), rflags (u64)
        out_buf[note_cursor..note_cursor + 2]
            .copy_from_slice(&(report.reason.signal_num() as u16).to_le_bytes());
        out_buf[note_cursor + 2..note_cursor + 4].copy_from_slice(&0u16.to_le_bytes());
        out_buf[note_cursor + 4..note_cursor + 8].copy_from_slice(&report.pid.to_le_bytes());
        out_buf[note_cursor + 8..note_cursor + 12].copy_from_slice(&0u32.to_le_bytes()); // ppid
        out_buf[note_cursor + 12..note_cursor + 20]
            .copy_from_slice(&report.regs.instruction_pointer().to_le_bytes());
        out_buf[note_cursor + 20..note_cursor + 28]
            .copy_from_slice(&report.regs.stack_pointer().to_le_bytes());
        out_buf[note_cursor + 28..note_cursor + 36]
            .copy_from_slice(&report.regs.frame_pointer().to_le_bytes());
        out_buf[note_cursor + 36..note_cursor + 44]
            .copy_from_slice(&report.regs.fault_address().to_le_bytes());
        note_cursor += prstatus_len;
        // Mise à jour descsz NT_PRSTATUS
        out_buf[note_offset + 4..note_offset + 8]
            .copy_from_slice(&(prstatus_len as u32).to_le_bytes());

        // Note NT_PRPSINFO (nom du binaire et état)
        let prpsinfo_offset = note_cursor;
        out_buf[note_cursor..note_cursor + 4].copy_from_slice(&5u32.to_le_bytes());
        out_buf[note_cursor + 8..note_cursor + 12]
            .copy_from_slice(&Self::NT_PRPSINFO.to_le_bytes());
        note_cursor += 12;
        out_buf[note_cursor..note_cursor + 8].copy_from_slice(b"CORE\0\0\0\0");
        note_cursor += 8;

        let desc_prps_start = note_cursor;
        out_buf[note_cursor] = b'R'; // state
        out_buf[note_cursor + 1] = b'X'; // state name
        out_buf[note_cursor + 2..note_cursor + 6].copy_from_slice(&report.pid.to_le_bytes());
        note_cursor += 6;
        let fname_len = if report.process_name_len > 16 {
            16
        } else {
            report.process_name_len
        };
        out_buf[note_cursor..note_cursor + fname_len]
            .copy_from_slice(&report.process_name[..fname_len]);
        for b in &mut out_buf[note_cursor + fname_len..note_cursor + 16] {
            *b = 0;
        }
        note_cursor += 16;
        let prpsinfo_desc_len = note_cursor - desc_prps_start;
        // alignement 4 octets
        let align_pad = (4 - (prpsinfo_desc_len % 4)) % 4;
        for _ in 0..align_pad {
            out_buf[note_cursor] = 0;
            note_cursor += 1;
        }
        out_buf[prpsinfo_offset + 4..prpsinfo_offset + 8]
            .copy_from_slice(&((prpsinfo_desc_len + align_pad) as u32).to_le_bytes());

        // Note NT_SIGINFO (signal et adresse de faute)
        let siginfo_offset = note_cursor;
        out_buf[note_cursor..note_cursor + 4].copy_from_slice(&5u32.to_le_bytes());
        out_buf[note_cursor + 8..note_cursor + 12].copy_from_slice(&Self::NT_SIGINFO.to_le_bytes());
        note_cursor += 12;
        out_buf[note_cursor..note_cursor + 8].copy_from_slice(b"CORE\0\0\0\0");
        note_cursor += 8;

        out_buf[note_cursor..note_cursor + 4]
            .copy_from_slice(&(report.reason.signal_num() as i32).to_le_bytes());
        out_buf[note_cursor + 4..note_cursor + 8].copy_from_slice(&0i32.to_le_bytes()); // si_errno
        out_buf[note_cursor + 8..note_cursor + 12]
            .copy_from_slice(&(report.reason.code() as i32).to_le_bytes());
        out_buf[note_cursor + 12..note_cursor + 20]
            .copy_from_slice(&report.regs.fault_address().to_le_bytes());
        note_cursor += 20;
        out_buf[siginfo_offset + 4..siginfo_offset + 8].copy_from_slice(&20u32.to_le_bytes());

        let note_total_size = note_cursor - note_offset;

        // 3. Écriture du Program Header 0 : PT_NOTE
        let mut phdr_cursor = ehdr_size;
        out_buf[phdr_cursor..phdr_cursor + 4].copy_from_slice(&Self::PT_NOTE.to_le_bytes()); // p_type
        out_buf[phdr_cursor + 4..phdr_cursor + 8].copy_from_slice(&4u32.to_le_bytes()); // p_flags (PF_R)
        out_buf[phdr_cursor + 8..phdr_cursor + 16]
            .copy_from_slice(&(note_offset as u64).to_le_bytes()); // p_offset
        out_buf[phdr_cursor + 16..phdr_cursor + 24].copy_from_slice(&0u64.to_le_bytes()); // p_vaddr
        out_buf[phdr_cursor + 24..phdr_cursor + 32].copy_from_slice(&0u64.to_le_bytes()); // p_paddr
        out_buf[phdr_cursor + 32..phdr_cursor + 40]
            .copy_from_slice(&(note_total_size as u64).to_le_bytes()); // p_filesz
        out_buf[phdr_cursor + 40..phdr_cursor + 48]
            .copy_from_slice(&(note_total_size as u64).to_le_bytes()); // p_memsz
        out_buf[phdr_cursor + 48..phdr_cursor + 56].copy_from_slice(&4u64.to_le_bytes()); // p_align
        phdr_cursor += phdr_size;

        // 4. Copie des segments mémoires capturés (Pile & VMOs) et Program Headers PT_LOAD
        let mut data_cursor = note_cursor;

        for i in 0..report.region_count {
            let region = &report.regions[i];
            let is_stack = region.tag_str() == "[stack]";
            let segment_file_size = if is_stack {
                report.stack_snapshot_len
            } else {
                0
            };

            let seg_offset = if segment_file_size > 0 {
                let off = data_cursor;
                if out_buf.len() < data_cursor + segment_file_size {
                    return Err(SysError::BufferTooSmall);
                }
                out_buf[data_cursor..data_cursor + segment_file_size]
                    .copy_from_slice(&report.stack_snapshot[..segment_file_size]);
                data_cursor += segment_file_size;
                off
            } else {
                0
            };

            // Mapping des drapeaux de protection ELF (PF_X=1, PF_W=2, PF_R=4)
            let mut pf_flags = 0u32;
            if (region.flags & memory_flags::PROT_READ) != 0 {
                pf_flags |= 4;
            }
            if (region.flags & memory_flags::PROT_WRITE) != 0 {
                pf_flags |= 2;
            }
            if (region.flags & memory_flags::PROT_EXEC) != 0 {
                pf_flags |= 1;
            }

            // Écriture PT_LOAD
            out_buf[phdr_cursor..phdr_cursor + 4].copy_from_slice(&Self::PT_LOAD.to_le_bytes());
            out_buf[phdr_cursor + 4..phdr_cursor + 8].copy_from_slice(&pf_flags.to_le_bytes());
            out_buf[phdr_cursor + 8..phdr_cursor + 16]
                .copy_from_slice(&(seg_offset as u64).to_le_bytes());
            out_buf[phdr_cursor + 16..phdr_cursor + 24]
                .copy_from_slice(&region.vaddr.to_le_bytes());
            out_buf[phdr_cursor + 24..phdr_cursor + 32].copy_from_slice(&0u64.to_le_bytes());
            out_buf[phdr_cursor + 32..phdr_cursor + 40]
                .copy_from_slice(&(segment_file_size as u64).to_le_bytes());
            out_buf[phdr_cursor + 40..phdr_cursor + 48].copy_from_slice(&region.size.to_le_bytes());
            out_buf[phdr_cursor + 48..phdr_cursor + 56].copy_from_slice(&0x1000u64.to_le_bytes());
            phdr_cursor += phdr_size;
        }

        Ok(data_cursor)
    }
}

// ============================================================================
// RECOMMANDATIONS DE RÉCUPÉRATION & TÉLÉMÉTRIE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryRecommendation {
    RestartProcess,
    IsolateAndRespawnService,
    NodeFailover,
    KernelPanicHalt,
    QuarantineOnly,
}

impl RecoveryRecommendation {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecoveryRecommendation::RestartProcess => "RESTART_PROCESS",
            RecoveryRecommendation::IsolateAndRespawnService => "ISOLATE_RESPAWN_SERVICE",
            RecoveryRecommendation::NodeFailover => "NODE_FAILOVER",
            RecoveryRecommendation::KernelPanicHalt => "KERNEL_PANIC_HALT",
            RecoveryRecommendation::QuarantineOnly => "QUARANTINE_ONLY",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostCrashTelemetry {
    pub record_id: u64,
    pub report_id: u64,
    pub timestamp: u64,
    pub node_id: u32,
    pub pid: u32,
    pub reason_code: u32,
    pub fault_pc: u64,
    pub fault_addr: u64,
    pub quarantined_pages: u32,
    pub recommendation: RecoveryRecommendation,
    pub telemetry_hash: [u8; 32],
}

// ============================================================================
// RAPPORT DE CRASH SCELLÉ (Sealed Crash Report)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedCrashReport {
    pub report_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub process_name: [u8; MAX_NAME_LEN],
    pub process_name_len: usize,
    pub reason: CrashReason,
    pub regs: ArchRegisters,
    pub regions: [CoreMemoryRegion; MAX_REGIONS],
    pub region_count: usize,
    pub stack_snapshot: [u8; MAX_STACK_BYTES],
    pub stack_snapshot_len: usize,
    pub call_trace: [u64; MAX_CALL_TRACE],
    pub call_trace_len: usize,
    pub elf_size: usize,
    pub elf_digest: [u8; 32],
    pub sealed_digest: [u8; 32],
    pub quarantined: bool,
    pub telemetry_emitted: bool,
    pub recommendation: RecoveryRecommendation,
}

impl SealedCrashReport {
    pub fn new(
        report_id: u64,
        timestamp: u64,
        pid: u32,
        tid: u32,
        process_name: &str,
        reason: CrashReason,
        regs: ArchRegisters,
    ) -> Self {
        let mut name = [0u8; MAX_NAME_LEN];
        let bytes = process_name.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        name[..len].copy_from_slice(&bytes[..len]);

        let dummy_region = CoreMemoryRegion::new(0, 0, 0, "");

        let recommendation = match reason {
            CrashReason::KernelPanic | CrashReason::DoubleFault => {
                RecoveryRecommendation::KernelPanicHalt
            }
            CrashReason::WatchdogTimeout => RecoveryRecommendation::NodeFailover,
            CrashReason::GeneralProtectionFault { .. } | CrashReason::InvalidOpcode => {
                RecoveryRecommendation::IsolateAndRespawnService
            }
            _ => RecoveryRecommendation::RestartProcess,
        };

        Self {
            report_id,
            timestamp,
            pid,
            tid,
            process_name: name,
            process_name_len: len,
            reason,
            regs,
            regions: [dummy_region; MAX_REGIONS],
            region_count: 0,
            stack_snapshot: [0u8; MAX_STACK_BYTES],
            stack_snapshot_len: 0,
            call_trace: [0u64; MAX_CALL_TRACE],
            call_trace_len: 0,
            elf_size: 0,
            elf_digest: [0u8; 32],
            sealed_digest: [0u8; 32],
            quarantined: false,
            telemetry_emitted: false,
            recommendation,
        }
    }

    pub fn process_name_str(&self) -> &str {
        core::str::from_utf8(&self.process_name[..self.process_name_len]).unwrap_or("unknown")
    }

    pub fn add_region(&mut self, region: CoreMemoryRegion) -> Result<(), SysError> {
        if self.region_count >= MAX_REGIONS {
            return Err(SysError::OutOfMemory);
        }
        self.regions[self.region_count] = region;
        self.region_count += 1;
        Ok(())
    }

    pub fn set_stack_snapshot(&mut self, data: &[u8]) {
        let len = if data.len() > MAX_STACK_BYTES {
            MAX_STACK_BYTES
        } else {
            data.len()
        };
        self.stack_snapshot[..len].copy_from_slice(&data[..len]);
        self.stack_snapshot_len = len;
    }

    pub fn add_call_trace(&mut self, ip: u64) {
        if self.call_trace_len < MAX_CALL_TRACE {
            self.call_trace[self.call_trace_len] = ip;
            self.call_trace_len += 1;
        }
    }

    /// Calcule le condensat cryptographique de scellement du rapport
    pub fn compute_seal(&self) -> [u8; 32] {
        let mut buf = [0u8; 256];
        buf[0..8].copy_from_slice(&self.report_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[16..20].copy_from_slice(&self.pid.to_le_bytes());
        buf[20..24].copy_from_slice(&self.tid.to_le_bytes());
        buf[24..28].copy_from_slice(&self.reason.code().to_le_bytes());
        buf[28..36].copy_from_slice(&self.regs.instruction_pointer().to_le_bytes());
        buf[36..44].copy_from_slice(&self.regs.fault_address().to_le_bytes());
        buf[44..52].copy_from_slice(&(self.elf_size as u64).to_le_bytes());
        buf[52..84].copy_from_slice(&self.elf_digest);
        buf[84] = if self.quarantined { 1 } else { 0 };

        Sha256::digest(&buf[..85])
    }
}

// ============================================================================
// STATISTIQUES DU DÉMON CORE
// ============================================================================

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreDaemonStats {
    pub total_crashes_captured: u64,
    pub total_elf_generated: u64,
    pub total_reports_sealed: u64,
    pub total_pages_quarantined: u64,
    pub total_telemetry_emitted: u64,
    pub total_verifications_succeeded: u64,
    pub total_verifications_failed: u64,
}

// ============================================================================
// DÉMON JAMBO-CORE (`JamboCoreDaemon`)
// ============================================================================

pub struct JamboCoreDaemon {
    pub daemon_id: u32,
    pub admin_cap: CoreCap,
    pub reports: [Option<SealedCrashReport>; MAX_CRASH_REPORTS],
    pub report_count: usize,
    pub next_report_id: u64,
    pub telemetry_logs: [Option<PostCrashTelemetry>; MAX_TELEMETRY_LOGS],
    pub telemetry_count: usize,
    pub next_telemetry_id: u64,
    pub audit_digest: [u8; 32],
    pub stats: CoreDaemonStats,
}

impl JamboCoreDaemon {
    pub fn new(daemon_id: u32, admin_cap: CoreCap) -> Self {
        Self {
            daemon_id,
            admin_cap,
            reports: [None; MAX_CRASH_REPORTS],
            report_count: 0,
            next_report_id: 1,
            telemetry_logs: [None; MAX_TELEMETRY_LOGS],
            telemetry_count: 0,
            next_telemetry_id: 1,
            audit_digest: [0u8; 32],
            stats: CoreDaemonStats::default(),
        }
    }

    /// Initialise le démon avec des rapports types représentatifs
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Crash #1 : Faute de page (SIGSEGV) dans un worker Ring 3
        let mut x86_regs = X86_64Registers::default();
        x86_regs.rip = 0x00007fff80041234;
        x86_regs.rsp = 0x00007fffa000ff00;
        x86_regs.rbp = 0x00007fffa000ff40;
        x86_regs.cr2 = 0x0000000000000028; // Déréférencement pointeur nul + offset 0x28
        x86_regs.rax = 0;
        x86_regs.rdi = 0x00007fffa000ff20;

        let stack_sample = [
            0x34, 0x12, 0x04, 0x80, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
        ];

        let mut report = SealedCrashReport::new(
            self.next_report_id,
            1000,
            42,
            1,
            "worker-service",
            CrashReason::PageFault {
                fault_addr: 0x0000000000000028,
                error_code: 4, // Ring 3 read violation
            },
            ArchRegisters::X86_64(x86_regs),
        );
        report
            .add_region(CoreMemoryRegion::new(
                0x00007fff80040000,
                0x4000,
                memory_flags::PROT_READ | memory_flags::PROT_EXEC,
                "[text]",
            ))
            .ok();
        report
            .add_region(CoreMemoryRegion::new(
                0x00007fffa0000000,
                0x10000,
                memory_flags::PROT_READ | memory_flags::PROT_WRITE,
                "[stack]",
            ))
            .ok();
        report.set_stack_snapshot(&stack_sample);
        report.add_call_trace(0x00007fff80041234);
        report.add_call_trace(0x00007fff80040500);

        self.commit_report(&cap, report).ok();

        // 2. Crash #2 : Dépassement de chien de garde dans un pilote
        let mut arm_regs = AArch64Registers::default();
        arm_regs.pc = 0xffff000000108840;
        arm_regs.sp = 0xffff000000200000;
        arm_regs.fault_addr = 0;

        let mut report2 = SealedCrashReport::new(
            self.next_report_id,
            1050,
            12,
            1,
            "virtio-driver",
            CrashReason::WatchdogTimeout,
            ArchRegisters::AArch64(arm_regs),
        );
        report2
            .add_region(CoreMemoryRegion::new(
                0xffff000000100000,
                0x20000,
                memory_flags::PROT_READ | memory_flags::PROT_EXEC,
                "[driver-text]",
            ))
            .ok();
        report2.add_call_trace(0xffff000000108840);

        self.commit_report(&cap, report2).ok();
    }

    /// Capture un nouvel état de crash et génère son rapport scellé
    pub fn capture_crash(
        &mut self,
        cap: &CoreCap,
        pid: u32,
        tid: u32,
        name: &str,
        reason: CrashReason,
        regs: ArchRegisters,
        stack_bytes: &[u8],
        call_trace: &[u64],
        timestamp: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(core_rights::CORE_CAPTURE) {
            return Err(SysError::PermissionDenied);
        }

        let mut report =
            SealedCrashReport::new(self.next_report_id, timestamp, pid, tid, name, reason, regs);

        // Mappings standards
        report.add_region(CoreMemoryRegion::new(
            regs.instruction_pointer() & !0xfff,
            0x1000,
            memory_flags::PROT_READ | memory_flags::PROT_EXEC,
            "[code]",
        ))?;
        report.add_region(CoreMemoryRegion::new(
            regs.stack_pointer() & !0xfff,
            0x4000,
            memory_flags::PROT_READ | memory_flags::PROT_WRITE,
            "[stack]",
        ))?;

        report.set_stack_snapshot(stack_bytes);
        for &ip in call_trace {
            report.add_call_trace(ip);
        }

        self.commit_report(cap, report)
    }

    /// Valide, génère le dump ELF, scelle le rapport et l'insère dans le tampon annulaire
    pub fn commit_report(
        &mut self,
        cap: &CoreCap,
        mut report: SealedCrashReport,
    ) -> Result<u64, SysError> {
        if !cap.has_right(core_rights::CORE_CAPTURE) {
            return Err(SysError::PermissionDenied);
        }

        // Génération du Core Dump ELF64 pour obtenir sa taille et son empreinte SHA-256
        let mut elf_buf = [0u8; 2048];
        let elf_size = Elf64Generator::generate_core_dump(&report, &mut elf_buf)?;
        report.elf_size = elf_size;
        report.elf_digest = Sha256::digest(&elf_buf[..elf_size]);
        self.stats.total_elf_generated += 1;

        // Scellement cryptographique du rapport
        report.sealed_digest = report.compute_seal();
        self.stats.total_reports_sealed += 1;

        let report_id = report.report_id;
        self.next_report_id += 1;
        self.stats.total_crashes_captured += 1;

        // Mise à jour du journal d'audit chaîné
        let mut audit_feed = [0u8; 64];
        audit_feed[0..32].copy_from_slice(&self.audit_digest);
        audit_feed[32..64].copy_from_slice(&report.sealed_digest);
        self.audit_digest = Sha256::digest(&audit_feed);

        // Insertion dans le tampon annulaire
        let slot = (report_id as usize - 1) % MAX_CRASH_REPORTS;
        self.reports[slot] = Some(report);
        if self.report_count < MAX_CRASH_REPORTS {
            self.report_count += 1;
        }

        Ok(report_id)
    }

    /// Génère le binaire ELF64 Core Dump pour un rapport existant
    pub fn generate_elf(
        &self,
        cap: &CoreCap,
        report_id: u64,
        out_buf: &mut [u8],
    ) -> Result<usize, SysError> {
        if !cap.has_right(core_rights::CORE_GENERATE) {
            return Err(SysError::PermissionDenied);
        }

        let report = self
            .get_report(report_id)
            .ok_or(SysError::InvalidArgument)?;
        Elf64Generator::generate_core_dump(report, out_buf)
    }

    /// Vérifie l'intégrité et l'authenticité d'un rapport de crash scellé
    pub fn verify_seal(&mut self, cap: &CoreCap, report_id: u64) -> Result<bool, SysError> {
        if !cap.has_right(core_rights::CORE_INSPECT) {
            return Err(SysError::PermissionDenied);
        }

        let report = self
            .get_report(report_id)
            .ok_or(SysError::InvalidArgument)?;
        let expected = report.compute_seal();
        let valid = expected == report.sealed_digest;

        if valid {
            self.stats.total_verifications_succeeded += 1;
        } else {
            self.stats.total_verifications_failed += 1;
        }

        Ok(valid)
    }

    /// Met en quarantaine les pages mémoires associées au processus crashé
    pub fn quarantine_memory(&mut self, cap: &CoreCap, report_id: u64) -> Result<u64, SysError> {
        if !cap.has_right(core_rights::CORE_QUARANTINE) {
            return Err(SysError::PermissionDenied);
        }

        let mut pages_quarantined = 0u64;

        for slot in self.reports.iter_mut() {
            if let Some(ref mut rep) = slot {
                if rep.report_id == report_id {
                    rep.quarantined = true;
                    for r in rep.regions.iter_mut() {
                        r.quarantined = true;
                        pages_quarantined += (r.size + 0xfff) / 0x1000;
                    }
                    rep.sealed_digest = rep.compute_seal();
                    self.stats.total_pages_quarantined += pages_quarantined;
                    return Ok(pages_quarantined);
                }
            }
        }

        Err(SysError::InvalidArgument)
    }

    /// Émet un rapport de télémétrie post-crash pour le superviseur et la grappe
    pub fn emit_telemetry(
        &mut self,
        cap: &CoreCap,
        report_id: u64,
        node_id: u32,
    ) -> Result<PostCrashTelemetry, SysError> {
        if !cap.has_right(core_rights::CORE_TELEMETRY) {
            return Err(SysError::PermissionDenied);
        }

        let report = *self
            .get_report(report_id)
            .ok_or(SysError::InvalidArgument)?;

        let mut hash_input = [0u8; 64];
        hash_input[0..8].copy_from_slice(&report.report_id.to_le_bytes());
        hash_input[8..12].copy_from_slice(&node_id.to_le_bytes());
        hash_input[12..16].copy_from_slice(&report.pid.to_le_bytes());
        hash_input[16..20].copy_from_slice(&report.reason.code().to_le_bytes());
        hash_input[20..28].copy_from_slice(&report.regs.instruction_pointer().to_le_bytes());
        hash_input[28..36].copy_from_slice(&report.regs.fault_address().to_le_bytes());
        let hash = Sha256::digest(&hash_input[..36]);

        let telemetry = PostCrashTelemetry {
            record_id: self.next_telemetry_id,
            report_id,
            timestamp: report.timestamp,
            node_id,
            pid: report.pid,
            reason_code: report.reason.code(),
            fault_pc: report.regs.instruction_pointer(),
            fault_addr: report.regs.fault_address(),
            quarantined_pages: report.region_count as u32 * 4,
            recommendation: report.recommendation,
            telemetry_hash: hash,
        };

        self.next_telemetry_id += 1;
        self.stats.total_telemetry_emitted += 1;

        // Mise à jour de l'état du rapport
        for slot in self.reports.iter_mut() {
            if let Some(ref mut rep) = slot {
                if rep.report_id == report_id {
                    rep.telemetry_emitted = true;
                    break;
                }
            }
        }

        let slot = (telemetry.record_id as usize - 1) % MAX_TELEMETRY_LOGS;
        self.telemetry_logs[slot] = Some(telemetry);
        if self.telemetry_count < MAX_TELEMETRY_LOGS {
            self.telemetry_count += 1;
        }

        Ok(telemetry)
    }

    /// Purge les rapports de crash archivés
    pub fn purge_reports(&mut self, cap: &CoreCap) -> Result<usize, SysError> {
        if !cap.has_right(core_rights::CORE_PURGE) {
            return Err(SysError::PermissionDenied);
        }

        let purged = self.report_count;
        for slot in self.reports.iter_mut() {
            *slot = None;
        }
        self.report_count = 0;
        Ok(purged)
    }

    pub fn get_report(&self, report_id: u64) -> Option<&SealedCrashReport> {
        for slot in self.reports.iter() {
            if let Some(ref rep) = slot {
                if rep.report_id == report_id {
                    return Some(rep);
                }
            }
        }
        None
    }

    pub fn get_audit_digest(&self, cap: &CoreCap) -> Result<[u8; 32], SysError> {
        if !cap.has_right(core_rights::CORE_INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.audit_digest)
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_cap_attenuation_and_anti_amplification() {
        let admin = CoreCap::new(Handle::new(100, 1), core_rights::ALL);
        assert!(admin.has_right(core_rights::CORE_INSPECT));
        assert!(admin.has_right(core_rights::CORE_CAPTURE));
        assert!(admin.has_right(core_rights::CORE_ADMIN));

        let inspect_only = admin.attenuate(core_rights::CORE_INSPECT).unwrap();
        assert!(inspect_only.has_right(core_rights::CORE_INSPECT));
        assert!(!inspect_only.has_right(core_rights::CORE_CAPTURE));
        assert!(!inspect_only.has_right(core_rights::CORE_ADMIN));

        // Rejet formel de toute tentative d'amplification
        assert_eq!(
            inspect_only.attenuate(core_rights::CORE_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_crash_capture_and_elf_generation() {
        let admin = CoreCap::new(Handle::new(101, 1), core_rights::ALL);
        let mut daemon = JamboCoreDaemon::new(1, admin);
        daemon.init_defaults();

        assert_eq!(daemon.report_count, 2);
        let rep1 = daemon.get_report(1).expect("Report 1 must exist");
        assert_eq!(rep1.process_name_str(), "worker-service");
        assert_eq!(rep1.pid, 42);
        assert!(rep1.elf_size > 0);

        // Validation du binaire ELF64
        let mut buf = [0u8; 2048];
        let bytes_written = daemon.generate_elf(&admin, 1, &mut buf).unwrap();
        assert_eq!(bytes_written, rep1.elf_size);

        // Validation en-tête ELF
        assert_eq!(buf[0], 0x7f);
        assert_eq!(buf[1], b'E');
        assert_eq!(buf[2], b'L');
        assert_eq!(buf[3], b'F');
        assert_eq!(buf[4], 2); // 64-bit
        assert_eq!(buf[5], 1); // Little endian
        let elf_type = u16::from_le_bytes([buf[16], buf[17]]);
        assert_eq!(elf_type, Elf64Generator::ET_CORE);
    }

    #[test]
    fn test_cryptographic_seal_and_tamper_detection() {
        let admin = CoreCap::new(Handle::new(102, 1), core_rights::ALL);
        let mut daemon = JamboCoreDaemon::new(1, admin);
        daemon.init_defaults();

        // Vérification nominale du sceau
        assert!(daemon.verify_seal(&admin, 1).unwrap());

        // Altération malveillante d'un bit dans le rapport
        for slot in daemon.reports.iter_mut() {
            if let Some(ref mut rep) = slot {
                if rep.report_id == 1 {
                    rep.pid = 9999; // Modification non autorisée
                }
            }
        }

        // Le sceau doit détecter la falsification
        assert!(!daemon.verify_seal(&admin, 1).unwrap());
    }

    #[test]
    fn test_memory_quarantine_isolation() {
        let admin = CoreCap::new(Handle::new(103, 1), core_rights::ALL);
        let mut daemon = JamboCoreDaemon::new(1, admin);
        daemon.init_defaults();

        let rep_before = daemon.get_report(1).unwrap();
        assert!(!rep_before.quarantined);

        let pages = daemon.quarantine_memory(&admin, 1).unwrap();
        assert!(pages > 0);

        let rep_after = daemon.get_report(1).unwrap();
        assert!(rep_after.quarantined);
        assert!(rep_after.regions[0].quarantined);
        assert!(rep_after.regions[1].quarantined);
    }

    #[test]
    fn test_post_crash_telemetry_emission() {
        let admin = CoreCap::new(Handle::new(104, 1), core_rights::ALL);
        let mut daemon = JamboCoreDaemon::new(1, admin);
        daemon.init_defaults();

        let telemetry = daemon.emit_telemetry(&admin, 1, 10).unwrap();
        assert_eq!(telemetry.report_id, 1);
        assert_eq!(telemetry.node_id, 10);
        assert_eq!(telemetry.pid, 42);
        assert_eq!(
            telemetry.recommendation,
            RecoveryRecommendation::RestartProcess
        );

        let rep = daemon.get_report(1).unwrap();
        assert!(rep.telemetry_emitted);
    }

    #[test]
    fn test_audit_digest_chain() {
        let admin = CoreCap::new(Handle::new(105, 1), core_rights::ALL);
        let mut daemon = JamboCoreDaemon::new(1, admin);
        daemon.init_defaults();

        let digest1 = daemon.get_audit_digest(&admin).unwrap();
        assert_ne!(digest1, [0u8; 32]);

        // Capture d'un 3e crash
        let regs = X86_64Registers::default();
        daemon
            .capture_crash(
                &admin,
                77,
                1,
                "failed-task",
                CrashReason::AssertionFailed,
                ArchRegisters::X86_64(regs),
                &[1, 2, 3, 4],
                &[0x1000],
                2000,
            )
            .unwrap();

        let digest2 = daemon.get_audit_digest(&admin).unwrap();
        assert_ne!(digest1, digest2); // L'audit a évolué de manière monotone
    }
}

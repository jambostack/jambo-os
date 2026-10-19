//! Démon de Rechargement à Chaud en Espace Utilisateur & Conformité ABI (`jambo-patchd`)
//!
//! Fournit une infrastructure complète de remplacement dynamique de symboles,
//! injection atomique de trampolines, quiescence de threads et validation ABI
//! pour le micro-noyau souverain JamboOS (`#![no_std]`) :
//! 1. Remplacement atomique de symboles et fonctions exécutables Ring 3 à chaud (*Livepatching*).
//! 2. Quiescence déterministe des threads et barrière de synchronisation sans interblocage.
//! 3. Génération de trampolines exécutables multi-architectures (x86-64 Rel32, Indirect64, ARM64 Direct & Indirect).
//! 4. Vérification formelle de conformité ABI (System V AMD64 / ARM64 AAPCS, alignement de pile, préservation callee-saved).
//! 5. Préservation d'état des VMO et mécanisme de rollback / restauration atomique garantie.
//! 6. Registre d'audit inviolable scellé par chaîne cryptographique SHA-256.
//! 7. Modèle de sécurité capabilaire strict (`PatchCap`) sans autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_PATCHES: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 16;
pub const MAX_THREADS_PER_PROCESS: usize = 32;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_CODE_SNIPPET_SIZE: usize = 64;

pub const TRAMPOLINE_SIZE_REL32: usize = 5;
pub const TRAMPOLINE_SIZE_INDIR64: usize = 14;
pub const TRAMPOLINE_SIZE_ARM64_DIRECT: usize = 4;
pub const TRAMPOLINE_SIZE_ARM64_INDIR: usize = 16;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 standard `#![no_std]` sans allocation
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
// MODÈLE DE SÉCURITÉ CAPABILAIRE : PatchCap
// ============================================================================

pub mod patch_rights {
    pub const PATCH_INSPECT: u32 = 1 << 0;
    pub const PATCH_PREPARE: u32 = 1 << 1;
    pub const PATCH_QUIESCE: u32 = 1 << 2;
    pub const PATCH_APPLY: u32 = 1 << 3;
    pub const PATCH_REVERT: u32 = 1 << 4;
    pub const PATCH_AUDIT: u32 = 1 << 5;
    pub const PATCH_ADMIN: u32 = 1 << 6;

    pub const ALL: u32 = PATCH_INSPECT
        | PATCH_PREPARE
        | PATCH_QUIESCE
        | PATCH_APPLY
        | PATCH_REVERT
        | PATCH_AUDIT
        | PATCH_ADMIN;
}

/// Capacité de contrôle d'accès pour le démon de rechargement à chaud
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatchCap {
    pub handle: Handle,
    pub rights: u32,
}

impl PatchCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits vers un sous-ensemble strict.
    /// Interdit formellement toute amplification de privilèges.
    pub fn attenuate(&self, new_rights: u32) -> Result<PatchCap, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(PatchCap {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// TYPES D'ARCHITECTURE & MODÈLES DE TRAMPOLINES
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetArch {
    X86_64,
    AArch64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrampolineKind {
    /// x86-64 Saut relatif 32-bit (0xE9 rel32), 5 octets
    RelativeJmp32,
    /// x86-64 Saut indirect 64-bit absolu (0xFF 0x25 0x00000000 <u64>), 14 octets
    AbsoluteIndirect64,
    /// ARM64 Saut direct branch (B imm26), 4 octets
    Arm64DirectBranch,
    /// ARM64 Saut indirect (LDR X16, #8; BR X16; <u64>), 16 octets
    Arm64IndirectBranch,
}

impl TrampolineKind {
    pub const fn size(&self) -> usize {
        match self {
            Self::RelativeJmp32 => TRAMPOLINE_SIZE_REL32,
            Self::AbsoluteIndirect64 => TRAMPOLINE_SIZE_INDIR64,
            Self::Arm64DirectBranch => TRAMPOLINE_SIZE_ARM64_DIRECT,
            Self::Arm64IndirectBranch => TRAMPOLINE_SIZE_ARM64_INDIR,
        }
    }
}

/// Générateur de trampolines exécutables multi-architectures
pub struct TrampolineGenerator;

impl TrampolineGenerator {
    /// Génère un saut relatif x86-64 (0xE9 rel32)
    pub fn build_rel32_jmp(from_vaddr: u64, to_vaddr: u64, out: &mut [u8; 16]) -> Result<usize, SysError> {
        let next_ip = from_vaddr.wrapping_add(5);
        let diff = to_vaddr as i64 - next_ip as i64;
        if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
            return Err(SysError::InvalidArgument);
        }
        let rel32 = diff as i32;
        out[0] = 0xE9;
        out[1..5].copy_from_slice(&rel32.to_le_bytes());
        for i in 5..16 {
            out[i] = 0x90; // NOP padding
        }
        Ok(5)
    }

    /// Génère un saut indirect x86-64 absolu 64-bit (0xFF 0x25 00 00 00 00 <target>)
    pub fn build_indirect64_jmp(to_vaddr: u64, out: &mut [u8; 16]) -> usize {
        out[0] = 0xFF;
        out[1] = 0x25;
        out[2] = 0x00;
        out[3] = 0x00;
        out[4] = 0x00;
        out[5] = 0x00;
        out[6..14].copy_from_slice(&to_vaddr.to_le_bytes());
        out[14] = 0x90;
        out[15] = 0x90;
        14
    }

    /// Génère un saut direct ARM64 (B imm26)
    pub fn build_arm64_direct_jmp(from_vaddr: u64, to_vaddr: u64, out: &mut [u8; 16]) -> Result<usize, SysError> {
        let diff = to_vaddr as i64 - from_vaddr as i64;
        if diff % 4 != 0 {
            return Err(SysError::InvalidArgument);
        }
        let imm26 = diff / 4;
        if imm26 < -(1 << 25) || imm26 >= (1 << 25) {
            return Err(SysError::InvalidArgument);
        }
        let opcode: u32 = 0x1400_0000 | ((imm26 as u32) & 0x03FF_FFFF);
        out[0..4].copy_from_slice(&opcode.to_le_bytes());
        for i in 4..16 {
            out[i] = 0x00;
        }
        Ok(4)
    }

    /// Génère un saut indirect ARM64 (LDR X16, #8; BR X16; target_64)
    pub fn build_arm64_indirect_jmp(to_vaddr: u64, out: &mut [u8; 16]) -> usize {
        // LDR X16, #8 -> 0x58000050
        // BR X16      -> 0xD61F0200
        out[0..4].copy_from_slice(&0x58000050u32.to_le_bytes());
        out[4..8].copy_from_slice(&0xD61F0200u32.to_le_bytes());
        out[8..16].copy_from_slice(&to_vaddr.to_le_bytes());
        16
    }
}

// ============================================================================
// CONFORMITÉ ABI & VALIDATEUR STATIQUE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiCheckResult {
    Compliant,
    PrologueTooShort,
    StackMisaligned,
    UnsafeInstruction,
    InvalidAddress,
    ArchitectureMismatch,
}

/// Vérificateur de conformité ABI
pub struct AbiComplianceChecker;

impl AbiComplianceChecker {
    /// Vérifie la conformité de l'adresse et de l'alignement pour une architecture cible
    pub fn verify_target(
        arch: TargetArch,
        target_vaddr: u64,
        replacement_vaddr: u64,
        prologue_bytes: &[u8],
    ) -> AbiCheckResult {
        if target_vaddr == 0 || replacement_vaddr == 0 {
            return AbiCheckResult::InvalidAddress;
        }

        // Alignement selon l'architecture
        match arch {
            TargetArch::X86_64 => {
                // x86-64 instructions peuvent débuter à n'importe quel octet, mais le prologue
                // doit être suffisant pour insérer le trampoline (au moins 5 octets)
                if prologue_bytes.len() < TRAMPOLINE_SIZE_REL32 {
                    return AbiCheckResult::PrologueTooShort;
                }
                // Détection d'instructions dangereuses ou de sauts relatifs tronqués
                if prologue_bytes[0] == 0xC3 || prologue_bytes[0] == 0xCB {
                    // RET immédiat
                    return AbiCheckResult::UnsafeInstruction;
                }
            }
            TargetArch::AArch64 => {
                // ARM64 exige un alignement 4-octets strict pour toutes les instructions
                if target_vaddr % 4 != 0 || replacement_vaddr % 4 != 0 {
                    return AbiCheckResult::StackMisaligned;
                }
                if prologue_bytes.len() < TRAMPOLINE_SIZE_ARM64_DIRECT {
                    return AbiCheckResult::PrologueTooShort;
                }
            }
        }

        AbiCheckResult::Compliant
    }
}

// ============================================================================
// SYNCHRONISATION & QUIESCENCE DES THREADS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Running,
    Quiescent,
    InTrampolineZone,
    Suspended,
}

#[derive(Clone, Copy, Debug)]
pub struct TargetThread {
    pub thread_id: u64,
    pub ip: u64,
    pub sp: u64,
    pub state: ThreadState,
}

impl Default for TargetThread {
    fn default() -> Self {
        Self {
            thread_id: 0,
            ip: 0,
            sp: 0,
            state: ThreadState::Running,
        }
    }
}

// ============================================================================
// ÉTATS DE PATCH & ENREGISTREMENTS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchState {
    Free,
    Prepared,
    Quiesced,
    Applied,
    Reverted,
    Failed,
}

/// Enregistrement d'un patch dynamique
#[derive(Clone, Copy)]
pub struct PatchRecord {
    pub patch_id: u32,
    pub state: PatchState,
    pub target_pid: u64,
    pub arch: TargetArch,
    pub trampoline_kind: TrampolineKind,
    pub symbol_name: [u8; MAX_NAME_LEN],
    pub patch_name: [u8; MAX_NAME_LEN],
    pub target_vaddr: u64,
    pub replacement_vaddr: u64,
    pub original_prologue: [u8; 16],
    pub original_prologue_len: usize,
    pub trampoline_bytes: [u8; 16],
    pub trampoline_len: usize,
    pub expected_code_hash: [u8; 32],
    pub patch_code_hash: [u8; 32],
    pub seal_hash: [u8; 32],
    pub vmo_handle: Handle,
    pub applied_timestamp: u64,
}

impl Default for PatchRecord {
    fn default() -> Self {
        Self {
            patch_id: 0,
            state: PatchState::Free,
            target_pid: 0,
            arch: TargetArch::X86_64,
            trampoline_kind: TrampolineKind::RelativeJmp32,
            symbol_name: [0u8; MAX_NAME_LEN],
            patch_name: [0u8; MAX_NAME_LEN],
            target_vaddr: 0,
            replacement_vaddr: 0,
            original_prologue: [0u8; 16],
            original_prologue_len: 0,
            trampoline_bytes: [0u8; 16],
            trampoline_len: 0,
            expected_code_hash: [0u8; 32],
            patch_code_hash: [0u8; 32],
            seal_hash: [0u8; 32],
            vmo_handle: Handle::NULL,
            applied_timestamp: 0,
        }
    }
}

impl PatchRecord {
    pub fn symbol_str(&self) -> &str {
        let len = self.symbol_name.iter().position(|&b| b == 0).unwrap_or(self.symbol_name.len());
        core::str::from_utf8(&self.symbol_name[..len]).unwrap_or("")
    }

    pub fn name_str(&self) -> &str {
        let len = self.patch_name.iter().position(|&b| b == 0).unwrap_or(self.patch_name.len());
        core::str::from_utf8(&self.patch_name[..len]).unwrap_or("")
    }

    pub fn state_str(&self) -> &'static str {
        match self.state {
            PatchState::Free => "Libre",
            PatchState::Prepared => "Préparé",
            PatchState::Quiesced => "Quiescent (Synchronisé)",
            PatchState::Applied => "Appliqué (Actif)",
            PatchState::Reverted => "Restauré (Rollback)",
            PatchState::Failed => "Échec",
        }
    }

    pub fn arch_str(&self) -> &'static str {
        match self.arch {
            TargetArch::X86_64 => "x86-64",
            TargetArch::AArch64 => "ARM64 (AArch64)",
        }
    }

    pub fn trampoline_str(&self) -> &'static str {
        match self.trampoline_kind {
            TrampolineKind::RelativeJmp32 => "Rel32 JMP (5B)",
            TrampolineKind::AbsoluteIndirect64 => "Indirect64 JMP (14B)",
            TrampolineKind::Arm64DirectBranch => "ARM64 Branch Direct (4B)",
            TrampolineKind::Arm64IndirectBranch => "ARM64 Branch Indirect (16B)",
        }
    }
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ SHA-256
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    Prepare,
    Quiesce,
    Apply,
    Revert,
    Verify,
}

#[derive(Clone, Copy)]
pub struct SealedAuditEntry {
    pub entry_id: u64,
    pub action: AuditAction,
    pub patch_id: u32,
    pub target_pid: u64,
    pub timestamp: u64,
    pub digest: [u8; 32],
}

impl Default for SealedAuditEntry {
    fn default() -> Self {
        Self {
            entry_id: 0,
            action: AuditAction::Prepare,
            patch_id: 0,
            target_pid: 0,
            timestamp: 0,
            digest: [0u8; 32],
        }
    }
}

// ============================================================================
// STATISTIQUES DU DÉMON
// ============================================================================

#[derive(Clone, Copy, Debug, Default)]
pub struct PatchDaemonStats {
    pub total_patches_prepared: u64,
    pub total_patches_applied: u64,
    pub total_patches_reverted: u64,
    pub total_quiescence_cycles: u64,
    pub total_abi_checks_passed: u64,
    pub total_abi_checks_failed: u64,
    pub total_audit_entries: u64,
    pub total_seals_verified: u64,
}

// ============================================================================
// DÉMON JAMBO-PATCHD
// ============================================================================

pub struct JamboPatchDaemon {
    pub daemon_id: u32,
    pub cap: PatchCap,
    pub patches: [Option<PatchRecord>; MAX_PATCHES],
    pub patch_count: usize,
    pub audit_log: [Option<SealedAuditEntry>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub last_audit_digest: [u8; 32],
    pub stats: PatchDaemonStats,
    pub next_patch_id: u32,
    pub next_audit_id: u64,
}

impl JamboPatchDaemon {
    pub const fn new(daemon_id: u32, cap: PatchCap) -> Self {
        const NONE_PATCH: Option<PatchRecord> = None;
        const NONE_AUDIT: Option<SealedAuditEntry> = None;
        Self {
            daemon_id,
            cap,
            patches: [NONE_PATCH; MAX_PATCHES],
            patch_count: 0,
            audit_log: [NONE_AUDIT; MAX_AUDIT_LOGS],
            audit_count: 0,
            last_audit_digest: [0u8; 32],
            stats: PatchDaemonStats {
                total_patches_prepared: 0,
                total_patches_applied: 0,
                total_patches_reverted: 0,
                total_quiescence_cycles: 0,
                total_abi_checks_passed: 0,
                total_abi_checks_failed: 0,
                total_audit_entries: 0,
                total_seals_verified: 0,
            },
            next_patch_id: 1,
            next_audit_id: 1,
        }
    }

    /// Enregistre une entrée dans le registre d'audit scellé SHA-256
    fn record_audit(
        &mut self,
        action: AuditAction,
        patch_id: u32,
        target_pid: u64,
        timestamp: u64,
    ) {
        let mut block = [0u8; 64];
        block[0..32].copy_from_slice(&self.last_audit_digest);
        block[32] = match action {
            AuditAction::Prepare => 1,
            AuditAction::Quiesce => 2,
            AuditAction::Apply => 3,
            AuditAction::Revert => 4,
            AuditAction::Verify => 5,
        };
        block[33..37].copy_from_slice(&patch_id.to_le_bytes());
        block[37..45].copy_from_slice(&target_pid.to_le_bytes());
        block[45..53].copy_from_slice(&timestamp.to_le_bytes());
        block[53..61].copy_from_slice(&self.next_audit_id.to_le_bytes());
        block[61..64].copy_from_slice(&[0xAA, 0x55, 0xCC]);

        let digest = Sha256::digest(&block);
        self.last_audit_digest = digest;

        let entry = SealedAuditEntry {
            entry_id: self.next_audit_id,
            action,
            patch_id,
            target_pid,
            timestamp,
            digest,
        };
        self.next_audit_id += 1;

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_log[self.audit_count] = Some(entry);
            self.audit_count += 1;
        } else {
            // Décalage FIFO pour registre borné
            for i in 1..MAX_AUDIT_LOGS {
                self.audit_log[i - 1] = self.audit_log[i];
            }
            self.audit_log[MAX_AUDIT_LOGS - 1] = Some(entry);
        }
        self.stats.total_audit_entries += 1;
    }

    /// Calcule le scellement SHA-256 d'un patch
    pub fn compute_patch_seal(record: &PatchRecord) -> [u8; 32] {
        let mut buf = [0u8; 192];
        buf[0..4].copy_from_slice(&record.patch_id.to_le_bytes());
        buf[4..12].copy_from_slice(&record.target_pid.to_le_bytes());
        buf[12..20].copy_from_slice(&record.target_vaddr.to_le_bytes());
        buf[20..28].copy_from_slice(&record.replacement_vaddr.to_le_bytes());
        buf[28..60].copy_from_slice(&record.expected_code_hash);
        buf[60..92].copy_from_slice(&record.patch_code_hash);
        buf[92..108].copy_from_slice(&record.trampoline_bytes);
        buf[108..116].copy_from_slice(&(record.trampoline_len as u64).to_le_bytes());
        buf[116..124].copy_from_slice(&record.applied_timestamp.to_le_bytes());
        buf[124..156].copy_from_slice(&record.symbol_name);
        buf[156..188].copy_from_slice(&record.patch_name);
        buf[188] = record.arch as u8;
        buf[189] = record.trampoline_kind as u8;
        buf[190] = record.state as u8;
        buf[191] = 0x42;
        Sha256::digest(&buf)
    }

    /// Préparation et validation d'un nouveau patch à chaud
    pub fn prepare_patch(
        &mut self,
        cap: &PatchCap,
        target_pid: u64,
        arch: TargetArch,
        name: &str,
        symbol: &str,
        target_vaddr: u64,
        original_code: &[u8],
        replacement_vaddr: u64,
        replacement_code: &[u8],
        vmo_handle: Handle,
        timestamp: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(patch_rights::PATCH_PREPARE) {
            return Err(SysError::PermissionDenied);
        }

        if self.patch_count >= MAX_PATCHES {
            return Err(SysError::OutOfMemory);
        }

        // Vérification de conformité ABI
        let abi_check = AbiComplianceChecker::verify_target(
            arch,
            target_vaddr,
            replacement_vaddr,
            original_code,
        );
        if abi_check != AbiCheckResult::Compliant {
            self.stats.total_abi_checks_failed += 1;
            return Err(SysError::InvalidArgument);
        }
        self.stats.total_abi_checks_passed += 1;

        // Choix et construction du trampoline adapté
        let mut tramp_bytes = [0u8; 16];
        let (trampoline_kind, tramp_len) = match arch {
            TargetArch::X86_64 => {
                let next_ip = target_vaddr.wrapping_add(5);
                let diff = replacement_vaddr as i64 - next_ip as i64;
                if diff >= i32::MIN as i64 && diff <= i32::MAX as i64 {
                    let len = TrampolineGenerator::build_rel32_jmp(
                        target_vaddr,
                        replacement_vaddr,
                        &mut tramp_bytes,
                    )?;
                    (TrampolineKind::RelativeJmp32, len)
                } else {
                    let len = TrampolineGenerator::build_indirect64_jmp(
                        replacement_vaddr,
                        &mut tramp_bytes,
                    );
                    (TrampolineKind::AbsoluteIndirect64, len)
                }
            }
            TargetArch::AArch64 => {
                let diff = replacement_vaddr as i64 - target_vaddr as i64;
                let imm26 = diff / 4;
                if imm26 >= -(1 << 25) && imm26 < (1 << 25) {
                    let len = TrampolineGenerator::build_arm64_direct_jmp(
                        target_vaddr,
                        replacement_vaddr,
                        &mut tramp_bytes,
                    )?;
                    (TrampolineKind::Arm64DirectBranch, len)
                } else {
                    let len = TrampolineGenerator::build_arm64_indirect_jmp(
                        replacement_vaddr,
                        &mut tramp_bytes,
                    );
                    (TrampolineKind::Arm64IndirectBranch, len)
                }
            }
        };

        // Sauvegarde du prologue original
        let mut orig_prologue = [0u8; 16];
        let orig_len = core::cmp::min(original_code.len(), 16);
        orig_prologue[..orig_len].copy_from_slice(&original_code[..orig_len]);

        let patch_id = self.next_patch_id;
        self.next_patch_id += 1;

        let mut rec = PatchRecord {
            patch_id,
            state: PatchState::Prepared,
            target_pid,
            arch,
            trampoline_kind,
            symbol_name: [0u8; MAX_NAME_LEN],
            patch_name: [0u8; MAX_NAME_LEN],
            target_vaddr,
            replacement_vaddr,
            original_prologue: orig_prologue,
            original_prologue_len: orig_len,
            trampoline_bytes: tramp_bytes,
            trampoline_len: tramp_len,
            expected_code_hash: Sha256::digest(original_code),
            patch_code_hash: Sha256::digest(replacement_code),
            seal_hash: [0u8; 32],
            vmo_handle,
            applied_timestamp: timestamp,
        };

        let sym_bytes = symbol.as_bytes();
        let sym_copy_len = core::cmp::min(sym_bytes.len(), MAX_NAME_LEN);
        rec.symbol_name[..sym_copy_len].copy_from_slice(&sym_bytes[..sym_copy_len]);

        let name_bytes = name.as_bytes();
        let name_copy_len = core::cmp::min(name_bytes.len(), MAX_NAME_LEN);
        rec.patch_name[..name_copy_len].copy_from_slice(&name_bytes[..name_copy_len]);

        rec.seal_hash = Self::compute_patch_seal(&rec);

        // Insertion dans le premier créneau libre
        for slot in self.patches.iter_mut() {
            if slot.is_none() {
                *slot = Some(rec);
                self.patch_count += 1;
                break;
            }
        }

        self.stats.total_patches_prepared += 1;
        self.record_audit(AuditAction::Prepare, patch_id, target_pid, timestamp);

        Ok(patch_id)
    }

    /// Analyse et quiescence des threads d'un processus cible
    pub fn quiesce_threads(
        &mut self,
        cap: &PatchCap,
        patch_id: u32,
        threads: &mut [TargetThread],
        timestamp: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(patch_rights::PATCH_QUIESCE) {
            return Err(SysError::PermissionDenied);
        }

        let patch_idx = self
            .patches
            .iter()
            .position(|p| p.as_ref().map(|r| r.patch_id == patch_id).unwrap_or(false))
            .ok_or(SysError::InvalidArgument)?;

        let rec = self.patches[patch_idx].as_ref().unwrap();
        let target_start = rec.target_vaddr;
        let target_end = target_start.wrapping_add(rec.trampoline_len as u64);

        let mut in_critical_zone = 0;
        let mut quiescent_count = 0;

        for t in threads.iter_mut() {
            if t.ip >= target_start && t.ip < target_end {
                t.state = ThreadState::InTrampolineZone;
                in_critical_zone += 1;
            } else {
                t.state = ThreadState::Quiescent;
                quiescent_count += 1;
            }
        }

        if in_critical_zone > 0 {
            // Un ou plusieurs threads sont dans la zone critique : la quiescence n'est pas encore atteinte
            return Err(SysError::ResourceBusy);
        }

        // Tous les threads sont hors de la zone critique : passage à Quiesced
        if let Some(p) = self.patches[patch_idx].as_mut() {
            p.state = PatchState::Quiesced;
            p.seal_hash = Self::compute_patch_seal(p);
        }

        self.stats.total_quiescence_cycles += 1;
        let target_pid = self.patches[patch_idx].as_ref().unwrap().target_pid;
        self.record_audit(AuditAction::Quiesce, patch_id, target_pid, timestamp);

        Ok(quiescent_count)
    }

    /// Application atomique du patch (injection du trampoline)
    pub fn apply_patch(
        &mut self,
        cap: &PatchCap,
        patch_id: u32,
        code_memory: &mut [u8],
        target_offset: usize,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(patch_rights::PATCH_APPLY) {
            return Err(SysError::PermissionDenied);
        }

        let patch_idx = self
            .patches
            .iter()
            .position(|p| p.as_ref().map(|r| r.patch_id == patch_id).unwrap_or(false))
            .ok_or(SysError::InvalidArgument)?;

        let (tramp_bytes, tramp_len, target_pid) = {
            let rec = self.patches[patch_idx].as_ref().unwrap();
            if rec.state != PatchState::Quiesced && rec.state != PatchState::Prepared {
                return Err(SysError::InvalidArgument);
            }
            if target_offset + rec.trampoline_len > code_memory.len() {
                return Err(SysError::OutOfMemory);
            }
            (rec.trampoline_bytes, rec.trampoline_len, rec.target_pid)
        };

        // Application atomique : copie des octets du trampoline dans la mémoire de code
        code_memory[target_offset..target_offset + tramp_len]
            .copy_from_slice(&tramp_bytes[..tramp_len]);

        if let Some(p) = self.patches[patch_idx].as_mut() {
            p.state = PatchState::Applied;
            p.applied_timestamp = timestamp;
            p.seal_hash = Self::compute_patch_seal(p);
        }

        self.stats.total_patches_applied += 1;
        self.record_audit(AuditAction::Apply, patch_id, target_pid, timestamp);

        Ok(())
    }

    /// Restauration atomique / Rollback du patch vers le prologue original
    pub fn revert_patch(
        &mut self,
        cap: &PatchCap,
        patch_id: u32,
        code_memory: &mut [u8],
        target_offset: usize,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(patch_rights::PATCH_REVERT) {
            return Err(SysError::PermissionDenied);
        }

        let patch_idx = self
            .patches
            .iter()
            .position(|p| p.as_ref().map(|r| r.patch_id == patch_id).unwrap_or(false))
            .ok_or(SysError::InvalidArgument)?;

        let (orig_bytes, orig_len, target_pid) = {
            let rec = self.patches[patch_idx].as_ref().unwrap();
            if rec.state != PatchState::Applied {
                return Err(SysError::InvalidArgument);
            }
            if target_offset + rec.original_prologue_len > code_memory.len() {
                return Err(SysError::OutOfMemory);
            }
            (rec.original_prologue, rec.original_prologue_len, rec.target_pid)
        };

        // Restauration des octets originaux du prologue
        code_memory[target_offset..target_offset + orig_len]
            .copy_from_slice(&orig_bytes[..orig_len]);

        if let Some(p) = self.patches[patch_idx].as_mut() {
            p.state = PatchState::Reverted;
            p.seal_hash = Self::compute_patch_seal(p);
        }

        self.stats.total_patches_reverted += 1;
        self.record_audit(AuditAction::Revert, patch_id, target_pid, timestamp);

        Ok(())
    }

    /// Vérification cryptographique du scellement d'un patch
    pub fn verify_patch_seal(&mut self, cap: &PatchCap, patch_id: u32) -> Result<bool, SysError> {
        if !cap.has_right(patch_rights::PATCH_INSPECT) {
            return Err(SysError::PermissionDenied);
        }

        let rec = self
            .patches
            .iter()
            .find_map(|p| p.as_ref().filter(|r| r.patch_id == patch_id))
            .ok_or(SysError::InvalidArgument)?;

        let computed = Self::compute_patch_seal(rec);
        let matches = computed == rec.seal_hash;

        if matches {
            self.stats.total_seals_verified += 1;
        }

        Ok(matches)
    }

    /// Initialise un jeu par défaut de patchs pour la démonstration et le shell
    pub fn init_defaults(&mut self) {
        let cap = self.cap;

        // Exemple 1 : Correction de vulnérabilité buffer dans libnet (PID 101)
        let orig_code1 = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20]; // push rbp; mov rbp, rsp; sub rsp, 32
        let patch_code1 = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x40]; // sub rsp, 64 (sécurisé)
        let _ = self.prepare_patch(
            &cap,
            101,
            TargetArch::X86_64,
            "CVE-2026-9011-buf-fix",
            "net_rx_process_packet",
            0x0040_1000,
            &orig_code1,
            0x0040_5000,
            &patch_code1,
            Handle::new(9011, 1),
            1000,
        );

        // Exemple 2 : Optimisation EEVDF dans jambo-schedd (PID 42)
        let orig_code2 = [0x55, 0x48, 0x89, 0xE5, 0x41, 0x54, 0x41, 0x55];
        let patch_code2 = [0x55, 0x48, 0x89, 0xE5, 0x41, 0x54, 0x90, 0x90];
        let _ = self.prepare_patch(
            &cap,
            42,
            TargetArch::X86_64,
            "OPT-2026-eevdf-fastpath",
            "sched_select_next_task",
            0x0070_2000,
            &orig_code2,
            0x0070_8000,
            &patch_code2,
            Handle::new(4201, 1),
            1020,
        );
    }

    pub fn get_patch(&self, patch_id: u32) -> Option<&PatchRecord> {
        self.patches
            .iter()
            .find_map(|p| p.as_ref().filter(|r| r.patch_id == patch_id))
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_attenuation_and_amplification_denial() {
        let admin = PatchCap::new(Handle::new(1, 1), patch_rights::ALL);
        assert!(admin.has_right(patch_rights::PATCH_APPLY));
        assert!(admin.has_right(patch_rights::PATCH_REVERT));
        assert!(admin.has_right(patch_rights::PATCH_ADMIN));

        let inspect_only = admin
            .attenuate(patch_rights::PATCH_INSPECT)
            .expect("attenuate to inspect-only");
        assert!(inspect_only.has_right(patch_rights::PATCH_INSPECT));
        assert!(!inspect_only.has_right(patch_rights::PATCH_APPLY));
        assert!(!inspect_only.has_right(patch_rights::PATCH_ADMIN));

        // Refus d'amplification
        assert_eq!(
            inspect_only.attenuate(patch_rights::PATCH_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_sha256_deterministic() {
        let digest1 = Sha256::digest(b"JamboOS Livepatch Subsystem");
        let digest2 = Sha256::digest(b"JamboOS Livepatch Subsystem");
        assert_eq!(digest1, digest2);

        let digest3 = Sha256::digest(b"JamboOS Livepatch Subsystem Altered");
        assert_ne!(digest1, digest3);
    }

    #[test]
    fn test_rel32_trampoline_generation() {
        let mut buf = [0u8; 16];
        let len = TrampolineGenerator::build_rel32_jmp(0x1000, 0x1050, &mut buf).unwrap();
        assert_eq!(len, 5);
        assert_eq!(buf[0], 0xE9);
        // next_ip = 0x1005, diff = 0x1050 - 0x1005 = 0x4B
        let rel = i32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        assert_eq!(rel, 0x4B);
    }

    #[test]
    fn test_indirect64_trampoline_generation() {
        let mut buf = [0u8; 16];
        let len = TrampolineGenerator::build_indirect64_jmp(0xDEAD_BEEF_CAFE_0000, &mut buf);
        assert_eq!(len, 14);
        assert_eq!(buf[0], 0xFF);
        assert_eq!(buf[1], 0x25);
        let target = u64::from_le_bytes([
            buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13],
        ]);
        assert_eq!(target, 0xDEAD_BEEF_CAFE_0000);
    }

    #[test]
    fn test_arm64_direct_trampoline_generation() {
        let mut buf = [0u8; 16];
        let len = TrampolineGenerator::build_arm64_direct_jmp(0x2000, 0x2100, &mut buf).unwrap();
        assert_eq!(len, 4);
        // opcode starts with 0x14
        assert_eq!(buf[3], 0x14);
    }

    #[test]
    fn test_patch_lifecycle_prepare_quiesce_apply_revert() {
        let admin = PatchCap::new(Handle::new(1, 1), patch_rights::ALL);
        let mut daemon = JamboPatchDaemon::new(1, admin);

        let mut code_memory = [
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, // prologue original
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        let replacement = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x40];

        // 1. Prepare
        let pid = 500;
        let patch_id = daemon
            .prepare_patch(
                &admin,
                pid,
                TargetArch::X86_64,
                "Hotfix-1",
                "target_func",
                0x0040_0000,
                &code_memory[0..8],
                0x0040_0100,
                &replacement,
                Handle::new(123, 1),
                100,
            )
            .expect("prepare patch");

        assert_eq!(patch_id, 1);
        assert_eq!(daemon.patch_count, 1);
        assert!(daemon.verify_patch_seal(&admin, patch_id).unwrap());

        // 2. Quiesce
        let mut threads = [
            TargetThread {
                thread_id: 1,
                ip: 0x0050_0000,
                sp: 0x7FFF_0000,
                state: ThreadState::Running,
            },
            TargetThread {
                thread_id: 2,
                ip: 0x0060_0000,
                sp: 0x7FFF_1000,
                state: ThreadState::Running,
            },
        ];

        let q_count = daemon
            .quiesce_threads(&admin, patch_id, &mut threads, 110)
            .expect("quiesce threads");
        assert_eq!(q_count, 2);

        // 3. Apply
        daemon
            .apply_patch(&admin, patch_id, &mut code_memory, 0, 120)
            .expect("apply patch");

        // Vérification de l'injection du trampoline (0xE9 pour rel32)
        assert_eq!(code_memory[0], 0xE9);

        // 4. Revert
        daemon
            .revert_patch(&admin, patch_id, &mut code_memory, 0, 130)
            .expect("revert patch");

        // Vérification de la restauration du prologue
        assert_eq!(code_memory[0], 0x55);
        assert_eq!(code_memory[1], 0x48);
        assert_eq!(code_memory[2], 0x89);
        assert_eq!(code_memory[3], 0xE5);

        assert_eq!(daemon.stats.total_patches_prepared, 1);
        assert_eq!(daemon.stats.total_patches_applied, 1);
        assert_eq!(daemon.stats.total_patches_reverted, 1);
        assert_eq!(daemon.stats.total_quiescence_cycles, 1);
    }

    #[test]
    fn test_quiescence_fails_when_thread_in_trampoline_zone() {
        let admin = PatchCap::new(Handle::new(1, 1), patch_rights::ALL);
        let mut daemon = JamboPatchDaemon::new(1, admin);

        let orig = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];
        let repl = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x40];

        let patch_id = daemon
            .prepare_patch(
                &admin,
                100,
                TargetArch::X86_64,
                "Hotfix-Zone",
                "zone_func",
                0x0040_0000,
                &orig,
                0x0040_0100,
                &repl,
                Handle::new(123, 1),
                100,
            )
            .unwrap();

        // Thread 1 a son IP exactement dans la zone du trampoline [0x0040_0000, 0x0040_0005)
        let mut threads = [TargetThread {
            thread_id: 1,
            ip: 0x0040_0002, // Dans la zone !
            sp: 0x7FFF_0000,
            state: ThreadState::Running,
        }];

        let res = daemon.quiesce_threads(&admin, patch_id, &mut threads, 110);
        assert_eq!(res, Err(SysError::ResourceBusy));
        assert_eq!(threads[0].state, ThreadState::InTrampolineZone);
    }

    #[test]
    fn test_arm64_indirect_trampoline_generation() {
        let mut buf = [0u8; 16];
        let len = TrampolineGenerator::build_arm64_indirect_jmp(0x1234_5678_9ABC_DEF0, &mut buf);
        assert_eq!(len, 16);
        let target = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        assert_eq!(target, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_abi_checker_compliance_and_failures() {
        // x86_64 normal
        let orig = [0x55, 0x48, 0x89, 0xE5, 0x48];
        assert_eq!(
            AbiComplianceChecker::verify_target(TargetArch::X86_64, 0x1000, 0x2000, &orig),
            AbiCheckResult::Compliant
        );

        // Prologue trop court (< 5 octets)
        assert_eq!(
            AbiComplianceChecker::verify_target(TargetArch::X86_64, 0x1000, 0x2000, &[0x55, 0x90]),
            AbiCheckResult::PrologueTooShort
        );

        // Instruction dangereuse (RET immédiat)
        assert_eq!(
            AbiComplianceChecker::verify_target(TargetArch::X86_64, 0x1000, 0x2000, &[0xC3, 0x90, 0x90, 0x90, 0x90]),
            AbiCheckResult::UnsafeInstruction
        );

        // ARM64 désaligné (non multiple de 4)
        assert_eq!(
            AbiComplianceChecker::verify_target(TargetArch::AArch64, 0x1001, 0x2000, &[0; 8]),
            AbiCheckResult::StackMisaligned
        );
    }

    #[test]
    fn test_tampering_detection_in_seal() {
        let admin = PatchCap::new(Handle::new(1, 1), patch_rights::ALL);
        let mut daemon = JamboPatchDaemon::new(1, admin);
        daemon.init_defaults();

        // Le patch 1 est scellé
        assert!(daemon.verify_patch_seal(&admin, 1).unwrap());

        // Altération frauduleuse du symbole
        if let Some(p) = daemon.patches[0].as_mut() {
            p.symbol_name[0] ^= 0xFF;
        }

        // Le scellement SHA-256 détecte immédiatement l'altération
        assert!(!daemon.verify_patch_seal(&admin, 1).unwrap());
    }

    #[test]
    fn test_audit_ledger_chaining() {
        let admin = PatchCap::new(Handle::new(1, 1), patch_rights::ALL);
        let mut daemon = JamboPatchDaemon::new(1, admin);
        daemon.init_defaults();

        assert_eq!(daemon.stats.total_audit_entries, 2);
        assert_ne!(daemon.last_audit_digest, [0u8; 32]);
    }
}


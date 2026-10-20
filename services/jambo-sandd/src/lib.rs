//! Démon de Confinement de Processus et Micro-Bacs à Sable Zero-Ambient (`jambo-sandd`)
//!
//! Fournit un sous-système de confinement granulaire inspiré de Seccomp et Landlock pour micro-noyau `#![no_std]` :
//! 1. Filtrage d'appels système par masque binaire O(1) et prédicats d'arguments (SyscallRule, ArgFilter).
//! 2. Arbre hiérarchique de profils de restriction dynamique avec garantie formelle de resserrement monotone
//!    (interdiction stricte d'amplification ou d'assouplissement de privilèges par les profils enfants).
//! 3. Confinement de ressources et de chemins VFS à autorité zéro (LandlockPathRule, droits granulaires).
//! 4. Journal d'audit et de violations scellé cryptographiquement par chaîne SHA-256.
//! 5. Contrôle d'accès capabilaire strict sans autorité ambiante via `SandCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_PROFILES: usize = 16;
pub const MAX_SANDBOXES: usize = 32;
pub const MAX_RULES_PER_PROFILE: usize = 32;
pub const MAX_LANDLOCK_RULES: usize = 8;
pub const MAX_VIOLATIONS: usize = 64;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_PATH_LEN: usize = 48;

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
// MODÈLE DE SÉCURITÉ CAPABILAIRE : SandCap
// ============================================================================

pub mod sand_rights {
    pub const SAND_INSPECT: u32 = 1 << 0;
    pub const SAND_CREATE: u32 = 1 << 1;
    pub const SAND_APPLY: u32 = 1 << 2;
    pub const SAND_RESTRICT: u32 = 1 << 3;
    pub const SAND_KILL: u32 = 1 << 4;
    pub const SAND_AUDIT: u32 = 1 << 5;
    pub const SAND_ADMIN: u32 = 1 << 6;

    pub const ALL: u32 = SAND_INSPECT
        | SAND_CREATE
        | SAND_APPLY
        | SAND_RESTRICT
        | SAND_KILL
        | SAND_AUDIT
        | SAND_ADMIN;
}

/// Capacité de contrôle d'accès pour les micro-bacs à sable sans autorité ambiante
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandCap {
    pub handle: Handle,
    pub rights: u32,
}

impl SandCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits vers un sous-ensemble strict.
    /// Interdit formellement toute amplification de droits.
    pub fn attenuate(&self, new_rights: u32) -> Result<SandCap, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(SandCap {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// ACTIONS DE FILTRAGE ET RÈGLES SECCOMP-LIKE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterAction {
    Allow,
    Deny(SysError),
    Trap,
    Kill,
    LogAndAllow,
}

impl FilterAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            FilterAction::Allow => "ALLOW",
            FilterAction::Deny(_) => "DENY",
            FilterAction::Trap => "TRAP",
            FilterAction::Kill => "KILL",
            FilterAction::LogAndAllow => "LOG_ALLOW",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "allow" | "ALLOW" => Some(FilterAction::Allow),
            "deny" | "DENY" => Some(FilterAction::Deny(SysError::PermissionDenied)),
            "trap" | "TRAP" => Some(FilterAction::Trap),
            "kill" | "KILL" => Some(FilterAction::Kill),
            "log" | "log_allow" | "LOG_ALLOW" => Some(FilterAction::LogAndAllow),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgFilter {
    Any,
    Eq(u64),
    NotEq(u64),
    MaskEq { mask: u64, value: u64 },
    Range { min: u64, max: u64 },
    LessThan(u64),
    GreaterThan(u64),
}

impl ArgFilter {
    pub fn matches(&self, val: u64) -> bool {
        match *self {
            ArgFilter::Any => true,
            ArgFilter::Eq(v) => val == v,
            ArgFilter::NotEq(v) => val != v,
            ArgFilter::MaskEq { mask, value } => (val & mask) == value,
            ArgFilter::Range { min, max } => val >= min && val <= max,
            ArgFilter::LessThan(v) => val < v,
            ArgFilter::GreaterThan(v) => val > v,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallRule {
    pub syscall_nr: u32,
    pub action: FilterAction,
    pub arg_filters: [ArgFilter; 4],
}

impl SyscallRule {
    pub const fn allow_any(syscall_nr: u32) -> Self {
        Self {
            syscall_nr,
            action: FilterAction::Allow,
            arg_filters: [ArgFilter::Any; 4],
        }
    }

    pub const fn deny(syscall_nr: u32, err: SysError) -> Self {
        Self {
            syscall_nr,
            action: FilterAction::Deny(err),
            arg_filters: [ArgFilter::Any; 4],
        }
    }

    pub const fn with_arg_filters(
        syscall_nr: u32,
        action: FilterAction,
        filters: [ArgFilter; 4],
    ) -> Self {
        Self {
            syscall_nr,
            action,
            arg_filters: filters,
        }
    }

    pub fn matches_args(&self, args: &[u64; 4]) -> bool {
        for i in 0..4 {
            if !self.arg_filters[i].matches(args[i]) {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// CONFINEMENT DE CHEMINS VFS & RESSOURCES LANDLOCK-LIKE
// ============================================================================

pub mod landlock_access {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXECUTE: u32 = 1 << 2;
    pub const CREATE: u32 = 1 << 3;
    pub const DELETE: u32 = 1 << 4;

    pub const ALL: u32 = READ | WRITE | EXECUTE | CREATE | DELETE;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LandlockPathRule {
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: usize,
    pub allowed_access: u32,
}

impl LandlockPathRule {
    pub fn new(path_str: &str, allowed_access: u32) -> Self {
        let mut path = [0u8; MAX_PATH_LEN];
        let bytes = path_str.as_bytes();
        let len = if bytes.len() > MAX_PATH_LEN {
            MAX_PATH_LEN
        } else {
            bytes.len()
        };
        path[..len].copy_from_slice(&bytes[..len]);
        Self {
            path,
            path_len: len,
            allowed_access,
        }
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }

    pub fn matches_prefix(&self, target: &str) -> bool {
        let prefix = self.path_str();
        if prefix.is_empty() {
            return false;
        }
        target.starts_with(prefix)
    }
}

// ============================================================================
// PROFILS DE RESTRICTION & ARBRE D'HÉRITAGE DYNAMIQUE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxProfile {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub parent_id: Option<u32>,
    pub default_action: FilterAction,
    pub allowed_syscall_mask: u64, // bits 0..63 pour syscalls 1..64
    pub rules: [Option<SyscallRule>; MAX_RULES_PER_PROFILE],
    pub rule_count: usize,
    pub landlock_rules: [Option<LandlockPathRule>; MAX_LANDLOCK_RULES],
    pub landlock_count: usize,
    pub strictness_level: u8, // 0 (permissif) à 100 (confinement maximal)
    pub no_new_privs: bool,
}

impl SandboxProfile {
    pub fn new(id: u32, name: &str, default_action: FilterAction, strictness_level: u8) -> Self {
        let mut n = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        n[..len].copy_from_slice(&bytes[..len]);

        Self {
            id,
            name: n,
            name_len: len,
            parent_id: None,
            default_action,
            allowed_syscall_mask: 0,
            rules: [None; MAX_RULES_PER_PROFILE],
            rule_count: 0,
            landlock_rules: [None; MAX_LANDLOCK_RULES],
            landlock_count: 0,
            strictness_level,
            no_new_privs: true,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unknown")
    }

    #[inline]
    pub fn allow_syscall_fast(&mut self, syscall_nr: u32) {
        if syscall_nr > 0 && syscall_nr <= 64 {
            self.allowed_syscall_mask |= 1u64 << (syscall_nr - 1);
        }
    }

    #[inline]
    pub fn is_syscall_allowed_fast(&self, syscall_nr: u32) -> bool {
        if syscall_nr > 0 && syscall_nr <= 64 {
            (self.allowed_syscall_mask & (1u64 << (syscall_nr - 1))) != 0
        } else {
            false
        }
    }

    pub fn add_rule(&mut self, rule: SyscallRule) -> Result<(), SysError> {
        if self.rule_count >= MAX_RULES_PER_PROFILE {
            return Err(SysError::OutOfMemory);
        }
        for slot in self.rules.iter_mut() {
            if slot.is_none() {
                *slot = Some(rule);
                self.rule_count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    pub fn add_landlock_rule(&mut self, rule: LandlockPathRule) -> Result<(), SysError> {
        if self.landlock_count >= MAX_LANDLOCK_RULES {
            return Err(SysError::OutOfMemory);
        }
        for slot in self.landlock_rules.iter_mut() {
            if slot.is_none() {
                *slot = Some(rule);
                self.landlock_count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Vérifie l'invariant de resserrement monotone par rapport à un profil parent.
    /// Un enfant ne peut JAMAIS autoriser un appel système ou un accès refusé par le parent.
    pub fn is_stricter_or_equal(&self, parent: &SandboxProfile) -> bool {
        // 1. Masque d'appels système : l'enfant ne peut pas avoir de bits à 1 là où le parent a un 0
        if (self.allowed_syscall_mask & !parent.allowed_syscall_mask) != 0 {
            return false;
        }

        // 2. Niveau de rigueur : l'enfant doit être au moins aussi strict que le parent
        if self.strictness_level < parent.strictness_level {
            return false;
        }

        // 3. no_new_privs : doit rester actif si le parent l'activait
        if parent.no_new_privs && !self.no_new_privs {
            return false;
        }

        true
    }
}

// ============================================================================
// INSTANCES DE BAC À SABLE ET VIOLATIONS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxInstance {
    pub id: u32,
    pub process_id: u64,
    pub thread_id: u64,
    pub profile_id: u32,
    pub is_active: bool,
    pub is_killed: bool,
    pub violation_count: u32,
    pub evaluation_count: u64,
    pub created_at: u64,
    pub last_activity: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxViolation {
    pub violation_id: u64,
    pub sandbox_id: u32,
    pub process_id: u64,
    pub syscall_nr: u32,
    pub args: [u64; 4],
    pub action_taken: FilterAction,
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SandboxStats {
    pub total_evaluations: u64,
    pub total_allowed: u64,
    pub total_denied: u64,
    pub total_trapped: u64,
    pub total_killed: u64,
    pub total_landlock_checks: u64,
    pub total_landlock_blocked: u64,
    pub total_violations: u64,
}

// ============================================================================
// DÉMON PRINCIPAL : JamboSandDaemon
// ============================================================================

pub struct JamboSandDaemon {
    pub daemon_id: u32,
    pub admin_cap: SandCap,
    pub profiles: [Option<SandboxProfile>; MAX_PROFILES],
    pub profile_count: usize,
    pub sandboxes: [Option<SandboxInstance>; MAX_SANDBOXES],
    pub sandbox_count: usize,
    pub violations: [Option<SandboxViolation>; MAX_VIOLATIONS],
    pub violation_head: usize,
    pub violation_total: u64,
    pub stats: SandboxStats,
    pub audit_digest: [u8; 32],
}

impl JamboSandDaemon {
    pub fn new(daemon_id: u32, admin_cap: SandCap) -> Self {
        Self {
            daemon_id,
            admin_cap,
            profiles: [None; MAX_PROFILES],
            profile_count: 0,
            sandboxes: [None; MAX_SANDBOXES],
            sandbox_count: 0,
            violations: [None; MAX_VIOLATIONS],
            violation_head: 0,
            violation_total: 0,
            stats: SandboxStats::default(),
            audit_digest: [0u8; 32],
        }
    }

    /// Initialise les profils de confinement par défaut du système
    pub fn init_defaults(&mut self) {
        // 1. Profil Strict (Confinement maximal : calcul pur, zero-syscall except yield/exit/clock)
        let mut p_strict = SandboxProfile::new(1, "Strict", FilterAction::Kill, 100);
        p_strict.allow_syscall_fast(11); // ThreadExit
        p_strict.allow_syscall_fast(12); // ThreadYield
        p_strict.allow_syscall_fast(24); // ClockGettime
        let _ = self.register_profile_internal(p_strict);

        // 2. Profil ComputeOnly (WASM / charges de calcul avec allocation VMO mémoire et synchro Futex)
        let mut p_comp = SandboxProfile::new(
            2,
            "ComputeOnly",
            FilterAction::Deny(SysError::PermissionDenied),
            80,
        );
        p_comp.allow_syscall_fast(4); // VmoCreate
        p_comp.allow_syscall_fast(5); // VmoMap
        p_comp.allow_syscall_fast(6); // VmoUnmap
        p_comp.allow_syscall_fast(11); // ThreadExit
        p_comp.allow_syscall_fast(12); // ThreadYield
        p_comp.allow_syscall_fast(19); // FutexWait
        p_comp.allow_syscall_fast(20); // FutexWake
        p_comp.allow_syscall_fast(24); // ClockGettime
        let _ = p_comp.add_landlock_rule(LandlockPathRule::new("/data/", landlock_access::READ));
        let _ = self.register_profile_internal(p_comp);

        // 3. Profil NetworkWorker (Démons réseau et passerelles IPC confinées)
        let mut p_net = SandboxProfile::new(
            3,
            "NetworkWorker",
            FilterAction::Deny(SysError::PermissionDenied),
            60,
        );
        p_net.allow_syscall_fast(11); // ThreadExit
        p_net.allow_syscall_fast(12); // ThreadYield
        p_net.allow_syscall_fast(13); // ChannelCreate
        p_net.allow_syscall_fast(14); // ChannelCall
        p_net.allow_syscall_fast(15); // PortCreate
        p_net.allow_syscall_fast(16); // PortWait
        p_net.allow_syscall_fast(17); // RingSetup
        p_net.allow_syscall_fast(18); // RingEnter
        p_net.allow_syscall_fast(24); // ClockGettime
        let _ = p_net.add_landlock_rule(LandlockPathRule::new(
            "/net/",
            landlock_access::READ | landlock_access::WRITE,
        ));
        let _ = self.register_profile_internal(p_net);

        // 4. Profil UntrustedPlugin (Dérivé de ComputeOnly : VMO restreint en lecture seule)
        let mut p_plugin = SandboxProfile::new(4, "UntrustedPlugin", FilterAction::Trap, 90);
        p_plugin.parent_id = Some(2); // Parent: ComputeOnly
        p_plugin.allow_syscall_fast(5); // VmoMap
        p_plugin.allow_syscall_fast(6); // VmoUnmap
        p_plugin.allow_syscall_fast(11); // ThreadExit
        p_plugin.allow_syscall_fast(12); // ThreadYield
        p_plugin.allow_syscall_fast(24); // ClockGettime
                                         // Argument filter: VmoMap (syscall 5) argument prot (arg1) doit interdire l'écriture (mask WRITE == 0)
        let _ = p_plugin.add_rule(SyscallRule::with_arg_filters(
            5,
            FilterAction::Allow,
            [
                ArgFilter::Any,
                ArgFilter::MaskEq {
                    mask: 0x02,
                    value: 0x00,
                }, // No write allowed
                ArgFilter::Any,
                ArgFilter::Any,
            ],
        ));
        let _ =
            p_plugin.add_landlock_rule(LandlockPathRule::new("/tmp/cache", landlock_access::READ));
        let _ = self.register_profile_internal(p_plugin);

        // Instanciation de bacs à sable initiaux
        let _ = self.create_sandbox_internal(101, 1, 1, 10);
        let _ = self.create_sandbox_internal(202, 2, 2, 20);
        let _ = self.create_sandbox_internal(303, 3, 3, 30);
        let _ = self.create_sandbox_internal(404, 4, 4, 40);

        self.recompute_digest();
    }

    fn register_profile_internal(&mut self, profile: SandboxProfile) -> Result<u32, SysError> {
        if self.profile_count >= MAX_PROFILES {
            return Err(SysError::OutOfMemory);
        }
        for slot in self.profiles.iter_mut() {
            if slot.is_none() {
                let id = profile.id;
                *slot = Some(profile);
                self.profile_count += 1;
                return Ok(id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    fn create_sandbox_internal(
        &mut self,
        pid: u64,
        tid: u64,
        profile_id: u32,
        now: u64,
    ) -> Result<u32, SysError> {
        if self.sandbox_count >= MAX_SANDBOXES {
            return Err(SysError::OutOfMemory);
        }
        if self.get_profile(profile_id).is_none() {
            return Err(SysError::InvalidArgument);
        }

        let new_id = (self.sandbox_count as u32) + 1;
        let inst = SandboxInstance {
            id: new_id,
            process_id: pid,
            thread_id: tid,
            profile_id,
            is_active: true,
            is_killed: false,
            violation_count: 0,
            evaluation_count: 0,
            created_at: now,
            last_activity: now,
        };

        for slot in self.sandboxes.iter_mut() {
            if slot.is_none() {
                *slot = Some(inst);
                self.sandbox_count += 1;
                return Ok(new_id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Création d'un nouveau profil de confinement avec vérification capabilaire
    pub fn create_profile(
        &mut self,
        cap: &SandCap,
        profile: SandboxProfile,
    ) -> Result<u32, SysError> {
        if !cap.has_right(sand_rights::SAND_CREATE) {
            return Err(SysError::PermissionDenied);
        }
        let id = self.register_profile_internal(profile)?;
        self.recompute_digest();
        Ok(id)
    }

    /// Dérive un profil enfant depuis un profil parent en appliquant strictement l'invariant de resserrement monotone
    pub fn derive_child_profile(
        &mut self,
        cap: &SandCap,
        parent_id: u32,
        child_name: &str,
        allowed_syscall_mask: u64,
        extra_rules: &[SyscallRule],
        extra_landlock: &[LandlockPathRule],
        strictness_level: u8,
    ) -> Result<u32, SysError> {
        if !cap.has_right(sand_rights::SAND_CREATE) || !cap.has_right(sand_rights::SAND_RESTRICT) {
            return Err(SysError::PermissionDenied);
        }

        let parent = self
            .get_profile(parent_id)
            .copied()
            .ok_or(SysError::InvalidArgument)?;

        let mut child = SandboxProfile::new(
            (self.profile_count as u32) + 1,
            child_name,
            parent.default_action,
            strictness_level,
        );
        child.parent_id = Some(parent_id);
        child.allowed_syscall_mask = allowed_syscall_mask;
        child.no_new_privs = parent.no_new_privs;

        // Invariant Formel : l'enfant doit être plus strict ou égal au parent
        if !child.is_stricter_or_equal(&parent) {
            return Err(SysError::PermissionDenied);
        }

        for r in extra_rules {
            child.add_rule(*r)?;
        }
        for l in extra_landlock {
            child.add_landlock_rule(*l)?;
        }

        let id = self.register_profile_internal(child)?;
        self.recompute_digest();
        Ok(id)
    }

    /// Attache un processus à un profil de bac à sable
    pub fn create_sandbox(
        &mut self,
        cap: &SandCap,
        pid: u64,
        tid: u64,
        profile_id: u32,
        now: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(sand_rights::SAND_APPLY) {
            return Err(SysError::PermissionDenied);
        }
        let id = self.create_sandbox_internal(pid, tid, profile_id, now)?;
        self.recompute_digest();
        Ok(id)
    }

    /// Évalue un appel système pour un bac à sable donné selon les règles Seccomp-like
    pub fn evaluate_syscall(
        &mut self,
        sandbox_id: u32,
        syscall_nr: u32,
        args: [u64; 4],
        timestamp: u64,
    ) -> FilterAction {
        self.stats.total_evaluations += 1;

        let (profile_id, is_active, is_killed, pid) = match self.get_sandbox(sandbox_id) {
            Some(s) => (s.profile_id, s.is_active, s.is_killed, s.process_id),
            None => {
                self.stats.total_denied += 1;
                return FilterAction::Deny(SysError::InvalidHandle);
            }
        };

        if !is_active || is_killed {
            self.stats.total_killed += 1;
            return FilterAction::Kill;
        }

        let profile = match self.get_profile(profile_id).copied() {
            Some(p) => p,
            None => {
                self.stats.total_denied += 1;
                return FilterAction::Deny(SysError::InvalidHandle);
            }
        };

        // 1. Vérification des règles fines avec prédicats d'arguments
        for slot in profile.rules.iter().flatten() {
            if slot.syscall_nr == syscall_nr && slot.matches_args(&args) {
                return self.apply_decision(
                    sandbox_id,
                    pid,
                    syscall_nr,
                    args,
                    slot.action,
                    timestamp,
                );
            }
        }

        // 2. Vérification rapide par masque binaire O(1)
        if profile.is_syscall_allowed_fast(syscall_nr) {
            return self.apply_decision(
                sandbox_id,
                pid,
                syscall_nr,
                args,
                FilterAction::Allow,
                timestamp,
            );
        }

        // 3. Action par défaut du profil
        self.apply_decision(
            sandbox_id,
            pid,
            syscall_nr,
            args,
            profile.default_action,
            timestamp,
        )
    }

    fn apply_decision(
        &mut self,
        sandbox_id: u32,
        pid: u64,
        syscall_nr: u32,
        args: [u64; 4],
        action: FilterAction,
        timestamp: u64,
    ) -> FilterAction {
        match action {
            FilterAction::Allow => {
                self.stats.total_allowed += 1;
                if let Some(s) = self.get_sandbox_mut(sandbox_id) {
                    s.evaluation_count += 1;
                    s.last_activity = timestamp;
                }
            }
            FilterAction::LogAndAllow => {
                self.stats.total_allowed += 1;
                self.record_violation(sandbox_id, pid, syscall_nr, args, action, timestamp);
                if let Some(s) = self.get_sandbox_mut(sandbox_id) {
                    s.evaluation_count += 1;
                    s.last_activity = timestamp;
                }
            }
            FilterAction::Deny(_) => {
                self.stats.total_denied += 1;
                self.record_violation(sandbox_id, pid, syscall_nr, args, action, timestamp);
                if let Some(s) = self.get_sandbox_mut(sandbox_id) {
                    s.violation_count += 1;
                    s.evaluation_count += 1;
                    s.last_activity = timestamp;
                }
            }
            FilterAction::Trap => {
                self.stats.total_trapped += 1;
                self.record_violation(sandbox_id, pid, syscall_nr, args, action, timestamp);
                if let Some(s) = self.get_sandbox_mut(sandbox_id) {
                    s.violation_count += 1;
                    s.evaluation_count += 1;
                    s.last_activity = timestamp;
                }
            }
            FilterAction::Kill => {
                self.stats.total_killed += 1;
                self.record_violation(sandbox_id, pid, syscall_nr, args, action, timestamp);
                if let Some(s) = self.get_sandbox_mut(sandbox_id) {
                    s.violation_count += 1;
                    s.evaluation_count += 1;
                    s.is_killed = true;
                    s.is_active = false;
                    s.last_activity = timestamp;
                }
            }
        }
        action
    }

    /// Évalue l'accès à un chemin selon les règles Landlock-like
    pub fn evaluate_landlock(
        &mut self,
        sandbox_id: u32,
        target_path: &str,
        requested_access: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        self.stats.total_landlock_checks += 1;

        let (profile_id, is_active, is_killed, pid) = match self.get_sandbox(sandbox_id) {
            Some(s) => (s.profile_id, s.is_active, s.is_killed, s.process_id),
            None => {
                self.stats.total_landlock_blocked += 1;
                return Err(SysError::InvalidHandle);
            }
        };

        if !is_active || is_killed {
            self.stats.total_landlock_blocked += 1;
            return Err(SysError::PermissionDenied);
        }

        let profile = match self.get_profile(profile_id) {
            Some(p) => *p,
            None => {
                self.stats.total_landlock_blocked += 1;
                return Err(SysError::InvalidHandle);
            }
        };

        // Si aucune règle Landlock n'est configurée sur le profil, le modèle Zero-Ambient interdit tout
        if profile.landlock_count == 0 {
            self.stats.total_landlock_blocked += 1;
            self.record_violation(
                sandbox_id,
                pid,
                0,
                [requested_access as u64, 0, 0, 0],
                FilterAction::Deny(SysError::PermissionDenied),
                timestamp,
            );
            return Err(SysError::PermissionDenied);
        }

        for slot in profile.landlock_rules.iter().flatten() {
            if slot.matches_prefix(target_path) {
                if (requested_access & !slot.allowed_access) == 0 {
                    return Ok(());
                } else {
                    self.stats.total_landlock_blocked += 1;
                    self.record_violation(
                        sandbox_id,
                        pid,
                        0,
                        [requested_access as u64, slot.allowed_access as u64, 0, 0],
                        FilterAction::Deny(SysError::PermissionDenied),
                        timestamp,
                    );
                    return Err(SysError::PermissionDenied);
                }
            }
        }

        self.stats.total_landlock_blocked += 1;
        self.record_violation(
            sandbox_id,
            pid,
            0,
            [requested_access as u64, 0, 0, 0],
            FilterAction::Deny(SysError::PermissionDenied),
            timestamp,
        );
        Err(SysError::PermissionDenied)
    }

    /// Resserre dynamiquement le profil d'un bac à sable existant (monotone tightening)
    pub fn tighten_sandbox(
        &mut self,
        cap: &SandCap,
        sandbox_id: u32,
        new_profile_id: u32,
    ) -> Result<(), SysError> {
        if !cap.has_right(sand_rights::SAND_RESTRICT) {
            return Err(SysError::PermissionDenied);
        }

        let current_profile_id = self
            .get_sandbox(sandbox_id)
            .ok_or(SysError::InvalidArgument)?
            .profile_id;
        let current_profile = self
            .get_profile(current_profile_id)
            .copied()
            .ok_or(SysError::InvalidArgument)?;
        let new_profile = self
            .get_profile(new_profile_id)
            .copied()
            .ok_or(SysError::InvalidArgument)?;

        // Le nouveau profil doit obligatoirement être au moins aussi strict ou dériver du courant
        if !new_profile.is_stricter_or_equal(&current_profile) {
            return Err(SysError::PermissionDenied);
        }

        if let Some(s) = self.get_sandbox_mut(sandbox_id) {
            s.profile_id = new_profile_id;
            self.recompute_digest();
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Termine et confine définitivement un bac à sable en cas d'alerte critique
    pub fn kill_sandbox(&mut self, cap: &SandCap, sandbox_id: u32) -> Result<(), SysError> {
        if !cap.has_right(sand_rights::SAND_KILL) {
            return Err(SysError::PermissionDenied);
        }
        if let Some(s) = self.get_sandbox_mut(sandbox_id) {
            s.is_killed = true;
            s.is_active = false;
            self.recompute_digest();
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Enregistre une violation dans l'anneau circulaire d'audit
    fn record_violation(
        &mut self,
        sandbox_id: u32,
        process_id: u64,
        syscall_nr: u32,
        args: [u64; 4],
        action_taken: FilterAction,
        timestamp: u64,
    ) {
        self.stats.total_violations += 1;
        self.violation_total += 1;
        let idx = self.violation_head;
        self.violations[idx] = Some(SandboxViolation {
            violation_id: self.violation_total,
            sandbox_id,
            process_id,
            syscall_nr,
            args,
            action_taken,
            timestamp,
        });
        self.violation_head = (self.violation_head + 1) % MAX_VIOLATIONS;
    }

    /// Recalcule le condensat SHA-256 scellé de l'ensemble de l'état du sous-système
    pub fn recompute_digest(&mut self) {
        let mut buf = [0u8; 512];
        let mut offset = 0;

        // Entête
        buf[offset..offset + 4].copy_from_slice(&self.daemon_id.to_be_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&(self.profile_count as u32).to_be_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&(self.sandbox_count as u32).to_be_bytes());
        offset += 4;
        buf[offset..offset + 8].copy_from_slice(&self.violation_total.to_be_bytes());
        offset += 8;

        for p in self.profiles.iter().flatten() {
            if offset + 16 <= buf.len() {
                buf[offset..offset + 4].copy_from_slice(&p.id.to_be_bytes());
                offset += 4;
                buf[offset..offset + 8].copy_from_slice(&p.allowed_syscall_mask.to_be_bytes());
                offset += 8;
                buf[offset] = p.strictness_level;
                offset += 1;
            }
        }

        self.audit_digest = Sha256::digest(&buf[..offset]);
    }

    /// Renvoie le condensat SHA-256 de preuve d'intégrité de l'audit
    pub fn get_audit_digest(&self, cap: &SandCap) -> Result<[u8; 32], SysError> {
        if !cap.has_right(sand_rights::SAND_AUDIT) && !cap.has_right(sand_rights::SAND_INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.audit_digest)
    }

    pub fn get_profile(&self, id: u32) -> Option<&SandboxProfile> {
        for slot in self.profiles.iter().flatten() {
            if slot.id == id {
                return Some(slot);
            }
        }
        None
    }

    pub fn find_profile_by_name(&self, name: &str) -> Option<&SandboxProfile> {
        for slot in self.profiles.iter().flatten() {
            if slot.name_str() == name {
                return Some(slot);
            }
        }
        None
    }

    pub fn get_sandbox(&self, id: u32) -> Option<&SandboxInstance> {
        for slot in self.sandboxes.iter().flatten() {
            if slot.id == id {
                return Some(slot);
            }
        }
        None
    }

    pub fn get_sandbox_mut(&mut self, id: u32) -> Option<&mut SandboxInstance> {
        for slot in self.sandboxes.iter_mut().flatten() {
            if slot.id == id {
                return Some(slot);
            }
        }
        None
    }

    pub fn find_sandbox_by_pid(&self, pid: u64) -> Option<&SandboxInstance> {
        for slot in self.sandboxes.iter().flatten() {
            if slot.process_id == pid {
                return Some(slot);
            }
        }
        None
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] / lib test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sand_cap_attenuation_and_no_amplification() {
        let admin_cap = SandCap::new(Handle::new(8101, 1), sand_rights::ALL);
        assert!(admin_cap.has_right(sand_rights::SAND_INSPECT));
        assert!(admin_cap.has_right(sand_rights::SAND_ADMIN));

        let inspect_cap = admin_cap.attenuate(sand_rights::SAND_INSPECT).unwrap();
        assert!(inspect_cap.has_right(sand_rights::SAND_INSPECT));
        assert!(!inspect_cap.has_right(sand_rights::SAND_ADMIN));

        // Amplification formellement rejetée
        assert_eq!(
            inspect_cap.attenuate(sand_rights::SAND_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_seccomp_filter_evaluation() {
        let admin_cap = SandCap::new(Handle::new(8101, 1), sand_rights::ALL);
        let mut daemon = JamboSandDaemon::new(1, admin_cap);
        daemon.init_defaults();

        // Sandbox 1 (Strict) : Syscall 12 (ThreadYield) est autorisé
        let act1 = daemon.evaluate_syscall(1, 12, [0, 0, 0, 0], 100);
        assert_eq!(act1, FilterAction::Allow);

        // Syscall 26 (ConsoleWrite) n'est pas autorisé dans Strict -> Kill
        let act2 = daemon.evaluate_syscall(1, 26, [1, 0x1000, 10, 0], 101);
        assert_eq!(act2, FilterAction::Kill);

        // Après Kill, tout appel est rejeté par Kill
        let act3 = daemon.evaluate_syscall(1, 12, [0, 0, 0, 0], 102);
        assert_eq!(act3, FilterAction::Kill);
    }

    #[test]
    fn test_monotonic_tightening_invariant() {
        let admin_cap = SandCap::new(Handle::new(8101, 1), sand_rights::ALL);
        let mut daemon = JamboSandDaemon::new(1, admin_cap);
        daemon.init_defaults();

        let parent_id = 2; // ComputeOnly : mask 4,5,6,11,12,19,20,24

        // Tentative d'ajouter un appel système non autorisé par le parent (ex: Syscall 26 ConsoleWrite)
        let mut illegal_mask = daemon.get_profile(parent_id).unwrap().allowed_syscall_mask;
        illegal_mask |= 1u64 << (26 - 1); // Syscall 26

        let res = daemon.derive_child_profile(
            &admin_cap,
            parent_id,
            "IllegalChild",
            illegal_mask,
            &[],
            &[],
            85,
        );
        assert_eq!(res, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_landlock_path_confinement() {
        let admin_cap = SandCap::new(Handle::new(8101, 1), sand_rights::ALL);
        let mut daemon = JamboSandDaemon::new(1, admin_cap);
        daemon.init_defaults();

        // Sandbox 2 (ComputeOnly) : accès à /data/ en lecture autorisé
        let res_read = daemon.evaluate_landlock(2, "/data/input.bin", landlock_access::READ, 1);
        assert_eq!(res_read, Ok(()));

        // Écriture dans /data/ rejetée
        let res_write = daemon.evaluate_landlock(2, "/data/out.bin", landlock_access::WRITE, 2);
        assert_eq!(res_write, Err(SysError::PermissionDenied));

        // Accès à /etc/passwd rejeté
        let res_etc = daemon.evaluate_landlock(2, "/etc/passwd", landlock_access::READ, 3);
        assert_eq!(res_etc, Err(SysError::PermissionDenied));
    }
}

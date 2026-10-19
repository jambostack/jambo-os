//! Confinement de Sécurité du Système de Fichiers & Sandboxing Monotone (`jambo-landlock`)
//!
//! Fournit un sous-système de confinement d'accès aux fichiers et répertoires sans autorité ambiante
//! pour le micro-noyau souverain JamboOS (`#![no_std]`) :
//! 1. Élimination formelle de l'autorité ambiante : Règles d'arborescence VFS strictes ancrées sur des descripteurs
//!    de répertoires/fichiers (`PathBeneathRule`) et limitation granulaire des opérations FS (`LandlockAccessFs`).
//! 2. Empilement de couches de restriction monotones (`LandlockLayer` / `LandlockDomain`) :
//!    - Chaque appel à `restrict_self` empile une nouvelle couche de règles sur le domaine du processus.
//!    - Propriété d'intersection stricte : Une opération doit être autorisée par TOUTES les couches empilées.
//!    - Irréversibilité et monotonie formelle : L'ajout d'une couche ne peut que restreindre ou maintenir
//!      les permissions, sans aucune possibilité d'amplification ni de déconfinement ultérieur.
//! 3. Héritage automatique de confinement lors du clonage de tâches (`inherit_domain`).
//! 4. Contrôle capabilaire sans autorité ambiante (`LandlockCap`) avec atténuation stricte et rejet d'élévation.
//! 5. Registre d'audit cryptographique inviolable chaîné par hachage SHA-256 pur (`#![no_std]`).

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_PATH_LEN: usize = 64;
pub const MAX_RULES_PER_LAYER: usize = 16;
pub const MAX_LAYERS_PER_DOMAIN: usize = 8;
pub const MAX_RULESETS: usize = 32;
pub const MAX_DOMAINS: usize = 32;
pub const MAX_AUDIT_LOGS: usize = 64;
pub const MAX_NAME_LEN: usize = 32;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 pure `#![no_std]` sans allocation heap
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
    fn bsig0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn bsig1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn ssig0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn ssig1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn process_block(h: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for t in 0..16 {
            let offset = t * 4;
            w[t] = ((block[offset] as u32) << 24)
                | ((block[offset + 1] as u32) << 16)
                | ((block[offset + 2] as u32) << 8)
                | (block[offset + 3] as u32);
        }
        for t in 16..64 {
            w[t] = Self::ssig1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(Self::ssig0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for t in 0..64 {
            let t1 = hh
                .wrapping_add(Self::bsig1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[t])
                .wrapping_add(w[t]);
            let t2 = Self::bsig0(a).wrapping_add(Self::maj(a, b, c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    /// Calcule le haché SHA-256 d'un tampon d'octets
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let len = data.len();
        let mut offset = 0;
        let mut block = [0u8; 64];

        while offset + 64 <= len {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut h, &block);
            offset += 64;
        }

        let rem = len - offset;
        block[..rem].copy_from_slice(&data[offset..len]);
        block[rem] = 0x80;
        for i in (rem + 1)..64 {
            block[i] = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut h, &block);
            block = [0u8; 64];
        }

        let bit_len = (len as u64) * 8;
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut h, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// CONTRÔLE CAPABILAIRE SANS AUTORITÉ AMBIANTE (LandlockCap)
// ============================================================================

pub mod landlock_rights {
    pub const RULESET_CREATE: u32 = 1 << 0;
    pub const RULE_ADD: u32 = 1 << 1;
    pub const RESTRICT_SELF: u32 = 1 << 2;
    pub const AUDIT: u32 = 1 << 3;
    pub const ADMIN: u32 = 1 << 4;
    pub const ALL: u32 = RULESET_CREATE | RULE_ADD | RESTRICT_SELF | AUDIT | ADMIN;
}

/// Capacité de gouvernance du sous-système Landlock
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockCap {
    pub handle: Handle,
    pub rights: u32,
}

impl LandlockCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits de la capacité sans possibilité d'élévation
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
// MASQUES DE DROITS D'ACCÈS DU SYSTÈME DE FICHIERS (LandlockAccessFs)
// ============================================================================

pub mod fs_access {
    pub const EXECUTE: u32 = 1 << 0;
    pub const WRITE_FILE: u32 = 1 << 1;
    pub const READ_FILE: u32 = 1 << 2;
    pub const READ_DIR: u32 = 1 << 3;
    pub const REMOVE_DIR: u32 = 1 << 4;
    pub const REMOVE_FILE: u32 = 1 << 5;
    pub const MAKE_CHAR: u32 = 1 << 6;
    pub const MAKE_DIR: u32 = 1 << 7;
    pub const MAKE_REG: u32 = 1 << 8;
    pub const MAKE_SOCK: u32 = 1 << 9;
    pub const MAKE_FIFO: u32 = 1 << 10;
    pub const MAKE_BLOCK: u32 = 1 << 11;
    pub const MAKE_SYM: u32 = 1 << 12;
    pub const REFER: u32 = 1 << 13;
    pub const TRUNCATE: u32 = 1 << 14;

    /// Combinaison pour la lecture complète (fichiers + dossiers)
    pub const READ: u32 = READ_FILE | READ_DIR;

    /// Combinaison pour l'écriture et modifications de structure
    pub const WRITE: u32 = WRITE_FILE
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM
        | REFER
        | TRUNCATE;

    /// Combinaison pour l'exécution seule
    pub const EXEC: u32 = EXECUTE;

    /// Ensemble de tous les droits de système de fichiers gérés
    pub const ALL: u32 = (1 << 15) - 1;
}

/// Helper pour vérifier si un chemin cible est situé sous une ancre de répertoire
pub fn is_path_beneath(anchor: &str, target: &str) -> bool {
    if anchor == "/" {
        return target.starts_with('/');
    }
    if target == anchor {
        return true;
    }
    if target.starts_with(anchor) {
        let anchor_len = anchor.len();
        if anchor.ends_with('/') {
            return true;
        }
        if let Some(&b'/') = target.as_bytes().get(anchor_len) {
            return true;
        }
    }
    false
}

// ============================================================================
// STRUCTURES DE RÈGLES ET ENSEMBLES DE RÈGLES (LandlockRuleset)
// ============================================================================

/// Règle de portée sous-jacente (`path_beneath`) ancrée sur un descripteur VFS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathBeneathRule {
    pub parent_handle: Handle,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: usize,
    pub allowed_access: u32,
}

impl PathBeneathRule {
    pub fn new(parent_handle: Handle, path_str: &str, allowed_access: u32) -> Result<Self, SysError> {
        let bytes = path_str.as_bytes();
        if bytes.len() > MAX_PATH_LEN || bytes.is_empty() {
            return Err(SysError::InvalidArgument);
        }
        let mut path = [0u8; MAX_PATH_LEN];
        path[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            parent_handle,
            path,
            path_len: bytes.len(),
            allowed_access,
        })
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("/")
    }

    #[inline(always)]
    pub fn matches_path(&self, target_path: &str) -> bool {
        is_path_beneath(self.path_str(), target_path)
    }
}

/// Ensemble de règles Landlock configuré avant son application
#[derive(Debug, Clone, Copy)]
pub struct LandlockRuleset {
    pub id: u32,
    pub handled_access_fs: u32,
    pub rules: [Option<PathBeneathRule>; MAX_RULES_PER_LAYER],
    pub rule_count: usize,
    pub is_committed: bool,
}

impl LandlockRuleset {
    pub const fn new(id: u32, handled_access_fs: u32) -> Self {
        Self {
            id,
            handled_access_fs,
            rules: [None; MAX_RULES_PER_LAYER],
            rule_count: 0,
            is_committed: false,
        }
    }

    pub fn add_rule(&mut self, rule: PathBeneathRule) -> Result<(), SysError> {
        if self.is_committed {
            return Err(SysError::PermissionDenied); // Impossible de modifier un ruleset scellé
        }
        if self.rule_count >= MAX_RULES_PER_LAYER {
            return Err(SysError::OutOfMemory);
        }
        for slot in &mut self.rules {
            if slot.is_none() {
                *slot = Some(rule);
                self.rule_count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    pub fn commit(&mut self) {
        self.is_committed = true;
    }
}

// ============================================================================
// COUCHE DE RESTRICTION & DOMAINE MONOTONE (LandlockDomain)
// ============================================================================

/// Couche de restriction active au sein d'une tâche
#[derive(Debug, Clone, Copy)]
pub struct LandlockLayer {
    pub ruleset_id: u32,
    pub handled_access_fs: u32,
    pub rules: [Option<PathBeneathRule>; MAX_RULES_PER_LAYER],
    pub rule_count: usize,
}

impl LandlockLayer {
    pub fn from_ruleset(ruleset: &LandlockRuleset) -> Self {
        Self {
            ruleset_id: ruleset.id,
            handled_access_fs: ruleset.handled_access_fs,
            rules: ruleset.rules,
            rule_count: ruleset.rule_count,
        }
    }

    /// Évalue une opération demandée sur un chemin donné.
    /// Retourne `Ok(())` si autorisée, ou `Err(missing_access)` si bloquée par cette couche.
    pub fn evaluate_access(&self, target_path: &str, requested_access: u32) -> Result<(), u32> {
        let intercepted = self.handled_access_fs & requested_access;
        // Si aucun des droits demandés n'est intercepté par cette couche, elle ne s'applique pas
        if intercepted == 0 {
            return Ok(());
        }

        // Calculer l'union des permissions accordées par les règles correspondantes
        let mut allowed = 0u32;
        for slot in &self.rules {
            if let Some(rule) = slot {
                if rule.matches_path(target_path) {
                    allowed |= rule.allowed_access;
                }
            }
        }

        let missing = intercepted & !allowed;
        if missing == 0 {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

/// Décision d'accès retournée lors de l'évaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockDecision {
    Granted,
    Denied {
        layer_index: usize,
        handled_access: u32,
        missing_access: u32,
    },
    ProcessUnconfined,
}

/// Domaine de confinement attaché à un processus ou fil d'exécution
#[derive(Debug, Clone, Copy)]
pub struct LandlockDomain {
    pub pid: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub layers: [Option<LandlockLayer>; MAX_LAYERS_PER_DOMAIN],
    pub layer_count: usize,
    pub no_new_privs: bool,
    pub total_handled_access: u32,
}

impl LandlockDomain {
    pub fn new(pid: u32, name_str: &str) -> Self {
        let bytes = name_str.as_bytes();
        let copy_len = bytes.len().min(MAX_NAME_LEN);
        let mut name = [0u8; MAX_NAME_LEN];
        name[..copy_len].copy_from_slice(&bytes[..copy_len]);
        Self {
            pid,
            name,
            name_len: copy_len,
            layers: [None; MAX_LAYERS_PER_DOMAIN],
            layer_count: 0,
            no_new_privs: true,
            total_handled_access: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<unknown>")
    }

    /// Empile une nouvelle couche de restriction monotone
    pub fn push_layer(&mut self, layer: LandlockLayer) -> Result<(), SysError> {
        if self.layer_count >= MAX_LAYERS_PER_DOMAIN {
            return Err(SysError::OutOfMemory);
        }
        for slot in &mut self.layers {
            if slot.is_none() {
                self.total_handled_access |= layer.handled_access_fs;
                *slot = Some(layer);
                self.layer_count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Évaluation contre toutes les couches empilées (Intersection stricte)
    pub fn evaluate(&self, target_path: &str, requested_access: u32) -> LandlockDecision {
        if self.layer_count == 0 {
            return LandlockDecision::ProcessUnconfined;
        }

        for (idx, slot) in self.layers.iter().enumerate() {
            if let Some(layer) = slot {
                if let Err(missing) = layer.evaluate_access(target_path, requested_access) {
                    return LandlockDecision::Denied {
                        layer_index: idx,
                        handled_access: layer.handled_access_fs,
                        missing_access: missing,
                    };
                }
            }
        }
        LandlockDecision::Granted
    }
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SHA-256 INVIOLABLE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    RulesetCreated,
    RuleAdded,
    DomainRestricted,
    DomainInherited,
    AccessGranted,
    AccessDenied,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::RulesetCreated => "RULESET_CREATED",
            AuditAction::RuleAdded => "RULE_ADDED",
            AuditAction::DomainRestricted => "DOMAIN_RESTRICTED",
            AuditAction::DomainInherited => "DOMAIN_INHERITED",
            AuditAction::AccessGranted => "ACCESS_GRANTED",
            AuditAction::AccessDenied => "ACCESS_DENIED",
        }
    }
}

/// Entrée d'audit cryptographiquement scellée
#[derive(Debug, Clone, Copy)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: u64,
    pub action: AuditAction,
    pub pid: u32,
    pub target_path: [u8; MAX_PATH_LEN],
    pub target_path_len: usize,
    pub access_mask: u32,
    pub prev_hash: [u8; 32],
    pub current_hash: [u8; 32],
}

// ============================================================================
// DÉMON PRINCIPAL JAMBO-LANDLOCK (JamboLandlockDaemon)
// ============================================================================

pub struct JamboLandlockDaemon {
    pub cap: LandlockCap,
    pub rulesets: [Option<LandlockRuleset>; MAX_RULESETS],
    pub domains: [Option<LandlockDomain>; MAX_DOMAINS],
    pub audit_log: [Option<AuditEntry>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub last_audit_digest: [u8; 32],
    pub next_ruleset_id: u32,
    pub evaluations_count: u64,
    pub granted_count: u64,
    pub denied_count: u64,
}

impl JamboLandlockDaemon {
    pub fn new(cap: LandlockCap) -> Self {
        Self {
            cap,
            rulesets: [None; MAX_RULESETS],
            domains: [None; MAX_DOMAINS],
            audit_log: [None; MAX_AUDIT_LOGS],
            audit_count: 0,
            last_audit_digest: [0u8; 32],
            next_ruleset_id: 1,
            evaluations_count: 0,
            granted_count: 0,
            denied_count: 0,
        }
    }

    /// Initialisation des règles et profils de bac à sable par défaut du système
    pub fn init_defaults(&mut self) {
        let ts = 1000;

        // 1. Profil PID 1 (Init) : Non-confiné (accès complet)
        let _ = self.register_domain(1, "system-init");

        // 2. Profil PID 10 (JamboShell jsh) : Lecture générale sur /, écriture restreinte sur /tmp et /dev
        let r_shell = self
            .create_ruleset_internal(fs_access::ALL, ts)
            .expect("create ruleset shell");
        let h_root = Handle::new(100, 1);
        let h_tmp = Handle::new(101, 1);
        let h_dev = Handle::new(102, 1);

        let _ = self.add_rule_path_beneath_internal(r_shell, h_root, "/", fs_access::READ | fs_access::EXEC, ts);
        let _ = self.add_rule_path_beneath_internal(r_shell, h_tmp, "/tmp", fs_access::READ | fs_access::WRITE, ts);
        let _ = self.add_rule_path_beneath_internal(r_shell, h_dev, "/dev", fs_access::READ | fs_access::WRITE, ts);

        let _ = self.register_domain(10, "jsh");
        let _ = self.restrict_domain_internal(10, r_shell, ts);

        // 3. Profil PID 20 (Worker Confine) :
        //    - Couche 1 : Lecture/Exec sur /usr, lecture sur /etc, lecture/écriture sur /tmp
        //    - Couche 2 : Empilement strict limitant l'écriture UNIQUEMENT à /tmp/worker/
        let r_worker1 = self
            .create_ruleset_internal(fs_access::ALL, ts + 1)
            .expect("create ruleset worker1");
        let _ = self.add_rule_path_beneath_internal(r_worker1, Handle::new(201, 1), "/usr", fs_access::READ | fs_access::EXEC, ts);
        let _ = self.add_rule_path_beneath_internal(r_worker1, Handle::new(202, 1), "/etc", fs_access::READ, ts);
        let _ = self.add_rule_path_beneath_internal(r_worker1, Handle::new(203, 1), "/tmp", fs_access::READ | fs_access::WRITE, ts);

        let _ = self.register_domain(20, "sandbox-worker");
        let _ = self.restrict_domain_internal(20, r_worker1, ts + 1);

        // Couche 2 empilée pour PID 20 : Seule l'écriture dans /tmp/worker est tolérée
        let r_worker2 = self
            .create_ruleset_internal(fs_access::WRITE, ts + 2)
            .expect("create ruleset worker2");
        let _ = self.add_rule_path_beneath_internal(r_worker2, Handle::new(204, 1), "/tmp/worker", fs_access::WRITE, ts + 2);
        let _ = self.restrict_domain_internal(20, r_worker2, ts + 2);

        // 4. Profil PID 30 (Micro-Service Isolé) : Lecture seule sur /usr/share, zéro écriture
        let r_isolated = self
            .create_ruleset_internal(fs_access::ALL, ts + 3)
            .expect("create ruleset isolated");
        let _ = self.add_rule_path_beneath_internal(r_isolated, Handle::new(301, 1), "/usr/share", fs_access::READ, ts + 3);

        let _ = self.register_domain(30, "isolated-daemon");
        let _ = self.restrict_domain_internal(30, r_isolated, ts + 3);
    }

    /// Crée un nouveau ruleset Landlock
    pub fn create_ruleset(
        &mut self,
        cap: &LandlockCap,
        handled_access_fs: u32,
        timestamp: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(landlock_rights::RULESET_CREATE) {
            return Err(SysError::PermissionDenied);
        }
        self.create_ruleset_internal(handled_access_fs, timestamp)
    }

    fn create_ruleset_internal(&mut self, handled_access_fs: u32, timestamp: u64) -> Result<u32, SysError> {
        let id = self.next_ruleset_id;
        for slot in &mut self.rulesets {
            if slot.is_none() {
                *slot = Some(LandlockRuleset::new(id, handled_access_fs));
                self.next_ruleset_id += 1;
                self.record_audit(
                    AuditAction::RulesetCreated,
                    id,
                    "",
                    handled_access_fs,
                    timestamp,
                );
                return Ok(id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Ajoute une règle de chemin sous-jacent (`path_beneath`) à un ruleset
    pub fn add_rule_path_beneath(
        &mut self,
        cap: &LandlockCap,
        ruleset_id: u32,
        parent_handle: Handle,
        path_prefix: &str,
        allowed_access: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(landlock_rights::RULE_ADD) {
            return Err(SysError::PermissionDenied);
        }
        self.add_rule_path_beneath_internal(ruleset_id, parent_handle, path_prefix, allowed_access, timestamp)
    }

    fn add_rule_path_beneath_internal(
        &mut self,
        ruleset_id: u32,
        parent_handle: Handle,
        path_prefix: &str,
        allowed_access: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        let rule = PathBeneathRule::new(parent_handle, path_prefix, allowed_access)?;
        for slot in &mut self.rulesets {
            if let Some(ruleset) = slot {
                if ruleset.id == ruleset_id {
                    ruleset.add_rule(rule)?;
                    self.record_audit(
                        AuditAction::RuleAdded,
                        ruleset_id,
                        path_prefix,
                        allowed_access,
                        timestamp,
                    );
                    return Ok(());
                }
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Enregistre un domaine pour un processus cible
    pub fn register_domain(&mut self, pid: u32, name_str: &str) -> Result<(), SysError> {
        for slot in &self.domains {
            if let Some(dom) = slot {
                if dom.pid == pid {
                    return Ok(()); // Déjà présent
                }
            }
        }
        for slot in &mut self.domains {
            if slot.is_none() {
                *slot = Some(LandlockDomain::new(pid, name_str));
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Applique et empile un ruleset sur le processus appelant (`restrict_self`)
    pub fn restrict_self(
        &mut self,
        cap: &LandlockCap,
        pid: u32,
        ruleset_id: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(landlock_rights::RESTRICT_SELF) {
            return Err(SysError::PermissionDenied);
        }
        self.restrict_domain_internal(pid, ruleset_id, timestamp)
    }

    fn restrict_domain_internal(
        &mut self,
        pid: u32,
        ruleset_id: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        // Localiser et verrouiller le ruleset
        let layer = {
            let mut found = None;
            for slot in &mut self.rulesets {
                if let Some(ruleset) = slot {
                    if ruleset.id == ruleset_id {
                        ruleset.commit();
                        found = Some(LandlockLayer::from_ruleset(ruleset));
                        break;
                    }
                }
            }
            match found {
                Some(l) => l,
                None => return Err(SysError::InvalidArgument),
            }
        };

        // Empiler la couche dans le domaine du processus
        for slot in &mut self.domains {
            if let Some(dom) = slot {
                if dom.pid == pid {
                    dom.push_layer(layer)?;
                    self.record_audit(
                        AuditAction::DomainRestricted,
                        pid,
                        "",
                        layer.handled_access_fs,
                        timestamp,
                    );
                    return Ok(());
                }
            }
        }

        // Si le domaine n'existait pas encore, le créer et empiler
        let mut new_dom = LandlockDomain::new(pid, "user-task");
        new_dom.push_layer(layer)?;
        for slot in &mut self.domains {
            if slot.is_none() {
                *slot = Some(new_dom);
                self.record_audit(
                    AuditAction::DomainRestricted,
                    pid,
                    "",
                    layer.handled_access_fs,
                    timestamp,
                );
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Hérite du domaine complet (toutes les couches empilées) lors du clonage de processus
    pub fn inherit_domain(
        &mut self,
        cap: &LandlockCap,
        parent_pid: u32,
        child_pid: u32,
        child_name: &str,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(landlock_rights::ADMIN) && !cap.has_right(landlock_rights::RESTRICT_SELF) {
            return Err(SysError::PermissionDenied);
        }

        let parent_domain = {
            let mut found = None;
            for slot in &self.domains {
                if let Some(dom) = slot {
                    if dom.pid == parent_pid {
                        found = Some(*dom);
                        break;
                    }
                }
            }
            found
        };

        match parent_domain {
            Some(parent) => {
                let mut child = LandlockDomain::new(child_pid, child_name);
                child.layers = parent.layers;
                child.layer_count = parent.layer_count;
                child.total_handled_access = parent.total_handled_access;

                for slot in &mut self.domains {
                    if slot.is_none() {
                        *slot = Some(child);
                        self.record_audit(
                            AuditAction::DomainInherited,
                            child_pid,
                            "",
                            child.total_handled_access,
                            timestamp,
                        );
                        return Ok(());
                    }
                }
                Err(SysError::OutOfMemory)
            }
            None => {
                // Parent non-confiné
                let child = LandlockDomain::new(child_pid, child_name);
                for slot in &mut self.domains {
                    if slot.is_none() {
                        *slot = Some(child);
                        return Ok(());
                    }
                }
                Err(SysError::OutOfMemory)
            }
        }
    }

    /// Évalue un accès au système de fichiers pour un processus donné
    pub fn check_access(
        &mut self,
        pid: u32,
        target_path: &str,
        requested_access: u32,
        timestamp: u64,
    ) -> LandlockDecision {
        self.evaluations_count += 1;

        let domain = self.get_domain(pid);
        let decision = match domain {
            Some(dom) => dom.evaluate(target_path, requested_access),
            None => LandlockDecision::ProcessUnconfined,
        };

        match decision {
            LandlockDecision::Granted | LandlockDecision::ProcessUnconfined => {
                self.granted_count += 1;
                self.record_audit(
                    AuditAction::AccessGranted,
                    pid,
                    target_path,
                    requested_access,
                    timestamp,
                );
            }
            LandlockDecision::Denied { .. } => {
                self.denied_count += 1;
                self.record_audit(
                    AuditAction::AccessDenied,
                    pid,
                    target_path,
                    requested_access,
                    timestamp,
                );
            }
        }

        decision
    }

    pub fn get_domain(&self, pid: u32) -> Option<&LandlockDomain> {
        for slot in &self.domains {
            if let Some(dom) = slot {
                if dom.pid == pid {
                    return Some(dom);
                }
            }
        }
        None
    }

    pub fn get_ruleset(&self, id: u32) -> Option<&LandlockRuleset> {
        for slot in &self.rulesets {
            if let Some(ruleset) = slot {
                if ruleset.id == id {
                    return Some(ruleset);
                }
            }
        }
        None
    }

    // ========================================================================
    // JOURNALISATION D'AUDIT CRYPTOGRAPHIQUE SCELLÉE SHA-256
    // ========================================================================

    fn record_audit(
        &mut self,
        action: AuditAction,
        pid: u32,
        path_str: &str,
        access_mask: u32,
        timestamp: u64,
    ) {
        let index = self.audit_count as u64;
        let mut target_path = [0u8; MAX_PATH_LEN];
        let bytes = path_str.as_bytes();
        let copy_len = bytes.len().min(MAX_PATH_LEN);
        target_path[..copy_len].copy_from_slice(&bytes[..copy_len]);

        // Construire les données pour l'empreinte SHA-256
        let mut hash_input = [0u8; 128];
        let mut pos = 0;
        hash_input[pos..pos + 32].copy_from_slice(&self.last_audit_digest);
        pos += 32;
        hash_input[pos..pos + 8].copy_from_slice(&index.to_be_bytes());
        pos += 8;
        hash_input[pos..pos + 8].copy_from_slice(&timestamp.to_be_bytes());
        pos += 8;
        hash_input[pos..pos + 4].copy_from_slice(&pid.to_be_bytes());
        pos += 4;
        hash_input[pos..pos + 4].copy_from_slice(&access_mask.to_be_bytes());
        pos += 4;
        hash_input[pos..pos + 4].copy_from_slice(&(action as u32).to_be_bytes());
        pos += 4;
        let p_len = copy_len.min(60);
        hash_input[pos..pos + p_len].copy_from_slice(&target_path[..p_len]);
        pos += p_len;

        let current_hash = Sha256::digest(&hash_input[..pos]);
        let entry = AuditEntry {
            index,
            timestamp,
            action,
            pid,
            target_path,
            target_path_len: copy_len,
            access_mask,
            prev_hash: self.last_audit_digest,
            current_hash,
        };

        let slot_idx = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_log[slot_idx] = Some(entry);
        self.audit_count += 1;
        self.last_audit_digest = current_hash;
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS (#![no_std] / cargo test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_pure() {
        let digest_empty = Sha256::digest(b"");
        assert_eq!(
            digest_empty,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn test_path_beneath_matching() {
        assert!(is_path_beneath("/", "/etc/passwd"));
        assert!(is_path_beneath("/", "/tmp"));
        assert!(is_path_beneath("/usr", "/usr"));
        assert!(is_path_beneath("/usr", "/usr/bin/sh"));
        assert!(is_path_beneath("/usr/", "/usr/bin/sh"));
        assert!(!is_path_beneath("/usr", "/usrlib"));
        assert!(!is_path_beneath("/usr", "/etc/hosts"));
        assert!(is_path_beneath("/tmp/sandbox", "/tmp/sandbox/file.txt"));
        assert!(!is_path_beneath("/tmp/sandbox", "/tmp/other.txt"));
    }

    #[test]
    fn test_cap_rights_and_attenuation() {
        let cap_all = LandlockCap::new(Handle::new(1, 1), landlock_rights::ALL);
        assert!(cap_all.has_right(landlock_rights::RULESET_CREATE));
        assert!(cap_all.has_right(landlock_rights::RESTRICT_SELF));

        // Atténuation légitime
        let cap_restrict = cap_all
            .attenuate(landlock_rights::RESTRICT_SELF | landlock_rights::AUDIT)
            .unwrap();
        assert!(cap_restrict.has_right(landlock_rights::RESTRICT_SELF));
        assert!(cap_restrict.has_right(landlock_rights::AUDIT));
        assert!(!cap_restrict.has_right(landlock_rights::ADMIN));
        assert!(!cap_restrict.has_right(landlock_rights::RULESET_CREATE));

        // Rejet formel d'élévation
        let elevated = cap_restrict.attenuate(landlock_rights::ADMIN);
        assert_eq!(elevated, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_monotonic_layer_stacking_and_confinement() {
        let cap = LandlockCap::new(Handle::new(1, 1), landlock_rights::ALL);
        let mut daemon = JamboLandlockDaemon::new(cap);
        daemon.init_defaults();

        // PID 20 (sandbox-worker) :
        // Couche 1 autorise Read/Exec sur /usr, Read sur /etc, Read/Write sur /tmp
        // Couche 2 limite Write exclusivement à /tmp/worker/

        // 1. Lecture dans /usr/bin/sh : Autorisée par couche 1, non interceptée en lecture par couche 2
        let dec_read_usr = daemon.check_access(20, "/usr/bin/sh", fs_access::READ_FILE, 2000);
        assert_eq!(dec_read_usr, LandlockDecision::Granted);

        // 2. Écriture dans /tmp/worker/job.dat : Autorisée par les 2 couches !
        let dec_write_worker = daemon.check_access(20, "/tmp/worker/job.dat", fs_access::WRITE_FILE, 2001);
        assert_eq!(dec_write_worker, LandlockDecision::Granted);

        // 3. Écriture dans /tmp/evil.sh : Bloquée par la couche 2 (non présente sous /tmp/worker)
        let dec_write_tmp = daemon.check_access(20, "/tmp/evil.sh", fs_access::WRITE_FILE, 2002);
        match dec_write_tmp {
            LandlockDecision::Denied { layer_index, missing_access, .. } => {
                assert_eq!(layer_index, 1);
                assert_eq!(missing_access, fs_access::WRITE_FILE);
            }
            _ => panic!("Expected Denied by layer 1 (second layer), got {:?}", dec_write_tmp),
        }

        // 4. Écriture dans /etc/passwd : Bloquée dès la couche 0
        let dec_write_etc = daemon.check_access(20, "/etc/passwd", fs_access::WRITE_FILE, 2003);
        match dec_write_etc {
            LandlockDecision::Denied { layer_index, .. } => {
                assert_eq!(layer_index, 0);
            }
            _ => panic!("Expected Denied by layer 0, got {:?}", dec_write_etc),
        }

        // 5. Lecture dans /etc/hosts : Autorisée par couche 0 (lecture autorisée sur /etc)
        let dec_read_etc = daemon.check_access(20, "/etc/hosts", fs_access::READ_FILE, 2004);
        assert_eq!(dec_read_etc, LandlockDecision::Granted);

        // 6. Monotonie formelle : Empilement d'une couche 3 interdisant TOUT accès réseau/périphérique
        let r3 = daemon.create_ruleset_internal(fs_access::READ, 2005).unwrap();
        // Couche 3 n'autorise QUE /usr
        let _ = daemon.add_rule_path_beneath_internal(r3, Handle::new(401, 1), "/usr", fs_access::READ, 2005);
        let _ = daemon.restrict_domain_internal(20, r3, 2005);

        // Maintenant, la lecture de /etc/hosts est BLOQUÉE par la couche 3 (index 2) !
        let dec_read_etc_after = daemon.check_access(20, "/etc/hosts", fs_access::READ_FILE, 2006);
        match dec_read_etc_after {
            LandlockDecision::Denied { layer_index, .. } => {
                assert_eq!(layer_index, 2);
            }
            _ => panic!("Expected Denied by layer 2, got {:?}", dec_read_etc_after),
        }

        // Mais la lecture de /usr/bin/sh reste toujours autorisée (intersection vérifiée)
        let dec_read_usr_after = daemon.check_access(20, "/usr/bin/sh", fs_access::READ_FILE, 2007);
        assert_eq!(dec_read_usr_after, LandlockDecision::Granted);
    }

    #[test]
    fn test_domain_inheritance_on_fork() {
        let cap = LandlockCap::new(Handle::new(1, 1), landlock_rights::ALL);
        let mut daemon = JamboLandlockDaemon::new(cap);
        daemon.init_defaults();

        // Hériter du domaine PID 20 pour un nouveau processus enfant PID 21
        let res = daemon.inherit_domain(&cap, 20, 21, "worker-child", 3000);
        assert!(res.is_ok());

        // Vérifier que PID 21 possède les 2 mêmes couches empilées
        let child_dom = daemon.get_domain(21).unwrap();
        assert_eq!(child_dom.layer_count, 2);

        // Même décision que le parent : écriture dans /tmp/worker autorisée, /tmp/evil refusée
        assert_eq!(
            daemon.check_access(21, "/tmp/worker/sub.txt", fs_access::WRITE_FILE, 3001),
            LandlockDecision::Granted
        );
        match daemon.check_access(21, "/tmp/evil.sh", fs_access::WRITE_FILE, 3002) {
            LandlockDecision::Denied { layer_index, .. } => {
                assert_eq!(layer_index, 1);
            }
            _ => panic!("Expected Denied by layer 1"),
        }
    }

    #[test]
    fn test_tamper_evident_audit_trail() {
        let cap = LandlockCap::new(Handle::new(1, 1), landlock_rights::ALL);
        let mut daemon = JamboLandlockDaemon::new(cap);
        daemon.init_defaults();

        assert!(daemon.audit_count > 0);
        assert_ne!(daemon.last_audit_digest, [0u8; 32]);

        // Vérification de l'intégrité de la chaîne
        let mut prev_hash = [0u8; 32];
        for i in 0..daemon.audit_count.min(MAX_AUDIT_LOGS) {
            let entry = daemon.audit_log[i].as_ref().unwrap();
            assert_eq!(entry.prev_hash, prev_hash, "Chaîne de hash rompue à l'indice {}", i);
            prev_hash = entry.current_hash;
        }
    }
}

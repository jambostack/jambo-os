//! Spécification Formelle, Vérification de Conformité Dynamique d'Atténuation de Capacités
//! et Validation d'Invariants de Sécurité CSpace pour Micro-Noyau Souverain (`jambo-capspec`)
//!
//! Phase 91 — Jalon v0.2.89
//!
//! Fournit les garanties formelles du modèle de capacités de JamboOS :
//! 1. Absence d'autorité ambiante : tout accès exige une capacité valide non nulle.
//! 2. Atténuation monotone irréversible : Rights(child) ⊆ Rights(parent). Rejet formel d'amplification.
//! 3. Intégrité et acyclicité de l'arbre de dérivation CSpace (profondeur bornée).
//! 4. Révocation en cascade déterministe : l'invalidation d'un ancêtre révoque tout le sous-arbre.
//! 5. Confinement par profils formels (StrictIsolation, ServiceWorker, SystemSupervisor).
//! 6. Scellement cryptographique des jetons et registre d'audit chaîné par hachage SHA-256.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_CAP_NODES: usize = 128;
pub const MAX_PROFILES: usize = 16;
pub const MAX_TASK_PROFILES: usize = 64;
pub const MAX_AUDIT_LOGS: usize = 64;
pub const MAX_DERIVATION_DEPTH: u8 = 16;
pub const MAX_NAME_LEN: usize = 32;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

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
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let total_bits = (data.len() as u64).wrapping_mul(8);
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let remaining = data.len() - offset;
        block[..remaining].copy_from_slice(&data[offset..]);
        block[remaining] = 0x80;
        for i in (remaining + 1)..64 {
            block[i] = 0;
        }

        if remaining >= 56 {
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
        }

        block[56..64].copy_from_slice(&total_bits.to_be_bytes());
        Self::process_block(&mut state, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// DROITS CAPABILAIRES & JETON CapSpecCap
// ============================================================================

pub mod capspec_rights {
    pub const VERIFY: u32 = 1 << 0;
    pub const REGISTER_SPEC: u32 = 1 << 1;
    pub const ENFORCE: u32 = 1 << 2;
    pub const AUDIT: u32 = 1 << 3;
    pub const ADMIN: u32 = 1 << 4;

    pub const ALL: u32 = VERIFY | REGISTER_SPEC | ENFORCE | AUDIT | ADMIN;
}

/// Jeton de capacité souverain pour la gouvernance CapSpec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapSpecCap {
    pub handle: Handle,
    pub rights: u32,
}

impl CapSpecCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone irréversible
    pub fn attenuate(&self, requested_rights: u32) -> Result<Self, SysError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
        })
    }
}

// ============================================================================
// TYPES DE CAPACITÉS DU MICRO-NOYAU & MASQUES
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapType {
    MemoryVmo = 0,
    IpcEndpoint = 1,
    ThreadTask = 2,
    IoPortIrq = 3,
    DeviceDriver = 4,
    FileSystem = 5,
    Network = 6,
    SecurityPolicy = 7,
}

impl CapType {
    pub const fn mask(&self) -> u32 {
        1 << (*self as u32)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CapType::MemoryVmo => "VMO",
            CapType::IpcEndpoint => "IPC",
            CapType::ThreadTask => "TASK",
            CapType::IoPortIrq => "IO/IRQ",
            CapType::DeviceDriver => "DEVICE",
            CapType::FileSystem => "VFS",
            CapType::Network => "NET",
            CapType::SecurityPolicy => "SECPOL",
        }
    }
}

// ============================================================================
// NŒUD D'ARBRE CSPACE & SCEAU CRYPTOGRAPHIQUE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CSpaceNode {
    pub id: u32,
    pub handle: Handle,
    pub cap_type: CapType,
    pub rights: u32,
    pub parent_id: Option<u32>,
    pub owner_pid: u32,
    pub depth: u8,
    pub is_revoked: bool,
    pub allow_transfer: bool,
    pub token_hash: [u8; 32],
}

impl CSpaceNode {
    pub fn compute_hash(
        id: u32,
        handle: Handle,
        cap_type: CapType,
        rights: u32,
        parent_id: Option<u32>,
        owner_pid: u32,
        depth: u8,
    ) -> [u8; 32] {
        let mut buf = [0u8; 48];
        buf[0..4].copy_from_slice(&id.to_be_bytes());
        buf[4..12].copy_from_slice(&handle.0.to_be_bytes());
        buf[12] = cap_type as u8;
        buf[13..17].copy_from_slice(&rights.to_be_bytes());
        let p_val = parent_id.unwrap_or(0);
        buf[17..21].copy_from_slice(&p_val.to_be_bytes());
        buf[21..25].copy_from_slice(&owner_pid.to_be_bytes());
        buf[25] = depth;
        // Sel fixe souverain CapSpec
        buf[26..34].copy_from_slice(&0x535045435f434150u64.to_be_bytes());
        Sha256::digest(&buf[0..34])
    }

    pub fn verify_authenticity(&self) -> bool {
        let expected = Self::compute_hash(
            self.id,
            self.handle,
            self.cap_type,
            self.rights,
            self.parent_id,
            self.owner_pid,
            self.depth,
        );
        self.token_hash == expected
    }
}

// ============================================================================
// INVARIANTS FORMELS ET TYPES DE VIOLATIONS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantViolation {
    AmbientAuthorityAttempt {
        pid: u32,
    },
    RightsAmplification {
        parent_rights: u32,
        requested_rights: u32,
    },
    CycleDetected {
        node_id: u32,
    },
    MaxDepthExceeded {
        depth: u8,
    },
    TransferProhibited {
        pid: u32,
        node_id: u32,
    },
    UnauthorizedCapType {
        profile_id: u32,
        cap_type: CapType,
    },
    IntegrityTampered {
        node_id: u32,
    },
    RevokedAccess {
        node_id: u32,
    },
    InvalidCapabilityHandle {
        handle_val: u64,
    },
    TaskNotPermitted {
        pid: u32,
    },
    ProfileBoundaryExceeded {
        rights: u32,
        max_rights: u32,
    },
}

// ============================================================================
// PROFILS FORMELS DE CONFINEMENT
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct ConfinementProfile {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub allowed_types_mask: u32,
    pub max_rights_mask: u32,
    pub allow_delegation: bool,
    pub allow_transfer: bool,
    pub max_derivation_depth: u8,
    pub enforce_strict_zero_ambient: bool,
}

impl ConfinementProfile {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<inconnu>")
    }

    /// Profil de confinement étanche pour code non fiable / Wasm / bac à sable
    pub fn strict_isolation(id: u32) -> Self {
        let mut name = [0u8; MAX_NAME_LEN];
        let tag = b"StrictIsolation";
        name[..tag.len()].copy_from_slice(tag);
        Self {
            id,
            name,
            name_len: tag.len(),
            allowed_types_mask: CapType::MemoryVmo.mask() | CapType::FileSystem.mask(),
            max_rights_mask: libjambo::cap_rights::READ | libjambo::cap_rights::EXECUTE,
            allow_delegation: false,
            allow_transfer: false,
            max_derivation_depth: 2,
            enforce_strict_zero_ambient: true,
        }
    }

    /// Profil standard pour service système Ring 3 (ex. VFS, Netd, Logd)
    pub fn service_worker(id: u32) -> Self {
        let mut name = [0u8; MAX_NAME_LEN];
        let tag = b"ServiceWorker";
        name[..tag.len()].copy_from_slice(tag);
        Self {
            id,
            name,
            name_len: tag.len(),
            allowed_types_mask: CapType::MemoryVmo.mask()
                | CapType::IpcEndpoint.mask()
                | CapType::FileSystem.mask()
                | CapType::Network.mask(),
            max_rights_mask: libjambo::cap_rights::ALL,
            allow_delegation: true,
            allow_transfer: true,
            max_derivation_depth: 6,
            enforce_strict_zero_ambient: true,
        }
    }

    /// Profil superviseur / init pour gestion du système
    pub fn system_supervisor(id: u32) -> Self {
        let mut name = [0u8; MAX_NAME_LEN];
        let tag = b"SystemSupervisor";
        name[..tag.len()].copy_from_slice(tag);
        Self {
            id,
            name,
            name_len: tag.len(),
            allowed_types_mask: 0xFFFF_FFFF,
            max_rights_mask: 0xFFFF_FFFF,
            allow_delegation: true,
            allow_transfer: true,
            max_derivation_depth: MAX_DERIVATION_DEPTH,
            enforce_strict_zero_ambient: true,
        }
    }
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ SHA-256
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    SpecRegistered,
    ProfileAssigned,
    RootCapCreated,
    CapDerived,
    CapTransferred,
    CapRevoked,
    InvariantsVerified,
    ViolationDetected,
}

#[derive(Debug, Clone, Copy)]
pub struct AuditEntry {
    pub timestamp_ns: u64,
    pub action: AuditAction,
    pub actor_pid: u32,
    pub node_id: u32,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

// ============================================================================
// DÉMON DE SPÉCIFICATION ET VÉRIFICATION DYNAMIQUE CSPACE
// ============================================================================

pub struct JamboCapSpecDaemon {
    pub cap: CapSpecCap,
    pub nodes: [Option<CSpaceNode>; MAX_CAP_NODES],
    pub profiles: [Option<ConfinementProfile>; MAX_PROFILES],
    pub task_profiles: [Option<(u32, u32)>; MAX_TASK_PROFILES], // (pid, profile_id)
    pub audit_logs: [Option<AuditEntry>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub last_audit_digest: [u8; 32],
    pub evaluations_count: u64,
    pub violations_count: u64,
    pub revocations_count: u64,
    pub next_node_id: u32,
    pub next_profile_id: u32,
}

impl JamboCapSpecDaemon {
    pub const fn new(cap: CapSpecCap) -> Self {
        Self {
            cap,
            nodes: [None; MAX_CAP_NODES],
            profiles: [None; MAX_PROFILES],
            task_profiles: [None; MAX_TASK_PROFILES],
            audit_logs: [None; MAX_AUDIT_LOGS],
            audit_count: 0,
            last_audit_digest: [0u8; 32],
            evaluations_count: 0,
            violations_count: 0,
            revocations_count: 0,
            next_node_id: 1,
            next_profile_id: 1,
        }
    }

    /// Enregistre une entrée d'audit cryptographique chaînée par SHA-256
    pub fn append_audit(
        &mut self,
        timestamp_ns: u64,
        action: AuditAction,
        actor_pid: u32,
        node_id: u32,
    ) {
        let mut buf = [0u8; 80];
        buf[0..8].copy_from_slice(&timestamp_ns.to_be_bytes());
        buf[8] = action as u8;
        buf[9..13].copy_from_slice(&actor_pid.to_be_bytes());
        buf[13..17].copy_from_slice(&node_id.to_be_bytes());
        buf[17..49].copy_from_slice(&self.last_audit_digest);

        let digest = Sha256::digest(&buf[0..49]);
        let entry = AuditEntry {
            timestamp_ns,
            action,
            actor_pid,
            node_id,
            prev_hash: self.last_audit_digest,
            entry_hash: digest,
        };

        self.last_audit_digest = digest;
        let idx = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_logs[idx] = Some(entry);
        self.audit_count = self.audit_count.wrapping_add(1);
    }

    /// Initialise les profils de base et la racine CSpace
    pub fn init_defaults(&mut self) {
        let p_iso = ConfinementProfile::strict_isolation(1);
        let p_srv = ConfinementProfile::service_worker(2);
        let p_sup = ConfinementProfile::system_supervisor(3);

        self.profiles[0] = Some(p_iso);
        self.profiles[1] = Some(p_srv);
        self.profiles[2] = Some(p_sup);
        self.next_profile_id = 4;

        // Association initiale du superviseur (PID 1)
        self.task_profiles[0] = Some((1, 3));

        // Création de la racine VMO pour PID 1
        let h_root = Handle::new(1001, 1);
        let hash = CSpaceNode::compute_hash(
            1,
            h_root,
            CapType::MemoryVmo,
            libjambo::cap_rights::ALL,
            None,
            1,
            0,
        );
        self.nodes[0] = Some(CSpaceNode {
            id: 1,
            handle: h_root,
            cap_type: CapType::MemoryVmo,
            rights: libjambo::cap_rights::ALL,
            parent_id: None,
            owner_pid: 1,
            depth: 0,
            is_revoked: false,
            allow_transfer: true,
            token_hash: hash,
        });
        self.next_node_id = 2;

        self.append_audit(1000, AuditAction::SpecRegistered, 1, 1);
    }

    /// Enregistre un nouveau profil formel de confinement
    pub fn register_profile(
        &mut self,
        cap: &CapSpecCap,
        profile: ConfinementProfile,
    ) -> Result<u32, SysError> {
        if !cap.has_right(capspec_rights::REGISTER_SPEC) {
            return Err(SysError::PermissionDenied);
        }
        for slot in self.profiles.iter_mut() {
            if slot.is_none() {
                let id = self.next_profile_id;
                self.next_profile_id += 1;
                let mut p = profile;
                p.id = id;
                *slot = Some(p);
                self.append_audit(2000, AuditAction::SpecRegistered, 1, id);
                return Ok(id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Affecte un profil de confinement à une tâche (PID)
    pub fn assign_profile(
        &mut self,
        cap: &CapSpecCap,
        pid: u32,
        profile_id: u32,
    ) -> Result<(), SysError> {
        if !cap.has_right(capspec_rights::ENFORCE) {
            return Err(SysError::PermissionDenied);
        }
        // Vérifie l'existence du profil
        let mut exists = false;
        for p in self.profiles.iter().flatten() {
            if p.id == profile_id {
                exists = true;
                break;
            }
        }
        if !exists {
            return Err(SysError::InvalidArgument);
        }

        // Met à jour ou insère l'association
        for slot in self.task_profiles.iter_mut() {
            if let Some((p, _)) = slot {
                if *p == pid {
                    *slot = Some((pid, profile_id));
                    self.append_audit(2100, AuditAction::ProfileAssigned, pid, profile_id);
                    return Ok(());
                }
            }
        }
        for slot in self.task_profiles.iter_mut() {
            if slot.is_none() {
                *slot = Some((pid, profile_id));
                self.append_audit(2100, AuditAction::ProfileAssigned, pid, profile_id);
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Récupère le profil associé à une tâche
    pub fn get_task_profile(&self, pid: u32) -> Option<ConfinementProfile> {
        let mut prof_id = None;
        for slot in self.task_profiles.iter().flatten() {
            if slot.0 == pid {
                prof_id = Some(slot.1);
                break;
            }
        }
        let target_id = prof_id?;
        for p in self.profiles.iter().flatten() {
            if p.id == target_id {
                return Some(*p);
            }
        }
        None
    }

    /// Crée une capacité racine pour un PID donné (réservé aux superviseurs)
    pub fn create_root_capability(
        &mut self,
        cap: &CapSpecCap,
        pid: u32,
        cap_type: CapType,
        rights: u32,
        allow_transfer: bool,
    ) -> Result<u32, SysError> {
        if !cap.has_right(capspec_rights::ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        for slot in self.nodes.iter_mut() {
            if slot.is_none() {
                let id = self.next_node_id;
                self.next_node_id += 1;
                let handle = Handle::new(id + 1000, 1);
                let hash = CSpaceNode::compute_hash(id, handle, cap_type, rights, None, pid, 0);
                *slot = Some(CSpaceNode {
                    id,
                    handle,
                    cap_type,
                    rights,
                    parent_id: None,
                    owner_pid: pid,
                    depth: 0,
                    is_revoked: false,
                    allow_transfer,
                    token_hash: hash,
                });
                self.append_audit(3000, AuditAction::RootCapCreated, pid, id);
                return Ok(id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Dérive et atténue une capacité de façon monotone irréversible
    pub fn derive_capability(
        &mut self,
        _cap: &CapSpecCap,
        parent_id: u32,
        requested_rights: u32,
        target_pid: u32,
    ) -> Result<u32, InvariantViolation> {
        self.evaluations_count += 1;

        // 1. Recherche du parent
        let mut parent_opt = None;
        for slot in self.nodes.iter().flatten() {
            if slot.id == parent_id {
                parent_opt = Some(*slot);
                break;
            }
        }
        let parent = match parent_opt {
            Some(p) => p,
            None => {
                self.violations_count += 1;
                return Err(InvariantViolation::InvalidCapabilityHandle {
                    handle_val: parent_id as u64,
                });
            }
        };

        // 2. Invariant d'intégrité : vérification de révocation
        if parent.is_revoked {
            self.violations_count += 1;
            return Err(InvariantViolation::RevokedAccess { node_id: parent_id });
        }

        // 3. Invariant de profondeur maximale
        if parent.depth >= MAX_DERIVATION_DEPTH {
            self.violations_count += 1;
            return Err(InvariantViolation::MaxDepthExceeded {
                depth: parent.depth,
            });
        }

        // 4. Invariant d'atténuation monotone : Rights(child) ⊆ Rights(parent)
        // Aucune élévation de privilèges autorisée
        if (requested_rights & !parent.rights) != 0 {
            self.violations_count += 1;
            self.append_audit(4000, AuditAction::ViolationDetected, target_pid, parent_id);
            return Err(InvariantViolation::RightsAmplification {
                parent_rights: parent.rights,
                requested_rights,
            });
        }

        // 5. Invariant de frontière de profil pour la tâche cible
        let mut target_allow_transfer = parent.allow_transfer;
        if let Some(prof) = self.get_task_profile(target_pid) {
            // Vérification de la compatibilité de type
            if (prof.allowed_types_mask & parent.cap_type.mask()) == 0 {
                self.violations_count += 1;
                return Err(InvariantViolation::UnauthorizedCapType {
                    profile_id: prof.id,
                    cap_type: parent.cap_type,
                });
            }
            // Vérification des droits maximaux permis par le profil
            if (requested_rights & !prof.max_rights_mask) != 0 {
                self.violations_count += 1;
                return Err(InvariantViolation::ProfileBoundaryExceeded {
                    rights: requested_rights,
                    max_rights: prof.max_rights_mask,
                });
            }
            // Vérification de la profondeur autorisée par le profil
            if (parent.depth + 1) > prof.max_derivation_depth {
                self.violations_count += 1;
                return Err(InvariantViolation::MaxDepthExceeded {
                    depth: parent.depth + 1,
                });
            }
            if !prof.allow_transfer {
                target_allow_transfer = false;
            }
        }

        // 6. Enregistrement du nœud dérivé
        let new_id = self.next_node_id;
        self.next_node_id += 1;
        let new_handle = Handle::new(new_id + 1000, 1);
        let new_depth = parent.depth + 1;
        let hash = CSpaceNode::compute_hash(
            new_id,
            new_handle,
            parent.cap_type,
            requested_rights,
            Some(parent_id),
            target_pid,
            new_depth,
        );

        let new_node = CSpaceNode {
            id: new_id,
            handle: new_handle,
            cap_type: parent.cap_type,
            rights: requested_rights,
            parent_id: Some(parent_id),
            owner_pid: target_pid,
            depth: new_depth,
            is_revoked: false,
            allow_transfer: target_allow_transfer,
            token_hash: hash,
        };

        for slot in self.nodes.iter_mut() {
            if slot.is_none() {
                *slot = Some(new_node);
                self.append_audit(4100, AuditAction::CapDerived, target_pid, new_id);
                return Ok(new_id);
            }
        }

        Err(InvariantViolation::MaxDepthExceeded { depth: new_depth })
    }

    /// Transfère la possession d'une capacité sous respect des frontières de profil
    pub fn transfer_capability(
        &mut self,
        _cap: &CapSpecCap,
        node_id: u32,
        sender_pid: u32,
        receiver_pid: u32,
    ) -> Result<(), InvariantViolation> {
        self.evaluations_count += 1;

        let node_idx = match self
            .nodes
            .iter()
            .position(|n| n.map_or(false, |node| node.id == node_id))
        {
            Some(idx) => idx,
            None => {
                self.violations_count += 1;
                return Err(InvariantViolation::InvalidCapabilityHandle {
                    handle_val: node_id as u64,
                });
            }
        };

        let mut node = self.nodes[node_idx].unwrap();

        // 1. Vérification de propriété
        if node.owner_pid != sender_pid {
            self.violations_count += 1;
            return Err(InvariantViolation::TaskNotPermitted { pid: sender_pid });
        }

        // 2. Vérification de révocation
        if node.is_revoked {
            self.violations_count += 1;
            return Err(InvariantViolation::RevokedAccess { node_id });
        }

        // 3. Vérification du profil de l'expéditeur
        if let Some(tx_prof) = self.get_task_profile(sender_pid) {
            if !tx_prof.allow_transfer {
                self.violations_count += 1;
                return Err(InvariantViolation::TransferProhibited {
                    pid: sender_pid,
                    node_id,
                });
            }
        }

        // 4. Vérification de transférabilité du nœud
        if !node.allow_transfer {
            self.violations_count += 1;
            return Err(InvariantViolation::TransferProhibited {
                pid: sender_pid,
                node_id,
            });
        }

        // 4. Vérification du profil du destinataire
        if let Some(rx_prof) = self.get_task_profile(receiver_pid) {
            if !rx_prof.allow_transfer {
                self.violations_count += 1;
                return Err(InvariantViolation::TransferProhibited {
                    pid: receiver_pid,
                    node_id,
                });
            }
            if (rx_prof.allowed_types_mask & node.cap_type.mask()) == 0 {
                self.violations_count += 1;
                return Err(InvariantViolation::UnauthorizedCapType {
                    profile_id: rx_prof.id,
                    cap_type: node.cap_type,
                });
            }
            if (node.rights & !rx_prof.max_rights_mask) != 0 {
                self.violations_count += 1;
                return Err(InvariantViolation::ProfileBoundaryExceeded {
                    rights: node.rights,
                    max_rights: rx_prof.max_rights_mask,
                });
            }
        }

        // Transfert validé : réémission du token hash pour le nouveau propriétaire
        node.owner_pid = receiver_pid;
        node.token_hash = CSpaceNode::compute_hash(
            node.id,
            node.handle,
            node.cap_type,
            node.rights,
            node.parent_id,
            receiver_pid,
            node.depth,
        );

        self.nodes[node_idx] = Some(node);
        self.append_audit(4500, AuditAction::CapTransferred, receiver_pid, node_id);
        Ok(())
    }

    /// Révocation en cascade déterministe d'un nœud et de tous ses descendants
    pub fn revoke_capability(
        &mut self,
        cap: &CapSpecCap,
        root_node_id: u32,
    ) -> Result<u32, SysError> {
        if !cap.has_right(capspec_rights::ENFORCE) {
            return Err(SysError::PermissionDenied);
        }

        let mut to_revoke = [0u32; MAX_CAP_NODES];
        let mut count = 0;
        to_revoke[count] = root_node_id;
        count += 1;

        // Parcours itératif pour collecter tous les descendants
        let mut scan_idx = 0;
        while scan_idx < count {
            let parent_id = to_revoke[scan_idx];
            scan_idx += 1;

            for slot in self.nodes.iter().flatten() {
                if slot.parent_id == Some(parent_id) && !slot.is_revoked {
                    // Vérifie qu'il n'est pas déjà dans la file
                    let mut already = false;
                    for i in 0..count {
                        if to_revoke[i] == slot.id {
                            already = true;
                            break;
                        }
                    }
                    if !already && count < MAX_CAP_NODES {
                        to_revoke[count] = slot.id;
                        count += 1;
                    }
                }
            }
        }

        // Application de la révocation
        let mut total_revoked = 0;
        for i in 0..count {
            let target_id = to_revoke[i];
            for slot in self.nodes.iter_mut() {
                if let Some(ref mut n) = slot {
                    if n.id == target_id && !n.is_revoked {
                        n.is_revoked = true;
                        total_revoked += 1;
                    }
                }
            }
        }

        self.revocations_count += total_revoked as u64;
        self.append_audit(5000, AuditAction::CapRevoked, 1, root_node_id);
        Ok(total_revoked)
    }

    /// Vérification d'une opération ponctuelle sans autorité ambiante
    pub fn verify_operation(
        &mut self,
        pid: u32,
        handle: Handle,
        required_rights: u32,
    ) -> Result<(), InvariantViolation> {
        self.evaluations_count += 1;

        // Invariant 1 : Rejet formel de l'autorité ambiante (Handle NULL)
        if handle.is_null() {
            self.violations_count += 1;
            self.append_audit(6000, AuditAction::ViolationDetected, pid, 0);
            return Err(InvariantViolation::AmbientAuthorityAttempt { pid });
        }

        // Recherche du nœud correspondant
        let mut matched = None;
        for slot in self.nodes.iter().flatten() {
            if slot.handle == handle && slot.owner_pid == pid {
                matched = Some(*slot);
                break;
            }
        }

        let node = match matched {
            Some(n) => n,
            None => {
                self.violations_count += 1;
                return Err(InvariantViolation::InvalidCapabilityHandle {
                    handle_val: handle.0,
                });
            }
        };

        // Invariant 2 : Non-révocation
        if node.is_revoked {
            self.violations_count += 1;
            return Err(InvariantViolation::RevokedAccess { node_id: node.id });
        }

        // Invariant 3 : Intégrité cryptographique du token
        if !node.verify_authenticity() {
            self.violations_count += 1;
            return Err(InvariantViolation::IntegrityTampered { node_id: node.id });
        }

        // Invariant 4 : Droits requis inclus dans les droits détenus
        if (required_rights & !node.rights) != 0 {
            self.violations_count += 1;
            return Err(InvariantViolation::RightsAmplification {
                parent_rights: node.rights,
                requested_rights: required_rights,
            });
        }

        Ok(())
    }

    /// Contrôle formel global de tous les invariants du CSpace
    pub fn check_all_invariants(&mut self) -> Result<u32, InvariantViolation> {
        let mut verified_count = 0;

        for i in 0..MAX_CAP_NODES {
            let node = match self.nodes[i] {
                Some(n) => n,
                None => continue,
            };

            // Invariant 1 : Handle non nul
            if node.handle.is_null() {
                self.violations_count += 1;
                return Err(InvariantViolation::AmbientAuthorityAttempt {
                    pid: node.owner_pid,
                });
            }

            // Invariant 2 : Intégrité cryptographique
            if !node.verify_authenticity() {
                self.violations_count += 1;
                return Err(InvariantViolation::IntegrityTampered { node_id: node.id });
            }

            // Invariant 3 : Profondeur bornée
            if node.depth > MAX_DERIVATION_DEPTH {
                self.violations_count += 1;
                return Err(InvariantViolation::MaxDepthExceeded { depth: node.depth });
            }

            // Invariant 4 : Détection de cycle & vérification parent
            if let Some(p_id) = node.parent_id {
                let mut current = p_id;
                let mut visited_depth = 0;
                let mut parent_node_opt = None;

                while visited_depth < MAX_DERIVATION_DEPTH {
                    let mut found = None;
                    for slot in self.nodes.iter().flatten() {
                        if slot.id == current {
                            found = Some(*slot);
                            break;
                        }
                    }

                    match found {
                        Some(p) => {
                            if visited_depth == 0 {
                                parent_node_opt = Some(p);
                            }
                            if p.id == node.id {
                                self.violations_count += 1;
                                return Err(InvariantViolation::CycleDetected { node_id: node.id });
                            }
                            match p.parent_id {
                                Some(next_p) => {
                                    current = next_p;
                                    visited_depth += 1;
                                }
                                None => break,
                            }
                        }
                        None => {
                            self.violations_count += 1;
                            return Err(InvariantViolation::InvalidCapabilityHandle {
                                handle_val: current as u64,
                            });
                        }
                    }
                }

                // Invariant 5 : Inclusion stricte des droits parent/enfant
                if let Some(parent) = parent_node_opt {
                    if (node.rights & !parent.rights) != 0 {
                        self.violations_count += 1;
                        return Err(InvariantViolation::RightsAmplification {
                            parent_rights: parent.rights,
                            requested_rights: node.rights,
                        });
                    }
                    // Cohérence de révocation : si parent révoqué, enfant doit être révoqué
                    if parent.is_revoked && !node.is_revoked {
                        self.violations_count += 1;
                        return Err(InvariantViolation::RevokedAccess { node_id: node.id });
                    }
                }
            }

            verified_count += 1;
        }

        self.append_audit(7000, AuditAction::InvariantsVerified, 1, verified_count);
        Ok(verified_count)
    }
}

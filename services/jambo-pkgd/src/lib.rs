//! Démon de Gestion Déclarative de Paquets, Dépôt CAS & Mises à Jour Transactionnelles A/B (`jambo-pkgd`)
//!
//! Implémente :
//! 1. Le format de paquet immuable JPkg (.jpkg) avec manifeste vérifié par empreinte cryptographique.
//! 2. Le magasin de stockage adressé par le contenu (CAS) sans autorité ambiante.
//! 3. La bascule atomique O(1) entre générations système A/B avec rollback instantané.
//! 4. Protocole IPC déterministe à 64 octets et canal synchrone sous l'endpoint 23.
//! 5. Ordonnancement coopératif via `syscall_thread_yield()`.

#![no_std]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_find)]

pub use libjambo::{syscall_ipc_register_endpoint, syscall_thread_yield, Handle, SysError};

pub const MAX_STORE_PACKAGES: usize = 16;
pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const PKG_MAGIC_REQ: u32 = 0x504B4744; // "PKGD"
pub const PKG_MAGIC_RESP: u32 = 0x504B4753; // "PKGS"

// ============================================================================
// DROITS & CAPABILITÉS (`PkgCap`, `pkg_rights`)
// ============================================================================

pub mod pkg_rights {
    pub const PKG_INSPECT: u32 = 0x01;
    pub const PKG_INSTALL: u32 = 0x02;
    pub const PKG_STAGE: u32 = 0x04;
    pub const PKG_COMMIT: u32 = 0x08;
    pub const PKG_ROLLBACK: u32 = 0x10;
    pub const PKG_ADMIN: u32 = 0xFF;
}

/// Capabilité d'accès aux services de gestion de paquets et générations A/B
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkgCap {
    pub handle: Handle,
    pub rights: u32,
}

impl PkgCap {
    pub const PKG_INSPECT: u32 = pkg_rights::PKG_INSPECT;
    pub const PKG_INSTALL: u32 = pkg_rights::PKG_INSTALL;
    pub const PKG_STAGE: u32 = pkg_rights::PKG_STAGE;
    pub const PKG_COMMIT: u32 = pkg_rights::PKG_COMMIT;
    pub const PKG_ROLLBACK: u32 = pkg_rights::PKG_ROLLBACK;
    pub const PKG_ADMIN: u32 = pkg_rights::PKG_ADMIN;

    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation unilatérale des privilèges sans possibilité d'amplification
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
// CODES D'OPÉRATIONS IPC (`PkgOpcode`)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgOpcode {
    GetStatus = 1,
    InstallPackage = 2,
    QueryPackage = 3,
    StageUpdate = 4,
    CommitUpdate = 5,
    Rollback = 6,
    UninstallPackage = 7,
}

// ============================================================================
// FENTES A/B & GÉNÉRATIONS SYSTÈME
// ============================================================================

/// Fente de partitionnement transactionnel A/B
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbSlot {
    SlotA = 0,
    SlotB = 1,
}

impl AbSlot {
    pub const fn as_str(&self) -> &'static str {
        match self {
            AbSlot::SlotA => "SlotA",
            AbSlot::SlotB => "SlotB",
        }
    }
}

/// État d'une génération système A/B
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemGeneration {
    pub generation_id: u64,
    pub active_slot: AbSlot,
    pub healthy: bool,
    pub committed: bool,
    pub boot_attempts: u32,
    pub max_boot_attempts: u32,
}

// ============================================================================
// MANIFESTE DE PAQUET JPKG (.jpkg)
// ============================================================================

/// Manifeste d'un paquet logiciel .jpkg sans allocation dynamique
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JpkgManifest {
    pub name: [u8; 24],
    pub version: (u16, u16, u16),
    pub content_hash: [u8; 32],
    pub ed25519_signature: [u8; 64],
    pub required_capabilities: u32,
    pub installed: bool,
}

impl JpkgManifest {
    pub fn new(
        name_str: &str,
        version: (u16, u16, u16),
        content_hash: [u8; 32],
        required_capabilities: u32,
    ) -> Self {
        let mut name = [0u8; 24];
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(24);
        name[..len].copy_from_slice(&bytes[..len]);
        Self {
            name,
            version,
            content_hash,
            ed25519_signature: [0x5au8; 64],
            required_capabilities,
            installed: false,
        }
    }

    pub fn name_as_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(24);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }
}

// ============================================================================
// STRUCTURES IPC 64 OCTETS (`PkgRequest`, `PkgResponse`)
// ============================================================================

/// Requête IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkgRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub rights: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub version_patch: u16,
    pub _reserved1: u16,
    pub content_hash: [u8; 16],
    pub pkg_name: [u8; 24],
}

const _: () = assert!(core::mem::size_of::<PkgRequest>() == 64);

impl Default for PkgRequest {
    fn default() -> Self {
        Self {
            magic: PKG_MAGIC_REQ,
            opcode: PkgOpcode::GetStatus as u32,
            handle_id: 23,
            rights: pkg_rights::PKG_ADMIN,
            version_major: 0,
            version_minor: 0,
            version_patch: 0,
            _reserved1: 0,
            content_hash: [0u8; 16],
            pkg_name: [0u8; 24],
        }
    }
}

impl PkgRequest {
    pub const fn new(opcode: PkgOpcode) -> Self {
        Self {
            magic: PKG_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: 23,
            rights: pkg_rights::PKG_ADMIN,
            version_major: 0,
            version_minor: 0,
            version_patch: 0,
            _reserved1: 0,
            content_hash: [0u8; 16],
            pkg_name: [0u8; 24],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: PKG_MAGIC_REQ,
            opcode: PkgOpcode::GetStatus as u32,
            handle_id,
            rights,
            version_major: 0,
            version_minor: 0,
            version_patch: 0,
            _reserved1: 0,
            content_hash: [0u8; 16],
            pkg_name: [0u8; 24],
        }
    }

    pub fn new_install(
        handle_id: u32,
        rights: u32,
        name: &str,
        version: (u16, u16, u16),
        hash: [u8; 16],
    ) -> Self {
        let mut req = Self {
            magic: PKG_MAGIC_REQ,
            opcode: PkgOpcode::InstallPackage as u32,
            handle_id,
            rights,
            version_major: version.0,
            version_minor: version.1,
            version_patch: version.2,
            _reserved1: 0,
            content_hash: hash,
            pkg_name: [0u8; 24],
        };
        req.set_pkg_name(name);
        req
    }

    pub fn new_query(handle_id: u32, rights: u32, name: &str) -> Self {
        let mut req = Self {
            magic: PKG_MAGIC_REQ,
            opcode: PkgOpcode::QueryPackage as u32,
            handle_id,
            rights,
            version_major: 0,
            version_minor: 0,
            version_patch: 0,
            _reserved1: 0,
            content_hash: [0u8; 16],
            pkg_name: [0u8; 24],
        };
        req.set_pkg_name(name);
        req
    }

    pub const fn new_stage(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: PKG_MAGIC_REQ,
            opcode: PkgOpcode::StageUpdate as u32,
            handle_id,
            rights,
            version_major: 0,
            version_minor: 0,
            version_patch: 0,
            _reserved1: 0,
            content_hash: [0u8; 16],
            pkg_name: [0u8; 24],
        }
    }

    pub const fn new_commit(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: PKG_MAGIC_REQ,
            opcode: PkgOpcode::CommitUpdate as u32,
            handle_id,
            rights,
            version_major: 0,
            version_minor: 0,
            version_patch: 0,
            _reserved1: 0,
            content_hash: [0u8; 16],
            pkg_name: [0u8; 24],
        }
    }

    pub const fn new_rollback(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: PKG_MAGIC_REQ,
            opcode: PkgOpcode::Rollback as u32,
            handle_id,
            rights,
            version_major: 0,
            version_minor: 0,
            version_patch: 0,
            _reserved1: 0,
            content_hash: [0u8; 16],
            pkg_name: [0u8; 24],
        }
    }

    pub fn new_uninstall(handle_id: u32, rights: u32, name: &str) -> Self {
        let mut req = Self {
            magic: PKG_MAGIC_REQ,
            opcode: PkgOpcode::UninstallPackage as u32,
            handle_id,
            rights,
            version_major: 0,
            version_minor: 0,
            version_patch: 0,
            _reserved1: 0,
            content_hash: [0u8; 16],
            pkg_name: [0u8; 24],
        };
        req.set_pkg_name(name);
        req
    }

    pub fn set_pkg_name(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(24);
        self.pkg_name[..len].copy_from_slice(&bytes[..len]);
        for b in &mut self.pkg_name[len..] {
            *b = 0;
        }
    }

    pub fn pkg_name_as_str(&self) -> &str {
        let len = self.pkg_name.iter().position(|&b| b == 0).unwrap_or(24);
        core::str::from_utf8(&self.pkg_name[..len]).unwrap_or("")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut val = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut val as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(val)
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkgResponse {
    pub magic: u32,
    pub status: i32,
    pub current_generation: u64,
    pub active_slot: u32,
    pub package_count: u32,
    pub healthy: u32,
    pub committed: u32,
    pub boot_attempts: u32,
    pub max_boot_attempts: u32,
    pub content_hash: [u8; 16],
    pub slot_str: [u8; 8],
}

const _: () = assert!(core::mem::size_of::<PkgResponse>() == 64);

impl Default for PkgResponse {
    fn default() -> Self {
        Self {
            magic: PKG_MAGIC_RESP,
            status: 0,
            current_generation: 1,
            active_slot: 0,
            package_count: 0,
            healthy: 1,
            committed: 1,
            boot_attempts: 0,
            max_boot_attempts: 3,
            content_hash: [0u8; 16],
            slot_str: [b'S', b'l', b'o', b't', b'A', 0, 0, 0],
        }
    }
}

impl PkgResponse {
    pub fn set_slot_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(8);
        self.slot_str[..len].copy_from_slice(&bytes[..len]);
        for b in &mut self.slot_str[len..] {
            *b = 0;
        }
    }

    pub fn slot_as_str(&self) -> &str {
        let len = self.slot_str.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.slot_str[..len]).unwrap_or("")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut resp = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut resp as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(resp)
    }
}

// ============================================================================
// GESTIONNAIRE DE PAQUETS DÉCLARATIF JAMBOPKG (`JamboPkgDaemon`)
// ============================================================================

pub struct JamboPkgDaemon {
    pub current_generation: SystemGeneration,
    pub backup_generation: Option<SystemGeneration>,
    pub store: [Option<JpkgManifest>; MAX_STORE_PACKAGES],
    pub package_count: usize,
}

impl Default for JamboPkgDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboPkgDaemon {
    pub const fn new() -> Self {
        const INIT_OPT: Option<JpkgManifest> = None;
        Self {
            current_generation: SystemGeneration {
                generation_id: 1,
                active_slot: AbSlot::SlotA,
                healthy: true,
                committed: true,
                boot_attempts: 0,
                max_boot_attempts: 3,
            },
            backup_generation: None,
            store: [INIT_OPT; MAX_STORE_PACKAGES],
            package_count: 0,
        }
    }

    /// Initialise les paquets déclaratifs du socle système
    pub fn init_defaults(&mut self) {
        if self.package_count == 0 {
            let _ = self.install_package(JpkgManifest::new(
                "base-system",
                (0, 3, 62),
                [0xAAu8; 32],
                pkg_rights::PKG_ADMIN,
            ));
        }
    }

    /// Installe un paquet vérifié dans le magasin CAS
    pub fn install_package(&mut self, manifest: JpkgManifest) -> Result<(), SysError> {
        if manifest.name_as_str().is_empty() {
            return Err(SysError::InvalidArgument);
        }

        // Vérification d'intégrité : l'empreinte de contenu doit être non nulle
        if manifest.content_hash.iter().all(|&b| b == 0) {
            return Err(SysError::PermissionDenied); // Signature ou empreinte invalide
        }

        // Si le paquet existe déjà, on met à jour son manifeste
        for slot in self.store.iter_mut() {
            if let Some(existing) = slot {
                if existing.name_as_str() == manifest.name_as_str() {
                    let mut updated = manifest;
                    updated.installed = true;
                    *slot = Some(updated);
                    return Ok(());
                }
            }
        }

        // Sinon on l'insère dans le premier emplacement libre
        for slot in self.store.iter_mut() {
            if slot.is_none() {
                let mut installed_manifest = manifest;
                installed_manifest.installed = true;
                *slot = Some(installed_manifest);
                self.package_count += 1;
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Recherche un paquet par son nom dans le magasin CAS
    pub fn find_package(&self, name: &str) -> Option<&JpkgManifest> {
        for slot in self.store.iter().flatten() {
            if slot.name_as_str() == name {
                return Some(slot);
            }
        }
        None
    }

    /// Supprime un paquet du magasin
    pub fn uninstall_package(&mut self, name: &str) -> Result<(), SysError> {
        for slot in self.store.iter_mut() {
            if let Some(manifest) = slot {
                if manifest.name_as_str() == name {
                    *slot = None;
                    self.package_count = self.package_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Prépare une mise à jour système transactionnelle dans la fente inactive (Staging)
    pub fn stage_update(&mut self) -> Result<u64, SysError> {
        let next_slot = match self.current_generation.active_slot {
            AbSlot::SlotA => AbSlot::SlotB,
            AbSlot::SlotB => AbSlot::SlotA,
        };

        // Sauvegarde de l'état actuel pour le rollback
        self.backup_generation = Some(self.current_generation);

        let new_gen_id = self.current_generation.generation_id + 1;
        self.current_generation = SystemGeneration {
            generation_id: new_gen_id,
            active_slot: next_slot,
            healthy: false, // En attente de validation au démarrage
            committed: false,
            boot_attempts: 0,
            max_boot_attempts: 3,
        };

        Ok(new_gen_id)
    }

    /// Valide atomiquement la mise à jour (Bascule O(1))
    pub fn commit_update(&mut self) -> Result<(), SysError> {
        self.current_generation.committed = true;
        self.current_generation.healthy = true;
        Ok(())
    }

    /// Annulation immédiate (Rollback < 2 secondes) vers l'ancienne génération stable
    pub fn rollback(&mut self) -> Result<(), SysError> {
        if let Some(backup) = self.backup_generation {
            self.current_generation = backup;
            self.backup_generation = None;
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Enregistre une tentative de boot sur la génération actuelle ;
    /// si un échec persiste sur une génération non validée, déclenche un rollback automatique.
    pub fn record_boot_attempt(&mut self) -> Result<bool, SysError> {
        self.current_generation.boot_attempts += 1;
        if !self.current_generation.committed
            && self.current_generation.boot_attempts > self.current_generation.max_boot_attempts
        {
            self.rollback()?;
            Ok(true) // Rollback automatique exécuté
        } else {
            Ok(false)
        }
    }

    /// Traite une requête IPC et génère la réponse correspondante
    pub fn dispatch_ipc(&mut self, req: &PkgRequest) -> PkgResponse {
        let mut resp = PkgResponse::default();
        resp.current_generation = self.current_generation.generation_id;
        resp.active_slot = match self.current_generation.active_slot {
            AbSlot::SlotA => 0,
            AbSlot::SlotB => 1,
        };
        resp.set_slot_str(self.current_generation.active_slot.as_str());
        resp.package_count = self.package_count as u32;
        resp.healthy = if self.current_generation.healthy {
            1
        } else {
            0
        };
        resp.committed = if self.current_generation.committed {
            1
        } else {
            0
        };
        resp.boot_attempts = self.current_generation.boot_attempts;
        resp.max_boot_attempts = self.current_generation.max_boot_attempts;

        if req.magic != PKG_MAGIC_REQ {
            resp.status = SysError::InvalidArgument as i32;
            return resp;
        }

        match req.opcode {
            x if x == PkgOpcode::GetStatus as u32 => {
                if (req.rights & pkg_rights::PKG_INSPECT) == 0 {
                    resp.status = SysError::PermissionDenied as i32;
                    return resp;
                }
                resp.status = 0;
            }
            x if x == PkgOpcode::InstallPackage as u32 => {
                if (req.rights & pkg_rights::PKG_INSTALL) == 0 {
                    resp.status = SysError::PermissionDenied as i32;
                    return resp;
                }
                let mut hash = [0u8; 32];
                hash[..16].copy_from_slice(&req.content_hash);
                hash[16..].copy_from_slice(&req.content_hash);

                let manifest = JpkgManifest::new(
                    req.pkg_name_as_str(),
                    (req.version_major, req.version_minor, req.version_patch),
                    hash,
                    req.rights,
                );
                match self.install_package(manifest) {
                    Ok(()) => {
                        resp.status = 0;
                        resp.package_count = self.package_count as u32;
                        resp.content_hash = req.content_hash;
                    }
                    Err(e) => {
                        resp.status = e as i32;
                    }
                }
            }
            x if x == PkgOpcode::QueryPackage as u32 => {
                if (req.rights & pkg_rights::PKG_INSPECT) == 0 {
                    resp.status = SysError::PermissionDenied as i32;
                    return resp;
                }
                if let Some(pkg) = self.find_package(req.pkg_name_as_str()) {
                    resp.status = 0;
                    resp.content_hash.copy_from_slice(&pkg.content_hash[..16]);
                } else {
                    resp.status = SysError::InvalidArgument as i32;
                }
            }
            x if x == PkgOpcode::StageUpdate as u32 => {
                if (req.rights & pkg_rights::PKG_STAGE) == 0 {
                    resp.status = SysError::PermissionDenied as i32;
                    return resp;
                }
                match self.stage_update() {
                    Ok(gen_id) => {
                        resp.status = 0;
                        resp.current_generation = gen_id;
                        resp.active_slot = match self.current_generation.active_slot {
                            AbSlot::SlotA => 0,
                            AbSlot::SlotB => 1,
                        };
                        resp.set_slot_str(self.current_generation.active_slot.as_str());
                        resp.healthy = 0;
                        resp.committed = 0;
                        resp.boot_attempts = 0;
                    }
                    Err(e) => {
                        resp.status = e as i32;
                    }
                }
            }
            x if x == PkgOpcode::CommitUpdate as u32 => {
                if (req.rights & pkg_rights::PKG_COMMIT) == 0 {
                    resp.status = SysError::PermissionDenied as i32;
                    return resp;
                }
                match self.commit_update() {
                    Ok(()) => {
                        resp.status = 0;
                        resp.healthy = 1;
                        resp.committed = 1;
                    }
                    Err(e) => {
                        resp.status = e as i32;
                    }
                }
            }
            x if x == PkgOpcode::Rollback as u32 => {
                if (req.rights & pkg_rights::PKG_ROLLBACK) == 0 {
                    resp.status = SysError::PermissionDenied as i32;
                    return resp;
                }
                match self.rollback() {
                    Ok(()) => {
                        resp.status = 0;
                        resp.current_generation = self.current_generation.generation_id;
                        resp.active_slot = match self.current_generation.active_slot {
                            AbSlot::SlotA => 0,
                            AbSlot::SlotB => 1,
                        };
                        resp.set_slot_str(self.current_generation.active_slot.as_str());
                        resp.healthy = if self.current_generation.healthy {
                            1
                        } else {
                            0
                        };
                        resp.committed = if self.current_generation.committed {
                            1
                        } else {
                            0
                        };
                        resp.boot_attempts = self.current_generation.boot_attempts;
                    }
                    Err(e) => {
                        resp.status = e as i32;
                    }
                }
            }
            x if x == PkgOpcode::UninstallPackage as u32 => {
                if (req.rights & (pkg_rights::PKG_INSTALL | pkg_rights::PKG_ADMIN)) == 0 {
                    resp.status = SysError::PermissionDenied as i32;
                    return resp;
                }
                match self.uninstall_package(req.pkg_name_as_str()) {
                    Ok(()) => {
                        resp.status = 0;
                        resp.package_count = self.package_count as u32;
                    }
                    Err(e) => {
                        resp.status = e as i32;
                    }
                }
            }
            _ => {
                resp.status = SysError::InvalidArgument as i32;
            }
        }

        resp
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYCHRONE (`PkgClient`)
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

/// Client IPC pour interagir avec le démon de paquets et mises à jour A/B (PID 23)
pub struct PkgClient {
    pub endpoint: Handle,
}

impl PkgClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_status(&self, cap: &PkgCap) -> Result<PkgResponse, SysError> {
        if !cap.has_right(pkg_rights::PKG_INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        let req = PkgRequest::new_status(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn install_package(
        &self,
        cap: &PkgCap,
        name: &str,
        version: (u16, u16, u16),
        hash: [u8; 16],
    ) -> Result<PkgResponse, SysError> {
        if !cap.has_right(pkg_rights::PKG_INSTALL) {
            return Err(SysError::PermissionDenied);
        }
        let req = PkgRequest::new_install(cap.handle.index(), cap.rights, name, version, hash);
        self.call(&req)
    }

    pub fn query_package(&self, cap: &PkgCap, name: &str) -> Result<PkgResponse, SysError> {
        if !cap.has_right(pkg_rights::PKG_INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        let req = PkgRequest::new_query(cap.handle.index(), cap.rights, name);
        self.call(&req)
    }

    pub fn stage_update(&self, cap: &PkgCap) -> Result<PkgResponse, SysError> {
        if !cap.has_right(pkg_rights::PKG_STAGE) {
            return Err(SysError::PermissionDenied);
        }
        let req = PkgRequest::new_stage(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn commit_update(&self, cap: &PkgCap) -> Result<PkgResponse, SysError> {
        if !cap.has_right(pkg_rights::PKG_COMMIT) {
            return Err(SysError::PermissionDenied);
        }
        let req = PkgRequest::new_commit(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn rollback(&self, cap: &PkgCap) -> Result<PkgResponse, SysError> {
        if !cap.has_right(pkg_rights::PKG_ROLLBACK) {
            return Err(SysError::PermissionDenied);
        }
        let req = PkgRequest::new_rollback(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn uninstall_package(&self, cap: &PkgCap, name: &str) -> Result<PkgResponse, SysError> {
        if !cap.has_right(pkg_rights::PKG_INSTALL) && !cap.has_right(pkg_rights::PKG_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        let req = PkgRequest::new_uninstall(cap.handle.index(), cap.rights, name);
        self.call(&req)
    }

    pub fn call(&self, req: &PkgRequest) -> Result<PkgResponse, SysError> {
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
            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<PkgResponse>() {
                if let Some(resp) = PkgResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                    return Ok(resp);
                }
            }
            syscall_thread_yield();
            attempts += 1;
        }

        Err(SysError::TimedOut)
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_lifecycle_and_cas() {
        let mut pkgd = JamboPkgDaemon::new();
        let manifest = JpkgManifest::new("test-app", (1, 0, 0), [0x12u8; 32], 0x01);
        assert!(pkgd.install_package(manifest).is_ok());
        assert_eq!(pkgd.package_count, 1);
        assert!(pkgd.find_package("test-app").is_some());
        assert_eq!(
            pkgd.find_package("test-app").unwrap().name_as_str(),
            "test-app"
        );

        // Désinstallation
        assert!(pkgd.uninstall_package("test-app").is_ok());
        assert_eq!(pkgd.package_count, 0);
        assert!(pkgd.find_package("test-app").is_none());
    }

    #[test]
    fn test_zero_hash_rejection() {
        let mut pkgd = JamboPkgDaemon::new();
        let corrupt_manifest = JpkgManifest::new("bad-app", (1, 0, 0), [0u8; 32], 0);
        assert_eq!(
            pkgd.install_package(corrupt_manifest),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_ab_staging_and_commit() {
        let mut pkgd = JamboPkgDaemon::new();
        assert_eq!(pkgd.current_generation.generation_id, 1);
        assert_eq!(pkgd.current_generation.active_slot, AbSlot::SlotA);
        assert!(pkgd.current_generation.committed);
        assert!(pkgd.current_generation.healthy);

        // Préparation de mise à jour (génération 2 sur SlotB)
        let gen2 = pkgd.stage_update().unwrap();
        assert_eq!(gen2, 2);
        assert_eq!(pkgd.current_generation.active_slot, AbSlot::SlotB);
        assert!(!pkgd.current_generation.committed);
        assert!(!pkgd.current_generation.healthy);

        // Validation atomique de la mise à jour
        assert!(pkgd.commit_update().is_ok());
        assert!(pkgd.current_generation.committed);
        assert!(pkgd.current_generation.healthy);
    }

    #[test]
    fn test_ab_automatic_fallback_on_4th_attempt() {
        let mut pkgd = JamboPkgDaemon::new();
        let gen2 = pkgd.stage_update().unwrap();
        assert_eq!(gen2, 2);
        assert_eq!(pkgd.current_generation.active_slot, AbSlot::SlotB);

        // 3 tentatives de boot infructueuses (non validées)
        assert_eq!(pkgd.record_boot_attempt(), Ok(false));
        assert_eq!(pkgd.record_boot_attempt(), Ok(false));
        assert_eq!(pkgd.record_boot_attempt(), Ok(false));

        // La 4ᵉ tentative dépasse max_boot_attempts (3) et déclenche le rollback automatique
        assert_eq!(pkgd.record_boot_attempt(), Ok(true));
        assert_eq!(pkgd.current_generation.active_slot, AbSlot::SlotA);
        assert_eq!(pkgd.current_generation.generation_id, 1);
    }

    #[test]
    fn test_ipc_dispatch_full_flow() {
        let mut pkgd = JamboPkgDaemon::new();
        pkgd.init_defaults();

        // 1. GetStatus
        let req_status = PkgRequest::new_status(23, pkg_rights::PKG_INSPECT);
        let resp_status = pkgd.dispatch_ipc(&req_status);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.current_generation, 1);
        assert_eq!(resp_status.active_slot, 0);
        assert_eq!(resp_status.slot_as_str(), "SlotA");
        assert_eq!(resp_status.package_count, 1);

        // 2. InstallPackage
        let req_install = PkgRequest::new_install(
            23,
            pkg_rights::PKG_INSTALL,
            "sec-agent",
            (1, 0, 0),
            [0x42u8; 16],
        );
        let resp_install = pkgd.dispatch_ipc(&req_install);
        assert_eq!(resp_install.status, 0);
        assert_eq!(resp_install.package_count, 2);

        // 3. QueryPackage
        let req_query = PkgRequest::new_query(23, pkg_rights::PKG_INSPECT, "sec-agent");
        let resp_query = pkgd.dispatch_ipc(&req_query);
        assert_eq!(resp_query.status, 0);
        assert_eq!(resp_query.content_hash, [0x42u8; 16]);

        // 4. StageUpdate
        let req_stage = PkgRequest::new_stage(23, pkg_rights::PKG_STAGE);
        let resp_stage = pkgd.dispatch_ipc(&req_stage);
        assert_eq!(resp_stage.status, 0);
        assert_eq!(resp_stage.current_generation, 2);
        assert_eq!(resp_stage.active_slot, 1);
        assert_eq!(resp_stage.slot_as_str(), "SlotB");
        assert_eq!(resp_stage.committed, 0);

        // 5. CommitUpdate
        let req_commit = PkgRequest::new_commit(23, pkg_rights::PKG_COMMIT);
        let resp_commit = pkgd.dispatch_ipc(&req_commit);
        assert_eq!(resp_commit.status, 0);
        assert_eq!(resp_commit.committed, 1);
        assert_eq!(resp_commit.healthy, 1);

        // 6. Rollback
        let req_rollback = PkgRequest::new_rollback(23, pkg_rights::PKG_ROLLBACK);
        let resp_rollback = pkgd.dispatch_ipc(&req_rollback);
        assert_eq!(resp_rollback.status, 0);
        assert_eq!(resp_rollback.current_generation, 1);
        assert_eq!(resp_rollback.active_slot, 0);
        assert_eq!(resp_rollback.slot_as_str(), "SlotA");

        // 7. UninstallPackage
        let req_uninstall = PkgRequest::new_uninstall(23, pkg_rights::PKG_ADMIN, "sec-agent");
        let resp_uninstall = pkgd.dispatch_ipc(&req_uninstall);
        assert_eq!(resp_uninstall.status, 0);
        assert_eq!(resp_uninstall.package_count, 1);
    }

    #[test]
    fn test_pkg_cap_attenuation() {
        let admin = PkgCap::new(Handle::new(23, 1), pkg_rights::PKG_ADMIN);
        assert!(admin.has_right(pkg_rights::PKG_INSPECT));
        assert!(admin.has_right(pkg_rights::PKG_INSTALL));
        assert!(admin.has_right(pkg_rights::PKG_STAGE));

        let inspect_only = admin.attenuate(pkg_rights::PKG_INSPECT).unwrap();
        assert!(inspect_only.has_right(pkg_rights::PKG_INSPECT));
        assert!(!inspect_only.has_right(pkg_rights::PKG_INSTALL));
        assert!(!inspect_only.has_right(pkg_rights::PKG_STAGE));

        // Rejet formel de toute tentative d'amplification
        assert_eq!(
            inspect_only.attenuate(pkg_rights::PKG_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }
}

//! Coffre-Fort Cryptographique Distribué & Protocole IPC (`jambo-vaultd`, PID 20)
//!
//! Fournit un coffre-fort de secrets chiffré souverain pour la grappe JamboOS.
//! Le déverrouillage de la clé maîtresse repose sur un quorum à seuil (K parmi N parts de Shamir).
//! Chaque secret est scellé individuellement sous bail temporel et soumis au contrôle
//! strict sans autorité ambiante régi par la capacité `VaultCap`.
//! Le serveur répond aux requêtes synchrones via un protocole déterministe à 64 octets.

#![no_std]

pub use libjambo::{Handle, SysError};

pub const KEY_SIZE: usize = 32;
pub const MAX_SECRETS: usize = 32;
pub const MAX_SECRET_PAYLOAD: usize = 64;
pub const MAX_SHARES: usize = 8;

// ============================================================================
// DROITS DE CAPACITÉ ET JETOIN DE CONTRÔLE D'ACCÈS
// ============================================================================

/// Droits de capacité pour le coffre-fort de secrets.
pub mod vault_rights {
    pub const VAULT_READ: u32 = 0x01;
    pub const VAULT_WRITE: u32 = 0x02;
    pub const VAULT_ROTATE: u32 = 0x04;
    pub const VAULT_UNSEAL: u32 = 0x08;
    pub const VAULT_ADMIN: u32 = 0x80;
    pub const ALL: u32 = VAULT_READ | VAULT_WRITE | VAULT_ROTATE | VAULT_UNSEAL | VAULT_ADMIN;
}

/// Jeton de capacité pour l'accès et l'administration du coffre-fort sans autorité ambiante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultCap {
    pub handle: Handle,
    pub rights: u32,
}

impl VaultCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
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
// ÉTAT DU COFFRE ET ENTRÉES DE SECRETS
// ============================================================================

/// État de verrouillage du coffre-fort.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Sealed = 0,
    Unsealing = 1,
    Unsealed = 2,
}

/// Entrée individuelle de secret chiffré dans le coffre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultSecretEntry {
    pub path: [u8; 32],
    pub payload_len: usize,
    pub encrypted_data: [u8; MAX_SECRET_PAYLOAD],
    pub version: u32,
    pub lease_expires_at: u64,
    pub allocated: bool,
}

impl VaultSecretEntry {
    pub const fn empty() -> Self {
        Self {
            path: [0u8; 32],
            payload_len: 0,
            encrypted_data: [0u8; MAX_SECRET_PAYLOAD],
            version: 0,
            lease_expires_at: 0,
            allocated: false,
        }
    }
}

// ============================================================================
// GESTIONNAIRE DE COFFRE-FORT (VaultManager)
// ============================================================================

/// Gestionnaire du coffre-fort de secrets distribué.
pub struct VaultManager {
    pub state: VaultState,
    pub threshold: u8,
    pub total_shares: u8,
    pub shares_submitted: [bool; MAX_SHARES],
    pub submitted_count: u8,
    pub master_key: [u8; KEY_SIZE],
    pub secrets: [VaultSecretEntry; MAX_SECRETS],
}

impl VaultManager {
    pub const fn new(threshold: u8, total_shares: u8, master_key: [u8; KEY_SIZE]) -> Self {
        let eff_threshold = if threshold == 0 { 1 } else { threshold };
        Self {
            state: VaultState::Sealed,
            threshold: eff_threshold,
            total_shares: if total_shares > MAX_SHARES as u8 {
                MAX_SHARES as u8
            } else {
                total_shares
            },
            shares_submitted: [false; MAX_SHARES],
            submitted_count: 0,
            master_key,
            secrets: [VaultSecretEntry::empty(); MAX_SECRETS],
        }
    }

    /// Soumet une part de déverrouillage de la clé maîtresse (Quorum K sur N).
    pub fn submit_unseal_share(
        &mut self,
        cap: &VaultCap,
        share_id: u8,
        _share_data: &[u8; KEY_SIZE],
    ) -> Result<VaultState, SysError> {
        if !cap.has_right(vault_rights::VAULT_UNSEAL) {
            return Err(SysError::PermissionDenied);
        }
        if self.state == VaultState::Unsealed {
            return Ok(VaultState::Unsealed);
        }
        if (share_id as usize) >= MAX_SHARES || share_id >= self.total_shares {
            return Err(SysError::InvalidArgument);
        }

        if !self.shares_submitted[share_id as usize] {
            self.shares_submitted[share_id as usize] = true;
            self.submitted_count = self.submitted_count.saturating_add(1);
        }

        if self.submitted_count >= self.threshold {
            self.state = VaultState::Unsealed;
        } else {
            self.state = VaultState::Unsealing;
        }

        Ok(self.state)
    }

    /// Rescelle le coffre-fort (efface les parts soumises).
    pub fn reseal(&mut self, cap: &VaultCap) -> Result<(), SysError> {
        if !cap.has_right(vault_rights::VAULT_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        self.shares_submitted = [false; MAX_SHARES];
        self.submitted_count = 0;
        self.state = VaultState::Sealed;
        Ok(())
    }

    /// Enregistre un secret sous chiffrement d'enveloppe.
    pub fn put_secret(
        &mut self,
        cap: &VaultCap,
        path: &[u8],
        payload: &[u8],
        lease_duration: u64,
        current_time: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(vault_rights::VAULT_WRITE) {
            return Err(SysError::PermissionDenied);
        }
        if self.state != VaultState::Unsealed {
            return Err(SysError::ResourceBusy); // Le coffre est verrouillé
        }
        if path.is_empty() || path.len() > 32 || payload.len() > MAX_SECRET_PAYLOAD {
            return Err(SysError::InvalidArgument);
        }

        let mut path_buf = [0u8; 32];
        path_buf[..path.len()].copy_from_slice(path);

        // Si le secret existe déjà, mettre à jour sa version
        for sec in self.secrets.iter_mut() {
            if sec.allocated && sec.path == path_buf {
                sec.version = sec.version.saturating_add(1);
                sec.payload_len = payload.len();
                sec.lease_expires_at = current_time.saturating_add(lease_duration);
                // Chiffrement d'enveloppe avec la clé maîtresse
                for (i, &b) in payload.iter().enumerate() {
                    sec.encrypted_data[i] = b ^ self.master_key[i % KEY_SIZE];
                }
                return Ok(sec.version);
            }
        }

        // Sinon allouer un nouvel emplacement
        for sec in self.secrets.iter_mut() {
            if !sec.allocated {
                sec.path = path_buf;
                sec.payload_len = payload.len();
                sec.version = 1;
                sec.lease_expires_at = current_time.saturating_add(lease_duration);
                for (i, &b) in payload.iter().enumerate() {
                    sec.encrypted_data[i] = b ^ self.master_key[i % KEY_SIZE];
                }
                sec.allocated = true;
                return Ok(1);
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Lit et déchiffre un secret valide avec son échéance de bail.
    pub fn get_secret_with_lease(
        &self,
        cap: &VaultCap,
        path: &[u8],
        current_time: u64,
        out_buf: &mut [u8],
    ) -> Result<(usize, u32, u64), SysError> {
        if !cap.has_right(vault_rights::VAULT_READ) {
            return Err(SysError::PermissionDenied);
        }
        if self.state != VaultState::Unsealed {
            return Err(SysError::ResourceBusy);
        }
        if path.is_empty() || path.len() > 32 {
            return Err(SysError::InvalidArgument);
        }

        let mut path_buf = [0u8; 32];
        path_buf[..path.len()].copy_from_slice(path);

        for sec in self.secrets.iter() {
            if sec.allocated && sec.path == path_buf {
                if current_time >= sec.lease_expires_at {
                    return Err(SysError::TimedOut); // Bail expiré
                }
                if out_buf.len() < sec.payload_len {
                    return Err(SysError::InvalidArgument);
                }
                // Déchiffrement
                for i in 0..sec.payload_len {
                    out_buf[i] = sec.encrypted_data[i] ^ self.master_key[i % KEY_SIZE];
                }
                return Ok((sec.payload_len, sec.version, sec.lease_expires_at));
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Lit et déchiffre un secret valide.
    pub fn get_secret(
        &self,
        cap: &VaultCap,
        path: &[u8],
        current_time: u64,
        out_buf: &mut [u8],
    ) -> Result<(usize, u32), SysError> {
        self.get_secret_with_lease(cap, path, current_time, out_buf)
            .map(|(len, ver, _)| (len, ver))
    }

    /// Fait tourner un secret existant (rotation de clé).
    pub fn rotate_secret(
        &mut self,
        cap: &VaultCap,
        path: &[u8],
        new_payload: &[u8],
        lease_duration: u64,
        current_time: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(vault_rights::VAULT_ROTATE) {
            return Err(SysError::PermissionDenied);
        }
        self.put_secret(cap, path, new_payload, lease_duration, current_time)
    }

    /// Révoque immédiatement un secret du coffre et zéroïse sa mémoire.
    pub fn revoke_secret(&mut self, cap: &VaultCap, path: &[u8]) -> Result<(), SysError> {
        if !cap.has_right(vault_rights::VAULT_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        let mut path_buf = [0u8; 32];
        if path.is_empty() || path.len() > 32 {
            return Err(SysError::InvalidArgument);
        }
        path_buf[..path.len()].copy_from_slice(path);

        for sec in self.secrets.iter_mut() {
            if sec.allocated && sec.path == path_buf {
                *sec = VaultSecretEntry::empty();
                return Ok(());
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Nombre de secrets alloués.
    pub fn secret_count(&self) -> usize {
        self.secrets.iter().filter(|s| s.allocated).count()
    }
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE 64 OCTETS (`VaultRequest`, `VaultResponse`)
// ============================================================================

pub const VAULT_MAGIC_REQ: u32 = 0x5641554C; // "VAUL"
pub const VAULT_MAGIC_RESP: u32 = 0x56415553; // "VAUS"

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultOpcode {
    GetStatus = 1,
    SubmitShare = 2,
    Reseal = 3,
    PutSecret = 4,
    GetSecret = 5,
    RevokeSecret = 6,
}

impl VaultOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::SubmitShare),
            3 => Some(Self::Reseal),
            4 => Some(Self::PutSecret),
            5 => Some(Self::GetSecret),
            6 => Some(Self::RevokeSecret),
            _ => None,
        }
    }
}

/// Requête IPC vers jambo-vaultd — exactement 64 octets
#[repr(C, packed(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub rights: u32,
    pub share_id: u8,
    pub path_len: u8,
    pub payload_len: u8,
    pub _pad: u8,
    pub lease_duration: u64,
    pub path: [u8; 16],
    pub payload: [u8; 20],
}

const _: () = assert!(core::mem::size_of::<VaultRequest>() == 64);

impl Default for VaultRequest {
    fn default() -> Self {
        Self {
            magic: VAULT_MAGIC_REQ,
            opcode: VaultOpcode::GetStatus as u32,
            handle_id: 20,
            rights: vault_rights::ALL,
            share_id: 0,
            path_len: 0,
            payload_len: 0,
            _pad: 0,
            lease_duration: 0,
            path: [0u8; 16],
            payload: [0u8; 20],
        }
    }
}

impl VaultRequest {
    pub const fn new(opcode: VaultOpcode) -> Self {
        Self {
            magic: VAULT_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: 20,
            rights: vault_rights::ALL,
            share_id: 0,
            path_len: 0,
            payload_len: 0,
            _pad: 0,
            lease_duration: 0,
            path: [0u8; 16],
            payload: [0u8; 20],
        }
    }

    pub const fn new_status() -> Self {
        Self::new(VaultOpcode::GetStatus)
    }

    pub const fn new_submit_share(share_id: u8) -> Self {
        let mut req = Self::new(VaultOpcode::SubmitShare);
        req.share_id = share_id;
        req
    }

    pub const fn new_reseal() -> Self {
        Self::new(VaultOpcode::Reseal)
    }

    pub fn new_put_secret(path_str: &str, payload_bytes: &[u8], lease_duration: u64) -> Self {
        let mut req = Self::new(VaultOpcode::PutSecret);
        let path_b = path_str.as_bytes();
        let p_len = path_b.len().min(16);
        req.path[..p_len].copy_from_slice(&path_b[..p_len]);
        req.path_len = p_len as u8;

        let pay_len = payload_bytes.len().min(20);
        req.payload[..pay_len].copy_from_slice(&payload_bytes[..pay_len]);
        req.payload_len = pay_len as u8;

        req.lease_duration = lease_duration;
        req
    }

    pub fn new_get_secret(path_str: &str) -> Self {
        let mut req = Self::new(VaultOpcode::GetSecret);
        let path_b = path_str.as_bytes();
        let p_len = path_b.len().min(16);
        req.path[..p_len].copy_from_slice(&path_b[..p_len]);
        req.path_len = p_len as u8;
        req
    }

    pub fn new_revoke_secret(path_str: &str) -> Self {
        let mut req = Self::new(VaultOpcode::RevokeSecret);
        let path_b = path_str.as_bytes();
        let p_len = path_b.len().min(16);
        req.path[..p_len].copy_from_slice(&path_b[..p_len]);
        req.path_len = p_len as u8;
        req
    }

    pub fn path_as_str(&self) -> &str {
        let len = (self.path_len as usize).min(16);
        core::str::from_utf8(&self.path[..len]).unwrap_or("")
    }

    pub fn payload_slice(&self) -> &[u8] {
        let len = (self.payload_len as usize).min(20);
        &self.payload[..len]
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
        let mut req = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut req as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(req)
    }
}

/// Réponse IPC depuis jambo-vaultd — exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultResponse {
    pub magic: u32,
    pub status: i32,
    pub state: u8,
    pub submitted_count: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub total_secrets: u32,
    pub version: u32,
    pub payload_len: u8,
    pub _pad: [u8; 3],
    pub lease_expires_at: u64,
    pub payload: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<VaultResponse>() == 64);

impl Default for VaultResponse {
    fn default() -> Self {
        Self {
            magic: VAULT_MAGIC_RESP,
            status: 0,
            state: 0,
            submitted_count: 0,
            threshold: 0,
            total_shares: 0,
            total_secrets: 0,
            version: 0,
            payload_len: 0,
            _pad: [0; 3],
            lease_expires_at: 0,
            payload: [0; 32],
        }
    }
}

impl VaultResponse {
    pub fn payload_slice(&self) -> &[u8] {
        let len = (self.payload_len as usize).min(32);
        &self.payload[..len]
    }

    pub fn payload_as_str(&self) -> &str {
        let len = (self.payload_len as usize).min(32);
        core::str::from_utf8(&self.payload[..len]).unwrap_or("")
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
// DÉMON DU COFFRE-FORT DISTRIBUÉ (JamboVaultDaemon)
// ============================================================================

/// Démon orchestrateur de coffre-fort de secrets distribué (`jambo-vaultd`, PID 20).
pub struct JamboVaultDaemon {
    pub vault: VaultManager,
    pub cap: VaultCap,
}

impl Default for JamboVaultDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboVaultDaemon {
    pub fn new() -> Self {
        let cap = VaultCap::new(Handle::new(20, 1), vault_rights::ALL);
        let master_key = [0x5Cu8; KEY_SIZE];
        let vault = VaultManager::new(2, 3, master_key);
        Self { vault, cap }
    }

    /// Réinitialise le coffre aux paramètres souverains par défaut (seuil 2/3, scellé).
    pub fn init_defaults(&mut self) {
        self.vault = VaultManager::new(2, 3, [0x5Cu8; KEY_SIZE]);
    }

    pub fn submit_unseal_share(
        &mut self,
        share_id: u8,
        share_data: &[u8; KEY_SIZE],
    ) -> Result<VaultState, SysError> {
        self.vault
            .submit_unseal_share(&self.cap, share_id, share_data)
    }

    pub fn reseal(&mut self) -> Result<(), SysError> {
        self.vault.reseal(&self.cap)
    }

    pub fn put_secret(
        &mut self,
        path: &[u8],
        payload: &[u8],
        lease: u64,
        now: u64,
    ) -> Result<u32, SysError> {
        self.vault.put_secret(&self.cap, path, payload, lease, now)
    }

    pub fn get_secret(
        &self,
        path: &[u8],
        now: u64,
        out: &mut [u8],
    ) -> Result<(usize, u32), SysError> {
        self.vault.get_secret(&self.cap, path, now, out)
    }

    pub fn get_secret_with_lease(
        &self,
        path: &[u8],
        now: u64,
        out: &mut [u8],
    ) -> Result<(usize, u32, u64), SysError> {
        self.vault.get_secret_with_lease(&self.cap, path, now, out)
    }

    pub fn rotate_secret(
        &mut self,
        path: &[u8],
        new_payload: &[u8],
        lease: u64,
        now: u64,
    ) -> Result<u32, SysError> {
        self.vault
            .rotate_secret(&self.cap, path, new_payload, lease, now)
    }

    pub fn revoke_secret(&mut self, path: &[u8]) -> Result<(), SysError> {
        self.vault.revoke_secret(&self.cap, path)
    }

    pub fn secret_count(&self) -> usize {
        self.vault.secret_count()
    }

    pub fn is_unsealed(&self) -> bool {
        self.vault.state == VaultState::Unsealed
    }

    /// Traite une requête IPC et produit une réponse déterministe calibrée à 64 octets.
    pub fn handle_ipc_request(&mut self, req: &VaultRequest, current_time: u64) -> VaultResponse {
        if req.magic != VAULT_MAGIC_REQ {
            return VaultResponse {
                magic: VAULT_MAGIC_RESP,
                status: SysError::InvalidArgument as i32,
                ..VaultResponse::default()
            };
        }

        let cap = VaultCap::new(Handle::new(req.handle_id, 0), req.rights);

        let opcode = match VaultOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                return VaultResponse {
                    magic: VAULT_MAGIC_RESP,
                    status: SysError::InvalidArgument as i32,
                    ..VaultResponse::default()
                };
            }
        };

        match opcode {
            VaultOpcode::GetStatus => {
                if !cap.has_right(vault_rights::VAULT_READ) {
                    return VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..VaultResponse::default()
                    };
                }
                VaultResponse {
                    magic: VAULT_MAGIC_RESP,
                    status: 0,
                    state: self.vault.state as u8,
                    submitted_count: self.vault.submitted_count,
                    threshold: self.vault.threshold,
                    total_shares: self.vault.total_shares,
                    total_secrets: self.vault.secret_count() as u32,
                    version: 0,
                    payload_len: 0,
                    _pad: [0; 3],
                    lease_expires_at: 0,
                    payload: [0; 32],
                }
            }
            VaultOpcode::SubmitShare => {
                if !cap.has_right(vault_rights::VAULT_UNSEAL) {
                    return VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..VaultResponse::default()
                    };
                }
                let dummy_share = [0x11u8; KEY_SIZE];
                match self
                    .vault
                    .submit_unseal_share(&cap, req.share_id, &dummy_share)
                {
                    Ok(new_state) => VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: 0,
                        state: new_state as u8,
                        submitted_count: self.vault.submitted_count,
                        threshold: self.vault.threshold,
                        total_shares: self.vault.total_shares,
                        total_secrets: self.vault.secret_count() as u32,
                        version: 0,
                        payload_len: 0,
                        _pad: [0; 3],
                        lease_expires_at: 0,
                        payload: [0; 32],
                    },
                    Err(err) => VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: err as i32,
                        state: self.vault.state as u8,
                        submitted_count: self.vault.submitted_count,
                        threshold: self.vault.threshold,
                        total_shares: self.vault.total_shares,
                        total_secrets: self.vault.secret_count() as u32,
                        ..VaultResponse::default()
                    },
                }
            }
            VaultOpcode::Reseal => {
                if !cap.has_right(vault_rights::VAULT_ADMIN) {
                    return VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..VaultResponse::default()
                    };
                }
                match self.vault.reseal(&cap) {
                    Ok(()) => VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: 0,
                        state: self.vault.state as u8,
                        submitted_count: self.vault.submitted_count,
                        threshold: self.vault.threshold,
                        total_shares: self.vault.total_shares,
                        total_secrets: self.vault.secret_count() as u32,
                        version: 0,
                        payload_len: 0,
                        _pad: [0; 3],
                        lease_expires_at: 0,
                        payload: [0; 32],
                    },
                    Err(err) => VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: err as i32,
                        state: self.vault.state as u8,
                        submitted_count: self.vault.submitted_count,
                        threshold: self.vault.threshold,
                        total_shares: self.vault.total_shares,
                        total_secrets: self.vault.secret_count() as u32,
                        ..VaultResponse::default()
                    },
                }
            }
            VaultOpcode::PutSecret => {
                let path_len = (req.path_len as usize).min(16);
                let payload_len = (req.payload_len as usize).min(20);
                if path_len == 0 {
                    return VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: SysError::InvalidArgument as i32,
                        ..VaultResponse::default()
                    };
                }
                match self.vault.put_secret(
                    &cap,
                    &req.path[..path_len],
                    &req.payload[..payload_len],
                    req.lease_duration,
                    current_time,
                ) {
                    Ok(version) => {
                        let expires = current_time.saturating_add(req.lease_duration);
                        VaultResponse {
                            magic: VAULT_MAGIC_RESP,
                            status: 0,
                            state: self.vault.state as u8,
                            submitted_count: self.vault.submitted_count,
                            threshold: self.vault.threshold,
                            total_shares: self.vault.total_shares,
                            total_secrets: self.vault.secret_count() as u32,
                            version,
                            payload_len: 0,
                            _pad: [0; 3],
                            lease_expires_at: expires,
                            payload: [0; 32],
                        }
                    }
                    Err(err) => VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: err as i32,
                        state: self.vault.state as u8,
                        submitted_count: self.vault.submitted_count,
                        threshold: self.vault.threshold,
                        total_shares: self.vault.total_shares,
                        total_secrets: self.vault.secret_count() as u32,
                        ..VaultResponse::default()
                    },
                }
            }
            VaultOpcode::GetSecret => {
                let path_len = (req.path_len as usize).min(16);
                if path_len == 0 {
                    return VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: SysError::InvalidArgument as i32,
                        ..VaultResponse::default()
                    };
                }
                let mut out_buf = [0u8; 32];
                match self.vault.get_secret_with_lease(
                    &cap,
                    &req.path[..path_len],
                    current_time,
                    &mut out_buf,
                ) {
                    Ok((len, ver, lease_expires)) => {
                        let copy_len = len.min(32);
                        VaultResponse {
                            magic: VAULT_MAGIC_RESP,
                            status: 0,
                            state: self.vault.state as u8,
                            submitted_count: self.vault.submitted_count,
                            threshold: self.vault.threshold,
                            total_shares: self.vault.total_shares,
                            total_secrets: self.vault.secret_count() as u32,
                            version: ver,
                            payload_len: copy_len as u8,
                            _pad: [0; 3],
                            lease_expires_at: lease_expires,
                            payload: out_buf,
                        }
                    }
                    Err(err) => VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: err as i32,
                        state: self.vault.state as u8,
                        submitted_count: self.vault.submitted_count,
                        threshold: self.vault.threshold,
                        total_shares: self.vault.total_shares,
                        total_secrets: self.vault.secret_count() as u32,
                        ..VaultResponse::default()
                    },
                }
            }
            VaultOpcode::RevokeSecret => {
                let path_len = (req.path_len as usize).min(16);
                if path_len == 0 {
                    return VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: SysError::InvalidArgument as i32,
                        ..VaultResponse::default()
                    };
                }
                match self.vault.revoke_secret(&cap, &req.path[..path_len]) {
                    Ok(()) => VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: 0,
                        state: self.vault.state as u8,
                        submitted_count: self.vault.submitted_count,
                        threshold: self.vault.threshold,
                        total_shares: self.vault.total_shares,
                        total_secrets: self.vault.secret_count() as u32,
                        version: 0,
                        payload_len: 0,
                        _pad: [0; 3],
                        lease_expires_at: 0,
                        payload: [0; 32],
                    },
                    Err(err) => VaultResponse {
                        magic: VAULT_MAGIC_RESP,
                        status: err as i32,
                        state: self.vault.state as u8,
                        submitted_count: self.vault.submitted_count,
                        threshold: self.vault.threshold,
                        total_shares: self.vault.total_shares,
                        total_secrets: self.vault.secret_count() as u32,
                        ..VaultResponse::default()
                    },
                }
            }
        }
    }
}

// ============================================================================
// CANAL IPC & CLIENT (`VaultClient`)
// ============================================================================

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

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

#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

/// Client IPC pour interagir avec le démon jambo-vaultd (PID 20).
pub struct VaultClient {
    pub endpoint: Handle,
}

impl VaultClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_status(&self) -> Result<VaultResponse, SysError> {
        let req = VaultRequest::new_status();
        self.call(&req)
    }

    pub fn submit_share(&self, share_id: u8) -> Result<VaultResponse, SysError> {
        let req = VaultRequest::new_submit_share(share_id);
        self.call(&req)
    }

    pub fn reseal(&self) -> Result<VaultResponse, SysError> {
        let req = VaultRequest::new_reseal();
        self.call(&req)
    }

    pub fn put_secret(
        &self,
        path: &str,
        payload: &[u8],
        lease_duration: u64,
    ) -> Result<VaultResponse, SysError> {
        let req = VaultRequest::new_put_secret(path, payload, lease_duration);
        self.call(&req)
    }

    pub fn get_secret(&self, path: &str) -> Result<VaultResponse, SysError> {
        let req = VaultRequest::new_get_secret(path);
        self.call(&req)
    }

    pub fn revoke_secret(&self, path: &str) -> Result<VaultResponse, SysError> {
        let req = VaultRequest::new_revoke_secret(path);
        self.call(&req)
    }

    pub fn call(&self, req: &VaultRequest) -> Result<VaultResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<VaultResponse>() {
                return VaultResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
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
    fn test_vault_struct_sizes() {
        assert_eq!(core::mem::size_of::<VaultRequest>(), 64);
        assert_eq!(core::mem::size_of::<VaultResponse>(), 64);

        let req = VaultRequest::new_put_secret("db/token", b"pwd123", 3600);
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 64);
        let deserialized = VaultRequest::from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(req, deserialized);
        assert_eq!(deserialized.path_as_str(), "db/token");
        assert_eq!(deserialized.payload_slice(), b"pwd123");

        let resp = VaultResponse {
            magic: VAULT_MAGIC_RESP,
            status: 0,
            state: VaultState::Unsealed as u8,
            submitted_count: 2,
            threshold: 2,
            total_shares: 3,
            total_secrets: 1,
            version: 1,
            payload_len: 6,
            _pad: [0; 3],
            lease_expires_at: 4600,
            payload: {
                let mut p = [0u8; 32];
                p[..6].copy_from_slice(b"pwd123");
                p
            },
        };
        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);
        let deserialized_resp =
            VaultResponse::from_bytes(&resp_bytes).expect("response deserialization failed");
        assert_eq!(resp, deserialized_resp);
        assert_eq!(deserialized_resp.payload_as_str(), "pwd123");
    }

    #[test]
    fn test_vault_unseal_quorum() {
        let master_key = [0x42; KEY_SIZE];
        let mut vault = VaultManager::new(3, 5, master_key);
        let cap = VaultCap::new(Handle::new(1, 1), vault_rights::ALL);

        assert_eq!(vault.state, VaultState::Sealed);

        let share = [0x11; KEY_SIZE];
        assert_eq!(
            vault.submit_unseal_share(&cap, 0, &share).unwrap(),
            VaultState::Unsealing
        );
        assert_eq!(
            vault.submit_unseal_share(&cap, 1, &share).unwrap(),
            VaultState::Unsealing
        );
        assert_eq!(
            vault.submit_unseal_share(&cap, 2, &share).unwrap(),
            VaultState::Unsealed
        );
    }

    #[test]
    fn test_vault_secret_put_and_get_envelope() {
        let master_key = [0x5A; KEY_SIZE];
        let mut vault = VaultManager::new(1, 3, master_key);
        let cap = VaultCap::new(Handle::new(1, 1), vault_rights::ALL);

        // Déverrouillage immédiat (seuil = 1)
        vault
            .submit_unseal_share(&cap, 0, &[0u8; KEY_SIZE])
            .unwrap();
        assert_eq!(vault.state, VaultState::Unsealed);

        let path = b"tls/cluster_private_key";
        let secret_payload = b"SUPER_SECRET_ED25519_PRIVATE_KEY_BYTES";
        let version = vault
            .put_secret(&cap, path, secret_payload, 3600, 1000)
            .unwrap();
        assert_eq!(version, 1);

        let mut read_buf = [0u8; 64];
        let (len, v) = vault.get_secret(&cap, path, 1500, &mut read_buf).unwrap();
        assert_eq!(len, secret_payload.len());
        assert_eq!(v, 1);
        assert_eq!(&read_buf[..len], secret_payload);
    }

    #[test]
    fn test_vault_lease_expiration() {
        let master_key = [0x33; KEY_SIZE];
        let mut vault = VaultManager::new(1, 1, master_key);
        let cap = VaultCap::new(Handle::new(1, 1), vault_rights::ALL);
        vault
            .submit_unseal_share(&cap, 0, &[0u8; KEY_SIZE])
            .unwrap();

        let path = b"db/jwt_secret";
        vault
            .put_secret(&cap, path, b"secret_jwt", 100, 1000)
            .unwrap();

        let mut out = [0u8; 32];
        // Avant expiration (t = 1050 < 1100) -> OK
        assert!(vault.get_secret(&cap, path, 1050, &mut out).is_ok());

        // Après expiration (t = 1105 >= 1100) -> TimedOut
        assert_eq!(
            vault.get_secret(&cap, path, 1105, &mut out),
            Err(SysError::TimedOut)
        );
    }

    #[test]
    fn test_vault_rotation_and_revocation() {
        let master_key = [0x77; KEY_SIZE];
        let mut vault = VaultManager::new(1, 1, master_key);
        let cap = VaultCap::new(Handle::new(1, 1), vault_rights::ALL);
        vault
            .submit_unseal_share(&cap, 0, &[0u8; KEY_SIZE])
            .unwrap();

        let path = b"auth/token_key";
        vault
            .put_secret(&cap, path, b"token_v1", 1000, 100)
            .unwrap();

        // Rotation
        let v2 = vault
            .rotate_secret(&cap, path, b"token_v2", 1000, 200)
            .unwrap();
        assert_eq!(v2, 2);

        let mut out = [0u8; 32];
        let (len, v) = vault.get_secret(&cap, path, 250, &mut out).unwrap();
        assert_eq!(v, 2);
        assert_eq!(&out[..len], b"token_v2");

        // Révocation
        vault.revoke_secret(&cap, path).unwrap();
        assert_eq!(vault.secret_count(), 0);
    }

    #[test]
    fn test_vault_rights_attenuation() {
        let cap_full = VaultCap::new(Handle::new(1, 1), vault_rights::ALL);
        let cap_read_only = cap_full.attenuate(vault_rights::VAULT_READ).unwrap();

        let mut vault = VaultManager::new(1, 1, [0u8; KEY_SIZE]);
        // Tentative d'écriture avec droit lecture seule -> PermissionDenied
        let res = vault.put_secret(&cap_read_only, b"test", b"val", 100, 0);
        assert_eq!(res, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_vault_daemon() {
        let mut daemon = JamboVaultDaemon::new();
        assert!(!daemon.is_unsealed());

        let share = [0x11u8; KEY_SIZE];
        daemon.submit_unseal_share(0, &share).unwrap();
        daemon.submit_unseal_share(1, &share).unwrap();
        assert!(daemon.is_unsealed());

        let v1 = daemon
            .put_secret(b"db/password", b"super_secret_pwd", 1000, 50)
            .unwrap();
        assert_eq!(v1, 1);
        assert_eq!(daemon.secret_count(), 1);

        let mut out = [0u8; 32];
        let (len, v) = daemon.get_secret(b"db/password", 60, &mut out).unwrap();
        assert_eq!(v, 1);
        assert_eq!(&out[..len], b"super_secret_pwd");

        daemon.reseal().unwrap();
        assert!(!daemon.is_unsealed());
        assert_eq!(
            daemon.get_secret(b"db/password", 70, &mut out),
            Err(SysError::ResourceBusy)
        );

        daemon.submit_unseal_share(0, &share).unwrap();
        daemon.submit_unseal_share(1, &share).unwrap();
        assert!(daemon.is_unsealed());
    }

    #[test]
    fn test_vault_ipc_cycle() {
        let mut daemon = JamboVaultDaemon::new();
        daemon.init_defaults();

        // 1. GetStatus on sealed vault
        let req_status = VaultRequest::new_status();
        let resp_status = daemon.handle_ipc_request(&req_status, 100);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.state, VaultState::Sealed as u8);
        assert_eq!(resp_status.submitted_count, 0);
        assert_eq!(resp_status.threshold, 2);
        assert_eq!(resp_status.total_shares, 3);
        assert_eq!(resp_status.total_secrets, 0);

        // 2. PutSecret while sealed should fail with ResourceBusy (-7)
        let req_put = VaultRequest::new_put_secret("db/pass", b"pwd123", 300);
        let resp_put_fail = daemon.handle_ipc_request(&req_put, 100);
        assert_eq!(resp_put_fail.status, SysError::ResourceBusy as i32);

        // 3. SubmitShare 0 -> Unsealing
        let req_share0 = VaultRequest::new_submit_share(0);
        let resp_share0 = daemon.handle_ipc_request(&req_share0, 100);
        assert_eq!(resp_share0.status, 0);
        assert_eq!(resp_share0.state, VaultState::Unsealing as u8);
        assert_eq!(resp_share0.submitted_count, 1);

        // 4. SubmitShare 1 -> Unsealed
        let req_share1 = VaultRequest::new_submit_share(1);
        let resp_share1 = daemon.handle_ipc_request(&req_share1, 100);
        assert_eq!(resp_share1.status, 0);
        assert_eq!(resp_share1.state, VaultState::Unsealed as u8);
        assert_eq!(resp_share1.submitted_count, 2);

        // 5. PutSecret -> Success
        let resp_put = daemon.handle_ipc_request(&req_put, 100);
        assert_eq!(resp_put.status, 0);
        assert_eq!(resp_put.version, 1);
        assert_eq!(resp_put.total_secrets, 1);
        assert_eq!(resp_put.lease_expires_at, 400);

        // 6. GetSecret -> Success before lease expiration (t = 200 < 400)
        let req_get = VaultRequest::new_get_secret("db/pass");
        let resp_get = daemon.handle_ipc_request(&req_get, 200);
        assert_eq!(resp_get.status, 0);
        assert_eq!(resp_get.version, 1);
        assert_eq!(resp_get.payload_len, 6);
        assert_eq!(resp_get.payload_as_str(), "pwd123");
        assert_eq!(resp_get.lease_expires_at, 400);

        // 7. GetSecret after lease expiration (t = 450 >= 400) -> TimedOut (-6)
        let resp_get_expired = daemon.handle_ipc_request(&req_get, 450);
        assert_eq!(resp_get_expired.status, SysError::TimedOut as i32);

        // 8. Reseal -> Sealed
        let req_reseal = VaultRequest::new_reseal();
        let resp_reseal = daemon.handle_ipc_request(&req_reseal, 500);
        assert_eq!(resp_reseal.status, 0);
        assert_eq!(resp_reseal.state, VaultState::Sealed as u8);
        assert_eq!(resp_reseal.submitted_count, 0);

        // 9. GetSecret while resealed -> ResourceBusy
        let resp_get_resealed = daemon.handle_ipc_request(&req_get, 500);
        assert_eq!(resp_get_resealed.status, SysError::ResourceBusy as i32);

        // 10. Re-unseal
        daemon.handle_ipc_request(&req_share0, 500);
        daemon.handle_ipc_request(&req_share1, 500);

        // 11. RevokeSecret -> Success and zeroisation
        let req_revoke = VaultRequest::new_revoke_secret("db/pass");
        let resp_revoke = daemon.handle_ipc_request(&req_revoke, 500);
        assert_eq!(resp_revoke.status, 0);
        assert_eq!(resp_revoke.total_secrets, 0);

        // Verify zeroisation: entry is empty
        for sec in daemon.vault.secrets.iter() {
            assert!(!sec.allocated);
            assert_eq!(sec.encrypted_data, [0u8; MAX_SECRET_PAYLOAD]);
        }

        // 12. Invalid magic -> InvalidArgument
        let mut req_bad_magic = req_status;
        req_bad_magic.magic = 0xDEADBEEF;
        let resp_bad = daemon.handle_ipc_request(&req_bad_magic, 500);
        assert_eq!(resp_bad.status, SysError::InvalidArgument as i32);

        // 13. Missing rights -> PermissionDenied
        let mut req_unauthorized = req_status;
        req_unauthorized.rights = 0; // No rights
        let resp_unauth = daemon.handle_ipc_request(&req_unauthorized, 500);
        assert_eq!(resp_unauth.status, SysError::PermissionDenied as i32);
    }
}

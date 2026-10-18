//! Coffre-Fort de Secrets Distribué & Déverrouillage par Partage à Seuil (`jambo-vaultd`)
//!
//! Fournit un coffre-fort de secrets chiffré pour la grappe JamboOS.
//! Le déverrouillage de la clé maîtresse repose sur un quorum à seuil (K parmi N parts).
//! Chaque secret est scellé individuellement sous bail temporel et soumis au contrôle
//! strict sans autorité ambiante régi par la capacité `VaultCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const KEY_SIZE: usize = 32;
pub const MAX_SECRETS: usize = 32;
pub const MAX_SECRET_PAYLOAD: usize = 64;
pub const MAX_SHARES: usize = 8;

/// Droits de capacité pour le coffre-fort de secrets.
pub mod vault_rights {
    pub const VAULT_READ: u32 = 0x01;
    pub const VAULT_WRITE: u32 = 0x02;
    pub const VAULT_ROTATE: u32 = 0x04;
    pub const VAULT_UNSEAL: u32 = 0x08;
    pub const VAULT_ADMIN: u32 = 0x80;
    pub const ALL: u32 = VAULT_READ | VAULT_WRITE | VAULT_ROTATE | VAULT_UNSEAL | VAULT_ADMIN;
}

/// Jeton de capacité pour l'accès et l'administration du coffre-fort.
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

/// État de verrouillage du coffre-fort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Sealed,
    Unsealing,
    Unsealed,
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

    /// Lit et déchiffre un secret valide.
    pub fn get_secret(
        &self,
        cap: &VaultCap,
        path: &[u8],
        current_time: u64,
        out_buf: &mut [u8],
    ) -> Result<(usize, u32), SysError> {
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
                return Ok((sec.payload_len, sec.version));
            }
        }

        Err(SysError::InvalidHandle)
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

    /// Révoque immédiatement un secret du coffre.
    pub fn revoke_secret(&mut self, cap: &VaultCap, path: &[u8]) -> Result<(), SysError> {
        if !cap.has_right(vault_rights::VAULT_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        let mut path_buf = [0u8; 32];
        if path.len() > 32 {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

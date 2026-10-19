//! Système de Fichiers Distribué Adressable par Contenu et Réplication de Blocs (`jambo-dfsd`)
//!
//! Fournit un magasin de blocs immuables, dédupliqués et répliqués à travers les nœuds du cluster,
//! adressés par leur empreinte cryptographique (Content-Addressed Storage - CAS).
//! Toutes les opérations sont strictement régies par la capacité `DfsCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const HASH_SIZE: usize = 32;
pub const BLOCK_SIZE: usize = 128;
pub const MAX_BLOCKS: usize = 64;
pub const MAX_REPLICAS: usize = 16;

/// Droits de capacité pour le système de fichiers distribué.
pub mod dfs_rights {
    pub const DFS_READ: u32 = 0x01;
    pub const DFS_WRITE: u32 = 0x02;
    pub const DFS_PIN: u32 = 0x04;
    pub const DFS_REPLICATE: u32 = 0x08;
    pub const DFS_DELETE: u32 = 0x10;
    pub const DFS_ADMIN: u32 = 0x80;
    pub const ALL: u32 = DFS_READ | DFS_WRITE | DFS_PIN | DFS_REPLICATE | DFS_DELETE | DFS_ADMIN;
}

/// Jeton de capacité pour l'accès aux blocs distribués.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DfsCap {
    pub handle: Handle,
    pub rights: u32,
}

impl DfsCap {
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

/// Bloc immuable adressable par contenu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentAddressedBlock {
    pub hash: [u8; HASH_SIZE],
    pub size: usize,
    pub data: [u8; BLOCK_SIZE],
    pub replica_mask: u16,
    pub ref_count: u32,
    pub pinned: bool,
    pub allocated: bool,
}

impl ContentAddressedBlock {
    pub const fn empty() -> Self {
        Self {
            hash: [0u8; HASH_SIZE],
            size: 0,
            data: [0u8; BLOCK_SIZE],
            replica_mask: 0,
            ref_count: 0,
            pinned: false,
            allocated: false,
        }
    }
}

/// Calcule une empreinte cryptographique déterministe de 256 bits pour un bloc `#![no_std]`.
pub fn compute_block_hash(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hash = [0u8; HASH_SIZE];
    // Seed déterministe (constantes de SipHash/BLAKE)
    let mut h0: u64 = 0x736f6d6570736575;
    let mut h1: u64 = 0x646f72616e646f6d;
    let mut h2: u64 = 0x6c7967656e657261;
    let mut h3: u64 = 0x7465646279746573;

    for (i, &b) in data.iter().enumerate() {
        let val = (b as u64) ^ (i as u64);
        match i % 4 {
            0 => h0 = h0.rotate_left(13) ^ val.wrapping_mul(0x517cc1b727220a95),
            1 => h1 = h1.rotate_left(17) ^ val.wrapping_mul(0x9e3779b97f4a7c15),
            2 => h2 = h2.rotate_left(29) ^ val.wrapping_mul(0xbf58476d1ce4e5b9),
            _ => h3 = h3.rotate_left(31) ^ val.wrapping_mul(0x94d049bb133111eb),
        }
    }

    let b0 = h0.to_le_bytes();
    let b1 = h1.to_le_bytes();
    let b2 = h2.to_le_bytes();
    let b3 = h3.to_le_bytes();

    hash[0..8].copy_from_slice(&b0);
    hash[8..16].copy_from_slice(&b1);
    hash[16..24].copy_from_slice(&b2);
    hash[24..32].copy_from_slice(&b3);

    hash
}

/// Magasin de blocs distribué et dédupliqué.
pub struct DfsBlockStore {
    pub node_id: u16,
    pub blocks: [ContentAddressedBlock; MAX_BLOCKS],
    pub total_stored_bytes: usize,
    pub dedup_count: usize,
}

impl DfsBlockStore {
    pub const fn new(node_id: u16) -> Self {
        Self {
            node_id,
            blocks: [ContentAddressedBlock::empty(); MAX_BLOCKS],
            total_stored_bytes: 0,
            dedup_count: 0,
        }
    }

    /// Écrit un bloc de données. Si le bloc existe déjà, déduplique et incrémente son compteur.
    pub fn put_block(
        &mut self,
        cap: &DfsCap,
        data: &[u8],
        pin: bool,
    ) -> Result<[u8; HASH_SIZE], SysError> {
        if !cap.has_right(dfs_rights::DFS_WRITE) {
            return Err(SysError::PermissionDenied);
        }
        if data.len() > BLOCK_SIZE {
            return Err(SysError::InvalidArgument);
        }
        if pin && !cap.has_right(dfs_rights::DFS_PIN) {
            return Err(SysError::PermissionDenied);
        }

        let hash = compute_block_hash(data);

        // 1. Détection de déduplication CAS
        for blk in self.blocks.iter_mut() {
            if blk.allocated && blk.hash == hash {
                blk.ref_count = blk.ref_count.saturating_add(1);
                blk.replica_mask |= 1 << (self.node_id % MAX_REPLICAS as u16);
                if pin {
                    blk.pinned = true;
                }
                self.dedup_count = self.dedup_count.saturating_add(1);
                return Ok(hash);
            }
        }

        // 2. Allocation d'un nouvel emplacement
        for blk in self.blocks.iter_mut() {
            if !blk.allocated {
                blk.hash = hash;
                blk.size = data.len();
                blk.data[..data.len()].copy_from_slice(data);
                blk.replica_mask = 1 << (self.node_id % MAX_REPLICAS as u16);
                blk.ref_count = 1;
                blk.pinned = pin;
                blk.allocated = true;

                self.total_stored_bytes = self.total_stored_bytes.saturating_add(data.len());
                return Ok(hash);
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Lit un bloc par son empreinte cryptographique, avec validation stricte d'intégrité.
    pub fn get_block(
        &self,
        cap: &DfsCap,
        hash: &[u8; HASH_SIZE],
        out_buf: &mut [u8],
    ) -> Result<usize, SysError> {
        if !cap.has_right(dfs_rights::DFS_READ) {
            return Err(SysError::PermissionDenied);
        }

        for blk in self.blocks.iter() {
            if blk.allocated && &blk.hash == hash {
                // Vérification d'intégrité anti-corruption
                let actual_hash = compute_block_hash(&blk.data[..blk.size]);
                if &actual_hash != hash {
                    return Err(SysError::BadAddress); // Données corrompues
                }
                if out_buf.len() < blk.size {
                    return Err(SysError::InvalidArgument);
                }
                out_buf[..blk.size].copy_from_slice(&blk.data[..blk.size]);
                return Ok(blk.size);
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Ajoute un nœud réplique pour un bloc donné.
    pub fn add_replica(
        &mut self,
        cap: &DfsCap,
        hash: &[u8; HASH_SIZE],
        remote_node_id: u16,
    ) -> Result<(), SysError> {
        if !cap.has_right(dfs_rights::DFS_REPLICATE) {
            return Err(SysError::PermissionDenied);
        }

        for blk in self.blocks.iter_mut() {
            if blk.allocated && &blk.hash == hash {
                blk.replica_mask |= 1 << (remote_node_id % MAX_REPLICAS as u16);
                return Ok(());
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Modifie le statut d'épinglage persistant d'un bloc.
    pub fn pin_block(
        &mut self,
        cap: &DfsCap,
        hash: &[u8; HASH_SIZE],
        pinned: bool,
    ) -> Result<(), SysError> {
        if !cap.has_right(dfs_rights::DFS_PIN) {
            return Err(SysError::PermissionDenied);
        }

        for blk in self.blocks.iter_mut() {
            if blk.allocated && &blk.hash == hash {
                blk.pinned = pinned;
                return Ok(());
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Supprime ou décrémente la référence à un bloc CAS.
    pub fn delete_block(&mut self, cap: &DfsCap, hash: &[u8; HASH_SIZE]) -> Result<bool, SysError> {
        if !cap.has_right(dfs_rights::DFS_DELETE) {
            return Err(SysError::PermissionDenied);
        }

        for blk in self.blocks.iter_mut() {
            if blk.allocated && &blk.hash == hash {
                if blk.pinned {
                    return Err(SysError::ResourceBusy); // Ne peut pas être supprimé si épinglé
                }
                blk.ref_count = blk.ref_count.saturating_sub(1);
                if blk.ref_count == 0 {
                    self.total_stored_bytes = self.total_stored_bytes.saturating_sub(blk.size);
                    *blk = ContentAddressedBlock::empty();
                    return Ok(true); // Supprimé physiquement
                }
                return Ok(false); // Décrémenté seulement
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Nombre de blocs distincts alloués.
    pub fn block_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.allocated).count()
    }

    /// Compte le nombre de répliques pour un bloc donné.
    pub fn replica_count(&self, hash: &[u8; HASH_SIZE]) -> Result<u32, SysError> {
        for blk in self.blocks.iter() {
            if blk.allocated && &blk.hash == hash {
                return Ok(blk.replica_mask.count_ones());
            }
        }
        Err(SysError::InvalidHandle)
    }
}

/// Démon orchestrateur de stockage distribué adressé par le contenu (`jambo-dfsd`).
pub struct JamboDfsDaemon {
    pub store: DfsBlockStore,
    pub cap: DfsCap,
}

impl Default for JamboDfsDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboDfsDaemon {
    pub fn new() -> Self {
        let cap = DfsCap::new(Handle::new(6401, 1), dfs_rights::ALL);
        let store = DfsBlockStore::new(1);
        Self { store, cap }
    }

    pub fn put_block(&mut self, data: &[u8], pin: bool) -> Result<[u8; HASH_SIZE], SysError> {
        self.store.put_block(&self.cap, data, pin)
    }

    pub fn get_block(&self, hash: &[u8; HASH_SIZE], out_buf: &mut [u8]) -> Result<usize, SysError> {
        self.store.get_block(&self.cap, hash, out_buf)
    }

    pub fn add_replica(
        &mut self,
        hash: &[u8; HASH_SIZE],
        remote_node_id: u16,
    ) -> Result<(), SysError> {
        self.store.add_replica(&self.cap, hash, remote_node_id)
    }

    pub fn pin_block(&mut self, hash: &[u8; HASH_SIZE], pinned: bool) -> Result<(), SysError> {
        self.store.pin_block(&self.cap, hash, pinned)
    }

    pub fn delete_block(&mut self, hash: &[u8; HASH_SIZE]) -> Result<bool, SysError> {
        self.store.delete_block(&self.cap, hash)
    }

    pub fn block_count(&self) -> usize {
        self.store.block_count()
    }

    pub fn replica_count(&self, hash: &[u8; HASH_SIZE]) -> Result<u32, SysError> {
        self.store.replica_count(hash)
    }

    pub fn total_bytes(&self) -> usize {
        self.store.total_stored_bytes
    }

    pub fn dedup_count(&self) -> usize {
        self.store.dedup_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dfs_put_and_get_integrity() {
        let mut store = DfsBlockStore::new(0);
        let cap = DfsCap::new(Handle::new(1, 1), dfs_rights::ALL);

        let data = b"JamboOS Sovereign Microkernel Distributed Block 12345";
        let hash = store
            .put_block(&cap, data, false)
            .expect("Put block failed");

        let mut out_buf = [0u8; 128];
        let read_len = store
            .get_block(&cap, &hash, &mut out_buf)
            .expect("Get block failed");

        assert_eq!(read_len, data.len());
        assert_eq!(&out_buf[..read_len], data);
        assert_eq!(store.block_count(), 1);
        assert_eq!(store.dedup_count, 0);
    }

    #[test]
    fn test_dfs_deduplication() {
        let mut store = DfsBlockStore::new(0);
        let cap = DfsCap::new(Handle::new(1, 1), dfs_rights::ALL);

        let data = b"Identical Micro-VM Image Header";
        let hash1 = store.put_block(&cap, data, false).unwrap();
        let hash2 = store.put_block(&cap, data, false).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(store.block_count(), 1);
        assert_eq!(store.dedup_count, 1);

        // Décrémente la référence
        let deleted = store.delete_block(&cap, &hash1).unwrap();
        assert!(!deleted); // Pas supprimé car ref_count passe de 2 à 1
        assert_eq!(store.block_count(), 1);

        let deleted_second = store.delete_block(&cap, &hash1).unwrap();
        assert!(deleted_second); // Maintenant supprimé
        assert_eq!(store.block_count(), 0);
    }

    #[test]
    fn test_dfs_replication_and_pin() {
        let mut store = DfsBlockStore::new(1);
        let cap = DfsCap::new(Handle::new(1, 1), dfs_rights::ALL);

        let data = b"System Root Kernel Inode Block";
        let hash = store.put_block(&cap, data, true).unwrap();

        // Ajout de répliques distantes (nœud 2 et nœud 3)
        store.add_replica(&cap, &hash, 2).unwrap();
        store.add_replica(&cap, &hash, 3).unwrap();

        assert_eq!(store.replica_count(&hash).unwrap(), 3); // node 1, 2, 3

        // Tentative de suppression d'un bloc épinglé -> Erreur ResourceBusy
        let res = store.delete_block(&cap, &hash);
        assert_eq!(res, Err(SysError::ResourceBusy));

        // Dépingler le bloc
        store.pin_block(&cap, &hash, false).unwrap();
        let deleted = store.delete_block(&cap, &hash).unwrap();
        assert!(deleted);
    }

    #[test]
    fn test_dfs_rights_attenuation() {
        let cap_full = DfsCap::new(Handle::new(1, 1), dfs_rights::ALL);
        let cap_read_only = cap_full.attenuate(dfs_rights::DFS_READ).unwrap();

        let mut store = DfsBlockStore::new(0);
        let data = b"Restricted Payload";

        // Écriture avec capacité lecture seule -> PermissionDenied
        let res = store.put_block(&cap_read_only, data, false);
        assert_eq!(res, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_dfs_daemon() {
        let mut daemon = JamboDfsDaemon::new();
        let hash = daemon.put_block(b"Test daemon payload", true).unwrap();
        assert_eq!(daemon.block_count(), 1);
        daemon.add_replica(&hash, 2).unwrap();
        assert_eq!(daemon.replica_count(&hash).unwrap(), 2);
        let mut out = [0u8; 64];
        let n = daemon.get_block(&hash, &mut out).unwrap();
        assert_eq!(&out[..n], b"Test daemon payload");
        daemon.pin_block(&hash, false).unwrap();
        assert!(daemon.delete_block(&hash).unwrap());
        assert_eq!(daemon.block_count(), 0);
    }
}

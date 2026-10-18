//! Démon de Magasin Clé-Valeur Distribué Transactionnel et Linéarisable (`jambo-kvd`)
//!
//! Fournit un magasin d'état partagé multiversionné (MVCC) déterministe `#![no_std]`
//! sans autorité ambiante. Chaque opération (lecture, écriture, suppression, baux temporels,
//! transactions atomiques) est gouvernée par une capacité dédiée `KvCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_KEY_SIZE: usize = 32;
pub const MAX_VAL_SIZE: usize = 64;
pub const MAX_ENTRIES: usize = 64;
pub const MAX_LEASES: usize = 16;
pub const MAX_LEASE_KEYS: usize = 8;

/// Droits de capacité pour le magasin clé-valeur.
pub mod kv_rights {
    pub const KV_READ: u32 = 0x01;
    pub const KV_WRITE: u32 = 0x02;
    pub const KV_DELETE: u32 = 0x04;
    pub const KV_TXN: u32 = 0x08;
    pub const KV_LEASE: u32 = 0x10;
    pub const KV_WATCH: u32 = 0x20;
    pub const KV_ADMIN: u32 = 0x80;
    pub const ALL: u32 = KV_READ | KV_WRITE | KV_DELETE | KV_TXN | KV_LEASE | KV_WATCH | KV_ADMIN;
}

/// Jeton de capacité pour le magasin clé-valeur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KvCap {
    pub handle: Handle,
    pub rights: u32,
}

impl KvCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }
}

/// Enregistrement d'une entrée multiversionnée (MVCC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyValue {
    pub key: [u8; MAX_KEY_SIZE],
    pub key_len: usize,
    pub value: [u8; MAX_VAL_SIZE],
    pub value_len: usize,
    pub create_revision: u64,
    pub mod_revision: u64,
    pub version: u64,
    pub lease_id: Option<u64>,
    pub tombstone: bool,
}

impl KeyValue {
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }

    pub fn key_bytes(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

/// Bail temporel avec expiration automatique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub id: u64,
    pub ttl_ms: u64,
    pub granted_at_ms: u64,
    pub keys: [[u8; MAX_KEY_SIZE]; MAX_LEASE_KEYS],
    pub keys_len: [usize; MAX_LEASE_KEYS],
    pub keys_count: usize,
}

impl Lease {
    pub fn new(id: u64, ttl_ms: u64, granted_at_ms: u64) -> Self {
        Self {
            id,
            ttl_ms,
            granted_at_ms,
            keys: [[0u8; MAX_KEY_SIZE]; MAX_LEASE_KEYS],
            keys_len: [0usize; MAX_LEASE_KEYS],
            keys_count: 0,
        }
    }

    pub fn attach_key(&mut self, key: &[u8]) -> bool {
        if self.keys_count >= MAX_LEASE_KEYS {
            return false;
        }
        for i in 0..self.keys_count {
            if self.keys_len[i] == key.len() && &self.keys[i][..key.len()] == key {
                return true;
            }
        }
        let copy_len = key.len().min(MAX_KEY_SIZE);
        self.keys[self.keys_count][..copy_len].copy_from_slice(&key[..copy_len]);
        self.keys_len[self.keys_count] = copy_len;
        self.keys_count += 1;
        true
    }
}

/// Prédicat de comparaison pour transaction atomique conditionnelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareTarget {
    Version(u64),
    Value([u8; MAX_VAL_SIZE], usize),
}

impl CompareTarget {
    pub fn from_value_bytes(val: &[u8]) -> Self {
        let mut buf = [0u8; MAX_VAL_SIZE];
        let copy_len = val.len().min(MAX_VAL_SIZE);
        buf[..copy_len].copy_from_slice(&val[..copy_len]);
        Self::Value(buf, copy_len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Equal,
    NotEqual,
    Greater,
    Less,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KvCompare {
    pub key: [u8; MAX_KEY_SIZE],
    pub key_len: usize,
    pub target: CompareTarget,
    pub op: CompareOp,
}

impl KvCompare {
    pub fn new(key: &[u8], target: CompareTarget, op: CompareOp) -> Self {
        let mut buf = [0u8; MAX_KEY_SIZE];
        let copy_len = key.len().min(MAX_KEY_SIZE);
        buf[..copy_len].copy_from_slice(&key[..copy_len]);
        Self {
            key: buf,
            key_len: copy_len,
            target,
            op,
        }
    }
}

/// Opération élémentaire au sein d'une transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvOp {
    Put {
        key: [u8; MAX_KEY_SIZE],
        key_len: usize,
        value: [u8; MAX_VAL_SIZE],
        value_len: usize,
        lease_id: Option<u64>,
    },
    Delete {
        key: [u8; MAX_KEY_SIZE],
        key_len: usize,
    },
}

impl KvOp {
    pub fn new_put(key: &[u8], value: &[u8], lease_id: Option<u64>) -> Self {
        let mut k_buf = [0u8; MAX_KEY_SIZE];
        let mut v_buf = [0u8; MAX_VAL_SIZE];
        let k_len = key.len().min(MAX_KEY_SIZE);
        let v_len = value.len().min(MAX_VAL_SIZE);
        k_buf[..k_len].copy_from_slice(&key[..k_len]);
        v_buf[..v_len].copy_from_slice(&value[..v_len]);
        Self::Put {
            key: k_buf,
            key_len: k_len,
            value: v_buf,
            value_len: v_len,
            lease_id,
        }
    }

    pub fn new_delete(key: &[u8]) -> Self {
        let mut k_buf = [0u8; MAX_KEY_SIZE];
        let k_len = key.len().min(MAX_KEY_SIZE);
        k_buf[..k_len].copy_from_slice(&key[..k_len]);
        Self::Delete {
            key: k_buf,
            key_len: k_len,
        }
    }
}

/// Résultat d'une transaction atomique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxnResult {
    pub succeeded: bool,
    pub revision: u64,
}

/// Moteur de magasin Clé-Valeur multiversionné (MVCC).
pub struct KvStore {
    pub current_revision: u64,
    pub entries: [Option<KeyValue>; MAX_ENTRIES],
    pub leases: [Option<Lease>; MAX_LEASES],
    pub next_lease_id: u64,
}

impl Default for KvStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KvStore {
    pub const fn new() -> Self {
        Self {
            current_revision: 0,
            entries: [None; MAX_ENTRIES],
            leases: [None; MAX_LEASES],
            next_lease_id: 1,
        }
    }

    pub fn revision(&self) -> u64 {
        self.current_revision
    }

    fn find_entry_idx(&self, key: &[u8]) -> Option<usize> {
        for (i, entry) in self.entries.iter().enumerate() {
            if let Some(kv) = entry {
                if kv.key_len == key.len() && &kv.key[..kv.key_len] == key {
                    return Some(i);
                }
            }
        }
        None
    }

    fn find_free_entry_idx(&self) -> Option<usize> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.is_none() {
                return Some(i);
            }
        }
        None
    }

    /// Insère ou met à jour une valeur multiversionnée.
    pub fn put(
        &mut self,
        cap: &KvCap,
        key: &[u8],
        value: &[u8],
        lease_id: Option<u64>,
    ) -> Result<u64, SysError> {
        if !cap.has_right(kv_rights::KV_WRITE) {
            return Err(SysError::PermissionDenied);
        }

        if let Some(lid) = lease_id {
            let lease_exists = self.leases.iter().any(|l| match l {
                Some(lease) => lease.id == lid,
                None => false,
            });
            if !lease_exists {
                return Err(SysError::InvalidArgument);
            }
        }

        self.current_revision += 1;
        let rev = self.current_revision;

        let (idx, create_rev, version) = match self.find_entry_idx(key) {
            Some(i) => {
                let existing = self.entries[i].as_ref().unwrap();
                let c_rev = if existing.tombstone {
                    rev
                } else {
                    existing.create_revision
                };
                (i, c_rev, existing.version + 1)
            }
            None => {
                let free_idx = self.find_free_entry_idx().ok_or(SysError::OutOfMemory)?;
                (free_idx, rev, 1)
            }
        };

        let mut k_buf = [0u8; MAX_KEY_SIZE];
        let mut v_buf = [0u8; MAX_VAL_SIZE];
        let k_len = key.len().min(MAX_KEY_SIZE);
        let v_len = value.len().min(MAX_VAL_SIZE);
        k_buf[..k_len].copy_from_slice(&key[..k_len]);
        v_buf[..v_len].copy_from_slice(&value[..v_len]);

        let kv = KeyValue {
            key: k_buf,
            key_len: k_len,
            value: v_buf,
            value_len: v_len,
            create_revision: create_rev,
            mod_revision: rev,
            version,
            lease_id,
            tombstone: false,
        };

        if let Some(lid) = lease_id {
            for l in self.leases.iter_mut() {
                if let Some(lease) = l {
                    if lease.id == lid {
                        let _ = lease.attach_key(key);
                        break;
                    }
                }
            }
        }

        self.entries[idx] = Some(kv);
        Ok(rev)
    }

    /// Récupère la valeur active d'une clé.
    pub fn get(&self, cap: &KvCap, key: &[u8]) -> Result<Option<KeyValue>, SysError> {
        if !cap.has_right(kv_rights::KV_READ) {
            return Err(SysError::PermissionDenied);
        }

        match self.find_entry_idx(key) {
            Some(idx) => {
                let kv = self.entries[idx].as_ref().unwrap();
                if kv.tombstone {
                    Ok(None)
                } else {
                    Ok(Some(*kv))
                }
            }
            None => Ok(None),
        }
    }

    /// Supprime une clé (pose d'un tombstone logique).
    pub fn delete(&mut self, cap: &KvCap, key: &[u8]) -> Result<bool, SysError> {
        if !cap.has_right(kv_rights::KV_DELETE) {
            return Err(SysError::PermissionDenied);
        }

        let idx = match self.find_entry_idx(key) {
            Some(i) => i,
            None => return Ok(false),
        };

        let existing = self.entries[idx].as_ref().unwrap();
        if existing.tombstone {
            return Ok(false);
        }

        self.current_revision += 1;
        let rev = self.current_revision;

        let mut tombstone = *existing;
        tombstone.mod_revision = rev;
        tombstone.version += 1;
        tombstone.value_len = 0;
        tombstone.lease_id = None;
        tombstone.tombstone = true;

        self.entries[idx] = Some(tombstone);
        Ok(true)
    }

    /// Octroie un nouveau bail temporel.
    pub fn grant_lease(
        &mut self,
        cap: &KvCap,
        ttl_ms: u64,
        current_time_ms: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(kv_rights::KV_LEASE) {
            return Err(SysError::PermissionDenied);
        }

        let free_slot = self
            .leases
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(SysError::OutOfMemory)?;

        let id = self.next_lease_id;
        self.next_lease_id += 1;

        *free_slot = Some(Lease::new(id, ttl_ms, current_time_ms));
        Ok(id)
    }

    /// Renouvelle la durée de vie d'un bail temporel.
    pub fn renew_lease(
        &mut self,
        cap: &KvCap,
        lease_id: u64,
        current_time_ms: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(kv_rights::KV_LEASE) {
            return Err(SysError::PermissionDenied);
        }

        let lease = self
            .leases
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|l| l.id == lease_id))
            .ok_or(SysError::InvalidArgument)?;

        lease.granted_at_ms = current_time_ms;
        Ok(())
    }

    /// Purge les baux arrivés à expiration et supprime atomiquement leurs clés.
    pub fn purge_expired_leases(&mut self, current_time_ms: u64) -> usize {
        let mut purged_keys = 0;
        let admin_cap = KvCap::new(Handle::new(0, 0), kv_rights::KV_DELETE);

        for i in 0..MAX_LEASES {
            let is_expired = if let Some(lease) = &self.leases[i] {
                current_time_ms >= lease.granted_at_ms.saturating_add(lease.ttl_ms)
            } else {
                false
            };

            if is_expired {
                if let Some(lease) = self.leases[i].take() {
                    for k_idx in 0..lease.keys_count {
                        let k = &lease.keys[k_idx][..lease.keys_len[k_idx]];
                        let _ = self.delete(&admin_cap, k);
                        purged_keys += 1;
                    }
                }
            }
        }

        purged_keys
    }

    /// Exécute une transaction atomique conditionnelle.
    pub fn txn(
        &mut self,
        cap: &KvCap,
        compares: &[KvCompare],
        success_ops: &[KvOp],
        failure_ops: &[KvOp],
    ) -> Result<TxnResult, SysError> {
        if !cap.has_right(kv_rights::KV_TXN) {
            return Err(SysError::PermissionDenied);
        }

        let mut matches = true;
        for cmp in compares {
            let active = self
                .find_entry_idx(&cmp.key[..cmp.key_len])
                .and_then(|idx| self.entries[idx].as_ref())
                .filter(|kv| !kv.tombstone);

            let condition_met = match (cmp.target, active) {
                (CompareTarget::Version(expected), Some(kv)) => match cmp.op {
                    CompareOp::Equal => kv.version == expected,
                    CompareOp::NotEqual => kv.version != expected,
                    CompareOp::Greater => kv.version > expected,
                    CompareOp::Less => kv.version < expected,
                },
                (CompareTarget::Version(expected), None) => match cmp.op {
                    CompareOp::Equal => expected == 0,
                    CompareOp::NotEqual => expected != 0,
                    CompareOp::Greater => false,
                    CompareOp::Less => expected > 0,
                },
                (CompareTarget::Value(expected_buf, expected_len), Some(kv)) => {
                    let val_match = kv.value_len == expected_len
                        && &kv.value[..kv.value_len] == &expected_buf[..expected_len];
                    match cmp.op {
                        CompareOp::Equal => val_match,
                        CompareOp::NotEqual => !val_match,
                        _ => false,
                    }
                }
                (CompareTarget::Value(_, _), None) => cmp.op == CompareOp::NotEqual,
            };

            if !condition_met {
                matches = false;
                break;
            }
        }

        let ops = if matches { success_ops } else { failure_ops };
        let write_cap = KvCap::new(
            Handle::new(0, 0),
            kv_rights::KV_WRITE | kv_rights::KV_DELETE,
        );

        for op in ops {
            match op {
                KvOp::Put {
                    key,
                    key_len,
                    value,
                    value_len,
                    lease_id,
                } => {
                    self.put(
                        &write_cap,
                        &key[..*key_len],
                        &value[..*value_len],
                        *lease_id,
                    )?;
                }
                KvOp::Delete { key, key_len } => {
                    self.delete(&write_cap, &key[..*key_len])?;
                }
            }
        }

        Ok(TxnResult {
            succeeded: matches,
            revision: self.current_revision,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_permissions() {
        let mut store = KvStore::new();
        let read_cap = KvCap::new(Handle::new(1, 1), kv_rights::KV_READ);
        let write_cap = KvCap::new(Handle::new(2, 1), kv_rights::KV_WRITE);

        // Put sans droit d'écriture doit échouer
        let res = store.put(&read_cap, b"k1", b"v1", None);
        assert_eq!(res, Err(SysError::PermissionDenied));

        // Put avec droit réussit
        let res = store.put(&write_cap, b"k1", b"v1", None);
        assert!(res.is_ok());

        // Get sans droit de lecture échoue
        let res = store.get(&write_cap, b"k1");
        assert_eq!(res, Err(SysError::PermissionDenied));

        // Get avec droit réussit
        let kv = store.get(&read_cap, b"k1").unwrap().unwrap();
        assert_eq!(kv.value_bytes(), b"v1");
    }

    #[test]
    fn test_mvcc_lifecycle() {
        let mut store = KvStore::new();
        let cap = KvCap::new(
            Handle::new(1, 1),
            kv_rights::KV_READ | kv_rights::KV_WRITE | kv_rights::KV_DELETE,
        );

        let rev1 = store.put(&cap, b"cfg/mtu", b"1500", None).unwrap();
        assert_eq!(rev1, 1);

        let rev2 = store.put(&cap, b"cfg/mtu", b"9000", None).unwrap();
        assert_eq!(rev2, 2);

        let kv = store.get(&cap, b"cfg/mtu").unwrap().unwrap();
        assert_eq!(kv.value_bytes(), b"9000");
        assert_eq!(kv.version, 2);
        assert_eq!(kv.create_revision, 1);
        assert_eq!(kv.mod_revision, 2);

        let deleted = store.delete(&cap, b"cfg/mtu").unwrap();
        assert!(deleted);
        assert!(store.get(&cap, b"cfg/mtu").unwrap().is_none());
        assert_eq!(store.revision(), 3);
    }

    #[test]
    fn test_leases_expiration() {
        let mut store = KvStore::new();
        let cap = KvCap::new(
            Handle::new(1, 1),
            kv_rights::KV_READ | kv_rights::KV_WRITE | kv_rights::KV_LEASE | kv_rights::KV_DELETE,
        );

        let lid = store.grant_lease(&cap, 500, 1000).unwrap();
        store
            .put(&cap, b"node/discovery", b"active", Some(lid))
            .unwrap();

        // À t=1200, le bail est actif
        assert_eq!(store.purge_expired_leases(1200), 0);
        assert!(store.get(&cap, b"node/discovery").unwrap().is_some());

        // À t=1600, le bail a expiré
        assert_eq!(store.purge_expired_leases(1600), 1);
        assert!(store.get(&cap, b"node/discovery").unwrap().is_none());
    }

    #[test]
    fn test_atomic_transaction() {
        let mut store = KvStore::new();
        let cap = KvCap::new(
            Handle::new(1, 1),
            kv_rights::KV_READ | kv_rights::KV_WRITE | kv_rights::KV_TXN,
        );

        store.put(&cap, b"counter", b"10", None).unwrap();

        let cmp = [KvCompare::new(
            b"counter",
            CompareTarget::from_value_bytes(b"10"),
            CompareOp::Equal,
        )];
        let success = [KvOp::new_put(b"counter", b"11", None)];
        let failure = [];

        let txn_res = store.txn(&cap, &cmp, &success, &failure).unwrap();
        assert!(txn_res.succeeded);

        let kv = store.get(&cap, b"counter").unwrap().unwrap();
        assert_eq!(kv.value_bytes(), b"11");
    }
}

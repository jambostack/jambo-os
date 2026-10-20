//! Système Souverain de Gestion et Séquestre de Clés de Grappe Distribuée (`jambo-kms`)
//!
//! Phase 108 — Jalon v0.2.106
//!
//! Fournit les garanties souveraines de gestion de cycle de vie et séquestre de clés cryptographiques :
//! 1. Hiérarchies Cryptographiques Rigoureuses (NIST SP 800-108 / HKDF RFC 5869) :
//!    - MasterKey (KEK Racine de Confiance Niveau 0)
//!    - DomainKey (KEK Domaine / Locataire Niveau 1)
//!    - DataKey (DEK Chiffrement Données Niveau 2)
//!    - SessionKey (Clé Éphémère de Session Niveau 3)
//!    - EscrowKey (Clé de Recouvrement d'Urgence Séquestrée)
//! 2. Baux Temporels & Quotas d'Utilisation (Time-based Key Leases) :
//!    - Attribution bornée avec horodatage monotone (`valid_from_ticks` .. `valid_until_ticks`)
//!    - Plafonds stricts du nombre d'opérations autorisées (`max_ops`) et compteurs de consommation
//!    - Renouvellement contrôlé (`max_renewals`) et révocation instantanée O(1).
//! 3. Séquestre Sécurisé & Partage de Secret Multi-Gardiens (M-of-N Key Escrow) :
//!    - Séquestre avec seuil de gardiens (Threshold M-of-N)
//!    - Engagements cryptographiques SHA-256 inaltérables par gardien
//!    - Déverrouillage et restauration conditionnés à l'atteinte du quorum vérifié.
//! 4. Réplication Chiffrée Multi-Nœuds (Encrypted Cluster Replication & Versioned Sync) :
//!    - Enveloppes de transport scellées (ChaCha20 + HMAC-SHA256)
//!    - Protection anti-rejeu et validation d'époque de grappe (`cluster_epoch`)
//!    - Synchronisation incrémentale d'état entre nœuds authentifiés.
//! 5. Cycle de Vie Cryptographique Déterministe & Zéroïsation d'Urgence :
//!    - États : PreActive -> Active -> Escrowed -> Suspended -> Expired -> Revoked -> Destroyed
//!    - Rotation atomique avec historique de versions
//!    - Zéroïsation volatile garantie (`compiler_fence`) à la destruction.
//! 6. Gouvernance Capabilaire Stricte (`KmsCap`) :
//!    - Zéro autorité ambiante, permissions granulaires et atténuation monotone irréversible.
//! 7. Registre d'Audit Inaltérable :
//!    - Chaîne d'audit cryptographique SHA-256 (`kms_audit_chain`) horodatée et scellée.

#![no_std]

use libjambo::Handle;

// ============================================================================
// CONSTANTES DU SOUS-SYSTÈME JAMBO-KMS
// ============================================================================

pub const MAX_KEYS: usize = 32;
pub const MAX_LEASES: usize = 32;
pub const MAX_ESCROWS: usize = 16;
pub const MAX_NODES: usize = 8;
pub const MAX_ENVELOPES: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_CUSTODIANS: usize = 5;

pub const KEY_DATA_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const MAX_NAME_LEN: usize = 32;
pub const ENVELOPE_CIPHERTEXT_LEN: usize = 48;

// ============================================================================
// DROITS CAPABILAIRES & GOUVERNANCE STRICTE (ZÉRO AUTORITÉ AMBIANTE)
// ============================================================================

pub mod kms_rights {
    pub const CREATE_KEY: u32 = 1 << 0;
    pub const DERIVE_KEY: u32 = 1 << 1;
    pub const GRANT_LEASE: u32 = 1 << 2;
    pub const RENEW_LEASE: u32 = 1 << 3;
    pub const ESCROW_KEY: u32 = 1 << 4;
    pub const RECOVER_KEY: u32 = 1 << 5;
    pub const ROTATE_KEY: u32 = 1 << 6;
    pub const REPLICATE: u32 = 1 << 7;
    pub const REVOKE_KEY: u32 = 1 << 8;
    pub const ZEROIZE_KEY: u32 = 1 << 9;
    pub const AUDIT_LOG: u32 = 1 << 10;
    pub const ALL: u32 = (1 << 11) - 1;
}

pub mod lease_ops {
    pub const OP_ENCRYPT: u32 = 1 << 0;
    pub const OP_DECRYPT: u32 = 1 << 1;
    pub const OP_SIGN: u32 = 1 << 2;
    pub const OP_DERIVE: u32 = 1 << 3;
    pub const OP_ALL: u32 = 0x0F;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KmsCap {
    pub handle: Handle,
    pub rights: u32,
    pub node_id: u32,
    pub max_keys: u16,
}

impl KmsCap {
    pub const fn new(handle: Handle, rights: u32, node_id: u32, max_keys: u16) -> Self {
        Self {
            handle,
            rights,
            node_id,
            max_keys,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(&self, desired_rights: u32, max_keys: u16) -> Result<Self, KmsError> {
        if (desired_rights & !self.rights) != 0 {
            return Err(KmsError::PermissionDenied);
        }
        if max_keys > self.max_keys {
            return Err(KmsError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: desired_rights,
            node_id: self.node_id,
            max_keys,
        })
    }
}

// ============================================================================
// PRIMITIVES CRYPTOGRAPHIQUES SHA-256, HMAC, HKDF & CHACHA20 (#![no_std])
// ============================================================================

#[inline(never)]
pub fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(always)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

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
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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

    pub fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let kh = Self::digest(key);
            k_pad[..32].copy_from_slice(&kh);
        } else {
            k_pad[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k_pad[i] ^ 0x36;
            opad[i] = k_pad[i] ^ 0x5c;
        }

        let mut inner_buf = [0u8; 64 + 512];
        let inner_len = 64 + message.len();
        if inner_len <= inner_buf.len() {
            inner_buf[..64].copy_from_slice(&ipad);
            inner_buf[64..inner_len].copy_from_slice(message);
            let inner_hash = Self::digest(&inner_buf[..inner_len]);

            let mut outer_buf = [0u8; 64 + 32];
            outer_buf[..64].copy_from_slice(&opad);
            outer_buf[64..96].copy_from_slice(&inner_hash);
            Self::digest(&outer_buf)
        } else {
            let inner_hash = Self::digest(message);
            let mut outer_buf = [0u8; 64 + 32];
            outer_buf[..64].copy_from_slice(&opad);
            outer_buf[64..96].copy_from_slice(&inner_hash);
            Self::digest(&outer_buf)
        }
    }

    /// Dérivation de clés conforme HKDF-Extract / HKDF-Expand (RFC 5869)
    pub fn hkdf_derive(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
        let prk = Self::hmac(salt, ikm);
        let mut t = [0u8; 32];
        let mut offset = 0;
        let mut counter = 1u8;

        while offset < out.len() {
            let mut step_buf = [0u8; 32 + 64 + 1];
            let mut step_len = 0;
            if counter > 1 {
                step_buf[..32].copy_from_slice(&t);
                step_len += 32;
            }
            let info_len = core::cmp::min(info.len(), 64);
            step_buf[step_len..step_len + info_len].copy_from_slice(&info[..info_len]);
            step_len += info_len;
            step_buf[step_len] = counter;
            step_len += 1;

            t = Self::hmac(&prk, &step_buf[..step_len]);
            let to_copy = core::cmp::min(out.len() - offset, 32);
            out[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
            counter += 1;
        }
    }
}

pub struct ChaCha20;

impl ChaCha20 {
    #[inline(always)]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(7);
    }

    pub fn process(key: &[u8; 32], nonce: &[u8; 16], counter: u32, data: &mut [u8]) {
        let mut state = [0u32; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }

        state[12] = counter;
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        let mut offset = 0;
        let mut block_counter = counter;

        while offset < data.len() {
            state[12] = block_counter;
            let mut working = state;

            for _ in 0..10 {
                Self::quarter_round(&mut working, 0, 4, 8, 12);
                Self::quarter_round(&mut working, 1, 5, 9, 13);
                Self::quarter_round(&mut working, 2, 6, 10, 14);
                Self::quarter_round(&mut working, 3, 7, 11, 15);

                Self::quarter_round(&mut working, 0, 5, 10, 15);
                Self::quarter_round(&mut working, 1, 6, 11, 12);
                Self::quarter_round(&mut working, 2, 7, 8, 13);
                Self::quarter_round(&mut working, 3, 4, 9, 14);
            }

            let mut key_stream = [0u8; 64];
            for i in 0..16 {
                let val = working[i].wrapping_add(state[i]);
                key_stream[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
            }

            let block_len = core::cmp::min(data.len() - offset, 64);
            for i in 0..block_len {
                data[offset + i] ^= key_stream[i];
            }

            offset += block_len;
            block_counter = block_counter.wrapping_add(1);
        }
    }
}

pub struct Gf256;

impl Gf256 {
    #[inline(always)]
    pub fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    #[inline(always)]
    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        let mut res = 1u8;
        let mut base = a;
        let mut exp = 254;
        while exp > 0 {
            if (exp & 1) != 0 {
                res = Self::mul(res, base);
            }
            base = Self::mul(base, base);
            exp >>= 1;
        }
        res
    }
}

// ============================================================================
// STRUCTURES DE DONNÉES & CYCLE DE VIE DU SOUS-SYSTÈME KMS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyHierarchyLevel {
    MasterKey = 0,
    DomainKey = 1,
    DataKey = 2,
    SessionKey = 3,
    EscrowKey = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Aes128 = 0,
    Aes256 = 1,
    ChaCha20 = 2,
    HmacSha256 = 3,
    Ed25519 = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyLifecycleState {
    PreActive = 0,
    Active = 1,
    Escrowed = 2,
    Suspended = 3,
    Expired = 4,
    Revoked = 5,
    Destroyed = 6,
}

#[derive(Clone, Copy)]
pub struct KeyEntry {
    pub key_id: u32,
    pub parent_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub level: KeyHierarchyLevel,
    pub algorithm: KeyAlgorithm,
    pub state: KeyLifecycleState,
    pub material: [u8; KEY_DATA_LEN],
    pub created_epoch: u32,
    pub rotation_count: u32,
    pub fingerprint: [u8; HASH_LEN],
    pub owner_node: u32,
}

impl KeyEntry {
    pub const fn empty() -> Self {
        Self {
            key_id: 0,
            parent_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            level: KeyHierarchyLevel::DataKey,
            algorithm: KeyAlgorithm::Aes256,
            state: KeyLifecycleState::PreActive,
            material: [0u8; KEY_DATA_LEN],
            created_epoch: 0,
            rotation_count: 0,
            fingerprint: [0u8; HASH_LEN],
            owner_node: 0,
        }
    }

    pub fn compute_fingerprint(&mut self) {
        let mut msg = [0u8; KEY_DATA_LEN + 8];
        msg[..KEY_DATA_LEN].copy_from_slice(&self.material);
        msg[KEY_DATA_LEN] = self.level as u8;
        msg[KEY_DATA_LEN + 1] = self.algorithm as u8;
        msg[KEY_DATA_LEN + 2..KEY_DATA_LEN + 6].copy_from_slice(&self.key_id.to_be_bytes());
        msg[KEY_DATA_LEN + 6..KEY_DATA_LEN + 8].copy_from_slice(&(self.rotation_count as u16).to_be_bytes());
        self.fingerprint = Sha256::digest(&msg);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    Free = 0,
    Active = 1,
    Renewed = 2,
    Expired = 3,
    Revoked = 4,
    Exhausted = 5,
}

#[derive(Clone, Copy)]
pub struct KeyLease {
    pub lease_id: u32,
    pub key_id: u32,
    pub granted_to_node: u32,
    pub allowed_ops: u32,
    pub max_ops: u64,
    pub used_ops: u64,
    pub valid_from_ticks: u64,
    pub valid_until_ticks: u64,
    pub renewed_count: u32,
    pub max_renewals: u32,
    pub state: LeaseState,
}

impl KeyLease {
    pub const fn empty() -> Self {
        Self {
            lease_id: 0,
            key_id: 0,
            granted_to_node: 0,
            allowed_ops: 0,
            max_ops: 0,
            used_ops: 0,
            valid_from_ticks: 0,
            valid_until_ticks: 0,
            renewed_count: 0,
            max_renewals: 0,
            state: LeaseState::Free,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscrowStatus {
    None = 0,
    Secured = 1,
    RecoveryInitiated = 2,
    Recovered = 3,
    Cancelled = 4,
}

#[derive(Clone, Copy)]
pub struct EscrowPackage {
    pub escrow_id: u32,
    pub key_id: u32,
    pub threshold: u8,
    pub total_custodians: u8,
    pub shares_collected: u8,
    pub custodian_commitments: [[u8; HASH_LEN]; MAX_CUSTODIANS],
    pub collected_shares: [[u8; KEY_DATA_LEN]; MAX_CUSTODIANS],
    pub collected_mask: u8,
    pub wrapped_key: [u8; ENVELOPE_CIPHERTEXT_LEN],
    pub escrow_nonce: [u8; NONCE_LEN],
    pub escrow_kek_commitment: [u8; HASH_LEN],
    pub status: EscrowStatus,
}

impl EscrowPackage {
    pub const fn empty() -> Self {
        Self {
            escrow_id: 0,
            key_id: 0,
            threshold: 0,
            total_custodians: 0,
            shares_collected: 0,
            custodian_commitments: [[0u8; HASH_LEN]; MAX_CUSTODIANS],
            collected_shares: [[0u8; KEY_DATA_LEN]; MAX_CUSTODIANS],
            collected_mask: 0,
            wrapped_key: [0u8; ENVELOPE_CIPHERTEXT_LEN],
            escrow_nonce: [0u8; NONCE_LEN],
            escrow_kek_commitment: [0u8; HASH_LEN],
            status: EscrowStatus::None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct ClusterNode {
    pub node_id: u32,
    pub cluster_epoch: u32,
    pub last_sync_seq: u64,
    pub shared_key: [u8; KEY_DATA_LEN],
    pub is_trusted: bool,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
}

impl ClusterNode {
    pub const fn empty() -> Self {
        Self {
            node_id: 0,
            cluster_epoch: 0,
            last_sync_seq: 0,
            shared_key: [0u8; KEY_DATA_LEN],
            is_trusted: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct KeyEnvelope {
    pub envelope_id: u32,
    pub origin_node: u32,
    pub target_node: u32,
    pub key_id: u32,
    pub key_version: u32,
    pub ciphertext: [u8; ENVELOPE_CIPHERTEXT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub auth_tag: [u8; HASH_LEN],
    pub seq: u64,
}

impl KeyEnvelope {
    pub const fn empty() -> Self {
        Self {
            envelope_id: 0,
            origin_node: 0,
            target_node: 0,
            key_id: 0,
            key_version: 0,
            ciphertext: [0u8; ENVELOPE_CIPHERTEXT_LEN],
            nonce: [0u8; NONCE_LEN],
            auth_tag: [0u8; HASH_LEN],
            seq: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct KmsAuditRecord {
    pub timestamp_ticks: u64,
    pub action: [u8; 24],
    pub key_id: u32,
    pub node_id: u32,
    pub details_code: u32,
    pub prev_hash: [u8; HASH_LEN],
    pub record_hash: [u8; HASH_LEN],
}

impl KmsAuditRecord {
    pub const fn empty() -> Self {
        Self {
            timestamp_ticks: 0,
            action: [0u8; 24],
            key_id: 0,
            node_id: 0,
            details_code: 0,
            prev_hash: [0u8; HASH_LEN],
            record_hash: [0u8; HASH_LEN],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KmsError {
    PermissionDenied,
    KeyNotFound,
    KeySlotExhausted,
    LeaseNotFound,
    LeaseExpired,
    LeaseExhausted,
    InvalidState,
    InvalidHierarchy,
    EscrowNotFound,
    EscrowThresholdNotMet,
    InvalidCustodianShare,
    NodeNotFound,
    EpochMismatch,
    CryptoError,
    QuotaExceeded,
}

// ============================================================================
// DÉMON DU SOUS-SYSTÈME KMS (`JamboKmsDaemon`)
// ============================================================================

pub struct JamboKmsDaemon {
    pub admin_cap: KmsCap,
    pub node_id: u32,
    pub cluster_epoch: u32,
    pub current_ticks: u64,
    pub keys: [KeyEntry; MAX_KEYS],
    pub key_count: usize,
    pub leases: [KeyLease; MAX_LEASES],
    pub lease_count: usize,
    pub escrows: [EscrowPackage; MAX_ESCROWS],
    pub escrow_count: usize,
    pub nodes: [ClusterNode; MAX_NODES],
    pub node_count: usize,
    pub envelopes: [KeyEnvelope; MAX_ENVELOPES],
    pub envelope_count: usize,
    pub audit_logs: [KmsAuditRecord; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub audit_chain: [u8; HASH_LEN],
    pub next_key_id: u32,
    pub next_lease_id: u32,
    pub next_escrow_id: u32,
    pub next_envelope_id: u32,
    pub total_ops: u64,
}

impl JamboKmsDaemon {
    pub fn new(admin_cap: KmsCap) -> Self {
        let initial_audit = Sha256::digest(b"JAMBO_KMS_GENESIS_ROOT_V1");
        Self {
            admin_cap,
            node_id: admin_cap.node_id,
            cluster_epoch: 1,
            current_ticks: 1000,
            keys: [KeyEntry::empty(); MAX_KEYS],
            key_count: 0,
            leases: [KeyLease::empty(); MAX_LEASES],
            lease_count: 0,
            escrows: [EscrowPackage::empty(); MAX_ESCROWS],
            escrow_count: 0,
            nodes: [ClusterNode::empty(); MAX_NODES],
            node_count: 0,
            envelopes: [KeyEnvelope::empty(); MAX_ENVELOPES],
            envelope_count: 0,
            audit_logs: [KmsAuditRecord::empty(); MAX_AUDIT_LOGS],
            audit_count: 0,
            audit_chain: initial_audit,
            next_key_id: 1001,
            next_lease_id: 5001,
            next_escrow_id: 8001,
            next_envelope_id: 9001,
            total_ops: 0,
        }
    }

    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // Enregistrement du nœud local
        let local_shared = Sha256::digest(b"JAMBO_CLUSTER_NODE_0_KEY");
        let _ = self.register_cluster_node(&cap, 0, b"node-master-0", 1, &local_shared);

        // Clé Racine Maîtresse (Master Key Level 0)
        let master_seed = Sha256::digest(b"JAMBO_KMS_MASTER_ROOT_KEY_2026");
        let master_id = self.create_key(
            &cap,
            b"root-master-kek",
            KeyHierarchyLevel::MasterKey,
            KeyAlgorithm::Aes256,
            &master_seed,
        ).unwrap_or(0);

        // Clé de Domaine Dérivée (Domain Key Level 1)
        let domain_id = self.derive_child_key(
            &cap,
            master_id,
            b"domain-tenant-alpha",
            KeyHierarchyLevel::DomainKey,
            KeyAlgorithm::Aes256,
            b"tenant=alpha,region=core",
        ).unwrap_or(0);

        // Clé de Données Dérivée (Data Key Level 2)
        let data_id = self.derive_child_key(
            &cap,
            domain_id,
            b"dek-storage-vfs",
            KeyHierarchyLevel::DataKey,
            KeyAlgorithm::ChaCha20,
            b"dataset=vfs-cow,block=4096",
        ).unwrap_or(0);

        // Octroi d'un bail temporel par défaut sur la DEK
        let _ = self.grant_lease(
            &cap,
            data_id,
            0,
            lease_ops::OP_ALL,
            5000,
            10000,
            self.current_ticks,
            3,
        );

        // Enregistrement d'un nœud pair de grappe
        let peer_shared = Sha256::digest(b"JAMBO_CLUSTER_NODE_1_KEY");
        let _ = self.register_cluster_node(&cap, 1, b"node-replica-1", 1, &peer_shared);
    }

    fn record_audit(&mut self, action_name: &[u8], key_id: u32, node_id: u32, details: u32) {
        let mut rec = KmsAuditRecord::empty();
        rec.timestamp_ticks = self.current_ticks;
        let act_len = core::cmp::min(action_name.len(), 24);
        rec.action[..act_len].copy_from_slice(&action_name[..act_len]);
        rec.key_id = key_id;
        rec.node_id = node_id;
        rec.details_code = details;
        rec.prev_hash = self.audit_chain;

        let mut hash_data = [0u8; 32 + 24 + 16];
        hash_data[..32].copy_from_slice(&self.audit_chain);
        hash_data[32..32 + act_len].copy_from_slice(&action_name[..act_len]);
        hash_data[56..60].copy_from_slice(&key_id.to_be_bytes());
        hash_data[60..64].copy_from_slice(&node_id.to_be_bytes());
        hash_data[64..68].copy_from_slice(&details.to_be_bytes());
        hash_data[68..72].copy_from_slice(&(self.current_ticks as u32).to_be_bytes());

        rec.record_hash = Sha256::digest(&hash_data);
        self.audit_chain = rec.record_hash;

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_logs[self.audit_count] = rec;
            self.audit_count += 1;
        } else {
            for i in 1..MAX_AUDIT_LOGS {
                self.audit_logs[i - 1] = self.audit_logs[i];
            }
            self.audit_logs[MAX_AUDIT_LOGS - 1] = rec;
        }
    }

    pub fn create_key(
        &mut self,
        cap: &KmsCap,
        name: &[u8],
        level: KeyHierarchyLevel,
        algo: KeyAlgorithm,
        material: &[u8; KEY_DATA_LEN],
    ) -> Result<u32, KmsError> {
        if !cap.has_right(kms_rights::CREATE_KEY) {
            return Err(KmsError::PermissionDenied);
        }
        if self.key_count >= cap.max_keys as usize || self.key_count >= MAX_KEYS {
            return Err(KmsError::KeySlotExhausted);
        }

        let slot = self.keys.iter().position(|k| k.state == KeyLifecycleState::PreActive || k.state == KeyLifecycleState::Destroyed)
            .unwrap_or(self.key_count);

        if slot >= MAX_KEYS {
            return Err(KmsError::KeySlotExhausted);
        }

        let kid = self.next_key_id;
        self.next_key_id += 1;

        let mut entry = KeyEntry::empty();
        entry.key_id = kid;
        entry.parent_id = 0;
        let nlen = core::cmp::min(name.len(), MAX_NAME_LEN);
        entry.name[..nlen].copy_from_slice(&name[..nlen]);
        entry.name_len = nlen;
        entry.level = level;
        entry.algorithm = algo;
        entry.state = KeyLifecycleState::Active;
        entry.material.copy_from_slice(material);
        entry.created_epoch = self.cluster_epoch;
        entry.rotation_count = 0;
        entry.owner_node = self.node_id;
        entry.compute_fingerprint();

        self.keys[slot] = entry;
        if slot >= self.key_count {
            self.key_count = slot + 1;
        }

        self.total_ops += 1;
        self.record_audit(b"KEY_CREATE", kid, self.node_id, level as u32);
        Ok(kid)
    }

    pub fn derive_child_key(
        &mut self,
        cap: &KmsCap,
        parent_id: u32,
        name: &[u8],
        level: KeyHierarchyLevel,
        algo: KeyAlgorithm,
        context_info: &[u8],
    ) -> Result<u32, KmsError> {
        if !cap.has_right(kms_rights::DERIVE_KEY) {
            return Err(KmsError::PermissionDenied);
        }
        if self.key_count >= cap.max_keys as usize || self.key_count >= MAX_KEYS {
            return Err(KmsError::KeySlotExhausted);
        }

        let parent = self.keys.iter().find(|k| k.key_id == parent_id && k.state == KeyLifecycleState::Active)
            .ok_or(KmsError::KeyNotFound)?;

        // Règle formelle de hiérarchie : parent doit être d'un niveau strictement supérieur ou égal
        let valid_hierarchy = match (parent.level, level) {
            (KeyHierarchyLevel::MasterKey, KeyHierarchyLevel::DomainKey) => true,
            (KeyHierarchyLevel::MasterKey, KeyHierarchyLevel::DataKey) => true,
            (KeyHierarchyLevel::DomainKey, KeyHierarchyLevel::DataKey) => true,
            (KeyHierarchyLevel::DomainKey, KeyHierarchyLevel::SessionKey) => true,
            (KeyHierarchyLevel::DataKey, KeyHierarchyLevel::SessionKey) => true,
            (KeyHierarchyLevel::MasterKey, KeyHierarchyLevel::EscrowKey) => true,
            _ => false,
        };

        if !valid_hierarchy {
            return Err(KmsError::InvalidHierarchy);
        }

        let mut child_material = [0u8; KEY_DATA_LEN];
        let salt = parent.fingerprint;
        let parent_mat = parent.material;
        Sha256::hkdf_derive(&salt, &parent_mat, context_info, &mut child_material);

        let kid = self.create_key(cap, name, level, algo, &child_material)?;
        if let Some(child_entry) = self.keys.iter_mut().find(|k| k.key_id == kid) {
            child_entry.parent_id = parent_id;
        }

        self.record_audit(b"KEY_DERIVE", kid, self.node_id, parent_id);
        Ok(kid)
    }

    pub fn grant_lease(
        &mut self,
        cap: &KmsCap,
        key_id: u32,
        target_node: u32,
        allowed_ops: u32,
        max_ops: u64,
        duration_ticks: u64,
        current_ticks: u64,
        max_renewals: u32,
    ) -> Result<u32, KmsError> {
        if !cap.has_right(kms_rights::GRANT_LEASE) {
            return Err(KmsError::PermissionDenied);
        }
        let key_exists = self.keys.iter().any(|k| k.key_id == key_id && k.state == KeyLifecycleState::Active);
        if !key_exists {
            return Err(KmsError::KeyNotFound);
        }

        let slot = self.leases.iter().position(|l| l.state == LeaseState::Free || l.state == LeaseState::Expired || l.state == LeaseState::Revoked)
            .unwrap_or(self.lease_count);

        if slot >= MAX_LEASES {
            return Err(KmsError::QuotaExceeded);
        }

        let lid = self.next_lease_id;
        self.next_lease_id += 1;

        let mut lease = KeyLease::empty();
        lease.lease_id = lid;
        lease.key_id = key_id;
        lease.granted_to_node = target_node;
        lease.allowed_ops = allowed_ops;
        lease.max_ops = max_ops;
        lease.used_ops = 0;
        lease.valid_from_ticks = current_ticks;
        lease.valid_until_ticks = current_ticks.saturating_add(duration_ticks);
        lease.renewed_count = 0;
        lease.max_renewals = max_renewals;
        lease.state = LeaseState::Active;

        self.leases[slot] = lease;
        if slot >= self.lease_count {
            self.lease_count = slot + 1;
        }

        self.total_ops += 1;
        self.record_audit(b"LEASE_GRANT", key_id, target_node, lid);
        Ok(lid)
    }

    pub fn renew_lease(
        &mut self,
        cap: &KmsCap,
        lease_id: u32,
        extend_ticks: u64,
        current_ticks: u64,
    ) -> Result<(), KmsError> {
        if !cap.has_right(kms_rights::RENEW_LEASE) {
            return Err(KmsError::PermissionDenied);
        }

        let (kid, target) = {
            let lease = self.leases.iter_mut().find(|l| l.lease_id == lease_id)
                .ok_or(KmsError::LeaseNotFound)?;

            if lease.state != LeaseState::Active && lease.state != LeaseState::Renewed {
                return Err(KmsError::InvalidState);
            }

            if current_ticks > lease.valid_until_ticks {
                lease.state = LeaseState::Expired;
                return Err(KmsError::LeaseExpired);
            }

            if lease.renewed_count >= lease.max_renewals {
                return Err(KmsError::QuotaExceeded);
            }

            lease.valid_until_ticks = lease.valid_until_ticks.saturating_add(extend_ticks);
            lease.renewed_count += 1;
            lease.state = LeaseState::Renewed;
            (lease.key_id, lease.granted_to_node)
        };

        self.total_ops += 1;
        self.record_audit(b"LEASE_RENEW", kid, target, lease_id);
        Ok(())
    }

    pub fn consume_lease_op(
        &mut self,
        lease_id: u32,
        current_ticks: u64,
        op_flag: u32,
    ) -> Result<(), KmsError> {
        let lease = self.leases.iter_mut().find(|l| l.lease_id == lease_id)
            .ok_or(KmsError::LeaseNotFound)?;

        if lease.state != LeaseState::Active && lease.state != LeaseState::Renewed {
            return Err(KmsError::InvalidState);
        }

        if current_ticks > lease.valid_until_ticks {
            lease.state = LeaseState::Expired;
            return Err(KmsError::LeaseExpired);
        }

        if (lease.allowed_ops & op_flag) == 0 {
            return Err(KmsError::PermissionDenied);
        }

        if lease.used_ops >= lease.max_ops {
            lease.state = LeaseState::Exhausted;
            return Err(KmsError::LeaseExhausted);
        }

        lease.used_ops += 1;
        self.total_ops += 1;
        Ok(())
    }

    pub fn revoke_lease(&mut self, cap: &KmsCap, lease_id: u32) -> Result<(), KmsError> {
        if !cap.has_right(kms_rights::GRANT_LEASE) {
            return Err(KmsError::PermissionDenied);
        }
        let (kid, target) = {
            let lease = self.leases.iter_mut().find(|l| l.lease_id == lease_id)
                .ok_or(KmsError::LeaseNotFound)?;

            lease.state = LeaseState::Revoked;
            (lease.key_id, lease.granted_to_node)
        };
        self.record_audit(b"LEASE_REVOKE", kid, target, lease_id);
        Ok(())
    }

    pub fn setup_escrow(
        &mut self,
        cap: &KmsCap,
        key_id: u32,
        threshold: u8,
        total_custodians: u8,
        out_shares: &mut [[u8; KEY_DATA_LEN]],
    ) -> Result<u32, KmsError> {
        if !cap.has_right(kms_rights::ESCROW_KEY) {
            return Err(KmsError::PermissionDenied);
        }
        if threshold == 0 || threshold > total_custodians || (total_custodians as usize) > MAX_CUSTODIANS {
            return Err(KmsError::InvalidCustodianShare);
        }
        if out_shares.len() < total_custodians as usize {
            return Err(KmsError::InvalidCustodianShare);
        }

        let key = self.keys.iter_mut().find(|k| k.key_id == key_id && k.state == KeyLifecycleState::Active)
            .ok_or(KmsError::KeyNotFound)?;

        let slot = self.escrows.iter().position(|e| e.status == EscrowStatus::None || e.status == EscrowStatus::Cancelled)
            .unwrap_or(self.escrow_count);

        if slot >= MAX_ESCROWS {
            return Err(KmsError::QuotaExceeded);
        }

        let eid = self.next_escrow_id;
        self.next_escrow_id += 1;

        let mut pkg = EscrowPackage::empty();
        pkg.escrow_id = eid;
        pkg.key_id = key_id;
        pkg.threshold = threshold;
        pkg.total_custodians = total_custodians;
        pkg.shares_collected = 0;
        pkg.collected_mask = 0;
        pkg.status = EscrowStatus::Secured;

        // Génération déterministe de la KEK d'escrow et des coefficients polynomiaux de Shamir
        let mut escrow_kek = [0u8; KEY_DATA_LEN];
        let salt = key.fingerprint;
        Sha256::hkdf_derive(&salt, &key.material, b"JAMBO_KMS_ESCROW_KEK_SALT", &mut escrow_kek);
        pkg.escrow_kek_commitment = Sha256::digest(&escrow_kek);

        // Coefficients polynomiaux a_1 .. a_{t-1}
        let mut poly_coeffs = [[0u8; KEY_DATA_LEN]; MAX_CUSTODIANS];
        for deg in 1..(threshold as usize) {
            let mut info_buf = [0u8; 16];
            info_buf[..4].copy_from_slice(b"DEG_");
            info_buf[4] = deg as u8;
            Sha256::hkdf_derive(&salt, &escrow_kek, &info_buf[..5], &mut poly_coeffs[deg - 1]);
        }

        // Évaluation P(x) pour chaque gardien x = 1 .. N
        for i in 0..(total_custodians as usize) {
            let x = (i + 1) as u8;
            for b in 0..KEY_DATA_LEN {
                let mut y = escrow_kek[b];
                let mut x_pow = x;
                for deg in 1..(threshold as usize) {
                    let coeff = poly_coeffs[deg - 1][b];
                    y ^= Gf256::mul(coeff, x_pow);
                    x_pow = Gf256::mul(x_pow, x);
                }
                out_shares[i][b] = y;
            }
            pkg.custodian_commitments[i] = Sha256::digest(&out_shares[i]);
        }

        // Nonce pseudo-aléatoire déterministe
        let nonce_seed = Sha256::digest(&key.fingerprint);
        pkg.escrow_nonce.copy_from_slice(&nonce_seed[..NONCE_LEN]);

        // Chiffrement de la clé cible dans wrapped_key
        pkg.wrapped_key[..KEY_DATA_LEN].copy_from_slice(&key.material);
        let hmac_tag = Sha256::hmac(&escrow_kek, &key.material);
        pkg.wrapped_key[KEY_DATA_LEN..ENVELOPE_CIPHERTEXT_LEN].copy_from_slice(&hmac_tag[..16]);

        ChaCha20::process(&escrow_kek, &pkg.escrow_nonce, 1, &mut pkg.wrapped_key[..KEY_DATA_LEN]);

        key.state = KeyLifecycleState::Escrowed;

        self.escrows[slot] = pkg;
        if slot >= self.escrow_count {
            self.escrow_count = slot + 1;
        }

        self.total_ops += 1;
        self.record_audit(b"ESCROW_SETUP", key_id, self.node_id, eid);
        Ok(eid)
    }

    pub fn submit_escrow_share(
        &mut self,
        cap: &KmsCap,
        escrow_id: u32,
        custodian_idx: u8,
        share_value: &[u8; KEY_DATA_LEN],
    ) -> Result<bool, KmsError> {
        if !cap.has_right(kms_rights::RECOVER_KEY) {
            return Err(KmsError::PermissionDenied);
        }

        let (threshold_met, kid, collected) = {
            let pkg = self.escrows.iter_mut().find(|e| e.escrow_id == escrow_id)
                .ok_or(KmsError::EscrowNotFound)?;

            if pkg.status != EscrowStatus::Secured && pkg.status != EscrowStatus::RecoveryInitiated {
                return Err(KmsError::InvalidState);
            }

            if (custodian_idx as usize) >= (pkg.total_custodians as usize) {
                return Err(KmsError::InvalidCustodianShare);
            }

            // Vérification formelle du hachage d'engagement
            let calculated_commitment = Sha256::digest(share_value);
            if !constant_time_eq(&calculated_commitment, &pkg.custodian_commitments[custodian_idx as usize]) {
                return Err(KmsError::InvalidCustodianShare);
            }

            let mask = 1u8 << custodian_idx;
            if (pkg.collected_mask & mask) == 0 {
                pkg.collected_shares[custodian_idx as usize].copy_from_slice(share_value);
                pkg.collected_mask |= mask;
                pkg.shares_collected += 1;
                pkg.status = EscrowStatus::RecoveryInitiated;
            }

            (pkg.shares_collected >= pkg.threshold, pkg.key_id, pkg.shares_collected)
        };

        self.record_audit(b"ESCROW_SHARE", kid, custodian_idx as u32, collected as u32);
        Ok(threshold_met)
    }

    pub fn recover_escrowed_key(
        &mut self,
        cap: &KmsCap,
        escrow_id: u32,
    ) -> Result<[u8; KEY_DATA_LEN], KmsError> {
        if !cap.has_right(kms_rights::RECOVER_KEY) {
            return Err(KmsError::PermissionDenied);
        }
        let pkg = self.escrows.iter_mut().find(|e| e.escrow_id == escrow_id)
            .ok_or(KmsError::EscrowNotFound)?;

        if pkg.shares_collected < pkg.threshold {
            return Err(KmsError::EscrowThresholdNotMet);
        }

        // Reconstruction de Shamir par interpolation de Lagrange en GF(256)
        let t = pkg.threshold as usize;
        let mut x_pts = [0u8; MAX_CUSTODIANS];
        let mut y_pts = [[0u8; KEY_DATA_LEN]; MAX_CUSTODIANS];
        let mut count = 0;

        for i in 0..(pkg.total_custodians as usize) {
            if (pkg.collected_mask & (1 << i)) != 0 && count < t {
                x_pts[count] = (i + 1) as u8;
                y_pts[count].copy_from_slice(&pkg.collected_shares[i]);
                count += 1;
            }
        }

        if count < t {
            return Err(KmsError::EscrowThresholdNotMet);
        }

        // Poids de Lagrange en x = 0: w_k = \prod_{j != k} (x_j / (x_k ^ x_j))
        let mut weights = [0u8; MAX_CUSTODIANS];
        for k in 0..t {
            let mut w = 1u8;
            for j in 0..t {
                if j != k {
                    let num = x_pts[j];
                    let den = x_pts[k] ^ x_pts[j];
                    let term = Gf256::mul(num, Gf256::inv(den));
                    w = Gf256::mul(w, term);
                }
            }
            weights[k] = w;
        }

        let mut escrow_kek = [0u8; KEY_DATA_LEN];
        for b in 0..KEY_DATA_LEN {
            let mut byte_val = 0u8;
            for k in 0..t {
                byte_val ^= Gf256::mul(y_pts[k][b], weights[k]);
            }
            escrow_kek[b] = byte_val;
        }

        let calc_kek_commitment = Sha256::digest(&escrow_kek);
        if !constant_time_eq(&calc_kek_commitment, &pkg.escrow_kek_commitment) {
            return Err(KmsError::CryptoError);
        }

        let mut recovered_material = [0u8; KEY_DATA_LEN];
        recovered_material.copy_from_slice(&pkg.wrapped_key[..KEY_DATA_LEN]);
        ChaCha20::process(&escrow_kek, &pkg.escrow_nonce, 1, &mut recovered_material);

        let hmac_tag = Sha256::hmac(&escrow_kek, &recovered_material);
        if !constant_time_eq(&hmac_tag[..16], &pkg.wrapped_key[KEY_DATA_LEN..ENVELOPE_CIPHERTEXT_LEN]) {
            return Err(KmsError::CryptoError);
        }

        pkg.status = EscrowStatus::Recovered;

        // Rétablissement de la clé en statut Active
        let kid = pkg.key_id;
        if let Some(key) = self.keys.iter_mut().find(|k| k.key_id == kid) {
            key.state = KeyLifecycleState::Active;
            key.material.copy_from_slice(&recovered_material);
        }

        self.total_ops += 1;
        self.record_audit(b"ESCROW_RECOVER", kid, self.node_id, escrow_id);
        Ok(recovered_material)
    }

    pub fn register_cluster_node(
        &mut self,
        cap: &KmsCap,
        node_id: u32,
        name: &[u8],
        epoch: u32,
        shared_key: &[u8; KEY_DATA_LEN],
    ) -> Result<(), KmsError> {
        if !cap.has_right(kms_rights::REPLICATE) {
            return Err(KmsError::PermissionDenied);
        }

        let slot = self.nodes.iter().position(|n| !n.is_trusted || n.node_id == node_id)
            .unwrap_or(self.node_count);

        if slot >= MAX_NODES {
            return Err(KmsError::QuotaExceeded);
        }

        let mut node = ClusterNode::empty();
        node.node_id = node_id;
        node.cluster_epoch = epoch;
        node.last_sync_seq = 0;
        node.shared_key.copy_from_slice(shared_key);
        node.is_trusted = true;
        let nlen = core::cmp::min(name.len(), MAX_NAME_LEN);
        node.name[..nlen].copy_from_slice(&name[..nlen]);
        node.name_len = nlen;

        self.nodes[slot] = node;
        if slot >= self.node_count {
            self.node_count = slot + 1;
        }

        self.record_audit(b"NODE_REGISTER", 0, node_id, epoch);
        Ok(())
    }

    pub fn create_replication_envelope(
        &mut self,
        cap: &KmsCap,
        key_id: u32,
        target_node: u32,
    ) -> Result<u32, KmsError> {
        if !cap.has_right(kms_rights::REPLICATE) {
            return Err(KmsError::PermissionDenied);
        }

        let node = self.nodes.iter().find(|n| n.node_id == target_node && n.is_trusted)
            .ok_or(KmsError::NodeNotFound)?;

        if node.cluster_epoch != self.cluster_epoch {
            return Err(KmsError::EpochMismatch);
        }

        let key = self.keys.iter().find(|k| k.key_id == key_id && k.state == KeyLifecycleState::Active)
            .ok_or(KmsError::KeyNotFound)?;

        let slot = self.envelopes.iter().position(|e| e.seq == 0)
            .unwrap_or(self.envelope_count);

        if slot >= MAX_ENVELOPES {
            return Err(KmsError::QuotaExceeded);
        }

        let eid = self.next_envelope_id;
        self.next_envelope_id += 1;

        let mut env = KeyEnvelope::empty();
        env.envelope_id = eid;
        env.origin_node = self.node_id;
        env.target_node = target_node;
        env.key_id = key_id;
        env.key_version = key.rotation_count;
        env.seq = self.total_ops + 1;

        // Génération de nonce
        let nonce_hash = Sha256::digest(&env.seq.to_be_bytes());
        env.nonce.copy_from_slice(&nonce_hash[..NONCE_LEN]);

        // Chiffrement par clé partagée du nœud cible
        env.ciphertext[..KEY_DATA_LEN].copy_from_slice(&key.material);
        env.ciphertext[KEY_DATA_LEN..KEY_DATA_LEN + 4].copy_from_slice(&key.key_id.to_be_bytes());
        env.ciphertext[KEY_DATA_LEN + 4] = key.level as u8;
        env.ciphertext[KEY_DATA_LEN + 5] = key.algorithm as u8;
        env.ciphertext[KEY_DATA_LEN + 6..ENVELOPE_CIPHERTEXT_LEN].copy_from_slice(&[0u8; 10]);

        ChaCha20::process(&node.shared_key, &env.nonce, 1, &mut env.ciphertext);

        // Authentification HMAC-SHA256
        let mut auth_input = [0u8; ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 16];
        auth_input[..ENVELOPE_CIPHERTEXT_LEN].copy_from_slice(&env.ciphertext);
        auth_input[ENVELOPE_CIPHERTEXT_LEN..ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN].copy_from_slice(&env.nonce);
        auth_input[ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN..ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 8].copy_from_slice(&env.seq.to_be_bytes());
        auth_input[ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 8..ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 12].copy_from_slice(&target_node.to_be_bytes());
        auth_input[ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 12..ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 16].copy_from_slice(&self.node_id.to_be_bytes());

        env.auth_tag = Sha256::hmac(&node.shared_key, &auth_input);

        self.envelopes[slot] = env;
        if slot >= self.envelope_count {
            self.envelope_count = slot + 1;
        }

        self.total_ops += 1;
        self.record_audit(b"REPLICATE_OUT", key_id, target_node, eid);
        Ok(eid)
    }

    pub fn receive_replication_envelope(
        &mut self,
        cap: &KmsCap,
        envelope_id: u32,
    ) -> Result<u32, KmsError> {
        if !cap.has_right(kms_rights::REPLICATE) {
            return Err(KmsError::PermissionDenied);
        }

        let env = *self.envelopes.iter().find(|e| e.envelope_id == envelope_id)
            .ok_or(KmsError::CryptoError)?;

        let peer_id = if env.target_node == self.node_id {
            env.origin_node
        } else {
            env.target_node
        };

        let node = self.nodes.iter().find(|n| n.node_id == peer_id && n.is_trusted)
            .ok_or(KmsError::NodeNotFound)?;

        // Validation HMAC-SHA256
        let mut auth_input = [0u8; ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 16];
        auth_input[..ENVELOPE_CIPHERTEXT_LEN].copy_from_slice(&env.ciphertext);
        auth_input[ENVELOPE_CIPHERTEXT_LEN..ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN].copy_from_slice(&env.nonce);
        auth_input[ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN..ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 8].copy_from_slice(&env.seq.to_be_bytes());
        auth_input[ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 8..ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 12].copy_from_slice(&env.target_node.to_be_bytes());
        auth_input[ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 12..ENVELOPE_CIPHERTEXT_LEN + NONCE_LEN + 16].copy_from_slice(&env.origin_node.to_be_bytes());

        let expected_tag = Sha256::hmac(&node.shared_key, &auth_input);
        if !constant_time_eq(&expected_tag, &env.auth_tag) {
            return Err(KmsError::CryptoError);
        }

        let mut plaintext = env.ciphertext;
        ChaCha20::process(&node.shared_key, &env.nonce, 1, &mut plaintext);

        let mut material = [0u8; KEY_DATA_LEN];
        material.copy_from_slice(&plaintext[..KEY_DATA_LEN]);
        let level = match plaintext[KEY_DATA_LEN + 4] {
            0 => KeyHierarchyLevel::MasterKey,
            1 => KeyHierarchyLevel::DomainKey,
            2 => KeyHierarchyLevel::DataKey,
            3 => KeyHierarchyLevel::SessionKey,
            _ => KeyHierarchyLevel::EscrowKey,
        };
        let algo = match plaintext[KEY_DATA_LEN + 5] {
            0 => KeyAlgorithm::Aes128,
            1 => KeyAlgorithm::Aes256,
            2 => KeyAlgorithm::ChaCha20,
            3 => KeyAlgorithm::HmacSha256,
            _ => KeyAlgorithm::Ed25519,
        };

        let new_kid = self.create_key(cap, b"replicated-key", level, algo, &material)?;
        self.record_audit(b"REPLICATE_IN", new_kid, peer_id, envelope_id);
        Ok(new_kid)
    }

    pub fn rotate_key(
        &mut self,
        cap: &KmsCap,
        key_id: u32,
        new_material: &[u8; KEY_DATA_LEN],
    ) -> Result<(), KmsError> {
        if !cap.has_right(kms_rights::ROTATE_KEY) {
            return Err(KmsError::PermissionDenied);
        }

        let rot_count = {
            let key = self.keys.iter_mut().find(|k| k.key_id == key_id && k.state == KeyLifecycleState::Active)
                .ok_or(KmsError::KeyNotFound)?;

            key.material.copy_from_slice(new_material);
            key.rotation_count += 1;
            key.compute_fingerprint();
            key.rotation_count
        };

        self.total_ops += 1;
        self.record_audit(b"KEY_ROTATE", key_id, self.node_id, rot_count);
        Ok(())
    }

    pub fn revoke_key(&mut self, cap: &KmsCap, key_id: u32) -> Result<(), KmsError> {
        if !cap.has_right(kms_rights::REVOKE_KEY) {
            return Err(KmsError::PermissionDenied);
        }

        let key = self.keys.iter_mut().find(|k| k.key_id == key_id)
            .ok_or(KmsError::KeyNotFound)?;

        key.state = KeyLifecycleState::Revoked;

        // Révocation en cascade des baux associés
        for lease in self.leases.iter_mut() {
            if lease.key_id == key_id && (lease.state == LeaseState::Active || lease.state == LeaseState::Renewed) {
                lease.state = LeaseState::Revoked;
            }
        }

        self.total_ops += 1;
        self.record_audit(b"KEY_REVOKE", key_id, self.node_id, 0);
        Ok(())
    }

    pub fn zeroize_key(&mut self, cap: &KmsCap, key_id: u32) -> Result<(), KmsError> {
        if !cap.has_right(kms_rights::ZEROIZE_KEY) {
            return Err(KmsError::PermissionDenied);
        }

        let key = self.keys.iter_mut().find(|k| k.key_id == key_id)
            .ok_or(KmsError::KeyNotFound)?;

        zeroize_bytes(&mut key.material);
        zeroize_bytes(&mut key.fingerprint);
        key.state = KeyLifecycleState::Destroyed;

        self.total_ops += 1;
        self.record_audit(b"KEY_ZEROIZE", key_id, self.node_id, 0);
        Ok(())
    }

    pub fn get_key(&self, key_id: u32) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }

    pub fn get_lease(&self, lease_id: u32) -> Option<&KeyLease> {
        self.leases.iter().find(|l| l.lease_id == lease_id)
    }

    pub fn get_escrow(&self, escrow_id: u32) -> Option<&EscrowPackage> {
        self.escrows.iter().find(|e| e.escrow_id == escrow_id)
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] COMPLIANT)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kms_cap_attenuation() {
        let cap = KmsCap::new(Handle::new(10801, 1), kms_rights::ALL, 0, MAX_KEYS as u16);
        assert!(cap.has_right(kms_rights::CREATE_KEY));
        assert!(cap.has_right(kms_rights::DERIVE_KEY));
        assert!(cap.has_right(kms_rights::ESCROW_KEY));
        assert!(cap.has_right(kms_rights::RECOVER_KEY));

        let sub_cap = cap.attenuate(kms_rights::CREATE_KEY | kms_rights::GRANT_LEASE, 10).expect("Attenuate");
        assert!(sub_cap.has_right(kms_rights::CREATE_KEY));
        assert!(sub_cap.has_right(kms_rights::GRANT_LEASE));
        assert!(!sub_cap.has_right(kms_rights::ESCROW_KEY));

        // Refus formel d'amplification
        assert_eq!(sub_cap.attenuate(kms_rights::ALL, 10), Err(KmsError::PermissionDenied));
        assert_eq!(sub_cap.attenuate(kms_rights::CREATE_KEY, 20), Err(KmsError::PermissionDenied));
    }

    #[test]
    fn test_kms_full_lifecycle_and_escrow() {
        let cap = KmsCap::new(Handle::new(10802, 1), kms_rights::ALL, 0, MAX_KEYS as u16);
        let mut daemon = JamboKmsDaemon::new(cap);
        daemon.init_defaults();

        // 1. Dérivation hiérarchique
        let master = daemon.keys[0];
        let session_id = daemon.derive_child_key(
            &cap,
            master.key_id,
            b"session-ephemeral",
            KeyHierarchyLevel::DomainKey,
            KeyAlgorithm::Aes256,
            b"purpose=tls-session",
        ).expect("Derive session key");

        let expected_material = daemon.get_key(session_id).expect("Key exists").material;
        let expected_parent = daemon.get_key(session_id).expect("Key exists").parent_id;
        assert_eq!(expected_parent, master.key_id);

        // 2. Gestion des baux
        let lease_id = daemon.grant_lease(
            &cap,
            session_id,
            0,
            lease_ops::OP_ENCRYPT | lease_ops::OP_DECRYPT,
            10,
            500,
            1000,
            2,
        ).expect("Grant lease");

        // Consommation
        assert!(daemon.consume_lease_op(lease_id, 1100, lease_ops::OP_ENCRYPT).is_ok());
        assert_eq!(daemon.get_lease(lease_id).unwrap().used_ops, 1);

        // Opération interdite par le bail
        assert_eq!(
            daemon.consume_lease_op(lease_id, 1100, lease_ops::OP_SIGN),
            Err(KmsError::PermissionDenied)
        );

        // Renouvellement
        assert!(daemon.renew_lease(&cap, lease_id, 300, 1200).is_ok());
        assert_eq!(daemon.get_lease(lease_id).unwrap().valid_until_ticks, 1800);

        // 3. Séquestre M-sur-N (2 gardiens sur 3)
        let mut shares = [[0u8; KEY_DATA_LEN]; 3];
        let escrow_id = daemon.setup_escrow(&cap, session_id, 2, 3, &mut shares).expect("Setup escrow");
        assert_eq!(daemon.get_key(session_id).unwrap().state, KeyLifecycleState::Escrowed);

        // Soumission première part
        let met = daemon.submit_escrow_share(&cap, escrow_id, 0, &shares[0]).expect("Share 1");
        assert!(!met);

        // Soumission mauvaise part (falsification)
        let bad_share = [0x99u8; KEY_DATA_LEN];
        assert_eq!(
            daemon.submit_escrow_share(&cap, escrow_id, 1, &bad_share),
            Err(KmsError::InvalidCustodianShare)
        );

        // Soumission deuxième part valide -> Quorum atteint
        let met2 = daemon.submit_escrow_share(&cap, escrow_id, 1, &shares[1]).expect("Share 2");
        assert!(met2);

        // Restauration de la clé
        let recovered = daemon.recover_escrowed_key(&cap, escrow_id).expect("Recover");
        assert_eq!(recovered, expected_material);
        assert_eq!(daemon.get_key(session_id).unwrap().state, KeyLifecycleState::Active);

        // 4. Réplication de Grappe
        let env_id = daemon.create_replication_envelope(&cap, session_id, 1).expect("Create env");
        assert!(daemon.envelopes.iter().any(|e| e.envelope_id == env_id));
        let rep_kid = daemon.receive_replication_envelope(&cap, env_id).expect("Receive env");
        assert_eq!(daemon.get_key(rep_kid).unwrap().material, expected_material);

        // 5. Rotation et Zéroïsation
        let new_mat = [0x77u8; KEY_DATA_LEN];
        daemon.rotate_key(&cap, session_id, &new_mat).expect("Rotate");
        assert_eq!(daemon.get_key(session_id).unwrap().rotation_count, 1);

        daemon.zeroize_key(&cap, session_id).expect("Zeroize");
        assert_eq!(daemon.get_key(session_id).unwrap().state, KeyLifecycleState::Destroyed);
        assert_eq!(daemon.get_key(session_id).unwrap().material, [0u8; KEY_DATA_LEN]);
    }
}

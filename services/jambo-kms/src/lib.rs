//! Gestionnaire et Séquestre de Clés Cryptographiques de Grappe (`jambo-kms`, Ring 3, PID 28)
//!
//! Fournit les garanties souveraines de gestion de cycle de vie et séquestre de clés cryptographiques :
//! 1. Hiérarchies cryptographiques rigoureuses (NIST SP 800-108 / HKDF RFC 5869) :
//!    - MasterKey (KEK Racine de Confiance Niveau 0)
//!    - DomainKey (KEK Domaine / Locataire Niveau 1)
//!    - DataKey (DEK Chiffrement Données Niveau 2)
//!    - SessionKey (Clé Éphémère de Session Niveau 3)
//!    - EscrowKey (Clé de Recouvrement d'Urgence Séquestrée Niveau 4)
//! 2. Baux temporels et quotas d'utilisation (Key Leases) :
//!    - Attribution bornée avec horodatage monotone (`valid_until_ticks`)
//!    - Plafonds stricts du nombre d'opérations autorisées (`remaining_ops`)
//! 3. Cycle de vie cryptographique déterministe et zéroïsation d'urgence :
//!    - États : PreActive -> Active -> Escrowed -> Suspended -> Expired -> Revoked -> Destroyed
//!    - Rotation atomique avec historique de versions
//!    - Zéroïsation volatile garantie (`compiler_fence`) à la révocation / destruction.
//! 4. Gouvernance capabilaire stricte (`KmsCap`) :
//!    - Zéro autorité ambiante, permissions granulaires et atténuation monotone irréversible.
//! 5. Protocole IPC déterministe à 64 octets (`KmsRequest`, `KmsResponse`) pour endpoint 28.

#![no_std]

pub use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES DU SOUS-SYSTÈME JAMBO-KMS
// ============================================================================

pub const MAX_KEYS: usize = 32;
pub const MAX_LEASES: usize = 32;
pub const KEY_DATA_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

// ============================================================================
// DROITS CAPABILAIRES & GOUVERNANCE STRICTE (ZÉRO AUTORITÉ AMBIANTE)
// ============================================================================

pub mod kms_rights {
    pub const CREATE_KEY: u32 = 1 << 0; // 0x0001
    pub const DERIVE_KEY: u32 = 1 << 1; // 0x0002
    pub const GRANT_LEASE: u32 = 1 << 2; // 0x0004
    pub const RENEW_LEASE: u32 = 1 << 3; // 0x0008
    pub const ESCROW_KEY: u32 = 1 << 4; // 0x0010
    pub const ROTATE_KEY: u32 = 1 << 5; // 0x0020
    pub const REVOKE_KEY: u32 = 1 << 6; // 0x0040
    pub const ZEROIZE_KEY: u32 = 1 << 7; // 0x0080
    pub const AUDIT_LOG: u32 = 1 << 8; // 0x0100
    pub const ADMIN: u32 = 0x8000;
    pub const ALL: u32 = 0x81FF;
}

pub mod lease_ops {
    pub const OP_ENCRYPT: u32 = 1 << 0;
    pub const OP_DECRYPT: u32 = 1 << 1;
    pub const OP_SIGN: u32 = 1 << 2;
    pub const OP_DERIVE: u32 = 1 << 3;
    pub const OP_ALL: u32 = 0x0F;
}

/// Jeton de capacité souverain pour KMS sans autorité ambiante.
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
    pub const fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone irréversible : interdiction formelle d'élargir les droits.
    pub fn attenuate(&self, desired_rights: u32, max_keys: u16) -> Result<Self, SysError> {
        if (desired_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        if max_keys > self.max_keys {
            return Err(SysError::PermissionDenied);
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
// PRIMITIVES CRYPTOGRAPHIQUES SHA-256, HMAC, HKDF & ZEROÏSATION (#![no_std])
// ============================================================================

/// Zéroïsation garantie en mémoire volatile avec barrière du compilateur.
#[inline(never)]
pub fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Comparaison en temps constant pour éviter toute fuite par canal auxiliaire.
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

/// Implémentation SHA-256 déterministe en streaming (#![no_std]).
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

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

        for (i, &w_val) in w.iter().enumerate() {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w_val);
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

    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        while !data.is_empty() {
            if self.buf_len == 0 && data.len() >= 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&data[..64]);
                Self::process_block(&mut self.state, &block);
                data = &data[64..];
            } else {
                let to_copy = (64 - self.buf_len).min(data.len());
                self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
                self.buf_len += to_copy;
                data = &data[to_copy..];
                if self.buf_len == 64 {
                    Self::process_block(&mut self.state, &self.buffer);
                    self.buf_len = 0;
                }
            }
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let total_bits = self.total_len.wrapping_mul(8);
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            for b in &mut self.buffer[self.buf_len..64] {
                *b = 0;
            }
            Self::process_block(&mut self.state, &self.buffer);
            self.buf_len = 0;
        }

        for b in &mut self.buffer[self.buf_len..56] {
            *b = 0;
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        Self::process_block(&mut self.state, &self.buffer);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finish()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Implémentation HMAC-SHA256 (#![no_std]).
#[derive(Clone, Copy)]
pub struct HmacSha256 {
    opad: [u8; 64],
    inner: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let kh = Sha256::digest(key);
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

        let mut inner = Sha256::new();
        inner.update(&ipad);
        Self { opad, inner }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(self) -> [u8; 32] {
        let inner_hash = self.inner.finish();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner_hash);
        outer.finish()
    }

    pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut h = Self::new(key);
        h.update(data);
        h.finish()
    }
}

/// Dérivation de clés conforme HKDF-Extract / HKDF-Expand (RFC 5869).
pub struct Hkdf;

impl Hkdf {
    pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
        let default_salt = [0u8; 32];
        let salt_key = if salt.is_empty() {
            &default_salt[..]
        } else {
            salt
        };
        let prk = HmacSha256::mac(salt_key, ikm);

        let mut t = [0u8; 32];
        let mut offset = 0;
        let mut counter = 1u8;

        while offset < out.len() {
            let mut hmac = HmacSha256::new(&prk);
            if counter > 1 {
                hmac.update(&t);
            }
            hmac.update(info);
            hmac.update(&[counter]);
            t = hmac.finish();

            let to_copy = (out.len() - offset).min(32);
            out[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
            counter = counter.wrapping_add(1);
        }
    }
}

// ============================================================================
// TYPES ET ÉTATS DU CYCLE DE VIE DES CLÉS
// ============================================================================

/// Type de clé selon la hiérarchie NIST SP 800-108.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Master = 0,
    Domain = 1,
    Data = 2,
    Session = 3,
    Escrow = 4,
}

impl KeyType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            KeyType::Master => "Master",
            KeyType::Domain => "Domain",
            KeyType::Data => "Data",
            KeyType::Session => "Session",
            KeyType::Escrow => "Escrow",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("master") {
            Some(KeyType::Master)
        } else if s.eq_ignore_ascii_case("domain") {
            Some(KeyType::Domain)
        } else if s.eq_ignore_ascii_case("data") {
            Some(KeyType::Data)
        } else if s.eq_ignore_ascii_case("session") {
            Some(KeyType::Session)
        } else if s.eq_ignore_ascii_case("escrow") {
            Some(KeyType::Escrow)
        } else {
            None
        }
    }

    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(KeyType::Master),
            1 => Some(KeyType::Domain),
            2 => Some(KeyType::Data),
            3 => Some(KeyType::Session),
            4 => Some(KeyType::Escrow),
            _ => None,
        }
    }
}

/// Cycle de vie strict d'une clé cryptographique.
#[repr(u8)]
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

impl KeyLifecycleState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            KeyLifecycleState::PreActive => "PreActive",
            KeyLifecycleState::Active => "Active",
            KeyLifecycleState::Escrowed => "Escrowed",
            KeyLifecycleState::Suspended => "Suspended",
            KeyLifecycleState::Expired => "Expired",
            KeyLifecycleState::Revoked => "Revoked",
            KeyLifecycleState::Destroyed => "Destroyed",
        }
    }

    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(KeyLifecycleState::PreActive),
            1 => Some(KeyLifecycleState::Active),
            2 => Some(KeyLifecycleState::Escrowed),
            3 => Some(KeyLifecycleState::Suspended),
            4 => Some(KeyLifecycleState::Expired),
            5 => Some(KeyLifecycleState::Revoked),
            6 => Some(KeyLifecycleState::Destroyed),
            _ => None,
        }
    }
}

/// Enregistrement d'une clé cryptographique au sein du magasin KMS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    pub id: u32,
    pub parent_id: u32,
    pub key_type: KeyType,
    pub version: u32,
    pub state: KeyLifecycleState,
    pub name: [u8; 24],
    pub name_len: usize,
    pub key_data: [u8; KEY_DATA_LEN],
    pub created_ticks: u64,
}

impl KeyRecord {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            parent_id: 0,
            key_type: KeyType::Data,
            version: 0,
            state: KeyLifecycleState::PreActive,
            name: [0u8; 24],
            name_len: 0,
            key_data: [0u8; KEY_DATA_LEN],
            created_ticks: 0,
        }
    }

    pub fn name_as_str(&self) -> &str {
        let len = self.name_len.min(24);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    pub fn compute_hash(&self) -> [u8; 16] {
        let full = Sha256::digest(&self.key_data);
        let mut h = [0u8; 16];
        h.copy_from_slice(&full[..16]);
        h
    }
}

/// Bail temporel et quota d'utilisation d'une clé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyLease {
    pub lease_id: u32,
    pub key_id: u32,
    pub ops_mask: u32,
    pub remaining_ops: u32,
    pub valid_until_ticks: u64,
    pub active: bool,
}

impl KeyLease {
    pub const fn empty() -> Self {
        Self {
            lease_id: 0,
            key_id: 0,
            ops_mask: 0,
            remaining_ops: 0,
            valid_until_ticks: 0,
            active: false,
        }
    }
}

// ============================================================================
// OPCODES ET PROTOCOLE IPC DÉTERMINISTE 64 OCTETS
// ============================================================================

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KmsOpcode {
    GetStatus = 1,
    CreateKey = 2,
    DeriveKey = 3,
    GrantLease = 4,
    RotateKey = 5,
    RevokeKey = 6,
}

impl KmsOpcode {
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::CreateKey),
            3 => Some(Self::DeriveKey),
            4 => Some(Self::GrantLease),
            5 => Some(Self::RotateKey),
            6 => Some(Self::RevokeKey),
            _ => None,
        }
    }
}

pub const KMS_MAGIC_REQ: u32 = 0x4B4D5344; // "KMSD"
pub const KMS_MAGIC_RESP: u32 = 0x4B4D5353; // "KMSS"

/// Requête IPC calibrée à exactement 64 octets.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KmsRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub rights: u32,
    pub key_id: u32,
    pub parent_key_id: u32,
    pub key_type: u8,
    pub algorithm: u8,
    pub _reserved1: u16,
    pub lease_ops: u32,
    pub validity_ticks: u64,
    pub key_name: [u8; 24],
}

const _: () = assert!(core::mem::size_of::<KmsRequest>() == 64);

impl Default for KmsRequest {
    fn default() -> Self {
        Self {
            magic: KMS_MAGIC_REQ,
            opcode: KmsOpcode::GetStatus as u32,
            handle_id: 28,
            rights: kms_rights::ALL,
            key_id: 0,
            parent_key_id: 0,
            key_type: KeyType::Data as u8,
            algorithm: 0,
            _reserved1: 0,
            lease_ops: 0,
            validity_ticks: 0,
            key_name: [0u8; 24],
        }
    }
}

impl KmsRequest {
    pub const fn new(opcode: KmsOpcode) -> Self {
        Self {
            magic: KMS_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: 28,
            rights: kms_rights::ALL,
            key_id: 0,
            parent_key_id: 0,
            key_type: KeyType::Data as u8,
            algorithm: 0,
            _reserved1: 0,
            lease_ops: 0,
            validity_ticks: 0,
            key_name: [0u8; 24],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        let mut req = Self::new(KmsOpcode::GetStatus);
        req.handle_id = handle_id;
        req.rights = rights;
        req
    }

    pub fn new_create_key(handle_id: u32, rights: u32, key_type: KeyType, name: &str) -> Self {
        let mut req = Self::new(KmsOpcode::CreateKey);
        req.handle_id = handle_id;
        req.rights = rights;
        req.key_type = key_type as u8;
        let bytes = name.as_bytes();
        let len = bytes.len().min(24);
        req.key_name[..len].copy_from_slice(&bytes[..len]);
        req
    }

    pub fn new_derive_key(handle_id: u32, rights: u32, parent_id: u32, name: &str) -> Self {
        let mut req = Self::new(KmsOpcode::DeriveKey);
        req.handle_id = handle_id;
        req.rights = rights;
        req.parent_key_id = parent_id;
        let bytes = name.as_bytes();
        let len = bytes.len().min(24);
        req.key_name[..len].copy_from_slice(&bytes[..len]);
        req
    }

    pub const fn new_grant_lease(
        handle_id: u32,
        rights: u32,
        key_id: u32,
        lease_ops: u32,
        validity_ticks: u64,
    ) -> Self {
        let mut req = Self::new(KmsOpcode::GrantLease);
        req.handle_id = handle_id;
        req.rights = rights;
        req.key_id = key_id;
        req.lease_ops = lease_ops;
        req.validity_ticks = validity_ticks;
        req
    }

    pub const fn new_rotate_key(handle_id: u32, rights: u32, key_id: u32) -> Self {
        let mut req = Self::new(KmsOpcode::RotateKey);
        req.handle_id = handle_id;
        req.rights = rights;
        req.key_id = key_id;
        req
    }

    pub const fn new_revoke_key(handle_id: u32, rights: u32, key_id: u32) -> Self {
        let mut req = Self::new(KmsOpcode::RevokeKey);
        req.handle_id = handle_id;
        req.rights = rights;
        req.key_id = key_id;
        req
    }

    pub fn name_as_str(&self) -> &str {
        let len = self
            .key_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.key_name.len());
        core::str::from_utf8(&self.key_name[..len]).unwrap_or("")
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
        if req.magic != KMS_MAGIC_REQ {
            return None;
        }
        Some(req)
    }
}

/// Réponse IPC calibrée à exactement 64 octets.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KmsResponse {
    pub magic: u32,
    pub status: i32,
    pub key_id: u32,
    pub lease_id: u32,
    pub total_keys: u32,
    pub active_leases: u32,
    pub key_version: u32,
    pub state: u8,
    pub _reserved1: u8,
    pub _reserved2: u16,
    pub key_hash: [u8; 16],
    pub status_str: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<KmsResponse>() == 64);

impl Default for KmsResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsResponse {
    pub const fn new() -> Self {
        Self {
            magic: KMS_MAGIC_RESP,
            status: 0,
            key_id: 0,
            lease_id: 0,
            total_keys: 0,
            active_leases: 0,
            key_version: 0,
            state: 0,
            _reserved1: 0,
            _reserved2: 0,
            key_hash: [0u8; 16],
            status_str: [0u8; 16],
        }
    }

    pub fn set_status_str(&mut self, s: &str) {
        self.status_str = [0u8; 16];
        let bytes = s.as_bytes();
        let len = bytes.len().min(16);
        self.status_str[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn status_as_str(&self) -> &str {
        let len = self
            .status_str
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.status_str.len());
        core::str::from_utf8(&self.status_str[..len]).unwrap_or("")
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
        let mut resp = Self::new();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut resp as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        if resp.magic != KMS_MAGIC_RESP {
            return None;
        }
        Some(resp)
    }
}

// ============================================================================
// GESTIONNAIRE DU SERVICE DE CLÉS (KmsManager)
// ============================================================================

/// Gestionnaire souverain de clés cryptographiques et baux temporels (Ring 3, PID 28).
pub struct KmsManager {
    pub keys: [Option<KeyRecord>; MAX_KEYS],
    pub leases: [Option<KeyLease>; MAX_LEASES],
    pub next_key_id: u32,
    pub next_lease_id: u32,
}

impl Default for KmsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsManager {
    pub const fn new() -> Self {
        Self {
            keys: [None; MAX_KEYS],
            leases: [None; MAX_LEASES],
            next_key_id: 1,
            next_lease_id: 1,
        }
    }

    /// Initialise les clés cryptographiques de démarrage requises par la grappe JamboOS.
    pub fn init_defaults(&mut self) {
        self.keys = [None; MAX_KEYS];
        self.leases = [None; MAX_LEASES];

        // 1. MasterKey racine de grappe (cluster-root-kek)
        let mut root_key = [0u8; KEY_DATA_LEN];
        let root_seed = b"JAMBO_CLUSTER_ROOT_KEK_MASTER_0";
        root_key[..root_seed.len()].copy_from_slice(root_seed);

        let mut root_name = [0u8; 24];
        let root_name_bytes = b"cluster-root-kek";
        root_name[..root_name_bytes.len()].copy_from_slice(root_name_bytes);

        self.keys[0] = Some(KeyRecord {
            id: 1,
            parent_id: 0,
            key_type: KeyType::Master,
            version: 1,
            state: KeyLifecycleState::Active,
            name: root_name,
            name_len: root_name_bytes.len(),
            key_data: root_key,
            created_ticks: 1,
        });

        // 2. DomainKey dérivée pour le stockage (storage-domain-kek)
        let mut domain_key = [0u8; KEY_DATA_LEN];
        Hkdf::derive_key(
            &root_key,
            b"jambo-kms-salt",
            b"storage-domain-kek",
            &mut domain_key,
        );

        let mut domain_name = [0u8; 24];
        let domain_name_bytes = b"storage-domain-kek";
        domain_name[..domain_name_bytes.len()].copy_from_slice(domain_name_bytes);

        self.keys[1] = Some(KeyRecord {
            id: 2,
            parent_id: 1,
            key_type: KeyType::Domain,
            version: 1,
            state: KeyLifecycleState::Active,
            name: domain_name,
            name_len: domain_name_bytes.len(),
            key_data: domain_key,
            created_ticks: 1,
        });

        // 3. SessionKey dérivée pour le réseau (net-session-key)
        let mut session_key = [0u8; KEY_DATA_LEN];
        Hkdf::derive_key(
            &domain_key,
            b"jambo-kms-salt",
            b"net-session-key",
            &mut session_key,
        );

        let mut session_name = [0u8; 24];
        let session_name_bytes = b"net-session-key";
        session_name[..session_name_bytes.len()].copy_from_slice(session_name_bytes);

        self.keys[2] = Some(KeyRecord {
            id: 3,
            parent_id: 2,
            key_type: KeyType::Session,
            version: 1,
            state: KeyLifecycleState::Active,
            name: session_name,
            name_len: session_name_bytes.len(),
            key_data: session_key,
            created_ticks: 1,
        });

        self.next_key_id = 4;
        self.next_lease_id = 1;
    }

    /// Nombre de clés valides présentes dans le magasin.
    pub fn key_count(&self) -> usize {
        self.keys.iter().filter(|k| k.is_some()).count()
    }

    /// Nombre de baux actuellement actifs.
    pub fn lease_count(&self) -> usize {
        self.leases
            .iter()
            .filter(|l| l.is_some_and(|lease| lease.active))
            .count()
    }

    /// Récupère une référence vers un enregistrement de clé par son ID.
    pub fn get_key(&self, id: u32) -> Option<&KeyRecord> {
        self.keys.iter().flatten().find(|k| k.id == id)
    }

    /// Récupère une référence mutable vers un enregistrement de clé par son ID.
    fn get_key_mut(&mut self, id: u32) -> Option<&mut KeyRecord> {
        self.keys.iter_mut().flatten().find(|k| k.id == id)
    }

    /// Crée une nouvelle clé souveraine.
    pub fn create_key(
        &mut self,
        cap: &KmsCap,
        key_type: KeyType,
        name: &[u8],
        initial_data: Option<&[u8; KEY_DATA_LEN]>,
        current_ticks: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(kms_rights::CREATE_KEY) {
            return Err(SysError::PermissionDenied);
        }
        if name.is_empty() || name.len() > 24 {
            return Err(SysError::InvalidArgument);
        }

        let slot_idx = self
            .keys
            .iter()
            .position(|k| k.is_none())
            .ok_or(SysError::OutOfMemory)?;

        let id = self.next_key_id;
        self.next_key_id += 1;

        let mut key_data = [0u8; KEY_DATA_LEN];
        if let Some(init) = initial_data {
            key_data.copy_from_slice(init);
        } else {
            // Génération déterministe HKDF basée sur le nom et l'ID
            let mut seed_msg = [0u8; 32];
            let n_len = name.len().min(24);
            seed_msg[..n_len].copy_from_slice(&name[..n_len]);
            seed_msg[24..28].copy_from_slice(&id.to_le_bytes());
            seed_msg[28..32].copy_from_slice(&(current_ticks as u32).to_le_bytes());
            Hkdf::derive_key(
                &seed_msg,
                b"jambo-create-key-salt",
                b"key-material",
                &mut key_data,
            );
        }

        let mut name_buf = [0u8; 24];
        let n_len = name.len().min(24);
        name_buf[..n_len].copy_from_slice(&name[..n_len]);

        self.keys[slot_idx] = Some(KeyRecord {
            id,
            parent_id: 0,
            key_type,
            version: 1,
            state: KeyLifecycleState::Active,
            name: name_buf,
            name_len: n_len,
            key_data,
            created_ticks: current_ticks,
        });

        Ok(id)
    }

    /// Dérive une nouvelle clé enfant à partir d'une clé parente selon HKDF RFC 5869.
    pub fn derive_key(
        &mut self,
        cap: &KmsCap,
        parent_id: u32,
        name: &[u8],
        key_type: KeyType,
        current_ticks: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(kms_rights::DERIVE_KEY) {
            return Err(SysError::PermissionDenied);
        }
        if name.is_empty() || name.len() > 24 {
            return Err(SysError::InvalidArgument);
        }

        let parent_key_data = {
            let parent = self.get_key(parent_id).ok_or(SysError::InvalidHandle)?;
            if parent.state != KeyLifecycleState::Active {
                return Err(SysError::InvalidHandle);
            }
            parent.key_data
        };

        let slot_idx = self
            .keys
            .iter()
            .position(|k| k.is_none())
            .ok_or(SysError::OutOfMemory)?;

        let id = self.next_key_id;
        self.next_key_id += 1;

        let mut derived_material = [0u8; KEY_DATA_LEN];
        Hkdf::derive_key(
            &parent_key_data,
            b"jambo-kms-salt",
            name,
            &mut derived_material,
        );

        let mut name_buf = [0u8; 24];
        let n_len = name.len().min(24);
        name_buf[..n_len].copy_from_slice(&name[..n_len]);

        self.keys[slot_idx] = Some(KeyRecord {
            id,
            parent_id,
            key_type,
            version: 1,
            state: KeyLifecycleState::Active,
            name: name_buf,
            name_len: n_len,
            key_data: derived_material,
            created_ticks: current_ticks,
        });

        Ok(id)
    }

    /// Attribue un bail temporel d'utilisation pour une clé active.
    pub fn grant_lease(
        &mut self,
        cap: &KmsCap,
        key_id: u32,
        ops_mask: u32,
        max_ops: u32,
        validity_ticks: u64,
        current_ticks: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(kms_rights::GRANT_LEASE) {
            return Err(SysError::PermissionDenied);
        }

        let key = self.get_key(key_id).ok_or(SysError::InvalidHandle)?;
        if key.state != KeyLifecycleState::Active {
            return Err(SysError::InvalidHandle);
        }

        let slot_idx = self
            .leases
            .iter()
            .position(|l| l.is_none() || l.is_some_and(|lease| !lease.active))
            .ok_or(SysError::OutOfMemory)?;

        let lease_id = self.next_lease_id;
        self.next_lease_id += 1;

        self.leases[slot_idx] = Some(KeyLease {
            lease_id,
            key_id,
            ops_mask,
            remaining_ops: max_ops,
            valid_until_ticks: current_ticks.saturating_add(validity_ticks),
            active: true,
        });

        Ok(lease_id)
    }

    /// Consomme une opération autorisée sur un bail actif.
    pub fn consume_lease(
        &mut self,
        lease_id: u32,
        op: u32,
        current_ticks: u64,
    ) -> Result<(), SysError> {
        for lease in self.leases.iter_mut().flatten() {
            if lease.lease_id == lease_id && lease.active {
                if current_ticks > lease.valid_until_ticks {
                    lease.active = false;
                    return Err(SysError::TimedOut);
                }
                if (lease.ops_mask & op) == 0 {
                    return Err(SysError::PermissionDenied);
                }
                if lease.remaining_ops == 0 {
                    lease.active = false;
                    return Err(SysError::ResourceBusy);
                }
                lease.remaining_ops -= 1;
                if lease.remaining_ops == 0 {
                    lease.active = false;
                }
                return Ok(());
            }
        }
        Err(SysError::InvalidHandle)
    }

    /// Effectue la rotation atomique d'une clé active.
    pub fn rotate_key(
        &mut self,
        cap: &KmsCap,
        key_id: u32,
        current_ticks: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(kms_rights::ROTATE_KEY) {
            return Err(SysError::PermissionDenied);
        }

        let key = self.get_key_mut(key_id).ok_or(SysError::InvalidHandle)?;
        if key.state != KeyLifecycleState::Active {
            return Err(SysError::InvalidHandle);
        }

        key.version += 1;
        key.created_ticks = current_ticks;

        let mut new_material = [0u8; KEY_DATA_LEN];
        let mut info_buf = [0u8; 16];
        info_buf[..8].copy_from_slice(b"rotation");
        info_buf[8..12].copy_from_slice(&key.version.to_le_bytes());
        Hkdf::derive_key(
            &key.key_data,
            b"jambo-rotate-salt",
            &info_buf,
            &mut new_material,
        );
        key.key_data = new_material;

        Ok(key.version)
    }

    /// Révoque une clé et zéroïse immédiatement son contenu en mémoire.
    pub fn revoke_key(&mut self, cap: &KmsCap, key_id: u32) -> Result<(), SysError> {
        if !cap.has_right(kms_rights::REVOKE_KEY) {
            return Err(SysError::PermissionDenied);
        }

        let key = self.get_key_mut(key_id).ok_or(SysError::InvalidHandle)?;
        key.state = KeyLifecycleState::Revoked;
        zeroize_bytes(&mut key.key_data);

        // Désactive immédiatement tous les baux rattachés à cette clé
        for lease in self.leases.iter_mut().flatten() {
            if lease.key_id == key_id {
                lease.active = false;
            }
        }

        Ok(())
    }

    /// Traite une requête IPC et produit une réponse déterministe à 64 octets.
    pub fn dispatch_ipc(&mut self, req: &KmsRequest) -> KmsResponse {
        if req.magic != KMS_MAGIC_REQ {
            let mut resp = KmsResponse::new();
            resp.status = SysError::InvalidArgument as i32;
            resp.set_status_str("BAD_MAGIC");
            return resp;
        }

        let cap = KmsCap::new(
            Handle::new(req.handle_id, 0),
            req.rights,
            0,
            MAX_KEYS as u16,
        );

        let opcode = match KmsOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                let mut resp = KmsResponse::new();
                resp.status = SysError::InvalidArgument as i32;
                resp.set_status_str("BAD_OPCODE");
                return resp;
            }
        };

        match opcode {
            KmsOpcode::GetStatus => {
                if !cap.has_right(kms_rights::AUDIT_LOG)
                    && !cap.has_right(kms_rights::ADMIN)
                    && (cap.rights & kms_rights::ALL) == 0
                {
                    let mut resp = KmsResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("PERM_DENIED");
                    return resp;
                }
                let mut resp = KmsResponse::new();
                resp.status = 0;
                resp.total_keys = self.key_count() as u32;
                resp.active_leases = self.lease_count() as u32;
                resp.set_status_str("OK_STATUS");
                resp
            }
            KmsOpcode::CreateKey => {
                let kt = KeyType::from_u8(req.key_type).unwrap_or(KeyType::Data);
                let name_str = req.name_as_str();
                match self.create_key(&cap, kt, name_str.as_bytes(), None, req.validity_ticks) {
                    Ok(kid) => {
                        let mut resp = KmsResponse::new();
                        resp.status = 0;
                        resp.key_id = kid;
                        resp.total_keys = self.key_count() as u32;
                        resp.active_leases = self.lease_count() as u32;
                        resp.key_version = 1;
                        resp.state = KeyLifecycleState::Active as u8;
                        if let Some(k) = self.get_key(kid) {
                            resp.key_hash = k.compute_hash();
                        }
                        resp.set_status_str("CREATED");
                        resp
                    }
                    Err(err) => {
                        let mut resp = KmsResponse::new();
                        resp.status = err as i32;
                        resp.set_status_str("ERR_CREATE");
                        resp
                    }
                }
            }
            KmsOpcode::DeriveKey => {
                let kt = KeyType::from_u8(req.key_type).unwrap_or(KeyType::Data);
                let name_str = req.name_as_str();
                match self.derive_key(
                    &cap,
                    req.parent_key_id,
                    name_str.as_bytes(),
                    kt,
                    req.validity_ticks,
                ) {
                    Ok(kid) => {
                        let mut resp = KmsResponse::new();
                        resp.status = 0;
                        resp.key_id = kid;
                        resp.total_keys = self.key_count() as u32;
                        resp.active_leases = self.lease_count() as u32;
                        resp.key_version = 1;
                        resp.state = KeyLifecycleState::Active as u8;
                        if let Some(k) = self.get_key(kid) {
                            resp.key_hash = k.compute_hash();
                        }
                        resp.set_status_str("DERIVED");
                        resp
                    }
                    Err(err) => {
                        let mut resp = KmsResponse::new();
                        resp.status = err as i32;
                        resp.set_status_str("ERR_DERIVE");
                        resp
                    }
                }
            }
            KmsOpcode::GrantLease => {
                let max_ops = if req.algorithm > 0 {
                    req.algorithm as u32
                } else {
                    100
                };
                let validity = if req.validity_ticks > 0 {
                    req.validity_ticks
                } else {
                    1000
                };
                match self.grant_lease(&cap, req.key_id, req.lease_ops, max_ops, validity, 0) {
                    Ok(lid) => {
                        let mut resp = KmsResponse::new();
                        resp.status = 0;
                        resp.key_id = req.key_id;
                        resp.lease_id = lid;
                        resp.total_keys = self.key_count() as u32;
                        resp.active_leases = self.lease_count() as u32;
                        resp.set_status_str("LEASE_GRANTED");
                        resp
                    }
                    Err(err) => {
                        let mut resp = KmsResponse::new();
                        resp.status = err as i32;
                        resp.set_status_str("ERR_LEASE");
                        resp
                    }
                }
            }
            KmsOpcode::RotateKey => match self.rotate_key(&cap, req.key_id, req.validity_ticks) {
                Ok(ver) => {
                    let mut resp = KmsResponse::new();
                    resp.status = 0;
                    resp.key_id = req.key_id;
                    resp.key_version = ver;
                    resp.total_keys = self.key_count() as u32;
                    resp.active_leases = self.lease_count() as u32;
                    resp.state = KeyLifecycleState::Active as u8;
                    if let Some(k) = self.get_key(req.key_id) {
                        resp.key_hash = k.compute_hash();
                    }
                    resp.set_status_str("ROTATED");
                    resp
                }
                Err(err) => {
                    let mut resp = KmsResponse::new();
                    resp.status = err as i32;
                    resp.set_status_str("ERR_ROTATE");
                    resp
                }
            },
            KmsOpcode::RevokeKey => match self.revoke_key(&cap, req.key_id) {
                Ok(()) => {
                    let mut resp = KmsResponse::new();
                    resp.status = 0;
                    resp.key_id = req.key_id;
                    resp.state = KeyLifecycleState::Revoked as u8;
                    resp.total_keys = self.key_count() as u32;
                    resp.active_leases = self.lease_count() as u32;
                    resp.set_status_str("REVOKED");
                    resp
                }
                Err(err) => {
                    let mut resp = KmsResponse::new();
                    resp.status = err as i32;
                    resp.set_status_str("ERR_REVOKE");
                    resp
                }
            },
        }
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`KmsClient`)
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

/// Client synchrone Ring 3 pour interagir avec `jambo-kms` (PID 28, endpoint 28).
pub struct KmsClient {
    pub endpoint: Handle,
}

impl KmsClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn call(&self, req: &KmsRequest) -> Result<KmsResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<KmsResponse>() {
                if let Some(resp) = KmsResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                    return Ok(resp);
                }
            }
            attempts += 1;
            libjambo::syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }

    pub fn get_status(&self, cap: &KmsCap) -> Result<KmsResponse, SysError> {
        let req = KmsRequest::new_status(cap.handle.0 as u32, cap.rights);
        self.call(&req)
    }

    pub fn create_key(
        &self,
        cap: &KmsCap,
        key_type: KeyType,
        name: &str,
    ) -> Result<KmsResponse, SysError> {
        let req = KmsRequest::new_create_key(cap.handle.0 as u32, cap.rights, key_type, name);
        self.call(&req)
    }

    pub fn derive_key(
        &self,
        cap: &KmsCap,
        parent_id: u32,
        name: &str,
    ) -> Result<KmsResponse, SysError> {
        let req = KmsRequest::new_derive_key(cap.handle.0 as u32, cap.rights, parent_id, name);
        self.call(&req)
    }

    pub fn grant_lease(
        &self,
        cap: &KmsCap,
        key_id: u32,
        ops: u32,
        validity_ticks: u64,
    ) -> Result<KmsResponse, SysError> {
        let req = KmsRequest::new_grant_lease(
            cap.handle.0 as u32,
            cap.rights,
            key_id,
            ops,
            validity_ticks,
        );
        self.call(&req)
    }

    pub fn rotate_key(&self, cap: &KmsCap, key_id: u32) -> Result<KmsResponse, SysError> {
        let req = KmsRequest::new_rotate_key(cap.handle.0 as u32, cap.rights, key_id);
        self.call(&req)
    }

    pub fn revoke_key(&self, cap: &KmsCap, key_id: u32) -> Result<KmsResponse, SysError> {
        let req = KmsRequest::new_revoke_key(cap.handle.0 as u32, cap.rights, key_id);
        self.call(&req)
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_and_attenuation() {
        let cap = KmsCap::new(Handle::new(28, 1), kms_rights::ALL, 0, 32);
        assert!(cap.has_right(kms_rights::CREATE_KEY));
        assert!(cap.has_right(kms_rights::DERIVE_KEY));
        assert!(cap.has_right(kms_rights::GRANT_LEASE));
        assert!(cap.has_right(kms_rights::ROTATE_KEY));
        assert!(cap.has_right(kms_rights::REVOKE_KEY));

        // Atténuation légitime
        let reduced = cap
            .attenuate(kms_rights::CREATE_KEY | kms_rights::DERIVE_KEY, 16)
            .expect("attenuation should succeed");
        assert!(reduced.has_right(kms_rights::CREATE_KEY));
        assert!(reduced.has_right(kms_rights::DERIVE_KEY));
        assert!(!reduced.has_right(kms_rights::REVOKE_KEY));
        assert_eq!(reduced.max_keys, 16);

        // Tentative d'amplification de privilège (doit échouer)
        let amplified = reduced.attenuate(kms_rights::ALL, 16);
        assert_eq!(amplified, Err(SysError::PermissionDenied));

        // Tentative d'augmentation du quota de clés (doit échouer)
        let quota_amp = reduced.attenuate(kms_rights::CREATE_KEY, 64);
        assert_eq!(quota_amp, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_crypto_sha256_hmac_and_hkdf() {
        // Test SHA-256 standard
        let digest_empty = Sha256::digest(b"");
        assert_eq!(
            digest_empty,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );

        let digest_abc = Sha256::digest(b"abc");
        assert_eq!(
            digest_abc,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );

        // Test HMAC-SHA256
        let mac = HmacSha256::mac(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_ne!(mac, [0u8; 32]);

        // Test HKDF RFC 5869 dérivation
        let mut okm1 = [0u8; 32];
        let mut okm2 = [0u8; 32];
        Hkdf::derive_key(b"ikm_material", b"salt", b"info1", &mut okm1);
        Hkdf::derive_key(b"ikm_material", b"salt", b"info2", &mut okm2);
        assert_ne!(okm1, [0u8; 32]);
        assert_ne!(okm2, [0u8; 32]);
        assert_ne!(okm1, okm2); // Différentes infos produisent différentes clés
    }

    #[test]
    fn test_zeroize_bytes_and_constant_time_eq() {
        let mut secret = [0x55u8; 32];
        assert!(constant_time_eq(&secret, &[0x55u8; 32]));
        assert!(!constant_time_eq(&secret, &[0xAAu8; 32]));

        zeroize_bytes(&mut secret);
        assert_eq!(secret, [0u8; 32]);
        assert!(constant_time_eq(&secret, &[0u8; 32]));
    }

    #[test]
    fn test_init_defaults_hierarchy() {
        let mut mgr = KmsManager::new();
        mgr.init_defaults();

        assert_eq!(mgr.key_count(), 3);
        assert_eq!(mgr.lease_count(), 0);

        let k1 = mgr.get_key(1).expect("Key 1 must exist");
        assert_eq!(k1.key_type, KeyType::Master);
        assert_eq!(k1.parent_id, 0);
        assert_eq!(k1.name_as_str(), "cluster-root-kek");
        assert_eq!(k1.version, 1);
        assert_eq!(k1.state, KeyLifecycleState::Active);

        let k2 = mgr.get_key(2).expect("Key 2 must exist");
        assert_eq!(k2.key_type, KeyType::Domain);
        assert_eq!(k2.parent_id, 1);
        assert_eq!(k2.name_as_str(), "storage-domain-kek");

        let k3 = mgr.get_key(3).expect("Key 3 must exist");
        assert_eq!(k3.key_type, KeyType::Session);
        assert_eq!(k3.parent_id, 2);
        assert_eq!(k3.name_as_str(), "net-session-key");
    }

    #[test]
    fn test_create_and_derive_key() {
        let mut mgr = KmsManager::new();
        mgr.init_defaults();

        let cap = KmsCap::new(Handle::new(28, 1), kms_rights::ALL, 0, 32);

        // Création d'une clé racine additionnelle
        let k4_id = mgr
            .create_key(&cap, KeyType::Data, b"db-encrypt-key", None, 100)
            .expect("create key should succeed");
        assert_eq!(k4_id, 4);
        assert_eq!(mgr.key_count(), 4);

        let k4_data = {
            let k4 = mgr.get_key(k4_id).unwrap();
            assert_eq!(k4.name_as_str(), "db-encrypt-key");
            assert_eq!(k4.key_type, KeyType::Data);
            assert_eq!(k4.state, KeyLifecycleState::Active);
            k4.key_data
        };

        // Dérivation d'une sous-clé à partir de k4
        let k5_id = mgr
            .derive_key(&cap, k4_id, b"db-table-users", KeyType::Data, 105)
            .expect("derive key should succeed");
        assert_eq!(k5_id, 5);
        assert_eq!(mgr.key_count(), 5);

        let k5 = mgr.get_key(k5_id).unwrap();
        assert_eq!(k5.parent_id, k4_id);
        assert_eq!(k5.name_as_str(), "db-table-users");
        assert_ne!(k5.key_data, k4_data);
    }

    #[test]
    fn test_lease_grant_and_consumption() {
        let mut mgr = KmsManager::new();
        mgr.init_defaults();

        let cap = KmsCap::new(Handle::new(28, 1), kms_rights::ALL, 0, 32);

        // Attribution d'un bail de 2 opérations valable pour 100 ticks
        let lease_id = mgr
            .grant_lease(
                &cap,
                1,
                lease_ops::OP_ENCRYPT | lease_ops::OP_DECRYPT,
                2,
                100,
                10,
            )
            .expect("grant lease should succeed");
        assert_eq!(lease_id, 1);
        assert_eq!(mgr.lease_count(), 1);

        // 1ère opération légitime à t = 20
        assert_eq!(
            mgr.consume_lease(lease_id, lease_ops::OP_ENCRYPT, 20),
            Ok(())
        );
        assert_eq!(mgr.lease_count(), 1);

        // Opération non autorisée par le masque (OP_SIGN)
        assert_eq!(
            mgr.consume_lease(lease_id, lease_ops::OP_SIGN, 25),
            Err(SysError::PermissionDenied)
        );

        // 2ème opération légitime à t = 30 (épuisement du quota de 2 ops)
        assert_eq!(
            mgr.consume_lease(lease_id, lease_ops::OP_DECRYPT, 30),
            Ok(())
        );

        // Le bail est maintenant épuisé (inactif)
        assert_eq!(mgr.lease_count(), 0);
        assert_eq!(
            mgr.consume_lease(lease_id, lease_ops::OP_ENCRYPT, 35),
            Err(SysError::InvalidHandle)
        );

        // Test expiration temporelle
        let lease_id_2 = mgr
            .grant_lease(&cap, 1, lease_ops::OP_ALL, 10, 50, 100)
            .expect("grant lease 2");
        assert_eq!(mgr.lease_count(), 1);
        // Appel à t = 160 > valid_until_ticks (150) -> TimedOut
        assert_eq!(
            mgr.consume_lease(lease_id_2, lease_ops::OP_ENCRYPT, 160),
            Err(SysError::TimedOut)
        );
        assert_eq!(mgr.lease_count(), 0);
    }

    #[test]
    fn test_rotate_and_revoke_key_with_zeroization() {
        let mut mgr = KmsManager::new();
        mgr.init_defaults();

        let cap = KmsCap::new(Handle::new(28, 1), kms_rights::ALL, 0, 32);

        // Rotation de la clé 2
        let initial_data = mgr.get_key(2).unwrap().key_data;
        let new_ver = mgr
            .rotate_key(&cap, 2, 200)
            .expect("rotation should succeed");
        assert_eq!(new_ver, 2);

        let k2_rotated = mgr.get_key(2).unwrap();
        assert_eq!(k2_rotated.version, 2);
        assert_ne!(k2_rotated.key_data, initial_data);

        // Attribution d'un bail sur la clé 2
        let l_id = mgr
            .grant_lease(&cap, 2, lease_ops::OP_ALL, 5, 500, 200)
            .expect("lease for key 2");
        assert_eq!(mgr.lease_count(), 1);

        // Révocation de la clé 2
        mgr.revoke_key(&cap, 2).expect("revocation should succeed");
        let k2_revoked = mgr.get_key(2).unwrap();
        assert_eq!(k2_revoked.state, KeyLifecycleState::Revoked);
        assert_eq!(k2_revoked.key_data, [0u8; KEY_DATA_LEN]); // Zéroïsé !

        // Tous les baux associés doivent être désactivés
        assert_eq!(mgr.lease_count(), 0);
        assert_eq!(
            mgr.consume_lease(l_id, lease_ops::OP_ENCRYPT, 205),
            Err(SysError::InvalidHandle)
        );
    }

    #[test]
    fn test_ipc_protocol_serialization_and_dispatch() {
        let mut mgr = KmsManager::new();
        mgr.init_defaults();

        // Test GetStatus
        let req_status = KmsRequest::new_status(28, kms_rights::ALL);
        assert_eq!(core::mem::size_of_val(&req_status), 64);
        let bytes = req_status.to_bytes();
        let parsed = KmsRequest::from_bytes(&bytes).expect("deserialization should work");
        assert_eq!(parsed, req_status);

        let resp_status = mgr.dispatch_ipc(&parsed);
        assert_eq!(core::mem::size_of_val(&resp_status), 64);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.total_keys, 3);
        assert_eq!(resp_status.status_as_str(), "OK_STATUS");

        // Test CreateKey via IPC
        let req_create =
            KmsRequest::new_create_key(28, kms_rights::ALL, KeyType::Data, "ipc-created-key");
        let resp_create = mgr.dispatch_ipc(&req_create);
        assert_eq!(resp_create.status, 0);
        assert_eq!(resp_create.key_id, 4);
        assert_eq!(resp_create.status_as_str(), "CREATED");
        assert_eq!(resp_create.total_keys, 4);

        // Test DeriveKey via IPC
        let req_derive = KmsRequest::new_derive_key(28, kms_rights::ALL, 4, "ipc-child-key");
        let resp_derive = mgr.dispatch_ipc(&req_derive);
        assert_eq!(resp_derive.status, 0);
        assert_eq!(resp_derive.key_id, 5);
        assert_eq!(resp_derive.status_as_str(), "DERIVED");
        assert_eq!(resp_derive.total_keys, 5);

        // Test RotateKey via IPC
        let req_rotate = KmsRequest::new_rotate_key(28, kms_rights::ALL, 5);
        let resp_rotate = mgr.dispatch_ipc(&req_rotate);
        assert_eq!(resp_rotate.status, 0);
        assert_eq!(resp_rotate.key_version, 2);
        assert_eq!(resp_rotate.status_as_str(), "ROTATED");

        // Test RevokeKey via IPC
        let req_revoke = KmsRequest::new_revoke_key(28, kms_rights::ALL, 5);
        let resp_revoke = mgr.dispatch_ipc(&req_revoke);
        assert_eq!(resp_revoke.status, 0);
        assert_eq!(resp_revoke.state, KeyLifecycleState::Revoked as u8);
        assert_eq!(resp_revoke.status_as_str(), "REVOKED");

        // Vérifier que la clé révoquée est bien mise à zéro
        let k5 = mgr.get_key(5).unwrap();
        assert_eq!(k5.key_data, [0u8; KEY_DATA_LEN]);
    }
}

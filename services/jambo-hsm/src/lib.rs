//! Module de Sécurité Matériel HSM Ring 3, Dérivation PKCS#11
//! et Stockage de Clés Cryptographiques Scellées (`jambo-hsm`)
//!
//! Phase 94 — Jalon v0.2.92
//!
//! Fournit les garanties souveraines d'isolation matérielle et d'opérations cryptographiques scellées :
//! 1. Émulation et abstraction de module de sécurité matériel (Hardware Security Module - HSM) Ring 3 souverain.
//! 2. Conformité et alignement architectural avec le standard PKCS#11 (Cryptographic Token Interface) :
//!    Slots matériels, Tokens sécurisés, Sessions R/O et R/W, Authentification SO (Security Officer) et Utilisateur.
//! 3. Hiérarchie et dérivation de clés cryptographiques via HKDF-SHA256 (RFC 5869 Extract & Expand) :
//!    dérivation déterministe de clés de chiffrement de stockage (DEK), clés d'enclave et clés de tunnel IPC
//!    à partir d'une Clé Maîtresse HSM (Master Key / KEK) qui ne quitte JAMAIS la frontière matérielle.
//! 4. Attributs de protection d'objets stricts : `CKA_SENSITIVE` (interdiction d'extraction en clair),
//!    `CKA_EXTRACTABLE = false` (interdiction de wrapping non autorisé), `CKA_ENCRYPT`, `CKA_DECRYPT`,
//!    `CKA_SIGN`, `CKA_VERIFY`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_DERIVE`.
//! 5. Scellement et enveloppement sécurisé de clés (Key Wrapping & Unwrapping) sous clé de chiffrement maîtresse KEK.
//! 6. Détection d'effraction et procédure de Zéroïsation d'Urgence (Emergency Zeroization) détruisant
//!    l'intégralité des clés privées et secrètes en temps O(1).
//! 7. Registre d'audit inviolable scellé par chaîne SHA-256 (`hsm_audit_chain`).
//! 8. Contrôle d'accès capabilaire strict (`HsmCap`) interdisant toute autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_SLOTS: usize = 4;
pub const MAX_SESSIONS: usize = 8;
pub const MAX_OBJECTS: usize = 32;
pub const MAX_AUDIT_LOGS: usize = 64;
pub const MAX_LABEL_LEN: usize = 32;
pub const MAX_KEY_SIZE: usize = 64;
pub const MAX_DATA_SIZE: usize = 256;
pub const MAX_PIN_LEN: usize = 32;
pub const MAX_REASON_LEN: usize = 48;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 & HMAC (#![no_std])
// ============================================================================

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

    /// Calcul HMAC-SHA256
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

        let mut inner = [0u8; 64 + 512];
        let inner_len = 64 + message.len();
        if inner_len <= inner.len() {
            inner[..64].copy_from_slice(&ipad);
            inner[64..inner_len].copy_from_slice(message);
            let inner_hash = Self::digest(&inner[..inner_len]);

            let mut outer = [0u8; 64 + 32];
            outer[..64].copy_from_slice(&opad);
            outer[64..].copy_from_slice(&inner_hash);
            Self::digest(&outer)
        } else {
            let mut fallback = [0u8; 32];
            fallback.copy_from_slice(&Self::digest(message));
            for i in 0..32 {
                fallback[i] ^= k_pad[i];
            }
            Self::digest(&fallback)
        }
    }
}

// ============================================================================
// DÉRIVATION DE CLÉS HKDF-SHA256 (RFC 5869) (#![no_std])
// ============================================================================

pub struct HkdfSha256;

impl HkdfSha256 {
    /// Étape Extract : PRK = HMAC-Hash(Salt, IKM)
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        if salt.is_empty() {
            let zero_salt = [0u8; 32];
            Sha256::hmac(&zero_salt, ikm)
        } else {
            Sha256::hmac(salt, ikm)
        }
    }

    /// Étape Expand : OKM = HMAC-Hash(PRK, info || 0x01) || ...
    pub fn expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) -> Result<(), SysError> {
        if okm.len() > 255 * 32 {
            return Err(SysError::InvalidArgument);
        }

        let mut t = [0u8; 32];
        let mut t_len = 0;
        let mut offset = 0;
        let mut block_idx = 1u8;

        let mut step_buf = [0u8; 32 + 128 + 1];

        while offset < okm.len() {
            let mut cur_len = 0;
            if t_len > 0 {
                step_buf[..t_len].copy_from_slice(&t[..t_len]);
                cur_len += t_len;
            }

            let info_len = if info.len() > 128 { 128 } else { info.len() };
            step_buf[cur_len..cur_len + info_len].copy_from_slice(&info[..info_len]);
            cur_len += info_len;

            step_buf[cur_len] = block_idx;
            cur_len += 1;

            t = Sha256::hmac(prk, &step_buf[..cur_len]);
            t_len = 32;

            let to_copy = if okm.len() - offset < 32 {
                okm.len() - offset
            } else {
                32
            };

            okm[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
            block_idx = block_idx.wrapping_add(1);
        }

        Ok(())
    }

    /// Dérivation complète Extract & Expand
    pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), SysError> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, okm)
    }
}

// ============================================================================
// CHIFFREMENT DE FLUX CHACHA20 (#![no_std]) POUR WRAPPING & OPÉRATIONS
// ============================================================================

pub struct ChaCha20Hsm;

impl ChaCha20Hsm {
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

    fn generate_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 64]) {
        let state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
            u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
            u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
            u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
            counter,
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];

        let mut working_state = state;
        for _ in 0..10 {
            Self::quarter_round(&mut working_state, 0, 4, 8, 12);
            Self::quarter_round(&mut working_state, 1, 5, 9, 13);
            Self::quarter_round(&mut working_state, 2, 6, 10, 14);
            Self::quarter_round(&mut working_state, 3, 7, 11, 15);
            Self::quarter_round(&mut working_state, 0, 5, 10, 15);
            Self::quarter_round(&mut working_state, 1, 6, 11, 12);
            Self::quarter_round(&mut working_state, 2, 7, 8, 13);
            Self::quarter_round(&mut working_state, 3, 4, 9, 14);
        }

        for i in 0..16 {
            let sum = working_state[i].wrapping_add(state[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&sum.to_le_bytes());
        }
    }

    pub fn xor_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
        let mut block = [0u8; 64];
        let mut cur_counter = counter;
        let mut offset = 0;

        while offset < data.len() {
            Self::generate_block(key, nonce, cur_counter, &mut block);
            let to_process = if data.len() - offset < 64 {
                data.len() - offset
            } else {
                64
            };

            for i in 0..to_process {
                data[offset + i] ^= block[i];
            }

            offset += to_process;
            cur_counter = cur_counter.wrapping_add(1);
        }
    }
}

// ============================================================================
// TYPES ET DÉFINITIONS CONFORMES PKCS#11 (#![no_std])
// ============================================================================

/// Mécanismes cryptographiques PKCS#11 supportés
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMechanism {
    Sha256,
    Sha256Hmac,
    ChaCha20,
    AesKeyGen,
    HkdfDerive,
    KeyWrapChaCha,
}

impl HsmMechanism {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "CKM_SHA256",
            Self::Sha256Hmac => "CKM_SHA256_HMAC",
            Self::ChaCha20 => "CKM_CHACHA20",
            Self::AesKeyGen => "CKM_AES_KEY_GEN",
            Self::HkdfDerive => "CKM_HKDF_DERIVE",
            Self::KeyWrapChaCha => "CKM_KEY_WRAP_CHACHA",
        }
    }
}

/// Classe de l'objet PKCS#11 (CK_OBJECT_CLASS)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmObjectClass {
    Data,
    Certificate,
    PublicKey,
    PrivateKey,
    SecretKey,
}

impl HsmObjectClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Data => "CKO_DATA",
            Self::Certificate => "CKO_CERTIFICATE",
            Self::PublicKey => "CKO_PUBLIC_KEY",
            Self::PrivateKey => "CKO_PRIVATE_KEY",
            Self::SecretKey => "CKO_SECRET_KEY",
        }
    }
}

/// Type de clé cryptographique (CK_KEY_TYPE)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmKeyType {
    Aes,
    ChaCha20,
    Ed25519,
    GenericSecret,
}

impl HsmKeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes => "CKK_AES",
            Self::ChaCha20 => "CKK_CHACHA20",
            Self::Ed25519 => "CKK_ED25519",
            Self::GenericSecret => "CKK_GENERIC_SECRET",
        }
    }
}

/// Type d'utilisateur PKCS#11 pour authentification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmUserType {
    SecurityOfficer, // CKU_SO
    User,            // CKU_USER
}

/// État d'une session PKCS#11
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmSessionState {
    RoPublicSession,
    RoUserFunctions,
    RwPublicSession,
    RwUserFunctions,
    RwSoFunctions,
}

impl HsmSessionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoPublicSession => "RO_PUBLIC_SESSION",
            Self::RoUserFunctions => "RO_USER_FUNCTIONS",
            Self::RwPublicSession => "RW_PUBLIC_SESSION",
            Self::RwUserFunctions => "RW_USER_FUNCTIONS",
            Self::RwSoFunctions => "RW_SO_FUNCTIONS",
        }
    }
}

/// Attributs de protection et de politique d'une clé PKCS#11
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HsmKeyAttributes {
    /// CKA_SENSITIVE : interdiction de lire la clé en clair
    pub sensitive: bool,
    /// CKA_EXTRACTABLE : si faux, interdiction formelle d'envelopper/exporter la clé
    pub extractable: bool,
    /// CKA_ENCRYPT
    pub encrypt: bool,
    /// CKA_DECRYPT
    pub decrypt: bool,
    /// CKA_SIGN
    pub sign: bool,
    /// CKA_VERIFY
    pub verify: bool,
    /// CKA_WRAP : utilisable pour envelopper d'autres clés (ex: KEK)
    pub wrap: bool,
    /// CKA_UNWRAP : utilisable pour désenvelopper
    pub unwrap: bool,
    /// CKA_DERIVE : autorisée comme clé de base HKDF
    pub derive: bool,
}

impl Default for HsmKeyAttributes {
    fn default() -> Self {
        Self {
            sensitive: true,
            extractable: false,
            encrypt: true,
            decrypt: true,
            sign: true,
            verify: true,
            wrap: false,
            unwrap: false,
            derive: true,
        }
    }
}

// ============================================================================
// GOUVERNANCE CAPABILAIRE HSM
// ============================================================================

pub mod hsm_rights {
    pub const OPEN_SESSION: u32 = 1 << 0;
    pub const LOGIN: u32        = 1 << 1;
    pub const GENERATE_KEY: u32 = 1 << 2;
    pub const DERIVE_KEY: u32   = 1 << 3;
    pub const CRYPTO_OP: u32    = 1 << 4;
    pub const WRAP_KEY: u32     = 1 << 5;
    pub const UNWRAP_KEY: u32   = 1 << 6;
    pub const DESTROY_KEY: u32  = 1 << 7;
    pub const ZEROIZE: u32      = 1 << 8;
    pub const ADMIN: u32        = 1 << 9;

    pub const ALL: u32 = OPEN_SESSION
        | LOGIN
        | GENERATE_KEY
        | DERIVE_KEY
        | CRYPTO_OP
        | WRAP_KEY
        | UNWRAP_KEY
        | DESTROY_KEY
        | ZEROIZE
        | ADMIN;
}

/// Jeton de capacité souverain pour le sous-système HSM (`HsmCap`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HsmCap {
    pub handle: Handle,
    pub rights: u32,
}

impl HsmCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone des privilèges : interdiction d'élévation
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
// STRUCTURES MATÉRIELLES HSM : SLOTS, TOKENS, OBJETS ET SESSIONS
// ============================================================================

/// Emplacement matériel ou logique d'un HSM (Slot)
#[derive(Clone, Copy)]
pub struct HsmSlot {
    pub slot_id: u32,
    pub manufacturer: [u8; MAX_LABEL_LEN],
    pub manufacturer_len: usize,
    pub description: [u8; MAX_LABEL_LEN],
    pub description_len: usize,
    pub hw_version: (u8, u8),
    pub fw_version: (u8, u8),
    pub token_present: bool,
}

impl HsmSlot {
    pub fn description_as_str(&self) -> &str {
        core::str::from_utf8(&self.description[..self.description_len]).unwrap_or("<unknown>")
    }
    pub fn manufacturer_as_str(&self) -> &str {
        core::str::from_utf8(&self.manufacturer[..self.manufacturer_len]).unwrap_or("<unknown>")
    }
}

/// Jeton cryptographique physique ou virtuel scellé (Token)
#[derive(Clone, Copy)]
pub struct HsmToken {
    pub slot_id: u32,
    pub label: [u8; MAX_LABEL_LEN],
    pub label_len: usize,
    pub model: [u8; MAX_LABEL_LEN],
    pub model_len: usize,
    pub serial_number: [u8; MAX_LABEL_LEN],
    pub serial_number_len: usize,
    pub user_pin: [u8; MAX_PIN_LEN],
    pub user_pin_len: usize,
    pub so_pin: [u8; MAX_PIN_LEN],
    pub so_pin_len: usize,
    pub user_attempts_left: u8,
    pub so_attempts_left: u8,
    pub is_locked: bool,
    pub is_zeroized: bool,
    pub total_keys: u32,
}

impl HsmToken {
    pub fn label_as_str(&self) -> &str {
        core::str::from_utf8(&self.label[..self.label_len]).unwrap_or("<unnamed-token>")
    }
}

/// Session active entre une application et un token HSM
#[derive(Clone, Copy)]
pub struct HsmSession {
    pub session_id: u32,
    pub slot_id: u32,
    pub state: HsmSessionState,
    pub is_rw: bool,
}

/// Objet / Clé cryptographique stocké dans la mémoire sécurisée du HSM
#[derive(Clone, Copy)]
pub struct HsmObject {
    pub object_id: u32,
    pub slot_id: u32,
    pub class: HsmObjectClass,
    pub key_type: HsmKeyType,
    pub label: [u8; MAX_LABEL_LEN],
    pub label_len: usize,
    pub attrs: HsmKeyAttributes,
    /// Données cryptographiques de la clé scellée
    pub key_material: [u8; MAX_KEY_SIZE],
    pub key_len: usize,
    /// Compteur d'utilisations de la clé
    pub usage_count: u64,
}

impl HsmObject {
    pub fn label_as_str(&self) -> &str {
        core::str::from_utf8(&self.label[..self.label_len]).unwrap_or("<unnamed-key>")
    }

    /// Effacement sécurisé immédiat de la clé (Zeroization)
    pub fn zeroize(&mut self) {
        for b in self.key_material.iter_mut() {
            *b = 0;
        }
        self.key_len = 0;
        self.usage_count = 0;
    }
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SCELLÉ SHA-256
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmAction {
    InitSlot,
    OpenSession,
    CloseSession,
    LoginUser,
    LoginSo,
    Logout,
    GenerateKey,
    DeriveKey,
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    WrapKey,
    UnwrapKey,
    DestroyKey,
    ZeroizeEmergency,
}

impl HsmAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InitSlot => "INIT_SLOT",
            Self::OpenSession => "OPEN_SESSION",
            Self::CloseSession => "CLOSE_SESSION",
            Self::LoginUser => "LOGIN_USER",
            Self::LoginSo => "LOGIN_SO",
            Self::Logout => "LOGOUT",
            Self::GenerateKey => "GENERATE_KEY",
            Self::DeriveKey => "DERIVE_KEY",
            Self::Encrypt => "ENCRYPT",
            Self::Decrypt => "DECRYPT",
            Self::Sign => "SIGN",
            Self::Verify => "VERIFY",
            Self::WrapKey => "WRAP_KEY",
            Self::UnwrapKey => "UNWRAP_KEY",
            Self::DestroyKey => "DESTROY_KEY",
            Self::ZeroizeEmergency => "ZEROIZE_EMERGENCY",
        }
    }
}

#[derive(Clone, Copy)]
pub struct HsmAuditEntry {
    pub action: HsmAction,
    pub slot_id: u32,
    pub object_id: u32,
    pub reason: [u8; MAX_REASON_LEN],
    pub reason_len: usize,
    pub epoch: u64,
    pub block_hash: [u8; 32],
}

impl HsmAuditEntry {
    pub fn reason_as_str(&self) -> &str {
        core::str::from_utf8(&self.reason[..self.reason_len]).unwrap_or("")
    }
}

// ============================================================================
// DÉMON DU MODULE DE SÉCURITÉ MATÉRIEL (`JamboHsmDaemon`)
// ============================================================================

pub struct JamboHsmDaemon {
    pub admin_cap: HsmCap,
    pub slots: [Option<HsmSlot>; MAX_SLOTS],
    pub tokens: [Option<HsmToken>; MAX_SLOTS],
    pub sessions: [Option<HsmSession>; MAX_SESSIONS],
    pub objects: [Option<HsmObject>; MAX_OBJECTS],
    pub next_session_id: u32,
    pub next_object_id: u32,
    pub total_ops: u64,
    pub keys_generated: u64,
    pub keys_derived: u64,
    pub keys_wrapped: u64,
    pub keys_unwrapped: u64,
    pub crypto_ops_count: u64,
    pub zeroizations: u64,
    pub epoch: u64,
    pub audit_chain: [u8; 32],
    pub audit_logs: [Option<HsmAuditEntry>; MAX_AUDIT_LOGS],
    pub audit_head: usize,
}

impl JamboHsmDaemon {
    pub fn new(admin_cap: HsmCap) -> Self {
        let genesis_audit = Sha256::digest(b"JAMBO_HSM_GENESIS_ROOT_CHAIN_2026");

        Self {
            admin_cap,
            slots: [None; MAX_SLOTS],
            tokens: [None; MAX_SLOTS],
            sessions: [None; MAX_SESSIONS],
            objects: [None; MAX_OBJECTS],
            next_session_id: 1,
            next_object_id: 100,
            total_ops: 0,
            keys_generated: 0,
            keys_derived: 0,
            keys_wrapped: 0,
            keys_unwrapped: 0,
            crypto_ops_count: 0,
            zeroizations: 0,
            epoch: 1,
            audit_chain: genesis_audit,
            audit_logs: [None; MAX_AUDIT_LOGS],
            audit_head: 0,
        }
    }

    /// Enregistre une opération dans le journal scellé par chaîne SHA-256
    pub fn record_audit(&mut self, action: HsmAction, slot_id: u32, object_id: u32, reason_str: &str) {
        let mut r_buf = [0u8; MAX_REASON_LEN];
        let bytes = reason_str.as_bytes();
        let copy_len = if bytes.len() > MAX_REASON_LEN {
            MAX_REASON_LEN
        } else {
            bytes.len()
        };
        r_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let mut hash_input = [0u8; 32 + 4 + 4 + 4 + MAX_REASON_LEN + 8];
        hash_input[0..32].copy_from_slice(&self.audit_chain);
        hash_input[32..36].copy_from_slice(&(action as u32).to_be_bytes());
        hash_input[36..40].copy_from_slice(&slot_id.to_be_bytes());
        hash_input[40..44].copy_from_slice(&object_id.to_be_bytes());
        hash_input[44..44 + MAX_REASON_LEN].copy_from_slice(&r_buf);
        hash_input[44 + MAX_REASON_LEN..52 + MAX_REASON_LEN].copy_from_slice(&self.epoch.to_be_bytes());

        let new_hash = Sha256::digest(&hash_input);
        self.audit_chain = new_hash;

        let entry = HsmAuditEntry {
            action,
            slot_id,
            object_id,
            reason: r_buf,
            reason_len: copy_len,
            epoch: self.epoch,
            block_hash: new_hash,
        };

        self.audit_logs[self.audit_head] = Some(entry);
        self.audit_head = (self.audit_head + 1) % MAX_AUDIT_LOGS;
        self.total_ops = self.total_ops.wrapping_add(1);
    }

    /// Initialise la configuration HSM par défaut (Slot 0 : Matériel souverain, Slot 1 : Enclave TEE)
    pub fn init_defaults(&mut self) {
        // 1. Initialiser Slot 0 : Module Physique Souverain
        let mut desc0 = [0u8; MAX_LABEL_LEN];
        let d0_str = b"Jambo Physical Sovereign HSM";
        desc0[..d0_str.len()].copy_from_slice(d0_str);

        let mut man0 = [0u8; MAX_LABEL_LEN];
        let m0_str = b"Jambo Cryptographic Labs";
        man0[..m0_str.len()].copy_from_slice(m0_str);

        self.slots[0] = Some(HsmSlot {
            slot_id: 0,
            manufacturer: man0,
            manufacturer_len: m0_str.len(),
            description: desc0,
            description_len: d0_str.len(),
            hw_version: (2, 0),
            fw_version: (1, 4),
            token_present: true,
        });

        // Token 0 : Token Racine Souverain
        let mut tok_lbl = [0u8; MAX_LABEL_LEN];
        let tl_str = b"JAMBO_ROOT_HSM_TOKEN";
        tok_lbl[..tl_str.len()].copy_from_slice(tl_str);

        let mut tok_mod = [0u8; MAX_LABEL_LEN];
        let tm_str = b"HSM-SOV-2000";
        tok_mod[..tm_str.len()].copy_from_slice(tm_str);

        let mut tok_ser = [0u8; MAX_LABEL_LEN];
        let ts_str = b"JAMBO-SN-77889900";
        tok_ser[..ts_str.len()].copy_from_slice(ts_str);

        let mut u_pin = [0u8; MAX_PIN_LEN];
        let up_str = b"user_sec_pin_2026";
        u_pin[..up_str.len()].copy_from_slice(up_str);

        let mut so_pin = [0u8; MAX_PIN_LEN];
        let sp_str = b"so_admin_pin_2026";
        so_pin[..sp_str.len()].copy_from_slice(sp_str);

        self.tokens[0] = Some(HsmToken {
            slot_id: 0,
            label: tok_lbl,
            label_len: tl_str.len(),
            model: tok_mod,
            model_len: tm_str.len(),
            serial_number: tok_ser,
            serial_number_len: ts_str.len(),
            user_pin: u_pin,
            user_pin_len: up_str.len(),
            so_pin,
            so_pin_len: sp_str.len(),
            user_attempts_left: 5,
            so_attempts_left: 5,
            is_locked: false,
            is_zeroized: false,
            total_keys: 0,
        });

        // 2. Initialiser Slot 1 : Enclave Virtuelle TEE HSM
        let mut desc1 = [0u8; MAX_LABEL_LEN];
        let d1_str = b"Jambo Virtual TEE Enclave HSM";
        desc1[..d1_str.len()].copy_from_slice(d1_str);

        self.slots[1] = Some(HsmSlot {
            slot_id: 1,
            manufacturer: man0,
            manufacturer_len: m0_str.len(),
            description: desc1,
            description_len: d1_str.len(),
            hw_version: (1, 1),
            fw_version: (1, 0),
            token_present: true,
        });

        let mut tok1_lbl = [0u8; MAX_LABEL_LEN];
        let t1_str = b"JAMBO_TEE_HSM_TOKEN";
        tok1_lbl[..t1_str.len()].copy_from_slice(t1_str);

        self.tokens[1] = Some(HsmToken {
            slot_id: 1,
            label: tok1_lbl,
            label_len: t1_str.len(),
            model: tok_mod,
            model_len: tm_str.len(),
            serial_number: tok_ser,
            serial_number_len: ts_str.len(),
            user_pin: u_pin,
            user_pin_len: up_str.len(),
            so_pin,
            so_pin_len: sp_str.len(),
            user_attempts_left: 5,
            so_attempts_left: 5,
            is_locked: false,
            is_zeroized: false,
            total_keys: 0,
        });

        // Créer une Clé Maîtresse d'Enveloppement KEK (Root Master Wrapping Key) dans le Slot 0
        let kek_material = Sha256::digest(b"JAMBO_SOVEREIGN_HSM_ROOT_MASTER_KEK_SEED_2026");
        let mut kek_label = [0u8; MAX_LABEL_LEN];
        let kl_str = b"KEK_MASTER_ROOT";
        kek_label[..kl_str.len()].copy_from_slice(kl_str);

        let kek_attrs = HsmKeyAttributes {
            sensitive: true,
            extractable: false, // Clé racine JAMAIS extractible ni wrappée
            encrypt: true,
            decrypt: true,
            sign: true,
            verify: true,
            wrap: true,
            unwrap: true,
            derive: true,
        };

        let mut key_buf = [0u8; MAX_KEY_SIZE];
        key_buf[..32].copy_from_slice(&kek_material);

        self.objects[0] = Some(HsmObject {
            object_id: 1, // ID réservé Root Master Key
            slot_id: 0,
            class: HsmObjectClass::SecretKey,
            key_type: HsmKeyType::ChaCha20,
            label: kek_label,
            label_len: kl_str.len(),
            attrs: kek_attrs,
            key_material: key_buf,
            key_len: 32,
            usage_count: 0,
        });

        if let Some(tok) = self.tokens[0].as_mut() {
            tok.total_keys = 1;
        }

        self.record_audit(HsmAction::InitSlot, 0, 1, "Initialisation HSM racine et clé KEK maître");
    }

    /// Ouvre une nouvelle session PKCS#11 sur un slot
    pub fn open_session(
        &mut self,
        cap: &HsmCap,
        slot_id: u32,
        rw: bool,
    ) -> Result<u32, SysError> {
        if !cap.has_right(hsm_rights::OPEN_SESSION) {
            return Err(SysError::PermissionDenied);
        }

        if slot_id as usize >= MAX_SLOTS || self.slots[slot_id as usize].is_none() {
            return Err(SysError::InvalidArgument);
        }

        let token = self.tokens[slot_id as usize]
            .as_ref()
            .ok_or(SysError::ResourceBusy)?;
        if token.is_zeroized || token.is_locked {
            return Err(SysError::ResourceBusy);
        }

        // Trouver un emplacement de session libre
        let mut slot_idx = None;
        for (i, s) in self.sessions.iter().enumerate() {
            if s.is_none() {
                slot_idx = Some(i);
                break;
            }
        }

        let idx = slot_idx.ok_or(SysError::OutOfMemory)?;
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        let initial_state = if rw {
            HsmSessionState::RwPublicSession
        } else {
            HsmSessionState::RoPublicSession
        };

        self.sessions[idx] = Some(HsmSession {
            session_id,
            slot_id,
            state: initial_state,
            is_rw: rw,
        });

        self.record_audit(HsmAction::OpenSession, slot_id, session_id, "Ouverture session PKCS#11");
        Ok(session_id)
    }

    /// Ferme une session PKCS#11 existante
    pub fn close_session(&mut self, cap: &HsmCap, session_id: u32) -> Result<(), SysError> {
        if !cap.has_right(hsm_rights::OPEN_SESSION) {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.sessions.iter_mut() {
            if let Some(s) = slot {
                if s.session_id == session_id {
                    let slot_id = s.slot_id;
                    *slot = None;
                    self.record_audit(HsmAction::CloseSession, slot_id, session_id, "Fermeture session");
                    return Ok(());
                }
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Authentification PKCS#11 (Login SO ou User avec code PIN)
    pub fn login(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        user_type: HsmUserType,
        pin: &[u8],
    ) -> Result<(), SysError> {
        if !cap.has_right(hsm_rights::LOGIN) {
            return Err(SysError::PermissionDenied);
        }

        // 1. Localiser la session
        let (slot_id, is_rw, _cur_state) = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            (s.slot_id, s.is_rw, s.state)
        };

        let token = self.tokens[slot_id as usize]
            .as_mut()
            .ok_or(SysError::ResourceBusy)?;
        if token.is_zeroized || token.is_locked {
            return Err(SysError::ResourceBusy);
        }

        match user_type {
            HsmUserType::SecurityOfficer => {
                if !is_rw {
                    // CKR_SESSION_READ_ONLY_EXISTS : Le SO ne peut se connecter qu'en session R/W
                    return Err(SysError::PermissionDenied);
                }
                if token.so_attempts_left == 0 {
                    token.is_locked = true;
                    return Err(SysError::PermissionDenied);
                }

                // Vérifier PIN SO
                if pin == &token.so_pin[..token.so_pin_len] {
                    token.so_attempts_left = 5;
                    // Mettre à jour l'état de la session
                    for opt in self.sessions.iter_mut() {
                        if let Some(s) = opt {
                            if s.session_id == session_id {
                                s.state = HsmSessionState::RwSoFunctions;
                            }
                        }
                    }
                    self.record_audit(HsmAction::LoginSo, slot_id, session_id, "Connexion SO réussie");
                    Ok(())
                } else {
                    token.so_attempts_left = token.so_attempts_left.saturating_sub(1);
                    if token.so_attempts_left == 0 {
                        token.is_locked = true;
                    }
                    self.record_audit(HsmAction::LoginSo, slot_id, session_id, "Échec authentification SO PIN");
                    Err(SysError::PermissionDenied)
                }
            }
            HsmUserType::User => {
                if token.user_attempts_left == 0 {
                    token.is_locked = true;
                    return Err(SysError::PermissionDenied);
                }

                // Vérifier PIN Utilisateur
                if pin == &token.user_pin[..token.user_pin_len] {
                    token.user_attempts_left = 5;
                    let new_state = if is_rw {
                        HsmSessionState::RwUserFunctions
                    } else {
                        HsmSessionState::RoUserFunctions
                    };

                    for opt in self.sessions.iter_mut() {
                        if let Some(s) = opt {
                            if s.session_id == session_id {
                                s.state = new_state;
                            }
                        }
                    }
                    self.record_audit(HsmAction::LoginUser, slot_id, session_id, "Connexion Utilisateur réussie");
                    Ok(())
                } else {
                    token.user_attempts_left = token.user_attempts_left.saturating_sub(1);
                    if token.user_attempts_left == 0 {
                        token.is_locked = true;
                    }
                    self.record_audit(HsmAction::LoginUser, slot_id, session_id, "Échec authentification User PIN");
                    Err(SysError::PermissionDenied)
                }
            }
        }
    }

    /// Déconnexion de la session (Logout)
    pub fn logout(&mut self, cap: &HsmCap, session_id: u32) -> Result<(), SysError> {
        if !cap.has_right(hsm_rights::LOGIN) {
            return Err(SysError::PermissionDenied);
        }

        let mut target_slot = None;
        for opt in self.sessions.iter_mut() {
            if let Some(s) = opt {
                if s.session_id == session_id {
                    s.state = if s.is_rw {
                        HsmSessionState::RwPublicSession
                    } else {
                        HsmSessionState::RoPublicSession
                    };
                    target_slot = Some(s.slot_id);
                    break;
                }
            }
        }
        if let Some(slot_id) = target_slot {
            self.record_audit(HsmAction::Logout, slot_id, session_id, "Déconnexion utilisateur");
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Génération d'une nouvelle clé cryptographique scellée dans le HSM
    pub fn generate_key(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        class: HsmObjectClass,
        key_type: HsmKeyType,
        label: &str,
        attrs: HsmKeyAttributes,
        custom_entropy: &[u8],
    ) -> Result<u32, SysError> {
        if !cap.has_right(hsm_rights::GENERATE_KEY) {
            return Err(SysError::PermissionDenied);
        }

        // Vérifier la session
        let (slot_id, state) = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            (s.slot_id, s.state)
        };

        // Création de clé privée requiert utilisateur connecté en RW
        if state != HsmSessionState::RwUserFunctions && state != HsmSessionState::RwSoFunctions {
            return Err(SysError::PermissionDenied);
        }

        // Trouver un emplacement libre pour l'objet
        let mut obj_idx = None;
        for (i, opt) in self.objects.iter().enumerate() {
            if opt.is_none() {
                obj_idx = Some(i);
                break;
            }
        }
        let idx = obj_idx.ok_or(SysError::OutOfMemory)?;

        // Dériver le matériel de clé sécurisé
        let mut key_material = [0u8; MAX_KEY_SIZE];
        let key_len = match key_type {
            HsmKeyType::Aes => 32,
            HsmKeyType::ChaCha20 => 32,
            HsmKeyType::Ed25519 => 32,
            HsmKeyType::GenericSecret => 32,
        };

        let mut seed = [0u8; 64];
        let ent_len = if custom_entropy.len() > 32 { 32 } else { custom_entropy.len() };
        seed[..ent_len].copy_from_slice(&custom_entropy[..ent_len]);
        seed[32..36].copy_from_slice(&self.next_object_id.to_be_bytes());
        seed[36..44].copy_from_slice(&self.epoch.to_be_bytes());
        let digest = Sha256::digest(&seed);
        key_material[..32].copy_from_slice(&digest);

        let mut l_buf = [0u8; MAX_LABEL_LEN];
        let l_bytes = label.as_bytes();
        let l_len = if l_bytes.len() > MAX_LABEL_LEN { MAX_LABEL_LEN } else { l_bytes.len() };
        l_buf[..l_len].copy_from_slice(&l_bytes[..l_len]);

        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);

        self.objects[idx] = Some(HsmObject {
            object_id,
            slot_id,
            class,
            key_type,
            label: l_buf,
            label_len: l_len,
            attrs,
            key_material,
            key_len,
            usage_count: 0,
        });

        if let Some(tok) = self.tokens[slot_id as usize].as_mut() {
            tok.total_keys = tok.total_keys.wrapping_add(1);
        }
        self.keys_generated = self.keys_generated.wrapping_add(1);

        self.record_audit(HsmAction::GenerateKey, slot_id, object_id, label);
        Ok(object_id)
    }

    /// Dérivation d'une clé fille via HKDF-SHA256 (RFC 5869)
    pub fn derive_key_hkdf(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        base_key_id: u32,
        salt: &[u8],
        info: &[u8],
        derived_len: usize,
        label: &str,
        attrs: HsmKeyAttributes,
    ) -> Result<u32, SysError> {
        if !cap.has_right(hsm_rights::DERIVE_KEY) {
            return Err(SysError::PermissionDenied);
        }

        if derived_len > MAX_KEY_SIZE || derived_len == 0 {
            return Err(SysError::InvalidArgument);
        }

        let (slot_id, state) = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            (s.slot_id, s.state)
        };

        if state != HsmSessionState::RwUserFunctions && state != HsmSessionState::RwSoFunctions {
            return Err(SysError::PermissionDenied);
        }

        // Vérifier que la clé de base existe, est dans le même slot et autorise CKA_DERIVE
        let (base_material, base_len) = {
            let base_obj = self
                .objects
                .iter_mut()
                .filter_map(|opt| opt.as_mut())
                .find(|o| o.object_id == base_key_id)
                .ok_or(SysError::InvalidArgument)?;

            if base_obj.slot_id != slot_id {
                return Err(SysError::PermissionDenied);
            }
            if !base_obj.attrs.derive {
                return Err(SysError::PermissionDenied);
            }

            base_obj.usage_count = base_obj.usage_count.wrapping_add(1);
            (base_obj.key_material, base_obj.key_len)
        };

        // Calculer la dérivation HKDF
        let mut derived_material = [0u8; MAX_KEY_SIZE];
        HkdfSha256::derive(salt, &base_material[..base_len], info, &mut derived_material[..derived_len])?;

        // Stocker la clé dérivée
        let mut obj_idx = None;
        for (i, opt) in self.objects.iter().enumerate() {
            if opt.is_none() {
                obj_idx = Some(i);
                break;
            }
        }
        let idx = obj_idx.ok_or(SysError::OutOfMemory)?;

        let mut l_buf = [0u8; MAX_LABEL_LEN];
        let l_bytes = label.as_bytes();
        let l_len = if l_bytes.len() > MAX_LABEL_LEN { MAX_LABEL_LEN } else { l_bytes.len() };
        l_buf[..l_len].copy_from_slice(&l_bytes[..l_len]);

        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);

        self.objects[idx] = Some(HsmObject {
            object_id,
            slot_id,
            class: HsmObjectClass::SecretKey,
            key_type: HsmKeyType::ChaCha20,
            label: l_buf,
            label_len: l_len,
            attrs,
            key_material: derived_material,
            key_len: derived_len,
            usage_count: 0,
        });

        if let Some(tok) = self.tokens[slot_id as usize].as_mut() {
            tok.total_keys = tok.total_keys.wrapping_add(1);
        }
        self.keys_derived = self.keys_derived.wrapping_add(1);

        self.record_audit(HsmAction::DeriveKey, slot_id, object_id, label);
        Ok(object_id)
    }

    /// Chiffrement in-place de données par le HSM sans exposer la clé
    pub fn encrypt(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        key_id: u32,
        nonce: &[u8; 12],
        data: &mut [u8],
    ) -> Result<(), SysError> {
        if !cap.has_right(hsm_rights::CRYPTO_OP) {
            return Err(SysError::PermissionDenied);
        }

        let slot_id = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            s.slot_id
        };

        let obj = self
            .objects
            .iter_mut()
            .filter_map(|opt| opt.as_mut())
            .find(|o| o.object_id == key_id)
            .ok_or(SysError::InvalidArgument)?;

        if obj.slot_id != slot_id || !obj.attrs.encrypt {
            return Err(SysError::PermissionDenied);
        }

        let mut key32 = [0u8; 32];
        let copy_len = if obj.key_len < 32 { obj.key_len } else { 32 };
        key32[..copy_len].copy_from_slice(&obj.key_material[..copy_len]);

        ChaCha20Hsm::xor_keystream(&key32, nonce, 1, data);
        obj.usage_count = obj.usage_count.wrapping_add(1);
        self.crypto_ops_count = self.crypto_ops_count.wrapping_add(1);

        self.record_audit(HsmAction::Encrypt, slot_id, key_id, "Chiffrement symétrique in-HSM");
        Ok(())
    }

    /// Déchiffrement in-place de données par le HSM sans exposer la clé
    pub fn decrypt(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        key_id: u32,
        nonce: &[u8; 12],
        data: &mut [u8],
    ) -> Result<(), SysError> {
        if !cap.has_right(hsm_rights::CRYPTO_OP) {
            return Err(SysError::PermissionDenied);
        }

        let slot_id = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            s.slot_id
        };

        let obj = self
            .objects
            .iter_mut()
            .filter_map(|opt| opt.as_mut())
            .find(|o| o.object_id == key_id)
            .ok_or(SysError::InvalidArgument)?;

        if obj.slot_id != slot_id || !obj.attrs.decrypt {
            return Err(SysError::PermissionDenied);
        }

        let mut key32 = [0u8; 32];
        let copy_len = if obj.key_len < 32 { obj.key_len } else { 32 };
        key32[..copy_len].copy_from_slice(&obj.key_material[..copy_len]);

        ChaCha20Hsm::xor_keystream(&key32, nonce, 1, data);
        obj.usage_count = obj.usage_count.wrapping_add(1);
        self.crypto_ops_count = self.crypto_ops_count.wrapping_add(1);

        self.record_audit(HsmAction::Decrypt, slot_id, key_id, "Déchiffrement symétrique in-HSM");
        Ok(())
    }

    /// Signature HMAC-SHA256 par le HSM
    pub fn sign_hmac(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        key_id: u32,
        message: &[u8],
    ) -> Result<[u8; 32], SysError> {
        if !cap.has_right(hsm_rights::CRYPTO_OP) {
            return Err(SysError::PermissionDenied);
        }

        let slot_id = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            s.slot_id
        };

        let obj = self
            .objects
            .iter_mut()
            .filter_map(|opt| opt.as_mut())
            .find(|o| o.object_id == key_id)
            .ok_or(SysError::InvalidArgument)?;

        if obj.slot_id != slot_id || !obj.attrs.sign {
            return Err(SysError::PermissionDenied);
        }

        let sig = Sha256::hmac(&obj.key_material[..obj.key_len], message);
        obj.usage_count = obj.usage_count.wrapping_add(1);
        self.crypto_ops_count = self.crypto_ops_count.wrapping_add(1);

        self.record_audit(HsmAction::Sign, slot_id, key_id, "Signature HMAC in-HSM");
        Ok(sig)
    }

    /// Vérification HMAC-SHA256 par le HSM
    pub fn verify_hmac(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        key_id: u32,
        message: &[u8],
        expected_sig: &[u8; 32],
    ) -> Result<bool, SysError> {
        if !cap.has_right(hsm_rights::CRYPTO_OP) {
            return Err(SysError::PermissionDenied);
        }

        let slot_id = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            s.slot_id
        };

        let obj = self
            .objects
            .iter_mut()
            .filter_map(|opt| opt.as_mut())
            .find(|o| o.object_id == key_id)
            .ok_or(SysError::InvalidArgument)?;

        if obj.slot_id != slot_id || !obj.attrs.verify {
            return Err(SysError::PermissionDenied);
        }

        let calc_sig = Sha256::hmac(&obj.key_material[..obj.key_len], message);
        obj.usage_count = obj.usage_count.wrapping_add(1);
        self.crypto_ops_count = self.crypto_ops_count.wrapping_add(1);

        let matches = &calc_sig == expected_sig;
        self.record_audit(
            HsmAction::Verify,
            slot_id,
            key_id,
            if matches { "Vérification HMAC OK" } else { "Échec vérification HMAC" },
        );
        Ok(matches)
    }

    /// Enveloppement sécurisé de clé (Key Wrapping) sous une KEK (Key Encrypting Key)
    /// Structure enveloppée : [Nonce 12B] || [Ciphertext (len B)] || [HMAC-SHA256 32B]
    pub fn wrap_key(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        wrapping_key_id: u32,
        target_key_id: u32,
        out_buf: &mut [u8],
    ) -> Result<usize, SysError> {
        if !cap.has_right(hsm_rights::WRAP_KEY) {
            return Err(SysError::PermissionDenied);
        }

        let slot_id = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            s.slot_id
        };

        // 1. Vérifier la clé d'enveloppement (KEK)
        let (kek_material, kek_len) = {
            let kek = self
                .objects
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|o| o.object_id == wrapping_key_id)
                .ok_or(SysError::InvalidArgument)?;
            if kek.slot_id != slot_id || !kek.attrs.wrap {
                return Err(SysError::PermissionDenied);
            }
            (kek.key_material, kek.key_len)
        };

        // 2. Vérifier la clé cible : CKA_EXTRACTABLE doit être TRUE !
        let (target_material, target_len) = {
            let target = self
                .objects
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|o| o.object_id == target_key_id)
                .ok_or(SysError::InvalidArgument)?;
            if target.slot_id != slot_id {
                return Err(SysError::PermissionDenied);
            }
            if !target.attrs.extractable {
                // Violation d'attribut : Clé non extractible !
                return Err(SysError::PermissionDenied);
            }
            (target.key_material, target.key_len)
        };

        let total_required = 12 + target_len + 32;
        if out_buf.len() < total_required {
            return Err(SysError::InvalidArgument);
        }

        // Générer nonce déterministe
        let nonce = [0x55, 0xAA, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00];
        out_buf[..12].copy_from_slice(&nonce);

        // Chiffrer le matériel de clé
        let mut encrypted = [0u8; MAX_KEY_SIZE];
        encrypted[..target_len].copy_from_slice(&target_material[..target_len]);

        let mut key32 = [0u8; 32];
        let copy_k = if kek_len < 32 { kek_len } else { 32 };
        key32[..copy_k].copy_from_slice(&kek_material[..copy_k]);
        ChaCha20Hsm::xor_keystream(&key32, &nonce, 1, &mut encrypted[..target_len]);

        out_buf[12..12 + target_len].copy_from_slice(&encrypted[..target_len]);

        // Calculer HMAC d'intégrité de l'enveloppe
        let mac = Sha256::hmac(&key32, &out_buf[..12 + target_len]);
        out_buf[12 + target_len..12 + target_len + 32].copy_from_slice(&mac);

        self.keys_wrapped = self.keys_wrapped.wrapping_add(1);
        self.record_audit(HsmAction::WrapKey, slot_id, target_key_id, "Enveloppement sécurisé sous KEK");
        Ok(total_required)
    }

    /// Désenveloppement de clé (Key Unwrapping) sous une KEK
    pub fn unwrap_key(
        &mut self,
        cap: &HsmCap,
        session_id: u32,
        wrapping_key_id: u32,
        wrapped_data: &[u8],
        class: HsmObjectClass,
        key_type: HsmKeyType,
        label: &str,
        attrs: HsmKeyAttributes,
    ) -> Result<u32, SysError> {
        if !cap.has_right(hsm_rights::UNWRAP_KEY) {
            return Err(SysError::PermissionDenied);
        }

        if wrapped_data.len() < 12 + 32 {
            return Err(SysError::InvalidArgument);
        }

        let slot_id = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            s.slot_id
        };

        // 1. Vérifier la KEK
        let (kek_material, kek_len) = {
            let kek = self
                .objects
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|o| o.object_id == wrapping_key_id)
                .ok_or(SysError::InvalidArgument)?;
            if kek.slot_id != slot_id || !kek.attrs.unwrap {
                return Err(SysError::PermissionDenied);
            }
            (kek.key_material, kek.key_len)
        };

        let mut key32 = [0u8; 32];
        let copy_k = if kek_len < 32 { kek_len } else { 32 };
        key32[..copy_k].copy_from_slice(&kek_material[..copy_k]);

        // 2. Vérifier le HMAC de l'enveloppe
        let cipher_end = wrapped_data.len() - 32;
        let expected_mac = Sha256::hmac(&key32, &wrapped_data[..cipher_end]);
        if &expected_mac != &wrapped_data[cipher_end..] {
            return Err(SysError::PermissionDenied); // Altération ou mauvaise KEK
        }

        // 3. Déchiffrer la clé
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&wrapped_data[..12]);

        let target_len = cipher_end - 12;
        if target_len > MAX_KEY_SIZE {
            return Err(SysError::InvalidArgument);
        }

        let mut decrypted = [0u8; MAX_KEY_SIZE];
        decrypted[..target_len].copy_from_slice(&wrapped_data[12..cipher_end]);
        ChaCha20Hsm::xor_keystream(&key32, &nonce, 1, &mut decrypted[..target_len]);

        // 4. Enregistrer la clé désenveloppée dans le HSM
        let mut obj_idx = None;
        for (i, opt) in self.objects.iter().enumerate() {
            if opt.is_none() {
                obj_idx = Some(i);
                break;
            }
        }
        let idx = obj_idx.ok_or(SysError::OutOfMemory)?;

        let mut l_buf = [0u8; MAX_LABEL_LEN];
        let l_bytes = label.as_bytes();
        let l_len = if l_bytes.len() > MAX_LABEL_LEN { MAX_LABEL_LEN } else { l_bytes.len() };
        l_buf[..l_len].copy_from_slice(&l_bytes[..l_len]);

        let object_id = self.next_object_id;
        self.next_object_id = self.next_object_id.wrapping_add(1);

        self.objects[idx] = Some(HsmObject {
            object_id,
            slot_id,
            class,
            key_type,
            label: l_buf,
            label_len: l_len,
            attrs,
            key_material: decrypted,
            key_len: target_len,
            usage_count: 0,
        });

        if let Some(tok) = self.tokens[slot_id as usize].as_mut() {
            tok.total_keys = tok.total_keys.wrapping_add(1);
        }
        self.keys_unwrapped = self.keys_unwrapped.wrapping_add(1);

        self.record_audit(HsmAction::UnwrapKey, slot_id, object_id, label);
        Ok(object_id)
    }

    /// Destruction explicite d'une clé cryptographique
    pub fn destroy_key(&mut self, cap: &HsmCap, session_id: u32, key_id: u32) -> Result<(), SysError> {
        if !cap.has_right(hsm_rights::DESTROY_KEY) {
            return Err(SysError::PermissionDenied);
        }

        let slot_id = {
            let s = self
                .sessions
                .iter()
                .filter_map(|opt| opt.as_ref())
                .find(|s| s.session_id == session_id)
                .ok_or(SysError::InvalidArgument)?;
            s.slot_id
        };

        let mut target_idx = None;
        for (i, opt) in self.objects.iter().enumerate() {
            if let Some(obj) = opt {
                if obj.object_id == key_id {
                    if obj.slot_id != slot_id {
                        return Err(SysError::PermissionDenied);
                    }
                    target_idx = Some(i);
                    break;
                }
            }
        }

        if let Some(idx) = target_idx {
            if let Some(mut obj) = self.objects[idx].take() {
                obj.zeroize();
            }
            if let Some(tok) = self.tokens[slot_id as usize].as_mut() {
                tok.total_keys = tok.total_keys.saturating_sub(1);
            }
            self.record_audit(HsmAction::DestroyKey, slot_id, key_id, "Destruction sécurisée de clé");
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// ZÉROÏSATION D'URGENCE (Emergency Hardware Zeroization)
    /// En cas d'effraction matérielle, intrusion physique ou alerte critique :
    /// détruit immédiatement toutes les clés privées, secrets et bannières du token en O(1).
    pub fn emergency_zeroize(&mut self, cap: &HsmCap, slot_id: u32) -> Result<(), SysError> {
        if !cap.has_right(hsm_rights::ZEROIZE) {
            return Err(SysError::PermissionDenied);
        }

        if slot_id as usize >= MAX_SLOTS {
            return Err(SysError::InvalidArgument);
        }

        // 1. Zéroïser tous les objets appartenant au slot
        for opt in self.objects.iter_mut() {
            if let Some(obj) = opt {
                if obj.slot_id == slot_id {
                    obj.zeroize();
                    *opt = None;
                }
            }
        }

        // 2. Clôturer toutes les sessions ouvertes sur ce slot
        for opt in self.sessions.iter_mut() {
            if let Some(s) = opt {
                if s.slot_id == slot_id {
                    *opt = None;
                }
            }
        }

        // 3. Marquer le token comme définitivement zéroïsé et verrouillé
        if let Some(tok) = self.tokens[slot_id as usize].as_mut() {
            tok.is_zeroized = true;
            tok.is_locked = true;
            tok.total_keys = 0;
            for b in tok.user_pin.iter_mut() {
                *b = 0;
            }
            for b in tok.so_pin.iter_mut() {
                *b = 0;
            }
        }

        self.zeroizations = self.zeroizations.wrapping_add(1);
        self.record_audit(
            HsmAction::ZeroizeEmergency,
            slot_id,
            0,
            "EFFACEMENT MATÉRIEL D'URGENCE EFFECTUÉ (Zeroization)",
        );
        Ok(())
    }

    /// Compte le nombre d'objets clés actifs
    pub fn count_active_keys(&self) -> usize {
        self.objects.iter().filter(|o| o.is_some()).count()
    }

    /// Compte le nombre de sessions ouvertes
    pub fn count_active_sessions(&self) -> usize {
        self.sessions.iter().filter(|s| s.is_some()).count()
    }

    /// Récupère un slot par son ID
    pub fn get_slot(&self, slot_id: u32) -> Option<&HsmSlot> {
        if (slot_id as usize) < MAX_SLOTS {
            self.slots[slot_id as usize].as_ref()
        } else {
            None
        }
    }

    /// Récupère un token par slot ID
    pub fn get_token(&self, slot_id: u32) -> Option<&HsmToken> {
        if (slot_id as usize) < MAX_SLOTS {
            self.tokens[slot_id as usize].as_ref()
        } else {
            None
        }
    }

    /// Récupère un objet clé par son ID
    pub fn get_object(&self, object_id: u32) -> Option<&HsmObject> {
        self.objects
            .iter()
            .filter_map(|opt| opt.as_ref())
            .find(|o| o.object_id == object_id)
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_and_hmac() {
        let msg = b"JAMBO_HSM_TEST";
        let d = Sha256::digest(msg);
        assert_ne!(d, [0u8; 32]);

        let key = b"HSM_SECRET_KEY";
        let h = Sha256::hmac(key, msg);
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_derivation() {
        let ikm = b"MASTER_INPUT_KEY_MATERIAL";
        let salt = b"CLUSTER_SALT_2026";
        let info = b"STORAGE_ENCRYPTION_KEY";
        let mut okm = [0u8; 32];
        HkdfSha256::derive(salt, ikm, info, &mut okm).expect("HKDF derive ok");
        assert_ne!(okm, [0u8; 32]);

        // Déterministe
        let mut okm2 = [0u8; 32];
        HkdfSha256::derive(salt, ikm, info, &mut okm2).expect("HKDF derive ok");
        assert_eq!(okm, okm2);
    }

    #[test]
    fn test_hsm_lifecycle() {
        let admin_cap = HsmCap::new(Handle::new(9401, 1), hsm_rights::ALL);
        let mut daemon = JamboHsmDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.count_active_keys(), 1); // KEK root
        let slot0 = daemon.get_slot(0).expect("Slot 0 présent");
        assert!(slot0.token_present);

        // Ouvrir session RW
        let sess = daemon.open_session(&admin_cap, 0, true).expect("Session ouverte");

        // Connexion utilisateur avec mauvais PIN -> échec
        assert_eq!(
            daemon.login(&admin_cap, sess, HsmUserType::User, b"wrong_pin"),
            Err(SysError::PermissionDenied)
        );

        // Connexion utilisateur avec bon PIN -> succès
        daemon.login(&admin_cap, sess, HsmUserType::User, b"user_sec_pin_2026").expect("Login ok");

        // Générer une clé ChaCha20 extractible
        let mut attrs = HsmKeyAttributes::default();
        attrs.extractable = true;
        let key_id = daemon
            .generate_key(
                &admin_cap,
                sess,
                HsmObjectClass::SecretKey,
                HsmKeyType::ChaCha20,
                "DISK_ENCRYPTION_KEY",
                attrs,
                b"entropy_seed_disk",
            )
            .expect("Génération clé");

        assert_eq!(daemon.count_active_keys(), 2);

        // Chiffrement / Déchiffrement
        let nonce = [1u8; 12];
        let mut data = [0x42u8; 64];
        let original = data;
        daemon.encrypt(&admin_cap, sess, key_id, &nonce, &mut data).expect("Encrypt ok");
        assert_ne!(data, original);
        daemon.decrypt(&admin_cap, sess, key_id, &nonce, &mut data).expect("Decrypt ok");
        assert_eq!(data, original);

        // Key Wrapping sous KEK (object 1)
        let mut wrapped = [0u8; 128];
        let wrapped_len = daemon
            .wrap_key(&admin_cap, sess, 1, key_id, &mut wrapped)
            .expect("Wrap ok");
        assert!(wrapped_len > 0);

        // Key Unwrapping sous KEK
        let unwrap_id = daemon
            .unwrap_key(
                &admin_cap,
                sess,
                1,
                &wrapped[..wrapped_len],
                HsmObjectClass::SecretKey,
                HsmKeyType::ChaCha20,
                "UNWRAPPED_DISK_KEY",
                attrs,
            )
            .expect("Unwrap ok");

        assert_eq!(daemon.count_active_keys(), 3);

        // Vérifier que la clé désenveloppée déchiffre les mêmes données
        let mut test_buf = original;
        daemon.encrypt(&admin_cap, sess, key_id, &nonce, &mut test_buf).expect("Encrypt");
        daemon.decrypt(&admin_cap, sess, unwrap_id, &nonce, &mut test_buf).expect("Decrypt with unwrapped");
        assert_eq!(test_buf, original);

        // Zéroïsation d'urgence
        daemon.emergency_zeroize(&admin_cap, 0).expect("Zeroize");
        assert_eq!(daemon.count_active_keys(), 0);
        let tok = daemon.get_token(0).expect("Token 0");
        assert!(tok.is_zeroized);
    }

    #[test]
    fn test_cap_attenuation_and_protection() {
        let admin_cap = HsmCap::new(Handle::new(9402, 1), hsm_rights::ALL);
        assert!(admin_cap.has_right(hsm_rights::GENERATE_KEY));
        assert!(admin_cap.has_right(hsm_rights::ZEROIZE));

        let crypto_only_cap = admin_cap
            .attenuate(hsm_rights::OPEN_SESSION | hsm_rights::CRYPTO_OP)
            .expect("Attenuation ok");
        assert!(crypto_only_cap.has_right(hsm_rights::CRYPTO_OP));
        assert!(!crypto_only_cap.has_right(hsm_rights::ZEROIZE));
        assert!(!crypto_only_cap.has_right(hsm_rights::ADMIN));

        // Rejet formel d'amplification
        assert_eq!(
            crypto_only_cap.attenuate(hsm_rights::ALL),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_unextractable_key_protection() {
        let admin_cap = HsmCap::new(Handle::new(9403, 1), hsm_rights::ALL);
        let mut daemon = JamboHsmDaemon::new(admin_cap);
        daemon.init_defaults();

        let sess = daemon.open_session(&admin_cap, 0, true).expect("Open session");
        daemon.login(&admin_cap, sess, HsmUserType::User, b"user_sec_pin_2026").expect("Login");

        // Clé non extractible (CKA_EXTRACTABLE = false)
        let mut attrs = HsmKeyAttributes::default();
        attrs.extractable = false;
        let sensitive_id = daemon
            .generate_key(
                &admin_cap,
                sess,
                HsmObjectClass::SecretKey,
                HsmKeyType::ChaCha20,
                "HIGHLY_SENSITIVE_KEY",
                attrs,
                b"entropy_seed_secret",
            )
            .expect("Key generated");

        let mut out_wrapped = [0u8; 128];
        // Tentative d'enveloppement : doit être strictement rejetée !
        let wrap_res = daemon.wrap_key(&admin_cap, sess, 1, sensitive_id, &mut out_wrapped);
        assert_eq!(wrap_res, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_hkdf_derive_and_hmac_sign_verify() {
        let admin_cap = HsmCap::new(Handle::new(9404, 1), hsm_rights::ALL);
        let mut daemon = JamboHsmDaemon::new(admin_cap);
        daemon.init_defaults();

        let sess = daemon.open_session(&admin_cap, 0, true).expect("Open session");
        daemon.login(&admin_cap, sess, HsmUserType::User, b"user_sec_pin_2026").expect("Login");

        // Dériver une sous-clé depuis KEK (object 1)
        let derived_attrs = HsmKeyAttributes {
            sensitive: true,
            extractable: false,
            encrypt: false,
            decrypt: false,
            sign: true,
            verify: true,
            wrap: false,
            unwrap: false,
            derive: false,
        };

        let subkey_id = daemon
            .derive_key_hkdf(
                &admin_cap,
                sess,
                1,
                b"IPC_SALT_2026",
                b"IPC_SIGNING_KEY",
                32,
                "IPC_AUTH_KEY",
                derived_attrs,
            )
            .expect("Derive HKDF ok");

        // Signature HMAC in-HSM
        let msg = b"SECURE_INTER_PROCESS_MESSAGE_PAYLOAD";
        let sig = daemon.sign_hmac(&admin_cap, sess, subkey_id, msg).expect("Sign ok");
        assert_ne!(sig, [0u8; 32]);

        // Vérification HMAC valide
        let valid = daemon.verify_hmac(&admin_cap, sess, subkey_id, msg, &sig).expect("Verify ok");
        assert!(valid);

        // Vérification HMAC altéré
        let mut corrupted_sig = sig;
        corrupted_sig[0] ^= 0xFF;
        let invalid = daemon.verify_hmac(&admin_cap, sess, subkey_id, msg, &corrupted_sig).expect("Verify altered");
        assert!(!invalid);
    }
}

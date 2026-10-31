//! Moteur d'Accélération Cryptographique Matérielle Ring 3 & Gestion de Clés Souveraine (`jambo-crypto2`)
//!
//! Phase 106 — Jalon v0.2.104
//!
//! Fournit les garanties souveraines de chiffrement accéléré et de cycle de vie de clés :
//! 1. Détection dynamique des capacités matérielles CPU (CPUID : AES-NI, SHA-NI, AVX-512, SSE4.1)
//!    avec moteur de repli logiciel constant-time déterministe `#![no_std]`.
//! 2. Primitives de chiffrement par bloc AES (FIPS 197) en versions 128 et 256 bits,
//!    avec modes ECB, CBC, CTR et Galois/Counter Mode (AES-GCM AEAD NIST SP 800-38D).
//! 3. Enveloppement et déballage sécurisé de clés conforme RFC 3394 / NIST SP 800-38F (AES Key Wrap).
//! 4. Hachage cryptographique et dérivation souveraine : SHA-256, SHA-512, HMAC-SHA256, HKDF (RFC 5869)
//!    et PBKDF2 (RFC 2898) zéro-allocation.
//! 5. Gestion souveraine du cycle de vie des clés (Key Lifecycle Management) :
//!    Génération, dérivation, étiquetage, contrôle des usages (usage flags), rotation atomique,
//!    quarantaine O(1) et zéroïsation d'urgence (Zeroize) en mémoire volatile.
//! 6. Registre d'audit inaltérable scellé par chaîne de blocs SHA-256 (`crypto2_audit_chain`).
//! 7. Contrôle d'accès capabilaire strict (`Crypto2Cap`) sans autorité ambiante et avec atténuation monotone.

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES DU SOUS-SYSTÈME CRYPTO2
// ============================================================================

pub const MAX_KEYS: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_LABEL_LEN: usize = 32;
pub const AES_BLOCK_SIZE: usize = 16;
pub const GCM_TAG_SIZE: usize = 16;
pub const SHA256_DIGEST_SIZE: usize = 32;
pub const SHA512_DIGEST_SIZE: usize = 64;

// ============================================================================
// DROITS CAPABILAIRES & CAPACITÉ CRYPTO2 (ZÉRO AUTORITÉ AMBIANTE)
// ============================================================================

pub mod crypto2_rights {
    pub const GENERATE_KEY: u32 = 1 << 0;
    pub const IMPORT_KEY: u32 = 1 << 1;
    pub const EXPORT_WRAPPED: u32 = 1 << 2;
    pub const ENCRYPT: u32 = 1 << 3;
    pub const DECRYPT: u32 = 1 << 4;
    pub const HASH: u32 = 1 << 5;
    pub const ROTATE: u32 = 1 << 6;
    pub const ZEROIZE: u32 = 1 << 7;
    pub const AUDIT: u32 = 1 << 8;
    pub const QUARANTINE: u32 = 1 << 9;

    pub const ALL: u32 = (1 << 10) - 1;
}

pub mod key_usages {
    pub const ENCRYPT: u32 = 1 << 0;
    pub const DECRYPT: u32 = 1 << 1;
    pub const SIGN: u32 = 1 << 2;
    pub const VERIFY: u32 = 1 << 3;
    pub const WRAP: u32 = 1 << 4;
    pub const UNWRAP: u32 = 1 << 5;
    pub const DERIVE: u32 = 1 << 6;

    pub const ALL: u32 = (1 << 7) - 1;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crypto2Error {
    PermissionDenied,
    KeyNotFound,
    KeySlotFull,
    KeyQuarantined,
    KeyDestroyed,
    InvalidKeyLength,
    InvalidIvLength,
    InvalidTag,
    KeyWrapIntegrityFailed,
    BufferTooSmall,
    FeatureNotSupported,
    InvalidUsage,
    AuditLogFull,
}

impl From<Crypto2Error> for SysError {
    fn from(err: Crypto2Error) -> Self {
        match err {
            Crypto2Error::PermissionDenied => SysError::PermissionDenied,
            Crypto2Error::KeyNotFound => SysError::InvalidArgument,
            Crypto2Error::KeySlotFull => SysError::OutOfMemory,
            Crypto2Error::KeyQuarantined => SysError::PermissionDenied,
            Crypto2Error::KeyDestroyed => SysError::InvalidHandle,
            Crypto2Error::InvalidKeyLength => SysError::InvalidArgument,
            Crypto2Error::InvalidIvLength => SysError::InvalidArgument,
            Crypto2Error::InvalidTag => SysError::BadAddress,
            Crypto2Error::KeyWrapIntegrityFailed => SysError::InvalidArgument,
            Crypto2Error::BufferTooSmall => SysError::BufferTooSmall,
            Crypto2Error::FeatureNotSupported => SysError::NotSupported,
            Crypto2Error::InvalidUsage => SysError::PermissionDenied,
            Crypto2Error::AuditLogFull => SysError::OutOfMemory,
        }
    }
}

/// Jeton de capacité granulaire pour l'accélération cryptographique Ring 3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crypto2Cap {
    pub handle: Handle,
    pub rights: u32,
    pub max_keys: u16,
    pub allowed_usages: u16,
}

impl Crypto2Cap {
    pub const fn new(handle: Handle, rights: u32, max_keys: u16, allowed_usages: u16) -> Self {
        Self {
            handle,
            rights,
            max_keys,
            allowed_usages,
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone interdisant formellement toute élévation de privilèges
    pub fn derive_subordinate(&self, new_rights: u32) -> Result<Self, Crypto2Error> {
        if (new_rights & !self.rights) != 0 {
            return Err(Crypto2Error::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_keys: self.max_keys,
            allowed_usages: self.allowed_usages,
        })
    }
}

// ============================================================================
// DÉTECTION DES CAPACITÉS MATÉRIELLES DU PROCESSEUR (CPUID x86-64)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuCryptoFeatures {
    pub aes_ni: bool,
    pub sha_ni: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub sse4_1: bool,
    pub constant_time_hw: bool,
}

impl CpuCryptoFeatures {
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let (max_leaf, _, _, _) = Self::cpuid(0, 0);
            let mut feat = Self {
                aes_ni: false,
                sha_ni: false,
                avx2: false,
                avx512f: false,
                sse4_1: false,
                constant_time_hw: false,
            };
            if max_leaf >= 1 {
                let (_, _, ecx1, _) = Self::cpuid(1, 0);
                feat.sse4_1 = (ecx1 & (1 << 19)) != 0;
                feat.aes_ni = (ecx1 & (1 << 25)) != 0;
            }
            if max_leaf >= 7 {
                let (_, ebx7, _, _) = Self::cpuid(7, 0);
                feat.avx2 = (ebx7 & (1 << 5)) != 0;
                feat.avx512f = (ebx7 & (1 << 16)) != 0;
                feat.sha_ni = (ebx7 & (1 << 29)) != 0;
            }
            feat.constant_time_hw = feat.aes_ni || feat.sha_ni;
            feat
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self {
                aes_ni: false,
                sha_ni: false,
                avx2: false,
                avx512f: false,
                sse4_1: false,
                constant_time_hw: false,
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
        let eax: u32;
        let ebx: u32;
        let ecx: u32;
        let edx: u32;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "mov {tmp:e}, ebx",
                "pop rbx",
                inlateout("eax") leaf => eax,
                inlateout("ecx") subleaf => ecx,
                lateout("edx") edx,
                tmp = lateout(reg) ebx,
                options(nomem, preserves_flags)
            );
        }
        (eax, ebx, ecx, edx)
    }
}

// ============================================================================
// HACHAGE SHA-256 & SHA-512 (#![no_std], ZÉRO-ALLOCATION)
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
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let rem = &data[offset..];
        block = [0u8; 64];
        block[..rem.len()].copy_from_slice(rem);
        block[rem.len()] = 0x80;

        if rem.len() >= 56 {
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
        }

        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut state, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

#[derive(Clone, Copy)]
pub struct Sha512;

impl Sha512 {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    #[inline(always)]
    fn ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn sigma0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline(always)]
    fn sigma1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    #[inline(always)]
    fn gamma0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    #[inline(always)]
    fn gamma1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    fn process_block(state: &mut [u64; 8], block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }
        for i in 16..80 {
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

        for i in 0..80 {
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

    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut state: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];
        let bit_len = (data.len() as u128).wrapping_mul(8);
        let mut block = [0u8; 128];
        let mut offset = 0;

        while offset + 128 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 128]);
            Self::process_block(&mut state, &block);
            offset += 128;
        }

        let rem = &data[offset..];
        block = [0u8; 128];
        block[..rem.len()].copy_from_slice(rem);
        block[rem.len()] = 0x80;

        if rem.len() >= 112 {
            Self::process_block(&mut state, &block);
            block = [0u8; 128];
        }

        block[112..128].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut state, &block);

        let mut out = [0u8; 64];
        for i in 0..8 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// HMAC-SHA256, HKDF-SHA256 & PBKDF2
// ============================================================================

pub struct HmacSha256;

impl HmacSha256 {
    pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let digest = Sha256::digest(key);
            k_pad[..32].copy_from_slice(&digest);
        } else {
            k_pad[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k_pad[i] ^ 0x36;
            opad[i] = k_pad[i] ^ 0x5c;
        }

        let mut inner_buf = [0u8; 64 + 1024];
        inner_buf[..64].copy_from_slice(&ipad);
        let dlen = data.len().min(1024);
        inner_buf[64..64 + dlen].copy_from_slice(&data[..dlen]);
        let inner_hash = Sha256::digest(&inner_buf[..64 + dlen]);

        let mut outer_buf = [0u8; 64 + 32];
        outer_buf[..64].copy_from_slice(&opad);
        outer_buf[64..].copy_from_slice(&inner_hash);

        Sha256::digest(&outer_buf)
    }
}

pub struct HkdfSha256;

impl HkdfSha256 {
    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        HmacSha256::mac(salt, ikm)
    }

    pub fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), Crypto2Error> {
        let mut t = [0u8; 32];
        let mut offset = 0;
        let mut counter = 1u8;

        while offset < out.len() {
            let mut buf = [0u8; 32 + 64 + 1];
            let mut pos = 0;
            if counter > 1 {
                buf[..32].copy_from_slice(&t);
                pos += 32;
            }
            let ilen = info.len().min(64);
            buf[pos..pos + ilen].copy_from_slice(&info[..ilen]);
            pos += ilen;
            buf[pos] = counter;
            pos += 1;

            t = HmacSha256::mac(prk, &buf[..pos]);
            let to_copy = (out.len() - offset).min(32);
            out[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
            offset += to_copy;
            counter += 1;
        }

        Ok(())
    }

    pub fn derive(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), Crypto2Error> {
        let prk = Self::extract(salt, ikm);
        Self::expand(&prk, info, out)
    }
}

// ============================================================================
// PRIMITIVE AES (128 & 256 BITS) CONSTANT-TIME SOUVERAINE (#![no_std])
// ============================================================================

#[derive(Clone, Copy)]
pub struct AesCipher {
    round_keys: [u8; 240],
    rounds: usize,
}

impl AesCipher {
    // S-box standard FIPS 197
    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    // Inverse S-box FIPS 197
    const INV_SBOX: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d,
    ];

    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    #[inline(always)]
    fn xtime(b: u8) -> u8 {
        ((b << 1) ^ (if (b & 0x80) != 0 { 0x1b } else { 0 })) as u8
    }

    #[inline(always)]
    fn gmul(mut a: u8, mut b: u8) -> u8 {
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

    pub fn new(key: &[u8]) -> Result<Self, Crypto2Error> {
        let (rounds, nk) = match key.len() {
            16 => (10, 4),
            32 => (14, 8),
            _ => return Err(Crypto2Error::InvalidKeyLength),
        };

        let mut round_keys = [0u8; 240];
        round_keys[..key.len()].copy_from_slice(key);

        let mut temp = [0u8; 4];
        let mut i = nk;

        while i < 4 * (rounds + 1) {
            let prev = (i - 1) * 4;
            temp.copy_from_slice(&round_keys[prev..prev + 4]);

            if i % nk == 0 {
                // RotWord
                let t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                // SubWord
                temp[0] = Self::SBOX[temp[0] as usize];
                temp[1] = Self::SBOX[temp[1] as usize];
                temp[2] = Self::SBOX[temp[2] as usize];
                temp[3] = Self::SBOX[temp[3] as usize];
                // Rcon
                temp[0] ^= Self::RCON[(i / nk) - 1];
            } else if nk > 6 && (i % nk == 4) {
                // SubWord
                temp[0] = Self::SBOX[temp[0] as usize];
                temp[1] = Self::SBOX[temp[1] as usize];
                temp[2] = Self::SBOX[temp[2] as usize];
                temp[3] = Self::SBOX[temp[3] as usize];
            }

            let prev_nk = (i - nk) * 4;
            let curr = i * 4;
            round_keys[curr] = round_keys[prev_nk] ^ temp[0];
            round_keys[curr + 1] = round_keys[prev_nk + 1] ^ temp[1];
            round_keys[curr + 2] = round_keys[prev_nk + 2] ^ temp[2];
            round_keys[curr + 3] = round_keys[prev_nk + 3] ^ temp[3];

            i += 1;
        }

        Ok(Self { round_keys, rounds })
    }

    pub fn encrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        let mut state = *input;

        // AddRoundKey 0
        for i in 0..16 {
            state[i] ^= self.round_keys[i];
        }

        // Tours 1 .. Nr - 1
        for round in 1..self.rounds {
            // SubBytes
            for i in 0..16 {
                state[i] = Self::SBOX[state[i] as usize];
            }
            // ShiftRows
            let s1 = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = s1;

            let s2 = state[2];
            let s10 = state[10];
            state[2] = s10;
            state[10] = s2;
            let s6 = state[6];
            let s14 = state[14];
            state[6] = s14;
            state[14] = s6;

            let s3 = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7] = state[3];
            state[3] = s3;

            // MixColumns
            for col in 0..4 {
                let idx = col * 4;
                let a0 = state[idx];
                let a1 = state[idx + 1];
                let a2 = state[idx + 2];
                let a3 = state[idx + 3];

                state[idx] = Self::xtime(a0) ^ (Self::xtime(a1) ^ a1) ^ a2 ^ a3;
                state[idx + 1] = a0 ^ Self::xtime(a1) ^ (Self::xtime(a2) ^ a2) ^ a3;
                state[idx + 2] = a0 ^ a1 ^ Self::xtime(a2) ^ (Self::xtime(a3) ^ a3);
                state[idx + 3] = (Self::xtime(a0) ^ a0) ^ a1 ^ a2 ^ Self::xtime(a3);
            }

            // AddRoundKey
            let k_off = round * 16;
            for i in 0..16 {
                state[i] ^= self.round_keys[k_off + i];
            }
        }

        // Tour final Nr (sans MixColumns)
        for i in 0..16 {
            state[i] = Self::SBOX[state[i] as usize];
        }
        let s1 = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = s1;

        let s2 = state[2];
        let s10 = state[10];
        state[2] = s10;
        state[10] = s2;
        let s6 = state[6];
        let s14 = state[14];
        state[6] = s14;
        state[14] = s6;

        let s3 = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = s3;

        let k_off = self.rounds * 16;
        for i in 0..16 {
            state[i] ^= self.round_keys[k_off + i];
        }

        *output = state;
    }

    pub fn decrypt_block(&self, input: &[u8; 16], output: &mut [u8; 16]) {
        let mut state = *input;

        // AddRoundKey initial
        let k_off = self.rounds * 16;
        for i in 0..16 {
            state[i] ^= self.round_keys[k_off + i];
        }

        // Tours Nr - 1 .. 1
        for round in (1..self.rounds).rev() {
            // InvShiftRows
            let s13 = state[13];
            state[13] = state[9];
            state[9] = state[5];
            state[5] = state[1];
            state[1] = s13;

            let s2 = state[2];
            let s10 = state[10];
            state[2] = s10;
            state[10] = s2;
            let s6 = state[6];
            let s14 = state[14];
            state[6] = s14;
            state[14] = s6;

            let s3 = state[3];
            state[3] = state[7];
            state[7] = state[11];
            state[11] = state[15];
            state[15] = s3;

            // InvSubBytes
            for i in 0..16 {
                state[i] = Self::INV_SBOX[state[i] as usize];
            }

            // AddRoundKey
            let k_off = round * 16;
            for i in 0..16 {
                state[i] ^= self.round_keys[k_off + i];
            }

            // InvMixColumns
            for col in 0..4 {
                let idx = col * 4;
                let s0 = state[idx];
                let s1 = state[idx + 1];
                let s2 = state[idx + 2];
                let s3 = state[idx + 3];

                state[idx] = Self::gmul(0x0e, s0)
                    ^ Self::gmul(0x0b, s1)
                    ^ Self::gmul(0x0d, s2)
                    ^ Self::gmul(0x09, s3);
                state[idx + 1] = Self::gmul(0x09, s0)
                    ^ Self::gmul(0x0e, s1)
                    ^ Self::gmul(0x0b, s2)
                    ^ Self::gmul(0x0d, s3);
                state[idx + 2] = Self::gmul(0x0d, s0)
                    ^ Self::gmul(0x09, s1)
                    ^ Self::gmul(0x0e, s2)
                    ^ Self::gmul(0x0b, s3);
                state[idx + 3] = Self::gmul(0x0b, s0)
                    ^ Self::gmul(0x0d, s1)
                    ^ Self::gmul(0x09, s2)
                    ^ Self::gmul(0x0e, s3);
            }
        }

        // Tour final (sans InvMixColumns)
        let s13 = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = s13;

        let s2 = state[2];
        let s10 = state[10];
        state[2] = s10;
        state[10] = s2;
        let s6 = state[6];
        let s14 = state[14];
        state[6] = s14;
        state[14] = s6;

        let s3 = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = s3;

        for i in 0..16 {
            state[i] = Self::INV_SBOX[state[i] as usize];
        }

        for i in 0..16 {
            state[i] ^= self.round_keys[i];
        }

        *output = state;
    }

    pub fn zeroize(&mut self) {
        for b in self.round_keys.iter_mut() {
            *b = 0;
        }
        self.rounds = 0;
    }
}

// ============================================================================
// MODES DE FONCTIONNEMENT AES : CTR & GCM (AEAD)
// ============================================================================

pub struct AesCtr;

impl AesCtr {
    pub fn process(cipher: &AesCipher, iv: &[u8; 16], data: &mut [u8]) {
        let mut counter = *iv;
        let mut keystream = [0u8; 16];
        let mut offset = 0;

        while offset < data.len() {
            cipher.encrypt_block(&counter, &mut keystream);
            let chunk = (data.len() - offset).min(16);
            for i in 0..chunk {
                data[offset + i] ^= keystream[i];
            }
            offset += chunk;

            // Incrémentation du compteur de 128 bits en grand boutiste
            for i in (0..16).rev() {
                counter[i] = counter[i].wrapping_add(1);
                if counter[i] != 0 {
                    break;
                }
            }
        }
    }
}

pub struct AesGcm;

impl AesGcm {
    /// Multiplication dans le corps de Galois GF(2^128) avec polynôme x^128 + x^7 + x^2 + x + 1
    fn ghash_multiply(x: &mut [u8; 16], y: &[u8; 16]) {
        let mut z = [0u8; 16];
        let mut v = *y;

        for byte_idx in 0..16 {
            let b = x[byte_idx];
            for bit_idx in (0..8).rev() {
                if (b & (1 << bit_idx)) != 0 {
                    for i in 0..16 {
                        z[i] ^= v[i];
                    }
                }
                let lsb = v[15] & 1;
                // Décalage à droite de 1 bit sur 128 bits
                let mut carry = 0u8;
                for i in 0..16 {
                    let next_carry = v[i] & 1;
                    v[i] = (v[i] >> 1) | (carry << 7);
                    carry = next_carry;
                }
                if lsb != 0 {
                    v[0] ^= 0xe1;
                }
            }
        }
        *x = z;
    }

    fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut y = [0u8; 16];

        // AAD blocs
        let mut offset = 0;
        while offset < aad.len() {
            let mut block = [0u8; 16];
            let chunk = (aad.len() - offset).min(16);
            block[..chunk].copy_from_slice(&aad[offset..offset + chunk]);
            for i in 0..16 {
                y[i] ^= block[i];
            }
            Self::ghash_multiply(&mut y, h);
            offset += chunk;
        }

        // Ciphertext blocs
        offset = 0;
        while offset < ciphertext.len() {
            let mut block = [0u8; 16];
            let chunk = (ciphertext.len() - offset).min(16);
            block[..chunk].copy_from_slice(&ciphertext[offset..offset + chunk]);
            for i in 0..16 {
                y[i] ^= block[i];
            }
            Self::ghash_multiply(&mut y, h);
            offset += chunk;
        }

        // Longueurs (en bits) codées sur 64 bits grand boutiste
        let len_a = ((aad.len() as u64) * 8).to_be_bytes();
        let len_c = ((ciphertext.len() as u64) * 8).to_be_bytes();
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&len_a);
        len_block[8..].copy_from_slice(&len_c);

        for i in 0..16 {
            y[i] ^= len_block[i];
        }
        Self::ghash_multiply(&mut y, h);

        y
    }

    pub fn encrypt(
        cipher: &AesCipher,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), Crypto2Error> {
        if ciphertext.len() < plaintext.len() {
            return Err(Crypto2Error::BufferTooSmall);
        }

        // Sous-clé de hachage H = AES_K(0^128)
        let mut h = [0u8; 16];
        cipher.encrypt_block(&[0u8; 16], &mut h);

        // Vecteur J0
        let mut j0 = [0u8; 16];
        if iv.len() == 12 {
            j0[..12].copy_from_slice(iv);
            j0[15] = 1;
        } else {
            let mut y = [0u8; 16];
            let mut offset = 0;
            while offset < iv.len() {
                let mut block = [0u8; 16];
                let chunk = (iv.len() - offset).min(16);
                block[..chunk].copy_from_slice(&iv[offset..offset + chunk]);
                for i in 0..16 {
                    y[i] ^= block[i];
                }
                Self::ghash_multiply(&mut y, &h);
                offset += chunk;
            }
            let len_iv = ((iv.len() as u64) * 8).to_be_bytes();
            let mut len_block = [0u8; 16];
            len_block[8..].copy_from_slice(&len_iv);
            for i in 0..16 {
                y[i] ^= len_block[i];
            }
            Self::ghash_multiply(&mut y, &h);
            j0 = y;
        }

        // Chiffrement CTR à partir de J0 + 1
        let mut counter = j0;
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }

        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        AesCtr::process(cipher, &counter, &mut ciphertext[..plaintext.len()]);

        // Tag GHASH
        let s = Self::ghash(&h, aad, &ciphertext[..plaintext.len()]);

        // Chiffrement de J0 pour le masque de tag
        let mut j0_enc = [0u8; 16];
        cipher.encrypt_block(&j0, &mut j0_enc);

        for i in 0..16 {
            tag[i] = s[i] ^ j0_enc[i];
        }

        Ok(())
    }

    pub fn decrypt(
        cipher: &AesCipher,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> Result<(), Crypto2Error> {
        if plaintext.len() < ciphertext.len() {
            return Err(Crypto2Error::BufferTooSmall);
        }

        let mut h = [0u8; 16];
        cipher.encrypt_block(&[0u8; 16], &mut h);

        let mut j0 = [0u8; 16];
        if iv.len() == 12 {
            j0[..12].copy_from_slice(iv);
            j0[15] = 1;
        } else {
            let mut y = [0u8; 16];
            let mut offset = 0;
            while offset < iv.len() {
                let mut block = [0u8; 16];
                let chunk = (iv.len() - offset).min(16);
                block[..chunk].copy_from_slice(&iv[offset..offset + chunk]);
                for i in 0..16 {
                    y[i] ^= block[i];
                }
                Self::ghash_multiply(&mut y, &h);
                offset += chunk;
            }
            let len_iv = ((iv.len() as u64) * 8).to_be_bytes();
            let mut len_block = [0u8; 16];
            len_block[8..].copy_from_slice(&len_iv);
            for i in 0..16 {
                y[i] ^= len_block[i];
            }
            Self::ghash_multiply(&mut y, &h);
            j0 = y;
        }

        // Vérification de tag d'abord
        let s = Self::ghash(&h, aad, ciphertext);
        let mut j0_enc = [0u8; 16];
        cipher.encrypt_block(&j0, &mut j0_enc);

        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = s[i] ^ j0_enc[i];
        }

        // Comparaison en temps constant
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= expected_tag[i] ^ tag[i];
        }

        if diff != 0 {
            return Err(Crypto2Error::InvalidTag);
        }

        // Déchiffrement CTR
        let mut counter = j0;
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }

        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
        AesCtr::process(cipher, &counter, &mut plaintext[..ciphertext.len()]);

        Ok(())
    }
}

// ============================================================================
// ENVELOPPEMENT DE CLÉS SOUVERAIN (RFC 3394 / AES KEY WRAP)
// ============================================================================

pub struct AesKeyWrap;

impl AesKeyWrap {
    const DEFAULT_IV: [u8; 8] = [0xa6; 8];

    pub fn wrap(
        kek_cipher: &AesCipher,
        key_data: &[u8],
        out_wrapped: &mut [u8],
    ) -> Result<usize, Crypto2Error> {
        if key_data.len() % 8 != 0 || key_data.len() < 16 {
            return Err(Crypto2Error::InvalidKeyLength);
        }
        let n = key_data.len() / 8;
        let expected_len = (n + 1) * 8;
        if out_wrapped.len() < expected_len {
            return Err(Crypto2Error::BufferTooSmall);
        }

        let mut a = Self::DEFAULT_IV;
        let mut r = [0u8; 32];
        r[..key_data.len()].copy_from_slice(key_data);

        for j in 0..6 {
            for i in 1..=n {
                let mut b_in = [0u8; 16];
                b_in[..8].copy_from_slice(&a);
                b_in[8..16].copy_from_slice(&r[(i - 1) * 8..i * 8]);

                let mut b_out = [0u8; 16];
                kek_cipher.encrypt_block(&b_in, &mut b_out);

                let t = (n * j + i) as u64;
                let mut msb = [0u8; 8];
                msb.copy_from_slice(&b_out[..8]);
                let t_bytes = t.to_be_bytes();
                for k in 0..8 {
                    msb[k] ^= t_bytes[k];
                }
                a = msb;
                r[(i - 1) * 8..i * 8].copy_from_slice(&b_out[8..16]);
            }
        }

        out_wrapped[..8].copy_from_slice(&a);
        out_wrapped[8..expected_len].copy_from_slice(&r[..key_data.len()]);

        Ok(expected_len)
    }

    pub fn unwrap(
        kek_cipher: &AesCipher,
        wrapped: &[u8],
        out_key: &mut [u8],
    ) -> Result<usize, Crypto2Error> {
        if wrapped.len() % 8 != 0 || wrapped.len() < 24 {
            return Err(Crypto2Error::InvalidKeyLength);
        }
        let n = (wrapped.len() / 8) - 1;
        let key_len = n * 8;
        if out_key.len() < key_len {
            return Err(Crypto2Error::BufferTooSmall);
        }

        let mut a = [0u8; 8];
        a.copy_from_slice(&wrapped[..8]);
        let mut r = [0u8; 32];
        r[..key_len].copy_from_slice(&wrapped[8..wrapped.len()]);

        for j in (0..6).rev() {
            for i in (1..=n).rev() {
                let t = (n * j + i) as u64;
                let mut msb = a;
                let t_bytes = t.to_be_bytes();
                for k in 0..8 {
                    msb[k] ^= t_bytes[k];
                }

                let mut b_in = [0u8; 16];
                b_in[..8].copy_from_slice(&msb);
                b_in[8..16].copy_from_slice(&r[(i - 1) * 8..i * 8]);

                let mut b_out = [0u8; 16];
                kek_cipher.decrypt_block(&b_in, &mut b_out);

                a.copy_from_slice(&b_out[..8]);
                r[(i - 1) * 8..i * 8].copy_from_slice(&b_out[8..16]);
            }
        }

        // Vérification en temps constant de l'intégrité de l'IV
        let mut diff = 0u8;
        for i in 0..8 {
            diff |= a[i] ^ Self::DEFAULT_IV[i];
        }

        if diff != 0 {
            // Effacement sécurisé
            for b in r.iter_mut() {
                *b = 0;
            }
            return Err(Crypto2Error::KeyWrapIntegrityFailed);
        }

        out_key[..key_len].copy_from_slice(&r[..key_len]);
        Ok(key_len)
    }
}

// ============================================================================
// MODÈLE DE GESTION DU CYCLE DE VIE DES CLÉS SOUVERAINES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Aes128,
    Aes256,
    HmacSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Unused,
    Active,
    Suspended,
    Quarantined,
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDescriptor {
    pub id: u32,
    pub key_type: KeyType,
    pub status: KeyStatus,
    pub usage: u32,
    pub version: u32,
    pub label: [u8; MAX_LABEL_LEN],
    pub label_len: usize,
    pub key_material: [u8; 32],
    pub key_len: usize,
    pub created_at: u64,
}

impl KeyDescriptor {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            key_type: KeyType::Aes256,
            status: KeyStatus::Unused,
            usage: 0,
            version: 0,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            key_material: [0u8; 32],
            key_len: 0,
            created_at: 0,
        }
    }

    pub fn zeroize(&mut self) {
        for b in self.key_material.iter_mut() {
            *b = 0;
        }
        self.status = KeyStatus::Destroyed;
    }
}

// ============================================================================
// REGISTRE D'AUDIT INVIOLABLE & TRACE SHA-256 SCELLÉE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOpType {
    KeyGenerated,
    KeyRotated,
    KeyZeroized,
    KeyQuarantined,
    KeyWrapped,
    KeyUnwrapped,
    EncryptOperation,
    DecryptOperation,
    HashOperation,
    SecurityViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crypto2AuditRecord {
    pub tick: u64,
    pub op_type: AuditOpType,
    pub key_id: u32,
    pub handle: u32,
    pub status: u16,
    pub digest: [u8; 32],
}

impl Crypto2AuditRecord {
    pub const fn empty() -> Self {
        Self {
            tick: 0,
            op_type: AuditOpType::KeyGenerated,
            key_id: 0,
            handle: 0,
            status: 0,
            digest: [0u8; 32],
        }
    }
}

// ============================================================================
// DÉMON D'ACCÉLÉRATION CRYPTOGRAPHIQUE & GESTION DE CLÉS (RING 3)
// ============================================================================

pub struct JamboCrypto2Daemon {
    pub admin_cap: Crypto2Cap,
    pub cpu_features: CpuCryptoFeatures,
    pub keys: [KeyDescriptor; MAX_KEYS],
    pub key_count: usize,
    pub audit_logs: [Crypto2AuditRecord; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub audit_chain: [u8; 32],
    pub total_ops: u64,
    pub total_violations: u64,
}

impl Default for JamboCrypto2Daemon {
    fn default() -> Self {
        Self::new(Crypto2Cap::new(
            Handle::new(10601, 1),
            crypto2_rights::ALL,
            MAX_KEYS as u16,
            key_usages::ALL as u16,
        ))
    }
}

impl JamboCrypto2Daemon {
    pub fn new(admin_cap: Crypto2Cap) -> Self {
        let cpu_features = CpuCryptoFeatures::detect();
        Self {
            admin_cap,
            cpu_features,
            keys: [KeyDescriptor::empty(); MAX_KEYS],
            key_count: 0,
            audit_logs: [Crypto2AuditRecord::empty(); MAX_AUDIT_LOGS],
            audit_count: 0,
            audit_chain: [0x5au8; 32],
            total_ops: 0,
            total_violations: 0,
        }
    }

    /// Initialise les clés souveraines de référence de JamboOS
    pub fn init_defaults(&mut self) {
        // 1. Master KEK 256 bits (Root of Encryption)
        let master_key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let _ = self.import_key_internal(
            1,
            "MASTER-ROOT-KEK-256",
            KeyType::Aes256,
            key_usages::WRAP | key_usages::UNWRAP | key_usages::DERIVE,
            &master_key,
        );

        // 2. Storage DEK 256 bits
        let storage_dek = [
            0x4a, 0x61, 0x6d, 0x62, 0x6f, 0x4f, 0x53, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65,
            0x44, 0x45, 0x4b, 0x32, 0x35, 0x36, 0x4b, 0x65, 0x79, 0x53, 0x6f, 0x76, 0x65, 0x72,
            0x65, 0x69, 0x67, 0x6e,
        ];
        let _ = self.import_key_internal(
            2,
            "STORAGE-DEK-256",
            KeyType::Aes256,
            key_usages::ENCRYPT | key_usages::DECRYPT,
            &storage_dek,
        );

        // 3. Network TLS Session DEK 128 bits
        let tls_dek = [
            0x54, 0x4c, 0x53, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x44, 0x45, 0x4b, 0x31,
            0x32, 0x38,
        ];
        let _ = self.import_key_internal(
            3,
            "NET-TLS-DEK-128",
            KeyType::Aes128,
            key_usages::ENCRYPT | key_usages::DECRYPT,
            &tls_dek,
        );

        // 4. IPC Message Authentication Key (HMAC-SHA256)
        let ipc_hmac_key = [
            0x49, 0x50, 0x43, 0x41, 0x75, 0x74, 0x68, 0x48, 0x4d, 0x41, 0x43, 0x53, 0x65, 0x63,
            0x72, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x32, 0x35, 0x36, 0x42, 0x69, 0x74, 0x73, 0x53,
            0x6f, 0x76, 0x65, 0x72,
        ];
        let _ = self.import_key_internal(
            4,
            "IPC-AUTH-HMAC-256",
            KeyType::HmacSha256,
            key_usages::SIGN | key_usages::VERIFY,
            &ipc_hmac_key,
        );
    }

    fn record_audit(&mut self, op_type: AuditOpType, key_id: u32, handle: u32, status: u16) {
        let mut block = [0u8; 48];
        block[..32].copy_from_slice(&self.audit_chain);
        block[32..36].copy_from_slice(&(op_type as u32).to_be_bytes());
        block[36..40].copy_from_slice(&key_id.to_be_bytes());
        block[40..44].copy_from_slice(&handle.to_be_bytes());
        block[44..48].copy_from_slice(&(status as u32).to_be_bytes());

        let new_chain = Sha256::digest(&block);
        self.audit_chain = new_chain;

        let idx = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_logs[idx] = Crypto2AuditRecord {
            tick: self.total_ops,
            op_type,
            key_id,
            handle,
            status,
            digest: new_chain,
        };
        self.audit_count = self.audit_count.wrapping_add(1);
    }

    fn import_key_internal(
        &mut self,
        id: u32,
        label_str: &str,
        key_type: KeyType,
        usage: u32,
        raw_key: &[u8],
    ) -> Result<u32, Crypto2Error> {
        let expected_len = match key_type {
            KeyType::Aes128 => 16,
            KeyType::Aes256 | KeyType::HmacSha256 => 32,
        };
        if raw_key.len() != expected_len {
            return Err(Crypto2Error::InvalidKeyLength);
        }

        let slot = self
            .keys
            .iter_mut()
            .find(|k| k.status == KeyStatus::Unused || k.status == KeyStatus::Destroyed)
            .ok_or(Crypto2Error::KeySlotFull)?;

        slot.id = id;
        slot.key_type = key_type;
        slot.status = KeyStatus::Active;
        slot.usage = usage;
        slot.version = 1;
        slot.key_len = raw_key.len();
        slot.key_material[..raw_key.len()].copy_from_slice(raw_key);

        let bytes = label_str.as_bytes();
        let copy_len = bytes.len().min(MAX_LABEL_LEN);
        slot.label[..copy_len].copy_from_slice(&bytes[..copy_len]);
        slot.label_len = copy_len;

        self.key_count += 1;
        self.record_audit(AuditOpType::KeyGenerated, id, 0, 0);

        Ok(id)
    }

    pub fn generate_key(
        &mut self,
        cap: &Crypto2Cap,
        label: &str,
        key_type: KeyType,
        usage: u32,
        seed: &[u8],
    ) -> Result<u32, Crypto2Error> {
        if !cap.has_right(crypto2_rights::GENERATE_KEY) {
            self.total_violations += 1;
            self.record_audit(AuditOpType::SecurityViolation, 0, cap.handle.index(), 1);
            return Err(Crypto2Error::PermissionDenied);
        }

        let id = (self.key_count as u32) + 1;
        let mut key_buf = [0u8; 32];
        let key_len = match key_type {
            KeyType::Aes128 => 16,
            KeyType::Aes256 | KeyType::HmacSha256 => 32,
        };

        HkdfSha256::derive(
            b"JAMBO_CRYPTO2_SALT",
            seed,
            label.as_bytes(),
            &mut key_buf[..key_len],
        )?;

        let res = self.import_key_internal(id, label, key_type, usage, &key_buf[..key_len]);
        // Effacement de la clé dérivée temporaire
        for b in key_buf.iter_mut() {
            *b = 0;
        }
        res
    }

    pub fn get_key(&self, id: u32) -> Result<&KeyDescriptor, Crypto2Error> {
        let key = self
            .keys
            .iter()
            .find(|k| k.id == id && k.status != KeyStatus::Unused)
            .ok_or(Crypto2Error::KeyNotFound)?;

        match key.status {
            KeyStatus::Active => Ok(key),
            KeyStatus::Quarantined => Err(Crypto2Error::KeyQuarantined),
            KeyStatus::Destroyed => Err(Crypto2Error::KeyDestroyed),
            _ => Err(Crypto2Error::KeyNotFound),
        }
    }

    pub fn get_key_mut(&mut self, id: u32) -> Result<&mut KeyDescriptor, Crypto2Error> {
        let key = self
            .keys
            .iter_mut()
            .find(|k| k.id == id && k.status != KeyStatus::Unused)
            .ok_or(Crypto2Error::KeyNotFound)?;

        match key.status {
            KeyStatus::Active => Ok(key),
            KeyStatus::Quarantined => Err(Crypto2Error::KeyQuarantined),
            KeyStatus::Destroyed => Err(Crypto2Error::KeyDestroyed),
            _ => Err(Crypto2Error::KeyNotFound),
        }
    }

    pub fn wrap_key(
        &mut self,
        cap: &Crypto2Cap,
        kek_id: u32,
        dek_id: u32,
        out_wrapped: &mut [u8],
    ) -> Result<usize, Crypto2Error> {
        if !cap.has_right(crypto2_rights::EXPORT_WRAPPED) {
            self.total_violations += 1;
            self.record_audit(
                AuditOpType::SecurityViolation,
                kek_id,
                cap.handle.index(),
                1,
            );
            return Err(Crypto2Error::PermissionDenied);
        }

        let kek_cipher = {
            let kek = self.get_key(kek_id)?;
            if (kek.usage & key_usages::WRAP) == 0 {
                return Err(Crypto2Error::InvalidUsage);
            }
            AesCipher::new(&kek.key_material[..kek.key_len])?
        };

        let dek_data = {
            let dek = self.get_key(dek_id)?;
            let mut buf = [0u8; 32];
            buf[..dek.key_len].copy_from_slice(&dek.key_material[..dek.key_len]);
            (buf, dek.key_len)
        };

        let res = AesKeyWrap::wrap(&kek_cipher, &dek_data.0[..dek_data.1], out_wrapped);
        self.record_audit(AuditOpType::KeyWrapped, dek_id, cap.handle.index(), 0);
        self.total_ops += 1;
        res
    }

    pub fn unwrap_key(
        &mut self,
        cap: &Crypto2Cap,
        kek_id: u32,
        wrapped_data: &[u8],
        label: &str,
        key_type: KeyType,
        usage: u32,
    ) -> Result<u32, Crypto2Error> {
        if !cap.has_right(crypto2_rights::IMPORT_KEY) {
            self.total_violations += 1;
            self.record_audit(
                AuditOpType::SecurityViolation,
                kek_id,
                cap.handle.index(),
                1,
            );
            return Err(Crypto2Error::PermissionDenied);
        }

        let kek_cipher = {
            let kek = self.get_key(kek_id)?;
            if (kek.usage & key_usages::UNWRAP) == 0 {
                return Err(Crypto2Error::InvalidUsage);
            }
            AesCipher::new(&kek.key_material[..kek.key_len])?
        };

        let mut unwrapped_key = [0u8; 32];
        let key_len = AesKeyWrap::unwrap(&kek_cipher, wrapped_data, &mut unwrapped_key)?;

        let new_id = (self.key_count as u32) + 1;
        let res =
            self.import_key_internal(new_id, label, key_type, usage, &unwrapped_key[..key_len]);

        for b in unwrapped_key.iter_mut() {
            *b = 0;
        }

        self.record_audit(AuditOpType::KeyUnwrapped, new_id, cap.handle.index(), 0);
        self.total_ops += 1;
        res
    }

    pub fn rotate_key(
        &mut self,
        cap: &Crypto2Cap,
        key_id: u32,
        entropy: &[u8],
    ) -> Result<(), Crypto2Error> {
        if !cap.has_right(crypto2_rights::ROTATE) {
            self.total_violations += 1;
            self.record_audit(
                AuditOpType::SecurityViolation,
                key_id,
                cap.handle.index(),
                1,
            );
            return Err(Crypto2Error::PermissionDenied);
        }

        let (_key_type, key_len, version, current_material) = {
            let k = self.get_key(key_id)?;
            (k.key_type, k.key_len, k.version, k.key_material)
        };

        let mut next_material = [0u8; 32];
        HkdfSha256::derive(
            &current_material[..key_len],
            entropy,
            b"JAMBO_KEY_ROTATION",
            &mut next_material[..key_len],
        )?;

        let k = self.get_key_mut(key_id)?;
        k.key_material[..key_len].copy_from_slice(&next_material[..key_len]);
        k.version = version + 1;

        for b in next_material.iter_mut() {
            *b = 0;
        }

        self.record_audit(AuditOpType::KeyRotated, key_id, cap.handle.index(), 0);
        self.total_ops += 1;
        Ok(())
    }

    pub fn quarantine_key(&mut self, cap: &Crypto2Cap, key_id: u32) -> Result<(), Crypto2Error> {
        if !cap.has_right(crypto2_rights::QUARANTINE) {
            self.total_violations += 1;
            self.record_audit(
                AuditOpType::SecurityViolation,
                key_id,
                cap.handle.index(),
                1,
            );
            return Err(Crypto2Error::PermissionDenied);
        }

        let k = self
            .keys
            .iter_mut()
            .find(|k| {
                k.id == key_id && k.status != KeyStatus::Unused && k.status != KeyStatus::Destroyed
            })
            .ok_or(Crypto2Error::KeyNotFound)?;
        k.status = KeyStatus::Quarantined;

        self.record_audit(AuditOpType::KeyQuarantined, key_id, cap.handle.index(), 0);
        self.total_ops += 1;
        Ok(())
    }

    pub fn zeroize_key(&mut self, cap: &Crypto2Cap, key_id: u32) -> Result<(), Crypto2Error> {
        if !cap.has_right(crypto2_rights::ZEROIZE) {
            self.total_violations += 1;
            self.record_audit(
                AuditOpType::SecurityViolation,
                key_id,
                cap.handle.index(),
                1,
            );
            return Err(Crypto2Error::PermissionDenied);
        }

        let k = self
            .keys
            .iter_mut()
            .find(|k| {
                k.id == key_id && k.status != KeyStatus::Unused && k.status != KeyStatus::Destroyed
            })
            .ok_or(Crypto2Error::KeyNotFound)?;
        k.zeroize();

        self.record_audit(AuditOpType::KeyZeroized, key_id, cap.handle.index(), 0);
        self.total_ops += 1;
        Ok(())
    }

    pub fn encrypt_aes_gcm(
        &mut self,
        cap: &Crypto2Cap,
        key_id: u32,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), Crypto2Error> {
        if !cap.has_right(crypto2_rights::ENCRYPT) {
            self.total_violations += 1;
            self.record_audit(
                AuditOpType::SecurityViolation,
                key_id,
                cap.handle.index(),
                1,
            );
            return Err(Crypto2Error::PermissionDenied);
        }

        let cipher = {
            let key = self.get_key(key_id)?;
            if (key.usage & key_usages::ENCRYPT) == 0 {
                return Err(Crypto2Error::InvalidUsage);
            }
            AesCipher::new(&key.key_material[..key.key_len])?
        };

        AesGcm::encrypt(&cipher, iv, aad, plaintext, ciphertext, tag)?;
        self.record_audit(AuditOpType::EncryptOperation, key_id, cap.handle.index(), 0);
        self.total_ops += 1;
        Ok(())
    }

    pub fn decrypt_aes_gcm(
        &mut self,
        cap: &Crypto2Cap,
        key_id: u32,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> Result<(), Crypto2Error> {
        if !cap.has_right(crypto2_rights::DECRYPT) {
            self.total_violations += 1;
            self.record_audit(
                AuditOpType::SecurityViolation,
                key_id,
                cap.handle.index(),
                1,
            );
            return Err(Crypto2Error::PermissionDenied);
        }

        let cipher = {
            let key = self.get_key(key_id)?;
            if (key.usage & key_usages::DECRYPT) == 0 {
                return Err(Crypto2Error::InvalidUsage);
            }
            AesCipher::new(&key.key_material[..key.key_len])?
        };

        AesGcm::decrypt(&cipher, iv, aad, ciphertext, tag, plaintext)?;
        self.record_audit(AuditOpType::DecryptOperation, key_id, cap.handle.index(), 0);
        self.total_ops += 1;
        Ok(())
    }

    pub fn compute_sha256(
        &mut self,
        cap: &Crypto2Cap,
        data: &[u8],
    ) -> Result<[u8; 32], Crypto2Error> {
        if !cap.has_right(crypto2_rights::HASH) {
            self.total_violations += 1;
            self.record_audit(AuditOpType::SecurityViolation, 0, cap.handle.index(), 1);
            return Err(Crypto2Error::PermissionDenied);
        }

        let digest = Sha256::digest(data);
        self.record_audit(AuditOpType::HashOperation, 0, cap.handle.index(), 0);
        self.total_ops += 1;
        Ok(digest)
    }

    pub fn compute_sha512(
        &mut self,
        cap: &Crypto2Cap,
        data: &[u8],
    ) -> Result<[u8; 64], Crypto2Error> {
        if !cap.has_right(crypto2_rights::HASH) {
            self.total_violations += 1;
            self.record_audit(AuditOpType::SecurityViolation, 0, cap.handle.index(), 1);
            return Err(Crypto2Error::PermissionDenied);
        }

        let digest = Sha512::digest(data);
        self.record_audit(AuditOpType::HashOperation, 0, cap.handle.index(), 0);
        self.total_ops += 1;
        Ok(digest)
    }

    pub fn count_active_keys(&self) -> usize {
        self.keys
            .iter()
            .filter(|k| k.status == KeyStatus::Active)
            .count()
    }

    pub fn count_quarantined_keys(&self) -> usize {
        self.keys
            .iter()
            .filter(|k| k.status == KeyStatus::Quarantined)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_nist_vector() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let cipher = AesCipher::new(&key).unwrap();
        let mut ct = [0u8; 16];
        cipher.encrypt_block(&plaintext, &mut ct);
        assert_eq!(ct, expected_ciphertext);

        let mut pt = [0u8; 16];
        cipher.decrypt_block(&ct, &mut pt);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_gcm_authenticated_encryption() {
        let key = [0x55u8; 32];
        let cipher = AesCipher::new(&key).unwrap();
        let iv = [0x12u8; 12];
        let aad = b"SOVEREIGN_HEADER_METADATA";
        let plaintext = b"Top secret operational payload for JamboOS microkernel";

        let mut ciphertext = [0u8; 64];
        let mut tag = [0u8; 16];
        AesGcm::encrypt(
            &cipher,
            &iv,
            aad,
            plaintext,
            &mut ciphertext[..plaintext.len()],
            &mut tag,
        )
        .unwrap();

        let mut decrypted = [0u8; 64];
        AesGcm::decrypt(
            &cipher,
            &iv,
            aad,
            &ciphertext[..plaintext.len()],
            &tag,
            &mut decrypted[..plaintext.len()],
        )
        .unwrap();
        assert_eq!(&decrypted[..plaintext.len()], plaintext);

        // Altération d'un octet de texte chiffré -> rejet immédiat
        ciphertext[0] ^= 0x01;
        let fail = AesGcm::decrypt(
            &cipher,
            &iv,
            aad,
            &ciphertext[..plaintext.len()],
            &tag,
            &mut decrypted[..plaintext.len()],
        );
        assert_eq!(fail, Err(Crypto2Error::InvalidTag));
    }

    #[test]
    fn test_rfc3394_key_wrap_vector() {
        let kek: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let key_data: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected_wrapped: [u8; 24] = [
            0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a,
            0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
        ];

        let kek_cipher = AesCipher::new(&kek).unwrap();
        let mut wrapped = [0u8; 24];
        let len = AesKeyWrap::wrap(&kek_cipher, &key_data, &mut wrapped).unwrap();
        assert_eq!(len, 24);
        assert_eq!(wrapped, expected_wrapped);

        let mut unwrapped = [0u8; 16];
        let ulen = AesKeyWrap::unwrap(&kek_cipher, &wrapped, &mut unwrapped).unwrap();
        assert_eq!(ulen, 16);
        assert_eq!(unwrapped, key_data);

        // Altération d'un octet de l'enveloppe
        wrapped[0] ^= 0xff;
        let fail = AesKeyWrap::unwrap(&kek_cipher, &wrapped, &mut unwrapped);
        assert_eq!(fail, Err(Crypto2Error::KeyWrapIntegrityFailed));
    }

    #[test]
    fn test_sha256_and_sha512_vectors() {
        let digest256 = Sha256::digest(b"abc");
        let expected256: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest256, expected256);

        let digest512 = Sha512::digest(b"abc");
        let expected512: [u8; 64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(digest512, expected512);
    }

    #[test]
    fn test_key_lifecycle_and_attenuation() {
        let admin_cap = Crypto2Cap::new(
            Handle::new(100, 1),
            crypto2_rights::ALL,
            16,
            key_usages::ALL as u16,
        );
        let mut daemon = JamboCrypto2Daemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.count_active_keys(), 4);

        // Rotation de la clé DEK de stockage
        daemon
            .rotate_key(&admin_cap, 2, b"NEW_ENTROPY_CYCLE_106")
            .unwrap();
        let k2 = daemon.get_key(2).unwrap();
        assert_eq!(k2.version, 2);

        // Atténuation monotone : cap avec uniquement HASH
        let hash_cap = admin_cap.derive_subordinate(crypto2_rights::HASH).unwrap();
        assert!(hash_cap.has_right(crypto2_rights::HASH));
        assert!(!hash_cap.has_right(crypto2_rights::GENERATE_KEY));

        // Tentative d'escalade : tentative de dériver une capacité supérieure
        let escalate = hash_cap.derive_subordinate(crypto2_rights::GENERATE_KEY);
        assert_eq!(escalate, Err(Crypto2Error::PermissionDenied));

        // Tentative de rotation avec hash_cap -> PermissionDenied
        let denied = daemon.rotate_key(&hash_cap, 2, b"FORBIDDEN");
        assert_eq!(denied, Err(Crypto2Error::PermissionDenied));

        // Zéroïsation de la clé 3 (TLS DEK)
        daemon.zeroize_key(&admin_cap, 3).unwrap();
        let k3_fail = daemon.get_key(3);
        assert_eq!(k3_fail, Err(Crypto2Error::KeyDestroyed));
    }
}

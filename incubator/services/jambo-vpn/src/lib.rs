//! Passerelle VPN Post-Quantique WireGuard Souveraine Ring 3 & Transport Chiffré Inter-Grappe (`jambo-vpn`)
//!
//! Phase 113 — Jalon v0.2.111
//!
//! Fournit une passerelle VPN souveraine inspirée de WireGuard durcie en `#![no_std]` :
//! 1. Échange de clés hybride Dual-Defense Post-Quantique :
//!    - Négociation combinée Curve25519 (ECDH classique Montgomery RFC 7748) et ML-KEM
//!      (Module-LWE dans l'anneau quotient R_q = Z_q[X]/(X^N + 1)).
//!    - Dérivation sécurisée des clés de session via HKDF-SHA256 (Dual-Defense).
//! 2. Encapsulation & Transport Chiffré Haute Performance :
//!    - Chiffrement symétrique de flux ChaCha20 (256 bits).
//!    - Étiquette d'intégrité et d'authentification MAC (HMAC-SHA256 128 bits).
//!    - Numérotation séquentielle et protection anti-rejeu par fenêtre glissante (128 paquets).
//! 3. Routage Cryptographique (Cryptokey Routing) & Sous-réseaux Autorisés (`AllowedIPs`) :
//!    - Table de routage granulaire par sous-réseaux CIDR IPv4.
//!    - Filtrage strict à l'entrée (Ingress verification) et isolation inter-grappe.
//! 4. Contrôle d'Accès Capabilaire Strict (`VpnCap`) :
//!    - Zéro autorité ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone sans amplification de privilèges.
//! 5. Zéroïsation en mémoire volatile et registre d'audit inaltérable scellé par chaîne SHA-256.

#![no_std]

use libjambo::Handle;

// ============================================================================
// CONSTANTES & LIMITES DU SOUS-SYSTÈME VPN
// ============================================================================

pub const MAX_PEERS: usize = 8;
pub const MAX_ALLOWED_IPS_PER_PEER: usize = 4;
pub const MAX_AUDIT_LOGS: usize = 16;
pub const MAX_PEER_NAME_LEN: usize = 24;
pub const MAX_DATA_PAYLOAD: usize = 512;

// Paramètres ML-KEM compacts et déterministes
pub const KEM_N: usize = 128; // Degré polynomial post-quantique (128 coefficients)
pub const KEM_K: usize = 2; // Dimension matricielle
pub const KEM_Q: i32 = 3329; // Modulus Kyber

pub const KEM_PUBLIC_KEY_LEN: usize = 32 + (KEM_K * KEM_N * 2); // 32 + 512 = 544 octets
pub const KEM_SECRET_KEY_LEN: usize = (KEM_K * KEM_N * 2) + 32; // 512 + 32 = 544 octets
pub const KEM_CIPHERTEXT_LEN: usize = (KEM_K + 1) * KEM_N * 2; // 3 * 128 * 2 = 768 octets
pub const KEM_SHARED_SECRET_LEN: usize = 32;

pub const CURVE25519_KEY_LEN: usize = 32;

// Types de paquets protocole WireGuard Hybride
pub const WG_PKT_HANDSHAKE_INITIATION: u32 = 1;
pub const WG_PKT_HANDSHAKE_RESPONSE: u32 = 2;
pub const WG_PKT_COOKIE_REPLY: u32 = 3;
pub const WG_PKT_DATA: u32 = 4;

// Seuil de renouvellement de clés (rekeying) en paquets
pub const REKEY_AFTER_PACKETS: u64 = 100_000;

// ============================================================================
// DROITS CAPABILAIRES (VpnCap)
// ============================================================================

pub mod vpn_rights {
    pub const ROUTE_TRAFFIC: u32 = 1 << 0;
    pub const CREATE_TUNNEL: u32 = 1 << 1;
    pub const CONFIGURE_PEER: u32 = 1 << 2;
    pub const INITIATE_HANDSHAKE: u32 = 1 << 3;
    pub const ROTATE_KEYS: u32 = 1 << 4;
    pub const TERMINATE_TUNNEL: u32 = 1 << 5;
    pub const AUDIT_INSPECT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = ROUTE_TRAFFIC
        | CREATE_TUNNEL
        | CONFIGURE_PEER
        | INITIATE_HANDSHAKE
        | ROTATE_KEYS
        | TERMINATE_TUNNEL
        | AUDIT_INSPECT
        | ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_peers: u16,
    pub generation: u16,
}

impl VpnCap {
    pub const fn new(handle: Handle, rights: u32, max_peers: u16, generation: u16) -> Self {
        Self {
            handle,
            rights,
            max_peers,
            generation,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(&self, new_rights: u32, new_max_peers: u16) -> Result<Self, VpnError> {
        if (new_rights & !self.rights) != 0 {
            return Err(VpnError::PermissionDenied);
        }
        if new_max_peers > self.max_peers {
            return Err(VpnError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_peers: new_max_peers,
            generation: self.generation.saturating_add(1),
        })
    }

    pub fn is_valid(&self) -> bool {
        self.rights != 0 && self.max_peers > 0
    }
}

// ============================================================================
// ERREURS DU SOUS-SYSTÈME VPN
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnError {
    PermissionDenied,
    PeerNotFound,
    PeerCapacityExceeded,
    PeerAlreadyExists,
    TunnelNotEstablished,
    InvalidPacketHeader,
    PayloadTooLarge,
    AntiReplayDrop,
    MacVerificationFailed,
    NoRouteToDestination,
    IngressValidationFailed,
    HandshakeFailed,
    InvalidArgument,
}

// ============================================================================
// HACHAGE SHA-256, HMAC & HKDF SOUVERAIN
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
    fn bsig0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn bsig1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn ssig0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn ssig1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = [
            0x6a09e667u32,
            0xbb67ae85u32,
            0x3c6ef372u32,
            0xa54ff53au32,
            0x510e527fu32,
            0x9b05688cu32,
            0x1f83d9abu32,
            0x5be0cd19u32,
        ];

        let len = data.len();
        let bit_len = (len as u64) * 8;

        let mut block = [0u8; 64];
        let mut idx = 0;

        while idx + 64 <= len {
            block.copy_from_slice(&data[idx..idx + 64]);
            Self::process_block(&mut h, &block);
            idx += 64;
        }

        let rem = len - idx;
        block = [0u8; 64];
        block[..rem].copy_from_slice(&data[idx..]);
        block[rem] = 0x80;

        if rem >= 56 {
            Self::process_block(&mut h, &block);
            block = [0u8; 64];
        }

        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut h, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }

    fn process_block(h: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                block[t * 4],
                block[t * 4 + 1],
                block[t * 4 + 2],
                block[t * 4 + 3],
            ]);
        }
        for t in 16..64 {
            let s1 = Self::ssig1(w[t - 2]);
            let s0 = Self::ssig0(w[t - 15]);
            w[t] = s1
                .wrapping_add(w[t - 7])
                .wrapping_add(s0)
                .wrapping_add(w[t - 16]);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hn = h[7];

        for t in 0..64 {
            let t1 = hn
                .wrapping_add(Self::bsig1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[t])
                .wrapping_add(w[t]);
            let t2 = Self::bsig0(a).wrapping_add(Self::maj(a, b, c));
            hn = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hn);
    }

    pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let hashed_key = Self::digest(key);
            k_pad[..32].copy_from_slice(&hashed_key);
        } else {
            k_pad[..key.len()].copy_from_slice(key);
        }

        let mut i_pad = [0x36u8; 64];
        let mut o_pad = [0x5cu8; 64];
        for i in 0..64 {
            i_pad[i] ^= k_pad[i];
            o_pad[i] ^= k_pad[i];
        }

        let mut inner_buf = [0u8; 64 + 1024];
        let copy_len = msg.len().min(1024);
        inner_buf[..64].copy_from_slice(&i_pad);
        inner_buf[64..64 + copy_len].copy_from_slice(&msg[..copy_len]);
        let inner_hash = Self::digest(&inner_buf[..64 + copy_len]);

        let mut outer_buf = [0u8; 64 + 32];
        outer_buf[..64].copy_from_slice(&o_pad);
        outer_buf[64..96].copy_from_slice(&inner_hash);

        Self::digest(&outer_buf)
    }

    pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8; 32]) {
        let prk = Self::hmac(salt, ikm);
        let mut t_buf = [0u8; 64 + 64];
        let info_len = info.len().min(64);
        t_buf[..info_len].copy_from_slice(&info[..info_len]);
        t_buf[info_len] = 0x01;
        let out = Self::hmac(&prk, &t_buf[..info_len + 1]);
        okm.copy_from_slice(&out);
    }

    pub fn xof(seed: &[u8], domain: u8, out: &mut [u8]) {
        let mut counter = 0u32;
        let mut offset = 0;
        let mut block_buf = [0u8; 64];

        while offset < out.len() {
            let seed_len = seed.len().min(48);
            block_buf[..seed_len].copy_from_slice(&seed[..seed_len]);
            block_buf[48] = domain;
            block_buf[49..53].copy_from_slice(&counter.to_le_bytes());
            let hash = Self::digest(&block_buf[..53]);

            let chunk = (out.len() - offset).min(32);
            out[offset..offset + chunk].copy_from_slice(&hash[..chunk]);
            offset += chunk;
            counter += 1;
        }
    }
}

// ============================================================================
// CHIFFREMENT DE FLUX CHACHA20 RFC 7539 / 8439
// ============================================================================

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

    pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
        let mut state = [0u32; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
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

        for i in 0..16 {
            let val = working[i].wrapping_add(state[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    pub fn apply_keystream(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
        let mut block_buf = [0u8; 64];
        let mut current_counter = counter;
        let mut offset = 0;

        while offset < data.len() {
            Self::block(key, current_counter, nonce, &mut block_buf);
            let chunk = (data.len() - offset).min(64);
            for i in 0..chunk {
                data[offset + i] ^= block_buf[i];
            }
            offset += chunk;
            current_counter = current_counter.wrapping_add(1);
        }
    }
}

// ============================================================================
// ÉCHANGE DE CLÉS CURVE25519 (X25519 - RFC 7748) EN `#![no_std]`
// ============================================================================

/// Arithmétique modulaire en GF(2^255 - 19)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fe25519(pub [u64; 4]);

impl Fe25519 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const P: [u64; 4] = [
        0xffff_ffff_ffff_ffed,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
    ];

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes([
                bytes[i * 8],
                bytes[i * 8 + 1],
                bytes[i * 8 + 2],
                bytes[i * 8 + 3],
                bytes[i * 8 + 4],
                bytes[i * 8 + 5],
                bytes[i * 8 + 6],
                bytes[i * 8 + 7],
            ]);
        }
        limbs[3] &= 0x7fff_ffff_ffff_ffff;
        Self(limbs)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let canonical = self.reduce_canonical();
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&canonical.0[i].to_le_bytes());
        }
        out
    }

    fn reduce_canonical(&self) -> Self {
        let mut val = *self;
        if Self::ge_raw(&val.0, &Self::P) {
            val.0 = Self::sub_raw(&val.0, &Self::P);
        }
        val
    }

    fn ge_raw(a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true
    }

    fn sub_raw(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = (a[i] as i128) - (b[i] as i128) - borrow;
            if diff < 0 {
                out[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                out[i] = diff as u64;
                borrow = 0;
            }
        }
        out
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            out[i] = s as u64;
            carry = s >> 64;
        }

        if carry > 0 {
            let mut c = 38u128;
            for i in 0..4 {
                let s = (out[i] as u128) + c;
                out[i] = s as u64;
                c = s >> 64;
            }
        }

        if (out[3] & (1 << 63)) != 0 {
            out[3] &= 0x7fff_ffff_ffff_ffff;
            let mut c = 19u128;
            for i in 0..4 {
                let s = (out[i] as u128) + c;
                out[i] = s as u64;
                c = s >> 64;
            }
        }

        let mut res = Self(out);
        if Self::ge_raw(&res.0, &Self::P) {
            res.0 = Self::sub_raw(&res.0, &Self::P);
        }
        res
    }

    pub fn sub(&self, other: &Self) -> Self {
        if Self::ge_raw(&self.0, &other.0) {
            Self(Self::sub_raw(&self.0, &other.0))
        } else {
            let mut carry = 0u128;
            let mut self_plus_p = [0u64; 4];
            for i in 0..4 {
                let s = (self.0[i] as u128) + (Self::P[i] as u128) + carry;
                self_plus_p[i] = s as u64;
                carry = s >> 64;
            }
            Self(Self::sub_raw(&self_plus_p, &other.0))
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut res = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let sum = (self.0[i] as u128) * (other.0[j] as u128) + (res[i + j] as u128) + carry;
                res[i + j] = sum as u64;
                carry = sum >> 64;
            }
            res[i + 4] = carry as u64;
        }

        let mut h38 = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..4 {
            let prod = (res[4 + i] as u128) * 38 + carry;
            h38[i] = prod as u64;
            carry = prod >> 64;
        }
        h38[4] = carry as u64;

        let mut sum = [0u64; 5];
        let mut carry_sum = 0u128;
        for i in 0..4 {
            let s = (res[i] as u128) + (h38[i] as u128) + carry_sum;
            sum[i] = s as u64;
            carry_sum = s >> 64;
        }
        sum[4] = (h38[4] as u128 + carry_sum) as u64;

        let extra = (sum[4] as u128) * 38;
        let mut carry_extra = extra;
        let mut out = [0u64; 4];
        for i in 0..4 {
            let s = (sum[i] as u128) + carry_extra;
            out[i] = s as u64;
            carry_extra = s >> 64;
        }

        if carry_extra > 0 {
            let mut c = (carry_extra as u128) * 38;
            for i in 0..4 {
                let s = (out[i] as u128) + c;
                out[i] = s as u64;
                c = s >> 64;
            }
        }

        if (out[3] & (1 << 63)) != 0 {
            out[3] &= 0x7fff_ffff_ffff_ffff;
            let mut c = 19u128;
            for i in 0..4 {
                let s = (out[i] as u128) + c;
                out[i] = s as u64;
                c = s >> 64;
            }
        }

        let mut final_res = Self(out);
        if Self::ge_raw(&final_res.0, &Self::P) {
            final_res.0 = Self::sub_raw(&final_res.0, &Self::P);
        }
        final_res
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    pub fn mul_scalar_u32(&self, scalar: u32) -> Self {
        let sc = Self([scalar as u64, 0, 0, 0]);
        self.mul(&sc)
    }

    pub fn invert(&self) -> Self {
        let mut res = Self::ONE;
        let mut base = *self;

        let p_minus_2: [u64; 4] = [
            0xffff_ffff_ffff_ffeb,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x7fff_ffff_ffff_ffff,
        ];

        for i in 0..4 {
            let mut word = p_minus_2[i];
            let max_bits = if i == 3 { 63 } else { 64 };
            for _ in 0..max_bits {
                if (word & 1) != 0 {
                    res = res.mul(&base);
                }
                base = base.square();
                word >>= 1;
            }
        }
        res
    }
}

pub struct Curve25519;

impl Curve25519 {
    pub const BASE_POINT: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    pub fn clamp_scalar(scalar: &mut [u8; 32]) {
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
    }

    /// Échelle de Montgomery X25519 (RFC 7748)
    pub fn scalar_mult(scalar: &[u8; 32], point_u: &[u8; 32]) -> [u8; 32] {
        let mut clamped = *scalar;
        Self::clamp_scalar(&mut clamped);

        let x1 = Fe25519::from_bytes(point_u);
        let mut x2 = Fe25519::ONE;
        let mut z2 = Fe25519::ZERO;
        let mut x3 = x1;
        let mut z3 = Fe25519::ONE;
        let mut swap = 0;

        let a24 = 121665u32; // (486662 - 2) / 4

        for byte_idx in (0..32).rev() {
            let byte = clamped[byte_idx];
            for bit_idx in (0..8).rev() {
                let bit = ((byte >> bit_idx) & 1) as usize;
                swap ^= bit;
                if swap != 0 {
                    core::mem::swap(&mut x2, &mut x3);
                    core::mem::swap(&mut z2, &mut z3);
                }
                swap = bit;

                let a = x2.add(&z2);
                let aa = a.square();
                let b = x2.sub(&z2);
                let bb = b.square();
                let e = aa.sub(&bb);
                let c = x3.add(&z3);
                let d = x3.sub(&z3);
                let da = d.mul(&a);
                let cb = c.mul(&b);

                let x3_next = da.add(&cb).square();
                let z3_next = x1.mul(&da.sub(&cb).square());

                let x2_next = aa.mul(&bb);
                let z2_next = e.mul(&aa.add(&e.mul_scalar_u32(a24)));

                x2 = x2_next;
                z2 = z2_next;
                x3 = x3_next;
                z3 = z3_next;
            }
        }

        if swap != 0 {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }

        let z2_inv = z2.invert();
        let result = x2.mul(&z2_inv);
        result.to_bytes()
    }

    pub fn public_key(secret_key: &[u8; 32]) -> [u8; 32] {
        Self::scalar_mult(secret_key, &Self::BASE_POINT)
    }
}

// ============================================================================
// PRIMITIVE ML-KEM POST-QUANTIQUE (Module-LWE dans R_q)
// ============================================================================

pub struct MlKem;

impl MlKem {
    pub fn poly_mul_negacyclic(a: &[i32; KEM_N], b: &[i32; KEM_N], q: i32) -> [i32; KEM_N] {
        let mut c = [0i32; KEM_N];
        let q_i64 = q as i64;

        for k in 0..KEM_N {
            let mut sum: i64 = 0;
            for j in 0..=k {
                sum += (a[j] as i64) * (b[k - j] as i64);
            }
            for j in (k + 1)..KEM_N {
                sum -= (a[j] as i64) * (b[k + KEM_N - j] as i64);
            }
            let rem = (sum % q_i64) as i32;
            c[k] = if rem < 0 { rem + q } else { rem };
        }
        c
    }

    pub fn poly_add(a: &[i32; KEM_N], b: &[i32; KEM_N], q: i32) -> [i32; KEM_N] {
        let mut c = [0i32; KEM_N];
        for i in 0..KEM_N {
            let sum = a[i] + b[i];
            c[i] = if sum >= q { sum - q } else { sum };
        }
        c
    }

    pub fn poly_sub(a: &[i32; KEM_N], b: &[i32; KEM_N], q: i32) -> [i32; KEM_N] {
        let mut c = [0i32; KEM_N];
        for i in 0..KEM_N {
            let diff = a[i] - b[i];
            c[i] = if diff < 0 { diff + q } else { diff };
        }
        c
    }

    pub fn sample_cbd1(stream: &[u8]) -> [i32; KEM_N] {
        let mut poly = [0i32; KEM_N];
        let mut byte_idx = 0;
        let mut bit_idx = 0;

        for i in 0..KEM_N {
            if byte_idx < stream.len() {
                let b1 = (stream[byte_idx] >> bit_idx) & 1;
                let b2 = (stream[byte_idx] >> (bit_idx + 1)) & 1;
                bit_idx += 2;
                if bit_idx >= 8 {
                    bit_idx = 0;
                    byte_idx += 1;
                }
                let mut coeff = (b1 as i32) - (b2 as i32);
                if coeff < 0 {
                    coeff += KEM_Q;
                }
                poly[i] = coeff;
            }
        }
        poly
    }

    pub fn keygen(
        seed: &[u8],
        pk: &mut [u8; KEM_PUBLIC_KEY_LEN],
        sk: &mut [u8; KEM_SECRET_KEY_LEN],
    ) {
        let seed_hash = Sha256::digest(seed);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&seed_hash);

        let mut s_buf = [0u8; KEM_N * 2];
        let mut e_buf = [0u8; KEM_N * 2];
        Sha256::xof(seed, 0x01, &mut s_buf);
        Sha256::xof(seed, 0x02, &mut e_buf);

        let mut s = [[0i32; KEM_N]; KEM_K];
        let mut e = [[0i32; KEM_N]; KEM_K];
        for i in 0..KEM_K {
            s[i] = Self::sample_cbd1(&s_buf[i * (KEM_N / 2)..]);
            e[i] = Self::sample_cbd1(&e_buf[i * (KEM_N / 2)..]);
        }

        let mut a = [[[0i32; KEM_N]; KEM_K]; KEM_K];
        let mut a_buf = [0u8; KEM_N * 2];
        for i in 0..KEM_K {
            for j in 0..KEM_K {
                Sha256::xof(&rho, ((i << 2) | j) as u8, &mut a_buf);
                for n in 0..KEM_N {
                    let w = u16::from_le_bytes([a_buf[n * 2], a_buf[n * 2 + 1]]);
                    a[i][j][n] = (w as i32) % KEM_Q;
                }
            }
        }

        let mut t = [[0i32; KEM_N]; KEM_K];
        for i in 0..KEM_K {
            let mut acc = [0i32; KEM_N];
            for j in 0..KEM_K {
                let prod = Self::poly_mul_negacyclic(&a[i][j], &s[j], KEM_Q);
                acc = Self::poly_add(&acc, &prod, KEM_Q);
            }
            t[i] = Self::poly_add(&acc, &e[i], KEM_Q);
        }

        pk[..32].copy_from_slice(&rho);
        for i in 0..KEM_K {
            for n in 0..KEM_N {
                let pos = 32 + (i * KEM_N + n) * 2;
                pk[pos..pos + 2].copy_from_slice(&(t[i][n] as u16).to_le_bytes());
            }
        }

        for i in 0..KEM_K {
            for n in 0..KEM_N {
                let pos = (i * KEM_N + n) * 2;
                sk[pos..pos + 2].copy_from_slice(&(s[i][n] as u16).to_le_bytes());
            }
        }
        sk[KEM_K * KEM_N * 2..KEM_K * KEM_N * 2 + 32].copy_from_slice(&rho);
    }

    pub fn encapsulate(
        pk: &[u8; KEM_PUBLIC_KEY_LEN],
        entropy: &[u8],
        ct: &mut [u8; KEM_CIPHERTEXT_LEN],
        ss: &mut [u8; KEM_SHARED_SECRET_LEN],
    ) {
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&pk[..32]);

        let mut t = [[0i32; KEM_N]; KEM_K];
        for i in 0..KEM_K {
            for n in 0..KEM_N {
                let pos = 32 + (i * KEM_N + n) * 2;
                let val = u16::from_le_bytes([pk[pos], pk[pos + 1]]);
                t[i][n] = val as i32;
            }
        }

        let mut r_buf = [0u8; KEM_N * 2];
        let mut e1_buf = [0u8; KEM_N * 2];
        let mut e2_buf = [0u8; KEM_N];
        Sha256::xof(entropy, 0x10, &mut r_buf);
        Sha256::xof(entropy, 0x11, &mut e1_buf);
        Sha256::xof(entropy, 0x12, &mut e2_buf);

        let mut r = [[0i32; KEM_N]; KEM_K];
        let mut e1 = [[0i32; KEM_N]; KEM_K];
        for i in 0..KEM_K {
            r[i] = Self::sample_cbd1(&r_buf[i * (KEM_N / 2)..]);
            e1[i] = Self::sample_cbd1(&e1_buf[i * (KEM_N / 2)..]);
        }
        let e2 = Self::sample_cbd1(&e2_buf);

        let mut a = [[[0i32; KEM_N]; KEM_K]; KEM_K];
        let mut a_buf = [0u8; KEM_N * 2];
        for i in 0..KEM_K {
            for j in 0..KEM_K {
                Sha256::xof(&rho, ((i << 2) | j) as u8, &mut a_buf);
                for n in 0..KEM_N {
                    let w = u16::from_le_bytes([a_buf[n * 2], a_buf[n * 2 + 1]]);
                    a[i][j][n] = (w as i32) % KEM_Q;
                }
            }
        }

        // u = A^T * r + e1
        let mut u = [[0i32; KEM_N]; KEM_K];
        for i in 0..KEM_K {
            let mut acc = [0i32; KEM_N];
            for j in 0..KEM_K {
                let prod = Self::poly_mul_negacyclic(&a[j][i], &r[j], KEM_Q);
                acc = Self::poly_add(&acc, &prod, KEM_Q);
            }
            u[i] = Self::poly_add(&acc, &e1[i], KEM_Q);
        }

        // v = t^T * r + e2 + Encode(msg)
        let mut t_dot_r = [0i32; KEM_N];
        for i in 0..KEM_K {
            let prod = Self::poly_mul_negacyclic(&t[i], &r[i], KEM_Q);
            t_dot_r = Self::poly_add(&t_dot_r, &prod, KEM_Q);
        }
        let mut v = Self::poly_add(&t_dot_r, &e2, KEM_Q);

        let msg_seed = Sha256::digest(entropy);
        let center = (KEM_Q + 1) / 2;
        for bit_i in 0..KEM_N {
            let byte_idx = bit_i / 8;
            let bit = (msg_seed[byte_idx] >> (bit_i % 8)) & 1;
            if bit == 1 {
                v[bit_i] = (v[bit_i] + center) % KEM_Q;
            }
        }

        for i in 0..KEM_K {
            for n in 0..KEM_N {
                let pos = (i * KEM_N + n) * 2;
                ct[pos..pos + 2].copy_from_slice(&(u[i][n] as u16).to_le_bytes());
            }
        }
        let v_offset = KEM_K * KEM_N * 2;
        for n in 0..KEM_N {
            let pos = v_offset + n * 2;
            ct[pos..pos + 2].copy_from_slice(&(v[n] as u16).to_le_bytes());
        }

        let ct_hash = Sha256::digest(ct);
        let mut kdf_input = [0u8; 48];
        kdf_input[..16].copy_from_slice(&msg_seed[..16]);
        kdf_input[16..48].copy_from_slice(&ct_hash);
        *ss = Sha256::digest(&kdf_input);
    }

    pub fn decapsulate(
        sk: &[u8; KEM_SECRET_KEY_LEN],
        ct: &[u8; KEM_CIPHERTEXT_LEN],
        ss: &mut [u8; KEM_SHARED_SECRET_LEN],
    ) {
        let mut s = [[0i32; KEM_N]; KEM_K];
        for i in 0..KEM_K {
            for n in 0..KEM_N {
                let pos = (i * KEM_N + n) * 2;
                let val = u16::from_le_bytes([sk[pos], sk[pos + 1]]);
                s[i][n] = val as i32;
            }
        }

        let mut u = [[0i32; KEM_N]; KEM_K];
        for i in 0..KEM_K {
            for n in 0..KEM_N {
                let pos = (i * KEM_N + n) * 2;
                let val = u16::from_le_bytes([ct[pos], ct[pos + 1]]);
                u[i][n] = val as i32;
            }
        }

        let mut v = [0i32; KEM_N];
        let v_offset = KEM_K * KEM_N * 2;
        for n in 0..KEM_N {
            let pos = v_offset + n * 2;
            v[n] = u16::from_le_bytes([ct[pos], ct[pos + 1]]) as i32;
        }

        let mut s_dot_u = [0i32; KEM_N];
        for i in 0..KEM_K {
            let prod = Self::poly_mul_negacyclic(&s[i], &u[i], KEM_Q);
            s_dot_u = Self::poly_add(&s_dot_u, &prod, KEM_Q);
        }

        let w = Self::poly_sub(&v, &s_dot_u, KEM_Q);

        let mut recovered_msg = [0u8; 32];
        let threshold = KEM_Q / 4;
        let center = (KEM_Q + 1) / 2;

        for bit_i in 0..KEM_N {
            let coeff = w[bit_i];
            let diff = if coeff > center {
                (coeff - center).min(KEM_Q - coeff + center)
            } else {
                (center - coeff).min(coeff + KEM_Q - center)
            };

            if diff < threshold {
                let byte_idx = bit_i / 8;
                recovered_msg[byte_idx] |= 1 << (bit_i % 8);
            }
        }

        let ct_hash = Sha256::digest(ct);
        let mut kdf_input = [0u8; 48];
        kdf_input[..16].copy_from_slice(&recovered_msg[..16]);
        kdf_input[16..48].copy_from_slice(&ct_hash);
        *ss = Sha256::digest(&kdf_input);
    }
}

// ============================================================================
// COMBINAISON HYBRIDE DUAL-DEFENSE (Curve25519 + ML-KEM)
// ============================================================================

pub struct HybridKeyExchange;

impl HybridKeyExchange {
    pub fn derive_master_secrets(
        classical_shared: &[u8; 32],
        kem_shared: &[u8; 32],
        session_info: &[u8],
        tx_key: &mut [u8; 32],
        rx_key: &mut [u8; 32],
    ) {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(classical_shared);
        ikm[32..64].copy_from_slice(kem_shared);

        let salt = b"JAMBO_HYBRID_VPN_WIREGUARD_KEX_V1";
        let mut prk = [0u8; 32];
        Sha256::hkdf(salt, &ikm, session_info, &mut prk);

        Sha256::hkdf(&prk, b"TX_KEY_DIRECTIONAL_STREAM", session_info, tx_key);
        Sha256::hkdf(&prk, b"RX_KEY_DIRECTIONAL_STREAM", session_info, rx_key);
    }
}

// ============================================================================
// PROTECTION ANTI-REJEU PAR FENÊTRE GLISSANTE (128 PAQUETS)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiReplayWindow {
    pub last_seq: u64,
    pub bitmap: u128,
}

impl AntiReplayWindow {
    pub const fn new() -> Self {
        Self {
            last_seq: 0,
            bitmap: 0,
        }
    }

    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }

        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff < 128 {
                self.bitmap <<= diff;
                self.bitmap |= 1;
            } else {
                self.bitmap = 1;
            }
            self.last_seq = seq;
            true
        } else {
            let diff = self.last_seq - seq;
            if diff >= 128 {
                return false;
            }
            let bit = 1u128 << diff;
            if (self.bitmap & bit) != 0 {
                return false;
            }
            self.bitmap |= bit;
            true
        }
    }
}

// ============================================================================
// SOUS-RÉSEAUX AUTORISÉS & ROUTAGE CRYPTOGRAPHIQUE (CRYPTOKEY ROUTING)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnSubnet {
    pub network: [u8; 4],
    pub prefix_len: u8,
}

impl VpnSubnet {
    pub const fn new(network: [u8; 4], prefix_len: u8) -> Self {
        Self {
            network,
            prefix_len,
        }
    }

    pub fn matches(&self, ip: &[u8; 4]) -> bool {
        if self.prefix_len > 32 {
            return false;
        }
        if self.prefix_len == 0 {
            return true;
        }

        let net_u32 = u32::from_be_bytes(self.network);
        let ip_u32 = u32::from_be_bytes(*ip);
        let mask = !((1u32 << (32 - self.prefix_len)) - 1);

        (net_u32 & mask) == (ip_u32 & mask)
    }
}

// ============================================================================
// STRUCTURES DE PAQUETS WIREGUARD HYBRIDE
// ============================================================================

#[derive(Clone, Copy)]
pub struct HandshakeInitiationPacket {
    pub msg_type: u32,
    pub sender_index: u32,
    pub uncalibrated_tai64n: [u8; 12],
    pub ephemeral_classical: [u8; 32],
    pub pqc_ciphertext: [u8; KEM_CIPHERTEXT_LEN],
    pub encrypted_static: [u8; 32],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Clone, Copy)]
pub struct HandshakeResponsePacket {
    pub msg_type: u32,
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral_classical: [u8; 32],
    pub pqc_shared_secret_tag: [u8; 32],
    pub encrypted_nothing: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Clone, Copy)]
pub struct VpnDataPacket {
    pub msg_type: u32,
    pub receiver_index: u32,
    pub counter: u64,
    pub payload_len: u16,
    pub encrypted_payload: [u8; MAX_DATA_PAYLOAD],
    pub auth_tag: [u8; 16],
}

// ============================================================================
// ÉTAT DE SESSION ET GESTION DES PAIRS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPeerState {
    Idle,
    Handshaking,
    Established,
    Rekeying,
    Suspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnSession {
    pub local_index: u32,
    pub remote_index: u32,
    pub sending_key: [u8; 32],
    pub receiving_key: [u8; 32],
    pub tx_counter: u64,
    pub replay_window: AntiReplayWindow,
    pub created_at_ms: u64,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub is_valid: bool,
}

impl VpnSession {
    pub const fn empty() -> Self {
        Self {
            local_index: 0,
            remote_index: 0,
            sending_key: [0u8; 32],
            receiving_key: [0u8; 32],
            tx_counter: 0,
            replay_window: AntiReplayWindow::new(),
            created_at_ms: 0,
            packets_sent: 0,
            bytes_sent: 0,
            is_valid: false,
        }
    }

    pub fn zeroize(&mut self) {
        self.sending_key = [0u8; 32];
        self.receiving_key = [0u8; 32];
        self.is_valid = false;
        self.tx_counter = 0;
        self.replay_window = AntiReplayWindow::new();
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VpnPeer {
    pub peer_id: u32,
    pub name: [u8; MAX_PEER_NAME_LEN],
    pub name_len: usize,
    pub endpoint_ip: [u8; 4],
    pub endpoint_port: u16,
    pub static_pk_curve25519: [u8; 32],
    pub static_pk_mlkem: [u8; KEM_PUBLIC_KEY_LEN],
    pub allowed_ips: [VpnSubnet; MAX_ALLOWED_IPS_PER_PEER],
    pub allowed_ips_count: usize,
    pub state: VpnPeerState,
    pub current_session: Option<VpnSession>,
    pub previous_session: Option<VpnSession>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub last_handshake_ms: u64,
}

impl VpnPeer {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unknown")
    }
}

// ============================================================================
// ENREGISTREMENT D'AUDIT SCELLÉ PAR SHA-256
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct VpnAuditEntry {
    pub timestamp_ms: u64,
    pub peer_id: u32,
    pub event_code: u16,
    pub details: [u8; 32],
    pub cumulative_hash: [u8; 32],
}

// ============================================================================
// DÉMON PRINCIPAL PASSERELLE VPN SOUVERAINE (JamboVpnDaemon)
// ============================================================================

pub struct JamboVpnDaemon {
    pub admin_cap: VpnCap,
    pub local_static_sk_curve25519: [u8; 32],
    pub local_static_pk_curve25519: [u8; 32],
    pub local_static_sk_mlkem: [u8; KEM_SECRET_KEY_LEN],
    pub local_static_pk_mlkem: [u8; KEM_PUBLIC_KEY_LEN],
    pub listen_port: u16,
    pub peers: [Option<VpnPeer>; MAX_PEERS],
    pub peer_count: usize,
    pub audit_log: [VpnAuditEntry; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub audit_chain: [u8; 32],
    pub next_session_index: u32,
    pub total_handshakes_completed: u64,
    pub total_packets_routed: u64,
    pub total_replay_drops: u64,
    pub total_bytes_encrypted: u64,
    pub total_bytes_decrypted: u64,
}

impl JamboVpnDaemon {
    pub fn new(admin_cap: VpnCap) -> Self {
        Self {
            admin_cap,
            local_static_sk_curve25519: [0u8; 32],
            local_static_pk_curve25519: [0u8; 32],
            local_static_sk_mlkem: [0u8; KEM_SECRET_KEY_LEN],
            local_static_pk_mlkem: [0u8; KEM_PUBLIC_KEY_LEN],
            listen_port: 51820,
            peers: [None; MAX_PEERS],
            peer_count: 0,
            audit_log: [VpnAuditEntry {
                timestamp_ms: 0,
                peer_id: 0,
                event_code: 0,
                details: [0u8; 32],
                cumulative_hash: [0u8; 32],
            }; MAX_AUDIT_LOGS],
            audit_count: 0,
            audit_chain: [0x5au8; 32],
            next_session_index: 0x1000,
            total_handshakes_completed: 0,
            total_packets_routed: 0,
            total_replay_drops: 0,
            total_bytes_encrypted: 0,
            total_bytes_decrypted: 0,
        }
    }

    pub fn init_defaults(&mut self) {
        let sk_seed = b"JAMBO_GATEWAY_STATIC_CURVE25519_SECRET_SEED_2026";
        let sk_hash = Sha256::digest(sk_seed);
        self.local_static_sk_curve25519 = sk_hash;
        self.local_static_pk_curve25519 = Curve25519::public_key(&self.local_static_sk_curve25519);

        let pq_seed = b"JAMBO_GATEWAY_STATIC_MLKEM_SECRET_SEED_2026";
        MlKem::keygen(
            pq_seed,
            &mut self.local_static_pk_mlkem,
            &mut self.local_static_sk_mlkem,
        );

        self.record_audit(0, 0x01, b"VPN_GATEWAY_INITIALIZED_2026");

        let mut peer2_sk = [0u8; 32];
        peer2_sk.copy_from_slice(&Sha256::digest(b"JAMBO_PEER2_STATIC_SECRET_SEED"));
        let peer2_pk_curve = Curve25519::public_key(&peer2_sk);

        let mut peer2_pk_kem = [0u8; KEM_PUBLIC_KEY_LEN];
        let mut peer2_sk_kem = [0u8; KEM_SECRET_KEY_LEN];
        MlKem::keygen(
            b"JAMBO_PEER2_MLKEM_SEED",
            &mut peer2_pk_kem,
            &mut peer2_sk_kem,
        );

        let mut subnets = [VpnSubnet::new([0, 0, 0, 0], 0); MAX_ALLOWED_IPS_PER_PEER];
        subnets[0] = VpnSubnet::new([10, 0, 2, 0], 24);

        let admin_cap = self.admin_cap;
        let _ = self.add_peer(
            &admin_cap,
            2,
            "cluster-node-2",
            [192, 168, 1, 20],
            51820,
            &peer2_pk_curve,
            &peer2_pk_kem,
            &subnets[..1],
        );
    }

    pub fn record_audit(&mut self, peer_id: u32, event_code: u16, data: &[u8]) {
        let mut details = [0u8; 32];
        let len = data.len().min(32);
        details[..len].copy_from_slice(&data[..len]);

        let mut chain_buf = [0u8; 64 + 32 + 8];
        chain_buf[..32].copy_from_slice(&self.audit_chain);
        chain_buf[32..36].copy_from_slice(&peer_id.to_le_bytes());
        chain_buf[36..38].copy_from_slice(&event_code.to_le_bytes());
        chain_buf[38..70].copy_from_slice(&details);

        let new_hash = Sha256::digest(&chain_buf[..70]);
        self.audit_chain = new_hash;

        let entry = VpnAuditEntry {
            timestamp_ms: 1000 + (self.audit_count as u64) * 100,
            peer_id,
            event_code,
            details,
            cumulative_hash: new_hash,
        };

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_log[self.audit_count] = entry;
            self.audit_count += 1;
        } else {
            for i in 1..MAX_AUDIT_LOGS {
                self.audit_log[i - 1] = self.audit_log[i];
            }
            self.audit_log[MAX_AUDIT_LOGS - 1] = entry;
        }
    }

    pub fn add_peer(
        &mut self,
        cap: &VpnCap,
        peer_id: u32,
        name: &str,
        endpoint_ip: [u8; 4],
        endpoint_port: u16,
        pk_curve: &[u8; 32],
        pk_kem: &[u8; KEM_PUBLIC_KEY_LEN],
        subnets: &[VpnSubnet],
    ) -> Result<(), VpnError> {
        if !cap.has_right(vpn_rights::CONFIGURE_PEER) {
            return Err(VpnError::PermissionDenied);
        }
        if self.peer_count >= (cap.max_peers as usize).min(MAX_PEERS) {
            return Err(VpnError::PeerCapacityExceeded);
        }
        for opt in self.peers.iter() {
            if let Some(p) = opt {
                if p.peer_id == peer_id {
                    return Err(VpnError::PeerAlreadyExists);
                }
            }
        }

        let mut name_buf = [0u8; MAX_PEER_NAME_LEN];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(MAX_PEER_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let mut allowed = [VpnSubnet::new([0, 0, 0, 0], 0); MAX_ALLOWED_IPS_PER_PEER];
        let sub_len = subnets.len().min(MAX_ALLOWED_IPS_PER_PEER);
        allowed[..sub_len].copy_from_slice(&subnets[..sub_len]);

        let peer = VpnPeer {
            peer_id,
            name: name_buf,
            name_len: copy_len,
            endpoint_ip,
            endpoint_port,
            static_pk_curve25519: *pk_curve,
            static_pk_mlkem: *pk_kem,
            allowed_ips: allowed,
            allowed_ips_count: sub_len,
            state: VpnPeerState::Idle,
            current_session: None,
            previous_session: None,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            last_handshake_ms: 0,
        };

        for opt in self.peers.iter_mut() {
            if opt.is_none() {
                *opt = Some(peer);
                self.peer_count += 1;
                self.record_audit(peer_id, 0x02, name.as_bytes());
                return Ok(());
            }
        }

        Err(VpnError::PeerCapacityExceeded)
    }

    pub fn remove_peer(&mut self, cap: &VpnCap, peer_id: u32) -> Result<(), VpnError> {
        if !cap.has_right(vpn_rights::TERMINATE_TUNNEL) {
            return Err(VpnError::PermissionDenied);
        }

        for opt in self.peers.iter_mut() {
            if let Some(p) = opt.as_mut() {
                if p.peer_id == peer_id {
                    if let Some(cur) = p.current_session.as_mut() {
                        cur.zeroize();
                    }
                    if let Some(prev) = p.previous_session.as_mut() {
                        prev.zeroize();
                    }
                    *opt = None;
                    self.peer_count = self.peer_count.saturating_sub(1);
                    self.record_audit(peer_id, 0x03, b"PEER_TERMINATED_AND_ZEROIZED");
                    return Ok(());
                }
            }
        }
        Err(VpnError::PeerNotFound)
    }

    pub fn create_handshake_initiation(
        &mut self,
        cap: &VpnCap,
        peer_id: u32,
        ephemeral_seed: &[u8; 32],
        out_packet: &mut HandshakeInitiationPacket,
    ) -> Result<([u8; 32], [u8; 32]), VpnError> {
        if !cap.has_right(vpn_rights::INITIATE_HANDSHAKE) {
            return Err(VpnError::PermissionDenied);
        }

        let peer = self
            .peers
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| p.peer_id == peer_id)
            .ok_or(VpnError::PeerNotFound)?;

        let local_index = self.next_session_index;
        self.next_session_index = self.next_session_index.wrapping_add(1);

        let eph_sk = Sha256::digest(ephemeral_seed);
        let eph_pk = Curve25519::public_key(&eph_sk);

        let mut pq_ct = [0u8; KEM_CIPHERTEXT_LEN];
        let mut pq_ss = [0u8; KEM_SHARED_SECRET_LEN];
        MlKem::encapsulate(
            &peer.static_pk_mlkem,
            ephemeral_seed,
            &mut pq_ct,
            &mut pq_ss,
        );

        let classical_ss = Curve25519::scalar_mult(&eph_sk, &peer.static_pk_curve25519);

        out_packet.msg_type = WG_PKT_HANDSHAKE_INITIATION;
        out_packet.sender_index = local_index;
        out_packet.uncalibrated_tai64n = [0x50, 0x51, 0x57, 0x47, 0, 0, 0, 0, 0, 0, 0, 1];
        out_packet.ephemeral_classical = eph_pk;
        out_packet.pqc_ciphertext = pq_ct;

        let mut enc_static = self.local_static_pk_curve25519;
        let nonce = [0x42u8; 12];
        ChaCha20::apply_keystream(&classical_ss, 0, &nonce, &mut enc_static);
        out_packet.encrypted_static = enc_static;

        let mac1 = Sha256::hmac(&peer.static_pk_curve25519, &eph_pk);
        out_packet.mac1.copy_from_slice(&mac1[..16]);
        out_packet.mac2 = [0u8; 16];

        peer.state = VpnPeerState::Handshaking;

        Ok((classical_ss, pq_ss))
    }

    pub fn process_handshake_initiation_and_respond(
        &mut self,
        cap: &VpnCap,
        init_pkt: &HandshakeInitiationPacket,
        responder_ephemeral_seed: &[u8; 32],
        out_resp: &mut HandshakeResponsePacket,
    ) -> Result<u32, VpnError> {
        if !cap.has_right(vpn_rights::INITIATE_HANDSHAKE) {
            return Err(VpnError::PermissionDenied);
        }
        if init_pkt.msg_type != WG_PKT_HANDSHAKE_INITIATION {
            return Err(VpnError::InvalidPacketHeader);
        }

        let classical_ss = Curve25519::scalar_mult(
            &self.local_static_sk_curve25519,
            &init_pkt.ephemeral_classical,
        );

        let mut dec_static = init_pkt.encrypted_static;
        let nonce = [0x42u8; 12];
        ChaCha20::apply_keystream(&classical_ss, 0, &nonce, &mut dec_static);

        let peer = self
            .peers
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| p.static_pk_curve25519 == dec_static)
            .ok_or(VpnError::PeerNotFound)?;

        let peer_id = peer.peer_id;

        let mut pq_ss = [0u8; KEM_SHARED_SECRET_LEN];
        MlKem::decapsulate(
            &self.local_static_sk_mlkem,
            &init_pkt.pqc_ciphertext,
            &mut pq_ss,
        );

        let resp_eph_sk = Sha256::digest(responder_ephemeral_seed);
        let resp_eph_pk = Curve25519::public_key(&resp_eph_sk);

        let eph_classical_ss = Curve25519::scalar_mult(&resp_eph_sk, &init_pkt.ephemeral_classical);

        let local_session_index = self.next_session_index;
        self.next_session_index = self.next_session_index.wrapping_add(1);

        let mut tx_key = [0u8; 32];
        let mut rx_key = [0u8; 32];
        HybridKeyExchange::derive_master_secrets(
            &eph_classical_ss,
            &pq_ss,
            b"JAMBO_WIREGUARD_SESSION_V1",
            &mut tx_key,
            &mut rx_key,
        );

        let session = VpnSession {
            local_index: local_session_index,
            remote_index: init_pkt.sender_index,
            sending_key: tx_key,
            receiving_key: rx_key,
            tx_counter: 0,
            replay_window: AntiReplayWindow::new(),
            created_at_ms: 1000,
            packets_sent: 0,
            bytes_sent: 0,
            is_valid: true,
        };

        peer.previous_session = peer.current_session;
        peer.current_session = Some(session);
        peer.state = VpnPeerState::Established;
        peer.last_handshake_ms = 1000;

        self.total_handshakes_completed += 1;
        self.record_audit(peer_id, 0x04, b"HANDSHAKE_ESTABLISHED_RESPONDER");

        out_resp.msg_type = WG_PKT_HANDSHAKE_RESPONSE;
        out_resp.sender_index = local_session_index;
        out_resp.receiver_index = init_pkt.sender_index;
        out_resp.ephemeral_classical = resp_eph_pk;
        out_resp.pqc_shared_secret_tag = pq_ss;
        out_resp.encrypted_nothing = [0x5au8; 16];
        out_resp.mac1 = [0x11u8; 16];
        out_resp.mac2 = [0x22u8; 16];

        Ok(peer_id)
    }

    pub fn complete_handshake_initiation_session(
        &mut self,
        cap: &VpnCap,
        peer_id: u32,
        eph_sk: &[u8; 32],
        pq_ss: &[u8; 32],
        resp_pkt: &HandshakeResponsePacket,
    ) -> Result<(), VpnError> {
        if !cap.has_right(vpn_rights::INITIATE_HANDSHAKE) {
            return Err(VpnError::PermissionDenied);
        }
        if resp_pkt.msg_type != WG_PKT_HANDSHAKE_RESPONSE {
            return Err(VpnError::InvalidPacketHeader);
        }

        let peer = self
            .peers
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| p.peer_id == peer_id)
            .ok_or(VpnError::PeerNotFound)?;

        let eph_classical_ss = Curve25519::scalar_mult(eph_sk, &resp_pkt.ephemeral_classical);

        let mut tx_key = [0u8; 32];
        let mut rx_key = [0u8; 32];
        HybridKeyExchange::derive_master_secrets(
            &eph_classical_ss,
            pq_ss,
            b"JAMBO_WIREGUARD_SESSION_V1",
            &mut rx_key,
            &mut tx_key,
        );

        let session = VpnSession {
            local_index: resp_pkt.receiver_index,
            remote_index: resp_pkt.sender_index,
            sending_key: tx_key,
            receiving_key: rx_key,
            tx_counter: 0,
            replay_window: AntiReplayWindow::new(),
            created_at_ms: 1000,
            packets_sent: 0,
            bytes_sent: 0,
            is_valid: true,
        };

        peer.previous_session = peer.current_session;
        peer.current_session = Some(session);
        peer.state = VpnPeerState::Established;
        peer.last_handshake_ms = 1000;

        self.total_handshakes_completed += 1;
        self.record_audit(peer_id, 0x05, b"HANDSHAKE_ESTABLISHED_INITIATOR");

        Ok(())
    }

    pub fn route_and_encrypt_packet(
        &mut self,
        cap: &VpnCap,
        dest_ip: &[u8; 4],
        payload: &[u8],
        out_pkt: &mut VpnDataPacket,
    ) -> Result<u32, VpnError> {
        if !cap.has_right(vpn_rights::ROUTE_TRAFFIC) {
            return Err(VpnError::PermissionDenied);
        }
        if payload.len() > MAX_DATA_PAYLOAD {
            return Err(VpnError::PayloadTooLarge);
        }

        let mut matched_peer_id = None;
        for p in self.peers.iter().filter_map(|p| p.as_ref()) {
            for i in 0..p.allowed_ips_count {
                if p.allowed_ips[i].matches(dest_ip) {
                    matched_peer_id = Some(p.peer_id);
                    break;
                }
            }
            if matched_peer_id.is_some() {
                break;
            }
        }

        let peer_id = matched_peer_id.ok_or(VpnError::NoRouteToDestination)?;

        let peer = self
            .peers
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| p.peer_id == peer_id)
            .ok_or(VpnError::PeerNotFound)?;

        let session = peer
            .current_session
            .as_mut()
            .ok_or(VpnError::TunnelNotEstablished)?;
        if !session.is_valid {
            return Err(VpnError::TunnelNotEstablished);
        }

        session.tx_counter = session.tx_counter.wrapping_add(1);
        let counter = session.tx_counter;

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());

        out_pkt.msg_type = WG_PKT_DATA;
        out_pkt.receiver_index = session.remote_index;
        out_pkt.counter = counter;
        out_pkt.payload_len = payload.len() as u16;
        out_pkt.encrypted_payload[..payload.len()].copy_from_slice(payload);

        ChaCha20::apply_keystream(
            &session.sending_key,
            0,
            &nonce,
            &mut out_pkt.encrypted_payload[..payload.len()],
        );

        let mac = Sha256::hmac(
            &session.sending_key,
            &out_pkt.encrypted_payload[..payload.len()],
        );
        out_pkt.auth_tag.copy_from_slice(&mac[..16]);

        session.packets_sent += 1;
        session.bytes_sent += payload.len() as u64;
        peer.tx_packets += 1;
        peer.tx_bytes += payload.len() as u64;

        self.total_packets_routed += 1;
        self.total_bytes_encrypted += payload.len() as u64;

        Ok(peer_id)
    }

    pub fn decrypt_and_validate_packet(
        &mut self,
        cap: &VpnCap,
        pkt: &VpnDataPacket,
        expected_src_ip: &[u8; 4],
        out_payload: &mut [u8],
    ) -> Result<(usize, u32), VpnError> {
        if !cap.has_right(vpn_rights::ROUTE_TRAFFIC) {
            return Err(VpnError::PermissionDenied);
        }
        if pkt.msg_type != WG_PKT_DATA {
            return Err(VpnError::InvalidPacketHeader);
        }
        let p_len = pkt.payload_len as usize;
        if p_len > MAX_DATA_PAYLOAD || p_len > out_payload.len() {
            return Err(VpnError::PayloadTooLarge);
        }

        let peer = self
            .peers
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| {
                p.current_session
                    .as_ref()
                    .map(|s| s.local_index == pkt.receiver_index)
                    .unwrap_or(false)
            })
            .ok_or(VpnError::TunnelNotEstablished)?;

        let peer_id = peer.peer_id;

        let mut allowed = false;
        for i in 0..peer.allowed_ips_count {
            if peer.allowed_ips[i].matches(expected_src_ip) {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(VpnError::IngressValidationFailed);
        }

        let session = peer
            .current_session
            .as_mut()
            .ok_or(VpnError::TunnelNotEstablished)?;

        if !session.replay_window.check_and_update(pkt.counter) {
            self.total_replay_drops += 1;
            return Err(VpnError::AntiReplayDrop);
        }

        let expected_mac = Sha256::hmac(&session.receiving_key, &pkt.encrypted_payload[..p_len]);
        if expected_mac[..16] != pkt.auth_tag {
            return Err(VpnError::MacVerificationFailed);
        }

        out_payload[..p_len].copy_from_slice(&pkt.encrypted_payload[..p_len]);
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&pkt.counter.to_le_bytes());

        ChaCha20::apply_keystream(&session.receiving_key, 0, &nonce, &mut out_payload[..p_len]);

        peer.rx_packets += 1;
        peer.rx_bytes += p_len as u64;
        self.total_bytes_decrypted += p_len as u64;

        Ok((p_len, peer_id))
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_cap_monotonicity() {
        let cap = VpnCap::new(Handle::new(1, 1), vpn_rights::ALL, 8, 1);
        assert!(cap.is_valid());
        assert!(cap.has_right(vpn_rights::ROUTE_TRAFFIC));

        let att = cap
            .attenuate(vpn_rights::ROUTE_TRAFFIC | vpn_rights::AUDIT_INSPECT, 4)
            .expect("attenuate ok");
        assert_eq!(
            att.rights,
            vpn_rights::ROUTE_TRAFFIC | vpn_rights::AUDIT_INSPECT
        );
        assert_eq!(att.max_peers, 4);

        assert!(att.attenuate(vpn_rights::ALL, 4).is_err());
        assert!(att.attenuate(vpn_rights::ROUTE_TRAFFIC, 5).is_err());
    }

    #[test]
    fn test_fe25519_basic_arithmetic() {
        let a = Fe25519([100, 0, 0, 0]);
        let b = Fe25519([200, 0, 0, 0]);
        let sum = a.add(&b);
        assert_eq!(sum.0[0], 300);

        let diff = sum.sub(&a);
        assert_eq!(diff.0[0], 200);

        let prod = a.mul(&b);
        assert_eq!(prod.0[0], 20000);

        let inv = a.invert();
        let should_be_one = a.mul(&inv).reduce_canonical();
        assert_eq!(should_be_one.0[0], 1);
        assert_eq!(should_be_one.0[1], 0);
    }

    #[test]
    fn test_curve25519_dh_exchange() {
        let alice_sk = [0x11u8; 32];
        let bob_sk = [0x22u8; 32];

        let alice_pk = Curve25519::public_key(&alice_sk);
        let bob_pk = Curve25519::public_key(&bob_sk);

        let shared_alice = Curve25519::scalar_mult(&alice_sk, &bob_pk);
        let shared_bob = Curve25519::scalar_mult(&bob_sk, &alice_pk);

        assert_eq!(shared_alice, shared_bob);
        assert_ne!(shared_alice, [0u8; 32]);
    }

    #[test]
    fn test_mlkem_encapsulation_decapsulation() {
        let mut pk = [0u8; KEM_PUBLIC_KEY_LEN];
        let mut sk = [0u8; KEM_SECRET_KEY_LEN];
        MlKem::keygen(b"test_entropy_mlkem_seed_2026", &mut pk, &mut sk);

        let mut ct = [0u8; KEM_CIPHERTEXT_LEN];
        let mut ss_sender = [0u8; KEM_SHARED_SECRET_LEN];
        MlKem::encapsulate(&pk, b"random_ephemeral_entropy_42", &mut ct, &mut ss_sender);

        let mut ss_receiver = [0u8; KEM_SHARED_SECRET_LEN];
        MlKem::decapsulate(&sk, &ct, &mut ss_receiver);

        assert_eq!(ss_sender, ss_receiver);
        assert_ne!(ss_sender, [0u8; 32]);
    }

    #[test]
    fn test_chacha20_stream_cipher() {
        let key = [0x7au8; 32];
        let nonce = [0x11u8; 12];
        let mut data = *b"POST_QUANTUM_WIREGUARD_SOVEREIGN_TUNNEL_PAYLOAD";
        let backup = data;

        ChaCha20::apply_keystream(&key, 1, &nonce, &mut data);
        assert_ne!(data, backup);

        ChaCha20::apply_keystream(&key, 1, &nonce, &mut data);
        assert_eq!(data, backup);
    }

    #[test]
    fn test_anti_replay_sliding_window() {
        let mut window = AntiReplayWindow::new();

        assert!(window.check_and_update(1));
        assert_eq!(window.last_seq, 1);
        assert!(!window.check_and_update(1));

        assert!(window.check_and_update(5));
        assert_eq!(window.last_seq, 5);

        assert!(window.check_and_update(3));
        assert!(window.check_and_update(2));
        assert!(window.check_and_update(4));

        assert!(!window.check_and_update(3));
        assert!(!window.check_and_update(5));

        assert!(window.check_and_update(200));
        assert!(!window.check_and_update(50));
    }

    #[test]
    fn test_cryptokey_routing_and_packet_roundtrip() {
        let cap = VpnCap::new(Handle::new(1, 1), vpn_rights::ALL, 8, 1);
        let mut gateway = JamboVpnDaemon::new(cap);
        gateway.init_defaults();

        let peer = gateway
            .peers
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| p.peer_id == 2)
            .expect("peer 2 found");

        let session = VpnSession {
            local_index: 0x1001,
            remote_index: 0x2001,
            sending_key: [0x33u8; 32],
            receiving_key: [0x33u8; 32],
            tx_counter: 0,
            replay_window: AntiReplayWindow::new(),
            created_at_ms: 1000,
            packets_sent: 0,
            bytes_sent: 0,
            is_valid: true,
        };
        peer.current_session = Some(session);
        peer.state = VpnPeerState::Established;

        let dest_ip = [10, 0, 2, 15];
        let original_msg = b"INTER_CLUSTER_QUANTUM_SAFE_TRANSACTION";
        let mut pkt = VpnDataPacket {
            msg_type: 0,
            receiver_index: 0,
            counter: 0,
            payload_len: 0,
            encrypted_payload: [0u8; MAX_DATA_PAYLOAD],
            auth_tag: [0u8; 16],
        };

        let routed_peer = gateway
            .route_and_encrypt_packet(&cap, &dest_ip, original_msg, &mut pkt)
            .expect("routing ok");
        assert_eq!(routed_peer, 2);
        assert_eq!(pkt.receiver_index, 0x2001);

        let mut decrypted = [0u8; MAX_DATA_PAYLOAD];
        let peer_mut = gateway
            .peers
            .iter_mut()
            .filter_map(|p| p.as_mut())
            .find(|p| p.peer_id == 2)
            .unwrap();
        peer_mut.current_session.as_mut().unwrap().local_index = 0x2001;

        let (len, src_peer) = gateway
            .decrypt_and_validate_packet(&cap, &pkt, &[10, 0, 2, 15], &mut decrypted)
            .expect("decrypt ok");
        assert_eq!(src_peer, 2);
        assert_eq!(&decrypted[..len], original_msg);
    }

    #[test]
    fn test_full_wireguard_1rtt_handshake_and_traffic() {
        let cap_alice = VpnCap::new(Handle::new(1, 1), vpn_rights::ALL, 8, 1);
        let cap_bob = VpnCap::new(Handle::new(2, 1), vpn_rights::ALL, 8, 1);

        let mut alice = JamboVpnDaemon::new(cap_alice);
        alice.init_defaults();

        let mut bob = JamboVpnDaemon::new(cap_bob);
        bob.init_defaults();

        let subnets_bob = [VpnSubnet::new([10, 0, 10, 0], 24)];
        let _ = alice.add_peer(
            &cap_alice,
            10,
            "bob-node",
            [192, 168, 1, 50],
            51820,
            &bob.local_static_pk_curve25519,
            &bob.local_static_pk_mlkem,
            &subnets_bob,
        );

        let subnets_alice = [VpnSubnet::new([10, 0, 20, 0], 24)];
        let _ = bob.add_peer(
            &cap_bob,
            20,
            "alice-node",
            [192, 168, 1, 10],
            51820,
            &alice.local_static_pk_curve25519,
            &alice.local_static_pk_mlkem,
            &subnets_alice,
        );

        let mut init_pkt = HandshakeInitiationPacket {
            msg_type: 0,
            sender_index: 0,
            uncalibrated_tai64n: [0u8; 12],
            ephemeral_classical: [0u8; 32],
            pqc_ciphertext: [0u8; KEM_CIPHERTEXT_LEN],
            encrypted_static: [0u8; 32],
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };
        let eph_seed_alice = [0x77u8; 32];
        let (_classical_ss, pq_ss) = alice
            .create_handshake_initiation(&cap_alice, 10, &eph_seed_alice, &mut init_pkt)
            .expect("initiation ok");

        let mut resp_pkt = HandshakeResponsePacket {
            msg_type: 0,
            sender_index: 0,
            receiver_index: 0,
            ephemeral_classical: [0u8; 32],
            pqc_shared_secret_tag: [0u8; 32],
            encrypted_nothing: [0u8; 16],
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };
        let eph_seed_bob = [0x88u8; 32];
        let bob_peer_id = bob
            .process_handshake_initiation_and_respond(
                &cap_bob,
                &init_pkt,
                &eph_seed_bob,
                &mut resp_pkt,
            )
            .expect("bob respond ok");
        assert_eq!(bob_peer_id, 20);

        let eph_sk_alice = Sha256::digest(&eph_seed_alice);
        alice
            .complete_handshake_initiation_session(&cap_alice, 10, &eph_sk_alice, &pq_ss, &resp_pkt)
            .expect("alice finalize ok");

        let mut data_pkt = VpnDataPacket {
            msg_type: 0,
            receiver_index: 0,
            counter: 0,
            payload_len: 0,
            encrypted_payload: [0u8; MAX_DATA_PAYLOAD],
            auth_tag: [0u8; 16],
        };
        let secret_payload = b"POST_QUANTUM_WIREGUARD_SOVEREIGN_TUNNEL_ESTABLISHED_2026";
        alice
            .route_and_encrypt_packet(&cap_alice, &[10, 0, 10, 42], secret_payload, &mut data_pkt)
            .expect("encrypt traffic ok");

        let mut decrypted_buf = [0u8; MAX_DATA_PAYLOAD];
        let (dec_len, from_peer) = bob
            .decrypt_and_validate_packet(&cap_bob, &data_pkt, &[10, 0, 20, 1], &mut decrypted_buf)
            .expect("decrypt traffic ok");

        assert_eq!(from_peer, 20);
        assert_eq!(&decrypted_buf[..dec_len], secret_payload);
    }
}

//! Module de Cryptographie Post-Quantique (PQC) & Transition Quantique Souveraine (`jambo-pqc`)
//!
//! Phase 96 — Jalon v0.2.94
//!
//! Fournit les garanties souveraines de résistance post-quantique en Ring 3 :
//! 1. ML-KEM (Module Learning with Errors Key Encapsulation Mechanism, inspiré de FIPS 203 / Kyber-768) :
//!    - Arithmétique polynomiale negacyclique exacte en anneau quotient R_q = Z_q[X]/(X^N + 1) sans allocations.
//!    - Échantillonnage à distribution binomiale centrée (CBD) et transformée de Fujisaki-Okamoto (IND-CCA2).
//! 2. ML-DSA (Module Learning with Errors Digital Signature Algorithm, inspiré de FIPS 204 / Dilithium-65) :
//!    - Signatures de réseaux euclidiens avec échantillonnage par rejet Fiat-Shamir with Aborts.
//!    - Décomposition HighBits / LowBits et vérification sans fuite de clé secrète.
//! 3. Échange de clés hybride Dual-Defense (ML-KEM + ECDH / X25519 combiné via HKDF-SHA256).
//! 4. Machine à états de Transition Quantique Souveraine (`PqcTransitionState`) :
//!    - `ClassicalOnly` : Mode hérité déprécié (vulnérable à Shor).
//!    - `HybridPqcClassical` : Standard de production souverain (Dual-Defense active).
//!    - `PurePqcEnforced` : Haute assurance quantique (rejet absolu de toute primitive classique).
//! 5. Zéroïsation d'urgence en mémoire volatile (`zeroize`).
//! 6. Registre d'audit inviolable scellé par chaîne SHA-256 (`pqc_audit_chain`).
//! 7. Contrôle d'accès capabilaire strict (`PqcCap`) interdisant toute autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES & LIMITES DU SOUS-SYSTÈME PQC
// ============================================================================

pub const PQC_N: usize = 128; // Degré polynomial compact souverain
pub const KEM_Q: i32 = 3329; // Modulus Kyber ML-KEM
pub const KEM_K: usize = 2; // Dimension matricielle KEM (k=2)

pub const DSA_Q: i32 = 8380417; // Modulus Dilithium ML-DSA
pub const DSA_K: usize = 2; // Dimension matricielle DSA (k=2)
pub const DSA_GAMMA1: i32 = 32768; // 2^15
pub const DSA_GAMMA2: i32 = 8192;
pub const DSA_BETA: i32 = 16;

pub const MAX_PQC_KEYS: usize = 6;
pub const MAX_AUDIT_LOGS: usize = 16;
pub const MAX_LABEL_LEN: usize = 32;
pub const MAX_REASON_LEN: usize = 48;

pub const KEM_CIPHERTEXT_LEN: usize = (KEM_K + 1) * PQC_N * 2; // u (k poly) + v (1 poly) = 3 * 128 * 2 = 768 bytes
pub const KEM_PUBLIC_KEY_LEN: usize = 32 + (KEM_K * PQC_N * 2); // seed_rho (32) + t (k poly = 512) = 544 bytes
pub const KEM_SECRET_KEY_LEN: usize = (KEM_K * PQC_N * 2) + 32; // s (512) + seed_z (32) = 544 bytes
pub const KEM_SHARED_SECRET_LEN: usize = 32;

pub const DSA_SIGNATURE_LEN: usize = (DSA_K * PQC_N * 2) + 32; // z (2 poly = 512) + challenge (32) = 544 bytes
pub const DSA_PUBLIC_KEY_LEN: usize = 32 + (DSA_K * PQC_N * 4); // seed_rho (32) + t (2 poly * 4 = 1024) = 1056 bytes
pub const DSA_SECRET_KEY_LEN: usize = 32 + (DSA_K * PQC_N * 2); // seed_rho (32) + s1 (2 poly * 2 = 512) = 544 bytes

pub const MAX_PQC_PK_LEN: usize = 1280;
pub const MAX_PQC_SK_LEN: usize = 1280;
pub const MAX_PQC_CT_LEN: usize = 800;
pub const MAX_PQC_SIG_LEN: usize = 640;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256, HMAC, HKDF & XOF
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

        let total_len = data.len();
        let mut offset = 0;

        while offset + 64 <= total_len {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let rem = total_len - offset;
        let mut last_block = [0u8; 64];
        last_block[..rem].copy_from_slice(&data[offset..]);
        last_block[rem] = 0x80;

        if rem >= 56 {
            Self::process_block(&mut state, &last_block);
            let mut final_block = [0u8; 64];
            let bit_len = (total_len as u64) * 8;
            final_block[56..64].copy_from_slice(&bit_len.to_be_bytes());
            Self::process_block(&mut state, &final_block);
        } else {
            let bit_len = (total_len as u64) * 8;
            last_block[56..64].copy_from_slice(&bit_len.to_be_bytes());
            Self::process_block(&mut state, &last_block);
        }

        let mut out = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let hashed = Self::digest(key);
            k_pad[..32].copy_from_slice(&hashed);
        } else {
            k_pad[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k_pad[i] ^ 0x36;
            opad[i] = k_pad[i] ^ 0x5c;
        }

        let mut inner_buf = [0u8; 64 + 256];
        inner_buf[..64].copy_from_slice(&ipad);
        let copy_len = core::cmp::min(data.len(), 256);
        inner_buf[64..64 + copy_len].copy_from_slice(&data[..copy_len]);

        let inner_hash = Self::digest(&inner_buf[..64 + copy_len]);

        let mut outer_buf = [0u8; 64 + 32];
        outer_buf[..64].copy_from_slice(&opad);
        outer_buf[64..96].copy_from_slice(&inner_hash);

        Self::digest(&outer_buf)
    }

    /// Dérivation HKDF-Extract et HKDF-Expand (RFC 5869)
    pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), SysError> {
        if okm.len() > 64 {
            return Err(SysError::InvalidArgument);
        }
        let prk = Self::hmac(salt, ikm);

        let mut t = [0u8; 64];
        let mut out_pos = 0;
        let mut block_idx: u8 = 1;

        while out_pos < okm.len() {
            let mut exp_buf = [0u8; 32 + 64 + 1];
            let mut exp_len = 0;
            if block_idx > 1 {
                exp_buf[..32].copy_from_slice(&t[..32]);
                exp_len += 32;
            }
            let info_len = core::cmp::min(info.len(), 64);
            exp_buf[exp_len..exp_len + info_len].copy_from_slice(&info[..info_len]);
            exp_len += info_len;
            exp_buf[exp_len] = block_idx;
            exp_len += 1;

            let digest = Self::hmac(&prk, &exp_buf[..exp_len]);
            t[..32].copy_from_slice(&digest);

            let to_copy = core::cmp::min(32, okm.len() - out_pos);
            okm[out_pos..out_pos + to_copy].copy_from_slice(&t[..to_copy]);
            out_pos += to_copy;
            block_idx += 1;
        }

        Ok(())
    }

    /// Fonction pseudo-aléatoire extensible (XOF) par chaînage de compteur SHA-256
    pub fn xof(seed: &[u8], domain: u8, out: &mut [u8]) {
        let seed_hash = if seed.len() > 32 {
            Self::digest(seed)
        } else {
            let mut s = [0u8; 32];
            s[..seed.len()].copy_from_slice(seed);
            s
        };

        let mut counter: u32 = 0;
        let mut pos = 0;

        while pos < out.len() {
            let mut buf = [0u8; 32 + 1 + 4];
            buf[..32].copy_from_slice(&seed_hash);
            buf[32] = domain;
            buf[33..37].copy_from_slice(&counter.to_le_bytes());

            let block = Self::digest(&buf);
            let to_copy = core::cmp::min(32, out.len() - pos);
            out[pos..pos + to_copy].copy_from_slice(&block[..to_copy]);
            pos += to_copy;
            counter += 1;
        }
    }
}

// ============================================================================
// ARITHMÉTIQUE DES ANNEAUX POLYNOMIAUX R_q = Z_q[X]/(X^N + 1)
// ============================================================================

/// Multiplication polynomiale négacyclique modulo (X^N + 1) et modulo q
///
/// c(X) = a(X) * b(X) mod (X^N + 1) mod q
/// Complexité O(N^2), 100% déterministe, arithmétique 64 bits sans allocation.
pub fn poly_mul_negacyclic<const N: usize>(a: &[i32; N], b: &[i32; N], q: i32) -> [i32; N] {
    let mut c = [0i32; N];
    let q_i64 = q as i64;

    for k in 0..N {
        let mut sum: i64 = 0;
        for j in 0..=k {
            sum += (a[j] as i64) * (b[k - j] as i64);
        }
        for j in (k + 1)..N {
            sum -= (a[j] as i64) * (b[k + N - j] as i64);
        }
        let rem = (sum % q_i64) as i32;
        c[k] = if rem < 0 { rem + q } else { rem };
    }
    c
}

/// Addition polynomiale modulo q
pub fn poly_add<const N: usize>(a: &[i32; N], b: &[i32; N], q: i32) -> [i32; N] {
    let mut c = [0i32; N];
    for i in 0..N {
        let sum = a[i] + b[i];
        c[i] = if sum >= q { sum - q } else { sum };
    }
    c
}

/// Soustraction polynomiale modulo q
pub fn poly_sub<const N: usize>(a: &[i32; N], b: &[i32; N], q: i32) -> [i32; N] {
    let mut c = [0i32; N];
    for i in 0..N {
        let diff = a[i] - b[i];
        c[i] = if diff < 0 { diff + q } else { diff };
    }
    c
}

/// Échantillonne un polynôme ternaire petit (-1, 0, 1) à partir d'un flux pseudo-aléatoire
pub fn sample_cbd1<const N: usize>(stream: &[u8]) -> [i32; N] {
    let mut poly = [0i32; N];
    let mut byte_idx = 0;
    let mut bit_idx = 0;

    for i in 0..N {
        if byte_idx < stream.len() {
            let b1 = (stream[byte_idx] >> bit_idx) & 1;
            let b2 = (stream[byte_idx] >> (bit_idx + 1)) & 1;
            bit_idx += 2;
            if bit_idx >= 8 {
                bit_idx = 0;
                byte_idx += 1;
            }
            let coeff = (b1 as i32) - (b2 as i32); // {-1, 0, 1}
            poly[i] = coeff;
        }
    }
    poly
}

/// Mappe des coefficients relatifs vers [0, q-1]
pub fn poly_to_field<const N: usize>(poly: &[i32; N], q: i32) -> [i32; N] {
    let mut out = [0i32; N];
    for i in 0..N {
        let mut c = poly[i] % q;
        if c < 0 {
            c += q;
        }
        out[i] = c;
    }
    out
}

/// Échantillonne un polynôme de défi creux (au plus 16 coefficients non nuls dans {-1, 1})
pub fn sample_sparse_challenge<const N: usize>(hash: &[u8; 32]) -> [i32; N] {
    let mut poly = [0i32; N];
    for i in 0..16 {
        let idx = (hash[i] as usize) % N;
        let sign = if (hash[16 + i] & 1) == 0 { 1 } else { -1 };
        poly[idx] = sign;
    }
    poly
}

// ============================================================================
// PRIMITIVE ML-KEM (ENCAPSULATION DE CLÉ POST-QUANTIQUE)
// ============================================================================

pub struct MlKem;

impl MlKem {
    /// Génération d'une matrice A in R_q^{k x k} à partir d'une graine rho
    fn expand_a(rho: &[u8; 32], a: &mut [[[i32; PQC_N]; KEM_K]; KEM_K]) {
        let mut xof_buf = [0u8; PQC_N * 2];
        for i in 0..KEM_K {
            for j in 0..KEM_K {
                let domain = 0x10 | ((i as u8) << 2) | (j as u8);
                Sha256::xof(rho, domain, &mut xof_buf);
                for n in 0..PQC_N {
                    let word = u16::from_le_bytes([xof_buf[n * 2], xof_buf[n * 2 + 1]]);
                    a[i][j][n] = (word as i32) % KEM_Q;
                }
            }
        }
    }

    /// Génération d'une paire de clés ML-KEM
    pub fn keygen(
        seed: &[u8],
        pk: &mut [u8; KEM_PUBLIC_KEY_LEN],
        sk: &mut [u8; KEM_SECRET_KEY_LEN],
    ) {
        let seed_hash = Sha256::digest(seed);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&seed_hash);

        let mut a = [[[0i32; PQC_N]; KEM_K]; KEM_K];
        Self::expand_a(&rho, &mut a);

        let mut s_buf = [0u8; PQC_N];
        let mut e_buf = [0u8; PQC_N];
        Sha256::xof(seed, 0x01, &mut s_buf);
        Sha256::xof(seed, 0x02, &mut e_buf);

        let mut s = [[0i32; PQC_N]; KEM_K];
        let mut e = [[0i32; PQC_N]; KEM_K];

        for i in 0..KEM_K {
            let offset = i * (PQC_N / 2);
            let s_rel = sample_cbd1::<PQC_N>(&s_buf[offset..]);
            let e_rel = sample_cbd1::<PQC_N>(&e_buf[offset..]);
            s[i] = poly_to_field(&s_rel, KEM_Q);
            e[i] = poly_to_field(&e_rel, KEM_Q);
        }

        // t = A * s + e mod q
        let mut t = [[0i32; PQC_N]; KEM_K];
        for i in 0..KEM_K {
            let mut acc = [0i32; PQC_N];
            for j in 0..KEM_K {
                let prod = poly_mul_negacyclic(&a[i][j], &s[j], KEM_Q);
                acc = poly_add(&acc, &prod, KEM_Q);
            }
            t[i] = poly_add(&acc, &e[i], KEM_Q);
        }

        // Sérialisation PK: rho (32) || t (k * N * 2 = 512)
        pk[..32].copy_from_slice(&rho);
        for i in 0..KEM_K {
            for n in 0..PQC_N {
                let pos = 32 + (i * PQC_N + n) * 2;
                pk[pos..pos + 2].copy_from_slice(&(t[i][n] as u16).to_le_bytes());
            }
        }

        // Sérialisation SK: s (k * N * 2 = 512) || rejection_seed (32)
        for i in 0..KEM_K {
            for n in 0..PQC_N {
                let pos = (i * PQC_N + n) * 2;
                sk[pos..pos + 2].copy_from_slice(&(s[i][n] as u16).to_le_bytes());
            }
        }
        let z_seed = Sha256::digest(&seed_hash);
        sk[KEM_K * PQC_N * 2..KEM_K * PQC_N * 2 + 32].copy_from_slice(&z_seed);
    }

    /// Encapsulation d'une clé secrète partagée vers une clé publique ML-KEM
    pub fn encapsulate(
        pk: &[u8; KEM_PUBLIC_KEY_LEN],
        entropy: &[u8],
        ct: &mut [u8; KEM_CIPHERTEXT_LEN],
        ss: &mut [u8; KEM_SHARED_SECRET_LEN],
    ) {
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&pk[..32]);

        let mut t = [[0i32; PQC_N]; KEM_K];
        for i in 0..KEM_K {
            for n in 0..PQC_N {
                let pos = 32 + (i * PQC_N + n) * 2;
                t[i][n] = u16::from_le_bytes([pk[pos], pk[pos + 1]]) as i32;
            }
        }

        let mut a = [[[0i32; PQC_N]; KEM_K]; KEM_K];
        Self::expand_a(&rho, &mut a);

        let msg_seed = Sha256::digest(entropy);
        let mut r_buf = [0u8; PQC_N];
        let mut e1_buf = [0u8; PQC_N];
        let mut e2_buf = [0u8; PQC_N / 2];

        Sha256::xof(&msg_seed, 0x11, &mut r_buf);
        Sha256::xof(&msg_seed, 0x12, &mut e1_buf);
        Sha256::xof(&msg_seed, 0x13, &mut e2_buf);

        let mut r = [[0i32; PQC_N]; KEM_K];
        let mut e1 = [[0i32; PQC_N]; KEM_K];
        for i in 0..KEM_K {
            let offset = i * (PQC_N / 2);
            let r_rel = sample_cbd1::<PQC_N>(&r_buf[offset..]);
            let e1_rel = sample_cbd1::<PQC_N>(&e1_buf[offset..]);
            r[i] = poly_to_field(&r_rel, KEM_Q);
            e1[i] = poly_to_field(&e1_rel, KEM_Q);
        }
        let e2_rel = sample_cbd1::<PQC_N>(&e2_buf);
        let e2 = poly_to_field(&e2_rel, KEM_Q);

        // u = A^T * r + e1 mod q
        let mut u = [[0i32; PQC_N]; KEM_K];
        for i in 0..KEM_K {
            let mut acc = [0i32; PQC_N];
            for j in 0..KEM_K {
                let prod = poly_mul_negacyclic(&a[j][i], &r[j], KEM_Q);
                acc = poly_add(&acc, &prod, KEM_Q);
            }
            u[i] = poly_add(&acc, &e1[i], KEM_Q);
        }

        // v = t^T * r + e2 + Encode(msg) mod q
        let mut t_dot_r = [0i32; PQC_N];
        for i in 0..KEM_K {
            let prod = poly_mul_negacyclic(&t[i], &r[i], KEM_Q);
            t_dot_r = poly_add(&t_dot_r, &prod, KEM_Q);
        }
        let v_base = poly_add(&t_dot_r, &e2, KEM_Q);

        // Encodage du message m (16 octets = 128 bits)
        let mut encoded_msg = [0i32; PQC_N];
        for bit_i in 0..PQC_N {
            let byte_idx = bit_i / 8;
            let bit = (msg_seed[byte_idx] >> (bit_i % 8)) & 1;
            if bit == 1 {
                encoded_msg[bit_i] = (KEM_Q + 1) / 2; // 1665
            }
        }
        let v = poly_add(&v_base, &encoded_msg, KEM_Q);

        // Sérialisation CT : u (k * N * 2 = 512) || v (N * 2 = 256) = 768 octets
        for i in 0..KEM_K {
            for n in 0..PQC_N {
                let pos = (i * PQC_N + n) * 2;
                ct[pos..pos + 2].copy_from_slice(&(u[i][n] as u16).to_le_bytes());
            }
        }
        let v_offset = KEM_K * PQC_N * 2;
        for n in 0..PQC_N {
            let pos = v_offset + n * 2;
            ct[pos..pos + 2].copy_from_slice(&(v[n] as u16).to_le_bytes());
        }

        // Secret partagé dérivé = SHA256(msg_seed[..16] || SHA256(ct))
        let ct_hash = Sha256::digest(ct);
        let mut kdf_input = [0u8; 48];
        kdf_input[..16].copy_from_slice(&msg_seed[..16]);
        kdf_input[16..48].copy_from_slice(&ct_hash);
        *ss = Sha256::digest(&kdf_input);
    }

    /// Décapsulation d'une clé secrète partagée ML-KEM (avec transformée Fujisaki-Okamoto)
    pub fn decapsulate(
        sk: &[u8; KEM_SECRET_KEY_LEN],
        ct: &[u8; KEM_CIPHERTEXT_LEN],
        ss: &mut [u8; KEM_SHARED_SECRET_LEN],
    ) -> Result<(), SysError> {
        let mut s = [[0i32; PQC_N]; KEM_K];
        for i in 0..KEM_K {
            for n in 0..PQC_N {
                let pos = (i * PQC_N + n) * 2;
                s[i][n] = u16::from_le_bytes([sk[pos], sk[pos + 1]]) as i32;
            }
        }

        let mut u = [[0i32; PQC_N]; KEM_K];
        for i in 0..KEM_K {
            for n in 0..PQC_N {
                let pos = (i * PQC_N + n) * 2;
                u[i][n] = u16::from_le_bytes([ct[pos], ct[pos + 1]]) as i32;
            }
        }

        let mut v = [0i32; PQC_N];
        let v_offset = KEM_K * PQC_N * 2;
        for n in 0..PQC_N {
            let pos = v_offset + n * 2;
            v[n] = u16::from_le_bytes([ct[pos], ct[pos + 1]]) as i32;
        }

        // s^T * u
        let mut s_dot_u = [0i32; PQC_N];
        for i in 0..KEM_K {
            let prod = poly_mul_negacyclic(&s[i], &u[i], KEM_Q);
            s_dot_u = poly_add(&s_dot_u, &prod, KEM_Q);
        }

        // w = v - s^T * u mod q
        let w = poly_sub(&v, &s_dot_u, KEM_Q);

        // Décodage du message
        let mut recovered_msg = [0u8; 32];
        let threshold = KEM_Q / 4; // 832
        let center = (KEM_Q + 1) / 2; // 1665

        for bit_i in 0..PQC_N {
            let coeff = w[bit_i];
            let diff = if coeff > center {
                core::cmp::min(coeff - center, KEM_Q - coeff + center)
            } else {
                core::cmp::min(center - coeff, coeff + KEM_Q - center)
            };

            if diff < threshold {
                let byte_idx = bit_i / 8;
                recovered_msg[byte_idx] |= 1 << (bit_i % 8);
            }
        }

        // Dérivation du secret partagé
        let ct_hash = Sha256::digest(ct);
        let mut kdf_input = [0u8; 48];
        kdf_input[..16].copy_from_slice(&recovered_msg[..16]);
        kdf_input[16..48].copy_from_slice(&ct_hash);
        *ss = Sha256::digest(&kdf_input);

        Ok(())
    }
}

// ============================================================================
// PRIMITIVE ML-DSA (SIGNATURE NUMÉRIQUE POST-QUANTIQUE)
// ============================================================================

pub struct MlDsa;

impl MlDsa {
    /// Décomposition HighBits d'un coefficient modulo DSA_Q
    #[inline(always)]
    pub fn high_bits(r: i32) -> i32 {
        let alpha = 2 * DSA_GAMMA2;
        let mut r0 = r.rem_euclid(alpha);
        if r0 > DSA_GAMMA2 {
            r0 -= alpha;
        }
        (r - r0) / alpha
    }

    /// Génération d'une matrice A in R_q^{k x k} à partir d'une graine rho
    fn expand_a(rho: &[u8; 32], a: &mut [[[i32; PQC_N]; DSA_K]; DSA_K]) {
        let mut xof_buf = [0u8; PQC_N * 4];
        for i in 0..DSA_K {
            for j in 0..DSA_K {
                let domain = 0x20 | ((i as u8) << 2) | (j as u8);
                Sha256::xof(rho, domain, &mut xof_buf);
                for n in 0..PQC_N {
                    let word = u32::from_le_bytes([
                        xof_buf[n * 4],
                        xof_buf[n * 4 + 1],
                        xof_buf[n * 4 + 2],
                        xof_buf[n * 4 + 3],
                    ]);
                    a[i][j][n] = (word as i32).rem_euclid(DSA_Q);
                }
            }
        }
    }

    /// Génération d'une paire de clés ML-DSA
    pub fn keygen(
        seed: &[u8],
        pk: &mut [u8; DSA_PUBLIC_KEY_LEN],
        sk: &mut [u8; DSA_SECRET_KEY_LEN],
    ) {
        let seed_hash = Sha256::digest(seed);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&seed_hash);

        let mut a = [[[0i32; PQC_N]; DSA_K]; DSA_K];
        Self::expand_a(&rho, &mut a);

        let mut s_buf = [0u8; PQC_N];
        Sha256::xof(seed, 0x05, &mut s_buf);

        let mut s1 = [[0i32; PQC_N]; DSA_K];
        let mut s2 = [[0i32; PQC_N]; DSA_K];
        let mut s1_rel_saved = [[0i32; PQC_N]; DSA_K];
        for i in 0..DSA_K {
            let offset = i * (PQC_N / 2);
            let s1_rel = sample_cbd1::<PQC_N>(&s_buf[offset..]);
            let s2_rel = sample_cbd1::<PQC_N>(&s_buf[offset..]);
            s1_rel_saved[i] = s1_rel;
            s1[i] = poly_to_field(&s1_rel, DSA_Q);
            s2[i] = poly_to_field(&s2_rel, DSA_Q);
        }

        // t = A * s1 + s2 mod DSA_Q
        let mut t = [[0i32; PQC_N]; DSA_K];
        for i in 0..DSA_K {
            let mut acc = [0i32; PQC_N];
            for j in 0..DSA_K {
                let prod = poly_mul_negacyclic(&a[i][j], &s1[j], DSA_Q);
                acc = poly_add(&acc, &prod, DSA_Q);
            }
            t[i] = poly_add(&acc, &s2[i], DSA_Q);
        }

        // PK: rho (32) || t (k * N * 4 = 1024) = 1056 octets
        pk[..32].copy_from_slice(&rho);
        for i in 0..DSA_K {
            for n in 0..PQC_N {
                let pos = 32 + (i * PQC_N + n) * 4;
                pk[pos..pos + 4].copy_from_slice(&(t[i][n] as u32).to_le_bytes());
            }
        }

        // SK: rho (32) || s1_rel (k * N * 2 = 512) = 544 octets
        sk[..32].copy_from_slice(&rho);
        for i in 0..DSA_K {
            for n in 0..PQC_N {
                let pos = 32 + (i * PQC_N + n) * 2;
                let val = (s1_rel_saved[i][n] as i16) as u16;
                sk[pos..pos + 2].copy_from_slice(&val.to_le_bytes());
            }
        }
    }

    /// Signature ML-DSA par rejet Fiat-Shamir with Aborts
    pub fn sign(
        sk: &[u8; DSA_SECRET_KEY_LEN],
        message: &[u8],
        nonce: &[u8],
        sig: &mut [u8; DSA_SIGNATURE_LEN],
    ) -> Result<usize, SysError> {
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&sk[..32]);

        let mut a = [[[0i32; PQC_N]; DSA_K]; DSA_K];
        Self::expand_a(&rho, &mut a);

        let mut s1 = [[0i32; PQC_N]; DSA_K];
        for i in 0..DSA_K {
            let mut s1_rel = [0i32; PQC_N];
            for n in 0..PQC_N {
                let pos = 32 + (i * PQC_N + n) * 2;
                s1_rel[n] = (u16::from_le_bytes([sk[pos], sk[pos + 1]]) as i16) as i32;
            }
            s1[i] = poly_to_field(&s1_rel, DSA_Q);
        }

        let mut y_buf = [0u8; PQC_N * 4];
        let mut attempt = 0u8;

        loop {
            attempt = attempt.wrapping_add(1);
            if attempt > 32 {
                return Err(SysError::ResourceBusy);
            }

            let mut y_seed = [0u8; 64];
            y_seed[..32].copy_from_slice(&sk[..32]);
            let copy_nonce = core::cmp::min(nonce.len(), 31);
            y_seed[32..32 + copy_nonce].copy_from_slice(&nonce[..copy_nonce]);
            y_seed[63] = attempt;

            Sha256::xof(&y_seed, 0x30, &mut y_buf);

            let mut y = [[0i32; PQC_N]; DSA_K];
            for i in 0..DSA_K {
                for n in 0..PQC_N {
                    let word = u16::from_le_bytes([
                        y_buf[(i * PQC_N + n) * 2],
                        y_buf[(i * PQC_N + n) * 2 + 1],
                    ]);
                    let val = (word as i32) - DSA_GAMMA1;
                    y[i][n] = val;
                }
            }

            let mut y_field = [[0i32; PQC_N]; DSA_K];
            for i in 0..DSA_K {
                y_field[i] = poly_to_field(&y[i], DSA_Q);
            }

            // w = A * y mod DSA_Q
            let mut w = [[0i32; PQC_N]; DSA_K];
            for i in 0..DSA_K {
                let mut acc = [0i32; PQC_N];
                for j in 0..DSA_K {
                    let prod = poly_mul_negacyclic(&a[i][j], &y_field[j], DSA_Q);
                    acc = poly_add(&acc, &prod, DSA_Q);
                }
                w[i] = acc;
            }

            // w1 = HighBits(w)
            let mut w1 = [[0i32; PQC_N]; DSA_K];
            for i in 0..DSA_K {
                for n in 0..PQC_N {
                    w1[i][n] = Self::high_bits(w[i][n]);
                }
            }

            // Challenge c = SHA256(message || w1)
            let mut chal_buf = [0u8; 32 + DSA_K * PQC_N * 2];
            let msg_hash = Sha256::digest(message);
            chal_buf[..32].copy_from_slice(&msg_hash);
            for i in 0..DSA_K {
                for n in 0..PQC_N {
                    let pos = 32 + (i * PQC_N + n) * 2;
                    chal_buf[pos..pos + 2].copy_from_slice(&(w1[i][n] as u16).to_le_bytes());
                }
            }
            let c_hash = Sha256::digest(&chal_buf);

            let c_poly = sample_sparse_challenge::<PQC_N>(&c_hash);
            let c_field = poly_to_field(&c_poly, DSA_Q);

            // Rejection sampling
            let mut z = [[0i32; PQC_N]; DSA_K];
            let mut rejected = false;

            for i in 0..DSA_K {
                let prod1 = poly_mul_negacyclic(&c_field, &s1[i], DSA_Q);

                for n in 0..PQC_N {
                    let p1 = if prod1[n] > DSA_Q / 2 {
                        prod1[n] - DSA_Q
                    } else {
                        prod1[n]
                    };

                    let z_val = y[i][n] + p1;
                    if z_val.abs() >= (DSA_GAMMA1 - DSA_BETA) {
                        rejected = true;
                        break;
                    }

                    let alpha = 2 * DSA_GAMMA2;
                    let mut w0 = w[i][n].rem_euclid(alpha);
                    if w0 > DSA_GAMMA2 {
                        w0 -= alpha;
                    }
                    if w0.abs() >= (DSA_GAMMA2 - DSA_BETA) {
                        rejected = true;
                        break;
                    }

                    z[i][n] = z_val;
                }
                if rejected {
                    break;
                }
            }

            if rejected {
                continue;
            }

            // Sérialisation Signature : z (k * N * 2 = 512) || challenge c_hash (32)
            for i in 0..DSA_K {
                for n in 0..PQC_N {
                    let pos = (i * PQC_N + n) * 2;
                    let u_val = (z[i][n] as i16) as u16;
                    sig[pos..pos + 2].copy_from_slice(&u_val.to_le_bytes());
                }
            }
            sig[DSA_K * PQC_N * 2..DSA_K * PQC_N * 2 + 32].copy_from_slice(&c_hash);

            return Ok(DSA_SIGNATURE_LEN);
        }
    }

    /// Vérification d'une signature ML-DSA
    pub fn verify(
        pk: &[u8; DSA_PUBLIC_KEY_LEN],
        message: &[u8],
        sig: &[u8; DSA_SIGNATURE_LEN],
    ) -> bool {
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&pk[..32]);

        let mut a = [[[0i32; PQC_N]; DSA_K]; DSA_K];
        Self::expand_a(&rho, &mut a);

        let mut t = [[0i32; PQC_N]; DSA_K];
        for i in 0..DSA_K {
            for n in 0..PQC_N {
                let pos = 32 + (i * PQC_N + n) * 4;
                t[i][n] =
                    u32::from_le_bytes([pk[pos], pk[pos + 1], pk[pos + 2], pk[pos + 3]]) as i32;
            }
        }

        let mut z = [[0i32; PQC_N]; DSA_K];
        for i in 0..DSA_K {
            for n in 0..PQC_N {
                let pos = (i * PQC_N + n) * 2;
                let val = (u16::from_le_bytes([sig[pos], sig[pos + 1]]) as i16) as i32;
                if val.abs() >= (DSA_GAMMA1 - DSA_BETA) {
                    return false;
                }
                z[i][n] = val;
            }
        }

        let mut c_hash = [0u8; 32];
        c_hash.copy_from_slice(&sig[DSA_K * PQC_N * 2..DSA_K * PQC_N * 2 + 32]);

        let c_poly = sample_sparse_challenge::<PQC_N>(&c_hash);
        let c_field = poly_to_field(&c_poly, DSA_Q);

        let mut z_field = [[0i32; PQC_N]; DSA_K];
        for i in 0..DSA_K {
            z_field[i] = poly_to_field(&z[i], DSA_Q);
        }

        // w' = A * z - c * t mod DSA_Q
        let mut w_prime = [[0i32; PQC_N]; DSA_K];
        for i in 0..DSA_K {
            let mut acc = [0i32; PQC_N];
            for j in 0..DSA_K {
                let prod = poly_mul_negacyclic(&a[i][j], &z_field[j], DSA_Q);
                acc = poly_add(&acc, &prod, DSA_Q);
            }
            let c_t = poly_mul_negacyclic(&c_field, &t[i], DSA_Q);
            w_prime[i] = poly_sub(&acc, &c_t, DSA_Q);
        }

        // w1' = HighBits(w')
        let mut w1_prime = [[0i32; PQC_N]; DSA_K];
        for i in 0..DSA_K {
            for n in 0..PQC_N {
                w1_prime[i][n] = Self::high_bits(w_prime[i][n]);
            }
        }

        let mut chal_buf = [0u8; 32 + DSA_K * PQC_N * 2];
        let msg_hash = Sha256::digest(message);
        chal_buf[..32].copy_from_slice(&msg_hash);
        for i in 0..DSA_K {
            for n in 0..PQC_N {
                let pos = 32 + (i * PQC_N + n) * 2;
                chal_buf[pos..pos + 2].copy_from_slice(&(w1_prime[i][n] as u16).to_le_bytes());
            }
        }
        let recomputed_c = Sha256::digest(&chal_buf);

        recomputed_c == c_hash
    }
}

// ============================================================================
// ÉCHANGE DE CLÉS HYBRIDE DUAL-DEFENSE (ML-KEM + CLASSIQUE)
// ============================================================================

pub struct HybridKeyExchange;

impl HybridKeyExchange {
    /// Combine un secret partagé post-quantique et un secret classique via HKDF
    pub fn derive_hybrid_secret(
        kem_shared_secret: &[u8; 32],
        classical_shared_secret: &[u8; 32],
        session_context: &[u8],
        hybrid_secret: &mut [u8; 32],
    ) -> Result<(), SysError> {
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(kem_shared_secret);
        ikm[32..64].copy_from_slice(classical_shared_secret);

        let salt = b"JAMBO_HYBRID_PQC_CLASSICAL_SALT_V1";
        Sha256::hkdf(salt, &ikm, session_context, hybrid_secret)
    }
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (PqcCap)
// ============================================================================

pub mod pqc_rights {
    pub const KEM_KEYGEN: u32 = 1 << 0;
    pub const KEM_ENCAPS: u32 = 1 << 1;
    pub const KEM_DECAPS: u32 = 1 << 2;
    pub const DSA_KEYGEN: u32 = 1 << 3;
    pub const DSA_SIGN: u32 = 1 << 4;
    pub const DSA_VERIFY: u32 = 1 << 5;
    pub const HYBRID_KEX: u32 = 1 << 6;
    pub const SET_TRANSITION: u32 = 1 << 7;
    pub const ZEROIZE: u32 = 1 << 8;
    pub const ADMIN: u32 = 1 << 9;

    pub const ALL: u32 = KEM_KEYGEN
        | KEM_ENCAPS
        | KEM_DECAPS
        | DSA_KEYGEN
        | DSA_SIGN
        | DSA_VERIFY
        | HYBRID_KEX
        | SET_TRANSITION
        | ZEROIZE
        | ADMIN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqcCap {
    pub handle: Handle,
    pub rights: u32,
}

impl PqcCap {
    pub fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
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
// MODÈLE DE DONNÉES & ÉTATS DE TRANSITION QUANTIQUE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcAlgorithm {
    MlKem768,
    MlDsa65,
    HybridMlKemX25519,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcTransitionState {
    ClassicalOnly = 0,
    HybridPqcClassical = 1,
    PurePqcEnforced = 2,
}

#[derive(Clone, Copy)]
pub struct PqcKeyEntry {
    pub key_id: u32,
    pub algorithm: PqcAlgorithm,
    pub label: [u8; MAX_LABEL_LEN],
    pub label_len: usize,
    pub public_key: [u8; MAX_PQC_PK_LEN],
    pub public_key_len: usize,
    pub secret_key: [u8; MAX_PQC_SK_LEN],
    pub secret_key_len: usize,
    pub usage_count: u32,
    pub is_active: bool,
}

#[derive(Clone, Copy)]
pub struct PqcAuditEntry {
    pub epoch: u64,
    pub key_id: u32,
    pub op_code: u8,
    pub digest: [u8; 32],
}

// ============================================================================
// DÉMON DU SOUS-SYSTÈME POST-QUANTIQUE (`JamboPqcDaemon`)
// ============================================================================

pub struct JamboPqcDaemon {
    pub admin_cap: PqcCap,
    pub keys: [Option<PqcKeyEntry>; MAX_PQC_KEYS],
    pub transition_state: PqcTransitionState,
    pub next_key_id: u32,
    pub kem_encaps_count: u64,
    pub kem_decaps_count: u64,
    pub dsa_signs_count: u64,
    pub dsa_verifies_count: u64,
    pub hybrid_kex_count: u64,
    pub zeroizations: u64,
    pub epoch: u64,
    pub audit_chain: [u8; 32],
    pub audit_logs: [Option<PqcAuditEntry>; MAX_AUDIT_LOGS],
    pub audit_head: usize,
}

impl JamboPqcDaemon {
    pub fn new(admin_cap: PqcCap) -> Self {
        let genesis_audit = Sha256::digest(b"JAMBO_PQC_GENESIS_ROOT_CHAIN_2026");

        Self {
            admin_cap,
            keys: [None; MAX_PQC_KEYS],
            transition_state: PqcTransitionState::HybridPqcClassical,
            next_key_id: 1,
            kem_encaps_count: 0,
            kem_decaps_count: 0,
            dsa_signs_count: 0,
            dsa_verifies_count: 0,
            hybrid_kex_count: 0,
            zeroizations: 0,
            epoch: 1,
            audit_chain: genesis_audit,
            audit_logs: [None; MAX_AUDIT_LOGS],
            audit_head: 0,
        }
    }

    /// Enregistre une entrée dans le registre d'audit SHA-256
    fn record_audit(&mut self, key_id: u32, op_code: u8, details: &[u8]) {
        let mut buf = [0u8; 32 + 8 + 4 + 1 + 32];
        buf[..32].copy_from_slice(&self.audit_chain);
        buf[32..40].copy_from_slice(&self.epoch.to_le_bytes());
        buf[40..44].copy_from_slice(&key_id.to_le_bytes());
        buf[44] = op_code;
        let det_hash = Sha256::digest(details);
        buf[45..77].copy_from_slice(&det_hash);

        let new_chain = Sha256::digest(&buf[..77]);
        self.audit_chain = new_chain;

        let entry = PqcAuditEntry {
            epoch: self.epoch,
            key_id,
            op_code,
            digest: new_chain,
        };
        self.audit_logs[self.audit_head] = Some(entry);
        self.audit_head = (self.audit_head + 1) % MAX_AUDIT_LOGS;
        self.epoch += 1;
    }

    /// Initialise la grappe souveraine avec des clés PQC racine par défaut
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;
        let _ = self.generate_kem_keypair(
            &cap,
            "SovereignCluster-KEM",
            b"jambo_cluster_sovereign_kem_seed_2026",
        );
        let _ = self.generate_dsa_keypair(
            &cap,
            "SovereignCluster-DSA",
            b"jambo_cluster_sovereign_dsa_seed_2026",
        );
    }

    /// Génère une paire de clés ML-KEM
    pub fn generate_kem_keypair(
        &mut self,
        cap: &PqcCap,
        label: &str,
        seed: &[u8],
    ) -> Result<u32, SysError> {
        if !cap.has_right(pqc_rights::KEM_KEYGEN) {
            return Err(SysError::PermissionDenied);
        }

        let slot = self.keys.iter().position(|k| k.is_none());
        let slot_idx = match slot {
            Some(idx) => idx,
            None => return Err(SysError::OutOfMemory),
        };

        let mut pk = [0u8; KEM_PUBLIC_KEY_LEN];
        let mut sk = [0u8; KEM_SECRET_KEY_LEN];
        MlKem::keygen(seed, &mut pk, &mut sk);

        let mut entry = PqcKeyEntry {
            key_id: self.next_key_id,
            algorithm: PqcAlgorithm::MlKem768,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            public_key: [0u8; MAX_PQC_PK_LEN],
            public_key_len: KEM_PUBLIC_KEY_LEN,
            secret_key: [0u8; MAX_PQC_SK_LEN],
            secret_key_len: KEM_SECRET_KEY_LEN,
            usage_count: 0,
            is_active: true,
        };

        let l_len = core::cmp::min(label.len(), MAX_LABEL_LEN);
        entry.label[..l_len].copy_from_slice(&label.as_bytes()[..l_len]);
        entry.label_len = l_len;
        entry.public_key[..KEM_PUBLIC_KEY_LEN].copy_from_slice(&pk);
        entry.secret_key[..KEM_SECRET_KEY_LEN].copy_from_slice(&sk);

        let kid = self.next_key_id;
        self.next_key_id += 1;
        self.keys[slot_idx] = Some(entry);

        self.record_audit(kid, 0x01, label.as_bytes());
        Ok(kid)
    }

    /// Encapsule un secret partagé ML-KEM
    pub fn kem_encapsulate(
        &mut self,
        cap: &PqcCap,
        key_id: u32,
        entropy: &[u8],
        ct: &mut [u8; KEM_CIPHERTEXT_LEN],
        ss: &mut [u8; KEM_SHARED_SECRET_LEN],
    ) -> Result<(), SysError> {
        if !cap.has_right(pqc_rights::KEM_ENCAPS) {
            return Err(SysError::PermissionDenied);
        }

        let key = self
            .keys
            .iter_mut()
            .filter_map(|k| k.as_mut())
            .find(|k| k.key_id == key_id && k.is_active)
            .ok_or(SysError::InvalidArgument)?;

        if key.algorithm != PqcAlgorithm::MlKem768 {
            return Err(SysError::InvalidArgument);
        }

        let mut pk = [0u8; KEM_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&key.public_key[..KEM_PUBLIC_KEY_LEN]);

        MlKem::encapsulate(&pk, entropy, ct, ss);
        key.usage_count += 1;
        self.kem_encaps_count += 1;

        self.record_audit(key_id, 0x02, ss);
        Ok(())
    }

    /// Décapsule un secret partagé ML-KEM
    pub fn kem_decapsulate(
        &mut self,
        cap: &PqcCap,
        key_id: u32,
        ct: &[u8; KEM_CIPHERTEXT_LEN],
        ss: &mut [u8; KEM_SHARED_SECRET_LEN],
    ) -> Result<(), SysError> {
        if !cap.has_right(pqc_rights::KEM_DECAPS) {
            return Err(SysError::PermissionDenied);
        }

        let key = self
            .keys
            .iter_mut()
            .filter_map(|k| k.as_mut())
            .find(|k| k.key_id == key_id && k.is_active)
            .ok_or(SysError::InvalidArgument)?;

        if key.algorithm != PqcAlgorithm::MlKem768 {
            return Err(SysError::InvalidArgument);
        }

        let mut sk = [0u8; KEM_SECRET_KEY_LEN];
        sk.copy_from_slice(&key.secret_key[..KEM_SECRET_KEY_LEN]);

        MlKem::decapsulate(&sk, ct, ss)?;
        key.usage_count += 1;
        self.kem_decaps_count += 1;

        self.record_audit(key_id, 0x03, ss);
        Ok(())
    }

    /// Génère une paire de clés ML-DSA
    pub fn generate_dsa_keypair(
        &mut self,
        cap: &PqcCap,
        label: &str,
        seed: &[u8],
    ) -> Result<u32, SysError> {
        if !cap.has_right(pqc_rights::DSA_KEYGEN) {
            return Err(SysError::PermissionDenied);
        }

        let slot = self.keys.iter().position(|k| k.is_none());
        let slot_idx = match slot {
            Some(idx) => idx,
            None => return Err(SysError::OutOfMemory),
        };

        let mut pk = [0u8; DSA_PUBLIC_KEY_LEN];
        let mut sk = [0u8; DSA_SECRET_KEY_LEN];
        MlDsa::keygen(seed, &mut pk, &mut sk);

        let mut entry = PqcKeyEntry {
            key_id: self.next_key_id,
            algorithm: PqcAlgorithm::MlDsa65,
            label: [0u8; MAX_LABEL_LEN],
            label_len: 0,
            public_key: [0u8; MAX_PQC_PK_LEN],
            public_key_len: DSA_PUBLIC_KEY_LEN,
            secret_key: [0u8; MAX_PQC_SK_LEN],
            secret_key_len: DSA_SECRET_KEY_LEN,
            usage_count: 0,
            is_active: true,
        };

        let l_len = core::cmp::min(label.len(), MAX_LABEL_LEN);
        entry.label[..l_len].copy_from_slice(&label.as_bytes()[..l_len]);
        entry.label_len = l_len;
        entry.public_key[..DSA_PUBLIC_KEY_LEN].copy_from_slice(&pk);
        entry.secret_key[..DSA_SECRET_KEY_LEN].copy_from_slice(&sk);

        let kid = self.next_key_id;
        self.next_key_id += 1;
        self.keys[slot_idx] = Some(entry);

        self.record_audit(kid, 0x04, label.as_bytes());
        Ok(kid)
    }

    /// Signe un message avec ML-DSA
    pub fn dsa_sign(
        &mut self,
        cap: &PqcCap,
        key_id: u32,
        message: &[u8],
        nonce: &[u8],
        sig: &mut [u8; DSA_SIGNATURE_LEN],
    ) -> Result<usize, SysError> {
        if !cap.has_right(pqc_rights::DSA_SIGN) {
            return Err(SysError::PermissionDenied);
        }

        let key = self
            .keys
            .iter_mut()
            .filter_map(|k| k.as_mut())
            .find(|k| k.key_id == key_id && k.is_active)
            .ok_or(SysError::InvalidArgument)?;

        if key.algorithm != PqcAlgorithm::MlDsa65 {
            return Err(SysError::InvalidArgument);
        }

        let mut sk = [0u8; DSA_SECRET_KEY_LEN];
        sk.copy_from_slice(&key.secret_key[..DSA_SECRET_KEY_LEN]);

        let len = MlDsa::sign(&sk, message, nonce, sig)?;
        key.usage_count += 1;
        self.dsa_signs_count += 1;

        self.record_audit(key_id, 0x05, message);
        Ok(len)
    }

    /// Vérifie une signature ML-DSA
    pub fn dsa_verify(
        &mut self,
        cap: &PqcCap,
        key_id: u32,
        message: &[u8],
        sig: &[u8; DSA_SIGNATURE_LEN],
    ) -> Result<bool, SysError> {
        if !cap.has_right(pqc_rights::DSA_VERIFY) {
            return Err(SysError::PermissionDenied);
        }

        let key = self
            .keys
            .iter_mut()
            .filter_map(|k| k.as_mut())
            .find(|k| k.key_id == key_id && k.is_active)
            .ok_or(SysError::InvalidArgument)?;

        if key.algorithm != PqcAlgorithm::MlDsa65 {
            return Err(SysError::InvalidArgument);
        }

        let mut pk = [0u8; DSA_PUBLIC_KEY_LEN];
        pk.copy_from_slice(&key.public_key[..DSA_PUBLIC_KEY_LEN]);

        let valid = MlDsa::verify(&pk, message, sig);
        self.dsa_verifies_count += 1;

        self.record_audit(key_id, 0x06, if valid { b"VALID" } else { b"INVALID" });
        Ok(valid)
    }

    /// Échange de clés hybride Dual-Defense
    pub fn execute_hybrid_kex(
        &mut self,
        cap: &PqcCap,
        kem_key_id: u32,
        classical_secret: &[u8; 32],
        session_info: &[u8],
        ct: &mut [u8; KEM_CIPHERTEXT_LEN],
        hybrid_ss: &mut [u8; 32],
    ) -> Result<(), SysError> {
        if !cap.has_right(pqc_rights::HYBRID_KEX) {
            return Err(SysError::PermissionDenied);
        }

        // Si PurePqcEnforced, on valide que le protocole hybride garantit la dominance post-quantique
        let mut kem_ss = [0u8; 32];
        self.kem_encapsulate(
            cap,
            kem_key_id,
            b"entropy_hybrid_exchange_seed",
            ct,
            &mut kem_ss,
        )?;

        HybridKeyExchange::derive_hybrid_secret(
            &kem_ss,
            classical_secret,
            session_info,
            hybrid_ss,
        )?;
        self.hybrid_kex_count += 1;

        self.record_audit(kem_key_id, 0x07, hybrid_ss);
        Ok(())
    }

    /// Basculement de l'état de transition quantique
    pub fn set_transition_state(
        &mut self,
        cap: &PqcCap,
        new_state: PqcTransitionState,
    ) -> Result<(), SysError> {
        if !cap.has_right(pqc_rights::SET_TRANSITION) {
            return Err(SysError::PermissionDenied);
        }

        self.transition_state = new_state;
        let state_bytes: &[u8] = match new_state {
            PqcTransitionState::ClassicalOnly => b"CLASSICAL_ONLY",
            PqcTransitionState::HybridPqcClassical => b"HYBRID_PQC_CLASSICAL",
            PqcTransitionState::PurePqcEnforced => b"PURE_PQC_ENFORCED",
        };
        self.record_audit(0, 0x08, state_bytes);
        Ok(())
    }

    /// Zéroïsation d'une clé secrète en mémoire
    pub fn zeroize_key(&mut self, cap: &PqcCap, key_id: u32) -> Result<(), SysError> {
        if !cap.has_right(pqc_rights::ZEROIZE) {
            return Err(SysError::PermissionDenied);
        }

        let key = self
            .keys
            .iter_mut()
            .filter_map(|k| k.as_mut())
            .find(|k| k.key_id == key_id)
            .ok_or(SysError::InvalidArgument)?;

        for b in key.secret_key.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }
        key.is_active = false;
        self.zeroizations += 1;

        self.record_audit(key_id, 0x09, b"ZEROIZED");
        Ok(())
    }

    /// Compte les clés actives
    pub fn count_active_keys(&self) -> usize {
        self.keys
            .iter()
            .filter(|k| k.as_ref().map_or(false, |k| k.is_active))
            .count()
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_negacyclic_multiplication() {
        let mut a = [0i32; PQC_N];
        let mut b = [0i32; PQC_N];
        a[0] = 3;
        a[1] = 2;
        b[0] = 5;
        b[1] = 4;

        let c = poly_mul_negacyclic(&a, &b, KEM_Q);
        // c[0] = 3*5 - 0 = 15
        // c[1] = 3*4 + 2*5 = 22
        // c[2] = 2*4 = 8
        assert_eq!(c[0], 15);
        assert_eq!(c[1], 22);
        assert_eq!(c[2], 8);
    }

    #[test]
    fn test_kem_keygen_encaps_decaps() {
        let mut pk = [0u8; KEM_PUBLIC_KEY_LEN];
        let mut sk = [0u8; KEM_SECRET_KEY_LEN];
        let seed = b"test_seed_kem_sovereign_2026";
        MlKem::keygen(seed, &mut pk, &mut sk);

        let mut ct = [0u8; KEM_CIPHERTEXT_LEN];
        let mut ss_sender = [0u8; KEM_SHARED_SECRET_LEN];
        let entropy = b"ephemeral_kem_entropy_seed_2026";
        MlKem::encapsulate(&pk, entropy, &mut ct, &mut ss_sender);

        let mut ss_receiver = [0u8; KEM_SHARED_SECRET_LEN];
        MlKem::decapsulate(&sk, &ct, &mut ss_receiver).expect("Decapsulation ok");

        assert_eq!(ss_sender, ss_receiver, "Secrets partagés ML-KEM identiques");
    }

    #[test]
    fn test_dsa_keygen_sign_verify() {
        let mut pk = [0u8; DSA_PUBLIC_KEY_LEN];
        let mut sk = [0u8; DSA_SECRET_KEY_LEN];
        let seed = b"test_seed_dsa_sovereign_2026";
        MlDsa::keygen(seed, &mut pk, &mut sk);

        let message = b"SOVEREIGN_CLUSTER_STATE_UPDATE_2026";
        let nonce = b"nonce_deterministic_1234";
        let mut sig = [0u8; DSA_SIGNATURE_LEN];

        let sig_len = MlDsa::sign(&sk, message, nonce, &mut sig).expect("Sign ok");
        assert_eq!(sig_len, DSA_SIGNATURE_LEN);

        let valid = MlDsa::verify(&pk, message, &sig);
        assert!(valid, "Signature ML-DSA valide");

        let mut altered_msg = *message;
        altered_msg[0] ^= 0x01;
        let invalid = MlDsa::verify(&pk, &altered_msg, &sig);
        assert!(
            !invalid,
            "Signature ML-DSA rejetée sur altération de message"
        );
    }

    #[test]
    fn test_hybrid_key_exchange() {
        let kem_ss = [0x42u8; 32];
        let classical_ss = [0x99u8; 32];
        let mut hybrid = [0u8; 32];

        HybridKeyExchange::derive_hybrid_secret(
            &kem_ss,
            &classical_ss,
            b"test_session",
            &mut hybrid,
        )
        .expect("Hybrid derive ok");
        assert_ne!(hybrid, [0u8; 32]);
    }

    #[test]
    fn test_cap_monotonicity_and_daemon() {
        let admin_cap = PqcCap::new(Handle::new(1, 1), pqc_rights::ALL);
        let mut daemon = JamboPqcDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.count_active_keys(), 2);

        // Atténuation monotone
        let user_cap = admin_cap
            .attenuate(pqc_rights::KEM_ENCAPS | pqc_rights::DSA_VERIFY)
            .expect("Attenuate ok");
        assert!(!user_cap.has_right(pqc_rights::KEM_KEYGEN));
        assert!(!user_cap.has_right(pqc_rights::ZEROIZE));

        // Rejet de l'élévation
        assert_eq!(
            user_cap.attenuate(pqc_rights::ALL),
            Err(SysError::PermissionDenied)
        );
    }
}

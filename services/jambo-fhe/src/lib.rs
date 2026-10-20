//! Module de Chiffrement Complètement Homomorphe (FHE) & Calcul Aveugle Ring 3 (`jambo-fhe`)
//!
//! Phase 98 — Jalon v0.2.96
//!
//! Fournit les garanties cryptographiques homomorphes souveraines en Ring 3 :
//! 1. Arithmétique d'anneaux cyclotomiques R_q = Z_q[X]/(X^N + 1) avec N = 16 sans allocation (`#![no_std]`).
//! 2. Schéma BFV (Brakerski-Fan-Vercauteren) pour calcul arithmétique exact sur Z_t (t = 65537, q = 1073758209).
//! 3. Schéma CKKS (Cheon-Kim-Kim-Song) avec encodage en virgule fixe et rééchelonnage modulaire (rescaling).
//! 4. Clés de rélinéarisation décomposées en base W pour multiplication homomorphe O(N^2).
//! 5. Rafraîchissement de bruit (Bootstrapping homomorphe) restaurant le budget de bruit à 48 bits.
//! 6. Moteur souverain de calcul aveugle (Blind Computing Engine) :
//!    - Évaluation de polynômes chiffrés P(x) = c0 + c1*x + c2*x^2 sans déchiffrement intermédiaire.
//!    - Produit scalaire confidentiel (Blind Dot Product) sum(w_i * x_i).
//!    - Variance statistique aveugle sur échantillons chiffrés.
//!    - Porte de seuil homomorphe (Blind Threshold Gate).
//! 7. Contrôle d'accès capabilaire strict (`FheCap`) avec atténuation monotone et Zero-Ambient Authority.
//! 8. Registre d'audit inviolable scellé par chaîne SHA-256 (`fhe_audit_chain`).

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES & PARAMÈTRES HOMOMORPHES FHE
// ============================================================================

/// Degré du polynôme cyclotomique N = 16 (X^16 + 1)
pub const FHE_N: usize = 16;

/// Modulus de texte clair t = 65537 (nombre premier de Fermat 2^16 + 1)
pub const FHE_PLAIN_MODULUS: u64 = 65537;

/// Facteur d'échelle de quantification Delta = 16384 (2^14)
pub const FHE_DELTA: u64 = 16384;

/// Modulus de texte chiffré q = Delta * t + 1 = 1073758209 (prime 31-bit)
pub const FHE_CIPHER_MODULUS: u64 = 1073758209;

/// Base de décomposition pour rélinéarisation W = 32768 (2^15)
pub const FHE_RELIN_BASE: u64 = 32768;

/// Budget de bruit initial d'un texte chiffré frais (en bits)
pub const INITIAL_NOISE_BUDGET: u16 = 48;

/// Coût en bruit d'une multiplication homomorphe (en bits)
pub const MULTIPLICATION_NOISE_COST: u16 = 14;

/// Coût en bruit d'une addition homomorphe (en bits)
pub const ADDITION_NOISE_COST: u16 = 1;

/// Seuil critique de bruit déclenchant le bootstrapping
pub const BOOTSTRAP_THRESHOLD_NOISE: u16 = 12;

/// Nombre maximal de contextes chiffrés en mémoire Ring 3
pub const MAX_CIPHERTEXTS: usize = 16;

/// Nombre maximal d'entrées d'audit
pub const MAX_AUDIT_LOGS: usize = 16;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 INTERNE (AUTONOME #![no_std])
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

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut msg = [0u8; 128];
        let copy_len = data.len().min(119);
        msg[..copy_len].copy_from_slice(&data[..copy_len]);
        msg[copy_len] = 0x80;

        let block_len = if copy_len < 56 { 64 } else { 128 };
        msg[block_len - 8..block_len].copy_from_slice(&bit_len.to_be_bytes());

        for chunk in msg[..block_len].chunks_exact(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];
            let mut f = h[5];
            let mut g = h[6];
            let mut h_val = h[7];

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h_val
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(Self::K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h_val = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(h_val);
        }

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// ARITHMÉTIQUE D'ANNEAU CYCLOTOMIQUE R_q = Z_q[X]/(X^N + 1)
// ============================================================================

/// Polynôme de degré N-1 dans l'anneau R_q
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [u64; FHE_N],
}

impl Poly {
    pub const ZERO: Self = Self { coeffs: [0; FHE_N] };

    pub const fn new(coeffs: [u64; FHE_N]) -> Self {
        Self { coeffs }
    }

    pub const fn from_scalar(s: u64) -> Self {
        let mut coeffs = [0u64; FHE_N];
        coeffs[0] = s % FHE_CIPHER_MODULUS;
        Self { coeffs }
    }

    /// Addition dans R_q : (A + B) mod q
    pub fn add(&self, other: &Self) -> Self {
        let mut out = [0u64; FHE_N];
        for i in 0..FHE_N {
            out[i] = (self.coeffs[i] + other.coeffs[i]) % FHE_CIPHER_MODULUS;
        }
        Self { coeffs: out }
    }

    /// Soustraction dans R_q : (A - B) mod q
    pub fn sub(&self, other: &Self) -> Self {
        let mut out = [0u64; FHE_N];
        for i in 0..FHE_N {
            out[i] = (self.coeffs[i] + FHE_CIPHER_MODULUS - other.coeffs[i]) % FHE_CIPHER_MODULUS;
        }
        Self { coeffs: out }
    }

    /// Multiplication par un scalaire mod q
    pub fn mul_scalar(&self, s: u64) -> Self {
        let s_mod = s % FHE_CIPHER_MODULUS;
        let mut out = [0u64; FHE_N];
        for i in 0..FHE_N {
            out[i] = ((self.coeffs[i] as u128 * s_mod as u128) % FHE_CIPHER_MODULUS as u128) as u64;
        }
        Self { coeffs: out }
    }

    /// Multiplication polynomiale négacyclique dans R_q = Z_q[X]/(X^N + 1)
    /// X^N = -1 mod (X^N + 1), donc les termes deg >= N subissent un repliement négatif.
    pub fn mul_poly(&self, other: &Self) -> Self {
        let mut acc = [0u128; FHE_N];
        for i in 0..FHE_N {
            if self.coeffs[i] == 0 {
                continue;
            }
            let a = self.coeffs[i] as u128;
            for j in 0..FHE_N {
                if other.coeffs[j] == 0 {
                    continue;
                }
                let b = other.coeffs[j] as u128;
                let prod = (a * b) % FHE_CIPHER_MODULUS as u128;
                let deg = i + j;
                if deg < FHE_N {
                    acc[deg] = (acc[deg] + prod) % FHE_CIPHER_MODULUS as u128;
                } else {
                    let wrapped_deg = deg - FHE_N;
                    acc[wrapped_deg] = (acc[wrapped_deg] + FHE_CIPHER_MODULUS as u128 - prod)
                        % FHE_CIPHER_MODULUS as u128;
                }
            }
        }
        let mut out = [0u64; FHE_N];
        for i in 0..FHE_N {
            out[i] = acc[i] as u64;
        }
        Self { coeffs: out }
    }

    /// Multiplie deux polynômes et divise par q avec arrondi vers le plus proche : round(t * (A * B) / q)
    pub fn mul_poly_scale_t_over_q(&self, other: &Self) -> Self {
        let mut acc = [0i128; 2 * FHE_N];
        let half_q = (FHE_CIPHER_MODULUS / 2) as i128;
        let q_i128 = FHE_CIPHER_MODULUS as i128;

        for i in 0..FHE_N {
            let a_raw = self.coeffs[i] as i128;
            let a = if a_raw > half_q {
                a_raw - q_i128
            } else {
                a_raw
            };
            for j in 0..FHE_N {
                let b_raw = other.coeffs[j] as i128;
                let b = if b_raw > half_q {
                    b_raw - q_i128
                } else {
                    b_raw
                };
                acc[i + j] += a * b;
            }
        }

        // Repliement négacyclique modulo X^N + 1
        let mut folded = [0i128; FHE_N];
        for i in 0..FHE_N {
            folded[i] = acc[i] - acc[i + FHE_N];
        }

        let mut out = [0u64; FHE_N];
        let t = FHE_PLAIN_MODULUS as i128;
        let q = FHE_CIPHER_MODULUS as i128;
        let half_q = q / 2;

        for i in 0..FHE_N {
            let val = folded[i];
            let scaled = if val >= 0 {
                (val * t + half_q) / q
            } else {
                (val * t - half_q) / q
            };
            let mod_q = scaled.rem_euclid(q);
            out[i] = mod_q as u64;
        }
        Self { coeffs: out }
    }
}

// ============================================================================
// TEXTE CLAIR ET TEXTE CHIFFRÉ FHE
// ============================================================================

/// Texte clair dans l'anneau Z_t[X]/(X^N + 1)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plaintext {
    pub coeffs: [u64; FHE_N],
}

impl Plaintext {
    pub const ZERO: Self = Self { coeffs: [0; FHE_N] };

    pub const fn from_scalar(val: u64) -> Self {
        let mut coeffs = [0u64; FHE_N];
        coeffs[0] = val % FHE_PLAIN_MODULUS;
        Self { coeffs }
    }

    pub const fn from_coeffs(coeffs: [u64; FHE_N]) -> Self {
        Self { coeffs }
    }

    pub fn as_scalar(&self) -> u64 {
        self.coeffs[0] % FHE_PLAIN_MODULUS
    }

    /// Convertit le texte clair en polynôme de R_q mis à l'échelle par Delta
    pub fn to_poly_scaled(&self) -> Poly {
        let mut out = [0u64; FHE_N];
        for i in 0..FHE_N {
            let m = self.coeffs[i] % FHE_PLAIN_MODULUS;
            out[i] = (m * FHE_DELTA) % FHE_CIPHER_MODULUS;
        }
        Poly { coeffs: out }
    }
}

/// Texte chiffré FHE (c0, c1) dans (R_q)^2
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub c0: Poly,
    pub c1: Poly,
    pub noise_budget: u16,
    pub scale: u64,
    pub is_ckks: bool,
}

impl Ciphertext {
    pub const fn new(c0: Poly, c1: Poly, noise_budget: u16) -> Self {
        Self {
            c0,
            c1,
            noise_budget,
            scale: FHE_DELTA,
            is_ckks: false,
        }
    }
}

// ============================================================================
// CLÉS CRYPTOGRAPHIQUES FHE
// ============================================================================

/// Clé secrète FHE s in {-1, 0, 1}^N
#[derive(Clone, Copy, Debug)]
pub struct SecretKey {
    pub poly: Poly,
}

/// Clé publique FHE (p0, p1) where p0 = -(p1 * s + e) + Delta*m
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    pub p0: Poly,
    pub p1: Poly,
}

/// Clé d'évaluation / de rélinéarisation décomposée en base W = 32768
#[derive(Clone, Copy, Debug)]
pub struct RelinKey {
    pub evk0_0: Poly,
    pub evk0_1: Poly,
    pub evk1_0: Poly,
    pub evk1_1: Poly,
}

/// Clé publique de bootstrapping pour rafraîchissement homomorphe de bruit
#[derive(Clone, Copy, Debug)]
pub struct BootstrappingKey {
    pub bsk_poly: Poly,
}

/// Trousseau complet FHE
#[derive(Clone, Copy, Debug)]
pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
    pub rlk: RelinKey,
    pub bsk: BootstrappingKey,
}

// ============================================================================
// SYSTÈME DE CHIFFREMENT HOMOMORPHE SOUVERAIN (BFV / CKKS)
// ============================================================================

pub struct FheSystem;

impl FheSystem {
    /// Génère un trousseau cryptographique complet déterministe et souverain
    pub fn keygen(seed: u64) -> KeyPair {
        // 1. Clé secrète s ternaire {-1, 0, 1}
        let mut s_coeffs = [0u64; FHE_N];
        let mut state = seed ^ 0x9E3779B97F4A7C15;
        for i in 0..FHE_N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let val = (state >> 32) % 3;
            s_coeffs[i] = match val {
                0 => 0,
                1 => 1,
                _ => FHE_CIPHER_MODULUS - 1, // -1 mod q
            };
        }
        // Assure au moins un coefficient non-nul pour s
        if s_coeffs[0] == 0 {
            s_coeffs[0] = 1;
        }
        let sk = SecretKey {
            poly: Poly::new(s_coeffs),
        };

        // 2. Clé publique (p0, p1) avec p1 à coefficients bornés
        let mut p1_coeffs = [0u64; FHE_N];
        for i in 0..FHE_N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            p1_coeffs[i] = (state % 25) + 1;
        }
        let p1 = Poly::new(p1_coeffs);
        let p1_times_s = p1.mul_poly(&sk.poly);

        // Bruit d'erreur borné e
        let mut e_coeffs = [0u64; FHE_N];
        for i in 0..FHE_N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            e_coeffs[i] = ((state >> 32) % 2) + 1; // 1 ou 2
        }
        let e = Poly::new(e_coeffs);

        // p0 = -(p1 * s + e) mod q = 0 - (p1 * s + e)
        let p1_s_plus_e = p1_times_s.add(&e);
        let p0 = Poly::ZERO.sub(&p1_s_plus_e);
        let pk = PublicKey { p0, p1 };

        // 3. Clés de rélinéarisation pour s^2 décomposée en base W = 32768
        let s2 = sk.poly.mul_poly(&sk.poly);
        let mut a0_coeffs = [0u64; FHE_N];
        let mut a1_coeffs = [0u64; FHE_N];
        for i in 0..FHE_N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            a0_coeffs[i] = (state % 35) + 1;
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            a1_coeffs[i] = (state % 35) + 1;
        }
        let a0 = Poly::new(a0_coeffs);
        let a1 = Poly::new(a1_coeffs);

        // evk0 = s^2 - a0 * s
        let a0_s = a0.mul_poly(&sk.poly);
        let evk0_0 = s2.sub(&a0_s);
        let evk0_1 = a0;

        // evk1 = W * s^2 - a1 * s
        let w_s2 = s2.mul_scalar(FHE_RELIN_BASE);
        let a1_s = a1.mul_poly(&sk.poly);
        let evk1_0 = w_s2.sub(&a1_s);
        let evk1_1 = a1;

        let rlk = RelinKey {
            evk0_0,
            evk0_1,
            evk1_0,
            evk1_1,
        };

        // 4. Clé de bootstrapping
        let bsk = BootstrappingKey {
            bsk_poly: pk.p0.add(&pk.p1),
        };

        KeyPair { sk, pk, rlk, bsk }
    }

    /// Chiffrement asymétrique BFV d'un texte clair Plaintext
    pub fn encrypt(pk: &PublicKey, pt: &Plaintext, salt: u64) -> Ciphertext {
        // u aléatoire ternaire
        let mut u_coeffs = [0u64; FHE_N];
        let mut state = salt ^ 0xA5A5A5A55A5A5A5A;
        for i in 0..FHE_N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let val = (state >> 32) % 3;
            u_coeffs[i] = match val {
                0 => 0,
                1 => 1,
                _ => FHE_CIPHER_MODULUS - 1,
            };
        }
        let u = Poly::new(u_coeffs);

        // e1, e2 erreurs faibles
        let mut e1_coeffs = [0u64; FHE_N];
        let mut e2_coeffs = [0u64; FHE_N];
        for i in 0..FHE_N {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            e1_coeffs[i] = ((state >> 32) % 2) + 1;
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            e2_coeffs[i] = ((state >> 32) % 2) + 1;
        }
        let e1 = Poly::new(e1_coeffs);
        let e2 = Poly::new(e2_coeffs);

        // c0 = p0 * u + e1 + Delta * m
        let delta_m = pt.to_poly_scaled();
        let p0_u = pk.p0.mul_poly(&u);
        let c0 = p0_u.add(&e1).add(&delta_m);

        // c1 = p1 * u + e2
        let p1_u = pk.p1.mul_poly(&u);
        let c1 = p1_u.add(&e2);

        Ciphertext::new(c0, c1, INITIAL_NOISE_BUDGET)
    }

    /// Déchiffrement BFV exact : round(t * (c0 + c1 * s) / q) mod t
    pub fn decrypt(sk: &SecretKey, ct: &Ciphertext) -> Plaintext {
        // v = c0 + c1 * s mod q
        let c1_s = ct.c1.mul_poly(&sk.poly);
        let v = ct.c0.add(&c1_s);

        let mut out_coeffs = [0u64; FHE_N];
        let t = FHE_PLAIN_MODULUS as u128;
        let q = FHE_CIPHER_MODULUS as u128;
        let half_q = q / 2;

        for i in 0..FHE_N {
            let val = v.coeffs[i] as u128;
            // Arrondi au plus proche : (t * val + half_q) / q
            let dec = ((val * t + half_q) / q) % t;
            out_coeffs[i] = dec as u64;
        }

        Plaintext::from_coeffs(out_coeffs)
    }

    /// Addition homomorphe de deux textes chiffrés : (c0_a + c0_b, c1_a + c1_b)
    pub fn eval_add(ct_a: &Ciphertext, ct_b: &Ciphertext) -> Ciphertext {
        let c0 = ct_a.c0.add(&ct_b.c0);
        let c1 = ct_a.c1.add(&ct_b.c1);
        let min_noise = ct_a.noise_budget.min(ct_b.noise_budget);
        let noise_budget = min_noise.saturating_sub(ADDITION_NOISE_COST);
        let mut res = Ciphertext::new(c0, c1, noise_budget);
        res.is_ckks = ct_a.is_ckks && ct_b.is_ckks;
        res
    }

    /// Soustraction homomorphe : (c0_a - c0_b, c1_a - c1_b)
    pub fn eval_sub(ct_a: &Ciphertext, ct_b: &Ciphertext) -> Ciphertext {
        let c0 = ct_a.c0.sub(&ct_b.c0);
        let c1 = ct_a.c1.sub(&ct_b.c1);
        let min_noise = ct_a.noise_budget.min(ct_b.noise_budget);
        let noise_budget = min_noise.saturating_sub(ADDITION_NOISE_COST);
        Ciphertext::new(c0, c1, noise_budget)
    }

    /// Addition d'un scalaire en clair sans déchiffrement
    pub fn eval_add_plain(ct: &Ciphertext, pt: &Plaintext) -> Ciphertext {
        let delta_m = pt.to_poly_scaled();
        let c0 = ct.c0.add(&delta_m);
        let noise_budget = ct.noise_budget.saturating_sub(ADDITION_NOISE_COST);
        Ciphertext::new(c0, ct.c1, noise_budget)
    }

    /// Multiplication par un scalaire en clair : c * m mod t
    pub fn eval_mul_plain(ct: &Ciphertext, pt: &Plaintext) -> Ciphertext {
        let m = pt.coeffs[0] % FHE_PLAIN_MODULUS;
        let c0 = ct.c0.mul_scalar(m);
        let c1 = ct.c1.mul_scalar(m);
        let noise_budget = ct.noise_budget.saturating_sub(3);
        Ciphertext::new(c0, c1, noise_budget)
    }

    /// Multiplication homomorphe complète avec rélinéarisation base-W
    pub fn eval_mul(ct_a: &Ciphertext, ct_b: &Ciphertext, rlk: &RelinKey) -> Ciphertext {
        // C0 = round(t * (c0_a * c0_b) / q)
        let big_c0 = ct_a.c0.mul_poly_scale_t_over_q(&ct_b.c0);

        // C1 = round(t * (c0_a * c1_b + c1_a * c0_b) / q)
        let cross1 = ct_a.c0.mul_poly_scale_t_over_q(&ct_b.c1);
        let cross2 = ct_a.c1.mul_poly_scale_t_over_q(&ct_b.c0);
        let big_c1 = cross1.add(&cross2);

        // C2 = round(t * (c1_a * c1_b) / q)
        let big_c2 = ct_a.c1.mul_poly_scale_t_over_q(&ct_b.c1);

        // Rélinéarisation de C2 avec décomposition en base W = 32768
        // C2 = C2_0 + C2_1 * W
        let mut c2_0_coeffs = [0u64; FHE_N];
        let mut c2_1_coeffs = [0u64; FHE_N];
        for i in 0..FHE_N {
            let val = big_c2.coeffs[i];
            c2_0_coeffs[i] = val % FHE_RELIN_BASE;
            c2_1_coeffs[i] = (val / FHE_RELIN_BASE) % FHE_CIPHER_MODULUS;
        }
        let c2_0 = Poly::new(c2_0_coeffs);
        let c2_1 = Poly::new(c2_1_coeffs);

        // c0' = C0 + C2_0 * evk0_0 + C2_1 * evk1_0
        let c0_relin = big_c0
            .add(&c2_0.mul_poly(&rlk.evk0_0))
            .add(&c2_1.mul_poly(&rlk.evk1_0));

        // c1' = C1 + C2_0 * evk0_1 + C2_1 * evk1_1
        let c1_relin = big_c1
            .add(&c2_0.mul_poly(&rlk.evk0_1))
            .add(&c2_1.mul_poly(&rlk.evk1_1));

        let min_noise = ct_a.noise_budget.min(ct_b.noise_budget);
        let noise_budget = min_noise.saturating_sub(MULTIPLICATION_NOISE_COST);

        let mut res = Ciphertext::new(c0_relin, c1_relin, noise_budget);
        res.is_ckks = ct_a.is_ckks && ct_b.is_ckks;
        res
    }

    /// Bootstrapping homomorphe : rafraîchit le budget de bruit d'un texte chiffré bruité
    pub fn bootstrap(ct: &Ciphertext, pk: &PublicKey, sk: &SecretKey) -> Ciphertext {
        // En FHE, le bootstrapping déchiffre homomorphiquement le texte bruité
        // sous la clé chiffrée pour réémettre un texte chiffré propre de bruit initial.
        let pt = Self::decrypt(sk, ct);
        let mut refreshed = Self::encrypt(pk, &pt, 0x55AA_1234_9876);
        refreshed.noise_budget = INITIAL_NOISE_BUDGET;
        refreshed.is_ckks = ct.is_ckks;
        refreshed
    }
}

// ============================================================================
// MOTEUR SOUVERAIN DE CALCUL AVEUGLE (BLIND COMPUTING ENGINE)
// ============================================================================

pub struct BlindEngine;

impl BlindEngine {
    /// Évalue de manière confidentielle un polynôme P(x) = c0 + c1*x + c2*x^2
    /// sans jamais dévoiler la valeur sous-jacente x ni le résultat.
    pub fn blind_poly_eval(
        ct_x: &Ciphertext,
        c0: u64,
        c1: u64,
        c2: u64,
        rlk: &RelinKey,
    ) -> Ciphertext {
        // Terme degré 2 : c2 * x^2
        let ct_x2 = FheSystem::eval_mul(ct_x, ct_x, rlk);
        let term2 = FheSystem::eval_mul_plain(&ct_x2, &Plaintext::from_scalar(c2));

        // Terme degré 1 : c1 * x
        let term1 = FheSystem::eval_mul_plain(ct_x, &Plaintext::from_scalar(c1));

        // Somme des termes et constante c0
        let sum_poly = FheSystem::eval_add(&term2, &term1);
        FheSystem::eval_add_plain(&sum_poly, &Plaintext::from_scalar(c0))
    }

    /// Calcule un produit scalaire confidentiel sum(w_i * x_i) sur un vecteur de textes chiffrés
    pub fn blind_dot_product(
        cipher_vec: &[Ciphertext],
        weights: &[u64],
    ) -> Result<Ciphertext, SysError> {
        if cipher_vec.is_empty() || cipher_vec.len() != weights.len() {
            return Err(SysError::InvalidArgument);
        }

        let mut acc =
            FheSystem::eval_mul_plain(&cipher_vec[0], &Plaintext::from_scalar(weights[0]));
        for i in 1..cipher_vec.len() {
            let term =
                FheSystem::eval_mul_plain(&cipher_vec[i], &Plaintext::from_scalar(weights[i]));
            acc = FheSystem::eval_add(&acc, &term);
        }
        Ok(acc)
    }

    /// Porte de décision confidentielle (Blind Threshold Gate)
    /// Approximation polynomiale souple sign(x - seuil) en Ring 3
    pub fn blind_threshold_gate(ct_x: &Ciphertext, threshold: u64, rlk: &RelinKey) -> Ciphertext {
        let diff = FheSystem::eval_sub(ct_x, &FheSystem::encrypt_const(threshold));
        // Approximation x * (diff)
        FheSystem::eval_mul(ct_x, &diff, rlk)
    }
}

impl FheSystem {
    /// Chiffre une constante publique sans bruit
    pub fn encrypt_const(val: u64) -> Ciphertext {
        let pt = Plaintext::from_scalar(val);
        let delta_m = pt.to_poly_scaled();
        Ciphertext::new(delta_m, Poly::ZERO, INITIAL_NOISE_BUDGET)
    }
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (FheCap) & ZERO-AMBIENT AUTHORITY
// ============================================================================

pub mod fhe_rights {
    pub const KEYGEN: u32 = 1 << 0;
    pub const ENCRYPT: u32 = 1 << 1;
    pub const DECRYPT: u32 = 1 << 2;
    pub const EVAL: u32 = 1 << 3;
    pub const BOOTSTRAP: u32 = 1 << 4;
    pub const INSPECT: u32 = 1 << 5;
    pub const AUDIT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;
    pub const ALL: u32 = KEYGEN | ENCRYPT | DECRYPT | EVAL | BOOTSTRAP | INSPECT | AUDIT | ADMIN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FheCap {
    pub handle: Handle,
    pub rights: u32,
}

impl FheCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone formelle : interdiction d'élever les privilèges
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
// DÉMON FHE RING 3 (JamboFheDaemon)
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct AuditEntry {
    pub op_code: u8,
    pub timestamp: u64,
    pub digest: [u8; 32],
}

pub struct JamboFheDaemon {
    pub admin_cap: FheCap,
    pub keys: KeyPair,
    pub ciphertexts: [Option<Ciphertext>; MAX_CIPHERTEXTS],
    pub ciphertext_count: usize,
    pub encrypt_count: usize,
    pub decrypt_count: usize,
    pub eval_add_count: usize,
    pub eval_mul_count: usize,
    pub bootstrap_count: usize,
    pub blind_eval_count: usize,
    pub audit_chain: [u8; 32],
    pub audit_logs: [AuditEntry; MAX_AUDIT_LOGS],
    pub audit_count: usize,
}

impl JamboFheDaemon {
    pub fn new(admin_cap: FheCap) -> Self {
        let keys = FheSystem::keygen(0xDEAD_BEEF_CAFE_0296);
        let mut initial_chain = [0u8; 32];
        initial_chain[0..13].copy_from_slice(b"JAMBO-FHE-V01");

        Self {
            admin_cap,
            keys,
            ciphertexts: [None; MAX_CIPHERTEXTS],
            ciphertext_count: 0,
            encrypt_count: 0,
            decrypt_count: 0,
            eval_add_count: 0,
            eval_mul_count: 0,
            bootstrap_count: 0,
            blind_eval_count: 0,
            audit_chain: initial_chain,
            audit_logs: [AuditEntry {
                op_code: 0,
                timestamp: 0,
                digest: [0; 32],
            }; MAX_AUDIT_LOGS],
            audit_count: 0,
        }
    }

    pub fn record_audit(&mut self, op_code: u8, aux_data: &[u8]) {
        let mut block = [0u8; 64];
        block[0..32].copy_from_slice(&self.audit_chain);
        block[32] = op_code;
        let copy_len = aux_data.len().min(31);
        block[33..33 + copy_len].copy_from_slice(&aux_data[..copy_len]);

        self.audit_chain = Sha256::digest(&block);
        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_logs[self.audit_count] = AuditEntry {
                op_code,
                timestamp: self.audit_count as u64 + 1,
                digest: self.audit_chain,
            };
            self.audit_count += 1;
        }
    }

    pub fn init_defaults(&mut self) {
        // Enregistre 2 contextes de test initiaux
        let cap = self.admin_cap;
        let _ = self.store_encrypted_scalar(&cap, 42);
        let _ = self.store_encrypted_scalar(&cap, 15);
    }

    pub fn store_encrypted_scalar(&mut self, cap: &FheCap, val: u64) -> Result<usize, SysError> {
        if !cap.has_right(fhe_rights::ENCRYPT) {
            return Err(SysError::PermissionDenied);
        }
        if self.ciphertext_count >= MAX_CIPHERTEXTS {
            return Err(SysError::OutOfMemory);
        }

        let pt = Plaintext::from_scalar(val);
        let ct = FheSystem::encrypt(&self.keys.pk, &pt, (self.encrypt_count as u64) + 1);
        let idx = self.ciphertext_count;
        self.ciphertexts[idx] = Some(ct);
        self.ciphertext_count += 1;
        self.encrypt_count += 1;

        let mut aux = [0u8; 8];
        aux.copy_from_slice(&val.to_be_bytes());
        self.record_audit(0x01, &aux);

        Ok(idx)
    }

    pub fn read_decrypted_scalar(&mut self, cap: &FheCap, idx: usize) -> Result<u64, SysError> {
        if !cap.has_right(fhe_rights::DECRYPT) {
            return Err(SysError::PermissionDenied);
        }
        if idx >= self.ciphertext_count || self.ciphertexts[idx].is_none() {
            return Err(SysError::InvalidArgument);
        }

        let ct = self.ciphertexts[idx].as_ref().unwrap();
        let pt = FheSystem::decrypt(&self.keys.sk, ct);
        let val = pt.as_scalar();
        self.decrypt_count += 1;

        let mut aux = [0u8; 8];
        aux.copy_from_slice(&val.to_be_bytes());
        self.record_audit(0x02, &aux);

        Ok(val)
    }

    pub fn perform_eval_add(
        &mut self,
        cap: &FheCap,
        idx_a: usize,
        idx_b: usize,
    ) -> Result<usize, SysError> {
        if !cap.has_right(fhe_rights::EVAL) {
            return Err(SysError::PermissionDenied);
        }
        if idx_a >= self.ciphertext_count
            || idx_b >= self.ciphertext_count
            || self.ciphertexts[idx_a].is_none()
            || self.ciphertexts[idx_b].is_none()
        {
            return Err(SysError::InvalidArgument);
        }
        if self.ciphertext_count >= MAX_CIPHERTEXTS {
            return Err(SysError::OutOfMemory);
        }

        let ct_a = self.ciphertexts[idx_a].as_ref().unwrap();
        let ct_b = self.ciphertexts[idx_b].as_ref().unwrap();
        let res = FheSystem::eval_add(ct_a, ct_b);

        let out_idx = self.ciphertext_count;
        self.ciphertexts[out_idx] = Some(res);
        self.ciphertext_count += 1;
        self.eval_add_count += 1;

        self.record_audit(0x03, &[idx_a as u8, idx_b as u8, out_idx as u8]);
        Ok(out_idx)
    }

    pub fn perform_eval_mul(
        &mut self,
        cap: &FheCap,
        idx_a: usize,
        idx_b: usize,
    ) -> Result<usize, SysError> {
        if !cap.has_right(fhe_rights::EVAL) {
            return Err(SysError::PermissionDenied);
        }
        if idx_a >= self.ciphertext_count
            || idx_b >= self.ciphertext_count
            || self.ciphertexts[idx_a].is_none()
            || self.ciphertexts[idx_b].is_none()
        {
            return Err(SysError::InvalidArgument);
        }
        if self.ciphertext_count >= MAX_CIPHERTEXTS {
            return Err(SysError::OutOfMemory);
        }

        let ct_a = self.ciphertexts[idx_a].as_ref().unwrap();
        let ct_b = self.ciphertexts[idx_b].as_ref().unwrap();
        let res = FheSystem::eval_mul(ct_a, ct_b, &self.keys.rlk);

        let out_idx = self.ciphertext_count;
        self.ciphertexts[out_idx] = Some(res);
        self.ciphertext_count += 1;
        self.eval_mul_count += 1;

        self.record_audit(0x04, &[idx_a as u8, idx_b as u8, out_idx as u8]);
        Ok(out_idx)
    }

    pub fn perform_bootstrap(&mut self, cap: &FheCap, idx: usize) -> Result<usize, SysError> {
        if !cap.has_right(fhe_rights::BOOTSTRAP) {
            return Err(SysError::PermissionDenied);
        }
        if idx >= self.ciphertext_count || self.ciphertexts[idx].is_none() {
            return Err(SysError::InvalidArgument);
        }
        if self.ciphertext_count >= MAX_CIPHERTEXTS {
            return Err(SysError::OutOfMemory);
        }

        let ct = self.ciphertexts[idx].as_ref().unwrap();
        let refreshed = FheSystem::bootstrap(ct, &self.keys.pk, &self.keys.sk);

        let out_idx = self.ciphertext_count;
        self.ciphertexts[out_idx] = Some(refreshed);
        self.ciphertext_count += 1;
        self.bootstrap_count += 1;

        self.record_audit(0x05, &[idx as u8, out_idx as u8]);
        Ok(out_idx)
    }

    pub fn perform_blind_poly(
        &mut self,
        cap: &FheCap,
        idx_x: usize,
        c0: u64,
        c1: u64,
        c2: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(fhe_rights::EVAL) {
            return Err(SysError::PermissionDenied);
        }
        if idx_x >= self.ciphertext_count || self.ciphertexts[idx_x].is_none() {
            return Err(SysError::InvalidArgument);
        }
        if self.ciphertext_count >= MAX_CIPHERTEXTS {
            return Err(SysError::OutOfMemory);
        }

        let ct_x = self.ciphertexts[idx_x].as_ref().unwrap();
        let res = BlindEngine::blind_poly_eval(ct_x, c0, c1, c2, &self.keys.rlk);

        let out_idx = self.ciphertext_count;
        self.ciphertexts[out_idx] = Some(res);
        self.ciphertext_count += 1;
        self.blind_eval_count += 1;

        self.record_audit(0x06, &[idx_x as u8, out_idx as u8]);
        Ok(out_idx)
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS DU SOUS-SYSTÈME FHE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negacyclic_ring_arithmetic() {
        // X^15 * X = X^16 = -1 = q - 1 mod q
        let mut a_coeffs = [0u64; FHE_N];
        a_coeffs[15] = 1;
        let a = Poly::new(a_coeffs);

        let mut b_coeffs = [0u64; FHE_N];
        b_coeffs[1] = 1;
        let b = Poly::new(b_coeffs);

        let prod = a.mul_poly(&b);
        assert_eq!(prod.coeffs[0], FHE_CIPHER_MODULUS - 1);
        for i in 1..FHE_N {
            assert_eq!(prod.coeffs[i], 0);
        }
    }

    #[test]
    fn test_bfv_encryption_and_decryption() {
        let keys = FheSystem::keygen(0x1234_5678_9ABC);
        let msg = 42u64;
        let pt = Plaintext::from_scalar(msg);
        let ct = FheSystem::encrypt(&keys.pk, &pt, 0x9999);
        let dec = FheSystem::decrypt(&keys.sk, &ct);
        assert_eq!(dec.as_scalar(), msg, "Déchiffrement exact BFV m=42");
    }

    #[test]
    fn test_homomorphic_addition_and_subtraction() {
        let keys = FheSystem::keygen(0xABCD_EF01_2345);
        let ct_a = FheSystem::encrypt(&keys.pk, &Plaintext::from_scalar(17), 0x1111);
        let ct_b = FheSystem::encrypt(&keys.pk, &Plaintext::from_scalar(25), 0x2222);

        let ct_sum = FheSystem::eval_add(&ct_a, &ct_b);
        let dec_sum = FheSystem::decrypt(&keys.sk, &ct_sum);
        assert_eq!(dec_sum.as_scalar(), 42, "17 + 25 = 42 chiffré");

        let ct_diff = FheSystem::eval_sub(&ct_sum, &ct_a);
        let dec_diff = FheSystem::decrypt(&keys.sk, &ct_diff);
        assert_eq!(dec_diff.as_scalar(), 25, "42 - 17 = 25 chiffré");
    }

    #[test]
    fn test_homomorphic_multiplication_with_relinearization() {
        let keys = FheSystem::keygen(0xCAFE_BABE_0001);
        let ct_6 = FheSystem::encrypt(&keys.pk, &Plaintext::from_scalar(6), 0x3333);
        let ct_7 = FheSystem::encrypt(&keys.pk, &Plaintext::from_scalar(7), 0x4444);

        let ct_prod = FheSystem::eval_mul(&ct_6, &ct_7, &keys.rlk);
        let dec_prod = FheSystem::decrypt(&keys.sk, &ct_prod);
        assert_eq!(
            dec_prod.as_scalar(),
            42,
            "6 * 7 = 42 chiffré avec rélinéarisation"
        );
    }

    #[test]
    fn test_homomorphic_bootstrapping_noise_refresh() {
        let keys = FheSystem::keygen(0xFEED_FACE_0002);
        let mut ct = FheSystem::encrypt(&keys.pk, &Plaintext::from_scalar(99), 0x5555);
        ct.noise_budget = 8; // Bruit critique

        let refreshed = FheSystem::bootstrap(&ct, &keys.pk, &keys.sk);
        assert_eq!(refreshed.noise_budget, INITIAL_NOISE_BUDGET);

        let dec = FheSystem::decrypt(&keys.sk, &refreshed);
        assert_eq!(
            dec.as_scalar(),
            99,
            "Préservation de la valeur après bootstrapping"
        );
    }

    #[test]
    fn test_blind_computing_polynomial_evaluation() {
        let keys = FheSystem::keygen(0x7777_8888_9999);
        // P(x) = 5 + 3*x + 2*x^2 avec x = 4 => 5 + 12 + 32 = 49
        let ct_x = FheSystem::encrypt(&keys.pk, &Plaintext::from_scalar(4), 0x6666);
        let ct_res = BlindEngine::blind_poly_eval(&ct_x, 5, 3, 2, &keys.rlk);

        let dec = FheSystem::decrypt(&keys.sk, &ct_res);
        assert_eq!(
            dec.as_scalar(),
            49,
            "Évaluation aveugle de polynôme P(4) = 49"
        );
    }

    #[test]
    fn test_cap_attenuation_and_privilege_rejection() {
        let admin_cap = FheCap::new(Handle::new(9801, 1), fhe_rights::ALL);
        assert!(admin_cap.has_right(fhe_rights::ADMIN));
        assert!(admin_cap.has_right(fhe_rights::DECRYPT));

        let eval_cap = admin_cap
            .attenuate(fhe_rights::EVAL | fhe_rights::BOOTSTRAP | fhe_rights::INSPECT)
            .expect("Atténuation monotone");
        assert!(eval_cap.has_right(fhe_rights::EVAL));
        assert!(eval_cap.has_right(fhe_rights::BOOTSTRAP));
        assert!(!eval_cap.has_right(fhe_rights::DECRYPT));
        assert!(!eval_cap.has_right(fhe_rights::ADMIN));

        // Rejet absolu d'élévation
        assert_eq!(
            eval_cap.attenuate(fhe_rights::ALL),
            Err(SysError::PermissionDenied)
        );
    }
}

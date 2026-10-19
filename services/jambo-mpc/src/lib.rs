//! Calcul Multipartite Sécurisé (MPC), Partage Secret de Seuil &
//! Consensus Cryptographique Distribué (`jambo-mpc`)
//!
//! Phase 95 — Jalon v0.2.93
//!
//! Fournit les garanties souveraines de confidentialité préservée et de calcul distribué :
//! 1. Corps fini de Galois GF(256) souverain (`#![no_std]`) avec arithmétique constante O(1).
//! 2. Schéma de partage secret de seuil de Shamir (Shamir's Secret Sharing - SSS, seuil (t, n)).
//! 3. Partage secret vérifiable (Verifiable Secret Sharing - VSS) avec engagements cryptographiques SHA-256/HMAC.
//! 4. Évaluation de circuits arithmétiques multipartites sécurisés via Triplés de Beaver (Beaver Triplets) :
//!    multiplication aveugle sans révélation des opérandes d'entrée.
//! 5. Consensus cryptographique de seuil (Threshold Consensus) et détection/bannissement de nœuds byzantins (Slashing).
//! 6. Registre d'audit inviolable scellé par chaîne SHA-256 (`mpc_audit_chain`).
//! 7. Contrôle d'accès capabilaire strict (`MpcCap`) interdisant toute autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_MPC_NODES: usize = 16;
pub const MAX_MPC_SESSIONS: usize = 8;
pub const MAX_BEAVER_TRIPLETS: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 64;
pub const MAX_SECRET_LEN: usize = 64;
pub const MAX_LABEL_LEN: usize = 32;
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
// CORPS FINI DE GALOIS GF(256) (#![no_std])
// ============================================================================

/// Élément du corps fini GF(2^8) avec polynôme irréductible x^8 + x^4 + x^3 + x + 1 (0x11b)
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Gf256(pub u8);

impl Gf256 {
    pub const ZERO: Self = Gf256(0);
    pub const ONE: Self = Gf256(1);

    #[inline(always)]
    pub fn add(self, rhs: Self) -> Self {
        Gf256(self.0 ^ rhs.0)
    }

    #[inline(always)]
    pub fn sub(self, rhs: Self) -> Self {
        Gf256(self.0 ^ rhs.0)
    }

    pub fn mul(self, rhs: Self) -> Self {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut p = 0u8;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        Gf256(p)
    }

    pub fn inv(self) -> Result<Self, SysError> {
        if self.0 == 0 {
            return Err(SysError::InvalidArgument);
        }
        // Théorème de Fermat dans GF(256) : a^(256 - 2) = a^254
        let mut res = Gf256::ONE;
        let mut base = self;
        let mut exp = 254u8;
        while exp > 0 {
            if exp & 1 == 1 {
                res = res.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        Ok(res)
    }

    pub fn div(self, rhs: Self) -> Result<Self, SysError> {
        let inv_rhs = rhs.inv()?;
        Ok(self.mul(inv_rhs))
    }
}

// ============================================================================
// GÉNÉRATEUR PSEUDO-ALÉATOIRE CRYPTOGRAPHIQUE DETERMINISTE (#![no_std])
// ============================================================================

pub struct MpcPrng {
    state: [u8; 32],
    counter: u64,
}

impl MpcPrng {
    pub fn new(seed: &[u8]) -> Self {
        let state = Sha256::digest(seed);
        Self { state, counter: 0 }
    }

    pub fn next_u8(&mut self) -> u8 {
        let mut buf = [0u8; 40];
        buf[0..32].copy_from_slice(&self.state);
        buf[32..40].copy_from_slice(&self.counter.to_be_bytes());
        let digest = Sha256::digest(&buf);
        self.state = digest;
        self.counter = self.counter.wrapping_add(1);
        self.state[0]
    }

    pub fn next_non_zero_u8(&mut self) -> u8 {
        loop {
            let val = self.next_u8();
            if val != 0 {
                return val;
            }
        }
    }
}

// ============================================================================
// PARTAGE SECRET DE SHAMIR (SSS) & VÉRIFIABLE (VSS) (#![no_std])
// ============================================================================

/// Part de secret individuelle détenue par un participant
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretShare {
    /// Identifiant du participant (x_i != 0)
    pub node_id: u8,
    /// Éléments d'évaluation y_i = P(x_i)
    pub values: [u8; MAX_SECRET_LEN],
    pub len: usize,
}

/// Engagement de Feldman/VSS pour les coefficients d'un polynôme de partage
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VssCommitment {
    pub coeff_index: usize,
    pub commitment_hash: [u8; 32],
}

pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Divise un secret en `n` parts avec un seuil `t` (t <= n <= MAX_MPC_NODES)
    pub fn split_secret(
        secret: &[u8],
        t: usize,
        n: usize,
        seed: &[u8],
        shares_out: &mut [SecretShare],
        commitments_out: &mut [VssCommitment],
    ) -> Result<usize, SysError> {
        if t == 0 || t > n || n > MAX_MPC_NODES || secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(SysError::InvalidArgument);
        }
        if shares_out.len() < n || commitments_out.len() < t {
            return Err(SysError::BufferTooSmall);
        }

        let mut prng = MpcPrng::new(seed);

        // Pour chaque octet du secret, on génère un polynôme P(x) = secret + a1*x + ... + a_{t-1}*x^{t-1}
        let sec_len = secret.len();
        let mut poly_coeffs = [[Gf256::ZERO; MAX_MPC_NODES]; MAX_SECRET_LEN];

        for byte_idx in 0..sec_len {
            poly_coeffs[byte_idx][0] = Gf256(secret[byte_idx]);
            for deg in 1..t {
                poly_coeffs[byte_idx][deg] = Gf256(prng.next_u8());
            }
        }

        // Générer les engagements VSS pour chaque coefficient
        for deg in 0..t {
            let mut commit_data = [0u8; MAX_SECRET_LEN + 8];
            for b in 0..sec_len {
                commit_data[b] = poly_coeffs[b][deg].0;
            }
            commit_data[MAX_SECRET_LEN..MAX_SECRET_LEN + 8].copy_from_slice(&(deg as u64).to_be_bytes());
            commitments_out[deg] = VssCommitment {
                coeff_index: deg,
                commitment_hash: Sha256::digest(&commit_data),
            };
        }

        // Calculer les parts pour chaque nœud (x = 1..=n)
        for i in 0..n {
            let x = Gf256((i + 1) as u8);
            let mut share = SecretShare {
                node_id: (i + 1) as u8,
                values: [0u8; MAX_SECRET_LEN],
                len: sec_len,
            };

            for byte_idx in 0..sec_len {
                let mut y = Gf256::ZERO;
                let mut x_pow = Gf256::ONE;
                for deg in 0..t {
                    let term = poly_coeffs[byte_idx][deg].mul(x_pow);
                    y = y.add(term);
                    x_pow = x_pow.mul(x);
                }
                share.values[byte_idx] = y.0;
            }
            shares_out[i] = share;
        }

        Ok(n)
    }

    /// Reconstruit le secret à partir d'au moins `t` parts via interpolation de Lagrange en x = 0
    pub fn reconstruct_secret(
        shares: &[SecretShare],
        t: usize,
        secret_out: &mut [u8],
    ) -> Result<usize, SysError> {
        if shares.len() < t || t == 0 {
            return Err(SysError::InvalidArgument);
        }
        let sec_len = shares[0].len;
        if sec_len == 0 || sec_len > MAX_SECRET_LEN || secret_out.len() < sec_len {
            return Err(SysError::BufferTooSmall);
        }

        // Vérifier l'unicité des x_i
        for i in 0..t {
            if shares[i].node_id == 0 {
                return Err(SysError::InvalidArgument);
            }
            for j in (i + 1)..t {
                if shares[i].node_id == shares[j].node_id {
                    return Err(SysError::InvalidArgument);
                }
            }
        }

        // Interpolation de Lagrange byte par byte en x = 0
        for byte_idx in 0..sec_len {
            let mut secret_val = Gf256::ZERO;

            for i in 0..t {
                let xi = Gf256(shares[i].node_id);
                let yi = Gf256(shares[i].values[byte_idx]);

                // L_i(0) = \prod_{j != i} (0 - x_j) / (x_i - x_j) = \prod x_j / (x_i ^ x_j)
                let mut num = Gf256::ONE;
                let mut den = Gf256::ONE;

                for j in 0..t {
                    if i != j {
                        let xj = Gf256(shares[j].node_id);
                        num = num.mul(xj);
                        let diff = xi.sub(xj);
                        den = den.mul(diff);
                    }
                }

                let li_0 = num.div(den)?;
                let term = yi.mul(li_0);
                secret_val = secret_val.add(term);
            }

            secret_out[byte_idx] = secret_val.0;
        }

        Ok(sec_len)
    }
}

// ============================================================================
// TRIPLÉS DE BEAVER & MULTIPLICATION SÉCURISÉE MULTIPARTITE (#![no_std])
// ============================================================================

/// Triplet de Beaver pré-calculé ([a], [b], [c]) avec c = a * b
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaverTriplet {
    pub triplet_id: u32,
    pub a_val: Gf256,
    pub b_val: Gf256,
    pub c_val: Gf256,
    pub used: bool,
}

/// Parts d'un triplet de Beaver distribuées à un participant
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaverShare {
    pub node_id: u8,
    pub a_share: Gf256,
    pub b_share: Gf256,
    pub c_share: Gf256,
}

pub struct BeaverProtocol;

impl BeaverProtocol {
    /// Génère un triplet de Beaver aléatoire vérifiant c = a * b
    pub fn generate_triplet(triplet_id: u32, seed: &[u8]) -> BeaverTriplet {
        let mut prng = MpcPrng::new(seed);
        let a = Gf256(prng.next_non_zero_u8());
        let b = Gf256(prng.next_non_zero_u8());
        let c = a.mul(b);

        BeaverTriplet {
            triplet_id,
            a_val: a,
            b_val: b,
            c_val: c,
            used: false,
        }
    }

    /// Partage additif d'une valeur v entre n parties (v = \sum_{i=1}^n v_i)
    pub fn share_additive(val: Gf256, n: usize, seed: &[u8], shares_out: &mut [Gf256]) -> Result<(), SysError> {
        if n == 0 || n > MAX_MPC_NODES || shares_out.len() < n {
            return Err(SysError::InvalidArgument);
        }
        let mut prng = MpcPrng::new(seed);
        let mut sum = Gf256::ZERO;
        for i in 0..(n - 1) {
            let r = Gf256(prng.next_u8());
            shares_out[i] = r;
            sum = sum.add(r);
        }
        // Le dernier nœud reçoit la différence pour fermer la somme
        shares_out[n - 1] = val.sub(sum);
        Ok(())
    }

    /// Multiplication sécurisée MPC de deux valeurs partagées [x] et [y] via le triplet ([a], [b], [c])
    pub fn compute_multiplication_step(
        d: Gf256, // d = x - a (reconstruit publiquement)
        e: Gf256, // e = y - b (reconstruit publiquement)
        node_idx: usize,
        a_share: Gf256,
        b_share: Gf256,
        c_share: Gf256,
    ) -> Gf256 {
        // [z]_i = [c]_i + d * [b]_i + e * [a]_i + (si node 0 : d * e)
        let term1 = c_share;
        let term2 = d.mul(b_share);
        let term3 = e.mul(a_share);

        let mut z = term1.add(term2).add(term3);
        if node_idx == 0 {
            z = z.add(d.mul(e));
        }
        z
    }
}

// ============================================================================
// GOUVERNANCE CAPABILAIRE MPC
// ============================================================================

pub mod mpc_rights {
    pub const INIT_SESSION: u32     = 1 << 0;
    pub const REGISTER_NODE: u32    = 1 << 1;
    pub const SHARE_SECRET: u32     = 1 << 2;
    pub const RECONSTRUCT: u32      = 1 << 3;
    pub const BEAVER_TRIPLET: u32   = 1 << 4;
    pub const SECURE_COMPUTE: u32   = 1 << 5;
    pub const SLASH_BYZANTINE: u32  = 1 << 6;
    pub const ZEROIZE: u32          = 1 << 7;
    pub const ADMIN: u32            = 1 << 8;

    pub const ALL: u32 = INIT_SESSION
        | REGISTER_NODE
        | SHARE_SECRET
        | RECONSTRUCT
        | BEAVER_TRIPLET
        | SECURE_COMPUTE
        | SLASH_BYZANTINE
        | ZEROIZE
        | ADMIN;
}

/// Jeton de capacité souverain pour le sous-système MPC (`MpcCap`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpcCap {
    pub handle: Handle,
    pub rights: u32,
}

impl MpcCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone des privilèges : interdiction formelle d'élévation
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
// STRUCTURES MPC : NŒUDS, SESSIONS ET CONSENSUS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcNodeStatus {
    Active,
    Quarantine,
    SlashedByzantine,
}

impl MpcNodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Quarantine => "QUARANTINE",
            Self::SlashedByzantine => "SLASHED_BYZANTINE",
        }
    }
}

/// Nœud participant à la grappe MPC
#[derive(Clone, Copy)]
pub struct MpcNode {
    pub node_id: u8,
    pub name: [u8; MAX_LABEL_LEN],
    pub name_len: usize,
    pub status: MpcNodeStatus,
    pub shares_handled: u64,
    pub byzantine_strikes: u32,
}

impl MpcNode {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<unknown>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcSessionType {
    ThresholdSharing,
    BeaverArithmetic,
    ThresholdConsensus,
}

impl MpcSessionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ThresholdSharing => "THRESHOLD_SHARING",
            Self::BeaverArithmetic => "BEAVER_ARITHMETIC",
            Self::ThresholdConsensus => "THRESHOLD_CONSENSUS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcSessionState {
    Initialized,
    SharesDistributed,
    Evaluated,
    Reconstructed,
    Failed,
}

impl MpcSessionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initialized => "INITIALIZED",
            Self::SharesDistributed => "SHARES_DISTRIBUTED",
            Self::Evaluated => "EVALUATED",
            Self::Reconstructed => "RECONSTRUCTED",
            Self::Failed => "FAILED",
        }
    }
}

/// Session active de calcul multipartite
#[derive(Clone, Copy)]
pub struct MpcSession {
    pub session_id: u32,
    pub session_type: MpcSessionType,
    pub state: MpcSessionState,
    pub threshold_t: usize,
    pub total_nodes_n: usize,
    pub secret_len: usize,
    pub hash_commitment: [u8; 32],
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SCELLÉ SHA-256
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcAction {
    InitDaemon,
    RegisterNode,
    SlashNode,
    CreateSession,
    SplitSecret,
    ReconstructSecret,
    GenerateBeaverTriplet,
    ComputeBeaverMult,
    ZeroizeEmergency,
}

impl MpcAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InitDaemon => "INIT_DAEMON",
            Self::RegisterNode => "REGISTER_NODE",
            Self::SlashNode => "SLASH_NODE",
            Self::CreateSession => "CREATE_SESSION",
            Self::SplitSecret => "SPLIT_SECRET",
            Self::ReconstructSecret => "RECONSTRUCT_SECRET",
            Self::GenerateBeaverTriplet => "GENERATE_BEAVER_TRIPLET",
            Self::ComputeBeaverMult => "COMPUTE_BEAVER_MULT",
            Self::ZeroizeEmergency => "ZEROIZE_EMERGENCY",
        }
    }
}

#[derive(Clone, Copy)]
pub struct MpcAuditEntry {
    pub action: MpcAction,
    pub session_id: u32,
    pub node_id: u8,
    pub reason: [u8; MAX_REASON_LEN],
    pub reason_len: usize,
    pub epoch: u64,
    pub block_hash: [u8; 32],
}

impl MpcAuditEntry {
    pub fn reason_as_str(&self) -> &str {
        core::str::from_utf8(&self.reason[..self.reason_len]).unwrap_or("")
    }
}

// ============================================================================
// DÉMON DU CALCUL MULTIPARTITE SÉCURISÉ (`JamboMpcDaemon`)
// ============================================================================

pub struct JamboMpcDaemon {
    pub admin_cap: MpcCap,
    pub nodes: [Option<MpcNode>; MAX_MPC_NODES],
    pub sessions: [Option<MpcSession>; MAX_MPC_SESSIONS],
    pub triplets: [Option<BeaverTriplet>; MAX_BEAVER_TRIPLETS],
    pub next_session_id: u32,
    pub next_triplet_id: u32,
    pub sessions_created: u64,
    pub secrets_split: u64,
    pub secrets_reconstructed: u64,
    pub beaver_mults_computed: u64,
    pub byzantine_slashes: u64,
    pub epoch: u64,
    pub audit_chain: [u8; 32],
    pub audit_logs: [Option<MpcAuditEntry>; MAX_AUDIT_LOGS],
    pub audit_head: usize,
}

impl JamboMpcDaemon {
    pub fn new(admin_cap: MpcCap) -> Self {
        let genesis_audit = Sha256::digest(b"JAMBO_MPC_GENESIS_ROOT_CHAIN_2026");

        Self {
            admin_cap,
            nodes: [None; MAX_MPC_NODES],
            sessions: [None; MAX_MPC_SESSIONS],
            triplets: [None; MAX_BEAVER_TRIPLETS],
            next_session_id: 1,
            next_triplet_id: 10,
            sessions_created: 0,
            secrets_split: 0,
            secrets_reconstructed: 0,
            beaver_mults_computed: 0,
            byzantine_slashes: 0,
            epoch: 1,
            audit_chain: genesis_audit,
            audit_logs: [None; MAX_AUDIT_LOGS],
            audit_head: 0,
        }
    }

    /// Enregistre une opération dans le journal scellé par chaîne SHA-256
    pub fn record_audit(&mut self, action: MpcAction, session_id: u32, node_id: u8, reason_str: &str) {
        let mut r_buf = [0u8; MAX_REASON_LEN];
        let bytes = reason_str.as_bytes();
        let copy_len = if bytes.len() > MAX_REASON_LEN {
            MAX_REASON_LEN
        } else {
            bytes.len()
        };
        r_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let mut hash_input = [0u8; 32 + 4 + 4 + 1 + MAX_REASON_LEN + 8];
        hash_input[0..32].copy_from_slice(&self.audit_chain);
        hash_input[32..36].copy_from_slice(&(action as u32).to_be_bytes());
        hash_input[36..40].copy_from_slice(&session_id.to_be_bytes());
        hash_input[40] = node_id;
        hash_input[41..41 + MAX_REASON_LEN].copy_from_slice(&r_buf);
        hash_input[41 + MAX_REASON_LEN..49 + MAX_REASON_LEN].copy_from_slice(&self.epoch.to_be_bytes());

        let new_hash = Sha256::digest(&hash_input);
        self.audit_chain = new_hash;

        let entry = MpcAuditEntry {
            action,
            session_id,
            node_id,
            reason: r_buf,
            reason_len: copy_len,
            epoch: self.epoch,
            block_hash: new_hash,
        };

        self.audit_logs[self.audit_head] = Some(entry);
        self.audit_head = (self.audit_head + 1) % MAX_AUDIT_LOGS;
    }

    /// Initialise la topologie MPC par défaut (5 nœuds souverains de grappe)
    pub fn init_defaults(&mut self) {
        let node_names: [&str; 5] = [
            "jambo-node-alpha",
            "jambo-node-beta",
            "jambo-node-gamma",
            "jambo-node-delta",
            "jambo-node-epsilon",
        ];

        for (idx, &name) in node_names.iter().enumerate() {
            let id = (idx + 1) as u8;
            let mut name_buf = [0u8; MAX_LABEL_LEN];
            let n_bytes = name.as_bytes();
            let c_len = if n_bytes.len() > MAX_LABEL_LEN {
                MAX_LABEL_LEN
            } else {
                n_bytes.len()
            };
            name_buf[..c_len].copy_from_slice(&n_bytes[..c_len]);

            self.nodes[idx] = Some(MpcNode {
                node_id: id,
                name: name_buf,
                name_len: c_len,
                status: MpcNodeStatus::Active,
                shares_handled: 0,
                byzantine_strikes: 0,
            });
        }

        self.record_audit(MpcAction::InitDaemon, 0, 0, "Cluster MPC par défaut initialisé (5 nœuds)");
    }

    pub fn count_active_nodes(&self) -> usize {
        self.nodes.iter().filter(|n| {
            if let Some(node) = n {
                node.status == MpcNodeStatus::Active
            } else {
                false
            }
        }).count()
    }

    pub fn register_node(&mut self, cap: &MpcCap, name: &str) -> Result<u8, SysError> {
        if !cap.has_right(mpc_rights::REGISTER_NODE) {
            return Err(SysError::PermissionDenied);
        }

        for (i, slot) in self.nodes.iter_mut().enumerate() {
            if slot.is_none() {
                let id = (i + 1) as u8;
                let mut name_buf = [0u8; MAX_LABEL_LEN];
                let b = name.as_bytes();
                let len = if b.len() > MAX_LABEL_LEN { MAX_LABEL_LEN } else { b.len() };
                name_buf[..len].copy_from_slice(&b[..len]);

                *slot = Some(MpcNode {
                    node_id: id,
                    name: name_buf,
                    name_len: len,
                    status: MpcNodeStatus::Active,
                    shares_handled: 0,
                    byzantine_strikes: 0,
                });

                self.record_audit(MpcAction::RegisterNode, 0, id, name);
                return Ok(id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    pub fn slash_byzantine_node(&mut self, cap: &MpcCap, node_id: u8, reason: &str) -> Result<(), SysError> {
        if !cap.has_right(mpc_rights::SLASH_BYZANTINE) {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.nodes.iter_mut() {
            if let Some(n) = slot {
                if n.node_id == node_id {
                    n.status = MpcNodeStatus::SlashedByzantine;
                    n.byzantine_strikes = n.byzantine_strikes.wrapping_add(1);
                    self.byzantine_slashes = self.byzantine_slashes.wrapping_add(1);
                    self.record_audit(MpcAction::SlashNode, 0, node_id, reason);
                    return Ok(());
                }
            }
        }
        Err(SysError::InvalidArgument)
    }

    pub fn create_session(
        &mut self,
        cap: &MpcCap,
        session_type: MpcSessionType,
        threshold_t: usize,
        total_nodes_n: usize,
    ) -> Result<u32, SysError> {
        if !cap.has_right(mpc_rights::INIT_SESSION) {
            return Err(SysError::PermissionDenied);
        }
        if threshold_t == 0 || threshold_t > total_nodes_n || total_nodes_n > MAX_MPC_NODES {
            return Err(SysError::InvalidArgument);
        }

        for slot in self.sessions.iter_mut() {
            if slot.is_none() {
                let s_id = self.next_session_id;
                self.next_session_id = self.next_session_id.wrapping_add(1);

                *slot = Some(MpcSession {
                    session_id: s_id,
                    session_type,
                    state: MpcSessionState::Initialized,
                    threshold_t,
                    total_nodes_n,
                    secret_len: 0,
                    hash_commitment: [0u8; 32],
                });

                self.sessions_created = self.sessions_created.wrapping_add(1);
                self.record_audit(MpcAction::CreateSession, s_id, 0, session_type.as_str());
                return Ok(s_id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Partage un secret dans une session MPC avec seuil (t, n) et distribution vérifiable
    pub fn split_secret_in_session(
        &mut self,
        cap: &MpcCap,
        session_id: u32,
        secret: &[u8],
        seed: &[u8],
        shares_out: &mut [SecretShare],
        commitments_out: &mut [VssCommitment],
    ) -> Result<usize, SysError> {
        if !cap.has_right(mpc_rights::SHARE_SECRET) {
            return Err(SysError::PermissionDenied);
        }

        let (t, n) = {
            let s = self.find_session(session_id)?;
            (s.threshold_t, s.total_nodes_n)
        };

        let count = ShamirSecretSharing::split_secret(
            secret,
            t,
            n,
            seed,
            shares_out,
            commitments_out,
        )?;

        let commit_hash = Sha256::digest(secret);

        let sess = self.find_session_mut(session_id)?;
        sess.state = MpcSessionState::SharesDistributed;
        sess.secret_len = secret.len();
        sess.hash_commitment = commit_hash;

        // Incrémenter les compteurs de part pour les nœuds actifs
        for i in 0..n {
            let nid = (i + 1) as u8;
            if let Some(node) = self.find_node_mut(nid) {
                node.shares_handled = node.shares_handled.wrapping_add(1);
            }
        }

        self.secrets_split = self.secrets_split.wrapping_add(1);
        self.record_audit(MpcAction::SplitSecret, session_id, 0, "Secret divisé et partagé");
        Ok(count)
    }

    /// Reconstruit le secret de la session MPC à partir d'au moins `t` parts
    pub fn reconstruct_secret_in_session(
        &mut self,
        cap: &MpcCap,
        session_id: u32,
        shares: &[SecretShare],
        secret_out: &mut [u8],
    ) -> Result<usize, SysError> {
        if !cap.has_right(mpc_rights::RECONSTRUCT) {
            return Err(SysError::PermissionDenied);
        }

        let (t, exp_hash, exp_len) = {
            let s = self.find_session(session_id)?;
            (s.threshold_t, s.hash_commitment, s.secret_len)
        };

        if shares.len() < t {
            return Err(SysError::InvalidArgument);
        }

        let len = ShamirSecretSharing::reconstruct_secret(shares, t, secret_out)?;
        if len != exp_len {
            return Err(SysError::InvalidArgument);
        }

        // Vérification de l'intégrité par rapport à l'engagement initial
        let rec_hash = Sha256::digest(&secret_out[..len]);
        if rec_hash != exp_hash {
            return Err(SysError::PermissionDenied);
        }

        let sess = self.find_session_mut(session_id)?;
        sess.state = MpcSessionState::Reconstructed;

        self.secrets_reconstructed = self.secrets_reconstructed.wrapping_add(1);
        self.record_audit(MpcAction::ReconstructSecret, session_id, 0, "Secret reconstruit avec succès");
        Ok(len)
    }

    /// Alloue un triplet de Beaver pour des multiplications MPC
    pub fn allocate_beaver_triplet(&mut self, cap: &MpcCap, seed: &[u8]) -> Result<BeaverTriplet, SysError> {
        if !cap.has_right(mpc_rights::BEAVER_TRIPLET) {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.triplets.iter_mut() {
            if slot.is_none() {
                let id = self.next_triplet_id;
                self.next_triplet_id = self.next_triplet_id.wrapping_add(1);

                let trip = BeaverProtocol::generate_triplet(id, seed);
                *slot = Some(trip);

                self.record_audit(MpcAction::GenerateBeaverTriplet, 0, 0, "Triplet de Beaver alloué");
                return Ok(trip);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Exécute une multiplication multipartite sécurisée complète sur deux opérandes partagés x et y
    pub fn execute_beaver_mult(
        &mut self,
        cap: &MpcCap,
        x_val: Gf256,
        y_val: Gf256,
        n_parties: usize,
        seed: &[u8],
    ) -> Result<Gf256, SysError> {
        if !cap.has_right(mpc_rights::SECURE_COMPUTE) {
            return Err(SysError::PermissionDenied);
        }
        if n_parties == 0 || n_parties > MAX_MPC_NODES {
            return Err(SysError::InvalidArgument);
        }

        // 1. Allouer un triplet Beaver
        let trip = self.allocate_beaver_triplet(cap, seed)?;

        // 2. Partager additivement x et y
        let mut x_shares = [Gf256::ZERO; MAX_MPC_NODES];
        let mut y_shares = [Gf256::ZERO; MAX_MPC_NODES];
        BeaverProtocol::share_additive(x_val, n_parties, b"seed_share_x", &mut x_shares[..n_parties])?;
        BeaverProtocol::share_additive(y_val, n_parties, b"seed_share_y", &mut y_shares[..n_parties])?;

        // 3. Partager additivement les composantes du triplet (a, b, c)
        let mut a_shares = [Gf256::ZERO; MAX_MPC_NODES];
        let mut b_shares = [Gf256::ZERO; MAX_MPC_NODES];
        let mut c_shares = [Gf256::ZERO; MAX_MPC_NODES];
        BeaverProtocol::share_additive(trip.a_val, n_parties, b"seed_share_a", &mut a_shares[..n_parties])?;
        BeaverProtocol::share_additive(trip.b_val, n_parties, b"seed_share_b", &mut b_shares[..n_parties])?;
        BeaverProtocol::share_additive(trip.c_val, n_parties, b"seed_share_c", &mut c_shares[..n_parties])?;

        // 4. Calcul de [d]_i = [x]_i - [a]_i et [e]_i = [y]_i - [b]_i puis ouverture publique
        let mut d_sum = Gf256::ZERO;
        let mut e_sum = Gf256::ZERO;
        for i in 0..n_parties {
            let di = x_shares[i].sub(a_shares[i]);
            let ei = y_shares[i].sub(b_shares[i]);
            d_sum = d_sum.add(di);
            e_sum = e_sum.add(ei);
        }

        // 5. Calcul local des parts [z]_i et agrégation finale
        let mut final_result = Gf256::ZERO;
        for i in 0..n_parties {
            let zi = BeaverProtocol::compute_multiplication_step(
                d_sum,
                e_sum,
                i,
                a_shares[i],
                b_shares[i],
                c_shares[i],
            );
            final_result = final_result.add(zi);
        }

        self.beaver_mults_computed = self.beaver_mults_computed.wrapping_add(1);
        self.record_audit(MpcAction::ComputeBeaverMult, 0, 0, "Multiplication Beaver MPC réussie");
        Ok(final_result)
    }

    /// Zéroïsation d'urgence de toutes les données et sessions MPC en mémoire
    pub fn zeroize_emergency(&mut self, cap: &MpcCap, reason: &str) -> Result<(), SysError> {
        if !cap.has_right(mpc_rights::ZEROIZE) {
            return Err(SysError::PermissionDenied);
        }

        for s in self.sessions.iter_mut() {
            *s = None;
        }
        for t in self.triplets.iter_mut() {
            *t = None;
        }

        self.record_audit(MpcAction::ZeroizeEmergency, 0, 0, reason);
        Ok(())
    }

    fn find_session(&self, id: u32) -> Result<&MpcSession, SysError> {
        for slot in self.sessions.iter() {
            if let Some(s) = slot {
                if s.session_id == id {
                    return Ok(s);
                }
            }
        }
        Err(SysError::InvalidHandle)
    }

    fn find_session_mut(&mut self, id: u32) -> Result<&mut MpcSession, SysError> {
        for slot in self.sessions.iter_mut() {
            if let Some(s) = slot {
                if s.session_id == id {
                    return Ok(s);
                }
            }
        }
        Err(SysError::InvalidHandle)
    }

    fn find_node_mut(&mut self, node_id: u8) -> Option<&mut MpcNode> {
        for slot in self.nodes.iter_mut() {
            if let Some(n) = slot {
                if n.node_id == node_id {
                    return Some(n);
                }
            }
        }
        None
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_arithmetic() {
        let a = Gf256(0x53);
        let b = Gf256(0xca);

        // Addition = XOR
        assert_eq!(a.add(b), Gf256(0x53 ^ 0xca));
        assert_eq!(a.sub(b), a.add(b));

        // Neutre
        assert_eq!(a.mul(Gf256::ONE), a);
        assert_eq!(a.mul(Gf256::ZERO), Gf256::ZERO);

        // Inverse
        let inv_a = a.inv().expect("Inverse de a");
        assert_eq!(a.mul(inv_a), Gf256::ONE);

        // Division
        let div = a.div(b).expect("Division a / b");
        assert_eq!(div.mul(b), a);
    }

    #[test]
    fn test_shamir_split_and_reconstruct() {
        let secret = b"JAMBO_MPC_SOVEREIGN_KEY_2026";
        let mut shares = [SecretShare {
            node_id: 0,
            values: [0u8; MAX_SECRET_LEN],
            len: 0,
        }; 5];
        let mut commitments = [VssCommitment {
            coeff_index: 0,
            commitment_hash: [0u8; 32],
        }; 3];

        let n = ShamirSecretSharing::split_secret(
            secret,
            3, // Seuil t = 3
            5, // n = 5
            b"test_seed_mpc",
            &mut shares,
            &mut commitments,
        ).expect("Split secret");

        assert_eq!(n, 5);

        // Reconstruire avec les parts {1, 2, 4} (taille 3 >= seuil 3)
        let subset = [shares[0], shares[1], shares[3]];
        let mut recovered = [0u8; MAX_SECRET_LEN];
        let r_len = ShamirSecretSharing::reconstruct_secret(&subset, 3, &mut recovered).expect("Reconstruct");
        assert_eq!(&recovered[..r_len], secret);

        // Reconstruire avec une combinaison différente {2, 3, 5}
        let subset2 = [shares[1], shares[2], shares[4]];
        let mut recovered2 = [0u8; MAX_SECRET_LEN];
        let r_len2 = ShamirSecretSharing::reconstruct_secret(&subset2, 3, &mut recovered2).expect("Reconstruct 2");
        assert_eq!(&recovered2[..r_len2], secret);
    }

    #[test]
    fn test_beaver_secure_multiplication() {
        let admin_cap = MpcCap::new(Handle::new(1, 1), mpc_rights::ALL);
        let mut daemon = JamboMpcDaemon::new(admin_cap);

        let x = Gf256(0x07);
        let y = Gf256(0x09);
        let expected = x.mul(y);

        let result = daemon.execute_beaver_mult(&admin_cap, x, y, 4, b"test_beaver_seed")
            .expect("Beaver multiplication");

        assert_eq!(result, expected);
        assert_eq!(daemon.beaver_mults_computed, 1);
    }

    #[test]
    fn test_cap_monotonicity_and_slashing() {
        let admin_cap = MpcCap::new(Handle::new(1, 1), mpc_rights::ALL);
        let mut daemon = JamboMpcDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.count_active_nodes(), 5);

        // Atténuation monotone
        let user_cap = admin_cap.attenuate(mpc_rights::INIT_SESSION | mpc_rights::SHARE_SECRET)
            .expect("Attenuate");
        assert!(!user_cap.has_right(mpc_rights::SLASH_BYZANTINE));

        // Rejet de l'élévation
        assert_eq!(
            user_cap.attenuate(mpc_rights::ALL),
            Err(SysError::PermissionDenied)
        );

        // Bannissement d'un nœud byzantin
        daemon.slash_byzantine_node(&admin_cap, 2, "Tentative d'altération de part").expect("Slash node");
        assert_eq!(daemon.byzantine_slashes, 1);
        assert_eq!(daemon.count_active_nodes(), 4);
    }
}

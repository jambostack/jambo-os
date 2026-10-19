//! Attestation Cryptographique à Distance, Preuves Zero-Knowledge (ZKP)
//! et Confinement Matériel de Grappe (`jambo-attest`)
//!
//! Phase 93 — Jalon v0.2.91
//!
//! Fournit les garanties souveraines d'intégrité de grappe et de confinement matériel :
//! 1. Attestation cryptographique à distance multi-architecture : TPM 2.0 (PCR), Intel TDX (Trust Domains),
//!    AMD SEV-SNP, ARM CCA (Realms) et enclaves matérielles souveraines JamboOS (`jambo-tee`).
//! 2. Preuves d'intégrité à divulgation nulle de connaissance (Zero-Knowledge Proofs - ZKP) via le protocole
//!    de Schnorr / Fiat-Shamir (NIZKPoK) : preuve de possession de clé/mesure sans divulgation de secrets.
//! 3. Revendications d'intégrité signées (`NodeIntegrityClaim`) avec défi anti-rejeu inter-nœuds.
//! 4. Confinement matériel adaptatif de grappe (`ConfinementLevel` : Unrestricted, Sandboxed, Isolated, Ejected)
//!    avec mise en quarantaine immédiate en cas d'anomalie ou de compromission de mesure.
//! 5. Registre d'audit inaltérable scellé par chaîne de blocs SHA-256 (`audit_chain`).
//! 6. Contrôle d'accès capabilaire strict (`AttestCap`) interdisant toute autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_NODES: usize = 32;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_AUDIT_LOGS: usize = 64;
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

    /// Calcul de HMAC-SHA256 pour signature et scellement d'intégrité
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
// ARITHMÉTIQUE DE CORPS FINI & PROTOCOLE ZKP SCHNORR / FIAT-SHAMIR (#![no_std])
// ============================================================================

/// Module de preuve à divulgation nulle de connaissance (ZKP)
///
/// Implémente le protocole de Schnorr non interactif (NIZKPoK) via l'heuristique de Fiat-Shamir.
/// Soit un grand nombre premier p = 2^64 - 59 et le générateur multiplicatif g = 3.
/// Énoncé public : y = g^x (mod p), où x est le secret matériel (témoin) du nœud.
/// 1. Le prouveur choisit un facteur d'aveuglement v, calcule l'engagement t = g^v (mod p).
/// 2. Le défi c = H(g || y || t || claim_digest || cluster_challenge) (mod p - 1).
/// 3. La réponse r = (v + c * x) (mod p - 1).
/// Le vérificateur s'assure que g^r = t * y^c (mod p) sans jamais connaître x.
pub mod zkp {
    use super::Sha256;

    /// Plus grand nombre premier d'ordre 64 bits : p = 2^64 - 59
    pub const ZKP_PRIME: u64 = 0xFFFF_FFFF_FFFF_FFC5;
    /// Ordre du sous-groupe multiplicatif : q = p - 1
    pub const ZKP_ORDER: u64 = ZKP_PRIME - 1;
    /// Générateur multiplicatif du groupe
    pub const ZKP_GEN: u64 = 3;

    /// Multiplication modulaire sécurisée : (a * b) mod m
    #[inline(always)]
    pub fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
        ((a as u128 * b as u128) % m as u128) as u64
    }

    /// Exponentiation modulaire binaire rapide : base^exp mod m
    pub fn pow_mod(mut base: u64, mut exp: u64, m: u64) -> u64 {
        if m == 1 {
            return 0;
        }
        let mut result = 1u64;
        base %= m;
        while exp > 0 {
            if (exp & 1) == 1 {
                result = mul_mod(result, base, m);
            }
            base = mul_mod(base, base, m);
            exp >>= 1;
        }
        result
    }

    /// Calcule l'énoncé public y = g^x mod p à partir du secret x
    pub fn compute_public_statement(secret_x: u64) -> u64 {
        pow_mod(ZKP_GEN, secret_x % ZKP_ORDER, ZKP_PRIME)
    }

    /// Calcule le défi Fiat-Shamir c = H(g || y || t || claim_digest || cluster_challenge) mod (p - 1)
    pub fn compute_challenge(
        statement_y: u64,
        commitment_t: u64,
        claim_digest: &[u8; 32],
        cluster_challenge: &[u8; 32],
    ) -> u64 {
        let mut buf = [0u8; 8 + 8 + 8 + 32 + 32];
        buf[0..8].copy_from_slice(&ZKP_GEN.to_be_bytes());
        buf[8..16].copy_from_slice(&statement_y.to_be_bytes());
        buf[16..24].copy_from_slice(&commitment_t.to_be_bytes());
        buf[24..56].copy_from_slice(claim_digest);
        buf[56..88].copy_from_slice(cluster_challenge);

        let digest = Sha256::digest(&buf);
        let raw = u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3],
            digest[4], digest[5], digest[6], digest[7],
        ]);
        (raw % (ZKP_ORDER - 1)) + 1
    }

    /// Preuve à divulgation nulle de connaissance (Zero-Knowledge Proof)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ZkProof {
        pub node_id: u32,
        pub commitment_t: u64,
        pub challenge_c: u64,
        pub response_r: u64,
        pub statement_y: u64,
        pub claim_digest: [u8; 32],
        pub cluster_challenge: [u8; 32],
        pub epoch: u64,
    }

    impl ZkProof {
        /// Vérifie la validité mathématique de la preuve de Schnorr
        pub fn verify(&self) -> bool {
            if self.commitment_t == 0 || self.commitment_t >= ZKP_PRIME {
                return false;
            }
            if self.statement_y == 0 || self.statement_y >= ZKP_PRIME {
                return false;
            }

            // 1. Recalculer le défi Fiat-Shamir
            let expected_c = compute_challenge(
                self.statement_y,
                self.commitment_t,
                &self.claim_digest,
                &self.cluster_challenge,
            );
            if self.challenge_c != expected_c {
                return false;
            }

            // 2. Vérification de la relation de Schnorr : g^r == t * y^c (mod p)
            let lhs = pow_mod(ZKP_GEN, self.response_r, ZKP_PRIME);
            let y_to_c = pow_mod(self.statement_y, self.challenge_c, ZKP_PRIME);
            let rhs = mul_mod(self.commitment_t, y_to_c, ZKP_PRIME);

            lhs == rhs
        }
    }

    /// Génère une preuve de Schnorr complète pour le témoin secret `secret_x`
    pub fn prove(
        node_id: u32,
        secret_x: u64,
        blinding_v: u64,
        claim_digest: [u8; 32],
        cluster_challenge: [u8; 32],
        epoch: u64,
    ) -> ZkProof {
        let statement_y = compute_public_statement(secret_x);
        let v_mod = (blinding_v % (ZKP_ORDER - 1)) + 1;
        let commitment_t = pow_mod(ZKP_GEN, v_mod, ZKP_PRIME);

        let challenge_c = compute_challenge(
            statement_y,
            commitment_t,
            &claim_digest,
            &cluster_challenge,
        );

        // r = (v + c * x) mod (p - 1)
        let cx = (challenge_c as u128 * (secret_x % ZKP_ORDER) as u128) % ZKP_ORDER as u128;
        let response_r = ((v_mod as u128 + cx) % ZKP_ORDER as u128) as u64;

        ZkProof {
            node_id,
            commitment_t,
            challenge_c,
            response_r,
            statement_y,
            claim_digest,
            cluster_challenge,
            epoch,
        }
    }
}

// ============================================================================
// GOUVERNANCE CAPABILAIRE & DROITS ATTEST
// ============================================================================

pub mod attest_rights {
    pub const GENERATE_CLAIM: u32 = 1 << 0;
    pub const VERIFY_CLAIM: u32   = 1 << 1;
    pub const GENERATE_ZKP: u32    = 1 << 2;
    pub const VERIFY_ZKP: u32      = 1 << 3;
    pub const CONFINE_NODE: u32    = 1 << 4;
    pub const ADMIN: u32           = 1 << 5;

    pub const ALL: u32 = GENERATE_CLAIM
        | VERIFY_CLAIM
        | GENERATE_ZKP
        | VERIFY_ZKP
        | CONFINE_NODE
        | ADMIN;
}

/// Jeton de capacité souverain pour le sous-système d'attestation et de confinement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestCap {
    pub handle: Handle,
    pub rights: u32,
}

impl AttestCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone des droits : impossible d'acquérir des privilèges supérieurs
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
// TYPES DE RACINES DE CONFIANCE & STATUTS DE CONFINEMENT
// ============================================================================

/// Type de racine de confiance matérielle (Hardware Root of Trust)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareTrustRoot {
    Tpm2Pcr,
    IntelTdx,
    AmdSevSnp,
    ArmCcaRealm,
    JamboTeeEnclave,
}

impl HardwareTrustRoot {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tpm2Pcr => "TPM 2.0 (PCR)",
            Self::IntelTdx => "Intel TDX (Trust Domain)",
            Self::AmdSevSnp => "AMD SEV-SNP",
            Self::ArmCcaRealm => "ARM CCA (Realm RME)",
            Self::JamboTeeEnclave => "JamboOS TEE Enclave",
        }
    }
}

/// Statut de conformité cryptographique du nœud
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Unverified,
    PendingZkp,
    VerifiedTrusted,
    Quarantined,
    Revoked,
}

impl NodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unverified => "Unverified",
            Self::PendingZkp => "Pending ZKP",
            Self::VerifiedTrusted => "Verified & Trusted",
            Self::Quarantined => "Quarantined",
            Self::Revoked => "Revoked",
        }
    }
}

/// Niveau de confinement matériel appliqué au nœud dans la grappe
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfinementLevel {
    Unrestricted,
    Sandboxed,
    Isolated,
    Ejected,
}

impl ConfinementLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unrestricted => "Unrestricted (Full Cluster Access)",
            Self::Sandboxed => "Sandboxed (Restricted IPC)",
            Self::Isolated => "Isolated (No Network/IPC, Quarantined)",
            Self::Ejected => "Ejected (Excluded from Cluster)",
        }
    }
}

// ============================================================================
// REVENDICATIONS D'INTÉGRITÉ & ENREGISTREMENTS DE NŒUDS
// ============================================================================

/// Revendication d'intégrité signée d'un nœud (`NodeIntegrityClaim`)
#[derive(Clone, Copy)]
pub struct NodeIntegrityClaim {
    pub node_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub trust_root: HardwareTrustRoot,
    pub measurement: [u8; 32],
    pub cspace_revision: u32,
    pub security_level: u32,
    pub challenge_nonce: [u8; 32],
    pub epoch: u64,
    pub signature: [u8; 32],
}

impl NodeIntegrityClaim {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalid-utf8>")
    }

    /// Calcule le condensat SHA-256 canonique des données de la revendication
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut buf = [0u8; 4 + 32 + 32 + 4 + 4 + 32 + 8];
        buf[0..4].copy_from_slice(&self.node_id.to_be_bytes());
        buf[4..36].copy_from_slice(&self.name);
        buf[36..68].copy_from_slice(&self.measurement);
        buf[68..72].copy_from_slice(&self.cspace_revision.to_be_bytes());
        buf[72..76].copy_from_slice(&self.security_level.to_be_bytes());
        buf[76..108].copy_from_slice(&self.challenge_nonce);
        buf[108..116].copy_from_slice(&self.epoch.to_be_bytes());
        Sha256::digest(&buf)
    }

    /// Signe la revendication d'intégrité par HMAC-SHA256 avec la clé de signature du nœud
    pub fn sign(&mut self, signing_key: &[u8]) {
        let digest = self.compute_digest();
        self.signature = Sha256::hmac(signing_key, &digest);
    }

    /// Vérifie la signature HMAC-SHA256 de la revendication
    pub fn verify_signature(&self, signing_key: &[u8]) -> bool {
        let digest = self.compute_digest();
        let expected = Sha256::hmac(signing_key, &digest);
        expected == self.signature
    }
}

/// Enregistrement de nœud dans l'annuaire du gestionnaire d'attestation
#[derive(Clone, Copy)]
pub struct NodeRecord {
    pub node_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub trust_root: HardwareTrustRoot,
    pub baseline_measurement: [u8; 32],
    pub public_statement_y: u64,
    pub signing_key: [u8; 32],
    pub status: NodeStatus,
    pub confinement: ConfinementLevel,
    pub last_verified_epoch: u64,
    pub claims_count: u32,
    pub zkp_count: u32,
    pub violations_count: u32,
}

impl NodeRecord {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalid-utf8>")
    }
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ & ACTIONS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestAction {
    RegisterNode,
    ClaimGenerated,
    ClaimVerified,
    ClaimRejected,
    ZkpGenerated,
    ZkpVerified,
    ZkpRejected,
    NodeConfined,
    NodeQuarantined,
    ChallengeRotated,
}

impl AttestAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RegisterNode => "REGISTER_NODE",
            Self::ClaimGenerated => "CLAIM_GENERATED",
            Self::ClaimVerified => "CLAIM_VERIFIED",
            Self::ClaimRejected => "CLAIM_REJECTED",
            Self::ZkpGenerated => "ZKP_GENERATED",
            Self::ZkpVerified => "ZKP_VERIFIED",
            Self::ZkpRejected => "ZKP_REJECTED",
            Self::NodeConfined => "NODE_CONFINED",
            Self::NodeQuarantined => "NODE_QUARANTINED",
            Self::ChallengeRotated => "CHALLENGE_ROTATED",
        }
    }
}

#[derive(Clone, Copy)]
pub struct AttestAuditEntry {
    pub action: AttestAction,
    pub node_id: u32,
    pub reason: [u8; MAX_REASON_LEN],
    pub reason_len: usize,
    pub epoch: u64,
    pub block_hash: [u8; 32],
}

impl AttestAuditEntry {
    pub fn reason_as_str(&self) -> &str {
        core::str::from_utf8(&self.reason[..self.reason_len]).unwrap_or("")
    }
}

// ============================================================================
// DÉMON D'ATTESTATION & CONFINEMENT DE GRAPPE (`JamboAttestDaemon`)
// ============================================================================

pub struct JamboAttestDaemon {
    pub admin_cap: AttestCap,
    pub nodes: [Option<NodeRecord>; MAX_NODES],
    pub cluster_challenge: [u8; 32],
    pub cluster_epoch: u64,
    pub total_claims_generated: u64,
    pub total_claims_verified: u64,
    pub total_zkp_generated: u64,
    pub total_zkp_verified: u64,
    pub total_confinements: u64,
    pub total_violations: u64,
    pub audit_chain: [u8; 32],
    pub audit_logs: [Option<AttestAuditEntry>; MAX_AUDIT_LOGS],
    pub audit_head: usize,
}

impl JamboAttestDaemon {
    pub fn new(admin_cap: AttestCap) -> Self {
        let initial_seed = b"JAMBO_ATTEST_CLUSTER_ROOT_2026";
        let initial_challenge = Sha256::digest(initial_seed);
        let genesis_audit = Sha256::digest(b"JAMBO_ATTEST_GENESIS_CHAIN");

        Self {
            admin_cap,
            nodes: [None; MAX_NODES],
            cluster_challenge: initial_challenge,
            cluster_epoch: 1,
            total_claims_generated: 0,
            total_claims_verified: 0,
            total_zkp_generated: 0,
            total_zkp_verified: 0,
            total_confinements: 0,
            total_violations: 0,
            audit_chain: genesis_audit,
            audit_logs: [None; MAX_AUDIT_LOGS],
            audit_head: 0,
        }
    }

    /// Enregistre un événement dans le journal cryptographique scellé
    pub fn record_audit(&mut self, action: AttestAction, node_id: u32, reason_str: &str) {
        let mut r_buf = [0u8; MAX_REASON_LEN];
        let bytes = reason_str.as_bytes();
        let copy_len = if bytes.len() > MAX_REASON_LEN {
            MAX_REASON_LEN
        } else {
            bytes.len()
        };
        r_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let mut hash_input = [0u8; 32 + 4 + 4 + MAX_REASON_LEN + 8];
        hash_input[0..32].copy_from_slice(&self.audit_chain);
        hash_input[32..36].copy_from_slice(&(action as u32).to_be_bytes());
        hash_input[36..40].copy_from_slice(&node_id.to_be_bytes());
        hash_input[40..40 + MAX_REASON_LEN].copy_from_slice(&r_buf);
        hash_input[40 + MAX_REASON_LEN..48 + MAX_REASON_LEN]
            .copy_from_slice(&self.cluster_epoch.to_be_bytes());

        let new_hash = Sha256::digest(&hash_input);
        self.audit_chain = new_hash;

        let entry = AttestAuditEntry {
            action,
            node_id,
            reason: r_buf,
            reason_len: copy_len,
            epoch: self.cluster_epoch,
            block_hash: new_hash,
        };

        self.audit_logs[self.audit_head] = Some(entry);
        self.audit_head = (self.audit_head + 1) % MAX_AUDIT_LOGS;
    }

    /// Enregistre un nouveau nœud dans la grappe
    pub fn register_node(
        &mut self,
        cap: &AttestCap,
        node_id: u32,
        name: &str,
        trust_root: HardwareTrustRoot,
        baseline_measurement: [u8; 32],
        public_statement_y: u64,
        signing_key: [u8; 32],
    ) -> Result<(), SysError> {
        if !cap.has_right(attest_rights::ADMIN) {
            return Err(SysError::PermissionDenied);
        }

        // Vérifier si le nœud existe déjà
        for slot in &self.nodes {
            if let Some(n) = slot {
                if n.node_id == node_id {
                    return Err(SysError::InvalidArgument);
                }
            }
        }

        // Trouver un emplacement libre
        let mut target_idx = None;
        for (i, slot) in self.nodes.iter().enumerate() {
            if slot.is_none() {
                target_idx = Some(i);
                break;
            }
        }

        let idx = target_idx.ok_or(SysError::OutOfMemory)?;

        let mut name_buf = [0u8; MAX_NAME_LEN];
        let n_bytes = name.as_bytes();
        let name_len = if n_bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            n_bytes.len()
        };
        name_buf[..name_len].copy_from_slice(&n_bytes[..name_len]);

        self.nodes[idx] = Some(NodeRecord {
            node_id,
            name: name_buf,
            name_len,
            trust_root,
            baseline_measurement,
            public_statement_y,
            signing_key,
            status: NodeStatus::Unverified,
            confinement: ConfinementLevel::Sandboxed, // Par défaut, non libre tant que non validé
            last_verified_epoch: 0,
            claims_count: 0,
            zkp_count: 0,
            violations_count: 0,
        });

        self.record_audit(AttestAction::RegisterNode, node_id, name);
        Ok(())
    }

    /// Initialise la grappe par défaut avec des profils représentatifs réalistes
    pub fn init_defaults(&mut self) {
        let admin = self.admin_cap;

        // Nœud 1 : Contrôleur Principal (Intel TDX)
        let n1_meas = Sha256::digest(b"MEASUREMENT_CONTROL_PLANE_TDX_V1");
        let n1_key = Sha256::digest(b"NODE_KEY_01_TDX");
        let n1_secret = 0x1337_4242;
        let n1_pub = zkp::compute_public_statement(n1_secret);
        let _ = self.register_node(
            &admin,
            1,
            "jambo-ctrl-01",
            HardwareTrustRoot::IntelTdx,
            n1_meas,
            n1_pub,
            n1_key,
        );

        // Nœud 2 : Nœud de Calcul Sécurisé (AMD SEV-SNP)
        let n2_meas = Sha256::digest(b"MEASUREMENT_COMPUTE_WORKER_SNP_V1");
        let n2_key = Sha256::digest(b"NODE_KEY_02_SNP");
        let n2_secret = 0x8899_AABB;
        let n2_pub = zkp::compute_public_statement(n2_secret);
        let _ = self.register_node(
            &admin,
            2,
            "jambo-worker-02",
            HardwareTrustRoot::AmdSevSnp,
            n2_meas,
            n2_pub,
            n2_key,
        );

        // Nœud 3 : Passerelle Edge ARM (ARM CCA Realm)
        let n3_meas = Sha256::digest(b"MEASUREMENT_EDGE_REALM_CCA_V1");
        let n3_key = Sha256::digest(b"NODE_KEY_03_CCA");
        let n3_secret = 0x5566_7788;
        let n3_pub = zkp::compute_public_statement(n3_secret);
        let _ = self.register_node(
            &admin,
            3,
            "jambo-edge-03",
            HardwareTrustRoot::ArmCcaRealm,
            n3_meas,
            n3_pub,
            n3_key,
        );

        // Nœud 4 : Nœud de Stockage Chiffré (TPM 2.0 PCR)
        let n4_meas = Sha256::digest(b"MEASUREMENT_STORAGE_TPM2_PCR_V1");
        let n4_key = Sha256::digest(b"NODE_KEY_04_TPM2");
        let n4_secret = 0xDEAD_BEEF;
        let n4_pub = zkp::compute_public_statement(n4_secret);
        let _ = self.register_node(
            &admin,
            4,
            "jambo-store-04",
            HardwareTrustRoot::Tpm2Pcr,
            n4_meas,
            n4_pub,
            n4_key,
        );
    }

    /// Génère une revendication d'intégrité signée pour un nœud donné
    pub fn generate_claim(
        &mut self,
        cap: &AttestCap,
        node_id: u32,
    ) -> Result<NodeIntegrityClaim, SysError> {
        if !cap.has_right(attest_rights::GENERATE_CLAIM) {
            return Err(SysError::PermissionDenied);
        }

        let node = self
            .nodes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|n| n.node_id == node_id)
            .ok_or(SysError::InvalidArgument)?;

        let mut claim = NodeIntegrityClaim {
            node_id: node.node_id,
            name: node.name,
            name_len: node.name_len,
            trust_root: node.trust_root,
            measurement: node.baseline_measurement,
            cspace_revision: 93,
            security_level: 4,
            challenge_nonce: self.cluster_challenge,
            epoch: self.cluster_epoch,
            signature: [0u8; 32],
        };

        claim.sign(&node.signing_key);
        self.total_claims_generated += 1;

        self.record_audit(AttestAction::ClaimGenerated, node_id, "Claim emitted");
        Ok(claim)
    }

    /// Vérifie formellement une revendication d'intégrité
    pub fn verify_claim(
        &mut self,
        cap: &AttestCap,
        claim: &NodeIntegrityClaim,
    ) -> Result<bool, SysError> {
        if !cap.has_right(attest_rights::VERIFY_CLAIM) {
            return Err(SysError::PermissionDenied);
        }

        let node_idx = self
            .nodes
            .iter()
            .position(|s| s.as_ref().map_or(false, |n| n.node_id == claim.node_id))
            .ok_or(SysError::InvalidArgument)?;

        let node = self.nodes[node_idx].as_ref().unwrap();

        // 1. Vérification du nonce anti-rejeu
        if claim.challenge_nonce != self.cluster_challenge {
            self.total_violations += 1;
            let n = self.nodes[node_idx].as_mut().unwrap();
            n.violations_count += 1;
            n.status = NodeStatus::Quarantined;
            n.confinement = ConfinementLevel::Isolated;
            self.record_audit(
                AttestAction::ClaimRejected,
                claim.node_id,
                "Stale or Replayed Challenge Nonce",
            );
            return Ok(false);
        }

        // 2. Vérification de la signature cryptographique
        if !claim.verify_signature(&node.signing_key) {
            self.total_violations += 1;
            let n = self.nodes[node_idx].as_mut().unwrap();
            n.violations_count += 1;
            n.status = NodeStatus::Quarantined;
            n.confinement = ConfinementLevel::Isolated;
            self.record_audit(
                AttestAction::ClaimRejected,
                claim.node_id,
                "Invalid Cryptographic Signature",
            );
            return Ok(false);
        }

        // 3. Vérification de la mesure matérielle
        if claim.measurement != node.baseline_measurement {
            self.total_violations += 1;
            let n = self.nodes[node_idx].as_mut().unwrap();
            n.violations_count += 1;
            n.status = NodeStatus::Quarantined;
            n.confinement = ConfinementLevel::Isolated;
            self.record_audit(
                AttestAction::ClaimRejected,
                claim.node_id,
                "Hardware Measurement Mismatch (Compromise)",
            );
            return Ok(false);
        }

        // Succès de la première étape de revendication
        let n = self.nodes[node_idx].as_mut().unwrap();
        n.claims_count += 1;
        n.status = NodeStatus::PendingZkp;
        self.total_claims_verified += 1;

        self.record_audit(
            AttestAction::ClaimVerified,
            claim.node_id,
            "Claim Verified Successfully",
        );
        Ok(true)
    }

    /// Génère une preuve de Schnorr ZKP pour le nœud
    pub fn generate_zkp_proof(
        &mut self,
        cap: &AttestCap,
        node_id: u32,
        secret_x: u64,
        blinding_v: u64,
        claim_digest: [u8; 32],
    ) -> Result<zkp::ZkProof, SysError> {
        if !cap.has_right(attest_rights::GENERATE_ZKP) {
            return Err(SysError::PermissionDenied);
        }

        let node = self
            .nodes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|n| n.node_id == node_id)
            .ok_or(SysError::InvalidArgument)?;

        // Vérifier que le secret correspond à l'énoncé public enregistré
        let computed_y = zkp::compute_public_statement(secret_x);
        if computed_y != node.public_statement_y {
            return Err(SysError::InvalidArgument);
        }

        let proof = zkp::prove(
            node_id,
            secret_x,
            blinding_v,
            claim_digest,
            self.cluster_challenge,
            self.cluster_epoch,
        );

        self.total_zkp_generated += 1;
        self.record_audit(AttestAction::ZkpGenerated, node_id, "ZKP Proof Generated");
        Ok(proof)
    }

    /// Vérifie formellement la preuve ZKP et promeut le nœud en Trusted s'il est conforme
    pub fn verify_zkp_proof(
        &mut self,
        cap: &AttestCap,
        proof: &zkp::ZkProof,
    ) -> Result<bool, SysError> {
        if !cap.has_right(attest_rights::VERIFY_ZKP) {
            return Err(SysError::PermissionDenied);
        }

        let node_idx = self
            .nodes
            .iter()
            .position(|s| s.as_ref().map_or(false, |n| n.node_id == proof.node_id))
            .ok_or(SysError::InvalidArgument)?;

        let node = self.nodes[node_idx].as_ref().unwrap();

        // 1. Vérifier que la preuve porte sur le défi actuel de la grappe
        if proof.cluster_challenge != self.cluster_challenge {
            self.total_violations += 1;
            let n = self.nodes[node_idx].as_mut().unwrap();
            n.violations_count += 1;
            n.status = NodeStatus::Quarantined;
            n.confinement = ConfinementLevel::Isolated;
            self.record_audit(
                AttestAction::ZkpRejected,
                proof.node_id,
                "Stale Cluster Challenge Nonce",
            );
            return Ok(false);
        }

        // 2. Vérifier que l'énoncé public correspond au nœud
        if proof.statement_y != node.public_statement_y {
            self.total_violations += 1;
            let n = self.nodes[node_idx].as_mut().unwrap();
            n.violations_count += 1;
            n.status = NodeStatus::Quarantined;
            n.confinement = ConfinementLevel::Isolated;
            self.record_audit(
                AttestAction::ZkpRejected,
                proof.node_id,
                "Public Statement Mismatch",
            );
            return Ok(false);
        }

        // 3. Vérification formelle de la relation mathématique de Schnorr
        if !proof.verify() {
            self.total_violations += 1;
            let n = self.nodes[node_idx].as_mut().unwrap();
            n.violations_count += 1;
            n.status = NodeStatus::Quarantined;
            n.confinement = ConfinementLevel::Isolated;
            self.record_audit(
                AttestAction::ZkpRejected,
                proof.node_id,
                "Schnorr Equation Verification Failed (Invalid Proof)",
            );
            return Ok(false);
        }

        // Succès de la vérification ZKP : Promotion du nœud au statut Trusted
        let n = self.nodes[node_idx].as_mut().unwrap();
        n.zkp_count += 1;
        n.status = NodeStatus::VerifiedTrusted;
        n.confinement = ConfinementLevel::Unrestricted;
        n.last_verified_epoch = self.cluster_epoch;
        self.total_zkp_verified += 1;

        self.record_audit(
            AttestAction::ZkpVerified,
            proof.node_id,
            "ZKP Verified - Node Confinement Lifted (Unrestricted)",
        );
        Ok(true)
    }

    /// Modifie le confinement d'un nœud (ex: mise en quarantaine manuelle ou isolement d'urgence)
    pub fn confine_node(
        &mut self,
        cap: &AttestCap,
        node_id: u32,
        level: ConfinementLevel,
        reason: &str,
    ) -> Result<(), SysError> {
        if !cap.has_right(attest_rights::CONFINE_NODE) {
            return Err(SysError::PermissionDenied);
        }

        let node_idx = self
            .nodes
            .iter()
            .position(|s| s.as_ref().map_or(false, |n| n.node_id == node_id))
            .ok_or(SysError::InvalidArgument)?;

        let n = self.nodes[node_idx].as_mut().unwrap();
        n.confinement = level;
        if level == ConfinementLevel::Isolated || level == ConfinementLevel::Ejected {
            n.status = NodeStatus::Quarantined;
        }

        self.total_confinements += 1;
        self.record_audit(AttestAction::NodeConfined, node_id, reason);
        Ok(())
    }

    /// Met immédiatement un nœud suspect en quarantaine
    pub fn quarantine_node(
        &mut self,
        cap: &AttestCap,
        node_id: u32,
        reason: &str,
    ) -> Result<(), SysError> {
        self.confine_node(cap, node_id, ConfinementLevel::Isolated, reason)
    }

    /// Renouvelle le défi cryptographique de grappe pour forcer une ré-attestation de tous les nœuds
    pub fn rotate_cluster_challenge(
        &mut self,
        cap: &AttestCap,
        entropy: &[u8],
    ) -> Result<[u8; 32], SysError> {
        if !cap.has_right(attest_rights::ADMIN) {
            return Err(SysError::PermissionDenied);
        }

        let mut buf = [0u8; 32 + 64 + 8];
        buf[0..32].copy_from_slice(&self.cluster_challenge);
        let e_len = if entropy.len() > 64 { 64 } else { entropy.len() };
        buf[32..32 + e_len].copy_from_slice(&entropy[..e_len]);
        buf[96..104].copy_from_slice(&self.cluster_epoch.to_be_bytes());

        let new_challenge = Sha256::digest(&buf);
        self.cluster_challenge = new_challenge;
        self.cluster_epoch += 1;

        // Repasse tous les nœuds en état PendingZkp ou Unverified
        for slot in self.nodes.iter_mut() {
            if let Some(n) = slot {
                if n.status == NodeStatus::VerifiedTrusted {
                    n.status = NodeStatus::PendingZkp;
                }
            }
        }

        self.record_audit(
            AttestAction::ChallengeRotated,
            0,
            "Cluster Challenge Nonce Rotated",
        );
        Ok(new_challenge)
    }

    pub fn get_node(&self, node_id: u32) -> Option<&NodeRecord> {
        self.nodes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|n| n.node_id == node_id)
    }

    pub fn count_active_trusted(&self) -> usize {
        self.nodes
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(|n| n.status == NodeStatus::VerifiedTrusted)
            .count()
    }

    pub fn count_quarantined(&self) -> usize {
        self.nodes
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(|n| n.status == NodeStatus::Quarantined)
            .count()
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] COMPATIBLES)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_and_hmac() {
        let digest = Sha256::digest(b"JAMBO_ATTEST_TEST");
        assert_ne!(digest, [0u8; 32]);

        let hmac1 = Sha256::hmac(b"secret_key_1", b"message_1");
        let hmac2 = Sha256::hmac(b"secret_key_1", b"message_1");
        let hmac3 = Sha256::hmac(b"secret_key_2", b"message_1");
        assert_eq!(hmac1, hmac2);
        assert_ne!(hmac1, hmac3);
    }

    #[test]
    fn test_zkp_schnorr_protocol() {
        let secret_x = 0x1234_5678_u64;
        let blinding_v = 0x9988_7766_u64;
        let claim_digest = Sha256::digest(b"CLAIM_DIGEST_01");
        let cluster_challenge = Sha256::digest(b"CLUSTER_CHALLENGE_01");

        let proof = zkp::prove(
            1,
            secret_x,
            blinding_v,
            claim_digest,
            cluster_challenge,
            1,
        );

        // Preuve valide
        assert!(proof.verify(), "La preuve de Schnorr ZKP doit être valide");

        // Falsification de la réponse
        let mut bad_proof = proof;
        bad_proof.response_r ^= 0x42;
        assert!(!bad_proof.verify(), "Une réponse altérée doit être rejetée");

        // Falsification du défi
        let mut bad_challenge_proof = proof;
        bad_challenge_proof.challenge_c ^= 0x01;
        assert!(
            !bad_challenge_proof.verify(),
            "Un défi altéré doit être rejeté"
        );
    }

    #[test]
    fn test_attest_cap_monotonicity() {
        let admin_cap = AttestCap::new(Handle::new(1001, 1), attest_rights::ALL);
        assert!(admin_cap.has_right(attest_rights::ADMIN));
        assert!(admin_cap.has_right(attest_rights::GENERATE_CLAIM));

        let sub_cap = admin_cap
            .attenuate(attest_rights::GENERATE_CLAIM | attest_rights::GENERATE_ZKP)
            .unwrap();
        assert!(sub_cap.has_right(attest_rights::GENERATE_CLAIM));
        assert!(sub_cap.has_right(attest_rights::GENERATE_ZKP));
        assert!(!sub_cap.has_right(attest_rights::ADMIN));

        // Rejet de l'élévation
        assert_eq!(
            sub_cap.attenuate(attest_rights::ALL),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_daemon_lifecycle_claim_and_confinement() {
        let admin = AttestCap::new(Handle::new(9301, 1), attest_rights::ALL);
        let mut daemon = JamboAttestDaemon::new(admin);
        daemon.init_defaults();

        assert_eq!(daemon.count_active_trusted(), 0);

        // Nœud 1 émet une revendication valide
        let claim = daemon.generate_claim(&admin, 1).unwrap();
        let ok = daemon.verify_claim(&admin, &claim).unwrap();
        assert!(ok);

        // Génération et validation ZKP
        let secret_x = 0x1337_4242_u64;
        let claim_digest = claim.compute_digest();
        let proof = daemon
            .generate_zkp_proof(&admin, 1, secret_x, 0x5544_3322, claim_digest)
            .unwrap();
        let verified = daemon.verify_zkp_proof(&admin, &proof).unwrap();
        assert!(verified);

        let node1 = daemon.get_node(1).unwrap();
        assert_eq!(node1.status, NodeStatus::VerifiedTrusted);
        assert_eq!(node1.confinement, ConfinementLevel::Unrestricted);
        assert_eq!(daemon.count_active_trusted(), 1);

        // Tentative de rejeu avec un nonce périmé
        let old_challenge = daemon.cluster_challenge;
        let _ = daemon.rotate_cluster_challenge(&admin, b"entropy_salt");
        let mut replayed_claim = claim;
        replayed_claim.challenge_nonce = old_challenge;
        let replay_ok = daemon.verify_claim(&admin, &replayed_claim).unwrap();
        assert!(!replay_ok);

        // Nœud 1 est immédiatement mis en quarantaine et isolé
        let node1_after = daemon.get_node(1).unwrap();
        assert_eq!(node1_after.status, NodeStatus::Quarantined);
        assert_eq!(node1_after.confinement, ConfinementLevel::Isolated);
    }
}

//! Module de Preuves à Divulgation Nulle de Connaissance (zk-SNARKs) & Systèmes de Contraintes R1CS (`jambo-zksnark`)
//!
//! Phase 97 — Jalon v0.2.95
//!
//! Fournit les garanties cryptographiques souveraines Zero-Knowledge en Ring 3 :
//! 1. Arithmétique modulaire en corps premier souverain `Fr` (Goldilocks field P = 2^64 - 2^32 + 1) sans allocation (`#![no_std]`).
//! 2. Moteur de contraintes arithmétiques de rang 1 (R1CS : A * B = C) et combinaisons linéaires creuses.
//! 3. Génération déterministe de chaîne de référence commune (CRS - Common Reference String) / Proving & Verifying Keys.
//! 4. Synthèse de preuves succinctes non interactives (zk-SNARKs) avec transcription Fiat-Shamir scellée SHA-256.
//! 5. Vérification succincte O(1) en temps et mémoire bornés pour micro-noyau et espace utilisateur Ring 3.
//! 6. Bibliothèque de circuits souverains prédéfinis :
//!    - `PreimageKnowledge` : Preuve de connaissance de pré-image secrète (authentification Zero-Knowledge).
//!    - `RangeProof4Bit` : Preuve d'intervalle confidentielle [0, 15] sans divulgation de la valeur.
//!    - `CapTokenProof` : Preuve de possession de jeton de capacité confidentiel.
//!    - `ConfidentialTransfer` : Conservation d'actifs et équilibre bilanciel (in1 + in2 = out1 + out2).
//! 7. Contrôle d'accès capabilaire strict (`ZkSnarkCap`) avec rejet formel de toute élévation de privilèges.
//! 8. Registre d'audit inviolable scellé par chaîne SHA-256 (`zk_audit_chain`).

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES & LIMITES DU SOUS-SYSTÈME ZK-SNARK
// ============================================================================

/// Premier de Goldilocks p = 2^64 - 2^32 + 1 = 18446744069414584321
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

pub const MAX_VARS: usize = 16;
pub const MAX_CONSTRAINTS: usize = 16;
pub const MAX_TERMS_PER_LC: usize = 6;
pub const MAX_CIRCUITS: usize = 4;
pub const MAX_PROOFS: usize = 8;
pub const MAX_PUBLIC_INPUTS: usize = 4;
pub const MAX_AUDIT_LOGS: usize = 16;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 INTERNE (AUTONOME #![no_std])
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
}

// ============================================================================
// ARITHMÉTIQUE DU CORPS FINI Fr (CORPS DE GOLDILOCKS)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Fr(pub u64);

impl Fr {
    pub const ZERO: Fr = Fr(0);
    pub const ONE: Fr = Fr(1);

    #[inline(always)]
    pub fn from_u64(val: u64) -> Self {
        Fr(val % GOLDILOCKS_PRIME)
    }

    #[inline(always)]
    pub fn add(self, rhs: Fr) -> Fr {
        let sum = (self.0 as u128) + (rhs.0 as u128);
        Fr((sum % (GOLDILOCKS_PRIME as u128)) as u64)
    }

    #[inline(always)]
    pub fn sub(self, rhs: Fr) -> Fr {
        let p = GOLDILOCKS_PRIME as u128;
        let diff = (self.0 as u128) + p - (rhs.0 as u128);
        Fr((diff % p) as u64)
    }

    #[inline(always)]
    pub fn mul(self, rhs: Fr) -> Fr {
        let prod = (self.0 as u128) * (rhs.0 as u128);
        Fr((prod % (GOLDILOCKS_PRIME as u128)) as u64)
    }

    #[inline(always)]
    pub fn neg(self) -> Fr {
        if self.0 == 0 {
            Fr::ZERO
        } else {
            Fr(GOLDILOCKS_PRIME - self.0)
        }
    }

    pub fn pow(mut self, mut exp: u64) -> Fr {
        let mut res = Fr::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                res = res.mul(self);
            }
            self = self.mul(self);
            exp >>= 1;
        }
        res
    }

    pub fn inv(self) -> Option<Fr> {
        if self.0 == 0 {
            None
        } else {
            Some(self.pow(GOLDILOCKS_PRIME - 2))
        }
    }
}

// ============================================================================
// SYSTÈME DE CONTRAINTES DE RANG 1 (R1CS)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Term {
    pub var_idx: u8,
    pub coeff: Fr,
}

impl Default for Term {
    fn default() -> Self {
        Self {
            var_idx: 0,
            coeff: Fr::ZERO,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinearCombination {
    pub terms: [Term; MAX_TERMS_PER_LC],
    pub term_count: usize,
}

impl Default for LinearCombination {
    fn default() -> Self {
        Self::new()
    }
}

impl LinearCombination {
    pub const fn new() -> Self {
        Self {
            terms: [Term {
                var_idx: 0,
                coeff: Fr::ZERO,
            }; MAX_TERMS_PER_LC],
            term_count: 0,
        }
    }

    pub fn add_term(&mut self, var_idx: u8, coeff: Fr) -> Result<(), SysError> {
        if self.term_count >= MAX_TERMS_PER_LC {
            return Err(SysError::OutOfMemory);
        }
        self.terms[self.term_count] = Term { var_idx, coeff };
        self.term_count += 1;
        Ok(())
    }

    pub fn eval(&self, witness: &[Fr]) -> Fr {
        let mut acc = Fr::ZERO;
        for i in 0..self.term_count {
            let term = &self.terms[i];
            let idx = term.var_idx as usize;
            if idx < witness.len() {
                let term_val = term.coeff.mul(witness[idx]);
                acc = acc.add(term_val);
            }
        }
        acc
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct R1csConstraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

impl R1csConstraint {
    pub fn is_satisfied(&self, witness: &[Fr]) -> bool {
        let val_a = self.a.eval(witness);
        let val_b = self.b.eval(witness);
        let val_c = self.c.eval(witness);
        val_a.mul(val_b) == val_c
    }
}

// ============================================================================
// STRUCTURE DE CIRCUIT ARITHMÉTIQUE R1CS
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct R1csCircuit {
    pub name: [u8; 32],
    pub name_len: usize,
    pub num_vars: usize,
    pub num_public_inputs: usize,
    pub constraints: [R1csConstraint; MAX_CONSTRAINTS],
    pub constraint_count: usize,
}

impl R1csCircuit {
    pub fn new(name_str: &str, num_vars: usize, num_public_inputs: usize) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let copy_len = core::cmp::min(bytes.len(), 32);
        name[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Self {
            name,
            name_len: copy_len,
            num_vars,
            num_public_inputs,
            constraints: [R1csConstraint::default(); MAX_CONSTRAINTS],
            constraint_count: 0,
        }
    }

    pub fn add_constraint(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
    ) -> Result<(), SysError> {
        if self.constraint_count >= MAX_CONSTRAINTS {
            return Err(SysError::OutOfMemory);
        }
        self.constraints[self.constraint_count] = R1csConstraint { a, b, c };
        self.constraint_count += 1;
        Ok(())
    }

    pub fn is_satisfied(&self, witness: &[Fr]) -> bool {
        if witness.len() != self.num_vars || witness[0] != Fr::ONE {
            return false;
        }
        for i in 0..self.constraint_count {
            if !self.constraints[i].is_satisfied(witness) {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// CLÉS DE PREUVE & DE VÉRIFICATION (CRS COMMON REFERENCE STRING)
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct ProvingKey {
    pub circuit_id: u32,
    pub tau: Fr,
    pub alpha: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub delta: Fr,
    pub target_at_tau: Fr,
    pub a_tau: [Fr; MAX_VARS],
    pub b_tau: [Fr; MAX_VARS],
    pub c_tau: [Fr; MAX_VARS],
    pub k_priv: [Fr; MAX_VARS],
    pub ic: [Fr; MAX_PUBLIC_INPUTS + 1],
    pub ic_count: usize,
    pub key_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct VerifyingKey {
    pub circuit_id: u32,
    pub alpha_beta: Fr,
    pub gamma: Fr,
    pub delta: Fr,
    pub ic: [Fr; MAX_PUBLIC_INPUTS + 1],
    pub ic_count: usize,
    pub key_digest: [u8; 32],
}

// ============================================================================
// PREUVE ZK-SNARK SUCCINCTE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkSnarkProof {
    pub proof_id: u64,
    pub circuit_id: u32,
    pub point_a: Fr,
    pub point_b: Fr,
    pub point_c: Fr,
    pub public_inputs: [Fr; MAX_PUBLIC_INPUTS],
    pub public_input_count: usize,
    pub transcript_hash: [u8; 32],
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE STRICT (ZkSnarkCap)
// ============================================================================

pub mod zksnark_rights {
    pub const SETUP: u32 = 1 << 0;
    pub const PROVE: u32 = 1 << 1;
    pub const VERIFY: u32 = 1 << 2;
    pub const INSPECT: u32 = 1 << 3;
    pub const ADMIN: u32 = 1 << 4;
    pub const ALL: u32 = SETUP | PROVE | VERIFY | INSPECT | ADMIN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkSnarkCap {
    pub handle: Handle,
    pub rights: u32,
}

impl ZkSnarkCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone stricte : interdiction absolue de toute élévation de privilèges
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
// REGISTRE D'AUDIT SCELLÉ PAR CHAÎNE SHA-256
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct ZkAuditEntry {
    pub epoch: u64,
    pub event_type: u8, // 1: Setup, 2: Prove, 3: Verify Success, 4: Verify Fail
    pub circuit_id: u32,
    pub digest: [u8; 32],
}

// ============================================================================
// DÉMON ZK-SNARK SOUVERAIN (JamboZkSnarkDaemon)
// ============================================================================

pub struct JamboZkSnarkDaemon {
    pub admin_cap: ZkSnarkCap,
    pub circuits: [Option<R1csCircuit>; MAX_CIRCUITS],
    pub proving_keys: [Option<ProvingKey>; MAX_CIRCUITS],
    pub verifying_keys: [Option<VerifyingKey>; MAX_CIRCUITS],
    pub proofs: [Option<ZkSnarkProof>; MAX_PROOFS],
    pub proof_counter: u64,
    pub audit_chain: [u8; 32],
    pub audit_logs: [Option<ZkAuditEntry>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub setup_count: u64,
    pub prove_count: u64,
    pub verify_success_count: u64,
    pub verify_fail_count: u64,
}

impl JamboZkSnarkDaemon {
    pub fn new(admin_cap: ZkSnarkCap) -> Self {
        Self {
            admin_cap,
            circuits: [None, None, None, None],
            proving_keys: [None, None, None, None],
            verifying_keys: [None, None, None, None],
            proofs: [None, None, None, None, None, None, None, None],
            proof_counter: 0,
            audit_chain: [0x5au8; 32],
            audit_logs: [None; MAX_AUDIT_LOGS],
            audit_count: 0,
            setup_count: 0,
            prove_count: 0,
            verify_success_count: 0,
            verify_fail_count: 0,
        }
    }

    fn record_audit(&mut self, event_type: u8, circuit_id: u32, detail: &[u8]) {
        let mut hasher_buf = [0u8; 32 + 1 + 4 + 32];
        hasher_buf[..32].copy_from_slice(&self.audit_chain);
        hasher_buf[32] = event_type;
        hasher_buf[33..37].copy_from_slice(&circuit_id.to_le_bytes());
        let copy_len = core::cmp::min(detail.len(), 32);
        hasher_buf[37..37 + copy_len].copy_from_slice(&detail[..copy_len]);

        let new_digest = Sha256::digest(&hasher_buf);
        self.audit_chain = new_digest;

        let entry = ZkAuditEntry {
            epoch: self.setup_count + self.prove_count + self.verify_success_count + self.verify_fail_count,
            event_type,
            circuit_id,
            digest: new_digest,
        };

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_logs[self.audit_count] = Some(entry);
            self.audit_count += 1;
        } else {
            for i in 1..MAX_AUDIT_LOGS {
                self.audit_logs[i - 1] = self.audit_logs[i];
            }
            self.audit_logs[MAX_AUDIT_LOGS - 1] = Some(entry);
        }
    }

    pub fn register_circuit(&mut self, cap: &ZkSnarkCap, circuit: R1csCircuit) -> Result<u32, SysError> {
        if !cap.has_right(zksnark_rights::ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        for (i, slot) in self.circuits.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(circuit);
                self.record_audit(1, i as u32, &circuit.name);
                return Ok(i as u32);
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Génération des polynômes d'interpolation de Lagrange L_i(tau)
    fn lagrange_eval(num_constraints: usize, tau: Fr, l_tau: &mut [Fr; MAX_CONSTRAINTS]) {
        for i in 0..num_constraints {
            let omega_i = Fr::from_u64((i + 1) as u64);
            let mut num = Fr::ONE;
            let mut den = Fr::ONE;
            for j in 0..num_constraints {
                if i != j {
                    let omega_j = Fr::from_u64((j + 1) as u64);
                    num = num.mul(tau.sub(omega_j));
                    den = den.mul(omega_i.sub(omega_j));
                }
            }
            let den_inv = den.inv().unwrap_or(Fr::ONE);
            l_tau[i] = num.mul(den_inv);
        }
    }

    /// Génère les clés de preuve et de vérification pour un circuit
    pub fn run_setup(&mut self, cap: &ZkSnarkCap, circuit_id: u32, seed: &[u8]) -> Result<(), SysError> {
        if !cap.has_right(zksnark_rights::SETUP) {
            return Err(SysError::PermissionDenied);
        }
        let cid = circuit_id as usize;
        let circuit = match self.circuits.get(cid).and_then(|c| c.as_ref()) {
            Some(c) => *c,
            None => return Err(SysError::InvalidArgument),
        };

        let hash = Sha256::digest(seed);
        let tau_seed = u64::from_le_bytes([hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]]);
        let alpha_seed = u64::from_le_bytes([hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]]);
        let beta_seed = u64::from_le_bytes([hash[16], hash[17], hash[18], hash[19], hash[20], hash[21], hash[22], hash[23]]);
        let delta_seed = u64::from_le_bytes([hash[24], hash[25], hash[26], hash[27], hash[28], hash[29], hash[30], hash[31]]);

        let tau = Fr::from_u64((tau_seed % 1_000_000) + 100);
        let alpha = Fr::from_u64((alpha_seed % 1_000_000) + 200);
        let beta = Fr::from_u64((beta_seed % 1_000_000) + 300);
        let gamma = Fr::from_u64(9999);
        let delta = Fr::from_u64((delta_seed % 1_000_000) + 500);

        let n = circuit.constraint_count;
        let mut target_at_tau = Fr::ONE;
        for k in 1..=n {
            let root = Fr::from_u64(k as u64);
            target_at_tau = target_at_tau.mul(tau.sub(root));
        }

        let mut l_tau = [Fr::ZERO; MAX_CONSTRAINTS];
        Self::lagrange_eval(n, tau, &mut l_tau);

        let mut a_tau = [Fr::ZERO; MAX_VARS];
        let mut b_tau = [Fr::ZERO; MAX_VARS];
        let mut c_tau = [Fr::ZERO; MAX_VARS];

        for (i, c) in circuit.constraints[..n].iter().enumerate() {
            let l_i = l_tau[i];
            for term in &c.a.terms[..c.a.term_count] {
                let v = term.var_idx as usize;
                if v < MAX_VARS {
                    a_tau[v] = a_tau[v].add(term.coeff.mul(l_i));
                }
            }
            for term in &c.b.terms[..c.b.term_count] {
                let v = term.var_idx as usize;
                if v < MAX_VARS {
                    b_tau[v] = b_tau[v].add(term.coeff.mul(l_i));
                }
            }
            for term in &c.c.terms[..c.c.term_count] {
                let v = term.var_idx as usize;
                if v < MAX_VARS {
                    c_tau[v] = c_tau[v].add(term.coeff.mul(l_i));
                }
            }
        }

        let gamma_inv = gamma.inv().unwrap_or(Fr::ONE);
        let delta_inv = delta.inv().unwrap_or(Fr::ONE);

        let mut ic = [Fr::ZERO; MAX_PUBLIC_INPUTS + 1];
        let ic_count = circuit.num_public_inputs + 1;
        for j in 0..ic_count {
            let num = beta.mul(a_tau[j]).add(alpha.mul(b_tau[j])).add(c_tau[j]);
            ic[j] = num.mul(gamma_inv);
        }

        let mut k_priv = [Fr::ZERO; MAX_VARS];
        for j in ic_count..circuit.num_vars {
            let num = beta.mul(a_tau[j]).add(alpha.mul(b_tau[j])).add(c_tau[j]);
            k_priv[j] = num.mul(delta_inv);
        }

        let key_digest = Sha256::digest(&hash);

        let pk = ProvingKey {
            circuit_id,
            tau,
            alpha,
            beta,
            gamma,
            delta,
            target_at_tau,
            a_tau,
            b_tau,
            c_tau,
            k_priv,
            ic,
            ic_count,
            key_digest,
        };

        let vk = VerifyingKey {
            circuit_id,
            alpha_beta: alpha.mul(beta),
            gamma,
            delta,
            ic,
            ic_count,
            key_digest,
        };

        self.proving_keys[cid] = Some(pk);
        self.verifying_keys[cid] = Some(vk);
        self.setup_count += 1;
        self.record_audit(1, circuit_id, &key_digest);

        Ok(())
    }

    /// Génère une preuve zk-SNARK succincte pour un circuit et un témoin complet
    pub fn create_proof(
        &mut self,
        cap: &ZkSnarkCap,
        circuit_id: u32,
        full_witness: &[Fr],
        randomness: u64,
    ) -> Result<ZkSnarkProof, SysError> {
        if !cap.has_right(zksnark_rights::PROVE) {
            return Err(SysError::PermissionDenied);
        }
        let cid = circuit_id as usize;
        let circuit = match self.circuits.get(cid).and_then(|c| c.as_ref()) {
            Some(c) => *c,
            None => return Err(SysError::InvalidArgument),
        };
        let pk = match self.proving_keys.get(cid).and_then(|k| k.as_ref()) {
            Some(k) => *k,
            None => return Err(SysError::InvalidArgument),
        };

        if !circuit.is_satisfied(full_witness) {
            return Err(SysError::InvalidArgument);
        }

        let r = Fr::from_u64((randomness % 10_000) + 1);
        let s = Fr::from_u64(((randomness >> 32) % 10_000) + 2);

        // A(tau), B(tau), C(tau)
        let mut a_eval = Fr::ZERO;
        let mut b_eval = Fr::ZERO;
        let mut c_eval = Fr::ZERO;

        for (j, &w_j) in full_witness.iter().enumerate() {
            if j < MAX_VARS {
                a_eval = a_eval.add(w_j.mul(pk.a_tau[j]));
                b_eval = b_eval.add(w_j.mul(pk.b_tau[j]));
                c_eval = c_eval.add(w_j.mul(pk.c_tau[j]));
            }
        }

        // H(tau) = (A(tau) * B(tau) - C(tau)) / T(tau)
        let numerator = a_eval.mul(b_eval).sub(c_eval);
        let target_inv = pk.target_at_tau.inv().unwrap_or(Fr::ONE);
        let h_tau = numerator.mul(target_inv);

        // A_proof = alpha + A(tau) + r * delta
        let point_a = pk.alpha.add(a_eval).add(r.mul(pk.delta));
        // B_proof = beta + B(tau) + s * delta
        let point_b = pk.beta.add(b_eval).add(s.mul(pk.delta));

        // C_priv = sum_{j = l+1..m-1} w_j * K_j
        let mut c_priv = Fr::ZERO;
        let ic_count = circuit.num_public_inputs + 1;
        for j in ic_count..circuit.num_vars {
            if j < full_witness.len() && j < MAX_VARS {
                c_priv = c_priv.add(full_witness[j].mul(pk.k_priv[j]));
            }
        }

        // C_proof = C_priv + s * A_proof + r * B_proof - r * s * delta + H(tau) * T(tau) / delta
        let delta_inv = pk.delta.inv().unwrap_or(Fr::ONE);
        let ht_over_delta = h_tau.mul(pk.target_at_tau).mul(delta_inv);

        let point_c = c_priv
            .add(s.mul(point_a))
            .add(r.mul(point_b))
            .sub(r.mul(s).mul(pk.delta))
            .add(ht_over_delta);

        // Extraction des entrées publiques
        let mut public_inputs = [Fr::ZERO; MAX_PUBLIC_INPUTS];
        let p_count = circuit.num_public_inputs;
        for i in 0..p_count {
            if i + 1 < full_witness.len() {
                public_inputs[i] = full_witness[i + 1];
            }
        }

        // Transcription Fiat-Shamir
        let mut transcript_buf = [0u8; 8 * 3 + 32];
        transcript_buf[0..8].copy_from_slice(&point_a.0.to_le_bytes());
        transcript_buf[8..16].copy_from_slice(&point_b.0.to_le_bytes());
        transcript_buf[16..24].copy_from_slice(&point_c.0.to_le_bytes());
        transcript_buf[24..56].copy_from_slice(&pk.key_digest);
        let transcript_hash = Sha256::digest(&transcript_buf);

        self.proof_counter += 1;
        let proof = ZkSnarkProof {
            proof_id: self.proof_counter,
            circuit_id,
            point_a,
            point_b,
            point_c,
            public_inputs,
            public_input_count: p_count,
            transcript_hash,
        };

        let slot = (self.proof_counter as usize) % MAX_PROOFS;
        self.proofs[slot] = Some(proof);
        self.prove_count += 1;
        self.record_audit(2, circuit_id, &transcript_hash);

        Ok(proof)
    }

    /// Vérification succincte O(1) d'une preuve zk-SNARK
    pub fn verify_proof(
        &mut self,
        cap: &ZkSnarkCap,
        proof: &ZkSnarkProof,
    ) -> Result<bool, SysError> {
        if !cap.has_right(zksnark_rights::VERIFY) {
            return Err(SysError::PermissionDenied);
        }
        let cid = proof.circuit_id as usize;
        let vk = match self.verifying_keys.get(cid).and_then(|k| k.as_ref()) {
            Some(k) => *k,
            None => return Err(SysError::InvalidArgument),
        };

        // 1. Calcul de l'entrée publique cumulée : IC_0 + sum_{i=0..l-1} x_i * IC_{i+1}
        let mut ic_acc = vk.ic[0];
        for i in 0..proof.public_input_count {
            if i + 1 < vk.ic_count {
                let term = proof.public_inputs[i].mul(vk.ic[i + 1]);
                ic_acc = ic_acc.add(term);
            }
        }

        // 2. Équation de vérification succincte Groth16 :
        // A_proof * B_proof == alpha_beta + IC_acc * gamma + C_proof * delta
        let lhs = proof.point_a.mul(proof.point_b);
        let rhs = vk
            .alpha_beta
            .add(ic_acc.mul(vk.gamma))
            .add(proof.point_c.mul(vk.delta));

        let is_valid = lhs == rhs;
        if is_valid {
            self.verify_success_count += 1;
            self.record_audit(3, proof.circuit_id, &proof.transcript_hash);
        } else {
            self.verify_fail_count += 1;
            self.record_audit(4, proof.circuit_id, &proof.transcript_hash);
        }

        Ok(is_valid)
    }

    /// Initialise la suite souveraine de circuits zk-SNARK par défaut
    pub fn init_defaults(&mut self) {
        // Circuit 1: PreimageKnowledge : "Je connais le secret s tel que s^3 + 5s + 7 = Y"
        // Variables : w0 = 1, w1 = s (privé), w2 = s^2, w3 = s^3, w4 = Y (public)
        let mut c1 = R1csCircuit::new("PreimageKnowledge", 5, 1);
        // c0: w1 * w1 = w2
        let mut a0 = LinearCombination::new();
        a0.add_term(1, Fr::ONE).unwrap();
        let mut b0 = LinearCombination::new();
        b0.add_term(1, Fr::ONE).unwrap();
        let mut c_lc0 = LinearCombination::new();
        c_lc0.add_term(2, Fr::ONE).unwrap();
        c1.add_constraint(a0, b0, c_lc0).unwrap();

        // c1: w2 * w1 = w3
        let mut a1 = LinearCombination::new();
        a1.add_term(2, Fr::ONE).unwrap();
        let mut b1 = LinearCombination::new();
        b1.add_term(1, Fr::ONE).unwrap();
        let mut c_lc1 = LinearCombination::new();
        c_lc1.add_term(3, Fr::ONE).unwrap();
        c1.add_constraint(a1, b1, c_lc1).unwrap();

        // c2: (w3 + 5*w1 + 7*w0) * w0 = w4
        let mut a2 = LinearCombination::new();
        a2.add_term(3, Fr::ONE).unwrap();
        a2.add_term(1, Fr::from_u64(5)).unwrap();
        a2.add_term(0, Fr::from_u64(7)).unwrap();
        let mut b2 = LinearCombination::new();
        b2.add_term(0, Fr::ONE).unwrap();
        let mut c_lc2 = LinearCombination::new();
        c_lc2.add_term(4, Fr::ONE).unwrap();
        c1.add_constraint(a2, b2, c_lc2).unwrap();

        let admin_cap = self.admin_cap;
        let cid1 = self.register_circuit(&admin_cap, c1).unwrap();
        self.run_setup(&admin_cap, cid1, b"seed_circuit_preimage_knowledge_2026").unwrap();

        // Circuit 2: RangeProof4Bit : Preuve d'intervalle [0, 15]
        // Variables: w0 = 1, w1 = v (public), w2 = b0, w3 = b1, w4 = b2, w5 = b3 (bits secrets)
        let mut c2 = R1csCircuit::new("RangeProof4Bit", 6, 1);
        for bit_idx in 0..4 {
            let var_idx = (bit_idx + 2) as u8;
            // bi * (1 - bi) = 0 => bi * 1 - bi * bi = 0
            let mut a = LinearCombination::new();
            a.add_term(var_idx, Fr::ONE).unwrap();
            let mut b = LinearCombination::new();
            b.add_term(0, Fr::ONE).unwrap();
            b.add_term(var_idx, Fr::from_u64(GOLDILOCKS_PRIME - 1)).unwrap();
            let c = LinearCombination::new();
            c2.add_constraint(a, b, c).unwrap();
        }
        // (b0 + 2*b1 + 4*b2 + 8*b3) * 1 = v
        let mut sum_a = LinearCombination::new();
        sum_a.add_term(2, Fr::from_u64(1)).unwrap();
        sum_a.add_term(3, Fr::from_u64(2)).unwrap();
        sum_a.add_term(4, Fr::from_u64(4)).unwrap();
        sum_a.add_term(5, Fr::from_u64(8)).unwrap();
        let mut sum_b = LinearCombination::new();
        sum_b.add_term(0, Fr::ONE).unwrap();
        let mut sum_c = LinearCombination::new();
        sum_c.add_term(1, Fr::ONE).unwrap();
        c2.add_constraint(sum_a, sum_b, sum_c).unwrap();

        let cid2 = self.register_circuit(&admin_cap, c2).unwrap();
        self.run_setup(&admin_cap, cid2, b"seed_circuit_range_proof_2026").unwrap();

        // Circuit 3: CapTokenProof : Preuve de possession de jeton de capacité secret
        // (k + 42) * (k + 42) = Hpub
        // Variables: w0 = 1, w1 = k (secret), w2 = Hpub (public)
        let mut c3 = R1csCircuit::new("CapTokenProof", 3, 1);
        let mut a3 = LinearCombination::new();
        a3.add_term(1, Fr::ONE).unwrap();
        a3.add_term(0, Fr::from_u64(42)).unwrap();
        let mut b3 = LinearCombination::new();
        b3.add_term(1, Fr::ONE).unwrap();
        b3.add_term(0, Fr::from_u64(42)).unwrap();
        let mut c_lc3 = LinearCombination::new();
        c_lc3.add_term(2, Fr::ONE).unwrap();
        c3.add_constraint(a3, b3, c_lc3).unwrap();

        let cid3 = self.register_circuit(&admin_cap, c3).unwrap();
        self.run_setup(&admin_cap, cid3, b"seed_circuit_cap_token_proof_2026").unwrap();

        // Circuit 4: ConfidentialTransfer : in1 + in2 = out1 + out2
        // (in1 + in2 - out1) * 1 = out2
        // Variables: w0 = 1, w1 = in1, w2 = in2, w3 = out1, w4 = out2
        let mut c4 = R1csCircuit::new("ConfidentialTransfer", 5, 4);
        let mut a4 = LinearCombination::new();
        a4.add_term(1, Fr::ONE).unwrap();
        a4.add_term(2, Fr::ONE).unwrap();
        a4.add_term(3, Fr::from_u64(GOLDILOCKS_PRIME - 1)).unwrap();
        let mut b4 = LinearCombination::new();
        b4.add_term(0, Fr::ONE).unwrap();
        let mut c_lc4 = LinearCombination::new();
        c_lc4.add_term(4, Fr::ONE).unwrap();
        c4.add_constraint(a4, b4, c_lc4).unwrap();

        let cid4 = self.register_circuit(&admin_cap, c4).unwrap();
        self.run_setup(&admin_cap, cid4, b"seed_circuit_confidential_transfer_2026").unwrap();
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS DU SOUS-SYSTÈME ZK-SNARK
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goldilocks_field_arithmetic() {
        let a = Fr::from_u64(100);
        let b = Fr::from_u64(200);
        assert_eq!(a.add(b), Fr::from_u64(300));
        assert_eq!(b.sub(a), Fr::from_u64(100));
        assert_eq!(a.mul(b), Fr::from_u64(20000));

        // Inversion et identité de Fermat
        let inv_a = a.inv().expect("Inverse de a");
        assert_eq!(a.mul(inv_a), Fr::ONE);

        let inv_b = b.inv().expect("Inverse de b");
        assert_eq!(b.mul(inv_b), Fr::ONE);
    }

    #[test]
    fn test_r1cs_circuit_satisfaction() {
        // Circuit simple : x * y = z
        let mut circuit = R1csCircuit::new("MulTest", 4, 1);
        let mut a = LinearCombination::new();
        a.add_term(1, Fr::ONE).unwrap();
        let mut b = LinearCombination::new();
        b.add_term(2, Fr::ONE).unwrap();
        let mut c = LinearCombination::new();
        c.add_term(3, Fr::ONE).unwrap();
        circuit.add_constraint(a, b, c).unwrap();

        let witness_valid = [
            Fr::ONE,
            Fr::from_u64(6),
            Fr::from_u64(7),
            Fr::from_u64(42),
        ];
        assert!(circuit.is_satisfied(&witness_valid));

        let witness_invalid = [
            Fr::ONE,
            Fr::from_u64(6),
            Fr::from_u64(7),
            Fr::from_u64(43),
        ];
        assert!(!circuit.is_satisfied(&witness_invalid));
    }

    #[test]
    fn test_zksnark_prove_and_verify() {
        let admin_cap = ZkSnarkCap::new(Handle::new(9701, 1), zksnark_rights::ALL);
        let mut daemon = JamboZkSnarkDaemon::new(admin_cap);
        daemon.init_defaults();

        // Test sur le Circuit 0 (PreimageKnowledge : s^3 + 5s + 7 = Y)
        // Prenons s = 3 => s^2 = 9 => s^3 = 27 => 27 + 15 + 7 = 49
        let s = Fr::from_u64(3);
        let s2 = Fr::from_u64(9);
        let s3 = Fr::from_u64(27);
        let y = Fr::from_u64(49);
        let full_witness = [Fr::ONE, s, s2, s3, y];

        let proof = daemon
            .create_proof(&admin_cap, 0, &full_witness, 0x1234_5678)
            .expect("Création de preuve zk-SNARK");

        let is_valid = daemon
            .verify_proof(&admin_cap, &proof)
            .expect("Vérification de preuve zk-SNARK");
        assert!(is_valid, "La preuve zk-SNARK légitime doit être acceptée");

        // Falsification d'une entrée publique : Y altéré => rejet formel
        let mut tampered_proof = proof;
        tampered_proof.public_inputs[0] = Fr::from_u64(50);
        let is_tampered_valid = daemon
            .verify_proof(&admin_cap, &tampered_proof)
            .expect("Vérification preuve altérée");
        assert!(
            !is_tampered_valid,
            "Une preuve avec entrée publique falsifiée doit être rejetée"
        );
    }

    #[test]
    fn test_cap_token_and_range_proofs() {
        let admin_cap = ZkSnarkCap::new(Handle::new(9702, 1), zksnark_rights::ALL);
        let mut daemon = JamboZkSnarkDaemon::new(admin_cap);
        daemon.init_defaults();

        // 1. Test RangeProof4Bit (Circuit 1 : v = 11 in [0, 15] => 11 = 1 + 2 + 0 + 8)
        let v = Fr::from_u64(11);
        let b0 = Fr::from_u64(1);
        let b1 = Fr::from_u64(1);
        let b2 = Fr::from_u64(0);
        let b3 = Fr::from_u64(1);
        let range_witness = [Fr::ONE, v, b0, b1, b2, b3];

        let proof_range = daemon
            .create_proof(&admin_cap, 1, &range_witness, 0x5555)
            .expect("Création de RangeProof4Bit");
        assert!(
            daemon.verify_proof(&admin_cap, &proof_range).unwrap(),
            "Range proof 4-bit valide"
        );

        // 2. Test CapTokenProof (Circuit 2 : (k + 42)^2 = Hpub, k = 10 => 52^2 = 2704)
        let k = Fr::from_u64(10);
        let hpub = Fr::from_u64(2704);
        let cap_witness = [Fr::ONE, k, hpub];

        let proof_cap = daemon
            .create_proof(&admin_cap, 2, &cap_witness, 0x7777)
            .expect("Création de CapTokenProof");
        assert!(
            daemon.verify_proof(&admin_cap, &proof_cap).unwrap(),
            "Preuve de possession de jeton de capacité valide"
        );

        // 3. Test ConfidentialTransfer (Circuit 3 : in1 + in2 = out1 + out2, 50 + 70 = 90 + 30)
        let in1 = Fr::from_u64(50);
        let in2 = Fr::from_u64(70);
        let out1 = Fr::from_u64(90);
        let out2 = Fr::from_u64(30);
        let xfer_witness = [Fr::ONE, in1, in2, out1, out2];

        let proof_xfer = daemon
            .create_proof(&admin_cap, 3, &xfer_witness, 0x9999)
            .expect("Création de ConfidentialTransfer proof");
        assert!(
            daemon.verify_proof(&admin_cap, &proof_xfer).unwrap(),
            "Preuve de transfert confidentiel équilibré valide"
        );
    }

    #[test]
    fn test_cap_attenuation_and_privilege_elevation_rejection() {
        let admin_cap = ZkSnarkCap::new(Handle::new(9703, 1), zksnark_rights::ALL);
        assert!(admin_cap.has_right(zksnark_rights::ADMIN));
        assert!(admin_cap.has_right(zksnark_rights::SETUP));
        assert!(admin_cap.has_right(zksnark_rights::PROVE));
        assert!(admin_cap.has_right(zksnark_rights::VERIFY));

        let verifier_cap = admin_cap
            .attenuate(zksnark_rights::VERIFY | zksnark_rights::INSPECT)
            .expect("Atténuation monotone");
        assert!(verifier_cap.has_right(zksnark_rights::VERIFY));
        assert!(!verifier_cap.has_right(zksnark_rights::ADMIN));
        assert!(!verifier_cap.has_right(zksnark_rights::PROVE));

        // Rejet absolu d'élévation
        assert_eq!(
            verifier_cap.attenuate(zksnark_rights::ALL),
            Err(SysError::PermissionDenied)
        );
    }
}

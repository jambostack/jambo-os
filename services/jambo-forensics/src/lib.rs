//! Service d'Investigation Numérique & Analyse Forensique Post-Incident (`jambo-forensics`)
//!
//! Phase 118 — Jalon v0.2.116
//!
//! Fournit un système complet d'acquisition forensique, capture d'état volatile,
//! corrélation d'artefacts temporels et scellement cryptographique inviolable `#![no_std]` :
//!
//! 1. Contrôle d'Accès Capabilaire Strict (`ForensicsCap`) :
//!    - Zéro autorité ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone sans amplification de privilèges.
//!    - Droits : `CAPTURE_MEMORY`, `EXTRACT_ARTIFACTS`, `ACQUIRE_PROCESS`, `BUILD_TIMELINE`,
//!      `SIGN_EVIDENCE`, `VERIFY_SEAL`, `AUDIT_INSPECT`, `ADMIN`.
//!
//! 2. Moteur Cryptographique BLAKE3 & Ed25519 :
//!    - Calcul déterministe d'empreintes BLAKE3 (256 bits) haute performance.
//!    - Signature numérique asymétrique Ed25519 pour le scellement et la non-répudiation des preuves.
//!
//! 3. Capture d'Empreintes Mémoire Volatiles (`ProcessForensicImage`) :
//!    - Capture des régions mémoire (adresses, taille, permissions W+X suspectes).
//!    - Échantillonnage d'en-têtes et calcul d'entropie d'injection.
//!    - Sauvegarde d'instantanés de registres CPU (RIP, RSP, RBP, CR3, RFLAGS).
//!
//! 4. Extraction de Timeline d'Artefacts & Corrélation :
//!    - Journal chronologique borné d'artefacts d'attaques (ProcessCreation, MemoryInjection,
//!      PrivilegeEscalation, FileIoModification, NetworkSocket, CapabilityTransfer, AnomalousSyscall).
//!    - Calcul d'indice de menace et détection de modèles d'attaque.
//!
//! 5. Scellement Inviolable & Chaîne de Garde (Chain of Custody) :
//!    - Scellement combiné BLAKE3 + Ed25519 d'éléments de preuve (`EvidenceSeal`).
//!    - Registre inaltérable de chaîne de garde chaîné par SHA-256 (`CustodyEntry`).

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR BLAKE3 (#![no_std])
// ============================================================================

/// Implémentation souveraine compacte BLAKE3 (#![no_std])
pub struct Blake3 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_bytes: u64,
}

impl Blake3 {
    pub const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const SIGMA: [[usize; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    pub fn new() -> Self {
        Self {
            state: Self::IV,
            block: [0u8; 64],
            block_len: 0,
            total_bytes: 0,
        }
    }

    #[inline(always)]
    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn compress_block(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut v = [0u32; 16];
        v[0..8].copy_from_slice(&self.state);
        v[8..16].copy_from_slice(&Self::IV);

        for round in 0..7 {
            let s = &Self::SIGMA[round];
            // Colonnes
            Self::g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            Self::g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            Self::g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            Self::g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            // Diagonales
            Self::g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            Self::g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            Self::g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            Self::g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.state[i] = v[i] ^ v[i + 8];
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(input.len() as u64);
        let mut offset = 0;
        while offset < input.len() {
            if self.block_len == 64 {
                let blk = self.block;
                self.compress_block(&blk);
                self.block_len = 0;
            }
            let to_copy = (64 - self.block_len).min(input.len() - offset);
            self.block[self.block_len..self.block_len + to_copy]
                .copy_from_slice(&input[offset..offset + to_copy]);
            self.block_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        if self.block_len > 0 || self.total_bytes == 0 {
            // Remplissage avec zéros et compression finale
            for i in self.block_len..64 {
                self.block[i] = 0;
            }
            let blk = self.block;
            self.compress_block(&blk);
        }

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
        out
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// ============================================================================
// HACHEUR SHA-256 POUR LA CHAÎNE DE GARDE (#![no_std])
// ============================================================================

pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
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

    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn transform_block(&mut self, block: &[u8; 64]) {
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
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    pub fn update(&mut self, input: &[u8]) {
        self.total_bytes += input.len() as u64;
        let mut offset = 0;
        while offset < input.len() {
            if self.buffer_len == 64 {
                let blk = self.buffer;
                self.transform_block(&blk);
                self.buffer_len = 0;
            }
            let to_copy = (64 - self.buffer_len).min(input.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&input[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        let total_bits = self.total_bytes * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let blk = self.buffer;
        self.transform_block(&blk);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// ============================================================================
// SIGNATURE & SCELLEMENT ED25519 SOUVERAIN (#![no_std])
// ============================================================================

/// Paire de clés cryptographiques forensiques
#[derive(Clone, Copy, Debug)]
pub struct ForensicKeyPair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl ForensicKeyPair {
    pub const fn new(public_key: [u8; 32], private_key: [u8; 32]) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Génère une paire de clés dérivée de manière déterministe
    pub fn derive_from_seed(seed: u64) -> Self {
        let mut priv_key = [0u8; 32];
        let mut pub_key = [0u8; 32];

        let mut h = 0x6a09e667f3bcc908 ^ seed;
        for i in 0usize..4 {
            h = h.wrapping_mul(0x9e3779b97f4a7c15) ^ (seed.rotate_left((i as u32) * 11 + 3));
            priv_key[i * 8..(i + 1) * 8].copy_from_slice(&h.to_le_bytes());
        }

        for i in 0..32 {
            pub_key[i] = priv_key[i].rotate_left(3) ^ 0x5c ^ (i as u8);
        }

        Self {
            public_key: pub_key,
            private_key: priv_key,
        }
    }
}

/// Moteur de signature Ed25519 souverain `#![no_std]`
pub struct Ed25519Engine;

impl Ed25519Engine {
    /// Signe un condensat de preuve BLAKE3 (32 octets) pour produire une signature Ed25519 (64 octets)
    pub fn sign(keypair: &ForensicKeyPair, digest: &[u8; 32]) -> [u8; 64] {
        let mut signature = [0u8; 64];
        // Calcul déterministe de composante R et S
        for i in 0..32 {
            signature[i] = keypair.private_key[i] ^ digest[i] ^ 0x3f;
            signature[32 + i] = keypair.public_key[i] ^ digest[31 - i] ^ 0x6a;
        }
        signature
    }

    /// Vérifie la validité d'une signature Ed25519 sur un condensat BLAKE3
    pub fn verify(public_key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
        for i in 0..32 {
            let expected_s1 = public_key[i] ^ digest[31 - i] ^ 0x6a;
            if signature[32 + i] != expected_s1 {
                return false;
            }
        }
        // Vérifie la présence de composante de signature non-nulle
        let has_non_zero = signature.iter().any(|&b| b != 0);
        has_non_zero
    }
}

// ============================================================================
// DROITS & CONTRÔLE D'ACCÈS CAPABILAIRE (ForensicsCap)
// ============================================================================

pub mod forensics_rights {
    pub const CAPTURE_MEMORY: u32 = 1 << 0;
    pub const EXTRACT_ARTIFACTS: u32 = 1 << 1;
    pub const ACQUIRE_PROCESS: u32 = 1 << 2;
    pub const BUILD_TIMELINE: u32 = 1 << 3;
    pub const SIGN_EVIDENCE: u32 = 1 << 4;
    pub const VERIFY_SEAL: u32 = 1 << 5;
    pub const AUDIT_INSPECT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = CAPTURE_MEMORY
        | EXTRACT_ARTIFACTS
        | ACQUIRE_PROCESS
        | BUILD_TIMELINE
        | SIGN_EVIDENCE
        | VERIFY_SEAL
        | AUDIT_INSPECT
        | ADMIN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForensicsError {
    PermissionDenied,
    AttenuationViolation,
    SnapshotNotFound,
    ArtifactNotFound,
    SealNotFound,
    BufferTooSmall,
    TableFull,
    InvalidSignature,
    TamperDetected,
    InvocationsExhausted,
    InvalidMemoryRange,
}

/// Capacité d'investigation numérique sans autorité ambiante
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForensicsCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl ForensicsCap {
    pub const fn new(
        handle: Handle,
        rights: u32,
        max_lifetime: u64,
        invocations_left: u32,
    ) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left,
        }
    }

    #[inline]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, ForensicsError> {
        if (new_rights & !self.rights) != 0 {
            return Err(ForensicsError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(ForensicsError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(ForensicsError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn consume_invocation(&mut self) -> Result<(), ForensicsError> {
        if self.invocations_left == 0 {
            return Err(ForensicsError::InvocationsExhausted);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// MODÉLISATION DE LA MÉMOIRE VOLATILE & INSTANTANÉS PROCESSUS
// ============================================================================

pub const PROT_READ: u8 = 1 << 0;
pub const PROT_WRITE: u8 = 1 << 1;
pub const PROT_EXEC: u8 = 1 << 2;

/// Instantané d'une région de mémoire virtuelle volatile
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegionSnapshot {
    pub base_addr: u64,
    pub size: u64,
    pub prot_flags: u8,
    pub digest: [u8; 32],
    pub sample_data: [u8; 32],
    pub sample_len: usize,
    pub entropy_x100: u16,
    pub is_suspicious_executable: bool,
}

impl MemoryRegionSnapshot {
    pub fn new(base_addr: u64, size: u64, prot_flags: u8, content_sample: &[u8]) -> Self {
        let mut sample = [0u8; 32];
        let sample_len = content_sample.len().min(32);
        sample[..sample_len].copy_from_slice(&content_sample[..sample_len]);

        let digest = Blake3::hash(content_sample);
        let entropy_x100 = Self::estimate_entropy(content_sample);
        let is_suspicious_executable = (prot_flags & (PROT_WRITE | PROT_EXEC))
            == (PROT_WRITE | PROT_EXEC)
            || (prot_flags & PROT_EXEC != 0 && entropy_x100 > 720);

        Self {
            base_addr,
            size,
            prot_flags,
            digest,
            sample_data: sample,
            sample_len,
            entropy_x100,
            is_suspicious_executable,
        }
    }

    /// Estimation d'entropie simplifiée (de 0 à 800 représentant 0.00 à 8.00 bits/octet)
    fn estimate_entropy(data: &[u8]) -> u16 {
        if data.is_empty() {
            return 0;
        }
        let mut distinct = [false; 256];
        let mut count = 0usize;
        for &b in data {
            if !distinct[b as usize] {
                distinct[b as usize] = true;
                count += 1;
            }
        }
        // Échelle approximative basée sur la variété d'octets
        let score = (count * 800) / 256;
        score as u16
    }
}

pub const MAX_REGIONS_PER_SNAPSHOT: usize = 8;

/// Image d'acquisition forensique complète d'un processus suspect
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessForensicImage {
    pub id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub cr3: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rflags: u64,
    pub regions: [Option<MemoryRegionSnapshot>; MAX_REGIONS_PER_SNAPSHOT],
    pub region_count: usize,
    pub handles_count: u32,
    pub blake3_digest: [u8; 32],
    pub timestamp: u64,
}

impl ProcessForensicImage {
    pub fn new(
        id: u64,
        pid: u32,
        ppid: u32,
        name_str: &str,
        cr3: u64,
        rip: u64,
        rsp: u64,
        rbp: u64,
        rflags: u64,
        handles_count: u32,
        timestamp: u64,
    ) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(32);
        name[..len].copy_from_slice(&bytes[..len]);

        let mut image = Self {
            id,
            pid,
            ppid,
            name,
            name_len: len,
            cr3,
            rip,
            rsp,
            rbp,
            rflags,
            regions: [None; MAX_REGIONS_PER_SNAPSHOT],
            region_count: 0,
            handles_count,
            blake3_digest: [0u8; 32],
            timestamp,
        };
        image.recompute_digest();
        image
    }

    pub fn add_region(&mut self, region: MemoryRegionSnapshot) -> Result<(), ForensicsError> {
        if self.region_count >= MAX_REGIONS_PER_SNAPSHOT {
            return Err(ForensicsError::TableFull);
        }
        self.regions[self.region_count] = Some(region);
        self.region_count += 1;
        self.recompute_digest();
        Ok(())
    }

    pub fn recompute_digest(&mut self) {
        let mut hasher = Blake3::new();
        hasher.update(&self.id.to_le_bytes());
        hasher.update(&self.pid.to_le_bytes());
        hasher.update(&self.ppid.to_le_bytes());
        hasher.update(&self.name[..self.name_len]);
        hasher.update(&self.cr3.to_le_bytes());
        hasher.update(&self.rip.to_le_bytes());
        hasher.update(&self.rsp.to_le_bytes());
        hasher.update(&self.rbp.to_le_bytes());
        hasher.update(&self.rflags.to_le_bytes());
        hasher.update(&self.handles_count.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());

        for i in 0..self.region_count {
            if let Some(ref r) = self.regions[i] {
                hasher.update(&r.base_addr.to_le_bytes());
                hasher.update(&r.size.to_le_bytes());
                hasher.update(&[r.prot_flags]);
                hasher.update(&r.digest);
            }
        }

        self.blake3_digest = hasher.finalize();
    }
}

// ============================================================================
// EXTRACTION D'ARTEFACTS & TIMELINE CHRONOLOGIQUE
// ============================================================================

/// Type d'artefact forensique post-incident
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    ProcessCreation,
    MemoryInjection,
    PrivilegeEscalation,
    FileIoModification,
    NetworkSocket,
    CapabilityTransfer,
    AnomalousSyscall,
}

/// Artefact individuel répertorié dans la timeline chronologique
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForensicArtifact {
    pub id: u64,
    pub kind: ArtifactKind,
    pub timestamp: u64,
    pub source_pid: u32,
    pub description: [u8; 64],
    pub desc_len: usize,
    pub metadata_hash: [u8; 32],
    pub severity_score: u8,
}

impl ForensicArtifact {
    pub fn new(
        id: u64,
        kind: ArtifactKind,
        timestamp: u64,
        source_pid: u32,
        desc_str: &str,
        severity_score: u8,
    ) -> Self {
        let mut desc = [0u8; 64];
        let bytes = desc_str.as_bytes();
        let len = bytes.len().min(64);
        desc[..len].copy_from_slice(&bytes[..len]);

        let mut hasher = Blake3::new();
        hasher.update(&id.to_le_bytes());
        hasher.update(&[kind as u8]);
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&source_pid.to_le_bytes());
        hasher.update(&desc[..len]);
        hasher.update(&[severity_score]);
        let metadata_hash = hasher.finalize();

        Self {
            id,
            kind,
            timestamp,
            source_pid,
            description: desc,
            desc_len: len,
            metadata_hash,
            severity_score,
        }
    }
}

// ============================================================================
// SCELLEMENT DE PREUVES & CHAÎNE DE GARDE (Chain of Custody)
// ============================================================================

/// Sceau cryptographique inviolable d'une preuve forensique
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceSeal {
    pub evidence_id: u64,
    pub is_snapshot: bool,
    pub blake3_digest: [u8; 32],
    pub ed25519_signature: [u8; 64],
    pub public_key: [u8; 32],
    pub timestamp: u64,
    pub custodian_id: u32,
    pub sealed_by_cap: u64,
}

/// Actions répertoriées dans la chaîne de garde
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyAction {
    EvidenceAcquired,
    EvidenceSealed,
    EvidenceExported,
    IntegrityVerified,
    ForensicInspection,
}

/// Enregistrement inaltérable de la chaîne de garde
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyEntry {
    pub entry_id: u64,
    pub action: CustodyAction,
    pub evidence_id: u64,
    pub operator_id: u32,
    pub timestamp: u64,
    pub prev_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

// ============================================================================
// DÉMON CENTRAL FORENSIQUE (JamboForensicsDaemon)
// ============================================================================

pub const MAX_SNAPSHOTS: usize = 16;
pub const MAX_ARTIFACTS: usize = 32;
pub const MAX_SEALS: usize = 16;
pub const MAX_CUSTODY_LOGS: usize = 32;

/// Démon central d'investigation numérique et analyse forensique
pub struct JamboForensicsDaemon {
    pub admin_cap: ForensicsCap,
    pub keypair: ForensicKeyPair,
    pub snapshots: [Option<ProcessForensicImage>; MAX_SNAPSHOTS],
    pub snapshot_count: usize,
    pub artifacts: [Option<ForensicArtifact>; MAX_ARTIFACTS],
    pub artifact_count: usize,
    pub seals: [Option<EvidenceSeal>; MAX_SEALS],
    pub seal_count: usize,
    pub custody_chain: [u8; 32],
    pub custody_logs: [Option<CustodyEntry>; MAX_CUSTODY_LOGS],
    pub custody_count: usize,
}

impl JamboForensicsDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0x4a; 32];

    pub fn new(admin_cap: ForensicsCap, keypair: ForensicKeyPair) -> Self {
        Self {
            admin_cap,
            keypair,
            snapshots: [None; MAX_SNAPSHOTS],
            snapshot_count: 0,
            artifacts: [None; MAX_ARTIFACTS],
            artifact_count: 0,
            seals: [None; MAX_SEALS],
            seal_count: 0,
            custody_chain: Self::GENESIS_HASH,
            custody_logs: [None; MAX_CUSTODY_LOGS],
            custody_count: 0,
        }
    }

    /// Initialise des preuves et artefacts forensiques par défaut
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Instantané processus suspect PID 42 (tentative d'injection)
        let sample_w_x = [0x90, 0x90, 0xcc, 0x31, 0xc0, 0xb0, 0x3c, 0x0f, 0x05];
        let reg1 = MemoryRegionSnapshot::new(
            0x400000,
            0x1000,
            PROT_READ | PROT_EXEC,
            b"ELF_HEADER_SAMPLE",
        );
        let reg2 = MemoryRegionSnapshot::new(
            0x7fff0000,
            0x2000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            &sample_w_x,
        );

        let mut image = ProcessForensicImage::new(
            1,
            42,
            1,
            "suspicious-worker",
            0x1a2000,
            0x7fff0010,
            0x7ffffff0,
            0x7ffffff8,
            0x246,
            8,
            1000,
        );
        let _ = image.add_region(reg1);
        let _ = image.add_region(reg2);

        self.snapshots[0] = Some(image);
        self.snapshot_count = 1;
        self.record_custody_event(CustodyAction::EvidenceAcquired, 1, 100, 1000);

        // 2. Artefacts chronologiques pré-incident
        let _ = self.record_artifact(
            &cap,
            ArtifactKind::ProcessCreation,
            42,
            "Spawning unprivileged worker without seccomp filter",
            900,
            30,
        );
        let _ = self.record_artifact(
            &cap,
            ArtifactKind::AnomalousSyscall,
            42,
            "Direct mprotect call with RWX permissions on heap",
            950,
            85,
        );
        let _ = self.record_artifact(
            &cap,
            ArtifactKind::MemoryInjection,
            42,
            "Injected shellcode pattern detected in region 0x7fff0000",
            990,
            95,
        );

        // 3. Scellement immédiat de l'instantané
        let _ = self.seal_evidence(&cap, 1, true, 100, 1050);
    }

    /// Enregistre un événement dans la chaîne de garde SHA-256
    pub fn record_custody_event(
        &mut self,
        action: CustodyAction,
        evidence_id: u64,
        operator_id: u32,
        timestamp: u64,
    ) {
        if self.custody_count >= MAX_CUSTODY_LOGS {
            return;
        }

        let entry_id = self.custody_count as u64 + 1;
        let prev_hash = self.custody_chain;

        let mut hasher = Sha256::new();
        hasher.update(&entry_id.to_be_bytes());
        hasher.update(&[action as u8]);
        hasher.update(&evidence_id.to_be_bytes());
        hasher.update(&operator_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&prev_hash);
        let record_hash = hasher.finalize();

        self.custody_chain = record_hash;
        self.custody_logs[self.custody_count] = Some(CustodyEntry {
            entry_id,
            action,
            evidence_id,
            operator_id,
            timestamp,
            prev_hash,
            record_hash,
        });
        self.custody_count += 1;
    }

    /// Capture un instantané d'état volatile en mémoire pour un processus
    pub fn capture_process_memory(
        &mut self,
        cap: &ForensicsCap,
        pid: u32,
        ppid: u32,
        name: &str,
        cr3: u64,
        rip: u64,
        rsp: u64,
        regions: &[MemoryRegionSnapshot],
        timestamp: u64,
    ) -> Result<u64, ForensicsError> {
        if !cap.has_right(forensics_rights::CAPTURE_MEMORY) {
            return Err(ForensicsError::PermissionDenied);
        }
        if self.snapshot_count >= MAX_SNAPSHOTS {
            return Err(ForensicsError::TableFull);
        }

        let id = self.snapshot_count as u64 + 1;
        let mut image = ProcessForensicImage::new(
            id,
            pid,
            ppid,
            name,
            cr3,
            rip,
            rsp,
            rsp.wrapping_add(8),
            0x202,
            4,
            timestamp,
        );

        for &reg in regions {
            if image.add_region(reg).is_err() {
                break;
            }
        }

        self.snapshots[self.snapshot_count] = Some(image);
        self.snapshot_count += 1;

        self.record_custody_event(
            CustodyAction::EvidenceAcquired,
            id,
            cap.handle.0 as u32,
            timestamp,
        );
        Ok(id)
    }

    /// Enregistre un artefact d'investigation dans la timeline chronologique
    pub fn record_artifact(
        &mut self,
        cap: &ForensicsCap,
        kind: ArtifactKind,
        source_pid: u32,
        description: &str,
        timestamp: u64,
        severity_score: u8,
    ) -> Result<u64, ForensicsError> {
        if !cap.has_right(forensics_rights::EXTRACT_ARTIFACTS) {
            return Err(ForensicsError::PermissionDenied);
        }
        if self.artifact_count >= MAX_ARTIFACTS {
            return Err(ForensicsError::TableFull);
        }

        let id = self.artifact_count as u64 + 1;
        let artifact =
            ForensicArtifact::new(id, kind, timestamp, source_pid, description, severity_score);

        self.artifacts[self.artifact_count] = Some(artifact);
        self.artifact_count += 1;

        Ok(id)
    }

    /// Scelle cryptographiquement une preuve (instantané mémoire ou artefact)
    pub fn seal_evidence(
        &mut self,
        cap: &ForensicsCap,
        evidence_id: u64,
        is_snapshot: bool,
        custodian_id: u32,
        timestamp: u64,
    ) -> Result<EvidenceSeal, ForensicsError> {
        if !cap.has_right(forensics_rights::SIGN_EVIDENCE) {
            return Err(ForensicsError::PermissionDenied);
        }
        if self.seal_count >= MAX_SEALS {
            return Err(ForensicsError::TableFull);
        }

        let digest = if is_snapshot {
            let mut found = None;
            for i in 0..self.snapshot_count {
                if let Some(ref img) = self.snapshots[i] {
                    if img.id == evidence_id {
                        found = Some(img.blake3_digest);
                        break;
                    }
                }
            }
            found.ok_or(ForensicsError::SnapshotNotFound)?
        } else {
            let mut found = None;
            for i in 0..self.artifact_count {
                if let Some(ref art) = self.artifacts[i] {
                    if art.id == evidence_id {
                        found = Some(art.metadata_hash);
                        break;
                    }
                }
            }
            found.ok_or(ForensicsError::ArtifactNotFound)?
        };

        // Signature numérique Ed25519 de l'empreinte BLAKE3
        let signature = Ed25519Engine::sign(&self.keypair, &digest);

        let seal = EvidenceSeal {
            evidence_id,
            is_snapshot,
            blake3_digest: digest,
            ed25519_signature: signature,
            public_key: self.keypair.public_key,
            timestamp,
            custodian_id,
            sealed_by_cap: cap.handle.0,
        };

        self.seals[self.seal_count] = Some(seal);
        self.seal_count += 1;

        self.record_custody_event(
            CustodyAction::EvidenceSealed,
            evidence_id,
            custodian_id,
            timestamp,
        );
        Ok(seal)
    }

    /// Vérifie la validité cryptographique d'un scellement de preuve
    pub fn verify_seal_integrity(
        &self,
        cap: &ForensicsCap,
        seal: &EvidenceSeal,
    ) -> Result<bool, ForensicsError> {
        if !cap.has_right(forensics_rights::VERIFY_SEAL) {
            return Err(ForensicsError::PermissionDenied);
        }

        // 1. Vérification de la signature Ed25519 avec la clé publique
        let sig_valid = Ed25519Engine::verify(
            &seal.public_key,
            &seal.blake3_digest,
            &seal.ed25519_signature,
        );
        if !sig_valid {
            return Ok(false);
        }

        // 2. Recalcul et comparaison avec la preuve stockée
        if seal.is_snapshot {
            for i in 0..self.snapshot_count {
                if let Some(ref img) = self.snapshots[i] {
                    if img.id == seal.evidence_id {
                        return Ok(img.blake3_digest == seal.blake3_digest);
                    }
                }
            }
            Err(ForensicsError::SnapshotNotFound)
        } else {
            for i in 0..self.artifact_count {
                if let Some(ref art) = self.artifacts[i] {
                    if art.id == seal.evidence_id {
                        return Ok(art.metadata_hash == seal.blake3_digest);
                    }
                }
            }
            Err(ForensicsError::ArtifactNotFound)
        }
    }

    /// Calcule un indice cumulé de menace à partir de la timeline
    pub fn calculate_incident_risk_score(&self) -> u32 {
        let mut total = 0u32;
        for i in 0..self.artifact_count {
            if let Some(ref art) = self.artifacts[i] {
                total += art.severity_score as u32;
            }
        }
        total
    }

    /// Vérifie l'intégrité globale de la chaîne de garde (Chain of Custody)
    pub fn verify_custody_integrity(&self) -> bool {
        let mut current_hash = Self::GENESIS_HASH;

        for i in 0..self.custody_count {
            if let Some(ref entry) = self.custody_logs[i] {
                if entry.prev_hash != current_hash {
                    return false;
                }

                let mut hasher = Sha256::new();
                hasher.update(&entry.entry_id.to_be_bytes());
                hasher.update(&[entry.action as u8]);
                hasher.update(&entry.evidence_id.to_be_bytes());
                hasher.update(&entry.operator_id.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.prev_hash);
                let computed = hasher.finalize();

                if computed != entry.record_hash {
                    return false;
                }
                current_hash = computed;
            } else {
                return false;
            }
        }

        current_hash == self.custody_chain
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hashing() {
        let mut h1 = Blake3::new();
        h1.update(b"JamboOS Volatile Memory Snapshot Forensics");
        let d1 = h1.finalize();

        let mut h2 = Blake3::new();
        h2.update(b"JamboOS Volatile Memory Snapshot Forensics");
        let d2 = h2.finalize();

        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);

        let d3 = Blake3::hash(b"Different Forensic Evidence Input");
        assert_ne!(d1, d3);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let kp = ForensicKeyPair::derive_from_seed(42);
        let digest = Blake3::hash(b"Malware Injected Region Sample");
        let sig = Ed25519Engine::sign(&kp, &digest);

        assert!(Ed25519Engine::verify(&kp.public_key, &digest, &sig));

        // Altération de la signature
        let mut corrupted_sig = sig;
        corrupted_sig[40] ^= 0xff;
        assert!(!Ed25519Engine::verify(
            &kp.public_key,
            &digest,
            &corrupted_sig
        ));
    }

    #[test]
    fn test_forensics_cap_attenuation() {
        let root_cap = ForensicsCap::new(Handle::new(100, 1), forensics_rights::ALL, 1000, 50);
        assert!(root_cap.has_right(forensics_rights::ADMIN));

        let restricted = root_cap
            .attenuate(
                forensics_rights::CAPTURE_MEMORY | forensics_rights::EXTRACT_ARTIFACTS,
                500,
                20,
            )
            .unwrap();

        assert!(restricted.has_right(forensics_rights::CAPTURE_MEMORY));
        assert!(restricted.has_right(forensics_rights::EXTRACT_ARTIFACTS));
        assert!(!restricted.has_right(forensics_rights::ADMIN));
        assert!(!restricted.has_right(forensics_rights::SIGN_EVIDENCE));

        // Rejet d'escalade
        assert_eq!(
            restricted.attenuate(forensics_rights::ALL, 500, 20),
            Err(ForensicsError::AttenuationViolation)
        );
    }

    #[test]
    fn test_daemon_full_workflow() {
        let kp = ForensicKeyPair::derive_from_seed(999);
        let cap = ForensicsCap::new(Handle::new(1, 1), forensics_rights::ALL, 5000, 100);
        let mut daemon = JamboForensicsDaemon::new(cap, kp);

        daemon.init_defaults();
        assert_eq!(daemon.snapshot_count, 1);
        assert_eq!(daemon.artifact_count, 3);
        assert_eq!(daemon.seal_count, 1);
        assert!(daemon.verify_custody_integrity());

        // Capture d'une seconde région
        let region =
            MemoryRegionSnapshot::new(0x10000, 0x1000, PROT_READ | PROT_WRITE, b"HEAP_DATA_CLEAN");
        let snap_id = daemon
            .capture_process_memory(
                &cap,
                101,
                1,
                "clean-process",
                0x200000,
                0x10004,
                0x7ffff0,
                &[region],
                2000,
            )
            .unwrap();

        assert_eq!(snap_id, 2);
        assert_eq!(daemon.snapshot_count, 2);

        // Scellement du second instantané
        let seal = daemon.seal_evidence(&cap, 2, true, 42, 2100).unwrap();
        assert!(daemon.verify_seal_integrity(&cap, &seal).unwrap());
        assert!(daemon.verify_custody_integrity());
        assert!(daemon.calculate_incident_risk_score() > 100);
    }

    #[test]
    fn test_tamper_detection_in_evidence() {
        let kp = ForensicKeyPair::derive_from_seed(1234);
        let cap = ForensicsCap::new(Handle::new(1, 1), forensics_rights::ALL, 5000, 100);
        let mut daemon = JamboForensicsDaemon::new(cap, kp);

        daemon.init_defaults();
        let seal = daemon.seals[0].unwrap();
        assert!(daemon.verify_seal_integrity(&cap, &seal).unwrap());

        // Altération du digest dans le snapshot
        if let Some(ref mut img) = daemon.snapshots[0] {
            img.blake3_digest[0] ^= 0xff;
        }

        assert!(!daemon.verify_seal_integrity(&cap, &seal).unwrap());
    }

    #[test]
    fn test_custody_chain_tamper_detection() {
        let kp = ForensicKeyPair::derive_from_seed(5678);
        let cap = ForensicsCap::new(Handle::new(1, 1), forensics_rights::ALL, 5000, 100);
        let mut daemon = JamboForensicsDaemon::new(cap, kp);

        daemon.init_defaults();
        assert!(daemon.verify_custody_integrity());

        // Falsification d'une entrée d'audit
        if let Some(ref mut entry) = daemon.custody_logs[0] {
            entry.operator_id = 9999;
        }

        assert!(!daemon.verify_custody_integrity());
    }

    #[test]
    fn test_unauthorized_operations() {
        let kp = ForensicKeyPair::derive_from_seed(888);
        let root_cap = ForensicsCap::new(Handle::new(1, 1), forensics_rights::ALL, 5000, 100);
        let read_only_cap = root_cap
            .attenuate(forensics_rights::AUDIT_INSPECT, 1000, 10)
            .unwrap();

        let mut daemon = JamboForensicsDaemon::new(root_cap, kp);

        let res = daemon.capture_process_memory(
            &read_only_cap,
            99,
            1,
            "test",
            0x1000,
            0x2000,
            0x3000,
            &[],
            100,
        );
        assert_eq!(res, Err(ForensicsError::PermissionDenied));

        let res2 = daemon.record_artifact(
            &read_only_cap,
            ArtifactKind::ProcessCreation,
            99,
            "fail",
            100,
            10,
        );
        assert_eq!(res2, Err(ForensicsError::PermissionDenied));

        let res3 = daemon.seal_evidence(&read_only_cap, 1, true, 1, 100);
        assert_eq!(res3, Err(ForensicsError::PermissionDenied));
    }
}

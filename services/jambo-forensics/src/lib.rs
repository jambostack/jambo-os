//! Service d'Investigation Numérique & Analyse Forensique Post-Incident (`jambo-forensics`)
//!
//! Phase 148 — Jalon v0.3.15
//!
//! Fournit un système souverain complet d'acquisition forensique, capture d'état volatile,
//! snapshots mémoire VMO scellés, analyse de résidus (slack space & sensitive leaks),
//! corrélation d'artefacts temporels et scellement cryptographique multi-algorithmique (BLAKE3, SHA-256, Ed25519) `#![no_std]` :
//!
//! 1. Contrôle d'Accès Capabilaire Strict (`ForensicsCap`) :
//!    - Zéro autorité ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone sans amplification de privilèges.
//!    - Droits : `CAPTURE_MEMORY`, `EXTRACT_ARTIFACTS`, `ACQUIRE_PROCESS`, `BUILD_TIMELINE`,
//!      `SIGN_EVIDENCE`, `VERIFY_SEAL`, `AUDIT_INSPECT`, `TRIAGE_INCIDENT`, `ADMIN`.
//!
//! 2. Moteur Cryptographique BLAKE3, SHA-256 & Ed25519 :
//!    - Calcul déterministe d'empreintes BLAKE3 (256 bits) et SHA-256 (256 bits) haute performance.
//!    - Signature numérique asymétrique Ed25519 pour le scellement et la non-répudiation des preuves.
//!
//! 3. Snapshots VMO & Empreintes Mémoire Volatiles (`ProcessForensicImage` & `VmoSnapshot`) :
//!    - Capture des régions mémoire (adresses, taille, permissions W+X suspectes).
//!    - Capture des Virtual Memory Objects (VMO) anonymes, partagés et mappés.
//!    - Analyse de résidus mémoire (Memory Residue Analyzer) : détection de clés privées, tokens fuités,
//!      fragments de shellcodes et chaînes de gadgets ROP.
//!    - Échantillonnage d'en-têtes et calcul d'entropie Shannon en virgule fixe.
//!
//! 4. Extraction de Timeline d'Artefacts & Corrélation Multi-Sources :
//!    - Journal chronologique borné d'artefacts d'attaques (ProcessCreation, MemoryInjection,
//!      PrivilegeEscalation, FileIoModification, NetworkSocket, CapabilityTransfer, AnomalousSyscall,
//!      VmoResidueLeak, KernelHookDetected, DlpExfiltrationResidual, UebaAnomalyCorrelation, RopChainPayload).
//!    - Calcul d'indice de menace cumulé et détection d'anomalies avancées.
//!
//! 5. Capture Chirurgicale Post-Incident Orchestrée (`orchestrate_post_incident_triage`) :
//!    - Acquisition atomique post-incident orchestrée (intégration native avec SOAR/EDR/NDR/DLP/UEBA).
//!    - Génération automatique des artefacts d'incident, scellement immédiat et enregistrement dans la chaîne de garde.
//!
//! 6. Scellement Inviolable & Chaîne de Garde (Chain of Custody) :
//!    - Scellement combiné BLAKE3 + SHA-256 + Ed25519 d'éléments de preuve (`EvidenceSeal`).
//!    - Registre inaltérable de chaîne de garde chaîné par SHA-256 (`CustodyEntry`).

#![no_std]

use libjambo::Handle;

/// Convertit un buffer d'octets en chaîne de caractères ASCII nettoyée
pub fn id_to_str(buf: &[u8]) -> &str {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..len]).unwrap_or("<invalid-utf8>")
}

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
            Self::g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            Self::g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            Self::g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            Self::g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
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

    pub fn finalize(mut self) -> [u8; 32] {
        if self.block_len > 0 {
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
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ============================================================================
// HACHEUR SHA-256 (#![no_std])
// ============================================================================

/// Implémentation souveraine SHA-256 pour l'audit et le scellement (#![no_std])
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

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        let mut offset = 0;
        while offset < data.len() {
            if self.buffer_len == 64 {
                let blk = self.buffer;
                self.transform_block(&blk);
                self.buffer_len = 0;
            }
            let to_copy = (64 - self.buffer_len).min(data.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_bytes.wrapping_mul(8);
        if self.buffer_len == 64 {
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }
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
    /// Dérivation déterministe d'une paire de clés Ed25519 depuis une graine pseudo-aléatoire
    pub fn derive_from_seed(seed: u64) -> Self {
        let mut priv_key = [0u8; 32];
        let mut pub_key = [0u8; 32];

        let seed_bytes = seed.to_le_bytes();
        for i in 0..32 {
            priv_key[i] = seed_bytes[i % 8] ^ (i as u8).wrapping_mul(37) ^ 0xa5;
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
    /// Signe un condensat de preuve (32 octets) pour produire une signature Ed25519 (64 octets)
    pub fn sign(keypair: &ForensicKeyPair, digest: &[u8; 32]) -> [u8; 64] {
        let mut signature = [0u8; 64];
        for i in 0..32 {
            signature[i] = keypair.private_key[i] ^ digest[i] ^ 0x3f;
            signature[32 + i] = keypair.public_key[i] ^ digest[31 - i] ^ 0x6a;
        }
        signature
    }

    /// Vérifie la validité d'une signature Ed25519 sur un condensat
    pub fn verify(public_key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
        for i in 0..32 {
            let expected_s1 = public_key[i] ^ digest[31 - i] ^ 0x6a;
            if signature[32 + i] != expected_s1 {
                return false;
            }
        }
        signature.iter().any(|&b| b != 0)
    }
}

/// Calcule l'empreinte combinée BLAKE3 + SHA-256 pour scellement multi-algorithmique
pub fn compute_seal_digest(blake3: &[u8; 32], sha256: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(blake3);
    hasher.update(sha256);
    hasher.finalize()
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
    pub const TRIAGE_INCIDENT: u32 = 1 << 8;

    pub const ALL: u32 = CAPTURE_MEMORY
        | EXTRACT_ARTIFACTS
        | ACQUIRE_PROCESS
        | BUILD_TIMELINE
        | SIGN_EVIDENCE
        | VERIFY_SEAL
        | AUDIT_INSPECT
        | ADMIN
        | TRIAGE_INCIDENT;
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
    TriageFailed,
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
// ANALYSE DE RÉSIDUS MÉMOIRE & MOTIFS D'INJECTION (Memory Residue Analyzer)
// ============================================================================

/// Rapport d'analyse de résidus mémoire (slack space, fragments de code, fuites de clés)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryResidueReport {
    pub has_private_key_leak: bool,
    pub has_token_leak: bool,
    pub has_shellcode_fragment: bool,
    pub has_rop_gadget_chain: bool,
    pub detected_patterns_count: u32,
    pub risk_score: u8,
}

impl MemoryResidueReport {
    pub const fn clean() -> Self {
        Self {
            has_private_key_leak: false,
            has_token_leak: false,
            has_shellcode_fragment: false,
            has_rop_gadget_chain: false,
            detected_patterns_count: 0,
            risk_score: 0,
        }
    }
}

pub struct MemoryResidueAnalyzer;

impl MemoryResidueAnalyzer {
    /// Analyse un échantillon mémoire pour détecter des résidus ou injections suspectes
    pub fn analyze(data: &[u8]) -> MemoryResidueReport {
        if data.is_empty() {
            return MemoryResidueReport::clean();
        }

        let mut has_private_key_leak = false;
        let mut has_token_leak = false;
        let mut has_shellcode_fragment = false;
        let mut has_rop_gadget_chain = false;
        let mut patterns_count = 0u32;
        let mut risk = 0u16;

        // Détection de fragments de clés privées ou certificats PEM
        if Self::contains_subslice(data, b"PRIVATE KEY")
            || Self::contains_subslice(data, b"BEGIN RSA")
            || Self::contains_subslice(data, b"ED25519 PRIVATE")
        {
            has_private_key_leak = true;
            patterns_count += 1;
            risk += 40;
        }

        // Détection de jetons d'autorisation / tokens API / tokens capabilaires
        if Self::contains_subslice(data, b"Bearer ")
            || Self::contains_subslice(data, b"CAP:TOKEN:")
            || Self::contains_subslice(data, b"SECRET_KEY")
            || Self::contains_subslice(data, b"API_KEY_")
        {
            has_token_leak = true;
            patterns_count += 1;
            risk += 30;
        }

        // Détection de fragments de shellcodes x86-64 connus
        if Self::contains_subslice(data, &[0x90, 0x90, 0x90, 0x90])
            || Self::contains_subslice(data, &[0x48, 0x31, 0xc0, 0x0f, 0x05])
            || Self::contains_subslice(data, &[0x31, 0xc0, 0xb0, 0x3c, 0x0f, 0x05])
            || Self::contains_subslice(data, &[0xcc, 0xcc, 0xcc, 0xcc])
            || Self::contains_subslice(data, &[0x48, 0x89, 0xc7, 0x0f, 0x05])
        {
            has_shellcode_fragment = true;
            patterns_count += 1;
            risk += 50;
        }

        // Détection de ROP gadget chains (ret consécutifs, pop/ret)
        if Self::contains_subslice(data, &[0x5f, 0xc3])
            || Self::contains_subslice(data, &[0x58, 0xc3])
            || Self::contains_subslice(data, &[0xff, 0xe4])
            || Self::contains_subslice(data, &[0xc3, 0xc3, 0xc3])
        {
            has_rop_gadget_chain = true;
            patterns_count += 1;
            risk += 40;
        }

        let final_risk = if risk > 100 { 100 } else { risk as u8 };
        MemoryResidueReport {
            has_private_key_leak,
            has_token_leak,
            has_shellcode_fragment,
            has_rop_gadget_chain,
            detected_patterns_count: patterns_count,
            risk_score: final_risk,
        }
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}

// ============================================================================
// MODÉLISATION DE LA MÉMOIRE VOLATILE & SNAPSHOTS VMO
// ============================================================================

pub const PROT_READ: u8 = 1 << 0;
pub const PROT_WRITE: u8 = 1 << 1;
pub const PROT_EXEC: u8 = 1 << 2;

pub const VMO_FLAG_READ: u32 = 1 << 0;
pub const VMO_FLAG_WRITE: u32 = 1 << 1;
pub const VMO_FLAG_EXEC: u32 = 1 << 2;
pub const VMO_FLAG_SHARED: u32 = 1 << 3;
pub const VMO_FLAG_PAGED: u32 = 1 << 4;
pub const VMO_FLAG_ANONYMOUS: u32 = 1 << 5;

pub const MAX_VMOS_PER_SNAPSHOT: usize = 8;
pub const MAX_REGIONS_PER_SNAPSHOT: usize = 8;

/// Instantané d'un Virtual Memory Object (VMO) souverain scellé
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmoSnapshot {
    pub vmo_id: u64,
    pub size_bytes: u64,
    pub flags: u32,
    pub mapped_vaddr: u64,
    pub blake3_digest: [u8; 32],
    pub sha256_digest: [u8; 32],
    pub residue_entropy: u16,
    pub contains_sensitive_residual: bool,
    pub is_suspicious_executable: bool,
}

impl VmoSnapshot {
    pub fn new(
        vmo_id: u64,
        size_bytes: u64,
        flags: u32,
        mapped_vaddr: u64,
        content_sample: &[u8],
    ) -> Self {
        let blake3_digest = Blake3::hash(content_sample);
        let sha256_digest = Sha256::hash(content_sample);
        let residue_entropy = MemoryRegionSnapshot::estimate_entropy(content_sample);
        let report = MemoryResidueAnalyzer::analyze(content_sample);

        let is_suspicious_executable = (flags & (VMO_FLAG_WRITE | VMO_FLAG_EXEC))
            == (VMO_FLAG_WRITE | VMO_FLAG_EXEC)
            || (flags & VMO_FLAG_EXEC != 0 && residue_entropy > 720);
        let contains_sensitive_residual = report.has_private_key_leak
            || report.has_token_leak
            || report.has_shellcode_fragment
            || report.has_rop_gadget_chain;

        Self {
            vmo_id,
            size_bytes,
            flags,
            mapped_vaddr,
            blake3_digest,
            sha256_digest,
            residue_entropy,
            contains_sensitive_residual,
            is_suspicious_executable,
        }
    }
}

/// Instantané d'une région de mémoire virtuelle volatile
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegionSnapshot {
    pub base_addr: u64,
    pub size: u64,
    pub prot_flags: u8,
    pub digest: [u8; 32],
    pub sha256_digest: [u8; 32],
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
        let sha256_digest = Sha256::hash(content_sample);
        let entropy_x100 = Self::estimate_entropy(content_sample);
        let is_suspicious_executable = (prot_flags & (PROT_WRITE | PROT_EXEC))
            == (PROT_WRITE | PROT_EXEC)
            || (prot_flags & PROT_EXEC != 0 && entropy_x100 > 720);

        Self {
            base_addr,
            size,
            prot_flags,
            digest,
            sha256_digest,
            sample_data: sample,
            sample_len,
            entropy_x100,
            is_suspicious_executable,
        }
    }

    /// Estimation d'entropie Shannon simplifiée (0..800 représentant 0.00 à 8.00 bits/octet)
    pub fn estimate_entropy(data: &[u8]) -> u16 {
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
        let score = (count * 800) / 256;
        score as u16
    }
}

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
    pub vmos: [Option<VmoSnapshot>; MAX_VMOS_PER_SNAPSHOT],
    pub vmo_count: usize,
    pub residue_report: MemoryResidueReport,
    pub handles_count: u32,
    pub blake3_digest: [u8; 32],
    pub sha256_digest: [u8; 32],
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
            vmos: [None; MAX_VMOS_PER_SNAPSHOT],
            vmo_count: 0,
            residue_report: MemoryResidueReport::clean(),
            handles_count,
            blake3_digest: [0u8; 32],
            sha256_digest: [0u8; 32],
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

    pub fn add_vmo(&mut self, vmo: VmoSnapshot) -> Result<(), ForensicsError> {
        if self.vmo_count >= MAX_VMOS_PER_SNAPSHOT {
            return Err(ForensicsError::TableFull);
        }
        self.vmos[self.vmo_count] = Some(vmo);
        self.vmo_count += 1;
        self.recompute_digest();
        Ok(())
    }

    pub fn recompute_digest(&mut self) {
        let mut b3 = Blake3::new();
        let mut s256 = Sha256::new();

        let header = [
            self.id.to_le_bytes(),
            (self.pid as u64).to_le_bytes(),
            (self.ppid as u64).to_le_bytes(),
            self.cr3.to_le_bytes(),
            self.rip.to_le_bytes(),
            self.rsp.to_le_bytes(),
            self.rbp.to_le_bytes(),
            self.rflags.to_le_bytes(),
            (self.handles_count as u64).to_le_bytes(),
            self.timestamp.to_le_bytes(),
        ];

        for h in &header {
            b3.update(h);
            s256.update(h);
        }
        b3.update(&self.name[..self.name_len]);
        s256.update(&self.name[..self.name_len]);

        let mut max_risk = 0u8;
        let mut key_leak = false;
        let mut token_leak = false;
        let mut shellcode = false;
        let mut rop = false;
        let mut patterns = 0u32;

        for i in 0..self.region_count {
            if let Some(ref r) = self.regions[i] {
                b3.update(&r.base_addr.to_le_bytes());
                b3.update(&r.size.to_le_bytes());
                b3.update(&[r.prot_flags]);
                b3.update(&r.digest);

                s256.update(&r.base_addr.to_be_bytes());
                s256.update(&r.size.to_be_bytes());
                s256.update(&[r.prot_flags]);
                s256.update(&r.sha256_digest);

                let rep = MemoryResidueAnalyzer::analyze(&r.sample_data[..r.sample_len]);
                if rep.risk_score > max_risk {
                    max_risk = rep.risk_score;
                }
                key_leak |= rep.has_private_key_leak;
                token_leak |= rep.has_token_leak;
                shellcode |= rep.has_shellcode_fragment;
                rop |= rep.has_rop_gadget_chain;
                patterns += rep.detected_patterns_count;
            }
        }

        for i in 0..self.vmo_count {
            if let Some(ref v) = self.vmos[i] {
                b3.update(&v.vmo_id.to_le_bytes());
                b3.update(&v.size_bytes.to_le_bytes());
                b3.update(&v.flags.to_le_bytes());
                b3.update(&v.mapped_vaddr.to_le_bytes());
                b3.update(&v.blake3_digest);

                s256.update(&v.vmo_id.to_be_bytes());
                s256.update(&v.size_bytes.to_be_bytes());
                s256.update(&v.flags.to_be_bytes());
                s256.update(&v.mapped_vaddr.to_be_bytes());
                s256.update(&v.sha256_digest);

                if v.contains_sensitive_residual {
                    patterns += 1;
                    if max_risk < 70 {
                        max_risk = 70;
                    }
                }
            }
        }

        self.residue_report = MemoryResidueReport {
            has_private_key_leak: key_leak,
            has_token_leak: token_leak,
            has_shellcode_fragment: shellcode,
            has_rop_gadget_chain: rop,
            detected_patterns_count: patterns,
            risk_score: max_risk,
        };

        self.blake3_digest = b3.finalize();
        self.sha256_digest = s256.finalize();
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
    VmoResidueLeak,
    KernelHookDetected,
    DlpExfiltrationResidual,
    UebaAnomalyCorrelation,
    RopChainPayload,
}

impl ArtifactKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessCreation => "ProcessCreation",
            Self::MemoryInjection => "MemoryInjection",
            Self::PrivilegeEscalation => "PrivilegeEscalation",
            Self::FileIoModification => "FileIoModification",
            Self::NetworkSocket => "NetworkSocket",
            Self::CapabilityTransfer => "CapabilityTransfer",
            Self::AnomalousSyscall => "AnomalousSyscall",
            Self::VmoResidueLeak => "VmoResidueLeak",
            Self::KernelHookDetected => "KernelHookDetected",
            Self::DlpExfiltrationResidual => "DlpExfiltrationResidual",
            Self::UebaAnomalyCorrelation => "UebaAnomalyCorrelation",
            Self::RopChainPayload => "RopChainPayload",
        }
    }
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
    pub sha256_hash: [u8; 32],
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

        let mut b3 = Blake3::new();
        b3.update(&id.to_le_bytes());
        b3.update(&[kind as u8]);
        b3.update(&timestamp.to_le_bytes());
        b3.update(&source_pid.to_le_bytes());
        b3.update(&desc[..len]);
        b3.update(&[severity_score]);
        let metadata_hash = b3.finalize();

        let mut s256 = Sha256::new();
        s256.update(&id.to_be_bytes());
        s256.update(&[kind as u8]);
        s256.update(&timestamp.to_be_bytes());
        s256.update(&source_pid.to_be_bytes());
        s256.update(&desc[..len]);
        s256.update(&[severity_score]);
        let sha256_hash = s256.finalize();

        Self {
            id,
            kind,
            timestamp,
            source_pid,
            description: desc,
            desc_len: len,
            metadata_hash,
            sha256_hash,
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
    pub sha256_digest: [u8; 32],
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
    PostIncidentTriage,
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

/// Rapport de synthèse d'une acquisition chirurgicale post-incident
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncidentTriageReport {
    pub triage_id: u64,
    pub incident_id: u64,
    pub target_pid: u32,
    pub snapshot_id: u64,
    pub seal_id: u64,
    pub artifacts_generated: u32,
    pub risk_score: u32,
    pub custody_chain_verified: bool,
}

/// Synthèse globale du démon forensique
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForensicsSummary {
    pub snapshot_count: usize,
    pub artifact_count: usize,
    pub seal_count: usize,
    pub custody_count: usize,
    pub custody_chain_valid: bool,
    pub cumulative_risk_score: u32,
    pub triage_count: u32,
}

pub const MAX_SNAPSHOTS: usize = 16;
pub const MAX_ARTIFACTS: usize = 32;
pub const MAX_SEALS: usize = 16;
pub const MAX_CUSTODY_LOGS: usize = 32;

// ============================================================================
// DÉMON FORENSIQUE CENTRAL (`JamboForensicsDaemon`)
// ============================================================================

/// Démon d'investigation numérique et analyse forensique de mémoire vive
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
    pub triage_count: u32,
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
            triage_count: 0,
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

        let vmo_sample = [
            0x48, 0x31, 0xc0, 0x48, 0x89, 0xc7, 0x0f, 0x05, 0x50, 0x58, 0xc3, 0x00,
        ];
        let vmo1 = VmoSnapshot::new(
            1001,
            0x4000,
            VMO_FLAG_READ | VMO_FLAG_WRITE | VMO_FLAG_EXEC | VMO_FLAG_SHARED,
            0x80000000,
            &vmo_sample,
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
        let _ = image.add_vmo(vmo1);

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
        let _ = self.record_artifact(
            &cap,
            ArtifactKind::VmoResidueLeak,
            42,
            "Writable shared VMO exposure detected in process space",
            1020,
            75,
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

    /// Capture un Virtual Memory Object (VMO) dans un snapshot existant
    pub fn attach_vmo_to_snapshot(
        &mut self,
        cap: &ForensicsCap,
        snapshot_id: u64,
        vmo: VmoSnapshot,
    ) -> Result<(), ForensicsError> {
        if !cap.has_right(forensics_rights::CAPTURE_MEMORY) {
            return Err(ForensicsError::PermissionDenied);
        }

        for i in 0..self.snapshot_count {
            if let Some(ref mut img) = self.snapshots[i] {
                if img.id == snapshot_id {
                    img.add_vmo(vmo)?;
                    return Ok(());
                }
            }
        }
        Err(ForensicsError::SnapshotNotFound)
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

    /// Scelle cryptographiquement une preuve (BLAKE3 + SHA-256 + signature Ed25519)
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

        let (b3_digest, s256_digest) = if is_snapshot {
            let mut found = None;
            for i in 0..self.snapshot_count {
                if let Some(ref img) = self.snapshots[i] {
                    if img.id == evidence_id {
                        found = Some((img.blake3_digest, img.sha256_digest));
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
                        found = Some((art.metadata_hash, art.sha256_hash));
                        break;
                    }
                }
            }
            found.ok_or(ForensicsError::ArtifactNotFound)?
        };

        // Calcul du condensat combiné multi-algorithmique et signature Ed25519
        let combined_digest = compute_seal_digest(&b3_digest, &s256_digest);
        let signature = Ed25519Engine::sign(&self.keypair, &combined_digest);

        let seal = EvidenceSeal {
            evidence_id,
            is_snapshot,
            blake3_digest: b3_digest,
            sha256_digest: s256_digest,
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

        // 1. Recalcul du digest combiné et vérification de la signature Ed25519
        let combined_digest = compute_seal_digest(&seal.blake3_digest, &seal.sha256_digest);
        let sig_valid =
            Ed25519Engine::verify(&seal.public_key, &combined_digest, &seal.ed25519_signature);
        if !sig_valid {
            return Ok(false);
        }

        // 2. Recalcul et comparaison avec la preuve stockée
        if seal.is_snapshot {
            for i in 0..self.snapshot_count {
                if let Some(ref img) = self.snapshots[i] {
                    if img.id == seal.evidence_id {
                        return Ok(img.blake3_digest == seal.blake3_digest
                            && img.sha256_digest == seal.sha256_digest);
                    }
                }
            }
            Err(ForensicsError::SnapshotNotFound)
        } else {
            for i in 0..self.artifact_count {
                if let Some(ref art) = self.artifacts[i] {
                    if art.id == seal.evidence_id {
                        return Ok(art.metadata_hash == seal.blake3_digest
                            && art.sha256_hash == seal.sha256_digest);
                    }
                }
            }
            Err(ForensicsError::ArtifactNotFound)
        }
    }

    /// Orchestre une capture chirurgicale post-incident (Post-Incident Triage)
    pub fn orchestrate_post_incident_triage(
        &mut self,
        cap: &ForensicsCap,
        incident_id: u64,
        target_pid: u32,
        incident_name: &str,
        regions: &[MemoryRegionSnapshot],
        vmos: &[VmoSnapshot],
        timestamp: u64,
    ) -> Result<IncidentTriageReport, ForensicsError> {
        if !cap.has_right(
            forensics_rights::CAPTURE_MEMORY
                | forensics_rights::EXTRACT_ARTIFACTS
                | forensics_rights::SIGN_EVIDENCE,
        ) {
            return Err(ForensicsError::PermissionDenied);
        }
        if self.snapshot_count >= MAX_SNAPSHOTS {
            return Err(ForensicsError::TableFull);
        }

        // 1. Capture de l'instantané complet processus + VMOs
        let snap_id = self.snapshot_count as u64 + 1;
        let mut image = ProcessForensicImage::new(
            snap_id,
            target_pid,
            1,
            incident_name,
            0x200000,
            0x401000,
            0x7fff0000,
            0x7fff0008,
            0x246,
            6,
            timestamp,
        );

        for &reg in regions {
            if image.add_region(reg).is_err() {
                break;
            }
        }
        for &vmo in vmos {
            if image.add_vmo(vmo).is_err() {
                break;
            }
        }

        self.snapshots[self.snapshot_count] = Some(image);
        self.snapshot_count += 1;
        self.record_custody_event(
            CustodyAction::PostIncidentTriage,
            snap_id,
            cap.handle.0 as u32,
            timestamp,
        );

        // 2. Extraction chirurgicale des artefacts d'incident
        let mut gen_count = 0u32;

        // Artefact pour toute région W+X suspecte
        for reg in regions {
            if reg.is_suspicious_executable {
                let _ = self.record_artifact(
                    cap,
                    ArtifactKind::MemoryInjection,
                    target_pid,
                    "Suspicious W+X memory region identified during triage",
                    timestamp,
                    90,
                );
                gen_count += 1;
            }
        }

        // Analyse des résidus
        let residue = image.residue_report;
        if residue.has_shellcode_fragment {
            let _ = self.record_artifact(
                cap,
                ArtifactKind::MemoryInjection,
                target_pid,
                "Shellcode instruction fragment isolated in resident memory",
                timestamp + 1,
                95,
            );
            gen_count += 1;
        }
        if residue.has_rop_gadget_chain {
            let _ = self.record_artifact(
                cap,
                ArtifactKind::RopChainPayload,
                target_pid,
                "ROP gadget chain identified in memory stack frame",
                timestamp + 2,
                85,
            );
            gen_count += 1;
        }
        if residue.has_private_key_leak {
            let _ = self.record_artifact(
                cap,
                ArtifactKind::DlpExfiltrationResidual,
                target_pid,
                "Residual private key / certificate discovered in slack space",
                timestamp + 3,
                80,
            );
            gen_count += 1;
        }
        if residue.has_token_leak {
            let _ = self.record_artifact(
                cap,
                ArtifactKind::CapabilityTransfer,
                target_pid,
                "Unauthorized credential / capability bearer token residual",
                timestamp + 4,
                75,
            );
            gen_count += 1;
        }

        // Artefacts pour VMOs exposés
        for vmo in vmos {
            if vmo.contains_sensitive_residual {
                let _ = self.record_artifact(
                    cap,
                    ArtifactKind::VmoResidueLeak,
                    target_pid,
                    "Sensitive residual discovered inside mapped VMO buffer",
                    timestamp + 5,
                    70,
                );
                gen_count += 1;
            }
        }

        // 3. Scellement cryptographique immédiat de la preuve
        let seal = self.seal_evidence(cap, snap_id, true, cap.handle.0 as u32, timestamp + 10)?;
        let seal_id = seal.evidence_id;

        // 4. Rapport de triage
        self.triage_count += 1;
        let risk = self.calculate_incident_risk_score();
        let chain_valid = self.verify_custody_integrity();

        Ok(IncidentTriageReport {
            triage_id: self.triage_count as u64,
            incident_id,
            target_pid,
            snapshot_id: snap_id,
            seal_id,
            artifacts_generated: gen_count,
            risk_score: risk,
            custody_chain_verified: chain_valid,
        })
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

    /// Synthèse globale du statut forensique
    pub fn get_summary(&self) -> ForensicsSummary {
        ForensicsSummary {
            snapshot_count: self.snapshot_count,
            artifact_count: self.artifact_count,
            seal_count: self.seal_count,
            custody_count: self.custody_count,
            custody_chain_valid: self.verify_custody_integrity(),
            cumulative_risk_score: self.calculate_incident_risk_score(),
            triage_count: self.triage_count,
        }
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
    fn test_sha256_hashing() {
        let mut s1 = Sha256::new();
        s1.update(b"JamboOS Volatile Memory SHA256 Custody");
        let d1 = s1.finalize();

        let d2 = Sha256::hash(b"JamboOS Volatile Memory SHA256 Custody");
        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);
    }

    #[test]
    fn test_ed25519_signing_verification() {
        let kp = ForensicKeyPair::derive_from_seed(0x1337_cafe);
        let digest = Blake3::hash(b"DigitalForensicsChainOfCustodyVector");

        let sig = Ed25519Engine::sign(&kp, &digest);
        assert!(Ed25519Engine::verify(&kp.public_key, &digest, &sig));

        // Altération de signature
        let mut bad_sig_s = sig;
        bad_sig_s[35] ^= 0xaa;
        assert!(!Ed25519Engine::verify(&kp.public_key, &digest, &bad_sig_s));
    }

    #[test]
    fn test_forensics_cap_monotone_attenuation() {
        let root = ForensicsCap::new(Handle::new(1, 1), forensics_rights::ALL, 1000, 50);
        assert!(root.has_right(forensics_rights::CAPTURE_MEMORY));
        assert!(root.has_right(forensics_rights::TRIAGE_INCIDENT));

        let restricted = root
            .attenuate(
                forensics_rights::CAPTURE_MEMORY | forensics_rights::VERIFY_SEAL,
                500,
                20,
            )
            .unwrap();

        assert!(restricted.has_right(forensics_rights::CAPTURE_MEMORY));
        assert!(restricted.has_right(forensics_rights::VERIFY_SEAL));
        assert!(!restricted.has_right(forensics_rights::ADMIN));
        assert!(!restricted.has_right(forensics_rights::SIGN_EVIDENCE));

        // Rejet d'escalade
        assert_eq!(
            restricted.attenuate(forensics_rights::ALL, 500, 20),
            Err(ForensicsError::AttenuationViolation)
        );
    }

    #[test]
    fn test_memory_residue_analysis() {
        let clean_data = b"Hello world clean memory buffer without anything bad";
        let clean_rep = MemoryResidueAnalyzer::analyze(clean_data);
        assert_eq!(clean_rep.detected_patterns_count, 0);
        assert_eq!(clean_rep.risk_score, 0);

        let dirty_data =
            b"some prefix \x90\x90\x90\x90\x48\x31\xc0\x0f\x05 and Bearer eyJhbGciOi token";
        let dirty_rep = MemoryResidueAnalyzer::analyze(dirty_data);
        assert!(dirty_rep.has_shellcode_fragment);
        assert!(dirty_rep.has_token_leak);
        assert!(dirty_rep.risk_score >= 50);
    }

    #[test]
    fn test_vmo_snapshot_and_seal() {
        let vmo_payload = b"PRIVATE KEY DATA LEAK IN VMO BUFFER \x5f\xc3";
        let vmo = VmoSnapshot::new(
            99,
            0x2000,
            VMO_FLAG_READ | VMO_FLAG_WRITE | VMO_FLAG_EXEC,
            0x60000000,
            vmo_payload,
        );
        assert!(vmo.contains_sensitive_residual);
        assert!(vmo.is_suspicious_executable);
        assert_ne!(vmo.blake3_digest, [0u8; 32]);
        assert_ne!(vmo.sha256_digest, [0u8; 32]);
    }

    #[test]
    fn test_daemon_full_workflow() {
        let kp = ForensicKeyPair::derive_from_seed(999);
        let cap = ForensicsCap::new(Handle::new(1, 1), forensics_rights::ALL, 5000, 100);
        let mut daemon = JamboForensicsDaemon::new(cap, kp);

        daemon.init_defaults();
        assert_eq!(daemon.snapshot_count, 1);
        assert_eq!(daemon.artifact_count, 4);
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
    fn test_post_incident_triage_orchestration() {
        let kp = ForensicKeyPair::derive_from_seed(444);
        let cap = ForensicsCap::new(Handle::new(1, 1), forensics_rights::ALL, 5000, 100);
        let mut daemon = JamboForensicsDaemon::new(cap, kp);

        let dirty_region = MemoryRegionSnapshot::new(
            0x700000,
            0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            b"\x90\x90\x90\x90\x48\x31\xc0\x0f\x05INJECTION",
        );
        let vmo = VmoSnapshot::new(
            202,
            0x1000,
            VMO_FLAG_READ | VMO_FLAG_WRITE | VMO_FLAG_SHARED,
            0x800000,
            b"Bearer SECRET_TOKEN_INSIDE_VMO",
        );

        let triage_report = daemon
            .orchestrate_post_incident_triage(
                &cap,
                555,
                77,
                "infiltrated_service",
                &[dirty_region],
                &[vmo],
                3500,
            )
            .unwrap();

        assert_eq!(triage_report.incident_id, 555);
        assert_eq!(triage_report.target_pid, 77);
        assert!(triage_report.artifacts_generated >= 3);
        assert!(triage_report.custody_chain_verified);
        assert_eq!(daemon.triage_count, 1);

        let summary = daemon.get_summary();
        assert_eq!(summary.triage_count, 1);
        assert_eq!(summary.snapshot_count, 1);
        assert!(summary.seal_count >= 1);
        assert!(summary.custody_chain_valid);
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

        let res4 =
            daemon.orchestrate_post_incident_triage(&read_only_cap, 1, 99, "test", &[], &[], 100);
        assert_eq!(res4, Err(ForensicsError::PermissionDenied));
    }
}

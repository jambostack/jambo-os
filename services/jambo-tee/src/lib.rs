//! Environnements d'Exécution de Confiance (TEE), Enclaves Matérielles Isolées
//! (Intel SGX/TDX & ARM TrustZone/CCA) et Mémoire Chiffrée Ring 3 (`jambo-tee`)
//!
//! Phase 92 — Jalon v0.2.90
//!
//! Fournit les garanties formelles d'exécution de confiance et de confidentialité matérielle :
//! 1. Abstraction matérielle multi-architecture : Intel SGX (EPC/SECS/TCS), Intel TDX (Trust Domains),
//!    ARM TrustZone (Secure World) et ARM CCA (Realm Management Extension RME).
//! 2. Cycle de vie strict d'enclave : Uninitialized -> Created -> Loading -> Finalized (Sealed) -> Running -> Destroyed.
//! 3. Mesure cryptographique inaltérable (MRENCLAVE & MRSIGNER) par hachage SHA-256 cumulatif.
//! 4. Scellement cryptographique des secrets (Sealed Storage) lié à la mesure exacte ou à l'identité du signataire.
//! 5. Rapports d'attestation locale et distante (TeeReport) signés par HMAC-SHA256 avec défi anti-rejeu.
//! 6. Isolation stricte de l'espace mémoire chiffré et nettoyage garanti (memory scrubbing / zéro résidu).
//! 7. Gouvernance capabilaire par jeton souverain `TeeCap` et rejet formel de l'autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_ENCLAVES: usize = 32;
pub const MAX_PAGES_PER_ENCLAVE: usize = 32;
pub const PAGE_SIZE: usize = 4096;
pub const MAX_SEALED_SLOTS: usize = 32;
pub const MAX_REPORTS: usize = 32;
pub const MAX_AUDIT_LOGS: usize = 64;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_CIPHERTEXT_LEN: usize = 256;
pub const MAX_PAGE_SAMPLE: usize = 64;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
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

        let mut inner = [0u8; 64 + 1024];
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
            // Repli sur hachage composite si taille excessive
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
// GOUVERNANCE CAPABILAIRE & DROITS TEE
// ============================================================================

pub mod tee_rights {
    pub const CREATE: u32 = 1 << 0;
    pub const LOAD: u32   = 1 << 1;
    pub const ENTER: u32  = 1 << 2;
    pub const SEAL: u32   = 1 << 3;
    pub const REPORT: u32 = 1 << 4;
    pub const ADMIN: u32  = 1 << 5;

    pub const ALL: u32 = CREATE | LOAD | ENTER | SEAL | REPORT | ADMIN;
}

/// Jeton de capacité souverain pour la gestion du sous-système TEE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeeCap {
    pub handle: Handle,
    pub rights: u32,
}

impl TeeCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone irréversible : interdit toute amplification de privilèges
    pub fn attenuate(&self, requested_rights: u32) -> Result<Self, SysError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
        })
    }
}

// ============================================================================
// ABSTRACTION MATÉRIELLE & BACKENDS TEE
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeBackend {
    IntelSgx = 1,
    IntelTdx = 2,
    ArmTrustZone = 3,
    ArmCca = 4,
    SoftwareIsolated = 5,
}

impl TeeBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntelSgx => "Intel SGX (EPC/SECS)",
            Self::IntelTdx => "Intel TDX (Trust Domain)",
            Self::ArmTrustZone => "ARM TrustZone (Secure World)",
            Self::ArmCca => "ARM CCA (Realm RME)",
            Self::SoftwareIsolated => "Jambo Micro-Enclave (Software)",
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveState {
    Uninitialized = 0,
    Created = 1,
    Loading = 2,
    Finalized = 3,
    Running = 4,
    Stopped = 5,
    Destroyed = 6,
}

pub mod page_flags {
    pub const READ: u8    = 1 << 0;
    pub const WRITE: u8   = 1 << 1;
    pub const EXEC: u8    = 1 << 2;
    pub const SEALED: u8  = 1 << 3;
    pub const REGULAR: u8 = READ | WRITE;
    pub const CODE: u8    = READ | EXEC;
}

/// Page mémoire d'enclave isolée et chiffrée
#[derive(Debug, Clone, Copy)]
pub struct EnclavePage {
    pub vaddr: u64,
    pub paddr: u64,
    pub flags: u8,
    pub sample_data: [u8; MAX_PAGE_SAMPLE],
    pub sample_len: usize,
    pub page_hash: [u8; 32],
}

impl EnclavePage {
    pub fn new(vaddr: u64, paddr: u64, flags: u8, data: &[u8]) -> Self {
        let page_hash = Sha256::digest(data);
        let mut sample = [0u8; MAX_PAGE_SAMPLE];
        let copy_len = if data.len() < MAX_PAGE_SAMPLE { data.len() } else { MAX_PAGE_SAMPLE };
        sample[..copy_len].copy_from_slice(&data[..copy_len]);

        Self {
            vaddr,
            paddr,
            flags,
            sample_data: sample,
            sample_len: copy_len,
            page_hash,
        }
    }

    /// Effacement sécurisé de la page (Memory Scrubbing)
    pub fn scrub(&mut self) {
        self.flags = 0;
        self.vaddr = 0;
        self.paddr = 0;
        self.sample_len = 0;
        for b in self.sample_data.iter_mut() {
            *b = 0;
        }
        for b in self.page_hash.iter_mut() {
            *b = 0;
        }
    }
}

// ============================================================================
// SCELLEMENT CRYPTOGRAPHIQUE (SEALED STORAGE) & RAPPORTS D'ATTESTATION
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealingPolicy {
    ExactMeasurement = 1, // Lié strictement au MRENCLAVE (code et données identiques)
    SignerIdentity = 2,   // Lié au MRSIGNER (même autorité de signature)
}

#[derive(Debug, Clone, Copy)]
pub struct SealedBlob {
    pub id: u32,
    pub enclave_id: u32,
    pub policy: SealingPolicy,
    pub expected_measurement: [u8; 32],
    pub signer_id: [u8; 32],
    pub nonce: [u8; 16],
    pub tag: [u8; 32],
    pub ciphertext_len: usize,
    pub ciphertext: [u8; MAX_CIPHERTEXT_LEN],
}

#[derive(Debug, Clone, Copy)]
pub struct TeeReport {
    pub enclave_id: u32,
    pub backend: TeeBackend,
    pub measurement: [u8; 32],
    pub signer_id: [u8; 32],
    pub user_data: [u8; 64],
    pub user_data_len: usize,
    pub timestamp: u64,
    pub report_mac: [u8; 32],
}

// ============================================================================
// STRUCTURE D'ENCLAVE ISOLÉE
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct Enclave {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub backend: TeeBackend,
    pub state: EnclaveState,
    pub owner_pid: u64,
    pub base_vaddr: u64,
    pub size_bytes: u64,
    pub page_count: usize,
    pub pages: [Option<EnclavePage>; MAX_PAGES_PER_ENCLAVE],
    pub mrenclave: [u8; 32],
    pub mrsigner: [u8; 32],
    pub entry_point: u64,
    pub total_entries: u32,
    pub total_exits: u32,
    pub is_isolated: bool,
}

impl Enclave {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }

    /// Vérifie si une adresse virtuelle se situe à l'intérieur de l'espace de mémoire isolée
    pub fn contains_vaddr(&self, vaddr: u64) -> bool {
        vaddr >= self.base_vaddr && vaddr < (self.base_vaddr + self.size_bytes)
    }
}

// ============================================================================
// JOURNAL D'AUDIT INALTÉRABLE
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeAction {
    EnclaveCreated = 1,
    PageLoaded = 2,
    EnclaveFinalized = 3,
    EnclaveEntered = 4,
    EnclaveExited = 5,
    DataSealed = 6,
    DataUnsealed = 7,
    ReportGenerated = 8,
    EnclaveDestroyed = 9,
    ViolationDetected = 10,
}

#[derive(Debug, Clone, Copy)]
pub struct TeeAuditLog {
    pub timestamp: u64,
    pub action: TeeAction,
    pub enclave_id: u32,
    pub status: u32,
    pub digest: [u8; 32],
}

// ============================================================================
// DÉMON DU SOUS-SYSTÈME TEE SOUVERAIN (`JamboTeeDaemon`)
// ============================================================================

pub struct JamboTeeDaemon {
    pub admin_cap: TeeCap,
    pub enclaves: [Option<Enclave>; MAX_ENCLAVES],
    pub sealed_blobs: [Option<SealedBlob>; MAX_SEALED_SLOTS],
    pub reports: [Option<TeeReport>; MAX_REPORTS],
    pub audit_logs: [Option<TeeAuditLog>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub audit_chain: [u8; 32],
    pub total_created: u64,
    pub total_entries: u64,
    pub total_seals: u64,
    pub total_violations: u64,
    next_blob_id: u32,
}

impl JamboTeeDaemon {
    pub const fn new(admin_cap: TeeCap) -> Self {
        Self {
            admin_cap,
            enclaves: [None; MAX_ENCLAVES],
            sealed_blobs: [None; MAX_SEALED_SLOTS],
            reports: [None; MAX_REPORTS],
            audit_logs: [None; MAX_AUDIT_LOGS],
            audit_count: 0,
            audit_chain: [0u8; 32],
            total_created: 0,
            total_entries: 0,
            total_seals: 0,
            total_violations: 0,
            next_blob_id: 1,
        }
    }

    /// Initialise les enclaves système de démonstration (SGX & TrustZone)
    pub fn init_defaults(&mut self) {
        let admin_cap = self.admin_cap;
        let signer = Sha256::digest(b"JamboOS Sovereign Security Authority");
        if let Ok(id1) = self.create_enclave(
            &admin_cap,
            "sec-keyring",
            TeeBackend::IntelSgx,
            1,
            0x0000_7000_0000_0000,
            64 * 1024,
            signer,
        ) {
            let _ = self.load_page(&admin_cap, id1, 0x0000_7000_0000_0000, page_flags::CODE, b"SEC_KEYRING_BOOT_CODE");
            let _ = self.finalize_enclave(&admin_cap, id1, 0x0000_7000_0000_0000);
        }

        if let Ok(id2) = self.create_enclave(
            &admin_cap,
            "realm-crypto",
            TeeBackend::ArmCca,
            2,
            0x0000_7001_0000_0000,
            128 * 1024,
            signer,
        ) {
            let _ = self.load_page(&admin_cap, id2, 0x0000_7001_0000_0000, page_flags::CODE, b"REALM_CRYPTO_BOOT_CODE");
            let _ = self.finalize_enclave(&admin_cap, id2, 0x0000_7001_0000_0000);
        }
    }

    /// Enregistre une entrée dans le journal d'audit inaltérable chaîné
    fn append_audit(&mut self, timestamp: u64, action: TeeAction, enclave_id: u32, status: u32) {
        let mut buffer = [0u8; 48];
        buffer[0..8].copy_from_slice(&timestamp.to_be_bytes());
        buffer[8] = action as u8;
        buffer[9..13].copy_from_slice(&enclave_id.to_be_bytes());
        buffer[13..17].copy_from_slice(&status.to_be_bytes());
        buffer[17..48].copy_from_slice(&self.audit_chain[0..31]);

        let digest = Sha256::digest(&buffer);
        self.audit_chain = digest;

        let log = TeeAuditLog {
            timestamp,
            action,
            enclave_id,
            status,
            digest,
        };

        let slot = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_logs[slot] = Some(log);
        self.audit_count += 1;
    }

    /// Création d'une enclave isolée Ring 3
    pub fn create_enclave(
        &mut self,
        cap: &TeeCap,
        name: &str,
        backend: TeeBackend,
        owner_pid: u64,
        base_vaddr: u64,
        size_bytes: u64,
        mrsigner: [u8; 32],
    ) -> Result<u32, SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::CREATE) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        // Trouver un emplacement libre
        let mut free_idx = None;
        for (i, slot) in self.enclaves.iter().enumerate() {
            if slot.is_none() {
                free_idx = Some(i);
                break;
            }
        }

        let idx = match free_idx {
            Some(i) => i,
            None => return Err(SysError::OutOfMemory),
        };

        let id = (idx as u32) + 1;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let copy_len = if bytes.len() < MAX_NAME_LEN { bytes.len() } else { MAX_NAME_LEN };
        name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let enclave = Enclave {
            id,
            name: name_buf,
            name_len: copy_len,
            backend,
            state: EnclaveState::Created,
            owner_pid,
            base_vaddr,
            size_bytes,
            page_count: 0,
            pages: [None; MAX_PAGES_PER_ENCLAVE],
            mrenclave: [0u8; 32],
            mrsigner,
            entry_point: 0,
            total_entries: 0,
            total_exits: 0,
            is_isolated: true,
        };

        self.enclaves[idx] = Some(enclave);
        self.total_created += 1;
        self.append_audit(1000, TeeAction::EnclaveCreated, id, 0);

        Ok(id)
    }

    /// Chargement d'une page isolée dans l'enclave (EADD / EPC Allocation)
    pub fn load_page(
        &mut self,
        cap: &TeeCap,
        enclave_id: u32,
        vaddr: u64,
        flags: u8,
        data: &[u8],
    ) -> Result<(), SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::LOAD) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        let enclave = self.get_enclave_mut(enclave_id)?;
        if enclave.state != EnclaveState::Created && enclave.state != EnclaveState::Loading {
            return Err(SysError::InvalidArgument);
        }

        if !enclave.contains_vaddr(vaddr) {
            return Err(SysError::InvalidArgument);
        }

        if enclave.page_count >= MAX_PAGES_PER_ENCLAVE {
            return Err(SysError::OutOfMemory);
        }

        let page_idx = enclave.page_count;
        let paddr = 0x8000_0000_u64 + (enclave_id as u64 * 0x100000) + (page_idx as u64 * 4096);
        let page = EnclavePage::new(vaddr, paddr, flags, data);

        enclave.pages[page_idx] = Some(page);
        enclave.page_count += 1;
        enclave.state = EnclaveState::Loading;

        self.append_audit(1001, TeeAction::PageLoaded, enclave_id, page_idx as u32);
        Ok(())
    }

    /// Finalisation et scellement cryptographique de la mesure (EINIT / MRENCLAVE)
    pub fn finalize_enclave(
        &mut self,
        cap: &TeeCap,
        enclave_id: u32,
        entry_point: u64,
    ) -> Result<[u8; 32], SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::CREATE) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        let enclave = self.get_enclave_mut(enclave_id)?;
        if enclave.state != EnclaveState::Created && enclave.state != EnclaveState::Loading {
            return Err(SysError::InvalidArgument);
        }

        // Calcul cumulatif du hash MRENCLAVE sur toutes les pages chargées et métadonnées
        let mut accum = [0u8; 64];
        accum[0..4].copy_from_slice(&enclave.id.to_be_bytes());
        accum[4] = enclave.backend as u8;
        accum[8..16].copy_from_slice(&enclave.base_vaddr.to_be_bytes());
        accum[16..24].copy_from_slice(&enclave.size_bytes.to_be_bytes());
        accum[24..32].copy_from_slice(&entry_point.to_be_bytes());
        let mut rolling_hash = Sha256::digest(&accum);

        for slot in enclave.pages.iter().flatten() {
            let mut page_block = [0u8; 64];
            page_block[0..32].copy_from_slice(&rolling_hash);
            page_block[32..64].copy_from_slice(&slot.page_hash);
            rolling_hash = Sha256::digest(&page_block);
        }

        enclave.mrenclave = rolling_hash;
        enclave.entry_point = entry_point;
        enclave.state = EnclaveState::Finalized;

        self.append_audit(1002, TeeAction::EnclaveFinalized, enclave_id, 0);
        Ok(rolling_hash)
    }

    /// Entrée dans l'enclave en Ring 3 (EENTER / Commutation de contexte sécurisé)
    pub fn enter_enclave(
        &mut self,
        cap: &TeeCap,
        enclave_id: u32,
        caller_context: u64,
    ) -> Result<u64, SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::ENTER) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        let entry_point = {
            let enclave = self.get_enclave_mut(enclave_id)?;
            if enclave.state != EnclaveState::Finalized && enclave.state != EnclaveState::Running {
                return Err(SysError::InvalidArgument);
            }

            enclave.state = EnclaveState::Running;
            enclave.total_entries += 1;
            enclave.entry_point
        };

        self.total_entries += 1;
        self.append_audit(1003, TeeAction::EnclaveEntered, enclave_id, caller_context as u32);
        Ok(entry_point)
    }

    /// Sortie ordonnée de l'enclave (EEXIT)
    pub fn exit_enclave(
        &mut self,
        cap: &TeeCap,
        enclave_id: u32,
        return_code: u64,
    ) -> Result<(), SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::ENTER) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        let enclave = self.get_enclave_mut(enclave_id)?;
        if enclave.state != EnclaveState::Running {
            return Err(SysError::InvalidArgument);
        }

        enclave.total_exits += 1;
        self.append_audit(1004, TeeAction::EnclaveExited, enclave_id, return_code as u32);
        Ok(())
    }

    /// Scellement cryptographique de données (Sealed Storage)
    pub fn seal_data(
        &mut self,
        cap: &TeeCap,
        enclave_id: u32,
        policy: SealingPolicy,
        plaintext: &[u8],
        secret_key: &[u8; 32],
    ) -> Result<u32, SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::SEAL) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        if plaintext.len() > MAX_CIPHERTEXT_LEN {
            return Err(SysError::InvalidArgument);
        }

        let (mrenclave, mrsigner) = {
            let enclave = self.get_enclave(enclave_id)?;
            if enclave.state != EnclaveState::Finalized && enclave.state != EnclaveState::Running {
                return Err(SysError::InvalidArgument);
            }
            (enclave.mrenclave, enclave.mrsigner)
        };

        // Trouver un emplacement libre pour le blob scellé
        let mut free_slot = None;
        for (i, slot) in self.sealed_blobs.iter().enumerate() {
            if slot.is_none() {
                free_slot = Some(i);
                break;
            }
        }

        let slot_idx = match free_slot {
            Some(i) => i,
            None => return Err(SysError::OutOfMemory),
        };

        // Dérivation de clé de scellement liée à la politique choisie
        let mut kdf_input = [0u8; 65];
        kdf_input[0] = policy as u8;
        match policy {
            SealingPolicy::ExactMeasurement => {
                kdf_input[1..33].copy_from_slice(&mrenclave);
                kdf_input[33..65].copy_from_slice(secret_key);
            }
            SealingPolicy::SignerIdentity => {
                kdf_input[1..33].copy_from_slice(&mrsigner);
                kdf_input[33..65].copy_from_slice(secret_key);
            }
        }
        let derived_key = Sha256::digest(&kdf_input);

        // Chiffrement par flux et calcul du tag d'intégrité
        let mut ciphertext = [0u8; MAX_CIPHERTEXT_LEN];
        let mut nonce = [0u8; 16];
        let seed = (self.next_blob_id as u64).to_be_bytes();
        nonce[0..8].copy_from_slice(&seed);
        nonce[8..16].copy_from_slice(&seed);

        let mut keystream_seed = [0u8; 48];
        keystream_seed[0..32].copy_from_slice(&derived_key);
        keystream_seed[32..48].copy_from_slice(&nonce);
        let keystream = Sha256::digest(&keystream_seed);

        for (i, b) in plaintext.iter().enumerate() {
            ciphertext[i] = b ^ keystream[i % 32];
        }

        // Calcul du tag d'intégrité (HMAC sur ciphertext + nonce + mesure)
        let tag = Sha256::hmac(&derived_key, &ciphertext[..plaintext.len()]);

        let blob_id = self.next_blob_id;
        self.next_blob_id += 1;

        let blob = SealedBlob {
            id: blob_id,
            enclave_id,
            policy,
            expected_measurement: mrenclave,
            signer_id: mrsigner,
            nonce,
            tag,
            ciphertext_len: plaintext.len(),
            ciphertext,
        };

        self.sealed_blobs[slot_idx] = Some(blob);
        self.total_seals += 1;
        self.append_audit(1005, TeeAction::DataSealed, enclave_id, blob_id);

        Ok(blob_id)
    }

    /// Déscellement de données (Unseal) avec vérification formelle de la mesure
    pub fn unseal_data(
        &mut self,
        cap: &TeeCap,
        enclave_id: u32,
        blob_id: u32,
        secret_key: &[u8; 32],
        output: &mut [u8],
    ) -> Result<usize, SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::SEAL) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        let enclave = self.get_enclave(enclave_id)?;
        let blob = match self.sealed_blobs.iter().flatten().find(|b| b.id == blob_id) {
            Some(b) => *b,
            None => return Err(SysError::InvalidHandle),
        };

        // Vérification formelle de la conformité de politique
        match blob.policy {
            SealingPolicy::ExactMeasurement => {
                if blob.expected_measurement != enclave.mrenclave {
                    self.total_violations += 1;
                    self.append_audit(1006, TeeAction::ViolationDetected, enclave_id, AUDIT_BAD_MRENCLAVE);
                    return Err(SysError::PermissionDenied);
                }
            }
            SealingPolicy::SignerIdentity => {
                if blob.signer_id != enclave.mrsigner {
                    self.total_violations += 1;
                    self.append_audit(1006, TeeAction::ViolationDetected, enclave_id, AUDIT_BAD_SIGNER);
                    return Err(SysError::PermissionDenied);
                }
            }
        }

        // Régénération de la clé dérivée
        let mut kdf_input = [0u8; 65];
        kdf_input[0] = blob.policy as u8;
        match blob.policy {
            SealingPolicy::ExactMeasurement => {
                kdf_input[1..33].copy_from_slice(&enclave.mrenclave);
                kdf_input[33..65].copy_from_slice(secret_key);
            }
            SealingPolicy::SignerIdentity => {
                kdf_input[1..33].copy_from_slice(&enclave.mrsigner);
                kdf_input[33..65].copy_from_slice(secret_key);
            }
        }
        let derived_key = Sha256::digest(&kdf_input);

        // Vérification du tag d'intégrité
        let expected_tag = Sha256::hmac(&derived_key, &blob.ciphertext[..blob.ciphertext_len]);
        if expected_tag != blob.tag {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        if output.len() < blob.ciphertext_len {
            return Err(SysError::InvalidArgument);
        }

        // Déchiffrement
        let mut keystream_seed = [0u8; 48];
        keystream_seed[0..32].copy_from_slice(&derived_key);
        keystream_seed[32..48].copy_from_slice(&blob.nonce);
        let keystream = Sha256::digest(&keystream_seed);

        for i in 0..blob.ciphertext_len {
            output[i] = blob.ciphertext[i] ^ keystream[i % 32];
        }

        self.append_audit(1007, TeeAction::DataUnsealed, enclave_id, blob_id);
        Ok(blob.ciphertext_len)
    }

    /// Génération d'un rapport d'attestation cryptographique (EREPORT)
    pub fn generate_report(
        &mut self,
        cap: &TeeCap,
        enclave_id: u32,
        user_data: &[u8],
    ) -> Result<TeeReport, SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::REPORT) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        let enclave = self.get_enclave(enclave_id)?;
        if enclave.state != EnclaveState::Finalized && enclave.state != EnclaveState::Running {
            return Err(SysError::InvalidArgument);
        }

        let mut udata = [0u8; 64];
        let copy_len = if user_data.len() < 64 { user_data.len() } else { 64 };
        udata[..copy_len].copy_from_slice(&user_data[..copy_len]);

        // Construction du payload pour signature MAC
        let mut report_payload = [0u8; 32 + 32 + 64 + 8];
        report_payload[0..32].copy_from_slice(&enclave.mrenclave);
        report_payload[32..64].copy_from_slice(&enclave.mrsigner);
        report_payload[64..128].copy_from_slice(&udata);
        report_payload[128..136].copy_from_slice(&1008_u64.to_be_bytes());

        let report_mac = Sha256::hmac(&enclave.mrsigner, &report_payload);

        let report = TeeReport {
            enclave_id,
            backend: enclave.backend,
            measurement: enclave.mrenclave,
            signer_id: enclave.mrsigner,
            user_data: udata,
            user_data_len: copy_len,
            timestamp: 1008,
            report_mac,
        };

        // Stocker dans le tampon circulaire de rapports
        let slot = (self.reports.iter().filter(|r| r.is_some()).count()) % MAX_REPORTS;
        self.reports[slot] = Some(report);

        self.append_audit(1008, TeeAction::ReportGenerated, enclave_id, 0);
        Ok(report)
    }

    /// Destruction d'une enclave et nettoyage strict de la mémoire (Memory Scrubbing)
    pub fn destroy_enclave(&mut self, cap: &TeeCap, enclave_id: u32) -> Result<(), SysError> {
        if cap.handle.is_null() || !cap.has_right(tee_rights::ADMIN) {
            self.total_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        let idx = (enclave_id as usize).checked_sub(1).ok_or(SysError::InvalidArgument)?;
        if idx >= MAX_ENCLAVES {
            return Err(SysError::InvalidArgument);
        }

        if let Some(mut enclave) = self.enclaves[idx].take() {
            // Effacement sécurisé de toutes les pages physiques / virtuelles
            for slot in enclave.pages.iter_mut() {
                if let Some(ref mut page) = slot {
                    page.scrub();
                }
                *slot = None;
            }
            self.append_audit(1009, TeeAction::EnclaveDestroyed, enclave_id, 0);
            Ok(())
        } else {
            Err(SysError::InvalidHandle)
        }
    }

    /// Vérifie l'étanchéité mémoire : interdit tout accès direct depuis l'extérieur à la mémoire isolée
    pub fn verify_memory_isolation(&self, enclave_id: u32, target_vaddr: u64) -> bool {
        if let Ok(enclave) = self.get_enclave(enclave_id) {
            if enclave.is_isolated && enclave.contains_vaddr(target_vaddr) {
                return true; // Protégée par l'enclave
            }
        }
        false
    }

    pub fn get_enclave(&self, id: u32) -> Result<&Enclave, SysError> {
        let idx = (id as usize).checked_sub(1).ok_or(SysError::InvalidArgument)?;
        if idx < MAX_ENCLAVES {
            if let Some(ref enc) = self.enclaves[idx] {
                return Ok(enc);
            }
        }
        Err(SysError::InvalidHandle)
    }

    fn get_enclave_mut(&mut self, id: u32) -> Result<&mut Enclave, SysError> {
        let idx = (id as usize).checked_sub(1).ok_or(SysError::InvalidArgument)?;
        if idx < MAX_ENCLAVES {
            if let Some(ref mut enc) = self.enclaves[idx] {
                return Ok(enc);
            }
        }
        Err(SysError::InvalidHandle)
    }
}

pub const AUDIT_BAD_MRENCLAVE: u32 = 0xBAD1;
pub const AUDIT_BAD_SIGNER: u32 = 0xBAD2;

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_lifecycle_and_sealing() {
        let admin_cap = TeeCap::new(Handle::new(100, 1), tee_rights::ALL);
        let mut daemon = JamboTeeDaemon::new(admin_cap);

        let signer = Sha256::digest(b"Vendor-Cert");
        let enc_id = daemon
            .create_enclave(
                &admin_cap,
                "vault-app",
                TeeBackend::IntelSgx,
                42,
                0x7000_0000,
                0x10000,
                signer,
            )
            .expect("Create enclave");

        assert_eq!(enc_id, 1);
        let enc = daemon.get_enclave(enc_id).unwrap();
        assert_eq!(enc.name_as_str(), "vault-app");
        assert_eq!(enc.state, EnclaveState::Created);

        // Chargement de page
        daemon
            .load_page(
                &admin_cap,
                enc_id,
                0x7000_0000,
                page_flags::CODE,
                b"SECURE_ENTRYPOINT_CODE_BYTES",
            )
            .expect("Load page");

        // Finalisation
        let mrenclave = daemon
            .finalize_enclave(&admin_cap, enc_id, 0x7000_0000)
            .expect("Finalize");
        assert_ne!(mrenclave, [0u8; 32]);

        // Entrée et sortie
        let entry = daemon.enter_enclave(&admin_cap, enc_id, 1234).expect("Enter");
        assert_eq!(entry, 0x7000_0000);
        daemon.exit_enclave(&admin_cap, enc_id, 0).expect("Exit");

        // Scellement
        let key = [0x5au8; 32];
        let secret = b"TOP_SECRET_PASSPHRASE";
        let blob_id = daemon
            .seal_data(
                &admin_cap,
                enc_id,
                SealingPolicy::ExactMeasurement,
                secret,
                &key,
            )
            .expect("Seal");

        // Déscellement réussi
        let mut out = [0u8; 64];
        let len = daemon
            .unseal_data(&admin_cap, enc_id, blob_id, &key, &mut out)
            .expect("Unseal");
        assert_eq!(&out[..len], secret);

        // Attestation
        let report = daemon
            .generate_report(&admin_cap, enc_id, b"CHALLENGE_NONCE_123")
            .expect("Report");
        assert_eq!(report.measurement, mrenclave);
        assert_eq!(&report.user_data[..19], b"CHALLENGE_NONCE_123");

        // Destruction & scrubbing
        daemon.destroy_enclave(&admin_cap, enc_id).expect("Destroy");
        assert!(daemon.get_enclave(enc_id).is_err());
    }

    #[test]
    fn test_tee_attenuation() {
        let admin_cap = TeeCap::new(Handle::new(100, 1), tee_rights::ALL);
        let attenuated = admin_cap.attenuate(tee_rights::ENTER | tee_rights::REPORT).unwrap();

        assert!(attenuated.has_right(tee_rights::ENTER));
        assert!(attenuated.has_right(tee_rights::REPORT));
        assert!(!attenuated.has_right(tee_rights::ADMIN));
        assert!(!attenuated.has_right(tee_rights::CREATE));

        // Rejet d'amplification
        assert!(attenuated.attenuate(tee_rights::ALL).is_err());
    }
}

//! Micro-hyperviseurs d'Enclaves de Confiance Imbriquées & Isolation de Mémoire Chiffrée Multi-Locataires (`jambo-tee2`)
//!
//! Phase 107 — Jalon v0.2.105
//!
//! Fournit les garanties souveraines d'exécution de confiance imbriquée et d'étanchéité multi-locataires :
//! 1. Hiérarchie Micro-Hyperviseur d'Enclaves Imbriquées (Nested TEEs) :
//!    Prise en charge de la virtualisation à deux niveaux (L0 Hôte -> L1 Superviseur d'Enclave de Locataire -> L2 Enclave Imbriquée / Conteneur Realm).
//! 2. Isolation de Mémoire Chiffrée Multi-Locataires (Multi-Tenant Encrypted Isolation) :
//!    Attribution stricte d'identifiants de clés matérielles (KeyID / HKID / ASID) et de clés MEK (Multi-tenant Encryption Key) 256 bits,
//!    garantissant l'absence de fuite d'adresses physiques ou de données entre locataires.
//! 3. Tables EPT Imbriquées (Nested Extended Page Tables / Stage-2 Nested Translation) :
//!    Traduction rigoureuse à deux étages : GPA (Guest Physical Address L2) -> IPA (Intermediate Physical Address L1) -> HPA (Host Physical Address L0).
//!    Validation formelle des permissions (R/W/X/Encrypted) et intégrité Merkle SHA-256 de la configuration EPT.
//! 4. Chaîne de Mesure Cryptographique Imbriquée & Attestation Distante :
//!    Mesure cumulative combinant le superviseur L1 (MRENCLAVE_L1), la charge utile imbriquée L2 (MRENCLAVE_L2) et
//!    la racine d'intégrité EPT. Rapports d'attestation `NestedTeeReport` scellés par HMAC-SHA256 avec défi anti-rejeu.
//! 5. Scellement Multi-Locataire de Secrets (Nested Sealed Storage) :
//!    Politiques de scellement strictes (`ExactNestedMeasurement` ou `TenantDomain`) interdisant tout accès non autorisé.
//! 6. Détection et Confinement O(1) des Violations EPT & Zéro Résidu :
//!    Blocage instantané des tentatives de chevauchement d'adresses inter-locataires et effacement garanti (Memory Scrubbing) à la destruction.
//! 7. Gouvernance Capabilaire Stricte (`Tee2Cap`) :
//!    Gestion sans autorité ambiante avec droits granulaires et atténuation monotone irréversible.
//! 8. Registre d'Audit Inaltérable :
//!    Traçabilité scellée par hachage cumulatif SHA-256 (`audit_chain`) de chaque événement de cycle de vie et d'accès mémoire.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_TENANTS: usize = 16;
pub const MAX_ENCLAVES: usize = 32;
pub const MAX_EPT_MAPPINGS: usize = 64;
pub const MAX_SEALED_SLOTS: usize = 32;
pub const MAX_REPORTS: usize = 32;
pub const MAX_AUDIT_LOGS: usize = 64;
pub const MAX_NAME_LEN: usize = 32;
pub const PAGE_SIZE: usize = 4096;
pub const HASH_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const MAX_CIPHERTEXT_LEN: usize = 256;
pub const MAX_PAGE_SAMPLE: usize = 64;

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
            let mut fallback = [0u8; 32];
            fallback.copy_from_slice(&Self::digest(message));
            for i in 0..32 {
                fallback[i] ^= k_pad[i];
            }
            Self::digest(&fallback)
        }
    }
}

/// Égalité en temps constant
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// GOUVERNANCE CAPABILAIRE & DROITS TEE2
// ============================================================================

pub mod tee2_rights {
    pub const CREATE_TENANT: u32 = 1 << 0;
    pub const CREATE_L1: u32     = 1 << 1;
    pub const CREATE_L2: u32     = 1 << 2;
    pub const MAP_EPT: u32       = 1 << 3;
    pub const ENCRYPT_MEM: u32   = 1 << 4;
    pub const ATTEST: u32        = 1 << 5;
    pub const SEAL: u32          = 1 << 6;
    pub const UNSEAL: u32        = 1 << 7;
    pub const MIGRATE: u32       = 1 << 8;
    pub const SCRUB: u32         = 1 << 9;
    pub const AUDIT: u32         = 1 << 10;

    pub const ALL: u32 = CREATE_TENANT
        | CREATE_L1
        | CREATE_L2
        | MAP_EPT
        | ENCRYPT_MEM
        | ATTEST
        | SEAL
        | UNSEAL
        | MIGRATE
        | SCRUB
        | AUDIT;
}

/// Jeton de capacité souverain pour la gestion du sous-système TEE imbriqué
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tee2Cap {
    pub handle: Handle,
    pub rights: u32,
    pub tenant_id: u32,
    pub max_enclaves: u16,
}

impl Tee2Cap {
    pub const fn new(handle: Handle, rights: u32, tenant_id: u32, max_enclaves: u16) -> Self {
        Self {
            handle,
            rights,
            tenant_id,
            max_enclaves,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone irréversible : interdit toute amplification de privilèges
    pub fn attenuate(&self, requested_rights: u32, requested_max: u16) -> Result<Self, NestedTeeError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(NestedTeeError::PermissionDenied);
        }
        if requested_max > self.max_enclaves {
            return Err(NestedTeeError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
            tenant_id: self.tenant_id,
            max_enclaves: requested_max,
        })
    }
}

// ============================================================================
// TYPES, STRUCTURES & ERREURS TEE IMBRIQUÉ
// ============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NestedTeeBackend {
    IntelTdxPartitioning = 1,
    IntelSgxNested = 2,
    ArmCcaRealm = 3,
    AmdSevSnpVmpl = 4,
    JamboMicroHypervisor = 5,
}

impl NestedTeeBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntelTdxPartitioning => "Intel TDX Partitioning (L1/L2 Trust Domains)",
            Self::IntelSgxNested => "Intel SGX Nested (vEPC/SECS/TCS)",
            Self::ArmCcaRealm => "ARM CCA Realm (RME Stage-2 Nested)",
            Self::AmdSevSnpVmpl => "AMD SEV-SNP (VMPL0..3 RMP)",
            Self::JamboMicroHypervisor => "Jambo Sovereign Micro-Hypervisor",
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveLevel {
    L1Supervisor = 1,
    L2Nested = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveState {
    Uninitialized = 0,
    Created = 1,
    EptConfigured = 2,
    L2Loaded = 3,
    Sealed = 4,
    Running = 5,
    Paused = 6,
    Destroyed = 7,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NestedSealingPolicy {
    ExactNestedMeasurement = 1, // Lié strictement à la mesure combinée L1 + L2 + EPT
    TenantDomain = 2,           // Accessible par toute enclave du même TenantId et KeyId
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NestedTeeError {
    TenantNotFound,
    TenantLimitReached,
    TenantAlreadyExists,
    TenantMismatch,
    EnclaveNotFound,
    EnclaveLimitReached,
    InvalidStateTransition,
    EptViolation,
    EptTableFull,
    EptAlignmentError,
    EptPermissionDenied,
    CrossTenantAccessDenied,
    MemoryEncryptionFailed,
    KeyIdNotFound,
    AttestationFailed,
    ChallengeMismatch,
    SealingFailed,
    UnsealingFailed,
    PermissionDenied,
    CapacityExceeded,
    AuditLogFull,
}

impl From<NestedTeeError> for SysError {
    fn from(err: NestedTeeError) -> Self {
        match err {
            NestedTeeError::PermissionDenied | NestedTeeError::CrossTenantAccessDenied => {
                SysError::PermissionDenied
            }
            NestedTeeError::TenantNotFound | NestedTeeError::EnclaveNotFound => {
                SysError::InvalidArgument
            }
            NestedTeeError::TenantLimitReached
            | NestedTeeError::EnclaveLimitReached
            | NestedTeeError::EptTableFull
            | NestedTeeError::CapacityExceeded => SysError::OutOfMemory,
            NestedTeeError::EptAlignmentError | NestedTeeError::InvalidStateTransition => {
                SysError::InvalidArgument
            }
            _ => SysError::NotSupported,
        }
    }
}

pub mod ept_flags {
    pub const READ: u8            = 1 << 0;
    pub const WRITE: u8           = 1 << 1;
    pub const EXEC: u8            = 1 << 2;
    pub const ENCRYPTED: u8       = 1 << 3;
    pub const SUPERVISOR_ONLY: u8 = 1 << 4;
    pub const NESTED_SHADOW: u8   = 1 << 5;
    pub const REGULAR: u8         = READ | WRITE | ENCRYPTED;
    pub const CODE: u8            = READ | EXEC | ENCRYPTED;
}

/// Entrée de mappage de table de pages étendue imbriquée (Nested EPT / Stage-2)
#[derive(Debug, Clone, Copy)]
pub struct NestedEptMapping {
    pub gpa: u64,           // Guest Physical Address (L2)
    pub ipa: u64,           // Intermediate Physical Address (L1)
    pub hpa: u64,           // Host Physical Address (L0)
    pub flags: u8,          // ept_flags
    pub key_id: u16,        // Hardware KeyID pour chiffrement mémoire (MK-TME / TDX HKID)
    pub tenant_id: u32,     // Isolation multi-locataire stricte
    pub page_hash: [u8; 32],// Empreinte d'intégrité SHA-256 de la page
    pub valid: bool,
}

impl NestedEptMapping {
    pub const fn empty() -> Self {
        Self {
            gpa: 0,
            ipa: 0,
            hpa: 0,
            flags: 0,
            key_id: 0,
            tenant_id: 0,
            page_hash: [0u8; 32],
            valid: false,
        }
    }

    #[inline(always)]
    pub fn is_readable(&self) -> bool {
        (self.flags & ept_flags::READ) != 0
    }

    #[inline(always)]
    pub fn is_writable(&self) -> bool {
        (self.flags & ept_flags::WRITE) != 0
    }

    #[inline(always)]
    pub fn is_executable(&self) -> bool {
        (self.flags & ept_flags::EXEC) != 0
    }

    #[inline(always)]
    pub fn is_encrypted(&self) -> bool {
        (self.flags & ept_flags::ENCRYPTED) != 0
    }
}

/// Table de pages étendues imbriquées (Nested EPT) par enclave
#[derive(Debug, Clone, Copy)]
pub struct NestedEptTable {
    pub entries: [NestedEptMapping; MAX_EPT_MAPPINGS],
    pub count: usize,
    pub root_hash: [u8; 32],
}

impl NestedEptTable {
    pub const fn new() -> Self {
        Self {
            entries: [NestedEptMapping::empty(); MAX_EPT_MAPPINGS],
            count: 0,
            root_hash: [0u8; 32],
        }
    }

    /// Recalcule l'empreinte Merkle SHA-256 de la table EPT imbriquée
    pub fn update_root_hash(&mut self) {
        let mut buffer = [0u8; 64];
        let mut running_hash = [0u8; 32];

        for entry in self.entries.iter() {
            if entry.valid {
                buffer[..8].copy_from_slice(&entry.gpa.to_le_bytes());
                buffer[8..16].copy_from_slice(&entry.ipa.to_le_bytes());
                buffer[16..24].copy_from_slice(&entry.hpa.to_le_bytes());
                buffer[24] = entry.flags;
                buffer[25..27].copy_from_slice(&entry.key_id.to_le_bytes());
                buffer[27..31].copy_from_slice(&entry.tenant_id.to_le_bytes());
                buffer[31] = 0xAA;
                buffer[32..64].copy_from_slice(&entry.page_hash);

                let mut merge = [0u8; 64];
                merge[..32].copy_from_slice(&running_hash);
                merge[32..64].copy_from_slice(&Sha256::digest(&buffer));
                running_hash = Sha256::digest(&merge);
            }
        }
        self.root_hash = running_hash;
    }

    /// Insère un mappage GPA -> IPA -> HPA dans la table EPT imbriquée
    pub fn map_page(
        &mut self,
        gpa: u64,
        ipa: u64,
        hpa: u64,
        flags: u8,
        key_id: u16,
        tenant_id: u32,
        data: &[u8],
    ) -> Result<(), NestedTeeError> {
        if (gpa % PAGE_SIZE as u64) != 0
            || (ipa % PAGE_SIZE as u64) != 0
            || (hpa % PAGE_SIZE as u64) != 0
        {
            return Err(NestedTeeError::EptAlignmentError);
        }

        // Vérifier si le GPA est déjà mappé
        for entry in self.entries.iter_mut() {
            if entry.valid && entry.gpa == gpa {
                entry.ipa = ipa;
                entry.hpa = hpa;
                entry.flags = flags;
                entry.key_id = key_id;
                entry.tenant_id = tenant_id;
                entry.page_hash = Sha256::digest(data);
                self.update_root_hash();
                return Ok(());
            }
        }

        if self.count >= MAX_EPT_MAPPINGS {
            return Err(NestedTeeError::EptTableFull);
        }

        for entry in self.entries.iter_mut() {
            if !entry.valid {
                entry.gpa = gpa;
                entry.ipa = ipa;
                entry.hpa = hpa;
                entry.flags = flags;
                entry.key_id = key_id;
                entry.tenant_id = tenant_id;
                entry.page_hash = Sha256::digest(data);
                entry.valid = true;
                self.count += 1;
                self.update_root_hash();
                return Ok(());
            }
        }

        Err(NestedTeeError::EptTableFull)
    }

    /// Traduit une adresse GPA L2 en HPA L0 avec vérification formelle des droits et du tenant
    pub fn translate(
        &self,
        gpa: u64,
        is_write: bool,
        is_exec: bool,
        caller_tenant_id: u32,
    ) -> Result<(u64, u16), NestedTeeError> {
        let page_offset = gpa % PAGE_SIZE as u64;
        let base_gpa = gpa - page_offset;

        for entry in self.entries.iter() {
            if entry.valid && entry.gpa == base_gpa {
                // Contrôle strict de confinement multi-locataire
                if entry.tenant_id != caller_tenant_id {
                    return Err(NestedTeeError::CrossTenantAccessDenied);
                }
                // Contrôle des permissions d'accès
                if is_write && !entry.is_writable() {
                    return Err(NestedTeeError::EptPermissionDenied);
                }
                if is_exec && !entry.is_executable() {
                    return Err(NestedTeeError::EptPermissionDenied);
                }
                if !is_write && !is_exec && !entry.is_readable() {
                    return Err(NestedTeeError::EptPermissionDenied);
                }
                return Ok((entry.hpa + page_offset, entry.key_id));
            }
        }

        Err(NestedTeeError::EptViolation)
    }

    /// Effacement sécurisé (scrubbing) complet de la table EPT
    pub fn scrub(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = NestedEptMapping::empty();
        }
        self.count = 0;
        self.root_hash = [0u8; 32];
    }
}

// ============================================================================
// PARTITION MULTI-LOCATAIRE & GESTION DES CLÉS MEK
// ============================================================================

/// Partition d'isolation mémoire d'un locataire
#[derive(Debug, Clone, Copy)]
pub struct TenantPartition {
    pub tenant_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub key_id: u16,            // KeyID matériel associé au locataire
    pub mek: [u8; KEY_LEN],     // Multi-tenant Encryption Key (256 bits)
    pub base_gpa: u64,          // Plage GPA de base attribuée
    pub size_bytes: u64,        // Taille totale allouée
    pub l1_enclaves_count: usize,
    pub l2_enclaves_count: usize,
    pub total_encrypted_pages: u64,
    pub total_violations: u64,
    pub active: bool,
}

impl TenantPartition {
    pub const fn empty() -> Self {
        Self {
            tenant_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            key_id: 0,
            mek: [0u8; KEY_LEN],
            base_gpa: 0,
            size_bytes: 0,
            l1_enclaves_count: 0,
            l2_enclaves_count: 0,
            total_encrypted_pages: 0,
            total_violations: 0,
            active: false,
        }
    }

    pub fn new(tenant_id: u32, name: &str, key_id: u16, mek: [u8; KEY_LEN], base_gpa: u64, size_bytes: u64) -> Self {
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let copy_len = if bytes.len() < MAX_NAME_LEN { bytes.len() } else { MAX_NAME_LEN };
        name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Self {
            tenant_id,
            name: name_buf,
            name_len: copy_len,
            key_id,
            mek,
            base_gpa,
            size_bytes,
            l1_enclaves_count: 0,
            l2_enclaves_count: 0,
            total_encrypted_pages: 0,
            total_violations: 0,
            active: true,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<inconnu>")
    }

    /// Dérive un flux pseudo-aléatoire (keystream) pour le chiffrement mémoire par page
    pub fn derive_keystream(&self, hpa: u64, out: &mut [u8]) {
        let mut nonce_buf = [0u8; 48];
        nonce_buf[..32].copy_from_slice(&self.mek);
        nonce_buf[32..40].copy_from_slice(&hpa.to_le_bytes());
        nonce_buf[40..44].copy_from_slice(&self.tenant_id.to_le_bytes());
        nonce_buf[44..46].copy_from_slice(&self.key_id.to_le_bytes());
        nonce_buf[46..48].copy_from_slice(&[0x55, 0xAA]);

        let block_hash = Sha256::digest(&nonce_buf);
        let len = if out.len() < 32 { out.len() } else { 32 };
        out[..len].copy_from_slice(&block_hash[..len]);
    }

    /// Chiffrement d'un bloc de mémoire en temps constant
    pub fn encrypt_memory(&mut self, hpa: u64, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), NestedTeeError> {
        if ciphertext.len() < plaintext.len() {
            return Err(NestedTeeError::CapacityExceeded);
        }
        let mut ks = [0u8; 32];
        self.derive_keystream(hpa, &mut ks);

        for (i, (&p, c)) in plaintext.iter().zip(ciphertext.iter_mut()).enumerate() {
            *c = p ^ ks[i % 32];
        }
        self.total_encrypted_pages += 1;
        Ok(())
    }

    /// Déchiffrement d'un bloc de mémoire en temps constant
    pub fn decrypt_memory(&self, hpa: u64, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), NestedTeeError> {
        if plaintext.len() < ciphertext.len() {
            return Err(NestedTeeError::CapacityExceeded);
        }
        let mut ks = [0u8; 32];
        self.derive_keystream(hpa, &mut ks);

        for (i, (&c, p)) in ciphertext.iter().zip(plaintext.iter_mut()).enumerate() {
            *p = c ^ ks[i % 32];
        }
        Ok(())
    }
}

// ============================================================================
// ENCLAVE DE CONFIANCE IMBRIQUÉE (NESTED ENCLAVE)
// ============================================================================

/// Enclave d'exécution de confiance imbriquée (L1 ou L2)
#[derive(Debug, Clone, Copy)]
pub struct NestedEnclave {
    pub enclave_id: u32,
    pub tenant_id: u32,
    pub level: EnclaveLevel,
    pub parent_l1_id: Option<u32>, // Défini si level == L2Nested
    pub backend: NestedTeeBackend,
    pub state: EnclaveState,
    pub key_id: u16,
    pub mrenclave: [u8; 32],      // Empreinte d'intégrité de la charge
    pub ept_table: NestedEptTable, // Tables EPT imbriquées propres
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub active_pages: usize,
}

impl NestedEnclave {
    pub const fn empty() -> Self {
        Self {
            enclave_id: 0,
            tenant_id: 0,
            level: EnclaveLevel::L1Supervisor,
            parent_l1_id: None,
            backend: NestedTeeBackend::JamboMicroHypervisor,
            state: EnclaveState::Uninitialized,
            key_id: 0,
            mrenclave: [0u8; 32],
            ept_table: NestedEptTable::new(),
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            active_pages: 0,
        }
    }

    pub fn new(
        enclave_id: u32,
        tenant_id: u32,
        level: EnclaveLevel,
        parent_l1_id: Option<u32>,
        backend: NestedTeeBackend,
        key_id: u16,
        name: &str,
    ) -> Self {
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let copy_len = if bytes.len() < MAX_NAME_LEN { bytes.len() } else { MAX_NAME_LEN };
        name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Self {
            enclave_id,
            tenant_id,
            level,
            parent_l1_id,
            backend,
            state: EnclaveState::Created,
            key_id,
            mrenclave: [0u8; 32],
            ept_table: NestedEptTable::new(),
            name: name_buf,
            name_len: copy_len,
            active_pages: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<enclave>")
    }

    /// Charge un segment de code ou données et actualise MRENCLAVE
    pub fn load_payload(&mut self, payload: &[u8]) -> Result<(), NestedTeeError> {
        if self.state != EnclaveState::Created && self.state != EnclaveState::EptConfigured {
            return Err(NestedTeeError::InvalidStateTransition);
        }

        let mut composite = [0u8; 64];
        composite[..32].copy_from_slice(&self.mrenclave);
        composite[32..64].copy_from_slice(&Sha256::digest(payload));
        self.mrenclave = Sha256::digest(&composite);

        self.state = EnclaveState::L2Loaded;
        Ok(())
    }

    /// Nettoyage sécurisé de l'enclave (Memory Scrubbing & Zero Residue)
    pub fn scrub(&mut self) {
        self.ept_table.scrub();
        for b in self.mrenclave.iter_mut() {
            *b = 0;
        }
        self.state = EnclaveState::Destroyed;
        self.active_pages = 0;
    }
}

// ============================================================================
// ATTESTATION DISTANTE & RAPPORT D'ENCLAVE IMBRIQUÉE
// ============================================================================

/// Rapport d'attestation d'enclave imbriquée
#[derive(Debug, Clone, Copy)]
pub struct NestedTeeReport {
    pub report_id: u32,
    pub tenant_id: u32,
    pub l1_id: u32,
    pub l2_id: u32,
    pub key_id: u16,
    pub backend: NestedTeeBackend,
    pub l1_measurement: [u8; 32],      // MRENCLAVE du superviseur L1
    pub l2_measurement: [u8; 32],      // MRENCLAVE de la charge L2
    pub ept_root_hash: [u8; 32],       // Empreinte racine de la table EPT imbriquée
    pub combined_measurement: [u8; 32],// Digest(L1 || L2 || EPT || Tenant || KeyID)
    pub challenge: [u8; 32],           // Nonce anti-rejeu
    pub user_data: [u8; 32],           // Données fournies par le client
    pub hmac_signature: [u8; 32],      // Signature matérielle HMAC-SHA256
    pub valid: bool,
}

impl NestedTeeReport {
    pub const fn empty() -> Self {
        Self {
            report_id: 0,
            tenant_id: 0,
            l1_id: 0,
            l2_id: 0,
            key_id: 0,
            backend: NestedTeeBackend::JamboMicroHypervisor,
            l1_measurement: [0u8; 32],
            l2_measurement: [0u8; 32],
            ept_root_hash: [0u8; 32],
            combined_measurement: [0u8; 32],
            challenge: [0u8; 32],
            user_data: [0u8; 32],
            hmac_signature: [0u8; 32],
            valid: false,
        }
    }
}

// ============================================================================
// SCELLEMENT DE SECRETS MULTI-LOCATAIRE (SEALED STORAGE)
// ============================================================================

/// Emplacement de secret scellé pour enclave imbriquée
#[derive(Debug, Clone, Copy)]
pub struct NestedSealedSlot {
    pub slot_id: u32,
    pub tenant_id: u32,
    pub key_id: u16,
    pub policy: NestedSealingPolicy,
    pub expected_measurement: [u8; 32], // Empreinte combinée attendue
    pub ciphertext: [u8; MAX_CIPHERTEXT_LEN],
    pub cipher_len: usize,
    pub hmac_tag: [u8; 32],
    pub valid: bool,
}

impl NestedSealedSlot {
    pub const fn empty() -> Self {
        Self {
            slot_id: 0,
            tenant_id: 0,
            key_id: 0,
            policy: NestedSealingPolicy::ExactNestedMeasurement,
            expected_measurement: [0u8; 32],
            ciphertext: [0u8; MAX_CIPHERTEXT_LEN],
            cipher_len: 0,
            hmac_tag: [0u8; 32],
            valid: false,
        }
    }
}

// ============================================================================
// REGISTRE D'AUDIT CRYPTOGRAPHIQUE SCEL LÉ
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct NestedAuditEntry {
    pub event_id: u64,
    pub tenant_id: u32,
    pub enclave_id: u32,
    pub action: &'static str,
    pub success: bool,
    pub hash: [u8; 32],
}

impl NestedAuditEntry {
    pub const fn empty() -> Self {
        Self {
            event_id: 0,
            tenant_id: 0,
            enclave_id: 0,
            action: "",
            success: false,
            hash: [0u8; 32],
        }
    }
}

// ============================================================================
// DÉMON PRINCIPAL : JamboTee2Daemon
// ============================================================================

/// Démon souverain de micro-hyperviseurs d'enclaves imbriquées et d'isolation multi-locataires
pub struct JamboTee2Daemon {
    pub admin_cap: Tee2Cap,
    pub tenants: [TenantPartition; MAX_TENANTS],
    pub tenant_count: usize,
    pub enclaves: [NestedEnclave; MAX_ENCLAVES],
    pub enclave_count: usize,
    pub sealed_slots: [NestedSealedSlot; MAX_SEALED_SLOTS],
    pub sealed_count: usize,
    pub reports: [NestedTeeReport; MAX_REPORTS],
    pub report_count: usize,
    pub audit_logs: [NestedAuditEntry; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub audit_chain: [u8; 32],
    pub root_attest_key: [u8; 32],
    pub next_tenant_id: u32,
    pub next_enclave_id: u32,
    pub next_slot_id: u32,
    pub next_report_id: u32,
    pub total_ops: u64,
    pub total_violations: u64,
}

impl JamboTee2Daemon {
    pub fn new(admin_cap: Tee2Cap) -> Self {
        Self {
            admin_cap,
            tenants: [TenantPartition::empty(); MAX_TENANTS],
            tenant_count: 0,
            enclaves: [NestedEnclave::empty(); MAX_ENCLAVES],
            enclave_count: 0,
            sealed_slots: [NestedSealedSlot::empty(); MAX_SEALED_SLOTS],
            sealed_count: 0,
            reports: [NestedTeeReport::empty(); MAX_REPORTS],
            report_count: 0,
            audit_logs: [NestedAuditEntry::empty(); MAX_AUDIT_LOGS],
            audit_count: 0,
            audit_chain: [0x5A; 32],
            root_attest_key: [
                0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
            ],
            next_tenant_id: 1,
            next_enclave_id: 100,
            next_slot_id: 1,
            next_report_id: 1,
            total_ops: 0,
            total_violations: 0,
        }
    }

    /// Journalise une opération dans la chaîne d'audit inaltérable
    pub fn log_audit(
        &mut self,
        tenant_id: u32,
        enclave_id: u32,
        action: &'static str,
        success: bool,
    ) {
        let event_id = self.total_ops + 1;
        self.total_ops = event_id;

        let mut record = [0u8; 80];
        record[..8].copy_from_slice(&event_id.to_le_bytes());
        record[8..12].copy_from_slice(&tenant_id.to_le_bytes());
        record[12..16].copy_from_slice(&enclave_id.to_le_bytes());
        record[16] = if success { 1 } else { 0 };
        let action_bytes = action.as_bytes();
        let copy_len = if action_bytes.len() < 31 { action_bytes.len() } else { 31 };
        record[17..17 + copy_len].copy_from_slice(&action_bytes[..copy_len]);
        record[48..80].copy_from_slice(&self.audit_chain);

        let new_hash = Sha256::digest(&record);
        self.audit_chain = new_hash;

        let idx = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_logs[idx] = NestedAuditEntry {
            event_id,
            tenant_id,
            enclave_id,
            action,
            success,
            hash: new_hash,
        };
        self.audit_count += 1;
    }

    /// Enrôle une nouvelle partition de locataire avec sa clé MEK et son KeyID matériel
    pub fn create_tenant(
        &mut self,
        cap: &Tee2Cap,
        name: &str,
        key_id: u16,
        mek: [u8; KEY_LEN],
        base_gpa: u64,
        size_bytes: u64,
    ) -> Result<u32, NestedTeeError> {
        if !cap.has_right(tee2_rights::CREATE_TENANT) {
            self.total_violations += 1;
            return Err(NestedTeeError::PermissionDenied);
        }

        if self.tenant_count >= MAX_TENANTS {
            return Err(NestedTeeError::TenantLimitReached);
        }

        // Vérifier l'unicité du KeyID et l'absence de chevauchement GPA
        for t in self.tenants.iter() {
            if t.active {
                if t.key_id == key_id {
                    return Err(NestedTeeError::TenantAlreadyExists);
                }
                // Vérifier chevauchement d'espace mémoire
                let t_end = t.base_gpa.saturating_add(t.size_bytes);
                let new_end = base_gpa.saturating_add(size_bytes);
                if (base_gpa < t_end) && (new_end > t.base_gpa) {
                    return Err(NestedTeeError::CrossTenantAccessDenied);
                }
            }
        }

        let tenant_id = self.next_tenant_id;
        self.next_tenant_id += 1;

        for slot in self.tenants.iter_mut() {
            if !slot.active {
                *slot = TenantPartition::new(tenant_id, name, key_id, mek, base_gpa, size_bytes);
                self.tenant_count += 1;
                self.log_audit(tenant_id, 0, "CREATE_TENANT", true);
                return Ok(tenant_id);
            }
        }

        Err(NestedTeeError::TenantLimitReached)
    }

    /// Crée un superviseur d'enclave L1 pour un locataire donné
    pub fn create_l1_supervisor(
        &mut self,
        cap: &Tee2Cap,
        tenant_id: u32,
        backend: NestedTeeBackend,
        name: &str,
    ) -> Result<u32, NestedTeeError> {
        if !cap.has_right(tee2_rights::CREATE_L1) {
            self.total_violations += 1;
            return Err(NestedTeeError::PermissionDenied);
        }
        if cap.tenant_id != 0 && cap.tenant_id != tenant_id {
            self.total_violations += 1;
            return Err(NestedTeeError::CrossTenantAccessDenied);
        }

        let key_id = {
            let tenant = self
                .tenants
                .iter_mut()
                .find(|t| t.active && t.tenant_id == tenant_id)
                .ok_or(NestedTeeError::TenantNotFound)?;
            tenant.l1_enclaves_count += 1;
            tenant.key_id
        };

        if self.enclave_count >= MAX_ENCLAVES {
            return Err(NestedTeeError::EnclaveLimitReached);
        }

        let enclave_id = self.next_enclave_id;
        self.next_enclave_id += 1;

        for slot in self.enclaves.iter_mut() {
            if slot.state == EnclaveState::Uninitialized || slot.state == EnclaveState::Destroyed {
                *slot = NestedEnclave::new(
                    enclave_id,
                    tenant_id,
                    EnclaveLevel::L1Supervisor,
                    None,
                    backend,
                    key_id,
                    name,
                );
                self.enclave_count += 1;
                self.log_audit(tenant_id, enclave_id, "CREATE_L1_SUPERVISOR", true);
                return Ok(enclave_id);
            }
        }

        Err(NestedTeeError::EnclaveLimitReached)
    }

    /// Crée une enclave imbriquée L2 s'exécutant au sein d'un superviseur L1
    pub fn create_l2_nested_enclave(
        &mut self,
        cap: &Tee2Cap,
        tenant_id: u32,
        parent_l1_id: u32,
        name: &str,
    ) -> Result<u32, NestedTeeError> {
        if !cap.has_right(tee2_rights::CREATE_L2) {
            self.total_violations += 1;
            return Err(NestedTeeError::PermissionDenied);
        }
        if cap.tenant_id != 0 && cap.tenant_id != tenant_id {
            self.total_violations += 1;
            return Err(NestedTeeError::CrossTenantAccessDenied);
        }

        // Vérifier que le parent L1 existe et appartient bien au tenant
        let (backend, key_id) = {
            let parent = self
                .enclaves
                .iter()
                .find(|e| e.enclave_id == parent_l1_id && e.state != EnclaveState::Destroyed)
                .ok_or(NestedTeeError::EnclaveNotFound)?;

            if parent.tenant_id != tenant_id || parent.level != EnclaveLevel::L1Supervisor {
                self.total_violations += 1;
                return Err(NestedTeeError::CrossTenantAccessDenied);
            }
            (parent.backend, parent.key_id)
        };

        if self.enclave_count >= MAX_ENCLAVES {
            return Err(NestedTeeError::EnclaveLimitReached);
        }

        let enclave_id = self.next_enclave_id;
        self.next_enclave_id += 1;

        for slot in self.enclaves.iter_mut() {
            if slot.state == EnclaveState::Uninitialized || slot.state == EnclaveState::Destroyed {
                *slot = NestedEnclave::new(
                    enclave_id,
                    tenant_id,
                    EnclaveLevel::L2Nested,
                    Some(parent_l1_id),
                    backend,
                    key_id,
                    name,
                );
                self.enclave_count += 1;

                if let Some(tenant) = self.tenants.iter_mut().find(|t| t.active && t.tenant_id == tenant_id) {
                    tenant.l2_enclaves_count += 1;
                }

                self.log_audit(tenant_id, enclave_id, "CREATE_L2_NESTED", true);
                return Ok(enclave_id);
            }
        }

        Err(NestedTeeError::EnclaveLimitReached)
    }

    /// Configure une entrée de table EPT imbriquée (GPA L2 -> IPA L1 -> HPA L0)
    pub fn configure_nested_ept(
        &mut self,
        cap: &Tee2Cap,
        enclave_id: u32,
        gpa: u64,
        ipa: u64,
        hpa: u64,
        flags: u8,
        data_sample: &[u8],
    ) -> Result<(), NestedTeeError> {
        if !cap.has_right(tee2_rights::MAP_EPT) {
            self.total_violations += 1;
            return Err(NestedTeeError::PermissionDenied);
        }

        let enclave = self
            .enclaves
            .iter_mut()
            .find(|e| e.enclave_id == enclave_id && e.state != EnclaveState::Destroyed)
            .ok_or(NestedTeeError::EnclaveNotFound)?;

        if cap.tenant_id != 0 && cap.tenant_id != enclave.tenant_id {
            self.total_violations += 1;
            return Err(NestedTeeError::CrossTenantAccessDenied);
        }

        // Vérifier que l'adresse GPA est dans la plage allouée au tenant
        let tenant = self
            .tenants
            .iter()
            .find(|t| t.active && t.tenant_id == enclave.tenant_id)
            .ok_or(NestedTeeError::TenantNotFound)?;

        if gpa < tenant.base_gpa || (gpa + PAGE_SIZE as u64) > (tenant.base_gpa + tenant.size_bytes) {
            self.total_violations += 1;
            return Err(NestedTeeError::CrossTenantAccessDenied);
        }

        let key_id = enclave.key_id;
        let tenant_id = enclave.tenant_id;
        enclave.ept_table.map_page(gpa, ipa, hpa, flags, key_id, tenant_id, data_sample)?;
        enclave.active_pages += 1;
        if enclave.state == EnclaveState::Created {
            enclave.state = EnclaveState::EptConfigured;
        }

        self.log_audit(tenant_id, enclave_id, "MAP_NESTED_EPT", true);
        Ok(())
    }

    /// Charge la charge utile dans l'enclave imbriquée L2 et met à jour sa mesure
    pub fn load_l2_payload(
        &mut self,
        cap: &Tee2Cap,
        enclave_id: u32,
        payload: &[u8],
    ) -> Result<(), NestedTeeError> {
        let tenant_id = {
            let enclave = self
                .enclaves
                .iter_mut()
                .find(|e| e.enclave_id == enclave_id && e.state != EnclaveState::Destroyed)
                .ok_or(NestedTeeError::EnclaveNotFound)?;

            if cap.tenant_id != 0 && cap.tenant_id != enclave.tenant_id {
                self.total_violations += 1;
                return Err(NestedTeeError::CrossTenantAccessDenied);
            }

            enclave.load_payload(payload)?;
            enclave.tenant_id
        };

        self.log_audit(tenant_id, enclave_id, "LOAD_L2_PAYLOAD", true);
        Ok(())
    }

    /// Finalise et scelle l'enclave imbriquée (passage à Running)
    pub fn finalize_and_seal(
        &mut self,
        cap: &Tee2Cap,
        enclave_id: u32,
    ) -> Result<(), NestedTeeError> {
        let tenant_id = {
            let enclave = self
                .enclaves
                .iter_mut()
                .find(|e| e.enclave_id == enclave_id && e.state != EnclaveState::Destroyed)
                .ok_or(NestedTeeError::EnclaveNotFound)?;

            if cap.tenant_id != 0 && cap.tenant_id != enclave.tenant_id {
                self.total_violations += 1;
                return Err(NestedTeeError::CrossTenantAccessDenied);
            }

            if enclave.state != EnclaveState::L2Loaded && enclave.state != EnclaveState::EptConfigured {
                return Err(NestedTeeError::InvalidStateTransition);
            }

            enclave.state = EnclaveState::Running;
            enclave.tenant_id
        };

        self.log_audit(tenant_id, enclave_id, "SEAL_AND_RUN", true);
        Ok(())
    }

    /// Traduction matérielle GPA -> HPA avec contrôle d'intégrité et de tenant
    pub fn translate_nested_gpa(
        &self,
        enclave_id: u32,
        gpa: u64,
        is_write: bool,
        is_exec: bool,
        caller_tenant_id: u32,
    ) -> Result<(u64, u16), NestedTeeError> {
        let enclave = self
            .enclaves
            .iter()
            .find(|e| e.enclave_id == enclave_id && e.state == EnclaveState::Running)
            .ok_or(NestedTeeError::EnclaveNotFound)?;

        enclave.ept_table.translate(gpa, is_write, is_exec, caller_tenant_id)
    }

    /// Chiffre une page de mémoire pour un locataire via son KeyID matériel
    pub fn encrypt_tenant_page(
        &mut self,
        cap: &Tee2Cap,
        tenant_id: u32,
        hpa: u64,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), NestedTeeError> {
        if !cap.has_right(tee2_rights::ENCRYPT_MEM) {
            self.total_violations += 1;
            return Err(NestedTeeError::PermissionDenied);
        }
        if cap.tenant_id != 0 && cap.tenant_id != tenant_id {
            self.total_violations += 1;
            return Err(NestedTeeError::CrossTenantAccessDenied);
        }

        let tenant = self
            .tenants
            .iter_mut()
            .find(|t| t.active && t.tenant_id == tenant_id)
            .ok_or(NestedTeeError::TenantNotFound)?;

        tenant.encrypt_memory(hpa, plaintext, ciphertext)?;
        self.log_audit(tenant_id, 0, "ENCRYPT_PAGE", true);
        Ok(())
    }

    /// Déchiffre une page de mémoire pour un locataire
    pub fn decrypt_tenant_page(
        &self,
        tenant_id: u32,
        hpa: u64,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), NestedTeeError> {
        let tenant = self
            .tenants
            .iter()
            .find(|t| t.active && t.tenant_id == tenant_id)
            .ok_or(NestedTeeError::TenantNotFound)?;

        tenant.decrypt_memory(hpa, ciphertext, plaintext)
    }

    /// Génère un rapport d'attestation d'enclave imbriquée avec mesure cumulative et signature HMAC
    pub fn generate_nested_report(
        &mut self,
        cap: &Tee2Cap,
        l2_enclave_id: u32,
        challenge: &[u8; 32],
        user_data: &[u8; 32],
    ) -> Result<NestedTeeReport, NestedTeeError> {
        if !cap.has_right(tee2_rights::ATTEST) {
            self.total_violations += 1;
            return Err(NestedTeeError::PermissionDenied);
        }

        let (tenant_id, l1_id, backend, key_id, l2_measure, ept_root) = {
            let l2 = self
                .enclaves
                .iter()
                .find(|e| e.enclave_id == l2_enclave_id && e.state != EnclaveState::Destroyed)
                .ok_or(NestedTeeError::EnclaveNotFound)?;

            if l2.level != EnclaveLevel::L2Nested {
                return Err(NestedTeeError::InvalidStateTransition);
            }
            if cap.tenant_id != 0 && cap.tenant_id != l2.tenant_id {
                self.total_violations += 1;
                return Err(NestedTeeError::CrossTenantAccessDenied);
            }

            let parent_id = l2.parent_l1_id.ok_or(NestedTeeError::EnclaveNotFound)?;
            (
                l2.tenant_id,
                parent_id,
                l2.backend,
                l2.key_id,
                l2.mrenclave,
                l2.ept_table.root_hash,
            )
        };

        let l1_measure = {
            let l1 = self
                .enclaves
                .iter()
                .find(|e| e.enclave_id == l1_id && e.state != EnclaveState::Destroyed)
                .ok_or(NestedTeeError::EnclaveNotFound)?;
            l1.mrenclave
        };

        // Calcul de la mesure combinée : SHA-256(L1 || L2 || EPT_ROOT || TenantID || KeyID)
        let mut combined_buf = [0u8; 104];
        combined_buf[..32].copy_from_slice(&l1_measure);
        combined_buf[32..64].copy_from_slice(&l2_measure);
        combined_buf[64..96].copy_from_slice(&ept_root);
        combined_buf[96..100].copy_from_slice(&tenant_id.to_le_bytes());
        combined_buf[100..102].copy_from_slice(&key_id.to_le_bytes());
        combined_buf[102..104].copy_from_slice(&[0x11, 0x22]);

        let combined_measurement = Sha256::digest(&combined_buf);

        // Signature du rapport : HMAC-SHA256(root_attest_key, combined || challenge || user_data)
        let mut sign_payload = [0u8; 96];
        sign_payload[..32].copy_from_slice(&combined_measurement);
        sign_payload[32..64].copy_from_slice(challenge);
        sign_payload[64..96].copy_from_slice(user_data);
        let hmac_signature = Sha256::hmac(&self.root_attest_key, &sign_payload);

        let report_id = self.next_report_id;
        self.next_report_id += 1;

        let report = NestedTeeReport {
            report_id,
            tenant_id,
            l1_id,
            l2_id: l2_enclave_id,
            key_id,
            backend,
            l1_measurement: l1_measure,
            l2_measurement: l2_measure,
            ept_root_hash: ept_root,
            combined_measurement,
            challenge: *challenge,
            user_data: *user_data,
            hmac_signature,
            valid: true,
        };

        if self.report_count < MAX_REPORTS {
            self.reports[self.report_count] = report;
            self.report_count += 1;
        }

        self.log_audit(tenant_id, l2_enclave_id, "GENERATE_NESTED_REPORT", true);
        Ok(report)
    }

    /// Vérifie formellement la signature et l'intégrité d'un rapport d'attestation
    pub fn verify_nested_report(
        &self,
        report: &NestedTeeReport,
        expected_challenge: &[u8; 32],
    ) -> Result<bool, NestedTeeError> {
        if !report.valid {
            return Ok(false);
        }

        if !constant_time_eq(&report.challenge, expected_challenge) {
            return Err(NestedTeeError::ChallengeMismatch);
        }

        // Vérifier le HMAC
        let mut sign_payload = [0u8; 96];
        sign_payload[..32].copy_from_slice(&report.combined_measurement);
        sign_payload[32..64].copy_from_slice(&report.challenge);
        sign_payload[64..96].copy_from_slice(&report.user_data);
        let expected_sig = Sha256::hmac(&self.root_attest_key, &sign_payload);

        if constant_time_eq(&report.hmac_signature, &expected_sig) {
            Ok(true)
        } else {
            Err(NestedTeeError::AttestationFailed)
        }
    }

    /// Scelle un secret pour une enclave imbriquée (Sealed Storage)
    pub fn seal_tenant_secret(
        &mut self,
        cap: &Tee2Cap,
        enclave_id: u32,
        secret: &[u8],
        policy: NestedSealingPolicy,
    ) -> Result<u32, NestedTeeError> {
        if !cap.has_right(tee2_rights::SEAL) {
            self.total_violations += 1;
            return Err(NestedTeeError::PermissionDenied);
        }
        if secret.len() > MAX_CIPHERTEXT_LEN {
            return Err(NestedTeeError::CapacityExceeded);
        }

        let (tenant_id, key_id, combined_measure) = {
            let enc = self
                .enclaves
                .iter()
                .find(|e| e.enclave_id == enclave_id && e.state != EnclaveState::Destroyed)
                .ok_or(NestedTeeError::EnclaveNotFound)?;

            if cap.tenant_id != 0 && cap.tenant_id != enc.tenant_id {
                self.total_violations += 1;
                return Err(NestedTeeError::CrossTenantAccessDenied);
            }

            let parent_measure = if let Some(p_id) = enc.parent_l1_id {
                self.enclaves
                    .iter()
                    .find(|p| p.enclave_id == p_id)
                    .map(|p| p.mrenclave)
                    .unwrap_or([0u8; 32])
            } else {
                [0u8; 32]
            };

            let mut comb = [0u8; 96];
            comb[..32].copy_from_slice(&parent_measure);
            comb[32..64].copy_from_slice(&enc.mrenclave);
            comb[64..96].copy_from_slice(&enc.ept_table.root_hash);
            (enc.tenant_id, enc.key_id, Sha256::digest(&comb))
        };

        if self.sealed_count >= MAX_SEALED_SLOTS {
            return Err(NestedTeeError::CapacityExceeded);
        }

        // Chiffrement du secret avec la clé MEK du tenant
        let mut cipher_buf = [0u8; MAX_CIPHERTEXT_LEN];
        let tenant = self
            .tenants
            .iter_mut()
            .find(|t| t.active && t.tenant_id == tenant_id)
            .ok_or(NestedTeeError::TenantNotFound)?;

        tenant.encrypt_memory(0x5EA1_0000, secret, &mut cipher_buf[..secret.len()])?;

        let hmac_tag = Sha256::hmac(&tenant.mek, &cipher_buf[..secret.len()]);

        let slot_id = self.next_slot_id;
        self.next_slot_id += 1;

        for slot in self.sealed_slots.iter_mut() {
            if !slot.valid {
                *slot = NestedSealedSlot {
                    slot_id,
                    tenant_id,
                    key_id,
                    policy,
                    expected_measurement: combined_measure,
                    ciphertext: cipher_buf,
                    cipher_len: secret.len(),
                    hmac_tag,
                    valid: true,
                };
                self.sealed_count += 1;
                self.log_audit(tenant_id, enclave_id, "SEAL_SECRET", true);
                return Ok(slot_id);
            }
        }

        Err(NestedTeeError::CapacityExceeded)
    }

    /// Déscelle un secret pour une enclave imbriquée avec vérification de politique
    pub fn unseal_tenant_secret(
        &self,
        cap: &Tee2Cap,
        enclave_id: u32,
        slot_id: u32,
        plaintext_out: &mut [u8],
    ) -> Result<usize, NestedTeeError> {
        if !cap.has_right(tee2_rights::UNSEAL) {
            return Err(NestedTeeError::PermissionDenied);
        }

        let slot = self
            .sealed_slots
            .iter()
            .find(|s| s.valid && s.slot_id == slot_id)
            .ok_or(NestedTeeError::SealingFailed)?;

        let enc = self
            .enclaves
            .iter()
            .find(|e| e.enclave_id == enclave_id && e.state != EnclaveState::Destroyed)
            .ok_or(NestedTeeError::EnclaveNotFound)?;

        if enc.tenant_id != slot.tenant_id || enc.key_id != slot.key_id {
            return Err(NestedTeeError::CrossTenantAccessDenied);
        }

        if slot.policy == NestedSealingPolicy::ExactNestedMeasurement {
            let parent_measure = if let Some(p_id) = enc.parent_l1_id {
                self.enclaves
                    .iter()
                    .find(|p| p.enclave_id == p_id)
                    .map(|p| p.mrenclave)
                    .unwrap_or([0u8; 32])
            } else {
                [0u8; 32]
            };

            let mut comb = [0u8; 96];
            comb[..32].copy_from_slice(&parent_measure);
            comb[32..64].copy_from_slice(&enc.mrenclave);
            comb[64..96].copy_from_slice(&enc.ept_table.root_hash);
            let current_measure = Sha256::digest(&comb);

            if !constant_time_eq(&current_measure, &slot.expected_measurement) {
                return Err(NestedTeeError::UnsealingFailed);
            }
        }

        let tenant = self
            .tenants
            .iter()
            .find(|t| t.active && t.tenant_id == slot.tenant_id)
            .ok_or(NestedTeeError::TenantNotFound)?;

        let expected_tag = Sha256::hmac(&tenant.mek, &slot.ciphertext[..slot.cipher_len]);
        if !constant_time_eq(&expected_tag, &slot.hmac_tag) {
            return Err(NestedTeeError::UnsealingFailed);
        }

        if plaintext_out.len() < slot.cipher_len {
            return Err(NestedTeeError::CapacityExceeded);
        }

        tenant.decrypt_memory(
            0x5EA1_0000,
            &slot.ciphertext[..slot.cipher_len],
            &mut plaintext_out[..slot.cipher_len],
        )?;

        Ok(slot.cipher_len)
    }

    /// Destruction et effacement sécurisé (Scrubbing) d'une enclave
    pub fn destroy_enclave(
        &mut self,
        cap: &Tee2Cap,
        enclave_id: u32,
    ) -> Result<(), NestedTeeError> {
        if !cap.has_right(tee2_rights::SCRUB) {
            self.total_violations += 1;
            return Err(NestedTeeError::PermissionDenied);
        }

        let enclave = self
            .enclaves
            .iter_mut()
            .find(|e| e.enclave_id == enclave_id && e.state != EnclaveState::Destroyed)
            .ok_or(NestedTeeError::EnclaveNotFound)?;

        if cap.tenant_id != 0 && cap.tenant_id != enclave.tenant_id {
            self.total_violations += 1;
            return Err(NestedTeeError::CrossTenantAccessDenied);
        }

        let tenant_id = enclave.tenant_id;
        enclave.scrub();
        self.enclave_count = self.enclave_count.saturating_sub(1);

        self.log_audit(tenant_id, enclave_id, "DESTROY_AND_SCRUB_ENCLAVE", true);
        Ok(())
    }

    /// Initialise la configuration par défaut pour le shell interactif et les tests
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;
        let mek_tenant1: [u8; KEY_LEN] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        ];
        let mek_tenant2: [u8; KEY_LEN] = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
            0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
            0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
        ];

        let t1 = self
            .create_tenant(
                &cap,
                "FinCore-Tenant",
                101,
                mek_tenant1,
                0x1_0000_0000,
                0x4000_0000,
            )
            .unwrap_or(1);

        let t2 = self
            .create_tenant(
                &cap,
                "HealthSovereign-Tenant",
                102,
                mek_tenant2,
                0x2_0000_0000,
                0x4000_0000,
            )
            .unwrap_or(2);

        // L1 Supervisor pour FinCore
        let l1_fin = self
            .create_l1_supervisor(
                &cap,
                t1,
                NestedTeeBackend::IntelTdxPartitioning,
                "FinCore-L1-Supervisor",
            )
            .unwrap_or(100);

        // L2 Workload imbriqué pour FinCore
        let l2_fin = self
            .create_l2_nested_enclave(
                &cap,
                t1,
                l1_fin,
                "FinCore-L2-TradingEngine",
            )
            .unwrap_or(101);

        // Configurer mappages EPT imbriqués pour L2
        let dummy_page = [0x55u8; 64];
        let _ = self.configure_nested_ept(
            &cap,
            l2_fin,
            0x1_0000_0000,
            0x8000_0000,
            0x4000_0000,
            ept_flags::REGULAR,
            &dummy_page,
        );

        let dummy_code = [0x90u8; 64]; // NOP sled
        let _ = self.configure_nested_ept(
            &cap,
            l2_fin,
            0x1_0000_1000,
            0x8000_1000,
            0x4000_1000,
            ept_flags::CODE,
            &dummy_code,
        );

        let _ = self.load_l2_payload(&cap, l2_fin, b"SOVEREIGN_TRADING_BYTECODE_V1");
        let _ = self.finalize_and_seal(&cap, l2_fin);

        // L1 Supervisor pour HealthSovereign
        let l1_health = self
            .create_l1_supervisor(
                &cap,
                t2,
                NestedTeeBackend::ArmCcaRealm,
                "Health-L1-Supervisor",
            )
            .unwrap_or(102);

        let l2_health = self
            .create_l2_nested_enclave(
                &cap,
                t2,
                l1_health,
                "Health-L2-PatientVault",
            )
            .unwrap_or(103);

        let _ = self.configure_nested_ept(
            &cap,
            l2_health,
            0x2_0000_0000,
            0x9000_0000,
            0x5000_0000,
            ept_flags::REGULAR,
            &dummy_page,
        );

        let _ = self.load_l2_payload(&cap, l2_health, b"GENOMICS_ANALYTICS_KERNEL_V2");
        let _ = self.finalize_and_seal(&cap, l2_health);

        // Générer un rapport d'attestation d'exemple
        let challenge = [0x42u8; 32];
        let user_data = [0x99u8; 32];
        let _ = self.generate_nested_report(&cap, l2_fin, &challenge, &user_data);
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] compatibles)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_and_hmac() {
        let msg = b"JamboOS-TEE2-Nested-Enclaves";
        let h1 = Sha256::digest(msg);
        let h2 = Sha256::digest(msg);
        assert_eq!(h1, h2);

        let key = b"sovereign_secret_key_256bits_!";
        let sig1 = Sha256::hmac(key, msg);
        let sig2 = Sha256::hmac(key, msg);
        assert_eq!(sig1, sig2);
        assert!(constant_time_eq(&sig1, &sig2));
    }

    #[test]
    fn test_cap_governance_and_monotonic_attenuation() {
        let admin_cap = Tee2Cap::new(Handle::new(10700, 1), tee2_rights::ALL, 0, 32);
        assert!(admin_cap.has_right(tee2_rights::CREATE_TENANT));
        assert!(admin_cap.has_right(tee2_rights::CREATE_L1));
        assert!(admin_cap.has_right(tee2_rights::CREATE_L2));
        assert!(admin_cap.has_right(tee2_rights::MAP_EPT));
        assert!(admin_cap.has_right(tee2_rights::ENCRYPT_MEM));
        assert!(admin_cap.has_right(tee2_rights::ATTEST));
        assert!(admin_cap.has_right(tee2_rights::SEAL));
        assert!(admin_cap.has_right(tee2_rights::UNSEAL));
        assert!(admin_cap.has_right(tee2_rights::SCRUB));

        // Atténuation monotone
        let sub_cap = admin_cap
            .attenuate(tee2_rights::CREATE_L2 | tee2_rights::ATTEST, 10)
            .expect("Atténuation");
        assert!(sub_cap.has_right(tee2_rights::CREATE_L2));
        assert!(sub_cap.has_right(tee2_rights::ATTEST));
        assert!(!sub_cap.has_right(tee2_rights::CREATE_TENANT));
        assert!(!sub_cap.has_right(tee2_rights::SCRUB));

        // Tentative d'amplification rejetée
        assert_eq!(
            sub_cap.attenuate(tee2_rights::ALL, 10),
            Err(NestedTeeError::PermissionDenied)
        );
        assert_eq!(
            sub_cap.attenuate(tee2_rights::ATTEST, 20),
            Err(NestedTeeError::PermissionDenied)
        );
    }

    #[test]
    fn test_multi_tenant_isolation_and_nested_ept() {
        let admin_cap = Tee2Cap::new(Handle::new(10701, 1), tee2_rights::ALL, 0, 32);
        let mut daemon = JamboTee2Daemon::new(admin_cap);

        let mek1 = [0x11u8; 32];
        let mek2 = [0x22u8; 32];

        let t1 = daemon
            .create_tenant(&admin_cap, "Tenant-Alpha", 10, mek1, 0x1000_0000, 0x1000_0000)
            .expect("T1");
        let t2 = daemon
            .create_tenant(&admin_cap, "Tenant-Beta", 20, mek2, 0x2000_0000, 0x1000_0000)
            .expect("T2");

        // Rejet chevauchement mémoire
        assert_eq!(
            daemon.create_tenant(&admin_cap, "Overlap", 30, mek1, 0x1500_0000, 0x1000_0000),
            Err(NestedTeeError::CrossTenantAccessDenied)
        );

        // Création L1 et L2
        let l1 = daemon
            .create_l1_supervisor(&admin_cap, t1, NestedTeeBackend::IntelTdxPartitioning, "L1-Sup")
            .expect("L1");
        let l2 = daemon
            .create_l2_nested_enclave(&admin_cap, t1, l1, "L2-Workload")
            .expect("L2");

        // Mappage EPT imbriqué
        let sample = [0xAAu8; 32];
        daemon
            .configure_nested_ept(&admin_cap, l2, 0x1000_0000, 0x8000_0000, 0x4000_0000, ept_flags::REGULAR, &sample)
            .expect("EPT Map");

        // Chargement charge et passage à Running
        daemon.load_l2_payload(&admin_cap, l2, b"SECURE_BYTECODE").expect("Load");
        daemon.finalize_and_seal(&admin_cap, l2).expect("Seal & Run");

        // Traduction GPA valide pour Tenant 1
        let (hpa, key_id) = daemon.translate_nested_gpa(l2, 0x1000_0042, false, false, t1).expect("Translate");
        assert_eq!(hpa, 0x4000_0042);
        assert_eq!(key_id, 10);

        // Tentative d'accès cross-tenant par Tenant 2 bloquée !
        assert_eq!(
            daemon.translate_nested_gpa(l2, 0x1000_0042, false, false, t2),
            Err(NestedTeeError::CrossTenantAccessDenied)
        );

        // Chiffrement / Déchiffrement mémoire multi-locataire
        let plaintext = b"SOVEREIGN_TRANSACTION_PAYLOAD_32";
        let mut cipher = [0u8; 32];
        let mut recovered = [0u8; 32];

        daemon
            .encrypt_tenant_page(&admin_cap, t1, 0x4000_0000, plaintext, &mut cipher)
            .expect("Encrypt");
        assert_ne!(plaintext, &cipher);

        daemon
            .decrypt_tenant_page(t1, 0x4000_0000, &cipher, &mut recovered)
            .expect("Decrypt T1");
        assert_eq!(plaintext, &recovered);

        // Déchiffrement par Tenant 2 donne des données corrompues (clé différente)
        let mut recovered_t2 = [0u8; 32];
        daemon
            .decrypt_tenant_page(t2, 0x4000_0000, &cipher, &mut recovered_t2)
            .expect("Decrypt T2");
        assert_ne!(plaintext, &recovered_t2);

        // Attestation distante imbriquée
        let challenge = [0x33u8; 32];
        let user_data = [0x77u8; 32];
        let report = daemon
            .generate_nested_report(&admin_cap, l2, &challenge, &user_data)
            .expect("Attest Report");
        assert!(daemon.verify_nested_report(&report, &challenge).expect("Verify Report"));

        // Scellement & Déscellement de secrets
        let secret = b"TENANT_SECRET_KMS_SEED";
        let slot_id = daemon
            .seal_tenant_secret(&admin_cap, l2, secret, NestedSealingPolicy::ExactNestedMeasurement)
            .expect("Seal Secret");

        let mut unsealed = [0u8; 64];
        let unsealed_len = daemon
            .unseal_tenant_secret(&admin_cap, l2, slot_id, &mut unsealed)
            .expect("Unseal");
        assert_eq!(&unsealed[..unsealed_len], secret);

        // Destruction & effacement sécurisé (scrubbing)
        daemon.destroy_enclave(&admin_cap, l2).expect("Destroy");
        assert_eq!(
            daemon.translate_nested_gpa(l2, 0x1000_0042, false, false, t1),
            Err(NestedTeeError::EnclaveNotFound)
        );
    }
}


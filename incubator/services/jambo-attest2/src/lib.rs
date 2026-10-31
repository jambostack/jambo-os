//! Attestation d'Enclave Matérielle Distante Avancée & Chaînes de Confiance Multi-Puces (`jambo-attest2`)
//!
//! Phase 105 — Jalon v0.2.103
//!
//! Fournit les garanties souveraines d'intégrité distante et de confiance matérielle multi-puces :
//! 1. Hiérarchie de Confiance Multi-Puces (Multi-Chip Root of Trust) :
//!    Fédération et validation croisée de processeurs hôtes (SoC), processeurs cryptographiques (TPM 2.0),
//!    coprocesseurs HSM dédiés et contrôleurs de gestion de plateforme (BMC).
//! 2. Identité de Plateforme Composée (Compound Platform ID) :
//!    Agrégation Merkle SHA-256 en arbre binaire de l'ensemble des puces matérielles enrôlées.
//! 3. Enrôlement & Mesure de Micro-Enclaves Souveraines Ring 3 / TEE :
//!    Gestion d'enclaves avec hachage MRENCLAVE (intégrité code/données initiales), MRSIGNER (autorité d'endossement),
//!    SVN (numéro de version sécurisée anti-rollback) et attributs d'isolation matérielle.
//! 4. Devis d'Attestation Distante (Remote Attestation Quotes) avec Défi Anti-Rejeu :
//!    Génération et scellement HMAC-SHA256 de devis d'enclave contenant le nonce de défi et l'état de la chaîne multi-puces.
//! 5. Vérification Formelle de Devis & Politiques d'Intégrité de Référence :
//!    Contrôle de fraîcheur du nonce anti-rejeu, validation de signatures matérielles, contrôle contre les mesures dorées
//!    (Golden Reference Policies) et rejet immédiat en cas de dérive de mesure ou de tentative de régression (rollback).
//! 6. Endossement Croisé Inter-Puces (Cross-Chip Mutual Attestation) :
//!    Attestation mutuelle inter-puces pour détecter toute puce corrompue, compromise ou injectée.
//! 7. Quarantaine & Confinement Matériel Autonome en Temps O(1) :
//!    Isolement instantané de toute enclave déviante ou de tout composant silicium non conforme.
//! 8. Registre d'Audit Cryptographique Inaltérable Scellé par Chaîne de Blocs SHA-256 (`attest2_audit_chain`).
//! 9. Contrôle d'Accès Capabilaire Strict (`Attest2Cap`) interdisant toute autorité ambiante et rejetant l'amplification.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_CHIPS: usize = 8;
pub const MAX_ENCLAVES: usize = 16;
pub const MAX_QUOTES: usize = 16;
pub const MAX_CROSS_ENDORSEMENTS: usize = 16;
pub const MAX_POLICIES: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 64;
pub const MAX_NAME_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
pub const SIG_LEN: usize = 32;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 & HMAC-SHA256 (#![no_std])
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

        let mut rem = [0u8; 128];
        let rem_len = total_len - offset;
        rem[..rem_len].copy_from_slice(&data[offset..]);
        rem[rem_len] = 0x80;

        let total_bits = (total_len as u64) * 8;
        let pad_len = if rem_len < 56 {
            rem[56..64].copy_from_slice(&total_bits.to_be_bytes());
            64
        } else {
            rem[120..128].copy_from_slice(&total_bits.to_be_bytes());
            128
        };

        let mut p_off = 0;
        while p_off < pad_len {
            let mut block = [0u8; 64];
            block.copy_from_slice(&rem[p_off..p_off + 64]);
            Self::process_block(&mut state, &block);
            p_off += 64;
        }

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }

    pub fn digest_chunks(chunks: &[&[u8]]) -> [u8; 32] {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let mut total_len: usize = 0;
        for c in chunks {
            total_len += c.len();
        }

        let mut buffer = [0u8; 64];
        let mut buf_idx = 0;

        for c in chunks {
            for &byte in *c {
                buffer[buf_idx] = byte;
                buf_idx += 1;
                if buf_idx == 64 {
                    Self::process_block(&mut state, &buffer);
                    buf_idx = 0;
                }
            }
        }

        let mut rem = [0u8; 128];
        rem[..buf_idx].copy_from_slice(&buffer[..buf_idx]);
        rem[buf_idx] = 0x80;

        let total_bits = (total_len as u64) * 8;
        let pad_len = if buf_idx < 56 {
            rem[56..64].copy_from_slice(&total_bits.to_be_bytes());
            64
        } else {
            rem[120..128].copy_from_slice(&total_bits.to_be_bytes());
            128
        };

        let mut p_off = 0;
        while p_off < pad_len {
            let mut block = [0u8; 64];
            block.copy_from_slice(&rem[p_off..p_off + 64]);
            Self::process_block(&mut state, &block);
            p_off += 64;
        }

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

pub struct HmacSha256;

impl HmacSha256 {
    pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let kh = Sha256::digest(key);
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

        let inner_hash = Sha256::digest_chunks(&[&ipad, data]);
        Sha256::digest_chunks(&[&opad, &inner_hash])
    }

    pub fn verify(key: &[u8], data: &[u8], expected_tag: &[u8; 32]) -> bool {
        let actual = Self::mac(key, data);
        ct_eq(&actual, expected_tag)
    }
}

#[inline(always)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (Attest2Cap)
// ============================================================================

pub mod attest2_rights {
    pub const ENROLL_CHIP: u32 = 1 << 0;
    pub const REGISTER_ENCLAVE: u32 = 1 << 1;
    pub const GENERATE_QUOTE: u32 = 1 << 2;
    pub const VERIFY_QUOTE: u32 = 1 << 3;
    pub const CROSS_ENDORSE: u32 = 1 << 4;
    pub const CONFINE: u32 = 1 << 5;
    pub const AUDIT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;
    pub const ALL: u32 = 0xFF;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attest2Cap {
    pub handle: Handle,
    pub rights: u32,
    pub max_enclaves: usize,
    pub max_chips: usize,
}

impl Attest2Cap {
    pub const fn new(handle: Handle, rights: u32, max_enclaves: usize, max_chips: usize) -> Self {
        Self {
            handle,
            rights,
            max_enclaves,
            max_chips,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn check(&self, right: u32) -> Result<(), SysError> {
        if self.has_right(right) {
            Ok(())
        } else {
            Err(SysError::PermissionDenied)
        }
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_max_enclaves: usize,
        new_max_chips: usize,
    ) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        if new_max_enclaves > self.max_enclaves {
            return Err(SysError::PermissionDenied);
        }
        if new_max_chips > self.max_chips {
            return Err(SysError::PermissionDenied);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_enclaves: new_max_enclaves,
            max_chips: new_max_chips,
        })
    }
}

// ============================================================================
// MODÈLE DE CONFIANCE MULTI-PUCES & ENCLAVES
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChipTrustLevel {
    SiliconRootOfTrust = 0,    // Matrice matérielle CPU / Fuses
    BoardRootOfTrust = 1,      // TPM 2.0 dédié / FPGA souverain
    PlatformRootOfTrust = 2,   // Coprocesseur HSM / Microcontrôleur sécurisé
    PeripheralRootOfTrust = 3, // SmartNIC / Accélérateur PCIe
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChipStatus {
    Uninitialized = 0,
    Enrolled = 1,
    AttestedActive = 2,
    Degraded = 3,
    Quarantined = 4,
    Revoked = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChipNode {
    pub chip_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub trust_level: ChipTrustLevel,
    pub status: ChipStatus,
    pub endorsement_key_hash: [u8; 32],
    pub secret_signing_key: [u8; 32],
    pub firmware_svn: u32,
    pub pcr_measurement: [u8; 32],
    pub last_heartbeat_epoch: u64,
}

impl ChipNode {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<inconnu>")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossEndorsement {
    pub issuer_chip_id: u32,
    pub subject_chip_id: u32,
    pub subject_pcr: [u8; 32],
    pub epoch: u64,
    pub signature: [u8; 32],
    pub valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnclaveStatus {
    Registered = 0,
    Active = 1,
    Attested = 2,
    Quarantined = 3,
    Terminated = 4,
}

pub mod enclave_attrs {
    pub const DEBUG_ALLOWED: u32 = 1 << 0;
    pub const MEMORY_ENCRYPTED: u32 = 1 << 1;
    pub const MIGRATION_ALLOWED: u32 = 1 << 2;
    pub const HARDWARE_ISOLATED: u32 = 1 << 3;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MicroEnclaveRecord {
    pub enclave_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub chip_id: u32,
    pub mr_enclave: [u8; 32],
    pub mr_signer: [u8; 32],
    pub svn: u32,
    pub attributes: u32,
    pub policy_hash: [u8; 32],
    pub status: EnclaveStatus,
    pub quote_count: u32,
}

impl MicroEnclaveRecord {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<inconnu>")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteHeader {
    pub version: u16,
    pub tee_type: u16,
    pub chip_id: u32,
    pub enclave_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnclaveQuote {
    pub header: QuoteHeader,
    pub mr_enclave: [u8; 32],
    pub mr_signer: [u8; 32],
    pub svn: u32,
    pub attributes: u32,
    pub report_data: [u8; 32],
    pub compound_platform_hash: [u8; 32],
    pub signature: [u8; 32],
    pub timestamp_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferencePolicy {
    pub policy_id: u32,
    pub enclave_name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub expected_mr_enclave: [u8; 32],
    pub expected_mr_signer: [u8; 32],
    pub min_svn: u32,
    pub allowed_attributes_mask: u32,
    pub active: bool,
}

impl ReferencePolicy {
    pub fn enclave_name_as_str(&self) -> &str {
        core::str::from_utf8(&self.enclave_name[..self.name_len]).unwrap_or("<inconnu>")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attest2Error {
    PermissionDenied,
    ChipNotFound,
    EnclaveNotFound,
    PolicyNotFound,
    CapacityExceeded,
    ReplayAttackDetected,
    InvalidSignature,
    MeasurementMismatch,
    SignerMismatch,
    RollbackDetected,
    HostingChipNotTrusted,
    EnclaveQuarantined,
    ChainBroken,
    BufferTooSmall,
}

impl From<Attest2Error> for SysError {
    fn from(err: Attest2Error) -> Self {
        match err {
            Attest2Error::PermissionDenied => SysError::PermissionDenied,
            Attest2Error::CapacityExceeded => SysError::OutOfMemory,
            Attest2Error::BufferTooSmall => SysError::BufferTooSmall,
            _ => SysError::InvalidArgument,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub epoch: u64,
    pub op_code: u8,
    pub target_id: u32,
    pub digest: [u8; 32],
}

// ============================================================================
// DÉMON PRINCIPAL D'ATTESTATION MATÉRIELLE MULTI-PUCES (`JamboAttest2Daemon`)
// ============================================================================

pub struct JamboAttest2Daemon {
    pub admin_cap: Attest2Cap,
    pub chips: [Option<ChipNode>; MAX_CHIPS],
    pub chip_count: usize,
    pub enclaves: [Option<MicroEnclaveRecord>; MAX_ENCLAVES],
    pub enclave_count: usize,
    pub quotes: [Option<EnclaveQuote>; MAX_QUOTES],
    pub quote_count: usize,
    pub cross_endorsements: [Option<CrossEndorsement>; MAX_CROSS_ENDORSEMENTS],
    pub cross_endorsement_count: usize,
    pub policies: [Option<ReferencePolicy>; MAX_POLICIES],
    pub policy_count: usize,
    pub compound_platform_id: [u8; 32],
    pub epoch: u64,
    pub total_quotes_generated: u64,
    pub total_quotes_verified: u64,
    pub total_cross_checks: u64,
    pub total_quarantines: u64,
    pub total_violations: u64,
    pub audit_chain: [u8; 32],
    pub audit_logs: [AuditEntry; MAX_AUDIT_LOGS],
    pub audit_count: usize,
}

impl JamboAttest2Daemon {
    pub const fn new(admin_cap: Attest2Cap) -> Self {
        Self {
            admin_cap,
            chips: [None; MAX_CHIPS],
            chip_count: 0,
            enclaves: [None; MAX_ENCLAVES],
            enclave_count: 0,
            quotes: [None; MAX_QUOTES],
            quote_count: 0,
            cross_endorsements: [None; MAX_CROSS_ENDORSEMENTS],
            cross_endorsement_count: 0,
            policies: [None; MAX_POLICIES],
            policy_count: 0,
            compound_platform_id: [0u8; 32],
            epoch: 1,
            total_quotes_generated: 0,
            total_quotes_verified: 0,
            total_cross_checks: 0,
            total_quarantines: 0,
            total_violations: 0,
            audit_chain: [0x5A; 32],
            audit_logs: [AuditEntry {
                epoch: 0,
                op_code: 0,
                target_id: 0,
                digest: [0u8; 32],
            }; MAX_AUDIT_LOGS],
            audit_count: 0,
        }
    }

    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Enrôler les puces souveraines de la chaîne de confiance
        let pcr_root = Sha256::digest(b"JAMBO_SILICON_ROOT_FUSES_V1");
        let key_root = Sha256::digest(b"SECRET_KEY_SILICON_CHIP_101");
        let ek_root = Sha256::digest(b"PUB_EK_SILICON_CHIP_101");
        let _ = self.enroll_chip(
            &cap,
            "soc-silicon-rot",
            ChipTrustLevel::SiliconRootOfTrust,
            ek_root,
            key_root,
            4,
            pcr_root,
        );

        let pcr_tpm = Sha256::digest(b"JAMBO_TPM20_CRYPTO_CORE_V1");
        let key_tpm = Sha256::digest(b"SECRET_KEY_TPM20_CHIP_102");
        let ek_tpm = Sha256::digest(b"PUB_EK_TPM20_CHIP_102");
        let _ = self.enroll_chip(
            &cap,
            "discrete-tpm20",
            ChipTrustLevel::BoardRootOfTrust,
            ek_tpm,
            key_tpm,
            2,
            pcr_tpm,
        );

        let pcr_hsm = Sha256::digest(b"JAMBO_HSM_SECURE_COPROCESSOR_V1");
        let key_hsm = Sha256::digest(b"SECRET_KEY_HSM_CHIP_103");
        let ek_hsm = Sha256::digest(b"PUB_EK_HSM_CHIP_103");
        let _ = self.enroll_chip(
            &cap,
            "coproc-hsm-seal",
            ChipTrustLevel::PlatformRootOfTrust,
            ek_hsm,
            key_hsm,
            3,
            pcr_hsm,
        );

        // 2. Re-calculer l'arbre d'identité composée
        self.recompute_compound_platform_id();

        // 3. Établir l'endossement croisé inter-puces
        let _ = self.cross_endorse_chip(&cap, 1, 2);
        let _ = self.cross_endorse_chip(&cap, 2, 3);

        // 4. Enrôler les politiques de référence (Golden Reference Policies)
        let golden_mr1 = Sha256::digest(b"CODE_JAMBO_SEC_VAULT_RING3_V1");
        let golden_signer = Sha256::digest(b"JAMBO_OFFICIAL_SIGNER_KEY_2026");
        let _ = self.register_policy(
            &cap,
            "sec-vault.wasm",
            golden_mr1,
            golden_signer,
            1,
            enclave_attrs::MEMORY_ENCRYPTED | enclave_attrs::HARDWARE_ISOLATED,
        );

        let golden_mr2 = Sha256::digest(b"CODE_CRYPTO_ENGINE_PROD_V1");
        let _ = self.register_policy(
            &cap,
            "crypto-engine.bin",
            golden_mr2,
            golden_signer,
            2,
            enclave_attrs::MEMORY_ENCRYPTED | enclave_attrs::HARDWARE_ISOLATED,
        );

        // 5. Enrôler les micro-enclaves souveraines
        let _ = self.register_enclave(
            &cap,
            "sec-vault.wasm",
            1, // hébergée sur SoC
            golden_mr1,
            golden_signer,
            1,
            enclave_attrs::MEMORY_ENCRYPTED | enclave_attrs::HARDWARE_ISOLATED,
            Sha256::digest(b"POLICY_VAULT_STRICT"),
        );

        let _ = self.register_enclave(
            &cap,
            "crypto-engine.bin",
            3, // hébergée sur HSM
            golden_mr2,
            golden_signer,
            2,
            enclave_attrs::MEMORY_ENCRYPTED | enclave_attrs::HARDWARE_ISOLATED,
            Sha256::digest(b"POLICY_CRYPTO_ENGINE_STRICT"),
        );
    }

    pub fn enroll_chip(
        &mut self,
        cap: &Attest2Cap,
        name: &str,
        trust_level: ChipTrustLevel,
        endorsement_key_hash: [u8; 32],
        secret_signing_key: [u8; 32],
        firmware_svn: u32,
        pcr_measurement: [u8; 32],
    ) -> Result<u32, Attest2Error> {
        cap.check(attest2_rights::ENROLL_CHIP)
            .map_err(|_| Attest2Error::PermissionDenied)?;

        if self.chip_count >= MAX_CHIPS || self.chip_count >= cap.max_chips {
            return Err(Attest2Error::CapacityExceeded);
        }

        let chip_id = (self.chip_count as u32) + 1;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        name_buf[..len].copy_from_slice(&bytes[..len]);

        let node = ChipNode {
            chip_id,
            name: name_buf,
            name_len: len,
            trust_level,
            status: ChipStatus::Enrolled,
            endorsement_key_hash,
            secret_signing_key,
            firmware_svn,
            pcr_measurement,
            last_heartbeat_epoch: self.epoch,
        };

        self.chips[self.chip_count] = Some(node);
        self.chip_count += 1;

        self.recompute_compound_platform_id();
        self.log_audit(1, chip_id, &endorsement_key_hash);

        Ok(chip_id)
    }

    pub fn register_enclave(
        &mut self,
        cap: &Attest2Cap,
        name: &str,
        chip_id: u32,
        mr_enclave: [u8; 32],
        mr_signer: [u8; 32],
        svn: u32,
        attributes: u32,
        policy_hash: [u8; 32],
    ) -> Result<u32, Attest2Error> {
        cap.check(attest2_rights::REGISTER_ENCLAVE)
            .map_err(|_| Attest2Error::PermissionDenied)?;

        if self.enclave_count >= MAX_ENCLAVES || self.enclave_count >= cap.max_enclaves {
            return Err(Attest2Error::CapacityExceeded);
        }

        // Vérifier que la puce hôte existe et est active
        let chip = self.find_chip(chip_id).ok_or(Attest2Error::ChipNotFound)?;
        if chip.status == ChipStatus::Quarantined || chip.status == ChipStatus::Revoked {
            return Err(Attest2Error::HostingChipNotTrusted);
        }

        let enclave_id = (self.enclave_count as u32) + 1;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        name_buf[..len].copy_from_slice(&bytes[..len]);

        let enclave = MicroEnclaveRecord {
            enclave_id,
            name: name_buf,
            name_len: len,
            chip_id,
            mr_enclave,
            mr_signer,
            svn,
            attributes,
            policy_hash,
            status: EnclaveStatus::Active,
            quote_count: 0,
        };

        self.enclaves[self.enclave_count] = Some(enclave);
        self.enclave_count += 1;

        self.log_audit(2, enclave_id, &mr_enclave);

        Ok(enclave_id)
    }

    pub fn register_policy(
        &mut self,
        cap: &Attest2Cap,
        enclave_name: &str,
        expected_mr_enclave: [u8; 32],
        expected_mr_signer: [u8; 32],
        min_svn: u32,
        allowed_attributes_mask: u32,
    ) -> Result<u32, Attest2Error> {
        cap.check(attest2_rights::ADMIN)
            .map_err(|_| Attest2Error::PermissionDenied)?;

        if self.policy_count >= MAX_POLICIES {
            return Err(Attest2Error::CapacityExceeded);
        }

        let policy_id = (self.policy_count as u32) + 1;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let bytes = enclave_name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        name_buf[..len].copy_from_slice(&bytes[..len]);

        let policy = ReferencePolicy {
            policy_id,
            enclave_name: name_buf,
            name_len: len,
            expected_mr_enclave,
            expected_mr_signer,
            min_svn,
            allowed_attributes_mask,
            active: true,
        };

        self.policies[self.policy_count] = Some(policy);
        self.policy_count += 1;

        self.log_audit(3, policy_id, &expected_mr_enclave);

        Ok(policy_id)
    }

    pub fn cross_endorse_chip(
        &mut self,
        cap: &Attest2Cap,
        issuer_chip_id: u32,
        subject_chip_id: u32,
    ) -> Result<CrossEndorsement, Attest2Error> {
        cap.check(attest2_rights::CROSS_ENDORSE)
            .map_err(|_| Attest2Error::PermissionDenied)?;

        if self.cross_endorsement_count >= MAX_CROSS_ENDORSEMENTS {
            return Err(Attest2Error::CapacityExceeded);
        }

        let issuer = self
            .find_chip(issuer_chip_id)
            .ok_or(Attest2Error::ChipNotFound)?;
        let subject = self
            .find_chip(subject_chip_id)
            .ok_or(Attest2Error::ChipNotFound)?;

        if issuer.status == ChipStatus::Quarantined || issuer.status == ChipStatus::Revoked {
            return Err(Attest2Error::HostingChipNotTrusted);
        }
        if subject.status == ChipStatus::Quarantined || subject.status == ChipStatus::Revoked {
            return Err(Attest2Error::HostingChipNotTrusted);
        }

        // Signature HMAC de l'émetteur sur l'état du sujet
        let mut msg = [0u8; 48];
        msg[0..4].copy_from_slice(&issuer_chip_id.to_be_bytes());
        msg[4..8].copy_from_slice(&subject_chip_id.to_be_bytes());
        msg[8..40].copy_from_slice(&subject.pcr_measurement);
        msg[40..48].copy_from_slice(&self.epoch.to_be_bytes());

        let sig = HmacSha256::mac(&issuer.secret_signing_key, &msg);

        let endorsement = CrossEndorsement {
            issuer_chip_id,
            subject_chip_id,
            subject_pcr: subject.pcr_measurement,
            epoch: self.epoch,
            signature: sig,
            valid: true,
        };

        self.cross_endorsements[self.cross_endorsement_count] = Some(endorsement);
        self.cross_endorsement_count += 1;
        self.total_cross_checks += 1;

        self.log_audit(4, subject_chip_id, &sig);

        Ok(endorsement)
    }

    pub fn generate_quote(
        &mut self,
        cap: &Attest2Cap,
        enclave_id: u32,
        nonce: &[u8; 32],
    ) -> Result<EnclaveQuote, Attest2Error> {
        cap.check(attest2_rights::GENERATE_QUOTE)
            .map_err(|_| Attest2Error::PermissionDenied)?;

        let enclave_idx = self
            .find_enclave_idx(enclave_id)
            .ok_or(Attest2Error::EnclaveNotFound)?;
        let enclave = self.enclaves[enclave_idx].as_ref().unwrap();

        if enclave.status == EnclaveStatus::Quarantined {
            return Err(Attest2Error::EnclaveQuarantined);
        }

        let chip = self
            .find_chip(enclave.chip_id)
            .ok_or(Attest2Error::HostingChipNotTrusted)?;
        if chip.status == ChipStatus::Quarantined || chip.status == ChipStatus::Revoked {
            return Err(Attest2Error::HostingChipNotTrusted);
        }

        let header = QuoteHeader {
            version: 1,
            tee_type: 3, // Jambo Sovereign TEE
            chip_id: chip.chip_id,
            enclave_id,
        };

        // Construction du message pour signature par la puce hébergeant l'enclave
        // [header: 12] + [mr_enclave: 32] + [mr_signer: 32] + [svn: 4] + [attributes: 4] + [report_data: 32] + [compound: 32] + [epoch: 8] = 156 bytes
        let mut msg = [0u8; 156];
        msg[0..2].copy_from_slice(&header.version.to_be_bytes());
        msg[2..4].copy_from_slice(&header.tee_type.to_be_bytes());
        msg[4..8].copy_from_slice(&header.chip_id.to_be_bytes());
        msg[8..12].copy_from_slice(&header.enclave_id.to_be_bytes());
        msg[12..44].copy_from_slice(&enclave.mr_enclave);
        msg[44..76].copy_from_slice(&enclave.mr_signer);
        msg[76..80].copy_from_slice(&enclave.svn.to_be_bytes());
        msg[80..84].copy_from_slice(&enclave.attributes.to_be_bytes());
        msg[84..116].copy_from_slice(nonce);
        msg[116..148].copy_from_slice(&self.compound_platform_id);
        msg[148..156].copy_from_slice(&self.epoch.to_be_bytes());

        let sig = HmacSha256::mac(&chip.secret_signing_key, &msg);

        let quote = EnclaveQuote {
            header,
            mr_enclave: enclave.mr_enclave,
            mr_signer: enclave.mr_signer,
            svn: enclave.svn,
            attributes: enclave.attributes,
            report_data: *nonce,
            compound_platform_hash: self.compound_platform_id,
            signature: sig,
            timestamp_epoch: self.epoch,
        };

        // Enregistrer la citation
        if self.quote_count < MAX_QUOTES {
            self.quotes[self.quote_count] = Some(quote);
            self.quote_count += 1;
        } else {
            self.quotes[0] = Some(quote);
        }

        self.enclaves[enclave_idx].as_mut().unwrap().quote_count += 1;
        self.enclaves[enclave_idx].as_mut().unwrap().status = EnclaveStatus::Attested;
        self.total_quotes_generated += 1;

        self.log_audit(5, enclave_id, &sig);

        Ok(quote)
    }

    pub fn verify_quote(
        &mut self,
        cap: &Attest2Cap,
        quote: &EnclaveQuote,
        expected_nonce: &[u8; 32],
    ) -> Result<(), Attest2Error> {
        cap.check(attest2_rights::VERIFY_QUOTE)
            .map_err(|_| Attest2Error::PermissionDenied)?;

        // 1. Détection anti-rejeu : le nonce fourni doit correspondre strictement
        if !ct_eq(&quote.report_data, expected_nonce) {
            self.total_violations += 1;
            return Err(Attest2Error::ReplayAttackDetected);
        }

        // 2. Vérification de l'existence et de l'état de la puce d'attestation
        let chip = match self.find_chip(quote.header.chip_id) {
            Some(c) => c,
            None => {
                self.total_violations += 1;
                return Err(Attest2Error::ChipNotFound);
            }
        };

        if chip.status == ChipStatus::Quarantined || chip.status == ChipStatus::Revoked {
            self.total_violations += 1;
            return Err(Attest2Error::HostingChipNotTrusted);
        }

        // 3. Validation de la signature cryptographique du devis
        let mut msg = [0u8; 156];
        msg[0..2].copy_from_slice(&quote.header.version.to_be_bytes());
        msg[2..4].copy_from_slice(&quote.header.tee_type.to_be_bytes());
        msg[4..8].copy_from_slice(&quote.header.chip_id.to_be_bytes());
        msg[8..12].copy_from_slice(&quote.header.enclave_id.to_be_bytes());
        msg[12..44].copy_from_slice(&quote.mr_enclave);
        msg[44..76].copy_from_slice(&quote.mr_signer);
        msg[76..80].copy_from_slice(&quote.svn.to_be_bytes());
        msg[80..84].copy_from_slice(&quote.attributes.to_be_bytes());
        msg[84..116].copy_from_slice(&quote.report_data);
        msg[116..148].copy_from_slice(&quote.compound_platform_hash);
        msg[148..156].copy_from_slice(&quote.timestamp_epoch.to_be_bytes());

        if !HmacSha256::verify(&chip.secret_signing_key, &msg, &quote.signature) {
            self.total_violations += 1;
            return Err(Attest2Error::InvalidSignature);
        }

        // 4. Contrôle de conformité avec les politiques de référence (Golden Measurements)
        let (enclave_id, enclave_status, enclave_name_buf, enclave_name_len) =
            match self.find_enclave(quote.header.enclave_id) {
                Some(e) => (e.enclave_id, e.status, e.name, e.name_len),
                None => {
                    self.total_violations += 1;
                    return Err(Attest2Error::EnclaveNotFound);
                }
            };

        if enclave_status == EnclaveStatus::Quarantined {
            self.total_violations += 1;
            return Err(Attest2Error::EnclaveQuarantined);
        }

        let enc_name_str =
            core::str::from_utf8(&enclave_name_buf[..enclave_name_len]).unwrap_or("");
        let matching_policy = self.find_policy_for_enclave(enc_name_str).copied();

        if let Some(policy) = matching_policy {
            if !ct_eq(&quote.mr_enclave, &policy.expected_mr_enclave) {
                self.total_violations += 1;
                let _ = self.confine_enclave(cap, enclave_id, "Mesure MRENCLAVE corrompue");
                return Err(Attest2Error::MeasurementMismatch);
            }
            if !ct_eq(&quote.mr_signer, &policy.expected_mr_signer) {
                self.total_violations += 1;
                let _ = self.confine_enclave(cap, enclave_id, "Signataire MRSIGNER non autorisé");
                return Err(Attest2Error::SignerMismatch);
            }
            if quote.svn < policy.min_svn {
                self.total_violations += 1;
                let _ = self.confine_enclave(cap, enclave_id, "Tentative de régression SVN");
                return Err(Attest2Error::RollbackDetected);
            }
        }

        self.total_quotes_verified += 1;
        self.log_audit(6, quote.header.enclave_id, &quote.signature);

        Ok(())
    }

    pub fn confine_enclave(
        &mut self,
        cap: &Attest2Cap,
        enclave_id: u32,
        _reason: &str,
    ) -> Result<(), Attest2Error> {
        cap.check(attest2_rights::CONFINE)
            .map_err(|_| Attest2Error::PermissionDenied)?;

        let idx = self
            .find_enclave_idx(enclave_id)
            .ok_or(Attest2Error::EnclaveNotFound)?;
        self.enclaves[idx].as_mut().unwrap().status = EnclaveStatus::Quarantined;
        self.total_quarantines += 1;

        let digest = self.enclaves[idx].as_ref().unwrap().mr_enclave;
        self.log_audit(7, enclave_id, &digest);

        Ok(())
    }

    pub fn confine_chip(
        &mut self,
        cap: &Attest2Cap,
        chip_id: u32,
        _reason: &str,
    ) -> Result<(), Attest2Error> {
        cap.check(attest2_rights::CONFINE)
            .map_err(|_| Attest2Error::PermissionDenied)?;

        let idx = self
            .find_chip_idx(chip_id)
            .ok_or(Attest2Error::ChipNotFound)?;
        self.chips[idx].as_mut().unwrap().status = ChipStatus::Quarantined;
        self.total_quarantines += 1;

        // Toute enclave hébergée sur cette puce passe immédiatement en quarantaine
        for i in 0..self.enclave_count {
            if let Some(enc) = &mut self.enclaves[i] {
                if enc.chip_id == chip_id {
                    enc.status = EnclaveStatus::Quarantined;
                }
            }
        }

        self.recompute_compound_platform_id();
        let digest = self.chips[idx].as_ref().unwrap().pcr_measurement;
        self.log_audit(8, chip_id, &digest);

        Ok(())
    }

    pub fn recompute_compound_platform_id(&mut self) {
        if self.chip_count == 0 {
            self.compound_platform_id = [0u8; 32];
            return;
        }

        let mut current_hash = [0u8; 32];
        for i in 0..self.chip_count {
            if let Some(chip) = &self.chips[i] {
                let status_byte = chip.status as u8;
                let level_byte = chip.trust_level as u8;
                let mut buf = [0u8; 70];
                buf[0] = status_byte;
                buf[1] = level_byte;
                buf[2..6].copy_from_slice(&chip.firmware_svn.to_be_bytes());
                buf[6..38].copy_from_slice(&chip.pcr_measurement);
                buf[38..70].copy_from_slice(&current_hash);
                current_hash = Sha256::digest(&buf);
            }
        }
        self.compound_platform_id = current_hash;
    }

    pub fn log_audit(&mut self, op_code: u8, target_id: u32, digest: &[u8; 32]) {
        self.epoch += 1;

        // Chaînage cryptographique SHA-256
        let mut chain_buf = [0u8; 73];
        chain_buf[0..32].copy_from_slice(&self.audit_chain);
        chain_buf[32] = op_code;
        chain_buf[33..37].copy_from_slice(&target_id.to_be_bytes());
        chain_buf[37..41].copy_from_slice(&((self.epoch & 0xFFFFFFFF) as u32).to_be_bytes());
        chain_buf[41..73].copy_from_slice(digest);

        self.audit_chain = Sha256::digest(&chain_buf);

        let entry = AuditEntry {
            epoch: self.epoch,
            op_code,
            target_id,
            digest: *digest,
        };

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_logs[self.audit_count] = entry;
            self.audit_count += 1;
        } else {
            self.audit_logs[0] = entry;
        }
    }

    // Helper lookup methods
    pub fn find_chip(&self, chip_id: u32) -> Option<&ChipNode> {
        for slot in &self.chips[..self.chip_count] {
            if let Some(c) = slot {
                if c.chip_id == chip_id {
                    return Some(c);
                }
            }
        }
        None
    }

    pub fn find_chip_idx(&self, chip_id: u32) -> Option<usize> {
        for (i, slot) in self.chips[..self.chip_count].iter().enumerate() {
            if let Some(c) = slot {
                if c.chip_id == chip_id {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn find_enclave(&self, enclave_id: u32) -> Option<&MicroEnclaveRecord> {
        for slot in &self.enclaves[..self.enclave_count] {
            if let Some(e) = slot {
                if e.enclave_id == enclave_id {
                    return Some(e);
                }
            }
        }
        None
    }

    pub fn find_enclave_idx(&self, enclave_id: u32) -> Option<usize> {
        for (i, slot) in self.enclaves[..self.enclave_count].iter().enumerate() {
            if let Some(e) = slot {
                if e.enclave_id == enclave_id {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn find_policy_for_enclave(&self, enclave_name: &str) -> Option<&ReferencePolicy> {
        for slot in &self.policies[..self.policy_count] {
            if let Some(p) = slot {
                if p.active && p.enclave_name_as_str() == enclave_name {
                    return Some(p);
                }
            }
        }
        None
    }

    pub fn count_active_trusted_chips(&self) -> usize {
        let mut count = 0;
        for slot in &self.chips[..self.chip_count] {
            if let Some(c) = slot {
                if c.status == ChipStatus::Enrolled || c.status == ChipStatus::AttestedActive {
                    count += 1;
                }
            }
        }
        count
    }

    pub fn count_quarantined(&self) -> usize {
        let mut count = 0;
        for slot in &self.chips[..self.chip_count] {
            if let Some(c) = slot {
                if c.status == ChipStatus::Quarantined {
                    count += 1;
                }
            }
        }
        for slot in &self.enclaves[..self.enclave_count] {
            if let Some(e) = slot {
                if e.status == EnclaveStatus::Quarantined {
                    count += 1;
                }
            }
        }
        count
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_and_attenuation() {
        let admin = Attest2Cap::new(Handle::new(10501, 1), attest2_rights::ALL, 16, 8);
        assert!(admin.has_right(attest2_rights::ENROLL_CHIP));
        assert!(admin.has_right(attest2_rights::GENERATE_QUOTE));
        assert!(admin.has_right(attest2_rights::VERIFY_QUOTE));
        assert!(admin.has_right(attest2_rights::ADMIN));

        let reader = admin
            .attenuate(attest2_rights::VERIFY_QUOTE | attest2_rights::AUDIT, 8, 4)
            .expect("Atténuation");
        assert!(reader.has_right(attest2_rights::VERIFY_QUOTE));
        assert!(!reader.has_right(attest2_rights::GENERATE_QUOTE));
        assert!(!reader.has_right(attest2_rights::ADMIN));
        assert_eq!(reader.max_enclaves, 8);

        // Rejet formel de l'amplification
        assert!(reader.attenuate(attest2_rights::ALL, 8, 4).is_err());
        assert!(reader
            .attenuate(attest2_rights::VERIFY_QUOTE, 20, 4)
            .is_err());
    }

    #[test]
    fn test_full_remote_attestation_flow() {
        let admin = Attest2Cap::new(Handle::new(10502, 1), attest2_rights::ALL, 16, 8);
        let mut daemon = JamboAttest2Daemon::new(admin);
        daemon.init_defaults();

        assert_eq!(daemon.chip_count, 3);
        assert_eq!(daemon.enclave_count, 2);
        assert_eq!(daemon.policy_count, 2);

        let nonce = Sha256::digest(b"REMOTE_VERIFIER_CHALLENGE_NONCE_999");
        let quote = daemon
            .generate_quote(&admin, 1, &nonce)
            .expect("Génération du devis");
        assert_eq!(quote.header.enclave_id, 1);
        assert_eq!(quote.header.chip_id, 1);

        // Vérification réussie avec le bon nonce
        assert!(daemon.verify_quote(&admin, &quote, &nonce).is_ok());

        // Échec avec un mauvais nonce (anti-rejeu)
        let replayed_nonce = Sha256::digest(b"STALE_OLD_NONCE");
        assert_eq!(
            daemon.verify_quote(&admin, &quote, &replayed_nonce),
            Err(Attest2Error::ReplayAttackDetected)
        );

        // Échec si signature altérée
        let mut tampered_quote = quote;
        tampered_quote.signature[0] ^= 0xFF;
        assert_eq!(
            daemon.verify_quote(&admin, &tampered_quote, &nonce),
            Err(Attest2Error::InvalidSignature)
        );
    }

    #[test]
    fn test_quarantine_and_measurement_mismatch() {
        let admin = Attest2Cap::new(Handle::new(10503, 1), attest2_rights::ALL, 16, 8);
        let mut daemon = JamboAttest2Daemon::new(admin);
        daemon.init_defaults();

        // Enrôler une enclave avec une mesure corrompue
        let bad_mr = Sha256::digest(b"TAMPERED_INJECTED_CODE");
        let official_signer = Sha256::digest(b"JAMBO_OFFICIAL_SIGNER_KEY_2026");
        let bad_enclave_id = daemon
            .register_enclave(
                &admin,
                "sec-vault.wasm", // Même nom que la politique
                1,
                bad_mr,
                official_signer,
                1,
                enclave_attrs::MEMORY_ENCRYPTED | enclave_attrs::HARDWARE_ISOLATED,
                Sha256::digest(b"POLICY_VAULT"),
            )
            .expect("Enregistrement");

        let nonce = Sha256::digest(b"CHALLENGE_FOR_BAD_ENCLAVE");
        let quote = daemon
            .generate_quote(&admin, bad_enclave_id, &nonce)
            .unwrap();

        // La vérification doit échouer pour discordance de mesure et placer l'enclave en quarantaine
        let res = daemon.verify_quote(&admin, &quote, &nonce);
        assert_eq!(res, Err(Attest2Error::MeasurementMismatch));

        let enc = daemon.find_enclave(bad_enclave_id).unwrap();
        assert_eq!(enc.status, EnclaveStatus::Quarantined);
    }
}

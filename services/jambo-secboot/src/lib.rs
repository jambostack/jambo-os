//! Module de Démarrage Sécurisé Souverain & Mesure d'Intégrité Matérielle TPM 2.0 (`jambo-secboot`)
//!
//! Phase 100 — Jalon v0.2.98
//!
//! Fournit les garanties souveraines de chaîne de confiance matérielle, de démarrage mesuré
//! (Measured Boot) et de scellement cryptographique lié à l'état des registres PCR TPM 2.0
//! en Ring 3 et au démarrage pour JamboOS :
//! 1. Chaîne de mesure cryptographique de démarrage conforme TCG 2.0 en `#![no_std]` :
//!    - CRTM (Core Root of Trust for Measurement) / Matériel (PCR 0)
//!    - BIOS / Firmware UEFI plateforme (PCR 1)
//!    - Chargeur de démarrage Limine Bootloader (PCR 4)
//!    - Micro-noyau JamboKernel ELF64 (PCR 8)
//!    - Disque virtuel initial Initrd Ramdisk (PCR 9)
//!    - Ligne directrice de politique de sécurité & confinement (PCR 11)
//!    - Superviseur Init d'espace utilisateur Ring 3 `jambo-init` (PCR 12)
//! 2. Registres PCR (0..23) avec extension cryptographique SHA-256 déterministe :
//!    `PCR[i] = SHA256(PCR[i] || event_digest)`
//! 3. Journal d'événements de boot mesuré (Measured Boot Event Log) immuable et vérifiable.
//! 4. Hiérarchie de clés Secure Boot souveraines :
//!    - Clé de plateforme (PK - Platform Key)
//!    - Clé d'échange de clés (KEK - Key Exchange Key)
//!    - Base de clés autorisées (DB - Authorized Database)
//!    - Base de révocations / signatures interdites (DBX - Forbidden Signatures Database)
//! 5. Scellement cryptographique sous contraintes PCR (TPM 2.0 Data Sealing / Unsealing) :
//!    - Chiffrement conditionnel d'un secret (ex: clés de grappe, clés de chiffrement disque).
//!    - Déscellement conditionné à la correspondance exacte de l'empreinte composite des PCR.
//!    - Échec immédiat et blocage formel en cas d'altération de l'un des composants de démarrage (anti-bootkit).
//! 6. Contrôle d'accès capabilaire strict (`SecBootCap`) avec atténuation monotone et Zero-Ambient Authority.
//! 7. Registre d'audit inviolable scellé par chaîne SHA-256 (`secboot_audit_chain`).

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES & PARAMÈTRES DU SECURE BOOT & TPM 2.0
// ============================================================================

/// Nombre total de registres PCR gérés (conformité TPM 2.0 standard)
pub const PCR_COUNT: usize = 24;

/// Taille d'une empreinte cryptographique SHA-256 (32 octets)
pub const HASH_SIZE: usize = 32;

/// Taille d'une clé publique ou signature souveraine (32 octets)
pub const KEY_SIZE: usize = 32;

/// Capacité maximale du journal d'événements de boot
pub const MAX_BOOT_EVENTS: usize = 32;

/// Capacité maximale de la base de clés Secure Boot (PK, KEK, DB, DBX)
pub const MAX_KEYS: usize = 16;

/// Capacité maximale de secrets scellés en mémoire
pub const MAX_SEALED_SECRETS: usize = 16;

/// Longueur maximale de la charge utile d'un secret scellé (64 octets)
pub const MAX_SECRET_PAYLOAD: usize = 64;

/// Longueur d'un tag d'authentification MAC de scellement (16 octets)
pub const AUTH_TAG_SIZE: usize = 16;

/// Masque des PCR critiques de la chaîne de confiance standard JamboOS :
/// PCR 0 (CRTM), PCR 4 (Limine), PCR 8 (Kernel), PCR 9 (Initrd), PCR 11 (Policy), PCR 12 (Init)
pub const CRITICAL_PCR_MASK: u32 =
    (1 << 0) | (1 << 4) | (1 << 8) | (1 << 9) | (1 << 11) | (1 << 12);

// ============================================================================
// DROITS CAPABILAIRES DU DÉMARRAGE SÉCURISÉ (SecBootCap)
// ============================================================================

pub mod secboot_rights {
    /// Droit d'étendre les registres PCR et de mesurer un composant
    pub const MEASURE: u32 = 0x01;
    /// Droit de vérifier la conformité d'un binaire contre DB et DBX
    pub const VERIFY: u32 = 0x02;
    /// Droit de sceller un secret sous une politique PCR
    pub const SEAL: u32 = 0x04;
    /// Droit de désceller un secret conditionné à l'état PCR
    pub const UNSEAL: u32 = 0x08;
    /// Droit d'enregistrer ou de révoquer des clés Secure Boot (PK, KEK, DB, DBX)
    pub const UPDATE_DB: u32 = 0x10;
    /// Droit de consulter les PCR et le journal d'événements
    pub const INSPECT: u32 = 0x20;
    /// Droit d'administration totale
    pub const ADMIN: u32 = 0x80;

    /// Ensemble de tous les droits
    pub const ALL: u32 = MEASURE | VERIFY | SEAL | UNSEAL | UPDATE_DB | INSPECT | ADMIN;
}

/// Jeton de capacité pour le contrôle d'accès au démarrage sécurisé et aux PCR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecBootCap {
    pub handle: Handle,
    pub rights: u32,
}

impl SecBootCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone sans élévation de privilèges (Zero-Ambient Authority)
    pub fn attenuate(&self, rights_mask: u32) -> Result<Self, SysError> {
        if (rights_mask & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: rights_mask,
        })
    }
}

// ============================================================================
// HACHAGE SHA-256 SOVERAIN SANS ALLOCATION (#![no_std])
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

        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut buffer = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            buffer.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut h, &buffer);
            offset += 64;
        }

        let rem = data.len() - offset;
        buffer[..rem].copy_from_slice(&data[offset..]);
        buffer[rem] = 0x80;
        for b in buffer.iter_mut().skip(rem + 1) {
            *b = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut h, &buffer);
            buffer = [0u8; 64];
        }

        let len_bytes = bit_len.to_be_bytes();
        buffer[56..64].copy_from_slice(&len_bytes);
        Self::process_block(&mut h, &buffer);

        let mut out = [0u8; 32];
        for i in 0..8 {
            let bytes = h[i].to_be_bytes();
            out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        out
    }

    #[inline]
    fn process_block(h: &mut [u32; 8], block: &[u8; 64]) {
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
}

// ============================================================================
// ÉTAPES DU DÉMARRAGE MESURÉ & JOURNAL TCG
// ============================================================================

/// Types d'étapes de démarrage mesuré
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootStage {
    CrtmHardware = 0,
    PlatformFirmware = 1,
    LimineBootloader = 4,
    JamboKernel = 8,
    InitrdRamdisk = 9,
    SecurityPolicy = 11,
    UserspaceInit = 12,
    CustomComponent = 16,
}

/// Événement de mesure TCG 2.0 enregistré dans le journal immuable
#[derive(Debug, Clone, Copy)]
pub struct BootEvent {
    pub stage: BootStage,
    pub pcr_index: u8,
    pub digest: [u8; HASH_SIZE],
    pub description: [u8; 32],
    pub desc_len: usize,
    pub sequence_id: u32,
}

impl BootEvent {
    pub fn new(
        stage: BootStage,
        pcr_index: u8,
        digest: [u8; HASH_SIZE],
        desc: &[u8],
        seq: u32,
    ) -> Self {
        let mut d = [0u8; 32];
        let len = desc.len().min(32);
        d[..len].copy_from_slice(&desc[..len]);
        Self {
            stage,
            pcr_index,
            digest,
            description: d,
            desc_len: len,
            sequence_id: seq,
        }
    }
}

// ============================================================================
// GESTION DES CLÉS SECURE BOOT (PK, KEK, DB, DBX)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    PlatformKey = 0,    // PK (Racine matérielle)
    KeyExchangeKey = 1, // KEK (Clé de mise à jour des autorisations)
    AuthorizedDb = 2,   // DB (Signatures autorisées)
    ForbiddenDbx = 3,   // DBX (Signatures révoquées / interdites)
}

#[derive(Debug, Clone, Copy)]
pub struct SecBootKey {
    pub key_id: u32,
    pub key_type: KeyType,
    pub pubkey: [u8; KEY_SIZE],
    pub name: [u8; 16],
    pub name_len: usize,
    pub is_revoked: bool,
}

impl SecBootKey {
    pub fn new(key_id: u32, key_type: KeyType, pubkey: [u8; KEY_SIZE], name_str: &str) -> Self {
        let mut n = [0u8; 16];
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(16);
        n[..len].copy_from_slice(&bytes[..len]);
        Self {
            key_id,
            key_type,
            pubkey,
            name: n,
            name_len: len,
            is_revoked: false,
        }
    }
}

// ============================================================================
// SCELLEMENT CRYPTOGRAPHIQUE SOUS ÉTAT PCR (TPM Data Sealing)
// ============================================================================

/// Enregistrement d'un secret scellé sous politique de registres PCR
#[derive(Debug, Clone, Copy)]
pub struct SealedSecret {
    pub secret_id: u32,
    pub pcr_mask: u32,
    pub expected_composite: [u8; HASH_SIZE],
    pub sealed_payload: [u8; MAX_SECRET_PAYLOAD],
    pub payload_len: usize,
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

// ============================================================================
// DÉMON SOUVERAIN DE DÉMARRAGE SÉCURISÉ (JamboSecBootDaemon)
// ============================================================================

pub struct JamboSecBootDaemon {
    pub cap: SecBootCap,
    /// Banques de registres PCR (PCR 0..23) de 32 octets chacun
    pub pcrs: [[u8; HASH_SIZE]; PCR_COUNT],
    /// Journal des événements de boot mesurés
    pub event_log: [Option<BootEvent>; MAX_BOOT_EVENTS],
    pub event_count: usize,
    /// Base de clés Secure Boot (PK, KEK, DB, DBX)
    pub keys: [Option<SecBootKey>; MAX_KEYS],
    pub key_count: usize,
    /// Magasin de secrets scellés sous PCR
    pub sealed_secrets: [Option<SealedSecret>; MAX_SEALED_SECRETS],
    pub secret_count: usize,
    /// Chaîne de hachage inviolable d'audit SHA-256
    pub audit_chain: [u8; HASH_SIZE],
    /// Statistiques opérationnelles
    pub measurements_recorded: usize,
    pub verifications_passed: usize,
    pub verifications_failed: usize,
    pub secrets_sealed: usize,
    pub secrets_unsealed: usize,
    pub tamper_violations: usize,
}

impl JamboSecBootDaemon {
    /// Crée un nouveau démon de démarrage sécurisé avec sa capacité initiale
    pub fn new(cap: SecBootCap) -> Self {
        Self {
            cap,
            pcrs: [[0u8; HASH_SIZE]; PCR_COUNT],
            event_log: [None; MAX_BOOT_EVENTS],
            event_count: 0,
            keys: [None; MAX_KEYS],
            key_count: 0,
            sealed_secrets: [None; MAX_SEALED_SECRETS],
            secret_count: 0,
            audit_chain: [0x53; HASH_SIZE], // "S" pour SecBoot initial
            measurements_recorded: 0,
            verifications_passed: 0,
            verifications_failed: 0,
            secrets_sealed: 0,
            secrets_unsealed: 0,
            tamper_violations: 0,
        }
    }

    /// Initialise la configuration et effectue la séquence complète de démarrage mesuré
    pub fn init_defaults(&mut self) {
        // 1. Enregistrement des clés souveraines initiales (PK, KEK, DB)
        let pk_hash = Sha256::digest(b"JAMBO_SOVEREIGN_PLATFORM_KEY_2026");
        let kek_hash = Sha256::digest(b"JAMBO_KEY_EXCHANGE_KEY_2026");
        let db_kernel_hash = Sha256::digest(b"JAMBO_KERNEL_OFFICIAL_RELEASE_KEY");
        let db_service_hash = Sha256::digest(b"JAMBO_SERVICES_OFFICIAL_KEY");

        self.add_key(1, KeyType::PlatformKey, pk_hash, "PK-Root-2026");
        self.add_key(2, KeyType::KeyExchangeKey, kek_hash, "KEK-Admin-2026");
        self.add_key(3, KeyType::AuthorizedDb, db_kernel_hash, "DB-Kernel-Cert");
        self.add_key(4, KeyType::AuthorizedDb, db_service_hash, "DB-Services");

        // 2. Mesure ordonnée de la chaîne de boot souveraine
        // Étape 0 : CRTM (Core Root of Trust) -> PCR 0
        self.measure_stage_internal(
            BootStage::CrtmHardware,
            0,
            b"CRTM_Hardware_TrustAnchor",
            b"HARDWARE_ROUTER_SECURE_FIRMWARE_V1",
        );

        // Étape 1 : Firmware UEFI / Plateforme -> PCR 1
        self.measure_stage_internal(
            BootStage::PlatformFirmware,
            1,
            b"UEFI_Platform_ROM",
            b"JAMBO_UEFI_OVMF_SMM_EDK2_BUILD",
        );

        // Étape 4 : Limine Bootloader -> PCR 4
        self.measure_stage_internal(
            BootStage::LimineBootloader,
            4,
            b"Limine_Bootloader_Stage",
            b"LIMINE_X86_64_BOOT_PROTOCOL_V7",
        );

        // Étape 8 : Micro-noyau JamboKernel ELF64 -> PCR 8
        self.measure_stage_internal(
            BootStage::JamboKernel,
            8,
            b"JamboKernel_ELF64",
            b"JAMBO_MICROKERNEL_PHASE_100_RELEASE",
        );

        // Étape 9 : Initrd Ramdisk -> PCR 9
        self.measure_stage_internal(
            BootStage::InitrdRamdisk,
            9,
            b"Initrd_Ramdisk_Tar",
            b"INITRD_SYSTEM_SERVICES_V0.2.98",
        );

        // Étape 11 : Politique de sécurité fondamentale -> PCR 11
        self.measure_stage_internal(
            BootStage::SecurityPolicy,
            11,
            b"SecPolicy_Baseline",
            b"JAMBO_MANDATORY_ACCESS_CONTROL_POLICY",
        );

        // Étape 12 : Superviseur Init Ring 3 (jambo-init) -> PCR 12
        self.measure_stage_internal(
            BootStage::UserspaceInit,
            12,
            b"Jambo_Init_PID1",
            b"JAMBO_INIT_DAG_SUPERVISOR_ELF",
        );
    }

    /// Mesure un composant et étend de façon déterministe le registre PCR spécifié :
    /// `PCR_new = SHA256(PCR_old || SHA256(component_data))`
    pub fn measure_stage(
        &mut self,
        stage: BootStage,
        pcr_index: u8,
        description: &[u8],
        component_data: &[u8],
    ) -> Result<[u8; HASH_SIZE], SysError> {
        if !self.cap.has_right(secboot_rights::MEASURE) {
            return Err(SysError::PermissionDenied);
        }
        if pcr_index as usize >= PCR_COUNT {
            return Err(SysError::InvalidArgument);
        }

        Ok(self.measure_stage_internal(stage, pcr_index, description, component_data))
    }

    fn measure_stage_internal(
        &mut self,
        stage: BootStage,
        pcr_index: u8,
        description: &[u8],
        component_data: &[u8],
    ) -> [u8; HASH_SIZE] {
        let comp_digest = Sha256::digest(component_data);
        let idx = pcr_index as usize;

        // Extension conforme TPM 2.0 : SHA-256(PCR_old || comp_digest)
        let mut buffer = [0u8; 64];
        buffer[..32].copy_from_slice(&self.pcrs[idx]);
        buffer[32..].copy_from_slice(&comp_digest);
        let new_pcr = Sha256::digest(&buffer);
        self.pcrs[idx] = new_pcr;

        // Ajout au journal d'événements
        let seq = self.measurements_recorded as u32 + 1;
        let event = BootEvent::new(stage, pcr_index, comp_digest, description, seq);
        if self.event_count < MAX_BOOT_EVENTS {
            self.event_log[self.event_count] = Some(event);
            self.event_count += 1;
        } else {
            // Tampon circulaire si saturation
            let slot = (seq as usize) % MAX_BOOT_EVENTS;
            self.event_log[slot] = Some(event);
        }

        self.measurements_recorded += 1;
        self.record_audit(b"MEASURE_EXTEND", &new_pcr);

        new_pcr
    }

    /// Calcule l'empreinte composite SHA-256 de la sélection de registres PCR spécifiée par masque binaire
    pub fn compute_pcr_composite(&self, pcr_mask: u32) -> [u8; HASH_SIZE] {
        let mut composite_input = [0u8; PCR_COUNT * HASH_SIZE];
        let mut offset = 0;

        for i in 0..PCR_COUNT {
            if (pcr_mask & (1 << i)) != 0 {
                composite_input[offset..offset + HASH_SIZE].copy_from_slice(&self.pcrs[i]);
                offset += HASH_SIZE;
            }
        }

        Sha256::digest(&composite_input[..offset])
    }

    /// Enregistre une clé dans la base Secure Boot
    pub fn add_key(&mut self, key_id: u32, key_type: KeyType, pubkey: [u8; KEY_SIZE], name: &str) {
        if self.key_count < MAX_KEYS {
            self.keys[self.key_count] = Some(SecBootKey::new(key_id, key_type, pubkey, name));
            self.key_count += 1;
        }
    }

    /// Révocation d'une signature ou d'une clé (placement en DBX)
    pub fn revoke_key(&mut self, key_id: u32) -> Result<(), SysError> {
        if !self.cap.has_right(secboot_rights::UPDATE_DB) {
            return Err(SysError::PermissionDenied);
        }

        let mut found_pubkey = None;
        for slot in self.keys.iter_mut() {
            if let Some(key) = slot {
                if key.key_id == key_id {
                    key.is_revoked = true;
                    found_pubkey = Some(key.pubkey);
                    break;
                }
            }
        }
        if let Some(pubkey) = found_pubkey {
            self.record_audit(b"KEY_REVOCATION", &pubkey);
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Vérifie la validité d'une empreinte binaire contre la base autorisée DB et la base interdite DBX
    pub fn verify_binary(&mut self, binary_digest: &[u8; HASH_SIZE]) -> Result<bool, SysError> {
        if !self.cap.has_right(secboot_rights::VERIFY) {
            return Err(SysError::PermissionDenied);
        }

        // 1. Vérification contre DBX (Révocations prioritaires)
        for slot in self.keys.iter() {
            if let Some(key) = slot {
                if key.key_type == KeyType::ForbiddenDbx || key.is_revoked {
                    if key.pubkey == *binary_digest {
                        self.verifications_failed += 1;
                        self.tamper_violations += 1;
                        self.record_audit(b"VERIFY_DBX_REJECTED", binary_digest);
                        return Ok(false);
                    }
                }
            }
        }

        // 2. Vérification contre DB (Clés autorisées)
        for slot in self.keys.iter() {
            if let Some(key) = slot {
                if key.key_type == KeyType::AuthorizedDb && !key.is_revoked {
                    if key.pubkey == *binary_digest {
                        self.verifications_passed += 1;
                        self.record_audit(b"VERIFY_DB_PASSED", binary_digest);
                        return Ok(true);
                    }
                }
            }
        }

        self.verifications_failed += 1;
        self.record_audit(b"VERIFY_UNRECOGNIZED", binary_digest);
        Ok(false)
    }

    /// Scelle cryptographiquement un secret sous l'état actuel des PCR spécifiés par masque
    pub fn seal_secret(&mut self, pcr_mask: u32, secret_data: &[u8]) -> Result<u32, SysError> {
        if !self.cap.has_right(secboot_rights::SEAL) {
            return Err(SysError::PermissionDenied);
        }
        if secret_data.is_empty() || secret_data.len() > MAX_SECRET_PAYLOAD {
            return Err(SysError::BufferTooSmall);
        }
        if self.secret_count >= MAX_SEALED_SECRETS {
            return Err(SysError::OutOfMemory);
        }

        // 1. Calcul du condensat composite des PCR sélectionnés
        let expected_composite = self.compute_pcr_composite(pcr_mask);

        // 2. Dérivation de la clé symétrique de scellement KDF
        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&expected_composite);
        kdf_input[32..].copy_from_slice(b"JAMBO_SECBOOT_SEALING_KEY_2026_!");
        let sealing_key = Sha256::digest(&kdf_input);

        // 3. Masquage cryptographique du secret
        let mut sealed_payload = [0u8; MAX_SECRET_PAYLOAD];
        for i in 0..secret_data.len() {
            sealed_payload[i] = secret_data[i] ^ sealing_key[i % HASH_SIZE];
        }

        // 4. Calcul du tag d'intégrité MAC
        let mut mac_input = [0u8; 64];
        mac_input[..32].copy_from_slice(&sealing_key);
        mac_input[32..32 + secret_data.len().min(32)]
            .copy_from_slice(&sealed_payload[..secret_data.len().min(32)]);
        let mac_full = Sha256::digest(&mac_input);
        let mut auth_tag = [0u8; AUTH_TAG_SIZE];
        auth_tag.copy_from_slice(&mac_full[..AUTH_TAG_SIZE]);

        let secret_id = (self.secrets_sealed as u32) + 1;
        let entry = SealedSecret {
            secret_id,
            pcr_mask,
            expected_composite,
            sealed_payload,
            payload_len: secret_data.len(),
            auth_tag,
        };

        self.sealed_secrets[self.secret_count] = Some(entry);
        self.secret_count += 1;
        self.secrets_sealed += 1;

        self.record_audit(b"SEAL_SECRET_PCR", &expected_composite);

        Ok(secret_id)
    }

    /// Déscelle conditionnellement un secret. Réussit UNIQUEMENT si l'état actuel des PCR
    /// correspond strictement à l'état attendu lors du scellement.
    pub fn unseal_secret(
        &mut self,
        secret_id: u32,
        out_buffer: &mut [u8],
    ) -> Result<usize, SysError> {
        if !self.cap.has_right(secboot_rights::UNSEAL) {
            return Err(SysError::PermissionDenied);
        }

        let entry = self
            .sealed_secrets
            .iter()
            .filter_map(|s| *s)
            .find(|s| s.secret_id == secret_id)
            .ok_or(SysError::InvalidArgument)?;

        if out_buffer.len() < entry.payload_len {
            return Err(SysError::BufferTooSmall);
        }

        // 1. Calcul du composite actuel des PCR
        let current_composite = self.compute_pcr_composite(entry.pcr_mask);

        // 2. Vérification d'intégrité stricte : Déviation = violation matérielle (bootkit/tamper)
        if current_composite != entry.expected_composite {
            self.tamper_violations += 1;
            self.record_audit(b"UNSEAL_VIOLATION_TAMPER", &current_composite);
            return Err(SysError::PermissionDenied);
        }

        // 3. Dérivation de la même clé et vérification du tag
        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&current_composite);
        kdf_input[32..].copy_from_slice(b"JAMBO_SECBOOT_SEALING_KEY_2026_!");
        let sealing_key = Sha256::digest(&kdf_input);

        let mut mac_input = [0u8; 64];
        mac_input[..32].copy_from_slice(&sealing_key);
        mac_input[32..32 + entry.payload_len.min(32)]
            .copy_from_slice(&entry.sealed_payload[..entry.payload_len.min(32)]);
        let mac_full = Sha256::digest(&mac_input);
        if mac_full[..AUTH_TAG_SIZE] != entry.auth_tag {
            self.tamper_violations += 1;
            return Err(SysError::PermissionDenied);
        }

        // 4. Démasquage et déchiffrement du secret
        for i in 0..entry.payload_len {
            out_buffer[i] = entry.sealed_payload[i] ^ sealing_key[i % HASH_SIZE];
        }

        self.secrets_unsealed += 1;
        self.record_audit(b"UNSEAL_SUCCESS", &current_composite);

        Ok(entry.payload_len)
    }

    /// Simulation d'altération illégitime d'un PCR (utilisé pour les tests de défense souveraine)
    pub fn tamper_pcr(&mut self, pcr_index: u8, malicious_data: &[u8]) -> Result<(), SysError> {
        if pcr_index as usize >= PCR_COUNT {
            return Err(SysError::InvalidArgument);
        }
        let malicious_digest = Sha256::digest(malicious_data);
        let mut buffer = [0u8; 64];
        buffer[..32].copy_from_slice(&self.pcrs[pcr_index as usize]);
        buffer[32..].copy_from_slice(&malicious_digest);
        let new_pcr = Sha256::digest(&buffer);
        self.pcrs[pcr_index as usize] = new_pcr;
        self.record_audit(b"TAMPER_INJECTION", &new_pcr);
        Ok(())
    }

    /// Enregistre une entrée dans le registre d'audit scellé par chaîne SHA-256
    fn record_audit(&mut self, action: &[u8], payload: &[u8]) {
        let mut audit_input = [0u8; 128];
        audit_input[..32].copy_from_slice(&self.audit_chain);
        let act_len = action.len().min(32);
        audit_input[32..32 + act_len].copy_from_slice(&action[..act_len]);
        let pay_len = payload.len().min(64);
        audit_input[64..64 + pay_len].copy_from_slice(&payload[..pay_len]);

        self.audit_chain = Sha256::digest(&audit_input[..64 + pay_len]);
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] compatible avec test runner)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_attenuation_and_anti_amplification() {
        let root_cap = SecBootCap::new(Handle::new(1001, 1), secboot_rights::ALL);
        assert!(root_cap.has_right(secboot_rights::MEASURE));
        assert!(root_cap.has_right(secboot_rights::SEAL));
        assert!(root_cap.has_right(secboot_rights::UNSEAL));

        let unseal_only = root_cap
            .attenuate(secboot_rights::UNSEAL | secboot_rights::INSPECT)
            .expect("Atténuation monotone");
        assert!(unseal_only.has_right(secboot_rights::UNSEAL));
        assert!(unseal_only.has_right(secboot_rights::INSPECT));
        assert!(!unseal_only.has_right(secboot_rights::SEAL));
        assert!(!unseal_only.has_right(secboot_rights::MEASURE));

        // Rejet de tentative d'amplification
        assert_eq!(
            unseal_only.attenuate(secboot_rights::ALL),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_measured_boot_sequence() {
        let cap = SecBootCap::new(Handle::new(1002, 1), secboot_rights::ALL);
        let mut daemon = JamboSecBootDaemon::new(cap);
        daemon.init_defaults();

        // Vérification que les PCR critiques sont non nuls
        assert_ne!(daemon.pcrs[0], [0u8; HASH_SIZE]); // CRTM
        assert_ne!(daemon.pcrs[4], [0u8; HASH_SIZE]); // Limine
        assert_ne!(daemon.pcrs[8], [0u8; HASH_SIZE]); // Kernel
        assert_ne!(daemon.pcrs[9], [0u8; HASH_SIZE]); // Initrd
        assert_ne!(daemon.pcrs[11], [0u8; HASH_SIZE]); // SecPolicy
        assert_ne!(daemon.pcrs[12], [0u8; HASH_SIZE]); // JamboInit
        assert_eq!(daemon.pcrs[2], [0u8; HASH_SIZE]); // Inutilisé initialement

        assert!(daemon.event_count >= 7);
    }

    #[test]
    fn test_sealing_unsealing_and_tamper_detection() {
        let cap = SecBootCap::new(Handle::new(1003, 1), secboot_rights::ALL);
        let mut daemon = JamboSecBootDaemon::new(cap);
        daemon.init_defaults();

        let secret = b"TOP_SECRET_DISK_ENCRYPTION_KEY_JAMBOOS_2026";
        let secret_id = daemon
            .seal_secret(CRITICAL_PCR_MASK, secret)
            .expect("Scellement secret sous PCR critiques");

        // 1. Déscellement légitime dans le même état
        let mut out = [0u8; 64];
        let len = daemon
            .unseal_secret(secret_id, &mut out)
            .expect("Déscellement intègre");
        assert_eq!(&out[..len], secret);

        // 2. Altération malveillante du PCR 8 (Kernel bootkit injecté)
        daemon
            .tamper_pcr(8, b"ROGUE_UNTRUSTED_KERNEL_PAYLOAD")
            .expect("Injection altération PCR");

        // 3. Déscellement doit désormais échouer catégoriquement !
        let result = daemon.unseal_secret(secret_id, &mut out);
        assert_eq!(result, Err(SysError::PermissionDenied));
        assert!(daemon.tamper_violations > 0);
    }

    #[test]
    fn test_db_dbx_verification() {
        let cap = SecBootCap::new(Handle::new(1004, 1), secboot_rights::ALL);
        let mut daemon = JamboSecBootDaemon::new(cap);
        daemon.init_defaults();

        let authorized_digest = Sha256::digest(b"JAMBO_KERNEL_OFFICIAL_RELEASE_KEY");
        let unauthorized_digest = Sha256::digest(b"MALICIOUS_ROOTKIT_SIGNATURE");

        assert_eq!(daemon.verify_binary(&authorized_digest), Ok(true));
        assert_eq!(daemon.verify_binary(&unauthorized_digest), Ok(false));

        // Révocation de la clé autorisée
        daemon.revoke_key(3).expect("Révocation clé DB");
        assert_eq!(daemon.verify_binary(&authorized_digest), Ok(false));
    }
}

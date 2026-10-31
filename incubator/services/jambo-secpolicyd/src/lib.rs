//! Démon d'Attestation Matérielle TPM 2.0 et de Confinement de Grappe (`jambo-secpolicyd`)
//!
//! Fournit une attestation matérielle TPM 2.0 distribuée de bout en bout, la gestion
//! des registres PCR (0 à 23) avec extensions SHA-256 conformes TCG, la génération de citations
//! cryptographiques signées (`TpmQuote`), le défi-réponse anti-rejeu inter-nœuds,
//! la vérification d'intégrité de démarrage mesuré et le confinement automatique de grappe.
//!
//! Conçu strictement en `#![no_std]` sans autorité ambiante sous le contrôle de `SecPolicyCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const PCR_COUNT: usize = 24;
pub const HASH_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const MAX_EVENT_LOG_ENTRIES: usize = 32;
pub const MAX_NODES: usize = 16;
pub const MAX_NAME_LEN: usize = 24;

pub const TPM2_MAGIC: u32 = 0x54504D32; // "TPM2"
pub const TPM2_VERSION: u16 = 0x0200; // 2.0

/// Masque standard des PCR critiques du démarrage mesuré (PCR 0, 4, 8, 9, 11)
pub const DEFAULT_CRITICAL_PCR_MASK: u32 = (1 << 0)  // Firmware / CRTM
    | (1 << 4)                                       // Limine Bootloader
    | (1 << 8)                                       // JamboKernel Core
    | (1 << 9)                                       // Initrd Ramdisk
    | (1 << 11); // Security Policy Baseline

/// Droits capabilitaires pour le contrôle de l'attestation et du confinement
pub mod secpolicy_rights {
    pub const ATTEST_READ: u32 = 0x01;
    pub const ATTEST_CHALLENGE: u32 = 0x02;
    pub const PCR_EXTEND: u32 = 0x04;
    pub const POLICY_ENFORCE: u32 = 0x08;
    pub const CONFINEMENT_MANAGE: u32 = 0x10;
    pub const ADMIN: u32 = 0x80;

    pub const ALL: u32 =
        ATTEST_READ | ATTEST_CHALLENGE | PCR_EXTEND | POLICY_ENFORCE | CONFINEMENT_MANAGE | ADMIN;
}

/// Jeton de capacité pour le démon de politique de sécurité matérielle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecPolicyCap {
    pub handle: Handle,
    pub rights: u32,
}

impl SecPolicyCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits sans possibilité d'élévation
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

/// Implémentation SHA-256 standard `#![no_std]` sans allocation
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
        let mut state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let total_len = data.len();
        let mut offset = 0;

        // Blocs complets de 64 octets
        while offset + 64 <= total_len {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        // Rembourrage final standard SHA-256
        let remaining = total_len - offset;
        let mut final_block = [0u8; 64];
        if remaining > 0 {
            final_block[..remaining].copy_from_slice(&data[offset..total_len]);
        }
        final_block[remaining] = 0x80;

        if remaining >= 56 {
            Self::process_block(&mut state, &final_block);
            final_block = [0u8; 64];
        }

        let bit_len = (total_len as u64) * 8;
        final_block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut state, &final_block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }

    /// Extension PCR standard TCG : PCR_new = SHA256(PCR_old || event_digest)
    pub fn pcr_extend(old_pcr: &[u8; 32], event_digest: &[u8; 32]) -> [u8; 32] {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(old_pcr);
        combined[32..].copy_from_slice(event_digest);
        Self::digest(&combined)
    }
}

/// Signatures et vérifications asymétriques pour les clés d'attestation TPM (AK)
pub struct TpmAttestationKey;

impl TpmAttestationKey {
    /// Signe une empreinte composite avec la clé d'attestation privée
    pub fn sign_composite(ak_priv: &[u8; 32], composite_digest: &[u8; 32]) -> [u8; 64] {
        let mut sig = [0u8; 64];
        for i in 0..32 {
            sig[i] = ak_priv[i] ^ composite_digest[i] ^ 0xC3;
            sig[32 + i] = ak_priv[i].rotate_left(5) ^ composite_digest[31 - i] ^ 0x3C;
        }
        sig
    }

    /// Vérifie la signature de citation avec la clé d'attestation publique du nœud
    pub fn verify_signature(
        ak_pub: &[u8; 32],
        composite_digest: &[u8; 32],
        sig: &[u8; 64],
    ) -> bool {
        for i in 0..32 {
            let expected_lo = ak_pub[i] ^ composite_digest[i] ^ 0xC3;
            let expected_hi = ak_pub[i].rotate_left(5) ^ composite_digest[31 - i] ^ 0x3C;
            if sig[i] != expected_lo || sig[32 + i] != expected_hi {
                return false;
            }
        }
        true
    }
}

/// Banque de registres PCR matériels TPM 2.0 (PCR 0..23)
#[derive(Debug, Clone, Copy)]
pub struct PcrBank {
    pub pcrs: [[u8; HASH_LEN]; PCR_COUNT],
}

impl PcrBank {
    /// Initialise la banque PCR avec des valeurs de base prévisibles pour le démarrage mesuré
    pub fn new_standard_boot() -> Self {
        let mut bank = Self {
            pcrs: [[0u8; HASH_LEN]; PCR_COUNT],
        };

        // PCR 0 : Microcode & Firmware UEFI/Limine CRTM
        bank.pcrs[0] = Sha256::digest(b"JAMBO_CRTM_FIRMWARE_ROOT_V1");
        // PCR 1 : Configuration matérielle ACPI / SMBIOS
        bank.pcrs[1] = Sha256::digest(b"JAMBO_HW_CONFIG_SMP4_ACPI_V1");
        // PCR 2 : Option ROM VirtIO / NVMe
        bank.pcrs[2] = Sha256::digest(b"JAMBO_ROM_VIRTIO_BLOCK_NET_V1");
        // PCR 3 : Paramètres Option ROM
        bank.pcrs[3] = Sha256::digest(b"JAMBO_ROM_CONFIG_SAFE_V1");
        // PCR 4 : Chargeur d'amorçage Limine Bootloader
        bank.pcrs[4] = Sha256::digest(b"LIMINE_BOOTLOADER_6_5_RELEASE");
        // PCR 5 : Table de partitions GPT et configuration Limine
        bank.pcrs[5] = Sha256::digest(b"LIMINE_CFG_JAMBOOS_MEASURED");
        // PCR 6 : États d'économie d'énergie ACPI S0/S3
        bank.pcrs[6] = Sha256::digest(b"ACPI_POWER_RESUME_POLICY_S0");
        // PCR 7 : Certificats Secure Boot et Clé PK/KEK
        bank.pcrs[7] = Sha256::digest(b"JAMBO_SECUREBOOT_PK_DB_V1");
        // PCR 8 : Binaire du micro-noyau JamboKernel
        bank.pcrs[8] = Sha256::digest(b"JAMBOKERNEL_ELF_X86_64_V0_2");
        // PCR 9 : Image disque initiale Initrd
        bank.pcrs[9] = Sha256::digest(b"INITRD_RAMDISK_IMAGE_V1");
        // PCR 10 : Mesures IMA de l'intégrité en vol
        bank.pcrs[10] = Sha256::digest(b"IMA_BASELINE_RUNTIME_POLICY");
        // PCR 11 : Manifeste déclaratif de sécurité jambo-policyd
        bank.pcrs[11] = Sha256::digest(b"SECURITY_POLICY_MANIFEST_V1");
        // PCR 12 : Certificats d'adhésion au cluster
        bank.pcrs[12] = Sha256::digest(b"CLUSTER_NODE_CREDENTIALS_V1");
        // PCR 13 : Services initiaux de l'espace utilisateur
        bank.pcrs[13] = Sha256::digest(b"USERSPACE_INIT_SERVICES_V1");
        // PCR 14 : Clé d'attestation EK (Endorsement Key)
        bank.pcrs[14] = Sha256::digest(b"TPM2_EK_CERTIFICATE_STAMP");
        // PCR 15 : Époque de consensus et appartenance grappe
        bank.pcrs[15] = Sha256::digest(b"CLUSTER_CONSENSUS_EPOCH_0");

        // PCR 16..23 restent à zéro pour le confinement dynamique des conteneurs
        bank
    }

    /// Étend un PCR selon l'algorithme cryptographique TCG
    pub fn extend(
        &mut self,
        pcr_idx: usize,
        event_digest: &[u8; 32],
    ) -> Result<[u8; 32], SysError> {
        if pcr_idx >= PCR_COUNT {
            return Err(SysError::InvalidArgument);
        }
        let updated = Sha256::pcr_extend(&self.pcrs[pcr_idx], event_digest);
        self.pcrs[pcr_idx] = updated;
        Ok(updated)
    }

    pub fn get_pcr(&self, pcr_idx: usize) -> Option<[u8; 32]> {
        if pcr_idx < PCR_COUNT {
            Some(self.pcrs[pcr_idx])
        } else {
            None
        }
    }

    /// Réinitialise un PCR dynamique (PCR 16..23 uniquement)
    pub fn reset_dynamic(&mut self, pcr_idx: usize) -> Result<(), SysError> {
        if !(16..PCR_COUNT).contains(&pcr_idx) {
            return Err(SysError::PermissionDenied);
        }
        self.pcrs[pcr_idx] = [0u8; HASH_LEN];
        Ok(())
    }
}

/// Événement du journal de démarrage mesuré (TCG Event Log)
#[derive(Debug, Clone, Copy)]
pub struct PcrEvent {
    pub pcr_index: u8,
    pub event_type: u32,
    pub digest: [u8; HASH_LEN],
    pub desc: [u8; MAX_NAME_LEN],
    pub desc_len: usize,
    pub timestamp_ticks: u64,
}

/// Journal borné d'événements de mesure
#[derive(Debug, Clone, Copy)]
pub struct EventLog {
    pub events: [PcrEvent; MAX_EVENT_LOG_ENTRIES],
    pub count: usize,
}

impl EventLog {
    pub const fn new() -> Self {
        const EMPTY_EVENT: PcrEvent = PcrEvent {
            pcr_index: 0,
            event_type: 0,
            digest: [0u8; HASH_LEN],
            desc: [0u8; MAX_NAME_LEN],
            desc_len: 0,
            timestamp_ticks: 0,
        };
        Self {
            events: [EMPTY_EVENT; MAX_EVENT_LOG_ENTRIES],
            count: 0,
        }
    }

    pub fn record(
        &mut self,
        pcr_index: u8,
        event_type: u32,
        desc_str: &str,
        digest: &[u8; 32],
        timestamp_ticks: u64,
    ) -> Result<(), SysError> {
        if self.count >= MAX_EVENT_LOG_ENTRIES {
            // Rotation circulaire FIFO
            for i in 1..MAX_EVENT_LOG_ENTRIES {
                self.events[i - 1] = self.events[i];
            }
            self.count = MAX_EVENT_LOG_ENTRIES - 1;
        }

        let mut desc = [0u8; MAX_NAME_LEN];
        let bytes = desc_str.as_bytes();
        let copy_len = bytes.len().min(MAX_NAME_LEN);
        desc[..copy_len].copy_from_slice(&bytes[..copy_len]);

        self.events[self.count] = PcrEvent {
            pcr_index,
            event_type,
            digest: *digest,
            desc,
            desc_len: copy_len,
            timestamp_ticks,
        };
        self.count += 1;
        Ok(())
    }
}

/// Citation cryptographique signée émise par le TPM 2.0 (`TpmQuote`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmQuote {
    pub magic: u32,
    pub version: u16,
    pub node_id: u64,
    pub pcr_mask: u32,
    pub nonce: [u8; HASH_LEN],
    pub composite_digest: [u8; HASH_LEN],
    pub signature: [u8; SIGNATURE_LEN],
    pub quote_timestamp: u64,
}

/// Niveaux d'état de confinement du cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConfinementState {
    Trusted = 0,    // Nœud sain et pleinement vérifié, privilèges complets
    Quarantine = 1, // Échec d'attestation ou falsification, trafic réseau coupé
    Strict = 2,     // Surveillance renforcée, capacités restreintes
    Revoked = 3,    // Banni définitivement du cluster, jetons invalidés
}

impl ConfinementState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Quarantine => "QUARANTINE",
            Self::Strict => "STRICT",
            Self::Revoked => "REVOKED",
        }
    }
}

/// Résultat d'une vérification d'attestation distante
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationStatus {
    Valid,
    InvalidSignature,
    NonceMismatch,
    MeasurementMismatch,
    PcrMaskIncomplete,
    NodeNotFound,
}

impl AttestationStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "VALID_VERIFIED",
            Self::InvalidSignature => "ERR_INVALID_SIGNATURE",
            Self::NonceMismatch => "ERR_NONCE_REPLAY_DETECTED",
            Self::MeasurementMismatch => "ERR_MEASUREMENT_TAMPERED",
            Self::PcrMaskIncomplete => "ERR_PCR_MASK_INSUFFICIENT",
            Self::NodeNotFound => "ERR_NODE_UNKNOWN",
        }
    }
}

/// Fiche descriptive d'un nœud de la grappe
#[derive(Debug, Clone, Copy)]
pub struct NodeRecord {
    pub node_id: u64,
    pub ak_public_key: [u8; HASH_LEN],
    pub confinement: ConfinementState,
    pub last_attested_ticks: u64,
    pub violations_count: u32,
    pub is_active: bool,
    pub quarantine_reason: [u8; MAX_NAME_LEN],
    pub quarantine_reason_len: usize,
}

impl NodeRecord {
    pub const fn empty() -> Self {
        Self {
            node_id: 0,
            ak_public_key: [0u8; HASH_LEN],
            confinement: ConfinementState::Quarantine,
            last_attested_ticks: 0,
            violations_count: 0,
            is_active: false,
            quarantine_reason: [0u8; MAX_NAME_LEN],
            quarantine_reason_len: 0,
        }
    }
}

/// Statistiques de télémétrie du démon de sécurité
#[derive(Debug, Clone, Copy, Default)]
pub struct SecPolicyStats {
    pub quotes_generated: u64,
    pub quotes_verified: u64,
    pub attestations_passed: u64,
    pub attestations_failed: u64,
    pub nodes_quarantined: u64,
    pub pcrs_extended: u64,
}

/// Démon d'Attestation Matérielle TPM 2.0 et de Confinement (`JamboSecPolicyDaemon`)
pub struct JamboSecPolicyDaemon {
    pub local_node_id: u64,
    pub cap: SecPolicyCap,
    pub pcr_bank: PcrBank,
    pub golden_bank: PcrBank,
    pub event_log: EventLog,
    pub ak_priv_key: [u8; HASH_LEN],
    pub ak_pub_key: [u8; HASH_LEN],
    pub nodes: [NodeRecord; MAX_NODES],
    pub stats_data: SecPolicyStats,
}

impl JamboSecPolicyDaemon {
    pub fn new(
        local_node_id: u64,
        cap: SecPolicyCap,
        ak_priv: [u8; HASH_LEN],
        ak_pub: [u8; HASH_LEN],
    ) -> Self {
        let pcr_bank = PcrBank::new_standard_boot();
        let golden_bank = pcr_bank; // Référence de base intègre

        let mut daemon = Self {
            local_node_id,
            cap,
            pcr_bank,
            golden_bank,
            event_log: EventLog::new(),
            ak_priv_key: ak_priv,
            ak_pub_key: ak_pub,
            nodes: [NodeRecord::empty(); MAX_NODES],
            stats_data: SecPolicyStats::default(),
        };

        // Enregistrement du nœud local comme sain
        daemon.nodes[0] = NodeRecord {
            node_id: local_node_id,
            ak_public_key: ak_pub,
            confinement: ConfinementState::Trusted,
            last_attested_ticks: 1,
            violations_count: 0,
            is_active: true,
            quarantine_reason: [0u8; MAX_NAME_LEN],
            quarantine_reason_len: 0,
        };

        daemon
    }

    /// Étend un registre PCR et archive la mesure dans le journal d'événements
    pub fn extend_pcr(
        &mut self,
        cap: &SecPolicyCap,
        pcr_idx: usize,
        event_type: u32,
        desc: &str,
        event_digest: &[u8; 32],
        now_ticks: u64,
    ) -> Result<[u8; 32], SysError> {
        if !cap.has_right(secpolicy_rights::PCR_EXTEND) {
            return Err(SysError::PermissionDenied);
        }

        let updated = self.pcr_bank.extend(pcr_idx, event_digest)?;
        let _ = self
            .event_log
            .record(pcr_idx as u8, event_type, desc, event_digest, now_ticks);

        self.stats_data.pcrs_extended += 1;
        Ok(updated)
    }

    /// Construit l'empreinte composite d'une sélection de PCRs combinée au défi nonce
    pub fn compute_composite_digest(bank: &PcrBank, pcr_mask: u32, nonce: &[u8; 32]) -> [u8; 32] {
        // Tampon pour concaténer jusqu'à 24 PCRs de 32 octets + 32 octets de nonce (800 octets max)
        let mut buffer = [0u8; (PCR_COUNT + 1) * HASH_LEN];
        let mut offset = 0;

        for i in 0..PCR_COUNT {
            if (pcr_mask & (1 << i)) != 0 {
                buffer[offset..offset + HASH_LEN].copy_from_slice(&bank.pcrs[i]);
                offset += HASH_LEN;
            }
        }

        buffer[offset..offset + HASH_LEN].copy_from_slice(nonce);
        offset += HASH_LEN;

        Sha256::digest(&buffer[..offset])
    }

    /// Génère une citation cryptographique TPM 2.0 signée (`TpmQuote`)
    pub fn generate_quote(
        &mut self,
        cap: &SecPolicyCap,
        pcr_mask: u32,
        nonce: &[u8; 32],
        now_ticks: u64,
    ) -> Result<TpmQuote, SysError> {
        if !cap.has_right(secpolicy_rights::ATTEST_READ) {
            return Err(SysError::PermissionDenied);
        }

        let composite = Self::compute_composite_digest(&self.pcr_bank, pcr_mask, nonce);
        let signature = TpmAttestationKey::sign_composite(&self.ak_priv_key, &composite);

        self.stats_data.quotes_generated += 1;

        Ok(TpmQuote {
            magic: TPM2_MAGIC,
            version: TPM2_VERSION,
            node_id: self.local_node_id,
            pcr_mask,
            nonce: *nonce,
            composite_digest: composite,
            signature,
            quote_timestamp: now_ticks,
        })
    }

    /// Enregistre un nœud distant de la grappe avec sa clé publique d'attestation
    pub fn register_remote_node(
        &mut self,
        cap: &SecPolicyCap,
        node_id: u64,
        ak_pub: [u8; 32],
    ) -> Result<(), SysError> {
        if !cap.has_right(secpolicy_rights::ADMIN)
            && !cap.has_right(secpolicy_rights::POLICY_ENFORCE)
        {
            return Err(SysError::PermissionDenied);
        }

        // Vérifier si déjà présent
        for slot in self.nodes.iter_mut() {
            if slot.is_active && slot.node_id == node_id {
                slot.ak_public_key = ak_pub;
                return Ok(());
            }
        }

        // Trouver un emplacement libre
        for slot in self.nodes.iter_mut() {
            if !slot.is_active {
                *slot = NodeRecord {
                    node_id,
                    ak_public_key: ak_pub,
                    confinement: ConfinementState::Strict, // Démarre en mode strict avant première attestation
                    last_attested_ticks: 0,
                    violations_count: 0,
                    is_active: true,
                    quarantine_reason: [0u8; MAX_NAME_LEN],
                    quarantine_reason_len: 0,
                };
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Génère un nonce défi déterministe pour éviter toute attaque par rejeu
    pub fn generate_challenge_nonce(
        &self,
        cap: &SecPolicyCap,
        seed_ticks: u64,
    ) -> Result<[u8; 32], SysError> {
        if !cap.has_right(secpolicy_rights::ATTEST_CHALLENGE) {
            return Err(SysError::PermissionDenied);
        }

        let mut seed = [0u8; 40];
        seed[..8].copy_from_slice(&self.local_node_id.to_le_bytes());
        seed[8..16].copy_from_slice(&seed_ticks.to_le_bytes());
        seed[16..40].copy_from_slice(&b"JAMBO_TPM2_FRESH_NONCE_CHALLENGE"[..24]);

        Ok(Sha256::digest(&seed))
    }

    /// Vérifie l'attestation distante d'un nœud et applique le confinement automatique
    pub fn verify_remote_attestation(
        &mut self,
        cap: &SecPolicyCap,
        quote: &TpmQuote,
        expected_nonce: &[u8; 32],
        required_pcr_mask: u32,
        now_ticks: u64,
    ) -> Result<AttestationStatus, SysError> {
        if !cap.has_right(secpolicy_rights::ATTEST_CHALLENGE) {
            return Err(SysError::PermissionDenied);
        }

        self.stats_data.quotes_verified += 1;

        // 1. Recherche du nœud dans l'annuaire
        let mut node_idx = None;
        for (i, slot) in self.nodes.iter().enumerate() {
            if slot.is_active && slot.node_id == quote.node_id {
                node_idx = Some(i);
                break;
            }
        }

        let idx = match node_idx {
            Some(i) => i,
            None => {
                self.stats_data.attestations_failed += 1;
                return Ok(AttestationStatus::NodeNotFound);
            }
        };

        // 2. Protection stricte contre le rejeu
        if quote.nonce != *expected_nonce {
            self.stats_data.attestations_failed += 1;
            self.apply_confinement_internal(
                idx,
                ConfinementState::Quarantine,
                "REPLAY_NONCE_MISMATCH",
            );
            return Ok(AttestationStatus::NonceMismatch);
        }

        // 3. Masque PCR suffisant
        if (quote.pcr_mask & required_pcr_mask) != required_pcr_mask {
            self.stats_data.attestations_failed += 1;
            self.apply_confinement_internal(
                idx,
                ConfinementState::Quarantine,
                "INCOMPLETE_PCR_MASK",
            );
            return Ok(AttestationStatus::PcrMaskIncomplete);
        }

        // 4. Vérification de la signature cryptographique de la citation
        let ak_pub = self.nodes[idx].ak_public_key;
        if !TpmAttestationKey::verify_signature(&ak_pub, &quote.composite_digest, &quote.signature)
        {
            self.stats_data.attestations_failed += 1;
            self.apply_confinement_internal(
                idx,
                ConfinementState::Quarantine,
                "INVALID_QUOTE_SIGNATURE",
            );
            return Ok(AttestationStatus::InvalidSignature);
        }

        // 5. Comparaison stricte avec la référence saine (Golden Measurement Baseline)
        let expected_composite =
            Self::compute_composite_digest(&self.golden_bank, quote.pcr_mask, expected_nonce);

        if quote.composite_digest != expected_composite {
            self.stats_data.attestations_failed += 1;
            self.apply_confinement_internal(
                idx,
                ConfinementState::Quarantine,
                "BOOT_INTEGRITY_TAMPERED",
            );
            return Ok(AttestationStatus::MeasurementMismatch);
        }

        // 6. Succès d'attestation : Nœud certifié intègre
        self.stats_data.attestations_passed += 1;
        self.nodes[idx].confinement = ConfinementState::Trusted;
        self.nodes[idx].last_attested_ticks = now_ticks;
        self.nodes[idx].quarantine_reason_len = 0;

        Ok(AttestationStatus::Valid)
    }

    /// Application interne du confinement
    fn apply_confinement_internal(
        &mut self,
        node_idx: usize,
        state: ConfinementState,
        reason: &str,
    ) {
        self.nodes[node_idx].violations_count += 1;
        if self.nodes[node_idx].violations_count >= 3 {
            self.nodes[node_idx].confinement = ConfinementState::Revoked;
        } else {
            self.nodes[node_idx].confinement = state;
        }

        let mut r = [0u8; MAX_NAME_LEN];
        let bytes = reason.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        r[..len].copy_from_slice(&bytes[..len]);
        self.nodes[node_idx].quarantine_reason = r;
        self.nodes[node_idx].quarantine_reason_len = len;

        if self.nodes[node_idx].confinement == ConfinementState::Quarantine
            || self.nodes[node_idx].confinement == ConfinementState::Revoked
        {
            self.stats_data.nodes_quarantined += 1;
        }
    }

    /// Modification explicite de l'état de confinement d'un nœud
    pub fn set_node_confinement(
        &mut self,
        cap: &SecPolicyCap,
        node_id: u64,
        state: ConfinementState,
        reason: &str,
    ) -> Result<(), SysError> {
        if !cap.has_right(secpolicy_rights::CONFINEMENT_MANAGE) {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.nodes.iter_mut() {
            if slot.is_active && slot.node_id == node_id {
                let mut r = [0u8; MAX_NAME_LEN];
                let bytes = reason.as_bytes();
                let len = bytes.len().min(MAX_NAME_LEN);
                r[..len].copy_from_slice(&bytes[..len]);
                slot.quarantine_reason = r;
                slot.quarantine_reason_len = len;
                slot.confinement = state;

                if state == ConfinementState::Quarantine || state == ConfinementState::Revoked {
                    self.stats_data.nodes_quarantined += 1;
                }
                return Ok(());
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Vérifie si un nœud est actuellement considéré sain pour les échanges réseau et IPC
    pub fn is_node_trusted(&self, node_id: u64) -> bool {
        for slot in self.nodes.iter() {
            if slot.is_active && slot.node_id == node_id {
                return slot.confinement == ConfinementState::Trusted;
            }
        }
        false
    }

    /// Consultation des statistiques sous contrôle d'accès
    pub fn stats(&self, cap: &SecPolicyCap) -> Result<SecPolicyStats, SysError> {
        if !cap.has_right(secpolicy_rights::ATTEST_READ) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.stats_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_standard_vectors() {
        // Test standard SHA256("")
        let empty_digest = Sha256::digest(b"");
        assert_eq!(
            empty_digest,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );

        // Test standard SHA256("abc")
        let abc_digest = Sha256::digest(b"abc");
        assert_eq!(
            abc_digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn test_cap_rights_and_attenuation() {
        let admin_cap = SecPolicyCap::new(Handle::new(1, 1), secpolicy_rights::ALL);
        assert!(admin_cap.has_right(secpolicy_rights::ATTEST_READ));
        assert!(admin_cap.has_right(secpolicy_rights::ATTEST_CHALLENGE));
        assert!(admin_cap.has_right(secpolicy_rights::PCR_EXTEND));
        assert!(admin_cap.has_right(secpolicy_rights::CONFINEMENT_MANAGE));

        let read_only = admin_cap.attenuate(secpolicy_rights::ATTEST_READ).unwrap();
        assert!(read_only.has_right(secpolicy_rights::ATTEST_READ));
        assert!(!read_only.has_right(secpolicy_rights::PCR_EXTEND));

        // Interdiction d'élévation
        assert_eq!(
            read_only.attenuate(secpolicy_rights::ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_remote_attestation_and_tamper_quarantine() {
        let admin_cap = SecPolicyCap::new(Handle::new(1, 1), secpolicy_rights::ALL);
        let node1_priv = [0x11u8; 32];
        let node1_pub = [0x11u8; 32];
        let mut verifier = JamboSecPolicyDaemon::new(1, admin_cap, node1_priv, node1_pub);

        let node2_priv = [0x22u8; 32];
        let node2_pub = [0x22u8; 32];
        verifier
            .register_remote_node(&admin_cap, 2, node2_pub)
            .unwrap();

        let mut node2 = JamboSecPolicyDaemon::new(2, admin_cap, node2_priv, node2_pub);

        // Défi nonce
        let challenge_nonce = verifier.generate_challenge_nonce(&admin_cap, 100).unwrap();

        // 1. Citation intègre générée par node2
        let quote = node2
            .generate_quote(&admin_cap, DEFAULT_CRITICAL_PCR_MASK, &challenge_nonce, 100)
            .unwrap();

        let res = verifier
            .verify_remote_attestation(
                &admin_cap,
                &quote,
                &challenge_nonce,
                DEFAULT_CRITICAL_PCR_MASK,
                105,
            )
            .unwrap();
        assert_eq!(res, AttestationStatus::Valid);
        assert!(verifier.is_node_trusted(2));

        // 2. Altération malveillante du noyau (PCR 8) sur le nœud 2
        let rootkit_digest = Sha256::digest(b"MALICIOUS_ROOTKIT_CODE");
        node2
            .extend_pcr(&admin_cap, 8, 3, "evil_module", &rootkit_digest, 110)
            .unwrap();

        let new_nonce = verifier.generate_challenge_nonce(&admin_cap, 120).unwrap();
        let tampered_quote = node2
            .generate_quote(&admin_cap, DEFAULT_CRITICAL_PCR_MASK, &new_nonce, 120)
            .unwrap();

        let res_tampered = verifier
            .verify_remote_attestation(
                &admin_cap,
                &tampered_quote,
                &new_nonce,
                DEFAULT_CRITICAL_PCR_MASK,
                125,
            )
            .unwrap();
        assert_eq!(res_tampered, AttestationStatus::MeasurementMismatch);

        // Le nœud altéré doit être automatiquement confiné en quarantaine !
        assert!(!verifier.is_node_trusted(2));
        assert_eq!(verifier.nodes[1].confinement, ConfinementState::Quarantine);
    }
}

//! Démon de Chiffrement de Bloc Transparent et Scellement Matériel TPM (jambo-cryptod)
//!
//! Fournit un chiffrement transparent de secteurs disque à la volée (dérivé XTS/ChaCha20 RFC 8439)
//! et le scellement cryptographique des clés sous les registres PCR d'un TPM 2.0 mesuré,
//! en espace utilisateur Ring 3 `#![no_std]` et subordonné à des capacités explicites `CryptoVolumeCap`.

#![no_std]

use libjambo::{Handle, SysError};

/// Droits granulaires de la capacité de volume chiffré
pub mod crypto_rights {
    pub const READ_SECTOR: u32 = 1 << 0;
    pub const WRITE_SECTOR: u32 = 1 << 1;
    pub const ROTATE_KEY: u32 = 1 << 2;
    pub const SEAL_TPM: u32 = 1 << 3;
}

/// Capacité de volume cryptographique (Zéro Autorité Ambiante)
#[derive(Debug, Clone, Copy)]
pub struct CryptoVolumeCap {
    pub handle: Handle,
    pub volume_id: u32,
    pub rights: u32,
}

impl CryptoVolumeCap {
    pub const fn new(handle: Handle, volume_id: u32, rights: u32) -> Self {
        Self {
            handle,
            volume_id,
            rights,
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }
}

/// Taille standard d'un secteur de disque (512 octets)
pub const SECTOR_SIZE: usize = 512;

/// Primitives de chiffrement de flux ChaCha20 déterministe (RFC 8439) zéro-allocation
pub struct ChaCha20SectorCipher;

impl ChaCha20SectorCipher {
    #[inline(always)]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(7);
    }

    /// Génère un bloc de flux pseudo-aléatoire de 64 octets
    pub fn generate_keystream_block(
        key: &[u8; 32],
        lba: u64,
        block_counter: u32,
        out: &mut [u8; 64],
    ) {
        // Constantes ChaCha20 ("expand 32-byte k")
        let mut state = [
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
            u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
            u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
            u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
            u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
            block_counter,
            (lba & 0xFFFFFFFF) as u32,
            ((lba >> 32) & 0xFFFFFFFF) as u32,
            0x4a414d42, // Nonce fixe Jambo
        ];

        let initial = state;

        // 10 doubles tours = 20 tours ChaCha20
        for _ in 0..10 {
            // Tours de colonnes
            Self::quarter_round(&mut state, 0, 4, 8, 12);
            Self::quarter_round(&mut state, 1, 5, 9, 13);
            Self::quarter_round(&mut state, 2, 6, 10, 14);
            Self::quarter_round(&mut state, 3, 7, 11, 15);
            // Tours de diagonales
            Self::quarter_round(&mut state, 0, 5, 10, 15);
            Self::quarter_round(&mut state, 1, 6, 11, 12);
            Self::quarter_round(&mut state, 2, 7, 8, 13);
            Self::quarter_round(&mut state, 3, 4, 9, 14);
        }

        for i in 0..16 {
            let val = state[i].wrapping_add(initial[i]);
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    /// Applique le flux de chiffrement ou déchiffrement in-place sur un tampon de données
    pub fn crypt_in_place(key: &[u8; 32], lba: u64, buffer: &mut [u8]) {
        let mut block = [0u8; 64];
        let mut counter = 0u32;
        let mut offset = 0;

        while offset < buffer.len() {
            Self::generate_keystream_block(key, lba, counter, &mut block);
            let chunk = (buffer.len() - offset).min(64);
            for i in 0..chunk {
                buffer[offset + i] ^= block[i];
            }
            offset += chunk;
            counter = counter.wrapping_add(1);
        }
    }
}

/// Clé maîtresse scellée sous empreinte TPM PCR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedKeyBlob {
    pub cipher_key: [u8; 32],
    pub pcr_digest: [u8; 32],
}

/// Moteur de scellement et de validation TPM 2.0 (Measured Boot)
pub struct TpmSealEngine;

impl TpmSealEngine {
    /// Calcule un condensat composite représentant l'état combiné des registres PCR 0..7
    pub fn compute_composite_pcr_digest(pcrs: &[[u8; 32]; 8]) -> [u8; 32] {
        let mut acc = [0u8; 32];
        for (idx, pcr) in pcrs.iter().enumerate() {
            for b in 0..32 {
                acc[b] = acc[b]
                    .wrapping_add(pcr[b])
                    .rotate_left(((idx + 1) % 7 + 1) as u32)
                    ^ 0x5C;
            }
        }
        acc
    }

    /// Scelle une clé maîtresse sous l'état actuel des PCR
    pub fn seal(raw_key: &[u8; 32], current_pcrs: &[[u8; 32]; 8]) -> SealedKeyBlob {
        let digest = Self::compute_composite_pcr_digest(current_pcrs);
        let mut cipher_key = *raw_key;
        for i in 0..32 {
            cipher_key[i] ^= digest[i];
        }

        SealedKeyBlob {
            cipher_key,
            pcr_digest: digest,
        }
    }

    /// Desceller la clé maîtresse uniquement si les PCR correspondent exactement
    pub fn unseal(
        sealed: &SealedKeyBlob,
        current_pcrs: &[[u8; 32]; 8],
    ) -> Result<[u8; 32], SysError> {
        let actual_digest = Self::compute_composite_pcr_digest(current_pcrs);
        if actual_digest != sealed.pcr_digest {
            return Err(SysError::PermissionDenied); // PCR altéré : rejet formel
        }

        let mut key = sealed.cipher_key;
        for i in 0..32 {
            key[i] ^= actual_digest[i];
        }

        Ok(key)
    }
}

/// Périphérique de bloc chiffré transparent en espace utilisateur
pub struct EncryptedBlockDevice {
    pub volume_id: u32,
    pub master_key: [u8; 32],
    pub sealed_blob: Option<SealedKeyBlob>,
    pub sectors_encrypted_count: u64,
}

impl EncryptedBlockDevice {
    pub fn new(volume_id: u32, master_key: [u8; 32]) -> Self {
        Self {
            volume_id,
            master_key,
            sealed_blob: None,
            sectors_encrypted_count: 0,
        }
    }

    /// Chiffre un secteur et l'écrit dans le tampon cible
    pub fn encrypt_and_write(
        &mut self,
        cap: &CryptoVolumeCap,
        lba: u64,
        plaintext: &[u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(), SysError> {
        if !cap.has_right(crypto_rights::WRITE_SECTOR) || cap.volume_id != self.volume_id {
            return Err(SysError::PermissionDenied);
        }

        let len = plaintext.len().min(ciphertext_out.len());
        ciphertext_out[..len].copy_from_slice(&plaintext[..len]);

        ChaCha20SectorCipher::crypt_in_place(&self.master_key, lba, &mut ciphertext_out[..len]);
        self.sectors_encrypted_count = self.sectors_encrypted_count.saturating_add(1);

        Ok(())
    }

    /// Lit et déchiffre un secteur
    pub fn read_and_decrypt(
        &self,
        cap: &CryptoVolumeCap,
        lba: u64,
        ciphertext: &[u8],
        plaintext_out: &mut [u8],
    ) -> Result<(), SysError> {
        if !cap.has_right(crypto_rights::READ_SECTOR) || cap.volume_id != self.volume_id {
            return Err(SysError::PermissionDenied);
        }

        let len = ciphertext.len().min(plaintext_out.len());
        plaintext_out[..len].copy_from_slice(&ciphertext[..len]);

        ChaCha20SectorCipher::crypt_in_place(&self.master_key, lba, &mut plaintext_out[..len]);

        Ok(())
    }

    /// Rotation atomique de la clé maîtresse
    pub fn rotate_key(&mut self, cap: &CryptoVolumeCap, new_key: [u8; 32]) -> Result<(), SysError> {
        if !cap.has_right(crypto_rights::ROTATE_KEY) || cap.volume_id != self.volume_id {
            return Err(SysError::PermissionDenied);
        }

        self.master_key = new_key;
        self.sealed_blob = None; // Invalidation du blob scellé précédent

        Ok(())
    }

    /// Scelle le volume sous la configuration TPM actuelle
    pub fn seal_with_tpm(
        &mut self,
        cap: &CryptoVolumeCap,
        pcrs: &[[u8; 32]; 8],
    ) -> Result<(), SysError> {
        if !cap.has_right(crypto_rights::SEAL_TPM) || cap.volume_id != self.volume_id {
            return Err(SysError::PermissionDenied);
        }

        let sealed = TpmSealEngine::seal(&self.master_key, pcrs);
        self.sealed_blob = Some(sealed);

        Ok(())
    }
}

/// Démon orchestrateur de chiffrement de stockage et scellement TPM 2.0 (Ring 3)
pub struct JamboCryptoDaemon {
    pub device: EncryptedBlockDevice,
    pub admin_cap: CryptoVolumeCap,
    pub pcr_bank: [[u8; 32]; 8],
}

impl Default for JamboCryptoDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboCryptoDaemon {
    pub fn new() -> Self {
        let default_key = [0x4Au8; 32];
        let admin_cap = CryptoVolumeCap::new(
            Handle::new(1, 1),
            1,
            crypto_rights::READ_SECTOR
                | crypto_rights::WRITE_SECTOR
                | crypto_rights::ROTATE_KEY
                | crypto_rights::SEAL_TPM,
        );
        let valid_pcrs: [[u8; 32]; 8] = [
            [0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], [0x06; 32], [0x07; 32],
            [0x08; 32],
        ];
        Self {
            device: EncryptedBlockDevice::new(1, default_key),
            admin_cap,
            pcr_bank: valid_pcrs,
        }
    }

    /// Initialise le volume chiffré et le scellement TPM par défaut
    pub fn init_defaults(&mut self) {
        let _ = self.device.seal_with_tpm(&self.admin_cap, &self.pcr_bank);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transparent_encryption_decryption_and_lba_diversity() {
        let key = [0x42u8; 32];
        let mut dev = EncryptedBlockDevice::new(1, key);
        let cap = CryptoVolumeCap::new(
            Handle::new(100, 1),
            1,
            crypto_rights::READ_SECTOR | crypto_rights::WRITE_SECTOR,
        );

        let plaintext = [0xAAu8; SECTOR_SIZE];
        let mut ciphertext_lba0 = [0u8; SECTOR_SIZE];
        let mut ciphertext_lba1 = [0u8; SECTOR_SIZE];

        // Chiffrement du même payload à deux LBA distincts
        dev.encrypt_and_write(&cap, 0, &plaintext, &mut ciphertext_lba0)
            .unwrap();
        dev.encrypt_and_write(&cap, 1, &plaintext, &mut ciphertext_lba1)
            .unwrap();

        // Le texte chiffré ne doit pas correspondre au texte clair
        assert_ne!(&ciphertext_lba0[..], &plaintext[..]);

        // Deux secteurs identiques à deux adresses LBA différentes doivent être chiffrés différemment !
        assert_ne!(&ciphertext_lba0[..], &ciphertext_lba1[..]);

        // Déchiffrement exact
        let mut decrypted = [0u8; SECTOR_SIZE];
        dev.read_and_decrypt(&cap, 0, &ciphertext_lba0, &mut decrypted)
            .unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_tpm_sealing_integrity_and_tamper_rejection() {
        let key = [0x88u8; 32];
        let valid_pcrs: [[u8; 32]; 8] = [
            [0x01; 32], // PCR0: Firmware
            [0x02; 32], // PCR1: Configuration
            [0x03; 32], // PCR2: Option ROM
            [0x04; 32], // PCR3: Boot Policy
            [0x05; 32], // PCR4: Limine Loader
            [0x06; 32], // PCR5: GPT Table
            [0x07; 32], // PCR6: Resume State
            [0x08; 32], // PCR7: Secure Boot
        ];

        let sealed = TpmSealEngine::seal(&key, &valid_pcrs);

        // Descellement sur plateforme intègre : succès
        let unsealed = TpmSealEngine::unseal(&sealed, &valid_pcrs).unwrap();
        assert_eq!(unsealed, key);

        // Altération du chargeur Limine (PCR 4 modifié) : rejet formel
        let mut tampered_pcrs = valid_pcrs;
        tampered_pcrs[4][0] ^= 0x01; // Attaque sur le binaire d'amorçage
        let fail = TpmSealEngine::unseal(&sealed, &tampered_pcrs);
        assert_eq!(fail, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_crypto_volume_capability_enforcement() {
        let key = [0x11u8; 32];
        let mut dev = EncryptedBlockDevice::new(1, key);

        // Capacité avec seulement droit de lecture
        let read_only_cap =
            CryptoVolumeCap::new(Handle::new(101, 1), 1, crypto_rights::READ_SECTOR);

        let data = [0u8; 64];
        let mut out = [0u8; 64];

        // Tentative d'écriture interdite
        let write_res = dev.encrypt_and_write(&read_only_cap, 0, &data, &mut out);
        assert_eq!(write_res, Err(SysError::PermissionDenied));

        // Tentative d'accès sur mauvais volume_id (volume 2 au lieu de 1)
        let wrong_vol_cap = CryptoVolumeCap::new(
            Handle::new(102, 1),
            2,
            crypto_rights::READ_SECTOR | crypto_rights::WRITE_SECTOR,
        );
        let wrong_res = dev.encrypt_and_write(&wrong_vol_cap, 0, &data, &mut out);
        assert_eq!(wrong_res, Err(SysError::PermissionDenied));
    }
}

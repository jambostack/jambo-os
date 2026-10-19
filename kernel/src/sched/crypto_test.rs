//! Module de validation du Chiffrement de Bloc Transparent & Scellement Matériel TPM 2.0 (Phase 54 - v0.2.52)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_cryptod::{
    crypto_rights, ChaCha20SectorCipher, CryptoVolumeCap, EncryptedBlockDevice, JamboCryptoDaemon,
    SealedKeyBlob, TpmSealEngine, SECTOR_SIZE,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de chiffrement de secteur à la volée et scellement TPM mesuré (Phase 54)
pub fn execute_transparent_crypto_test() -> bool {
    kprintln!(
        "[CRYPTO/TEST] Démarrage du test de chiffrement de bloc transparent & scellement TPM (Phase 54)..."
    );

    // 1. Validation du chiffrement de secteur transparent ChaCha20 RFC 8439 & diversité LBA
    let master_key = [0x77u8; 32];
    let mut dev = EncryptedBlockDevice::new(1, master_key);
    let admin_cap = CryptoVolumeCap::new(
        Handle::new(1, 1),
        1,
        crypto_rights::READ_SECTOR
            | crypto_rights::WRITE_SECTOR
            | crypto_rights::ROTATE_KEY
            | crypto_rights::SEAL_TPM,
    );

    let plaintext = [0x5Au8; SECTOR_SIZE];
    let mut cipher_lba0 = [0u8; SECTOR_SIZE];
    let mut cipher_lba1 = [0u8; SECTOR_SIZE];

    // Chiffrement sur deux LBA distincts
    assert!(dev
        .encrypt_and_write(&admin_cap, 0, &plaintext, &mut cipher_lba0)
        .is_ok());
    assert!(dev
        .encrypt_and_write(&admin_cap, 1, &plaintext, &mut cipher_lba1)
        .is_ok());

    // Le texte chiffré doit différer du texte clair
    assert_ne!(&cipher_lba0[..], &plaintext[..]);
    // Diversité LBA : Deux secteurs identiques à deux LBA distincts ont des flux cryptographiques différents
    assert_ne!(&cipher_lba0[..], &cipher_lba1[..]);

    // Déchiffrement exact
    let mut decrypted = [0u8; SECTOR_SIZE];
    assert!(dev
        .read_and_decrypt(&admin_cap, 0, &cipher_lba0, &mut decrypted)
        .is_ok());
    assert_eq!(&decrypted[..], &plaintext[..]);
    kprintln!("[CRYPTO/CHACHA20] Chiffrement/déchiffrement de secteur et diversité LBA validés");

    // 2. Validation du confinement strict par capacité CryptoVolumeCap (Zero-Ambient Authority)
    let read_only_cap = CryptoVolumeCap::new(Handle::new(10, 1), 1, crypto_rights::READ_SECTOR);
    let mut dummy_out = [0u8; SECTOR_SIZE];

    // Tentative d'écriture interdite avec capacité read-only
    let rogue_write = dev.encrypt_and_write(&read_only_cap, 0, &plaintext, &mut dummy_out);
    assert_eq!(
        rogue_write,
        Err(SysError::PermissionDenied),
        "Une écriture sans droit WRITE_SECTOR doit être rejetée"
    );

    // Tentative d'accès sur un autre volume (volume 2 au lieu de 1)
    let wrong_vol_cap = CryptoVolumeCap::new(
        Handle::new(11, 1),
        2,
        crypto_rights::READ_SECTOR | crypto_rights::WRITE_SECTOR,
    );
    let rogue_vol = dev.encrypt_and_write(&wrong_vol_cap, 0, &plaintext, &mut dummy_out);
    assert_eq!(
        rogue_vol,
        Err(SysError::PermissionDenied),
        "Tout accès sur un volume non autorisé doit être rejeté"
    );
    kprintln!("[CRYPTO/CAP] Confinement strict des droits CryptoVolumeCap (Zero-Ambient Authority) validé");

    // 3. Validation du scellement matériel TPM 2.0 (Measured Boot)
    let valid_pcrs: [[u8; 32]; 8] = [
        [0x10; 32], // PCR0
        [0x11; 32], // PCR1
        [0x12; 32], // PCR2
        [0x13; 32], // PCR3
        [0x14; 32], // PCR4
        [0x15; 32], // PCR5
        [0x16; 32], // PCR6
        [0x17; 32], // PCR7
    ];

    let sealed_blob = TpmSealEngine::seal(&master_key, &valid_pcrs);
    let unsealed_key = TpmSealEngine::unseal(&sealed_blob, &valid_pcrs);
    assert_eq!(
        unsealed_key,
        Ok(master_key),
        "Descellement légitime TPM réussi"
    );

    // Altération simulée de la chaîne de démarrage (ex: injection de code dans Limine - PCR 4)
    let mut corrupted_pcrs = valid_pcrs;
    corrupted_pcrs[4][0] ^= 0xFF;
    let corrupted_unseal = TpmSealEngine::unseal(&sealed_blob, &corrupted_pcrs);
    assert_eq!(
        corrupted_unseal,
        Err(SysError::PermissionDenied),
        "Toute modification de l'état mesuré PCR doit bloquer le descellement de la clé"
    );
    kprintln!("[CRYPTO/TPM] Scellement/descellement sous registres PCR 0..7 & détection d'altération validés");

    // 4. Validation du démon JamboCryptoDaemon
    let mut daemon = JamboCryptoDaemon::new();
    daemon.init_defaults();
    assert!(daemon.device.sealed_blob.is_some());
    assert_eq!(daemon.device.volume_id, 1);
    kprintln!("[CRYPTO/DAEMON] Démon JamboCryptoDaemon opérationnel de bout en bout");

    // 5. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'crypto status'
    let (st_stat, len_stat) = shell.execute_line("crypto status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("CHIFFREMENT DE BLOC TRANSPARENT"));
    assert!(str_stat.contains("ChaCha20"));
    kprintln!("[CRYPTO/SHELL] Commande 'crypto status' validée");

    // Commande 'crypto encrypt 0 SecretData'
    let (st_enc, len_enc) = shell.execute_line("crypto encrypt 0 SecretData", &mut out_buf);
    assert_eq!(st_enc, ShellStatus::Success);
    let str_enc = core::str::from_utf8(&out_buf[..len_enc]).unwrap_or("");
    assert!(str_enc.contains("chiffré et écrit avec succès"));
    kprintln!("[CRYPTO/SHELL] Commande 'crypto encrypt' validée");

    // Commande 'crypto seal'
    let (st_seal, len_seal) = shell.execute_line("crypto seal", &mut out_buf);
    assert_eq!(st_seal, ShellStatus::Success);
    let str_seal = core::str::from_utf8(&out_buf[..len_seal]).unwrap_or("");
    assert!(str_seal.contains("scellée sous l'empreinte composite"));
    kprintln!("[CRYPTO/SHELL] Commande 'crypto seal' validée");

    // Commande 'crypto verify'
    let (st_verif, len_verif) = shell.execute_line("crypto verify", &mut out_buf);
    assert_eq!(st_verif, ShellStatus::Success);
    let str_verif = core::str::from_utf8(&out_buf[..len_verif]).unwrap_or("");
    assert!(str_verif.contains("Intégrité de la plateforme (Measured Boot) validée"));
    kprintln!("[CRYPTO/SHELL] Commande 'crypto verify' validée");

    kprintln!(
        "[CRYPTO/PASS] Chiffrement de bloc transparent & scellement matériel TPM validés avec succès."
    );
    true
}

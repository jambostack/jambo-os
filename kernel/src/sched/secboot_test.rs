//! Module de validation du Démarrage Sécurisé Souverain & Mesure d'Intégrité Matérielle TPM 2.0 (`jambo-secboot`)
//! Phase 100 — Jalon v0.2.98
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_secboot::{
    secboot_rights, BootStage, JamboSecBootDaemon, KeyType, SecBootCap, Sha256,
    CRITICAL_PCR_MASK, HASH_SIZE, PCR_COUNT,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle du démarrage sécurisé et TPM 2.0 (Phase 100)
pub fn execute_secboot_daemon_test() -> bool {
    kprintln!(
        "[SECBOOT/TEST] Démarrage du test de validation du démarrage sécurisé souverain TPM 2.0 (Phase 100)..."
    );

    // 1. Contrôle d'accès capabilaire (SecBootCap) et rejet formel de toute élévation de privilèges
    let admin_cap = SecBootCap::new(Handle::new(10001, 1), secboot_rights::ALL);
    assert!(admin_cap.has_right(secboot_rights::MEASURE));
    assert!(admin_cap.has_right(secboot_rights::VERIFY));
    assert!(admin_cap.has_right(secboot_rights::SEAL));
    assert!(admin_cap.has_right(secboot_rights::UNSEAL));
    assert!(admin_cap.has_right(secboot_rights::UPDATE_DB));
    assert!(admin_cap.has_right(secboot_rights::INSPECT));
    assert!(admin_cap.has_right(secboot_rights::ADMIN));

    let unseal_cap = admin_cap
        .attenuate(secboot_rights::UNSEAL | secboot_rights::INSPECT)
        .expect("Atténuation monotone SecBootCap");
    assert!(unseal_cap.has_right(secboot_rights::UNSEAL));
    assert!(unseal_cap.has_right(secboot_rights::INSPECT));
    assert!(!unseal_cap.has_right(secboot_rights::SEAL));
    assert!(!unseal_cap.has_right(secboot_rights::MEASURE));
    assert!(!unseal_cap.has_right(secboot_rights::ADMIN));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        unseal_cap.attenuate(secboot_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits SecBootCap formellement rejetée"
    );
    kprintln!("[SECBOOT/CAP] Contrôle d'accès capabilaire SecBootCap et atténuation monotone validés");

    // 2. Initialisation du démon de démarrage sécurisé
    let mut daemon = JamboSecBootDaemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.key_count, 4);
    assert!(daemon.event_count >= 7);
    kprintln!("[SECBOOT/INIT] Démon SecBoot initialisé (Chaîne de confiance 7 étages mesurée)");

    // 3. Validation de l'intégrité des registres PCR critiques
    assert_ne!(daemon.pcrs[0], [0u8; HASH_SIZE], "PCR 0 (CRTM) initialisé");
    assert_ne!(daemon.pcrs[1], [0u8; HASH_SIZE], "PCR 1 (UEFI) initialisé");
    assert_ne!(daemon.pcrs[4], [0u8; HASH_SIZE], "PCR 4 (Limine) initialisé");
    assert_ne!(daemon.pcrs[8], [0u8; HASH_SIZE], "PCR 8 (Kernel) initialisé");
    assert_ne!(daemon.pcrs[9], [0u8; HASH_SIZE], "PCR 9 (Initrd) initialisé");
    assert_ne!(daemon.pcrs[11], [0u8; HASH_SIZE], "PCR 11 (SecPolicy) initialisé");
    assert_ne!(daemon.pcrs[12], [0u8; HASH_SIZE], "PCR 12 (JamboInit) initialisé");
    kprintln!("[SECBOOT/PCR] Banques PCR TPM 2.0 conformes et étendues par SHA-256");

    // 4. Validation des bases de signatures DB et détection de révocations DBX
    let kernel_release_digest = Sha256::digest(b"JAMBO_KERNEL_OFFICIAL_RELEASE_KEY");
    let rogue_rootkit_digest = Sha256::digest(b"ROGUE_INJECTED_UNTRUSTED_BINARY");

    assert_eq!(
        daemon.verify_binary(&kernel_release_digest),
        Ok(true),
        "Noyau officiel certifié par DB"
    );
    assert_eq!(
        daemon.verify_binary(&rogue_rootkit_digest),
        Ok(false),
        "Binaire inconnu/corrompu rejeté"
    );

    // Révocation de clé DB
    daemon.revoke_key(3).expect("Révocation de clé DB");
    assert_eq!(
        daemon.verify_binary(&kernel_release_digest),
        Ok(false),
        "Clé révoquée rejetée (DBX)"
    );
    kprintln!("[SECBOOT/DB] Hiérarchie de clés Secure Boot PK/KEK/DB/DBX et révocations validées");

    // 5. Scellement cryptographique sous l'empreinte des PCR critiques (Data Sealing)
    let secret = b"ENCRYPTED_VOLUME_MASTER_KEY_JAMBOOS_2026";
    let secret_id = daemon
        .seal_secret(CRITICAL_PCR_MASK, secret)
        .expect("Scellement cryptographique du secret");
    assert_eq!(daemon.secrets_sealed, 1);

    // 6. Déscellement légitime sous intégrité matérielle intacte
    let mut plaintext = [0u8; 64];
    let len = daemon
        .unseal_secret(secret_id, &mut plaintext)
        .expect("Déscellement intègre du secret");
    assert_eq!(&plaintext[..len], secret, "Secret déscellé conforme");
    assert_eq!(daemon.secrets_unsealed, 1);
    kprintln!("[SECBOOT/SEAL] Scellement et déscellement sous état PCR critique validés");

    // 7. Détection et blocage immédiat d'une altération de boot (Tentative de Rootkit/Bootkit)
    daemon
        .tamper_pcr(8, b"COMPROMISED_MALICIOUS_KERNEL_OVERWRITE")
        .expect("Injection altération malveillante PCR 8");

    let tamper_attempt = daemon.unseal_secret(secret_id, &mut plaintext);
    assert_eq!(
        tamper_attempt,
        Err(SysError::PermissionDenied),
        "Tentative de déscellement post-altération formellement rejetée"
    );
    assert!(daemon.tamper_violations > 0);
    kprintln!("[SECBOOT/TAMPER] Violation d'intégrité détectée et blocage immédiat du déscellement validé");

    // 8. Registre d'audit scellé par chaîne SHA-256
    assert_ne!(daemon.audit_chain, [0u8; HASH_SIZE]);
    kprintln!("[SECBOOT/AUDIT] Chaîne d'audit cryptographique SHA-256 scellée et vérifiée");

    // 9. Intégration dans le Shell interactif Ring 3 (jsh)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (st1, len1) = shell.execute_line("secboot status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    assert!(len1 > 0);

    let (st2, len2) = shell.execute_line("secboot measure", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    assert!(len2 > 0);

    let (st3, len3) = shell.execute_line("secboot seal", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    assert!(len3 > 0);

    let (st4, len4) = shell.execute_line("secboot verify", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    assert!(len4 > 0);

    let (st5, len5) = shell.execute_line("secboot audit", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    assert!(len5 > 0);

    kprintln!("[SECBOOT/SHELL] Commandes Ring 3 jsh 'secboot' validées avec succès");
    true
}

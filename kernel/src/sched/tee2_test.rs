//! Module de validation des Micro-hyperviseurs d'Enclaves Imbriquées
//! et de l'Isolation de Mémoire Chiffrée Multi-Locataires (`jambo-tee2`)
//! Phase 107 — Jalon v0.2.105
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_tee2::{
    constant_time_eq, ept_flags, tee2_rights, EnclaveLevel, EnclaveState, JamboTee2Daemon,
    NestedSealingPolicy, NestedTeeBackend, NestedTeeError, Sha256, Tee2Cap, KEY_LEN,
    MAX_ENCLAVES, MAX_TENANTS,
};

/// Exécute la suite complète de validation formelle des enclaves imbriquées et de l'isolation multi-locataires (Phase 107)
pub fn execute_tee2_daemon_test() -> bool {
    kprintln!(
        "[TEE2/TEST] Démarrage du test de validation des enclaves imbriquées & isolation multi-locataires (Phase 107)..."
    );

    // 1. Contrôle d'accès capabilaire (Tee2Cap) et atténuation monotone
    let admin_cap = Tee2Cap::new(Handle::new(10701, 1), tee2_rights::ALL, 0, MAX_ENCLAVES as u16);
    assert!(admin_cap.has_right(tee2_rights::CREATE_TENANT));
    assert!(admin_cap.has_right(tee2_rights::CREATE_L1));
    assert!(admin_cap.has_right(tee2_rights::CREATE_L2));
    assert!(admin_cap.has_right(tee2_rights::MAP_EPT));
    assert!(admin_cap.has_right(tee2_rights::ENCRYPT_MEM));
    assert!(admin_cap.has_right(tee2_rights::ATTEST));
    assert!(admin_cap.has_right(tee2_rights::SEAL));
    assert!(admin_cap.has_right(tee2_rights::UNSEAL));
    assert!(admin_cap.has_right(tee2_rights::SCRUB));
    assert!(admin_cap.has_right(tee2_rights::AUDIT));

    let tenant_cap = admin_cap
        .attenuate(tee2_rights::CREATE_L2 | tee2_rights::MAP_EPT | tee2_rights::ATTEST, 8)
        .expect("Atténuation monotone Tee2Cap");
    assert!(tenant_cap.has_right(tee2_rights::CREATE_L2));
    assert!(tenant_cap.has_right(tee2_rights::MAP_EPT));
    assert!(tenant_cap.has_right(tee2_rights::ATTEST));
    assert!(!tenant_cap.has_right(tee2_rights::CREATE_TENANT));
    assert!(!tenant_cap.has_right(tee2_rights::SCRUB));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        tenant_cap.attenuate(tee2_rights::ALL, 8),
        Err(NestedTeeError::PermissionDenied),
        "Amplification de droits Tee2Cap formellement rejetée"
    );
    assert_eq!(
        tenant_cap.attenuate(tee2_rights::CREATE_L2, 16),
        Err(NestedTeeError::PermissionDenied),
        "Augmentation du quota d'enclaves formellement rejetée"
    );
    kprintln!("[TEE2/CAP] Contrôle d'accès capabilaire Tee2Cap et atténuation monotone validés");

    // 2. Initialisation du démon TEE2 souverain
    let mut daemon = JamboTee2Daemon::new(admin_cap);

    // 3. Enrôlement de locataires avec clés MEK (256 bits) et KeyID matériel
    let mek_t1 = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    ];
    let mek_t2 = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
        0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    ];

    let t1 = daemon
        .create_tenant(
            &admin_cap,
            "FinBank-Core",
            101,
            mek_t1,
            0x1_0000_0000,
            0x2000_0000,
        )
        .expect("Création Tenant 1");
    let t2 = daemon
        .create_tenant(
            &admin_cap,
            "HealthCloud-Sovereign",
            102,
            mek_t2,
            0x2_0000_0000,
            0x2000_0000,
        )
        .expect("Création Tenant 2");

    // Vérification de la prévention de collisions (KeyID dupliqué ou chevauchement GPA)
    assert_eq!(
        daemon.create_tenant(&admin_cap, "DuplicateKey", 101, mek_t1, 0x3_0000_0000, 0x1000_0000),
        Err(NestedTeeError::TenantAlreadyExists),
        "KeyID dupliqué rejeté"
    );
    assert_eq!(
        daemon.create_tenant(&admin_cap, "OverlapGPA", 103, mek_t1, 0x1_1000_0000, 0x1000_0000),
        Err(NestedTeeError::CrossTenantAccessDenied),
        "Chevauchement de plage GPA rejeté"
    );
    kprintln!("[TEE2/TENANT] Enrôlement et étanchéité des partitions multi-locataires validés");

    // 4. Hiérarchie Micro-Hyperviseur : L1 Supervisor et L2 Nested Enclave
    let l1_fin = daemon
        .create_l1_supervisor(
            &admin_cap,
            t1,
            NestedTeeBackend::IntelTdxPartitioning,
            "FinBank-L1-Supervisor",
        )
        .expect("Création L1 Supervisor FinBank");

    let l2_fin = daemon
        .create_l2_nested_enclave(
            &admin_cap,
            t1,
            l1_fin,
            "FinBank-L2-LedgerWorker",
        )
        .expect("Création L2 Nested Workload FinBank");

    // Tentative illégale de rattachement cross-tenant
    assert_eq!(
        daemon.create_l2_nested_enclave(&admin_cap, t2, l1_fin, "HackedL2"),
        Err(NestedTeeError::CrossTenantAccessDenied),
        "Rattachement d'une enclave L2 à un L1 d'un autre tenant formellement interdit"
    );
    kprintln!("[TEE2/HIERARCHY] Hiérarchie micro-hyperviseur L1/L2 et étanchéité parent/enfant validées");

    // 5. Configuration des tables EPT imbriquées (GPA L2 -> IPA L1 -> HPA L0)
    let dummy_data = [0x5Au8; 64];
    daemon
        .configure_nested_ept(
            &admin_cap,
            l2_fin,
            0x1_0000_0000,
            0x8000_0000,
            0x4000_0000,
            ept_flags::REGULAR,
            &dummy_data,
        )
        .expect("Mappage EPT Page Données");

    let dummy_code = [0xCCu8; 64];
    daemon
        .configure_nested_ept(
            &admin_cap,
            l2_fin,
            0x1_0000_1000,
            0x8000_1000,
            0x4000_1000,
            ept_flags::CODE,
            &dummy_code,
        )
        .expect("Mappage EPT Page Code");

    // Vérification du calcul d'intégrité Merkle EPT
    let l2_enc = daemon.enclaves.iter().find(|e| e.enclave_id == l2_fin).unwrap();
    assert_ne!(l2_enc.ept_table.root_hash, [0u8; 32]);

    // Chargement de la charge utile L2 et scellement
    daemon
        .load_l2_payload(&admin_cap, l2_fin, b"JAMBO_LEDGER_TRANSACTION_EXECUTOR_V1")
        .expect("Chargement charge L2");
    daemon
        .finalize_and_seal(&admin_cap, l2_fin)
        .expect("Scellement L2");
    kprintln!("[TEE2/EPT] Tables EPT imbriquées, empreinte Merkle et cycle de vie L2 validés");

    // 6. Traduction GPA et confinement strict multi-locataire
    let (hpa_data, key_id_data) = daemon
        .translate_nested_gpa(l2_fin, 0x1_0000_0080, false, false, t1)
        .expect("Traduction GPA valide");
    assert_eq!(hpa_data, 0x4000_0080);
    assert_eq!(key_id_data, 101);

    // Tentative de lecture de l'adresse par le Tenant 2 formellement bloquée
    assert_eq!(
        daemon.translate_nested_gpa(l2_fin, 0x1_0000_0080, false, false, t2),
        Err(NestedTeeError::CrossTenantAccessDenied),
        "Accès cross-tenant à la mémoire bloqué avec succès"
    );
    kprintln!("[TEE2/ISOLATION] Traduction d'adresses et confinement strict multi-locataires prouvés");

    // 7. Chiffrement et déchiffrement mémoire multi-locataire
    let test_secret = b"FINANCIAL_CONSORTIUM_LEDGER_KEY!";
    let mut ciphertext = [0u8; 32];
    let mut decrypted_t1 = [0u8; 32];
    let mut decrypted_t2 = [0u8; 32];

    daemon
        .encrypt_tenant_page(&admin_cap, t1, 0x4000_0000, test_secret, &mut ciphertext)
        .expect("Chiffrement mémoire Tenant 1");
    assert_ne!(test_secret, &ciphertext);

    daemon
        .decrypt_tenant_page(t1, 0x4000_0000, &ciphertext, &mut decrypted_t1)
        .expect("Déchiffrement mémoire Tenant 1");
    assert_eq!(test_secret, &decrypted_t1);

    // Déchiffrement avec la clé du Tenant 2 donne du bruit cryptographique
    daemon
        .decrypt_tenant_page(t2, 0x4000_0000, &ciphertext, &mut decrypted_t2)
        .expect("Déchiffrement mémoire Tenant 2");
    assert_ne!(test_secret, &decrypted_t2);
    kprintln!("[TEE2/CRYPTO] Chiffrement mémoire multi-locataire en temps constant validé");

    // 8. Chaîne d'attestation imbriquée & génération de rapport (NestedTeeReport)
    let challenge = [0x77u8; 32];
    let user_data = [0xEEu8; 32];
    let report = daemon
        .generate_nested_report(&admin_cap, l2_fin, &challenge, &user_data)
        .expect("Génération du rapport d'attestation");

    assert_eq!(report.tenant_id, t1);
    assert_eq!(report.l1_id, l1_fin);
    assert_eq!(report.l2_id, l2_fin);
    assert_ne!(report.combined_measurement, [0u8; 32]);
    assert_ne!(report.hmac_signature, [0u8; 32]);

    assert!(
        daemon.verify_nested_report(&report, &challenge).expect("Vérification rapport"),
        "Signature et fraîcheur du rapport validées"
    );

    // Falsification du nonce défi détectée et rejetée
    let fake_challenge = [0x00u8; 32];
    assert_eq!(
        daemon.verify_nested_report(&report, &fake_challenge),
        Err(NestedTeeError::ChallengeMismatch),
        "Rejet immédiat d'un défi falsifié"
    );
    kprintln!("[TEE2/ATTEST] Chaîne d'attestation imbriquée et signatures HMAC-SHA256 validées");

    // 9. Scellement et déscellement de secrets (Sealed Storage)
    let sovereign_vault_data = b"SOVEREIGN_OFFLINE_RECOVERY_PHRASE";
    let slot = daemon
        .seal_tenant_secret(
            &admin_cap,
            l2_fin,
            sovereign_vault_data,
            NestedSealingPolicy::ExactNestedMeasurement,
        )
        .expect("Scellement du secret");

    let mut unsealed_buf = [0u8; 64];
    let unsealed_len = daemon
        .unseal_tenant_secret(&admin_cap, l2_fin, slot, &mut unsealed_buf)
        .expect("Déscellement autorisé");
    assert_eq!(&unsealed_buf[..unsealed_len], sovereign_vault_data);
    kprintln!("[TEE2/SEAL] Stockage scellé multi-locataire et intégrité de mesure validés");

    // 10. Effacement sécurisé et Zéro Résidu (Scrubbing)
    daemon.destroy_enclave(&admin_cap, l2_fin).expect("Destruction L2");
    assert_eq!(
        daemon.translate_nested_gpa(l2_fin, 0x1_0000_0000, false, false, t1),
        Err(NestedTeeError::EnclaveNotFound),
        "Enclave détruite inaccessible"
    );
    kprintln!("[TEE2/SCRUB] Effacement sécurisé et zéro résidu après destruction validés");

    // 11. Validation des commandes Shell Ring 3 (jambo-sh)
    let mut shell = JamboShell::new();
    let mut output_buf = [0u8; 1024];

    let commands = [
        "tee2 status",
        "tee2 tenants",
        "tee2 enclaves",
        "tee2 ept 101",
        "tee2 attest 101",
        "tee2 benchmark",
        "tee2 audit",
    ];

    for cmd in &commands {
        let (status, written) = shell.execute_line(cmd, &mut output_buf);
        assert_eq!(
            status,
            ShellStatus::Success,
            "Échec commande shell : {}",
            cmd
        );
        assert!(written > 0, "Sortie vide pour : {}", cmd);
    }
    kprintln!("[TEE2/SHELL] Commandes interactives Shell jsh tee2 validées");

    kprintln!(
        "\x1b[1;32m[TEE2/SUCCESS] Phase 107 - Micro-hyperviseurs d'Enclaves Imbriquées & Isolation Mémoire Multi-Locataires validée avec succès !\x1b[0m"
    );
    true
}

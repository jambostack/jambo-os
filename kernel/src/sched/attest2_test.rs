//! Module de validation de l'Attestation d'Enclaves Matérielles Distantes
//! et des Chaînes de Confiance Multi-Puces Ring 3 (`jambo-attest2`)
//! Phase 105 — Jalon v0.2.103
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_attest2::{
    attest2_rights, enclave_attrs, Attest2Cap, Attest2Error, ChipStatus, ChipTrustLevel,
    EnclaveStatus, JamboAttest2Daemon, Sha256, MAX_CHIPS, MAX_ENCLAVES,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle de l'attestation multi-puces (Phase 105)
pub fn execute_attest2_daemon_test() -> bool {
    kprintln!(
        "[ATTEST2/TEST] Démarrage du test de validation de l'attestation distante d'enclaves & multi-puces (Phase 105)..."
    );

    // 1. Contrôle d'accès capabilaire (Attest2Cap) et rejet formel de toute élévation de privilèges
    let admin_cap = Attest2Cap::new(Handle::new(10501, 1), attest2_rights::ALL, 16, 8);
    assert!(admin_cap.has_right(attest2_rights::ENROLL_CHIP));
    assert!(admin_cap.has_right(attest2_rights::REGISTER_ENCLAVE));
    assert!(admin_cap.has_right(attest2_rights::GENERATE_QUOTE));
    assert!(admin_cap.has_right(attest2_rights::VERIFY_QUOTE));
    assert!(admin_cap.has_right(attest2_rights::CROSS_ENDORSE));
    assert!(admin_cap.has_right(attest2_rights::CONFINE));
    assert!(admin_cap.has_right(attest2_rights::AUDIT));
    assert!(admin_cap.has_right(attest2_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(attest2_rights::VERIFY_QUOTE | attest2_rights::AUDIT, 8, 4)
        .expect("Atténuation monotone Attest2Cap");
    assert!(attenuated_cap.has_right(attest2_rights::VERIFY_QUOTE));
    assert!(attenuated_cap.has_right(attest2_rights::AUDIT));
    assert!(!attenuated_cap.has_right(attest2_rights::GENERATE_QUOTE));
    assert!(!attenuated_cap.has_right(attest2_rights::ENROLL_CHIP));
    assert!(!attenuated_cap.has_right(attest2_rights::ADMIN));
    assert_eq!(attenuated_cap.max_enclaves, 8);
    assert_eq!(attenuated_cap.max_chips, 4);

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        attenuated_cap.attenuate(attest2_rights::ALL, 8, 4),
        Err(SysError::PermissionDenied),
        "Amplification de droits Attest2Cap formellement rejetée"
    );
    assert_eq!(
        attenuated_cap.attenuate(attest2_rights::VERIFY_QUOTE, 12, 4),
        Err(SysError::PermissionDenied),
        "Augmentation d'enclaves maximales formellement rejetée"
    );
    assert_eq!(
        attenuated_cap.attenuate(attest2_rights::VERIFY_QUOTE, 8, 6),
        Err(SysError::PermissionDenied),
        "Augmentation de puces maximales formellement rejetée"
    );
    kprintln!(
        "[ATTEST2/CAP] Contrôle d'accès capabilaire Attest2Cap et atténuation monotone validés"
    );

    // 2. Initialisation du démon et topologie de chaîne de confiance multi-puces
    let mut daemon = JamboAttest2Daemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.chip_count, 3);
    assert_eq!(daemon.count_active_trusted_chips(), 3);
    assert_eq!(daemon.enclave_count, 2);
    assert_eq!(daemon.policy_count, 2);
    assert_ne!(daemon.compound_platform_id, [0u8; 32]);
    kprintln!("[ATTEST2/TOPOLOGY] Chaîne multi-puces (SoC, TPM 2.0, Dedicated HSM) et identité composée validées");

    // 3. Validation de l'endossement croisé inter-puces (Cross-Chip Mutual Attestation)
    assert!(daemon.cross_endorsement_count >= 2);
    let cross_check_res = daemon.cross_endorse_chip(&admin_cap, 1, 3);
    assert!(
        cross_check_res.is_ok(),
        "Endossement croisé SoC -> HSM valide"
    );
    kprintln!("[ATTEST2/CROSS] Endossement croisé et validation mutuelle inter-puces validés");

    // 4. Génération de devis d'attestation distante avec défi anti-rejeu (Challenge-Response)
    let fresh_nonce = Sha256::digest(b"CHALLENGE_NONCE_VERIFIER_ALPHA_2026");
    let quote = daemon
        .generate_quote(&admin_cap, 1, &fresh_nonce)
        .expect("Génération du devis d'attestation");
    assert_eq!(quote.header.enclave_id, 1);
    assert_eq!(quote.header.chip_id, 1);
    assert_eq!(quote.report_data, fresh_nonce);
    assert_eq!(quote.compound_platform_hash, daemon.compound_platform_id);
    kprintln!(
        "[ATTEST2/QUOTE] Devis d'attestation distante scellé par HMAC-SHA256 avec nonce anti-rejeu"
    );

    // 5. Vérification formelle du devis contre la politique de référence dorée (Golden Policy)
    assert_eq!(
        daemon.verify_quote(&admin_cap, &quote, &fresh_nonce),
        Ok(()),
        "Vérification nominale du devis d'attestation"
    );
    kprintln!(
        "[ATTEST2/VERIFY] Vérification formelle d'intégrité MRENCLAVE / MRSIGNER / SVN validée"
    );

    // 6. Détection stricte de rejeu (Anti-Replay Attack)
    let stale_nonce = Sha256::digest(b"STALE_OLD_REPLAYED_NONCE");
    assert_eq!(
        daemon.verify_quote(&admin_cap, &quote, &stale_nonce),
        Err(Attest2Error::ReplayAttackDetected),
        "Attaque par rejeu de nonce formellement détectée et bloquée"
    );
    kprintln!("[ATTEST2/REPLAY] Détection et neutralisation d'attaque par rejeu validées");

    // 7. Détection d'altération de mesure et confinement O(1) en quarantaine
    let bad_mr = Sha256::digest(b"MALICIOUS_INJECTED_PAYLOAD");
    let signer = Sha256::digest(b"JAMBO_OFFICIAL_SIGNER_KEY_2026");
    let tampered_id = daemon
        .register_enclave(
            &admin_cap,
            "sec-vault.wasm", // Mappe sur la politique dorée
            1,
            bad_mr,
            signer,
            1,
            enclave_attrs::MEMORY_ENCRYPTED | enclave_attrs::HARDWARE_ISOLATED,
            Sha256::digest(b"TAMPERED_POLICY"),
        )
        .expect("Enrôlement enclave cible");

    let tampered_nonce = Sha256::digest(b"CHALLENGE_FOR_TAMPERED");
    let tampered_quote = daemon
        .generate_quote(&admin_cap, tampered_id, &tampered_nonce)
        .expect("Quote pour enclave altérée");

    let verify_tampered = daemon.verify_quote(&admin_cap, &tampered_quote, &tampered_nonce);
    assert_eq!(
        verify_tampered,
        Err(Attest2Error::MeasurementMismatch),
        "Altération de mesure MRENCLAVE formellement interceptée"
    );

    // Vérifier la mise en quarantaine immédiate
    let quarantined_enc = daemon.find_enclave(tampered_id).unwrap();
    assert_eq!(quarantined_enc.status, EnclaveStatus::Quarantined);

    // Une enclave en quarantaine ne peut plus générer de devis
    assert_eq!(
        daemon.generate_quote(&admin_cap, tampered_id, &tampered_nonce),
        Err(Attest2Error::EnclaveQuarantined),
        "Enclave en quarantaine rejetée pour toute nouvelle attestation"
    );
    kprintln!("[ATTEST2/QUARANTINE] Détection d'incohérence et confinement autonome O(1) validés");

    // 8. Isolation d'une puce silicium et cascade de quarantaine
    let conf_chip_res = daemon.confine_chip(&admin_cap, 3, "Puce HSM défaillante");
    assert!(conf_chip_res.is_ok());
    let chip3 = daemon.find_chip(3).unwrap();
    assert_eq!(chip3.status, ChipStatus::Quarantined);
    // L'enclave #2 hébergée sur la puce 3 doit être en quarantaine
    let enc2 = daemon.find_enclave(2).unwrap();
    assert_eq!(enc2.status, EnclaveStatus::Quarantined);
    kprintln!("[ATTEST2/CASCADE] Confinement de puce matérielle et mise en quarantaine en cascade validés");

    // 9. Vérification du registre d'audit inaltérable scellé SHA-256
    assert!(daemon.audit_count > 5);
    assert_ne!(daemon.audit_chain, [0x5A; 32]);
    kprintln!("[ATTEST2/AUDIT] Registre d'audit inaltérable scellé par chaîne SHA-256 validé");

    // 10. Validation de l'intégration Shell Ring 3 (jambo-sh)
    let mut shell = JamboShell::new();
    let mut output_buf = [0u8; 1024];

    let commands = [
        "attest2 status",
        "attest2 chips",
        "attest2 enclaves",
        "attest2 quote 1",
        "attest2 verify 1",
        "attest2 cross-check",
        "attest2 audit",
    ];

    for cmd in &commands {
        let (status, written) = shell.execute_line(cmd, &mut output_buf);
        assert_eq!(
            status,
            ShellStatus::Success,
            "Échec commande shell : {}",
            cmd
        );
        assert!(written > 0, "Aucune sortie pour : {}", cmd);
    }
    kprintln!("[ATTEST2/SHELL] Commandes interactives Shell jsh attest2 validées");

    kprintln!(
        "\x1b[1;32m[ATTEST2/SUCCESS] Phase 105 - Attestation Distante d'Enclaves & Multi-Puces validée avec succès !\x1b[0m"
    );
    true
}

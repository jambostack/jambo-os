//! Module de validation de l'Attestation Matérielle Distante TPM 2.0 et Confinement de Grappe (Phase 78 - v0.2.76)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_secpolicyd::{
    secpolicy_rights, AttestationStatus, ConfinementState, JamboSecPolicyDaemon, PcrBank,
    SecPolicyCap, Sha256, TpmAttestationKey, DEFAULT_CRITICAL_PCR_MASK,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation de l'attestation TPM 2.0 et du confinement (Phase 78)
pub fn execute_secpolicy_daemon_test() -> bool {
    kprintln!(
        "[SECPOLICY/TEST] Démarrage du test d'attestation TPM 2.0 et confinement de grappe (Phase 78)..."
    );

    // 1. Contrôle d'accès capabilaire (SecPolicyCap) et rejet d'amplification
    let admin_cap = SecPolicyCap::new(Handle::new(7801, 1), secpolicy_rights::ALL);
    assert!(admin_cap.has_right(secpolicy_rights::ATTEST_READ));
    assert!(admin_cap.has_right(secpolicy_rights::ATTEST_CHALLENGE));
    assert!(admin_cap.has_right(secpolicy_rights::PCR_EXTEND));
    assert!(admin_cap.has_right(secpolicy_rights::POLICY_ENFORCE));
    assert!(admin_cap.has_right(secpolicy_rights::CONFINEMENT_MANAGE));
    assert!(admin_cap.has_right(secpolicy_rights::ADMIN));

    let audit_cap = admin_cap
        .attenuate(secpolicy_rights::ATTEST_READ)
        .expect("attenuate SecPolicyCap to read-only");
    assert!(audit_cap.has_right(secpolicy_rights::ATTEST_READ));
    assert!(!audit_cap.has_right(secpolicy_rights::PCR_EXTEND));
    assert!(!audit_cap.has_right(secpolicy_rights::CONFINEMENT_MANAGE));

    // Tentative d'élévation formellement rejetée
    assert_eq!(
        audit_cap.attenuate(secpolicy_rights::ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let node1_priv = [0x78u8; 32];
    let node1_pub = [0x78u8; 32];
    let mut local_daemon = JamboSecPolicyDaemon::new(1, admin_cap, node1_priv, node1_pub);

    // Tentative d'extension PCR sans droit PCR_EXTEND
    let dummy_digest = Sha256::digest(b"UNAUTHORIZED_EXTENSION");
    assert_eq!(
        local_daemon.extend_pcr(&audit_cap, 8, 1, "test", &dummy_digest, 10),
        Err(SysError::PermissionDenied),
        "Extension sans droit PCR_EXTEND doit échouer"
    );
    kprintln!("[SECPOLICY/CAP] Contrôle d'accès capabilaire et interdiction d'élévation validés");

    // 2. Gestion des registres PCR TPM 2.0 et extensions cryptographiques SHA-256
    let initial_pcr8 = local_daemon.pcr_bank.get_pcr(8).expect("PCR 8 présent");
    let kernel_patch_digest = Sha256::digest(b"KERNEL_LIVEPATCH_SECURITY_V1");

    let updated_pcr8 = local_daemon
        .extend_pcr(&admin_cap, 8, 3, "livepatch_sec", &kernel_patch_digest, 20)
        .expect("extension PCR 8");

    assert_ne!(initial_pcr8, updated_pcr8);
    let expected_ext = Sha256::pcr_extend(&initial_pcr8, &kernel_patch_digest);
    assert_eq!(
        updated_pcr8, expected_ext,
        "Formule TCG SHA256(PCR || digest)"
    );
    assert_eq!(local_daemon.event_log.count, 1);
    assert_eq!(local_daemon.stats_data.pcrs_extended, 1);
    kprintln!("[SECPOLICY/PCR] Registres PCR 0..23, extensions SHA-256 et TCG Event Log validés");

    // 3. Citations signées TpmQuote et immunité anti-rejeu par nonce
    let challenge_nonce_1 = local_daemon
        .generate_challenge_nonce(&admin_cap, 100)
        .expect("nonce 1");

    let quote_node1 = local_daemon
        .generate_quote(
            &admin_cap,
            DEFAULT_CRITICAL_PCR_MASK,
            &challenge_nonce_1,
            105,
        )
        .expect("generate quote node 1");

    assert_eq!(quote_node1.node_id, 1);
    assert_eq!(quote_node1.nonce, challenge_nonce_1);
    assert!(TpmAttestationKey::verify_signature(
        &node1_pub,
        &quote_node1.composite_digest,
        &quote_node1.signature
    ));
    kprintln!("[SECPOLICY/QUOTE] Citations signées TpmQuote et empreintes composites validées");

    // 4. Défi-réponse d'attestation inter-nœuds et vérification d'intégrité de grappe
    let node2_priv = [0x55u8; 32];
    let node2_pub = [0x55u8; 32];
    local_daemon
        .register_remote_node(&admin_cap, 2, node2_pub)
        .expect("register remote node 2");

    let mut remote_node2 = JamboSecPolicyDaemon::new(2, admin_cap, node2_priv, node2_pub);

    // Étape A : Nœud 2 sain (Golden baseline intacte)
    let challenge_nonce_node2 = local_daemon
        .generate_challenge_nonce(&admin_cap, 200)
        .expect("challenge nonce node 2");

    let quote_node2_clean = remote_node2
        .generate_quote(
            &admin_cap,
            DEFAULT_CRITICAL_PCR_MASK,
            &challenge_nonce_node2,
            205,
        )
        .expect("quote clean node 2");

    let verify_clean = local_daemon
        .verify_remote_attestation(
            &admin_cap,
            &quote_node2_clean,
            &challenge_nonce_node2,
            DEFAULT_CRITICAL_PCR_MASK,
            210,
        )
        .expect("verify clean node 2");

    assert_eq!(verify_clean, AttestationStatus::Valid);
    assert!(local_daemon.is_node_trusted(2));

    // Étape B : Détection d'attaque par rejeu (ancien nonce)
    let replay_nonce = [0xAAu8; 32];
    let verify_replay = local_daemon
        .verify_remote_attestation(
            &admin_cap,
            &quote_node2_clean,
            &replay_nonce,
            DEFAULT_CRITICAL_PCR_MASK,
            220,
        )
        .expect("verify replay node 2");

    assert_eq!(verify_replay, AttestationStatus::NonceMismatch);

    // Étape C : Détection de compromission d'amorçage (altération malveillante du chargeur PCR 4)
    let bootloader_exploit = Sha256::digest(b"MALICIOUS_UEFI_BOOTKIT_INJECT");
    remote_node2
        .extend_pcr(&admin_cap, 4, 1, "bootkit", &bootloader_exploit, 230)
        .expect("inject tampered pcr4");

    let fresh_challenge_3 = local_daemon
        .generate_challenge_nonce(&admin_cap, 240)
        .expect("fresh challenge 3");

    let quote_node2_tampered = remote_node2
        .generate_quote(
            &admin_cap,
            DEFAULT_CRITICAL_PCR_MASK,
            &fresh_challenge_3,
            245,
        )
        .expect("quote tampered node 2");

    let verify_tampered = local_daemon
        .verify_remote_attestation(
            &admin_cap,
            &quote_node2_tampered,
            &fresh_challenge_3,
            DEFAULT_CRITICAL_PCR_MASK,
            250,
        )
        .expect("verify tampered node 2");

    assert_eq!(verify_tampered, AttestationStatus::MeasurementMismatch);

    // Vérification du confinement automatique immédiat : mise en quarantaine
    assert!(!local_daemon.is_node_trusted(2));
    assert_eq!(
        local_daemon.nodes[1].confinement,
        ConfinementState::Quarantine
    );
    kprintln!("[SECPOLICY/CONFINEMENT] Attestation distante, détection d'altération et auto-quarantaine validées");

    // 5. Intégration des commandes Shell jsh ('secpolicy')
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande : secpolicy status
    let (st_status, len_status) = shell.execute_line("secpolicy status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("ATTESTATION MATÉRIELLE TPM 2.0"));
    assert!(out_str_status.contains("TPM 2.0"));
    kprintln!("[SECPOLICY/SHELL] Commande 'secpolicy status' validée");

    // Commande : secpolicy pcrs
    let (st_pcrs, len_pcrs) = shell.execute_line("secpolicy pcrs", &mut out_buf);
    assert_eq!(st_pcrs, ShellStatus::Success);
    let out_str_pcrs = core::str::from_utf8(&out_buf[..len_pcrs]).unwrap();
    assert!(out_str_pcrs.contains("PCR #0"));
    assert!(out_str_pcrs.contains("PCR #4"));
    assert!(out_str_pcrs.contains("PCR #8"));
    kprintln!("[SECPOLICY/SHELL] Commande 'secpolicy pcrs' validée");

    // Commande : secpolicy verify 2
    let (st_verify, len_verify) = shell.execute_line("secpolicy verify 2", &mut out_buf);
    assert_eq!(st_verify, ShellStatus::Success);
    let out_str_verify = core::str::from_utf8(&out_buf[..len_verify]).unwrap();
    assert!(out_str_verify.contains("[SECPOLICY]"));
    kprintln!("[SECPOLICY/SHELL] Commande 'secpolicy verify' validée");

    // Commande : secpolicy confine 2 quarantine
    let (st_confine, len_confine) =
        shell.execute_line("secpolicy confine 2 quarantine", &mut out_buf);
    assert_eq!(st_confine, ShellStatus::Success);
    let out_str_confine = core::str::from_utf8(&out_buf[..len_confine]).unwrap();
    assert!(out_str_confine.contains("QUARANTINE"));
    kprintln!("[SECPOLICY/SHELL] Commande 'secpolicy confine' validée");

    kprintln!(
        "\x1b[1;32m[SECPOLICY/PASS] Suite de tests Attestation Distante TPM 2.0 & Confinement validée avec succès !\x1b[0m"
    );
    true
}

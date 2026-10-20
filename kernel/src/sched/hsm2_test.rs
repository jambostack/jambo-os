//! Module de validation de l'Architecture HSM Distribuée Ring 3,
//! de la Fédération de Clés à Seuil Multi-Puces et de l'Accord de Clés de Groupe (`jambo-hsm2`)
//! Phase 102 — Jalon v0.2.100
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_hsm2::{
    hsm2_rights, ChipNodeStatus, ChipSecurityLevel, Gf256, Hsm2Cap, JamboHsm2Daemon,
    MAX_FEDERATED_CHIPS,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle de l'architecture HSM2 distribuée (Phase 102)
pub fn execute_hsm2_daemon_test() -> bool {
    kprintln!(
        "[HSM2/TEST] Démarrage du test de validation du HSM Distribué & Fédération Multi-Puces (Phase 102)..."
    );

    // 1. Contrôle d'accès capabilaire (Hsm2Cap) et rejet formel de toute élévation de privilèges
    let admin_cap = Hsm2Cap::new(Handle::new(10201, 1), hsm2_rights::ALL);
    assert!(admin_cap.has_right(hsm2_rights::FEDERATE));
    assert!(admin_cap.has_right(hsm2_rights::ATTEST));
    assert!(admin_cap.has_right(hsm2_rights::AGREE_KEY));
    assert!(admin_cap.has_right(hsm2_rights::THRESHOLD_SIGN));
    assert!(admin_cap.has_right(hsm2_rights::THRESHOLD_DECRYPT));
    assert!(admin_cap.has_right(hsm2_rights::DISTRIBUTE_SHARES));
    assert!(admin_cap.has_right(hsm2_rights::ZEROIZE_FEDERATION));
    assert!(admin_cap.has_right(hsm2_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(hsm2_rights::AGREE_KEY | hsm2_rights::THRESHOLD_SIGN)
        .expect("Atténuation monotone Hsm2Cap");
    assert!(attenuated_cap.has_right(hsm2_rights::AGREE_KEY));
    assert!(attenuated_cap.has_right(hsm2_rights::THRESHOLD_SIGN));
    assert!(!attenuated_cap.has_right(hsm2_rights::ZEROIZE_FEDERATION));
    assert!(!attenuated_cap.has_right(hsm2_rights::ADMIN));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        attenuated_cap.attenuate(hsm2_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits Hsm2Cap formellement rejetée"
    );
    kprintln!("[HSM2/CAP] Contrôle d'accès capabilaire Hsm2Cap et atténuation monotone validés");

    // 2. Initialisation du démon HSM2 et topologie multi-puces par défaut
    let mut daemon = JamboHsm2Daemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.chip_count, 3);
    assert_eq!(daemon.count_active_chips(), 3);
    assert_eq!(daemon.active_epoch, 1);
    assert!(!daemon.zeroized);
    kprintln!("[HSM2/INIT] Fédération multi-puces initialisée avec 3 Secure Elements souverains");

    // 3. Validation de l'arithmétique dans le corps fini GF(256)
    let elem_a = Gf256(0x57);
    let elem_b = Gf256(0x83);
    let elem_sum = elem_a.add(elem_b);
    assert_eq!(elem_sum.0, 0x57 ^ 0x83);
    let elem_inv = elem_a.inv().expect("Inversion multiplicative");
    assert_eq!(elem_a.mul(elem_inv), Gf256::ONE);
    kprintln!("[HSM2/GF256] Arithmétique souveraine de corps fini GF(2^8) validée");

    // 4. Protocole d'accord de clés de groupe (GKA) et rotation d'époques
    let old_epoch = daemon.active_epoch;
    let old_key = daemon.group_session_key;
    let new_key = daemon
        .perform_group_key_agreement(&admin_cap)
        .expect("Accord de clé de groupe GKA");
    assert_eq!(daemon.active_epoch, old_epoch + 1);
    assert_ne!(new_key, old_key);
    assert_eq!(new_key, daemon.group_session_key);
    kprintln!("[HSM2/GKA] Protocole Group Key Agreement et rotation d'époques cryptographiques validés");

    // 5. Schéma de partage de seuil de Shamir (T=2, N=3) & Reconstitution de Lagrange
    let master_secret = [0x39u8; 32];
    daemon
        .distribute_threshold_key(&admin_cap, 100, &master_secret, 2)
        .expect("Distribution des parts Shamir");
    assert_eq!(daemon.active_scheme.share_count, 3);
    assert_eq!(daemon.active_scheme.threshold_t, 2);

    let shares_subset = [
        daemon.active_scheme.shares[0],
        daemon.active_scheme.shares[1],
    ];
    let recovered_secret = daemon
        .reconstruct_threshold_secret(&shares_subset)
        .expect("Interpolation de Lagrange");
    assert_eq!(
        recovered_secret, master_secret,
        "Secret maître reconstitué sans altération par interpolation de Lagrange"
    );
    kprintln!("[HSM2/SHAMIR] Partage secret de seuil (T=2, N=3) et reconstruction de Lagrange validés");

    // 6. Signature collaborative de seuil et détection de fautes byzantines
    let critical_command = b"EXECUTE_SECURE_KERNEL_PAYLOAD_STAGE3";
    let participants = [101, 102];
    let threshold_sig = daemon
        .threshold_sign(&admin_cap, critical_command, &participants)
        .expect("Génération signature collaborative de seuil");
    assert_eq!(daemon.signatures_generated, 1);
    assert!(
        daemon.verify_threshold_signature(critical_command, &threshold_sig),
        "Vérification cryptographique de la signature de seuil"
    );

    // Injection délibérée d'une corruption de part sur la puce 101 pour vérifier le slashing
    daemon.active_scheme.shares[0].commitment_hash = [0xde; 32];
    let byzantine_attempt = daemon.threshold_sign(&admin_cap, critical_command, &[101, 102]);
    assert_eq!(byzantine_attempt, Err(SysError::ResourceBusy));
    assert!(daemon.is_quarantined(101));
    kprintln!("[HSM2/BYZANTINE] Signature de seuil collaborative et mise en quarantaine byzantine validées");

    // 7. Zéroïsation d'Urgence Distribuée en temps O(1)
    daemon
        .emergency_zeroize(&admin_cap, b"TEST_EMERGENCY_TAMPER")
        .expect("Zéroïsation d'urgence");
    assert!(daemon.zeroized);
    assert_eq!(daemon.count_active_chips(), 0);
    assert_eq!(daemon.group_session_key, [0u8; 32]);
    assert_eq!(
        daemon.perform_group_key_agreement(&admin_cap),
        Err(SysError::PermissionDenied)
    );
    kprintln!("[HSM2/ZEROIZE] Zéroïsation d'Urgence Distribuée O(1) et neutralisation des secrets validées");

    // 8. Validation de l'intégration dans le Shell Ring 3 (jambo-sh)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (s1, l1) = shell.execute_line("hsm2 status", &mut out);
    assert_eq!(s1, ShellStatus::Success);
    let out_str1 = core::str::from_utf8(&out[..l1]).unwrap_or("");
    assert!(out_str1.contains("ARCHITECTURE HSM DISTRIBUÉE"));

    let (s2, l2) = shell.execute_line("hsm2 federate", &mut out);
    assert_eq!(s2, ShellStatus::Success);
    let out_str2 = core::str::from_utf8(&out[..l2]).unwrap_or("");
    assert!(out_str2.contains("Puce #101"));

    let (s3, l3) = shell.execute_line("hsm2 gka", &mut out);
    assert_eq!(s3, ShellStatus::Success);
    let out_str3 = core::str::from_utf8(&out[..l3]).unwrap_or("");
    assert!(out_str3.contains("Clé de session de groupe GKA"));

    let (s4, l4) = shell.execute_line("hsm2 sign", &mut out);
    assert_eq!(s4, ShellStatus::Success);
    let out_str4 = core::str::from_utf8(&out[..l4]).unwrap_or("");
    assert!(out_str4.contains("Signature de seuil 64 octets générée"));

    let (s5, l5) = shell.execute_line("hsm2 verify", &mut out);
    assert_eq!(s5, ShellStatus::Success);
    let out_str5 = core::str::from_utf8(&out[..l5]).unwrap_or("");
    assert!(out_str5.contains("Preuve de signature de seuil cryptographiquement VALIDÉE"));

    let (s6, l6) = shell.execute_line("hsm2 audit", &mut out);
    assert_eq!(s6, ShellStatus::Success);
    let out_str6 = core::str::from_utf8(&out[..l6]).unwrap_or("");
    assert!(out_str6.contains("Condensat SHA-256 d'Audit HSM2"));

    kprintln!("[HSM2/SHELL] Commandes Shell natives `hsm2` (status, federate, gka, sign, verify, audit) validées");

    true
}

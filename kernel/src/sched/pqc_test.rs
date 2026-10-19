//! Module de validation de la Cryptographie Post-Quantique (PQC) & Transition Quantique (`jambo-pqc`)
//! Phase 96 — Jalon v0.2.94
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_pqc::{
    pqc_rights, HybridKeyExchange, JamboPqcDaemon, MlDsa, MlKem, PqcAlgorithm, PqcCap,
    PqcTransitionState, DSA_PUBLIC_KEY_LEN, DSA_SECRET_KEY_LEN, DSA_SIGNATURE_LEN,
    KEM_CIPHERTEXT_LEN, KEM_PUBLIC_KEY_LEN, KEM_SECRET_KEY_LEN, KEM_SHARED_SECRET_LEN,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle du sous-système PQC souverain (Phase 96)
pub fn execute_pqc_daemon_test() -> bool {
    kprintln!(
        "[PQC/TEST] Démarrage du test de validation de la Cryptographie Post-Quantique PQC (Phase 96)..."
    );

    // 1. Contrôle d'accès capabilaire (PqcCap) et rejet formel de toute élévation de privilèges
    let admin_cap = PqcCap::new(Handle::new(9601, 1), pqc_rights::ALL);
    assert!(admin_cap.has_right(pqc_rights::KEM_KEYGEN));
    assert!(admin_cap.has_right(pqc_rights::KEM_ENCAPS));
    assert!(admin_cap.has_right(pqc_rights::KEM_DECAPS));
    assert!(admin_cap.has_right(pqc_rights::DSA_KEYGEN));
    assert!(admin_cap.has_right(pqc_rights::DSA_SIGN));
    assert!(admin_cap.has_right(pqc_rights::DSA_VERIFY));
    assert!(admin_cap.has_right(pqc_rights::HYBRID_KEX));
    assert!(admin_cap.has_right(pqc_rights::SET_TRANSITION));
    assert!(admin_cap.has_right(pqc_rights::ZEROIZE));
    assert!(admin_cap.has_right(pqc_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(pqc_rights::KEM_ENCAPS | pqc_rights::DSA_VERIFY | pqc_rights::HYBRID_KEX)
        .expect("Atténuation monotone PqcCap");
    assert!(attenuated_cap.has_right(pqc_rights::KEM_ENCAPS));
    assert!(!attenuated_cap.has_right(pqc_rights::ZEROIZE));
    assert!(!attenuated_cap.has_right(pqc_rights::ADMIN));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        attenuated_cap.attenuate(pqc_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits PqcCap formellement rejetée"
    );
    kprintln!("[PQC/CAP] Contrôle d'accès capabilaire PqcCap et atténuation monotone validés");

    // 2. Initialisation du démon PQC et clés souveraines par défaut
    let mut daemon = JamboPqcDaemon::new(admin_cap);
    daemon.init_defaults();

    assert_eq!(daemon.count_active_keys(), 2);
    assert_eq!(
        daemon.transition_state,
        PqcTransitionState::HybridPqcClassical
    );
    kprintln!("[PQC/INIT] Démon PQC initialisé (Clés souveraines ML-KEM & ML-DSA actives)");

    // 3. Mécanisme d'Encapsulation de Clé Post-Quantique ML-KEM
    let kem_kid = daemon
        .generate_kem_keypair(
            &admin_cap,
            "Node-PQC-KEM",
            b"node_kem_sovereign_ephemeral_seed_2026",
        )
        .expect("Génération paire de clés ML-KEM");

    let mut ct = [0u8; KEM_CIPHERTEXT_LEN];
    let mut ss_sender = [0u8; KEM_SHARED_SECRET_LEN];
    daemon
        .kem_encapsulate(
            &admin_cap,
            kem_kid,
            b"cluster_ephemeral_entropy_exchange_2026",
            &mut ct,
            &mut ss_sender,
        )
        .expect("Encapsulation ML-KEM");

    let mut ss_receiver = [0u8; KEM_SHARED_SECRET_LEN];
    daemon
        .kem_decapsulate(&admin_cap, kem_kid, &ct, &mut ss_receiver)
        .expect("Décapsulation ML-KEM");

    assert_eq!(
        ss_sender, ss_receiver,
        "Secrets partagés ML-KEM émetteur et récepteur strictement identiques"
    );
    assert_ne!(ss_sender, [0u8; 32]);
    kprintln!("[PQC/ML-KEM] Encapsulation / Décapsulation ML-KEM validées (Secret 256 bits conforme)");

    // 4. Signature Numérique Post-Quantique ML-DSA (Fiat-Shamir with Aborts)
    let dsa_kid = daemon
        .generate_dsa_keypair(
            &admin_cap,
            "Node-PQC-DSA",
            b"node_dsa_sovereign_signing_seed_2026",
        )
        .expect("Génération paire de clés ML-DSA");

    let sovereign_statement = b"JAMBO_OS_KERNEL_INTEGRITY_PQC_ATTESTATION_2026";
    let mut signature = [0u8; DSA_SIGNATURE_LEN];
    let sig_len = daemon
        .dsa_sign(
            &admin_cap,
            dsa_kid,
            sovereign_statement,
            b"nonce_sign_attestation",
            &mut signature,
        )
        .expect("Signature ML-DSA");
    assert_eq!(sig_len, DSA_SIGNATURE_LEN);

    let is_valid = daemon
        .dsa_verify(&admin_cap, dsa_kid, sovereign_statement, &signature)
        .expect("Vérification signature ML-DSA");
    assert!(is_valid, "Authenticité de signature ML-DSA validée");

    let mut tampered_statement = *sovereign_statement;
    tampered_statement[0] ^= 0x5A;
    let is_tampered_valid = daemon
        .dsa_verify(&admin_cap, dsa_kid, &tampered_statement, &signature)
        .expect("Vérification signature altérée");
    assert!(
        !is_tampered_valid,
        "Rejet strict de la signature ML-DSA sur énoncé altéré"
    );
    kprintln!("[PQC/ML-DSA] Signature et vérification ML-DSA sur réseaux euclidiens validées");

    // 5. Échange de clés hybride Dual-Defense (ML-KEM + Diffie-Hellman / X25519)
    let classical_ecdh_secret = [0x5cu8; 32];
    let session_context = b"TLS_HYBRID_PQC_SESSION_CHANNEL_0";
    let mut hybrid_shared_key = [0u8; 32];
    daemon
        .execute_hybrid_kex(
            &admin_cap,
            kem_kid,
            &classical_ecdh_secret,
            session_context,
            &mut ct,
            &mut hybrid_shared_key,
        )
        .expect("Échange de clés hybride Dual-Defense");
    assert_ne!(hybrid_shared_key, [0u8; 32]);
    kprintln!("[PQC/HYBRID] Échange de clés hybride Dual-Defense (ML-KEM + Classique) validé");

    // 6. Machine à états de Transition Quantique Souveraine
    daemon
        .set_transition_state(&admin_cap, PqcTransitionState::PurePqcEnforced)
        .expect("Bascule vers PurePqcEnforced");
    assert_eq!(
        daemon.transition_state,
        PqcTransitionState::PurePqcEnforced
    );
    kprintln!("[PQC/TRANSITION] Politique souveraine de transition quantique activée (PurePqcEnforced)");

    // 7. Zéroïsation d'urgence en mémoire volatile
    let initial_active_keys = daemon.count_active_keys();
    daemon
        .zeroize_key(&admin_cap, kem_kid)
        .expect("Zéroïsation clé ML-KEM");
    assert_eq!(daemon.count_active_keys(), initial_active_keys - 1);
    assert_eq!(daemon.zeroizations, 1);
    kprintln!("[PQC/ZEROIZE] Zéroïsation volatile des secrets cryptographiques validée");

    // 8. Registre d'audit inviolable scellé par chaîne SHA-256
    assert_ne!(daemon.audit_chain, [0u8; 32]);
    kprintln!("[PQC/AUDIT] Chaîne d'audit cryptographique SHA-256 scellée et vérifiée");

    // 9. Intégration dans le Shell interactif Ring 3 (jsh)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (st1, len1) = shell.execute_line("pqc status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    assert!(len1 > 0);

    let (st2, len2) = shell.execute_line("pqc keys", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    assert!(len2 > 0);

    let (st3, len3) = shell.execute_line("pqc kem", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    assert!(len3 > 0);

    let (st4, len4) = shell.execute_line("pqc dsa", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    assert!(len4 > 0);

    let (st5, len5) = shell.execute_line("pqc hybrid", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    assert!(len5 > 0);

    let (st6, len6) = shell.execute_line("pqc transition pure", &mut out);
    assert_eq!(st6, ShellStatus::Success);
    assert!(len6 > 0);

    let (st7, len7) = shell.execute_line("pqc audit", &mut out);
    assert_eq!(st7, ShellStatus::Success);
    assert!(len7 > 0);

    kprintln!("[PQC/SHELL] Commandes Ring 3 jsh 'pqc' validées avec succès");
    true
}

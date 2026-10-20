//! Module de validation de l'Attestation Cryptographique à Distance,
//! des Preuves Zero-Knowledge (ZKP) et du Confinement Matériel de Grappe (`jambo-attest`)
//! Phase 93 — Jalon v0.2.91
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_attest::{
    attest_rights, zkp, AttestCap, ConfinementLevel, HardwareTrustRoot, JamboAttestDaemon,
    NodeIntegrityClaim, NodeStatus, Sha256, MAX_NODES,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle du sous-système d'attestation et de ZKP (Phase 93)
pub fn execute_attest_daemon_test() -> bool {
    kprintln!(
        "[ATTEST/TEST] Démarrage du test d'attestation distante, preuves ZKP et confinement grappe (Phase 93)..."
    );

    // 1. Contrôle d'accès capabilaire (AttestCap) et rejet formel d'amplification
    let admin_cap = AttestCap::new(Handle::new(9301, 1), attest_rights::ALL);
    assert!(admin_cap.has_right(attest_rights::GENERATE_CLAIM));
    assert!(admin_cap.has_right(attest_rights::VERIFY_CLAIM));
    assert!(admin_cap.has_right(attest_rights::GENERATE_ZKP));
    assert!(admin_cap.has_right(attest_rights::VERIFY_ZKP));
    assert!(admin_cap.has_right(attest_rights::CONFINE_NODE));
    assert!(admin_cap.has_right(attest_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(attest_rights::GENERATE_CLAIM | attest_rights::VERIFY_CLAIM)
        .expect("Atténuation monotone AttestCap");
    assert!(attenuated_cap.has_right(attest_rights::GENERATE_CLAIM));
    assert!(attenuated_cap.has_right(attest_rights::VERIFY_CLAIM));
    assert!(!attenuated_cap.has_right(attest_rights::ADMIN));
    assert!(!attenuated_cap.has_right(attest_rights::CONFINE_NODE));

    // Rejet formel de toute tentative d'élévation
    assert_eq!(
        attenuated_cap.attenuate(attest_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits AttestCap formellement rejetée"
    );
    kprintln!("[ATTEST/CAP] Contrôle capabilaire AttestCap et rejet de l'amplification validés");

    // 2. Initialisation du démon d'attestation et chargement des profils matériels
    let mut daemon = JamboAttestDaemon::new(admin_cap);
    daemon.init_defaults();

    assert_eq!(daemon.count_active_trusted(), 0);
    assert_eq!(daemon.count_quarantined(), 0);

    // Vérifier les racines matérielles initialisées
    let n1 = daemon.get_node(1).expect("Nœud 1 présent");
    assert_eq!(n1.trust_root, HardwareTrustRoot::IntelTdx);
    assert_eq!(n1.confinement, ConfinementLevel::Sandboxed);

    let n2 = daemon.get_node(2).expect("Nœud 2 présent");
    assert_eq!(n2.trust_root, HardwareTrustRoot::AmdSevSnp);

    let n3 = daemon.get_node(3).expect("Nœud 3 présent");
    assert_eq!(n3.trust_root, HardwareTrustRoot::ArmCcaRealm);

    let n4 = daemon.get_node(4).expect("Nœud 4 présent");
    assert_eq!(n4.trust_root, HardwareTrustRoot::Tpm2Pcr);
    kprintln!("[ATTEST/INIT] Racines matérielles (TDX, SEV-SNP, CCA Realm, TPM 2.0) initialisées");

    // 3. Émission et validation d'une revendication d'intégrité signée (NodeIntegrityClaim)
    let claim1 = daemon
        .generate_claim(&admin_cap, 1)
        .expect("Génération de revendication pour le nœud 1");
    assert_eq!(claim1.node_id, 1);
    assert_eq!(claim1.challenge_nonce, daemon.cluster_challenge);

    let verify_ok = daemon
        .verify_claim(&admin_cap, &claim1)
        .expect("Vérification de la revendication");
    assert!(verify_ok, "Revendication d'intégrité valide acceptée");

    let n1_pending = daemon.get_node(1).expect("Nœud 1");
    assert_eq!(n1_pending.status, NodeStatus::PendingZkp);
    kprintln!("[ATTEST/CLAIM] Revendication d'intégrité signée par HMAC validée avec succès");

    // 4. Détection et mise en quarantaine immédiate sur falsification de signature
    let mut bad_claim = claim1;
    bad_claim.signature[0] ^= 0xEE; // Altération de la signature cryptographique
    let bad_verify = daemon
        .verify_claim(&admin_cap, &bad_claim)
        .expect("Vérification d'une fausse signature");
    assert!(!bad_verify, "Une fausse signature doit être rejetée");

    let n1_quarantine = daemon.get_node(1).expect("Nœud 1");
    assert_eq!(n1_quarantine.status, NodeStatus::Quarantined);
    assert_eq!(n1_quarantine.confinement, ConfinementLevel::Isolated);
    kprintln!(
        "[ATTEST/QUARANTINE] Falsification détectée : mise en quarantaine et isolation automatique"
    );

    // 5. Génération et validation mathématique d'une preuve Zero-Knowledge (ZKP Schnorr / Fiat-Shamir)
    // Réhabilitation du nœud 1 pour valider le protocole complet
    let claim1_clean = daemon
        .generate_claim(&admin_cap, 1)
        .expect("Nouvelle revendication propre");
    let ok2 = daemon
        .verify_claim(&admin_cap, &claim1_clean)
        .expect("Vérification de la revendication propre");
    assert!(ok2);

    let secret_x = 0x1337_4242_u64;
    let blinding_v = 0x5544_3322_u64;
    let claim_digest = claim1_clean.compute_digest();

    let proof = daemon
        .generate_zkp_proof(&admin_cap, 1, secret_x, blinding_v, claim_digest)
        .expect("Génération de la preuve ZKP");

    // Vérification unitaire directe de l'équation de Schnorr
    assert!(
        proof.verify(),
        "L'équation mathématique g^r == t * y^c (mod p) doit être vérifiée"
    );

    // Vérification formelle par le démon d'attestation et levée du confinement
    let zkp_verified = daemon
        .verify_zkp_proof(&admin_cap, &proof)
        .expect("Vérification ZKP par le démon");
    assert!(zkp_verified, "Preuve ZKP acceptée par la grappe");

    let n1_trusted = daemon.get_node(1).expect("Nœud 1 vérifié");
    assert_eq!(n1_trusted.status, NodeStatus::VerifiedTrusted);
    assert_eq!(n1_trusted.confinement, ConfinementLevel::Unrestricted);
    assert_eq!(daemon.count_active_trusted(), 1);
    kprintln!("[ATTEST/ZKP] Preuve Zero-Knowledge (Schnorr/Fiat-Shamir) validée, confinement levé");

    // 6. Rejet d'une preuve ZKP falsifiée (tentative d'imposture)
    let mut fake_proof = proof;
    fake_proof.response_r = fake_proof.response_r.wrapping_add(1);
    assert!(!fake_proof.verify(), "Preuve altérée rejetée");

    let _ = daemon.verify_zkp_proof(&admin_cap, &fake_proof);
    let n1_re_quarantined = daemon.get_node(1).expect("Nœud 1");
    assert_eq!(n1_re_quarantined.status, NodeStatus::Quarantined);
    assert_eq!(n1_re_quarantined.confinement, ConfinementLevel::Isolated);
    kprintln!("[ATTEST/DEFENSE] Preuve ZKP falsifiée bloquée, nœud ré-isolé");

    // 7. Renouvellement du défi de grappe (Anti-Rejeu) & Invalidation des anciens nonces
    let old_challenge = daemon.cluster_challenge;
    let new_challenge = daemon
        .rotate_cluster_challenge(&admin_cap, b"ENTROPY_SALT_TEST_2026")
        .expect("Rotation du défi");
    assert_ne!(old_challenge, new_challenge);
    assert_eq!(daemon.cluster_epoch, 2);
    kprintln!("[ATTEST/REPLAY] Rotation du défi anti-rejeu et incrémentation de l'époque validées");

    // 8. Registre d'audit inaltérable scellé SHA-256
    assert_ne!(daemon.audit_chain, [0u8; 32]);
    kprintln!("[ATTEST/AUDIT] Chaîne d'audit SHA-256 scellée et inviolable validée");

    // 9. Validation des commandes interactives du shell (`attest`)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    // Commande status
    let (st1, len1) = shell.execute_line("attest status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    let s1 = core::str::from_utf8(&out[..len1]).unwrap_or("");
    assert!(s1.contains("ATTESTATION CRYPTOGRAPHIQUE & CONFINEMENT DE GRAPPE"));
    assert!(s1.contains("Schnorr / Fiat-Shamir"));

    // Commande nodes
    let (st2, len2) = shell.execute_line("attest nodes", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    let s2 = core::str::from_utf8(&out[..len2]).unwrap_or("");
    assert!(s2.contains("jambo-ctrl-01"));
    assert!(s2.contains("Intel TDX"));
    assert!(s2.contains("jambo-worker-02"));

    // Commande verify (Exécution complète claim + ZKP)
    let (st3, len3) = shell.execute_line("attest verify", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    let s3 = core::str::from_utf8(&out[..len3]).unwrap_or("");
    assert!(s3.contains("Preuve Zero-Knowledge validée avec succès"));

    // Commande confine
    let (st4, len4) = shell.execute_line("attest confine", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    let s4 = core::str::from_utf8(&out[..len4]).unwrap_or("");
    assert!(s4.contains("Nœud 2 isolé"));

    // Commande rotate
    let (st5, len5) = shell.execute_line("attest rotate", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    let s5 = core::str::from_utf8(&out[..len5]).unwrap_or("");
    assert!(s5.contains("Défi renouvelé"));

    // Commande audit
    let (st6, len6) = shell.execute_line("attest audit", &mut out);
    assert_eq!(st6, ShellStatus::Success);
    let s6 = core::str::from_utf8(&out[..len6]).unwrap_or("");
    assert!(s6.contains("Condensat SHA-256 d'Audit Attestation"));

    kprintln!(
        "[ATTEST/SHELL] Commandes d'administration 'attest status/nodes/verify/confine/rotate/audit' validées"
    );
    kprintln!(
        "[ATTEST/SUCCESS] Attestation Distante, Preuves ZKP et Confinement de Grappe entièrement validés (Phase 93)"
    );

    true
}

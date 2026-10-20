//! Module de validation de l'Infrastructure à Clés Publiques Post-Quantique (`jambo-pki2`)
//! Phase 109 — Jalon v0.2.107
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_pki2::{
    key_usages, pki_rights, CaTrustLevel, CertStatus, FederatedCa, HybridPublicKey,
    HybridSignature, JamboPkiDaemon, PkiAlgorithm, PkiCap, PkiCert, PkiError, RevocationReason,
    Sha256, MAX_CAS, MAX_CERTS, MAX_CRL_ENTRIES,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle de la PKI hybride post-quantique et fédération CA (Phase 109)
pub fn execute_pki2_daemon_test() -> bool {
    kprintln!(
        "[PKI2/TEST] Démarrage du test de validation de l'infrastructure PKI hybride et fédération de CA (Phase 109)..."
    );

    // 1. Contrôle d'accès capabilaire (PkiCap) et atténuation monotone
    let admin_cap = PkiCap::new(Handle::new(10901, 1), pki_rights::ALL, 1, MAX_CERTS as u16);
    assert!(admin_cap.has_right(pki_rights::ISSUE_CERT));
    assert!(admin_cap.has_right(pki_rights::VERIFY_CERT));
    assert!(admin_cap.has_right(pki_rights::REVOKE_CERT));
    assert!(admin_cap.has_right(pki_rights::UPDATE_CRL));
    assert!(admin_cap.has_right(pki_rights::FEDERATE_CA));
    assert!(admin_cap.has_right(pki_rights::CROSS_SIGN));
    assert!(admin_cap.has_right(pki_rights::ROTATE_ROOT));
    assert!(admin_cap.has_right(pki_rights::AUDIT_LOG));

    let verifier_cap = admin_cap
        .attenuate(pki_rights::VERIFY_CERT, 16)
        .expect("Atténuation monotone PkiCap");
    assert!(verifier_cap.has_right(pki_rights::VERIFY_CERT));
    assert!(!verifier_cap.has_right(pki_rights::ISSUE_CERT));
    assert!(!verifier_cap.has_right(pki_rights::REVOKE_CERT));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        verifier_cap.attenuate(pki_rights::ALL, 16),
        Err(PkiError::PermissionDenied),
        "Amplification de droits PkiCap formellement rejetée"
    );
    assert_eq!(
        verifier_cap.attenuate(pki_rights::VERIFY_CERT, 32),
        Err(PkiError::PermissionDenied),
        "Augmentation du quota de certificats PkiCap formellement rejetée"
    );
    kprintln!("[PKI2/CAP] Contrôle d'accès capabilaire PkiCap et atténuation monotone validés");

    // 2. Initialisation du démon PKI et fédération de CAs
    let mut daemon = JamboPkiDaemon::new(admin_cap);
    daemon.init_defaults();
    assert!(
        daemon.ca_count >= 2,
        "Root CA et Intermediate CA configurées"
    );
    assert!(
        daemon.cert_count >= 2,
        "Certificats souverains émis par défaut"
    );
    kprintln!("[PKI2/INIT] Démon PKI souverain, hiérarchie et fédération de CA initialisées");

    // 3. Validation de chaîne stricte (RFC 5280 Strict Path Validation)
    let srv_serial = daemon.certs[0].serial_number;
    let val_res = daemon.validate_cert(&admin_cap, srv_serial, key_usages::SERVER_AUTH);
    assert_eq!(
        val_res,
        Ok(true),
        "Validation de la chaîne de confiance pour le certificat serveur"
    );

    // Vérification de l'interdiction d'un usage non accordé
    let usage_err = daemon.validate_cert(&admin_cap, srv_serial, key_usages::CODE_SIGN);
    assert_eq!(
        usage_err,
        Err(PkiError::KeyUsageNotPermitted),
        "Violation d'usage de clé détectée et rejetée"
    );
    kprintln!("[PKI2/PATH] Validation stricte de chaîne et politique de KeyUsage validées");

    // 4. Émission dynamique et signatures hybrides Dual-Defense (ML-DSA + Ed25519)
    let test_subject_pk = HybridPublicKey::new_hybrid(b"SEED_TEST_ED", b"SEED_TEST_ML");
    let ca_sk_ed = [0x77u8; 32];
    let ca_sk_ml = [0x88u8; 32];
    let new_serial = daemon
        .issue_certificate(
            &admin_cap,
            1, // Root CA
            201,
            b"test.worker.jambo",
            test_subject_pk,
            10_000,
            key_usages::CLIENT_AUTH,
            false,
            0,
            &ca_sk_ed,
            &ca_sk_ml,
        )
        .expect("Émission d'un certificat hybride réussie");

    assert_eq!(
        daemon.validate_cert(&admin_cap, new_serial, key_usages::CLIENT_AUTH),
        Ok(true)
    );
    kprintln!("[PKI2/DUAL] Signatures hybrides Dual-Defense (ML-DSA + Ed25519) validées");

    // 5. Révocation temps réel et validation CRL
    daemon
        .revoke_certificate(&admin_cap, new_serial, RevocationReason::KeyCompromise)
        .expect("Révocation réussie");

    let post_revocation_check =
        daemon.validate_cert(&admin_cap, new_serial, key_usages::CLIENT_AUTH);
    assert_eq!(
        post_revocation_check,
        Err(PkiError::CertRevoked),
        "Certificat révoqué immédiatement rejeté par la CRL"
    );
    assert_eq!(
        daemon.crl.is_revoked(new_serial),
        Some(RevocationReason::KeyCompromise)
    );
    kprintln!("[PKI2/CRL] Révocation en temps réel et liste CRL conformes");

    // 6. Registre d'audit inviolable scellé par SHA-256
    assert!(daemon.audit_count >= 4, "Événements d'audit consignés");
    assert_ne!(daemon.audit_chain, [0u8; 32], "Chaîne d'audit active");
    kprintln!("[PKI2/AUDIT] Registre d'audit inaltérable SHA-256 validé");

    // 7. Intégration Shell `jsh` (commandes `pki status`, `pki cas`, `pki benchmark`)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (st, len) = shell.execute_line("pki status", &mut out);
    assert_eq!(st, ShellStatus::Success);
    let status_str = core::str::from_utf8(&out[..len]).unwrap_or("");
    assert!(status_str.contains("INFRASTRUCTURE PKI HYBRIDE POST-QUANTIQUE"));

    let (st, len) = shell.execute_line("pki cas", &mut out);
    assert_eq!(st, ShellStatus::Success);
    let cas_str = core::str::from_utf8(&out[..len]).unwrap_or("");
    assert!(cas_str.contains("AUTORITÉS DE CERTIFICATION"));

    let (st, len) = shell.execute_line("pki benchmark", &mut out);
    assert_eq!(st, ShellStatus::Success);
    let bench_str = core::str::from_utf8(&out[..len]).unwrap_or("");
    assert!(bench_str.contains("Benchmark PKI2 : Émission hybride"));

    kprintln!("[PKI2/SHELL] Intégration shell Ring 3 et commandes interactives validées");

    kprintln!("\x1b[1;32m[PASS] Phase 109 - Infrastructure PKI Post-Quantique & Fédération CA (jambo-pki2) Validée avec Succès !\x1b[0m");
    true
}

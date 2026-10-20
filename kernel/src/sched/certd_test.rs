//! Module de validation de l'Autorité de Certification Éphémère & mTLS (Phase 71 - v0.2.69)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_certd::{
    cert_rights, key_usages, CertCap, CertStatus, ClusterCa, EphemeralCert, JamboCertDaemon,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de l'autorité de certification éphémère et mTLS (Phase 71)
pub fn execute_cluster_ca_test() -> bool {
    kprintln!(
        "[CERT/TEST] Démarrage du test de l'autorité de certification éphémère et mTLS (Phase 71)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (CertCap)
    let admin_cap = CertCap::new(Handle::new(71, 1), cert_rights::ALL);
    assert!(admin_cap.has_right(cert_rights::CERT_ISSUE));
    assert!(admin_cap.has_right(cert_rights::CERT_REVOKE));
    assert!(admin_cap.has_right(cert_rights::CERT_VERIFY));
    assert!(admin_cap.has_right(cert_rights::CERT_AUDIT));
    assert!(admin_cap.has_right(cert_rights::CERT_ADMIN));

    let verify_only_cap = admin_cap
        .attenuate(cert_rights::CERT_VERIFY)
        .expect("attenuate CertCap to verify-only");
    let mut raw_ca = ClusterCa::new(1, [0x11; 32], [0x22; 32]);
    assert_eq!(
        raw_ca.issue_cert(
            &verify_only_cap,
            b"test.cluster.local",
            [1u8; 32],
            1000,
            2000,
            key_usages::USAGE_SERVER_AUTH
        ),
        Err(SysError::PermissionDenied),
        "Émission de certificat sans droit CERT_ISSUE doit être rejetée"
    );
    kprintln!("[CERT/CAP] Confinement capabilaire CertCap et autorité ambiante zéro validés");

    // 2. Émission, intégrité cryptographique et validation temporelle
    let pub_key = [42u8; 32];
    let cert = raw_ca
        .issue_cert(
            &admin_cap,
            b"worker-1.mesh.local",
            pub_key,
            1000,
            1500,
            key_usages::USAGE_SERVER_AUTH | key_usages::USAGE_CLIENT_AUTH,
        )
        .expect("issue certificate");

    assert_eq!(cert.subject_str(), "worker-1.mesh.local");
    assert_eq!(cert.public_key, pub_key);
    assert!(cert.is_time_valid(1200));
    assert!(!cert.is_time_valid(999));
    assert!(!cert.is_time_valid(1501));

    // Vérification de validité via CA
    let status = raw_ca
        .verify_cert(&admin_cap, &cert, key_usages::USAGE_SERVER_AUTH, 1250)
        .expect("verify cert");
    assert_eq!(status, CertStatus::Valid);

    // Vérification pour un certificat expiré
    let status_expired = raw_ca
        .verify_cert(&admin_cap, &cert, key_usages::USAGE_SERVER_AUTH, 1600)
        .expect("verify expired");
    assert_eq!(status_expired, CertStatus::Expired);
    kprintln!("[CERT/CRYPTO] Signature cryptographique et bornes temporelles validées");

    // 3. Révocation de certificat et mise à jour de la table CRL
    let serial = cert.serial;
    raw_ca
        .revoke_cert(&admin_cap, serial)
        .expect("revoke certificate");
    let status_revoked = raw_ca
        .verify_cert(&admin_cap, &cert, key_usages::USAGE_SERVER_AUTH, 1250)
        .expect("verify revoked");
    assert_eq!(status_revoked, CertStatus::Revoked);
    kprintln!("[CERT/REVOKE] Révocation immédiate et table CRL validées");

    // 4. Démon de certification JamboCertDaemon
    let mut daemon = JamboCertDaemon::new();
    assert_eq!(daemon.active_count(), 1); // Certificat d'amorce node-0

    let pub2 = [7u8; 32];
    let c2 = daemon
        .issue_cert(
            b"gateway.cluster.local",
            pub2,
            1000,
            2000,
            key_usages::USAGE_SERVER_AUTH,
        )
        .expect("daemon issue cert");
    assert_eq!(daemon.active_count(), 2);

    let v_ok = daemon
        .verify_cert(&c2, key_usages::USAGE_SERVER_AUTH, 1500)
        .expect("daemon verify");
    assert_eq!(v_ok, CertStatus::Valid);

    daemon.revoke_cert(c2.serial).expect("daemon revoke");
    let v_rev = daemon
        .verify_cert(&c2, key_usages::USAGE_SERVER_AUTH, 1500)
        .expect("daemon verify revoked");
    assert_eq!(v_rev, CertStatus::Revoked);
    kprintln!("[CERT/DAEMON] Cycle de vie complet du démon JamboCertDaemon validé");

    // 5. Intégration shell interactive (cert status, issue, verify, revoke)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // cert status
    let (st, len) = shell.execute_line("cert status", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("AUTORITÉ DE CERTIFICATION"));
    assert!(s.contains("Certificats actifs"));
    kprintln!("[CERT/SHELL] Commande 'cert status' validée");

    // cert issue
    let (st, len) = shell.execute_line("cert issue 1001 test-node.mesh 1000 3000", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[CERT/ISSUE]"));
    assert!(s.contains("test-node.mesh"));
    kprintln!("[CERT/SHELL] Commande 'cert issue' validée");

    // cert verify
    let (st, len) = shell.execute_line("cert verify 1001 1500", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[CERT/VERIFY]"));
    assert!(s.contains("Valid"));
    kprintln!("[CERT/SHELL] Commande 'cert verify' validée");

    // cert revoke
    let (st, len) = shell.execute_line("cert revoke 1001 2000", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[CERT/REVOKE]"));
    kprintln!("[CERT/SHELL] Commande 'cert revoke' validée");

    // cert verify post-revocation
    let (st, len) = shell.execute_line("cert verify 1001 2500", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("Revoked") || s.contains("introuvable"));
    kprintln!("[CERT/SHELL] Révocation interactive vérifiée avec succès");

    kprintln!("[CERT/PASS] Suite de tests PKI éphémère et mTLS complétée avec succès !");
    true
}

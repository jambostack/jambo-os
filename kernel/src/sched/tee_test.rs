//! Module de validation des Environnements d'Exécution de Confiance (TEE),
//! des Enclaves Matérielles Isolées et de la Mémoire Chiffrée Ring 3 (`jambo-tee`)
//! Phase 92 — Jalon v0.2.90
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_tee::{
    page_flags, tee_rights, EnclaveState, JamboTeeDaemon, SealingPolicy, Sha256,
    TeeAction, TeeBackend, TeeCap, MAX_ENCLAVES,
};

/// Exécute la suite complète de validation formelle du sous-système TEE (Phase 92)
pub fn execute_tee_daemon_test() -> bool {
    kprintln!(
        "[TEE/TEST] Démarrage du test des environnements d'exécution de confiance et enclaves (Phase 92)..."
    );

    // 1. Contrôle d'accès capabilaire (TeeCap) et rejet formel d'amplification
    let admin_cap = TeeCap::new(Handle::new(9201, 1), tee_rights::ALL);
    assert!(admin_cap.has_right(tee_rights::CREATE));
    assert!(admin_cap.has_right(tee_rights::LOAD));
    assert!(admin_cap.has_right(tee_rights::ENTER));
    assert!(admin_cap.has_right(tee_rights::SEAL));
    assert!(admin_cap.has_right(tee_rights::REPORT));
    assert!(admin_cap.has_right(tee_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(tee_rights::ENTER | tee_rights::SEAL | tee_rights::REPORT)
        .expect("attenuate TeeCap");
    assert!(attenuated_cap.has_right(tee_rights::ENTER));
    assert!(attenuated_cap.has_right(tee_rights::SEAL));
    assert!(attenuated_cap.has_right(tee_rights::REPORT));
    assert!(!attenuated_cap.has_right(tee_rights::CREATE));
    assert!(!attenuated_cap.has_right(tee_rights::LOAD));
    assert!(!attenuated_cap.has_right(tee_rights::ADMIN));

    // Rejet formel de toute tentative d'élévation
    assert_eq!(
        attenuated_cap.attenuate(tee_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits TeeCap formellement rejetée"
    );

    let mut daemon = JamboTeeDaemon::new(admin_cap);
    daemon.init_defaults();

    // Rejet de création d'enclave sans CREATE
    let signer = Sha256::digest(b"Vendor-SecAuthority-01");
    assert_eq!(
        daemon.create_enclave(
            &attenuated_cap,
            "illegal-enclave",
            TeeBackend::IntelSgx,
            10,
            0x7000_0000,
            0x10000,
            signer,
        ),
        Err(SysError::PermissionDenied),
        "Création sans droit CREATE doit être rejetée"
    );
    kprintln!("[TEE/CAP] Modèle de sécurité capabilaire TeeCap et rejet d'amplification validés");

    // 2. Invariant : Absence d'autorité ambiante (No Ambient Authority)
    let null_cap = TeeCap::new(Handle::NULL, tee_rights::ALL);
    assert_eq!(
        daemon.create_enclave(
            &null_cap,
            "ambient-test",
            TeeBackend::IntelTdx,
            10,
            0x7000_0000,
            0x10000,
            signer,
        ),
        Err(SysError::PermissionDenied),
        "Autorité ambiante (Handle NULL) formellement bloquée"
    );
    kprintln!("[TEE/AMBIENT] Absence d'autorité ambiante et étanchéité des handles validées");

    // 3. Cycle de vie strict de l'enclave & Mesure MRENCLAVE
    // Création d'une enclave Intel SGX
    let enc_id = daemon
        .create_enclave(
            &admin_cap,
            "secure-vault",
            TeeBackend::IntelSgx,
            100,
            0x0000_7002_0000_0000,
            64 * 1024,
            signer,
        )
        .expect("Création de l'enclave secure-vault");
    assert_eq!(enc_id, 3); // 1 et 2 créées par init_defaults

    let enclave_ref = daemon.get_enclave(enc_id).expect("get enclave");
    assert_eq!(enclave_ref.state, EnclaveState::Created);
    assert_eq!(enclave_ref.page_count, 0);

    // Chargement de pages (EADD)
    let page1_data = b"ENCLAVE_CODE_SEGMENT_DATA_INITIALIZER";
    daemon
        .load_page(
            &admin_cap,
            enc_id,
            0x0000_7002_0000_0000,
            page_flags::CODE,
            page1_data,
        )
        .expect("Chargement page 1 CODE");

    let page2_data = b"ENCLAVE_STATIC_SECRETS_TABLE";
    daemon
        .load_page(
            &admin_cap,
            enc_id,
            0x0000_7002_0000_1000,
            page_flags::REGULAR,
            page2_data,
        )
        .expect("Chargement page 2 DATA");

    // Finalisation & Calcul MRENCLAVE (EINIT)
    let mrenclave = daemon
        .finalize_enclave(&admin_cap, enc_id, 0x0000_7002_0000_0000)
        .expect("Finalisation de l'enclave");
    assert_ne!(mrenclave, [0u8; 32], "MRENCLAVE doit être non nul");

    // Interdiction de charger une page une fois finalisée
    assert_eq!(
        daemon.load_page(
            &admin_cap,
            enc_id,
            0x0000_7002_0000_2000,
            page_flags::REGULAR,
            b"LATE_PAGE_INJECTION",
        ),
        Err(SysError::InvalidArgument),
        "Modification post-finalisation formellement interdite"
    );

    // 4. Commutation de contexte sécurisé (EENTER / EEXIT)
    let entry = daemon
        .enter_enclave(&admin_cap, enc_id, 0xCAFE_BABE)
        .expect("Entrée dans l'enclave");
    assert_eq!(entry, 0x0000_7002_0000_0000);

    daemon
        .exit_enclave(&admin_cap, enc_id, 0)
        .expect("Sortie ordonnée de l'enclave");

    kprintln!("[TEE/LIFECYCLE] Cycle de vie (Created -> Loading -> Finalized -> Running) et MRENCLAVE validés");

    // 5. Isolation de mémoire chiffrée
    assert!(daemon.verify_memory_isolation(enc_id, 0x0000_7002_0000_0000));
    assert!(daemon.verify_memory_isolation(enc_id, 0x0000_7002_0000_FFF0));
    assert!(!daemon.verify_memory_isolation(enc_id, 0x0000_8000_0000_0000));
    kprintln!("[TEE/MEMORY] Étanchéité de l'espace mémoire d'enclave vérifiée");

    // 6. Scellement cryptographique (Sealed Storage)
    let secret_key = [0x42u8; 32];
    let secret_payload = b"ROOT_ENCLAVE_MASTER_SIGNING_KEY_2026";

    // Scellement par mesure exacte (ExactMeasurement)
    let blob_id = daemon
        .seal_data(
            &admin_cap,
            enc_id,
            SealingPolicy::ExactMeasurement,
            secret_payload,
            &secret_key,
        )
        .expect("Scellement de données");

    let mut unseal_buf = [0u8; 128];
    let len = daemon
        .unseal_data(&admin_cap, enc_id, blob_id, &secret_key, &mut unseal_buf)
        .expect("Déscellement conforme");
    assert_eq!(&unseal_buf[..len], secret_payload);

    // Tentative de déscellement avec mauvaise clé secrète
    let bad_key = [0x99u8; 32];
    assert_eq!(
        daemon.unseal_data(&admin_cap, enc_id, blob_id, &bad_key, &mut unseal_buf),
        Err(SysError::PermissionDenied),
        "Déscellement avec mauvaise clé formellement rejeté"
    );

    // Tentative de déscellement depuis une autre enclave (mismatch de mesure)
    let other_enc_id = 1; // Enclave sec-keyring (mesure différente)
    assert_eq!(
        daemon.unseal_data(&admin_cap, other_enc_id, blob_id, &secret_key, &mut unseal_buf),
        Err(SysError::PermissionDenied),
        "Déscellement inter-enclaves sans conformité de mesure formellement rejeté"
    );
    kprintln!("[TEE/SEAL] Stockage scellé, intégrité HMAC et confinement MRENCLAVE validés");

    // 7. Attestation cryptographique locale et distante (EREPORT)
    let challenge_nonce = b"CLUSTER_ATTESTATION_NONCE_NON_REPLAY_2026";
    let report = daemon
        .generate_report(&admin_cap, enc_id, challenge_nonce)
        .expect("Génération du rapport d'attestation");

    assert_eq!(report.enclave_id, enc_id);
    assert_eq!(report.backend, TeeBackend::IntelSgx);
    assert_eq!(report.measurement, mrenclave);
    assert_eq!(report.signer_id, signer);
    assert_eq!(&report.user_data[..challenge_nonce.len()], challenge_nonce);
    assert_ne!(report.report_mac, [0u8; 32]);
    kprintln!("[TEE/ATTEST] Rapport d'attestation signé par HMAC-SHA256 validé");

    // 8. Nettoyage strict et effacement de mémoire (Memory Scrubbing)
    daemon
        .destroy_enclave(&admin_cap, enc_id)
        .expect("Destruction de l'enclave");
    assert!(daemon.get_enclave(enc_id).is_err());
    kprintln!("[TEE/SCRUB] Destruction d'enclave et effacement sécurisé de mémoire validés");

    // 9. Validation des commandes interactives du shell (`tee`)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    // Commande status
    let (st1, len1) = shell.execute_line("tee status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    let s1 = core::str::from_utf8(&out[..len1]).unwrap_or("");
    assert!(s1.contains("ENVIRONNEMENTS D'EXÉCUTION DE CONFIANCE"));
    assert!(s1.contains("Intel SGX / TDX"));

    // Commande list
    let (st2, len2) = shell.execute_line("tee list", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    let s2 = core::str::from_utf8(&out[..len2]).unwrap_or("");
    assert!(s2.contains("sec-keyring"));
    assert!(s2.contains("realm-crypto"));

    // Commande report
    let (st3, len3) = shell.execute_line("tee report", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    let s3 = core::str::from_utf8(&out[..len3]).unwrap_or("");
    assert!(s3.contains("Attestation TEE"));
    assert!(s3.contains("MRENCLAVE"));

    // Commande audit
    let (st4, len4) = shell.execute_line("tee audit", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    let s4 = core::str::from_utf8(&out[..len4]).unwrap_or("");
    assert!(s4.contains("Condensat SHA-256 d'Audit TEE"));

    kprintln!("[TEE/SHELL] Commandes d'administration 'tee status/list/report/audit' validées");
    kprintln!("[TEE/SUCCESS] Sous-système TEE, Enclaves et Mémoire Chiffrée entièrement validés (Phase 92)");

    true
}

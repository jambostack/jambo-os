//! Module de validation formelle de la Gestion Continue de l'Exposition aux Menaces (CTEM) (`jambo-ctem`)
//! Phase 132 — Jalon v0.2.130
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_ctem::{
    ctem_rights, BusinessCriticality, CtemCap, CtemCycleSummary, CtemError, CtemPhase,
    ExposureSeverity, ExposureSource, ExposureStatus, JamboCtemDaemon, MobilizationActionType,
};

/// Exécute la suite complète de validation formelle du démon CTEM (Phase 132)
pub fn execute_ctem_daemon_test() -> bool {
    kprintln!(
        "[CTEM/TEST] Démarrage de la validation formelle de la gestion continue de l'exposition aux menaces CTEM (Phase 132)..."
    );

    // 1. Contrôle d'accès capabilaire (CtemCap) et atténuation monotone
    let admin_cap = CtemCap::new(Handle::new(13201, 1), ctem_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(ctem_rights::SCOPE_MANAGEMENT));
    assert!(admin_cap.has_right(ctem_rights::DISCOVERY_FEED));
    assert!(admin_cap.has_right(ctem_rights::PRIORITIZE_EXPOSURES));
    assert!(admin_cap.has_right(ctem_rights::VALIDATE_EXPLOITABILITY));
    assert!(admin_cap.has_right(ctem_rights::MOBILIZE_REMEDIATION));
    assert!(admin_cap.has_right(ctem_rights::QUERY_POSTURE));
    assert!(admin_cap.has_right(ctem_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(ctem_rights::ADMIN));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            ctem_rights::QUERY_POSTURE | ctem_rights::PRIORITIZE_EXPOSURES,
            5000,
            200,
        )
        .expect("Atténuation monotone CtemCap");
    assert!(monitor_cap.has_right(ctem_rights::QUERY_POSTURE));
    assert!(monitor_cap.has_right(ctem_rights::PRIORITIZE_EXPOSURES));
    assert!(!monitor_cap.has_right(ctem_rights::MOBILIZE_REMEDIATION));
    assert!(!monitor_cap.has_right(ctem_rights::ADMIN));
    assert_eq!(monitor_cap.max_lifetime, 5000);
    assert_eq!(monitor_cap.invocations_left, 200);

    // Rejet d'escalade
    assert_eq!(
        monitor_cap.attenuate(ctem_rights::ALL, 5000, 200),
        Err(CtemError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et scénario de référence
    let mut ctem = JamboCtemDaemon::new(admin_cap);
    ctem.init_defaults();
    assert_eq!(ctem.scope_count, 4);
    assert_eq!(ctem.exposure_count, 5);
    assert!(ctem.overall_exposure_score > 0);
    assert!(ctem.verify_ledger_integrity());

    // 3. Cadrage (Scoping) et Découverte (Discovery)
    let new_scope_id = ctem
        .add_scope(
            &admin_cap,
            "Sovereign Cryptographic Mesh",
            "jambo-pqc,kms,secroute",
            BusinessCriticality::Critical,
            16,
            5000,
        )
        .expect("Ajout périmètre souverain");
    assert_eq!(new_scope_id, 5);
    assert_eq!(ctem.scope_count, 5);

    let new_exp_id = ctem
        .ingest_exposure(
            &admin_cap,
            "Unverified Wasm Bytecode Admission",
            ExposureSource::Aspm,
            "jambo-pkgd:staging",
            BusinessCriticality::High,
            ExposureSeverity::High,
            "Package Ingestion -> Missing CycloneDX Sign Check",
            5010,
        )
        .expect("Ingestion nouvelle exposition");
    assert_eq!(new_exp_id, 6);
    assert_eq!(ctem.exposure_count, 6);

    // Rejet d'opération d'écriture par capacité atténuée
    assert_eq!(
        ctem.add_scope(
            &monitor_cap,
            "Rogue Scope",
            "none",
            BusinessCriticality::Low,
            1,
            5015
        ),
        Err(CtemError::PermissionDenied)
    );

    // 4. Hiérarchisation contextuelle (Prioritization)
    let prioritized = ctem
        .prioritize_exposures(&admin_cap, 5020)
        .expect("Hiérarchisation des expositions");
    assert_eq!(prioritized, 6);

    // 5. Validation empirique de l'exploitabilité (Validation)
    ctem.validate_exposure(&admin_cap, 1, true, 5030)
        .expect("Validation exposition #1");
    assert!(ctem.exposures[0].unwrap().validated_exploitable);

    // Validation négative (neutralisée par contrôle compensatoire)
    ctem.validate_exposure(&admin_cap, 4, false, 5035)
        .expect("Validation exposition #4 neutralisée");
    assert!(!ctem.exposures[3].unwrap().validated_exploitable);

    // 6. Mobilisation & Remédiation proactive (Mobilization & Remediate)
    let action_id = ctem
        .mobilize_remediation(
            &admin_cap,
            1,
            MobilizationActionType::EnforceWaf,
            "jambo-waf",
            5040,
        )
        .expect("Mobilisation remédiation #1");
    assert_eq!(action_id, 1);
    assert_eq!(ctem.action_count, 1);

    let initial_score = ctem.overall_exposure_score;
    ctem.remediate_exposure(&admin_cap, 1, 5050)
        .expect("Remédiation finale #1");
    assert_eq!(
        ctem.exposures[0].unwrap().status,
        ExposureStatus::Remediated
    );
    assert!(ctem.overall_exposure_score < initial_score);

    // 7. Cycle complet automatisé & Synthèse
    let summary = ctem
        .run_full_cycle(&admin_cap, 5060)
        .expect("Cycle complet automatisé");
    assert_eq!(summary.total_scopes, 5);
    assert_eq!(summary.total_exposures, 6);
    assert!(summary.mobilized_count > 0);

    // 8. Intégrité cryptographique SHA-256 du registre d'audit
    assert!(ctem.verify_ledger_integrity());

    kprintln!(
        "[CTEM/TEST] Validation réussie : 5 périmètres cadrés, 6 expositions fédérées, exploitabilité validée, remédiation orchestrée, registre SHA-256 intègre."
    );
    true
}

//! Module de validation formelle de la Gestion des Risques Fournisseurs & Dépendances Tierces (`jambo-tprm`)
//! Phase 139 — Jalon v0.3.6
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_tprm::{
    tprm_rights, ComplianceStandard, DependencyType, IngestionDecision, JamboTprmDaemon, Sha256,
    ThirdPartyAttestation, ToxicRiskFactor, TprmCap, TprmError, VendorStatus, VendorTier,
};

/// Exécute la suite complète de validation formelle du démon TPRM (Phase 139)
pub fn execute_tprm_daemon_test() -> bool {
    kprintln!(
        "[TPRM/TEST] Démarrage de la validation formelle TPRM & gouvernance des fournisseurs (Phase 139)..."
    );

    // 1. Contrôle d'accès capabilaire (TprmCap) et atténuation monotone
    let mut admin_cap = TprmCap::new(Handle::new(13901, 1), tprm_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(tprm_rights::REGISTER_VENDOR));
    assert!(admin_cap.has_right(tprm_rights::MAP_DEPENDENCY));
    assert!(admin_cap.has_right(tprm_rights::EVALUATE_RISK));
    assert!(admin_cap.has_right(tprm_rights::VERIFY_COMPLIANCE));
    assert!(admin_cap.has_right(tprm_rights::INGESTION_GATE));
    assert!(admin_cap.has_right(tprm_rights::QUARANTINE_ACTION));
    assert!(admin_cap.has_right(tprm_rights::QUERY_AUDIT));
    assert!(admin_cap.has_right(tprm_rights::ADMIN));

    // Atténuation monotone
    let gate_cap = admin_cap
        .attenuate(
            tprm_rights::INGESTION_GATE | tprm_rights::QUERY_AUDIT,
            4000,
            200,
        )
        .expect("Atténuation monotone TprmCap");
    assert!(gate_cap.has_right(tprm_rights::INGESTION_GATE));
    assert!(gate_cap.has_right(tprm_rights::QUERY_AUDIT));
    assert!(!gate_cap.has_right(tprm_rights::ADMIN));
    assert!(!gate_cap.has_right(tprm_rights::QUARANTINE_ACTION));
    assert_eq!(gate_cap.max_lifetime, 4000);
    assert_eq!(gate_cap.invocations_left, 200);

    // Rejet d'escalade illicite
    assert_eq!(
        gate_cap.attenuate(tprm_rights::ALL, 4000, 200),
        Err(TprmError::AttenuationViolation)
    );

    // 2. Initialisation du démon TPRM souverain avec données par défaut
    let mut tprm = JamboTprmDaemon::new(admin_cap);
    tprm.init_defaults();

    assert_eq!(tprm.vendor_count, 4);
    assert_eq!(tprm.dependency_count, 4);
    assert_eq!(tprm.attestation_count, 3);
    assert_eq!(tprm.evaluation_count, 4);

    // 3. Vérification des évaluations d'ingestion par défaut
    let eval_pqc = tprm
        .evaluations
        .iter()
        .flatten()
        .find(|e| e.dependency_id == 1)
        .expect("Évaluation PQC");
    assert_eq!(eval_pqc.decision, IngestionDecision::Approved);
    assert!(!eval_pqc.isolation_required);

    let eval_http = tprm
        .evaluations
        .iter()
        .flatten()
        .find(|e| e.dependency_id == 3)
        .expect("Évaluation HTTP parser");
    assert_eq!(eval_http.decision, IngestionDecision::ConditionalSandbox);
    assert!(eval_http.isolation_required);

    let eval_shadow = tprm
        .evaluations
        .iter()
        .flatten()
        .find(|e| e.dependency_id == 4)
        .expect("Évaluation Telemetry");
    assert_eq!(eval_shadow.decision, IngestionDecision::Quarantined);
    assert!(eval_shadow.isolation_required);

    let dep_shadow = tprm.find_dependency(4).expect("Dépendance #4");
    assert!(dep_shadow.is_quarantined);

    // 4. Enregistrement d'un nouveau fournisseur souverain : Quantum Hardware Security (id 5)
    tprm.register_vendor(
        &mut admin_cap,
        5,
        "Quantum-Hardware-Security",
        VendorTier::Tier1SovereignCore,
        99,
        true,
        2000,
    )
    .expect("Enregistrement fournisseur #5");
    assert_eq!(tprm.vendor_count, 5);

    // 5. Attestation de conformité SecNumCloud pour le fournisseur #5
    tprm.record_attestation(
        &mut admin_cap,
        4,
        5,
        ComplianceStandard::SecNumCloud,
        "ANSSI-Auditor-L4",
        &[0x55; 32],
        300_000,
        2010,
    )
    .expect("Attestation SecNumCloud fournisseur #5");

    // 6. Cartographie d'une dépendance souveraine #5
    tprm.map_dependency(
        &mut admin_cap,
        5,
        5,
        "libquantum-rng-core",
        10000,
        DependencyType::RustCrate,
        &[0x77; 32],
        0,
        0,
        ToxicRiskFactor::None,
        2020,
    )
    .expect("Cartographie dépendance #5");
    assert_eq!(tprm.dependency_count, 5);

    // 7. Évaluation d'ingestion de la dépendance #5 -> Doit être Approved
    let dec5 = tprm
        .evaluate_ingestion(&mut admin_cap, 5, 2030)
        .expect("Évaluation dépendance #5");
    assert_eq!(dec5, IngestionDecision::Approved);

    // 8. Test de mise en quarantaine ciblée et cascade fournisseur
    tprm.quarantine_dependency(&mut admin_cap, 3, 2040)
        .expect("Quarantaine dépendance #3");
    assert!(tprm.find_dependency(3).unwrap().is_quarantined);

    tprm.quarantine_vendor(&mut admin_cap, 4, 2050)
        .expect("Quarantaine fournisseur #4");
    let v4 = tprm.find_vendor(4).unwrap();
    assert_eq!(v4.status, VendorStatus::Quarantined);
    assert_eq!(v4.composite_risk_score, 99);

    // 9. Vérification de la synthèse TPRM globale
    let summary = tprm.get_summary(&admin_cap).expect("Synthèse TPRM");
    assert_eq!(summary.total_vendors, 5);
    assert_eq!(summary.total_dependencies, 5);
    assert_eq!(summary.quarantined_dependencies, 2);
    assert_eq!(summary.verified_attestations, 4);
    assert!(summary.global_supply_chain_health > 50);

    // 10. Vérification du registre d'audit cryptographique SHA-256
    assert!(tprm.verify_ledger_integrity());

    kprintln!(
        "[TPRM/TEST] Validation formelle TPRM réussie : 5 fournisseurs gouvernés, 5 dépendances supervisées, quarantaine O(1) opérationnelle, registre SHA-256 intègre."
    );
    true
}

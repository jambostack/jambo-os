//! Module de validation formelle de la Gestion des Risques Fournisseurs & Dépendances Tierces (`jambo-tprm`)
//! Phase 169 — Jalon v0.3.36
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_tprm::{
    tprm_rights, ComplianceStandard, DependencyType, IngestionDecision, JamboTprmDaemon, Sha256,
    ThirdPartyAttestation, ToxicRiskFactor, TprmCap, TprmError, TprmPostureReport,
    TprmRemediationReport, TprmVendorReport, VendorStatus, VendorTier,
};

/// Exécute la suite complète de validation formelle du démon TPRM (Phase 169 - v0.3.36)
pub fn execute_tprm_daemon_test() -> bool {
    kprintln!(
        "[TPRM/TEST] Démarrage de la validation formelle TPRM & gouvernance des fournisseurs (Phase 169 - v0.3.36)..."
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
    assert!(admin_cap.has_right(tprm_rights::REMEDIATE));
    assert!(admin_cap.has_right(tprm_rights::GENERATE_REPORT));

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
    assert!(!gate_cap.has_right(tprm_rights::REMEDIATE));
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
    assert_eq!(tprm.attestation_count, 4);
    assert_eq!(tprm.evaluation_count, 4);

    // Vérification de la souveraineté européenne et TEE Hardware sur le fournisseur 1
    let v1 = tprm.find_vendor(1).expect("Fournisseur 1");
    assert!(v1.european_sovereign);
    assert!(v1.tee_hardware_assured);
    assert!(v1.compliance_certified);
    assert!(v1.fixed_point_risk < 1000); // Risque < 10.00%

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

    // 4. Vérification de la signature Ed25519 de la dépendance #1
    let dep1 = tprm.find_dependency(1).expect("Dépendance #1");
    assert!(dep1.is_signed);
    assert!(dep1.signature_valid);
    assert!(tprm
        .verify_package_signature(&mut admin_cap, 1, 1500)
        .expect("Vérification signature"));

    // 5. Enregistrement d'un nouveau fournisseur souverain : Quantum Hardware Security (id 5) avec TEE
    tprm.register_vendor_ext(
        &mut admin_cap,
        5,
        "Quantum-Hardware-Security",
        VendorTier::Tier1SovereignCore,
        99,
        true,
        true, // European sovereign
        true, // TEE hardware assured
        2000,
    )
    .expect("Enregistrement fournisseur #5");
    assert_eq!(tprm.vendor_count, 5);

    // 6. Attestation de conformité SecNumCloud pour le fournisseur #5
    tprm.record_attestation(
        &mut admin_cap,
        5,
        5,
        ComplianceStandard::SecNumCloud,
        "ANSSI-Auditor-L4",
        &[0x55; 32],
        300_000,
        2010,
    )
    .expect("Attestation SecNumCloud fournisseur #5");
    assert_eq!(tprm.attestation_count, 5);

    // 7. Cartographie d'une dépendance souveraine #5 signée Ed25519
    let sig5 = [0x7Au8; 64];
    tprm.map_signed_dependency(
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
        true,
        &sig5,
        2020,
    )
    .expect("Cartographie dépendance #5 signée");
    assert_eq!(tprm.dependency_count, 5);

    // 8. Évaluation d'ingestion de la dépendance #5 -> Doit être Approved
    let dec5 = tprm
        .evaluate_ingestion(&mut admin_cap, 5, 2030)
        .expect("Évaluation dépendance #5");
    assert_eq!(dec5, IngestionDecision::Approved);

    // 9. Remédiation proactive O(1) de tous les composants & fournisseurs compromis
    let rem_count = tprm
        .remediate_all_compromised(&mut admin_cap, 2040)
        .expect("Remédiation proactive O(1)");
    assert!(
        rem_count > 0,
        "Au moins le fournisseur 4 et la dépendance 4 remédiés"
    );

    let v4 = tprm.find_vendor(4).unwrap();
    assert_eq!(v4.status, VendorStatus::Quarantined);
    assert_eq!(v4.composite_risk_score, 99);

    // 10. Génération et vérification des rapports scellés SHA-256
    let rep_posture = tprm
        .generate_posture_report(&admin_cap, 2050)
        .expect("Rapport de posture scellé");
    assert!(
        rep_posture.verify_seal(),
        "Sceau SHA-256 du rapport de posture TPRM valide"
    );
    assert_eq!(rep_posture.total_vendors, 5);
    assert_eq!(rep_posture.total_dependencies, 5);

    let rep_vendor = tprm
        .generate_vendor_report(&admin_cap, 5, 2060)
        .expect("Rapport fournisseur scellé");
    assert!(
        rep_vendor.verify_seal(),
        "Sceau SHA-256 du rapport fournisseur TPRM valide"
    );
    assert!(rep_vendor.european_sovereign);
    assert!(rep_vendor.tee_hardware_assured);

    let rep_rem = tprm
        .generate_remediation_report(&mut admin_cap, 2070)
        .expect("Rapport de remédiation scellé");
    assert!(
        rep_rem.verify_seal(),
        "Sceau SHA-256 du rapport de remédiation TPRM valide"
    );

    // 11. Vérification de la synthèse TPRM globale
    let summary = tprm.get_summary(&admin_cap).expect("Synthèse TPRM");
    assert_eq!(summary.total_vendors, 5);
    assert_eq!(summary.total_dependencies, 5);
    assert_eq!(summary.verified_attestations, 5);
    assert!(summary.global_supply_chain_health > 50);

    // 12. Vérification du registre d'audit cryptographique SHA-256
    assert!(
        tprm.verify_ledger_integrity(),
        "Registre d'audit cryptographique TPRM intègre"
    );

    kprintln!(
        "[TPRM/TEST] Validation Phase 169 réussie : 5 fournisseurs gouvernés (SecNumCloud/EU/TEE), signatures Ed25519 vérifiées, scoring virgule fixe actif, remédiation autonome O(1) & quarantaine validées, rapports scellés SHA-256 vérifiés, registre SHA-256 intègre."
    );
    true
}

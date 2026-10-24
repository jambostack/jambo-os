//! Module de validation formelle de la Plateforme Unifiée de Protection des Applications Cloud-Natives CNAPP (`jambo-cnapp`)
//! Corrélation Multi-Signaux CSPM+CWPP+CIEM & Calcul de Graphe de Risque Holistique
//!
//! Phase 158 — Jalon v0.3.25
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_cnapp::{
    cnapp_rights, AttackPath, AttackPathNode, CloudEnvironment, CnappAssessmentReport, CnappCap,
    CnappError, CnappFinding, CnappSeverity, JamboCnappDaemon, OrchestrationAction, SignalSource,
    ToxicCombinationType, WorkloadKind,
};

/// Exécute la suite complète de validation formelle du démon CNAPP souverain (Phase 158 - v0.3.25)
pub fn execute_cnapp_daemon_test() -> bool {
    kprintln!(
        "[CNAPP/TEST] Démarrage de la validation formelle CNAPP, corrélation CSPM+CWPP+CIEM & graphes de risque (Phase 158 - v0.3.25)..."
    );

    // 1. Contrôle d'accès capabilaire (CnappCap) et atténuation monotone stricte
    let admin_cap = CnappCap::new(Handle::new(12801, 1), cnapp_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(cnapp_rights::INGEST_SIGNALS));
    assert!(admin_cap.has_right(cnapp_rights::CORRELATE_RISK));
    assert!(admin_cap.has_right(cnapp_rights::BUILD_ATTACK_GRAPH));
    assert!(admin_cap.has_right(cnapp_rights::ORCHESTRATE_REMEDIATION));
    assert!(admin_cap.has_right(cnapp_rights::QUERY_POSTURE));
    assert!(admin_cap.has_right(cnapp_rights::READ_METRICS));
    assert!(admin_cap.has_right(cnapp_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(cnapp_rights::ADMIN));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            cnapp_rights::QUERY_POSTURE | cnapp_rights::READ_METRICS,
            5000,
            200,
        )
        .expect("Atténuation monotone CnappCap");
    assert!(monitor_cap.has_right(cnapp_rights::QUERY_POSTURE));
    assert!(monitor_cap.has_right(cnapp_rights::READ_METRICS));
    assert!(!monitor_cap.has_right(cnapp_rights::ORCHESTRATE_REMEDIATION));
    assert!(!monitor_cap.has_right(cnapp_rights::ADMIN));
    assert_eq!(monitor_cap.max_lifetime, 5000);
    assert_eq!(monitor_cap.invocations_left, 200);

    // Rejet d'escalade
    assert_eq!(
        monitor_cap.attenuate(cnapp_rights::ALL, 5000, 200),
        Err(CnappError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et cartographie de grappe par défaut
    let mut cnapp = JamboCnappDaemon::new(admin_cap);
    cnapp.init_defaults();
    assert_eq!(cnapp.node_count, 4);
    assert_eq!(cnapp.finding_count, 4);
    assert!(cnapp.verify_ledger_integrity());

    // 3. Détection de combinaison toxique tri-plans (Toxic Combination) sur cluster-operator (103)
    let node103 = cnapp
        .nodes
        .iter()
        .flatten()
        .find(|n| n.workload_id == 103)
        .unwrap();
    assert!(node103.is_toxic_combination);
    assert_eq!(
        node103.toxic_type,
        ToxicCombinationType::TriPlaneSovereignBreach
    );
    assert_eq!(node103.unified_risk_score, 100);

    // Graphe d'attaque corrélé
    assert!(cnapp.path_count >= 1);
    assert_eq!(cnapp.toxic_combinations_count, 1);

    // 4. Exécution de la corrélation multidimensionnelle au tick 2000
    let (paths, toxics) = cnapp
        .correlate_signals(&admin_cap, 2000)
        .expect("Corrélation contextuelle CNAPP");
    assert!(paths >= 1);
    assert_eq!(toxics, 1);
    assert!(cnapp.verify_ledger_integrity());

    // Rejet de remédiation avec privilèges insuffisants
    assert_eq!(
        cnapp.orchestrate_remediation(&monitor_cap, 103, 2100),
        Err(CnappError::PermissionDenied)
    );

    // 5. Orchestration autonome de la remédiation unifiée sur la combinaison toxique 103
    let action = cnapp
        .orchestrate_remediation(&admin_cap, 103, 2200)
        .expect("Remédiation unifiée CNAPP");
    assert_eq!(action, OrchestrationAction::FullUnifiedContainment);

    // Vérification de la sécurisation et de la mise en quarantaine de la charge 103
    let rem_node103 = cnapp
        .nodes
        .iter()
        .flatten()
        .find(|n| n.workload_id == 103)
        .unwrap();
    assert!(rem_node103.is_quarantined);
    assert!(!rem_node103.is_toxic_combination);
    assert!(rem_node103.unified_risk_score <= 10);

    // 6. Validation du rapport d'évaluation & remédiation scellé SHA-256
    assert!(cnapp.report_count > 0);
    let rep = cnapp.latest_report().expect("Rapport scellé présent");
    assert_eq!(rep.workload_id, 103);
    assert_eq!(rep.action, OrchestrationAction::FullUnifiedContainment);
    assert!(rep.toxic_broken);
    assert!(rep.initial_risk >= 90);
    assert!(rep.post_risk <= 10);

    let expected_seal = CnappAssessmentReport::compute_seal(
        rep.report_id,
        rep.workload_id,
        rep.timestamp,
        rep.action,
        rep.initial_risk,
        rep.post_risk,
        rep.toxic_broken,
        rep.attack_paths_neutralized,
    );
    assert_eq!(rep.report_seal, expected_seal);

    // 7. Enregistrement dynamique d'une enclave TEE et détection d'exfiltration de données
    cnapp
        .register_workload_detailed(
            &admin_cap,
            105,
            "secnum-hsm-enclave",
            CloudEnvironment::SecNumCloudEnclave,
            WorkloadKind::EnclaveTEE,
            true, // exposée via egress
            3,    // haute sensibilité
            2300,
        )
        .expect("Enregistrement enclave TEE");

    // Ingestion de droits CIEM excessifs sur clés cryptographiques
    cnapp
        .ingest_finding(
            &admin_cap,
            CnappFinding::new(
                205,
                105,
                SignalSource::CiemEntitlement,
                CnappSeverity::Critical,
                95,
                "CIEM: Unlimited Master Key Export Privilege",
                2350,
            ),
        )
        .expect("Ingestion signal CIEM");

    let (paths_dyn, toxics_dyn) = cnapp
        .correlate_signals(&admin_cap, 2400)
        .expect("Corrélation post-TEE");
    assert!(paths_dyn >= 1);
    assert_eq!(toxics_dyn, 1);

    let node105 = cnapp
        .nodes
        .iter()
        .flatten()
        .find(|n| n.workload_id == 105)
        .unwrap();
    assert!(node105.is_toxic_combination);
    assert_eq!(
        node105.toxic_type,
        ToxicCombinationType::EnclaveDataExfiltration
    );

    // Remédiation d'urgence de l'enclave
    let act105 = cnapp
        .orchestrate_remediation(&admin_cap, 105, 2500)
        .expect("Remédiation enclave TEE");
    assert_eq!(act105, OrchestrationAction::FullUnifiedContainment);

    // 8. Remédiation globale critique
    let rem_count = cnapp
        .remediate_all_critical(&admin_cap, 2600)
        .expect("Remédiation globale critique");
    assert_eq!(rem_count, 0); // Déjà remédié

    // Recalcul de corrélation
    let (_p_final, toxics_final) = cnapp
        .correlate_signals(&admin_cap, 2700)
        .expect("Corrélation finale");
    assert_eq!(toxics_final, 0);

    // 9. Vérification de l'intégrité cryptographique absolue du registre d'audit SHA-256
    assert!(cnapp.verify_ledger_integrity());

    kprintln!(
        "[CNAPP/TEST] \x1b[1;32mSuccès de la validation formelle CNAPP (Phase 158) : {} charges, {} signaux ingérés, {} rapports scellés SHA-256, intégrité vérifiée\x1b[0m",
        cnapp.node_count,
        cnapp.finding_count,
        cnapp.report_count
    );

    true
}

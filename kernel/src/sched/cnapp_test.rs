//! Module de validation formelle de la Plateforme Intégrée de Protection Cloud-Native (CNAPP) (`jambo-cnapp`)
//! Phase 128 — Jalon v0.2.126
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_cnapp::{
    cnapp_rights, AttackPath, AttackPathNode, CnappCap, CnappError, CnappFinding, CnappSeverity,
    JamboCnappDaemon, OrchestrationAction, SignalSource,
};

/// Exécute la suite complète de validation formelle du démon CNAPP (Phase 128)
pub fn execute_cnapp_daemon_test() -> bool {
    kprintln!(
        "[CNAPP/TEST] Démarrage de la validation formelle de la protection applicative cloud-native CNAPP (Phase 128)..."
    );

    // 1. Contrôle d'accès capabilaire (CnappCap) et atténuation monotone
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

    // 2. Initialisation du démon central et scénario de référence
    let mut cnapp = JamboCnappDaemon::new(admin_cap);
    cnapp.init_defaults();
    assert_eq!(cnapp.node_count, 4);
    assert_eq!(cnapp.finding_count, 4);
    assert!(cnapp.verify_ledger_integrity());

    // 3. Détection de combinaison toxique (Toxic Combination) et score maximal sur cluster-operator (103)
    let node103 = cnapp
        .nodes
        .iter()
        .flatten()
        .find(|n| n.workload_id == 103)
        .unwrap();
    assert!(node103.is_toxic_combination);
    assert_eq!(node103.unified_risk_score, 100);

    // Graphe d'attaque corrélé
    assert!(cnapp.path_count >= 1);
    assert_eq!(cnapp.toxic_combinations_count, 1);

    // 4. Exécution de la corrélation contextuelle au tick 2000
    let (paths, toxics) = cnapp
        .correlate_signals(&admin_cap, 2000)
        .expect("Corrélation contextuelle CNAPP");
    assert!(paths >= 1);
    assert_eq!(toxics, 1);
    assert!(cnapp.verify_ledger_integrity());

    // Rejet avec privilèges insuffisants
    assert_eq!(
        cnapp.orchestrate_remediation(&monitor_cap, 103, 2100),
        Err(CnappError::PermissionDenied)
    );

    // 5. Orchestration autonome de la remédiation unifiée sur la combinaison toxique 103
    let action = cnapp
        .orchestrate_remediation(&admin_cap, 103, 2200)
        .expect("Remédiation unifiée CNAPP");
    assert_eq!(action, OrchestrationAction::FullUnifiedContainment);

    // Vérification de la sécurisation de la charge
    let rem_node103 = cnapp
        .nodes
        .iter()
        .flatten()
        .find(|n| n.workload_id == 103)
        .unwrap();
    assert!(rem_node103.is_quarantined);
    assert!(!rem_node103.is_toxic_combination);
    assert!(rem_node103.unified_risk_score <= 10);

    // 6. Recalcul de corrélation post-remédiation
    let (_paths_post, toxics_post) = cnapp
        .correlate_signals(&admin_cap, 2300)
        .expect("Corrélation post-remédiation");
    assert_eq!(toxics_post, 0);

    // 7. Vérification de l'intégrité cryptographique absolue du registre d'audit SHA-256
    assert!(cnapp.verify_ledger_integrity());

    kprintln!(
        "[CNAPP/TEST] \x1b[1;32mSuccès de la validation formelle CNAPP : {} charges, {} signaux ingérés, {} chemins d'attaque corrélés, remédiation unifiée totale scellée SHA-256\x1b[0m",
        cnapp.node_count,
        cnapp.finding_count,
        cnapp.path_count
    );

    true
}

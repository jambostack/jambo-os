//! Module de validation formelle des Opérations IT Pilotées par l'IA (AIOps) (`jambo-aiops`)
//! Phase 137 — Jalon v0.3.4
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_aiops::{
    aiops_rights, AiopsCap, AiopsError, AnomalySeverity, EventSeverity, EventSource,
    IncidentStatus, JamboAiopsDaemon, PlaybookAction, Sha256,
};

/// Exécute la suite complète de validation formelle du démon AIOps (Phase 137)
pub fn execute_aiops_daemon_test() -> bool {
    kprintln!(
        "[AIOPS/TEST] Démarrage de la validation formelle des opérations IT pilotées par l'IA (Phase 137)..."
    );

    // 1. Contrôle d'accès capabilaire (AiopsCap) et atténuation monotone
    let mut admin_cap = AiopsCap::new(Handle::new(13701, 1), aiops_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(aiops_rights::INGEST_EVENTS));
    assert!(admin_cap.has_right(aiops_rights::DETECT_ANOMALIES));
    assert!(admin_cap.has_right(aiops_rights::CORRELATE_INCIDENTS));
    assert!(admin_cap.has_right(aiops_rights::TRIGGER_PLAYBOOK));
    assert!(admin_cap.has_right(aiops_rights::MANAGE_TOPOLOGY));
    assert!(admin_cap.has_right(aiops_rights::CONFIGURE_RULES));
    assert!(admin_cap.has_right(aiops_rights::QUERY_AUDIT));
    assert!(admin_cap.has_right(aiops_rights::ADMIN));

    // Atténuation monotone
    let telemetry_cap = admin_cap
        .attenuate(
            aiops_rights::INGEST_EVENTS | aiops_rights::QUERY_AUDIT,
            4000,
            200,
        )
        .expect("Atténuation monotone AiopsCap");
    assert!(telemetry_cap.has_right(aiops_rights::INGEST_EVENTS));
    assert!(telemetry_cap.has_right(aiops_rights::QUERY_AUDIT));
    assert!(!telemetry_cap.has_right(aiops_rights::ADMIN));
    assert!(!telemetry_cap.has_right(aiops_rights::TRIGGER_PLAYBOOK));
    assert_eq!(telemetry_cap.max_lifetime, 4000);
    assert_eq!(telemetry_cap.invocations_left, 200);

    // Rejet d'escalade illicite
    assert_eq!(
        telemetry_cap.attenuate(aiops_rights::ALL, 4000, 200),
        Err(AiopsError::AttenuationViolation)
    );

    // 2. Initialisation du démon AIOps souverain avec topologie par défaut
    let mut aiops = JamboAiopsDaemon::new(admin_cap);
    aiops.init_defaults();

    assert_eq!(aiops.topology_count, 4);
    assert_eq!(aiops.playbook_count, 3);

    // 3. Enregistrement d'un service souverain supplémentaire dans la topologie
    // Service 5 : Nœud de Cache Décentralisé (Tier 1, dépend de la BD 1)
    aiops
        .register_service(&mut admin_cap, 5, "sovereign_cache", 1, &[1], 5000)
        .expect("Enregistrement nœud de cache");
    assert_eq!(aiops.topology_count, 5);

    // 4. Établissement d'une baseline de télémétrie sur sovereign_db (service 1) et api_gateway (service 3)
    for t in 0..12 {
        let _ = aiops
            .ingest_metric(
                &mut admin_cap,
                1,
                EventSource::DatabaseEngine,
                "db_query_latency_ms",
                25 + (t % 4),
                6000 + t as u64,
            )
            .expect("Ingestion métrique DB nominale");

        let _ = aiops
            .ingest_metric(
                &mut admin_cap,
                3,
                EventSource::ApiGateway,
                "gateway_5xx_rate",
                0,
                6000 + t as u64,
            )
            .expect("Ingestion métrique Gateway nominale");
    }

    // Aucune anomalie sur le régime stable
    assert_eq!(aiops.anomaly_count, 0);

    // 5. Injection d'une anomalie statistique prédictive (Z-score élevé)
    // Pic brutal de latence sur la BD souveraine (750 ms au lieu de ~25 ms)
    let anom1 = aiops
        .ingest_metric(
            &mut admin_cap,
            1,
            EventSource::DatabaseEngine,
            "db_query_latency_ms",
            750,
            6020,
        )
        .expect("Ingestion pic de latence DB");
    assert!(
        anom1.is_some(),
        "L'anomalie critique sur la BD doit être détectée"
    );

    // Propagation de l'incident : pic d'erreurs 5xx sur la passerelle API
    let anom2 = aiops
        .ingest_metric(
            &mut admin_cap,
            3,
            EventSource::ApiGateway,
            "gateway_5xx_rate",
            120,
            6025,
        )
        .expect("Ingestion pic d'erreurs passerelle");
    assert!(
        anom2.is_some(),
        "L'anomalie critique sur la passerelle doit être détectée"
    );
    assert_eq!(aiops.anomaly_count, 2);

    // 6. Corrélation topologique multi-sources et Root Cause Analysis (RCA)
    let correlated = aiops
        .correlate_incidents(&mut admin_cap, 6030)
        .expect("Corrélation topologique");
    assert_eq!(correlated, 1);
    assert_eq!(aiops.incident_count, 1);

    let incident = aiops.incidents[0].unwrap();
    assert_eq!(
        incident.root_cause_service_id, 1,
        "La cause racine identifiée doit être le service DB (Tier 2)"
    );
    assert_eq!(incident.status, IncidentStatus::Active);
    assert!(incident.confidence_score >= 80);

    // 7. Déclenchement automatique et exécution du playbook d'auto-remédiation
    let action = aiops
        .trigger_remediation(&mut admin_cap, incident.id, 6035)
        .expect("Exécution du playbook de remédiation");
    assert_eq!(
        action,
        PlaybookAction::ScaleResource,
        "Le playbook auto_scale_database doit être sélectionné"
    );

    let resolved_incident = aiops.incidents[0].unwrap();
    assert_eq!(resolved_incident.status, IncidentStatus::Resolved);
    assert_eq!(
        resolved_incident.playbook_executed,
        Some(PlaybookAction::ScaleResource)
    );

    // 8. Synthèse globale AIOps
    let summary = aiops
        .get_summary(&admin_cap)
        .expect("Synthèse globale AIOps");
    assert_eq!(summary.total_services, 5);
    assert_eq!(summary.total_anomalies, 2);
    assert_eq!(summary.active_incidents, 0);
    assert_eq!(summary.resolved_incidents, 1);
    assert_eq!(summary.health_score, 100);

    // 9. Vérification de l'intégrité cryptographique du registre d'audit SHA-256
    assert!(
        aiops.verify_ledger_integrity(),
        "Registre d'audit AIOps cryptographiquement intègre"
    );

    kprintln!(
        "[AIOPS/TEST] Validation réussie : 5 services topologiques, 2 anomalies corrélées, RCA validé (DB root cause), playbook auto-scale exécuté, audit SHA-256 vérifié."
    );
    true
}

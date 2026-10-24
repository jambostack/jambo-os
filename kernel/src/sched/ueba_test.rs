//! Module de validation formelle de l'Analyse Comportementale des Utilisateurs et Entités Souveraine (`jambo-ueba`)
//! Phase 146 — Jalon v0.3.13
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_ueba::{
    ueba_rights, ActivityEvent, BehaviorBaseline, EntityType, JamboUebaDaemon, RiskLevel,
    UebaAction, UebaAnomalyType, UebaCap, UebaError, UebaSummary,
};

/// Exécute la suite complète de validation formelle du moteur UEBA souverain (Phase 146)
pub fn execute_ueba_daemon_test() -> bool {
    kprintln!(
        "[UEBA/TEST] Démarrage de la validation formelle Analyse Comportementale des Utilisateurs et Entités (Phase 146)..."
    );

    // 1. Contrôle d'accès capabilaire (UebaCap) et atténuation monotone
    let admin_cap = UebaCap::new(Handle::new(14601, 1), ueba_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(ueba_rights::INGEST_EVENT));
    assert!(admin_cap.has_right(ueba_rights::TRAIN_BASELINE));
    assert!(admin_cap.has_right(ueba_rights::ANALYZE_BEHAVIOR));
    assert!(admin_cap.has_right(ueba_rights::ENFORCE_ACTION));
    assert!(admin_cap.has_right(ueba_rights::QUARANTINE_ENTITY));
    assert!(admin_cap.has_right(ueba_rights::CONFIGURE_MODEL));
    assert!(admin_cap.has_right(ueba_rights::QUERY_METRICS));
    assert!(admin_cap.has_right(ueba_rights::QUERY_AUDIT));
    assert!(admin_cap.has_right(ueba_rights::ADMIN));

    // Atténuation monotone
    let analyze_cap = admin_cap
        .attenuate(
            ueba_rights::INGEST_EVENT | ueba_rights::ANALYZE_BEHAVIOR | ueba_rights::QUERY_AUDIT,
            5000,
            250,
        )
        .expect("Atténuation monotone UebaCap");
    assert!(analyze_cap.has_right(ueba_rights::INGEST_EVENT));
    assert!(analyze_cap.has_right(ueba_rights::ANALYZE_BEHAVIOR));
    assert!(analyze_cap.has_right(ueba_rights::QUERY_AUDIT));
    assert!(!analyze_cap.has_right(ueba_rights::ADMIN));
    assert!(!analyze_cap.has_right(ueba_rights::QUARANTINE_ENTITY));
    assert!(!analyze_cap.has_right(ueba_rights::CONFIGURE_MODEL));
    assert_eq!(analyze_cap.max_lifetime, 5000);
    assert_eq!(analyze_cap.invocations_left, 250);

    // Rejet d'escalade illicite
    assert_eq!(
        analyze_cap.attenuate(ueba_rights::ALL, 5000, 250),
        Err(UebaError::AttenuationViolation)
    );

    // 2. Initialisation du démon UEBA souverain avec profils par défaut
    let mut ueba = JamboUebaDaemon::new(admin_cap);
    ueba.init_defaults();

    assert_eq!(ueba.profile_count, 3);
    assert_eq!(ueba.quarantine_count, 0);

    let summary0 = ueba.get_summary();
    assert_eq!(summary0.profiles_count, 3);
    assert_eq!(summary0.events_processed, 0);
    assert_eq!(summary0.anomalies_detected, 0);
    assert_eq!(summary0.quarantine_count, 0);
    assert!(summary0.ledger_valid);

    // 3. Activité nominale et bénigne : service frontend (14h00, 50 syscalls, 2000 octets, pair connu)
    let event_benign = ActivityEvent::new(
        101,
        "frontend_srv",
        EntityType::ServiceDaemon,
        1735200000,
        14,
        50,
        2000,
        "backend_srv",
    );
    let res_benign = ueba
        .ingest_and_analyze(&event_benign)
        .expect("Analyse nominale");
    assert_eq!(res_benign.action, UebaAction::Allow);
    assert_eq!(res_benign.risk_level, RiskLevel::Low);
    assert!(res_benign.risk_score < 30);
    assert_eq!(res_benign.primary_anomaly, UebaAnomalyType::None);
    assert!(!res_benign.quarantined);

    // 4. Dérive volumétrique (VolumeSurge) : tentative d'exfiltration ou lecture massive
    let event_volume = ActivityEvent::new(
        102,
        "frontend_srv",
        EntityType::ServiceDaemon,
        1735201000,
        14,
        50,
        250000, // 250k octets vs 2k nominal
        "backend_srv",
    );
    let res_volume = ueba
        .ingest_and_analyze(&event_volume)
        .expect("Analyse volumétrique");
    assert!(res_volume.volume_z_score_x10 >= 30);
    assert!(res_volume.risk_score >= 30);
    assert_ne!(res_volume.action, UebaAction::Allow);

    // 5. Mouvement latéral (LateralMovement) : tentative de connexion à un pair non autorisé
    let event_lateral = ActivityEvent::new(
        103,
        "frontend_srv",
        EntityType::ServiceDaemon,
        1735202000,
        15,
        50,
        2000,
        "rogue_internal_node",
    );
    let res_lateral = ueba
        .ingest_and_analyze(&event_lateral)
        .expect("Analyse mouvement latéral");
    assert!(res_lateral.peer_anomaly_detected);
    assert!(res_lateral.risk_score >= 30);

    // 6. Anomalie temporelle hors-plage (OffHoursSpike) + opération privilégiée non planifiée
    let event_offhours = ActivityEvent::new(
        104,
        "sys_admin",
        EntityType::UserAccount,
        1735203000,
        2, // 02h00 du matin (hors-plage 09h..19h)
        20,
        500,
        "internal_bastion",
    )
    .with_privileged(true);
    let res_offhours = ueba
        .ingest_and_analyze(&event_offhours)
        .expect("Analyse hors-plage");
    assert!(res_offhours.temporal_anomaly_detected);
    assert!(res_offhours.privilege_anomaly_detected);
    assert!(res_offhours.risk_score >= 60);

    // 7. Attaque multidimensionnelle critique -> Quarantaine O(1)
    let event_critical = ActivityEvent::new(
        105,
        "malicious_agent",
        EntityType::ServiceDaemon,
        1735204000,
        1, // Nocturne
        800,
        2000000, // Volume massif
        "external_c2_peer",
    )
    .with_privileged(true)
    .with_failed_auth(true);
    let res_critical = ueba
        .ingest_and_analyze(&event_critical)
        .expect("Analyse critique");
    assert_eq!(res_critical.risk_level, RiskLevel::Critical);
    assert_eq!(res_critical.action, UebaAction::Quarantine);
    assert!(res_critical.quarantined);
    assert!(res_critical.risk_score >= 85);
    assert!(ueba.is_quarantined("malicious_agent"));

    // 8. Vérification du confinement O(1) : tout événement ultérieur est bloqué immédiatement
    let event_blocked = ActivityEvent::new(
        106,
        "malicious_agent",
        EntityType::ServiceDaemon,
        1735204100,
        12,
        10,
        100,
        "backend_srv",
    );
    let res_blocked = ueba
        .ingest_and_analyze(&event_blocked)
        .expect("Vérification confinement");
    assert_eq!(res_blocked.action, UebaAction::Quarantine);
    assert!(res_blocked.quarantined);
    assert_eq!(res_blocked.risk_score, 100);

    // 9. Levée administrative de la quarantaine
    ueba.release_quarantine("malicious_agent")
        .expect("Levée de quarantaine");
    assert!(!ueba.is_quarantined("malicious_agent"));

    // 10. Vérification de l'intégrité du registre d'audit cryptographique SHA-256
    assert!(
        ueba.verify_audit_integrity(),
        "Le registre d'audit cryptographique UEBA doit être scellé et intègre"
    );
    assert!(ueba.audit_count >= 6);

    // 11. Synthèse globale
    let final_summary = ueba.get_summary();
    assert_eq!(final_summary.events_processed, 6);
    assert!(final_summary.anomalies_detected >= 4);
    assert!(final_summary.ledger_valid);

    kprintln!(
        "[UEBA/TEST] \x1b[1;32m[PASS]\x1b[0m Analyse Comportementale Souveraine UEBA (Profilage, Détection Multidimensionnelle, Scoring Adaptatif, Quarantaine O(1), Registre SHA-256) validée avec succès!"
    );

    true
}

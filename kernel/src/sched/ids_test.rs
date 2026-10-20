//! Module de validation de la Prévention et Corrélation d'Intrusions Multi-Points & Révocation de Capacités (`jambo-ids`)
//! Phase 112 — Jalon v0.2.110
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_ids::{
    ids_rights, BehavioralBaseline, CorrelatedIncident, IdsCap, IdsError,
    JamboIdsDaemon, MitigationAction, ProbeCategory, SensorProbe, Sha256,
    TelemetryEvent, ThreatIndicator, ThreatLevel, CRITICAL_THREAT_THRESHOLD,
    HIGH_THREAT_THRESHOLD, MAX_BASELINES, MAX_CORRELATIONS, MAX_EVENTS,
    MAX_PROBES, MAX_QUARANTINE_RECORDS, SUSPICIOUS_THREAT_THRESHOLD,
};

/// Exécute la suite complète de validation formelle de la détection et corrélation d'intrusions multi-points (Phase 112)
pub fn execute_ids_daemon_test() -> bool {
    kprintln!(
        "[IDS/TEST] Démarrage du test de validation de la corrélation d'intrusions multi-points et révocation automatisée (Phase 112)..."
    );

    // 1. Contrôle d'accès capabilaire (IdsCap) et atténuation monotone
    let admin_cap = IdsCap::new(Handle::new(11201, 1), ids_rights::ALL, 64, 1);
    assert!(admin_cap.has_right(ids_rights::INSPECT));
    assert!(admin_cap.has_right(ids_rights::REPORT_EVENT));
    assert!(admin_cap.has_right(ids_rights::REGISTER_PROBE));
    assert!(admin_cap.has_right(ids_rights::UPDATE_BASELINE));
    assert!(admin_cap.has_right(ids_rights::CORRELATE));
    assert!(admin_cap.has_right(ids_rights::TRIGGER_MITIGATION));
    assert!(admin_cap.has_right(ids_rights::RESET_ALERT));
    assert!(admin_cap.has_right(ids_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(ids_rights::INSPECT | ids_rights::REPORT_EVENT | ids_rights::CORRELATE, 32)
        .expect("Atténuation monotone IdsCap");
    assert!(attenuated_cap.has_right(ids_rights::INSPECT));
    assert!(attenuated_cap.has_right(ids_rights::REPORT_EVENT));
    assert!(attenuated_cap.has_right(ids_rights::CORRELATE));
    assert!(!attenuated_cap.has_right(ids_rights::TRIGGER_MITIGATION));
    assert!(!attenuated_cap.has_right(ids_rights::REGISTER_PROBE));
    assert_eq!(attenuated_cap.max_events_per_window, 32);

    // Rejet formel de toute amplification de droits
    assert_eq!(
        attenuated_cap.attenuate(ids_rights::ALL, 32),
        Err(IdsError::PermissionDenied),
        "Amplification de droits IdsCap formellement rejetée"
    );
    assert_eq!(
        attenuated_cap.attenuate(ids_rights::INSPECT, 64),
        Err(IdsError::PermissionDenied),
        "Augmentation de quota IdsCap formellement rejetée"
    );
    kprintln!("  [1/7] Contrôle d'accès capabilaire et atténuation monotone validés.");

    // 2. Initialisation du démon IDS et enregistrement des sondes hétérogènes
    let mut daemon = JamboIdsDaemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.probe_count, 6);
    assert_eq!(daemon.baseline_count, 2);

    // Enregistrement dynamique d'une nouvelle sonde de composant matériel
    let p_id = daemon
        .register_probe(&admin_cap, ProbeCategory::CryptoHardware, "tpm_nitro_probe", 9)
        .expect("Enregistrement sonde dynamique");
    assert_eq!(p_id, 7);
    assert_eq!(daemon.probe_count, 7);
    kprintln!("  [2/7] Initialisation du démon et sondes distribuées validées.");

    // 3. Moteur d'analyse comportementale et détection d'anomalies
    // Acteur 42 avec profil de base : 100Hz max, 256B max, allowed_channels 0x00FF, tolérance 50%
    let normal_flow = daemon.check_behavioral_anomaly(42, 95, 200, 1);
    assert!(normal_flow.is_none(), "Flux normal non signalé");

    // Dépassement de canal (accès canal privilégié non autorisé)
    let violation_canal = daemon.check_behavioral_anomaly(42, 100, 200, 16);
    assert!(violation_canal.is_some(), "Accès canal non autorisé détecté");
    let (ind, _) = violation_canal.unwrap();
    assert_eq!(ind, ThreatIndicator::CrossZoneBoundaryViolation);

    // Rafale de déni de service (Flood / Burst)
    let flood_anomaly = daemon.check_behavioral_anomaly(42, 350, 200, 1);
    assert!(flood_anomaly.is_some(), "Rafale anormale de messages détectée");
    let (ind2, score2) = flood_anomaly.unwrap();
    assert_eq!(ind2, ThreatIndicator::IpcFloodBurst);
    assert!(score2 >= 80);
    kprintln!("  [3/7] Analyse comportementale et détection d'anomalies de flux validées.");

    // 4. Ingestion d'événements de télémétrie multi-sources
    let test_actor = 77;
    let t0 = 10_000u64;

    // Événement sonde 1 (Kernel Syscall)
    let ev1 = daemon.ingest_event(
        &admin_cap,
        1,
        test_actor,
        ThreatIndicator::AbnormalSyscallSequence,
        75,
        0,
        t0,
    ).expect("Ingestion événement sonde 1");
    assert!(ev1 > 0);

    // Événement sonde 2 (IPC Router)
    let ev2 = daemon.ingest_event(
        &admin_cap,
        2,
        test_actor,
        ThreatIndicator::IpcFloodBurst,
        80,
        1,
        t0 + 20,
    ).expect("Ingestion événement sonde 2");
    assert!(ev2 > ev1);

    // Événement sonde 4 (SecRoute Network)
    let ev3 = daemon.ingest_event(
        &admin_cap,
        4,
        test_actor,
        ThreatIndicator::CrossZoneBoundaryViolation,
        85,
        2,
        t0 + 40,
    ).expect("Ingestion événement sonde 4");
    assert!(ev3 > ev2);
    kprintln!("  [4/7] Ingestion d'événements de télémétrie multi-sources validée.");

    // 5. Moteur de corrélation spatio-temporelle d'intrusions multi-points
    let correlated = daemon
        .correlate_events(&admin_cap, test_actor, t0 + 100)
        .expect("Corrélation d'événements")
        .expect("Incident corrélé existant");

    assert_eq!(correlated.actor_id, test_actor);
    assert_eq!(correlated.distinct_probes_count, 3);
    assert_eq!(correlated.event_count, 3);
    assert_eq!(correlated.threat_level, ThreatLevel::Critical);
    assert!(correlated.aggregated_score >= CRITICAL_THREAT_THRESHOLD);
    assert_eq!(correlated.automated_mitigation, MitigationAction::QuarantineProcess);
    kprintln!("  [5/7] Corrélation spatio-temporelle multi-points et score d'attaque coordonnée validés.");

    // 6. Révocation automatisée de capacités et quarantaine immédiate O(1)
    let mitigation = daemon
        .execute_automated_mitigation(
            &admin_cap,
            test_actor,
            correlated.aggregated_score,
            correlated.primary_indicator,
            t0 + 150,
        )
        .expect("Exécution mitigation autonome");

    assert_eq!(mitigation, MitigationAction::QuarantineProcess);
    assert!(daemon.is_quarantined(test_actor), "Acteur placé sous quarantaine O(1)");

    // Test de levée de quarantaine
    daemon.lift_quarantine(&admin_cap, test_actor).expect("Levée de quarantaine");
    assert!(!daemon.is_quarantined(test_actor), "Quarantaine levée");

    // Remise en quarantaine pour validation
    daemon
        .quarantine_actor(
            &admin_cap,
            test_actor,
            ThreatIndicator::PrivilegeEscalationAttempt,
            t0 + 200,
        )
        .expect("Remise en quarantaine");
    assert!(daemon.is_quarantined(test_actor));
    kprintln!("  [6/7] Révocation automatisée et quarantaine O(1) validées.");

    // 7. Intégration Shell interactif jsh et chaîne d'audit SHA-256
    let mut shell = JamboShell::new();

    let st_status = shell.execute("ids status");
    assert_eq!(st_status, ShellStatus::Success);

    let st_probes = shell.execute("ids probes");
    assert_eq!(st_probes, ShellStatus::Success);

    let st_baselines = shell.execute("ids baselines");
    assert_eq!(st_baselines, ShellStatus::Success);

    let st_correlate = shell.execute("ids correlate 42");
    assert_eq!(st_correlate, ShellStatus::Success);

    let st_alerts = shell.execute("ids alerts");
    assert_eq!(st_alerts, ShellStatus::Success);

    let st_bench = shell.execute("ids benchmark");
    assert_eq!(st_bench, ShellStatus::Success);

    let st_quarantine = shell.execute("ids quarantine 88");
    assert_eq!(st_quarantine, ShellStatus::Success);

    let st_lift = shell.execute("ids lift 88");
    assert_eq!(st_lift, ShellStatus::Success);

    let st_audit = shell.execute("ids audit");
    assert_eq!(st_audit, ShellStatus::Success);

    assert!(daemon.verify_audit_chain(), "Vérification cryptographique de la chaîne d'audit");
    kprintln!("  [7/7] Commandes CLI jsh et chaîne d'audit SHA-256 scellée validées.");

    kprintln!(
        "[IDS/TEST] \x1b[1;32mSUCCÈS : Tous les tests de prévention, corrélation d'intrusions et révocation (Phase 112) ont réussi avec succès !\x1b[0m"
    );
    true
}

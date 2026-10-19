//! Module de validation des Métriques Chronologiques & Télémétrie de Grappe (Phase 67 - v0.2.65)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_metricsd::{
    metrics_rights, AlertCondition, JamboMetricsDaemon, MetricsCap, MetricsCollector, RING_CAPACITY,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests des métriques chronologiques et télémétrie (Phase 67)
pub fn execute_metrics_telemetry_test() -> bool {
    kprintln!(
        "[METRICS/TEST] Démarrage du test des métriques chronologiques et télémétrie (Phase 67)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (MetricsCap)
    let admin_cap = MetricsCap::new(Handle::new(67, 1), metrics_rights::ALL);
    assert!(admin_cap.has_right(metrics_rights::METRICS_INGEST));
    assert!(admin_cap.has_right(metrics_rights::METRICS_QUERY));
    assert!(admin_cap.has_right(metrics_rights::METRICS_ALERT));
    assert!(admin_cap.has_right(metrics_rights::METRICS_ADMIN));

    let query_only_cap = admin_cap
        .attenuate(metrics_rights::METRICS_QUERY)
        .expect("attenuate MetricsCap to query-only");
    let mut raw_collector = MetricsCollector::new();
    assert_eq!(
        raw_collector.ingest(&query_only_cap, b"cpu", 1, 100, 50),
        Err(SysError::PermissionDenied),
        "Ingestion sans droit METRICS_INGEST doit être rejetée"
    );
    kprintln!("[METRICS/CAP] Confinement capabilaire MetricsCap et autorité ambiante zéro validés");

    // 2. Enregistrement de séries temporelles et calculs statistiques agrégés
    let mut collector = MetricsCollector::new();
    collector
        .register_series(&admin_cap, b"cluster_load", 1)
        .expect("register series");
    collector
        .ingest(&admin_cap, b"cluster_load", 1, 1000, 10)
        .expect("ingest 1");
    collector
        .ingest(&admin_cap, b"cluster_load", 1, 1001, 30)
        .expect("ingest 2");
    collector
        .ingest(&admin_cap, b"cluster_load", 1, 1002, 50)
        .expect("ingest 3");

    let (min, max, avg, last, count) = collector
        .query_stats(&admin_cap, b"cluster_load", 1)
        .expect("query stats");
    assert_eq!(min, 10);
    assert_eq!(max, 50);
    assert_eq!(avg, 30); // (10 + 30 + 50) / 3 = 30
    assert_eq!(last, 50);
    assert_eq!(count, 3);
    kprintln!(
        "[METRICS/SERIES] Enregistrement de séries temporelles et calculs statistiques validés"
    );

    // 3. Tampon annulaire circulaire borné et politique drop-oldest
    collector
        .register_series(&admin_cap, b"network_bps", 1)
        .expect("register series net");
    for i in 0..40 {
        collector
            .ingest(
                &admin_cap,
                b"network_bps",
                1,
                2000 + i as u64,
                (i * 10) as u64,
            )
            .expect("ring ingest");
    }
    let (_, _, _, ring_last, ring_count) = collector
        .query_stats(&admin_cap, b"network_bps", 1)
        .expect("ring stats");
    assert_eq!(ring_count, RING_CAPACITY); // Plafonné à 32
    assert_eq!(ring_last, 390); // 39 * 10
    kprintln!("[METRICS/RING] Tampon annulaire circulaire borné et politique drop-oldest validés");

    // 4. Règles d'alerte à seuil et détection de violation
    collector
        .register_alert(&admin_cap, b"cluster_load", AlertCondition::GreaterThan, 80)
        .expect("register alert");
    assert!(!collector
        .is_alert_triggered(&admin_cap, b"cluster_load")
        .expect("alert check 1"));

    let alert_hit = collector
        .ingest(&admin_cap, b"cluster_load", 1, 1003, 95)
        .expect("ingest trigger alert");
    assert!(alert_hit);
    assert!(collector
        .is_alert_triggered(&admin_cap, b"cluster_load")
        .expect("alert check 2"));
    kprintln!("[METRICS/ALERT] Règles d'alerte à seuil et détection de dépassement validées");

    // 5. Démon orchestrateur JamboMetricsDaemon
    let daemon = JamboMetricsDaemon::new();
    assert_eq!(daemon.series_count(), 2);
    assert_eq!(daemon.samples_ingested, 2);
    let (d_min, d_max, d_avg, d_last, d_cnt) =
        daemon.query_stats(b"node_cpu", 1).expect("daemon query");
    assert_eq!(d_min, 25);
    assert_eq!(d_max, 25);
    assert_eq!(d_avg, 25);
    assert_eq!(d_last, 25);
    assert_eq!(d_cnt, 1);
    kprintln!("[METRICS/DAEMON] Démon JamboMetricsDaemon opérationnel");

    // 6. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'metrics status'
    let (st_stat, len_stat) = shell.execute_line("metrics status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("MÉTRIQUES DISTRIBUÉES"));
    assert!(str_stat.contains("Séries enregistrées"));
    assert!(str_stat.contains("MetricsCap"));
    kprintln!("[METRICS/SHELL] Commande 'metrics status' validée");

    // Commande 'metrics query'
    let (st_query, len_query) = shell.execute_line("metrics query node_cpu", &mut out_buf);
    assert_eq!(st_query, ShellStatus::Success);
    let str_query = core::str::from_utf8(&out_buf[..len_query]).unwrap_or("");
    assert!(str_query.contains("[METRICS/QUERY]"));
    assert!(str_query.contains("Moyenne: 25"));
    kprintln!("[METRICS/SHELL] Commande 'metrics query' validée");

    // Commande 'metrics ingest'
    let (st_ingest, len_ingest) = shell.execute_line("metrics ingest node_cpu 95", &mut out_buf);
    assert_eq!(st_ingest, ShellStatus::Success);
    let str_ingest = core::str::from_utf8(&out_buf[..len_ingest]).unwrap_or("");
    assert!(str_ingest.contains("[ALERTE SEUIL DÉCLENCHÉE !]"));
    kprintln!("[METRICS/SHELL] Commande 'metrics ingest' validée");

    kprintln!(
        "[METRICS/PASS] Métriques chronologiques et télémétrie de grappe validées avec succès."
    );
    true
}

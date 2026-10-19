//! Module de validation de la Journalisation Structurée & Agrégation Distribuée (Phase 75 - v0.2.73)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_dfsd::{dfs_rights, DfsBlockStore, DfsCap, BLOCK_SIZE};
use jambo_logd::{
    encrypt_archive_payload, log_rights, JamboLogDaemon, LogCap, LogField, LogLevel, LogQueryFilter,
    LogRecord, RING_BUFFER_CAPACITY,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du démon de journalisation structurée et agrégation distribuée (Phase 75)
pub fn execute_log_daemon_test() -> bool {
    kprintln!(
        "[LOG/TEST] Démarrage du test de la journalisation structurée et agrégation distribuée (Phase 75)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (LogCap) et atténuation stricte
    let admin_cap = LogCap::new(Handle::new(75, 1), log_rights::ALL);
    assert!(admin_cap.has_right(log_rights::LOG_READ));
    assert!(admin_cap.has_right(log_rights::LOG_WRITE));
    assert!(admin_cap.has_right(log_rights::LOG_QUERY));
    assert!(admin_cap.has_right(log_rights::LOG_ARCHIVE));
    assert!(admin_cap.has_right(log_rights::LOG_ADMIN));

    let ro_cap = admin_cap
        .attenuate(log_rights::LOG_READ | log_rights::LOG_QUERY)
        .expect("attenuate LogCap to read-only");
    assert!(ro_cap.has_right(log_rights::LOG_READ));
    assert!(ro_cap.has_right(log_rights::LOG_QUERY));
    assert!(!ro_cap.has_right(log_rights::LOG_WRITE));
    assert!(!ro_cap.has_right(log_rights::LOG_ARCHIVE));

    // Interdiction formelle d'escalade de privilèges
    assert_eq!(
        ro_cap.attenuate(log_rights::LOG_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification de privilège capabilaire formellement interdite"
    );

    let mut daemon = JamboLogDaemon::new(admin_cap, 1);

    // Tentative d'écriture sans droit LOG_WRITE
    assert_eq!(
        daemon.log(
            &ro_cap,
            LogLevel::Info,
            "UNAUTH",
            "Tentative d'écriture sans droit",
            None,
            None,
            &[],
            100
        ),
        Err(SysError::PermissionDenied),
        "Écriture sans capacité adéquate doit être rejetée"
    );
    kprintln!("[LOG/CAP] Confinement capabilaire LogCap et autorité ambiante zéro validés");

    // 2. Journalisation structurée multi-niveaux et attributs contextuels
    let trace_id = [0x12u8; 16];
    let span_id = [0x34u8; 8];
    let fields = [
        LogField::new("module", "scheduler"),
        LogField::new("cpu_core", "3"),
    ];

    let id1 = daemon
        .log(
            &admin_cap,
            LogLevel::Debug,
            "SCHED",
            "Ordonnanceur EEVDF synchronisé",
            None,
            None,
            &[],
            1000,
        )
        .expect("log debug");
    assert_eq!(id1, 1);

    let id2 = daemon
        .log(
            &admin_cap,
            LogLevel::Info,
            "NET",
            "VirtIO-Net paquet routé vers interface jambo0",
            Some(trace_id),
            Some(span_id),
            &fields,
            1200,
        )
        .expect("log info with trace");
    assert_eq!(id2, 2);

    let id3 = daemon
        .log(
            &admin_cap,
            LogLevel::Warn,
            "STORAGE",
            "Latence I/O anormalement élevée sur NVMe #1",
            None,
            None,
            &[],
            1500,
        )
        .expect("log warn");
    assert_eq!(id3, 3);

    let id4 = daemon
        .log(
            &admin_cap,
            LogLevel::Error,
            "AUTH",
            "Échec d'authentification par clé Ed25519 corrompue",
            None,
            None,
            &[],
            1800,
        )
        .expect("log error");
    assert_eq!(id4, 4);

    kprintln!("[LOG/STRUCT] Ingestion de logs structurés, niveaux de sévérité et W3C TraceContext validés");

    // 3. Moteur de recherche et filtrage multi-critères
    let mut query_results = [LogRecord::empty(); 8];

    // Recherche par niveau minimal Warn
    let mut warn_filter = LogQueryFilter::empty();
    warn_filter.min_level = Some(LogLevel::Warn);
    let matched_warn = daemon
        .query(&admin_cap, &warn_filter, &mut query_results)
        .expect("query warn filter");
    assert_eq!(matched_warn, 2);
    assert_eq!(query_results[0].level, LogLevel::Warn);
    assert_eq!(query_results[1].level, LogLevel::Error);

    // Recherche par sous-système "NET"
    let mut net_filter = LogQueryFilter::empty();
    net_filter.subsystem = Some("NET");
    let matched_net = daemon
        .query(&admin_cap, &net_filter, &mut query_results)
        .expect("query net filter");
    assert_eq!(matched_net, 1);
    assert_eq!(query_results[0].subsystem_str(), "NET");
    assert!(query_results[0].has_trace);
    assert_eq!(query_results[0].trace_id, trace_id);

    // Recherche par mot-clé dans le message
    let mut kw_filter = LogQueryFilter::empty();
    kw_filter.keyword = Some("authentification");
    let matched_kw = daemon
        .query(&admin_cap, &kw_filter, &mut query_results)
        .expect("query keyword");
    assert_eq!(matched_kw, 1);
    assert_eq!(query_results[0].id, 4);

    kprintln!("[LOG/QUERY] Moteur de requêtes multi-critères (sévérité, sous-système, mot-clé, trace) validé");

    // 4. Chaînage cryptographique inviolable (tamper-evident Merkle hash chain)
    let is_valid = daemon
        .verify_integrity(&admin_cap)
        .expect("verify integrity");
    assert!(is_valid, "La chaîne cryptographique doit être 100% intègre");

    // Test de falsification malveillante détectée immédiatement
    daemon.ring_buffer.entries[0].message[0] ^= 0xFF;
    let corrupted_check = daemon
        .verify_integrity(&admin_cap)
        .expect("verify integrity corrupted");
    assert!(
        !corrupted_check,
        "Toute altération malveillante d'un enregistrement doit être rejetée"
    );

    // Rétablissement de l'intégrité
    daemon.ring_buffer.entries[0].message[0] ^= 0xFF;
    assert!(
        daemon.verify_integrity(&admin_cap).unwrap(),
        "Rétablissement de la chaîne d'intégrité"
    );
    kprintln!("[LOG/CRYPTO] Chaîne de scellement cryptographique et détection d'altération validées");

    // 5. Archivage chiffré dédupliqué vers jambo-dfsd
    let mut dfs_store = DfsBlockStore::new(1);
    let dfs_cap = DfsCap::new(Handle::new(64, 1), dfs_rights::ALL);
    let enc_key = [0x7au8; 32];

    let desc = daemon
        .archive_to_dfs(&admin_cap, &mut dfs_store, &dfs_cap, &enc_key, 2500)
        .expect("archive to dfs");

    assert_eq!(desc.archive_id, 1);
    assert_eq!(desc.count, 4);
    assert_eq!(daemon.archives_count, 1);
    assert_eq!(dfs_store.blocks[0].allocated, true);

    // Restauration et déchiffrement depuis dfs
    let mut decrypted = [0u8; BLOCK_SIZE];
    let restored = daemon
        .restore_archive(&admin_cap, &dfs_store, &dfs_cap, 1, &enc_key, &mut decrypted)
        .expect("restore archive");
    assert_eq!(restored.archive_id, 1);
    assert_eq!(&decrypted[0..4], b"JLOG");
    kprintln!("[LOG/DFS] Archivage chiffré dédupliqué vers jambo-dfsd et restauration validés");

    // 6. Intégration interactive du shell jsh (log status, log write, log tail, log query, log verify, log archive)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 4096];

    // log status
    let (st, len) = shell.execute_line("log status", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("JOURNALISATION STRUCTURÉE ET AGRÉGATION"));
    assert!(s.contains("Entrées enregistrées"));
    assert!(s.contains("CONFORME"));
    kprintln!("[LOG/SHELL] Commande 'log status' validée");

    // log write
    let (st, len) = shell.execute_line("log write WARN SECURITY Intrusion_tentative", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[LOG]"));
    assert!(s.contains("consignée et scellée"));
    kprintln!("[LOG/SHELL] Commande 'log write' validée");

    // log tail
    let (st, len) = shell.execute_line("log tail 3", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("SECURITY: Intrusion_tentative"));
    kprintln!("[LOG/SHELL] Commande 'log tail' validée");

    // log query
    let (st, len) = shell.execute_line("log query SECURITY", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("SECURITY"));
    kprintln!("[LOG/SHELL] Commande 'log query' validée");

    // log verify
    let (st, len) = shell.execute_line("log verify", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("100% Intègre et Inviolable"));
    kprintln!("[LOG/SHELL] Commande 'log verify' validée");

    // log archive
    let (st, len) = shell.execute_line("log archive", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[LOG] Archive"));
    assert!(s.contains("jambo-dfsd"));
    kprintln!("[LOG/SHELL] Commande 'log archive' validée");

    kprintln!("[LOG/PASS] Suite de tests Journalisation Structurée & Agrégation Distribuée complétée avec succès !");
    true
}

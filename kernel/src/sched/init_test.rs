//! Module de validation du Superviseur Système PID 1 & DAG de Dépendances (Phase 72 - v0.2.70)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_init::{
    init_rights, DaemonState, InitCap, JamboInitDaemon, SupervisedService, SystemSupervisor,
    DEFAULT_MAX_RESTARTS,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du superviseur système PID 1 et gestionnaire de DAG (Phase 72)
pub fn execute_init_supervisor_test() -> bool {
    kprintln!(
        "[INIT/TEST] Démarrage du test du superviseur PID 1 et gestionnaire de DAG (Phase 72)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (InitCap)
    let admin_cap = InitCap::new(Handle::new(72, 1), init_rights::ALL);
    assert!(admin_cap.has_right(init_rights::INIT_START));
    assert!(admin_cap.has_right(init_rights::INIT_STOP));
    assert!(admin_cap.has_right(init_rights::INIT_RESTART));
    assert!(admin_cap.has_right(init_rights::INIT_STATUS));
    assert!(admin_cap.has_right(init_rights::INIT_SHUTDOWN));
    assert!(admin_cap.has_right(init_rights::INIT_ADMIN));

    let status_only_cap = admin_cap
        .attenuate(init_rights::INIT_STATUS)
        .expect("attenuate InitCap to status-only");
    let mut raw_supervisor = SystemSupervisor::new();
    let dummy_service = SupervisedService::new(1, b"test-svc", &[], DEFAULT_MAX_RESTARTS, 501)
        .expect("create test service");
    assert_eq!(
        raw_supervisor.register_service(&status_only_cap, dummy_service),
        Err(SysError::PermissionDenied),
        "Enregistrement de service sans droit INIT_ADMIN doit être rejeté"
    );
    kprintln!("[INIT/CAP] Confinement capabilaire InitCap et autorité ambiante zéro validés");

    // 2. Gestion des dépendances de démarrage et détection de cycle (DAG)
    let s1 = SupervisedService::new(1, b"storage", &[], DEFAULT_MAX_RESTARTS, 100).unwrap();
    let s2 = SupervisedService::new(2, b"database", &[1], DEFAULT_MAX_RESTARTS, 101).unwrap();
    let s3 = SupervisedService::new(3, b"web-api", &[2], DEFAULT_MAX_RESTARTS, 102).unwrap();

    raw_supervisor
        .register_service(&admin_cap, s1)
        .expect("reg s1");
    raw_supervisor
        .register_service(&admin_cap, s2)
        .expect("reg s2");
    raw_supervisor
        .register_service(&admin_cap, s3)
        .expect("reg s3");
    assert_eq!(raw_supervisor.service_count, 3);
    assert!(!raw_supervisor.has_cycle());

    // Vérification de dépendance non satisfaite : s2 ne peut pas démarrer avant s1
    assert_eq!(
        raw_supervisor.start_service(&admin_cap, 2, 100),
        Err(SysError::ResourceBusy),
        "Démarrage prématuré d'un service avec dépendance inactive doit échouer"
    );

    // Démarrage ordonné complet selon le DAG (start_all)
    let started = raw_supervisor
        .start_all(&admin_cap, 150)
        .expect("start_all services");
    assert_eq!(started, 3);
    assert_eq!(raw_supervisor.active_count(), 3);
    kprintln!("[INIT/DAG] Résolution d'ordre topologique du DAG et blocage prématuré validés");

    // 3. Supervision des pannes et auto-guérison (Self-Healing)
    let state_heal1 = raw_supervisor
        .report_crash(&admin_cap, 2, 200)
        .expect("report crash 1");
    assert_eq!(state_heal1, DaemonState::Running);
    let s2_info = raw_supervisor.get_service(&admin_cap, 2).expect("get s2");
    assert_eq!(s2_info.restart_count, 1);

    // Crashes successifs jusqu'à dépassement du quota de tolérance (DEFAULT_MAX_RESTARTS = 3)
    raw_supervisor.report_crash(&admin_cap, 2, 210).unwrap();
    raw_supervisor.report_crash(&admin_cap, 2, 220).unwrap();
    let state_failed = raw_supervisor
        .report_crash(&admin_cap, 2, 230)
        .expect("report crash 4 (exceeded)");
    assert_eq!(state_failed, DaemonState::Failed);
    assert_eq!(raw_supervisor.failed_count(), 1);
    kprintln!("[INIT/HEALING] Auto-guérison et seuil maximal de tolérance aux pannes validés");

    // 4. Extinction ordonnée (Shutdown en ordre inverse du DAG)
    let stopped_count = raw_supervisor
        .shutdown(&admin_cap)
        .expect("ordered shutdown");
    assert_eq!(stopped_count, 2); // s1 et s3 étaient encore Running (s2 était Failed)
    assert!(raw_supervisor.is_shutdown);
    kprintln!("[INIT/SHUTDOWN] Extinction ordonnée en ordre inverse du DAG validée");

    // 5. Démon complet PID 1 JamboInitDaemon
    let mut init_daemon = JamboInitDaemon::new();
    assert_eq!(init_daemon.total_services(), 10);
    assert_eq!(init_daemon.active_count(), 10);
    assert_eq!(init_daemon.failed_count(), 0);

    // Crash et relance d'un service dans le démon
    let st = init_daemon
        .report_crash_by_name(b"jambo-netd")
        .expect("daemon crash report");
    assert_eq!(st, DaemonState::Running);
    assert_eq!(init_daemon.get_service_restarts(b"jambo-netd"), Some(1));
    kprintln!("[INIT/DAEMON] Démon d'initialisation PID 1 opérationnel avec 10 services DAG");

    // 6. Intégration shell interactive (init status, init restart, init shutdown)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // init status
    let (st, len) = shell.execute_line("init status", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("SUPERVISEUR SYSTÈME PID 1"));
    assert!(s.contains("Services Actifs"));
    assert!(s.contains("DAG Topologique"));
    kprintln!("[INIT/SHELL] Commande 'init status' validée");

    // init restart
    let (st, len) = shell.execute_line("init restart jambo-serviced", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[INIT/RESTART]"));
    assert!(s.contains("jambo-serviced"));
    kprintln!("[INIT/SHELL] Commande 'init restart' validée");

    // init shutdown
    let (st, len) = shell.execute_line("init shutdown", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[INIT/SHUTDOWN]"));
    assert!(s.contains("services arrêtés"));
    kprintln!("[INIT/SHELL] Commande 'init shutdown' validée");

    kprintln!("[INIT/PASS] Suite de tests Superviseur PID 1 et DAG complétée avec succès !");
    true
}

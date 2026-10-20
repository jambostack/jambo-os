//! Module de validation formelle de la Protection des Charges de Travail Cloud/Grappe (CWPP) (`jambo-cwpp`)
//! Phase 126 — Jalon v0.2.124
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_cwpp::{
    cwpp_rights, AnomalyType, ContainmentAction, CwppCap, CwppError, JamboCwppDaemon,
    Workload, WorkloadProfile, WorkloadState, WorkloadType,
};

/// Exécute la suite complète de validation formelle du démon CWPP (Phase 126)
pub fn execute_cwpp_daemon_test() -> bool {
    kprintln!(
        "[CWPP/TEST] Démarrage de la validation formelle de la protection des charges de travail (Phase 126)..."
    );

    // 1. Contrôle d'accès capabilaire (CwppCap) et atténuation monotone
    let admin_cap = CwppCap::new(Handle::new(12601, 1), cwpp_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(cwpp_rights::REGISTER_WORKLOAD));
    assert!(admin_cap.has_right(cwpp_rights::INSPECT_WORKLOAD));
    assert!(admin_cap.has_right(cwpp_rights::DETECT_ANOMALY));
    assert!(admin_cap.has_right(cwpp_rights::CONTAIN_WORKLOAD));
    assert!(admin_cap.has_right(cwpp_rights::MANAGE_PROFILES));
    assert!(admin_cap.has_right(cwpp_rights::READ_METRICS));
    assert!(admin_cap.has_right(cwpp_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(cwpp_rights::ADMIN));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            cwpp_rights::INSPECT_WORKLOAD | cwpp_rights::READ_METRICS,
            5000,
            200,
        )
        .expect("Atténuation monotone CwppCap");
    assert!(monitor_cap.has_right(cwpp_rights::INSPECT_WORKLOAD));
    assert!(monitor_cap.has_right(cwpp_rights::READ_METRICS));
    assert!(!monitor_cap.has_right(cwpp_rights::CONTAIN_WORKLOAD));
    assert!(!monitor_cap.has_right(cwpp_rights::ADMIN));
    assert_eq!(monitor_cap.max_lifetime, 5000);
    assert_eq!(monitor_cap.invocations_left, 200);

    // Rejet d'escalade
    assert_eq!(
        monitor_cap.attenuate(cwpp_rights::ALL, 5000, 200),
        Err(CwppError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et charges de travail par défaut
    let mut cwpp = JamboCwppDaemon::new(admin_cap);
    cwpp.init_defaults();
    assert_eq!(cwpp.profile_count, 4);
    assert_eq!(cwpp.workload_count, 4);
    assert_eq!(cwpp.active_workloads, 4);
    assert_eq!(cwpp.total_anomalies_detected, 0);
    assert_eq!(cwpp.total_containments, 0);
    assert!(cwpp.verify_ledger_integrity());
    assert_ne!(cwpp.ledger_hash, JamboCwppDaemon::GENESIS_HASH);

    // 3. Détection d'anomalies en temps réel
    // Événement nominal sur ID 101 (jambo-ingress)
    let ev1 = cwpp
        .report_execution_event(
            &admin_cap,
            101,
            1,
            8 * 1024 * 1024,
            2,
            false,
            true,
            1000,
        )
        .expect("Événement nominal");
    assert_eq!(ev1, None);

    // Détection anomalie W+X (Injection de mémoire) sur ID 102 (jambo-kvd-db)
    let ev2 = cwpp
        .report_execution_event(
            &admin_cap,
            102,
            2,
            32 * 1024 * 1024,
            4,
            true, // Cartographie W+X interdite
            true,
            1100,
        )
        .expect("Événement anomalie W+X");
    assert_eq!(ev2, Some(AnomalyType::MemoryInjection));

    // Détection dérivation RIP (Divergence de flot d'exécution / ROP) sur ID 103 (jambo-ai-infer)
    let ev3 = cwpp
        .report_execution_event(
            &admin_cap,
            103,
            0,
            64 * 1024 * 1024,
            2,
            false,
            false, // RIP non canonique / altéré
            1200,
        )
        .expect("Événement divergence RIP");
    assert_eq!(ev3, Some(AnomalyType::RipDivergence));

    // Détection appel système interdit sur ID 104 (jambo-log-audit)
    // Profile 4 a mask 0x3FF (bits 0..9). Syscall 45 est interdit
    let ev4 = cwpp
        .report_execution_event(
            &admin_cap,
            104,
            45,
            16 * 1024 * 1024,
            2,
            false,
            true,
            1300,
        )
        .expect("Événement syscall interdit");
    assert_eq!(ev4, Some(AnomalyType::UnauthorizedSyscall));

    assert_eq!(cwpp.total_anomalies_detected, 3);
    assert!(cwpp.verify_ledger_integrity());

    // 4. Confinement instantané O(1)
    // Confinement ID 102 : Quarantaine
    let ok_quar = cwpp
        .contain_workload(&admin_cap, 102, ContainmentAction::Quarantine, 2000)
        .expect("Confinement en quarantaine");
    assert!(ok_quar);
    let wl102 = cwpp.inspect_workload(&admin_cap, 102).unwrap();
    assert_eq!(wl102.state, WorkloadState::Contained);
    assert_eq!(wl102.applied_containment, ContainmentAction::Quarantine);

    // Confinement ID 103 : Terminaison immédiate (SIGKILL)
    let ok_kill = cwpp
        .contain_workload(&admin_cap, 103, ContainmentAction::Terminate, 2100)
        .expect("Terminaison charge compromise");
    assert!(ok_kill);
    let wl103 = cwpp.inspect_workload(&admin_cap, 103).unwrap();
    assert_eq!(wl103.state, WorkloadState::Terminated);
    assert_eq!(wl103.applied_containment, ContainmentAction::Terminate);
    assert_eq!(cwpp.active_workloads, 3);

    // Vérification que les privilèges insuffisants sont rejetés pour le confinement
    assert_eq!(
        cwpp.contain_workload(&monitor_cap, 104, ContainmentAction::Freeze, 2200),
        Err(CwppError::PermissionDenied)
    );

    // Confinement ID 104 : Gel (SIGSTOP)
    let ok_freeze = cwpp
        .contain_workload(&admin_cap, 104, ContainmentAction::Freeze, 2300)
        .expect("Gel charge anormale");
    assert!(ok_freeze);
    let wl104 = cwpp.inspect_workload(&admin_cap, 104).unwrap();
    assert_eq!(wl104.state, WorkloadState::Contained);

    assert_eq!(cwpp.total_containments, 3);

    // 5. Scan global des charges de travail
    let (checked, anomalies) = cwpp
        .scan_all_workloads(&admin_cap, 3000)
        .expect("Scan global CWPP");
    assert_eq!(checked, 4);
    assert_eq!(anomalies, 3); // 102, 103, 104 ont eu des anomalies

    // 6. Vérification cryptographique du registre d'audit inaltérable SHA-256
    assert!(cwpp.verify_ledger_integrity());

    kprintln!(
        "[CWPP/TEST] \x1b[1;32mSuccès de la validation formelle CWPP : {} profils, {} charges ({} actives), {} anomalies, {} confinements scellés SHA-256\x1b[0m",
        cwpp.profile_count,
        cwpp.workload_count,
        cwpp.active_workloads,
        cwpp.total_anomalies_detected,
        cwpp.total_containments
    );

    true
}

//! Module de validation formelle de la Protection des Charges de Travail Cloud Souveraines CWPP (`jambo-cwpp`)
//! Phase 156 — Jalon v0.3.23
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_cwpp::{
    cwpp_rights, AnomalyType, ContainmentAction, CwppCap, CwppError, ExecutionIntegrity,
    JamboCwppDaemon, RuntimeIsolation, Workload, WorkloadProfile, WorkloadState, WorkloadType,
};

/// Exécute la suite complète de validation formelle du démon CWPP Souverain (Phase 156)
pub fn execute_cwpp_daemon_test() -> bool {
    kprintln!(
        "[CWPP/TEST] Démarrage de la validation formelle de la protection des charges de travail souveraines (Phase 156 - v0.3.23)..."
    );

    // 1. Contrôle d'accès capabilaire (CwppCap) et atténuation monotone
    let admin_cap = CwppCap::new(Handle::new(12601, 1), cwpp_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(cwpp_rights::REGISTER_WORKLOAD));
    assert!(admin_cap.has_right(cwpp_rights::INSPECT_WORKLOAD));
    assert!(admin_cap.has_right(cwpp_rights::DETECT_ANOMALY));
    assert!(admin_cap.has_right(cwpp_rights::CONTAIN_WORKLOAD));
    assert!(admin_cap.has_right(cwpp_rights::MANAGE_PROFILES));
    assert!(admin_cap.has_right(cwpp_rights::VERIFY_INTEGRITY));
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
    assert_eq!(cwpp.total_rollbacks, 0);
    assert!(cwpp.verify_ledger_integrity());
    assert_ne!(cwpp.ledger_hash, JamboCwppDaemon::GENESIS_HASH);

    let golden_gw = cwpp.profiles[0].unwrap().golden_hash;
    let golden_db = cwpp.profiles[1].unwrap().golden_hash;
    let golden_ai = cwpp.profiles[2].unwrap().golden_hash;
    let golden_audit = cwpp.profiles[3].unwrap().golden_hash;

    // 3. Détection d'anomalies en temps réel et télémétrie d'intégrité
    // Événement nominal sur ID 101 (jambo-ingress-gw)
    let ev1 = cwpp
        .report_execution_telemetry(
            &admin_cap,
            101,
            1,
            8 * 1024 * 1024,
            2,
            false,
            false,
            false,
            false,
            golden_gw,
            1000,
        )
        .expect("Événement nominal");
    assert_eq!(ev1, None);

    // Détection anomalie W+X (Injection de mémoire) sur ID 102 (jambo-kvd-db)
    let ev2 = cwpp
        .report_execution_telemetry(
            &admin_cap,
            102,
            2,
            32 * 1024 * 1024,
            4,
            true, // Violation W^X !
            false,
            false,
            false,
            golden_db,
            1100,
        )
        .expect("Événement anomalie W+X");
    assert_eq!(ev2, Some(AnomalyType::MemoryInjection));

    // Détection dérivation RIP (Divergence de flot d'exécution / CFI / ROP) sur ID 103 (jambo-ai-infer)
    let ev3 = cwpp
        .report_execution_telemetry(
            &admin_cap,
            103,
            0,
            64 * 1024 * 1024,
            2,
            false,
            true, // CFI / RIP non valide
            false,
            false,
            golden_ai,
            1200,
        )
        .expect("Événement divergence RIP");
    assert_eq!(ev3, Some(AnomalyType::RipDivergence));

    // Détection altération de canari de pile sur ID 101 (Buffer Overflow tenté)
    let ev_canary = cwpp
        .report_execution_telemetry(
            &admin_cap,
            101,
            1,
            12 * 1024 * 1024,
            2,
            false,
            false,
            true, // Stack canary détruit
            false,
            golden_gw,
            1250,
        )
        .expect("Événement canari écrasé");
    assert_eq!(ev_canary, Some(AnomalyType::StackCanaryCorruption));

    // Détection violation de frontière d'enclave TEE sur ID 103 (Micro-VM Enclave)
    let ev_tee = cwpp
        .report_execution_telemetry(
            &admin_cap,
            103,
            1,
            64 * 1024 * 1024,
            2,
            false,
            false,
            false,
            true, // Enclave Boundary Violation
            golden_ai,
            1280,
        )
        .expect("Événement violation frontière TEE");
    assert_eq!(ev_tee, Some(AnomalyType::EnclaveBoundaryViolation));

    // Détection appel système interdit sur ID 104 (jambo-log-audit)
    // Profile 4 a mask 0x3FF (bits 0..9). Syscall 45 est interdit
    let ev4 = cwpp
        .report_execution_telemetry(
            &admin_cap,
            104,
            45,
            16 * 1024 * 1024,
            2,
            false,
            false,
            false,
            false,
            golden_audit,
            1300,
        )
        .expect("Événement syscall interdit");
    assert_eq!(ev4, Some(AnomalyType::UnauthorizedSyscall));

    assert_eq!(cwpp.total_anomalies_detected, 5);
    assert!(cwpp.verify_ledger_integrity());

    // 4. Confinement chirurgical instantané O(1)
    // Confinement ID 102 : Quarantaine
    let ok_quar = cwpp
        .contain_workload(&admin_cap, 102, ContainmentAction::Quarantine, 2000)
        .expect("Confinement en quarantaine");
    assert!(ok_quar);
    let wl102 = cwpp.inspect_workload(&admin_cap, 102).unwrap();
    assert_eq!(wl102.state, WorkloadState::Contained);
    assert_eq!(wl102.applied_containment, ContainmentAction::Quarantine);

    // Confinement ID 101 : Isolation Réseau (IsolateNetwork)
    let ok_net = cwpp
        .contain_workload(&admin_cap, 101, ContainmentAction::IsolateNetwork, 2050)
        .expect("Isolation réseau");
    assert!(ok_net);
    let wl101 = cwpp.inspect_workload(&admin_cap, 101).unwrap();
    assert_eq!(wl101.applied_containment, ContainmentAction::IsolateNetwork);

    // Confinement ID 103 : Restauration autonome vers snapshot doré O(1) (Rollback)
    let ok_roll = cwpp
        .rollback_workload(&admin_cap, 103, 2100)
        .expect("Rollback snapshot doré");
    assert!(ok_roll);
    let wl103 = cwpp.inspect_workload(&admin_cap, 103).unwrap();
    assert_eq!(wl103.state, WorkloadState::Restored);
    assert_eq!(wl103.anomaly_count, 0);
    assert_eq!(wl103.last_anomaly, AnomalyType::None);
    assert_eq!(cwpp.total_rollbacks, 1);

    // Confinement ID 104 : Gel (SIGSTOP)
    let ok_freeze = cwpp
        .contain_workload(&admin_cap, 104, ContainmentAction::Freeze, 2200)
        .expect("Gel charge anormale");
    assert!(ok_freeze);
    let wl104 = cwpp.inspect_workload(&admin_cap, 104).unwrap();
    assert_eq!(wl104.state, WorkloadState::Contained);

    // Vérification que les privilèges insuffisants sont rejetés pour le confinement
    assert_eq!(
        cwpp.contain_workload(&monitor_cap, 104, ContainmentAction::Terminate, 2250),
        Err(CwppError::PermissionDenied)
    );

    // Terminaison forcée de la charge hostile ID 104 (SIGKILL)
    let ok_kill = cwpp
        .contain_workload(&admin_cap, 104, ContainmentAction::Terminate, 2300)
        .expect("Terminaison charge compromise");
    assert!(ok_kill);
    let wl104_post = cwpp.inspect_workload(&admin_cap, 104).unwrap();
    assert_eq!(wl104_post.state, WorkloadState::Terminated);
    assert_eq!(cwpp.active_workloads, 3);

    // 5. Scan global des charges de travail
    let (checked, anomalies) = cwpp
        .scan_all_workloads(&admin_cap, 3000)
        .expect("Scan global CWPP");
    assert_eq!(checked, 4);
    assert_eq!(anomalies, 3); // 101, 102 et 104 ont eu des anomalies enregistrées

    // 6. Vérification des rapports d'incidents scellés SHA-256
    assert!(cwpp.report_count >= 5);
    let latest_rep = cwpp.latest_report().expect("Dernier rapport présent");
    assert_eq!(latest_rep.workload_id, 104);
    assert_eq!(latest_rep.action, ContainmentAction::Terminate);
    assert_ne!(latest_rep.report_hash, [0u8; 32]);

    // 7. Vérification cryptographique du registre d'audit inaltérable SHA-256
    assert!(cwpp.verify_ledger_integrity());

    kprintln!(
        "[CWPP/TEST] \x1b[1;32mSuccès de la validation formelle CWPP : {} profils, {} charges ({} actives), {} anomalies, {} confinements (dont {} rollbacks) scellés SHA-256\x1b[0m",
        cwpp.profile_count,
        cwpp.workload_count,
        cwpp.active_workloads,
        cwpp.total_anomalies_detected,
        cwpp.total_containments,
        cwpp.total_rollbacks
    );

    true
}

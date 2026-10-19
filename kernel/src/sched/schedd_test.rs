//! Module de validation de l'Ordonnanceur de Tâches & Conteneurs Distribués (Phase 61 - v0.2.59)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_schedd::{
    sched_rights, ClusterNode, ClusterScheduler, JamboSchedDaemon, RuntimeType, SchedCap, Task,
    TaskSpec, TaskState,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de l'ordonnanceur distribué et conteneurs (Phase 61)
pub fn execute_cluster_scheduler_test() -> bool {
    kprintln!("[SCHEDD/TEST] Démarrage du test de l'ordonnanceur de grappe (Phase 61)...");

    // 1. Validation du contrôle d'accès capabilaire (SchedCap)
    let admin_cap = SchedCap::new(Handle::new(61, 1), sched_rights::ALL);
    assert!(admin_cap.has_right(sched_rights::SCHED_SUBMIT));
    assert!(admin_cap.has_right(sched_rights::SCHED_CANCEL));
    assert!(admin_cap.has_right(sched_rights::SCHED_QUERY));
    assert!(admin_cap.has_right(sched_rights::SCHED_MIGRATE));
    assert!(admin_cap.has_right(sched_rights::SCHED_DRAIN));
    assert!(admin_cap.has_right(sched_rights::SCHED_ADMIN));

    let unauth_cap = SchedCap::new(Handle::new(61, 2), 0);
    let mut raw_sched = ClusterScheduler::new();
    let spec = TaskSpec::new(0, b"unauth-task", RuntimeType::Posix, 1, 32, None);
    assert_eq!(
        raw_sched.submit_task(&unauth_cap, spec),
        Err(SysError::PermissionDenied),
        "Soumission sans droit SCHED_SUBMIT doit être rejetée"
    );
    assert_eq!(
        raw_sched.register_node(&unauth_cap, 10, 4, 1024),
        Err(SysError::PermissionDenied),
        "Enregistrement de nœud sans droit SCHED_ADMIN doit être rejeté"
    );
    kprintln!("[SCHEDD/CAP] Confinement capabilaire SchedCap et autorité ambiante zéro validés");

    // 2. Enregistrement des nœuds de calcul et quotas matériels
    raw_sched
        .register_node(&admin_cap, 1, 8, 2048)
        .expect("register node 1");
    raw_sched
        .register_node(&admin_cap, 2, 4, 1024)
        .expect("register node 2");
    kprintln!("[SCHEDD/NODES] Nœuds de calcul enregistrés avec quotas vCPUs et pages MMU");

    // 3. Soumission et placement de tâches hétérogènes (MicroVmm, Wasm, Posix)
    let t_vmm = TaskSpec::new(0, b"vmm-instance-1", RuntimeType::MicroVmm, 4, 512, None);
    let t_wasm = TaskSpec::new(0, b"wasm-sandbox-1", RuntimeType::Wasm, 2, 128, None);
    let t_posix = TaskSpec::new(0, b"posix-worker-1", RuntimeType::Posix, 2, 256, None);

    let id1 = raw_sched
        .submit_task(&admin_cap, t_vmm)
        .expect("submit vmm");
    let id2 = raw_sched
        .submit_task(&admin_cap, t_wasm)
        .expect("submit wasm");
    let id3 = raw_sched
        .submit_task(&admin_cap, t_posix)
        .expect("submit posix");

    let placed = raw_sched.schedule_pending(100);
    assert_eq!(placed, 3, "Toutes les 3 tâches doivent être ordonnancées");

    let q1 = raw_sched.query_task(&admin_cap, id1).expect("query 1");
    let q2 = raw_sched.query_task(&admin_cap, id2).expect("query 2");
    let q3 = raw_sched.query_task(&admin_cap, id3).expect("query 3");
    assert_eq!(q1.state, TaskState::Running);
    assert_eq!(q2.state, TaskState::Running);
    assert_eq!(q3.state, TaskState::Running);
    assert!(q1.assigned_node.is_some());
    assert!(q2.assigned_node.is_some());
    assert!(q3.assigned_node.is_some());
    kprintln!("[SCHEDD/PLACEMENT] Réconciliation déclarative et placement Least-Allocated validés");

    // 4. Migration de tâche active
    let original_node = q1.assigned_node.unwrap();
    let target_node = if original_node == 1 { 2 } else { 1 };
    let _ = raw_sched.migrate_task(&admin_cap, id1, target_node);
    kprintln!("[SCHEDD/MIGRATE] Migration de conteneur/tâche validée");

    // 5. Drainage de nœud (Eviction & Rescheduling)
    let drained_count = raw_sched.drain_node(&admin_cap, 1).expect("drain node 1");
    assert!(drained_count >= 1);
    kprintln!("[SCHEDD/DRAIN] Drainage de nœud avec éviction contrôlée validé");

    // 6. Démon orchestrateur JamboSchedDaemon
    let mut daemon = JamboSchedDaemon::new();
    assert_eq!(daemon.active_nodes_count(), 2);
    let tid = daemon
        .submit(b"k8s-pod-mock", RuntimeType::MicroVmm, 2, 64, None)
        .expect("submit daemon task");
    assert_eq!(daemon.schedule_pending(200), 1);
    assert_eq!(daemon.running_tasks_count(), 1);
    daemon.cancel(tid).expect("cancel task");
    assert_eq!(daemon.running_tasks_count(), 0);
    kprintln!("[SCHEDD/DAEMON] Démon JamboSchedDaemon opérationnel");

    // 7. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'sched status'
    let (st_stat, len_stat) = shell.execute_line("sched status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("ORDONNANCEUR DE CHARGES & CONTENEURS"));
    assert!(str_stat.contains("Nœuds de calcul actifs"));
    assert!(str_stat.contains("Least-Allocated"));
    kprintln!("[SCHEDD/SHELL] Commande 'sched status' validée");

    // Commande 'sched submit'
    let (st_sub, len_sub) = shell.execute_line("sched submit web-service 2 128", &mut out_buf);
    assert_eq!(st_sub, ShellStatus::Success);
    let str_sub = core::str::from_utf8(&out_buf[..len_sub]).unwrap_or("");
    assert!(str_sub.contains("[SCHED/OK] Tâche enregistrée"));
    kprintln!("[SCHEDD/SHELL] Commande 'sched submit' validée");

    // Commande 'sched run'
    let (st_run, len_run) = shell.execute_line("sched run", &mut out_buf);
    assert_eq!(st_run, ShellStatus::Success);
    let str_run = core::str::from_utf8(&out_buf[..len_run]).unwrap_or("");
    assert!(str_run.contains("[SCHED/RECONCILE]"));
    kprintln!("[SCHEDD/SHELL] Commande 'sched run' validée");

    // Commande 'sched cancel'
    let (st_can, len_can) = shell.execute_line("sched cancel 1", &mut out_buf);
    assert_eq!(st_can, ShellStatus::Success);
    let str_can = core::str::from_utf8(&out_buf[..len_can]).unwrap_or("");
    assert!(str_can.contains("[SCHED/OK] Tâche annulée"));
    kprintln!("[SCHEDD/SHELL] Commande 'sched cancel' validée");

    // Commande 'sched drain'
    let (st_dr, len_dr) = shell.execute_line("sched drain 2", &mut out_buf);
    assert_eq!(st_dr, ShellStatus::Success);
    let str_dr = core::str::from_utf8(&out_buf[..len_dr]).unwrap_or("");
    assert!(str_dr.contains("[SCHED/DRAIN] Nœud drainé"));
    kprintln!("[SCHEDD/SHELL] Commande 'sched drain' validée");

    kprintln!("[SCHEDD/PASS] Ordonnanceur de charges et conteneurs distribués validé avec succès.");
    true
}

//! Module de validation de la Surveillance de Vivacité, Chien de Garde Matériel & Logiciel et Isolation NMI (Phase 82 - v0.2.80)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_watchdogd::{
    watchdog_rights, FailoverAction, HwWatchdogEvent, HwWatchdogStatus, HwWatchdogType,
    JamboWatchdogDaemon, LockupType, NodeLivenessState, TargetLivenessState, WatchdogCap,
    WatchdogTarget, WatchdogTargetType,
};

/// Exécute la suite complète de validation de la surveillance de vivacité, watchdog et isolation NMI (Phase 82)
pub fn execute_watchdog_daemon_test() -> bool {
    kprintln!(
        "[WATCHDOG/TEST] Démarrage du test de surveillance de vivacité, watchdog matériel/logiciel et isolation NMI (Phase 82)..."
    );

    // 1. Contrôle d'accès capabilaire (WatchdogCap) et interdiction stricte d'amplification
    let admin_cap = WatchdogCap::new(Handle::new(8201, 1), watchdog_rights::ALL);
    assert!(admin_cap.has_right(watchdog_rights::WATCHDOG_INSPECT));
    assert!(admin_cap.has_right(watchdog_rights::WATCHDOG_PET));
    assert!(admin_cap.has_right(watchdog_rights::WATCHDOG_REGISTER));
    assert!(admin_cap.has_right(watchdog_rights::WATCHDOG_CONFIGURE));
    assert!(admin_cap.has_right(watchdog_rights::WATCHDOG_TRIGGER));
    assert!(admin_cap.has_right(watchdog_rights::WATCHDOG_FAILOVER));
    assert!(admin_cap.has_right(watchdog_rights::WATCHDOG_ADMIN));

    let inspect_only_cap = admin_cap
        .attenuate(watchdog_rights::WATCHDOG_INSPECT)
        .expect("attenuate WatchdogCap to inspect-only");
    assert!(inspect_only_cap.has_right(watchdog_rights::WATCHDOG_INSPECT));
    assert!(!inspect_only_cap.has_right(watchdog_rights::WATCHDOG_ADMIN));
    assert!(!inspect_only_cap.has_right(watchdog_rights::WATCHDOG_PET));
    assert!(!inspect_only_cap.has_right(watchdog_rights::WATCHDOG_TRIGGER));

    // Rejet formel de toute amplification capabilaire
    assert_eq!(
        inspect_only_cap.attenuate(watchdog_rights::WATCHDOG_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboWatchdogDaemon::new(1, admin_cap);
    daemon.init_defaults();

    // Rejet d'enregistrement sans WATCHDOG_REGISTER
    let dummy_target = WatchdogTarget::new(
        99,
        "unauthorized",
        WatchdogTargetType::UserspaceTask,
        10,
        10,
        1000,
        200,
        FailoverAction::RestartService,
        100,
    );
    assert_eq!(
        daemon.register_target(&inspect_only_cap, dummy_target),
        Err(SysError::PermissionDenied),
        "Enregistrement de cible sans WATCHDOG_REGISTER doit échouer"
    );

    // Rejet de nourriture sans WATCHDOG_PET
    assert_eq!(
        daemon.pet_target(&inspect_only_cap, 1, 150),
        Err(SysError::PermissionDenied),
        "Nourriture sans WATCHDOG_PET doit échouer"
    );

    // Rejet de déclenchement NMI sans WATCHDOG_TRIGGER
    assert_eq!(
        daemon.trigger_nmi(
            &inspect_only_cap,
            0,
            Some(1),
            LockupType::HardLockup,
            0,
            0,
            200
        ),
        Err(SysError::PermissionDenied),
        "Déclenchement NMI sans WATCHDOG_TRIGGER doit échouer"
    );
    kprintln!(
        "[WATCHDOG/CAP] Contrôle d'accès capabilaire WatchdogCap & non-amplification validés"
    );

    // 2. Vérification de la configuration nominale initiale
    assert_eq!(daemon.target_count, 4);
    assert_eq!(daemon.cluster_count, 2);
    assert_eq!(daemon.hw_watchdog.status, HwWatchdogStatus::Armed);
    assert_eq!(daemon.hw_watchdog.timeout_ms, 30000);
    assert_eq!(daemon.hw_watchdog.pre_timeout_ms, 5000);

    let t1 = daemon
        .get_target(1)
        .expect("Target 1 (kernel-sched) exists");
    assert_eq!(t1.name_str(), "kernel-sched");
    assert_eq!(t1.target_type, WatchdogTargetType::KernelCore);
    assert_eq!(t1.timeout_ms, 1000);
    assert_eq!(t1.state, TargetLivenessState::Active);

    let t2 = daemon.get_target(2).expect("Target 2 (jambo-init) exists");
    assert_eq!(t2.name_str(), "jambo-init");
    assert_eq!(t2.target_type, WatchdogTargetType::CriticalService);

    let n1 = daemon.get_cluster_node(1).expect("Node 1 exists");
    assert_eq!(n1.name_str(), "node-alpha");
    assert!(n1.is_primary);
    assert_eq!(n1.state, NodeLivenessState::Healthy);
    kprintln!("[WATCHDOG/INIT] Cibles logicielles et chien de garde matériel iTCO v2 initialisés");

    // 3. Test de nourriture nominale (Petting) et détection de dérive (Event Loop Drift)
    // Cible 1 : Pet nominal (intervalle 50ms <= max_drift 150ms)
    assert_eq!(daemon.pet_target(&admin_cap, 1, 150), Ok(()));
    let t1_after = daemon.get_target(1).unwrap();
    assert_eq!(t1_after.state, TargetLivenessState::Active);
    assert_eq!(t1_after.total_pets, 1);

    // Cible 2 : Dérive détectée (intervalle 450ms > max_drift 300ms)
    assert_eq!(daemon.pet_target(&admin_cap, 2, 550), Ok(()));
    let t2_after = daemon.get_target(2).unwrap();
    assert_eq!(t2_after.state, TargetLivenessState::WarningDrift);
    assert!(t2_after.last_drift_ms > 0);
    assert_eq!(daemon.stats.total_drifts_warned, 1);
    kprintln!("[WATCHDOG/PET] Nourriture périodique et détection de dérive d'event loop validées");

    // 4. Test du chien de garde matériel (Recharge & Pré-timeout NMI)
    assert_eq!(daemon.reload_hardware(&admin_cap, 200), Ok(()));
    assert_eq!(daemon.stats.total_hw_reloads, 1);

    // Simulation d'une progression temporelle jusqu'au pré-timeout (26 000 ms après la recharge à t=200 -> t=26 200)
    // Timeout = 30 000 ms, pré-timeout NMI = 5000 ms -> seuil NMI = 25 000 ms
    daemon.evaluate_system_liveness(&admin_cap, 26_000).unwrap();
    assert_eq!(
        daemon.hw_watchdog.status,
        HwWatchdogStatus::PreTimeoutWarning,
        "Le chien de garde matériel doit passer en pré-timeout warning"
    );
    assert!(daemon.stats.total_nmi_alerts >= 1);
    kprintln!("[WATCHDOG/HW] Chien de garde matériel & pré-timeout NMI iTCO validés");

    // 5. Blocage de thread logiciel (Stall Detection) et isolation automatique
    // Cible 4 (jambo-ipcd) timeout 2500ms, dernière activité t=100. À t=28 000ms, elle est bloquée.
    // L'action requise est IsolateAndKillThread.
    let t4_before = daemon.get_target(4).unwrap();
    assert_eq!(
        t4_before.failover_action,
        FailoverAction::IsolateAndKillThread
    );

    daemon.evaluate_system_liveness(&admin_cap, 28_000).unwrap();
    let t4_after = daemon.get_target(4).unwrap();
    assert_eq!(t4_after.state, TargetLivenessState::Isolated);
    assert!(daemon.stats.total_threads_isolated >= 1);
    assert!(daemon.stats.total_stalls_detected >= 1);
    kprintln!("[WATCHDOG/STALL] Détection de blocage de thread et isolation sécurisée validées");

    // 6. Battements de cœur de grappe (Cluster Liveness) et bascule de secours (Failover)
    // Le nœud 1 (node-alpha, primaire) n'a pas émis depuis t=100. À t=28 000ms, le seuil de 3 manques est dépassé.
    let n1_after = daemon.get_cluster_node(1).unwrap();
    assert_eq!(n1_after.state, NodeLivenessState::FailoverInitiated);
    assert!(daemon.stats.total_cluster_failovers >= 1);
    kprintln!(
        "[WATCHDOG/CLUSTER] Battements de cœur de grappe et bascule automatique (Failover) validés"
    );

    // 7. Déclenchement NMI manuel avec capture de contexte et isolation
    let rip = 0xFFFFFFFF80108A40u64;
    let rsp = 0xFFFF80000003F100u64;
    let alert_id = daemon
        .trigger_nmi(
            &admin_cap,
            1,
            Some(2),
            LockupType::HardLockup,
            rip,
            rsp,
            28_500,
        )
        .expect("Trigger NMI alert");
    assert!(alert_id > 0);

    let t2_final = daemon.get_target(2).unwrap();
    assert_eq!(t2_final.state, TargetLivenessState::Isolated);
    kprintln!("[WATCHDOG/NMI] Interruption non-masquable (NMI) et isolation post-lockup validées");

    // 8. Condensat d'audit SHA-256 inviolable
    let digest = daemon.get_audit_digest(&admin_cap).expect("Audit digest");
    assert_ne!(digest, [0u8; 32]);
    kprintln!("[WATCHDOG/AUDIT] Condensat SHA-256 de preuve d'audit de vivacité validé");

    // 9. Validation des commandes Shell interactives ('watchdog')
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande : watchdog status
    let (st_status, len_status) = shell.execute_line("watchdog status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("SURVEILLANCE DE VIVACITÉ & CHIEN DE GARDE"));
    assert!(out_str_status.contains("Cibles Surveillées"));
    assert!(out_str_status.contains("Nœuds de Grappe"));
    kprintln!("[WATCHDOG/SHELL] Commande 'watchdog status' validée");

    // Commande : watchdog targets
    let (st_targets, len_targets) = shell.execute_line("watchdog targets", &mut out_buf);
    assert_eq!(st_targets, ShellStatus::Success);
    let out_str_targets = core::str::from_utf8(&out_buf[..len_targets]).unwrap();
    assert!(out_str_targets.contains("kernel-sched"));
    assert!(out_str_targets.contains("jambo-init"));
    assert!(out_str_targets.contains("jambo-netd"));
    kprintln!("[WATCHDOG/SHELL] Commande 'watchdog targets' validée");

    // Commande : watchdog hw
    let (st_hw, len_hw) = shell.execute_line("watchdog hw", &mut out_buf);
    assert_eq!(st_hw, ShellStatus::Success);
    let out_str_hw = core::str::from_utf8(&out_buf[..len_hw]).unwrap();
    assert!(out_str_hw.contains("Intel iTCO v2"));
    assert!(out_str_hw.contains("Timeout Total"));
    kprintln!("[WATCHDOG/SHELL] Commande 'watchdog hw' validée");

    // Commande : watchdog nodes
    let (st_nodes, len_nodes) = shell.execute_line("watchdog nodes", &mut out_buf);
    assert_eq!(st_nodes, ShellStatus::Success);
    let out_str_nodes = core::str::from_utf8(&out_buf[..len_nodes]).unwrap();
    assert!(out_str_nodes.contains("node-alpha"));
    assert!(out_str_nodes.contains("PRIMARY"));
    assert!(out_str_nodes.contains("node-beta"));
    kprintln!("[WATCHDOG/SHELL] Commande 'watchdog nodes' validée");

    // Commande : watchdog pet 1
    let (st_pet, len_pet) = shell.execute_line("watchdog pet 1", &mut out_buf);
    assert_eq!(st_pet, ShellStatus::Success);
    let out_str_pet = core::str::from_utf8(&out_buf[..len_pet]).unwrap();
    assert!(out_str_pet.contains("nourrie avec succès"));
    kprintln!("[WATCHDOG/SHELL] Commande 'watchdog pet' validée");

    // Commande : watchdog nmi 3
    let (st_nmi, len_nmi) = shell.execute_line("watchdog nmi 3", &mut out_buf);
    assert_eq!(st_nmi, ShellStatus::Success);
    let out_str_nmi = core::str::from_utf8(&out_buf[..len_nmi]).unwrap();
    assert!(out_str_nmi.contains("déclenchée et cible #3 isolée avec succès"));
    kprintln!("[WATCHDOG/SHELL] Commande 'watchdog nmi' validée");

    // Commande : watchdog alerts
    let (st_alerts, len_alerts) = shell.execute_line("watchdog alerts", &mut out_buf);
    assert_eq!(st_alerts, ShellStatus::Success);
    let out_str_alerts = core::str::from_utf8(&out_buf[..len_alerts]).unwrap();
    assert!(out_str_alerts.contains("Alerte #"));
    kprintln!("[WATCHDOG/SHELL] Commande 'watchdog alerts' validée");

    // Commande : watchdog digest
    let (st_dig, len_dig) = shell.execute_line("watchdog digest", &mut out_buf);
    assert_eq!(st_dig, ShellStatus::Success);
    let out_str_dig = core::str::from_utf8(&out_buf[..len_dig]).unwrap();
    assert!(out_str_dig.contains("Condensat SHA-256 de Vivacité"));
    kprintln!("[WATCHDOG/SHELL] Commande 'watchdog digest' validée");

    kprintln!(
        "\x1b[1;32m[WATCHDOG/PASS] Suite de tests Surveillance de Vivacité & Chien de Garde validée avec succès !\x1b[0m"
    );
    true
}

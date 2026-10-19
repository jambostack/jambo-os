//! Module de validation de la Gestion de l'Énergie Matérielle ACPI & C-States (Phase 53 - v0.2.51)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_powerd::{
    power_rights, AcpiFadtInfo, BatteryTelemetry, CpuPowerState, JamboPowerDaemon, PowerCap,
    PowerManager, PowerPolicyAction, PowerState, MAX_SUPPORTED_CORES,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de gestion d'énergie ACPI, régulation C-States et observabilité thermique (Phase 53)
pub fn execute_hardware_power_test() -> bool {
    kprintln!(
        "[POWER/TEST] Démarrage du test de gestion d'énergie ACPI & régulation C-States (Phase 53)..."
    );

    // 1. Validation du contrôle d'accès strict par capacité PowerCap (Zero-Ambient Authority)
    let fadt = AcpiFadtInfo::default();
    let mut mgr = PowerManager::new(fadt);

    let read_only_cap = PowerCap::new(Handle::new(10, 1), power_rights::BATTERY_QUERY);

    // Tentative d'extinction S5 interdite
    let rogue_s5 = mgr.transition_state(&read_only_cap, PowerState::S5SoftOff);
    assert_eq!(
        rogue_s5,
        Err(SysError::PermissionDenied),
        "Une transition S5 sans droit SHUTDOWN doit être rejetée"
    );

    // Tentative de mise en veille S3 interdite
    let rogue_s3 = mgr.transition_state(&read_only_cap, PowerState::S3SuspendToRam);
    assert_eq!(
        rogue_s3,
        Err(SysError::PermissionDenied),
        "Une transition S3 sans droit SUSPEND doit être rejetée"
    );

    // Tentative de régulation C-State interdite
    let rogue_cs = mgr.set_core_cstate(&read_only_cap, 0, CpuPowerState::C3DeepSleep);
    assert_eq!(
        rogue_cs,
        Err(SysError::PermissionDenied),
        "Une modification de C-State sans droit THROTTLE doit être rejetée"
    );
    kprintln!("[POWER/CAP] Confinement strict des droits PowerCap (Zero-Ambient Authority) validé");

    // 2. Validation des transitions d'état ACPI globales
    let admin_cap = PowerCap::new(
        Handle::new(1, 1),
        power_rights::SHUTDOWN
            | power_rights::REBOOT
            | power_rights::SUSPEND
            | power_rights::THROTTLE
            | power_rights::BATTERY_QUERY,
    );

    assert_eq!(
        mgr.transition_state(&admin_cap, PowerState::S3SuspendToRam),
        Ok(PowerState::S3SuspendToRam),
        "Mise en veille S3 légitime autorisée"
    );
    assert_eq!(
        mgr.transition_state(&admin_cap, PowerState::S0Working),
        Ok(PowerState::S0Working),
        "Réveil vers S0 nominal autorisé"
    );
    assert_eq!(
        mgr.transition_state(&admin_cap, PowerState::S5SoftOff),
        Ok(PowerState::S5SoftOff),
        "Transition vers Soft-Off S5 autorisée"
    );
    assert_eq!(mgr.total_state_transitions, 3);
    kprintln!("[POWER/ACPI] Transitions d'état globales S0 -> S3 -> S0 -> S5 validées");

    // 3. Validation de la régulation fine des cœurs CPU SMP (C-States)
    let mut smp_mgr = PowerManager::new(fadt);
    assert!(smp_mgr
        .set_core_cstate(&admin_cap, 1, CpuPowerState::C1Halt)
        .is_ok());
    assert!(smp_mgr
        .set_core_cstate(&admin_cap, 2, CpuPowerState::C3DeepSleep)
        .is_ok());
    assert_eq!(smp_mgr.cpu_cstates[0], CpuPowerState::C0Active);
    assert_eq!(smp_mgr.cpu_cstates[1], CpuPowerState::C1Halt);
    assert_eq!(smp_mgr.cpu_cstates[2], CpuPowerState::C3DeepSleep);

    // Cœur hors-bornes
    assert_eq!(
        smp_mgr.set_core_cstate(&admin_cap, 99, CpuPowerState::C1Halt),
        Err(SysError::InvalidHandle)
    );
    kprintln!("[POWER/CSTATES] Contrôle granulaire des C-States CPU SMP C0/C1/C3 validé");

    // 4. Validation des politiques thermiques et de sauvegarde d'énergie
    let mut bat_mgr = PowerManager::new(fadt);

    // Télémétrie nominale
    bat_mgr.update_battery(&admin_cap, 90, false, 34).unwrap();
    assert_eq!(bat_mgr.evaluate_policy(), PowerPolicyAction::None);

    // Batterie faible (12%) => Engagement du mode économie
    bat_mgr.update_battery(&admin_cap, 12, false, 36).unwrap();
    assert_eq!(
        bat_mgr.evaluate_policy(),
        PowerPolicyAction::EngageBatterySaver
    );
    assert!(bat_mgr.power_saver_active);

    // Surchauffe thermique (89°C) => Régulation thermique immédiate
    bat_mgr.update_battery(&admin_cap, 50, true, 89).unwrap();
    assert_eq!(
        bat_mgr.evaluate_policy(),
        PowerPolicyAction::ThermalThrottle
    );

    // Seuil critique (4%) => Extinction d'urgence ordonnée
    bat_mgr.update_battery(&admin_cap, 4, false, 42).unwrap();
    assert_eq!(
        bat_mgr.evaluate_policy(),
        PowerPolicyAction::EmergencyShutdown
    );
    kprintln!("[POWER/POLICY] Politiques thermiques et d'extinction d'urgence validées");

    // 5. Validation du démon JamboPowerDaemon
    let mut daemon = JamboPowerDaemon::new();
    daemon.init_defaults();
    assert_eq!(daemon.manager.current_state, PowerState::S0Working);
    assert_eq!(daemon.manager.battery.percentage, 100);
    assert!(daemon.manager.battery.is_charging);
    kprintln!("[POWER/DAEMON] Démon JamboPowerDaemon opérationnel de bout en bout");

    // 6. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'power status'
    let (st_stat, len_stat) = shell.execute_line("power status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("GESTION DE L'ÉNERGIE MATÉRIELLE ACPI"));
    assert!(str_stat.contains("S0"));
    kprintln!("[POWER/SHELL] Commande 'power status' validée");

    // Commande 'power cstate 1 c1'
    let (st_cs, len_cs) = shell.execute_line("power cstate 1 c1", &mut out_buf);
    assert_eq!(st_cs, ShellStatus::Success);
    let str_cs = core::str::from_utf8(&out_buf[..len_cs]).unwrap_or("");
    assert!(str_cs.contains("C-State configuré avec succès"));
    kprintln!("[POWER/SHELL] Commande 'power cstate' validée");

    // Commande 'power state s3'
    let (st_s3, len_s3) = shell.execute_line("power state s3", &mut out_buf);
    assert_eq!(st_s3, ShellStatus::Success);
    let str_s3 = core::str::from_utf8(&out_buf[..len_s3]).unwrap_or("");
    assert!(str_s3.contains("Transition ACPI réussie"));
    kprintln!("[POWER/SHELL] Commande 'power state s3' validée");

    // Commande 'power policy'
    let (st_pol, len_pol) = shell.execute_line("power policy", &mut out_buf);
    assert_eq!(st_pol, ShellStatus::Success);
    let str_pol = core::str::from_utf8(&out_buf[..len_pol]).unwrap_or("");
    assert!(str_pol.contains("Politique d'alimentation"));
    kprintln!("[POWER/SHELL] Commande 'power policy' validée");

    kprintln!(
        "[POWER/PASS] Gestion d'énergie matérielle ACPI, C-states et politiques thermiques validées avec succès."
    );
    true
}

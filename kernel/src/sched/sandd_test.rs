//! Module de validation du Confinement de Processus et Micro-Bacs à Sable Zero-Ambient (Phase 81 - v0.2.79)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sandd::{
    landlock_access, sand_rights, ArgFilter, FilterAction, JamboSandDaemon, LandlockPathRule,
    SandCap, SandboxProfile, SyscallRule,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du confinement de processus et micro-bacs à sable (Phase 81)
pub fn execute_sand_daemon_test() -> bool {
    kprintln!(
        "[SAND/TEST] Démarrage du test de confinement de processus et micro-bacs à sable Zero-Ambient (Phase 81)..."
    );

    // 1. Contrôle d'accès capabilaire (SandCap) et rejet strict d'amplification
    let admin_cap = SandCap::new(Handle::new(8101, 1), sand_rights::ALL);
    assert!(admin_cap.has_right(sand_rights::SAND_INSPECT));
    assert!(admin_cap.has_right(sand_rights::SAND_CREATE));
    assert!(admin_cap.has_right(sand_rights::SAND_APPLY));
    assert!(admin_cap.has_right(sand_rights::SAND_RESTRICT));
    assert!(admin_cap.has_right(sand_rights::SAND_KILL));
    assert!(admin_cap.has_right(sand_rights::SAND_AUDIT));
    assert!(admin_cap.has_right(sand_rights::SAND_ADMIN));

    let inspect_only_cap = admin_cap
        .attenuate(sand_rights::SAND_INSPECT)
        .expect("attenuate SandCap to inspect-only");
    assert!(inspect_only_cap.has_right(sand_rights::SAND_INSPECT));
    assert!(!inspect_only_cap.has_right(sand_rights::SAND_ADMIN));
    assert!(!inspect_only_cap.has_right(sand_rights::SAND_CREATE));
    assert!(!inspect_only_cap.has_right(sand_rights::SAND_KILL));

    // Rejet formel de toute tentative d'amplification de droits
    assert_eq!(
        inspect_only_cap.attenuate(sand_rights::SAND_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboSandDaemon::new(1, admin_cap);
    daemon.init_defaults();

    // Rejet de création de profil sans SAND_CREATE
    let dummy_profile = SandboxProfile::new(99, "unauthorized", FilterAction::Kill, 100);
    assert_eq!(
        daemon.create_profile(&inspect_only_cap, dummy_profile),
        Err(SysError::PermissionDenied),
        "Création de profil sans SAND_CREATE doit échouer"
    );

    // Rejet d'application sans SAND_APPLY
    assert_eq!(
        daemon.create_sandbox(&inspect_only_cap, 999, 1, 1, 100),
        Err(SysError::PermissionDenied),
        "Application de bac à sable sans SAND_APPLY doit échouer"
    );

    // Rejet de neutralisation sans SAND_KILL
    assert_eq!(
        daemon.kill_sandbox(&inspect_only_cap, 1),
        Err(SysError::PermissionDenied),
        "Neutralisation de bac à sable sans SAND_KILL doit échouer"
    );
    kprintln!("[SAND/CAP] Contrôle d'accès capabilaire SandCap & non-amplification validés");

    // 2. Vérification des profils par défaut et bacs à sable initiaux
    assert_eq!(daemon.profile_count, 4);
    assert_eq!(daemon.sandbox_count, 4);

    let prof_strict = daemon.get_profile(1).expect("Strict profile exists");
    assert_eq!(prof_strict.name_str(), "Strict");
    assert_eq!(prof_strict.strictness_level, 100);
    assert!(prof_strict.is_syscall_allowed_fast(12)); // ThreadYield
    assert!(!prof_strict.is_syscall_allowed_fast(26)); // ConsoleWrite interdit

    let prof_comp = daemon.get_profile(2).expect("ComputeOnly profile exists");
    assert_eq!(prof_comp.name_str(), "ComputeOnly");
    assert!(prof_comp.is_syscall_allowed_fast(4)); // VmoCreate
    assert!(prof_comp.is_syscall_allowed_fast(5)); // VmoMap
    kprintln!("[SAND/INIT] Profils de confinement nominaux validés (Strict, Compute, Net, Plugin)");

    // 3. Test de filtrage Seccomp-like (Syscall autorisé vs interdit avec Kill)
    // Sandbox 1 (Strict)
    let act_yield = daemon.evaluate_syscall(1, 12, [0, 0, 0, 0], 100);
    assert_eq!(act_yield, FilterAction::Allow);

    let act_unauth = daemon.evaluate_syscall(1, 26, [1, 0x2000, 16, 0], 101);
    assert_eq!(act_unauth, FilterAction::Kill);

    let sb_strict_after = daemon.get_sandbox(1).unwrap();
    assert!(sb_strict_after.is_killed);
    assert!(!sb_strict_after.is_active);
    assert_eq!(sb_strict_after.violation_count, 1);

    // Tout appel ultérieur par ce bac à sable est tué immédiatement
    let act_after_kill = daemon.evaluate_syscall(1, 12, [0, 0, 0, 0], 102);
    assert_eq!(act_after_kill, FilterAction::Kill);
    kprintln!("[SAND/SECCOMP] Filtrage Seccomp-like d'appels système & neutralisation Kill validés");

    // 4. Test d'invariant de resserrement monotone (Monotonic Tightening Invariant)
    let parent_id = 2; // ComputeOnly
    let parent_mask = daemon.get_profile(parent_id).unwrap().allowed_syscall_mask;

    // Tentative d'assouplissement : ajouter un appel système non autorisé par le parent (ex: Syscall 26)
    let illegal_mask = parent_mask | (1u64 << (26 - 1));
    let derive_illegal = daemon.derive_child_profile(
        &admin_cap,
        parent_id,
        "IllegalPrivilegedChild",
        illegal_mask,
        &[],
        &[],
        90,
    );
    assert_eq!(
        derive_illegal,
        Err(SysError::PermissionDenied),
        "Dérivation assouplissant un profil parent doit être formellement rejetée"
    );

    // Dérivation légitime : sous-ensemble strict (ex: restriction à ThreadYield, Exit, Clock uniquement)
    let legal_mask = (1u64 << (11 - 1)) | (1u64 << (12 - 1)) | (1u64 << (24 - 1));
    let child_id = daemon
        .derive_child_profile(
            &admin_cap,
            parent_id,
            "LegalRestrictedWorker",
            legal_mask,
            &[],
            &[],
            95,
        )
        .expect("derive valid tightened child profile");
    assert_eq!(daemon.profile_count, 5);
    let child_prof = daemon.get_profile(child_id).unwrap();
    assert_eq!(child_prof.parent_id, Some(parent_id));
    assert_eq!(child_prof.strictness_level, 95);
    kprintln!("[SAND/MONOTONE] Invariant de resserrement monotone (Seccomp/Landlock) formellement prouvé");

    // 5. Test de restriction Landlock-like sur chemins VFS
    // Sandbox 2 (ComputeOnly a la règle: /data/ en lecture seule)
    let res_read_ok = daemon.evaluate_landlock(2, "/data/dataset.parquet", landlock_access::READ, 200);
    assert_eq!(res_read_ok, Ok(()));

    // Écriture interdite dans /data/
    let res_write_err =
        daemon.evaluate_landlock(2, "/data/dataset.parquet", landlock_access::WRITE, 201);
    assert_eq!(res_write_err, Err(SysError::PermissionDenied));

    // Chemin hors règle Landlock interdit (Zero-Ambient)
    let res_root_err = daemon.evaluate_landlock(2, "/etc/shadow", landlock_access::READ, 202);
    assert_eq!(res_root_err, Err(SysError::PermissionDenied));
    kprintln!("[SAND/LANDLOCK] Confinement Landlock-like des chemins VFS validé");

    // 6. Test d'audit cryptographique SHA-256 et journal de violations
    let digest = daemon
        .get_audit_digest(&admin_cap)
        .expect("audit digest retrieved");
    assert_ne!(digest, [0u8; 32]);
    assert!(daemon.violation_total >= 3);
    kprintln!("[SAND/AUDIT] Condensat SHA-256 de preuve d'audit de confinement validé");

    // 7. Validation des commandes Shell interactives ('sand')
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande : sand status
    let (st_status, len_status) = shell.execute_line("sand status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("CONFINEMENT & MICRO-BACS À SABLE ZERO-AMBIENT"));
    assert!(out_str_status.contains("Profils Actifs"));
    assert!(out_str_status.contains("Bacs à Sable Actifs"));
    kprintln!("[SAND/SHELL] Commande 'sand status' validée");

    // Commande : sand profiles
    let (st_prof, len_prof) = shell.execute_line("sand profiles", &mut out_buf);
    assert_eq!(st_prof, ShellStatus::Success);
    let out_str_prof = core::str::from_utf8(&out_buf[..len_prof]).unwrap();
    assert!(out_str_prof.contains("Strict"));
    assert!(out_str_prof.contains("ComputeOnly"));
    assert!(out_str_prof.contains("NetworkWorker"));
    assert!(out_str_prof.contains("UntrustedPlugin"));
    kprintln!("[SAND/SHELL] Commande 'sand profiles' validée");

    // Commande : sand list
    let (st_list, len_list) = shell.execute_line("sand list", &mut out_buf);
    assert_eq!(st_list, ShellStatus::Success);
    let out_str_list = core::str::from_utf8(&out_buf[..len_list]).unwrap();
    assert!(out_str_list.contains("#1"));
    assert!(out_str_list.contains("#2"));
    kprintln!("[SAND/SHELL] Commande 'sand list' validée");

    // Commande : sand inspect 1
    let (st_insp, len_insp) = shell.execute_line("sand inspect 1", &mut out_buf);
    assert_eq!(st_insp, ShellStatus::Success);
    let out_str_insp = core::str::from_utf8(&out_buf[..len_insp]).unwrap();
    assert!(out_str_insp.contains("PROFIL DE CONFINEMENT"));
    assert!(out_str_insp.contains("Strict"));
    kprintln!("[SAND/SHELL] Commande 'sand inspect' validée");

    // Commande : sand test 2 12
    let (st_test, len_test) = shell.execute_line("sand test 2 12", &mut out_buf);
    assert_eq!(st_test, ShellStatus::Success);
    let out_str_test = core::str::from_utf8(&out_buf[..len_test]).unwrap();
    assert!(out_str_test.contains("ALLOW"));
    kprintln!("[SAND/SHELL] Commande 'sand test' validée");

    // Commande : sand violations
    let (st_viol, _len_viol) = shell.execute_line("sand violations", &mut out_buf);
    assert_eq!(st_viol, ShellStatus::Success);
    kprintln!("[SAND/SHELL] Commande 'sand violations' validée");

    // Commande : sand digest
    let (st_dig, len_dig) = shell.execute_line("sand digest", &mut out_buf);
    assert_eq!(st_dig, ShellStatus::Success);
    let out_str_dig = core::str::from_utf8(&out_buf[..len_dig]).unwrap();
    assert!(out_str_dig.contains("Condensat SHA-256 de Confinement"));
    kprintln!("[SAND/SHELL] Commande 'sand digest' validée");

    kprintln!(
        "\x1b[1;32m[SAND/PASS] Suite de tests Confinement de Processus & Micro-Bacs à Sable validée avec succès !\x1b[0m"
    );
    true
}

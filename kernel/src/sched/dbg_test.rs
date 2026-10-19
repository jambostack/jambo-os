//! Module de validation du Débogage Dynamique d'Espace Utilisateur, DR0..DR7 & Introspection (Phase 86 - v0.2.84)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_dbg::{
    dbg_rights, AuditAction, Breakpoint, BreakpointType, DbgCap, DebugSession, DebugThread,
    DisasmInstruction, DrCondition, DrLength, DrSlot, Dr6Status, HardwareDrConfig,
    JamboDebuggerDaemon, MemoryRegion, SessionState, Sha256, StopReason, ThreadRegisters,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du démon de débogage dynamique Ring 3 (Phase 86)
pub fn execute_dbg_daemon_test() -> bool {
    kprintln!(
        "[DBG/TEST] Démarrage du test de débogage dynamique, DR0..DR7 & introspection mémoire (Phase 86)..."
    );

    // 1. Contrôle d'accès capabilaire (DbgCap) et rejet formel d'amplification
    let admin_cap = DbgCap::new(Handle::new(8601, 1), dbg_rights::ALL);
    assert!(admin_cap.has_right(dbg_rights::DBG_INSPECT));
    assert!(admin_cap.has_right(dbg_rights::DBG_ATTACH));
    assert!(admin_cap.has_right(dbg_rights::DBG_BREAKPOINT));
    assert!(admin_cap.has_right(dbg_rights::DBG_STEP));
    assert!(admin_cap.has_right(dbg_rights::DBG_MEM_READ));
    assert!(admin_cap.has_right(dbg_rights::DBG_MEM_WRITE));
    assert!(admin_cap.has_right(dbg_rights::DBG_REG_READ));
    assert!(admin_cap.has_right(dbg_rights::DBG_REG_WRITE));
    assert!(admin_cap.has_right(dbg_rights::DBG_AUDIT));
    assert!(admin_cap.has_right(dbg_rights::DBG_ADMIN));

    let inspect_only_cap = admin_cap
        .attenuate(dbg_rights::DBG_INSPECT | dbg_rights::DBG_MEM_READ)
        .expect("attenuate DbgCap to inspect/read-only");
    assert!(inspect_only_cap.has_right(dbg_rights::DBG_INSPECT));
    assert!(inspect_only_cap.has_right(dbg_rights::DBG_MEM_READ));
    assert!(!inspect_only_cap.has_right(dbg_rights::DBG_BREAKPOINT));
    assert!(!inspect_only_cap.has_right(dbg_rights::DBG_MEM_WRITE));
    assert!(!inspect_only_cap.has_right(dbg_rights::DBG_STEP));
    assert!(!inspect_only_cap.has_right(dbg_rights::DBG_ADMIN));

    // Rejet formel de toute tentative d'élévation / amplification
    assert_eq!(
        inspect_only_cap.attenuate(dbg_rights::DBG_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboDebuggerDaemon::new(1, admin_cap);
    daemon.init_defaults();

    // Rejet d'insertion de breakpoint sans DBG_BREAKPOINT
    assert_eq!(
        daemon.add_software_breakpoint(&inspect_only_cap, 1, 0x0040_0001, 100),
        Err(SysError::PermissionDenied),
        "Insertion de breakpoint sans DBG_BREAKPOINT doit échouer"
    );

    // Rejet de pas à pas sans DBG_STEP
    assert_eq!(
        daemon.step_instruction(&inspect_only_cap, 1, 1, 101),
        Err(SysError::PermissionDenied),
        "Pas à pas sans DBG_STEP doit échouer"
    );

    // Rejet d'écriture mémoire sans DBG_MEM_WRITE
    assert_eq!(
        daemon.write_memory(&inspect_only_cap, 1, 0x0040_0001, &[0x90], 102),
        Err(SysError::PermissionDenied),
        "Écriture mémoire sans DBG_MEM_WRITE doit échouer"
    );
    kprintln!("[DBG/CAP] Modèle de sécurité capabilaire DbgCap et interdiction d'amplification validés");

    // 2. Gestion des sessions : Attachement et Détachement
    daemon.attach_process(&admin_cap, 42, 200).expect("attach process 42");
    assert!(daemon.get_session(42).is_some());
    assert_eq!(daemon.session_count, 2);

    daemon.detach_process(&admin_cap, 42, 201).expect("detach process 42");
    assert!(daemon.get_session(42).is_none());
    assert_eq!(daemon.session_count, 1);
    kprintln!("[DBG/SESSION] Cycle d'attachement et détachement de processus validé");

    // 3. Registres matériels de débogage DR0..DR7 & Watchpoints
    let (hw_bp_id, slot) = daemon
        .add_hardware_breakpoint(
            &admin_cap,
            1,
            0x7FFF_0040,
            DrCondition::DataWrite,
            DrLength::Len8,
            300,
        )
        .expect("add hardware breakpoint DR0");
    assert_eq!(hw_bp_id, 1);
    assert_eq!(slot, DrSlot::Dr0);

    let session = daemon.get_session(1).unwrap();
    let thread = session.get_thread(1).unwrap();
    assert_eq!(thread.hw_dr.dr[0], 0x7FFF_0040);
    assert!(thread.hw_dr.is_slot_enabled(DrSlot::Dr0));

    // Simulation de l'interception matérielle INT1 (#DB) sur accès en écriture
    let stop_reason = daemon.handle_int1_exception(1, 1, 1 << 0, 301).expect("handle INT1 DR0");
    assert_eq!(
        stop_reason,
        StopReason::HardwareWatchpoint(DrSlot::Dr0, 0x7FFF_0040),
        "Détection matérielle du watchpoint sur DR0 validée"
    );

    let session_after = daemon.get_session(1).unwrap();
    let bp_hw = session_after.breakpoints[0].unwrap();
    assert_eq!(bp_hw.hit_count, 1);
    kprintln!("[DBG/HARDWARE] Registres DR0..DR7 et interception d'exception INT1 (#DB) validés");

    // 4. Points d'arrêt logiciels INT3 (0xCC), rembobinage RIP & restauration mémoire
    let sw_bp_id = daemon
        .add_software_breakpoint(&admin_cap, 1, 0x0040_0004, 400)
        .expect("add software breakpoint INT3");

    // Vérifier que l'instruction d'origine (CALL 0xE8) a été remplacée par 0xCC
    let mut read_buf = [0u8; 1];
    daemon.read_memory(&admin_cap, 1, 0x0040_0004, &mut read_buf, 401).unwrap();
    assert_eq!(read_buf[0], 0xCC, "Opcode 0xCC correctement injecté en mémoire");

    // Simuler le déclenchement de l'exception INT3 (#BP)
    // Le processeur x86-64 avance RIP à 0x0040_0005 lors d'INT3
    let hit_id = daemon.handle_int3_exception(1, 1, 0x0040_0005, 402).expect("handle INT3");
    assert_eq!(hit_id, sw_bp_id);

    // Vérifier le rembobinage automatique de RIP vers l'adresse exacte du breakpoint
    let regs = daemon.read_registers(&admin_cap, 1, 1, 403).unwrap();
    assert_eq!(regs.rip, 0x0040_0004, "Rembobinage automatique de RIP validé");

    // Suppression du breakpoint et vérification de la restauration de l'instruction originale
    daemon.remove_breakpoint(&admin_cap, 1, sw_bp_id, 404).unwrap();
    daemon.read_memory(&admin_cap, 1, 0x0040_0004, &mut read_buf, 405).unwrap();
    assert_eq!(read_buf[0], 0xE8, "Opcode d'origine (CALL 0xE8) fidèlement restauré");
    kprintln!("[DBG/INT3] Point d'arrêt INT3, rembobinage automatique de RIP et restauration validés");

    // 5. Exécution pas à pas (*Single-Stepping*) via Trap Flag (TF)
    // Remettre RIP à 0x0040_0000 (NOP)
    let mut reset_regs = regs;
    reset_regs.rip = 0x0040_0000;
    daemon.write_registers(&admin_cap, 1, 1, reset_regs, 500).unwrap();

    let inst1 = daemon.step_instruction(&admin_cap, 1, 1, 501).expect("step 1");
    assert_eq!(inst1.mnemonic, "nop");
    assert_eq!(inst1.len, 1);

    let regs_after_step = daemon.read_registers(&admin_cap, 1, 1, 502).unwrap();
    assert_eq!(regs_after_step.rip, 0x0040_0001, "RIP avancé après pas à pas NOP");
    assert!(!regs_after_step.is_single_step_enabled(), "TF réinitialisé après arrêt");

    // 6. Intégrité cryptographique SHA-256 de la chaîne d'audit
    assert!(daemon.verify_audit_integrity(), "Chaîne d'audit SHA-256 intègre et scellée");
    kprintln!("[DBG/STEP] Exécution pas à pas (TF flag) et audit cryptographique SHA-256 validés");

    // 7. Validation des commandes du Shell interactif JamboShell
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 4096];

    // Commande : dbg status
    let (st_status, len_status) = shell.execute_line("dbg status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("DÉBOGUEUR D'ESPACE UTILISATEUR"));
    assert!(out_str_status.contains("VALIDE & SCELLÉE"));
    assert!(out_str_status.contains("PID 1"));
    kprintln!("[DBG/SHELL] Commande 'dbg status' validée");

    // Commande : dbg bp list
    let (st_bplist, len_bplist) = shell.execute_line("dbg bp list", &mut out_buf);
    assert_eq!(st_bplist, ShellStatus::Success);
    let out_str_bplist = core::str::from_utf8(&out_buf[..len_bplist]).unwrap();
    assert!(out_str_bplist.contains("POINTS D'ARRÊT ACTIFS"));
    kprintln!("[DBG/SHELL] Commande 'dbg bp list' validée");

    // Commande : dbg bp add 0x00400001
    let (st_bpadd, len_bpadd) = shell.execute_line("dbg bp add 0x00400001", &mut out_buf);
    assert_eq!(st_bpadd, ShellStatus::Success);
    let out_str_bpadd = core::str::from_utf8(&out_buf[..len_bpadd]).unwrap();
    assert!(out_str_bpadd.contains("point d'arrêt logiciel INT3"));
    kprintln!("[DBG/SHELL] Commande 'dbg bp add' validée");

    // Commande : dbg regs
    let (st_regs, len_regs) = shell.execute_line("dbg regs", &mut out_buf);
    assert_eq!(st_regs, ShellStatus::Success);
    let out_str_regs = core::str::from_utf8(&out_buf[..len_regs]).unwrap();
    assert!(out_str_regs.contains("REGISTRES DU THREAD TID 1"));
    assert!(out_str_regs.contains("RIP:"));
    assert!(out_str_regs.contains("RFLAGS:"));
    kprintln!("[DBG/SHELL] Commande 'dbg regs' validée");

    // Commande : dbg mem 0x00400000
    let (st_mem, len_mem) = shell.execute_line("dbg mem 0x00400000", &mut out_buf);
    assert_eq!(st_mem, ShellStatus::Success);
    let out_str_mem = core::str::from_utf8(&out_buf[..len_mem]).unwrap();
    assert!(out_str_mem.contains("INTROSPECTION MÉMOIRE À 0x400000"));
    assert!(out_str_mem.contains("Instruction désassemblée"));
    kprintln!("[DBG/SHELL] Commande 'dbg mem' validée");

    // Commande : dbg step
    let (st_step, len_step) = shell.execute_line("dbg step", &mut out_buf);
    assert_eq!(st_step, ShellStatus::Success);
    let out_str_step = core::str::from_utf8(&out_buf[..len_step]).unwrap();
    assert!(out_str_step.contains("pas à pas exécuté"));
    kprintln!("[DBG/SHELL] Commande 'dbg step' validée");

    // Commande : dbg cont
    let (st_cont, len_cont) = shell.execute_line("dbg cont", &mut out_buf);
    assert_eq!(st_cont, ShellStatus::Success);
    let out_str_cont = core::str::from_utf8(&out_buf[..len_cont]).unwrap();
    assert!(out_str_cont.contains("reprise de l'exécution du thread"));
    kprintln!("[DBG/SHELL] Commande 'dbg cont' validée");

    // Commande : dbg digest
    let (st_dig, len_dig) = shell.execute_line("dbg digest", &mut out_buf);
    assert_eq!(st_dig, ShellStatus::Success);
    let out_str_dig = core::str::from_utf8(&out_buf[..len_dig]).unwrap();
    assert!(out_str_dig.contains("Condensat SHA-256 d'Audit Débogueur"));
    kprintln!("[DBG/SHELL] Commande 'dbg digest' validée");

    kprintln!(
        "\x1b[1;32m[DBG/PASS] Suite de tests Débogage Dynamique Ring 3, DR0..DR7 & Introspection validée avec succès !\x1b[0m"
    );
    true
}

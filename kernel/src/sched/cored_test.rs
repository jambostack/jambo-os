//! Module de validation de la Capture d'État Post-Mortem, Crash Dumps ELF Scellés et Télémétrie Post-Crash (Phase 83 - v0.2.81)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_cored::{
    core_rights, memory_flags, ArchRegisters, CoreCap, CoreMemoryRegion, CrashReason,
    Elf64Generator, JamboCoreDaemon, RecoveryRecommendation, SealedCrashReport, Sha256,
    X86_64Registers, AArch64Registers,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du gestionnaire de crash dumps post-mortem (Phase 83)
pub fn execute_core_daemon_test() -> bool {
    kprintln!(
        "[CORE/TEST] Démarrage du test de capture d'état post-mortem, crash dumps ELF scellés et télémétrie (Phase 83)..."
    );

    // 1. Contrôle d'accès capabilaire (CoreCap) et interdiction stricte d'amplification
    let admin_cap = CoreCap::new(Handle::new(8301, 1), core_rights::ALL);
    assert!(admin_cap.has_right(core_rights::CORE_INSPECT));
    assert!(admin_cap.has_right(core_rights::CORE_CAPTURE));
    assert!(admin_cap.has_right(core_rights::CORE_GENERATE));
    assert!(admin_cap.has_right(core_rights::CORE_SEAL));
    assert!(admin_cap.has_right(core_rights::CORE_QUARANTINE));
    assert!(admin_cap.has_right(core_rights::CORE_TELEMETRY));
    assert!(admin_cap.has_right(core_rights::CORE_PURGE));
    assert!(admin_cap.has_right(core_rights::CORE_ADMIN));

    let inspect_only_cap = admin_cap
        .attenuate(core_rights::CORE_INSPECT)
        .expect("attenuate CoreCap to inspect-only");
    assert!(inspect_only_cap.has_right(core_rights::CORE_INSPECT));
    assert!(!inspect_only_cap.has_right(core_rights::CORE_ADMIN));
    assert!(!inspect_only_cap.has_right(core_rights::CORE_CAPTURE));
    assert!(!inspect_only_cap.has_right(core_rights::CORE_GENERATE));
    assert!(!inspect_only_cap.has_right(core_rights::CORE_QUARANTINE));
    assert!(!inspect_only_cap.has_right(core_rights::CORE_TELEMETRY));

    // Rejet formel de toute amplification capabilaire
    assert_eq!(
        inspect_only_cap.attenuate(core_rights::CORE_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboCoreDaemon::new(1, admin_cap);
    daemon.init_defaults();

    // Rejet de capture sans CORE_CAPTURE
    let dummy_regs = ArchRegisters::X86_64(X86_64Registers::default());
    assert_eq!(
        daemon.capture_crash(
            &inspect_only_cap,
            99,
            1,
            "unauthorized",
            CrashReason::KernelPanic,
            dummy_regs,
            &[],
            &[],
            100
        ),
        Err(SysError::PermissionDenied),
        "Capture de crash sans CORE_CAPTURE doit échouer"
    );

    // Rejet de génération ELF sans CORE_GENERATE
    let mut dummy_buf = [0u8; 512];
    assert_eq!(
        daemon.generate_elf(&inspect_only_cap, 1, &mut dummy_buf),
        Err(SysError::PermissionDenied),
        "Génération ELF sans CORE_GENERATE doit échouer"
    );

    // Rejet de mise en quarantaine sans CORE_QUARANTINE
    assert_eq!(
        daemon.quarantine_memory(&inspect_only_cap, 1),
        Err(SysError::PermissionDenied),
        "Mise en quarantaine sans CORE_QUARANTINE doit échouer"
    );

    // Rejet d'émission de télémétrie sans CORE_TELEMETRY
    assert_eq!(
        daemon.emit_telemetry(&inspect_only_cap, 1, 1),
        Err(SysError::PermissionDenied),
        "Émission de télémétrie sans CORE_TELEMETRY doit échouer"
    );

    // Rejet de purge sans CORE_PURGE
    assert_eq!(
        daemon.purge_reports(&inspect_only_cap),
        Err(SysError::PermissionDenied),
        "Purge sans CORE_PURGE doit échouer"
    );

    kprintln!("[CORE/CAP] Contrôle d'accès capabilaire CoreCap & non-amplification validés");

    // 2. Vérification de la configuration nominale initiale
    assert_eq!(daemon.report_count, 2);
    let r1 = daemon.get_report(1).expect("Report 1 must exist");
    assert_eq!(r1.process_name_str(), "worker-service");
    assert_eq!(r1.pid, 42);
    assert_eq!(r1.tid, 1);
    assert_eq!(r1.reason.as_str(), "PAGE_FAULT");
    assert_eq!(r1.regs.fault_address(), 0x28);
    assert!(r1.elf_size > 0);
    assert!(!r1.quarantined);

    let r2 = daemon.get_report(2).expect("Report 2 must exist");
    assert_eq!(r2.process_name_str(), "virtio-driver");
    assert_eq!(r2.pid, 12);
    assert_eq!(r2.reason.as_str(), "WATCHDOG_TIMEOUT");
    assert_eq!(r2.recommendation, RecoveryRecommendation::NodeFailover);
    kprintln!("[CORE/REPORTS] Configuration nominale des rapports de crash validée");

    // 3. Validation de la génération de Core Dump binaire ELF64
    let mut elf_buf = [0u8; 2048];
    let written = daemon
        .generate_elf(&admin_cap, 1, &mut elf_buf)
        .expect("ELF generation");
    assert_eq!(written, r1.elf_size);

    // En-tête standard ELF64
    assert_eq!(elf_buf[0], 0x7f);
    assert_eq!(elf_buf[1], b'E');
    assert_eq!(elf_buf[2], b'L');
    assert_eq!(elf_buf[3], b'F');
    assert_eq!(elf_buf[4], 2); // 64-bit ELF
    assert_eq!(elf_buf[5], 1); // Little endian
    assert_eq!(elf_buf[6], 1); // Version 1
    let elf_type = u16::from_le_bytes([elf_buf[16], elf_buf[17]]);
    assert_eq!(elf_type, Elf64Generator::ET_CORE); // ET_CORE = 4
    let elf_machine = u16::from_le_bytes([elf_buf[18], elf_buf[19]]);
    assert_eq!(elf_machine, 62); // EM_X86_64 = 62
    let phnum = u16::from_le_bytes([elf_buf[56], elf_buf[57]]);
    assert_eq!(phnum, 1 + r1.region_count as u16);
    kprintln!("[CORE/ELF] Génération de Core Dump ELF64 (ET_CORE, PT_NOTE, PT_LOAD) validée");

    // 4. Scellement cryptographique SHA-256 & Détection formelle de falsification
    let is_sealed_valid = daemon.verify_seal(&admin_cap, 1).expect("Seal verify");
    assert!(is_sealed_valid, "Le sceau du rapport 1 doit être intègre");

    // Mutation malveillante simulée d'un champ
    for slot in daemon.reports.iter_mut() {
        if let Some(ref mut rep) = slot {
            if rep.report_id == 1 {
                rep.pid = 9999; // Falsification
            }
        }
    }
    let is_tampered_valid = daemon.verify_seal(&admin_cap, 1).expect("Seal verify tampered");
    assert!(!is_tampered_valid, "La falsification doit être immédiatement détectée");

    // Rétablissement du champ légitime
    for slot in daemon.reports.iter_mut() {
        if let Some(ref mut rep) = slot {
            if rep.report_id == 1 {
                rep.pid = 42;
            }
        }
    }
    assert!(daemon.verify_seal(&admin_cap, 1).unwrap());
    kprintln!("[CORE/SEAL] Scellement cryptographique SHA-256 & détection de falsification validés");

    // 5. Confinement et mise en quarantaine de mémoire
    let pages = daemon.quarantine_memory(&admin_cap, 1).expect("Quarantine memory");
    assert!(pages > 0);
    let r1_quarantined = daemon.get_report(1).unwrap();
    assert!(r1_quarantined.quarantined);
    assert!(r1_quarantined.regions[0].quarantined);
    assert!(r1_quarantined.regions[1].quarantined);
    kprintln!("[CORE/QUARANTINE] Confinement et mise en quarantaine de la mémoire validés");

    // 6. Émission de télémétrie post-crash et recommandation d'auto-guérison
    let tel = daemon.emit_telemetry(&admin_cap, 1, 10).expect("Emit telemetry");
    assert_eq!(tel.report_id, 1);
    assert_eq!(tel.node_id, 10);
    assert_eq!(tel.pid, 42);
    assert_eq!(tel.recommendation, RecoveryRecommendation::RestartProcess);
    assert_ne!(tel.telemetry_hash, [0u8; 32]);
    let r1_tel = daemon.get_report(1).unwrap();
    assert!(r1_tel.telemetry_emitted);
    kprintln!("[CORE/TELEMETRY] Émission de télémétrie post-crash & recommandations d'auto-guérison validées");

    // 7. Capture dynamique de crash à l'exécution & évolution de l'audit
    let audit_initial = daemon.get_audit_digest(&admin_cap).expect("Audit initial");
    assert_ne!(audit_initial, [0u8; 32]);

    let mut crash_regs = X86_64Registers::default();
    crash_regs.rip = 0x00007fff90010000;
    crash_regs.rsp = 0x00007fffa0010000;
    crash_regs.rbp = 0x00007fffa0010040;

    let rep3_id = daemon
        .capture_crash(
            &admin_cap,
            88,
            2,
            "crypto-worker",
            CrashReason::AssertionFailed,
            ArchRegisters::X86_64(crash_regs),
            &[0xcc, 0x90, 0x90, 0x90],
            &[0x00007fff90010000, 0x00007fff90005000],
            2500,
        )
        .expect("Dynamic crash capture");
    assert_eq!(rep3_id, 3);
    assert_eq!(daemon.report_count, 3);

    let audit_after = daemon.get_audit_digest(&admin_cap).expect("Audit after");
    assert_ne!(audit_initial, audit_after, "L'audit chaîné doit progresser de manière monotone");
    kprintln!("[CORE/DYNAMIC] Capture dynamique de crash & registre d'audit chaîné validés");

    // 8. Validation des commandes Shell interactives ('core')
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande : core status
    let (st_status, len_status) = shell.execute_line("core status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("GESTIONNAIRE DE CRASH DUMPS & FORENSIQUE POST-MORTEM"));
    assert!(out_str_status.contains("Rapports Archivés"));
    assert!(out_str_status.contains("Crashs Capturés"));
    kprintln!("[CORE/SHELL] Commande 'core status' validée");

    // Commande : core list
    let (st_list, len_list) = shell.execute_line("core list", &mut out_buf);
    assert_eq!(st_list, ShellStatus::Success);
    let out_str_list = core::str::from_utf8(&out_buf[..len_list]).unwrap();
    assert!(out_str_list.contains("worker-service"));
    assert!(out_str_list.contains("virtio-driver"));
    kprintln!("[CORE/SHELL] Commande 'core list' validée");

    // Commande : core view 1
    let (st_view, len_view) = shell.execute_line("core view 1", &mut out_buf);
    assert_eq!(st_view, ShellStatus::Success);
    let out_str_view = core::str::from_utf8(&out_buf[..len_view]).unwrap();
    assert!(out_str_view.contains("DÉTAILS DU CRASH DUMP #1"));
    assert!(out_str_view.contains("worker-service"));
    assert!(out_str_view.contains("PAGE_FAULT"));
    kprintln!("[CORE/SHELL] Commande 'core view' validée");

    // Commande : core quarantine 1
    let (st_quar, len_quar) = shell.execute_line("core quarantine 1", &mut out_buf);
    assert_eq!(st_quar, ShellStatus::Success);
    let out_str_quar = core::str::from_utf8(&out_buf[..len_quar]).unwrap();
    assert!(out_str_quar.contains("mis en quarantaine"));
    kprintln!("[CORE/SHELL] Commande 'core quarantine' validée");

    // Commande : core telemetry 1
    let (st_tel, len_tel) = shell.execute_line("core telemetry 1", &mut out_buf);
    assert_eq!(st_tel, ShellStatus::Success);
    let out_str_tel = core::str::from_utf8(&out_buf[..len_tel]).unwrap();
    assert!(out_str_tel.contains("télémétrie post-crash émise"));
    kprintln!("[CORE/SHELL] Commande 'core telemetry' validée");

    // Commande : core verify 1
    let (st_ver, len_ver) = shell.execute_line("core verify 1", &mut out_buf);
    assert_eq!(st_ver, ShellStatus::Success);
    let out_str_ver = core::str::from_utf8(&out_buf[..len_ver]).unwrap();
    assert!(out_str_ver.contains("[VALIDE / INTÈGRE]"));
    kprintln!("[CORE/SHELL] Commande 'core verify' validée");

    // Commande : core elf 1
    let (st_elf, len_elf) = shell.execute_line("core elf 1", &mut out_buf);
    assert_eq!(st_elf, ShellStatus::Success);
    let out_str_elf = core::str::from_utf8(&out_buf[..len_elf]).unwrap();
    assert!(out_str_elf.contains("binaire ELF64 Core Dump généré"));
    kprintln!("[CORE/SHELL] Commande 'core elf' validée");

    // Commande : core digest
    let (st_dig, len_dig) = shell.execute_line("core digest", &mut out_buf);
    assert_eq!(st_dig, ShellStatus::Success);
    let out_str_dig = core::str::from_utf8(&out_buf[..len_dig]).unwrap();
    assert!(out_str_dig.contains("Condensat SHA-256 d'Audit Crash"));
    kprintln!("[CORE/SHELL] Commande 'core digest' validée");

    kprintln!(
        "\x1b[1;32m[CORE/PASS] Suite de tests Capture Post-Mortem & Core Dumps ELF scellés validée avec succès !\x1b[0m"
    );
    true
}

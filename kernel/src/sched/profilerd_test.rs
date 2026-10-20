//! Module de validation de l'Échantillonnage PMC/PEBS, Profils de Flammes & Latence (Phase 85 - v0.2.83)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_profilerd::{
    profile_rights, AuditAction, FlameNode, JamboProfilerDaemon, LatencyCategory, PebsRecord,
    PmcConfig, PmcEventType, PmcSample, ProfileCap, ProfileReport, RingFilter, Sha256, TargetArch,
    MAX_CALL_STACK_DEPTH,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du démon de profilage matériel Ring 3 (Phase 85)
pub fn execute_profiler_daemon_test() -> bool {
    kprintln!(
        "[PROFILER/TEST] Démarrage du test d'échantillonnage PMC/PEBS, Flamegraphs & Latence (Phase 85)..."
    );

    // 1. Contrôle d'accès capabilaire (ProfileCap) et interdiction stricte d'amplification
    let admin_cap = ProfileCap::new(Handle::new(8501, 1), profile_rights::ALL);
    assert!(admin_cap.has_right(profile_rights::PROFILE_INSPECT));
    assert!(admin_cap.has_right(profile_rights::PROFILE_CONFIGURE));
    assert!(admin_cap.has_right(profile_rights::PROFILE_SAMPLE));
    assert!(admin_cap.has_right(profile_rights::PROFILE_COLLECT));
    assert!(admin_cap.has_right(profile_rights::PROFILE_EXPORT));
    assert!(admin_cap.has_right(profile_rights::PROFILE_AUDIT));
    assert!(admin_cap.has_right(profile_rights::PROFILE_ADMIN));

    let inspect_only_cap = admin_cap
        .attenuate(profile_rights::PROFILE_INSPECT)
        .expect("attenuate ProfileCap to inspect-only");
    assert!(inspect_only_cap.has_right(profile_rights::PROFILE_INSPECT));
    assert!(!inspect_only_cap.has_right(profile_rights::PROFILE_ADMIN));
    assert!(!inspect_only_cap.has_right(profile_rights::PROFILE_CONFIGURE));
    assert!(!inspect_only_cap.has_right(profile_rights::PROFILE_SAMPLE));
    assert!(!inspect_only_cap.has_right(profile_rights::PROFILE_COLLECT));
    assert!(!inspect_only_cap.has_right(profile_rights::PROFILE_EXPORT));

    // Rejet formel de toute amplification capabilaire
    assert_eq!(
        inspect_only_cap.attenuate(profile_rights::PROFILE_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboProfilerDaemon::new(1, admin_cap);
    daemon.init_defaults();

    // Rejet de configuration sans PROFILE_CONFIGURE
    assert_eq!(
        daemon.configure_pmc(&inspect_only_cap, 99, PmcConfig::default(), 100),
        Err(SysError::PermissionDenied),
        "Configuration PMC sans PROFILE_CONFIGURE doit échouer"
    );

    // Rejet d'échantillonnage sans PROFILE_SAMPLE
    let dummy_sample = PmcSample::default();
    assert_eq!(
        daemon.record_sample(&inspect_only_cap, dummy_sample),
        Err(SysError::PermissionDenied),
        "Enregistrement d'échantillon sans PROFILE_SAMPLE doit échouer"
    );

    // Rejet de mesure de latence sans PROFILE_COLLECT
    assert_eq!(
        daemon.record_latency(
            &inspect_only_cap,
            LatencyCategory::ContextSwitch,
            500,
            1,
            100
        ),
        Err(SysError::PermissionDenied),
        "Mesure de latence sans PROFILE_COLLECT doit échouer"
    );

    // Rejet d'export de rapport sans PROFILE_EXPORT
    assert_eq!(
        daemon.generate_report(&inspect_only_cap, 1, 1000, 100),
        Err(SysError::PermissionDenied),
        "Génération de rapport sans PROFILE_EXPORT doit échouer"
    );
    kprintln!(
        "[PROFILER/SECURITY] Contrôles capabilaires et atténuation sans amplification validés"
    );

    // 2. Compteurs PMC matériels et calculs IPC / Branch miss rate
    let sample_inst = PmcSample {
        sample_id: 10,
        pid: 42,
        tid: 1,
        timestamp: 1000,
        ip: 0x0040_1000,
        sp: 0x7FFF_0000,
        event: PmcEventType::Instructions,
        counter_val: 50_000_000,
        call_stack: [0u64; MAX_CALL_STACK_DEPTH],
        call_stack_len: 0,
        pebs: None,
    };
    daemon
        .record_sample(&admin_cap, sample_inst)
        .expect("sample instructions");

    let sample_cyc = PmcSample {
        sample_id: 11,
        pid: 42,
        tid: 1,
        timestamp: 1001,
        ip: 0x0040_1000,
        sp: 0x7FFF_0000,
        event: PmcEventType::CpuCycles,
        counter_val: 25_000_000,
        call_stack: [0u64; MAX_CALL_STACK_DEPTH],
        call_stack_len: 0,
        pebs: None,
    };
    daemon
        .record_sample(&admin_cap, sample_cyc)
        .expect("sample cycles");

    let (ipc_whole, _) = daemon.aggregated.ipc_ratio();
    assert!(ipc_whole >= 1, "Ratio IPC cohérent");
    kprintln!("[PROFILER/PMC] Compteurs d'événements matériels PMC et calcul IPC validés");

    // 3. Arbre d'appels (Call Graph), Flamegraph & Déroulement de pile
    let stack = [0x0040_0000, 0x0040_1050, 0x0040_2050]; // main -> vfs_read -> ipc_send_msg
    let sample_stack = PmcSample {
        sample_id: 12,
        pid: 42,
        tid: 1,
        timestamp: 1002,
        ip: 0x0040_2050,
        sp: 0x7FFF_0000,
        event: PmcEventType::Instructions,
        counter_val: 100_000,
        call_stack: [
            stack[0], stack[1], stack[2], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        call_stack_len: 3,
        pebs: Some(PebsRecord {
            precise_ip: 0x0040_2050,
            linear_data_addr: 0x7FFF_00A0,
            flags: 0x01,
            event_index: 0,
        }),
    };
    daemon
        .record_sample(&admin_cap, sample_stack)
        .expect("sample with stack");
    assert!(daemon.flame_count >= 3, "Nœuds de l'arbre d'appels créés");
    kprintln!("[PROFILER/FLAME] Déroulement de pile et agrégation de nœuds Flamegraph validés");

    // 4. Analyse de distribution de latence (p50, p90, p99, p99.9)
    for lat in [120, 140, 160, 180, 200, 220, 250, 300, 450, 800] {
        daemon
            .record_latency(&admin_cap, LatencyCategory::ContextSwitch, lat, 42, 1010)
            .expect("record latency");
    }
    let cs_stats = daemon.calculate_latency_stats(Some(LatencyCategory::ContextSwitch));
    assert!(cs_stats.count >= 10);
    assert!(cs_stats.min_ns <= 120);
    assert!(cs_stats.p50_ns >= 150 && cs_stats.p50_ns <= 300);
    assert!(cs_stats.p99_ns >= 450);
    kprintln!("[PROFILER/LATENCY] Calculs de percentiles p50/p90/p99 de latence validés");

    // 5. Scellement cryptographique SHA-256 du rapport de profilage et vérification d'intégrité
    let rep_id = daemon
        .generate_report(&admin_cap, 42, 5_000_000, 1020)
        .expect("generate report");
    let seal_valid = daemon
        .verify_report_seal(&admin_cap, rep_id)
        .expect("verify seal");
    assert!(seal_valid, "Sceau SHA-256 du rapport de profilage valide");

    // Détection de falsification
    let rep_idx = daemon
        .reports
        .iter()
        .position(|r| {
            r.as_ref()
                .map(|rep| rep.report_id == rep_id)
                .unwrap_or(false)
        })
        .unwrap();
    daemon.reports[rep_idx].as_mut().unwrap().pmc.cycles ^= 0xCAFE;
    let seal_tampered = daemon
        .verify_report_seal(&admin_cap, rep_id)
        .expect("verify tampered");
    assert!(
        !seal_tampered,
        "Détection immédiate d'altération de métriques dans le rapport"
    );
    kprintln!("[PROFILER/CRYPTO] Scellement SHA-256 et détection de falsification validés");

    // 6. Validation des commandes du Shell interactif JamboShell
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 4096];

    // Commande : profiler status
    let (st_status, len_status) = shell.execute_line("profiler status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("OBSERVABILITÉ & PROFILAGE MATÉRIEL"));
    assert!(out_str_status.contains("Échantillons Capturés"));
    kprintln!("[PROFILER/SHELL] Commande 'profiler status' validée");

    // Commande : profiler pmc
    let (st_pmc, len_pmc) = shell.execute_line("profiler pmc", &mut out_buf);
    assert_eq!(st_pmc, ShellStatus::Success);
    let out_str_pmc = core::str::from_utf8(&out_buf[..len_pmc]).unwrap();
    assert!(out_str_pmc.contains("COMPTEURS DE PERFORMANCE MATÉRIELLE"));
    assert!(out_str_pmc.contains("Instructions Retirées"));
    assert!(out_str_pmc.contains("IPC"));
    kprintln!("[PROFILER/SHELL] Commande 'profiler pmc' validée");

    // Commande : profiler sample
    let (st_samp, len_samp) = shell.execute_line("profiler sample", &mut out_buf);
    assert_eq!(st_samp, ShellStatus::Success);
    let out_str_samp = core::str::from_utf8(&out_buf[..len_samp]).unwrap();
    assert!(out_str_samp.contains("échantillon matériel capturé avec succès"));
    kprintln!("[PROFILER/SHELL] Commande 'profiler sample' validée");

    // Commande : profiler flame
    let (st_flame, len_flame) = shell.execute_line("profiler flame", &mut out_buf);
    assert_eq!(st_flame, ShellStatus::Success);
    let out_str_flame = core::str::from_utf8(&out_buf[..len_flame]).unwrap();
    assert!(out_str_flame.contains("PROFILS DE FLAMMES & ARBRE D'APPELS"));
    assert!(out_str_flame.contains("Profondeur"));
    kprintln!("[PROFILER/SHELL] Commande 'profiler flame' validée");

    // Commande : profiler latency
    let (st_lat, len_lat) = shell.execute_line("profiler latency", &mut out_buf);
    assert_eq!(st_lat, ShellStatus::Success);
    let out_str_lat = core::str::from_utf8(&out_buf[..len_lat]).unwrap();
    assert!(out_str_lat.contains("ANALYSE DE LATENCE SYSTÈME"));
    assert!(out_str_lat.contains("SyscallDispatch"));
    assert!(out_str_lat.contains("ContextSwitch"));
    kprintln!("[PROFILER/SHELL] Commande 'profiler latency' validée");

    // Commande : profiler report
    let (st_rep, len_rep) = shell.execute_line("profiler report", &mut out_buf);
    assert_eq!(st_rep, ShellStatus::Success);
    let out_str_rep = core::str::from_utf8(&out_buf[..len_rep]).unwrap();
    assert!(out_str_rep.contains("RAPPORT DE PROFILAGE DE PERFORMANCE RING 3"));
    assert!(out_str_rep.contains("Sceau SHA-256"));
    kprintln!("[PROFILER/SHELL] Commande 'profiler report' validée");

    // Commande : profiler verify 1
    let (st_ver, len_ver) = shell.execute_line("profiler verify 1", &mut out_buf);
    assert_eq!(st_ver, ShellStatus::Success);
    let out_str_ver = core::str::from_utf8(&out_buf[..len_ver]).unwrap();
    assert!(out_str_ver.contains("[VALIDE / INTÈGRE]"));
    kprintln!("[PROFILER/SHELL] Commande 'profiler verify' validée");

    // Commande : profiler digest
    let (st_dig, len_dig) = shell.execute_line("profiler digest", &mut out_buf);
    assert_eq!(st_dig, ShellStatus::Success);
    let out_str_dig = core::str::from_utf8(&out_buf[..len_dig]).unwrap();
    assert!(out_str_dig.contains("Condensat SHA-256 d'Audit Profilage"));
    kprintln!("[PROFILER/SHELL] Commande 'profiler digest' validée");

    kprintln!(
        "\x1b[1;32m[PROFILER/PASS] Suite de tests Échantillonnage PMC/PEBS, Flamegraphs & Latence validée avec succès !\x1b[0m"
    );
    true
}

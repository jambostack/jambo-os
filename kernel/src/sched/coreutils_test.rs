//! Module de test et validation des Pipelines d'Objets Structurés & Utilitaires Confinés (Phase 45 - v0.2.43)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{cap_rights, Handle, SysError};
use jambo_sh::{
    ArgumentCapability, CmdCapStat, CmdCat, CmdFilter, CmdJpkg, CmdPs, CmdTop, JamboShell,
    ObjectRecord, ShellStatus, StructuredPipeline,
};

/// Exécute la suite de tests des pipelines d'objets structurés et utilitaires jambo-coreutils (Phase 45)
pub fn execute_coreutils_pipeline_test() -> bool {
    kprintln!("[COREUTILS/TEST] Démarrage du test des pipelines d'objets structurés & utilitaires confinés (Phase 45)...");

    // 1. Validation de CmdPs et du flux d'objets Process
    let processes = CmdPs::list_processes();
    assert_eq!(processes.len(), 6);
    assert_eq!(processes[0].name, "jambo-init");
    assert_eq!(processes[0].cap_count, 14);

    let pipe = CmdPs::pipeline();
    assert_eq!(pipe.count(), 6);
    kprintln!(
        "[COREUTILS/PS] Pipeline structuré de processus initialisé (6 enregistrements typés)"
    );

    // 2. Validation du filtrage d'objets (CmdFilter)
    let filtered_caps = CmdFilter::filter_by_min_caps(&pipe, 8);
    assert_eq!(filtered_caps.count(), 3); // jambo-init (14), pcie-bus-mgr (8), jambo-netd (12)
    kprintln!("[COREUTILS/FILTER] Filtre '--min-caps 8' validé (3/6 processus retenus)");

    let filtered_mem = CmdFilter::filter_by_min_memory(&pipe, 32);
    assert_eq!(filtered_mem.count(), 4); // jambo-init (32), nvme-drv (64), xhci-drv (32), jambo-netd (128)
    kprintln!("[COREUTILS/FILTER] Filtre '--min-mem 32' validé (4/6 processus retenus)");

    let filtered_prefix = CmdFilter::filter_by_prefix(&pipe, "jambo");
    assert_eq!(filtered_prefix.count(), 3); // jambo-init, jambo-netd, jambo-sh
    kprintln!("[COREUTILS/FILTER] Filtre '--prefix jambo' validé (3/6 processus retenus)");

    // 3. Validation de CmdCapStat et inspection de CSpace
    let caps_res = CmdCapStat::inspect_cspace(1);
    assert!(caps_res.is_ok());
    let caps = caps_res.unwrap();
    assert_eq!(caps.len(), 4);
    assert_eq!(caps[0].object_type, "VMO (CoW Heap)");
    assert_eq!(caps[3].object_type, "NetCap (HTTPS/DoT)");
    kprintln!(
        "[COREUTILS/CAPSTAT] Inspection de la CSpace du PID 1 validée (4 capacités identifiées)"
    );

    // 4. Validation de CmdTop (Métriques ordonnanceur et PMM)
    let (cpu, free_pages, slub) = CmdTop::system_metrics();
    assert_eq!(cpu, 3);
    assert!(free_pages > 500_000);
    assert_eq!(slub, 4);
    kprintln!(
        "[COREUTILS/TOP] Métriques système temps-réel capturées (CPU 3%, PMM libre > 500k pgs)"
    );

    // 5. Validation de CmdJpkg (Intégrité cryptographique BLAKE3)
    let blake3_hash = [0x5au8; 32];
    assert!(CmdJpkg::verify_package_integrity(
        "system.jpkg",
        &blake3_hash
    ));
    assert!(!CmdJpkg::verify_package_integrity("", &blake3_hash));
    kprintln!("[COREUTILS/JPKG] Vérification d'intégrité BLAKE3 de paquet immuable validée");

    // 6. Validation de CmdCat avec confinement par capacité
    let valid_cap = ArgumentCapability {
        target_resource_id: 101,
        granted_handle: Handle::new(51, 1),
        rights: cap_rights::READ,
    };
    let test_bytes = b"DonneesConfineesJamboOS";
    assert_eq!(
        CmdCat::read_confined(&valid_cap, test_bytes),
        Ok(&test_bytes[..])
    );

    let invalid_cap = ArgumentCapability {
        target_resource_id: 101,
        granted_handle: Handle::new(51, 1),
        rights: 0, // Zéro droit READ
    };
    assert_eq!(
        CmdCat::read_confined(&invalid_cap, test_bytes),
        Err(SysError::PermissionDenied)
    );
    kprintln!("[COREUTILS/CAT] Confinement zéro-autorité validé (Rejet strict sans droit READ)");

    // 7. Test d'exécution interactif dans JamboShell avec pipelines réels
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Pipeline: ps | filter --min-caps 8
    let (st_pipe, len_pipe) = shell.execute_line("ps | filter --min-caps 8", &mut out_buf);
    assert_eq!(st_pipe, ShellStatus::Success);
    let str_pipe = core::str::from_utf8(&out_buf[..len_pipe]).unwrap_or("");
    assert!(str_pipe.contains("jambo-init") && str_pipe.contains("jambo-netd"));
    assert!(!str_pipe.contains("jambo-sh")); // cap_count = 5 < 8
    kprintln!("[COREUTILS/SHELL] Pipeline 'ps | filter --min-caps 8' exécuté avec succès");

    // Commande: capstat 1
    let (st_cap, len_cap) = shell.execute_line("capstat 1", &mut out_buf);
    assert_eq!(st_cap, ShellStatus::Success);
    let str_cap = core::str::from_utf8(&out_buf[..len_cap]).unwrap_or("");
    assert!(str_cap.contains("VMO (CoW Heap)") && str_cap.contains("NetCap"));
    kprintln!("[COREUTILS/SHELL] Commande 'capstat 1' validée");

    // Commande: top
    let (st_top, len_top) = shell.execute_line("top", &mut out_buf);
    assert_eq!(st_top, ShellStatus::Success);
    let str_top = core::str::from_utf8(&out_buf[..len_top]).unwrap_or("");
    assert!(str_top.contains("Utilisation CPU") && str_top.contains("PMM Pages Libres"));
    kprintln!("[COREUTILS/SHELL] Commande 'top' validée");

    // Commande: jpkg verify system.jpkg
    let (st_jpkg, len_jpkg) = shell.execute_line("jpkg verify system.jpkg", &mut out_buf);
    assert_eq!(st_jpkg, ShellStatus::Success);
    let str_jpkg = core::str::from_utf8(&out_buf[..len_jpkg]).unwrap_or("");
    assert!(str_jpkg.contains("INTÈGRE & VALIDÉ"));
    kprintln!("[COREUTILS/SHELL] Commande 'jpkg verify' validée");

    kprintln!(
        "[COREUTILS/PASS] Pipelines d'objets structurés & utilitaires jambo-coreutils validés."
    );
    true
}

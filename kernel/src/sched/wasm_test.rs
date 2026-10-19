//! Module de validation du Moteur WebAssembly Sandboxed & WasmCap (Phase 73 - v0.2.71)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_wasm::{
    wasm_rights, WasmCap, WasmEngine, WasmInstance, WasmLinearMemory, SAMPLE_ADD_WASM,
    SAMPLE_GAS_WASM, SAMPLE_MEM_WASM, SAMPLE_OOB_WASM,
};

/// Exécute la suite de tests du moteur WebAssembly sandboxed et WasmCap (Phase 73)
pub fn execute_wasm_runtime_test() -> bool {
    kprintln!(
        "[WASM/TEST] Démarrage du test du moteur WebAssembly sandboxed et WasmCap (Phase 73)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (WasmCap) et atténuation
    let admin_cap = WasmCap::new(Handle::new(73, 1), wasm_rights::ALL, 16, 1_000_000);
    assert!(admin_cap.has_right(wasm_rights::WASM_EXEC));
    assert!(admin_cap.has_right(wasm_rights::WASM_MEM_GROW));
    assert!(admin_cap.has_right(wasm_rights::WASM_WASI_IO));
    assert!(admin_cap.has_right(wasm_rights::WASM_WASI_TIME));
    assert!(admin_cap.has_right(wasm_rights::WASM_INSTANTIATE));
    assert!(admin_cap.has_right(wasm_rights::WASM_ADMIN));

    let status_cap = admin_cap
        .attenuate(wasm_rights::WASM_WASI_TIME, 1, 10_000)
        .expect("attenuate WasmCap to status/time only");
    assert!(!status_cap.has_right(wasm_rights::WASM_EXEC));
    assert!(!status_cap.has_right(wasm_rights::WASM_INSTANTIATE));

    let mut engine = WasmEngine::new();
    assert_eq!(
        engine.load_module_with_cap(&status_cap, SAMPLE_ADD_WASM).err(),
        Some(SysError::PermissionDenied),
        "Instanciation sans droit WASM_INSTANTIATE doit être rejetée"
    );

    // Tentative d'escalade de privilège interdite
    assert_eq!(
        status_cap.attenuate(wasm_rights::WASM_EXEC, 1, 10_000),
        Err(SysError::PermissionDenied),
        "Amplification de droits interdite"
    );
    assert_eq!(
        status_cap.attenuate(wasm_rights::WASM_WASI_TIME, 2, 10_000),
        Err(SysError::PermissionDenied),
        "Augmentation de quota mémoire interdite"
    );
    kprintln!("[WASM/CAP] Confinement capabilaire WasmCap et atténuation stricte validés");

    // 2. Parsing et validation des sections Wasm binaires
    let mut add_instance = engine
        .load_module_with_cap(&admin_cap, SAMPLE_ADD_WASM)
        .expect("charger module add valide");
    assert_eq!(add_instance.exports_count, 1);
    assert_eq!(add_instance.exports[0].name(), "add");
    assert_eq!(add_instance.func_count, 1);

    let corrupt_wasm = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00];
    assert_eq!(
        engine.load_module_with_cap(&admin_cap, &corrupt_wasm).err(),
        Some(SysError::InvalidArgument),
        "Module binaire invalide doit être rejeté"
    );
    kprintln!("[WASM/PARSE] Parsing des sections binaires (Type, Export, Code) validé");

    // 3. Exécution sur la Stack Machine Wasm
    let sum = engine
        .invoke_export_with_cap(&admin_cap, &mut add_instance, "add", &[15, 27])
        .expect("exécuter export add");
    assert_eq!(sum, 42);
    assert!(engine.gas_consumed > 0);
    kprintln!("[WASM/STACK] Machine à pile Wasm et exécution arithmétique (15 + 27 = 42) validées");

    // 4. Mémoire linéaire sandboxed et isolation
    let mut mem_instance = engine
        .load_module_with_cap(&admin_cap, SAMPLE_MEM_WASM)
        .expect("charger module mem valide");
    let mem_result = engine
        .invoke_export_with_cap(&admin_cap, &mut mem_instance, "mem_test", &[32])
        .expect("exécuter export mem_test");
    assert_eq!(mem_result, 42); // 32 stocké, relu, + 10 = 42

    let mut mem = WasmLinearMemory::new(1);
    assert!(mem.write_memory(0, b"jambo-kernel-wasm").is_ok());
    assert_eq!(mem.read_memory(0, 17).unwrap(), b"jambo-kernel-wasm");
    assert_eq!(
        mem.write_memory(4090, b"too large for memory page"),
        Err(SysError::BadAddress)
    );

    let grow_res = mem.grow(&admin_cap, 1);
    assert!(grow_res.is_ok());
    assert_eq!(mem.pages, 2);

    let no_grow_cap = admin_cap
        .attenuate(wasm_rights::WASM_EXEC, 1, 10_000)
        .unwrap();
    assert_eq!(
        mem.grow(&no_grow_cap, 1),
        Err(SysError::PermissionDenied),
        "Agrandissement sans droit WASM_MEM_GROW doit échouer"
    );
    kprintln!("[WASM/MEM] Mémoire linéaire isolée, opérations store/load et grow validés");

    // 5. Détection des pièges matériels et logiciels (Traps)
    let mut oob_instance = engine
        .load_module_with_cap(&admin_cap, SAMPLE_OOB_WASM)
        .expect("charger module oob");
    let trap_oob = engine.invoke_export_with_cap(&admin_cap, &mut oob_instance, "oob_test", &[]);
    assert_eq!(
        trap_oob,
        Err(SysError::BadAddress),
        "Débordement mémoire doit lever un trap BadAddress"
    );

    let low_gas_cap = WasmCap::new(Handle::new(73, 2), wasm_rights::ALL, 1, 50);
    let mut gas_instance = engine
        .load_module_with_cap(&low_gas_cap, SAMPLE_GAS_WASM)
        .expect("charger module gas");
    let trap_gas = engine.invoke_export_with_cap(&low_gas_cap, &mut gas_instance, "gas_test", &[]);
    assert_eq!(
        trap_gas,
        Err(SysError::ResourceBusy),
        "Épuisement de gaz doit interrompre la boucle infinie"
    );
    kprintln!("[WASM/TRAPS] Traps Out-Of-Bounds et épuisement de gaz interceptés sans panique noyau");

    // 6. WASI Preview 1 avec confinement capabilaire
    let wasi_inst = WasmLinearMemory::new(1);
    let _ = wasi_inst;
    assert_eq!(
        add_instance
            .wasi_fd_write_with_cap(&admin_cap, 1, b"hello from wasi")
            .unwrap(),
        15
    );
    assert_eq!(
        add_instance.wasi_fd_write_with_cap(&status_cap, 1, b"hello"),
        Err(SysError::PermissionDenied)
    );
    assert!(add_instance.wasi_clock_time_get_with_cap(&admin_cap, 0).unwrap() > 0);
    assert_eq!(
        add_instance.wasi_clock_time_get_with_cap(&no_grow_cap, 0),
        Err(SysError::PermissionDenied)
    );
    kprintln!("[WASM/WASI] Shims WASI Preview 1 (fd_write, clock_time_get) et permissions validés");

    // 7. Intégration shell interactive (wasm status, wasm run, wasm test)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // wasm status
    let (st_status, len_status) = shell.execute_line("wasm status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap_or("");
    assert!(str_status.contains("MOTEUR WEBASSEMBLY SANDBOXÉ"));
    assert!(str_status.contains("WasmCap"));
    assert!(str_status.contains("WASI Sandboxed Runtime"));
    kprintln!("[WASM/SHELL] Commande 'wasm status' validée");

    // wasm run add.wasm
    let (st_run, len_run) = shell.execute_line("wasm run add.wasm", &mut out_buf);
    assert_eq!(st_run, ShellStatus::Success);
    let str_run = core::str::from_utf8(&out_buf[..len_run]).unwrap_or("");
    assert!(str_run.contains("add.wasm"));
    assert!(str_run.contains("code 42"));
    kprintln!("[WASM/SHELL] Commande 'wasm run add.wasm' validée (code 42)");

    // wasm test
    let (st_test, len_test) = shell.execute_line("wasm test", &mut out_buf);
    assert_eq!(st_test, ShellStatus::Success);
    let str_test = core::str::from_utf8(&out_buf[..len_test]).unwrap_or("");
    assert!(str_test.contains("[WASM/TEST]"));
    assert!(str_test.contains("add=42"));
    assert!(str_test.contains("mem=42"));
    kprintln!("[WASM/SHELL] Commande 'wasm test' validée");

    kprintln!("[WASM/PASS] Suite de tests Moteur WebAssembly sandboxed complétée avec succès !");
    true
}

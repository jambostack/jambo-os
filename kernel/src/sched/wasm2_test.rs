//! Module de validation du Moteur de Composants WebAssembly & Interfaces de Capacités Ring 3 (`jambo-wasm2`)
//! Phase 104 — Jalon v0.2.102
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_wasm2::{
    wasm2_rights, CanonAbi, ComponentError, InstanceStatus, JamboWasm2Daemon, ResourceTable,
    Wasm2Cap, WitValType, WitValue, WASM_COMPONENT_VERSION, WASM_MAGIC,
};

/// Exécute la suite complète de validation formelle du Wasm Component Model (Phase 104)
pub fn execute_wasm2_daemon_test() -> bool {
    kprintln!(
        "[WASM2/TEST] Démarrage du test de validation du Wasm Component Model & Interfaces Ring 3 (Phase 104)..."
    );

    // 1. Contrôle d'accès capabilaire (Wasm2Cap) et rejet formel de toute élévation de privilèges
    let admin_cap = Wasm2Cap::new(Handle::new(10401, 1), wasm2_rights::ALL, 8, 500_000);
    assert!(admin_cap.has_right(wasm2_rights::INSTANTIATE));
    assert!(admin_cap.has_right(wasm2_rights::INVOKE));
    assert!(admin_cap.has_right(wasm2_rights::LINK));
    assert!(admin_cap.has_right(wasm2_rights::RESOURCE_MANAGE));
    assert!(admin_cap.has_right(wasm2_rights::UPGRADE));
    assert!(admin_cap.has_right(wasm2_rights::AUDIT));
    assert!(admin_cap.has_right(wasm2_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(wasm2_rights::INSTANTIATE | wasm2_rights::INVOKE, 4, 100_000)
        .expect("Atténuation monotone Wasm2Cap");
    assert!(attenuated_cap.has_right(wasm2_rights::INSTANTIATE));
    assert!(attenuated_cap.has_right(wasm2_rights::INVOKE));
    assert!(!attenuated_cap.has_right(wasm2_rights::LINK));
    assert!(!attenuated_cap.has_right(wasm2_rights::ADMIN));
    assert_eq!(attenuated_cap.max_instances, 4);
    assert_eq!(attenuated_cap.max_fuel, 100_000);

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        attenuated_cap.attenuate(wasm2_rights::ALL, 4, 100_000),
        Err(SysError::PermissionDenied),
        "Amplification de droits Wasm2Cap formellement rejetée"
    );
    assert_eq!(
        attenuated_cap.attenuate(wasm2_rights::INSTANTIATE, 8, 100_000),
        Err(SysError::PermissionDenied),
        "Augmentation d'instances maximales formellement rejetée"
    );
    kprintln!("[WASM2/CAP] Contrôle d'accès capabilaire Wasm2Cap et atténuation monotone validés");

    // 2. Vérification de l'en-tête binaire Component Model
    let valid_header = [0x00, 0x61, 0x73, 0x6D, 0x0d, 0x00, 0x01, 0x00];
    assert_eq!(JamboWasm2Daemon::validate_header(&valid_header), Ok(()));
    let corrupted_magic = [0xFF, 0x61, 0x73, 0x6D, 0x0d, 0x00, 0x01, 0x00];
    assert_eq!(
        JamboWasm2Daemon::validate_header(&corrupted_magic),
        Err(ComponentError::InvalidMagic)
    );
    let legacy_module_header = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    assert_eq!(
        JamboWasm2Daemon::validate_header(&legacy_module_header),
        Err(ComponentError::InvalidVersion)
    );
    kprintln!("[WASM2/HEADER] Validation de la spécification binaire Component Model validée");

    // 3. Validation de la Canonical ABI (canon lift & lower)
    let mut mem_arena = [0u8; 256];
    CanonAbi::lower_u32(0xCAFEBABE, &mut mem_arena, 0).expect("Lower u32");
    let lifted_u32 = CanonAbi::lift_u32(&mem_arena, 0).expect("Lift u32");
    assert_eq!(lifted_u32, 0xCAFEBABE);

    let test_msg = "JamboOS Component Model Canonical ABI Sovereign String";
    CanonAbi::lower_string(test_msg, &mut mem_arena, 8, 64).expect("Lower string");
    let lifted_str = CanonAbi::lift_string(&mem_arena, 8).expect("Lift string");
    assert_eq!(lifted_str, test_msg);

    let test_fields = [100, 200, 300, 400];
    let written = CanonAbi::lower_record(&test_fields, &mut mem_arena, 128).expect("Lower record");
    assert_eq!(written, 16);
    let mut read_fields = [0u32; 4];
    CanonAbi::lift_record(&mem_arena, 128, 4, &mut read_fields).expect("Lift record");
    assert_eq!(read_fields, test_fields);

    // Vérification des bornes mémoire (OutOfBounds trap)
    assert_eq!(
        CanonAbi::lower_u32(1, &mut mem_arena, 254),
        Err(ComponentError::MemoryOutOfBounds)
    );
    kprintln!(
        "[WASM2/CABI] Canonical ABI lift/lower (u32, string, record) et bornes mémoire validés"
    );

    // 4. Gestion du cycle de vie des ressources (ResourceTable, borrow, drop, double-free)
    let mut res_table = ResourceTable::new();
    let res_h = res_table.allocate(42, 1).expect("Allocation ressource #1");
    assert!(res_table.is_valid(res_h));
    assert!(res_table.borrow(res_h, 1).is_ok());

    // Tentative de libération par une instance non autorisée
    assert_eq!(
        res_table.drop_resource(res_h, 2),
        Err(ComponentError::ResourceAccessDenied)
    );
    // Libération par le propriétaire légitime
    assert!(res_table.drop_resource(res_h, 1).is_ok());
    assert!(!res_table.is_valid(res_h));
    // Détection immédiate du double-free
    assert_eq!(
        res_table.drop_resource(res_h, 1),
        Err(ComponentError::ResourceAlreadyFree)
    );
    kprintln!("[WASM2/RES] Cycle de vie des ressources, propriété et rejet de double-free validés");

    // 5. Initialisation du Démon et des composants standards
    let mut daemon = JamboWasm2Daemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.component_count, 3);
    assert_eq!(daemon.instance_count, 0);
    assert_eq!(daemon.link_count, 0);

    // Instanciation sandboxed de 2 composants
    let inst_hasher = daemon
        .instantiate(&admin_cap, 1, 80_000)
        .expect("Instanciation Hasher");
    let inst_validator = daemon
        .instantiate(&admin_cap, 2, 80_000)
        .expect("Instanciation Validator");
    assert_eq!(daemon.instance_count, 2);
    assert_eq!(daemon.instances[0].status, InstanceStatus::Ready);
    assert_eq!(daemon.instances[1].status, InstanceStatus::Ready);
    kprintln!("[WASM2/INIT] Démon initialisé et composants instanciés dans leurs bacs à sable");

    // 6. Invocation directe et passage par Canonical ABI
    let hash_res = daemon
        .invoke_export(
            &admin_cap,
            inst_hasher,
            "hash_block",
            WitValue::from_str("JamboBlockDataPayload"),
        )
        .expect("Invocation hash_block");
    match hash_res {
        WitValue::U32(val) => assert!(val > 0),
        _ => panic!("Type de retour invalide"),
    }
    assert!(daemon.instances[0].fuel_consumed >= 1500);

    // Allocation d'une ressource via appel de composant
    let res_call = daemon
        .invoke_export(
            &admin_cap,
            inst_hasher,
            "create_hasher_res",
            WitValue::U32(10),
        )
        .expect("Allocation HasherResource");
    match res_call {
        WitValue::Resource(id) => assert!(daemon.resource_table.is_valid(id)),
        _ => panic!("Type de ressource attendu"),
    }
    kprintln!("[WASM2/INVOKE] Invocation de fonction exportée et allocation de ressource validées");

    // 7. Composition et liaison inter-composants (Component Linking sans mémoire partagée)
    let link_id = daemon
        .link_components(
            &admin_cap,
            inst_validator,
            "hasher_dep",
            inst_hasher,
            "hash_block",
        )
        .expect("Liaison inter-composants Hasher -> Validator");
    assert_eq!(link_id, 1);
    assert_eq!(daemon.link_count, 1);

    // Invocation inter-composants : Validator appelle Hasher via son import lié
    let inter_res = daemon
        .invoke_inter_component(
            &admin_cap,
            inst_validator,
            "hasher_dep",
            WitValue::from_str("CrossSandboxData"),
        )
        .expect("Appel inter-composants via interface liée");
    match inter_res {
        WitValue::U32(v) => assert!(v > 0),
        _ => panic!("Type de retour inter-composant attendu"),
    }
    kprintln!("[WASM2/LINK] Liaison inter-composants et appel inter-sandbox sans mémoire partagée validés");

    // 8. Contrôle du carburant (Fuel Metering) et interception du trap d'épuisement
    let starved_inst = daemon
        .instantiate(&admin_cap, 1, 1000)
        .expect("Instanciation à faible quota de carburant");
    let starve_res = daemon.invoke_export(
        &admin_cap,
        starved_inst,
        "hash_block",
        WitValue::from_str("PayloadExceedingFuelQuota"),
    );
    assert_eq!(starve_res, Err(ComponentError::FuelExhausted));
    assert_eq!(daemon.total_traps, 1);
    kprintln!(
        "[WASM2/FUEL] Épuisement de carburant intercepté de façon sécurisée (FuelExhausted trap)"
    );

    // 9. Chaîne d'audit inviolable scellée par SHA-256
    let audit_chain = daemon.get_audit_chain(&admin_cap).expect("Lecture audit");
    assert_ne!(audit_chain, [0u8; 32]);
    assert!(daemon.audit_count >= 5);
    kprintln!("[WASM2/AUDIT] Chaîne d'audit cryptographique SHA-256 validée");

    // 10. Validation des commandes Shell Ring 3 (`jambo-sh`)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (s1, l1) = shell.execute_line("wasm2 status", &mut out);
    assert_eq!(s1, ShellStatus::Success);
    let out_str1 = core::str::from_utf8(&out[..l1]).unwrap_or("");
    assert!(out_str1.contains("MOTEUR DE COMPOSANTS WASM"));

    let (s2, l2) = shell.execute_line("wasm2 list", &mut out);
    assert_eq!(s2, ShellStatus::Success);
    let out_str2 = core::str::from_utf8(&out[..l2]).unwrap_or("");
    assert!(out_str2.contains("jambo:crypto/hasher"));

    let (s3, l3) = shell.execute_line("wasm2 run 1 hash_block", &mut out);
    assert_eq!(s3, ShellStatus::Success);
    let out_str3 = core::str::from_utf8(&out[..l3]).unwrap_or("");
    assert!(out_str3.contains("Succes de l'appel"));

    let (s4, l4) = shell.execute_line("wasm2 link", &mut out);
    assert_eq!(s4, ShellStatus::Success);
    let out_str4 = core::str::from_utf8(&out[..l4]).unwrap_or("");
    assert!(out_str4.contains("Liaison de composants reussie"));

    let (s5, l5) = shell.execute_line("wasm2 inspect 1", &mut out);
    assert_eq!(s5, ShellStatus::Success);
    let out_str5 = core::str::from_utf8(&out[..l5]).unwrap_or("");
    assert!(out_str5.contains("INSPECTION WIT"));

    let (s6, l6) = shell.execute_line("wasm2 fuel-check", &mut out);
    assert_eq!(s6, ShellStatus::Success);
    let out_str6 = core::str::from_utf8(&out[..l6]).unwrap_or("");
    assert!(out_str6.contains("INTERCEPTION REUSSIE"));

    let (s7, l7) = shell.execute_line("wasm2 audit", &mut out);
    assert_eq!(s7, ShellStatus::Success);
    let out_str7 = core::str::from_utf8(&out[..l7]).unwrap_or("");
    assert!(out_str7.contains("Condensat SHA-256 du Registre d'Audit"));

    kprintln!("[WASM2/SHELL] Commandes Shell Ring 3 `wasm2` (status, list, run, link, inspect, fuel-check, audit) validées");

    true
}

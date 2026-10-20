//! Module de validation formelle de la Gestion de la Surface d'Attaque Externe (EASM) (`jambo-easm`)
//! Phase 131 — Jalon v0.2.129
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_easm::{
    easm_rights, AssetType, AttackSurfaceSummary, DiscoveredAsset, EasmCap, EasmError,
    ExposureLevel, FindingCategory, FindingSeverity, FindingStatus, JamboEasmDaemon,
    PerimeterFinding,
};

/// Exécute la suite complète de validation formelle du démon EASM (Phase 131)
pub fn execute_easm_daemon_test() -> bool {
    kprintln!(
        "[EASM/TEST] Démarrage de la validation formelle de la gestion de la surface d'attaque externe EASM (Phase 131)..."
    );

    // 1. Contrôle d'accès capabilaire (EasmCap) et atténuation monotone
    let admin_cap = EasmCap::new(Handle::new(13101, 1), easm_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(easm_rights::DISCOVER_ASSETS));
    assert!(admin_cap.has_right(easm_rights::SCAN_PERIMETER));
    assert!(admin_cap.has_right(easm_rights::QUERY_SURFACE));
    assert!(admin_cap.has_right(easm_rights::MANAGE_ASSETS));
    assert!(admin_cap.has_right(easm_rights::REMEDIATE_EXPOSURE));
    assert!(admin_cap.has_right(easm_rights::EXPORT_INVENTORY));
    assert!(admin_cap.has_right(easm_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(easm_rights::ADMIN));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            easm_rights::QUERY_SURFACE | easm_rights::SCAN_PERIMETER,
            5000,
            200,
        )
        .expect("Atténuation monotone EasmCap");
    assert!(monitor_cap.has_right(easm_rights::QUERY_SURFACE));
    assert!(monitor_cap.has_right(easm_rights::SCAN_PERIMETER));
    assert!(!monitor_cap.has_right(easm_rights::MANAGE_ASSETS));
    assert!(!monitor_cap.has_right(easm_rights::REMEDIATE_EXPOSURE));
    assert!(!monitor_cap.has_right(easm_rights::ADMIN));
    assert_eq!(monitor_cap.max_lifetime, 5000);
    assert_eq!(monitor_cap.invocations_left, 200);

    // Rejet d'escalade
    assert_eq!(
        monitor_cap.attenuate(easm_rights::ALL, 5000, 200),
        Err(EasmError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et scénario de référence
    let mut easm = JamboEasmDaemon::new(admin_cap);
    easm.init_defaults();
    assert_eq!(easm.asset_count, 5);
    assert_eq!(easm.finding_count, 4);
    assert!(easm.verify_ledger_integrity());

    // 3. Scan continu du périmètre et détection de Shadow IT
    let scan_res = easm
        .scan_perimeter(&admin_cap, 5000)
        .expect("Scan du périmètre externe");
    assert_eq!(scan_res.total_assets, 5);
    assert_eq!(scan_res.shadow_it_count, 1);
    assert_eq!(scan_res.open_findings_count, 4);
    assert_eq!(scan_res.critical_findings_count, 1);
    assert!(scan_res.exposure_index > 50);

    // Rejet de gestion sans droits
    assert_eq!(
        easm.register_asset(
            &monitor_cap,
            "rogue",
            "rogue.jambo.net",
            AssetType::DomainName,
            ExposureLevel::PublicVulnerable,
            80,
            true,
            0,
            5010
        ),
        Err(EasmError::PermissionDenied)
    );

    // 4. Découverte dynamique d'un nouvel actif numérique
    let new_asset_id = easm
        .register_asset(
            &admin_cap,
            "partner-api",
            "api.partner.jambo.net",
            AssetType::DomainName,
            ExposureLevel::PublicHardened,
            443,
            false,
            365,
            5020,
        )
        .expect("Enregistrement nouvel actif");
    assert_eq!(new_asset_id, 6);
    assert_eq!(easm.asset_count, 6);

    // 5. Remédiation proactive et durcissement des vulnérabilités périmétriques
    let initial_index = easm.exposure_index;

    // Remédier l'interface d'administration exposée (#1 - Critique)
    easm.remediate_finding(&admin_cap, 1, 5100)
        .expect("Remédiation interface admin exposée");

    // Remédier le certificat TLS expiré (#2 - Élevée)
    easm.remediate_finding(&admin_cap, 2, 5105)
        .expect("Remédiation certificat expiré");

    // Rejet de remédiation par une capacité non autorisée
    assert_eq!(
        easm.remediate_finding(&monitor_cap, 3, 5110),
        Err(EasmError::PermissionDenied)
    );

    // Remédier le stockage public (#3 - Élevée)
    easm.remediate_finding(&admin_cap, 3, 5115)
        .expect("Remédiation stockage public");

    let post_remediation = easm
        .get_summary(&admin_cap)
        .expect("Résumé après remédiations");
    assert_eq!(post_remediation.critical_findings_count, 0);
    assert!(post_remediation.exposure_index < initial_index);

    // 6. Intégrité cryptographique SHA-256 du registre d'audit
    assert!(easm.verify_ledger_integrity());

    kprintln!(
        "[EASM/TEST] Validation réussie : 6 actifs recensés, Shadow IT détecté & remédié, indice d'exposition durci, registre SHA-256 intègre."
    );
    true
}

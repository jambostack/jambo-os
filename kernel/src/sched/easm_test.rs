//! Module de validation formelle de la Gestion Souveraine de la Surface d'Attaque Externe (EASM) (`jambo-easm`)
//! Phase 161 — Jalon v0.3.28
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_easm::{
    easm_rights, AssetType, AttackSurfaceSummary, DiscoveredAsset, DiscoveryMode, EasmCap,
    EasmError, EasmPerimeterReport, EasmRemediationReport, ExposureLevel, FindingCategory,
    FindingSeverity, FindingStatus, JamboEasmDaemon, PerimeterFinding,
};

/// Exécute la suite complète de validation formelle du démon EASM souverain (Phase 161 - v0.3.28)
pub fn execute_easm_daemon_test() -> bool {
    kprintln!(
        "[EASM/TEST] Démarrage de la validation formelle de la gestion souveraine de la surface d'attaque externe EASM (Phase 161 - v0.3.28)..."
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
    assert!(admin_cap.has_right(easm_rights::CORRELATE_INTEL));
    assert!(admin_cap.has_right(easm_rights::GENERATE_REPORT));
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
    assert!(!monitor_cap.has_right(easm_rights::CORRELATE_INTEL));
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
    assert_eq!(easm.asset_count, 6);
    assert_eq!(easm.finding_count, 5);
    assert!(easm.verify_ledger_integrity());

    // 3. Scan continu du périmètre et détection de Shadow IT
    let scan_res = easm
        .scan_perimeter(&admin_cap, 5000)
        .expect("Scan du périmètre externe");
    assert_eq!(scan_res.total_assets, 6);
    assert_eq!(scan_res.shadow_it_count, 1);
    assert_eq!(scan_res.open_findings_count, 5);
    assert_eq!(scan_res.critical_findings_count, 2);
    assert!(scan_res.exposure_index > 50);
    assert!(scan_res.perimeter_hardening_score < 50);

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
    assert_eq!(new_asset_id, 7);
    assert_eq!(easm.asset_count, 7);

    // 5. Corrélation Cyber Threat Intelligence (CTI - jambo-intel)
    let cti_fid = easm
        .correlate_cti(&admin_cap, 7, 88, 2, 5030)
        .expect("Corrélation CTI");
    assert!(cti_fid > 0);
    let asset7 = easm.assets[6].unwrap();
    assert!(asset7.is_flagged_by_cti);
    assert_eq!(asset7.intel_reputation_score, 88);

    // 6. Génération et scellement cryptographique d'un rapport de surface d'attaque SHA-256
    let report = easm
        .generate_perimeter_report(&admin_cap, DiscoveryMode::SecNumCloudAudit, 5040)
        .expect("Génération rapport EASM");
    assert_eq!(report.report_id, 1);
    assert_eq!(report.mode, DiscoveryMode::SecNumCloudAudit);
    assert_eq!(report.total_assets, 7);
    assert_eq!(report.shadow_it_count, 1);
    assert_ne!(report.report_hash, [0u8; 32]);

    let fetched_report = easm
        .get_perimeter_report(&admin_cap, 1)
        .expect("Consultation rapport");
    assert_eq!(fetched_report.report_hash, report.report_hash);

    // 7. Remédiation globale automatisée et durcissement O(1) de l'ensemble des risques
    let initial_index = easm.exposure_index;
    let rem_report = easm
        .remediate_all_findings(&admin_cap, 5100)
        .expect("Remédiation globale des expositions");
    assert!(rem_report.remediated_count >= 5);
    assert_ne!(rem_report.report_hash, [0u8; 32]);
    assert!(rem_report.new_exposure_index < initial_index);
    assert!(rem_report.perimeter_hardening_score >= 80);

    let post_remediation = easm
        .get_summary(&admin_cap)
        .expect("Résumé après remédiations");
    assert_eq!(post_remediation.open_findings_count, 0);
    assert_eq!(post_remediation.critical_findings_count, 0);
    assert_eq!(post_remediation.shadow_it_count, 0);
    assert!(post_remediation.exposure_index <= 20);
    assert!(post_remediation.perimeter_hardening_score >= 80);

    // 8. Intégrité cryptographique SHA-256 du registre d'audit
    assert!(easm.verify_ledger_integrity());

    kprintln!(
        "[EASM/TEST] \x1b[1;32mSuccès de la validation formelle EASM (Phase 161 - v0.3.28) : 7 actifs recensés, Shadow IT détecté & remédié, corrélation CTI validée, rapports scellés SHA-256, durcissement >= 80%, registre SHA-256 intègre.\x1b[0m"
    );
    true
}

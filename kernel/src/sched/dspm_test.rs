//! Module de validation formelle de la Gestion de la Posture de Sécurité des Données (DSPM) (`jambo-dspm`)
//! Phase 135 — Jalon v0.3.2
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_dspm::{
    dspm_rights, DataCategory, DataCompartment, DspmCap, DspmError, FlowAction,
    JamboDspmDaemon, SensitivityLevel, StorageLocationType, ViolationType,
};

/// Exécute la suite complète de validation formelle du démon DSPM (Phase 135)
pub fn execute_dspm_daemon_test() -> bool {
    kprintln!(
        "[DSPM/TEST] Démarrage de la validation formelle de la gestion de la posture des données DSPM (Phase 135)..."
    );

    // 1. Contrôle d'accès capabilaire (DspmCap) et atténuation monotone
    let mut admin_cap = DspmCap::new(Handle::new(13501, 1), dspm_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(dspm_rights::DISCOVER_DATA));
    assert!(admin_cap.has_right(dspm_rights::CLASSIFY_DATA));
    assert!(admin_cap.has_right(dspm_rights::MAP_DATA_FLOWS));
    assert!(admin_cap.has_right(dspm_rights::ENFORCE_POLICY));
    assert!(admin_cap.has_right(dspm_rights::QUARANTINE_DATA));
    assert!(admin_cap.has_right(dspm_rights::QUERY_AUDIT));
    assert!(admin_cap.has_right(dspm_rights::EXPORT_INVENTORY));
    assert!(admin_cap.has_right(dspm_rights::ADMIN));

    // Atténuation monotone
    let mut operator_cap = admin_cap
        .attenuate(
            dspm_rights::DISCOVER_DATA | dspm_rights::MAP_DATA_FLOWS | dspm_rights::QUERY_AUDIT,
            5000,
            200,
        )
        .expect("Atténuation monotone DspmCap");
    assert!(operator_cap.has_right(dspm_rights::DISCOVER_DATA));
    assert!(operator_cap.has_right(dspm_rights::MAP_DATA_FLOWS));
    assert!(operator_cap.has_right(dspm_rights::QUERY_AUDIT));
    assert!(!operator_cap.has_right(dspm_rights::ADMIN));
    assert!(!operator_cap.has_right(dspm_rights::QUARANTINE_DATA));
    assert_eq!(operator_cap.max_lifetime, 5000);
    assert_eq!(operator_cap.invocations_left, 200);

    // Rejet d'escalade illicite
    assert_eq!(
        operator_cap.attenuate(dspm_rights::ALL, 5000, 200),
        Err(DspmError::AttenuationViolation)
    );

    // 2. Initialisation du démon DSPM et politiques de flux souveraines
    let mut dspm = JamboDspmDaemon::new(admin_cap);
    dspm.init_defaults();

    assert_eq!(dspm.asset_count, 4);
    assert_eq!(dspm.flow_rule_count, 5);

    // 3. Découverte et enregistrement d'actifs de données
    let new_asset_id = dspm
        .register_asset(
            &mut admin_cap,
            "sovereign_tax_records",
            "vfs:///sec/finance/tax_2026.db",
            StorageLocationType::NvmeBlock,
            DataCompartment::SecFabric,
            SensitivityLevel::Secret,
            DataCategory::FinancialData,
            32768,
            [0x55; 32],
            105,
            true,
            7000,
        )
        .expect("Enregistrement actif financier chiffré");
    assert_eq!(new_asset_id, 5);
    assert_eq!(dspm.asset_count, 5);

    // 4. Détection automatique de données sensibles non chiffrées
    let shadow_id = dspm
        .register_asset(
            &mut admin_cap,
            "shadow_user_passwords",
            "vfs:///tmp/dump.txt",
            StorageLocationType::VfsMount,
            DataCompartment::UserWorkload,
            SensitivityLevel::Confidential,
            DataCategory::PII,
            1024,
            [0x66; 32],
            999,
            false, // Alerte : Non chiffré !
            7010,
        )
        .expect("Enregistrement actif non chiffré");
    assert_eq!(shadow_id, 6);
    assert!(dspm.violation_count > 0);

    // 5. Cartographie et blocage des flux illicites transfrontaliers
    // Actif Secret -> CrossBorderUntrusted : DOIT ÊTRE BLOQUÉ
    let blocked_flow = dspm
        .evaluate_flow(
            &mut operator_cap,
            new_asset_id,
            DataCompartment::CrossBorderUntrusted,
            8192,
            7020,
        )
        .expect("Évaluation de flux transfrontalier");
    assert!(!blocked_flow, "Le flux transfrontalier secret doit être bloqué");

    // Actif Public -> UserWorkload : DOIT ÊTRE AUTORISÉ
    let allowed_flow = dspm
        .evaluate_flow(
            &mut operator_cap,
            4, // workload_public_metrics
            DataCompartment::UserWorkload,
            1024,
            7030,
        )
        .expect("Évaluation de flux public interne");
    assert!(allowed_flow, "Le flux public interne doit être autorisé");

    // 6. Mise en quarantaine immédiate O(1) de l'actif non chiffré
    dspm.quarantine_asset(&mut admin_cap, shadow_id, 7040)
        .expect("Quarantaine de l'actif compromis");
    assert!(dspm.assets[5].unwrap().quarantined);

    // Tentative de flux depuis un actif en quarantaine : DOIT ÉCHOUER
    let q_flow = dspm
        .evaluate_flow(
            &mut operator_cap,
            shadow_id,
            DataCompartment::UserWorkload,
            256,
            7050,
        )
        .expect("Évaluation de flux depuis quarantaine");
    assert!(!q_flow, "Un actif en quarantaine ne peut émettre aucun flux");

    // 7. Balayage proactif d'inventaire
    let scanned = dspm
        .run_discovery_scan(&mut admin_cap, 7060)
        .expect("Balayage d'inventaire DSPM");
    assert_eq!(scanned, 6);

    // 8. Synthèse globale et intégrité du registre cryptographique SHA-256
    let summary = dspm.get_summary(&admin_cap).expect("Synthèse DSPM");
    assert_eq!(summary.total_assets, 6);
    assert_eq!(summary.quarantined_assets, 1);
    assert!(dspm.verify_ledger_integrity());

    kprintln!(
        "[DSPM/TEST] Validation réussie : 6 actifs cartographiés, flux transfrontaliers régulés, quarantaine O(1) validée, balayage proactif conforme, registre SHA-256 intègre."
    );
    true
}

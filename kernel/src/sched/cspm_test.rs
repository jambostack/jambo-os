//! Module de validation formelle de la Gestion de Posture CSPM, Détection de Dérive & Remédiation (`jambo-cspm`)
//! Phase 125 — Jalon v0.2.123
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_cspm::{
    cspm_rights, BaselineStandard, ComplianceStatus, ConfigItem, ConfigScope, CspmAuditAction,
    CspmCap, CspmError, CspmRule, DriftReport, JamboCspmDaemon, RuleSeverity,
};

/// Exécute la suite complète de validation formelle du démon CSPM (Phase 125)
pub fn execute_cspm_daemon_test() -> bool {
    kprintln!(
        "[CSPM/TEST] Démarrage de la validation de la gestion de posture CSPM & remédiation autonome (Phase 125)..."
    );

    // 1. Contrôle d'accès capabilaire (CspmCap) et atténuation monotone
    let admin_cap = CspmCap::new(Handle::new(12501, 1), cspm_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(cspm_rights::AUDIT_CONFIG));
    assert!(admin_cap.has_right(cspm_rights::SCAN_DRIFT));
    assert!(admin_cap.has_right(cspm_rights::REMEDIATE_DRIFT));
    assert!(admin_cap.has_right(cspm_rights::MANAGE_BASELINES));
    assert!(admin_cap.has_right(cspm_rights::CONFIGURE_RULES));
    assert!(admin_cap.has_right(cspm_rights::READ_METRICS));
    assert!(admin_cap.has_right(cspm_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(cspm_rights::ADMIN));

    // Atténuation monotone
    let auditor_cap = admin_cap
        .attenuate(
            cspm_rights::AUDIT_CONFIG | cspm_rights::SCAN_DRIFT | cspm_rights::READ_METRICS,
            5000,
            200,
        )
        .expect("Atténuation monotone CspmCap");
    assert!(auditor_cap.has_right(cspm_rights::SCAN_DRIFT));
    assert!(auditor_cap.has_right(cspm_rights::READ_METRICS));
    assert!(!auditor_cap.has_right(cspm_rights::REMEDIATE_DRIFT));
    assert!(!auditor_cap.has_right(cspm_rights::ADMIN));
    assert_eq!(auditor_cap.max_lifetime, 5000);
    assert_eq!(auditor_cap.invocations_left, 200);

    // Rejet d'escalade
    assert_eq!(
        auditor_cap.attenuate(cspm_rights::ALL, 5000, 200),
        Err(CspmError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et baselines durcies souveraines
    let mut cspm = JamboCspmDaemon::new(admin_cap);
    cspm.init_defaults();
    assert_eq!(cspm.rule_count, 8);
    assert_eq!(cspm.item_count, 8);
    assert_eq!(cspm.total_scans, 0);
    assert!(cspm.verify_ledger_integrity());
    assert_ne!(cspm.ledger_hash, JamboCspmDaemon::GENESIS_HASH);

    // 3. Détection de dérive (Drift Detection) et calcul d'indice de risque
    let (checked, drift_cnt, initial_posture, initial_risk) = cspm
        .scan_drift(&admin_cap, 1000)
        .expect("Scan CSPM initial");
    assert_eq!(checked, 8);
    assert_eq!(drift_cnt, 4);
    assert!(initial_posture <= 65);
    assert!(initial_risk >= 350);
    assert_eq!(cspm.total_drifts_detected, 4);
    assert_eq!(cspm.total_scans, 1);
    assert!(cspm.verify_ledger_integrity());

    // Vérification que les droits insuffisants rejettent la remédiation
    assert_eq!(
        cspm.remediate_drift(&auditor_cap, 102, 1500),
        Err(CspmError::PermissionDenied)
    );

    // 4. Remédiation autonome en temps réel (Auto-Remediation des règles souveraines)
    let auto_fixed = cspm
        .remediate_all_auto(&admin_cap, 2000)
        .expect("Remédiation autonome CSPM");
    assert_eq!(auto_fixed, 3);
    assert!(cspm.current_posture_score > initial_posture);
    assert!(cspm.current_risk_index < initial_risk);
    assert_eq!(cspm.drift_count, 1); // Seule la règle 108 (ZTNA) n'a pas auto_remediate

    // 5. Remédiation ciblée pour la règle 108 et rétablissement total de la posture
    let rem108 = cspm
        .remediate_drift(&admin_cap, 108, 3000)
        .expect("Remédiation ciblée ZTNA");
    assert!(rem108);

    // Rescan pour conformité 100%
    let (final_checked, final_drifts, final_posture, final_risk) = cspm
        .scan_drift(&admin_cap, 4000)
        .expect("Rescan CSPM post-remédiation");
    assert_eq!(final_checked, 8);
    assert_eq!(final_drifts, 0);
    assert_eq!(final_posture, 100);
    assert_eq!(final_risk, 0);
    assert_eq!(cspm.total_remediations, 4);

    // 6. Vérification cryptographique finale de la chaîne d'audit SHA-256
    assert!(cspm.verify_ledger_integrity());

    kprintln!(
        "[CSPM/TEST] Validation formelle réussie : 8 baselines durcies, détection de dérive (drift), remédiation autonome & ledger SHA-256 intègre."
    );
    true
}

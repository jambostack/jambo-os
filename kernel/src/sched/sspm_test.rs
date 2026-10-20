//! Module de validation formelle de la Gestion de la Posture de Sécurité des Services & SaaS (SSPM) (`jambo-sspm`)
//! Phase 136 — Jalon v0.3.3
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_sspm::{
    sspm_rights, ComplianceStandard, ConfigDriftEvent, DriftSeverity, DriftType,
    JamboSspmDaemon, PermissionScope, ServiceEnvironment, ServiceType, Sha256,
    SspmCap, SspmConnector, SspmError, SspmServiceAsset,
};

/// Exécute la suite complète de validation formelle du démon SSPM (Phase 136)
pub fn execute_sspm_daemon_test() -> bool {
    kprintln!(
        "[SSPM/TEST] Démarrage de la validation formelle de la posture de sécurité SaaS/Services (Phase 136)..."
    );

    // 1. Contrôle d'accès capabilaire (SspmCap) et atténuation monotone
    let mut admin_cap = SspmCap::new(Handle::new(13601, 1), sspm_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(sspm_rights::ASSESS_POSTURE));
    assert!(admin_cap.has_right(sspm_rights::SCAN_CONFIGS));
    assert!(admin_cap.has_right(sspm_rights::DETECT_DRIFT));
    assert!(admin_cap.has_right(sspm_rights::MANAGE_INTEGRATIONS));
    assert!(admin_cap.has_right(sspm_rights::REMEDIATE_DRIFT));
    assert!(admin_cap.has_right(sspm_rights::QUARANTINE_SERVICE));
    assert!(admin_cap.has_right(sspm_rights::QUERY_AUDIT));
    assert!(admin_cap.has_right(sspm_rights::ADMIN));

    // Atténuation monotone
    let audit_cap = admin_cap
        .attenuate(
            sspm_rights::ASSESS_POSTURE | sspm_rights::DETECT_DRIFT | sspm_rights::QUERY_AUDIT,
            4000,
            200,
        )
        .expect("Atténuation monotone SspmCap");
    assert!(audit_cap.has_right(sspm_rights::ASSESS_POSTURE));
    assert!(audit_cap.has_right(sspm_rights::DETECT_DRIFT));
    assert!(audit_cap.has_right(sspm_rights::QUERY_AUDIT));
    assert!(!audit_cap.has_right(sspm_rights::ADMIN));
    assert!(!audit_cap.has_right(sspm_rights::QUARANTINE_SERVICE));
    assert_eq!(audit_cap.max_lifetime, 4000);
    assert_eq!(audit_cap.invocations_left, 200);

    // Rejet d'escalade illicite
    assert_eq!(
        audit_cap.attenuate(sspm_rights::ALL, 4000, 200),
        Err(SspmError::AttenuationViolation)
    );

    // 2. Initialisation du démon SSPM avec baseline souveraine
    let mut sspm = JamboSspmDaemon::new(admin_cap);
    sspm.init_defaults();

    assert_eq!(sspm.service_count, 4);
    assert_eq!(sspm.connector_count, 2);

    // 3. Enregistrement d'un nouveau micro-service souverain conforme
    let vault_baseline = Sha256::digest(b"sovereign_key_vault_v1");
    let svc_id = sspm
        .register_service(
            &mut admin_cap,
            "sovereign_key_vault",
            "ipc:///svc/crypto/vault",
            ServiceType::ComputeMicroservice,
            ServiceEnvironment::SecFabric,
            ComplianceStandard::AnssiSecNumCloud,
            PermissionScope::AdminPrivileged,
            false,
            true, // MFA
            true, // TLS
            vault_baseline,
            vault_baseline,
            8000,
        )
        .expect("Enregistrement micro-service coffre-fort de clés");
    assert_eq!(svc_id, 5);
    assert_eq!(sspm.service_count, 5);

    // 4. Détection automatique de dérive de configuration (MFA absent sur compte admin)
    let drifted_baseline = Sha256::digest(b"portal_baseline_v1");
    let portal_id = sspm
        .register_service(
            &mut admin_cap,
            "customer_portal",
            "https://portal.userworkload.jambo:443",
            ServiceType::ComputeMicroservice,
            ServiceEnvironment::UserWorkload,
            ComplianceStandard::ZeroTrustBaseline,
            PermissionScope::AdminPrivileged,
            false,
            false, // Alerte : MFA désactivé pour un rôle admin !
            true,
            drifted_baseline,
            drifted_baseline,
            8010,
        )
        .expect("Enregistrement service portail");
    assert_eq!(portal_id, 6);

    // Vérification de la détection de la dérive
    let mut mfa_drift_id = None;
    for d in sspm.drifts.iter().flatten() {
        if d.service_id == portal_id && d.drift_type == DriftType::MfaDisabledOnPrivilegedAccess {
            mfa_drift_id = Some(d.id);
            break;
        }
    }
    assert!(mfa_drift_id.is_some(), "La dérive MFA doit être détectée");

    // 5. Remédiation automatisée de la dérive
    sspm.remediate_drift(&mut admin_cap, mfa_drift_id.unwrap(), 8020)
        .expect("Remédiation de la dérive MFA");
    assert!(sspm.services[5].unwrap().mfa_enforced, "MFA restauré sur le service");

    // 6. Détection et mise en quarantaine immédiate O(1) d'un connecteur tiers Shadow SaaS
    let shadow_conn_id = 2; // external_analytics_hook enregistré dans init_defaults
    assert!(!sspm.connectors[1].unwrap().approved_by_sovereign_governance);
    assert!(sspm.connectors[1].unwrap().is_risky());

    sspm.quarantine_connector(&mut admin_cap, shadow_conn_id, 8030)
        .expect("Mise en quarantaine du connecteur tiers non approuvé");
    assert!(sspm.connectors[1].unwrap().quarantined);

    // 7. Mise en quarantaine et levée de quarantaine d'un service
    sspm.quarantine_service(&mut admin_cap, portal_id, 8040)
        .expect("Quarantaine du service portail");
    assert!(sspm.services[5].unwrap().quarantined);

    sspm.unquarantine_service(&mut admin_cap, portal_id, 8050)
        .expect("Levée de quarantaine du service portail");
    assert!(!sspm.services[5].unwrap().quarantined);

    // 8. Balayage complet de posture et vérification de conformité
    let scanned = sspm
        .run_full_posture_scan(&mut admin_cap, 8060)
        .expect("Balayage de posture complet");
    assert_eq!(scanned, 6);

    let summary = sspm.get_summary(&admin_cap).expect("Synthèse globale SSPM");
    assert_eq!(summary.total_services, 6);
    assert_eq!(summary.total_connectors, 2);
    assert!(summary.global_sspm_score <= 100);

    // 9. Vérification de l'intégrité cryptographique du registre d'audit SHA-256
    assert!(sspm.verify_ledger_integrity(), "Registre d'audit SSPM cryptographiquement intègre");

    kprintln!(
        "[SSPM/TEST] Validation réussie : 6 services évalués, 2 connecteurs surveillés, dérive MFA remédiée, quarantaine O(1) validée, audit SHA-256 vérifié."
    );
    true
}

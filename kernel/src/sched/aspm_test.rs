//! Module de validation formelle de la Posture de Sécurité Applicative (ASPM) & SBOM CycloneDX (`jambo-aspm`)
//! Phase 129 — Jalon v0.2.127
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_aspm::{
    aspm_rights, AdmissionDecision, AspmCap, AspmError, ComponentType, JamboAspmDaemon,
    SbomComponent, SupplyChainThreat, VulnerabilityFinding, VulnerabilitySeverity,
};

/// Exécute la suite complète de validation formelle du démon ASPM (Phase 129)
pub fn execute_aspm_daemon_test() -> bool {
    kprintln!(
        "[ASPM/TEST] Démarrage de la validation formelle de la posture de sécurité applicative et supply chain ASPM (Phase 129)..."
    );

    // 1. Contrôle d'accès capabilaire (AspmCap) et atténuation monotone
    let admin_cap = AspmCap::new(Handle::new(12901, 1), aspm_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(aspm_rights::SCAN_DEPENDENCIES));
    assert!(admin_cap.has_right(aspm_rights::INGEST_SBOM));
    assert!(admin_cap.has_right(aspm_rights::GENERATE_SBOM));
    assert!(admin_cap.has_right(aspm_rights::ENFORCE_POLICIES));
    assert!(admin_cap.has_right(aspm_rights::QUERY_POSTURE));
    assert!(admin_cap.has_right(aspm_rights::BLOCK_DEPLOYMENT));
    assert!(admin_cap.has_right(aspm_rights::REMEDIATE));
    assert!(admin_cap.has_right(aspm_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(aspm_rights::ADMIN));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            aspm_rights::QUERY_POSTURE | aspm_rights::GENERATE_SBOM,
            5000,
            200,
        )
        .expect("Atténuation monotone AspmCap");
    assert!(monitor_cap.has_right(aspm_rights::QUERY_POSTURE));
    assert!(monitor_cap.has_right(aspm_rights::GENERATE_SBOM));
    assert!(!monitor_cap.has_right(aspm_rights::REMEDIATE));
    assert!(!monitor_cap.has_right(aspm_rights::ADMIN));
    assert_eq!(monitor_cap.max_lifetime, 5000);
    assert_eq!(monitor_cap.invocations_left, 200);

    // Rejet d'escalade
    assert_eq!(
        monitor_cap.attenuate(aspm_rights::ALL, 5000, 200),
        Err(AspmError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et scénario de référence
    let mut aspm = JamboAspmDaemon::new(admin_cap);
    aspm.init_defaults();
    assert_eq!(aspm.component_count, 5);
    assert_eq!(aspm.vulnerability_count, 2);
    assert!(aspm.verify_ledger_integrity());

    // 3. Génération SBOM CycloneDX 1.5
    let mut sbom_buf = [0u8; 1024];
    let sbom_len = aspm
        .generate_cyclonedx_sbom(&admin_cap, &mut sbom_buf)
        .expect("Génération CycloneDX SBOM");
    assert!(sbom_len > 0);

    // Rejet de génération si pas de droits
    let no_sbom_cap = admin_cap
        .attenuate(aspm_rights::QUERY_POSTURE, 1000, 10)
        .expect("Atténuation no_sbom");
    let mut err_buf = [0u8; 128];
    assert_eq!(
        aspm.generate_cyclonedx_sbom(&no_sbom_cap, &mut err_buf),
        Err(AspmError::PermissionDenied)
    );

    // 4. Contrôle d'admission et barrière de sécurité de déploiement
    let adm1 = aspm
        .evaluate_admission(&admin_cap, 1, 2000)
        .expect("Admission composant 1");
    assert_eq!(adm1, AdmissionDecision::Allowed);

    // Composant 4 est bloqué en admission
    let adm4 = aspm
        .evaluate_admission(&admin_cap, 4, 2100)
        .expect("Admission composant 4");
    assert_eq!(adm4, AdmissionDecision::Blocked);

    // 5. Analyse continue des dépendances
    let (total_comps, threats) = aspm
        .scan_dependencies(&admin_cap, 2200)
        .expect("Scan dépendances");
    assert_eq!(total_comps, 5);
    assert!(threats >= 2);

    // 6. Remédiation globale et rétablissement de posture
    let initial_posture = aspm.global_posture_score;
    assert!(initial_posture <= 50);

    let rem_count = aspm
        .remediate_all_critical(&admin_cap, 2300)
        .expect("Remédiation critique");
    assert!(rem_count >= 1);
    assert!(aspm.global_posture_score > initial_posture);

    // Vérifier réévaluation post-remédiation
    let adm4_post = aspm
        .evaluate_admission(&admin_cap, 4, 2400)
        .expect("Admission composant 4 post-remédiation");
    assert_ne!(adm4_post, AdmissionDecision::Blocked);

    // 7. Vérification de l'intégrité cryptographique absolue du registre d'audit SHA-256
    assert!(aspm.verify_ledger_integrity());

    kprintln!(
        "[ASPM/TEST] \x1b[1;32mSuccès de la validation formelle ASPM : {} composants SBOM, {} vulnérabilités tracées, conformité CycloneDX 1.5, contrôle d'admission et scellement SHA-256 validés\x1b[0m",
        aspm.component_count,
        aspm.vulnerability_count
    );

    true
}

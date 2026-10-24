//! Module de validation formelle de la Sécurité des Pipelines & Orchestration DevSecOps (`jambo-devsecops`)
//! Phase 138 — Jalon v0.3.5
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_devsecops::{
    devsecops_rights, AdmissionStatus, DevSecOpsCap, DevSecOpsError, JamboDevSecOpsDaemon,
    PipelineStage, SandboxingProfile, Sha256, SignatureScheme, SlsaLevel,
};

/// Exécute la suite complète de validation formelle du démon DevSecOps (Phase 138)
pub fn execute_devsecops_daemon_test() -> bool {
    kprintln!(
        "[DEVSECOPS/TEST] Démarrage de la validation formelle DevSecOps & admission souveraine (Phase 138)..."
    );

    // 1. Contrôle d'accès capabilaire (DevSecOpsCap) et atténuation monotone
    let mut admin_cap =
        DevSecOpsCap::new(Handle::new(13801, 1), devsecops_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(devsecops_rights::VALIDATE_MANIFEST));
    assert!(admin_cap.has_right(devsecops_rights::VERIFY_ATTESTATION));
    assert!(admin_cap.has_right(devsecops_rights::ADMISSION_CONTROL));
    assert!(admin_cap.has_right(devsecops_rights::ENFORCE_POLICY));
    assert!(admin_cap.has_right(devsecops_rights::SIGN_ARTIFACT));
    assert!(admin_cap.has_right(devsecops_rights::MANAGE_PIPELINES));
    assert!(admin_cap.has_right(devsecops_rights::QUERY_AUDIT));
    assert!(admin_cap.has_right(devsecops_rights::ADMIN));

    // Atténuation monotone
    let admission_cap = admin_cap
        .attenuate(
            devsecops_rights::ADMISSION_CONTROL | devsecops_rights::QUERY_AUDIT,
            4000,
            200,
        )
        .expect("Atténuation monotone DevSecOpsCap");
    assert!(admission_cap.has_right(devsecops_rights::ADMISSION_CONTROL));
    assert!(admission_cap.has_right(devsecops_rights::QUERY_AUDIT));
    assert!(!admission_cap.has_right(devsecops_rights::ADMIN));
    assert!(!admission_cap.has_right(devsecops_rights::SIGN_ARTIFACT));
    assert_eq!(admission_cap.max_lifetime, 4000);
    assert_eq!(admission_cap.invocations_left, 200);

    // Rejet d'escalade illicite
    assert_eq!(
        admission_cap.attenuate(devsecops_rights::ALL, 4000, 200),
        Err(DevSecOpsError::AttenuationViolation)
    );

    // 2. Initialisation du démon DevSecOps souverain avec manifests par défaut
    let mut devsecops = JamboDevSecOpsDaemon::new(admin_cap);
    devsecops.init_defaults();

    assert_eq!(devsecops.manifest_count, 4);
    assert_eq!(devsecops.attestation_count, 3);
    assert_eq!(devsecops.admission_count, 4);

    // 3. Vérification des admissions par défaut (3 admis, 1 rejeté)
    let adm_vault = devsecops.admissions[0].unwrap();
    assert_eq!(adm_vault.manifest_id, 1);
    assert_eq!(adm_vault.status, AdmissionStatus::Admitted);
    assert!(adm_vault.slsa_verified);
    assert!(adm_vault.signature_verified);

    let adm_shadow = devsecops.admissions[3].unwrap();
    assert_eq!(adm_shadow.manifest_id, 4);
    assert_eq!(adm_shadow.status, AdmissionStatus::Rejected);
    assert_eq!(adm_shadow.rejection_reason_code, 1); // Ambient privs disallowed

    // 4. Enregistrement d'un nouveau micro-service souverain : Nœud de Signature KMS (service 5)
    devsecops
        .register_manifest(
            &mut admin_cap,
            5,
            "jambo-kms",
            200,
            8192,
            true,  // no ambient privileges
            true,  // read-only rootfs
            false, // no escalation
            SandboxingProfile::TeeEnclave,
            SlsaLevel::L3,
            true, // require signed
            0,    // 0 CVE critiques
            0,    // 0 CVE hautes
            2000,
        )
        .expect("Enregistrement du manifest jambo-kms");
    assert_eq!(devsecops.manifest_count, 5);

    // 5. Tentative d'admission sans attestation -> Rejet conforme
    let adm_kms_before = devsecops
        .evaluate_admission(&mut admin_cap, 5, 2010)
        .expect("Évaluation admission sans attestation");
    assert_eq!(adm_kms_before.status, AdmissionStatus::Rejected);

    // 6. Soumission de l'attestation de provenance SLSA L3 avec signature cryptographique
    let sig_kms = [0x5Au8; 64];
    devsecops
        .submit_provenance(
            &mut admin_cap,
            4,
            5,
            "jambo-hermetic-builder",
            &Sha256::digest(b"git://jambo-os/jambo-kms@commit-kms1"),
            &Sha256::digest(b"in-toto-materials-kms"),
            SlsaLevel::L3,
            SignatureScheme::Ed25519Sovereign,
            &sig_kms,
            2020,
        )
        .expect("Soumission attestation de provenance SLSA L3");
    assert_eq!(devsecops.attestation_count, 4);

    // 7. Nouvelle évaluation d'admission -> Admission autorisée
    let adm_kms_after = devsecops
        .evaluate_admission(&mut admin_cap, 5, 2030)
        .expect("Ré-évaluation admission après attestation");
    assert_eq!(adm_kms_after.status, AdmissionStatus::Admitted);
    assert!(adm_kms_after.slsa_verified);
    assert!(adm_kms_after.signature_verified);
    assert!(adm_kms_after.policy_satisfied);

    // 8. Exécution des étapes du pipeline DevSecOps pour jambo-kms
    devsecops
        .execute_pipeline(
            &mut admin_cap,
            10,
            5,
            PipelineStage::StaticAnalysisLint,
            true,
            99,
            2040,
        )
        .expect("Pipeline SAST");
    devsecops
        .execute_pipeline(
            &mut admin_cap,
            11,
            5,
            PipelineStage::DependencySecurityAudit,
            true,
            97,
            2045,
        )
        .expect("Pipeline SCA");
    devsecops
        .execute_pipeline(
            &mut admin_cap,
            12,
            5,
            PipelineStage::AttestationVerification,
            true,
            100,
            2050,
        )
        .expect("Pipeline Attestation");
    devsecops
        .execute_pipeline(
            &mut admin_cap,
            13,
            5,
            PipelineStage::AdmissionControlGate,
            true,
            100,
            2055,
        )
        .expect("Pipeline Gate d'admission");

    // 9. Synthèse globale DevSecOps
    let summary = devsecops
        .get_summary(&admin_cap)
        .expect("Synthèse globale DevSecOps");
    assert_eq!(summary.total_manifests, 5);
    assert_eq!(summary.total_attestations, 4);
    assert_eq!(summary.admitted_count, 4);
    assert_eq!(summary.rejected_count, 1);
    assert_eq!(summary.slsa_l3_or_higher_count, 4);
    assert!(summary.compliance_score >= 80);

    // 10. Vérification de l'intégrité cryptographique du registre d'audit SHA-256
    assert!(
        devsecops.verify_ledger_integrity(),
        "Registre d'audit DevSecOps cryptographiquement intègre"
    );

    kprintln!(
        "[DEVSECOPS/TEST] Validation réussie : 5 manifests gérés, attestations SLSA L3 et signatures vérifiées, contrôle d'admission strict (4 admis, 1 rejeté), pipelines exécutés, audit SHA-256 scellé."
    );
    true
}

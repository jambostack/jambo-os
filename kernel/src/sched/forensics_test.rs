//! Module de validation formelle de l'Investigation Numérique & Analyse Forensique Souveraine (`jambo-forensics`)
//! Phase 148 — Jalon v0.3.15
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_forensics::{
    forensics_rights, id_to_str, ArtifactKind, Blake3, CustodyAction, Ed25519Engine, EvidenceSeal,
    ForensicArtifact, ForensicKeyPair, ForensicsCap, ForensicsError, ForensicsSummary,
    IncidentTriageReport, JamboForensicsDaemon, MemoryRegionSnapshot, MemoryResidueAnalyzer,
    ProcessForensicImage, Sha256, VmoSnapshot, PROT_EXEC, PROT_READ, PROT_WRITE,
    VMO_FLAG_ANONYMOUS, VMO_FLAG_EXEC, VMO_FLAG_PAGED, VMO_FLAG_READ, VMO_FLAG_SHARED,
    VMO_FLAG_WRITE,
};

/// Exécute la suite complète de validation formelle du moteur forensique souverain (Phase 148)
pub fn execute_forensics_daemon_test() -> bool {
    kprintln!(
        "[FORENSICS/TEST] Démarrage de la validation formelle de l'investigation numérique, snapshots VMO & preuves scellées (Phase 148)..."
    );

    // 1. Contrôle d'accès capabilaire (ForensicsCap), droit TRIAGE_INCIDENT et atténuation monotone
    let admin_cap = ForensicsCap::new(Handle::new(14801, 1), forensics_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(forensics_rights::CAPTURE_MEMORY));
    assert!(admin_cap.has_right(forensics_rights::EXTRACT_ARTIFACTS));
    assert!(admin_cap.has_right(forensics_rights::ACQUIRE_PROCESS));
    assert!(admin_cap.has_right(forensics_rights::BUILD_TIMELINE));
    assert!(admin_cap.has_right(forensics_rights::SIGN_EVIDENCE));
    assert!(admin_cap.has_right(forensics_rights::VERIFY_SEAL));
    assert!(admin_cap.has_right(forensics_rights::AUDIT_INSPECT));
    assert!(admin_cap.has_right(forensics_rights::TRIAGE_INCIDENT));
    assert!(admin_cap.has_right(forensics_rights::ADMIN));

    // Atténuation monotone
    let triage_cap = admin_cap
        .attenuate(
            forensics_rights::CAPTURE_MEMORY
                | forensics_rights::EXTRACT_ARTIFACTS
                | forensics_rights::SIGN_EVIDENCE
                | forensics_rights::TRIAGE_INCIDENT
                | forensics_rights::VERIFY_SEAL,
            5000,
            250,
        )
        .expect("Atténuation monotone ForensicsCap");
    assert!(triage_cap.has_right(forensics_rights::CAPTURE_MEMORY));
    assert!(triage_cap.has_right(forensics_rights::EXTRACT_ARTIFACTS));
    assert!(triage_cap.has_right(forensics_rights::SIGN_EVIDENCE));
    assert!(triage_cap.has_right(forensics_rights::TRIAGE_INCIDENT));
    assert!(triage_cap.has_right(forensics_rights::VERIFY_SEAL));
    assert!(!triage_cap.has_right(forensics_rights::ADMIN));
    assert_eq!(triage_cap.max_lifetime, 5000);
    assert_eq!(triage_cap.invocations_left, 250);

    // Rejet d'escalade
    assert_eq!(
        triage_cap.attenuate(forensics_rights::ALL, 5000, 250),
        Err(ForensicsError::AttenuationViolation)
    );

    // 2. Moteur cryptographique BLAKE3, SHA-256 & Ed25519
    let mut b3 = Blake3::new();
    b3.update(b"VolatileMemoryForensicsTestVectorPhase148");
    let b3_digest = b3.finalize();
    assert_ne!(b3_digest, [0u8; 32]);

    let sha_digest = Sha256::hash(b"VolatileMemoryForensicsTestVectorPhase148");
    assert_ne!(sha_digest, [0u8; 32]);

    let keypair = ForensicKeyPair::derive_from_seed(0x148_cafe);
    let signature = Ed25519Engine::sign(&keypair, &b3_digest);
    assert!(Ed25519Engine::verify(
        &keypair.public_key,
        &b3_digest,
        &signature
    ));

    // 3. Initialisation du démon central et preuves de référence
    let mut forensics = JamboForensicsDaemon::new(admin_cap, keypair);
    forensics.init_defaults();
    assert_eq!(forensics.snapshot_count, 1);
    assert_eq!(forensics.artifact_count, 4);
    assert_eq!(forensics.seal_count, 1);
    assert!(forensics.verify_custody_integrity());

    // 4. Capture d'empreinte mémoire d'un processus suspect d'exfiltration (trojan-beacon)
    let sample_payload = [0x48, 0x31, 0xc0, 0x48, 0x89, 0xc7, 0x0f, 0x05, 0x90, 0x90];
    let code_region =
        MemoryRegionSnapshot::new(0x400000, 0x4000, PROT_READ | PROT_EXEC, b"ELF_TEXT_SEGMENT");
    let injected_region = MemoryRegionSnapshot::new(
        0x7fff1000,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        &sample_payload,
    );
    assert!(injected_region.is_suspicious_executable);

    let snap_id = forensics
        .capture_process_memory(
            &admin_cap,
            88,
            1,
            "trojan-beacon",
            0x3f0000,
            0x7fff1004,
            0x7ffffff0,
            &[code_region, injected_region],
            1200,
        )
        .expect("Capture mémoire réussie");
    assert_eq!(snap_id, 2);
    assert_eq!(forensics.snapshot_count, 2);

    // 5. Capture et intégration de snapshot mémoire VMO scellé avec détection de fuite de certificat
    let vmo_payload = b"PRIVATE KEY EXFILTRATION ATTEMPT IN MAPPED VMO BUFFER \x5f\xc3";
    let vmo_snap = VmoSnapshot::new(
        2002,
        0x4000,
        VMO_FLAG_READ | VMO_FLAG_WRITE | VMO_FLAG_SHARED,
        0x90000000,
        vmo_payload,
    );
    assert!(vmo_snap.contains_sensitive_residual);
    assert_ne!(vmo_snap.blake3_digest, [0u8; 32]);
    assert_ne!(vmo_snap.sha256_digest, [0u8; 32]);

    forensics
        .attach_vmo_to_snapshot(&admin_cap, snap_id, vmo_snap)
        .expect("Attachement VMO au snapshot");

    // 6. Ajout d'artefacts d'investigation spécifiques
    let art_id = forensics
        .record_artifact(
            &admin_cap,
            ArtifactKind::PrivilegeEscalation,
            88,
            "Unauthorized credential access via leaked kernel cap token",
            1250,
            90,
        )
        .expect("Enregistrement artefact");
    assert_eq!(art_id, 5);
    assert_eq!(forensics.artifact_count, 5);

    // 7. Scellement cryptographique Ed25519/BLAKE3/SHA-256 de l'instantané capturé
    let seal = forensics
        .seal_evidence(&admin_cap, snap_id, true, 777, 1300)
        .expect("Scellement de preuve réussi");
    assert_eq!(seal.evidence_id, snap_id);
    assert!(seal.is_snapshot);
    assert_ne!(seal.sha256_digest, [0u8; 32]);
    assert!(forensics
        .verify_seal_integrity(&admin_cap, &seal)
        .expect("Vérification intégrité du sceau"));

    // 8. Orchestration d'un triage forensique chirurgical post-incident (Phase 148)
    let rwx_region = MemoryRegionSnapshot::new(
        0x70001000,
        0x2000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        b"\x90\x90\x90\x90\x48\x31\xc0\x0f\x05INJECTED_POST_INCIDENT_SHELLCODE",
    );
    let token_vmo = VmoSnapshot::new(
        3003,
        0x2000,
        VMO_FLAG_READ | VMO_FLAG_WRITE | VMO_FLAG_ANONYMOUS,
        0xa0000000,
        b"CAP:TOKEN:UNAUTHORIZED_BEARER_AUTH_KEY_LEAK \x58\xc3",
    );

    let triage_rep = forensics
        .orchestrate_post_incident_triage(
            &triage_cap,
            9001,
            104,
            "incident_worker_exfil",
            &[rwx_region],
            &[token_vmo],
            2000,
        )
        .expect("Triage post-incident orchestré");

    assert_eq!(triage_rep.incident_id, 9001);
    assert_eq!(triage_rep.target_pid, 104);
    assert_eq!(triage_rep.snapshot_id, 3);
    assert!(triage_rep.artifacts_generated >= 3);
    assert!(triage_rep.custody_chain_verified);
    assert_eq!(forensics.triage_count, 1);

    // 9. Vérification des métriques globales et de la chaîne de garde (Chain of Custody) inaltérable
    let summary: ForensicsSummary = forensics.get_summary();
    assert_eq!(summary.snapshot_count, 3);
    assert!(summary.artifact_count >= 8);
    assert_eq!(summary.seal_count, 3);
    assert_eq!(summary.triage_count, 1);
    assert!(summary.custody_count >= 6);
    assert!(summary.custody_chain_valid);
    assert!(forensics.verify_custody_integrity());
    assert_ne!(forensics.custody_chain, JamboForensicsDaemon::GENESIS_HASH);

    kprintln!(
        "[FORENSICS/TEST] \x1b[1;32mSuccès : Snapshots VMO scellés, triage post-incident validé, scellement BLAKE3/SHA-256/Ed25519 & chaîne de garde intègre ({} entrées, score risque: {})\x1b[0m",
        summary.custody_count,
        summary.cumulative_risk_score
    );
    true
}

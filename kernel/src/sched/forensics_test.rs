//! Module de validation de l'Investigation Numérique & Analyse Forensique Post-Incident (`jambo-forensics`)
//! Phase 118 — Jalon v0.2.116
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_forensics::{
    forensics_rights, ArtifactKind, Blake3, CustodyAction, Ed25519Engine, EvidenceSeal,
    ForensicArtifact, ForensicKeyPair, ForensicsCap, ForensicsError, JamboForensicsDaemon,
    MemoryRegionSnapshot, ProcessForensicImage, PROT_EXEC, PROT_READ, PROT_WRITE,
};

/// Exécute la suite complète de validation formelle du moteur forensique (Phase 118)
pub fn execute_forensics_daemon_test() -> bool {
    kprintln!(
        "[FORENSICS/TEST] Démarrage de la validation de l'investigation numérique & empreintes mémoire (Phase 118)..."
    );

    // 1. Contrôle d'accès capabilaire (ForensicsCap) et atténuation monotone
    let admin_cap = ForensicsCap::new(Handle::new(11801, 1), forensics_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(forensics_rights::CAPTURE_MEMORY));
    assert!(admin_cap.has_right(forensics_rights::EXTRACT_ARTIFACTS));
    assert!(admin_cap.has_right(forensics_rights::ACQUIRE_PROCESS));
    assert!(admin_cap.has_right(forensics_rights::BUILD_TIMELINE));
    assert!(admin_cap.has_right(forensics_rights::SIGN_EVIDENCE));
    assert!(admin_cap.has_right(forensics_rights::VERIFY_SEAL));
    assert!(admin_cap.has_right(forensics_rights::AUDIT_INSPECT));
    assert!(admin_cap.has_right(forensics_rights::ADMIN));

    // Atténuation monotone
    let attenuated = admin_cap
        .attenuate(
            forensics_rights::CAPTURE_MEMORY
                | forensics_rights::EXTRACT_ARTIFACTS
                | forensics_rights::VERIFY_SEAL,
            2000,
            50,
        )
        .expect("Atténuation monotone ForensicsCap");
    assert!(attenuated.has_right(forensics_rights::CAPTURE_MEMORY));
    assert!(attenuated.has_right(forensics_rights::EXTRACT_ARTIFACTS));
    assert!(attenuated.has_right(forensics_rights::VERIFY_SEAL));
    assert!(!attenuated.has_right(forensics_rights::ADMIN));
    assert!(!attenuated.has_right(forensics_rights::SIGN_EVIDENCE));
    assert_eq!(attenuated.max_lifetime, 2000);
    assert_eq!(attenuated.invocations_left, 50);

    // Rejet d'escalade
    assert_eq!(
        attenuated.attenuate(forensics_rights::ALL, 2000, 50),
        Err(ForensicsError::AttenuationViolation)
    );

    // 2. Moteur cryptographique BLAKE3 & Ed25519
    let mut b3 = Blake3::new();
    b3.update(b"VolatileMemoryForensicsTestVector");
    let digest = b3.finalize();
    assert_ne!(digest, [0u8; 32]);

    let keypair = ForensicKeyPair::derive_from_seed(0x118_cafe);
    let signature = Ed25519Engine::sign(&keypair, &digest);
    assert!(Ed25519Engine::verify(
        &keypair.public_key,
        &digest,
        &signature
    ));

    // 3. Initialisation du démon central et preuves par défaut
    let mut forensics = JamboForensicsDaemon::new(admin_cap, keypair);
    forensics.init_defaults();
    assert_eq!(forensics.snapshot_count, 1);
    assert_eq!(forensics.artifact_count, 3);
    assert_eq!(forensics.seal_count, 1);
    assert!(forensics.verify_custody_integrity());

    // 4. Capture d'empreinte mémoire d'un processus suspect d'exfiltration
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

    // 5. Ajout d'artefacts d'évasion de privilèges
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
    assert_eq!(art_id, 4);
    assert_eq!(forensics.artifact_count, 4);

    // 6. Scellement cryptographique Ed25519/BLAKE3 de l'instantané capturé
    let seal = forensics
        .seal_evidence(&admin_cap, snap_id, true, 777, 1300)
        .expect("Scellement de preuve réussi");
    assert_eq!(seal.evidence_id, snap_id);
    assert!(seal.is_snapshot);
    assert!(forensics
        .verify_seal_integrity(&admin_cap, &seal)
        .expect("Vérification intégrité"));

    // 7. Vérification de la chaîne de garde (Chain of Custody) inaltérable
    assert!(forensics.verify_custody_integrity());
    assert_ne!(forensics.custody_chain, JamboForensicsDaemon::GENESIS_HASH);
    assert!(forensics.custody_count >= 4);

    kprintln!(
        "[FORENSICS/TEST] \x1b[1;32mSuccès : Empreintes mémoire capturées, détection W+X validée, scellement BLAKE3/Ed25519 & chaîne de garde intègre ({} entrées)\x1b[0m",
        forensics.custody_count
    );
    true
}

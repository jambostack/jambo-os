//! Module de validation formelle de la Cyber-Résilience & Intégrité Noyau/Pilotes (`jambo-kdir`)
//! Phase 171 — Jalon v0.3.38
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_kdir::{
    kdir_rights, DriverEntry, DriverStatus, IntegrityStatus, JamboKdirDaemon, KdirCap, KdirError,
    KdirPostureReport, KdirProbeReport, KdirRemediationReport, KdirSummary, KernelProbe,
    RootkitThreatType, Sha256, StructureType, ThreatSeverity,
};

/// Exécute la suite complète de validation formelle du moteur KDIR souverain (Phase 171)
pub fn execute_kdir_daemon_test() -> bool {
    kprintln!(
        "[KDIR/TEST] Démarrage de la validation formelle Cyber-Résilience, Intégrité Noyau & Auto-Restauration O(1) (Phase 171)..."
    );

    // 1. Contrôle d'accès capabilaire (KdirCap) et atténuation monotone
    let admin_cap = KdirCap::new(Handle::new(14101, 1), kdir_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(kdir_rights::REGISTER_PROBE));
    assert!(admin_cap.has_right(kdir_rights::VERIFY_INTEGRITY));
    assert!(admin_cap.has_right(kdir_rights::ATTEST_MEMORY));
    assert!(admin_cap.has_right(kdir_rights::RESTORE_TABLE));
    assert!(admin_cap.has_right(kdir_rights::ISOLATE_DRIVER));
    assert!(admin_cap.has_right(kdir_rights::CONFIGURE_POLICY));
    assert!(admin_cap.has_right(kdir_rights::QUERY_AUDIT));
    assert!(admin_cap.has_right(kdir_rights::ADMIN));
    assert!(admin_cap.has_right(kdir_rights::GENERATE_REPORT));
    assert!(admin_cap.has_right(kdir_rights::REMEDIATE));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            kdir_rights::VERIFY_INTEGRITY | kdir_rights::QUERY_AUDIT | kdir_rights::GENERATE_REPORT,
            5000,
            250,
        )
        .expect("Atténuation monotone KdirCap");
    assert!(monitor_cap.has_right(kdir_rights::VERIFY_INTEGRITY));
    assert!(monitor_cap.has_right(kdir_rights::QUERY_AUDIT));
    assert!(monitor_cap.has_right(kdir_rights::GENERATE_REPORT));
    assert!(!monitor_cap.has_right(kdir_rights::ADMIN));
    assert!(!monitor_cap.has_right(kdir_rights::RESTORE_TABLE));
    assert!(!monitor_cap.has_right(kdir_rights::ISOLATE_DRIVER));
    assert!(!monitor_cap.has_right(kdir_rights::REMEDIATE));
    assert_eq!(monitor_cap.max_lifetime, 5000);
    assert_eq!(monitor_cap.invocations_left, 250);

    // Rejet d'escalade illicite
    assert_eq!(
        monitor_cap.attenuate(kdir_rights::ALL, 5000, 250),
        Err(KdirError::AttenuationViolation)
    );

    // 2. Initialisation du démon KDIR souverain avec structures par défaut
    let mut kdir = JamboKdirDaemon::new(admin_cap);
    kdir.init_defaults();

    assert_eq!(kdir.probe_count, 4);
    assert_eq!(kdir.driver_count, 3);
    assert_eq!(kdir.threat_count, 0);

    let summary0 = kdir.get_summary();
    assert_eq!(summary0.probes_count, 4);
    assert_eq!(summary0.intact_count, 4);
    assert_eq!(summary0.tampered_count, 0);
    assert_eq!(summary0.drivers_count, 3);
    assert_eq!(summary0.isolated_drivers_count, 0);
    assert_eq!(summary0.global_resilience_score, 100);
    assert!(summary0.ledger_valid);

    // 3. Enregistrement dynamique d'une sonde de texte noyau (.text)
    let text_golden = b"JAMBO_KERNEL_TEXT_SECTION_IMMUTABLE_CODE_HASH_2026";
    let text_probe_id = kdir
        .register_probe(
            "kernel_text_section",
            StructureType::KernelText,
            0xFFFF_8000_0010_0000,
            text_golden.len(),
            text_golden,
            1735001000,
        )
        .expect("Enregistrement sonde .text");
    assert_eq!(kdir.probe_count, 5);

    // 4. Vérification d'intégrité nominale de l'IDT
    let idt_probe_id = kdir.probes[0].as_ref().unwrap().probe_id;
    let idt_nominal = b"JAMBO_IDT_GOLDEN_VECTORS_0_TO_256_RING0_EXCEPTIONS_INTERRUPT_GATES";
    let is_valid = kdir
        .verify_structure_integrity(idt_probe_id, idt_nominal, 1735001100)
        .expect("Vérification IDT nominale");
    assert!(is_valid, "L'IDT de référence doit être intègre");

    // 5. Détection d'altération / Rootkit IDT Hooking
    let idt_hooked = b"JAMBO_IDT_ROOTKIT_HOOK_VECTOR_0x80_COMPROMISED";
    let is_tampered = kdir
        .verify_structure_integrity(idt_probe_id, idt_hooked, 1735001200)
        .expect("Vérification IDT hookée");
    assert!(!is_tampered, "La sonde doit détecter l'altération de l'IDT");

    let summary1 = kdir.get_summary();
    assert_eq!(summary1.tampered_count, 1);
    assert_eq!(summary1.threats_detected, 1);
    assert_eq!(
        kdir.threats[0].as_ref().unwrap().threat_type,
        RootkitThreatType::IdtHooking
    );
    assert_eq!(
        kdir.threats[0].as_ref().unwrap().severity,
        ThreatSeverity::Critical
    );
    assert!(summary1.global_resilience_score < 100);

    // 6. Génération et validation du rapport individuel de sonde scellé SHA-256
    let probe_rep = kdir
        .generate_probe_report(text_probe_id, 1735001250)
        .expect("Rapport sonde");
    assert!(probe_rep.verify_seal());
    assert_eq!(probe_rep.name_str(), "kernel_text_section");

    // Détection d'altération sur le rapport de sonde
    let mut tampered_probe_rep = probe_rep;
    tampered_probe_rep.size_bytes += 4096;
    assert!(!tampered_probe_rep.verify_seal());

    // 7. Auto-restauration chirurgicale de l'IDT depuis le snapshot de référence
    let mut restored_idt = [0u8; 128];
    let bytes_restored = kdir
        .auto_restore_structure(idt_probe_id, &mut restored_idt, 1735001300)
        .expect("Auto-restauration IDT");
    assert!(bytes_restored > 0);
    assert_eq!(&restored_idt[..idt_nominal.len()], idt_nominal.as_slice());

    let summary2 = kdir.get_summary();
    assert_eq!(summary2.intact_count, 5);
    assert_eq!(summary2.tampered_count, 0);
    assert_eq!(summary2.remediated_threats, 1);
    assert!(kdir.threats[0].as_ref().unwrap().auto_restored);

    // 8. Enregistrement d'un pilote non conforme et confinement instantané O(1)
    let rogue_sig = Sha256::digest(b"MALICIOUS_DRIVER_VMO_BYTECODE");
    let rogue_id = kdir
        .register_driver(
            "compromised-pci",
            Handle::new(999, 1),
            0xFFFF_8000_00AA_0000,
            32768,
            rogue_sig,
            0x05,
            1735001400,
        )
        .expect("Enregistrement rogue driver");
    assert_eq!(kdir.driver_count, 4);

    kdir.isolate_driver(rogue_id, 1735001500)
        .expect("Confinement immédiat du pilote compromis");

    let summary3 = kdir.get_summary();
    assert_eq!(summary3.isolated_drivers_count, 1);
    let isolated_driver = kdir
        .drivers
        .iter()
        .flatten()
        .find(|d| d.driver_id == rogue_id)
        .expect("Pilote trouvé");
    assert_eq!(isolated_driver.status, DriverStatus::Isolated);
    assert_eq!(isolated_driver.capabilities_mask, 0);

    // Rejet d'un double isolement
    assert_eq!(
        kdir.isolate_driver(rogue_id, 1735001600),
        Err(KdirError::DriverAlreadyIsolated)
    );

    // 9. Simulation d'une altération supplémentaire pour tester le playbook de remédiation globale
    let gdt_probe_id = kdir.probes[1].as_ref().unwrap().probe_id;
    let gdt_tampered = b"JAMBO_GDT_MALICIOUS_DESCRIPTOR_ROOTKIT_INJECTION";
    let _ = kdir.verify_structure_integrity(gdt_probe_id, gdt_tampered, 1735001700);
    assert_eq!(kdir.get_summary().tampered_count, 1);

    // 10. Génération et vérification du rapport de posture global scellé SHA-256
    let posture_rep = kdir
        .generate_posture_report(1735001800)
        .expect("Génération posture report");
    assert!(posture_rep.verify_seal());

    // Détection d'altération sur le rapport de posture
    let mut tampered_posture = posture_rep;
    tampered_posture.probes_count += 10;
    assert!(!tampered_posture.verify_seal());

    // 11. Exécution du playbook autonome de remédiation O(1) et rapport de remédiation scellé
    let rem_rep = kdir
        .generate_remediation_report(1735001900)
        .expect("Rapport de remédiation globale");
    assert!(rem_rep.verify_seal());
    assert_eq!(rem_rep.restored_probes_count, 1);
    assert_eq!(rem_rep.resilience_score_after, 95); // 100 - 5 (un pilote isolé)
    assert!(rem_rep.resilience_score_after > rem_rep.resilience_score_before);

    let summary_final = kdir.get_summary();
    assert_eq!(summary_final.tampered_count, 0);
    assert_eq!(summary_final.intact_count, 5);
    assert_eq!(summary_final.remediated_threats, 2);

    // 12. Vérification de l'intégrité de la chaîne cryptographique SHA-256
    assert!(
        kdir.verify_ledger_integrity(),
        "Le registre d'audit cryptographique KDIR doit être inviolé"
    );
    assert!(kdir.audit_count >= 8);

    kprintln!(
        "[KDIR/TEST] \x1b[1;32m[PASS]\x1b[0m Intégrité IDT/GDT/CR3/Syscall, auto-restauration O(1), rapports scellés SHA-256 et registre validés avec succès!"
    );

    true
}

//! Module de validation formelle de la Résilience & Défense Matérielle/Firmware (`jambo-fdr`)
//! Phase 142 — Jalon v0.3.9
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_fdr::{
    fdr_rights, BootkitThreatType, DeviceStatus, FdrCap, FdrError, FdrSummary,
    FirmwareIntegrityStatus, FirmwareProbe, FirmwareType, JamboFdrDaemon, Sha256, ThreatSeverity,
};

/// Exécute la suite complète de validation formelle du moteur FDR souverain (Phase 142)
pub fn execute_fdr_daemon_test() -> bool {
    kprintln!(
        "[FDR/TEST] Démarrage de la validation formelle Résilience & Défense Matérielle/Firmware (Phase 142)..."
    );

    // 1. Contrôle d'accès capabilaire (FdrCap) et atténuation monotone
    let admin_cap = FdrCap::new(Handle::new(14201, 1), fdr_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(fdr_rights::ATTEST_TPM));
    assert!(admin_cap.has_right(fdr_rights::VERIFY_FIRMWARE));
    assert!(admin_cap.has_right(fdr_rights::EXTEND_PCR));
    assert!(admin_cap.has_right(fdr_rights::SCAN_ACPI));
    assert!(admin_cap.has_right(fdr_rights::RESTORE_FIRMWARE));
    assert!(admin_cap.has_right(fdr_rights::ISOLATE_DEVICE));
    assert!(admin_cap.has_right(fdr_rights::CONFIGURE_POLICY));
    assert!(admin_cap.has_right(fdr_rights::QUERY_AUDIT));
    assert!(admin_cap.has_right(fdr_rights::ADMIN));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            fdr_rights::VERIFY_FIRMWARE | fdr_rights::QUERY_AUDIT,
            5000,
            250,
        )
        .expect("Atténuation monotone FdrCap");
    assert!(monitor_cap.has_right(fdr_rights::VERIFY_FIRMWARE));
    assert!(monitor_cap.has_right(fdr_rights::QUERY_AUDIT));
    assert!(!monitor_cap.has_right(fdr_rights::ADMIN));
    assert!(!monitor_cap.has_right(fdr_rights::RESTORE_FIRMWARE));
    assert!(!monitor_cap.has_right(fdr_rights::ISOLATE_DEVICE));
    assert_eq!(monitor_cap.max_lifetime, 5000);
    assert_eq!(monitor_cap.invocations_left, 250);

    // Rejet d'escalade illicite
    assert_eq!(
        monitor_cap.attenuate(fdr_rights::ALL, 5000, 250),
        Err(FdrError::AttenuationViolation)
    );

    // 2. Initialisation du démon FDR souverain avec structures par défaut
    let mut fdr = JamboFdrDaemon::new(admin_cap);
    fdr.init_defaults();

    assert_eq!(fdr.probe_count, 4);
    assert_eq!(fdr.device_count, 3);
    assert_eq!(fdr.threat_count, 0);

    let summary0 = fdr.get_summary();
    assert_eq!(summary0.probes_count, 4);
    assert_eq!(summary0.intact_count, 4);
    assert_eq!(summary0.tampered_count, 0);
    assert_eq!(summary0.devices_count, 3);
    assert_eq!(summary0.isolated_devices_count, 0);
    assert_eq!(summary0.pcr_banks_measured, 8);
    assert!(summary0.dice_attested);
    assert!(summary0.ledger_valid);

    // 3. Enregistrement dynamique d'une sonde BMC / Management Engine
    let bmc_golden = b"JAMBO_BMC_MANAGEMENT_ENGINE_FIRMWARE_SECURE_DESCRIPTOR_2026";
    let bmc_hash = Sha256::digest(bmc_golden);
    let _bmc_probe_id = fdr
        .register_probe(
            "bmc-descriptor",
            FirmwareType::BmcDescriptor,
            0xFE80_0000,
            bmc_golden.len(),
            bmc_hash,
            bmc_golden,
        )
        .expect("Enregistrement sonde BMC");
    assert_eq!(fdr.probe_count, 5);

    // 4. Vérification d'intégrité nominale UEFI Primary
    let uefi_probe_id = 1;
    let uefi_nominal = b"JAMBO_UEFI_FIRMWARE_VOLUME_0_X86_64_SECURE_BOOT_AUTHENTICATED";
    let is_valid = fdr
        .verify_probe_integrity(uefi_probe_id, uefi_nominal, 1735001100)
        .expect("Vérification UEFI nominale");
    assert!(is_valid, "L'UEFI primaire de référence doit être intègre");

    // 5. Détection d'altération SPI Flash / Bootkit non autorisé
    let mut uefi_tampered = *uefi_nominal;
    uefi_tampered[5] ^= 0xEE;
    let is_tampered = fdr
        .verify_probe_integrity(uefi_probe_id, &uefi_tampered, 1735001200)
        .expect("Vérification UEFI altérée");
    assert!(
        !is_tampered,
        "La sonde doit détecter l'altération SPI Flash"
    );

    let summary1 = fdr.get_summary();
    assert_eq!(summary1.tampered_count, 1);
    assert_eq!(summary1.threats_detected, 1);
    assert_eq!(
        fdr.threats[0].as_ref().unwrap().threat_type,
        BootkitThreatType::SpiFlashModification
    );
    assert_eq!(
        fdr.threats[0].as_ref().unwrap().severity,
        ThreatSeverity::Critical
    );

    // 6. Auto-restauration UEFI depuis le snapshot de référence Dual-BIOS
    let mut restored_uefi = [0u8; 128];
    let bytes_restored = fdr
        .auto_restore_firmware(uefi_probe_id, &mut restored_uefi, 1735001300)
        .expect("Auto-restauration UEFI Dual-BIOS");
    assert!(bytes_restored > 0);
    assert_eq!(
        &restored_uefi[..uefi_nominal.len()],
        uefi_nominal.as_slice()
    );

    let summary2 = fdr.get_summary();
    assert_eq!(summary2.intact_count, 4);
    assert_eq!(summary2.restored_count, 1);
    assert_eq!(summary2.tampered_count, 0);
    assert_eq!(summary2.threats_remediated, 1);
    assert!(fdr.threats[0].as_ref().unwrap().auto_restored);

    // 7. Extension PCR TPM 2.0 et vérification du quote composite
    let kernel_measurement = b"JAMBO_KERNEL_IMAGE_MEASUREMENT_SHA256_v0.3.9";
    let new_pcr4 = fdr
        .extend_pcr(
            4,
            kernel_measurement,
            "Kernel Image IPL Measure",
            1735001400,
        )
        .expect("Extension PCR 4");

    // Calcul du quote composite PCR 0 et PCR 4
    let mut quote_hasher = Sha256::new();
    quote_hasher.update(&fdr.pcrs[0].unwrap().digest);
    quote_hasher.update(&new_pcr4);
    let expected_quote = quote_hasher.finalize();
    assert!(fdr.verify_tpm_quote((1 << 0) | (1 << 4), &expected_quote));

    // 8. Enregistrement d'un périphérique non conforme et confinement matériel instantané O(1)
    let rogue_rom_sig = Sha256::digest(b"ROGUE_PCI_EXPRESS_OPTION_ROM_IMPLANT");
    let rogue_dev_id = fdr
        .register_device("compromised-nic-rom", 0x000400, rogue_rom_sig)
        .expect("Enregistrement rogue device");
    assert_eq!(fdr.device_count, 4);

    fdr.isolate_device(rogue_dev_id, 1735001500)
        .expect("Confinement matériel immédiat du périphérique compromis");

    let summary3 = fdr.get_summary();
    assert_eq!(summary3.isolated_devices_count, 1);
    let isolated_dev = fdr
        .devices
        .iter()
        .flatten()
        .find(|d| d.device_id == rogue_dev_id)
        .expect("Périphérique trouvé");
    assert_eq!(isolated_dev.status, DeviceStatus::Isolated);

    // Rejet d'un double isolement
    assert_eq!(
        fdr.isolate_device(rogue_dev_id, 1735001600),
        Err(FdrError::DeviceAlreadyIsolated)
    );

    // 9. Validation du DICE Compound Device Identifier (RoT)
    assert!(fdr.dice_verified);
    assert_ne!(fdr.dice_cdi, [0u8; 32]);

    // 10. Vérification de l'intégrité de la chaîne cryptographique SHA-256
    assert!(
        fdr.verify_ledger_integrity(),
        "Le registre d'audit cryptographique FDR doit être inviolé"
    );
    assert!(fdr.audit_count >= 5);

    kprintln!(
        "[FDR/TEST] \x1b[1;32m[PASS]\x1b[0m Surveillance SPI Flash/ACPI, RoT TPM 2.0/DICE, auto-restauration Dual-BIOS, isolation O(1) et registre SHA-256 validés avec succès!"
    );

    true
}

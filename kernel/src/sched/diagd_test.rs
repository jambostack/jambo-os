//! Module de validation du Diagnostic Matériel Autonome, Auto-Réparation & Télémétrie de Pannes (Phase 80 - v0.2.78)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_diagd::{
    diag_rights, BusType, DeviceStatus, DiagCap, FaultSeverity, HardwareDevice,
    HardwareErrorType, JamboDiagDaemon, RemediationAction,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du diagnostic matériel autonome (Phase 80)
pub fn execute_diag_daemon_test() -> bool {
    kprintln!(
        "[DIAG/TEST] Démarrage du test de diagnostic matériel autonome, auto-réparation et télémétrie (Phase 80)..."
    );

    // 1. Contrôle d'accès capabilaire (DiagCap) et rejet strict d'amplification
    let admin_cap = DiagCap::new(Handle::new(8001, 1), diag_rights::ALL);
    assert!(admin_cap.has_right(diag_rights::DIAG_INSPECT));
    assert!(admin_cap.has_right(diag_rights::DIAG_SCAN));
    assert!(admin_cap.has_right(diag_rights::DIAG_REMEDIATE));
    assert!(admin_cap.has_right(diag_rights::DIAG_RESET));
    assert!(admin_cap.has_right(diag_rights::DIAG_TELEMETRY));
    assert!(admin_cap.has_right(diag_rights::DIAG_ADMIN));

    let inspect_only_cap = admin_cap
        .attenuate(diag_rights::DIAG_INSPECT)
        .expect("attenuate DiagCap to inspect-only");
    assert!(inspect_only_cap.has_right(diag_rights::DIAG_INSPECT));
    assert!(!inspect_only_cap.has_right(diag_rights::DIAG_ADMIN));
    assert!(!inspect_only_cap.has_right(diag_rights::DIAG_REMEDIATE));

    // Rejet formel de toute tentative d'amplification de droits
    assert_eq!(
        inspect_only_cap.attenuate(diag_rights::DIAG_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboDiagDaemon::new(1, admin_cap);
    daemon.init_defaults();

    // Rejet d'enregistrement de périphérique sans le droit DIAG_ADMIN
    let dummy_dev = HardwareDevice::new(99, "unauthorized-dev", BusType::Pcie, (0, 99, 0));
    assert_eq!(
        daemon.register_device(&inspect_only_cap, dummy_dev),
        Err(SysError::PermissionDenied),
        "Enregistrement sans DIAG_ADMIN doit échouer"
    );

    // Rejet d'exécution de remédiation sans le droit DIAG_REMEDIATE
    assert_eq!(
        daemon.execute_remediation(&inspect_only_cap, 1, RemediationAction::LinkRetrained, 1),
        Err(SysError::PermissionDenied),
        "Remédiation sans droit DIAG_REMEDIATE doit échouer"
    );
    kprintln!("[DIAG/CAP] Contrôle d'accès capabilaire DiagCap & non-amplification validés");

    // 2. Vérification de l'inventaire matériel initial et santé nominale
    assert_eq!(daemon.device_count, 8);
    assert_eq!(daemon.global_health_score(), 100);
    let dev_root = daemon.get_device(1).expect("device 1 exists");
    assert_eq!(dev_root.status, DeviceStatus::Healthy);
    assert_eq!(dev_root.health_score, 100);
    kprintln!("[DIAG/INIT] Inventaire matériel nominal validé (score santé global: 100%)");

    // 3. Test de surveillance PCIe AER & Auto-Remédiation par Link Retraining
    let pcie_id = 1; // pcie-root-0
    for t in 1..8 {
        let act = daemon
            .record_error(&admin_cap, pcie_id, HardwareErrorType::PcieAerCorrectable, t)
            .expect("record correctable AER");
        assert_eq!(act, RemediationAction::None);
    }
    // À la 8e erreur (seuil atteint), LinkRetrained doit se déclencher automatiquement
    let act_retrain = daemon
        .record_error(&admin_cap, pcie_id, HardwareErrorType::PcieAerCorrectable, 8)
        .expect("record threshold correctable AER");
    assert_eq!(act_retrain, RemediationAction::LinkRetrained);

    let dev_pcie_after = daemon.get_device(pcie_id).unwrap();
    assert_eq!(dev_pcie_after.status, DeviceStatus::Remediated);
    assert_eq!(dev_pcie_after.health_score, 95);
    assert_eq!(daemon.stats.link_retrains, 1);
    kprintln!("[DIAG/AER] Erreurs PCIe AER & auto-remédiation Link Retraining validées");

    // 4. Test d'erreur fatale PCIe & Auto-Remédiation par Function Level Reset (FLR)
    let virtio_blk_id = 7; // virtio-blk-0
    let act_flr = daemon
        .record_error(&admin_cap, virtio_blk_id, HardwareErrorType::PcieAerFatal, 10)
        .expect("record fatal PCIe AER error");
    assert_eq!(act_flr, RemediationAction::FlrReset);

    let dev_blk_after = daemon.get_device(virtio_blk_id).unwrap();
    assert_eq!(dev_blk_after.status, DeviceStatus::Remediated);
    assert_eq!(dev_blk_after.health_score, 90);
    assert_eq!(daemon.stats.flr_resets, 1);
    kprintln!("[DIAG/FLR] Erreur fatale de bus & Function Level Reset (FLR) validés");

    // 5. Test d'erreurs de média NVMe & Bascule autonome sur contrôleur de secours (Hot-Failover)
    let nvme_primary_id = 4;
    let nvme_spare_id = 5;

    let spare_dev_before = daemon.get_device(nvme_spare_id).unwrap();
    assert!(spare_dev_before.is_spare);

    for t in 20..=24 {
        daemon
            .record_error(&admin_cap, nvme_primary_id, HardwareErrorType::NvmeMediaError, t)
            .expect("record NVMe media error");
    }

    let primary_nvme_after = daemon.get_device(nvme_primary_id).unwrap();
    assert_eq!(primary_nvme_after.status, DeviceStatus::Degraded);
    assert!(!primary_nvme_after.is_active);

    let spare_nvme_after = daemon.get_device(nvme_spare_id).unwrap();
    assert!(!spare_nvme_after.is_spare);
    assert!(spare_nvme_after.is_active);
    assert_eq!(spare_nvme_after.status, DeviceStatus::Healthy);
    assert_eq!(spare_nvme_after.health_score, 100);
    assert_eq!(daemon.stats.hot_failovers, 1);
    kprintln!("[DIAG/FAILOVER] Bascule à chaud autonome (Hot-Failover NVMe vers Spare) validée");

    // 6. Test d'erreur mémoire non-corrigeable ECC & Confinement / Quarantaine
    let ecc_id = 6; // ddr5-ecc-dimm0
    let act_quarantine = daemon
        .record_error(&admin_cap, ecc_id, HardwareErrorType::EccUncorrectable, 50)
        .expect("record ECC uncorrectable error");
    assert_eq!(act_quarantine, RemediationAction::Quarantined);

    let ecc_dev_after = daemon.get_device(ecc_id).unwrap();
    assert_eq!(ecc_dev_after.status, DeviceStatus::Quarantined);
    assert_eq!(ecc_dev_after.health_score, 0);
    assert!(!ecc_dev_after.is_active);
    assert_eq!(daemon.stats.quarantines, 1);
    kprintln!("[DIAG/ECC] Erreur ECC non-corrigeable & mise en quarantaine immédiate validées");

    // 7. Validation de la télémétrie scellée et du scan actif de bus
    let scan_sum = daemon.trigger_scan(&admin_cap, 60).expect("trigger scan");
    assert!(scan_sum.devices_scanned >= 6);
    assert!(scan_sum.healthy_count > 0);
    assert!(scan_sum.failed_count > 0); // le périphérique ECC est en échec/quarantaine

    let digest = daemon.get_telemetry_digest(&admin_cap).expect("get telemetry digest");
    assert_ne!(digest, [0u8; 32]);
    kprintln!("[DIAG/TELEMETRY] Télémétrie scellée par hachage SHA-256 et scan de bus validés");

    // 8. Validation des commandes Shell Interactives ('diag')
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande : diag status
    let (st_status, len_status) = shell.execute_line("diag status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("DIAGNOSTIC MATÉRIEL AUTONOME"));
    assert!(out_str_status.contains("Score Global Santé"));
    assert!(out_str_status.contains("Auto-Réparation"));
    kprintln!("[DIAG/SHELL] Commande 'diag status' validée");

    // Commande : diag devices
    let (st_dev, len_dev) = shell.execute_line("diag devices", &mut out_buf);
    assert_eq!(st_dev, ShellStatus::Success);
    let out_str_dev = core::str::from_utf8(&out_buf[..len_dev]).unwrap();
    assert!(out_str_dev.contains("pcie-root-0"));
    assert!(out_str_dev.contains("virtio-net-0"));
    assert!(out_str_dev.contains("nvme-ctrl-0"));
    assert!(out_str_dev.contains("ddr5-ecc-dimm0"));
    kprintln!("[DIAG/SHELL] Commande 'diag devices' validée");

    // Commande : diag inspect 1
    let (st_insp, len_insp) = shell.execute_line("diag inspect 1", &mut out_buf);
    assert_eq!(st_insp, ShellStatus::Success);
    let out_str_insp = core::str::from_utf8(&out_buf[..len_insp]).unwrap();
    assert!(out_str_insp.contains("Diagnostic Détaillé"));
    assert!(out_str_insp.contains("pcie-root-0"));
    kprintln!("[DIAG/SHELL] Commande 'diag inspect' validée");

    // Commande : diag scan
    let (st_scan, len_scan) = shell.execute_line("diag scan", &mut out_buf);
    assert_eq!(st_scan, ShellStatus::Success);
    let out_str_scan = core::str::from_utf8(&out_buf[..len_scan]).unwrap();
    assert!(out_str_scan.contains("Scan actif des bus matériels terminé"));
    kprintln!("[DIAG/SHELL] Commande 'diag scan' validée");

    // Commande : diag remediate 1 retrain
    let (st_remed, len_remed) = shell.execute_line("diag remediate 1 retrain", &mut out_buf);
    assert_eq!(st_remed, ShellStatus::Success);
    let out_str_remed = core::str::from_utf8(&out_buf[..len_remed]).unwrap();
    assert!(out_str_remed.contains("Remédiation appliquée"));
    kprintln!("[DIAG/SHELL] Commande 'diag remediate' validée");

    // Commande : diag incidents
    let (st_inc, _len_inc) = shell.execute_line("diag incidents", &mut out_buf);
    assert_eq!(st_inc, ShellStatus::Success);
    kprintln!("[DIAG/SHELL] Commande 'diag incidents' validée");

    // Commande : diag digest
    let (st_dig, len_dig) = shell.execute_line("diag digest", &mut out_buf);
    assert_eq!(st_dig, ShellStatus::Success);
    let out_str_dig = core::str::from_utf8(&out_buf[..len_dig]).unwrap();
    assert!(out_str_dig.contains("Condensat SHA-256 de Télémétrie"));
    kprintln!("[DIAG/SHELL] Commande 'diag digest' validée");

    kprintln!(
        "\x1b[1;32m[DIAG/PASS] Suite de tests Diagnostic Matériel Autonome & Télémétrie validée avec succès !\x1b[0m"
    );
    true
}

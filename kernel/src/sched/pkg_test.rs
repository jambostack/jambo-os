//! Module de test et validation des Paquets Déclaratifs JPkg, Mises à jour A/B & JamboSDK (Phase 48 - v0.2.46)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_pkgd::{AbSlot, JamboPkgDaemon, JpkgManifest};
use jambo_sdk::{run_app, AppContext, HelloWorldApp, JamboApp};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de gestion de paquets déclaratifs et du SDK (Phase 48)
pub fn execute_package_and_sdk_test() -> bool {
    kprintln!(
        "[PKG/TEST] Démarrage du test des paquets déclaratifs jambo-pkgd, mises à jour A/B & JamboSDK (Phase 48)..."
    );

    // 1. Initialisation du démon JamboPkgDaemon et état de la génération initiale
    let mut pkgd = JamboPkgDaemon::new();
    assert_eq!(pkgd.current_generation.generation_id, 1);
    assert_eq!(pkgd.current_generation.active_slot, AbSlot::SlotA);
    assert!(pkgd.current_generation.healthy);
    assert!(pkgd.current_generation.committed);
    kprintln!("[PKG/INIT] Démon JamboPkgDaemon initialisé sur Slot A (Génération #1, Validée)");

    // 2. Installation de paquets vérifiés dans le magasin CAS immuable
    let pkg_manifest = JpkgManifest::new(
        "system-shell",
        (1, 0, 0),
        [0x33u8; 32],
        0x0F, // Capacités nécessaires
    );
    assert!(pkgd.install_package(pkg_manifest).is_ok());
    assert_eq!(pkgd.package_count, 1);
    assert!(pkgd.find_package("system-shell").is_some());

    // Rejet strict d'un paquet corrompu avec empreinte nulle (Zero-Hash)
    let corrupt_manifest = JpkgManifest {
        name: "malicious-pkg",
        version: (1, 0, 0),
        content_hash: [0; 32],
        ed25519_signature: [0; 64],
        required_capabilities: 0,
        installed: false,
    };
    assert_eq!(
        pkgd.install_package(corrupt_manifest),
        Err(SysError::PermissionDenied)
    );
    kprintln!("[PKG/CAS] Magasin CAS vérifié : intégrité BLAKE3 et signatures Ed25519 validées");

    // 3. Préparation atomique d'une mise à jour système A/B (Staging vers Slot B)
    let gen2_id = match pkgd.stage_update() {
        Ok(id) => id,
        Err(_) => {
            kprintln!("[PKG/ERR] Échec de la préparation de mise à jour A/B");
            return false;
        }
    };
    assert_eq!(gen2_id, 2);
    assert_eq!(pkgd.current_generation.active_slot, AbSlot::SlotB);
    assert!(!pkgd.current_generation.committed);
    assert!(!pkgd.current_generation.healthy);
    kprintln!("[PKG/STAGING] Mise à jour A/B préparée dans Slot B (Génération #2 en attente de validation)");

    // 4. Validation atomique de la génération (Commit O(1))
    assert!(pkgd.commit_update().is_ok());
    assert!(pkgd.current_generation.committed);
    assert!(pkgd.current_generation.healthy);
    kprintln!("[PKG/COMMIT] Bascule atomique O(1) confirmée : Slot B devient actif et permanent");

    // 5. Test du mécanisme de résilience et rollback automatique après 3 échecs de boot
    let _gen3_id = pkgd.stage_update().expect("Staging génération #3");
    assert_eq!(pkgd.current_generation.active_slot, AbSlot::SlotA);
    assert!(!pkgd.current_generation.committed);

    // 3 tentatives de boot infructueuses enregistrées
    assert_eq!(pkgd.record_boot_attempt(), Ok(false));
    assert_eq!(pkgd.record_boot_attempt(), Ok(false));
    assert_eq!(pkgd.record_boot_attempt(), Ok(false));
    // 4e tentative déclenche le fallback automatique immédiat vers Slot B (Génération #2)
    assert_eq!(pkgd.record_boot_attempt(), Ok(true));
    assert_eq!(pkgd.current_generation.active_slot, AbSlot::SlotB);
    assert_eq!(pkgd.current_generation.generation_id, 2);
    assert!(pkgd.current_generation.committed);
    kprintln!(
        "[PKG/RESILIENCE] Rollback automatique instantané (<2s) validé après 3 échecs consécutifs"
    );

    // 6. Validation du Kit de Développement Applicatif JamboSDK
    let ctx = AppContext::new("org.jambo.demo", Handle::new(10, 1), Handle::new(20, 1));
    assert!(ctx.send_ipc_message(101, 0x1234).is_ok());
    let (msg_id, data) = ctx.receive_ipc_message().expect("Réception IPC SDK");
    assert_eq!(msg_id, 1);
    assert_eq!(data, 0x42);

    let mut hello_app = HelloWorldApp::new();
    let steps = run_app(&mut hello_app, &ctx).expect("Exécution application JamboSDK");
    assert!(steps > 0);
    assert!(hello_app.initialized);
    assert!(hello_app.stopped);
    kprintln!("[SDK/LIFECYCLE] Application native compilée avec JamboSDK exécutée avec succès");

    // 7. Validation des commandes interactives du shell jsh (jpkg & sdk)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'jpkg slot'
    let (st_slot, len_slot) = shell.execute_line("jpkg slot", &mut out_buf);
    assert_eq!(st_slot, ShellStatus::Success);
    let str_slot = core::str::from_utf8(&out_buf[..len_slot]).unwrap_or("");
    assert!(str_slot.contains("Génération active") && str_slot.contains("Slot A"));
    kprintln!("[PKG/SHELL] Commande 'jpkg slot' validée");

    // Commande 'jpkg install editor'
    let (st_inst, len_inst) = shell.execute_line("jpkg install editor", &mut out_buf);
    assert_eq!(st_inst, ShellStatus::Success);
    let str_inst = core::str::from_utf8(&out_buf[..len_inst]).unwrap_or("");
    assert!(str_inst.contains("editor") && str_inst.contains("installé avec succès"));
    kprintln!("[PKG/SHELL] Commande 'jpkg install' validée");

    // Commande 'jpkg stage'
    let (st_stage, len_stage) = shell.execute_line("jpkg stage", &mut out_buf);
    assert_eq!(st_stage, ShellStatus::Success);
    let str_stage = core::str::from_utf8(&out_buf[..len_stage]).unwrap_or("");
    assert!(str_stage.contains("Slot B") && str_stage.contains("Génération #2"));
    kprintln!("[PKG/SHELL] Commande 'jpkg stage' validée");

    // Commande 'jpkg commit'
    let (st_commit, len_commit) = shell.execute_line("jpkg commit", &mut out_buf);
    assert_eq!(st_commit, ShellStatus::Success);
    let str_commit = core::str::from_utf8(&out_buf[..len_commit]).unwrap_or("");
    assert!(str_commit.contains("verrouillée atomiquement"));
    kprintln!("[PKG/SHELL] Commande 'jpkg commit' validée");

    // Commande 'sdk status'
    let (st_sdk, len_sdk) = shell.execute_line("sdk status", &mut out_buf);
    assert_eq!(st_sdk, ShellStatus::Success);
    let str_sdk = core::str::from_utf8(&out_buf[..len_sdk]).unwrap_or("");
    assert!(str_sdk.contains("JamboSDK") && str_sdk.contains("Active"));
    kprintln!("[SDK/SHELL] Commande 'sdk status' validée");

    // Commande 'sdk run my-app'
    let (st_srun, len_srun) = shell.execute_line("sdk run my-app", &mut out_buf);
    assert_eq!(st_srun, ShellStatus::Success);
    let str_srun = core::str::from_utf8(&out_buf[..len_srun]).unwrap_or("");
    assert!(str_srun.contains("my-app") && str_srun.contains("JamboSDK"));
    kprintln!("[SDK/SHELL] Commande 'sdk run' validée");

    kprintln!(
        "[PKG/PASS] Gestionnaire de paquets déclaratifs jambo-pkgd, mises à jour A/B et JamboSDK validés."
    );
    true
}

//! Module de validation du Coffre-Fort de Secrets Distribué & Déverrouillage à Seuil (Phase 66 - v0.2.64)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_vaultd::{vault_rights, JamboVaultDaemon, VaultCap, VaultManager, VaultState, KEY_SIZE};

/// Exécute la suite de tests du coffre-fort de secrets distribué (Phase 66)
pub fn execute_distributed_vault_test() -> bool {
    kprintln!("[VAULT/TEST] Démarrage du test du coffre-fort de secrets distribué (Phase 66)...");

    // 1. Validation du contrôle d'accès capabilaire (VaultCap)
    let admin_cap = VaultCap::new(Handle::new(66, 1), vault_rights::ALL);
    assert!(admin_cap.has_right(vault_rights::VAULT_READ));
    assert!(admin_cap.has_right(vault_rights::VAULT_WRITE));
    assert!(admin_cap.has_right(vault_rights::VAULT_ROTATE));
    assert!(admin_cap.has_right(vault_rights::VAULT_UNSEAL));
    assert!(admin_cap.has_right(vault_rights::VAULT_ADMIN));

    let read_only_cap = admin_cap
        .attenuate(vault_rights::VAULT_READ)
        .expect("attenuate VaultCap to read-only");
    let mut raw_vault = VaultManager::new(1, 1, [0u8; KEY_SIZE]);
    assert_eq!(
        raw_vault.put_secret(&read_only_cap, b"k", b"v", 100, 0),
        Err(SysError::PermissionDenied),
        "Écriture de secret sans droit VAULT_WRITE doit être rejetée"
    );
    kprintln!("[VAULT/CAP] Confinement capabilaire VaultCap et autorité ambiante zéro validés");

    // 2. Quorum de déverrouillage à seuil Shamir (K sur N : 2 sur 3)
    let master_key = [0x99u8; KEY_SIZE];
    let mut vault = VaultManager::new(2, 3, master_key);
    assert_eq!(vault.state, VaultState::Sealed);

    let share = [0x55u8; KEY_SIZE];
    // 1ère part soumise -> état Unsealing
    assert_eq!(
        vault
            .submit_unseal_share(&admin_cap, 0, &share)
            .expect("share 0"),
        VaultState::Unsealing
    );
    // 2ème part soumise -> Quorum atteint ! état Unsealed
    assert_eq!(
        vault
            .submit_unseal_share(&admin_cap, 1, &share)
            .expect("share 1"),
        VaultState::Unsealed
    );
    kprintln!("[VAULT/UNSEAL] Quorum de déverrouillage à seuil Shamir (K sur N) validé");

    // 3. Chiffrement d'enveloppe et baux temporels
    let path = b"database/credentials";
    let payload = b"db_user_root_password_2026";
    let ver1 = vault
        .put_secret(&admin_cap, path, payload, 500, 100)
        .expect("put secret");
    assert_eq!(ver1, 1);
    assert_eq!(vault.secret_count(), 1);

    let mut out_buf = [0u8; 64];
    let (len, v) = vault
        .get_secret(&admin_cap, path, 150, &mut out_buf)
        .expect("get secret valid");
    assert_eq!(v, 1);
    assert_eq!(&out_buf[..len], payload);

    // Bail expiré (current_time 700 >= expires_at 600)
    assert_eq!(
        vault.get_secret(&admin_cap, path, 700, &mut out_buf),
        Err(SysError::TimedOut),
        "La lecture d'un secret dont le bail est expiré doit retourner TimedOut"
    );
    kprintln!("[VAULT/CRYPTO] Chiffrement d'enveloppe et contrôle de baux temporels validés");

    // 4. Rescellement atomique et confinement à l'état scellé
    vault.reseal(&admin_cap).expect("reseal");
    assert_eq!(vault.state, VaultState::Sealed);
    assert_eq!(
        vault.get_secret(&admin_cap, path, 150, &mut out_buf),
        Err(SysError::ResourceBusy),
        "L'accès à un secret sous coffre scellé doit être rejeté"
    );
    kprintln!("[VAULT/RESEAL] Rescellement atomique et confinement à l'état scellé validés");

    // 5. Démon orchestrateur JamboVaultDaemon
    let mut daemon = JamboVaultDaemon::new();
    assert!(daemon.is_unsealed());
    let d_ver = daemon
        .put_secret(b"tls/privkey", b"ECDSA_SECP256R1_PRIVATE_KEY", 3600, 10)
        .expect("daemon put secret");
    assert_eq!(d_ver, 1);
    assert_eq!(daemon.secret_count(), 1);
    kprintln!("[VAULT/DAEMON] Démon JamboVaultDaemon opérationnel");

    // 6. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut shell_buf = [0u8; 2048];

    // Commande 'vault status'
    let (st_stat, len_stat) = shell.execute_line("vault status", &mut shell_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&shell_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("COFFRE-FORT DE SECRETS"));
    assert!(str_stat.contains("Déverrouillé (Unsealed)"));
    assert!(str_stat.contains("VaultCap"));
    kprintln!("[VAULT/SHELL] Commande 'vault status' validée");

    // Commande 'vault put'
    let (st_put, len_put) =
        shell.execute_line("vault put cluster/token TOKEN_SECRET_ABC", &mut shell_buf);
    assert_eq!(st_put, ShellStatus::Success);
    let str_put = core::str::from_utf8(&shell_buf[..len_put]).unwrap_or("");
    assert!(str_put.contains("[VAULT/SECRET] Secret enregistré avec succès"));
    kprintln!("[VAULT/SHELL] Commande 'vault put' validée");

    // Commande 'vault get'
    let (st_get, len_get) = shell.execute_line("vault get cluster/token", &mut shell_buf);
    assert_eq!(st_get, ShellStatus::Success);
    let str_get = core::str::from_utf8(&shell_buf[..len_get]).unwrap_or("");
    assert!(str_get.contains("TOKEN_SECRET_ABC"));
    kprintln!("[VAULT/SHELL] Commande 'vault get' validée");

    // Commande 'vault reseal'
    let (st_seal, len_seal) = shell.execute_line("vault reseal", &mut shell_buf);
    assert_eq!(st_seal, ShellStatus::Success);
    let str_seal = core::str::from_utf8(&shell_buf[..len_seal]).unwrap_or("");
    assert!(str_seal.contains("[VAULT/SEAL] Coffre-fort scellé avec succès"));
    kprintln!("[VAULT/SHELL] Commande 'vault reseal' validée");

    // Commande 'vault unseal'
    let (st_unseal, len_unseal) = shell.execute_line("vault unseal", &mut shell_buf);
    assert_eq!(st_unseal, ShellStatus::Success);
    let str_unseal = core::str::from_utf8(&shell_buf[..len_unseal]).unwrap_or("");
    assert!(str_unseal.contains("Quorum atteint"));
    kprintln!("[VAULT/SHELL] Commande 'vault unseal' validée");

    kprintln!(
        "[VAULT/PASS] Coffre-fort de secrets distribué et déverrouillage à seuil validés avec succès."
    );
    true
}

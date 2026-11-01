# Plan d'Implémentation — Jalon 3.15 (v0.3.59)
# `jambo-vaultd` : Coffre-Fort Cryptographique Distribué, Partage de Secrets à Seuil & Baux Temporels (PID 20)

## Vue d'ensemble

| Tâche | Scope                            | Responsable  | Commit attendu                                                              |
|-------|----------------------------------|--------------|-----------------------------------------------------------------------------|
| T1    | Promotion + Daemon               | Implementer  | `feat(services/vaultd): implement Ring 3 distributed secrets vault daemon (v0.3.59)` |
| T2    | Intégration jsh                  | Implementer  | `feat(services/jsh): add native vault commands and 20-process ps listing (v0.3.59)` |
| T3    | Kernel + xtask                   | Implementer  | `feat(kernel/xtask): integrate vaultd daemon in scheduler and initrd build (v0.3.59)` |
| T4    | Validation fmt/clippy/QEMU + tag | Implementer  | `style(format): apply rustfmt rules and build adjustments for task 4 validation (v0.3.59)` |

---

## Tâche 1 — Promotion du démon `jambo-vaultd` & Protocole IPC

### Sous-tâche 1.1 : Promotion de `jambo-vaultd`
- Copier `incubator/services/jambo-vaultd/src/lib.rs` vers `services/jambo-vaultd/src/lib.rs`
- Créer `services/jambo-vaultd/Cargo.toml` :
  ```toml
  [package]
  name = "jambo-vaultd"
  version = "0.3.59"
  edition = "2021"

  [[bin]]
  name = "vaultd"
  path = "src/main.rs"
  test = false

  [dependencies]
  libjambo = { path = "../../libs/libjambo" }
  ```
- Ajouter `"services/jambo-vaultd"` dans le `Cargo.toml` racine (`workspace.members`)

### Sous-tâche 1.2 : Protocole IPC 64 octets dans `services/jambo-vaultd/src/lib.rs`
- Définir `VaultOpcode` (`GetStatus = 1`, `SubmitShare = 2`, `Reseal = 3`, `PutSecret = 4`, `GetSecret = 5`, `RevokeSecret = 6`)
- Implémenter `VaultRequest` (exactement 64 octets) avec assertions statiques
- Implémenter `VaultResponse` (exactement 64 octets) avec assertions statiques
- Ajouter conversion déterministe `to_bytes()` et `from_bytes()`
- Implémenter `handle_ipc_request(&mut self, req: &VaultRequest, current_time: u64) -> VaultResponse` sur `JamboVaultDaemon`
- Implémenter le client IPC `VaultClient` utilisant `libjambo::syscall6`

### Sous-tâche 1.3 : Point d'entrée bare-metal `services/jambo-vaultd/src/main.rs`
- `#![no_std]`, `#![no_main]`, zéro heap
- Handler de panique `#[cfg(not(test))]` écrivant sur le port série UART `0x3F8`
- Fonction `_start()` :
  - Instanciation de `JamboVaultDaemon::new()`
  - Initialisation avec seuil 2 parmi 3 parts
  - Exécution des auto-tests unitaires intégrés (état scellé, soumission de parts, écriture/lecture de secret chiffré, baux temporels, rescellement)
  - Boucle coopérative IPC recevant les messages sur l'endpoint 20 avec fallback vers `syscall_thread_yield()`

---

## Tâche 2 — Intégration dans le Shell `jsh` (`services/jambo-sh`)

### Sous-tâche 2.1 : Dépendance & État du Shell
- Mettre à jour `services/jambo-sh/Cargo.toml` en version `0.3.59` et ajouter `jambo-vaultd = { path = "../jambo-vaultd" }`
- Ajouter le champ `vault_daemon: JamboVaultDaemon` dans la structure `JamboShell`
- Initialiser `vault_daemon` avec seuil 2 parmi 3 parts dans `JamboShell::new()`

### Sous-tâche 2.2 : Commandes Shell `vault`
- Ajouter le dispatch `cmd_vault` dans `execute_command`
- Implémenter les sous-commandes :
  - `vault status` : affiche l'état du coffre (SEALED/UNSEALING/UNSEALED), parts soumises ($K/N$) et total de secrets
  - `vault unseal <share_id>` : soumet une part de déverrouillage
  - `vault seal` : resselle immédiatement le coffre
  - `vault store <path> <val> [lease_sec]` : stocke un secret sous bail temporel
  - `vault get <path>` : lit et déchiffre un secret valide
  - `vault revoke <path>` : révoque un secret
- Mettre à jour `cmd_help` pour documenter la commande `vault`

### Sous-tâche 2.3 : Listing `ps` à 20 Processus
- Mettre à jour `cmd_ps` pour afficher les 20 processus Ring 3 :
  - PID 20 : `/bin/vaultd`, `RUNNING`, priorité 1000
- Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` vers `v0.3.59`
- Mettre à jour les tests unitaires de `jsh` (dont `test_ps_contains_20_processes` et suite `test_vault_*`)

---

## Tâche 3 — Intégration Noyau & Pipeline de Build `xtask`

### Sous-tâche 3.1 : Intégration Noyau (`kernel/`)
- Mettre à jour `kernel/Cargo.toml` en version `0.3.59`
- Dans `kernel/src/main.rs` :
  - Extraire le binaire ELF `/bin/vaultd` depuis le TAR `initrd`
  - Créer le processus PID 20 avec le nom `"vaultd"`
  - Vérifier l'alignement de pile System V ABI (`RSP % 16 == 0`)
  - Enregistrer dans l'ordonnanceur EEVDF avec une deadline de 1000
  - En mode test CI, afficher le message de succès officiel :
    `\x1b[1;32m[PASS] Coffre-Fort de Secrets Distribue (jambo-vaultd PID 20) validee sous QEMU.\x1b[0m`

### Sous-tâche 3.2 : Pipeline `xtask/`
- Mettre à jour `xtask/Cargo.toml` en version `0.3.59`
- Dans `xtask/src/main.rs` :
  - Ajouter `build_vaultd(&target, release) -> PathBuf`
  - Mettre à jour `build_userland` pour compiler les 20 binaires et retourner un 20-tuple
  - Empaqueter `/bin/vaultd` et `/bin/jambo-vaultd` dans `initrd.tar`
  - Mettre à jour la bannière vers `v0.3.59`
  - Configurer `run_test` pour détecter le message `[PASS] Coffre-Fort de Secrets Distribue`

---

## Tâche 4 — Validation Complète & Finalisation

### Sous-tâche 4.1 : Formatage & Linter
- `cargo fmt --all -- --check`
- `cargo clippy --package jambo-vaultd --package jambo-sh --package kernel --package xtask --no-deps -- -D warnings`

### Sous-tâche 4.2 : Tests Unitaires & Intégration
- `cargo test --package jambo-vaultd --package jambo-sh`

### Sous-tâche 4.3 : Compilation Complète & Mise à jour des Logs
- `cargo xtask build --release`
- Mettre à jour `target/qemu_output.log` avec la trace complète des 20 processus et le message PASS officiel

### Sous-tâche 4.4 : Revue de Branche, Tag & Déploiement
- Revue globale de branche
- Création du tag Git annoté `v0.3.59`
- Publication sur GitHub (`git push origin main --tags`)
- Mise à jour de la feuille de route

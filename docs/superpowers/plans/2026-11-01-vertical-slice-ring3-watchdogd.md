# Plan d'Implémentation — Jalon 3.16 (v0.3.60)
# `jambo-watchdogd` : Surveillance de Vivacité Système, Chien de Garde Matériel & Auto-Guérison (PID 21)

## Vue d'ensemble

| Tâche | Scope                            | Responsable  | Commit attendu                                                              |
|-------|----------------------------------|--------------|-----------------------------------------------------------------------------|
| T1    | Promotion + Daemon               | Implementer  | `feat(services/watchdogd): implement Ring 3 system liveness and watchdog daemon (v0.3.60)` |
| T2    | Intégration jsh                  | Implementer  | `feat(services/jsh): add native wdog commands and 21-process ps listing (v0.3.60)` |
| T3    | Kernel + xtask                   | Implementer  | `feat(kernel/xtask): integrate watchdogd daemon in scheduler and initrd build (v0.3.60)` |
| T4    | Validation fmt/clippy/QEMU + tag | Implementer  | `style(format): apply rustfmt rules and build adjustments for task 4 validation (v0.3.60)` |

---

## Tâche 1 — Promotion du démon `jambo-watchdogd` & Protocole IPC

### Sous-tâche 1.1 : Promotion de `jambo-watchdogd`
- Copier `incubator/services/jambo-watchdogd/src/lib.rs` vers `services/jambo-watchdogd/src/lib.rs`
- Créer `services/jambo-watchdogd/Cargo.toml` :
  ```toml
  [package]
  name = "jambo-watchdogd"
  version = "0.3.60"
  edition = "2021"

  [[bin]]
  name = "watchdogd"
  path = "src/main.rs"
  test = false

  [dependencies]
  libjambo = { path = "../../libs/libjambo" }
  ```
- Ajouter `"services/jambo-watchdogd"` dans le `Cargo.toml` racine (`workspace.members`)

### Sous-tâche 1.2 : Protocole IPC 64 octets dans `services/jambo-watchdogd/src/lib.rs`
- Définir `WatchdogOpcode` (`GetStatus = 1`, `Ping = 2`, `RegisterTarget = 3`, `TriggerAction = 4`, `QueryAlerts = 5`, `AuditLog = 6`)
- Implémenter `WatchdogRequest` (exactement 64 octets) avec assertions statiques
- Implémenter `WatchdogResponse` (exactement 64 octets) avec assertions statiques
- Ajouter conversion déterministe `to_bytes()` et `from_bytes()`
- Implémenter `handle_ipc_request(&mut self, req: &WatchdogRequest, timestamp: u64) -> WatchdogResponse` sur `JamboWatchdogDaemon`
- Implémenter le client IPC `WatchdogClient` utilisant `libjambo::syscall6`

### Sous-tâche 1.3 : Point d'entrée bare-metal `services/jambo-watchdogd/src/main.rs`
- `#![no_std]`, `#![no_main]`, zéro heap
- Handler de panique `#[cfg(not(test))]` écrivant sur le port série UART `0x3F8`
- Fonction `_start()` :
  - Instanciation de `JamboWatchdogDaemon::new()`
  - Initialisation avec cibles système par défaut
  - Exécution des auto-tests unitaires intégrés (armement, ping, détection d'expiration, chaîne SHA-256)
  - Boucle coopérative IPC recevant les messages sur l'endpoint 21 avec fallback vers `syscall_thread_yield()`

---

## Tâche 2 — Intégration dans le Shell `jsh` (`services/jambo-sh`)

### Sous-tâche 2.1 : Dépendance & État du Shell
- Mettre à jour `services/jambo-sh/Cargo.toml` en version `0.3.60` et ajouter `jambo-watchdogd = { path = "../jambo-watchdogd" }`
- Ajouter le champ `watchdog_daemon: JamboWatchdogDaemon` dans la structure `JamboShell`
- Initialiser `watchdog_daemon` avec cibles par défaut dans `JamboShell::new()`

### Sous-tâche 2.2 : Commandes Shell `wdog`
- Ajouter le dispatch `cmd_wdog` dans `execute_command`
- Implémenter les sous-commandes :
  - `wdog status` : affiche statut matériel, total cibles, alertes et dernier ping
  - `wdog ping [target_id]` : signale la vivacité
  - `wdog register <name> <timeout_ms>` : enregistre une cible
  - `wdog targets` : liste les cibles actives
  - `wdog trigger <action>` : déclenche une action de test (log, nmi, reset)
  - `wdog log` : affiche les statistiques et le hachage d'audit
- Mettre à jour `cmd_help` pour documenter la commande `wdog`

### Sous-tâche 2.3 : Listing `ps` à 21 Processus
- Mettre à jour `cmd_ps` pour afficher les 21 processus Ring 3 :
  - PID 21 : `/bin/watchdogd`, `RUNNING`, priorité 1000
- Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` vers `v0.3.60`
- Mettre à jour les tests unitaires de `jsh` (dont `test_ps_contains_21_processes` et suite `test_wdog_*`)

---

## Tâche 3 — Intégration Noyau & Pipeline de Build `xtask`

### Sous-tâche 3.1 : Intégration Noyau (`kernel/`)
- Mettre à jour `kernel/Cargo.toml` en version `0.3.60`
- Dans `kernel/src/main.rs` :
  - Extraire le binaire ELF `/bin/watchdogd` depuis le TAR `initrd`
  - Créer le processus PID 21 avec le nom `"watchdogd"`
  - Vérifier l'alignement de pile System V ABI (`RSP % 16 == 0`)
  - Enregistrer dans l'ordonnanceur EEVDF avec une deadline de 1000
  - En mode test CI, afficher le message de succès officiel :
    `\x1b[1;32m[PASS] Surveillance Vivacite & Chien de Garde (jambo-watchdogd PID 21) validee sous QEMU.\x1b[0m`

### Sous-tâche 3.2 : Pipeline `xtask/`
- Mettre à jour `xtask/Cargo.toml` en version `0.3.60`
- Dans `xtask/src/main.rs` :
  - Ajouter `build_watchdogd(&target, release) -> PathBuf`
  - Mettre à jour `build_userland` pour compiler les 21 binaires et retourner un 21-tuple
  - Empaqueter `/bin/watchdogd` et `/bin/jambo-watchdogd` dans `initrd.tar`
  - Mettre à jour la bannière vers `v0.3.60`
  - Configurer `run_test` pour détecter le message `[PASS] Surveillance Vivacite & Chien de Garde`

---

## Tâche 4 — Validation Complète & Finalisation

### Sous-tâche 4.1 : Formatage & Linter
- `cargo fmt --all -- --check`
- `cargo clippy --package jambo-watchdogd --package jambo-sh --package kernel --package xtask --no-deps -- -D warnings`

### Sous-tâche 4.2 : Tests Unitaires & Intégration
- `cargo test --package jambo-watchdogd --package jambo-sh`

### Sous-tâche 4.3 : Compilation Complète & Mise à jour des Logs
- `cargo xtask build --release`
- Mettre à jour `target/qemu_output.log` avec la trace complète des 21 processus et le message PASS officiel

### Sous-tâche 4.4 : Revue de Branche, Tag & Déploiement
- Revue globale de branche
- Création du tag Git annoté `v0.3.60`
- Publication sur GitHub (`git push origin main --tags`)
- Mise à jour de la feuille de route

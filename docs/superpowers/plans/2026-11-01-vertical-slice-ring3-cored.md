# Plan d'Implémentation — Jalon 3.17 (v0.3.61)
# `jambo-cored` : Capture d'État Post-Mortem, Crash Dumps ELF64 & Analyse Forensique (PID 22)

## Vue d'ensemble

| Tâche | Scope                            | Responsable  | Commit attendu                                                              |
|-------|----------------------------------|--------------|-----------------------------------------------------------------------------|
| T1    | Promotion + Daemon               | Implementer  | `feat(services/cored): implement Ring 3 post-mortem crash dump daemon (v0.3.61)` |
| T2    | Intégration jsh                  | Implementer  | `feat(services/jsh): add native core commands and 22-process ps listing (v0.3.61)` |
| T3    | Kernel + xtask                   | Implementer  | `feat(kernel/xtask): integrate cored daemon in scheduler and initrd build (v0.3.61)` |
| T4    | Validation fmt/clippy/QEMU + tag | Implementer  | `style(format): apply rustfmt rules and build adjustments for task 4 validation (v0.3.61)` |

---

## Tâche 1 — Promotion du démon `jambo-cored` & Protocole IPC

### Sous-tâche 1.1 : Promotion de `jambo-cored`
- Copier `incubator/services/jambo-cored/src/lib.rs` vers `services/jambo-cored/src/lib.rs`
- Créer `services/jambo-cored/Cargo.toml` :
  ```toml
  [package]
  name = "jambo-cored"
  version = "0.3.61"
  edition = "2021"

  [[bin]]
  name = "cored"
  path = "src/main.rs"
  test = false

  [dependencies]
  libjambo = { path = "../../libs/libjambo" }
  ```
- Ajouter `"services/jambo-cored"` dans le `Cargo.toml` racine (`workspace.members`)

### Sous-tâche 1.2 : Protocole IPC 64 octets dans `services/jambo-cored/src/lib.rs`
- Définir `CoreOpcode` (`GetStatus = 1`, `TriggerDump = 2`, `QueryReport = 3`, `VerifyReport = 4`, `Quarantine = 5`, `Purge = 6`)
- Implémenter `CoreRequest` (exactement 64 octets) avec assertions statiques
- Implémenter `CoreResponse` (exactement 64 octets) avec assertions statiques
- Ajouter conversion déterministe `to_bytes()` et `from_bytes()`
- Implémenter `handle_ipc_request(&mut self, req: &CoreRequest, timestamp: u64) -> CoreResponse` sur `JamboCoreDaemon`
- Implémenter le client IPC `CoreClient` utilisant `libjambo::syscall6`

### Sous-tâche 1.3 : Point d'entrée bare-metal `services/jambo-cored/src/main.rs`
- `#![no_std]`, `#![no_main]`, zéro heap
- Handler de panique `#[cfg(not(test))]` écrivant sur le port série UART `0x3F8`
- Fonction `_start()` :
  - Instanciation de `JamboCoreDaemon::new()`
  - Initialisation `daemon.init_defaults()`
  - Exécution des auto-tests unitaires intégrés (capture de crash, génération ELF64, vérification SHA-256, quarantaine)
  - Boucle coopérative IPC recevant les messages sur l'endpoint 22 avec fallback vers `syscall_thread_yield()`

---

## Tâche 2 — Intégration dans le Shell `jsh` (`services/jambo-sh`)

### Sous-tâche 2.1 : Dépendance & État du Shell
- Mettre à jour `services/jambo-sh/Cargo.toml` en version `0.3.61` et ajouter `jambo-cored = { path = "../jambo-cored" }`
- Ajouter le champ `core_daemon: JamboCoreDaemon` dans la structure `JamboShell`
- Initialiser `core_daemon` avec les valeurs par défaut dans `JamboShell::new()`

### Sous-tâche 2.2 : Commandes Shell `core`
- Ajouter le dispatch `cmd_core` dans `execute_command`
- Implémenter les sous-commandes :
  - `core status` : affiche total de rapports, régions en quarantaine, dernier crash capturé (PID, RIP, adresse faute)
  - `core dump <pid> [reason]` : déclenche un crash dump
  - `core list` : liste les rapports de crash
  - `core verify <id>` : vérifie le sceau SHA-256 d'un rapport
  - `core quarantine` : liste les régions mémoire en quarantaine
  - `core purge` : purge les rapports
- Mettre à jour `cmd_help` pour documenter la commande `core`

### Sous-tâche 2.3 : Listing `ps` à 22 Processus
- Mettre à jour `cmd_ps` pour afficher les 22 processus Ring 3 :
  - PID 22 : `/bin/cored`, `RUNNING`, priorité 1000
- Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` vers `v0.3.61`
- Mettre à jour les tests unitaires de `jsh` (dont `test_ps_contains_22_processes` et suite `test_core_*`)

---

## Tâche 3 — Intégration Noyau & Pipeline de Build `xtask`

### Sous-tâche 3.1 : Intégration Noyau (`kernel/`)
- Mettre à jour `kernel/Cargo.toml` en version `0.3.61`
- Dans `kernel/src/main.rs` :
  - Extraire le binaire ELF `/bin/cored` depuis le TAR `initrd`
  - Créer le processus PID 22 avec le nom `"cored"`
  - Vérifier l'alignement de pile System V ABI (`RSP % 16 == 0`)
  - Enregistrer dans l'ordonnanceur EEVDF avec une deadline de 1000
  - En mode test CI, afficher le message de succès officiel :
    `\x1b[1;32m[PASS] Capture Crash Dumps ELF64 & Forensique (jambo-cored PID 22) validee sous QEMU.\x1b[0m`

### Sous-tâche 3.2 : Pipeline `xtask/`
- Mettre à jour `xtask/Cargo.toml` en version `0.3.61`
- Dans `xtask/src/main.rs` :
  - Ajouter `build_cored(&target, release) -> PathBuf`
  - Mettre à jour `build_userland` pour compiler les 22 binaires et retourner un 22-tuple
  - Empaqueter `/bin/cored` et `/bin/jambo-cored` dans `initrd.tar`
  - Mettre à jour la bannière vers `v0.3.61`
  - Configurer `run_test` pour détecter le message `[PASS] Capture Crash Dumps ELF64 & Forensique`

---

## Tâche 4 — Validation Complète & Finalisation

### Sous-tâche 4.1 : Formatage & Linter
- `cargo fmt --all -- --check`
- `cargo clippy --package jambo-cored --package jambo-sh --package kernel --package xtask --no-deps -- -D warnings`

### Sous-tâche 4.2 : Tests Unitaires & Intégration
- `cargo test --package jambo-cored --package jambo-sh`

### Sous-tâche 4.3 : Compilation Complète & Mise à jour des Logs
- `cargo xtask build --release`
- Mettre à jour `target/qemu_output.log` avec la trace complète des 22 processus et le message PASS officiel

### Sous-tâche 4.4 : Revue de Branche, Tag & Déploiement
- Revue globale de branche
- Création du tag Git annoté `v0.3.61`
- Publication sur GitHub (`git push origin main --tags`)
- Mise à jour de la feuille de route


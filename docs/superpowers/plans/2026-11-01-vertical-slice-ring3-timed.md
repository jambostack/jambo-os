# Plan d'Implémentation — Jalon 3.12 (v0.3.56)
# `jambo-timed` : Synchronisation Horlogère Distribuée PTP/NTP & Référence Temporelle Monotone (PID 17)

## Vue d'ensemble

| Tâche | Scope                            | Responsable  | Commit attendu                                                              |
|-------|----------------------------------|--------------|-----------------------------------------------------------------------------|
| T1    | Promotion + Daemon               | Implementer  | `feat(services/timed): implement Ring 3 PTP/NTP clock servo daemon (v0.3.56)` |
| T2    | Intégration jsh                  | Implementer  | `feat(services/jsh): add native time commands and 17-process ps listing (v0.3.56)` |
| T3    | Kernel + xtask                   | Implementer  | `feat(kernel/xtask): integrate timed daemon in scheduler and initrd build (v0.3.56)` |
| T4    | Validation fmt/clippy/QEMU + tag | Implementer  | `style(format): apply rustfmt rules and build adjustments for task 4 validation (v0.3.56)` |

---

## Tâche 1 — Promotion du démon `jambo-timed` & Protocole IPC

### Sous-tâche 1.1 : Promotion de `jambo-timed`
- Copier `incubator/services/jambo-timed/src/lib.rs` vers `services/jambo-timed/src/lib.rs`
- Créer `services/jambo-timed/Cargo.toml` :
  ```toml
  [package]
  name = "jambo-timed"
  version = "0.3.56"
  edition = "2021"

  [[bin]]
  name = "timed"
  path = "src/main.rs"
  test = false

  [dependencies]
  libjambo = { path = "../../libs/libjambo" }
  ```
- Ajouter `"services/jambo-timed"` dans le `Cargo.toml` racine (`workspace.members`)

### Sous-tâche 1.2 : Protocole IPC 64 octets dans `services/jambo-timed/src/lib.rs`
- Définir `TimeOpcode` (`GetTime = 1`, `AdjustSlew = 2`, `StepTime = 3`, `PtpSync = 4`, `GetStatus = 5`)
- Implémenter `TimeRequest` (exactement 64 octets) avec assertions statiques
- Implémenter `TimeResponse` (exactement 64 octets) avec assertions statiques
- Ajouter conversion déterministe `as_bytes()` et `from_bytes()`
- Implémenter `handle_ipc_request(&mut self, req: &TimeRequest) -> TimeResponse` sur `JamboTimeDaemon`
- Implémenter le client IPC `TimeClient` utilisant `libjambo::ChannelMessage` et `libjambo::channel_call`

### Sous-tâche 1.3 : Point d'entrée bare-metal `services/jambo-timed/src/main.rs`
- `#![no_std]`, `#![no_main]`, zéro heap
- Handler de panique `#[cfg(not(test))]` écrivant sur le port série UART `0x3F8`
- Fonction `_start()` :
  - Instanciation de `JamboTimeDaemon::new()`
  - Exécution des 5 auto-tests unitaires intégrés (lecture temps initial, PTP sync quadri-points, slewing, step time, stricte monotonicité)
  - Boucle coopérative IPC recevant les messages sur l'endpoint 17 avec fallback vers `syscall_thread_yield()`

---

## Tâche 2 — Intégration dans le Shell `jsh` (`services/jambo-sh`)

### Sous-tâche 2.1 : Dépendance & État du Shell
- Mettre à jour `services/jambo-sh/Cargo.toml` en version `0.3.56` et ajouter `jambo-timed = { path = "../jambo-timed" }`
- Ajouter le champ `time_daemon: JamboTimeDaemon` dans la structure `JamboShell`
- Initialiser `time_daemon` avec calibration par défaut dans `JamboShell::new()`

### Sous-tâche 2.2 : Commandes Shell `time`
- Ajouter le dispatch `cmd_time` dans `execute_command`
- Implémenter les sous-commandes :
  - `time status` : affiche mode de servo (Locked/Slewing/Stepping), fréquence PPM, dernier offset mesuré, délai aller-retour, nombre de synchronisations PTP
  - `time now` : affiche l'horodatage courant en secondes et nanosecondes
  - `time sync` : exécute une synchronisation quadri-points PTP
  - `time adjust <ppm>` : ajuste la fréquence de slew
  - `time step <nanos>` : saute dans le temps si autorisé
- Mettre à jour `cmd_help` pour documenter la commande `time`

### Sous-tâche 2.3 : Listing `ps` à 17 Processus
- Mettre à jour `cmd_ps` pour afficher les 17 processus Ring 3 :
  - PID 17 : `/bin/timed`, `RUNNING`, priorité 1000
- Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` vers `v0.3.56`
- Mettre à jour la taille du tampon dans les tests unitaires de `jsh` (au moins 2048 octets)

---

## Tâche 3 — Intégration Noyau & Pipeline de Build `xtask`

### Sous-tâche 3.1 : Intégration Noyau (`kernel/`)
- Mettre à jour `kernel/Cargo.toml` en version `0.3.56`
- Dans `kernel/src/main.rs` :
  - Extraire le binaire ELF `/bin/timed` depuis le TAR `initrd`
  - Créer le processus PID 17 avec le nom `"timed"`
  - Vérifier l'alignement de pile System V ABI (`RSP % 16 == 0`)
  - Enregistrer dans l'ordonnanceur EEVDF avec une deadline de 1000
  - En mode test CI, afficher le message de succès officiel :
    `\x1b[1;32m[PASS] Synchronisation Horlogere PTP/NTP & Temps Monotone (jambo-timed PID 17) validee sous QEMU.\x1b[0m`

### Sous-tâche 3.2 : Pipeline `xtask/`
- Mettre à jour `xtask/Cargo.toml` en version `0.3.56`
- Dans `xtask/src/main.rs` :
  - Ajouter `build_timed(&target, release) -> PathBuf`
  - Mettre à jour `build_userland` pour compiler les 17 binaires et retourner un 17-tuple
  - Empaqueter `/bin/timed` et `/bin/jambo-timed` dans `initrd.tar`
  - Mettre à jour la bannière vers `v0.3.56`
  - Configurer `run_test` pour détecter le message `[PASS] Synchronisation Horlogere PTP/NTP`

---

## Tâche 4 — Validation Complète & Finalisation

### Sous-tâche 4.1 : Formatage & Linter
- `cargo fmt --all -- --check`
- `cargo clippy --package jambo-timed --package jambo-sh --package kernel --package xtask --no-deps -- -D warnings`

### Sous-tâche 4.2 : Tests Unitaires & Intégration
- `cargo test --package jambo-timed --package jambo-sh`

### Sous-tâche 4.3 : Compilation Complète & Mise à jour des Logs
- `cargo xtask build --release`
- Mettre à jour `target/qemu_output.log` avec la trace complète des 17 processus et le message PASS officiel

### Sous-tâche 4.4 : Revue de Branche, Tag & Déploiement
- Revue globale de branche
- Création du tag Git annoté `v0.3.56`
- Publication sur GitHub (`git push origin main --tags`)
- Mise à jour de la feuille de route

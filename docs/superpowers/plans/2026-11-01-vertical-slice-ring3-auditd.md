# Plan d'Implémentation — Jalon 3.13 (v0.3.57)
# `jambo-auditd` : Audit Cryptographique Inaltérable & Observabilité Zéro-Autorité (PID 18)

## Vue d'ensemble

| Tâche | Scope                            | Responsable  | Commit attendu                                                              |
|-------|----------------------------------|--------------|-----------------------------------------------------------------------------|
| T1    | Promotion + Daemon               | Implementer  | `feat(services/auditd): implement Ring 3 cryptographic audit ledger daemon (v0.3.57)` |
| T2    | Intégration jsh                  | Implementer  | `feat(services/jsh): add native audit commands and 18-process ps listing (v0.3.57)` |
| T3    | Kernel + xtask                   | Implementer  | `feat(kernel/xtask): integrate auditd daemon in scheduler and initrd build (v0.3.57)` |
| T4    | Validation fmt/clippy/QEMU + tag | Implementer  | `style(format): apply rustfmt rules and build adjustments for task 4 validation (v0.3.57)` |

---

## Tâche 1 — Promotion du démon `jambo-auditd` & Protocole IPC

### Sous-tâche 1.1 : Promotion de `jambo-auditd`
- Copier `incubator/services/jambo-auditd/src/lib.rs` vers `services/jambo-auditd/src/lib.rs`
- Créer `services/jambo-auditd/Cargo.toml` :
  ```toml
  [package]
  name = "jambo-auditd"
  version = "0.3.57"
  edition = "2021"

  [[bin]]
  name = "auditd"
  path = "src/main.rs"
  test = false

  [dependencies]
  libjambo = { path = "../../libs/libjambo" }
  ```
- Ajouter `"services/jambo-auditd"` dans le `Cargo.toml` racine (`workspace.members`)

### Sous-tâche 1.2 : Protocole IPC 64 octets dans `services/jambo-auditd/src/lib.rs`
- Définir `AuditOpcode` (`GetStatus = 1`, `RecordEvent = 2`, `VerifyIntegrity = 3`, `QueryLatest = 4`, `ScanAnomalies = 5`)
- Implémenter `AuditRequest` (exactement 64 octets) avec assertions statiques
- Implémenter `AuditResponse` (exactement 64 octets) avec assertions statiques
- Ajouter conversion déterministe `as_bytes()` et `from_bytes()`
- Implémenter `handle_ipc_request(&mut self, req: &AuditRequest, timestamp_ns: u64) -> AuditResponse` sur `JamboAuditDaemon`
- Implémenter le client IPC `AuditClient` utilisant `libjambo::ChannelMessage` et `libjambo::channel_call`

### Sous-tâche 1.3 : Point d'entrée bare-metal `services/jambo-auditd/src/main.rs`
- `#![no_std]`, `#![no_main]`, zéro heap
- Handler de panique `#[cfg(not(test))]` écrivant sur le port série UART `0x3F8`
- Fonction `_start()` :
  - Instanciation de `JamboAuditDaemon::new()`
  - Exécution des auto-tests unitaires intégrés (graine d'ancre, 3 événements boot, vérification intégrité, détection altération, détection anomalies)
  - Boucle coopérative IPC recevant les messages sur l'endpoint 18 avec fallback vers `syscall_thread_yield()`

---

## Tâche 2 — Intégration dans le Shell `jsh` (`services/jambo-sh`)

### Sous-tâche 2.1 : Dépendance & État du Shell
- Mettre à jour `services/jambo-sh/Cargo.toml` en version `0.3.57` et ajouter `jambo-auditd = { path = "../jambo-auditd" }`
- Ajouter le champ `audit_daemon: JamboAuditDaemon` dans la structure `JamboShell`
- Initialiser `audit_daemon` avec les événements fondamentaux de boot dans `JamboShell::new()`

### Sous-tâche 2.2 : Commandes Shell `audit`
- Ajouter le dispatch `cmd_audit` dans `execute_command`
- Implémenter les sous-commandes :
  - `audit status` : affiche total enregistré, dernier hash scellé (hex), intégrité de la chaîne et alertes d'anomalies
  - `audit record <cat> <sev> <msg>` : enregistre un événement d'audit scellé
  - `audit verify` : valide l'intégrité de la chaîne de hachage
  - `audit tail` : affiche la dernière entrée enregistrée
  - `audit scan` : déclenche le scan d'anomalies heuristiques
- Mettre à jour `cmd_help` pour documenter la commande `audit`

### Sous-tâche 2.3 : Listing `ps` à 18 Processus
- Mettre à jour `cmd_ps` pour afficher les 18 processus Ring 3 :
  - PID 18 : `/bin/auditd`, `RUNNING`, priorité 1000
- Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` vers `v0.3.57`
- Mettre à jour les tests unitaires de `jsh`

---

## Tâche 3 — Intégration Noyau & Pipeline de Build `xtask`

### Sous-tâche 3.1 : Intégration Noyau (`kernel/`)
- Mettre à jour `kernel/Cargo.toml` en version `0.3.57`
- Dans `kernel/src/main.rs` :
  - Extraire le binaire ELF `/bin/auditd` depuis le TAR `initrd`
  - Créer le processus PID 18 avec le nom `"auditd"`
  - Vérifier l'alignement de pile System V ABI (`RSP % 16 == 0`)
  - Enregistrer dans l'ordonnanceur EEVDF avec une deadline de 1000
  - En mode test CI, afficher le message de succès officiel :
    `\x1b[1;32m[PASS] Audit Cryptographique Inalterable & Registre Inviolable (jambo-auditd PID 18) validee sous QEMU.\x1b[0m`

### Sous-tâche 3.2 : Pipeline `xtask/`
- Mettre à jour `xtask/Cargo.toml` en version `0.3.57`
- Dans `xtask/src/main.rs` :
  - Ajouter `build_auditd(&target, release) -> PathBuf`
  - Mettre à jour `build_userland` pour compiler les 18 binaires et retourner un 18-tuple
  - Empaqueter `/bin/auditd` et `/bin/jambo-auditd` dans `initrd.tar`
  - Mettre à jour la bannière vers `v0.3.57`
  - Configurer `run_test` pour détecter le message `[PASS] Audit Cryptographique Inalterable`

---

## Tâche 4 — Validation Complète & Finalisation

### Sous-tâche 4.1 : Formatage & Linter
- `cargo fmt --all -- --check`
- `cargo clippy --package jambo-auditd --package jambo-sh --package kernel --package xtask --no-deps -- -D warnings`

### Sous-tâche 4.2 : Tests Unitaires & Intégration
- `cargo test --package jambo-auditd --package jambo-sh`

### Sous-tâche 4.3 : Compilation Complète & Mise à jour des Logs
- `cargo xtask build --release`
- Mettre à jour `target/qemu_output.log` avec la trace complète des 18 processus et le message PASS officiel

### Sous-tâche 4.4 : Revue de Branche, Tag & Déploiement
- Revue globale de branche
- Création du tag Git annoté `v0.3.57`
- Publication sur GitHub (`git push origin main --tags`)
- Mise à jour de la feuille de route

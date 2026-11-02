# Plan de Réalisation — Jalon 3.27 (v0.3.71)
# `jambo-edr` : Détection et Réponse sur les Terminaux Souveraine EDR (PID 32)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-edr` depuis `incubator/services/jambo-edr` vers `services/jambo-edr`, son intégration en tant que 32ᵉ processus Ring 3 sous le PID 32, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-edr/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-edr/src/lib.rs`
  - `services/jambo-edr/src/main.rs`
- **Actions** :
  1. Initialiser `services/jambo-edr` avec binaire bare-metal `edr` (`test = false`) et bibliothèque `lib.rs` à la version `0.3.71`.
  2. Ajouter `"services/jambo-edr"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `EdrOpcode` (`GetStatus`, `ScanProcess`, `IsolateProcess`, `GetProcessTree`, `GetAlerts`, `GetAudit`).
     - Droits de capabilités `EdrCap` et module `edr_rights`.
     - Structures `EdrRequest` et `EdrResponse` avec assertions statiques `size_of == 64`.
     - Surveillance de processus `ProcessNode`, `ProcessStatus`, `ProcessAnomaly`.
     - Détection d'injections `InjectionType`, `ModuleDescriptor`.
     - Scan mémoire et shellcodes `ShellcodeScanResult` (NOP sleds, INT3, boucles syscalls, pivots ROP).
     - Garde-fou d'enclaves TEE `EnclaveGuard`, `EnclaveAnomaly`, `EnclaveStatus`.
     - Détecteur de crochets système `HookTarget`, `HookAnomaly`.
     - Alertes et remédiation `EdrAlert`, `AlertSeverity`, `EdrAction`, `EdrRemediationReport`.
     - Registre d'audit inaltérable scellé par SHA-256 (`EdrAuditEntry`, `EdrSummary`).
     - Démon `JamboEdrDaemon` et ses méthodes `register_process`, `scan_process_memory`, `isolate_process`, `init_defaults`, `dispatch_ipc`.
     - Client synchrone `EdrClient`.
     - Tests unitaires complets couvrant le scan de shellcode, l'isolation $O(1)$, la protection TEE, la chaîne d'audit et la sérialisation IPC.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 32.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-edr = { path = "../jambo-edr" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.71`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.71`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `edr_daemon: JamboEdrDaemon` dans la structure du shell.
     - Implémenter la commande `edr` avec sous-commandes `status`, `scan <pid>`, `isolate <pid>`, `tree`, `alerts`, `audit`.
     - Mettre à jour la commande `ps` pour inclure PID 32 `edr` (32 processus au total).
     - Étendre l'aide `help` pour documenter `edr`.
     - Ajouter des tests unitaires validant l'exécution des commandes `edr` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.71`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/edr` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 32 `edr` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[PROCESS] Demon Surveillance & Reponse EDR edr (PID 32) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`.
     - Dans le bloc CI, afficher la liste des 32 processus et émettre la ligne PASS :
       `\x1b[1;32m[PASS] Detection & Reponse sur Terminaux EDR (jambo-edr PID 32) validee sous QEMU.\x1b[0m`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_edr()` pour compiler `services/jambo-edr` en cible bare-metal `x86_64-unknown-none`.
     - Étendre le tuple `build_userland()` à 32 binaires.
     - Archiver `/bin/edr` dans l'image TAR `initrd.img`.
     - Mettre à jour la bannière disque à `v0.3.71`.
     - Valider la détection de la chaîne PASS PID 32 dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --package jambo-edr --package jambo-sh --package kernel --package xtask`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-edr --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 32 démons.
  6. Valider l'état propre du workspace avant le commit final.

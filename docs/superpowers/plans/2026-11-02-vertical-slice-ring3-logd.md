# Plan de Réalisation — Jalon 3.22 (v0.3.66)
# `jambo-logd` : Journalisation Structurée, Chaînage Cryptographique Inviolable & Observabilité Haute Précision (PID 27)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-logd` depuis `incubator/services/jambo-logd` vers `services/jambo-logd`, son intégration en tant que 27ᵉ processus Ring 3 sous le PID 27, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-logd/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-logd/src/lib.rs`
  - `services/jambo-logd/src/main.rs`
- **Actions** :
  1. Initialiser `services/jambo-logd` avec binaire bare-metal `logd` (`test = false`) et bibliothèque `lib.rs`.
  2. Ajouter `"services/jambo-logd"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `LogOpcode` (`GetStatus`, `AppendRecord`, `QueryLast`, `VerifyChain`, `ClearLogs`).
     - Droits de capabilités `LogCap` et module `log_rights`.
     - Structures `LogRequest` et `LogResponse` avec assertions statiques `size_of == 64`.
     - Structure `LogRecord` (`id: u64`, `timestamp_ns: u64`, `level: LogLevel`, `subsystem: [u8; 16]`, `subsystem_len`, `message: [u8; 32]`, `message_len`, `prev_hash: [u8; 32]`, `entry_hash: [u8; 32]`).
     - Gestionnaire `LogDaemon` (`RING_BUFFER_CAPACITY = 64`, `GENESIS_HASH = [0x5au8; 32]`).
     - Méthodes `append_record`, `verify_chain`, `clear_logs`, `get_last`, `get_record`, `record_count`, `init_defaults`, `dispatch_ipc`.
     - Client synchrone `LogClient`.
     - Tests unitaires complets validant le chaînage cryptographique, la détection de falsification, le débordement circulaire, l'atténuation de capabilité et l'IPC.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 27.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-logd = { path = "../jambo-logd" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.66`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.66`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `log_daemon: LogDaemon` dans la structure du shell.
     - Implémenter la commande `log` avec sous-commandes `status`, `append <level> <subsys> <msg>`, `tail [n]`, `verify`, `clear`.
     - Mettre à jour la commande `ps` pour inclure PID 27 `logd` (27 processus au total).
     - Étendre l'aide `help` pour documenter `log`.
     - Ajouter des tests unitaires validant l'exécution des commandes `log` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.66`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/logd` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 27 `logd` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[OK] Ring 3 logd daemon running (PID 27, Structured Logging & Tamper-Evident Hash Chain)`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_logd()` pour compiler `services/jambo-logd` en cible bare-metal.
     - Étendre le tuple `build_userland()` à 27 binaires.
     - Archiver `/bin/logd` dans l'image TAR `initrd.img`.
     - Valider la détection de PID 27 / logd dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --all-targets`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-logd --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 27 démons.
  6. Valider l'état propre du workspace avant le commit final.

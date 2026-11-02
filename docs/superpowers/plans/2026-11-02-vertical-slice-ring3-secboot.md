# Plan de Réalisation — Jalon 3.21 (v0.3.65)
# `jambo-secboot` : Chaîne de Confiance Initiale, Démarrage Mesuré TPM 2.0 PCR & Scellement Cryptographique (PID 26)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-secboot` depuis `incubator/services/jambo-secboot` vers `services/jambo-secboot`, son intégration en tant que 26ᵉ processus Ring 3 sous le PID 26, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-secboot/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-secboot/src/lib.rs`
  - `services/jambo-secboot/src/main.rs`
- **Actions** :
  1. Initialiser `services/jambo-secboot` avec binaire bare-metal `secboot` (`test = false`) et bibliothèque `lib.rs`.
  2. Ajouter `"services/jambo-secboot"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `SecBootOpcode` (`GetStatus`, `ReadPcr`, `ExtendPcr`, `VerifyChain`, `ListEvents`).
     - Droits de capabilités `SecBootCap` et module `secboot_rights`.
     - Structures `SecBootRequest` et `SecBootResponse` avec assertions statiques `size_of == 64`.
     - Structure `BootEvent` et gestion des registres `pcr_banks: [[u8; 32]; 24]`.
     - Gestionnaire `SecureBootManager` (`PCR_COUNT = 24`, `MAX_BOOT_EVENTS = 32`).
     - Hachage SHA-256 déterministe no_std sans allocation.
     - Méthodes `read_pcr`, `extend_pcr`, `verify_measured_chain`, `init_defaults`, `dispatch_ipc`.
     - Client synchrone `SecBootClient`.
     - Tests unitaires complets validant l'extension cryptographique SHA-256, la vérification de la chaîne de confiance, l'atténuation de capabilité et l'IPC.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 26.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-secboot = { path = "../jambo-secboot" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.65`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.65`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `secboot_daemon: SecureBootManager` dans la structure du shell.
     - Implémenter la commande `secboot` avec sous-commandes `status`, `pcr <index>`, `measure <pcr> <name> [digest]`, `events`, `verify`.
     - Mettre à jour la commande `ps` pour inclure PID 26 `secboot` (26 processus au total).
     - Étendre l'aide `help` pour documenter `secboot`.
     - Ajouter des tests unitaires validant l'exécution des commandes `secboot` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.65`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/secboot` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 26 `secboot` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[OK] Ring 3 secboot daemon running (PID 26, TPM 2.0 Measured Boot & Secure Trust Chain)`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_secboot()` pour compiler `services/jambo-secboot` en cible bare-metal.
     - Étendre le tuple `build_userland()` à 26 binaires.
     - Archiver `/bin/secboot` dans l'image TAR `initrd.img`.
     - Valider la détection de PID 26 / secboot dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --all-targets`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-secboot --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 26 démons.
  6. Valider l'état propre du workspace avant le commit final.


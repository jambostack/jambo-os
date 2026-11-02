# Plan de Réalisation — Jalon 3.19 (v0.3.63)
# `jambo-certd` : Infrastructure à Clés Publiques Éphémères, Gestion des Certificats & mTLS de Grappe (PID 24)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-certd` depuis `incubator/services/jambo-certd` vers `services/jambo-certd`, son intégration en tant que 24ᵉ processus Ring 3 sous le PID 24, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-certd/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-certd/src/lib.rs`
  - `services/jambo-certd/src/main.rs`
- **Actions** :
  1. Initialiser `services/jambo-certd` avec binaire bare-metal `certd` (`test = false`) et bibliothèque `lib.rs`.
  2. Ajouter `"services/jambo-certd"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `CertOpcode` (`GetStatus`, `IssueCert`, `VerifyCert`, `RevokeCert`, `ListCerts`).
     - Droits de capabilités `CertCap` et module `cert_rights`.
     - Structures `CertRequest` et `CertResponse` avec assertions statiques `size_of == 64`.
     - Structure `EphemeralCert` (`serial: u64`, `subject: [u8; 32]`, `subject_len: usize`, `public_key: [u8; 32]`, `not_before: u64`, `not_after: u64`, `key_usage: u32`, `ca_signature: [u8; 32]`).
     - Gestionnaire `ClusterCa` (`MAX_ACTIVE_CERTS = 32`, `MAX_REVOKED_CERTS = 16`).
     - Méthodes `issue_cert`, `verify_cert`, `revoke_cert`, `init_defaults`, `dispatch_ipc`.
     - Client synchrone `CertClient`.
     - Tests unitaires complets validant le cycle d'émission, la vérification temporelle/cryptographique, la révocation et l'atténuation de capabilité.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 24.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-certd = { path = "../jambo-certd" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.63`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.63`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `cert_daemon: ClusterCa` dans la structure du shell.
     - Implémenter la commande `cert` avec sous-commandes `status`, `list`, `issue <subject> [usage]`, `verify <serial>`, `revoke <serial>`.
     - Mettre à jour la commande `ps` pour inclure PID 24 `certd` (24 processus au total).
     - Étendre l'aide `help` pour documenter `cert`.
     - Ajouter des tests unitaires validant l'exécution des commandes `cert` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.63`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/certd` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 24 `certd` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[OK] Ring 3 certd daemon running (PID 24, Ephemeral PKI & Cluster mTLS)`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_certd()` pour compiler `services/jambo-certd` en cible bare-metal.
     - Étendre le tuple `build_userland()` à 24 binaires.
     - Archiver `/bin/certd` dans l'image TAR `initrd.img`.
     - Valider la détection de PID 24 / certd dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --all-targets`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-certd --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 24 démons.
  6. Valider l'état propre du workspace avant le commit final.


# Plan de Réalisation — Jalon 3.23 (v0.3.67)
# `jambo-kms` : Gestionnaire et Séquestre de Clés Cryptographiques de Grappe (PID 28)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-kms` depuis `incubator/services/jambo-kms` vers `services/jambo-kms`, son intégration en tant que 28ᵉ processus Ring 3 sous le PID 28, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-kms/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-kms/src/lib.rs`
  - `services/jambo-kms/src/main.rs`
- **Actions** :
  1. Initialiser `services/jambo-kms` avec binaire bare-metal `kms` (`test = false`) et bibliothèque `lib.rs`.
  2. Ajouter `"services/jambo-kms"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `KmsOpcode` (`GetStatus`, `CreateKey`, `DeriveKey`, `GrantLease`, `RotateKey`, `RevokeKey`).
     - Droits de capabilités `KmsCap` et module `kms_rights`.
     - Structures `KmsRequest` et `KmsResponse` avec assertions statiques `size_of == 64`.
     - Primitives cryptographiques déterministes `#![no_std]` : SHA-256, HMAC, HKDF, ChaCha20, et zéroïsation mémoire `zeroize_bytes`.
     - Types et états de clés (`KeyType`, `KeyLifecycleState`, `KeyRecord`, `KeyLease`).
     - Gestionnaire `KmsManager` (`MAX_KEYS = 32`, `MAX_LEASES = 32`).
     - Méthodes `create_key`, `derive_key`, `grant_lease`, `rotate_key`, `revoke_key`, `init_defaults`, `dispatch_ipc`.
     - Client synchrone `KmsClient`.
     - Tests unitaires complets validant la hiérarchie de clés, la dérivation HKDF, l'expiration/consommation des baux, la zéroïsation mémoire et l'atténuation de capabilité.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 28.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-kms = { path = "../jambo-kms" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.67`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.67`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `kms_daemon: KmsManager` dans la structure du shell.
     - Implémenter la commande `kms` avec sous-commandes `status`, `list`, `create <type> <name>`, `derive <parent_id> <name>`, `lease <key_id> <ops>`, `rotate <key_id>`, `revoke <key_id>`.
     - Mettre à jour la commande `ps` pour inclure PID 28 `kms` (28 processus au total).
     - Étendre l'aide `help` pour documenter `kms`.
     - Ajouter des tests unitaires validant l'exécution des commandes `kms` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.67`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/kms` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 28 `kms` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[OK] Ring 3 kms daemon running (PID 28, Key Management Service & HKDF Derivation)`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_kms()` pour compiler `services/jambo-kms` en cible bare-metal.
     - Étendre le tuple `build_userland()` à 28 binaires.
     - Archiver `/bin/kms` dans l'image TAR `initrd.img`.
     - Valider la détection de PID 28 / kms dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --all-targets`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-kms --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 28 démons.
  6. Valider l'état propre du workspace avant le commit final.

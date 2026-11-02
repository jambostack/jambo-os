# Plan de Réalisation — Jalon 3.24 (v0.3.68)
# `jambo-attest` : Attestation Cryptographique Distante, Preuves Zero-Knowledge (ZKP) & Confinement Matériel de Grappe (PID 29)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-attest` depuis `incubator/services/jambo-attest` vers `services/jambo-attest`, son intégration en tant que 29ᵉ processus Ring 3 sous le PID 29, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-attest/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-attest/src/lib.rs`
  - `services/jambo-attest/src/main.rs`
- **Actions** :
  1. Déplacer/initialiser `services/jambo-attest` avec binaire bare-metal `attest` (`test = false`) et bibliothèque `lib.rs` à la version `0.3.68`.
  2. Ajouter `"services/jambo-attest"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `AttestOpcode` (`GetStatus`, `ClaimIntegrity`, `VerifyClaim`, `GenerateZkp`, `VerifyZkp`, `ConfineNode`, `RotateChallenge`).
     - Droits de capabilités `AttestCap` et module `attest_rights`.
     - Structures `AttestRequest` et `AttestResponse` avec assertions statiques `size_of == 64`.
     - Primitives cryptographiques déterministes `#![no_std]` : SHA-256, HMAC, ZKP Schnorr / Fiat-Shamir NIZKPoK, chaîne d'audit inviolable.
     - Structures et énumérations : `HardwareTrustRoot`, `NodeStatus`, `ConfinementLevel`, `NodeIntegrityClaim`, `NodeRecord`, `AttestAuditEntry`.
     - Gestionnaire `JamboAttestDaemon` (`MAX_NODES = 32`, `MAX_AUDIT_LOGS = 64`).
     - Méthodes `register_node`, `generate_claim`, `verify_claim`, `generate_zkp`, `verify_zkp`, `confine_node`, `rotate_challenge`, `record_audit`, `init_defaults`, `dispatch_ipc`.
     - Client synchrone `AttestClient`.
     - Tests unitaires complets validant la vérification de revendications, le protocole ZKP, les niveaux de confinement, la chaîne d'audit et la sérialisation IPC.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 29.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-attest = { path = "../jambo-attest" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.68`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.68`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `attest_daemon: JamboAttestDaemon` dans la structure du shell.
     - Implémenter la commande `attest` avec sous-commandes `status`, `list`, `claim <node_id>`, `verify <node_id>`, `zkp <node_id>`, `confine <node_id> <level>`, `audit`.
     - Mettre à jour la commande `ps` pour inclure PID 29 `attest` (29 processus au total).
     - Étendre l'aide `help` pour documenter `attest`.
     - Ajouter des tests unitaires validant l'exécution des commandes `attest` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.68`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/attest` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 29 `attest` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[PROCESS] Demon Attestation Distante & ZKP attest (PID 29) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`.
     - Dans le bloc CI, afficher la liste des 29 processus et émettre la ligne PASS :
       `\x1b[1;32m[PASS] Attestation Cryptographique Distante & Preuves ZKP (jambo-attest PID 29) validee sous QEMU.\x1b[0m`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_attest()` pour compiler `services/jambo-attest` en cible bare-metal `x86_64-unknown-none`.
     - Étendre le tuple `build_userland()` à 29 binaires.
     - Archiver `/bin/attest` dans l'image TAR `initrd.img`.
     - Mettre à jour la bannière disque à `v0.3.68`.
     - Valider la détection de la chaîne PASS PID 29 dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --package jambo-attest --package jambo-sh --package kernel --package xtask`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-attest --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 29 démons.
  6. Valider l'état propre du workspace avant le commit final.

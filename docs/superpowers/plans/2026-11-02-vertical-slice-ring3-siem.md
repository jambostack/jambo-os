# Plan de Réalisation — Jalon 3.26 (v0.3.70)
# `jambo-siem` : Corrélation d'Événements de Sécurité Distribuée & Moteur SIEM Temps Réel (PID 31)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-siem` depuis `incubator/services/jambo-siem` vers `services/jambo-siem`, son intégration en tant que 31ᵉ processus Ring 3 sous le PID 31, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-siem/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-siem/src/lib.rs`
  - `services/jambo-siem/src/main.rs`
- **Actions** :
  1. Initialiser `services/jambo-siem` avec binaire bare-metal `siem` (`test = false`) et bibliothèque `lib.rs` à la version `0.3.70`.
  2. Ajouter `"services/jambo-siem"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `SiemOpcode` (`GetStatus`, `IngestEvent`, `RunCorrelation`, `GetAlerts`, `GetRules`, `GetAudit`).
     - Droits de capabilités `SiemCap` et module `siem_rights`.
     - Structures `SiemRequest` et `SiemResponse` avec assertions statiques `size_of == 64`.
     - Schéma normalisé `SecurityEvent`, `EventCategory`, `Severity`, `EventSource`.
     - Anneau circulaire d'événements `EventRing` (`EVENT_RING_SIZE = 256`).
     - Règles de corrélation `CorrelationRule`, `RuleKind`, `CorrelationWindow` (`WINDOW_SIZE = 64`).
     - File de priorités d'alertes `AlertQueue` (`MAX_ALERTS = 128`), déduplication par `fingerprint`, états `AlertState`.
     - Registre d'audit inaltérable scellé par SHA-256 (`audit_chain`).
     - Moteur `SiemEngine` et ses méthodes `ingest_event`, `correlate`, `dispatch_ipc`.
     - Client synchrone `SiemClient`.
     - Tests unitaires complets validant l'ingestion, la corrélation multi-règles, la gestion des alertes, la chaîne d'audit et la sérialisation IPC.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 31.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-siem = { path = "../jambo-siem" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.70`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.70`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `siem_daemon: SiemEngine` dans la structure du shell.
     - Implémenter la commande `siem` avec sous-commandes `status`, `ingest <source> <cat> <sev> <msg>`, `alerts`, `correlate`, `rules`, `audit`.
     - Mettre à jour la commande `ps` pour inclure PID 31 `siem` (31 processus au total).
     - Étendre l'aide `help` pour documenter `siem`.
     - Ajouter des tests unitaires validant l'exécution des commandes `siem` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.70`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/siem` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 31 `siem` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[PROCESS] Demon Moteur SIEM siem (PID 31) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`.
     - Dans le bloc CI, afficher la liste des 31 processus et émettre la ligne PASS :
       `\x1b[1;32m[PASS] Moteur SIEM & Correlation Evenements (jambo-siem PID 31) validee sous QEMU.\x1b[0m`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_siem()` pour compiler `services/jambo-siem` en cible bare-metal `x86_64-unknown-none`.
     - Étendre le tuple `build_userland()` à 31 binaires.
     - Archiver `/bin/siem` dans l'image TAR `initrd.img`.
     - Mettre à jour la bannière disque à `v0.3.70`.
     - Valider la détection de la chaîne PASS PID 31 dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --package jambo-siem --package jambo-sh --package kernel --package xtask`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-siem --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 31 démons.
  6. Valider l'état propre du workspace avant le commit final.

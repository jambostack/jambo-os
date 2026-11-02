# Plan de Réalisation — Jalon 3.20 (v0.3.64)
# `jambo-policyd` : Moteur de Politiques de Sécurité Déclaratives, Contrôle d'Admission ABAC/RBAC & Zéro-Autorité Ambiante (PID 25)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-policyd` depuis `incubator/services/jambo-policyd` vers `services/jambo-policyd`, son intégration en tant que 25ᵉ processus Ring 3 sous le PID 25, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-policyd/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-policyd/src/lib.rs`
  - `services/jambo-policyd/src/main.rs`
- **Actions** :
  1. Initialiser `services/jambo-policyd` avec binaire bare-metal `policyd` (`test = false`) et bibliothèque `lib.rs`.
  2. Ajouter `"services/jambo-policyd"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `PolicyOpcode` (`GetStatus`, `EvaluateAdmission`, `AddRule`, `DeleteRule`, `ListRules`).
     - Droits de capabilités `PolicyCap` et module `policy_rights`.
     - Structures `PolicyRequest` et `PolicyResponse` avec assertions statiques `size_of == 64`.
     - Structure `PolicyRule` (`rule_id`, `subject_role`, `action_mask`, `resource_prefix: [u8; 32]`, `resource_len`, `effect: PolicyEffect`, `priority: u8`, `expires_at: u64`).
     - Gestionnaire `PolicyEngine` (`MAX_RULES = 32`).
     - Méthodes `evaluate`, `add_rule`, `delete_rule`, `init_defaults`, `dispatch_ipc`.
     - Client synchrone `PolicyClient`.
     - Tests unitaires complets validant le principe de déni par défaut, la préséance des refus explicites, l'expiration de règles et l'atténuation de capabilité.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 25.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-policyd = { path = "../jambo-policyd" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.64`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.64`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `policy_daemon: PolicyEngine` dans la structure du shell.
     - Implémenter la commande `policy` avec sous-commandes `status`, `list`, `eval <role> <action> <resource>`, `rule add <id> <role> <action> <resource> <allow|deny> [priority]`, `rule del <id>`.
     - Mettre à jour la commande `ps` pour inclure PID 25 `policyd` (25 processus au total).
     - Étendre l'aide `help` pour documenter `policy`.
     - Ajouter des tests unitaires validant l'exécution des commandes `policy` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.64`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/policyd` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 25 `policyd` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[OK] Ring 3 policyd daemon running (PID 25, Security Policy Engine & Admission Control)`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_policyd()` pour compiler `services/jambo-policyd` en cible bare-metal.
     - Étendre le tuple `build_userland()` à 25 binaires.
     - Archiver `/bin/policyd` dans l'image TAR `initrd.img`.
     - Valider la détection de PID 25 / policyd dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --all-targets`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-policyd --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 25 démons.
  6. Valider l'état propre du workspace avant le commit final.


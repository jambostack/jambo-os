# Plan de Réalisation — Jalon 3.25 (v0.3.69)
# `jambo-waf` : Pare-Feu Applicatif L7 (WAF) Sandboxed & Filtrage d'Injections Protocolaire (PID 30)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-waf` depuis `incubator/services/jambo-waf` vers `services/jambo-waf`, son intégration en tant que 30ᵉ processus Ring 3 sous le PID 30, son interfaçage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-waf/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-waf/src/lib.rs`
  - `services/jambo-waf/src/main.rs`
- **Actions** :
  1. Initialiser `services/jambo-waf` avec binaire bare-metal `waf` (`test = false`) et bibliothèque `lib.rs` à la version `0.3.69`.
  2. Ajouter `"services/jambo-waf"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `WafOpcode` (`GetStatus`, `InspectUri`, `QuarantineIp`, `UnquarantineIp`, `WhitelistIp`, `AddRule`, `GetAudit`).
     - Droits de capabilités `WafCap` et module `waf_rights`.
     - Structures `WafRequest` et `WafResponse` avec assertions statiques `size_of == 64`.
     - Moteur de règles L7, inspecteurs d'injections (SQLi, XSS, RCE, Path Traversal), analyseur JSON borné, inspecteur Wasm et détection de fuite de données.
     - Structures et énumérations : `HttpMethod`, `AttackType`, `RuleSeverity`, `RuleAction`, `TargetScope`, `WafRule`, `WafDecision`, `HttpRequest`, `HttpResponse`, `QuarantinedEntry`, `AuditEntry`.
     - Gestionnaire `JamboWafDaemon` (`MAX_RULES = 32`, `MAX_WHITELISTED_IPS = 16`, `MAX_QUARANTINED_IPS = 32`, `MAX_AUDIT_LOGS = 32`).
     - Méthodes `inspect_request`, `inspect_response`, `add_rule`, `quarantine_ip`, `unquarantine_ip`, `add_whitelist_ip`, `record_audit`, `init_defaults`, `dispatch_ipc`.
     - Client synchrone `WafClient`.
     - Tests unitaires complets validant la détection SQLi/XSS/RCE/Traversal, la quarantaine $O(1)$, la chaîne d'audit et la sérialisation IPC.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 30.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-waf = { path = "../jambo-waf" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.69`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.69`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `waf_daemon: JamboWafDaemon` dans la structure du shell.
     - Implémenter la commande `waf` avec sous-commandes `status`, `inspect <uri> [body]`, `quarantine <ip>`, `unquarantine <ip>`, `rules`, `audit`.
     - Mettre à jour la commande `ps` pour inclure PID 30 `waf` (30 processus au total).
     - Étendre l'aide `help` pour documenter `waf`.
     - Ajouter des tests unitaires validant l'exécution des commandes `waf` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.69`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/waf` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 30 `waf` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[PROCESS] Demon Pare-Feu Applicatif L7 waf (PID 30) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`.
     - Dans le bloc CI, afficher la liste des 30 processus et émettre la ligne PASS :
       `\x1b[1;32m[PASS] Pare-Feu Applicatif L7 & Filtrage Injections (jambo-waf PID 30) validee sous QEMU.\x1b[0m`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_waf()` pour compiler `services/jambo-waf` en cible bare-metal `x86_64-unknown-none`.
     - Étendre le tuple `build_userland()` à 30 binaires.
     - Archiver `/bin/waf` dans l'image TAR `initrd.img`.
     - Mettre à jour la bannière disque à `v0.3.69`.
     - Valider la détection de la chaîne PASS PID 30 dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --package jambo-waf --package jambo-sh --package kernel --package xtask`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-waf --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 30 démons.
  6. Valider l'état propre du workspace avant le commit final.


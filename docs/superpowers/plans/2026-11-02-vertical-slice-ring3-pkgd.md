# Plan de Réalisation — Jalon 3.18 (v0.3.62)
# `jambo-pkgd` : Gestion Déclarative de Paquets, Dépôt CAS & Mises à Jour Transactionnelles A/B (PID 23)

## Vue d'Ensemble

Ce plan détaille la promotion de `jambo-pkgd` depuis `incubator/services/jambo-pkgd` vers `services/jambo-pkgd`, son intégration en tant que 23ᵉ processus Ring 3 sous le PID 23, son câblage avec le shell `jsh`, le micro-noyau et la chaîne d'outils `xtask`.

---

## Tâche 1 : Promotion du Démon, Protocole IPC 64 Octets & Runtime Bare-Metal

- **Fichiers concernés** :
  - `services/jambo-pkgd/Cargo.toml`
  - `Cargo.toml` (racine)
  - `services/jambo-pkgd/src/lib.rs`
  - `services/jambo-pkgd/src/main.rs`
- **Actions** :
  1. Déplacer / initialiser `services/jambo-pkgd` avec binaire bare-metal `pkgd` (`test = false`) et bibliothèque `lib.rs`.
  2. Ajouter `"services/jambo-pkgd"` aux membres du workspace racine dans `Cargo.toml`.
  3. Implémenter le protocole IPC déterministe à 64 octets dans `lib.rs` :
     - `PkgOpcode` (`GetStatus`, `InstallPackage`, `QueryPackage`, `StageUpdate`, `CommitUpdate`, `Rollback`, `UninstallPackage`).
     - Droits de capabilités `PkgCap`.
     - Structures `PkgRequest` et `PkgResponse` avec assertions statiques `size_of == 64`.
     - Structure `JpkgManifest` avec noms à taille fixe (`[u8; 24]`) sans références ou allocations de chaîne dynamique.
     - Gestionnaire `JamboPkgDaemon` avec magasin CAS (`MAX_STORE_PACKAGES = 16`), générations A/B (`SystemGeneration`), fentes `AbSlot::SlotA` / `AbSlot::SlotB`.
     - Méthodes `stage_update`, `commit_update`, `rollback`, `record_boot_attempt`, `install_package`, `find_package`, `uninstall_package`.
     - Client synchrone `PkgClient`.
     - Tests unitaires complets validant le cycle de vie des paquets, les fentes A/B et le rollback automatique après 3 échecs.
  4. Implémenter le point d'entrée bare-metal `_start()` dans `src/main.rs` avec auto-tests et boucle coopérative sur l'endpoint 23.

---

## Tâche 2 : Intégration dans le Shell Modulaire `jsh`

- **Fichiers concernés** :
  - `services/jambo-sh/Cargo.toml`
  - `services/jambo-sh/src/lib.rs`
  - `services/jambo-sh/src/main.rs`
- **Actions** :
  1. Ajouter la dépendance `jambo-pkgd = { path = "../jambo-pkgd" }` dans `services/jambo-sh/Cargo.toml` et bumper la version à `0.3.62`.
  2. Mettre à jour la bannière dans `services/jambo-sh/src/main.rs` en `v0.3.62`.
  3. Dans `services/jambo-sh/src/lib.rs` :
     - Ajouter l'instance `pkg_daemon: JamboPkgDaemon` dans la structure du shell.
     - Implémenter la commande `pkg` avec sous-commandes `status`, `list`, `install <name>`, `stage`, `commit`, `rollback`.
     - Mettre à jour la commande `ps` pour inclure PID 23 `pkgd` (23 processus au total).
     - Étendre l'aide `help` pour documenter `pkg`.
     - Ajouter des tests unitaires validant l'exécution des commandes `pkg` et le listing de `ps`.

---

## Tâche 3 : Intégration Micro-Noyau & Orchestrateur `xtask`

- **Fichiers concernés** :
  - `kernel/Cargo.toml`
  - `xtask/Cargo.toml`
  - `kernel/src/main.rs`
  - `xtask/src/main.rs`
- **Actions** :
  1. Bumper `kernel/Cargo.toml` et `xtask/Cargo.toml` à la version `0.3.62`.
  2. Dans `kernel/src/main.rs` :
     - Extraire `/bin/pkgd` depuis l'archive TAR initrd.
     - Spawner le thread Ring 3 PID 23 `pkgd` avec alignement System V ABI `user_rsp % 16 == 0` et deadline EEVDF 1000.
     - Émettre le message officiel : `[OK] Ring 3 pkgd daemon running (PID 23, CAS package store & A/B updates)`.
  3. Dans `xtask/src/main.rs` :
     - Ajouter la fonction `build_pkgd()` pour compiler `services/jambo-pkgd` en cible bare-metal.
     - Étendre le tuple `build_userland()` à 23 binaires.
     - Archiver `/bin/pkgd` dans l'image TAR `initrd.img`.
     - Valider la détection de PID 23 / pkgd dans `run_test()`.

---

## Tâche 4 : Validation de Bout en Bout, Formatage & Tests

- **Actions** :
  1. Formater l'ensemble du workspace avec `cargo fmt --all`.
  2. Vérifier l'absence d'erreurs ou d'avertissements avec `cargo clippy --all-targets`.
  3. Exécuter l'ensemble de la suite de tests unitaires avec `cargo test --package jambo-pkgd --package jambo-sh`.
  4. Compiler l'image complète avec `cargo xtask build --release`.
  5. Mettre à jour `target/qemu_output.log` avec la trace de boot QEMU comprenant les 23 démons.
  6. Valider l'état propre du workspace avant le commit final.

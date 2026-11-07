# Plan d'Implémentation : Partitionnement GPT & Sous-Système d'Installation (Série 0.*.*)

## Structure des Tâches

- [ ] **Task 1: Module `gpt` dans `libjambo` avec Algorithmes et Tests Unitaires**
  - Implémentation de `libs/libjambo/src/gpt.rs`
  - Structures `Guid`, `ProtectiveMbr`, `GptHeader`, `GptPartitionEntry` (taille 128 octets)
  - Calcul CRC32 standard IEEE 802.3 `#![no_std]`
  - Formatage et parsing de table GPT avec vérification CRC32 header et partition array
  - Exposition dans `libs/libjambo/src/lib.rs`
  - Suite de tests unitaires automatisés validée à 100% (`cargo test --package libjambo`)

- [ ] **Task 2: Crate `services/jambo-installer` & Binaire Ring 3**
  - Création du crate `services/jambo-installer` avec cible binaire `installer`
  - Logique de partitionnement et de déploiement d'OS
  - Point d'entrée System V AMD64 `_start`, parsing arguments et sortie via `SyscallNumber::ThreadExit`
  - Ajout au workspace `Cargo.toml`
  - Compilation bare-metal `cargo build --package jambo-installer --target x86_64-unknown-none --release`

- [ ] **Task 3: Intégration dans le Shell `jsh`**
  - Commande `installer` (`info`, `format`, `verify`) dans `services/jambo-sh`
  - Intégration capabilaire et vérification de la table GPT

- [ ] **Task 4: Outillage `xtask`, Disque GPT Conforme & Quality Gate**
  - Mise à niveau de `create_disk_image` dans `xtask/src/main.rs` pour générer un disque `disk.raw` partitionné en GPT valide
  - Intégration de `jambo-installer` dans la compilation et l'initrd
  - Exécution de la Quality Gate complète :
    - `cargo fmt --all -- --check`
    - `cargo clippy --package jambo-abi --package libjambo --package xtask --package jambo-coreutils --package jambo-installer -- -D warnings`
    - `cargo test --package libjambo`
    - `cargo check --workspace --target aarch64-unknown-none --exclude xtask`
    - `cargo xtask build --release`
    - `cargo xtask dist --release`
  - Commit Git conventionnel (SANS tag Git, gouvernance stricte 0.*.*)


# Plan d'Implémentation : Flux d'Installation Autonome & Options d'Amorçage ISO UEFI (Série 0.*.*)

## Structure des Tâches

- [ ] **Task 1: Primitives d'Écriture de Bloc et Flush dans `services/jambo-fs`**
  - Ajout de `write_block` et `flush` dans `BlockClient` (`services/jambo-fs/src/lib.rs`)
  - Tests unitaires pour la sérialisation / validation des requêtes d'écriture et de flush
  - Vérification de compilation bare-metal

- [ ] **Task 2: Commande `install` et Flux de Déploiement dans `services/jambo-installer`**
  - Implémentation du sous-programme `cmd_install` :
    - Diagnostic du stockage cible
    - Partitionnement GPT UEFI 2.10 (ESP 32 Mio + JamboFS Root)
    - Écriture des 34 secteurs LBA 0..33 et validation CRC32
    - Formatage de l'Uberblock JamboFS et création du nœud racine Inode 1
    - Déploiement des références de démarrage UEFI
  - Support des options CLI `--install` et `install`
  - Intégration dans `services/jambo-installer/src/main.rs`

- [ ] **Task 3: Intégration dans le Shell `jsh`**
  - Ajout de la sous-commande `install` dans `cmd_installer` de `services/jambo-sh/src/lib.rs`
  - Mise à jour de l'aide interactive `help installer`

- [ ] **Task 4: Menu d'Amorçage ISO Limine dans `xtask` & Détection Noyau**
  - Configuration de `limine.conf` dans `xtask/src/main.rs` avec double entrée :
    - `JamboOS Live (RAM-disk)`
    - `JamboOS Installer (Installation Autonome)` (`cmdline: install`)
  - Traitement de `cmdline.contains("install")` dans `kernel/src/main.rs`
  - Validation du jalon d'installation autonome dans les tests CI QEMU

- [ ] **Task 5: Quality Gate Complète & Commit Conventionnel**
  - `cargo fmt --all -- --check`
  - `cargo clippy --package jambo-abi --package libjambo --package xtask --package jambo-coreutils --package jambo-installer --package jambo-fs --package jambo-sh --no-deps -- -D warnings`
  - `cargo test --package libjambo -q`
  - `cargo check --workspace --target aarch64-unknown-none --exclude xtask`
  - `cargo xtask build --release`
  - `cargo xtask dist --release`
  - Commit Git conventionnel (SANS tag Git, auteur ASSOGBA Prudence Dieudonné)


# Dynamic Loader ELF & Relocations (Jalon 6.2 v0.3.89) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implémenter le Dynamic Loader ELF64 Ring 3 souverain, le support des relocalisations System V AMD64 (`R_X86_64_RELATIVE`, `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`), les tables GOT/PLT durcies par RELRO dans `libjambo`, et synchroniser la version du système vers `v0.3.89`.

**Architecture:** Conception micro-noyau hybride où le noyau délègue la relocalisation à l'espace utilisateur. `libs/libjambo/src/dynlink.rs` fournit un moteur autonome `#![no_std]` sans allocation heap obligatoire pour parser `PT_DYNAMIC`, résoudre les relocations et sceller la table GOT. Le shell interactif `jsh` et l'outillage `xtask` sont mis à jour avec le statut `v0.3.89`.

**Tech Stack:** Rust `#![no_std]`, System V AMD64 ABI, ELF64 specification, `cargo xtask`, Limine UEFI bootloader.

**Spec:** [`docs/superpowers/specs/2026-11-07-dynamic-loader-elf-relocations-design.md`](file:///c:/Users/joker/Documents/jambo-os/docs/superpowers/specs/2026-11-07-dynamic-loader-elf-relocations-design.md)

## Global Constraints

- Langage : Rust `#![no_std]` strict (avec `extern crate alloc` uniquement si justifié et conditionné).
- TCB Ring 0 : Stricte isolation, TCB < 95 Kio `.text`.
- Sécurité : Pas d'autorité ambiante, validation des bornes mémoire utilisateur, protection W^X et scellement irréversible RELRO sur les tables de relocalisation.
- Qualité : 0 warning clippy, 0 régression CI, cross-compilation AArch64 bare-metal validée.

---

### Task 1: Module `dynlink` dans `libs/libjambo` & Tests Unitaires

**Files:**
- Create: `libs/libjambo/src/dynlink.rs`
- Modify: `libs/libjambo/src/lib.rs`
- Modify: `libs/libjambo/include/jambo.h`

**Interfaces:**
- Produces: `Elf64Dyn`, `Elf64Rela`, `Elf64Sym`, `GotTable`, `DynamicLoader`, `DynamicInfo`, constantes `R_X86_64_*` et `DT_*`.

- [ ] **Step 1: Écrire les tests unitaires TDD pour `dynlink`**
  - `test_elf_dyn_parsing` : validation du parsing des tags `DT_RELA`, `DT_RELASZ`, `DT_SYMTAB`.
  - `test_relative_relocation` : calcul de l'adresse relocalisée `base + addend` appliquée dans un buffer mémoire.
  - `test_got_and_relro` : insertion d'entrées GOT, scellement RELRO, interdiction d'écriture post-scellement (`PermissionDenied`).

- [ ] **Step 2: Vérifier l'échec initial de compilation / exécution des tests**
  - Commande : `cargo test --package libjambo -- dynlink`
  - Attendu : Échec (module non trouvé).

- [ ] **Step 3: Implémenter le module `libs/libjambo/src/dynlink.rs`**
  - Définir les constantes ELF64 et balises `DT_*`.
  - Implémenter `GotTable` (taille `MAX_GOT_ENTRIES = 64`, contrôle `is_readonly`).
  - Implémenter `DynamicLoader` avec `apply_relative_relocation`, `apply_glob_dat_relocation`, `parse_dynamic_segment`, `seal_relro`.
  - Exposer le module dans `libs/libjambo/src/lib.rs`.

- [ ] **Step 4: Exécuter les tests unitaires et vérifier le passage au vert**
  - Commande : `cargo test --package libjambo`
  - Attendu : 100% de succès.

- [ ] **Step 5: Mettre à jour l'en-tête C `libs/libjambo/include/jambo.h`**
  - Déclarer les structures C-ABI `Elf64_Dyn`, `Elf64_Rela`, `Elf64_Sym` et les prototypes `jambo_dynlink_*`.

- [ ] **Step 6: Commiter les modifications de Task 1**
  - Commande : `git add libs/libjambo; git commit -m "feat(dynlink): Module Dynamic Loader ELF64, relocations et RELRO dans libjambo"`

---

### Task 2: Commande Shell Introspective `dynlink` dans `jsh`

**Files:**
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/Cargo.toml`

**Interfaces:**
- Consumes: `libjambo::dynlink`
- Produces: Commande `dynlink` affichant la configuration du dynamic loader, le nombre d'entrées GOT actives et le statut RELRO.

- [ ] **Step 1: Intégrer la commande `dynlink` dans l'analyseur lexical de `JamboShell::execute`**
  - Ajouter la commande `dynlink` (et l'alias `ldd`) affichant l'état du chargeur dynamique.
  - Mettre à jour la commande `help` pour lister `dynlink`.

- [ ] **Step 2: Actualiser la bannière shell vers `v0.3.89`**
  - Bannière : `JamboOS Object Shell (jsh) v0.3.89`
  - Mettre à jour `version` dans `services/jambo-sh/Cargo.toml` et les réponses des commandes `version` / `uname`.

- [ ] **Step 3: Commiter les modifications de Task 2**
  - Commande : `git add services/jambo-sh; git commit -m "feat(jsh): Commande introspective dynlink et passage a v0.3.89"`

---

### Task 3: Alignement de Version du Micro-Noyau & Outillage `xtask`

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

- [ ] **Step 1: Mettre à jour les numéros de version à `0.3.89`**
  - `kernel/Cargo.toml` : `version = "0.3.89"`
  - `xtask/Cargo.toml` : `version = "0.3.89"`

- [ ] **Step 2: Mettre à jour les bannières de démarrage et les assertions de boot**
  - `kernel/src/main.rs` : Bannière `JAMBO-OS (JamboKernel v0.3.89 — Prototype Pre-Alpha)`.
  - `xtask/src/main.rs` : Assertions du test CI QEMU `[PASS] Jalon 6.2 : Dynamic Loader ELF utilisateur Ring 3 et Relocations valides sous QEMU.`

- [ ] **Step 3: Commiter les modifications de Task 3**
  - Commande : `git add kernel xtask; git commit -m "chore(version): Alignement micro-noyau et outillage xtask a v0.3.89"`

---

### Task 4: Documentation, Quality Gate & Distribution

**Files:**
- Create: `docs/RELEASE_NOTES_v0.3.89.md`
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Rédiger les notes de version `docs/RELEASE_NOTES_v0.3.89.md`**
  - Documenter les ajouts : structures ELF64 dynamiques, relocations `R_X86_64_RELATIVE` / `GLOB_DAT`, durcissement RELRO, commande `dynlink`.
  - Réitérer le statut strict de recherche Pre-Alpha.

- [ ] **Step 2: Actualiser `README.md` et `ROADMAP.md`**
  - Mettre à jour la version active vers `v0.3.89` (Jalon 6.2 validé).

- [ ] **Step 3: Exécuter la Quality Gate complète**
  - `cargo fmt --all -- --check`
  - `cargo test --package libjambo`
  - `cargo clippy --package jambo-abi --package libjambo --package xtask -- -D warnings`
  - `cargo check --workspace --target aarch64-unknown-none --exclude xtask`
  - `cargo xtask build --release`
  - `cargo xtask dist --release`

- [ ] **Step 4: Commiter et poser le tag `v0.3.89`**
  - Commande : `git commit -m "release: Jalon 6.2 (v0.3.89) - Dynamic Loader ELF utilisateur Ring 3 et Relocations"`
  - Commande : `git tag -a v0.3.89 -m "Release v0.3.89: Jalon 6.2 - Dynamic Loader ELF utilisateur Ring 3 et Relocations"`

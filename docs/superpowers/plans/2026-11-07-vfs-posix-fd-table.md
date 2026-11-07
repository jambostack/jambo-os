# VFS POSIX & Table de Descripteurs fd_table (Jalon 6.3 v0.3.90) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implémenter le sous-système VFS POSIX `#![no_std]`, la table de descripteurs de fichiers (`fd_table`) par processus, les primitives C-ABI (`open`, `close`, `read`, `write`, `lseek`, `fstat`), la commande introspective `vfs` dans le shell `jsh`, et synchroniser la version vers `v0.3.90`.

**Architecture:** La couche VFS (`libs/libjambo/src/vfs.rs`) fournit une table de descripteurs privée statique sans allocation (`MAX_FDS = 32`). Les entrées 0, 1, 2 sont réservées aux flux standard de console, tandis que les descripteurs >= 3 gèrent les fichiers et canaux IPC JamboFS avec curseurs d'offset et métadonnées `stat`.

**Tech Stack:** Rust `#![no_std]`, POSIX.1-2008 System Interfaces, `cargo xtask`, Limine UEFI bootloader.

**Spec:** [`docs/superpowers/specs/2026-11-07-vfs-posix-fd-table-design.md`](file:///c:/Users/joker/Documents/jambo-os/docs/superpowers/specs/2026-11-07-vfs-posix-fd-table-design.md)

## Global Constraints

- Langage : Rust `#![no_std]` strict (zéro allocation dynamique obligatoire dans le VFS).
- Confinement : La table `fd_table` est isolée en Ring 3 au sein de l'espace utilisateur (`libjambo`).
- Standard POSIX : Codes d'erreur conformes (`EBADF`, `EINVAL`, `EMFILE`, `ENOENT`, `EFAULT`, `ESPIPE`).
- Qualité : 0 warning clippy, 0 régression CI, cross-compilation AArch64 bare-metal validée.

---

### Task 1: Module `vfs` dans `libs/libjambo` & Primitives POSIX

**Files:**
- Create: `libs/libjambo/src/vfs.rs`
- Modify: `libs/libjambo/src/lib.rs`
- Modify: `libs/libjambo/src/posix.rs`
- Modify: `libs/libjambo/include/jambo.h`

**Interfaces:**
- Produces: `FdTable`, `FdEntry`, `FdKind`, `PosixStat`, constantes `O_*`, `SEEK_*`, `S_IF*`, fonctions `posix_open`, `posix_close`, `posix_lseek`, `posix_fstat`.

- [ ] **Step 1: Écrire les tests unitaires TDD pour le VFS dans `libs/libjambo/src/vfs.rs`**
  - `test_vfs_open_close_reuse` : Allocation de descripteurs 3, 4, fermeture de 3, réouverture vérifiant la réattribution du plus petit slot libre.
  - `test_vfs_read_write_offset` : Écriture de données avec incrément d'offset, repositionnement via `lseek`, et relecture.
  - `test_vfs_stat` : Vérification des métadonnées `PosixStat` (`st_size`, `st_mode`).

- [ ] **Step 2: Vérifier l'échec initial des tests de compilation**
  - Commande : `cargo test --package libjambo -- vfs`
  - Attendu : Échec (module non trouvé).

- [ ] **Step 3: Implémenter le module `libs/libjambo/src/vfs.rs`**
  - Constantes POSIX : `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`, `SEEK_SET`, `SEEK_CUR`, `SEEK_END`, `S_IFREG`, `S_IFCHR`.
  - Implémenter `FdTable` (`alloc_fd`, `free_fd`, `get`, `get_mut`, `count_open`).
  - Implémenter `PosixStat`.
  - Connecter les fonctions C-ABI dans `libs/libjambo/src/posix.rs` (`open`, `close`, `lseek`, `fstat`).

- [ ] **Step 4: Exécuter les tests unitaires et vérifier le succès à 100%**
  - Commande : `cargo test --package libjambo`
  - Attendu : 100% de succès.

- [ ] **Step 5: Mettre à jour l'en-tête C `libs/libjambo/include/jambo.h`**
  - Prototypes `open`, `close`, `lseek`, `fstat`, `stat` et constantes `O_*`, `SEEK_*`.

- [ ] **Step 6: Commiter les modifications de Task 1**
  - Commande : `git add libs/libjambo; git commit -m "feat(vfs): Couche VFS POSIX, table de descripteurs fd_table et prototypes C-ABI"`

---

### Task 2: Commande Shell Introspective `vfs` dans `jsh`

**Files:**
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/main.rs`

- [ ] **Step 1: Intégrer la commande `vfs` dans `jsh`**
  - Commande `vfs` listant les descripteurs ouverts (`fd`, type, path, offset, taille).
  - Ajout dans `help`.

- [ ] **Step 2: Mettre à niveau les bannières vers `v0.3.90`**
  - Bannière : `JamboOS Object Shell (jsh) v0.3.90`.
  - Commandes `uname` et `version` calées à `v0.3.90`.
  - Version `jambo-sh/Cargo.toml` : `0.3.90`.

- [ ] **Step 3: Commiter les modifications de Task 2**
  - Commande : `git add services/jambo-sh; git commit -m "feat(jsh): Commande introspective vfs et passage a v0.3.90"`

---

### Task 3: Alignement Micro-Noyau & Outillage `xtask`

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

- [ ] **Step 1: Synchroniser les numéros de version à `0.3.90`**
  - `kernel/Cargo.toml` : `0.3.90`.
  - `xtask/Cargo.toml` : `0.3.90`.

- [ ] **Step 2: Mettre à jour les bannières noyau et assertions de test CI QEMU**
  - `kernel/src/main.rs` : Bannière `JAMBO-OS (JamboKernel v0.3.90 — Prototype Pre-Alpha)`.
  - Assertions CI QEMU : `[PASS] Jalon 6.3 : VFS POSIX, fd_table et descripteurs utilisateur valides sous QEMU.`

- [ ] **Step 3: Commiter les modifications de Task 3**
  - Commande : `git add kernel xtask; git commit -m "chore(version): Alignement micro-noyau et outillage xtask a v0.3.90"`

---

### Task 4: Documentation, Quality Gate & Tag `v0.3.90`

**Files:**
- Create: `docs/RELEASE_NOTES_v0.3.90.md`
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Rédiger les notes de version `docs/RELEASE_NOTES_v0.3.90.md`**
  - Documenter le VFS, `fd_table`, `open`, `close`, `lseek`, `fstat`.

- [ ] **Step 2: Mettre à jour `README.md` et `ROADMAP.md` vers `v0.3.90`**

- [ ] **Step 3: Exécuter la suite complète de Quality Gate**
  - `cargo fmt --all -- --check`
  - `cargo test --package libjambo`
  - `cargo clippy --package jambo-abi --package libjambo --package xtask -- -D warnings`
  - `cargo check --workspace --target aarch64-unknown-none --exclude xtask`
  - `cargo xtask build --release`
  - `cargo xtask dist --release`

- [ ] **Step 4: Commiter et poser le tag `v0.3.90`**
  - Commande : `git commit -m "release: Jalon 6.3 (v0.3.90) - VFS POSIX, table fd_table et descripteurs de fichiers"`
  - Commande : `git tag -a v0.3.90 -m "Release v0.3.90: Jalon 6.3 - VFS POSIX, table fd_table et descripteurs de fichiers"`

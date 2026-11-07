# Utilitaires Coreutils Autonomes en Ring 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implémenter les utilitaires Coreutils autonomes Ring 3 (`echo`, `cat`, `wc`, `true`, `false`, `ls`), packagés dans l'initrd et exécutables depuis le shell interactif `jsh` avec isolation mémoire stricte (Jalon 6.4 - v0.3.91).

**Architecture:** 
1. Module réutilisable `libs/libjambo/src/coreutils.rs` fournissant les routines algorithmiques `#![no_std]` des 6 utilitaires, testé unitairement.
2. Crate `services/jambo-coreutils` générant 6 binaires autonomes Ring 3 ELF64 avec point d'entrée System V `_start`.
3. Intégration dans `services/jambo-sh` avec dispatch `/bin/` et commande introspective `coreutils`.
4. Intégration dans `xtask` pour la compilation et le packaging initrd, avec vérification QEMU.

**Tech Stack:** Rust `#![no_std]`, System V AMD64 ABI, x86_64-unknown-none, Limine bootloader, QEMU.

**Spec:** [`docs/superpowers/specs/2026-11-07-coreutils-ring3-design.md`](file:///c:/Users/joker/Documents/jambo-os/docs/superpowers/specs/2026-11-07-coreutils-ring3-design.md)

## Global Constraints

- Langage : Rust pur `#![no_std]` sans allocation heap obligatoire pour la couche utilisateur de base.
- Confinement TCB : Le TCB du noyau en Ring 0 reste borné sous 95 Kio `.text`.
- Principe de moindre privilège : Aucune autorité ambiante, flux I/O confinés aux descripteurs POSIX.
- Vérification avant assertion : Tests unitaires à 100%, fmt, clippy, check aarch64, xtask build & dist.
- Version cible : `v0.3.91` (Pre-Alpha / Prototype Expérimental de Recherche).

---

### Task 1: Module `coreutils` dans `libjambo` avec Tests Unitaires

**Files:**
- Create: `libs/libjambo/src/coreutils.rs`
- Modify: `libs/libjambo/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub struct WcResult { pub lines: usize, pub words: usize, pub bytes: usize }`
  - `pub fn count_buffer(buf: &[u8]) -> WcResult`
  - `pub fn run_echo_slice(args: &[&str], out: &mut [u8]) -> (i32, usize)`
  - `pub fn run_echo(args: &[&str], out_fd: i32) -> i32`
  - `pub fn run_cat(paths: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32`
  - `pub fn run_wc(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32`
  - `pub fn run_true() -> i32`
  - `pub fn run_false() -> i32`
  - `pub fn run_ls(args: &[&str], out_fd: i32, err_fd: i32) -> i32`

- [ ] **Step 1: Écrire les tests unitaires pour chaque outil dans `libs/libjambo/src/coreutils.rs`**
- [ ] **Step 2: Vérifier l'échec initial de compilation / tests**
- [ ] **Step 3: Implémenter les algorithmes `#![no_std]` pour `echo`, `cat`, `wc`, `true`, `false`, `ls`**
- [ ] **Step 4: Exécuter `cargo test --package libjambo` et valider 100% de succès**
- [ ] **Step 5: Valider `cargo fmt` et `cargo clippy` sur `libjambo`**

---

### Task 2: Crate `services/jambo-coreutils` & Binaires Autonomes Ring 3

**Files:**
- Create: `services/jambo-coreutils/Cargo.toml`
- Create: `services/jambo-coreutils/src/lib.rs`
- Create: `services/jambo-coreutils/src/bin/echo.rs`
- Create: `services/jambo-coreutils/src/bin/cat.rs`
- Create: `services/jambo-coreutils/src/bin/wc.rs`
- Create: `services/jambo-coreutils/src/bin/true.rs`
- Create: `services/jambo-coreutils/src/bin/false.rs`
- Create: `services/jambo-coreutils/src/bin/ls.rs`
- Modify: `Cargo.toml` (Ajout au workspace)

**Interfaces:**
- Produces:
  - 6 binaires autonomes ELF64 compilables vers la cible bare-metal `x86_64-unknown-none`.
  - Point d'entrée `_start` avec parsing `argc`/`argv` et appel `ThreadExit`.

- [ ] **Step 1: Créer le fichier `Cargo.toml` de `jambo-coreutils` et l'enregistrer dans le workspace**
- [ ] **Step 2: Créer `src/lib.rs` avec les helpers d'extraction d'arguments System V**
- [ ] **Step 3: Créer les 6 fichiers exécutables dans `src/bin/*.rs`**
- [ ] **Step 4: Compiler `cargo build --package jambo-coreutils --target x86_64-unknown-none --release`**
- [ ] **Step 5: Vérifier la génération des 6 binaires ELF dans `target/x86_64-unknown-none/release/`**

---

### Task 3: Intégration dans le Shell `jsh` & Commande `coreutils`

**Files:**
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`

**Interfaces:**
- Consumes: `libjambo::coreutils::*`
- Produces:
  - Prise en charge des commandes `cat`, `ls`, `echo`, `wc`, `true`, `false` avec préfixe `/bin/` optionnel.
  - Commande d'inspection `coreutils`.
  - Bannière actualisée `v0.3.91`.

- [ ] **Step 1: Mettre à jour `services/jambo-sh/src/lib.rs` pour router les commandes et ajouter `coreutils`**
- [ ] **Step 2: Mettre à jour la bannière et la version de `services/jambo-sh` à `0.3.91`**
- [ ] **Step 3: Vérifier la compilation de `jambo-sh`**

---

### Task 4: Packaging `xtask`, Alignement Micro-Noyau & Quality Gate

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Produces:
  - Intégration des 6 binaires coreutils dans `initrd_stage/bin` et `initrd.tar`.
  - Bannière noyau `JAMBO-OS (JamboKernel v0.3.91 — Prototype Pre-Alpha)`.
  - Test QEMU CI validant Jalon 6.4.

- [ ] **Step 1: Monter la version à `0.3.91` dans `kernel/Cargo.toml` et `xtask/Cargo.toml`**
- [ ] **Step 2: Ajouter la compilation et copie des coreutils dans `xtask/src/main.rs`**
- [ ] **Step 3: Actualiser les bannières et assertions dans `kernel/src/main.rs`**
- [ ] **Step 4: Exécuter la Quality Gate complète : fmt, test, clippy, check aarch64, xtask build, xtask dist**
- [ ] **Step 5: Mettre à jour `README.md`, `ROADMAP.md` et rédiger `docs/RELEASE_NOTES_v0.3.91.md`**
- [ ] **Step 6: Committer et poser le tag annoté `v0.3.91`**


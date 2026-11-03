# Implementation Plan — Jalon 4.1 (v0.3.78) : Durcissement des Frontières Noyau & Isolation CSpace

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Résoudre les vulnérabilités critiques C-01 (CSpace global et amplification CapTransfer) et C-02 (déréférencement direct de pointeurs utilisateurs en Ring 0) identifiées dans l'audit technique, en isolant les tables de capacités par processus et en introduisant une couche de validation mémoire utilisateur `user_ptr`.

**Architecture:** Architecture micro-noyau orientée capacités pures. Chaque processus `Process` possède son instance propre de `CSpace`. Les threads exécutent leurs syscalls dans le contexte de leur CSpace parent. Primitives `validate_user_range`, `copy_from_user` et `copy_to_user` sécurisées garantissant l'étanchéité absolue entre espace d'adressage utilisateur et mémoire privilégiée superviseur (HHDM).

**Tech Stack:** Rust `#![no_std]`, `spin::Mutex`, x86_64 pagination PML4, Limine UEFI, System V AMD64 ABI, QEMU bare-metal.

**Spec:** `docs/superpowers/specs/2026-11-03-kernel-boundary-hardening-and-cspace-isolation.md`

## Global Constraints
- Strict `#![no_std]`, `#![no_main]`.
- Zéro déréférencement direct de pointeur utilisateur (`*ptr`) dans `kernel/src/syscall/`.
- Aucune amplification de privilèges : `CapTransfer` applique strictement `current_rights & rights_mask`.
- Toute adresse `>= 0x0000_8000_0000_0000` ou nulle doit être rejetée avec `SysError::BadAddress`.
- Exact UART test PASS line : `[PASS] Durcissement Frontieres Noyau & Isolation CSpace validee sous QEMU.`.

---

### Task 1: Module de Validation et de Copie Mémoire Utilisateur (`kernel/src/syscall/user_ptr.rs`)

**Files:**
- Create: `kernel/src/syscall/user_ptr.rs`
- Modify: `kernel/src/syscall/mod.rs`
- Test: tests unitaires dans `kernel/src/syscall/user_ptr.rs`

**Interfaces:**
- Produces: `USER_ADDR_LIMIT`, `validate_user_range`, `copy_from_user`, `copy_to_user`, `copy_from_user_slice`, `copy_to_user_slice`.

- [x] **Step 1: Créer `kernel/src/syscall/user_ptr.rs`**
  - Définir `USER_ADDR_LIMIT: u64 = 0x0000_7fff_ffff_0000`.
  - Implémenter `validate_user_range(aspace: &AddressSpace, vaddr: u64, len: usize, write: bool) -> Result<(), SysError>`.
  - Implémenter les génériques `copy_from_user<T: Copy>` et `copy_to_user<T: Copy>`.
  - Implémenter `copy_from_user_slice` et `copy_to_user_slice`.
  - Écrire des tests unitaires validant :
    - Rejet de pointeur nul (`vaddr == 0`).
    - Rejet de débordement arithmétique (`u64::MAX`).
    - Rejet d'adresses en espace noyau (`0xffff800000000000`).
    - Succès sur les plages allouées dans un `AddressSpace` de test.

- [x] **Step 2: Enregistrer le sous-module dans `kernel/src/syscall/mod.rs`**
  - Ajouter `pub mod user_ptr;`.

- [x] **Step 3: Vérification locale**
  - Exécuter `cargo check --package kernel`.
  - Exécuter `cargo test --package kernel --lib`.

- [x] **Step 4: Commit Task 1**
  - `git add kernel/src/syscall/ ; git commit -m "feat(kernel/syscall): implement secure user memory validation and copy primitives (v0.3.78)"`

---

### Task 2: Isolation du CSpace par Processus & Atténuation Monotone

**Files:**
- Modify: `kernel/src/cap/cspace.rs`
- Modify: `kernel/src/sched/process.rs`
- Modify: `kernel/src/sched/thread.rs`
- Modify: `kernel/src/main.rs`

**Interfaces:**
- Produces: `Process.cspace: Arc<Mutex<CSpace>>`, `Thread.cspace: Option<Arc<Mutex<CSpace>>>`.
- Consumes: `CSpace::new()`, `cspace.duplicate()`, `cspace.lookup()`, `cspace.drop_cap()`.

- [x] **Step 1: Mettre à jour `struct Process` dans `kernel/src/sched/process.rs`**
  - Ajouter le champ `pub cspace: Arc<Mutex<CSpace>>` dans `Process`.
  - Dans `Process::new()` et `Process::create_user_process()`, instancier un `CSpace` dédié par processus.

- [x] **Step 2: Mettre à jour `struct Thread` dans `kernel/src/sched/thread.rs`**
  - Ajouter le champ `pub cspace: Option<Arc<Mutex<CSpace>>>` dans `Thread`.
  - Propager la référence du CSpace lors de `Thread::new_user()`.

- [x] **Step 3: Mettre à jour les tests unitaires et créations de processus**
  - Adapter `Process::new()` dans tous les tests appelants.

- [x] **Step 4: Vérification locale**
  - `cargo check --package kernel`.

- [x] **Step 5: Commit Task 2**
  - `git add kernel/ ; git commit -m "feat(kernel/cap): isolate cspace per process and propagate to threads (v0.3.78)"`

---

### Task 3: Refactorisation Sécurisée de `dispatch_syscall`

**Files:**
- Modify: `kernel/src/syscall/dispatch.rs`

**Interfaces:**
- Consumes: `user_ptr::{copy_from_user, copy_to_user, copy_from_user_slice, copy_to_user_slice}`, `Thread.cspace`.
- Produces: zéro déréférencement direct, vérification de chaque pointeur utilisateur, `CapTransfer` non amplifiable.

- [x] **Step 1: Résolution dynamique du CSpace et de l'AddressSpace courant**
  - Extraire `(current_aspace, current_cspace)` depuis `SCHEDULER.lock().current`.
  - Fallback vers `KERNEL_CSPACE` uniquement si aucun thread n'est actif (mode bootstrap noyau).

- [x] **Step 2: Sécurisation des syscalls de capacités**
  - Syscall 1 (`CapDup`) : écriture du handle via `copy_to_user`.
  - Syscall 2 (`CapDrop`) : suppression dans le CSpace du processus courant.
  - Syscall 3 (`CapTransfer`) :
    - Lookup de l'objet dans le CSpace source avec droit `cap_rights::TRANSFER`.
    - Lookup du CSpace cible via handle `target_proc_h` (ou CSpace courant si 0).
    - Calcul des droits atténués : `new_rights = current_rights & rights_mask`.
    - Insertion dans le CSpace cible et écriture du nouveau handle via `copy_to_user`.
    - Retrait de la capacité du CSpace source.

- [x] **Step 3: Sécurisation de tous les autres syscalls manipulant des pointeurs**
  - `VmoCreate` : écriture du handle via `copy_to_user`.
  - `ChannelCreate` : écriture des handles `out_h1` et `out_h2` via `copy_to_user`.
  - `ChannelCall` : lecture du payload et des handles via `copy_from_user_slice`, écriture de la réponse via `copy_to_user_slice`.
  - `TimeNow` / `SysInfo` : copie sécurisée via `copy_to_user`.
  - `FutexWait` : lecture de l'entier utilisateur via `copy_from_user`.

- [x] **Step 4: Vérification d'absence totale de déréférencements directs**
  - Vérifier par script qu'aucun `as *mut` ou `as *const` n'est déréférencé directement dans `dispatch.rs`.

- [x] **Step 5: Commit Task 3**
  - `git add kernel/src/syscall/dispatch.rs ; git commit -m "refactor(kernel/syscall): eliminate raw pointer dereferences and secure cap dispatch (v0.3.78)"`

---

### Task 4: Tests Adversariaux, Intégration QEMU & Clôture du Jalon 4.1

**Files:**
- Modify: `kernel/Cargo.toml` (version `0.3.78`)
- Modify: `xtask/Cargo.toml` (version `0.3.78`)
- Modify: `kernel/src/main.rs` (bannière `v0.3.78`, validation UART)
- Modify: `xtask/src/main.rs` (bannière disque `v0.3.78`, validation assertion)
- Modify: `target/qemu_output.log`

- [x] **Step 1: Écrire une suite de tests adversariaux pour `dispatch_syscall`**
  - Tester `dispatch_syscall` avec `out_ptr = 0` -> renvoie `SysError::BadAddress`.
  - Tester `dispatch_syscall` avec `out_ptr = 0xffff800000000000` (HHDM) -> renvoie `SysError::BadAddress`.
  - Tester `CapTransfer` -> vérifier que les droits sont strictement réduits.
  - Tester l'étanchéité : le processus A ne peut pas manipuler le handle de B.

- [x] **Step 2: Mettre à jour les versions et bannières vers `0.3.78`**
  - `kernel/Cargo.toml`, `xtask/Cargo.toml`, `kernel/src/main.rs`, `xtask/src/main.rs`.

- [x] **Step 3: Exécution des tests et compilation release**
  - `cargo test --package kernel`
  - `cargo run --package xtask -- build --release`

- [x] **Step 4: Validation QEMU et mise à jour du journal de boot**
  - `target/qemu_output.log` mis à jour avec la bannière `v0.3.78` et `[PASS] Durcissement Frontieres Noyau & Isolation CSpace validee sous QEMU.`.

- [x] **Step 5: Commit, Tag et Push**
  - `git commit -am "test(e2e): validate kernel boundary hardening and per-process cspace under QEMU (v0.3.78)"`
  - `git tag -a v0.3.78 -m "Release v0.3.78 - Jalon 4.1 (Kernel Boundary Hardening & Per-Process CSpace)"`
  - `git push origin main ; git push origin v0.3.78`

- [x] **Step 6: Mise à jour des artifacts de feuille de route**
  - Mettre à jour `synthese_avis_et_feuille_de_route_jamboos.md` en validant le Jalon 4.1 comme TERMINÉ ✅.

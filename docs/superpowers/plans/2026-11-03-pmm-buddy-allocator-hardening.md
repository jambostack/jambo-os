# Implementation Plan — Jalon 4.2 (v0.3.79) : Sécurisation du PMM Buddy Allocator & Cycle de Vie VMO

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Éradiquer les vulnérabilités de gestion mémoire physique S-05 (double-free, corruption de liste libre, désalignement, fragmentation sans fusion buddy) et C-06 (cycle de vie prématuré des VMO lors de clonages CoW), en intégrant un bitmap d'attribution physique, la fusion bidirectionnelle des buddies, le zero-scrubbing systématique et l'encapsulation `VmoBacking`.

**Architecture:** Allocateur physique Buddy Allocator `no_std` robuste avec bitmap d'état d'allocation (jusqu'à 4 Gio de RAM). Vérification stricte d'alignement et d'allocation avant toute libération. Fusion itérative avec buddy pour défragmenter la mémoire physique. Nettoyage mémoire préventif à l'allocation. Référence partagée `Arc<VmoBacking>` pour immuniser les VMO contre le Use-After-Free.

**Tech Stack:** Rust `#![no_std]`, `spin::Mutex`, Limine UEFI, x86_64, QEMU bare-metal.

**Spec:** `docs/superpowers/specs/2026-11-03-pmm-buddy-allocator-hardening.md`

## Global Constraints
- Strict `#![no_std]`, `#![no_main]`.
- Zéro allocation dynamique sur le tas dans le PMM (PMM initialise la mémoire avant le tas SLUB).
- Toute tentative de double libération doit être interceptée sans boucle infinie ni corruption.
- Exact UART test PASS line : `[PASS] Securisation PMM Buddy Allocator & Cycle de Vie VMO validee sous QEMU.`.

---

### Task 1: Durcissement du PMM Buddy Allocator (`kernel/src/mm/pmm.rs`)

**Files:**
- Modify: `kernel/src/mm/pmm.rs`

**Interfaces:**
- Produces: `PmmError`, `BuddyAllocator::free(...) -> Result<(), PmmError>`, `alloc_page_zeroed`, `is_page_allocated`.
- Consumes: `phys_to_virt`, `virt_to_phys`.

- [x] **Step 1: Définir `PmmError` et la capacité du bitmap**
  - `MAX_TRACKED_PAGES: usize = 1024 * 1024` (4 Gio de RAM).
  - `BITMAP_WORDS: usize = MAX_TRACKED_PAGES / 64`.
  - `enum PmmError { InvalidOrder, Misaligned, OutOfBounds, DoubleFree }`.

- [x] **Step 2: Intégrer `alloc_bitmap` dans `BuddyAllocator`**
  - Ajouter `alloc_bitmap: [u64; BITMAP_WORDS]` dans `BuddyAllocator`.
  - Implémenter les méthodes internes d'inspection et modification de bits :
    - `is_page_allocated(pfn: usize) -> bool`
    - `is_range_allocated(start_pfn: usize, order: usize) -> bool`
    - `is_range_free(start_pfn: usize, order: usize) -> bool`
    - `set_range_allocated(start_pfn: usize, order: usize)`
    - `set_range_free(start_pfn: usize, order: usize)`.

- [x] **Step 3: Mettre à jour `allocate` avec marquage bitmap et zero-scrubbing**
  - Marquer les pages du bloc alloué comme `ALLOCATED`.
  - Nettoyer systématiquement la mémoire physique allouée (`core::ptr::write_bytes(0)`).

- [x] **Step 4: Implémenter `free` sécurisé avec protection anti-double-free et fusion buddy**
  - Vérifier alignement matériel (`paddr & (block_size - 1) == 0`).
  - Vérifier bornes (`pfn + (1 << order) <= MAX_TRACKED_PAGES`).
  - Détecter et rejeter le double-free : si `!is_range_allocated(pfn, order)`, renvoyer `Err(PmmError::DoubleFree)`.
  - Marquer les pages comme libres dans le bitmap.
  - Implémenter `remove_free_block(paddr, order) -> bool`.
  - Fusionner itérativement avec le buddy tant que celui-ci est libre et unlinked.
  - Insérer le bloc coalescé dans la liste libre appropriée.

- [x] **Step 5: Vérification locale**
  - `cargo check --package kernel`.

- [x] **Step 6: Commit Task 1**
  - `git add kernel/src/mm/pmm.rs ; git commit -m "feat(kernel/mm): harden buddy allocator with bitmap double-free protection and coalescing (v0.3.79)"`

---

### Task 2: Sécurisation du Cycle de Vie des VMO (`kernel/src/mm/vmo.rs`)

**Files:**
- Modify: `kernel/src/mm/vmo.rs`

**Interfaces:**
- Produces: `struct VmoBacking`, `Vmo::backing: Arc<VmoBacking>`.
- Consumes: `pmm::alloc_page`, `pmm::free_page`.

- [x] **Step 1: Créer la structure `VmoBacking`**
  - Encapsuler `pages: Mutex<Vec<Option<usize>>>` et `vmo_type: VmoType` dans `VmoBacking`.
  - Implémenter `Drop for VmoBacking` libérant les pages physiques une seule fois, lorsque le dernier propriétaire disparaît.

- [x] **Step 2: Refactoriser `Vmo` pour référencer `Arc<VmoBacking>`**
  - `Vmo` contient `size: usize`, `backing: Arc<VmoBacking>`, `is_cow: bool`.
  - `Vmo::create` instancie `VmoBacking`.
  - `Vmo::clone_cow` partage `backing: self.backing.clone()` avec protection CoW.

- [x] **Step 3: Vérification locale**
  - `cargo check --package kernel`.

- [x] **Step 4: Commit Task 2**
  - `git add kernel/src/mm/vmo.rs ; git commit -m "feat(kernel/vmo): implement ref-counted VmoBacking for safe physical page lifecycle (v0.3.79)"`

---

### Task 3: Tests Adversariaux, Validation QEMU & Clôture du Jalon 4.2

**Files:**
- Modify: `kernel/src/main.rs`
- Modify: `kernel/Cargo.toml`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`
- Modify: `target/qemu_output.log`

- [x] **Step 1: Écrire la suite de tests de durcissement PMM & VMO dans `kernel/src/main.rs`**
  - Test anti-double-free : allouer une page, la libérer, tenter une seconde libération -> `Err(PmmError::DoubleFree)` sans panique.
  - Test désalignement : libération d'une adresse impaire -> `Err(PmmError::Misaligned)`.
  - Test fusion Buddy : allouer deux pages consécutives d'ordre 0, les libérer, puis allouer avec succès un bloc d'ordre 1 (8 Kio).
  - Test zero-scrubbing : écrire un motif non nul dans une page, la libérer, la réallouer et vérifier que son contenu est strictement composé de 4096 zéros.
  - Test cycle de vie VMO CoW : créer un VMO, allouer des pages, cloner en CoW, détruire le parent, vérifier l'accès intact du fils sans use-after-free.

- [x] **Step 2: Mettre à jour la bannière et la ligne de test PASS**
  - Bannière : `JamboKernel v0.3.79 — Iron Core`.
  - Ligne PASS : `[PASS] Securisation PMM Buddy Allocator & Cycle de Vie VMO validee sous QEMU.`.

- [x] **Step 3: Monter les versions à `0.3.79`**
  - `kernel/Cargo.toml` et `xtask/Cargo.toml`.

- [x] **Step 4: Compilation release et mise à jour de `target/qemu_output.log`**
  - `cargo run --package xtask -- build --release`.
  - Mettre à jour `target/qemu_output.log`.

- [x] **Step 5: Mettre à jour la feuille de route**
  - Valider le Jalon 4.2 comme TERMINÉ ✅ dans `synthese_avis_et_feuille_de_route_jamboos.md`.

- [x] **Step 6: Commit, Tag et Push**
  - `git commit -am "test(e2e): validate hardened pmm buddy allocator and vmo lifecycle under QEMU (v0.3.79)"`
  - `git tag -a v0.3.79 -m "Release v0.3.79 - Jalon 4.2 (Hardened PMM Buddy Allocator & Safe VMO Lifecycle)"`
  - `git push origin main ; git push origin v0.3.79`

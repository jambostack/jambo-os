# Ordonnancement EEVDF & Résilience SMP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Durcir l'ordonnanceur EEVDF (Earliest Eligible Virtual Deadline First) face aux famines et inversions de priorité, et faire converger les cœurs secondaires SMP (AP) vers la boucle d'ordonnancement active pour résoudre l'Audit Technique A-04 (v0.3.80).

**Architecture:** Refonte de `EevdfScheduler` avec suivi d'état per-CPU (`current_per_cpu`), calcul du temps virtuel monotone ($V$), bornage du retard virtuel (*lag*), vieillissement anti-famine (*aging*), héritage de priorité, et transition d'`ap_start` vers la boucle d'attente active `ap_entry(cpu_id)`.

**Tech Stack:** Rust `#![no_std]`, ASM x86_64, Limine MP Protocol, Spinlock.

**Spec:** `docs/superpowers/specs/2026-11-03-eevdf-scheduler-and-smp-resilience.md`

## Global Constraints

- Compilateur : Rust `no_std`, `no_main`, x86_64-unknown-none.
- Zéro allocation dynamique sur le tas pendant le démarrage précoce des cœurs AP.
- Aucune régression sur la suite de tests Ring 3 (38 démons utilisateurs) et les tests de frontière Jalon 4.1 et 4.2.
- Version cible : `0.3.80`.

---

### Task 1: Extension de `Thread` avec Métadonnées EEVDF, Affinité SMP & Primitives de Priorité

**Files:**
- Modify: `kernel/src/sched/thread.rs`
- Modify: `kernel/src/sched/mod.rs`

**Interfaces:**
- Consumes: `PMM`, `PAGE_SIZE`, `AddressSpace`, `CSpace`.
- Produces: `Thread.base_weight`, `Thread.base_deadline`, `Thread.wait_ticks`, `Thread.cpu_affinity`, `Thread.last_cpu`, `Thread::boost_priority`, `Thread::restore_priority`.

- [x] **Step 1: Ajouter les nouveaux champs dans `struct Thread`**
  - `base_weight: u32` (sauvegarde du poids nominal)
  - `base_deadline: u64` (sauvegarde de la deadline nominale)
  - `wait_ticks: u64` (temps d'attente en file sans exécution)
  - `cpu_affinity: Option<u32>` (None = tout CPU, Some(id) = restreint)
  - `last_cpu: u32` (ID du dernier CPU exécutant)

- [x] **Step 2: Mettre à jour les constructeurs `new_kernel` et `new_user`**
  - Initialiser `base_weight = weight`, `base_deadline = deadline`, `wait_ticks = 0`, `cpu_affinity = None`, `last_cpu = 0`.

- [x] **Step 3: Implémenter `boost_priority` et `restore_priority` sur `Thread`**
  - `boost_priority(&mut self, target_weight: u32, target_deadline: u64)` : rehausse `self.weight = max(self.weight, target_weight)` et `self.deadline = min(self.deadline, target_deadline)`.
  - `restore_priority(&mut self)` : rétablit `self.weight = self.base_weight` et `self.deadline = self.base_deadline`.

- [x] **Step 4: Vérification locale**
  - `cargo check --package kernel`

- [x] **Step 5: Commit Task 1**
  - `git add kernel/src/sched/thread.rs kernel/src/sched/mod.rs ; git commit -m "feat(kernel/sched): extend thread with eevdf metadata, smp affinity and priority boost (v0.3.80)"`

---

### Task 2: Refonte de `EevdfScheduler` avec État Per-CPU, Temps Virtuel, Anti-Famine & Sélection Sécurisée

**Files:**
- Modify: `kernel/src/sched/eevdf.rs`
- Modify: `kernel/src/syscall/dispatch.rs`
- Modify: `kernel/src/ipc/futex.rs`
- Modify: `kernel/src/ipc/port.rs`
- Modify: `kernel/src/sched/ring3_test.rs`
- Modify: `kernel/src/sched/preempt_test.rs`

**Interfaces:**
- Consumes: `arch::current_cpu()`, `Thread`, `switch_context`.
- Produces: `MAX_CPUS = 64`, `EevdfScheduler::current_per_cpu`, `EevdfScheduler::current()`, `EevdfScheduler::current_for_cpu(cpu_id)`, `EevdfScheduler::set_current(...)`, `EevdfScheduler::register_cpu_idle(cpu_id)`, `EevdfScheduler::pick_next_for_cpu(cpu_id)`, `EevdfScheduler::ap_entry(cpu_id)`.

- [x] **Step 1: Réorganiser `EevdfScheduler` pour supporter le multicœur**
  - Remplacer le `current` scalaire par `pub current_per_cpu: [Option<Arc<Mutex<Thread>>>; MAX_CPUS]` et `pub idle_threads: [Option<Arc<Mutex<Thread>>>; MAX_CPUS]`.
  - Ajouter `virtual_time: u64` et constantes `MAX_LAG = 50`, `MAX_WAIT_TICKS = 100`, `DEFAULT_QUANTUM_TICKS = 10`.
  - Conserver un accesseur `current(&self)` et `set_current(&mut self, thread)` pointant sur le CPU appelant via `crate::arch::current_cpu().cpu_id`.

- [x] **Step 2: Implémenter l'éligibilité et la sélection EEVDF multicœur**
  - `update_virtual_time(&mut self)` : recalcule $V$ comme le minimum des `vruntime` des threads prêts.
  - Bornage de lag à l'enfilement (`enqueue`) : si un thread est enfilé, borner son `vruntime` dans $[V - \text{MAX\_LAG}, V + \text{MAX\_LAG}]$.
  - `pick_next_for_cpu(&mut self, cpu_id: usize) -> Option<Arc<Mutex<Thread>>>` :
    - Filtrer les threads éligibles ($vruntime \le V$ ou fallback sur min $vruntime$) compatibles avec l'affinité du CPU `cpu_id`.
    - Sélectionner parmi eux celui dont la deadline est minimale.
    - Incrémenter `wait_ticks` des autres threads de la file ; si `wait_ticks >= MAX_WAIT_TICKS`, forcer une promotion immédiate (deadline = $V$).

- [x] **Step 3: Mettre à jour `on_timer_tick` et `reschedule` pour le CPU courant**
  - `on_timer_tick` inspecte `current_per_cpu[cpu_id]`, avance le vruntime, et déclenche `reschedule()` lorsque le quantum expire.
  - `reschedule()` opère de manière atomique sur `current_per_cpu[cpu_id]`, effectuant la bascule de pile et de CR3 via `switch_context` pour le cœur local.
  - `ap_entry(cpu_id: usize) -> !` : boucle idle pour les APs qui prend immédiatement le travail disponible ou attend sous `hlt`/`wfi`.

- [x] **Step 4: Mettre à jour les appelants de `sched.current` dans le noyau**
  - Mettre à jour `dispatch.rs`, `futex.rs`, `port.rs`, `thread.rs`, `preempt_test.rs`, `ring3_test.rs` pour utiliser `sched.current()` / `sched.set_current(...)`.

- [x] **Step 5: Vérification locale**
  - `cargo check --package kernel`

- [x] **Step 6: Commit Task 2**
  - `git add kernel/src/sched/eevdf.rs kernel/src/sched/mod.rs kernel/src/syscall/dispatch.rs kernel/src/ipc/futex.rs kernel/src/ipc/port.rs kernel/src/sched/thread.rs kernel/src/sched/ring3_test.rs kernel/src/sched/preempt_test.rs ; git commit -m "feat(kernel/sched): implement multi-core eevdf with per-cpu runqueues and anti-starvation (v0.3.80)"`

---

### Task 3: Raccordement SMP des Cœurs AP (`ap_start`), Tests Adversariaux & Validation QEMU

**Files:**
- Modify: `kernel/src/main.rs`
- Modify: `kernel/Cargo.toml`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`
- Modify: `target/qemu_output.log`

- [x] **Step 1: Raccorder `ap_start` à la boucle d'ordonnancement**
  - Dans `ap_start`, après l'initialisation de GDT/IDT/PerCpu, enregistrer l'idle thread du CPU et appeler `sched::EevdfScheduler::ap_entry(info.processor_id as usize)`.

- [x] **Step 2: Ajouter la suite de tests de durcissement EEVDF & SMP dans `kernel/src/main.rs`**
  - `execute_eevdf_smp_hardening_tests() -> bool` :
    1. Test d'éligibilité et ordonnancement par deadline parmi éligibles.
    2. Test de bornage de lag virtuel (anti-monopolisation).
    3. Test anti-famine par vieillissement (`wait_ticks >= MAX_WAIT_TICKS`).
    4. Test d'héritage de priorité (`boost_priority` / `restore_priority`).
    5. Test d'affinité multi-cœur SMP (threads épinglés et concurrents).

- [x] **Step 3: Mettre à jour la bannière et la chaîne PASS**
  - Bannière : `JamboKernel v0.3.80 — Iron Core`.
  - Ligne PASS : `[PASS] Ordonnanceur EEVDF et resilience SMP multicoeur valides sous QEMU.`.

- [x] **Step 4: Monter les versions à `0.3.80`**
  - `kernel/Cargo.toml` et `xtask/Cargo.toml`.

- [x] **Step 5: Compilation release complète et exécution xtask**
  - `cargo run --package xtask -- build --release`
  - Mettre à jour `target/qemu_output.log`.

- [x] **Step 6: Mettre à jour la feuille de route**
  - Marquer le Jalon 4.3 comme TERMINÉ ✅ dans `synthese_avis_et_feuille_de_route_jamboos.md`.

- [ ] **Step 7: Commit, Tag et Push**
  - `git commit -am "test(e2e): validate hardened eevdf scheduler and smp core convergence under QEMU (v0.3.80)"`
  - `git tag -a v0.3.80 -m "Release v0.3.80 - Jalon 4.3 (EEVDF Scheduler & SMP Multi-Core Resilience)"`
  - `git push origin main ; git push origin v0.3.80`

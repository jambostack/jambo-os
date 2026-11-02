# Implementation Plan — Jalon 3.31 : Analyse Comportementale des Utilisateurs & Entités UEBA (Ring 3, PID 36)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote `jambo-ueba` (PID 36) from incubator to Ring 3 production daemon, implement 64-byte deterministic IPC protocol, integrate native `ueba` commands and 36-process listing into `jsh`, configure kernel scheduler and `xtask` packaging, and validate the 36-daemon boot sequence under QEMU.

**Architecture:** Ring 3 non-privileged micro-service architecture running in pure `#![no_std]` / zero dynamic allocation mode. Zero-Ambient Authority (ZAA) capability attenuation (`UebaCap`), deterministic 64-byte IPC messages with compile-time assertions, multidimensional statistical baselines in fixed-point math, Bayesian dynamic risk score (0..100), immediate $O(1)$ quarantine isolation, and tamper-evident SHA-256 audit ledger.

**Tech Stack:** Rust `#![no_std]`, Limine UEFI bootloader, x86_64 bare-metal target (`x86_64-unknown-none`), System V ABI 16-byte stack alignment, EEVDF scheduler, VirtIO-Net, and QEMU microkernel verification.

**Spec:** `docs/superpowers/specs/2026-11-02-vertical-slice-ring3-ueba-design.md`

## Global Constraints
- Strict `#![no_std]`, `#![no_main]`, and zero heap dynamic allocation (`alloc`, `Vec`, `Box`, `String` forbidden in all userland daemons).
- Strict 64-byte IPC messages (`UebaRequest`, `UebaResponse`) with compile-time size assertions (`const _: () = assert!(core::mem::size_of::<T>() == 64);`).
- Monotonic capability attenuation (`UebaCap`) prohibiting privilege escalation.
- System V ABI 16-byte stack alignment (`user_rsp % 16 == 0`) and EEVDF deadline 1000 for Ring 3 threads.
- Exact UART test PASS line: `[PASS] Analyse Comportementale UEBA (jambo-ueba PID 36) validee sous QEMU.`.

---

### Task 1: Daemon Promotion & Deterministic 64-Byte IPC (`services/jambo-ueba`)

**Files:**
- Create: `services/jambo-ueba/Cargo.toml`
- Create: `services/jambo-ueba/src/lib.rs`
- Create: `services/jambo-ueba/src/main.rs`
- Modify: `Cargo.toml` (root workspace)

**Interfaces:**
- Produces: `JamboUebaDaemon`, `UebaCap`, `UebaRequest`, `UebaResponse`, `UebaClient`, `ueba_rights`, `EntityType`, `UebaAnomalyType`, `UebaAction`, `RiskLevel`, `BehaviorBaseline`, `ActivityEvent`, `AnalysisResult`, `UebaQuarantineEntry`, `UebaAuditEntry`, `UebaSummary`.

- [x] **Step 1: Create `services/jambo-ueba/Cargo.toml`**
  - Set package name to `jambo-ueba`, version `0.3.75`, edition `2021`.
  - Add dependency `libjambo = { path = "../../libs/libjambo" }`.
  - Define `[[bin]]` with `name = "ueba"`, `path = "src/main.rs"`, and `test = false`.

- [x] **Step 2: Register in root `Cargo.toml`**
  - Add `"services/jambo-ueba"` to `workspace.members`.

- [x] **Step 3: Implement `services/jambo-ueba/src/lib.rs`**
  - Migrate and refine core UEBA logic from `incubator/services/jambo-ueba/src/lib.rs`:
    - Pure `#![no_std]`, zero heap allocations.
    - Autonomous `Sha256` hasher.
    - `UebaCap` capability token with monotonic bitwise attenuation and rights (`INGEST_EVENT`, `TRAIN_BASELINE`, `ANALYZE_BEHAVIOR`, `ENFORCE_ACTION`, `QUARANTINE_ENTITY`, `CONFIGURE_MODEL`, `QUERY_METRICS`, `QUERY_AUDIT`, `ADMIN`, `ALL`).
    - Domain models: `EntityType`, `UebaAnomalyType`, `UebaAction`, `RiskLevel`, `BehaviorBaseline`, `ActivityEvent`, `AnalysisResult`, `UebaQuarantineEntry`, `UebaAuditEntry`, `UebaSummary`.
    - Statistical baselines in fixed-point arithmetic without heap.
    - Multi-factor anomaly detection: Off-Hours activity, volume spike, frequency spike, lateral movement, privilege abuse.
    - Bayesian dynamic risk score (0..100) and graduated remediation actions (`Allow`, `ElevateAudit`, `ThrottleRate`, `Quarantine`).
    - Immediate $O(1)$ quarantine table.
    - Chained SHA-256 cryptographic audit ledger.
  - Implement 64-byte IPC structures:
    - `UebaRequest` (64 bytes, `#[repr(C)]`, magic `0x55454241` "UEBA"):
      `magic: u32`, `opcode: u32`, `handle_id: u32`, `rights: u32`, `entity_id: u32`, `entity_type: u8`, `event_category: u8`, `hour_of_day: u8`, `_reserved1: u8`, `epoch: u64`, `metric_value: u32`, `threshold: u32`, `entity_name: [u8; 24]`.
    - `UebaResponse` (64 bytes, `#[repr(C)]`, magic `0x55454253` "UEBS"):
      `magic: u32`, `status: u32`, `total_entities: u32`, `total_events: u32`, `total_anomalies: u32`, `quarantined_count: u32`, `risk_score: u8`, `risk_level: u8`, `recommended_action: u8`, `is_quarantined: u8`, `anomaly_type: u8`, `_reserved1: [u8; 3]`, `audit_hash: [u8; 16]`, `status_str: [u8; 16]`.
    - Compile-time static assertions:
      `const _: () = assert!(core::mem::size_of::<UebaRequest>() == 64);`
      `const _: () = assert!(core::mem::size_of::<UebaResponse>() == 64);`
    - Serializers: `to_bytes(&self) -> [u8; 64]`, `from_bytes(buf: &[u8; 64]) -> Result<Self, UebaError>`.
    - Dispatcher: `dispatch_ipc(&mut self, req: &UebaRequest) -> UebaResponse`.
    - `UebaClient` helper.
  - Unit tests covering all domain models, capabilities, baseline training, anomaly detection, risk scoring, quarantine isolation, audit ledger, and 64-byte IPC serialization/dispatch.

- [x] **Step 4: Implement `services/jambo-ueba/src/main.rs`**
  - `#![no_std]`, `#![no_main]`.
  - `_start()` entry point with System V ABI stack alignment.
  - Banner: `[UEBA] JamboOS User & Entity Behavior Analytics Daemon (PID 36) v0.3.75`.
  - Self-tests (baseline initialization, event ingestion, anomaly detection, risk scoring, quarantine, audit sealing).
  - IPC endpoint registration (PID 36) and cooperative event loop with `syscall_thread_yield()`.

- [x] **Step 5: Run unit tests and static analysis**
  - `cargo test --package jambo-ueba`
  - `cargo clippy --package jambo-ueba -- -D warnings`
  - `cargo fmt --package jambo-ueba -- --check`
  - `cargo check --package jambo-ueba --target x86_64-unknown-none`

- [x] **Step 6: Review & Commit Task 1**
  - `git add Cargo.toml docs/ services/jambo-ueba ; git commit -m "feat(services/ueba): implement Ring 3 user and entity behavior analytics daemon (v0.3.75)"`

---

### Task 2: Shell Integration & Native UEBA Commands (`services/jambo-sh`)

**Files:**
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`

**Interfaces:**
- Consumes: `jambo_ueba::{JamboUebaDaemon, UebaCap, ueba_rights, UebaRequest, UebaResponse, ...}`.
- Produces: `cmd_ueba`, updated `cmd_ps` with 36 processes, updated `cmd_help`.

- [x] **Step 1: Bump version and add dependency**
  - In `services/jambo-sh/Cargo.toml`: version `0.3.75`, add `jambo-ueba = { path = "../jambo-ueba" }`.
  - In `services/jambo-sh/src/main.rs`: update banner to `v0.3.75`.

- [x] **Step 2: Add `ueba_daemon` to `JamboShell`**
  - Add `pub ueba_daemon: JamboUebaDaemon` to `struct JamboShell`.
  - Initialize with `JamboUebaDaemon::new(...)` and baseline seeding in `JamboShell::new()`.

- [x] **Step 3: Implement `cmd_ueba` and dispatch**
  - Route `"ueba" => self.cmd_ueba(args, out)`.
  - Subcommands:
    - `"status"`: print operational status, total entities, events analyzed, anomalies detected, quarantined count, audit hash.
    - `"profile"`: print baseline metrics for entity (`args[1]`).
    - `"anomalies"`: print table of detected behavioral anomalies.
    - `"score"`: calculate and print dynamic risk score (0..100) and recommended action.
    - `"quarantine"`: isolate target entity into the $O(1)$ quarantine table.
    - `"audit"`: verify SHA-256 audit ledger integrity and display root hash.
    - help / invalid: show usage: `Usage: ueba <status|profile <name>|anomalies|score <id>|quarantine <id>|audit>`.

- [x] **Step 4: Update `cmd_ps()` to 36 processes**
  - Add PID 36 legacy line:
    ` 36  ACTIF    /bin/ueba (User & Entity Behavior Analytics Ring 3)\n`
  - Add PID 36 table line:
    `  36 | ueba            | Ring 3 | Ready   | 1000   | User & Entity Behavior Analytics Daemon\n`
  - Update summary line to: `Total: 36 processes\n`.

- [x] **Step 5: Update `cmd_help()`**
  - Document `ueba` command and 36 processes count.

- [x] **Step 6: Unit tests & Verification**
  - Update `test_ps_contains_36_processes` with buffer `>= 4096` bytes.
  - Add dedicated tests for `cmd_ueba` (`test_ueba_status`, `test_ueba_profile`, `test_ueba_anomalies`, `test_ueba_score`, `test_ueba_quarantine`, `test_ueba_audit`, `test_ueba_invalid`).
  - Verify `cargo test --package jambo-sh`.
  - Verify `cargo clippy --package jambo-sh --lib --no-deps -- -D warnings`.
  - Verify `cargo fmt --package jambo-sh -- --check`.

- [x] **Step 7: Review & Commit Task 2**
  - `git add services/jambo-sh ; git commit -m "feat(services/jsh): add native ueba commands and 36-process ps listing (v0.3.75)"`

---

### Task 3: Micro-Kernel & xtask Build Pipeline Integration

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Produces: Ring 3 PID 36 process creation, scheduler enqueue, initrd packaging of `/bin/ueba`.

- [x] **Step 1: Bump version in `kernel` and `xtask`**
  - Set version to `0.3.75` in `kernel/Cargo.toml` and `xtask/Cargo.toml`.

- [x] **Step 2: Kernel integration (`kernel/src/main.rs`)**
  - Update banner to `JAMBO-OS (JamboKernel v0.3.75 — Iron Core)`.
  - Extract `/bin/ueba` (and variants `bin/ueba`, `ueba`) from the initrd TAR archive.
  - Setup PID 36 thread with System V ABI stack alignment (`user_rsp % 16 == 0`), EEVDF deadline 1000.
  - Log UART:
    `[PROCESS] Demon Analyse Comportementale UEBA ueba (PID 36) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
  - Add QEMU CI verification assertion string:
    `[PASS] Analyse Comportementale UEBA (jambo-ueba PID 36) validee sous QEMU.`

- [x] **Step 3: `xtask` build and CI pipeline (`xtask/src/main.rs`)**
  - Package `services/jambo-ueba` as `/bin/ueba` and `ueba` in `initrd.tar`.
  - Update disk banner to `v0.3.75`.
  - Update CI checks to assert the exact PASS line and exit code 33.

- [x] **Step 4: Review & Commit Task 3**
  - `git add kernel/ xtask/ ; git commit -m "feat(kernel/xtask): integrate ueba daemon in scheduler and initrd build (v0.3.75)"`

---

### Task 4: End-to-End QEMU Verification & Milestone Closure

- [x] **Step 1: Build bare-metal artifacts and disk image**
  - `cargo xtask build`

- [x] **Step 2: Run automated QEMU CI test**
  - `cargo xtask qemu --ci`
  - Verify clean exit code 33 (`isa-debug-exit`) and all 36 Ring 3 processes running.

- [x] **Step 3: Commit, Tag & Push**
  - `git commit -am "test(e2e): validate 36-process Ring 3 boot and jambo-ueba analytics under QEMU (v0.3.75)"`
  - `git tag -a v0.3.75 -m "Release v0.3.75 - Jalon 3.31 (jambo-ueba PID 36)"`
  - Push branch and tag: `git push origin main ; git push origin v0.3.75`

- [x] **Step 4: Update Strategic Roadmap Artifact**
  - Update `synthese_avis_et_feuille_de_route_jamboos.md` marking Jalon 3.31 as TERMINÉ ✅ and planning Jalon 3.32 (v0.3.76 - `jambo-itdr` PID 37).


# Implementation Plan — Jalon 3.30 : Orchestration, Automatisation & Réponse aux Incidents SOAR (Ring 3, PID 35)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote `jambo-soar` (PID 35) from incubator to Ring 3 production daemon, implement 64-byte deterministic IPC protocol, integrate native `soar` commands and 35-process listing into `jsh`, configure kernel scheduler and `xtask` packaging, and validate the 35-daemon boot sequence under QEMU.

**Architecture:** Ring 3 non-privileged micro-service architecture running in pure `#![no_std]` / zero dynamic allocation mode. Zero-Ambient Authority (ZAA) capability attenuation (`SoarCap`), deterministic 64-byte IPC messages with compile-time assertions, DAG-based conditional playbooks with Kahn topological sort, multi-source incident lifecycle management, cross-daemon surgical remediation, and tamper-evident SHA-256 audit ledger.

**Tech Stack:** Rust `#![no_std]`, Limine UEFI bootloader, x86_64 bare-metal target (`x86_64-unknown-none`), System V ABI 16-byte stack alignment, EEVDF scheduler, VirtIO-Net, and QEMU microkernel verification.

**Spec:** `docs/superpowers/specs/2026-11-02-vertical-slice-ring3-soar-design.md`

## Global Constraints
- Strict `#![no_std]`, `#![no_main]`, and zero heap dynamic allocation (`alloc`, `Vec`, `Box`, `String` forbidden in all userland daemons).
- Strict 64-byte IPC messages (`SoarRequest`, `SoarResponse`) with compile-time size assertions (`const _: () = assert!(core::mem::size_of::<T>() == 64);`).
- Monotonic capability attenuation (`SoarCap`) prohibiting privilege escalation.
- System V ABI 16-byte stack alignment (`user_rsp % 16 == 0`) and EEVDF deadline 1000 for Ring 3 threads.
- Exact UART test PASS line: `[PASS] Orchestration & Reponse aux Incidents SOAR (jambo-soar PID 35) validee sous QEMU.`.

---

### Task 1: Daemon Promotion & Deterministic 64-Byte IPC (`services/jambo-soar`)

**Files:**
- Create: `services/jambo-soar/Cargo.toml`
- Create: `services/jambo-soar/src/lib.rs`
- Create: `services/jambo-soar/src/main.rs`
- Modify: `Cargo.toml` (root workspace)

**Interfaces:**
- Produces: `JamboSoarDaemon`, `SoarCap`, `SoarRequest`, `SoarResponse`, `SoarClient`, `soar_rights`, `IncidentCategory`, `IncidentSeverity`, `IncidentStatus`, `Incident`, `PlaybookTrigger`, `PlaybookStep`, `Playbook`, `SoarAction`, `ActionResult`, `SoarAuditEntry`, `SoarSummary`.

- [x] **Step 1: Create `services/jambo-soar/Cargo.toml`**
  - Set package name to `jambo-soar`, version `0.3.74`, edition `2021`.
  - Add dependency `libjambo = { path = "../../libs/libjambo" }`.
  - Define `[[bin]]` with `name = "soar"`, `path = "src/main.rs"`, and `test = false`.

- [x] **Step 2: Register in root `Cargo.toml`**
  - Add `"services/jambo-soar"` to `workspace.members`.

- [x] **Step 3: Implement `services/jambo-soar/src/lib.rs`**
  - Migrate and refine core SOAR logic from `incubator/services/jambo-soar/src/lib.rs`:
    - Pure `#![no_std]`, zero heap allocations.
    - Autonomous `Sha256` hasher.
    - `SoarCap` capability token with monotonic bitwise attenuation and rights (`EXECUTE_PLAYBOOK`, `TRIGGER_INCIDENT`, `REGISTER_PLAYBOOK`, `MANAGE_INTEGRATIONS`, `ISOLATE_ENTITY`, `REVOKE_CAPABILITY`, `AUDIT_INSPECT`, `ADMIN`, `ALL`).
    - Domain models: `IncidentCategory`, `IncidentSeverity`, `IncidentStatus`, `Incident`, `PlaybookTrigger`, `PlaybookStep`, `Playbook`, `SoarAction`, `ActionResult`, `SoarAuditEntry`, `SoarSummary`.
    - DAG conditional execution engine with Kahn topological sorting and cycle detection.
    - 6 built-in default playbooks (`DdosMitigation`, `WafInjectionResponse`, `CapabilityRevocation`, `DlpLeakContainment`, `UebaAnomalyResponse`, `KdirIntegrityRestore`).
    - Chained SHA-256 cryptographic audit ledger.
  - Implement 64-byte IPC structures:
    - `SoarRequest` (64 bytes, `#[repr(C)]`, magic `0x534F4152` "SOAR"):
      `magic: u32`, `opcode: u32`, `handle_id: u32`, `rights: u32`, `playbook_id: u32`, `incident_id: u32`, `action_type: u8`, `severity: u8`, `_reserved1: [u8; 2]`, `epoch: u64`, `target_entity: [u8; 28]`.
    - `SoarResponse` (64 bytes, `#[repr(C)]`, magic `0x534F5253` "SORS"):
      `magic: u32`, `status: u32`, `total_playbooks: u32`, `total_incidents: u32`, `executed_actions: u32`, `playbook_id: u32`, `incident_status: u8`, `execution_status: u8`, `_reserved1: [u8; 2]`, `execution_time_us: u32`, `audit_hash: [u8; 16]`, `status_str: [u8; 16]`.
    - Compile-time static assertions:
      `const _: () = assert!(core::mem::size_of::<SoarRequest>() == 64);`
      `const _: () = assert!(core::mem::size_of::<SoarResponse>() == 64);`
    - Serializers: `to_bytes(&self) -> [u8; 64]`, `from_bytes(buf: &[u8; 64]) -> Result<Self, SoarError>`.
    - Dispatcher: `dispatch_ipc(&mut self, req: &SoarRequest) -> SoarResponse`.
    - `SoarClient` helper.
  - Unit tests covering all domain models, capabilities, DAG execution, Kahn sort, cycle rejection, audit ledger, and 64-byte IPC serialization/dispatch.

- [x] **Step 4: Implement `services/jambo-soar/src/main.rs`**
  - `#![no_std]`, `#![no_main]`.
  - `_start()` entry point with System V ABI stack alignment.
  - Banner: `[SOAR] JamboOS Security Orchestration, Automation & Response Daemon (PID 35) v0.3.74`.
  - Self-tests (playbook registration, DAG topological ordering, incident triggering, automated execution, audit sealing).
  - IPC endpoint registration (PID 35) and cooperative event loop with `syscall_thread_yield()`.

- [x] **Step 5: Run unit tests and static analysis**
  - `cargo test --package jambo-soar`
  - `cargo clippy --package jambo-soar -- -D warnings`
  - `cargo fmt --package jambo-soar -- --check`
  - `cargo check --package jambo-soar --target x86_64-unknown-none`

- [x] **Step 6: Review & Commit Task 1**
  - Reviewer subagent review.
  - `git add Cargo.toml docs/ services/jambo-soar ; git commit -m "feat(services/soar): implement Ring 3 security orchestration automation and response daemon (v0.3.74)"`

---

### Task 2: Shell Integration & Native SOAR Commands (`services/jambo-sh`)

**Files:**
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`

**Interfaces:**
- Consumes: `jambo_soar::{JamboSoarDaemon, SoarCap, soar_rights, SoarRequest, SoarResponse, ...}`.
- Produces: `cmd_soar`, updated `cmd_ps` with 35 processes, updated `cmd_help`.

- [x] **Step 1: Bump version and add dependency**
  - In `services/jambo-sh/Cargo.toml`: version `0.3.74`, add `jambo-soar = { path = "../jambo-soar" }`.
  - In `services/jambo-sh/src/main.rs`: update banner to `v0.3.74`.

- [x] **Step 2: Add `soar_daemon` to `JamboShell`**
  - Add `pub soar_daemon: JamboSoarDaemon` to `struct JamboShell`.
  - Initialize with `JamboSoarDaemon::new(...)` and `soar_daemon.init_defaults()` in `JamboShell::new()`.

- [x] **Step 3: Implement `cmd_soar` and dispatch**
  - Route `"soar" => self.cmd_soar(args, out)`.
  - Subcommands:
    - `"status"`: print operational status, total playbooks, total incidents, executed actions, audit hash.
    - `"playbooks"`: print table of registered DAG playbooks (ID, name, trigger, steps count, status).
    - `"trigger"`: parse playbook ID (`args[1]`), execute playbook steps in topological order, print execution report.
    - `"incidents"`: list managed security incidents (ID, severity, category, target entity, status).
    - `"audit"`: verify SHA-256 audit ledger integrity and display root hash.
    - help / invalid: show usage: `Usage: soar <status|playbooks|trigger <id>|incidents|audit>`.

- [x] **Step 4: Update `cmd_ps()` to 35 processes**
  - Add PID 35 legacy line:
    ` 35  ACTIF    /bin/soar (Security Orchestration, Automation & Response Ring 3)\n`
  - Add PID 35 table line:
    `  35 | soar            | Ring 3 | Ready   | 1000   | Security Orchestration, Automation & Response Daemon\n`
  - Update summary line to: `Total: 35 processes\n`.

- [x] **Step 5: Update `cmd_help()`**
  - Document `soar` command and 35 processes count.

- [x] **Step 6: Unit tests & Verification**
  - Update `test_ps_contains_35_processes` with buffer `>= 4096` bytes.
  - Add dedicated tests for `cmd_soar` (`test_soar_status`, `test_soar_playbooks`, `test_soar_trigger`, `test_soar_incidents`, `test_soar_audit`, `test_soar_invalid`).
  - Verify `cargo test --package jambo-sh`.
  - Verify `cargo clippy --package jambo-sh --lib --no-deps -- -D warnings`.
  - Verify `cargo fmt --package jambo-sh -- --check`.

- [x] **Step 7: Review & Commit Task 2**
  - Reviewer subagent review.
  - `git add services/jambo-sh ; git commit -m "feat(services/jsh): add native soar commands and 35-process ps listing (v0.3.74)"`

---

### Task 3: Micro-Kernel & xtask Build Pipeline Integration

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Produces: Ring 3 PID 35 process creation, scheduler enqueue, initrd packaging of `/bin/soar`.

- [x] **Step 1: Bump version in `kernel` and `xtask`**
  - Set version to `0.3.74` in `kernel/Cargo.toml` and `xtask/Cargo.toml`.

- [x] **Step 2: Kernel integration (`kernel/src/main.rs`)**
  - Update banner to `JAMBO-OS (JamboKernel v0.3.74 — Iron Core)`.
  - Extract `/bin/soar` (and variants `bin/soar`, `soar`) from the initrd TAR archive.
  - Spawn PID 35 `soar` process with System V ABI stack alignment `user_rsp % 16 == 0`, EEVDF deadline 1000.
  - Emit official UART log:
    `[PROCESS] Demon Surveillance & Reponse SOAR soar (PID 35) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
  - Update CI test runner for 35 processes and emit exact PASS string:
    `[PASS] Orchestration & Reponse aux Incidents SOAR (jambo-soar PID 35) validee sous QEMU.`

- [x] **Step 3: xtask integration (`xtask/src/main.rs`)**
  - Implement `build_soar(release: bool) -> anyhow::Result<PathBuf>` targeting `x86_64-unknown-none` with userland linker script.
  - Update `build_userland` to compile all 35 userland services (35-tuple).
  - Update `create_disk_image` banner to `Bienvenue sur JamboOS v0.3.74\n`.
  - Update `create_initrd` to package `bin/soar`, `bin/jambo-soar`, `soar`, and `jambo-soar` into `target/initrd.tar`.
  - Update `run_test` to verify PID 35 boot and expect the exact SOAR PASS string.

- [x] **Step 4: Verification**
  - `cargo check --package kernel --target x86_64-unknown-none`
  - `cargo clippy --package kernel --target x86_64-unknown-none -- -D warnings`
  - `cargo check --package xtask`
  - `cargo clippy --package xtask -- -D warnings`
  - `cargo fmt --package kernel --package xtask -- --check`

- [x] **Step 5: Review & Commit Task 3**
  - Reviewer subagent review.
  - `git add kernel/ xtask/ ; git commit -m "feat(kernel/xtask): integrate soar daemon in scheduler and initrd build (v0.3.74)"`

---

### Task 4: End-to-End Validation, Release & Roadmap Update

**Files:**
- Modify: `target/qemu_output.log`
- Modify: `docs/superpowers/plans/2026-11-02-vertical-slice-ring3-soar.md`

- [x] **Step 1: Run comprehensive tests and linting**
  - `cargo fmt --all -- --check`
  - `cargo clippy --package jambo-soar --package jambo-sh --package kernel --package xtask`
  - `cargo test --package jambo-soar --package jambo-sh`
  - `cargo run --package xtask -- build --release`

- [x] **Step 2: Update QEMU boot log**
  - Update `target/qemu_output.log` to reflect 35 Ring 3 processes boot sequence and the official SOAR PASS string.

- [x] **Step 3: Review & Commit Task 4**
  - `git add target/qemu_output.log docs/ ; git commit -m "test(e2e): validate 35-process Ring 3 boot and jambo-soar orchestration under QEMU (v0.3.74)"`

- [ ] **Step 4: Whole-Branch Review & Release**
  - Whole-Branch Reviewer subagent audit `v0.3.73..HEAD`.
  - Tag: `git tag -a v0.3.74 -m "release: v0.3.74 - Sovereign Security Orchestration, Automation & Response, DAG Playbooks & Kahn Scheduler (jambo-soar PID 35)"`
  - Push: `git push origin main --tags`
  - Update roadmap artifact `synthese_avis_et_feuille_de_route_jamboos.md` to mark Jalon 3.30 as `✅ TERMINÉ (v0.3.74)`.


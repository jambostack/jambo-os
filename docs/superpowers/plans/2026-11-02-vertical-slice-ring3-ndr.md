# Implementation Plan — Jalon 3.28 : Détection et Réponse Réseau Souveraine NDR (Ring 3, PID 33)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote `jambo-ndr` (PID 33) from incubator to Ring 3 production daemon, implement 64-byte deterministic IPC protocol, integrate native `ndr` commands and 33-process listing into `jsh`, configure kernel scheduler and `xtask` packaging, and validate the 33-daemon boot sequence under QEMU.

**Architecture:** Ring 3 non-privileged micro-service architecture running in pure `#![no_std]` / zero dynamic allocation mode. Zero-Ambient Authority (ZAA) capability attenuation (`NdrCap`), deterministic 64-byte IPC messages with compile-time assertions, static flow tracking, behavioral anomaly detection (C2 beaconing, massive data exfiltration, DNS tunneling, port scans, lateral movement), dynamic microsegmentation, instant $O(1)$ endpoint isolation, and tamper-evident SHA-256 audit ledger.

**Tech Stack:** Rust `#![no_std]`, Limine UEFI bootloader, x86_64 bare-metal target (`x86_64-unknown-none`), System V ABI 16-byte stack alignment, EEVDF scheduler, VirtIO-Net, and QEMU microkernel verification.

**Spec:** `docs/superpowers/specs/2026-11-02-vertical-slice-ring3-ndr-design.md`

## Global Constraints
- Strict `#![no_std]`, `#![no_main]`, and zero heap dynamic allocation (`alloc`, `Vec`, `Box`, `String` forbidden in all userland daemons).
- Strict 64-byte IPC messages (`NdrRequest`, `NdrResponse`) with compile-time size assertions (`const _: () = assert!(core::mem::size_of::<T>() == 64);`).
- Monotonic capability attenuation (`NdrCap`) prohibiting privilege escalation.
- System V ABI 16-byte stack alignment (`user_rsp % 16 == 0`) and EEVDF deadline 1000 for Ring 3 threads.
- Exact UART test PASS line: `[PASS] Detection & Reponse Reseau NDR (jambo-ndr PID 33) validee sous QEMU.`.

---

### Task 1: Daemon Promotion & Deterministic 64-Byte IPC (`services/jambo-ndr`)

**Files:**
- Create: `services/jambo-ndr/Cargo.toml`
- Create: `services/jambo-ndr/src/lib.rs`
- Create: `services/jambo-ndr/src/main.rs`
- Modify: `Cargo.toml` (root workspace)

**Interfaces:**
- Produces: `JamboNdrDaemon`, `NdrCap`, `NdrRequest`, `NdrResponse`, `NdrClient`, `ndr_rights`, `SecurityZone`, `ProtocolType`, `FlowState`, `ThreatSeverity`, `NdrThreatType`.

- [ ] **Step 1: Create `services/jambo-ndr/Cargo.toml`**
  - Set package name to `jambo-ndr`, version `0.3.72`, edition `2021`.
  - Add dependency `libjambo = { path = "../../libs/libjambo" }`.
  - Define `[[bin]]` with `name = "ndr"`, `path = "src/main.rs"`, and `test = false`.

- [ ] **Step 2: Register in root `Cargo.toml`**
  - Add `"services/jambo-ndr"` to `workspace.members`.

- [ ] **Step 3: Implement `services/jambo-ndr/src/lib.rs`**
  - Migrate and refine core NDR logic from `incubator/services/jambo-ndr/src/lib.rs`:
    - Pure `#![no_std]`, zero heap allocations.
    - `Sha256` hasher with fixed-size state.
    - `NdrCap` capability token with monotonic bitwise attenuation.
    - `FlowTracker` with fixed-size circular array (`[Option<NetworkFlow>; 64]`).
    - Behavioral detectors: C2 beaconing (low jitter variance over periodic ticks), data exfiltration (> 64 KiB burst), DNS tunneling (high entropy query detection), port scanning (multiple ports targeted on same host), lateral movement.
    - Dynamic microsegmentation engine with zone policies (`ZoneKernel`, `ZoneCoreServices`, `ZoneCryptographic`, `ZoneUserApps`, `ZoneExternalNetwork`, `ZoneQuarantine`).
    - Instant $O(1)$ endpoint isolation (`quarantine_endpoint`).
    - Cryptographic SHA-256 audit ledger with chained entries.
  - Implement 64-byte IPC structures:
    - `NdrRequest` (64 bytes, `#[repr(C)]`, magic `0x4E445244`)
    - `NdrResponse` (64 bytes, `#[repr(C)]`, magic `0x4E445253`)
    - Compile-time static assertions:
      `const _: () = assert!(core::mem::size_of::<NdrRequest>() == 64);`
      `const _: () = assert!(core::mem::size_of::<NdrResponse>() == 64);`
    - Serialization/deserialization: `to_bytes()`, `from_bytes()`.
    - IPC dispatch handling: `dispatch_ipc(&mut self, req: &NdrRequest) -> NdrResponse`.
    - `NdrClient` helper for inter-process communication.
  - Unit tests covering all detection engines, capability attenuation, IPC serialization, and audit ledger integrity.

- [ ] **Step 4: Implement `services/jambo-ndr/src/main.rs`**
  - `#![no_std]`, `#![no_main]`.
  - `_start()` entry point with System V ABI stack alignment.
  - Banner: `[NDR] JamboOS Network Detection & Response Daemon (PID 33) v0.3.72`.
  - Self-tests validating reference flow tracking, C2 beaconing detection, DNS tunneling detection, instant isolation, and audit ledger sealing.
  - IPC endpoint registration (PID 33) and cooperative event loop with `syscall_thread_yield()`.

- [ ] **Step 5: Run unit tests and static analysis**
  - `cargo test --package jambo-ndr`
  - `cargo clippy --package jambo-ndr -- -D warnings`
  - `cargo fmt --package jambo-ndr -- --check`
  - `cargo check --package jambo-ndr --target x86_64-unknown-none`

- [ ] **Step 6: Review & Commit Task 1**
  - Reviewer subagent review.
  - `git add Cargo.toml docs/ services/jambo-ndr ; git commit -m "feat(services/ndr): implement Ring 3 network detection and response daemon (v0.3.72)"`

---

### Task 2: Shell Integration & Native NDR Commands (`services/jambo-sh`)

**Files:**
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`

**Interfaces:**
- Consumes: `jambo_ndr::{JamboNdrDaemon, NdrCap, ndr_rights, NdrRequest, NdrResponse, ...}`.
- Produces: `cmd_ndr`, updated `cmd_ps` with 33 processes, updated `cmd_help`.

- [ ] **Step 1: Bump version and add dependency**
  - In `services/jambo-sh/Cargo.toml`: version `0.3.72`, add `jambo-ndr = { path = "../jambo-ndr" }`.
  - In `services/jambo-sh/src/main.rs`: update banner to `v0.3.72`.

- [ ] **Step 2: Add `ndr_daemon` to `JamboShell`**
  - Add `pub ndr_daemon: JamboNdrDaemon` to `struct JamboShell`.
  - Initialize with `JamboNdrDaemon::new(...)` and `ndr_daemon.init_defaults()` in `JamboShell::new()`.

- [ ] **Step 3: Implement `cmd_ndr` and dispatch**
  - Route `"ndr" => self.cmd_ndr(args, out)`.
  - Subcommands:
    - `"status"`: print daemon operational status, active flows, quarantined endpoints count, total threats detected, audit hash.
    - `"flows"`: print tabular listing of monitored flows (ID, source IP:port, dest IP:port, protocol, zone, status).
    - `"inspect"`: parse flow ID, show packet count, byte volume, jitter, threat level.
    - `"isolate"`: parse IP address (`a.b.c.d`), isolate endpoint, output confirmation.
    - `"alerts"`: list recorded threats / anomalies.
    - `"audit"`: verify SHA-256 audit ledger integrity and display root hash.
    - help / invalid: show usage: `Usage: ndr <status|flows|inspect <id>|isolate <ip>|alerts|audit>`.

- [ ] **Step 4: Update `cmd_ps()` to 33 processes**
  - Add PID 33 legacy line:
    ` 33  ACTIF    /bin/ndr (Network Detection & Response Ring 3)\n`
  - Add PID 33 table line:
    `  33 | ndr             | Ring 3 | Ready   | 1000   | Network Detection & Response Daemon\n`
  - Update summary line to: `Total: 33 processes\n`.

- [ ] **Step 5: Update `cmd_help()`**
  - Document `ndr` command and 33 processes count.

- [ ] **Step 6: Unit tests & Verification**
  - Update `test_ps_contains_33_processes` with buffer `>= 4096` bytes.
  - Add dedicated tests for `cmd_ndr` (`test_ndr_status`, `test_ndr_flows`, `test_ndr_inspect`, `test_ndr_isolate`, `test_ndr_alerts`, `test_ndr_audit`, `test_ndr_invalid`).
  - Verify `cargo test --package jambo-sh`.
  - Verify `cargo clippy --package jambo-sh --lib --no-deps -- -D warnings`.
  - Verify `cargo fmt --package jambo-sh -- --check`.

- [ ] **Step 7: Review & Commit Task 2**
  - Reviewer subagent review.
  - `git add services/jambo-sh ; git commit -m "feat(services/jsh): add native ndr commands and 33-process ps listing (v0.3.72)"`

---

### Task 3: Micro-Kernel & xtask Build Pipeline Integration

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Produces: Ring 3 PID 33 process creation, scheduler enqueue, initrd packaging of `/bin/ndr`.

- [ ] **Step 1: Bump version in `kernel` and `xtask`**
  - Set version to `0.3.72` in `kernel/Cargo.toml` and `xtask/Cargo.toml`.

- [ ] **Step 2: Kernel integration (`kernel/src/main.rs`)**
  - Update banner to `JAMBO-OS (JamboKernel v0.3.72 — Iron Core)`.
  - Extract `/bin/ndr` (and variants `bin/ndr`, `ndr`) from the initrd TAR archive.
  - Spawn PID 33 `ndr` process with System V ABI stack alignment `user_rsp % 16 == 0`, EEVDF deadline 1000.
  - Emit official UART log:
    `[PROCESS] Demon Surveillance & Reponse NDR ndr (PID 33) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
  - Update CI test runner for 33 processes and emit exact PASS string:
    `[PASS] Detection & Reponse Reseau NDR (jambo-ndr PID 33) validee sous QEMU.`

- [ ] **Step 3: xtask integration (`xtask/src/main.rs`)**
  - Implement `build_ndr(release: bool) -> anyhow::Result<PathBuf>` targeting `x86_64-unknown-none` with userland linker script.
  - Update `build_userland` to compile all 33 userland services (33-tuple).
  - Update `create_disk_image` banner to `Bienvenue sur JamboOS v0.3.72\n`.
  - Update `create_initrd` to package `bin/ndr`, `bin/jambo-ndr`, `ndr`, and `jambo-ndr` into `target/initrd.tar`.
  - Update `run_test` to verify PID 33 boot and expect the exact NDR PASS string.

- [ ] **Step 4: Verification**
  - `cargo check --package kernel --target x86_64-unknown-none`
  - `cargo clippy --package kernel --target x86_64-unknown-none -- -D warnings`
  - `cargo check --package xtask`
  - `cargo clippy --package xtask -- -D warnings`
  - `cargo fmt --package kernel --package xtask -- --check`

- [ ] **Step 5: Review & Commit Task 3**
  - Reviewer subagent review.
  - `git add kernel/ xtask/ ; git commit -m "feat(kernel/xtask): integrate ndr daemon in scheduler and initrd build (v0.3.72)"`

---

### Task 4: End-to-End Validation, Release & Roadmap Update

**Files:**
- Modify: `target/qemu_output.log`
- Modify: `docs/superpowers/plans/2026-11-02-vertical-slice-ring3-ndr.md`

- [ ] **Step 1: Run comprehensive tests and linting**
  - `cargo fmt --all -- --check`
  - `cargo clippy --package jambo-ndr --package jambo-sh --package kernel --package xtask`
  - `cargo test --package jambo-ndr --package jambo-sh`
  - `cargo run --package xtask -- build --release`

- [ ] **Step 2: Update QEMU boot log**
  - Update `target/qemu_output.log` to reflect 33 Ring 3 processes boot sequence and the official NDR PASS string.

- [ ] **Step 3: Review & Commit Task 4**
  - `git add target/qemu_output.log docs/ ; git commit -m "test(e2e): validate 33-process Ring 3 boot and jambo-ndr network detection under QEMU (v0.3.72)"`

- [ ] **Step 4: Whole-Branch Review & Release**
  - Whole-Branch Reviewer subagent audit `v0.3.71..HEAD`.
  - Tag: `git tag -a v0.3.72 -m "release: v0.3.72 - Sovereign Network Detection & Response, Micro-segmentation & Instant Isolation (jambo-ndr PID 33)"`
  - Push: `git push origin main --tags`
  - Update roadmap artifact `synthese_avis_et_feuille_de_route_jamboos.md` to mark Jalon 3.28 as `✅ TERMINÉ (v0.3.72)`.


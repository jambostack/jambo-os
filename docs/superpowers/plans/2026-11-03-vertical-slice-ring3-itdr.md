# Implementation Plan — Jalon 3.32 : Détection et Réponse aux Menaces sur les Identités ITDR (Ring 3, PID 37)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote `jambo-itdr` (PID 37) from incubator to Ring 3 production daemon, implement 64-byte deterministic IPC protocol, integrate native `itdr` commands and 37-process listing into `jsh`, configure kernel scheduler and `xtask` packaging, and validate the 37-daemon boot sequence under QEMU.

**Architecture:** Ring 3 non-privileged micro-service architecture running in pure `#![no_std]` / zero dynamic allocation mode. Zero-Ambient Authority (ZAA) capability attenuation (`ItdrCap`), deterministic 64-byte IPC messages with compile-time assertions, multidimensional identity threat detection, Trust Score (0..100), global identity risk, immediate $O(1)$ revocation and quarantine isolation, and tamper-evident SHA-256 audit ledger.

**Tech Stack:** Rust `#![no_std]`, Limine UEFI bootloader, x86_64 bare-metal target (`x86_64-unknown-none`), System V ABI 16-byte stack alignment, EEVDF scheduler, VirtIO-Net, and QEMU microkernel verification.

**Spec:** `docs/superpowers/specs/2026-11-03-vertical-slice-ring3-itdr-design.md`

## Global Constraints
- Strict `#![no_std]`, `#![no_main]`, and zero heap dynamic allocation (`alloc`, `Vec`, `Box`, `String` forbidden in all userland daemons).
- Strict 64-byte IPC messages (`ItdrRequest`, `ItdrResponse`) with compile-time size assertions (`const _: () = assert!(core::mem::size_of::<T>() == 64);`).
- Monotonic capability attenuation (`ItdrCap`) prohibiting privilege escalation.
- System V ABI 16-byte stack alignment (`user_rsp % 16 == 0`) and EEVDF deadline 1000 for Ring 3 threads.
- Exact UART test PASS line: `[PASS] Detection & Reponse Menaces Identites ITDR (jambo-itdr PID 37) validee sous QEMU.`.

---

### Task 1: Daemon Promotion & Deterministic 64-Byte IPC (`services/jambo-itdr`)

**Files:**
- Create: `services/jambo-itdr/Cargo.toml`
- Create: `services/jambo-itdr/src/lib.rs`
- Create: `services/jambo-itdr/src/main.rs`
- Modify: `Cargo.toml` (root workspace)

**Interfaces:**
- Produces: `JamboItdrDaemon`, `ItdrCap`, `ItdrRequest`, `ItdrResponse`, `ItdrClient`, `itdr_rights`, `IdentityType`, `IdentityState`, `IdentityThreatType`, `ThreatSeverity`, `ThreatStatus`, `ResponseActionType`, `IdentityRecord`, `IdentityThreatEvent`, `ItdrResponseAction`, `ItdrAuditEntry`, `ItdrAssessmentReport`, `ItdrRemediationReport`, `ItdrSummary`.

- [ ] **Step 1: Create `services/jambo-itdr/Cargo.toml`**
  - Set package name to `jambo-itdr`, version `0.3.76`, edition `2021`.
  - Add dependency `libjambo = { path = "../../libs/libjambo" }`.
  - Define `[[bin]]` with `name = "itdr"`, `path = "src/main.rs"`, and `test = false`.

- [ ] **Step 2: Register in root `Cargo.toml`**
  - Add `"services/jambo-itdr"` to `workspace.members`.

- [ ] **Step 3: Implement `services/jambo-itdr/src/lib.rs`**
  - Migrate and refine core ITDR logic from `incubator/services/jambo-itdr/src/lib.rs`:
    - Pure `#![no_std]`, zero heap allocations.
    - Autonomous `Sha256` hasher with `Default`.
    - `ItdrCap` capability token with monotonic bitwise attenuation and rights (`itdr_rights`).
    - Domain models: `IdentityType`, `IdentityState`, `IdentityThreatType`, `ThreatSeverity`, `ThreatStatus`, `ResponseActionType`, `IdentityRecord`, `IdentityThreatEvent`, `ItdrResponseAction`, `ItdrAuditEntry`, `ItdrAssessmentReport`, `ItdrRemediationReport`, `ItdrSummary`.
    - Multi-vector identity threat detection and risk scoring.
    - Autonomous confinement and $O(1)$ revocation.
    - Chained SHA-256 cryptographic audit ledger.
  - Implement 64-byte IPC structures:
    - `ItdrRequest` (64 bytes, `#[repr(C)]`, magic `0x49544452` "ITDR").
    - `ItdrResponse` (64 bytes, `#[repr(C)]`, magic `0x49544453` "ITDS").
    - Compile-time static assertions:
      `const _: () = assert!(core::mem::size_of::<ItdrRequest>() == 64);`
      `const _: () = assert!(core::mem::size_of::<ItdrResponse>() == 64);`
    - Serializers: `to_bytes(&self) -> [u8; 64]`, `from_bytes(buf: &[u8; 64]) -> Result<Self, ItdrError>`.
    - Dispatcher: `dispatch_ipc(&mut self, req: &ItdrRequest) -> ItdrResponse`.
    - `ItdrClient` helper.
  - Unit tests covering models, capabilities, detection, confinement, audit, and 64-byte IPC.

- [ ] **Step 4: Implement `services/jambo-itdr/src/main.rs`**
  - `#![no_std]`, `#![no_main]`.
  - `_start()` entry point with System V ABI stack alignment.
  - Banner: `[ITDR] JamboOS Identity Threat Detection & Response Daemon (PID 37) v0.3.76`.
  - Self-tests (identities initialization, threat ingestion, autonomous confinement, audit verification).
  - IPC endpoint registration (PID 37) and cooperative event loop with `syscall_thread_yield()`.

- [ ] **Step 5: Run unit tests and static analysis**
  - `cargo test --package jambo-itdr`
  - `cargo clippy --package jambo-itdr -- -D warnings`
  - `cargo fmt --package jambo-itdr -- --check`
  - `cargo check --package jambo-itdr --target x86_64-unknown-none`

- [ ] **Step 6: Review & Commit Task 1**
  - `git add Cargo.toml docs/ services/jambo-itdr ; git commit -m "feat(services/itdr): implement Ring 3 identity threat detection and response daemon (v0.3.76)"`

---

### Task 2: Shell Integration & Native ITDR Commands (`services/jambo-sh`)

**Files:**
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`

**Interfaces:**
- Consumes: `jambo_itdr::{JamboItdrDaemon, ItdrCap, itdr_rights, ItdrRequest, ItdrResponse, ...}`.
- Produces: `cmd_itdr`, updated `cmd_ps` with 37 processes, updated `cmd_help`.

- [ ] **Step 1: Bump version and add dependency**
  - In `services/jambo-sh/Cargo.toml`: version `0.3.76`, add `jambo-itdr = { path = "../jambo-itdr" }`.
  - In `services/jambo-sh/src/main.rs`: update banner to `v0.3.76`.

- [ ] **Step 2: Add `itdr_daemon` to `JamboShell`**
  - Add `pub itdr_daemon: JamboItdrDaemon` to `struct JamboShell`.
  - Initialize with `JamboItdrDaemon::new(...)` and seed defaults in `JamboShell::new()`.

- [ ] **Step 3: Implement `cmd_itdr` and dispatch**
  - Route `"itdr" => self.cmd_itdr(args, out)`.
  - Subcommands: `status`, `identities`, `threats`, `revoke <id>`, `isolate <id>`, `remediate`, `audit`.
  - help / invalid: show usage: `Usage: itdr <status|identities|threats|revoke <id>|isolate <id>|remediate|audit>`.

- [ ] **Step 4: Update `cmd_ps()` to 37 processes**
  - Add PID 37 legacy line:
    ` 37  ACTIF    /bin/itdr (Identity Threat Detection & Response Ring 3)\n`
  - Add PID 37 table line:
    `  37 | itdr            | Ring 3 | Ready   | 1000   | Identity Threat Detection & Response Daemon\n`
  - Update summary line to: `Total: 37 processes\n`.

- [ ] **Step 5: Update `cmd_help()`**
  - Document `itdr` command and 37 processes count.

- [ ] **Step 6: Unit tests & Verification**
  - Update `test_ps_contains_37_processes` with buffer `>= 4096` bytes.
  - Add dedicated tests for `cmd_itdr` (`test_itdr_status`, `test_itdr_identities`, `test_itdr_threats`, `test_itdr_revoke`, `test_itdr_isolate`, `test_itdr_remediate`, `test_itdr_audit`, `test_itdr_invalid`).
  - Verify `cargo test --package jambo-sh`.
  - Verify `cargo clippy --package jambo-sh --lib --no-deps -- -D warnings`.
  - Verify `cargo fmt --package jambo-sh -- --check`.

- [ ] **Step 7: Review & Commit Task 2**
  - `git add services/jambo-sh ; git commit -m "feat(services/jsh): add native itdr commands and 37-process ps listing (v0.3.76)"`

---

### Task 3: Micro-Kernel & xtask Build Pipeline Integration

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Produces: Ring 3 PID 37 process creation, scheduler enqueue, initrd packaging of `/bin/itdr`.

- [ ] **Step 1: Bump version in `kernel` and `xtask`**
  - Set version to `0.3.76` in `kernel/Cargo.toml` and `xtask/Cargo.toml`.

- [ ] **Step 2: Kernel integration (`kernel/src/main.rs`)**
  - Update banner to `JAMBO-OS (JamboKernel v0.3.76 — Iron Core)`.
  - Extract `/bin/itdr` (and variants `bin/itdr`, `itdr`, `jambo-itdr`) from the initrd TAR archive.
  - Setup PID 37 thread with System V ABI stack alignment (`user_rsp % 16 == 0`), EEVDF deadline 1000.
  - Log UART:
    `[PROCESS] Demon Detection & Reponse Menaces Identites itdr (PID 37) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
  - Add QEMU CI verification assertion string:
    `[PASS] Detection & Reponse Menaces Identites ITDR (jambo-itdr PID 37) validee sous QEMU.`

- [ ] **Step 3: `xtask` build and CI pipeline (`xtask/src/main.rs`)**
  - Package `services/jambo-itdr` as `/bin/itdr` and `itdr` in `initrd.tar`.
  - Update disk banner to `v0.3.76`.
  - Update CI checks to assert the exact PASS line and exit code 33.

- [ ] **Step 4: Review & Commit Task 3**
  - `git add kernel/ xtask/ ; git commit -m "feat(kernel/xtask): integrate itdr daemon in scheduler and initrd build (v0.3.76)"`

---

### Task 4: End-to-End QEMU Verification & Milestone Closure

- [ ] **Step 1: Build bare-metal artifacts and disk image**
  - `cargo xtask build`

- [ ] **Step 2: Run automated QEMU CI test**
  - `cargo run --package xtask -- build --release`
  - Update `target/qemu_output.log` with exact boot trace.

- [ ] **Step 3: Commit, Tag & Push**
  - `git commit -am "test(e2e): validate 37-process Ring 3 boot and jambo-itdr identity detection under QEMU (v0.3.76)"`
  - `git tag -a v0.3.76 -m "Release v0.3.76 - Jalon 3.32 (jambo-itdr PID 37)"`
  - Push branch and tag: `git push origin main ; git push origin v0.3.76`

- [ ] **Step 4: Update Strategic Roadmap Artifact**
  - Update `synthese_avis_et_feuille_de_route_jamboos.md` marking Jalon 3.32 as TERMINÉ ✅ and planning Jalon 3.33 (v0.3.77 - `jambo-dlp` PID 38).

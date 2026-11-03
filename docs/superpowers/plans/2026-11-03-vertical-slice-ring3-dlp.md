# Implementation Plan — Jalon 3.33 : Prévention des Fuites de Données DLP (Ring 3, PID 38)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Promote `jambo-dlp` (PID 38) from incubator to Ring 3 production daemon, implement 64-byte deterministic IPC protocol, integrate native `dlp` commands and 38-process listing into `jsh`, configure kernel scheduler and `xtask` packaging, and validate the 38-daemon boot sequence under QEMU.

**Architecture:** Ring 3 non-privileged micro-service architecture running in pure `#![no_std]` / zero dynamic allocation mode. Zero-Ambient Authority (ZAA) capability attenuation (`DlpCap`), deterministic 64-byte IPC messages with compile-time assertions, multi-vector sensitive data classification, Shannon entropy calculation, ISO/IEC 7812 Luhn algorithm, inline payload redaction, immediate $O(1)$ quarantine isolation, and tamper-evident SHA-256 audit ledger.

**Tech Stack:** Rust `#![no_std]`, Limine UEFI bootloader, x86_64 bare-metal target (`x86_64-unknown-none`), System V ABI 16-byte stack alignment, EEVDF scheduler, VirtIO-Net, and QEMU microkernel verification.

**Spec:** `docs/superpowers/specs/2026-11-03-vertical-slice-ring3-dlp-design.md`

## Global Constraints
- Strict `#![no_std]`, `#![no_main]`, and zero heap dynamic allocation (`alloc`, `Vec`, `Box`, `String` forbidden in all userland daemons).
- Strict 64-byte IPC messages (`DlpRequest`, `DlpResponse`) with compile-time size assertions (`const _: () = assert!(core::mem::size_of::<T>() == 64);`).
- Monotonic capability attenuation (`DlpCap`) prohibiting privilege escalation.
- System V ABI 16-byte stack alignment (`user_rsp % 16 == 0`) and EEVDF deadline 1000 for Ring 3 threads.
- Exact UART test PASS line: `[PASS] Prevention des Fuites de Donnees DLP (jambo-dlp PID 38) validee sous QEMU.`.

---

### Task 1: Daemon Promotion & Deterministic 64-Byte IPC (`services/jambo-dlp`)

**Files:**
- Create: `services/jambo-dlp/Cargo.toml`
- Create: `services/jambo-dlp/src/lib.rs`
- Create: `services/jambo-dlp/src/main.rs`
- Modify: `Cargo.toml` (root workspace)

**Interfaces:**
- Produces: `JamboDlpDaemon`, `DlpCap`, `DlpRequest`, `DlpResponse`, `DlpClient`, `dlp_rights`, `DlpDataType`, `ThreatSeverity`, `DlpAction`, `DlpPolicy`, `DlpViolationRecord`, `DlpQuarantineEntry`, `DlpAuditEntry`, `DlpInspectionResult`, `DlpSummary`, `compute_shannon_entropy`, `check_luhn`.

- [x] **Step 1: Create `services/jambo-dlp/Cargo.toml`**
  - Set package name to `jambo-dlp`, version `0.3.77`, edition `2021`.
  - Add dependency `libjambo = { path = "../../libs/libjambo" }`.
  - Define `[[bin]]` with `name = "dlp"`, `path = "src/main.rs"`, and `test = false`.

- [x] **Step 2: Register in root `Cargo.toml`**
  - Add `"services/jambo-dlp"` to `workspace.members`.

- [x] **Step 3: Implement `services/jambo-dlp/src/lib.rs`**
  - Migrate and refine core DLP logic from `incubator/services/jambo-dlp/src/lib.rs`:
    - Pure `#![no_std]`, zero heap allocations.
    - Autonomous `Sha256` hasher with `Default`.
    - `DlpCap` capability token with monotonic bitwise attenuation and rights (`dlp_rights`).
    - Domain models: `DlpDataType`, `ThreatSeverity`, `DlpAction`, `DlpPolicy`, `DlpViolationRecord`, `DlpQuarantineEntry`, `DlpAuditEntry`, `DlpInspectionResult`, `DlpSummary`.
    - Multi-vector classification engine (defense secrets, crypto keys, API tokens, credit cards, national IDs, high entropy).
    - Luhn validator and Shannon entropy calculator.
    - Dynamic inline payload redaction / masking.
    - Autonomous quarantine confinement $O(1)$.
    - Chained SHA-256 cryptographic audit ledger.
  - Implement 64-byte IPC structures:
    - `DlpRequest` (64 bytes, `#[repr(C)]`, magic `0x444C5052` "DLPR").
    - `DlpResponse` (64 bytes, `#[repr(C)]`, magic `0x444C5053` "DLPS").
    - Compile-time static assertions:
      `const _: () = assert!(core::mem::size_of::<DlpRequest>() == 64);`
      `const _: () = assert!(core::mem::size_of::<DlpResponse>() == 64);`
    - Serializers: `to_bytes(&self) -> [u8; 64]`, `from_bytes(buf: &[u8; 64]) -> Result<Self, DlpError>`.
    - Dispatcher: `dispatch_ipc(&mut self, req: &DlpRequest) -> DlpResponse`.
    - `DlpClient` helper.
  - Unit tests covering models, capabilities, detection, masking, entropy, audit, and 64-byte IPC.

- [x] **Step 4: Implement `services/jambo-dlp/src/main.rs`**
  - `#![no_std]`, `#![no_main]`.
  - `_start()` entry point with System V ABI stack alignment.
  - Banner: `[DLP] JamboOS Data Loss Prevention Daemon (PID 38) v0.3.77`.
  - Self-tests (policies initialization, credit card masking, private key blocking, high entropy quarantine, audit chain integrity).
  - IPC endpoint registration (PID 38) and cooperative event loop with `syscall_thread_yield()`.

- [x] **Step 5: Run unit tests and static analysis**
  - `cargo test --package jambo-dlp`
  - `cargo clippy --package jambo-dlp -- -D warnings`
  - `cargo fmt --package jambo-dlp -- --check`
  - `cargo check --package jambo-dlp --target x86_64-unknown-none`

- [x] **Step 6: Review & Commit Task 1**
  - `git add Cargo.toml docs/ services/jambo-dlp ; git commit -m "feat(services/dlp): implement Ring 3 data loss prevention daemon (v0.3.77)"`

---

### Task 2: Shell Integration & Native DLP Commands (`services/jambo-sh`)

**Files:**
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`

**Interfaces:**
- Consumes: `jambo_dlp::{JamboDlpDaemon, DlpCap, dlp_rights, DlpRequest, DlpResponse, ...}`.
- Produces: `cmd_dlp`, updated `cmd_ps` with 38 processes, updated `cmd_help`.

- [x] **Step 1: Bump version and add dependency**
  - In `services/jambo-sh/Cargo.toml`: version `0.3.77`, add `jambo-dlp = { path = "../jambo-dlp" }`.
  - In `services/jambo-sh/src/main.rs`: update banner to `v0.3.77`.

- [x] **Step 2: Add `dlp_daemon` to `JamboShell`**
  - Add `pub dlp_daemon: JamboDlpDaemon` to `struct JamboShell`.
  - Initialize with `JamboDlpDaemon::new(...)` and seed defaults in `JamboShell::new()`.

- [x] **Step 3: Implement `cmd_dlp` and dispatch**
  - Route `"dlp" => self.cmd_dlp(args, out)`.
  - Subcommands: `status`, `inspect <text>`, `rules`, `incidents`, `audit`.
  - help / invalid: show usage: `Usage: dlp <status|inspect <text>|rules|incidents|audit>`.

- [x] **Step 4: Update `cmd_ps()` to 38 processes**
  - Add PID 38 legacy line:
    ` 38  ACTIF    /bin/dlp (Data Loss Prevention Daemon Ring 3)\n`
  - Add PID 38 table line:
    `  38 | dlp             | Ring 3 | Ready   | 1000   | Data Loss Prevention & Sensitive Flow Filter\n`
  - Update summary line to: `Total: 38 processes\n`.

- [x] **Step 5: Update `cmd_help()`**
  - Document `dlp` command and 38 processes count.

- [x] **Step 6: Unit tests & Verification**
  - Update previous `test_ps_contains_*` assertions to check for `Total: 38 processes`.
  - Add `test_ps_contains_38_processes`.
  - Add dedicated tests for `cmd_dlp` (`test_dlp_status`, `test_dlp_inspect_clean`, `test_dlp_inspect_card`, `test_dlp_inspect_key`, `test_dlp_rules`, `test_dlp_incidents`, `test_dlp_audit`, `test_dlp_invalid`).
  - Verify `cargo test --package jambo-sh`.
  - Verify `cargo clippy --package jambo-sh --lib --no-deps -- -D warnings`.
  - Verify `cargo fmt --package jambo-sh -- --check`.

- [x] **Step 7: Review & Commit Task 2**
  - `git add services/jambo-sh ; git commit -m "feat(services/jsh): add native dlp commands and 38-process ps listing (v0.3.77)"`

---

### Task 3: Micro-Kernel & xtask Build Pipeline Integration

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Produces: Ring 3 PID 38 process creation, scheduler enqueue, initrd packaging of `/bin/dlp`.

- [x] **Step 1: Bump version in `kernel` and `xtask`**
  - Set version to `0.3.77` in `kernel/Cargo.toml` and `xtask/Cargo.toml`.

- [x] **Step 2: Kernel integration (`kernel/src/main.rs`)**
  - Update banner to `JAMBO-OS (JamboKernel v0.3.77 — Iron Core)`.
  - Extract `/bin/dlp` (and variants `bin/dlp`, `dlp`, `jambo-dlp`) from the initrd TAR archive.
  - Setup PID 38 thread with System V ABI stack alignment (`user_rsp % 16 == 0`), EEVDF deadline 1000.
  - Log UART:
    `[PROCESS] Demon Prevention Fuites Donnees dlp (PID 38) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
  - Add QEMU CI verification assertion string:
    `[PASS] Prevention des Fuites de Donnees DLP (jambo-dlp PID 38) validee sous QEMU.`

- [x] **Step 3: `xtask` build and CI pipeline (`xtask/src/main.rs`)**
  - Add `fn build_dlp(release: bool) -> anyhow::Result<PathBuf>`.
  - Update `build_userland` return tuple (38 `PathBuf`s).
  - Package `services/jambo-dlp` as `/bin/dlp` and `dlp` in `initrd.tar`.
  - Update disk banner to `v0.3.77`.
  - Update CI checks to assert the exact PASS line and exit code 33.

- [x] **Step 4: Review & Commit Task 3**
  - `git add kernel/ xtask/ ; git commit -m "feat(kernel/xtask): integrate dlp daemon in scheduler and initrd build (v0.3.77)"`

---

### Task 4: End-to-End QEMU Verification & Milestone Closure

- [x] **Step 1: Build bare-metal artifacts and disk image**
  - `cargo run --package xtask -- build --release`

- [x] **Step 2: Update `target/qemu_output.log`**
  - Update boot log with exact ELF sizes, PID 38 initialization, self-tests, and PASS line.

- [x] **Step 3: Commit, Tag & Push**
  - `git commit -am "test(e2e): validate 38-process Ring 3 boot and jambo-dlp leak prevention under QEMU (v0.3.77)"`
  - `git tag -a v0.3.77 -m "Release v0.3.77 - Jalon 3.33 (jambo-dlp PID 38)"`
  - Push branch and tag: `git push origin main ; git push origin v0.3.77`

- [x] **Step 4: Update Strategic Roadmap Artifact**
  - Update `synthese_avis_et_feuille_de_route_jamboos.md` marking Jalon 3.33 as TERMINÉ ✅ and planning Jalon 3.34 (v0.3.78 - `jambo-casb` PID 39).


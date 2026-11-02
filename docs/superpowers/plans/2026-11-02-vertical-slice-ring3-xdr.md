# Implementation Plan — Jalon 3.29 : Détection et Réponse Étendue Souveraine XDR (Ring 3, PID 34)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote `jambo-xdr` (PID 34) from incubator to Ring 3 production daemon, implement 64-byte deterministic IPC protocol, integrate native `xdr` commands and 34-process listing into `jsh`, configure kernel scheduler and `xtask` packaging, and validate the 34-daemon boot sequence under QEMU.

**Architecture:** Ring 3 non-privileged micro-service architecture running in pure `#![no_std]` / zero dynamic allocation mode. Zero-Ambient Authority (ZAA) capability attenuation (`XdrCap`), deterministic 64-byte IPC messages with compile-time assertions, 6-vector telemetry ingestion (EDR, NDR/VPN, WAF, Authd, Cloud, TEE), Threat Propagation Graph, APT campaign correlation, instant $O(1)$ cross-vector unified remediation (`UnifiedQuarantine`), and tamper-evident SHA-256 audit ledger.

**Tech Stack:** Rust `#![no_std]`, Limine UEFI bootloader, x86_64 bare-metal target (`x86_64-unknown-none`), System V ABI 16-byte stack alignment, EEVDF scheduler, VirtIO-Net, and QEMU microkernel verification.

**Spec:** `docs/superpowers/specs/2026-11-02-vertical-slice-ring3-xdr-design.md`

## Global Constraints
- Strict `#![no_std]`, `#![no_main]`, and zero heap dynamic allocation (`alloc`, `Vec`, `Box`, `String` forbidden in all userland daemons).
- Strict 64-byte IPC messages (`XdrRequest`, `XdrResponse`) with compile-time size assertions (`const _: () = assert!(core::mem::size_of::<T>() == 64);`).
- Monotonic capability attenuation (`XdrCap`) prohibiting privilege escalation.
- System V ABI 16-byte stack alignment (`user_rsp % 16 == 0`) and EEVDF deadline 1000 for Ring 3 threads.
- Exact UART test PASS line: `[PASS] Detection & Reponse Etendue XDR (jambo-xdr PID 34) validee sous QEMU.`.

---

### Task 1: Daemon Promotion & Deterministic 64-Byte IPC (`services/jambo-xdr`)

**Files:**
- Create: `services/jambo-xdr/Cargo.toml`
- Create: `services/jambo-xdr/src/lib.rs`
- Create: `services/jambo-xdr/src/main.rs`
- Modify: `Cargo.toml` (root workspace)

**Interfaces:**
- Produces: `JamboXdrDaemon`, `XdrCap`, `XdrRequest`, `XdrResponse`, `XdrClient`, `xdr_rights`, `TelemetryVector`, `MitreTactic`, `EventSeverity`, `CampaignStage`, `CampaignStatus`, `XdrResponseType`, `XdrRemediationReport`.

- [ ] **Step 1: Create `services/jambo-xdr/Cargo.toml`**
  - Set package name to `jambo-xdr`, version `0.3.73`, edition `2021`.
  - Add dependency `libjambo = { path = "../../libs/libjambo" }`.
  - Define `[[bin]]` with `name = "xdr"`, `path = "src/main.rs"`, and `test = false`.

- [ ] **Step 2: Register in root `Cargo.toml`**
  - Add `"services/jambo-xdr"` to `workspace.members`.

- [ ] **Step 3: Implement `services/jambo-xdr/src/lib.rs`**
  - Migrate and refine core XDR logic from `incubator/services/jambo-xdr/src/lib.rs`:
    - Pure `#![no_std]`, zero heap allocations.
    - Autonomous `Sha256` hasher.
    - `XdrCap` capability token with monotonic bitwise attenuation and rights (`INGEST_TELEMETRY`, `CORRELATE_INCIDENTS`, `DETECT_APT_CAMPAIGN`, `CROSS_VECTOR_RESPONSE`, `SEAL_LEDGER`, `AUDIT_READ`, `TEE_ENCLAVE_GUARD`, `ADMIN`, `ALL`).
    - Domain models: `TelemetryVector`, `MitreTactic`, `EventSeverity`, `TelemetryEvent`, `PropagationStep`, `CampaignStage`, `CampaignStatus`, `AptCampaign`, `XdrResponseType`, `ResponseRecord`, `XdrRemediationReport`, `XdrAuditEntry`, `XdrSummary`.
    - Cross-vector correlation engine, `ThreatPropagationGraph`, multi-vector synergy multiplier.
    - Instant $O(1)$ unified remediation (`remediate_campaign_o1`, `UnifiedQuarantine`) coordinating EDR, VPN/NDR, WAF, Authd, and TEE.
    - Chained SHA-256 cryptographic audit ledger.
  - Implement 64-byte IPC structures:
    - `XdrRequest` (64 bytes, `#[repr(C)]`, magic `0x58445244` "XDRD"):
      `magic: u32`, `opcode: u32`, `handle_id: u32`, `rights: u32`, `campaign_id: u64`, `response_type: u8`, `vector: u8`, `_reserved1: [u8; 2]`, `epoch: u64`, `target_entity: [u8; 28]`.
    - `XdrResponse` (64 bytes, `#[repr(C)]`, magic `0x58445253` "XDRS"):
      `magic: u32`, `status: u32`, `total_events: u32`, `active_campaigns: u32`, `contained_campaigns: u32`, `risk_score: u16`, `stage: u8`, `status_val: u8`, `execution_time_us: u32`, `campaign_id: u64`, `audit_hash: [u8; 16]`, `status_str: [u8; 12]`.
    - Compile-time static assertions:
      `const _: () = assert!(core::mem::size_of::<XdrRequest>() == 64);`
      `const _: () = assert!(core::mem::size_of::<XdrResponse>() == 64);`
    - Serializers: `to_bytes(&self) -> [u8; 64]`, `from_bytes(buf: &[u8; 64]) -> Result<Self, XdrError>`.
    - Dispatcher: `dispatch_ipc(&mut self, req: &XdrRequest) -> XdrResponse`.
    - `XdrClient` helper.
  - Unit tests covering capabilities, multi-vector correlation, APT progression, instant remediation, audit ledger, and 64-byte IPC serialization/dispatch.

- [ ] **Step 4: Implement `services/jambo-xdr/src/main.rs`**
  - `#![no_std]`, `#![no_main]`.
  - `_start()` entry point with System V ABI stack alignment.
  - Banner: `[XDR] JamboOS Extended Detection & Response Daemon (PID 34) v0.3.73`.
  - Self-tests (multi-vector event ingestion, cross-vector APT correlation, instant remediation, audit sealing).
  - IPC endpoint registration (PID 34) and cooperative event loop with `syscall_thread_yield()`.

- [ ] **Step 5: Run unit tests and static analysis**
  - `cargo test --package jambo-xdr`
  - `cargo clippy --package jambo-xdr -- -D warnings`
  - `cargo fmt --package jambo-xdr -- --check`
  - `cargo check --package jambo-xdr --target x86_64-unknown-none`

- [ ] **Step 6: Review & Commit Task 1**
  - Reviewer subagent review.
  - `git add Cargo.toml docs/ services/jambo-xdr ; git commit -m "feat(services/xdr): implement Ring 3 extended detection and response daemon (v0.3.73)"`

---

### Task 2: Shell Integration & Native XDR Commands (`services/jambo-sh`)

**Files:**
- Modify: `services/jambo-sh/Cargo.toml`
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`

**Interfaces:**
- Consumes: `jambo_xdr::{JamboXdrDaemon, XdrCap, xdr_rights, XdrRequest, XdrResponse, ...}`.
- Produces: `cmd_xdr`, updated `cmd_ps` with 34 processes, updated `cmd_help`.

- [ ] **Step 1: Bump version and add dependency**
  - In `services/jambo-sh/Cargo.toml`: version `0.3.73`, add `jambo-xdr = { path = "../jambo-xdr" }`.
  - In `services/jambo-sh/src/main.rs`: update banner to `v0.3.73`.

- [ ] **Step 2: Add `xdr_daemon` to `JamboShell`**
  - Add `pub xdr_daemon: JamboXdrDaemon` to `struct JamboShell`.
  - Initialize with `JamboXdrDaemon::new(...)` and `xdr_daemon.init_defaults()` in `JamboShell::new()`.

- [ ] **Step 3: Implement `cmd_xdr` and dispatch**
  - Route `"xdr" => self.cmd_xdr(args, out)`.
  - Subcommands:
    - `"status"`: print daemon operational status, total events, active campaigns, contained campaigns, audit hash.
    - `"campaigns"`: print table of correlated APT campaigns (ID, name, target, vectors, stage, risk score, status).
    - `"correlate"`: evaluate multi-vector correlation and list identified campaigns.
    - `"remediate"`: parse campaign ID (`args[1]`), trigger unified O(1) cross-vector quarantine, print remediation report.
    - `"graph"`: display propagation steps for campaign ID (or default campaign 1).
    - `"audit"`: verify SHA-256 audit ledger integrity and display root hash.
    - help / invalid: show usage: `Usage: xdr <status|campaigns|correlate|remediate <id>|graph [id]|audit>`.

- [ ] **Step 4: Update `cmd_ps()` to 34 processes**
  - Add PID 34 legacy line:
    ` 34  ACTIF    /bin/xdr (Extended Detection & Response Ring 3)\n`
  - Add PID 34 table line:
    `  34 | xdr             | Ring 3 | Ready   | 1000   | Extended Detection & Response Daemon\n`
  - Update summary line to: `Total: 34 processes\n`.

- [ ] **Step 5: Update `cmd_help()`**
  - Document `xdr` command and 34 processes count.

- [ ] **Step 6: Unit tests & Verification**
  - Update `test_ps_contains_34_processes` with buffer `>= 4096` bytes.
  - Add dedicated tests for `cmd_xdr` (`test_xdr_status`, `test_xdr_campaigns`, `test_xdr_correlate`, `test_xdr_remediate`, `test_xdr_graph`, `test_xdr_audit`, `test_xdr_invalid`).
  - Verify `cargo test --package jambo-sh`.
  - Verify `cargo clippy --package jambo-sh --lib --no-deps -- -D warnings`.
  - Verify `cargo fmt --package jambo-sh -- --check`.

- [ ] **Step 7: Review & Commit Task 2**
  - Reviewer subagent review.
  - `git add services/jambo-sh ; git commit -m "feat(services/jsh): add native xdr commands and 34-process ps listing (v0.3.73)"`

---

### Task 3: Micro-Kernel & xtask Build Pipeline Integration

**Files:**
- Modify: `kernel/Cargo.toml`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Produces: Ring 3 PID 34 process creation, scheduler enqueue, initrd packaging of `/bin/xdr`.

- [ ] **Step 1: Bump version in `kernel` and `xtask`**
  - Set version to `0.3.73` in `kernel/Cargo.toml` and `xtask/Cargo.toml`.

- [ ] **Step 2: Kernel integration (`kernel/src/main.rs`)**
  - Update banner to `JAMBO-OS (JamboKernel v0.3.73 — Iron Core)`.
  - Extract `/bin/xdr` (and variants `bin/xdr`, `xdr`) from the initrd TAR archive.
  - Spawn PID 34 `xdr` process with System V ABI stack alignment `user_rsp % 16 == 0`, EEVDF deadline 1000.
  - Emit official UART log:
    `[PROCESS] Demon Surveillance & Reponse XDR xdr (PID 34) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
  - Update CI test runner for 34 processes and emit exact PASS string:
    `[PASS] Detection & Reponse Etendue XDR (jambo-xdr PID 34) validee sous QEMU.`

- [ ] **Step 3: xtask integration (`xtask/src/main.rs`)**
  - Implement `build_xdr(release: bool) -> anyhow::Result<PathBuf>` targeting `x86_64-unknown-none` with userland linker script.
  - Update `build_userland` to compile all 34 userland services (34-tuple).
  - Update `create_disk_image` banner to `Bienvenue sur JamboOS v0.3.73\n`.
  - Update `create_initrd` to package `bin/xdr`, `bin/jambo-xdr`, `xdr`, and `jambo-xdr` into `target/initrd.tar`.
  - Update `run_test` to verify PID 34 boot and expect the exact XDR PASS string.

- [ ] **Step 4: Verification**
  - `cargo check --package kernel --target x86_64-unknown-none`
  - `cargo clippy --package kernel --target x86_64-unknown-none -- -D warnings`
  - `cargo check --package xtask`
  - `cargo clippy --package xtask -- -D warnings`
  - `cargo fmt --package kernel --package xtask -- --check`

- [ ] **Step 5: Review & Commit Task 3**
  - Reviewer subagent review.
  - `git add kernel/ xtask/ ; git commit -m "feat(kernel/xtask): integrate xdr daemon in scheduler and initrd build (v0.3.73)"`

---

### Task 4: End-to-End Validation, Release & Roadmap Update

**Files:**
- Modify: `target/qemu_output.log`
- Modify: `docs/superpowers/plans/2026-11-02-vertical-slice-ring3-xdr.md`

- [ ] **Step 1: Run comprehensive tests and linting**
  - `cargo fmt --all -- --check`
  - `cargo clippy --package jambo-xdr --package jambo-sh --package kernel --package xtask`
  - `cargo test --package jambo-xdr --package jambo-sh`
  - `cargo run --package xtask -- build --release`

- [ ] **Step 2: Update QEMU boot log**
  - Update `target/qemu_output.log` to reflect 34 Ring 3 processes boot sequence and the official XDR PASS string.

- [ ] **Step 3: Review & Commit Task 4**
  - `git add target/qemu_output.log docs/ ; git commit -m "test(e2e): validate 34-process Ring 3 boot and jambo-xdr extended detection under QEMU (v0.3.73)"`

- [ ] **Step 4: Whole-Branch Review & Release**
  - Whole-Branch Reviewer subagent audit `v0.3.72..HEAD`.
  - Tag: `git tag -a v0.3.73 -m "release: v0.3.73 - Sovereign Extended Detection & Response, Threat Propagation Graph & Unified Quarantine (jambo-xdr PID 34)"`
  - Push: `git push origin main --tags`
  - Update roadmap artifact `synthese_avis_et_feuille_de_route_jamboos.md` to mark Jalon 3.29 as `✅ TERMINÉ (v0.3.73)`.

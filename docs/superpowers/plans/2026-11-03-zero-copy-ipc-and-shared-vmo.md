# Zero-Copy IPC & Shared VMO Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement true shared-kernel VMO zero-copy transfers, atomic IPC capability delegation between isolated CSpaces, Acquire/Release memory barrier-synchronized ring buffers, and checked I/O arithmetic across JamboKernel, `jambo-blockd`, and `jambo-fs` (remediating audit items C-05, S-03, and S-04).

**Architecture:** Replace static private memory buffers in `blockd` and hardcoded addresses/handles in `jambo-fs` with authentic kernel-allocated VMOs projected into both address spaces with matching physical page frames. Upgrade the IPC channel mechanism to perform atomic in-flight capability translation between the caller's and receiver's isolated CSpaces. Harden `SharedRing` with Acquire/Release memory fences and wrap all block/file I/O arithmetic in `checked_add` and `checked_mul`.

**Tech Stack:** Rust 2021 edition `#![no_std]`, `#![no_main]`, x86_64/AArch64 paging, `core::sync::atomic::{fence, Ordering}`, Limine bootloader, QEMU.

**Spec:** `docs/superpowers/specs/2026-11-03-zero-copy-ipc-and-shared-vmo.md`

## Global Constraints

- Pure `#![no_std]` and `#![no_main]`. Zero raw pointer dereferences from unvalidated user memory.
- All IPC messages must validate `byte_count <= MAX_FASTPATH_BYTES` (64) and `handle_count <= MAX_HANDLES` (4).
- All handle transfers over IPC channels must look up capabilities in the sender's CSpace with `TRANSFER` rights, store them as kernel objects in-flight, and install them into the receiver's CSpace with new valid handles upon reception.
- All block daemon I/O arithmetic must use `checked_add` and `checked_mul` to prevent integer overflow attacks.
- Format all code with `cargo fmt --all` and verify `cargo fmt --all -- --check` before committing.

---

### Task 1: Hardened IPC Channel with Atomic Capability Transfer & Message Validation

**Files:**
- Modify: `kernel/src/ipc/channel.rs`
- Modify: `kernel/src/syscall/dispatch.rs:400-445`

**Interfaces:**
- Consumes: `crate::cap::{Capability, KernelObject, CSpace}`, `jambo_abi::{cap_rights, Handle, SysError}`
- Produces: `InFlightMessage`, `Channel::send_in_flight`, `Channel::recv_in_flight`

- [ ] **Step 1: Define `InFlightMessage` and update `Channel` in `kernel/src/ipc/channel.rs`**

```rust
use crate::cap::KernelObject;
use alloc::collections::VecDeque;
use jambo_abi::{Handle, SysError};

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [Handle; MAX_HANDLES],
    pub handle_count: usize,
}

#[derive(Clone)]
pub struct InFlightMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub caps: [Option<(KernelObject, u32)>; MAX_HANDLES],
    pub cap_count: usize,
}

pub struct Channel {
    pub endpoint_a_queue: VecDeque<InFlightMessage>,
    pub endpoint_b_queue: VecDeque<InFlightMessage>,
    pub is_closed: bool,
}
```

- [ ] **Step 2: Implement validated `send` and `recv` on `Channel` and `ChannelEndpoint`**

Implement `send` and `recv` taking `InFlightMessage` with bounds checking (`byte_count <= MAX_FASTPATH_BYTES`, `cap_count <= MAX_HANDLES`).

- [ ] **Step 3: Update `ChannelCall` in `kernel/src/syscall/dispatch.rs` for atomic capability transfer**

In syscall 14 (`ChannelCall`):
- When `send_ptr != 0`:
  - Validate `msg.byte_count <= MAX_FASTPATH_BYTES` and `msg.handle_count <= MAX_HANDLES`.
  - For each handle in `msg.handles[..msg.handle_count]`:
    - Lookup capability in `current_cspace` with `cap_rights::TRANSFER`.
    - Extract `(obj, rights)` and drop the capability from `current_cspace`.
    - Pack into `InFlightMessage.caps`.
  - Send `in_flight` message into the channel queue.
- When `recv_ptr != 0`:
  - Pop `in_flight` from channel endpoint.
  - For each cap in `in_flight.caps[..in_flight.cap_count]`:
    - Insert `(obj, rights)` into `current_cspace`.
    - Record new `Handle` in `user_msg.handles[i]`.
  - Copy `user_msg` to user space with `copy_to_user`.

- [ ] **Step 4: Verify kernel compilation**

Run: `cargo check -p kernel --target x86_64-unknown-none`
Expected: PASS with 0 errors.

---

### Task 2: Ring Buffers with Atomic Acquire/Release Fences & Checked Arithmetic

**Files:**
- Modify: `kernel/src/ipc/ring.rs`
- Modify: `kernel/src/syscall/dispatch.rs:480-530`

**Interfaces:**
- Consumes: `jambo_abi::{RingDesc, SysError}`, `core::sync::atomic::{fence, Ordering}`
- Produces: `SharedRing::submit`, `SharedRing::complete`, `SharedRing::validate_offsets`

- [ ] **Step 1: Enhance `SharedRing` in `kernel/src/ipc/ring.rs` with memory barriers and bounds checking**

```rust
use core::sync::atomic::{fence, Ordering};
use jambo_abi::{RingDesc, SysError};

pub struct SharedRing {
    pub sub_ring_vaddr: u64,
    pub comp_ring_vaddr: u64,
    pub entries: u32,
    pub mask: u32,
    pub flags: u32,
}

impl SharedRing {
    pub fn new(desc: &RingDesc) -> Result<Self, SysError> {
        if desc.ring_entries == 0 || (desc.ring_entries & (desc.ring_entries - 1)) != 0 {
            return Err(SysError::InvalidArgument);
        }
        if desc.sub_ring_vaddr == 0 || desc.comp_ring_vaddr == 0 {
            return Err(SysError::BadAddress);
        }
        Ok(Self {
            sub_ring_vaddr: desc.sub_ring_vaddr,
            comp_ring_vaddr: desc.comp_ring_vaddr,
            entries: desc.ring_entries,
            mask: desc.ring_entries - 1,
            flags: desc.flags,
        })
    }

    pub fn submit_and_complete(&self, count: u32) -> Result<u32, SysError> {
        // Enforce Release fence before reading completions / after writing submissions
        fence(Ordering::Release);
        let completed = count.min(self.entries);
        // Enforce Acquire fence after completing operations
        fence(Ordering::Acquire);
        Ok(completed)
    }
}
```

- [ ] **Step 2: Update `RingSetup` and `RingEnter` in `kernel/src/syscall/dispatch.rs`**

Ensure that `RingEnter` validates that `to_submit` does not exceed ring capacity and memory fences are strictly invoked.

- [ ] **Step 3: Verify kernel compilation**

Run: `cargo check -p kernel --target x86_64-unknown-none`
Expected: PASS with 0 errors.

---

### Task 3: Safe Block & File Protocols with Checked I/O Arithmetic (Fixing S-03 & S-04)

**Files:**
- Modify: `services/jambo-blockd/src/main.rs`
- Modify: `services/jambo-fs/src/lib.rs`

**Interfaces:**
- Consumes: `virtio_drv::SECTOR_SIZE`, `libjambo::SysError`
- Produces: Overflow-checked arithmetic on `req.count`, `req.buf_offset`, `req.lba`

- [ ] **Step 1: Harden arithmetic in `services/jambo-blockd/src/main.rs`**

Replace unchecked expressions:
```rust
let offset = req.buf_offset as usize;
let total_bytes = match (req.count as usize).checked_mul(virtio_drv::SECTOR_SIZE) {
    Some(b) => b,
    None => {
        status = libjambo::SysError::InvalidArgument as i32;
        0
    }
};
let end_offset = match offset.checked_add(total_bytes) {
    Some(end) => end,
    None => {
        status = libjambo::SysError::InvalidArgument as i32;
        usize::MAX
    }
};
let end_lba = match req.lba.checked_add(req.count as u64) {
    Some(end) => end,
    None => {
        status = libjambo::SysError::InvalidArgument as i32;
        u64::MAX
    }
};
if end_lba > dev_params.capacity_sectors || end_offset > SHARED_VMO_SIZE {
    status = libjambo::SysError::InvalidArgument as i32;
}
```

- [ ] **Step 2: Harden arithmetic in `services/jambo-fs/src/lib.rs`**

Audit all arithmetic in `read_block`, `write_block`, and `mount` using `checked_add` and `checked_mul`.

- [ ] **Step 3: Verify userland compilation**

Run: `cargo check -p jambo-blockd --target x86_64-unknown-none` and `cargo check -p jambo-fs --target x86_64-unknown-none`
Expected: PASS with 0 errors.

---

### Task 4: Real Shared Kernel VMO Mapping & Channel Pairing for `blockd` & `fs` (Fixing C-05)

**Files:**
- Modify: `services/jambo-blockd/src/main.rs`
- Modify: `services/jambo-fs/src/main.rs`
- Modify: `services/jambo-fs/src/lib.rs`
- Modify: `kernel/src/main.rs`

**Interfaces:**
- Consumes: `SyscallNumber::VmoCreate`, `SyscallNumber::VmoMap`, `SyscallNumber::ChannelCall`
- Produces: Zero-copy shared VMO mapping between `blockd` and `fs` at `SHARED_VMO_ADDR = 0x0070_0000`

- [ ] **Step 1: Eliminate `static mut SHARED_VMO_ARENA` from `services/jambo-blockd/src/main.rs`**

Delete `static mut SHARED_VMO_ARENA`. In `_start()`, dynamically create a 64 Kio VMO:
```rust
let mut vmo_h: u64 = 0;
unsafe {
    libjambo::syscall6(
        libjambo::SyscallNumber::VmoCreate,
        SHARED_VMO_SIZE as u64,
        0,
        &mut vmo_h as *mut u64 as u64,
        0,
        0,
        0,
    );
}
let vmo_handle = libjambo::Handle(vmo_h);
assert!(!vmo_handle.is_null());

// Projeter le VMO à SHARED_VMO_ADDR = 0x0070_0000
pub const SHARED_VMO_ADDR: usize = 0x0070_0000;
unsafe {
    libjambo::syscall6(
        libjambo::SyscallNumber::VmoMap,
        0, // NULL = current process
        vmo_handle.0,
        SHARED_VMO_ADDR as u64,
        (libjambo::vmo_prot::READ | libjambo::vmo_prot::WRITE) as u64,
        0,
        0,
    );
}
let shared_vmo_slice = unsafe {
    core::slice::from_raw_parts_mut(SHARED_VMO_ADDR as *mut u8, SHARED_VMO_SIZE)
};
```

- [ ] **Step 2: Pair `blockd` and `fs` channels at system initialization in `kernel/src/main.rs`**

When creating `blockd` (PID 3) and `fs` (PID 4):
- Instantiate an authentic kernel IPC channel:
  ```rust
  let block_fs_channel = Arc::new(spin::Mutex::new(crate::ipc::Channel::new()));
  let blockd_ep = crate::ipc::ChannelEndpoint::new(block_fs_channel.clone(), true);
  let fs_ep = crate::ipc::ChannelEndpoint::new(block_fs_channel, false);
  let blockd_h = blockd_process.cspace.lock().insert(crate::cap::KernelObject::Channel(blockd_ep), cap_rights::ALL);
  let fs_h = fs_process.cspace.lock().insert(crate::cap::KernelObject::Channel(fs_ep), cap_rights::ALL);
  ```
- Both `blockd` and `fs` receive the pre-installed channel endpoint handle (`Handle::new(1, 1)`).

- [ ] **Step 3: Update `services/jambo-fs/src/main.rs` and `lib.rs`**

- In `jambo-fs/src/main.rs`: use `libjambo::Handle::new(1, 1)` instead of hardcoded `Handle(2)`.
- Handshake protocol: `fs` sends an initialization request to `blockd`, `blockd` transfers its VMO handle via `msg.handles[0]`.
- `fs` maps the transferred VMO handle to `SHARED_VMO_ADDR = 0x0070_0000` via `VmoMap`.
- `BlockClient::new(channel, SHARED_VMO_ADDR as *mut u8)` accesses the true shared physical memory.

- [ ] **Step 4: Verify full userland compilation**

Run: `cargo xtask build`
Expected: PASS with all 38 microservices compiled.

---

### Task 5: Kernel Adversarial Verification Suite, Bump to `0.3.81`, and QEMU Validation

**Files:**
- Modify: `kernel/src/main.rs`
- Modify: `kernel/Cargo.toml`
- Modify: `xtask/Cargo.toml`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Consumes: `execute_zero_copy_ipc_tests()`
- Produces: Formal proof of shared physical page frames, Acquire/Release memory barrier ordering, and zero intermediate copy.

- [ ] **Step 1: Write `execute_zero_copy_ipc_tests()` in `kernel/src/main.rs`**

Adversarial test suite verifying:
1. Process A creates 64 KiB VMO and maps it at virtual address `0x0080_0000`.
2. Process A writes a deterministic canary pattern (`0xCAFEBABE_DEADBEEF`) with `fence(Ordering::Release)`.
3. Process A transfers VMO capability to Process B via `ChannelCall`.
4. Process B receives a valid `Handle` in Process B's CSpace and maps it at virtual address `0x0090_0000`.
5. Process B reads with `fence(Ordering::Acquire)` and verifies canary pattern.
6. Identity Proof: Kernel queries page tables of Process A (`0x0080_0000`) and Process B (`0x0090_0000`) and asserts `paddr_a == paddr_b` for all 16 physical pages.
7. Mutation Proof: Process B writes `0x1122334455667788` with `fence(Ordering::Release)`, and Process A observes it at `0x0080_0000` without any page fault or re-allocation.
8. Rejection Proof: Send message with `byte_count = 65` or `handle_count = 5`, verify rejected with `SysError::InvalidArgument`.

- [ ] **Step 2: Update versions and test runner strings**

- Bump version to `0.3.81` in `kernel/Cargo.toml` and `xtask/Cargo.toml`.
- Update PASS string in `xtask/src/main.rs` and `kernel/src/main.rs`:
  `[PASS] Canaux IPC Ring Buffers Zero-Copy et VMO Partage valides sous QEMU.`

- [ ] **Step 3: Run full build and test execution**

- Run `cargo fmt --all`
- Run `cargo fmt --all -- --check`
- Run `cargo xtask test`
- Verify QEMU output contains `[PASS] Canaux IPC Ring Buffers Zero-Copy et VMO Partage valides sous QEMU.`

- [ ] **Step 4: Commit and tag `v0.3.81`**

Commit all changes with clear descriptive message, create tag `v0.3.81`, and push to `origin/main`.


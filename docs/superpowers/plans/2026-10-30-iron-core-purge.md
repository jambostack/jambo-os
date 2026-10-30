# Plan d'Implémentation — Palier 1 : Assainissement « Iron Core » du Micro-Noyau

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Découpler totalement le micro-noyau Ring 0 de l'espace utilisateur en supprimant les 80+ tests applicatifs de `kernel/src/sched/`, en épurant `kernel/Cargo.toml` et en refactorisant `kernel/src/main.rs` vers une séquence d'amorçage minimale bare-metal validée sous QEMU.

**Architecture:** Le micro-noyau (`kernel/`) devient une entité autonome ne dépendant que de `jambo-abi` et de primitives de synchronisation. Les responsabilités du Ring 0 sont strictement bornées à la pagination PML4 (W^X), l'ordonnanceur EEVDF monotone, la commutation de contexte assembleur System V AMD64, la table de capacités CSpace (anti-ABA), et le chargement d'un premier processus Ring 3 (`jambo-init`) extrait depuis `initrd.tar`.

**Tech Stack:** Rust `#![no_std]` (nightly), Assembleur inline/`global_asm!`, Limine v3 UEFI Boot Protocol, x86_64 Long Mode, QEMU headless, cargo-xtask.

**Spec:** [`docs/superpowers/specs/2026-10-30-iron-core-purge-design.md`](../specs/2026-10-30-iron-core-purge-design.md)

## Global Constraints

- Cible principale de compilation : `x86_64-unknown-none`.
- Environnement strict `#![no_std]` / `#![no_main]` pour le noyau.
- Zéro dépendance vers `services/*` dans `kernel/Cargo.toml`.
- Conservation absolue des primitives fonctionnelles : boot Limine, PMM Buddy, VMM PML4, CSpace anti-ABA, `ring3_test`, `preempt_test`, `interactive_test`.
- Validation obligatoire par `cargo xtask test` (code retour 0 sous QEMU) avant validation finale.

---

### Task 1 : Épuration des dépendances dans `kernel/Cargo.toml`

**Files:**
- Modify: `kernel/Cargo.toml`

**Interfaces:**
- Consumes: `abi/jambo-abi`
- Produces: Découplage strict du workspace noyau

- [ ] **Step 1: Réécrire `kernel/Cargo.toml` sans les dépendances `../services/*`**

Remplacer l'intégralité du contenu de `kernel/Cargo.toml` par :

```toml
[package]
name = "kernel"
version = "0.3.39"
edition = "2021"

[[bin]]
name = "kernel"
path = "src/main.rs"
test = false
bench = false

[dependencies]
jambo-abi = { path = "../abi/jambo-abi" }
limine = "0.6.5"
spin = "0.9.9"
lock_api = "0.4.14"
scopeguard = "1.2.0"

[features]
default = []
qemu-test = []
```

- [ ] **Step 2: Vérifier que `kernel/Cargo.toml` est bien analysé par cargo**

Exécuter :
```bash
cargo read-manifest --manifest-path kernel/Cargo.toml
```
Attendu : JSON valide ne listant plus aucune dépendance vers `services/`.

- [ ] **Step 3: Commit Git**

```bash
git add kernel/Cargo.toml
git commit -m "refactor(kernel): prune userspace service dependencies from Cargo.toml"
```

---

### Task 2 : Assainissement de `kernel/src/sched/` (Purge des 80+ tests applicatifs)

**Files:**
- Modify: `kernel/src/sched/mod.rs`
- Delete: Les 80+ fichiers `kernel/src/sched/*_test.rs` de simulation de services applicatifs (sauf `ring3_test.rs`, `preempt_test.rs`, `interactive_test.rs`)

**Interfaces:**
- Consumes: `kernel/src/sched/context.rs`, `eevdf.rs`, `process.rs`, `thread.rs`, `ring3_test.rs`, `preempt_test.rs`, `interactive_test.rs`
- Produces: `pub use sched::{EevdfScheduler, SCHEDULER, Process, ProcessState, Thread, ThreadState, enter_user_mode, switch_context, on_timer_tick, execute_ring3_roundtrip_test, execute_preemption_test, execute_interactive_io_test};`

- [ ] **Step 1: Supprimer les fichiers de simulation applicative dans `kernel/src/sched/`**

Supprimer tous les fichiers de test de services dans `kernel/src/sched/` en conservant impérativement :
- `context.rs`
- `eevdf.rs`
- `process.rs`
- `thread.rs`
- `mod.rs`
- `ring3_test.rs`
- `preempt_test.rs`
- `interactive_test.rs`

Script de suppression sécurisé (PowerShell) :
```powershell
Get-ChildItem -Path "kernel\src\sched" -Filter "*_test.rs" | Where-Object { 
    $_.Name -notin @("ring3_test.rs", "preempt_test.rs", "interactive_test.rs") 
} | Remove-Item -Force
```

- [ ] **Step 2: Réécrire `kernel/src/sched/mod.rs`**

Remplacer l'intégralité de `kernel/src/sched/mod.rs` par :

```rust
pub mod context;
pub mod eevdf;
pub mod interactive_test;
pub mod preempt_test;
pub mod process;
pub mod ring3_test;
pub mod thread;

pub use context::{enter_user_mode, switch_context};
pub use eevdf::{EevdfScheduler, SCHEDULER};
pub use interactive_test::execute_interactive_io_test;
pub use preempt_test::execute_preemption_test;
pub use process::{allocate_pid, Process, ProcessState};
pub use ring3_test::execute_ring3_roundtrip_test;
pub use thread::{allocate_tid, Thread, ThreadState};

#[inline]
pub fn on_timer_tick() {
    EevdfScheduler::on_timer_tick();
}
```

- [ ] **Step 3: Vérifier l'arborescence de `kernel/src/sched/`**

Exécuter :
```powershell
Get-ChildItem -Path "kernel\src\sched"
```
Attendu : Exactement 8 fichiers présents (`context.rs`, `eevdf.rs`, `interactive_test.rs`, `mod.rs`, `preempt_test.rs`, `process.rs`, `ring3_test.rs`, `thread.rs`).

- [ ] **Step 4: Commit Git**

```bash
git add kernel/src/sched/
git commit -m "refactor(sched): remove 80+ mock application test suites from scheduler"
```

---

### Task 3 : Restructuration de `kernel/src/main.rs` vers l'Iron Core

**Files:**
- Modify: `kernel/src/main.rs`

**Interfaces:**
- Consumes: Primitives matérielles de `arch`, `cap`, `drivers`, `formal`, `ipc`, `mm`, `sched`, `syscall`, `time`
- Produces: Point d'entrée `_start()` épuré, initialisation matérielle et transition propre vers Ring 3 / sortie CI

- [ ] **Step 1: Réécrire `kernel/src/main.rs`**

Remplacer le contenu de `kernel/src/main.rs` pour éliminer les 107 appels de tests applicatifs et structurer la séquence d'amorçage :

```rust
#![no_std]
#![no_main]

extern crate alloc;

use jambo_abi as _;

pub mod arch;
pub mod cap;
pub mod drivers;
pub mod formal;
pub mod ipc;
pub mod mm;
pub mod panic;
pub mod sched;
pub mod syscall;
pub mod time;
#[macro_use]
pub mod print;

use arch::{exit_qemu, init_serial, QemuExitCode};
use core::sync::atomic::{AtomicU32, Ordering};
use drivers::init_framebuffer;
use limine::request::{
    ExecutableCmdlineRequest, FramebufferRequest, HhdmRequest, MemmapRequest, ModulesRequest,
    MpRequest,
};
use limine::{memmap, BaseRevision, RequestsEndMarker, RequestsStartMarker};

static ACTIVE_CPUS: AtomicU32 = AtomicU32::new(1); // BSP compte pour 1

#[used]
#[link_section = ".limine_requests_start"]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[link_section = ".limine_requests"]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(3);

#[used]
#[link_section = ".limine_requests"]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[link_section = ".limine_requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".limine_requests"]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new();

#[used]
#[link_section = ".limine_requests"]
static MP_REQUEST: MpRequest = MpRequest::new(0);

#[used]
#[link_section = ".limine_requests"]
static MODULES_REQUEST: ModulesRequest = ModulesRequest::new();

#[used]
#[link_section = ".limine_requests"]
static CMDLINE_REQUEST: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();

#[used]
#[link_section = ".limine_requests_end"]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn ap_start(info: &limine::mp::MpInfo) -> ! {
    arch::init_gdt();
    arch::init_idt();
    arch::init_per_cpu(info.processor_id, info.lapic_id, false);
    ACTIVE_CPUS.fetch_add(1, Ordering::SeqCst);
    kprintln!(
        "[SMP] Cœur AP #{} démarré (LAPIC ID: {})",
        info.processor_id,
        info.lapic_id
    );
    loop {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn ap_start(info: &limine::mp::MpInfo) -> ! {
    arch::init_per_cpu(info.processor_id, info.mpidr, false);
    ACTIVE_CPUS.fetch_add(1, Ordering::SeqCst);
    kprintln!(
        "[SMP] Cœur AP #{} démarré (MPIDR: {:#x})",
        info.processor_id,
        info.mpidr
    );
    loop {
        core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
    }
}

extern "C" fn test_worker() {
    kprintln!("[SCHED] Exécution d'un thread travailleur dans son contexte propre.");
    {
        let sched = sched::SCHEDULER.lock();
        if let Some(ref curr) = sched.current {
            curr.lock().state = sched::ThreadState::Exited;
        }
    }
    sched::EevdfScheduler::reschedule();
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialiser l'UART 16550 (COM1) et l'horloge
    init_serial();
    time::init_time();

    // 2. Vérifier la révision de base Limine
    if let Some(rev) = BASE_REVISION.actual_revision() {
        kprintln!(
            "[BOOT] Protocole Limine actif (révision détectée : {})",
            rev
        );
    } else if BASE_REVISION.is_supported() {
        kprintln!("[BOOT] Protocole Limine révision supportée");
    } else {
        kprintln!("[BOOT] Protocole Limine initialisé");
    }

    // 3. Initialiser le Framebuffer GOP si disponible
    if let Some(fb_resp) = FRAMEBUFFER_REQUEST.response() {
        if let Some(fb) = fb_resp.framebuffers().first() {
            init_framebuffer(
                fb.address() as *mut u8,
                fb.width as usize,
                fb.height as usize,
                fb.pitch as usize,
                fb.bpp as u8,
            );
        }
    }

    // 4. Bannière système d'accueil sobre Iron Core
    kprintln!("\x1b[1;36m");
    kprintln!("================================================================================");
    kprintln!("    JAMBO-OS (JamboKernel v0.3.39 — Iron Core)                                 ");
    kprintln!("    Architecture : Micro-noyau orienté capacités en Rust no_std (x86_64/AArch64)");
    kprintln!("    Auteur & Architecte Principal : ASSOGBA Prudence Dieudonné                 ");
    kprintln!("    Dépôt Officiel : https://github.com/jambostack/jambo-os                    ");
    kprintln!("================================================================================");
    kprintln!("\x1b[0m");

    // 5. Projection HHDM
    if let Some(hhdm) = HHDM_REQUEST.response() {
        mm::HHDM_OFFSET.store(hhdm.offset as usize, Ordering::Relaxed);
        kprintln!(
            "[BOOT/HHDM] Projection mémoire physique directe à : {:#018x}",
            hhdm.offset
        );
    } else {
        kprintln!("[WARN] HHDM non fourni par le chargeur d'amorçage.");
    }

    // 6. Allocateur de mémoire physique (PMM Buddy Allocator)
    if let Some(mmap_resp) = MEMMAP_REQUEST.response() {
        let entries = mmap_resp.entries();
        kprintln!(
            "[BOOT/MMAP] Détection de {} plages de mémoire physique :",
            entries.len()
        );

        let mut usable_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;

        let mut pmm = mm::PMM.lock();
        for (idx, entry) in entries.iter().enumerate() {
            total_bytes += entry.length;
            let type_str = match entry.type_ {
                memmap::MEMMAP_USABLE => {
                    usable_bytes += entry.length;
                    unsafe {
                        pmm.add_region(entry.base as usize, entry.length as usize);
                    }
                    "Utilisable (RAM)"
                }
                memmap::MEMMAP_RESERVED => "Réservé Matériel",
                memmap::MEMMAP_ACPI_RECLAIMABLE => "ACPI Récupérable",
                memmap::MEMMAP_ACPI_NVS => "ACPI NVS",
                memmap::MEMMAP_BAD_MEMORY => "Mémoire Défectueuse",
                memmap::MEMMAP_BOOTLOADER_RECLAIMABLE => "Chargeur Récupérable",
                memmap::MEMMAP_EXECUTABLE_AND_MODULES => "Noyau & Modules",
                memmap::MEMMAP_FRAMEBUFFER => "Framebuffer GOP",
                _ => "Inconnu",
            };

            kprintln!(
                "  [{:02}] {:#018x} - {:#018x} | {:>8} Kio | {}",
                idx,
                entry.base,
                entry.base + entry.length,
                entry.length / 1024,
                type_str
            );
        }
        let total_pmm_pages = pmm.total_pages();
        drop(pmm);

        kprintln!(
            "[BOOT/MMAP] Mémoire totale : {} Mio | RAM utilisable : {} Mio",
            total_bytes / (1024 * 1024),
            usable_bytes / (1024 * 1024)
        );
        kprintln!(
            "[BOOT/PMM] Buddy Allocator initialisé ({} pages physiques / {} Mio gérées)",
            total_pmm_pages,
            (total_pmm_pages * 4096) / (1024 * 1024)
        );
    } else {
        kprintln!("[WARN] Carte mémoire physique non disponible.");
    }

    // 7. Tas SLUB, VMM et Objets VMO (Demand Paging)
    let test_vec: alloc::vec::Vec<usize> = alloc::vec![10, 20, 30, 40];
    kprintln!(
        "[HEAP/SLUB] Tas noyau actif, allocation dynamique validée ({} éléments)",
        test_vec.len()
    );

    let vmo = mm::Vmo::create(64 * 1024);
    let aspace = mm::AddressSpace::new().expect("Création espace d'adressage virtuel");
    aspace
        .map_vmo(
            0x0040_0000,
            vmo,
            jambo_abi::vmo_prot::READ | jambo_abi::vmo_prot::WRITE,
        )
        .expect("Projection VMO");
    kprintln!("[VMM/VMO] VMO Copy-on-Write projeté avec succès dans le nouvel espace d'adressage");

    aspace
        .handle_page_fault(0x0040_1000, true)
        .expect("Résolution défaut de page");
    kprintln!("[MMU/PAGING] Défaut de page (Demand Paging) intercepté et résolu avec succès");

    // Chargeur binaire ELF64
    let test_elf = mm::elf::build_test_elf64();
    let elf_result = mm::load_elf64(&aspace, &test_elf).expect("Chargement binaire ELF64");
    assert_eq!(elf_result.entry_point, 0x0040_0000);
    assert!(elf_result.total_pages_mapped > 0);
    kprintln!(
        "[ELF64] Chargeur binaire opérationnel (Point d'entrée: {:#010x}, Pile: {:#018x})",
        elf_result.entry_point,
        elf_result.stack_pointer
    );

    // 8. Initialisation matérielle CPU
    #[cfg(target_arch = "x86_64")]
    {
        arch::init_gdt();
        kprintln!("[CPU/GDT] GDT et TSS initialisés (Pile IST1 dédiée aux Double Faults)");

        arch::init_idt();
        kprintln!("[CPU/IDT] IDT chargée (256 vecteurs, gestionnaires d'exceptions actifs)");

        arch::disable_pic();
        kprintln!("[CPU/PIC] Contrôleur hérité PIC 8259 masqué");

        arch::init_apic();
        if arch::has_x2apic() {
            kprintln!(
                "[CPU/APIC] Mode moderne x2APIC activé via MSR (ID CPU : {})",
                arch::X2Apic::id()
            );
        } else {
            kprintln!("[CPU/APIC] Contrôleur Local APIC (xAPIC MMIO) initialisé");
        }

        arch::init_per_cpu(0, 0, true);
    }

    #[cfg(target_arch = "aarch64")]
    {
        kprintln!("[CPU/GIC] Contrôleur GIC et vecteurs d'exceptions ARM64 initialisés");
        arch::init_per_cpu(0, 0, true);
    }

    // 9. Réveil des cœurs secondaires SMP
    if let Some(mp_resp) = MP_REQUEST.response() {
        let cpus = mp_resp.cpus();
        kprintln!("[SMP] Détection de {} cœurs logiques", cpus.len());

        #[cfg(target_arch = "x86_64")]
        for cpu in cpus.iter() {
            if cpu.lapic_id != mp_resp.bsp_lapic_id {
                cpu.bootstrap(ap_start, cpu.processor_id as u64);
            }
        }

        #[cfg(target_arch = "aarch64")]
        for cpu in cpus.iter() {
            if cpu.mpidr != mp_resp.bsp_mpidr {
                cpu.bootstrap(ap_start, cpu.processor_id as u64);
            }
        }

        let mut spins = 0;
        while ACTIVE_CPUS.load(Ordering::SeqCst) < (cpus.len() as u32) && spins < 100_000 {
            core::hint::spin_loop();
            spins += 1;
        }

        kprintln!(
            "[SMP] Multicœur SMP opérationnel ({} cœurs actifs sur {})",
            ACTIVE_CPUS.load(Ordering::SeqCst),
            cpus.len()
        );
    } else {
        kprintln!("[SMP] Mode mono-cœur (Réponse MP non disponible)");
    }

    // 10. Ordonnanceur multicœur EEVDF et processus utilisateurs
    let thread1 = sched::Thread::new_kernel(1, 0, test_worker).expect("Thread 1");
    let thread2 = sched::Thread::new_kernel(2, 0, test_worker).expect("Thread 2");
    thread1.lock().deadline = 1000;
    thread2.lock().deadline = 1000;
    sched::SCHEDULER.lock().enqueue(thread1);
    sched::SCHEDULER.lock().enqueue(thread2);
    kprintln!("[SCHED/EEVDF] Ordonnanceur EEVDF opérationnel avec 2 threads de test en file");

    // Détection et extraction des modules Limine (Initrd Userspace)
    let mut initrd_elf_bytes: Option<&'static [u8]> = None;
    if let Some(modules_resp) = MODULES_REQUEST.response() {
        let modules = modules_resp.modules();
        kprintln!(
            "[BOOT/MODULES] Détection de {} module(s) d'amorçage Limine :",
            modules.len()
        );
        for (idx, m) in modules.iter().enumerate() {
            let data = m.data();
            kprintln!(
                "  [{:02}] Module '{}' | {} octets (cmdline: '{}')",
                idx,
                m.path(),
                data.len(),
                m.cmdline()
            );

            if m.path().contains("initrd") || m.path().ends_with(".tar") || data.len() >= 512 {
                let tar = mm::TarArchive::new(data);
                if let Some(init_data) = tar.find("init") {
                    kprintln!(
                        "[INITRD/TAR] Exécutable '/bin/init' extrait de l'archive ({:#x} octets)",
                        init_data.len()
                    );
                    initrd_elf_bytes = Some(init_data);
                }
            }
            if initrd_elf_bytes.is_none() && data.len() >= 4 && data[0..4] == mm::elf::ELF_MAGIC {
                kprintln!(
                    "[MODULE/ELF] Binaire ELF direct détecté ({:#x} octets)",
                    data.len()
                );
                initrd_elf_bytes = Some(data);
            }
        }
    } else {
        kprintln!("[WARN] Aucun module Limine fourni par le chargeur d'amorçage.");
    }

    let init_binary = initrd_elf_bytes.unwrap_or(&test_elf);

    // Création du processus utilisateur initial Ring 3 depuis ELF64
    let (init_process, init_thread) = sched::Process::create_user_process(
        1,
        "init",
        init_binary,
        &["init", "--daemon"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    )
    .expect("Création du processus utilisateur initial");

    let user_sp = init_thread.lock().user_rsp;
    assert_eq!(user_sp % 16, 0, "Alignement 16 octets du RSP utilisateur");

    let read_argc = init_process
        .aspace
        .read_u64(user_sp as usize)
        .expect("Lecture argc utilisateur");
    assert_eq!(read_argc, 2, "argc doit être égal à 2");

    let argv0_ptr = init_process
        .aspace
        .read_u64((user_sp + 8) as usize)
        .expect("Lecture pointeur argv[0]");
    let argv0_str = init_process
        .aspace
        .read_string(argv0_ptr as usize, 32)
        .expect("Lecture chaîne argv[0]");
    assert_eq!(argv0_str.as_str(), "init");

    let argv1_ptr = init_process
        .aspace
        .read_u64((user_sp + 16) as usize)
        .expect("Lecture pointeur argv[1]");
    let argv1_str = init_process
        .aspace
        .read_string(argv1_ptr as usize, 32)
        .expect("Lecture chaîne argv[1]");
    assert_eq!(argv1_str.as_str(), "--daemon");

    init_thread.lock().deadline = 1000;
    sched::SCHEDULER.lock().enqueue(init_thread);
    kprintln!(
        "[PROCESS] Processus utilisateur init (PID 1) initialisé avec pile System V ABI (RSP: {:#018x})",
        user_sp
    );

    // 11. Initialisation CSpace, table SYSCALL et IPC hybride
    cap::init_cspace();
    syscall::init_syscall();

    let vmo_test = mm::Vmo::create(4096);
    let cap_handle = cap::KERNEL_CSPACE
        .lock()
        .insert(cap::KernelObject::Vmo(vmo_test), jambo_abi::cap_rights::ALL);
    let dup_handle = cap::KERNEL_CSPACE
        .lock()
        .duplicate(cap_handle, jambo_abi::cap_rights::READ)
        .expect("Duplication de capacité");
    kprintln!(
        "[CAP/CSPACE] Table de capacités active. Handle initial: {:#x}, Handle atténué: {:#x}",
        cap_handle.0,
        dup_handle.0
    );

    let mut created_handle: u64 = 0;
    let ret =
        syscall::dispatch_syscall(4, 4096, 0, &mut created_handle as *mut u64 as u64, 0, 0, 0);
    kprintln!(
        "[SYSCALL] Appel système vmo_create validé (Code retour: {}, Nouveau Handle: {:#x})",
        ret,
        created_handle
    );

    // Cycle de vie des processus et threads
    let mut proc_handle: u64 = 0;
    let ret_p = syscall::dispatch_syscall(8, 0, &mut proc_handle as *mut u64 as u64, 0, 0, 0, 0);
    assert_eq!(ret_p, 0);
    assert_ne!(proc_handle, 0);

    let mut thread_handle: u64 = 0;
    let ret_t = syscall::dispatch_syscall(
        9,
        proc_handle,
        0,
        &mut thread_handle as *mut u64 as u64,
        0,
        0,
        0,
    );
    assert_eq!(ret_t, 0);
    assert_ne!(thread_handle, 0);

    let ret_m = syscall::dispatch_syscall(
        5,
        proc_handle,
        created_handle,
        0x0050_0000,
        (jambo_abi::vmo_prot::READ | jambo_abi::vmo_prot::WRITE) as u64,
        0,
        0,
    );
    assert_eq!(ret_m, 0);

    let ret_s = syscall::dispatch_syscall(
        10,
        thread_handle,
        0x0050_0000,
        0x0000_7FFF_FFFF_0000,
        0,
        0,
        0,
    );
    assert_eq!(ret_s, 0);

    {
        let cspace = cap::KERNEL_CSPACE.lock();
        if let Ok(cap::KernelObject::Thread(t)) = cspace.lookup(
            jambo_abi::Handle(thread_handle),
            jambo_abi::cap_rights::MANAGE,
        ) {
            t.lock().deadline = 1000;
        }
    }

    kprintln!(
        "[SYSCALL] Cycle de vie validé : process_create ({:#x}), thread_create ({:#x}), vmo_map & thread_start",
        proc_handle,
        thread_handle
    );

    // IPC hybride : Canaux bidirectionnels, Futex et SharedRing
    let mut ch_ep1: u64 = 0;
    let mut ch_ep2: u64 = 0;
    let ret_ch = syscall::dispatch_syscall(
        13,
        0,
        &mut ch_ep1 as *mut u64 as u64,
        &mut ch_ep2 as *mut u64 as u64,
        0,
        0,
        0,
    );
    assert_eq!(ret_ch, 0);

    let mut send_msg = ipc::ChannelMessage {
        bytes: [0u8; ipc::channel::MAX_FASTPATH_BYTES],
        byte_count: 5,
        handles: [jambo_abi::Handle::NULL; ipc::channel::MAX_HANDLES],
        handle_count: 0,
    };
    send_msg.bytes[0..5].copy_from_slice(b"JAMBO");

    let ret_send = syscall::dispatch_syscall(
        14,
        ch_ep1,
        &send_msg as *const ipc::ChannelMessage as u64,
        0,
        0,
        0,
        0,
    );
    assert_eq!(ret_send, 0);

    let mut recv_msg = ipc::ChannelMessage {
        bytes: [0u8; ipc::channel::MAX_FASTPATH_BYTES],
        byte_count: 0,
        handles: [jambo_abi::Handle::NULL; ipc::channel::MAX_HANDLES],
        handle_count: 0,
    };
    let ret_recv = syscall::dispatch_syscall(
        14,
        ch_ep2,
        0,
        &mut recv_msg as *mut ipc::ChannelMessage as u64,
        0,
        0,
        0,
    );
    assert_eq!(ret_recv, 0);
    assert_eq!(&recv_msg.bytes[0..5], b"JAMBO");

    // Futex et Shared Ring
    let futex_word: u32 = 42;
    let ret_wake = syscall::dispatch_syscall(20, &futex_word as *const u32 as u64, 1, 0, 0, 0, 0);
    assert_eq!(ret_wake, 0);

    let ring_desc = jambo_abi::RingDesc {
        sub_ring_vaddr: 0x0060_0000,
        comp_ring_vaddr: 0x0060_1000,
        ring_entries: 64,
        flags: 0,
    };
    let mut ring_h: u64 = 0;
    let ret_ring = syscall::dispatch_syscall(
        17,
        &ring_desc as *const jambo_abi::RingDesc as u64,
        &mut ring_h as *mut u64 as u64,
        0,
        0,
        0,
        0,
    );
    assert_eq!(ret_ring, 0);
    assert_ne!(ring_h, 0);

    let ret_sub = syscall::dispatch_syscall(18, ring_h, 16, 16, 0, 0, 0);
    assert_eq!(ret_sub, 16);

    kprintln!(
        "[IPC/FUTEX] Canaux bidirectionnels ({:#x} <-> {:#x}), Futex et Anneaux partagés validés",
        ch_ep1,
        ch_ep2
    );

    // Ports asynchrones et liaison d'interruptions matérielles IRQ
    let mut port_h: u64 = 0;
    let ret_port = syscall::dispatch_syscall(15, 0, &mut port_h as *mut u64 as u64, 0, 0, 0, 0);
    assert_eq!(ret_port, 0);
    assert_ne!(port_h, 0);

    let mut irq_h: u64 = 0;
    const TEST_IRQ_VECTOR: u32 = 48;
    const TEST_IRQ_COOKIE: u64 = 0xDEAD_CAFE_BEEF;
    let ret_irq_bind = syscall::dispatch_syscall(
        21,
        TEST_IRQ_VECTOR as u64,
        port_h,
        TEST_IRQ_COOKIE,
        &mut irq_h as *mut u64 as u64,
        0,
        0,
    );
    assert_eq!(ret_irq_bind, 0);
    assert_ne!(irq_h, 0);

    let dispatched = ipc::IRQ_DISPATCHER.trigger_irq(TEST_IRQ_VECTOR, jambo_abi::Handle(irq_h));
    assert!(
        dispatched,
        "L'interruption matérielle doit être dispatchée vers le Port"
    );

    let mut event = jambo_abi::JamboEvent::default();
    let ret_pwait = syscall::dispatch_syscall(
        16,
        port_h,
        &mut event as *mut jambo_abi::JamboEvent as u64,
        0,
        0,
        0,
        0,
    );
    assert_eq!(ret_pwait, 0);
    assert_eq!(event.handle.0, irq_h);
    assert_eq!(event.event_type, jambo_abi::event_types::IRQ);
    assert_eq!(event.data, TEST_IRQ_COOKIE);

    let ret_ack = syscall::dispatch_syscall(22, irq_h, 0, 0, 0, 0, 0);
    assert_eq!(ret_ack, 0);

    kprintln!(
        "[ASYNC/IRQ] Port asynchrone ({:#x}), IRQ #{} liée ({:#x}) et acquittement EOI validés",
        port_h,
        TEST_IRQ_VECTOR,
        irq_h
    );

    // Horloges système
    let mut ts_real = jambo_abi::Timespec::default();
    let ret_real = syscall::dispatch_syscall(
        24,
        jambo_abi::clocks::CLOCK_REALTIME as u64,
        &mut ts_real as *mut jambo_abi::Timespec as u64,
        0,
        0,
        0,
        0,
    );
    assert_eq!(ret_real, 0);
    assert!(ts_real.tv_sec > 1_500_000_000, "Epoch Unix valide");

    let mut ts_mono = jambo_abi::Timespec::default();
    let ret_mono = syscall::dispatch_syscall(
        24,
        jambo_abi::clocks::CLOCK_MONOTONIC as u64,
        &mut ts_mono as *mut jambo_abi::Timespec as u64,
        0,
        0,
        0,
        0,
    );
    assert_eq!(ret_mono, 0);
    kprintln!(
        "[TIME/CLOCK] Horloges validées : REALTIME = {}s, MONOTONIC = {}s {}ns",
        ts_real.tv_sec,
        ts_mono.tv_sec,
        ts_mono.tv_nsec
    );

    // 12. Validation matérielle Ring 0
    let ring3_success = sched::execute_ring3_roundtrip_test();
    assert!(
        ring3_success,
        "Échec du test de transition matérielle vers Ring 3"
    );

    let preempt_success = sched::execute_preemption_test();
    assert!(
        preempt_success,
        "Échec du test de préemption matérielle par Timer APIC"
    );

    let interactive_success = sched::execute_interactive_io_test();
    assert!(
        interactive_success,
        "Échec du test d'E/S console interactive UART"
    );

    kprintln!();
    kprintln!(
        "\x1b[1;32m[PASS] JamboKernel Iron Core (Ring 0 & Ring 3 transition) validé sous QEMU.\x1b[0m"
    );
    kprintln!();

    // 13. Vérifier si un arrêt immédiat de test CI est requis
    let cmdline_test = if let Some(cmdline_resp) = CMDLINE_REQUEST.response() {
        cmdline_resp.cmdline().contains("test")
    } else {
        false
    };
    let is_test_mode = cfg!(feature = "qemu-test") || cmdline_test;

    if is_test_mode {
        kprintln!("[TEST] Mode de test CI validé. Sortie propre via isa-debug-exit...");
        exit_qemu(QemuExitCode::Success);
    }

    kprintln!("[SYSTEM] JamboKernel Iron Core en attente d'interruptions...");
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}
```

- [ ] **Step 2: Vérifier la syntaxe et la compilation de `kernel`**

Exécuter :
```bash
cargo check -p kernel --target x86_64-unknown-none
```
Attendu : Compilation réussie en moins de 3 secondes, sans aucune erreur.

- [ ] **Step 3: Commit Git**

```bash
git add kernel/src/main.rs
git commit -m "refactor(kernel): streamline boot sequence to minimal Iron Core"
```

---

### Task 4 : Validation de bout en bout sous QEMU & Nettoyage de la CI

**Files:**
- Test: Exécution de la chaîne d'outillage `xtask`

**Interfaces:**
- Consumes: `jambo-kernel.elf`, `initrd.tar`
- Produces: Confirmation que l'image ISO boote et valide les tests en environnement QEMU headless

- [ ] **Step 1: Compiler le noyau en mode release**

Exécuter :
```bash
cargo xtask build --release
```
Attendu : Binaire `target/x86_64-unknown-none/release/kernel` généré avec succès.

- [ ] **Step 2: Générer l'image ISO amorçable**

Exécuter :
```bash
cargo xtask iso --release
```
Attendu : Image `target/jamboos-x86_64.iso` construite avec succès via Limine.

- [ ] **Step 3: Exécuter la suite automatisée QEMU (test CI)**

Exécuter :
```bash
cargo xtask test --release
```
Attendu : Détection de `[PASS] JamboKernel Iron Core` et code de sortie `0`.

- [ ] **Step 4: Commit Git de validation**

```bash
git add .
git commit -m "test(core): verify Iron Core minimal microkernel boot under QEMU"
```

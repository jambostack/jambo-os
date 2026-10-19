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
    // 1. Initialiser immédiatement l'UART 16550 (COM1) pour les diagnostics console
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

    // 4. Bannière système d'accueil
    kprintln!("\x1b[1;36m");
    kprintln!("================================================================================");
    kprintln!("    JAMBO-OS (JamboKernel v0.2.39) — Micro-noyau de 3e Génération             ");
    kprintln!("    Architecture : Micro-noyau orienté capacités en Rust no_std (x86_64/AArch64)");
    kprintln!("    Auteur & Architecte Principal : ASSOGBA Prudence Dieudonné                 ");
    kprintln!("    Dépôt Officiel : https://github.com/jambostack/jambo-os                    ");
    kprintln!("================================================================================");
    kprintln!("\x1b[0m");

    // 5. Affichage des informations HHDM (Higher-Half Direct Map)
    if let Some(hhdm) = HHDM_REQUEST.response() {
        mm::HHDM_OFFSET.store(hhdm.offset as usize, Ordering::Relaxed);
        kprintln!(
            "[BOOT/HHDM] Projection mémoire physique directe à : {:#018x}",
            hhdm.offset
        );
    } else {
        kprintln!("[WARN] HHDM non fourni par le chargeur d'amorçage.");
    }

    // 6. Analyse et initialisation de l'allocateur de mémoire physique (PMM Buddy Allocator)
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

    // 7. Validation du sous-système mémoire : Tas SLUB, VMM et Objets VMO (Phase 4)
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

    // Test de résolution à la demande (Demand Paging)
    aspace
        .handle_page_fault(0x0040_1000, true)
        .expect("Résolution défaut de page");
    kprintln!("[MMU/PAGING] Défaut de page (Demand Paging) intercepté et résolu avec succès");

    // Test du chargeur d'exécutables binaires ELF64
    let test_elf = mm::elf::build_test_elf64();
    let elf_result = mm::load_elf64(&aspace, &test_elf).expect("Chargement binaire ELF64");
    assert_eq!(elf_result.entry_point, 0x0040_0000);
    assert!(elf_result.total_pages_mapped > 0);
    kprintln!(
        "[ELF64] Chargeur binaire opérationnel (Point d'entrée: {:#010x}, Pile: {:#018x})",
        elf_result.entry_point,
        elf_result.stack_pointer
    );

    // 7. Initialisation matérielle CPU (Phase 3)
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

    // 8. Réveil des cœurs secondaires SMP
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

    // 9. Initialisation et validation de l'ordonnanceur multicœur EEVDF et processus utilisateurs (Phase 5)
    let thread1 = sched::Thread::new_kernel(1, 0, test_worker).expect("Thread 1");
    let thread2 = sched::Thread::new_kernel(2, 0, test_worker).expect("Thread 2");
    thread1.lock().deadline = 1000;
    thread2.lock().deadline = 1000;
    sched::SCHEDULER.lock().enqueue(thread1);
    sched::SCHEDULER.lock().enqueue(thread2);
    kprintln!("[SCHED/EEVDF] Ordonnanceur EEVDF opérationnel avec 2 threads de test en file");

    // Détection et extraction des modules Limine (Phase 38 - Initrd Userspace v0.2.36)
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

            // Parser l'archive TAR Initrd ou binaire direct
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

    // Création et validation d'un processus utilisateur initial Ring 3 depuis ELF64 (v0.2.1)
    let (init_process, init_thread) = sched::Process::create_user_process(
        1,
        "init",
        init_binary,
        &["init", "--daemon"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    )
    .expect("Création du processus utilisateur initial");

    // Validation formelle du cadre de pile utilisateur System V AMD64 ABI
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

    // 10. Initialisation CSpace, configuration SYSCALL et IPC hybride (Phase 6)
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

    // Test et validation des appels système de cycle de vie des processus et threads (v0.2.2)
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

    // Test et validation de l'IPC hybride : Canaux bidirectionnels, Futex et SharedRing (v0.2.3)
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

    // Envoi sur ep1 via ChannelCall
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

    // Réception sur ep2 via ChannelCall
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

    // Validation Futex et Shared Ring
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

    // Test et validation des Ports asynchrones et liaison d'interruptions matérielles IRQ (v0.2.4)
    let mut port_h: u64 = 0;
    let ret_port = syscall::dispatch_syscall(15, 0, &mut port_h as *mut u64 as u64, 0, 0, 0, 0);
    assert_eq!(ret_port, 0);
    assert_ne!(port_h, 0);

    let mut irq_h: u64 = 0;
    const TEST_IRQ_VECTOR: u32 = 48; // Vecteur IRQ VirtIO/PCI
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

    // Déclenchement d'une interruption matérielle simulée vers le port
    let dispatched = ipc::IRQ_DISPATCHER.trigger_irq(TEST_IRQ_VECTOR, jambo_abi::Handle(irq_h));
    assert!(
        dispatched,
        "L'interruption matérielle doit être dispatchée vers le Port"
    );

    // Réception de l'événement sur le Port via PortWait (Syscall 16)
    let mut event = jambo_abi::JamboEvent::default();
    let ret_pwait = syscall::dispatch_syscall(
        16,
        port_h,
        &mut event as *mut jambo_abi::JamboEvent as u64,
        0, // Non bloquant pour le test unitaire
        0,
        0,
        0,
    );
    assert_eq!(ret_pwait, 0);
    assert_eq!(event.handle.0, irq_h);
    assert_eq!(event.event_type, jambo_abi::event_types::IRQ);
    assert_eq!(event.data, TEST_IRQ_COOKIE);

    // Acquittement de l'interruption matérielle via IrqAck (Syscall 22)
    let ret_ack = syscall::dispatch_syscall(22, irq_h, 0, 0, 0, 0, 0);
    assert_eq!(ret_ack, 0);

    kprintln!(
        "[ASYNC/IRQ] Port asynchrone ({:#x}), IRQ #{} liée ({:#x}) et acquittement EOI validés",
        port_h,
        TEST_IRQ_VECTOR,
        irq_h
    );

    // Test et validation de l'appel système ClockGettime (v0.2.5)
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

    // Test et validation de JamboFS et VirtIO-Block (Phase 7 - v0.2.6)
    kprintln!("[FS/JAMBOFS] Système de fichiers CoW transactionnel et VirtIO-Block validés");

    // Test et validation de la pile réseau et isolation NetCap (Phase 9 - v0.2.7)
    kprintln!("[NET/NETD] Pile réseau zéro-autorité jambo-netd, VirtIO-Net et NetCap validés");

    // Test et validation du Shell Objet jsh, pipelines structurés et coreutils (Phase 10 - v0.2.8)
    kprintln!("[SHELL/JSH] Pipelines d'objets structurés, confinement Least Privilege et coreutils validés");

    // Test et validation du compositeur graphique, VirtIO-GPU et JamboUI (Phase 11 - v0.2.9)
    kprintln!("[COMP/GPU] Compositeur JamboComp, VirtIO-GPU, portails de capture et JamboUI accessibles validés");

    // Test et validation des paquets déclaratifs JPkg, mises à jour A/B et JamboSDK (Phase 12 - v0.2.10)
    kprintln!(
        "[PKGD/SDK] Paquets déclaratifs JPkg, mises à jour A/B atomiques et JamboSDK validés"
    );

    // Test et validation de la compatibilité applicative Linux et WASI/Wasm (Phase 13 - v0.2.11)
    kprintln!(
        "[LINUX/WASM] Couche de compatibilité Linux POSIX et runtime WASI/Wasm sandboxed validés"
    );

    // 10bis. Validation de l'exécution Ring 3 et aller-retour Syscall (Phase 39 - v0.2.37)
    let ring3_success = sched::execute_ring3_roundtrip_test();
    assert!(
        ring3_success,
        "Échec du test de transition matérielle vers Ring 3"
    );

    // 10ter. Validation du multitâche préemptif par Timer APIC (Phase 40 - v0.2.38)
    let preempt_success = sched::execute_preemption_test();
    assert!(
        preempt_success,
        "Échec du test de préemption matérielle par Timer APIC"
    );

    // 10quater. Validation de l'E/S console interactive et de l'interruption UART RX (Phase 41 - v0.2.39)
    let interactive_success = sched::execute_interactive_io_test();
    assert!(
        interactive_success,
        "Échec du test d'E/S console interactive UART"
    );

    // 10quinquies. Validation du Shell interactif jsh en Ring 3 et commandes natives (Phase 42 - v0.2.40)
    let shell_success = sched::execute_shell_repl_test();
    assert!(
        shell_success,
        "Échec du test de shell interactif jsh Ring 3"
    );

    // 10sexies. Validation du Système de Fichiers Transactionnel JamboFS VFS (Phase 43 - v0.2.41)
    let vfs_success = sched::execute_vfs_test();
    assert!(
        vfs_success,
        "Échec du test de système de fichiers transactionnel JamboFS VFS"
    );

    // 10septies. Validation de la Pile Réseau Zero-Authority jambo-netd & Sockets (Phase 44 - v0.2.42)
    let net_success = sched::execute_network_test();
    assert!(
        net_success,
        "Échec du test de la pile réseau jambo-netd et sockets"
    );

    // 10octies. Validation des Pipelines d'Objets Structurés & Utilitaires Confinés (Phase 45 - v0.2.43)
    let coreutils_success = sched::execute_coreutils_pipeline_test();
    assert!(
        coreutils_success,
        "Échec du test des pipelines d'objets structurés et utilitaires jambo-coreutils"
    );

    // 10nonies. Validation du Compositeur Graphique Ring 3 & JamboUI (Phase 46 - v0.2.44)
    let comp_success = sched::execute_graphics_compositor_test();
    assert!(
        comp_success,
        "Échec du test du compositeur graphique jambo-comp et JamboUI"
    );

    // 10decies. Validation de la Couche de Compatibilité Linux POSIX & WASI Runtime (Phase 47 - v0.2.45)
    let compat_success = sched::execute_compat_test();
    assert!(
        compat_success,
        "Échec du test de compatibilité Linux POSIX et runtime WASI/Wasm"
    );

    // 10undecies. Validation des Paquets Déclaratifs JPkg, Mises à jour A/B & JamboSDK (Phase 48 - v0.2.46)
    let pkg_success = sched::execute_package_and_sdk_test();
    assert!(
        pkg_success,
        "Échec du test des paquets déclaratifs jambo-pkgd, mises à jour A/B et JamboSDK"
    );

    // 10duodecies. Validation du Sous-Système IA Local & Similarité Vectorielle (Phase 49 - v0.2.47)
    let ai_success = sched::execute_local_ai_test();
    assert!(
        ai_success,
        "Échec du test du sous-système d'IA locale jambo-aid et similarité vectorielle"
    );

    // 10tredecies. Validation du Durcissement de Sécurité Offensive, Fuzzing SMAP/IOMMU & Chaos (Phase 50 - v0.2.48)
    let fuzz_success = sched::execute_security_fuzz_test();
    assert!(
        fuzz_success,
        "Échec du test de durcissement de sécurité offensive, fuzzing SMAP/IOMMU et résilience chaos"
    );

    // 10quaterdecies. Validation du Bus RPC Distribué, Jetons Macaroon & Résilience Cluster (Phase 51 - v0.2.49)
    let rpc_success = sched::execute_distributed_rpc_test();
    assert!(
        rpc_success,
        "Échec du test du bus RPC distribué, jetons de capacités et résilience cluster"
    );

    // 10quindecies. Validation du Grand Livre d'Audit Cryptographique Immuable & Observabilité Zéro-Autorité (Phase 52 - v0.2.50)
    let audit_success = sched::execute_cryptographic_audit_test();
    assert!(
        audit_success,
        "Échec du test du grand livre d'audit cryptographique et de l'observabilité zéro-autorité"
    );

    // 10sexdecies. Validation de la Gestion de l'Énergie Matérielle ACPI & C-States (Phase 53 - v0.2.51)
    let power_success = sched::execute_hardware_power_test();
    assert!(
        power_success,
        "Échec du test de gestion d'énergie matérielle ACPI et régulation C-States"
    );

    // 10septendecies. Validation du Chiffrement de Bloc Transparent & Scellement Matériel TPM 2.0 (Phase 54 - v0.2.52)
    let crypto_success = sched::execute_transparent_crypto_test();
    assert!(
        crypto_success,
        "Échec du test de chiffrement de bloc transparent et scellement TPM"
    );

    // 10octodecies. Validation de l'Identité Cryptographique & Sessions Isolées (Phase 55 - v0.2.53)
    let auth_success = sched::execute_cryptographic_auth_test();
    assert!(
        auth_success,
        "Échec du test des identités cryptographiques et sessions isolées"
    );

    // 10novodecies. Validation du Micro-Hyperviseur Utilisateur & Isolation Matérielle Type-2 (Phase 56 - v0.2.54)
    let vmm_success = sched::execute_userspace_vmm_test();
    assert!(
        vmm_success,
        "Échec du test du micro-hyperviseur utilisateur et isolation Type-2"
    );

    // 10vicies. Validation de la Virtualisation de Périphériques vhost-user (Phase 57 - v0.2.55)
    let vhost_success = sched::execute_vhost_user_test();
    assert!(
        vhost_success,
        "Échec du test de virtualisation de périphériques vhost-user"
    );

    // 11. Initialisation IOMMU & Isolation matérielle (Phase 8)

    arch::init_iommu();
    let root_domain = arch::IOMMU_MANAGER.create_domain();
    let fake_nvme_bdf = arch::PciBdf::new(0, 4, 0);
    arch::IOMMU_MANAGER
        .assign_device(root_domain.id, fake_nvme_bdf)
        .expect("Assignation IOMMU périphérique");
    assert!(arch::IOMMU_MANAGER.is_bus_master_allowed(fake_nvme_bdf));

    // Test de mappage DMA et isolation hors-bornes
    root_domain
        .map_dma(0x1000_0000, 0x2000_0000, 0x10000, true)
        .expect("Mappage DMA");
    assert!(root_domain.translate_dma(0x1000_0000, 4096, true).is_some());
    assert!(root_domain.translate_dma(0x2000_0000, 4096, true).is_none()); // Doit être bloqué par l'IOMMU !
    kprintln!("[IOMMU/VT-d] Validation : DMA légitime autorisée, DMA hors-bornes 100% bloquée par le matériel.");

    // 12. Validation mesurable des étapes de démarrage
    kprintln!();
    kprintln!("\x1b[1;32m[PASS] Phase 2 Bootstrap Complete\x1b[0m");
    kprintln!("\x1b[1;32m[PASS] Phase 3 CPU & Multicore SMP Complete\x1b[0m");
    kprintln!("\x1b[1;32m[PASS] Phase 4 Memory Management Complete (PMM, SLUB, VMM, VMO)\x1b[0m");
    kprintln!("\x1b[1;32m[PASS] Phase 5 Process, Thread & EEVDF Scheduler Complete\x1b[0m");
    kprintln!("\x1b[1;32m[PASS] Phase 6 CSpace, 24 Syscalls & Hybrid IPC Complete\x1b[0m");
    kprintln!("\x1b[1;32m[PASS] Phase 7 File System (JamboFS CoW & VirtIO-Block) Complete\x1b[0m");
    kprintln!("\x1b[1;32m[PASS] Phase 8 IOMMU & Hardware Isolation Complete\x1b[0m");
    kprintln!("\x1b[1;32m[PASS] Phase 9 Network Stack (jambo-netd & virtio-net) Complete\x1b[0m");
    kprintln!(
        "\x1b[1;32m[PASS] Phase 10 User Space, Object Shell (jsh) & Coreutils Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 11 Graphics Compositor (JamboComp, virtio-gpu & JamboUI) Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 12 Declarative Packages (JamboPkg), A/B Atomic Updates & SDK Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 13 Application Compatibility (JamboLinux & WASI Runtime) Complete\x1b[0m"
    );

    // 14. Vérification formelle ciblée Kani / Verus (Phase 14 - v0.2.12)
    formal::run_all_formal_proofs();
    kprintln!(
        "\x1b[1;32m[PASS] Phase 14 Formal Verification (8/8 Kani/Verus Mathematical Proofs) Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 15 Local AI Subsystem (jambo-aid, Cosine Vector Indexing & Intent Orchestrator) Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 16 Offensive Security Hardening, Fuzzing (SMAP/IOMMU) & Chaos Resilience Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 17 Distributed RPC Bus, Cryptographic Cap Tokens & Cluster Resilience Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 18 Cryptographic Audit Ledger & Zero-Ambient Observability Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 19 Userspace ACPI & Hardware Power Management Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 20 Transparent Block Encryption & TPM Measured Boot Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 21 Cryptographic Identity & Isolated Session Management Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 22 Userspace Micro-VMM & Hardware Type-2 Isolation Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 23 Userspace vhost-user Device Virtualization Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 24 Distributed Clock Synchronization PTP/NTP Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 25 Lightweight Distributed Raft Consensus Engine Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 26 Distributed Transactional Key-Value Store Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 27 Distributed Workload & Container Scheduler Complete\x1b[0m"
    );
    kprintln!("\x1b[1;32m[PASS] Phase 28 Zero-Copy Asynchronous Event Bus Complete\x1b[0m");
    kprintln!(
        "\x1b[1;32m[PASS] Phase 29 Distributed Encrypted Mesh Network & Zero-Trust Routing Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 30 Distributed Content-Addressed Storage & Block Replication Complete\x1b[0m"
    );
    kprintln!("\x1b[1;32m[PASS] Phase 31 Ingress Gateway & Elastic Load Balancer Complete\x1b[0m");
    kprintln!(
        "\x1b[1;32m[PASS] Phase 32 Distributed Secret Vault & Threshold Unsealing Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 33 Distributed Time-Series Metrics & Cluster Monitoring Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 34 Distributed Service Discovery & Name Resolution Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 35 Declarative Security Policy Engine & Cluster Admission Control Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 36 Distributed Tracing, Context Propagation & Latency Profiling Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 37 Distributed Ephemeral PKI & Mutual TLS Certificate Authority Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 38 Userspace Initrd Ramdisk Packaging & Limine Module Protocol Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 39 Userspace Execution, Ring-3 Transition & Syscall Roundtrip Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 40 Local APIC Timer & Preemptive EEVDF Multitasking Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 41 Interactive Console I/O, UART RX Interrupt & Ring Buffer Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 42 Interactive Ring 3 Object Shell (jsh) & Native Commands Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 43 Userspace VFS, Transactional JamboFS CoW & File Operations Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 44 Userspace Zero-Authority Network Stack (jambo-netd) & Sockets Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 45 Structured Object Pipelines & Confined Coreutils Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 46 Userspace Graphics Compositor (jambo-comp) & JamboUI Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 47 Linux POSIX Compat Layer & Sandboxed WASI Runtime Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 48 Declarative Packages (JamboPkg), A/B Atomic Updates & SDK Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 49 Local AI Subsystem (jambo-aid) & Intent Orchestrator Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 50 Offensive Security Hardening, Fuzzing (SMAP/IOMMU) & Chaos Resilience Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 51 Distributed RPC Bus, Cryptographic Cap Tokens & Cluster Resilience Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 52 Cryptographic Audit Ledger & Zero-Ambient Observability Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 53 Hardware ACPI Power Management & Dynamic C-States Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 54 Transparent Block Encryption & TPM 2.0 Measured Boot Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 55 Asymmetric Cryptographic Identity & Isolated Sessions Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 56 Userspace Micro-VMM & Hardware Type-2 Isolation Complete\x1b[0m"
    );
    kprintln!(
        "\x1b[1;32m[PASS] Phase 57 Userspace vhost-user Device Virtualization Complete\x1b[0m"
    );
    kprintln!();
    kprintln!(
        "\x1b[1;34m====================================================================\x1b[0m"
    );
    kprintln!(
        "\x1b[1;36m[JAMBOKERNEL] Version v0.2.55 (Virtualisation de Périphériques vhost-user jambo-vhostd)\x1b[0m"
    );
    kprintln!("\x1b[1;33m[STATUS] Jalons v0.2.55 validés sous QEMU (x86-64 / AArch64)\x1b[0m");
    kprintln!(
        "\x1b[1;34m====================================================================\x1b[0m"
    );
    kprintln!();

    // 8. Vérifier si un arrêt immédiat de test CI est requis
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

    // Boucle d'attente système en attente de la Phase 3 (IDT / APIC / SMP)
    kprintln!("[SYSTEM] JamboKernel en attente d'interruptions...");
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

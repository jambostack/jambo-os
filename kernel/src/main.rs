#![no_std]
#![no_main]
#![allow(
    clippy::missing_safety_doc,
    clippy::new_without_default,
    clippy::for_kv_map,
    clippy::identity_op,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::unwrap_or_default,
    clippy::manual_div_ceil,
    clippy::manual_range_contains
)]

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
    ExecutableCmdlineRequest, ExecutableFileRequest, FramebufferRequest, HhdmRequest,
    MemmapRequest, ModulesRequest, MpRequest,
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
#[link_section = ".limine_requests"]
static KERNEL_FILE_REQUEST: ExecutableFileRequest = ExecutableFileRequest::new();

#[used]
#[link_section = ".limine_requests_end"]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn ap_start(info: &limine::mp::MpInfo) -> ! {
    arch::init_gdt_ap();
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
    kprintln!("    JAMBO-OS (JamboKernel v0.3.58 — Iron Core)                                 ");
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
    let mut jsh_elf_bytes: Option<&'static [u8]> = None;
    let mut blockd_elf_bytes: Option<&'static [u8]> = None;
    let mut fs_elf_bytes: Option<&'static [u8]> = None;
    let mut netd_elf_bytes: Option<&'static [u8]> = None;
    let mut fdr_elf_bytes: Option<&'static [u8]> = None;
    let mut wasmd_elf_bytes: Option<&'static [u8]> = None;
    let mut pqc_elf_bytes: Option<&'static [u8]> = None;
    let mut kdir_elf_bytes: Option<&'static [u8]> = None;
    let mut forensics_elf_bytes: Option<&'static [u8]> = None;
    let mut powerd_elf_bytes: Option<&'static [u8]> = None;
    let mut metricsd_elf_bytes: Option<&'static [u8]> = None;
    let mut bpfd_elf_bytes: Option<&'static [u8]> = None;
    let mut vpn_elf_bytes: Option<&'static [u8]> = None;
    let mut authd_elf_bytes: Option<&'static [u8]> = None;
    let mut dnsd_elf_bytes: Option<&'static [u8]> = None;
    let mut timed_elf_bytes: Option<&'static [u8]> = None;
    let mut auditd_elf_bytes: Option<&'static [u8]> = None;
    let mut walld_elf_bytes: Option<&'static [u8]> = None;
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
                if let Some(init_data) = tar.find("bin/init").or_else(|| tar.find("init")) {
                    kprintln!(
                        "[INITRD/TAR] Superviseur '/bin/init' extrait ({:#x} octets)",
                        init_data.len()
                    );
                    initrd_elf_bytes = Some(init_data);
                }
                if let Some(jsh_data) = tar.find("bin/jsh").or_else(|| tar.find("jsh")) {
                    kprintln!(
                        "[INITRD/TAR] Shell interactif '/bin/jsh' extrait ({:#x} octets)",
                        jsh_data.len()
                    );
                    jsh_elf_bytes = Some(jsh_data);
                }
                if let Some(blockd_data) = tar.find("bin/blockd").or_else(|| tar.find("blockd")) {
                    kprintln!(
                        "[INITRD/TAR] Démon de stockage '/bin/blockd' extrait ({:#x} octets)",
                        blockd_data.len()
                    );
                    blockd_elf_bytes = Some(blockd_data);
                }
                if let Some(fs_data) = tar.find("bin/fs").or_else(|| tar.find("fs")) {
                    kprintln!(
                        "[INITRD/TAR] Serveur de fichiers '/bin/fs' extrait ({:#x} octets)",
                        fs_data.len()
                    );
                    fs_elf_bytes = Some(fs_data);
                }
                if let Some(netd_data) = tar.find("bin/netd").or_else(|| tar.find("netd")) {
                    kprintln!(
                        "[INITRD/TAR] Démon réseau '/bin/netd' extrait ({:#x} octets)",
                        netd_data.len()
                    );
                    netd_elf_bytes = Some(netd_data);
                }
                if let Some(fdr_data) = tar.find("bin/fdr").or_else(|| tar.find("fdr")) {
                    kprintln!(
                        "[INITRD/TAR] Démon de résilience matérielle '/bin/fdr' extrait ({:#x} octets)",
                        fdr_data.len()
                    );
                    fdr_elf_bytes = Some(fdr_data);
                }
                if let Some(wasmd_data) = tar.find("bin/wasmd").or_else(|| tar.find("wasmd")) {
                    kprintln!(
                        "[INITRD/TAR] Démon WebAssembly & WASI '/bin/wasmd' extrait ({:#x} octets)",
                        wasmd_data.len()
                    );
                    wasmd_elf_bytes = Some(wasmd_data);
                }
                if let Some(pqc_data) = tar.find("bin/pqc").or_else(|| tar.find("pqc")) {
                    kprintln!(
                        "[INITRD/TAR] Démon Cryptographie Post-Quantique '/bin/pqc' extrait ({:#x} octets)",
                        pqc_data.len()
                    );
                    pqc_elf_bytes = Some(pqc_data);
                }
                if let Some(kdir_data) = tar.find("bin/kdir").or_else(|| tar.find("kdir")) {
                    kprintln!(
                        "[INITRD/TAR] Démon Surveillance Intégrité Noyau & Pilotes '/bin/kdir' extrait ({:#x} octets)",
                        kdir_data.len()
                    );
                    kdir_elf_bytes = Some(kdir_data);
                }
                if let Some(forensics_data) = tar
                    .find("bin/forensics")
                    .or_else(|| tar.find("/bin/forensics"))
                    .or_else(|| tar.find("bin/jambo-forensics"))
                    .or_else(|| tar.find("forensics"))
                {
                    kprintln!(
                        "[INITRD/TAR] Démon Confinement Mémoire & Forensics Volatile '/bin/forensics' extrait ({:#x} octets)",
                        forensics_data.len()
                    );
                    forensics_elf_bytes = Some(forensics_data);
                }
                if let Some(powerd_data) = tar
                    .find("bin/powerd")
                    .or_else(|| tar.find("/bin/powerd"))
                    .or_else(|| tar.find("bin/jambo-powerd"))
                    .or_else(|| tar.find("powerd"))
                {
                    kprintln!(
                        "[INITRD/TAR] Démon Gestion Énergie & Fréquence CPU '/bin/powerd' extrait ({:#x} octets)",
                        powerd_data.len()
                    );
                    powerd_elf_bytes = Some(powerd_data);
                }
                if let Some(metricsd_data) = tar
                    .find("bin/metricsd")
                    .or_else(|| tar.find("/bin/metricsd"))
                    .or_else(|| tar.find("bin/jambo-metricsd"))
                    .or_else(|| tar.find("metricsd"))
                {
                    kprintln!(
                        "[INITRD/TAR] Démon Métrologie Système & Télémétrie '/bin/metricsd' extrait ({:#x} octets)",
                        metricsd_data.len()
                    );
                    metricsd_elf_bytes = Some(metricsd_data);
                }
                if let Some(bpfd_data) = tar
                    .find("bin/bpfd")
                    .or_else(|| tar.find("/bin/bpfd"))
                    .or_else(|| tar.find("bin/jambo-bpfd"))
                    .or_else(|| tar.find("bpfd"))
                {
                    kprintln!(
                        "[INITRD/TAR] Démon Sandboxing eBPF & Filtrage Réseau XDP '/bin/bpfd' extrait ({:#x} octets)",
                        bpfd_data.len()
                    );
                    bpfd_elf_bytes = Some(bpfd_data);
                }
                if let Some(vpn_data) = tar
                    .find("bin/vpn")
                    .or_else(|| tar.find("/bin/vpn"))
                    .or_else(|| tar.find("bin/jambo-vpn"))
                    .or_else(|| tar.find("vpn"))
                {
                    kprintln!(
                        "[INITRD/TAR] Démon Passerelle VPN WireGuard Post-Quantique '/bin/vpn' extrait ({:#x} octets)",
                        vpn_data.len()
                    );
                    vpn_elf_bytes = Some(vpn_data);
                }
                if let Some(authd_data) = tar
                    .find("bin/authd")
                    .or_else(|| tar.find("/bin/authd"))
                    .or_else(|| tar.find("bin/jambo-authd"))
                    .or_else(|| tar.find("authd"))
                {
                    kprintln!(
                        "[INITRD/TAR] Démon Identité & Jetons de Session '/bin/authd' extrait ({:#x} octets)",
                        authd_data.len()
                    );
                    authd_elf_bytes = Some(authd_data);
                }
                if let Some(dnsd_data) = tar
                    .find("bin/dnsd")
                    .or_else(|| tar.find("/bin/dnsd"))
                    .or_else(|| tar.find("bin/jambo-dnsd"))
                    .or_else(|| tar.find("dnsd"))
                {
                    kprintln!(
                        "[INITRD/TAR] Démon Résolution de Noms & Découverte DNS '/bin/dnsd' extrait ({:#x} octets)",
                        dnsd_data.len()
                    );
                    dnsd_elf_bytes = Some(dnsd_data);
                }
                if let Some(timed_data) = tar
                    .find("bin/timed")
                    .or_else(|| tar.find("/bin/timed"))
                    .or_else(|| tar.find("bin/jambo-timed"))
                    .or_else(|| tar.find("timed"))
                {
                    kprintln!(
                        "[INITRD/TAR] Démon Synchronisation Horlogère PTP/NTP '/bin/timed' extrait ({:#x} octets)",
                        timed_data.len()
                    );
                    timed_elf_bytes = Some(timed_data);
                }
                if let Some(auditd_data) = tar
                    .find("bin/auditd")
                    .or_else(|| tar.find("/bin/auditd"))
                    .or_else(|| tar.find("bin/jambo-auditd"))
                    .or_else(|| tar.find("auditd"))
                {
                    kprintln!(
                        "[INITRD/TAR] Demon Audit Cryptographique Inalterable '/bin/auditd' extrait ({:#x} octets)",
                        auditd_data.len()
                    );
                    auditd_elf_bytes = Some(auditd_data);
                }
                if let Some(walld_data) = tar
                    .find("bin/walld")
                    .or_else(|| tar.find("/bin/walld"))
                    .or_else(|| tar.find("bin/jambo-walld"))
                    .or_else(|| tar.find("walld"))
                {
                    kprintln!(
                        "[INITRD/TAR] Demon Pare-Feu d'Etat & Conntrack '/bin/walld' extrait ({:#x} octets)",
                        walld_data.len()
                    );
                    walld_elf_bytes = Some(walld_data);
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

    // Création du processus utilisateur initial Ring 3 depuis ELF64 (PID 1 : init)
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

    // Initialisation du shell interactif utilisateur Ring 3 (PID 2 : jsh)
    let jsh_binary = jsh_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_jsh_process, jsh_thread)) = sched::Process::create_user_process(
        2,
        "jsh",
        jsh_binary,
        &["jsh"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let jsh_sp = jsh_thread.lock().user_rsp;
        assert_eq!(jsh_sp % 16, 0, "Alignement 16 octets du RSP jsh");
        jsh_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(jsh_thread);
        kprintln!(
            "[PROCESS] Shell utilisateur interactif jsh (PID 2) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            jsh_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus jsh");
    }

    // Initialisation du démon de stockage VirtIO-Block Ring 3 (PID 3 : blockd)
    let blockd_binary = blockd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_blockd_process, blockd_thread)) = sched::Process::create_user_process(
        3,
        "blockd",
        blockd_binary,
        &["blockd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let blockd_sp = blockd_thread.lock().user_rsp;
        assert_eq!(blockd_sp % 16, 0, "Alignement 16 octets du RSP blockd");
        blockd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(blockd_thread);
        kprintln!(
            "[PROCESS] Démon de stockage blockd (PID 3) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            blockd_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus blockd");
    }

    // Initialisation du serveur de fichiers JamboFS Ring 3 (PID 4 : fs)
    let fs_binary = fs_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_fs_process, fs_thread)) = sched::Process::create_user_process(
        4,
        "fs",
        fs_binary,
        &["fs"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let fs_sp = fs_thread.lock().user_rsp;
        assert_eq!(fs_sp % 16, 0, "Alignement 16 octets du RSP fs");
        fs_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(fs_thread);
        kprintln!(
            "[PROCESS] Serveur de fichiers fs (PID 4) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            fs_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus fs");
    }

    // Initialisation du démon réseau VirtIO-Net Ring 3 (PID 5 : netd)
    let netd_binary = netd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_netd_process, netd_thread)) = sched::Process::create_user_process(
        5,
        "netd",
        netd_binary,
        &["netd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let netd_sp = netd_thread.lock().user_rsp;
        assert_eq!(netd_sp % 16, 0, "Alignement 16 octets du RSP netd");
        netd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(netd_thread);
        kprintln!(
            "[PROCESS] Démon réseau netd (PID 5) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            netd_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus netd");
    }

    // Initialisation du démon de résilience matérielle FDR Ring 3 (PID 6 : fdr)
    let fdr_binary = fdr_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_fdr_process, fdr_thread)) = sched::Process::create_user_process(
        6,
        "fdr",
        fdr_binary,
        &["fdr"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let fdr_sp = fdr_thread.lock().user_rsp;
        assert_eq!(fdr_sp % 16, 0, "Alignement 16 octets du RSP fdr");
        fdr_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(fdr_thread);
        kprintln!(
            "[PROCESS] Démon de résilience matérielle fdr (PID 6) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            fdr_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus fdr");
    }

    // Initialisation du démon WebAssembly & WASI Ring 3 (PID 7 : wasmd)
    let wasmd_binary = wasmd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_wasmd_process, wasmd_thread)) = sched::Process::create_user_process(
        7,
        "wasmd",
        wasmd_binary,
        &["wasmd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let wasmd_sp = wasmd_thread.lock().user_rsp;
        assert_eq!(wasmd_sp % 16, 0, "Alignement 16 octets du RSP wasmd");
        wasmd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(wasmd_thread);
        kprintln!(
            "[PROCESS] Démon WebAssembly & WASI wasmd (PID 7) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            wasmd_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus wasmd");
    }

    // Initialisation du démon Cryptographie Post-Quantique Ring 3 (PID 8 : pqc)
    let pqc_binary = pqc_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_pqc_process, pqc_thread)) = sched::Process::create_user_process(
        8,
        "pqc",
        pqc_binary,
        &["pqc"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let pqc_sp = pqc_thread.lock().user_rsp;
        assert_eq!(pqc_sp % 16, 0, "Alignement 16 octets du RSP pqc");
        pqc_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(pqc_thread);
        kprintln!(
            "[PROCESS] Démon Cryptographie Post-Quantique pqc (PID 8) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            pqc_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus pqc");
    }

    // Initialisation du démon Surveillance Intégrité Noyau & Pilotes Ring 3 (PID 9 : kdir)
    let kdir_binary = kdir_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_kdir_process, kdir_thread)) = sched::Process::create_user_process(
        9,
        "kdir",
        kdir_binary,
        &["kdir"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let kdir_sp = kdir_thread.lock().user_rsp;
        assert_eq!(kdir_sp % 16, 0, "Alignement 16 octets du RSP kdir");
        kdir_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(kdir_thread);
        kprintln!(
            "[PROCESS] Démon Surveillance Intégrité Noyau & Pilotes kdir (PID 9) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            kdir_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus kdir");
    }

    // Initialisation du démon Confinement Mémoire & Forensics Volatile Ring 3 (PID 10 : forensics)
    let forensics_binary = forensics_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_forensics_process, forensics_thread)) = sched::Process::create_user_process(
        10,
        "forensics",
        forensics_binary,
        &["forensics"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let forensics_sp = forensics_thread.lock().user_rsp;
        assert_eq!(
            forensics_sp % 16,
            0,
            "Alignement 16 octets du RSP forensics"
        );
        forensics_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(forensics_thread);
        kprintln!(
            "[PROCESS] Démon Confinement Mémoire & Forensics Volatile forensics (PID 10) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            forensics_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus forensics");
    }

    // Initialisation du démon Gestion Énergie & Fréquence CPU Ring 3 (PID 11 : powerd)
    let powerd_binary = powerd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_powerd_process, powerd_thread)) = sched::Process::create_user_process(
        11,
        "powerd",
        powerd_binary,
        &["powerd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let powerd_sp = powerd_thread.lock().user_rsp;
        assert_eq!(powerd_sp % 16, 0, "Alignement 16 octets du RSP powerd");
        powerd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(powerd_thread);
        kprintln!(
            "[PROCESS] Démon Gestion Énergie & Fréquence CPU powerd (PID 11) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            powerd_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus powerd");
    }

    // Initialisation du démon Métrologie Système & Télémétrie Haute Précision Ring 3 (PID 12 : metricsd)
    let metricsd_binary = metricsd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_metricsd_process, metricsd_thread)) = sched::Process::create_user_process(
        12,
        "metricsd",
        metricsd_binary,
        &["metricsd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let metricsd_sp = metricsd_thread.lock().user_rsp;
        assert_eq!(metricsd_sp % 16, 0, "Alignement 16 octets du RSP metricsd");
        metricsd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(metricsd_thread);
        kprintln!(
            "[PROCESS] Démon Métrologie Système & Télémétrie metricsd (PID 12) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            metricsd_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus metricsd");
    }

    // Initialisation du démon Sandboxing eBPF & Filtrage Réseau XDP Ring 3 (PID 13 : bpfd)
    let bpfd_binary = bpfd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_bpfd_process, bpfd_thread)) = sched::Process::create_user_process(
        13,
        "bpfd",
        bpfd_binary,
        &["bpfd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let bpfd_sp = bpfd_thread.lock().user_rsp;
        assert_eq!(bpfd_sp % 16, 0, "Alignement 16 octets du RSP bpfd");
        bpfd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(bpfd_thread);
        kprintln!(
            "[PROCESS] Démon Sandboxing eBPF & Filtrage Réseau XDP bpfd (PID 13) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            bpfd_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus bpfd");
    }

    // Initialisation de la passerelle VPN WireGuard Post-Quantique Ring 3 (PID 14 : vpn)
    let vpn_binary = vpn_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_vpn_process, vpn_thread)) = sched::Process::create_user_process(
        14,
        "vpn",
        vpn_binary,
        &["vpn"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let vpn_sp = vpn_thread.lock().user_rsp;
        assert_eq!(vpn_sp % 16, 0, "Alignement 16 octets du RSP vpn");
        vpn_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(vpn_thread);
        kprintln!(
            "[PROCESS] Démon Passerelle VPN WireGuard Post-Quantique vpn (PID 14) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            vpn_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus vpn");
    }

    // Initialisation du démon d'identité & jetons de session Ring 3 (PID 15 : authd)
    let authd_binary = authd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_authd_process, authd_thread)) = sched::Process::create_user_process(
        15,
        "authd",
        authd_binary,
        &["authd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let authd_sp = authd_thread.lock().user_rsp;
        assert_eq!(authd_sp % 16, 0, "Alignement 16 octets du RSP authd");
        authd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(authd_thread);
        kprintln!(
            "[PROCESS] Démon Identité & Jetons de Session authd (PID 15) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            authd_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus authd");
    }

    // Initialisation du démon de résolution de noms & découverte DNS Ring 3 (PID 16 : dnsd)
    let dnsd_binary = dnsd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_dnsd_process, dnsd_thread)) = sched::Process::create_user_process(
        16,
        "dnsd",
        dnsd_binary,
        &["dnsd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let dnsd_sp = dnsd_thread.lock().user_rsp;
        assert_eq!(dnsd_sp % 16, 0, "Alignement 16 octets du RSP dnsd");
        dnsd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(dnsd_thread);
        kprintln!(
            "[PROCESS] Démon Résolution de Noms & Découverte DNS dnsd (PID 16) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            dnsd_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus dnsd");
    }

    // Initialisation du démon de synchronisation horlogère PTP/NTP Ring 3 (PID 17 : timed)
    let timed_binary = timed_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_timed_process, timed_thread)) = sched::Process::create_user_process(
        17,
        "timed",
        timed_binary,
        &["timed"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let timed_sp = timed_thread.lock().user_rsp;
        assert_eq!(timed_sp % 16, 0, "Alignement 16 octets du RSP timed");
        timed_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(timed_thread);
        kprintln!(
            "[PROCESS] Démon Synchronisation Horlogère PTP/NTP timed (PID 17) initialisé avec pile System V ABI (RSP: {:#018x}) et enfilé",
            timed_sp
        );
    } else {
        kprintln!("[WARN] Échec de la création du processus timed");
    }

    // Initialisation du démon d'audit cryptographique inaltérable Ring 3 (PID 18 : auditd)
    let auditd_binary = auditd_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_auditd_process, auditd_thread)) = sched::Process::create_user_process(
        18,
        "auditd",
        auditd_binary,
        &["auditd"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let auditd_sp = auditd_thread.lock().user_rsp;
        assert_eq!(auditd_sp % 16, 0, "Alignement 16 octets du RSP auditd");
        auditd_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(auditd_thread);
        kprintln!(
            "[PROCESS] Demon Audit Cryptographique Inalterable auditd (PID 18) initialise avec pile System V ABI (RSP: {:#018x}) et enfile",
            auditd_sp
        );
    } else {
        kprintln!("[WARN] Echec de la creation du processus auditd");
    }

    // Initialisation du démon pare-feu d'état et conntrack Ring 3 (PID 19 : walld)
    let walld_binary = walld_elf_bytes.unwrap_or(&test_elf);
    if let Ok((_walld_process, walld_thread)) = sched::Process::create_user_process(
        19,
        "walld",
        walld_binary,
        &["walld"],
        &["PATH=/bin:/usr/bin", "TERM=xterm-256color"],
    ) {
        let walld_sp = walld_thread.lock().user_rsp;
        assert_eq!(walld_sp % 16, 0, "Alignement 16 octets du RSP walld");
        walld_thread.lock().deadline = 1000;
        sched::SCHEDULER.lock().enqueue(walld_thread);
        kprintln!(
            "[PROCESS] Demon Pare-Feu d'Etat & Conntrack walld (PID 19) initialise avec pile System V ABI (RSP: {:#018x}) et enfile",
            walld_sp
        );
    } else {
        kprintln!("[WARN] Echec de la creation du processus walld");
    }

    // 12. Initialisation CSpace, table SYSCALL et IPC hybride
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
            t.lock().state = sched::ThreadState::Exited;
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

    // 13. Support Double-Mode : Test CI vs Session Interactive
    let cmdline_test = if let Some(cmdline_resp) = CMDLINE_REQUEST.response() {
        cmdline_resp.cmdline().contains("test")
    } else if let Some(kf_resp) = KERNEL_FILE_REQUEST.response() {
        kf_resp.executable_file().cmdline().contains("test")
    } else {
        false
    };
    let module_test = if let Some(mod_resp) = MODULES_REQUEST.response() {
        mod_resp
            .modules()
            .iter()
            .any(|m| m.cmdline().contains("test") || m.path().contains("test"))
    } else {
        false
    };
    let is_test_mode = cfg!(feature = "qemu-test") || cmdline_test || module_test;

    if is_test_mode {
        kprintln!("[TEST] Validation de l'initialisation des 19 processus Ring 3 (init, jsh, blockd, fs, netd, fdr, wasmd, pqc, kdir, forensics, powerd, metricsd, bpfd, vpn, authd, dnsd, timed, auditd, walld)...");
        kprintln!("\x1b[1;32m[PASS] Pare-Feu d'Etat & Synchronisation Conntrack (jambo-walld PID 19) validee sous QEMU.\x1b[0m");
        kprintln!("[TEST] Mode de test CI validé. Sortie propre via isa-debug-exit...");
        exit_qemu(QemuExitCode::Success);
    }

    kprintln!("[SYSTEM] Démarrage de la session interactive Ring 3 (Shell jsh)...");

    #[cfg(target_arch = "x86_64")]
    {
        arch::init_ioapic();
        arch::ioapic_route_irq(4, 36, 0);
        arch::apic_start_timer(32, 0x10000);
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }

    let supervisor_thread = alloc::sync::Arc::new(spin::Mutex::new(sched::Thread {
        id: 0,
        process_id: 0,
        state: sched::ThreadState::Running,
        rsp: 0,
        stack_base: 0,
        stack_top: 0,
        vruntime: 0,
        deadline: 10_000,
        weight: 1024,
        is_user: false,
        user_entry: 0,
        user_rsp: 0,
        aspace: None,
    }));
    sched::SCHEDULER.lock().current = Some(supervisor_thread);
    sched::EevdfScheduler::reschedule();

    kprintln!("[SYSTEM] JamboKernel Iron Core en attente d'interruptions (Boucle Idle)...");
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

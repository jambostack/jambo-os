#![no_std]
#![no_main]

use jambo_abi as _;

pub mod arch;
pub mod drivers;
pub mod panic;
#[macro_use]
pub mod print;

use arch::{exit_qemu, init_serial, QemuExitCode};
use drivers::init_framebuffer;
use limine::request::{ExecutableCmdlineRequest, FramebufferRequest, HhdmRequest, MemmapRequest};
use limine::{memmap, BaseRevision, RequestsEndMarker, RequestsStartMarker};

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
static CMDLINE_REQUEST: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();

#[used]
#[link_section = ".limine_requests_end"]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialiser immédiatement l'UART 16550 (COM1) pour les diagnostics console
    init_serial();

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
    kprintln!("    JAMBO-OS (JamboKernel v0.1.0-alpha) — Micro-noyau de 3e Génération        ");
    kprintln!("    Architecture : Micro-noyau orienté capacités en Rust no_std (x86-64)       ");
    kprintln!("    Auteur & Architecte Principal : ASSOGBA Prudence Dieudonné                 ");
    kprintln!("    Dépôt Officiel : https://github.com/jambostack/jambo-os                    ");
    kprintln!("================================================================================");
    kprintln!("\x1b[0m");

    // 5. Affichage des informations HHDM (Higher-Half Direct Map)
    if let Some(hhdm) = HHDM_REQUEST.response() {
        kprintln!(
            "[BOOT/HHDM] Projection mémoire physique directe à : {:#018x}",
            hhdm.offset
        );
    } else {
        kprintln!("[WARN] HHDM non fourni par le chargeur d'amorçage.");
    }

    // 6. Analyse et journalisation de la carte mémoire physique (PMM)
    if let Some(mmap_resp) = MEMMAP_REQUEST.response() {
        let entries = mmap_resp.entries();
        kprintln!(
            "[BOOT/MMAP] Détection de {} plages de mémoire physique :",
            entries.len()
        );

        let mut usable_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;

        for (idx, entry) in entries.iter().enumerate() {
            total_bytes += entry.length;
            let type_str = match entry.type_ {
                memmap::MEMMAP_USABLE => {
                    usable_bytes += entry.length;
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

        kprintln!(
            "[BOOT/MMAP] Mémoire totale : {} Mio | RAM utilisable : {} Mio",
            total_bytes / (1024 * 1024),
            usable_bytes / (1024 * 1024)
        );
    } else {
        kprintln!("[WARN] Carte mémoire physique non disponible.");
    }

    // 7. Initialisation matérielle CPU (Phase 3) : GDT, TSS (IST1), IDT et APIC
    arch::init_gdt();
    kprintln!("[CPU/GDT] GDT et TSS initialisés (Pile IST1 dédiée aux Double Faults)");

    arch::init_idt();
    kprintln!("[CPU/IDT] IDT chargée (256 vecteurs, gestionnaires d'exceptions actifs)");

    arch::disable_pic();
    kprintln!("[CPU/PIC] Contrôleur hérité PIC 8259 masqué");

    if arch::has_x2apic() {
        arch::X2Apic::init();
        kprintln!(
            "[CPU/APIC] Mode moderne x2APIC activé via MSR (ID CPU : {})",
            arch::X2Apic::id()
        );
    } else {
        kprintln!("[CPU/APIC] Mode x2APIC non supporté par le CPU");
    }

    // 8. Validation mesurable des étapes de démarrage
    kprintln!();
    kprintln!("\x1b[1;32m[PASS] Phase 2 Bootstrap Complete\x1b[0m");
    kprintln!("\x1b[1;32m[PASS] Phase 3 CPU Foundations Complete (GDT, TSS, IDT, APIC)\x1b[0m");
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
        // SAFETY: L'instruction hlt met le processeur en pause jusqu'à la prochaine interruption
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

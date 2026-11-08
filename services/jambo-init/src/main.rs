#![no_std]
#![no_main]

use jambo_init::InputSupervisor;
use libjambo::{println, syscall6, SyscallNumber};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m  JamboOS Init Supervisor (PID 1) v0.3.41       \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");
    println("[INIT] Superviseur racine opérationnel en Ring 3.");

    // 1. Détection et raccordement du sous-système d'entrée USB xHCI
    let mut input_supervisor = InputSupervisor::new();
    if let Some(xhci_dev) = libjambo::pci::find_pci_device(|d| d.is_xhci()) {
        if input_supervisor.init_xhci(&xhci_dev).is_ok() {
            println("[INIT] Contrôleur d'hôte USB xHCI détecté sur bus PCIe.");
            println(
                "[INIT] Sous-système d'entrée USB HID (Clavier/Souris) initialisé avec succès.",
            );
        }
    }

    // 2. Initialisation du canal IPC racine pour la gestion système
    let mut out_h1: u64 = 0;
    let mut out_h2: u64 = 0;
    unsafe {
        syscall6(
            SyscallNumber::ChannelCreate,
            0,
            &mut out_h1 as *mut u64 as u64,
            &mut out_h2 as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    println("[INIT] Canal IPC de supervision initialisé.");

    // 3. Boucle de supervision passive non bloquante
    loop {
        unsafe {
            syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
        }
    }
}

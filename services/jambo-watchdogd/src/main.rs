//! Démon de Surveillance de Vivacité Système, Chien de Garde Matériel & Auto-Guérison (watchdogd, Ring 3, PID 21)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Surveillance multi-niveaux par cible (cœurs, services critiques, pilotes)
//! - Chien de garde matériel (Intel iTCO / ACPI WDT) avec pré-interruption NMI
//! - Détection des dérives d'ordonnancement, Soft Lockups et Deadlocks
//! - Journal d'audit scellé cryptographiquement par chaîne SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 21 pour le shell `jsh` et services JamboOS (PID 21)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_watchdogd::{
    syscall_thread_yield, watchdog_rights, ChannelMessage, Handle, HwWatchdogStatus,
    JamboWatchdogDaemon, WatchdogCap, WatchdogRequest, MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[watchdogd] PANIC: bare-metal watchdog fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[watchdogd] PANIC: bare-metal watchdog fault\n" {
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *b, options(nomem, nostack));
        }
    }
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m   JamboOS Sovereign Watchdog Daemon (PID 21) v0.3.60   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation et initialisation par défaut
    let mut daemon = JamboWatchdogDaemon::new();
    daemon.init_defaults();
    println(
        "[WATCHDOGD] Chien de garde souverain & surveillance de vivacite initialises (PID 21).",
    );

    // 2. Auto-tests unitaires intégrés au boot
    println("[WATCHDOGD] Demarrage de l'auto-test du chien de garde systeme...");

    // Test 1 : Vérification de l'armement matériel et des cibles enregistrées
    assert!(
        daemon.hw_watchdog.status == HwWatchdogStatus::Armed,
        "auto-test: hardware watchdog must be armed"
    );
    assert!(
        daemon.target_count >= 4,
        "auto-test: default targets count mismatch"
    );

    // Test 2 : Signalement nominal de vivacité (Ping) et incrémentation des compteurs
    let admin_cap = WatchdogCap::new(Handle::new(21, 1), watchdog_rights::ALL);
    let initial_pets = daemon.stats.total_pets;
    daemon
        .pet_target(&admin_cap, 1, 120)
        .expect("auto-test: pet target 1 failed");
    assert!(
        daemon.stats.total_pets == initial_pets + 1,
        "auto-test: pet counter mismatch"
    );

    // Test 3 : Détection d'expiration artificielle de cible et déclenchement d'alerte
    daemon
        .evaluate_system_liveness(&admin_cap, 25_000)
        .expect("auto-test: evaluate failed");
    assert!(
        daemon.stats.total_stalls_detected >= 1,
        "auto-test: stall must be detected"
    );

    // Test 4 : Calcul et vérification de la chaîne d'audit SHA-256
    let digest = daemon
        .get_audit_digest(&admin_cap)
        .expect("auto-test: audit digest failed");
    assert!(
        digest != [0u8; 32],
        "auto-test: SHA-256 audit digest must not be zero"
    );

    println("[WATCHDOGD] Auto-test reussi : armement materiel, ping, detection de blocage et chaine SHA-256 valides.");
    println("[WATCHDOGD] Serveur Chien de Garde & Vivacite Systeme (jambo-watchdogd PID 21) pret.");

    // 3. Initialisation du canal IPC pour communication avec le shell jsh et les services
    let mut wdog_srv_h: u64 = 0;
    let mut wdog_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut wdog_srv_h as *mut u64 as u64,
            &mut wdog_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = Handle(if wdog_srv_h != 0 {
        wdog_srv_h
    } else {
        21 // Endpoint standard PID 21
    });
    println("[WATCHDOGD] Canal IPC Watchdog operationnel (endpoint PID 21 pret).");

    // 4. Boucle de service IPC Ring 3
    let mut tick: u64 = 1000;
    loop {
        let mut rx_msg = ChannelMessage::default();
        let (ret, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                server_endpoint.0,
                0,
                &mut rx_msg as *mut ChannelMessage as u64,
                0,
                0,
                0,
            )
        };

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<WatchdogRequest>() {
            if let Some(req) = WatchdogRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = daemon.handle_ipc_request(&req, tick);
                let resp_bytes = resp.to_bytes();
                let mut tx_msg = ChannelMessage::default();
                let copy_len = resp_bytes.len().min(MAX_FASTPATH_BYTES);
                tx_msg.bytes[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
                tx_msg.byte_count = copy_len;

                unsafe {
                    libjambo::syscall6(
                        libjambo::SyscallNumber::ChannelCall,
                        server_endpoint.0,
                        &tx_msg as *const ChannelMessage as u64,
                        0,
                        0,
                        0,
                        0,
                    );
                }
            }
        }

        tick = tick.wrapping_add(1);
        syscall_thread_yield();
    }
}

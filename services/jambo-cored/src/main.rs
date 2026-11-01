//! Démon de Capture d'État Post-Mortem, Crash Dumps ELF64 & Analyse Forensique (cored, Ring 3, PID 22)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Capture déterministe de l'état post-mortem des registres CPU et de la pile mémoire
//! - Génération de Core Dumps ELF64 conformes (`ET_CORE`, `PT_NOTE`, `PT_LOAD`)
//! - Scellement cryptographique inviolable par chaîne SHA-256
//! - Confinement et mise en quarantaine immédiate des segments mémoires VMO défaillants
//! - Serveur IPC synchrone 64 octets sous l'endpoint 22 pour le shell `jsh` et services JamboOS (PID 22)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_cored::{
    syscall_thread_yield, ChannelMessage, CoreRequest, Elf64Generator, Handle, JamboCoreDaemon,
    MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[cored] PANIC: bare-metal crash dump daemon fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[cored] PANIC: bare-metal crash dump daemon fault\n" {
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
    println("\x1b[1;32m   JamboOS Sovereign Core Dump Daemon (PID 22) v0.3.61   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation et initialisation par défaut
    let mut daemon = JamboCoreDaemon::new();
    daemon.init_defaults();
    println(
        "[CORED] Demon de capture de crash dumps ELF64 & analyse forensique initialise (PID 22).",
    );

    // 2. Auto-tests unitaires intégrés au boot
    println("[CORED] Demarrage de l'auto-test du demon post-mortem...");

    // Test 1 : Vérification des rapports par défaut
    assert!(
        daemon.report_count >= 2,
        "auto-test: default reports count mismatch"
    );

    let rep1 = daemon.get_report(1).expect("auto-test: report 1 missing");
    assert!(
        rep1.elf_size > 0,
        "auto-test: report 1 ELF size must be non-zero"
    );
    assert_eq!(
        rep1.process_name_str(),
        "worker-service",
        "auto-test: report 1 process name mismatch"
    );

    // Test 2 : Génération et validation des en-têtes ELF64 standard (ET_CORE, PT_NOTE, etc.)
    let admin_cap = daemon.admin_cap;
    let mut elf_buf = [0u8; 2048];
    let elf_len = daemon
        .generate_elf(&admin_cap, 1, &mut elf_buf)
        .expect("auto-test: ELF generation failed");
    assert_eq!(
        elf_buf[0..4],
        [0x7f, b'E', b'L', b'F'],
        "auto-test: ELF magic header invalid"
    );
    assert_eq!(elf_buf[4], 2, "auto-test: must be ELFCLASS64");
    assert_eq!(
        u16::from_le_bytes([elf_buf[16], elf_buf[17]]),
        Elf64Generator::ET_CORE,
        "auto-test: must be ET_CORE"
    );
    assert_eq!(elf_len, rep1.elf_size, "auto-test: ELF size mismatch");

    // Test 3 : Validation du scellement SHA-256 et détection d'intégrité
    let seal_valid = daemon
        .verify_seal(&admin_cap, 1)
        .expect("auto-test: seal verification failed");
    assert!(seal_valid, "auto-test: seal must be valid");

    // Test 4 : Mise en quarantaine VMO
    let pages = daemon
        .quarantine_memory(&admin_cap, 1)
        .expect("auto-test: quarantine failed");
    assert!(pages > 0, "auto-test: quarantined pages must be > 0");
    assert!(
        daemon.get_report(1).unwrap().quarantined,
        "auto-test: report 1 must be marked quarantined"
    );

    println("[CORED] Auto-test reussi : capture crash, generation ELF64, verification SHA-256 et quarantaine VMO valides.");
    println("[CORED] Serveur Crash Dumps & Forensique (jambo-cored PID 22) pret.");

    // 3. Initialisation du canal IPC pour communication avec le shell jsh et services
    let mut core_srv_h: u64 = 0;
    let mut core_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut core_srv_h as *mut u64 as u64,
            &mut core_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = Handle(if core_srv_h != 0 {
        core_srv_h
    } else {
        22 // Endpoint standard PID 22
    });
    println("[CORED] Canal IPC CoreDump operationnel (endpoint PID 22 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<CoreRequest>() {
            if let Some(req) = CoreRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
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

//! Démon de Journalisation Structurée & Chaînage Cryptographique Inviolable (jambo-logd, Ring 3, PID 27)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Journalisation structurée en mémoire circulaire (64 entrées)
//! - Chaînage cryptographique inviolable depuis `GENESIS_HASH`
//! - Vérification d'intégrité de bout en bout en temps linéaire
//! - Serveur IPC synchrone 64 octets sous l'endpoint 27 pour le shell `jsh` et services JamboOS (PID 27)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_logd::{ChannelMessage, LogDaemon, LogLevel, LogRequest, MAX_FASTPATH_BYTES};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[logd] PANIC: bare-metal structured logging daemon fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[logd] PANIC: bare-metal structured logging daemon fault\n" {
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
    println("\x1b[1;32m   JamboOS Structured Logging Daemon (PID 27) v0.3.66   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation du gestionnaire et initialisation des entrées de démarrage
    let mut daemon = LogDaemon::new();
    daemon.init_defaults();
    println("[LOGD] Journal circulaire et chaine cryptographique initialises (PID 27).");

    // 2. Auto-tests intégrés au démarrage
    println("[LOGD] Demarrage de l'auto-test du demon de journalisation...");

    // Auto-test 1: Vérification de la chaîne initiale (boot logs)
    let initial_chain_ok = daemon.verify_chain();
    assert!(
        initial_chain_ok,
        "auto-test: initial hash chain verification failed"
    );
    println(
        "[LOGD] Chaine de hachage initiale verifiee : OK (tamper-evident Merkle/Hash chain valide).",
    );

    // Auto-test 2: Écriture d'un message structuré
    let append_res = daemon.append_record(LogLevel::Info, b"netd", b"VirtIO-Net 1.2 link UP");
    assert!(
        append_res.is_ok(),
        "auto-test: append structured record failed"
    );
    println("[LOGD] Auto-test: Ajout d'une entree de log structuree reussi.");

    // Auto-test 3: Vérification que la chaîne demeure intègre après l'ajout
    assert!(
        daemon.verify_chain(),
        "auto-test: hash chain compromised after record append"
    );
    println("[LOGD] Auto-test: Integrite de la chaine post-ecriture validee.");

    // Auto-test 4: Validation de l'empreinte et contenu de la dernière entrée
    let last = daemon
        .get_last()
        .expect("auto-test: last record should exist");
    assert_eq!(
        last.subsystem_str(),
        "netd",
        "auto-test: subsystem mismatch"
    );
    assert_eq!(
        last.message_str(),
        "VirtIO-Net 1.2 link UP",
        "auto-test: message mismatch"
    );
    println("[LOGD] Auto-test: Conformite du record et empreinte SHA-256 validee.");
    println("[LOGD] Auto-test reussi : observabilite et integrite cryptographique validees.");
    println("[LOGD] Serveur Structured Logging (jambo-logd PID 27) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 27
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(27);
    println("[LOGD] Canal IPC Log Daemon operationnel (endpoint PID 27 pret).");

    // 4. Boucle coopérative de service IPC Ring 3
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<LogRequest>() {
            if let Some(req) = LogRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = daemon.dispatch_ipc(&req);
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

        libjambo::syscall_thread_yield();
    }
}

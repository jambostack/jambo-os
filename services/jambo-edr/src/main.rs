//! Démon Détection & Réponse sur les Terminaux (jambo-edr, Ring 3, PID 32)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Surveillance d'arborescence et calcul d'indice de menace comportementale
//! - Analyse et scanneur de shellcode en mémoire vive (NOP sleds, INT3, boucles syscall, pivots ROP)
//! - Moteur d'interception d'injections dynamiques et divergence ELF
//! - Protection d'enclaves TEE et crochets système IDT / syscalls
//! - Confinement O(1) instantané et registre d'audit inaltérable scellé SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 32 (PID 32)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_edr::{
    edr_rights, ChannelMessage, EdrAction, EdrCap, EdrRequest, InjectionType, JamboEdrDaemon,
    ProcessStatus, ShellcodeScanResult, EDR_ENDPOINT_ID, MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[edr] PANIC: bare-metal EDR service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[edr] PANIC: bare-metal EDR service fault\n" {
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
    println("\x1b[1;32m  JamboOS Endpoint Detection & Response Daemon (PID 32) v0.3.71  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon EDR avec capacité souveraine
    let admin_cap = EdrCap::new(
        libjambo::Handle::new(EDR_ENDPOINT_ID, 1),
        edr_rights::ALL,
        100_000,
        10_000,
    );
    let mut daemon = JamboEdrDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[EDR] Daemon EDR souverain et tables de surveillance initialises (PID 32).");

    // 2. Auto-tests de démarrage
    println("[EDR] Demarrage de l'auto-test du service EDR...");

    // Auto-test 1: Surveillance de processus de référence
    let p1 = daemon
        .get_process(1)
        .expect("auto-test: init process (PID 1) must exist");
    assert_eq!(
        p1.status,
        ProcessStatus::Running,
        "auto-test: init status must be Running"
    );
    assert_eq!(
        p1.name_as_str(),
        "jambo-init",
        "auto-test: init name mismatch"
    );
    let p2 = daemon
        .get_process(2)
        .expect("auto-test: schedd process (PID 2) must exist");
    assert!(p2.is_enclave, "auto-test: PID 2 must be an enclave");
    println("[EDR] Auto-test 1: Surveillance des processus de reference : OK.");

    // Auto-test 2: Scan de shellcode en mémoire vive
    let mut shellcode = [0x90u8; 16];
    shellcode[12] = 0xC3;
    let scan_res = daemon
        .scan_process_memory(&admin_cap, 3, &shellcode, 100)
        .expect("auto-test: memory scan");
    assert_eq!(
        scan_res,
        ShellcodeScanResult::NopSledDetected,
        "auto-test: NOP sled must be intercepted"
    );
    assert_eq!(
        daemon.shellcodes_intercepted_count, 1,
        "auto-test: shellcode intercepted count must be 1"
    );
    println("[EDR] Auto-test 2: Scan de shellcode en memoire vive : OK.");

    // Auto-test 3: Détection d'injection dynamique et divergence ELF
    let hollowed = daemon
        .detect_process_hollowing(&admin_cap, 3, 0x0040_0000, 0xCAFE_0000, 200)
        .expect("auto-test: detect process hollowing");
    assert!(hollowed, "auto-test: process hollowing must be detected");
    let inj_wx = daemon
        .load_and_inspect_module(
            &admin_cap,
            4,
            0x7000_0000,
            0x1000,
            "/tmp/inject.jso",
            false,
            true,
            250,
        )
        .expect("auto-test: inspect module");
    assert_eq!(
        inj_wx,
        InjectionType::WritableExecutableSegment,
        "auto-test: W+X segment injection must be intercepted"
    );
    println("[EDR] Auto-test 3: Detection d'injection dynamique et divergence ELF : OK.");

    // Auto-test 4: Isolation O(1) immédiate et scellement d'audit SHA-256
    let prev_ledger_hash = daemon.ledger_hash;
    let rep = daemon
        .isolate_process_with_report(&admin_cap, 4, "Immediate O(1) isolation auto-test", 300)
        .expect("auto-test: isolate process with report");
    assert_eq!(
        rep.action,
        EdrAction::QuarantineIsolate,
        "auto-test: remediation action must be QuarantineIsolate"
    );
    assert_eq!(rep.pid, 4, "auto-test: remediation PID mismatch");
    assert_ne!(
        daemon.ledger_hash, prev_ledger_hash,
        "auto-test: ledger hash must be updated sequentially"
    );
    assert!(
        daemon.verify_ledger_integrity(),
        "auto-test: SHA-256 audit ledger cryptographic integrity must hold"
    );
    println("[EDR] Auto-test 4: Isolation O(1) immediate et scellement d'audit SHA-256 : OK.");

    println("[EDR] Auto-test reussi : surveillance, anti-injections et isolation valides.");
    println("[EDR] Serveur EDR (jambo-edr PID 32) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 32
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(EDR_ENDPOINT_ID as u64);
    println("[EDR] Canal IPC EDR operationnel (endpoint PID 32 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<EdrRequest>() {
            if let Some(req) = EdrRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
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

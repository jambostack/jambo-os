//! Démon de Démarrage Mesuré TPM 2.0, PCR & Chaîne de Confiance Initiale (secboot, Ring 3, PID 26)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Chaîne de mesure cryptographique de démarrage conforme TCG 2.0
//! - Registres PCR TPM 2.0 (PCR 0..23) avec extension SHA-256 déterministe
//! - Vérification d'intégrité de la chaîne critique (PCR 0, 4, 8, 9, 11, 12)
//! - Serveur IPC synchrone 64 octets sous l'endpoint 26 pour le shell `jsh` et services JamboOS (PID 26)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_secboot::{
    ChannelMessage, SecBootRequest, SecureBootManager, Sha256, MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[secboot] PANIC: bare-metal TPM 2.0 measured boot daemon fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[secboot] PANIC: bare-metal TPM 2.0 measured boot daemon fault\n" {
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
    println("\x1b[1;32m   JamboOS TPM 2.0 Measured Boot Daemon (PID 26) v0.3.65   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation du gestionnaire et initialisation de la chaîne mesurée standard
    let mut manager = SecureBootManager::new();
    manager.init_defaults();
    println("[SECBOOT] Registres PCR TPM 2.0 et chaine de mesure souveraine initialises (PID 26).");

    // 2. Auto-tests intégrés au démarrage
    println("[SECBOOT] Demarrage de l'auto-test du demon de demarrage mesure...");

    // Auto-test 1: Vérification de la chaîne de boot mesurée initiale
    let initial_chain_ok = manager.verify_measured_chain();
    assert!(
        initial_chain_ok,
        "auto-test: initial measured chain verification failed"
    );
    println(
        "[SECBOOT] Chaine de confiance initiale verifiee : OK (PCR 0, 4, 8, 9, 11, 12 valides).",
    );

    // Auto-test 2: Extension de test sur PCR 14
    let test_meas = Sha256::digest(b"SELFTEST_SECBOOT_MEASUREMENT_PAYLOAD");
    let extend_res = manager
        .extend_pcr(14, 0x10, b"SelfTest", &test_meas)
        .expect("auto-test: extend PCR 14 failed");
    println("[SECBOOT] Auto-test: Extension cryptographique PCR 14 reussie.");

    // Auto-test 3: Relecture et validation de l'empreinte de PCR 14
    let read_res = manager.read_pcr(14).expect("auto-test: read PCR 14 failed");
    assert_eq!(
        read_res, extend_res,
        "auto-test: PCR 14 readback digest mismatch"
    );
    println("[SECBOOT] Auto-test: Relecture et conformite SHA-256 PCR 14 validees.");

    // Auto-test 4: Vérification que la chaîne critique demeure intègre
    assert!(
        manager.verify_measured_chain(),
        "auto-test: critical chain compromised after PCR 14 extension"
    );
    println("[SECBOOT] Auto-test reussi : intégrité et extension TPM 2.0 validees.");
    println("[SECBOOT] Serveur TPM 2.0 Measured Boot (jambo-secboot PID 26) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 26
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(26);
    println("[SECBOOT] Canal IPC SecBoot Daemon operationnel (endpoint PID 26 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<SecBootRequest>() {
            if let Some(req) = SecBootRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = manager.dispatch_ipc(&req);
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

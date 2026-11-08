//! Démon de Prévention des Fuites de Données (jambo-dlp, Ring 3, PID 38)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Inspection et classification en vol des flux de données (secrets défense, clés privées, PII, jetons)
//! - Algorithme de Luhn ISO/IEC 7812 et calcul déterministe d'entropie de Shannon
//! - Masquage dynamique en vol (redaction) des données sensibles
//! - Blocage immédiat et confinement atomique O(1) des flux illicites
//! - Registre d'audit inaltérable scellé cryptographiquement par SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 38 (PID 38)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_dlp::{
    dlp_rights, ChannelMessage, DlpAction, DlpCap, DlpDataType, DlpRequest, JamboDlpDaemon,
    DLP_ENDPOINT_ID,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[dlp] PANIC: bare-metal DLP service fault");
    loop {
        libjambo::syscall_thread_yield();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Alignement de pile System V ABI (RSP aligné sur 16 octets)
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("and rsp, -16", options(nomem, nostack));
    }

    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m  [DLP] JamboOS Data Loss Prevention Daemon (PID 38) v0.3.77  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon DLP avec capacité souveraine
    let admin_cap = DlpCap::new(
        libjambo::Handle::new(DLP_ENDPOINT_ID, 1),
        dlp_rights::ALL,
        100_000,
        10_000,
    );
    let mut daemon = JamboDlpDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[DLP] Daemon DLP souverain et politiques de classification initialises (PID 38).");

    // 2. Auto-tests de démarrage
    println("[DLP] Demarrage de l'auto-test du service DLP...");

    // Auto-test 1: Politiques fondamentales par défaut
    assert_eq!(daemon.policy_count, 6, "auto-test: 6 default policies");
    println("[DLP] Auto-test 1: Politiques DLP par defaut : OK (6 politiques).");

    // Auto-test 2: Masquage dynamique en vol (PCI-DSS Luhn)
    let card_payload = b"Processing transaction on card: 4111-1111-1111-1111 for order 884";
    let mut out_buf = [0u8; 128];
    let res_mask = daemon
        .inspect_flow(
            1,
            "test_client",
            "payment_gw",
            card_payload,
            &mut out_buf,
            1000,
        )
        .expect("auto-test: mask card");
    assert_eq!(res_mask.action, DlpAction::Mask);
    assert_eq!(res_mask.data_type, DlpDataType::PiiCreditCard);
    println("[DLP] Auto-test 2: Masquage dynamique en vol (redaction PCI-DSS) : OK.");

    // Auto-test 3: Blocage immédiat et confinement O(1) de clé privée
    let key_payload =
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----";
    let res_block = daemon
        .inspect_flow(
            2,
            "suspicious_app",
            "foreign_host",
            key_payload,
            &mut out_buf,
            1010,
        )
        .expect("auto-test: block key");
    assert_eq!(res_block.action, DlpAction::Block);
    assert_eq!(res_block.data_type, DlpDataType::CryptoPrivateKey);
    assert!(res_block.quarantined);
    println("[DLP] Auto-test 3: Blocage immediat et mise en quarantaine O(1) de cle privee : OK.");

    // Auto-test 4: Détection et confinement de flux haute entropie
    let mut high_entropy = [0u8; 256];
    for (i, item) in high_entropy.iter_mut().enumerate() {
        *item = i as u8;
    }
    let res_entropy = daemon
        .inspect_flow(
            3,
            "covert_channel",
            "remote_sink",
            &high_entropy,
            &mut out_buf,
            1020,
        )
        .expect("auto-test: entropy quarantine");
    assert_eq!(res_entropy.action, DlpAction::Quarantine);
    assert_eq!(res_entropy.data_type, DlpDataType::HighEntropyExfiltration);
    println("[DLP] Auto-test 4: Detection et confinement de flux haute entropie : OK.");

    // Auto-test 5: Intégrité de la chaîne d'audit SHA-256
    assert!(
        daemon.verify_audit_integrity(),
        "auto-test: audit integrity"
    );
    println("[DLP] Auto-test 5: Scellement cryptographique d'audit SHA-256 : OK.");

    println("[DLP] Auto-test reussi : moteur d'inspection, masquage et quarantaine valides.");
    println("[DLP] Serveur DLP (jambo-dlp PID 38) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 38
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(DLP_ENDPOINT_ID as u64);
    println("[DLP] Canal IPC DLP operationnel (endpoint PID 38 pret).");

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

        if ret == 0 && rx_msg.byte_count >= 64 {
            let mut req_buf = [0u8; 64];
            req_buf.copy_from_slice(&rx_msg.bytes[..64]);
            if let Ok(req) = DlpRequest::from_bytes(&req_buf) {
                let resp = daemon.dispatch_ipc(&req);
                let resp_bytes = resp.to_bytes();

                let mut tx_msg = ChannelMessage::default();
                tx_msg.bytes[..64].copy_from_slice(&resp_bytes);
                tx_msg.byte_count = 64;

                let _ = unsafe {
                    libjambo::syscall6(
                        libjambo::SyscallNumber::ChannelCall,
                        server_endpoint.0,
                        &tx_msg as *const ChannelMessage as u64,
                        0,
                        0,
                        0,
                        0,
                    )
                };
            }
        }

        libjambo::syscall_thread_yield();
    }
}

//! Démon d'Infrastructure à Clés Publiques Éphémères & Gestion des Certificats de Grappe (certd, Ring 3, PID 24)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Autorité de certification de grappe mTLS autonome
//! - Émission et révocation de certificats éphémères signés cryptographiquement
//! - Validation d'intégrité, d'usages autorisés et de baux temporels
//! - Serveur IPC synchrone 64 octets sous l'endpoint 24 pour le shell `jsh` et services JamboOS (PID 24)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_certd::{
    cert_rights, key_usages, CertCap, CertRequest, CertStatus, ChannelMessage, ClusterCa, Handle,
    MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[certd] PANIC: bare-metal ephemeral PKI daemon fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[certd] PANIC: bare-metal ephemeral PKI daemon fault\n" {
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
    println("\x1b[1;32m   JamboOS Ephemeral PKI Daemon (PID 24) v0.3.63   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation de l'autorité de grappe et initialisation par défaut
    let mut ca = ClusterCa::new();
    ca.init_defaults();
    println("[CERTD] Autorite de certification de grappe souveraine initialisee (PID 24).");

    // 2. Auto-tests intégrés au boot
    println("[CERTD] Demarrage de l'auto-test du demon PKI...");
    let admin_cap = CertCap::new(Handle::new(24, 1), cert_rights::ALL);

    // Auto-test 1: Émission d'un certificat éphémère pour netd.jambo
    let netd_cert = ca
        .issue_cert(
            &admin_cap,
            b"netd.jambo",
            [0x44; 32],
            1000,
            2000,
            key_usages::USAGE_SERVER_AUTH | key_usages::USAGE_CLIENT_AUTH,
        )
        .expect("auto-test: issue cert for netd.jambo failed");
    assert_eq!(netd_cert.subject_str(), "netd.jambo");

    // Auto-test 2: Vérification du certificat valide
    let status_valid = ca
        .verify_cert(&admin_cap, &netd_cert, key_usages::USAGE_SERVER_AUTH, 1500)
        .expect("auto-test: verify valid cert failed");
    assert_eq!(status_valid, CertStatus::Valid);

    // Auto-test 3: Révocation explicite
    ca.revoke_cert(&admin_cap, netd_cert.serial)
        .expect("auto-test: revoke cert failed");

    // Auto-test 4: Vérification post-révocation
    let status_revoked = ca
        .verify_cert(&admin_cap, &netd_cert, key_usages::USAGE_SERVER_AUTH, 1500)
        .expect("auto-test: verify revoked cert failed");
    assert_eq!(status_revoked, CertStatus::Revoked);

    println("[CERTD] Auto-test reussi : emission, validation cryptographique et revocation mTLS validees.");
    println("[CERTD] Serveur PKI Ephemere (jambo-certd PID 24) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 24
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(24);
    println("[CERTD] Canal IPC PKI Daemon operationnel (endpoint PID 24 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<CertRequest>() {
            if let Some(req) = CertRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = ca.dispatch_ipc(&req);
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

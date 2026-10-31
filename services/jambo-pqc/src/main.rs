//! Démon de Cryptographie Post-Quantique Souveraine (jambo-pqc, Ring 3, PID 8)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Module Learning with Errors Key Encapsulation Mechanism (ML-KEM / Kyber-768)
//! - Module Learning with Errors Digital Signature Algorithm (ML-DSA / Dilithium-65)
//! - Échange de clés hybride Dual-Defense via HKDF-SHA256
//! - Registre d'audit immuable scellé par chaîne SHA-256
//! - Serveur IPC pour le shell `jsh` (opcodes GetStatus, KeyExchange, SignVerify, GetAudit)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_pqc::{
    pqc_rights, syscall_thread_yield, ChannelMessage, JamboPqcDaemon, PqcCap, PqcOpcode,
    PqcRequest, PqcResponse, Sha256, DSA_SIGNATURE_LEN, KEM_CIPHERTEXT_LEN, KEM_SHARED_SECRET_LEN,
    MAX_FASTPATH_BYTES, PQC_STATUS_ERROR, PQC_STATUS_OK,
};
use libjambo::println;

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
    println("\x1b[1;32m   JamboOS Sovereign PQC Daemon (PID 8) v0.3.47  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation de la capabilité racine PQC
    let cap = PqcCap::new(libjambo::Handle::new(184, 1), pqc_rights::ALL);
    let mut pqc_daemon = JamboPqcDaemon::new(cap);

    // Initialisation des clés par défaut de la grappe (KEM key_id=1, DSA key_id=2)
    pqc_daemon.init_defaults();
    println("[PQC] Cles souveraines racine initialisees (ML-KEM ID 1, ML-DSA ID 2).");

    // 2. Auto-test du moteur PQC au démarrage (ML-KEM & ML-DSA)
    println("[PQC] Demarrage de l'auto-test cryptographique post-quantique...");

    // Test ML-KEM
    let mut kem_ct = [0u8; KEM_CIPHERTEXT_LEN];
    let mut kem_ss_enc = [0u8; KEM_SHARED_SECRET_LEN];
    let mut kem_ss_dec = [0u8; KEM_SHARED_SECRET_LEN];
    let kem_res = pqc_daemon
        .kem_encapsulate(
            &cap,
            1,
            b"boot_selftest_kem_entropy_seed_2026",
            &mut kem_ct,
            &mut kem_ss_enc,
        )
        .and_then(|()| pqc_daemon.kem_decapsulate(&cap, 1, &kem_ct, &mut kem_ss_dec));

    if kem_res.is_ok() && kem_ss_enc == kem_ss_dec {
        println("[PQC] Auto-test ML-KEM reussi : Encapsulation & Decapsulation verifiees.");
    } else {
        println("[PQC] ERREUR : Echec de l'auto-test ML-KEM !");
    }

    // Test ML-DSA
    let test_msg = b"JAMBO_PQC_SELFTEST_BOOT_PAYLOAD_2026";
    let nonce = b"selftest_nonce_pqc_1234";
    let mut dsa_sig = [0u8; DSA_SIGNATURE_LEN];
    let dsa_sign_res = pqc_daemon.dsa_sign(&cap, 2, test_msg, nonce, &mut dsa_sig);
    let dsa_verify_res = if dsa_sign_res.is_ok() {
        pqc_daemon.dsa_verify(&cap, 2, test_msg, &dsa_sig)
    } else {
        Ok(false)
    };

    if dsa_verify_res.unwrap_or(false) {
        println("[PQC] Auto-test ML-DSA reussi : Signature & Verification authentifiees.");
    } else {
        println("[PQC] ERREUR : Echec de l'auto-test ML-DSA !");
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh
    let mut pqc_srv_h: u64 = 0;
    let mut pqc_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut pqc_srv_h as *mut u64 as u64,
            &mut pqc_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if pqc_srv_h != 0 { pqc_srv_h } else { 8 });
    println("[PQC] Canal IPC de cryptographie post-quantique operationnel (endpoint PID 8 pret).");

    // 4. Boucle de service IPC Ring 3
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<PqcRequest>() {
            if let Some(req) = PqcRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let mut resp = PqcResponse::default();

                match req.opcode {
                    x if x == PqcOpcode::GetStatus as u32 => {
                        resp.status = PQC_STATUS_OK;
                        resp.transition_state = pqc_daemon.transition_state as u32;
                        resp.active_keys = pqc_daemon.count_active_keys() as u32;
                        resp.operations_count = pqc_daemon.total_operations() as u32;
                        resp.audit_logs_count =
                            pqc_daemon.audit_logs.iter().filter(|l| l.is_some()).count() as u32;
                        resp.result_code = 0;
                        resp.digest.copy_from_slice(&pqc_daemon.audit_chain);
                    }
                    x if x == PqcOpcode::KeyExchange as u32 => {
                        let mut ct = [0u8; KEM_CIPHERTEXT_LEN];
                        let mut hybrid_ss = [0u8; 32];
                        let classical = [0x5au8; 32];
                        let session = b"JAMBO_PQC_IPC_KEX_2026";
                        match pqc_daemon.execute_hybrid_kex(
                            &cap,
                            1,
                            &classical,
                            session,
                            &mut ct,
                            &mut hybrid_ss,
                        ) {
                            Ok(()) => {
                                resp.status = PQC_STATUS_OK;
                                resp.transition_state = pqc_daemon.transition_state as u32;
                                resp.active_keys = pqc_daemon.count_active_keys() as u32;
                                resp.operations_count = pqc_daemon.total_operations() as u32;
                                resp.result_code = 1;
                                resp.digest = hybrid_ss;
                            }
                            Err(_) => {
                                resp.status = PQC_STATUS_ERROR;
                            }
                        }
                    }
                    x if x == PqcOpcode::SignVerify as u32 => {
                        let msg_bytes =
                            if req.data_len > 0 && (req.data_len as usize) <= req.payload.len() {
                                &req.payload[..req.data_len as usize]
                            } else {
                                b"SOVEREIGN_CLUSTER_PQC_2026"
                            };
                        let nonce = b"pqc_ipc_deterministic_nonce";
                        let mut sig = [0u8; DSA_SIGNATURE_LEN];
                        match pqc_daemon.dsa_sign(&cap, 2, msg_bytes, nonce, &mut sig) {
                            Ok(_) => match pqc_daemon.dsa_verify(&cap, 2, msg_bytes, &sig) {
                                Ok(valid) if valid => {
                                    resp.status = PQC_STATUS_OK;
                                    resp.transition_state = pqc_daemon.transition_state as u32;
                                    resp.active_keys = pqc_daemon.count_active_keys() as u32;
                                    resp.operations_count = pqc_daemon.total_operations() as u32;
                                    resp.result_code = 1;
                                    resp.digest = Sha256::digest(&sig);
                                }
                                _ => {
                                    resp.status = PQC_STATUS_ERROR;
                                    resp.result_code = 0;
                                }
                            },
                            Err(_) => {
                                resp.status = PQC_STATUS_ERROR;
                            }
                        }
                    }
                    x if x == PqcOpcode::GetAudit as u32 => {
                        resp.status = PQC_STATUS_OK;
                        resp.transition_state = pqc_daemon.transition_state as u32;
                        resp.active_keys = pqc_daemon.count_active_keys() as u32;
                        resp.operations_count = pqc_daemon.total_operations() as u32;
                        resp.audit_logs_count =
                            pqc_daemon.audit_logs.iter().filter(|l| l.is_some()).count() as u32;
                        resp.result_code = pqc_daemon.epoch as i32;
                        resp.digest.copy_from_slice(&pqc_daemon.audit_chain);
                    }
                    _ => {
                        resp.status = PQC_STATUS_ERROR;
                    }
                }

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

        syscall_thread_yield();
    }
}

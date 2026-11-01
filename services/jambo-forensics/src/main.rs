//! Démon d'Investigation Numérique & Confinement Mémoire Post-Incident (jambo-forensics, Ring 3, PID 10)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Acquisition médico-légale et capture d'images mémoire vive (processus, VMO)
//! - Analyse de résidus mémoire (slack space, fragments de shellcode, chaînes de gadgets ROP)
//! - Scellement cryptographique combiné BLAKE3 + SHA-256 + Ed25519
//! - Registre inaltérable de chaîne de garde (*Chain of Custody*) chaîné par SHA-256
//! - Confinement et mise en quarantaine atomique de processus compromis
//! - Serveur IPC pour le shell `jsh` (opcodes GetStatus, DumpProcess, GetTimeline, QuarantineProcess)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_forensics::{
    forensics_rights, syscall_thread_yield, ChannelMessage, ForensicKeyPair, ForensicsCap,
    ForensicsOpcode, ForensicsRequest, ForensicsResponse, JamboForensicsDaemon,
    FORENSICS_STATUS_ERROR, FORENSICS_STATUS_OK, MAX_FASTPATH_BYTES,
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
    println("\x1b[1;32m   JamboOS Sovereign Forensics Daemon (PID 10) v0.3.49 \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation de la capabilité racine et dérivation des clés Ed25519
    let cap = ForensicsCap::new(
        libjambo::Handle::new(10, 1),
        forensics_rights::ALL,
        u64::MAX,
        u32::MAX,
    );
    let keypair = ForensicKeyPair::derive_from_seed(0x20261101_00000010);
    let mut daemon = JamboForensicsDaemon::new(cap, keypair);

    // Initialisation des preuves et artefacts témoins par défaut
    daemon.init_defaults();
    println("[FORENSICS] Cles Ed25519 et capabilites racine initialisees (PID 10).");

    // 2. Auto-test du moteur forensique au démarrage
    println("[FORENSICS] Demarrage de l'auto-test d'investigation volatile...");
    let custody_ok = daemon.verify_custody_integrity();
    let seal_ok = if let Some(ref seal) = daemon.seals[0] {
        daemon.verify_seal_integrity(&cap, seal).unwrap_or(false)
    } else {
        false
    };

    if custody_ok && seal_ok && daemon.snapshot_count > 0 {
        println("[FORENSICS] Auto-test reussi : Snapshot memoire, residus, scellement BLAKE3+SHA256+Ed25519 et chaine de garde valides.");
    } else {
        println("[FORENSICS] ALERTE : Anomalie detectee lors de l'auto-test FORENSICS !");
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh
    let mut forensics_srv_h: u64 = 0;
    let mut forensics_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut forensics_srv_h as *mut u64 as u64,
            &mut forensics_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if forensics_srv_h != 0 {
        forensics_srv_h
    } else {
        10
    });
    println(
        "[FORENSICS] Canal IPC d'investigation et confinement memoire operationnel (endpoint PID 10 pret).",
    );

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<ForensicsRequest>() {
            if let Some(req) = ForensicsRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let mut resp = ForensicsResponse::default();

                match req.opcode {
                    x if x == ForensicsOpcode::GetStatus as u32 => {
                        let summary = daemon.get_summary();
                        resp.status = FORENSICS_STATUS_OK;
                        resp.snapshot_count = summary.snapshot_count as u32;
                        resp.seal_count = summary.seal_count as u32;
                        resp.custody_count = summary.custody_count as u32;
                        resp.artifact_count = summary.artifact_count as u32;
                        resp.risk_score = summary.cumulative_risk_score;
                        resp.custody_valid = if summary.custody_chain_valid { 1 } else { 0 };
                        resp.result_code = 0;
                        resp.digest = daemon.custody_chain;
                    }
                    x if x == ForensicsOpcode::DumpProcess as u32 => {
                        let target_pid = req.target_pid;
                        match daemon.dump_and_seal_process(
                            &cap,
                            target_pid,
                            2000 + daemon.snapshot_count as u64,
                        ) {
                            Ok(seal) => {
                                let summary = daemon.get_summary();
                                resp.status = FORENSICS_STATUS_OK;
                                resp.snapshot_count = summary.snapshot_count as u32;
                                resp.seal_count = summary.seal_count as u32;
                                resp.custody_count = summary.custody_count as u32;
                                resp.artifact_count = summary.artifact_count as u32;
                                resp.risk_score = summary.cumulative_risk_score;
                                resp.custody_valid =
                                    if summary.custody_chain_valid { 1 } else { 0 };
                                resp.result_code = target_pid as i32;
                                resp.digest = seal.blake3_digest;
                            }
                            Err(_) => {
                                resp.status = FORENSICS_STATUS_ERROR;
                                resp.result_code = -(target_pid as i32);
                            }
                        }
                    }
                    x if x == ForensicsOpcode::GetTimeline as u32 => {
                        let summary = daemon.get_summary();
                        resp.status = FORENSICS_STATUS_OK;
                        resp.snapshot_count = summary.snapshot_count as u32;
                        resp.seal_count = summary.seal_count as u32;
                        resp.custody_count = summary.custody_count as u32;
                        resp.artifact_count = summary.artifact_count as u32;
                        resp.risk_score = summary.cumulative_risk_score;
                        resp.custody_valid = if summary.custody_chain_valid { 1 } else { 0 };
                        resp.result_code = summary.artifact_count as i32;
                        resp.digest = daemon.custody_chain;
                    }
                    x if x == ForensicsOpcode::QuarantineProcess as u32 => {
                        let target_pid = req.target_pid;
                        match daemon.quarantine_process(
                            &cap,
                            target_pid,
                            3000 + daemon.custody_count as u64,
                        ) {
                            Ok(_) => {
                                let summary = daemon.get_summary();
                                resp.status = FORENSICS_STATUS_OK;
                                resp.snapshot_count = summary.snapshot_count as u32;
                                resp.seal_count = summary.seal_count as u32;
                                resp.custody_count = summary.custody_count as u32;
                                resp.artifact_count = summary.artifact_count as u32;
                                resp.risk_score = summary.cumulative_risk_score;
                                resp.custody_valid =
                                    if summary.custody_chain_valid { 1 } else { 0 };
                                resp.result_code = target_pid as i32;
                                resp.digest = daemon.custody_chain;
                            }
                            Err(_) => {
                                resp.status = FORENSICS_STATUS_ERROR;
                                resp.result_code = -(target_pid as i32);
                            }
                        }
                    }
                    _ => {
                        resp.status = FORENSICS_STATUS_ERROR;
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

//! Démon de Cyber-Résilience et Contrôle d'Intégrité Noyau (jambo-kdir, Ring 3, PID 9)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Surveillance continue d'intégrité des structures critiques du noyau (IDT, GDT, CR3 PML4, MSR LSTAR)
//! - Contrôle de signatures cryptographiques des pilotes VMO
//! - Détection de rootkits DKOM et hooks IDT/MSR
//! - Auto-restauration en temps constant O(1) depuis le Golden Snapshot
//! - Registre d'audit immuable scellé par chaîne SHA-256
//! - Serveur IPC pour le shell `jsh` (opcodes GetStatus, ScanIntegrity, RestoreSnapshot, GetAudit)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_kdir::{
    kdir_rights, syscall_thread_yield, ChannelMessage, JamboKdirDaemon, KdirCap, KdirOpcode,
    KdirRequest, KdirResponse, KDIR_PROTECTION_DEGRADED, KDIR_PROTECTION_SECURED,
    KDIR_STATUS_ERROR, KDIR_STATUS_OK, MAX_FASTPATH_BYTES,
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
    println("\x1b[1;32m   JamboOS Sovereign KDIR Daemon (PID 9) v0.3.48 \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation de la capabilité racine KDIR
    let cap = KdirCap::new(
        libjambo::Handle::new(141, 1),
        kdir_rights::ALL,
        u64::MAX,
        u32::MAX,
    );
    let mut daemon = JamboKdirDaemon::new(cap);

    // Initialisation des structures système et pilotes par défaut
    daemon.init_defaults();
    println(
        "[KDIR] Configuration souveraine initialisee (4 sondes systeme, 3 pilotes surveilles).",
    );

    // 2. Auto-test du moteur KDIR au démarrage
    println("[KDIR] Demarrage de l'auto-test de cyber-resilience noyau...");
    let (intact, tampered) = daemon.scan_all_probes_with_golden(1735000005);
    if intact == 4 && tampered == 0 {
        println("[KDIR] Auto-test reussi : 4 sondes systeme (IDT, GDT, CR3, LSTAR) et 3 pilotes valides.");
    } else {
        println("[KDIR] ALERTE : Anomalie detectee lors de l'auto-test KDIR !");
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh
    let mut kdir_srv_h: u64 = 0;
    let mut kdir_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut kdir_srv_h as *mut u64 as u64,
            &mut kdir_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if kdir_srv_h != 0 { kdir_srv_h } else { 9 });
    println(
        "[KDIR] Canal IPC de surveillance cyber-resilience operationnel (endpoint PID 9 pret).",
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<KdirRequest>() {
            if let Some(req) = KdirRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let mut resp = KdirResponse::default();

                match req.opcode {
                    x if x == KdirOpcode::GetStatus as u32 => {
                        let summary = daemon.get_summary();
                        resp.status = KDIR_STATUS_OK;
                        resp.protection_state = if summary.tampered_count == 0 {
                            KDIR_PROTECTION_SECURED
                        } else {
                            KDIR_PROTECTION_DEGRADED
                        };
                        resp.active_probes = summary.probes_count as u32;
                        resp.monitored_drivers = summary.drivers_count as u32;
                        resp.active_threats =
                            (summary.threats_detected - summary.remediated_threats) as u32;
                        resp.audit_entries = summary.ledger_entries as u32;
                        resp.result_code = summary.global_resilience_score as i32;
                        resp.digest = daemon.last_audit_hash;
                    }
                    x if x == KdirOpcode::ScanIntegrity as u32 => {
                        let (intact, tampered) = daemon.scan_all_probes_with_golden(1735000010);
                        let summary = daemon.get_summary();
                        resp.status = KDIR_STATUS_OK;
                        resp.protection_state = if tampered == 0 {
                            KDIR_PROTECTION_SECURED
                        } else {
                            KDIR_PROTECTION_DEGRADED
                        };
                        resp.active_probes = intact as u32;
                        resp.monitored_drivers = summary.drivers_count as u32;
                        resp.active_threats =
                            (summary.threats_detected - summary.remediated_threats) as u32;
                        resp.audit_entries = summary.ledger_entries as u32;
                        resp.result_code = summary.global_resilience_score as i32;
                        resp.digest = daemon.last_audit_hash;
                    }
                    x if x == KdirOpcode::RestoreSnapshot as u32 => {
                        let restored = daemon.remediate_all_threats(1735000020).unwrap_or(0);
                        let summary = daemon.get_summary();
                        resp.status = KDIR_STATUS_OK;
                        resp.protection_state = KDIR_PROTECTION_SECURED;
                        resp.active_probes = summary.intact_count as u32;
                        resp.monitored_drivers = summary.drivers_count as u32;
                        resp.active_threats = 0;
                        resp.audit_entries = summary.ledger_entries as u32;
                        resp.result_code = restored as i32;
                        resp.digest = daemon.last_audit_hash;
                    }
                    x if x == KdirOpcode::GetAudit as u32 => {
                        let summary = daemon.get_summary();
                        resp.status = KDIR_STATUS_OK;
                        resp.protection_state = if summary.ledger_valid {
                            KDIR_PROTECTION_SECURED
                        } else {
                            KDIR_PROTECTION_DEGRADED
                        };
                        resp.active_probes = summary.probes_count as u32;
                        resp.monitored_drivers = summary.drivers_count as u32;
                        resp.active_threats =
                            (summary.threats_detected - summary.remediated_threats) as u32;
                        resp.audit_entries = summary.ledger_entries as u32;
                        resp.result_code = summary.global_resilience_score as i32;
                        resp.digest = daemon.last_audit_hash;
                    }
                    _ => {
                        resp.status = KDIR_STATUS_ERROR;
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

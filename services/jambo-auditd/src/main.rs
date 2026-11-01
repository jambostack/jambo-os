//! Démon d'Audit Cryptographique Inaltérable et Observabilité Zéro-Autorité (auditd, Ring 3, PID 18)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Journal d'audit de sécurité inviolable (tamper-evident ledger)
//! - Scellement séquentiel par chaîne de hachage cryptographique déterministe
//! - Contrôle d'accès strict par capacité `AuditCap` sans autorité ambiante
//! - Détecteur d'anomalies de sécurité en temps réel (seuil heuristique d'incidents)
//! - Serveur IPC synchrone 64 octets pour le shell `jsh` et les services de grappe (PID 18)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_auditd::{
    syscall_thread_yield, AnomalyType, AuditCategory, AuditRequest, AuditSeverity, ChannelMessage,
    JamboAuditDaemon, MAX_FASTPATH_BYTES,
};
use libjambo::{println, Handle};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m  JamboOS Sovereign Audit Daemon (PID 18) v0.3.57  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon d'audit cryptographique
    let mut daemon = JamboAuditDaemon::new();
    println("[AUDITD] Grand livre d'audit cryptographique initialise (PID 18).");

    // 2. Auto-test au démarrage
    println("[AUDITD] Demarrage de l'auto-test d'integrite du grand livre...");

    // Test 1 : Vérification de la graine d'initialisation
    assert!(
        daemon.ledger.last_hash == [0x5A; 16],
        "auto-test: initial seed hash mismatch"
    );

    // Test 2 : Initialisation des événements fondamentaux de boot
    daemon.init_defaults();
    assert!(
        daemon.ledger.total_recorded() == 3,
        "auto-test: expected 3 boot events"
    );

    // Test 3 : Vérification mathématique de l'intégrité de la chaîne
    let intact = daemon.verify_integrity();
    assert!(intact, "auto-test: hash chain integrity failed");

    // Test 4 : Simulation de falsification et détection d'altération
    let mut test_daemon = JamboAuditDaemon::new();
    test_daemon.init_defaults();
    test_daemon.ledger.corrupt_entry_for_test(1);
    assert!(
        !test_daemon.verify_integrity(),
        "auto-test: tampering detection failed"
    );

    // Test 5 : Détection heuristique d'anomalies de sécurité
    let cap = daemon.admin_cap;
    for _ in 0..3 {
        let _ = daemon.ledger.record_event(
            &cap,
            42,
            AuditCategory::DistributedRpc,
            AuditSeverity::SecurityViolation,
            101,
            b"Replay attack simulated",
            5000,
        );
    }
    let alert = daemon
        .detector
        .scan_for_anomalies(&daemon.ledger)
        .expect("auto-test: anomaly detection failed");
    assert!(
        alert.anomaly == AnomalyType::PotentialRpcReplayAttack,
        "auto-test: wrong anomaly type"
    );
    assert!(alert.suspect_pid == 42, "auto-test: wrong suspect PID");
    assert!(
        alert.incident_count == 3,
        "auto-test: wrong incident count"
    );

    println("[AUDITD] Auto-test reussi : chaine cryptographique scellee, detection de falsification et heuristique d'anomalies validees.");
    println("[AUDITD] Demon d'audit de securite (jambo-auditd PID 18) pret.");

    // 3. Initialisation du canal IPC pour communication avec jsh et les services
    let mut audit_srv_h: u64 = 0;
    let mut audit_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut audit_srv_h as *mut u64 as u64,
            &mut audit_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = Handle(if audit_srv_h != 0 {
        audit_srv_h
    } else {
        18 // Endpoint standard PID 18
    });
    println("[AUDITD] Canal IPC audit operationnel (endpoint PID 18 pret).");

    let mut mock_time_ns: u64 = 10_000;

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<AuditRequest>() {
            if let Some(req) = AuditRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                mock_time_ns = mock_time_ns.saturating_add(100);
                let resp = daemon.handle_ipc_request(&req, mock_time_ns);
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

//! Démon d'Orchestration de Sécurité, Automatisation & Réponse (jambo-soar, Ring 3, PID 35)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Surveillance et orchestration centralisée de sécurité SOAR
//! - Moteur de playbooks conditionnels en graphe acyclique dirigé (DAG) avec tri de Kahn
//! - Atténuation DDoS, réponse WAF, révocation capabilités, DLP, UEBA et restauration KDIR
//! - Registre d'audit inaltérable scellé cryptographiquement par SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 35 (PID 35)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_soar::{
    soar_rights, ChannelMessage, Incident, IncidentCategory, IncidentSeverity, JamboSoarDaemon,
    SoarCap, SoarRequest, MAX_FASTPATH_BYTES, SOAR_ENDPOINT_ID,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[soar] PANIC: bare-metal SOAR service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[soar] PANIC: bare-metal SOAR service fault\n" {
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *b, options(nomem, nostack));
        }
    }
    loop {
        core::hint::spin_loop();
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
    println(
        "\x1b[1;32m  [SOAR] JamboOS Security Orchestration, Automation & Response Daemon (PID 35) v0.3.74  \x1b[0m",
    );
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon SOAR avec capacité souveraine
    let admin_cap = SoarCap::new(
        libjambo::Handle::new(SOAR_ENDPOINT_ID, 1),
        soar_rights::ALL,
        100_000,
        10_000,
    );
    let mut daemon = JamboSoarDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[SOAR] Daemon SOAR souverain et playbooks DAG initialises (PID 35).");

    // 2. Auto-tests de démarrage
    println("[SOAR] Demarrage de l'auto-test du service SOAR...");

    // Auto-test 1: Enregistrement et vérification des 6 playbooks par défaut
    assert_eq!(daemon.playbook_count, 6, "auto-test: 6 default playbooks");
    println("[SOAR] Auto-test 1: Enregistrement des playbooks DAG par defaut : OK (6 playbooks).");

    // Auto-test 2: Validation topologique DAG de Kahn et absence de cycles
    for pb_opt in daemon.playbooks.iter().take(daemon.playbook_count) {
        if let Some(ref pb) = *pb_opt {
            assert!(
                pb.validate_dag().is_ok(),
                "auto-test: DAG must be acyclic and valid"
            );
        }
    }
    println(
        "[SOAR] Auto-test 2: Ordonnancement topologique Kahn et verification anti-cycles : OK.",
    );

    // Auto-test 3: Déclenchement d'incident et exécution automatisée de playbook
    let inc = Incident::new(
        1,
        "Self-Test DDoS Flood Detection",
        IncidentCategory::DDoSFlood,
        IncidentSeverity::High,
        "selftest",
        [192, 0, 2, 1],
        80,
        None,
        None,
        1000,
    );
    let inc_id = daemon
        .create_incident(&admin_cap, inc)
        .expect("auto-test: create incident");
    let exec_res = daemon
        .execute_playbook(&admin_cap, 1, inc_id, 1050)
        .expect("auto-test: execute playbook 1");
    assert!(
        exec_res.fully_mitigated,
        "auto-test: playbook execution fully mitigated"
    );
    println(
        "[SOAR] Auto-test 3: Declenchement incident et execution automatisee de playbook : OK.",
    );

    // Auto-test 4: Scellement cryptographique et intégrité du grand livre SHA-256
    assert!(
        daemon.verify_audit_integrity(),
        "auto-test: audit ledger integrity must hold"
    );
    println("[SOAR] Auto-test 4: Scellement cryptographique d'audit SHA-256 : OK.");

    println("[SOAR] Auto-test reussi : moteur DAG, playbooks et registre d'audit valides.");
    println("[SOAR] Serveur SOAR (jambo-soar PID 35) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 35
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(SOAR_ENDPOINT_ID as u64);
    println("[SOAR] Canal IPC SOAR operationnel (endpoint PID 35 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<SoarRequest>() {
            let mut req_buf = [0u8; 64];
            req_buf.copy_from_slice(&rx_msg.bytes[..64]);
            if let Ok(req) = SoarRequest::from_bytes(&req_buf) {
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

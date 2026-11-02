//! Démon d'Analyse Comportementale des Utilisateurs & Entités (jambo-ueba, Ring 3, PID 36)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Profilage continu des entités et utilisateurs de l'OS
//! - Détection des anomalies comportementales (heures hors-plage, sauts de volume, mouvements latéraux)
//! - Calcul dynamique du score de risque bayésien (0..100) et quarantaine O(1)
//! - Registre d'audit inaltérable scellé cryptographiquement par SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 36 (PID 36)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_ueba::{
    ueba_rights, ActivityEvent, ChannelMessage, EntityType, JamboUebaDaemon, RiskLevel, UebaAction,
    UebaCap, UebaRequest, MAX_FASTPATH_BYTES, UEBA_ENDPOINT_ID,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[ueba] PANIC: bare-metal UEBA service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[ueba] PANIC: bare-metal UEBA service fault\n" {
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
        "\x1b[1;32m  [UEBA] JamboOS User & Entity Behavior Analytics Daemon (PID 36) v0.3.75  \x1b[0m",
    );
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon UEBA avec capacité souveraine
    let admin_cap = UebaCap::new(
        libjambo::Handle::new(UEBA_ENDPOINT_ID, 1),
        ueba_rights::ALL,
        100_000,
        10_000,
    );
    let mut daemon = JamboUebaDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[UEBA] Daemon UEBA souverain et profils comportementaux initialises (PID 36).");

    // 2. Auto-tests de démarrage
    println("[UEBA] Demarrage de l'auto-test du service UEBA...");

    // Auto-test 1: Profils par défaut enregistrés (frontend_srv, sys_admin, backup_d)
    assert_eq!(daemon.profile_count, 3, "auto-test: 3 default profiles");
    println("[UEBA] Auto-test 1: Profils comportementaux par defaut : OK (3 profils).");

    // Auto-test 2: Ingestion d'activité normale et vérification du score de risque faible
    let normal_evt = ActivityEvent::new(
        1,
        "frontend_srv",
        EntityType::ServiceDaemon,
        1000,
        14,   // 14h00 (heures normales 09h..20h)
        50,   // 50 syscalls
        2000, // 2000 octets
        "backend_srv",
    );
    let norm_res = daemon
        .ingest_and_analyze(&normal_evt)
        .expect("auto-test: normal analysis");
    assert_eq!(norm_res.action, UebaAction::Allow);
    assert_eq!(norm_res.risk_level, RiskLevel::Low);
    assert!(!norm_res.quarantined);
    println("[UEBA] Auto-test 2: Ingestion d'activite nominale et score faible : OK.");

    // Auto-test 3: Détection d'anomalie multidimensionnelle (nocturne, volume extrême, pair C2) et quarantaine
    let attack_evt = ActivityEvent::new(
        2,
        "frontend_srv",
        EntityType::ServiceDaemon,
        1050,
        3,            // 03h00 nocturne
        5000,         // Dérive de syscalls
        800000,       // Volume anormal
        "hostile_c2", // Pair inconnu
    )
    .with_privileged(true)
    .with_failed_auth(true);

    let attack_res = daemon
        .ingest_and_analyze(&attack_evt)
        .expect("auto-test: attack analysis");
    assert_eq!(attack_res.action, UebaAction::Quarantine);
    assert_eq!(attack_res.risk_level, RiskLevel::Critical);
    assert!(attack_res.quarantined);
    assert!(daemon.is_quarantined("frontend_srv"));
    println("[UEBA] Auto-test 3: Detection d'anomalie critique et mise en quarantaine O(1) : OK.");

    // Auto-test 4: Scellement cryptographique et intégrité du grand livre SHA-256
    assert!(
        daemon.verify_audit_integrity(),
        "auto-test: audit ledger integrity must hold"
    );
    println("[UEBA] Auto-test 4: Scellement cryptographique d'audit SHA-256 : OK.");

    println("[UEBA] Auto-test reussi : moteur d'analyse, baselines et quarantaine valides.");
    println("[UEBA] Serveur UEBA (jambo-ueba PID 36) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 36
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(UEBA_ENDPOINT_ID as u64);
    println("[UEBA] Canal IPC UEBA operationnel (endpoint PID 36 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<UebaRequest>() {
            let mut req_buf = [0u8; 64];
            req_buf.copy_from_slice(&rx_msg.bytes[..64]);
            if let Ok(req) = UebaRequest::from_bytes(&req_buf) {
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

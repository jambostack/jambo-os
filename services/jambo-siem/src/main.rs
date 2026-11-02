//! Démon Gestion des Informations & des Événements de Sécurité (jambo-siem, Ring 3, PID 31)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Ingestion normalisée multi-sources CEF/OCSF
//! - Corrélation d'attaques multi-étapes en fenêtres glissantes O(1)
//! - Génération et déduplication d'alertes SIEM avec empreinte SHA-256
//! - Registre d'audit inaltérable scellé séquentiellement
//! - Serveur IPC synchrone 64 octets sous l'endpoint 31 (PID 31)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_siem::{
    siem_rights, ChannelMessage, EventCategory, EventSource, SecurityEvent, Severity, SiemCap,
    SiemEngine, SiemOp, SiemRequest, MAX_FASTPATH_BYTES, SIEM_ENDPOINT_ID,
};
use libjambo::{println, Handle};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[siem] PANIC: bare-metal SIEM service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[siem] PANIC: bare-metal SIEM service fault\n" {
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
    println(
        "\x1b[1;32m  JamboOS Security Information & Event Management (PID 31) v0.3.70  \x1b[0m",
    );
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du moteur SIEM avec capacité souveraine
    let admin_cap = SiemCap::new(siem_rights::ALL);
    let mut engine = SiemEngine::new(Handle::new(SIEM_ENDPOINT_ID, 1), admin_cap);
    engine.init_defaults();
    println("[SIEM] Moteur SIEM et regles de correlation initialises (PID 31).");

    // 2. Auto-tests de démarrage
    println("[SIEM] Demarrage de l'auto-test du service SIEM...");

    // Auto-test 1: Ingestion d'événements de référence (Walld, Waf, Authd)
    let ev1 = SecurityEvent::new(
        EventSource::JamboWalld,
        EventCategory::Network,
        Severity::Low,
    );
    engine
        .ingest_event(ev1, 100)
        .expect("auto-test: walld event");

    let ev2 = SecurityEvent::new(
        EventSource::JamboWaf,
        EventCategory::Vulnerability,
        Severity::Medium,
    );
    engine.ingest_event(ev2, 200).expect("auto-test: waf event");

    let ev3 = SecurityEvent::new(
        EventSource::JamboAuthd,
        EventCategory::Authentication,
        Severity::Informational,
    );
    engine
        .ingest_event(ev3, 300)
        .expect("auto-test: authd event");

    assert_eq!(
        engine.event_count(),
        3,
        "auto-test: must have 3 ingested events"
    );
    println("[SIEM] Auto-test 1: Ingestion d'evenements de reference (Walld, Waf, Authd) : OK.");

    // Auto-test 2: Corrélation de règle Brute Force validée
    for i in 0..10u64 {
        let mut ev_bf = SecurityEvent::new(
            EventSource::JamboAuthd,
            EventCategory::Authentication,
            Severity::Medium,
        );
        ev_bf.outcome_success = false;
        engine
            .ingest_event(ev_bf, 1000 + i * 100)
            .expect("auto-test: brute force event");
    }
    assert!(
        engine.alert_count() > 0,
        "auto-test: Brute force rule must fire an alert"
    );
    println("[SIEM] Auto-test 2: Correlation de regle Brute Force validee : OK.");

    // Auto-test 3: Génération et déduplication d'alertes
    let initial_alert_count = engine.alert_count();
    let initial_dedup = engine.dedup_count;
    let mut ev_bf_extra = SecurityEvent::new(
        EventSource::JamboAuthd,
        EventCategory::Authentication,
        Severity::Medium,
    );
    ev_bf_extra.outcome_success = false;
    engine
        .ingest_event(ev_bf_extra, 2500)
        .expect("auto-test: extra bf event");
    assert_eq!(
        engine.alert_count(),
        initial_alert_count,
        "auto-test: Duplicate alert must be deduplicated"
    );
    assert!(
        engine.dedup_count > initial_dedup,
        "auto-test: Dedup counter must increase"
    );
    println("[SIEM] Auto-test 3: Generation et deduplication d'alertes : OK.");

    // Auto-test 4: Scellement séquentiel du grand livre d'audit
    let prev_audit = engine.audit_chain;
    assert!(
        prev_audit.iter().any(|&b| b != 0),
        "auto-test: audit chain must not be zero"
    );
    engine.audit.record(SiemOp::ExportRequested, 3000);
    engine.audit_chain = *engine.audit.chain_head();
    assert_ne!(
        engine.audit_chain, prev_audit,
        "auto-test: audit chain must be sealed sequentially"
    );
    println("[SIEM] Auto-test 4: Scellement sequentiel du grand livre d'audit : OK.");

    println("[SIEM] Auto-test reussi : ingestion, correlation et alertes valides.");
    println("[SIEM] Serveur SIEM (jambo-siem PID 31) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 31
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(SIEM_ENDPOINT_ID as u64);
    println("[SIEM] Canal IPC SIEM operationnel (endpoint PID 31 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<SiemRequest>() {
            if let Some(req) = SiemRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = engine.dispatch_ipc(&req);
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

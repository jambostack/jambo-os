//! Démon Détection & Réponse Étendue (jambo-xdr, Ring 3, PID 34)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Surveillance et ingestion unifiée multi-vecteurs (EDR, NDR/VPN, WAF, Authd, Cloud, TEE)
//! - Graphe de propagation de menaces et détection heuristique de campagnes APT
//! - Facteur de synergie trans-vectorielle avec surcote de sévérité TEE
//! - Orchestration de remédiation instantanée O(1) (UnifiedQuarantine)
//! - Registre d'audit inaltérable scellé cryptographiquement par SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 34 (PID 34)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_xdr::{
    xdr_rights, ChannelMessage, EventSeverity, JamboXdrDaemon, MitreTactic, TelemetryVector,
    XdrCap, XdrRequest, MAX_FASTPATH_BYTES, XDR_ENDPOINT_ID,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[xdr] PANIC: bare-metal XDR service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[xdr] PANIC: bare-metal XDR service fault\n" {
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
        "\x1b[1;32m  [XDR] JamboOS Extended Detection & Response Daemon (PID 34) v0.3.73  \x1b[0m",
    );
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon XDR avec capacité souveraine
    let admin_cap = XdrCap::new(
        libjambo::Handle::new(XDR_ENDPOINT_ID, 1),
        xdr_rights::ALL,
        100_000,
        10_000,
    );
    let mut daemon = JamboXdrDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[XDR] Daemon XDR souverain et correlation APT initialises (PID 34).");

    // 2. Auto-tests de démarrage
    println("[XDR] Demarrage de l'auto-test du service XDR...");

    // Auto-test 1: Ingestion de télémétrie multi-vecteurs
    let ev_id = daemon
        .ingest_event(
            &admin_cap,
            TelemetryVector::EndpointEdr,
            "selftest-worker",
            MitreTactic::Execution,
            EventSeverity::High,
            80,
            "Self-test execution anomaly",
            2000,
        )
        .expect("auto-test: telemetry event ingestion");
    assert!(ev_id > 0, "auto-test: event id must be valid");
    println("[XDR] Auto-test 1: Ingestion telemetrie multi-vecteurs : OK.");

    // Auto-test 2: Corrélation croisée et détection APT
    let _ = daemon.ingest_event(
        &admin_cap,
        TelemetryVector::NetworkVpn,
        "selftest-worker",
        MitreTactic::LateralMovement,
        EventSeverity::Critical,
        85,
        "Self-test VPN lateral tunnel",
        2050,
    );
    let _ = daemon
        .correlate_campaigns(&admin_cap, 2100)
        .expect("auto-test: correlate campaigns");
    assert!(
        daemon.campaign_count >= 1,
        "auto-test: at least 1 APT campaign correlated"
    );
    println("[XDR] Auto-test 2: Correlation croisee et detection APT : OK.");

    // Auto-test 3: Confinement unifié O(1) tous vecteurs
    let report = daemon
        .remediate_campaign_o1(&admin_cap, 1, 2200)
        .expect("auto-test: remediate campaign 1");
    assert_eq!(
        report.campaign_id, 1,
        "auto-test: report campaign id must match"
    );
    assert!(report.endpoint_isolated, "auto-test: endpoint isolated");
    assert!(report.network_severed, "auto-test: network severed");
    assert!(report.waf_route_blocked, "auto-test: waf route blocked");
    assert!(report.identity_revoked, "auto-test: identity revoked");
    assert!(report.tee_locked_down, "auto-test: tee locked down");
    println("[XDR] Auto-test 3: Remediation instantanee O(1) tous vecteurs : OK.");

    // Auto-test 4: Scellement cryptographique et intégrité du registre d'audit SHA-256
    assert!(
        daemon.verify_ledger_integrity(),
        "auto-test: audit ledger integrity must hold"
    );
    println("[XDR] Auto-test 4: Scellement cryptographique d'audit SHA-256 : OK.");

    println("[XDR] Auto-test reussi : surveillance, moteurs de detection et isolation valides.");
    println("[XDR] Serveur XDR (jambo-xdr PID 34) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 34
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(XDR_ENDPOINT_ID as u64);
    println("[XDR] Canal IPC XDR operationnel (endpoint PID 34 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<XdrRequest>() {
            let mut req_buf = [0u8; 64];
            req_buf.copy_from_slice(&rx_msg.bytes[..64]);
            if let Ok(req) = XdrRequest::from_bytes(&req_buf) {
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

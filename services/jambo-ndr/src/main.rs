//! Démon Détection & Réponse Réseau (jambo-ndr, Ring 3, PID 33)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Surveillance comportementale du trafic réseau et suivi de flux en temps réel
//! - Moteur de détection de balisage périodique C2 (Command & Control) à faible gigue (< 50ms)
//! - Détecteur d'exfiltration massive de données (> 64 Kio)
//! - Détecteur de tunneling DNS par analyse d'entropie de Shannon et heuristiques de sous-domaines
//! - Moteur de microsegmentation dynamique Zero-Trust (deny-by-default)
//! - Confinement O(1) instantané des hôtes compromis et rejet immédiat de paquets
//! - Registre d'audit inaltérable scellé cryptographiquement par SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 33 (PID 33)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_ndr::{
    ndr_rights, ChannelMessage, FlowState, JamboNdrDaemon, NdrCap, NdrError, NdrRequest,
    ProtocolType, RuleAction, SecurityZone, MAX_FASTPATH_BYTES, NDR_ENDPOINT_ID,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[ndr] PANIC: bare-metal NDR service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[ndr] PANIC: bare-metal NDR service fault\n" {
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
        "\x1b[1;32m  [NDR] JamboOS Network Detection & Response Daemon (PID 33) v0.3.72  \x1b[0m",
    );
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon NDR avec capacité souveraine
    let admin_cap = NdrCap::new(
        libjambo::Handle::new(NDR_ENDPOINT_ID, 1),
        ndr_rights::ALL,
        100_000,
        10_000,
    );
    let mut daemon = JamboNdrDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[NDR] Daemon NDR souverain et politiques Zero-Trust initialises (PID 33).");

    // 2. Auto-tests de démarrage
    println("[NDR] Demarrage de l'auto-test du service NDR...");

    // Auto-test 1: Enregistrement et suivi d'un flux de référence
    let ref_src_ip = [192, 168, 1, 10];
    let ref_dst_ip = [10, 0, 0, 1];
    let action = daemon
        .ingest_packet(
            &admin_cap,
            1,
            ref_src_ip,
            ref_dst_ip,
            49152,
            443,
            ProtocolType::Tcp,
            SecurityZone::ZoneCoreServices,
            SecurityZone::ZoneExternalNetwork,
            b"GET /health HTTP/1.1\r\n\r\n",
            100,
        )
        .expect("auto-test: reference flow packet ingestion");
    assert_eq!(
        action,
        RuleAction::Allow,
        "auto-test: CoreServices -> ExternalNetwork must be allowed"
    );
    let f1 = daemon
        .get_flow(1)
        .expect("auto-test: reference flow must be tracked");
    assert_eq!(
        f1.state,
        FlowState::Active,
        "auto-test: flow state must be Active"
    );
    assert_eq!(
        f1.packet_count, 1,
        "auto-test: reference flow packet count must be 1"
    );
    println("[NDR] Auto-test 1: Suivi de flux de reference : OK.");

    // Auto-test 2: Détection de balisage périodique C2 (Command & Control)
    let c2_ip = [192, 168, 1, 99];
    let c2_srv = [198, 51, 100, 2];
    let _ = daemon.ingest_packet(
        &admin_cap,
        2,
        c2_ip,
        c2_srv,
        51000,
        443,
        ProtocolType::Tcp,
        SecurityZone::ZoneCoreServices,
        SecurityZone::ZoneExternalNetwork,
        b"beacon-1",
        1000,
    );
    let _ = daemon.ingest_packet(
        &admin_cap,
        2,
        c2_ip,
        c2_srv,
        51000,
        443,
        ProtocolType::Tcp,
        SecurityZone::ZoneCoreServices,
        SecurityZone::ZoneExternalNetwork,
        b"beacon-2",
        2000,
    );
    let _ = daemon.ingest_packet(
        &admin_cap,
        2,
        c2_ip,
        c2_srv,
        51000,
        443,
        ProtocolType::Tcp,
        SecurityZone::ZoneCoreServices,
        SecurityZone::ZoneExternalNetwork,
        b"beacon-3",
        3008,
    );
    let res_c2 = daemon.ingest_packet(
        &admin_cap,
        2,
        c2_ip,
        c2_srv,
        51000,
        443,
        ProtocolType::Tcp,
        SecurityZone::ZoneCoreServices,
        SecurityZone::ZoneExternalNetwork,
        b"beacon-4",
        4012,
    );
    assert_eq!(
        res_c2,
        Err(NdrError::FlowBlocked),
        "auto-test: C2 beaconing must be blocked"
    );
    assert!(
        daemon.c2_beacons_detected >= 1,
        "auto-test: C2 beacon count must be >= 1"
    );
    assert!(
        daemon.is_endpoint_quarantined(&c2_ip),
        "auto-test: C2 source IP must be quarantined"
    );
    println("[NDR] Auto-test 2: Detection de balisage C2 a faible gigue : OK.");

    // Auto-test 3: Détection de Tunneling DNS par entropie de Shannon
    let dns_tunnel_ip = [192, 168, 1, 120];
    let dns_server = [8, 8, 4, 4];
    let tunnel_query = b"b83ac79e4d21f8a9e701bc493a7d2e05fa813c9b7e12.tunnel.c2.net";
    let res_dns = daemon.ingest_packet(
        &admin_cap,
        3,
        dns_tunnel_ip,
        dns_server,
        53535,
        53,
        ProtocolType::Dns,
        SecurityZone::ZoneCoreServices,
        SecurityZone::ZoneExternalNetwork,
        tunnel_query,
        500,
    );
    assert_eq!(
        res_dns,
        Err(NdrError::FlowBlocked),
        "auto-test: DNS tunneling must be blocked"
    );
    assert!(
        daemon.dns_tunnels_detected >= 1,
        "auto-test: DNS tunnel count must be >= 1"
    );
    assert!(
        daemon.is_endpoint_quarantined(&dns_tunnel_ip),
        "auto-test: DNS tunneling IP must be quarantined"
    );
    println("[NDR] Auto-test 3: Detection de tunneling DNS haute entropie : OK.");

    // Auto-test 4: Isolation instantanée O(1)
    let rogue_ip = [172, 16, 42, 42];
    daemon
        .quarantine_endpoint(&admin_cap, rogue_ip, "Self-test manual quarantine", 600)
        .expect("auto-test: quarantine endpoint");
    assert!(
        daemon.is_endpoint_quarantined(&rogue_ip),
        "auto-test: rogue endpoint must be quarantined"
    );
    let res_rogue = daemon.ingest_packet(
        &admin_cap,
        4,
        rogue_ip,
        ref_dst_ip,
        52000,
        80,
        ProtocolType::Tcp,
        SecurityZone::ZoneCoreServices,
        SecurityZone::ZoneExternalNetwork,
        b"rogue-packet",
        650,
    );
    assert_eq!(
        res_rogue,
        Err(NdrError::FlowBlocked),
        "auto-test: quarantined packet must be rejected with FlowBlocked"
    );
    println("[NDR] Auto-test 4: Isolation O(1) immediate : OK.");

    // Auto-test 5: Scellement cryptographique et intégrité du registre d'audit SHA-256
    let prev_hash = daemon.ledger_hash;
    daemon
        .record_audit_entry(&admin_cap, "SELF_TEST_SEAL", 700)
        .expect("auto-test: record audit entry");
    assert_ne!(
        daemon.ledger_hash, prev_hash,
        "auto-test: ledger hash must be updated sequentially"
    );
    assert!(
        daemon.verify_ledger_integrity(),
        "auto-test: SHA-256 audit ledger cryptographic integrity must hold"
    );
    println("[NDR] Auto-test 5: Scellement cryptographique d'audit SHA-256 : OK.");

    println("[NDR] Auto-test reussi : surveillance, moteurs de detection et isolation valides.");
    println("[NDR] Serveur NDR (jambo-ndr PID 33) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 33
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(NDR_ENDPOINT_ID as u64);
    println("[NDR] Canal IPC NDR operationnel (endpoint PID 33 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<NdrRequest>() {
            let mut req_buf = [0u8; 64];
            req_buf.copy_from_slice(&rx_msg.bytes[..64]);
            if let Ok(req) = NdrRequest::from_bytes(&req_buf) {
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

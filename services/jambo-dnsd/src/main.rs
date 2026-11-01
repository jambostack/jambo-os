//! Démon Serveur et Résolveur DNS d'Autorité de Grappe (dnsd, Ring 3, PID 16)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Résolution DNS autoritaire pour la zone souveraine `.jambo`
//! - Support complet RFC 1035 wire-format et enregistrements A, AAAA, SRV, CNAME, TXT, PTR
//! - Cache DNS local sécurisé avec gestion TTL et expulsion
//! - Synchronisation bidirectionnelle avec le registre de découverte `jambo-serviced`
//! - Serveur IPC synchrone 64 octets pour le shell `jsh` et les services JamboOS (PID 16)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_dnsd::{
    dns_rights, syscall_thread_yield, ChannelMessage, DnsCap, DnsRecordData, DnsRequest, DnsType,
    JamboDnsDaemon, MAX_FASTPATH_BYTES,
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
    println("\x1b[1;32m   JamboOS Sovereign DNS Daemon (PID 16) v0.3.55   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon DNS souverain (PID 16)
    let cap = DnsCap::new(Handle::new(74, 1), dns_rights::ALL);
    let mut daemon = JamboDnsDaemon::new(cap);
    println("[DNSD] Serveur DNS souverain et zone autoritaire .jambo initialises (PID 16).");

    // 2. Enregistrements par défaut de la zone .jambo
    let ts: u64 = 0;
    let _ = daemon.add_record(
        &cap,
        "dns.jambo",
        DnsType::A,
        86400,
        DnsRecordData::A([10, 0, 0, 53]),
        ts,
    );
    let _ = daemon.add_record(
        &cap,
        "ns.jambo",
        DnsType::A,
        86400,
        DnsRecordData::A([10, 0, 0, 1]),
        ts,
    );

    // 3. Auto-test au démarrage
    println("[DNSD] Demarrage de l'auto-test de resolution DNS...");

    // Test 1 : Résolution A record dns.jambo
    let ip = daemon
        .resolve_a(&cap, "dns.jambo", ts)
        .expect("auto-test: resolve_a failed")
        .expect("auto-test: ip not found");
    assert!(ip == [10, 0, 0, 53], "auto-test: wrong IP for dns.jambo");

    // Test 2 : Enregistrement SRV _dns._udp.jambo
    let mut srv_target = [0u8; 64];
    srv_target[..8].copy_from_slice(b"ns.jambo");
    let _ = daemon.add_record(
        &cap,
        "_dns._udp.jambo",
        DnsType::SRV,
        300,
        DnsRecordData::SRV {
            priority: 10,
            weight: 100,
            port: 53,
            target: srv_target,
            target_len: 8,
        },
        ts,
    );
    let srv = daemon
        .resolve_srv(&cap, "_dns._udp.jambo", ts)
        .expect("auto-test: resolve_srv failed")
        .expect("auto-test: SRV not found");
    assert!(srv.2 == 53, "auto-test: SRV port mismatch");

    // Test 3 : Cache lookup (résolution répétée même timestamp)
    let ip2 = daemon
        .resolve_a(&cap, "dns.jambo", ts)
        .expect("auto-test: cache lookup failed")
        .expect("auto-test: cached ip not found");
    assert!(ip2 == [10, 0, 0, 53], "auto-test: cache mismatch");

    // Test 4 : Résolution CNAME
    let mut cname_tgt = [0u8; 64];
    cname_tgt[..9].copy_from_slice(b"dns.jambo");
    let _ = daemon.add_record(
        &cap,
        "resolver.jambo",
        DnsType::CNAME,
        300,
        DnsRecordData::CNAME {
            target: cname_tgt,
            target_len: 9,
        },
        ts,
    );
    let cname = daemon
        .resolve_cname(&cap, "resolver.jambo", ts)
        .expect("auto-test: resolve_cname failed");
    assert!(cname.is_some(), "auto-test: CNAME not found");

    println("[DNSD] Auto-test reussi : resolution A dns.jambo (10.0.0.53), resolution SRV, cache DNS et resolution CNAME valides.");
    println("[DNSD] Serveur DNS souverain de grappe (jambo-dnsd PID 16) pret.");

    // 4. Initialisation du canal IPC pour communication avec le shell jsh et les services
    let mut dns_srv_h: u64 = 0;
    let mut dns_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut dns_srv_h as *mut u64 as u64,
            &mut dns_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = Handle(if dns_srv_h != 0 {
        dns_srv_h
    } else {
        16 // Endpoint standard PID 16
    });
    println("[DNSD] Canal IPC DNS operationnel (endpoint PID 16 pret).");

    // 5. Boucle de service IPC Ring 3
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<DnsRequest>() {
            if let Some(req) = DnsRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = daemon.handle_ipc_request(&req, ts);
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

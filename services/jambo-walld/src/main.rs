//! Démon de Pare-Feu Distribué Stateful & Synchronisation Conntrack (walld, Ring 3, PID 19)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Suivi d'état de sessions réseau (TCP 3-way handshake, UDP, ICMP) via table Conntrack bornée
//! - Filtrage adaptatif Zero-Trust et auto-défense contre les anomalies (scans XMAS, NULL)
//! - Synchronisation d'état inter-nœuds cryptographiquement scellée par HMAC-SHA256
//! - Serveur IPC synchrone 64 octets pour le shell `jsh` et les services JamboOS (PID 19)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_walld::{
    ip_proto, syscall_thread_yield, tcp_flags, wall_rights, ChannelMessage, ConntrackState,
    ConntrackTuple, Handle, JamboFirewall, PacketFilterInput, SecurityZone, WallAction, WallCap,
    WallRequest, MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[walld] PANIC: bare-metal firewall fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[walld] PANIC: bare-metal firewall fault\n" {
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
    println("\x1b[1;32m   JamboOS Sovereign Firewall Daemon (PID 19) v0.3.58   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation du pare-feu d'état souverain et initialisation des règles par défaut
    let mut wall = JamboFirewall::new();
    wall.init_defaults();
    println("[WALLD] Pare-feu d'etat & synchronisation conntrack initialises (PID 19).");

    // 2. Auto-tests unitaires intégrés au boot
    println("[WALLD] Demarrage de l'auto-test du pare-feu stateful...");

    // Test 1 : Validation de l'installation des règles par défaut
    assert!(
        wall.rule_count >= 5,
        "auto-test: default rules count mismatch"
    );

    // Test 2 : Transition conntrack TCP SYN -> SYN/ACK -> ESTABLISHED
    let admin_cap = WallCap::new(Handle::new(19, 1), wall_rights::ALL);
    let tuple = ConntrackTuple::new(ip_proto::TCP, [192, 168, 1, 100], [10, 0, 0, 80], 54321, 80);

    let pkt_syn = PacketFilterInput {
        tuple,
        src_zone: SecurityZone::ExternalUntrusted,
        dst_zone: SecurityZone::WorkloadEdge,
        tcp_flags: tcp_flags::SYN,
        payload_len: 40,
    };
    let act_syn = wall
        .filter_packet(&admin_cap, &pkt_syn, 1)
        .expect("auto-test: syn filter failed");
    assert!(
        act_syn == WallAction::Allow,
        "auto-test: syn should be allowed"
    );

    let pkt_synack = PacketFilterInput {
        tuple: tuple.reverse(),
        src_zone: SecurityZone::WorkloadEdge,
        dst_zone: SecurityZone::ExternalUntrusted,
        tcp_flags: tcp_flags::SYN | tcp_flags::ACK,
        payload_len: 40,
    };
    let _ = wall
        .filter_packet(&admin_cap, &pkt_synack, 2)
        .expect("auto-test: synack filter failed");

    let pkt_ack = PacketFilterInput {
        tuple,
        src_zone: SecurityZone::ExternalUntrusted,
        dst_zone: SecurityZone::WorkloadEdge,
        tcp_flags: tcp_flags::ACK,
        payload_len: 0,
    };
    let _ = wall
        .filter_packet(&admin_cap, &pkt_ack, 3)
        .expect("auto-test: ack filter failed");

    let (idx, _) = wall
        .conntrack
        .lookup(&tuple)
        .expect("auto-test: conntrack entry missing");
    assert!(
        wall.conntrack.entries[idx].state == ConntrackState::Established,
        "auto-test: connection must be established"
    );

    // Test 3 : Détection et blocage d'anomalie furtive (scan XMAS)
    let attacker_ip = [203, 0, 113, 77];
    let tuple_xmas = ConntrackTuple::new(ip_proto::TCP, attacker_ip, [10, 0, 0, 80], 44444, 80);
    let pkt_xmas = PacketFilterInput {
        tuple: tuple_xmas,
        src_zone: SecurityZone::ExternalUntrusted,
        dst_zone: SecurityZone::WorkloadEdge,
        tcp_flags: tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG,
        payload_len: 0,
    };
    let act_xmas = wall
        .filter_packet(&admin_cap, &pkt_xmas, 4)
        .expect("auto-test: xmas filter failed");
    assert!(
        act_xmas == WallAction::Drop,
        "auto-test: xmas must be dropped"
    );
    assert!(
        wall.stats.threats_detected >= 1,
        "auto-test: threat counter mismatch"
    );
    assert!(
        wall.count_dynamic_blocks(4) >= 1,
        "auto-test: dynamic block must be active"
    );

    // Test 4 : Génération et vérification de signature HMAC-SHA256
    let sync_event = wall
        .generate_sync_event(&admin_cap, &tuple)
        .expect("auto-test: sync gen failed");
    assert!(
        sync_event.verify(&wall.sync_key),
        "auto-test: HMAC signature verification failed"
    );

    println("[WALLD] Auto-test reussi : regles souveraines, poignee de main TCP FSM, blocage XMAS et HMAC conntrack valides.");
    println(
        "[WALLD] Serveur Pare-Feu d'Etat & Synchronisation Conntrack (jambo-walld PID 19) pret.",
    );

    // 3. Initialisation du canal IPC pour communication avec le shell jsh et les services
    let mut wall_srv_h: u64 = 0;
    let mut wall_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut wall_srv_h as *mut u64 as u64,
            &mut wall_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = Handle(if wall_srv_h != 0 {
        wall_srv_h
    } else {
        19 // Endpoint standard PID 19
    });
    println("[WALLD] Canal IPC Firewall operationnel (endpoint PID 19 pret).");

    // 4. Boucle de service IPC Ring 3
    let mut tick: u64 = 100;
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<WallRequest>() {
            if let Some(req) = WallRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = wall.handle_ipc_request(&req, tick);
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

        tick = tick.wrapping_add(1);
        syscall_thread_yield();
    }
}

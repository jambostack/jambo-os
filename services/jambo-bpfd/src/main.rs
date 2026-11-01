//! Démon eBPF Souverain en Espace Utilisateur (bpfd, Ring 3, PID 13)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Machine Virtuelle eBPF 64-bit sandboxed
//! - Vérificateur formel DAG de terminaison (sans boucles infinies)
//! - Filtrage de paquets réseau XDP et tables de stockage partagées
//! - Serveur IPC pour le shell `jsh` et les services JamboOS (PID 13)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_bpfd::{
    bpf_helpers, bpf_jmp, bpf_rights, syscall_thread_yield, xdp_action, BpfCap, BpfInstruction,
    BpfProgramType, BpfRequest, ChannelMessage, JamboBpfDaemon, MAX_FASTPATH_BYTES,
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
    println("\x1b[1;32m   JamboOS Sovereign eBPF Daemon (PID 13) v0.3.52 \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation de la capabilité racine et du démon
    let admin_cap = BpfCap::new(libjambo::Handle::new(13, 1), bpf_rights::ALL);
    let mut daemon = JamboBpfDaemon::new_with_cap(admin_cap);
    println("[BPFD] Capabilites racine et daemon eBPF initialises (PID 13).");

    // 2. Auto-test au démarrage : chargement d'un filtre XDP par défaut, vérification formelle DAG validée,
    //    exécution de paquets test avec verdicts XDP_PASS / XDP_DROP et comptage de cycles, vérification des statistiques
    println("[BPFD] Demarrage de l'auto-test du moteur eBPF et filtre XDP...");

    let default_xdp_prog = [
        BpfInstruction::mov64_imm(1, 0),
        BpfInstruction::call(bpf_helpers::PACKET_READ_BYTE),
        BpfInstruction::jmp_imm(bpf_jmp::BPF_JEQ, 0, 0x42, 2),
        BpfInstruction::mov64_imm(0, xdp_action::XDP_PASS as i32),
        BpfInstruction::exit(),
        BpfInstruction::mov64_imm(0, xdp_action::XDP_DROP as i32),
        BpfInstruction::exit(),
    ];

    let load_res = daemon.load_and_verify(
        &admin_cap,
        BpfProgramType::Xdp,
        "default_xdp",
        &default_xdp_prog,
    );
    let mut autotest_ok = false;
    if let Ok(prog_id) = load_res {
        if daemon.attach(&admin_cap, prog_id, "eth0_xdp").is_ok() {
            let test_pkt_pass = [0xAA, 0xBB, 0xCC, 0xDD];
            let test_pkt_drop = [0x42, 0x00, 0x01, 0x02];

            let v_pass = daemon.filter_packet(&admin_cap, "eth0_xdp", &test_pkt_pass, 1000);
            let v_drop = daemon.filter_packet(&admin_cap, "eth0_xdp", &test_pkt_drop, 1001);

            if let (Ok(vp), Ok(vd)) = (v_pass, v_drop) {
                if vp == xdp_action::XDP_PASS && vd == xdp_action::XDP_DROP {
                    if let Ok(stats) = daemon.stats(&admin_cap) {
                        if stats.packets_inspected == 2
                            && stats.packets_passed == 1
                            && stats.packets_dropped == 1
                            && stats.total_cycles > 0
                        {
                            autotest_ok = true;
                        }
                    }
                }
            }
        }
    }

    if autotest_ok {
        println("[BPFD] Auto-test reussi : filtre XDP charge, DAG valide, verdicts XDP_PASS/DROP et cycles valides.");
    } else {
        println("[BPFD] ALERTE : Anomalie detectee lors de l'auto-test eBPF !");
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh et les services
    let mut bpfd_srv_h: u64 = 0;
    let mut bpfd_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut bpfd_srv_h as *mut u64 as u64,
            &mut bpfd_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if bpfd_srv_h != 0 {
        bpfd_srv_h
    } else {
        13 // Endpoint standard PID 13
    });
    println("[BPFD] Canal IPC eBPF operationnel (endpoint PID 13 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<BpfRequest>() {
            if let Some(req) = BpfRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = daemon.handle_ipc_request(&req);
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

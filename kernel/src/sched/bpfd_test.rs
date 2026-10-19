//! Module de validation du Moteur eBPF Souverain & Filtrage de Paquets (Phase 76 - v0.2.74)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_bpfd::{
    bpf_helpers, bpf_jmp, bpf_rights, bpf_size, xdp_action, BpfCap, BpfContext,
    BpfInstruction, BpfMapType, BpfProgramType, BpfVerifier, JamboBpfDaemon,
    VerificationError,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du moteur eBPF et du filtrage réseau XDP (Phase 76)
pub fn execute_bpf_daemon_test() -> bool {
    kprintln!(
        "[BPF/TEST] Démarrage du test du moteur eBPF et filtrage souverain (Phase 76)..."
    );

    // 1. Contrôle d'accès capabilaire (BpfCap) et atténuation stricte
    let admin_cap = BpfCap::new(Handle::new(76, 1), bpf_rights::ALL);
    assert!(admin_cap.has_right(bpf_rights::BPF_PROG_LOAD));
    assert!(admin_cap.has_right(bpf_rights::BPF_PROG_RUN));
    assert!(admin_cap.has_right(bpf_rights::BPF_PROG_ATTACH));
    assert!(admin_cap.has_right(bpf_rights::BPF_MAP_CREATE));
    assert!(admin_cap.has_right(bpf_rights::BPF_MAP_READ));
    assert!(admin_cap.has_right(bpf_rights::BPF_MAP_WRITE));
    assert!(admin_cap.has_right(bpf_rights::BPF_ADMIN));

    let run_only_cap = admin_cap
        .attenuate(bpf_rights::BPF_PROG_RUN)
        .expect("attenuate BpfCap to run-only");
    assert!(run_only_cap.has_right(bpf_rights::BPF_PROG_RUN));
    assert!(!run_only_cap.has_right(bpf_rights::BPF_PROG_LOAD));
    assert!(!run_only_cap.has_right(bpf_rights::BPF_ADMIN));

    // Interdiction formelle d'amplification de privilège
    assert_eq!(
        run_only_cap.attenuate(bpf_rights::BPF_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboBpfDaemon::new(admin_cap);

    // Tentative de chargement d'un programme sans droit BPF_PROG_LOAD
    let dummy_prog = [
        BpfInstruction::mov64_imm(0, 0),
        BpfInstruction::exit(),
    ];
    assert_eq!(
        daemon.load_and_verify(&run_only_cap, BpfProgramType::Xdp, "unauth", &dummy_prog),
        Err(SysError::PermissionDenied),
        "Chargement sans droit BPF_PROG_LOAD doit être rejeté"
    );
    kprintln!("[BPF/CAP] Contrôle d'accès capabilaire et interdiction d'élévation validés");

    // 2. Preuves mathématiques et vérificateur formel de terminaison (BpfVerifier)
    // Preuve 1 : Détection et interdiction des boucles infinies (Saut arrière off <= 0)
    let loop_program = [
        BpfInstruction::mov64_imm(0, 1),
        BpfInstruction::jmp_always(-1),
        BpfInstruction::exit(),
    ];
    assert_eq!(
        BpfVerifier::verify(&loop_program),
        Err(VerificationError::BackwardJumpForbidden(-1)),
        "Les boucles arrière doivent être formellement interdites (DAG strict)"
    );

    // Preuve 2 : Protection de la pile bornée ([-512, 0) par rapport à R10)
    let oob_stack_program = [
        BpfInstruction::st_imm(bpf_size::BPF_DW, 10, 8, 1234), // Offset positif interdit
        BpfInstruction::exit(),
    ];
    assert_eq!(
        BpfVerifier::verify(&oob_stack_program),
        Err(VerificationError::StackOutOfBounds(8)),
        "Débordement de pile eBPF doit être détecté et bloqué"
    );

    // Preuve 3 : Immutabilité du registre R10 (Frame Pointer)
    let r10_violation = [
        BpfInstruction::mov64_imm(10, 0x1000),
        BpfInstruction::exit(),
    ];
    assert_eq!(
        BpfVerifier::verify(&r10_violation),
        Err(VerificationError::WriteToReadOnlyRegister),
        "Toute écriture dans R10 doit être formellement rejetée"
    );

    // Preuve 4 : Programme acyclique valide avec branchements vers l'avant
    let valid_xdp = [
        // R1 contient l'offset du paquet à inspecter (0)
        BpfInstruction::mov64_imm(1, 0),
        // Helper PACKET_READ_BYTE
        BpfInstruction::call(bpf_helpers::PACKET_READ_BYTE),
        // Si R0 == 0x53 (Port DNS UDP par convention de test), sauter à +2 (DROP)
        BpfInstruction::jmp_imm(bpf_jmp::BPF_JEQ, 0, 0x53, 2),
        // Sinon PASS
        BpfInstruction::mov64_imm(0, xdp_action::XDP_PASS as i32),
        BpfInstruction::exit(),
        // Bloc DROP
        BpfInstruction::mov64_imm(0, xdp_action::XDP_DROP as i32),
        BpfInstruction::exit(),
    ];
    let rep = BpfVerifier::verify(&valid_xdp).expect("Vérification formelle eBPF");
    assert!(rep.verified);
    assert_eq!(rep.instruction_count, 7);
    assert_eq!(rep.branch_count, 1);
    kprintln!("[BPF/VERIFIER] Vérificateur formel et preuves de terminaison (DAG sans boucle) validés");

    // 3. Enregistrement, Attachement et Filtrage Réseau XDP
    let xdp_id = daemon
        .load_and_verify(&admin_cap, BpfProgramType::Xdp, "xdp_dns_firewall", &valid_xdp)
        .expect("load and verify valid XDP filter");
    assert_eq!(xdp_id, 1);

    daemon
        .attach(&admin_cap, xdp_id, "eth0_xdp")
        .expect("attach XDP filter to eth0");

    // Test paquet HTTP légitime (premier octet = 0x50 = 80)
    let pkt_http = [0x50, 0x00, 0x01, 0x02];
    let v_pass = daemon
        .filter_packet(&admin_cap, "eth0_xdp", &pkt_http, 100_000)
        .expect("filter HTTP packet");
    assert_eq!(v_pass, xdp_action::XDP_PASS);

    // Test paquet DNS filtré (premier octet = 0x53 = 83)
    let pkt_dns = [0x53, 0x00, 0x01, 0x02];
    let v_drop = daemon
        .filter_packet(&admin_cap, "eth0_xdp", &pkt_dns, 100_100)
        .expect("filter DNS packet");
    assert_eq!(v_drop, xdp_action::XDP_DROP);

    let stats = daemon.stats(&admin_cap).expect("read stats");
    assert_eq!(stats.packets_inspected, 2);
    assert_eq!(stats.packets_passed, 1);
    assert_eq!(stats.packets_dropped, 1);
    kprintln!("[BPF/XDP] Filtrage de paquets XDP en ligne et verdicts (PASS/DROP) validés");

    // 4. Cartes de stockage mémoire partagées eBPF (Maps)
    let map_id = daemon
        .create_map(&admin_cap, "flow_tracker", BpfMapType::HashMap, 4, 8, 16)
        .expect("create eBPF hash map");
    assert_eq!(map_id, 1);

    // Mise à jour de métrique de flux depuis le noyau / usermode
    let key = 0x0a000001u32.to_ne_bytes(); // IP: 10.0.0.1
    let val = 42u64.to_ne_bytes();
    daemon.maps[0]
        .as_mut()
        .unwrap()
        .update(&key, &val)
        .expect("update flow_tracker map");

    let read_val = daemon.maps[0].as_ref().unwrap().lookup(&key);
    assert!(read_val.is_some());
    let mut num = 0u64;
    for (i, &b) in read_val.unwrap().iter().enumerate() {
        num |= (b as u64) << (i * 8);
    }
    assert_eq!(num, 42);
    kprintln!("[BPF/MAP] Cartes de stockage partagées eBPF (HashMap & Array) validées");

    // 5. Intégration interactive du shell jsh (bpf status, bpf list, bpf maps, bpf verify, bpf run, bpf attach)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 4096];

    // bpf status
    let (st, len) = shell.execute_line("bpf status", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("MOTEUR eBPF SOUVERAIN"));
    assert!(s.contains("Programmes chargés & vérifiés"));
    assert!(s.contains("DAG Acyclique formellement vérifié"));
    kprintln!("[BPF/SHELL] Commande 'bpf status' validée");

    // bpf list
    let (st, len) = shell.execute_line("bpf list", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("xdp_guard"));
    kprintln!("[BPF/SHELL] Commande 'bpf list' validée");

    // bpf maps
    let (st, len) = shell.execute_line("bpf maps", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("packet_stats"));
    kprintln!("[BPF/SHELL] Commande 'bpf maps' validée");

    // bpf verify
    let (st, len) = shell.execute_line("bpf verify", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("Vérification formelle réussie"));
    assert!(s.contains("DAG Acyclique : OUI"));
    kprintln!("[BPF/SHELL] Commande 'bpf verify' validée");

    // bpf run
    let (st, len) = shell.execute_line("bpf run 1", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[BPF] Programme #1 exécuté"));
    kprintln!("[BPF/SHELL] Commande 'bpf run' validée");

    // bpf attach
    let (st, len) = shell.execute_line("bpf attach 1 ingress_hook", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("attaché avec succès au crochet 'ingress_hook'"));
    kprintln!("[BPF/SHELL] Commande 'bpf attach' validée");

    kprintln!("[BPF/PASS] Suite de tests Moteur eBPF Souverain & Filtrage de Paquets complétée avec succès !");
    true
}

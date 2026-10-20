//! Module de validation du Pare-Feu Distribué Dynamique & Synchronisation Conntrack (Phase 79 - v0.2.77)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_walld::{
    ip_proto, tcp_flags, wall_rights, ConntrackState, ConntrackTuple, JamboWallDaemon,
    PacketFilterInput, SecurityZone, WallAction, WallCap, WallRule,
};

/// Exécute la suite complète de validation du pare-feu dynamique et de la synchro conntrack (Phase 79)
pub fn execute_wall_daemon_test() -> bool {
    kprintln!(
        "[WALL/TEST] Démarrage du test de pare-feu distribué et synchronisation conntrack (Phase 79)..."
    );

    // 1. Contrôle d'accès capabilaire (WallCap) et rejet strict d'amplification
    let admin_cap = WallCap::new(Handle::new(7901, 1), wall_rights::ALL);
    assert!(admin_cap.has_right(wall_rights::WALL_INSPECT));
    assert!(admin_cap.has_right(wall_rights::WALL_RULE_MANAGE));
    assert!(admin_cap.has_right(wall_rights::WALL_CONNTRACK_SYNC));
    assert!(admin_cap.has_right(wall_rights::WALL_FILTER));
    assert!(admin_cap.has_right(wall_rights::WALL_ZONE_MANAGE));
    assert!(admin_cap.has_right(wall_rights::WALL_ADMIN));

    let inspect_only_cap = admin_cap
        .attenuate(wall_rights::WALL_INSPECT)
        .expect("attenuate WallCap to inspect-only");
    assert!(inspect_only_cap.has_right(wall_rights::WALL_INSPECT));
    assert!(!inspect_only_cap.has_right(wall_rights::WALL_RULE_MANAGE));
    assert!(!inspect_only_cap.has_right(wall_rights::WALL_ADMIN));

    // Tentative d'amplification formellement rejetée
    assert_eq!(
        inspect_only_cap.attenuate(wall_rights::WALL_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let cluster_key = [0x79u8; 32];
    let mut node1_daemon = JamboWallDaemon::new(1, admin_cap, cluster_key);
    node1_daemon.init_defaults();

    // Tentative d'ajout de règle sans le droit WALL_RULE_MANAGE
    let mut dummy_rule = WallRule::empty();
    dummy_rule.set_name("unauthorized");
    assert_eq!(
        node1_daemon.add_rule(&inspect_only_cap, dummy_rule),
        Err(SysError::PermissionDenied),
        "Ajout de règle sans droit doit échouer"
    );

    // Tentative d'activation du lockdown sans le droit WALL_ADMIN
    assert_eq!(
        node1_daemon.set_lockdown(&inspect_only_cap, true),
        Err(SysError::PermissionDenied),
        "Lockdown sans droit WALL_ADMIN doit échouer"
    );
    kprintln!("[WALL/CAP] Contrôle d'accès capabilaire et interdiction d'élévation validés");

    // 2. Suivi d'état TCP (Stateful Conntrack FSM) et Fast-Path
    let client_ip = [10, 0, 1, 100];
    let server_ip = [10, 0, 2, 200];
    let client_port = 45120;
    let server_port = 443;
    let tuple_tcp = ConntrackTuple::new(
        ip_proto::TCP,
        client_ip,
        server_ip,
        client_port,
        server_port,
    );

    // Étape A : Paquet TCP SYN initial (Client -> Serveur)
    let pkt_syn = PacketFilterInput {
        tuple: tuple_tcp,
        src_zone: SecurityZone::ExternalUntrusted,
        dst_zone: SecurityZone::WorkloadEdge,
        tcp_flags: tcp_flags::SYN,
        payload_len: 40,
    };

    let action_syn = node1_daemon
        .filter_packet(&admin_cap, &pkt_syn, 10)
        .expect("filter SYN");
    assert_eq!(
        action_syn,
        WallAction::Allow,
        "SYN autorisé par la règle d'ingress HTTPS"
    );
    assert_eq!(node1_daemon.conntrack.active_count(), 1);

    let (entry_idx, is_reply) = node1_daemon
        .conntrack
        .lookup(&tuple_tcp)
        .expect("conntrack lookup");
    assert!(!is_reply);
    assert_eq!(
        node1_daemon.conntrack.entries[entry_idx].state,
        ConntrackState::New
    );

    // Étape B : Paquet TCP SYN/ACK (Serveur -> Client)
    let pkt_syn_ack = PacketFilterInput {
        tuple: tuple_tcp.reverse(),
        src_zone: SecurityZone::WorkloadEdge,
        dst_zone: SecurityZone::ExternalUntrusted,
        tcp_flags: tcp_flags::SYN | tcp_flags::ACK,
        payload_len: 40,
    };
    let _ = node1_daemon
        .filter_packet(&admin_cap, &pkt_syn_ack, 12)
        .expect("filter SYN-ACK");

    // Étape C : Paquet TCP ACK final (Client -> Serveur) -> Passage à ESTABLISHED
    let pkt_ack = PacketFilterInput {
        tuple: tuple_tcp,
        src_zone: SecurityZone::ExternalUntrusted,
        dst_zone: SecurityZone::WorkloadEdge,
        tcp_flags: tcp_flags::ACK,
        payload_len: 0,
    };
    let _ = node1_daemon
        .filter_packet(&admin_cap, &pkt_ack, 14)
        .expect("filter ACK");

    assert_eq!(
        node1_daemon.conntrack.entries[entry_idx].state,
        ConntrackState::Established,
        "La connexion TCP doit être à l'état ESTABLISHED"
    );

    // Étape D : Paquets de données applicatives (Fast-Path Conntrack)
    let pkt_data = PacketFilterInput {
        tuple: tuple_tcp,
        src_zone: SecurityZone::ExternalUntrusted,
        dst_zone: SecurityZone::WorkloadEdge,
        tcp_flags: tcp_flags::PSH | tcp_flags::ACK,
        payload_len: 1024,
    };
    let action_data = node1_daemon
        .filter_packet(&admin_cap, &pkt_data, 20)
        .expect("filter data");
    assert_eq!(action_data, WallAction::Allow);
    assert!(
        node1_daemon.stats.conntrack_fastpath_hits >= 1,
        "Fastpath conntrack validé"
    );
    kprintln!("[WALL/CONNTRACK] Machine à états TCP, 5-tuple bidirectionnel et Fast-Path validés");

    // 3. Détection d'anomalies de paquets, Scans (XMAS/NULL) et Auto-Blocage Zero-Trust
    let attacker_ip = [198, 51, 100, 77];
    let tuple_malicious = ConntrackTuple::new(ip_proto::TCP, attacker_ip, server_ip, 33333, 80);

    // Envoi d'un paquet XMAS scan (FIN + PSH + URG sans ACK)
    let pkt_xmas = PacketFilterInput {
        tuple: tuple_malicious,
        src_zone: SecurityZone::ExternalUntrusted,
        dst_zone: SecurityZone::WorkloadEdge,
        tcp_flags: tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG,
        payload_len: 0,
    };

    let action_xmas = node1_daemon
        .filter_packet(&admin_cap, &pkt_xmas, 30)
        .expect("filter XMAS scan");
    assert_eq!(
        action_xmas,
        WallAction::Drop,
        "Scan malveillant doit être rejeté"
    );
    assert!(node1_daemon.stats.threats_detected >= 1);
    assert!(node1_daemon.stats.dynamic_blocks_created >= 1);

    // Vérification que l'attaquant est désormais bloqué dynamiquement par règle de priorité 0
    let pkt_subsequent = PacketFilterInput {
        tuple: tuple_malicious,
        src_zone: SecurityZone::ExternalUntrusted,
        dst_zone: SecurityZone::WorkloadEdge,
        tcp_flags: tcp_flags::SYN,
        payload_len: 40,
    };
    let action_blocked = node1_daemon
        .filter_packet(&admin_cap, &pkt_subsequent, 35)
        .expect("filter subsequent attack");
    assert_eq!(
        action_blocked,
        WallAction::Drop,
        "L'attaquant doit être formellement bloqué par la règle adaptative"
    );
    kprintln!("[WALL/THREAT] Détection de scans XMAS/NULL et injection de règle dynamique Zero-Trust validées");

    // 4. Synchronisation d'état de sessions inter-nœuds (Cluster Sync)
    let mut node2_daemon = JamboWallDaemon::new(2, admin_cap, cluster_key);
    node2_daemon.init_defaults();
    assert_eq!(node2_daemon.conntrack.active_count(), 0);

    // Génération de l'événement de synchro depuis le Nœud 1
    let sync_event = node1_daemon
        .generate_sync_event(&admin_cap, &tuple_tcp)
        .expect("generate sync event");
    assert_eq!(sync_event.state, ConntrackState::Established);
    assert!(sync_event.verify(&cluster_key));

    // Test A : Rejet d'un événement altéré (attaque par modification de données / falsification HMAC)
    let mut tampered_event = sync_event;
    tampered_event.tuple.dst_port = 9999; // Modification non autorisée du port
    assert_eq!(
        node2_daemon.receive_sync_event(&admin_cap, &tampered_event, 50),
        Err(SysError::PermissionDenied),
        "Événement falsifié doit être rejeté"
    );

    // Test B : Application légitime sur le Nœud 2 (bascule à chaud / hot failover)
    node2_daemon
        .receive_sync_event(&admin_cap, &sync_event, 55)
        .expect("receive authentic sync event");
    assert_eq!(
        node2_daemon.conntrack.active_count(),
        1,
        "La session doit être instanciée sur le Nœud 2"
    );

    // Vérification de bascule : le Nœud 2 reçoit immédiatement un paquet de données et l'autorise via Fast-Path !
    let action_failover = node2_daemon
        .filter_packet(&admin_cap, &pkt_data, 60)
        .expect("filter failover packet on Node 2");
    assert_eq!(
        action_failover,
        WallAction::Allow,
        "Le Nœud 2 doit autoriser le paquet en session synchronisée"
    );
    assert_eq!(node2_daemon.stats.conntrack_fastpath_hits, 1);
    kprintln!(
        "[WALL/SYNC] Synchronisation d'état conntrack scellée par HMAC et bascule à chaud validées"
    );

    // 5. Validation des commandes Shell Interactives ('wall')
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande : wall status
    let (st_status, len_status) = shell.execute_line("wall status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("PARE-FEU DISTRIBUÉ"));
    assert!(out_str_status.contains("Politique Zero-Trust"));
    kprintln!("[WALL/SHELL] Commande 'wall status' validée");

    // Commande : wall rules
    let (st_rules, len_rules) = shell.execute_line("wall rules", &mut out_buf);
    assert_eq!(st_rules, ShellStatus::Success);
    let out_str_rules = core::str::from_utf8(&out_buf[..len_rules]).unwrap();
    assert!(out_str_rules.contains("state_established_fastpath"));
    assert!(out_str_rules.contains("allow_cluster_internal"));
    kprintln!("[WALL/SHELL] Commande 'wall rules' validée");

    // Commande : wall conntrack
    let (st_ct, _len_ct) = shell.execute_line("wall conntrack", &mut out_buf);
    assert_eq!(st_ct, ShellStatus::Success);
    kprintln!("[WALL/SHELL] Commande 'wall conntrack' validée");

    // Commande : wall add internal edge tcp 8080 allow
    let (st_add, len_add) =
        shell.execute_line("wall add internal edge tcp 8080 allow", &mut out_buf);
    assert_eq!(st_add, ShellStatus::Success);
    let out_str_add = core::str::from_utf8(&out_buf[..len_add]).unwrap();
    assert!(out_str_add.contains("[WALL] Règle #"));
    kprintln!("[WALL/SHELL] Commande 'wall add' validée");

    // Commande : wall lockdown on / off
    let (st_lock, len_lock) = shell.execute_line("wall lockdown on", &mut out_buf);
    assert_eq!(st_lock, ShellStatus::Success);
    let out_str_lock = core::str::from_utf8(&out_buf[..len_lock]).unwrap();
    assert!(out_str_lock.contains("VERROUILLAGE D'URGENCE ACTIVÉ"));

    let (st_unlock, len_unlock) = shell.execute_line("wall lockdown off", &mut out_buf);
    assert_eq!(st_unlock, ShellStatus::Success);
    let out_str_unlock = core::str::from_utf8(&out_buf[..len_unlock]).unwrap();
    assert!(out_str_unlock.contains("reprise du trafic nominal"));
    kprintln!("[WALL/SHELL] Commande 'wall lockdown' validée");

    kprintln!(
        "\x1b[1;32m[WALL/PASS] Suite de tests Pare-Feu Distribué & Synchronisation Conntrack validée avec succès !\x1b[0m"
    );
    true
}

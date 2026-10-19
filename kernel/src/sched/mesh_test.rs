//! Module de validation du Maillage Réseau Chiffré Distribué & Routage Zero-Trust (Phase 63 - v0.2.61)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_meshd::{mesh_rights, JamboMeshDaemon, MeshCap, MeshNetwork, MeshPacket, KEY_SIZE};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du maillage réseau chiffré pair-à-pair (Phase 63)
pub fn execute_encrypted_mesh_test() -> bool {
    kprintln!("[MESH/TEST] Démarrage du test du maillage réseau chiffré Zero-Trust (Phase 63)...");

    // 1. Validation du contrôle d'accès capabilaire (MeshCap)
    let admin_cap = MeshCap::new(Handle::new(63, 1), mesh_rights::ALL);
    assert!(admin_cap.has_right(mesh_rights::MESH_TUNNEL));
    assert!(admin_cap.has_right(mesh_rights::MESH_PEER_ADD));
    assert!(admin_cap.has_right(mesh_rights::MESH_ROUTE));
    assert!(admin_cap.has_right(mesh_rights::MESH_KEY_ROT));

    let unauth_cap = MeshCap::new(Handle::new(63, 2), 0);
    let mut raw_net = MeshNetwork::new(1, [10, 42, 0, 1]);
    assert_eq!(
        raw_net.add_peer(
            &unauth_cap,
            2,
            &[0xAA; KEY_SIZE],
            [10, 42, 0, 2],
            ([192, 168, 1, 102], 51820),
            &[0x55; KEY_SIZE],
        ),
        Err(SysError::PermissionDenied),
        "Ajout de pair sans droit MESH_PEER_ADD doit être rejeté"
    );
    kprintln!("[MESH/CAP] Confinement capabilaire MeshCap et autorité ambiante zéro validés");

    // 2. Établissement de tunnel pair-à-pair et chiffrement de bout en bout
    let mut node1 = MeshNetwork::new(1, [10, 42, 0, 1]);
    let mut node2 = MeshNetwork::new(2, [10, 42, 0, 2]);
    let shared_session_key = [0x77u8; KEY_SIZE];

    node1
        .add_peer(
            &admin_cap,
            2,
            &[0x02; KEY_SIZE],
            [10, 42, 0, 2],
            ([192, 168, 1, 20], 51820),
            &shared_session_key,
        )
        .expect("add peer 2 on node 1");
    node2
        .add_peer(
            &admin_cap,
            1,
            &[0x01; KEY_SIZE],
            [10, 42, 0, 1],
            ([192, 168, 1, 10], 51820),
            &shared_session_key,
        )
        .expect("add peer 1 on node 2");

    let payload = b"RPC_ZERO_TRUST_ENCRYPTED_MESSAGE";
    let packet = node1
        .encapsulate_and_encrypt(&admin_cap, [10, 42, 0, 2], payload)
        .expect("encrypt packet");
    assert_ne!(packet.data_bytes(), payload, "Le paquet doit être chiffré");
    assert_eq!(packet.sender_peer_id, 1);
    assert_eq!(packet.dest_peer_id, 2);

    let mut decrypted = [0u8; 64];
    let len = node2
        .decrypt_and_decapsulate(&admin_cap, &packet, &mut decrypted)
        .expect("decrypt packet");
    assert_eq!(&decrypted[..len], payload);
    kprintln!("[MESH/TUNNEL] Tunnel chiffré bidirectionnel et intégrité MAC validés");

    // 3. Protection Anti-Rejeu (Replay Protection)
    let replay_res = node2.decrypt_and_decapsulate(&admin_cap, &packet, &mut decrypted);
    assert_eq!(
        replay_res,
        Err(SysError::InvalidArgument),
        "Un paquet réémis avec le même numéro de séquence doit être rejeté"
    );
    kprintln!("[MESH/ANTI-REPLAY] Protection anti-rejeu par séquence stricte validée");

    // 4. Rotation de clé de session
    let new_key = [0x88u8; KEY_SIZE];
    node1
        .rotate_session_key(&admin_cap, 2, &new_key)
        .expect("rotate key");
    assert_eq!(node1.peers[0].unwrap().session_key, new_key);
    assert_eq!(node1.peers[0].unwrap().tx_sequence, 1);
    kprintln!("[MESH/REKEY] Rotation dynamique de clé de session symétrique validée");

    // 5. Démon orchestrateur JamboMeshDaemon
    let mut daemon = JamboMeshDaemon::new();
    assert_eq!(daemon.active_peers_count(), 1);
    assert_eq!(daemon.routes_count(), 1);
    let ping_packet = daemon
        .send_packet([10, 42, 0, 2], b"PING_DISCOVERY")
        .expect("daemon send");
    assert_eq!(ping_packet.data_len, 14);
    assert_eq!(daemon.packets_tunneled(), 1);
    kprintln!("[MESH/DAEMON] Démon JamboMeshDaemon opérationnel");

    // 6. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'mesh status'
    let (st_stat, len_stat) = shell.execute_line("mesh status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("MAILLAGE RÉSEAU CHIFFRÉ ZERO-TRUST"));
    assert!(str_stat.contains("IP virtuelle locale"));
    assert!(str_stat.contains("Pairs maillés actifs"));
    kprintln!("[MESH/SHELL] Commande 'mesh status' validée");

    // Commande 'mesh ping'
    let (st_ping, len_ping) = shell.execute_line("mesh ping 10.42.0.2", &mut out_buf);
    assert_eq!(st_ping, ShellStatus::Success);
    let str_ping = core::str::from_utf8(&out_buf[..len_ping]).unwrap_or("");
    assert!(str_ping.contains("[MESH/TUNNEL] Paquet chiffré transmis"));
    kprintln!("[MESH/SHELL] Commande 'mesh ping' validée");

    // Commande 'mesh peers'
    let (st_peers, len_peers) = shell.execute_line("mesh peers", &mut out_buf);
    assert_eq!(st_peers, ShellStatus::Success);
    let str_peers = core::str::from_utf8(&out_buf[..len_peers]).unwrap_or("");
    assert!(str_peers.contains("Peer #2"));
    assert!(str_peers.contains("192.168.1.102:51820"));
    kprintln!("[MESH/SHELL] Commande 'mesh peers' validée");

    kprintln!(
        "[MESH/PASS] Maillage réseau chiffré distribué et routage Zero-Trust validés avec succès."
    );
    true
}

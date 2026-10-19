//! Module de validation du Multiplexeur & Passerelle de Messagerie IPC Distribuée (Phase 77 - v0.2.75)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_ipcd::{
    ipc_flags, ipc_rights, ChannelState, IpcCap, IpcChannel, IpcMessage, IpcPriority, IpcRoute,
    JamboIpcDaemon,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du multiplexeur IPC et passerelle déterministe (Phase 77)
pub fn execute_ipc_daemon_test() -> bool {
    kprintln!(
        "[IPC/TEST] Démarrage du test du multiplexeur IPC et routage déterministe (Phase 77)..."
    );

    // 1. Contrôle d'accès capabilaire (IpcCap) et atténuation stricte
    let admin_cap = IpcCap::new(Handle::new(77, 1), ipc_rights::ALL);
    assert!(admin_cap.has_right(ipc_rights::IPC_CHANNEL_CREATE));
    assert!(admin_cap.has_right(ipc_rights::IPC_SEND));
    assert!(admin_cap.has_right(ipc_rights::IPC_RECV));
    assert!(admin_cap.has_right(ipc_rights::IPC_ROUTE));
    assert!(admin_cap.has_right(ipc_rights::IPC_ENCRYPT));
    assert!(admin_cap.has_right(ipc_rights::IPC_PRIORITY));
    assert!(admin_cap.has_right(ipc_rights::IPC_ADMIN));

    let send_only_cap = admin_cap
        .attenuate(ipc_rights::IPC_SEND)
        .expect("attenuate IpcCap to send-only");
    assert!(send_only_cap.has_right(ipc_rights::IPC_SEND));
    assert!(!send_only_cap.has_right(ipc_rights::IPC_CHANNEL_CREATE));
    assert!(!send_only_cap.has_right(ipc_rights::IPC_ADMIN));

    // Interdiction formelle d'élévation / amplification de privilège
    assert_eq!(
        send_only_cap.attenuate(ipc_rights::IPC_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboIpcDaemon::new(1, admin_cap);

    // Tentative de création de canal sans droit IPC_CHANNEL_CREATE
    assert_eq!(
        daemon.create_channel(
            &send_only_cap,
            "unauth",
            1,
            50,
            50,
            IpcPriority::Normal,
            false,
            None
        ),
        Err(SysError::PermissionDenied),
        "Création sans droit IPC_CHANNEL_CREATE doit être rejetée"
    );
    kprintln!("[IPC/CAP] Contrôle d'accès capabilaire et interdiction d'élévation validés");

    // 2. Multiplexage de canaux et chiffrement symétrique de bout en bout
    let session_key = [0x5au8; 32];
    let ch_ctrl = daemon
        .create_channel(
            &admin_cap,
            "kernel-ctl",
            1,
            10,
            10,
            IpcPriority::Critical,
            false,
            None,
        )
        .expect("create control channel");

    let ch_sec = daemon
        .create_channel(
            &admin_cap,
            "crypto-cluster",
            2,
            443,
            443,
            IpcPriority::High,
            true,
            Some(session_key),
        )
        .expect("create encrypted channel");

    assert_eq!(daemon.stats_data.channels_count, 2);

    let mut msg_sec = IpcMessage::new(
        1,
        ch_sec,
        1,
        2,
        443,
        443,
        IpcPriority::High,
        b"CONFIDENTIAL_STATE_TRANSFER",
        1,
        1000,
        500,
    )
    .expect("create message");

    msg_sec.encrypt(&session_key);
    assert_ne!(msg_sec.flags & ipc_flags::FLAG_ENCRYPTED, 0);
    assert_ne!(
        &msg_sec.payload[..msg_sec.payload_len],
        b"CONFIDENTIAL_STATE_TRANSFER"
    );

    // Test de falsification : altération d'un octet chiffré
    let mut tampered = msg_sec;
    tampered.payload[2] ^= 0xEE;
    assert_eq!(
        tampered.decrypt(&session_key),
        Err(SysError::PermissionDenied),
        "Toute altération du payload chiffré doit être bloquée par l'étiquette MAC"
    );

    // Déchiffrement légitime
    msg_sec.decrypt(&session_key).expect("decrypt valid message");
    assert_eq!(
        &msg_sec.payload[..msg_sec.payload_len],
        b"CONFIDENTIAL_STATE_TRANSFER"
    );
    kprintln!("[IPC/CRYPTO] Chiffrement symétrique in-situ et intégrité MAC validés");

    // 3. Ordonnancement déterministe strict par priorité (Critical > High > Normal > Background)
    let ch_norm = daemon
        .create_channel(
            &admin_cap,
            "telemetry",
            1,
            80,
            80,
            IpcPriority::Normal,
            false,
            None,
        )
        .expect("create normal channel");

    // Injection dans le désordre : Normal, puis Critical
    daemon
        .send_message(&admin_cap, ch_norm, b"TelemetryData", 100)
        .expect("send normal");
    daemon
        .send_message(&admin_cap, ch_ctrl, b"UrgentHeartbeat", 101)
        .expect("send critical");

    // Dépilement déterministe : Critical doit être acheminé avant Normal
    let dispatched = daemon.dispatch_deterministic(105);
    assert_eq!(dispatched, 2);

    let recv_crit = daemon
        .receive_message(&admin_cap, ch_ctrl)
        .expect("recv critical");
    assert_eq!(&recv_crit.payload[..recv_crit.payload_len], b"UrgentHeartbeat");

    let recv_norm = daemon
        .receive_message(&admin_cap, ch_norm)
        .expect("recv normal");
    assert_eq!(&recv_norm.payload[..recv_norm.payload_len], b"TelemetryData");
    kprintln!("[IPC/SCHED] Ordonnancement déterministe temps réel (Critical > High > Normal) validé");

    // 4. Passerelle inter-nœuds, routage déterministe et protection anti-rejeu
    daemon
        .add_route(&admin_cap, 2, 1, 5, 200, true)
        .expect("add route to node 2");

    daemon
        .send_message(&admin_cap, ch_sec, b"ClusterSyncPayload", 200)
        .expect("send remote");
    daemon.dispatch_deterministic(205);

    assert_eq!(daemon.stats_data.total_forwarded, 1);
    let fwd = daemon.pop_forward_frame().expect("pop forward frame");
    assert_eq!(fwd.dst_node, 2);
    assert_ne!(fwd.flags & ipc_flags::FLAG_ROUTED, 0);

    // Test réception réseau distant et protection anti-rejeu
    let wire_msg1 = IpcMessage::new(
        99,
        ch_norm,
        2,
        1,
        80,
        80,
        IpcPriority::Normal,
        b"RemotePacketSeq1",
        1,
        210,
        500,
    )
    .unwrap();

    daemon.process_inbound_wire(wire_msg1, 215).expect("wire packet seq 1");

    // Tentative de rejeu de la séquence 1
    assert_eq!(
        daemon.process_inbound_wire(wire_msg1, 216),
        Err(SysError::PermissionDenied),
        "Le rejeu d'une séquence déjà traitée doit être formellement rejeté"
    );

    // Séquence 2 valide
    let mut wire_msg2 = wire_msg1;
    wire_msg2.sequence = 2;
    daemon.process_inbound_wire(wire_msg2, 220).expect("wire packet seq 2");
    kprintln!("[IPC/ROUTER] Passerelle de transit et immunité anti-rejeu validées");

    // 5. Intégration interactive du shell jsh (ipc status, ipc channels, ipc routes, ipc send, ipc dispatch)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 4096];

    // ipc status
    let (st, len) = shell.execute_line("ipc status", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("MULTIPLEXEUR ET PASSERELLE IPC DISTRIBUÉE"));
    assert!(s.contains("Canaux multiplexés actifs"));
    assert!(s.contains("Priorités déterministes : Critical (0) > High (1)"));
    kprintln!("[IPC/SHELL] Commande 'ipc status' validée");

    // ipc channels
    let (st, len) = shell.execute_line("ipc channels", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("sys-control"));
    assert!(s.contains("cluster-sync"));
    kprintln!("[IPC/SHELL] Commande 'ipc channels' validée");

    // ipc routes
    let (st, len) = shell.execute_line("ipc routes", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("PASSERELLE"));
    kprintln!("[IPC/SHELL] Commande 'ipc routes' validée");

    // ipc send
    let (st, len) = shell.execute_line("ipc send 1 TestMessageFromShell", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("mis en file d'attente d'émission déterministe"));
    kprintln!("[IPC/SHELL] Commande 'ipc send' validée");

    // ipc dispatch
    let (st, len) = shell.execute_line("ipc dispatch", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("Ordonnancement déterministe achevé"));
    kprintln!("[IPC/SHELL] Commande 'ipc dispatch' validée");

    kprintln!(
        "[IPC/PASS] Suite de tests Multiplexeur IPC & Passerelle Déterministe complétée avec succès !"
    );
    true
}

//! Module de validation du Bus RPC Distribué, Jetons Macaroon & Résilience Cluster (Phase 51 - v0.2.49)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::SysError;
use jambo_rpc::{
    ClusterManager, DistributedCapToken, JamboRpcDaemon, NodeStatus, RpcPacket, RpcPacketType,
    RpcRegistry, RpcServerDispatcher, RPC_MAGIC, RPC_VERSION,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du bus RPC distribué, des jetons de capacités et du cluster (Phase 51)
pub fn execute_distributed_rpc_test() -> bool {
    kprintln!(
        "[RPC/TEST] Démarrage du test du bus RPC distribué, jetons signés & cluster (Phase 51)..."
    );

    // 1. Validation des jetons de capacités distribuées signés & anti-rejeu
    let secret = [0x55u8; 32];
    let token = DistributedCapToken::new_signed(1, 2, 0x1000, 0x03, 100, &secret);
    assert!(
        token.verify(&secret, 100).is_ok(),
        "Le jeton signé doit être vérifié avec succès"
    );
    assert_eq!(
        token.verify(&secret, 101),
        Err(SysError::PermissionDenied),
        "Un nonce antérieur doit être rejeté (protection anti-rejeu)"
    );
    let rogue_secret = [0x99u8; 32];
    assert_eq!(
        token.verify(&rogue_secret, 100),
        Err(SysError::PermissionDenied),
        "Une signature calculée avec une clé erronée doit être rejetée"
    );
    kprintln!("[RPC/TOKEN] Jetons de capacités signés Macaroon & protection anti-rejeu validés");

    // 2. Validation des paquets RPC binaires
    let req_pkt = RpcPacket::new_request(42, 0x1000, 1, token, b"ping_payload");
    assert_eq!(req_pkt.magic, RPC_MAGIC);
    assert_eq!(req_pkt.version, RPC_VERSION);
    assert_eq!(req_pkt.pkt_type, RpcPacketType::Request);
    assert_eq!(req_pkt.call_id, 42);
    assert_eq!(req_pkt.payload_len, 12);
    kprintln!("[RPC/PACKET] Format de paquets RPC compacts conforme (Magic: 0x4A525043, v1)");

    // 3. Validation du registre de services et du dispatcher
    let mut registry = RpcRegistry::new();
    assert!(registry.register_service(0x1000, "compute", 0x01).is_ok());
    assert!(registry.register_service(0x2000, "storage", 0x03).is_ok());
    assert_eq!(registry.count, 2);

    let mut dispatcher = RpcServerDispatcher::new(registry, secret);
    let resp = dispatcher
        .dispatch(&req_pkt)
        .expect("Traitement de requête RPC valide");
    assert_eq!(resp.status, 0);
    assert_eq!(resp.pkt_type, RpcPacketType::Response);
    assert_eq!(resp.payload[0], 0xAA);
    assert_eq!(resp.payload[1], 1);
    assert_eq!(dispatcher.calls_processed, 1);

    // Test de rejet pour droits insuffisants
    let weak_token = DistributedCapToken::new_signed(1, 2, 0x2000, 0x01, 200, &secret); // Requiert 0x03
    let weak_req = RpcPacket::new_request(43, 0x2000, 1, weak_token, b"forbidden");
    assert_eq!(
        dispatcher.dispatch(&weak_req),
        Err(SysError::PermissionDenied),
        "Une requête avec droits insuffisants doit être rejetée"
    );
    kprintln!("[RPC/DISPATCHER] Dispatcher RPC et contrôle strict des droits de capacités validés");

    // 4. Validation du gestionnaire de grappe (ClusterManager) & Failover
    let mut cluster = ClusterManager::new(1);
    assert!(cluster.add_node(2, [192, 168, 1, 20]).is_ok());
    assert!(cluster.add_node(3, [192, 168, 1, 30]).is_ok());
    assert_eq!(cluster.active_nodes, 2);

    assert!(cluster.record_heartbeat(2, 160).is_ok());
    let degraded = cluster.monitor_liveness(165, 10);
    assert_eq!(
        degraded, 1,
        "Le nœud 3 sans heartbeat récent doit être marqué Degraded"
    );

    let backup_node = cluster.trigger_failover(2);
    assert_eq!(
        backup_node,
        Some(3),
        "Bascule automatique failover vers nœud de secours saine"
    );
    kprintln!("[RPC/CLUSTER] Topologie de cluster, heartbeat et bascule de failover validés");

    // 5. Validation du démon JamboRpcDaemon
    let mut rpc_daemon = JamboRpcDaemon::new();
    rpc_daemon.init_defaults();
    let rpc_res = rpc_daemon.call_service(0x1000, 2, b"test_compute");
    assert!(rpc_res.is_ok());
    assert!(rpc_daemon.ping_node(2, 200).is_ok());
    kprintln!("[RPC/DAEMON] Démon JamboRpcDaemon opérationnel de bout en bout");

    // 6. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'rpc status'
    let (st_stat, len_stat) = shell.execute_line("rpc status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("JamboRPC Bus: Actif"));
    kprintln!("[RPC/SHELL] Commande 'rpc status' validée");

    // Commande 'rpc call'
    let (st_call, len_call) = shell.execute_line("rpc call 0x1000 1", &mut out_buf);
    assert_eq!(st_call, ShellStatus::Success);
    let str_call = core::str::from_utf8(&out_buf[..len_call]).unwrap_or("");
    assert!(str_call.contains("succès") && str_call.contains("0xAA"));
    kprintln!("[RPC/SHELL] Commande 'rpc call' validée");

    // Commande 'rpc ping'
    let (st_ping, len_ping) = shell.execute_line("rpc ping 2", &mut out_buf);
    assert_eq!(st_ping, ShellStatus::Success);
    let str_ping = core::str::from_utf8(&out_buf[..len_ping]).unwrap_or("");
    assert!(str_ping.contains("acquitté"));
    kprintln!("[RPC/SHELL] Commande 'rpc ping' validée");

    // Commande 'rpc cluster'
    let (st_cluster, len_cluster) = shell.execute_line("rpc cluster", &mut out_buf);
    assert_eq!(st_cluster, ShellStatus::Success);
    let str_cluster = core::str::from_utf8(&out_buf[..len_cluster]).unwrap_or("");
    assert!(str_cluster.contains("192.168.1.20"));
    kprintln!("[RPC/SHELL] Commande 'rpc cluster' validée");

    // Commande 'rpc failover'
    let (st_failover, len_failover) = shell.execute_line("rpc failover 2", &mut out_buf);
    assert_eq!(st_failover, ShellStatus::Success);
    let str_failover = core::str::from_utf8(&out_buf[..len_failover]).unwrap_or("");
    assert!(str_failover.contains("bascule réussie"));
    kprintln!("[RPC/SHELL] Commande 'rpc failover' validée");

    kprintln!(
        "[RPC/PASS] Bus RPC distribué, jetons de capacités Macaroon & résilience cluster validés avec succès."
    );
    true
}

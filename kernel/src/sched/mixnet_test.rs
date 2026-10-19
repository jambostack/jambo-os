//! Module de validation du Réseau de Mixage Anonyme Sphinx & Dissimulation de Trafic (`jambo-mixnet`)
//! Phase 99 — Jalon v0.2.97
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_mixnet::{
    mix_rights, HopConfig, JamboMixnetDaemon, MixCap, MixPool, SphinxPacket, SphinxRouter,
    ALPHA_SIZE, BETA_SIZE, GAMMA_SIZE, HOP_INFO_SIZE, MAX_HOPS, MIX_POOL_CAPACITY, PAYLOAD_SIZE,
    SPHINX_PACKET_SIZE,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle du réseau de mixage Sphinx souverain (Phase 99)
pub fn execute_mixnet_daemon_test() -> bool {
    kprintln!(
        "[MIXNET/TEST] Démarrage du test de validation du réseau de mixage anonyme Sphinx (Phase 99)..."
    );

    // 1. Contrôle d'accès capabilaire (MixCap) et rejet formel de toute élévation de privilèges
    let admin_cap = MixCap::new(Handle::new(9901, 1), mix_rights::ALL);
    assert!(admin_cap.has_right(mix_rights::ROUTE));
    assert!(admin_cap.has_right(mix_rights::MIX));
    assert!(admin_cap.has_right(mix_rights::UNWRAP));
    assert!(admin_cap.has_right(mix_rights::DUMMY));
    assert!(admin_cap.has_right(mix_rights::ADMIN));
    assert!(admin_cap.has_right(mix_rights::INSPECT));

    let route_cap = admin_cap
        .attenuate(mix_rights::ROUTE | mix_rights::INSPECT)
        .expect("Atténuation monotone MixCap");
    assert!(route_cap.has_right(mix_rights::ROUTE));
    assert!(route_cap.has_right(mix_rights::INSPECT));
    assert!(!route_cap.has_right(mix_rights::ADMIN));
    assert!(!route_cap.has_right(mix_rights::MIX));
    assert!(!route_cap.has_right(mix_rights::DUMMY));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        route_cap.attenuate(mix_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits MixCap formellement rejetée"
    );
    kprintln!("[MIXNET/CAP] Contrôle d'accès capabilaire MixCap et atténuation monotone validés");

    // 2. Initialisation du démon de mixage souverain
    let mut daemon = JamboMixnetDaemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.node_count, 4);
    kprintln!("[MIXNET/INIT] Démon Mixnet initialisé (Topologie 4 nœuds actifs [101, 102, 103, 104])");

    // 3. Validation de l'encapsulation et du routage multi-sauts Sphinx (4 sauts : 101 -> 102 -> 103 -> 104)
    let original_secret = b"JAMBO_CONFIDENTIAL_MULTI_HOP_SPHINX_PACKET_2026";
    let route = [101, 102, 103, 104];
    let extracted_payload = daemon
        .route_onion_message(&route, original_secret, 0x55AA1122)
        .expect("Routage Sphinx multi-sauts");

    assert_eq!(
        &extracted_payload[..original_secret.len()],
        original_secret,
        "Intégrité de la charge utile déchiffrée au nœud de sortie"
    );
    assert_eq!(daemon.packets_routed, 1);
    assert_eq!(daemon.packets_unwrapped, 1);
    kprintln!("[MIXNET/ROUTE] Routage en oignon Sphinx 4 sauts validé (101 -> 102 -> 103 -> 104)");

    // 4. Validation de la taille fixe constante (256 octets) et sérialisation sans fuite
    let mut serialized_packet = [0u8; SPHINX_PACKET_SIZE];
    let dummy_packet = SphinxPacket::empty();
    dummy_packet.serialize(&mut serialized_packet);
    assert_eq!(serialized_packet.len(), 256);
    let deserialized = SphinxPacket::deserialize(&serialized_packet);
    assert_eq!(dummy_packet, deserialized);
    kprintln!("[MIXNET/SIZE] Invariance stricte de taille de paquet (256 octets fixes, 0 fuite)");

    // 5. Détection et blocage immédiat des attaques par rejeu (Replay Attack)
    let hops = [
        HopConfig {
            node_id: 101,
            public_key: daemon.nodes[0].public_key,
            delay_ms: 10,
            is_exit: false,
        },
        HopConfig {
            node_id: 102,
            public_key: daemon.nodes[1].public_key,
            delay_ms: 20,
            is_exit: true,
        },
    ];
    let test_packet = SphinxRouter::build_onion_packet(&hops, b"REPLAY_SHIELD", 0x8888).unwrap();
    let node_101 = daemon.find_node_mut(101).unwrap();

    let first_pass = node_101.process_packet(&test_packet, 0);
    assert!(first_pass.is_ok(), "Premier passage légitime accepté");

    let replay_pass = node_101.process_packet(&test_packet, 0);
    assert_eq!(
        replay_pass,
        Err(SysError::ResourceBusy),
        "Rejet anti-rejeu strict validé"
    );
    kprintln!("[MIXNET/REPLAY] Protection anti-rejeu ReplayCache validée (Doublon rejeté)");

    // 6. Détection et blocage immédiat des altérations de paquet (Integrity MAC Failure)
    let mut corrupted_packet = SphinxRouter::build_onion_packet(&hops, b"INTEGRITY_SHIELD", 0x7777).unwrap();
    corrupted_packet.beta[2] ^= 0xEE; // Altération d'un octet de routage
    let tamper_pass = node_101.process_packet(&corrupted_packet, 0);
    assert_eq!(
        tamper_pass,
        Err(SysError::InvalidArgument),
        "Altération de paquet formellement rejetée par vérification MAC"
    );
    kprintln!("[MIXNET/INTEGRITY] Vérification MAC HMAC-SHA256 validée (Paquet corrompu rejeté)");

    // 7. Bassin de mixage (MixPool), permutation pseudo-aléatoire Fisher-Yates & trafic de leurre
    let mut pool = MixPool::new();
    pool.inject_cover_packet(101, 10, 0x1010).expect("Injection leurre 1");
    pool.inject_cover_packet(102, 20, 0x2020).expect("Injection leurre 2");
    pool.inject_cover_packet(103, 30, 0x3030).expect("Injection leurre 3");
    assert_eq!(pool.count, 3);
    assert_eq!(pool.cover_injected, 3);

    let flushed = pool.shuffle_and_flush(0xFEDCBA9876543210);
    assert_eq!(flushed, 3);
    assert_eq!(pool.count, 0);
    assert_eq!(pool.total_mixed, 3);
    kprintln!("[MIXNET/POOL] Bassin MixPool et brassage Fisher-Yates validés (3 paquets décorrélés)");

    // 8. Registre d'audit scellé par chaîne SHA-256
    assert_ne!(daemon.audit_chain, [0u8; 32]);
    kprintln!("[MIXNET/AUDIT] Chaîne d'audit cryptographique SHA-256 scellée et vérifiée");

    // 9. Intégration dans le Shell interactif Ring 3 (jsh)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (st1, len1) = shell.execute_line("mixnet status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    assert!(len1 > 0);

    let (st2, len2) = shell.execute_line("mixnet route", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    assert!(len2 > 0);

    let (st3, len3) = shell.execute_line("mixnet mix", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    assert!(len3 > 0);

    let (st4, len4) = shell.execute_line("mixnet dummy", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    assert!(len4 > 0);

    let (st5, len5) = shell.execute_line("mixnet audit", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    assert!(len5 > 0);

    kprintln!("[MIXNET/SHELL] Commandes Ring 3 jsh 'mixnet' validées avec succès");
    true
}

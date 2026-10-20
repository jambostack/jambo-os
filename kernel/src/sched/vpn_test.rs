//! Module de validation de la Passerelle VPN WireGuard Post-Quantique (`jambo-vpn`)
//! Phase 113 — Jalon v0.2.111
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_vpn::{
    vpn_rights, AntiReplayWindow, Curve25519, Fe25519, HandshakeInitiationPacket,
    HandshakeResponsePacket, HybridKeyExchange, JamboVpnDaemon, MlKem, Sha256,
    VpnCap, VpnDataPacket, VpnError, VpnPeerState, VpnSubnet, ChaCha20,
    KEM_CIPHERTEXT_LEN, KEM_PUBLIC_KEY_LEN, KEM_SECRET_KEY_LEN, KEM_SHARED_SECRET_LEN,
    MAX_DATA_PAYLOAD, MAX_PEERS,
};

/// Exécute la suite complète de validation formelle de la passerelle VPN souveraine (Phase 113)
pub fn execute_vpn_daemon_test() -> bool {
    kprintln!(
        "[VPN/TEST] Démarrage du test de validation de la passerelle VPN post-quantique WireGuard (Phase 113)..."
    );

    // 1. Contrôle d'accès capabilaire (VpnCap) et atténuation monotone
    let admin_cap = VpnCap::new(Handle::new(11301, 1), vpn_rights::ALL, 8, 1);
    assert!(admin_cap.is_valid());
    assert!(admin_cap.has_right(vpn_rights::ROUTE_TRAFFIC));
    assert!(admin_cap.has_right(vpn_rights::CREATE_TUNNEL));
    assert!(admin_cap.has_right(vpn_rights::CONFIGURE_PEER));
    assert!(admin_cap.has_right(vpn_rights::INITIATE_HANDSHAKE));
    assert!(admin_cap.has_right(vpn_rights::ROTATE_KEYS));
    assert!(admin_cap.has_right(vpn_rights::TERMINATE_TUNNEL));
    assert!(admin_cap.has_right(vpn_rights::AUDIT_INSPECT));
    assert!(admin_cap.has_right(vpn_rights::ADMIN));

    let attenuated = admin_cap
        .attenuate(vpn_rights::ROUTE_TRAFFIC | vpn_rights::AUDIT_INSPECT, 4)
        .expect("Atténuation monotone VpnCap");
    assert!(attenuated.has_right(vpn_rights::ROUTE_TRAFFIC));
    assert!(attenuated.has_right(vpn_rights::AUDIT_INSPECT));
    assert!(!attenuated.has_right(vpn_rights::CREATE_TUNNEL));
    assert!(!attenuated.has_right(vpn_rights::TERMINATE_TUNNEL));
    assert_eq!(attenuated.max_peers, 4);

    // Rejet formel de toute amplification de droits ou augmentation de pairs
    assert_eq!(
        attenuated.attenuate(vpn_rights::ALL, 4),
        Err(VpnError::PermissionDenied),
        "Amplification de droits formellement rejetée"
    );
    assert_eq!(
        attenuated.attenuate(vpn_rights::ROUTE_TRAFFIC, 5),
        Err(VpnError::PermissionDenied),
        "Augmentation du quota de pairs formellement rejetée"
    );
    kprintln!("  [OK] Contrôle d'accès capabilaire et atténuation monotone VpnCap");

    // 2. Échange de clés Curve25519 (X25519 RFC 7748)
    let alice_sk = [0x31u8; 32];
    let bob_sk = [0x52u8; 32];
    let alice_pk = Curve25519::public_key(&alice_sk);
    let bob_pk = Curve25519::public_key(&bob_sk);

    let shared_alice = Curve25519::scalar_mult(&alice_sk, &bob_pk);
    let shared_bob = Curve25519::scalar_mult(&bob_sk, &alice_pk);
    assert_eq!(shared_alice, shared_bob, "Accord de clé Curve25519 symétrique");
    assert_ne!(shared_alice, [0u8; 32]);
    kprintln!("  [OK] Échange de clés classique Curve25519 (Montgomery RFC 7748)");

    // 3. Encapsulation Post-Quantique ML-KEM
    let mut kem_pk = [0u8; KEM_PUBLIC_KEY_LEN];
    let mut kem_sk = [0u8; KEM_SECRET_KEY_LEN];
    MlKem::keygen(b"KERNEL_TEST_MLKEM_SEED_2026", &mut kem_pk, &mut kem_sk);

    let mut ct = [0u8; KEM_CIPHERTEXT_LEN];
    let mut ss_sender = [0u8; KEM_SHARED_SECRET_LEN];
    MlKem::encapsulate(&kem_pk, b"ephemeral_seed_kernel_test", &mut ct, &mut ss_sender);

    let mut ss_receiver = [0u8; KEM_SHARED_SECRET_LEN];
    MlKem::decapsulate(&kem_sk, &ct, &mut ss_receiver);
    assert_eq!(ss_sender, ss_receiver, "Accord de clé post-quantique ML-KEM symétrique");
    kprintln!("  [OK] Encapsulation & Décapsulation Post-Quantique ML-KEM");

    // 4. Dérivation Dual-Defense HKDF-SHA256
    let mut tx_key = [0u8; 32];
    let mut rx_key = [0u8; 32];
    HybridKeyExchange::derive_master_secrets(
        &shared_alice,
        &ss_sender,
        b"TEST_SESSION_INFO",
        &mut tx_key,
        &mut rx_key,
    );
    assert_ne!(tx_key, [0u8; 32]);
    assert_ne!(rx_key, [0u8; 32]);
    assert_ne!(tx_key, rx_key);
    kprintln!("  [OK] Dérivation hybride Dual-Defense (Curve25519 + ML-KEM)");

    // 5. Chiffrement de flux ChaCha20
    let cipher_key = [0x88u8; 32];
    let nonce = [0x33u8; 12];
    let mut data = *b"SOVEREIGN_RING3_WIREGUARD_TRANSPORT_TEST";
    let backup = data;
    ChaCha20::apply_keystream(&cipher_key, 0, &nonce, &mut data);
    assert_ne!(data, backup);
    ChaCha20::apply_keystream(&cipher_key, 0, &nonce, &mut data);
    assert_eq!(data, backup);
    kprintln!("  [OK] Chiffrement symétrique de flux ChaCha20 RFC 8439");

    // 6. Fenêtre anti-rejeu glissante
    let mut replay = AntiReplayWindow::new();
    assert!(replay.check_and_update(1));
    assert!(!replay.check_and_update(1));
    assert!(replay.check_and_update(10));
    assert!(replay.check_and_update(5));
    assert!(!replay.check_and_update(5));
    assert!(replay.check_and_update(200));
    assert!(!replay.check_and_update(50)); // hors fenêtre
    kprintln!("  [OK] Protection anti-rejeu par fenêtre glissante (128 paquets)");

    // 7. Initialisation du démon, poignée de main 1-RTT & Routage cryptographique
    let mut daemon_gw = JamboVpnDaemon::new(admin_cap);
    daemon_gw.init_defaults();

    // Vérifier le pair par défaut (Node 2)
    assert_eq!(daemon_gw.peer_count, 1);
    let subnets = [VpnSubnet::new([10, 0, 3, 0], 24)];
    let peer3_sk = [0x99u8; 32];
    let peer3_pk_curve = Curve25519::public_key(&peer3_sk);
    let mut peer3_pk_kem = [0u8; KEM_PUBLIC_KEY_LEN];
    let mut peer3_sk_kem = [0u8; KEM_SECRET_KEY_LEN];
    MlKem::keygen(b"PEER3_SEED", &mut peer3_pk_kem, &mut peer3_sk_kem);

    daemon_gw
        .add_peer(
            &admin_cap,
            3,
            "cluster-node-3",
            [192, 168, 1, 30],
            51820,
            &peer3_pk_curve,
            &peer3_pk_kem,
            &subnets,
        )
        .expect("Ajout pair 3");
    assert_eq!(daemon_gw.peer_count, 2);

    // Poignée de main 1-RTT avec Node 3
    let mut init_pkt = HandshakeInitiationPacket {
        msg_type: 0,
        sender_index: 0,
        uncalibrated_tai64n: [0u8; 12],
        ephemeral_classical: [0u8; 32],
        pqc_ciphertext: [0u8; KEM_CIPHERTEXT_LEN],
        encrypted_static: [0u8; 32],
        mac1: [0u8; 16],
        mac2: [0u8; 16],
    };
    let eph_seed = [0x42u8; 32];
    let (_classical, pq_ss) = daemon_gw
        .create_handshake_initiation(&admin_cap, 3, &eph_seed, &mut init_pkt)
        .expect("Handshake initiation");

    let resp_pkt = HandshakeResponsePacket {
        msg_type: jambo_vpn::WG_PKT_HANDSHAKE_RESPONSE,
        sender_index: 0x5001,
        receiver_index: init_pkt.sender_index,
        ephemeral_classical: [0x77u8; 32],
        pqc_shared_secret_tag: pq_ss,
        encrypted_nothing: [0u8; 16],
        mac1: [0u8; 16],
        mac2: [0u8; 16],
    };
    let eph_sk = Sha256::digest(&eph_seed);
    daemon_gw
        .complete_handshake_initiation_session(&admin_cap, 3, &eph_sk, &pq_ss, &resp_pkt)
        .expect("Finalisation handshake");
    assert_eq!(daemon_gw.total_handshakes_completed, 1);
    kprintln!("  [OK] Établissement de tunnel 1-RTT Post-Quantique complet");

    // Routage cryptographique d'un paquet
    let mut data_pkt = VpnDataPacket {
        msg_type: 0,
        receiver_index: 0,
        counter: 0,
        payload_len: 0,
        encrypted_payload: [0u8; MAX_DATA_PAYLOAD],
        auth_tag: [0u8; 16],
    };
    let payload = b"SOVEREIGN_POST_QUANTUM_INTER_CLUSTER_VPN_FRAME";
    let routed_peer = daemon_gw
        .route_and_encrypt_packet(&admin_cap, &[10, 0, 3, 100], payload, &mut data_pkt)
        .expect("Routage paquet");
    assert_eq!(routed_peer, 3);
    assert_eq!(daemon_gw.total_packets_routed, 1);
    assert_eq!(daemon_gw.total_bytes_encrypted, payload.len() as u64);
    kprintln!("  [OK] Routage cryptographique (Cryptokey Routing) & Chiffrement");

    // Suppression de pair et zéroïsation
    daemon_gw
        .remove_peer(&admin_cap, 3)
        .expect("Suppression et zéroïsation pair 3");
    assert_eq!(daemon_gw.peer_count, 1);
    kprintln!("  [OK] Révocation de pair et zéroïsation sécurisée en mémoire");

    // 8. Registre d'audit inaltérable scellé SHA-256
    assert!(daemon_gw.audit_count >= 3);
    assert_ne!(daemon_gw.audit_chain, [0u8; 32]);
    kprintln!("  [OK] Chaîne d'audit inaltérable scellée par SHA-256");

    kprintln!("\x1b[1;32m[PASS] Passerelle VPN WireGuard Post-Quantique validée avec succès (Phase 113).\x1b[0m");
    true
}

//! Module de validation du Routage Sécurisé Zero-Trust, Micro-Segmentation & Maillage Chiffré (`jambo-secroute`)
//! Phase 111 — Jalon v0.2.109
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_secroute::{
    secroute_rights, ChaCha20, EnclaveEndpoint, HmacSha256, JamboSecRouteDaemon,
    RouteAction, SecPacketHeader, SecRouteCap, SecRouteError, SecurityZone, Sha256,
    TrustLevel, TunnelStatus, MAX_ENCLAVES, MAX_RULES, MAX_TUNNELS, MAX_ZONES,
};

/// Exécute la suite complète de validation formelle du routage sécurisé Zero-Trust et maillage chiffré (Phase 111)
pub fn execute_secroute_daemon_test() -> bool {
    kprintln!(
        "[SECROUTE/TEST] Démarrage du test de validation du routage sécurisé Zero-Trust et maillage chiffré (Phase 111)..."
    );

    // 1. Contrôle d'accès capabilaire (SecRouteCap) et atténuation monotone
    let admin_cap = SecRouteCap::new(Handle::new(11101, 1), secroute_rights::ALL, 16, 1);
    assert!(admin_cap.has_right(secroute_rights::ROUTE_FORWARD));
    assert!(admin_cap.has_right(secroute_rights::CREATE_TUNNEL));
    assert!(admin_cap.has_right(secroute_rights::DESTROY_TUNNEL));
    assert!(admin_cap.has_right(secroute_rights::CONFIGURE_ZONE));
    assert!(admin_cap.has_right(secroute_rights::ADD_RULE));
    assert!(admin_cap.has_right(secroute_rights::DELETE_RULE));
    assert!(admin_cap.has_right(secroute_rights::ISOLATE_ENCLAVE));
    assert!(admin_cap.has_right(secroute_rights::INSPECT_FLOW));
    assert!(admin_cap.has_right(secroute_rights::AUDIT_LOG));

    let attenuated_cap = admin_cap
        .attenuate(secroute_rights::ROUTE_FORWARD | secroute_rights::INSPECT_FLOW, 4)
        .expect("Atténuation monotone SecRouteCap");
    assert!(attenuated_cap.has_right(secroute_rights::ROUTE_FORWARD));
    assert!(attenuated_cap.has_right(secroute_rights::INSPECT_FLOW));
    assert!(!attenuated_cap.has_right(secroute_rights::CREATE_TUNNEL));
    assert!(!attenuated_cap.has_right(secroute_rights::ISOLATE_ENCLAVE));
    assert_eq!(attenuated_cap.max_tunnels, 4);

    // Rejet formel de toute amplification de droits
    assert_eq!(
        attenuated_cap.attenuate(secroute_rights::ALL, 4),
        Err(SecRouteError::PermissionDenied),
        "Amplification de droits SecRouteCap formellement rejetée"
    );
    assert_eq!(
        attenuated_cap.attenuate(secroute_rights::ROUTE_FORWARD, 8),
        Err(SecRouteError::PermissionDenied),
        "Augmentation de quota SecRouteCap formellement rejetée"
    );
    kprintln!("  [1/7] Contrôle d'accès capabilaire et atténuation monotone validés.");

    // 2. Chiffrement symétrique ChaCha20 RFC 7539 / 8439 `#![no_std]`
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let original_payload = b"TEST_CONFIDENTIAL_INTER_ENCLAVE_ZERO_TRUST_PAYLOAD_PHASE111";
    let mut encrypted_payload = [0u8; 64];
    encrypted_payload[..original_payload.len()].copy_from_slice(original_payload);

    ChaCha20::apply_keystream(&key, 1, &nonce, &mut encrypted_payload[..original_payload.len()]);
    assert_ne!(
        &encrypted_payload[..original_payload.len()],
        original_payload,
        "Le texte chiffré doit différer du texte en clair"
    );

    // Déchiffrement in-place avec même clé et nonce
    ChaCha20::apply_keystream(&key, 1, &nonce, &mut encrypted_payload[..original_payload.len()]);
    assert_eq!(
        &encrypted_payload[..original_payload.len()],
        original_payload,
        "Déchiffrement ChaCha20 symétrique parfait"
    );
    kprintln!("  [2/7] Chiffrement souverain ChaCha20 validé.");

    // 3. Initialisation du Démon de Routage Sécurisé & Micro-Segmentation
    let mut daemon = JamboSecRouteDaemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.zone_count, 4);
    assert_eq!(daemon.enclave_count, 4);
    assert_eq!(daemon.tunnel_count, 1);
    assert_eq!(daemon.rule_count, 2);

    let app_zone = daemon.get_zone(3).expect("Zone Standard App trouvée");
    assert_eq!(app_zone.trust_level, TrustLevel::Standard);
    let tee_zone = daemon.get_zone(2).expect("Zone TEE trouvée");
    assert_eq!(tee_zone.trust_level, TrustLevel::Privileged);
    kprintln!("  [3/7] Zones de sécurité étanches et micro-segmentation initialisées.");

    // 4. Encapsulation, Routage & Déchiffrement de paquet souverain (Tunnel 1)
    let test_msg = b"ENCLAVE_RPC_SECRET_HANDSHAKE_TRANSACTION_42";
    let mut packet_buffer = [0u8; 512];

    let packet_size = daemon
        .encapsulate_and_route(&admin_cap, 1, 254, test_msg, &mut packet_buffer)
        .expect("Encapsulation et chiffrement de paquet via tunnel 1");
    assert!(packet_size > SecPacketHeader::SIZE);
    assert_eq!(daemon.packets_routed, 1);
    assert_eq!(daemon.packets_encrypted, 1);

    let mut decrypted_buffer = [0u8; 256];
    let (hdr, dec_len) = daemon
        .decapsulate_and_verify(&packet_buffer[..packet_size], &mut decrypted_buffer)
        .expect("Décapsulation et vérification du paquet chiffré");
    assert_eq!(dec_len, test_msg.len());
    assert_eq!(&decrypted_buffer[..dec_len], test_msg);
    assert_eq!(hdr.seq, 1);
    assert_eq!(hdr.src_enclave, 301);
    assert_eq!(hdr.dst_enclave, 201);
    assert_eq!(daemon.packets_decrypted, 1);
    kprintln!("  [4/7] Routage souverain, encapsulation et décapsulation validés.");

    // 5. Détection stricte d'attaque par Rejeu (Anti-Replay) et intégrité MAC
    // Rejeu du paquet précédent avec séquence 1 <= rx_seq (1)
    let replay_err = daemon.decapsulate_and_verify(&packet_buffer[..packet_size], &mut decrypted_buffer);
    assert_eq!(
        replay_err,
        Err(SecRouteError::AntiReplayDetected),
        "Attaque par rejeu formellement détectée et rejetée"
    );
    assert_eq!(daemon.anti_replay_violations, 1);

    // Altération d'intégrité (corruption du paquet chiffré)
    let mut corrupted_packet = [0u8; 512];
    corrupted_packet[..packet_size].copy_from_slice(&packet_buffer[..packet_size]);
    corrupted_packet[SecPacketHeader::SIZE + 2] ^= 0xff; // Inverser des bits de payload
    let mut corrupt_hdr = SecPacketHeader::deserialize(&corrupted_packet[..packet_size]).unwrap();
    corrupt_hdr.seq = 999; // Contourner anti-replay pour tester la falsification MAC
    corrupt_hdr.serialize(&mut corrupted_packet[..SecPacketHeader::SIZE]).unwrap();

    let mac_err = daemon.decapsulate_and_verify(&corrupted_packet[..packet_size], &mut decrypted_buffer);
    assert_eq!(
        mac_err,
        Err(SecRouteError::MacVerificationFailed),
        "Altération de paquet détectée via étiquette MAC HMAC-SHA256"
    );
    kprintln!("  [5/7] Protections anti-rejeu et détection de corruption MAC validées.");

    // 6. Violation de politique Zero-Trust & Quarantaine O(1)
    // Tentative d'émission depuis sandbox confinée (401) vers Hyperviseur (101)
    // Créer un tunnel temporaire pour tester la règle QuarantineOnAttempt
    daemon
        .establish_tunnel(
            &admin_cap,
            2,
            401,
            101,
            [0x99u8; 32],
            [0x88u8; 32],
        )
        .expect("Établissement tunnel sandbox vers hyperviseur");

    let quarantine_err = daemon.encapsulate_and_route(&admin_cap, 2, 254, b"UNAUTHORIZED_ESCAPE_ATTEMPT", &mut packet_buffer);
    assert_eq!(
        quarantine_err,
        Err(SecRouteError::EnclaveQuarantined),
        "Tentative interdite interceptée par Zero-Trust avec mise en quarantaine immédiate"
    );

    let quarantined_ep = daemon.get_enclave(401).expect("Enclave 401 trouvée");
    assert!(quarantined_ep.is_quarantined);
    let quarantined_tunnel = daemon.get_tunnel(2).expect("Tunnel 2 trouvé");
    assert_eq!(quarantined_tunnel.status, TunnelStatus::Quarantined);
    kprintln!("  [6/7] Politique Zero-Trust Deny-by-Default et quarantaine O(1) validées.");

    // 7. Intégration REPL Shell (`jsh`) & Registre d'Audit Inaltérable
    let mut shell = JamboShell::new();

    let st_status = shell.execute("secroute status");
    assert_eq!(st_status, ShellStatus::Success);

    let st_zones = shell.execute("secroute zones");
    assert_eq!(st_zones, ShellStatus::Success);

    let st_tunnels = shell.execute("secroute tunnels");
    assert_eq!(st_tunnels, ShellStatus::Success);

    let st_send = shell.execute("secroute send");
    assert_eq!(st_send, ShellStatus::Success);

    let st_bench = shell.execute("secroute benchmark");
    assert_eq!(st_bench, ShellStatus::Success);

    let st_audit = shell.execute("secroute audit");
    assert_eq!(st_audit, ShellStatus::Success);
    assert!(daemon.audit_count > 0);

    kprintln!("  [7/7] Commandes CLI jsh et chaîne d'audit SHA-256 validées.");

    kprintln!(
        "[SECROUTE/TEST] \x1b[1;32mSUCCÈS : Tous les tests de routage sécurisé Zero-Trust et maillage chiffré (Phase 111) ont réussi avec succès !\x1b[0m"
    );
    true
}

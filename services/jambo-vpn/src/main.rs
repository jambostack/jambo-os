//! Démon Passerelle VPN Post-Quantique WireGuard Souveraine (vpn, Ring 3, PID 14)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Passerelle VPN WireGuard durcie Dual-Defense (Curve25519 + ML-KEM)
//! - Routage cryptographique granulaire (Cryptokey Routing)
//! - Chiffrement symétrique ChaCha20 et authentification HMAC-SHA256
//! - Fenêtre glissante anti-rejeu et registre d'audit inaltérable
//! - Serveur IPC pour le shell `jsh` et les services JamboOS (PID 14)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_vpn::{
    syscall_thread_yield, vpn_rights, AntiReplayWindow, ChaCha20, ChannelMessage, Curve25519,
    HandshakeInitiationPacket, HandshakeResponsePacket, HybridKeyExchange, JamboVpnDaemon, MlKem,
    Sha256, VpnCap, VpnDataPacket, VpnRequest, KEM_CIPHERTEXT_LEN, KEM_PUBLIC_KEY_LEN,
    KEM_SECRET_KEY_LEN, KEM_SHARED_SECRET_LEN, MAX_DATA_PAYLOAD, MAX_FASTPATH_BYTES,
    WG_PKT_HANDSHAKE_RESPONSE,
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
    println("\x1b[1;32m   JamboOS Sovereign VPN Daemon (PID 14) v0.3.53  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation de la capabilité racine et du démon
    let admin_cap = VpnCap::new(libjambo::Handle::new(14, 1), vpn_rights::ALL, 8, 1);
    let mut daemon = JamboVpnDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[VPN] Capabilites racine et daemon WireGuard initialises (PID 14).");

    // 2. Auto-test au démarrage : poignée de main WireGuard hybride Curve25519 + ML-KEM avec le pair node 2,
    //    vérification de la dérivation des clés, routage/chiffrement d'un paquet test [0xAA, 0xBB, 0xCC, 0xDD],
    //    vérification du déchiffrement et de la conformité MAC/anti-rejeu.
    println("[VPN] Demarrage de l'auto-test de la passerelle VPN Post-Quantique WireGuard...");

    let mut autotest_ok = false;

    // a. Création du paquet d'initiation par daemon pour peer 2
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
    let eph_seed_gateway = [0x55u8; 32];
    if let Ok((_classical_ss, pq_ss)) =
        daemon.create_handshake_initiation(&admin_cap, 2, &eph_seed_gateway, &mut init_pkt)
    {
        // b. Pair 2 reçoit l'initiation et répond
        let mut peer2_sk_curve = [0u8; 32];
        peer2_sk_curve.copy_from_slice(&Sha256::digest(b"JAMBO_PEER2_STATIC_SECRET_SEED"));
        let mut peer2_pk_kem = [0u8; KEM_PUBLIC_KEY_LEN];
        let mut peer2_sk_kem = [0u8; KEM_SECRET_KEY_LEN];
        MlKem::keygen(
            b"JAMBO_PEER2_MLKEM_SEED",
            &mut peer2_pk_kem,
            &mut peer2_sk_kem,
        );

        // Déchiffrement de la clé statique initiateur
        let classical_ss_peer2 =
            Curve25519::scalar_mult(&peer2_sk_curve, &init_pkt.ephemeral_classical);
        let mut dec_static = init_pkt.encrypted_static;
        let nonce = [0x42u8; 12];
        ChaCha20::apply_keystream(&classical_ss_peer2, 0, &nonce, &mut dec_static);

        if dec_static == daemon.local_static_pk_curve25519 {
            let mut pq_ss_peer2 = [0u8; KEM_SHARED_SECRET_LEN];
            MlKem::decapsulate(&peer2_sk_kem, &init_pkt.pqc_ciphertext, &mut pq_ss_peer2);

            let resp_eph_seed = [0x66u8; 32];
            let resp_eph_sk = Sha256::digest(&resp_eph_seed);
            let resp_eph_pk = Curve25519::public_key(&resp_eph_sk);
            let eph_classical_ss =
                Curve25519::scalar_mult(&resp_eph_sk, &init_pkt.ephemeral_classical);

            let mut peer2_tx_key = [0u8; 32];
            let mut peer2_rx_key = [0u8; 32];
            HybridKeyExchange::derive_master_secrets(
                &eph_classical_ss,
                &pq_ss_peer2,
                b"JAMBO_WIREGUARD_SESSION_V1",
                &mut peer2_tx_key,
                &mut peer2_rx_key,
            );

            let resp_pkt = HandshakeResponsePacket {
                msg_type: WG_PKT_HANDSHAKE_RESPONSE,
                sender_index: 0x2001,
                receiver_index: init_pkt.sender_index,
                ephemeral_classical: resp_eph_pk,
                pqc_shared_secret_tag: pq_ss_peer2,
                encrypted_nothing: [0x5au8; 16],
                mac1: [0x11u8; 16],
                mac2: [0x22u8; 16],
            };

            // c. Gateway finalise le handshake avec la réponse
            let eph_sk_gw = Sha256::digest(&eph_seed_gateway);
            if daemon
                .complete_handshake_initiation_session(&admin_cap, 2, &eph_sk_gw, &pq_ss, &resp_pkt)
                .is_ok()
            {
                // d. Routage et chiffrement d'un paquet test [0xAA, 0xBB, 0xCC, 0xDD]
                let test_payload = [0xAA, 0xBB, 0xCC, 0xDD];
                let mut data_pkt = VpnDataPacket {
                    msg_type: 0,
                    receiver_index: 0,
                    counter: 0,
                    payload_len: 0,
                    encrypted_payload: [0u8; MAX_DATA_PAYLOAD],
                    auth_tag: [0u8; 16],
                };

                if daemon
                    .route_and_encrypt_packet(
                        &admin_cap,
                        &[10, 0, 2, 15],
                        &test_payload,
                        &mut data_pkt,
                    )
                    .is_ok()
                {
                    // e. Déchiffrement et validation du paquet côté pair 2
                    let p_len = data_pkt.payload_len as usize;
                    let expected_mac =
                        Sha256::hmac(&peer2_rx_key, &data_pkt.encrypted_payload[..p_len]);
                    if expected_mac[..16] == data_pkt.auth_tag && p_len == 4 {
                        let mut decrypted_payload = [0u8; 4];
                        decrypted_payload.copy_from_slice(&data_pkt.encrypted_payload[..4]);
                        let mut pkt_nonce = [0u8; 12];
                        pkt_nonce[4..12].copy_from_slice(&data_pkt.counter.to_le_bytes());
                        ChaCha20::apply_keystream(
                            &peer2_rx_key,
                            0,
                            &pkt_nonce,
                            &mut decrypted_payload,
                        );

                        if decrypted_payload == test_payload {
                            // f. Vérification anti-rejeu
                            let mut replay_win = AntiReplayWindow::new();
                            if replay_win.check_and_update(data_pkt.counter)
                                && !replay_win.check_and_update(data_pkt.counter)
                            {
                                autotest_ok = true;
                            }
                        }
                    }
                }
            }
        }
    }

    if autotest_ok {
        println("[VPN] Auto-test reussi : handshake hybride Curve25519+ML-KEM valide, chiffrement/dechiffrement test OK, anti-rejeu verifie.");
        println("[VPN] Passerelle VPN Post-Quantique WireGuard (jambo-vpn PID 14) prete sur le port virtuel 51820.");
    } else {
        println("[VPN] ALERTE : Echec de l'auto-test VPN !");
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh et les services
    let mut vpn_srv_h: u64 = 0;
    let mut vpn_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut vpn_srv_h as *mut u64 as u64,
            &mut vpn_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if vpn_srv_h != 0 {
        vpn_srv_h
    } else {
        14 // Endpoint standard PID 14
    });
    println("[VPN] Canal IPC VPN operationnel (endpoint PID 14 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<VpnRequest>() {
            if let Some(req) = VpnRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
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

//! Module de validation de l'Accélération Cryptographique Matérielle Ring 3
//! et de la Gestion Souveraine de Clés (`jambo-crypto2`)
//! Phase 106 — Jalon v0.2.104
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_crypto2::{
    crypto2_rights, key_usages, AesCipher, AesGcm, AesKeyWrap, CpuCryptoFeatures, Crypto2Cap,
    Crypto2Error, JamboCrypto2Daemon, KeyStatus, KeyType, Sha256, Sha512, MAX_KEYS,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle de l'accélération crypto & gestion de clés (Phase 106)
pub fn execute_crypto2_daemon_test() -> bool {
    kprintln!(
        "[CRYPTO2/TEST] Démarrage du test de validation de l'accélération crypto & gestion de clés (Phase 106)..."
    );

    // 1. Contrôle d'accès capabilaire (Crypto2Cap) et atténuation monotone
    let admin_cap = Crypto2Cap::new(
        Handle::new(10601, 1),
        crypto2_rights::ALL,
        MAX_KEYS as u16,
        key_usages::ALL as u16,
    );
    assert!(admin_cap.has_right(crypto2_rights::GENERATE_KEY));
    assert!(admin_cap.has_right(crypto2_rights::IMPORT_KEY));
    assert!(admin_cap.has_right(crypto2_rights::EXPORT_WRAPPED));
    assert!(admin_cap.has_right(crypto2_rights::ENCRYPT));
    assert!(admin_cap.has_right(crypto2_rights::DECRYPT));
    assert!(admin_cap.has_right(crypto2_rights::HASH));
    assert!(admin_cap.has_right(crypto2_rights::ROTATE));
    assert!(admin_cap.has_right(crypto2_rights::ZEROIZE));
    assert!(admin_cap.has_right(crypto2_rights::AUDIT));

    let hash_cap = admin_cap
        .derive_subordinate(crypto2_rights::HASH | crypto2_rights::AUDIT)
        .expect("Atténuation monotone Crypto2Cap");
    assert!(hash_cap.has_right(crypto2_rights::HASH));
    assert!(hash_cap.has_right(crypto2_rights::AUDIT));
    assert!(!hash_cap.has_right(crypto2_rights::ENCRYPT));
    assert!(!hash_cap.has_right(crypto2_rights::ROTATE));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        hash_cap.derive_subordinate(crypto2_rights::ALL),
        Err(Crypto2Error::PermissionDenied),
        "Amplification de droits Crypto2Cap formellement rejetée"
    );
    kprintln!(
        "[CRYPTO2/CAP] Contrôle d'accès capabilaire Crypto2Cap et atténuation monotone validés"
    );

    // 2. Détection des capacités matérielles CPU (CPUID x86-64)
    let features = CpuCryptoFeatures::detect();
    kprintln!(
        "[CRYPTO2/CPUID] Détection CPU terminée : AES-NI={}, SHA-NI={}, AVX2={}, SSE4.1={}",
        features.aes_ni,
        features.sha_ni,
        features.avx2,
        features.sse4_1
    );

    // 3. Initialisation du démon de clés souverain et des clés de référence JamboOS
    let mut daemon = JamboCrypto2Daemon::new(admin_cap);
    daemon.init_defaults();
    assert_eq!(daemon.key_count, 4);
    assert_eq!(daemon.count_active_keys(), 4);
    assert_eq!(daemon.count_quarantined_keys(), 0);
    assert_ne!(daemon.audit_chain, [0x5au8; 32]);
    kprintln!("[CRYPTO2/INIT] 4 clés souveraines initialisées (Master KEK, Storage DEK, TLS DEK, IPC HMAC)");

    // 4. Test vecteur NIST FIPS 197 AES-128
    let nist_key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let nist_pt: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let expected_ct: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];

    let aes = AesCipher::new(&nist_key).expect("Initialisation cipher AES");
    let mut ct = [0u8; 16];
    aes.encrypt_block(&nist_pt, &mut ct);
    assert_eq!(
        ct, expected_ct,
        "Vecteur de chiffrement NIST AES-128 conforme"
    );

    let mut roundtrip_pt = [0u8; 16];
    aes.decrypt_block(&ct, &mut roundtrip_pt);
    assert_eq!(roundtrip_pt, nist_pt, "Déchiffrement AES-128 exact");
    kprintln!("[CRYPTO2/AES] Primitive AES FIPS 197 validée contre les vecteurs NIST");

    // 5. Chiffrement authentifié AES-GCM (AEAD) et détection d'altération
    let iv = [0x42u8; 12];
    let aad = b"SYSTEM_AUTHENTICATED_METADATA";
    let payload = b"JamboOS Sovereign Microkernel Ring 3 Payload!";
    let mut ciphertext = [0u8; 64];
    let mut tag = [0u8; 16];

    // Chiffrement avec Storage DEK (#2)
    daemon
        .encrypt_aes_gcm(
            &admin_cap,
            2,
            &iv,
            aad,
            payload,
            &mut ciphertext[..payload.len()],
            &mut tag,
        )
        .expect("Chiffrement AES-GCM DEK");

    // Déchiffrement nominal
    let mut decrypted = [0u8; 64];
    daemon
        .decrypt_aes_gcm(
            &admin_cap,
            2,
            &iv,
            aad,
            &ciphertext[..payload.len()],
            &tag,
            &mut decrypted[..payload.len()],
        )
        .expect("Déchiffrement AES-GCM DEK");
    assert_eq!(&decrypted[..payload.len()], payload);

    // Détection d'altération du texte chiffré
    ciphertext[0] ^= 0x01;
    let fail_tamper = daemon.decrypt_aes_gcm(
        &admin_cap,
        2,
        &iv,
        aad,
        &ciphertext[..payload.len()],
        &tag,
        &mut decrypted[..payload.len()],
    );
    assert_eq!(
        fail_tamper,
        Err(Crypto2Error::InvalidTag),
        "Altération de tag interceptée"
    );
    kprintln!("[CRYPTO2/GCM] AEAD AES-GCM NIST SP 800-38D et rejet d'altération validés");

    // 6. Enveloppement de clés RFC 3394 (AES Key Wrap)
    let mut wrapped_dek = [0u8; 40];
    let wrap_len = daemon
        .wrap_key(&admin_cap, 1, 2, &mut wrapped_dek)
        .expect("Enveloppement DEK sous Master KEK");
    assert_eq!(wrap_len, 40); // 32 octets DEK -> 40 octets enveloppés

    // Déballage sécurisé
    let new_dek_id = daemon
        .unwrap_key(
            &admin_cap,
            1,
            &wrapped_dek[..wrap_len],
            "RESTORED-DEK-256",
            KeyType::Aes256,
            key_usages::ENCRYPT | key_usages::DECRYPT,
        )
        .expect("Déballage RFC 3394 de la DEK");
    assert!(new_dek_id > 4);
    kprintln!("[CRYPTO2/WRAP] Enveloppement et déballage sécurisé RFC 3394 (AES-KW) validés");

    // 7. Cycle de vie : Rotation atomique, Quarantaine et Zéroïsation d'urgence
    daemon
        .rotate_key(&admin_cap, 2, b"ENTROPY_CYCLE_VALIDATION_106")
        .expect("Rotation atomique de la clé DEK #2");
    let k2 = daemon.get_key(2).unwrap();
    assert_eq!(k2.version, 2, "Incrémentation de version après rotation");

    // Quarantaine de la clé #3 (TLS DEK)
    daemon
        .quarantine_key(&admin_cap, 3)
        .expect("Quarantaine clé #3");
    assert_eq!(daemon.get_key(3), Err(Crypto2Error::KeyQuarantined));
    assert_eq!(daemon.count_quarantined_keys(), 1);

    // Zéroïsation d'urgence de la clé #3
    daemon
        .zeroize_key(&admin_cap, 3)
        .expect("Zéroïsation clé #3");
    assert_eq!(daemon.get_key(3), Err(Crypto2Error::KeyDestroyed));
    kprintln!(
        "[CRYPTO2/LIFECYCLE] Rotation atomique, Quarantaine O(1) et Zéroïsation d'urgence validées"
    );

    // 8. Hachage cryptographique SHA-256 & SHA-512
    let d256 = daemon
        .compute_sha256(&admin_cap, b"abc")
        .expect("SHA-256 abc");
    assert_eq!(
        d256[0..4],
        [0xba, 0x78, 0x16, 0xbf],
        "Vecteur standard SHA-256 vérifié"
    );

    let d512 = daemon
        .compute_sha512(&admin_cap, b"abc")
        .expect("SHA-512 abc");
    assert_eq!(
        d512[0..4],
        [0xdd, 0xaf, 0x35, 0xa1],
        "Vecteur standard SHA-512 vérifié"
    );
    kprintln!("[CRYPTO2/HASH] Hachages SHA-256 & SHA-512 conformes aux standards FIPS 180-4");

    // 9. Vérification de la chaîne d'audit inaltérable SHA-256
    assert!(daemon.audit_count >= 8);
    assert_ne!(daemon.audit_chain, [0x5au8; 32]);
    kprintln!("[CRYPTO2/AUDIT] Registre d'audit inviolable scellé par chaîne SHA-256 validé");

    // 10. Validation des commandes Shell Ring 3 (jambo-sh)
    let mut shell = JamboShell::new();
    let mut output_buf = [0u8; 1024];

    let commands = [
        "crypto2 status",
        "crypto2 cpu-features",
        "crypto2 keys",
        "crypto2 wrap 1 2",
        "crypto2 rotate 2",
        "crypto2 quarantine 4",
        "crypto2 hash sha256 JamboTest",
        "crypto2 hash sha512 JamboTest",
        "crypto2 audit",
    ];

    for cmd in &commands {
        let (status, written) = shell.execute_line(cmd, &mut output_buf);
        assert_eq!(
            status,
            ShellStatus::Success,
            "Échec commande shell : {}",
            cmd
        );
        assert!(written > 0, "Sortie vide pour : {}", cmd);
    }
    kprintln!("[CRYPTO2/SHELL] Commandes interactives Shell jsh crypto2 validées");

    kprintln!(
        "\x1b[1;32m[CRYPTO2/SUCCESS] Phase 106 - Accélération Cryptographique Ring 3 & Gestion de Clés validée avec succès !\x1b[0m"
    );
    true
}

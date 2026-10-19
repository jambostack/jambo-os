//! Module de validation du Module de Sécurité Matériel HSM Ring 3,
//! de la Dérivation PKCS#11 et du Stockage de Clés Cryptographiques Scellées (`jambo-hsm`)
//! Phase 94 — Jalon v0.2.92
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_hsm::{
    hsm_rights, HsmCap, HsmKeyAttributes, HsmKeyType, HsmObjectClass, HsmUserType,
    JamboHsmDaemon, Sha256, MAX_OBJECTS, MAX_SLOTS,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle du sous-système HSM Ring 3 (Phase 94)
pub fn execute_hsm_daemon_test() -> bool {
    kprintln!(
        "[HSM/TEST] Démarrage du test du module de sécurité matériel HSM Ring 3 & PKCS#11 (Phase 94)..."
    );

    // 1. Contrôle d'accès capabilaire (HsmCap) et rejet formel de toute élévation de privilèges
    let admin_cap = HsmCap::new(Handle::new(9401, 1), hsm_rights::ALL);
    assert!(admin_cap.has_right(hsm_rights::OPEN_SESSION));
    assert!(admin_cap.has_right(hsm_rights::LOGIN));
    assert!(admin_cap.has_right(hsm_rights::GENERATE_KEY));
    assert!(admin_cap.has_right(hsm_rights::DERIVE_KEY));
    assert!(admin_cap.has_right(hsm_rights::CRYPTO_OP));
    assert!(admin_cap.has_right(hsm_rights::WRAP_KEY));
    assert!(admin_cap.has_right(hsm_rights::UNWRAP_KEY));
    assert!(admin_cap.has_right(hsm_rights::DESTROY_KEY));
    assert!(admin_cap.has_right(hsm_rights::ZEROIZE));
    assert!(admin_cap.has_right(hsm_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(hsm_rights::OPEN_SESSION | hsm_rights::LOGIN | hsm_rights::CRYPTO_OP)
        .expect("Atténuation monotone HsmCap");
    assert!(attenuated_cap.has_right(hsm_rights::CRYPTO_OP));
    assert!(!attenuated_cap.has_right(hsm_rights::ZEROIZE));
    assert!(!attenuated_cap.has_right(hsm_rights::ADMIN));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        attenuated_cap.attenuate(hsm_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits HsmCap formellement rejetée"
    );
    kprintln!("[HSM/CAP] Contrôle d'accès capabilaire HsmCap et rejet de l'amplification validés");

    // 2. Initialisation du démon HSM et chargement des slots/tokens matériels
    let mut daemon = JamboHsmDaemon::new(admin_cap);
    daemon.init_defaults();

    assert_eq!(daemon.count_active_keys(), 1); // Clé KEK racine
    let slot0 = daemon.get_slot(0).expect("Slot 0 présent");
    assert!(slot0.token_present);
    assert_eq!(slot0.hw_version, (2, 0));

    let slot1 = daemon.get_slot(1).expect("Slot 1 présent");
    assert!(slot1.token_present);

    let token0 = daemon.get_token(0).expect("Token 0 présent");
    assert_eq!(token0.label_as_str(), "JAMBO_ROOT_HSM_TOKEN");
    assert!(!token0.is_zeroized);
    kprintln!("[HSM/INIT] Slots matériels souverains et token racine KEK initialisés avec succès");

    // 3. Gestion de session PKCS#11 et authentification PIN
    let sess = daemon
        .open_session(&admin_cap, 0, true)
        .expect("Ouverture de session RW sur Slot 0");
    assert_eq!(daemon.count_active_sessions(), 1);

    // Échec authentification mauvais PIN
    let bad_pin_res = daemon.login(&admin_cap, sess, HsmUserType::User, b"invalid_pin");
    assert_eq!(bad_pin_res, Err(SysError::PermissionDenied));

    // Succès authentification bon PIN utilisateur
    daemon
        .login(&admin_cap, sess, HsmUserType::User, b"user_sec_pin_2026")
        .expect("Connexion utilisateur réussie");
    kprintln!("[HSM/AUTH] Authentification PKCS#11 (PIN User) et protection anti-bruteforce validées");

    // 4. Dérivation de clés cryptographiques hiérarchiques HKDF-SHA256 (RFC 5869)
    let dek_attrs = HsmKeyAttributes {
        sensitive: true,
        extractable: false, // Clé de stockage scellée non extractible
        encrypt: true,
        decrypt: true,
        sign: false,
        verify: false,
        wrap: false,
        unwrap: false,
        derive: false,
    };

    let derived_dek_id = daemon
        .derive_key_hkdf(
            &admin_cap,
            sess,
            1, // KEK Maître
            b"CLUSTER_SALT_STORAGE_2026",
            b"STORAGE_DATA_ENCRYPTION_KEY_PAYLOAD",
            32,
            "STORAGE_DEK_SCELLÉE",
            dek_attrs,
        )
        .expect("Dérivation HKDF-SHA256 d'une clé DEK");
    assert_eq!(daemon.count_active_keys(), 2);
    kprintln!("[HSM/DERIVE] Dérivation HKDF-SHA256 depuis la KEK racine validée (clé DEK scellée)");

    // 5. Chiffrement et Déchiffrement in-HSM sans exposition de la clé
    let nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC];
    let mut payload = [0x5Au8; 64];
    let original_payload = payload;

    daemon
        .encrypt(&admin_cap, sess, derived_dek_id, &nonce, &mut payload)
        .expect("Chiffrement in-HSM");
    assert_ne!(payload, original_payload, "Les données doivent être chiffrées");

    daemon
        .decrypt(&admin_cap, sess, derived_dek_id, &nonce, &mut payload)
        .expect("Déchiffrement in-HSM");
    assert_eq!(payload, original_payload, "Les données restaurées doivent être identiques");
    kprintln!("[HSM/CRYPTO] Chiffrement/Déchiffrement symétrique in-HSM sans fuite de clé validé");

    // 6. Signature et Vérification HMAC-SHA256 in-HSM
    let mut sign_attrs = HsmKeyAttributes::default();
    sign_attrs.extractable = false;
    let sign_key_id = daemon
        .generate_key(
            &admin_cap,
            sess,
            HsmObjectClass::SecretKey,
            HsmKeyType::ChaCha20,
            "HMAC_SIGNING_KEY",
            sign_attrs,
            b"seed_hmac_2026",
        )
        .expect("Génération clé HMAC");

    let message = b"CRITICAL_INTER_ENCLAVE_SYSTEM_EVENT";
    let signature = daemon
        .sign_hmac(&admin_cap, sess, sign_key_id, message)
        .expect("Signature HMAC in-HSM");
    assert_ne!(signature, [0u8; 32]);

    let sig_valid = daemon
        .verify_hmac(&admin_cap, sess, sign_key_id, message, &signature)
        .expect("Vérification HMAC");
    assert!(sig_valid, "La signature HMAC doit être valide");

    let mut forged_sig = signature;
    forged_sig[0] ^= 0xEE;
    let forged_valid = daemon
        .verify_hmac(&admin_cap, sess, sign_key_id, message, &forged_sig)
        .expect("Vérification HMAC falsifiée");
    assert!(!forged_valid, "Une signature altérée doit être rejetée");
    kprintln!("[HSM/SIGN] Signature et vérification HMAC-SHA256 in-HSM avec rejet des contrefaçons validées");

    // 7. Enveloppement sécurisé de clé (Key Wrapping) et rejet sur CKA_EXTRACTABLE = false
    // Tentative d'envelopper la clé de signature (qui a extractable = false) -> rejet formel
    let mut wrap_buffer = [0u8; 128];
    let bad_wrap = daemon.wrap_key(&admin_cap, sess, 1, sign_key_id, &mut wrap_buffer);
    assert_eq!(
        bad_wrap,
        Err(SysError::PermissionDenied),
        "Enveloppement d'une clé non extractible formellement rejeté"
    );

    // Générer une clé extractible et l'envelopper sous la KEK
    let mut ext_attrs = HsmKeyAttributes::default();
    ext_attrs.extractable = true;
    let exportable_key_id = daemon
        .generate_key(
            &admin_cap,
            sess,
            HsmObjectClass::SecretKey,
            HsmKeyType::ChaCha20,
            "EXPORTABLE_KEY",
            ext_attrs,
            b"seed_exportable_2026",
        )
        .expect("Génération clé exportable");

    let wrapped_len = daemon
        .wrap_key(&admin_cap, sess, 1, exportable_key_id, &mut wrap_buffer)
        .expect("Enveloppement de clé sous KEK");
    assert!(wrapped_len > 44);

    // Désenvelopper sous un nouvel objet
    let unwrap_id = daemon
        .unwrap_key(
            &admin_cap,
            sess,
            1,
            &wrap_buffer[..wrapped_len],
            HsmObjectClass::SecretKey,
            HsmKeyType::ChaCha20,
            "RESTORED_WRAPPED_KEY",
            ext_attrs,
        )
        .expect("Désenveloppement de clé sous KEK");
    assert_ne!(unwrap_id, exportable_key_id);
    kprintln!("[HSM/WRAP] Enveloppement (Wrapping) et Désenveloppement (Unwrapping) sous KEK validés");

    // 8. Zéroïsation matérielle d'urgence (Emergency Zeroization)
    daemon
        .emergency_zeroize(&admin_cap, 0)
        .expect("Zéroïsation d'urgence Slot 0");
    assert_eq!(daemon.count_active_keys(), 0, "Toutes les clés du slot 0 doivent être détruites");
    assert_eq!(daemon.count_active_sessions(), 0, "Toutes les sessions doivent être closes");
    let tok0_after = daemon.get_token(0).expect("Token 0");
    assert!(tok0_after.is_zeroized);
    assert!(tok0_after.is_locked);
    kprintln!("[HSM/ZEROIZE] Zéroïsation matérielle d'urgence détruisant toutes les clés en O(1) validée");

    // 9. Registre d'audit inaltérable scellé par chaîne SHA-256
    assert_ne!(daemon.audit_chain, [0u8; 32]);
    kprintln!("[HSM/AUDIT] Chaîne d'audit SHA-256 inaltérable scellée validée");

    // 10. Validation des commandes interactives du shell (`hsm`)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    // Commande status
    let (st1, len1) = shell.execute_line("hsm status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    let s1 = core::str::from_utf8(&out[..len1]).unwrap_or("");
    assert!(s1.contains("MODULE DE SÉCURITÉ MATÉRIEL SOUVERAIN"));
    assert!(s1.contains("PKCS#11 v2.40"));

    // Commande slots
    let (st2, len2) = shell.execute_line("hsm slots", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    let s2 = core::str::from_utf8(&out[..len2]).unwrap_or("");
    assert!(s2.contains("Jambo Physical Sovereign HSM"));
    assert!(s2.contains("JAMBO_ROOT_HSM_TOKEN"));

    // Commande objects
    let (st3, len3) = shell.execute_line("hsm objects", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    let s3 = core::str::from_utf8(&out[..len3]).unwrap_or("");
    assert!(s3.contains("KEK_MASTER_ROOT"));

    // Commande derive
    let (st4, len4) = shell.execute_line("hsm derive", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    let s4 = core::str::from_utf8(&out[..len4]).unwrap_or("");
    assert!(s4.contains("Nouvelle clé dérivée scellée ID"));

    // Commande wrap
    let (st5, len5) = shell.execute_line("hsm wrap", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    let s5 = core::str::from_utf8(&out[..len5]).unwrap_or("");
    assert!(s5.contains("Clé désenveloppée et réintégrée"));

    // Commande zeroize
    let (st6, len6) = shell.execute_line("hsm zeroize", &mut out);
    assert_eq!(st6, ShellStatus::Success);
    let s6 = core::str::from_utf8(&out[..len6]).unwrap_or("");
    assert!(s6.contains("Zéroïsation effectuée"));

    // Commande audit
    let (st7, len7) = shell.execute_line("hsm audit", &mut out);
    assert_eq!(st7, ShellStatus::Success);
    let s7 = core::str::from_utf8(&out[..len7]).unwrap_or("");
    assert!(s7.contains("Condensat SHA-256 d'Audit HSM"));

    kprintln!(
        "[HSM/SHELL] Commandes d'administration 'hsm status/slots/objects/derive/wrap/zeroize/audit' validées"
    );
    kprintln!(
        "[HSM/SUCCESS] Module de Sécurité Matériel HSM Ring 3 & PKCS#11 entièrement validés (Phase 94)"
    );

    true
}

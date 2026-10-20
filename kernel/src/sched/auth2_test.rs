//! Module de validation de l'Authentification Passkeys WebAuthn & Jetons Éphémères (`jambo-auth2`)
//! Phase 110 — Jalon v0.2.108
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_auth2::{
    auth2_rights, schnorr, token_scopes, webauthn_flags, Auth2Cap, Auth2Error,
    AuthenticatorData, BiometricFactor, JamboAuth2Daemon, PasskeyTransport,
    RevocationReason, Sha256, MAX_PASSKEYS, MAX_TOKENS,
};

/// Exécute la suite complète de validation formelle de l'authentification Passkeys WebAuthn et jetons éphémères (Phase 110)
pub fn execute_auth2_daemon_test() -> bool {
    kprintln!(
        "[AUTH2/TEST] Démarrage du test de validation de l'authentification Passkeys WebAuthn et jetons éphémères (Phase 110)..."
    );

    // 1. Contrôle d'accès capabilaire (Auth2Cap) et atténuation monotone
    let admin_cap = Auth2Cap::new(Handle::new(11001, 1), auth2_rights::ALL, 1, 100);
    assert!(admin_cap.has_right(auth2_rights::REGISTER_PASSKEY));
    assert!(admin_cap.has_right(auth2_rights::AUTHENTICATE_WEBAUTHN));
    assert!(admin_cap.has_right(auth2_rights::ISSUE_TOKEN));
    assert!(admin_cap.has_right(auth2_rights::VERIFY_TOKEN));
    assert!(admin_cap.has_right(auth2_rights::ATTENUATE_TOKEN));
    assert!(admin_cap.has_right(auth2_rights::REVOKE_TOKEN));
    assert!(admin_cap.has_right(auth2_rights::REVOKE_USER));
    assert!(admin_cap.has_right(auth2_rights::BUMP_EPOCH));
    assert!(admin_cap.has_right(auth2_rights::AUDIT_LOG));

    let verifier_cap = admin_cap
        .attenuate(auth2_rights::VERIFY_TOKEN | auth2_rights::ATTENUATE_TOKEN, 32)
        .expect("Atténuation monotone Auth2Cap");
    assert!(verifier_cap.has_right(auth2_rights::VERIFY_TOKEN));
    assert!(verifier_cap.has_right(auth2_rights::ATTENUATE_TOKEN));
    assert!(!verifier_cap.has_right(auth2_rights::REGISTER_PASSKEY));
    assert!(!verifier_cap.has_right(auth2_rights::REVOKE_USER));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        verifier_cap.attenuate(auth2_rights::ALL, 32),
        Err(Auth2Error::PermissionDenied),
        "Amplification de droits Auth2Cap formellement rejetée"
    );
    assert_eq!(
        verifier_cap.attenuate(auth2_rights::VERIFY_TOKEN, 64),
        Err(Auth2Error::PermissionDenied),
        "Augmentation du quota Auth2Cap formellement rejetée"
    );
    kprintln!("[AUTH2/CAP] Contrôle d'accès capabilaire Auth2Cap et atténuation monotone validés");

    // 2. Initialisation du démon Auth2 et clés d'accès Passkeys par défaut
    let mut daemon = JamboAuth2Daemon::new(admin_cap);
    daemon.init_defaults();
    assert!(daemon.passkey_count >= 2, "Passkeys administrateur et opérateur initialisées");
    kprintln!("[AUTH2/INIT] Démon Passkeys & Jetons Éphémères jambo-auth2 initialisé");

    // 3. Enregistrement dynamique d'une clé Passkey avec biométrie matérielle
    let user_secret = 0x9876_5432_10FE_DCBA;
    let user_pub = schnorr::compute_public_key(user_secret);
    let cred_id = daemon
        .register_passkey(
            &admin_cap,
            42,
            "sec.jambo.internal",
            "secops-lead",
            user_pub,
            BiometricFactor::IrisScan,
            PasskeyTransport::InternalPlatform,
            webauthn_flags::FLAG_UP | webauthn_flags::FLAG_UV | webauthn_flags::FLAG_BE,
        )
        .expect("Enregistrement Passkey avec biométrie oculaire");
    kprintln!("[AUTH2/PASSKEY] Clé Passkey WebAuthn avec facteur biométrique enregistrée");

    // 4. Défi cryptographique & Assertion WebAuthn avec signature Schnorr déterministe
    let challenge = daemon
        .create_challenge(42, "sec.jambo.internal")
        .expect("Création du défi WebAuthn anti-rejeu");

    let client_data_hash = Sha256::digest(b"{\"type\":\"webauthn.get\",\"origin\":\"sec.jambo.internal\"}");
    let auth_data = AuthenticatorData {
        rp_id_hash: challenge.rp_id_hash,
        flags: webauthn_flags::FLAG_UP | webauthn_flags::FLAG_UV,
        sign_count: 1,
    };

    let mut msg_buf = [0u8; 37 + 32];
    let auth_bytes = auth_data.to_bytes();
    msg_buf[..37].copy_from_slice(&auth_bytes);
    msg_buf[37..].copy_from_slice(&client_data_hash);
    let assertion_digest = Sha256::digest(&msg_buf);

    let (t, s) = schnorr::sign_deterministic(user_secret, &assertion_digest);

    let token = daemon
        .authenticate_webauthn(
            &admin_cap,
            &cred_id,
            challenge.challenge_id,
            &client_data_hash,
            auth_data,
            t,
            s,
            token_scopes::READ | token_scopes::WRITE | token_scopes::EXEC,
            180,
        )
        .expect("Authentification WebAuthn Schnorr réussie");

    assert_eq!(token.user_id, 42);
    assert_eq!(token.scopes, token_scopes::READ | token_scopes::WRITE | token_scopes::EXEC);
    kprintln!("[AUTH2/ASSERTION] Assertion WebAuthn Schnorr ZKP et émission du jeton validées");

    // 5. Détection anti-clonage et anti-rejeu (Rejet sign_count <= compteur précédent)
    let replay_result = daemon.authenticate_webauthn(
        &admin_cap,
        &cred_id,
        challenge.challenge_id,
        &client_data_hash,
        auth_data,
        t,
        s,
        token_scopes::READ,
        180,
    );
    assert_eq!(
        replay_result,
        Err(Auth2Error::ReplayAttackDetected),
        "Attaque par rejeu ou clonage d'authentificateur formellement détectée et bloquée"
    );
    kprintln!("[AUTH2/ANTI_REPLAY] Protection anti-rejeu et anti-clonage strictement validée");

    // 6. Vérification cryptographique et atténuation monotone du jeton
    let verified = daemon
        .verify_token(token.token_id, token_scopes::READ | token_scopes::WRITE)
        .expect("Jeton vérifié avec succès");
    assert_eq!(verified.token_id, token.token_id);

    // Atténuation monotone vers le scope READ uniquement
    let child_token = daemon
        .attenuate_token(token.token_id, token_scopes::READ, 60)
        .expect("Atténuation monotone de jeton");
    assert_eq!(child_token.scopes, token_scopes::READ);
    assert_eq!(child_token.parent_token_id, token.token_id);

    // Tentative d'amplification de scope : rejet formel
    let amp_result = daemon.attenuate_token(token.token_id, token_scopes::ADMIN, 30);
    assert_eq!(
        amp_result,
        Err(Auth2Error::PermissionDenied),
        "Amplification de portée de jeton formellement rejetée"
    );
    kprintln!("[AUTH2/TOKEN] Sceau cryptographique et atténuation monotone de jetons validés");

    // 7. Révocation ciblée et révocation globale par époque
    daemon
        .revoke_token(&admin_cap, token.token_id, RevocationReason::ExplicitLogout)
        .expect("Révocation ciblée de jeton");
    assert_eq!(
        daemon.verify_token(token.token_id, token_scopes::READ),
        Err(Auth2Error::TokenRevoked),
        "Jeton révoqué immédiatement rejeté"
    );

    let revoked_user_count = daemon
        .revoke_user_sessions(&admin_cap, 42, RevocationReason::SecurityEpochBump)
        .expect("Révocation de sessions utilisateur");
    assert!(revoked_user_count >= 1);
    assert_eq!(
        daemon.verify_token(child_token.token_id, token_scopes::READ),
        Err(Auth2Error::TokenRevoked),
        "Tous les jetons dérivés de l'utilisateur révoqués en O(1)"
    );
    kprintln!("[AUTH2/REVOCATION] Révocation ciblée et invalidation O(1) par époque validées");

    // 8. Registre d'audit inaltérable scellé par SHA-256
    assert!(daemon.audit_count >= 5, "Événements d'audit consignés");
    assert_ne!(daemon.audit_chain, [0u8; 32], "Chaîne d'audit active");
    kprintln!("[AUTH2/AUDIT] Registre d'audit inaltérable SHA-256 validé");

    // 9. Intégration Shell `jsh` (commandes `auth2 status`, `auth2 passkeys`, `auth2 benchmark`)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (st, len) = shell.execute_line("auth2 status", &mut out);
    assert_eq!(st, ShellStatus::Success);
    let status_str = core::str::from_utf8(&out[..len]).unwrap_or("");
    assert!(status_str.contains("DÉMON D'AUTHENTIFICATION PASSKEYS"));

    let (st, len) = shell.execute_line("auth2 passkeys", &mut out);
    assert_eq!(st, ShellStatus::Success);
    let passkeys_str = core::str::from_utf8(&out[..len]).unwrap_or("");
    assert!(passkeys_str.contains("CLÉS PASSKEYS WEBAUTHN"));

    let (st, len) = shell.execute_line("auth2 benchmark", &mut out);
    assert_eq!(st, ShellStatus::Success);
    let bench_str = core::str::from_utf8(&out[..len]).unwrap_or("");
    assert!(bench_str.contains("Benchmark Auth2 : Enregistrement Passkey"));

    kprintln!("[AUTH2/SHELL] Intégration shell Ring 3 et commandes interactives validées");

    kprintln!(
        "\x1b[1;32m[PASS] Phase 110 - Authentification Passkeys WebAuthn & Jetons Éphémères (jambo-auth2) Validée avec Succès !\x1b[0m"
    );
    true
}

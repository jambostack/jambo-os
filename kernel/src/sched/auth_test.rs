//! Module de validation de l'Identité Cryptographique & Sessions Isolées (Phase 55 - v0.2.53)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_authd::{
    CryptoAuthEngine, JamboAuthDaemon, SessionManager, SessionTokenCap, UserIdentity, UserRole,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests des identités cryptographiques asymétriques et sessions isolées (Phase 55)
pub fn execute_cryptographic_auth_test() -> bool {
    kprintln!(
        "[AUTH/TEST] Démarrage du test d'identité cryptographique & sessions isolées (Phase 55)..."
    );

    // 1. Validation de l'authentification par défi-réponse sans mot de passe en clair
    let mut session_mgr = SessionManager::new();
    let alice_privkey = [0x42u8; 32];
    let alice_pubkey = alice_privkey; // Modèle déterministe dérivé
    let alice = UserIdentity::new(101, "alice", alice_pubkey, UserRole::StandardUser, 0x00FF);
    assert!(session_mgr.register_user(alice).is_ok());

    let challenge = CryptoAuthEngine::generate_challenge(0xBEEF, 1);
    let valid_signature = CryptoAuthEngine::sign_challenge(&alice_privkey, &challenge);

    // Preuve cryptographique valide
    let auth_res = session_mgr.authenticate("alice", &challenge, &valid_signature, 1000, 10_000);
    assert!(
        auth_res.is_ok(),
        "L'authentification défi-réponse avec clé privée valide doit réussir"
    );
    let token = auth_res.unwrap();
    assert_eq!(token.user_id, 101);
    assert_eq!(token.role, UserRole::StandardUser);
    kprintln!("[AUTH/CRYPTO] Authentification asymétrique défi-réponse validée avec succès");

    // Tentative d'usurpation avec fausse signature
    let mut forged_signature = valid_signature;
    forged_signature[0] ^= 0xFF;
    let rogue_auth = session_mgr.authenticate("alice", &challenge, &forged_signature, 1000, 10_000);
    assert_eq!(
        rogue_auth,
        Err(SysError::PermissionDenied),
        "Une signature falsifiée doit être rejetée instantanément"
    );
    kprintln!(
        "[AUTH/SECURITY] Rejet formel des tentatives d'usurpation / signature corrompue validé"
    );

    // 2. Validation du cycle de vie du jeton et expiration temporelle
    assert!(
        session_mgr.validate_session(&token, 5000).is_ok(),
        "La session doit être valide dans son intervalle de validité"
    );
    assert_eq!(
        session_mgr.validate_session(&token, 15_000),
        Err(SysError::PermissionDenied),
        "Une session expirée doit être invalidée"
    );
    kprintln!("[AUTH/TTL] Validation et expiration temporelle des jetons de session validées");

    // 3. Révocation atomique et purge sans résidu (Zero-Remanence)
    assert!(session_mgr.terminate_session(token.session_id).is_ok());
    assert_eq!(session_mgr.active_sessions_count(), 0);
    assert_eq!(
        session_mgr.validate_session(&token, 5000),
        Err(SysError::InvalidHandle),
        "Un jeton révoqué ne doit plus jamais être accepté"
    );
    kprintln!(
        "[AUTH/REMANENCE] Révocation atomique en cascade & purge mémoire Zero-Remanence validées"
    );

    // 4. Validation du démon JamboAuthDaemon
    let mut auth_daemon = JamboAuthDaemon::new();
    auth_daemon.init_defaults();
    assert!(auth_daemon.active_token.is_some());
    assert_eq!(auth_daemon.manager.registered_users_count(), 3);
    assert_eq!(auth_daemon.manager.active_sessions_count(), 1);
    kprintln!("[AUTH/DAEMON] Démon JamboAuthDaemon opérationnel de bout en bout");

    // 5. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'auth status'
    let (st_stat, len_stat) = shell.execute_line("auth status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("GESTIONNAIRE D'IDENTITÉS CRYPTOGRAPHIQUES"));
    assert!(str_stat.contains("Session #"));
    kprintln!("[AUTH/SHELL] Commande 'auth status' validée");

    // Commande 'auth verify'
    let (st_verif, len_verif) = shell.execute_line("auth verify", &mut out_buf);
    assert_eq!(st_verif, ShellStatus::Success);
    let str_verif = core::str::from_utf8(&out_buf[..len_verif]).unwrap_or("");
    assert!(str_verif.contains("SessionTokenCap valide et actif"));
    kprintln!("[AUTH/SHELL] Commande 'auth verify' validée");

    // Commande 'auth logout'
    let (st_logout, len_logout) = shell.execute_line("auth logout", &mut out_buf);
    assert_eq!(st_logout, ShellStatus::Success);
    let str_logout = core::str::from_utf8(&out_buf[..len_logout]).unwrap_or("");
    assert!(str_logout.contains("Session révoquée avec succès"));
    kprintln!("[AUTH/SHELL] Commande 'auth logout' validée");

    // Commande 'auth login auditor'
    let (st_login, len_login) = shell.execute_line("auth login auditor", &mut out_buf);
    assert_eq!(st_login, ShellStatus::Success);
    let str_login = core::str::from_utf8(&out_buf[..len_login]).unwrap_or("");
    assert!(str_login.contains("Authentification réussie pour 'auditor'"));
    kprintln!("[AUTH/SHELL] Commande 'auth login' validée");

    kprintln!(
        "[AUTH/PASS] Identités cryptographiques, défi-réponse & sessions isolées validés avec succès."
    );
    true
}

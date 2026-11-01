//! Démon d'Identité Cryptographique et Gestionnaire de Sessions Isolées (authd, Ring 3, PID 15)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Bannissement du modèle monolithique root Unix
//! - Annuaire d'identités souveraines avec clés asymétriques Ed25519
//! - Défis-réponses déterministes sans mot de passe en clair
//! - Jetons de session capabilitaires non forgeables avec révocation zero-remanence
//! - Serveur IPC synchrone 64 octets pour le shell `jsh` et les services JamboOS (PID 15)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_authd::{
    syscall_thread_yield, AuthRequest, ChannelMessage, CryptoAuthEngine, JamboAuthDaemon, UserRole,
    MAX_FASTPATH_BYTES,
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
    println("\x1b[1;32m   JamboOS Sovereign Auth Daemon (PID 15) v0.3.54  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon et des identités par défaut (PID 15)
    let mut daemon = JamboAuthDaemon::new();
    daemon.init_defaults();
    println("[AUTHD] Annuaire d'identites et gestionnaire de sessions capabilitaires initialises (PID 15).");

    // 2. Auto-test au démarrage : validation session opérateur, défi-réponse auditeur,
    //    vérification jeton capabilaire, révocation atomique et validation zero-remanence.
    println("[AUTHD] Demarrage de l'auto-test d'authentification cryptographique...");

    let mut autotest_ok = false;

    // a. Validation de la session opérateur créée par défaut
    if let Some(op_token) = daemon.active_token {
        if daemon.manager.validate_session(&op_token, 2000).is_ok() {
            // b. Authentification par défi-réponse pour l'utilisateur auditeur
            let auditor_key = [0x7Eu8; 32];
            let challenge = CryptoAuthEngine::generate_challenge(0xCAFE_BABE, 2);
            let signature = CryptoAuthEngine::sign_challenge(&auditor_key, &challenge);

            if let Ok(auditor_token) = daemon.manager.authenticate(
                "auditor",
                &challenge,
                &signature,
                2000,
                3_600_000_000_000,
            ) {
                // c. Vérification du jeton de session capabilaire
                let token_valid = daemon
                    .manager
                    .validate_session(&auditor_token, 3000)
                    .is_ok()
                    && auditor_token.user_id == 2
                    && auditor_token.role == UserRole::SecurityAuditor;

                if token_valid {
                    // d. Révocation atomique et validation zero-remanence
                    let term_res = daemon.manager.terminate_session(auditor_token.session_id);
                    let zero_remanence_ok = term_res.is_ok()
                        && daemon.manager.validate_session(&auditor_token, 3000)
                            == Err(libjambo::SysError::InvalidHandle)
                        && daemon.manager.active_sessions_count() == 1;

                    if zero_remanence_ok {
                        autotest_ok = true;
                    }
                }
            }
        }
    }

    if autotest_ok {
        println("[AUTHD] Auto-test reussi : session operateur valide, defi-reponse auditeur valide, jeton capabilaire verifie, revocation zero-remanence confirmee.");
        println("[AUTHD] Gestionnaire d'identite et sessions souverain (jambo-authd PID 15) pret.");
    } else {
        println("[AUTHD] ALERTE : Echec de l'auto-test d'authentification !");
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh et les services
    let mut auth_srv_h: u64 = 0;
    let mut auth_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut auth_srv_h as *mut u64 as u64,
            &mut auth_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if auth_srv_h != 0 {
        auth_srv_h
    } else {
        15 // Endpoint standard PID 15
    });
    println("[AUTHD] Canal IPC Auth operationnel (endpoint PID 15 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<AuthRequest>() {
            if let Some(req) = AuthRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
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

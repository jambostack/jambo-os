//! Démon Moteur de Politiques de Sécurité Déclaratives & Contrôle d'Admission de Grappe (policyd, Ring 3, PID 25)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Moteur d'évaluation de politiques ABAC/RBAC déterministe
//! - Contrôle d'admission basé sur le principe de déni par défaut (Deny-by-default)
//! - Préséance stricte des refus explicites et gestion de baux temporels
//! - Serveur IPC synchrone 64 octets sous l'endpoint 25 pour le shell `jsh` et services JamboOS (PID 25)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_policyd::{
    actions, policy_rights, roles, AdmissionDecision, AdmissionRequest, ChannelMessage, Handle,
    PolicyCap, PolicyEffect, PolicyEngine, PolicyRequest, PolicyRule, MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[policyd] PANIC: bare-metal security policy daemon fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[policyd] PANIC: bare-metal security policy daemon fault\n" {
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *b, options(nomem, nostack));
        }
    }
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m   JamboOS Declarative Security Policy Engine (PID 25) v0.3.64   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation du moteur de politiques et initialisation des règles par défaut
    let mut engine = PolicyEngine::new();
    engine.init_defaults();
    println(
        "[POLICYD] Moteur de politiques declaratives initialise (PID 25, 3 regles par defaut).",
    );

    // 2. Auto-tests intégrés au boot
    println("[POLICYD] Demarrage de l'auto-test du demon de securite...");
    let admin_cap = PolicyCap::new(Handle::new(25, 1), policy_rights::ALL);

    // Auto-test 1: Évaluation d'une action autorisée (SYSTEM -> system/kernel)
    let req_allow = AdmissionRequest::new(
        1,
        roles::ROLE_SYSTEM,
        actions::ACTION_ADMIN,
        b"system/kernel",
        1000,
    )
    .expect("auto-test: create req_allow failed");
    let dec_allow = engine
        .evaluate(&admin_cap, &req_allow)
        .expect("auto-test: evaluate req_allow failed");
    assert_eq!(dec_allow, AdmissionDecision::Allowed);

    // Auto-test 2: Évaluation d'une ressource inconnue (deny-by-default)
    let req_unknown = AdmissionRequest::new(
        2,
        roles::ROLE_GUEST,
        actions::ACTION_ACCESS_SECRET,
        b"secrets/private-key",
        1000,
    )
    .expect("auto-test: create req_unknown failed");
    let dec_unknown = engine
        .evaluate(&admin_cap, &req_unknown)
        .expect("auto-test: evaluate req_unknown failed");
    match dec_unknown {
        AdmissionDecision::Denied {
            matching_rule_id, ..
        } => {
            assert_eq!(matching_rule_id, None);
        }
        _ => panic!("auto-test: unknown resource must be denied by default"),
    }

    // Auto-test 3: Ajout d'une règle de refus explicite (Deny sur vault/restricted)
    let deny_rule = PolicyRule::new(
        4,
        roles::ROLE_WORKLOAD,
        actions::ACTION_ACCESS_SECRET,
        b"vault/restricted",
        PolicyEffect::Deny,
        90,
        0,
    )
    .expect("auto-test: create deny_rule failed");
    engine
        .add_rule(&admin_cap, deny_rule)
        .expect("auto-test: add deny_rule failed");

    // Auto-test 4: Vérification de la préséance du refus explicite
    let req_denied = AdmissionRequest::new(
        3,
        roles::ROLE_WORKLOAD,
        actions::ACTION_ACCESS_SECRET,
        b"vault/restricted/keys",
        1000,
    )
    .expect("auto-test: create req_denied failed");
    let dec_denied = engine
        .evaluate(&admin_cap, &req_denied)
        .expect("auto-test: evaluate req_denied failed");
    match dec_denied {
        AdmissionDecision::Denied {
            matching_rule_id, ..
        } => {
            assert_eq!(matching_rule_id, Some(4));
        }
        _ => panic!("auto-test: explicit deny must take precedence"),
    }

    println("[POLICYD] Auto-test reussi : evaluation d'admission, deny-by-default et precedence explicite validees.");
    println("[POLICYD] Serveur Policy Engine (jambo-policyd PID 25) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 25
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(25);
    println("[POLICYD] Canal IPC Policy Engine operationnel (endpoint PID 25 pret).");

    // 4. Boucle coopérative de service IPC Ring 3
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<PolicyRequest>() {
            if let Some(req) = PolicyRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = engine.dispatch_ipc(&req);
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

        libjambo::syscall_thread_yield();
    }
}

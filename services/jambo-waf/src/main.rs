//! Démon Pare-Feu Applicatif L7 & Filtrage d'Injections Protocolaire (jambo-waf, Ring 3, PID 30)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Inspection et filtrage applicatif L7 strict (SQLi, XSS, RCE, Path Traversal, CRLF)
//! - Analyseur JSON récursif borné et détection de pollution de prototype
//! - Inspection de bytecode WebAssembly (Wasm) et prévention de bombes mémoire
//! - Détection de fuite de données sortantes (DLP)
//! - Quarantaine IP dynamique O(1), liste blanche et audit inaltérable SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 30 (PID 30)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_waf::{
    waf_rights, AttackType, ChannelMessage, HttpMethod, HttpRequest, JamboWafDaemon, RuleAction,
    WafCap, WafDecision, WafRequest, MAX_FASTPATH_BYTES, WAF_ENDPOINT_ID,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[waf] PANIC: bare-metal L7 firewall service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[waf] PANIC: bare-metal L7 firewall service fault\n" {
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
    println("\x1b[1;32m  JamboOS L7 Web Application Firewall (PID 30) v0.3.69  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon WAF avec capacité souveraine
    let admin_cap = WafCap::new(
        libjambo::Handle::new(WAF_ENDPOINT_ID, 1),
        waf_rights::ALL,
        100_000,
        1,
    );
    let mut daemon = JamboWafDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[WAF] Pare-feu L7 et signatures de securite initialises (PID 30).");

    // 2. Auto-tests de démarrage
    println("[WAF] Demarrage de l'auto-test du service WAF...");

    // Auto-test 1: Requête saine validée (Allow)
    let mut req_clean =
        HttpRequest::new([192, 168, 1, 10], HttpMethod::Get, "/api/v1/system/status");
    req_clean
        .add_header("Host", "jambo.local")
        .expect("auto-test: header Host");
    req_clean
        .add_header("Accept", "application/json")
        .expect("auto-test: header Accept");
    let res1 = daemon
        .inspect_request(&admin_cap, &req_clean, 100)
        .expect("auto-test: req_clean failed");
    assert_eq!(
        res1,
        WafDecision::Allow,
        "auto-test: clean request must be allowed"
    );
    println("[WAF] Auto-test 1: Requete saine validee (Allow) : OK.");

    // Auto-test 2: Injection SQL bloquée (Block / SQLi)
    let req_sqli = HttpRequest::new(
        [192, 168, 1, 20],
        HttpMethod::Get,
        "/users?id=1'%20or%20'1'='1",
    );
    let res2 = daemon
        .inspect_request(&admin_cap, &req_sqli, 101)
        .expect("auto-test: req_sqli failed");
    match res2 {
        WafDecision::Block { attack_type, .. } => {
            assert_eq!(
                attack_type,
                AttackType::SqlInjection,
                "auto-test: must detect SQLi"
            );
        }
        _ => panic!("auto-test: SQLi not blocked"),
    }
    println("[WAF] Auto-test 2: Injection SQL bloquee (Block / SQLi) : OK.");

    // Auto-test 3: Injection XSS bloquée (Block / XSS)
    let mut req_xss = HttpRequest::new([192, 168, 1, 30], HttpMethod::Post, "/comments");
    req_xss
        .set_body(b"<script>alert(document.cookie)</script>")
        .expect("auto-test: body xss");
    let res3 = daemon
        .inspect_request(&admin_cap, &req_xss, 102)
        .expect("auto-test: req_xss failed");
    match res3 {
        WafDecision::Block { attack_type, .. } => {
            assert_eq!(
                attack_type,
                AttackType::CrossSiteScripting,
                "auto-test: must detect XSS"
            );
        }
        _ => panic!("auto-test: XSS not blocked"),
    }
    println("[WAF] Auto-test 3: Injection XSS bloquee (Block / XSS) : OK.");

    // Auto-test 4: Traversée de répertoire bloquée (Block / PathTraversal)
    let req_trav = HttpRequest::new(
        [192, 168, 1, 40],
        HttpMethod::Get,
        "/static/../../etc/passwd",
    );
    let res4 = daemon
        .inspect_request(&admin_cap, &req_trav, 103)
        .expect("auto-test: req_trav failed");
    match res4 {
        WafDecision::Block { attack_type, .. } => {
            assert_eq!(
                attack_type,
                AttackType::PathTraversal,
                "auto-test: must detect PathTraversal"
            );
        }
        _ => panic!("auto-test: Path traversal not blocked"),
    }
    println("[WAF] Auto-test 4: Traversee de repertoire bloquee (Block / PathTraversal) : OK.");

    // Auto-test 5: Quarantaine IP appliquée et audit scellé
    let prev_audit = daemon.audit_chain;
    daemon
        .quarantine_ip(&admin_cap, [10, 0, 0, 99], AttackType::CommandInjection)
        .expect("auto-test: quarantine failed");
    assert!(
        daemon.is_ip_quarantined(&[10, 0, 0, 99]),
        "auto-test: IP must be quarantined"
    );
    daemon.log_audit(
        104,
        [10, 0, 0, 99],
        AttackType::CommandInjection,
        1007,
        RuleAction::Quarantine,
        100,
    );
    assert_ne!(
        daemon.audit_chain, prev_audit,
        "auto-test: audit chain hash must be sealed"
    );
    println("[WAF] Auto-test 5: Quarantaine IP appliquee et audit scelle : OK.");

    println("[WAF] Auto-test reussi : filtrage L7, anti-injections et quarantaine valides.");
    println("[WAF] Serveur Pare-Feu Applicatif L7 (jambo-waf PID 30) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 30
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(WAF_ENDPOINT_ID as u64);
    println("[WAF] Canal IPC Pare-Feu Applicatif operationnel (endpoint PID 30 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<WafRequest>() {
            if let Some(req) = WafRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = daemon.dispatch_ipc(&req);
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

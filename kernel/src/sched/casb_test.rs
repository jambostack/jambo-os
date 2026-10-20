//! Module de validation formelle du Courtier CASB & DLP Avancé (`jambo-casb`)
//! Phase 124 — Jalon v0.2.122
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_casb::{
    casb_rights, data_classes, AdmissionDecision, CasbCap, CasbError, CasbRequest, ComplianceTier,
    DataClassification, DlpAction, DlpPatternType, JamboCasbDaemon,
};

/// Exécute la suite complète de validation formelle du courtier CASB et DLP (Phase 124)
pub fn execute_casb_daemon_test() -> bool {
    kprintln!(
        "[CASB/TEST] Démarrage de la validation du courtier d'accès cloud/grappe (CASB) & DLP (Phase 124)..."
    );

    // 1. Contrôle d'accès capabilaire (CasbCap) et atténuation monotone
    let admin_cap = CasbCap::new(Handle::new(12401, 1), casb_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(casb_rights::INSPECT_TRAFFIC));
    assert!(admin_cap.has_right(casb_rights::ENFORCE_DLP));
    assert!(admin_cap.has_right(casb_rights::MANAGE_TENANTS));
    assert!(admin_cap.has_right(casb_rights::CONFIGURE_POLICIES));
    assert!(admin_cap.has_right(casb_rights::QUARANTINE_ACTION));
    assert!(admin_cap.has_right(casb_rights::AUDIT_READ));
    assert!(admin_cap.has_right(casb_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(casb_rights::ADMIN));

    // Atténuation monotone
    let inspect_cap = admin_cap
        .attenuate(
            casb_rights::INSPECT_TRAFFIC | casb_rights::AUDIT_READ,
            2000,
            50,
        )
        .expect("Atténuation monotone CasbCap");
    assert!(inspect_cap.has_right(casb_rights::INSPECT_TRAFFIC));
    assert!(inspect_cap.has_right(casb_rights::AUDIT_READ));
    assert!(!inspect_cap.has_right(casb_rights::ADMIN));
    assert!(!inspect_cap.has_right(casb_rights::MANAGE_TENANTS));
    assert!(!inspect_cap.has_right(casb_rights::QUARANTINE_ACTION));
    assert_eq!(inspect_cap.max_lifetime, 2000);
    assert_eq!(inspect_cap.invocations_left, 50);

    // Rejet d'escalade
    assert_eq!(
        inspect_cap.attenuate(casb_rights::ALL, 2000, 50),
        Err(CasbError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et vérification de l'état initial
    let mut casb = JamboCasbDaemon::new(admin_cap);
    casb.init_defaults();
    assert_eq!(casb.tenant_count, 3);
    assert_eq!(casb.dlp_rule_count, 5);
    assert_eq!(casb.total_inspections, 0);
    assert!(casb.verify_ledger_integrity());
    assert_ne!(casb.ledger_hash, JamboCasbDaemon::GENESIS_HASH);

    let mut sanitized = [0u8; 256];

    // 3. Validation de l'admission d'une requête légitime (Tenant 100 sovereign.core)
    let req_legit = CasbRequest::new(
        1001,
        100, // sovereign.core
        "core_node",
        "key_vault",
        "FETCH_KEY",
        true, // Chiffré conforme
        b"vault_id=sec_master_01",
    );
    let dec1 = casb
        .scan_and_broker_admission(&admin_cap, &req_legit, &mut sanitized, 200)
        .expect("Admission requête légitime");
    match dec1 {
        AdmissionDecision::Approved {
            transaction_id,
            sanitized_len,
        } => {
            assert!(transaction_id >= 5000);
            assert_eq!(sanitized_len, req_legit.payload_len);
        }
        _ => panic!("Requête légitime sovereign.core aurait dû être approuvée"),
    }
    assert_eq!(casb.total_approvals, 1);
    assert_eq!(casb.total_inspections, 1);

    // 4. Validation de la détection DLP & masquage (Redact) de carte bancaire
    // Tenant 102 (community.guest) n'a pas accès à la classe FinancialPci
    let req_pci = CasbRequest::new(
        1002,
        102, // community.guest
        "portal_ui",
        "pay_engine",
        "CHECKOUT",
        false,
        b"order_id=42&card=4242424242424242&cvv=123",
    );
    let dec_redact = casb
        .scan_and_broker_admission(&admin_cap, &req_pci, &mut sanitized, 210)
        .expect("Admission avec masquage");
    match dec_redact {
        AdmissionDecision::RedactedAndApproved {
            transaction_id,
            redacted_count,
            ..
        } => {
            assert!(transaction_id > 0);
            assert_eq!(redacted_count, 1);
            // Vérifie que les 16 chiffres de la carte sont remplacés par '*'
            assert_eq!(&sanitized[17..33], b"****************");
        }
        _ => panic!("Requête avec carte de crédit aurait dû être masquée et approuvée"),
    }
    assert_eq!(casb.total_redactions, 1);

    // 5. Validation de la détection de fuite critique de clé API & quarantaine automatique
    let req_leak = CasbRequest::new(
        1003,
        102, // community.guest
        "portal_ui",
        "external_sync",
        "POST_DATA",
        false,
        b"data=sync_all&key=jambokey_live_super_secret_master_token",
    );
    let dec_quar = casb
        .scan_and_broker_admission(&admin_cap, &req_leak, &mut sanitized, 220)
        .expect("Admission déclenchant quarantaine");
    match dec_quar {
        AdmissionDecision::Quarantined { .. } => {}
        _ => panic!("Fuite critique de clé API aurait dû déclencher la mise en quarantaine"),
    }
    assert_eq!(casb.total_quarantines, 1);

    // Vérifie que le locataire 102 est maintenant marqué en quarantaine
    assert!(casb.tenants[2].unwrap().is_quarantined);

    // Les requêtes ultérieures de ce locataire doivent être immédiatement bloquées
    let req_blocked = CasbRequest::new(
        1004,
        102,
        "portal_ui",
        "search_engine",
        "QUERY",
        false,
        b"q=help",
    );
    let dec_blk = casb
        .scan_and_broker_admission(&admin_cap, &req_blocked, &mut sanitized, 230)
        .expect("Refus locataire en quarantaine");
    assert!(matches!(dec_blk, AdmissionDecision::Quarantined { .. }));

    // 6. Validation du rejet de trafic non chiffré sur locataire à conformité stricte
    // Tenant 101 (enterprise.banking) requiert require_encryption = true
    let req_unenc = CasbRequest::new(
        1005,
        101, // enterprise.banking
        "bank_agent",
        "account_service",
        "GET_BAL",
        false, // NON CHIFFRÉ -> Violation de conformité
        b"acc=123456",
    );
    let dec_unenc = casb
        .scan_and_broker_admission(&admin_cap, &req_unenc, &mut sanitized, 240)
        .expect("Contrôle chiffrement obligatoire");
    match dec_unenc {
        AdmissionDecision::Blocked { violation_code, .. } => {
            assert_eq!(violation_code, 4031);
        }
        _ => panic!("Trafic non chiffré sur enterprise.banking aurait dû être bloqué"),
    }
    assert_eq!(casb.total_blocks, 3); // 1 pour req_leak + 1 pour req_blocked + 1 pour req_unenc

    // 7. Cycle de vie de quarantaine manuelle et levée de quarantaine
    assert!(!casb.tenants[1].unwrap().is_quarantined);
    casb.quarantine_tenant(&admin_cap, 101, "Suspicion d'intrusion", 250)
        .expect("Mise en quarantaine manuelle");
    assert!(casb.tenants[1].unwrap().is_quarantined);

    casb.lift_quarantine(&admin_cap, 101, 260)
        .expect("Levée de quarantaine manuelle");
    assert!(!casb.tenants[1].unwrap().is_quarantined);

    // 8. Vérification formelle d'intégrité de la chaîne d'audit SHA-256
    assert!(casb.verify_ledger_integrity());
    assert!(casb.audit_count >= 10);

    kprintln!(
        "[CASB/TEST] \x1b[1;32mSuccès : Courtier d'accès cloud/grappe (CASB), conformité multi-tenant, DLP Luhn/Secrets, passerelle mandataire & scellement SHA-256 validés ({} locataires, {} règles DLP, {} inspections, {} accords, {} rédactions, {} blocages, {} quarantaines)\x1b[0m",
        casb.tenant_count,
        casb.dlp_rule_count,
        casb.total_inspections,
        casb.total_approvals,
        casb.total_redactions,
        casb.total_blocks,
        casb.total_quarantines
    );
    true
}

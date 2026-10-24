//! Module de validation formelle du Courtier d'Accès Sécurisé Cloud Souverain (CASB) & Passerelle DLP d'Enclave
//! Phase 154 — Jalon v0.3.21
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_casb::{
    casb_rights, data_classes, AdmissionDecision, CasbCap, CasbError, CasbRequest, ComplianceTier,
    DataClassification, DlpAction, DlpPatternType, EnclaveFlowDirection, EnclaveType, GeoZone,
    JamboCasbDaemon, SovereignEnvelopeMetadata,
};

/// Exécute la suite complète de validation formelle du courtier CASB souverain et passerelle DLP d'enclave (Phase 154)
pub fn execute_casb_daemon_test() -> bool {
    kprintln!(
        "[CASB/TEST] Démarrage de la validation du courtier d'accès cloud souverain (CASB) & DLP d'enclave (Phase 154)..."
    );

    // 1. Contrôle d'accès capabilaire (CasbCap) et atténuation monotone
    let admin_cap = CasbCap::new(Handle::new(15401, 1), casb_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(casb_rights::INSPECT_TRAFFIC));
    assert!(admin_cap.has_right(casb_rights::ENFORCE_DLP));
    assert!(admin_cap.has_right(casb_rights::MANAGE_TENANTS));
    assert!(admin_cap.has_right(casb_rights::CONFIGURE_POLICIES));
    assert!(admin_cap.has_right(casb_rights::QUARANTINE_ACTION));
    assert!(admin_cap.has_right(casb_rights::AUDIT_READ));
    assert!(admin_cap.has_right(casb_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(casb_rights::INTERCEPT_ENCLAVE));
    assert!(admin_cap.has_right(casb_rights::BLIND_INSPECT));
    assert!(admin_cap.has_right(casb_rights::ISOLATE_ENCLAVE));
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
    assert!(!inspect_cap.has_right(casb_rights::ISOLATE_ENCLAVE));
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
    assert_eq!(casb.dlp_rule_count, 8);
    assert_eq!(casb.enclave_flow_count, 1);
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
    assert!(casb.tenants[2].unwrap().is_quarantined);

    // Requête ultérieure bloquée
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
    // Tenant 101 (enterprise.secnumcloud) requiert require_encryption = true
    let req_unenc = CasbRequest::new(
        1005,
        101, // enterprise.secnumcloud
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
        _ => panic!("Trafic non chiffré sur enterprise.secnumcloud aurait dû être bloqué"),
    }

    // 7. Validation de la détection DLP d'exfiltration de secrets d'enclave (VMPCK / SGX / ML-KEM)
    // Levée de la quarantaine sur le locataire 102 pour valider le filtrage DLP d'enclave
    casb.lift_quarantine(&admin_cap, 102, 245)
        .expect("Levée quarantaine locataire 102");
    assert!(!casb.tenants[2].unwrap().is_quarantined);

    let req_vmpck = CasbRequest::new(
        1006,
        102,
        "enclave_runner",
        "exfil_target",
        "DUMP",
        false,
        b"leak=VMPCK_a1b2c3d4e5f60718293a4b5c6d7e8f90",
    );
    let dec_vmpck = casb
        .scan_and_broker_admission(&admin_cap, &req_vmpck, &mut sanitized, 250)
        .expect("DLP fuite VMPCK");
    match dec_vmpck {
        AdmissionDecision::EnclaveIsolated { enclave_id, .. } => {
            assert_eq!(enclave_id, 102);
        }
        _ => panic!("Fuite de VMPCK d'enclave aurait dû isoler l'enclave"),
    }

    // 8. Interception et courtage des flux d'enclave matérielle TEE & Zero-Egress
    let mrenclave_snp = [0x5E; 32];
    let flow_snp = casb
        .register_enclave_flow(
            &admin_cap,
            9100,
            EnclaveType::AmdSevSnp,
            mrenclave_snp,
            2,
            EnclaveFlowDirection::Egress,
            "sovereign.cloud.target",
            false,
            260,
        )
        .expect("Enregistrement flux enclave AMD SEV-SNP");
    assert_eq!(flow_snp, 8001);

    // 9. Inspection L7 aveugle sans rupture de chiffrement (Sovereign Blind Inspection)
    let env_legit = SovereignEnvelopeMetadata {
        session_id: 1101,
        sender_enclave_id: 9100,
        claimed_classification: DataClassification::Confidential,
        blinded_payload_hash: [0x42; 32],
        attestation_token_tag: [0x88; 16],
        target_geo_zone: GeoZone::SovereignSoil,
        payload_entropy_millibits: 7150,
        is_homomorphic_tagged: true,
    };
    let dec_blind_ok = casb
        .inspect_enclave_blind_envelope(&admin_cap, flow_snp, &env_legit, 270)
        .expect("Inspection aveugle conforme");
    assert!(matches!(dec_blind_ok, AdmissionDecision::Approved { .. }));

    // Rejet géo-fencing étranger (UntrustedForeign)
    let env_foreign = SovereignEnvelopeMetadata {
        target_geo_zone: GeoZone::UntrustedForeign,
        ..env_legit
    };
    let dec_geo = casb
        .inspect_enclave_blind_envelope(&admin_cap, flow_snp, &env_foreign, 275)
        .expect("Rejet géo-fencing");
    match dec_geo {
        AdmissionDecision::Blocked { violation_code, .. } => {
            assert_eq!(violation_code, 4052);
        }
        _ => panic!("Flux vers zone étrangère aurait dû être bloqué"),
    }

    // Rejet Zero-Egress sur flux 8000
    let env_zero_egress = SovereignEnvelopeMetadata {
        sender_enclave_id: 7001,
        ..env_legit
    };
    let dec_ze = casb
        .inspect_enclave_blind_envelope(&admin_cap, 8000, &env_zero_egress, 280)
        .expect("Rejet Zero-Egress");
    match dec_ze {
        AdmissionDecision::Blocked { violation_code, .. } => {
            assert_eq!(violation_code, 4051);
        }
        _ => panic!("Flux en violation Zero-Egress aurait dû être bloqué"),
    }

    // 10. Isolation O(1) de l'enclave et levée d'isolation
    casb.isolate_enclave(&admin_cap, 9100, "Confinement défensif", 290)
        .expect("Isolation enclave OK");
    let dec_iso = casb
        .inspect_enclave_blind_envelope(&admin_cap, flow_snp, &env_legit, 295)
        .expect("Refus enclave isolée");
    assert!(matches!(dec_iso, AdmissionDecision::EnclaveIsolated { .. }));

    casb.lift_enclave_isolation(&admin_cap, 9100, 300)
        .expect("Levée isolation OK");
    let dec_uniso = casb
        .inspect_enclave_blind_envelope(&admin_cap, flow_snp, &env_legit, 305)
        .expect("Reprise post-isolation");
    assert!(matches!(dec_uniso, AdmissionDecision::Approved { .. }));

    // 11. Cycle de vie de quarantaine manuelle de locataire
    assert!(!casb.tenants[1].unwrap().is_quarantined);
    casb.quarantine_tenant(&admin_cap, 101, "Suspicion d'intrusion", 310)
        .expect("Mise en quarantaine manuelle");
    assert!(casb.tenants[1].unwrap().is_quarantined);

    casb.lift_quarantine(&admin_cap, 101, 320)
        .expect("Levée de quarantaine manuelle");
    assert!(!casb.tenants[1].unwrap().is_quarantined);

    // 12. Vérification formelle d'intégrité de la chaîne d'audit SHA-256
    assert!(casb.verify_ledger_integrity());
    assert!(casb.audit_count >= 12);

    kprintln!(
        "[CASB/TEST] \x1b[1;32mSuccès : Courtier d'accès cloud souverain (CASB), flux d'enclave TEE, DLP VMPCK/SGX/PQC, inspection aveugle L7 & scellement SHA-256 validés ({} locataires, {} règles DLP, {} flux d'enclaves, {} inspections, {} accords, {} rédactions, {} blocages, {} quarantaines, {} isolations d'enclave)\x1b[0m",
        casb.tenant_count,
        casb.dlp_rule_count,
        casb.enclave_flow_count,
        casb.total_inspections,
        casb.total_approvals,
        casb.total_redactions,
        casb.total_blocks,
        casb.total_quarantines,
        casb.total_enclave_isolations
    );
    true
}

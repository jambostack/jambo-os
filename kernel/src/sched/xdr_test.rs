//! Module de validation formelle de la Détection & Réponse Étendue (`jambo-xdr`)
//! Phase 120 — Jalon v0.2.118
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_xdr::{
    xdr_rights, AptCampaign, CampaignStage, CampaignStatus, EventSeverity, JamboXdrDaemon,
    MitreTactic, TelemetryVector, XdrCap, XdrError, XdrResponseType,
};

/// Exécute la suite complète de validation formelle du moteur XDR (Phase 120)
pub fn execute_xdr_daemon_test() -> bool {
    kprintln!(
        "[XDR/TEST] Démarrage de la validation de la détection & réponse étendue multi-vecteurs (Phase 120)..."
    );

    // 1. Contrôle d'accès capabilaire (XdrCap) et atténuation monotone
    let admin_cap = XdrCap::new(Handle::new(12001, 1), xdr_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(xdr_rights::INGEST_TELEMETRY));
    assert!(admin_cap.has_right(xdr_rights::CORRELATE_INCIDENTS));
    assert!(admin_cap.has_right(xdr_rights::DETECT_APT_CAMPAIGN));
    assert!(admin_cap.has_right(xdr_rights::CROSS_VECTOR_RESPONSE));
    assert!(admin_cap.has_right(xdr_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(xdr_rights::AUDIT_READ));
    assert!(admin_cap.has_right(xdr_rights::ADMIN));

    // Atténuation monotone
    let ingest_cap = admin_cap
        .attenuate(
            xdr_rights::INGEST_TELEMETRY | xdr_rights::AUDIT_READ,
            2000,
            50,
        )
        .expect("Atténuation monotone XdrCap");
    assert!(ingest_cap.has_right(xdr_rights::INGEST_TELEMETRY));
    assert!(ingest_cap.has_right(xdr_rights::AUDIT_READ));
    assert!(!ingest_cap.has_right(xdr_rights::ADMIN));
    assert!(!ingest_cap.has_right(xdr_rights::CROSS_VECTOR_RESPONSE));
    assert_eq!(ingest_cap.max_lifetime, 2000);
    assert_eq!(ingest_cap.invocations_left, 50);

    // Rejet d'escalade
    assert_eq!(
        ingest_cap.attenuate(xdr_rights::ALL, 2000, 50),
        Err(XdrError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et vérification de l'état initial
    let mut xdr = JamboXdrDaemon::new(admin_cap);
    xdr.init_defaults();
    assert_eq!(xdr.event_count, 5);
    assert_eq!(xdr.campaign_count, 1);
    assert!(xdr.verify_ledger_integrity());
    assert_ne!(xdr.ledger_hash, JamboXdrDaemon::GENESIS_HASH);

    // 3. Vérification de la campagne APT corrélée sur l'entité pivot "admin-svc"
    let camp = xdr.get_campaign(1).expect("Campagne APT #1 présente");
    assert_eq!(camp.primary_entity_as_str(), "admin-svc");
    assert_eq!(camp.vector_count(), 4); // Auth + VPN + WAF + EDR
    assert!(camp.risk_score >= 500);
    assert!(camp.confidence >= 80);
    assert_eq!(camp.stage, CampaignStage::LateralMovement);
    assert_eq!(camp.status, CampaignStatus::Active);

    // 4. Ingestion dynamique d'un nouvel événement vecteur CloudInfra sur l'entité
    let ev_id = xdr
        .ingest_event(
            &admin_cap,
            TelemetryVector::CloudInfra,
            "admin-svc",
            MitreTactic::Exfiltration,
            EventSeverity::Critical,
            96,
            "Tentative d'exfiltration via réplication asynchrone DFS non-autorisée",
            1300,
        )
        .expect("Ingestion événement CloudInfra");
    assert_eq!(ev_id, 6);

    // Re-corrélation avec mise à jour du profil d'attaque
    let newly = xdr
        .correlate_campaigns(&admin_cap, 1350)
        .expect("Corrélation XDR");
    assert_eq!(newly, 0); // Déjà regroupé sous la campagne existante

    // 5. Orchestration de réponse trans-vectorielle : Confinement unifié (UnifiedQuarantine)
    xdr.isolate_all_vectors(&admin_cap, 1, 1400)
        .expect("Exécution confinement unifié");

    assert_eq!(xdr.cross_vector_responses_count, 1);
    assert_eq!(xdr.quarantined_entities_count, 1);

    let updated_camp = xdr.get_campaign(1).unwrap();
    assert_eq!(updated_camp.status, CampaignStatus::Contained);
    assert_eq!(updated_camp.stage, CampaignStage::Contained);

    let resp = xdr.responses[0]
        .as_ref()
        .expect("Enregistrement de réponse présent");
    assert_eq!(resp.response_type, XdrResponseType::UnifiedQuarantine);
    assert_eq!(resp.target_as_str(), "admin-svc");
    assert!(resp.success);

    // 6. Vérification de l'intégrité cryptographique SHA-256 du registre inaltérable
    assert!(xdr.verify_ledger_integrity());
    assert!(xdr.audit_count >= 6);

    kprintln!(
        "[XDR/TEST] \x1b[1;32mSuccès : Corrélation multi-vecteurs (EDR/VPN/WAF/AUTH), détection APT, confinement unifié & scellement SHA-256 validés ({} événements, {} campagne(s))\x1b[0m",
        xdr.event_count,
        xdr.campaign_count
    );
    true
}

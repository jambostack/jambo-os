//! Module de validation formelle de la Détection et Réponse Étendue Souveraine XDR (`jambo-xdr`)
//! Phase 150 — Jalon v0.3.17
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_xdr::{
    xdr_rights, AptCampaign, CampaignStage, CampaignStatus, EventSeverity, JamboXdrDaemon,
    MitreTactic, TelemetryVector, XdrCap, XdrError, XdrRemediationReport, XdrResponseType,
    XdrSummary,
};

/// Exécute la suite complète de validation formelle du moteur XDR souverain (Phase 150)
pub fn execute_xdr_daemon_test() -> bool {
    kprintln!(
        "[XDR/TEST] Démarrage de la validation formelle de la détection et réponse étendue souveraine XDR (Phase 150)..."
    );

    // 1. Contrôle d'accès capabilaire (XdrCap) et atténuation monotone Zero-Ambient Authority
    let admin_cap = XdrCap::new(Handle::new(12001, 1), xdr_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(xdr_rights::INGEST_TELEMETRY));
    assert!(admin_cap.has_right(xdr_rights::CORRELATE_INCIDENTS));
    assert!(admin_cap.has_right(xdr_rights::DETECT_APT_CAMPAIGN));
    assert!(admin_cap.has_right(xdr_rights::CROSS_VECTOR_RESPONSE));
    assert!(admin_cap.has_right(xdr_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(xdr_rights::AUDIT_READ));
    assert!(admin_cap.has_right(xdr_rights::TEE_ENCLAVE_GUARD));
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
    assert!(!ingest_cap.has_right(xdr_rights::TEE_ENCLAVE_GUARD));
    assert_eq!(ingest_cap.max_lifetime, 2000);
    assert_eq!(ingest_cap.invocations_left, 50);

    // Rejet d'escalade
    assert_eq!(
        ingest_cap.attenuate(xdr_rights::ALL, 2000, 50),
        Err(XdrError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et vérification de la télémétrie multi-vecteurs
    let mut xdr = JamboXdrDaemon::new(admin_cap);
    xdr.init_defaults();
    assert_eq!(xdr.event_count, 6);
    assert_eq!(xdr.campaign_count, 1);
    assert_eq!(xdr.tee_anomalies_count, 1);
    assert!(xdr.verify_ledger_integrity());
    assert_ne!(xdr.ledger_hash, JamboXdrDaemon::GENESIS_HASH);

    // 3. Vérification de la campagne APT corrélée sur l'entité pivot "admin-svc"
    let camp = xdr.get_campaign(1).expect("Campagne APT #1 présente");
    assert_eq!(camp.primary_entity_as_str(), "admin-svc");
    assert_eq!(camp.vector_count(), 5); // Auth + VPN + WAF + EDR + TEE
    assert!(camp.has_tee_breach());
    assert!(camp.risk_score >= 800);
    assert!(camp.confidence >= 80);
    assert_eq!(camp.stage, CampaignStage::EnclaveBreach);
    assert_eq!(camp.status, CampaignStatus::Active);

    // 4. Validation du Graphe de Propagation des Menaces (Threat Propagation Graph)
    let propagation = xdr.trace_propagation(1);
    assert!(propagation[0].is_some(), "Graphe de propagation présent");
    let step0 = propagation[0].unwrap();
    assert_eq!(step0.from_vector, TelemetryVector::IdentityAuth);
    assert_eq!(step0.to_vector, TelemetryVector::NetworkVpn);

    // 5. Ingestion dynamique d'un nouvel événement vecteur CloudInfra sur l'entité
    let ev_id = xdr
        .ingest_event(
            &admin_cap,
            TelemetryVector::CloudInfra,
            "admin-svc",
            MitreTactic::Exfiltration,
            EventSeverity::Critical,
            96,
            "Tentative d'exfiltration via réplication asynchrone DFS non-autorisée",
            1400,
        )
        .expect("Ingestion événement CloudInfra");
    assert_eq!(ev_id, 7);

    // Re-corrélation avec mise à jour du profil d'attaque
    let newly = xdr
        .correlate_campaigns(&admin_cap, 1450)
        .expect("Corrélation XDR");
    assert_eq!(newly, 0); // Déjà regroupé sous la campagne existante

    // 6. Orchestration de réponse trans-vectorielle O(1) & Rapport de Remédiation Déterministe
    let report = xdr
        .remediate_campaign_o1(&admin_cap, 1, 1500)
        .expect("Exécution remédiation O(1)");

    assert_eq!(report.campaign_id, 1);
    assert_eq!(report.target_as_str(), "admin-svc");
    assert!(report.endpoint_isolated);
    assert!(report.network_severed);
    assert!(report.waf_route_blocked);
    assert!(report.identity_revoked);
    assert!(report.tee_locked_down);
    assert_eq!(report.execution_time_us, 12);
    assert_ne!(report.report_hash, [0u8; 32]);

    assert_eq!(xdr.cross_vector_responses_count, 1);
    assert_eq!(xdr.quarantined_entities_count, 1);

    let updated_camp = xdr.get_campaign(1).unwrap();
    assert_eq!(updated_camp.status, CampaignStatus::Contained);
    assert_eq!(updated_camp.stage, CampaignStage::Contained);

    // 7. Vérification des métriques de synthèse et de l'intégrité cryptographique SHA-256
    let sum = xdr.summary();
    assert_eq!(sum.total_events, 7);
    assert_eq!(sum.active_campaigns, 0);
    assert_eq!(sum.contained_campaigns, 1);
    assert_eq!(sum.total_responses, 1);
    assert_eq!(sum.quarantined_entities, 1);
    assert_eq!(sum.tee_anomalies_correlated, 1);
    assert!(sum.ledger_valid);
    assert!(xdr.verify_ledger_integrity());
    assert!(xdr.audit_count >= 8);

    kprintln!(
        "[XDR/TEST] \x1b[1;32mSuccès : Corrélation multi-vecteurs (EDR/NDR/WAF/AUTH/CLOUD/TEE), graphe APT, remédiation O(1) & scellement SHA-256 validés ({} événements, {} campagne(s), latence: {}µs)\x1b[0m",
        sum.total_events,
        sum.contained_campaigns,
        report.execution_time_us
    );
    true
}

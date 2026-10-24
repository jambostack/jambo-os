//! Module de validation formelle du Renseignement Cyber & Partage de Flux d'IoC Souverain CTI (`jambo-intel`)
//! Phase 151 — Jalon v0.3.18
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_intel::{
    intel_rights, IntelAction, IntelCap, IntelError, IocKind, JamboIntelDaemon, KillChainPhase,
    StixIndicator, ThreatCategory, ThreatSeverity, TlpLevel,
};

/// Exécute la suite complète de validation formelle du moteur CTI / IoC Souverain (Phase 151)
pub fn execute_intel_daemon_test() -> bool {
    kprintln!(
        "[INTEL/TEST] Démarrage de la validation du renseignement cyber & partage de flux d'IoC (Phase 151)..."
    );

    // 1. Contrôle d'accès capabilaire (IntelCap) et atténuation monotone
    let admin_cap = IntelCap::new(Handle::new(15101, 1), intel_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(intel_rights::INGEST_IOC));
    assert!(admin_cap.has_right(intel_rights::QUERY_IOC));
    assert!(admin_cap.has_right(intel_rights::EXPIRE_IOC));
    assert!(admin_cap.has_right(intel_rights::UPDATE_FEED));
    assert!(admin_cap.has_right(intel_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(intel_rights::AUDIT_READ));
    assert!(admin_cap.has_right(intel_rights::STIX_INGEST));
    assert!(admin_cap.has_right(intel_rights::TAXII_SYNC));
    assert!(admin_cap.has_right(intel_rights::ADMIN));

    // Atténuation monotone
    let query_cap = admin_cap
        .attenuate(intel_rights::QUERY_IOC | intel_rights::AUDIT_READ, 2000, 50)
        .expect("Atténuation monotone IntelCap");
    assert!(query_cap.has_right(intel_rights::QUERY_IOC));
    assert!(query_cap.has_right(intel_rights::AUDIT_READ));
    assert!(!query_cap.has_right(intel_rights::ADMIN));
    assert!(!query_cap.has_right(intel_rights::INGEST_IOC));
    assert!(!query_cap.has_right(intel_rights::TAXII_SYNC));
    assert_eq!(query_cap.max_lifetime, 2000);
    assert_eq!(query_cap.invocations_left, 50);

    // Rejet d'escalade
    assert_eq!(
        query_cap.attenuate(intel_rights::ALL, 2000, 50),
        Err(IntelError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et vérification de l'état initial
    let mut intel = JamboIntelDaemon::new(admin_cap);
    intel.init_defaults();
    assert_eq!(intel.feed_count, 3);
    assert_eq!(intel.collection_count, 2);
    assert_eq!(intel.peer_count, 2);
    assert!(intel.ioc_count >= 6);
    assert!(intel.verify_ledger_integrity());
    assert_ne!(intel.ledger_hash, JamboIntelDaemon::GENESIS_HASH);

    // 3. Validation de la recherche O(1) via BloomFilter et Hash Table
    // a) Recherche Malware SHA-256
    let sha_malware: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];
    let match_sha = intel
        .query_ioc(&admin_cap, IocKind::Sha256, &sha_malware, 200)
        .expect("Requête SHA-256")
        .expect("IoC SHA-256 détecté");
    assert_eq!(match_sha.ioc_id, 1);
    assert_eq!(match_sha.category, ThreatCategory::MalwarePayload);
    assert_eq!(match_sha.severity, ThreatSeverity::Critical);
    assert_eq!(match_sha.confidence, 98);
    assert_eq!(match_sha.hit_count, 1);

    // b) Recherche IP Bogon (198.51.100.23)
    let ip_bogon = [198, 51, 100, 23];
    let match_ip = intel
        .query_ioc(&admin_cap, IocKind::Ipv4, &ip_bogon, 210)
        .expect("Requête IP")
        .expect("IoC IP détecté");
    assert_eq!(match_ip.category, ThreatCategory::BogonIp);
    assert_eq!(match_ip.confidence, 99);

    // c) Élément clean (rejet Bloom immédiat)
    let clean_ip = [10, 0, 1, 42];
    let match_clean = intel
        .query_ioc(&admin_cap, IocKind::Ipv4, &clean_ip, 220)
        .expect("Requête IP clean");
    assert!(match_clean.is_none());

    // 4. Évaluation approfondie STIX 2.1 & Scoring de réputation adaptatif
    let domain_stix = b"volt-typhoon.backdoor.sovereign";
    let assessment = intel
        .assess_threat(&admin_cap, IocKind::Domain, domain_stix, 230)
        .expect("Évaluation de menace")
        .expect("Menace STIX évaluée");
    assert_eq!(assessment.severity, ThreatSeverity::Critical);
    assert_eq!(assessment.tlp, TlpLevel::Red);
    assert_eq!(assessment.kill_chain, KillChainPhase::CommandAndControl);
    assert_eq!(assessment.action, IntelAction::BlockTraffic);
    assert!(assessment.reputation_score >= 90);

    // 5. Synchronisation TAXII 2.1 avec pair souverain
    let sync_res = intel.sync_taxii_peer(&admin_cap, 100, 240);
    assert!(sync_res.is_ok());

    // 6. Ingestion dynamique d'un nouvel indicateur (URL Phishing)
    let new_url = b"https://auth-fake.sovereign/login";
    let new_id = intel
        .ingest_ioc(
            &admin_cap,
            IocKind::UrlPattern,
            new_url,
            ThreatCategory::Phishing,
            ThreatSeverity::High,
            91,
            "Sovereign-CERT",
            1000, // TTL 1000 ticks
            250,
        )
        .expect("Ingestion dynamique IoC");
    assert!(new_id >= 7);

    // Détection immédiate du nouvel indicateur
    let match_phish = intel
        .query_ioc(&admin_cap, IocKind::UrlPattern, new_url, 300)
        .expect("Requête URL")
        .expect("IoC URL détecté");
    assert_eq!(match_phish.ioc_id, new_id);
    assert_eq!(match_phish.category, ThreatCategory::Phishing);

    // 7. Expiration dynamique par TTL et purge
    let match_before = intel
        .query_ioc(&admin_cap, IocKind::UrlPattern, new_url, 1200)
        .expect("Requête avant expiration");
    assert!(match_before.is_some());

    let match_after = intel
        .query_ioc(&admin_cap, IocKind::UrlPattern, new_url, 1300)
        .expect("Requête après expiration");
    assert!(match_after.is_none());

    let purged = intel
        .purge_expired(&admin_cap, 1300)
        .expect("Purge expirés");
    assert!(purged >= 1);

    // 8. Vérification formelle du registre d'audit et scellement SHA-256
    assert!(intel.verify_ledger_integrity());
    assert!(intel.audit_count >= 10);

    kprintln!(
        "[INTEL/TEST] \x1b[1;32mSuccès : STIX 2.1, fédération TAXII, recherche Bloom/Hash O(1), réputation adaptative & scellement SHA-256 validés ({} IoCs, {} flux, {} collections)\x1b[0m",
        intel.ioc_count,
        intel.feed_count,
        intel.collection_count
    );
    true
}

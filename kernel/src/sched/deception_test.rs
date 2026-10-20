//! Module de validation formelle de la Cyber-Déception & Honeypots (`jambo-deception`)
//! Phase 122 — Jalon v0.2.120
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_deception::{
    deception_rights, AttackerLevel, DeceptionCap, DeceptionError, DecoyKind, JamboDeceptionDaemon,
    ProbeAction, ThreatSeverity,
};

/// Exécute la suite complète de validation formelle du moteur de Cyber-Déception (Phase 122)
pub fn execute_deception_daemon_test() -> bool {
    kprintln!(
        "[DECEPTION/TEST] Démarrage de la validation de la cyber-déception & honeypots (Phase 122)..."
    );

    // 1. Contrôle d'accès capabilaire (DeceptionCap) et atténuation monotone
    let admin_cap = DeceptionCap::new(Handle::new(12201, 1), deception_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(deception_rights::DEPLOY_DECOY));
    assert!(admin_cap.has_right(deception_rights::TRIGGER_ALERT));
    assert!(admin_cap.has_right(deception_rights::PROBE_DECOY));
    assert!(admin_cap.has_right(deception_rights::PROFILE_ATTACKER));
    assert!(admin_cap.has_right(deception_rights::QUARANTINE));
    assert!(admin_cap.has_right(deception_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(deception_rights::AUDIT_READ));
    assert!(admin_cap.has_right(deception_rights::ADMIN));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            deception_rights::TRIGGER_ALERT | deception_rights::AUDIT_READ,
            2000,
            50,
        )
        .expect("Atténuation monotone DeceptionCap");
    assert!(monitor_cap.has_right(deception_rights::TRIGGER_ALERT));
    assert!(monitor_cap.has_right(deception_rights::AUDIT_READ));
    assert!(!monitor_cap.has_right(deception_rights::ADMIN));
    assert!(!monitor_cap.has_right(deception_rights::DEPLOY_DECOY));
    assert!(!monitor_cap.has_right(deception_rights::QUARANTINE));
    assert_eq!(monitor_cap.max_lifetime, 2000);
    assert_eq!(monitor_cap.invocations_left, 50);

    // Rejet d'escalade
    assert_eq!(
        monitor_cap.attenuate(deception_rights::ALL, 2000, 50),
        Err(DeceptionError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et vérification de l'état initial
    let mut deception = JamboDeceptionDaemon::new(admin_cap);
    deception.init_defaults();
    assert_eq!(deception.decoy_count, 5);
    assert_eq!(deception.total_probes, 0);
    assert!(deception.verify_ledger_integrity());
    assert_ne!(deception.ledger_hash, JamboDeceptionDaemon::GENESIS_HASH);

    // 3. Validation du déclenchement silencieux O(1) sur HoneyCap (Leurre #1)
    let alert1 = deception
        .trigger_decoy(&admin_cap, 1, 4001, ProbeAction::InvokeHoneyCap, 200)
        .expect("Déclenchement HoneyCap");
    assert_eq!(alert1.decoy_id, 1);
    assert_eq!(alert1.attacker_source, 4001);
    assert_eq!(alert1.decoy_kind, DecoyKind::HoneyCap);
    assert_eq!(alert1.severity, ThreatSeverity::Critical);
    assert!(alert1.silent);

    // Vérification du profil comportemental
    let prof1 = deception.get_attacker_profile(4001).expect("Profil 4001");
    assert_eq!(prof1.hit_count, 1);
    assert_eq!(prof1.threat_score, 35);
    assert_eq!(prof1.level, AttackerLevel::Reconnaissance);
    assert!(!prof1.quarantined);

    // 4. Validation des pièges à évasion d'enclave TEE (Leurre #4)
    let alert_tee = deception
        .trigger_decoy(&admin_cap, 4, 7777, ProbeAction::EnclaveEscapeAttempt, 500)
        .expect("Piège évasion enclave");
    assert_eq!(alert_tee.decoy_kind, DecoyKind::EnclaveTrapDecoy);
    assert_eq!(alert_tee.severity, ThreatSeverity::Critical);

    let prof_tee = deception.get_attacker_profile(7777).expect("Profil 7777");
    assert_eq!(prof_tee.level, AttackerLevel::EnclaveEscapeAttempt);
    assert_eq!(prof_tee.threat_score, 50);

    // Deuxième tentative d'évasion d'enclave -> Quarantaine immédiate
    deception
        .trigger_decoy(&admin_cap, 4, 7777, ProbeAction::EnclaveEscapeAttempt, 550)
        .expect("Deuxième sonde évasion");
    let prof_tee2 = deception
        .get_attacker_profile(7777)
        .expect("Profil 7777 après");
    assert_eq!(prof_tee2.threat_score, 100);
    assert!(prof_tee2.quarantined);
    assert!(deception.total_quarantines >= 1);

    // 5. Confinement manuel et désactivation de leurre
    deception
        .trigger_decoy(&admin_cap, 5, 9999, ProbeAction::FileAccess, 600)
        .expect("Sonde canari fichier");
    let manual_q = deception
        .quarantine_attacker(&admin_cap, 9999, 610)
        .expect("Quarantaine manuelle");
    assert!(manual_q);
    let prof_man = deception.get_attacker_profile(9999).unwrap();
    assert!(prof_man.quarantined);
    assert_eq!(prof_man.threat_score, 100);

    // Désactivation du leurre #5
    deception
        .deactivate_decoy(&admin_cap, 5, 620)
        .expect("Désactivation leurre");
    let probe_dead = deception.trigger_decoy(&admin_cap, 5, 9999, ProbeAction::FileAccess, 630);
    assert_eq!(probe_dead, Err(DeceptionError::DecoyNotFound));

    // 6. Vérification formelle du registre d'audit et scellement SHA-256
    assert!(deception.verify_ledger_integrity());
    assert!(deception.audit_count >= 10);

    kprintln!(
        "[DECEPTION/TEST] \x1b[1;32mSuccès : HoneyCaps, leurres VMO, pièges d'enclave TEE, profilage attaquant, quarantaine & scellement SHA-256 validés ({} leurres, {} sondes, {} alertes, {} profils, {} quarantaines)\x1b[0m",
        deception.decoy_count,
        deception.total_probes,
        deception.alert_count,
        deception.profile_count,
        deception.total_quarantines
    );
    true
}

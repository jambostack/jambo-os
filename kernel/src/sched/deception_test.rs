//! Module de validation formelle de la Cyber-Déception, Honeypots & Pièges d'Évasion TEE (`jambo-deception`)
//! Phase 152 — Jalon v0.3.19
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_deception::{
    deception_rights, AttackerLevel, DeceptionCap, DeceptionContainmentAction, DeceptionError,
    DecoyKind, JamboDeceptionDaemon, ProbeAction, TeeTrapVector, ThreatSeverity,
};

/// Exécute la suite complète de validation formelle du moteur de Cyber-Déception (Phase 152)
pub fn execute_deception_daemon_test() -> bool {
    kprintln!(
        "[DECEPTION/TEST] Démarrage de la validation cyber-déception, honeypots & pièges d'enclave TEE (Phase 152)..."
    );

    // 1. Contrôle d'accès capabilaire (DeceptionCap) et atténuation monotone
    let admin_cap = DeceptionCap::new(Handle::new(15201, 1), deception_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(deception_rights::DEPLOY_DECOY));
    assert!(admin_cap.has_right(deception_rights::TRIGGER_ALERT));
    assert!(admin_cap.has_right(deception_rights::PROBE_DECOY));
    assert!(admin_cap.has_right(deception_rights::PROFILE_ATTACKER));
    assert!(admin_cap.has_right(deception_rights::QUARANTINE));
    assert!(admin_cap.has_right(deception_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(deception_rights::AUDIT_READ));
    assert!(admin_cap.has_right(deception_rights::XDR_DISPATCH));
    assert!(admin_cap.has_right(deception_rights::TEE_TRAP_MANAGE));
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
    assert!(!monitor_cap.has_right(deception_rights::XDR_DISPATCH));
    assert_eq!(monitor_cap.max_lifetime, 2000);
    assert_eq!(monitor_cap.invocations_left, 50);

    // Rejet d'escalade
    assert_eq!(
        monitor_cap.attenuate(deception_rights::ALL, 2000, 50),
        Err(DeceptionError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et déploiement de la suite souveraine par défaut
    let mut deception = JamboDeceptionDaemon::new(admin_cap);
    deception.init_defaults();
    assert_eq!(deception.decoy_count, 7);
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

    // Vérification du profil comportemental (PrivilegeEscalation)
    let prof1 = deception.get_attacker_profile(4001).expect("Profil 4001");
    assert_eq!(prof1.hit_count, 1);
    assert_eq!(prof1.threat_score, 35);
    assert_eq!(prof1.level, AttackerLevel::PrivilegeEscalation);
    assert!(!prof1.quarantined);

    // 4. Validation des notifications O(1) vers XDR / SOAR (MITRE ATT&CK T1078)
    let notif1 = deception
        .pop_pending_xdr_notification(&admin_cap)
        .expect("Pop XDR")
        .expect("Notification HoneyCap XDR présente");
    assert_eq!(notif1.decoy_id, 1);
    assert_eq!(notif1.mitre_as_str(), "T1078");
    assert_eq!(
        notif1.recommended_action,
        DeceptionContainmentAction::RevokeHoneyCap
    );

    // 5. Validation des pièges à évasion d'enclave matérielle TEE (SEV-SNP / TDX / SGX)
    let alert_tee = deception
        .trigger_tee_escape_trap(&admin_cap, 4, TeeTrapVector::SevSnpVmsaPoisoning, 7777, 500)
        .expect("Piège évasion TEE");
    assert_eq!(alert_tee.decoy_kind, DecoyKind::EnclaveTrapDecoy);
    assert_eq!(alert_tee.severity, ThreatSeverity::Critical);
    assert_eq!(deception.tee_traps_fired, 1);

    let prof_tee = deception.get_attacker_profile(7777).expect("Profil 7777");
    assert_eq!(prof_tee.level, AttackerLevel::EnclaveEscapeAttempt);
    assert_eq!(prof_tee.threat_score, 50);

    // Deuxième tentative d'évasion d'enclave -> Quarantaine immédiate (score >= 70)
    deception
        .trigger_decoy(&admin_cap, 4, 7777, ProbeAction::EnclaveEscapeAttempt, 550)
        .expect("Deuxième sonde évasion TEE");
    let prof_tee2 = deception
        .get_attacker_profile(7777)
        .expect("Profil 7777 après");
    assert_eq!(prof_tee2.threat_score, 100);
    assert!(prof_tee2.quarantined);
    assert!(deception.total_quarantines >= 1);

    // Notification XDR pour l'évasion TEE (MITRE T1211)
    let notif_tee = deception
        .pop_pending_xdr_notification(&admin_cap)
        .expect("Pop XDR")
        .expect("Notification TEE");
    assert_eq!(notif_tee.mitre_as_str(), "T1211");
    assert_eq!(
        notif_tee.recommended_action,
        DeceptionContainmentAction::IsolateEnclave
    );

    // Dépiler la seconde notification TEE issue de la deuxième tentative
    let notif_tee2 = deception
        .pop_pending_xdr_notification(&admin_cap)
        .expect("Pop XDR")
        .expect("Seconde notification TEE");
    assert_eq!(notif_tee2.mitre_as_str(), "T1211");

    // 6. Validation du leurre de mouvement latéral (#7)
    let alert_lat = deception
        .trigger_decoy(&admin_cap, 7, 8888, ProbeAction::LateralMovementScan, 600)
        .expect("Déclenchement leurre latéral");
    assert_eq!(alert_lat.decoy_kind, DecoyKind::LateralMovementDecoy);
    let prof_lat = deception.get_attacker_profile(8888).expect("Profil 8888");
    assert_eq!(prof_lat.level, AttackerLevel::LateralMovement);

    let notif_lat = deception
        .pop_pending_xdr_notification(&admin_cap)
        .expect("Pop XDR")
        .expect("Notification Lateral");
    assert_eq!(notif_lat.mitre_as_str(), "T1021");
    assert_eq!(
        notif_lat.recommended_action,
        DeceptionContainmentAction::BlockLateralSubnet
    );

    // 7. Génération dynamique de leurres haute fidélité (HoneyCap & Faux Secret Ring 3)
    let dyn_honey = deception
        .generate_honey_cap(&admin_cap, "Dyn-HoneyCap-Admin", 0xCAFE, 0x1234_5678, 650)
        .expect("Génération dynamique HoneyCap");
    assert!(dyn_honey >= 8);

    let dyn_sec = deception
        .generate_fake_secret(
            &admin_cap,
            "Dyn-FakeKey-DiskXts",
            "XTS_MASTER_KEY_DECOY_BYTES_0123456789ABCDEF",
            "sec://crypto/xts_master.key",
            0xFEED_FACE,
            660,
        )
        .expect("Génération faux secret");
    assert!(dyn_sec >= 9);

    // 8. Confinement manuel et désactivation de leurre
    deception
        .trigger_decoy(&admin_cap, 5, 9999, ProbeAction::FileAccess, 700)
        .expect("Sonde canari fichier");
    let manual_q = deception
        .quarantine_attacker(&admin_cap, 9999, 710)
        .expect("Quarantaine manuelle");
    assert!(manual_q);
    let prof_man = deception.get_attacker_profile(9999).unwrap();
    assert!(prof_man.quarantined);
    assert_eq!(prof_man.threat_score, 100);

    // Désactivation du leurre #5
    deception
        .deactivate_decoy(&admin_cap, 5, 720)
        .expect("Désactivation leurre");
    let probe_dead = deception.trigger_decoy(&admin_cap, 5, 9999, ProbeAction::FileAccess, 730);
    assert_eq!(probe_dead, Err(DeceptionError::DecoyNotFound));

    // 9. Vérification formelle du registre d'audit et scellement SHA-256
    assert!(deception.verify_ledger_integrity());
    assert!(deception.audit_count >= 12);

    kprintln!(
        "[DECEPTION/TEST] \x1b[1;32mSuccès : HoneyCaps, faux secrets Ring 3, pièges d'enclave TEE SEV-SNP/TDX, mouvements latéraux, XDR O(1) & scellement SHA-256 validés ({} leurres, {} sondes, {} alertes, {} profils, {} quarantaines)\x1b[0m",
        deception.decoy_count,
        deception.total_probes,
        deception.alert_count,
        deception.profile_count,
        deception.total_quarantines
    );
    true
}

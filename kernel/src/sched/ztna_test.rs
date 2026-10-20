//! Module de validation formelle de l'Architecture Zero Trust & Micro-Périmètres (`jambo-ztna`)
//! Phase 123 — Jalon v0.2.121
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_ztna::{
    ztna_rights, AccessDecision, DevicePosture, JamboZtnaDaemon, MicroPerimeterPolicy,
    PostureStatus, ResourceKind, ZtnaCap, ZtnaError,
};

/// Exécute la suite complète de validation formelle du moteur Zero Trust ZTNA (Phase 123)
pub fn execute_ztna_daemon_test() -> bool {
    kprintln!(
        "[ZTNA/TEST] Démarrage de la validation de l'architecture Zero Trust & micro-périmètres (Phase 123)..."
    );

    // 1. Contrôle d'accès capabilaire (ZtnaCap) et atténuation monotone
    let admin_cap = ZtnaCap::new(Handle::new(12301, 1), ztna_rights::ALL, 5000, 100);
    assert!(admin_cap.has_right(ztna_rights::CREATE_POLICY));
    assert!(admin_cap.has_right(ztna_rights::EVALUATE_ACCESS));
    assert!(admin_cap.has_right(ztna_rights::UPDATE_POSTURE));
    assert!(admin_cap.has_right(ztna_rights::REVOKE_TRUST));
    assert!(admin_cap.has_right(ztna_rights::AUDIT_READ));
    assert!(admin_cap.has_right(ztna_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(ztna_rights::ADMIN));

    // Atténuation monotone
    let eval_cap = admin_cap
        .attenuate(
            ztna_rights::EVALUATE_ACCESS | ztna_rights::AUDIT_READ,
            2000,
            50,
        )
        .expect("Atténuation monotone ZtnaCap");
    assert!(eval_cap.has_right(ztna_rights::EVALUATE_ACCESS));
    assert!(eval_cap.has_right(ztna_rights::AUDIT_READ));
    assert!(!eval_cap.has_right(ztna_rights::ADMIN));
    assert!(!eval_cap.has_right(ztna_rights::CREATE_POLICY));
    assert!(!eval_cap.has_right(ztna_rights::REVOKE_TRUST));
    assert_eq!(eval_cap.max_lifetime, 2000);
    assert_eq!(eval_cap.invocations_left, 50);

    // Rejet d'escalade
    assert_eq!(
        eval_cap.attenuate(ztna_rights::ALL, 2000, 50),
        Err(ZtnaError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et vérification de l'état initial
    let mut ztna = JamboZtnaDaemon::new(admin_cap);
    ztna.init_defaults();
    assert_eq!(ztna.policy_count, 4);
    assert_eq!(ztna.device_count, 2);
    assert_eq!(ztna.total_evaluations, 0);
    assert!(ztna.verify_ledger_integrity());
    assert_ne!(ztna.ledger_hash, JamboZtnaDaemon::GENESIS_HASH);

    // 3. Validation de l'accès unitaire conforme (Device 1001 -> KMS)
    let dec1 = ztna
        .evaluate_access(&admin_cap, 501, 1001, "ipc://sys.sec.kms", 200)
        .expect("Évaluation accès conforme");
    match dec1 {
        AccessDecision::Granted {
            session_id,
            trust_score,
        } => {
            assert!(session_id > 0);
            assert!(trust_score >= 85);
        }
        _ => panic!("Accès KMS conforme aurait dû être accordé"),
    }
    assert_eq!(ztna.total_grants, 1);
    assert_eq!(ztna.session_count, 1);

    // Réutilisation de session éphémère
    let dec_repeat = ztna
        .evaluate_access(&admin_cap, 501, 1001, "ipc://sys.sec.kms", 210)
        .expect("Évaluation session existante");
    match dec_repeat {
        AccessDecision::Granted { session_id, .. } => {
            assert_eq!(session_id, 1);
        }
        _ => panic!("Échec de réutilisation de session"),
    }

    // 4. Validation du refus Zero Trust sur terminal non conforme / non attesté
    let dec_denied = ztna
        .evaluate_access(&admin_cap, 502, 1002, "ipc://sys.sec.kms", 220)
        .expect("Évaluation terminal non conforme");
    match dec_denied {
        AccessDecision::Denied { reason_code, .. } => {
            assert!(reason_code == 2 || reason_code == 1);
        }
        _ => panic!("Accès terminal non conforme aurait dû être refusé"),
    }
    assert_eq!(ztna.total_denials, 1);

    // 5. Validation de la ré-évaluation dynamique de posture et révocation de session
    // Device 1001 accède à enclave://sgx/vault
    let dec_tee = ztna
        .evaluate_access(&admin_cap, 777, 1001, "enclave://sgx/vault", 300)
        .expect("Accès enclave initial");
    assert!(matches!(dec_tee, AccessDecision::Granted { .. }));

    // Dégradation de posture du terminal 1001 (anomalie détectée -> 50)
    let updated_posture = ztna
        .update_device_posture(&admin_cap, 1001, 45, 30, false, 50, 310)
        .expect("Mise à jour posture dégradée");
    assert_eq!(updated_posture.posture_status, PostureStatus::NonCompliant);

    // Les sessions actives de ce terminal doivent être automatiquement révoquées
    assert!(ztna.sessions[0].unwrap().revoked);
    assert!(ztna.total_revocations >= 1);

    // Requête suivante bloquée
    let dec_blocked = ztna
        .evaluate_access(&admin_cap, 777, 1001, "enclave://sgx/vault", 320)
        .expect("Accès après dégradation");
    assert!(matches!(dec_blocked, AccessDecision::Denied { .. }));

    // 6. Révocation explicite / Quarantaine immédiate O(1)
    let p_reg = ztna
        .update_device_posture(&admin_cap, 2001, 95, 90, true, 0, 400)
        .expect("Enregistrement device 2001");
    assert_eq!(p_reg.posture_status, PostureStatus::Compliant);

    let dec_net = ztna
        .evaluate_access(&admin_cap, 999, 2001, "net://10.0.0.1:443", 410)
        .expect("Accès net");
    assert!(matches!(dec_net, AccessDecision::Granted { .. }));

    ztna.revoke_trust(&admin_cap, 2001, 420)
        .expect("Quarantaine 2001");
    let dev2001 = ztna.get_device_posture(2001).unwrap();
    assert_eq!(dev2001.posture_status, PostureStatus::Quarantined);
    assert_eq!(dev2001.composite_trust_score, 0);

    let dec_quar = ztna
        .evaluate_access(&admin_cap, 999, 2001, "net://10.0.0.1:443", 430)
        .expect("Accès après quarantaine");
    match dec_quar {
        AccessDecision::Denied { reason_code, .. } => {
            assert_eq!(reason_code, 3);
        }
        _ => panic!("Accès aurait dû être refusé pour terminal mis en quarantaine"),
    }

    // 7. Intégrité cryptographique SHA-256 du registre d'audit
    assert!(ztna.verify_ledger_integrity());
    assert!(ztna.audit_count >= 10);

    kprintln!(
        "[ZTNA/TEST] \x1b[1;32mSuccès : Architecture Zero Trust (ZTNA), micro-périmètres continus, ré-évaluation dynamique de posture, quarantaine & scellement SHA-256 validés ({} politiques, {} terminaux, {} évals, {} accords, {} refus, {} révocations)\x1b[0m",
        ztna.policy_count,
        ztna.device_count,
        ztna.total_evaluations,
        ztna.total_grants,
        ztna.total_denials,
        ztna.total_revocations
    );
    true
}

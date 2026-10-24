//! Module de validation formelle de la Gestion des Droits sur l'Infrastructure Cloud Souveraine CIEM (`jambo-ciem`)
//! Phase 157 — Jalon v0.3.24
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_ciem::{
    ciem_rights, entitlement_bits, CiemAction, CiemAnomalyType, CiemCap, CiemError,
    EntitlementScope, EntitlementStatus, IdentityKind, JamboCiemDaemon, RiskLevel,
};

/// Exécute la suite complète de validation formelle du démon CIEM souverain (Phase 157)
pub fn execute_ciem_daemon_test() -> bool {
    kprintln!(
        "[CIEM/TEST] Démarrage de la validation formelle CIEM, analyse des droits excessifs & moindre privilège (Phase 157 - v0.3.24)..."
    );

    // 1. Contrôle d'accès capabilaire (CiemCap) et atténuation monotone stricte
    let admin_cap = CiemCap::new(Handle::new(12701, 1), ciem_rights::ALL, 10000, 1000);
    assert!(admin_cap.has_right(ciem_rights::REGISTER_IDENTITY));
    assert!(admin_cap.has_right(ciem_rights::INSPECT_ENTITLEMENTS));
    assert!(admin_cap.has_right(ciem_rights::ANALYZE_EXCESS));
    assert!(admin_cap.has_right(ciem_rights::ENFORCE_LEAST_PRIV));
    assert!(admin_cap.has_right(ciem_rights::REVOKE_DORMANT));
    assert!(admin_cap.has_right(ciem_rights::MANAGE_POLICIES));
    assert!(admin_cap.has_right(ciem_rights::READ_METRICS));
    assert!(admin_cap.has_right(ciem_rights::SEAL_LEDGER));
    assert!(admin_cap.has_right(ciem_rights::ADMIN));

    // Atténuation monotone
    let monitor_cap = admin_cap
        .attenuate(
            ciem_rights::INSPECT_ENTITLEMENTS | ciem_rights::READ_METRICS,
            5000,
            200,
        )
        .expect("Atténuation monotone CiemCap");
    assert!(monitor_cap.has_right(ciem_rights::INSPECT_ENTITLEMENTS));
    assert!(monitor_cap.has_right(ciem_rights::READ_METRICS));
    assert!(!monitor_cap.has_right(ciem_rights::ENFORCE_LEAST_PRIV));
    assert!(!monitor_cap.has_right(ciem_rights::ADMIN));
    assert_eq!(monitor_cap.max_lifetime, 5000);
    assert_eq!(monitor_cap.invocations_left, 200);

    // Rejet d'escalade
    assert_eq!(
        monitor_cap.attenuate(ciem_rights::ALL, 5000, 200),
        Err(CiemError::AttenuationViolation)
    );

    // 2. Initialisation du démon central et cartographie par défaut
    let mut ciem = JamboCiemDaemon::new(admin_cap);
    ciem.init_defaults();
    assert_eq!(ciem.identity_count, 3);
    assert_eq!(ciem.entitlement_count, 4);
    assert_eq!(ciem.active_identities, 3);
    assert!(ciem.verify_ledger_integrity());

    // 3. Scan de cartographie au tick 2500 & analyse d'écarts (Entitlement Gap)
    let (checked, anomalies) = ciem
        .scan_all_entitlements(&admin_cap, 2500)
        .expect("Scan des cartographies CIEM");
    assert_eq!(checked, 4);
    assert!(anomalies >= 3);
    assert_eq!(ciem.total_scans, 1);
    assert!(ciem.verify_ledger_integrity());

    // Vérification de l'Entitlement Gap sur l'Ingress Gateway (E#202)
    let ent202_initial = ciem
        .entitlements
        .iter()
        .flatten()
        .find(|e| e.id == 202)
        .unwrap();
    assert_eq!(ent202_initial.excess_rights(), 0xF8);
    assert_eq!(ent202_initial.gap_percentage(), 62);
    assert!(ciem.average_gap_percentage() > 0);

    // 4. Réduction monotone vers le moindre privilège effectif O(1)
    let new_rights = ciem
        .enforce_least_privilege(&admin_cap, 202, 2600)
        .expect("Application moindre privilège O(1)");
    assert_eq!(new_rights, 0x07);

    let ent202 = ciem
        .entitlements
        .iter()
        .flatten()
        .find(|e| e.id == 202)
        .unwrap();
    assert_eq!(ent202.status, EntitlementStatus::Attenuated);
    assert_eq!(ent202.granted_rights, 0x07);
    assert_eq!(ent202.excess_rights(), 0);
    assert_eq!(ent202.gap_percentage(), 0);

    // Vérification de la génération du rapport de remédiation scellé SHA-256
    assert!(ciem.report_count > 0);
    let rep202 = ciem.latest_report().expect("Rapport scellé présent");
    assert_eq!(rep202.identity_id, 102);
    assert_eq!(rep202.entitlement_id, 202);
    assert_eq!(rep202.action, CiemAction::LeastPrivilegeEnforced);
    assert_eq!(rep202.initial_rights, 0xFF);
    assert_eq!(rep202.effective_rights, 0x07);

    // Rejet avec privilèges insuffisants
    assert_eq!(
        ciem.enforce_least_privilege(&monitor_cap, 202, 2650),
        Err(CiemError::PermissionDenied)
    );

    // 5. Révocation des privilèges dormants (Entitlement 203)
    let ok_rev = ciem
        .revoke_entitlement(&admin_cap, 203, 2700)
        .expect("Révocation privilèges dormants");
    assert!(ok_rev);

    let ent203 = ciem
        .entitlements
        .iter()
        .flatten()
        .find(|e| e.id == 203)
        .unwrap();
    assert_eq!(ent203.status, EntitlementStatus::Revoked);
    assert_eq!(ent203.granted_rights, 0);

    // 6. Injection et neutralisation chirurgicale d'une combinaison toxique
    let id_toxic = ciem
        .register_identity(
            &admin_cap,
            104,
            "secnum-mesh-agent",
            IdentityKind::WorkloadAgent,
            2750,
        )
        .expect("Enregistrement agent secnum");
    let toxic_rights = entitlement_bits::IAM_ADMIN
        | entitlement_bits::SECRETS_READ
        | entitlement_bits::NETWORK_EGRESS
        | entitlement_bits::STORAGE_READ;
    let eid_toxic = ciem
        .grant_entitlement(
            &admin_cap,
            205,
            id_toxic,
            EntitlementScope::SecurityServices,
            toxic_rights,
            5000,
            2760,
        )
        .expect("Attribution entitlement toxique");

    // L'agent n'exerce en réalité que STORAGE_READ
    ciem.record_usage(
        &admin_cap,
        id_toxic,
        eid_toxic,
        entitlement_bits::STORAGE_READ,
        2770,
    )
    .expect("Usage partiel");

    // Scan pour détection de la combinaison toxique
    let (_, anom_toxic) = ciem
        .scan_all_entitlements(&admin_cap, 2780)
        .expect("Scan combinaison toxique");
    assert!(anom_toxic > 0);

    let ent_toxic_before = ciem
        .entitlements
        .iter()
        .flatten()
        .find(|e| e.id == eid_toxic)
        .unwrap();
    assert!(ent_toxic_before.has_toxic_combination());
    assert_eq!(ent_toxic_before.risk, RiskLevel::Critical);

    // Neutralisation O(1) par enforcement du moindre privilège
    let purged_rights = ciem
        .enforce_least_privilege(&admin_cap, eid_toxic, 2790)
        .expect("Neutralisation combinaison toxique");
    assert_eq!(purged_rights, entitlement_bits::STORAGE_READ);

    let ent_toxic_after = ciem
        .entitlements
        .iter()
        .flatten()
        .find(|e| e.id == eid_toxic)
        .unwrap();
    assert!(!ent_toxic_after.has_toxic_combination());
    assert_eq!(ent_toxic_after.risk, RiskLevel::Low);

    // 7. Remédiation globale automatique des anomalies orphelines restantes
    let rem_count = ciem
        .remediate_all(&admin_cap, 2800)
        .expect("Remédiation globale CIEM");
    assert!(rem_count >= 1);

    // 8. Vérification stricte de l'intégrité cryptographique du registre d'audit SHA-256
    assert!(ciem.verify_ledger_integrity());

    kprintln!(
        "[CIEM/TEST] \x1b[1;32mSuccès de la validation formelle CIEM (Phase 157 - v0.3.24) : {} identités ({} actives), {} droits cartographiés, {} anomalies détectées, {} remédiations Moindre Privilège scellées SHA-256\x1b[0m",
        ciem.identity_count,
        ciem.active_identities,
        ciem.entitlement_count,
        ciem.total_anomalies_detected,
        ciem.total_remediations
    );

    true
}

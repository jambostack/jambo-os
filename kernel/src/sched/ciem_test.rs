//! Module de validation formelle de la Gestion des Droits et Privilèges Cloud/Grappe (CIEM) (`jambo-ciem`)
//! Phase 127 — Jalon v0.2.125
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::Handle;
use jambo_ciem::{
    ciem_rights, CiemAnomalyType, CiemCap, CiemError, EntitlementScope, EntitlementStatus,
    IdentityKind, JamboCiemDaemon, RiskLevel,
};

/// Exécute la suite complète de validation formelle du démon CIEM (Phase 127)
pub fn execute_ciem_daemon_test() -> bool {
    kprintln!(
        "[CIEM/TEST] Démarrage de la validation formelle de la gestion des droits et privilèges cloud/grappe (Phase 127)..."
    );

    // 1. Contrôle d'accès capabilaire (CiemCap) et atténuation monotone
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

    // 3. Scan de cartographie au tick 2500
    let (checked, anomalies) = ciem
        .scan_all_entitlements(&admin_cap, 2500)
        .expect("Scan des cartographies CIEM");
    assert_eq!(checked, 4);
    assert!(anomalies >= 3);
    assert_eq!(ciem.total_scans, 1);
    assert!(ciem.verify_ledger_integrity());

    // 4. Réduction monotone vers le moindre privilège effectif (Least-Privilege Monotonic Attenuation)
    // Entitlement 202 (jambo-ingress-gw) a granted 0xFF mais exercised 0x07
    let new_rights = ciem
        .enforce_least_privilege(&admin_cap, 202, 2600)
        .expect("Application moindre privilège");
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

    // 6. Remédiation globale automatique des anomalies restantes (ex: purge orphelin 204)
    let rem_count = ciem
        .remediate_all(&admin_cap, 2800)
        .expect("Remédiation globale CIEM");
    assert!(rem_count >= 1);

    // 7. Vérification de l'intégrité cryptographique du registre d'audit SHA-256
    assert!(ciem.verify_ledger_integrity());

    kprintln!(
        "[CIEM/TEST] \x1b[1;32mSuccès de la validation formelle CIEM : {} identités ({} actives), {} droits cartographiés, {} anomalies détectées, {} remédiations Moindre Privilège scellées SHA-256\x1b[0m",
        ciem.identity_count,
        ciem.active_identities,
        ciem.entitlement_count,
        ciem.total_anomalies_detected,
        ciem.total_remediations
    );

    true
}

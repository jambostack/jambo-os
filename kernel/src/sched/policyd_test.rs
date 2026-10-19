//! Module de validation du Moteur Déclaratif de Politiques & Admission Control (Phase 69 - v0.2.67)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_policyd::{
    actions, policy_rights, roles, AdmissionDecision, AdmissionRequest, JamboPolicyDaemon,
    PolicyCap, PolicyEffect, PolicyEngine, PolicyRule,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du moteur déclaratif de politiques et admission control (Phase 69)
pub fn execute_policy_engine_test() -> bool {
    kprintln!(
        "[POLICY/TEST] Démarrage du test du moteur déclaratif de politiques et admission control (Phase 69)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (PolicyCap)
    let admin_cap = PolicyCap::new(Handle::new(69, 1), policy_rights::ALL);
    assert!(admin_cap.has_right(policy_rights::POLICY_EVALUATE));
    assert!(admin_cap.has_right(policy_rights::POLICY_RULE_ADD));
    assert!(admin_cap.has_right(policy_rights::POLICY_RULE_DEL));
    assert!(admin_cap.has_right(policy_rights::POLICY_AUDIT));
    assert!(admin_cap.has_right(policy_rights::POLICY_ADMIN));

    let eval_only_cap = admin_cap
        .attenuate(policy_rights::POLICY_EVALUATE)
        .expect("attenuate PolicyCap to eval-only");
    let mut raw_engine = PolicyEngine::new();
    let dummy_rule = PolicyRule::new(
        1,
        roles::ROLE_SYSTEM,
        actions::ACTION_ADMIN,
        b"admin/",
        PolicyEffect::Allow,
        10,
        0,
    )
    .expect("create rule");
    assert_eq!(
        raw_engine.add_rule(&eval_only_cap, dummy_rule),
        Err(SysError::PermissionDenied),
        "Ajout de règle sans droit POLICY_RULE_ADD doit être rejeté"
    );
    kprintln!("[POLICY/CAP] Confinement capabilaire PolicyCap et autorité ambiante zéro validés");

    // 2. Principe fondamental de sécurité Deny-by-default
    let mut engine = PolicyEngine::new();
    let req_unmatched = AdmissionRequest::new(
        100,
        roles::ROLE_WORKLOAD,
        actions::ACTION_SPAWN_WORKLOAD,
        b"workloads/unknown-task",
        1000,
    )
    .expect("create req");
    let decision = engine
        .evaluate(&admin_cap, &req_unmatched)
        .expect("eval deny");
    assert_eq!(
        decision,
        AdmissionDecision::Denied {
            reason: "Default Deny: no matching allow rule",
            matching_rule_id: None,
        }
    );
    kprintln!("[POLICY/DENY] Principe fondamental de sécurité Deny-by-default validé");

    // 3. Préséance stricte du refus explicite (Deny) sur l'autorisation
    let rule_allow = PolicyRule::new(
        1,
        roles::ROLE_WORKLOAD,
        actions::ACTION_ACCESS_SECRET,
        b"workloads/",
        PolicyEffect::Allow,
        5,
        0,
    )
    .expect("rule allow");
    let rule_deny = PolicyRule::new(
        2,
        roles::ROLE_WORKLOAD,
        actions::ACTION_ACCESS_SECRET,
        b"workloads/restricted",
        PolicyEffect::Deny,
        10,
        0,
    )
    .expect("rule deny");

    engine.add_rule(&admin_cap, rule_allow).expect("add allow");
    engine.add_rule(&admin_cap, rule_deny).expect("add deny");

    let req_public = AdmissionRequest::new(
        101,
        roles::ROLE_WORKLOAD,
        actions::ACTION_ACCESS_SECRET,
        b"workloads/public-app",
        1000,
    )
    .expect("req public");
    assert_eq!(
        engine
            .evaluate(&admin_cap, &req_public)
            .expect("eval allow"),
        AdmissionDecision::Allowed
    );

    let req_restricted = AdmissionRequest::new(
        102,
        roles::ROLE_WORKLOAD,
        actions::ACTION_ACCESS_SECRET,
        b"workloads/restricted/db",
        1000,
    )
    .expect("req restricted");
    assert_eq!(
        engine
            .evaluate(&admin_cap, &req_restricted)
            .expect("eval deny"),
        AdmissionDecision::Denied {
            reason: "Explicit policy Deny matched",
            matching_rule_id: Some(2),
        }
    );
    kprintln!(
        "[POLICY/PRECEDENCE] Préséance stricte du refus explicite (Deny) sur l'autorisation validée"
    );

    // 4. Expiration temporelle de règles et purge déterministe
    let rule_timed = PolicyRule::new(
        10,
        roles::ROLE_ANY,
        actions::ACTION_ROUTE_TRAFFIC,
        b"routes/",
        PolicyEffect::Allow,
        1,
        1500,
    )
    .expect("timed rule");
    engine
        .add_rule(&admin_cap, rule_timed)
        .expect("add timed rule");

    let req_before = AdmissionRequest::new(
        50,
        roles::ROLE_WORKLOAD,
        actions::ACTION_ROUTE_TRAFFIC,
        b"routes/mesh-1",
        1400,
    )
    .expect("req before");
    assert_eq!(
        engine
            .evaluate(&admin_cap, &req_before)
            .expect("eval before"),
        AdmissionDecision::Allowed
    );

    let req_after = AdmissionRequest::new(
        50,
        roles::ROLE_WORKLOAD,
        actions::ACTION_ROUTE_TRAFFIC,
        b"routes/mesh-1",
        1600,
    )
    .expect("req after");
    assert_eq!(
        engine.evaluate(&admin_cap, &req_after).expect("eval after"),
        AdmissionDecision::Denied {
            reason: "Default Deny: no matching allow rule",
            matching_rule_id: None,
        }
    );
    let purged = engine.purge_expired(1600);
    assert_eq!(purged, 1);
    kprintln!("[POLICY/LEASE] Expiration temporelle de règles et purge déterministe validées");

    // 5. Démon orchestrateur JamboPolicyDaemon
    let mut daemon = JamboPolicyDaemon::new();
    assert_eq!(daemon.rule_count(), 2);
    let req_daemon_sys = AdmissionRequest::new(
        1,
        roles::ROLE_SYSTEM,
        actions::ACTION_ADMIN,
        b"admin/kernel",
        100,
    )
    .expect("daemon sys req");
    assert_eq!(
        daemon.evaluate(&req_daemon_sys).expect("d eval sys"),
        AdmissionDecision::Allowed
    );

    let req_daemon_guest = AdmissionRequest::new(
        2,
        roles::ROLE_GUEST,
        actions::ACTION_ACCESS_SECRET,
        b"secrets/master-key",
        100,
    )
    .expect("daemon guest req");
    match daemon.evaluate(&req_daemon_guest).expect("d eval guest") {
        AdmissionDecision::Denied { .. } => {}
        _ => panic!("Guest secret access must be denied"),
    }
    let (evals, allows, denies) = daemon.stats().expect("d stats");
    assert_eq!(evals, 2);
    assert_eq!(allows, 1);
    assert_eq!(denies, 1);
    kprintln!("[POLICY/DAEMON] Démon JamboPolicyDaemon opérationnel");

    // 6. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'policy status'
    let (st_stat, len_stat) = shell.execute_line("policy status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("POLITIQUES DE SÉCURITÉ"));
    assert!(str_stat.contains("Règles déclaratives"));
    assert!(str_stat.contains("PolicyCap"));
    kprintln!("[POLICY/SHELL] Commande 'policy status' validée");

    // Commande 'policy eval system admin/subsystem'
    let (st_eval1, len_eval1) =
        shell.execute_line("policy eval system admin/subsystem", &mut out_buf);
    assert_eq!(st_eval1, ShellStatus::Success);
    let str_eval1 = core::str::from_utf8(&out_buf[..len_eval1]).unwrap_or("");
    assert!(str_eval1.contains("[POLICY/EVAL]"));
    assert!(str_eval1.contains("AUTORISÉ (Allowed)"));
    kprintln!("[POLICY/SHELL] Commande 'policy eval (système)' validée");

    // Commande 'policy eval guest secrets/keys'
    let (st_eval2, len_eval2) = shell.execute_line("policy eval guest secrets/keys", &mut out_buf);
    assert_eq!(st_eval2, ShellStatus::Success);
    let str_eval2 = core::str::from_utf8(&out_buf[..len_eval2]).unwrap_or("");
    assert!(str_eval2.contains("[POLICY/EVAL]"));
    assert!(str_eval2.contains("REJETÉ (Denied)"));
    kprintln!("[POLICY/SHELL] Commande 'policy eval (invité)' validée");

    // Commande 'policy add 50 public/'
    let (st_add, len_add) = shell.execute_line("policy add 50 public/", &mut out_buf);
    assert_eq!(st_add, ShellStatus::Success);
    let str_add = core::str::from_utf8(&out_buf[..len_add]).unwrap_or("");
    assert!(str_add.contains("[POLICY/ADD]"));
    assert!(str_add.contains("Règle #50"));
    kprintln!("[POLICY/SHELL] Commande 'policy add' validée");

    kprintln!(
        "[POLICY/PASS] Moteur déclaratif de politiques et admission control validés avec succès."
    );
    true
}

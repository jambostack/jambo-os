//! Module de validation de la Découverte de Services & Résolution de Noms (Phase 68 - v0.2.66)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_serviced::{discovery_rights, DiscoveryCap, JamboServiceDaemon, ServiceRegistry};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de découverte de services et résolution de noms (Phase 68)
pub fn execute_service_discovery_test() -> bool {
    kprintln!(
        "[SERVICE/TEST] Démarrage du test de découverte de services et résolution de noms (Phase 68)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (DiscoveryCap)
    let admin_cap = DiscoveryCap::new(Handle::new(68, 1), discovery_rights::ALL);
    assert!(admin_cap.has_right(discovery_rights::DISCOVERY_REGISTER));
    assert!(admin_cap.has_right(discovery_rights::DISCOVERY_RESOLVE));
    assert!(admin_cap.has_right(discovery_rights::DISCOVERY_DEREGISTER));
    assert!(admin_cap.has_right(discovery_rights::DISCOVERY_HEARTBEAT));
    assert!(admin_cap.has_right(discovery_rights::DISCOVERY_ADMIN));

    let resolve_only_cap = admin_cap
        .attenuate(discovery_rights::DISCOVERY_RESOLVE)
        .expect("attenuate DiscoveryCap to resolve-only");
    let mut raw_registry = ServiceRegistry::new();
    assert_eq!(
        raw_registry.register_instance(
            &resolve_only_cap,
            b"test.svc",
            1,
            [127, 0, 0, 1],
            80,
            1,
            60,
            100,
        ),
        Err(SysError::PermissionDenied),
        "Enregistrement sans droit DISCOVERY_REGISTER doit être rejeté"
    );
    kprintln!(
        "[SERVICE/CAP] Confinement capabilaire DiscoveryCap et autorité ambiante zéro validés"
    );

    // 2. Enregistrement multi-instances et résolution sémantique
    let mut registry = ServiceRegistry::new();
    registry
        .register_instance(
            &admin_cap,
            b"auth.service",
            101,
            [10, 0, 1, 10],
            8000,
            1,
            60,
            1000,
        )
        .expect("register auth 1");
    registry
        .register_instance(
            &admin_cap,
            b"auth.service",
            102,
            [10, 0, 1, 11],
            8000,
            2,
            60,
            1000,
        )
        .expect("register auth 2");

    let mut eps = [([0u8; 4], 0u16); 4];
    let count = registry
        .resolve(&admin_cap, b"auth.service", 1020, &mut eps)
        .expect("resolve auth");
    assert_eq!(count, 2);
    assert_eq!(eps[0], ([10, 0, 1, 10], 8000));
    assert_eq!(eps[1], ([10, 0, 1, 11], 8000));
    kprintln!("[SERVICE/RESOLVE] Enregistrement multi-instances et résolution sémantique validés");

    // 3. Renouvellement de bail et éviction automatique par TTL
    registry
        .register_instance(
            &admin_cap,
            b"kvd.service",
            201,
            [10, 0, 2, 5],
            7000,
            1,
            10,
            100,
        )
        .expect("register kvd");

    let mut kvd_eps = [([0u8; 4], 0u16); 2];
    assert_eq!(
        registry
            .resolve(&admin_cap, b"kvd.service", 105, &mut kvd_eps)
            .expect("resolve alive"),
        1
    );
    // Après TTL (100 + 10 = 110)
    assert_eq!(
        registry
            .resolve(&admin_cap, b"kvd.service", 115, &mut kvd_eps)
            .expect("resolve expired"),
        0
    );
    let purged = registry.purge_expired(115);
    assert_eq!(purged, 1);
    assert_eq!(registry.instance_count(b"kvd.service").expect("count"), 0);
    kprintln!("[SERVICE/LEASE] Renouvellement de bail et éviction automatique par TTL validés");

    // 4. Retrait ordonné d'instance (dé-enregistrement)
    registry
        .register_instance(
            &admin_cap,
            b"gw.service",
            301,
            [10, 0, 3, 1],
            9000,
            1,
            60,
            100,
        )
        .expect("register gw");
    assert_eq!(registry.instance_count(b"gw.service").expect("count gw"), 1);
    registry
        .deregister_instance(&admin_cap, b"gw.service", 301)
        .expect("deregister gw");
    assert_eq!(
        registry.instance_count(b"gw.service").expect("count gw 0"),
        0
    );
    kprintln!("[SERVICE/DEREGISTER] Retrait ordonné d'instance validé");

    // 5. Démon orchestrateur JamboServiceDaemon
    let mut daemon = JamboServiceDaemon::new();
    assert_eq!(daemon.service_count(), 2);
    assert_eq!(
        daemon.instance_count(b"kvd.service").expect("d count kvd"),
        1
    );

    let mut d_eps = [([0u8; 4], 0u16); 4];
    let d_n = daemon
        .resolve(b"kvd.service", 150, &mut d_eps)
        .expect("d resolve");
    assert_eq!(d_n, 1);
    assert_eq!(d_eps[0], ([127, 0, 0, 1], 7001));

    daemon
        .register(b"api.service", 10, [192, 168, 1, 50], 443, 2, 60, 200)
        .expect("d register");
    assert_eq!(daemon.service_count(), 3);
    assert_eq!(
        daemon.instance_count(b"api.service").expect("d count api"),
        1
    );
    daemon.heartbeat(b"api.service", 10, 210).expect("d hb");
    daemon.deregister(b"api.service", 10).expect("d dereg");
    assert_eq!(
        daemon
            .instance_count(b"api.service")
            .expect("d count api 0"),
        0
    );
    kprintln!("[SERVICE/DAEMON] Démon JamboServiceDaemon opérationnel");

    // 6. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'service status'
    let (st_stat, len_stat) = shell.execute_line("service status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("DÉCOUVERTE DE SERVICES DISTRIBUÉE"));
    assert!(str_stat.contains("Services déclarés"));
    assert!(str_stat.contains("DiscoveryCap"));
    kprintln!("[SERVICE/SHELL] Commande 'service status' validée");

    // Commande 'service resolve'
    let (st_resolve, len_resolve) = shell.execute_line("service resolve kvd.service", &mut out_buf);
    assert_eq!(st_resolve, ShellStatus::Success);
    let str_resolve = core::str::from_utf8(&out_buf[..len_resolve]).unwrap_or("");
    assert!(str_resolve.contains("[SERVICE/RESOLVE]"));
    assert!(str_resolve.contains("127.0.0.1:7001"));
    kprintln!("[SERVICE/SHELL] Commande 'service resolve' validée");

    // Commande 'service register'
    let (st_reg, len_reg) = shell.execute_line("service register api.service 42", &mut out_buf);
    assert_eq!(st_reg, ShellStatus::Success);
    let str_reg = core::str::from_utf8(&out_buf[..len_reg]).unwrap_or("");
    assert!(str_reg.contains("[SERVICE/REGISTER]"));
    assert!(str_reg.contains("api.service"));
    kprintln!("[SERVICE/SHELL] Commande 'service register' validée");

    // Commande 'service heartbeat'
    let (st_hb, len_hb) = shell.execute_line("service heartbeat api.service 42", &mut out_buf);
    assert_eq!(st_hb, ShellStatus::Success);
    let str_hb = core::str::from_utf8(&out_buf[..len_hb]).unwrap_or("");
    assert!(str_hb.contains("[SERVICE/HEARTBEAT]"));
    kprintln!("[SERVICE/SHELL] Commande 'service heartbeat' validée");

    // Commande 'service deregister'
    let (st_dereg, len_dereg) =
        shell.execute_line("service deregister api.service 42", &mut out_buf);
    assert_eq!(st_dereg, ShellStatus::Success);
    let str_dereg = core::str::from_utf8(&out_buf[..len_dereg]).unwrap_or("");
    assert!(str_dereg.contains("[SERVICE/DEREGISTER]"));
    kprintln!("[SERVICE/SHELL] Commande 'service deregister' validée");

    kprintln!("[SERVICE/PASS] Découverte de services et résolution de noms validées avec succès.");
    true
}

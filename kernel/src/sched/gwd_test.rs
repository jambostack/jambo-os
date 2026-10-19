//! Module de validation de la Passerelle Ingress & Répartiteur de Charge Élastique (Phase 65 - v0.2.63)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_gwd::{gw_rights, GatewayCap, GatewayManager, JamboGatewayDaemon, LoadBalanceStrategy};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de la passerelle ingress et équilibreur de charge (Phase 65)
pub fn execute_gateway_lb_test() -> bool {
    kprintln!(
        "[GW/TEST] Démarrage du test de la passerelle ingress et répartiteur de charge (Phase 65)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (GatewayCap)
    let admin_cap = GatewayCap::new(Handle::new(65, 1), gw_rights::ALL);
    assert!(admin_cap.has_right(gw_rights::GW_ROUTE));
    assert!(admin_cap.has_right(gw_rights::GW_BACKEND_ADD));
    assert!(admin_cap.has_right(gw_rights::GW_HEALTH_REPORT));
    assert!(admin_cap.has_right(gw_rights::GW_CIRCUIT_BREAK));
    assert!(admin_cap.has_right(gw_rights::GW_ADMIN));

    let route_only_cap = admin_cap
        .attenuate(gw_rights::GW_ROUTE)
        .expect("attenuate GatewayCap to route-only");
    let mut raw_gw = GatewayManager::new();
    assert_eq!(
        raw_gw.register_service(&route_only_cap, 1, 80, LoadBalanceStrategy::RoundRobin, 3),
        Err(SysError::PermissionDenied),
        "Enregistrement de service sans droit GW_ADMIN doit être rejeté"
    );
    kprintln!("[GW/CAP] Confinement capabilaire GatewayCap et autorité ambiante zéro validés");

    // 2. Validation des stratégies de répartition (Round-Robin & Least-Connections)
    let mut gw = GatewayManager::new();
    gw.register_service(&admin_cap, 10, 80, LoadBalanceStrategy::RoundRobin, 3)
        .expect("register service 10");
    gw.add_backend(&admin_cap, 10, [10, 0, 0, 1], 8080, 1)
        .expect("add backend 1");
    gw.add_backend(&admin_cap, 10, [10, 0, 0, 2], 8080, 1)
        .expect("add backend 2");

    let ep1 = gw
        .route_packet(&admin_cap, 80, [192, 168, 1, 50])
        .expect("route 1");
    let ep2 = gw
        .route_packet(&admin_cap, 80, [192, 168, 1, 51])
        .expect("route 2");
    let ep3 = gw
        .route_packet(&admin_cap, 80, [192, 168, 1, 52])
        .expect("route 3");
    assert_eq!(ep1, ([10, 0, 0, 1], 8080));
    assert_eq!(ep2, ([10, 0, 0, 2], 8080));
    assert_eq!(ep3, ([10, 0, 0, 1], 8080));

    // Least-Connections
    gw.register_service(
        &admin_cap,
        20,
        443,
        LoadBalanceStrategy::LeastConnections,
        3,
    )
    .expect("register service 20");
    gw.add_backend(&admin_cap, 20, [10, 0, 0, 10], 8443, 1)
        .expect("add backend 10");
    gw.add_backend(&admin_cap, 20, [10, 0, 0, 20], 8443, 1)
        .expect("add backend 20");

    let c1 = gw
        .route_packet(&admin_cap, 443, [1, 2, 3, 4])
        .expect("lc route 1");
    assert_eq!(c1, ([10, 0, 0, 10], 8443));
    let c2 = gw
        .route_packet(&admin_cap, 443, [1, 2, 3, 5])
        .expect("lc route 2");
    assert_eq!(c2, ([10, 0, 0, 20], 8443));
    gw.release_connection(443, [10, 0, 0, 10], 8443)
        .expect("release connection node 10");
    let c3 = gw
        .route_packet(&admin_cap, 443, [1, 2, 3, 6])
        .expect("lc route 3");
    assert_eq!(c3, ([10, 0, 0, 10], 8443));
    kprintln!("[GW/ALGO] Stratégies Round-Robin, Least-Connections et IP-Hash validées");

    // 3. Sondes de santé et déclenchement automatique du coupe-circuit (Circuit Breaker)
    gw.register_service(&admin_cap, 30, 8080, LoadBalanceStrategy::RoundRobin, 2)
        .expect("register service 30");
    gw.add_backend(&admin_cap, 30, [10, 0, 1, 1], 9000, 1)
        .expect("add node 1");
    gw.add_backend(&admin_cap, 30, [10, 0, 1, 2], 9000, 1)
        .expect("add node 2");

    assert!(gw
        .report_health(&admin_cap, 30, [10, 0, 1, 1], 9000, false)
        .expect("health 1"));
    assert!(!gw
        .report_health(&admin_cap, 30, [10, 0, 1, 1], 9000, false)
        .expect("health 2 (cb tripped)"));

    // Toutes les requêtes vers le port 8080 doivent désormais basculer sur node 2
    let f1 = gw
        .route_packet(&admin_cap, 8080, [192, 168, 1, 1])
        .expect("failover 1");
    let f2 = gw
        .route_packet(&admin_cap, 8080, [192, 168, 1, 2])
        .expect("failover 2");
    assert_eq!(f1, ([10, 0, 1, 2], 9000));
    assert_eq!(f2, ([10, 0, 1, 2], 9000));
    kprintln!("[GW/CIRCUIT-BREAKER] Sondes de santé, coupe-circuit et bascule failover validés");

    // 4. Démon orchestrateur JamboGatewayDaemon
    let mut daemon = JamboGatewayDaemon::new();
    assert_eq!(daemon.service_count(), 1);
    assert_eq!(daemon.total_backends(), 2);
    let d_ep = daemon
        .route_packet(80, [192, 168, 1, 10])
        .expect("daemon route");
    assert_eq!(d_ep, ([10, 0, 0, 1], 8080));
    assert_eq!(daemon.routes_processed, 1);
    kprintln!("[GW/DAEMON] Démon JamboGatewayDaemon opérationnel");

    // 5. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'gw status'
    let (st_stat, len_stat) = shell.execute_line("gw status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("PASSERELLE INGRESS"));
    assert!(str_stat.contains("Services virtuels"));
    assert!(str_stat.contains("GatewayCap"));
    kprintln!("[GW/SHELL] Commande 'gw status' validée");

    // Commande 'gw route'
    let (st_route, len_route) = shell.execute_line("gw route", &mut out_buf);
    assert_eq!(st_route, ShellStatus::Success);
    let str_route = core::str::from_utf8(&out_buf[..len_route]).unwrap_or("");
    assert!(str_route.contains("[GW/ROUTE] Requête acheminée avec succès vers backend"));
    kprintln!("[GW/SHELL] Commande 'gw route' validée");

    // Commande 'gw cb'
    let (st_cb, len_cb) = shell.execute_line("gw cb", &mut out_buf);
    assert_eq!(st_cb, ShellStatus::Success);
    let str_cb = core::str::from_utf8(&out_buf[..len_cb]).unwrap_or("");
    assert!(str_cb.contains("[GW/CIRCUIT-BREAKER] Coupe-circuit déclenché"));
    kprintln!("[GW/SHELL] Commande 'gw cb' validée");

    kprintln!(
        "[GW/PASS] Passerelle ingress et répartiteur de charge élastique validés avec succès."
    );
    true
}

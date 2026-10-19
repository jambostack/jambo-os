//! Module de validation du Bus d'Événements Asynchrone Zéro-Copie (Phase 62 - v0.2.60)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_eventd::{event_rights, EventBus, EventCap, EventMessage, JamboEventDaemon};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du bus d'événements pub/sub zéro-copie (Phase 62)
pub fn execute_event_bus_test() -> bool {
    kprintln!("[EVENT/TEST] Démarrage du test du bus d'événements asynchrone (Phase 62)...");

    // 1. Validation du contrôle d'accès capabilaire (EventCap)
    let admin_cap = EventCap::new(Handle::new(62, 1), event_rights::ALL);
    assert!(admin_cap.has_right(event_rights::EVENT_PUBLISH));
    assert!(admin_cap.has_right(event_rights::EVENT_SUBSCRIBE));
    assert!(admin_cap.has_right(event_rights::EVENT_DRAIN));

    let unauth_cap = EventCap::new(Handle::new(62, 2), 0);
    let mut raw_bus = EventBus::new();
    assert_eq!(
        raw_bus.subscribe(&unauth_cap, b"sys/alerts", false),
        Err(SysError::PermissionDenied),
        "Souscription sans droit EVENT_SUBSCRIBE doit être rejetée"
    );
    assert_eq!(
        raw_bus.publish(&unauth_cap, 10, b"sys/alerts", b"PAYLOAD", 100),
        Err(SysError::PermissionDenied),
        "Publication sans droit EVENT_PUBLISH doit être rejetée"
    );
    kprintln!("[EVENT/CAP] Confinement capabilaire EventCap et autorité ambiante zéro validés");

    // 2. Filtrage exact et par préfixe hiérarchique
    let sub_prefix = raw_bus
        .subscribe(&admin_cap, b"cluster/", true)
        .expect("subscribe prefix");
    let sub_exact = raw_bus
        .subscribe(&admin_cap, b"cluster/heartbeat", false)
        .expect("subscribe exact");

    // Événement matchant les deux
    let seq1 = raw_bus
        .publish(&admin_cap, 1, b"cluster/heartbeat", b"NODE_ALIVE", 200)
        .expect("publish 1");
    assert_eq!(seq1, 1);

    // Événement matchant uniquement le préfixe
    let seq2 = raw_bus
        .publish(&admin_cap, 1, b"cluster/metrics", b"CPU_LOAD_42", 201)
        .expect("publish 2");
    assert_eq!(seq2, 2);

    let m_pref1 = raw_bus
        .poll_event(&admin_cap, sub_prefix)
        .expect("poll prefix")
        .unwrap();
    let m_pref2 = raw_bus
        .poll_event(&admin_cap, sub_prefix)
        .expect("poll prefix 2")
        .unwrap();
    assert_eq!(m_pref1.payload_bytes(), b"NODE_ALIVE");
    assert_eq!(m_pref2.payload_bytes(), b"CPU_LOAD_42");

    let m_exact = raw_bus
        .poll_event(&admin_cap, sub_exact)
        .expect("poll exact")
        .unwrap();
    assert_eq!(m_exact.payload_bytes(), b"NODE_ALIVE");
    assert!(raw_bus
        .poll_event(&admin_cap, sub_exact)
        .expect("poll exact empty")
        .is_none());
    kprintln!("[EVENT/FILTER] Filtrage par préfixe et routage exact validés");

    // 3. File d'attente circulaire et politique de dépassement Drop-Oldest
    let sub_stream = raw_bus
        .subscribe(&admin_cap, b"sensor/stream", false)
        .expect("subscribe stream");
    for i in 0..10 {
        let mut p = [0u8; 1];
        p[0] = i as u8;
        raw_bus
            .publish(&admin_cap, 2, b"sensor/stream", &p, 300 + i as u64)
            .expect("pub stream");
    }
    let oldest_kept = raw_bus
        .poll_event(&admin_cap, sub_stream)
        .expect("poll stream")
        .unwrap();
    assert_eq!(
        oldest_kept.payload_bytes()[0],
        2,
        "Les messages 0 et 1 doivent avoir été évincés (queue=8)"
    );
    kprintln!("[EVENT/QUEUE] File circulaire bornée et politique drop-oldest validées");

    // 4. Démon orchestrateur JamboEventDaemon
    let mut daemon = JamboEventDaemon::new();
    assert_eq!(daemon.active_subscriptions_count(), 1); // default system/
    let sub_app = daemon
        .subscribe(b"apps/worker", false)
        .expect("sub daemon app");
    let pub_seq = daemon
        .publish(100, b"apps/worker", b"WORKER_STARTED", 400)
        .expect("pub daemon");
    assert_eq!(pub_seq, 1);
    let polled = daemon.poll(sub_app).expect("poll daemon").unwrap();
    assert_eq!(polled.payload_bytes(), b"WORKER_STARTED");
    daemon.unsubscribe(sub_app).expect("unsub daemon");
    kprintln!("[EVENT/DAEMON] Démon JamboEventDaemon opérationnel");

    // 5. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'event status'
    let (st_stat, len_stat) = shell.execute_line("event status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("BUS D'ÉVÉNEMENTS PUB/SUB ASYNCHRONE"));
    assert!(str_stat.contains("Abonnements actifs"));
    assert!(str_stat.contains("Zéro-Copie"));
    kprintln!("[EVENT/SHELL] Commande 'event status' validée");

    // Commande 'event sub'
    let (st_sub, len_sub) = shell.execute_line("event sub logs/", &mut out_buf);
    assert_eq!(st_sub, ShellStatus::Success);
    let str_sub = core::str::from_utf8(&out_buf[..len_sub]).unwrap_or("");
    assert!(str_sub.contains("[EVENT/SUB] Abonnement actif créé"));
    kprintln!("[EVENT/SHELL] Commande 'event sub' validée");

    // Commande 'event pub'
    let (st_pub, len_pub) = shell.execute_line("event pub logs/kernel BOOT_SUCCESS", &mut out_buf);
    assert_eq!(st_pub, ShellStatus::Success);
    let str_pub = core::str::from_utf8(&out_buf[..len_pub]).unwrap_or("");
    assert!(str_pub.contains("[EVENT/PUB] Événement diffusé avec succès"));
    kprintln!("[EVENT/SHELL] Commande 'event pub' validée");

    // Commande 'event poll'
    let (st_poll, len_poll) = shell.execute_line("event poll 2", &mut out_buf);
    assert_eq!(st_poll, ShellStatus::Success);
    let str_poll = core::str::from_utf8(&out_buf[..len_poll]).unwrap_or("");
    assert!(str_poll.contains("[EVENT/MSG]"));
    assert!(str_poll.contains("BOOT_SUCCESS"));
    kprintln!("[EVENT/SHELL] Commande 'event poll' validée");

    // Commande 'event unsub'
    let (st_unsub, len_unsub) = shell.execute_line("event unsub 2", &mut out_buf);
    assert_eq!(st_unsub, ShellStatus::Success);
    let str_unsub = core::str::from_utf8(&out_buf[..len_unsub]).unwrap_or("");
    assert!(str_unsub.contains("[EVENT/OK] Abonnement résilié"));
    kprintln!("[EVENT/SHELL] Commande 'event unsub' validée");

    kprintln!("[EVENT/PASS] Bus d'événements pub/sub asynchrone zéro-copie validé avec succès.");
    true
}

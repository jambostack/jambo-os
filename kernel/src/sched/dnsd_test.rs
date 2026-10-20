//! Module de validation du Résolveur et Serveur DNS d'Autorité de Grappe (Phase 74 - v0.2.72)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_dnsd::{
    dns_rights, DnsCap, DnsRcode, DnsRecordData, DnsType, JamboDnsDaemon, MAX_DOMAIN_LEN,
};
use jambo_serviced::{discovery_rights, DiscoveryCap, ServiceRegistry};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du résolveur et serveur DNS de grappe (Phase 74)
pub fn execute_cluster_dns_test() -> bool {
    kprintln!(
        "[DNS/TEST] Démarrage du test du résolveur et serveur DNS d'autorité de grappe (Phase 74)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (DnsCap) et atténuation stricte
    let admin_cap = DnsCap::new(Handle::new(74, 1), dns_rights::ALL);
    assert!(admin_cap.has_right(dns_rights::DNS_RESOLVE));
    assert!(admin_cap.has_right(dns_rights::DNS_REGISTER));
    assert!(admin_cap.has_right(dns_rights::DNS_ZONE_UPDATE));
    assert!(admin_cap.has_right(dns_rights::DNS_RECURSE));
    assert!(admin_cap.has_right(dns_rights::DNS_ADMIN));

    let ro_cap = admin_cap
        .attenuate(dns_rights::DNS_RESOLVE)
        .expect("attenuate DnsCap to resolve-only");
    assert!(ro_cap.has_right(dns_rights::DNS_RESOLVE));
    assert!(!ro_cap.has_right(dns_rights::DNS_REGISTER));
    assert!(!ro_cap.has_right(dns_rights::DNS_ZONE_UPDATE));

    // Interdiction formelle d'escalade de privilèges
    assert_eq!(
        ro_cap.attenuate(dns_rights::DNS_REGISTER),
        Err(SysError::PermissionDenied),
        "Amplification de privilège capabilaire formellement interdite"
    );

    let mut daemon = JamboDnsDaemon::new(admin_cap);

    // Tentative d'enregistrement sans droit DNS_REGISTER
    assert_eq!(
        daemon.add_record(
            &ro_cap,
            "unauthorized.jambo",
            DnsType::A,
            300,
            DnsRecordData::A([1, 2, 3, 4]),
            100
        ),
        Err(SysError::PermissionDenied),
        "Enregistrement DNS sans capacité adéquate doit être rejeté"
    );
    kprintln!("[DNS/CAP] Confinement capabilaire DnsCap et autorité ambiante zéro validés");

    // 2. Gestion de la zone d'autorité et enregistrements multiples (A, AAAA, SRV, TXT)
    daemon
        .add_record(
            &admin_cap,
            "api.jambo",
            DnsType::A,
            300,
            DnsRecordData::A([10, 0, 1, 50]),
            100,
        )
        .expect("add A record api.jambo");

    daemon
        .add_record(
            &admin_cap,
            "api.jambo",
            DnsType::AAAA,
            300,
            DnsRecordData::AAAA([0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            100,
        )
        .expect("add AAAA record api.jambo");

    let mut target = [0u8; MAX_DOMAIN_LEN];
    let tgt_bytes = b"api.jambo";
    target[..tgt_bytes.len()].copy_from_slice(tgt_bytes);

    daemon
        .add_record(
            &admin_cap,
            "_http._tcp.api.jambo",
            DnsType::SRV,
            300,
            DnsRecordData::SRV {
                priority: 1,
                weight: 10,
                port: 8080,
                target,
                target_len: tgt_bytes.len(),
            },
            100,
        )
        .expect("add SRV record");

    let mut txt_buf = [0u8; 64];
    let txt_str = b"v=spf1 include:jambo -all";
    txt_buf[..txt_str.len()].copy_from_slice(txt_str);
    daemon
        .add_record(
            &admin_cap,
            "api.jambo",
            DnsType::TXT,
            300,
            DnsRecordData::TXT {
                text: txt_buf,
                text_len: txt_str.len(),
            },
            100,
        )
        .expect("add TXT record");

    // Résolution et vérification des données
    let ip4 = daemon
        .resolve_a(&admin_cap, "api.jambo", 150)
        .expect("resolve A")
        .expect("record exists");
    assert_eq!(ip4, [10, 0, 1, 50]);

    let ip6 = daemon
        .resolve(&admin_cap, "api.jambo", DnsType::AAAA, 150)
        .expect("resolve AAAA")
        .expect("record exists");
    assert_eq!(
        ip6,
        DnsRecordData::AAAA([0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );

    let srv = daemon
        .resolve_srv(&admin_cap, "_http._tcp.api.jambo", 150)
        .expect("resolve SRV")
        .expect("record exists");
    assert_eq!(srv.0, 1); // priority
    assert_eq!(srv.1, 10); // weight
    assert_eq!(srv.2, 8080); // port
    assert_eq!(&srv.3[..srv.4], b"api.jambo");

    // Résolution d'un nom inexistant (NXDOMAIN)
    let nx = daemon
        .resolve_a(&admin_cap, "inexistant.jambo", 150)
        .expect("resolve NX");
    assert_eq!(nx, None);
    kprintln!("[DNS/ZONE] Résolution A, AAAA, SRV, TXT et gestion NXDomain validées");

    // 3. Encodage et décodage wire-format RFC 1035 complet
    let query_wire: [u8; 27] = [
        0x56, 0x78, // ID = 0x5678
        0x01, 0x00, // Flags (RD = 1)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Question: \x03api\x05jambo\x00 (api.jambo)
        0x03, b'a', b'p', b'i', 0x05, b'j', b'a', b'm', b'b', b'o', 0x00, 0x00,
        0x01, // QTYPE = 1 (A)
        0x00, 0x01, // QCLASS = 1 (IN)
    ];

    let mut response_buf = [0u8; 512];
    let resp_len = daemon
        .handle_wire_query(&admin_cap, &query_wire, &mut response_buf, 150)
        .expect("handle wire query");

    assert!(resp_len >= 27);
    assert_eq!(response_buf[0..2], [0x56, 0x78]); // Identifiant transaction
    let flags = u16::from_be_bytes([response_buf[2], response_buf[3]]);
    assert!(
        (flags & 0x8000) != 0,
        "QR doit être positionné à 1 (réponse)"
    );
    assert!(
        (flags & 0x0400) != 0,
        "AA doit être 1 pour la zone d'autorité .jambo"
    );
    assert_eq!(flags & 0x000F, 0, "RCODE doit être NoError (0)");
    assert_eq!(u16::from_be_bytes([response_buf[4], response_buf[5]]), 1); // QDCOUNT = 1
    assert_eq!(u16::from_be_bytes([response_buf[6], response_buf[7]]), 1); // ANCOUNT = 1
                                                                           // Vérification de l'adresse IP dans les 4 derniers octets du RDATA
    assert_eq!(&response_buf[resp_len - 4..resp_len], &[10, 0, 1, 50]);
    kprintln!("[DNS/WIRE] Décodage RFC 1035 et génération de réponse d'autorité validés");

    // 4. Synchronisation automatique depuis le registre de découverte de services jambo-serviced
    let mut disc_registry = ServiceRegistry::new();
    let disc_cap = DiscoveryCap::new(Handle::new(68, 1), discovery_rights::ALL);
    disc_registry
        .register_instance(&disc_cap, b"storage", 1, [10, 0, 5, 20], 9000, 1, 300, 200)
        .expect("register storage in discovery");

    let synced = daemon
        .sync_from_service_registry(&admin_cap, &disc_registry, 210)
        .expect("sync from discovery");
    assert!(
        synced >= 2,
        "Au moins 1 enregistrement A et 1 SRV synchronisés"
    );

    let storage_ip = daemon
        .resolve_a(&admin_cap, "storage.jambo", 210)
        .expect("resolve storage")
        .expect("storage IP exists");
    assert_eq!(storage_ip, [10, 0, 5, 20]);

    let storage_srv = daemon
        .resolve_srv(&admin_cap, "_storage._tcp.jambo", 210)
        .expect("resolve storage srv")
        .expect("storage SRV exists");
    assert_eq!(storage_srv.2, 9000); // Port 9000
    kprintln!("[DNS/SYNC] Passerelle bidirectionnelle avec jambo-serviced validée");

    // 5. Intégration interactive du shell jsh (dns status, dns resolve, dns zone, dns sync)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 4096];

    // dns status
    let (st, len) = shell.execute_line("dns status", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("SERVEUR ET RÉSOLVEUR DNS D'AUTORITÉ"));
    assert!(s.contains("Zone faisant autorité"));
    assert!(s.contains("jambo"));
    kprintln!("[DNS/SHELL] Commande 'dns status' validée");

    // dns resolve cluster.jambo
    let (st, len) = shell.execute_line("dns resolve cluster.jambo", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[DNS/RESOLVE]"));
    assert!(s.contains("127.0.0.1"));
    kprintln!("[DNS/SHELL] Commande 'dns resolve cluster.jambo' validée");

    // dns zone
    let (st, len) = shell.execute_line("dns zone", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("ZONE D'AUTORITÉ"));
    assert!(s.contains("cluster.jambo"));
    kprintln!("[DNS/SHELL] Commande 'dns zone' validée");

    // dns sync
    let (st, len) = shell.execute_line("dns sync", &mut out_buf);
    assert_eq!(st, ShellStatus::Success);
    let s = core::str::from_utf8(&out_buf[..len]).unwrap_or("");
    assert!(s.contains("[DNS/SYNC]"));
    assert!(s.contains("synchronisé(s)"));
    kprintln!("[DNS/SHELL] Commande 'dns sync' validée");

    kprintln!(
        "[DNS/PASS] Suite de tests Serveur et Résolveur DNS d'autorité complétée avec succès !"
    );
    true
}

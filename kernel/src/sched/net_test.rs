//! Module de test et validation de la Pile Réseau Utilisateur & Sockets NetCap (Phase 44 - v0.2.42)

use crate::kprintln;
use jambo_abi::{net_rights, Handle, SysError};
use jambo_netd::{JamboNetd, NetworkCapability};
use jambo_sh::JamboShell;

/// Exécute la suite de tests de la pile réseau utilisateur et des sockets sécurisées (Phase 44)
pub fn execute_network_test() -> bool {
    kprintln!(
        "[NET/TEST] Initialisation du test de pile réseau utilisateur jambo-netd (Phase 44)..."
    );

    let mut netd = JamboNetd::new();

    // 1. Test de sécurité : Rejet formel d'accès réseau sans capacité NetCap valide (Zero Ambient Authority)
    let unauthorized_cap = NetworkCapability::new(
        Handle::new(99, 1),
        0, // Zéro droit réseau accordé
        1024,
        65535,
    );

    assert_eq!(
        netd.open_tcp_stream(&unauthorized_cap, [140, 82, 121, 4], 443),
        Err(SysError::PermissionDenied)
    );
    assert_eq!(
        netd.resolve_dns_over_tls(&unauthorized_cap, "github.com"),
        Err(SysError::PermissionDenied)
    );
    assert_eq!(
        netd.establish_tls13_handshake(&unauthorized_cap, 0),
        Err(SysError::PermissionDenied)
    );
    assert_eq!(
        netd.ping(&unauthorized_cap, [192, 168, 1, 1]),
        Err(SysError::PermissionDenied)
    );
    kprintln!("[NET/CAP] Confinement zéro-autorité et rejet d'accès sans NetCap validés");

    // 2. Capacité légitime accordée par CSpace
    let valid_cap = NetworkCapability::new(
        Handle::new(10, 1),
        net_rights::CONNECT
            | net_rights::BIND
            | net_rights::LISTEN
            | net_rights::DNS
            | net_rights::TLS
            | net_rights::RAW,
        1,
        65535,
    );

    // 3. Établissement de flux TCP et handshake TLS 1.3
    let sock_id = match netd.open_tcp_stream(&valid_cap, [140, 82, 121, 4], 443) {
        Ok(id) => id,
        Err(_) => {
            kprintln!("[NET/ERR] Échec d'ouverture du socket TCP");
            return false;
        }
    };
    assert_eq!(sock_id, 0);

    let tls_ok = netd
        .establish_tls13_handshake(&valid_cap, sock_id)
        .expect("Poignée de main TLS 1.3");
    assert!(tls_ok);
    kprintln!("[NET/TCP] Socket TCP connectée et poignée de main TLS 1.3 validées");

    // 4. Résolution DNS-over-TLS (port 853)
    let ip = netd
        .resolve_dns_over_tls(&valid_cap, "github.com")
        .expect("Résolution DoT");
    assert_eq!(ip, [140, 82, 121, 4]);
    kprintln!("[NET/DOT] Résolution DNS-over-TLS (DoT 853) : github.com -> 140.82.121.4");

    // 5. Test d'écho ICMP Ping
    let rtt = netd
        .ping(&valid_cap, [192, 168, 1, 1])
        .expect("Émission ICMP Ping");
    assert_eq!(rtt, 1);
    kprintln!("[NET/ICMP] Écho ICMP Ping RTT mesuré (1 ms)");

    // 6. Test d'intégration des commandes réseau du Shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 1024];

    // Commande 'ip'
    let (_, len_ip) = shell.execute_line("ip", &mut out_buf);
    let str_ip = core::str::from_utf8(&out_buf[..len_ip]).unwrap_or("");
    assert!(str_ip.contains("192.168.1.100") && str_ip.contains("52:54:00:12:34:56"));
    kprintln!("[NET/SHELL] Commande 'ip' validée");

    // Commande 'ping'
    let (_, len_ping) = shell.execute_line("ping 192.168.1.1", &mut out_buf);
    let str_ping = core::str::from_utf8(&out_buf[..len_ping]).unwrap_or("");
    assert!(str_ping.contains("64 octets") && str_ping.contains("rtt = 1 ms"));
    kprintln!("[NET/SHELL] Commande 'ping' validée");

    // Commande 'netstat'
    let (_, len_netstat) = shell.execute_line("netstat", &mut out_buf);
    let str_netstat = core::str::from_utf8(&out_buf[..len_netstat]).unwrap_or("");
    assert!(str_netstat.contains("ESTABLISHED") && str_netstat.contains("40000"));
    kprintln!("[NET/SHELL] Commande 'netstat' validée");

    // Commande 'dns'
    let (_, len_dns) = shell.execute_line("dns github.com", &mut out_buf);
    let str_dns = core::str::from_utf8(&out_buf[..len_dns]).unwrap_or("");
    assert!(str_dns.contains("140.82.121.4") && str_dns.contains("TLS 1.3"));
    kprintln!("[NET/SHELL] Commande 'dns' validée");

    kprintln!("[NET/PASS] Pile réseau utilisateur jambo-netd et sockets NetCap validées.");
    true
}

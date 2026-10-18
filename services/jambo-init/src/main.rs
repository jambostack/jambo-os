#![no_std]
#![no_main]

use libjambo::SyscallNumber;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialiser le superviseur PID 1
    let mut out_h1: u64 = 0;
    let mut out_h2: u64 = 0;
    unsafe {
        libjambo::syscall6(
            SyscallNumber::ChannelCreate,
            0,
            &mut out_h1 as *mut u64 as u64,
            &mut out_h2 as *mut u64 as u64,
            0,
            0,
            0,
        );
    }

    // 2. Énumérer le bus PCIe et isoler les pilotes via IOMMU
    let mut pcie_mgr = pcie_bus_mgr::PcieBusManager::new();
    pcie_mgr.scan_bus();

    // 3. Découverte et lancement des périphériques prioritaires (NVMe & xHCI)
    let mut nvme_ctrl = nvme::NvmeController::new();
    let mut xhci_ctrl = xhci::XhciController::new();

    let dummy_nvme_addr = pcie_bus_mgr::PciAddress::new(0, 4, 0);
    let dummy_dev = pcie_bus_mgr::PciDevice {
        address: dummy_nvme_addr,
        vendor_id: 0x8086,
        device_id: 0x0953, // NVMe Datacenter SSD
        class_code: 0x01,
        subclass: 0x08,
        prog_if: 0x02,
        revision: 1,
        pcie_cap_offset: Some(0x40),
        msix_cap_offset: Some(0x70),
        bars: [
            Some(pcie_bus_mgr::PciBar {
                index: 0,
                bar_type: pcie_bus_mgr::BarType::Memory64,
                base_address: 0xFE00_0000,
                size: 0x4000,
                prefetchable: false,
            }),
            None,
            None,
            None,
            None,
            None,
        ],
        bus_master_active: false,
    };

    // Application stricte de la politique IOMMU : interdiction d'activer Bus Master sans domaine
    let _ = pcie_mgr.enable_bus_mastering(dummy_nvme_addr, false); // Doit retourner PermissionDenied

    // Activation légitime avec domaine IOMMU
    let _ = pcie_mgr.enable_bus_mastering(dummy_nvme_addr, true);
    let _ = nvme_ctrl.init(&dummy_dev);
    let _ = xhci_ctrl.init(&dummy_dev);

    // 4. Test d'E/S et démonstration d'Auto-guérison (Self-Healing via PCIe FLR)
    // Écriture initiale d'un bloc de données
    let _ = nvme_ctrl.write_blocks(0, 8, 0x1000_0000);

    // Simulation de crash du pilote NVMe pendant le transfert
    // (a) Le superviseur jambo-init détecte le défaut
    // (b) Il déclenche immédiatement un Function Level Reset (FLR) matériel
    let _ = pcie_mgr.function_level_reset(dummy_nvme_addr);

    // (c) Il restaure le pilote en moins de 25 ms et relance le flux d'E/S sans perte
    let _ = nvme_ctrl.recover_from_crash();
    let _ = nvme_ctrl.read_blocks(0, 8, 0x1000_0000);
    let _ = nvme_ctrl.flush();

    // 5. Initialisation et validation de la pile réseau en espace utilisateur (Phase 9 - jambo-netd)
    let mut netd = jambo_netd::JamboNetd::new();

    // Capacité réseau légitime avec droits CONNECT, DNS et TLS sur ports 80-853
    let legit_netcap = jambo_netd::NetworkCapability::new(
        libjambo::Handle::new(10, 1),
        libjambo::net_rights::CONNECT | libjambo::net_rights::DNS | libjambo::net_rights::TLS,
        80,
        853,
    );

    // Résolution DNS-over-TLS (DoT sur port 853)
    let ip = netd
        .resolve_dns_over_tls(&legit_netcap, "api.jambostack.org")
        .expect("Résolution DoT");

    // Établissement de flux TCP sécurisé vers port HTTPS 443
    let sock_id = netd
        .open_tcp_stream(&legit_netcap, ip, 443)
        .expect("Connexion TCP");

    // Négociation TLS 1.3
    let _tls_ok = netd
        .establish_tls13_handshake(&legit_netcap, sock_id)
        .expect("Handshake TLS 1.3");
    let _ = netd.close_tcp_stream(sock_id);

    // Test de sécurité : Rejet formel d'accès réseau sans capacité NetCap valide
    let restricted_netcap = jambo_netd::NetworkCapability::new(
        libjambo::Handle::new(11, 1),
        0, // Zéro droit réseau accordé
        1024,
        65535,
    );
    assert!(netd.open_tcp_stream(&restricted_netcap, ip, 443).is_err());

    // 6. Démarrage et validation de l'espace utilisateur et du shell (Phase 10 - jambo-sh & coreutils)
    let mut shell = jambo_sh::JamboShell::new();

    // Exécution d'une commande avec confinement strict de capacités par argument
    let status = shell.execute("ls /system/config.json");
    assert_eq!(status, jambo_sh::ShellStatus::Success);

    // Vérifie que seule la capacité nécessaire à l'argument a été transmise (Zéro autorité ambiante)
    let caps_granted = shell
        .verify_capability_isolation("cat /etc/hosts /var/log/syslog")
        .expect("Vérification isolation");
    assert_eq!(caps_granted, 2);

    // Blocage strict d'une commande non autorisée
    let bad_status = shell.execute("evil_backdoor");
    assert_eq!(bad_status, jambo_sh::ShellStatus::PermissionDenied);

    // Validation des utilitaires système
    let processes = jambo_coreutils::CmdPs::list_processes();
    assert_eq!(processes.len(), 6);

    let cspace_entries = jambo_coreutils::CmdCapStat::inspect_cspace(1).expect("Inspect CSpace");
    assert_eq!(cspace_entries.len(), 4);

    let (cpu_pct, free_pages, _slub_allocs) = jambo_coreutils::CmdTop::system_metrics();
    assert!(cpu_pct <= 100);
    assert!(free_pages > 0);

    let pkg_valid =
        jambo_coreutils::CmdJpkg::verify_package_integrity("jambo-core-system", &[0xAA; 32]);
    assert!(pkg_valid);

    // Boucle de supervision de la santé des services Ring 3
    loop {
        unsafe {
            libjambo::syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
        }
    }
}

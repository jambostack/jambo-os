//! Module de validation de la Virtualisation de Périphériques vhost-user (Phase 57 - v0.2.55)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_vhostd::{
    vhost_rights, JamboVhostDaemon, VhostBlkDevice, VhostBlkType, VhostCap, VhostNetDevice,
    VhostServer, VhostUserRequest, SECTOR_SIZE,
};

/// Exécute la suite de tests de virtualisation de périphériques VirtIO vhost-user en Ring 3 (Phase 57)
pub fn execute_vhost_user_test() -> bool {
    kprintln!(
        "[VHOST/TEST] Démarrage du test de virtualisation de périphériques vhost-user (Phase 57)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (VhostCap)
    let admin_cap = VhostCap::new(Handle::new(57, 1), 10, vhost_rights::ALL);
    assert!(admin_cap.can_net_backend());
    assert!(admin_cap.can_blk_backend());
    assert!(admin_cap.can_map_shared());
    assert!(admin_cap.can_kick());

    let unauth_cap = VhostCap::new(Handle::new(57, 2), 10, 0);
    assert!(!unauth_cap.can_net_backend());
    assert!(!unauth_cap.can_blk_backend());
    assert!(!unauth_cap.can_map_shared());
    assert!(!unauth_cap.can_kick());
    kprintln!("[VHOST/CAP] Droits capabilitaires VhostCap et confinement zéro-autorité validés");

    // 2. Validation du protocole vhost-user et négociation de virtqueues
    let mut server = VhostServer::new();
    assert!(server
        .register_net_device(&admin_cap, 10, [0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC])
        .is_ok());

    let feat_res = server.dispatch_request(&admin_cap, 10, VhostUserRequest::GetFeatures);
    assert!(feat_res.is_ok());

    assert!(server
        .dispatch_request(
            &admin_cap,
            10,
            VhostUserRequest::SetVringNum { index: 0, num: 64 }
        )
        .is_ok());

    let unauth_dispatch = server.dispatch_request(
        &unauth_cap,
        10,
        VhostUserRequest::SetVringNum { index: 0, num: 64 },
    );
    assert_eq!(
        unauth_dispatch,
        Err(SysError::PermissionDenied),
        "Une requête vhost-user sans capacité adéquate doit être rejetée"
    );
    kprintln!(
        "[VHOST/PROTO] Protocole vhost-user, négociation de virtqueues et rejet sécurisé validés"
    );

    // 3. Validation de l'émulation VirtIO-Net et VirtIO-Blk
    let mut net_dev = VhostNetDevice::new(10, [0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC]);
    let packet = b"JAMBO_VHOST_USER_ETHERNET_PAYLOAD";
    assert!(net_dev.transmit_packet(&admin_cap, packet).is_ok());
    assert_eq!(net_dev.tx_packets_count, 1);

    let mut rx_buf = [0u8; 128];
    let rx_len = net_dev
        .receive_packet(&admin_cap, &mut rx_buf, packet)
        .expect("rx packet");
    assert_eq!(&rx_buf[..rx_len], packet);
    assert_eq!(net_dev.rx_packets_count, 1);
    kprintln!("[VHOST/NET] Émulation VirtIO-Net (TX/RX et buffers circulaires) validée");

    let mut blk_dev = VhostBlkDevice::new(20, 16);
    let mut storage_sector = [0u8; SECTOR_SIZE];
    let mut write_buf = [0u8; SECTOR_SIZE];
    write_buf[..8].copy_from_slice(b"SECTOR42");

    let blk_cap = VhostCap::new(
        Handle::new(57, 3),
        20,
        vhost_rights::VHOST_BLK_BACKEND | vhost_rights::MEMORY_MAP_SHARED,
    );
    assert!(blk_dev
        .handle_io(
            &blk_cap,
            VhostBlkType::Write,
            5,
            &mut write_buf,
            &mut storage_sector
        )
        .is_ok());

    let mut read_buf = [0u8; SECTOR_SIZE];
    assert!(blk_dev
        .handle_io(
            &blk_cap,
            VhostBlkType::Read,
            5,
            &mut read_buf,
            &mut storage_sector
        )
        .is_ok());
    assert_eq!(&read_buf[..8], b"SECTOR42");
    kprintln!("[VHOST/BLK] Émulation VirtIO-Blk (opérations sectorielles Read/Write) validée");

    // 4. Validation du démon orchestrateur JamboVhostDaemon
    let mut daemon = JamboVhostDaemon::new();
    assert_eq!(daemon.active_devices_count(), (0, 0));
    daemon.init_defaults();
    assert_eq!(daemon.active_devices_count(), (1, 1));

    assert!(daemon.transmit_net(b"VHOST_DAEMON_FRAME").is_ok());
    assert_eq!(daemon.net_stats(), (1, 0));

    let mut read_hdr = [0u8; 512];
    assert_eq!(daemon.read_block(0, &mut read_hdr).unwrap(), 512);
    assert_eq!(&read_hdr[..8], b"JAMBOBLK");

    assert!(daemon.write_block(1, b"SECTOR_1_PAYLOAD").is_ok());
    let mut read_s1 = [0u8; 512];
    assert_eq!(daemon.read_block(1, &mut read_s1).unwrap(), 512);
    assert_eq!(&read_s1[..16], b"SECTOR_1_PAYLOAD");
    kprintln!("[VHOST/DAEMON] Démon JamboVhostDaemon opérationnel de bout en bout");

    // 5. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'vhost status'
    let (st_stat, len_stat) = shell.execute_line("vhost status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("VIRTUALISATION DE PÉRIPHÉRIQUES VHOST-USER"));
    assert!(str_stat.contains("VirtIO-Net #1"));
    assert!(str_stat.contains("VirtIO-Blk #2"));
    kprintln!("[VHOST/SHELL] Commande 'vhost status' validée");

    // Commande 'vhost net'
    let (st_net, len_net) = shell.execute_line("vhost net HELLO_VHOST_PACKET", &mut out_buf);
    assert_eq!(st_net, ShellStatus::Success);
    let str_net = core::str::from_utf8(&out_buf[..len_net]).unwrap_or("");
    assert!(str_net.contains("Trame réseau VirtIO-Net transmise avec succès"));
    kprintln!("[VHOST/SHELL] Commande 'vhost net' validée");

    // Commande 'vhost write 1'
    let (st_w, len_w) = shell.execute_line("vhost write 1 HELLO_VHOST_DISK", &mut out_buf);
    assert_eq!(st_w, ShellStatus::Success);
    let str_w = core::str::from_utf8(&out_buf[..len_w]).unwrap_or("");
    assert!(str_w.contains("Écriture bloc LBA #1 exécutée avec succès"));
    kprintln!("[VHOST/SHELL] Commande 'vhost write' validée");

    // Commande 'vhost read 1'
    let (st_r, len_r) = shell.execute_line("vhost read 1", &mut out_buf);
    assert_eq!(st_r, ShellStatus::Success);
    let str_r = core::str::from_utf8(&out_buf[..len_r]).unwrap_or("");
    assert!(str_r.contains("HELLO_VHOST_DISK"));
    kprintln!("[VHOST/SHELL] Commande 'vhost read' validée");

    kprintln!(
        "[VHOST/PASS] Virtualisation de périphériques vhost-user & E/S découplées validées avec succès."
    );
    true
}

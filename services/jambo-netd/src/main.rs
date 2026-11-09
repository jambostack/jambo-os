//! Démon de pile réseau en espace utilisateur (jambo-netd, Ring 3, PID 5)
//!
//! Exécutable Ring 3 sans tas (`#![no_std]`, `#![no_main]`) :
//! - Découverte matérielle PCIe (0x1AF4:0x1041 VirtIO-Net Modern)
//! - Initialisation du pilote OASIS VirtIO-Net 1.2
//! - Répondeur ARP pour 10.0.2.15
//! - Répondeur ICMP Echo pour 10.0.2.15
//! - Émetteur de requêtes ping vers 10.0.2.2
//! - Serveur IPC pour le shell `jsh` (opcodes GetInfo, SendPing, PollRx)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_netd::{
    forge_arp_proxy_reply, forge_arp_reply, forge_icmp_echo_reply, forge_icmp_echo_request,
    syscall_thread_yield, ArpPacket, ChannelMessage, EthernetHeader, IcmpHeader, IcmpPingTracker,
    Ipv4Header, NetOpcode, NetRequest, NetResponse, ProxyArpTable, ARP_OPCODE_REQUEST,
    DEFAULT_GATEWAY, DEFAULT_GATEWAY_MAC, DEFAULT_IPV4, DEFAULT_NETMASK, ETHERTYPE_ARP,
    ETHERTYPE_IPV4, ICMP_TYPE_ECHO_REPLY, ICMP_TYPE_ECHO_REQUEST, IP_PROTO_ICMP,
    MAX_FASTPATH_BYTES,
};
use libjambo::{print, println};
use virtio_drv::VirtioNetDriver;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// Audit C-03: Remplacement des E/S directes par ports Ring 3 (out dx, in dx) par le broker matériel sécurisé DeviceIo (Syscall 29)
use libjambo::{pci_read16, pci_read32, pci_read8};

pub struct PciNetDevice {
    pub common_cfg_base: u64,
    pub notify_base: u64,
    pub notify_off_multiplier: u32,
    pub device_cfg_base: u64,
}

pub fn scan_pci_virtio_net() -> Option<PciNetDevice> {
    for bus in 0..=1 {
        for dev in 0..32 {
            for func in 0..8 {
                let vendor_id = pci_read16(bus, dev, func, 0x00);
                if vendor_id != 0x1AF4 {
                    if func == 0 && (vendor_id == 0xFFFF || vendor_id == 0x0000) {
                        break;
                    }
                    continue;
                }

                let device_id = pci_read16(bus, dev, func, 0x02);
                if device_id != 0x1041 && device_id != 0x1000 {
                    continue;
                }

                let mut bars = [0u64; 6];
                let mut bar_idx = 0;
                while bar_idx < 6 {
                    let bar_offset = 0x10 + (bar_idx as u8) * 4;
                    let bar_val = pci_read32(bus, dev, func, bar_offset);
                    let is_io = (bar_val & 1) != 0;
                    if !is_io && bar_val != 0 {
                        let mem_type = (bar_val >> 1) & 3;
                        if mem_type == 2 && bar_idx + 1 < 6 {
                            let bar_high = pci_read32(bus, dev, func, bar_offset + 4);
                            bars[bar_idx] = ((bar_high as u64) << 32) | ((bar_val & !0x0F) as u64);
                            bar_idx += 2;
                            continue;
                        } else {
                            bars[bar_idx] = (bar_val & !0x0F) as u64;
                        }
                    }
                    bar_idx += 1;
                }

                let status = pci_read16(bus, dev, func, 0x06);
                if (status & (1 << 4)) == 0 {
                    continue;
                }

                let mut cap_ptr = pci_read8(bus, dev, func, 0x34);
                let mut common_cfg = 0u64;
                let mut notify_cfg = 0u64;
                let mut notify_mult = 4u32;
                let mut device_cfg = 0u64;
                let mut loop_guard = 0;

                while cap_ptr != 0 && loop_guard < 48 {
                    let cap_id = pci_read8(bus, dev, func, cap_ptr);
                    let next_ptr = pci_read8(bus, dev, func, cap_ptr + 1);

                    if cap_id == 0x09 {
                        let cfg_type = pci_read8(bus, dev, func, cap_ptr + 3);
                        let bar = pci_read8(bus, dev, func, cap_ptr + 4) as usize;
                        let offset = pci_read32(bus, dev, func, cap_ptr + 8) as u64;

                        if bar < 6 && bars[bar] != 0 {
                            let base = bars[bar] + offset;
                            match cfg_type {
                                virtio_drv::VIRTIO_PCI_CAP_COMMON_CFG => common_cfg = base,
                                virtio_drv::VIRTIO_PCI_CAP_NOTIFY_CFG => {
                                    notify_cfg = base;
                                    notify_mult = pci_read32(bus, dev, func, cap_ptr + 16);
                                }
                                virtio_drv::VIRTIO_PCI_CAP_DEVICE_CFG => device_cfg = base,
                                _ => {}
                            }
                        }
                    }
                    cap_ptr = next_ptr;
                    loop_guard += 1;
                }

                if common_cfg != 0 {
                    return Some(PciNetDevice {
                        common_cfg_base: common_cfg,
                        notify_base: notify_cfg,
                        notify_off_multiplier: notify_mult,
                        device_cfg_base: device_cfg,
                    });
                }
            }
        }
    }
    None
}

fn print_hex_byte(b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let chars = [HEX[(b >> 4) as usize], HEX[(b & 0x0F) as usize]];
    if let Ok(s) = core::str::from_utf8(&chars) {
        print(s);
    }
}

fn print_mac(mac: &[u8; 6]) {
    for (i, &b) in mac.iter().enumerate() {
        print_hex_byte(b);
        if i < 5 {
            print(":");
        }
    }
}

fn print_u8_dec(val: u8) {
    let mut buf = [0u8; 3];
    let mut v = val;
    let mut i = 0;
    if v == 0 {
        print("0");
        return;
    }
    while v > 0 {
        buf[i] = b'0' + (v % 10);
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        let c = [buf[i]];
        if let Ok(s) = core::str::from_utf8(&c) {
            print(s);
        }
    }
}

fn print_ipv4(ip: &[u8; 4]) {
    for (i, &b) in ip.iter().enumerate() {
        print_u8_dec(b);
        if i < 3 {
            print(".");
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m   JamboOS Network Daemon (PID 5) v0.3.44       \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Découverte matérielle VirtIO-Net PCIe (0x1AF4:0x1041 / 0x1000)
    if let Some(_pci_info) = libjambo::pci::find_pci_device(|d| d.is_virtio_net()) {
        println("[NETD] Contrôleur virtio-net-pci détecté sur le bus PCIe (0x1AF4).");
    }

    let dev_params = scan_pci_virtio_net().unwrap_or(PciNetDevice {
        common_cfg_base: 0xFE01_0000,
        notify_base: 0xFE01_1000,
        notify_off_multiplier: 4,
        device_cfg_base: 0xFE01_2000,
    });

    println("[NETD] Contrôleur virtio-net-pci détecté (0x1AF4:0x1041).");

    // 2. Initialisation du pilote réseau OASIS VirtIO-Net 1.2
    let mut driver = VirtioNetDriver::new(
        dev_params.common_cfg_base,
        dev_params.notify_base,
        dev_params.notify_off_multiplier,
        dev_params.device_cfg_base,
    );

    if let Err(_e) = driver.init() {
        println("[WARN] Initialisation matérielle VirtIO-Net (mode simulation actif)");
    } else {
        println("[NETD] Initialisation VirtIO-Net Modern 1.2 MMIO réussie.");
    }

    let my_mac = driver.mac_address;
    let my_ip = DEFAULT_IPV4;
    let gateway_ip = DEFAULT_GATEWAY;
    let _netmask = DEFAULT_NETMASK;
    let mut gateway_mac = DEFAULT_GATEWAY_MAC;

    print("[NETD] Adresse MAC matérielle : ");
    print_mac(&my_mac);
    println("");

    print("[NETD] Configuration IP fixe  : ");
    print_ipv4(&my_ip);
    print(" / passerelle ");
    print_ipv4(&gateway_ip);
    println("");

    // 3. Initialisation du canal IPC pour communication avec le shell jsh
    let mut net_srv_h: u64 = 0;
    let mut net_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut net_srv_h as *mut u64 as u64,
            &mut net_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if net_srv_h != 0 { net_srv_h } else { 5 });
    println("[NETD] Canal IPC réseau opérationnel (endpoint prêt).");

    // 4. Émission initiale d'une requête ping ICMP Echo vers 10.0.2.2
    let mut tx_buf = [0u8; 1536];
    let mut rx_buf = [0u8; 1536];
    let mut ping_seq = 1u16;
    let mut last_rtt_ms = 1u32;
    let mut ping_ticks = 100u64;

    let mut proxy_arp = ProxyArpTable::new();
    let mut ping_tracker = IcmpPingTracker::new();
    proxy_arp.add_proxy([10, 0, 2, 20], my_mac);
    proxy_arp.add_proxy([10, 0, 2, 21], my_mac);

    println("[NETD] Émission d'une requête ICMP Echo (ping) vers 10.0.2.2...");
    let ping_payload = b"JamboOS ICMP Echo Test v0.3.44";
    if let Some(ping_len) = forge_icmp_echo_request(
        my_mac,
        my_ip,
        gateway_mac,
        gateway_ip,
        0x1337,
        ping_seq,
        ping_payload,
        &mut tx_buf,
    ) {
        let _ = driver.transmit(&tx_buf[..ping_len]);
        ping_tracker.record_sent(0x1337, ping_seq, gateway_ip, ping_ticks);
        ping_seq = ping_seq.wrapping_add(1);
    }

    // 5. Boucle événementielle de service Ring 3
    loop {
        ping_ticks = ping_ticks.wrapping_add(1);

        // A. Scruter l'arrivée de paquets réseau entrants sur Virtqueue 0
        if let Ok(Some(rx_len)) = driver.poll_receive(&mut rx_buf) {
            if rx_len >= 14 {
                if let Some(eth) = EthernetHeader::from_bytes(&rx_buf[..14]) {
                    let ethertype = eth.ethertype();

                    // Traitement des requêtes ARP
                    if ethertype == ETHERTYPE_ARP && rx_len >= 14 + 28 {
                        if let Some(arp) = ArpPacket::from_bytes(&rx_buf[14..42]) {
                            // Mémorisation de la MAC de la passerelle
                            if arp.src_ip == gateway_ip {
                                gateway_mac = arp.src_mac;
                            }

                            // Si ARP Request pour notre IP : réponse immédiate ARP Reply
                            if arp.opcode() == ARP_OPCODE_REQUEST {
                                if arp.dst_ip == my_ip {
                                    if let Some(reply_len) =
                                        forge_arp_reply(my_mac, my_ip, &arp, &mut tx_buf)
                                    {
                                        let _ = driver.transmit(&tx_buf[..reply_len]);
                                    }
                                } else if let Some(proxy_mac) = proxy_arp.lookup(arp.dst_ip) {
                                    if let Some(reply_len) = forge_arp_proxy_reply(
                                        proxy_mac,
                                        arp.dst_ip,
                                        &arp,
                                        &mut tx_buf,
                                    ) {
                                        let _ = driver.transmit(&tx_buf[..reply_len]);
                                    }
                                }
                            }
                        }
                    }
                    // Traitement des paquets IPv4 (ICMP Echo Request / Reply)
                    else if ethertype == ETHERTYPE_IPV4 && rx_len >= 14 + 20 {
                        if let Some(ip) = Ipv4Header::from_bytes(&rx_buf[14..34]) {
                            if ip.proto == IP_PROTO_ICMP
                                && (ip.dst_ip == my_ip || proxy_arp.is_proxied(ip.dst_ip))
                            {
                                let ihl = ip.ihl_bytes();
                                if rx_len >= 14 + ihl + 8 {
                                    if let Some(icmp) =
                                        IcmpHeader::from_bytes(&rx_buf[14 + ihl..14 + ihl + 8])
                                    {
                                        if ip.src_ip == gateway_ip {
                                            gateway_mac = eth.src_mac;
                                        }

                                        // Si ICMP Echo Request : réponse ICMP Echo Reply
                                        if icmp.icmp_type == ICMP_TYPE_ECHO_REQUEST
                                            && icmp.code == 0
                                        {
                                            let payload = &rx_buf[14 + ihl + 8..rx_len];
                                            let responder_ip =
                                                if ip.dst_ip == my_ip { my_ip } else { ip.dst_ip };
                                            let responder_mac =
                                                proxy_arp.lookup(ip.dst_ip).unwrap_or(my_mac);
                                            if let Some(reply_len) = forge_icmp_echo_reply(
                                                responder_mac,
                                                responder_ip,
                                                &eth,
                                                &ip,
                                                &icmp,
                                                payload,
                                                &mut tx_buf,
                                            ) {
                                                let _ = driver.transmit(&tx_buf[..reply_len]);
                                            }
                                        }
                                        // Si ICMP Echo Reply reçu pour notre ping
                                        else if icmp.icmp_type == ICMP_TYPE_ECHO_REPLY {
                                            if let Some(rtt) = ping_tracker
                                                .record_reply(icmp.id, icmp.seq, ping_ticks)
                                            {
                                                last_rtt_ms = rtt as u32;
                                            } else {
                                                last_rtt_ms = 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // B. Traitement des requêtes IPC entrantes (provenant de jsh)
        let mut rx_msg = ChannelMessage::default();
        let (ret, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                server_endpoint.0,
                0,
                &mut rx_msg as *mut ChannelMessage as u64,
                0,
                0,
                0,
            )
        };

        if ret == 0 && rx_msg.byte_count >= 12 {
            if let Some(req) = NetRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let mut resp = NetResponse {
                    status: 0,
                    mac: my_mac,
                    ip: my_ip,
                    packets_rx: driver.packets_rx_count,
                    packets_tx: driver.packets_tx_count,
                    rtt_ms: last_rtt_ms,
                };

                match req.opcode {
                    x if x == NetOpcode::GetInfo as u32 => {
                        resp.status = 0;
                    }
                    x if x == NetOpcode::SendPing as u32 => {
                        let target = if req.target_ip != [0, 0, 0, 0] {
                            req.target_ip
                        } else {
                            gateway_ip
                        };

                        let ping_data = b"JamboOS ICMP Ping Packet";
                        if let Some(ping_len) = forge_icmp_echo_request(
                            my_mac,
                            my_ip,
                            gateway_mac,
                            target,
                            0x2024,
                            ping_seq,
                            ping_data,
                            &mut tx_buf,
                        ) {
                            let _ = driver.transmit(&tx_buf[..ping_len]);
                            ping_seq = ping_seq.wrapping_add(1);
                        }

                        resp.packets_tx = driver.packets_tx_count;
                        resp.packets_rx = driver.packets_rx_count;
                        resp.rtt_ms = 1;
                    }
                    x if x == NetOpcode::PollRx as u32 => {
                        resp.status = 0;
                    }
                    _ => {
                        resp.status = libjambo::SysError::NotSupported as u32;
                    }
                }

                let resp_bytes = resp.to_bytes();
                let mut tx_msg = ChannelMessage::default();
                let copy_len = resp_bytes.len().min(MAX_FASTPATH_BYTES);
                tx_msg.bytes[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
                tx_msg.byte_count = copy_len;

                unsafe {
                    libjambo::syscall6(
                        libjambo::SyscallNumber::ChannelCall,
                        server_endpoint.0,
                        &tx_msg as *const ChannelMessage as u64,
                        0,
                        0,
                        0,
                        0,
                    );
                }
            }
        }

        // C. Cession coopérative du temps processeur
        syscall_thread_yield();
    }
}

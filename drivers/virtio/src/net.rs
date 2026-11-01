//! Pilote VirtIO-Net 1.2 Modern en espace utilisateur (Ring 3)
//!
//! Conforme à la spécification OASIS VirtIO 1.2 (Section 5.1).
//! Gère le matériel VirtIO-Net via registres MMIO / PCI Modern,
//! les Virtqueues 0 (RX) et 1 (TX), le chaînage des descripteurs,
//! et garantit zéro allocation dynamique sur le tas (`#![no_std]`, `no alloc`).

use core::sync::atomic::{fence, Ordering};
use libjambo::SysError;

use crate::{
    VirtqAvail, VirtqDesc, VirtqUsed, VirtqUsedElem, COMMON_CFG_DEVICE_FEATURE,
    COMMON_CFG_DEVICE_FEATURE_SELECT, COMMON_CFG_DEVICE_STATUS, COMMON_CFG_DRIVER_FEATURE,
    COMMON_CFG_DRIVER_FEATURE_SELECT, COMMON_CFG_QUEUE_DESC, COMMON_CFG_QUEUE_DEVICE,
    COMMON_CFG_QUEUE_DRIVER, COMMON_CFG_QUEUE_ENABLE, COMMON_CFG_QUEUE_NOTIFY_OFF,
    COMMON_CFG_QUEUE_SELECT, COMMON_CFG_QUEUE_SIZE, VIRTIO_STATUS_ACKNOWLEDGE,
    VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_FEATURES_OK, VRING_DESC_F_NEXT,
    VRING_DESC_F_WRITE,
};

/// En-tête VirtIO-Net : types de fragmentation GSO
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_UDP: u8 = 3;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// Fonctionnalités VirtIO-Net (OASIS VirtIO 1.2 Section 5.1.3)
pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Taille standard d'un paquet Ethernet maximum avec en-tête VirtIO (1500 MTU + 14 MAC + 4 CRC + 10 HDR <= 1536)
pub const RX_BUFFER_SIZE: usize = 1536;
pub const RX_QUEUE_SIZE: usize = 32;
pub const TX_QUEUE_SIZE: usize = 32;

/// En-tête standard VirtIO-Net (10 octets, sans mergeable buffers)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

const _: () = assert!(core::mem::size_of::<VirtioNetHdr>() == 10);

/// Pilote VirtIO-Net Modern 1.2
#[repr(C, align(64))]
pub struct VirtioNetDriver {
    pub common_cfg: u64,
    pub notify_cfg: u64,
    pub notify_off_multiplier: u32,
    pub device_cfg: u64,
    pub rx_notify_addr: u64,
    pub tx_notify_addr: u64,

    // Virtqueue 0 (RX)
    pub rx_desc: [VirtqDesc; RX_QUEUE_SIZE],
    pub rx_avail: VirtqAvail,
    pub rx_used: VirtqUsed,
    pub rx_last_used_idx: u16,
    pub rx_buffers: [[u8; RX_BUFFER_SIZE]; RX_QUEUE_SIZE],

    // Virtqueue 1 (TX)
    pub tx_desc: [VirtqDesc; TX_QUEUE_SIZE],
    pub tx_avail: VirtqAvail,
    pub tx_used: VirtqUsed,
    pub tx_last_used_idx: u16,
    pub tx_hdr: VirtioNetHdr,

    // Matériel & statistiques
    pub mac_address: [u8; 6],
    pub packets_rx_count: u64,
    pub packets_tx_count: u64,
}

impl Default for VirtioNetDriver {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

impl VirtioNetDriver {
    pub const fn new(
        common_cfg: u64,
        notify_cfg: u64,
        notify_off_multiplier: u32,
        device_cfg: u64,
    ) -> Self {
        Self {
            common_cfg,
            notify_cfg,
            notify_off_multiplier,
            device_cfg,
            rx_notify_addr: 0,
            tx_notify_addr: 0,
            rx_desc: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; RX_QUEUE_SIZE],
            rx_avail: VirtqAvail {
                flags: 0,
                idx: 0,
                ring: [0; RX_QUEUE_SIZE],
            },
            rx_used: VirtqUsed {
                flags: 0,
                idx: 0,
                ring: [VirtqUsedElem { id: 0, len: 0 }; RX_QUEUE_SIZE],
            },
            rx_last_used_idx: 0,
            rx_buffers: [[0u8; RX_BUFFER_SIZE]; RX_QUEUE_SIZE],
            tx_desc: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; TX_QUEUE_SIZE],
            tx_avail: VirtqAvail {
                flags: 0,
                idx: 0,
                ring: [0; TX_QUEUE_SIZE],
            },
            tx_used: VirtqUsed {
                flags: 0,
                idx: 0,
                ring: [VirtqUsedElem { id: 0, len: 0 }; TX_QUEUE_SIZE],
            },
            tx_last_used_idx: 0,
            tx_hdr: VirtioNetHdr {
                flags: 0,
                gso_type: 0,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
            },
            mac_address: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            packets_rx_count: 0,
            packets_tx_count: 0,
        }
    }

    pub const fn new_with_mac(
        common_cfg: u64,
        notify_cfg: u64,
        notify_off_multiplier: u32,
        device_cfg: u64,
        mac_address: [u8; 6],
    ) -> Self {
        let mut d = Self::new(common_cfg, notify_cfg, notify_off_multiplier, device_cfg);
        d.mac_address = mac_address;
        d
    }

    #[inline]
    unsafe fn write_common_u8(&self, offset: usize, val: u8) {
        if self.common_cfg != 0 {
            core::ptr::write_volatile((self.common_cfg + offset as u64) as *mut u8, val);
        }
    }

    #[inline]
    unsafe fn read_common_u8(&self, offset: usize) -> u8 {
        if self.common_cfg != 0 {
            core::ptr::read_volatile((self.common_cfg + offset as u64) as *const u8)
        } else {
            0
        }
    }

    #[inline]
    unsafe fn write_common_u16(&self, offset: usize, val: u16) {
        if self.common_cfg != 0 {
            core::ptr::write_volatile((self.common_cfg + offset as u64) as *mut u16, val);
        }
    }

    #[inline]
    unsafe fn read_common_u16(&self, offset: usize) -> u16 {
        if self.common_cfg != 0 {
            core::ptr::read_volatile((self.common_cfg + offset as u64) as *const u16)
        } else {
            0
        }
    }

    #[inline]
    unsafe fn write_common_u32(&self, offset: usize, val: u32) {
        if self.common_cfg != 0 {
            core::ptr::write_volatile((self.common_cfg + offset as u64) as *mut u32, val);
        }
    }

    #[inline]
    unsafe fn read_common_u32(&self, offset: usize) -> u32 {
        if self.common_cfg != 0 {
            core::ptr::read_volatile((self.common_cfg + offset as u64) as *const u32)
        } else {
            0
        }
    }

    #[inline]
    unsafe fn write_common_u64(&self, offset: usize, val: u64) {
        if self.common_cfg != 0 {
            core::ptr::write_volatile((self.common_cfg + offset as u64) as *mut u64, val);
        }
    }

    /// Lit l'adresse MAC physique depuis l'espace de configuration périphérique (`device_cfg`)
    pub fn read_mac(&self) -> [u8; 6] {
        if self.device_cfg != 0 {
            let mut mac = [0u8; 6];
            unsafe {
                for (i, byte) in mac.iter_mut().enumerate() {
                    *byte = core::ptr::read_volatile((self.device_cfg + i as u64) as *const u8);
                }
            }
            if mac != [0, 0, 0, 0, 0, 0] {
                mac
            } else {
                self.mac_address
            }
        } else {
            self.mac_address
        }
    }

    /// Remplit les 32 descripteurs de la file RX avec les tampons statiques pré-alloués
    pub fn populate_rx_buffers(&mut self) {
        for i in 0..RX_QUEUE_SIZE {
            self.rx_desc[i] = VirtqDesc {
                addr: self.rx_buffers[i].as_ptr() as u64,
                len: RX_BUFFER_SIZE as u32,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            };
            self.rx_avail.ring[i] = i as u16;
        }
        fence(Ordering::SeqCst);
        self.rx_avail.idx = RX_QUEUE_SIZE as u16;
        self.rx_last_used_idx = 0;
        fence(Ordering::SeqCst);

        if self.rx_notify_addr != 0 {
            unsafe {
                core::ptr::write_volatile(self.rx_notify_addr as *mut u16, 0);
            }
        }
    }

    /// Ré-enfile un descripteur RX individuel dans l'anneau Available
    fn requeue_rx_desc(&mut self, desc_idx: usize) {
        if desc_idx >= RX_QUEUE_SIZE {
            return;
        }
        self.rx_desc[desc_idx] = VirtqDesc {
            addr: self.rx_buffers[desc_idx].as_ptr() as u64,
            len: RX_BUFFER_SIZE as u32,
            flags: VRING_DESC_F_WRITE,
            next: 0,
        };
        let avail_idx = self.rx_avail.idx;
        self.rx_avail.ring[(avail_idx as usize) % RX_QUEUE_SIZE] = desc_idx as u16;
        fence(Ordering::SeqCst);
        self.rx_avail.idx = avail_idx.wrapping_add(1);
        fence(Ordering::SeqCst);

        if self.rx_notify_addr != 0 {
            unsafe {
                core::ptr::write_volatile(self.rx_notify_addr as *mut u16, 0);
            }
        }
    }

    /// Initialise le matériel réseau conformément au standard OASIS VirtIO 1.2 Modern
    pub fn init(&mut self) -> Result<(), SysError> {
        if self.common_cfg == 0 {
            return Ok(());
        }

        unsafe {
            // 1. Reset device (status = 0)
            self.write_common_u8(COMMON_CFG_DEVICE_STATUS, 0);
            for _ in 0..1000 {
                if self.read_common_u8(COMMON_CFG_DEVICE_STATUS) == 0 {
                    break;
                }
                core::hint::spin_loop();
            }

            // 2. Set ACKNOWLEDGE | DRIVER
            let mut status = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER;
            self.write_common_u8(COMMON_CFG_DEVICE_STATUS, status);

            // 3. Négociation features (VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC)
            self.write_common_u32(COMMON_CFG_DEVICE_FEATURE_SELECT, 0);
            let dev_feat0 = self.read_common_u32(COMMON_CFG_DEVICE_FEATURE);

            self.write_common_u32(COMMON_CFG_DEVICE_FEATURE_SELECT, 1);
            let dev_feat1 = self.read_common_u32(COMMON_CFG_DEVICE_FEATURE);

            let driver_feat0 = dev_feat0 & (VIRTIO_NET_F_MAC as u32);
            let driver_feat1 = dev_feat1 & 1; // Bit 32: VIRTIO_F_VERSION_1

            self.write_common_u32(COMMON_CFG_DRIVER_FEATURE_SELECT, 0);
            self.write_common_u32(COMMON_CFG_DRIVER_FEATURE, driver_feat0);

            self.write_common_u32(COMMON_CFG_DRIVER_FEATURE_SELECT, 1);
            self.write_common_u32(COMMON_CFG_DRIVER_FEATURE, driver_feat1);

            // 4. Validation des features par le matériel
            status |= VIRTIO_STATUS_FEATURES_OK;
            self.write_common_u8(COMMON_CFG_DEVICE_STATUS, status);

            let current_status = self.read_common_u8(COMMON_CFG_DEVICE_STATUS);
            if (current_status & VIRTIO_STATUS_FEATURES_OK) == 0 {
                return Err(SysError::NotSupported);
            }

            // 5. Configuration Virtqueue 0 (RX)
            self.write_common_u16(COMMON_CFG_QUEUE_SELECT, 0);
            let rx_q_size = self.read_common_u16(COMMON_CFG_QUEUE_SIZE);
            if rx_q_size == 0 {
                return Err(SysError::NotSupported);
            }
            let rx_notify_off = self.read_common_u16(COMMON_CFG_QUEUE_NOTIFY_OFF);
            self.rx_notify_addr = if self.notify_cfg != 0 {
                self.notify_cfg + (rx_notify_off as u64) * (self.notify_off_multiplier as u64)
            } else {
                0
            };

            let rx_desc_paddr = self.rx_desc.as_ptr() as u64;
            let rx_avail_paddr = &self.rx_avail as *const _ as u64;
            let rx_used_paddr = &self.rx_used as *const _ as u64;

            self.write_common_u64(COMMON_CFG_QUEUE_DESC, rx_desc_paddr);
            self.write_common_u64(COMMON_CFG_QUEUE_DRIVER, rx_avail_paddr);
            self.write_common_u64(COMMON_CFG_QUEUE_DEVICE, rx_used_paddr);
            self.write_common_u16(COMMON_CFG_QUEUE_ENABLE, 1);

            // 6. Configuration Virtqueue 1 (TX)
            self.write_common_u16(COMMON_CFG_QUEUE_SELECT, 1);
            let tx_q_size = self.read_common_u16(COMMON_CFG_QUEUE_SIZE);
            if tx_q_size == 0 {
                return Err(SysError::NotSupported);
            }
            let tx_notify_off = self.read_common_u16(COMMON_CFG_QUEUE_NOTIFY_OFF);
            self.tx_notify_addr = if self.notify_cfg != 0 {
                self.notify_cfg + (tx_notify_off as u64) * (self.notify_off_multiplier as u64)
            } else {
                0
            };

            let tx_desc_paddr = self.tx_desc.as_ptr() as u64;
            let tx_avail_paddr = &self.tx_avail as *const _ as u64;
            let tx_used_paddr = &self.tx_used as *const _ as u64;

            self.write_common_u64(COMMON_CFG_QUEUE_DESC, tx_desc_paddr);
            self.write_common_u64(COMMON_CFG_QUEUE_DRIVER, tx_avail_paddr);
            self.write_common_u64(COMMON_CFG_QUEUE_DEVICE, tx_used_paddr);
            self.write_common_u16(COMMON_CFG_QUEUE_ENABLE, 1);

            // 7. Pré-remplissage des tampons RX
            self.populate_rx_buffers();

            // 8. Lecture de l'adresse MAC
            self.mac_address = self.read_mac();

            // 9. Activation finale du périphérique (DRIVER_OK)
            status |= VIRTIO_STATUS_DRIVER_OK;
            self.write_common_u8(COMMON_CFG_DEVICE_STATUS, status);
        }

        Ok(())
    }

    /// Alias pour compatibilité d'interface
    pub fn init_device(&mut self) -> Result<(), SysError> {
        self.init()
    }

    /// Émet une trame Ethernet brute sur la file TX VirtIO
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), SysError> {
        if packet.is_empty() || packet.len() > 1514 {
            return Err(SysError::InvalidArgument);
        }

        if self.common_cfg == 0 {
            self.packets_tx_count = self.packets_tx_count.wrapping_add(1);
            return Ok(());
        }

        // 1. Initialise l'en-tête de trame VirtIO-Net
        self.tx_hdr = VirtioNetHdr::default();

        // 2. Chaînage strict 2 descripteurs :
        // Descripteur 0 : VirtioNetHdr (10 octets, lecture seule matériel)
        self.tx_desc[0] = VirtqDesc {
            addr: &self.tx_hdr as *const _ as u64,
            len: core::mem::size_of::<VirtioNetHdr>() as u32,
            flags: VRING_DESC_F_NEXT,
            next: 1,
        };

        // Descripteur 1 : Données Ethernet (lecture seule matériel)
        self.tx_desc[1] = VirtqDesc {
            addr: packet.as_ptr() as u64,
            len: packet.len() as u32,
            flags: 0,
            next: 0,
        };

        // 3. Enfile le descripteur de tête (0) dans Available Ring
        let avail_idx = self.tx_avail.idx;
        self.tx_avail.ring[(avail_idx as usize) % TX_QUEUE_SIZE] = 0;
        fence(Ordering::SeqCst);
        self.tx_avail.idx = avail_idx.wrapping_add(1);
        fence(Ordering::SeqCst);

        // 4. Sonnette MMIO sur le registre de notification de la file 1 (TX)
        if self.tx_notify_addr != 0 {
            unsafe {
                core::ptr::write_volatile(self.tx_notify_addr as *mut u16, 1);
            }
        }

        // 5. Attente volatile de complétion dans l'anneau Used
        let expected_idx = self.tx_last_used_idx.wrapping_add(1);
        let mut timeout = 1_000_000usize;
        while unsafe { core::ptr::read_volatile(&self.tx_used.idx) } != expected_idx {
            core::hint::spin_loop();
            timeout -= 1;
            if timeout == 0 {
                return Err(SysError::TimedOut);
            }
        }
        self.tx_last_used_idx = expected_idx;
        self.packets_tx_count = self.packets_tx_count.wrapping_add(1);

        Ok(())
    }

    /// Scrute de façon non-bloquante l'arrivée d'une trame Ethernet sur la file RX VirtIO
    pub fn poll_receive(&mut self, out_buf: &mut [u8]) -> Result<Option<usize>, SysError> {
        if self.common_cfg == 0 {
            return Ok(None);
        }

        let current_used_idx = unsafe { core::ptr::read_volatile(&self.rx_used.idx) };
        if current_used_idx == self.rx_last_used_idx {
            return Ok(None);
        }

        let slot = (self.rx_last_used_idx as usize) % RX_QUEUE_SIZE;
        let used_elem = unsafe { core::ptr::read_volatile(&self.rx_used.ring[slot]) };
        self.rx_last_used_idx = self.rx_last_used_idx.wrapping_add(1);

        let desc_idx = (used_elem.id as usize) % RX_QUEUE_SIZE;
        let total_len = used_elem.len as usize;
        let hdr_len = core::mem::size_of::<VirtioNetHdr>();

        let payload_len = total_len.saturating_sub(hdr_len);

        if out_buf.len() < payload_len {
            self.requeue_rx_desc(desc_idx);
            return Err(SysError::BufferTooSmall);
        }

        if payload_len > 0 {
            out_buf[..payload_len]
                .copy_from_slice(&self.rx_buffers[desc_idx][hdr_len..hdr_len + payload_len]);
        }

        self.requeue_rx_desc(desc_idx);
        self.packets_rx_count = self.packets_rx_count.wrapping_add(1);

        Ok(Some(payload_len))
    }

    /// Récupère une trame Ethernet de manière non-bloquante (retourne le nombre d'octets ou 0)
    pub fn receive(&mut self, buf: &mut [u8]) -> Result<usize, SysError> {
        match self.poll_receive(buf)? {
            Some(len) => Ok(len),
            None => Ok(0),
        }
    }
}

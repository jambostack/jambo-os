#![no_std]

use libjambo as _;

/// Spécification OASIS VirtIO 1.2 — Types de requêtes de bloc
pub const VIRTIO_BLK_T_IN: u32 = 0; // Lecture
pub const VIRTIO_BLK_T_OUT: u32 = 1; // Écriture
pub const VIRTIO_BLK_T_FLUSH: u32 = 4; // Barrière de synchronisation cache

/// Statuts de transaction VirtIO-Block
pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Taille standard d'un secteur disque en octets
pub const SECTOR_SIZE: usize = 512;

/// En-tête de requête pour bloc VirtIO (16 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

/// Descripteur de Virtqueue (Ring partagé)
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

/// File disponible (Available Ring)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 32],
}

/// Élément de la file traitée (Used Element)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// File traitée (Used Ring)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; 32],
}

/// Capacités PCI VirtIO Modern (OASIS VirtIO 1.2 Section 4.1.4)
pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
pub const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;

/// Statuts de configuration de périphérique VirtIO
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

/// Features VirtIO 1.0/1.2 standard
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Décalages de registres dans la capacité VirtIO Modern Common Configuration
pub const COMMON_CFG_DEVICE_FEATURE_SELECT: usize = 0x00; // u32
pub const COMMON_CFG_DEVICE_FEATURE: usize = 0x04; // u32
pub const COMMON_CFG_DRIVER_FEATURE_SELECT: usize = 0x08; // u32
pub const COMMON_CFG_DRIVER_FEATURE: usize = 0x0C; // u32
pub const COMMON_CFG_CONFIG_MSIX_VECTOR: usize = 0x10; // u16
pub const COMMON_CFG_NUM_QUEUES: usize = 0x12; // u16
pub const COMMON_CFG_DEVICE_STATUS: usize = 0x14; // u8
pub const COMMON_CFG_CONFIG_GENERATION: usize = 0x15; // u8
pub const COMMON_CFG_QUEUE_SELECT: usize = 0x16; // u16
pub const COMMON_CFG_QUEUE_SIZE: usize = 0x18; // u16
pub const COMMON_CFG_QUEUE_MSIX_VECTOR: usize = 0x1A; // u16
pub const COMMON_CFG_QUEUE_ENABLE: usize = 0x1C; // u16
pub const COMMON_CFG_QUEUE_NOTIFY_OFF: usize = 0x1E; // u16
pub const COMMON_CFG_QUEUE_DESC: usize = 0x20; // u64
pub const COMMON_CFG_QUEUE_DRIVER: usize = 0x28; // u64
pub const COMMON_CFG_QUEUE_DEVICE: usize = 0x30; // u64

/// Opcodes du protocole IPC Block
pub const BLOCK_OP_READ: u32 = 1;
pub const BLOCK_OP_WRITE: u32 = 2;
pub const BLOCK_OP_FLUSH: u32 = 3;

/// Structure de requête IPC de bloc (32 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockRequest {
    pub opcode: u32, // 1 = Read, 2 = Write, 3 = Flush
    pub req_id: u32,
    pub lba: u64,
    pub count: u32,
    pub buf_offset: u32,
    pub _reserved: u32,
}

impl BlockRequest {
    pub fn to_bytes(&self) -> [u8; 32] {
        unsafe { core::mem::transmute(*self) }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Structure de réponse IPC de bloc (16 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockResponse {
    pub req_id: u32,
    pub status: i32,
    pub bytes_transferred: u32,
    pub _reserved: u32,
}

impl BlockResponse {
    pub fn to_bytes(&self) -> [u8; 16] {
        unsafe { core::mem::transmute(*self) }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Pilote VirtIO-Block Modern 1.0 en espace utilisateur Ring 3
pub struct VirtioBlockDriver {
    pub common_cfg_base: u64,
    pub notify_base: u64,
    pub notify_off_multiplier: u32,
    pub capacity_sectors: u64,
    pub notify_addr: u64,
    pub last_used_idx: u16,
    pub desc: [VirtqDesc; 32],
    pub avail: VirtqAvail,
    pub used: VirtqUsed,
    pub req_header: VirtioBlkReqHeader,
    pub req_status: u8,
}

impl VirtioBlockDriver {
    pub fn new(
        common_cfg_base: u64,
        notify_base: u64,
        notify_off_multiplier: u32,
        capacity_sectors: u64,
    ) -> Self {
        Self {
            common_cfg_base,
            notify_base,
            notify_off_multiplier,
            capacity_sectors,
            notify_addr: notify_base,
            last_used_idx: 0,
            desc: [VirtqDesc::default(); 32],
            avail: VirtqAvail::default(),
            used: VirtqUsed::default(),
            req_header: VirtioBlkReqHeader::default(),
            req_status: 0,
        }
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors * (SECTOR_SIZE as u64)
    }

    #[inline]
    unsafe fn write_common_u8(&self, offset: usize, val: u8) {
        if self.common_cfg_base != 0 {
            core::ptr::write_volatile((self.common_cfg_base + offset as u64) as *mut u8, val);
        }
    }

    #[inline]
    unsafe fn read_common_u8(&self, offset: usize) -> u8 {
        if self.common_cfg_base != 0 {
            core::ptr::read_volatile((self.common_cfg_base + offset as u64) as *const u8)
        } else {
            0
        }
    }

    #[inline]
    unsafe fn write_common_u16(&self, offset: usize, val: u16) {
        if self.common_cfg_base != 0 {
            core::ptr::write_volatile((self.common_cfg_base + offset as u64) as *mut u16, val);
        }
    }

    #[inline]
    unsafe fn read_common_u16(&self, offset: usize) -> u16 {
        if self.common_cfg_base != 0 {
            core::ptr::read_volatile((self.common_cfg_base + offset as u64) as *const u16)
        } else {
            0
        }
    }

    #[inline]
    unsafe fn write_common_u32(&self, offset: usize, val: u32) {
        if self.common_cfg_base != 0 {
            core::ptr::write_volatile((self.common_cfg_base + offset as u64) as *mut u32, val);
        }
    }

    #[inline]
    unsafe fn read_common_u32(&self, offset: usize) -> u32 {
        if self.common_cfg_base != 0 {
            core::ptr::read_volatile((self.common_cfg_base + offset as u64) as *const u32)
        } else {
            0
        }
    }

    #[inline]
    unsafe fn write_common_u64(&self, offset: usize, val: u64) {
        if self.common_cfg_base != 0 {
            core::ptr::write_volatile((self.common_cfg_base + offset as u64) as *mut u64, val);
        }
    }

    /// Initialise le matériel conformément au standard OASIS VirtIO 1.2 Modern
    pub fn init_device(&mut self) -> Result<(), libjambo::SysError> {
        if self.common_cfg_base == 0 {
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

            // 3. Négociation features
            self.write_common_u32(COMMON_CFG_DEVICE_FEATURE_SELECT, 1);
            let feat1 = self.read_common_u32(COMMON_CFG_DEVICE_FEATURE);

            self.write_common_u32(COMMON_CFG_DRIVER_FEATURE_SELECT, 0);
            self.write_common_u32(COMMON_CFG_DRIVER_FEATURE, 0);
            self.write_common_u32(COMMON_CFG_DRIVER_FEATURE_SELECT, 1);
            self.write_common_u32(COMMON_CFG_DRIVER_FEATURE, feat1 & 1);

            status |= VIRTIO_STATUS_FEATURES_OK;
            self.write_common_u8(COMMON_CFG_DEVICE_STATUS, status);

            let current_status = self.read_common_u8(COMMON_CFG_DEVICE_STATUS);
            if (current_status & VIRTIO_STATUS_FEATURES_OK) == 0 {
                return Err(libjambo::SysError::NotSupported);
            }

            // 4. Configuration Virtqueue 0
            self.write_common_u16(COMMON_CFG_QUEUE_SELECT, 0);
            let q_size = self.read_common_u16(COMMON_CFG_QUEUE_SIZE);
            if q_size == 0 {
                return Err(libjambo::SysError::NotSupported);
            }
            let notify_off = self.read_common_u16(COMMON_CFG_QUEUE_NOTIFY_OFF);
            self.notify_addr =
                self.notify_base + (notify_off as u64) * (self.notify_off_multiplier as u64);

            let desc_paddr = self.desc.as_ptr() as u64;
            let avail_paddr = &self.avail as *const _ as u64;
            let used_paddr = &self.used as *const _ as u64;

            self.write_common_u64(COMMON_CFG_QUEUE_DESC, desc_paddr);
            self.write_common_u64(COMMON_CFG_QUEUE_DRIVER, avail_paddr);
            self.write_common_u64(COMMON_CFG_QUEUE_DEVICE, used_paddr);
            self.write_common_u16(COMMON_CFG_QUEUE_ENABLE, 1);

            // 5. Set DRIVER_OK
            status |= VIRTIO_STATUS_DRIVER_OK;
            self.write_common_u8(COMMON_CFG_DEVICE_STATUS, status);
        }

        Ok(())
    }

    /// Soumet une lecture de secteur synchrone via VirtIO Ring
    pub fn submit_read(
        &mut self,
        sector: u64,
        buf: &mut [u8],
    ) -> Result<usize, libjambo::SysError> {
        if sector >= self.capacity_sectors {
            return Err(libjambo::SysError::InvalidArgument);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let read_len = buf.len().min(SECTOR_SIZE);

        if self.common_cfg_base == 0 {
            return Ok(read_len);
        }

        self.execute_request(
            VIRTIO_BLK_T_IN,
            sector,
            buf.as_mut_ptr(),
            read_len as u32,
            true,
        )?;
        Ok(read_len)
    }

    /// Soumet une écriture de secteur atomique via VirtIO Ring
    pub fn submit_write(&mut self, sector: u64, buf: &[u8]) -> Result<usize, libjambo::SysError> {
        if sector >= self.capacity_sectors {
            return Err(libjambo::SysError::InvalidArgument);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let write_len = buf.len().min(SECTOR_SIZE);

        if self.common_cfg_base == 0 {
            return Ok(write_len);
        }

        self.execute_request(
            VIRTIO_BLK_T_OUT,
            sector,
            buf.as_ptr() as *mut u8,
            write_len as u32,
            false,
        )?;
        Ok(write_len)
    }

    /// Envoie une barrière de synchronisation de cache disque (Flush)
    pub fn flush(&mut self) -> Result<(), libjambo::SysError> {
        if self.common_cfg_base == 0 {
            return Ok(());
        }

        self.execute_request(VIRTIO_BLK_T_FLUSH, 0, core::ptr::null_mut(), 0, false)?;
        Ok(())
    }

    fn execute_request(
        &mut self,
        req_type: u32,
        sector: u64,
        buf_ptr: *mut u8,
        buf_len: u32,
        is_read: bool,
    ) -> Result<(), libjambo::SysError> {
        // 1. Prépare l'en-tête de requête
        self.req_header = VirtioBlkReqHeader {
            req_type,
            reserved: 0,
            sector,
        };
        self.req_status = 0xFF;

        // 2. Chaînage strict des 3 descripteurs
        // Descripteur 0 : En-tête (Lecture seule matériel)
        self.desc[0] = VirtqDesc {
            addr: &self.req_header as *const _ as u64,
            len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
            flags: VRING_DESC_F_NEXT,
            next: 1,
        };

        // Descripteur 1 : Tampon de données
        let data_flags = if is_read {
            VRING_DESC_F_NEXT | VRING_DESC_F_WRITE
        } else {
            VRING_DESC_F_NEXT
        };
        self.desc[1] = VirtqDesc {
            addr: if buf_ptr.is_null() { 0 } else { buf_ptr as u64 },
            len: buf_len,
            flags: data_flags,
            next: 2,
        };

        // Descripteur 2 : Octet de statut de transaction (Écriture seule matériel)
        self.desc[2] = VirtqDesc {
            addr: &self.req_status as *const _ as u64,
            len: 1,
            flags: VRING_DESC_F_WRITE,
            next: 0,
        };

        // 3. Enfile le descripteur de tête (0) dans Available Ring
        let avail_idx = self.avail.idx;
        self.avail.ring[(avail_idx as usize) % 32] = 0;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.avail.idx = avail_idx.wrapping_add(1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // 4. Sonnette matérielle (Doorbell) par écriture MMIO sur le registre de notification
        if self.notify_addr != 0 {
            unsafe {
                core::ptr::write_volatile(self.notify_addr as *mut u16, 0);
            }
        }

        // 5. Attente de complétion dans Used Ring
        let expected_idx = self.last_used_idx.wrapping_add(1);
        let mut timeout = 1_000_000usize;
        while unsafe { core::ptr::read_volatile(&self.used.idx) } != expected_idx {
            core::hint::spin_loop();
            timeout -= 1;
            if timeout == 0 {
                return Err(libjambo::SysError::TimedOut);
            }
        }
        self.last_used_idx = expected_idx;

        // 6. Vérification du statut de réponse
        let status = unsafe { core::ptr::read_volatile(&self.req_status) };
        match status {
            VIRTIO_BLK_S_OK => Ok(()),
            VIRTIO_BLK_S_UNSUPP => Err(libjambo::SysError::NotSupported),
            _ => Err(libjambo::SysError::InvalidArgument),
        }
    }
}

pub mod gpu;
pub mod net;
pub use gpu::{VirtioGpuDriver, VirtioGpuRect};
pub use net::{
    VirtioNetDriver, VirtioNetHdr, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_MAC, VIRTIO_NET_F_STATUS,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_struct_sizes_and_alignments() {
        assert_eq!(core::mem::size_of::<VirtioBlkReqHeader>(), 16);
        assert_eq!(core::mem::size_of::<VirtqDesc>(), 16);
        assert_eq!(core::mem::align_of::<VirtqDesc>(), 16);
        assert_eq!(core::mem::size_of::<VirtioNetHdr>(), 10);
    }

    #[test]
    fn test_virtio_block_driver_mock_io() {
        let mut blk = VirtioBlockDriver::new(0, 0, 4, 1024);
        assert_eq!(blk.capacity_sectors, 1024);
        assert_eq!(blk.capacity_bytes(), 1024 * 512);

        // En mode mock (common_cfg_base == 0)
        let mut buf = [0u8; 512];
        let r = blk.submit_read(0, &mut buf).expect("Lecture mock");
        assert_eq!(r, 512);

        let w = blk.submit_write(0, &[0xAA; 512]).expect("Écriture mock");
        assert_eq!(w, 512);

        assert!(blk.flush().is_ok());

        // Hors limites
        assert_eq!(
            blk.submit_read(1024, &mut buf),
            Err(libjambo::SysError::InvalidArgument)
        );
        assert_eq!(
            blk.submit_write(1024, &buf),
            Err(libjambo::SysError::InvalidArgument)
        );
    }

    #[test]
    fn test_virtio_net_driver_mock_io() {
        let mut net = VirtioNetDriver::new(0, 0, 4, 0);
        net.mac_address = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        assert_eq!(net.packets_tx_count, 0);
        assert_eq!(net.packets_rx_count, 0);

        let packet = [0u8; 64];
        let tx_res = net.transmit(&packet);
        assert!(tx_res.is_ok());
        assert_eq!(net.packets_tx_count, 1);

        let mut rx_buf = [0u8; 1536];
        let rx_res = net.poll_receive(&mut rx_buf);
        assert_eq!(rx_res, Ok(None));
    }
}

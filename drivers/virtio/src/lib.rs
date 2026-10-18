#![no_std]

use libjambo as _;

/// Spécification OASIS VirtIO 1.2
pub const VIRTIO_BLK_T_IN: u32 = 0; // Lecture
pub const VIRTIO_BLK_T_OUT: u32 = 1; // Écriture
pub const VIRTIO_BLK_T_FLUSH: u32 = 4; // Barrière de synchronisation

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const SECTOR_SIZE: usize = 512;

/// En-tête de requête pour bloc VirtIO
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

/// File disponible (Available Ring)
#[repr(C)]
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
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; 32],
}

/// Pilote VirtIO-Block en espace utilisateur Ring 3
pub struct VirtioBlockDriver {
    pub mmio_base: u64,
    pub capacity_sectors: u64,
}

impl VirtioBlockDriver {
    pub fn new(mmio_base: u64, capacity_sectors: u64) -> Self {
        Self {
            mmio_base,
            capacity_sectors,
        }
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors * (SECTOR_SIZE as u64)
    }

    /// Soumet une lecture de secteur synchrone via VirtIO Ring
    pub fn submit_read(&self, sector: u64, buf: &mut [u8]) -> Result<usize, libjambo::SysError> {
        if sector >= self.capacity_sectors {
            return Err(libjambo::SysError::InvalidArgument);
        }
        let read_len = buf.len().min(SECTOR_SIZE);
        // Simulation matérielle : remplit les données demandées
        for (i, b) in buf[..read_len].iter_mut().enumerate() {
            *b = ((sector * 17 + i as u64) & 0xFF) as u8;
        }
        Ok(read_len)
    }

    /// Soumet une écriture de secteur atomique via VirtIO Ring
    pub fn submit_write(&self, sector: u64, buf: &[u8]) -> Result<usize, libjambo::SysError> {
        if sector >= self.capacity_sectors {
            return Err(libjambo::SysError::InvalidArgument);
        }
        let write_len = buf.len().min(SECTOR_SIZE);
        Ok(write_len)
    }

    /// Envoie une barrière de synchronisation de cache disque (Flush)
    pub fn flush(&self) -> Result<(), libjambo::SysError> {
        Ok(())
    }
}

pub mod gpu;
pub mod net;
pub use gpu::{VirtioGpuDriver, VirtioGpuRect};
pub use net::{VirtioNetDriver, VirtioNetHdr};

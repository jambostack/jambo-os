//! Bibliothèque d'abstraction et de gestion du démon de stockage en bloc (jambo-blockd).
//!
//! Assure le multiplexage et l'orchestration des pilotes de périphériques de stockage
//! (VirtIO Block et NVMe 1.4) en espace utilisateur (Ring 3), avec support du VMO
//! partagé zéro-copie et traitement sécurisé des requêtes IPC.

#![no_std]

#[cfg(test)]
extern crate std;

use libjambo::SysError;
use nvme_drv::NvmeController;
use virtio_drv::VirtioBlockDriver;

pub const BLOCK_OP_GET_VMO: u32 = 0;
pub const BLOCK_OP_READ: u32 = 1;
pub const BLOCK_OP_WRITE: u32 = 2;
pub const BLOCK_OP_FLUSH: u32 = 3;

pub const SHARED_VMO_ADDR: usize = 0x0070_0000;
pub const SHARED_VMO_SIZE: usize = 64 * 1024;
pub const SECTOR_SIZE: usize = 512;

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

/// Structure de requête IPC de bloc (32 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRequest {
    pub opcode: u32, // 0 = GetVmo, 1 = Read, 2 = Write, 3 = Flush
    pub req_id: u32,
    pub lba: u64,
    pub count: u32,
    pub buf_offset: u32,
    pub _reserved: u32,
}

impl BlockRequest {
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                core::mem::size_of::<Self>(),
            );
        }
        bytes
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockResponse {
    pub req_id: u32,
    pub status: i32,
    pub bytes_transferred: u32,
    pub _reserved: u32,
}

impl BlockResponse {
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                core::mem::size_of::<Self>(),
            );
        }
        bytes
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

/// Message IPC sur canal hybride (Fastpath 64 octets + Handles)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [libjambo::Handle; MAX_HANDLES],
    pub handle_count: usize,
}

impl Default for ChannelMessage {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
            handles: [libjambo::Handle::NULL; MAX_HANDLES],
            handle_count: 0,
        }
    }
}

/// Type de pilote de stockage sous-jacent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackendKind {
    Virtio,
    Nvme,
}

/// Backend de stockage unifié gérant soit VirtIO Block, soit NVMe 1.4
#[allow(clippy::large_enum_variant)]
pub enum UnifiedBlockStorage {
    Virtio(VirtioBlockDriver),
    Nvme(NvmeController),
}

impl UnifiedBlockStorage {
    pub fn kind(&self) -> StorageBackendKind {
        match self {
            Self::Virtio(_) => StorageBackendKind::Virtio,
            Self::Nvme(_) => StorageBackendKind::Nvme,
        }
    }

    pub fn capacity_sectors(&self) -> u64 {
        match self {
            Self::Virtio(drv) => drv.capacity_sectors,
            Self::Nvme(ctrl) => ctrl.namespace_size_blocks,
        }
    }

    pub fn submit_read(&mut self, lba: u64, dest: &mut [u8]) -> Result<usize, SysError> {
        match self {
            Self::Virtio(drv) => drv.submit_read(lba, dest),
            Self::Nvme(ctrl) => {
                let count = (dest.len().div_ceil(SECTOR_SIZE)).min(u16::MAX as usize) as u16;
                ctrl.read_blocks(lba, count, dest.as_ptr() as u64)?;
                Ok(dest.len())
            }
        }
    }

    pub fn submit_write(&mut self, lba: u64, src: &[u8]) -> Result<usize, SysError> {
        match self {
            Self::Virtio(drv) => drv.submit_write(lba, src),
            Self::Nvme(ctrl) => {
                let count = (src.len().div_ceil(SECTOR_SIZE)).min(u16::MAX as usize) as u16;
                ctrl.write_blocks(lba, count, src.as_ptr() as u64)?;
                Ok(src.len())
            }
        }
    }

    pub fn flush(&mut self) -> Result<(), SysError> {
        match self {
            Self::Virtio(drv) => drv.flush(),
            Self::Nvme(ctrl) => ctrl.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_request_serialization() {
        let req = BlockRequest {
            opcode: BLOCK_OP_READ,
            req_id: 101,
            lba: 2082,
            count: 8,
            buf_offset: 512,
            _reserved: 0,
        };
        let bytes = req.to_bytes();
        let parsed = BlockRequest::from_bytes(&bytes).expect("Désérialisation valide");
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_block_response_serialization() {
        let resp = BlockResponse {
            req_id: 101,
            status: 0,
            bytes_transferred: 4096,
            _reserved: 0,
        };
        let bytes = resp.to_bytes();
        let parsed = BlockResponse::from_bytes(&bytes).expect("Désérialisation valide");
        assert_eq!(resp, parsed);
    }

    #[test]
    fn test_storage_backend_kind() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;
        let mut storage = UnifiedBlockStorage::Nvme(ctrl);

        assert_eq!(storage.kind(), StorageBackendKind::Nvme);
        assert_eq!(storage.capacity_sectors(), 2_097_152);

        let mut buf = [0u8; 512];
        let res = storage.submit_read(100, &mut buf);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 512);

        let write_res = storage.submit_write(100, &buf);
        assert!(write_res.is_ok());
        assert_eq!(write_res.unwrap(), 512);

        assert!(storage.flush().is_ok());
    }
}

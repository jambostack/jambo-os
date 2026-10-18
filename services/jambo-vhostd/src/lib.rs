//! Démon de Virtualisation de Périphériques vhost-user et E/S Invitées Découplées (jambo-vhostd)
//!
//! Assure l'émulation haute performance et isolée en Ring 3 des périphériques virtuels
//! VirtIO (VirtIO-Net, VirtIO-Block) pour les micro-machines virtuelles (`jambo-vmm`).
//! Conforme à l'architecture sans autorité ambiante, chaque backend de périphérique
//! est régi par une capacité `VhostCap` et opère sur la mémoire partagée sans copie.

#![no_std]

use libjambo::{Handle, SysError};

/// Droits de capacité pour la gestion de périphériques virtuels vhost-user
pub mod vhost_rights {
    pub const VHOST_NET_BACKEND: u32 = 0x01;
    pub const VHOST_BLK_BACKEND: u32 = 0x02;
    pub const MEMORY_MAP_SHARED: u32 = 0x04;
    pub const KICK_SIGNAL: u32 = 0x08;
    pub const ALL: u32 = VHOST_NET_BACKEND | VHOST_BLK_BACKEND | MEMORY_MAP_SHARED | KICK_SIGNAL;
}

/// Capacité d'administration d'un périphérique ou canal vhost-user
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhostCap {
    pub handle: Handle,
    pub device_id: u32,
    pub rights: u32,
}

impl VhostCap {
    pub const fn new(handle: Handle, device_id: u32, rights: u32) -> Self {
        Self {
            handle,
            device_id,
            rights,
        }
    }

    pub fn can_net_backend(&self) -> bool {
        (self.rights & vhost_rights::VHOST_NET_BACKEND) != 0
    }

    pub fn can_blk_backend(&self) -> bool {
        (self.rights & vhost_rights::VHOST_BLK_BACKEND) != 0
    }

    pub fn can_map_shared(&self) -> bool {
        (self.rights & vhost_rights::MEMORY_MAP_SHARED) != 0
    }

    pub fn can_kick(&self) -> bool {
        (self.rights & vhost_rights::KICK_SIGNAL) != 0
    }
}

/// Requêtes du protocole normalisé vhost-user
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhostUserRequest {
    GetFeatures,
    SetFeatures(u64),
    SetOwner,
    SetMemTable {
        num_regions: u32,
    },
    SetVringNum {
        index: u32,
        num: u32,
    },
    SetVringAddr {
        index: u32,
        desc_addr: u64,
        avail_addr: u64,
        used_addr: u64,
    },
    SetVringKick {
        index: u32,
    },
    SetVringCall {
        index: u32,
    },
}

/// Flags standards de descripteur Virtqueue
pub mod vring_desc_flags {
    pub const NEXT: u16 = 0x01;
    pub const WRITE: u16 = 0x02;
    pub const INDIRECT: u16 = 0x04;
}

/// Structure de descripteur Virtqueue (16 octets standard VirtIO)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// État d'une file d'attente virtuelle (Virtqueue)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VhostVirtqueue {
    pub index: u32,
    pub num: u32,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
    pub last_avail_idx: u16,
    pub last_used_idx: u16,
    pub enabled: bool,
}

pub const MAX_VRINGS_PER_DEVICE: usize = 2;
pub const MAX_PACKET_SIZE: usize = 1514;
pub const SECTOR_SIZE: usize = 512;

/// Type de périphérique virtuel pris en charge
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhostDeviceType {
    Net,
    Block,
}

/// Backend de carte réseau virtuelle VirtIO-Net
pub struct VhostNetDevice {
    pub device_id: u32,
    pub mac_address: [u8; 6],
    pub vrings: [VhostVirtqueue; MAX_VRINGS_PER_DEVICE],
    pub negotiated_features: u64,
    pub rx_packets_count: u64,
    pub tx_packets_count: u64,
    pub last_tx_packet: [u8; MAX_PACKET_SIZE],
    pub last_tx_len: usize,
}

impl VhostNetDevice {
    pub fn new(device_id: u32, mac: [u8; 6]) -> Self {
        Self {
            device_id,
            mac_address: mac,
            vrings: [VhostVirtqueue::default(); MAX_VRINGS_PER_DEVICE],
            negotiated_features: 0,
            rx_packets_count: 0,
            tx_packets_count: 0,
            last_tx_packet: [0u8; MAX_PACKET_SIZE],
            last_tx_len: 0,
        }
    }

    /// Traite un paquet transmis par l'invité (Tx)
    pub fn transmit_packet(&mut self, cap: &VhostCap, packet: &[u8]) -> Result<(), SysError> {
        if !cap.can_net_backend() || cap.device_id != self.device_id {
            return Err(SysError::PermissionDenied);
        }

        if packet.is_empty() || packet.len() > MAX_PACKET_SIZE {
            return Err(SysError::InvalidArgument);
        }

        self.last_tx_packet[..packet.len()].copy_from_slice(packet);
        self.last_tx_len = packet.len();
        self.tx_packets_count += 1;
        Ok(())
    }

    /// Injecte un paquet réseau vers l'invité (Rx)
    pub fn receive_packet(
        &mut self,
        cap: &VhostCap,
        dest_buf: &mut [u8],
        packet: &[u8],
    ) -> Result<usize, SysError> {
        if !cap.can_net_backend() || cap.device_id != self.device_id {
            return Err(SysError::PermissionDenied);
        }

        if dest_buf.len() < packet.len() {
            return Err(SysError::BufferTooSmall);
        }

        dest_buf[..packet.len()].copy_from_slice(packet);
        self.rx_packets_count += 1;
        Ok(packet.len())
    }
}

/// Requête de stockage de bloc VirtIO-Blk
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhostBlkType {
    Read,
    Write,
    Flush,
}

/// Backend de disque virtuel VirtIO-Block
pub struct VhostBlkDevice {
    pub device_id: u32,
    pub capacity_sectors: u64,
    pub vrings: [VhostVirtqueue; MAX_VRINGS_PER_DEVICE],
    pub negotiated_features: u64,
    pub reads_count: u64,
    pub writes_count: u64,
}

impl VhostBlkDevice {
    pub fn new(device_id: u32, capacity_sectors: u64) -> Self {
        Self {
            device_id,
            capacity_sectors,
            vrings: [VhostVirtqueue::default(); MAX_VRINGS_PER_DEVICE],
            negotiated_features: 0,
            reads_count: 0,
            writes_count: 0,
        }
    }

    /// Exécute une opération d'E/S bloc contrôlée par capacité
    pub fn handle_io(
        &mut self,
        cap: &VhostCap,
        req_type: VhostBlkType,
        sector: u64,
        buffer: &mut [u8],
        storage_sector: &mut [u8],
    ) -> Result<(), SysError> {
        if !cap.can_blk_backend() || cap.device_id != self.device_id {
            return Err(SysError::PermissionDenied);
        }

        if sector >= self.capacity_sectors || buffer.len() < SECTOR_SIZE {
            return Err(SysError::InvalidArgument);
        }

        match req_type {
            VhostBlkType::Read => {
                buffer[..SECTOR_SIZE].copy_from_slice(&storage_sector[..SECTOR_SIZE]);
                self.reads_count += 1;
            }
            VhostBlkType::Write => {
                storage_sector[..SECTOR_SIZE].copy_from_slice(&buffer[..SECTOR_SIZE]);
                self.writes_count += 1;
            }
            VhostBlkType::Flush => {}
        }

        Ok(())
    }
}

/// Serveur de virtualisation de périphériques vhost-user
pub struct VhostServer {
    pub net_devices: [Option<VhostNetDevice>; 2],
    pub blk_devices: [Option<VhostBlkDevice>; 2],
}

impl Default for VhostServer {
    fn default() -> Self {
        Self::new()
    }
}

impl VhostServer {
    pub const fn new() -> Self {
        Self {
            net_devices: [None, None],
            blk_devices: [None, None],
        }
    }

    /// Enregistre un nouveau périphérique réseau
    pub fn register_net_device(
        &mut self,
        cap: &VhostCap,
        device_id: u32,
        mac: [u8; 6],
    ) -> Result<(), SysError> {
        if !cap.can_net_backend() || cap.device_id != device_id {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.net_devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(VhostNetDevice::new(device_id, mac));
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Enregistre un nouveau périphérique de stockage bloc
    pub fn register_blk_device(
        &mut self,
        cap: &VhostCap,
        device_id: u32,
        capacity_sectors: u64,
    ) -> Result<(), SysError> {
        if !cap.can_blk_backend() || cap.device_id != device_id {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.blk_devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(VhostBlkDevice::new(device_id, capacity_sectors));
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Configure une virtqueue selon un message vhost-user
    pub fn dispatch_request(
        &mut self,
        cap: &VhostCap,
        device_id: u32,
        req: VhostUserRequest,
    ) -> Result<u64, SysError> {
        if (!cap.can_net_backend() && !cap.can_blk_backend()) || cap.device_id != device_id {
            return Err(SysError::PermissionDenied);
        }

        match req {
            VhostUserRequest::GetFeatures => {
                // Features standard VirtIO 1.2
                Ok(0x1_0000_0000)
            }
            VhostUserRequest::SetFeatures(feat) => {
                // Enregistre les fonctionnalités négociées
                if let Some(dev) = self.find_net_device_mut(device_id) {
                    dev.negotiated_features = feat;
                } else if let Some(dev) = self.find_blk_device_mut(device_id) {
                    dev.negotiated_features = feat;
                }
                Ok(0)
            }
            VhostUserRequest::SetOwner => Ok(0),
            VhostUserRequest::SetMemTable { num_regions: _ } => {
                if !cap.can_map_shared() {
                    return Err(SysError::PermissionDenied);
                }
                Ok(0)
            }
            VhostUserRequest::SetVringNum { index, num } => {
                let vring = self.find_vring_mut(device_id, index)?;
                vring.num = num;
                vring.enabled = true;
                Ok(0)
            }
            VhostUserRequest::SetVringAddr {
                index,
                desc_addr,
                avail_addr,
                used_addr,
            } => {
                let vring = self.find_vring_mut(device_id, index)?;
                vring.desc_addr = desc_addr;
                vring.avail_addr = avail_addr;
                vring.used_addr = used_addr;
                Ok(0)
            }
            VhostUserRequest::SetVringKick { index: _ } => {
                if !cap.can_kick() {
                    return Err(SysError::PermissionDenied);
                }
                Ok(0)
            }
            VhostUserRequest::SetVringCall { index: _ } => Ok(0),
        }
    }

    fn find_net_device_mut(&mut self, device_id: u32) -> Option<&mut VhostNetDevice> {
        for slot in self.net_devices.iter_mut() {
            if let Some(dev) = slot {
                if dev.device_id == device_id {
                    return Some(dev);
                }
            }
        }
        None
    }

    fn find_blk_device_mut(&mut self, device_id: u32) -> Option<&mut VhostBlkDevice> {
        for slot in self.blk_devices.iter_mut() {
            if let Some(dev) = slot {
                if dev.device_id == device_id {
                    return Some(dev);
                }
            }
        }
        None
    }

    fn find_vring_mut(
        &mut self,
        device_id: u32,
        vring_index: u32,
    ) -> Result<&mut VhostVirtqueue, SysError> {
        if vring_index as usize >= MAX_VRINGS_PER_DEVICE {
            return Err(SysError::InvalidArgument);
        }

        if let Some(dev) = self.find_net_device_mut(device_id) {
            return Ok(&mut dev.vrings[vring_index as usize]);
        }
        if let Some(dev) = self.find_blk_device_mut(device_id) {
            return Ok(&mut dev.vrings[vring_index as usize]);
        }

        Err(SysError::InvalidArgument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vhost_cap_rights() {
        let cap_full = VhostCap::new(Handle::new(1, 0), 10, vhost_rights::ALL);
        assert!(cap_full.can_net_backend());
        assert!(cap_full.can_blk_backend());
        assert!(cap_full.can_map_shared());
        assert!(cap_full.can_kick());

        let cap_net_only = VhostCap::new(Handle::new(2, 0), 10, vhost_rights::VHOST_NET_BACKEND);
        assert!(cap_net_only.can_net_backend());
        assert!(!cap_net_only.can_blk_backend());
        assert!(!cap_net_only.can_map_shared());
        assert!(!cap_net_only.can_kick());
    }

    #[test]
    fn test_vhost_net_device_transmission() {
        let cap = VhostCap::new(Handle::new(1, 0), 1, vhost_rights::VHOST_NET_BACKEND);
        let mut net_dev = VhostNetDevice::new(1, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

        let packet = b"JAMBO_VHOST_NET_FRAME";
        assert!(net_dev.transmit_packet(&cap, packet).is_ok());
        assert_eq!(net_dev.tx_packets_count, 1);
        assert_eq!(&net_dev.last_tx_packet[..packet.len()], packet);

        // Réception
        let mut rx_buf = [0u8; 64];
        let rx_len = net_dev
            .receive_packet(&cap, &mut rx_buf, packet)
            .expect("rx packet");
        assert_eq!(rx_len, packet.len());
        assert_eq!(&rx_buf[..rx_len], packet);
        assert_eq!(net_dev.rx_packets_count, 1);
    }

    #[test]
    fn test_vhost_blk_device_io() {
        let cap = VhostCap::new(Handle::new(1, 0), 2, vhost_rights::VHOST_BLK_BACKEND);
        let mut blk_dev = VhostBlkDevice::new(2, 2048);

        let mut storage_sector = [0u8; SECTOR_SIZE];
        let mut write_buf = [0u8; SECTOR_SIZE];
        write_buf[..5].copy_from_slice(b"JAMBO");

        // Écriture de bloc
        assert!(blk_dev
            .handle_io(
                &cap,
                VhostBlkType::Write,
                10,
                &mut write_buf,
                &mut storage_sector
            )
            .is_ok());
        assert_eq!(&storage_sector[..5], b"JAMBO");
        assert_eq!(blk_dev.writes_count, 1);

        // Lecture de bloc
        let mut read_buf = [0u8; SECTOR_SIZE];
        assert!(blk_dev
            .handle_io(
                &cap,
                VhostBlkType::Read,
                10,
                &mut read_buf,
                &mut storage_sector
            )
            .is_ok());
        assert_eq!(&read_buf[..5], b"JAMBO");
        assert_eq!(blk_dev.reads_count, 1);
    }

    #[test]
    fn test_vhost_server_dispatch_and_unauthorized_rejection() {
        let mut server = VhostServer::new();
        let cap = VhostCap::new(Handle::new(1, 0), 5, vhost_rights::ALL);

        assert!(server.register_net_device(&cap, 5, [0x0; 6]).is_ok());

        // Configuration vhost-user
        assert!(server
            .dispatch_request(&cap, 5, VhostUserRequest::SetVringNum { index: 0, num: 64 })
            .is_ok());
        assert_eq!(server.net_devices[0].as_ref().unwrap().vrings[0].num, 64);
        assert!(server.net_devices[0].as_ref().unwrap().vrings[0].enabled);

        // Capacité non autorisée
        let unauth_cap = VhostCap::new(Handle::new(9, 0), 5, 0);
        let rej = server.dispatch_request(
            &unauth_cap,
            5,
            VhostUserRequest::SetVringNum { index: 0, num: 32 },
        );
        assert_eq!(rej, Err(SysError::PermissionDenied));
    }
}

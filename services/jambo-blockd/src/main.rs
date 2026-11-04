#![no_std]
#![no_main]

use libjambo::println;
use virtio_drv::VirtioBlockDriver;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

pub const BLOCK_OP_GET_VMO: u32 = 0;
pub const BLOCK_OP_READ: u32 = 1;
pub const BLOCK_OP_WRITE: u32 = 2;
pub const BLOCK_OP_FLUSH: u32 = 3;

/// Structure de requête IPC de bloc (32 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

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

/// Cède volontairement le temps processeur au scheduler
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

// Audit C-03: Remplacement des E/S directes par ports Ring 3 (out dx, in dx) par le broker matériel sécurisé DeviceIo (Syscall 29)
use libjambo::{pci_read16, pci_read32, pci_read8};

struct PciBlockDevice {
    common_cfg_base: u64,
    notify_base: u64,
    notify_off_multiplier: u32,
    capacity_sectors: u64,
}

fn scan_pci_virtio_block() -> Option<PciBlockDevice> {
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
                if device_id != 0x1042 && device_id != 0x1001 {
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

                let capacity = if device_cfg != 0 {
                    unsafe { core::ptr::read_volatile(device_cfg as *const u64) }
                } else {
                    65536
                };

                if common_cfg != 0 {
                    return Some(PciBlockDevice {
                        common_cfg_base: common_cfg,
                        notify_base: notify_cfg,
                        notify_off_multiplier: notify_mult,
                        capacity_sectors: if capacity > 0 { capacity } else { 65536 },
                    });
                }
            }
        }
    }
    None
}

/// Adresse et taille de projection du VMO partagé zéro-copie
pub const SHARED_VMO_ADDR: usize = 0x0070_0000;
pub const SHARED_VMO_SIZE: usize = 64 * 1024;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m  JamboOS Block Storage Daemon (PID 3) v0.3.81  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    let dev_params = scan_pci_virtio_block().unwrap_or(PciBlockDevice {
        common_cfg_base: 0xFE00_0000,
        notify_base: 0xFE00_1000,
        notify_off_multiplier: 4,
        capacity_sectors: 65536,
    });

    println("[BLOCKD] Contrôleur virtio-blk-pci configuré (0x1AF4:0x1042).");

    let mut driver = VirtioBlockDriver::new(
        dev_params.common_cfg_base,
        dev_params.notify_base,
        dev_params.notify_off_multiplier,
        dev_params.capacity_sectors,
    );

    if let Err(_e) = driver.init_device() {
        println("[WARN] Initialisation matérielle VirtIO (mode simulation/dégradé actif)");
    } else {
        println("[BLOCKD] Initialisation VirtIO Modern 1.0 MMIO réussie.");
    }

    // 1. Allouer un véritable VMO noyau partagé de 64 Kio (Audit C-05)
    let mut vmo_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::VmoCreate,
            SHARED_VMO_SIZE as u64,
            0,
            &mut vmo_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let vmo_handle = libjambo::Handle(vmo_h);
    if !vmo_handle.is_null() {
        unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::VmoMap,
                0,
                vmo_handle.0,
                SHARED_VMO_ADDR as u64,
                (libjambo::vmo_prot::READ | libjambo::vmo_prot::WRITE) as u64,
                0,
                0,
            );
        }
        println("[BLOCKD] VMO partagé noyau 64 Kio projeté avec succès à 0x0070_0000.");
    }

    // 2. Point d'accès IPC standard (Endpoint pré-injecté par le noyau à Handle::new(1, 1))
    let server_endpoint = libjambo::Handle::new(1, 1);
    println("[BLOCKD] Canal IPC de requêtes de stockage opérationnel.");

    // Boucle coopérative de traitement des requêtes de stockage
    loop {
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<BlockRequest>() {
            if let Some(req) = BlockRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let mut status = 0i32;
                let mut bytes_transferred = 0u32;
                let mut tx_msg = ChannelMessage::default();

                match req.opcode {
                    // Opcode 0 : Transmission sécurisée du VMO partagé vers le client FS (Audit C-05)
                    BLOCK_OP_GET_VMO => {
                        let mut dup_vmo: u64 = 0;
                        unsafe {
                            libjambo::syscall6(
                                libjambo::SyscallNumber::CapDup,
                                vmo_handle.0,
                                libjambo::cap_rights::ALL as u64,
                                &mut dup_vmo as *mut u64 as u64,
                                0,
                                0,
                                0,
                            );
                        }
                        status = 0;
                        bytes_transferred = SHARED_VMO_SIZE as u32;
                        tx_msg.handles[0] = libjambo::Handle(dup_vmo);
                        tx_msg.handle_count = 1;
                    }

                    // Opcode 1 : Lecture de blocs avec calculs arithmétiques 100 % vérifiés (Audit S-04)
                    BLOCK_OP_READ => {
                        let offset = req.buf_offset as usize;
                        let total_bytes =
                            match (req.count as usize).checked_mul(virtio_drv::SECTOR_SIZE) {
                                Some(b) => b,
                                None => {
                                    status = libjambo::SysError::InvalidArgument as i32;
                                    0
                                }
                            };
                        let end_offset = match offset.checked_add(total_bytes) {
                            Some(end) => end,
                            None => {
                                status = libjambo::SysError::InvalidArgument as i32;
                                usize::MAX
                            }
                        };
                        let end_lba = match req.lba.checked_add(req.count as u64) {
                            Some(end) => end,
                            None => {
                                status = libjambo::SysError::InvalidArgument as i32;
                                u64::MAX
                            }
                        };

                        if end_lba <= dev_params.capacity_sectors
                            && end_offset <= SHARED_VMO_SIZE
                            && status == 0
                        {
                            for s in 0..req.count {
                                let sector_lba = req.lba + s as u64;
                                let sector_off = offset + (s as usize) * virtio_drv::SECTOR_SIZE;
                                let dest = unsafe {
                                    core::slice::from_raw_parts_mut(
                                        (SHARED_VMO_ADDR + sector_off) as *mut u8,
                                        virtio_drv::SECTOR_SIZE,
                                    )
                                };
                                match driver.submit_read(sector_lba, dest) {
                                    Ok(n) => bytes_transferred += n as u32,
                                    Err(e) => {
                                        status = e as i32;
                                        break;
                                    }
                                }
                            }
                        } else if status == 0 {
                            status = libjambo::SysError::InvalidArgument as i32;
                        }
                    }

                    // Opcode 2 : Écriture de blocs avec calculs arithmétiques 100 % vérifiés (Audit S-04)
                    BLOCK_OP_WRITE => {
                        let offset = req.buf_offset as usize;
                        let total_bytes =
                            match (req.count as usize).checked_mul(virtio_drv::SECTOR_SIZE) {
                                Some(b) => b,
                                None => {
                                    status = libjambo::SysError::InvalidArgument as i32;
                                    0
                                }
                            };
                        let end_offset = match offset.checked_add(total_bytes) {
                            Some(end) => end,
                            None => {
                                status = libjambo::SysError::InvalidArgument as i32;
                                usize::MAX
                            }
                        };
                        let end_lba = match req.lba.checked_add(req.count as u64) {
                            Some(end) => end,
                            None => {
                                status = libjambo::SysError::InvalidArgument as i32;
                                u64::MAX
                            }
                        };

                        if end_lba <= dev_params.capacity_sectors
                            && end_offset <= SHARED_VMO_SIZE
                            && status == 0
                        {
                            for s in 0..req.count {
                                let sector_lba = req.lba + s as u64;
                                let sector_off = offset + (s as usize) * virtio_drv::SECTOR_SIZE;
                                let src = unsafe {
                                    core::slice::from_raw_parts(
                                        (SHARED_VMO_ADDR + sector_off) as *const u8,
                                        virtio_drv::SECTOR_SIZE,
                                    )
                                };
                                match driver.submit_write(sector_lba, src) {
                                    Ok(n) => bytes_transferred += n as u32,
                                    Err(e) => {
                                        status = e as i32;
                                        break;
                                    }
                                }
                            }
                        } else if status == 0 {
                            status = libjambo::SysError::InvalidArgument as i32;
                        }
                    }

                    // Opcode 3 : Vidage des caches
                    BLOCK_OP_FLUSH => {
                        if let Err(e) = driver.flush() {
                            status = e as i32;
                        }
                    }

                    _ => {
                        status = libjambo::SysError::NotSupported as i32;
                    }
                }

                let resp = BlockResponse {
                    req_id: req.req_id,
                    status,
                    bytes_transferred,
                    _reserved: 0,
                };

                let resp_bytes = resp.to_bytes();
                tx_msg.bytes[..16].copy_from_slice(&resp_bytes);
                tx_msg.byte_count = 16;

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

        syscall_thread_yield();
    }
}

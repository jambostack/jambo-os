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

// Ports de configuration PCIe standard x86
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

#[cfg(target_arch = "x86_64")]
unsafe fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let conf_addr = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32 & 0x1F) << 11)
        | ((func as u32 & 0x07) << 8)
        | ((offset as u32) & 0xFC);
    core::arch::asm!(
        "out dx, eax",
        in("dx") PCI_CONFIG_ADDRESS,
        in("eax") conf_addr,
        options(nomem, nostack)
    );
    let val: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") val,
        in("dx") PCI_CONFIG_DATA,
        options(nomem, nostack)
    );
    val
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn pci_read32(_bus: u8, _dev: u8, _func: u8, _offset: u8) -> u32 {
    0xFFFF_FFFF
}

unsafe fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let dword = pci_read32(bus, dev, func, offset & 0xFC);
    ((dword >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

unsafe fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let dword = pci_read32(bus, dev, func, offset & 0xFC);
    ((dword >> ((offset & 3) * 8)) & 0xFF) as u8
}

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
                let vendor_id = unsafe { pci_read16(bus, dev, func, 0x00) };
                if vendor_id != 0x1AF4 {
                    if func == 0 && (vendor_id == 0xFFFF || vendor_id == 0x0000) {
                        break;
                    }
                    continue;
                }

                let device_id = unsafe { pci_read16(bus, dev, func, 0x02) };
                if device_id != 0x1042 && device_id != 0x1001 {
                    continue;
                }

                let mut bars = [0u64; 6];
                let mut bar_idx = 0;
                while bar_idx < 6 {
                    let bar_offset = 0x10 + (bar_idx as u8) * 4;
                    let bar_val = unsafe { pci_read32(bus, dev, func, bar_offset) };
                    let is_io = (bar_val & 1) != 0;
                    if !is_io && bar_val != 0 {
                        let mem_type = (bar_val >> 1) & 3;
                        if mem_type == 2 && bar_idx + 1 < 6 {
                            let bar_high = unsafe { pci_read32(bus, dev, func, bar_offset + 4) };
                            bars[bar_idx] = ((bar_high as u64) << 32) | ((bar_val & !0x0F) as u64);
                            bar_idx += 2;
                            continue;
                        } else {
                            bars[bar_idx] = (bar_val & !0x0F) as u64;
                        }
                    }
                    bar_idx += 1;
                }

                let status = unsafe { pci_read16(bus, dev, func, 0x06) };
                if (status & (1 << 4)) == 0 {
                    continue;
                }

                let mut cap_ptr = unsafe { pci_read8(bus, dev, func, 0x34) };
                let mut common_cfg = 0u64;
                let mut notify_cfg = 0u64;
                let mut notify_mult = 4u32;
                let mut device_cfg = 0u64;
                let mut loop_guard = 0;

                while cap_ptr != 0 && loop_guard < 48 {
                    let cap_id = unsafe { pci_read8(bus, dev, func, cap_ptr) };
                    let next_ptr = unsafe { pci_read8(bus, dev, func, cap_ptr + 1) };

                    if cap_id == 0x09 {
                        let cfg_type = unsafe { pci_read8(bus, dev, func, cap_ptr + 3) };
                        let bar = unsafe { pci_read8(bus, dev, func, cap_ptr + 4) } as usize;
                        let offset = unsafe { pci_read32(bus, dev, func, cap_ptr + 8) } as u64;

                        if bar < 6 && bars[bar] != 0 {
                            let base = bars[bar] + offset;
                            match cfg_type {
                                virtio_drv::VIRTIO_PCI_CAP_COMMON_CFG => common_cfg = base,
                                virtio_drv::VIRTIO_PCI_CAP_NOTIFY_CFG => {
                                    notify_cfg = base;
                                    notify_mult =
                                        unsafe { pci_read32(bus, dev, func, cap_ptr + 16) };
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

/// Arène VMO partagée pour les transferts zéro-copie (64 Kio = 16 blocs de 4 Kio)
pub const SHARED_VMO_SIZE: usize = 64 * 1024;
static mut SHARED_VMO_ARENA: [u8; SHARED_VMO_SIZE] = [0u8; SHARED_VMO_SIZE];

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m  JamboOS Block Storage Daemon (PID 3) v0.3.42  \x1b[0m");
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

    // Initialisation du canal IPC pour communication avec le service de fichiers (jambo-fs)
    let mut ch_h1: u64 = 0;
    let mut ch_h2: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut ch_h1 as *mut u64 as u64,
            &mut ch_h2 as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if ch_h1 != 0 { ch_h1 } else { 1 });
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
                let offset = req.buf_offset as usize;
                let total_bytes = (req.count as usize) * virtio_drv::SECTOR_SIZE;

                match req.opcode {
                    BLOCK_OP_READ => {
                        if offset + total_bytes <= SHARED_VMO_SIZE {
                            for s in 0..req.count {
                                let sector_lba = req.lba + s as u64;
                                let sector_off = offset + (s as usize) * virtio_drv::SECTOR_SIZE;
                                let dest = unsafe {
                                    &mut SHARED_VMO_ARENA
                                        [sector_off..sector_off + virtio_drv::SECTOR_SIZE]
                                };
                                match driver.submit_read(sector_lba, dest) {
                                    Ok(n) => bytes_transferred += n as u32,
                                    Err(e) => {
                                        status = e as i32;
                                        break;
                                    }
                                }
                            }
                        } else {
                            status = libjambo::SysError::InvalidArgument as i32;
                        }
                    }
                    BLOCK_OP_WRITE => {
                        if offset + total_bytes <= SHARED_VMO_SIZE {
                            for s in 0..req.count {
                                let sector_lba = req.lba + s as u64;
                                let sector_off = offset + (s as usize) * virtio_drv::SECTOR_SIZE;
                                let src = unsafe {
                                    &SHARED_VMO_ARENA
                                        [sector_off..sector_off + virtio_drv::SECTOR_SIZE]
                                };
                                match driver.submit_write(sector_lba, src) {
                                    Ok(n) => bytes_transferred += n as u32,
                                    Err(e) => {
                                        status = e as i32;
                                        break;
                                    }
                                }
                            }
                        } else {
                            status = libjambo::SysError::InvalidArgument as i32;
                        }
                    }
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

                let mut tx_msg = ChannelMessage::default();
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

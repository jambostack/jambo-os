#![no_std]

pub use jambo_abi::*;

pub mod coreutils;
pub mod dynlink;
pub mod gpt;
pub mod net;
pub mod pci;
pub mod posix;
pub mod vfs;

/// Wrapper d'appel système brut pour x86-64
///
/// # Safety
///
/// Cette fonction effectue un appel système direct via l'instruction assembleur `SYSCALL`.
/// L'appelant doit s'assurer que les arguments passés sont valides et correspondent aux
/// préconditions définies dans l'ABI JamboOS.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn syscall6(
    num: SyscallNumber,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> (i64, u64) {
    let ret: i64;
    let ret2: u64;
    // SAFETY: Appel système direct en Ring 3 via l'instruction SYSCALL.
    core::arch::asm!(
        "syscall",
        inlateout("rax") num as u64 => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        inlateout("rdx") arg3 => ret2,
        in("r10") arg4,
        in("r8") arg5,
        in("r9") arg6,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags)
    );
    (ret, ret2)
}

/// Wrapper d'appel système brut pour ARM64 (AArch64)
///
/// # Safety
///
/// Cette fonction effectue un appel système direct via l'instruction `SVC #0` (EL0 -> EL1).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub unsafe fn syscall6(
    num: SyscallNumber,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> (i64, u64) {
    let ret: i64;
    let ret2: u64;
    // SAFETY: Appel système direct en EL0 via l'instruction SVC #0.
    core::arch::asm!(
        "svc #0",
        in("x8") num as u64,
        inlateout("x0") arg1 => ret,
        inlateout("x1") arg2 => ret2,
        in("x2") arg3,
        in("x3") arg4,
        in("x4") arg5,
        in("x5") arg6,
        options(nostack, preserves_flags)
    );
    (ret, ret2)
}

/// Lit des octets depuis la console interactive (Syscall 25)
pub fn console_read(buf: &mut [u8]) -> Result<usize, SysError> {
    let (ret, _) = unsafe {
        syscall6(
            SyscallNumber::ConsoleRead,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    if ret < 0 {
        Err(SysError::BadAddress)
    } else {
        Ok(ret as usize)
    }
}

/// Écrit des octets vers la console interactive (Syscall 26)
pub fn console_write(buf: &[u8]) -> Result<usize, SysError> {
    let (ret, _) = unsafe {
        syscall6(
            SyscallNumber::ConsoleWrite,
            buf.as_ptr() as u64,
            buf.len() as u64,
            0,
            0,
            0,
            0,
        )
    };
    if ret < 0 {
        Err(SysError::BadAddress)
    } else {
        Ok(ret as usize)
    }
}

/// Interroge les métriques du système d'exploitation (Syscall 27)
pub fn sys_info() -> Result<SystemInfo, SysError> {
    let mut info = SystemInfo::default();
    let (ret, _) = unsafe {
        syscall6(
            SyscallNumber::SysInfo,
            &mut info as *mut SystemInfo as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        Err(SysError::InvalidArgument)
    } else {
        Ok(info)
    }
}

/// Interroge une horloge système (Syscall 24 ClockGettime)
pub fn clock_gettime(clock_id: u32) -> Result<Timespec, SysError> {
    let mut ts = Timespec::default();
    // SAFETY: Appel système direct ClockGettime vers le noyau avec un pointeur valide alloué sur la pile
    let (ret, _) = unsafe {
        syscall6(
            SyscallNumber::ClockGettime,
            clock_id as u64,
            &mut ts as *mut Timespec as u64,
            0,
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        Err(SysError::InvalidArgument)
    } else {
        Ok(ts)
    }
}

/// Affiche une chaîne de caractères sur la console standard
pub fn print(s: &str) {
    let _ = console_write(s.as_bytes());
}

/// Affiche une chaîne de caractères suivie d'un retour à la ligne
pub fn println(s: &str) {
    print(s);
    print("\n");
}

/// Cède le temps processeur au planificateur (Syscall 12)
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

/// Enregistre un endpoint IPC standard (Syscall 13 ChannelCreate ou handle fixé)
pub fn syscall_ipc_register_endpoint(endpoint: u64) -> Handle {
    let mut srv_h: u64 = 0;
    let mut cli_h: u64 = 0;
    unsafe {
        syscall6(
            SyscallNumber::ChannelCreate,
            0,
            &mut srv_h as *mut u64 as u64,
            &mut cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    Handle(if srv_h != 0 { srv_h } else { endpoint })
}

/// Lit un registre 32 bits de l'espace de configuration PCI via le broker noyau (Syscall 29 DeviceIo)
pub fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let bdf = ((bus as u64) << 16) | ((dev as u64 & 0x1F) << 11) | ((func as u64 & 0x07) << 8);
    let mut val: u32 = 0xFFFF_FFFF;
    let (ret, _) = unsafe {
        syscall6(
            SyscallNumber::DeviceIo,
            device_io_op::PCI_READ32 as u64,
            bdf,
            offset as u64,
            &mut val as *mut u32 as u64,
            0,
            0,
        )
    };
    if ret == 0 {
        val
    } else {
        0xFFFF_FFFF
    }
}

/// Lit un registre 16 bits de l'espace de configuration PCI via le broker noyau
pub fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let dword = pci_read32(bus, dev, func, offset & 0xFC);
    ((dword >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Lit un registre 8 bits de l'espace de configuration PCI via le broker noyau
pub fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let dword = pci_read32(bus, dev, func, offset & 0xFC);
    ((dword >> ((offset & 3) * 8)) & 0xFF) as u8
}

/// Écrit un registre 32 bits de l'espace de configuration PCI via le broker noyau
pub fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) -> Result<(), SysError> {
    let bdf = ((bus as u64) << 16) | ((dev as u64 & 0x1F) << 11) | ((func as u64 & 0x07) << 8);
    let (ret, _) = unsafe {
        syscall6(
            SyscallNumber::DeviceIo,
            device_io_op::PCI_WRITE32 as u64,
            bdf,
            offset as u64,
            val as u64,
            0,
            0,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(SysError::PermissionDenied)
    }
}

/// Active la capacité MSI-X pour le périphérique spécifié via le broker DeviceIo
pub fn pci_msix_enable(bus: u8, dev: u8, func: u8, cap_offset: u8) -> Result<(), SysError> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (bus, dev, func, cap_offset);
        Ok(())
    }
    #[cfg(target_os = "none")]
    {
        let bdf = ((bus as u64) << 16) | ((dev as u64 & 0x1F) << 11) | ((func as u64 & 0x07) << 8);
        let (ret, _) = unsafe {
            syscall6(
                SyscallNumber::DeviceIo,
                device_io_op::MSIX_ENABLE as u64,
                bdf,
                cap_offset as u64,
                0,
                0,
                0,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(SysError::PermissionDenied)
        }
    }
}

/// Désactive la capacité MSI-X pour le périphérique spécifié via le broker DeviceIo
pub fn pci_msix_disable(bus: u8, dev: u8, func: u8, cap_offset: u8) -> Result<(), SysError> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (bus, dev, func, cap_offset);
        Ok(())
    }
    #[cfg(target_os = "none")]
    {
        let bdf = ((bus as u64) << 16) | ((dev as u64 & 0x1F) << 11) | ((func as u64 & 0x07) << 8);
        let (ret, _) = unsafe {
            syscall6(
                SyscallNumber::DeviceIo,
                device_io_op::MSIX_DISABLE as u64,
                bdf,
                cap_offset as u64,
                0,
                0,
                0,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(SysError::PermissionDenied)
        }
    }
}

/// Configure une entrée de table MSI-X pour le périphérique spécifié via le broker DeviceIo
pub fn pci_msix_set_entry(
    bus: u8,
    dev: u8,
    func: u8,
    entry_index: u8,
    entry: &jambo_abi::MsixEntryDescriptor,
) -> Result<(), SysError> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (bus, dev, func, entry_index, entry);
        Ok(())
    }
    #[cfg(target_os = "none")]
    {
        let bdf = ((bus as u64) << 16) | ((dev as u64 & 0x1F) << 11) | ((func as u64 & 0x07) << 8);
        let (ret, _) = unsafe {
            syscall6(
                SyscallNumber::DeviceIo,
                device_io_op::MSIX_SET_ENTRY as u64,
                bdf,
                entry_index as u64,
                entry as *const _ as u64,
                0,
                0,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(SysError::PermissionDenied)
        }
    }
}

/// Lit une entrée de table MSI-X pour le périphérique spécifié via le broker DeviceIo
pub fn pci_msix_get_entry(
    bus: u8,
    dev: u8,
    func: u8,
    entry_index: u8,
) -> Result<jambo_abi::MsixEntryDescriptor, SysError> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (bus, dev, func, entry_index);
        Ok(jambo_abi::MsixEntryDescriptor::default())
    }
    #[cfg(target_os = "none")]
    {
        let bdf = ((bus as u64) << 16) | ((dev as u64 & 0x1F) << 11) | ((func as u64 & 0x07) << 8);
        let mut entry = jambo_abi::MsixEntryDescriptor::default();
        let (ret, _) = unsafe {
            syscall6(
                SyscallNumber::DeviceIo,
                device_io_op::MSIX_GET_ENTRY as u64,
                bdf,
                entry_index as u64,
                &mut entry as *mut _ as u64,
                0,
                0,
            )
        };
        if ret == 0 {
            Ok(entry)
        } else {
            Err(SysError::PermissionDenied)
        }
    }
}

/// Délègue une interruption MSI-X vers un port de notification en espace utilisateur (Syscall 29 DeviceIo)
pub fn pci_msix_delegate_irq(
    bus: u8,
    dev: u8,
    func: u8,
    port_handle: Handle,
    cookie: u64,
    target_vector: u32,
) -> Result<Handle, SysError> {
    #[cfg(not(target_os = "none"))]
    {
        let _ = (bus, dev, func, port_handle, cookie);
        if (32..=255).contains(&target_vector) {
            Ok(Handle(target_vector as u64))
        } else {
            Err(SysError::InvalidArgument)
        }
    }
    #[cfg(target_os = "none")]
    {
        let bdf = ((bus as u64) << 16) | ((dev as u64 & 0x1F) << 11) | ((func as u64 & 0x07) << 8);
        let req = jambo_abi::MsixDelegateRequest {
            port_handle,
            cookie,
            target_vector,
        };
        let mut out_handle_val: u64 = 0;
        let (ret, _) = unsafe {
            syscall6(
                SyscallNumber::DeviceIo,
                device_io_op::MSIX_DELEGATE_IRQ as u64,
                bdf,
                0,
                &req as *const _ as u64,
                &mut out_handle_val as *mut _ as u64,
                0,
            )
        };
        if ret == 0 {
            Ok(Handle(out_handle_val))
        } else {
            Err(SysError::PermissionDenied)
        }
    }
}

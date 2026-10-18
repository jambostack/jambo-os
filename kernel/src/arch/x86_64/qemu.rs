use super::io::outb;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

/// Ferme la machine virtuelle QEMU via le périphérique isa-debug-exit (port 0xF4)
pub fn exit_qemu(exit_code: QemuExitCode) -> ! {
    outb(0xF4, exit_code as u8);
    // Boucle infinie si QEMU ne termine pas immédiatement
    loop {
        core::hint::spin_loop();
    }
}

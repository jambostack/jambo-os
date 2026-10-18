//! Émulation et sortie contrôlée QEMU pour AArch64 via PSCI / Semihosting

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0,
    Failed = 1,
}

/// Déclenche la sortie de l'émulateur QEMU via l'appel PSCI SYSTEM_OFF (ou boucle de secours)
pub fn exit_qemu(_exit_code: QemuExitCode) -> ! {
    // Appel PSCI SYSTEM_OFF (Function ID: 0x84000008)
    unsafe {
        core::arch::asm!(
            "hvc #0",
            in("x0") 0x8400_0008u64,
            options(nomem, nostack)
        );
    }
    loop {
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
        }
    }
}

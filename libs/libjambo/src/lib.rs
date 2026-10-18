#![no_std]

pub use jambo_abi::*;

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

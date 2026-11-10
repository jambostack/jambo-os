//! Utilitaire Coreutils Ring 3 : `seq` (POSIX/GNU print a sequence of numbers)
#![no_std]
#![no_main]

use jambo_coreutils::{exit_process, parse_stack_args};
use libjambo::coreutils::run_seq;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: Appel direct de terminaison en cas de panique en espace utilisateur Ring 3
    unsafe {
        exit_process(127);
    }
}

/// Point d'entrée exécutable autonome System V AMD64 / AArch64
///
/// # Safety
/// Cette fonction extrait directement les arguments sur la pile utilisateur et termine via un appel système.
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let sp: *const usize;
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!("mov {}, rsp", out(reg) sp);
    #[cfg(target_arch = "aarch64")]
    core::arch::asm!("mov {}, sp", out(reg) sp);

    let mut storage = [""; 16];
    let (_prog, args) = parse_stack_args(sp, &mut storage);
    let code = run_seq(args, 1, 2);
    exit_process(code);
}

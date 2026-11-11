//! Utilitaire Coreutils Ring 3 : `pathchk` (POSIX pathchk - vérification de validité et portabilité des chemins)
#![no_std]
#![no_main]

use jambo_coreutils::{exit_process, parse_stack_args};
use libjambo::coreutils::run_pathchk;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: Appel système brut de secours en cas de panique
    unsafe {
        exit_process(1);
    }
}

/// Point d'entrée exécutable autonome System V
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
    let code = run_pathchk(args, 1, 2);
    exit_process(code);
}

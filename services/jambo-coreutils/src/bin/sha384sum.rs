//! Utilitaire Coreutils Ring 3 : `sha384sum` (Calcul et vérification FIPS 180-4 SHA-384)
#![no_std]
#![no_main]

use jambo_coreutils::{exit_process, parse_stack_args};
use libjambo::coreutils::run_sha384sum;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: Appel système brut de secours en cas de panique
    unsafe {
        exit_process(127);
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
    let code = run_sha384sum(args, 0, 1, 2);
    exit_process(code);
}

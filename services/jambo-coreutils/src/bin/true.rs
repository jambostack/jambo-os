//! Utilitaire Coreutils Ring 3 : `true`
#![no_std]
#![no_main]

use jambo_coreutils::exit_process;
use libjambo::coreutils::run_true;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        exit_process(127);
    }
}

/// Point d'entrée exécutable autonome System V
///
/// # Safety
/// Cette fonction effectue un appel système de sortie propre.
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let code = run_true();
    exit_process(code);
}

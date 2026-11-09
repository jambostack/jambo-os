//! Point d'entrée du binaire Ring 3 `fuzz` (PID 40)
//! Exécute une campagne de fuzzing de robustesse et de résilience TCB

#![no_std]
#![no_main]

use jambo_fuzz::JamboFuzzDaemon;
use libjambo::{println, syscall6, SyscallNumber};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;35m====================================================\x1b[0m");
    println("\x1b[1;32m  JamboOS TCB Fuzzing & Silicon Resilience Engine   \x1b[0m");
    println("\x1b[1;35m====================================================\x1b[0m");

    let mut daemon = JamboFuzzDaemon::new();
    let report = daemon.run_campaign(1000);

    println("[FUZZ] Campagne de 1 000 mutations executee avec succes !");
    if report.zero_kernel_panics {
        println(
            "\x1b[1;32m[PASS] Zero Kernel Panic : frontieres TCB et CSpace 100% etanches.\x1b[0m",
        );
    } else {
        println("\x1b[1;31m[FAIL] Violation detectee dans les frontieres TCB !\x1b[0m");
    }

    unsafe {
        syscall6(SyscallNumber::ThreadExit, 0, 0, 0, 0, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

#![no_std]
#![no_main]

use libjambo::SyscallNumber;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialiser le premier processus superviseur (PID 1)
    // 2. Découvrir et lancer les pilotes matériels en espace utilisateur (virtio-blk, pcie-bus-mgr)
    // 3. Monter le système de fichiers racine transactionnel JamboFS

    let mut out_h1: u64 = 0;
    let mut out_h2: u64 = 0;
    unsafe {
        libjambo::syscall6(
            SyscallNumber::ChannelCreate,
            0,
            &mut out_h1 as *mut u64 as u64,
            &mut out_h2 as *mut u64 as u64,
            0,
            0,
            0,
        );
    }

    // Boucle de supervision de la santé des services Ring 3
    loop {
        unsafe {
            libjambo::syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
        }
    }
}

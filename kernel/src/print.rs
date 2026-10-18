use crate::arch::SERIAL1;
use crate::drivers::FRAMEBUFFER;
use core::fmt::{self, Write};

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // 1. Écriture sur le port série COM1 (indispensable pour les logs CI & QEMU)
    let _ = SERIAL1.lock().write_fmt(args);

    // 2. Écriture simultanée sur le Framebuffer GOP si initialisé
    if let Some(ref mut fb) = *FRAMEBUFFER.lock() {
        let _ = fb.write_fmt(args);
    }
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::print::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ($crate::kprint!("{}\n", format_args!($($arg)*)));
}

//! Pilote UART PL011 standard pour machine ARM64 QEMU virt (Base 0x09000000)

use core::fmt;
use spin::Mutex;

pub const PL011_UART_BASE: u64 = 0x0900_0000;

pub struct Pl011Uart {
    base: u64,
}

impl Pl011Uart {
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    pub fn write_byte(&mut self, byte: u8) {
        unsafe {
            let dr = self.base as *mut u32;
            let fr = (self.base + 0x18) as *const u32;
            // Attendre tant que la file d'émission est pleine (TXFF bit 5)
            while (core::ptr::read_volatile(fr) & (1 << 5)) != 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(dr, byte as u32);
        }
    }
}

impl fmt::Write for Pl011Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

pub static SERIAL1: Mutex<Pl011Uart> = Mutex::new(Pl011Uart::new(PL011_UART_BASE));

pub fn init_serial() {
    // Le port UART PL011 est pré-initialisé par QEMU virt firmware
}

use super::io::{inb, outb};
use core::fmt;
use spin::Mutex;

const COM1: u16 = 0x3F8;

pub struct SerialPort {
    port: u16,
}

impl SerialPort {
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    /// Initialise le port série 16550 à 115200 bauds (8N1)
    pub fn init(&mut self) {
        let p = self.port;
        outb(p + 1, 0x00); // Désactive toutes les interruptions
        outb(p + 3, 0x80); // Active le DLAB (Divisor Latch Access Bit)
        outb(p + 0, 0x01); // Diviseur de fréquence = 1 (115200 bauds, octet bas)
        outb(p + 1, 0x00); // Octet haut du diviseur
        outb(p + 3, 0x03); // 8 bits, pas de parité, un stop bit (8N1)
        outb(p + 2, 0xC7); // Active la FIFO, vide les files TX/RX, seuil 14 octets
        outb(p + 4, 0x0B); // Active IRQs, RTS/DSR activés
    }

    /// Indique si la file d'émission est prête à recevoir un octet
    #[inline]
    fn is_transmit_empty(&self) -> bool {
        (inb(self.port + 5) & 0x20) != 0
    }

    /// Écrit un octet brut sur le port série
    pub fn write_byte(&mut self, byte: u8) {
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }
        outb(self.port, byte);
    }

    /// Écrit une chaîne de caractères
    pub fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

pub static SERIAL1: Mutex<SerialPort> = Mutex::new(SerialPort::new(COM1));

pub fn init_serial() {
    SERIAL1.lock().init();
}

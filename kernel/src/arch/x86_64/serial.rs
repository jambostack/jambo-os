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
        outb(p + 4, 0x0B); // Active IRQs (OUT2), RTS/DTR activés
        outb(p + 1, 0x01); // Active l'interruption matérielle sur réception (ERBFI)
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

/// File d'attente circulaire à taille fixe pour réception sans allocation dynamique
pub struct RingBuffer<const N: usize> {
    buffer: [u8; N],
    head: usize,
    tail: usize,
    count: usize,
}

impl<const N: usize> RingBuffer<N> {
    pub const fn new() -> Self {
        Self {
            buffer: [0; N],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, byte: u8) -> bool {
        if self.count >= N {
            return false;
        }
        self.buffer[self.tail] = byte;
        self.tail = (self.tail + 1) % N;
        self.count += 1;
        true
    }

    pub fn pop(&mut self) -> Option<u8> {
        if self.count == 0 {
            return None;
        }
        let byte = self.buffer[self.head];
        self.head = (self.head + 1) % N;
        self.count -= 1;
        Some(byte)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

pub static SERIAL_RX_QUEUE: Mutex<RingBuffer<512>> = Mutex::new(RingBuffer::new());

/// Traite l'interruption série COM1 (vidage de la FIFO matérielle vers le ring buffer)
pub fn on_serial_irq() {
    let port = COM1;
    while (inb(port + 5) & 0x01) != 0 {
        let byte = inb(port);
        let mut queue = SERIAL_RX_QUEUE.lock();
        queue.push(byte);
    }
}

/// Tente de consommer un caractère reçu sans bloquer
pub fn try_get_char() -> Option<u8> {
    SERIAL_RX_QUEUE.lock().pop()
}

/// Lit un caractère en attente bloquante
pub fn get_char() -> u8 {
    loop {
        if let Some(c) = try_get_char() {
            return c;
        }
        core::hint::spin_loop();
    }
}

/// Injecte un octet dans la file d'entrée
pub fn inject_input_byte(byte: u8) {
    SERIAL_RX_QUEUE.lock().push(byte);
}

/// Injecte une chaîne de caractères dans la file d'entrée
pub fn inject_input_str(s: &str) {
    let mut queue = SERIAL_RX_QUEUE.lock();
    for b in s.bytes() {
        queue.push(b);
    }
}


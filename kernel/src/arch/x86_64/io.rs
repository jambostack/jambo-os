use core::arch::asm;

/// Écriture d'un octet (8 bits) sur un port d'E/S x86
#[inline]
pub fn outb(port: u16, val: u8) {
    // SAFETY: L'écriture sur un port d'E/S matériel x86 est une opération
    // d'architecture valide en Ring 0. Le caller doit s'assurer que le port est valide.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
    }
}

/// Lecture d'un octet (8 bits) depuis un port d'E/S x86
#[inline]
pub fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: La lecture depuis un port d'E/S matériel x86 en Ring 0 est sûre
    // pour les registres d'état des périphériques standards (UART, etc.).
    unsafe {
        asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Écriture d'un mot (16 bits) sur un port d'E/S x86
#[inline]
pub fn outw(port: u16, val: u16) {
    // SAFETY: Opération d'architecture privilégiée Ring 0 sur bus d'E/S.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
    }
}

/// Lecture d'un mot (16 bits) depuis un port d'E/S x86
#[inline]
pub fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: Opération de lecture matérielle autorisée en mode superviseur.
    unsafe {
        asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Écriture d'un double-mot (32 bits) sur un port d'E/S x86
#[inline]
pub fn outl(port: u16, val: u32) {
    // SAFETY: Opération d'architecture privilégiée Ring 0 sur bus d'E/S.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags));
    }
}

/// Lecture d'un double-mot (32 bits) depuis un port d'E/S x86
#[inline]
pub fn inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: Opération de lecture matérielle autorisée en mode superviseur.
    unsafe {
        asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Pause d'attente I/O (port inutilisé 0x80)
#[inline]
pub fn io_wait() {
    outb(0x80, 0);
}

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Lit un registre 32 bits de configuration PCI en Ring 0 (Broker matériel)
#[inline]
pub fn pci_read32_raw(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let conf_addr = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32 & 0x1F) << 11)
        | ((func as u32 & 0x07) << 8)
        | ((offset as u32) & 0xFC);
    outl(PCI_CONFIG_ADDRESS, conf_addr);
    inl(PCI_CONFIG_DATA)
}

/// Écrit un registre 32 bits de configuration PCI en Ring 0 (Broker matériel)
#[inline]
pub fn pci_write32_raw(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let conf_addr = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32 & 0x1F) << 11)
        | ((func as u32 & 0x07) << 8)
        | ((offset as u32) & 0xFC);
    outl(PCI_CONFIG_ADDRESS, conf_addr);
    outl(PCI_CONFIG_DATA, val);
}

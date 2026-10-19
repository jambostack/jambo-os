//! Pilote du contrôleur I/O APIC (Intel 82093AA / ICH / Q35)
//!
//! Assure le routage des interruptions matérielles (IRQs ISA/PCI)
//! vers les APIC locaux des cœurs CPU.

use spin::Mutex;

pub const IOAPIC_BASE_PADDR: usize = 0xFEC0_0000;

// Registres d'index et de fenêtre de données MMIO
const IOREGSEL_OFFSET: usize = 0x00;
const IOWIN_OFFSET: usize = 0x10;

// Registres internes de l'I/O APIC
const IOAPIC_REG_REDTBL_BASE: u8 = 0x10;

pub struct IoApic {
    base_vaddr: usize,
}

impl IoApic {
    pub const unsafe fn new(base_vaddr: usize) -> Self {
        Self { base_vaddr }
    }

    #[inline]
    unsafe fn write_reg(&self, reg: u8, val: u32) {
        let sel_ptr = (self.base_vaddr + IOREGSEL_OFFSET) as *mut u32;
        let win_ptr = (self.base_vaddr + IOWIN_OFFSET) as *mut u32;
        core::ptr::write_volatile(sel_ptr, reg as u32);
        core::ptr::write_volatile(win_ptr, val);
    }

    #[inline]
    unsafe fn read_reg(&self, reg: u8) -> u32 {
        let sel_ptr = (self.base_vaddr + IOREGSEL_OFFSET) as *mut u32;
        let win_ptr = (self.base_vaddr + IOWIN_OFFSET) as *mut u32;
        core::ptr::write_volatile(sel_ptr, reg as u32);
        core::ptr::read_volatile(win_ptr)
    }

    /// Redirige une ligne d'interruption (IRQ) vers un vecteur IDT cible
    pub fn route_irq(&self, irq: u8, vector: u8, dest_lapic_id: u8) {
        let low_reg = IOAPIC_REG_REDTBL_BASE + 2 * irq;
        let high_reg = low_reg + 1;

        // Entrée basse : Vector (bits 0..7), Mode Fixed (000), Dest Physical (0),
        // Active High (0), Edge-triggered (0 pour ISA), Démasqué (bit 16 = 0).
        let low_val = vector as u32;
        let high_val = (dest_lapic_id as u32) << 24;

        unsafe {
            self.write_reg(low_reg, low_val);
            self.write_reg(high_reg, high_val);
        }
    }

    /// Masque une ligne d'interruption
    pub fn mask_irq(&self, irq: u8) {
        let low_reg = IOAPIC_REG_REDTBL_BASE + 2 * irq;
        unsafe {
            let current = self.read_reg(low_reg);
            self.write_reg(low_reg, current | (1 << 16));
        }
    }
}

pub static IOAPIC: Mutex<Option<IoApic>> = Mutex::new(None);

/// Initialise l'I/O APIC et mappe sa page MMIO dans le PML4 superviseur
pub fn init_ioapic() {
    unsafe {
        let paddr = IOAPIC_BASE_PADDR;
        let vaddr = crate::mm::phys_to_virt(paddr);

        // Mappage de la page MMIO dans le PML4 superviseur actif
        let current_cr3 = crate::mm::read_cr3();
        let pml4 = &mut *(crate::mm::phys_to_virt(current_cr3) as *mut crate::mm::PageTable);
        let flags = 0x01 | 0x02 | (1 << 63); // PRESENT | WRITABLE | NO_EXECUTE
        let _ = crate::mm::map_page(pml4, vaddr, paddr, flags);

        let ioapic = IoApic::new(vaddr);
        *IOAPIC.lock() = Some(ioapic);
    }
}

/// Route une interruption matérielle via l'I/O APIC vers un cœur logique
pub fn ioapic_route_irq(irq: u8, vector: u8, dest_lapic_id: u8) {
    if let Some(ref ioapic) = *IOAPIC.lock() {
        ioapic.route_irq(irq, vector, dest_lapic_id);
    }
}

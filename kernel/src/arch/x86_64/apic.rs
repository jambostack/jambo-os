use super::io::outb;
use core::arch::asm;
use spin::Mutex;

pub const IA32_APIC_BASE_MSR: u32 = 0x1B;
pub const APIC_BASE_MSR_ENABLE: u64 = 1 << 11;
pub const APIC_BASE_MSR_X2APIC: u64 = 1 << 10;

// Registres MMIO Local APIC
const APIC_REG_ID: usize = 0x020;
const APIC_REG_TPR: usize = 0x080;
const APIC_REG_EOI: usize = 0x0B0;
const APIC_REG_SVR: usize = 0x0F0;
#[allow(dead_code)]
const APIC_REG_LVT_TIMER: usize = 0x320;
#[allow(dead_code)]
const APIC_REG_TIMER_INIT_CNT: usize = 0x380;
#[allow(dead_code)]
const APIC_REG_TIMER_CURR_CNT: usize = 0x390;
#[allow(dead_code)]
const APIC_REG_TIMER_DIV: usize = 0x3E0;

/// Masque complètement le contrôleur PIC 8259 hérité
pub fn disable_pic() {
    outb(0x21, 0xFF); // Masque tous les IRQs sur PIC1
    outb(0xA1, 0xFF); // Masque tous les IRQs sur PIC2
}

/// Vérifie le support matériel x2APIC via CPUID (Feuille 1, ECX bit 21)
pub fn has_x2apic() -> bool {
    let ecx: u32;
    // SAFETY: Instruction CPUID sûre sur processeur x86
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("eax") 1u32 => _,
            lateout("ecx") ecx,
            lateout("edx") _,
            options(nomem, nostack, preserves_flags)
        );
    }
    (ecx & (1 << 21)) != 0
}

/// Pilote pour le mode moderne x2APIC (accès ultra-rapide par MSRs 0x800..0x83F)
pub struct X2Apic;

impl X2Apic {
    pub fn init() {
        // SAFETY: Configuration matérielle privilégiée x2APIC par MSRs
        unsafe {
            let base = rdmsr(IA32_APIC_BASE_MSR);
            wrmsr(
                IA32_APIC_BASE_MSR,
                base | APIC_BASE_MSR_ENABLE | APIC_BASE_MSR_X2APIC,
            );
            wrmsr(0x808, 0); // TPR = 0 (accepter toutes les priorités)
            wrmsr(0x80F, 0x100 | 0xFF); // SVR : APIC activé (bit 8) + vecteur Spurious 0xFF
        }
    }

    #[inline]
    pub fn id() -> u32 {
        unsafe { rdmsr(0x802) as u32 }
    }

    #[inline]
    pub fn eoi() {
        unsafe {
            wrmsr(0x80B, 0);
        }
    }
}

/// Lit un registre MSR 64 bits
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Écrit dans un registre MSR 64 bits
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}

pub struct LocalApic {
    base_vaddr: u64,
}

impl LocalApic {
    pub const unsafe fn new(base_vaddr: u64) -> Self {
        Self { base_vaddr }
    }

    #[inline]
    unsafe fn read_reg(&self, offset: usize) -> u32 {
        let ptr = (self.base_vaddr + offset as u64) as *const u32;
        core::ptr::read_volatile(ptr)
    }

    #[inline]
    unsafe fn write_reg(&self, offset: usize, value: u32) {
        let ptr = (self.base_vaddr + offset as u64) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }

    /// Initialise et active le Local APIC
    pub fn init(&mut self) {
        // SAFETY: Configuration matérielle privilégiée de l'APIC en Ring 0.
        unsafe {
            // 1. Activer l'APIC dans le MSR IA32_APIC_BASE si nécessaire
            let apic_base = rdmsr(IA32_APIC_BASE_MSR);
            if (apic_base & APIC_BASE_MSR_ENABLE) == 0 {
                wrmsr(IA32_APIC_BASE_MSR, apic_base | APIC_BASE_MSR_ENABLE);
            }

            // 2. Accepter toutes les priorités (TPR = 0)
            self.write_reg(APIC_REG_TPR, 0);

            // 3. Spurious Interrupt Vector Register : Activer le logiciel APIC (bit 8) + vecteur 0xFF
            self.write_reg(APIC_REG_SVR, 0x100 | 0xFF);
        }
    }

    /// Signale la fin de traitement d'interruption (EOI)
    #[inline]
    pub fn eoi(&self) {
        unsafe {
            self.write_reg(APIC_REG_EOI, 0);
        }
    }

    /// Obtient l'identifiant matériel de l'APIC local
    pub fn id(&self) -> u32 {
        unsafe { self.read_reg(APIC_REG_ID) >> 24 }
    }

    /// Démarre le Timer APIC en mode périodique sur le vecteur spécifié
    pub fn start_timer(&mut self, vector: u8, initial_count: u32, divide_by_16: bool) {
        unsafe {
            let div_val = if divide_by_16 { 0x3 } else { 0xB };
            self.write_reg(APIC_REG_TIMER_DIV, div_val);
            let lvt_val = (1 << 17) | (vector as u32);
            self.write_reg(APIC_REG_LVT_TIMER, lvt_val);
            self.write_reg(APIC_REG_TIMER_INIT_CNT, initial_count);
        }
    }

    /// Arrête le Timer APIC
    pub fn stop_timer(&mut self) {
        unsafe {
            self.write_reg(APIC_REG_LVT_TIMER, 1 << 16);
            self.write_reg(APIC_REG_TIMER_INIT_CNT, 0);
        }
    }
}

pub static LOCAL_APIC: Mutex<Option<LocalApic>> = Mutex::new(None);

/// Initialise l'APIC local (x2APIC MSR ou xAPIC MMIO selon support matériel)
pub fn init_apic() {
    if has_x2apic() {
        X2Apic::init();
    } else {
        unsafe {
            let base = rdmsr(IA32_APIC_BASE_MSR);
            let paddr = (base & 0xFFFF_F000) as usize;
            let vaddr = crate::mm::phys_to_virt(paddr) as u64;

            // Mapper la page physique MMIO APIC dans le PML4 superviseur actif
            let current_cr3 = crate::mm::read_cr3();
            let pml4 = &mut *(crate::mm::phys_to_virt(current_cr3) as *mut crate::mm::PageTable);
            let flags = 0x01 | 0x02 | (1 << 63); // PRESENT | WRITABLE | NO_EXECUTE
            let _ = crate::mm::map_page(pml4, vaddr as usize, paddr, flags);

            let mut lapic = LocalApic::new(vaddr);
            lapic.init();
            *LOCAL_APIC.lock() = Some(lapic);
        }
    }
}

/// Démarre le Timer APIC périodique sur le vecteur spécifié
pub fn apic_start_timer(vector: u8, initial_count: u32) {
    if has_x2apic() {
        unsafe {
            wrmsr(0x83E, 0x3); // Divide by 16
            wrmsr(0x832, (1 << 17) | (vector as u64));
            wrmsr(0x838, initial_count as u64);
        }
    } else if let Some(ref mut lapic) = *LOCAL_APIC.lock() {
        lapic.start_timer(vector, initial_count, true);
    }
}

/// Arrête le Timer APIC
pub fn apic_stop_timer() {
    if has_x2apic() {
        unsafe {
            wrmsr(0x832, 1 << 16);
            wrmsr(0x838, 0);
        }
    } else if let Some(ref mut lapic) = *LOCAL_APIC.lock() {
        lapic.stop_timer();
    }
}

/// Envoie le signal EOI au contrôleur APIC
#[inline]
pub fn apic_eoi() {
    if has_x2apic() {
        X2Apic::eoi();
    } else if let Some(ref lapic) = *LOCAL_APIC.lock() {
        lapic.eoi();
    }
}


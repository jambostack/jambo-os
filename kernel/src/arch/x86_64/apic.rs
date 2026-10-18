use super::io::outb;
use core::arch::asm;

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
}

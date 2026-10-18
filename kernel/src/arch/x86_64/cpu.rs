use super::apic::wrmsr;
use core::arch::asm;

pub const IA32_GS_BASE_MSR: u32 = 0xC0000101;
pub const IA32_KERNEL_GS_BASE_MSR: u32 = 0xC0000102;

pub const MAX_CPUS: usize = 64;

#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct PerCpuData {
    pub self_ptr: u64,         // Offset 0 : Pointeur d'auto-référence (pour gs:[0])
    pub cpu_id: u32,           // Offset 8
    pub lapic_id: u32,         // Offset 12
    pub kernel_stack_top: u64, // Offset 16 : Pile superviseur active (pour gs:[16])
    pub user_rsp_scratch: u64, // Offset 24 : Sauvegarde temporaire RSP utilisateur (pour gs:[24])
    pub current_thread: u64,   // Offset 32
    pub is_bsp: bool,          // Offset 40
}

static mut PER_CPU_ARRAY: [PerCpuData; MAX_CPUS] = {
    const EMPTY: PerCpuData = PerCpuData {
        self_ptr: 0,
        cpu_id: 0,
        lapic_id: 0,
        kernel_stack_top: 0,
        user_rsp_scratch: 0,
        current_thread: 0,
        is_bsp: false,
    };
    [EMPTY; MAX_CPUS]
};

/// Initialise la structure PerCpuData pour le processeur courant et configure GS.base
pub fn init_per_cpu(cpu_id: u32, lapic_id: u32, is_bsp: bool) {
    if (cpu_id as usize) >= MAX_CPUS {
        return;
    }

    // SAFETY: Initialisation matérielle exclusive du processeur en cours d'activation.
    unsafe {
        let per_cpu_ptr = core::ptr::addr_of_mut!(PER_CPU_ARRAY[cpu_id as usize]);
        (*per_cpu_ptr).self_ptr = per_cpu_ptr as u64;
        (*per_cpu_ptr).cpu_id = cpu_id;
        (*per_cpu_ptr).lapic_id = lapic_id;
        (*per_cpu_ptr).kernel_stack_top = 0;
        (*per_cpu_ptr).user_rsp_scratch = 0;
        (*per_cpu_ptr).is_bsp = is_bsp;

        // Configurer IA32_GS_BASE pour pointer sur cette structure
        wrmsr(IA32_GS_BASE_MSR, per_cpu_ptr as u64);
        wrmsr(IA32_KERNEL_GS_BASE_MSR, per_cpu_ptr as u64);
    }
}

/// Obtient une référence sûre vers les données PerCpuData du cœur local via GS.base
#[inline]
pub fn current_cpu() -> &'static PerCpuData {
    let ptr: *const PerCpuData;
    // SAFETY: Lecture du registre de segment GS base configuré lors du démarrage du cœur.
    unsafe {
        asm!("mov {}, gs:[0]", out(reg) ptr, options(nostack, preserves_flags));
        &*ptr
    }
}

/// Met à jour le pointeur de pile noyau du CPU local dans PerCpuData
pub fn set_current_kernel_stack(stack_top: u64) {
    let cpu = current_cpu();
    let ptr = cpu as *const PerCpuData as *mut PerCpuData;
    unsafe {
        (*ptr).kernel_stack_top = stack_top;
    }
}

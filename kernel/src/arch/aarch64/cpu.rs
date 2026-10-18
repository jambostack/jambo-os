//! Gestion des données Per-CPU pour AArch64

pub const MAX_CPUS: usize = 16;

#[derive(Debug, Clone, Copy, Default)]
pub struct PerCpuData {
    pub cpu_id: u32,
    pub mpidr: u64,
    pub is_bsp: bool,
}

static mut PER_CPU: [PerCpuData; MAX_CPUS] = [PerCpuData {
    cpu_id: 0,
    mpidr: 0,
    is_bsp: false,
}; MAX_CPUS];

pub fn init_per_cpu(cpu_id: u32, mpidr: u64, is_bsp: bool) {
    if (cpu_id as usize) < MAX_CPUS {
        unsafe {
            PER_CPU[cpu_id as usize] = PerCpuData {
                cpu_id,
                mpidr,
                is_bsp,
            };
        }
    }
}

pub fn current_cpu() -> &'static PerCpuData {
    unsafe { &PER_CPU[0] }
}

pub fn set_current_kernel_stack(_stack_top: u64) {}

use super::apic::wrmsr;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

pub const IA32_GS_BASE_MSR: u32 = 0xC0000101;
pub const IA32_KERNEL_GS_BASE_MSR: u32 = 0xC0000102;

pub const MAX_CPUS: usize = 64;

/// État atomique du générateur pseudo-aléatoire SplitMix64 de secours (Audit S-02)
static ENTROPY_POOL: AtomicU64 = AtomicU64::new(0x853c49e6748fea9b);

/// Lit le compteur de cycles TSC (Time Stamp Counter)
#[inline]
pub fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: rdtsc est une instruction x86 non privilégiée de lecture du compteur de cycles.
    unsafe {
        asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
    }
    ((high as u64) << 32) | (low as u64)
}

/// Vérifie via CPUID feuille 1 si l'instruction matérielle RDRAND est supportée
#[inline]
pub fn has_rdrand() -> bool {
    let ecx: u32;
    // SAFETY: cpuid feuille 1 interroge les fonctionnalités du processeur.
    // rbx est sauvegardé et restauré pour respecter les contraintes de registres de LLVM.
    unsafe {
        asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("eax") _,
            out("ecx") ecx,
            out("edx") _,
            options(nomem, preserves_flags)
        );
    }
    (ecx & (1 << 30)) != 0
}

/// Tente de générer 64 bits d'entropie matérielle via RDRAND
#[inline]
pub fn try_rdrand() -> Option<u64> {
    let val: u64;
    let cf: u8;
    // SAFETY: Instruction rdrand exécutée sur processeur compatible ; vérifie le Carry Flag (CF=1).
    unsafe {
        asm!(
            "rdrand {0}",
            "setc {1}",
            out(reg) val,
            out(reg_byte) cf,
            options(nomem, nostack)
        );
    }
    if cf != 0 {
        Some(val)
    } else {
        None
    }
}

/// Algorithme d'avalanche pseudo-aléatoire SplitMix64
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Génère 64 bits d'entropie cryptographique ou pseudo-aléatoire (Audit S-02)
/// Combine le générateur matériel RDRAND (si disponible) et une source de jitter TSC
/// mélangée par un algorithme d'avalanche SplitMix64 sans blocage.
pub fn get_random_u64() -> u64 {
    let tsc = rdtsc();
    let prev = ENTROPY_POOL.fetch_add(tsc.wrapping_add(0x517cc1b727220a95), Ordering::Relaxed);
    let mut state = prev ^ tsc.rotate_left(17);
    let pseudo = splitmix64(&mut state);

    if has_rdrand() {
        if let Some(hw) = try_rdrand() {
            return hw ^ pseudo;
        }
    }
    pseudo
}

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
    // SAFETY: Mise à jour du sommet de pile noyau réservé au thread s'exécutant sur le cœur local.
    unsafe {
        (*ptr).kernel_stack_top = stack_top;
    }
}

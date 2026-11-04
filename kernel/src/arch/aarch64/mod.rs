//! Abstractions matérielles pour architecture AArch64 (ARM64)

pub mod cpu;
pub mod iommu;
pub mod qemu;
pub mod serial;

pub use cpu::{current_cpu, init_per_cpu, set_current_kernel_stack, PerCpuData, MAX_CPUS};
pub use iommu::{init_iommu, IommuDomain, PciBdf, IOMMU_MANAGER};
pub use qemu::{exit_qemu, QemuExitCode};
pub use serial::{init_serial, SERIAL1};

pub fn init_apic() {}
pub fn apic_start_timer(_vector: u8, _initial_count: u32) {}
pub fn apic_stop_timer() {}
pub fn apic_eoi() {}

pub fn init_ioapic() {}
pub fn ioapic_route_irq(_irq: u8, _vector: u8, _dest_lapic_id: u8) {}
pub fn try_get_char() -> Option<u8> {
    None
}
pub fn get_char() -> u8 {
    0
}
pub fn inject_input_byte(_b: u8) {}
pub fn inject_input_str(_s: &str) {}

#[inline]
pub fn pci_read32_raw(_bus: u8, _dev: u8, _func: u8, _offset: u8) -> u32 {
    0xFFFF_FFFF
}

#[inline]
pub fn pci_write32_raw(_bus: u8, _dev: u8, _func: u8, _offset: u8, _val: u32) {}

use core::sync::atomic::{AtomicU64, Ordering};

static ENTROPY_POOL: AtomicU64 = AtomicU64::new(0x853c49e6748fea9b);

#[inline]
pub fn cntvct_el0() -> u64 {
    let val: u64;
    // SAFETY: Lecture du compteur de cycles virtuel AArch64
    unsafe {
        core::arch::asm!("mrs {0}, cntvct_el0", out(reg) val, options(nomem, nostack));
    }
    val
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

pub fn get_random_u64() -> u64 {
    let cycles = cntvct_el0();
    let prev = ENTROPY_POOL.fetch_add(cycles.wrapping_add(0x517cc1b727220a95), Ordering::Relaxed);
    let mut state = prev ^ cycles.rotate_left(17);
    splitmix64(&mut state)
}

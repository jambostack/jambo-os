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

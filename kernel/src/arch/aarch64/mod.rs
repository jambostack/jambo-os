//! Abstractions matérielles pour architecture AArch64 (ARM64)

pub mod cpu;
pub mod iommu;
pub mod qemu;
pub mod serial;

pub use cpu::{current_cpu, init_per_cpu, PerCpuData, MAX_CPUS};
pub use iommu::{init_iommu, IommuDomain, PciBdf, IOMMU_MANAGER};
pub use qemu::{exit_qemu, QemuExitCode};
pub use serial::{init_serial, SERIAL1};

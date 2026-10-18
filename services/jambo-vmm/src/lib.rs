//! Moniteur de Micro-Machines Virtuelles et Isolation Matérielle Type-2 (jambo-vmm)
//!
//! Fournit un hyperviseur utilisateur (VMM) sans autorité ambiante pour exécuter
//! des micro-machines virtuelles légères isolées par virtualisation matérielle (VT-x / AMD-V / ARM EL2).
//! Chaque VM est régie par un jeton capabilaire `VmCap` contrôlant la création de vCPUs,
//! le mapping des tables EPT (Extended Page Tables) et le piégeage des I/O et MMIO.

#![no_std]

use libjambo::{Handle, SysError};

/// Droits capabilitaires pour le contrôle de virtualisation
pub mod vm_rights {
    pub const VM_CREATE: u32 = 0x01;
    pub const GUEST_RUN: u32 = 0x02;
    pub const MEMORY_MAP: u32 = 0x04;
    pub const IO_INTERCEPT: u32 = 0x08;
    pub const ALL: u32 = VM_CREATE | GUEST_RUN | MEMORY_MAP | IO_INTERCEPT;
}

/// Capacité d'administration et de gestion d'une micro-VM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmCap {
    pub handle: Handle,
    pub vm_id: u32,
    pub rights: u32,
}

impl VmCap {
    pub const fn new(handle: Handle, vm_id: u32, rights: u32) -> Self {
        Self {
            handle,
            vm_id,
            rights,
        }
    }

    pub fn can_create(&self) -> bool {
        (self.rights & vm_rights::VM_CREATE) != 0
    }

    pub fn can_run_guest(&self) -> bool {
        (self.rights & vm_rights::GUEST_RUN) != 0
    }

    pub fn can_map_memory(&self) -> bool {
        (self.rights & vm_rights::MEMORY_MAP) != 0
    }

    pub fn can_intercept_io(&self) -> bool {
        (self.rights & vm_rights::IO_INTERCEPT) != 0
    }
}

/// Permissions d'accès mémoire dans la table de pages étendue (EPT / Stage-2)
pub mod ept_perms {
    pub const READ: u8 = 0x01;
    pub const WRITE: u8 = 0x02;
    pub const EXECUTE: u8 = 0x04;
    pub const RW: u8 = READ | WRITE;
    pub const RWX: u8 = READ | WRITE | EXECUTE;
}

/// Entrée de mappage dans l'espace d'adressage physique invité (GPA -> HPA)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptMapping {
    pub gpa_start: u64,
    pub hpa_start: u64,
    pub size: usize,
    pub permissions: u8,
    pub active: bool,
}

impl Default for EptMapping {
    fn default() -> Self {
        Self {
            gpa_start: 0,
            hpa_start: 0,
            size: 0,
            permissions: 0,
            active: false,
        }
    }
}

/// Espace d'adressage virtuel à pagination imbriquée (EPT / NPT / Stage-2)
pub const MAX_EPT_MAPPINGS: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct EptAddressSpace {
    pub mappings: [EptMapping; MAX_EPT_MAPPINGS],
}

impl Default for EptAddressSpace {
    fn default() -> Self {
        Self {
            mappings: [EptMapping::default(); MAX_EPT_MAPPINGS],
        }
    }
}

impl EptAddressSpace {
    pub const fn new() -> Self {
        Self {
            mappings: [EptMapping {
                gpa_start: 0,
                hpa_start: 0,
                size: 0,
                permissions: 0,
                active: false,
            }; MAX_EPT_MAPPINGS],
        }
    }

    pub fn map_page(
        &mut self,
        gpa: u64,
        hpa: u64,
        size: usize,
        permissions: u8,
    ) -> Result<(), SysError> {
        if size == 0 {
            return Err(SysError::InvalidArgument);
        }

        // Vérifier chevauchement avec un mapping existant
        for mapping in &self.mappings {
            if mapping.active {
                let existing_end = mapping.gpa_start + mapping.size as u64;
                let new_end = gpa + size as u64;
                if gpa < existing_end && new_end > mapping.gpa_start {
                    return Err(SysError::ResourceBusy);
                }
            }
        }

        // Allouer un slot libre
        for slot in self.mappings.iter_mut() {
            if !slot.active {
                *slot = EptMapping {
                    gpa_start: gpa,
                    hpa_start: hpa,
                    size,
                    permissions,
                    active: true,
                };
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    pub fn unmap_page(&mut self, gpa: u64) -> Result<(), SysError> {
        for slot in self.mappings.iter_mut() {
            if slot.active && slot.gpa_start == gpa {
                slot.active = false;
                return Ok(());
            }
        }
        Err(SysError::InvalidArgument)
    }

    pub fn translate(&self, gpa: u64, required_perm: u8) -> Result<u64, VmExitReason> {
        for slot in &self.mappings {
            if slot.active {
                let end = slot.gpa_start + slot.size as u64;
                if gpa >= slot.gpa_start && gpa < end {
                    if (slot.permissions & required_perm) != required_perm {
                        return Err(VmExitReason::EptViolation {
                            gpa,
                            read: (required_perm & ept_perms::READ) != 0,
                            write: (required_perm & ept_perms::WRITE) != 0,
                            exec: (required_perm & ept_perms::EXECUTE) != 0,
                        });
                    }
                    let offset = gpa - slot.gpa_start;
                    return Ok(slot.hpa_start + offset);
                }
            }
        }

        Err(VmExitReason::EptViolation {
            gpa,
            read: (required_perm & ept_perms::READ) != 0,
            write: (required_perm & ept_perms::WRITE) != 0,
            exec: (required_perm & ept_perms::EXECUTE) != 0,
        })
    }
}

/// Registres d'architecture du processeur invité (vCPU)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cr3: u64,
}

/// Raison de piégeage et sortie de virtualisation matérielle (VM-Exit)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExitReason {
    IoInstruction {
        port: u16,
        is_write: bool,
        size: u8,
        data: u32,
    },
    MmioAccess {
        gpa: u64,
        is_write: bool,
        size: u8,
        data: u64,
    },
    Halt,
    CpuidQuery {
        leaf: u32,
        subleaf: u32,
    },
    EptViolation {
        gpa: u64,
        read: bool,
        write: bool,
        exec: bool,
    },
    InternalError,
}

/// État du cycle de vie d'un vCPU
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuState {
    Ready,
    Running,
    Halted,
    Exited,
}

/// Processeur virtuel invité (vCPU)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualCpu {
    pub vcpu_id: u32,
    pub regs: GuestRegisters,
    pub state: VcpuState,
    pub instruction_count: u64,
}

impl VirtualCpu {
    pub const fn new(vcpu_id: u32, rip: u64, rsp: u64) -> Self {
        let mut regs = GuestRegisters {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rsp,
            rbp: rsp,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip,
            rflags: 0x2, // Reserved bit 1 set in RFLAGS
            cr3: 0,
        };
        regs.rip = rip;
        regs.rsp = rsp;
        regs.rbp = rsp;

        Self {
            vcpu_id,
            regs,
            state: VcpuState::Ready,
            instruction_count: 0,
        }
    }
}

pub const MAX_VCPUS_PER_VM: usize = 4;
pub const SERIAL_BUFFER_CAPACITY: usize = 256;

/// Port standard de console série COM1 piégé par le VMM
pub const COM1_PORT: u16 = 0x3F8;
/// Port I/O pour signal d'extinction de la machine virtuelle
pub const SHUTDOWN_PORT: u16 = 0x604;

/// Moniteur de micro-machine virtuelle (MicroVMM)
pub struct MicroVmm {
    pub vm_id: u32,
    pub vcpus: [Option<VirtualCpu>; MAX_VCPUS_PER_VM],
    pub ept: EptAddressSpace,
    pub serial_buffer: [u8; SERIAL_BUFFER_CAPACITY],
    pub serial_len: usize,
    pub total_exits: u64,
}

impl MicroVmm {
    /// Crée une nouvelle micro-VM régie par une capacité valide
    pub fn new(cap: &VmCap, vm_id: u32) -> Result<Self, SysError> {
        if !cap.can_create() || cap.vm_id != vm_id {
            return Err(SysError::PermissionDenied);
        }

        Ok(Self {
            vm_id,
            vcpus: [None; MAX_VCPUS_PER_VM],
            ept: EptAddressSpace::new(),
            serial_buffer: [0u8; SERIAL_BUFFER_CAPACITY],
            serial_len: 0,
            total_exits: 0,
        })
    }

    /// Associe une plage de mémoire physique invitée (GPA) à la mémoire hôte (HPA)
    pub fn map_memory(
        &mut self,
        cap: &VmCap,
        gpa: u64,
        hpa: u64,
        size: usize,
        perms: u8,
    ) -> Result<(), SysError> {
        if !cap.can_map_memory() || cap.vm_id != self.vm_id {
            return Err(SysError::PermissionDenied);
        }
        self.ept.map_page(gpa, hpa, size, perms)
    }

    /// Révoque le mappage d'une plage physique invitée
    pub fn unmap_memory(&mut self, cap: &VmCap, gpa: u64) -> Result<(), SysError> {
        if !cap.can_map_memory() || cap.vm_id != self.vm_id {
            return Err(SysError::PermissionDenied);
        }
        self.ept.unmap_page(gpa)
    }

    /// Ajoute et configure un vCPU pour la micro-VM
    pub fn add_vcpu(
        &mut self,
        cap: &VmCap,
        vcpu_id: u32,
        entry_point: u64,
        stack_pointer: u64,
    ) -> Result<(), SysError> {
        if !cap.can_create() || cap.vm_id != self.vm_id {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.vcpus.iter_mut() {
            if slot.is_none() {
                *slot = Some(VirtualCpu::new(vcpu_id, entry_point, stack_pointer));
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Traite les opérations d'E/S piégées (I/O exit)
    pub fn handle_io_exit(
        &mut self,
        port: u16,
        is_write: bool,
        size: u8,
        data: u32,
    ) -> Result<u32, SysError> {
        self.total_exits += 1;

        if port == COM1_PORT && is_write {
            let byte = (data & 0xFF) as u8;
            if self.serial_len < SERIAL_BUFFER_CAPACITY {
                self.serial_buffer[self.serial_len] = byte;
                self.serial_len += 1;
            }
            return Ok(0);
        }

        if port == SHUTDOWN_PORT && is_write {
            // Signal d'arrêt de la VM
            return Ok(0x55AA);
        }

        // Port par défaut : lecture renvoie 0xFF, écriture ignorée
        if is_write {
            Ok(0)
        } else {
            let mask = match size {
                1 => 0xFF,
                2 => 0xFFFF,
                4 => 0xFFFF_FFFF,
                _ => 0xFF,
            };
            Ok(mask)
        }
    }

    /// Exécute une étape d'un vCPU sur un bytecode ou bloc invité émulé
    /// Déclenche un VM-Exit approprié (I/O, HLT, EPT Violation, etc.)
    pub fn step_vcpu(
        &mut self,
        cap: &VmCap,
        vcpu_index: usize,
        guest_ram: &[u8],
    ) -> Result<VmExitReason, SysError> {
        if !cap.can_run_guest() || cap.vm_id != self.vm_id {
            return Err(SysError::PermissionDenied);
        }

        if vcpu_index >= MAX_VCPUS_PER_VM {
            return Err(SysError::InvalidArgument);
        }

        let mut vcpu = match self.vcpus[vcpu_index] {
            Some(v) => v,
            None => return Err(SysError::InvalidArgument),
        };

        if vcpu.state == VcpuState::Halted || vcpu.state == VcpuState::Exited {
            return Ok(VmExitReason::Halt);
        }

        vcpu.state = VcpuState::Running;

        // Traduire le pointeur d'instruction (RIP) via l'EPT
        let hpa = match self.ept.translate(vcpu.regs.rip, ept_perms::EXECUTE) {
            Ok(addr) => addr as usize,
            Err(exit) => {
                self.total_exits += 1;
                vcpu.state = VcpuState::Ready;
                self.vcpus[vcpu_index] = Some(vcpu);
                return Ok(exit);
            }
        };

        if hpa >= guest_ram.len() {
            self.total_exits += 1;
            vcpu.state = VcpuState::Ready;
            self.vcpus[vcpu_index] = Some(vcpu);
            return Ok(VmExitReason::EptViolation {
                gpa: vcpu.regs.rip,
                read: false,
                write: false,
                exec: true,
            });
        }

        let opcode = guest_ram[hpa];
        vcpu.instruction_count += 1;

        let exit_reason = match opcode {
            // 0x90: NOP
            0x90 => {
                vcpu.regs.rip += 1;
                vcpu.state = VcpuState::Ready;
                VmExitReason::CpuidQuery {
                    leaf: 0,
                    subleaf: 0,
                }
            }
            // 0xF4: HLT
            0xF4 => {
                vcpu.regs.rip += 1;
                vcpu.state = VcpuState::Halted;
                self.total_exits += 1;
                VmExitReason::Halt
            }
            // 0xE6: OUT imm8, AL (écrit AL sur port 8-bit)
            0xE6 => {
                if hpa + 1 >= guest_ram.len() {
                    VmExitReason::InternalError
                } else {
                    let port = guest_ram[hpa + 1] as u16;
                    let data = (vcpu.regs.rax & 0xFF) as u32;
                    vcpu.regs.rip += 2;
                    let _ = self.handle_io_exit(port, true, 1, data);
                    vcpu.state = VcpuState::Ready;
                    VmExitReason::IoInstruction {
                        port,
                        is_write: true,
                        size: 1,
                        data,
                    }
                }
            }
            // 0xE4: IN AL, imm8 (lit depuis port 8-bit dans AL)
            0xE4 => {
                if hpa + 1 >= guest_ram.len() {
                    VmExitReason::InternalError
                } else {
                    let port = guest_ram[hpa + 1] as u16;
                    let val = self.handle_io_exit(port, false, 1, 0).unwrap_or(0xFF);
                    vcpu.regs.rax = (vcpu.regs.rax & !0xFF) | (val as u64 & 0xFF);
                    vcpu.regs.rip += 2;
                    vcpu.state = VcpuState::Ready;
                    VmExitReason::IoInstruction {
                        port,
                        is_write: false,
                        size: 1,
                        data: val,
                    }
                }
            }
            // 0xB8: MOV EAX, imm32
            0xB8 => {
                if hpa + 4 >= guest_ram.len() {
                    VmExitReason::InternalError
                } else {
                    let imm = u32::from_le_bytes([
                        guest_ram[hpa + 1],
                        guest_ram[hpa + 2],
                        guest_ram[hpa + 3],
                        guest_ram[hpa + 4],
                    ]);
                    vcpu.regs.rax = imm as u64;
                    vcpu.regs.rip += 5;
                    vcpu.state = VcpuState::Ready;
                    VmExitReason::CpuidQuery {
                        leaf: imm,
                        subleaf: 0,
                    }
                }
            }
            // Opcode inconnu ou non émulé -> VM-Exit d'instruction
            _ => {
                self.total_exits += 1;
                vcpu.state = VcpuState::Ready;
                vcpu.regs.rip += 1;
                VmExitReason::InternalError
            }
        };

        self.vcpus[vcpu_index] = Some(vcpu);
        Ok(exit_reason)
    }

    /// Récupère les données envoyées par l'invité sur la console série
    pub fn get_serial_output(&self) -> &[u8] {
        &self.serial_buffer[..self.serial_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_cap_rights() {
        let cap_full = VmCap::new(Handle::new(1, 0), 100, vm_rights::ALL);
        assert!(cap_full.can_create());
        assert!(cap_full.can_run_guest());
        assert!(cap_full.can_map_memory());
        assert!(cap_full.can_intercept_io());

        let cap_ro = VmCap::new(Handle::new(2, 0), 100, vm_rights::GUEST_RUN);
        assert!(!cap_ro.can_create());
        assert!(cap_ro.can_run_guest());
        assert!(!cap_ro.can_map_memory());
        assert!(!cap_ro.can_intercept_io());
    }

    #[test]
    fn test_ept_address_space_translation() {
        let mut ept = EptAddressSpace::new();

        // Mapper GPA 0x1000..0x2000 vers HPA 0x8000..0x9000 en RWX
        assert!(ept.map_page(0x1000, 0x8000, 0x1000, ept_perms::RWX).is_ok());

        // Traduction valide
        let hpa = ept.translate(0x1050, ept_perms::READ);
        assert_eq!(hpa, Ok(0x8050));

        let hpa_exec = ept.translate(0x1FFF, ept_perms::EXECUTE);
        assert_eq!(hpa_exec, Ok(0x8FFF));

        // GPA non mappé -> EPT violation
        let unmapped = ept.translate(0x3000, ept_perms::READ);
        assert_eq!(
            unmapped,
            Err(VmExitReason::EptViolation {
                gpa: 0x3000,
                read: true,
                write: false,
                exec: false
            })
        );
    }

    #[test]
    fn test_ept_permission_violation() {
        let mut ept = EptAddressSpace::new();
        // Mapper en Read-Only
        assert!(ept
            .map_page(0x2000, 0x5000, 0x1000, ept_perms::READ)
            .is_ok());

        // Tentative d'écriture -> EPT violation
        let write_res = ept.translate(0x2010, ept_perms::WRITE);
        assert_eq!(
            write_res,
            Err(VmExitReason::EptViolation {
                gpa: 0x2010,
                read: false,
                write: true,
                exec: false
            })
        );
    }

    #[test]
    fn test_micro_vmm_lifecycle_and_io_trap() {
        let cap = VmCap::new(Handle::new(1, 0), 42, vm_rights::ALL);
        let mut vmm = MicroVmm::new(&cap, 42).expect("création VMM");

        // Mapper mémoire
        vmm.map_memory(&cap, 0x0, 0x0, 0x1000, ept_perms::RWX)
            .expect("map RAM");

        // Configurer vCPU
        vmm.add_vcpu(&cap, 0, 0x0, 0x800).expect("add vCPU");

        // Payload invité :
        // 0x00: MOV EAX, 0x41 (B8 41 00 00 00)
        // 0x05: OUT 0xF8, AL (E6 F8) - COM1 port 0x3F8 tronqué à 0xF8 ou direct OUT
        let mut ram = [0u8; 0x1000];
        ram[0] = 0xB8; // MOV EAX, 'J'
        ram[1] = b'J';
        ram[2] = 0x00;
        ram[3] = 0x00;
        ram[4] = 0x00;
        ram[5] = 0xE6; // OUT 0xF8, AL
        ram[6] = 0xF8;
        ram[7] = 0xF4; // HLT

        // Étape 1 : MOV EAX, 'J'
        let exit1 = vmm.step_vcpu(&cap, 0, &ram).expect("step 1");
        assert_eq!(
            exit1,
            VmExitReason::CpuidQuery {
                leaf: b'J' as u32,
                subleaf: 0
            }
        );
        assert_eq!(vmm.vcpus[0].unwrap().regs.rax, b'J' as u64);

        // Étape 2 : OUT 0xF8, AL
        let exit2 = vmm.step_vcpu(&cap, 0, &ram).expect("step 2");
        assert_eq!(
            exit2,
            VmExitReason::IoInstruction {
                port: 0xF8,
                is_write: true,
                size: 1,
                data: b'J' as u32
            }
        );

        // Étape 3 : HLT
        let exit3 = vmm.step_vcpu(&cap, 0, &ram).expect("step 3");
        assert_eq!(exit3, VmExitReason::Halt);
        assert_eq!(vmm.vcpus[0].unwrap().state, VcpuState::Halted);
    }

    #[test]
    fn test_unauthorized_vmm_access_denied() {
        let cap_unauth = VmCap::new(Handle::new(1, 0), 99, 0); // 0 droits
        let vmm_res = MicroVmm::new(&cap_unauth, 99);
        assert_eq!(vmm_res.err(), Some(SysError::PermissionDenied));
    }
}

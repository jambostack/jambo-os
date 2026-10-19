//! Module de validation du Micro-Hyperviseur Utilisateur & Isolation Matérielle Type-2 (Phase 56 - v0.2.54)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_vmm::{
    ept_perms, vm_rights, EptAddressSpace, JamboVmmDaemon, MicroVmm, VcpuState, VmCap, VmExitReason,
};

/// Exécute la suite de tests du micro-hyperviseur utilisateur et de l'isolation matérielle Type-2 (Phase 56)
pub fn execute_userspace_vmm_test() -> bool {
    kprintln!("[VMM/TEST] Démarrage du test du micro-hyperviseur utilisateur Type-2 (Phase 56)...");

    // 1. Validation du contrôle d'accès capabilaire (VmCap)
    let admin_cap = VmCap::new(Handle::new(56, 1), 10, vm_rights::ALL);
    assert!(admin_cap.can_create());
    assert!(admin_cap.can_run_guest());
    assert!(admin_cap.can_map_memory());
    assert!(admin_cap.can_intercept_io());

    let guest_cap = VmCap::new(Handle::new(56, 2), 10, vm_rights::GUEST_RUN);
    assert!(!guest_cap.can_create());
    assert!(guest_cap.can_run_guest());
    assert!(!guest_cap.can_map_memory());
    assert!(!guest_cap.can_intercept_io());

    let unauth_create = MicroVmm::new(&guest_cap, 10);
    assert_eq!(
        unauth_create.err(),
        Some(SysError::PermissionDenied),
        "Création d'une VM sans le droit VM_CREATE doit échouer"
    );
    kprintln!("[VMM/CAP] Droits capabilitaires VmCap et confinement zéro-autorité validés");

    // 2. Validation de l'espace d'adressage EPT (Extended Page Tables)
    let mut ept = EptAddressSpace::new();
    assert!(ept.map_page(0x1000, 0x8000, 0x1000, ept_perms::RWX).is_ok());

    let hpa_read = ept.translate(0x1050, ept_perms::READ);
    assert_eq!(hpa_read, Ok(0x8050));
    let hpa_exec = ept.translate(0x1FF0, ept_perms::EXECUTE);
    assert_eq!(hpa_exec, Ok(0x8FF0));

    // Violation EPT sur GPA non mappé
    let unmapped_exit = ept.translate(0x4000, ept_perms::READ);
    assert_eq!(
        unmapped_exit,
        Err(VmExitReason::EptViolation {
            gpa: 0x4000,
            read: true,
            write: false,
            exec: false,
        })
    );
    kprintln!("[VMM/EPT] Pagination imbriquée GPA->HPA et détection de violations EPT validées");

    // 3. Validation de l'exécution pas-à-pas et piégeage des I/O
    let mut vmm = MicroVmm::new(&admin_cap, 10).expect("création MicroVmm");
    assert!(vmm
        .map_memory(&admin_cap, 0x0, 0x0, 0x1000, ept_perms::RWX)
        .is_ok());
    assert!(vmm.add_vcpu(&admin_cap, 0, 0x0, 0x800).is_ok());

    // Payload invité :
    // 0x00: MOV EAX, 'J' (B8 4A 00 00 00)
    // 0x05: OUT 0xF8, AL (E6 F8)
    // 0x07: HLT          (F4)
    let mut ram = [0u8; 0x1000];
    ram[0] = 0xB8;
    ram[1] = b'J';
    ram[2] = 0x00;
    ram[3] = 0x00;
    ram[4] = 0x00;
    ram[5] = 0xE6;
    ram[6] = 0xF8;
    ram[7] = 0xF4;

    let exit1 = vmm.step_vcpu(&admin_cap, 0, &ram).expect("step 1");
    assert_eq!(
        exit1,
        VmExitReason::CpuidQuery {
            leaf: b'J' as u32,
            subleaf: 0,
        }
    );

    let exit2 = vmm.step_vcpu(&admin_cap, 0, &ram).expect("step 2");
    assert_eq!(
        exit2,
        VmExitReason::IoInstruction {
            port: 0xF8,
            is_write: true,
            size: 1,
            data: b'J' as u32,
        }
    );
    assert_eq!(vmm.get_serial_output(), b"J");

    let exit3 = vmm.step_vcpu(&admin_cap, 0, &ram).expect("step 3");
    assert_eq!(exit3, VmExitReason::Halt);
    assert_eq!(vmm.vcpus[0].unwrap().state, VcpuState::Halted);
    kprintln!("[VMM/EXEC] vCPU step, piégeage I/O COM1 et interception HLT validés");

    // 4. Validation du démon orchestrateur JamboVmmDaemon
    let mut daemon = JamboVmmDaemon::new();
    assert!(!daemon.is_vm_active());
    daemon.init_defaults();
    assert!(daemon.is_vm_active());

    let steps = daemon.run_until_halt(0, 10).expect("run until halt");
    assert_eq!(steps, 5); // MOV 'J', OUT, MOV 'O', OUT, HLT
    assert_eq!(daemon.get_serial_output(), b"JO");
    assert_eq!(daemon.total_exits(), 3);
    kprintln!("[VMM/DAEMON] Démon JamboVmmDaemon opérationnel de bout en bout");

    // 5. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'vmm status'
    let (st_stat, len_stat) = shell.execute_line("vmm status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("MICRO-HYPERVISEUR UTILISATEUR TYPE-2"));
    assert!(str_stat.contains("OUI (VM #1)"));
    assert!(str_stat.contains("EPT / Stage-2 Pagetables"));
    kprintln!("[VMM/SHELL] Commande 'vmm status' validée");

    // Commande 'vmm reset'
    let (st_rst, len_rst) = shell.execute_line("vmm reset", &mut out_buf);
    assert_eq!(st_rst, ShellStatus::Success);
    let str_rst = core::str::from_utf8(&out_buf[..len_rst]).unwrap_or("");
    assert!(str_rst.contains("Micro-VM réinitialisée avec succès"));
    kprintln!("[VMM/SHELL] Commande 'vmm reset' validée");

    // Commande 'vmm step'
    let (st_step, len_step) = shell.execute_line("vmm step", &mut out_buf);
    assert_eq!(st_step, ShellStatus::Success);
    let str_step = core::str::from_utf8(&out_buf[..len_step]).unwrap_or("");
    assert!(str_step.contains("VM-Exit intercepté avec succès"));
    kprintln!("[VMM/SHELL] Commande 'vmm step' validée");

    // Commande 'vmm run'
    let (st_run, len_run) = shell.execute_line("vmm run", &mut out_buf);
    assert_eq!(st_run, ShellStatus::Success);
    let str_run = core::str::from_utf8(&out_buf[..len_run]).unwrap_or("");
    assert!(str_run.contains("Micro-VM exécutée jusqu'à HLT"));
    kprintln!("[VMM/SHELL] Commande 'vmm run' validée");

    kprintln!(
        "[VMM/PASS] Micro-hyperviseur utilisateur Type-2 et isolation matérielle validés avec succès."
    );
    true
}

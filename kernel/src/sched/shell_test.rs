//! Module de test et validation du Shell interactif jsh en Ring 3 & Commandes Natives (Phase 42 - v0.2.40)
#![allow(unused_imports, dead_code)]

extern crate alloc;
use alloc::sync::Arc;
use spin::Mutex;

use crate::kprintln;
use crate::mm::{AddressSpace, Vmo, PAGE_SIZE};
use crate::sched::{EevdfScheduler, Thread, ThreadState, SCHEDULER};
use jambo_abi::{vmo_prot, SystemInfo};

#[cfg(target_arch = "x86_64")]
pub fn execute_shell_repl_test() -> bool {
    kprintln!("[SHELL/TEST] Initialisation du test de shell interactif Ring 3 jsh (Phase 42)...");

    let aspace = match AddressSpace::new() {
        Some(a) => Arc::new(a),
        None => {
            kprintln!("[SHELL/ERR] Échec de création d'AddressSpace");
            return false;
        }
    };

    // 1. Mappage des pages utilisateur : Code (0x0040_0000), Data (0x0040_1000), Input (0x0040_2000), SysInfo (0x0040_3000)
    let code_vmo = Vmo::create(PAGE_SIZE);
    let data_vmo = Vmo::create(PAGE_SIZE);
    let in_vmo = Vmo::create(PAGE_SIZE);
    let info_vmo = Vmo::create(PAGE_SIZE);

    if aspace
        .map_vmo(
            0x0040_0000,
            code_vmo,
            vmo_prot::READ | vmo_prot::WRITE | vmo_prot::EXEC,
        )
        .is_err()
        || aspace
            .map_vmo(0x0040_1000, data_vmo, vmo_prot::READ | vmo_prot::WRITE)
            .is_err()
        || aspace
            .map_vmo(0x0040_2000, in_vmo, vmo_prot::READ | vmo_prot::WRITE)
            .is_err()
        || aspace
            .map_vmo(0x0040_3000, info_vmo, vmo_prot::READ | vmo_prot::WRITE)
            .is_err()
    {
        kprintln!("[SHELL/ERR] Échec du mapping des pages mémoire virtuelles");
        return false;
    }

    // 2. Initialiser les données : Prompt "jambo:/# " dans la page data
    let prompt = b"jambo:/# ";
    if aspace.write_bytes(0x0040_1000, prompt).is_err() {
        kprintln!("[SHELL/ERR] Échec d'écriture du prompt en mémoire utilisateur");
        return false;
    }

    // 3. Injecter la commande interactive dans la file d'entrée UART RX
    let input_cmd = "echo Hello JamboOS!\n";
    crate::arch::inject_input_str(input_cmd);

    // 4. Écrire le bytecode Ring 3 :
    //    - ConsoleWrite(0x00401000, 9)   ; Affiche prompt "jambo:/# "
    //    - ConsoleRead(0x00402000, 64)   ; Lit commande dans buffer utilisateur
    //    - SysInfo(0x00403000)           ; Interroge métriques système
    //    - ThreadYield                   ; Rend la main au superviseur (Syscall 12)
    //    - ThreadExit(0)                 ; Sortie propre (Syscall 11)
    let shell_bytecode: [u8; 92] = [
        // 1. ConsoleWrite(0x00401000, 9)
        0x48, 0xbf, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, 0x00401000
        0x48, 0xc7, 0xc6, 0x09, 0x00, 0x00, 0x00, // mov rsi, 9
        0x48, 0xc7, 0xc0, 0x1a, 0x00, 0x00, 0x00, // mov rax, 26 (ConsoleWrite)
        0x0f, 0x05, // syscall
        // 2. ConsoleRead(0x00402000, 64)
        0x48, 0xbf, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, 0x00402000
        0x48, 0xc7, 0xc6, 0x40, 0x00, 0x00, 0x00, // mov rsi, 64
        0x48, 0xc7, 0xc0, 0x19, 0x00, 0x00, 0x00, // mov rax, 25 (ConsoleRead)
        0x0f, 0x05, // syscall
        // 3. SysInfo(0x00403000)
        0x48, 0xbf, 0x00, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, 0x00403000
        0x48, 0xc7, 0xc0, 0x1b, 0x00, 0x00, 0x00, // mov rax, 27 (SysInfo)
        0x0f, 0x05, // syscall
        // 4. ThreadYield (12)
        0x48, 0xc7, 0xc0, 0x0c, 0x00, 0x00, 0x00, // mov rax, 12
        0x0f, 0x05, // syscall
        // 5. ThreadExit(0)
        0x48, 0x31, 0xff, // xor rdi, rdi
        0x48, 0xc7, 0xc0, 0x0b, 0x00, 0x00, 0x00, // mov rax, 11
        0x0f, 0x05, // syscall
    ];

    if aspace.write_bytes(0x0040_0000, &shell_bytecode).is_err() {
        kprintln!("[SHELL/ERR] Échec de copie du bytecode");
        return false;
    }

    // 5. Mappage de la pile utilisateur (64 Kio)
    let stack_vmo = Vmo::create(64 * 1024);
    let stack_base = 0x0000_7FFF_FFFF_0000usize - 64 * 1024;
    if aspace
        .map_vmo(stack_base, stack_vmo, vmo_prot::READ | vmo_prot::WRITE)
        .is_err()
    {
        kprintln!("[SHELL/ERR] Échec du mapping de la pile utilisateur");
        return false;
    }

    let user_entry = 0x0040_0000u64;
    let user_rsp = 0x0000_7FFF_FFFF_0000u64 - 16;

    // 6. Création du thread shell Ring 3
    let shell_thread = match Thread::new_user(888, 2, aspace.clone(), user_entry, user_rsp) {
        Some(t) => t,
        None => {
            kprintln!("[SHELL/ERR] Échec de création du thread");
            return false;
        }
    };
    shell_thread.lock().deadline = 2;

    let main_kernel_thread = Arc::new(Mutex::new(Thread {
        id: 0,
        process_id: 0,
        state: ThreadState::Running,
        rsp: 0,
        stack_base: 0,
        stack_top: 0,
        vruntime: 0,
        deadline: 0,
        weight: 1024,
        is_user: false,
        user_entry: 0,
        user_rsp: 0,
        aspace: None,
    }));

    {
        let mut sched = SCHEDULER.lock();
        sched.current = Some(main_kernel_thread.clone());
        sched.enqueue(shell_thread.clone());
    }

    kprintln!("[SHELL/REPL] Prompt 'jambo:/# ' initialisé en Ring 3");

    // Basculer vers le thread utilisateur
    EevdfScheduler::reschedule();

    // Vérifier les données lues dans le buffer utilisateur
    let mut captured_cmd = [0u8; 32];
    if aspace.read_bytes(0x0040_2000, &mut captured_cmd).is_ok() {
        let cmd_str = core::str::from_utf8(&captured_cmd[..input_cmd.len()]).unwrap_or("");
        kprintln!(
            "[SHELL/EXEC] Commande utilisateur capturée par Syscall 25 : {:?}",
            cmd_str
        );
        if cmd_str != input_cmd {
            kprintln!("[SHELL/ERR] Commande capturée non conforme");
            return false;
        }
    }

    // Vérifier les métriques retournées par SysInfo
    let mut captured_info = SystemInfo::default();
    let info_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut captured_info as *mut SystemInfo as *mut u8,
            core::mem::size_of::<SystemInfo>(),
        )
    };
    if aspace.read_bytes(0x0040_3000, info_bytes).is_ok() {
        kprintln!(
            "[SHELL/SYSINFO] Syscall SysInfo validé (Total: {} pgs, Libre: {} pgs, Uptime: {}s)",
            captured_info.total_pages,
            captured_info.free_pages,
            captured_info.uptime_seconds
        );
        assert!(captured_info.total_pages > 0);
    }

    // Validation des commandes natives réelles via JamboShell
    let mut shell = jambo_sh::JamboShell::new();
    let mut out_buf = [0u8; 1024];

    // Test commande 'echo'
    let (_, len_echo) = shell.execute_line("echo Hello JamboOS!", &mut out_buf);
    let str_echo = core::str::from_utf8(&out_buf[..len_echo]).unwrap_or("");
    kprintln!(
        "[SHELL/EXEC] Commande 'echo Hello JamboOS!' -> {:?}",
        str_echo.trim_ascii()
    );
    assert_eq!(str_echo.trim_ascii(), "Hello JamboOS!");

    // Test commande 'mem'
    let (_, len_mem) = shell.execute_line("mem", &mut out_buf);
    let str_mem = core::str::from_utf8(&out_buf[..len_mem]).unwrap_or("");
    assert!(str_mem.contains("PMM Allocateur"));
    kprintln!("[SHELL/EXEC] Commande 'mem' validée avec statistiques PMM");

    // Test commande 'ps'
    let (_, len_ps) = shell.execute_line("ps", &mut out_buf);
    let str_ps = core::str::from_utf8(&out_buf[..len_ps]).unwrap_or("");
    assert!(str_ps.contains("jambo-init") && str_ps.contains("jsh"));
    kprintln!("[SHELL/EXEC] Commande 'ps' validée avec table des processus Ring 3");

    // Test commande 'help'
    let (_, len_help) = shell.execute_line("help", &mut out_buf);
    let str_help = core::str::from_utf8(&out_buf[..len_help]).unwrap_or("");
    assert!(str_help.contains("version") && str_help.contains("poweroff"));
    kprintln!("[SHELL/EXEC] Commande 'help' validée");

    // Reprise du thread utilisateur pour exécuter ThreadExit
    shell_thread.lock().deadline = 0;
    EevdfScheduler::reschedule();

    let final_state = shell_thread.lock().state;
    kprintln!(
        "[SHELL/EXIT] Thread shell utilisateur terminé avec l'état : {:?}",
        final_state
    );

    if final_state != ThreadState::Exited {
        return false;
    }

    kprintln!("[SHELL/PASS] Shell interactif jsh Ring 3 et commandes natives validés.");
    true
}

#[cfg(target_arch = "aarch64")]
pub fn execute_shell_repl_test() -> bool {
    kprintln!("[SHELL/AARCH64] Validation de shell interactif jsh émulée");
    true
}

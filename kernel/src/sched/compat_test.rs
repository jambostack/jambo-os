//! Module de test et validation de la Couche de Compatibilité Linux POSIX et Runtime WASI/Wasm (Phase 47 - v0.2.45)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_linux::{
    emulate_linux_elf_binary, LinuxProcessEmulator, LINUX_SYS_BRK, LINUX_SYS_CLOSE,
    LINUX_SYS_GETPID, LINUX_SYS_MMAP, LINUX_SYS_OPEN, LINUX_SYS_UNAME, LINUX_SYS_WRITE,
};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_wasm::{execute_wasm_module, WasmEngine, WasmLinearMemory};

/// Exécute la suite de tests de compatibilité Linux POSIX et de runtime WASI/Wasm (Phase 47)
pub fn execute_compat_test() -> bool {
    kprintln!(
        "[COMPAT/TEST] Démarrage du test de compatibilité Linux POSIX & runtime WASI/Wasm (Phase 47)..."
    );

    // 1. Initialisation de l'émulateur Linux POSIX et isolation CSpace des descripteurs
    let mut emu = LinuxProcessEmulator::new(1001);
    assert_eq!(emu.pid, 1001);
    assert_eq!(
        emu.handle_linux_syscall(LINUX_SYS_GETPID, 0, 0, 0, 0, 0, 0),
        1001
    );
    assert_eq!(
        emu.handle_linux_syscall(LINUX_SYS_UNAME, 0, 0, 0, 0, 0, 0),
        0
    );

    // Fd 1 (stdout) est inscriptible
    assert_eq!(
        emu.handle_linux_syscall(LINUX_SYS_WRITE, 1, 0, 16, 0, 0, 0),
        16
    );
    // Fd 0 (stdin) est en lecture seule -> écriture rejetée EBADF (-9)
    assert_eq!(
        emu.handle_linux_syscall(LINUX_SYS_WRITE, 0, 0, 16, 0, 0, 0),
        -9
    );

    // Ouverture et fermeture de descripteur avec handle de capacité dédié
    let new_fd = emu.handle_linux_syscall(LINUX_SYS_OPEN, 0, 0, 0, 0, 0, 0);
    assert!(new_fd >= 3);
    assert_eq!(
        emu.handle_linux_syscall(LINUX_SYS_CLOSE, new_fd as u64, 0, 0, 0, 0, 0),
        0
    );
    assert_eq!(
        emu.handle_linux_syscall(LINUX_SYS_CLOSE, new_fd as u64, 0, 0, 0, 0, 0),
        -9 // EBADF déjà fermé
    );

    // Allocation mémoire mmap / brk
    let mmap_addr = emu.handle_linux_syscall(LINUX_SYS_MMAP, 0, 4096, 0, 0, 0, 0);
    assert_eq!(mmap_addr, 0x7000_0000);
    let brk_addr = emu.handle_linux_syscall(LINUX_SYS_BRK, 0x8000_0000, 0, 0, 0, 0, 0);
    assert_eq!(brk_addr, 0x8000_0000);
    kprintln!("[COMPAT/POSIX] Shims syscalls Linux validés (PID, UNAME, FDs, MMAP, BRK)");

    // 2. Émulation de binaire ELF Linux synthétique
    let (elf_code, syscall_count) = emulate_linux_elf_binary("coreutils_ls", 1002);
    assert_eq!(elf_code, 0);
    assert_eq!(syscall_count, 4);
    kprintln!(
        "[COMPAT/ELF] Binaire ELF Linux synthétique exécuté avec succès (0 dette POSIX en Ring 0)"
    );

    // 3. Mémoire linéaire WASM sandboxed & vérification stricte des bornes
    let mut wasm_mem = WasmLinearMemory::new(1);
    assert!(wasm_mem.write_memory(0, b"jambo-wasm-payload").is_ok());
    assert_eq!(wasm_mem.read_memory(0, 18).unwrap(), b"jambo-wasm-payload");
    // Débordement mémoire intercepté
    assert_eq!(
        wasm_mem.write_memory(4090, b"too large payload for page boundary"),
        Err(SysError::BadAddress)
    );
    assert_eq!(wasm_mem.read_memory(4095, 10), Err(SysError::BadAddress));
    kprintln!("[WASM/MEM] Mémoire linéaire isolée et contrôle strict des bornes validés");

    // 4. Moteur WASM & Sandbox WASI avec Gas Metering
    let mut engine = WasmEngine::new();
    let valid_wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    let mut instance = match engine.load_module(&valid_wasm) {
        Ok(inst) => inst,
        Err(_) => {
            kprintln!("[WASM/ERR] Échec du chargement du module WASM valide");
            return false;
        }
    };
    assert_eq!(instance.wasi_fd_write(1, b"wasm hello").unwrap(), 10);
    assert!(instance.wasi_clock_time_get(0).unwrap() > 0);
    assert_eq!(engine.invoke_export(&mut instance, "_start"), Ok(0));
    assert_eq!(engine.gas_consumed, 50);

    // Rejet de module corrompu
    let corrupt_wasm = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00];
    assert_eq!(
        engine.load_module(&corrupt_wasm).err(),
        Some(SysError::InvalidArgument)
    );
    kprintln!("[WASM/ENGINE] Moteur WASM, imports WASI et comptage de gaz validés");

    // 5. Exécution autonome de module WASM
    let (mod_code, gas) = execute_wasm_module("micro_service.wasm");
    assert_eq!(mod_code, 0);
    assert_eq!(gas, 50);
    kprintln!("[WASM/EXEC] Module WASM synthétique exécuté dans la sandbox WASI");

    // 6. Validation des commandes du Shell jsh (compat & wasm)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'compat status'
    let (st_cstat, len_cstat) = shell.execute_line("compat status", &mut out_buf);
    assert_eq!(st_cstat, ShellStatus::Success);
    let str_cstat = core::str::from_utf8(&out_buf[..len_cstat]).unwrap_or("");
    assert!(str_cstat.contains("Linux POSIX Translation Layer: Active"));
    kprintln!("[COMPAT/SHELL] Commande 'compat status' validée");

    // Commande 'compat run busybox_cat'
    let (st_crun, len_crun) = shell.execute_line("compat run busybox_cat", &mut out_buf);
    assert_eq!(st_crun, ShellStatus::Success);
    let str_crun = core::str::from_utf8(&out_buf[..len_crun]).unwrap_or("");
    assert!(str_crun.contains("busybox_cat") && str_crun.contains("syscalls"));
    kprintln!("[COMPAT/SHELL] Commande 'compat run' validée");

    // Commande 'wasm info'
    let (st_winfo, len_winfo) = shell.execute_line("wasm info", &mut out_buf);
    assert_eq!(st_winfo, ShellStatus::Success);
    let str_winfo = core::str::from_utf8(&out_buf[..len_winfo]).unwrap_or("");
    assert!(str_winfo.contains("WASI Sandboxed Runtime: Active"));
    kprintln!("[WASM/SHELL] Commande 'wasm info' validée");

    // Commande 'wasm run hello.wasm'
    let (st_wrun, len_wrun) = shell.execute_line("wasm run hello.wasm", &mut out_buf);
    assert_eq!(st_wrun, ShellStatus::Success);
    let str_wrun = core::str::from_utf8(&out_buf[..len_wrun]).unwrap_or("");
    assert!(str_wrun.contains("hello.wasm") && str_wrun.contains("gaz consommé"));
    kprintln!("[WASM/SHELL] Commande 'wasm run' validée");

    kprintln!(
        "[COMPAT/PASS] Couche de compatibilité Linux POSIX et runtime WASI/Wasm validés avec succès."
    );
    true
}

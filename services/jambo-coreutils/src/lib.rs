//! Bibliothèque commune pour les utilitaires Coreutils Ring 3 JamboOS
#![no_std]

use libjambo::{syscall6, SyscallNumber};

/// Quitte le processus courant via l'appel système ThreadExit (Syscall 11)
///
/// # Safety
/// Cette fonction effectue un appel système brut de terminaison irréversible du thread utilisateur.
pub unsafe fn exit_process(code: i32) -> ! {
    syscall6(SyscallNumber::ThreadExit, code as u64, 0, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Extrait les arguments de ligne de commande directement depuis le pointeur de pile System V
///
/// Layout attendu : `[argc][argv0][argv1]...[NULL]`
///
/// # Safety
/// Le pointeur `sp` doit désigner une pile valide configurée conformément à la System V AMD64 ABI.
pub unsafe fn parse_stack_args<'a>(
    sp: *const usize,
    storage: &'a mut [&'a str; 16],
) -> (&'a str, &'a [&'a str]) {
    if sp.is_null() {
        return ("", &[]);
    }
    let argc = *sp;
    let argv_ptr = sp.add(1) as *const *const u8;
    let mut count = 0;

    while count < argc && count < 16 {
        let ptr = *argv_ptr.add(count);
        if ptr.is_null() {
            break;
        }
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = core::slice::from_raw_parts(ptr, len);
        if let Ok(s) = core::str::from_utf8(slice) {
            storage[count] = s;
            count += 1;
        } else {
            break;
        }
    }

    let prog = if count > 0 { storage[0] } else { "" };
    let args = if count > 1 {
        &storage[1..count]
    } else {
        &storage[..0]
    };
    (prog, args)
}

//! Couche de compatibilité POSIX et C-ABI statique minimale pour JamboOS
//!
//! Fournit les symboles C d'entrée standard (write, read, mmap, munmap, exit, sched_yield, etc.)
//! mappés sur les 29 appels système sous-jacents de JamboKernel.

use crate::{console_read, console_write, syscall6, vmo_prot, SyscallNumber, SystemInfo};

// Constantes POSIX standard pour descripteurs de fichiers
pub const STDIN_FILENO: i32 = 0;
pub const STDOUT_FILENO: i32 = 1;
pub const STDERR_FILENO: i32 = 2;

// Constantes de protection mémoire mmap
pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;

// Constantes de drapeaux mmap
pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_ANONYMOUS: i32 = 0x20;
pub const MAP_ANON: i32 = MAP_ANONYMOUS;
pub const MAP_FAILED: *mut u8 = !0usize as *mut u8;

// Codes d'erreur POSIX courants
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const ENOSYS: i32 = 38;

// --- API C POSIX ---

/// Écrit `count` octets du tampon `buf` vers le descripteur de fichier `fd`
///
/// # Safety
/// Le pointeur `buf` doit être valide pour la lecture de `count` octets.
#[no_mangle]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    if buf.is_null() && count > 0 {
        return -EFAULT as isize;
    }
    match fd {
        STDOUT_FILENO | STDERR_FILENO => {
            let slice = core::slice::from_raw_parts(buf, count);
            match console_write(slice) {
                Ok(n) => n as isize,
                Err(_) => -EFAULT as isize,
            }
        }
        _ => -EBADF as isize,
    }
}

/// Lit jusqu'à `count` octets depuis le descripteur de fichier `fd` vers `buf`
///
/// # Safety
/// Le pointeur `buf` doit être valide pour l'écriture de `count` octets.
#[no_mangle]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, count: usize) -> isize {
    if buf.is_null() && count > 0 {
        return -EFAULT as isize;
    }
    match fd {
        STDIN_FILENO => {
            let slice = core::slice::from_raw_parts_mut(buf, count);
            match console_read(slice) {
                Ok(n) => n as isize,
                Err(_) => -EFAULT as isize,
            }
        }
        _ => -EBADF as isize,
    }
}

/// Cède le temps processeur au planificateur (équivalent sched_yield POSIX)
#[no_mangle]
pub extern "C" fn sched_yield() -> i32 {
    crate::syscall_thread_yield();
    0
}

/// Termine immédiatement l'exécution du processus appelant (_exit POSIX)
#[no_mangle]
pub extern "C" fn _exit(status: i32) -> ! {
    unsafe {
        syscall6(SyscallNumber::ThreadExit, status as u64, 0, 0, 0, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Termine l'exécution du processus (alias exit POSIX)
#[no_mangle]
pub extern "C" fn exit(status: i32) -> ! {
    _exit(status);
}

/// Projette de la mémoire virtuelle anonyme via un objet mémoire VMO (mmap POSIX)
///
/// # Safety
/// L'appelant doit respecter les contraintes de mémoire virtuelle.
#[no_mangle]
pub unsafe extern "C" fn mmap(
    _addr: *mut u8,
    length: usize,
    _prot: i32,
    flags: i32,
    _fd: i32,
    _offset: i64,
) -> *mut u8 {
    if length == 0 {
        return MAP_FAILED;
    }

    // Arrondi à la taille de page supérieure (4096 octets)
    let page_size = 4096usize;
    let aligned_len = (length + page_size - 1) & !(page_size - 1);

    // Allocation anonyme via VMO
    if (flags & MAP_ANONYMOUS) != 0 || (flags & MAP_ANON) != 0 {
        let mut vmo_handle: u64 = 0;
        let (ret_create, _) = syscall6(
            SyscallNumber::VmoCreate,
            aligned_len as u64,
            0,
            &mut vmo_handle as *mut u64 as u64,
            0,
            0,
            0,
        );
        if ret_create != 0 || vmo_handle == 0 {
            return MAP_FAILED;
        }

        let mut mapped_addr: u64 = 0;
        let (ret_map, _) = syscall6(
            SyscallNumber::VmoMap,
            vmo_handle,
            0, // Auto-allocation d'adresse virtuelle
            aligned_len as u64,
            (vmo_prot::READ | vmo_prot::WRITE | vmo_prot::USER) as u64,
            &mut mapped_addr as *mut u64 as u64,
            0,
        );
        if ret_map != 0 || mapped_addr == 0 {
            return MAP_FAILED;
        }

        mapped_addr as *mut u8
    } else {
        MAP_FAILED
    }
}

/// Libère une projection de mémoire virtuelle (munmap POSIX)
///
/// # Safety
/// Le pointeur `addr` doit correspondre à une projection active de taille `length`.
#[no_mangle]
pub unsafe extern "C" fn munmap(addr: *mut u8, length: usize) -> i32 {
    if addr.is_null() || length == 0 {
        return -EINVAL;
    }
    let (ret, _) = syscall6(
        SyscallNumber::VmoUnmap,
        addr as u64,
        length as u64,
        0,
        0,
        0,
        0,
    );
    if ret == 0 {
        0
    } else {
        -EINVAL
    }
}

// --- Fonctions utilitaires C standards (Memory & String) ---

use core::ffi::{c_char, c_void};

/// Copie `n` octets de `src` vers `dest` (memcpy C standard)
///
/// # Safety
/// Les zones mémoire doivent être valides et ne pas se chevaucher.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    let mut i = 0;
    while i < n {
        *d.add(i) = *s.add(i);
        i += 1;
    }
    dest
}

/// Remplit les `n` premiers octets de `dest` avec la valeur `c` (memset C standard)
///
/// # Safety
/// La zone mémoire `dest` doit être valide pour l'écriture de `n` octets.
#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let byte = c as u8;
    let mut i = 0;
    while i < n {
        *d.add(i) = byte;
        i += 1;
    }
    dest
}

/// Compare les `n` premiers octets de `s1` et `s2` (memcmp C standard)
///
/// # Safety
/// `s1` et `s2` doivent être valides pour la lecture de `n` octets.
#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    let a = s1 as *const u8;
    let b = s2 as *const u8;
    let mut i = 0;
    while i < n {
        let ba = *a.add(i);
        let bb = *b.add(i);
        if ba != bb {
            return (ba as i32) - (bb as i32);
        }
        i += 1;
    }
    0
}

/// Calcule la longueur d'une chaîne C terminée par un octet nul (strlen C standard)
///
/// # Safety
/// `s` doit être un pointeur valide vers une chaîne terminée par `\0`.
#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    let ptr = s as *const u8;
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    len
}

// --- API C Native JamboOS ---

/// Écrit des octets vers la console série JamboOS via C-ABI
///
/// # Safety
/// Le tampon `buf` doit pointer vers au moins `len` octets lisibles.
#[no_mangle]
pub unsafe extern "C" fn jambo_console_write(buf: *const u8, len: usize) -> isize {
    write(STDOUT_FILENO, buf, len)
}

/// Lit des octets depuis la console série JamboOS via C-ABI
///
/// # Safety
/// Le tampon `buf` doit être valide pour l'écriture de `len` octets.
#[no_mangle]
pub unsafe extern "C" fn jambo_console_read(buf: *mut u8, len: usize) -> isize {
    read(STDIN_FILENO, buf, len)
}

/// Cède le processeur au scheduler EEVDF via C-ABI
#[no_mangle]
pub extern "C" fn jambo_yield() -> i32 {
    sched_yield()
}

/// Quitte le thread courant via C-ABI
#[no_mangle]
pub extern "C" fn jambo_exit(status: i32) -> ! {
    _exit(status);
}

/// Interroge les statistiques système globales via C-ABI
///
/// # Safety
/// Le pointeur `out_info` doit pointer vers une structure `SystemInfo` valide et accessible en écriture.
#[no_mangle]
pub unsafe extern "C" fn jambo_sys_info(out_info: *mut SystemInfo) -> i32 {
    if out_info.is_null() {
        return -EFAULT;
    }
    match crate::sys_info() {
        Ok(info) => {
            *out_info = info;
            0
        }
        Err(_) => -EINVAL,
    }
}

/// Crée un objet mémoire virtuel partagé (VMO) via C-ABI
///
/// # Safety
/// Le pointeur `out_handle` doit être accessible en écriture pour stocker le descripteur 64 bits résultant.
#[no_mangle]
pub unsafe extern "C" fn jambo_vmo_create(size: u64, flags: u32, out_handle: *mut u64) -> i32 {
    if out_handle.is_null() {
        return -EFAULT;
    }
    let (ret, _) = syscall6(
        SyscallNumber::VmoCreate,
        size,
        flags as u64,
        out_handle as u64,
        0,
        0,
        0,
    );
    if ret == 0 {
        0
    } else {
        -EINVAL
    }
}

/// Projette un objet VMO dans l'espace d'adressage virtuel via C-ABI
///
/// # Safety
/// Le pointeur `out_mapped` doit être accessible en écriture pour stocker l'adresse virtuelle projetée.
#[no_mangle]
pub unsafe extern "C" fn jambo_vmo_map(
    vmo: u64,
    vaddr: u64,
    length: u64,
    rights: u32,
    out_mapped: *mut u64,
) -> i32 {
    if out_mapped.is_null() {
        return -EFAULT;
    }
    let (ret, _) = syscall6(
        SyscallNumber::VmoMap,
        vmo,
        vaddr,
        length,
        rights as u64,
        out_mapped as u64,
        0,
    );
    if ret == 0 {
        0
    } else {
        -EINVAL
    }
}

/// Déprojette une plage de mémoire virtuelle via C-ABI
///
/// # Safety
/// L'adresse virtuelle `vaddr` et la longueur `length` doivent correspondre à une projection VMO active.
#[no_mangle]
pub unsafe extern "C" fn jambo_vmo_unmap(vaddr: u64, length: u64) -> i32 {
    munmap(vaddr as *mut u8, length as usize)
}

/// Exécute une opération de configuration PCI via le broker matériel (Syscall 29)
///
/// # Safety
/// Le pointeur `val` doit être valide pour la lecture (sur écriture PCI) ou l'écriture (sur lecture PCI).
#[no_mangle]
pub unsafe extern "C" fn jambo_device_io(
    op: u32,
    bus: u8,
    dev: u8,
    func: u8,
    offset: u8,
    val: *mut u32,
) -> i32 {
    if val.is_null() {
        return -EFAULT;
    }
    let bdf = ((bus as u64) << 16) | ((dev as u64 & 0x1F) << 11) | ((func as u64 & 0x07) << 8);
    let (ret, _) = syscall6(
        SyscallNumber::DeviceIo,
        op as u64,
        bdf,
        offset as u64,
        val as u64,
        0,
        0,
    );
    if ret == 0 {
        0
    } else {
        -EPERM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_string_and_memory_primitives() {
        let mut buf = [0u8; 32];
        unsafe {
            memset(buf.as_mut_ptr() as *mut c_void, 0xAA, 16);
            assert_eq!(buf[0], 0xAA);
            assert_eq!(buf[15], 0xAA);
            assert_eq!(buf[16], 0);

            let src = b"Hello, JamboOS!\0";
            memcpy(
                buf.as_mut_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                src.len(),
            );
            assert_eq!(strlen(buf.as_ptr() as *const c_char), 15);
            assert_eq!(
                memcmp(
                    buf.as_ptr() as *const c_void,
                    src.as_ptr() as *const c_void,
                    src.len()
                ),
                0
            );
        }
    }
}

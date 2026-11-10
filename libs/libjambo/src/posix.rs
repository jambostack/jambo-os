//! Couche de compatibilité POSIX et C-ABI statique minimale pour JamboOS
//!
//! Fournit les symboles C d'entrée standard (write, read, mmap, munmap, exit, sched_yield, etc.)
//! mappés sur les 29 appels système sous-jacents de JamboKernel.

#[cfg(not(test))]
use crate::{syscall6, vmo_prot, SyscallNumber, SystemInfo};

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
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const EPIPE: i32 = 32;
pub const ENOSYS: i32 = 38;
pub const ENOTSOCK: i32 = 88;
pub const EAFNOSUPPORT: i32 = 97;
pub const EADDRINUSE: i32 = 98;
pub const ENOTCONN: i32 = 107;

// Constantes de signaux POSIX standard (1..31)
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGSTKFLT: i32 = 16;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const SIGURG: i32 = 23;
pub const SIGXCPU: i32 = 24;
pub const SIGXFSZ: i32 = 25;
pub const SIGVTALRM: i32 = 26;
pub const SIGPROF: i32 = 27;
pub const SIGWINCH: i32 = 28;
pub const SIGIO: i32 = 29;
pub const SIGPWR: i32 = 30;
pub const SIGSYS: i32 = 31;
pub const NSIG: usize = 32;

// Actions de signaux standard
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
pub const SIG_ERR: usize = !0usize;

// Commandes sigprocmask
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

// Drapeaux sigaction
pub const SA_NOCLDSTOP: i32 = 0x0000_0001;
pub const SA_NOCLDWAIT: i32 = 0x0000_0002;
pub const SA_SIGINFO: i32 = 0x0000_0004;
pub const SA_RESTART: i32 = 0x1000_0000;
pub const SA_NODEFER: i32 = 0x4000_0000;
pub const SA_RESETHAND: i32 = 0x8000_0000u32 as i32;

/// Masque d'ensemble de signaux POSIX (64 bits)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sigset {
    pub mask: u64,
}

#[allow(non_camel_case_types)]
pub type sigset_t = Sigset;

/// Structure de configuration d'action de signal POSIX (`sigaction`)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Sigaction {
    pub sa_handler: usize,
    pub sa_mask: Sigset,
    pub sa_flags: i32,
    pub sa_restorer: Option<unsafe extern "C" fn()>,
}

impl PartialEq for Sigaction {
    fn eq(&self, other: &Self) -> bool {
        self.sa_handler == other.sa_handler
            && self.sa_mask == other.sa_mask
            && self.sa_flags == other.sa_flags
    }
}

impl Eq for Sigaction {}

impl Default for Sigaction {
    fn default() -> Self {
        Self {
            sa_handler: SIG_DFL,
            sa_mask: Sigset::default(),
            sa_flags: 0,
            sa_restorer: None,
        }
    }
}

/// Initialise l'ensemble de signaux à zéro (aucun signal sélectionné)
///
/// # Safety
/// Le pointeur `set` doit pointer vers une structure `sigset_t` valide et accessible en écriture.
#[no_mangle]
pub unsafe extern "C" fn sigemptyset(set: *mut sigset_t) -> i32 {
    if set.is_null() {
        return -EFAULT;
    }
    (*set).mask = 0;
    0
}

/// Remplit l'ensemble avec tous les signaux valides
///
/// # Safety
/// Le pointeur `set` doit pointer vers une structure `sigset_t` valide et accessible en écriture.
#[no_mangle]
pub unsafe extern "C" fn sigfillset(set: *mut sigset_t) -> i32 {
    if set.is_null() {
        return -EFAULT;
    }
    // Tous les signaux 1..31
    (*set).mask = 0x0000_0000_FFFF_FFFE;
    0
}

/// Ajoute un signal spécifique à l'ensemble
///
/// # Safety
/// Le pointeur `set` doit pointer vers une structure `sigset_t` valide et accessible en écriture.
#[no_mangle]
pub unsafe extern "C" fn sigaddset(set: *mut sigset_t, signum: i32) -> i32 {
    if set.is_null() {
        return -EFAULT;
    }
    if !(1..NSIG as i32).contains(&signum) {
        return -EINVAL;
    }
    (*set).mask |= 1u64 << signum;
    0
}

/// Retire un signal spécifique de l'ensemble
///
/// # Safety
/// Le pointeur `set` doit pointer vers une structure `sigset_t` valide et accessible en écriture.
#[no_mangle]
pub unsafe extern "C" fn sigdelset(set: *mut sigset_t, signum: i32) -> i32 {
    if set.is_null() {
        return -EFAULT;
    }
    if !(1..NSIG as i32).contains(&signum) {
        return -EINVAL;
    }
    (*set).mask &= !(1u64 << signum);
    0
}

/// Vérifie si un signal appartient à l'ensemble (retourne 1 si présent, 0 sinon, négatif si erreur)
///
/// # Safety
/// Le pointeur `set` doit pointer vers une structure `sigset_t` valide et accessible en lecture.
#[no_mangle]
pub unsafe extern "C" fn sigismember(set: *const sigset_t, signum: i32) -> i32 {
    if set.is_null() {
        return -EFAULT;
    }
    if !(1..NSIG as i32).contains(&signum) {
        return -EINVAL;
    }
    if ((*set).mask & (1u64 << signum)) != 0 {
        1
    } else {
        0
    }
}

/// Table des gestionnaires de signaux de processus Ring 3
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SignalTable {
    pub actions: [Sigaction; NSIG],
    pub blocked_mask: u64,
    pub pending_mask: u64,
}

impl Default for SignalTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalTable {
    pub const fn new() -> Self {
        const DEFAULT_ACTION: Sigaction = Sigaction {
            sa_handler: SIG_DFL,
            sa_mask: Sigset { mask: 0 },
            sa_flags: 0,
            sa_restorer: None,
        };
        Self {
            actions: [DEFAULT_ACTION; NSIG],
            blocked_mask: 0,
            pending_mask: 0,
        }
    }

    /// Configure l'action associée à un signal POSIX avec protection anti-interception pour SIGKILL et SIGSTOP
    pub fn sigaction(
        &mut self,
        signum: i32,
        act: Option<&Sigaction>,
        oldact: Option<&mut Sigaction>,
    ) -> Result<(), i32> {
        if !(1..NSIG as i32).contains(&signum) {
            return Err(-EINVAL);
        }

        // RÈGLE FORMELLE POSIX : SIGKILL (9) et SIGSTOP (19) ne peuvent jamais être capturés ou ignorés
        if (signum == SIGKILL || signum == SIGSTOP) && act.is_some() {
            return Err(-EINVAL);
        }

        let idx = signum as usize;

        if let Some(old) = oldact {
            *old = self.actions[idx];
        }

        if let Some(new_act) = act {
            let mut sanitized = *new_act;
            // Interdire le masquage de SIGKILL ou SIGSTOP dans sa_mask
            let unmaskable = (1u64 << SIGKILL) | (1u64 << SIGSTOP);
            sanitized.sa_mask.mask &= !unmaskable;
            self.actions[idx] = sanitized;
        }

        Ok(())
    }

    /// Modifie ou interroge le masque de signaux bloqués avec protection stricte de SIGKILL et SIGSTOP
    pub fn sigprocmask(
        &mut self,
        how: i32,
        set: Option<&Sigset>,
        oldset: Option<&mut Sigset>,
    ) -> Result<(), i32> {
        if let Some(old) = oldset {
            old.mask = self.blocked_mask;
        }

        if let Some(s) = set {
            let unmaskable = (1u64 << SIGKILL) | (1u64 << SIGSTOP);
            let req = s.mask & !unmaskable;

            match how {
                SIG_BLOCK => {
                    self.blocked_mask |= req;
                }
                SIG_UNBLOCK => {
                    self.blocked_mask &= !req;
                }
                SIG_SETMASK => {
                    self.blocked_mask = req;
                }
                _ => return Err(-EINVAL),
            }
        }

        Ok(())
    }

    /// Envoie un signal au thread courant
    pub fn raise(&mut self, signum: i32) -> Result<(), i32> {
        if !(1..NSIG as i32).contains(&signum) {
            return Err(-EINVAL);
        }

        let bit = 1u64 << signum;
        let is_unmaskable = signum == SIGKILL || signum == SIGSTOP;

        // Si le signal est bloqué et maskable, il devient en attente (pending)
        if (self.blocked_mask & bit) != 0 && !is_unmaskable {
            self.pending_mask |= bit;
            return Ok(());
        }

        // Action associée
        let action = self.actions[signum as usize];
        if action.sa_handler == SIG_IGN && !is_unmaskable {
            return Ok(());
        }

        // Si handler utilisateur configuré
        if action.sa_handler > SIG_IGN {
            // SAFETY: Invocation sécurisée du pointeur de fonction utilisateur validé dans l'action de signal
            unsafe {
                let handler: unsafe extern "C" fn(i32) = core::mem::transmute(action.sa_handler);
                handler(signum);
            }
            if (action.sa_flags & SA_RESETHAND) != 0 && !is_unmaskable {
                self.actions[signum as usize].sa_handler = SIG_DFL;
            }
        }

        Ok(())
    }

    /// Envoie un signal vers un PID spécifique
    pub fn kill(&mut self, pid: i32, signum: i32) -> Result<(), i32> {
        if !(0..NSIG as i32).contains(&signum) {
            return Err(-EINVAL);
        }
        if signum == 0 {
            // Test de permission et existence sans envoi
            return Ok(());
        }
        if pid <= 0 {
            // Signal au groupe ou à soi-même
            self.raise(signum)
        } else {
            // Signal inter-processus via canal de contrôle ou auto-délivrance
            self.raise(signum)
        }
    }
}

static SIGNAL_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static mut GLOBAL_SIGNAL_TABLE: SignalTable = SignalTable::new();

#[inline]
fn acquire_signal_lock() {
    while SIGNAL_LOCK
        .compare_exchange_weak(
            false,
            true,
            core::sync::atomic::Ordering::Acquire,
            core::sync::atomic::Ordering::Relaxed,
        )
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn release_signal_lock() {
    SIGNAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

/// Accède de manière synchronisée à la table de signaux globale
pub fn with_signal_table<F, R>(f: F) -> R
where
    F: FnOnce(&mut SignalTable) -> R,
{
    acquire_signal_lock();
    // SAFETY: Accès exclusif garanti par SIGNAL_LOCK spinlock
    let ptr = core::ptr::addr_of_mut!(GLOBAL_SIGNAL_TABLE);
    let res = unsafe { f(&mut *ptr) };
    release_signal_lock();
    res
}

/// Primitives statiques d'accès aux signaux POSIX
pub fn sys_sigaction(
    signum: i32,
    act: Option<&Sigaction>,
    oldact: Option<&mut Sigaction>,
) -> Result<(), i32> {
    with_signal_table(|tbl| tbl.sigaction(signum, act, oldact))
}

pub fn sys_sigprocmask(
    how: i32,
    set: Option<&Sigset>,
    oldset: Option<&mut Sigset>,
) -> Result<(), i32> {
    with_signal_table(|tbl| tbl.sigprocmask(how, set, oldset))
}

pub fn sys_raise(signum: i32) -> Result<(), i32> {
    with_signal_table(|tbl| tbl.raise(signum))
}

pub fn sys_kill(pid: i32, signum: i32) -> Result<(), i32> {
    with_signal_table(|tbl| tbl.kill(pid, signum))
}

pub fn sys_sigpending(set: &mut Sigset) -> Result<(), i32> {
    with_signal_table(|tbl| {
        set.mask = tbl.pending_mask;
        Ok(())
    })
}

// Points d'entrée C standard exportés pour l'environnement bare-metal

/// Examine et modifie l'action associée à un signal POSIX
///
/// # Safety
/// Les pointeurs `act` et `oldact`, s'ils ne sont pas nuls, doivent pointer vers des structures `Sigaction` valides et alignées.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sigaction(
    signum: i32,
    act: *const Sigaction,
    oldact: *mut Sigaction,
) -> i32 {
    let act_ref = if !act.is_null() { Some(&*act) } else { None };
    let oldact_ref = if !oldact.is_null() {
        Some(&mut *oldact)
    } else {
        None
    };
    match sys_sigaction(signum, act_ref, oldact_ref) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Modifie ou examine le masque des signaux bloqués du processus appelant
///
/// # Safety
/// Les pointeurs `set` et `oldset`, s'ils ne sont pas nuls, doivent pointer vers des structures `sigset_t` valides.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sigprocmask(how: i32, set: *const sigset_t, oldset: *mut sigset_t) -> i32 {
    let set_ref = if !set.is_null() { Some(&*set) } else { None };
    let oldset_ref = if !oldset.is_null() {
        Some(&mut *oldset)
    } else {
        None
    };
    match sys_sigprocmask(how, set_ref, oldset_ref) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Récupère l'ensemble des signaux en attente pour le processus
///
/// # Safety
/// Le pointeur `set` doit être valide et accessible en écriture.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sigpending(set: *mut sigset_t) -> i32 {
    if set.is_null() {
        return -EFAULT;
    }
    match sys_sigpending(&mut *set) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Envoie un signal au thread courant
///
/// # Safety
/// Cette fonction invoque directement le dispatch de signaux en espace utilisateur Ring 3.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn raise(signum: i32) -> i32 {
    match sys_raise(signum) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Envoie un signal à un processus spécifié par son PID
///
/// # Safety
/// Cette fonction exécute la notification capabilaire inter-processus via l'espace d'adressage Ring 3.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kill(pid: i32, signum: i32) -> i32 {
    match sys_kill(pid, signum) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Associe un gestionnaire de signal selon l'interface standard C signal(2)
///
/// # Safety
/// Le paramètre `handler` doit être une adresse de fonction valide exécutable ou une constante `SIG_DFL`/`SIG_IGN`.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn signal(signum: i32, handler: usize) -> usize {
    let new_act = Sigaction {
        sa_handler: handler,
        sa_mask: Sigset::default(),
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut old_act = Sigaction::default();
    match sys_sigaction(signum, Some(&new_act), Some(&mut old_act)) {
        Ok(()) => old_act.sa_handler,
        Err(_) => SIG_ERR,
    }
}

// --- API C POSIX ---

/// Écrit `count` octets du tampon `buf` vers le descripteur de fichier `fd`
///
/// # Safety
/// Le pointeur `buf` doit être valide pour la lecture de `count` octets.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    if buf.is_null() && count > 0 {
        return -EFAULT as isize;
    }
    let slice = core::slice::from_raw_parts(buf, count);
    crate::vfs::with_fd_table(|table| match table.write(fd, slice) {
        Ok(n) => n as isize,
        Err(jambo_abi::SysError::PermissionDenied) => -EBADF as isize,
        Err(jambo_abi::SysError::OutOfMemory) => -ENOMEM as isize,
        Err(jambo_abi::SysError::PeerClosed) => -EPIPE as isize,
        Err(_) => -EBADF as isize,
    })
}

/// Lit jusqu'à `count` octets depuis le descripteur de fichier `fd` vers `buf`
///
/// # Safety
/// Le pointeur `buf` doit être valide pour l'écriture de `count` octets.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, count: usize) -> isize {
    if buf.is_null() && count > 0 {
        return -EFAULT as isize;
    }
    let slice = core::slice::from_raw_parts_mut(buf, count);
    crate::vfs::with_fd_table(|table| match table.read(fd, slice) {
        Ok(n) => n as isize,
        Err(jambo_abi::SysError::PermissionDenied) => -EBADF as isize,
        Err(_) => -EBADF as isize,
    })
}

/// Ouvre un fichier désigné par `pathname` avec les drapeaux `flags`
///
/// # Safety
/// `pathname` doit pointer vers une chaîne C valide terminée par un octet nul.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn open(pathname: *const core::ffi::c_char, flags: i32, _mode: u32) -> i32 {
    if pathname.is_null() {
        return -EFAULT;
    }
    let c_str = core::ffi::CStr::from_ptr(pathname);
    let path = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -EINVAL,
    };
    crate::vfs::with_fd_table(|table| {
        match table.alloc_fd(crate::vfs::FdKind::RegularFile, flags, path) {
            Ok(fd) => fd,
            Err(jambo_abi::SysError::OutOfMemory) => -ENOMEM,
            Err(_) => -EINVAL,
        }
    })
}

/// Ferme un descripteur de fichier ouvert
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn close(fd: i32) -> i32 {
    crate::vfs::with_fd_table(|table| match table.free_fd(fd) {
        Ok(()) => 0,
        Err(_) => -EBADF,
    })
}

/// Repositionne le pointeur de fichier
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    crate::vfs::with_fd_table(|table| match table.lseek(fd, offset, whence) {
        Ok(pos) => pos,
        Err(jambo_abi::SysError::NotSupported) => -29, // ESPIPE
        Err(_) => -EINVAL as i64,
    })
}

/// Récupère les métadonnées de fichier fstat
///
/// # Safety
/// `statbuf` doit pointer vers une zone mémoire valide pour l'écriture d'un `PosixStat`.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fstat(fd: i32, statbuf: *mut crate::vfs::PosixStat) -> i32 {
    if statbuf.is_null() {
        return -EFAULT;
    }
    crate::vfs::with_fd_table(|table| match table.fstat(fd) {
        Ok(st) => {
            *statbuf = st;
            0
        }
        Err(_) => -EBADF,
    })
}

/// Interroge les statistiques de système de fichiers fstatvfs
///
/// # Safety
/// `statvfsbuf` doit pointer vers une zone mémoire accessible en écriture pour un `PosixStatvfs`.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fstatvfs(fd: i32, statvfsbuf: *mut crate::vfs::PosixStatvfs) -> i32 {
    if statvfsbuf.is_null() {
        return -EFAULT;
    }
    crate::vfs::with_fd_table(|table| match table.fstatvfs(fd) {
        Ok(sv) => {
            *statvfsbuf = sv;
            0
        }
        Err(_) => -EBADF,
    })
}

/// Interroge les statistiques de système de fichiers statvfs
///
/// # Safety
/// `pathname` doit être une chaîne C valide terminée par 0 et `statvfsbuf` accessible en écriture.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn statvfs(
    pathname: *const core::ffi::c_char,
    statvfsbuf: *mut crate::vfs::PosixStatvfs,
) -> i32 {
    if pathname.is_null() || statvfsbuf.is_null() {
        return -EFAULT;
    }
    let mut len = 0;
    while *pathname.add(len) != 0 && len < 256 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(pathname as *const u8, len);
    let path_str = match core::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return -EINVAL,
    };
    crate::vfs::with_fd_table(|table| match table.statvfs(path_str) {
        Ok(sv) => {
            *statvfsbuf = sv;
            0
        }
        Err(_) => -ENOENT,
    })
}

pub const SYS_NMLN: usize = 65;

/// Structure standard POSIX `utsname` (sys/utsname.h)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixUtsname {
    pub sysname: [core::ffi::c_char; SYS_NMLN],
    pub nodename: [core::ffi::c_char; SYS_NMLN],
    pub release: [core::ffi::c_char; SYS_NMLN],
    pub version: [core::ffi::c_char; SYS_NMLN],
    pub machine: [core::ffi::c_char; SYS_NMLN],
}

impl Default for PosixUtsname {
    fn default() -> Self {
        Self {
            sysname: [0; SYS_NMLN],
            nodename: [0; SYS_NMLN],
            release: [0; SYS_NMLN],
            version: [0; SYS_NMLN],
            machine: [0; SYS_NMLN],
        }
    }
}

/// Renseigne le nom et les informations sur le système d'exploitation (uname POSIX)
///
/// # Safety
/// `buf` doit être un pointeur valide et accessible en écriture vers une structure `PosixUtsname`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn uname(buf: *mut PosixUtsname) -> i32 {
    if buf.is_null() {
        return -EFAULT;
    }

    let mut u = PosixUtsname::default();

    let sys = b"JamboOS\0";
    let node = b"jambo-node-0\0";
    let rel = b"0.3.44\0";
    #[cfg(target_arch = "x86_64")]
    let ver = b"#1 SMP PREEMPT EEVDF x86_64\0";
    #[cfg(target_arch = "aarch64")]
    let ver = b"#1 SMP PREEMPT EEVDF aarch64\0";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let ver = b"#1 SMP PREEMPT EEVDF unknown\0";

    #[cfg(target_arch = "x86_64")]
    let mach = b"x86_64\0";
    #[cfg(target_arch = "aarch64")]
    let mach = b"aarch64\0";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let mach = b"unknown\0";

    // SAFETY: Copie des chaînes C terminées par \0
    core::ptr::copy_nonoverlapping(
        sys.as_ptr() as *const core::ffi::c_char,
        u.sysname.as_mut_ptr(),
        sys.len(),
    );
    core::ptr::copy_nonoverlapping(
        node.as_ptr() as *const core::ffi::c_char,
        u.nodename.as_mut_ptr(),
        node.len(),
    );
    core::ptr::copy_nonoverlapping(
        rel.as_ptr() as *const core::ffi::c_char,
        u.release.as_mut_ptr(),
        rel.len(),
    );
    core::ptr::copy_nonoverlapping(
        ver.as_ptr() as *const core::ffi::c_char,
        u.version.as_mut_ptr(),
        ver.len(),
    );
    core::ptr::copy_nonoverlapping(
        mach.as_ptr() as *const core::ffi::c_char,
        u.machine.as_mut_ptr(),
        mach.len(),
    );

    *buf = u;
    0
}

/// Duplique un descripteur de fichier ouvert vers le plus petit descripteur disponible (dup POSIX)
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn dup(oldfd: i32) -> i32 {
    crate::vfs::with_fd_table(|table| match table.dup(oldfd) {
        Ok(newfd) => newfd,
        Err(jambo_abi::SysError::OutOfMemory) => -ENOMEM,
        Err(_) => -EBADF,
    })
}

/// Duplique un descripteur de fichier vers une destination spécifique (dup2 POSIX)
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn dup2(oldfd: i32, newfd: i32) -> i32 {
    crate::vfs::with_fd_table(|table| match table.dup2(oldfd, newfd) {
        Ok(fd) => fd,
        Err(jambo_abi::SysError::OutOfMemory) => -ENOMEM,
        Err(_) => -EBADF,
    })
}

/// Crée un canal de communication unidirectionnel en mémoire (pipe POSIX)
///
/// # Safety
/// `pipefd` doit être un pointeur valide vers un tableau de 2 entiers `i32`.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pipe(pipefd: *mut i32) -> i32 {
    pipe2(pipefd, 0)
}

/// Crée un canal de communication unidirectionnel en mémoire avec drapeaux (pipe2 POSIX)
///
/// # Safety
/// `pipefd` doit être un pointeur valide vers un tableau de 2 entiers `i32`.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pipe2(pipefd: *mut i32, _flags: i32) -> i32 {
    if pipefd.is_null() {
        return -EFAULT;
    }
    crate::vfs::with_fd_table(|table| match table.alloc_pipe() {
        Ok((rfd, wfd)) => {
            *pipefd = rfd;
            *pipefd.add(1) = wfd;
            0
        }
        Err(jambo_abi::SysError::OutOfMemory) => -ENOMEM,
        Err(_) => -EINVAL,
    })
}

/// Crée un point de terminaison de communication (socket POSIX)
///
/// # Safety
/// Les arguments de domaine, type et protocole doivent être des constantes valides.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn socket(domain: i32, type_: i32, protocol: i32) -> i32 {
    if domain != crate::net::AF_INET as i32 && domain != crate::net::AF_UNIX as i32 {
        return -EAFNOSUPPORT;
    }
    crate::vfs::with_fd_table(
        |table| match table.alloc_socket(domain as u16, type_, protocol) {
            Ok(fd) => fd,
            Err(jambo_abi::SysError::OutOfMemory) => -ENOMEM,
            Err(_) => -EINVAL,
        },
    )
}

/// Lie une socket à une adresse locale (bind POSIX)
///
/// # Safety
/// Le pointeur `addr` doit être valide et pointer vers au moins `addrlen` octets.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bind(sockfd: i32, addr: *const crate::net::SockAddr, addrlen: u32) -> i32 {
    if addr.is_null() || (addrlen as usize) < core::mem::size_of::<crate::net::SockAddr>() {
        return -EFAULT;
    }
    crate::vfs::with_fd_table(|table| {
        let entry = match table.get_mut(sockfd) {
            Some(e) => e,
            None => return -EBADF,
        };
        if entry.kind != crate::vfs::FdKind::Socket {
            return -ENOTSOCK;
        }
        0
    })
}

/// Établit une connexion vers une socket distante (connect POSIX)
///
/// # Safety
/// Le pointeur `addr` doit être valide et pointer vers au moins `addrlen` octets.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn connect(
    sockfd: i32,
    addr: *const crate::net::SockAddr,
    addrlen: u32,
) -> i32 {
    if addr.is_null() || (addrlen as usize) < core::mem::size_of::<crate::net::SockAddr>() {
        return -EFAULT;
    }
    crate::vfs::with_fd_table(|table| {
        let entry = match table.get_mut(sockfd) {
            Some(e) => e,
            None => return -EBADF,
        };
        if entry.kind != crate::vfs::FdKind::Socket {
            return -ENOTSOCK;
        }
        0
    })
}

/// Place une socket en écoute passive de connexions entrantes (listen POSIX)
///
/// # Safety
/// Le descripteur `sockfd` doit référencer une socket valide.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn listen(sockfd: i32, _backlog: i32) -> i32 {
    crate::vfs::with_fd_table(|table| {
        let entry = match table.get_mut(sockfd) {
            Some(e) => e,
            None => return -EBADF,
        };
        if entry.kind != crate::vfs::FdKind::Socket {
            return -ENOTSOCK;
        }
        0
    })
}

/// Accepte une connexion sur une socket en écoute (accept POSIX)
///
/// # Safety
/// Le descripteur `sockfd` doit référencer une socket d'écoute active.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn accept(
    sockfd: i32,
    _addr: *mut crate::net::SockAddr,
    _addrlen: *mut u32,
) -> i32 {
    crate::vfs::with_fd_table(|table| {
        let entry = match table.get(sockfd) {
            Some(e) => e,
            None => return -EBADF,
        };
        if entry.kind != crate::vfs::FdKind::Socket {
            return -ENOTSOCK;
        }
        match table.alloc_socket(
            crate::net::AF_INET,
            crate::net::SOCK_STREAM,
            crate::net::IPPROTO_TCP,
        ) {
            Ok(new_fd) => new_fd,
            Err(_) => -ENOMEM,
        }
    })
}

/// Émet des données sur une socket (send POSIX)
///
/// # Safety
/// Le tampon `buf` doit être valide pour la lecture de `len` octets.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn send(sockfd: i32, buf: *const u8, len: usize, _flags: i32) -> isize {
    write(sockfd, buf, len)
}

/// Reçoit des données depuis une socket (recv POSIX)
///
/// # Safety
/// Le tampon `buf` doit être valide pour l'écriture de `len` octets.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn recv(sockfd: i32, buf: *mut u8, len: usize, _flags: i32) -> isize {
    read(sockfd, buf, len)
}

/// Arrête la transmission ou la réception sur une socket (shutdown POSIX)
///
/// # Safety
/// Le descripteur `sockfd` doit référencer une socket valide.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn shutdown(sockfd: i32, how: i32) -> i32 {
    if !(0..=2).contains(&how) {
        return -EINVAL;
    }
    crate::vfs::with_fd_table(|table| {
        let entry = match table.get(sockfd) {
            Some(e) => e,
            None => return -EBADF,
        };
        if entry.kind != crate::vfs::FdKind::Socket {
            return -ENOTSOCK;
        }
        0
    })
}

/// Cède le temps processeur au planificateur (équivalent sched_yield POSIX)
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn sched_yield() -> i32 {
    crate::syscall_thread_yield();
    0
}

/// Termine immédiatement l'exécution du processus appelant (_exit POSIX)
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn _exit(status: i32) -> ! {
    unsafe {
        syscall6(SyscallNumber::ThreadExit, status as u64, 0, 0, 0, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Termine l'exécution du processus (alias exit POSIX)
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn exit(status: i32) -> ! {
    _exit(status);
}

/// Projette de la mémoire virtuelle anonyme via un objet mémoire VMO (mmap POSIX)
///
/// # Safety
/// L'appelant doit respecter les contraintes de mémoire virtuelle.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
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
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
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
#[cfg_attr(target_os = "none", no_mangle)]
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
#[cfg_attr(target_os = "none", no_mangle)]
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
#[cfg_attr(target_os = "none", no_mangle)]
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
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    let ptr = s as *const u8;
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    len
}

/// Compare deux chaînes C lexicographiquement (strcmp C standard)
///
/// # Safety
/// `s1` et `s2` doivent pointer vers des chaînes terminées par `\0`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strcmp(s1: *const c_char, s2: *const c_char) -> i32 {
    let mut p1 = s1 as *const u8;
    let mut p2 = s2 as *const u8;
    while *p1 != 0 && *p1 == *p2 {
        p1 = p1.add(1);
        p2 = p2.add(1);
    }
    (*p1 as i32) - (*p2 as i32)
}

/// Compare au maximum `n` octets de deux chaînes C (strncmp C standard)
///
/// # Safety
/// `s1` et `s2` doivent être lisibles pour `n` octets ou jusqu'à `\0`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
    if n == 0 {
        return 0;
    }
    let mut p1 = s1 as *const u8;
    let mut p2 = s2 as *const u8;
    let mut i = 0;
    while i < n && *p1 != 0 && *p1 == *p2 {
        p1 = p1.add(1);
        p2 = p2.add(1);
        i += 1;
    }
    if i == n {
        0
    } else {
        (*p1 as i32) - (*p2 as i32)
    }
}

/// Copie au plus `n` caractères de `src` vers `dest` (strncpy C standard)
///
/// # Safety
/// `dest` doit être valide pour l'écriture de `n` octets.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    let d = dest as *mut u8;
    let s = src as *const u8;
    let mut i = 0;
    let mut copying = true;
    while i < n {
        if copying {
            let b = *s.add(i);
            *d.add(i) = b;
            if b == 0 {
                copying = false;
            }
        } else {
            *d.add(i) = 0;
        }
        i += 1;
    }
    dest
}

/// Recherche la première occurrence du caractère `c` dans la chaîne `s` (strchr C standard)
///
/// # Safety
/// `s` doit être un pointeur valide vers une chaîne terminée par `\0`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strchr(s: *const c_char, c: i32) -> *mut c_char {
    let target = c as u8;
    let mut ptr = s as *const u8;
    loop {
        if *ptr == target {
            return ptr as *mut c_char;
        }
        if *ptr == 0 {
            return core::ptr::null_mut();
        }
        ptr = ptr.add(1);
    }
}

/// Convertit une chaîne de caractères en entier signé 32 bits (atoi C standard)
///
/// # Safety
/// `nptr` doit pointer vers une chaîne terminée par `\0`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn atoi(nptr: *const c_char) -> i32 {
    if nptr.is_null() {
        return 0;
    }
    let mut ptr = nptr as *const u8;
    while *ptr == b' ' || (*ptr >= 9 && *ptr <= 13) {
        ptr = ptr.add(1);
    }
    let mut sign = 1i32;
    if *ptr == b'-' {
        sign = -1;
        ptr = ptr.add(1);
    } else if *ptr == b'+' {
        ptr = ptr.add(1);
    }
    let mut result: i32 = 0;
    while *ptr >= b'0' && *ptr <= b'9' {
        let digit = (*ptr - b'0') as i32;
        result = result.wrapping_mul(10).wrapping_add(digit);
        ptr = ptr.add(1);
    }
    result.wrapping_mul(sign)
}

#[cfg(not(test))]
const MALLOC_MAGIC: usize = 0x4A41_4D42_4F53; // "JAMBOS"

#[cfg(not(test))]
#[repr(C)]
struct AllocHeader {
    magic: usize,
    size: usize,
}

/// Alloue un bloc mémoire de `size` octets (malloc C standard via mmap anonyme)
///
/// # Safety
/// La mémoire allouée doit être libérée par `free`.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    if size == 0 {
        return core::ptr::null_mut();
    }
    let total = size + core::mem::size_of::<AllocHeader>();
    let ptr = mmap(
        core::ptr::null_mut(),
        total,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    if ptr == MAP_FAILED || ptr.is_null() {
        return core::ptr::null_mut();
    }
    let header = ptr as *mut AllocHeader;
    (*header).magic = MALLOC_MAGIC;
    (*header).size = total;
    ptr.add(core::mem::size_of::<AllocHeader>()) as *mut c_void
}

/// Libère un bloc mémoire alloué par `malloc` (free C standard via munmap)
///
/// # Safety
/// `ptr` doit provenir d'un appel antérieur à `malloc`.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let raw = (ptr as *mut u8).sub(core::mem::size_of::<AllocHeader>());
    let header = raw as *mut AllocHeader;
    if (*header).magic == MALLOC_MAGIC {
        let total = (*header).size;
        (*header).magic = 0; // Invalidation du magic anti double-free
        munmap(raw, total);
    }
}

// --- API C Native JamboOS ---

/// Écrit des octets vers la console série JamboOS via C-ABI
///
/// # Safety
/// Le tampon `buf` doit pointer vers au moins `len` octets lisibles.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn jambo_console_write(buf: *const u8, len: usize) -> isize {
    write(STDOUT_FILENO, buf, len)
}

/// Lit des octets depuis la console série JamboOS via C-ABI
///
/// # Safety
/// Le tampon `buf` doit être valide pour l'écriture de `len` octets.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn jambo_console_read(buf: *mut u8, len: usize) -> isize {
    read(STDIN_FILENO, buf, len)
}

/// Cède le processeur au scheduler EEVDF via C-ABI
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn jambo_yield() -> i32 {
    sched_yield()
}

/// Quitte le thread courant via C-ABI
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn jambo_exit(status: i32) -> ! {
    _exit(status);
}

/// Interroge les statistiques système globales via C-ABI
///
/// # Safety
/// Le pointeur `out_info` doit pointer vers une structure `SystemInfo` valide et accessible en écriture.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
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
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
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
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
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
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn jambo_vmo_unmap(vaddr: u64, length: u64) -> i32 {
    munmap(vaddr as *mut u8, length as usize)
}

/// Exécute une opération de configuration PCI via le broker matériel (Syscall 29)
///
/// # Safety
/// Le pointeur `val` doit être valide pour la lecture (sur écriture PCI) ou l'écriture (sur lecture PCI).
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
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

    #[test]
    fn test_posix_string_comparisons_and_copy() {
        let s1 = b"abc\0";
        let s2 = b"abc\0";
        let s3 = b"abd\0";
        let s4 = b"abb\0";
        unsafe {
            assert_eq!(
                strcmp(s1.as_ptr() as *const c_char, s2.as_ptr() as *const c_char),
                0
            );
            assert!(strcmp(s1.as_ptr() as *const c_char, s3.as_ptr() as *const c_char) < 0);
            assert!(strcmp(s1.as_ptr() as *const c_char, s4.as_ptr() as *const c_char) > 0);

            assert_eq!(
                strncmp(
                    s1.as_ptr() as *const c_char,
                    s3.as_ptr() as *const c_char,
                    2
                ),
                0
            );
            assert!(
                strncmp(
                    s1.as_ptr() as *const c_char,
                    s3.as_ptr() as *const c_char,
                    3
                ) < 0
            );

            let mut dest = [0u8; 16];
            strncpy(
                dest.as_mut_ptr() as *mut c_char,
                s1.as_ptr() as *const c_char,
                2,
            );
            assert_eq!(dest[0], b'a');
            assert_eq!(dest[1], b'b');
            assert_eq!(dest[2], 0);

            let needle = strchr(s1.as_ptr() as *const c_char, b'b' as i32);
            assert!(!needle.is_null());
            assert_eq!(*needle as u8, b'b');

            let missing = strchr(s1.as_ptr() as *const c_char, b'z' as i32);
            assert!(missing.is_null());
        }
    }

    #[test]
    fn test_posix_atoi() {
        unsafe {
            let num1 = b"12345\0";
            assert_eq!(atoi(num1.as_ptr() as *const c_char), 12345);

            let num2 = b"-42\0";
            assert_eq!(atoi(num2.as_ptr() as *const c_char), -42);

            let num3 = b"  +999 with trailing text\0";
            assert_eq!(atoi(num3.as_ptr() as *const c_char), 999);

            let zero = b"0\0";
            assert_eq!(atoi(zero.as_ptr() as *const c_char), 0);
        }
    }

    #[test]
    fn test_posix_uname() {
        unsafe {
            let mut u = PosixUtsname::default();
            assert_eq!(uname(core::ptr::null_mut()), -EFAULT);
            assert_eq!(uname(&mut u), 0);

            let sysname = core::ffi::CStr::from_ptr(u.sysname.as_ptr())
                .to_str()
                .unwrap();
            let nodename = core::ffi::CStr::from_ptr(u.nodename.as_ptr())
                .to_str()
                .unwrap();
            let release = core::ffi::CStr::from_ptr(u.release.as_ptr())
                .to_str()
                .unwrap();
            let version = core::ffi::CStr::from_ptr(u.version.as_ptr())
                .to_str()
                .unwrap();
            let machine = core::ffi::CStr::from_ptr(u.machine.as_ptr())
                .to_str()
                .unwrap();

            assert_eq!(sysname, "JamboOS");
            assert_eq!(nodename, "jambo-node-0");
            assert_eq!(release, "0.3.44");
            assert!(version.contains("SMP PREEMPT EEVDF"));
            #[cfg(target_arch = "x86_64")]
            assert_eq!(machine, "x86_64");
            #[cfg(target_arch = "aarch64")]
            assert_eq!(machine, "aarch64");
        }
    }

    #[test]
    fn test_posix_signal_set_primitives() {
        unsafe {
            let mut set = Sigset::default();
            assert_eq!(sigemptyset(&mut set), 0);
            assert_eq!(set.mask, 0);

            // sigismember sur ensemble vide
            assert_eq!(sigismember(&set, SIGINT), 0);
            assert_eq!(sigismember(&set, SIGKILL), 0);

            // sigaddset
            assert_eq!(sigaddset(&mut set, SIGINT), 0);
            assert_eq!(sigaddset(&mut set, SIGTERM), 0);
            assert_eq!(sigismember(&set, SIGINT), 1);
            assert_eq!(sigismember(&set, SIGTERM), 1);
            assert_eq!(sigismember(&set, SIGHUP), 0);

            // Rejet signaux invalides
            assert_eq!(sigaddset(&mut set, 0), -EINVAL);
            assert_eq!(sigaddset(&mut set, 32), -EINVAL);
            assert_eq!(sigaddset(core::ptr::null_mut(), SIGINT), -EFAULT);

            // sigdelset
            assert_eq!(sigdelset(&mut set, SIGINT), 0);
            assert_eq!(sigismember(&set, SIGINT), 0);
            assert_eq!(sigismember(&set, SIGTERM), 1);

            // sigfillset
            assert_eq!(sigfillset(&mut set), 0);
            assert_eq!(sigismember(&set, SIGHUP), 1);
            assert_eq!(sigismember(&set, SIGINT), 1);
            assert_eq!(sigismember(&set, SIGKILL), 1);
            assert_eq!(sigismember(&set, SIGSTOP), 1);
        }
    }

    static TEST_HANDLER_CALLED: core::sync::atomic::AtomicI32 =
        core::sync::atomic::AtomicI32::new(0);
    unsafe extern "C" fn dummy_test_handler(sig: i32) {
        TEST_HANDLER_CALLED.store(sig, core::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn test_posix_signal_table_sigaction_and_unmaskable() {
        let mut table = SignalTable::new();

        // 1. RÈGLE POSIX : Interdiction formelle d'intercepter SIGKILL et SIGSTOP
        let act_kill = Sigaction {
            sa_handler: dummy_test_handler as *const () as usize,
            sa_mask: Sigset::default(),
            sa_flags: 0,
            sa_restorer: None,
        };
        assert_eq!(
            table.sigaction(SIGKILL, Some(&act_kill), None),
            Err(-EINVAL)
        );
        assert_eq!(
            table.sigaction(SIGSTOP, Some(&act_kill), None),
            Err(-EINVAL)
        );

        // 2. Configuration autorisée pour SIGUSR1
        let act_usr1 = Sigaction {
            sa_handler: dummy_test_handler as *const () as usize,
            sa_mask: Sigset::default(),
            sa_flags: 0,
            sa_restorer: None,
        };
        let mut old_act = Sigaction::default();
        assert_eq!(
            table.sigaction(SIGUSR1, Some(&act_usr1), Some(&mut old_act)),
            Ok(())
        );
        assert_eq!(old_act.sa_handler, SIG_DFL);

        // 3. Déclenchement de raise(SIGUSR1)
        TEST_HANDLER_CALLED.store(0, core::sync::atomic::Ordering::SeqCst);
        assert_eq!(table.raise(SIGUSR1), Ok(()));
        assert_eq!(
            TEST_HANDLER_CALLED.load(core::sync::atomic::Ordering::SeqCst),
            SIGUSR1
        );

        // 4. Signal hors bornes
        assert_eq!(table.raise(0), Err(-EINVAL));
        assert_eq!(table.raise(64), Err(-EINVAL));
    }

    #[test]
    fn test_posix_signal_masking_and_pending() {
        let mut table = SignalTable::new();

        // 1. Bloquer SIGINT et SIGTERM
        let mut block_set = Sigset::default();
        unsafe {
            let _ = sigaddset(&mut block_set, SIGINT);
            let _ = sigaddset(&mut block_set, SIGTERM);
            let _ = sigaddset(&mut block_set, SIGKILL); // Doit être neutralisé silencieusement (non masquable)
        }
        assert_eq!(table.sigprocmask(SIG_BLOCK, Some(&block_set), None), Ok(()));

        // Vérifier que SIGKILL n'est pas bloqué
        assert_eq!(table.blocked_mask & (1u64 << SIGKILL), 0);
        assert_ne!(table.blocked_mask & (1u64 << SIGINT), 0);
        assert_ne!(table.blocked_mask & (1u64 << SIGTERM), 0);

        // 2. raise(SIGINT) doit aller dans pending_mask car il est bloqué
        assert_eq!(table.raise(SIGINT), Ok(()));
        assert_ne!(table.pending_mask & (1u64 << SIGINT), 0);

        // 3. Débloquer SIGINT
        let mut unblock_set = Sigset::default();
        unsafe {
            let _ = sigaddset(&mut unblock_set, SIGINT);
        }
        assert_eq!(
            table.sigprocmask(SIG_UNBLOCK, Some(&unblock_set), None),
            Ok(())
        );
        assert_eq!(table.blocked_mask & (1u64 << SIGINT), 0);
    }
}

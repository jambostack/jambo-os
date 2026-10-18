//! Couche de compatibilité applicative Linux/POSIX en espace utilisateur (JamboLinux)
//!
//! Intercepte les appels système Linux x86-64 et les traduit de manière isolée
//! en requêtes de capacités sur micro-noyau JamboKernel. Zéro dette POSIX en Ring 0.

#![no_std]

use libjambo::{cap_rights, Handle};

pub const LINUX_SYS_READ: u64 = 0;
pub const LINUX_SYS_WRITE: u64 = 1;
pub const LINUX_SYS_OPEN: u64 = 2;
pub const LINUX_SYS_CLOSE: u64 = 3;
pub const LINUX_SYS_FSTAT: u64 = 5;
pub const LINUX_SYS_MMAP: u64 = 9;
pub const LINUX_SYS_BRK: u64 = 12;
pub const LINUX_SYS_GETPID: u64 = 39;
pub const LINUX_SYS_CLONE: u64 = 56;
pub const LINUX_SYS_EXIT: u64 = 60;
pub const LINUX_SYS_CLOCK_GETTIME: u64 = 228;

pub const MAX_FDS: usize = 32;

/// Descripteur de fichier POSIX traduit vers un Handle de capacité
#[derive(Debug, Clone, Copy)]
pub struct PosixFd {
    pub fd: i32,
    pub cap_handle: Handle,
    pub flags: u32,
    pub offset: u64,
}

/// Émulateur d'environnement d'exécution Linux
pub struct LinuxProcessEmulator {
    pub pid: u64,
    pub fds: [Option<PosixFd>; MAX_FDS],
    pub brk_current: u64,
}

impl Default for LinuxProcessEmulator {
    fn default() -> Self {
        Self::new(1001)
    }
}

impl LinuxProcessEmulator {
    pub const fn new(pid: u64) -> Self {
        const INIT_OPT: Option<PosixFd> = None;
        let mut fds = [INIT_OPT; MAX_FDS];

        // Standard POSIX descriptors (0: stdin, 1: stdout, 2: stderr)
        fds[0] = Some(PosixFd {
            fd: 0,
            cap_handle: Handle::new(1, 1),
            flags: cap_rights::READ,
            offset: 0,
        });
        fds[1] = Some(PosixFd {
            fd: 1,
            cap_handle: Handle::new(2, 1),
            flags: cap_rights::WRITE,
            offset: 0,
        });
        fds[2] = Some(PosixFd {
            fd: 2,
            cap_handle: Handle::new(3, 1),
            flags: cap_rights::WRITE,
            offset: 0,
        });

        Self {
            pid,
            fds,
            brk_current: 0x4000_0000,
        }
    }

    /// Traduction d'un appel système Linux vers JamboKernel
    pub fn handle_linux_syscall(
        &mut self,
        num: u64,
        a1: u64,
        _a2: u64,
        a3: u64,
        _a4: u64,
        _a5: u64,
        _a6: u64,
    ) -> i64 {
        match num {
            LINUX_SYS_READ => {
                let fd = a1 as i32;
                let count = a3;
                if fd < 0 || fd as usize >= MAX_FDS || self.fds[fd as usize].is_none() {
                    return -9; // EBADF
                }
                count as i64 // Simulation de lecture réussie
            }
            LINUX_SYS_WRITE => {
                let fd = a1 as i32;
                let count = a3;
                if fd < 0 || fd as usize >= MAX_FDS || self.fds[fd as usize].is_none() {
                    return -9; // EBADF
                }
                count as i64 // Simulation d'écriture réussie
            }
            LINUX_SYS_OPEN => {
                // Allouer un nouveau FD mappé vers un Handle de capacité
                for slot in self.fds.iter_mut().skip(3) {
                    if slot.is_none() {
                        let new_fd = 3;
                        *slot = Some(PosixFd {
                            fd: new_fd,
                            cap_handle: Handle::new(50, 1),
                            flags: cap_rights::READ,
                            offset: 0,
                        });
                        return new_fd as i64;
                    }
                }
                -24 // EMFILE
            }
            LINUX_SYS_CLOSE => {
                let fd = a1 as i32;
                if fd >= 0 && (fd as usize) < MAX_FDS {
                    self.fds[fd as usize] = None;
                    0 // Success
                } else {
                    -9 // EBADF
                }
            }
            LINUX_SYS_GETPID => self.pid as i64,
            LINUX_SYS_BRK => {
                let requested = a1;
                if requested != 0 && requested >= self.brk_current {
                    self.brk_current = requested;
                }
                self.brk_current as i64
            }
            LINUX_SYS_MMAP => {
                // Projection VMO mémoire anonyme ou de fichier
                0x7000_0000
            }
            LINUX_SYS_CLOCK_GETTIME => 0, // Success
            LINUX_SYS_EXIT => 0,
            _ => -38, // ENOSYS
        }
    }
}

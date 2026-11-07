//! Sous-système Virtual File System (VFS) & Descripteurs de Fichiers (`libjambo::vfs`)
//!
//! Fournit une gestion de descripteurs de fichiers (`fd_table`) privée par processus
//! et conforme aux spécifications POSIX.1-2008 en environnement `#![no_std]` :
//! 1. Constantes POSIX standard d'accès aux fichiers (`O_*`, `SEEK_*`, `S_IF*`).
//! 2. Table de descripteurs `FdTable` statique à capacité bornée (`MAX_FDS = 32`).
//! 3. Entrées réservées `0` (stdin), `1` (stdout), `2` (stderr).
//! 4. Descripteurs dynamiques `>= 3` pour fichiers réguliers et canaux IPC.
//! 5. Primitives d'accès et métadonnées `PosixStat` (`fstat`, `stat`).

use core::sync::atomic::{AtomicBool, Ordering};
use jambo_abi::SysError;

// ============================================================================
// CONSTANTES POSIX STANDARD
// ============================================================================

pub const MAX_FDS: usize = 32;
pub const MAX_PATH_LEN: usize = 64;
pub const FILE_BUFFER_SIZE: usize = 1024; // Tampon embarqué par descripteur

// Drapeaux d'ouverture de fichier (flags)
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_ACCMODE: i32 = 3;
pub const O_CREAT: i32 = 0o100;
pub const O_EXCL: i32 = 0o200;
pub const O_TRUNC: i32 = 0o1000;
pub const O_APPEND: i32 = 0o2000;

// Constantes de repositionnement lseek (whence)
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

// Modes et types de fichiers (stat st_mode)
pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000; // Fichier régulier
pub const S_IFDIR: u32 = 0o040000; // Répertoire
pub const S_IFCHR: u32 = 0o020000; // Périphérique caractère (console)
pub const S_IFIFO: u32 = 0o010000; // Pipe FIFO

// ============================================================================
// STRUCTURES DE DONNÉES DU VFS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    Closed,
    ConsoleIn,
    ConsoleOut,
    RegularFile,
    IpcChannel,
}

#[derive(Clone, Copy)]
pub struct FdEntry {
    pub kind: FdKind,
    pub flags: i32,
    pub offset: u64,
    pub size: u64,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: usize,
    pub buffer: [u8; FILE_BUFFER_SIZE],
}

impl FdEntry {
    pub const fn empty() -> Self {
        Self {
            kind: FdKind::Closed,
            flags: 0,
            offset: 0,
            size: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            buffer: [0u8; FILE_BUFFER_SIZE],
        }
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

/// Structure de métadonnées de fichier conforme POSIX `struct stat`
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PosixStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_mtime: i64,
    pub st_ctime: i64,
}

// ============================================================================
// TABLE DE DESCRIPTEURS DE FICHIERS (FdTable)
// ============================================================================

pub struct FdTable {
    pub entries: [FdEntry; MAX_FDS],
}

impl FdTable {
    pub const fn new() -> Self {
        let mut entries = [FdEntry::empty(); MAX_FDS];

        // 0: STDIN (ConsoleIn)
        entries[0].kind = FdKind::ConsoleIn;
        entries[0].flags = O_RDONLY;

        // 1: STDOUT (ConsoleOut)
        entries[1].kind = FdKind::ConsoleOut;
        entries[1].flags = O_WRONLY;

        // 2: STDERR (ConsoleOut)
        entries[2].kind = FdKind::ConsoleOut;
        entries[2].flags = O_WRONLY;

        Self { entries }
    }

    /// Alloue le plus petit descripteur de fichier disponible (fd >= 3)
    pub fn alloc_fd(&mut self, kind: FdKind, flags: i32, path: &str) -> Result<i32, SysError> {
        for (fd, entry) in self.entries.iter_mut().enumerate().skip(3) {
            if entry.kind == FdKind::Closed {
                let mut path_buf = [0u8; MAX_PATH_LEN];
                let path_bytes = path.as_bytes();
                let len = path_bytes.len().min(MAX_PATH_LEN);
                path_buf[..len].copy_from_slice(&path_bytes[..len]);

                *entry = FdEntry {
                    kind,
                    flags,
                    offset: 0,
                    size: 0,
                    path: path_buf,
                    path_len: len,
                    buffer: [0u8; FILE_BUFFER_SIZE],
                };
                return Ok(fd as i32);
            }
        }
        Err(SysError::OutOfMemory) // EMFILE : Table des descripteurs saturée
    }

    /// Libère un descripteur de fichier existant
    pub fn free_fd(&mut self, fd: i32) -> Result<(), SysError> {
        if fd < 0 || fd as usize >= MAX_FDS {
            return Err(SysError::InvalidArgument); // EBADF
        }
        let ufd = fd as usize;
        if self.entries[ufd].kind == FdKind::Closed {
            return Err(SysError::InvalidArgument); // EBADF
        }
        self.entries[ufd] = FdEntry::empty();
        Ok(())
    }

    /// Récupère une référence vers l'entrée de descripteur
    pub fn get(&self, fd: i32) -> Option<&FdEntry> {
        if fd >= 0 && (fd as usize) < MAX_FDS {
            let entry = &self.entries[fd as usize];
            if entry.kind != FdKind::Closed {
                return Some(entry);
            }
        }
        None
    }

    /// Récupère une référence mutable vers l'entrée de descripteur
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut FdEntry> {
        if fd >= 0 && (fd as usize) < MAX_FDS {
            let entry = &mut self.entries[fd as usize];
            if entry.kind != FdKind::Closed {
                return Some(entry);
            }
        }
        None
    }

    /// Compte le nombre de descripteurs actifs
    pub fn count_open(&self) -> usize {
        let mut count = 0;
        for entry in &self.entries {
            if entry.kind != FdKind::Closed {
                count += 1;
            }
        }
        count
    }

    /// Repositionne le pointeur de fichier (équivalent lseek)
    pub fn lseek(&mut self, fd: i32, offset: i64, whence: i32) -> Result<i64, SysError> {
        let entry = self.get_mut(fd).ok_or(SysError::InvalidArgument)?;

        if matches!(entry.kind, FdKind::ConsoleIn | FdKind::ConsoleOut) {
            return Err(SysError::NotSupported); // ESPIPE : Impossible de se déplacer sur un périphérique caractère
        }

        let new_offset = match whence {
            SEEK_SET => offset,
            SEEK_CUR => (entry.offset as i64).wrapping_add(offset),
            SEEK_END => (entry.size as i64).wrapping_add(offset),
            _ => return Err(SysError::InvalidArgument),
        };

        if new_offset < 0 {
            return Err(SysError::InvalidArgument); // EINVAL
        }

        entry.offset = new_offset as u64;
        Ok(new_offset)
    }

    /// Lit des données depuis le descripteur de fichier
    pub fn read(&mut self, fd: i32, buf: &mut [u8]) -> Result<usize, SysError> {
        let entry = self.get_mut(fd).ok_or(SysError::InvalidArgument)?;

        // Vérification des droits d'accès
        if (entry.flags & O_ACCMODE) == O_WRONLY {
            return Err(SysError::PermissionDenied); // EBADF : Ouvert en écriture seule
        }

        match entry.kind {
            FdKind::ConsoleIn => {
                #[cfg(not(test))]
                {
                    crate::console_read(buf)
                }
                #[cfg(test)]
                {
                    Ok(0)
                }
            }
            FdKind::RegularFile => {
                if entry.offset >= entry.size {
                    return Ok(0); // EOF
                }
                let available = (entry.size - entry.offset) as usize;
                let to_read = buf.len().min(available);
                let start = entry.offset as usize;
                buf[..to_read].copy_from_slice(&entry.buffer[start..start + to_read]);
                entry.offset += to_read as u64;
                Ok(to_read)
            }
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Écrit des données vers le descripteur de fichier
    pub fn write(&mut self, fd: i32, buf: &[u8]) -> Result<usize, SysError> {
        let entry = self.get_mut(fd).ok_or(SysError::InvalidArgument)?;

        // Vérification des droits d'accès
        if (entry.flags & O_ACCMODE) == O_RDONLY {
            return Err(SysError::PermissionDenied); // EBADF : Ouvert en lecture seule
        }

        match entry.kind {
            FdKind::ConsoleOut => {
                #[cfg(not(test))]
                {
                    crate::console_write(buf)
                }
                #[cfg(test)]
                {
                    Ok(buf.len())
                }
            }
            FdKind::RegularFile => {
                // Si O_APPEND est positionné, toujours écrire à la fin du fichier
                if (entry.flags & O_APPEND) != 0 {
                    entry.offset = entry.size;
                }

                let start = entry.offset as usize;
                if start >= FILE_BUFFER_SIZE {
                    return Err(SysError::OutOfMemory); // ENOSPC
                }
                let space_left = FILE_BUFFER_SIZE - start;
                let to_write = buf.len().min(space_left);

                entry.buffer[start..start + to_write].copy_from_slice(&buf[..to_write]);
                entry.offset += to_write as u64;
                if entry.offset > entry.size {
                    entry.size = entry.offset;
                }
                Ok(to_write)
            }
            _ => Err(SysError::InvalidArgument),
        }
    }

    /// Récupère les métadonnées de fichier fstat
    pub fn fstat(&self, fd: i32) -> Result<PosixStat, SysError> {
        let entry = self.get(fd).ok_or(SysError::InvalidArgument)?;
        let mut st = PosixStat::default();

        match entry.kind {
            FdKind::ConsoleIn | FdKind::ConsoleOut => {
                st.st_mode = S_IFCHR | 0o666;
                st.st_nlink = 1;
                st.st_size = 0;
            }
            FdKind::RegularFile => {
                st.st_mode = S_IFREG | 0o644;
                st.st_nlink = 1;
                st.st_size = entry.size as i64;
                st.st_blksize = 512;
                st.st_blocks = entry.size.div_ceil(512) as i64;
            }
            _ => return Err(SysError::InvalidArgument),
        }
        Ok(st)
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// VERROU ATOMIQUE ET INSTANCE GLOBALE VFS DU PROCESSUS
// ============================================================================

static VFS_LOCK: AtomicBool = AtomicBool::new(false);
static mut GLOBAL_FD_TABLE: FdTable = FdTable::new();

#[inline]
fn acquire_vfs_lock() {
    while VFS_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn release_vfs_lock() {
    VFS_LOCK.store(false, Ordering::Release);
}

/// Exécute une opération avec accès exclusif à la table `FdTable`
pub fn with_fd_table<F, R>(f: F) -> R
where
    F: FnOnce(&mut FdTable) -> R,
{
    acquire_vfs_lock();
    // SAFETY: Protégé par le spinlock VFS_LOCK garantissant l'accès exclusif à GLOBAL_FD_TABLE.
    let ptr = core::ptr::addr_of_mut!(GLOBAL_FD_TABLE);
    let res = unsafe { f(&mut *ptr) };
    release_vfs_lock();
    res
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vfs_initial_descriptors() {
        let table = FdTable::new();
        assert_eq!(table.count_open(), 3);

        let stdin = table.get(0).expect("stdin doit être alloué");
        assert_eq!(stdin.kind, FdKind::ConsoleIn);

        let stdout = table.get(1).expect("stdout doit être alloué");
        assert_eq!(stdout.kind, FdKind::ConsoleOut);

        let stderr = table.get(2).expect("stderr doit être alloué");
        assert_eq!(stderr.kind, FdKind::ConsoleOut);

        assert!(table.get(3).is_none());
    }

    #[test]
    fn test_vfs_open_close_reuse() {
        let mut table = FdTable::new();

        let fd1 = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/etc/config")
            .expect("Allouer fd1");
        assert_eq!(fd1, 3);
        assert_eq!(table.get(3).unwrap().path_str(), "/etc/config");

        let fd2 = table
            .alloc_fd(FdKind::RegularFile, O_RDONLY, "/var/log")
            .expect("Allouer fd2");
        assert_eq!(fd2, 4);

        assert_eq!(table.count_open(), 5);

        // Fermeture du descripteur 3
        assert!(table.free_fd(fd1).is_ok());
        assert!(table.get(3).is_none());
        assert_eq!(table.count_open(), 4);

        // Réallocation : doit réutiliser le slot 3 (plus petit slot libre)
        let fd3 = table
            .alloc_fd(FdKind::RegularFile, O_WRONLY, "/tmp/test.txt")
            .expect("Allouer fd3");
        assert_eq!(fd3, 3);
        assert_eq!(table.get(3).unwrap().path_str(), "/tmp/test.txt");
    }

    #[test]
    fn test_vfs_read_write_offset() {
        let mut table = FdTable::new();

        let fd = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/data.bin")
            .expect("Allouer fd");

        // Écriture de données
        let msg = b"JamboOS Sovereign Microkernel";
        let written = table.write(fd, msg).expect("Écriture fichier");
        assert_eq!(written, msg.len());

        let entry = table.get(fd).unwrap();
        assert_eq!(entry.size, msg.len() as u64);
        assert_eq!(entry.offset, msg.len() as u64);

        // Repositionnement au début via SEEK_SET
        let new_pos = table.lseek(fd, 0, SEEK_SET).expect("lseek début");
        assert_eq!(new_pos, 0);

        // Lecture des données
        let mut read_buf = [0u8; 64];
        let n = table.read(fd, &mut read_buf).expect("Lecture fichier");
        assert_eq!(n, msg.len());
        assert_eq!(&read_buf[..n], msg);

        // Repositionnement relatif SEEK_CUR
        let seek_pos = table.lseek(fd, -8, SEEK_CUR).expect("lseek arrière");
        assert_eq!(seek_pos, (msg.len() - 8) as i64);

        let mut tail_buf = [0u8; 8];
        let n2 = table.read(fd, &mut tail_buf).expect("Lecture queue");
        assert_eq!(n2, 8);
        assert_eq!(&tail_buf, b"rokernel");
    }

    #[test]
    fn test_vfs_stat() {
        let mut table = FdTable::new();

        let fd = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/test.txt")
            .expect("Allouer fd");
        table.write(fd, b"Hello VFS").expect("Écriture");

        let st = table.fstat(fd).expect("fstat");
        assert_eq!(st.st_size, 9);
        assert_eq!(st.st_mode & S_IFMT, S_IFREG);

        // Stat de la console (fd = 1)
        let st_console = table.fstat(1).expect("fstat stdout");
        assert_eq!(st_console.st_mode & S_IFMT, S_IFCHR);
    }
}

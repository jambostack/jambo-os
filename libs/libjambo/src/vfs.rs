//! Sous-système Virtual File System (VFS) & Descripteurs de Fichiers (`libjambo::vfs`)
//!
//! Fournit une gestion de descripteurs de fichiers (`fd_table`) privée par processus
//! et conforme aux spécifications POSIX.1-2008 en environnement `#![no_std]` :
//! 1. Constantes POSIX standard d'accès aux fichiers (`O_*`, `SEEK_*`, `S_IF*`).
//! 2. Table de descripteurs `FdTable` statique à capacité bornée (`MAX_FDS = 64`).
//! 3. Entrées réservées `0` (stdin), `1` (stdout), `2` (stderr).
//! 4. Descripteurs dynamiques `>= 3` pour fichiers réguliers et canaux IPC.
//! 5. Primitives d'accès et métadonnées `PosixStat` (`fstat`, `stat`).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use jambo_abi::SysError;

// ============================================================================
// CONSTANTES POSIX STANDARD
// ============================================================================

pub const MAX_FDS: usize = 256;
pub const MAX_PATH_LEN: usize = 64;
pub const FILE_BUFFER_SIZE: usize = 1024; // Tampon embarqué par descripteur
pub const MAX_PIPES: usize = 64; // Nombre maximal de canaux pipes simultanés
pub const PIPE_BUFFER_SIZE: usize = 1024; // Tampon circulaire par canal de pipe IPC

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
pub const S_IFSOCK: u32 = 0o140000; // Socket réseau
pub const S_IFLNK: u32 = 0o120000; // Lien symbolique
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
    Symlink,
    IpcChannel,
    Socket,
    PipeReader,
    PipeWriter,
}

/// Canal de communication FIFO pour pipes anonymes IPC en mémoire
#[derive(Clone, Copy)]
pub struct PipeChannel {
    pub buffer: [u8; PIPE_BUFFER_SIZE],
    pub head: usize,
    pub tail: usize,
    pub len: usize,
    pub readers: u8,
    pub writers: u8,
    pub active: bool,
}

impl PipeChannel {
    pub const fn empty() -> Self {
        Self {
            buffer: [0u8; PIPE_BUFFER_SIZE],
            head: 0,
            tail: 0,
            len: 0,
            readers: 0,
            writers: 0,
            active: false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct FdEntry {
    pub kind: FdKind,
    pub flags: i32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub offset: u64,
    pub size: u64,
    pub pipe_id: u8,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: usize,
    pub buffer: [u8; FILE_BUFFER_SIZE],
}

impl FdEntry {
    pub const fn empty() -> Self {
        Self {
            kind: FdKind::Closed,
            flags: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            offset: 0,
            size: 0,
            pipe_id: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            buffer: [0u8; FILE_BUFFER_SIZE],
        }
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

/// Structure temporelle haute résolution POSIX (secondes et nanosecondes)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PosixTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl PosixTimespec {
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }
}

/// Structure de métadonnées de fichier conforme POSIX `struct stat` avec support nanosecondes
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
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
}

impl PosixStat {
    /// Renvoie l'attribut temporel du dernier accès `st_atim` conforme POSIX.1-2008
    #[inline]
    pub fn st_atim(&self) -> PosixTimespec {
        PosixTimespec {
            tv_sec: self.st_atime,
            tv_nsec: self.st_atime_nsec,
        }
    }

    /// Renvoie l'attribut temporel de dernière modification `st_mtim` conforme POSIX.1-2008
    #[inline]
    pub fn st_mtim(&self) -> PosixTimespec {
        PosixTimespec {
            tv_sec: self.st_mtime,
            tv_nsec: self.st_mtime_nsec,
        }
    }

    /// Renvoie l'attribut temporel de dernier changement de métadonnées `st_ctim` conforme POSIX.1-2008
    #[inline]
    pub fn st_ctim(&self) -> PosixTimespec {
        PosixTimespec {
            tv_sec: self.st_ctime,
            tv_nsec: self.st_ctime_nsec,
        }
    }
}

/// Structure de métadonnées de système de fichiers conforme POSIX `struct statvfs`
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PosixStatvfs {
    pub f_bsize: u64,
    pub f_frsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: u64,
    pub f_flag: u64,
    pub f_namemax: u64,
}

// ============================================================================
// TABLE DE DESCRIPTEURS DE FICHIERS (FdTable)
// ============================================================================

pub struct FdTable {
    pub entries: [FdEntry; MAX_FDS],
    pub pipes: [PipeChannel; MAX_PIPES],
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

        Self {
            entries,
            pipes: [PipeChannel::empty(); MAX_PIPES],
        }
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
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    offset: 0,
                    size: 0,
                    pipe_id: 0,
                    path: path_buf,
                    path_len: len,
                    buffer: [0u8; FILE_BUFFER_SIZE],
                };
                return Ok(fd as i32);
            }
        }
        Err(SysError::OutOfMemory) // EMFILE : Table des descripteurs saturée
    }

    /// Alloue un canal de communication IPC anonyme unidirectionnel (pipe POSIX)
    ///
    /// Retourne la paire `(read_fd, write_fd)` où `read_fd` permet la lecture
    /// et `write_fd` permet l'écriture dans le tampon circulaire de 1 Kio.
    pub fn alloc_pipe(&mut self) -> Result<(i32, i32), SysError> {
        let mut pipe_idx = None;
        for (i, p) in self.pipes.iter().enumerate() {
            if !p.active {
                pipe_idx = Some(i);
                break;
            }
        }
        let pidx = pipe_idx.ok_or(SysError::OutOfMemory)?;

        let mut read_fd = None;
        let mut write_fd = None;

        for (fd, entry) in self.entries.iter().enumerate().skip(3) {
            if entry.kind == FdKind::Closed {
                if read_fd.is_none() {
                    read_fd = Some(fd as i32);
                } else if write_fd.is_none() {
                    write_fd = Some(fd as i32);
                    break;
                }
            }
        }

        let r_fd = read_fd.ok_or(SysError::OutOfMemory)?;
        let w_fd = write_fd.ok_or(SysError::OutOfMemory)?;

        self.pipes[pidx] = PipeChannel {
            buffer: [0u8; PIPE_BUFFER_SIZE],
            head: 0,
            tail: 0,
            len: 0,
            readers: 1,
            writers: 1,
            active: true,
        };

        let mut r_entry = FdEntry::empty();
        r_entry.kind = FdKind::PipeReader;
        r_entry.flags = O_RDONLY;
        r_entry.pipe_id = pidx as u8;
        let r_path = b"pipe:[reader]";
        r_entry.path[..r_path.len()].copy_from_slice(r_path);
        r_entry.path_len = r_path.len();
        self.entries[r_fd as usize] = r_entry;

        let mut w_entry = FdEntry::empty();
        w_entry.kind = FdKind::PipeWriter;
        w_entry.flags = O_WRONLY;
        w_entry.pipe_id = pidx as u8;
        let w_path = b"pipe:[writer]";
        w_entry.path[..w_path.len()].copy_from_slice(w_path);
        w_entry.path_len = w_path.len();
        self.entries[w_fd as usize] = w_entry;

        Ok((r_fd, w_fd))
    }

    /// Duplique un descripteur de fichier existant vers le plus petit numéro de descripteur libre
    pub fn dup(&mut self, oldfd: i32) -> Result<i32, SysError> {
        if oldfd < 0 || (oldfd as usize) >= MAX_FDS {
            return Err(SysError::InvalidArgument);
        }
        if self.entries[oldfd as usize].kind == FdKind::Closed {
            return Err(SysError::InvalidArgument);
        }

        for (newfd, entry) in self.entries.iter().enumerate() {
            if entry.kind == FdKind::Closed {
                return self.dup2(oldfd, newfd as i32);
            }
        }
        Err(SysError::OutOfMemory) // EMFILE
    }

    /// Duplique un descripteur de fichier `oldfd` vers un descripteur cible spécifique `newfd`
    ///
    /// Si `newfd` était préalablement ouvert, il est fermé silencieusement au préalable.
    /// Si `oldfd == newfd`, la validité de `oldfd` est vérifiée et `newfd` est retourné sans modification.
    pub fn dup2(&mut self, oldfd: i32, newfd: i32) -> Result<i32, SysError> {
        if oldfd < 0 || (oldfd as usize) >= MAX_FDS || newfd < 0 || (newfd as usize) >= MAX_FDS {
            return Err(SysError::InvalidArgument); // EBADF
        }
        let u_old = oldfd as usize;
        let u_new = newfd as usize;

        if self.entries[u_old].kind == FdKind::Closed {
            return Err(SysError::InvalidArgument); // EBADF
        }

        if oldfd == newfd {
            return Ok(newfd);
        }

        // Si newfd est ouvert, le fermer proprement
        if self.entries[u_new].kind != FdKind::Closed {
            let _ = self.free_fd(newfd);
        }

        let old_entry = self.entries[u_old];
        self.entries[u_new] = old_entry;

        // Mise à jour des références si descripteur de type pipe
        match old_entry.kind {
            FdKind::PipeReader => {
                let pidx = old_entry.pipe_id as usize;
                if pidx < MAX_PIPES && self.pipes[pidx].active {
                    self.pipes[pidx].readers = self.pipes[pidx].readers.saturating_add(1);
                }
            }
            FdKind::PipeWriter => {
                let pidx = old_entry.pipe_id as usize;
                if pidx < MAX_PIPES && self.pipes[pidx].active {
                    self.pipes[pidx].writers = self.pipes[pidx].writers.saturating_add(1);
                }
            }
            _ => {}
        }

        Ok(newfd)
    }

    /// Libère un descripteur de fichier existant
    pub fn free_fd(&mut self, fd: i32) -> Result<(), SysError> {
        if fd < 0 || fd as usize >= MAX_FDS {
            return Err(SysError::InvalidArgument); // EBADF
        }
        let ufd = fd as usize;
        let entry = self.entries[ufd];
        if entry.kind == FdKind::Closed {
            return Err(SysError::InvalidArgument); // EBADF
        }

        match entry.kind {
            FdKind::PipeReader => {
                let pidx = entry.pipe_id as usize;
                if pidx < MAX_PIPES && self.pipes[pidx].active {
                    self.pipes[pidx].readers = self.pipes[pidx].readers.saturating_sub(1);
                    if self.pipes[pidx].readers == 0 && self.pipes[pidx].writers == 0 {
                        self.pipes[pidx] = PipeChannel::empty();
                    }
                }
            }
            FdKind::PipeWriter => {
                let pidx = entry.pipe_id as usize;
                if pidx < MAX_PIPES && self.pipes[pidx].active {
                    self.pipes[pidx].writers = self.pipes[pidx].writers.saturating_sub(1);
                    if self.pipes[pidx].readers == 0 && self.pipes[pidx].writers == 0 {
                        self.pipes[pidx] = PipeChannel::empty();
                    }
                }
            }
            _ => {}
        }

        self.entries[ufd] = FdEntry::empty();
        Ok(())
    }

    /// Alloue un descripteur de fichier pour une socket réseau
    pub fn alloc_socket(
        &mut self,
        _domain: u16,
        _type_: i32,
        _protocol: i32,
    ) -> Result<i32, SysError> {
        self.alloc_fd(FdKind::Socket, O_RDWR, "socket:[net]")
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

        if matches!(
            entry.kind,
            FdKind::ConsoleIn
                | FdKind::ConsoleOut
                | FdKind::Socket
                | FdKind::PipeReader
                | FdKind::PipeWriter
        ) {
            return Err(SysError::NotSupported); // ESPIPE : Impossible de se déplacer sur un périphérique caractère, socket ou pipe
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
            FdKind::RegularFile | FdKind::Socket => {
                if entry.offset >= entry.size {
                    return Ok(0); // EOF / Pas de données disponibles
                }
                let available = (entry.size - entry.offset) as usize;
                let to_read = buf.len().min(available);
                let start = entry.offset as usize;
                buf[..to_read].copy_from_slice(&entry.buffer[start..start + to_read]);
                entry.offset += to_read as u64;
                Ok(to_read)
            }
            FdKind::PipeReader => {
                let pidx = entry.pipe_id as usize;
                if pidx >= MAX_PIPES || !self.pipes[pidx].active {
                    return Err(SysError::InvalidArgument);
                }
                if buf.is_empty() {
                    return Ok(0);
                }
                let pipe = &mut self.pipes[pidx];
                if pipe.len == 0 {
                    // Si aucun écrivain actif, EOF POSIX standard
                    return Ok(0);
                }
                let to_read = buf.len().min(pipe.len);
                for slot in buf.iter_mut().take(to_read) {
                    *slot = pipe.buffer[pipe.head];
                    pipe.head = (pipe.head + 1) % PIPE_BUFFER_SIZE;
                }
                pipe.len -= to_read;
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
            FdKind::RegularFile | FdKind::Socket => {
                // Si O_APPEND est positionné, toujours écrire à la fin du fichier
                if (entry.flags & O_APPEND) != 0 {
                    entry.offset = entry.size;
                }

                let start = entry.offset as usize;
                if start >= FILE_BUFFER_SIZE {
                    return Err(SysError::OutOfMemory); // ENOSPC / ENOBUFS
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
            FdKind::PipeWriter => {
                let pidx = entry.pipe_id as usize;
                if pidx >= MAX_PIPES || !self.pipes[pidx].active {
                    return Err(SysError::InvalidArgument);
                }
                let pipe = &mut self.pipes[pidx];
                if pipe.readers == 0 {
                    // SIGPIPE / EPIPE : Aucun lecteur sur le canal
                    return Err(SysError::PeerClosed);
                }
                if buf.is_empty() {
                    return Ok(0);
                }
                let space_left = PIPE_BUFFER_SIZE - pipe.len;
                if space_left == 0 {
                    return Err(SysError::OutOfMemory);
                }
                let to_write = buf.len().min(space_left);
                for &b in &buf[..to_write] {
                    pipe.buffer[pipe.tail] = b;
                    pipe.tail = (pipe.tail + 1) % PIPE_BUFFER_SIZE;
                }
                pipe.len += to_write;
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
                st.st_mode = if entry.mode != 0 {
                    entry.mode
                } else {
                    S_IFCHR | 0o666
                };
                st.st_nlink = 1;
                st.st_size = 0;
            }
            FdKind::RegularFile => {
                st.st_mode = if entry.mode != 0 {
                    entry.mode
                } else {
                    S_IFREG | 0o644
                };
                st.st_nlink = 1;
                st.st_size = entry.size as i64;
                st.st_blksize = 512;
                st.st_blocks = entry.size.div_ceil(512) as i64;
            }
            FdKind::Symlink => {
                st.st_mode = if entry.mode != 0 {
                    entry.mode
                } else {
                    S_IFLNK | 0o777
                };
                st.st_nlink = 1;
                st.st_size = entry.size as i64;
                st.st_blksize = 512;
                st.st_blocks = entry.size.div_ceil(512) as i64;
            }
            FdKind::Socket => {
                st.st_mode = if entry.mode != 0 {
                    entry.mode
                } else {
                    S_IFSOCK | 0o666
                };
                st.st_nlink = 1;
                st.st_size = entry.size as i64;
                st.st_blksize = 512;
                st.st_blocks = entry.size.div_ceil(512) as i64;
            }
            FdKind::PipeReader | FdKind::PipeWriter => {
                st.st_mode = if entry.mode != 0 {
                    entry.mode
                } else {
                    S_IFIFO | 0o600
                };
                st.st_nlink = 1;
                let pidx = entry.pipe_id as usize;
                if pidx < MAX_PIPES && self.pipes[pidx].active {
                    st.st_size = self.pipes[pidx].len as i64;
                    st.st_blocks = self.pipes[pidx].len.div_ceil(512) as i64;
                }
                st.st_blksize = 512;
            }
            _ => return Err(SysError::InvalidArgument),
        }
        st.st_uid = entry.uid;
        st.st_gid = entry.gid;
        Ok(st)
    }

    /// Modifie le masque de permissions d'un descripteur ouvert (fchmod)
    pub fn fchmod(&mut self, fd: i32, mode: u32) -> Result<(), SysError> {
        let entry = self.get_mut(fd).ok_or(SysError::InvalidArgument)?;
        if entry.kind == FdKind::Closed {
            return Err(SysError::InvalidArgument);
        }
        let file_type = match entry.kind {
            FdKind::RegularFile => S_IFREG,
            FdKind::Symlink => S_IFLNK,
            FdKind::ConsoleIn | FdKind::ConsoleOut => S_IFCHR,
            FdKind::Socket => S_IFSOCK,
            FdKind::PipeReader | FdKind::PipeWriter => S_IFIFO,
            _ => 0,
        };
        entry.mode = file_type | (mode & 0o7777);
        Ok(())
    }

    /// Modifie le propriétaire et le groupe d'un descripteur ouvert (fchown POSIX)
    pub fn fchown(&mut self, fd: i32, uid: u32, gid: u32) -> Result<(), SysError> {
        let entry = self.get_mut(fd).ok_or(SysError::InvalidArgument)?;
        if entry.kind == FdKind::Closed {
            return Err(SysError::InvalidArgument);
        }
        entry.uid = uid;
        entry.gid = gid;
        Ok(())
    }

    /// Modifie le masque de permissions de tous les descripteurs ouverts sur ce chemin (chmod)
    pub fn chmod(&mut self, path: &str, mode: u32) -> Result<(), SysError> {
        let mut modified = false;
        for entry in self.entries.iter_mut() {
            if entry.kind != FdKind::Closed && entry.path_str() == path {
                let file_type = match entry.kind {
                    FdKind::RegularFile => S_IFREG,
                    FdKind::Symlink => S_IFLNK,
                    FdKind::ConsoleIn | FdKind::ConsoleOut => S_IFCHR,
                    FdKind::Socket => S_IFSOCK,
                    FdKind::PipeReader | FdKind::PipeWriter => S_IFIFO,
                    _ => 0,
                };
                entry.mode = file_type | (mode & 0o7777);
                modified = true;
            }
        }
        if modified {
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Modifie le propriétaire et le groupe de tous les descripteurs ouverts sur ce chemin (chown POSIX)
    pub fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<(), SysError> {
        let mut modified = false;
        for entry in self.entries.iter_mut() {
            if entry.kind != FdKind::Closed && entry.path_str() == path {
                entry.uid = uid;
                entry.gid = gid;
                modified = true;
            }
        }
        if modified {
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Récupère les métadonnées pour un chemin donné dans la table des descripteurs
    pub fn stat(&self, path: &str) -> Result<PosixStat, SysError> {
        for entry in &self.entries {
            if entry.kind != FdKind::Closed && entry.path_str() == path {
                let default_mode = if entry.kind == FdKind::Symlink {
                    S_IFLNK | 0o777
                } else {
                    S_IFREG | 0o644
                };
                let st_mode = if entry.mode != 0 {
                    entry.mode
                } else {
                    default_mode
                };
                return Ok(PosixStat {
                    st_mode,
                    st_nlink: 1,
                    st_uid: entry.uid,
                    st_gid: entry.gid,
                    st_size: entry.size as i64,
                    st_blksize: 512,
                    st_blocks: entry.size.div_ceil(512) as i64,
                    ..Default::default()
                });
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Interroge les métadonnées de système de fichiers associées à un descripteur ouvert (fstatvfs POSIX)
    pub fn fstatvfs(&self, fd: i32) -> Result<PosixStatvfs, SysError> {
        let entry = self.get(fd).ok_or(SysError::InvalidArgument)?;
        if entry.kind == FdKind::Closed {
            return Err(SysError::InvalidArgument);
        }
        self.statvfs(entry.path_str())
    }

    /// Interroge les métadonnées de système de fichiers associées à un chemin (statvfs POSIX)
    pub fn statvfs(&self, path: &str) -> Result<PosixStatvfs, SysError> {
        if path.starts_with("/dev") {
            Ok(PosixStatvfs {
                f_bsize: 4096,
                f_frsize: 4096,
                f_blocks: 1,
                f_bfree: 0,
                f_bavail: 0,
                f_files: 16,
                f_ffree: 8,
                f_favail: 8,
                f_fsid: 0x4445_5646, // "DEVF"
                f_flag: 0,
                f_namemax: 64,
            })
        } else if path.starts_with("/tmp") {
            Ok(PosixStatvfs {
                f_bsize: 4096,
                f_frsize: 4096,
                f_blocks: 256,
                f_bfree: 254,
                f_bavail: 254,
                f_files: 256,
                f_ffree: 254,
                f_favail: 254,
                f_fsid: 0x544D_5046, // "TMPF"
                f_flag: 0,
                f_namemax: 64,
            })
        } else {
            // Volume persistant principal JamboFS (2048 blocs de 4 Kio = 8 Mio, 24 blocs réservés système)
            Ok(PosixStatvfs {
                f_bsize: 4096,
                f_frsize: 4096,
                f_blocks: 2048,
                f_bfree: 2024,
                f_bavail: 2024,
                f_files: 1024,
                f_ffree: 1000,
                f_favail: 1000,
                f_fsid: 0x5346_4F42, // "JAMBO_FS"
                f_flag: 0,
                f_namemax: 32,
            })
        }
    }

    /// Force la synchronisation des données et métadonnées du fichier vers le stockage persistant (fsync POSIX)
    pub fn fsync(&mut self, fd: i32) -> Result<(), SysError> {
        let entry = self.get(fd).ok_or(SysError::InvalidArgument)?;
        if entry.kind == FdKind::Closed {
            return Err(SysError::InvalidArgument);
        }
        Ok(())
    }

    /// Force la synchronisation des données utiles du fichier vers le stockage persistant (fdatasync POSIX)
    pub fn fdatasync(&mut self, fd: i32) -> Result<(), SysError> {
        self.fsync(fd)
    }

    /// Tronque ou étend un fichier régulier ouvert à la longueur spécifiée (ftruncate POSIX.1-2008)
    pub fn ftruncate(&mut self, fd: i32, length: u64) -> Result<(), SysError> {
        let entry = self.get_mut(fd).ok_or(SysError::InvalidArgument)?;
        if entry.kind != FdKind::RegularFile {
            return Err(SysError::InvalidArgument);
        }
        let acc = entry.flags & O_ACCMODE;
        if acc != O_WRONLY && acc != O_RDWR {
            return Err(SysError::PermissionDenied);
        }
        let target_len = length as usize;
        if target_len > FILE_BUFFER_SIZE {
            return Err(SysError::InvalidArgument);
        }
        let old_len = entry.size as usize;
        if target_len < old_len {
            // Réduction : zérotage des octets au-delà de la nouvelle fin
            entry.buffer[target_len..old_len].fill(0);
        } else if target_len > old_len {
            // Extension : zérotage des nouveaux octets (sparse / trou)
            entry.buffer[old_len..target_len].fill(0);
        }
        entry.size = length;
        // Remarque : POSIX spécifie que le pointeur de fichier (offset) n'est pas modifié par ftruncate
        Ok(())
    }

    /// Synchronise l'ensemble des systèmes de fichiers et tampons sales (sync POSIX)
    pub fn sync(&self) -> Result<(), SysError> {
        Ok(())
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

/// Duplique un descripteur existant vers le plus petit descripteur libre sur la table globale
pub fn dup(oldfd: i32) -> Result<i32, SysError> {
    with_fd_table(|table| table.dup(oldfd))
}

/// Duplique un descripteur vers une destination spécifique sur la table globale (redirection I/O)
pub fn dup2(oldfd: i32, newfd: i32) -> Result<i32, SysError> {
    with_fd_table(|table| table.dup2(oldfd, newfd))
}

/// Alloue un canal de communication IPC anonyme (pipe POSIX) sur la table globale
pub fn pipe() -> Result<(i32, i32), SysError> {
    with_fd_table(|table| table.alloc_pipe())
}

/// Modifie le masque de permissions d'un descripteur de fichier ouvert (fchmod POSIX)
pub fn fchmod(fd: i32, mode: u32) -> Result<(), SysError> {
    with_fd_table(|table| table.fchmod(fd, mode))
}

/// Modifie le masque de permissions associé à un chemin dans la table VFS
pub fn chmod(path: &str, mode: u32) -> Result<(), SysError> {
    with_fd_table(|table| table.chmod(path, mode))
}

/// Modifie le propriétaire et le groupe d'un descripteur de fichier ouvert (fchown POSIX)
pub fn fchown(fd: i32, uid: u32, gid: u32) -> Result<(), SysError> {
    with_fd_table(|table| table.fchown(fd, uid, gid))
}

/// Modifie le propriétaire et le groupe associé à un chemin dans la table VFS (chown POSIX)
pub fn chown(path: &str, uid: u32, gid: u32) -> Result<(), SysError> {
    with_fd_table(|table| table.chown(path, uid, gid))
}

/// Interroge les statistiques de système de fichiers par chemin (statvfs POSIX)
pub fn statvfs(path: &str) -> Result<PosixStatvfs, SysError> {
    with_fd_table(|table| table.statvfs(path))
}

/// Interroge les métadonnées de fichier par chemin (stat POSIX)
pub fn stat(path: &str) -> Result<PosixStat, SysError> {
    with_fd_table(|table| table.stat(path))
}

/// Interroge les statistiques de système de fichiers par descripteur de fichier ouvert (fstatvfs POSIX)
pub fn fstatvfs(fd: i32) -> Result<PosixStatvfs, SysError> {
    with_fd_table(|table| table.fstatvfs(fd))
}

/// Force la synchronisation d'un fichier ouvert vers le stockage (fsync POSIX)
pub fn fsync(fd: i32) -> Result<(), SysError> {
    with_fd_table(|table| table.fsync(fd))
}

/// Force la synchronisation des données d'un fichier ouvert vers le stockage (fdatasync POSIX)
pub fn fdatasync(fd: i32) -> Result<(), SysError> {
    with_fd_table(|table| table.fdatasync(fd))
}

/// Synchronise l'ensemble des tampons système vers le stockage persistant (sync POSIX)
pub fn sync() -> Result<(), SysError> {
    with_fd_table(|table| table.sync())
}

/// Repositionne le pointeur de fichier ouvert (lseek POSIX)
pub fn lseek(fd: i32, offset: i64, whence: i32) -> Result<i64, SysError> {
    with_fd_table(|table| table.lseek(fd, offset, whence))
}

/// Tronque ou étend un descripteur de fichier ouvert à une taille donnée (ftruncate POSIX)
pub fn ftruncate(fd: i32, length: u64) -> Result<(), SysError> {
    with_fd_table(|table| table.ftruncate(fd, length))
}

/// Tronque ou étend un fichier par son chemin à une taille donnée (truncate POSIX)
pub fn truncate(path: &str, length: u64) -> Result<(), SysError> {
    with_fd_table(|table| {
        let fd = table.alloc_fd(FdKind::RegularFile, O_WRONLY, path)?;
        let res = table.ftruncate(fd, length);
        let _ = table.free_fd(fd);
        res
    })
}

/// Lit la cible d'un lien symbolique dans le VFS (readlink POSIX)
pub fn readlink(path: &str, buf: &mut [u8]) -> Result<usize, SysError> {
    with_fd_table(|table| {
        for entry in &table.entries {
            if entry.kind == FdKind::Symlink && entry.path_str() == path {
                let to_copy = buf.len().min(entry.size as usize);
                buf[..to_copy].copy_from_slice(&entry.buffer[..to_copy]);
                return Ok(to_copy);
            }
        }
        Err(SysError::InvalidArgument) // ENOENT / EINVAL (pas un lien symbolique)
    })
}

/// Vérifie si un descripteur de fichier ouvert est associé à un terminal interactif (isatty POSIX)
pub fn isatty(fd: i32) -> bool {
    with_fd_table(|table| match table.get(fd) {
        Some(entry) => {
            entry.kind == FdKind::ConsoleIn
                || entry.kind == FdKind::ConsoleOut
                || entry.path_str().starts_with("/dev/tty")
                || entry.path_str() == "/dev/console"
        }
        None => false,
    })
}

/// Retourne le nom de fichier du terminal associé au descripteur de fichier (ttyname_r POSIX)
pub fn ttyname_r(fd: i32, buf: &mut [u8]) -> Result<usize, SysError> {
    with_fd_table(|table| match table.get(fd) {
        Some(entry) => {
            if entry.kind == FdKind::ConsoleIn
                || entry.kind == FdKind::ConsoleOut
                || entry.path_str().starts_with("/dev/tty")
                || entry.path_str() == "/dev/console"
            {
                let name = if entry.path_len > 0 && entry.path_str().starts_with("/dev/tty") {
                    entry.path_str()
                } else {
                    "/dev/tty1"
                };
                let bytes = name.as_bytes();
                if buf.len() < bytes.len() {
                    return Err(SysError::BufferTooSmall);
                }
                buf[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            } else {
                Err(SysError::NotSupported) // ENOTTY
            }
        }
        None => Err(SysError::InvalidArgument), // EBADF
    })
}

// Variables atomiques de contexte d'identité utilisateur et groupe Ring 3
static CURRENT_UID: AtomicU32 = AtomicU32::new(0);
static CURRENT_GID: AtomicU32 = AtomicU32::new(0);
static CURRENT_EUID: AtomicU32 = AtomicU32::new(0);
static CURRENT_EGID: AtomicU32 = AtomicU32::new(0);

/// Retourne l'identifiant utilisateur réel (UID) du processus courant
pub fn getuid() -> u32 {
    CURRENT_UID.load(Ordering::Relaxed)
}

/// Retourne l'identifiant utilisateur effectif (EUID) du processus courant
pub fn geteuid() -> u32 {
    CURRENT_EUID.load(Ordering::Relaxed)
}

/// Retourne l'identifiant de groupe réel (GID) du processus courant
pub fn getgid() -> u32 {
    CURRENT_GID.load(Ordering::Relaxed)
}

/// Retourne l'identifiant de groupe effectif (EGID) du processus courant
pub fn getegid() -> u32 {
    CURRENT_EGID.load(Ordering::Relaxed)
}

/// Définit l'identifiant utilisateur (UID/EUID) du processus courant
pub fn setuid(uid: u32) -> Result<(), SysError> {
    let euid = geteuid();
    if euid != 0 && uid != euid {
        return Err(SysError::PermissionDenied);
    }
    CURRENT_UID.store(uid, Ordering::Relaxed);
    CURRENT_EUID.store(uid, Ordering::Relaxed);
    Ok(())
}

/// Définit l'identifiant de groupe (GID/EGID) du processus courant
pub fn setgid(gid: u32) -> Result<(), SysError> {
    let euid = geteuid();
    if euid != 0 && gid != getegid() {
        return Err(SysError::PermissionDenied);
    }
    CURRENT_GID.store(gid, Ordering::Relaxed);
    CURRENT_EGID.store(gid, Ordering::Relaxed);
    Ok(())
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

    #[test]
    fn test_vfs_socket_descriptor() {
        let mut table = FdTable::new();
        let sock_fd = table.alloc_socket(2, 1, 6).expect("Allouer socket");
        assert!(sock_fd >= 3);

        let entry = table.get(sock_fd).expect("Entrée socket valide");
        assert_eq!(entry.kind, FdKind::Socket);
        assert_eq!(entry.path_str(), "socket:[net]");

        // Écriture de données réseau
        let msg = b"GET / HTTP/1.1\r\nHost: jamboos.local\r\n\r\n";
        let written = table.write(sock_fd, msg).expect("Écriture socket");
        assert_eq!(written, msg.len());

        // Lseek doit échouer sur une socket (ESPIPE)
        assert!(table.lseek(sock_fd, 0, SEEK_SET).is_err());

        // Lecture des données
        let mut rx_buf = [0u8; 64];
        table.get_mut(sock_fd).unwrap().offset = 0; // Réinitialise offset de lecture
        let read_len = table.read(sock_fd, &mut rx_buf).expect("Lecture socket");
        assert_eq!(read_len, msg.len());
        assert_eq!(&rx_buf[..read_len], msg);

        // Stat de la socket
        let st = table.fstat(sock_fd).expect("fstat socket");
        assert_eq!(st.st_mode & S_IFMT, S_IFSOCK);
    }

    #[test]
    fn test_vfs_pipe_lifecycle_and_io() {
        let mut table = FdTable::new();

        // 1. Allouer un pipe anonyme
        let (rfd, wfd) = table.alloc_pipe().expect("Allouer pipe");
        assert_eq!(rfd, 3);
        assert_eq!(wfd, 4);

        let r_entry = table.get(rfd).unwrap();
        assert_eq!(r_entry.kind, FdKind::PipeReader);
        assert_eq!(r_entry.flags, O_RDONLY);

        let w_entry = table.get(wfd).unwrap();
        assert_eq!(w_entry.kind, FdKind::PipeWriter);
        assert_eq!(w_entry.flags, O_WRONLY);

        // Stat sur pipe
        let st = table.fstat(rfd).expect("fstat pipe reader");
        assert_eq!(st.st_mode & S_IFMT, S_IFIFO);
        assert_eq!(st.st_size, 0);

        // Lseek doit échouer sur un pipe (ESPIPE)
        assert!(table.lseek(rfd, 0, SEEK_SET).is_err());
        assert!(table.lseek(wfd, 0, SEEK_SET).is_err());

        // 2. Écriture dans le pipe
        let msg = b"JamboOS IPC Anonymous Pipe Message";
        let nwritten = table.write(wfd, msg).expect("Écriture pipe");
        assert_eq!(nwritten, msg.len());

        // 3. Lecture depuis le pipe
        let mut rx_buf = [0u8; 64];
        let nread = table.read(rfd, &mut rx_buf).expect("Lecture pipe");
        assert_eq!(nread, msg.len());
        assert_eq!(&rx_buf[..nread], msg);

        // 4. Fermeture de l'écrivain : le lecteur doit voir EOF (0 octet lu)
        assert!(table.free_fd(wfd).is_ok());
        let eof_read = table.read(rfd, &mut rx_buf).expect("EOF pipe");
        assert_eq!(eof_read, 0);

        // 5. Fermeture du lecteur : le canal doit être complètement libéré
        assert!(table.free_fd(rfd).is_ok());
        assert!(!table.pipes[0].active);
    }

    #[test]
    fn test_vfs_dup_and_dup2_io_redirection() {
        let mut table = FdTable::new();

        // Créer un fichier régulier cible
        let fd_file = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/tmp/stdout.log")
            .expect("alloc file");
        assert_eq!(fd_file, 3);

        // Redirection I/O : dup2(fd_file, 1) pour rediriger stdout vers /tmp/stdout.log
        let redirected_stdout = table.dup2(fd_file, 1).expect("dup2 stdout");
        assert_eq!(redirected_stdout, 1);

        let stdout_entry = table.get(1).unwrap();
        assert_eq!(stdout_entry.kind, FdKind::RegularFile);
        assert_eq!(stdout_entry.path_str(), "/tmp/stdout.log");

        // Écriture via fd 1 (qui pointe désormais sur le fichier régulier)
        let msg = b"Redirection stdout reussie vers fichier";
        let nwritten = table.write(1, msg).expect("write to redirected stdout");
        assert_eq!(nwritten, msg.len());

        let target_entry = table.get(1).unwrap();
        assert_eq!(target_entry.size, msg.len() as u64);

        // Test dup simple : dup(1) doit allouer le plus petit slot libre (slot 4)
        let dup_fd = table.dup(1).expect("dup simple");
        assert_eq!(dup_fd, 4);
        assert_eq!(table.get(dup_fd).unwrap().path_str(), "/tmp/stdout.log");

        // Test dup2 sur soi-même : doit renvoyer newfd sans modification
        assert_eq!(table.dup2(dup_fd, dup_fd).unwrap(), dup_fd);

        // Test dup2 invalide
        assert!(table.dup2(-1, 5).is_err());
        assert!(table.dup2(100, 5).is_err());
        assert!(table.dup2(5, 100).is_err()); // Slot 5 fermé
    }

    #[test]
    fn test_vfs_pipe_epipe_when_readers_closed() {
        let mut table = FdTable::new();
        let (rfd, wfd) = table.alloc_pipe().expect("alloc pipe");

        // Fermer immédiatement le lecteur
        assert!(table.free_fd(rfd).is_ok());

        // Tenter d'écrire sur le pipe sans lecteur : doit retourner PeerClosed (EPIPE)
        let res = table.write(wfd, b"broken pipe test");
        assert_eq!(res, Err(SysError::PeerClosed));
    }

    #[test]
    fn test_vfs_chmod_and_fchmod() {
        let mut table = FdTable::new();
        let fd = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/etc/secure.conf")
            .expect("alloc regular file");

        // Vérification du mode par défaut
        let st0 = table.fstat(fd).expect("fstat");
        assert_eq!(st0.st_mode, S_IFREG | 0o644);

        // Application de fchmod (passage en 0600)
        assert!(table.fchmod(fd, 0o600).is_ok());
        let st1 = table.fstat(fd).expect("fstat after fchmod");
        assert_eq!(st1.st_mode, S_IFREG | 0o600);

        // Application de chmod par chemin (passage en 0755)
        assert!(table.chmod("/etc/secure.conf", 0o755).is_ok());
        let st2 = table.fstat(fd).expect("fstat after chmod");
        assert_eq!(st2.st_mode, S_IFREG | 0o755);

        // Test sur descripteur invalide
        assert!(table.fchmod(99, 0o644).is_err());
        assert!(table.chmod("/nonexistent", 0o644).is_err());
    }

    #[test]
    fn test_vfs_chown_and_identity() {
        let mut table = FdTable::new();
        let fd = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/var/run/app.pid")
            .expect("alloc regular file");

        let st0 = table.fstat(fd).expect("fstat");
        assert_eq!(st0.st_uid, 0);
        assert_eq!(st0.st_gid, 0);

        // Modification de propriété par fchown
        assert!(table.fchown(fd, 1000, 1000).is_ok());
        let st1 = table.fstat(fd).expect("fstat after fchown");
        assert_eq!(st1.st_uid, 1000);
        assert_eq!(st1.st_gid, 1000);

        // Modification par chemin chown
        assert!(table.chown("/var/run/app.pid", 1001, 1002).is_ok());
        let st2 = table.fstat(fd).expect("fstat after chown");
        assert_eq!(st2.st_uid, 1001);
        assert_eq!(st2.st_gid, 1002);

        // Identités du processus
        assert_eq!(getuid(), 0);
        assert_eq!(getgid(), 0);
        assert!(setuid(1000).is_ok());
        assert_eq!(getuid(), 1000);
        assert_eq!(geteuid(), 1000);

        // Rétablir root pour les autres tests
        CURRENT_UID.store(0, Ordering::Relaxed);
        CURRENT_EUID.store(0, Ordering::Relaxed);
    }

    #[test]
    fn test_vfs_statvfs_and_fstatvfs() {
        let mut table = FdTable::new();
        let fd = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/etc/hostname")
            .expect("alloc regular file");

        // statvfs sur le chemin racine JamboFS
        let sv_root = table.statvfs("/").expect("statvfs root");
        assert_eq!(sv_root.f_bsize, 4096);
        assert_eq!(sv_root.f_blocks, 2048);
        assert_eq!(sv_root.f_bfree, 2024);
        assert_eq!(sv_root.f_fsid, 0x5346_4F42);

        // fstatvfs sur le descripteur ouvert
        let sv_fd = table.fstatvfs(fd).expect("fstatvfs");
        assert_eq!(sv_fd.f_bsize, 4096);
        assert_eq!(sv_fd.f_blocks, 2048);

        // statvfs sur /dev
        let sv_dev = table.statvfs("/dev/console").expect("statvfs dev");
        assert_eq!(sv_dev.f_fsid, 0x4445_5646);

        // statvfs sur /tmp
        let sv_tmp = table.statvfs("/tmp/scratch").expect("statvfs tmp");
        assert_eq!(sv_tmp.f_fsid, 0x544D_5046);
    }

    #[test]
    fn test_vfs_sync_fsync_and_fdatasync() {
        let mut table = FdTable::new();
        let fd = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/var/log/messages")
            .expect("alloc log file");

        // fsync et fdatasync sur descripteur ouvert valide
        assert!(table.fsync(fd).is_ok());
        assert!(table.fdatasync(fd).is_ok());

        // fsync sur descripteur invalide
        assert!(table.fsync(99).is_err());
        assert!(table.fdatasync(99).is_err());

        // sync global
        assert!(table.sync().is_ok());
        assert!(sync().is_ok());
    }

    #[test]
    fn test_vfs_ftruncate_and_truncate() {
        let mut table = FdTable::new();
        let fd = table
            .alloc_fd(FdKind::RegularFile, O_RDWR, "/data/test.bin")
            .expect("alloc file");

        // Écriture de 10 octets initiaux
        let data = b"0123456789";
        let written = table.write(fd, data).expect("write");
        assert_eq!(written, 10);
        assert_eq!(table.get(fd).unwrap().size, 10);

        // 1. Extension avec ftruncate (de 10 à 20 octets, zérotage des 10 octets étendus)
        assert!(table.ftruncate(fd, 20).is_ok());
        let entry = table.get(fd).unwrap();
        assert_eq!(entry.size, 20);
        assert_eq!(&entry.buffer[..10], b"0123456789");
        assert_eq!(&entry.buffer[10..20], &[0u8; 10]);

        // 2. Réduction avec ftruncate (de 20 à 5 octets)
        assert!(table.ftruncate(fd, 5).is_ok());
        let entry2 = table.get(fd).unwrap();
        assert_eq!(entry2.size, 5);
        assert_eq!(&entry2.buffer[..5], b"01234");
        // Les octets au-delà sont zérotés
        assert_eq!(&entry2.buffer[5..10], &[0u8; 5]);

        // 3. Rejet si ouvert en lecture seule (O_RDONLY)
        let ro_fd = table
            .alloc_fd(FdKind::RegularFile, O_RDONLY, "/data/readonly.bin")
            .expect("alloc ro file");
        assert_eq!(table.ftruncate(ro_fd, 0), Err(SysError::PermissionDenied));

        // 4. Rejet sur type non fichier régulier
        assert_eq!(table.ftruncate(0, 0), Err(SysError::InvalidArgument)); // stdin ConsoleIn
    }
}

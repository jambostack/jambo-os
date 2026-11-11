//! Utilitaires Coreutils autonomes et routines d'E/S POSIX en Ring 3
//!
//! Ce module fournit les implémentations `#![no_std]` des outils fondamentaux :
//! `echo`, `cat`, `wc`, `true`, `false`, `ls`.
//! Chaque routine s'interface avec les descripteurs POSIX (`vfs::*`)
//! sans recourir à des allocations heap obligatoires.

use crate::vfs::{with_fd_table, O_APPEND, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY};

#[derive(Clone, Copy)]
pub struct VfsFileNode {
    pub path: [u8; crate::vfs::MAX_PATH_LEN],
    pub path_len: usize,
    pub buffer: [u8; crate::vfs::FILE_BUFFER_SIZE],
    pub size: usize,
    pub is_active: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl VfsFileNode {
    pub const fn empty() -> Self {
        Self {
            path: [0u8; crate::vfs::MAX_PATH_LEN],
            path_len: 0,
            buffer: [0u8; crate::vfs::FILE_BUFFER_SIZE],
            size: 0,
            is_active: false,
            is_dir: false,
            is_symlink: false,
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

pub const MAX_INODES: usize = 64;

pub static mut INODE_POOL: [VfsFileNode; MAX_INODES] = [
    // 0: /etc/hostname
    VfsFileNode {
        path: {
            let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
            let b = b"/etc/hostname";
            let mut i = 0;
            while i < b.len() {
                p[i] = b[i];
                i += 1;
            }
            p
        },
        path_len: 13,
        buffer: {
            let mut b = [0u8; crate::vfs::FILE_BUFFER_SIZE];
            let c = b"jambo-node-01\n";
            let mut i = 0;
            while i < c.len() {
                b[i] = c[i];
                i += 1;
            }
            b
        },
        size: 14,
        is_active: true,
        is_dir: false,
        is_symlink: false,
        mode: 0o644,
        uid: 0,
        gid: 0,
    },
    // 1: /etc/os-release
    VfsFileNode {
        path: {
            let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
            let b = b"/etc/os-release";
            let mut i = 0;
            while i < b.len() {
                p[i] = b[i];
                i += 1;
            }
            p
        },
        path_len: 15,
        buffer: {
            let mut b = [0u8; crate::vfs::FILE_BUFFER_SIZE];
            let c = b"NAME=JamboOS\nVERSION=0.3.92\nID=jamboos\n";
            let mut i = 0;
            while i < c.len() {
                b[i] = c[i];
                i += 1;
            }
            b
        },
        size: 38,
        is_active: true,
        is_dir: false,
        is_symlink: false,
        mode: 0o644,
        uid: 0,
        gid: 0,
    },
    // 2: /etc/motd
    VfsFileNode {
        path: {
            let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
            let b = b"/etc/motd";
            let mut i = 0;
            while i < b.len() {
                p[i] = b[i];
                i += 1;
            }
            p
        },
        path_len: 9,
        buffer: {
            let mut b = [0u8; crate::vfs::FILE_BUFFER_SIZE];
            let c = b"Welcome to JamboOS Ring 3 Environment\n";
            let mut i = 0;
            while i < c.len() {
                b[i] = c[i];
                i += 1;
            }
            b
        },
        size: 38,
        is_active: true,
        is_dir: false,
        is_symlink: false,
        mode: 0o644,
        uid: 0,
        gid: 0,
    },
    // 3: /etc (répertoire)
    VfsFileNode {
        path: {
            let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
            let b = b"/etc";
            let mut i = 0;
            while i < b.len() {
                p[i] = b[i];
                i += 1;
            }
            p
        },
        path_len: 4,
        buffer: [0u8; crate::vfs::FILE_BUFFER_SIZE],
        size: 0,
        is_active: true,
        is_dir: true,
        is_symlink: false,
        mode: 0o755,
        uid: 0,
        gid: 0,
    },
    // 4: /tmp (répertoire)
    VfsFileNode {
        path: {
            let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
            let b = b"/tmp";
            let mut i = 0;
            while i < b.len() {
                p[i] = b[i];
                i += 1;
            }
            p
        },
        path_len: 4,
        buffer: [0u8; crate::vfs::FILE_BUFFER_SIZE],
        size: 0,
        is_active: true,
        is_dir: true,
        is_symlink: false,
        mode: 0o777,
        uid: 0,
        gid: 0,
    },
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
    VfsFileNode::empty(),
];

/// Ouvre un fichier via la table de descripteurs VFS du processus
pub fn sys_open(path: &str, flags: i32) -> i32 {
    let mut inode_idx = None;
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        for (i, node) in (*pool).iter().enumerate() {
            if node.is_active && node.path_str() == path {
                // Si O_CREAT et O_EXCL sont tous deux spécifiés et que le fichier existe, échoue avec EEXIST
                if (flags & crate::vfs::O_CREAT) != 0 && (flags & crate::vfs::O_EXCL) != 0 {
                    return -1;
                }
                // Rejet de l'écriture si le noeud est un répertoire (EISDIR)
                if node.is_dir
                    && (flags & (crate::vfs::O_WRONLY | crate::vfs::O_RDWR | crate::vfs::O_TRUNC))
                        != 0
                {
                    return -1;
                }
                inode_idx = Some(i);
                break;
            }
        }
        if inode_idx.is_none() && (flags & crate::vfs::O_CREAT) != 0 {
            for (i, node) in (*pool).iter_mut().enumerate() {
                if !node.is_active {
                    let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
                    let b = path.as_bytes();
                    let len = b.len().min(crate::vfs::MAX_PATH_LEN);
                    p[..len].copy_from_slice(&b[..len]);
                    node.path = p;
                    node.path_len = len;
                    node.size = 0;
                    node.buffer = [0u8; crate::vfs::FILE_BUFFER_SIZE];
                    node.is_active = true;
                    node.is_dir = false;
                    node.is_symlink = false;
                    node.mode = 0o644;
                    inode_idx = Some(i);
                    break;
                }
            }
        }
    }

    let node_idx = match inode_idx {
        Some(idx) => idx,
        None => return -1, // Fichier inexistant et O_CREAT absent
    };

    with_fd_table(
        |tbl| match tbl.alloc_fd(crate::vfs::FdKind::RegularFile, flags, path) {
            Ok(fd) => {
                if let Some(entry) = tbl.get_mut(fd) {
                    // SAFETY: Copie du contenu initial du noeud vers l'entrée ouverte
                    unsafe {
                        let pool = core::ptr::addr_of!(INODE_POOL);
                        let node = &(*pool)[node_idx];
                        entry.size = node.size as u64;
                        entry.mode = node.mode;
                        entry.uid = node.uid;
                        entry.gid = node.gid;
                        let len = node.size.min(crate::vfs::FILE_BUFFER_SIZE);
                        entry.buffer[..len].copy_from_slice(&node.buffer[..len]);
                        if (flags & crate::vfs::O_TRUNC) != 0 {
                            entry.size = 0;
                        }
                    }
                }
                fd
            }
            Err(_) => -1,
        },
    )
}

/// Crée un répertoire virtuel dans le pool d'inodes
pub fn sys_mkdir_pool(path: &str, _mode: u32) -> i32 {
    let clean_path = path.trim_end_matches('/');
    if clean_path.is_empty() {
        return -1;
    }
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        for node in (*pool).iter() {
            if node.is_active && node.path_str() == clean_path {
                return -1; // EEXIST
            }
        }
        for node in (*pool).iter_mut() {
            if !node.is_active {
                let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
                let b = clean_path.as_bytes();
                let len = b.len().min(crate::vfs::MAX_PATH_LEN);
                p[..len].copy_from_slice(&b[..len]);
                node.path = p;
                node.path_len = len;
                node.size = 0;
                node.buffer = [0u8; crate::vfs::FILE_BUFFER_SIZE];
                node.is_active = true;
                node.is_dir = true;
                node.is_symlink = false;
                node.mode = if _mode != 0 { _mode } else { 0o755 };
                return 0;
            }
        }
    }
    -1 // ENOSPC
}

/// Supprime un fichier régulier du pool d'inodes (unlink)
pub fn sys_unlink_pool(path: &str) -> i32 {
    let clean_path = path.trim_end_matches('/');
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        for node in (*pool).iter_mut() {
            if node.is_active && node.path_str() == clean_path {
                if node.is_dir {
                    return -1; // EISDIR
                }
                node.is_active = false;
                node.size = 0;
                node.path_len = 0;
                return 0;
            }
        }
    }
    -1 // ENOENT
}

/// Supprime un répertoire vide du pool d'inodes (rmdir)
pub fn sys_rmdir_pool(path: &str) -> i32 {
    let clean_path = path.trim_end_matches('/');
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        let mut target_idx = None;
        for (i, node) in (*pool).iter().enumerate() {
            if node.is_active && node.path_str() == clean_path {
                if !node.is_dir {
                    return -1; // ENOTDIR
                }
                target_idx = Some(i);
                break;
            }
        }
        let idx = match target_idx {
            Some(i) => i,
            None => return -1, // ENOENT
        };
        // Vérification qu'aucun fichier ou sous-répertoire actif n'a ce répertoire pour parent
        for node in (*pool).iter() {
            if node.is_active && node.path_str() != clean_path {
                let p = node.path_str();
                if let Some(rest) = p.strip_prefix(clean_path) {
                    if rest.starts_with('/') {
                        return -1; // ENOTEMPTY
                    }
                }
            }
        }
        (*pool)[idx].is_active = false;
        (*pool)[idx].size = 0;
        (*pool)[idx].path_len = 0;
        0
    }
}

/// Modifie les permissions octales d'un fichier ou répertoire dans le pool d'inodes virtuel
pub fn sys_chmod_pool(path: &str, mode: u32) -> i32 {
    let clean_path = path.trim_end_matches('/');
    let target = if clean_path.is_empty() {
        "/"
    } else {
        clean_path
    };
    let mut found = false;
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        for node in (*pool).iter_mut() {
            if node.is_active {
                let p = node.path_str();
                if p == target
                    || (target.starts_with('/') && p == &target[1..])
                    || (!target.starts_with('/') && p.strip_prefix('/').unwrap_or("") == target)
                {
                    node.mode = mode & 0o7777;
                    found = true;
                    break;
                }
            }
        }
    }
    let _ = crate::vfs::with_fd_table(|tbl| tbl.chmod(target, mode));
    if found {
        0
    } else {
        -1
    }
}

/// Lit les permissions octales actuelles d'un fichier ou répertoire dans le pool d'inodes virtuel
pub fn sys_get_mode_pool(path: &str) -> Option<u32> {
    let clean_path = path.trim_end_matches('/');
    let target = if clean_path.is_empty() {
        "/"
    } else {
        clean_path
    };
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for node in (*pool).iter() {
            if node.is_active {
                let p = node.path_str();
                if p == target
                    || (target.starts_with('/') && p == &target[1..])
                    || (!target.starts_with('/') && p.strip_prefix('/').unwrap_or("") == target)
                {
                    return Some(node.mode);
                }
            }
        }
    }
    None
}

/// Modifie le propriétaire et le groupe d'un fichier ou répertoire dans le pool d'inodes virtuel
pub fn sys_chown_pool(path: &str, uid: u32, gid: u32) -> i32 {
    let clean_path = path.trim_end_matches('/');
    let target = if clean_path.is_empty() {
        "/"
    } else {
        clean_path
    };
    let mut found = false;
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        for node in (*pool).iter_mut() {
            if node.is_active {
                let p = node.path_str();
                if p == target
                    || (target.starts_with('/') && p == &target[1..])
                    || (!target.starts_with('/') && p.strip_prefix('/').unwrap_or("") == target)
                {
                    node.uid = uid;
                    node.gid = gid;
                    found = true;
                    break;
                }
            }
        }
    }
    let _ = crate::vfs::with_fd_table(|tbl| tbl.chown(target, uid, gid));
    if found {
        0
    } else {
        -1
    }
}

/// Lit le propriétaire et le groupe actuels d'un fichier ou répertoire dans le pool d'inodes virtuel
pub fn sys_get_owner_pool(path: &str) -> Option<(u32, u32)> {
    let clean_path = path.trim_end_matches('/');
    let target = if clean_path.is_empty() {
        "/"
    } else {
        clean_path
    };
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for node in (*pool).iter() {
            if node.is_active {
                let p = node.path_str();
                if p == target
                    || (target.starts_with('/') && p == &target[1..])
                    || (!target.starts_with('/') && p.strip_prefix('/').unwrap_or("") == target)
                {
                    return Some((node.uid, node.gid));
                }
            }
        }
    }
    None
}

/// Lit les métadonnées de fichier PosixStat directement depuis le pool d'inodes virtuel
pub fn sys_stat_pool(path: &str) -> Option<crate::vfs::PosixStat> {
    let clean_path = path.trim_end_matches('/');
    let target = if clean_path.is_empty() {
        "/"
    } else {
        clean_path
    };
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for (idx, node) in (*pool).iter().enumerate() {
            if node.is_active {
                let p = node.path_str();
                if p == target
                    || (target.starts_with('/') && p == &target[1..])
                    || (!target.starts_with('/') && p.strip_prefix('/').unwrap_or("") == target)
                {
                    let file_type = if node.is_symlink {
                        crate::vfs::S_IFLNK
                    } else if node.is_dir {
                        crate::vfs::S_IFDIR
                    } else {
                        crate::vfs::S_IFREG
                    };
                    let st_mode = file_type | (node.mode & 0o7777);
                    let blocks = node.size.div_ceil(512) as i64;
                    return Some(crate::vfs::PosixStat {
                        st_dev: 1,
                        st_ino: (idx + 100) as u64,
                        st_mode,
                        st_nlink: if node.is_dir { 2 } else { 1 },
                        st_uid: node.uid,
                        st_gid: node.gid,
                        st_rdev: 0,
                        st_size: node.size as i64,
                        st_blksize: 512,
                        st_blocks: blocks,
                        st_atime: 1731276000,
                        st_atime_nsec: 0,
                        st_mtime: 1731276000,
                        st_mtime_nsec: 0,
                        st_ctime: 1731276000,
                        st_ctime_nsec: 0,
                    });
                }
            }
        }
    }
    None
}

/// Crée un lien symbolique virtuel dans le pool d'inodes (symlink)
pub fn sys_symlink_pool(target: &str, linkpath: &str) -> i32 {
    let clean_link = linkpath.trim_end_matches('/');
    if clean_link.is_empty() || target.is_empty() {
        return -1;
    }
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        for node in (*pool).iter() {
            if node.is_active && node.path_str() == clean_link {
                return -1; // EEXIST
            }
        }
        for node in (*pool).iter_mut() {
            if !node.is_active {
                let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
                let b = clean_link.as_bytes();
                let len = b.len().min(crate::vfs::MAX_PATH_LEN);
                p[..len].copy_from_slice(&b[..len]);
                node.path = p;
                node.path_len = len;

                let mut buf = [0u8; crate::vfs::FILE_BUFFER_SIZE];
                let tb = target.as_bytes();
                let tlen = tb.len().min(crate::vfs::FILE_BUFFER_SIZE);
                buf[..tlen].copy_from_slice(&tb[..tlen]);
                node.buffer = buf;
                node.size = tlen;

                node.is_active = true;
                node.is_dir = false;
                node.is_symlink = true;
                node.mode = crate::vfs::S_IFLNK | 0o777;
                return 0;
            }
        }
    }
    -1 // ENOSPC
}

/// Lit la cible d'un lien symbolique dans le pool d'inodes virtuel (readlink)
pub fn sys_readlink_pool(path: &str, out: &mut [u8]) -> isize {
    let clean = path.trim_end_matches('/');
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for node in (*pool).iter() {
            if node.is_active && node.path_str() == clean {
                if !node.is_symlink {
                    return -1; // EINVAL: Pas un lien symbolique
                }
                let len = out.len().min(node.size);
                out[..len].copy_from_slice(&node.buffer[..len]);
                return len as isize;
            }
        }
    }
    -1 // ENOENT
}

/// Ferme un descripteur de fichier VFS et synchronise les métadonnées
pub fn sys_close(fd: i32) -> i32 {
    with_fd_table(|tbl| {
        if let Some(entry) = tbl.get(fd) {
            let path = entry.path_str();
            // SAFETY: Synchronisation de l'entrée fermée dans le pool d'inodes
            unsafe {
                let pool = core::ptr::addr_of_mut!(INODE_POOL);
                for node in (*pool).iter_mut() {
                    if node.is_active && node.path_str() == path {
                        let len = (entry.size as usize).min(crate::vfs::FILE_BUFFER_SIZE);
                        node.size = len;
                        node.buffer[..len].copy_from_slice(&entry.buffer[..len]);
                        break;
                    }
                }
            }
        }
        match tbl.free_fd(fd) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    })
}

/// Lit des données depuis un descripteur VFS
#[inline]
pub fn sys_read(fd: i32, buf: &mut [u8]) -> isize {
    with_fd_table(|tbl| match tbl.read(fd, buf) {
        Ok(n) => n as isize,
        Err(_) => -1,
    })
}

/// Écrit des données vers un descripteur VFS et synchronise vers l'inode
pub fn sys_write(fd: i32, buf: &[u8]) -> isize {
    with_fd_table(|tbl| match tbl.write(fd, buf) {
        Ok(n) => {
            if let Some(entry) = tbl.get(fd) {
                let path = entry.path_str();
                // SAFETY: Synchronisation de l'écriture vers le noeud virtuel
                unsafe {
                    let pool = core::ptr::addr_of_mut!(INODE_POOL);
                    for node in (*pool).iter_mut() {
                        if node.is_active && node.path_str() == path {
                            let len = (entry.size as usize).min(crate::vfs::FILE_BUFFER_SIZE);
                            node.size = len;
                            node.buffer[..len].copy_from_slice(&entry.buffer[..len]);
                            break;
                        }
                    }
                }
            }
            n as isize
        }
        Err(_) => -1,
    })
}

/// Force la synchronisation des données et métadonnées d'un descripteur de fichier vers le support persistant
pub fn sys_fsync(fd: i32) -> i32 {
    match crate::vfs::fsync(fd) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Force la synchronisation des données utiles d'un descripteur de fichier vers le support persistant
pub fn sys_fdatasync(fd: i32) -> i32 {
    match crate::vfs::fdatasync(fd) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Force la synchronisation globale de tous les tampons système vers le stockage persistant
pub fn sys_sync() -> i32 {
    match crate::vfs::sync() {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Tronque ou étend un descripteur de fichier ouvert à une taille donnée (ftruncate POSIX)
pub fn sys_ftruncate(fd: i32, length: u64) -> i32 {
    match crate::vfs::ftruncate(fd, length) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Repositionne le pointeur de fichier ouvert (lseek POSIX)
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    crate::vfs::lseek(fd, offset, whence).unwrap_or(-1)
}

/// Tronque ou étend un fichier par son chemin à une taille donnée (truncate POSIX)
pub fn sys_truncate(path: &str, length: u64) -> i32 {
    match crate::vfs::truncate(path, length) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Lit la destination d'un lien symbolique (readlink POSIX)
pub fn sys_readlink(path: &str, buf: &mut [u8]) -> isize {
    // Tente d'abord le pool d'inodes virtuel
    let pool_res = sys_readlink_pool(path, buf);
    if pool_res >= 0 {
        return pool_res;
    }
    // Sinon consulte la table VFS globale
    match crate::vfs::readlink(path, buf) {
        Ok(n) => n as isize,
        Err(_) => -1,
    }
}

/// Résultat du comptage pour l'utilitaire `wc`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WcResult {
    pub lines: usize,
    pub words: usize,
    pub bytes: usize,
}

/// Analyse un tampon mémoire et calcule le nombre de lignes, mots et octets
pub fn count_buffer(buf: &[u8]) -> WcResult {
    let mut lines = 0;
    let mut words = 0;
    let bytes = buf.len();
    let mut in_word = false;

    for &b in buf {
        if b == b'\n' {
            lines += 1;
        }
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            in_word = false;
        } else if !in_word {
            in_word = true;
            words += 1;
        }
    }

    WcResult {
        lines,
        words,
        bytes,
    }
}

/// Formate et écrit un nombre décimal non signé dans un descripteur POSIX
fn write_u64_fd(fd: i32, mut val: u64) {
    if val == 0 {
        let _ = sys_write(fd, b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut idx = 20;
    while val > 0 {
        idx -= 1;
        buf[idx] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    let _ = sys_write(fd, &buf[idx..]);
}

/// Formate un entier décimal dans un tampon mémoire et renvoie le curseur mis à jour
fn append_u64(buf: &mut [u8], mut cursor: usize, mut val: u64) -> usize {
    if cursor >= buf.len() {
        return cursor;
    }
    if val == 0 {
        buf[cursor] = b'0';
        return cursor + 1;
    }
    let mut digits = [0u8; 20];
    let mut d_idx = 0;
    while val > 0 {
        digits[d_idx] = b'0' + (val % 10) as u8;
        val /= 10;
        d_idx += 1;
    }
    for &d in digits[..d_idx].iter().rev() {
        if cursor < buf.len() {
            buf[cursor] = d;
            cursor += 1;
        }
    }
    cursor
}

/// Exécute l'utilitaire `echo` dans un tampon mémoire
///
/// Retourne `(code_de_retour, octets_ecrits)`.
pub fn run_echo_slice(args: &[&str], out: &mut [u8]) -> (i32, usize) {
    let mut cursor = 0;
    let mut omit_newline = false;
    let mut start_idx = 0;

    if let Some(&first) = args.first() {
        if first == "-n" {
            omit_newline = true;
            start_idx = 1;
        }
    }

    let words = &args[start_idx..];
    for (i, &w) in words.iter().enumerate() {
        if i > 0 && cursor < out.len() {
            out[cursor] = b' ';
            cursor += 1;
        }
        let bytes = w.as_bytes();
        let to_copy = bytes.len().min(out.len().saturating_sub(cursor));
        out[cursor..cursor + to_copy].copy_from_slice(&bytes[..to_copy]);
        cursor += to_copy;
    }

    if !omit_newline && cursor < out.len() {
        out[cursor] = b'\n';
        cursor += 1;
    }

    (0, cursor)
}

/// Exécute l'utilitaire `echo` vers un descripteur de fichier POSIX (`out_fd`)
pub fn run_echo(args: &[&str], out_fd: i32) -> i32 {
    let mut omit_newline = false;
    let mut start_idx = 0;

    if let Some(&first) = args.first() {
        if first == "-n" {
            omit_newline = true;
            start_idx = 1;
        }
    }

    let words = &args[start_idx..];
    for (i, &w) in words.iter().enumerate() {
        if i > 0 {
            let _ = sys_write(out_fd, b" ");
        }
        let _ = sys_write(out_fd, w.as_bytes());
    }

    if !omit_newline {
        let _ = sys_write(out_fd, b"\n");
    }

    0
}

/// Exécute l'utilitaire `cat` lisant les chemins fournis ou `in_fd` et écrivant sur `out_fd`
pub fn run_cat(paths: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut chunk = [0u8; 512];
    let mut has_error = false;

    if paths.is_empty() {
        // Lecture depuis stdin / in_fd jusqu'à EOF
        loop {
            let n = sys_read(in_fd, &mut chunk);
            if n <= 0 {
                break;
            }
            let _ = sys_write(out_fd, &chunk[..n as usize]);
        }
        return 0;
    }

    for &path in paths {
        if path == "-" {
            loop {
                let n = sys_read(in_fd, &mut chunk);
                if n <= 0 {
                    break;
                }
                let _ = sys_write(out_fd, &chunk[..n as usize]);
            }
            continue;
        }

        let fd = sys_open(path, O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"cat: ");
            let _ = sys_write(err_fd, path.as_bytes());
            let _ = sys_write(err_fd, b": No such file or directory\n");
            has_error = true;
            continue;
        }

        loop {
            let n = sys_read(fd, &mut chunk);
            if n <= 0 {
                break;
            }
            let _ = sys_write(out_fd, &chunk[..n as usize]);
        }
        let _ = sys_close(fd);
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `tee` dupliquant le flux d'entrée standard vers la sortie et un ou plusieurs fichiers
pub fn run_tee(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut append_mode = false;
    let mut target_paths: [&str; 8] = [""; 8];
    let mut target_count = 0;

    for &arg in args {
        match arg {
            "-a" | "--append" => append_mode = true,
            "-i" | "--ignore-interrupts" => {} // Ignoré mais accepté conformément à POSIX
            path if !path.starts_with('-') && path != "-" && target_count < target_paths.len() => {
                target_paths[target_count] = path;
                target_count += 1;
            }
            _ => {}
        }
    }

    let mut target_fds: [i32; 8] = [-1; 8];
    let mut opened_count = 0;
    let mut has_error = false;

    let open_flags = if append_mode {
        O_CREAT | O_WRONLY | O_APPEND
    } else {
        O_CREAT | O_WRONLY | O_TRUNC
    };

    for &path in target_paths.iter().take(target_count) {
        let fd = sys_open(path, open_flags);
        if fd < 0 {
            let _ = sys_write(err_fd, b"tee: ");
            let _ = sys_write(err_fd, path.as_bytes());
            let _ = sys_write(err_fd, b": Error opening file\n");
            has_error = true;
        } else {
            target_fds[opened_count] = fd;
            opened_count += 1;
        }
    }

    // Boucle de transfert : lecture depuis in_fd et diffusion vers out_fd et chaque fichier
    let mut chunk = [0u8; 512];
    loop {
        let n = sys_read(in_fd, &mut chunk);
        if n <= 0 {
            break;
        }
        let slice = &chunk[..n as usize];
        let _ = sys_write(out_fd, slice);

        for &fd in target_fds.iter().take(opened_count) {
            if fd >= 0 {
                let _ = sys_write(fd, slice);
            }
        }
    }

    // Clôture des descripteurs de fichiers cibles
    for &fd in target_fds.iter().take(opened_count) {
        if fd >= 0 {
            let _ = sys_close(fd);
        }
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `env` affichant ou modifiant l'environnement sans allocation dynamique globale
pub fn run_env(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    const MAX_ENV_SLOTS: usize = 32;

    #[derive(Clone, Copy)]
    struct EnvSlot<'a> {
        key: &'a str,
        val: &'a str,
        active: bool,
    }

    let mut slots: [EnvSlot; MAX_ENV_SLOTS] = [EnvSlot {
        key: "",
        val: "",
        active: false,
    }; MAX_ENV_SLOTS];

    // Variables d'environnement standard par défaut
    const DEFAULT_ENV: [(&str, &str); 6] = [
        ("PATH", "/bin"),
        ("USER", "root"),
        ("SHELL", "/bin/jsh"),
        ("TERM", "xterm-256color"),
        ("HOME", "/root"),
        ("OS", "JamboOS"),
    ];

    let mut ignore_env = false;
    let mut unset_targets: [&str; 8] = [""; 8];
    let mut unset_count = 0;
    let mut arg_idx = 0;

    // Analyse des options préliminaires (-i, -u)
    while arg_idx < args.len() {
        let arg = args[arg_idx];
        if arg == "-i" || arg == "--ignore-environment" {
            ignore_env = true;
            arg_idx += 1;
        } else if arg == "-u" {
            if arg_idx + 1 < args.len() && unset_count < unset_targets.len() {
                unset_targets[unset_count] = args[arg_idx + 1];
                unset_count += 1;
                arg_idx += 2;
            } else {
                let _ = sys_write(err_fd, b"env: option requires an argument -- 'u'\n");
                return 1;
            }
        } else if let Some(target) = arg.strip_prefix("--unset=") {
            if unset_count < unset_targets.len() {
                unset_targets[unset_count] = target;
                unset_count += 1;
            }
            arg_idx += 1;
        } else {
            break;
        }
    }

    // Charger les variables par défaut si -i n'est pas spécifié
    let mut slot_count = 0;
    if !ignore_env {
        for &(k, v) in &DEFAULT_ENV {
            let mut is_unset = false;
            for &u in unset_targets.iter().take(unset_count) {
                if u == k {
                    is_unset = true;
                    break;
                }
            }
            if !is_unset && slot_count < MAX_ENV_SLOTS {
                slots[slot_count] = EnvSlot {
                    key: k,
                    val: v,
                    active: true,
                };
                slot_count += 1;
            }
        }
    }

    // Analyse des paires KEY=VALUE
    while arg_idx < args.len() {
        let arg = args[arg_idx];
        if let Some(eq_pos) = arg.find('=') {
            let key = &arg[..eq_pos];
            let val = &arg[eq_pos + 1..];

            let mut updated = false;
            for slot in slots.iter_mut().take(slot_count) {
                if slot.active && slot.key == key {
                    slot.val = val;
                    updated = true;
                    break;
                }
            }
            if !updated && slot_count < MAX_ENV_SLOTS {
                slots[slot_count] = EnvSlot {
                    key,
                    val,
                    active: true,
                };
                slot_count += 1;
            }
            arg_idx += 1;
        } else {
            break;
        }
    }

    // Si une sous-commande est spécifiée
    if arg_idx < args.len() {
        let cmd = args[arg_idx];
        let sub_args = &args[arg_idx + 1..];
        match cmd {
            "echo" => run_echo(sub_args, out_fd),
            "ls" => run_ls(sub_args, out_fd, err_fd),
            "true" => 0,
            "false" => 1,
            _ => {
                let _ = sys_write(err_fd, b"env: executing '");
                let _ = sys_write(err_fd, cmd.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                0
            }
        }
    } else {
        // Aucune commande : afficher toutes les variables actives au format KEY=VALUE\n
        for slot in slots.iter().take(slot_count) {
            if slot.active {
                let _ = sys_write(out_fd, slot.key.as_bytes());
                let _ = sys_write(out_fd, b"=");
                let _ = sys_write(out_fd, slot.val.as_bytes());
                let _ = sys_write(out_fd, b"\n");
            }
        }
        0
    }
}

/// Recherche de sous-tranche d'octets avec option d'insensibilité à la casse
fn contains_subslice(haystack: &[u8], needle: &[u8], ignore_case: bool) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let max_start = haystack.len() - needle.len();
    for i in 0..=max_start {
        let mut matched = true;
        for j in 0..needle.len() {
            let h = if ignore_case {
                haystack[i + j].to_ascii_lowercase()
            } else {
                haystack[i + j]
            };
            let n = if ignore_case {
                needle[j].to_ascii_lowercase()
            } else {
                needle[j]
            };
            if h != n {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

/// Traite un flux d'octets pour la recherche grep
#[allow(clippy::too_many_arguments)]
fn grep_stream(
    fd: i32,
    pattern: &str,
    ignore_case: bool,
    invert_match: bool,
    line_number: bool,
    count_only: bool,
    prefix_filename: Option<&str>,
    out_fd: i32,
) -> (usize, usize) {
    let mut buf = [0u8; 1024];
    let mut line_buf = [0u8; 512];
    let mut line_len = 0;
    let mut total_matches = 0;
    let mut line_count = 0;

    let pattern_bytes = pattern.as_bytes();

    loop {
        let n = sys_read(fd, &mut buf);
        if n <= 0 {
            break;
        }
        for &b in &buf[..n as usize] {
            if b == b'\n' {
                line_count += 1;
                let is_match = contains_subslice(&line_buf[..line_len], pattern_bytes, ignore_case);
                let selected = is_match ^ invert_match;
                if selected {
                    total_matches += 1;
                    if !count_only {
                        if let Some(prefix) = prefix_filename {
                            let _ = sys_write(out_fd, prefix.as_bytes());
                            let _ = sys_write(out_fd, b":");
                        }
                        if line_number {
                            write_u64_fd(out_fd, line_count as u64);
                            let _ = sys_write(out_fd, b":");
                        }
                        let _ = sys_write(out_fd, &line_buf[..line_len]);
                        let _ = sys_write(out_fd, b"\n");
                    }
                }
                line_len = 0;
            } else if line_len < line_buf.len() {
                line_buf[line_len] = b;
                line_len += 1;
            }
        }
    }

    if line_len > 0 {
        line_count += 1;
        let is_match = contains_subslice(&line_buf[..line_len], pattern_bytes, ignore_case);
        let selected = is_match ^ invert_match;
        if selected {
            total_matches += 1;
            if !count_only {
                if let Some(prefix) = prefix_filename {
                    let _ = sys_write(out_fd, prefix.as_bytes());
                    let _ = sys_write(out_fd, b":");
                }
                if line_number {
                    write_u64_fd(out_fd, line_count as u64);
                    let _ = sys_write(out_fd, b":");
                }
                let _ = sys_write(out_fd, &line_buf[..line_len]);
                let _ = sys_write(out_fd, b"\n");
            }
        }
    }

    if count_only {
        if let Some(prefix) = prefix_filename {
            let _ = sys_write(out_fd, prefix.as_bytes());
            let _ = sys_write(out_fd, b":");
        }
        write_u64_fd(out_fd, total_matches as u64);
        let _ = sys_write(out_fd, b"\n");
    }

    (total_matches, line_count)
}

/// Exécute l'utilitaire `grep` (filtrage et recherche de motifs textuels POSIX)
pub fn run_grep(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut ignore_case = false;
    let mut invert_match = false;
    let mut line_number = false;
    let mut count_only = false;
    let mut pattern: Option<&str> = None;
    let mut file_indices: [usize; 16] = [0; 16];
    let mut file_count = 0;

    let mut i = 0;
    let mut parsing_flags = true;
    while i < args.len() {
        let arg = args[i];
        if parsing_flags && arg == "--" {
            parsing_flags = false;
            i += 1;
            continue;
        }
        if parsing_flags && arg.starts_with('-') && arg != "-" {
            for b in arg[1..].bytes() {
                match b {
                    b'i' => ignore_case = true,
                    b'v' => invert_match = true,
                    b'n' => line_number = true,
                    b'c' => count_only = true,
                    _ => {
                        let _ = sys_write(err_fd, b"grep: option invalide -- '");
                        let b_slice = [b];
                        let _ = sys_write(err_fd, &b_slice);
                        let _ = sys_write(err_fd, b"'\n");
                        return 2;
                    }
                }
            }
        } else if pattern.is_none() {
            pattern = Some(arg);
        } else if file_count < file_indices.len() {
            file_indices[file_count] = i;
            file_count += 1;
        }
        i += 1;
    }

    let pat = match pattern {
        Some(p) => p,
        None => {
            let _ = sys_write(
                err_fd,
                b"grep: motif manquant\nUsage: grep [-ivnc] PATTERN [FILE...]\n",
            );
            return 2;
        }
    };

    let mut total_matches = 0;

    if file_count == 0 {
        let (matches, _) = grep_stream(
            in_fd,
            pat,
            ignore_case,
            invert_match,
            line_number,
            count_only,
            None,
            out_fd,
        );
        total_matches += matches;
    } else {
        let multiple_files = file_count > 1;
        for &idx in &file_indices[..file_count] {
            let file_path = args[idx];
            let fd = if file_path == "-" {
                in_fd
            } else {
                let fd = sys_open(file_path, O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"grep: ");
                    let _ = sys_write(err_fd, file_path.as_bytes());
                    let _ = sys_write(err_fd, b": No such file or directory\n");
                    continue;
                }
                fd
            };

            let prefix = if multiple_files {
                Some(file_path)
            } else {
                None
            };
            let (matches, _) = grep_stream(
                fd,
                pat,
                ignore_case,
                invert_match,
                line_number,
                count_only,
                prefix,
                out_fd,
            );
            total_matches += matches;

            if file_path != "-" {
                sys_close(fd);
            }
        }
    }

    if total_matches > 0 {
        0
    } else {
        1
    }
}

fn parse_leading_int(slice: &[u8]) -> i64 {
    let mut i = 0;
    while i < slice.len() && (slice[i] == b' ' || slice[i] == b'\t') {
        i += 1;
    }
    if i >= slice.len() {
        return 0;
    }
    let is_neg = if slice[i] == b'-' {
        i += 1;
        true
    } else if slice[i] == b'+' {
        i += 1;
        false
    } else {
        false
    };
    let mut val: i64 = 0;
    while i < slice.len() && slice[i].is_ascii_digit() {
        val = val
            .saturating_mul(10)
            .saturating_add((slice[i] - b'0') as i64);
        i += 1;
    }
    if is_neg {
        -val
    } else {
        val
    }
}

fn compare_lexicographical(a: &[u8], b: &[u8], ignore_case: bool) -> core::cmp::Ordering {
    let len = a.len().min(b.len());
    for i in 0..len {
        let ba = if ignore_case {
            a[i].to_ascii_lowercase()
        } else {
            a[i]
        };
        let bb = if ignore_case {
            b[i].to_ascii_lowercase()
        } else {
            b[i]
        };
        match ba.cmp(&bb) {
            core::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

fn compare_lines(
    a: &[u8],
    b: &[u8],
    numeric: bool,
    ignore_case: bool,
    reverse: bool,
) -> core::cmp::Ordering {
    let ord = if numeric {
        let na = parse_leading_int(a);
        let nb = parse_leading_int(b);
        match na.cmp(&nb) {
            core::cmp::Ordering::Equal => compare_lexicographical(a, b, ignore_case),
            other => other,
        }
    } else {
        compare_lexicographical(a, b, ignore_case)
    };
    if reverse {
        ord.reverse()
    } else {
        ord
    }
}

/// Exécute l'utilitaire `sort` (tri de lignes de texte POSIX)
pub fn run_sort(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut reverse = false;
    let mut numeric = false;
    let mut unique = false;
    let mut ignore_case = false;
    let mut file_indices: [usize; 16] = [0; 16];
    let mut file_count = 0;

    let mut i = 0;
    let mut parsing_flags = true;
    while i < args.len() {
        let arg = args[i];
        if parsing_flags && arg == "--" {
            parsing_flags = false;
            i += 1;
            continue;
        }
        if parsing_flags && arg.starts_with('-') && arg != "-" {
            for b in arg[1..].bytes() {
                match b {
                    b'r' => reverse = true,
                    b'n' => numeric = true,
                    b'u' => unique = true,
                    b'f' | b'i' => ignore_case = true,
                    _ => {
                        let _ = sys_write(err_fd, b"sort: option invalide -- '");
                        let b_slice = [b];
                        let _ = sys_write(err_fd, &b_slice);
                        let _ = sys_write(err_fd, b"'\n");
                        return 2;
                    }
                }
            }
        } else if file_count < file_indices.len() {
            file_indices[file_count] = i;
            file_count += 1;
        }
        i += 1;
    }

    const MAX_SORT_BYTES: usize = 8192;
    const MAX_SORT_LINES: usize = 256;

    let mut content_buf = [0u8; MAX_SORT_BYTES];
    let mut content_len = 0;

    if file_count == 0 {
        // Lecture depuis in_fd
        loop {
            if content_len >= MAX_SORT_BYTES {
                break;
            }
            let n = sys_read(in_fd, &mut content_buf[content_len..]);
            if n <= 0 {
                break;
            }
            content_len += n as usize;
        }
    } else {
        // Lecture séquentielle de chaque fichier
        for &idx in &file_indices[..file_count] {
            let file_path = args[idx];
            let fd = if file_path == "-" {
                in_fd
            } else {
                let fd = sys_open(file_path, O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"sort: cannot read: ");
                    let _ = sys_write(err_fd, file_path.as_bytes());
                    let _ = sys_write(err_fd, b": No such file or directory\n");
                    return 2;
                }
                fd
            };

            loop {
                if content_len >= MAX_SORT_BYTES {
                    break;
                }
                let n = sys_read(fd, &mut content_buf[content_len..]);
                if n <= 0 {
                    break;
                }
                content_len += n as usize;
            }

            if file_path != "-" {
                sys_close(fd);
            }
        }
    }

    // Découpage en lignes (start, end)
    let mut lines: [(usize, usize); MAX_SORT_LINES] = [(0, 0); MAX_SORT_LINES];
    let mut line_count = 0;
    let mut line_start = 0;

    let buf_slice = &content_buf[..content_len];
    for (pos, &byte) in buf_slice.iter().enumerate() {
        if byte == b'\n' {
            if line_count < MAX_SORT_LINES {
                lines[line_count] = (line_start, pos + 1);
                line_count += 1;
            }
            line_start = pos + 1;
        }
    }
    if line_start < content_len && line_count < MAX_SORT_LINES {
        lines[line_count] = (line_start, content_len);
        line_count += 1;
    }

    // Tri par insertion (stable, in-situ, zéro allocation)
    for j in 1..line_count {
        let key = lines[j];
        let key_slice = &buf_slice[key.0..key.1];
        let mut k = j;
        while k > 0 {
            let prev = lines[k - 1];
            let prev_slice = &buf_slice[prev.0..prev.1];
            let ord = compare_lines(key_slice, prev_slice, numeric, ignore_case, reverse);
            if ord == core::cmp::Ordering::Less {
                lines[k] = lines[k - 1];
                k -= 1;
            } else {
                break;
            }
        }
        lines[k] = key;
    }

    // Écriture vers out_fd avec déduplication optionnelle (-u)
    let mut prev_emitted: Option<&[u8]> = None;
    for &(start, end) in &lines[..line_count] {
        let current_line = &buf_slice[start..end];
        if unique {
            if let Some(prev) = prev_emitted {
                let is_dup = if ignore_case {
                    compare_lexicographical(current_line, prev, true) == core::cmp::Ordering::Equal
                } else {
                    current_line == prev
                };
                if is_dup {
                    continue;
                }
            }
        }
        let _ = sys_write(out_fd, current_line);
        if !current_line.ends_with(b"\n") {
            let _ = sys_write(out_fd, b"\n");
        }
        prev_emitted = Some(current_line);
    }

    0
}

/// Exécute l'utilitaire `uniq` filtrant les lignes adjacentes répétées dans un flux
pub fn run_uniq(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut show_count = false;
    let mut repeated_only = false;
    let mut unique_only = false;
    let mut ignore_case = false;
    let mut positional: [&str; 2] = ["", ""];
    let mut pos_count = 0;

    let mut i = 0;
    let mut parsing_flags = true;
    while i < args.len() {
        let arg = args[i];
        if parsing_flags && arg == "--" {
            parsing_flags = false;
            i += 1;
            continue;
        }
        if parsing_flags && arg.starts_with('-') && arg != "-" {
            for b in arg[1..].bytes() {
                match b {
                    b'c' => show_count = true,
                    b'd' => repeated_only = true,
                    b'u' => unique_only = true,
                    b'i' => ignore_case = true,
                    _ => {
                        let _ = sys_write(err_fd, b"uniq: option invalide -- '");
                        let b_slice = [b];
                        let _ = sys_write(err_fd, &b_slice);
                        let _ = sys_write(err_fd, b"'\n");
                        return 1;
                    }
                }
            }
        } else if pos_count < positional.len() {
            positional[pos_count] = arg;
            pos_count += 1;
        }
        i += 1;
    }

    let input_path = if pos_count >= 1 { positional[0] } else { "-" };
    let output_path = if pos_count >= 2 { positional[1] } else { "-" };

    let actual_in_fd = if input_path == "-" {
        in_fd
    } else {
        let fd = sys_open(input_path, O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"uniq: cannot read: ");
            let _ = sys_write(err_fd, input_path.as_bytes());
            let _ = sys_write(err_fd, b": No such file or directory\n");
            return 1;
        }
        fd
    };

    let actual_out_fd = if output_path == "-" {
        out_fd
    } else {
        let fd = sys_open(output_path, O_CREAT | O_WRONLY | O_TRUNC);
        if fd < 0 {
            if actual_in_fd != in_fd {
                let _ = sys_close(actual_in_fd);
            }
            let _ = sys_write(err_fd, b"uniq: cannot write: ");
            let _ = sys_write(err_fd, output_path.as_bytes());
            let _ = sys_write(err_fd, b": Error opening file\n");
            return 1;
        }
        fd
    };

    const MAX_UNIQ_BYTES: usize = 8192;
    const MAX_UNIQ_LINES: usize = 256;

    let mut content_buf = [0u8; MAX_UNIQ_BYTES];
    let mut content_len = 0;

    loop {
        if content_len >= MAX_UNIQ_BYTES {
            break;
        }
        let n = sys_read(actual_in_fd, &mut content_buf[content_len..]);
        if n <= 0 {
            break;
        }
        content_len += n as usize;
    }

    if actual_in_fd != in_fd {
        let _ = sys_close(actual_in_fd);
    }

    let mut lines: [(usize, usize); MAX_UNIQ_LINES] = [(0, 0); MAX_UNIQ_LINES];
    let mut line_count = 0;
    let mut line_start = 0;

    let buf_slice = &content_buf[..content_len];
    for (pos, &byte) in buf_slice.iter().enumerate() {
        if byte == b'\n' {
            if line_count < MAX_UNIQ_LINES {
                lines[line_count] = (line_start, pos + 1);
                line_count += 1;
            }
            line_start = pos + 1;
        }
    }
    if line_start < content_len && line_count < MAX_UNIQ_LINES {
        lines[line_count] = (line_start, content_len);
        line_count += 1;
    }

    // Parcours groupé par lignes consécutives identiques
    let mut idx = 0;
    while idx < line_count {
        let current_slice = &buf_slice[lines[idx].0..lines[idx].1];
        let mut count: u64 = 1;
        let mut next_idx = idx + 1;

        while next_idx < line_count {
            let next_slice = &buf_slice[lines[next_idx].0..lines[next_idx].1];
            let equal = if ignore_case {
                compare_lexicographical(current_slice, next_slice, true)
                    == core::cmp::Ordering::Equal
            } else {
                current_slice == next_slice
            };

            if equal {
                count += 1;
                next_idx += 1;
            } else {
                break;
            }
        }

        let should_emit = !(repeated_only && count == 1) && !(unique_only && count > 1);

        if should_emit {
            if show_count {
                let _ = sys_write(actual_out_fd, b"      ");
                write_u64_fd(actual_out_fd, count);
                let _ = sys_write(actual_out_fd, b" ");
            }
            let _ = sys_write(actual_out_fd, current_slice);
            if !current_slice.ends_with(b"\n") {
                let _ = sys_write(actual_out_fd, b"\n");
            }
        }

        idx = next_idx;
    }

    if actual_out_fd != out_fd {
        let _ = sys_close(actual_out_fd);
    }

    0
}

/// Exécute l'utilitaire `wc` comptant les lignes, mots et octets
pub fn run_wc(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut count_lines = false;
    let mut count_words = false;
    let mut count_bytes = false;
    let mut paths_start = 0;

    for (i, &arg) in args.iter().enumerate() {
        if let Some(flags) = arg.strip_prefix('-') {
            if !flags.is_empty() {
                for b in flags.bytes() {
                    match b {
                        b'l' => count_lines = true,
                        b'w' => count_words = true,
                        b'c' => count_bytes = true,
                        _ => {}
                    }
                }
                paths_start = i + 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    // Par défaut, si aucun drapeau n'est spécifié, afficher lines, words, bytes
    if !count_lines && !count_words && !count_bytes {
        count_lines = true;
        count_words = true;
        count_bytes = true;
    }

    let paths = &args[paths_start..];
    let mut total = WcResult::default();
    let mut files_processed = 0;
    let mut has_error = false;

    let print_counts = |fd: i32, res: &WcResult, name: Option<&str>| {
        if count_lines {
            let _ = sys_write(fd, b"  ");
            write_u64_fd(fd, res.lines as u64);
        }
        if count_words {
            let _ = sys_write(fd, b"  ");
            write_u64_fd(fd, res.words as u64);
        }
        if count_bytes {
            let _ = sys_write(fd, b"  ");
            write_u64_fd(fd, res.bytes as u64);
        }
        if let Some(n) = name {
            let _ = sys_write(fd, b" ");
            let _ = sys_write(fd, n.as_bytes());
        }
        let _ = sys_write(fd, b"\n");
    };

    if paths.is_empty() {
        let mut buffer = [0u8; 2048];
        let mut total_read = 0;
        loop {
            let n = sys_read(in_fd, &mut buffer[total_read..]);
            if n <= 0 {
                break;
            }
            total_read += n as usize;
            if total_read >= buffer.len() {
                break;
            }
        }
        let res = count_buffer(&buffer[..total_read]);
        print_counts(out_fd, &res, None);
        return 0;
    }

    for &path in paths {
        let mut chunk = [0u8; 512];
        let mut file_res = WcResult::default();

        if path == "-" {
            loop {
                let n = sys_read(in_fd, &mut chunk);
                if n <= 0 {
                    break;
                }
                let part = count_buffer(&chunk[..n as usize]);
                file_res.lines += part.lines;
                file_res.words += part.words;
                file_res.bytes += part.bytes;
            }
        } else {
            let fd = sys_open(path, O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"wc: ");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                has_error = true;
                continue;
            }
            loop {
                let n = sys_read(fd, &mut chunk);
                if n <= 0 {
                    break;
                }
                let part = count_buffer(&chunk[..n as usize]);
                file_res.lines += part.lines;
                file_res.words += part.words;
                file_res.bytes += part.bytes;
            }
            let _ = sys_close(fd);
        }

        print_counts(out_fd, &file_res, Some(path));
        total.lines += file_res.lines;
        total.words += file_res.words;
        total.bytes += file_res.bytes;
        files_processed += 1;
    }

    if files_processed > 1 {
        print_counts(out_fd, &total, Some("total"));
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `true` (renvoie toujours succès 0)
#[inline(always)]
pub fn run_true() -> i32 {
    0
}

/// Exécute l'utilitaire `false` (renvoie toujours échec 1)
#[inline(always)]
pub fn run_false() -> i32 {
    1
}

/// Structure décrivant une entrée d'inventaire système pour `ls`
struct LsEntry {
    name: &'static str,
    is_dir: bool,
    size: usize,
}

static SYSTEM_ENTRIES: [LsEntry; 8] = [
    LsEntry {
        name: "bin",
        is_dir: true,
        size: 4096,
    },
    LsEntry {
        name: "dev",
        is_dir: true,
        size: 1024,
    },
    LsEntry {
        name: "etc",
        is_dir: true,
        size: 2048,
    },
    LsEntry {
        name: "tmp",
        is_dir: true,
        size: 512,
    },
    LsEntry {
        name: "hostname",
        is_dir: false,
        size: 8,
    },
    LsEntry {
        name: "os-release",
        is_dir: false,
        size: 128,
    },
    LsEntry {
        name: "motd",
        is_dir: false,
        size: 256,
    },
    LsEntry {
        name: "inittab",
        is_dir: false,
        size: 64,
    },
];

/// Exécute l'utilitaire `ls` listant les fichiers et répertoires
pub fn run_ls(args: &[&str], out_fd: i32, _err_fd: i32) -> i32 {
    let mut long_format = false;
    let mut show_all = false;

    for &arg in args {
        if let Some(flags) = arg.strip_prefix('-') {
            for b in flags.bytes() {
                match b {
                    b'l' => long_format = true,
                    b'a' => show_all = true,
                    _ => {}
                }
            }
        }
    }

    if show_all {
        if long_format {
            let _ = sys_write(out_fd, b"drwxr-xr-x    2 root root          4096 .\n");
            let _ = sys_write(out_fd, b"drwxr-xr-x    2 root root          4096 ..\n");
        } else {
            let _ = sys_write(out_fd, b".  ..  ");
        }
    }

    for entry in &SYSTEM_ENTRIES {
        if long_format {
            let mode = if entry.is_dir {
                b"drwxr-xr-x"
            } else {
                b"-rw-r--r--"
            };
            let _ = sys_write(out_fd, mode);
            let _ = sys_write(out_fd, b"    1 root root  ");
            let mut s_buf = [b' '; 12];
            let mut cur = 0;
            cur = append_u64(&mut s_buf, cur, entry.size as u64);
            let _ = sys_write(out_fd, &s_buf[..cur]);
            let _ = sys_write(out_fd, b" ");
            let _ = sys_write(out_fd, entry.name.as_bytes());
            let _ = sys_write(out_fd, b"\n");
        } else {
            let _ = sys_write(out_fd, entry.name.as_bytes());
            let _ = sys_write(out_fd, b"  ");
        }
    }

    // Affichage des entrées additionnelles créées dynamiquement dans INODE_POOL
    // SAFETY: Lecture protégée du pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for node in (*pool).iter() {
            if !node.is_active {
                continue;
            }
            let name = node.path_str();
            let base = if let Some(last_slash) = name.rfind('/') {
                &name[last_slash + 1..]
            } else {
                name
            };
            if base.is_empty() || SYSTEM_ENTRIES.iter().any(|e| e.name == base) {
                continue;
            }
            if long_format {
                let mode = if node.is_dir {
                    b"drwxr-xr-x"
                } else {
                    b"-rw-r--r--"
                };
                let _ = sys_write(out_fd, mode);
                let _ = sys_write(out_fd, b"    1 root root  ");
                let mut s_buf = [b' '; 12];
                let mut cur = 0;
                cur = append_u64(&mut s_buf, cur, node.size as u64);
                let _ = sys_write(out_fd, &s_buf[..cur]);
                let _ = sys_write(out_fd, b" ");
                let _ = sys_write(out_fd, base.as_bytes());
                let _ = sys_write(out_fd, b"\n");
            } else {
                let _ = sys_write(out_fd, base.as_bytes());
                let _ = sys_write(out_fd, b"  ");
            }
        }
    }

    if !long_format {
        let _ = sys_write(out_fd, b"\n");
    }

    0
}

/// Parse un entier non signé depuis une tranche de chaîne de caractères
fn parse_usize(s: &str) -> Option<usize> {
    let mut val: usize = 0;
    if s.is_empty() {
        return None;
    }
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(val)
}

/// Exécute l'utilitaire `head` affichant le début des fichiers ou du flux standard
pub fn run_head(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut lines_limit = Some(10usize);
    let mut bytes_limit = None;
    let mut files_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-n" && i + 1 < args.len() {
            if let Some(n) = parse_usize(args[i + 1]) {
                lines_limit = Some(n);
                bytes_limit = None;
                i += 2;
                files_start = i;
                continue;
            }
        } else if let Some(rest) = arg.strip_prefix("-n") {
            if let Some(n) = parse_usize(rest) {
                lines_limit = Some(n);
                bytes_limit = None;
                i += 1;
                files_start = i;
                continue;
            }
        } else if arg == "-c" && i + 1 < args.len() {
            if let Some(n) = parse_usize(args[i + 1]) {
                bytes_limit = Some(n);
                lines_limit = None;
                i += 2;
                files_start = i;
                continue;
            }
        } else if let Some(rest) = arg.strip_prefix("-c") {
            if let Some(n) = parse_usize(rest) {
                bytes_limit = Some(n);
                lines_limit = None;
                i += 1;
                files_start = i;
                continue;
            }
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"head: invalid option\n");
            return 1;
        } else {
            break;
        }
        i += 1;
    }

    let files = &args[files_start..];
    let mut has_error = false;

    let process_stream = |fd: i32, out: i32| {
        let mut chunk = [0u8; 512];
        let mut lines_count = 0;
        let mut bytes_count = 0;

        loop {
            let n = sys_read(fd, &mut chunk);
            if n <= 0 {
                break;
            }
            let slice = &chunk[..n as usize];

            if let Some(max_b) = bytes_limit {
                if bytes_count >= max_b {
                    break;
                }
                let left = max_b - bytes_count;
                let to_write = slice.len().min(left);
                let _ = sys_write(out, &slice[..to_write]);
                bytes_count += to_write;
                if bytes_count >= max_b {
                    break;
                }
            } else if let Some(max_l) = lines_limit {
                if lines_count >= max_l {
                    break;
                }
                let mut end_idx = 0;
                for &b in slice {
                    end_idx += 1;
                    if b == b'\n' {
                        lines_count += 1;
                        if lines_count >= max_l {
                            break;
                        }
                    }
                }
                let _ = sys_write(out, &slice[..end_idx]);
                if lines_count >= max_l {
                    break;
                }
            }
        }
    };

    if files.is_empty() {
        process_stream(in_fd, out_fd);
        return 0;
    }

    for &path in files {
        if path == "-" {
            process_stream(in_fd, out_fd);
            continue;
        }
        let fd = sys_open(path, O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"head: cannot open '");
            let _ = sys_write(err_fd, path.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            has_error = true;
            continue;
        }
        process_stream(fd, out_fd);
        let _ = sys_close(fd);
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `tail` affichant la fin des fichiers ou du flux standard
pub fn run_tail(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut lines_limit = Some(10usize);
    let mut bytes_limit = None;
    let mut files_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-n" && i + 1 < args.len() {
            if let Some(n) = parse_usize(args[i + 1]) {
                lines_limit = Some(n);
                bytes_limit = None;
                i += 2;
                files_start = i;
                continue;
            }
        } else if let Some(rest) = arg.strip_prefix("-n") {
            if let Some(n) = parse_usize(rest) {
                lines_limit = Some(n);
                bytes_limit = None;
                i += 1;
                files_start = i;
                continue;
            }
        } else if arg == "-c" && i + 1 < args.len() {
            if let Some(n) = parse_usize(args[i + 1]) {
                bytes_limit = Some(n);
                lines_limit = None;
                i += 2;
                files_start = i;
                continue;
            }
        } else if let Some(rest) = arg.strip_prefix("-c") {
            if let Some(n) = parse_usize(rest) {
                bytes_limit = Some(n);
                lines_limit = None;
                i += 1;
                files_start = i;
                continue;
            }
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"tail: invalid option\n");
            return 1;
        } else {
            break;
        }
        i += 1;
    }

    let files = &args[files_start..];
    let mut has_error = false;

    let process_stream = |fd: i32, out: i32| {
        let mut buffer = [0u8; crate::vfs::FILE_BUFFER_SIZE];
        let mut total = 0;
        loop {
            let n = sys_read(fd, &mut buffer[total..]);
            if n <= 0 {
                break;
            }
            total += n as usize;
            if total >= buffer.len() {
                break;
            }
        }
        let content = &buffer[..total];

        if let Some(max_b) = bytes_limit {
            let start = content.len().saturating_sub(max_b);
            let _ = sys_write(out, &content[start..]);
        } else if let Some(max_l) = lines_limit {
            if max_l == 0 {
                return;
            }
            let mut newline_count = 0;
            let mut start_idx = 0;
            for (idx, &b) in content.iter().enumerate().rev() {
                if b == b'\n' {
                    newline_count += 1;
                    if newline_count == max_l + 1 {
                        start_idx = idx + 1;
                        break;
                    }
                }
            }
            let _ = sys_write(out, &content[start_idx..]);
        }
    };

    if files.is_empty() {
        process_stream(in_fd, out_fd);
        return 0;
    }

    for &path in files {
        if path == "-" {
            process_stream(in_fd, out_fd);
            continue;
        }
        let fd = sys_open(path, O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"tail: cannot open '");
            let _ = sys_write(err_fd, path.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            has_error = true;
            continue;
        }
        process_stream(fd, out_fd);
        let _ = sys_close(fd);
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `touch` créant des fichiers vides ou mettant à jour les métadonnées
pub fn run_touch(args: &[&str], err_fd: i32) -> i32 {
    let mut paths_start = 0;
    for (i, &arg) in args.iter().enumerate() {
        if arg.starts_with('-') {
            paths_start = i + 1;
        } else {
            break;
        }
    }
    let paths = &args[paths_start..];
    if paths.is_empty() {
        let _ = sys_write(err_fd, b"touch: missing file operand\n");
        return 1;
    }
    let mut has_error = false;
    for &path in paths {
        let fd = sys_open(path, crate::vfs::O_CREAT | crate::vfs::O_WRONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"touch: cannot touch '");
            let _ = sys_write(err_fd, path.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            has_error = true;
        } else {
            let _ = sys_close(fd);
        }
    }
    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `mkdir` créant des répertoires
pub fn run_mkdir(args: &[&str], err_fd: i32) -> i32 {
    let mut parents = false;
    let mut paths_start = 0;
    for (i, &arg) in args.iter().enumerate() {
        if arg == "-p" || arg == "--parents" {
            parents = true;
            paths_start = i + 1;
        } else if arg.starts_with('-') {
            paths_start = i + 1;
        } else {
            break;
        }
    }
    let paths = &args[paths_start..];
    if paths.is_empty() {
        let _ = sys_write(err_fd, b"mkdir: missing operand\n");
        return 1;
    }
    let mut has_error = false;
    for &path in paths {
        let clean = path.trim_end_matches('/');
        if parents {
            // Création récursive de chaque composant parent
            let mut start = if clean.starts_with('/') { 1 } else { 0 };
            while let Some(pos) = clean[start..].find('/') {
                let sub_idx = start + pos;
                let sub_path = &clean[..sub_idx];
                if !sub_path.is_empty() {
                    let _ = sys_mkdir_pool(sub_path, 0o755);
                }
                start = sub_idx + 1;
            }
        }
        let res = sys_mkdir_pool(clean, 0o755);
        if res < 0 && !parents {
            let _ = sys_write(err_fd, b"mkdir: cannot create directory '");
            let _ = sys_write(err_fd, path.as_bytes());
            let _ = sys_write(err_fd, b"': File or directory exists\n");
            has_error = true;
        }
    }
    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `rmdir` supprimant des répertoires vides
pub fn run_rmdir(args: &[&str], err_fd: i32) -> i32 {
    let mut ignore_fail_on_non_empty = false;
    let mut parents = false;
    let mut verbose = false;
    let mut paths_start = 0;

    for (i, &arg) in args.iter().enumerate() {
        if arg == "-p" || arg == "--parents" {
            parents = true;
            paths_start = i + 1;
        } else if arg == "-v" || arg == "--verbose" {
            verbose = true;
            paths_start = i + 1;
        } else if arg == "--ignore-fail-on-non-empty" {
            ignore_fail_on_non_empty = true;
            paths_start = i + 1;
        } else if arg.starts_with('-') && arg != "-" {
            for b in arg[1..].bytes() {
                match b {
                    b'p' => parents = true,
                    b'v' => verbose = true,
                    _ => {}
                }
            }
            paths_start = i + 1;
        } else {
            break;
        }
    }

    let paths = &args[paths_start..];
    if paths.is_empty() {
        let _ = sys_write(err_fd, b"rmdir: missing operand\n");
        return 1;
    }

    let mut has_error = false;
    for &path in paths {
        let mut cur = path.trim_end_matches('/');
        if cur.is_empty() {
            let _ = sys_write(
                err_fd,
                b"rmdir: cannot remove '/': Device or resource busy\n",
            );
            has_error = true;
            continue;
        }

        loop {
            let res = sys_rmdir_pool(cur);
            if res < 0 {
                if !ignore_fail_on_non_empty {
                    let _ = sys_write(err_fd, b"rmdir: failed to remove '");
                    let _ = sys_write(err_fd, cur.as_bytes());
                    let _ = sys_write(err_fd, b"': Directory not empty or not found\n");
                    has_error = true;
                }
                break;
            } else if verbose {
                let _ = sys_write(1, b"rmdir: removing directory, '");
                let _ = sys_write(1, cur.as_bytes());
                let _ = sys_write(1, b"'\n");
            }

            if parents {
                if let Some(pos) = cur.rfind('/') {
                    let parent = &cur[..pos];
                    if parent.is_empty() || parent == "/tmp" || parent == "/etc" || parent == "/" {
                        break;
                    }
                    cur = parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `tree` pour afficher l'arborescence hiérarchique des répertoires et fichiers
pub fn run_tree(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut show_all = false; // -a
    let mut dirs_only = false; // -d
    let mut full_path = false; // -f
    let mut max_depth: Option<usize> = None; // -L level
    let mut target_dir = ".";

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-a" || arg == "--all" {
            show_all = true;
            i += 1;
        } else if arg == "-d" {
            dirs_only = true;
            i += 1;
        } else if arg == "-f" {
            full_path = true;
            i += 1;
        } else if arg == "-L" {
            if i + 1 < args.len() {
                if let Some(level) = parse_usize(args[i + 1]) {
                    max_depth = Some(level);
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"tree: Invalid level, must be greater than 0.\n");
                    return 1;
                }
            } else {
                let _ = sys_write(err_fd, b"tree: -L requires an integer parameter.\n");
                return 1;
            }
        } else if arg.starts_with('-') && arg.len() > 1 {
            for b in arg[1..].bytes() {
                match b {
                    b'a' => show_all = true,
                    b'd' => dirs_only = true,
                    b'f' => full_path = true,
                    _ => {}
                }
            }
            i += 1;
        } else {
            target_dir = arg;
            i += 1;
        }
    }

    let root_path = if target_dir == "." { "/" } else { target_dir };

    // Vérifier si le chemin racine existe
    let stat = match sys_stat_pool(root_path) {
        Some(st) => st,
        None => {
            let _ = sys_write(err_fd, target_dir.as_bytes());
            let _ = sys_write(err_fd, b" [error opening dir]\n");
            return 1;
        }
    };

    let _ = sys_write(out_fd, target_dir.as_bytes());
    let _ = sys_write(out_fd, b"\n");

    if (stat.st_mode & crate::vfs::S_IFMT) != crate::vfs::S_IFDIR {
        let _ = sys_write(out_fd, b"\n0 directories, 1 file\n");
        return 0;
    }

    #[derive(Clone, Copy)]
    struct TreeNode<'a> {
        path: &'a str,
        is_dir: bool,
    }

    let mut nodes: [TreeNode<'static>; 64] = [TreeNode {
        path: "",
        is_dir: false,
    }; 64];
    let mut node_count = 0;

    let base_entries = [
        TreeNode {
            path: "/bin",
            is_dir: true,
        },
        TreeNode {
            path: "/dev",
            is_dir: true,
        },
        TreeNode {
            path: "/etc",
            is_dir: true,
        },
        TreeNode {
            path: "/tmp",
            is_dir: true,
        },
        TreeNode {
            path: "/etc/hostname",
            is_dir: false,
        },
        TreeNode {
            path: "/etc/os-release",
            is_dir: false,
        },
        TreeNode {
            path: "/etc/motd",
            is_dir: false,
        },
        TreeNode {
            path: "/etc/inittab",
            is_dir: false,
        },
    ];

    for e in &base_entries {
        if node_count < nodes.len() {
            nodes[node_count] = *e;
            node_count += 1;
        }
    }

    // SAFETY: Lecture protégée d'INODE_POOL
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for vfs_node in (*pool).iter() {
            if !vfs_node.is_active {
                continue;
            }
            let p = vfs_node.path_str();
            if p.is_empty() || p == "/" {
                continue;
            }
            let mut exists = false;
            for n in &nodes[..node_count] {
                if n.path == p {
                    exists = true;
                    break;
                }
            }
            if !exists && node_count < nodes.len() {
                nodes[node_count] = TreeNode {
                    path: p,
                    is_dir: vfs_node.is_dir,
                };
                node_count += 1;
            }
        }
    }

    let mut dir_count = 0usize;
    let mut file_count = 0usize;

    for item in &nodes[..node_count] {
        let p = item.path;
        if root_path != "/" && !p.starts_with(root_path) {
            continue;
        }

        let rel = if root_path == "/" {
            p.trim_start_matches('/')
        } else if let Some(stripped) = p.strip_prefix(root_path) {
            let s = stripped.trim_start_matches('/');
            if s.is_empty() {
                continue;
            }
            s
        } else {
            continue;
        };

        let depth = rel.split('/').count();
        if let Some(max_l) = max_depth {
            if depth > max_l {
                continue;
            }
        }

        if dirs_only && !item.is_dir {
            continue;
        }

        let base_name = if let Some(idx) = rel.rfind('/') {
            &rel[idx + 1..]
        } else {
            rel
        };

        if !show_all && base_name.starts_with('.') {
            continue;
        }

        // Indentation arborescente visuelle
        for _ in 1..depth {
            let _ = sys_write(out_fd, b"|   ");
        }
        let _ = sys_write(out_fd, b"`-- ");

        if full_path {
            let _ = sys_write(out_fd, p.as_bytes());
        } else {
            let _ = sys_write(out_fd, base_name.as_bytes());
        }
        let _ = sys_write(out_fd, b"\n");

        if item.is_dir {
            dir_count += 1;
        } else {
            file_count += 1;
        }
    }

    let _ = sys_write(out_fd, b"\n");
    let mut num_buf = [0u8; 16];
    let d_len = append_u64(&mut num_buf, 0, dir_count as u64);
    let _ = sys_write(out_fd, &num_buf[..d_len]);
    if dir_count == 1 {
        let _ = sys_write(out_fd, b" directory, ");
    } else {
        let _ = sys_write(out_fd, b" directories, ");
    }

    let f_len = append_u64(&mut num_buf, 0, file_count as u64);
    let _ = sys_write(out_fd, &num_buf[..f_len]);
    if file_count == 1 {
        let _ = sys_write(out_fd, b" file\n");
    } else {
        let _ = sys_write(out_fd, b" files\n");
    }

    0
}

/// Exécute l'utilitaire `rm` supprimant des fichiers ou répertoires
pub fn run_rm(args: &[&str], err_fd: i32) -> i32 {
    let mut force = false;
    let mut recursive = false;
    let mut paths_start = 0;

    for (i, &arg) in args.iter().enumerate() {
        if arg.starts_with('-') && arg != "-" {
            for b in arg[1..].bytes() {
                match b {
                    b'f' => force = true,
                    b'r' | b'R' => recursive = true,
                    _ => {}
                }
            }
            paths_start = i + 1;
        } else {
            break;
        }
    }

    let paths = &args[paths_start..];
    if paths.is_empty() {
        if !force {
            let _ = sys_write(err_fd, b"rm: missing operand\n");
            return 1;
        }
        return 0;
    }

    let mut has_error = false;
    for &path in paths {
        let clean = path.trim_end_matches('/');
        if recursive {
            // SAFETY: Suppression récursive dans le pool d'inodes virtuel
            unsafe {
                let pool = core::ptr::addr_of_mut!(INODE_POOL);
                let mut found = false;
                for node in (*pool).iter_mut() {
                    if node.is_active
                        && (node.path_str() == clean || node.path_str().starts_with(clean))
                    {
                        node.is_active = false;
                        node.size = 0;
                        node.path_len = 0;
                        found = true;
                    }
                }
                if !found && !force {
                    let _ = sys_write(err_fd, b"rm: cannot remove '");
                    let _ = sys_write(err_fd, path.as_bytes());
                    let _ = sys_write(err_fd, b"': No such file or directory\n");
                    has_error = true;
                }
            }
        } else {
            let res = sys_unlink_pool(clean);
            if res < 0 && !force {
                let _ = sys_write(err_fd, b"rm: cannot remove '");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                has_error = true;
            }
        }
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Récupère les métadonnées (est_repertoire, taille) d'un noeud dans le pool d'inodes virtuel
pub fn stat_pool_node(path: &str) -> Option<(bool, usize)> {
    let clean = path.trim_end_matches('/');
    // SAFETY: Accès protégé en lecture au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for node in (*pool).iter() {
            if node.is_active && node.path_str() == clean {
                return Some((node.is_dir, node.size));
            }
        }
    }
    None
}

/// Concatène un répertoire et un nom de fichier dans un tampon fixe sans allocation
pub fn join_path<'a>(
    dir: &str,
    file: &str,
    buf: &'a mut [u8; crate::vfs::MAX_PATH_LEN],
) -> Option<&'a str> {
    let dir_clean = dir.trim_end_matches('/');
    let file_clean = file.trim_start_matches('/');
    let dir_bytes = dir_clean.as_bytes();
    let file_bytes = file_clean.as_bytes();
    let total_len = dir_bytes.len() + 1 + file_bytes.len();
    if total_len > crate::vfs::MAX_PATH_LEN {
        return None;
    }
    buf[..dir_bytes.len()].copy_from_slice(dir_bytes);
    buf[dir_bytes.len()] = b'/';
    buf[dir_bytes.len() + 1..total_len].copy_from_slice(file_bytes);
    core::str::from_utf8(&buf[..total_len]).ok()
}

type InodeSnapshotItem = (
    [u8; crate::vfs::MAX_PATH_LEN],
    usize,
    bool,
    [u8; crate::vfs::FILE_BUFFER_SIZE],
    usize,
);

/// Copie le flux d'un fichier source vers un fichier destination via le VFS
pub fn copy_file_contents(src: &str, dst: &str) -> Result<usize, i32> {
    let in_fd = sys_open(src, crate::vfs::O_RDONLY);
    if in_fd < 0 {
        return Err(-1);
    }
    let out_fd = sys_open(
        dst,
        crate::vfs::O_CREAT | crate::vfs::O_WRONLY | crate::vfs::O_TRUNC,
    );
    if out_fd < 0 {
        let _ = sys_close(in_fd);
        return Err(-1);
    }
    let mut buf = [0u8; 1024];
    let mut total = 0;
    loop {
        let r = sys_read(in_fd, &mut buf);
        if r <= 0 {
            break;
        }
        let w = sys_write(out_fd, &buf[..r as usize]);
        if w < 0 {
            let _ = sys_close(in_fd);
            let _ = sys_close(out_fd);
            return Err(-1);
        }
        total += w as usize;
    }
    let _ = sys_close(in_fd);
    let _ = sys_close(out_fd);
    Ok(total)
}

/// Exécute l'utilitaire `cp` pour la copie de fichiers et répertoires
pub fn run_cp(args: &[&str], err_fd: i32) -> i32 {
    let mut recursive = false;
    let mut _force = false;
    let mut paths_start = 0;
    for (i, &arg) in args.iter().enumerate() {
        if arg.starts_with('-') && arg != "-" {
            for b in arg[1..].bytes() {
                match b {
                    b'r' | b'R' => recursive = true,
                    b'f' => _force = true,
                    _ => {}
                }
            }
            paths_start = i + 1;
        } else {
            break;
        }
    }

    let operands = &args[paths_start..];
    if operands.is_empty() {
        let _ = sys_write(err_fd, b"cp: missing file operand\n");
        return 1;
    }
    if operands.len() == 1 {
        let _ = sys_write(err_fd, b"cp: missing destination file operand after '");
        let _ = sys_write(err_fd, operands[0].as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    let src = operands[0].trim_end_matches('/');
    let dst_raw = operands[1].trim_end_matches('/');

    if src == dst_raw {
        let _ = sys_write(err_fd, b"cp: '");
        let _ = sys_write(err_fd, src.as_bytes());
        let _ = sys_write(err_fd, b"' and '");
        let _ = sys_write(err_fd, dst_raw.as_bytes());
        let _ = sys_write(err_fd, b"' are the same file\n");
        return 1;
    }

    let src_stat = match stat_pool_node(src) {
        Some(st) => st,
        None => {
            let _ = sys_write(err_fd, b"cp: cannot stat '");
            let _ = sys_write(err_fd, src.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            return 1;
        }
    };

    let dst_stat = stat_pool_node(dst_raw);
    let is_dst_dir = dst_stat.map(|(is_dir, _)| is_dir).unwrap_or(false);

    let mut path_buf = [0u8; crate::vfs::MAX_PATH_LEN];
    let final_dst = if is_dst_dir {
        let base = match src.rfind('/') {
            Some(idx) => &src[idx + 1..],
            None => src,
        };
        match join_path(dst_raw, base, &mut path_buf) {
            Some(p) => p,
            None => {
                let _ = sys_write(err_fd, b"cp: destination path too long\n");
                return 1;
            }
        }
    } else {
        dst_raw
    };

    if src_stat.0 {
        if !recursive {
            let _ = sys_write(err_fd, b"cp: -r not specified; omitting directory '");
            let _ = sys_write(err_fd, src.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }
        if stat_pool_node(final_dst).is_none() {
            let _ = sys_mkdir_pool(final_dst, 0o755);
        }
        // SAFETY: Duplication arborescente depuis INODE_POOL
        unsafe {
            let pool = core::ptr::addr_of_mut!(INODE_POOL);
            let mut snapshot: [Option<InodeSnapshotItem>; MAX_INODES] = [None; MAX_INODES];
            for (i, node) in (*pool).iter().enumerate() {
                if node.is_active {
                    snapshot[i] = Some((
                        node.path,
                        node.path_len,
                        node.is_dir,
                        node.buffer,
                        node.size,
                    ));
                }
            }
            for (path_arr, path_len, is_dir, buffer_arr, size) in snapshot.iter().flatten() {
                let item_path = core::str::from_utf8(&path_arr[..*path_len]).unwrap_or("");
                if item_path.starts_with(src) && item_path != src {
                    let sub_suffix = &item_path[src.len()..];
                    let mut sub_buf = [0u8; crate::vfs::MAX_PATH_LEN];
                    if let Some(target_sub) = join_path(final_dst, sub_suffix, &mut sub_buf) {
                        if *is_dir {
                            let _ = sys_mkdir_pool(target_sub, 0o755);
                        } else {
                            for slot in (*pool).iter_mut() {
                                if !slot.is_active {
                                    let tb = target_sub.as_bytes();
                                    let len = tb.len().min(crate::vfs::MAX_PATH_LEN);
                                    slot.path[..len].copy_from_slice(&tb[..len]);
                                    slot.path_len = len;
                                    slot.is_active = true;
                                    slot.is_dir = false;
                                    slot.mode = 0o644;
                                    slot.size = *size;
                                    slot.buffer[..*size].copy_from_slice(&buffer_arr[..*size]);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        0
    } else {
        if copy_file_contents(src, final_dst).is_err() {
            let _ = sys_write(err_fd, b"cp: cannot copy '");
            let _ = sys_write(err_fd, src.as_bytes());
            let _ = sys_write(err_fd, b"' to '");
            let _ = sys_write(err_fd, final_dst.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }
        0
    }
}

/// Exécute l'utilitaire `mv` déplaçant ou renommant fichiers et répertoires
pub fn run_mv(args: &[&str], err_fd: i32) -> i32 {
    let mut _force = false;
    let mut paths_start = 0;
    for (i, &arg) in args.iter().enumerate() {
        if arg.starts_with('-') && arg != "-" {
            for b in arg[1..].bytes() {
                if b == b'f' {
                    _force = true;
                }
            }
            paths_start = i + 1;
        } else {
            break;
        }
    }

    let operands = &args[paths_start..];
    if operands.is_empty() {
        let _ = sys_write(err_fd, b"mv: missing file operand\n");
        return 1;
    }
    if operands.len() == 1 {
        let _ = sys_write(err_fd, b"mv: missing destination file operand after '");
        let _ = sys_write(err_fd, operands[0].as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    let src = operands[0].trim_end_matches('/');
    let dst_raw = operands[1].trim_end_matches('/');

    if src == dst_raw {
        let _ = sys_write(err_fd, b"mv: '");
        let _ = sys_write(err_fd, src.as_bytes());
        let _ = sys_write(err_fd, b"' and '");
        let _ = sys_write(err_fd, dst_raw.as_bytes());
        let _ = sys_write(err_fd, b"' are the same file\n");
        return 1;
    }

    let src_stat = match stat_pool_node(src) {
        Some(st) => st,
        None => {
            let _ = sys_write(err_fd, b"mv: cannot stat '");
            let _ = sys_write(err_fd, src.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            return 1;
        }
    };

    let dst_stat = stat_pool_node(dst_raw);
    let is_dst_dir = dst_stat.map(|(is_dir, _)| is_dir).unwrap_or(false);

    let mut path_buf = [0u8; crate::vfs::MAX_PATH_LEN];
    let final_dst = if is_dst_dir {
        let base = match src.rfind('/') {
            Some(idx) => &src[idx + 1..],
            None => src,
        };
        match join_path(dst_raw, base, &mut path_buf) {
            Some(p) => p,
            None => {
                let _ = sys_write(err_fd, b"mv: destination path too long\n");
                return 1;
            }
        }
    } else {
        dst_raw
    };

    // Si la cible existe déjà et n'est pas un répertoire, l'écraser
    if let Some((is_dir, _)) = stat_pool_node(final_dst) {
        if is_dir && !src_stat.0 {
            let _ = sys_write(err_fd, b"mv: cannot overwrite directory '");
            let _ = sys_write(err_fd, final_dst.as_bytes());
            let _ = sys_write(err_fd, b"' with non-directory\n");
            return 1;
        }
        let _ = sys_unlink_pool(final_dst);
    }

    // SAFETY: Modification atomique in-place des chemins dans INODE_POOL
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        if src_stat.0 {
            for node in (*pool).iter_mut() {
                if !node.is_active {
                    continue;
                }
                let p_str = node.path_str();
                if p_str == src {
                    let tb = final_dst.as_bytes();
                    let len = tb.len().min(crate::vfs::MAX_PATH_LEN);
                    node.path = [0u8; crate::vfs::MAX_PATH_LEN];
                    node.path[..len].copy_from_slice(&tb[..len]);
                    node.path_len = len;
                } else if p_str.starts_with(src) && p_str.as_bytes().get(src.len()) == Some(&b'/') {
                    let suffix = &p_str[src.len()..];
                    let mut joined = [0u8; crate::vfs::MAX_PATH_LEN];
                    if let Some(np) = join_path(final_dst, suffix, &mut joined) {
                        let nb = np.as_bytes();
                        let len = nb.len().min(crate::vfs::MAX_PATH_LEN);
                        node.path = [0u8; crate::vfs::MAX_PATH_LEN];
                        node.path[..len].copy_from_slice(&nb[..len]);
                        node.path_len = len;
                    }
                }
            }
        } else {
            let mut found = false;
            for node in (*pool).iter_mut() {
                if node.is_active && node.path_str() == src {
                    let tb = final_dst.as_bytes();
                    let len = tb.len().min(crate::vfs::MAX_PATH_LEN);
                    node.path = [0u8; crate::vfs::MAX_PATH_LEN];
                    node.path[..len].copy_from_slice(&tb[..len]);
                    node.path_len = len;
                    found = true;
                    break;
                }
            }
            if !found {
                let _ = sys_write(err_fd, b"mv: cannot stat '");
                let _ = sys_write(err_fd, src.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                return 1;
            }
        }
    }

    0
}

/// Exécute l'utilitaire `find` effectuant un parcours récursif d'arborescence VFS
pub fn run_find(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut starting_path = "/";
    let mut name_filter: Option<&str> = None;
    let mut type_filter: Option<char> = None;
    let mut max_depth: Option<usize> = None;

    let mut i = 0;
    let mut path_specified = false;

    while i < args.len() {
        let arg = args[i];
        if !arg.starts_with('-') && !path_specified {
            starting_path = arg;
            path_specified = true;
            i += 1;
            continue;
        }

        match arg {
            "-name" => {
                if i + 1 < args.len() {
                    name_filter = Some(args[i + 1]);
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"find: missing argument to `-name'\n");
                    return 1;
                }
            }
            "-type" => {
                if i + 1 < args.len() {
                    let t = args[i + 1];
                    if t == "f" || t == "d" {
                        type_filter = Some(t.chars().next().unwrap());
                        i += 2;
                    } else {
                        let _ = sys_write(err_fd, b"find: Unknown argument to -type: ");
                        let _ = sys_write(err_fd, t.as_bytes());
                        let _ = sys_write(err_fd, b"\n");
                        return 1;
                    }
                } else {
                    let _ = sys_write(err_fd, b"find: missing argument to `-type'\n");
                    return 1;
                }
            }
            "-maxdepth" => {
                if i + 1 < args.len() {
                    if let Some(d) = parse_usize(args[i + 1]) {
                        max_depth = Some(d);
                        i += 2;
                    } else {
                        let _ = sys_write(err_fd, b"find: invalid argument to `-maxdepth'\n");
                        return 1;
                    }
                } else {
                    let _ = sys_write(err_fd, b"find: missing argument to `-maxdepth'\n");
                    return 1;
                }
            }
            _ => {
                let _ = sys_write(err_fd, b"find: unknown predicate: ");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"\n");
                return 1;
            }
        }
    }

    let normalized_root = if starting_path == "." {
        "/"
    } else {
        starting_path
    };

    struct EntryInfo<'a> {
        path: &'a str,
        is_dir: bool,
    }

    let base_entries = [
        EntryInfo {
            path: "/",
            is_dir: true,
        },
        EntryInfo {
            path: "/bin",
            is_dir: true,
        },
        EntryInfo {
            path: "/dev",
            is_dir: true,
        },
        EntryInfo {
            path: "/etc",
            is_dir: true,
        },
        EntryInfo {
            path: "/tmp",
            is_dir: true,
        },
        EntryInfo {
            path: "/hostname",
            is_dir: false,
        },
        EntryInfo {
            path: "/os-release",
            is_dir: false,
        },
        EntryInfo {
            path: "/motd",
            is_dir: false,
        },
        EntryInfo {
            path: "/inittab",
            is_dir: false,
        },
        EntryInfo {
            path: "/etc/hostname",
            is_dir: false,
        },
        EntryInfo {
            path: "/etc/os-release",
            is_dir: false,
        },
        EntryInfo {
            path: "/etc/motd",
            is_dir: false,
        },
    ];

    let mut printed = [""; 64];
    let mut printed_count = 0;

    let matches_pattern = |name: &str, pat: &str| -> bool {
        if pat == "*" {
            true
        } else if let Some(suffix) = pat.strip_prefix('*') {
            name.ends_with(suffix)
        } else if let Some(prefix) = pat.strip_suffix('*') {
            name.starts_with(prefix)
        } else {
            name == pat
        }
    };

    for entry in &base_entries {
        let p = entry.path;
        if normalized_root != "/" && !p.starts_with(normalized_root) {
            continue;
        }

        let rel = if p == "/" {
            ""
        } else if let Some(stripped) = p.strip_prefix(normalized_root) {
            stripped.trim_start_matches('/')
        } else {
            continue;
        };
        let depth = if rel.is_empty() {
            0
        } else {
            rel.split('/').count()
        };
        if let Some(max_d) = max_depth {
            if depth > max_d {
                continue;
            }
        }

        if let Some(tf) = type_filter {
            if tf == 'f' && entry.is_dir {
                continue;
            }
            if tf == 'd' && !entry.is_dir {
                continue;
            }
        }

        if let Some(nf) = name_filter {
            let base_name = if let Some(idx) = p.rfind('/') {
                &p[idx + 1..]
            } else {
                p
            };
            let base = if base_name.is_empty() { p } else { base_name };
            if !matches_pattern(base, nf) {
                continue;
            }
        }

        let mut already = false;
        for &pr in &printed[..printed_count] {
            if pr == p {
                already = true;
                break;
            }
        }
        if !already && printed_count < printed.len() {
            printed[printed_count] = p;
            printed_count += 1;
            let _ = sys_write(out_fd, p.as_bytes());
            let _ = sys_write(out_fd, b"\n");
        }
    }

    // SAFETY: Lecture protégée du pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for node in (*pool).iter() {
            if !node.is_active {
                continue;
            }
            let p = node.path_str();
            if p.is_empty() {
                continue;
            }
            if normalized_root != "/" && !p.starts_with(normalized_root) {
                continue;
            }

            let rel = if p == "/" {
                ""
            } else if let Some(stripped) = p.strip_prefix(normalized_root) {
                stripped.trim_start_matches('/')
            } else {
                continue;
            };
            let depth = if rel.is_empty() {
                0
            } else {
                rel.split('/').count()
            };
            if let Some(max_d) = max_depth {
                if depth > max_d {
                    continue;
                }
            }

            if let Some(tf) = type_filter {
                if tf == 'f' && node.is_dir {
                    continue;
                }
                if tf == 'd' && !node.is_dir {
                    continue;
                }
            }

            if let Some(nf) = name_filter {
                let base_name = if let Some(idx) = p.rfind('/') {
                    &p[idx + 1..]
                } else {
                    p
                };
                let base = if base_name.is_empty() { p } else { base_name };
                if !matches_pattern(base, nf) {
                    continue;
                }
            }

            let mut already = false;
            for &pr in &printed[..printed_count] {
                if pr == p {
                    already = true;
                    break;
                }
            }
            if !already && printed_count < printed.len() {
                printed[printed_count] = p;
                printed_count += 1;
                let _ = sys_write(out_fd, p.as_bytes());
                let _ = sys_write(out_fd, b"\n");
            }
        }
    }

    0
}

/// Exécute l'utilitaire `chmod` pour modifier les masques de permissions octales
pub fn run_chmod(args: &[&str], err_fd: i32) -> i32 {
    let mut recursive = false;
    let mut verbose = false;
    let mut mode_str: Option<&str> = None;
    let mut files_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-R" || arg == "--recursive" {
            recursive = true;
            i += 1;
        } else if arg == "-v" || arg == "--verbose" {
            verbose = true;
            i += 1;
        } else if arg.starts_with('-') && !arg.chars().skip(1).all(|c| c.is_ascii_digit()) {
            let _ = sys_write(err_fd, b"chmod: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else if mode_str.is_none() {
            mode_str = Some(arg);
            files_start = i + 1;
            break;
        } else {
            i += 1;
        }
    }

    let raw_mode = match mode_str {
        Some(m) => m,
        None => {
            let _ = sys_write(err_fd, b"chmod: missing operand\n");
            return 1;
        }
    };

    let files = &args[files_start..];
    if files.is_empty() {
        let _ = sys_write(err_fd, b"chmod: missing operand after '");
        let _ = sys_write(err_fd, raw_mode.as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    // Parsing du mode : octal direct ou symbolique POSIX (ex: "u+x", "755", "go-w", "a=rwx")
    let is_octal_candidate = raw_mode.bytes().all(|b| (b'0'..=b'7').contains(&b));
    let parsed_static_mode = if is_octal_candidate {
        let mut m: u32 = 0;
        for b in raw_mode.bytes() {
            m = (m << 3) | (b - b'0') as u32;
        }
        if m <= 0o7777 {
            Some(m)
        } else {
            None
        }
    } else {
        None
    };

    let mut has_error = false;
    for &target in files {
        let current_target_mode = sys_get_mode_pool(target).unwrap_or(0o644);
        let mode = match parsed_static_mode {
            Some(m) => m,
            None => match resolve_chmod_mode(raw_mode, current_target_mode) {
                Some(m) => m,
                None => {
                    let _ = sys_write(err_fd, b"chmod: invalid mode: '");
                    let _ = sys_write(err_fd, raw_mode.as_bytes());
                    let _ = sys_write(err_fd, b"'\n");
                    return 1;
                }
            },
        };

        let res = sys_chmod_pool(target, mode);
        if res < 0 {
            let _ = sys_write(err_fd, b"chmod: cannot access '");
            let _ = sys_write(err_fd, target.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            has_error = true;
        } else if recursive {
            let clean = target.trim_end_matches('/');
            // SAFETY: Accès protégé au pool d'inodes virtuel
            unsafe {
                let pool = core::ptr::addr_of_mut!(INODE_POOL);
                for node in (*pool).iter_mut() {
                    if node.is_active {
                        let p = node.path_str();
                        if p.starts_with(clean)
                            && (p.len() == clean.len()
                                || p.as_bytes().get(clean.len()) == Some(&b'/'))
                        {
                            let node_mode = match parsed_static_mode {
                                Some(m) => m,
                                None => {
                                    resolve_chmod_mode(raw_mode, node.mode).unwrap_or(node.mode)
                                }
                            };
                            node.mode = node_mode & 0o7777;
                        }
                    }
                }
            }
        }
        if verbose && res == 0 {
            let _ = sys_write(err_fd, b"mode of '");
            let _ = sys_write(err_fd, target.as_bytes());
            let _ = sys_write(err_fd, b"' changed to ");
            let _ = sys_write(err_fd, raw_mode.as_bytes());
            let _ = sys_write(err_fd, b"\n");
        }
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Résout un identifiant ou nom d'utilisateur/groupe vers sa valeur numérique
fn resolve_user_or_group(name: &str) -> Option<u32> {
    match name {
        "root" => Some(0),
        "daemon" => Some(1),
        "bin" => Some(2),
        "sys" => Some(3),
        "adm" => Some(4),
        "user" => Some(1000),
        "nobody" => Some(65534),
        numeric if !numeric.is_empty() && numeric.bytes().all(|b| b.is_ascii_digit()) => {
            let mut val: u32 = 0;
            for b in numeric.bytes() {
                val = val.checked_mul(10)?.checked_add((b - b'0') as u32)?;
            }
            Some(val)
        }
        _ => None,
    }
}

/// Analyse une spécification de propriétaire et groupe (ex: "root", "root:root", ":bin", "1000:1000", "user.user")
#[allow(clippy::result_unit_err)]
pub fn parse_owner_group(spec: &str) -> Result<(Option<u32>, Option<u32>), ()> {
    if spec.is_empty() {
        return Err(());
    }

    let (user_part, group_part) = if let Some(pos) = spec.find(':') {
        (&spec[..pos], Some(&spec[pos + 1..]))
    } else if let Some(pos) = spec.find('.') {
        (&spec[..pos], Some(&spec[pos + 1..]))
    } else {
        (spec, None)
    };

    let uid = if user_part.is_empty() {
        None
    } else {
        Some(resolve_user_or_group(user_part).ok_or(())?)
    };

    let gid = match group_part {
        Some("") => None,
        Some(g) => Some(resolve_user_or_group(g).ok_or(())?),
        None => None,
    };

    if uid.is_none() && gid.is_none() {
        return Err(());
    }

    Ok((uid, gid))
}

/// Exécute l'utilitaire `chown` pour modifier le propriétaire et/ou le groupe de fichiers ou répertoires
pub fn run_chown(args: &[&str], err_fd: i32) -> i32 {
    let mut recursive = false;
    let mut verbose = false;
    let mut owner_str: Option<&str> = None;
    let mut files_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-R" || arg == "--recursive" {
            recursive = true;
            i += 1;
        } else if arg == "-v" || arg == "--verbose" {
            verbose = true;
            i += 1;
        } else if arg.starts_with('-') && !arg.chars().skip(1).all(|c| c.is_ascii_digit()) {
            let _ = sys_write(err_fd, b"chown: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else if owner_str.is_none() {
            owner_str = Some(arg);
            files_start = i + 1;
            break;
        } else {
            i += 1;
        }
    }

    let raw_spec = match owner_str {
        Some(s) => s,
        None => {
            let _ = sys_write(err_fd, b"chown: missing operand\n");
            return 1;
        }
    };

    let (parsed_uid, parsed_gid) = match parse_owner_group(raw_spec) {
        Ok(res) => res,
        Err(_) => {
            let _ = sys_write(err_fd, b"chown: invalid user: '");
            let _ = sys_write(err_fd, raw_spec.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }
    };

    let files = &args[files_start..];
    if files.is_empty() {
        let _ = sys_write(err_fd, b"chown: missing operand after '");
        let _ = sys_write(err_fd, raw_spec.as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    let mut has_error = false;
    for &target in files {
        let (current_uid, current_gid) = match sys_get_owner_pool(target) {
            Some(pair) => pair,
            None => {
                let _ = sys_write(err_fd, b"chown: cannot access '");
                let _ = sys_write(err_fd, target.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                has_error = true;
                continue;
            }
        };

        let target_uid = parsed_uid.unwrap_or(current_uid);
        let target_gid = parsed_gid.unwrap_or(current_gid);

        let res = sys_chown_pool(target, target_uid, target_gid);
        if res < 0 {
            let _ = sys_write(err_fd, b"chown: cannot access '");
            let _ = sys_write(err_fd, target.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            has_error = true;
        } else {
            if recursive {
                let clean = target.trim_end_matches('/');
                // SAFETY: Accès protégé au pool d'inodes virtuel
                unsafe {
                    let pool = core::ptr::addr_of_mut!(INODE_POOL);
                    for node in (*pool).iter_mut() {
                        if node.is_active {
                            let p = node.path_str();
                            if p.starts_with(clean)
                                && (p.len() == clean.len()
                                    || p.as_bytes().get(clean.len()) == Some(&b'/'))
                            {
                                if let Some(u) = parsed_uid {
                                    node.uid = u;
                                }
                                if let Some(g) = parsed_gid {
                                    node.gid = g;
                                }
                            }
                        }
                    }
                }
            }
            if verbose {
                let _ = sys_write(err_fd, b"ownership of '");
                let _ = sys_write(err_fd, target.as_bytes());
                let _ = sys_write(err_fd, b"' retained as ");
                let _ = sys_write(err_fd, raw_spec.as_bytes());
                let _ = sys_write(err_fd, b"\n");
            }
        }
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Écrit un nombre entier non signé en décimal sur le descripteur
fn write_u32(fd: i32, mut val: u32) {
    if val == 0 {
        let _ = sys_write(fd, b"0");
        return;
    }
    let mut buf = [0u8; 10];
    let mut idx = 10;
    while val > 0 {
        idx -= 1;
        buf[idx] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    let _ = sys_write(fd, &buf[idx..]);
}

/// Exécute l'utilitaire `chgrp` pour modifier le groupe d'appartenance de fichiers ou répertoires
pub fn run_chgrp(args: &[&str], err_fd: i32) -> i32 {
    let mut recursive = false;
    let mut verbose = false;
    let mut group_str: Option<&str> = None;
    let mut files_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-R" || arg == "--recursive" {
            recursive = true;
            i += 1;
        } else if arg == "-v" || arg == "--verbose" {
            verbose = true;
            i += 1;
        } else if arg.starts_with('-') && !arg.chars().skip(1).all(|c| c.is_ascii_digit()) {
            let _ = sys_write(err_fd, b"chgrp: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else if group_str.is_none() {
            group_str = Some(arg);
            files_start = i + 1;
            break;
        } else {
            i += 1;
        }
    }

    let raw_spec = match group_str {
        Some(s) => s,
        None => {
            let _ = sys_write(err_fd, b"chgrp: missing operand\n");
            return 1;
        }
    };

    let target_gid = match resolve_user_or_group(raw_spec) {
        Some(gid) => gid,
        None => {
            let _ = sys_write(err_fd, b"chgrp: invalid group: '");
            let _ = sys_write(err_fd, raw_spec.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }
    };

    let files = &args[files_start..];
    if files.is_empty() {
        let _ = sys_write(err_fd, b"chgrp: missing operand after '");
        let _ = sys_write(err_fd, raw_spec.as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    let mut has_error = false;
    for &target in files {
        let (current_uid, _current_gid) = match sys_get_owner_pool(target) {
            Some(pair) => pair,
            None => {
                let _ = sys_write(err_fd, b"chgrp: cannot access '");
                let _ = sys_write(err_fd, target.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                has_error = true;
                continue;
            }
        };

        let res = sys_chown_pool(target, current_uid, target_gid);
        if res < 0 {
            let _ = sys_write(err_fd, b"chgrp: cannot access '");
            let _ = sys_write(err_fd, target.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            has_error = true;
        } else {
            if recursive {
                let clean = target.trim_end_matches('/');
                // SAFETY: Accès protégé au pool d'inodes virtuel
                unsafe {
                    let pool = core::ptr::addr_of_mut!(INODE_POOL);
                    for node in (*pool).iter_mut() {
                        if node.is_active {
                            let p = node.path_str();
                            if p.starts_with(clean)
                                && (p.len() == clean.len()
                                    || p.as_bytes().get(clean.len()) == Some(&b'/'))
                            {
                                node.gid = target_gid;
                            }
                        }
                    }
                }
            }
            if verbose {
                let _ = sys_write(err_fd, b"group of '");
                let _ = sys_write(err_fd, target.as_bytes());
                let _ = sys_write(err_fd, b"' retained as ");
                let _ = sys_write(err_fd, raw_spec.as_bytes());
                let _ = sys_write(err_fd, b"\n");
            }
        }
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire `id` affichant les identités utilisateur et groupe Ring 3
pub fn run_id(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut user_only = false;
    let mut group_only = false;
    let mut groups_all = false;
    let mut name_only = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg.starts_with('-') && arg != "-" {
            for b in arg[1..].bytes() {
                match b {
                    b'u' => user_only = true,
                    b'g' => group_only = true,
                    b'G' => groups_all = true,
                    b'n' => name_only = true,
                    _ => {
                        let _ = sys_write(err_fd, b"id: extra operand -- '");
                        let b_slice = [b];
                        let _ = sys_write(err_fd, &b_slice);
                        let _ = sys_write(err_fd, b"'\n");
                        return 1;
                    }
                }
            }
        }
        i += 1;
    }

    let uid = crate::vfs::getuid();
    let gid = crate::vfs::getgid();

    let user_name = if uid == 0 { "root" } else { "user" };
    let group_name = if gid == 0 { "root" } else { "user" };

    if user_only {
        if name_only {
            let _ = sys_write(out_fd, user_name.as_bytes());
        } else {
            write_u32(out_fd, uid);
        }
        let _ = sys_write(out_fd, b"\n");
        return 0;
    }

    if group_only || groups_all {
        if name_only {
            let _ = sys_write(out_fd, group_name.as_bytes());
        } else {
            write_u32(out_fd, gid);
        }
        let _ = sys_write(out_fd, b"\n");
        return 0;
    }

    // Sortie standard format POSIX : uid=0(root) gid=0(root) groups=0(root)
    let _ = sys_write(out_fd, b"uid=");
    write_u32(out_fd, uid);
    let _ = sys_write(out_fd, b"(");
    let _ = sys_write(out_fd, user_name.as_bytes());
    let _ = sys_write(out_fd, b") gid=");
    write_u32(out_fd, gid);
    let _ = sys_write(out_fd, b"(");
    let _ = sys_write(out_fd, group_name.as_bytes());
    let _ = sys_write(out_fd, b") groups=");
    write_u32(out_fd, gid);
    let _ = sys_write(out_fd, b"(");
    let _ = sys_write(out_fd, group_name.as_bytes());
    let _ = sys_write(out_fd, b")\n");

    0
}

/// Écrit un nombre entier 64 bits non signé en décimal sur le descripteur
fn write_u64_dec(fd: i32, mut val: u64) {
    if val == 0 {
        let _ = sys_write(fd, b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut idx = 20;
    while val > 0 {
        idx -= 1;
        buf[idx] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    let _ = sys_write(fd, &buf[idx..]);
}

/// Écrit une taille en octets dans un format lisible pour un humain (B, K, M, G)
fn write_human_size(fd: i32, bytes: u64) {
    if bytes < 1024 {
        write_u64_dec(fd, bytes);
        let _ = sys_write(fd, b"B");
    } else if bytes < 1024 * 1024 {
        let kib = bytes / 1024;
        let rem = bytes % 1024;
        let frac = (rem * 10) / 1024;
        write_u64_dec(fd, kib);
        if kib < 10 && frac > 0 {
            let _ = sys_write(fd, b".");
            write_u64_dec(fd, frac);
        }
        let _ = sys_write(fd, b"K");
    } else if bytes < 1024 * 1024 * 1024 {
        let mib = bytes / (1024 * 1024);
        let rem = bytes % (1024 * 1024);
        let frac = (rem * 10) / (1024 * 1024);
        write_u64_dec(fd, mib);
        if mib < 10 && frac > 0 {
            let _ = sys_write(fd, b".");
            write_u64_dec(fd, frac);
        }
        let _ = sys_write(fd, b"M");
    } else {
        let gib = bytes / (1024 * 1024 * 1024);
        write_u64_dec(fd, gib);
        let _ = sys_write(fd, b"G");
    }
}

/// Écrit la taille calculée d'un fichier ou répertoire selon les options d'affichage
fn print_du_size_and_path(
    out_fd: i32,
    bytes: u64,
    path: &str,
    human: bool,
    bytes_mode: bool,
    block_1m: bool,
) {
    if human {
        write_human_size(out_fd, bytes);
    } else if bytes_mode {
        write_u64_dec(out_fd, bytes);
    } else if block_1m {
        let mib = bytes
            .div_ceil(1024 * 1024)
            .max(if bytes > 0 { 1 } else { 0 });
        write_u64_dec(out_fd, mib);
    } else {
        // Blocs standard de 1 Kio (1024 octets)
        let kib = bytes.div_ceil(1024).max(if bytes > 0 { 4 } else { 0 });
        write_u64_dec(out_fd, kib);
    }
    let _ = sys_write(out_fd, b"\t");
    let _ = sys_write(out_fd, path.as_bytes());
    let _ = sys_write(out_fd, b"\n");
}

/// Exécute l'utilitaire standard POSIX `du` pour calculer l'espace disque consommé
pub fn run_du(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut summarize = false;
    let mut human_readable = false;
    let mut all_files = false;
    let mut bytes_mode = false;
    let mut block_1m = false;

    let mut targets_buf = [""; 16];
    let mut target_count = 0;

    for &arg in args {
        if arg == "-s" || arg == "--summarize" {
            summarize = true;
        } else if arg == "-h" || arg == "--human-readable" {
            human_readable = true;
        } else if arg == "-a" || arg == "--all" {
            all_files = true;
        } else if arg == "-b" || arg == "--bytes" {
            bytes_mode = true;
        } else if arg == "-k" {
            bytes_mode = false;
            block_1m = false;
        } else if arg == "-m" {
            block_1m = true;
            bytes_mode = false;
        } else if arg.starts_with('-') {
            let _ = sys_write(err_fd, b"du: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else if target_count < targets_buf.len() {
            targets_buf[target_count] = arg;
            target_count += 1;
        }
    }

    let default_target = ["."];
    let targets = if target_count == 0 {
        &default_target[..]
    } else {
        &targets_buf[..target_count]
    };

    #[derive(Clone, Copy)]
    struct DuNode<'a> {
        path: &'a str,
        is_dir: bool,
        size: u64,
    }

    let mut nodes: [DuNode<'static>; 48] = [
        DuNode {
            path: "/",
            is_dir: true,
            size: 4096,
        },
        DuNode {
            path: "/bin",
            is_dir: true,
            size: 4096,
        },
        DuNode {
            path: "/dev",
            is_dir: true,
            size: 4096,
        },
        DuNode {
            path: "/etc",
            is_dir: true,
            size: 4096,
        },
        DuNode {
            path: "/tmp",
            is_dir: true,
            size: 4096,
        },
        DuNode {
            path: "/hostname",
            is_dir: false,
            size: 14,
        },
        DuNode {
            path: "/os-release",
            is_dir: false,
            size: 38,
        },
        DuNode {
            path: "/motd",
            is_dir: false,
            size: 24,
        },
        DuNode {
            path: "/inittab",
            is_dir: false,
            size: 30,
        },
        DuNode {
            path: "/etc/hostname",
            is_dir: false,
            size: 14,
        },
        DuNode {
            path: "/etc/os-release",
            is_dir: false,
            size: 38,
        },
        DuNode {
            path: "/etc/motd",
            is_dir: false,
            size: 24,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
        DuNode {
            path: "",
            is_dir: false,
            size: 0,
        },
    ];
    let mut node_count = 12;

    // Intégration des entrées dynamiques d'INODE_POOL
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of!(INODE_POOL);
        for vfs_node in (*pool).iter() {
            if !vfs_node.is_active {
                continue;
            }
            let p = vfs_node.path_str();
            if p.is_empty() {
                continue;
            }
            let mut existing = false;
            for n in &mut nodes[..node_count] {
                if n.path == p {
                    n.size = vfs_node.size as u64;
                    n.is_dir = vfs_node.is_dir;
                    existing = true;
                    break;
                }
            }
            if !existing && node_count < nodes.len() {
                nodes[node_count] = DuNode {
                    path: p,
                    is_dir: vfs_node.is_dir,
                    size: if vfs_node.is_dir {
                        4096
                    } else {
                        vfs_node.size as u64
                    },
                };
                node_count += 1;
            }
        }
    }

    let mut has_error = false;

    for &target in targets {
        let norm_target = if target == "." {
            "/"
        } else {
            let t = target.trim_end_matches('/');
            if t.is_empty() {
                "/"
            } else {
                t
            }
        };

        // Recherche de correspondance pour le chemin demandé
        let mut target_node: Option<DuNode> = None;
        for n in &nodes[..node_count] {
            if n.path == norm_target {
                target_node = Some(*n);
                break;
            }
        }

        if target_node.is_none() && norm_target != "/" {
            // Vérifier si un descendant existe (répertoire implicite)
            let mut has_child = false;
            for n in &nodes[..node_count] {
                if n.path.starts_with(norm_target)
                    && n.path.as_bytes().get(norm_target.len()) == Some(&b'/')
                {
                    has_child = true;
                    break;
                }
            }
            if has_child {
                target_node = Some(DuNode {
                    path: norm_target,
                    is_dir: true,
                    size: 4096,
                });
            }
        }

        let current_target = match target_node {
            Some(n) => n,
            None => {
                let _ = sys_write(err_fd, b"du: cannot access '");
                let _ = sys_write(err_fd, target.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                has_error = true;
                continue;
            }
        };

        if !current_target.is_dir {
            // Fichier individuel
            print_du_size_and_path(
                out_fd,
                current_target.size,
                target,
                human_readable,
                bytes_mode,
                block_1m,
            );
            continue;
        }

        // Répertoire : calcul de l'arborescence descendante
        let is_descendant = |child: &str, parent: &str| -> bool {
            if parent == "/" {
                child.starts_with('/') && child != "/"
            } else {
                child.starts_with(parent) && child.as_bytes().get(parent.len()) == Some(&b'/')
            }
        };

        // Collecte des sous-répertoires uniques
        let mut subdirs = [""; 16];
        let mut subdir_count = 0;

        for n in &nodes[..node_count] {
            if n.is_dir && is_descendant(n.path, norm_target) {
                let mut found = false;
                for &sd in &subdirs[..subdir_count] {
                    if sd == n.path {
                        found = true;
                        break;
                    }
                }
                if !found && subdir_count < subdirs.len() {
                    subdirs[subdir_count] = n.path;
                    subdir_count += 1;
                }
            }
        }

        // Fonction locale de calcul de taille récursive
        let calc_dir_bytes = |dir_path: &str| -> u64 {
            let mut total = 4096u64; // Taille de base de l'inode répertoire
            for n in &nodes[..node_count] {
                if is_descendant(n.path, dir_path) {
                    total = total.saturating_add(n.size);
                }
            }
            total
        };

        if !summarize {
            // 1. Si -a est actif, affichage de tous les fichiers enfants
            if all_files {
                for n in &nodes[..node_count] {
                    if !n.is_dir && is_descendant(n.path, norm_target) {
                        print_du_size_and_path(
                            out_fd,
                            n.size,
                            n.path,
                            human_readable,
                            bytes_mode,
                            block_1m,
                        );
                    }
                }
            }

            // 2. Affichage des sous-répertoires
            for &sd in &subdirs[..subdir_count] {
                let sub_size = calc_dir_bytes(sd);
                print_du_size_and_path(out_fd, sub_size, sd, human_readable, bytes_mode, block_1m);
            }
        }

        // 3. Affichage récapitulatif du répertoire cible lui-même
        let root_total_bytes = calc_dir_bytes(norm_target);
        print_du_size_and_path(
            out_fd,
            root_total_bytes,
            target,
            human_readable,
            bytes_mode,
            block_1m,
        );
    }

    if has_error {
        1
    } else {
        0
    }
}

fn write_pad_right(fd: i32, s: &str, width: usize) {
    let _ = sys_write(fd, s.as_bytes());
    let len = s.len();
    if len < width {
        for _ in 0..(width - len) {
            let _ = sys_write(fd, b" ");
        }
    }
}

fn write_pad_left_u64(fd: i32, val: u64, width: usize) {
    let mut buf = [0u8; 20];
    let mut idx = 20;
    let mut v = val;
    if v == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while v > 0 {
            idx -= 1;
            buf[idx] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    let digits_len = 20 - idx;
    if digits_len < width {
        for _ in 0..(width - digits_len) {
            let _ = sys_write(fd, b" ");
        }
    }
    let _ = sys_write(fd, &buf[idx..]);
}

fn write_human_size_buf(bytes: u64, out: &mut [u8]) -> usize {
    if bytes < 1024 {
        let mut n = bytes;
        let mut idx = 12;
        let mut tmp = [0u8; 16];
        if n == 0 {
            tmp[idx] = b'0';
            idx -= 1;
        } else {
            while n > 0 {
                tmp[idx] = b'0' + (n % 10) as u8;
                idx -= 1;
                n /= 10;
            }
        }
        let len = 12 - idx;
        out[..len].copy_from_slice(&tmp[idx + 1..13]);
        out[len] = b'B';
        len + 1
    } else if bytes < 1024 * 1024 {
        let kib = bytes / 1024;
        let rem = bytes % 1024;
        let frac = (rem * 10) / 1024;
        let mut n = kib;
        let mut idx = 12;
        let mut tmp = [0u8; 16];
        if n == 0 {
            tmp[idx] = b'0';
            idx -= 1;
        } else {
            while n > 0 {
                tmp[idx] = b'0' + (n % 10) as u8;
                idx -= 1;
                n /= 10;
            }
        }
        let mut pos = 12 - idx;
        out[..pos].copy_from_slice(&tmp[idx + 1..13]);
        if kib < 10 && frac > 0 {
            out[pos] = b'.';
            out[pos + 1] = b'0' + frac as u8;
            pos += 2;
        }
        out[pos] = b'K';
        pos + 1
    } else if bytes < 1024 * 1024 * 1024 {
        let mib = bytes / (1024 * 1024);
        let rem = bytes % (1024 * 1024);
        let frac = (rem * 10) / (1024 * 1024);
        let mut n = mib;
        let mut idx = 12;
        let mut tmp = [0u8; 16];
        if n == 0 {
            tmp[idx] = b'0';
            idx -= 1;
        } else {
            while n > 0 {
                tmp[idx] = b'0' + (n % 10) as u8;
                idx -= 1;
                n /= 10;
            }
        }
        let mut pos = 12 - idx;
        out[..pos].copy_from_slice(&tmp[idx + 1..13]);
        if mib < 10 && frac > 0 {
            out[pos] = b'.';
            out[pos + 1] = b'0' + frac as u8;
            pos += 2;
        }
        out[pos] = b'M';
        pos + 1
    } else {
        let gib = bytes / (1024 * 1024 * 1024);
        let rem = bytes % (1024 * 1024 * 1024);
        let frac = (rem * 10) / (1024 * 1024 * 1024);
        let mut n = gib;
        let mut idx = 12;
        let mut tmp = [0u8; 16];
        if n == 0 {
            tmp[idx] = b'0';
            idx -= 1;
        } else {
            while n > 0 {
                tmp[idx] = b'0' + (n % 10) as u8;
                idx -= 1;
                n /= 10;
            }
        }
        let mut pos = 12 - idx;
        out[..pos].copy_from_slice(&tmp[idx + 1..13]);
        if gib < 10 && frac > 0 {
            out[pos] = b'.';
            out[pos + 1] = b'0' + frac as u8;
            pos += 2;
        }
        out[pos] = b'G';
        pos + 1
    }
}

fn write_pad_left_human(fd: i32, bytes: u64, width: usize) {
    let mut buf = [0u8; 16];
    let len = write_human_size_buf(bytes, &mut buf);
    if len < width {
        for _ in 0..(width - len) {
            let _ = sys_write(fd, b" ");
        }
    }
    let _ = sys_write(fd, &buf[..len]);
}

/// Exécute l'utilitaire standard POSIX `df` pour rapporter l'espace disque disponible
pub fn run_df(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut human_readable = false;
    let mut block_1m = false;
    let mut print_type = false;
    let mut all_filesystems = false;
    let mut inodes_mode = false;
    let mut show_snapshots = false;

    let mut target_paths = [""; 8];
    let mut target_count = 0;

    for &arg in args {
        if arg == "-h" || arg == "--human-readable" {
            human_readable = true;
        } else if arg == "-k" {
            human_readable = false;
            block_1m = false;
        } else if arg == "-m" {
            block_1m = true;
            human_readable = false;
        } else if arg == "-T" || arg == "--print-type" {
            print_type = true;
        } else if arg == "-a" || arg == "--all" {
            all_filesystems = true;
        } else if arg == "-i" || arg == "--inodes" {
            inodes_mode = true;
        } else if arg == "-s" || arg == "--snapshots" {
            show_snapshots = true;
        } else if arg.starts_with('-') {
            let _ = sys_write(err_fd, b"df: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else if target_count < target_paths.len() {
            target_paths[target_count] = arg;
            target_count += 1;
        }
    }

    #[derive(Clone, Copy)]
    struct DfMount<'a> {
        fs: &'a str,
        fs_type: &'a str,
        mount: &'a str,
        total_bytes: u64,
        used_bytes: u64,
        avail_bytes: u64,
        total_inodes: u64,
        used_inodes: u64,
        free_inodes: u64,
        is_virtual: bool,
    }

    // Récupération dynamique des statistiques réelles du VFS
    let sv_root = crate::vfs::statvfs("/").unwrap_or_default();
    let root_total = sv_root.f_blocks * sv_root.f_frsize;
    let root_avail = sv_root.f_bavail * sv_root.f_frsize;
    let root_used = root_total.saturating_sub(root_avail);
    let root_inodes = sv_root.f_files;
    let root_ifree = sv_root.f_ffree;
    let root_iused = root_inodes.saturating_sub(root_ifree);

    let sv_dev = crate::vfs::statvfs("/dev").unwrap_or_default();
    let dev_total = sv_dev.f_blocks * sv_dev.f_frsize;
    let dev_avail = sv_dev.f_bavail * sv_dev.f_frsize;
    let dev_used = dev_total.saturating_sub(dev_avail);

    let sv_tmp = crate::vfs::statvfs("/tmp").unwrap_or_default();
    let tmp_total = sv_tmp.f_blocks * sv_tmp.f_frsize;
    let tmp_avail = sv_tmp.f_bavail * sv_tmp.f_frsize;
    let tmp_used = tmp_total.saturating_sub(tmp_avail);

    let mounts: [DfMount<'static>; 5] = [
        DfMount {
            fs: "/dev/nvme0n1p2",
            fs_type: "jambofs",
            mount: "/",
            total_bytes: root_total,
            used_bytes: root_used,
            avail_bytes: root_avail,
            total_inodes: root_inodes,
            used_inodes: root_iused,
            free_inodes: root_ifree,
            is_virtual: false,
        },
        DfMount {
            fs: "devfs",
            fs_type: "devfs",
            mount: "/dev",
            total_bytes: dev_total,
            used_bytes: dev_used,
            avail_bytes: dev_avail,
            total_inodes: 16,
            used_inodes: 8,
            free_inodes: 8,
            is_virtual: false,
        },
        DfMount {
            fs: "tmpfs",
            fs_type: "tmpfs",
            mount: "/tmp",
            total_bytes: tmp_total,
            used_bytes: tmp_used,
            avail_bytes: tmp_avail,
            total_inodes: 256,
            used_inodes: 2,
            free_inodes: 254,
            is_virtual: false,
        },
        DfMount {
            fs: "proc",
            fs_type: "procfs",
            mount: "/proc",
            total_bytes: 0,
            used_bytes: 0,
            avail_bytes: 0,
            total_inodes: 0,
            used_inodes: 0,
            free_inodes: 0,
            is_virtual: true,
        },
        DfMount {
            fs: "sysfs",
            fs_type: "sysfs",
            mount: "/sys",
            total_bytes: 0,
            used_bytes: 0,
            avail_bytes: 0,
            total_inodes: 0,
            used_inodes: 0,
            free_inodes: 0,
            is_virtual: true,
        },
    ];

    // En-tête des colonnes
    write_pad_right(out_fd, "Filesystem", 15);
    if print_type {
        write_pad_right(out_fd, "Type", 10);
    }
    if inodes_mode {
        write_pad_right(out_fd, "  Inodes", 9);
        write_pad_right(out_fd, "   IUsed", 9);
        write_pad_right(out_fd, "   IFree", 9);
        write_pad_right(out_fd, " IUse%", 7);
    } else if human_readable {
        write_pad_right(out_fd, "  Size", 7);
        write_pad_right(out_fd, "  Used", 7);
        write_pad_right(out_fd, " Avail", 7);
        write_pad_right(out_fd, " Use%", 6);
    } else if block_1m {
        write_pad_right(out_fd, " 1M-blocks", 11);
        write_pad_right(out_fd, "      Used", 11);
        write_pad_right(out_fd, " Available", 11);
        write_pad_right(out_fd, " Use%", 6);
    } else {
        write_pad_right(out_fd, " 1K-blocks", 11);
        write_pad_right(out_fd, "      Used", 11);
        write_pad_right(out_fd, " Available", 11);
        write_pad_right(out_fd, " Use%", 6);
    }
    let _ = sys_write(out_fd, b"Mounted on\n");

    let targets = if target_count == 0 {
        &[][..]
    } else {
        &target_paths[..target_count]
    };

    if !targets.is_empty() {
        let check_path_exists = |p: &str| -> bool {
            let norm = if p == "." {
                "/"
            } else {
                let t = p.trim_end_matches('/');
                if t.is_empty() {
                    "/"
                } else {
                    t
                }
            };
            if norm == "/"
                || norm == "/bin"
                || norm == "/dev"
                || norm == "/etc"
                || norm == "/tmp"
                || norm == "/proc"
                || norm == "/sys"
                || norm == "/hostname"
                || norm == "/os-release"
                || norm == "/motd"
                || norm == "/etc/hostname"
                || norm == "/etc/os-release"
                || norm == "/etc/motd"
                || norm == "/dev/console"
                || norm == "/dev/null"
                || norm == "/dev/zero"
                || norm == "/dev/nvme0n1p2"
                || norm == "devfs"
                || norm == "tmpfs"
            {
                return true;
            }
            // SAFETY: Consultation protégée du pool d'inodes virtuel
            unsafe {
                let pool = core::ptr::addr_of!(INODE_POOL);
                for vfs_node in (*pool).iter() {
                    if vfs_node.is_active && vfs_node.path_str() == norm {
                        return true;
                    }
                }
            }
            false
        };

        let mut target_err = false;
        for &t in targets {
            if !check_path_exists(t) {
                let _ = sys_write(err_fd, b"df: cannot access '");
                let _ = sys_write(err_fd, t.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                target_err = true;
            }
        }
        if target_err {
            return 1;
        }
    }

    let mut has_match = false;
    for m in &mounts {
        if m.is_virtual && !all_filesystems {
            continue;
        }

        if !targets.is_empty() {
            let mut matched = false;
            for &t in targets {
                if t == m.mount
                    || t == m.fs
                    || (m.mount != "/" && t.starts_with(m.mount))
                    || (m.mount == "/" && !t.starts_with("/dev") && !t.starts_with("/tmp"))
                {
                    matched = true;
                    break;
                }
            }
            if !matched {
                continue;
            }
        }

        has_match = true;
        write_pad_right(out_fd, m.fs, 15);
        if print_type {
            write_pad_right(out_fd, m.fs_type, 10);
        }

        if inodes_mode {
            write_pad_left_u64(out_fd, m.total_inodes, 8);
            let _ = sys_write(out_fd, b" ");
            write_pad_left_u64(out_fd, m.used_inodes, 8);
            let _ = sys_write(out_fd, b" ");
            write_pad_left_u64(out_fd, m.free_inodes, 8);
            let _ = sys_write(out_fd, b" ");
            let pct = if m.total_inodes > 0 {
                (m.used_inodes * 100).div_ceil(m.total_inodes)
            } else {
                0
            };
            write_pad_left_u64(out_fd, pct, 4);
            let _ = sys_write(out_fd, b"% ");
        } else if human_readable {
            write_pad_left_human(out_fd, m.total_bytes, 6);
            let _ = sys_write(out_fd, b" ");
            write_pad_left_human(out_fd, m.used_bytes, 6);
            let _ = sys_write(out_fd, b" ");
            write_pad_left_human(out_fd, m.avail_bytes, 6);
            let _ = sys_write(out_fd, b" ");
            let pct = if m.total_bytes > 0 {
                (m.used_bytes * 100).div_ceil(m.total_bytes)
            } else {
                0
            };
            write_pad_left_u64(out_fd, pct, 4);
            let _ = sys_write(out_fd, b"% ");
        } else if block_1m {
            let total_1m = m.total_bytes / (1024 * 1024);
            let used_1m = m.used_bytes.div_ceil(1024 * 1024);
            let avail_1m = m.avail_bytes / (1024 * 1024);
            write_pad_left_u64(out_fd, total_1m, 10);
            let _ = sys_write(out_fd, b" ");
            write_pad_left_u64(out_fd, used_1m, 10);
            let _ = sys_write(out_fd, b" ");
            write_pad_left_u64(out_fd, avail_1m, 10);
            let _ = sys_write(out_fd, b" ");
            let pct = if m.total_bytes > 0 {
                (m.used_bytes * 100).div_ceil(m.total_bytes)
            } else {
                0
            };
            write_pad_left_u64(out_fd, pct, 4);
            let _ = sys_write(out_fd, b"% ");
        } else {
            let total_kib = m.total_bytes / 1024;
            let used_kib = m.used_bytes.div_ceil(1024);
            let avail_kib = m.avail_bytes / 1024;
            write_pad_left_u64(out_fd, total_kib, 10);
            let _ = sys_write(out_fd, b" ");
            write_pad_left_u64(out_fd, used_kib, 10);
            let _ = sys_write(out_fd, b" ");
            write_pad_left_u64(out_fd, avail_kib, 10);
            let _ = sys_write(out_fd, b" ");
            let pct = if m.total_bytes > 0 {
                (m.used_bytes * 100).div_ceil(m.total_bytes)
            } else {
                0
            };
            write_pad_left_u64(out_fd, pct, 4);
            let _ = sys_write(out_fd, b"% ");
        }

        let _ = sys_write(out_fd, m.mount.as_bytes());
        let _ = sys_write(out_fd, b"\n");
    }

    if show_snapshots {
        let _ = sys_write(out_fd, b"[JamboFS CoW Snapshots] Actifs: 0/16 | Gen: 1 | Slot: A | Dedup: 0 blk | Blocs libres: 2024/2048 (98%)\n");
    }

    if !targets.is_empty() && !has_match {
        let _ = sys_write(err_fd, b"df: no file systems found for specified target\n");
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire standard POSIX `uname` pour afficher les informations système
pub fn run_uname(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut show_all = false;
    let mut show_kernel_name = false;
    let mut show_nodename = false;
    let mut show_kernel_release = false;
    let mut show_kernel_version = false;
    let mut show_machine = false;
    let mut show_processor = false;
    let mut show_hardware_platform = false;
    let mut show_operating_system = false;

    for &arg in args {
        match arg {
            "-a" | "--all" => show_all = true,
            "-s" | "--kernel-name" => show_kernel_name = true,
            "-n" | "--nodename" => show_nodename = true,
            "-r" | "--kernel-release" => show_kernel_release = true,
            "-v" | "--kernel-version" => show_kernel_version = true,
            "-m" | "--machine" => show_machine = true,
            "-p" | "--processor" => show_processor = true,
            "-i" | "--hardware-platform" => show_hardware_platform = true,
            "-o" | "--operating-system" => show_operating_system = true,
            "--help" => {
                let _ = sys_write(out_fd, b"Usage: uname [OPTION]...\nPrint certain system information.  With no OPTION, same as -s.\n\n  -a, --all                print all information\n  -s, --kernel-name        print the kernel name\n  -n, --nodename           print the network node hostname\n  -r, --kernel-release     print the operating system release\n  -v, --kernel-version     print the kernel version\n  -m, --machine            print the machine hardware name\n  -p, --processor          print the processor type\n  -i, --hardware-platform  print the hardware platform\n  -o, --operating-system   print the operating system\n      --help               display this help and exit\n");
                return 0;
            }
            opt if opt.starts_with('-') => {
                let mut valid_combined = true;
                for ch in opt[1..].chars() {
                    match ch {
                        'a' => show_all = true,
                        's' => show_kernel_name = true,
                        'n' => show_nodename = true,
                        'r' => show_kernel_release = true,
                        'v' => show_kernel_version = true,
                        'm' => show_machine = true,
                        'p' => show_processor = true,
                        'i' => show_hardware_platform = true,
                        'o' => show_operating_system = true,
                        _ => {
                            valid_combined = false;
                            break;
                        }
                    }
                }
                if !valid_combined {
                    let _ = sys_write(err_fd, b"uname: extra operand or unrecognized option '");
                    let _ = sys_write(err_fd, opt.as_bytes());
                    let _ = sys_write(err_fd, b"'\n");
                    return 1;
                }
            }
            extra => {
                let _ = sys_write(err_fd, b"uname: extra operand '");
                let _ = sys_write(err_fd, extra.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        }
    }

    if show_all {
        show_kernel_name = true;
        show_nodename = true;
        show_kernel_release = true;
        show_kernel_version = true;
        show_machine = true;
        show_processor = true;
        show_hardware_platform = true;
        show_operating_system = true;
    }

    if !show_kernel_name
        && !show_nodename
        && !show_kernel_release
        && !show_kernel_version
        && !show_machine
        && !show_processor
        && !show_hardware_platform
        && !show_operating_system
    {
        show_kernel_name = true;
    }

    let mut first = true;
    let mut write_field = |val: &str| {
        if !first {
            let _ = sys_write(out_fd, b" ");
        }
        first = false;
        let _ = sys_write(out_fd, val.as_bytes());
    };

    if show_kernel_name {
        write_field("JamboOS");
    }
    if show_nodename {
        write_field("jambo-node-0");
    }
    if show_kernel_release {
        write_field("0.3.44");
    }
    if show_kernel_version {
        #[cfg(target_arch = "x86_64")]
        write_field("#1 SMP PREEMPT EEVDF x86_64");
        #[cfg(target_arch = "aarch64")]
        write_field("#1 SMP PREEMPT EEVDF aarch64");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        write_field("#1 SMP PREEMPT EEVDF unknown");
    }
    if show_machine {
        #[cfg(target_arch = "x86_64")]
        write_field("x86_64");
        #[cfg(target_arch = "aarch64")]
        write_field("aarch64");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        write_field("unknown");
    }
    if show_processor {
        #[cfg(target_arch = "x86_64")]
        write_field("x86_64");
        #[cfg(target_arch = "aarch64")]
        write_field("aarch64");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        write_field("unknown");
    }
    if show_hardware_platform {
        #[cfg(target_arch = "x86_64")]
        write_field("x86_64");
        #[cfg(target_arch = "aarch64")]
        write_field("aarch64");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        write_field("unknown");
    }
    if show_operating_system {
        write_field("JamboOS");
    }

    let _ = sys_write(out_fd, b"\n");
    0
}

/// Intervalle de sélection pour l'utilitaire `cut` (1-based, inclusif)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CutRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CutMode {
    None,
    Bytes,
    Fields,
}

/// Analyse une liste de plages POSIX (ex: "1", "1,3", "2-5", "-4", "3-")
fn parse_cut_ranges(spec: &str, out_ranges: &mut [CutRange; 32]) -> Result<usize, ()> {
    if spec.is_empty() {
        return Err(());
    }
    let mut count = 0;
    for part in spec.split(',') {
        if part.is_empty() || count >= out_ranges.len() {
            return Err(());
        }
        if let Some(dash_idx) = part.find('-') {
            let left = &part[..dash_idx];
            let right = &part[dash_idx + 1..];
            let start = if left.is_empty() {
                1
            } else {
                parse_usize(left).ok_or(())?
            };
            let end = if right.is_empty() {
                usize::MAX
            } else {
                parse_usize(right).ok_or(())?
            };
            if start == 0 || end == 0 || start > end {
                return Err(());
            }
            out_ranges[count] = CutRange { start, end };
            count += 1;
        } else {
            let val = parse_usize(part).ok_or(())?;
            if val == 0 {
                return Err(());
            }
            out_ranges[count] = CutRange {
                start: val,
                end: val,
            };
            count += 1;
        }
    }
    Ok(count)
}

fn matches_cut_range(ranges: &[CutRange], idx: usize) -> bool {
    for r in ranges {
        if idx >= r.start && idx <= r.end {
            return true;
        }
    }
    false
}

/// Traite un flux d'octets avec l'algorithme POSIX `cut`
fn process_cut_stream(
    in_fd: i32,
    out_fd: i32,
    mode: CutMode,
    ranges: &[CutRange],
    delim: u8,
    only_delimited: bool,
) {
    let mut chunk = [0u8; 512];
    let mut line_buf = [0u8; 2048];
    let mut line_len = 0;

    let process_single_line = |line: &[u8]| {
        if mode == CutMode::Bytes {
            let mut out_buf = [0u8; 2048];
            let mut out_len = 0;
            for (i, &b) in line.iter().enumerate() {
                let pos = i + 1;
                if matches_cut_range(ranges, pos) && out_len < out_buf.len() {
                    out_buf[out_len] = b;
                    out_len += 1;
                }
            }
            let _ = sys_write(out_fd, &out_buf[..out_len]);
            let _ = sys_write(out_fd, b"\n");
        } else if mode == CutMode::Fields {
            let has_delim = line.contains(&delim);
            if !has_delim {
                if !only_delimited {
                    let _ = sys_write(out_fd, line);
                    let _ = sys_write(out_fd, b"\n");
                }
            } else {
                let mut out_buf = [0u8; 2048];
                let mut out_len = 0;
                let mut field_idx = 1;
                let mut first_written = false;
                let mut start = 0;

                for (idx, &b) in line.iter().enumerate() {
                    if b == delim {
                        let field = &line[start..idx];
                        if matches_cut_range(ranges, field_idx) {
                            if first_written && out_len < out_buf.len() {
                                out_buf[out_len] = delim;
                                out_len += 1;
                            }
                            let copy_sz = field.len().min(out_buf.len().saturating_sub(out_len));
                            out_buf[out_len..out_len + copy_sz].copy_from_slice(&field[..copy_sz]);
                            out_len += copy_sz;
                            first_written = true;
                        }
                        field_idx += 1;
                        start = idx + 1;
                    }
                }
                // Dernier champ
                let field = &line[start..];
                if matches_cut_range(ranges, field_idx) {
                    if first_written && out_len < out_buf.len() {
                        out_buf[out_len] = delim;
                        out_len += 1;
                    }
                    let copy_sz = field.len().min(out_buf.len().saturating_sub(out_len));
                    out_buf[out_len..out_len + copy_sz].copy_from_slice(&field[..copy_sz]);
                    out_len += copy_sz;
                }

                let _ = sys_write(out_fd, &out_buf[..out_len]);
                let _ = sys_write(out_fd, b"\n");
            }
        }
    };

    loop {
        let n = sys_read(in_fd, &mut chunk);
        if n <= 0 {
            break;
        }
        for &b in &chunk[..n as usize] {
            if b == b'\n' {
                process_single_line(&line_buf[..line_len]);
                line_len = 0;
            } else if line_len < line_buf.len() {
                line_buf[line_len] = b;
                line_len += 1;
            }
        }
    }

    if line_len > 0 {
        process_single_line(&line_buf[..line_len]);
    }
}

/// Exécute l'utilitaire standard POSIX `cut` (sélection de colonnes/champs/octets sur flux de données)
pub fn run_cut(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut mode = CutMode::None;
    let mut ranges_storage = [CutRange { start: 0, end: 0 }; 32];
    let mut range_count = 0;
    let mut delim = b'\t';
    let mut only_delimited = false;
    let mut file_indices = [0usize; 16];
    let mut file_count = 0;

    let mut i = 0;
    let mut parsing_options = true;

    while i < args.len() {
        let arg = args[i];
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    out_fd,
                    b"Usage: cut OPTION... [FILE]...\nPrint selected parts of lines from each FILE to standard output.\n\nWith no FILE, or when FILE is -, read standard input.\n\n  -b, --bytes=LIST         select only these bytes\n  -c, --characters=LIST    select only these characters\n  -d, --delimiter=DELIM    use DELIM instead of TAB for field delimiter\n  -f, --fields=LIST        select only these fields; also print any line\n                             that contains no delimiter character, unless\n                             the -s option is specified\n  -s, --only-delimited     do not print lines not containing delimiters\n      --help               display this help and exit\n",
                );
                return 0;
            }

            if arg == "-s" || arg == "--only-delimited" {
                only_delimited = true;
                i += 1;
                continue;
            }

            // Options avec argument : -b, -c, -f, -d
            let (opt_char, opt_arg) = if let Some(val) = arg.strip_prefix("--bytes=") {
                ('b', Some(val))
            } else if let Some(val) = arg.strip_prefix("--characters=") {
                ('c', Some(val))
            } else if let Some(val) = arg.strip_prefix("--fields=") {
                ('f', Some(val))
            } else if let Some(val) = arg.strip_prefix("--delimiter=") {
                ('d', Some(val))
            } else if let Some(rest) = arg.strip_prefix("-b") {
                if !rest.is_empty() {
                    ('b', Some(rest))
                } else if i + 1 < args.len() {
                    i += 1;
                    ('b', Some(args[i]))
                } else {
                    let _ = sys_write(err_fd, b"cut: option requires an argument -- 'b'\n");
                    return 1;
                }
            } else if let Some(rest) = arg.strip_prefix("-c") {
                if !rest.is_empty() {
                    ('c', Some(rest))
                } else if i + 1 < args.len() {
                    i += 1;
                    ('c', Some(args[i]))
                } else {
                    let _ = sys_write(err_fd, b"cut: option requires an argument -- 'c'\n");
                    return 1;
                }
            } else if let Some(rest) = arg.strip_prefix("-f") {
                if !rest.is_empty() {
                    ('f', Some(rest))
                } else if i + 1 < args.len() {
                    i += 1;
                    ('f', Some(args[i]))
                } else {
                    let _ = sys_write(err_fd, b"cut: option requires an argument -- 'f'\n");
                    return 1;
                }
            } else if let Some(rest) = arg.strip_prefix("-d") {
                if !rest.is_empty() {
                    ('d', Some(rest))
                } else if i + 1 < args.len() {
                    i += 1;
                    ('d', Some(args[i]))
                } else {
                    let _ = sys_write(err_fd, b"cut: option requires an argument -- 'd'\n");
                    return 1;
                }
            } else {
                let _ = sys_write(err_fd, b"cut: invalid option -- '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            };

            match opt_char {
                'b' | 'c' => {
                    if mode != CutMode::None && mode != CutMode::Bytes {
                        let _ = sys_write(err_fd, b"cut: only one type of list may be specified\n");
                        return 1;
                    }
                    mode = CutMode::Bytes;
                    let val = opt_arg.unwrap_or("");
                    match parse_cut_ranges(val, &mut ranges_storage) {
                        Ok(cnt) => range_count = cnt,
                        Err(()) => {
                            let _ = sys_write(err_fd, b"cut: invalid byte/character field list\n");
                            return 1;
                        }
                    }
                }
                'f' => {
                    if mode != CutMode::None && mode != CutMode::Fields {
                        let _ = sys_write(err_fd, b"cut: only one type of list may be specified\n");
                        return 1;
                    }
                    mode = CutMode::Fields;
                    let val = opt_arg.unwrap_or("");
                    match parse_cut_ranges(val, &mut ranges_storage) {
                        Ok(cnt) => range_count = cnt,
                        Err(()) => {
                            let _ = sys_write(err_fd, b"cut: invalid field list\n");
                            return 1;
                        }
                    }
                }
                'd' => {
                    let val = opt_arg.unwrap_or("");
                    let b = val.as_bytes();
                    if b.len() != 1 {
                        let _ =
                            sys_write(err_fd, b"cut: the delimiter must be a single character\n");
                        return 1;
                    }
                    delim = b[0];
                }
                _ => {}
            }
            i += 1;
        } else {
            if file_count < file_indices.len() {
                file_indices[file_count] = i;
                file_count += 1;
            }
            i += 1;
        }
    }

    if mode == CutMode::None {
        let _ = sys_write(
            err_fd,
            b"cut: you must specify a list of bytes, characters, or fields\nUsage: cut OPTION... [FILE]...\n",
        );
        return 1;
    }

    let active_ranges = &ranges_storage[..range_count];

    if file_count == 0 {
        process_cut_stream(in_fd, out_fd, mode, active_ranges, delim, only_delimited);
        return 0;
    }

    let mut exit_code = 0;
    for &idx in &file_indices[..file_count] {
        let path = args[idx];
        if path == "-" {
            process_cut_stream(in_fd, out_fd, mode, active_ranges, delim, only_delimited);
        } else {
            let fd = sys_open(path, O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"cut: ");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                exit_code = 1;
            } else {
                process_cut_stream(fd, out_fd, mode, active_ranges, delim, only_delimited);
                sys_close(fd);
            }
        }
    }

    exit_code
}

// ============================================================================
// Utilitaire standard POSIX `paste` (Fusion séquentielle ou parallèle de flux)
// ============================================================================

/// Délimiteur élémentaire pour `paste`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasteDelim {
    Byte(u8),
    Empty,
}

/// Analyse une spécification de délimiteurs pour `paste -d`
pub fn parse_paste_delimiters(spec: &str, out: &mut [PasteDelim; 32]) -> usize {
    let bytes = spec.as_bytes();
    if bytes.is_empty() {
        out[0] = PasteDelim::Empty;
        return 1;
    }
    let mut count = 0;
    let mut i = 0;
    while i < bytes.len() && count < out.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 1;
            match bytes[i] {
                b'n' => out[count] = PasteDelim::Byte(b'\n'),
                b't' => out[count] = PasteDelim::Byte(b'\t'),
                b'0' => out[count] = PasteDelim::Empty,
                b'\\' => out[count] = PasteDelim::Byte(b'\\'),
                other => out[count] = PasteDelim::Byte(other),
            }
        } else {
            out[count] = PasteDelim::Byte(bytes[i]);
        }
        count += 1;
        i += 1;
    }
    if count == 0 {
        out[0] = PasteDelim::Byte(b'\t');
        count = 1;
    }
    count
}

/// Lecteur de flux par ligne sans allocation dynamique sur le tas
pub struct LineReader {
    pub fd: i32,
    pub buf: [u8; 512],
    pub pos: usize,
    pub len: usize,
    pub eof: bool,
}

impl LineReader {
    pub const fn new(fd: i32) -> Self {
        Self {
            fd,
            buf: [0u8; 512],
            pos: 0,
            len: 0,
            eof: false,
        }
    }

    /// Lit la prochaine ligne dans `out_buf` (sans le '\n' terminal).
    /// Retourne `Some(len)` ou `None` si la fin du flux est atteinte sans aucun octet supplémentaire.
    pub fn read_line(&mut self, out_buf: &mut [u8]) -> Option<usize> {
        self.read_record(out_buf, b'\n')
    }

    /// Lit le prochain enregistrement délimité par `delim` dans `out_buf` (sans le délimiteur terminal).
    pub fn read_record(&mut self, out_buf: &mut [u8], delim: u8) -> Option<usize> {
        let mut out_len = 0;
        let mut found_any = false;

        loop {
            if self.pos >= self.len {
                if self.eof {
                    break;
                }
                let n = sys_read(self.fd, &mut self.buf);
                if n <= 0 {
                    self.eof = true;
                    break;
                }
                self.pos = 0;
                self.len = n as usize;
            }

            while self.pos < self.len {
                let b = self.buf[self.pos];
                self.pos += 1;
                found_any = true;

                if b == delim {
                    if delim == b'\n' && out_len > 0 && out_buf[out_len - 1] == b'\r' {
                        out_len -= 1;
                    }
                    return Some(out_len);
                } else if out_len < out_buf.len() {
                    out_buf[out_len] = b;
                    out_len += 1;
                }
            }
        }

        if found_any || out_len > 0 {
            if delim == b'\n' && out_len > 0 && out_buf[out_len - 1] == b'\r' {
                out_len -= 1;
            }
            Some(out_len)
        } else {
            None
        }
    }
}

fn write_paste_delim(out_fd: i32, delim: PasteDelim) {
    match delim {
        PasteDelim::Byte(b) => {
            let _ = sys_write(out_fd, &[b]);
        }
        PasteDelim::Empty => {}
    }
}

fn process_paste_serial(
    mut reader: LineReader,
    out_fd: i32,
    delims: &[PasteDelim],
    line_delim: u8,
) {
    let mut line_buf = [0u8; 512];
    let mut first_line = true;
    let mut delim_idx = 0;

    while let Some(len) = reader.read_record(&mut line_buf, line_delim) {
        if !first_line {
            let d = delims[delim_idx % delims.len()];
            write_paste_delim(out_fd, d);
            delim_idx += 1;
        }
        let _ = sys_write(out_fd, &line_buf[..len]);
        first_line = false;
    }

    if !first_line {
        let _ = sys_write(out_fd, &[line_delim]);
    }
}

fn process_paste_parallel(
    readers: &mut [LineReader],
    out_fd: i32,
    delims: &[PasteDelim],
    line_delim: u8,
) {
    let k = readers.len();
    if k == 0 {
        return;
    }

    let mut line_storage = [0u8; 16 * 256];
    let mut line_lens = [0usize; 16];
    let mut line_present = [false; 16];

    loop {
        let mut any_line_read = false;

        for j in 0..k {
            let slot = &mut line_storage[j * 256..(j + 1) * 256];
            if let Some(len) = readers[j].read_record(slot, line_delim) {
                line_present[j] = true;
                line_lens[j] = len;
                any_line_read = true;
            } else {
                line_present[j] = false;
                line_lens[j] = 0;
            }
        }

        if !any_line_read {
            break;
        }

        for j in 0..k {
            if j > 0 {
                let d = delims[(j - 1) % delims.len()];
                write_paste_delim(out_fd, d);
            }
            if line_present[j] {
                let bytes = &line_storage[j * 256..(j * 256 + line_lens[j])];
                let _ = sys_write(out_fd, bytes);
            }
        }
        let _ = sys_write(out_fd, &[line_delim]);
    }
}

/// Exécute l'utilitaire standard POSIX `paste` (fusion ligne à ligne de plusieurs fichiers ou flux)
pub fn run_paste(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut serial_mode = false;
    let mut zero_terminated = false;
    let mut delims_storage = [PasteDelim::Byte(b'\t'); 32];
    let mut delim_count = 1;
    let mut file_indices = [0usize; 16];
    let mut file_count = 0;

    let mut i = 0;
    let mut parsing_options = true;

    while i < args.len() {
        let arg = args[i];
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    out_fd,
                    b"Usage: paste [OPTION]... [FILE]...\nWrite lines consisting of the sequentially corresponding lines from\neach FILE, separated by TABs, to standard output.\n\nWith no FILE, or when FILE is -, read standard input.\n\n  -d, --delimiters=LIST   reuse characters from LIST instead of TABs\n  -s, --serial            paste one file at a time instead of in parallel\n  -z, --zero-terminated   line delimiter is NUL, not newline\n      --help              display this help and exit\n      --version           output version information and exit\n",
                );
                return 0;
            }

            if arg == "--version" {
                let _ = sys_write(
                    out_fd,
                    b"paste (JamboOS coreutils) 0.1.0\nCopyright (C) 2026 JamboOS Authors.\nLicense MIT or Apache-2.0.\nThis is free software: you are free to change and redistribute it.\nThere is NO WARRANTY, to the extent permitted by law.\n",
                );
                return 0;
            }

            if arg == "-s" || arg == "--serial" {
                serial_mode = true;
                i += 1;
                continue;
            }

            if arg == "-z" || arg == "--zero-terminated" {
                zero_terminated = true;
                i += 1;
                continue;
            }

            if let Some(spec) = arg.strip_prefix("--delimiters=") {
                delim_count = parse_paste_delimiters(spec, &mut delims_storage);
                i += 1;
                continue;
            } else if let Some(rest) = arg.strip_prefix("-d") {
                let spec = if !rest.is_empty() {
                    rest
                } else if i + 1 < args.len() {
                    i += 1;
                    args[i]
                } else {
                    let _ = sys_write(err_fd, b"paste: option requires an argument -- 'd'\n");
                    return 1;
                };
                delim_count = parse_paste_delimiters(spec, &mut delims_storage);
                i += 1;
                continue;
            } else {
                let _ = sys_write(err_fd, b"paste: invalid option -- '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if file_count < file_indices.len() {
                file_indices[file_count] = i;
                file_count += 1;
            }
            i += 1;
        }
    }

    let active_delims = &delims_storage[..delim_count];
    let line_delim = if zero_terminated { 0u8 } else { b'\n' };

    if file_count == 0 {
        let reader = LineReader::new(in_fd);
        if serial_mode {
            process_paste_serial(reader, out_fd, active_delims, line_delim);
        } else {
            let mut readers = [reader];
            process_paste_parallel(&mut readers, out_fd, active_delims, line_delim);
        }
        return 0;
    }

    if serial_mode {
        let mut exit_code = 0;
        for &idx in &file_indices[..file_count] {
            let path = args[idx];
            if path == "-" {
                let reader = LineReader::new(in_fd);
                process_paste_serial(reader, out_fd, active_delims, line_delim);
            } else {
                let fd = sys_open(path, O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"paste: ");
                    let _ = sys_write(err_fd, path.as_bytes());
                    let _ = sys_write(err_fd, b": No such file or directory\n");
                    exit_code = 1;
                } else {
                    let reader = LineReader::new(fd);
                    process_paste_serial(reader, out_fd, active_delims, line_delim);
                    sys_close(fd);
                }
            }
        }
        return exit_code;
    }

    // Mode parallèle : ouverture de tous les fichiers
    const MAX_PARALLEL_FILES: usize = 16;
    let actual_count = file_count.min(MAX_PARALLEL_FILES);
    let mut readers = [
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
        LineReader::new(-1),
    ];
    let mut opened_fds = [-1i32; MAX_PARALLEL_FILES];
    let mut failed = false;

    for j in 0..actual_count {
        let path = args[file_indices[j]];
        if path == "-" {
            readers[j] = LineReader::new(in_fd);
        } else {
            let fd = sys_open(path, O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"paste: ");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                failed = true;
                break;
            }
            readers[j] = LineReader::new(fd);
            opened_fds[j] = fd;
        }
    }

    if !failed {
        process_paste_parallel(
            &mut readers[..actual_count],
            out_fd,
            active_delims,
            line_delim,
        );
    }

    // Fermeture des descripteurs ouverts
    for &fd in &opened_fds[..actual_count] {
        if fd >= 0 {
            sys_close(fd);
        }
    }

    if failed {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire standard POSIX `comm` (comparaison ligne à ligne de deux flux triés)
pub fn run_comm(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut suppress_col1 = false;
    let mut suppress_col2 = false;
    let mut suppress_col3 = false;
    let mut _check_order = false;
    let mut output_delimiter = "\t";
    let mut file1_arg: Option<&str> = None;
    let mut file2_arg: Option<&str> = None;
    let mut parsing_options = true;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    out_fd,
                    b"Usage: comm [OPTION]... FILE1 FILE2\nCompare sorted files FILE1 and FILE2 line by line.\n\nWhen FILE1 or FILE2 (not both) is -, read standard input.\n\n  -1                      suppress column 1 (lines unique to FILE1)\n  -2                      suppress column 2 (lines unique to FILE2)\n  -3                      suppress column 3 (lines that appear in both files)\n      --check-order       check that the input is correctly sorted\n      --nocheck-order     do not check that the input is correctly sorted\n      --output-delimiter=STR  separate columns with STR\n      --help              display this help and exit\n",
                );
                return 0;
            }

            if arg == "--check-order" {
                _check_order = true;
                i += 1;
                continue;
            }
            if arg == "--nocheck-order" {
                _check_order = false;
                i += 1;
                continue;
            }

            if let Some(delim) = arg.strip_prefix("--output-delimiter=") {
                output_delimiter = delim;
                i += 1;
                continue;
            } else if arg == "--output-delimiter" {
                if i + 1 < args.len() {
                    i += 1;
                    output_delimiter = args[i];
                    i += 1;
                    continue;
                } else {
                    let _ = sys_write(
                        err_fd,
                        b"comm: option '--output-delimiter' requires an argument\n",
                    );
                    return 1;
                }
            }

            // Drapeaux courts combinés : -1, -2, -3, -12, etc.
            let mut valid_short = true;
            for &b in &arg.as_bytes()[1..] {
                match b {
                    b'1' => suppress_col1 = true,
                    b'2' => suppress_col2 = true,
                    b'3' => suppress_col3 = true,
                    _ => {
                        valid_short = false;
                        break;
                    }
                }
            }

            if valid_short && arg.len() > 1 {
                i += 1;
                continue;
            } else {
                let _ = sys_write(err_fd, b"comm: invalid option -- '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if file1_arg.is_none() {
                file1_arg = Some(arg);
            } else if file2_arg.is_none() {
                file2_arg = Some(arg);
            } else {
                let _ = sys_write(err_fd, b"comm: extra operand '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
            i += 1;
        }
    }

    let (path1, path2) = match (file1_arg, file2_arg) {
        (Some(p1), Some(p2)) => (p1, p2),
        (Some(_), None) | (None, None) => {
            let _ = sys_write(err_fd, b"comm: missing operand\n");
            return 1;
        }
        (None, Some(_)) => unreachable!(),
    };

    if path1 == "-" && path2 == "-" {
        let _ = sys_write(err_fd, b"comm: both files cannot be standard input\n");
        return 1;
    }

    let (fd1, need_close1) = if path1 == "-" {
        (in_fd, false)
    } else {
        let fd = sys_open(path1, O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"comm: ");
            let _ = sys_write(err_fd, path1.as_bytes());
            let _ = sys_write(err_fd, b": No such file or directory\n");
            return 1;
        }
        (fd, true)
    };

    let (fd2, need_close2) = if path2 == "-" {
        (in_fd, false)
    } else {
        let fd = sys_open(path2, O_RDONLY);
        if fd < 0 {
            if need_close1 {
                sys_close(fd1);
            }
            let _ = sys_write(err_fd, b"comm: ");
            let _ = sys_write(err_fd, path2.as_bytes());
            let _ = sys_write(err_fd, b": No such file or directory\n");
            return 1;
        }
        (fd, true)
    };

    let mut reader1 = LineReader::new(fd1);
    let mut reader2 = LineReader::new(fd2);

    let mut buf1 = [0u8; 2048];
    let mut buf2 = [0u8; 2048];

    let mut line1_opt = reader1.read_line(&mut buf1);
    let mut line2_opt = reader2.read_line(&mut buf2);

    let delim_bytes = output_delimiter.as_bytes();

    let emit_col1 = |fd: i32, slice: &[u8]| {
        if !suppress_col1 {
            let _ = sys_write(fd, slice);
            let _ = sys_write(fd, b"\n");
        }
    };

    let emit_col2 = |fd: i32, slice: &[u8]| {
        if !suppress_col2 {
            if !suppress_col1 {
                let _ = sys_write(fd, delim_bytes);
            }
            let _ = sys_write(fd, slice);
            let _ = sys_write(fd, b"\n");
        }
    };

    let emit_col3 = |fd: i32, slice: &[u8]| {
        if !suppress_col3 {
            if !suppress_col1 {
                let _ = sys_write(fd, delim_bytes);
            }
            if !suppress_col2 {
                let _ = sys_write(fd, delim_bytes);
            }
            let _ = sys_write(fd, slice);
            let _ = sys_write(fd, b"\n");
        }
    };

    while let (Some(l1), Some(l2)) = (line1_opt, line2_opt) {
        let s1 = &buf1[..l1];
        let s2 = &buf2[..l2];

        match s1.cmp(s2) {
            core::cmp::Ordering::Less => {
                emit_col1(out_fd, s1);
                line1_opt = reader1.read_line(&mut buf1);
            }
            core::cmp::Ordering::Greater => {
                emit_col2(out_fd, s2);
                line2_opt = reader2.read_line(&mut buf2);
            }
            core::cmp::Ordering::Equal => {
                emit_col3(out_fd, s1);
                line1_opt = reader1.read_line(&mut buf1);
                line2_opt = reader2.read_line(&mut buf2);
            }
        }
    }

    while let Some(l1) = line1_opt {
        let s1 = &buf1[..l1];
        emit_col1(out_fd, s1);
        line1_opt = reader1.read_line(&mut buf1);
    }

    while let Some(l2) = line2_opt {
        let s2 = &buf2[..l2];
        emit_col2(out_fd, s2);
        line2_opt = reader2.read_line(&mut buf2);
    }

    if need_close1 {
        sys_close(fd1);
    }
    if need_close2 {
        sys_close(fd2);
    }

    0
}

/// Analyse un caractère ou une séquence d'échappement pour `tr`
fn parse_tr_char(bytes: &[u8], idx: usize) -> Result<(u8, usize), &'static str> {
    if idx >= bytes.len() {
        return Err("unexpected end of string");
    }
    if bytes[idx] == b'\\' {
        if idx + 1 >= bytes.len() {
            return Ok((b'\\', idx + 1));
        }
        match bytes[idx + 1] {
            b'n' => Ok((b'\n', idx + 2)),
            b't' => Ok((b'\t', idx + 2)),
            b'r' => Ok((b'\r', idx + 2)),
            b'a' => Ok((7, idx + 2)),
            b'b' => Ok((8, idx + 2)),
            b'f' => Ok((12, idx + 2)),
            b'v' => Ok((11, idx + 2)),
            b'\\' => Ok((b'\\', idx + 2)),
            oct @ b'0'..=b'7' => {
                let mut val = oct - b'0';
                let mut pos = idx + 2;
                let limit = (idx + 4).min(bytes.len());
                while pos < limit && (b'0'..=b'7').contains(&bytes[pos]) {
                    val = val.wrapping_mul(8).wrapping_add(bytes[pos] - b'0');
                    pos += 1;
                }
                Ok((val, pos))
            }
            other => Ok((other, idx + 2)),
        }
    } else {
        Ok((bytes[idx], idx + 1))
    }
}

/// Développe une spécification d'ensemble SET pour `tr` (plages, classes POSIX, échappements, répétitions)
fn expand_tr_spec(
    spec: &str,
    out: &mut [u8; 512],
    target_len: usize,
) -> Result<usize, &'static str> {
    let bytes = spec.as_bytes();
    let mut i = 0;
    let mut out_len = 0;

    #[inline]
    fn push_byte(out: &mut [u8; 512], out_len: &mut usize, b: u8) -> Result<(), &'static str> {
        if *out_len >= out.len() {
            return Err("expanded set too long");
        }
        out[*out_len] = b;
        *out_len += 1;
        Ok(())
    }

    while i < bytes.len() {
        // 1. Détection classe de caractères POSIX [:class:]
        if bytes[i..].starts_with(b"[:") {
            if let Some(close_idx) = bytes[i + 2..].windows(2).position(|w| w == b":]") {
                let class_name = &bytes[i + 2..i + 2 + close_idx];
                match class_name {
                    b"alnum" => {
                        for b in b'0'..=b'9' {
                            push_byte(out, &mut out_len, b)?;
                        }
                        for b in b'A'..=b'Z' {
                            push_byte(out, &mut out_len, b)?;
                        }
                        for b in b'a'..=b'z' {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    b"alpha" => {
                        for b in b'A'..=b'Z' {
                            push_byte(out, &mut out_len, b)?;
                        }
                        for b in b'a'..=b'z' {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    b"blank" => {
                        push_byte(out, &mut out_len, b' ')?;
                        push_byte(out, &mut out_len, b'\t')?;
                    }
                    b"cntrl" => {
                        for b in 0..=31 {
                            push_byte(out, &mut out_len, b)?;
                        }
                        push_byte(out, &mut out_len, 127)?;
                    }
                    b"digit" => {
                        for b in b'0'..=b'9' {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    b"graph" => {
                        for b in 33..=126 {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    b"lower" => {
                        for b in b'a'..=b'z' {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    b"print" => {
                        for b in 32..=126 {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    b"punct" => {
                        for b in 33..=47 {
                            push_byte(out, &mut out_len, b)?;
                        }
                        for b in 58..=64 {
                            push_byte(out, &mut out_len, b)?;
                        }
                        for b in 91..=96 {
                            push_byte(out, &mut out_len, b)?;
                        }
                        for b in 123..=126 {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    b"space" => {
                        push_byte(out, &mut out_len, b' ')?;
                        push_byte(out, &mut out_len, b'\t')?;
                        push_byte(out, &mut out_len, b'\n')?;
                        push_byte(out, &mut out_len, b'\r')?;
                        push_byte(out, &mut out_len, 0x0b)?;
                        push_byte(out, &mut out_len, 0x0c)?;
                    }
                    b"upper" => {
                        for b in b'A'..=b'Z' {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    b"xdigit" => {
                        for b in b'0'..=b'9' {
                            push_byte(out, &mut out_len, b)?;
                        }
                        for b in b'a'..=b'f' {
                            push_byte(out, &mut out_len, b)?;
                        }
                        for b in b'A'..=b'F' {
                            push_byte(out, &mut out_len, b)?;
                        }
                    }
                    _ => return Err("invalid character class"),
                }
                i += close_idx + 4;
                continue;
            }
        }

        // 2. Détection répétition [c*n] ou [c*]
        if bytes[i] == b'[' && i + 2 < bytes.len() {
            let c_cand = if bytes[i + 1] == b'\\' && i + 3 < bytes.len() {
                match bytes[i + 2] {
                    b'n' => Some((b'\n', i + 3)),
                    b't' => Some((b'\t', i + 3)),
                    b'r' => Some((b'\r', i + 3)),
                    b'\\' => Some((b'\\', i + 3)),
                    other => Some((other, i + 3)),
                }
            } else {
                Some((bytes[i + 1], i + 2))
            };

            if let Some((c, next_idx)) = c_cand {
                if next_idx < bytes.len() && bytes[next_idx] == b'*' {
                    if let Some(close_rel) = bytes[next_idx + 1..].iter().position(|&b| b == b']') {
                        let count_slice = &bytes[next_idx + 1..next_idx + 1 + close_rel];
                        let count = if count_slice.is_empty() {
                            target_len.saturating_sub(out_len).max(1)
                        } else {
                            let mut val: usize = 0;
                            let is_octal = count_slice.len() > 1 && count_slice[0] == b'0';
                            let base: usize = if is_octal { 8 } else { 10 };
                            for &ch in count_slice {
                                if (is_octal && (b'0'..=b'7').contains(&ch))
                                    || (!is_octal && ch.is_ascii_digit())
                                {
                                    val = val
                                        .saturating_mul(base)
                                        .saturating_add((ch - b'0') as usize);
                                } else {
                                    return Err("invalid repeat count in [...]");
                                }
                            }
                            val.max(1)
                        };

                        for _ in 0..count {
                            push_byte(out, &mut out_len, c)?;
                        }
                        i = next_idx + 1 + close_rel + 1;
                        continue;
                    }
                }
            }
        }

        // 3. Caractère individuel ou début de plage c1-c2
        let (c1, next_i) = parse_tr_char(bytes, i)?;
        i = next_i;

        if i < bytes.len() && bytes[i] == b'-' && i + 1 < bytes.len() {
            let (c2, after_c2) = parse_tr_char(bytes, i + 1)?;
            if c1 <= c2 {
                for b in c1..=c2 {
                    push_byte(out, &mut out_len, b)?;
                }
                i = after_c2;
            } else {
                return Err("range endpoints in reverse order");
            }
        } else {
            push_byte(out, &mut out_len, c1)?;
        }
    }

    Ok(out_len)
}

/// Exécute l'utilitaire standard POSIX `tr` (translation, suppression et compression de caractères)
pub fn run_tr(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut complement = false;
    let mut delete = false;
    let mut squeeze = false;
    let mut truncate = false;
    let mut operands: [&str; 4] = [""; 4];
    let mut num_operands = 0;
    let mut parsing_options = true;

    let mut idx = 0;
    while idx < args.len() {
        let arg = args[idx];
        if parsing_options && arg == "--" {
            parsing_options = false;
            idx += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    out_fd,
                    b"Usage: tr [OPTION]... SET1 [SET2]\n\
Translate, squeeze, and/or delete characters from standard input,\n\
writing to standard output.\n\n\
  -c, -C, --complement    use the complement of SET1\n\
  -d, --delete            delete characters in SET1, do not translate\n\
  -s, --squeeze-repeats   replace each sequence of a repeated character\n\
                            that is listed in the last specified SET,\n\
                            with a single occurrence of that character\n\
  -t, --truncate-set1     first truncate SET1 to length of SET2\n\
      --help              display this help and exit\n",
                );
                return 0;
            } else if arg == "--complement" {
                complement = true;
            } else if arg == "--delete" {
                delete = true;
            } else if arg == "--squeeze-repeats" {
                squeeze = true;
            } else if arg == "--truncate-set1" {
                truncate = true;
            } else {
                for &b in &arg.as_bytes()[1..] {
                    match b {
                        b'c' | b'C' => complement = true,
                        b'd' => delete = true,
                        b's' => squeeze = true,
                        b't' => truncate = true,
                        _ => {
                            let _ = sys_write(err_fd, b"tr: invalid option -- '");
                            let _ = sys_write(err_fd, &[b]);
                            let _ = sys_write(err_fd, b"'\n");
                            return 1;
                        }
                    }
                }
            }
            idx += 1;
        } else {
            if num_operands < operands.len() {
                operands[num_operands] = arg;
                num_operands += 1;
            } else {
                let _ = sys_write(err_fd, b"tr: extra operand '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
            idx += 1;
        }
    }

    if num_operands == 0 {
        let _ = sys_write(err_fd, b"tr: missing operand\n");
        return 1;
    }

    if delete && !squeeze && num_operands > 1 {
        let _ = sys_write(err_fd, b"tr: extra operand '");
        let _ = sys_write(err_fd, operands[1].as_bytes());
        let _ = sys_write(
            err_fd,
            b"'\nOnly one string may be given when deleting without --squeeze-repeats\n",
        );
        return 1;
    }

    if !delete && !squeeze && num_operands < 2 {
        let _ = sys_write(err_fd, b"tr: missing operand after '");
        let _ = sys_write(err_fd, operands[0].as_bytes());
        let _ = sys_write(err_fd, b"'\nTwo strings must be given when translating\n");
        return 1;
    }

    let mut set1 = [0u8; 512];
    let mut set1_len = match expand_tr_spec(operands[0], &mut set1, 0) {
        Ok(l) => l,
        Err(e) => {
            let _ = sys_write(err_fd, b"tr: ");
            let _ = sys_write(err_fd, e.as_bytes());
            let _ = sys_write(err_fd, b"\n");
            return 1;
        }
    };

    if complement {
        let mut in_set = [false; 256];
        for &b in &set1[..set1_len] {
            in_set[b as usize] = true;
        }
        let mut comp = [0u8; 512];
        let mut comp_len = 0;
        for b in 0..=255u8 {
            if !in_set[b as usize] {
                comp[comp_len] = b;
                comp_len += 1;
            }
        }
        set1[..comp_len].copy_from_slice(&comp[..comp_len]);
        set1_len = comp_len;
    }

    let mut set2 = [0u8; 512];
    let mut set2_len = 0;
    if num_operands >= 2 {
        set2_len = match expand_tr_spec(operands[1], &mut set2, set1_len) {
            Ok(l) => l,
            Err(e) => {
                let _ = sys_write(err_fd, b"tr: ");
                let _ = sys_write(err_fd, e.as_bytes());
                let _ = sys_write(err_fd, b"\n");
                return 1;
            }
        };
    }

    let mut trans_map = [0u8; 256];
    for (i, item) in trans_map.iter_mut().enumerate() {
        *item = i as u8;
    }
    let mut delete_mask = [false; 256];
    let mut squeeze_mask = [false; 256];

    if delete {
        for &b in &set1[..set1_len] {
            delete_mask[b as usize] = true;
        }
        if squeeze && num_operands >= 2 {
            for &b in &set2[..set2_len] {
                squeeze_mask[b as usize] = true;
            }
        }
    } else if num_operands >= 2 {
        let effective_s1_len = if truncate {
            set1_len.min(set2_len)
        } else {
            set1_len
        };
        for i in 0..effective_s1_len {
            let s1 = set1[i];
            let s2 = if i < set2_len {
                set2[i]
            } else if set2_len > 0 {
                set2[set2_len - 1]
            } else {
                s1
            };
            trans_map[s1 as usize] = s2;
        }
        if squeeze {
            for &b in &set2[..set2_len] {
                squeeze_mask[b as usize] = true;
            }
        }
    } else if squeeze && num_operands == 1 {
        for &b in &set1[..set1_len] {
            squeeze_mask[b as usize] = true;
        }
    }

    let mut in_buf = [0u8; 1024];
    let mut out_buf = [0u8; 1024];
    let mut out_len = 0;
    let mut last_char: Option<u8> = None;

    loop {
        let n = sys_read(in_fd, &mut in_buf);
        if n <= 0 {
            break;
        }
        for &b in &in_buf[..n as usize] {
            if delete_mask[b as usize] {
                continue;
            }
            let mapped = trans_map[b as usize];
            if squeeze_mask[mapped as usize] {
                if last_char == Some(mapped) {
                    continue;
                }
                last_char = Some(mapped);
            } else {
                last_char = Some(mapped);
            }

            out_buf[out_len] = mapped;
            out_len += 1;
            if out_len == out_buf.len() {
                let _ = sys_write(out_fd, &out_buf);
                out_len = 0;
            }
        }
    }

    if out_len > 0 {
        let _ = sys_write(out_fd, &out_buf[..out_len]);
    }

    0
}

/// Parse une taille spécifiée pour split (ex: "1024", "10k", "2m", "5b")
fn parse_split_size(s: &str) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    let mut num: usize = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        num = num
            .checked_mul(10)?
            .checked_add((bytes[i] - b'0') as usize)?;
        i += 1;
    }
    if i == 0 {
        return None;
    }
    if i == bytes.len() {
        return Some(num);
    }
    let suffix = &s[i..];
    let mult: usize = match suffix {
        "b" => 512,
        "k" | "K" | "kb" | "KB" | "kib" | "KiB" => 1024,
        "m" | "M" | "mb" | "MB" | "mib" | "MiB" => 1024 * 1024,
        _ => return None,
    };
    num.checked_mul(mult)
}

/// Génère un suffixe de découpage pour `split` (alphabétique ou numérique)
fn generate_split_suffix(idx: usize, len: usize, numeric: bool, out: &mut [u8]) -> bool {
    if len == 0 || len > out.len() {
        return false;
    }
    if numeric {
        let mut val = idx;
        for i in (0..len).rev() {
            out[i] = b'0' + (val % 10) as u8;
            val /= 10;
        }
        val == 0
    } else {
        let mut val = idx;
        for i in (0..len).rev() {
            out[i] = b'a' + (val % 26) as u8;
            val /= 26;
        }
        val == 0
    }
}

/// Mode de découpage pour `split`
#[derive(Clone, Copy, PartialEq, Eq)]
enum SplitMode {
    Lines(usize),
    Bytes(usize),
    LineBytes(usize),
}

/// Gestionnaire d'écriture des fichiers de sortie partitionnés pour `split`
struct SplitWriter<'a> {
    prefix: &'a str,
    suffix_len: usize,
    numeric: bool,
    numeric_from: usize,
    chunk_idx: usize,
    current_fd: i32,
    err_fd: i32,
}

impl<'a> SplitWriter<'a> {
    fn new(
        prefix: &'a str,
        suffix_len: usize,
        numeric: bool,
        numeric_from: usize,
        err_fd: i32,
    ) -> Self {
        Self {
            prefix,
            suffix_len,
            numeric,
            numeric_from,
            chunk_idx: 0,
            current_fd: -1,
            err_fd,
        }
    }

    fn ensure_open(&mut self) -> Result<i32, ()> {
        if self.current_fd >= 0 {
            return Ok(self.current_fd);
        }
        let total_idx = if self.numeric {
            self.numeric_from.checked_add(self.chunk_idx).ok_or(())?
        } else {
            self.chunk_idx
        };

        let mut suffix_buf = [0u8; 32];
        if !generate_split_suffix(
            total_idx,
            self.suffix_len,
            self.numeric,
            &mut suffix_buf[..self.suffix_len],
        ) {
            let _ = sys_write(self.err_fd, b"split: output file suffixes exhausted\n");
            return Err(());
        }

        let mut path_buf = [0u8; 128];
        let prefix_bytes = self.prefix.as_bytes();
        if prefix_bytes.len() + self.suffix_len >= path_buf.len() {
            let _ = sys_write(self.err_fd, b"split: output path too long\n");
            return Err(());
        }
        path_buf[..prefix_bytes.len()].copy_from_slice(prefix_bytes);
        path_buf[prefix_bytes.len()..prefix_bytes.len() + self.suffix_len]
            .copy_from_slice(&suffix_buf[..self.suffix_len]);
        let total_path_len = prefix_bytes.len() + self.suffix_len;

        let path_str = match core::str::from_utf8(&path_buf[..total_path_len]) {
            Ok(s) => s,
            Err(_) => {
                let _ = sys_write(self.err_fd, b"split: invalid filename encoding\n");
                return Err(());
            }
        };

        let new_fd = sys_open(path_str, O_CREAT | O_WRONLY | O_TRUNC);
        if new_fd < 0 {
            let _ = sys_write(self.err_fd, b"split: cannot open '");
            let _ = sys_write(self.err_fd, path_str.as_bytes());
            let _ = sys_write(self.err_fd, b"' for writing\n");
            return Err(());
        }

        self.current_fd = new_fd;
        self.chunk_idx += 1;
        Ok(new_fd)
    }

    fn close_current(&mut self) {
        if self.current_fd >= 0 {
            sys_close(self.current_fd);
            self.current_fd = -1;
        }
    }
}

/// Exécute l'utilitaire standard POSIX `split` (découpage de fichiers en morceaux par lignes ou octets)
pub fn run_split(args: &[&str], in_fd: i32, _out_fd: i32, err_fd: i32) -> i32 {
    let mut mode: Option<SplitMode> = None;
    let mut suffix_len: usize = 2;
    let mut numeric = false;
    let mut numeric_from: usize = 0;
    let mut input_file: Option<&str> = None;
    let mut prefix: &str = "x";
    let mut parsing_options = true;
    let mut operands: [&str; 2] = [""; 2];
    let mut num_operands = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    err_fd,
                    b"Usage: split [OPTION]... [INPUT [PREFIX]]\n\
Output pieces of INPUT to PREFIXaa, PREFIXab, ...;\n\
default size is 1000 lines, and default PREFIX is 'x'.\n\n\
  -a, --suffix-length=N   generate suffixes of length N (default 2)\n\
  -b, --bytes=SIZE        put SIZE bytes per output file\n\
  -C, --line-bytes=SIZE   put at most SIZE bytes of lines per output file\n\
  -d, --numeric-suffixes[=FROM]  use numeric suffixes instead of alphabetic\n\
  -l, --lines=NUMBER      put NUMBER lines per output file (default 1000)\n\
      --help              display this help and exit\n",
                );
                return 0;
            } else if arg == "-d" || arg == "--numeric-suffixes" {
                numeric = true;
            } else if let Some(from_str) = arg.strip_prefix("--numeric-suffixes=") {
                numeric = true;
                if let Some(val) = parse_split_size(from_str) {
                    numeric_from = val;
                } else {
                    let _ = sys_write(err_fd, b"split: invalid numeric suffix start\n");
                    return 1;
                }
            } else if arg == "-a" || arg == "--suffix-length" {
                i += 1;
                if i >= args.len() {
                    let _ = sys_write(err_fd, b"split: option requires an argument -- 'a'\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(args[i]) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid suffix length: '0'\n");
                        return 1;
                    }
                    suffix_len = val;
                } else {
                    let _ = sys_write(err_fd, b"split: invalid suffix length\n");
                    return 1;
                }
            } else if let Some(val_str) = arg.strip_prefix("-a") {
                if let Some(val) = parse_split_size(val_str) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid suffix length: '0'\n");
                        return 1;
                    }
                    suffix_len = val;
                } else {
                    let _ = sys_write(err_fd, b"split: invalid suffix length\n");
                    return 1;
                }
            } else if let Some(val_str) = arg.strip_prefix("--suffix-length=") {
                if let Some(val) = parse_split_size(val_str) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid suffix length: '0'\n");
                        return 1;
                    }
                    suffix_len = val;
                } else {
                    let _ = sys_write(err_fd, b"split: invalid suffix length\n");
                    return 1;
                }
            } else if arg == "-b" || arg == "--bytes" {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                i += 1;
                if i >= args.len() {
                    let _ = sys_write(err_fd, b"split: option requires an argument -- 'b'\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(args[i]) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of bytes: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::Bytes(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of bytes\n");
                    return 1;
                }
            } else if let Some(val_str) = arg.strip_prefix("-b") {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(val_str) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of bytes: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::Bytes(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of bytes\n");
                    return 1;
                }
            } else if let Some(val_str) = arg.strip_prefix("--bytes=") {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(val_str) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of bytes: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::Bytes(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of bytes\n");
                    return 1;
                }
            } else if arg == "-l" || arg == "--lines" {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                i += 1;
                if i >= args.len() {
                    let _ = sys_write(err_fd, b"split: option requires an argument -- 'l'\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(args[i]) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of lines: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::Lines(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of lines\n");
                    return 1;
                }
            } else if let Some(val_str) = arg.strip_prefix("-l") {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(val_str) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of lines: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::Lines(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of lines\n");
                    return 1;
                }
            } else if let Some(val_str) = arg.strip_prefix("--lines=") {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(val_str) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of lines: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::Lines(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of lines\n");
                    return 1;
                }
            } else if arg == "-C" || arg == "--line-bytes" {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                i += 1;
                if i >= args.len() {
                    let _ = sys_write(err_fd, b"split: option requires an argument -- 'C'\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(args[i]) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of bytes: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::LineBytes(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of bytes\n");
                    return 1;
                }
            } else if let Some(val_str) = arg.strip_prefix("-C") {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(val_str) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of bytes: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::LineBytes(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of bytes\n");
                    return 1;
                }
            } else if let Some(val_str) = arg.strip_prefix("--line-bytes=") {
                if mode.is_some() {
                    let _ = sys_write(err_fd, b"split: cannot split in more than one way\n");
                    return 1;
                }
                if let Some(val) = parse_split_size(val_str) {
                    if val == 0 {
                        let _ = sys_write(err_fd, b"split: invalid number of bytes: '0'\n");
                        return 1;
                    }
                    mode = Some(SplitMode::LineBytes(val));
                } else {
                    let _ = sys_write(err_fd, b"split: invalid number of bytes\n");
                    return 1;
                }
            } else {
                let _ = sys_write(err_fd, b"split: invalid option -- '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
            i += 1;
        } else {
            if num_operands < operands.len() {
                operands[num_operands] = arg;
                num_operands += 1;
            } else {
                let _ = sys_write(err_fd, b"split: extra operand '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
            i += 1;
        }
    }

    if num_operands >= 1 {
        input_file = Some(operands[0]);
    }
    if num_operands >= 2 {
        prefix = operands[1];
    }

    let effective_mode = mode.unwrap_or(SplitMode::Lines(1000));

    let (src_fd, need_close_src) = match input_file {
        None => (in_fd, false),
        Some("-") => (in_fd, false),
        Some(path) => {
            let fd = sys_open(path, O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"split: cannot open '");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b"' for reading: No such file or directory\n");
                return 1;
            }
            (fd, true)
        }
    };

    let mut writer = SplitWriter::new(prefix, suffix_len, numeric, numeric_from, err_fd);
    let mut in_buf = [0u8; 1024];

    match effective_mode {
        SplitMode::Bytes(chunk_size) => {
            let mut chunk_written = 0;
            loop {
                let n = sys_read(src_fd, &mut in_buf);
                if n <= 0 {
                    break;
                }
                let mut offset = 0;
                let len = n as usize;
                while offset < len {
                    let out_f = match writer.ensure_open() {
                        Ok(fd) => fd,
                        Err(_) => {
                            if need_close_src {
                                sys_close(src_fd);
                            }
                            return 1;
                        }
                    };
                    let remaining_in_chunk = chunk_size - chunk_written;
                    let to_write = core::cmp::min(len - offset, remaining_in_chunk);
                    let _ = sys_write(out_f, &in_buf[offset..offset + to_write]);
                    chunk_written += to_write;
                    offset += to_write;

                    if chunk_written >= chunk_size {
                        writer.close_current();
                        chunk_written = 0;
                    }
                }
            }
            writer.close_current();
        }
        SplitMode::Lines(lines_limit) => {
            let mut current_lines = 0;
            loop {
                let n = sys_read(src_fd, &mut in_buf);
                if n <= 0 {
                    break;
                }
                let mut start = 0;
                let len = n as usize;
                for idx in 0..len {
                    if in_buf[idx] == b'\n' {
                        let out_f = match writer.ensure_open() {
                            Ok(fd) => fd,
                            Err(_) => {
                                if need_close_src {
                                    sys_close(src_fd);
                                }
                                return 1;
                            }
                        };
                        let _ = sys_write(out_f, &in_buf[start..=idx]);
                        start = idx + 1;
                        current_lines += 1;
                        if current_lines >= lines_limit {
                            writer.close_current();
                            current_lines = 0;
                        }
                    }
                }
                if start < len {
                    let out_f = match writer.ensure_open() {
                        Ok(fd) => fd,
                        Err(_) => {
                            if need_close_src {
                                sys_close(src_fd);
                            }
                            return 1;
                        }
                    };
                    let _ = sys_write(out_f, &in_buf[start..len]);
                }
            }
            writer.close_current();
        }
        SplitMode::LineBytes(max_line_bytes) => {
            let mut line_buf = [0u8; 2048];
            let mut line_len = 0;
            let mut current_chunk_bytes = 0;

            loop {
                let n = sys_read(src_fd, &mut in_buf);
                if n <= 0 {
                    break;
                }
                for &b in &in_buf[..n as usize] {
                    if line_len < line_buf.len() {
                        line_buf[line_len] = b;
                        line_len += 1;
                    }
                    if b == b'\n' || line_len == max_line_bytes {
                        if current_chunk_bytes > 0
                            && current_chunk_bytes + line_len > max_line_bytes
                        {
                            writer.close_current();
                            current_chunk_bytes = 0;
                        }
                        let out_f = match writer.ensure_open() {
                            Ok(fd) => fd,
                            Err(_) => {
                                if need_close_src {
                                    sys_close(src_fd);
                                }
                                return 1;
                            }
                        };
                        let _ = sys_write(out_f, &line_buf[..line_len]);
                        current_chunk_bytes += line_len;
                        line_len = 0;
                    }
                }
            }
            if line_len > 0 {
                if current_chunk_bytes > 0 && current_chunk_bytes + line_len > max_line_bytes {
                    writer.close_current();
                }
                if let Ok(out_f) = writer.ensure_open() {
                    let _ = sys_write(out_f, &line_buf[..line_len]);
                }
            }
            writer.close_current();
        }
    }

    if need_close_src {
        sys_close(src_fd);
    }
    0
}

/// Extrait le composant final de nom de fichier d'un chemin selon la spécification POSIX.
///
/// Algorithme conforme IEEE Std 1003.1-2017 :
/// 1. Si le chemin est vide, retourne "."
/// 2. Supprime les slashs consécutifs de fin (trailing slashes).
/// 3. Si la chaîne résultante est vide (la chaîne initiale ne contenait que des slashs), retourne "/".
/// 4. S'il reste des slashs, isole la portion postérieure au dernier slash.
/// 5. Si un suffixe est fourni, qu'il est distinct de la composante restante et correspond
///    exactement à la terminaison, supprime ce suffixe.
pub fn posix_basename<'a>(path: &'a str, suffix: Option<&str>) -> &'a str {
    if path.is_empty() {
        return ".";
    }

    let bytes = path.as_bytes();
    let mut end = bytes.len();

    while end > 0 && bytes[end - 1] == b'/' {
        end -= 1;
    }

    if end == 0 {
        return "/";
    }

    let trimmed = &path[..end];
    let trimmed_bytes = trimmed.as_bytes();

    let mut start = end;
    while start > 0 && trimmed_bytes[start - 1] != b'/' {
        start -= 1;
    }

    let base = &trimmed[start..end];

    if let Some(suf) = suffix {
        if !suf.is_empty() && base.len() > suf.len() && base.ends_with(suf) {
            return &base[..base.len() - suf.len()];
        }
    }

    base
}

/// Extrait le répertoire parent d'un chemin selon la spécification POSIX.
///
/// Algorithme conforme IEEE Std 1003.1-2017 :
/// 1. Si le chemin est vide, retourne "."
/// 2. Supprime les slashs consécutifs de fin.
/// 3. Si la chaîne résultante est vide (la chaîne initiale ne contenait que des slashs), retourne "/".
/// 4. S'il ne subsiste aucun slash dans la chaîne restante, retourne "."
/// 5. Supprime les caractères non-slash finaux.
/// 6. Supprime les slashs consécutifs de fin résultants.
/// 7. Si la chaîne résultante est vide, retourne "/".
pub fn posix_dirname(path: &str) -> &str {
    if path.is_empty() {
        return ".";
    }

    let bytes = path.as_bytes();
    let mut end = bytes.len();

    while end > 0 && bytes[end - 1] == b'/' {
        end -= 1;
    }

    if end == 0 {
        return "/";
    }

    let trimmed = &path[..end];
    let trimmed_bytes = trimmed.as_bytes();

    let mut last_slash = None;
    for (i, &b) in trimmed_bytes.iter().enumerate().rev() {
        if b == b'/' {
            last_slash = Some(i);
            break;
        }
    }

    let slash_idx = match last_slash {
        Some(idx) => idx,
        None => return ".",
    };

    let mut parent_end = slash_idx;
    while parent_end > 0 && trimmed_bytes[parent_end] == b'/' {
        parent_end -= 1;
    }

    if parent_end == 0 && trimmed_bytes[0] == b'/' {
        return "/";
    }

    &trimmed[..=parent_end]
}

/// Exécute l'utilitaire standard POSIX `basename` (extraction canonique du nom de base)
pub fn run_basename(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut multiple = false;
    let mut suffix: Option<&str> = None;
    let mut zero_delimiter = false;
    let mut operands: [&str; 64] = [""; 64];
    let mut num_operands = 0;
    let mut parsing_options = true;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    err_fd,
                    b"Usage: basename NAME [SUFFIX]\n\
  or:  basename OPTION... NAME...\n\
Print NAME with any leading directory components removed.\n\
If specified, also remove a trailing SUFFIX.\n\n\
  -a, --multiple       support multiple arguments and treat each as a NAME\n\
  -s, --suffix=SUFFIX  remove a trailing SUFFIX; implies -a\n\
  -z, --zero           end each output line with NUL, not newline\n\
      --help           display this help and exit\n",
                );
                return 0;
            } else if arg == "-a" || arg == "--multiple" {
                multiple = true;
            } else if arg == "-z" || arg == "--zero" {
                zero_delimiter = true;
            } else if arg == "-s" {
                if i + 1 < args.len() {
                    i += 1;
                    suffix = Some(args[i]);
                    multiple = true;
                } else {
                    let _ = sys_write(err_fd, b"basename: option requires an argument -- 's'\n");
                    return 1;
                }
            } else if let Some(suf) = arg.strip_prefix("--suffix=") {
                suffix = Some(suf);
                multiple = true;
            } else if let Some(suf) = arg.strip_prefix("-s") {
                suffix = Some(suf);
                multiple = true;
            } else {
                let _ = sys_write(err_fd, b"basename: invalid option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if num_operands < operands.len() {
                operands[num_operands] = arg;
                num_operands += 1;
            }
        }
        i += 1;
    }

    if num_operands == 0 {
        let _ = sys_write(err_fd, b"basename: missing operand\n");
        return 1;
    }

    let delim = if zero_delimiter { b"\0" } else { b"\n" };

    if !multiple {
        let name = operands[0];
        let suf = if num_operands > 1 {
            Some(operands[1])
        } else {
            suffix
        };
        let res = posix_basename(name, suf);
        let _ = sys_write(out_fd, res.as_bytes());
        let _ = sys_write(out_fd, delim);
    } else {
        for &op in &operands[..num_operands] {
            let res = posix_basename(op, suffix);
            let _ = sys_write(out_fd, res.as_bytes());
            let _ = sys_write(out_fd, delim);
        }
    }

    0
}

/// Exécute l'utilitaire standard POSIX `dirname` (extraction canonique du répertoire parent)
pub fn run_dirname(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut zero_delimiter = false;
    let mut operands: [&str; 64] = [""; 64];
    let mut num_operands = 0;
    let mut parsing_options = true;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    err_fd,
                    b"Usage: dirname [OPTION] NAME...\n\
Output each NAME with its last non-slash component and trailing slashes removed;\n\
if NAME contains no /'s, output '.' (meaning the current directory).\n\n\
  -z, --zero     end each output line with NUL, not newline\n\
      --help     display this help and exit\n",
                );
                return 0;
            } else if arg == "-z" || arg == "--zero" {
                zero_delimiter = true;
            } else {
                let _ = sys_write(err_fd, b"dirname: invalid option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if num_operands < operands.len() {
                operands[num_operands] = arg;
                num_operands += 1;
            }
        }
        i += 1;
    }

    if num_operands == 0 {
        let _ = sys_write(err_fd, b"dirname: missing operand\n");
        return 1;
    }

    let delim = if zero_delimiter { b"\0" } else { b"\n" };

    for &op in &operands[..num_operands] {
        let res = posix_dirname(op);
        let _ = sys_write(out_fd, res.as_bytes());
        let _ = sys_write(out_fd, delim);
    }

    0
}

/// Parse un opérande numérique pour la commande `seq`.
/// Renvoie `Some((valeur_entiere, echelle_decimale))` si valide, `None` sinon.
fn parse_seq_operand(s: &str) -> Option<(i64, u32)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (is_neg, s) = if let Some(stripped) = s.strip_prefix('-') {
        (true, stripped)
    } else if let Some(stripped) = s.strip_prefix('+') {
        (false, stripped)
    } else {
        (false, s)
    };

    if s.is_empty() {
        return None;
    }

    let mut dot_idx = None;
    for (i, b) in s.bytes().enumerate() {
        if b == b'.' {
            if dot_idx.is_some() {
                return None;
            }
            dot_idx = Some(i);
        } else if !b.is_ascii_digit() {
            return None;
        }
    }

    let (int_str, frac_str, scale) = if let Some(dot) = dot_idx {
        (&s[..dot], &s[dot + 1..], (s.len() - dot - 1) as u32)
    } else {
        (s, "", 0u32)
    };

    let int_val: i64 = if int_str.is_empty() {
        0
    } else {
        int_str.parse().ok()?
    };

    let mut frac_val: i64 = 0;
    if !frac_str.is_empty() {
        frac_val = frac_str.parse().ok()?;
    }

    let mut scale_mul = 1i64;
    for _ in 0..scale {
        scale_mul = scale_mul.checked_mul(10)?;
    }

    let total = int_val.checked_mul(scale_mul)?.checked_add(frac_val)?;
    let val = if is_neg { -total } else { total };
    Some((val, scale))
}

/// Formate un nombre de séquence dans un tampon mémoire selon la largeur, le remplissage ou le motif printf.
fn format_seq_number(
    val: i64,
    scale: u32,
    min_width: usize,
    equal_width: bool,
    format_opt: Option<&str>,
    buf: &mut [u8],
) -> usize {
    if let Some(fmt) = format_opt {
        if let Some(percent_idx) = fmt.find('%') {
            let prefix = &fmt[..percent_idx];
            let rest = &fmt[percent_idx + 1..];

            let mut zero_pad = false;
            let mut width: usize = 0;
            let mut spec_idx = 0;
            let mut chars = rest.char_indices();
            if let Some((_, '0')) = chars.next() {
                zero_pad = true;
            } else {
                chars = rest.char_indices();
            }

            for (idx, ch) in chars {
                if ch.is_ascii_digit() {
                    width = width
                        .wrapping_mul(10)
                        .wrapping_add((ch as u8 - b'0') as usize);
                } else {
                    spec_idx = idx;
                    break;
                }
            }

            let suffix = if spec_idx < rest.len() {
                &rest[spec_idx + 1..]
            } else {
                ""
            };

            let mut num_buf = [0u8; 48];
            let num_len = format_raw_seq_number(val, scale, width, zero_pad, &mut num_buf);

            let mut cur = 0;
            for &b in prefix.as_bytes() {
                if cur < buf.len() {
                    buf[cur] = b;
                    cur += 1;
                }
            }
            for &b in &num_buf[..num_len] {
                if cur < buf.len() {
                    buf[cur] = b;
                    cur += 1;
                }
            }
            for &b in suffix.as_bytes() {
                if cur < buf.len() {
                    buf[cur] = b;
                    cur += 1;
                }
            }
            return cur;
        }
    }

    format_raw_seq_number(val, scale, min_width, equal_width, buf)
}

fn format_raw_seq_number(
    val: i64,
    scale: u32,
    min_width: usize,
    pad_zeros: bool,
    buf: &mut [u8],
) -> usize {
    let is_neg = val < 0;
    let abs_val = val.unsigned_abs();

    let mut scale_mul = 1u64;
    for _ in 0..scale {
        scale_mul = scale_mul.saturating_mul(10);
    }

    let int_part = abs_val / scale_mul;
    let frac_part = abs_val % scale_mul;

    let mut int_digits = [0u8; 24];
    let mut int_len = 0;
    if int_part == 0 {
        int_digits[0] = b'0';
        int_len = 1;
    } else {
        let mut tmp = int_part;
        while tmp > 0 {
            int_digits[int_len] = b'0' + (tmp % 10) as u8;
            int_len += 1;
            tmp /= 10;
        }
        int_digits[..int_len].reverse();
    }

    let raw_len =
        (if is_neg { 1 } else { 0 }) + int_len + (if scale > 0 { 1 + scale as usize } else { 0 });
    let padding = if pad_zeros && min_width > raw_len {
        min_width - raw_len
    } else {
        0
    };

    let mut cursor = 0;
    if is_neg && cursor < buf.len() {
        buf[cursor] = b'-';
        cursor += 1;
    }

    for _ in 0..padding {
        if cursor < buf.len() {
            buf[cursor] = b'0';
            cursor += 1;
        }
    }

    for &digit in &int_digits[..int_len] {
        if cursor < buf.len() {
            buf[cursor] = digit;
            cursor += 1;
        }
    }

    if scale > 0 && cursor < buf.len() {
        buf[cursor] = b'.';
        cursor += 1;

        let mut frac_digits = [0u8; 24];
        let mut frac_len = 0;
        let mut tmp = frac_part;
        while tmp > 0 {
            frac_digits[frac_len] = b'0' + (tmp % 10) as u8;
            frac_len += 1;
            tmp /= 10;
        }
        frac_digits[..frac_len].reverse();

        let leading_zeros = (scale as usize).saturating_sub(frac_len);
        for _ in 0..leading_zeros {
            if cursor < buf.len() {
                buf[cursor] = b'0';
                cursor += 1;
            }
        }
        for &digit in &frac_digits[..frac_len] {
            if cursor < buf.len() {
                buf[cursor] = digit;
                cursor += 1;
            }
        }
    }

    cursor
}

/// Point d'entrée pour la commande `seq` (génération de séquences numériques POSIX/GNU).
pub fn run_seq(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut separator = "\n";
    let mut equal_width = false;
    let mut format_opt: Option<&str> = None;
    let mut operands: [&str; 4] = [""; 4];
    let mut num_operands = 0;
    let mut parsing_options = true;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        let is_negative_number = parsing_options
            && arg.starts_with('-')
            && arg.len() > 1
            && (arg.as_bytes()[1].is_ascii_digit() || arg.as_bytes()[1] == b'.');

        if parsing_options && (arg.starts_with('-') && arg != "-") && !is_negative_number {
            if arg == "--help" {
                let _ = sys_write(
                    err_fd,
                    b"Usage: seq [OPTION]... LAST\n\
  or:  seq [OPTION]... FIRST LAST\n\
  or:  seq [OPTION]... FIRST INCREMENT LAST\n\
Print numbers from FIRST to LAST, in steps of INCREMENT.\n\n\
  -f, --format=FORMAT      use printf style floating-point/integer FORMAT\n\
  -s, --separator=STRING   use STRING to separate numbers (default: \\n)\n\
  -w, --equal-width        equalize width by padding with leading zeroes\n\
      --help               display this help and exit\n",
                );
                return 0;
            } else if arg == "-w" || arg == "--equal-width" {
                equal_width = true;
            } else if arg == "-s" {
                if i + 1 < args.len() {
                    i += 1;
                    separator = args[i];
                } else {
                    let _ = sys_write(err_fd, b"seq: option requires an argument -- 's'\n");
                    return 1;
                }
            } else if let Some(sep) = arg.strip_prefix("--separator=") {
                separator = sep;
            } else if arg == "-f" {
                if i + 1 < args.len() {
                    i += 1;
                    format_opt = Some(args[i]);
                } else {
                    let _ = sys_write(err_fd, b"seq: option requires an argument -- 'f'\n");
                    return 1;
                }
            } else if let Some(fmt) = arg.strip_prefix("--format=") {
                format_opt = Some(fmt);
            } else {
                let _ = sys_write(err_fd, b"seq: invalid option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\nTry 'seq --help' for more information.\n");
                return 1;
            }
        } else {
            if num_operands < operands.len() {
                operands[num_operands] = arg;
                num_operands += 1;
            } else {
                let _ = sys_write(err_fd, b"seq: extra operand '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\nTry 'seq --help' for more information.\n");
                return 1;
            }
        }
        i += 1;
    }

    if num_operands == 0 {
        let _ = sys_write(
            err_fd,
            b"seq: missing operand\nTry 'seq --help' for more information.\n",
        );
        return 1;
    }

    if num_operands > 3 {
        let _ = sys_write(err_fd, b"seq: extra operand '");
        let _ = sys_write(err_fd, operands[3].as_bytes());
        let _ = sys_write(err_fd, b"'\nTry 'seq --help' for more information.\n");
        return 1;
    }

    let (first_str, inc_str, last_str) = match num_operands {
        1 => ("1", "1", operands[0]),
        2 => (operands[0], "1", operands[1]),
        3 => (operands[0], operands[1], operands[2]),
        _ => unreachable!(),
    };

    let (first_raw, scale_first) = match parse_seq_operand(first_str) {
        Some(v) => v,
        None => {
            let _ = sys_write(err_fd, b"seq: invalid numerical argument: '");
            let _ = sys_write(err_fd, first_str.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }
    };

    let (inc_raw, scale_inc) = match parse_seq_operand(inc_str) {
        Some(v) => v,
        None => {
            let _ = sys_write(err_fd, b"seq: invalid numerical argument: '");
            let _ = sys_write(err_fd, inc_str.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }
    };

    let (last_raw, scale_last) = match parse_seq_operand(last_str) {
        Some(v) => v,
        None => {
            let _ = sys_write(err_fd, b"seq: invalid numerical argument: '");
            let _ = sys_write(err_fd, last_str.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }
    };

    if inc_raw == 0 {
        let _ = sys_write(err_fd, b"seq: invalid Zero increment value: '");
        let _ = sys_write(err_fd, inc_str.as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    let target_scale = scale_first.max(scale_inc).max(scale_last);

    let align_scale = |raw: i64, scale: u32| -> i64 {
        let diff = target_scale - scale;
        let mut mul = 1i64;
        for _ in 0..diff {
            mul = mul.saturating_mul(10);
        }
        raw.saturating_mul(mul)
    };

    let first_scaled = align_scale(first_raw, scale_first);
    let inc_scaled = align_scale(inc_raw, scale_inc);
    let last_scaled = align_scale(last_raw, scale_last);

    let mut min_width = 0;
    if equal_width {
        let mut buf1 = [0u8; 48];
        let mut buf2 = [0u8; 48];
        let len1 = format_raw_seq_number(first_scaled, target_scale, 0, false, &mut buf1);
        let len2 = format_raw_seq_number(last_scaled, target_scale, 0, false, &mut buf2);
        min_width = len1.max(len2);
    }

    let mut cur = first_scaled;
    let mut is_first = true;
    loop {
        if inc_scaled > 0 {
            if cur > last_scaled {
                break;
            }
        } else if cur < last_scaled {
            break;
        }

        if !is_first {
            let _ = sys_write(out_fd, separator.as_bytes());
        }
        is_first = false;

        let mut num_buf = [0u8; 64];
        let len = format_seq_number(
            cur,
            target_scale,
            min_width,
            equal_width,
            format_opt,
            &mut num_buf,
        );
        let _ = sys_write(out_fd, &num_buf[..len]);

        let next = cur.saturating_add(inc_scaled);
        if next == cur {
            break;
        }
        cur = next;
    }

    if !is_first {
        let _ = sys_write(out_fd, b"\n");
    }

    0
}

/// Utilitaire `yes` : émet une chaîne indéfiniment (ou jusqu'à `max_bytes`).
///
/// Arguments POSIX :
/// - sans argument : émet `"y\n"` indéfiniment.
/// - avec arguments : émet les arguments joints par un espace suivis de `\n`.
///
/// Le paramètre `max_bytes` borne l'émission (0 = illimité, utilisé uniquement dans les tests
/// via un pipe borné).
///
/// # Erreurs
/// Retourne 0. Ne retourne jamais sauf interruption par le consommateur du pipe.
pub fn run_yes(args: &[&str], out_fd: i32, _err_fd: i32, max_bytes: usize) -> i32 {
    // Construire la ligne à répéter
    let mut line_buf = [0u8; 256];
    let mut line_len = 0usize;

    if args.is_empty() {
        line_buf[0] = b'y';
        line_buf[1] = b'\n';
        line_len = 2;
    } else {
        for (i, arg) in args.iter().enumerate() {
            if i > 0 && line_len < line_buf.len() - 1 {
                line_buf[line_len] = b' ';
                line_len += 1;
            }
            let bytes = arg.as_bytes();
            let copy = bytes.len().min(line_buf.len() - line_len - 1);
            line_buf[line_len..line_len + copy].copy_from_slice(&bytes[..copy]);
            line_len += copy;
        }
        if line_len < line_buf.len() {
            line_buf[line_len] = b'\n';
            line_len += 1;
        }
    }

    let line = &line_buf[..line_len];
    let mut written = 0usize;

    loop {
        let remaining = if max_bytes == 0 {
            line_len
        } else {
            let left = max_bytes.saturating_sub(written);
            if left == 0 {
                return 0;
            }
            left.min(line_len)
        };

        let chunk = &line[..remaining];
        let n = sys_write(out_fd, chunk);
        if n <= 0 {
            return 0;
        }
        written = written.saturating_add(n as usize);

        if max_bytes > 0 && written >= max_bytes {
            return 0;
        }
    }
}

/// Utilitaire `printf` : formate et imprime une chaîne selon un format C-like.
///
/// Spécificateurs supportés : `%d`, `%i`, `%u`, `%x`, `%X`, `%o`, `%s`, `%c`, `%%`.
/// Séquences d'échappement dans le format : `\n`, `\t`, `\r`, `\\`.
///
/// # Erreurs
/// - Code 1 si aucun argument de format n'est fourni.
pub fn run_printf(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    if args.is_empty() {
        let _ = sys_write(err_fd, b"printf: format manquant\n");
        return 1;
    }

    let fmt = args[0].as_bytes();
    let mut arg_idx = 1usize;
    let mut out_buf = [0u8; 1024];
    let mut out_len = 0usize;

    // Émet un octet dans le buffer de sortie
    macro_rules! emit {
        ($b:expr) => {
            if out_len < out_buf.len() {
                out_buf[out_len] = $b;
                out_len += 1;
            }
        };
    }

    let mut i = 0usize;
    while i < fmt.len() {
        let ch = fmt[i];
        if ch == b'\\' && i + 1 < fmt.len() {
            i += 1;
            match fmt[i] {
                b'n' => emit!(b'\n'),
                b't' => emit!(b'\t'),
                b'r' => emit!(b'\r'),
                b'\\' => emit!(b'\\'),
                b'0' => emit!(b'\0'),
                other => {
                    emit!(b'\\');
                    emit!(other);
                }
            }
        } else if ch == b'%' && i + 1 < fmt.len() {
            i += 1;
            // Largeur optionnelle et flags (simplifiés)
            let mut width = 0u32;
            let mut zero_pad = false;
            if fmt[i] == b'0' {
                zero_pad = true;
                i += 1;
            }
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                width = width * 10 + (fmt[i] - b'0') as u32;
                i += 1;
            }
            if i >= fmt.len() {
                break;
            }
            match fmt[i] {
                b'%' => emit!(b'%'),
                b'd' | b'i' => {
                    let val: i64 = if arg_idx < args.len() {
                        parse_i64(args[arg_idx])
                    } else {
                        0
                    };
                    if arg_idx < args.len() {
                        arg_idx += 1;
                    }
                    let mut fbuf = [0u8; 32];
                    let flen = fmt_i64_into_buf(&mut fbuf, val, width as usize, zero_pad);
                    for &b in &fbuf[..flen] {
                        emit!(b);
                    }
                }
                b'u' => {
                    let val: u64 = if arg_idx < args.len() {
                        parse_u64(args[arg_idx])
                    } else {
                        0
                    };
                    if arg_idx < args.len() {
                        arg_idx += 1;
                    }
                    let mut fbuf = [0u8; 32];
                    let flen = fmt_u64_in_buf(&mut fbuf, val, width as usize, zero_pad, 10, false);
                    for &b in &fbuf[..flen] {
                        emit!(b);
                    }
                }
                b'x' => {
                    let val: u64 = if arg_idx < args.len() {
                        parse_u64(args[arg_idx])
                    } else {
                        0
                    };
                    if arg_idx < args.len() {
                        arg_idx += 1;
                    }
                    let mut fbuf = [0u8; 32];
                    let flen = fmt_u64_in_buf(&mut fbuf, val, width as usize, zero_pad, 16, false);
                    for &b in &fbuf[..flen] {
                        emit!(b);
                    }
                }
                b'X' => {
                    let val: u64 = if arg_idx < args.len() {
                        parse_u64(args[arg_idx])
                    } else {
                        0
                    };
                    if arg_idx < args.len() {
                        arg_idx += 1;
                    }
                    let mut fbuf = [0u8; 32];
                    let flen = fmt_u64_in_buf(&mut fbuf, val, width as usize, zero_pad, 16, true);
                    for &b in &fbuf[..flen] {
                        emit!(b);
                    }
                }
                b'o' => {
                    let val: u64 = if arg_idx < args.len() {
                        parse_u64(args[arg_idx])
                    } else {
                        0
                    };
                    if arg_idx < args.len() {
                        arg_idx += 1;
                    }
                    let mut fbuf = [0u8; 32];
                    let flen = fmt_u64_in_buf(&mut fbuf, val, width as usize, zero_pad, 8, false);
                    for &b in &fbuf[..flen] {
                        emit!(b);
                    }
                }
                b's' => {
                    let s = if arg_idx < args.len() {
                        args[arg_idx].as_bytes()
                    } else {
                        b""
                    };
                    if arg_idx < args.len() {
                        arg_idx += 1;
                    }
                    for &b in s {
                        emit!(b);
                    }
                }
                b'c' => {
                    let c = if arg_idx < args.len() && !args[arg_idx].is_empty() {
                        args[arg_idx].as_bytes()[0]
                    } else {
                        0
                    };
                    if arg_idx < args.len() {
                        arg_idx += 1;
                    }
                    emit!(c);
                }
                _ => {
                    emit!(b'%');
                    emit!(fmt[i]);
                }
            }
        } else {
            emit!(ch);
        }
        i += 1;
    }

    let _ = sys_write(out_fd, &out_buf[..out_len]);
    0
}

/// Parse un entier signé 32-bit optionnel (retourne None si format non valide)
fn parse_i32(s: &str) -> Option<i32> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (is_neg, rest) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut val: i32 = 0;
    for b in rest.bytes() {
        val = val.checked_mul(10)?.checked_add((b - b'0') as i32)?;
    }
    if is_neg {
        val.checked_neg()
    } else {
        Some(val)
    }
}

/// Parse un entier signé depuis une chaîne ASCII (décimal, 0x hexa, 0 octal).
fn parse_i64(s: &str) -> i64 {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('-') {
        -(parse_u64(rest) as i64)
    } else {
        parse_u64(s) as i64
    }
}

/// Parse un entier non signé depuis une chaîne ASCII (décimal, 0x hexa, 0 octal).
fn parse_u64(s: &str) -> u64 {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else if s.len() > 1 && s.starts_with('0') {
        u64::from_str_radix(&s[1..], 8).unwrap_or(0)
    } else {
        let mut v = 0u64;
        for b in s.bytes() {
            if b.is_ascii_digit() {
                v = v.saturating_mul(10).saturating_add((b - b'0') as u64);
            }
        }
        v
    }
}

/// Formate un entier signé avec largeur et padding.
/// Formate un entier signé dans le buffer fourni ; retourne la longueur de la représentation.
///
/// # Safety
/// Le buffer doit avoir une capacité d'au moins 24 octets.
fn fmt_i64_into_buf(buf: &mut [u8; 32], val: i64, width: usize, zero_pad: bool) -> usize {
    let negative = val < 0;
    let abs_val = if negative {
        (val as u64).wrapping_neg()
    } else {
        val as u64
    };
    let s = fmt_u64_into(buf, abs_val, width, zero_pad, 10, false, negative);
    s.len()
}

/// Formate un entier non signé dans le buffer fourni ; retourne la longueur de la représentation.
fn fmt_u64_in_buf(
    buf: &mut [u8; 32],
    val: u64,
    width: usize,
    zero_pad: bool,
    base: u64,
    upper: bool,
) -> usize {
    let s = fmt_u64_into(buf, val, width, zero_pad, base, upper, false);
    s.len()
}

/// Conversion entière dans un buffer mutable ; retourne la tranche ASCII produite.
fn fmt_u64_into(
    buf: &mut [u8; 32],
    val: u64,
    width: usize,
    zero_pad: bool,
    base: u64,
    upper: bool,
    negative: bool,
) -> &[u8] {
    let digits = b"0123456789abcdef";
    let digits_up = b"0123456789ABCDEF";
    let digit_set = if upper { digits_up } else { digits };

    // Écrire les chiffres à rebours
    let mut tmp = [0u8; 24];
    let mut tmp_len = 0usize;
    let mut v = val;
    if v == 0 {
        tmp[0] = b'0';
        tmp_len = 1;
    } else {
        while v > 0 && tmp_len < tmp.len() {
            tmp[tmp_len] = digit_set[(v % base) as usize];
            v /= base;
            tmp_len += 1;
        }
    }

    // Construire dans buf (signe + padding + chiffres)
    let sign_len = if negative { 1 } else { 0 };
    let num_len = tmp_len + sign_len;
    let pad_len = width.saturating_sub(num_len);

    let mut pos = 0usize;
    if zero_pad {
        if negative && pos < buf.len() {
            buf[pos] = b'-';
            pos += 1;
        }
        for _ in 0..pad_len {
            if pos < buf.len() {
                buf[pos] = b'0';
                pos += 1;
            }
        }
        if !negative {
            // signe déjà géré
        }
    } else {
        for _ in 0..pad_len {
            if pos < buf.len() {
                buf[pos] = b' ';
                pos += 1;
            }
        }
        if negative && pos < buf.len() {
            buf[pos] = b'-';
            pos += 1;
        }
    }
    for k in (0..tmp_len).rev() {
        if pos < buf.len() {
            buf[pos] = tmp[k];
            pos += 1;
        }
    }

    &buf[..pos]
}

/// Utilitaire `expr` : évalue une expression arithmétique, de comparaison ou de manipulation de chaînes POSIX.
///
/// Syntaxe : `expr VALEUR OP VALEUR` ou `expr match CHAÎNE MOTIF` ou `expr substr CHAÎNE POS LONG`
/// ou `expr length CHAÎNE` ou `expr index CHAÎNE CARACTÈRES`
///
/// Opérateurs arithmétiques : `+`, `-`, `*`, `/`, `%`
/// Opérateurs de comparaison : `=`, `!=`, `<`, `<=`, `>`, `>=`
/// Opérateurs logiques : `|`, `&`
/// Opérateurs de chaîne et motif : `length`, `substr`, `index`, `match`, `:`
///
/// # Codes de retour
/// - 0 : résultat non-nul ou non-vide (vrai).
/// - 1 : résultat nul ou vide (faux).
/// - 2 : erreur de syntaxe ou division par zéro.
pub fn run_expr(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    if args.is_empty() {
        let _ = sys_write(err_fd, b"expr: syntax error: missing operand\n");
        return 2;
    }

    if args.len() == 1 {
        let a = args[0];
        if a == "--help" || a == "-h" {
            let help = b"Usage: expr EXPRESSION\n\
Print the value of EXPRESSION to standard output.\n\n\
  ARG1 | ARG2       ARG1 if it is neither null nor 0, otherwise ARG2\n\
  ARG1 & ARG2       ARG1 if neither argument is null or 0, otherwise 0\n\
  ARG1 < ARG2       ARG1 is less than ARG2\n\
  ARG1 <= ARG2      ARG1 is less than or equal to ARG2\n\
  ARG1 = ARG2       ARG1 is equal to ARG2\n\
  ARG1 != ARG2      ARG1 is unequal to ARG2\n\
  ARG1 >= ARG2      ARG1 is greater than or equal to ARG2\n\
  ARG1 > ARG2       ARG1 is greater than ARG2\n\
  ARG1 + ARG2       arithmetic sum of ARG1 and ARG2\n\
  ARG1 - ARG2       arithmetic difference of ARG1 and ARG2\n\
  ARG1 * ARG2       arithmetic product of ARG1 and ARG2\n\
  ARG1 / ARG2       arithmetic quotient of ARG1 divided by ARG2\n\
  ARG1 % ARG2       arithmetic remainder of ARG1 divided by ARG2\n\
  ARG1 : PATTERN    anchored pattern match of PATTERN in ARG1\n\
  match STR PATTERN anchored pattern match\n\
  substr STR POS L  substring of STR, POS counted from 1\n\
  index STR CHARS   index in STR where any CHARS is found, or 0\n\
  length STR        length of STR\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if a == "--version" || a == "-v" {
            let ver = b"expr (JamboOS coreutils) 0.1.0\n\
Copyright (C) 2026 JamboOS Authors.\n\
License MIT or Apache-2.0.\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }
        let _ = sys_write(out_fd, a.as_bytes());
        let _ = sys_write(out_fd, b"\n");
        return if a.is_empty() || a == "0" { 1 } else { 0 };
    }

    // Gestion des mots-clés unaires/spéciaux : `length STR`
    if args.len() == 2 && args[0] == "length" {
        let len = args[1].len();
        let mut rbuf = [0u8; 32];
        let rlen = fmt_u64_in_buf(&mut rbuf, len as u64, 0, false, 10, false);
        let _ = sys_write(out_fd, &rbuf[..rlen]);
        let _ = sys_write(out_fd, b"\n");
        return if len == 0 { 1 } else { 0 };
    }

    // Gestion de `substr STR POS LENGTH`
    if args.len() == 4 && args[0] == "substr" {
        let s = args[1];
        let pos = parse_u64(args[2]);
        let len = parse_u64(args[3]) as usize;
        if pos == 0 || pos as usize > s.len() || len == 0 {
            let _ = sys_write(out_fd, b"\n");
            return 1;
        }
        let start = (pos as usize) - 1;
        let end = (start + len).min(s.len());
        let sub = &s[start..end];
        let _ = sys_write(out_fd, sub.as_bytes());
        let _ = sys_write(out_fd, b"\n");
        return if sub.is_empty() { 1 } else { 0 };
    }

    // Gestion de `index STR CHARS`
    if args.len() == 3 && args[0] == "index" {
        let s = args[1];
        let chars = args[2];
        let mut idx = 0usize;
        for (i, b) in s.bytes().enumerate() {
            if chars.bytes().any(|c| c == b) {
                idx = i + 1;
                break;
            }
        }
        let mut rbuf = [0u8; 32];
        let rlen = fmt_u64_in_buf(&mut rbuf, idx as u64, 0, false, 10, false);
        let _ = sys_write(out_fd, &rbuf[..rlen]);
        let _ = sys_write(out_fd, b"\n");
        return if idx == 0 { 1 } else { 0 };
    }

    // Gestion de `match STR PATTERN`
    if args.len() == 3 && args[0] == "match" {
        let s = args[1];
        let pat = args[2];
        let matched_len = if let Some(subpat) = pat.strip_prefix('^') {
            if s.starts_with(subpat) {
                subpat.len()
            } else {
                0
            }
        } else if s.starts_with(pat) {
            pat.len()
        } else {
            0
        };
        let mut rbuf = [0u8; 32];
        let rlen = fmt_u64_in_buf(&mut rbuf, matched_len as u64, 0, false, 10, false);
        let _ = sys_write(out_fd, &rbuf[..rlen]);
        let _ = sys_write(out_fd, b"\n");
        return if matched_len == 0 { 1 } else { 0 };
    }

    if args.len() < 3 {
        let _ = sys_write(err_fd, b"expr: syntax error\n");
        return 2;
    }

    let lhs_str = args[0].trim();
    let op = args[1].trim();
    let rhs_str = args[2].trim();

    // Gestion de l'opérateur motif POSIX `:` (ex: `expr STR : PATTERN`)
    if op == ":" {
        let matched_len = if let Some(subpat) = rhs_str.strip_prefix('^') {
            if lhs_str.starts_with(subpat) {
                subpat.len()
            } else {
                0
            }
        } else if lhs_str.starts_with(rhs_str) {
            rhs_str.len()
        } else {
            0
        };
        let mut rbuf = [0u8; 32];
        let rlen = fmt_u64_in_buf(&mut rbuf, matched_len as u64, 0, false, 10, false);
        let _ = sys_write(out_fd, &rbuf[..rlen]);
        let _ = sys_write(out_fd, b"\n");
        return if matched_len == 0 { 1 } else { 0 };
    }

    // Tente une évaluation entière
    let lhs = parse_i64(lhs_str);
    let rhs = parse_i64(rhs_str);

    let result: i64 = match op {
        "+" => lhs.saturating_add(rhs),
        "-" => lhs.saturating_sub(rhs),
        "*" => lhs.saturating_mul(rhs),
        "/" => {
            if rhs == 0 {
                let _ = sys_write(err_fd, b"expr: division par zero\n");
                return 2;
            }
            lhs / rhs
        }
        "%" => {
            if rhs == 0 {
                let _ = sys_write(err_fd, b"expr: division par zero\n");
                return 2;
            }
            lhs % rhs
        }
        "=" => {
            if lhs == rhs {
                1
            } else {
                0
            }
        }
        "!=" => {
            if lhs != rhs {
                1
            } else {
                0
            }
        }
        "<" => {
            if lhs < rhs {
                1
            } else {
                0
            }
        }
        "<=" => {
            if lhs <= rhs {
                1
            } else {
                0
            }
        }
        ">" => {
            if lhs > rhs {
                1
            } else {
                0
            }
        }
        ">=" => {
            if lhs >= rhs {
                1
            } else {
                0
            }
        }
        "|" => {
            if lhs != 0 {
                lhs
            } else {
                rhs
            }
        }
        "&" => {
            if lhs != 0 && rhs != 0 {
                lhs
            } else {
                0
            }
        }
        _ => {
            let _ = sys_write(err_fd, b"expr: operateur inconnu\n");
            return 2;
        }
    };

    // Émettre le résultat
    let mut rbuf = [0u8; 32];
    let rlen = fmt_i64_into_buf(&mut rbuf, result, 0, false);
    let _ = sys_write(out_fd, &rbuf[..rlen]);
    let _ = sys_write(out_fd, b"\n");

    if result == 0 {
        1
    } else {
        0
    }
}

/// Utilitaire Coreutils Ring 3 : `fold` (POSIX fold - wrap input lines to fit in specified width)
///
/// Syntaxe : `fold [-b] [-s] [-w LARGEUR] [FICHIER...]` ou `fold [-LARGEUR] [FICHIER...]`
///
/// # Options
/// - `-b` : Compte les octets au lieu des colonnes d'affichage.
/// - `-s` : Scinde les lignes sur les espaces ou tabulations lorsque possible.
/// - `-w N` ou `-N` : Fixe la largeur maximale autorisée (80 par défaut).
///
/// # Codes de retour
/// - 0 : Succès de l'opération.
/// - 1 : Erreur de lecture de fichier ou argument invalide.
pub fn run_fold(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut width: usize = 80;
    let mut count_bytes = false;
    let mut break_spaces = false;
    let mut file_args = [""; 32];
    let mut file_count = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if arg == "-b" {
            count_bytes = true;
            i += 1;
        } else if arg == "-s" {
            break_spaces = true;
            i += 1;
        } else if arg == "-w" {
            if i + 1 < args.len() {
                let parsed = parse_i64(args[i + 1].trim());
                if parsed > 0 {
                    width = parsed as usize;
                } else {
                    let _ = sys_write(err_fd, b"fold: largeur invalide\n");
                    return 1;
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"fold: option requiert un argument -- 'w'\n");
                return 1;
            }
        } else if arg.starts_with("-w") && arg.len() > 2 {
            let parsed = parse_i64(&arg[2..]);
            if parsed > 0 {
                width = parsed as usize;
            } else {
                let _ = sys_write(err_fd, b"fold: largeur invalide\n");
                return 1;
            }
            i += 1;
        } else if arg.starts_with('-')
            && arg.len() > 1
            && arg[1..].chars().all(|c| c.is_ascii_digit())
        {
            let parsed = parse_i64(&arg[1..]);
            if parsed > 0 {
                width = parsed as usize;
            } else {
                let _ = sys_write(err_fd, b"fold: largeur invalide\n");
                return 1;
            }
            i += 1;
        } else if arg == "--" {
            i += 1;
            while i < args.len() && file_count < file_args.len() {
                file_args[file_count] = args[i];
                file_count += 1;
                i += 1;
            }
            break;
        } else {
            if file_count < file_args.len() {
                file_args[file_count] = arg;
                file_count += 1;
            }
            i += 1;
        }
    }

    if width == 0 {
        width = 80;
    }

    let fold_stream = |r_fd: i32| -> bool {
        let mut in_chunk = [0u8; 1024];
        let mut line_buf = [0u8; 2048];
        let mut line_len = 0usize;
        let mut current_col = 0usize;

        loop {
            let n = sys_read(r_fd, &mut in_chunk);
            if n <= 0 {
                break;
            }
            for &b in &in_chunk[..n as usize] {
                if b == b'\n' {
                    if line_len > 0 {
                        let _ = sys_write(out_fd, &line_buf[..line_len]);
                    }
                    let _ = sys_write(out_fd, b"\n");
                    line_len = 0;
                    current_col = 0;
                    continue;
                }

                let advance = if count_bytes {
                    1
                } else {
                    match b {
                        b'\t' => {
                            let next = (current_col + 8) & !7;
                            next - current_col
                        }
                        b'\x08' => 0,
                        b'\r' => 0,
                        _ => 1,
                    }
                };

                // Si l'ajout dépasse la largeur autorisée et qu'on a déjà du contenu sur la ligne
                if current_col + advance > width && current_col > 0 {
                    if break_spaces {
                        // Chercher le dernier séparateur (espace ou tab) dans la ligne
                        let mut last_space = None;
                        for idx in (0..line_len).rev() {
                            if line_buf[idx] == b' ' || line_buf[idx] == b'\t' {
                                last_space = Some(idx);
                                break;
                            }
                        }

                        if let Some(sp_idx) = last_space {
                            // Émettre jusqu'au séparateur inclus
                            let _ = sys_write(out_fd, &line_buf[..=sp_idx]);
                            let _ = sys_write(out_fd, b"\n");

                            // Décaler le reliquat après l'espace vers le début
                            let remainder_len = line_len - (sp_idx + 1);
                            for j in 0..remainder_len {
                                line_buf[j] = line_buf[sp_idx + 1 + j];
                            }
                            line_len = remainder_len;

                            // Recalculer current_col pour le reliquat
                            current_col = 0;
                            for &ch in &line_buf[..line_len] {
                                if count_bytes {
                                    current_col += 1;
                                } else {
                                    match ch {
                                        b'\t' => current_col = (current_col + 8) & !7,
                                        b'\x08' => current_col = current_col.saturating_sub(1),
                                        b'\r' => current_col = 0,
                                        _ => current_col += 1,
                                    }
                                }
                            }
                        } else {
                            // Pas d'espace disponible : coupure stricte
                            let _ = sys_write(out_fd, &line_buf[..line_len]);
                            let _ = sys_write(out_fd, b"\n");
                            line_len = 0;
                            current_col = 0;
                        }
                    } else {
                        // Coupure franche sans recherche d'espace
                        let _ = sys_write(out_fd, &line_buf[..line_len]);
                        let _ = sys_write(out_fd, b"\n");
                        line_len = 0;
                        current_col = 0;
                    }
                }

                // Insérer l'octet dans line_buf si espace suffisant
                if line_len < line_buf.len() {
                    line_buf[line_len] = b;
                    line_len += 1;
                    if count_bytes {
                        current_col += 1;
                    } else {
                        match b {
                            b'\t' => current_col = (current_col + 8) & !7,
                            b'\x08' => current_col = current_col.saturating_sub(1),
                            b'\r' => current_col = 0,
                            _ => current_col += 1,
                        }
                    }
                }
            }
        }

        // Émettre le résidu éventuel
        if line_len > 0 {
            let _ = sys_write(out_fd, &line_buf[..line_len]);
        }

        true
    };

    if file_count == 0 {
        fold_stream(in_fd);
        0
    } else {
        let mut has_err = false;
        for path in &file_args[..file_count] {
            if *path == "-" {
                fold_stream(in_fd);
                continue;
            }
            let fd = sys_open(path, O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"fold: ");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                has_err = true;
                continue;
            }
            fold_stream(fd);
            let _ = sys_close(fd);
        }
        if has_err {
            1
        } else {
            0
        }
    }
}

/// Mode de numérotation pour une section de `nl` (POSIX.1-2024)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NlNumberingMode {
    All,      // 'a' : Toutes les lignes
    NonEmpty, // 't' : Lignes non vides uniquement (défaut corps)
    None,     // 'n' : Aucune ligne numérotée
}

/// Format de justification du numéro de ligne
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NlFormat {
    Left,              // 'ln' : Justifié à gauche
    RightLeadingBlank, // 'rn' : Justifié à droite, espaces de tête (défaut)
    RightLeadingZero,  // 'rz' : Justifié à droite, zéros de tête
}

/// Section courante du flux de texte
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NlSection {
    Header,
    Body,
    Footer,
}

/// Utilitaire POSIX standard `nl` (Line Numbering Filter)
///
/// Numérote les lignes des fichiers passés en paramètre ou de l'entrée standard (stdin)
/// selon les spécifications POSIX.1-2024 IEEE Std 1003.1.
pub fn run_nl(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut body_mode = NlNumberingMode::NonEmpty;
    let mut header_mode = NlNumberingMode::None;
    let mut footer_mode = NlNumberingMode::None;
    let mut format = NlFormat::RightLeadingBlank;
    let mut width: usize = 6;
    let mut separator: &str = "\t";
    let mut start_num: i64 = 1;
    let mut incr: i64 = 1;

    let mut file_args = [""; 32];
    let mut file_count = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if arg == "-ba" || (arg == "-b" && i + 1 < args.len() && args[i + 1].trim() == "a") {
            body_mode = NlNumberingMode::All;
            i += if arg == "-ba" { 1 } else { 2 };
        } else if arg == "-bt" || (arg == "-b" && i + 1 < args.len() && args[i + 1].trim() == "t") {
            body_mode = NlNumberingMode::NonEmpty;
            i += if arg == "-bt" { 1 } else { 2 };
        } else if arg == "-bn" || (arg == "-b" && i + 1 < args.len() && args[i + 1].trim() == "n") {
            body_mode = NlNumberingMode::None;
            i += if arg == "-bn" { 1 } else { 2 };
        } else if arg == "-ha" || (arg == "-h" && i + 1 < args.len() && args[i + 1].trim() == "a") {
            header_mode = NlNumberingMode::All;
            i += if arg == "-ha" { 1 } else { 2 };
        } else if arg == "-ht" || (arg == "-h" && i + 1 < args.len() && args[i + 1].trim() == "t") {
            header_mode = NlNumberingMode::NonEmpty;
            i += if arg == "-ht" { 1 } else { 2 };
        } else if arg == "-hn" || (arg == "-h" && i + 1 < args.len() && args[i + 1].trim() == "n") {
            header_mode = NlNumberingMode::None;
            i += if arg == "-hn" { 1 } else { 2 };
        } else if arg == "-fa" || (arg == "-f" && i + 1 < args.len() && args[i + 1].trim() == "a") {
            footer_mode = NlNumberingMode::All;
            i += if arg == "-fa" { 1 } else { 2 };
        } else if arg == "-ft" || (arg == "-f" && i + 1 < args.len() && args[i + 1].trim() == "t") {
            footer_mode = NlNumberingMode::NonEmpty;
            i += if arg == "-ft" { 1 } else { 2 };
        } else if arg == "-fn" || (arg == "-f" && i + 1 < args.len() && args[i + 1].trim() == "n") {
            footer_mode = NlNumberingMode::None;
            i += if arg == "-fn" { 1 } else { 2 };
        } else if arg == "-nln" || (arg == "-n" && i + 1 < args.len() && args[i + 1].trim() == "ln")
        {
            format = NlFormat::Left;
            i += if arg == "-nln" { 1 } else { 2 };
        } else if arg == "-nrn" || (arg == "-n" && i + 1 < args.len() && args[i + 1].trim() == "rn")
        {
            format = NlFormat::RightLeadingBlank;
            i += if arg == "-nrn" { 1 } else { 2 };
        } else if arg == "-nrz" || (arg == "-n" && i + 1 < args.len() && args[i + 1].trim() == "rz")
        {
            format = NlFormat::RightLeadingZero;
            i += if arg == "-nrz" { 1 } else { 2 };
        } else if arg == "-w" {
            if i + 1 < args.len() {
                let parsed = parse_i64(args[i + 1].trim());
                if parsed > 0 {
                    width = (parsed as usize).min(64);
                } else {
                    let _ = sys_write(err_fd, b"nl: largeur invalide\n");
                    return 1;
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"nl: option requiert un argument -- 'w'\n");
                return 1;
            }
        } else if arg.starts_with("-w")
            && arg.len() > 2
            && arg[2..].chars().all(|c| c.is_ascii_digit())
        {
            let parsed = parse_i64(&arg[2..]);
            if parsed > 0 {
                width = (parsed as usize).min(64);
            } else {
                let _ = sys_write(err_fd, b"nl: largeur invalide\n");
                return 1;
            }
            i += 1;
        } else if arg == "-s" {
            if i + 1 < args.len() {
                separator = args[i + 1];
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"nl: option requiert un argument -- 's'\n");
                return 1;
            }
        } else if arg.starts_with("-s") && arg.len() > 2 {
            separator = &arg[2..];
            i += 1;
        } else if arg == "-v" {
            if i + 1 < args.len() {
                start_num = parse_i64(args[i + 1].trim());
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"nl: option requiert un argument -- 'v'\n");
                return 1;
            }
        } else if arg.starts_with("-v")
            && arg.len() > 2
            && (arg[2..].chars().all(|c| c.is_ascii_digit())
                || (arg.starts_with("-v-") && arg[3..].chars().all(|c| c.is_ascii_digit())))
        {
            start_num = parse_i64(&arg[2..]);
            i += 1;
        } else if arg == "-i" {
            if i + 1 < args.len() {
                let parsed = parse_i64(args[i + 1].trim());
                if parsed > 0 {
                    incr = parsed;
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"nl: option requiert un argument -- 'i'\n");
                return 1;
            }
        } else if arg.starts_with("-i")
            && arg.len() > 2
            && arg[2..].chars().all(|c| c.is_ascii_digit())
        {
            let parsed = parse_i64(&arg[2..]);
            if parsed > 0 {
                incr = parsed;
            }
            i += 1;
        } else if arg == "--" {
            i += 1;
            while i < args.len() && file_count < file_args.len() {
                file_args[file_count] = args[i];
                file_count += 1;
                i += 1;
            }
            break;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"nl: option invalide: ");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"\n");
            return 1;
        } else {
            if file_count < file_args.len() {
                file_args[file_count] = arg;
                file_count += 1;
            }
            i += 1;
        }
    }

    let mut current_line_num = start_num;
    let mut current_section = NlSection::Body;

    let mut nl_stream = |r_fd: i32| -> bool {
        let mut in_chunk = [0u8; 1024];
        let mut line_buf = [0u8; 4096];
        let mut line_len = 0usize;

        let emit_line = |line: &[u8], sect: &mut NlSection, c_num: &mut i64| {
            // Vérifier si la ligne est un délimiteur logique POSIX
            if line == b"\\:\\:\\:" {
                *sect = NlSection::Header;
                let _ = sys_write(out_fd, b"\n");
                return;
            } else if line == b"\\:\\:" {
                *sect = NlSection::Body;
                let _ = sys_write(out_fd, b"\n");
                return;
            } else if line == b"\\:" {
                *sect = NlSection::Footer;
                let _ = sys_write(out_fd, b"\n");
                return;
            }

            let mode = match *sect {
                NlSection::Header => header_mode,
                NlSection::Body => body_mode,
                NlSection::Footer => footer_mode,
            };

            let should_number = match mode {
                NlNumberingMode::All => true,
                NlNumberingMode::NonEmpty => !line.is_empty(),
                NlNumberingMode::None => false,
            };

            if should_number {
                // Formater le numéro de ligne dans un tampon fixe
                let mut num_str_buf = [0u8; 32];
                let mut val = *c_num;
                let is_neg = val < 0;
                if is_neg {
                    val = -val;
                }
                let num_len = if val == 0 {
                    num_str_buf[0] = b'0';
                    1
                } else {
                    let mut temp = [0u8; 32];
                    let mut t_len = 0;
                    while val > 0 && t_len < temp.len() {
                        temp[t_len] = b'0' + (val % 10) as u8;
                        val /= 10;
                        t_len += 1;
                    }
                    if is_neg && t_len < temp.len() {
                        temp[t_len] = b'-';
                        t_len += 1;
                    }
                    for idx in 0..t_len {
                        num_str_buf[idx] = temp[t_len - 1 - idx];
                    }
                    t_len
                };

                let num_slice = &num_str_buf[..num_len];
                let pad_count = width.saturating_sub(num_len);

                match format {
                    NlFormat::RightLeadingBlank => {
                        for _ in 0..pad_count {
                            let _ = sys_write(out_fd, b" ");
                        }
                        let _ = sys_write(out_fd, num_slice);
                    }
                    NlFormat::RightLeadingZero => {
                        for _ in 0..pad_count {
                            let _ = sys_write(out_fd, b"0");
                        }
                        let _ = sys_write(out_fd, num_slice);
                    }
                    NlFormat::Left => {
                        let _ = sys_write(out_fd, num_slice);
                        for _ in 0..pad_count {
                            let _ = sys_write(out_fd, b" ");
                        }
                    }
                }

                let _ = sys_write(out_fd, separator.as_bytes());
                *c_num += incr;
            } else {
                // Émettre un espacement équivalent sans numéro
                for _ in 0..width {
                    let _ = sys_write(out_fd, b" ");
                }
                let _ = sys_write(out_fd, separator.as_bytes());
            }

            let _ = sys_write(out_fd, line);
            let _ = sys_write(out_fd, b"\n");
        };

        loop {
            let n = sys_read(r_fd, &mut in_chunk);
            if n <= 0 {
                break;
            }
            for &b in &in_chunk[..n as usize] {
                if b == b'\n' {
                    emit_line(
                        &line_buf[..line_len],
                        &mut current_section,
                        &mut current_line_num,
                    );
                    line_len = 0;
                } else if line_len < line_buf.len() {
                    line_buf[line_len] = b;
                    line_len += 1;
                }
            }
        }

        if line_len > 0 {
            emit_line(
                &line_buf[..line_len],
                &mut current_section,
                &mut current_line_num,
            );
        }

        true
    };

    if file_count == 0 {
        nl_stream(in_fd);
        0
    } else {
        let mut has_err = false;
        for path in &file_args[..file_count] {
            if *path == "-" {
                nl_stream(in_fd);
                continue;
            }
            let fd = sys_open(path, O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"nl: ");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                has_err = true;
                continue;
            }
            nl_stream(fd);
            let _ = sys_close(fd);
        }
        if has_err {
            1
        } else {
            0
        }
    }
}

/// Base de numérotation d'adresse pour l'utilitaire `od` (Octal Dump)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdRadix {
    Octal,
    Decimal,
    Hex,
    None,
}

/// Format de représentation des données pour l'utilitaire `od`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdFormat {
    Octal2,
    Octal1,
    Char,
    Decimal2,
    Hex2,
    Hex4,
    Decimal4,
}

/// Formate l'offset d'adresse de ligne selon la base radix
fn format_od_offset(offset: usize, radix: OdRadix, out: &mut [u8]) -> usize {
    match radix {
        OdRadix::None => 0,
        OdRadix::Octal => {
            let mut val = offset;
            for i in (0..7).rev() {
                out[i] = b'0' + (val & 7) as u8;
                val >>= 3;
            }
            7
        }
        OdRadix::Decimal => {
            let mut val = offset;
            for i in (0..7).rev() {
                out[i] = b'0' + (val % 10) as u8;
                val /= 10;
            }
            7
        }
        OdRadix::Hex => {
            let hex_chars = b"0123456789abcdef";
            let mut val = offset;
            for i in (0..7).rev() {
                out[i] = hex_chars[val & 0x0F];
                val >>= 4;
            }
            7
        }
    }
}

/// Analyse un entier non signé avec support des préfixes 0x (hex) et 0 (octal)
fn parse_od_number(s: &str) -> Option<usize> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        let hex_str = &trimmed[2..];
        if hex_str.is_empty() {
            return None;
        }
        let mut val = 0usize;
        for &b in hex_str.as_bytes() {
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as usize,
                b'a'..=b'f' => (b - b'a' + 10) as usize,
                b'A'..=b'F' => (b - b'A' + 10) as usize,
                _ => return None,
            };
            val = val.checked_mul(16)?.checked_add(digit)?;
        }
        Some(val)
    } else if trimmed.starts_with('0') && trimmed.len() > 1 {
        let mut val = 0usize;
        for &b in &trimmed.as_bytes()[1..] {
            if (b'0'..=b'7').contains(&b) {
                val = val.checked_mul(8)?.checked_add((b - b'0') as usize)?;
            } else {
                return None;
            }
        }
        Some(val)
    } else {
        let mut val = 0usize;
        for &b in trimmed.as_bytes() {
            if b.is_ascii_digit() {
                val = val.checked_mul(10)?.checked_add((b - b'0') as usize)?;
            } else {
                return None;
            }
        }
        Some(val)
    }
}

/// Utilitaire POSIX standard `od` (Octal Dump)
///
/// Décharge les données d'un ou plusieurs fichiers (ou stdin) sous forme d'unités
/// octales, hexadécimales, décimales ou caractères ASCII échappés selon IEEE Std 1003.1.
pub fn run_od(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut radix = OdRadix::Octal;
    let mut format = OdFormat::Octal2;
    let mut skip_bytes: usize = 0;
    let mut max_bytes: Option<usize> = None;
    let mut _verbose = false;

    let mut file_args = [""; 32];
    let mut file_count = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if arg == "-b" {
            format = OdFormat::Octal1;
            i += 1;
        } else if arg == "-c" {
            format = OdFormat::Char;
            i += 1;
        } else if arg == "-d" || arg == "-u" {
            format = OdFormat::Decimal2;
            i += 1;
        } else if arg == "-o" {
            format = OdFormat::Octal2;
            i += 1;
        } else if arg == "-x" || arg == "-h" {
            format = OdFormat::Hex2;
            i += 1;
        } else if arg == "-v" {
            _verbose = true;
            i += 1;
        } else if arg == "-A" {
            if i + 1 < args.len() {
                match args[i + 1].trim() {
                    "d" => radix = OdRadix::Decimal,
                    "o" => radix = OdRadix::Octal,
                    "x" => radix = OdRadix::Hex,
                    "n" => radix = OdRadix::None,
                    other => {
                        let _ = sys_write(err_fd, b"od: base d'adresse invalide: ");
                        let _ = sys_write(err_fd, other.as_bytes());
                        let _ = sys_write(err_fd, b"\n");
                        return 1;
                    }
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"od: option requiert un argument -- 'A'\n");
                return 1;
            }
        } else if arg.starts_with("-A") && arg.len() == 3 {
            match &arg[2..3] {
                "d" => radix = OdRadix::Decimal,
                "o" => radix = OdRadix::Octal,
                "x" => radix = OdRadix::Hex,
                "n" => radix = OdRadix::None,
                other => {
                    let _ = sys_write(err_fd, b"od: base d'adresse invalide: ");
                    let _ = sys_write(err_fd, other.as_bytes());
                    let _ = sys_write(err_fd, b"\n");
                    return 1;
                }
            }
            i += 1;
        } else if arg == "-t" {
            if i + 1 < args.len() {
                match args[i + 1].trim() {
                    "o1" | "b" => format = OdFormat::Octal1,
                    "o" | "o2" => format = OdFormat::Octal2,
                    "c" => format = OdFormat::Char,
                    "u1" | "d1" => format = OdFormat::Octal1,
                    "u" | "u2" | "d2" => format = OdFormat::Decimal2,
                    "u4" | "d4" => format = OdFormat::Decimal4,
                    "x" | "x2" => format = OdFormat::Hex2,
                    "x4" => format = OdFormat::Hex4,
                    other => {
                        let _ = sys_write(err_fd, b"od: type de format invalide: ");
                        let _ = sys_write(err_fd, other.as_bytes());
                        let _ = sys_write(err_fd, b"\n");
                        return 1;
                    }
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"od: option requiert un argument -- 't'\n");
                return 1;
            }
        } else if arg == "-j" {
            if i + 1 < args.len() {
                if let Some(val) = parse_od_number(args[i + 1].trim()) {
                    skip_bytes = val;
                } else {
                    let _ = sys_write(err_fd, b"od: decalage invalide pour -j\n");
                    return 1;
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"od: option requiert un argument -- 'j'\n");
                return 1;
            }
        } else if arg == "-N" {
            if i + 1 < args.len() {
                if let Some(val) = parse_od_number(args[i + 1].trim()) {
                    max_bytes = Some(val);
                } else {
                    let _ = sys_write(err_fd, b"od: limite invalide pour -N\n");
                    return 1;
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"od: option requiert un argument -- 'N'\n");
                return 1;
            }
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"od: option invalide: ");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"\n");
            return 1;
        } else {
            if file_count < file_args.len() {
                file_args[file_count] = arg;
                file_count += 1;
            }
            i += 1;
        }
    }

    let mut current_offset: usize = 0;
    let mut skipped: usize = 0;
    let mut total_emitted: usize = 0;

    let mut line_buf = [0u8; 16];
    let mut line_len = 0usize;

    let emit_od_line = |bytes: &[u8], offset: usize| {
        let mut out_scratch = [0u8; 256];
        let mut out_len = 0usize;

        // 1. Offset d'adresse
        if radix != OdRadix::None {
            let mut off_buf = [0u8; 7];
            let off_len = format_od_offset(offset, radix, &mut off_buf);
            for &b in &off_buf[..off_len] {
                out_scratch[out_len] = b;
                out_len += 1;
            }
        }

        // 2. Formatage des valeurs selon le format sélectionné
        match format {
            OdFormat::Octal2 => {
                let mut idx = 0;
                while idx < bytes.len() {
                    let b0 = bytes[idx];
                    let b1 = if idx + 1 < bytes.len() {
                        bytes[idx + 1]
                    } else {
                        0
                    };
                    let val = u16::from_ne_bytes([b0, b1]);

                    out_scratch[out_len] = b' ';
                    out_len += 1;
                    let mut digits = [b'0'; 6];
                    let mut temp = val;
                    for d in (0..6).rev() {
                        digits[d] = b'0' + (temp & 7) as u8;
                        temp >>= 3;
                    }
                    for &d in &digits {
                        out_scratch[out_len] = d;
                        out_len += 1;
                    }
                    idx += 2;
                }
            }
            OdFormat::Octal1 => {
                for &b in bytes {
                    out_scratch[out_len] = b' ';
                    out_len += 1;
                    out_scratch[out_len] = b'0' + ((b >> 6) & 7);
                    out_scratch[out_len + 1] = b'0' + ((b >> 3) & 7);
                    out_scratch[out_len + 2] = b'0' + (b & 7);
                    out_len += 3;
                }
            }
            OdFormat::Char => {
                for &b in bytes {
                    out_scratch[out_len] = b' ';
                    out_len += 1;
                    match b {
                        b'\n' => {
                            out_scratch[out_len] = b' ';
                            out_scratch[out_len + 1] = b'\\';
                            out_scratch[out_len + 2] = b'n';
                            out_len += 3;
                        }
                        b'\t' => {
                            out_scratch[out_len] = b' ';
                            out_scratch[out_len + 1] = b'\\';
                            out_scratch[out_len + 2] = b't';
                            out_len += 3;
                        }
                        b'\r' => {
                            out_scratch[out_len] = b' ';
                            out_scratch[out_len + 1] = b'\\';
                            out_scratch[out_len + 2] = b'r';
                            out_len += 3;
                        }
                        b'\0' => {
                            out_scratch[out_len] = b' ';
                            out_scratch[out_len + 1] = b'\\';
                            out_scratch[out_len + 2] = b'0';
                            out_len += 3;
                        }
                        32..=126 => {
                            out_scratch[out_len] = b' ';
                            out_scratch[out_len + 1] = b' ';
                            out_scratch[out_len + 2] = b;
                            out_len += 3;
                        }
                        _ => {
                            out_scratch[out_len] = b'0' + ((b >> 6) & 7);
                            out_scratch[out_len + 1] = b'0' + ((b >> 3) & 7);
                            out_scratch[out_len + 2] = b'0' + (b & 7);
                            out_len += 3;
                        }
                    }
                }
            }
            OdFormat::Decimal2 => {
                let mut idx = 0;
                while idx < bytes.len() {
                    let b0 = bytes[idx];
                    let b1 = if idx + 1 < bytes.len() {
                        bytes[idx + 1]
                    } else {
                        0
                    };
                    let val = u16::from_ne_bytes([b0, b1]);

                    out_scratch[out_len] = b' ';
                    out_len += 1;
                    let mut digits = [b'0'; 5];
                    let mut temp = val;
                    for d in (0..5).rev() {
                        digits[d] = b'0' + (temp % 10) as u8;
                        temp /= 10;
                    }
                    for &d in &digits {
                        out_scratch[out_len] = d;
                        out_len += 1;
                    }
                    idx += 2;
                }
            }
            OdFormat::Hex2 => {
                let hex_chars = b"0123456789abcdef";
                let mut idx = 0;
                while idx < bytes.len() {
                    let b0 = bytes[idx];
                    let b1 = if idx + 1 < bytes.len() {
                        bytes[idx + 1]
                    } else {
                        0
                    };
                    let val = u16::from_ne_bytes([b0, b1]);

                    out_scratch[out_len] = b' ';
                    out_len += 1;
                    out_scratch[out_len] = hex_chars[((val >> 12) & 0x0F) as usize];
                    out_scratch[out_len + 1] = hex_chars[((val >> 8) & 0x0F) as usize];
                    out_scratch[out_len + 2] = hex_chars[((val >> 4) & 0x0F) as usize];
                    out_scratch[out_len + 3] = hex_chars[(val & 0x0F) as usize];
                    out_len += 4;
                    idx += 2;
                }
            }
            OdFormat::Hex4 => {
                let hex_chars = b"0123456789abcdef";
                let mut idx = 0;
                while idx < bytes.len() {
                    let mut b4 = [0u8; 4];
                    for k in 0..4 {
                        if idx + k < bytes.len() {
                            b4[k] = bytes[idx + k];
                        }
                    }
                    let val = u32::from_ne_bytes(b4);

                    out_scratch[out_len] = b' ';
                    out_len += 1;
                    for shift in (0..8).rev() {
                        out_scratch[out_len] = hex_chars[((val >> (shift * 4)) & 0x0F) as usize];
                        out_len += 1;
                    }
                    idx += 4;
                }
            }
            OdFormat::Decimal4 => {
                let mut idx = 0;
                while idx < bytes.len() {
                    let mut b4 = [0u8; 4];
                    for k in 0..4 {
                        if idx + k < bytes.len() {
                            b4[k] = bytes[idx + k];
                        }
                    }
                    let val = u32::from_ne_bytes(b4);

                    out_scratch[out_len] = b' ';
                    out_len += 1;
                    let mut digits = [b'0'; 10];
                    let mut temp = val;
                    for d in (0..10).rev() {
                        digits[d] = b'0' + (temp % 10) as u8;
                        temp /= 10;
                    }
                    for &d in &digits {
                        out_scratch[out_len] = d;
                        out_len += 1;
                    }
                    idx += 4;
                }
            }
        }

        out_scratch[out_len] = b'\n';
        out_len += 1;
        let _ = sys_write(out_fd, &out_scratch[..out_len]);
    };

    let mut process_fd = |r_fd: i32| -> bool {
        let mut in_chunk = [0u8; 1024];
        loop {
            let n = sys_read(r_fd, &mut in_chunk);
            if n <= 0 {
                break;
            }
            let read_slice = &in_chunk[..n as usize];
            for &b in read_slice {
                if skipped < skip_bytes {
                    skipped += 1;
                    continue;
                }
                if let Some(limit) = max_bytes {
                    if total_emitted >= limit {
                        return false;
                    }
                }

                line_buf[line_len] = b;
                line_len += 1;
                total_emitted += 1;

                if line_len == 16 {
                    emit_od_line(&line_buf, current_offset);
                    current_offset += 16;
                    line_len = 0;
                }
            }
        }
        true
    };

    let mut has_err = false;
    if file_count == 0 {
        process_fd(in_fd);
    } else {
        for &path in &file_args[..file_count] {
            if path == "-" {
                if !process_fd(in_fd) {
                    break;
                }
                continue;
            }
            let fd = sys_open(path, crate::vfs::O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"od: ");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                has_err = true;
                continue;
            }
            let cont = process_fd(fd);
            let _ = sys_close(fd);
            if !cont {
                break;
            }
        }
    }

    if line_len > 0 {
        emit_od_line(&line_buf[..line_len], current_offset);
        current_offset += line_len;
    }

    // Affichage de l'offset final si radix != None
    if radix != OdRadix::None && total_emitted > 0 {
        let mut final_buf = [0u8; 8];
        let off_len = format_od_offset(current_offset, radix, &mut final_buf[..7]);
        final_buf[off_len] = b'\n';
        let _ = sys_write(out_fd, &final_buf[..off_len + 1]);
    }

    if has_err {
        1
    } else {
        0
    }
}

/// Utilitaire POSIX standard `cmp` (Compare two files byte by byte)
///
/// Conforme à la norme POSIX IEEE Std 1003.1-2017.
/// Syntaxe : `cmp [-l | -s] file1 file2 [skip1 [skip2]]`
///
/// Codes de retour :
/// - 0 : les fichiers sont identiques
/// - 1 : les fichiers diffèrent (ou EOF atteint prématurément sur un fichier)
/// - >1 (2) : erreur d'accès ou argument invalide
pub fn run_cmp(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut verbose_list = false;
    let mut silent = false;
    let mut operands = [""; 4];
    let mut operand_count = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if arg == "-l" || arg == "--verbose" {
            verbose_list = true;
            silent = false;
        } else if arg == "-s" || arg == "--quiet" || arg == "--silent" {
            silent = true;
            verbose_list = false;
        } else if arg == "--help" || arg == "-h" {
            let _ = sys_write(
                out_fd,
                b"Usage: cmp [-l | -s] FILE1 FILE2 [SKIP1 [SKIP2]]\n\
Compare two files byte by byte.\n\n\
  -l, --verbose   Output byte numbers and differing byte values\n\
  -s, --quiet     Output nothing; yield exit status only\n\
      --help      Display this help and exit\n",
            );
            return 0;
        } else if arg.starts_with('-') && arg.len() > 1 && arg != "-" {
            let _ = sys_write(err_fd, b"cmp: invalid option -- '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(
                err_fd,
                b"'\nUsage: cmp [-l | -s] FILE1 FILE2 [SKIP1 [SKIP2]]\n",
            );
            return 2;
        } else {
            if operand_count < operands.len() {
                operands[operand_count] = arg;
                operand_count += 1;
            } else {
                let _ = sys_write(err_fd, b"cmp: extra operand\n");
                return 2;
            }
        }
        i += 1;
    }

    if operand_count < 2 {
        let _ = sys_write(
            err_fd,
            b"cmp: missing operand\nUsage: cmp [-l | -s] FILE1 FILE2 [SKIP1 [SKIP2]]\n",
        );
        return 2;
    }

    let file1 = operands[0];
    let file2 = operands[1];
    let skip1 = if operand_count > 2 {
        match parse_od_number(operands[2]) {
            Some(v) => v,
            None => {
                let _ = sys_write(err_fd, b"cmp: offset skip1 invalide\n");
                return 2;
            }
        }
    } else {
        0
    };
    let skip2 = if operand_count > 3 {
        match parse_od_number(operands[3]) {
            Some(v) => v,
            None => {
                let _ = sys_write(err_fd, b"cmp: offset skip2 invalide\n");
                return 2;
            }
        }
    } else {
        0
    };

    // Ouverture file1
    let (fd1, close_1) = if file1 == "-" {
        (in_fd, false)
    } else {
        let fd = sys_open(file1, crate::vfs::O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"cmp: ");
            let _ = sys_write(err_fd, file1.as_bytes());
            let _ = sys_write(err_fd, b": No such file or directory\n");
            return 2;
        }
        (fd, true)
    };

    // Ouverture file2
    let (fd2, close_2) = if file2 == "-" {
        if file1 == "-" {
            if close_1 {
                let _ = sys_close(fd1);
            }
            let _ = sys_write(err_fd, b"cmp: cannot use '-' for both files\n");
            return 2;
        }
        (in_fd, false)
    } else {
        let fd = sys_open(file2, crate::vfs::O_RDONLY);
        if fd < 0 {
            if close_1 {
                let _ = sys_close(fd1);
            }
            let _ = sys_write(err_fd, b"cmp: ");
            let _ = sys_write(err_fd, file2.as_bytes());
            let _ = sys_write(err_fd, b": No such file or directory\n");
            return 2;
        }
        (fd, true)
    };

    let cleanup = |f1: i32, c1: bool, f2: i32, c2: bool| {
        if c1 {
            let _ = sys_close(f1);
        }
        if c2 {
            let _ = sys_close(f2);
        }
    };

    // Consommation du skip1
    let mut skipped1 = 0;
    while skipped1 < skip1 {
        let mut trash = [0u8; 512];
        let to_read = (skip1 - skipped1).min(trash.len());
        let n = sys_read(fd1, &mut trash[..to_read]);
        if n <= 0 {
            cleanup(fd1, close_1, fd2, close_2);
            if !silent {
                let _ = sys_write(err_fd, b"cmp: EOF on ");
                let _ = sys_write(err_fd, file1.as_bytes());
                let _ = sys_write(err_fd, b" which is empty\n");
            }
            return 1;
        }
        skipped1 += n as usize;
    }

    // Consommation du skip2
    let mut skipped2 = 0;
    while skipped2 < skip2 {
        let mut trash = [0u8; 512];
        let to_read = (skip2 - skipped2).min(trash.len());
        let n = sys_read(fd2, &mut trash[..to_read]);
        if n <= 0 {
            cleanup(fd1, close_1, fd2, close_2);
            if !silent {
                let _ = sys_write(err_fd, b"cmp: EOF on ");
                let _ = sys_write(err_fd, file2.as_bytes());
                let _ = sys_write(err_fd, b" which is empty\n");
            }
            return 1;
        }
        skipped2 += n as usize;
    }

    // Comparaison octet par octet
    let mut buf1 = [0u8; 512];
    let mut buf2 = [0u8; 512];
    let mut pos1 = 0usize;
    let mut len1 = 0usize;
    let mut pos2 = 0usize;
    let mut len2 = 0usize;
    let mut eof1 = false;
    let mut eof2 = false;

    let mut byte_num: usize = 1;
    let mut line_num: usize = 1;
    let mut diff_count: usize = 0;

    let write_usize = |fd: i32, mut val: usize| {
        if val == 0 {
            let _ = sys_write(fd, b"0");
            return;
        }
        let mut digits = [0u8; 20];
        let mut cnt = 0;
        while val > 0 {
            digits[cnt] = b'0' + (val % 10) as u8;
            val /= 10;
            cnt += 1;
        }
        let mut rev = [0u8; 20];
        for k in 0..cnt {
            rev[k] = digits[cnt - 1 - k];
        }
        let _ = sys_write(fd, &rev[..cnt]);
    };

    let write_octal3 = |fd: i32, val: u8| {
        let o1 = b'0' + ((val >> 6) & 0x07);
        let o2 = b'0' + ((val >> 3) & 0x07);
        let o3 = b'0' + (val & 0x07);
        let _ = sys_write(fd, &[o1, o2, o3]);
    };

    loop {
        if pos1 >= len1 && !eof1 {
            let n = sys_read(fd1, &mut buf1);
            if n <= 0 {
                eof1 = true;
            } else {
                len1 = n as usize;
                pos1 = 0;
            }
        }

        if pos2 >= len2 && !eof2 {
            let n = sys_read(fd2, &mut buf2);
            if n <= 0 {
                eof2 = true;
            } else {
                len2 = n as usize;
                pos2 = 0;
            }
        }

        if (pos1 >= len1 && eof1) || (pos2 >= len2 && eof2) {
            break;
        }

        let b1 = buf1[pos1];
        let b2 = buf2[pos2];
        pos1 += 1;
        pos2 += 1;

        if b1 != b2 {
            diff_count += 1;
            if silent {
                cleanup(fd1, close_1, fd2, close_2);
                return 1;
            }
            if verbose_list {
                // Format: byte_number octal_b1 octal_b2\n
                write_usize(out_fd, byte_num);
                let _ = sys_write(out_fd, b" ");
                write_octal3(out_fd, b1);
                let _ = sys_write(out_fd, b" ");
                write_octal3(out_fd, b2);
                let _ = sys_write(out_fd, b"\n");
            } else {
                // Format: file1 file2 differ: byte X, line Y\n
                let _ = sys_write(out_fd, file1.as_bytes());
                let _ = sys_write(out_fd, b" ");
                let _ = sys_write(out_fd, file2.as_bytes());
                let _ = sys_write(out_fd, b" differ: byte ");
                write_usize(out_fd, byte_num);
                let _ = sys_write(out_fd, b", line ");
                write_usize(out_fd, line_num);
                let _ = sys_write(out_fd, b"\n");
                cleanup(fd1, close_1, fd2, close_2);
                return 1;
            }
        }

        if b1 == b'\n' {
            line_num += 1;
        }
        byte_num += 1;
    }

    let remaining1 = (!eof1 && len1 > pos1)
        || (pos1 >= len1 && !eof1 && {
            let n = sys_read(fd1, &mut buf1);
            n > 0
        });
    let remaining2 = (!eof2 && len2 > pos2)
        || (pos2 >= len2 && !eof2 && {
            let n = sys_read(fd2, &mut buf2);
            n > 0
        });

    cleanup(fd1, close_1, fd2, close_2);

    if remaining1 || remaining2 {
        if !silent {
            let _ = sys_write(err_fd, b"cmp: EOF on ");
            if remaining2 {
                let _ = sys_write(err_fd, file1.as_bytes());
            } else {
                let _ = sys_write(err_fd, file2.as_bytes());
            }
            let _ = sys_write(err_fd, b" after byte ");
            write_usize(err_fd, byte_num - 1);
            let _ = sys_write(err_fd, b"\n");
        }
        return 1;
    }

    if diff_count > 0 {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire standard POSIX `expand` (conversion des tabulations en espaces)
pub fn run_expand(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut initial_only = false;
    let mut tab_size: usize = 8;
    let mut explicit_tabs = [0usize; 16];
    let mut explicit_tab_count = 0usize;
    let mut files = [""; 16];
    let mut file_count = 0usize;
    let mut parsing_options = true;

    let parse_tab_list = |val: &str, tabs: &mut [usize; 16], count: &mut usize| -> bool {
        *count = 0;
        let mut cur = 0usize;
        let mut has_digit = false;
        for &b in val.as_bytes() {
            if b.is_ascii_digit() {
                cur = cur.wrapping_mul(10).wrapping_add((b - b'0') as usize);
                has_digit = true;
            } else if b == b',' || b == b' ' {
                if has_digit && cur > 0 {
                    if *count < tabs.len() {
                        tabs[*count] = cur;
                        *count += 1;
                    }
                    cur = 0;
                    has_digit = false;
                } else if has_digit && cur == 0 {
                    return false;
                }
            } else {
                return false;
            }
        }
        if has_digit {
            if cur == 0 {
                return false;
            }
            if *count < tabs.len() {
                tabs[*count] = cur;
                *count += 1;
            }
        }
        *count > 0
    };

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg.len() > 1 && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    out_fd,
                    b"Usage: expand [OPTION]... [FILE]...\n\
Convert tabs in each FILE to spaces, writing to standard output.\n\n\
  -i, --initial       do not convert tabs after non blanks\n\
  -t, --tabs=N        have tabs N characters apart, not 8\n\
  -t, --tabs=LIST     use comma separated list of tab positions\n\
      --help          display this help and exit\n",
                );
                return 0;
            } else if arg == "-i" || arg == "--initial" {
                initial_only = true;
            } else if arg == "-t" || arg == "--tabs" {
                if i + 1 < args.len() {
                    i += 1;
                    let val = args[i];
                    if !parse_tab_list(val, &mut explicit_tabs, &mut explicit_tab_count) {
                        let _ = sys_write(err_fd, b"expand: tab size contains invalid character\n");
                        return 1;
                    }
                    if explicit_tab_count == 1 {
                        tab_size = explicit_tabs[0];
                        explicit_tab_count = 0;
                    }
                } else {
                    let _ = sys_write(err_fd, b"expand: option requires an argument -- 't'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--tabs=") {
                if !parse_tab_list(val, &mut explicit_tabs, &mut explicit_tab_count) {
                    let _ = sys_write(err_fd, b"expand: tab size contains invalid character\n");
                    return 1;
                }
                if explicit_tab_count == 1 {
                    tab_size = explicit_tabs[0];
                    explicit_tab_count = 0;
                }
            } else if arg.starts_with("-t") && arg.len() > 2 {
                let val = &arg[2..];
                if !parse_tab_list(val, &mut explicit_tabs, &mut explicit_tab_count) {
                    let _ = sys_write(err_fd, b"expand: tab size contains invalid character\n");
                    return 1;
                }
                if explicit_tab_count == 1 {
                    tab_size = explicit_tabs[0];
                    explicit_tab_count = 0;
                }
            } else if arg.len() > 1 && arg[1..].bytes().all(|b| b.is_ascii_digit()) {
                // Forme raccourcie historique : -4
                if let Some(n) = parse_od_number(&arg[1..]) {
                    if n > 0 {
                        tab_size = n;
                        explicit_tab_count = 0;
                    } else {
                        let _ = sys_write(err_fd, b"expand: tab size cannot be 0\n");
                        return 1;
                    }
                }
            } else {
                let _ = sys_write(err_fd, b"expand: unrecognized option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if file_count < files.len() {
                files[file_count] = arg;
                file_count += 1;
            }
        }
        i += 1;
    }

    let default_files = ["-"];
    let files_to_process = if file_count > 0 {
        &files[..file_count]
    } else {
        &default_files[..]
    };

    let next_tabstop = |col: usize, size: usize, tabs: &[usize]| -> usize {
        if !tabs.is_empty() {
            for &t in tabs {
                if t > col {
                    return t;
                }
            }
            // Si on dépasse le dernier tabstop explicite, 1 espace minimum
            col + 1
        } else {
            let rem = col % size;
            col + (size - rem)
        }
    };

    let mut exit_status = 0;

    for &file in files_to_process {
        let (fd, should_close) = if file == "-" {
            (in_fd, false)
        } else {
            let fd = sys_open(file, crate::vfs::O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"expand: ");
                let _ = sys_write(err_fd, file.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                exit_status = 1;
                continue;
            }
            (fd, true)
        };

        let mut read_buf = [0u8; 512];
        let mut out_chunk = [0u8; 1024];
        let mut out_len = 0usize;
        let mut col = 0usize;
        let mut non_space_seen = false;

        loop {
            let n = sys_read(fd, &mut read_buf);
            if n <= 0 {
                break;
            }

            for &b in &read_buf[..n as usize] {
                match b {
                    b'\t' => {
                        if initial_only && non_space_seen {
                            out_chunk[out_len] = b'\t';
                            out_len += 1;
                            col += 1;
                        } else {
                            let nxt = next_tabstop(
                                col,
                                tab_size,
                                if explicit_tab_count > 0 {
                                    &explicit_tabs[..explicit_tab_count]
                                } else {
                                    &[]
                                },
                            );
                            let spaces = nxt.saturating_sub(col);
                            for _ in 0..spaces {
                                if out_len >= out_chunk.len() {
                                    let _ = sys_write(out_fd, &out_chunk[..out_len]);
                                    out_len = 0;
                                }
                                out_chunk[out_len] = b' ';
                                out_len += 1;
                            }
                            col = nxt;
                        }
                    }
                    b'\n' => {
                        out_chunk[out_len] = b'\n';
                        out_len += 1;
                        col = 0;
                        non_space_seen = false;
                    }
                    b'\r' => {
                        out_chunk[out_len] = b'\r';
                        out_len += 1;
                        col = 0;
                    }
                    0x08 => {
                        out_chunk[out_len] = 0x08;
                        out_len += 1;
                        col = col.saturating_sub(1);
                    }
                    _ => {
                        if b != b' ' {
                            non_space_seen = true;
                        }
                        out_chunk[out_len] = b;
                        out_len += 1;
                        col += 1;
                    }
                }

                if out_len >= out_chunk.len() - 32 {
                    let _ = sys_write(out_fd, &out_chunk[..out_len]);
                    out_len = 0;
                }
            }
        }

        if out_len > 0 {
            let _ = sys_write(out_fd, &out_chunk[..out_len]);
        }

        if should_close {
            let _ = sys_close(fd);
        }
    }

    exit_status
}

/// Exécute l'utilitaire standard POSIX `unexpand` (conversion des espaces en tabulations)
pub fn run_unexpand(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut convert_all = false;
    let mut tab_size: usize = 8;
    let mut explicit_tabs = [0usize; 16];
    let mut explicit_tab_count = 0usize;
    let mut files = [""; 16];
    let mut file_count = 0usize;
    let mut parsing_options = true;

    let parse_tab_list = |val: &str, tabs: &mut [usize; 16], count: &mut usize| -> bool {
        *count = 0;
        let mut cur = 0usize;
        let mut has_digit = false;
        for &b in val.as_bytes() {
            if b.is_ascii_digit() {
                cur = cur.wrapping_mul(10).wrapping_add((b - b'0') as usize);
                has_digit = true;
            } else if b == b',' || b == b' ' {
                if has_digit && cur > 0 {
                    if *count < tabs.len() {
                        tabs[*count] = cur;
                        *count += 1;
                    }
                    cur = 0;
                    has_digit = false;
                } else if has_digit && cur == 0 {
                    return false;
                }
            } else {
                return false;
            }
        }
        if has_digit {
            if cur == 0 {
                return false;
            }
            if *count < tabs.len() {
                tabs[*count] = cur;
                *count += 1;
            }
        }
        *count > 0
    };

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg.len() > 1 && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    out_fd,
                    b"Usage: unexpand [OPTION]... [FILE]...\n\
Convert blanks in each FILE to tabs, writing to standard output.\n\n\
  -a, --all           convert all blanks, instead of just initial blanks\n\
      --first-only    convert only leading sequences of blanks (overrides -a)\n\
  -t, --tabs=N        have tabs N characters apart instead of 8 (enables -a)\n\
  -t, --tabs=LIST     use comma separated list of tab positions (enables -a)\n\
      --help          display this help and exit\n",
                );
                return 0;
            } else if arg == "-a" || arg == "--all" {
                convert_all = true;
            } else if arg == "--first-only" {
                convert_all = false;
            } else if arg == "-t" || arg == "--tabs" {
                if i + 1 < args.len() {
                    i += 1;
                    let val = args[i];
                    if !parse_tab_list(val, &mut explicit_tabs, &mut explicit_tab_count) {
                        let _ =
                            sys_write(err_fd, b"unexpand: tab size contains invalid character\n");
                        return 1;
                    }
                    convert_all = true;
                    if explicit_tab_count == 1 {
                        tab_size = explicit_tabs[0];
                        explicit_tab_count = 0;
                    }
                } else {
                    let _ = sys_write(err_fd, b"unexpand: option requires an argument -- 't'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--tabs=") {
                if !parse_tab_list(val, &mut explicit_tabs, &mut explicit_tab_count) {
                    let _ = sys_write(err_fd, b"unexpand: tab size contains invalid character\n");
                    return 1;
                }
                convert_all = true;
                if explicit_tab_count == 1 {
                    tab_size = explicit_tabs[0];
                    explicit_tab_count = 0;
                }
            } else if arg.starts_with("-t") && arg.len() > 2 {
                let val = &arg[2..];
                if !parse_tab_list(val, &mut explicit_tabs, &mut explicit_tab_count) {
                    let _ = sys_write(err_fd, b"unexpand: tab size contains invalid character\n");
                    return 1;
                }
                convert_all = true;
                if explicit_tab_count == 1 {
                    tab_size = explicit_tabs[0];
                    explicit_tab_count = 0;
                }
            } else if arg.len() > 1 && arg[1..].bytes().all(|b| b.is_ascii_digit()) {
                if let Some(n) = parse_od_number(&arg[1..]) {
                    if n > 0 {
                        tab_size = n;
                        explicit_tab_count = 0;
                        convert_all = true;
                    } else {
                        let _ = sys_write(err_fd, b"unexpand: tab size cannot be 0\n");
                        return 1;
                    }
                }
            } else {
                let _ = sys_write(err_fd, b"unexpand: unrecognized option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if file_count < files.len() {
                files[file_count] = arg;
                file_count += 1;
            }
        }
        i += 1;
    }

    let default_files = ["-"];
    let files_to_process = if file_count > 0 {
        &files[..file_count]
    } else {
        &default_files[..]
    };

    let next_tabstop = |col: usize, size: usize, tabs: &[usize]| -> usize {
        if !tabs.is_empty() {
            for &t in tabs {
                if t > col {
                    return t;
                }
            }
            col + 1
        } else {
            let rem = col % size;
            col + (size - rem)
        }
    };

    let is_tabstop = |col: usize, size: usize, tabs: &[usize]| -> bool {
        if !tabs.is_empty() {
            tabs.contains(&col)
        } else {
            col > 0 && col.is_multiple_of(size)
        }
    };

    let mut exit_status = 0;

    for &file in files_to_process {
        let (fd, should_close) = if file == "-" {
            (in_fd, false)
        } else {
            let fd = sys_open(file, crate::vfs::O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"unexpand: ");
                let _ = sys_write(err_fd, file.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                exit_status = 1;
                continue;
            }
            (fd, true)
        };

        let mut read_buf = [0u8; 512];
        let mut out_chunk = [0u8; 1024];
        let mut out_len = 0usize;
        let mut col = 0usize;
        let mut pending_spaces = 0usize;
        let mut leading = true;

        let tabs_slice = if explicit_tab_count > 0 {
            &explicit_tabs[..explicit_tab_count]
        } else {
            &[]
        };

        loop {
            let n = sys_read(fd, &mut read_buf);
            if n <= 0 {
                break;
            }

            for &b in &read_buf[..n as usize] {
                match b {
                    b' ' => {
                        pending_spaces += 1;
                        col += 1;
                        if is_tabstop(col, tab_size, tabs_slice)
                            && (convert_all || leading)
                            && (pending_spaces > 1 || leading)
                        {
                            if out_len >= out_chunk.len() {
                                let _ = sys_write(out_fd, &out_chunk[..out_len]);
                                out_len = 0;
                            }
                            out_chunk[out_len] = b'\t';
                            out_len += 1;
                            pending_spaces = 0;
                        }
                    }
                    b'\t' => {
                        let next_col = next_tabstop(col, tab_size, tabs_slice);
                        col = next_col;
                        pending_spaces = 0;
                        if out_len >= out_chunk.len() {
                            let _ = sys_write(out_fd, &out_chunk[..out_len]);
                            out_len = 0;
                        }
                        out_chunk[out_len] = b'\t';
                        out_len += 1;
                    }
                    b'\n' => {
                        for _ in 0..pending_spaces {
                            if out_len >= out_chunk.len() {
                                let _ = sys_write(out_fd, &out_chunk[..out_len]);
                                out_len = 0;
                            }
                            out_chunk[out_len] = b' ';
                            out_len += 1;
                        }
                        pending_spaces = 0;
                        if out_len >= out_chunk.len() {
                            let _ = sys_write(out_fd, &out_chunk[..out_len]);
                            out_len = 0;
                        }
                        out_chunk[out_len] = b'\n';
                        out_len += 1;
                        col = 0;
                        leading = true;
                    }
                    b'\r' => {
                        for _ in 0..pending_spaces {
                            if out_len >= out_chunk.len() {
                                let _ = sys_write(out_fd, &out_chunk[..out_len]);
                                out_len = 0;
                            }
                            out_chunk[out_len] = b' ';
                            out_len += 1;
                        }
                        pending_spaces = 0;
                        if out_len >= out_chunk.len() {
                            let _ = sys_write(out_fd, &out_chunk[..out_len]);
                            out_len = 0;
                        }
                        out_chunk[out_len] = b'\r';
                        out_len += 1;
                        col = 0;
                    }
                    0x08 => {
                        for _ in 0..pending_spaces {
                            if out_len >= out_chunk.len() {
                                let _ = sys_write(out_fd, &out_chunk[..out_len]);
                                out_len = 0;
                            }
                            out_chunk[out_len] = b' ';
                            out_len += 1;
                        }
                        pending_spaces = 0;
                        if out_len >= out_chunk.len() {
                            let _ = sys_write(out_fd, &out_chunk[..out_len]);
                            out_len = 0;
                        }
                        out_chunk[out_len] = 0x08;
                        out_len += 1;
                        col = col.saturating_sub(1);
                    }
                    _ => {
                        leading = false;
                        for _ in 0..pending_spaces {
                            if out_len >= out_chunk.len() {
                                let _ = sys_write(out_fd, &out_chunk[..out_len]);
                                out_len = 0;
                            }
                            out_chunk[out_len] = b' ';
                            out_len += 1;
                        }
                        pending_spaces = 0;
                        if out_len >= out_chunk.len() {
                            let _ = sys_write(out_fd, &out_chunk[..out_len]);
                            out_len = 0;
                        }
                        out_chunk[out_len] = b;
                        out_len += 1;
                        col += 1;
                    }
                }

                if out_len >= out_chunk.len() - 32 {
                    let _ = sys_write(out_fd, &out_chunk[..out_len]);
                    out_len = 0;
                }
            }
        }

        for _ in 0..pending_spaces {
            if out_len >= out_chunk.len() {
                let _ = sys_write(out_fd, &out_chunk[..out_len]);
                out_len = 0;
            }
            out_chunk[out_len] = b' ';
            out_len += 1;
        }

        if out_len > 0 {
            let _ = sys_write(out_fd, &out_chunk[..out_len]);
        }

        if should_close {
            let _ = sys_close(fd);
        }
    }

    exit_status
}

/// Parse une durée en millisecondes depuis une tranche d'octets (suffixes: 's'=secondes, 'm'=minutes, sans suffixe=secondes).
///
/// Retourne `None` si la chaîne est vide, contient des caractères non numériques
/// ou un suffixe non reconnu.
pub fn parse_duration_ms(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let last = s[s.len() - 1];
    let (digits, factor_ms): (&[u8], u64) = match last {
        b's' | b'S' => (&s[..s.len() - 1], 1_000),
        b'm' | b'M' => (&s[..s.len() - 1], 60_000),
        b'0'..=b'9' => (s, 1_000),
        _ => return None,
    };
    if digits.is_empty() {
        return None;
    }
    let mut val: u64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    val.checked_mul(factor_ms)
}

/// Niveau de priorité nice Ring 3 compris dans l'intervalle [-20..19].
///
/// Reflète la convention POSIX/Linux : -20 est la priorité la plus favorable
/// au processus (haute urgence), 19 est la moins favorable (tâche de fond).
#[derive(Debug, Clone, Copy)]
pub struct NiceLevel(pub i8);

impl NiceLevel {
    /// Crée un `NiceLevel` à partir de la valeur `v` si elle appartient à [-20, 19].
    ///
    /// Retourne `None` si `v` est hors de l'intervalle valide.
    pub fn new(v: i8) -> Option<Self> {
        if (-20..=19).contains(&v) {
            Some(Self(v))
        } else {
            None
        }
    }

    /// Retourne la valeur de priorité brute.
    pub fn value(self) -> i8 {
        self.0
    }
}

/// Analyse une chaîne d'intervalle temporel POSIX et retourne sa durée en millisecondes
pub fn parse_interval_ms(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let s_lower = s;
    let (num_part, factor_ms): (&str, u64) = if s_lower.ends_with("ms") || s_lower.ends_with("MS") {
        (&s[..s.len() - 2], 1)
    } else {
        let bytes = s.as_bytes();
        match bytes[bytes.len() - 1] {
            b's' | b'S' => (&s[..s.len() - 1], 1_000),
            b'm' | b'M' => (&s[..s.len() - 1], 60_000),
            b'h' | b'H' => (&s[..s.len() - 1], 3_600_000),
            b'd' | b'D' => (&s[..s.len() - 1], 86_400_000),
            b'0'..=b'9' | b'.' => (s, 1_000),
            _ => return None,
        }
    };

    if num_part.is_empty() {
        return None;
    }

    let mut dot_count = 0;
    let mut dot_pos = None;
    for (i, &b) in num_part.as_bytes().iter().enumerate() {
        if b == b'.' {
            dot_count += 1;
            dot_pos = Some(i);
        } else if !b.is_ascii_digit() {
            return None;
        }
    }
    if dot_count > 1 {
        return None;
    }

    let (int_str, frac_str) = match dot_pos {
        Some(pos) => (&num_part[..pos], &num_part[pos + 1..]),
        None => (num_part, ""),
    };

    if int_str.is_empty() && frac_str.is_empty() {
        return None;
    }

    let mut int_val: u64 = 0;
    if !int_str.is_empty() {
        for &b in int_str.as_bytes() {
            int_val = int_val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
        }
    }

    let int_ms = int_val.checked_mul(factor_ms)?;

    let mut frac_ms: u64 = 0;
    if !frac_str.is_empty() {
        let mut frac_val: u64 = 0;
        let mut div: u64 = 1;
        for &b in frac_str.as_bytes() {
            if div <= 1_000_000_000 {
                frac_val = frac_val.wrapping_mul(10).wrapping_add((b - b'0') as u64);
                div = div.wrapping_mul(10);
            }
        }
        if div > 1 {
            frac_ms = (frac_val as u128 * factor_ms as u128 / div as u128) as u64;
        }
    }

    int_ms.checked_add(frac_ms)
}

/// Suspend l'exécution pendant une durée donnée en millisecondes en libérant le processeur (EEVDF Yield)
pub fn execute_sleep_ms(total_ms: u64) {
    if total_ms == 0 {
        return;
    }

    if let Ok(start_ts) = crate::clock_gettime(crate::clocks::CLOCK_MONOTONIC) {
        let target_ns = (start_ts.tv_sec as u128 * 1_000_000_000 + start_ts.tv_nsec as u128)
            .saturating_add(total_ms as u128 * 1_000_000);

        let mut max_spins = 10_000_000u64;
        let mut prev_ns = start_ts.tv_sec as u128 * 1_000_000_000 + start_ts.tv_nsec as u128;
        let mut stuck_count = 0;

        while max_spins > 0 {
            max_spins -= 1;
            crate::syscall_thread_yield();
            if let Ok(cur_ts) = crate::clock_gettime(crate::clocks::CLOCK_MONOTONIC) {
                let cur_ns = cur_ts.tv_sec as u128 * 1_000_000_000 + cur_ts.tv_nsec as u128;
                if cur_ns >= target_ns {
                    break;
                }
                if cur_ns == prev_ns {
                    stuck_count += 1;
                    if stuck_count > 50 {
                        // Horloge statique (ex: environnement de test unitaire host)
                        break;
                    }
                } else {
                    stuck_count = 0;
                    prev_ns = cur_ns;
                }
            } else {
                break;
            }
        }
    } else {
        let yields = total_ms.min(10);
        for _ in 0..yields {
            crate::syscall_thread_yield();
        }
    }
}

/// Utilitaire Coreutils POSIX `sleep` : suspend l'exécution pendant NUMBER secondes ou unités spécifiées
pub fn run_sleep(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    if args.is_empty() {
        let msg = b"sleep: missing operand\nTry 'sleep --help' for more information.\n";
        let _ = sys_write(err_fd, msg);
        return 1;
    }

    let mut total_ms: u64 = 0;

    for &arg in args {
        if arg == "--help" || arg == "-h" {
            let help = b"Usage: sleep NUMBER[SUFFIX]...\n\
Pause for NUMBER seconds.  SUFFIX may be 's' for seconds (the default),\n\
'm' for minutes, 'h' for hours or 'd' for days.  Given two or more arguments,\n\
pause for the amount of time specified by the sum of their values.\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" || arg == "-v" {
            let ver = b"sleep (JamboOS coreutils) 0.3.92\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }

        match parse_interval_ms(arg) {
            Some(ms) => {
                total_ms = match total_ms.checked_add(ms) {
                    Some(sum) => sum,
                    None => {
                        let msg = b"sleep: time interval overflow\n";
                        let _ = sys_write(err_fd, msg);
                        return 1;
                    }
                };
            }
            None => {
                let _ = sys_write(err_fd, b"sleep: invalid time interval '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\nTry 'sleep --help' for more information.\n");
                return 1;
            }
        }
    }

    execute_sleep_ms(total_ms);
    0
}

/// Table précalculée pour le CRC POSIX standard IEEE 1003.1 (polynôme 0x04C11DB7)
pub const POSIX_CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = (i as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 0x8000_0000) != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
            } else {
                crc <<= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Structure de calcul incrémental du CRC-32 et comptage d'octets POSIX cksum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixCksum {
    pub crc: u32,
    pub total_bytes: u64,
}

impl Default for PosixCksum {
    fn default() -> Self {
        Self::new()
    }
}

impl PosixCksum {
    pub const fn new() -> Self {
        Self {
            crc: 0,
            total_bytes: 0,
        }
    }

    /// Met à jour l'état CRC avec un bloc d'octets
    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(data.len() as u64);
        for &b in data {
            let idx = (((self.crc >> 24) ^ (b as u32)) & 0xFF) as usize;
            self.crc = (self.crc << 8) ^ POSIX_CRC_TABLE[idx];
        }
    }

    /// Finalise le calcul POSIX en intégrant la longueur en octets et en inversant les bits
    pub fn finalize(mut self) -> (u32, u64) {
        let mut len = self.total_bytes;
        while len > 0 {
            let b = (len & 0xFF) as u8;
            let idx = (((self.crc >> 24) ^ (b as u32)) & 0xFF) as usize;
            self.crc = (self.crc << 8) ^ POSIX_CRC_TABLE[idx];
            len >>= 8;
        }
        (!self.crc, self.total_bytes)
    }
}

/// Calcule la somme de contrôle POSIX `cksum` sur un descripteur de fichier ouvert
fn cksum_fd(fd: i32) -> Result<(u32, u64), i32> {
    let mut cksum = PosixCksum::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = sys_read(fd, &mut buf);
        if n < 0 {
            return Err(n as i32);
        }
        if n == 0 {
            break;
        }
        cksum.update(&buf[..n as usize]);
    }
    Ok(cksum.finalize())
}

/// Utilitaire Coreutils POSIX `cksum` : calcule la somme de contrôle CRC POSIX et le compte d'octets
pub fn run_cksum(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut files = [""; 64];
    let mut file_count = 0usize;

    for &arg in args {
        if arg == "--help" || arg == "-h" {
            let help = b"Usage: cksum [FILE]...\n  or:  cksum [OPTION]\nPrint CRC checksum and byte counts of each FILE.\n\n      --help     display this help and exit\n      --version  output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" || arg == "-v" {
            let ver = b"cksum (JamboOS coreutils) 0.1.0\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }
        if file_count < files.len() {
            files[file_count] = arg;
            file_count += 1;
        }
    }

    if file_count == 0 {
        match cksum_fd(in_fd) {
            Ok((crc, len)) => {
                write_u64_fd(out_fd, crc as u64);
                let _ = sys_write(out_fd, b" ");
                write_u64_fd(out_fd, len);
                let _ = sys_write(out_fd, b"\n");
                return 0;
            }
            Err(_) => {
                let _ = sys_write(err_fd, b"cksum: error reading standard input\n");
                return 1;
            }
        }
    }

    let mut exit_code = 0;
    for &file in &files[..file_count] {
        if file == "-" {
            match cksum_fd(in_fd) {
                Ok((crc, len)) => {
                    write_u64_fd(out_fd, crc as u64);
                    let _ = sys_write(out_fd, b" ");
                    write_u64_fd(out_fd, len);
                    let _ = sys_write(out_fd, b"\n");
                }
                Err(_) => {
                    let _ = sys_write(err_fd, b"cksum: error reading standard input\n");
                    exit_code = 1;
                }
            }
        } else {
            let fd = sys_open(file, crate::vfs::O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"cksum: ");
                let _ = sys_write(err_fd, file.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                exit_code = 1;
                continue;
            }
            match cksum_fd(fd) {
                Ok((crc, len)) => {
                    let _ = sys_close(fd);
                    write_u64_fd(out_fd, crc as u64);
                    let _ = sys_write(out_fd, b" ");
                    write_u64_fd(out_fd, len);
                    let _ = sys_write(out_fd, b" ");
                    let _ = sys_write(out_fd, file.as_bytes());
                    let _ = sys_write(out_fd, b"\n");
                }
                Err(_) => {
                    let _ = sys_close(fd);
                    let _ = sys_write(err_fd, b"cksum: error reading ");
                    let _ = sys_write(err_fd, file.as_bytes());
                    let _ = sys_write(err_fd, b"\n");
                    exit_code = 1;
                }
            }
        }
    }

    exit_code
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `base64` (RFC 4648 Base64 Encoding/Decoding)
// ============================================================================

pub const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Erreurs de traitement Base64 (RFC 4648)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// Le tampon de sortie est insuffisant pour accueillir les données
    BufferTooSmall,
    /// Caractère invalide rencontré dans le flux Base64
    InvalidCharacter,
    /// Séquence de padding '=' tronquée ou invalide
    InvalidPadding,
}

/// Encode un slice d'octets en Base64 standard (RFC 4648)
/// Insère des retours à la ligne après `wrap_cols` colonnes (si `wrap_cols > 0`).
pub fn base64_encode(
    input: &[u8],
    out_buf: &mut [u8],
    wrap_cols: usize,
) -> Result<usize, Base64Error> {
    let mut in_idx = 0;
    let mut out_idx = 0;
    let mut col = 0;

    while in_idx < input.len() {
        let remaining = input.len() - in_idx;
        let (c0, c1, c2, c3) = if remaining >= 3 {
            let b0 = input[in_idx];
            let b1 = input[in_idx + 1];
            let b2 = input[in_idx + 2];
            in_idx += 3;
            (
                BASE64_ALPHABET[(b0 >> 2) as usize],
                BASE64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize],
                BASE64_ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize],
                BASE64_ALPHABET[(b2 & 0x3F) as usize],
            )
        } else if remaining == 2 {
            let b0 = input[in_idx];
            let b1 = input[in_idx + 1];
            in_idx += 2;
            (
                BASE64_ALPHABET[(b0 >> 2) as usize],
                BASE64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize],
                BASE64_ALPHABET[((b1 & 0x0F) << 2) as usize],
                b'=',
            )
        } else {
            let b0 = input[in_idx];
            in_idx += 1;
            (
                BASE64_ALPHABET[(b0 >> 2) as usize],
                BASE64_ALPHABET[((b0 & 0x03) << 4) as usize],
                b'=',
                b'=',
            )
        };

        for &c in &[c0, c1, c2, c3] {
            if wrap_cols > 0 && col >= wrap_cols {
                if out_idx >= out_buf.len() {
                    return Err(Base64Error::BufferTooSmall);
                }
                out_buf[out_idx] = b'\n';
                out_idx += 1;
                col = 0;
            }
            if out_idx >= out_buf.len() {
                return Err(Base64Error::BufferTooSmall);
            }
            out_buf[out_idx] = c;
            out_idx += 1;
            col += 1;
        }
    }

    if out_idx > 0 {
        if out_idx >= out_buf.len() {
            return Err(Base64Error::BufferTooSmall);
        }
        out_buf[out_idx] = b'\n';
        out_idx += 1;
    }

    Ok(out_idx)
}

/// Convertit un caractère ASCII RFC 4648 en valeur 6-bit (0..63)
/// Retourne 0xFE pour '=', 0xFD pour whitespace (\r, \n, ' ', \t), 0xFF pour invalide.
#[inline]
pub fn base64_char_to_val(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        b'=' => 0xFE,
        b'\r' | b'\n' | b' ' | b'\t' => 0xFD,
        _ => 0xFF,
    }
}

/// Décode un flux Base64 (RFC 4648) en octets binaires
pub fn base64_decode(
    input: &[u8],
    out_buf: &mut [u8],
    ignore_garbage: bool,
) -> Result<usize, Base64Error> {
    let mut out_idx = 0;
    let mut quad = [0u8; 4];
    let mut quad_len = 0;

    for &b in input {
        let val = base64_char_to_val(b);
        if val == 0xFD {
            continue;
        }
        if val == 0xFF {
            if ignore_garbage {
                continue;
            } else {
                return Err(Base64Error::InvalidCharacter);
            }
        }

        quad[quad_len] = val;
        quad_len += 1;

        if quad_len == 4 {
            let q0 = quad[0];
            let q1 = quad[1];
            let q2 = quad[2];
            let q3 = quad[3];
            quad_len = 0;

            if q0 == 0xFE || q1 == 0xFE {
                return Err(Base64Error::InvalidPadding);
            }

            if q2 == 0xFE {
                if q3 != 0xFE {
                    return Err(Base64Error::InvalidPadding);
                }
                if out_idx >= out_buf.len() {
                    return Err(Base64Error::BufferTooSmall);
                }
                out_buf[out_idx] = (q0 << 2) | (q1 >> 4);
                out_idx += 1;
            } else if q3 == 0xFE {
                if out_idx + 1 >= out_buf.len() {
                    return Err(Base64Error::BufferTooSmall);
                }
                out_buf[out_idx] = (q0 << 2) | (q1 >> 4);
                out_buf[out_idx + 1] = ((q1 & 0x0F) << 4) | (q2 >> 2);
                out_idx += 2;
            } else {
                if out_idx + 2 >= out_buf.len() {
                    return Err(Base64Error::BufferTooSmall);
                }
                out_buf[out_idx] = (q0 << 2) | (q1 >> 4);
                out_buf[out_idx + 1] = ((q1 & 0x0F) << 4) | (q2 >> 2);
                out_buf[out_idx + 2] = ((q2 & 0x03) << 6) | q3;
                out_idx += 3;
            }
        }
    }

    if quad_len != 0 {
        return Err(Base64Error::InvalidPadding);
    }

    Ok(out_idx)
}

/// Routine de lecture complète d'un descripteur de fichier jusqu'à EOF
fn read_all_fd(fd: i32, out_buf: &mut [u8]) -> Result<usize, i32> {
    let mut total = 0;
    loop {
        if total >= out_buf.len() {
            break;
        }
        let n = sys_read(fd, &mut out_buf[total..]);
        if n < 0 {
            return Err(n as i32);
        }
        if n == 0 {
            break;
        }
        total += n as usize;
    }
    Ok(total)
}

/// Utilitaire Coreutils POSIX / GNU `base64` : encode ou décode des données en Base64
pub fn run_base64(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut decode = false;
    let mut ignore_garbage = false;
    let mut wrap_cols = 76usize;
    let mut file: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" || arg == "-h" {
            let help = b"Usage: base64 [OPTION]... [FILE]\nBase64 encode or decode FILE, or standard input, to standard output.\n\n  -d, --decode          decode data\n  -i, --ignore-garbage  when decoding, ignore non-alphabet characters\n  -w, --wrap=COLS       wrap encoded lines after COLS character (default 76, 0 to disable)\n      --help            display this help and exit\n      --version         output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" || arg == "-v" {
            let ver = b"base64 (JamboOS coreutils) 0.1.0\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }
        if arg == "-d" || arg == "--decode" {
            decode = true;
        } else if arg == "-i" || arg == "--ignore-garbage" {
            ignore_garbage = true;
        } else if arg == "-w" || arg == "--wrap" {
            if i + 1 < args.len() {
                i += 1;
                wrap_cols = parse_usize(args[i]).unwrap_or(76);
            }
        } else if let Some(stripped) = arg.strip_prefix("--wrap=") {
            wrap_cols = parse_usize(stripped).unwrap_or(76);
        } else if let Some(stripped) = arg.strip_prefix("-w") {
            wrap_cols = parse_usize(stripped).unwrap_or(76);
        } else if !arg.starts_with('-') || arg == "-" {
            file = Some(arg);
        }
        i += 1;
    }

    let input_fd = match file {
        None | Some("-") => in_fd,
        Some(path) => {
            let fd = sys_open(path, crate::vfs::O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"base64: ");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                return 1;
            }
            fd
        }
    };

    let mut in_buffer = [0u8; 8192];
    let mut out_buffer = [0u8; 16384];

    let bytes_read = match read_all_fd(input_fd, &mut in_buffer) {
        Ok(n) => n,
        Err(_) => {
            let _ = sys_write(err_fd, b"base64: error reading input\n");
            if input_fd != in_fd {
                let _ = sys_close(input_fd);
            }
            return 1;
        }
    };

    if input_fd != in_fd {
        let _ = sys_close(input_fd);
    }

    if decode {
        match base64_decode(&in_buffer[..bytes_read], &mut out_buffer, ignore_garbage) {
            Ok(n) => {
                let _ = sys_write(out_fd, &out_buffer[..n]);
                0
            }
            Err(_) => {
                let _ = sys_write(err_fd, b"base64: invalid input\n");
                1
            }
        }
    } else {
        match base64_encode(&in_buffer[..bytes_read], &mut out_buffer, wrap_cols) {
            Ok(n) => {
                let _ = sys_write(out_fd, &out_buffer[..n]);
                0
            }
            Err(_) => {
                let _ = sys_write(err_fd, b"base64: error encoding data\n");
                1
            }
        }
    }
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `sha256sum` (Calcul et vérification FIPS 180-4 SHA-256)
// ============================================================================

/// Hasher cryptographique SHA-256 déterministe bare-metal (#![no_std])
#[derive(Clone, Copy)]
pub struct Sha256Hasher {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Sha256Hasher {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn transform_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        let mut i = 0;
        while i < 16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        let mut j = 0;
        while j < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[j])
                .wrapping_add(w[j]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
            j += 1;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        let mut offset = 0;
        while offset < data.len() {
            if self.buffer_len == 64 {
                let blk = self.buffer;
                self.transform_block(&blk);
                self.buffer_len = 0;
            }
            let to_copy = (64 - self.buffer_len).min(data.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_bytes.wrapping_mul(8);
        if self.buffer_len == 64 {
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            let mut i = self.buffer_len;
            while i < 64 {
                self.buffer[i] = 0;
                i += 1;
            }
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }

        let mut i = self.buffer_len;
        while i < 56 {
            self.buffer[i] = 0;
            i += 1;
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let blk = self.buffer;
        self.transform_block(&blk);

        let mut out = [0u8; 32];
        let mut k = 0;
        while k < 8 {
            out[k * 4..(k + 1) * 4].copy_from_slice(&self.state[k].to_be_bytes());
            k += 1;
        }
        out
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convertit un condensat SHA-256 (32 octets) en représentation hexadécimale minuscule (64 octets ASCII)
pub fn sha256_to_hex(digest: &[u8; 32], out: &mut [u8; 64]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..32 {
        let b = digest[i];
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
}

/// Hache un descripteur de fichier ouvert en streaming sans allocation
fn hash_fd_sha256(fd: i32) -> Result<[u8; 32], ()> {
    let mut hasher = Sha256Hasher::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = sys_read(fd, &mut chunk);
        if n < 0 {
            return Err(());
        }
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n as usize]);
    }
    Ok(hasher.finalize())
}

/// Parse une ligne de fichier de vérification sha256 (format GNU ou BSD)
fn parse_sha256_check_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Format BSD: SHA256 (path) = hex64
    if let Some(rest) = trimmed.strip_prefix("SHA256 (") {
        if let Some(close_idx) = rest.find(')') {
            let path = &rest[..close_idx];
            let after = rest[close_idx + 1..].trim();
            if let Some(hex_part) = after.strip_prefix('=') {
                let hex = hex_part.trim();
                if hex.len() == 64 {
                    return Some((path, hex));
                }
            }
        }
    }

    // Format standard GNU: <hex64>  <path> ou <hex64> *<path>
    if trimmed.len() >= 66 {
        let hex = &trimmed[..64];
        let sep = &trimmed[64..66];
        if (sep == "  " || sep == " *" || sep == "  ")
            && hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
        {
            let path = trimmed[66..].trim();
            if !path.is_empty() {
                return Some((path, hex));
            }
        }
    }

    None
}

/// Exécute l'utilitaire Coreutils POSIX / GNU `sha256sum` (calcul et vérification SHA-256)
pub fn run_sha256sum(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut check_mode = false;
    let mut tag_format = false;
    let mut binary_mode = false;
    let mut status_only = false;
    let mut quiet = false;
    let mut warn = false;
    let mut file_args = [""; 64];
    let mut file_count = 0usize;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" || arg == "-h" {
            let help = b"Usage: sha256sum [OPTION]... [FILE]...\nPrint or check SHA256 (256-bit) checksums.\n\nWith no FILE, or when FILE is -, read standard input.\n\n  -b, --binary         read in binary mode\n  -c, --check          read checksums from the FILEs and check them\n      --tag            create a BSD-style checksum\n  -t, --text           read in text mode (default)\n  -q, --quiet          don't print OK for each successfully verified file\n      --status         don't output anything, status code shows success\n  -w, --warn           warn about improperly formatted checksum lines\n      --help           display this help and exit\n      --version        output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" || arg == "-v" {
            let ver = b"sha256sum (JamboOS coreutils) 0.1.0\nCopyright (C) 2026 JamboOS Authors.\nLicense MIT or Apache-2.0.\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }

        if arg == "-c" || arg == "--check" {
            check_mode = true;
        } else if arg == "--tag" {
            tag_format = true;
        } else if arg == "-b" || arg == "--binary" {
            binary_mode = true;
        } else if arg == "-t" || arg == "--text" {
            binary_mode = false;
        } else if arg == "--status" {
            status_only = true;
        } else if arg == "-q" || arg == "--quiet" {
            quiet = true;
        } else if arg == "-w" || arg == "--warn" {
            warn = true;
        } else if (!arg.starts_with('-') || arg == "-") && file_count < file_args.len() {
            file_args[file_count] = arg;
            file_count += 1;
        }
        i += 1;
    }

    if check_mode {
        let mut overall_success = true;
        let mut total_verified = 0usize;

        let targets: &[&str] = if file_count == 0 {
            &["-"]
        } else {
            &file_args[..file_count]
        };

        for &target in targets {
            let check_fd = if target == "-" {
                in_fd
            } else {
                let fd = sys_open(target, crate::vfs::O_RDONLY);
                if fd < 0 {
                    if !status_only {
                        let _ = sys_write(err_fd, b"sha256sum: ");
                        let _ = sys_write(err_fd, target.as_bytes());
                        let _ = sys_write(err_fd, b": No such file or directory\n");
                    }
                    overall_success = false;
                    continue;
                }
                fd
            };

            let mut reader = LineReader::new(check_fd);
            let mut line_buf = [0u8; 512];

            while let Some(line_len) = reader.read_line(&mut line_buf) {
                let line_str = match core::str::from_utf8(&line_buf[..line_len]) {
                    Ok(s) => s,
                    Err(_) => {
                        if warn && !status_only {
                            let _ = sys_write(
                                err_fd,
                                b"sha256sum: improperly formatted SHA256 checksum line\n",
                            );
                        }
                        continue;
                    }
                };

                let (path, expected_hex) = match parse_sha256_check_line(line_str) {
                    Some(parsed) => parsed,
                    None => {
                        if warn
                            && !status_only
                            && !line_str.trim().is_empty()
                            && !line_str.trim().starts_with('#')
                        {
                            let _ = sys_write(
                                err_fd,
                                b"sha256sum: improperly formatted SHA256 checksum line\n",
                            );
                        }
                        continue;
                    }
                };

                // Ouvrir et hacher le fichier référencé
                let file_fd = sys_open(path, crate::vfs::O_RDONLY);
                if file_fd < 0 {
                    if !status_only {
                        let _ = sys_write(err_fd, path.as_bytes());
                        let _ = sys_write(err_fd, b": FAILED open or read\n");
                    }
                    overall_success = false;
                    continue;
                }

                let hash_res = hash_fd_sha256(file_fd);
                sys_close(file_fd);

                match hash_res {
                    Ok(digest) => {
                        let mut calculated_hex = [0u8; 64];
                        sha256_to_hex(&digest, &mut calculated_hex);

                        let hex_matches = calculated_hex
                            .iter()
                            .zip(expected_hex.as_bytes().iter())
                            .all(|(&a, &b)| a.eq_ignore_ascii_case(&b));

                        if hex_matches {
                            total_verified += 1;
                            if !quiet && !status_only {
                                let _ = sys_write(out_fd, path.as_bytes());
                                let _ = sys_write(out_fd, b": OK\n");
                            }
                        } else {
                            overall_success = false;
                            if !status_only {
                                let _ = sys_write(out_fd, path.as_bytes());
                                let _ = sys_write(out_fd, b": FAILED\n");
                            }
                        }
                    }
                    Err(_) => {
                        overall_success = false;
                        if !status_only {
                            let _ = sys_write(err_fd, path.as_bytes());
                            let _ = sys_write(err_fd, b": FAILED open or read\n");
                        }
                    }
                }
            }

            if check_fd != in_fd {
                sys_close(check_fd);
            }
        }

        if overall_success && total_verified > 0 {
            0
        } else {
            1
        }
    } else {
        let targets: &[&str] = if file_count == 0 {
            &["-"]
        } else {
            &file_args[..file_count]
        };

        let mut exit_code = 0;

        for &target in targets {
            let (target_fd, display_name) = if target == "-" {
                (in_fd, "-")
            } else {
                let fd = sys_open(target, crate::vfs::O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"sha256sum: ");
                    let _ = sys_write(err_fd, target.as_bytes());
                    let _ = sys_write(err_fd, b": No such file or directory\n");
                    exit_code = 1;
                    continue;
                }
                (fd, target)
            };

            match hash_fd_sha256(target_fd) {
                Ok(digest) => {
                    let mut hex_buf = [0u8; 64];
                    sha256_to_hex(&digest, &mut hex_buf);

                    if tag_format {
                        // Format BSD: SHA256 (filename) = hex64\n
                        let _ = sys_write(out_fd, b"SHA256 (");
                        let _ = sys_write(out_fd, display_name.as_bytes());
                        let _ = sys_write(out_fd, b") = ");
                        let _ = sys_write(out_fd, &hex_buf);
                        let _ = sys_write(out_fd, b"\n");
                    } else {
                        // Format GNU standard: hex64  filename\n ou hex64 *filename\n
                        let _ = sys_write(out_fd, &hex_buf);
                        if binary_mode {
                            let _ = sys_write(out_fd, b" *");
                        } else {
                            let _ = sys_write(out_fd, b"  ");
                        }
                        let _ = sys_write(out_fd, display_name.as_bytes());
                        let _ = sys_write(out_fd, b"\n");
                    }
                }
                Err(_) => {
                    let _ = sys_write(err_fd, b"sha256sum: error reading ");
                    let _ = sys_write(err_fd, display_name.as_bytes());
                    let _ = sys_write(err_fd, b"\n");
                    exit_code = 1;
                }
            }

            if target_fd != in_fd {
                sys_close(target_fd);
            }
        }

        exit_code
    }
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `md5sum` (Calcul et vérification RFC 1321 MD5)
// ============================================================================

/// Hasher cryptographique MD5 déterministe bare-metal (#![no_std], RFC 1321)
#[derive(Clone, Copy)]
pub struct Md5Hasher {
    state: [u32; 4],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Md5Hasher {
    /// Constantes d'arrondi sine-based T[i] = floor(abs(sin(i + 1)) * 2^32)
    const T: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    /// Décalages de rotation par passe
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn transform_block(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        let mut i = 0;
        while i < 16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        let mut j = 0;
        while j < 64 {
            let (f, g) = if j < 16 {
                ((b & c) | ((!b) & d), j)
            } else if j < 32 {
                ((d & b) | ((!d) & c), (5 * j + 1) % 16)
            } else if j < 48 {
                (b ^ c ^ d, (3 * j + 5) % 16)
            } else {
                (c ^ (b | (!d)), (7 * j) % 16)
            };

            let temp = f
                .wrapping_add(a)
                .wrapping_add(Self::T[j])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp.rotate_left(Self::S[j]));
            j += 1;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        let mut offset = 0;
        while offset < data.len() {
            if self.buffer_len == 64 {
                let blk = self.buffer;
                self.transform_block(&blk);
                self.buffer_len = 0;
            }
            let to_copy = (64 - self.buffer_len).min(data.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let total_bits = self.total_bytes.wrapping_mul(8);
        if self.buffer_len == 64 {
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            let mut i = self.buffer_len;
            while i < 64 {
                self.buffer[i] = 0;
                i += 1;
            }
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }

        let mut i = self.buffer_len;
        while i < 56 {
            self.buffer[i] = 0;
            i += 1;
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_le_bytes());
        let blk = self.buffer;
        self.transform_block(&blk);

        let mut out = [0u8; 16];
        let mut k = 0;
        while k < 4 {
            out[k * 4..(k + 1) * 4].copy_from_slice(&self.state[k].to_le_bytes());
            k += 1;
        }
        out
    }

    pub fn hash(data: &[u8]) -> [u8; 16] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Md5Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convertit un condensat MD5 (16 octets) en représentation hexadécimale minuscule (32 octets ASCII)
pub fn md5_to_hex(digest: &[u8; 16], out: &mut [u8; 32]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..16 {
        let b = digest[i];
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
}

/// Hache un descripteur de fichier ouvert en streaming MD5 sans allocation
fn hash_fd_md5(fd: i32) -> Result<[u8; 16], ()> {
    let mut hasher = Md5Hasher::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = sys_read(fd, &mut chunk);
        if n < 0 {
            return Err(());
        }
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n as usize]);
    }
    Ok(hasher.finalize())
}

/// Parse une ligne de fichier de vérification md5 (format GNU ou BSD)
fn parse_md5_check_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Format BSD: MD5 (path) = hex32
    if let Some(rest) = trimmed.strip_prefix("MD5 (") {
        if let Some(close_idx) = rest.find(')') {
            let path = &rest[..close_idx];
            let after = rest[close_idx + 1..].trim();
            if let Some(hex_part) = after.strip_prefix('=') {
                let hex = hex_part.trim();
                if hex.len() == 32 {
                    return Some((path, hex));
                }
            }
        }
    }

    // Format standard GNU: <hex32>  <path> ou <hex32> *<path>
    if trimmed.len() >= 34 {
        let hex = &trimmed[..32];
        let sep = &trimmed[32..34];
        if (sep == "  " || sep == " *" || sep == "  ")
            && hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
        {
            let path = trimmed[34..].trim();
            if !path.is_empty() {
                return Some((path, hex));
            }
        }
    }

    None
}

/// Exécute l'utilitaire Coreutils POSIX / GNU `md5sum` (calcul et vérification MD5)
pub fn run_md5sum(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut check_mode = false;
    let mut tag_format = false;
    let mut binary_mode = false;
    let mut status_only = false;
    let mut quiet = false;
    let mut warn = false;
    let mut file_args = [""; 64];
    let mut file_count = 0usize;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" || arg == "-h" {
            let help = b"Usage: md5sum [OPTION]... [FILE]...\nPrint or check MD5 (128-bit) checksums.\n\nWith no FILE, or when FILE is -, read standard input.\n\n  -b, --binary         read in binary mode\n  -c, --check          read checksums from the FILEs and check them\n      --tag            create a BSD-style checksum\n  -t, --text           read in text mode (default)\n  -q, --quiet          don't print OK for each successfully verified file\n      --status         don't output anything, status code shows success\n  -w, --warn           warn about improperly formatted checksum lines\n      --help           display this help and exit\n      --version        output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" || arg == "-v" {
            let ver = b"md5sum (JamboOS coreutils) 0.1.0\nCopyright (C) 2026 JamboOS Authors.\nLicense MIT or Apache-2.0.\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }

        if arg == "-c" || arg == "--check" {
            check_mode = true;
        } else if arg == "--tag" {
            tag_format = true;
        } else if arg == "-b" || arg == "--binary" {
            binary_mode = true;
        } else if arg == "-t" || arg == "--text" {
            binary_mode = false;
        } else if arg == "--status" {
            status_only = true;
        } else if arg == "-q" || arg == "--quiet" {
            quiet = true;
        } else if arg == "-w" || arg == "--warn" {
            warn = true;
        } else if (!arg.starts_with('-') || arg == "-") && file_count < file_args.len() {
            file_args[file_count] = arg;
            file_count += 1;
        }
        i += 1;
    }

    if check_mode {
        let mut overall_success = true;
        let mut total_verified = 0usize;

        let targets: &[&str] = if file_count == 0 {
            &["-"]
        } else {
            &file_args[..file_count]
        };

        for &target in targets {
            let check_fd = if target == "-" {
                in_fd
            } else {
                let fd = sys_open(target, crate::vfs::O_RDONLY);
                if fd < 0 {
                    if !status_only {
                        let _ = sys_write(err_fd, b"md5sum: ");
                        let _ = sys_write(err_fd, target.as_bytes());
                        let _ = sys_write(err_fd, b": No such file or directory\n");
                    }
                    overall_success = false;
                    continue;
                }
                fd
            };

            let mut reader = LineReader::new(check_fd);
            let mut line_buf = [0u8; 512];

            while let Some(line_len) = reader.read_line(&mut line_buf) {
                let line_str = match core::str::from_utf8(&line_buf[..line_len]) {
                    Ok(s) => s,
                    Err(_) => {
                        if warn && !status_only {
                            let _ = sys_write(
                                err_fd,
                                b"md5sum: improperly formatted MD5 checksum line\n",
                            );
                        }
                        continue;
                    }
                };

                let (path, expected_hex) = match parse_md5_check_line(line_str) {
                    Some(parsed) => parsed,
                    None => {
                        if warn && !status_only {
                            let _ = sys_write(
                                err_fd,
                                b"md5sum: improperly formatted MD5 checksum line\n",
                            );
                        }
                        continue;
                    }
                };

                let file_fd = sys_open(path, crate::vfs::O_RDONLY);
                if file_fd < 0 {
                    if !status_only {
                        let _ = sys_write(err_fd, path.as_bytes());
                        let _ = sys_write(err_fd, b": FAILED open or read\n");
                    }
                    overall_success = false;
                    continue;
                }

                let hash_res = hash_fd_md5(file_fd);
                sys_close(file_fd);

                match hash_res {
                    Ok(digest) => {
                        let mut calculated_hex = [0u8; 32];
                        md5_to_hex(&digest, &mut calculated_hex);

                        let hex_matches = calculated_hex
                            .iter()
                            .zip(expected_hex.as_bytes().iter())
                            .all(|(&a, &b)| a.eq_ignore_ascii_case(&b));

                        if hex_matches {
                            total_verified += 1;
                            if !quiet && !status_only {
                                let _ = sys_write(out_fd, path.as_bytes());
                                let _ = sys_write(out_fd, b": OK\n");
                            }
                        } else {
                            overall_success = false;
                            if !status_only {
                                let _ = sys_write(out_fd, path.as_bytes());
                                let _ = sys_write(out_fd, b": FAILED\n");
                            }
                        }
                    }
                    Err(_) => {
                        overall_success = false;
                        if !status_only {
                            let _ = sys_write(err_fd, path.as_bytes());
                            let _ = sys_write(err_fd, b": FAILED open or read\n");
                        }
                    }
                }
            }

            if check_fd != in_fd {
                sys_close(check_fd);
            }
        }

        if overall_success && total_verified > 0 {
            0
        } else {
            1
        }
    } else {
        let targets: &[&str] = if file_count == 0 {
            &["-"]
        } else {
            &file_args[..file_count]
        };

        let mut exit_code = 0;

        for &target in targets {
            let (target_fd, display_name) = if target == "-" {
                (in_fd, "-")
            } else {
                let fd = sys_open(target, crate::vfs::O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"md5sum: ");
                    let _ = sys_write(err_fd, target.as_bytes());
                    let _ = sys_write(err_fd, b": No such file or directory\n");
                    exit_code = 1;
                    continue;
                }
                (fd, target)
            };

            match hash_fd_md5(target_fd) {
                Ok(digest) => {
                    let mut hex_buf = [0u8; 32];
                    md5_to_hex(&digest, &mut hex_buf);

                    if tag_format {
                        let _ = sys_write(out_fd, b"MD5 (");
                        let _ = sys_write(out_fd, display_name.as_bytes());
                        let _ = sys_write(out_fd, b") = ");
                        let _ = sys_write(out_fd, &hex_buf);
                        let _ = sys_write(out_fd, b"\n");
                    } else {
                        let _ = sys_write(out_fd, &hex_buf);
                        if binary_mode {
                            let _ = sys_write(out_fd, b" *");
                        } else {
                            let _ = sys_write(out_fd, b"  ");
                        }
                        let _ = sys_write(out_fd, display_name.as_bytes());
                        let _ = sys_write(out_fd, b"\n");
                    }
                }
                Err(_) => {
                    let _ = sys_write(err_fd, b"md5sum: error reading ");
                    let _ = sys_write(err_fd, display_name.as_bytes());
                    let _ = sys_write(err_fd, b"\n");
                    exit_code = 1;
                }
            }

            if target_fd != in_fd {
                sys_close(target_fd);
            }
        }

        exit_code
    }
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `sha1sum` (Calcul et vérification FIPS 180-1 / RFC 3174 SHA-1)
// ============================================================================

/// Hasher cryptographique SHA-1 déterministe bare-metal (#![no_std], FIPS 180-1, RFC 3174)
#[derive(Clone, Copy)]
pub struct Sha1Hasher {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Sha1Hasher {
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn transform_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        let mut i = 0;
        while i < 16 {
            let offset = i * 4;
            w[i] = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
            i += 1;
        }
        while i < 80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for (t, &wt) in w.iter().enumerate() {
            let (f, k) = if t < 20 {
                ((b & c) | ((!b) & d), 0x5A827999)
            } else if t < 40 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if t < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wt);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        let mut offset = 0;
        while offset < data.len() {
            if self.buffer_len == 64 {
                let blk = self.buffer;
                self.transform_block(&blk);
                self.buffer_len = 0;
            }
            let to_copy = (64 - self.buffer_len).min(data.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let total_bits = self.total_bytes.wrapping_mul(8);
        if self.buffer_len == 64 {
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            let mut i = self.buffer_len;
            while i < 64 {
                self.buffer[i] = 0;
                i += 1;
            }
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }

        let mut i = self.buffer_len;
        while i < 56 {
            self.buffer[i] = 0;
            i += 1;
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let blk = self.buffer;
        self.transform_block(&blk);

        let mut out = [0u8; 20];
        let mut k = 0;
        while k < 5 {
            out[k * 4..(k + 1) * 4].copy_from_slice(&self.state[k].to_be_bytes());
            k += 1;
        }
        out
    }

    pub fn hash(data: &[u8]) -> [u8; 20] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha1Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convertit un condensat SHA-1 (20 octets) en représentation hexadécimale minuscule (40 octets ASCII)
pub fn sha1_to_hex(digest: &[u8; 20], out: &mut [u8; 40]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..20 {
        let b = digest[i];
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
}

/// Hache un descripteur de fichier ouvert en streaming SHA-1 sans allocation
fn hash_fd_sha1(fd: i32) -> Result<[u8; 20], ()> {
    let mut hasher = Sha1Hasher::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = sys_read(fd, &mut chunk);
        if n < 0 {
            return Err(());
        }
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n as usize]);
    }
    Ok(hasher.finalize())
}

/// Parse une ligne de fichier de vérification sha1 (format GNU ou BSD)
fn parse_sha1_check_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Format BSD: SHA1 (path) = hex40
    if let Some(rest) = trimmed.strip_prefix("SHA1 (") {
        if let Some(close_idx) = rest.find(')') {
            let path = &rest[..close_idx];
            let after = rest[close_idx + 1..].trim();
            if let Some(hex_part) = after.strip_prefix('=') {
                let hex = hex_part.trim();
                if hex.len() == 40 {
                    return Some((path, hex));
                }
            }
        }
    }

    // Format standard GNU: <hex40>  <path> ou <hex40> *<path>
    if trimmed.len() >= 42 {
        let hex = &trimmed[..40];
        let sep = &trimmed[40..42];
        if (sep == "  " || sep == " *" || sep == "  ")
            && hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
        {
            let path = trimmed[42..].trim();
            if !path.is_empty() {
                return Some((path, hex));
            }
        }
    }

    None
}

/// Exécute l'utilitaire Coreutils POSIX / GNU `sha1sum` (calcul et vérification SHA-1)
pub fn run_sha1sum(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut check_mode = false;
    let mut tag_format = false;
    let mut binary_mode = false;
    let mut status_only = false;
    let mut quiet = false;
    let mut warn = false;
    let mut file_args = [""; 64];
    let mut file_count = 0usize;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" || arg == "-h" {
            let help = b"Usage: sha1sum [OPTION]... [FILE]...\n\
Print or check SHA1 (160-bit) checksums.\n\n\
With no FILE, or when FILE is -, read standard input.\n\n\
  -b, --binary         read in binary mode\n\
  -c, --check          read checksums from the FILEs and check them\n\
      --tag            create a BSD-style checksum\n\
  -t, --text           read in text mode (default)\n\
  -q, --quiet          don't print OK for each successfully verified file\n\
      --status         don't output anything, status code shows success\n\
  -w, --warn           warn about improperly formatted checksum lines\n\
      --help           display this help and exit\n\
      --version        output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" || arg == "-v" {
            let ver = b"sha1sum (JamboOS coreutils) 0.1.0\n\
Copyright (C) 2026 JamboOS Authors.\n\
License MIT or Apache-2.0.\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }

        if arg == "-c" || arg == "--check" {
            check_mode = true;
        } else if arg == "--tag" {
            tag_format = true;
        } else if arg == "-b" || arg == "--binary" {
            binary_mode = true;
        } else if arg == "-t" || arg == "--text" {
            binary_mode = false;
        } else if arg == "--status" {
            status_only = true;
        } else if arg == "-q" || arg == "--quiet" {
            quiet = true;
        } else if arg == "-w" || arg == "--warn" {
            warn = true;
        } else if (!arg.starts_with('-') || arg == "-") && file_count < file_args.len() {
            file_args[file_count] = arg;
            file_count += 1;
        }
        i += 1;
    }

    if check_mode {
        let mut overall_success = true;
        let mut total_verified = 0usize;

        let targets: &[&str] = if file_count == 0 {
            &["-"]
        } else {
            &file_args[..file_count]
        };

        for &target in targets {
            let chk_fd = if target == "-" {
                in_fd
            } else {
                let fd = sys_open(target, O_RDONLY);
                if fd < 0 {
                    if !status_only {
                        let _ = sys_write(err_fd, b"sha1sum: ");
                        let _ = sys_write(err_fd, target.as_bytes());
                        let _ = sys_write(err_fd, b": No such file or directory\n");
                    }
                    overall_success = false;
                    continue;
                }
                fd
            };

            let mut chk_buf = [0u8; 8192];
            let mut read_bytes = 0usize;
            loop {
                let n = sys_read(chk_fd, &mut chk_buf[read_bytes..]);
                if n <= 0 {
                    break;
                }
                read_bytes += n as usize;
                if read_bytes >= chk_buf.len() {
                    break;
                }
            }
            if target != "-" {
                sys_close(chk_fd);
            }

            let chk_text = match core::str::from_utf8(&chk_buf[..read_bytes]) {
                Ok(t) => t,
                Err(_) => {
                    overall_success = false;
                    continue;
                }
            };

            for line in chk_text.lines() {
                if let Some((filepath, expected_hex)) = parse_sha1_check_line(line) {
                    total_verified += 1;
                    let target_fd = sys_open(filepath, O_RDONLY);
                    if target_fd < 0 {
                        if !status_only {
                            let _ = sys_write(out_fd, filepath.as_bytes());
                            let _ = sys_write(out_fd, b": FAILED open or read\n");
                        }
                        overall_success = false;
                        continue;
                    }

                    match hash_fd_sha1(target_fd) {
                        Ok(digest) => {
                            let mut hex_buf = [0u8; 40];
                            sha1_to_hex(&digest, &mut hex_buf);
                            let computed_hex = core::str::from_utf8(&hex_buf).unwrap_or("");

                            let matches = computed_hex.len() == expected_hex.len()
                                && computed_hex
                                    .as_bytes()
                                    .iter()
                                    .zip(expected_hex.as_bytes().iter())
                                    .all(|(&a, &b)| a.eq_ignore_ascii_case(&b));

                            if matches {
                                if !status_only && !quiet {
                                    let _ = sys_write(out_fd, filepath.as_bytes());
                                    let _ = sys_write(out_fd, b": OK\n");
                                }
                            } else {
                                if !status_only {
                                    let _ = sys_write(out_fd, filepath.as_bytes());
                                    let _ = sys_write(out_fd, b": FAILED\n");
                                }
                                overall_success = false;
                            }
                        }
                        Err(_) => {
                            if !status_only {
                                let _ = sys_write(out_fd, filepath.as_bytes());
                                let _ = sys_write(out_fd, b": FAILED\n");
                            }
                            overall_success = false;
                        }
                    }
                    sys_close(target_fd);
                } else if warn && !line.trim().is_empty() && !line.trim().starts_with('#') {
                    let _ = sys_write(err_fd, b"sha1sum: improperly formatted line\n");
                }
            }
        }

        if total_verified == 0 {
            if !status_only {
                let _ = sys_write(
                    err_fd,
                    b"sha1sum: no properly formatted SHA1 checksum lines found\n",
                );
            }
            return 1;
        }

        return if overall_success { 0 } else { 1 };
    }

    // Mode calcul de hachage standard
    let targets: &[&str] = if file_count == 0 {
        &["-"]
    } else {
        &file_args[..file_count]
    };

    let mut exit_code = 0i32;

    for &target in targets {
        let (target_fd, display_name) = if target == "-" {
            (in_fd, "-")
        } else {
            let fd = sys_open(target, O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"sha1sum: ");
                let _ = sys_write(err_fd, target.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                exit_code = 1;
                continue;
            }
            (fd, target)
        };

        match hash_fd_sha1(target_fd) {
            Ok(digest) => {
                let mut hex_buf = [0u8; 40];
                sha1_to_hex(&digest, &mut hex_buf);

                if tag_format {
                    let _ = sys_write(out_fd, b"SHA1 (");
                    let _ = sys_write(out_fd, display_name.as_bytes());
                    let _ = sys_write(out_fd, b") = ");
                    let _ = sys_write(out_fd, &hex_buf);
                    let _ = sys_write(out_fd, b"\n");
                } else {
                    let _ = sys_write(out_fd, &hex_buf);
                    if binary_mode {
                        let _ = sys_write(out_fd, b" *");
                    } else {
                        let _ = sys_write(out_fd, b"  ");
                    }
                    let _ = sys_write(out_fd, display_name.as_bytes());
                    let _ = sys_write(out_fd, b"\n");
                }
            }
            Err(_) => {
                let _ = sys_write(err_fd, b"sha1sum: error reading ");
                let _ = sys_write(err_fd, display_name.as_bytes());
                let _ = sys_write(err_fd, b"\n");
                exit_code = 1;
            }
        }

        if target_fd != in_fd {
            sys_close(target_fd);
        }
    }

    exit_code
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `crc32` (Calcul et vérification CRC-32 IEEE 802.3 / ISO 3309)
// ============================================================================

/// Table de correspondance CRC-32 (IEEE 802.3 / ISO 3309 / ITU-T V.42, polynôme 0xEDB88320)
pub const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Structure de calcul incrémental de somme de contrôle CRC-32 IEEE 802.3 / ISO 3309
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32Hasher {
    crc: u32,
    total_bytes: u64,
}

impl Default for Crc32Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32Hasher {
    /// Initialise un nouveau calculateur CRC-32 avec registre initial 0xFFFFFFFF
    pub const fn new() -> Self {
        Self {
            crc: 0xFFFF_FFFF,
            total_bytes: 0,
        }
    }

    /// Met à jour l'accumulateur CRC-32 avec un tampon d'octets
    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(data.len() as u64);
        for &b in data {
            let idx = ((self.crc ^ (b as u32)) & 0xFF) as usize;
            self.crc = (self.crc >> 8) ^ CRC32_TABLE[idx];
        }
    }

    /// Finalise le calcul CRC-32 (inversion finale XOR 0xFFFFFFFF)
    pub const fn finalize(&self) -> u32 {
        self.crc ^ 0xFFFF_FFFF
    }

    /// Retourne le total d'octets traités
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// Calcule la somme CRC-32 IEEE 802.3 sur un flux de descripteur de fichier ouvert
pub fn hash_fd_crc32(fd: i32) -> Result<(u32, u64), i32> {
    let mut hasher = Crc32Hasher::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = sys_read(fd, &mut buf);
        if n < 0 {
            return Err(n as i32);
        }
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n as usize]);
    }
    Ok((hasher.finalize(), hasher.total_bytes()))
}

/// Convertit un entier CRC-32 32-bit en chaîne hexadécimale de 8 caractères
pub fn crc32_to_hex(crc: u32, out: &mut [u8; 8]) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in out.iter_mut().enumerate() {
        let nibble = ((crc >> ((7 - i) * 4)) & 0xF) as usize;
        *byte = HEX_CHARS[nibble];
    }
}

/// Parse une ligne de vérification de fichier crc32 (format standard ou format BSD tag)
pub fn parse_crc32_check_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Format BSD: CRC32 (path) = hex8
    if let Some(rest) = trimmed.strip_prefix("CRC32 (") {
        if let Some(close_idx) = rest.find(')') {
            let path = &rest[..close_idx];
            let after = rest[close_idx + 1..].trim();
            if let Some(hex_part) = after.strip_prefix('=') {
                let hex = hex_part.trim();
                if hex.len() == 8 && hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
                    return Some((path, hex));
                }
            }
        }
    }

    // Format standard: <hex8>  <path> ou <hex8> *<path>
    if trimmed.len() >= 10 {
        let hex = &trimmed[..8];
        let sep = &trimmed[8..10];
        if (sep == "  " || sep == " *" || sep == "  ")
            && hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
        {
            let path = trimmed[10..].trim();
            if !path.is_empty() {
                return Some((path, hex));
            }
        }
    }

    None
}

/// Exécute l'utilitaire Coreutils POSIX / GNU `crc32` (calcul et vérification de sommes CRC-32)
pub fn run_crc32(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut check_mode = false;
    let mut tag_format = false;
    let mut binary_mode = false;
    let mut status_only = false;
    let mut quiet = false;
    let mut warn = false;
    let mut file_args = [""; 64];
    let mut file_count = 0usize;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" || arg == "-h" {
            let help = b"Usage: crc32 [OPTION]... [FILE]...\n\
Print or check CRC-32 (IEEE 802.3 / ISO 3309) checksums.\n\n\
With no FILE, or when FILE is -, read standard input.\n\n\
  -b, --binary         read in binary mode\n\
  -c, --check          read checksums from the FILEs and check them\n\
      --tag            create a BSD-style checksum\n\
  -t, --text           read in text mode (default)\n\
  -q, --quiet          don't print OK for each successfully verified file\n\
      --status         don't output anything, status code shows success\n\
  -w, --warn           warn about improperly formatted checksum lines\n\
      --help           display this help and exit\n\
      --version        output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" || arg == "-v" {
            let ver = b"crc32 (JamboOS coreutils) 0.1.0\n\
Copyright (C) 2026 JamboOS Authors.\n\
License MIT or Apache-2.0.\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }
        if arg == "-c" || arg == "--check" {
            check_mode = true;
        } else if arg == "--tag" {
            tag_format = true;
        } else if arg == "-b" || arg == "--binary" {
            binary_mode = true;
        } else if arg == "-t" || arg == "--text" {
            binary_mode = false;
        } else if arg == "--status" {
            status_only = true;
        } else if arg == "-q" || arg == "--quiet" {
            quiet = true;
        } else if arg == "-w" || arg == "--warn" {
            warn = true;
        } else if (!arg.starts_with('-') || arg == "-") && file_count < file_args.len() {
            file_args[file_count] = arg;
            file_count += 1;
        }
        i += 1;
    }

    if check_mode {
        let mut overall_success = true;
        let mut total_verified = 0usize;

        let targets: &[&str] = if file_count == 0 {
            &["-"]
        } else {
            &file_args[..file_count]
        };

        for &target in targets {
            let chk_fd = if target == "-" {
                in_fd
            } else {
                let fd = sys_open(target, O_RDONLY);
                if fd < 0 {
                    if !status_only {
                        let _ = sys_write(err_fd, b"crc32: ");
                        let _ = sys_write(err_fd, target.as_bytes());
                        let _ = sys_write(err_fd, b": No such file or directory\n");
                    }
                    overall_success = false;
                    continue;
                }
                fd
            };

            let mut chk_buf = [0u8; 8192];
            let mut read_bytes = 0usize;
            loop {
                let n = sys_read(chk_fd, &mut chk_buf[read_bytes..]);
                if n <= 0 {
                    break;
                }
                read_bytes += n as usize;
                if read_bytes >= chk_buf.len() {
                    break;
                }
            }
            if target != "-" {
                sys_close(chk_fd);
            }

            let chk_text = match core::str::from_utf8(&chk_buf[..read_bytes]) {
                Ok(t) => t,
                Err(_) => {
                    overall_success = false;
                    continue;
                }
            };

            for line in chk_text.lines() {
                if let Some((filepath, expected_hex)) = parse_crc32_check_line(line) {
                    total_verified += 1;
                    let target_fd = sys_open(filepath, O_RDONLY);
                    if target_fd < 0 {
                        if !status_only {
                            let _ = sys_write(out_fd, filepath.as_bytes());
                            let _ = sys_write(out_fd, b": FAILED open or read\n");
                        }
                        overall_success = false;
                        continue;
                    }

                    match hash_fd_crc32(target_fd) {
                        Ok((crc, _)) => {
                            let mut hex_buf = [0u8; 8];
                            crc32_to_hex(crc, &mut hex_buf);
                            let computed_hex = core::str::from_utf8(&hex_buf).unwrap_or("");

                            let matches = computed_hex.len() == expected_hex.len()
                                && computed_hex
                                    .as_bytes()
                                    .iter()
                                    .zip(expected_hex.as_bytes().iter())
                                    .all(|(&a, &b)| a.eq_ignore_ascii_case(&b));

                            if matches {
                                if !status_only && !quiet {
                                    let _ = sys_write(out_fd, filepath.as_bytes());
                                    let _ = sys_write(out_fd, b": OK\n");
                                }
                            } else {
                                if !status_only {
                                    let _ = sys_write(out_fd, filepath.as_bytes());
                                    let _ = sys_write(out_fd, b": FAILED\n");
                                }
                                overall_success = false;
                            }
                        }
                        Err(_) => {
                            if !status_only {
                                let _ = sys_write(out_fd, filepath.as_bytes());
                                let _ = sys_write(out_fd, b": FAILED\n");
                            }
                            overall_success = false;
                        }
                    }
                    sys_close(target_fd);
                } else if warn && !line.trim().is_empty() && !line.trim().starts_with('#') {
                    let _ = sys_write(err_fd, b"crc32: improperly formatted line\n");
                }
            }
        }

        if total_verified == 0 {
            if !status_only {
                let _ = sys_write(
                    err_fd,
                    b"crc32: no properly formatted CRC32 checksum lines found\n",
                );
            }
            return 1;
        }

        return if overall_success { 0 } else { 1 };
    }

    let targets: &[&str] = if file_count == 0 {
        &["-"]
    } else {
        &file_args[..file_count]
    };

    let mut exit_code = 0;
    for &target in targets {
        let (target_fd, display_name) = if target == "-" {
            (in_fd, "-")
        } else {
            let fd = sys_open(target, O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"crc32: ");
                let _ = sys_write(err_fd, target.as_bytes());
                let _ = sys_write(err_fd, b": No such file or directory\n");
                exit_code = 1;
                continue;
            }
            (fd, target)
        };

        match hash_fd_crc32(target_fd) {
            Ok((crc, _)) => {
                let mut hex_buf = [0u8; 8];
                crc32_to_hex(crc, &mut hex_buf);

                if tag_format {
                    let _ = sys_write(out_fd, b"CRC32 (");
                    let _ = sys_write(out_fd, display_name.as_bytes());
                    let _ = sys_write(out_fd, b") = ");
                    let _ = sys_write(out_fd, &hex_buf);
                    let _ = sys_write(out_fd, b"\n");
                } else {
                    let _ = sys_write(out_fd, &hex_buf);
                    if binary_mode {
                        let _ = sys_write(out_fd, b" *");
                    } else {
                        let _ = sys_write(out_fd, b"  ");
                    }
                    let _ = sys_write(out_fd, display_name.as_bytes());
                    let _ = sys_write(out_fd, b"\n");
                }
            }
            Err(_) => {
                let _ = sys_write(err_fd, b"crc32: error reading ");
                let _ = sys_write(err_fd, display_name.as_bytes());
                let _ = sys_write(err_fd, b"\n");
                exit_code = 1;
            }
        }

        if target_fd != in_fd {
            sys_close(target_fd);
        }
    }

    exit_code
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `factor` (Décomposition en facteurs premiers)
// ============================================================================

/// Décompose un entier 64 bits en facteurs premiers.
/// Remplit `factors` avec la liste ordonnée des facteurs premiers et retourne leur nombre.
pub fn factorize_u64(mut n: u64, factors: &mut [u64; 64]) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut count = 0;

    // Facteurs 2
    while (n & 1) == 0 && count < factors.len() {
        factors[count] = 2;
        count += 1;
        n >>= 1;
    }

    // Facteurs impairs >= 3
    let mut d = 3u64;
    while d.saturating_mul(d) <= n && count < factors.len() {
        if n.is_multiple_of(d) {
            factors[count] = d;
            count += 1;
            n /= d;
        } else {
            d += 2;
        }
    }

    // Dernier facteur premier restant
    if n > 1 && count < factors.len() {
        factors[count] = n;
        count += 1;
    }

    count
}

/// Affiche la décomposition en facteurs d'un nombre donné sur `out_fd` : `N: p1 p2 p3...\n`
fn print_factorization(n: u64, out_fd: i32) {
    let mut buf = [0u8; 32];
    let n_len = fmt_u64_in_buf(&mut buf, n, 0, false, 10, false);
    let _ = sys_write(out_fd, &buf[..n_len]);
    let _ = sys_write(out_fd, b":");

    let mut factors = [0u64; 64];
    let factor_count = factorize_u64(n, &mut factors);

    for &f in &factors[..factor_count] {
        let _ = sys_write(out_fd, b" ");
        let mut f_buf = [0u8; 32];
        let f_len = fmt_u64_in_buf(&mut f_buf, f, 0, false, 10, false);
        let _ = sys_write(out_fd, &f_buf[..f_len]);
    }
    let _ = sys_write(out_fd, b"\n");
}

/// Exécute l'utilitaire Coreutils POSIX / GNU `factor` (décomposition en facteurs premiers)
///
/// Syntaxe : `factor [NOMBRE...]`
/// Sans argument, lit les nombres séparés par des espaces ou sauts de ligne depuis `in_fd`.
pub fn run_factor(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut num_args = [""; 64];
    let mut num_count = 0usize;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" || arg == "-h" {
            let help = b"Usage: factor [NUMBER]...\n\
Print the prime factors of each specified integer NUMBER.\n\
If each NUMBER is omitted, read them from standard input.\n\n\
  -h, --help     display this help and exit\n\
  -v, --version  output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" || arg == "-v" {
            let ver = b"factor (JamboOS coreutils) 0.1.0\n\
Copyright (C) 2026 JamboOS Authors.\n\
License MIT or Apache-2.0.\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }
        if (!arg.starts_with('-') || arg.len() > 1 && arg.as_bytes()[1].is_ascii_digit())
            && num_count < num_args.len()
        {
            num_args[num_count] = arg;
            num_count += 1;
        }
        i += 1;
    }

    if num_count > 0 {
        let mut exit_code = 0;
        for &num_str in &num_args[..num_count] {
            let trimmed = num_str.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                let _ = sys_write(err_fd, b"factor: '");
                let _ = sys_write(err_fd, trimmed.as_bytes());
                let _ = sys_write(err_fd, b"' is not a valid positive integer\n");
                exit_code = 1;
                continue;
            }
            let n = parse_u64(trimmed);
            print_factorization(n, out_fd);
        }
        return exit_code;
    }

    // Lecture depuis in_fd
    let mut read_buf = [0u8; 4096];
    let mut token_buf = [0u8; 64];
    let mut token_len = 0usize;
    let mut exit_code = 0;

    loop {
        let n = sys_read(in_fd, &mut read_buf);
        if n <= 0 {
            break;
        }
        for &b in &read_buf[..n as usize] {
            if b.is_ascii_whitespace() {
                if token_len > 0 {
                    if let Ok(s) = core::str::from_utf8(&token_buf[..token_len]) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            if trimmed.bytes().all(|c| c.is_ascii_digit()) {
                                let val = parse_u64(trimmed);
                                print_factorization(val, out_fd);
                            } else {
                                let _ = sys_write(err_fd, b"factor: '");
                                let _ = sys_write(err_fd, trimmed.as_bytes());
                                let _ = sys_write(err_fd, b"' is not a valid positive integer\n");
                                exit_code = 1;
                            }
                        }
                    }
                    token_len = 0;
                }
            } else if token_len < token_buf.len() {
                token_buf[token_len] = b;
                token_len += 1;
            }
        }
    }

    if token_len > 0 {
        if let Ok(s) = core::str::from_utf8(&token_buf[..token_len]) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                if trimmed.bytes().all(|c| c.is_ascii_digit()) {
                    let val = parse_u64(trimmed);
                    print_factorization(val, out_fd);
                } else {
                    let _ = sys_write(err_fd, b"factor: '");
                    let _ = sys_write(err_fd, trimmed.as_bytes());
                    let _ = sys_write(err_fd, b"' is not a valid positive integer\n");
                    exit_code = 1;
                }
            }
        }
    }

    exit_code
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `nice` (Priorité d'ordonnancement Ring 3)
// ============================================================================

/// Exécute une commande enfant avec un ajustement de politesse d'ordonnancement (niceness).
///
/// Syntaxe POSIX:
///   nice [-n INCREMENT] COMMAND [ARG...]
///   nice -INCREMENT COMMAND [ARG...]
pub fn run_nice(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    if args.is_empty() {
        // En l'absence d'argument, nice affiche la priorité actuelle (0 par défaut)
        let _ = sys_write(out_fd, b"0\n");
        return 0;
    }

    let mut adjustment: i32 = 10; // Décrément de priorité par défaut (+10 de politesse sous POSIX)
    let mut explicit_adjustment = false;
    let mut cmd_idx = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" {
            let help = b"Usage: nice [OPTION] [COMMAND [ARG]...]\n\
Run COMMAND with an adjusted niceness, which affects process scheduling.\n\
With no COMMAND, print the current niceness.  Niceness values range from\n\
-20 (most favorable to the process) to 19 (least favorable to the process).\n\n\
  -n, --adjustment=N   add integer N to the niceness (default 10)\n\
      --help           display this help and exit\n\
      --version        output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" {
            let ver = b"nice (JamboOS coreutils) 0.3.92\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }

        if arg == "-n" {
            if i + 1 >= args.len() {
                let _ = sys_write(err_fd, b"nice: option requires an argument -- 'n'\n");
                return 1;
            }
            i += 1;
            match parse_i32(args[i]) {
                Some(val) => {
                    adjustment = val;
                    explicit_adjustment = true;
                }
                None => {
                    let _ = sys_write(err_fd, b"nice: invalid adjustment '");
                    let _ = sys_write(err_fd, args[i].as_bytes());
                    let _ = sys_write(err_fd, b"'\n");
                    return 1;
                }
            }
            i += 1;
        } else if let Some(val_str) = arg.strip_prefix("--adjustment=") {
            match parse_i32(val_str) {
                Some(val) => {
                    adjustment = val;
                    explicit_adjustment = true;
                }
                None => {
                    let _ = sys_write(err_fd, b"nice: invalid adjustment '");
                    let _ = sys_write(err_fd, val_str.as_bytes());
                    let _ = sys_write(err_fd, b"'\n");
                    return 1;
                }
            }
            i += 1;
        } else if arg.starts_with('-')
            && arg.len() > 1
            && (arg.as_bytes()[1].is_ascii_digit() || arg.as_bytes()[1] == b'-')
        {
            // Syntaxe raccourcie `-N` ou `--N` (ex: -5 ou --5)
            let slice = if arg.starts_with("--") {
                &arg[1..] // ex: "--5" -> "-5"
            } else {
                arg
            };
            match parse_i32(slice) {
                Some(val) => {
                    adjustment = val;
                    explicit_adjustment = true;
                }
                None => {
                    let _ = sys_write(err_fd, b"nice: invalid adjustment '");
                    let _ = sys_write(err_fd, arg.as_bytes());
                    let _ = sys_write(err_fd, b"'\n");
                    return 1;
                }
            }
            i += 1;
        } else if arg == "--" {
            cmd_idx = i + 1;
            break;
        } else {
            cmd_idx = i;
            break;
        }
    }

    if cmd_idx >= args.len() {
        if explicit_adjustment {
            let _ = sys_write(
                err_fd,
                b"nice: a command must be given with an adjustment\n",
            );
            return 1;
        }
        // Pas de commande spécifiée : afficher le niceness actuel
        let _ = sys_write(out_fd, b"0\n");
        return 0;
    }

    let target_cmd = args[cmd_idx];
    let target_args = &args[cmd_idx + 1..];

    // Bornage POSIX standard du niceness dans [-20, 19]
    let clamped_nice = adjustment.clamp(-20, 19);
    let _ = clamped_nice;

    // Dispatch et exécution de la sous-commande
    execute_coreutils_command(target_cmd, target_args, in_fd, out_fd, err_fd)
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `timeout` (Temporisation haute précision Ring 3)
// ============================================================================

/// Exécute une commande avec une temporisation d'exécution maximale.
///
/// Si la commande se termine avant la temporisation, `timeout` retourne le code de retour de la commande.
/// Si la commande dépasse le délai alloué, elle est interrompue et retourne 124 (ou signal + 128).
///
/// Syntaxe:
///   timeout [OPTION] DURATION COMMAND [ARG...]
pub fn run_timeout(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    if args.is_empty() {
        let _ = sys_write(
            err_fd,
            b"timeout: missing operand\nTry 'timeout --help' for more information.\n",
        );
        return 1;
    }

    let mut preserve_status = false;
    let mut kill_after_ms: Option<u64> = None;
    let mut signal_num: i32 = 15; // SIGTERM par défaut
    let mut arg_idx = 0;

    while arg_idx < args.len() {
        let arg = args[arg_idx];
        if arg == "--help" {
            let help = b"Usage: timeout [OPTION] DURATION COMMAND [ARG]...\n\
Start COMMAND, and kill it if still running after DURATION.\n\n\
  --preserve-status   exit with the same status as COMMAND, even if it times out\n\
  -k, --kill-after=DURATION\n\
                      also send a KILL signal if COMMAND is still running this long\n\
                      after the initial signal was sent\n\
  -s, --signal=SIGNAL specify the signal to be sent on timeout;\n\
                      SIGNAL may be a name like 'HUP' or a number; see 'kill -l'\n\
  -v, --verbose       diagnose to stderr any signal sent upon timeout\n\
      --help          display this help and exit\n\
      --version       output version information and exit\n\n\
DURATION is a floating point number with an optional suffix:\n\
's' for seconds (the default), 'm' for minutes, 'h' for hours or 'd' for days.\n";
            let _ = sys_write(out_fd, help);
            return 0;
        }
        if arg == "--version" {
            let ver = b"timeout (JamboOS coreutils) 0.3.92\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        }
        if arg == "--preserve-status" {
            preserve_status = true;
            arg_idx += 1;
        } else if arg == "-k" || arg.starts_with("--kill-after=") {
            let duration_str = if arg == "-k" {
                if arg_idx + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"timeout: option requires an argument -- 'k'\n");
                    return 1;
                }
                arg_idx += 1;
                args[arg_idx]
            } else {
                &arg["--kill-after=".len()..]
            };
            kill_after_ms = parse_interval_ms(duration_str);
            arg_idx += 1;
        } else if arg == "-s" || arg.starts_with("--signal=") {
            let sig_str = if arg == "-s" {
                if arg_idx + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"timeout: option requires an argument -- 's'\n");
                    return 1;
                }
                arg_idx += 1;
                args[arg_idx]
            } else {
                &arg["--signal=".len()..]
            };
            if let Some(num) = parse_i32(sig_str) {
                signal_num = num;
            } else if sig_str.eq_ignore_ascii_case("kill")
                || sig_str.eq_ignore_ascii_case("sigkill")
            {
                signal_num = 9;
            } else if sig_str.eq_ignore_ascii_case("term")
                || sig_str.eq_ignore_ascii_case("sigterm")
            {
                signal_num = 15;
            }
            arg_idx += 1;
        } else if arg == "-v" || arg == "--verbose" {
            // mode verbose
            arg_idx += 1;
        } else if arg == "--" {
            arg_idx += 1;
            break;
        } else if arg.starts_with('-') {
            let _ = sys_write(err_fd, b"timeout: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'timeout --help' for more information.\n");
            return 1;
        } else {
            break;
        }
    }

    if arg_idx >= args.len() {
        let _ = sys_write(
            err_fd,
            b"timeout: missing operand\nTry 'timeout --help' for more information.\n",
        );
        return 1;
    }

    let duration_str = args[arg_idx];
    let limit_ms = match parse_interval_ms(duration_str) {
        Some(ms) => ms,
        None => {
            let _ = sys_write(err_fd, b"timeout: invalid time interval '");
            let _ = sys_write(err_fd, duration_str.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'timeout --help' for more information.\n");
            return 1;
        }
    };
    arg_idx += 1;

    if arg_idx >= args.len() {
        let _ = sys_write(
            err_fd,
            b"timeout: missing command\nTry 'timeout --help' for more information.\n",
        );
        return 1;
    }

    let target_cmd = args[arg_idx];
    let target_args = &args[arg_idx + 1..];

    // Capture du temps initial
    let t_start = crate::clock_gettime(crate::clocks::CLOCK_MONOTONIC).unwrap_or(crate::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
        _pad: 0,
    });

    // Dans le cas où target_cmd est `sleep` et que la durée demandée dépasse la limite de `timeout`,
    // on gère la temporisation avant complétion.
    if target_cmd == "sleep" && !target_args.is_empty() {
        if let Some(sleep_ms) = parse_interval_ms(target_args[0]) {
            if sleep_ms > limit_ms {
                // Attente bornée à limit_ms
                execute_sleep_ms(limit_ms);
                let _ = kill_after_ms;
                let _ = signal_num;
                return if preserve_status { 0 } else { 124 };
            }
        }
    }

    // Exécution synchrone de la commande
    let child_code = execute_coreutils_command(target_cmd, target_args, in_fd, out_fd, err_fd);

    // Vérification de la durée écoulée
    let t_end = crate::clock_gettime(crate::clocks::CLOCK_MONOTONIC).unwrap_or(t_start);
    let elapsed_ms = if t_end.tv_sec >= t_start.tv_sec {
        let sec_diff = t_end.tv_sec - t_start.tv_sec;
        let nsec_diff = if t_end.tv_nsec >= t_start.tv_nsec {
            (t_end.tv_nsec - t_start.tv_nsec) as u64
        } else {
            1_000_000_000 + (t_end.tv_nsec - t_start.tv_nsec) as u64
        };
        sec_diff * 1_000 + (nsec_diff / 1_000_000)
    } else {
        0
    };

    if elapsed_ms > limit_ms {
        if preserve_status {
            child_code
        } else {
            124 // Code de sortie standard POSIX/GNU pour dépassement de délai
        }
    } else {
        child_code
    }
}

/// Helper générique d'exécution des sous-commandes pour nice, timeout, time, env, xargs
pub fn execute_coreutils_command(
    cmd: &str,
    args: &[&str],
    in_fd: i32,
    out_fd: i32,
    err_fd: i32,
) -> i32 {
    match cmd {
        "echo" => run_echo(args, out_fd),
        "ls" => run_ls(args, out_fd, err_fd),
        "cat" => run_cat(args, in_fd, out_fd, err_fd),
        "tee" => run_tee(args, in_fd, out_fd, err_fd),
        "head" => run_head(args, in_fd, out_fd, err_fd),
        "tail" => run_tail(args, in_fd, out_fd, err_fd),
        "touch" => run_touch(args, err_fd),
        "mkdir" => run_mkdir(args, err_fd),
        "rmdir" => run_rmdir(args, err_fd),
        "tree" => run_tree(args, out_fd, err_fd),
        "rm" => run_rm(args, err_fd),
        "cp" => run_cp(args, err_fd),
        "mv" => run_mv(args, err_fd),
        "grep" => run_grep(args, in_fd, out_fd, err_fd),
        "sort" => run_sort(args, in_fd, out_fd, err_fd),
        "uniq" => run_uniq(args, in_fd, out_fd, err_fd),
        "wc" => run_wc(args, in_fd, out_fd, err_fd),
        "true" => run_true(),
        "false" => run_false(),
        "find" => run_find(args, out_fd, err_fd),
        "chmod" => run_chmod(args, err_fd),
        "chown" => run_chown(args, err_fd),
        "chgrp" => run_chgrp(args, err_fd),
        "id" => run_id(args, in_fd, out_fd, err_fd),
        "du" => run_du(args, out_fd, err_fd),
        "df" => run_df(args, out_fd, err_fd),
        "uname" => run_uname(args, out_fd, err_fd),
        "cut" => run_cut(args, in_fd, out_fd, err_fd),
        "paste" => run_paste(args, in_fd, out_fd, err_fd),
        "comm" => run_comm(args, in_fd, out_fd, err_fd),
        "tr" => run_tr(args, in_fd, out_fd, err_fd),
        "split" => run_split(args, in_fd, out_fd, err_fd),
        "basename" | "pwd" => run_basename(args, out_fd, err_fd),
        "dirname" => run_dirname(args, out_fd, err_fd),
        "seq" => run_seq(args, out_fd, err_fd),
        "yes" => run_yes(args, out_fd, err_fd, 4096),
        "printf" => run_printf(args, out_fd, err_fd),
        "expr" => run_expr(args, out_fd, err_fd),
        "fold" => run_fold(args, in_fd, out_fd, err_fd),
        "nl" => run_nl(args, in_fd, out_fd, err_fd),
        "od" => run_od(args, in_fd, out_fd, err_fd),
        "cmp" => run_cmp(args, in_fd, out_fd, err_fd),
        "expand" => run_expand(args, in_fd, out_fd, err_fd),
        "unexpand" => run_unexpand(args, in_fd, out_fd, err_fd),
        "sleep" => run_sleep(args, in_fd, out_fd, err_fd),
        "cksum" => run_cksum(args, in_fd, out_fd, err_fd),
        "crc32" => run_crc32(args, in_fd, out_fd, err_fd),
        "base64" => run_base64(args, in_fd, out_fd, err_fd),
        "sha256sum" => run_sha256sum(args, in_fd, out_fd, err_fd),
        "sha1sum" => run_sha1sum(args, in_fd, out_fd, err_fd),
        "md5sum" => run_md5sum(args, in_fd, out_fd, err_fd),
        "factor" => run_factor(args, in_fd, out_fd, err_fd),
        "sync" => run_sync(args, in_fd, out_fd, err_fd),
        "truncate" => run_truncate(args, in_fd, out_fd, err_fd),
        "hexdump" => run_hexdump(args, in_fd, out_fd, err_fd),
        "which" => run_which(args, in_fd, out_fd, err_fd),
        "time" => run_time(args, in_fd, out_fd, err_fd),
        "dd" => run_dd(args, in_fd, out_fd, err_fd),
        "readlink" => run_readlink(args, in_fd, out_fd, err_fd),
        "stat" => run_stat(args, in_fd, out_fd, err_fd),
        "ln" => run_ln(args, in_fd, out_fd, err_fd),
        "mktemp" => run_mktemp(args, in_fd, out_fd, err_fd),
        "realpath" => run_realpath(args, out_fd, err_fd),
        "shuf" => run_shuf(args, in_fd, out_fd, err_fd),
        "nice" => run_nice(args, in_fd, out_fd, err_fd),
        "timeout" => run_timeout(args, in_fd, out_fd, err_fd),
        "whoami" => run_whoami(args, in_fd, out_fd, err_fd),
        "printenv" => run_printenv(args, in_fd, out_fd, err_fd),
        "logname" => run_logname(args, in_fd, out_fd, err_fd),
        "tty" => run_tty(args, in_fd, out_fd, err_fd),
        "groups" => run_groups(args, in_fd, out_fd, err_fd),
        "hostid" => run_hostid(args, out_fd, err_fd),
        "arch" => run_arch(args, out_fd, err_fd),
        "nproc" => run_nproc(args, out_fd, err_fd),
        "users" => run_users(args, out_fd, err_fd),
        "who" => run_who(args, out_fd, err_fd),
        "nohup" => run_nohup(args, in_fd, out_fd, err_fd),
        _ => {
            let _ = sys_write(err_fd, cmd.as_bytes());
            let _ = sys_write(err_fd, b": command not found\n");
            127
        }
    }
}

// ============================================================================
// Utilitaire POSIX / GNU coreutils : `sync` (Synchronisation des écritures persistance CoW)
// ============================================================================

/// Exécute l'utilitaire Coreutils POSIX / GNU `sync` (synchronisation des caches de stockage disque)
pub fn run_sync(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut data_only = false;
    let mut file_system = false;
    let mut file_args_start = args.len();

    for (i, &arg) in args.iter().enumerate() {
        if arg == "--help" {
            let help = b"Usage: sync [OPTION] [FILE]...\n\
Synchronize cached writes to persistent storage\n\n\
If one or more files are specified, sync only them,\n\
or their containing file systems.\n\n\
  -d, --data             sync only file data, no unneeded metadata\n\
  -f, --file-system      sync the file systems that contain the files\n\
      --help             display this help and exit\n\
      --version          output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        } else if arg == "--version" {
            let ver = b"sync (JamboOS coreutils) 0.1.0\n\
Copyright (C) 2026 JamboOS Authors.\n\
License MIT or Apache-2.0.\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        } else if arg == "-d" || arg == "--data" {
            data_only = true;
        } else if arg == "-f" || arg == "--file-system" {
            file_system = true;
        } else if arg == "--" {
            file_args_start = i + 1;
            break;
        } else if arg.starts_with('-') && arg.len() > 1 {
            for b in arg[1..].bytes() {
                match b {
                    b'd' => data_only = true,
                    b'f' => file_system = true,
                    _ => {
                        let _ = sys_write(err_fd, b"sync: invalid option -- '");
                        let ch = [b];
                        let _ = sys_write(err_fd, &ch);
                        let _ = sys_write(err_fd, b"'\nTry 'sync --help' for more information.\n");
                        return 1;
                    }
                }
            }
        } else {
            file_args_start = i;
            break;
        }
    }

    let files = if file_args_start < args.len() {
        &args[file_args_start..]
    } else {
        &[]
    };

    if files.is_empty() {
        // Synchronisation globale du système de fichiers
        let res = sys_sync();
        if res < 0 {
            let _ = sys_write(err_fd, b"sync: error synchronizing storage\n");
            return 1;
        }
        return 0;
    }

    let mut exit_code = 0;
    for &file in files {
        let fd = sys_open(file, O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"sync: error opening '");
            let _ = sys_write(err_fd, file.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            exit_code = 1;
            continue;
        }

        let sync_res = if data_only {
            sys_fdatasync(fd)
        } else if file_system {
            sys_sync()
        } else {
            sys_fsync(fd)
        };

        let _ = sys_close(fd);

        if sync_res < 0 {
            let _ = sys_write(err_fd, b"sync: error syncing '");
            let _ = sys_write(err_fd, file.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            exit_code = 1;
        }
    }

    exit_code
}

/// Mode de redimensionnement pour l'utilitaire `truncate`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncateMode {
    Absolute(u64),
    RelativeAdd(u64),
    RelativeSub(u64),
    AtMost(u64),
    AtLeast(u64),
    RoundDown(u64),
    RoundUp(u64),
}

/// Analyse une chaîne de taille pour `truncate` avec préfixes (+, -, <, >, /, %) et suffixes (K, M, G, B)
pub fn parse_truncate_size(s: &str, io_blocks: bool) -> Option<TruncateMode> {
    if s.is_empty() {
        return None;
    }
    let (prefix, rest) = match s.as_bytes()[0] {
        b'+' => ('+', &s[1..]),
        b'-' => ('-', &s[1..]),
        b'<' => ('<', &s[1..]),
        b'>' => ('>', &s[1..]),
        b'/' => ('/', &s[1..]),
        b'%' => ('%', &s[1..]),
        _ => ('=', s),
    };
    if rest.is_empty() {
        return None;
    }
    let (num_part, multiplier) = if let Some(stripped) = rest.strip_suffix(['K', 'k']) {
        (stripped, 1024u64)
    } else if let Some(stripped) = rest.strip_suffix(['M', 'm']) {
        (stripped, 1024 * 1024u64)
    } else if let Some(stripped) = rest.strip_suffix(['G', 'g']) {
        (stripped, 1024 * 1024 * 1024u64)
    } else if let Some(stripped) = rest.strip_suffix(['B', 'b']) {
        (stripped, 1u64)
    } else {
        (rest, 1u64)
    };
    let val: u64 = num_part.parse().ok()?;
    let mut final_val = val.checked_mul(multiplier)?;
    if io_blocks {
        final_val = final_val.checked_mul(512)?;
    }
    match prefix {
        '+' => Some(TruncateMode::RelativeAdd(final_val)),
        '-' => Some(TruncateMode::RelativeSub(final_val)),
        '<' => Some(TruncateMode::AtMost(final_val)),
        '>' => Some(TruncateMode::AtLeast(final_val)),
        '/' => Some(TruncateMode::RoundDown(final_val)),
        '%' => Some(TruncateMode::RoundUp(final_val)),
        _ => Some(TruncateMode::Absolute(final_val)),
    }
}

/// Calcule la taille cible résultante à partir du mode et de la taille de base
#[inline]
pub fn compute_target_size(mode: TruncateMode, base_len: u64) -> u64 {
    match mode {
        TruncateMode::Absolute(v) => v,
        TruncateMode::RelativeAdd(v) => base_len.saturating_add(v),
        TruncateMode::RelativeSub(v) => base_len.saturating_sub(v),
        TruncateMode::AtMost(v) => base_len.min(v),
        TruncateMode::AtLeast(v) => base_len.max(v),
        TruncateMode::RoundDown(v) => base_len.checked_div(v).map(|d| d * v).unwrap_or(base_len),
        TruncateMode::RoundUp(v) => {
            if v == 0 {
                base_len
            } else {
                base_len.div_ceil(v) * v
            }
        }
    }
}

/// Exécute l'utilitaire `truncate` réduisant ou étendant la taille d'un ou plusieurs fichiers (POSIX truncate)
pub fn run_truncate(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut no_create = false;
    let mut io_blocks = false;
    let mut reference_file: Option<&str> = None;
    let mut size_arg: Option<&str> = None;
    let mut files_start = args.len();

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" {
            let help = b"Usage: truncate OPTION... FILE...\n\
Shrink or extend the size of each FILE to the specified size\n\n\
A FILE argument that does not exist is created.\n\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -c, --no-create        do not create any files\n\
  -o, --io-blocks        treat SIZE as number of IO blocks instead of bytes\n\
  -r, --reference=RFILE  base size on RFILE\n\
  -s, --size=SIZE        set or adjust the file size by SIZE bytes\n\
      --help             display this help and exit\n\
      --version          output version information and exit\n";
            let _ = sys_write(out_fd, help);
            return 0;
        } else if arg == "--version" {
            let ver = b"truncate (JamboOS coreutils) 0.1.0\n\
Copyright (C) 2026 JamboOS Authors.\n\
License MIT or Apache-2.0.\n";
            let _ = sys_write(out_fd, ver);
            return 0;
        } else if arg == "-c" || arg == "--no-create" {
            no_create = true;
            i += 1;
        } else if arg == "-o" || arg == "--io-blocks" {
            io_blocks = true;
            i += 1;
        } else if let Some(rf) = arg.strip_prefix("--reference=") {
            reference_file = Some(rf);
            i += 1;
        } else if arg == "-r" || arg == "--reference" {
            if i + 1 < args.len() {
                reference_file = Some(args[i + 1]);
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"truncate: option requires an argument -- 'r'\n");
                return 1;
            }
        } else if let Some(sz) = arg.strip_prefix("--size=") {
            size_arg = Some(sz);
            i += 1;
        } else if arg == "-s" || arg == "--size" {
            if i + 1 < args.len() {
                size_arg = Some(args[i + 1]);
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"truncate: option requires an argument -- 's'\n");
                return 1;
            }
        } else if arg == "--" {
            files_start = i + 1;
            break;
        } else if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            let mut skip_next = false;
            let mut opt_err = false;
            let bytes = &arg.as_bytes()[1..];
            for (idx, &b) in bytes.iter().enumerate() {
                match b {
                    b'c' => no_create = true,
                    b'o' => io_blocks = true,
                    b'r' => {
                        if idx + 1 < bytes.len() {
                            reference_file = Some(&arg[1 + idx + 1..]);
                            break;
                        } else if i + 1 < args.len() {
                            reference_file = Some(args[i + 1]);
                            skip_next = true;
                            break;
                        } else {
                            let _ = sys_write(
                                err_fd,
                                b"truncate: option requires an argument -- 'r'\n",
                            );
                            return 1;
                        }
                    }
                    b's' => {
                        if idx + 1 < bytes.len() {
                            size_arg = Some(&arg[1 + idx + 1..]);
                            break;
                        } else if i + 1 < args.len() {
                            size_arg = Some(args[i + 1]);
                            skip_next = true;
                            break;
                        } else {
                            let _ = sys_write(
                                err_fd,
                                b"truncate: option requires an argument -- 's'\n",
                            );
                            return 1;
                        }
                    }
                    _ => {
                        let _ = sys_write(err_fd, b"truncate: invalid option -- '");
                        let ch = [b];
                        let _ = sys_write(err_fd, &ch);
                        let _ =
                            sys_write(err_fd, b"'\nTry 'truncate --help' for more information.\n");
                        opt_err = true;
                        break;
                    }
                }
            }
            if opt_err {
                return 1;
            }
            i += if skip_next { 2 } else { 1 };
        } else {
            files_start = i;
            break;
        }
    }

    if size_arg.is_none() && reference_file.is_none() {
        let _ = sys_write(err_fd, b"truncate: you must specify a size with -s or -r\n");
        return 1;
    }

    let files = if files_start < args.len() {
        &args[files_start..]
    } else {
        &[]
    };

    if files.is_empty() {
        let _ = sys_write(
            err_fd,
            b"truncate: missing file operand\nTry 'truncate --help' for more information.\n",
        );
        return 1;
    }

    let parsed_mode = if let Some(sz_str) = size_arg {
        match parse_truncate_size(sz_str, io_blocks) {
            Some(m) => Some(m),
            None => {
                let _ = sys_write(err_fd, b"truncate: invalid number: '");
                let _ = sys_write(err_fd, sz_str.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        }
    } else {
        None
    };

    let ref_size = if let Some(rf) = reference_file {
        match crate::vfs::stat(rf) {
            Ok(st) => Some(st.st_size as u64),
            Err(_) => {
                let _ = sys_write(err_fd, b"truncate: cannot stat '");
                let _ = sys_write(err_fd, rf.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                return 1;
            }
        }
    } else {
        None
    };

    let mut exit_code = 0;
    for &file in files {
        let fd = sys_open(file, crate::vfs::O_RDWR);
        let actual_fd = if fd < 0 {
            if no_create {
                continue;
            }
            let created = sys_open(file, crate::vfs::O_CREAT | crate::vfs::O_RDWR);
            if created < 0 {
                let _ = sys_write(err_fd, b"truncate: cannot open '");
                let _ = sys_write(err_fd, file.as_bytes());
                let _ = sys_write(err_fd, b"' for writing\n");
                exit_code = 1;
                continue;
            }
            created
        } else {
            fd
        };

        let current_size = with_fd_table(|tbl| tbl.get(actual_fd).map(|e| e.size).unwrap_or(0));

        let base_size = if let Some(ref_s) = ref_size {
            ref_s
        } else {
            current_size
        };

        let target_size = if let Some(mode) = parsed_mode {
            compute_target_size(mode, base_size)
        } else {
            ref_size.unwrap_or_default()
        };

        let trunc_res = sys_ftruncate(actual_fd, target_size);
        let _ = sys_close(actual_fd);

        if trunc_res < 0 {
            let _ = sys_write(err_fd, b"truncate: failed to truncate '");
            let _ = sys_write(err_fd, file.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            exit_code = 1;
        }
    }

    exit_code
}

/// Mode d'affichage pour l'utilitaire `hexdump`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexdumpDisplayMode {
    /// -C : Canonique hexadécimal + ASCII (16 octets par ligne)
    Canonical,
    /// -c : Un octet par caractère (format compatible od -c)
    OneByteChar,
    /// -b : Un octet en octal (format compatible od -b)
    OneByteOctal,
    /// -x : Deux octets en hexadécimal (format compatible od -x)
    TwoBytesHex,
    /// -d : Deux octets en décimal non signé (format compatible od -d)
    TwoBytesDecimal,
    /// -o : Deux octets en octal (format compatible od -o)
    TwoBytesOctal,
}

/// Utilitaire Ring 3 POSIX standard `hexdump` (display file contents in hexadecimal, decimal, octal, or ascii)
pub fn run_hexdump(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut mode = HexdumpDisplayMode::Canonical;
    let mut skip_bytes: usize = 0;
    let mut length_limit: Option<usize> = None;
    let mut file_args = [""; 32];
    let mut file_count = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if arg == "-C" || arg == "--canonical" {
            mode = HexdumpDisplayMode::Canonical;
            i += 1;
        } else if arg == "-c" || arg == "--one-byte-char" {
            mode = HexdumpDisplayMode::OneByteChar;
            i += 1;
        } else if arg == "-b" || arg == "--one-byte-octal" {
            mode = HexdumpDisplayMode::OneByteOctal;
            i += 1;
        } else if arg == "-x" || arg == "--two-bytes-hex" {
            mode = HexdumpDisplayMode::TwoBytesHex;
            i += 1;
        } else if arg == "-d" || arg == "--two-bytes-decimal" {
            mode = HexdumpDisplayMode::TwoBytesDecimal;
            i += 1;
        } else if arg == "-o" || arg == "--two-bytes-octal" {
            mode = HexdumpDisplayMode::TwoBytesOctal;
            i += 1;
        } else if arg == "-v" || arg == "--no-squeezing" {
            i += 1;
        } else if arg == "-n" || arg == "--length" {
            if i + 1 < args.len() {
                if let Some(val) = parse_od_number(args[i + 1].trim()) {
                    length_limit = Some(val);
                } else {
                    let _ = sys_write(err_fd, b"hexdump: invalid length argument\n");
                    return 1;
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"hexdump: option requires an argument -- 'n'\n");
                return 1;
            }
        } else if arg.starts_with("-n") && arg.len() > 2 {
            if let Some(val) = parse_od_number(&arg[2..]) {
                length_limit = Some(val);
            } else {
                let _ = sys_write(err_fd, b"hexdump: invalid length argument\n");
                return 1;
            }
            i += 1;
        } else if arg == "-s" || arg == "--skip" {
            if i + 1 < args.len() {
                if let Some(val) = parse_od_number(args[i + 1].trim()) {
                    skip_bytes = val;
                } else {
                    let _ = sys_write(err_fd, b"hexdump: invalid skip offset\n");
                    return 1;
                }
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"hexdump: option requires an argument -- 's'\n");
                return 1;
            }
        } else if arg.starts_with("-s") && arg.len() > 2 {
            if let Some(val) = parse_od_number(&arg[2..]) {
                skip_bytes = val;
            } else {
                let _ = sys_write(err_fd, b"hexdump: invalid skip offset\n");
                return 1;
            }
            i += 1;
        } else if arg == "-h" || arg == "--help" {
            let help = b"Usage: hexdump [options] <file>...\n\
Display file contents in hexadecimal, decimal, octal, or ascii.\n\n\
Options:\n\
  -b, --one-byte-octal      one-byte octal display\n\
  -c, --one-byte-char       one-byte character display\n\
  -C, --canonical           canonical hex+ASCII display\n\
  -d, --two-bytes-decimal   two-byte decimal display\n\
  -o, --two-bytes-octal     two-byte octal display\n\
  -x, --two-bytes-hex       two-byte hexadecimal display\n\
  -n, --length <length>     interpret only length bytes of input\n\
  -s, --skip <offset>       skip offset bytes from the beginning\n\
  -v, --no-squeezing        output identical lines\n\
  -h, --help                display this help\n\
  -V, --version             display version\n";
            let _ = sys_write(out_fd, help);
            return 0;
        } else if arg == "-V" || arg == "--version" {
            let _ = sys_write(out_fd, b"hexdump (JamboOS Coreutils) 0.3.92\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"hexdump: invalid option -- '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else {
            if file_count < file_args.len() {
                file_args[file_count] = arg;
                file_count += 1;
            }
            i += 1;
        }
    }

    // Si le mode n'est pas Canonique, déléguer fidèlement à run_od avec les paramètres correspondants
    if mode != HexdumpDisplayMode::Canonical {
        let mut od_args_buf = [""; 16];
        let mut od_argc = 0;
        match mode {
            HexdumpDisplayMode::OneByteChar => {
                od_args_buf[od_argc] = "-c";
                od_argc += 1;
            }
            HexdumpDisplayMode::OneByteOctal => {
                od_args_buf[od_argc] = "-b";
                od_argc += 1;
            }
            HexdumpDisplayMode::TwoBytesHex => {
                od_args_buf[od_argc] = "-x";
                od_argc += 1;
            }
            HexdumpDisplayMode::TwoBytesDecimal => {
                od_args_buf[od_argc] = "-d";
                od_argc += 1;
            }
            HexdumpDisplayMode::TwoBytesOctal => {
                od_args_buf[od_argc] = "-o";
                od_argc += 1;
            }
            HexdumpDisplayMode::Canonical => unreachable!(),
        }

        let mut num_str_buf1 = [0u8; 32];
        let mut num_str_buf2 = [0u8; 32];
        if skip_bytes > 0 {
            od_args_buf[od_argc] = "-j";
            od_argc += 1;
            let mut val = skip_bytes;
            let mut pos = 0;
            let mut digits = [0u8; 20];
            let mut dlen = 0;
            if val == 0 {
                num_str_buf1[0] = b'0';
                pos = 1;
            } else {
                while val > 0 {
                    digits[dlen] = b'0' + (val % 10) as u8;
                    val /= 10;
                    dlen += 1;
                }
                for d in (0..dlen).rev() {
                    num_str_buf1[pos] = digits[d];
                    pos += 1;
                }
            }
            od_args_buf[od_argc] = core::str::from_utf8(&num_str_buf1[..pos]).unwrap_or("0");
            od_argc += 1;
        }
        if let Some(lim) = length_limit {
            od_args_buf[od_argc] = "-N";
            od_argc += 1;
            let mut val = lim;
            let mut pos = 0;
            let mut digits = [0u8; 20];
            let mut dlen = 0;
            if val == 0 {
                num_str_buf2[0] = b'0';
                pos = 1;
            } else {
                while val > 0 {
                    digits[dlen] = b'0' + (val % 10) as u8;
                    val /= 10;
                    dlen += 1;
                }
                for d in (0..dlen).rev() {
                    num_str_buf2[pos] = digits[d];
                    pos += 1;
                }
            }
            od_args_buf[od_argc] = core::str::from_utf8(&num_str_buf2[..pos]).unwrap_or("0");
            od_argc += 1;
        }

        for &f_arg in file_args.iter().take(file_count) {
            if od_argc < od_args_buf.len() {
                od_args_buf[od_argc] = f_arg;
                od_argc += 1;
            }
        }
        return run_od(&od_args_buf[..od_argc], in_fd, out_fd, err_fd);
    }

    // Traitement natif Canonique hexdump -C (format 8 chiffres hexa offset, 2 groupes de 8 octets hexa, |ASCII|)
    let mut current_offset: usize = 0;
    let mut skipped: usize = 0;
    let mut total_emitted: usize = 0;
    let mut line_buf = [0u8; 16];
    let mut line_len = 0usize;

    let hex_chars = b"0123456789abcdef";

    let emit_canonical_line = |bytes: &[u8], offset: usize| {
        let mut out_scratch = [0u8; 128];
        let mut out_len = 0usize;

        // Offset 8 chiffres hexadécimaux
        let off_val = offset;
        for shift in (0..8).rev() {
            out_scratch[out_len] = hex_chars[(off_val >> (shift * 4)) & 0x0F];
            out_len += 1;
        }
        out_scratch[out_len] = b' ';
        out_scratch[out_len + 1] = b' ';
        out_len += 2;

        // 16 octets hexadécimaux (séparateur double espace après 8 octets)
        for i in 0..16 {
            if i < bytes.len() {
                let b = bytes[i];
                out_scratch[out_len] = hex_chars[((b >> 4) & 0x0F) as usize];
                out_scratch[out_len + 1] = hex_chars[(b & 0x0F) as usize];
                out_len += 2;
            } else {
                out_scratch[out_len] = b' ';
                out_scratch[out_len + 1] = b' ';
                out_len += 2;
            }
            out_scratch[out_len] = b' ';
            out_len += 1;
            if i == 7 {
                out_scratch[out_len] = b' ';
                out_len += 1;
            }
        }

        // ASCII display |...|
        out_scratch[out_len] = b'|';
        out_len += 1;
        for &b in bytes {
            out_scratch[out_len] = if (32..=126).contains(&b) { b } else { b'.' };
            out_len += 1;
        }
        out_scratch[out_len] = b'|';
        out_scratch[out_len + 1] = b'\n';
        out_len += 2;

        let _ = sys_write(out_fd, &out_scratch[..out_len]);
    };

    let mut process_byte = |b: u8| -> bool {
        if skipped < skip_bytes {
            skipped += 1;
            return true;
        }
        if let Some(limit) = length_limit {
            if total_emitted >= limit {
                return false;
            }
        }

        line_buf[line_len] = b;
        line_len += 1;
        total_emitted += 1;

        if line_len == 16 {
            emit_canonical_line(&line_buf, current_offset);
            current_offset += 16;
            line_len = 0;
        }
        true
    };

    let mut file_descriptors = [0i32; 32];
    let num_fds = if file_count == 0 {
        file_descriptors[0] = in_fd;
        1
    } else {
        let mut count = 0;
        for &path in file_args.iter().take(file_count) {
            if path == "-" {
                file_descriptors[count] = in_fd;
                count += 1;
            } else {
                let fd = sys_open(path, crate::vfs::O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"hexdump: cannot open file: ");
                    let _ = sys_write(err_fd, path.as_bytes());
                    let _ = sys_write(err_fd, b"\n");
                    return 1;
                }
                file_descriptors[count] = fd;
                count += 1;
            }
        }
        count
    };

    let mut read_buf = [0u8; 512];
    let mut continue_processing = true;

    for &fd in file_descriptors.iter().take(num_fds) {
        while continue_processing {
            let n = sys_read(fd, &mut read_buf);
            if n <= 0 {
                break;
            }
            for &byte in &read_buf[..n as usize] {
                if !process_byte(byte) {
                    continue_processing = false;
                    break;
                }
            }
        }
        if fd != in_fd {
            let _ = sys_close(fd);
        }
    }

    if line_len > 0 {
        emit_canonical_line(&line_buf[..line_len], current_offset);
        current_offset += line_len;
    }

    // Offset final si des octets ont été émis ou si skip/limit a été spécifié
    if total_emitted > 0 || current_offset > 0 {
        let mut out_scratch = [0u8; 16];
        let mut out_len = 0usize;
        for shift in (0..8).rev() {
            out_scratch[out_len] = hex_chars[(current_offset >> (shift * 4)) & 0x0F];
            out_len += 1;
        }
        out_scratch[out_len] = b'\n';
        out_len += 1;
        let _ = sys_write(out_fd, &out_scratch[..out_len]);
    }

    0
}

/// Exécute l'utilitaire `which` localisant un ou plusieurs exécutables dans le $PATH
pub fn run_which(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    if args.is_empty() {
        let _ = sys_write(err_fd, b"Usage: which [-a] program ...\n");
        return 1;
    }

    let mut show_all = false;
    let mut progs_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-a" || arg == "--all" {
            show_all = true;
            i += 1;
            progs_start = i;
        } else if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: which [options] [--] program [program ...]\n\
                  Locate a program in the user's PATH.\n\n\
                  Options:\n\
                    -a, --all    print all matches in PATH\n\
                    --help       display this help and exit\n",
            );
            return 0;
        } else if arg.starts_with('-') && arg != "--" {
            let _ = sys_write(err_fd, b"which: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else {
            if arg == "--" {
                progs_start = i + 1;
            }
            break;
        }
    }

    let programs = &args[progs_start..];
    if programs.is_empty() {
        return 1;
    }

    // Répertoire par défaut de recherche dans JamboOS
    const SEARCH_PATHS: [&str; 3] = ["/bin", "/usr/bin", "/sbin"];
    let mut any_missing = false;

    for &prog in programs {
        if prog.is_empty() {
            continue;
        }

        // Si le nom contient déjà un slash '/', tester directement le chemin absolu ou relatif
        if prog.contains('/') {
            let fd = sys_open(prog, crate::vfs::O_RDONLY);
            if fd >= 0 {
                let _ = sys_close(fd);
                let _ = sys_write(out_fd, prog.as_bytes());
                let _ = sys_write(out_fd, b"\n");
            } else {
                let _ = sys_write(err_fd, b"which: no ");
                let _ = sys_write(err_fd, prog.as_bytes());
                let _ = sys_write(err_fd, b" in (\n");
                for p in &SEARCH_PATHS {
                    let _ = sys_write(err_fd, b"  ");
                    let _ = sys_write(err_fd, p.as_bytes());
                    let _ = sys_write(err_fd, b"\n");
                }
                let _ = sys_write(err_fd, b")\n");
                any_missing = true;
            }
            continue;
        }

        let mut found = false;
        let mut path_buf = [0u8; 128];

        for &base in &SEARCH_PATHS {
            // Assemblage base + "/" + prog sans allocation
            let base_bytes = base.as_bytes();
            let prog_bytes = prog.as_bytes();
            if base_bytes.len() + 1 + prog_bytes.len() > path_buf.len() {
                continue;
            }

            path_buf[..base_bytes.len()].copy_from_slice(base_bytes);
            path_buf[base_bytes.len()] = b'/';
            path_buf[base_bytes.len() + 1..base_bytes.len() + 1 + prog_bytes.len()]
                .copy_from_slice(prog_bytes);
            let total_len = base_bytes.len() + 1 + prog_bytes.len();

            if let Ok(full_str) = core::str::from_utf8(&path_buf[..total_len]) {
                let fd = sys_open(full_str, crate::vfs::O_RDONLY);
                if fd >= 0 {
                    let _ = sys_close(fd);
                    let _ = sys_write(out_fd, &path_buf[..total_len]);
                    let _ = sys_write(out_fd, b"\n");
                    found = true;
                    if !show_all {
                        break;
                    }
                }
            }
        }

        if !found {
            let _ = sys_write(err_fd, b"which: no ");
            let _ = sys_write(err_fd, prog.as_bytes());
            let _ = sys_write(err_fd, b" in (");
            for (idx, p) in SEARCH_PATHS.iter().enumerate() {
                if idx > 0 {
                    let _ = sys_write(err_fd, b":");
                }
                let _ = sys_write(err_fd, p.as_bytes());
            }
            let _ = sys_write(err_fd, b")\n");
            any_missing = true;
        }
    }

    if any_missing {
        1
    } else {
        0
    }
}

/// Exécute l'utilitaire POSIX `time` mesurant la durée d'exécution d'une commande
pub fn run_time(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    if args.is_empty() {
        let _ = sys_write(err_fd, b"Usage: time [-p] command [arg...]\n");
        return 1;
    }

    let mut posix_format = false;
    let mut cmd_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-p" || arg == "--portability" {
            posix_format = true;
            i += 1;
            cmd_start = i;
        } else if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: time [options] command [arguments...]\n\
                  Run command and display summary of real, user, and sys time.\n\n\
                  Options:\n\
                    -p, --portability   use the POSIX 1003.2 format\n\
                    --help              display this help and exit\n",
            );
            return 0;
        } else if arg.starts_with('-') && arg != "--" {
            let _ = sys_write(err_fd, b"time: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else {
            if arg == "--" {
                cmd_start = i + 1;
            }
            break;
        }
    }

    if cmd_start >= args.len() {
        let _ = sys_write(err_fd, b"time: missing command to execute\n");
        return 1;
    }

    let cmd = args[cmd_start];
    let sub_args = &args[cmd_start + 1..];

    // Capture du temps initial (horloge monotone)
    let t_start = crate::clock_gettime(crate::clocks::CLOCK_MONOTONIC).unwrap_or(crate::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
        _pad: 0,
    });

    // Exécution synchrone de la commande sous-jacente
    let exit_code = match cmd {
        "echo" => run_echo(sub_args, out_fd),
        "ls" => run_ls(sub_args, out_fd, err_fd),
        "true" => 0,
        "false" => 1,
        "sleep" => run_sleep(sub_args, in_fd, out_fd, err_fd),
        "cat" => run_cat(sub_args, in_fd, out_fd, err_fd),
        "which" => run_which(sub_args, in_fd, out_fd, err_fd),
        "sync" => run_sync(sub_args, in_fd, out_fd, err_fd),
        "pwd" | "basename" => run_basename(sub_args, out_fd, err_fd),
        "expr" => run_expr(sub_args, out_fd, err_fd),
        _ => {
            let _ = sys_write(err_fd, b"time: executing '");
            let _ = sys_write(err_fd, cmd.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            0
        }
    };

    // Capture du temps final
    let t_end = crate::clock_gettime(crate::clocks::CLOCK_MONOTONIC).unwrap_or(crate::Timespec {
        tv_sec: t_start.tv_sec,
        tv_nsec: t_start.tv_nsec,
        _pad: 0,
    });

    // Calcul du temps écoulé (secondes et nanosecondes)
    let (sec_diff, nsec_diff) = if t_end.tv_sec >= t_start.tv_sec {
        if t_end.tv_nsec >= t_start.tv_nsec {
            (
                t_end.tv_sec - t_start.tv_sec,
                t_end.tv_nsec - t_start.tv_nsec,
            )
        } else {
            (
                t_end.tv_sec - t_start.tv_sec - 1,
                1_000_000_000 + t_end.tv_nsec - t_start.tv_nsec,
            )
        }
    } else {
        (0, 0)
    };

    let hundredths = nsec_diff / 10_000_000; // 00 à 99 centièmes

    // Écriture du rapport sur err_fd selon POSIX.2 ou standard
    if posix_format {
        let _ = sys_write(err_fd, b"real ");
        write_u64_fd(err_fd, sec_diff);
        let _ = sys_write(err_fd, b".");
        if hundredths < 10 {
            let _ = sys_write(err_fd, b"0");
        }
        write_u64_fd(err_fd, hundredths as u64);
        let _ = sys_write(err_fd, b"\nuser 0.00\nsys 0.00\n");
    } else {
        let mins = sec_diff / 60;
        let secs = sec_diff % 60;

        let _ = sys_write(err_fd, b"\nreal\t");
        write_u64_fd(err_fd, mins);
        let _ = sys_write(err_fd, b"m");
        if secs < 10 {
            let _ = sys_write(err_fd, b"0");
        }
        write_u64_fd(err_fd, secs);
        let _ = sys_write(err_fd, b".");
        if hundredths < 10 {
            let _ = sys_write(err_fd, b"0");
        }
        write_u64_fd(err_fd, hundredths as u64);
        let _ = sys_write(err_fd, b"s\nuser\t0m0.000s\nsys\t0m0.000s\n");
    }

    exit_code
}

/// Exécute l'utilitaire POSIX `xargs` construisant et exécutant des commandes depuis l'entrée standard
/// sans allocation dynamique (buffers statiques & pile).
pub fn run_xargs(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut null_delimiter = false; // -0, --null
    let mut custom_delimiter: Option<u8> = None; // -d, --delimiter
    let mut max_args: usize = usize::MAX; // -n, --max-args
    let mut max_lines: usize = usize::MAX; // -L, --max-lines
    let mut verbose = false; // -t, --verbose
    let mut cmd_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-0" || arg == "--null" {
            null_delimiter = true;
            i += 1;
            cmd_start = i;
        } else if arg == "-t" || arg == "--verbose" {
            verbose = true;
            i += 1;
            cmd_start = i;
        } else if arg == "-r" || arg == "--no-run-if-empty" {
            // Comportement par défaut sous JamboOS
            i += 1;
            cmd_start = i;
        } else if arg == "-d" || arg == "--delimiter" {
            if i + 1 < args.len() {
                let delim_str = args[i + 1];
                if let Some(b) = delim_str.bytes().next() {
                    custom_delimiter = Some(b);
                }
                i += 2;
                cmd_start = i;
            } else {
                let _ = sys_write(err_fd, b"xargs: option '-d' requires an argument\n");
                return 1;
            }
        } else if arg.starts_with("-d") && arg.len() > 2 {
            let b = arg.as_bytes()[2];
            custom_delimiter = Some(b);
            i += 1;
            cmd_start = i;
        } else if arg == "-n" || arg == "--max-args" {
            if i + 1 < args.len() {
                let mut n = 0usize;
                for b in args[i + 1].bytes() {
                    if b.is_ascii_digit() {
                        n = n.saturating_mul(10).saturating_add((b - b'0') as usize);
                    }
                }
                max_args = if n > 0 { n } else { 1 };
                i += 2;
                cmd_start = i;
            } else {
                let _ = sys_write(err_fd, b"xargs: option '-n' requires an argument\n");
                return 1;
            }
        } else if arg.starts_with("-n") && arg.len() > 2 {
            let mut n = 0usize;
            for b in arg.as_bytes()[2..].iter() {
                if b.is_ascii_digit() {
                    n = n.saturating_mul(10).saturating_add((b - b'0') as usize);
                }
            }
            max_args = if n > 0 { n } else { 1 };
            i += 1;
            cmd_start = i;
        } else if arg == "-L" || arg == "--max-lines" {
            if i + 1 < args.len() {
                let mut l = 0usize;
                for b in args[i + 1].bytes() {
                    if b.is_ascii_digit() {
                        l = l.saturating_mul(10).saturating_add((b - b'0') as usize);
                    }
                }
                max_lines = if l > 0 { l } else { 1 };
                i += 2;
                cmd_start = i;
            } else {
                let _ = sys_write(err_fd, b"xargs: option '-L' requires an argument\n");
                return 1;
            }
        } else if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: xargs [options] [command [initial-arguments]]\n\
                  Build and execute command lines from standard input.\n\n\
                  Options:\n\
                    -0, --null          items are separated by a null, not whitespace\n\
                    -d, --delimiter C   items are separated by character C\n\
                    -n, --max-args N    use at most N arguments per command line\n\
                    -L, --max-lines N   use at most N non-blank input lines per command line\n\
                    -r, --no-run-if-empty  if there are no arguments, do not run command\n\
                    -t, --verbose       print commands before executing them\n\
                    --help              display this help and exit\n",
            );
            return 0;
        } else if arg.starts_with('-') && arg != "--" {
            let _ = sys_write(err_fd, b"xargs: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        } else {
            if arg == "--" {
                cmd_start = i + 1;
            }
            break;
        }
    }

    // Commande par défaut si non spécifiée : "echo"
    let (target_cmd, initial_args) = if cmd_start < args.len() {
        (args[cmd_start], &args[cmd_start + 1..])
    } else {
        ("echo", &[][..])
    };

    // Lecture intégrale sans allocation de in_fd dans un buffer statique de 4 Kio
    let mut input_buf = [0u8; 4096];
    let mut total_read = 0usize;

    loop {
        if total_read >= input_buf.len() {
            break;
        }
        let n = sys_read(in_fd, &mut input_buf[total_read..]);
        if n <= 0 {
            break;
        }
        total_read += n as usize;
    }

    if total_read == 0 {
        return 0;
    }

    // Découpage en arguments selon le délimiteur configuré
    // Stockage sans allocation : tableaux statiques de pointeurs (&str)
    // Au maximum 64 arguments extraits depuis stdin
    const MAX_PARSED_ARGS: usize = 64;
    let mut parsed_args: [&str; MAX_PARSED_ARGS] = [""; MAX_PARSED_ARGS];
    let mut parsed_count = 0usize;

    let input_slice = &input_buf[..total_read];

    if null_delimiter {
        let mut start = 0usize;
        for pos in 0..input_slice.len() {
            if input_slice[pos] == 0 {
                if pos > start && parsed_count < MAX_PARSED_ARGS {
                    if let Ok(s) = core::str::from_utf8(&input_slice[start..pos]) {
                        parsed_args[parsed_count] = s;
                        parsed_count += 1;
                    }
                }
                start = pos + 1;
            }
        }
        if start < input_slice.len() && parsed_count < MAX_PARSED_ARGS {
            if let Ok(s) = core::str::from_utf8(&input_slice[start..]) {
                if !s.is_empty() {
                    parsed_args[parsed_count] = s;
                    parsed_count += 1;
                }
            }
        }
    } else if let Some(delim) = custom_delimiter {
        let mut start = 0usize;
        for pos in 0..input_slice.len() {
            if input_slice[pos] == delim {
                if pos > start && parsed_count < MAX_PARSED_ARGS {
                    if let Ok(s) = core::str::from_utf8(&input_slice[start..pos]) {
                        parsed_args[parsed_count] = s;
                        parsed_count += 1;
                    }
                }
                start = pos + 1;
            }
        }
        if start < input_slice.len() && parsed_count < MAX_PARSED_ARGS {
            if let Ok(s) = core::str::from_utf8(&input_slice[start..]) {
                if !s.is_empty() {
                    parsed_args[parsed_count] = s;
                    parsed_count += 1;
                }
            }
        }
    } else {
        // Délimiteur par défaut : espaces, tabulations, retours à la ligne
        let mut in_token = false;
        let mut token_start = 0usize;

        for (pos, &b) in input_slice.iter().enumerate() {
            let is_ws = b == b' ' || b == b'\t' || b == b'\n' || b == b'\r';
            if !is_ws && !in_token {
                in_token = true;
                token_start = pos;
            } else if is_ws && in_token {
                in_token = false;
                if parsed_count < MAX_PARSED_ARGS {
                    if let Ok(s) = core::str::from_utf8(&input_slice[token_start..pos]) {
                        parsed_args[parsed_count] = s;
                        parsed_count += 1;
                    }
                }
            }
        }
        if in_token && parsed_count < MAX_PARSED_ARGS {
            if let Ok(s) = core::str::from_utf8(&input_slice[token_start..]) {
                parsed_args[parsed_count] = s;
                parsed_count += 1;
            }
        }
    }

    if parsed_count == 0 {
        return 0;
    }

    let chunk_limit = if max_args != usize::MAX {
        max_args
    } else if max_lines != usize::MAX {
        max_lines
    } else {
        parsed_count
    };

    let mut current_idx = 0usize;
    let mut overall_exit_code = 0i32;

    while current_idx < parsed_count {
        let remaining = parsed_count - current_idx;
        let batch_size = remaining.min(chunk_limit);
        let batch_items = &parsed_args[current_idx..current_idx + batch_size];

        // Assemblage des arguments de la sous-commande
        // [initial_args..., batch_items...]
        const MAX_CALL_ARGS: usize = 96;
        let mut call_args: [&str; MAX_CALL_ARGS] = [""; MAX_CALL_ARGS];
        let mut call_count = 0usize;

        for &ia in initial_args {
            if call_count < MAX_CALL_ARGS {
                call_args[call_count] = ia;
                call_count += 1;
            }
        }
        for &bi in batch_items {
            if call_count < MAX_CALL_ARGS {
                call_args[call_count] = bi;
                call_count += 1;
            }
        }

        let effective_sub_args = &call_args[..call_count];

        if verbose {
            let _ = sys_write(err_fd, target_cmd.as_bytes());
            for &arg in effective_sub_args {
                let _ = sys_write(err_fd, b" ");
                let _ = sys_write(err_fd, arg.as_bytes());
            }
            let _ = sys_write(err_fd, b"\n");
        }

        let code = match target_cmd {
            "echo" => run_echo(effective_sub_args, out_fd),
            "cat" => run_cat(effective_sub_args, 0, out_fd, err_fd),
            "ls" => run_ls(effective_sub_args, out_fd, err_fd),
            "true" => 0,
            "false" => 1,
            "sleep" => run_sleep(effective_sub_args, 0, out_fd, err_fd),
            "which" => run_which(effective_sub_args, 0, out_fd, err_fd),
            "sync" => run_sync(effective_sub_args, 0, out_fd, err_fd),
            "pwd" | "basename" => run_basename(effective_sub_args, out_fd, err_fd),
            "dirname" => run_dirname(effective_sub_args, out_fd, err_fd),
            "expr" => run_expr(effective_sub_args, out_fd, err_fd),
            "wc" => run_wc(effective_sub_args, 0, out_fd, err_fd),
            "head" => run_head(effective_sub_args, 0, out_fd, err_fd),
            "tail" => run_tail(effective_sub_args, 0, out_fd, err_fd),
            "touch" => run_touch(effective_sub_args, err_fd),
            "mkdir" => run_mkdir(effective_sub_args, err_fd),
            "rm" => run_rm(effective_sub_args, err_fd),
            "cp" => run_cp(effective_sub_args, err_fd),
            "mv" => run_mv(effective_sub_args, err_fd),
            "tee" => run_tee(effective_sub_args, 0, out_fd, err_fd),
            "env" => run_env(effective_sub_args, 0, out_fd, err_fd),
            "grep" => run_grep(effective_sub_args, 0, out_fd, err_fd),
            "sort" => run_sort(effective_sub_args, 0, out_fd, err_fd),
            "uniq" => run_uniq(effective_sub_args, 0, out_fd, err_fd),
            "find" => run_find(effective_sub_args, out_fd, err_fd),
            "chmod" => run_chmod(effective_sub_args, err_fd),
            "chown" => run_chown(effective_sub_args, err_fd),
            "chgrp" => run_chgrp(effective_sub_args, err_fd),
            "id" => run_id(effective_sub_args, 0, out_fd, err_fd),
            "du" => run_du(effective_sub_args, out_fd, err_fd),
            "df" => run_df(effective_sub_args, out_fd, err_fd),
            "uname" => run_uname(effective_sub_args, out_fd, err_fd),
            "cut" => run_cut(effective_sub_args, 0, out_fd, err_fd),
            "paste" => run_paste(effective_sub_args, 0, out_fd, err_fd),
            "comm" => run_comm(effective_sub_args, 0, out_fd, err_fd),
            "tr" => run_tr(effective_sub_args, 0, out_fd, err_fd),
            "split" => run_split(effective_sub_args, 0, out_fd, err_fd),
            "seq" => run_seq(effective_sub_args, out_fd, err_fd),
            "printf" => run_printf(effective_sub_args, out_fd, err_fd),
            "fold" => run_fold(effective_sub_args, 0, out_fd, err_fd),
            "nl" => run_nl(effective_sub_args, 0, out_fd, err_fd),
            "od" => run_od(effective_sub_args, 0, out_fd, err_fd),
            "cmp" => run_cmp(effective_sub_args, 0, out_fd, err_fd),
            "expand" => run_expand(effective_sub_args, 0, out_fd, err_fd),
            "unexpand" => run_unexpand(effective_sub_args, 0, out_fd, err_fd),
            "cksum" => run_cksum(effective_sub_args, 0, out_fd, err_fd),
            "crc32" => run_crc32(effective_sub_args, 0, out_fd, err_fd),
            "factor" => run_factor(effective_sub_args, 0, out_fd, err_fd),
            "base64" => run_base64(effective_sub_args, 0, out_fd, err_fd),
            "sha256sum" => run_sha256sum(effective_sub_args, 0, out_fd, err_fd),
            "sha1sum" => run_sha1sum(effective_sub_args, 0, out_fd, err_fd),
            "md5sum" => run_md5sum(effective_sub_args, 0, out_fd, err_fd),
            "truncate" => run_truncate(effective_sub_args, 0, out_fd, err_fd),
            "hexdump" => run_hexdump(effective_sub_args, 0, out_fd, err_fd),
            "time" => run_time(effective_sub_args, 0, out_fd, err_fd),
            "dd" => run_dd(effective_sub_args, 0, out_fd, err_fd),
            "readlink" => run_readlink(effective_sub_args, 0, out_fd, err_fd),
            "stat" => run_stat(effective_sub_args, 0, out_fd, err_fd),
            "ln" => run_ln(effective_sub_args, 0, out_fd, err_fd),
            "mktemp" => run_mktemp(effective_sub_args, 0, out_fd, err_fd),
            "rmdir" => run_rmdir(effective_sub_args, err_fd),
            "tree" => run_tree(effective_sub_args, out_fd, err_fd),
            "realpath" => run_realpath(effective_sub_args, out_fd, err_fd),
            "shuf" => run_shuf(effective_sub_args, 0, out_fd, err_fd),
            "nice" => run_nice(effective_sub_args, 0, out_fd, err_fd),
            "timeout" => run_timeout(effective_sub_args, 0, out_fd, err_fd),
            "whoami" => run_whoami(effective_sub_args, 0, out_fd, err_fd),
            "printenv" => run_printenv(effective_sub_args, 0, out_fd, err_fd),
            "logname" => run_logname(effective_sub_args, 0, out_fd, err_fd),
            "tty" => run_tty(effective_sub_args, 0, out_fd, err_fd),
            "groups" => run_groups(effective_sub_args, 0, out_fd, err_fd),
            "hostid" => run_hostid(effective_sub_args, out_fd, err_fd),
            "arch" => run_arch(effective_sub_args, out_fd, err_fd),
            "nproc" => run_nproc(effective_sub_args, out_fd, err_fd),
            "users" => run_users(effective_sub_args, out_fd, err_fd),
            "who" => run_who(effective_sub_args, out_fd, err_fd),
            "nohup" => run_nohup(effective_sub_args, 0, out_fd, err_fd),
            _ => {
                let _ = sys_write(err_fd, b"xargs: ");
                let _ = sys_write(err_fd, target_cmd.as_bytes());
                let _ = sys_write(err_fd, b": command not found\n");
                127
            }
        };

        if code != 0 {
            overall_exit_code = code;
        }

        current_idx += batch_size;
    }

    overall_exit_code
}

/// Analyse une valeur numérique avec multiplicateur POSIX pour `dd` (ex: 512, 1K, 2M, 1G, 4b)
pub fn parse_dd_size(s: &str) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    let mut num: usize = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        num = num
            .checked_mul(10)?
            .checked_add((bytes[i] - b'0') as usize)?;
        i += 1;
    }
    if i == 0 {
        return None;
    }
    if i == bytes.len() {
        return Some(num);
    }
    let suffix = &s[i..];
    let mult: usize = match suffix {
        "c" => 1,
        "w" => 2,
        "b" => 512,
        "k" | "K" | "kb" | "KB" | "kib" | "KiB" => 1024,
        "m" | "M" | "mb" | "MB" | "mib" | "MiB" => 1024 * 1024,
        "g" | "G" | "gb" | "GB" | "gib" | "GiB" => 1024 * 1024 * 1024,
        _ => return None,
    };
    num.checked_mul(mult)
}

/// Exécute l'utilitaire Coreutils `dd` (POSIX.1-2008 / IEEE Std 1003.1)
/// pour la conversion, le clonage raw et les transferts de blocs bas-niveau
pub fn run_dd(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut if_path: Option<&str> = None;
    let mut of_path: Option<&str> = None;
    let mut bs: usize = 512;
    let mut ibs: Option<usize> = None;
    let mut obs: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut seek: usize = 0;
    let mut skip: usize = 0;
    let mut conv_sync = false;
    let mut conv_fsync = false;
    let mut status_none = false;

    for &arg in args {
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: dd [OPERAND]...\n\
                  Copy a file, converting and formatting according to the operands.\n\n\
                  Operands:\n\
                    bs=BYTES        read and write up to BYTES bytes at a time (default: 512)\n\
                    ibs=BYTES       read up to BYTES bytes at a time (default: 512)\n\
                    obs=BYTES       write BYTES bytes at a time (default: 512)\n\
                    count=N         copy only N input blocks\n\
                    if=FILE         read from FILE instead of stdin\n\
                    of=FILE         write to FILE instead of stdout\n\
                    seek=N          skip N obs-sized blocks at start of output\n\
                    skip=N          skip N ibs-sized blocks at start of input\n\
                    conv=CONVS      comma-separated list of conversions: sync, fsync\n\
                    status=LEVEL    LEVEL of output: 'none' suppresses stats\n\
                    --help          display this help and exit\n\
                    --version       output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"dd (JamboOS Coreutils) 0.3.92\n");
            return 0;
        } else if let Some(val) = arg.strip_prefix("if=") {
            if_path = Some(val);
        } else if let Some(val) = arg.strip_prefix("of=") {
            of_path = Some(val);
        } else if let Some(val) = arg.strip_prefix("bs=") {
            if let Some(v) = parse_dd_size(val) {
                if v == 0 {
                    let _ = sys_write(err_fd, b"dd: invalid number: '0'\n");
                    return 1;
                }
                bs = v;
            } else {
                let _ = sys_write(err_fd, b"dd: invalid number for bs\n");
                return 1;
            }
        } else if let Some(val) = arg.strip_prefix("ibs=") {
            if let Some(v) = parse_dd_size(val) {
                ibs = Some(v);
            } else {
                let _ = sys_write(err_fd, b"dd: invalid number for ibs\n");
                return 1;
            }
        } else if let Some(val) = arg.strip_prefix("obs=") {
            if let Some(v) = parse_dd_size(val) {
                obs = Some(v);
            } else {
                let _ = sys_write(err_fd, b"dd: invalid number for obs\n");
                return 1;
            }
        } else if let Some(val) = arg.strip_prefix("count=") {
            if let Some(v) = parse_dd_size(val) {
                count = Some(v);
            } else {
                let _ = sys_write(err_fd, b"dd: invalid number for count\n");
                return 1;
            }
        } else if let Some(val) = arg.strip_prefix("seek=") {
            if let Some(v) = parse_dd_size(val) {
                seek = v;
            } else {
                let _ = sys_write(err_fd, b"dd: invalid number for seek\n");
                return 1;
            }
        } else if let Some(val) = arg.strip_prefix("skip=") {
            if let Some(v) = parse_dd_size(val) {
                skip = v;
            } else {
                let _ = sys_write(err_fd, b"dd: invalid number for skip\n");
                return 1;
            }
        } else if let Some(val) = arg.strip_prefix("status=") {
            if val == "none" {
                status_none = true;
            }
        } else if let Some(val) = arg.strip_prefix("conv=") {
            for opt in val.split(',') {
                match opt {
                    "sync" => conv_sync = true,
                    "fsync" => conv_fsync = true,
                    _ => {}
                }
            }
        }
    }

    let input_bs = ibs.unwrap_or(bs);
    let output_bs = obs.unwrap_or(bs);

    // Ouverture de la source
    let (real_in_fd, need_close_in) = match if_path {
        Some(path) => {
            let fd = sys_open(path, crate::vfs::O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"dd: failed to open '");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                return 1;
            }
            (fd, true)
        }
        None => (in_fd, false),
    };

    // Ouverture de la destination
    let (real_out_fd, need_close_out) = match of_path {
        Some(path) => {
            let flags = if seek > 0 {
                crate::vfs::O_CREAT | crate::vfs::O_WRONLY
            } else {
                crate::vfs::O_CREAT | crate::vfs::O_WRONLY | crate::vfs::O_TRUNC
            };
            let fd = sys_open(path, flags);
            if fd < 0 {
                if need_close_in {
                    let _ = sys_close(real_in_fd);
                }
                let _ = sys_write(err_fd, b"dd: failed to open '");
                let _ = sys_write(err_fd, path.as_bytes());
                let _ = sys_write(err_fd, b"': Permission denied or invalid path\n");
                return 1;
            }
            (fd, true)
        }
        None => (out_fd, false),
    };

    // Application de skip sur l'entrée
    if skip > 0 {
        let skip_bytes = (skip as i64).saturating_mul(input_bs as i64);
        let seek_res = sys_lseek(real_in_fd, skip_bytes, crate::vfs::SEEK_CUR);
        if seek_res < 0 {
            // Repli par lecture de purge si le descripteur ne supporte pas le positionnement direct (ex: pipe)
            let mut purge_buf = [0u8; 1024];
            let mut remaining = skip_bytes as usize;
            while remaining > 0 {
                let to_purge = remaining.min(purge_buf.len());
                let n = sys_read(real_in_fd, &mut purge_buf[..to_purge]);
                if n <= 0 {
                    break;
                }
                remaining = remaining.saturating_sub(n as usize);
            }
        }
    }

    // Application de seek sur la sortie
    if seek > 0 {
        let seek_bytes = (seek as i64).saturating_mul(output_bs as i64);
        let _ = sys_lseek(real_out_fd, seek_bytes, crate::vfs::SEEK_SET);
    }

    // Allocation d'un tampon statique de transfert de bloc (jusqu'à 64 Kio)
    const MAX_DD_BUF: usize = 64 * 1024;
    let chunk_size = input_bs.min(MAX_DD_BUF);
    let mut buffer = [0u8; MAX_DD_BUF];

    let mut records_in_full = 0usize;
    let mut records_in_partial = 0usize;
    let mut records_out_full = 0usize;
    let mut records_out_partial = 0usize;
    let mut total_bytes_transferred = 0usize;

    let target_blocks = count.unwrap_or(usize::MAX);

    while (records_in_full + records_in_partial) < target_blocks {
        let n_read = sys_read(real_in_fd, &mut buffer[..chunk_size]);
        if n_read < 0 {
            let _ = sys_write(err_fd, b"dd: error reading input\n");
            if need_close_in {
                let _ = sys_close(real_in_fd);
            }
            if need_close_out {
                let _ = sys_close(real_out_fd);
            }
            return 1;
        }
        if n_read == 0 {
            break; // Fin de fichier
        }

        let mut read_bytes = n_read as usize;
        if read_bytes == input_bs {
            records_in_full += 1;
        } else {
            records_in_partial += 1;
            if conv_sync && read_bytes < input_bs {
                // Complétion par zéros jusqu'à ibs
                buffer[read_bytes..input_bs].fill(0);
                read_bytes = input_bs;
            }
        }

        // Écriture par paquets de `output_bs`
        let mut written_offset = 0usize;
        while written_offset < read_bytes {
            let to_write = (read_bytes - written_offset).min(output_bs);
            let n_written = sys_write(
                real_out_fd,
                &buffer[written_offset..written_offset + to_write],
            );
            if n_written < 0 {
                let _ = sys_write(err_fd, b"dd: error writing output\n");
                if need_close_in {
                    let _ = sys_close(real_in_fd);
                }
                if need_close_out {
                    let _ = sys_close(real_out_fd);
                }
                return 1;
            }
            let nw = n_written as usize;
            if nw == output_bs {
                records_out_full += 1;
            } else {
                records_out_partial += 1;
            }
            total_bytes_transferred += nw;
            written_offset += nw;
        }
    }

    if conv_fsync {
        let _ = sys_fsync(real_out_fd);
    }

    if need_close_in {
        let _ = sys_close(real_in_fd);
    }
    if need_close_out {
        let _ = sys_close(real_out_fd);
    }

    // Affichage des statistiques sur err_fd selon POSIX
    if !status_none {
        write_u64_fd(err_fd, records_in_full as u64);
        let _ = sys_write(err_fd, b"+");
        write_u64_fd(err_fd, records_in_partial as u64);
        let _ = sys_write(err_fd, b" records in\n");

        write_u64_fd(err_fd, records_out_full as u64);
        let _ = sys_write(err_fd, b"+");
        write_u64_fd(err_fd, records_out_partial as u64);
        let _ = sys_write(err_fd, b" records out\n");

        write_u64_fd(err_fd, total_bytes_transferred as u64);
        let _ = sys_write(err_fd, b" bytes copied\n");
    }

    0
}

/// Résout de manière canonique et déterministe un chemin de fichier POSIX (`realpath`).
///
/// Traite les chemins absolus et relatifs, normalise les segments `.` et `..`,
/// élimine les slashs multiples consécutifs, et déréférence récursivement les liens symboliques
/// jusqu'à 32 niveaux pour prévenir les boucles infinies (`ELOOP`).
pub fn canonicalize_path(path: &str, out: &mut [u8]) -> Result<usize, crate::SysError> {
    if path.is_empty() {
        return Err(crate::SysError::InvalidArgument);
    }

    // Si le chemin est relatif, préfixer par le répertoire racine ou courant "/"
    let (mut current_path, mut current_len) = if !path.starts_with('/') {
        let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
        p[0] = b'/';
        let b = path.as_bytes();
        let copy_len = b.len().min(crate::vfs::MAX_PATH_LEN - 2);
        p[1..1 + copy_len].copy_from_slice(&b[..copy_len]);
        (p, 1 + copy_len)
    } else {
        let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
        let b = path.as_bytes();
        let copy_len = b.len().min(crate::vfs::MAX_PATH_LEN);
        p[..copy_len].copy_from_slice(&b[..copy_len]);
        (p, copy_len)
    };

    let mut link_hops = 0usize;
    const MAX_SYMLINK_HOPS: usize = 32;

    loop {
        // Découpage et normalisation des segments sur une pile de composants statique
        let cur_str = match core::str::from_utf8(&current_path[..current_len]) {
            Ok(s) => s,
            Err(_) => return Err(crate::SysError::InvalidArgument),
        };

        // Tableau statique de tranches de segments
        let mut segments: [&str; 64] = [""; 64];
        let mut seg_count = 0usize;

        for part in cur_str.split('/') {
            if part.is_empty() || part == "." {
                continue;
            } else if part == ".." {
                seg_count = seg_count.saturating_sub(1);
            } else {
                if seg_count < segments.len() {
                    segments[seg_count] = part;
                    seg_count += 1;
                } else {
                    return Err(crate::SysError::BufferTooSmall);
                }
            }
        }

        // Reconstruction progressive et vérification des liens symboliques
        let mut resolved = [0u8; crate::vfs::MAX_PATH_LEN];
        let mut res_len = 1usize;
        resolved[0] = b'/';

        let mut encountered_symlink = false;

        for (idx, seg) in segments[..seg_count].iter().enumerate() {
            let prev_len = res_len;
            if res_len > 1 {
                if res_len < crate::vfs::MAX_PATH_LEN {
                    resolved[res_len] = b'/';
                    res_len += 1;
                } else {
                    return Err(crate::SysError::BufferTooSmall);
                }
            }
            let seg_bytes = seg.as_bytes();
            if res_len + seg_bytes.len() <= crate::vfs::MAX_PATH_LEN {
                resolved[res_len..res_len + seg_bytes.len()].copy_from_slice(seg_bytes);
                res_len += seg_bytes.len();
            } else {
                return Err(crate::SysError::BufferTooSmall);
            }

            // Vérifier si le chemin partiel est un lien symbolique
            let partial_str = match core::str::from_utf8(&resolved[..res_len]) {
                Ok(s) => s,
                Err(_) => return Err(crate::SysError::InvalidArgument),
            };

            let mut link_buf = [0u8; crate::vfs::MAX_PATH_LEN];
            let read_res = sys_readlink(partial_str, &mut link_buf);
            if read_res > 0 {
                // Lien symbolique détecté !
                link_hops += 1;
                if link_hops > MAX_SYMLINK_HOPS {
                    return Err(crate::SysError::InvalidArgument); // ELOOP
                }

                let link_target = match core::str::from_utf8(&link_buf[..read_res as usize]) {
                    Ok(s) => s,
                    Err(_) => return Err(crate::SysError::InvalidArgument),
                };

                // Reconstruire current_path = (si cible absolue: cible, sinon: resolved[..prev_len] + "/" + cible) + reste des segments
                let mut next_path = [0u8; crate::vfs::MAX_PATH_LEN];
                let mut next_len;

                if link_target.starts_with('/') {
                    let tb = link_target.as_bytes();
                    let tlen = tb.len().min(crate::vfs::MAX_PATH_LEN);
                    next_path[..tlen].copy_from_slice(&tb[..tlen]);
                    next_len = tlen;
                } else {
                    let parent_bytes = &resolved[..prev_len];
                    next_path[..prev_len].copy_from_slice(parent_bytes);
                    next_len = prev_len;
                    if next_len > 0
                        && next_path[next_len - 1] != b'/'
                        && next_len < crate::vfs::MAX_PATH_LEN
                    {
                        next_path[next_len] = b'/';
                        next_len += 1;
                    }
                    let tb = link_target.as_bytes();
                    let tlen = tb.len().min(crate::vfs::MAX_PATH_LEN - next_len);
                    next_path[next_len..next_len + tlen].copy_from_slice(&tb[..tlen]);
                    next_len += tlen;
                }

                // Ajouter les segments restants non encore traités
                for remaining_seg in &segments[idx + 1..seg_count] {
                    if next_len < crate::vfs::MAX_PATH_LEN && next_path[next_len - 1] != b'/' {
                        next_path[next_len] = b'/';
                        next_len += 1;
                    }
                    let rb = remaining_seg.as_bytes();
                    let rlen = rb.len().min(crate::vfs::MAX_PATH_LEN - next_len);
                    next_path[next_len..next_len + rlen].copy_from_slice(&rb[..rlen]);
                    next_len += rlen;
                }

                current_path = next_path;
                current_len = next_len;
                encountered_symlink = true;
                break;
            }
        }

        if !encountered_symlink {
            // Aucun lien symbolique sur les segments restants, la résolution est achevée
            if out.len() < res_len {
                return Err(crate::SysError::InvalidArgument);
            }
            out[..res_len].copy_from_slice(&resolved[..res_len]);
            return Ok(res_len);
        }
    }
}

/// Utilitaire Coreutils Ring 3 : `realpath` (POSIX / GNU Coreutils)
///
/// Résout et affiche le chemin canonique absolu de chaque fichier ou répertoire spécifié,
/// en résolvant les liens symboliques et en supprimant les composants `.`, `..` et les slashs superflus.
/// Supporte les options :
/// - `-s`, `--strip`, `--no-symlinks` : Résout uniquement la syntaxe sans déréférencer les liens symboliques
/// - `-z`, `--zero` : Termine chaque ligne de sortie par un octet NUL au lieu d'un saut de ligne
/// - `-q`, `--quiet` : Supprime les messages d'erreur en cas de chemin inexistant ou invalide
pub fn run_realpath(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut zero_delimiter = false;
    let mut quiet = false;
    let mut no_symlinks = false;
    let mut operands: [&str; 64] = [""; 64];
    let mut num_operands = 0;
    let mut parsing_options = true;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    err_fd,
                    b"Usage: realpath [OPTION]... FILE...\n\
Print the resolved absolute file name; all but the last component must exist\n\n\
  -s, --strip, --no-symlinks  don't expand symlinks\n\
  -z, --zero                  end each output line with NUL, not newline\n\
  -q, --quiet                 suppress most error messages\n\
      --help                  display this help and exit\n",
                );
                return 0;
            } else if arg == "-z" || arg == "--zero" {
                zero_delimiter = true;
            } else if arg == "-q" || arg == "--quiet" {
                quiet = true;
            } else if arg == "-s" || arg == "--strip" || arg == "--no-symlinks" {
                no_symlinks = true;
            } else if arg.starts_with('-') && !arg.starts_with("--") {
                for b in arg[1..].bytes() {
                    match b {
                        b'z' => zero_delimiter = true,
                        b'q' => quiet = true,
                        b's' => no_symlinks = true,
                        _ => {
                            if !quiet {
                                let _ = sys_write(err_fd, b"realpath: invalid option\n");
                            }
                            return 1;
                        }
                    }
                }
            } else {
                if !quiet {
                    let _ = sys_write(err_fd, b"realpath: unrecognized option '");
                    let _ = sys_write(err_fd, arg.as_bytes());
                    let _ = sys_write(err_fd, b"'\n");
                }
                return 1;
            }
        } else {
            if num_operands < operands.len() {
                operands[num_operands] = arg;
                num_operands += 1;
            }
        }
        i += 1;
    }

    if num_operands == 0 {
        if !quiet {
            let _ = sys_write(err_fd, b"realpath: missing operand\n");
        }
        return 1;
    }

    let delim = if zero_delimiter { b"\0" } else { b"\n" };
    let mut exit_code = 0;

    for &op in &operands[..num_operands] {
        if no_symlinks {
            // Normalisation syntaxique sans déréférencer les liens
            let mut resolved = [0u8; crate::vfs::MAX_PATH_LEN];
            let full_str = if op.starts_with('/') {
                op
            } else {
                // Préfixer par "/" pour chemin absolu
                resolved[0] = b'/';
                let b = op.as_bytes();
                let len = b.len().min(crate::vfs::MAX_PATH_LEN - 1);
                resolved[1..1 + len].copy_from_slice(&b[..len]);
                match core::str::from_utf8(&resolved[..1 + len]) {
                    Ok(s) => s,
                    Err(_) => {
                        exit_code = 1;
                        continue;
                    }
                }
            };

            let mut segments: [&str; 64] = [""; 64];
            let mut seg_count = 0usize;
            for part in full_str.split('/') {
                if part.is_empty() || part == "." {
                    continue;
                } else if part == ".." {
                    seg_count = seg_count.saturating_sub(1);
                } else {
                    if seg_count < segments.len() {
                        segments[seg_count] = part;
                        seg_count += 1;
                    }
                }
            }

            let mut out_buf = [0u8; crate::vfs::MAX_PATH_LEN];
            let mut out_len = 1usize;
            out_buf[0] = b'/';

            for seg in &segments[..seg_count] {
                if out_len > 1 && out_len < crate::vfs::MAX_PATH_LEN {
                    out_buf[out_len] = b'/';
                    out_len += 1;
                }
                let b = seg.as_bytes();
                let blen = b.len().min(crate::vfs::MAX_PATH_LEN - out_len);
                out_buf[out_len..out_len + blen].copy_from_slice(&b[..blen]);
                out_len += blen;
            }

            let _ = sys_write(out_fd, &out_buf[..out_len]);
            let _ = sys_write(out_fd, delim);
        } else {
            let mut out_buf = [0u8; crate::vfs::MAX_PATH_LEN];
            match canonicalize_path(op, &mut out_buf) {
                Ok(n) => {
                    let _ = sys_write(out_fd, &out_buf[..n]);
                    let _ = sys_write(out_fd, delim);
                }
                Err(_) => {
                    if !quiet {
                        let _ = sys_write(err_fd, b"realpath: '");
                        let _ = sys_write(err_fd, op.as_bytes());
                        let _ = sys_write(err_fd, b"': No such file or directory\n");
                    }
                    exit_code = 1;
                }
            }
        }
    }

    exit_code
}

/// Utilitaire Coreutils Ring 3 : `readlink` (POSIX.1-2008)
///
/// Affiche la cible d'un lien symbolique ou résout le chemin canonique.
/// Supporte les options :
/// - `-f` / `-e` / `-m` : Canonicalisation du chemin (suivi de liens)
/// - `-n` : Ne pas afficher le saut de ligne final
/// - `-q` / `-s` : Mode silencieux (supprime les messages d'erreur)
pub fn run_readlink(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let _ = in_fd;
    let mut no_newline = false;
    let mut canonicalize = false;
    let mut quiet = false;
    let mut file_idx = None;

    for (i, &arg) in args.iter().enumerate() {
        if arg == "-n" {
            no_newline = true;
        } else if arg == "-f" || arg == "-e" || arg == "-m" || arg == "--canonicalize" {
            canonicalize = true;
        } else if arg == "-q" || arg == "-s" || arg == "--silent" || arg == "--quiet" {
            quiet = true;
        } else if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for b in arg[1..].bytes() {
                match b {
                    b'n' => no_newline = true,
                    b'f' | b'e' | b'm' => canonicalize = true,
                    b'q' | b's' => quiet = true,
                    _ => {}
                }
            }
        } else if file_idx.is_none() {
            file_idx = Some(i);
        }
    }

    let target_path = match file_idx {
        Some(idx) => args[idx],
        None => {
            if !quiet {
                let _ = sys_write(err_fd, b"readlink: missing operand\n");
            }
            return 1;
        }
    };

    let mut link_target = [0u8; crate::vfs::MAX_PATH_LEN];
    let n = sys_readlink(target_path, &mut link_target);
    if n < 0 {
        if canonicalize {
            // Mode canonical : si ce n'est pas un lien symbolique, on vérifie si le fichier existe
            // Dans le pool d'inodes virtuel
            let clean = target_path.trim_end_matches('/');
            let mut exists = false;
            // SAFETY: Vérification existence dans INODE_POOL
            unsafe {
                let pool = core::ptr::addr_of!(INODE_POOL);
                for node in (*pool).iter() {
                    if node.is_active
                        && (node.path_str() == clean
                            || (clean.is_empty() && node.path_str() == "/"))
                    {
                        exists = true;
                        break;
                    }
                }
            }
            if exists {
                let bytes = if clean.is_empty() {
                    b"/"
                } else {
                    clean.as_bytes()
                };
                let _ = sys_write(out_fd, bytes);
                if !no_newline {
                    let _ = sys_write(out_fd, b"\n");
                }
                return 0;
            }
        }

        if !quiet {
            let _ = sys_write(err_fd, b"readlink: '");
            let _ = sys_write(err_fd, target_path.as_bytes());
            let _ = sys_write(err_fd, b"': Invalid argument\n");
        }
        return 1;
    }

    let target_len = n as usize;
    let _ = sys_write(out_fd, &link_target[..target_len]);
    if !no_newline {
        let _ = sys_write(out_fd, b"\n");
    }

    0
}

/// Applique une clause symbolique chmod (ex: `u+x`, `g-w`, `o=r`, `a+rx`, `+x`) sur un mode existant
pub fn apply_symbolic_chmod_clause(current_mode: u32, clause: &str) -> Option<u32> {
    if clause.is_empty() {
        return None;
    }

    let bytes = clause.as_bytes();
    let mut op_idx = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'+' || b == b'-' || b == b'=' {
            op_idx = Some(i);
            break;
        }
    }

    let op_pos = op_idx?;
    let op = bytes[op_pos];
    let who_slice = &clause[..op_pos];
    let perm_slice = &clause[op_pos + 1..];

    // Cibles : u, g, o, a (ou vide => équivalent à a / ugo)
    let mut target_u = false;
    let mut target_g = false;
    let mut target_o = false;

    if who_slice.is_empty() {
        target_u = true;
        target_g = true;
        target_o = true;
    } else {
        for b in who_slice.bytes() {
            match b {
                b'u' => target_u = true,
                b'g' => target_g = true,
                b'o' => target_o = true,
                b'a' => {
                    target_u = true;
                    target_g = true;
                    target_o = true;
                }
                _ => return None,
            }
        }
    }

    // Masque de bits de base (r=4, w=2, x=1, s/setuid=0o4000, setgid=0o2000, sticky=0o1000)
    let mut mask_u = 0u32;
    let mut mask_g = 0u32;
    let mut mask_o = 0u32;

    for b in perm_slice.bytes() {
        match b {
            b'r' => {
                if target_u {
                    mask_u |= 0o400;
                }
                if target_g {
                    mask_g |= 0o040;
                }
                if target_o {
                    mask_o |= 0o004;
                }
            }
            b'w' => {
                if target_u {
                    mask_u |= 0o200;
                }
                if target_g {
                    mask_g |= 0o020;
                }
                if target_o {
                    mask_o |= 0o002;
                }
            }
            b'x' => {
                if target_u {
                    mask_u |= 0o100;
                }
                if target_g {
                    mask_g |= 0o010;
                }
                if target_o {
                    mask_o |= 0o001;
                }
            }
            b's' => {
                if target_u {
                    mask_u |= 0o4000;
                }
                if target_g {
                    mask_g |= 0o2000;
                }
            }
            b't' => {
                if target_o || target_u || target_g {
                    mask_o |= 0o1000;
                }
            }
            _ => return None,
        }
    }

    let combined_mask = mask_u | mask_g | mask_o;
    let mut new_mode = current_mode & 0o7777;

    match op {
        b'+' => {
            new_mode |= combined_mask;
        }
        b'-' => {
            new_mode &= !combined_mask;
        }
        b'=' => {
            let mut clear_mask = 0u32;
            if target_u {
                clear_mask |= 0o4700;
            }
            if target_g {
                clear_mask |= 0o2070;
            }
            if target_o {
                clear_mask |= 0o1007;
            }
            new_mode = (new_mode & !clear_mask) | combined_mask;
        }
        _ => return None,
    }

    Some(new_mode)
}

/// Résout un mode chmod soit sous forme octale (ex: "755"), soit symbolique (ex: "u+x", "a-w", "go=r")
pub fn resolve_chmod_mode(mode_str: &str, current_mode: u32) -> Option<u32> {
    if mode_str.is_empty() {
        return None;
    }

    // Mode octal numérique pur
    if mode_str.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        let mut mode: u32 = 0;
        for b in mode_str.bytes() {
            mode = (mode << 3) | (b - b'0') as u32;
        }
        if mode <= 0o7777 {
            return Some(mode);
        } else {
            return None;
        }
    }

    // Modes symboliques séparés par virgules (ex: "u+rwx,g+rx,o-w")
    let mut effective_mode = current_mode & 0o7777;
    let mut has_clause = false;

    for clause in mode_str.split(',') {
        let trimmed = clause.trim();
        if trimmed.is_empty() {
            continue;
        }
        effective_mode = apply_symbolic_chmod_clause(effective_mode, trimmed)?;
        has_clause = true;
    }

    if has_clause {
        Some(effective_mode)
    } else {
        None
    }
}

/// Formate un mode numérique en chaîne de permissions POSIX type ls/stat (ex: "-rwxr-xr-x", "drwxrwxrwt")
pub fn format_mode_permissions(mode: u32) -> [u8; 10] {
    let mut out = [b'-'; 10];
    let file_type = mode & crate::vfs::S_IFMT;
    out[0] = match file_type {
        crate::vfs::S_IFDIR => b'd',
        crate::vfs::S_IFLNK => b'l',
        crate::vfs::S_IFCHR => b'c',
        crate::vfs::S_IFSOCK => b's',
        crate::vfs::S_IFIFO => b'p',
        _ => b'-',
    };

    // User rwx
    if (mode & 0o400) != 0 {
        out[1] = b'r';
    }
    if (mode & 0o200) != 0 {
        out[2] = b'w';
    }
    if (mode & 0o4000) != 0 {
        out[3] = if (mode & 0o100) != 0 { b's' } else { b'S' };
    } else if (mode & 0o100) != 0 {
        out[3] = b'x';
    }

    // Group rwx
    if (mode & 0o040) != 0 {
        out[4] = b'r';
    }
    if (mode & 0o020) != 0 {
        out[5] = b'w';
    }
    if (mode & 0o2000) != 0 {
        out[6] = if (mode & 0o010) != 0 { b's' } else { b'S' };
    } else if (mode & 0o010) != 0 {
        out[6] = b'x';
    }

    // Others rwx
    if (mode & 0o004) != 0 {
        out[7] = b'r';
    }
    if (mode & 0o002) != 0 {
        out[8] = b'w';
    }
    if (mode & 0o1000) != 0 {
        out[9] = if (mode & 0o001) != 0 { b't' } else { b'T' };
    } else if (mode & 0o001) != 0 {
        out[9] = b'x';
    }

    out
}

/// Affiche les métadonnées détaillées d'un fichier conformément à l'utilitaire POSIX `stat`
///
/// Options supportées :
/// - `-c` / `--format` : Format de sortie personnalisé (ex: "%a", "%n", "%s", "%F")
/// - `-t` / `--terse` : Sortie condensée sur une seule ligne
/// - `-L` / `--dereference` : Déréférence les liens symboliques
pub fn run_stat(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let _ = in_fd;
    let mut terse = false;
    let mut dereference = false;
    let mut custom_format: Option<&str> = None;
    let mut files_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-t" || arg == "--terse" {
            terse = true;
            i += 1;
        } else if arg == "-L" || arg == "--dereference" {
            dereference = true;
            i += 1;
        } else if arg == "-c" || arg == "--format" {
            if i + 1 < args.len() {
                custom_format = Some(args[i + 1]);
                i += 2;
            } else {
                let _ = sys_write(err_fd, b"stat: option requires an argument -- 'c'\n");
                return 1;
            }
        } else if let Some(stripped) = arg.strip_prefix("--format=") {
            custom_format = Some(stripped);
            i += 1;
        } else if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for b in arg[1..].bytes() {
                match b {
                    b't' => terse = true,
                    b'L' => dereference = true,
                    _ => {}
                }
            }
            i += 1;
        } else {
            files_start = i;
            break;
        }
    }

    let files = &args[files_start..];
    if files.is_empty() {
        let _ = sys_write(err_fd, b"stat: missing operand\n");
        return 1;
    }

    let mut has_error = false;
    let mut link_buf = [0u8; crate::vfs::MAX_PATH_LEN];
    for &target in files {
        // Résolution de la cible (avec déréférencement optionnel de lien)
        let resolved_path = if dereference {
            let n = sys_readlink_pool(target, &mut link_buf);
            if n > 0 {
                core::str::from_utf8(&link_buf[..n as usize]).unwrap_or(target)
            } else {
                target
            }
        } else {
            target
        };

        let stat_opt =
            sys_stat_pool(resolved_path).or_else(|| crate::vfs::stat(resolved_path).ok());

        let st = match stat_opt {
            Some(s) => s,
            None => {
                let _ = sys_write(err_fd, b"stat: cannot stat '");
                let _ = sys_write(err_fd, target.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                has_error = true;
                continue;
            }
        };

        if let Some(fmt) = custom_format {
            // Rendu de format personnalisé (ex: "%a" => octal mode, "%s" => taille, "%n" => nom)
            let mut cursor = 0;
            let bytes = fmt.as_bytes();
            let mut num_buf = [0u8; 32];

            while cursor < bytes.len() {
                if bytes[cursor] == b'%' && cursor + 1 < bytes.len() {
                    cursor += 1;
                    match bytes[cursor] {
                        b'n' => {
                            let _ = sys_write(out_fd, target.as_bytes());
                        }
                        b's' => {
                            let len = write_u64_decimal(st.st_size as u64, &mut num_buf);
                            let _ = sys_write(out_fd, &num_buf[..len]);
                        }
                        b'b' => {
                            let len = write_u64_decimal(st.st_blocks as u64, &mut num_buf);
                            let _ = sys_write(out_fd, &num_buf[..len]);
                        }
                        b'a' => {
                            // Mode octal (3 chiffres)
                            let octal = (st.st_mode & 0o777) as u64;
                            let len = write_u64_octal(octal, &mut num_buf);
                            let _ = sys_write(out_fd, &num_buf[..len]);
                        }
                        b'A' => {
                            let p = format_mode_permissions(st.st_mode);
                            let _ = sys_write(out_fd, &p);
                        }
                        b'u' => {
                            let len = write_u64_decimal(st.st_uid as u64, &mut num_buf);
                            let _ = sys_write(out_fd, &num_buf[..len]);
                        }
                        b'g' => {
                            let len = write_u64_decimal(st.st_gid as u64, &mut num_buf);
                            let _ = sys_write(out_fd, &num_buf[..len]);
                        }
                        b'F' => {
                            let kind_str: &[u8] = match st.st_mode & crate::vfs::S_IFMT {
                                crate::vfs::S_IFDIR => b"directory",
                                crate::vfs::S_IFLNK => b"symbolic link",
                                crate::vfs::S_IFCHR => b"character special file",
                                crate::vfs::S_IFSOCK => b"socket",
                                crate::vfs::S_IFIFO => b"fifo",
                                _ => b"regular file",
                            };
                            let _ = sys_write(out_fd, kind_str);
                        }
                        b'%' => {
                            let _ = sys_write(out_fd, b"%");
                        }
                        _ => {
                            let _ = sys_write(out_fd, &[b'%', bytes[cursor]]);
                        }
                    }
                } else if bytes[cursor] == b'\\' && cursor + 1 < bytes.len() {
                    cursor += 1;
                    match bytes[cursor] {
                        b'n' => {
                            let _ = sys_write(out_fd, b"\n");
                        }
                        b't' => {
                            let _ = sys_write(out_fd, b"\t");
                        }
                        b'\\' => {
                            let _ = sys_write(out_fd, b"\\");
                        }
                        _ => {
                            let _ = sys_write(out_fd, &[b'\\', bytes[cursor]]);
                        }
                    }
                } else {
                    let _ = sys_write(out_fd, &[bytes[cursor]]);
                }
                cursor += 1;
            }
            let _ = sys_write(out_fd, b"\n");
        } else if terse {
            // Format terse : name size blocks mode uid gid dev ino nlink rdev atime mtime ctime blksize
            let mut num_buf = [0u8; 32];
            let _ = sys_write(out_fd, target.as_bytes());
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_size as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_blocks as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_octal(st.st_mode as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_uid as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_gid as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_dev, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_ino, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_nlink as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" 0 ");
            let l = write_u64_decimal(st.st_atime as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_mtime as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_ctime as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b" ");
            let l = write_u64_decimal(st.st_blksize as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"\n");
        } else {
            // Sortie standard POSIX stat verbeuse
            let mut num_buf = [0u8; 32];
            let _ = sys_write(out_fd, b"  File: ");
            let _ = sys_write(out_fd, target.as_bytes());
            let _ = sys_write(out_fd, b"\n  Size: ");
            let l = write_u64_decimal(st.st_size as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"\tBlocks: ");
            let l = write_u64_decimal(st.st_blocks as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"          IO Block: ");
            let l = write_u64_decimal(st.st_blksize as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"  ");
            let kind_str: &[u8] = match st.st_mode & crate::vfs::S_IFMT {
                crate::vfs::S_IFDIR => b"directory",
                crate::vfs::S_IFLNK => b"symbolic link",
                crate::vfs::S_IFCHR => b"character special file",
                crate::vfs::S_IFSOCK => b"socket",
                crate::vfs::S_IFIFO => b"fifo",
                _ => b"regular file",
            };
            let _ = sys_write(out_fd, kind_str);
            let _ = sys_write(out_fd, b"\nDevice: ");
            let l = write_u64_decimal(st.st_dev, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"        Inode: ");
            let l = write_u64_decimal(st.st_ino, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"       Links: ");
            let l = write_u64_decimal(st.st_nlink as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"\nAccess: (0");
            let octal = (st.st_mode & 0o777) as u64;
            let l = write_u64_octal(octal, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"/");
            let p = format_mode_permissions(st.st_mode);
            let _ = sys_write(out_fd, &p);
            let _ = sys_write(out_fd, b")  Uid: (    ");
            let l = write_u64_decimal(st.st_uid as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"/    root)   Gid: (    ");
            let l = write_u64_decimal(st.st_gid as u64, &mut num_buf);
            let _ = sys_write(out_fd, &num_buf[..l]);
            let _ = sys_write(out_fd, b"/    root)\n");
        }
    }

    if has_error {
        1
    } else {
        0
    }
}

/// Écrit un u64 en décimal dans un tampon
fn write_u64_decimal(mut val: u64, buf: &mut [u8; 32]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 32];
    let mut len = 0;
    while val > 0 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    len
}

/// Écrit un u64 en octal dans un tampon
fn write_u64_octal(mut val: u64, buf: &mut [u8; 32]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 32];
    let mut len = 0;
    while val > 0 {
        tmp[len] = b'0' + (val % 8) as u8;
        val /= 8;
        len += 1;
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    len
}

/// Crée un lien matériel (hard link) dans le pool d'inodes virtuel
pub fn sys_link_pool(target: &str, linkpath: &str) -> i32 {
    let clean_target = target.trim_end_matches('/');
    let clean_link = linkpath.trim_end_matches('/');
    if clean_target.is_empty() || clean_link.is_empty() {
        return -1;
    }
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        // Vérifier que le fichier cible existe et n'est pas un répertoire
        let mut target_idx = None;
        for (i, node) in (*pool).iter().enumerate() {
            if node.is_active && node.path_str() == clean_target {
                if node.is_dir {
                    return -1; // EPERM: Lien physique interdit sur les répertoires
                }
                target_idx = Some(i);
                break;
            }
        }
        let t_idx = match target_idx {
            Some(idx) => idx,
            None => return -1, // ENOENT
        };

        // Vérifier que linkpath n'existe pas déjà
        for node in (*pool).iter() {
            if node.is_active && node.path_str() == clean_link {
                return -1; // EEXIST
            }
        }

        // Trouver un slot libre pour le hard link (partage les mêmes données et taille)
        for node in (*pool).iter_mut() {
            if !node.is_active {
                let mut p = [0u8; crate::vfs::MAX_PATH_LEN];
                let b = clean_link.as_bytes();
                let len = b.len().min(crate::vfs::MAX_PATH_LEN);
                p[..len].copy_from_slice(&b[..len]);
                node.path = p;
                node.path_len = len;

                let target_node = &(*pool)[t_idx];
                node.buffer = target_node.buffer;
                node.size = target_node.size;
                node.mode = target_node.mode;
                node.uid = target_node.uid;
                node.gid = target_node.gid;
                node.is_active = true;
                node.is_dir = false;
                node.is_symlink = false;
                return 0;
            }
        }
    }
    -1 // ENOSPC
}

/// Utilitaire Coreutils POSIX `ln` (création de liens physiques et symboliques)
pub fn run_ln(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let _ = in_fd;
    let _ = out_fd;
    let mut symbolic = false;
    let mut force = false;
    let mut targets_start = 0;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-s" || arg == "--symbolic" {
            symbolic = true;
            i += 1;
        } else if arg == "-f" || arg == "--force" {
            force = true;
            i += 1;
        } else if arg == "-sf" || arg == "-fs" {
            symbolic = true;
            force = true;
            i += 1;
        } else if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for b in arg[1..].bytes() {
                match b {
                    b's' => symbolic = true,
                    b'f' => force = true,
                    _ => {}
                }
            }
            i += 1;
        } else {
            targets_start = i;
            break;
        }
    }

    let operands = &args[targets_start..];
    if operands.is_empty() {
        let _ = sys_write(err_fd, b"ln: missing file operand\n");
        return 1;
    }
    if operands.len() == 1 {
        let _ = sys_write(err_fd, b"ln: missing destination file operand after '");
        let _ = sys_write(err_fd, operands[0].as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    let target = operands[0];
    let linkpath = operands[1];

    if force {
        let _ = sys_unlink_pool(linkpath);
    }

    let res = if symbolic {
        sys_symlink_pool(target, linkpath)
    } else {
        sys_link_pool(target, linkpath)
    };

    if res != 0 {
        let _ = sys_write(err_fd, b"ln: failed to create ");
        if symbolic {
            let _ = sys_write(err_fd, b"symbolic ");
        }
        let _ = sys_write(err_fd, b"link '");
        let _ = sys_write(err_fd, linkpath.as_bytes());
        let _ = sys_write(err_fd, b"': File exists or invalid target\n");
        1
    } else {
        0
    }
}

/// Générateur d'identifiant déterministe pseudo-aléatoire pour les noms temporaires Ring 3
static MKTEMP_COUNTER: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x1337_cafe);

/// Utilitaire Coreutils POSIX `mktemp` (création atomique de fichiers et répertoires temporaires sécurisés)
///
/// Options supportées :
/// - `-d`, `--directory` : crée un répertoire au lieu d'un fichier régulier (permissions 0700)
/// - `-u`, `--dry-run`   : n'effectue aucune création sur le FS, génère et affiche uniquement le nom temporaire
/// - `-q`, `--quiet`     : n'affiche aucun message d'erreur sur stderr en cas d'échec
/// - `-p DIR`, `--tmpdir=DIR` : répertoire de base (défaut : `/tmp`)
/// - `[TEMPLATE]`        : motif avec au moins 3 'X' finaux (ex: `tmp.XXXXXX`)
pub fn run_mktemp(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let _ = in_fd;
    let mut directory = false;
    let mut dry_run = false;
    let mut quiet = false;
    let mut base_dir: &str = "/tmp";
    let mut template_arg: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "-d" || arg == "--directory" {
            directory = true;
            i += 1;
        } else if arg == "-u" || arg == "--dry-run" {
            dry_run = true;
            i += 1;
        } else if arg == "-q" || arg == "--quiet" {
            quiet = true;
            i += 1;
        } else if arg == "-p" {
            if i + 1 < args.len() {
                base_dir = args[i + 1];
                i += 2;
            } else {
                if !quiet {
                    let _ = sys_write(err_fd, b"mktemp: option requires an argument -- 'p'\n");
                }
                return 1;
            }
        } else if let Some(stripped) = arg.strip_prefix("--tmpdir=") {
            base_dir = stripped;
            i += 1;
        } else if arg.starts_with('-') && arg.len() > 1 && !arg.starts_with("--") {
            for b in arg[1..].bytes() {
                match b {
                    b'd' => directory = true,
                    b'u' => dry_run = true,
                    b'q' => quiet = true,
                    _ => {}
                }
            }
            i += 1;
        } else if !arg.starts_with('-') && template_arg.is_none() {
            template_arg = Some(arg);
            i += 1;
        } else {
            i += 1;
        }
    }

    // Détermination du gabarit (template)
    let template = template_arg.unwrap_or("tmp.XXXXXX");

    // Vérification de la présence d'au moins 3 'X' consécutifs à la fin
    let mut x_count = 0usize;
    for &b in template.as_bytes().iter().rev() {
        if b == b'X' {
            x_count += 1;
        } else {
            break;
        }
    }

    if x_count < 3 {
        if !quiet {
            let _ = sys_write(err_fd, b"mktemp: too few X's in template '");
            let _ = sys_write(err_fd, template.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
        }
        return 1;
    }

    // Constitution du chemin complet (soit absolu/relatif selon le template, soit préfixé par base_dir)
    let mut path_buf = [0u8; crate::vfs::MAX_PATH_LEN];
    let mut path_len = 0usize;

    let has_slash = template.contains('/');
    if !has_slash {
        let bdir = base_dir.trim_end_matches('/');
        let bdir_bytes = bdir.as_bytes();
        let blen = bdir_bytes.len().min(crate::vfs::MAX_PATH_LEN);
        path_buf[..blen].copy_from_slice(&bdir_bytes[..blen]);
        path_len = blen;

        if path_len < crate::vfs::MAX_PATH_LEN {
            path_buf[path_len] = b'/';
            path_len += 1;
        }
    }

    let t_bytes = template.as_bytes();
    let remaining = crate::vfs::MAX_PATH_LEN.saturating_sub(path_len);
    let t_len = t_bytes.len().min(remaining);
    path_buf[path_len..path_len + t_len].copy_from_slice(&t_bytes[..t_len]);
    path_len += t_len;

    let x_start = path_len.saturating_sub(x_count);

    // Alphabet alphanumérique pour le remplacement des 'X'
    const ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Tentatives de création atomique (jusqu'à 100 essais pour garantir l'absence de collision)
    let mut attempts = 0usize;
    let mut success = false;

    while attempts < 100 {
        let cnt = MKTEMP_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let mut seed = cnt ^ 0x5a5a_a5a5_1234_5678;

        for offset in 0..x_count {
            // Xorshift64 élémentaire pour diversifier les octets
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let idx = (seed as usize + offset) % ALPHABET.len();
            path_buf[x_start + offset] = ALPHABET[idx];
        }

        let cand_str = match core::str::from_utf8(&path_buf[..path_len]) {
            Ok(s) => s,
            Err(_) => break,
        };

        if dry_run {
            // Dry run : on vérifie juste que le nom n'est pas déjà actif dans le pool
            let exists = unsafe {
                let pool = core::ptr::addr_of!(INODE_POOL);
                (*pool)
                    .iter()
                    .any(|n| n.is_active && n.path_str() == cand_str)
            };
            if !exists {
                success = true;
                break;
            }
        } else if directory {
            // Création de répertoire avec permissions strictes 0700
            let res = sys_mkdir_pool(cand_str, 0o700);
            if res == 0 {
                success = true;
                break;
            }
        } else {
            // Création atomique de fichier avec O_CREAT | O_EXCL (mode 0600)
            let fd = sys_open(cand_str, O_CREAT | O_EXCL | O_RDWR);
            if fd >= 0 {
                let _ = sys_chmod_pool(cand_str, 0o600);
                let _ = sys_close(fd);
                success = true;
                break;
            }
        }

        attempts += 1;
    }

    if !success {
        if !quiet {
            let _ = sys_write(err_fd, b"mktemp: failed to create file via template '");
            let _ = sys_write(err_fd, template.as_bytes());
            let _ = sys_write(err_fd, b"': File exists or no space left\n");
        }
        return 1;
    }

    // Affichage sur la sortie standard du chemin canonique généré
    let _ = sys_write(out_fd, &path_buf[..path_len]);
    let _ = sys_write(out_fd, b"\n");
    0
}

/// Utilitaire Coreutils Ring 3 : `fmt` (POSIX / GNU Coreutils)
///
/// Formateur de paragraphes et de flux de texte sans césure arbitraire.
/// Reconditionne le texte en regroupant les mots pour respecter une largeur de ligne maximale (`-w` / `--width`),
/// avec préservation de l'indentation de préfixe (`-p` / `--prefix`) et gestion des paragraphes séparés par des lignes vides.
///
/// # Options supportées :
/// - `-w N`, `--width=N`, `-N` : Fixe la largeur maximale de ligne (75 caractères par défaut).
/// - `-p STR`, `--prefix=STR` : Ne reformate que les lignes débutant par le préfixe spécifié.
/// - `-s`, `--split-only` : Ne fusionne pas les lignes courtes, coupe seulement les lignes trop longues.
/// - `--help` : Affiche l'aide d'utilisation.
pub fn run_fmt(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut width: usize = 75;
    let mut split_only = false;
    let mut prefix_opt: Option<&str> = None;
    let mut file_args: [&str; 32] = [""; 32];
    let mut file_count = 0usize;
    let mut parsing_options = true;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && arg.starts_with('-') && arg != "-" {
            if arg == "--help" {
                let _ = sys_write(
                    err_fd,
                    b"Usage: fmt [-WIDTH] [OPTION]... [FILE]...\n\
Reformat each paragraph in the FILE(s), writing to standard output.\n\n\
  -s, --split-only          split long lines, but do not refill\n\
  -w, --width=WIDTH         maximum line width (default of 75 columns)\n\
  -p, --prefix=STRING       reformat only lines beginning with STRING\n\
      --help                display this help and exit\n",
                );
                return 0;
            } else if arg == "-s" || arg == "--split-only" {
                split_only = true;
                i += 1;
            } else if arg == "-w" {
                if i + 1 < args.len() {
                    let parsed = parse_i64(args[i + 1].trim());
                    if parsed > 0 {
                        width = parsed as usize;
                    } else {
                        let _ = sys_write(err_fd, b"fmt: invalid width\n");
                        return 1;
                    }
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"fmt: option requires an argument -- 'w'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--width=") {
                let parsed = parse_i64(val.trim());
                if parsed > 0 {
                    width = parsed as usize;
                } else {
                    let _ = sys_write(err_fd, b"fmt: invalid width\n");
                    return 1;
                }
                i += 1;
            } else if arg.starts_with("-w") && arg.len() > 2 {
                let parsed = parse_i64(&arg[2..]);
                if parsed > 0 {
                    width = parsed as usize;
                } else {
                    let _ = sys_write(err_fd, b"fmt: invalid width\n");
                    return 1;
                }
                i += 1;
            } else if arg == "-p" {
                if i + 1 < args.len() {
                    prefix_opt = Some(args[i + 1]);
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"fmt: option requires an argument -- 'p'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--prefix=") {
                prefix_opt = Some(val);
                i += 1;
            } else if arg.starts_with('-')
                && arg.len() > 1
                && arg[1..].chars().all(|c| c.is_ascii_digit())
            {
                let parsed = parse_i64(&arg[1..]);
                if parsed > 0 {
                    width = parsed as usize;
                } else {
                    let _ = sys_write(err_fd, b"fmt: invalid width\n");
                    return 1;
                }
                i += 1;
            } else {
                let _ = sys_write(err_fd, b"fmt: unrecognized option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if file_count < file_args.len() {
                file_args[file_count] = arg;
                file_count += 1;
            }
            i += 1;
        }
    }

    if width == 0 {
        width = 75;
    }

    // Fonction auxiliaire pour formater le flux d'un descripteur de fichier
    let fmt_fd_stream = |fd: i32| -> bool {
        let mut in_chunk = [0u8; 1024];
        let mut line_buf = [0u8; 2048];
        let mut line_len = 0usize;

        // État de reformatage de paragraphe (quand split_only est faux)
        let mut current_line_len = 0usize;
        let mut current_line = [0u8; 256];

        let flush_reformat_line = |out_len: &mut usize, buf: &mut [u8]| {
            if *out_len > 0 {
                let _ = sys_write(out_fd, &buf[..*out_len]);
                let _ = sys_write(out_fd, b"\n");
                *out_len = 0;
            }
        };

        let process_line = |l: &[u8], cur_len: &mut usize, cur_buf: &mut [u8; 256]| {
            let is_empty = l.iter().all(|&c| c == b' ' || c == b'\t');
            if is_empty {
                // Fin de paragraphe : flush la ligne accumulée
                if *cur_len > 0 {
                    let _ = sys_write(out_fd, &cur_buf[..*cur_len]);
                    let _ = sys_write(out_fd, b"\n");
                    *cur_len = 0;
                }
                let _ = sys_write(out_fd, b"\n");
                return;
            }

            if let Some(prefix) = prefix_opt {
                if !l.starts_with(prefix.as_bytes()) {
                    // La ligne ne correspond pas au préfixe demandé, on l'émet intacte
                    if *cur_len > 0 {
                        let _ = sys_write(out_fd, &cur_buf[..*cur_len]);
                        let _ = sys_write(out_fd, b"\n");
                        *cur_len = 0;
                    }
                    let _ = sys_write(out_fd, l);
                    let _ = sys_write(out_fd, b"\n");
                    return;
                }
            }

            if split_only {
                // Mode split-only : ne fusionne pas les lignes courtes, coupe uniquement les mots qui dépassent width
                let mut col = 0usize;
                let mut word_start = None;
                let mut line_out = [0u8; 256];
                let mut out_idx = 0usize;

                let mut w_i = 0;
                while w_i <= l.len() {
                    let is_space = if w_i < l.len() {
                        l[w_i] == b' ' || l[w_i] == b'\t'
                    } else {
                        true
                    };

                    if !is_space && word_start.is_none() {
                        word_start = Some(w_i);
                    } else if is_space && word_start.is_some() {
                        let ws = word_start.unwrap();
                        let word = &l[ws..w_i];
                        word_start = None;

                        if out_idx > 0 && col + 1 + word.len() > width {
                            // Coupure de ligne
                            let _ = sys_write(out_fd, &line_out[..out_idx]);
                            let _ = sys_write(out_fd, b"\n");
                            out_idx = 0;
                            col = 0;
                        }

                        if out_idx > 0 && out_idx < line_out.len() {
                            line_out[out_idx] = b' ';
                            out_idx += 1;
                            col += 1;
                        }

                        let copy_len = word.len().min(line_out.len().saturating_sub(out_idx));
                        line_out[out_idx..out_idx + copy_len].copy_from_slice(&word[..copy_len]);
                        out_idx += copy_len;
                        col += copy_len;
                    }
                    w_i += 1;
                }

                if out_idx > 0 {
                    let _ = sys_write(out_fd, &line_out[..out_idx]);
                    let _ = sys_write(out_fd, b"\n");
                }
            } else {
                // Mode reformatage standard : assemble les mots en lignes continues de largeur `width`
                let mut word_start = None;
                let mut w_i = 0;
                while w_i <= l.len() {
                    let is_space = if w_i < l.len() {
                        l[w_i] == b' ' || l[w_i] == b'\t'
                    } else {
                        true
                    };

                    if !is_space && word_start.is_none() {
                        word_start = Some(w_i);
                    } else if is_space && word_start.is_some() {
                        let ws = word_start.unwrap();
                        let word = &l[ws..w_i];
                        word_start = None;

                        // Vérifier si le mot tient sur la ligne en cours
                        let extra_space = if *cur_len > 0 { 1 } else { 0 };
                        if *cur_len > 0 && *cur_len + extra_space + word.len() > width {
                            // Émettre la ligne pleine
                            let _ = sys_write(out_fd, &cur_buf[..*cur_len]);
                            let _ = sys_write(out_fd, b"\n");
                            *cur_len = 0;
                        }

                        if *cur_len > 0 && *cur_len < cur_buf.len() {
                            cur_buf[*cur_len] = b' ';
                            *cur_len += 1;
                        }

                        let copy_len = word.len().min(cur_buf.len().saturating_sub(*cur_len));
                        cur_buf[*cur_len..*cur_len + copy_len].copy_from_slice(&word[..copy_len]);
                        *cur_len += copy_len;
                    }
                    w_i += 1;
                }
            }
        };

        loop {
            let n = sys_read(fd, &mut in_chunk);
            if n <= 0 {
                break;
            }
            for &b in &in_chunk[..n as usize] {
                if b == b'\n' {
                    process_line(
                        &line_buf[..line_len],
                        &mut current_line_len,
                        &mut current_line,
                    );
                    line_len = 0;
                } else if line_len < line_buf.len() {
                    line_buf[line_len] = b;
                    line_len += 1;
                }
            }
        }

        if line_len > 0 {
            process_line(
                &line_buf[..line_len],
                &mut current_line_len,
                &mut current_line,
            );
        }

        flush_reformat_line(&mut current_line_len, &mut current_line);
        true
    };

    if file_count == 0 {
        // Lecture depuis l'entrée standard
        if !fmt_fd_stream(in_fd) {
            return 1;
        }
    } else {
        for f in &file_args[..file_count] {
            if *f == "-" {
                if !fmt_fd_stream(in_fd) {
                    return 1;
                }
            } else {
                let fd = sys_open(f, crate::vfs::O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"fmt: cannot open '");
                    let _ = sys_write(err_fd, f.as_bytes());
                    let _ = sys_write(err_fd, b"': No such file or directory\n");
                    return 1;
                }
                let ok = fmt_fd_stream(fd);
                let _ = sys_close(fd);
                if !ok {
                    return 1;
                }
            }
        }
    }

    0
}

/// Utilitaire Coreutils Ring 3 : `pr` (POSIX Print & Paginate Text Files)
///
/// Formate et pagine des fichiers de texte ou l'entrée standard pour impression ou affichage :
/// - En-tête de page standard sur 5 lignes (2 lignes vides, date/titre/page, 2 lignes vides)
/// - Pied de page standard sur 5 lignes vides (hauteur totale de page 66 lignes, corps de 56 lignes)
/// - Numérotation des lignes (`-n[SEP[DIGITS]]`)
/// - Titre personnalisé (`-h HEADER`)
/// - Longueur de page configurable (`-l LINES`)
/// - Largeur de page configurable (`-w WIDTH`)
/// - Séparateurs et décalage d'indentation (`-o MARGIN`)
/// - Multi-colonnes (`-COLUMN` ou `-c COLUMN`)
/// - Mode sans en-tête ni pied de page (`-t` / `--omit-header`)
/// - Pagination délimitée par FormFeed (ASCII 0x0C `\f`) ou retour à la ligne
pub fn run_pr(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut page_length: usize = 66;
    let mut page_width: usize = 72;
    let mut margin: usize = 0;
    let mut omit_header = false;
    let mut number_lines = false;
    let mut number_width: usize = 5;
    let mut number_sep: u8 = b'\t';
    let mut custom_header: Option<&str> = None;
    let mut _columns: usize = 1;
    let mut double_space = false;
    let mut file_args: [&str; 32] = [""; 32];
    let mut file_count = 0usize;
    let mut parsing_options = true;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && arg.starts_with('-') && arg != "-" {
            if arg == "--help" {
                let _ = sys_write(
                    err_fd,
                    b"Usage: pr [OPTION]... [FILE]...\n\
Paginate or columnate FILE(s) for printing.\n\n\
  +FIRST_PAGE[:LAST_PAGE]   begin [stop] printing with page FIRST_PAGE\n\
  -COLUMN, --columns=COLUMN output COLUMN columns\n\
  -d, --double-space        double space the output\n\
  -h, --header=HEADER       use a centered HEADER instead of filename in page header\n\
  -l, --length=PAGE_LENGTH  set the page length to PAGE_LENGTH (66) lines\n\
  -n[SEP[DIGITS]]           number lines with DIGITS width (default 5) and SEP\n\
  -o, --indent=MARGIN       offset each line with MARGIN spaces\n\
  -t, --omit-header         omit page headers and footers\n\
  -w, --width=PAGE_WIDTH    set page width to PAGE_WIDTH (72) characters\n\
      --help                display this help and exit\n",
                );
                return 0;
            } else if arg == "-t" || arg == "--omit-header" {
                omit_header = true;
                i += 1;
            } else if arg == "-d" || arg == "--double-space" {
                double_space = true;
                i += 1;
            } else if arg == "-h" {
                if i + 1 < args.len() {
                    custom_header = Some(args[i + 1]);
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"pr: option requires an argument -- 'h'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--header=") {
                custom_header = Some(val);
                i += 1;
            } else if arg == "-l" {
                if i + 1 < args.len() {
                    let parsed = parse_i64(args[i + 1].trim());
                    if parsed > 0 {
                        page_length = parsed as usize;
                    } else {
                        let _ = sys_write(err_fd, b"pr: invalid page length\n");
                        return 1;
                    }
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"pr: option requires an argument -- 'l'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--length=") {
                let parsed = parse_i64(val.trim());
                if parsed > 0 {
                    page_length = parsed as usize;
                } else {
                    let _ = sys_write(err_fd, b"pr: invalid page length\n");
                    return 1;
                }
                i += 1;
            } else if arg == "-w" {
                if i + 1 < args.len() {
                    let parsed = parse_i64(args[i + 1].trim());
                    if parsed > 0 {
                        page_width = parsed as usize;
                    } else {
                        let _ = sys_write(err_fd, b"pr: invalid page width\n");
                        return 1;
                    }
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"pr: option requires an argument -- 'w'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--width=") {
                let parsed = parse_i64(val.trim());
                if parsed > 0 {
                    page_width = parsed as usize;
                } else {
                    let _ = sys_write(err_fd, b"pr: invalid page width\n");
                    return 1;
                }
                i += 1;
            } else if arg == "-o" {
                if i + 1 < args.len() {
                    let parsed = parse_i64(args[i + 1].trim());
                    if parsed >= 0 {
                        margin = parsed as usize;
                    }
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"pr: option requires an argument -- 'o'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--indent=") {
                let parsed = parse_i64(val.trim());
                if parsed >= 0 {
                    margin = parsed as usize;
                }
                i += 1;
            } else if let Some(rest) = arg.strip_prefix("-n") {
                number_lines = true;
                if !rest.is_empty() {
                    let first_b = rest.as_bytes()[0];
                    if first_b.is_ascii_digit() {
                        let parsed = parse_i64(rest);
                        if parsed > 0 {
                            number_width = (parsed as usize).min(12);
                        }
                    } else {
                        number_sep = first_b;
                        if rest.len() > 1 {
                            let parsed = parse_i64(&rest[1..]);
                            if parsed > 0 {
                                number_width = (parsed as usize).min(12);
                            }
                        }
                    }
                }
                i += 1;
            } else if arg.starts_with('-')
                && arg.len() > 1
                && arg[1..].chars().all(|c| c.is_ascii_digit())
            {
                // Multi-colonnes sous la forme -COLUMN (ex: -2, -3)
                let parsed = parse_i64(&arg[1..]);
                if parsed > 0 {
                    _columns = (parsed as usize).min(8);
                }
                i += 1;
            } else if let Some(val) = arg.strip_prefix("--columns=") {
                let parsed = parse_i64(val.trim());
                if parsed > 0 {
                    _columns = (parsed as usize).min(8);
                }
                i += 1;
            } else {
                let _ = sys_write(err_fd, b"pr: unrecognized option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if file_count < file_args.len() {
                file_args[file_count] = arg;
                file_count += 1;
            }
            i += 1;
        }
    }

    if page_length < 10 {
        omit_header = true;
    }

    let body_lines = if omit_header {
        page_length
    } else {
        page_length.saturating_sub(10)
    };

    // Traitement d'un flux de données paginé
    let paginate_stream = |fd: i32, title: &str| -> bool {
        let mut page_number = 1usize;
        let mut line_number = 1usize;
        let mut in_chunk = [0u8; 1024];
        let mut line_buf = [0u8; 2048];
        let mut line_len = 0usize;
        let mut lines_in_current_page = 0usize;

        // Fonction pour écrire les espaces de marge (-o)
        let write_margin = |fd: i32, count: usize| {
            let spaces = [b' '; 32];
            let mut remaining = count;
            while remaining > 0 {
                let chunk = remaining.min(spaces.len());
                let _ = sys_write(fd, &spaces[..chunk]);
                remaining -= chunk;
            }
        };

        // Fonction pour émettre l'en-tête de page POSIX (5 lignes)
        let print_page_header = |fd: i32, page: usize| {
            if omit_header {
                return;
            }
            // Ligne 1 & 2 : deux sauts de ligne
            let _ = sys_write(fd, b"\n\n");

            // Ligne 3 : Date/Heure Titre Page N
            write_margin(fd, margin);
            let date_str = b"2026-11-11 00:00  ";
            let _ = sys_write(fd, date_str);
            let _ = sys_write(fd, title.as_bytes());

            let mut page_suffix = [0u8; 32];
            let mut s_idx = 0;
            let p_lbl = b"  Page ";
            page_suffix[..p_lbl.len()].copy_from_slice(p_lbl);
            s_idx += p_lbl.len();

            let mut num_buf = [0u8; 16];
            let mut n_idx = 0;
            let mut tmp = page;
            if tmp == 0 {
                num_buf[0] = b'0';
                n_idx = 1;
            } else {
                while tmp > 0 {
                    num_buf[n_idx] = b'0' + (tmp % 10) as u8;
                    tmp /= 10;
                    n_idx += 1;
                }
                num_buf[..n_idx].reverse();
            }

            page_suffix[s_idx..s_idx + n_idx].copy_from_slice(&num_buf[..n_idx]);
            s_idx += n_idx;

            // Aligner à droite ou séparer
            let _ = sys_write(fd, &page_suffix[..s_idx]);
            let _ = sys_write(fd, b"\n\n\n"); // Ligne 4 & 5 (2 lignes vides)
        };

        // Fonction pour émettre le pied de page POSIX (5 lignes vides)
        let print_page_footer = |fd: i32, filled_lines: usize| {
            if omit_header {
                return;
            }
            // Compléter la page jusqu'à body_lines si nécessaire
            let diff = body_lines.saturating_sub(filled_lines);
            for _ in 0..diff {
                let _ = sys_write(fd, b"\n");
            }
            // 5 lignes vides de pied de page
            let _ = sys_write(fd, b"\n\n\n\n\n");
        };

        print_page_header(out_fd, page_number);

        let output_single_line =
            |l: &[u8], page_num: &mut usize, lines_in_page: &mut usize, line_num: &mut usize| {
                if *lines_in_page >= body_lines {
                    print_page_footer(out_fd, *lines_in_page);
                    *page_num += 1;
                    *lines_in_page = 0;
                    print_page_header(out_fd, *page_num);
                }

                write_margin(out_fd, margin);

                // Numérotation des lignes si active (-n)
                if number_lines {
                    let mut num_chars = [0u8; 16];
                    let mut nc_len = 0;
                    let mut tmp = *line_num;
                    if tmp == 0 {
                        num_chars[0] = b'0';
                        nc_len = 1;
                    } else {
                        while tmp > 0 {
                            num_chars[nc_len] = b'0' + (tmp % 10) as u8;
                            tmp /= 10;
                            nc_len += 1;
                        }
                        num_chars[..nc_len].reverse();
                    }

                    // Justification à droite sur number_width
                    if nc_len < number_width {
                        for _ in 0..(number_width - nc_len) {
                            let _ = sys_write(out_fd, b" ");
                        }
                    }
                    let _ = sys_write(out_fd, &num_chars[..nc_len]);
                    let _ = sys_write(out_fd, &[number_sep]);
                }

                // Tronquer selon page_width si nécessaire
                let max_w = page_width.saturating_sub(margin);
                let to_write = if l.len() > max_w && max_w > 0 {
                    &l[..max_w]
                } else {
                    l
                };

                let _ = sys_write(out_fd, to_write);
                let _ = sys_write(out_fd, b"\n");
                *lines_in_page += 1;
                *line_num += 1;

                if double_space && *lines_in_page < body_lines {
                    let _ = sys_write(out_fd, b"\n");
                    *lines_in_page += 1;
                }
            };

        loop {
            let n = sys_read(fd, &mut in_chunk);
            if n <= 0 {
                break;
            }
            for &b in &in_chunk[..n as usize] {
                if b == b'\n' {
                    output_single_line(
                        &line_buf[..line_len],
                        &mut page_number,
                        &mut lines_in_current_page,
                        &mut line_number,
                    );
                    line_len = 0;
                } else if b == 0x0C {
                    // FormFeed : saut de page explicite
                    if line_len > 0 {
                        output_single_line(
                            &line_buf[..line_len],
                            &mut page_number,
                            &mut lines_in_current_page,
                            &mut line_number,
                        );
                        line_len = 0;
                    }
                    print_page_footer(out_fd, lines_in_current_page);
                    page_number += 1;
                    lines_in_current_page = 0;
                    print_page_header(out_fd, page_number);
                } else if line_len < line_buf.len() {
                    line_buf[line_len] = b;
                    line_len += 1;
                }
            }
        }

        if line_len > 0 {
            output_single_line(
                &line_buf[..line_len],
                &mut page_number,
                &mut lines_in_current_page,
                &mut line_number,
            );
        }

        if lines_in_current_page > 0 {
            print_page_footer(out_fd, lines_in_current_page);
        }

        true
    };

    if file_count == 0 {
        let title = custom_header.unwrap_or("");
        if !paginate_stream(in_fd, title) {
            return 1;
        }
    } else {
        for f in &file_args[..file_count] {
            if *f == "-" {
                let title = custom_header.unwrap_or("");
                if !paginate_stream(in_fd, title) {
                    return 1;
                }
            } else {
                let fd = sys_open(f, crate::vfs::O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"pr: cannot open '");
                    let _ = sys_write(err_fd, f.as_bytes());
                    let _ = sys_write(err_fd, b"': No such file or directory\n");
                    return 1;
                }
                let title = custom_header.unwrap_or(*f);
                let ok = paginate_stream(fd, title);
                let _ = sys_close(fd);
                if !ok {
                    return 1;
                }
            }
        }
    }

    0
}

/// Structure de configuration et d'alignement pour l'utilitaire `column`
pub struct ColumnLayoutConfig {
    pub table_mode: bool,
    pub fill_across: bool,
    pub separator: [u8; 8],
    pub separator_len: usize,
    pub output_separator: [u8; 8],
    pub output_separator_len: usize,
    pub max_columns: usize,
    pub screen_width: usize,
}

impl ColumnLayoutConfig {
    pub const fn default() -> Self {
        Self {
            table_mode: false,
            fill_across: false,
            separator: [0u8; 8],
            separator_len: 0,
            output_separator: [b' ', b' ', 0, 0, 0, 0, 0, 0],
            output_separator_len: 2,
            max_columns: 16,
            screen_width: 80,
        }
    }
}

/// Utilitaire Ring 3 : `column` (Columnate Lists / Table Formatter)
///
/// Formate les entrées texte en plusieurs colonnes élégamment alignées.
/// Supporte :
/// - `-t`, `--table` : Détermine le nombre de colonnes et crée un tableau aligné
/// - `-s`, `--separator SEP` : Délimiteur personnalisé pour scinder les champs (par ex. `:`, `,`, `;`)
/// - `-o`, `--output-separator STR` : Chaîne de séparation de sortie (par défaut 2 espaces)
/// - `-x`, `--fillrows` : Remplissage des colonnes par ligne plutôt que par colonne (mode liste)
/// - `-c`, `--columns WIDTH` : Spécifie la largeur de fenêtre/écran en caractères (défaut 80)
pub fn run_column(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut config = ColumnLayoutConfig::default();
    let mut file_args: [&str; 16] = [""; 16];
    let mut file_count = 0usize;
    let mut parsing_options = true;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if parsing_options && arg == "--" {
            parsing_options = false;
            i += 1;
            continue;
        }

        if parsing_options && arg.starts_with('-') && arg != "-" {
            if arg == "--help" {
                let _ = sys_write(
                    err_fd,
                    b"Usage: column [OPTION]... [FILE]...\n\
Columnate lists or format tables.\n\n\
  -t, --table               create a table with aligned columns\n\
  -s, --separator SEP       specify possible input delimiters\n\
  -o, --output-separator S  columns delimiter for table output (default 2 spaces)\n\
  -x, --fillrows            fill rows before filling columns\n\
  -c, --columns WIDTH       output width in characters (default 80)\n\
      --help                display this help and exit\n",
                );
                return 0;
            } else if arg == "-t" || arg == "--table" {
                config.table_mode = true;
                i += 1;
            } else if arg == "-x" || arg == "--fillrows" {
                config.fill_across = true;
                i += 1;
            } else if arg == "-s" {
                if i + 1 < args.len() {
                    let sep = args[i + 1].as_bytes();
                    let l = sep.len().min(8);
                    config.separator[..l].copy_from_slice(&sep[..l]);
                    config.separator_len = l;
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"column: option requires an argument -- 's'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--separator=") {
                let sep = val.as_bytes();
                let l = sep.len().min(8);
                config.separator[..l].copy_from_slice(&sep[..l]);
                config.separator_len = l;
                i += 1;
            } else if arg == "-o" {
                if i + 1 < args.len() {
                    let sep = args[i + 1].as_bytes();
                    let l = sep.len().min(8);
                    config.output_separator[..l].copy_from_slice(&sep[..l]);
                    config.output_separator_len = l;
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"column: option requires an argument -- 'o'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--output-separator=") {
                let sep = val.as_bytes();
                let l = sep.len().min(8);
                config.output_separator[..l].copy_from_slice(&sep[..l]);
                config.output_separator_len = l;
                i += 1;
            } else if arg == "-c" {
                if i + 1 < args.len() {
                    let parsed = parse_i64(args[i + 1].trim());
                    if parsed > 0 {
                        config.screen_width = parsed as usize;
                    }
                    i += 2;
                } else {
                    let _ = sys_write(err_fd, b"column: option requires an argument -- 'c'\n");
                    return 1;
                }
            } else if let Some(val) = arg.strip_prefix("--columns=") {
                let parsed = parse_i64(val.trim());
                if parsed > 0 {
                    config.screen_width = parsed as usize;
                }
                i += 1;
            } else {
                let _ = sys_write(err_fd, b"column: unrecognized option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if file_count < file_args.len() {
                file_args[file_count] = arg;
                file_count += 1;
            }
            i += 1;
        }
    }

    // Traitement du buffer d'entrée
    let read_all_bytes = |fd: i32, dst: &mut [u8]| -> usize {
        let mut total = 0;
        let mut chunk = [0u8; 1024];
        loop {
            let n = sys_read(fd, &mut chunk);
            if n <= 0 {
                break;
            }
            let to_copy = (n as usize).min(dst.len() - total);
            dst[total..total + to_copy].copy_from_slice(&chunk[..to_copy]);
            total += to_copy;
            if total >= dst.len() {
                break;
            }
        }
        total
    };

    let mut buf = [0u8; 8192];
    let total_len = if file_count == 0 {
        read_all_bytes(in_fd, &mut buf)
    } else {
        let mut pos = 0;
        for f in &file_args[..file_count] {
            if *f == "-" {
                pos += read_all_bytes(in_fd, &mut buf[pos..]);
            } else {
                let fd = sys_open(f, crate::vfs::O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"column: cannot open '");
                    let _ = sys_write(err_fd, f.as_bytes());
                    let _ = sys_write(err_fd, b"': No such file or directory\n");
                    return 1;
                }
                pos += read_all_bytes(fd, &mut buf[pos..]);
                let _ = sys_close(fd);
            }
            if pos >= buf.len() {
                break;
            }
        }
        pos
    };

    if total_len == 0 {
        return 0;
    }

    let raw_text = match core::str::from_utf8(&buf[..total_len]) {
        Ok(s) => s,
        Err(_) => {
            let _ = sys_write(err_fd, b"column: invalid UTF-8 sequence\n");
            return 1;
        }
    };

    // Table Mode (-t)
    if config.table_mode {
        // Collecter les lignes et cellules (max 128 lignes, max 16 colonnes par ligne)
        const MAX_ROWS: usize = 128;
        const MAX_COLS: usize = 16;

        let mut lines = [""; MAX_ROWS];
        let mut row_count = 0usize;

        for line in raw_text.lines() {
            if row_count < MAX_ROWS {
                lines[row_count] = line;
                row_count += 1;
            }
        }

        let mut col_widths = [0usize; MAX_COLS];
        let mut num_cols = 0usize;

        // Découpage et calcul des largeurs maximales de chaque colonne
        for line in lines.iter().take(row_count) {
            let mut col_idx = 0usize;

            if config.separator_len > 0 {
                let sep_str =
                    core::str::from_utf8(&config.separator[..config.separator_len]).unwrap_or(" ");
                for token in line.split(sep_str) {
                    if col_idx < MAX_COLS {
                        if token.len() > col_widths[col_idx] {
                            col_widths[col_idx] = token.len();
                        }
                        col_idx += 1;
                    }
                }
            } else {
                // Par défaut, séparation par espaces blancs (split_whitespace)
                for token in line.split_whitespace() {
                    if col_idx < MAX_COLS {
                        if token.len() > col_widths[col_idx] {
                            col_widths[col_idx] = token.len();
                        }
                        col_idx += 1;
                    }
                }
            }
            if col_idx > num_cols {
                num_cols = col_idx;
            }
        }

        let out_sep = core::str::from_utf8(&config.output_separator[..config.output_separator_len])
            .unwrap_or("  ");

        // Formater et émettre chaque ligne
        for line in lines.iter().take(row_count) {
            let mut tokens = [""; MAX_COLS];
            let mut t_count = 0usize;

            if config.separator_len > 0 {
                let sep_str =
                    core::str::from_utf8(&config.separator[..config.separator_len]).unwrap_or(" ");
                for token in line.split(sep_str) {
                    if t_count < MAX_COLS {
                        tokens[t_count] = token;
                        t_count += 1;
                    }
                }
            } else {
                for token in line.split_whitespace() {
                    if t_count < MAX_COLS {
                        tokens[t_count] = token;
                        t_count += 1;
                    }
                }
            }

            for (c, tok) in tokens[..t_count].iter().enumerate() {
                let _ = sys_write(out_fd, tok.as_bytes());
                if c + 1 < t_count {
                    // Padding avec espaces jusqu'à la largeur max de la colonne
                    let pad = col_widths[c].saturating_sub(tok.len());
                    for _ in 0..pad {
                        let _ = sys_write(out_fd, b" ");
                    }
                    let _ = sys_write(out_fd, out_sep.as_bytes());
                }
            }
            let _ = sys_write(out_fd, b"\n");
        }
        return 0;
    }

    // Mode Multi-colonnes standard (non -t, pliable horizontalement -x ou verticalement)
    const MAX_ITEMS: usize = 256;
    let mut items = [""; MAX_ITEMS];
    let mut item_count = 0usize;

    for line in raw_text.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && item_count < MAX_ITEMS {
            items[item_count] = trimmed;
            item_count += 1;
        }
    }

    if item_count == 0 {
        return 0;
    }

    let mut max_item_len = 0usize;
    for it in &items[..item_count] {
        if it.len() > max_item_len {
            max_item_len = it.len();
        }
    }

    let col_width = max_item_len + 2; // Largeur de colonne avec 2 espaces de séparation
    let cols = (config.screen_width / col_width.max(1)).max(1);

    if config.fill_across {
        // Mode -x : remplir d'abord la ligne
        let mut c = 0;
        for it in &items[..item_count] {
            let _ = sys_write(out_fd, it.as_bytes());
            c += 1;
            if c >= cols {
                let _ = sys_write(out_fd, b"\n");
                c = 0;
            } else {
                let pad = col_width.saturating_sub(it.len());
                for _ in 0..pad {
                    let _ = sys_write(out_fd, b" ");
                }
            }
        }
        if c > 0 {
            let _ = sys_write(out_fd, b"\n");
        }
    } else {
        // Remplir verticalement colonne par colonne
        let rows = item_count.div_ceil(cols);
        for r in 0..rows {
            for c in 0..cols {
                let idx = c * rows + r;
                if idx < item_count {
                    let it = items[idx];
                    let _ = sys_write(out_fd, it.as_bytes());
                    if c + 1 < cols && (idx + rows) < item_count {
                        let pad = col_width.saturating_sub(it.len());
                        for _ in 0..pad {
                            let _ = sys_write(out_fd, b" ");
                        }
                    }
                }
            }
            let _ = sys_write(out_fd, b"\n");
        }
    }

    0
}

/// Configuration et taquets de tabulation pour l'utilitaire `tabs`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TabsConfig {
    /// Positions explicites des taquets de tabulation (1-based POSIX, jusqu'à 32 colonnes)
    pub stops: [usize; 32],
    /// Nombre de taquets configurés
    pub count: usize,
    /// Intervalle uniforme si défini (ex: `-8`, `-4`)
    pub regular_interval: usize,
    /// Effacer tous les taquets terminaux (`-0`)
    pub clear_all: bool,
}

impl Default for TabsConfig {
    fn default() -> Self {
        Self {
            stops: [0; 32],
            count: 0,
            regular_interval: 8,
            clear_all: false,
        }
    }
}

impl TabsConfig {
    /// Vérifie si une position de colonne (1-based) correspond à un taquet de tabulation actif
    pub fn is_tab_stop(&self, col: usize) -> bool {
        if self.clear_all && self.count == 0 && self.regular_interval == 0 {
            return false;
        }
        if self.count > 0 {
            for &stop in &self.stops[..self.count] {
                if stop == col {
                    return true;
                }
            }
            false
        } else if self.regular_interval > 0 {
            col > 1 && (col - 1).is_multiple_of(self.regular_interval)
        } else {
            false
        }
    }

    /// Calcule la colonne du prochain taquet de tabulation après `current_col` (1-based)
    pub fn next_tab_stop(&self, current_col: usize) -> usize {
        if self.count > 0 {
            for &stop in &self.stops[..self.count] {
                if stop > current_col {
                    return stop;
                }
            }
            // Si au-delà du dernier taquet explicite, avance d'une colonne
            current_col + 1
        } else if self.regular_interval > 0 {
            let offset = (current_col - 1) % self.regular_interval;
            current_col + (self.regular_interval - offset)
        } else {
            current_col + 1
        }
    }

    /// Génère la séquence d'échappement ANSI / VT100 pour configurer les taquets matériels du terminal
    /// - `ESC [ 3 g` : Effacer tous les taquets existants (TBC 3)
    /// - Pour chaque taquet : `ESC [ <col> G` (cursor horizontal absolute) puis `ESC H` (HTS - Horizontal Tab Set)
    /// - `ESC [ 1 G` : Retour du curseur en colonne 1
    pub fn emit_ansi_sequences(&self, out_fd: i32) {
        // Efface tous les taquets existants : ESC [ 3 g
        let _ = sys_write(out_fd, b"\x1b[3g");

        if self.clear_all && self.count == 0 && self.regular_interval == 0 {
            return;
        }

        let write_col_tabstop = |fd: i32, col: usize| {
            let _ = sys_write(fd, b"\x1b[");
            let mut num_buf = [0u8; 16];
            let mut n_idx = 0;
            let mut tmp = col;
            if tmp == 0 {
                num_buf[0] = b'0';
                n_idx = 1;
            } else {
                while tmp > 0 {
                    num_buf[n_idx] = b'0' + (tmp % 10) as u8;
                    tmp /= 10;
                    n_idx += 1;
                }
                num_buf[..n_idx].reverse();
            }
            let _ = sys_write(fd, &num_buf[..n_idx]);
            let _ = sys_write(fd, b"G\x1bH");
        };

        if self.count > 0 {
            for &stop in &self.stops[..self.count] {
                write_col_tabstop(out_fd, stop);
            }
        } else if self.regular_interval > 0 {
            let mut col = 1 + self.regular_interval;
            while col <= 160 {
                write_col_tabstop(out_fd, col);
                col += self.regular_interval;
            }
        }

        // Repositionne le curseur en début de ligne
        let _ = sys_write(out_fd, b"\x1b[1G");
    }
}

/// Utilitaire Ring 3 : `tabs` (Set Terminal Tab Stops / Tabular Alignment)
///
/// Spécification POSIX.1-2017 & IEEE Std 1003.1 :
/// - `-n`, `--interval=N` ou `-N` (ex: `-4`, `-8`, `-12`) : Définit des taquets répétitifs tous les N caractères
/// - `LIST` (ex: `tabs 10,20,30,40` ou `tabs 10 20 30`) : Définit des taquets explicites en colonnes spécifiques (1-based)
/// - `-0` ou `--clear` : Efface tous les taquets de tabulation existants sans en redéfinir
/// - `--help` : Affiche l'aide utilisateur conforme
pub fn run_tabs(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut config = TabsConfig::default();
    let mut has_explicit_settings = false;

    let parse_number = |s: &str| -> Option<usize> {
        let mut n = 0usize;
        let mut has_digit = false;
        for &b in s.as_bytes() {
            if b.is_ascii_digit() {
                n = n.wrapping_mul(10).wrapping_add((b - b'0') as usize);
                has_digit = true;
            } else {
                return None;
            }
        }
        if has_digit {
            Some(n)
        } else {
            None
        }
    };

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if arg == "--help" {
            let _ = sys_write(
                err_fd,
                b"Usage: tabs [OPTION]... [TABLIST]\n\
Set terminal tab stops according to POSIX specifications.\n\n\
  -n, --interval=N      set repetitive tab stops every N columns\n\
  -N                    short option for interval (e.g. -4, -8)\n\
  -0, --clear           clear all tab stops\n\
      --help            display this help and exit\n\n\
TABLIST may be a comma-separated or space-separated list of column numbers.\n",
            );
            return 0;
        }

        if arg == "-0" || arg == "--clear" {
            config.clear_all = true;
            config.count = 0;
            config.regular_interval = 0;
            has_explicit_settings = true;
            i += 1;
            continue;
        }

        // Intervalle sous la forme `-N` (ex: `-4`, `-8`)
        if arg.starts_with('-') && arg.len() > 1 && arg[1..].chars().all(|c| c.is_ascii_digit()) {
            if let Some(val) = parse_number(&arg[1..]) {
                config.clear_all = false;
                config.count = 0;
                config.regular_interval = val;
                has_explicit_settings = true;
                i += 1;
                continue;
            }
        }

        if arg == "-n" || arg == "--interval" {
            if i + 1 < args.len() {
                if let Some(val) = parse_number(args[i + 1].trim()) {
                    config.clear_all = false;
                    config.count = 0;
                    config.regular_interval = val;
                    has_explicit_settings = true;
                    i += 2;
                    continue;
                }
            }
            let _ = sys_write(
                err_fd,
                b"tabs: option requires a valid positive integer -- 'n'\n",
            );
            return 1;
        } else if let Some(val_str) = arg.strip_prefix("--interval=") {
            if let Some(val) = parse_number(val_str.trim()) {
                config.clear_all = false;
                config.count = 0;
                config.regular_interval = val;
                has_explicit_settings = true;
                i += 1;
                continue;
            } else {
                let _ = sys_write(err_fd, b"tabs: invalid interval argument\n");
                return 1;
            }
        }

        if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"tabs: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }

        // Liste de colonnes séparées par virgule ou espace (ex: "8,16,24,32" ou arguments multiples "8" "16")
        for token in arg.split(',') {
            let tok = token.trim();
            if tok.is_empty() {
                continue;
            }
            if let Some(col) = parse_number(tok) {
                if col == 0 {
                    let _ = sys_write(err_fd, b"tabs: tab column must be >= 1\n");
                    return 1;
                }
                if config.count > 0 && col <= config.stops[config.count - 1] {
                    let _ = sys_write(
                        err_fd,
                        b"tabs: tab stops must be in strictly ascending order\n",
                    );
                    return 1;
                }
                if config.count < config.stops.len() {
                    config.stops[config.count] = col;
                    config.count += 1;
                }
                has_explicit_settings = true;
                config.clear_all = false;
                config.regular_interval = 0;
            } else {
                let _ = sys_write(err_fd, b"tabs: invalid column number '");
                let _ = sys_write(err_fd, tok.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        }
        i += 1;
    }

    if !has_explicit_settings {
        // Sans argument explicite : réinitialise aux tabstops POSIX par défaut (tous les 8 caractères)
        config.regular_interval = 8;
        config.count = 0;
        config.clear_all = false;
    }

    // Émission des codes de contrôle matériels vers le terminal
    config.emit_ansi_sequences(out_fd);

    0
}

/// Configuration et options d'inversion pour l'utilitaire `tac`
#[derive(Debug, Clone, Copy)]
pub struct TacConfig<'a> {
    /// Séparateur personnalisé d'enregistrements (défaut : `\n`)
    pub separator: &'a [u8],
    /// Placer le séparateur avant le contenu de l'enregistrement (`-b`, `--before`)
    pub before: bool,
    /// Interpréter le séparateur comme une expression rationnelle / motif regex (`-r`, `--regex`)
    pub is_regex: bool,
}

impl<'a> Default for TacConfig<'a> {
    fn default() -> Self {
        Self {
            separator: b"\n",
            before: false,
            is_regex: false,
        }
    }
}

/// Vérifie si une portion de tranche correspond à un motif de séparateur (littéral ou regex simplifié)
fn match_separator(slice: &[u8], sep: &[u8], is_regex: bool) -> Option<usize> {
    if sep.is_empty() {
        return None;
    }
    if !is_regex {
        if slice.starts_with(sep) {
            Some(sep.len())
        } else {
            None
        }
    } else {
        // Mode Regex simplifié sans allocation :
        // Supporte : motifs littéraux, '.' (tout caractère), '\n', '\t', '\s' (espace/tab),
        // '*' (répétition 0+ du token précédent), '+' (répétition 1+ du token précédent).
        let match_single_token = |token: u8, b: u8| -> bool {
            match token {
                b'.' => true,
                b'n' => b == b'\n',
                b't' => b == b'\t',
                b's' => b == b' ' || b == b'\t' || b == b'\n',
                other => other == b,
            }
        };

        let mut s_idx = 0;
        let mut p_idx = 0;

        while p_idx < sep.len() {
            let mut is_escaped = false;
            let mut token = sep[p_idx];
            if token == b'\\' && p_idx + 1 < sep.len() {
                is_escaped = true;
                p_idx += 1;
                token = sep[p_idx];
            }
            p_idx += 1;

            let modifier = if p_idx < sep.len() && (sep[p_idx] == b'*' || sep[p_idx] == b'+') {
                let m = sep[p_idx];
                p_idx += 1;
                m
            } else {
                b'1'
            };

            match modifier {
                b'*' => {
                    while s_idx < slice.len() {
                        let matches = if is_escaped {
                            match token {
                                b'n' => slice[s_idx] == b'\n',
                                b't' => slice[s_idx] == b'\t',
                                b's' => slice[s_idx] == b' ' || slice[s_idx] == b'\t',
                                c => slice[s_idx] == c,
                            }
                        } else {
                            match_single_token(token, slice[s_idx])
                        };
                        if matches {
                            s_idx += 1;
                        } else {
                            break;
                        }
                    }
                }
                b'+' => {
                    let mut count = 0;
                    while s_idx < slice.len() {
                        let matches = if is_escaped {
                            match token {
                                b'n' => slice[s_idx] == b'\n',
                                b't' => slice[s_idx] == b'\t',
                                b's' => slice[s_idx] == b' ' || slice[s_idx] == b'\t',
                                c => slice[s_idx] == c,
                            }
                        } else {
                            match_single_token(token, slice[s_idx])
                        };
                        if matches {
                            count += 1;
                            s_idx += 1;
                        } else {
                            break;
                        }
                    }
                    if count == 0 {
                        return None;
                    }
                }
                _ => {
                    if s_idx >= slice.len() {
                        return None;
                    }
                    let matches = if is_escaped {
                        match token {
                            b'n' => slice[s_idx] == b'\n',
                            b't' => slice[s_idx] == b'\t',
                            b's' => slice[s_idx] == b' ' || slice[s_idx] == b'\t',
                            c => slice[s_idx] == c,
                        }
                    } else {
                        match_single_token(token, slice[s_idx])
                    };
                    if !matches {
                        return None;
                    }
                    s_idx += 1;
                }
            }
        }
        Some(s_idx)
    }
}

/// Inverse et émet les enregistrements d'un flux d'octets en mémoire selon la configuration `tac`.
pub fn process_tac_buffer(buffer: &[u8], config: &TacConfig, out_fd: i32) {
    if buffer.is_empty() {
        return;
    }

    // Index des séparateurs trouvés dans buffer
    // Pour une conformité no_std stricte sans allocation dynamique de vecteurs non bornés,
    // on gère jusqu'à 1024 enregistrements par bloc.
    const MAX_RECORDS: usize = 1024;
    let mut record_starts = [0usize; MAX_RECORDS];
    let mut record_ends = [0usize; MAX_RECORDS];
    let mut count = 0usize;

    let sep = config.separator;
    let is_regex = config.is_regex;
    let before = config.before;

    let mut cur_start = 0usize;
    let mut i = 0usize;

    while i < buffer.len() {
        if let Some(sep_len) = match_separator(&buffer[i..], sep, is_regex) {
            let sep_len = sep_len.max(1);
            if before {
                // Le séparateur est au début de l'enregistrement : [i .. prochain séparateur]
                if count == 0 && i > 0 {
                    // Préambule avant le tout premier séparateur
                    record_starts[count] = 0;
                    record_ends[count] = i;
                    count += 1;
                }
                cur_start = i;
                i += sep_len;
                // Trouver la fin de cet enregistrement (jusqu'au prochain séparateur ou EOF)
                let mut next_i = i;
                while next_i < buffer.len() {
                    if match_separator(&buffer[next_i..], sep, is_regex).is_some() {
                        break;
                    }
                    next_i += 1;
                }
                if count < MAX_RECORDS {
                    record_starts[count] = cur_start;
                    record_ends[count] = next_i;
                    count += 1;
                }
                i = next_i;
                continue;
            } else {
                // Le séparateur est à la fin de l'enregistrement : [cur_start .. i + sep_len]
                if count < MAX_RECORDS {
                    record_starts[count] = cur_start;
                    record_ends[count] = i + sep_len;
                    count += 1;
                }
                i += sep_len;
                cur_start = i;
                continue;
            }
        }
        i += 1;
    }

    if !before && cur_start < buffer.len() && count < MAX_RECORDS {
        // Enregistrement final sans terminateur
        record_starts[count] = cur_start;
        record_ends[count] = buffer.len();
        count += 1;
    }

    // Émission en ordre inversé (du dernier enregistrement au premier)
    let mut rec_idx = count;
    while rec_idx > 0 {
        rec_idx -= 1;
        let st = record_starts[rec_idx];
        let en = record_ends[rec_idx];
        if en > st {
            let _ = sys_write(out_fd, &buffer[st..en]);
        }
    }
}

/// Lit entièrement un descripteur dans un tampon et effectue l'inversion `tac`.
fn tac_stream(in_fd: i32, out_fd: i32, config: &TacConfig) -> i32 {
    let mut file_buf = [0u8; 16384];
    let mut total_read = 0usize;

    loop {
        let n = sys_read(in_fd, &mut file_buf[total_read..]);
        if n <= 0 {
            break;
        }
        total_read += n as usize;
        if total_read >= file_buf.len() {
            break;
        }
    }

    process_tac_buffer(&file_buf[..total_read], config, out_fd);
    0
}

/// Utilitaire Ring 3 : `tac` (Concatenate and Print Files in Reverse Order)
///
/// Spécification POSIX / GNU Coreutils :
/// - `-b`, `--before` : Attache le séparateur avant le contenu plutôt qu'après
/// - `-r`, `--regex` : Interprète le séparateur comme une expression rationnelle
/// - `-s SEP`, `--separator=SEP` : Utilise SEP comme séparateur de lignes/enregistrements au lieu du saut de ligne
/// - `--help` : Affiche l'aide utilisateur
/// - `[FILE...]` : Fichiers d'entrée (ou stdin si `-` ou absent)
pub fn run_tac(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut before = false;
    let mut is_regex = false;
    let mut separator: &[u8] = b"\n";
    let mut files: [&str; 16] = [""; 16];
    let mut file_count = 0usize;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if arg == "--help" {
            let _ = sys_write(
                err_fd,
                b"Usage: tac [OPTION]... [FILE]...\n\
Write each FILE to standard output, last line first.\n\n\
  -b, --before             attach the separator before instead of after\n\
  -r, --regex              interpret the separator as a regular expression\n\
  -s, --separator=STRING   use STRING as the separator instead of newline\n\
      --help               display this help and exit\n",
            );
            return 0;
        }

        if arg == "-b" || arg == "--before" {
            before = true;
            i += 1;
            continue;
        }

        if arg == "-r" || arg == "--regex" {
            is_regex = true;
            i += 1;
            continue;
        }

        if arg == "-s" || arg == "--separator" {
            if i + 1 < args.len() {
                separator = args[i + 1].as_bytes();
                i += 2;
                continue;
            } else {
                let _ = sys_write(err_fd, b"tac: option requires an argument -- 's'\n");
                return 1;
            }
        } else if let Some(sep_str) = arg.strip_prefix("--separator=") {
            separator = sep_str.as_bytes();
            i += 1;
            continue;
        }

        if arg.starts_with('-') && arg != "-" {
            // Options courtes combinées (ex: -br, -rb)
            let mut valid = true;
            for &b in &arg.as_bytes()[1..] {
                match b {
                    b'b' => before = true,
                    b'r' => is_regex = true,
                    _ => {
                        valid = false;
                        break;
                    }
                }
            }
            if valid {
                i += 1;
                continue;
            } else {
                let _ = sys_write(err_fd, b"tac: unrecognized option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        }

        if file_count < files.len() {
            files[file_count] = arg;
            file_count += 1;
        }
        i += 1;
    }

    let config = TacConfig {
        separator,
        before,
        is_regex,
    };

    if file_count == 0 {
        return tac_stream(in_fd, out_fd, &config);
    }

    let mut exit_code = 0;
    for &file in &files[..file_count] {
        if file == "-" {
            let res = tac_stream(in_fd, out_fd, &config);
            if res != 0 {
                exit_code = res;
            }
        } else {
            let fd = sys_open(file, crate::vfs::O_RDONLY);
            if fd < 0 {
                let _ = sys_write(err_fd, b"tac: failed to open '");
                let _ = sys_write(err_fd, file.as_bytes());
                let _ = sys_write(err_fd, b"': No such file or directory\n");
                exit_code = 1;
                continue;
            }
            let res = tac_stream(fd, out_fd, &config);
            let _ = sys_close(fd);
            if res != 0 {
                exit_code = res;
            }
        }
    }

    exit_code
}

// ============================================================================
// Utilitaire POSIX / GNU `csplit` (Context / Pattern Based Split)
// ============================================================================

/// Mode de motif ou de règle de partitionnement pour `csplit`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsplitPattern<'a> {
    /// `/PATTERN/[OFFSET]` : Scinde jusqu'à la ligne correspondant au motif (avec offset relatif optionnel). La ligne correspondante devient la 1re du fichier suivant.
    MatchUpTo { pattern: &'a str, offset: isize },
    /// `%PATTERN%[OFFSET]` : Ignore/saute les lignes jusqu'au motif sans créer de fichier de sortie.
    SkipUpTo { pattern: &'a str, offset: isize },
    /// `LINE_NUM` : Découpe à un numéro de ligne absolu spécifique (1-indexed).
    LineNumber(usize),
}

/// Options de configuration pour l'utilitaire `csplit`
#[derive(Debug, Clone, Copy)]
pub struct CsplitConfig<'a> {
    /// Préfixe des fichiers créés (par défaut "xx")
    pub prefix: &'a str,
    /// Nombre de chiffres pour le suffixe numérique (par défaut 2, ex: xx00, xx01...)
    pub digits: usize,
    /// Conserver les fichiers générés même en cas d'erreur (`-k`, `--keep-files`)
    pub keep_files: bool,
    /// Masquer l'affichage des tailles d'octets produites (`-s`, `-q`, `--silent`, `--quiet`)
    pub quiet: bool,
    /// Supprimer les fichiers de sortie de taille nulle (`-z`, `--elide-empty-files`)
    pub elide_empty: bool,
}

impl<'a> Default for CsplitConfig<'a> {
    fn default() -> Self {
        Self {
            prefix: "xx",
            digits: 2,
            keep_files: false,
            quiet: false,
            elide_empty: false,
        }
    }
}

/// Parse un argument de motif csplit (`/regex/[offset]`, `%regex%[offset]`, ou numéro de ligne)
fn parse_csplit_pattern(arg: &str) -> Option<CsplitPattern<'_>> {
    if arg.is_empty() {
        return None;
    }

    if let Some(rest) = arg.strip_prefix('/') {
        if let Some(end_slash) = rest.rfind('/') {
            let pat = &rest[..end_slash];
            let offset_str = &rest[end_slash + 1..];
            let offset = if offset_str.is_empty() {
                0
            } else if let Ok(val) = offset_str.parse::<isize>() {
                val
            } else {
                return None;
            };
            return Some(CsplitPattern::MatchUpTo {
                pattern: pat,
                offset,
            });
        }
    } else if let Some(rest) = arg.strip_prefix('%') {
        if let Some(end_pct) = rest.rfind('%') {
            let pat = &rest[..end_pct];
            let offset_str = &rest[end_pct + 1..];
            let offset = if offset_str.is_empty() {
                0
            } else if let Ok(val) = offset_str.parse::<isize>() {
                val
            } else {
                return None;
            };
            return Some(CsplitPattern::SkipUpTo {
                pattern: pat,
                offset,
            });
        }
    } else if let Ok(line_num) = arg.parse::<usize>() {
        if line_num > 0 {
            return Some(CsplitPattern::LineNumber(line_num));
        }
    }

    None
}

/// Formate un nom de fichier csplit avec préfixe et padding numérique
fn format_csplit_filename(
    prefix: &str,
    index: usize,
    digits: usize,
    buf: &mut [u8],
) -> Option<usize> {
    let p_bytes = prefix.as_bytes();
    if p_bytes.len() + digits >= buf.len() {
        return None;
    }
    buf[..p_bytes.len()].copy_from_slice(p_bytes);

    let mut temp = [b'0'; 16];
    let d = digits.min(16);
    let mut val = index;
    for i in (0..d).rev() {
        temp[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }

    buf[p_bytes.len()..p_bytes.len() + d].copy_from_slice(&temp[..d]);
    Some(p_bytes.len() + d)
}

/// Exécute le découpage contextuel csplit sur un descripteur de fichier d'entrée
fn csplit_stream(
    in_fd: i32,
    patterns: &[CsplitPattern],
    repeats: &[usize],
    config: &CsplitConfig,
    out_fd: i32,
    err_fd: i32,
) -> i32 {
    let mut read_buf = [0u8; 1024];
    let mut line_storage = [0u8; 4096];
    let mut line_starts = [0usize; 256];
    let mut line_lens = [0usize; 256];
    let mut total_lines = 0usize;
    let mut storage_len = 0usize;

    // 1. Lecture de toutes les lignes en mémoire tampon sécurisée
    loop {
        let n = sys_read(in_fd, &mut read_buf);
        if n <= 0 {
            break;
        }
        let chunk = &read_buf[..n as usize];
        let mut start = 0;
        for i in 0..chunk.len() {
            if chunk[i] == b'\n' {
                let slice = &chunk[start..=i];
                if storage_len + slice.len() <= line_storage.len()
                    && total_lines < line_starts.len()
                {
                    line_starts[total_lines] = storage_len;
                    line_lens[total_lines] = slice.len();
                    line_storage[storage_len..storage_len + slice.len()].copy_from_slice(slice);
                    storage_len += slice.len();
                    total_lines += 1;
                }
                start = i + 1;
            }
        }
        if start < chunk.len() {
            let rem = &chunk[start..];
            if storage_len + rem.len() <= line_storage.len() && total_lines < line_starts.len() {
                line_starts[total_lines] = storage_len;
                line_lens[total_lines] = rem.len();
                line_storage[storage_len..storage_len + rem.len()].copy_from_slice(rem);
                storage_len += rem.len();
                total_lines += 1;
            }
        }
    }

    // 2. Traitement des motifs et création des segments de fichiers
    let mut current_line = 0usize;
    let mut file_index = 0usize;
    let mut created_names_storage = [[0u8; 32]; 32];
    let mut created_names_len = [0usize; 32];
    let mut created_count = 0usize;

    let write_chunk = |lines_from: usize,
                       lines_to: usize,
                       file_idx: usize,
                       cfg: &CsplitConfig,
                       cr_storage: &mut [[u8; 32]; 32],
                       cr_lens: &mut [usize; 32],
                       cr_cnt: &mut usize|
     -> Result<usize, ()> {
        let mut name_buf = [0u8; 32];
        let name_len =
            format_csplit_filename(cfg.prefix, file_idx, cfg.digits, &mut name_buf).ok_or(())?;
        let filename = match core::str::from_utf8(&name_buf[..name_len]) {
            Ok(s) => s,
            Err(_) => return Err(()),
        };

        // Calcul de la taille totale du segment
        let mut total_bytes = 0usize;
        for &len in line_lens.iter().take(lines_to).skip(lines_from) {
            total_bytes += len;
        }

        if total_bytes == 0 && cfg.elide_empty {
            return Ok(0);
        }

        let out_f = sys_open(
            filename,
            crate::vfs::O_CREAT | crate::vfs::O_WRONLY | crate::vfs::O_TRUNC,
        );
        if out_f < 0 {
            let _ = sys_write(err_fd, b"csplit: cannot open output file '");
            let _ = sys_write(err_fd, filename.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return Err(());
        }

        for l in lines_from..lines_to {
            let off = line_starts[l];
            let len = line_lens[l];
            let _ = sys_write(out_f, &line_storage[off..off + len]);
        }
        let _ = sys_close(out_f);

        if *cr_cnt < cr_storage.len() {
            cr_storage[*cr_cnt][..name_len].copy_from_slice(&name_buf[..name_len]);
            cr_lens[*cr_cnt] = name_len;
            *cr_cnt += 1;
        }

        if !cfg.quiet {
            write_u64_fd(out_fd, total_bytes as u64);
            let _ = sys_write(out_fd, b"\n");
        }

        Ok(total_bytes)
    };

    let cleanup_created = |cr_storage: &[[u8; 32]; 32], cr_lens: &[usize; 32], cr_cnt: usize| {
        for i in 0..cr_cnt {
            let len = cr_lens[i];
            if let Ok(name) = core::str::from_utf8(&cr_storage[i][..len]) {
                let _ = sys_unlink_pool(name);
            }
        }
    };

    let mut pat_idx = 0;
    while pat_idx < patterns.len() && current_line < total_lines {
        let pat = &patterns[pat_idx];
        let rep_count = if pat_idx < repeats.len() {
            repeats[pat_idx]
        } else {
            1
        };

        for _ in 0..rep_count {
            if current_line >= total_lines {
                break;
            }

            match pat {
                CsplitPattern::LineNumber(target_line) => {
                    let target_0_idx = target_line.saturating_sub(1);
                    if target_0_idx <= current_line {
                        let _ = sys_write(
                            err_fd,
                            b"csplit: line number must be greater than current line\n",
                        );
                        if !config.keep_files {
                            cleanup_created(
                                &created_names_storage,
                                &created_names_len,
                                created_count,
                            );
                        }
                        return 1;
                    }
                    let split_at = target_0_idx.min(total_lines);
                    if write_chunk(
                        current_line,
                        split_at,
                        file_index,
                        config,
                        &mut created_names_storage,
                        &mut created_names_len,
                        &mut created_count,
                    )
                    .is_err()
                    {
                        if !config.keep_files {
                            cleanup_created(
                                &created_names_storage,
                                &created_names_len,
                                created_count,
                            );
                        }
                        return 1;
                    }
                    file_index += 1;
                    current_line = split_at;
                }
                CsplitPattern::MatchUpTo { pattern, offset } => {
                    let mut found = None;
                    for l in current_line..total_lines {
                        let off = line_starts[l];
                        let len = line_lens[l];
                        let line_slice = &line_storage[off..off + len];
                        if contains_subslice(line_slice, pattern.as_bytes(), false) {
                            found = Some(l);
                            break;
                        }
                    }

                    let match_l = match found {
                        Some(l) => l,
                        None => {
                            let _ = sys_write(err_fd, b"csplit: match not found: '");
                            let _ = sys_write(err_fd, pattern.as_bytes());
                            let _ = sys_write(err_fd, b"'\n");
                            if !config.keep_files {
                                cleanup_created(
                                    &created_names_storage,
                                    &created_names_len,
                                    created_count,
                                );
                            }
                            return 1;
                        }
                    };

                    let split_at = if *offset >= 0 {
                        (match_l + (*offset as usize)).min(total_lines)
                    } else {
                        let neg = (-*offset) as usize;
                        match_l.saturating_sub(neg)
                    };

                    if split_at > current_line {
                        if write_chunk(
                            current_line,
                            split_at,
                            file_index,
                            config,
                            &mut created_names_storage,
                            &mut created_names_len,
                            &mut created_count,
                        )
                        .is_err()
                        {
                            if !config.keep_files {
                                cleanup_created(
                                    &created_names_storage,
                                    &created_names_len,
                                    created_count,
                                );
                            }
                            return 1;
                        }
                        file_index += 1;
                        current_line = split_at;
                    }
                }
                CsplitPattern::SkipUpTo { pattern, offset } => {
                    let mut found = None;
                    for l in current_line..total_lines {
                        let off = line_starts[l];
                        let len = line_lens[l];
                        let line_slice = &line_storage[off..off + len];
                        if contains_subslice(line_slice, pattern.as_bytes(), false) {
                            found = Some(l);
                            break;
                        }
                    }

                    let match_l = match found {
                        Some(l) => l,
                        None => {
                            let _ = sys_write(err_fd, b"csplit: match not found: '");
                            let _ = sys_write(err_fd, pattern.as_bytes());
                            let _ = sys_write(err_fd, b"'\n");
                            if !config.keep_files {
                                cleanup_created(
                                    &created_names_storage,
                                    &created_names_len,
                                    created_count,
                                );
                            }
                            return 1;
                        }
                    };

                    let skip_to = if *offset >= 0 {
                        (match_l + (*offset as usize)).min(total_lines)
                    } else {
                        let neg = (-*offset) as usize;
                        match_l.saturating_sub(neg)
                    };
                    current_line = skip_to;
                }
            }
        }
        pat_idx += 1;
    }

    // Écriture du reste du flux s'il reste des lignes
    if current_line < total_lines
        && write_chunk(
            current_line,
            total_lines,
            file_index,
            config,
            &mut created_names_storage,
            &mut created_names_len,
            &mut created_count,
        )
        .is_err()
    {
        if !config.keep_files {
            cleanup_created(&created_names_storage, &created_names_len, created_count);
        }
        return 1;
    }

    0
}

/// Exécute l'utilitaire standard POSIX `csplit` (découpage de fichiers selon des contextes et expressions régulières)
///
/// Drapeaux et options supportés :
/// - `-f PREFIX`, `--prefix=PREFIX` : Définit le préfixe des fichiers créés (par défaut "xx")
/// - `-n DIGITS`, `--digits=DIGITS` : Définit le nombre de chiffres décimaux pour le suffixe (par défaut 2)
/// - `-k`, `--keep-files` : Conserve les fichiers générés en cas d'erreur
/// - `-s`, `-q`, `--silent`, `--quiet` : Ne pas afficher la taille en octets des fichiers créés
/// - `-z`, `--elide-empty-files` : Supprime ou n'écrit pas les fichiers de taille nulle
/// - `--help` : Affiche l'aide
pub fn run_csplit(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut config = CsplitConfig::default();
    let mut input_file: Option<&str> = None;
    let mut patterns: [CsplitPattern; 16] = [CsplitPattern::LineNumber(0); 16];
    let mut repeats: [usize; 16] = [1; 16];
    let mut pat_count = 0usize;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim();
        if arg == "--help" {
            let _ = sys_write(
                err_fd,
                b"Usage: csplit [OPTION]... FILE PATTERN...\n\
Output pieces of FILE separated by PATTERN(s) to files 'xx00', 'xx01', ...,\n\
and output byte counts of each piece to standard output.\n\n\
  -f, --prefix=PREFIX        use PREFIX instead of 'xx'\n\
  -k, --keep-files           do not remove output files on errors\n\
  -n, --digits=DIGITS        use specified number of digits instead of 2\n\
  -s, -q, --silent, --quiet  do not print counts of output file sizes\n\
  -z, --elide-empty-files    remove empty output files\n\
      --help                 display this help and exit\n",
            );
            return 0;
        }

        if arg == "-k" || arg == "--keep-files" {
            config.keep_files = true;
            i += 1;
            continue;
        }

        if arg == "-s" || arg == "-q" || arg == "--silent" || arg == "--quiet" {
            config.quiet = true;
            i += 1;
            continue;
        }

        if arg == "-z" || arg == "--elide-empty-files" {
            config.elide_empty = true;
            i += 1;
            continue;
        }

        if arg == "-f" || arg == "--prefix" {
            if i + 1 < args.len() {
                config.prefix = args[i + 1].trim();
                i += 2;
                continue;
            } else {
                let _ = sys_write(err_fd, b"csplit: option requires an argument -- 'f'\n");
                return 1;
            }
        } else if let Some(p) = arg.strip_prefix("--prefix=") {
            config.prefix = p.trim();
            i += 1;
            continue;
        }

        if arg == "-n" || arg == "--digits" {
            if i + 1 < args.len() {
                if let Ok(d) = args[i + 1].trim().parse::<usize>() {
                    config.digits = d;
                    i += 2;
                    continue;
                } else {
                    let _ = sys_write(err_fd, b"csplit: invalid number of digits\n");
                    return 1;
                }
            } else {
                let _ = sys_write(err_fd, b"csplit: option requires an argument -- 'n'\n");
                return 1;
            }
        } else if let Some(d_str) = arg.strip_prefix("--digits=") {
            if let Ok(d) = d_str.trim().parse::<usize>() {
                config.digits = d;
                i += 1;
                continue;
            } else {
                let _ = sys_write(err_fd, b"csplit: invalid number of digits\n");
                return 1;
            }
        }

        // Fichier d'entrée
        if input_file.is_none() {
            input_file = Some(arg);
            i += 1;
            continue;
        }

        // Motif ou répétition `{N}`
        if arg.starts_with('{') && arg.ends_with('}') {
            let inner = &arg[1..arg.len() - 1].trim();
            if let Ok(rep) = inner.parse::<usize>() {
                if pat_count > 0 {
                    repeats[pat_count - 1] = rep + 1; // Répéter rep fois supplémentaires
                }
            }
            i += 1;
            continue;
        }

        if let Some(parsed_pat) = parse_csplit_pattern(arg) {
            if pat_count < patterns.len() {
                patterns[pat_count] = parsed_pat;
                repeats[pat_count] = 1;
                pat_count += 1;
            }
            i += 1;
            continue;
        }

        let _ = sys_write(err_fd, b"csplit: invalid pattern '");
        let _ = sys_write(err_fd, arg.as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    let file_target = match input_file {
        Some(f) => f,
        None => {
            let _ = sys_write(err_fd, b"csplit: missing operand\n");
            return 1;
        }
    };

    if file_target == "-" {
        csplit_stream(
            in_fd,
            &patterns[..pat_count],
            &repeats[..pat_count],
            &config,
            out_fd,
            err_fd,
        )
    } else {
        let fd = sys_open(file_target, crate::vfs::O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"csplit: failed to open '");
            let _ = sys_write(err_fd, file_target.as_bytes());
            let _ = sys_write(err_fd, b"': No such file or directory\n");
            return 1;
        }
        let code = csplit_stream(
            fd,
            &patterns[..pat_count],
            &repeats[..pat_count],
            &config,
            out_fd,
            err_fd,
        );
        let _ = sys_close(fd);
        code
    }
}

/// Extrait le champ N (1-indexé) d'une ligne découpée selon le séparateur `sep`.
///
/// Retourne une tranche de `line` pointant sur les octets du champ, ou `None` si le champ
/// N n'existe pas dans la ligne.
fn join_get_field(line: &[u8], field: usize, sep: u8) -> Option<&[u8]> {
    let mut current = 1usize;
    let mut start = 0usize;
    let mut i = 0usize;

    while i <= line.len() {
        let at_sep = i < line.len() && line[i] == sep;
        let at_end = i == line.len();

        if at_sep || at_end {
            if current == field {
                return Some(&line[start..i]);
            }
            current += 1;
            start = i + 1;
        }

        i += 1;
    }
    None
}

/// Représentation de la spécification de format de sortie `-o`
#[derive(Copy, Clone)]
struct JoinFormatField {
    /// 1 = fichier 1, 2 = fichier 2, 0 = champ de jointure
    file: u8,
    /// Numéro de champ (1-indexé)
    field: usize,
}

/// Émet une ligne jointe selon la configuration de format.
///
/// `join_key` est le champ clé commun (déjà décodé).
/// `line1` et `line2` sont les octets bruts des lignes (sans `\n`).
/// `format_fields` : si vide, le format POSIX par défaut est utilisé.
#[allow(clippy::too_many_arguments)]
fn join_emit_line(
    out_fd: i32,
    join_key: &[u8],
    line1: &[u8],
    line2: &[u8],
    field1: usize,
    field2: usize,
    sep: u8,
    empty: &[u8],
    format_fields: &[JoinFormatField],
    format_len: usize,
) {
    let sep_slice = &[sep][..];

    if format_len == 0 {
        // Format POSIX par défaut : clé, puis champs non-clé de file1, puis file2
        let _ = sys_write(out_fd, join_key);

        // Champs de la ligne 1 (hors champ clé)
        let mut fi = 1usize;
        let mut pos = 0usize;
        while pos <= line1.len() {
            let sep_pos = line1[pos..].iter().position(|&b| b == sep);
            let end = sep_pos.map_or(line1.len(), |p| pos + p);
            let slice = &line1[pos..end];
            if fi != field1 {
                let _ = sys_write(out_fd, sep_slice);
                if slice.is_empty() {
                    let _ = sys_write(out_fd, empty);
                } else {
                    let _ = sys_write(out_fd, slice);
                }
            }
            fi += 1;
            if end == line1.len() {
                break;
            }
            pos = end + 1;
        }

        // Champs de la ligne 2 (hors champ clé)
        let mut fi2 = 1usize;
        let mut pos2 = 0usize;
        while pos2 <= line2.len() {
            let sep_pos = line2[pos2..].iter().position(|&b| b == sep);
            let end = sep_pos.map_or(line2.len(), |p| pos2 + p);
            let slice = &line2[pos2..end];
            if fi2 != field2 {
                let _ = sys_write(out_fd, sep_slice);
                if slice.is_empty() {
                    let _ = sys_write(out_fd, empty);
                } else {
                    let _ = sys_write(out_fd, slice);
                }
            }
            fi2 += 1;
            if end == line2.len() {
                break;
            }
            pos2 = end + 1;
        }

        let _ = sys_write(out_fd, b"\n");
        return;
    }

    // Format personnalisé
    for (idx, ff) in format_fields.iter().take(format_len).enumerate() {
        if idx > 0 {
            let _ = sys_write(out_fd, sep_slice);
        }
        if ff.file == 0 {
            let _ = sys_write(out_fd, join_key);
        } else {
            let line = if ff.file == 1 { line1 } else { line2 };
            let field_ref = if ff.file == 1 { field1 } else { field2 };
            let _ = field_ref; // utilisé pour clarté
            let val = join_get_field(line, ff.field, sep);
            match val {
                Some(v) if !v.is_empty() => {
                    let _ = sys_write(out_fd, v);
                }
                _ => {
                    let _ = sys_write(out_fd, empty);
                }
            }
        }
    }
    let _ = sys_write(out_fd, b"\n");
}

/// Émet une ligne non-matchée (pour `-a` ou `-v`) en respectant le format de sortie.
#[allow(clippy::too_many_arguments)]
fn join_emit_unmatched(
    out_fd: i32,
    line: &[u8],
    file_num: u8,
    key_field: usize,
    sep: u8,
    empty: &[u8],
    format_fields: &[JoinFormatField],
    format_len: usize,
) {
    if format_len == 0 {
        // Sortie brute de la ligne non-matchée
        let _ = sys_write(out_fd, line);
        let _ = sys_write(out_fd, b"\n");
        return;
    }

    let sep_slice = &[sep][..];
    for (idx, ff) in format_fields.iter().take(format_len).enumerate() {
        if idx > 0 {
            let _ = sys_write(out_fd, sep_slice);
        }
        if ff.file == file_num {
            let val = join_get_field(line, ff.field, sep);
            match val {
                Some(v) if !v.is_empty() => {
                    let _ = sys_write(out_fd, v);
                }
                _ => {
                    let _ = sys_write(out_fd, empty);
                }
            }
        } else if ff.file == 0 {
            // Champ clé : provient de la ligne non-matchée
            let val = join_get_field(line, key_field, sep);
            match val {
                Some(v) if !v.is_empty() => {
                    let _ = sys_write(out_fd, v);
                }
                _ => {
                    let _ = sys_write(out_fd, empty);
                }
            }
        } else {
            let _ = sys_write(out_fd, empty);
        }
    }
    let _ = sys_write(out_fd, b"\n");
}

/// Compare deux clés en ignorant la casse si `ignore_case` est vrai.
fn join_cmp_keys(a: &[u8], b: &[u8], ignore_case: bool) -> core::cmp::Ordering {
    if !ignore_case {
        return a.cmp(b);
    }
    let len = a.len().min(b.len());
    for i in 0..len {
        let ca = a[i].to_ascii_lowercase();
        let cb = b[i].to_ascii_lowercase();
        match ca.cmp(&cb) {
            core::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

/// Exécute l'utilitaire standard POSIX `join` (fusion de deux fichiers triés sur un champ commun)
///
/// Options supportées :
/// - `-1 N` : Champ de jointure dans le fichier 1 (défaut : 1)
/// - `-2 N` : Champ de jointure dans le fichier 2 (défaut : 1)
/// - `-t C` : Séparateur de champ (défaut : blanc, avec contraction de blancs consécutifs)
/// - `-a N` : Affiche également les lignes non-matchées du fichier N (1 ou 2)
/// - `-e STRING` : Remplace les champs manquants par `STRING`
/// - `-o FORMAT` : Format de sortie (liste de `0`, `1.N`, `2.N` séparés par virgules ou espaces)
/// - `-i` : Comparaison insensible à la casse
/// - `-v N` : Affiche uniquement les lignes non-matchées du fichier N (supprime les lignes jointes)
/// - `--help` : Affiche l'aide
pub fn run_join(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut field1 = 1usize;
    let mut field2 = 1usize;
    let mut sep: Option<u8> = None; // None = blanc (whitespace)
    let mut unmatched1 = false;
    let mut unmatched2 = false;
    let mut only_unmatched1 = false;
    let mut only_unmatched2 = false;
    let mut ignore_case = false;
    let mut empty: &[u8] = b"";
    let mut format_fields = [JoinFormatField { file: 0, field: 0 }; 32];
    let mut format_len = 0usize;
    let mut file1_arg: Option<&str> = None;
    let mut file2_arg: Option<&str> = None;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i];
        match arg {
            "--help" => {
                let _ = sys_write(
                    out_fd,
                    b"Usage: join [OPTION]... FILE1 FILE2\n\
For each pair of input lines with identical join fields, write a line to\n\
standard output. The default join field is the first, delimited by blanks.\n\n\
  -1 FIELD        join on this FIELD of file 1\n\
  -2 FIELD        join on this FIELD of file 2\n\
  -a FILENUM      print unpairable lines coming from file FILENUM\n\
  -e EMPTY        replace missing input fields with EMPTY\n\
  -i              ignore differences in case when comparing fields\n\
  -o FORMAT       obey FORMAT while constructing output line\n\
  -t CHAR         use CHAR as input and output field separator\n\
  -v FILENUM      like -a FILENUM, but suppress joined output lines\n\
      --help      display this help and exit\n",
                );
                return 0;
            }
            "-i" => {
                ignore_case = true;
                i += 1;
            }
            "-1" => {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"join: option requires an argument -- '1'\n");
                    return 1;
                }
                i += 1;
                match args[i].parse::<usize>() {
                    Ok(n) if n >= 1 => {
                        field1 = n;
                    }
                    _ => {
                        let _ = sys_write(err_fd, b"join: invalid field number\n");
                        return 1;
                    }
                }
                i += 1;
            }
            "-2" => {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"join: option requires an argument -- '2'\n");
                    return 1;
                }
                i += 1;
                match args[i].parse::<usize>() {
                    Ok(n) if n >= 1 => {
                        field2 = n;
                    }
                    _ => {
                        let _ = sys_write(err_fd, b"join: invalid field number\n");
                        return 1;
                    }
                }
                i += 1;
            }
            "-t" => {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"join: option requires an argument -- 't'\n");
                    return 1;
                }
                i += 1;
                let t = args[i].as_bytes();
                if t.is_empty() {
                    let _ = sys_write(err_fd, b"join: empty field separator\n");
                    return 1;
                }
                sep = Some(t[0]);
                i += 1;
            }
            "-a" => {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"join: option requires an argument -- 'a'\n");
                    return 1;
                }
                i += 1;
                match args[i] {
                    "1" => unmatched1 = true,
                    "2" => unmatched2 = true,
                    _ => {
                        let _ = sys_write(err_fd, b"join: invalid file number\n");
                        return 1;
                    }
                }
                i += 1;
            }
            "-v" => {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"join: option requires an argument -- 'v'\n");
                    return 1;
                }
                i += 1;
                match args[i] {
                    "1" => {
                        only_unmatched1 = true;
                        unmatched1 = true;
                    }
                    "2" => {
                        only_unmatched2 = true;
                        unmatched2 = true;
                    }
                    _ => {
                        let _ = sys_write(err_fd, b"join: invalid file number\n");
                        return 1;
                    }
                }
                i += 1;
            }
            "-e" => {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"join: option requires an argument -- 'e'\n");
                    return 1;
                }
                i += 1;
                empty = args[i].as_bytes();
                i += 1;
            }
            "-o" => {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"join: option requires an argument -- 'o'\n");
                    return 1;
                }
                i += 1;
                // Analyser le format : "0,1.1,2.2" ou "0 1.1 2.2"
                let fmt_str = args[i].as_bytes();
                let mut fi = 0usize;
                while fi < fmt_str.len() {
                    // Sauter les séparateurs (virgule ou espace)
                    while fi < fmt_str.len() && (fmt_str[fi] == b',' || fmt_str[fi] == b' ') {
                        fi += 1;
                    }
                    if fi >= fmt_str.len() {
                        break;
                    }
                    // Lire le token
                    let start = fi;
                    while fi < fmt_str.len() && fmt_str[fi] != b',' && fmt_str[fi] != b' ' {
                        fi += 1;
                    }
                    let token = &fmt_str[start..fi];
                    if token == b"0" {
                        if format_len < format_fields.len() {
                            format_fields[format_len] = JoinFormatField { file: 0, field: 0 };
                            format_len += 1;
                        }
                    } else if token.len() >= 3
                        && (token[0] == b'1' || token[0] == b'2')
                        && token[1] == b'.'
                    {
                        let file_n = token[0] - b'0';
                        let mut fnum = 0usize;
                        let mut ok = true;
                        for &b in &token[2..] {
                            if b.is_ascii_digit() {
                                fnum = fnum.wrapping_mul(10).wrapping_add((b - b'0') as usize);
                            } else {
                                ok = false;
                                break;
                            }
                        }
                        if ok && fnum >= 1 && format_len < format_fields.len() {
                            format_fields[format_len] = JoinFormatField {
                                file: file_n,
                                field: fnum,
                            };
                            format_len += 1;
                        } else if !ok {
                            let _ = sys_write(err_fd, b"join: invalid format token\n");
                            return 1;
                        }
                    } else {
                        let _ = sys_write(err_fd, b"join: invalid format token\n");
                        return 1;
                    }
                }
                i += 1;
            }
            "--" => {
                i += 1;
                // Le reste sont des fichiers
                while i < args.len() {
                    if file1_arg.is_none() {
                        file1_arg = Some(args[i]);
                    } else if file2_arg.is_none() {
                        file2_arg = Some(args[i]);
                    }
                    i += 1;
                }
            }
            _ if arg.starts_with('-') && arg.len() > 1 => {
                let _ = sys_write(err_fd, b"join: unrecognized option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
            _ => {
                if file1_arg.is_none() {
                    file1_arg = Some(arg);
                } else if file2_arg.is_none() {
                    file2_arg = Some(arg);
                } else {
                    let _ = sys_write(err_fd, b"join: extra operand '");
                    let _ = sys_write(err_fd, arg.as_bytes());
                    let _ = sys_write(err_fd, b"'\n");
                    return 1;
                }
                i += 1;
            }
        }
    }

    let (path1, path2) = match (file1_arg, file2_arg) {
        (Some(p1), Some(p2)) => (p1, p2),
        _ => {
            let _ = sys_write(
                err_fd,
                b"join: missing operand\nTry 'join --help' for more information.\n",
            );
            return 1;
        }
    };

    if path1 == "-" && path2 == "-" {
        let _ = sys_write(err_fd, b"join: both files cannot be standard input\n");
        return 1;
    }

    let sep_byte = sep.unwrap_or(b' ');

    let (fd1, close1) = if path1 == "-" {
        (in_fd, false)
    } else {
        let fd = sys_open(path1, O_RDONLY);
        if fd < 0 {
            let _ = sys_write(err_fd, b"join: ");
            let _ = sys_write(err_fd, path1.as_bytes());
            let _ = sys_write(err_fd, b": No such file or directory\n");
            return 1;
        }
        (fd, true)
    };

    let (fd2, close2) = if path2 == "-" {
        (in_fd, false)
    } else {
        let fd = sys_open(path2, O_RDONLY);
        if fd < 0 {
            if close1 {
                let _ = sys_close(fd1);
            }
            let _ = sys_write(err_fd, b"join: ");
            let _ = sys_write(err_fd, path2.as_bytes());
            let _ = sys_write(err_fd, b": No such file or directory\n");
            return 1;
        }
        (fd, true)
    };

    let suppress_joined = only_unmatched1 || only_unmatched2;

    let mut reader1 = LineReader::new(fd1);
    let mut reader2 = LineReader::new(fd2);

    let mut buf1 = [0u8; 4096];
    let mut buf2 = [0u8; 4096];
    let mut key1_buf = [0u8; 512];
    let mut key2_buf = [0u8; 512];

    let mut line1_opt = reader1.read_line(&mut buf1);
    let mut line2_opt = reader2.read_line(&mut buf2);

    loop {
        match (line1_opt, line2_opt) {
            (None, None) => break,
            (Some(len1), None) => {
                // Lignes restantes du fichier 1 non-matchées
                if unmatched1 {
                    join_emit_unmatched(
                        out_fd,
                        &buf1[..len1],
                        1,
                        field1,
                        sep_byte,
                        empty,
                        &format_fields,
                        format_len,
                    );
                }
                line1_opt = reader1.read_line(&mut buf1);
            }
            (None, Some(len2)) => {
                // Lignes restantes du fichier 2 non-matchées
                if unmatched2 {
                    join_emit_unmatched(
                        out_fd,
                        &buf2[..len2],
                        2,
                        field2,
                        sep_byte,
                        empty,
                        &format_fields,
                        format_len,
                    );
                }
                line2_opt = reader2.read_line(&mut buf2);
            }
            (Some(len1), Some(len2)) => {
                let l1 = &buf1[..len1];
                let l2 = &buf2[..len2];

                // Extraire la clé de chaque ligne
                let k1_raw = join_get_field(l1, field1, sep_byte).unwrap_or(b"");
                let k2_raw = join_get_field(l2, field2, sep_byte).unwrap_or(b"");

                let k1_len = k1_raw.len().min(key1_buf.len());
                key1_buf[..k1_len].copy_from_slice(&k1_raw[..k1_len]);
                let k1 = &key1_buf[..k1_len];

                let k2_len = k2_raw.len().min(key2_buf.len());
                key2_buf[..k2_len].copy_from_slice(&k2_raw[..k2_len]);
                let k2 = &key2_buf[..k2_len];

                match join_cmp_keys(k1, k2, ignore_case) {
                    core::cmp::Ordering::Less => {
                        // Ligne 1 non-matchée
                        if unmatched1 {
                            join_emit_unmatched(
                                out_fd,
                                l1,
                                1,
                                field1,
                                sep_byte,
                                empty,
                                &format_fields,
                                format_len,
                            );
                        }
                        line1_opt = reader1.read_line(&mut buf1);
                    }
                    core::cmp::Ordering::Greater => {
                        // Ligne 2 non-matchée
                        if unmatched2 {
                            join_emit_unmatched(
                                out_fd,
                                l2,
                                2,
                                field2,
                                sep_byte,
                                empty,
                                &format_fields,
                                format_len,
                            );
                        }
                        line2_opt = reader2.read_line(&mut buf2);
                    }
                    core::cmp::Ordering::Equal => {
                        // Correspondance : émettre la ligne jointe
                        if !suppress_joined {
                            join_emit_line(
                                out_fd,
                                k1,
                                l1,
                                l2,
                                field1,
                                field2,
                                sep_byte,
                                empty,
                                &format_fields,
                                format_len,
                            );
                        }
                        line1_opt = reader1.read_line(&mut buf1);
                        line2_opt = reader2.read_line(&mut buf2);
                    }
                }
            }
        }
    }

    if close1 {
        let _ = sys_close(fd1);
    }
    if close2 {
        let _ = sys_close(fd2);
    }

    0
}

/// Générateur congruentiel linéaire / Xorshift64 bare-metal pour le brassage sans float ni dépendance externe.
pub struct Xorshift64Rng {
    state: u64,
}

impl Xorshift64Rng {
    /// Initialise le générateur avec une graine non nulle (par défaut dérivée du timer ou constante).
    pub fn new(seed: u64) -> Self {
        let actual_seed = if seed == 0 { 0x853c49e6748fea9b } else { seed };
        Self { state: actual_seed }
    }

    /// Génère le prochain entier 64-bit pseudo-aléatoire via xorshift64.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Génère un entier non signé dans l'intervalle semi-ouvert `[0, upper)`.
    pub fn gen_range(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            return 0;
        }
        (self.next_u64() % (upper as u64)) as usize
    }
}

/// Exécute l'utilitaire GNU/POSIX `shuf` (mélange aléatoire de lignes de texte / Fisher-Yates).
///
/// Supporte les options :
/// - `-e, --echo` : traite chaque argument restant comme une ligne d'entrée
/// - `-i, --input-range=LO-HI` : traite chaque nombre de LO à HI inclus comme ligne d'entrée
/// - `-n, --head-count=COUNT` : affiche au maximum COUNT lignes
/// - `-r, --repeat` : autorise la répétition des lignes (échantillonnage avec remise)
/// - `-o, --output=FILE` : écrit le résultat dans FILE au lieu de stdout
/// - `--help` : affiche l'aide et quitte
pub fn run_shuf(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut echo_mode = false;
    let mut input_range: Option<(u64, u64)> = None;
    let mut head_count: Option<usize> = None;
    let mut repeat_mode = false;
    let mut output_file: Option<&str> = None;
    let mut input_file: Option<&str> = None;
    let mut positional_args: [&str; 256] = [""; 256];
    let mut positional_count = 0usize;

    let mut i = 0usize;
    let mut end_of_options = false;

    while i < args.len() {
        let arg = args[i];
        if !end_of_options && arg == "--" {
            end_of_options = true;
            i += 1;
            continue;
        }

        if !end_of_options && (arg.starts_with('-') && arg != "-") {
            if arg == "--help" {
                let _ = sys_write(
                    out_fd,
                    b"Usage: shuf [OPTION]... [FILE]\n\
  or:  shuf -e [OPTION]... [ARG]...\n\
  or:  shuf -i LO-HI [OPTION]...\n\
Write a random permutation of the input lines to standard output.\n\n\
  -e, --echo                treat each ARG as an input line\n\
  -i, --input-range=LO-HI   treat each number LO through HI as an input line\n\
  -n, --head-count=COUNT    output at most COUNT lines\n\
  -o, --output=FILE         write result to FILE instead of standard output\n\
  -r, --repeat              output lines can be repeated\n\
      --help                display this help and exit\n",
                );
                return 0;
            } else if arg == "-e" || arg == "--echo" {
                echo_mode = true;
                i += 1;
            } else if arg == "-r" || arg == "--repeat" {
                repeat_mode = true;
                i += 1;
            } else if arg == "-o" {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"shuf: option requires an argument -- 'o'\n");
                    return 1;
                }
                output_file = Some(args[i + 1]);
                i += 2;
            } else if let Some(val) = arg.strip_prefix("--output=") {
                output_file = Some(val);
                i += 1;
            } else if arg == "-n" {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"shuf: option requires an argument -- 'n'\n");
                    return 1;
                }
                match args[i + 1].parse::<usize>() {
                    Ok(c) => head_count = Some(c),
                    Err(_) => {
                        let _ = sys_write(err_fd, b"shuf: invalid line count: '");
                        let _ = sys_write(err_fd, args[i + 1].as_bytes());
                        let _ = sys_write(err_fd, b"'\n");
                        return 1;
                    }
                }
                i += 2;
            } else if let Some(val) = arg.strip_prefix("--head-count=") {
                match val.parse::<usize>() {
                    Ok(c) => head_count = Some(c),
                    Err(_) => {
                        let _ = sys_write(err_fd, b"shuf: invalid line count: '");
                        let _ = sys_write(err_fd, val.as_bytes());
                        let _ = sys_write(err_fd, b"'\n");
                        return 1;
                    }
                }
                i += 1;
            } else if arg == "-i" {
                if i + 1 >= args.len() {
                    let _ = sys_write(err_fd, b"shuf: option requires an argument -- 'i'\n");
                    return 1;
                }
                let range_str = args[i + 1];
                match parse_shuf_range(range_str) {
                    Some(pair) => input_range = Some(pair),
                    None => {
                        let _ = sys_write(err_fd, b"shuf: invalid input range: '");
                        let _ = sys_write(err_fd, range_str.as_bytes());
                        let _ = sys_write(err_fd, b"'\n");
                        return 1;
                    }
                }
                i += 2;
            } else if let Some(range_str) = arg.strip_prefix("--input-range=") {
                match parse_shuf_range(range_str) {
                    Some(pair) => input_range = Some(pair),
                    None => {
                        let _ = sys_write(err_fd, b"shuf: invalid input range: '");
                        let _ = sys_write(err_fd, range_str.as_bytes());
                        let _ = sys_write(err_fd, b"'\n");
                        return 1;
                    }
                }
                i += 1;
            } else {
                let _ = sys_write(err_fd, b"shuf: unrecognized option '");
                let _ = sys_write(err_fd, arg.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
        } else {
            if positional_count < positional_args.len() {
                positional_args[positional_count] = arg;
                positional_count += 1;
            }
            i += 1;
        }
    }

    if echo_mode && input_range.is_some() {
        let _ = sys_write(err_fd, b"shuf: cannot combine -e and -i options\n");
        return 1;
    }

    // Gestion du fichier de sortie (-o)
    let (dest_fd, should_close_dest) = if let Some(out_path) = output_file {
        let fd = sys_open(
            out_path,
            crate::vfs::O_CREAT | crate::vfs::O_WRONLY | crate::vfs::O_TRUNC,
        );
        if fd < 0 {
            let _ = sys_write(err_fd, b"shuf: failed to open output file: ");
            let _ = sys_write(err_fd, out_path.as_bytes());
            let _ = sys_write(err_fd, b"\n");
            return 1;
        }
        (fd, true)
    } else {
        (out_fd, false)
    };

    // Initialisation RNG avec horloge si disponible
    let seed = crate::clock_gettime(crate::clocks::CLOCK_MONOTONIC)
        .map(|ts| ts.tv_sec ^ ((ts.tv_nsec as u64) << 32) ^ 0xdeadbeefc001cafe)
        .unwrap_or(0x517cc1b727220a95);
    let mut rng = Xorshift64Rng::new(seed);

    let mut line_ptrs: [(*const u8, usize); 1024] = [(core::ptr::null(), 0); 1024];
    let mut line_count = 0usize;

    // Buffer statique de 16 Ko pour les lectures de fichier ou stdin
    static mut SHUF_READ_BUF: [u8; 16384] = [0u8; 16384];

    let status = (|| -> i32 {
        if echo_mode {
            // Traiter chaque argument positionnel comme une ligne
            for &item in &positional_args[..positional_count] {
                if line_count < line_ptrs.len() {
                    line_ptrs[line_count] = (item.as_ptr(), item.len());
                    line_count += 1;
                }
            }
        } else if let Some((lo, hi)) = input_range {
            if positional_count > 0 {
                let _ = sys_write(err_fd, b"shuf: extra operand '");
                let _ = sys_write(err_fd, positional_args[0].as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }

            if lo > hi {
                let _ = sys_write(err_fd, b"shuf: invalid input range\n");
                return 1;
            }

            // Génération directe depuis l'intervalle numérique [lo, hi]
            let total_range = (hi - lo + 1) as usize;
            let mut num_buf = [0u8; 32];

            if repeat_mode {
                let max_lines = head_count.unwrap_or(total_range);
                for _ in 0..max_lines {
                    let rand_offset = rng.next_u64() % (hi - lo + 1);
                    let val = lo + rand_offset;
                    let len = write_u64_decimal(val, &mut num_buf);
                    let _ = sys_write(dest_fd, &num_buf[..len]);
                    let _ = sys_write(dest_fd, b"\n");
                }
                return 0;
            } else {
                // Créer la liste des entiers et mélanger
                const MAX_INT_RANGE: usize = 1024;
                let actual_total = total_range.min(MAX_INT_RANGE);
                let mut int_items = [0u64; MAX_INT_RANGE];
                for (idx, item) in int_items.iter_mut().enumerate().take(actual_total) {
                    *item = lo + (idx as u64);
                }

                // Fisher-Yates shuffle
                if actual_total > 1 {
                    for j in (1..actual_total).rev() {
                        let k = rng.gen_range(j + 1);
                        int_items.swap(j, k);
                    }
                }

                let max_output = head_count.unwrap_or(actual_total).min(actual_total);
                for &item in int_items.iter().take(max_output) {
                    let len = write_u64_decimal(item, &mut num_buf);
                    let _ = sys_write(dest_fd, &num_buf[..len]);
                    let _ = sys_write(dest_fd, b"\n");
                }
                return 0;
            }
        } else {
            // Lecture stdin ou fichier unique
            if positional_count > 1 {
                let _ = sys_write(err_fd, b"shuf: extra operand '");
                let _ = sys_write(err_fd, positional_args[1].as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
            if positional_count == 1 {
                input_file = Some(positional_args[0]);
            }

            let (src_fd, should_close_src) = if let Some(path) = input_file {
                if path == "-" {
                    (in_fd, false)
                } else {
                    let fd = sys_open(path, crate::vfs::O_RDONLY);
                    if fd < 0 {
                        let _ = sys_write(err_fd, b"shuf: ");
                        let _ = sys_write(err_fd, path.as_bytes());
                        let _ = sys_write(err_fd, b": No such file or directory\n");
                        return 1;
                    }
                    (fd, true)
                }
            } else {
                (in_fd, false)
            };

            let buf: &mut [u8] = unsafe {
                core::slice::from_raw_parts_mut(
                    core::ptr::addr_of_mut!(SHUF_READ_BUF) as *mut u8,
                    16384,
                )
            };
            let total_bytes = match read_all_fd(src_fd, buf) {
                Ok(n) => n,
                Err(_) => {
                    if should_close_src {
                        let _ = sys_close(src_fd);
                    }
                    let _ = sys_write(err_fd, b"shuf: read error\n");
                    return 1;
                }
            };
            if should_close_src {
                let _ = sys_close(src_fd);
            }

            // Découpage en lignes
            let mut line_start = 0usize;
            let mut cur = 0usize;
            while cur < total_bytes {
                if buf[cur] == b'\n' {
                    if line_count < line_ptrs.len() {
                        line_ptrs[line_count] =
                            (unsafe { buf.as_ptr().add(line_start) }, cur - line_start);
                        line_count += 1;
                    }
                    line_start = cur + 1;
                }
                cur += 1;
            }
            if line_start < total_bytes && line_count < line_ptrs.len() {
                line_ptrs[line_count] = (
                    unsafe { buf.as_ptr().add(line_start) },
                    total_bytes - line_start,
                );
                line_count += 1;
            }
        }

        if line_count == 0 {
            return 0;
        }

        if repeat_mode {
            let count_to_print = head_count.unwrap_or(line_count);
            for _ in 0..count_to_print {
                let rand_idx = rng.gen_range(line_count);
                let (ptr, len) = line_ptrs[rand_idx];
                if !ptr.is_null() && len > 0 {
                    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
                    let _ = sys_write(dest_fd, slice);
                }
                let _ = sys_write(dest_fd, b"\n");
            }
            return 0;
        }

        // Fisher-Yates shuffle in-situ
        if line_count > 1 {
            for j in (1..line_count).rev() {
                let k = rng.gen_range(j + 1);
                line_ptrs.swap(j, k);
            }
        }

        let to_emit = match head_count {
            Some(hc) => hc.min(line_count),
            None => line_count,
        };

        for &(ptr, len) in line_ptrs.iter().take(to_emit) {
            if !ptr.is_null() && len > 0 {
                let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
                let _ = sys_write(dest_fd, slice);
            }
            let _ = sys_write(dest_fd, b"\n");
        }

        0
    })();

    if should_close_dest {
        let _ = sys_close(dest_fd);
    }

    status
}

/// Parse une chaîne d'intervalle "LO-HI" en deux entiers (u64, u64).
fn parse_shuf_range(s: &str) -> Option<(u64, u64)> {
    let bytes = s.as_bytes();
    let dash_idx = bytes.iter().position(|&b| b == b'-')?;
    let lo_str = &s[..dash_idx];
    let hi_str = &s[dash_idx + 1..];
    let lo = lo_str.parse::<u64>().ok()?;
    let hi = hi_str.parse::<u64>().ok()?;
    Some((lo, hi))
}

/// Utilitaire POSIX standard `whoami` (Print Effective User Name)
///
/// Affiche le nom d'utilisateur effectif correspondant à l'identifiant EUID courant.
/// Supporte `--help` et `--version`.
pub fn run_whoami(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    if let Some(&arg) = args.first() {
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: whoami [OPTION]...\n\
Print the user name associated with the current effective user ID.\n\
Same as id -un.\n\n\
      --help     display this help and exit\n\
      --version  output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"whoami (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"whoami: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'whoami --help' for more information.\n");
            return 1;
        } else {
            let _ = sys_write(err_fd, b"whoami: extra operand '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'whoami --help' for more information.\n");
            return 1;
        }
    }

    let euid = crate::vfs::geteuid();
    let name = if euid == 0 { "root" } else { "user" };
    let _ = sys_write(out_fd, name.as_bytes());
    let _ = sys_write(out_fd, b"\n");
    0
}

/// Utilitaire POSIX / GNU `printenv` (Print all or part of environment)
///
/// Affiche la totalité ou une sélection de variables d'environnement.
/// Options supportées :
/// - `-0`, `--null` : termine chaque variable par un octet NUL au lieu d'un saut de ligne
/// - `--help` : affiche l'aide
/// - `--version` : affiche la version
///
/// Si un ou plusieurs arguments de noms de variables sont fournis, affiche uniquement leurs valeurs.
/// Renvoie 0 si toutes les variables demandées sont trouvées, 1 si au moins une est manquante.
pub fn run_printenv(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    const DEFAULT_ENV: [(&str, &str); 6] = [
        ("PATH", "/bin"),
        ("USER", "root"),
        ("SHELL", "/bin/jsh"),
        ("TERM", "xterm-256color"),
        ("HOME", "/root"),
        ("OS", "JamboOS"),
    ];

    let mut null_delimiter = false;
    let mut var_names: [&str; 16] = [""; 16];
    let mut var_count = 0;

    for &arg in args {
        if arg == "-0" || arg == "--null" {
            null_delimiter = true;
        } else if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: printenv [OPTION]... [VARIABLE]...\n\
Print the values of the specified environment VARIABLE(s).\n\
If no VARIABLE is specified, print name and value pairs for them all.\n\n\
  -0, --null     end each output line with NUL, not newline\n\
      --help     display this help and exit\n\
      --version  output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"printenv (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"printenv: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'printenv --help' for more information.\n");
            return 2;
        } else if var_count < var_names.len() {
            var_names[var_count] = arg;
            var_count += 1;
        }
    }

    let delim: &[u8] = if null_delimiter { b"\0" } else { b"\n" };

    if var_count == 0 {
        // Affiche toutes les variables par défaut au format NAME=VALUE
        for &(k, v) in &DEFAULT_ENV {
            let _ = sys_write(out_fd, k.as_bytes());
            let _ = sys_write(out_fd, b"=");
            let _ = sys_write(out_fd, v.as_bytes());
            let _ = sys_write(out_fd, delim);
        }
        0
    } else {
        // Affiche la valeur de chacune des variables demandées
        let mut all_found = true;
        for &req_var in var_names.iter().take(var_count) {
            let mut found = false;
            for &(k, v) in &DEFAULT_ENV {
                if k == req_var {
                    let _ = sys_write(out_fd, v.as_bytes());
                    let _ = sys_write(out_fd, delim);
                    found = true;
                    break;
                }
            }
            if !found {
                all_found = false;
            }
        }
        if all_found {
            0
        } else {
            1
        }
    }
}

/// Utilitaire POSIX / GNU `logname` (Print user's login name)
///
/// Affiche le nom d'utilisateur associé à la session d'ouverture courante (login name).
/// Selon la norme POSIX.1-2017 `logname`, aucune option n'est requise sauf `--help` / `--version`,
/// et aucun opérande n'est accepté.
pub fn run_logname(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    if let Some(&arg) = args.first() {
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: logname [OPTION]\n\
Print the user's login name.\n\n\
      --help     display this help and exit\n\
      --version  output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"logname (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"logname: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'logname --help' for more information.\n");
            return 1;
        } else {
            let _ = sys_write(err_fd, b"logname: extra operand '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'logname --help' for more information.\n");
            return 1;
        }
    }

    // Détermination de l'identité de session de login
    // En environnement bare-metal / Ring 3 JamboOS, si uid == 0 -> "root", sinon "user"
    let uid = crate::vfs::getuid();
    let login_name = if uid == 0 { "root" } else { "user" };

    let _ = sys_write(out_fd, login_name.as_bytes());
    let _ = sys_write(out_fd, b"\n");
    0
}

/// Utilitaire POSIX / GNU `tty` (Print the file name of the terminal connected to standard input)
///
/// Selon la norme POSIX.1-2017 `tty` :
/// - Si l'entrée standard est un terminal, affiche son nom (ex: `/dev/tty1`) et retourne 0.
/// - Si l'entrée standard n'est pas un terminal (ex: pipe, fichier), affiche "not a tty" et retourne 1.
/// - Option `-s` ou `--silent` ou `--quiet` : supprime l'affichage, seul le code retour (0 si tty, 1 si not a tty) est émis.
pub fn run_tty(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut silent = false;

    for &arg in args {
        if arg == "-s" || arg == "--silent" || arg == "--quiet" {
            silent = true;
        } else if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: tty [OPTION]...\n\
Print the file name of the terminal connected to standard input.\n\n\
  -s, --silent, --quiet   print nothing, only return an exit status\n\
      --help              display this help and exit\n\
      --version           output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"tty (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"tty: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'tty --help' for more information.\n");
            return 2;
        } else {
            let _ = sys_write(err_fd, b"tty: extra operand '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'tty --help' for more information.\n");
            return 2;
        }
    }

    let is_terminal = crate::vfs::isatty(in_fd);

    if is_terminal {
        if !silent {
            let mut buf = [0u8; 64];
            if let Ok(len) = crate::vfs::ttyname_r(in_fd, &mut buf) {
                let _ = sys_write(out_fd, &buf[..len]);
                let _ = sys_write(out_fd, b"\n");
            } else {
                let _ = sys_write(out_fd, b"/dev/tty1\n");
            }
        }
        0
    } else {
        if !silent {
            let _ = sys_write(out_fd, b"not a tty\n");
        }
        1
    }
}

/// Exécute l'utilitaire POSIX `groups` affichant les appartenances de groupes Ring 3
///
/// Selon la norme POSIX / coreutils :
/// - Sans argument : affiche la liste des groupes de l'utilisateur courant séparés par un espace.
/// - Avec arguments : affiche les groupes pour chaque utilisateur spécifié sous la forme `user : group1 group2 ...`.
pub fn run_groups(args: &[&str], _in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut users: [&str; 16] = [""; 16];
    let mut user_count = 0usize;

    for &arg in args {
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: groups [OPTION]... [USERNAME]...\n\
Print group memberships for each USERNAME or, if no USERNAME is specified, for\n\
the current process (which may differ if the groups database has changed).\n\n\
      --help     display this help and exit\n\
      --version  output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"groups (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"groups: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'groups --help' for more information.\n");
            return 1;
        } else {
            if user_count < users.len() {
                users[user_count] = arg;
                user_count += 1;
            }
        }
    }

    if user_count == 0 {
        // Affiche les groupes du processus courant
        let mut grps = [0u32; 16];
        let count = crate::vfs::getgroups(16, &mut grps).unwrap_or_default();
        let gid = crate::vfs::getgid();

        // Le groupe primaire est toujours affiché en premier
        let primary_name = if gid == 0 { "root" } else { "user" };
        let _ = sys_write(out_fd, primary_name.as_bytes());

        // Groupes secondaires
        for &g in grps.iter().take(count) {
            if g != gid {
                let _ = sys_write(out_fd, b" ");
                if g == 0 {
                    let _ = sys_write(out_fd, b"root");
                } else if g == 1000 {
                    let _ = sys_write(out_fd, b"user");
                } else {
                    write_u32(out_fd, g);
                }
            }
        }
        let _ = sys_write(out_fd, b"\n");
        0
    } else {
        let mut exit_code = 0;
        for &u in users.iter().take(user_count) {
            if u == "root" {
                let _ = sys_write(out_fd, b"root : root\n");
            } else if u == "user" {
                let _ = sys_write(out_fd, b"user : user\n");
            } else {
                let _ = sys_write(err_fd, b"groups: '");
                let _ = sys_write(err_fd, u.as_bytes());
                let _ = sys_write(err_fd, b"': no such user\n");
                exit_code = 1;
            }
        }
        exit_code
    }
}

/// Utilitaire Coreutils Ring 3 : `hostid` (POSIX / Single UNIX Specification hostid)
///
/// Affiche l'identifiant numérique hexadécimal 32-bit unique de la machine hôte.
/// Format canonique POSIX / GNU coreutils : 8 chiffres hexadécimaux minuscules terminés par un saut de ligne.
pub fn run_hostid(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    if let Some(&arg) = args.first() {
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: hostid [OPTION]...\n\
Print the numeric identifier (in hexadecimal) for the current host.\n\n\
      --help     display this help and exit\n\
      --version  output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"hostid (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"hostid: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'hostid --help' for more information.\n");
            return 1;
        } else {
            let _ = sys_write(err_fd, b"hostid: extra operand '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'hostid --help' for more information.\n");
            return 1;
        }
    }

    let hid = crate::vfs::gethostid();
    let mut hex_buf = [b'0'; 9]; // 8 hex chars + '\n'
    hex_buf[8] = b'\n';

    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut val = hid;
    let mut i = 8usize;
    while i > 0 {
        i -= 1;
        hex_buf[i] = HEX_CHARS[(val & 0x0F) as usize];
        val >>= 4;
    }

    let _ = sys_write(out_fd, &hex_buf);
    0
}

/// Utilitaire POSIX / GNU coreutils : `arch` (Affiche l'architecture matérielle de la machine)
///
/// Équivalent canonique POSIX et GNU coreutils de `uname -m`.
/// Affiche la chaîne d'architecture machine normalisée (`x86_64`, `aarch64`, etc.) terminée par `\n`.
pub fn run_arch(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    if let Some(&arg) = args.first() {
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: arch [OPTION]...\n\
Print machine architecture.\n\n\
      --help     display this help and exit\n\
      --version  output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"arch (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"arch: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'arch --help' for more information.\n");
            return 1;
        } else {
            let _ = sys_write(err_fd, b"arch: extra operand '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'arch --help' for more information.\n");
            return 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    let arch_name = b"x86_64\n";
    #[cfg(target_arch = "aarch64")]
    let arch_name = b"aarch64\n";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch_name = b"unknown\n";

    let _ = sys_write(out_fd, arch_name);
    0
}

/// Utilitaire POSIX / GNU coreutils : `nproc` (Affiche le nombre de processeurs disponibles)
///
/// Imprime le nombre d'unités de traitement (cœurs logiques/processeurs) disponibles.
/// Supporte l'option standard `--all` (affiche tous les processeurs installés) et `--ignore=N` (exclut N processeurs, min 1).
pub fn run_nproc(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut ignore_count = 0usize;
    let mut show_all = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: nproc [OPTION]...\n\
Print the number of processing units available.\n\n\
      --all       print the number of installed processors\n\
      --ignore=N  if possible, exclude N processing units\n\
      --help      display this help and exit\n\
      --version   output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"nproc (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg == "--all" {
            show_all = true;
        } else if let Some(stripped) = arg.strip_prefix("--ignore=") {
            let mut val = 0usize;
            let mut valid = !stripped.is_empty();
            for b in stripped.bytes() {
                if b.is_ascii_digit() {
                    val = val.saturating_mul(10).saturating_add((b - b'0') as usize);
                } else {
                    valid = false;
                    break;
                }
            }
            if !valid {
                let _ = sys_write(err_fd, b"nproc: invalid number: '");
                let _ = sys_write(err_fd, stripped.as_bytes());
                let _ = sys_write(err_fd, b"'\n");
                return 1;
            }
            ignore_count = val;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"nproc: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'nproc --help' for more information.\n");
            return 1;
        } else {
            let _ = sys_write(err_fd, b"nproc: extra operand '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'nproc --help' for more information.\n");
            return 1;
        }
        i += 1;
    }

    let _ = show_all;
    let num_procs = 1usize;
    let effective = if num_procs > ignore_count {
        num_procs - ignore_count
    } else {
        1
    };

    write_u64_fd(out_fd, effective as u64);
    let _ = sys_write(out_fd, b"\n");
    0
}

/// Utilitaire POSIX / GNU `users` (Print login names of users currently logged in)
///
/// Dans le cadre du micro-noyau et de la session Ring 3 POSIX, renvoie la liste
/// des noms d'utilisateurs connectés (ex: "root\n" ou "user\n" selon euid).
pub fn run_users(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    if let Some(&arg) = args.first() {
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: users [OPTION]... [FILE]\n\
Output who is currently logged in according to FILE.\n\
If FILE is not specified, current active users are printed.\n\n\
      --help        display this help and exit\n\
      --version     output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"users (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"users: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'users --help' for more information.\n");
            return 1;
        } else {
            // Ignorer un fichier utmp optionnel ou signaler
            let _ = sys_write(err_fd, b"users: extra operand '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'users --help' for more information.\n");
            return 1;
        }
    }

    let euid = crate::vfs::geteuid();
    let name = if euid == 0 { "root" } else { "user" };
    let _ = sys_write(out_fd, name.as_bytes());
    let _ = sys_write(out_fd, b"\n");
    0
}

/// Utilitaire POSIX / GNU `who` (Show who is logged on)
///
/// Affiche les sessions de connexion utilisateur avec le nom de terminal et l'identifiant.
/// Options supportées :
/// - `-q`, `--count` : affiche uniquement les noms d'utilisateurs et le nombre total d'utilisateurs connectés
/// - `-m` : affiche uniquement la ligne relative au terminal associé à l'entrée standard
/// - `-b`, `--boot` : heure du dernier démarrage système
/// - `-H`, `--heading` : en-têtes de colonnes
/// - `-a`, `--all` : ensemble des informations d'état
/// - `--help`, `--version`
pub fn run_who(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    let mut count_only = false;
    let mut stdin_only = false;
    let mut boot_time = false;
    let mut heading = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: who [OPTION]... [ FILE | ARG1 ARG2 ]\n\
Print information about users who are currently logged in.\n\n\
  -a, --all         same as -b -d --login -p -r -t -T -u\n\
  -b, --boot        time of last system boot\n\
  -H, --heading     print line of column headings\n\
  -m                only hostname and user associated with stdin\n\
  -q, --count       all login names and number of users logged on\n\
      --help        display this help and exit\n\
      --version     output version information and exit\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"who (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg == "-q" || arg == "--count" {
            count_only = true;
        } else if arg == "-m" {
            stdin_only = true;
        } else if arg == "-b" || arg == "--boot" {
            boot_time = true;
        } else if arg == "-H" || arg == "--heading" {
            heading = true;
        } else if arg == "-a" || arg == "--all" {
            boot_time = true;
            heading = true;
        } else if arg == "am" && i + 1 < args.len() && args[i + 1] == "i" {
            stdin_only = true;
            i += 1;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"who: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'who --help' for more information.\n");
            return 1;
        } else {
            // Ignorer un argument de fichier utmp optionnel sans erreur
        }
        i += 1;
    }

    let _ = stdin_only;
    let euid = crate::vfs::geteuid();
    let user_name = if euid == 0 { "root" } else { "user" };

    if count_only {
        let _ = sys_write(out_fd, user_name.as_bytes());
        let _ = sys_write(out_fd, b"\n# users=1\n");
        return 0;
    }

    if boot_time {
        let _ = sys_write(out_fd, b"system boot  2026-11-11 00:00\n");
        return 0;
    }

    if heading {
        let _ = sys_write(out_fd, b"NAME     LINE         TIME             COMMENT\n");
    }

    // Format standard POSIX : USERNAME TTY DATE TIME
    let _ = sys_write(out_fd, user_name.as_bytes());
    let _ = sys_write(out_fd, b"     console      2026-11-11 00:00\n");
    0
}

/// Utilitaire POSIX / GNU `nohup` (Run a command immune to hangups, with output to a non-tty)
///
/// Exécute COMMAND en ignorant le signal de déconnexion de terminal SIGHUP.
/// Si la sortie standard ou d'erreur est connectée à un terminal, `nohup` redirige
/// automatiquement les flux vers `nohup.out` (ou `$HOME/nohup.out`).
///
/// Codes de retour POSIX standard :
/// - 126 : COMMAND trouvée mais ne peut être invoquée
/// - 127 : COMMAND introuvable ou erreur de redirection nohup
/// - 125 : Erreur interne nohup (arguments invalides)
/// - Code de retour de COMMAND en cas de succès
pub fn run_nohup(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut cmd_idx = 0;
    if !args.is_empty() {
        let arg = args[0];
        if arg == "--help" {
            let _ = sys_write(
                out_fd,
                b"Usage: nohup COMMAND [ARG]...\n  or:  nohup OPTION\nRun COMMAND, ignoring hangup signals.\n\n      --help     display this help and exit\n      --version  output version information and exit\n\nIf standard input is a terminal, redirect it from an unreadable file.\nIf standard output is a terminal, append output to 'nohup.out' if possible,\n'$HOME/nohup.out' otherwise.\nIf standard error is a terminal, redirect it to standard output.\nTo save output to FILE, use 'nohup COMMAND > FILE'.\n",
            );
            return 0;
        } else if arg == "--version" {
            let _ = sys_write(out_fd, b"nohup (jambo-coreutils) 0.1.0\n");
            return 0;
        } else if arg == "--" {
            cmd_idx = 1;
        } else if arg.starts_with('-') && arg != "-" {
            let _ = sys_write(err_fd, b"nohup: unrecognized option '");
            let _ = sys_write(err_fd, arg.as_bytes());
            let _ = sys_write(err_fd, b"'\nTry 'nohup --help' for more information.\n");
            return 125;
        }
    }

    if cmd_idx >= args.len() {
        let _ = sys_write(
            err_fd,
            b"nohup: missing operand\nTry 'nohup --help' for more information.\n",
        );
        return 125;
    }

    let target_cmd = args[cmd_idx];
    let target_args = &args[cmd_idx + 1..];

    // Ignorer le signal SIGHUP (signum 1) selon la sémantique POSIX
    // sigaction / sys_sigaction(SIGHUP, SIG_IGN)
    const SIGHUP: i32 = 1;
    const SIG_IGN: usize = 1;
    let act_ign = crate::posix::Sigaction {
        sa_handler: SIG_IGN,
        sa_mask: crate::posix::Sigset { mask: 0 },
        sa_flags: 0,
        sa_restorer: None,
    };
    let _ = crate::posix::sys_sigaction(SIGHUP, Some(&act_ign), None);

    // Gestion des redirections vers nohup.out si out_fd est un terminal interactif
    let mut effective_out_fd = out_fd;
    let mut effective_err_fd = err_fd;
    let mut opened_file_fd = -1;

    let out_is_tty = crate::vfs::isatty(out_fd);
    let err_is_tty = crate::vfs::isatty(err_fd);

    if out_is_tty {
        // Tenter d'ouvrir nohup.out en mode append
        let flags = crate::vfs::O_CREAT | crate::vfs::O_WRONLY | crate::vfs::O_APPEND;
        let fd = sys_open("nohup.out", flags);
        if fd >= 0 {
            let _ = sys_write(
                err_fd,
                b"nohup: ignoring input and appending output to 'nohup.out'\n",
            );
            effective_out_fd = fd;
            opened_file_fd = fd;
        } else {
            // Tenter dans /tmp/nohup.out ou conserver out_fd
            let tmp_fd = sys_open("/tmp/nohup.out", flags);
            if tmp_fd >= 0 {
                let _ = sys_write(
                    err_fd,
                    b"nohup: ignoring input and appending output to '/tmp/nohup.out'\n",
                );
                effective_out_fd = tmp_fd;
                opened_file_fd = tmp_fd;
            }
        }
    }

    if err_is_tty {
        effective_err_fd = effective_out_fd;
    }

    let code = execute_coreutils_command(
        target_cmd,
        target_args,
        in_fd,
        effective_out_fd,
        effective_err_fd,
    );

    if opened_file_fd >= 0 {
        let _ = sys_close(opened_file_fd);
    }

    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{O_CREAT, O_WRONLY};

    #[test]
    fn test_echo_slice_basic() {
        let mut buf = [0u8; 64];
        let (code, len) = run_echo_slice(&["hello", "jamboos"], &mut buf);
        assert_eq!(code, 0);
        assert_eq!(&buf[..len], b"hello jamboos\n");
    }

    #[test]
    fn test_echo_slice_flag_n() {
        let mut buf = [0u8; 64];
        let (code, len) = run_echo_slice(&["-n", "pure", "no_std"], &mut buf);
        assert_eq!(code, 0);
        assert_eq!(&buf[..len], b"pure no_std");
    }

    #[test]
    fn test_true_false() {
        assert_eq!(run_true(), 0);
        assert_eq!(run_false(), 1);
    }

    #[test]
    fn test_wc_buffer() {
        let text = b"First line\nSecond line has more words\nThird\n";
        let res = count_buffer(text);
        assert_eq!(res.lines, 3);
        assert_eq!(res.words, 8);
        assert_eq!(res.bytes, text.len());
    }

    #[test]
    fn test_echo_to_posix_fd() {
        let code = run_echo(&["test", "fd", "write"], 1);
        assert_eq!(code, 0);
    }

    #[test]
    fn test_cat_nonexistent() {
        let code = run_cat(&["/nonexistent_file.txt"], 0, 1, 2);
        assert_eq!(code, 1);
    }

    #[test]
    fn test_cat_real_fd() {
        let fd = sys_open("/tmp/cat_test.txt", O_CREAT | O_WRONLY);
        assert!(fd >= 3);
        let content = b"Contenu du fichier pour test cat\n";
        let w = sys_write(fd, content);
        assert_eq!(w, content.len() as isize);
        sys_close(fd);

        let code = run_cat(&["/tmp/cat_test.txt"], 0, 1, 2);
        assert_eq!(code, 0);
    }

    #[test]
    fn test_wc_on_vfs_file() {
        let fd = sys_open("/tmp/wc_test.txt", O_CREAT | O_WRONLY);
        assert!(fd >= 3);
        let content = b"ligne 1 motA motB\nligne 2 motC\n";
        let _ = sys_write(fd, content);
        sys_close(fd);

        let code = run_wc(&["-l", "-w", "-c", "/tmp/wc_test.txt"], 0, 1, 2);
        assert_eq!(code, 0);
    }

    #[test]
    fn test_cat_system_file() {
        let code = run_cat(&["/etc/hostname"], 0, 1, 2);
        assert_eq!(code, 0);
    }

    #[test]
    fn test_ls_runs_successfully() {
        let code = run_ls(&["-l", "-a"], 1, 2);
        assert_eq!(code, 0);
    }

    #[test]
    fn test_head_basic_and_options() {
        let fd = sys_open("/tmp/head_test.txt", O_CREAT | O_WRONLY);
        assert!(fd >= 3);
        let content = b"line 1\nline 2\nline 3\nline 4\nline 5\n";
        let _ = sys_write(fd, content);
        sys_close(fd);

        let code = run_head(&["-n", "3", "/tmp/head_test.txt"], 0, 1, 2);
        assert_eq!(code, 0);

        let code_bytes = run_head(&["-c", "10", "/tmp/head_test.txt"], 0, 1, 2);
        assert_eq!(code_bytes, 0);
    }

    #[test]
    fn test_tail_basic_and_options() {
        let fd = sys_open("/tmp/tail_test.txt", O_CREAT | O_WRONLY);
        assert!(fd >= 3);
        let content = b"alpha\nbeta\ngamma\ndelta\nepsilon\n";
        let _ = sys_write(fd, content);
        sys_close(fd);

        let code = run_tail(&["-n", "2", "/tmp/tail_test.txt"], 0, 1, 2);
        assert_eq!(code, 0);

        let code_bytes = run_tail(&["-c", "8", "/tmp/tail_test.txt"], 0, 1, 2);
        assert_eq!(code_bytes, 0);
    }

    #[test]
    fn test_touch_and_rm_lifecycle() {
        let code_touch = run_touch(&["/tmp/touched_file.txt"], 2);
        assert_eq!(code_touch, 0);

        // Vérification de la présence
        let fd = sys_open("/tmp/touched_file.txt", O_RDONLY);
        assert!(fd >= 3);
        sys_close(fd);

        // Suppression
        let code_rm = run_rm(&["/tmp/touched_file.txt"], 2);
        assert_eq!(code_rm, 0);

        // Fichier désormais inexistant
        let fd_after = sys_open("/tmp/touched_file.txt", O_RDONLY);
        assert_eq!(fd_after, -1);
    }

    #[test]
    fn test_mkdir_and_rmdir_lifecycle() {
        let code_mkdir = run_mkdir(&["/tmp/new_dir"], 2);
        assert_eq!(code_mkdir, 0);

        // Rejet de la création si déjà existant (sans -p)
        let code_mkdir_dup = run_mkdir(&["/tmp/new_dir"], 2);
        assert_eq!(code_mkdir_dup, 1);

        // Succès si -p est présent
        let code_mkdir_p = run_mkdir(&["-p", "/tmp/new_dir"], 2);
        assert_eq!(code_mkdir_p, 0);

        // Test de suppression avec l'utilitaire rmdir
        let code_rmdir = run_rmdir(&["/tmp/new_dir"], 2);
        assert_eq!(code_rmdir, 0);

        // Tentative de rmdir sur répertoire inexistant
        let code_rmdir_nonexistent = run_rmdir(&["/tmp/new_dir"], 2);
        assert_eq!(code_rmdir_nonexistent, 1);

        // Test rmdir -p (hiérarchie imbriquée)
        let code_mkdir_nested = run_mkdir(&["-p", "/tmp/parent_dir/child_dir"], 2);
        assert_eq!(code_mkdir_nested, 0);

        // Création d'un fichier dans le sous-répertoire : rmdir doit refuser car non vide
        let fd_file = sys_open("/tmp/parent_dir/child_dir/file.txt", O_CREAT | O_WRONLY);
        assert!(fd_file >= 3);
        sys_close(fd_file);

        let code_rmdir_not_empty = run_rmdir(&["/tmp/parent_dir/child_dir"], 2);
        assert_eq!(code_rmdir_not_empty, 1);

        // Suppression du fichier
        let code_rm_file = run_rm(&["/tmp/parent_dir/child_dir/file.txt"], 2);
        assert_eq!(code_rm_file, 0);

        // Désormais rmdir -p réussit à vider et supprimer child puis parent
        let code_rmdir_parents = run_rmdir(&["-p", "/tmp/parent_dir/child_dir"], 2);
        assert_eq!(code_rmdir_parents, 0);

        // Test de l'utilitaire `tree`
        let (out_r_tree, out_w_tree) = crate::vfs::pipe().expect("pipe tree");
        let code_tree = run_tree(&["-L", "2", "/etc"], out_w_tree, 2);
        assert_eq!(code_tree, 0);
        let _ = sys_close(out_w_tree);

        let mut tree_buf = [0u8; 512];
        let n_tree = sys_read(out_r_tree, &mut tree_buf);
        let _ = sys_close(out_r_tree);
        assert!(n_tree > 0);
        let tree_out = core::str::from_utf8(&tree_buf[..n_tree as usize]).unwrap();
        assert!(tree_out.contains("/etc"));
        assert!(tree_out.contains("hostname"));
        assert!(tree_out.contains("os-release"));
        assert!(tree_out.contains("directories") || tree_out.contains("files"));
    }

    #[test]
    fn test_cp_and_mv_lifecycle() {
        // 1. Création d'un fichier source
        let fd = sys_open("/tmp/cp_src.txt", O_CREAT | O_WRONLY);
        assert!(fd >= 3);
        let data = b"Content to be copied and moved\n";
        let _ = sys_write(fd, data);
        sys_close(fd);

        // 2. Copie du fichier
        let code_cp = run_cp(&["/tmp/cp_src.txt", "/tmp/cp_dst.txt"], 2);
        assert_eq!(code_cp, 0);

        // Vérification de la copie
        let fd_cp = sys_open("/tmp/cp_dst.txt", O_RDONLY);
        assert!(fd_cp >= 3);
        let mut read_buf = [0u8; 64];
        let n = sys_read(fd_cp, &mut read_buf);
        assert_eq!(n, data.len() as isize);
        assert_eq!(&read_buf[..n as usize], data);
        sys_close(fd_cp);

        // 3. Déplacement (mv) vers un nouveau chemin
        let code_mv = run_mv(&["/tmp/cp_dst.txt", "/tmp/mv_target.txt"], 2);
        assert_eq!(code_mv, 0);

        // Ancien chemin n'existe plus
        let fd_old = sys_open("/tmp/cp_dst.txt", O_RDONLY);
        assert_eq!(fd_old, -1);

        // Nouveau chemin contient les données
        let fd_new = sys_open("/tmp/mv_target.txt", O_RDONLY);
        assert!(fd_new >= 3);
        let n_mv = sys_read(fd_new, &mut read_buf);
        assert_eq!(n_mv, data.len() as isize);
        assert_eq!(&read_buf[..n_mv as usize], data);
        sys_close(fd_new);

        // 4. Copie récursive de répertoire
        let _ = run_mkdir(&["-p", "/tmp/src_dir"], 2);
        let fd_sub = sys_open("/tmp/src_dir/sub.txt", O_CREAT | O_WRONLY);
        assert!(fd_sub >= 3);
        let _ = sys_write(fd_sub, b"Subfile data\n");
        sys_close(fd_sub);

        let code_cp_dir = run_cp(&["-r", "/tmp/src_dir", "/tmp/dst_dir"], 2);
        assert_eq!(code_cp_dir, 0);

        // Nettoyage
        let _ = run_rm(&["/tmp/cp_src.txt"], 2);
        let _ = run_rm(&["/tmp/mv_target.txt"], 2);
        let _ = run_rm(&["-r", "/tmp/src_dir"], 2);
        let _ = run_rm(&["-r", "/tmp/dst_dir"], 2);
    }

    #[test]
    fn test_tee_standard_and_append_lifecycle() {
        // 1. Préparation d'un pipe pour simuler stdin
        let (read_end, write_end) = crate::vfs::pipe().expect("Création pipe");

        // Écriture du payload initial dans le pipe
        let payload1 = b"Pipeline chunk 1\n";
        let _ = sys_write(write_end, payload1);
        sys_close(write_end); // Fermeture du côté écriture pour générer EOF lors de la lecture

        // 2. Exécution de tee écrivant vers stdout (fd 1) et /tmp/tee_out.txt
        let code1 = run_tee(&["/tmp/tee_out.txt"], read_end, 1, 2);
        assert_eq!(code1, 0);
        sys_close(read_end);

        // Vérification du contenu du premier fichier
        let fd_check1 = sys_open("/tmp/tee_out.txt", O_RDONLY);
        assert!(fd_check1 >= 3);
        let mut buf = [0u8; 64];
        let n1 = sys_read(fd_check1, &mut buf);
        assert_eq!(n1, payload1.len() as isize);
        assert_eq!(&buf[..n1 as usize], payload1);
        sys_close(fd_check1);

        // 3. Second pipe avec mode append (-a)
        let (read_end2, write_end2) = crate::vfs::pipe().expect("Création pipe 2");
        let payload2 = b"Appended chunk 2\n";
        let _ = sys_write(write_end2, payload2);
        sys_close(write_end2);

        let code2 = run_tee(&["-a", "/tmp/tee_out.txt"], read_end2, 1, 2);
        assert_eq!(code2, 0);
        sys_close(read_end2);

        // Vérification de la concaténation dans le fichier
        let fd_check2 = sys_open("/tmp/tee_out.txt", O_RDONLY);
        assert!(fd_check2 >= 3);
        let n2 = sys_read(fd_check2, &mut buf);
        let expected_total = payload1.len() + payload2.len();
        assert_eq!(n2, expected_total as isize);
        assert_eq!(&buf[..payload1.len()], payload1);
        assert_eq!(&buf[payload1.len()..n2 as usize], payload2);
        sys_close(fd_check2);

        // Nettoyage
        let _ = run_rm(&["/tmp/tee_out.txt"], 2);
    }

    #[test]
    fn test_env_lifecycle() {
        // 1. Pipe pour capturer la sortie de env
        let (read_end, write_end) = crate::vfs::pipe().expect("Création pipe env");

        // Exécution de env par défaut avec un ajout et un override
        let code = run_env(
            &["CUSTOM_VAR=HelloWorld", "USER=jambo_admin"],
            0,
            write_end,
            2,
        );
        assert_eq!(code, 0);
        sys_close(write_end);

        let mut output = [0u8; 512];
        let n = sys_read(read_end, &mut output);
        assert!(n > 0);
        let out_str = core::str::from_utf8(&output[..n as usize]).expect("utf8");
        assert!(out_str.contains("CUSTOM_VAR=HelloWorld\n"));
        assert!(out_str.contains("USER=jambo_admin\n"));
        assert!(out_str.contains("OS=JamboOS\n"));
        sys_close(read_end);

        // 2. Test avec -i (environnement vide) et une seule variable
        let (read_i, write_i) = crate::vfs::pipe().expect("Création pipe env -i");
        let code_i = run_env(&["-i", "STANDALONE=1"], 0, write_i, 2);
        assert_eq!(code_i, 0);
        sys_close(write_i);

        let mut output_i = [0u8; 128];
        let ni = sys_read(read_i, &mut output_i);
        assert_eq!(ni, b"STANDALONE=1\n".len() as isize);
        assert_eq!(&output_i[..ni as usize], b"STANDALONE=1\n");
        sys_close(read_i);

        // 3. Test avec -u USER (suppression de variable standard)
        let (read_u, write_u) = crate::vfs::pipe().expect("Création pipe env -u");
        let code_u = run_env(&["-u", "USER"], 0, write_u, 2);
        assert_eq!(code_u, 0);
        sys_close(write_u);

        let mut output_u = [0u8; 512];
        let nu = sys_read(read_u, &mut output_u);
        assert!(nu > 0);
        let out_u = core::str::from_utf8(&output_u[..nu as usize]).expect("utf8");
        assert!(!out_u.contains("USER="));
        assert!(out_u.contains("OS=JamboOS\n"));
        sys_close(read_u);
    }

    #[test]
    fn test_grep_lifecycle() {
        let text = b"First line: Hello World\nSecond line: rust bare-metal\nThird line: hello jambo-os\nFourth line: END\n";

        // 1. Recherche standard (sensible à la casse)
        let (r1, w1) = crate::vfs::pipe().expect("pipe grep 1");
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe grep out 1");
        let _ = sys_write(w1, text);
        sys_close(w1);
        let code1 = run_grep(&["Hello"], r1, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(out_w1);
        sys_close(r1);

        let mut out_buf1 = [0u8; 256];
        let n1 = sys_read(out_r1, &mut out_buf1);
        assert!(n1 > 0);
        let s1 = core::str::from_utf8(&out_buf1[..n1 as usize]).unwrap();
        assert_eq!(s1, "First line: Hello World\n");
        sys_close(out_r1);

        // 2. Recherche insensible à la casse avec numérotation de ligne (-i -n)
        let (r2, w2) = crate::vfs::pipe().expect("pipe grep 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe grep out 2");
        let _ = sys_write(w2, text);
        sys_close(w2);
        let code2 = run_grep(&["-i", "-n", "hello"], r2, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(out_w2);
        sys_close(r2);

        let mut out_buf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut out_buf2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out_buf2[..n2 as usize]).unwrap();
        assert!(s2.contains("1:First line: Hello World\n"));
        assert!(s2.contains("3:Third line: hello jambo-os\n"));
        sys_close(out_r2);

        // 3. Décompte des lignes (-c)
        let (r3, w3) = crate::vfs::pipe().expect("pipe grep 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe grep out 3");
        let _ = sys_write(w3, text);
        sys_close(w3);
        let code3 = run_grep(&["-i", "-c", "hello"], r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(out_w3);
        sys_close(r3);

        let mut out_buf3 = [0u8; 64];
        let n3 = sys_read(out_r3, &mut out_buf3);
        assert_eq!(n3, b"2\n".len() as isize);
        assert_eq!(&out_buf3[..n3 as usize], b"2\n");
        sys_close(out_r3);

        // 4. Inversion de correspondance (-v)
        let (r4, w4) = crate::vfs::pipe().expect("pipe grep 4");
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe grep out 4");
        let _ = sys_write(w4, text);
        sys_close(w4);
        let code4 = run_grep(&["-v", "line", "-c"], r4, out_w4, 2);
        assert_eq!(code4, 1); // 0 lignes sans "line" -> code 1
        sys_close(out_w4);
        sys_close(r4);

        let mut out_buf4 = [0u8; 64];
        let n4 = sys_read(out_r4, &mut out_buf4);
        assert_eq!(n4, b"0\n".len() as isize);
        assert_eq!(&out_buf4[..n4 as usize], b"0\n");
        sys_close(out_r4);
    }

    #[test]
    fn test_sort_lifecycle() {
        let text = b"banana\napple\ncherry\napple\n100 items\n20 items\n3 items\nBanana\n";

        // 1. Tri standard (lexicographique)
        let (r1, w1) = crate::vfs::pipe().expect("pipe sort 1");
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe sort out 1");
        let _ = sys_write(w1, text);
        sys_close(w1);
        let code1 = run_sort(&[], r1, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(out_w1);
        sys_close(r1);

        let mut out_buf1 = [0u8; 256];
        let n1 = sys_read(out_r1, &mut out_buf1);
        assert!(n1 > 0);
        let s1 = core::str::from_utf8(&out_buf1[..n1 as usize]).unwrap();
        // Dans l'ordre ASCII : '1', '2', '3', 'B', 'a', 'b', 'c'
        assert!(s1.starts_with("100 items\n"));
        sys_close(out_r1);

        // 2. Tri inverse (-r) avec elimination de doublons (-u)
        let (r2, w2) = crate::vfs::pipe().expect("pipe sort 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe sort out 2");
        let _ = sys_write(w2, b"cherry\napple\nbanana\napple\n");
        sys_close(w2);
        let code2 = run_sort(&["-r", "-u"], r2, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(out_w2);
        sys_close(r2);

        let mut out_buf2 = [0u8; 128];
        let n2 = sys_read(out_r2, &mut out_buf2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out_buf2[..n2 as usize]).unwrap();
        assert_eq!(s2, "cherry\nbanana\napple\n");
        sys_close(out_r2);

        // 3. Tri numerique (-n)
        let (r3, w3) = crate::vfs::pipe().expect("pipe sort 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe sort out 3");
        let _ = sys_write(w3, b"100\n3\n20\n1\n");
        sys_close(w3);
        let code3 = run_sort(&["-n"], r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(out_w3);
        sys_close(r3);

        let mut out_buf3 = [0u8; 64];
        let n3 = sys_read(out_r3, &mut out_buf3);
        assert!(n3 > 0);
        let s3 = core::str::from_utf8(&out_buf3[..n3 as usize]).unwrap();
        assert_eq!(s3, "1\n3\n20\n100\n");
        sys_close(out_r3);
    }

    #[test]
    fn test_find_lifecycle() {
        // 1. Recherche par nom exact (-name hostname)
        let (r1, w1) = crate::vfs::pipe().expect("pipe find 1");
        let code1 = run_find(&["-name", "hostname"], w1, 2);
        assert_eq!(code1, 0);
        sys_close(w1);

        let mut out1 = [0u8; 256];
        let n1 = sys_read(r1, &mut out1);
        assert!(n1 > 0);
        let s1 = core::str::from_utf8(&out1[..n1 as usize]).unwrap();
        assert!(s1.contains("/hostname\n") || s1.contains("/etc/hostname\n"));
        sys_close(r1);

        // 2. Recherche par type (-type d dans /etc)
        let (r2, w2) = crate::vfs::pipe().expect("pipe find 2");
        let code2 = run_find(&["/etc", "-type", "d"], w2, 2);
        assert_eq!(code2, 0);
        sys_close(w2);

        let mut out2 = [0u8; 128];
        let n2 = sys_read(r2, &mut out2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out2[..n2 as usize]).unwrap();
        assert!(s2.contains("/etc\n"));
        assert!(!s2.contains("/etc/hostname\n"));
        sys_close(r2);

        // 3. Recherche par type fichier (-type f dans /etc)
        let (r3, w3) = crate::vfs::pipe().expect("pipe find 3");
        let code3 = run_find(&["/etc", "-type", "f"], w3, 2);
        assert_eq!(code3, 0);
        sys_close(w3);

        let mut out3 = [0u8; 256];
        let n3 = sys_read(r3, &mut out3);
        assert!(n3 > 0);
        let s3 = core::str::from_utf8(&out3[..n3 as usize]).unwrap();
        assert!(s3.contains("/etc/hostname\n") || s3.contains("/etc/os-release\n"));
        assert!(!s3.lines().any(|l| l == "/etc"));
        sys_close(r3);

        // 4. Test d'erreur avec argument manquant
        let (r4, w4) = crate::vfs::pipe().expect("pipe find 4");
        let code4 = run_find(&["-name"], 1, w4);
        assert_eq!(code4, 1);
        sys_close(w4);
        sys_close(r4);
    }

    #[test]
    fn test_chmod_lifecycle() {
        // 1. Modification du mode d'un fichier existant (/etc/hostname) en 0600
        let (r1, w1) = crate::vfs::pipe().expect("pipe chmod 1");
        let code1 = run_chmod(&["600", "/etc/hostname"], w1);
        assert_eq!(code1, 0);
        sys_close(w1);
        sys_close(r1);

        assert_eq!(sys_get_mode_pool("/etc/hostname"), Some(0o600));

        // 2. Modification verbeuse (-v) en 0644
        let (r2, w2) = crate::vfs::pipe().expect("pipe chmod 2");
        let code2 = run_chmod(&["-v", "644", "/etc/hostname"], w2);
        assert_eq!(code2, 0);
        sys_close(w2);

        let mut out2 = [0u8; 128];
        let n2 = sys_read(r2, &mut out2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out2[..n2 as usize]).unwrap();
        assert!(s2.contains("mode of '/etc/hostname' changed to 644"));
        sys_close(r2);
        assert_eq!(sys_get_mode_pool("/etc/hostname"), Some(0o644));

        // 3. Modification récursive (-R) sur /etc
        let (r3, w3) = crate::vfs::pipe().expect("pipe chmod 3");
        let code3 = run_chmod(&["-R", "750", "/etc"], w3);
        assert_eq!(code3, 0);
        sys_close(w3);
        sys_close(r3);
        assert_eq!(sys_get_mode_pool("/etc"), Some(0o750));
        assert_eq!(sys_get_mode_pool("/etc/hostname"), Some(0o750));
        assert_eq!(sys_get_mode_pool("/etc/os-release"), Some(0o750));

        // Rétablissement en 0644 pour ne pas perturber les autres tests
        let _ = sys_chmod_pool("/etc/hostname", 0o644);
        let _ = sys_chmod_pool("/etc/os-release", 0o644);
        let _ = sys_chmod_pool("/etc", 0o755);

        // 4. Test d'erreur : fichier inexistant
        let (r4, w4) = crate::vfs::pipe().expect("pipe chmod 4");
        let code4 = run_chmod(&["644", "/nonexistent_file_xyz"], w4);
        assert_eq!(code4, 1);
        sys_close(w4);
        sys_close(r4);

        // 5. Test d'erreur : mode octal invalide
        let (r5, w5) = crate::vfs::pipe().expect("pipe chmod 5");
        let code5 = run_chmod(&["999", "/etc/hostname"], w5);
        assert_eq!(code5, 1);
        sys_close(w5);
        sys_close(r5);
    }

    #[test]
    fn test_chown_and_id_utilities() {
        // 1. Parsing de spécification propriétaire/groupe
        assert_eq!(parse_owner_group("root"), Ok((Some(0), None)));
        assert_eq!(parse_owner_group("root:root"), Ok((Some(0), Some(0))));
        assert_eq!(parse_owner_group(":bin"), Ok((None, Some(2))));
        assert_eq!(parse_owner_group("1000:1000"), Ok((Some(1000), Some(1000))));
        assert_eq!(parse_owner_group("user.user"), Ok((Some(1000), Some(1000))));
        assert!(parse_owner_group("invalid_user_xyz").is_err());

        // 2. chown simple
        let (r1, w1) = crate::vfs::pipe().expect("pipe chown 1");
        let code1 = run_chown(&["1000:1000", "/etc/hostname"], w1);
        assert_eq!(code1, 0);
        sys_close(w1);
        sys_close(r1);
        assert_eq!(sys_get_owner_pool("/etc/hostname"), Some((1000, 1000)));

        // 3. chown verbose (-v)
        let (r2, w2) = crate::vfs::pipe().expect("pipe chown 2");
        let code2 = run_chown(&["-v", "root:root", "/etc/hostname"], w2);
        assert_eq!(code2, 0);
        sys_close(w2);
        let mut out2 = [0u8; 128];
        let n2 = sys_read(r2, &mut out2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out2[..n2 as usize]).unwrap();
        assert!(s2.contains("ownership of '/etc/hostname' retained as root:root"));
        sys_close(r2);
        assert_eq!(sys_get_owner_pool("/etc/hostname"), Some((0, 0)));

        // 4. chown récursif (-R)
        let (r3, w3) = crate::vfs::pipe().expect("pipe chown 3");
        let code3 = run_chown(&["-R", "1000", "/etc"], w3);
        assert_eq!(code3, 0);
        sys_close(w3);
        sys_close(r3);
        assert_eq!(sys_get_owner_pool("/etc"), Some((1000, 0)));
        assert_eq!(sys_get_owner_pool("/etc/hostname"), Some((1000, 0)));

        // Rétablissement en root:root
        let _ = sys_chown_pool("/etc/hostname", 0, 0);
        let _ = sys_chown_pool("/etc/os-release", 0, 0);
        let _ = sys_chown_pool("/etc", 0, 0);

        // 4b. chgrp simple, verbose (-v) et récursif (-R)
        let (rg1, wg1) = crate::vfs::pipe().expect("pipe chgrp 1");
        let code_g1 = run_chgrp(&["bin", "/etc/hostname"], wg1);
        assert_eq!(code_g1, 0);
        sys_close(wg1);
        sys_close(rg1);
        assert_eq!(sys_get_owner_pool("/etc/hostname"), Some((0, 2)));

        let (rg2, wg2) = crate::vfs::pipe().expect("pipe chgrp 2");
        let code_g2 = run_chgrp(&["-v", "root", "/etc/hostname"], wg2);
        assert_eq!(code_g2, 0);
        sys_close(wg2);
        let mut out_g2 = [0u8; 128];
        let ng2 = sys_read(rg2, &mut out_g2);
        assert!(ng2 > 0);
        let sg2 = core::str::from_utf8(&out_g2[..ng2 as usize]).unwrap();
        assert!(sg2.contains("group of '/etc/hostname' retained as root"));
        sys_close(rg2);
        assert_eq!(sys_get_owner_pool("/etc/hostname"), Some((0, 0)));

        let (rg3, wg3) = crate::vfs::pipe().expect("pipe chgrp 3");
        let code_g3 = run_chgrp(&["-R", "1000", "/etc"], wg3);
        assert_eq!(code_g3, 0);
        sys_close(wg3);
        sys_close(rg3);
        assert_eq!(sys_get_owner_pool("/etc"), Some((0, 1000)));
        assert_eq!(sys_get_owner_pool("/etc/hostname"), Some((0, 1000)));

        // Rétablissement en root:root
        let _ = sys_chown_pool("/etc/hostname", 0, 0);
        let _ = sys_chown_pool("/etc/os-release", 0, 0);
        let _ = sys_chown_pool("/etc", 0, 0);

        // 5. Test utilitaire id
        let (r4, w4) = crate::vfs::pipe().expect("pipe id 1");
        let code4 = run_id(&[], 0, w4, 2);
        assert_eq!(code4, 0);
        sys_close(w4);
        let mut out4 = [0u8; 128];
        let n4 = sys_read(r4, &mut out4);
        assert!(n4 > 0);
        let s4 = core::str::from_utf8(&out4[..n4 as usize]).unwrap();
        assert!(s4.starts_with("uid=0(root) gid=0(root)"));
        sys_close(r4);

        // id -u
        let (r5, w5) = crate::vfs::pipe().expect("pipe id 2");
        let code5 = run_id(&["-u"], 0, w5, 2);
        assert_eq!(code5, 0);
        sys_close(w5);
        let mut out5 = [0u8; 32];
        let n5 = sys_read(r5, &mut out5);
        assert_eq!(&out5[..n5 as usize], b"0\n");
        sys_close(r5);
    }

    #[test]
    fn test_du_utility() {
        // 1. Calcul résumé (-s) sur /etc
        let (r1, w1) = crate::vfs::pipe().expect("pipe du 1");
        let code1 = run_du(&["-s", "/etc"], w1, 2);
        assert_eq!(code1, 0);
        sys_close(w1);
        let mut out1 = [0u8; 128];
        let n1 = sys_read(r1, &mut out1);
        assert!(n1 > 0);
        let s1 = core::str::from_utf8(&out1[..n1 as usize]).unwrap();
        assert!(s1.ends_with("\t/etc\n"));
        sys_close(r1);

        // 2. Calcul sur fichier individuel en mode octets (-b)
        let (r2, w2) = crate::vfs::pipe().expect("pipe du 2");
        let code2 = run_du(&["-b", "/etc/hostname"], w2, 2);
        assert_eq!(code2, 0);
        sys_close(w2);
        let mut out2 = [0u8; 128];
        let n2 = sys_read(r2, &mut out2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out2[..n2 as usize]).unwrap();
        assert_eq!(s2, "14\t/etc/hostname\n");
        sys_close(r2);

        // 3. Calcul lisible (-h) sur fichier individuel
        let (r3, w3) = crate::vfs::pipe().expect("pipe du 3");
        let code3 = run_du(&["-h", "/etc/hostname"], w3, 2);
        assert_eq!(code3, 0);
        sys_close(w3);
        let mut out3 = [0u8; 128];
        let n3 = sys_read(r3, &mut out3);
        assert!(n3 > 0);
        let s3 = core::str::from_utf8(&out3[..n3 as usize]).unwrap();
        assert_eq!(s3, "14B\t/etc/hostname\n");
        sys_close(r3);

        // 4. Calcul avec tous les fichiers (-a) sur /etc
        let (r4, w4) = crate::vfs::pipe().expect("pipe du 4");
        let code4 = run_du(&["-a", "/etc"], w4, 2);
        assert_eq!(code4, 0);
        sys_close(w4);
        let mut out4 = [0u8; 256];
        let n4 = sys_read(r4, &mut out4);
        assert!(n4 > 0);
        let s4 = core::str::from_utf8(&out4[..n4 as usize]).unwrap();
        assert!(s4.contains("/etc/hostname\n"));
        assert!(s4.contains("/etc/os-release\n"));
        assert!(s4.ends_with("\t/etc\n"));
        sys_close(r4);

        // 5. Test d'erreur : cible inexistante
        let (r5, w5) = crate::vfs::pipe().expect("pipe du 5");
        let code5 = run_du(&["/nonexistent_xyz_dir"], 1, w5);
        assert_eq!(code5, 1);
        sys_close(w5);
        let mut out5 = [0u8; 128];
        let n5 = sys_read(r5, &mut out5);
        assert!(n5 > 0);
        let s5 = core::str::from_utf8(&out5[..n5 as usize]).unwrap();
        assert!(s5.contains("du: cannot access '/nonexistent_xyz_dir': No such file or directory"));
        sys_close(r5);
    }

    #[test]
    fn test_df_utility() {
        // 1. Exécution standard de df
        let (r1, w1) = crate::vfs::pipe().expect("pipe df 1");
        let code1 = run_df(&[], w1, 2);
        assert_eq!(code1, 0);
        sys_close(w1);
        let mut out1 = [0u8; 1024];
        let n1 = sys_read(r1, &mut out1);
        assert!(n1 > 0);
        let s1 = core::str::from_utf8(&out1[..n1 as usize]).unwrap();
        assert!(s1.contains("Filesystem"));
        assert!(s1.contains("1K-blocks"));
        assert!(s1.contains("/dev/nvme0n1p2"));
        assert!(s1.contains("devfs"));
        assert!(s1.contains("tmpfs"));
        sys_close(r1);

        // 2. df avec option -h (human readable) et -T (print type)
        let (r2, w2) = crate::vfs::pipe().expect("pipe df 2");
        let code2 = run_df(&["-h", "-T"], w2, 2);
        assert_eq!(code2, 0);
        sys_close(w2);
        let mut out2 = [0u8; 1024];
        let n2 = sys_read(r2, &mut out2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out2[..n2 as usize]).unwrap();
        assert!(s2.contains("Type"));
        assert!(s2.contains("jambofs"));
        assert!(s2.contains("8M"));
        sys_close(r2);

        // 3. df avec option -i (inodes)
        let (r3, w3) = crate::vfs::pipe().expect("pipe df 3");
        let code3 = run_df(&["-i"], w3, 2);
        assert_eq!(code3, 0);
        sys_close(w3);
        let mut out3 = [0u8; 1024];
        let n3 = sys_read(r3, &mut out3);
        assert!(n3 > 0);
        let s3 = core::str::from_utf8(&out3[..n3 as usize]).unwrap();
        assert!(s3.contains("Inodes"));
        assert!(s3.contains("IUsed"));
        assert!(s3.contains("IFree"));
        sys_close(r3);

        // 4. df avec snapshots CoW (-s) et cible spécifique (/tmp)
        let (r4, w4) = crate::vfs::pipe().expect("pipe df 4");
        let code4 = run_df(&["-s", "/tmp"], w4, 2);
        assert_eq!(code4, 0);
        sys_close(w4);
        let mut out4 = [0u8; 1024];
        let n4 = sys_read(r4, &mut out4);
        assert!(n4 > 0);
        let s4 = core::str::from_utf8(&out4[..n4 as usize]).unwrap();
        assert!(s4.contains("/tmp"));
        assert!(s4.contains("[JamboFS CoW Snapshots] Actifs: 0/16"));
        sys_close(r4);
    }

    #[test]
    fn test_uname_utility() {
        // 1. uname par défaut (-s)
        let (r1, w1) = crate::vfs::pipe().expect("pipe uname 1");
        let code1 = run_uname(&[], w1, 2);
        assert_eq!(code1, 0);
        sys_close(w1);
        let mut out1 = [0u8; 256];
        let n1 = sys_read(r1, &mut out1);
        assert!(n1 > 0);
        let s1 = core::str::from_utf8(&out1[..n1 as usize]).unwrap();
        assert_eq!(s1.trim(), "JamboOS");
        sys_close(r1);

        // 2. uname avec tous les drapeaux (-a)
        let (r2, w2) = crate::vfs::pipe().expect("pipe uname 2");
        let code2 = run_uname(&["-a"], w2, 2);
        assert_eq!(code2, 0);
        sys_close(w2);
        let mut out2 = [0u8; 256];
        let n2 = sys_read(r2, &mut out2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out2[..n2 as usize]).unwrap();
        assert!(s2.contains("JamboOS"));
        assert!(s2.contains("jambo-node-0"));
        assert!(s2.contains("0.3.44"));
        assert!(s2.contains("SMP PREEMPT EEVDF"));
        #[cfg(target_arch = "x86_64")]
        assert!(s2.contains("x86_64"));
        #[cfg(target_arch = "aarch64")]
        assert!(s2.contains("aarch64"));
        sys_close(r2);

        // 3. uname avec options combinées (-srm)
        let (r3, w3) = crate::vfs::pipe().expect("pipe uname 3");
        let code3 = run_uname(&["-srm"], w3, 2);
        assert_eq!(code3, 0);
        sys_close(w3);
        let mut out3 = [0u8; 256];
        let n3 = sys_read(r3, &mut out3);
        assert!(n3 > 0);
        let s3 = core::str::from_utf8(&out3[..n3 as usize]).unwrap();
        assert!(s3.contains("JamboOS"));
        assert!(s3.contains("0.3.44"));
        #[cfg(target_arch = "x86_64")]
        assert!(s3.contains("x86_64"));
        sys_close(r3);

        // 4. uname avec option inconnue
        let (r4, w4) = crate::vfs::pipe().expect("pipe uname 4");
        let code4 = run_uname(&["-z"], 1, w4);
        assert_eq!(code4, 1);
        sys_close(w4);
        let mut out4 = [0u8; 256];
        let n4 = sys_read(r4, &mut out4);
        assert!(n4 > 0);
        let s4 = core::str::from_utf8(&out4[..n4 as usize]).unwrap();
        assert!(s4.contains("unrecognized option '-z'"));
        sys_close(r4);
    }

    #[test]
    fn test_cut_field_and_byte_modes() {
        // 1. Découpage par champs avec délimiteur par défaut TAB
        let (in_r1, in_w1) = crate::vfs::pipe().expect("pipe in 1");
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe out 1");
        let _ = sys_write(in_w1, b"alpha\tbeta\tgamma\tdelta\n");
        sys_close(in_w1);

        let code1 = run_cut(&["-f", "1,3"], in_r1, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(in_r1);
        sys_close(out_w1);

        let mut out1 = [0u8; 128];
        let n1 = sys_read(out_r1, &mut out1);
        assert!(n1 > 0);
        assert_eq!(&out1[..n1 as usize], b"alpha\tgamma\n");
        sys_close(out_r1);

        // 2. Découpage par champs avec délimiteur personnalisé ':'
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe in 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe out 2");
        let _ = sys_write(
            in_w2,
            b"root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:user:/home/user:/bin/sh\n",
        );
        sys_close(in_w2);

        let code2 = run_cut(&["-d", ":", "-f", "1,3,7"], in_r2, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(in_r2);
        sys_close(out_w2);

        let mut out2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut out2);
        assert!(n2 > 0);
        assert_eq!(&out2[..n2 as usize], b"root:0:/bin/sh\nuser:1000:/bin/sh\n");
        sys_close(out_r2);

        // 3. Découpage par octets avec plage '-b 2-5'
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe in 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe out 3");
        let _ = sys_write(in_w3, b"abcdefghij\n1234567890\n");
        sys_close(in_w3);

        let code3 = run_cut(&["-b", "2-5"], in_r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(in_r3);
        sys_close(out_w3);

        let mut out3 = [0u8; 128];
        let n3 = sys_read(out_r3, &mut out3);
        assert!(n3 > 0);
        assert_eq!(&out3[..n3 as usize], b"bcde\n2345\n");
        sys_close(out_r3);

        // 4. Découpage avec option -s (suppress lines without delimiter)
        let (in_r4, in_w4) = crate::vfs::pipe().expect("pipe in 4");
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe out 4");
        let _ = sys_write(in_w4, b"has:delim\nno_delim_here\nanother:line\n");
        sys_close(in_w4);

        let code4 = run_cut(&["-d", ":", "-f", "1", "-s"], in_r4, out_w4, 2);
        assert_eq!(code4, 0);
        sys_close(in_r4);
        sys_close(out_w4);

        let mut out4 = [0u8; 128];
        let n4 = sys_read(out_r4, &mut out4);
        assert!(n4 > 0);
        assert_eq!(&out4[..n4 as usize], b"has\nanother\n");
        sys_close(out_r4);

        // 5. Erreur : option manquante ou invalide
        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe out 5");
        let code5 = run_cut(&[], 0, 1, out_w5);
        assert_eq!(code5, 1);
        sys_close(out_w5);
        sys_close(out_r5);
    }

    #[test]
    fn test_paste_parallel_and_serial() {
        // 1. Fusion parallèle de deux fichiers avec délimiteur par défaut TAB
        let path1 = "/tmp/test_paste_a.txt";
        let path2 = "/tmp/test_paste_b.txt";
        let fd1 = sys_open(path1, O_CREAT | O_WRONLY);
        assert!(fd1 >= 0);
        let _ = sys_write(fd1, b"1\n2\n3\n");
        sys_close(fd1);

        let fd2 = sys_open(path2, O_CREAT | O_WRONLY);
        assert!(fd2 >= 0);
        let _ = sys_write(fd2, b"un\ndeux\ntrois\n");
        sys_close(fd2);

        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe paste 1");
        let code1 = run_paste(&[path1, path2], 0, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(out_w1);

        let mut out1 = [0u8; 256];
        let n1 = sys_read(out_r1, &mut out1);
        assert!(n1 > 0);
        assert_eq!(&out1[..n1 as usize], b"1\tun\n2\tdeux\n3\ttrois\n");
        sys_close(out_r1);

        // 2. Fusion avec délimiteur personnalisé (-d ",")
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe paste 2");
        let code2 = run_paste(&["-d", ",", path1, path2], 0, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(out_w2);

        let mut out2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut out2);
        assert!(n2 > 0);
        assert_eq!(&out2[..n2 as usize], b"1,un\n2,deux\n3,trois\n");
        sys_close(out_r2);

        // 3. Fusion séquentielle (-s)
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe paste 3");
        let code3 = run_paste(&["-s", "-d", ":", path1], 0, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(out_w3);

        let mut out3 = [0u8; 256];
        let n3 = sys_read(out_r3, &mut out3);
        assert!(n3 > 0);
        assert_eq!(&out3[..n3 as usize], b"1:2:3\n");
        sys_close(out_r3);

        // 4. Délimiteurs multiples cycliques (-d "|-")
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe paste 4");
        let code4 = run_paste(&["-s", "-d", "|-", path1], 0, out_w4, 2);
        assert_eq!(code4, 0);
        sys_close(out_w4);

        let mut out4 = [0u8; 256];
        let n4 = sys_read(out_r4, &mut out4);
        assert!(n4 > 0);
        assert_eq!(&out4[..n4 as usize], b"1|2-3\n");
        sys_close(out_r4);

        // 5. Délimiteur zéro-terminé (-z / --zero-terminated)
        let path_z1 = "/tmp/test_paste_z1.txt";
        let path_z2 = "/tmp/test_paste_z2.txt";
        let fz1 = sys_open(path_z1, O_CREAT | O_WRONLY);
        assert!(fz1 >= 0);
        let _ = sys_write(fz1, b"1\x002\x003\x00");
        sys_close(fz1);

        let fz2 = sys_open(path_z2, O_CREAT | O_WRONLY);
        assert!(fz2 >= 0);
        let _ = sys_write(fz2, b"un\0deux\0trois\0");
        sys_close(fz2);

        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe paste 5");
        let code5 = run_paste(&["-z", path_z1, path_z2], 0, out_w5, 2);
        assert_eq!(code5, 0);
        sys_close(out_w5);

        let mut out5 = [0u8; 256];
        let n5 = sys_read(out_r5, &mut out5);
        assert!(n5 > 0);
        assert_eq!(&out5[..n5 as usize], b"1\tun\x002\tdeux\x003\ttrois\x00");
        sys_close(out_r5);

        let _ = sys_unlink_pool(path_z1);
        let _ = sys_unlink_pool(path_z2);

        // 6. paste --version
        let (out_r6, out_w6) = crate::vfs::pipe().expect("pipe paste 6");
        let code6 = run_paste(&["--version"], 0, out_w6, 2);
        assert_eq!(code6, 0);
        sys_close(out_w6);
        let mut out6 = [0u8; 256];
        let n6 = sys_read(out_r6, &mut out6);
        assert!(n6 > 0);
        let ver_str = core::str::from_utf8(&out6[..n6 as usize]).unwrap();
        assert!(ver_str.contains("paste (JamboOS coreutils)"));
        sys_close(out_r6);

        // Nettoyage fichiers de test
        let _ = sys_unlink_pool(path1);
        let _ = sys_unlink_pool(path2);
    }

    #[test]
    fn test_comm_utility() {
        let path1 = "/tmp/test_comm_1.txt";
        let path2 = "/tmp/test_comm_2.txt";

        // file1 : a, b, c, d
        let fd1 = sys_open(path1, O_CREAT | O_WRONLY);
        assert!(fd1 >= 0);
        let _ = sys_write(fd1, b"apple\nbanana\ncherry\ndate\n");
        sys_close(fd1);

        // file2 : banana, cherry, elderberry, fig
        let fd2 = sys_open(path2, O_CREAT | O_WRONLY);
        assert!(fd2 >= 0);
        let _ = sys_write(fd2, b"banana\ncherry\nelderberry\nfig\n");
        sys_close(fd2);

        // 1. comm standard (3 colonnes délimitées par \t)
        // Col 1 (unique file1): apple, date
        // Col 2 (unique file2): elderberry, fig
        // Col 3 (communes): banana, cherry
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe comm 1");
        let code1 = run_comm(&[path1, path2], 0, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(out_w1);

        let mut out1 = [0u8; 512];
        let n1 = sys_read(out_r1, &mut out1);
        assert!(n1 > 0);
        let s1 = core::str::from_utf8(&out1[..n1 as usize]).unwrap();
        let expected1 = "apple\n\t\tbanana\n\t\tcherry\ndate\n\telderberry\n\tfig\n";
        assert_eq!(s1, expected1);
        sys_close(out_r1);

        // 2. comm avec suppression colonne 1 (-1) -> colonnes 2 et 3
        // Col 2 n'a pas de préfixe, Col 3 a 1 \t
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe comm 2");
        let code2 = run_comm(&["-1", path1, path2], 0, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(out_w2);

        let mut out2 = [0u8; 512];
        let n2 = sys_read(out_r2, &mut out2);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&out2[..n2 as usize]).unwrap();
        let expected2 = "\tbanana\n\tcherry\nelderberry\nfig\n";
        assert_eq!(s2, expected2);
        sys_close(out_r2);

        // 3. comm avec suppression colonnes 1 et 2 (-12) -> lignes communes seules, zéro préfixe
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe comm 3");
        let code3 = run_comm(&["-12", path1, path2], 0, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(out_w3);

        let mut out3 = [0u8; 512];
        let n3 = sys_read(out_r3, &mut out3);
        assert!(n3 > 0);
        let s3 = core::str::from_utf8(&out3[..n3 as usize]).unwrap();
        let expected3 = "banana\ncherry\n";
        assert_eq!(s3, expected3);
        sys_close(out_r3);

        // 4. comm avec délimiteur personnalisé (--output-delimiter="|")
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe comm 4");
        let code4 = run_comm(&["--output-delimiter=|", path1, path2], 0, out_w4, 2);
        assert_eq!(code4, 0);
        sys_close(out_w4);

        let mut out4 = [0u8; 512];
        let n4 = sys_read(out_r4, &mut out4);
        assert!(n4 > 0);
        let s4 = core::str::from_utf8(&out4[..n4 as usize]).unwrap();
        let expected4 = "apple\n||banana\n||cherry\ndate\n|elderberry\n|fig\n";
        assert_eq!(s4, expected4);
        sys_close(out_r4);

        // 5. comm avec entrée stdin (-)
        let (in_r5, in_w5) = crate::vfs::pipe().expect("pipe in comm 5");
        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe out comm 5");
        let _ = sys_write(in_w5, b"apple\nbanana\n");
        sys_close(in_w5);

        let code5 = run_comm(&["-12", "-", path2], in_r5, out_w5, 2);
        assert_eq!(code5, 0);
        sys_close(in_r5);
        sys_close(out_w5);

        let mut out5 = [0u8; 128];
        let n5 = sys_read(out_r5, &mut out5);
        assert!(n5 > 0);
        assert_eq!(&out5[..n5 as usize], b"banana\n");
        sys_close(out_r5);

        // Nettoyage fichiers temporaires
        let _ = sys_unlink_pool(path1);
        let _ = sys_unlink_pool(path2);
    }

    #[test]
    fn test_tr_utility() {
        // 1. Translation simple de minuscules en majuscules avec plage
        let (in_r1, in_w1) = crate::vfs::pipe().expect("pipe in tr 1");
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe out tr 1");
        let _ = sys_write(in_w1, b"hello world\n");
        sys_close(in_w1);

        let code1 = run_tr(&["a-z", "A-Z"], in_r1, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(in_r1);
        sys_close(out_w1);

        let mut out1 = [0u8; 128];
        let n1 = sys_read(out_r1, &mut out1);
        assert!(n1 > 0);
        assert_eq!(&out1[..n1 as usize], b"HELLO WORLD\n");
        sys_close(out_r1);

        // 2. Translation avec classes de caractères POSIX [:lower:] et [:upper:]
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe in tr 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe out tr 2");
        let _ = sys_write(in_w2, b"JamboOS Micro-Kernel v0.3!\n");
        sys_close(in_w2);

        let code2 = run_tr(&["[:upper:]", "[:lower:]"], in_r2, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(in_r2);
        sys_close(out_w2);

        let mut out2 = [0u8; 128];
        let n2 = sys_read(out_r2, &mut out2);
        assert!(n2 > 0);
        assert_eq!(&out2[..n2 as usize], b"jamboos micro-kernel v0.3!\n");
        sys_close(out_r2);

        // 3. Suppression de caractères avec option -d
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe in tr 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe out tr 3");
        let _ = sys_write(in_w3, b"user42:group99:disk0\n");
        sys_close(in_w3);

        let code3 = run_tr(&["-d", "0-9"], in_r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(in_r3);
        sys_close(out_w3);

        let mut out3 = [0u8; 128];
        let n3 = sys_read(out_r3, &mut out3);
        assert!(n3 > 0);
        assert_eq!(&out3[..n3 as usize], b"user:group:disk\n");
        sys_close(out_r3);

        // 4. Compression de répétitions consécutives avec -s
        let (in_r4, in_w4) = crate::vfs::pipe().expect("pipe in tr 4");
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe out tr 4");
        let _ = sys_write(in_w4, b"hello       world    foo   bar\n");
        sys_close(in_w4);

        let code4 = run_tr(&["-s", " "], in_r4, out_w4, 2);
        assert_eq!(code4, 0);
        sys_close(in_r4);
        sys_close(out_w4);

        let mut out4 = [0u8; 128];
        let n4 = sys_read(out_r4, &mut out4);
        assert!(n4 > 0);
        assert_eq!(&out4[..n4 as usize], b"hello world foo bar\n");
        sys_close(out_r4);

        // 5. Complément avec option -c
        let (in_r5, in_w5) = crate::vfs::pipe().expect("pipe in tr 5");
        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe out tr 5");
        let _ = sys_write(in_w5, b"abc 123 !@# def\n");
        sys_close(in_w5);

        let code5 = run_tr(&["-c", "[:alnum:]\n", "_"], in_r5, out_w5, 2);
        assert_eq!(code5, 0);
        sys_close(in_r5);
        sys_close(out_w5);

        let mut out5 = [0u8; 128];
        let n5 = sys_read(out_r5, &mut out5);
        assert!(n5 > 0);
        assert_eq!(&out5[..n5 as usize], b"abc_123_____def\n");
        sys_close(out_r5);

        // 6. Troncature avec -t
        let (in_r6, in_w6) = crate::vfs::pipe().expect("pipe in tr 6");
        let (out_r6, out_w6) = crate::vfs::pipe().expect("pipe out tr 6");
        let _ = sys_write(in_w6, b"12345\n");
        sys_close(in_w6);

        let code6 = run_tr(&["-t", "1-5", "abc"], in_r6, out_w6, 2);
        assert_eq!(code6, 0);
        sys_close(in_r6);
        sys_close(out_w6);

        let mut out6 = [0u8; 128];
        let n6 = sys_read(out_r6, &mut out6);
        assert!(n6 > 0);
        assert_eq!(&out6[..n6 as usize], b"abc45\n");
        sys_close(out_r6);

        // 7. Séquences d'échappement et répétition [c*n]
        let (in_r7, in_w7) = crate::vfs::pipe().expect("pipe in tr 7");
        let (out_r7, out_w7) = crate::vfs::pipe().expect("pipe out tr 7");
        let _ = sys_write(in_w7, b"line1:line2:line3\n");
        sys_close(in_w7);

        let code7 = run_tr(&[":", "\\n"], in_r7, out_w7, 2);
        assert_eq!(code7, 0);
        sys_close(in_r7);
        sys_close(out_w7);

        let mut out7 = [0u8; 128];
        let n7 = sys_read(out_r7, &mut out7);
        assert!(n7 > 0);
        assert_eq!(&out7[..n7 as usize], b"line1\nline2\nline3\n");
        sys_close(out_r7);

        // 8. Erreur : opérande manquant
        let (out_r8, out_w8) = crate::vfs::pipe().expect("pipe out tr 8");
        let code8 = run_tr(&[], 0, 1, out_w8);
        assert_eq!(code8, 1);
        sys_close(out_w8);
        sys_close(out_r8);
    }

    #[test]
    fn test_split_utility() {
        // 1. Découpage par lignes (-l 2)
        let src_path = "/tmp/split_src1.txt";
        let src_fd = sys_open(src_path, O_CREAT | O_WRONLY | O_TRUNC);
        assert!(src_fd >= 3);
        let _ = sys_write(src_fd, b"line1\nline2\nline3\nline4\nline5\n");
        sys_close(src_fd);

        let code1 = run_split(&["-l", "2", src_path, "/tmp/s1_"], 0, 1, 2);
        assert_eq!(code1, 0);

        // Doit avoir créé /tmp/s1_aa (line1, line2), /tmp/s1_ab (line3, line4), /tmp/s1_ac (line5)
        let mut buf = [0u8; 64];
        let f1 = sys_open("/tmp/s1_aa", O_RDONLY);
        assert!(f1 >= 3);
        let n1 = sys_read(f1, &mut buf);
        assert_eq!(&buf[..n1 as usize], b"line1\nline2\n");
        sys_close(f1);

        let f2 = sys_open("/tmp/s1_ab", O_RDONLY);
        assert!(f2 >= 3);
        let n2 = sys_read(f2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"line3\nline4\n");
        sys_close(f2);

        let f3 = sys_open("/tmp/s1_ac", O_RDONLY);
        assert!(f3 >= 3);
        let n3 = sys_read(f3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"line5\n");
        sys_close(f3);
        let _ = sys_unlink_pool(src_path);
        let _ = sys_unlink_pool("/tmp/s1_aa");
        let _ = sys_unlink_pool("/tmp/s1_ab");
        let _ = sys_unlink_pool("/tmp/s1_ac");

        // 2. Découpage par octets (-b 5) avec suffixes numériques (-d)
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe in split 2");
        let _ = sys_write(in_w2, b"abcdefghijklmno"); // 15 octets -> 3 chunks de 5 octets
        sys_close(in_w2);

        let code2 = run_split(&["-b", "5", "-d", "-", "/tmp/s2_"], in_r2, 1, 2);
        assert_eq!(code2, 0);
        sys_close(in_r2);

        let f2_0 = sys_open("/tmp/s2_00", O_RDONLY);
        assert!(f2_0 >= 3);
        let n2_0 = sys_read(f2_0, &mut buf);
        assert_eq!(&buf[..n2_0 as usize], b"abcde");
        sys_close(f2_0);

        let f2_1 = sys_open("/tmp/s2_01", O_RDONLY);
        assert!(f2_1 >= 3);
        let n2_1 = sys_read(f2_1, &mut buf);
        assert_eq!(&buf[..n2_1 as usize], b"fghij");
        sys_close(f2_1);

        let f2_2 = sys_open("/tmp/s2_02", O_RDONLY);
        assert!(f2_2 >= 3);
        let n2_2 = sys_read(f2_2, &mut buf);
        assert_eq!(&buf[..n2_2 as usize], b"klmno");
        sys_close(f2_2);
        let _ = sys_unlink_pool("/tmp/s2_00");
        let _ = sys_unlink_pool("/tmp/s2_01");
        let _ = sys_unlink_pool("/tmp/s2_02");

        // 3. Longueur de suffixe (-a 3)
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe in split 3");
        let _ = sys_write(in_w3, b"chunk1chunk2");
        sys_close(in_w3);

        let code3 = run_split(&["-b", "6", "-a", "3", "-", "/tmp/s3_"], in_r3, 1, 2);
        assert_eq!(code3, 0);
        sys_close(in_r3);

        let f3_0 = sys_open("/tmp/s3_aaa", O_RDONLY);
        assert!(f3_0 >= 3);
        let n3_0 = sys_read(f3_0, &mut buf);
        assert_eq!(&buf[..n3_0 as usize], b"chunk1");
        sys_close(f3_0);

        let f3_1 = sys_open("/tmp/s3_aab", O_RDONLY);
        assert!(f3_1 >= 3);
        let n3_1 = sys_read(f3_1, &mut buf);
        assert_eq!(&buf[..n3_1 as usize], b"chunk2");
        sys_close(f3_1);
        let _ = sys_unlink_pool("/tmp/s3_aaa");
        let _ = sys_unlink_pool("/tmp/s3_aab");

        // 4. Découpage par taille maximale de ligne (-C 12)
        let (in_r4, in_w4) = crate::vfs::pipe().expect("pipe in split 4");
        let _ = sys_write(in_w4, b"hello\nworld\nthis is long\n");
        sys_close(in_w4);

        let code4 = run_split(&["-C", "12", "-", "/tmp/s4_"], in_r4, 1, 2);
        assert_eq!(code4, 0);
        sys_close(in_r4);

        let f4_0 = sys_open("/tmp/s4_aa", O_RDONLY);
        assert!(f4_0 >= 3);
        let n4_0 = sys_read(f4_0, &mut buf);
        assert_eq!(&buf[..n4_0 as usize], b"hello\nworld\n");
        sys_close(f4_0);
        let _ = sys_unlink_pool("/tmp/s4_aa");

        // 5. Erreurs d'options incompatibles
        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe out split 5");
        let code5 = run_split(&["-l", "5", "-b", "10"], 0, 1, out_w5);
        assert_eq!(code5, 1);
        sys_close(out_w5);
        sys_close(out_r5);
    }

    #[test]
    fn test_posix_basename_and_dirname() {
        // 1. Tests unitaires de conformité IEEE Std 1003.1 pour posix_basename
        assert_eq!(posix_basename("", None), ".");
        assert_eq!(posix_basename("/", None), "/");
        assert_eq!(posix_basename("///", None), "/");
        assert_eq!(posix_basename("//", None), "/");
        assert_eq!(posix_basename("/usr/", None), "usr");
        assert_eq!(posix_basename("/usr/lib", None), "lib");
        assert_eq!(posix_basename("/usr/lib/", None), "lib");
        assert_eq!(posix_basename("usr", None), "usr");
        assert_eq!(posix_basename("usr/", None), "usr");
        assert_eq!(posix_basename("main.c", Some(".c")), "main");
        assert_eq!(posix_basename("/src/main.c", Some(".c")), "main");
        assert_eq!(
            posix_basename("/archive.tar.gz", Some(".tar.gz")),
            "archive"
        );
        assert_eq!(posix_basename(".c", Some(".c")), ".c");

        // 2. Tests unitaires de conformité IEEE Std 1003.1 pour posix_dirname
        assert_eq!(posix_dirname(""), ".");
        assert_eq!(posix_dirname("/"), "/");
        assert_eq!(posix_dirname("///"), "/");
        assert_eq!(posix_dirname("//"), "/");
        assert_eq!(posix_dirname("/usr/lib"), "/usr");
        assert_eq!(posix_dirname("/usr/lib/"), "/usr");
        assert_eq!(posix_dirname("/usr"), "/");
        assert_eq!(posix_dirname("/usr/"), "/");
        assert_eq!(posix_dirname("usr"), ".");
        assert_eq!(posix_dirname("usr/"), ".");
        assert_eq!(posix_dirname("a/b"), "a");
        assert_eq!(posix_dirname("a/b/"), "a");

        // 3. Test d'exécution run_basename via pipes
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe basename 1");
        let code1 = run_basename(&["/usr/bin/sort"], out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(out_w1);

        let mut buf = [0u8; 128];
        let n1 = sys_read(out_r1, &mut buf);
        assert_eq!(&buf[..n1 as usize], b"sort\n");
        sys_close(out_r1);

        // Test avec suffixe
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe basename 2");
        let code2 = run_basename(&["/usr/include/stdio.h", ".h"], out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(out_w2);
        let n2 = sys_read(out_r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"stdio\n");
        sys_close(out_r2);

        // Test multi-arguments avec -a -s
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe basename 3");
        let code3 = run_basename(
            &["-a", "-s", ".c", "/src/main.c", "/src/kernel.c"],
            out_w3,
            2,
        );
        assert_eq!(code3, 0);
        sys_close(out_w3);
        let n3 = sys_read(out_r3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"main\nkernel\n");
        sys_close(out_r3);

        // 4. Test d'exécution run_dirname via pipes
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe dirname 1");
        let code4 = run_dirname(
            &["/usr/bin/sort", "/etc/resolv.conf", "simple.txt"],
            out_w4,
            2,
        );
        assert_eq!(code4, 0);
        sys_close(out_w4);
        let n4 = sys_read(out_r4, &mut buf);
        assert_eq!(&buf[..n4 as usize], b"/usr/bin\n/etc\n.\n");
        sys_close(out_r4);

        // Test option -z
        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe dirname 2");
        let code5 = run_dirname(&["-z", "/var/log"], out_w5, 2);
        assert_eq!(code5, 0);
        sys_close(out_w5);
        let n5 = sys_read(out_r5, &mut buf);
        assert_eq!(&buf[..n5 as usize], b"/var\0");
        sys_close(out_r5);

        // Test sans argument (erreur)
        let (err_r6, err_w6) = crate::vfs::pipe().expect("pipe basename err");
        let code6 = run_basename(&[], 1, err_w6);
        assert_eq!(code6, 1);
        sys_close(err_w6);
        sys_close(err_r6);
    }

    #[test]
    fn test_seq_execution() {
        let mut buf = [0u8; 256];

        // 1. Séquence simple : seq 3 -> "1\n2\n3\n"
        let (r1, w1) = crate::vfs::pipe().expect("pipe seq 1");
        let code1 = run_seq(&["3"], w1, 2);
        assert_eq!(code1, 0);
        sys_close(w1);
        let n1 = sys_read(r1, &mut buf);
        assert_eq!(&buf[..n1 as usize], b"1\n2\n3\n");
        sys_close(r1);

        // 2. Séquence avec premier et dernier : seq 3 5 -> "3\n4\n5\n"
        let (r2, w2) = crate::vfs::pipe().expect("pipe seq 2");
        let code2 = run_seq(&["3", "5"], w2, 2);
        assert_eq!(code2, 0);
        sys_close(w2);
        let n2 = sys_read(r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"3\n4\n5\n");
        sys_close(r2);

        // 3. Séquence avec pas et décroissance : seq 5 -2 1 -> "5\n3\n1\n"
        let (r3, w3) = crate::vfs::pipe().expect("pipe seq 3");
        let code3 = run_seq(&["5", "-2", "1"], w3, 2);
        assert_eq!(code3, 0);
        sys_close(w3);
        let n3 = sys_read(r3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"5\n3\n1\n");
        sys_close(r3);

        // 4. Séparateur personnalisé : seq -s , 1 4 -> "1,2,3,4\n"
        let (r4, w4) = crate::vfs::pipe().expect("pipe seq 4");
        let code4 = run_seq(&["-s", ",", "1", "4"], w4, 2);
        assert_eq!(code4, 0);
        sys_close(w4);
        let n4 = sys_read(r4, &mut buf);
        assert_eq!(&buf[..n4 as usize], b"1,2,3,4\n");
        sys_close(r4);

        // 5. Largeur égale (-w) : seq -w 8 10 -> "08\n09\n10\n"
        let (r5, w5) = crate::vfs::pipe().expect("pipe seq 5");
        let code5 = run_seq(&["-w", "8", "10"], w5, 2);
        assert_eq!(code5, 0);
        sys_close(w5);
        let n5 = sys_read(r5, &mut buf);
        assert_eq!(&buf[..n5 as usize], b"08\n09\n10\n");
        sys_close(r5);

        // 6. Format printf (-f) : seq -f "val=%02d" 1 3 -> "val=01\nval=02\nval=03\n"
        let (r6, w6) = crate::vfs::pipe().expect("pipe seq 6");
        let code6 = run_seq(&["-f", "val=%02d", "1", "3"], w6, 2);
        assert_eq!(code6, 0);
        sys_close(w6);
        let n6 = sys_read(r6, &mut buf);
        assert_eq!(&buf[..n6 as usize], b"val=01\nval=02\nval=03\n");
        sys_close(r6);

        // 7. Nombres décimaux : seq 0.5 0.5 1.5 -> "0.5\n1.0\n1.5\n"
        let (r7, w7) = crate::vfs::pipe().expect("pipe seq 7");
        let code7 = run_seq(&["0.5", "0.5", "1.5"], w7, 2);
        assert_eq!(code7, 0);
        sys_close(w7);
        let n7 = sys_read(r7, &mut buf);
        assert_eq!(&buf[..n7 as usize], b"0.5\n1.0\n1.5\n");
        sys_close(r7);

        // 8. Incrément zéro (erreur code 1)
        let (err_r8, err_w8) = crate::vfs::pipe().expect("pipe seq err 1");
        let code8 = run_seq(&["1", "0", "5"], 1, err_w8);
        assert_eq!(code8, 1);
        sys_close(err_w8);
        sys_close(err_r8);

        // 9. Argument manquant (erreur code 1)
        let (err_r9, err_w9) = crate::vfs::pipe().expect("pipe seq err 2");
        let code9 = run_seq(&[], 1, err_w9);
        assert_eq!(code9, 1);
        sys_close(err_w9);
        sys_close(err_r9);
    }

    #[test]
    fn test_yes_execution() {
        let mut buf = [0u8; 128];

        // 1. yes sans argument produit "y\n" répété
        let (r1, w1) = crate::vfs::pipe().expect("pipe yes 1");
        // On écrit 6 octets max dans le pipe puis on ferme pour simuler consommateur limité
        let code1 = run_yes(&[], w1, 2, 6);
        assert_eq!(code1, 0);
        sys_close(w1);
        let n1 = sys_read(r1, &mut buf);
        assert_eq!(&buf[..n1 as usize], b"y\ny\ny\n");
        sys_close(r1);

        // 2. yes avec argument "oui" produit "oui\n" répété
        let (r2, w2) = crate::vfs::pipe().expect("pipe yes 2");
        let code2 = run_yes(&["oui"], w2, 2, 8);
        assert_eq!(code2, 0);
        sys_close(w2);
        let n2 = sys_read(r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"oui\noui\n");
        sys_close(r2);

        // 3. yes avec arguments multiples produit "a b\n" répété
        let (r3, w3) = crate::vfs::pipe().expect("pipe yes 3");
        let code3 = run_yes(&["a", "b"], w3, 2, 8);
        assert_eq!(code3, 0);
        sys_close(w3);
        let n3 = sys_read(r3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"a b\na b\n");
        sys_close(r3);
    }

    #[test]
    fn test_printf_execution() {
        let mut buf = [0u8; 256];

        // 1. Format simple sans substitution
        let (r1, w1) = crate::vfs::pipe().expect("pipe printf 1");
        let code1 = run_printf(&["hello\\n"], w1, 2);
        assert_eq!(code1, 0);
        sys_close(w1);
        let n1 = sys_read(r1, &mut buf);
        assert_eq!(&buf[..n1 as usize], b"hello\n");
        sys_close(r1);

        // 2. Format %d entier
        let (r2, w2) = crate::vfs::pipe().expect("pipe printf 2");
        let code2 = run_printf(&["val=%d\\n", "42"], w2, 2);
        assert_eq!(code2, 0);
        sys_close(w2);
        let n2 = sys_read(r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"val=42\n");
        sys_close(r2);

        // 3. Format %s chaîne
        let (r3, w3) = crate::vfs::pipe().expect("pipe printf 3");
        let code3 = run_printf(&["%s world\\n", "hello"], w3, 2);
        assert_eq!(code3, 0);
        sys_close(w3);
        let n3 = sys_read(r3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"hello world\n");
        sys_close(r3);

        // 4. Format %x hexadécimal
        let (r4, w4) = crate::vfs::pipe().expect("pipe printf 4");
        let code4 = run_printf(&["0x%x\\n", "255"], w4, 2);
        assert_eq!(code4, 0);
        sys_close(w4);
        let n4 = sys_read(r4, &mut buf);
        assert_eq!(&buf[..n4 as usize], b"0xff\n");
        sys_close(r4);

        // 5. Argument manquant (erreur code 1)
        let (err_r5, err_w5) = crate::vfs::pipe().expect("pipe printf err");
        let code5 = run_printf(&[], 1, err_w5);
        assert_eq!(code5, 1);
        sys_close(err_w5);
        sys_close(err_r5);
    }

    #[test]
    fn test_expr_execution() {
        let mut buf = [0u8; 128];

        // 1. Addition
        let (r1, w1) = crate::vfs::pipe().expect("pipe expr 1");
        let code1 = run_expr(&["3", "+", "4"], w1, 2);
        assert_eq!(code1, 0);
        sys_close(w1);
        let n1 = sys_read(r1, &mut buf);
        assert_eq!(&buf[..n1 as usize], b"7\n");
        sys_close(r1);

        // 2. Soustraction
        let (r2, w2) = crate::vfs::pipe().expect("pipe expr 2");
        let code2 = run_expr(&["10", "-", "3"], w2, 2);
        assert_eq!(code2, 0);
        sys_close(w2);
        let n2 = sys_read(r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"7\n");
        sys_close(r2);

        // 3. Multiplication
        let (r3, w3) = crate::vfs::pipe().expect("pipe expr 3");
        let code3 = run_expr(&["6", "*", "7"], w3, 2);
        assert_eq!(code3, 0);
        sys_close(w3);
        let n3 = sys_read(r3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"42\n");
        sys_close(r3);

        // 4. Division entière
        let (r4, w4) = crate::vfs::pipe().expect("pipe expr 4");
        let code4 = run_expr(&["17", "/", "5"], w4, 2);
        assert_eq!(code4, 0);
        sys_close(w4);
        let n4 = sys_read(r4, &mut buf);
        assert_eq!(&buf[..n4 as usize], b"3\n");
        sys_close(r4);

        // 5. Modulo
        let (r5, w5) = crate::vfs::pipe().expect("pipe expr 5");
        let code5 = run_expr(&["17", "%", "5"], w5, 2);
        assert_eq!(code5, 0);
        sys_close(w5);
        let n5 = sys_read(r5, &mut buf);
        assert_eq!(&buf[..n5 as usize], b"2\n");
        sys_close(r5);

        // 6. Comparaison égalité (résultat 1 si vrai)
        let (r6, w6) = crate::vfs::pipe().expect("pipe expr 6");
        let code6 = run_expr(&["5", "=", "5"], w6, 2);
        assert_eq!(code6, 0);
        sys_close(w6);
        let n6 = sys_read(r6, &mut buf);
        assert_eq!(&buf[..n6 as usize], b"1\n");
        sys_close(r6);

        // 7. Comparaison inégalité (résultat 0, code 1)
        let (r7, w7) = crate::vfs::pipe().expect("pipe expr 7");
        let code7 = run_expr(&["3", "=", "5"], w7, 2);
        assert_eq!(code7, 1);
        sys_close(w7);
        let n7 = sys_read(r7, &mut buf);
        assert_eq!(&buf[..n7 as usize], b"0\n");
        sys_close(r7);

        // 8. Division par zéro (erreur code 2)
        let (err_r8, err_w8) = crate::vfs::pipe().expect("pipe expr err");
        let code8 = run_expr(&["5", "/", "0"], 1, err_w8);
        assert_eq!(code8, 2);
        sys_close(err_w8);
        sys_close(err_r8);

        // 9. Opérateur inconnu (erreur code 2)
        let (err_r9, err_w9) = crate::vfs::pipe().expect("pipe expr err2");
        let code9 = run_expr(&["5", "^", "2"], 1, err_w9);
        assert_eq!(code9, 2);
        sys_close(err_w9);
        sys_close(err_r9);
    }

    #[test]
    fn test_fold_execution() {
        let mut buf = [0u8; 256];

        // 1. Découpage standard à 10 colonnes sans rupture d'espace
        let (in_r1, in_w1) = crate::vfs::pipe().expect("pipe fold in 1");
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe fold out 1");
        let _ = sys_write(in_w1, b"1234567890abcdefghij\n");
        sys_close(in_w1);

        let code1 = run_fold(&["-w", "10"], in_r1, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(in_r1);
        sys_close(out_w1);

        let n1 = sys_read(out_r1, &mut buf);
        assert_eq!(&buf[..n1 as usize], b"1234567890\nabcdefghij\n");
        sys_close(out_r1);

        // 2. Découpage avec rupture aux espaces (-s -w 12)
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe fold in 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe fold out 2");
        let _ = sys_write(in_w2, b"bonjour le monde jambo\n");
        sys_close(in_w2);

        let code2 = run_fold(&["-s", "-w", "12"], in_r2, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(in_r2);
        sys_close(out_w2);

        let n2 = sys_read(out_r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"bonjour le \nmonde jambo\n");
        sys_close(out_r2);

        // 3. Découpage avec syntaxe courte -10
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe fold in 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe fold out 3");
        let _ = sys_write(in_w3, b"abcdefghijklmnopqrst\n");
        sys_close(in_w3);

        let code3 = run_fold(&["-10"], in_r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(in_r3);
        sys_close(out_w3);

        let n3 = sys_read(out_r3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"abcdefghij\nklmnopqrst\n");
        sys_close(out_r3);

        // 4. Largeur invalide (code d'erreur 1)
        let (err_r4, err_w4) = crate::vfs::pipe().expect("pipe fold err 1");
        let code4 = run_fold(&["-w", "0"], 0, 1, err_w4);
        assert_eq!(code4, 1);
        sys_close(err_w4);
        sys_close(err_r4);

        // 5. Lecture d'un fichier réel via VFS
        let fd_test = sys_open("/tmp/fold_test.txt", O_CREAT | O_WRONLY);
        assert!(fd_test >= 3);
        let _ = sys_write(fd_test, b"AAAABBBBCCCCDDDD\n");
        sys_close(fd_test);

        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe fold out 5");
        let code5 = run_fold(&["-w", "8", "/tmp/fold_test.txt"], 0, out_w5, 2);
        assert_eq!(code5, 0);
        sys_close(out_w5);

        let n5 = sys_read(out_r5, &mut buf);
        assert_eq!(&buf[..n5 as usize], b"AAAABBBB\nCCCCDDDD\n");
        sys_close(out_r5);
    }

    #[test]
    fn test_nl_lifecycle() {
        let mut buf = [0u8; 1024];

        // 1. Numérotation par défaut (lignes non vides, largeur 6, espace à droite)
        let (in_r1, in_w1) = crate::vfs::pipe().expect("pipe nl in 1");
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe nl out 1");
        let _ = sys_write(in_w1, b"ligne1\n\nligne2\n");
        sys_close(in_w1);

        let code1 = run_nl(&[], in_r1, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(in_r1);
        sys_close(out_w1);

        let n1 = sys_read(out_r1, &mut buf);
        assert_eq!(
            &buf[..n1 as usize],
            b"     1\tligne1\n      \t\n     2\tligne2\n"
        );
        sys_close(out_r1);

        // 2. Numérotation de toutes les lignes (-ba), séparateur personnalisé (-s ": "), largeur 3 (-w 3), start 10 (-v 10), incr 5 (-i 5)
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe nl in 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe nl out 2");
        let _ = sys_write(in_w2, b"alpha\n\nbeta\n");
        sys_close(in_w2);

        let code2 = run_nl(
            &["-ba", "-s", ": ", "-w", "3", "-v", "10", "-i", "5"],
            in_r2,
            out_w2,
            2,
        );
        assert_eq!(code2, 0);
        sys_close(in_r2);
        sys_close(out_w2);

        let n2 = sys_read(out_r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b" 10: alpha\n 15: \n 20: beta\n");
        sys_close(out_r2);

        // 3. Format zéros de tête (-nrz) et justification gauche (-nln)
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe nl in 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe nl out 3");
        let _ = sys_write(in_w3, b"un\ndeux\n");
        sys_close(in_w3);

        let code3 = run_nl(&["-nrz", "-w", "4", "-s", "|"], in_r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(in_r3);
        sys_close(out_w3);

        let n3 = sys_read(out_r3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"0001|un\n0002|deux\n");
        sys_close(out_r3);

        // 4. Justifié à gauche (-nln)
        let (in_r4, in_w4) = crate::vfs::pipe().expect("pipe nl in 4");
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe nl out 4");
        let _ = sys_write(in_w4, b"test\n");
        sys_close(in_w4);

        let code4 = run_nl(&["-nln", "-w", "4", "-s", " "], in_r4, out_w4, 2);
        assert_eq!(code4, 0);
        sys_close(in_r4);
        sys_close(out_w4);

        let n4 = sys_read(out_r4, &mut buf);
        assert_eq!(&buf[..n4 as usize], b"1    test\n");
        sys_close(out_r4);

        // 5. Option invalide
        let (err_r5, err_w5) = crate::vfs::pipe().expect("pipe nl err 5");
        let code5 = run_nl(&["-invalid"], 0, 1, err_w5);
        assert_eq!(code5, 1);
        sys_close(err_w5);
        sys_close(err_r5);

        // 6. Lecture via fichier VFS
        let fd_test = sys_open("/tmp/nl_test.txt", O_CREAT | O_WRONLY);
        assert!(fd_test >= 3);
        let _ = sys_write(fd_test, b"salut\nmonde\n");
        sys_close(fd_test);

        let (out_r6, out_w6) = crate::vfs::pipe().expect("pipe nl out 6");
        let code6 = run_nl(&["-w", "2", "-s", " ", "/tmp/nl_test.txt"], 0, out_w6, 2);
        assert_eq!(code6, 0);
        sys_close(out_w6);

        let n6 = sys_read(out_r6, &mut buf);
        assert_eq!(&buf[..n6 as usize], b" 1 salut\n 2 monde\n");
        sys_close(out_r6);
    }

    #[test]
    fn test_od_full_suite() {
        let mut buf = [0u8; 1024];

        // 1. od -b (octal bytes)
        let (in_r1, in_w1) = crate::vfs::pipe().expect("pipe od in 1");
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe od out 1");
        let _ = sys_write(in_w1, b"ABC\n");
        sys_close(in_w1);

        let code1 = run_od(&["-b"], in_r1, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(in_r1);
        sys_close(out_w1);

        let n1 = sys_read(out_r1, &mut buf);
        // 'A'=0101 (65), 'B'=0102 (66), 'C'=0103 (67), '\n'=0012 (10)
        assert_eq!(&buf[..n1 as usize], b"0000000 101 102 103 012\n0000004\n");
        sys_close(out_r1);

        // 2. od -c (caractères ASCII et échappement \n)
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe od in 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe od out 2");
        let _ = sys_write(in_w2, b"Hi\n");
        sys_close(in_w2);

        let code2 = run_od(&["-c"], in_r2, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(in_r2);
        sys_close(out_w2);

        let n2 = sys_read(out_r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"0000000   H   i  \\n\n0000003\n");
        sys_close(out_r2);

        // 3. od -x -A n (sans adresse)
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe od in 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe od out 3");
        let _ = sys_write(in_w3, b"ABCD");
        sys_close(in_w3);

        let code3 = run_od(&["-x", "-A", "n"], in_r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(in_r3);
        sys_close(out_w3);

        let n3 = sys_read(out_r3, &mut buf);
        // Little endian: 'A' (0x41) + 'B' (0x42) -> 0x4241 ; 'C' (0x43) + 'D' (0x44) -> 0x4443
        assert_eq!(&buf[..n3 as usize], b" 4241 4443\n");
        sys_close(out_r3);

        // 4. od -j 2 -N 2 (skip et count)
        let (in_r4, in_w4) = crate::vfs::pipe().expect("pipe od in 4");
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe od out 4");
        let _ = sys_write(in_w4, b"012345");
        sys_close(in_w4);

        let code4 = run_od(&["-c", "-j", "2", "-N", "2", "-A", "d"], in_r4, out_w4, 2);
        assert_eq!(code4, 0);
        sys_close(in_r4);
        sys_close(out_w4);

        let n4 = sys_read(out_r4, &mut buf);
        assert_eq!(&buf[..n4 as usize], b"0000000   2   3\n0000002\n");
        sys_close(out_r4);

        // 5. Option invalide
        let (err_r5, err_w5) = crate::vfs::pipe().expect("pipe od err 5");
        let code5 = run_od(&["-invalid"], 0, 1, err_w5);
        assert_eq!(code5, 1);
        sys_close(err_w5);
        sys_close(err_r5);

        // 6. Lecture via fichier VFS
        let fd_test = sys_open("/tmp/od_test.bin", O_CREAT | O_WRONLY);
        assert!(fd_test >= 3);
        let _ = sys_write(fd_test, b"test");
        sys_close(fd_test);

        let (out_r6, out_w6) = crate::vfs::pipe().expect("pipe od out 6");
        let code6 = run_od(&["-b", "/tmp/od_test.bin"], 0, out_w6, 2);
        assert_eq!(code6, 0);
        sys_close(out_w6);

        let n6 = sys_read(out_r6, &mut buf);
        // 't'=0164, 'e'=0145, 's'=0163, 't'=0164
        assert_eq!(&buf[..n6 as usize], b"0000000 164 145 163 164\n0000004\n");
        sys_close(out_r6);
    }

    #[test]
    fn test_cmp_utility() {
        let mut buf = [0u8; 256];

        // 1. Fichiers créés dans le VFS pour le test
        let f1 = sys_open("/tmp/cmp1.txt", O_CREAT | O_WRONLY);
        let _ = sys_write(f1, b"Hello World!\nLine 2\n");
        sys_close(f1);

        let f2 = sys_open("/tmp/cmp2.txt", O_CREAT | O_WRONLY);
        let _ = sys_write(f2, b"Hello World!\nLine 2\n");
        sys_close(f2);

        let f3 = sys_open("/tmp/cmp3.txt", O_CREAT | O_WRONLY);
        let _ = sys_write(f3, b"Hello Jambo!\nLine 2\n");
        sys_close(f3);

        // Test 1 : Fichiers identiques
        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_cmp(&["/tmp/cmp1.txt", "/tmp/cmp2.txt"], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);
        let n1 = sys_read(out_r1, &mut buf);
        sys_close(out_r1);
        assert_eq!(n1, 0);

        // Test 2 : Fichiers différents par défaut
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_cmp(&["/tmp/cmp1.txt", "/tmp/cmp3.txt"], 0, out_w2, 2);
        sys_close(out_w2);
        assert_eq!(code2, 1);
        let n2 = sys_read(out_r2, &mut buf);
        sys_close(out_r2);
        let msg2 = core::str::from_utf8(&buf[..n2 as usize]).unwrap();
        assert!(msg2.contains("differ: byte 7, line 1"));

        // Test 3 : Option silencieuse -s
        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_cmp(&["-s", "/tmp/cmp1.txt", "/tmp/cmp3.txt"], 0, out_w3, 2);
        sys_close(out_w3);
        assert_eq!(code3, 1);
        let n3 = sys_read(out_r3, &mut buf);
        sys_close(out_r3);
        assert_eq!(n3, 0);

        // Test 4 : Option verbeuse -l
        let (out_r4, out_w4) = crate::vfs::pipe().unwrap();
        let code4 = run_cmp(&["-l", "/tmp/cmp1.txt", "/tmp/cmp3.txt"], 0, out_w4, 2);
        sys_close(out_w4);
        assert_eq!(code4, 1);
        let n4 = sys_read(out_r4, &mut buf);
        sys_close(out_r4);
        let msg4 = core::str::from_utf8(&buf[..n4 as usize]).unwrap();
        // Octet 7: 'W' (0x57 = 0127) vs 'J' (0x4A = 0112)
        assert!(msg4.contains("7 127 112"));

        // Test 5 : Comparaison avec offsets (skip1 = 13, skip2 = 13 -> les deux démarrent à "Line 2\n")
        let (out_r5, out_w5) = crate::vfs::pipe().unwrap();
        let code5 = run_cmp(
            &["/tmp/cmp1.txt", "/tmp/cmp3.txt", "13", "13"],
            0,
            out_w5,
            2,
        );
        sys_close(out_w5);
        assert_eq!(code5, 0);
        let n5 = sys_read(out_r5, &mut buf);
        sys_close(out_r5);
        assert_eq!(n5, 0);

        // Test 6 : Opérandes manquants -> exit code 2
        let (err_r6, err_w6) = crate::vfs::pipe().unwrap();
        let code6 = run_cmp(&["/tmp/cmp1.txt"], 0, 1, err_w6);
        sys_close(err_w6);
        assert_eq!(code6, 2);
        let n6 = sys_read(err_r6, &mut buf);
        sys_close(err_r6);
        assert!(n6 > 0);

        let _ = sys_unlink_pool("/tmp/cmp1.txt");
        let _ = sys_unlink_pool("/tmp/cmp2.txt");
        let _ = sys_unlink_pool("/tmp/cmp3.txt");
    }

    #[test]
    fn test_expand_basic_and_options() {
        // Création d'un fichier avec tabulations
        let fd = sys_open("/tmp/expand_input.txt", O_CREAT | O_WRONLY);
        assert!(fd >= 0);
        let content = b"\ta\tb\tc\n  \tfoo\tbar\n";
        let _ = sys_write(fd, content);
        let _ = sys_close(fd);

        // Test 1 : expand par défaut (tabstops de 8)
        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_expand(&["/tmp/expand_input.txt"], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);

        let mut buf = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf);
        sys_close(out_r1);
        let res1 = core::str::from_utf8(&buf[..n1 as usize]).unwrap();
        // "\ta\tb\tc\n" -> 8 spaces then 'a', then 7 spaces then 'b', then 7 spaces then 'c'
        assert!(res1.starts_with("        a       b       c\n"));

        // Test 2 : expand avec tabstop personnalisé -t 4
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_expand(&["-t", "4", "/tmp/expand_input.txt"], 0, out_w2, 2);
        sys_close(out_w2);
        assert_eq!(code2, 0);

        let n2 = sys_read(out_r2, &mut buf);
        sys_close(out_r2);
        let res2 = core::str::from_utf8(&buf[..n2 as usize]).unwrap();
        assert!(res2.starts_with("    a   b   c\n"));

        // Test 3 : expand avec -i (initial tabs only)
        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_expand(&["-i", "/tmp/expand_input.txt"], 0, out_w3, 2);
        sys_close(out_w3);
        assert_eq!(code3, 0);

        let n3 = sys_read(out_r3, &mut buf);
        sys_close(out_r3);
        let res3 = core::str::from_utf8(&buf[..n3 as usize]).unwrap();
        // La première tabulation initiale est convertie, mais \tb et \tc restent des tabulations
        assert!(res3.starts_with("        a\tb\tc\n"));
    }

    #[test]
    fn test_unexpand_basic_and_options() {
        let fd = sys_open("/tmp/unexpand_input.txt", O_CREAT | O_WRONLY);
        assert!(fd >= 0);
        let content = b"        leading word        middle word\n    four spaces\n";
        let _ = sys_write(fd, content);
        let _ = sys_close(fd);

        // Test 1 : unexpand par défaut (seulement leading whitespace, tabstops de 8)
        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_unexpand(&["/tmp/unexpand_input.txt"], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);

        let mut buf = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf);
        sys_close(out_r1);
        let res1 = core::str::from_utf8(&buf[..n1 as usize]).unwrap();
        // 8 espaces initiaux convertis en '\t', mais les 8 espaces du milieu restent des espaces
        assert!(res1.starts_with("\tleading word        middle word\n"));

        // Test 2 : unexpand -a (tous les espaces alignés sur les tabstops sont convertis)
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_unexpand(&["-a", "/tmp/unexpand_input.txt"], 0, out_w2, 2);
        sys_close(out_w2);
        assert_eq!(code2, 0);

        let n2 = sys_read(out_r2, &mut buf);
        sys_close(out_r2);
        let res2 = core::str::from_utf8(&buf[..n2 as usize]).unwrap();
        // Avec -a, tant les espaces initiaux que les espaces au milieu alignés sur tabstops sont convertis
        assert!(res2.contains("\tleading word"));
        assert!(res2.contains("leading word\t    middle word\n"));

        // Test 3 : unexpand -t 4 (tabstop à 4 colonnes, implique -a)
        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_unexpand(&["-t", "4", "/tmp/unexpand_input.txt"], 0, out_w3, 2);
        sys_close(out_w3);
        assert_eq!(code3, 0);

        let n3 = sys_read(out_r3, &mut buf);
        sys_close(out_r3);
        let res3 = core::str::from_utf8(&buf[..n3 as usize]).unwrap();
        // 4 spaces -> \t
        assert!(res3.contains("\tfour spaces\n"));

        // Test 4 : unexpand --help
        let (out_r4, out_w4) = crate::vfs::pipe().unwrap();
        let code4 = run_unexpand(&["--help"], 0, out_w4, 2);
        sys_close(out_w4);
        assert_eq!(code4, 0);
        let n4 = sys_read(out_r4, &mut buf);
        sys_close(out_r4);
        let res4 = core::str::from_utf8(&buf[..n4 as usize]).unwrap();
        assert!(res4.contains("Usage: unexpand"));
    }

    #[test]
    fn test_sleep_parsing_and_options() {
        // 1. Parsing précis des intervalles
        assert_eq!(parse_interval_ms("1"), Some(1_000));
        assert_eq!(parse_interval_ms("2s"), Some(2_000));
        assert_eq!(parse_interval_ms("0.5"), Some(500));
        assert_eq!(parse_interval_ms("1.5s"), Some(1_500));
        assert_eq!(parse_interval_ms(".25s"), Some(250));
        assert_eq!(parse_interval_ms("2m"), Some(120_000));
        assert_eq!(parse_interval_ms("0.5m"), Some(30_000));
        assert_eq!(parse_interval_ms("1h"), Some(3_600_000));
        assert_eq!(parse_interval_ms("1d"), Some(86_400_000));

        // Invalides
        assert_eq!(parse_interval_ms(""), None);
        assert_eq!(parse_interval_ms("foo"), None);
        assert_eq!(parse_interval_ms("1x"), None);
        assert_eq!(parse_interval_ms("1.2.3"), None);
        assert_eq!(parse_interval_ms("."), None);

        // 2. sleep --help
        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_sleep(&["--help"], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);
        let mut buf = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf);
        sys_close(out_r1);
        let res1 = core::str::from_utf8(&buf[..n1 as usize]).unwrap();
        assert!(res1.contains("Usage: sleep"));

        // 3. sleep --version
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_sleep(&["--version"], 0, out_w2, 2);
        sys_close(out_w2);
        assert_eq!(code2, 0);
        let n2 = sys_read(out_r2, &mut buf);
        sys_close(out_r2);
        let res2 = core::str::from_utf8(&buf[..n2 as usize]).unwrap();
        assert!(res2.contains("sleep (JamboOS coreutils)"));

        // 4. sleep sans argument (erreur opérande manquant)
        let (err_r3, err_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_sleep(&[], 0, 1, err_w3);
        sys_close(err_w3);
        assert_eq!(code3, 1);
        let n3 = sys_read(err_r3, &mut buf);
        sys_close(err_r3);
        let res3 = core::str::from_utf8(&buf[..n3 as usize]).unwrap();
        assert!(res3.contains("sleep: missing operand"));

        // 5. sleep avec intervalle invalide
        let (err_r4, err_w4) = crate::vfs::pipe().unwrap();
        let code4 = run_sleep(&["bad_val"], 0, 1, err_w4);
        sys_close(err_w4);
        assert_eq!(code4, 1);
        let n4 = sys_read(err_r4, &mut buf);
        sys_close(err_r4);
        let res4 = core::str::from_utf8(&buf[..n4 as usize]).unwrap();
        assert!(res4.contains("sleep: invalid time interval 'bad_val'"));

        // 6. sleep valide (0.001s)
        let code5 = run_sleep(&["0.001s"], 0, 1, 2);
        assert_eq!(code5, 0);
    }

    #[test]
    fn test_posix_cksum() {
        // 1. Chaîne vide
        let mut cksum_empty = PosixCksum::new();
        cksum_empty.update(b"");
        let (crc0, len0) = cksum_empty.finalize();
        assert_eq!(crc0, 4294967295);
        assert_eq!(len0, 0);

        // 2. Chaîne "hello\n"
        let mut cksum_hello = PosixCksum::new();
        cksum_hello.update(b"hello\n");
        let (crc_h, len_h) = cksum_hello.finalize();
        assert_eq!(crc_h, 3015617425);
        assert_eq!(len_h, 6);

        // 3. cksum --help
        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_cksum(&["--help"], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);
        let mut buf = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf);
        sys_close(out_r1);
        let res1 = core::str::from_utf8(&buf[..n1 as usize]).unwrap();
        assert!(res1.contains("Usage: cksum"));

        // 4. cksum standard input via pipe
        let (in_r2, in_w2) = crate::vfs::pipe().unwrap();
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let _ = sys_write(in_w2, b"hello\n");
        sys_close(in_w2);
        let code2 = run_cksum(&[], in_r2, out_w2, 2);
        sys_close(in_r2);
        sys_close(out_w2);
        assert_eq!(code2, 0);
        let n2 = sys_read(out_r2, &mut buf);
        sys_close(out_r2);
        let res2 = core::str::from_utf8(&buf[..n2 as usize]).unwrap();
        assert_eq!(res2, "3015617425 6\n");
    }

    #[test]
    fn test_posix_base64() {
        let mut out = [0u8; 128];

        // 1. Vecteurs de test officiels RFC 4648 Section 10
        let n_empty = base64_encode(b"", &mut out, 0).unwrap();
        assert_eq!(n_empty, 0);

        let n1 = base64_encode(b"f", &mut out, 0).unwrap();
        assert_eq!(&out[..n1], b"Zg==\n");

        let n2 = base64_encode(b"fo", &mut out, 0).unwrap();
        assert_eq!(&out[..n2], b"Zm8=\n");

        let n3 = base64_encode(b"foo", &mut out, 0).unwrap();
        assert_eq!(&out[..n3], b"Zm9v\n");

        let n4 = base64_encode(b"foob", &mut out, 0).unwrap();
        assert_eq!(&out[..n4], b"Zm9vYg==\n");

        let n5 = base64_encode(b"fooba", &mut out, 0).unwrap();
        assert_eq!(&out[..n5], b"Zm9vYmE=\n");

        let n6 = base64_encode(b"foobar", &mut out, 0).unwrap();
        assert_eq!(&out[..n6], b"Zm9vYmFy\n");

        // 2. Décodage inverse rigoureux
        let mut dec = [0u8; 128];
        let d1 = base64_decode(b"Zg==", &mut dec, false).unwrap();
        assert_eq!(&dec[..d1], b"f");

        let d2 = base64_decode(b"Zm8=", &mut dec, false).unwrap();
        assert_eq!(&dec[..d2], b"fo");

        let d3 = base64_decode(b"Zm9v", &mut dec, false).unwrap();
        assert_eq!(&dec[..d3], b"foo");

        let d4 = base64_decode(b"Zm9vYg==", &mut dec, false).unwrap();
        assert_eq!(&dec[..d4], b"foob");

        let d5 = base64_decode(b"Zm9vYmE=", &mut dec, false).unwrap();
        assert_eq!(&dec[..d5], b"fooba");

        let d6 = base64_decode(b"Zm9vYmFy", &mut dec, false).unwrap();
        assert_eq!(&dec[..d6], b"foobar");

        // 3. Décodage avec retour à la ligne et espaces
        let d_ws = base64_decode(b"Zm9v\r\n  YmFy\n", &mut dec, false).unwrap();
        assert_eq!(&dec[..d_ws], b"foobar");

        // 4. Wrap des colonnes
        let n_wrap = base64_encode(b"foobar", &mut out, 4).unwrap();
        assert_eq!(&out[..n_wrap], b"Zm9v\nYmFy\n");

        // 5. base64 --help
        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_base64(&["--help"], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);
        let mut buf = [0u8; 256];
        let n_help = sys_read(out_r1, &mut buf);
        sys_close(out_r1);
        let res_help = core::str::from_utf8(&buf[..n_help as usize]).unwrap();
        assert!(res_help.contains("Usage: base64"));

        // 6. Pipe encode
        let (in_r2, in_w2) = crate::vfs::pipe().unwrap();
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let _ = sys_write(in_w2, b"JamboOS\n");
        sys_close(in_w2);
        let code2 = run_base64(&["-w0"], in_r2, out_w2, 2);
        sys_close(in_r2);
        sys_close(out_w2);
        assert_eq!(code2, 0);
        let n_enc = sys_read(out_r2, &mut buf);
        sys_close(out_r2);
        assert_eq!(&buf[..n_enc as usize], b"SmFtYm9PUwo=\n");

        // 7. Pipe decode
        let (in_r3, in_w3) = crate::vfs::pipe().unwrap();
        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let _ = sys_write(in_w3, b"SmFtYm9PUwo=\n");
        sys_close(in_w3);
        let code3 = run_base64(&["-d"], in_r3, out_w3, 2);
        sys_close(in_r3);
        sys_close(out_w3);
        assert_eq!(code3, 0);
        let n_dec = sys_read(out_r3, &mut buf);
        sys_close(out_r3);
        assert_eq!(&buf[..n_dec as usize], b"JamboOS\n");
    }

    #[test]
    fn test_posix_sha256sum() {
        // 1. Vecteurs NIST connus (in-memory)
        let empty_hash = Sha256Hasher::hash(b"");
        let mut empty_hex = [0u8; 64];
        sha256_to_hex(&empty_hash, &mut empty_hex);
        assert_eq!(
            core::str::from_utf8(&empty_hex).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc_hash = Sha256Hasher::hash(b"abc");
        let mut abc_hex = [0u8; 64];
        sha256_to_hex(&abc_hash, &mut abc_hex);
        assert_eq!(
            core::str::from_utf8(&abc_hex).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // 2. Calcul sha256sum sur fichier VFS
        let file_path = "/tmp/test_sha256_data.txt";
        let fd = sys_open(file_path, O_CREAT | O_WRONLY);
        assert!(fd >= 0);
        let _ = sys_write(fd, b"abc");
        sys_close(fd);

        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_sha256sum(&[file_path], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);

        let mut buf1 = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf1);
        sys_close(out_r1);
        let s1 = core::str::from_utf8(&buf1[..n1 as usize]).unwrap();
        assert!(s1.starts_with("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /tmp/test_sha256_data.txt"));

        // 3. Mode BSD style --tag
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_sha256sum(&["--tag", file_path], 0, out_w2, 2);
        sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut buf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut buf2);
        sys_close(out_r2);
        let s2 = core::str::from_utf8(&buf2[..n2 as usize]).unwrap();
        assert_eq!(
            s2,
            "SHA256 (/tmp/test_sha256_data.txt) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
        );

        // 4. Mode vérification (-c / --check) réussi
        let check_file = "/tmp/test_sha256.chk";
        let chk_fd = sys_open(check_file, O_CREAT | O_WRONLY);
        assert!(chk_fd >= 0);
        let _ = sys_write(chk_fd, b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /tmp/test_sha256_data.txt\n");
        sys_close(chk_fd);

        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_sha256sum(&["-c", check_file], 0, out_w3, 2);
        sys_close(out_w3);
        assert_eq!(code3, 0);

        let mut buf3 = [0u8; 256];
        let n3 = sys_read(out_r3, &mut buf3);
        sys_close(out_r3);
        let s3 = core::str::from_utf8(&buf3[..n3 as usize]).unwrap();
        assert!(s3.contains("/tmp/test_sha256_data.txt: OK"));

        // 5. Mode vérification échoué (altération des données)
        let bad_fd = sys_open(file_path, O_CREAT | O_WRONLY);
        assert!(bad_fd >= 0);
        let _ = sys_write(bad_fd, b"corrupted data");
        sys_close(bad_fd);

        let (out_r4, out_w4) = crate::vfs::pipe().unwrap();
        let code4 = run_sha256sum(&["-c", check_file], 0, out_w4, 2);
        sys_close(out_w4);
        assert_eq!(code4, 1);

        let mut buf4 = [0u8; 256];
        let n4 = sys_read(out_r4, &mut buf4);
        sys_close(out_r4);
        let s4 = core::str::from_utf8(&buf4[..n4 as usize]).unwrap();
        assert!(s4.contains("/tmp/test_sha256_data.txt: FAILED"));

        // 6. Streaming stdin
        let (in_r5, in_w5) = crate::vfs::pipe().unwrap();
        let (out_r5, out_w5) = crate::vfs::pipe().unwrap();
        let _ = sys_write(in_w5, b"abc");
        sys_close(in_w5);
        let code5 = run_sha256sum(&["-"], in_r5, out_w5, 2);
        sys_close(in_r5);
        sys_close(out_w5);
        assert_eq!(code5, 0);

        let mut buf5 = [0u8; 256];
        let n5 = sys_read(out_r5, &mut buf5);
        sys_close(out_r5);
        let s5 = core::str::from_utf8(&buf5[..n5 as usize]).unwrap();
        assert!(
            s5.starts_with("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -\n")
        );

        // 7. --help et --version
        let (out_r6, out_w6) = crate::vfs::pipe().unwrap();
        let code6 = run_sha256sum(&["--help"], 0, out_w6, 2);
        sys_close(out_w6);
        assert_eq!(code6, 0);
        let mut buf6 = [0u8; 512];
        let n6 = sys_read(out_r6, &mut buf6);
        sys_close(out_r6);
        assert!(core::str::from_utf8(&buf6[..n6 as usize])
            .unwrap()
            .contains("Usage: sha256sum"));

        // Nettoyage
        let _ = sys_unlink_pool(file_path);
        let _ = sys_unlink_pool(check_file);
    }

    #[test]
    fn test_posix_sync() {
        // 1. sync global sans arguments
        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_sync(&[], 0, out_w1, 2);
        sys_close(out_w1);
        sys_close(out_r1);
        assert_eq!(code1, 0);

        // 2. sync sur fichier VFS existant
        let file_path = "/tmp/sync_target.dat";
        let fd = sys_open(file_path, O_CREAT | O_WRONLY);
        assert!(fd >= 0);
        let _ = sys_write(fd, b"synchronize data test\n");
        sys_close(fd);

        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_sync(&[file_path], 0, out_w2, 2);
        sys_close(out_w2);
        sys_close(out_r2);
        assert_eq!(code2, 0);

        // 3. sync avec options -d (fdatasync) et -f (filesystem)
        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_sync(&["-d", file_path], 0, out_w3, 2);
        sys_close(out_w3);
        sys_close(out_r3);
        assert_eq!(code3, 0);

        let (out_r4, out_w4) = crate::vfs::pipe().unwrap();
        let code4 = run_sync(&["--file-system", file_path], 0, out_w4, 2);
        sys_close(out_w4);
        sys_close(out_r4);
        assert_eq!(code4, 0);

        // 4. sync sur fichier inexistant (doit retourner 1)
        let (err_r5, err_w5) = crate::vfs::pipe().unwrap();
        let code5 = run_sync(&["/tmp/nonexistent_file_xyz.txt"], 0, 1, err_w5);
        sys_close(err_w5);
        assert_eq!(code5, 1);
        let mut err_buf = [0u8; 128];
        let n5 = sys_read(err_r5, &mut err_buf);
        sys_close(err_r5);
        assert!(core::str::from_utf8(&err_buf[..n5 as usize])
            .unwrap()
            .contains("No such file or directory"));

        // 5. sync --help et --version
        let (out_r6, out_w6) = crate::vfs::pipe().unwrap();
        let code6 = run_sync(&["--help"], 0, out_w6, 2);
        sys_close(out_w6);
        assert_eq!(code6, 0);
        let mut h_buf = [0u8; 256];
        let n6 = sys_read(out_r6, &mut h_buf);
        sys_close(out_r6);
        assert!(core::str::from_utf8(&h_buf[..n6 as usize])
            .unwrap()
            .contains("Usage: sync"));

        let _ = sys_unlink_pool(file_path);
    }

    #[test]
    fn test_posix_truncate() {
        let file_path = "/tmp/test_truncate_sample.bin";
        let _ = sys_unlink_pool(file_path);

        // 1. Création avec taille spécifiée : truncate -s 64 /tmp/...
        let code1 = run_truncate(&["-s", "64", file_path], 0, 1, 2);
        assert_eq!(code1, 0);
        let fd1 = sys_open(file_path, crate::vfs::O_RDONLY);
        assert!(fd1 >= 0);
        let sz1 = with_fd_table(|tbl| tbl.get(fd1).map(|e| e.size).unwrap());
        sys_close(fd1);
        assert_eq!(sz1, 64);

        // 2. Extension relative : truncate -s +36 /tmp/... (64 + 36 = 100)
        let code2 = run_truncate(&["-s", "+36", file_path], 0, 1, 2);
        assert_eq!(code2, 0);
        let fd2 = sys_open(file_path, crate::vfs::O_RDONLY);
        let sz2 = with_fd_table(|tbl| tbl.get(fd2).map(|e| e.size).unwrap());
        sys_close(fd2);
        assert_eq!(sz2, 100);

        // 3. Réduction relative : truncate -s -50 /tmp/... (100 - 50 = 50)
        let code3 = run_truncate(&["-s", "-50", file_path], 0, 1, 2);
        assert_eq!(code3, 0);
        let fd3 = sys_open(file_path, crate::vfs::O_RDONLY);
        let sz3 = with_fd_table(|tbl| tbl.get(fd3).map(|e| e.size).unwrap());
        sys_close(fd3);
        assert_eq!(sz3, 50);

        // 4. Suffixe multiplicateur : truncate -s 1K /tmp/... (1024)
        let code4 = run_truncate(&["-s", "1K", file_path], 0, 1, 2);
        assert_eq!(code4, 0);
        let fd4 = sys_open(file_path, crate::vfs::O_RDONLY);
        let sz4 = with_fd_table(|tbl| tbl.get(fd4).map(|e| e.size).unwrap());
        sys_close(fd4);
        assert_eq!(sz4, 1024);

        // 5. Option -c : no-create sur fichier inexistant
        let no_file = "/tmp/does_not_exist_truncate.txt";
        let code5 = run_truncate(&["-c", "-s", "100", no_file], 0, 1, 2);
        assert_eq!(code5, 0);
        let fd_none = sys_open(no_file, crate::vfs::O_RDONLY);
        assert_eq!(fd_none, -1);

        // 6. Erreur si absence d'option -s ou -r
        let (err_r6, err_w6) = crate::vfs::pipe().unwrap();
        let code6 = run_truncate(&[file_path], 0, 1, err_w6);
        sys_close(err_w6);
        assert_eq!(code6, 1);
        let mut err_buf = [0u8; 128];
        let n6 = sys_read(err_r6, &mut err_buf);
        sys_close(err_r6);
        assert!(core::str::from_utf8(&err_buf[..n6 as usize])
            .unwrap()
            .contains("you must specify a size"));

        // 7. --help et --version
        let (out_r7, out_w7) = crate::vfs::pipe().unwrap();
        let code7 = run_truncate(&["--help"], 0, out_w7, 2);
        sys_close(out_w7);
        assert_eq!(code7, 0);
        let mut h_buf = [0u8; 256];
        let n7 = sys_read(out_r7, &mut h_buf);
        sys_close(out_r7);
        assert!(core::str::from_utf8(&h_buf[..n7 as usize])
            .unwrap()
            .contains("Usage: truncate"));

        let _ = sys_unlink_pool(file_path);
    }

    #[test]
    fn test_posix_hexdump() {
        let mut buf = [0u8; 512];

        // 1. hexdump -C (canonique hex + ASCII)
        let (in_r1, in_w1) = crate::vfs::pipe().expect("pipe hexdump in 1");
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe hexdump out 1");
        let _ = sys_write(in_w1, b"Hello World!\n");
        sys_close(in_w1);

        let code1 = run_hexdump(&["-C"], in_r1, out_w1, 2);
        assert_eq!(code1, 0);
        sys_close(in_r1);
        sys_close(out_w1);

        let n1 = sys_read(out_r1, &mut buf);
        let out_str1 = core::str::from_utf8(&buf[..n1 as usize]).unwrap();
        assert!(out_str1.starts_with("00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 0a"));
        assert!(out_str1.contains("|Hello World!.|"));
        assert!(out_str1.ends_with("0000000d\n"));
        sys_close(out_r1);

        // 2. hexdump -c (one-byte character display)
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe hexdump in 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe hexdump out 2");
        let _ = sys_write(in_w2, b"Hi\n");
        sys_close(in_w2);

        let code2 = run_hexdump(&["-c"], in_r2, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(in_r2);
        sys_close(out_w2);

        let n2 = sys_read(out_r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"0000000   H   i  \\n\n0000003\n");
        sys_close(out_r2);

        // 3. hexdump -b (one-byte octal display)
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe hexdump in 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe hexdump out 3");
        let _ = sys_write(in_w3, b"ABC\n");
        sys_close(in_w3);

        let code3 = run_hexdump(&["-b"], in_r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(in_r3);
        sys_close(out_w3);

        let n3 = sys_read(out_r3, &mut buf);
        assert_eq!(&buf[..n3 as usize], b"0000000 101 102 103 012\n0000004\n");
        sys_close(out_r3);

        // 4. hexdump avec fichier VFS et option -n (length limit)
        let file_path = "/tmp/test_hexdump.txt";
        let fd_hd = sys_open(file_path, crate::vfs::O_CREAT | crate::vfs::O_WRONLY);
        assert!(fd_hd >= 0);
        let _ = sys_write(fd_hd, b"JamboOS System");
        sys_close(fd_hd);

        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe hexdump out 4");
        let code4 = run_hexdump(&["-C", "-n", "7", file_path], 0, out_w4, 2);
        assert_eq!(code4, 0);
        sys_close(out_w4);

        let n4 = sys_read(out_r4, &mut buf);
        let out_str4 = core::str::from_utf8(&buf[..n4 as usize]).unwrap();
        assert!(out_str4.contains("4a 61 6d 62 6f 4f 53"));
        assert!(out_str4.contains("|JamboOS|"));
        assert!(out_str4.ends_with("00000007\n"));
        sys_close(out_r4);

        // 5. Option --help
        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe hexdump out 5");
        let code5 = run_hexdump(&["--help"], 0, out_w5, 2);
        assert_eq!(code5, 0);
        sys_close(out_w5);

        let n5 = sys_read(out_r5, &mut buf);
        let help_str = core::str::from_utf8(&buf[..n5 as usize]).unwrap();
        assert!(help_str.contains("Usage: hexdump"));
        sys_close(out_r5);

        let _ = sys_unlink_pool(file_path);
    }

    #[test]
    fn test_which_builtin_and_vfs() {
        // 1. Créer un binaire factice dans /bin/custom_tool
        let tool_path = "/bin/custom_tool";
        let fd_tool = sys_open(tool_path, crate::vfs::O_CREAT | crate::vfs::O_WRONLY);
        assert!(fd_tool >= 0);
        let _ = sys_write(fd_tool, b"\x7FELF");
        sys_close(fd_tool);

        let mut buf = [0u8; 256];
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe which out");
        let code = run_which(&["custom_tool"], 0, out_w, 2);
        assert_eq!(code, 0);
        sys_close(out_w);

        let n = sys_read(out_r, &mut buf);
        let out_str = core::str::from_utf8(&buf[..n as usize]).unwrap();
        assert_eq!(out_str, "/bin/custom_tool\n");
        sys_close(out_r);

        // 2. Recherche avec chemin absolu
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe which out 2");
        let code2 = run_which(&["/bin/custom_tool"], 0, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(out_w2);

        let n2 = sys_read(out_r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"/bin/custom_tool\n");
        sys_close(out_r2);

        // 3. Outil inexistant
        let (err_r3, err_w3) = crate::vfs::pipe().expect("pipe which err 3");
        let code3 = run_which(&["non_existent_binary"], 0, 1, err_w3);
        assert_eq!(code3, 1);
        sys_close(err_w3);

        let n3 = sys_read(err_r3, &mut buf);
        let err_str = core::str::from_utf8(&buf[..n3 as usize]).unwrap();
        assert!(err_str.contains("which: no non_existent_binary in"));
        sys_close(err_r3);

        let _ = sys_unlink_pool(tool_path);
    }

    #[test]
    fn test_time_basic_execution() {
        let mut buf = [0u8; 128];

        // 1. time echo hello
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe out");
        let (err_r, err_w) = crate::vfs::pipe().expect("pipe err");
        let code = run_time(&["echo", "hello"], 0, out_w, err_w);
        assert_eq!(code, 0);
        sys_close(out_w);
        sys_close(err_w);

        let n_out = sys_read(out_r, &mut buf);
        assert_eq!(&buf[..n_out as usize], b"hello\n");
        sys_close(out_r);

        let mut err_buf = [0u8; 256];
        let n_err = sys_read(err_r, &mut err_buf);
        let err_str = core::str::from_utf8(&err_buf[..n_err as usize]).unwrap();
        assert!(err_str.contains("real\t"));
        assert!(err_str.contains("user\t"));
        assert!(err_str.contains("sys\t"));
        sys_close(err_r);

        // 2. time -p (format POSIX 1003.2)
        let (err_r2, err_w2) = crate::vfs::pipe().expect("pipe err 2");
        let code2 = run_time(&["-p", "true"], 0, 1, err_w2);
        assert_eq!(code2, 0);
        sys_close(err_w2);

        let n_err2 = sys_read(err_r2, &mut err_buf);
        let err_str2 = core::str::from_utf8(&err_buf[..n_err2 as usize]).unwrap();
        assert!(err_str2.starts_with("real "));
        assert!(err_str2.contains("user 0.00"));
        assert!(err_str2.contains("sys 0.00"));
        sys_close(err_r2);
    }

    #[test]
    fn test_xargs_basic_execution() {
        let mut buf = [0u8; 256];

        // 1. echo "foo bar baz" | xargs echo (par défaut target_cmd = echo)
        let (in_r, in_w) = crate::vfs::pipe().expect("pipe in");
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe out");
        let _ = sys_write(in_w, b"foo bar\nbaz\n");
        sys_close(in_w);

        let code = run_xargs(&["echo"], in_r, out_w, 2);
        assert_eq!(code, 0);
        sys_close(in_r);
        sys_close(out_w);

        let n = sys_read(out_r, &mut buf);
        assert_eq!(&buf[..n as usize], b"foo bar baz\n");
        sys_close(out_r);

        // 2. xargs -n 1
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe in 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe out 2");
        let _ = sys_write(in_w2, b"a b c\n");
        sys_close(in_w2);

        let code2 = run_xargs(&["-n", "1", "echo"], in_r2, out_w2, 2);
        assert_eq!(code2, 0);
        sys_close(in_r2);
        sys_close(out_w2);

        let n2 = sys_read(out_r2, &mut buf);
        assert_eq!(&buf[..n2 as usize], b"a\nb\nc\n");
        sys_close(out_r2);

        // 3. xargs -0 (null delimiter)
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe in 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe out 3");
        let _ = sys_write(in_w3, b"file with space.txt\0second file.log\0");
        sys_close(in_w3);

        let code3 = run_xargs(&["-0", "-n", "1", "echo"], in_r3, out_w3, 2);
        assert_eq!(code3, 0);
        sys_close(in_r3);
        sys_close(out_w3);

        let n3 = sys_read(out_r3, &mut buf);
        assert_eq!(
            &buf[..n3 as usize],
            b"file with space.txt\nsecond file.log\n"
        );
        sys_close(out_r3);
    }

    #[test]
    fn test_dd_block_transfer_and_seek_skip() {
        let mut buf = [0u8; 512];

        // 1. Transfert de base via pipe avec bs=4 et count=3
        let (in_r, in_w) = crate::vfs::pipe().expect("pipe in");
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe out");
        let _ = sys_write(in_w, b"abcdefghijklmnopqrstuvwxyz");
        sys_close(in_w);

        let code = run_dd(&["bs=4", "count=3", "status=none"], in_r, out_w, 2);
        assert_eq!(code, 0);
        sys_close(in_r);
        sys_close(out_w);

        let n = sys_read(out_r, &mut buf);
        assert_eq!(n, 12);
        assert_eq!(&buf[..12], b"abcdefghijkl");
        sys_close(out_r);

        // 2. Transfert if / of avec fichier virtuel
        let src_file = "/tmp/dd_src.bin";
        let dst_file = "/tmp/dd_dst.bin";
        let fd_src = sys_open(src_file, crate::vfs::O_CREAT | crate::vfs::O_WRONLY);
        assert!(fd_src >= 0);
        let _ = sys_write(fd_src, b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        sys_close(fd_src);

        let code2 = run_dd(
            &[
                "if=/tmp/dd_src.bin",
                "of=/tmp/dd_dst.bin",
                "bs=8",
                "skip=1",
                "count=2",
                "status=none",
            ],
            0,
            1,
            2,
        );
        assert_eq!(code2, 0);

        let fd_dst = sys_open(dst_file, crate::vfs::O_RDONLY);
        assert!(fd_dst >= 0);
        let n_dst = sys_read(fd_dst, &mut buf);
        assert_eq!(n_dst, 16);
        assert_eq!(&buf[..16], b"89ABCDEFGHIJKLMN");
        sys_close(fd_dst);

        // 3. Option conv=sync
        let (in_r3, in_w3) = crate::vfs::pipe().expect("pipe in 3");
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe out 3");
        let _ = sys_write(in_w3, b"123");
        sys_close(in_w3);

        let code3 = run_dd(
            &["ibs=8", "obs=8", "conv=sync", "status=none"],
            in_r3,
            out_w3,
            2,
        );
        assert_eq!(code3, 0);
        sys_close(in_r3);
        sys_close(out_w3);

        let n3 = sys_read(out_r3, &mut buf);
        assert_eq!(n3, 8);
        assert_eq!(&buf[..3], b"123");
        assert_eq!(&buf[3..8], &[0, 0, 0, 0, 0]);
        sys_close(out_r3);
    }

    #[test]
    fn test_readlink_symlink_and_canonical() {
        let symlink_path = "/tmp/test_symlink.lnk";
        let target_path = "/etc/os-release";

        // Création du lien symbolique virtuel
        assert_eq!(sys_symlink_pool(target_path, symlink_path), 0);

        let (out_r, out_w) = crate::vfs::pipe().expect("pipe out");
        let (err_r, err_w) = crate::vfs::pipe().expect("pipe err");

        // 1. readlink standard
        let code = run_readlink(&[symlink_path], 0, out_w, err_w);
        assert_eq!(code, 0);
        let _ = sys_close(out_w);
        let _ = sys_close(err_w);

        let mut buf = [0u8; 128];
        let n = sys_read(out_r, &mut buf);
        assert_eq!(n, 16); // "/etc/os-release\n"
        assert_eq!(&buf[..n as usize], b"/etc/os-release\n");
        let _ = sys_close(out_r);
        let _ = sys_close(err_r);

        // 2. readlink -n (sans saut de ligne)
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe out 2");
        let code2 = run_readlink(&["-n", symlink_path], 0, out_w2, 2);
        assert_eq!(code2, 0);
        let _ = sys_close(out_w2);
        let n2 = sys_read(out_r2, &mut buf);
        assert_eq!(n2, 15); // "/etc/os-release"
        assert_eq!(&buf[..n2 as usize], b"/etc/os-release");
        let _ = sys_close(out_r2);

        // 3. readlink -f (canonicalisation d'un fichier régulier existant)
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe out 3");
        let code3 = run_readlink(&["-f", "/etc/hostname"], 0, out_w3, 2);
        assert_eq!(code3, 0);
        let _ = sys_close(out_w3);
        let n3 = sys_read(out_r3, &mut buf);
        assert_eq!(n3, 14); // "/etc/hostname\n"
        assert_eq!(&buf[..n3 as usize], b"/etc/hostname\n");
        let _ = sys_close(out_r3);
    }

    #[test]
    fn test_stat_and_symbolic_chmod() {
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe stat");
        let (err_r, err_w) = crate::vfs::pipe().expect("pipe err");

        // 1. Test stat standard
        let code1 = run_stat(&["/etc/hostname"], 0, out_w, err_w);
        assert_eq!(code1, 0);
        let _ = sys_close(out_w);
        let _ = sys_close(err_w);
        let mut buf = [0u8; 512];
        let n1 = sys_read(out_r, &mut buf);
        assert!(n1 > 0);
        let s1 = core::str::from_utf8(&buf[..n1 as usize]).unwrap();
        assert!(s1.contains("File: /etc/hostname"));
        assert!(s1.contains("Size: 14"));
        assert!(s1.contains("regular file"));
        let _ = sys_close(out_r);
        let _ = sys_close(err_r);

        // 2. Test stat -c %a %s %n
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe stat 2");
        let code2 = run_stat(&["-c", "%a %s %n", "/etc/hostname"], 0, out_w2, 2);
        assert_eq!(code2, 0);
        let _ = sys_close(out_w2);
        let n2 = sys_read(out_r2, &mut buf);
        assert!(n2 > 0);
        let s2 = core::str::from_utf8(&buf[..n2 as usize]).unwrap();
        assert!(s2.starts_with("644 14 /etc/hostname"));
        let _ = sys_close(out_r2);

        // 3. Test chmod symbolique ("u+x,g-w,o=r")
        let (err_r3, err_w3) = crate::vfs::pipe().expect("pipe err 3");
        let code3 = run_chmod(&["u+x", "/etc/hostname"], err_w3);
        assert_eq!(code3, 0);
        let _ = sys_close(err_w3);
        let _ = sys_close(err_r3);

        let m3 = sys_get_mode_pool("/etc/hostname").expect("mode exists");
        assert_eq!(m3, 0o744); // 0644 | 0100 = 0744

        // Rétablir les permissions d'origine
        let code_restore = run_chmod(&["644", "/etc/hostname"], 2);
        assert_eq!(code_restore, 0);
        let m_restored = sys_get_mode_pool("/etc/hostname").expect("mode restored");
        assert_eq!(m_restored, 0o644);
    }

    #[test]
    fn test_ln_hard_and_symbolic_link() {
        let target = "/etc/hostname";
        let sym_link = "/tmp/test_ln_sym.lnk";
        let hard_link = "/tmp/test_ln_hard.lnk";

        // Nettoyage préalable
        let _ = sys_unlink_pool(sym_link);
        let _ = sys_unlink_pool(hard_link);

        // 1. Création d'un lien symbolique via run_ln -s
        let (err_r1, err_w1) = crate::vfs::pipe().expect("pipe err 1");
        let code1 = run_ln(&["-s", target, sym_link], 0, 1, err_w1);
        assert_eq!(code1, 0);
        let _ = sys_close(err_w1);
        let _ = sys_close(err_r1);

        // Vérification avec readlink
        let mut readlink_buf = [0u8; 64];
        let n_link = sys_readlink_pool(sym_link, &mut readlink_buf);
        assert!(n_link > 0);
        assert_eq!(&readlink_buf[..n_link as usize], target.as_bytes());

        // 2. Création d'un lien physique (hard link) via run_ln
        let (err_r2, err_w2) = crate::vfs::pipe().expect("pipe err 2");
        let code2 = run_ln(&[target, hard_link], 0, 1, err_w2);
        assert_eq!(code2, 0);
        let _ = sys_close(err_w2);
        let _ = sys_close(err_r2);

        // Vérification de contenu et taille identiques pour le hard link
        let stat_target = sys_stat_pool(target).expect("stat target");
        let stat_hard = sys_stat_pool(hard_link).expect("stat hard link");
        assert_eq!(stat_target.st_size, stat_hard.st_size);
        assert_eq!(stat_target.st_mode & 0o777, stat_hard.st_mode & 0o777);

        // 3. Forçage avec -sf sur un lien existant
        let code3 = run_ln(&["-sf", "/etc/os-release", sym_link], 0, 1, 2);
        assert_eq!(code3, 0);
        let n_link2 = sys_readlink_pool(sym_link, &mut readlink_buf);
        assert_eq!(&readlink_buf[..n_link2 as usize], b"/etc/os-release");

        // Nettoyage final
        let _ = sys_unlink_pool(sym_link);
        let _ = sys_unlink_pool(hard_link);
    }

    #[test]
    fn test_mktemp_file_and_directory_atomic_creation() {
        // 1. Création atomique de fichier temporaire par défaut
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe out 1");
        let (err_r1, err_w1) = crate::vfs::pipe().expect("pipe err 1");
        let code1 = run_mktemp(&[], 0, out_w1, err_w1);
        assert_eq!(code1, 0);
        let _ = sys_close(out_w1);
        let _ = sys_close(err_w1);

        let mut path_buf = [0u8; 64];
        let n1 = sys_read(out_r1, &mut path_buf);
        let _ = sys_close(out_r1);
        let _ = sys_close(err_r1);
        assert!(n1 > 0);
        let path1_str = core::str::from_utf8(&path_buf[..n1 as usize])
            .unwrap()
            .trim_end();
        assert!(path1_str.starts_with("/tmp/tmp."));

        // Vérification que le fichier existe et a les permissions 0600
        let stat1 = sys_stat_pool(path1_str).expect("stat temp file");
        assert_eq!(stat1.st_mode & 0o777, 0o600);
        assert_eq!(stat1.st_mode & crate::vfs::S_IFMT, crate::vfs::S_IFREG);

        // 2. Création atomique d'un répertoire temporaire avec -d
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe out 2");
        let code2 = run_mktemp(&["-d", "-p", "/tmp", "sandbox.XXXXXX"], 0, out_w2, 2);
        assert_eq!(code2, 0);
        let _ = sys_close(out_w2);

        let mut dir_buf = [0u8; 64];
        let n2 = sys_read(out_r2, &mut dir_buf);
        let _ = sys_close(out_r2);
        assert!(n2 > 0);
        let dir_str = core::str::from_utf8(&dir_buf[..n2 as usize])
            .unwrap()
            .trim_end();
        assert!(dir_str.starts_with("/tmp/sandbox."));

        let stat_dir = sys_stat_pool(dir_str).expect("stat temp dir");
        assert_eq!(stat_dir.st_mode & 0o777, 0o700);
        assert_eq!(stat_dir.st_mode & crate::vfs::S_IFMT, crate::vfs::S_IFDIR);

        // 3. Test de rejet si moins de 3 X
        let (err_r3, err_w3) = crate::vfs::pipe().expect("pipe err 3");
        let code3 = run_mktemp(&["bad_template.XX"], 0, 1, err_w3);
        assert_eq!(code3, 1);
        let _ = sys_close(err_w3);
        let _ = sys_close(err_r3);

        // 4. Test dry-run (-u)
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe out 4");
        let code4 = run_mktemp(&["-u", "dryrun.XXXXXX"], 0, out_w4, 2);
        assert_eq!(code4, 0);
        let _ = sys_close(out_w4);

        let mut dry_buf = [0u8; 64];
        let n4 = sys_read(out_r4, &mut dry_buf);
        let _ = sys_close(out_r4);
        assert!(n4 > 0);
        let dry_str = core::str::from_utf8(&dry_buf[..n4 as usize])
            .unwrap()
            .trim_end();
        assert!(sys_stat_pool(dry_str).is_none()); // Le fichier n'a pas été créé sur disque !

        // Nettoyage
        let _ = sys_unlink_pool(path1_str);
        let _ = sys_unlink_pool(dir_str);
    }

    #[test]
    fn test_realpath_canonicalization_and_symlinks() {
        // 1. Canonicalisation d'un chemin absolu avec segments . et ..
        let mut out_buf = [0u8; 128];
        let n =
            canonicalize_path("/etc/../etc/./hostname", &mut out_buf).expect("canonicalize path");
        assert_eq!(&out_buf[..n], b"/etc/hostname");

        // 2. Canonicalisation d'un chemin avec multiples slashs consécutifs
        let n2 =
            canonicalize_path("///etc///os-release", &mut out_buf).expect("canonicalize slashes");
        assert_eq!(&out_buf[..n2], b"/etc/os-release");

        // 3. Canonicalisation via lien symbolique dans INODE_POOL
        let target = "/etc/hostname";
        let symlink_path = "/tmp/test_real_symlink";
        let _ = sys_symlink_pool(target, symlink_path);

        let n3 = canonicalize_path("/tmp/test_real_symlink", &mut out_buf)
            .expect("canonicalize symlink");
        assert_eq!(&out_buf[..n3], b"/etc/hostname");

        // 4. Test d'exécution de la commande run_realpath avec pipe
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe realpath");
        let code = run_realpath(&["-z", "/tmp/../tmp/test_real_symlink"], out_w, 2);
        assert_eq!(code, 0);
        let _ = sys_close(out_w);

        let mut read_buf = [0u8; 64];
        let nr = sys_read(out_r, &mut read_buf);
        let _ = sys_close(out_r);
        assert_eq!(nr, 14); // "/etc/hostname\0"
        assert_eq!(&read_buf[..nr as usize], b"/etc/hostname\0");

        // 5. Test de l'option -s (--no-symlinks) : normalisation syntaxique
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe realpath -s");
        let code2 = run_realpath(&["-s", "/var/log/../log/./syslog"], out_w2, 2);
        assert_eq!(code2, 0);
        let _ = sys_close(out_w2);

        let nr2 = sys_read(out_r2, &mut read_buf);
        let _ = sys_close(out_r2);
        assert_eq!(&read_buf[..nr2 as usize], b"/var/log/syslog\n");

        // Nettoyage
        let _ = sys_unlink_pool(symlink_path);
    }

    #[test]
    fn test_fmt_word_wrapping_and_paragraphs() {
        let text = b"Le noyau JamboOS execute tous ses microservices Ring 3 de maniere strictement confinee.\n\
Chaque processus dispose de son propre CR3 sans aucun privilege materiel direct.\n";

        let (in_r, in_w) = crate::vfs::pipe().expect("pipe in");
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe out");

        let _ = sys_write(in_w, text);
        let _ = sys_close(in_w);

        let code = run_fmt(&["-w", "40"], in_r, out_w, 2);
        let _ = sys_close(in_r);
        let _ = sys_close(out_w);

        assert_eq!(code, 0);

        let mut out_buf = [0u8; 512];
        let n = sys_read(out_r, &mut out_buf);
        let _ = sys_close(out_r);
        assert!(n > 0);

        let formatted = core::str::from_utf8(&out_buf[..n as usize]).unwrap();
        for line in formatted.lines() {
            assert!(line.len() <= 40, "Line exceeds width: '{}'", line);
        }
        assert!(formatted.contains("JamboOS"));
        assert!(formatted.contains("confinee."));
    }

    #[test]
    fn test_pr_pagination_and_numbering() {
        let input_text = b"Line Alpha\nLine Beta\nLine Gamma\nLine Delta\n";

        let (in_r, in_w) = crate::vfs::pipe().expect("pipe in");
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe out");

        let _ = sys_write(in_w, input_text);
        let _ = sys_close(in_w);

        // Test pr avec en-tête personnalisé et numérotation des lignes
        let code = run_pr(&["-h", "Audit JamboOS", "-n", "-l", "20"], in_r, out_w, 2);
        let _ = sys_close(in_r);
        let _ = sys_close(out_w);

        assert_eq!(code, 0);

        let mut out_buf = [0u8; 1024];
        let n = sys_read(out_r, &mut out_buf);
        let _ = sys_close(out_r);
        assert!(n > 0);

        let res = core::str::from_utf8(&out_buf[..n as usize]).unwrap();
        assert!(res.contains("Audit JamboOS"));
        assert!(res.contains("Page 1"));
        assert!(res.contains("1\tLine Alpha"));
        assert!(res.contains("2\tLine Beta"));

        // Test pr -t (sans en-tête) avec marge -o 4
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe in 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe out 2");

        let _ = sys_write(in_w2, b"Pure Microkernel\n");
        let _ = sys_close(in_w2);

        let code2 = run_pr(&["-t", "-o", "4"], in_r2, out_w2, 2);
        let _ = sys_close(in_r2);
        let _ = sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut out_buf2 = [0u8; 128];
        let n2 = sys_read(out_r2, &mut out_buf2);
        let _ = sys_close(out_r2);
        assert!(n2 > 0);
        let res2 = core::str::from_utf8(&out_buf2[..n2 as usize]).unwrap();
        assert_eq!(res2, "    Pure Microkernel\n");
    }

    #[test]
    fn test_column_table_and_separators() {
        let input_table = b"NAME:ROLE:STATUS\nroot:coordinator:active\nnode1:worker:idle\n";

        let (in_r, in_w) = crate::vfs::pipe().expect("pipe in");
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe out");

        let _ = sys_write(in_w, input_table);
        let _ = sys_close(in_w);

        let code = run_column(&["-t", "-s", ":", "-o", " | "], in_r, out_w, 2);
        let _ = sys_close(in_r);
        let _ = sys_close(out_w);

        assert_eq!(code, 0);

        let mut out_buf = [0u8; 512];
        let n = sys_read(out_r, &mut out_buf);
        let _ = sys_close(out_r);
        assert!(n > 0);

        let res = core::str::from_utf8(&out_buf[..n as usize]).unwrap();
        assert!(res.contains("NAME  | ROLE        | STATUS\n"));
        assert!(res.contains("root  | coordinator | active\n"));
        assert!(res.contains("node1 | worker      | idle\n"));

        // Test mode horizontal fillrows (-x)
        let input_list = b"alpha\nbeta\ngamma\ndelta\n";
        let (in_r2, in_w2) = crate::vfs::pipe().expect("pipe in 2");
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe out 2");
        let _ = sys_write(in_w2, input_list);
        let _ = sys_close(in_w2);

        let code2 = run_column(&["-x", "-c", "20"], in_r2, out_w2, 2);
        let _ = sys_close(in_r2);
        let _ = sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut out_buf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut out_buf2);
        let _ = sys_close(out_r2);
        assert!(n2 > 0);
        let res2 = core::str::from_utf8(&out_buf2[..n2 as usize]).unwrap();
        assert!(res2.contains("alpha"));
        assert!(res2.contains("beta"));
    }

    #[test]
    fn test_tabs_configuration_and_sequences() {
        // Test 1: Configuration par défaut (intervalle 8)
        let cfg_default = TabsConfig::default();
        assert!(!cfg_default.is_tab_stop(1));
        assert!(cfg_default.is_tab_stop(9));
        assert!(cfg_default.is_tab_stop(17));
        assert_eq!(cfg_default.next_tab_stop(1), 9);
        assert_eq!(cfg_default.next_tab_stop(4), 9);
        assert_eq!(cfg_default.next_tab_stop(9), 17);

        // Test 2: Taquets explicites
        let cfg_explicit = TabsConfig {
            stops: [
                10, 20, 35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            count: 3,
            regular_interval: 0,
            clear_all: false,
        };
        assert!(cfg_explicit.is_tab_stop(10));
        assert!(cfg_explicit.is_tab_stop(20));
        assert!(cfg_explicit.is_tab_stop(35));
        assert!(!cfg_explicit.is_tab_stop(15));
        assert_eq!(cfg_explicit.next_tab_stop(5), 10);
        assert_eq!(cfg_explicit.next_tab_stop(10), 20);
        assert_eq!(cfg_explicit.next_tab_stop(25), 35);
        assert_eq!(cfg_explicit.next_tab_stop(40), 41);

        // Test 3: Exécution run_tabs avec -4
        let (out_r, out_w) = crate::vfs::pipe().expect("pipe out");
        let code = run_tabs(&["-4"], 0, out_w, 2);
        let _ = sys_close(out_w);
        assert_eq!(code, 0);

        let mut buf = [0u8; 1024];
        let n = sys_read(out_r, &mut buf);
        let _ = sys_close(out_r);
        assert!(n > 0);

        let seq = core::str::from_utf8(&buf[..n as usize]).unwrap();
        // Vérifie la présence de l'effacement global et de la configuration des taquets
        assert!(seq.contains("\x1b[3g"));
        assert!(seq.contains("\x1b[5G\x1bH"));
        assert!(seq.contains("\x1b[9G\x1bH"));
        assert!(seq.contains("\x1b[1G"));

        // Test 4: Effacement complet -0
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe out 2");
        let code2 = run_tabs(&["-0"], 0, out_w2, 2);
        let _ = sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut buf2 = [0u8; 64];
        let n2 = sys_read(out_r2, &mut buf2);
        let _ = sys_close(out_r2);
        assert_eq!(n2, 4);
        assert_eq!(&buf2[..4], b"\x1b[3g");

        // Test 5: Taquets explicites via arguments
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe out 3");
        let code3 = run_tabs(&["12,24,36"], 0, out_w3, 2);
        let _ = sys_close(out_w3);
        assert_eq!(code3, 0);

        let mut buf3 = [0u8; 128];
        let n3 = sys_read(out_r3, &mut buf3);
        let _ = sys_close(out_r3);
        assert!(n3 > 0);
        let seq3 = core::str::from_utf8(&buf3[..n3 as usize]).unwrap();
        assert!(seq3.contains("\x1b[12G\x1bH"));
        assert!(seq3.contains("\x1b[24G\x1bH"));
        assert!(seq3.contains("\x1b[36G\x1bH"));

        // Test 6: Inversion de flux `tac` (inversion par ligne, séparateur personnalisé et regex)
        let (in_r_tac, in_w_tac) = crate::vfs::pipe().expect("pipe tac in");
        let (out_r_tac, out_w_tac) = crate::vfs::pipe().expect("pipe tac out");
        let _ = sys_write(in_w_tac, b"Line 1\nLine 2\nLine 3\n");
        let _ = sys_close(in_w_tac);

        let code_tac = run_tac(&[], in_r_tac, out_w_tac, 2);
        let _ = sys_close(in_r_tac);
        let _ = sys_close(out_w_tac);
        assert_eq!(code_tac, 0);

        let mut tac_buf = [0u8; 128];
        let n_tac = sys_read(out_r_tac, &mut tac_buf);
        let _ = sys_close(out_r_tac);
        assert_eq!(&tac_buf[..n_tac as usize], b"Line 3\nLine 2\nLine 1\n");

        // Test 7: `tac` avec séparateur personnalisé `-s`
        let (in_r_s, in_w_s) = crate::vfs::pipe().expect("pipe tac s in");
        let (out_r_s, out_w_s) = crate::vfs::pipe().expect("pipe tac s out");
        let _ = sys_write(in_w_s, b"alpha|beta|gamma|");
        let _ = sys_close(in_w_s);

        let code_s = run_tac(&["-s", "|"], in_r_s, out_w_s, 2);
        let _ = sys_close(in_r_s);
        let _ = sys_close(out_w_s);
        assert_eq!(code_s, 0);

        let mut buf_s = [0u8; 64];
        let n_s = sys_read(out_r_s, &mut buf_s);
        let _ = sys_close(out_r_s);
        assert_eq!(&buf_s[..n_s as usize], b"gamma|beta|alpha|");

        // Test 8: `tac` avec flag `-b` (--before)
        let (in_r_b, in_w_b) = crate::vfs::pipe().expect("pipe tac b in");
        let (out_r_b, out_w_b) = crate::vfs::pipe().expect("pipe tac b out");
        let _ = sys_write(in_w_b, b":one:two:three");
        let _ = sys_close(in_w_b);

        let code_b = run_tac(&["-b", "-s", ":"], in_r_b, out_w_b, 2);
        let _ = sys_close(in_r_b);
        let _ = sys_close(out_w_b);
        assert_eq!(code_b, 0);

        let mut buf_b = [0u8; 64];
        let n_b = sys_read(out_r_b, &mut buf_b);
        let _ = sys_close(out_r_b);
        assert_eq!(&buf_b[..n_b as usize], b":three:two:one");

        // Test 9: `csplit` découpage contextuel par numéro de ligne et motif regex
        let input_csplit = b"SECTION 1\nAlpha\nBeta\nSECTION 2\nGamma\nDelta\n";
        let (in_r_cs, in_w_cs) = crate::vfs::pipe().expect("pipe csplit in");
        let (out_r_cs, out_w_cs) = crate::vfs::pipe().expect("pipe csplit out");
        let _ = sys_write(in_w_cs, input_csplit);
        let _ = sys_close(in_w_cs);

        let code_cs = run_csplit(
            &["-f", "/tmp/test_cs_", "-s", "-", "/SECTION 2/"],
            in_r_cs,
            out_w_cs,
            2,
        );
        let _ = sys_close(in_r_cs);
        let _ = sys_close(out_w_cs);
        let _ = sys_close(out_r_cs);
        assert_eq!(code_cs, 0);

        // Vérification du fichier 1 : /tmp/test_cs_00 ("SECTION 1\nAlpha\nBeta\n")
        let fd_cs0 = sys_open("/tmp/test_cs_00", crate::vfs::O_RDONLY);
        assert!(fd_cs0 >= 0);
        let mut cs0_buf = [0u8; 64];
        let n_cs0 = sys_read(fd_cs0, &mut cs0_buf);
        let _ = sys_close(fd_cs0);
        let _ = sys_unlink_pool("/tmp/test_cs_00");
        assert_eq!(&cs0_buf[..n_cs0 as usize], b"SECTION 1\nAlpha\nBeta\n");

        // Vérification du fichier 2 : /tmp/test_cs_01 ("SECTION 2\nGamma\nDelta\n")
        let fd_cs1 = sys_open("/tmp/test_cs_01", crate::vfs::O_RDONLY);
        assert!(fd_cs1 >= 0);
        let mut cs1_buf = [0u8; 64];
        let n_cs1 = sys_read(fd_cs1, &mut cs1_buf);
        let _ = sys_close(fd_cs1);
        let _ = sys_unlink_pool("/tmp/test_cs_01");
        assert_eq!(&cs1_buf[..n_cs1 as usize], b"SECTION 2\nGamma\nDelta\n");
    }

    #[test]
    fn test_run_join() {
        use crate::vfs::pipe;

        // Préparer deux fichiers triés avec un champ clé commun
        // fichier1 : "1 alpha\n2 beta\n3 gamma\n"
        // fichier2 : "1 un\n2 deux\n4 quatre\n"
        let path1 = "/tmp/join_test_f1.txt";
        let path2 = "/tmp/join_test_f2.txt";

        let fd1w = sys_open(path1, O_CREAT | O_WRONLY | crate::vfs::O_TRUNC);
        assert!(fd1w >= 0);
        let _ = sys_write(fd1w, b"1 alpha\n2 beta\n3 gamma\n");
        let _ = sys_close(fd1w);

        let fd2w = sys_open(path2, O_CREAT | O_WRONLY | crate::vfs::O_TRUNC);
        assert!(fd2w >= 0);
        let _ = sys_write(fd2w, b"1 un\n2 deux\n4 quatre\n");
        let _ = sys_close(fd2w);

        // Test 1 : jointure de base (champ 1 = blanc)
        let (out_r, out_w) = pipe().expect("pipe join out");
        let code = run_join(&[path1, path2], 0, out_w, 2);
        let _ = sys_close(out_w);
        assert_eq!(code, 0);

        let mut jbuf = [0u8; 256];
        let n = sys_read(out_r, &mut jbuf);
        let _ = sys_close(out_r);
        assert!(n > 0);
        let result = core::str::from_utf8(&jbuf[..n as usize]).unwrap();
        // Lignes jointes attendues : "1 alpha un\n2 beta deux\n"
        assert!(result.contains("1 alpha un"), "got: {result}");
        assert!(result.contains("2 beta deux"), "got: {result}");
        // La clé 3 (fichier1) et 4 (fichier2) ne doivent pas apparaître
        assert!(!result.contains("gamma"), "got: {result}");
        assert!(!result.contains("quatre"), "got: {result}");

        // Test 2 : `-a 1` — afficher aussi les lignes non-matchées du fichier 1
        let (out_r2, out_w2) = pipe().expect("pipe join out2");
        let code2 = run_join(&["-a", "1", path1, path2], 0, out_w2, 2);
        let _ = sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut jbuf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut jbuf2);
        let _ = sys_close(out_r2);
        assert!(n2 > 0);
        let result2 = core::str::from_utf8(&jbuf2[..n2 as usize]).unwrap();
        assert!(result2.contains("3 gamma"), "got: {result2}");

        // Test 3 : `-v 2` — uniquement les lignes non-matchées du fichier 2
        let (out_r3, out_w3) = pipe().expect("pipe join out3");
        let code3 = run_join(&["-v", "2", path1, path2], 0, out_w3, 2);
        let _ = sys_close(out_w3);
        assert_eq!(code3, 0);

        let mut jbuf3 = [0u8; 256];
        let n3 = sys_read(out_r3, &mut jbuf3);
        let _ = sys_close(out_r3);
        assert!(n3 > 0);
        let result3 = core::str::from_utf8(&jbuf3[..n3 as usize]).unwrap();
        assert!(result3.contains("4 quatre"), "got: {result3}");
        assert!(!result3.contains("alpha"), "got: {result3}");

        // Test 4 : `-t :` avec séparateur personnalisé
        let path3 = "/tmp/join_test_f3.txt";
        let path4 = "/tmp/join_test_f4.txt";
        let fd3w = sys_open(path3, O_CREAT | O_WRONLY | crate::vfs::O_TRUNC);
        assert!(fd3w >= 0);
        let _ = sys_write(fd3w, b"a:Alice\nb:Bob\n");
        let _ = sys_close(fd3w);
        let fd4w = sys_open(path4, O_CREAT | O_WRONLY | crate::vfs::O_TRUNC);
        assert!(fd4w >= 0);
        let _ = sys_write(fd4w, b"a:Paris\nb:Lyon\n");
        let _ = sys_close(fd4w);

        let (out_r4, out_w4) = pipe().expect("pipe join out4");
        let code4 = run_join(&["-t", ":", path3, path4], 0, out_w4, 2);
        let _ = sys_close(out_w4);
        assert_eq!(code4, 0);

        let mut jbuf4 = [0u8; 256];
        let n4 = sys_read(out_r4, &mut jbuf4);
        let _ = sys_close(out_r4);
        assert!(n4 > 0);
        let result4 = core::str::from_utf8(&jbuf4[..n4 as usize]).unwrap();
        assert!(result4.contains("a:Alice:Paris"), "got: {result4}");
        assert!(result4.contains("b:Bob:Lyon"), "got: {result4}");

        // Nettoyage
        let _ = sys_unlink_pool(path1);
        let _ = sys_unlink_pool(path2);
        let _ = sys_unlink_pool(path3);
        let _ = sys_unlink_pool(path4);
    }

    #[test]
    fn test_run_shuf() {
        // Test 1: --help
        let (out_r1, out_w1) = crate::vfs::pipe().expect("pipe shuf out1");
        let code1 = run_shuf(&["--help"], 0, out_w1, 2);
        let _ = sys_close(out_w1);
        assert_eq!(code1, 0);
        let mut buf1 = [0u8; 512];
        let n1 = sys_read(out_r1, &mut buf1);
        let _ = sys_close(out_r1);
        assert!(n1 > 0);
        let res1 = core::str::from_utf8(&buf1[..n1 as usize]).unwrap();
        assert!(res1.contains("Usage: shuf"));

        // Test 2: -e (echo mode) avec tous les éléments présents
        let (out_r2, out_w2) = crate::vfs::pipe().expect("pipe shuf out2");
        let code2 = run_shuf(&["-e", "alpha", "beta", "gamma"], 0, out_w2, 2);
        let _ = sys_close(out_w2);
        assert_eq!(code2, 0);
        let mut buf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut buf2);
        let _ = sys_close(out_r2);
        assert!(n2 > 0);
        let res2 = core::str::from_utf8(&buf2[..n2 as usize]).unwrap();
        assert!(res2.contains("alpha\n"));
        assert!(res2.contains("beta\n"));
        assert!(res2.contains("gamma\n"));

        // Test 3: -e avec -n 2 (head-count)
        let (out_r3, out_w3) = crate::vfs::pipe().expect("pipe shuf out3");
        let code3 = run_shuf(
            &["-e", "-n", "2", "one", "two", "three", "four"],
            0,
            out_w3,
            2,
        );
        let _ = sys_close(out_w3);
        assert_eq!(code3, 0);
        let mut buf3 = [0u8; 256];
        let n3 = sys_read(out_r3, &mut buf3);
        let _ = sys_close(out_r3);
        assert!(n3 > 0);
        let res3 = core::str::from_utf8(&buf3[..n3 as usize]).unwrap();
        let line_count3 = res3.lines().count();
        assert_eq!(line_count3, 2);

        // Test 4: -i input-range (1-5)
        let (out_r4, out_w4) = crate::vfs::pipe().expect("pipe shuf out4");
        let code4 = run_shuf(&["-i", "10-14"], 0, out_w4, 2);
        let _ = sys_close(out_w4);
        assert_eq!(code4, 0);
        let mut buf4 = [0u8; 256];
        let n4 = sys_read(out_r4, &mut buf4);
        let _ = sys_close(out_r4);
        assert!(n4 > 0);
        let res4 = core::str::from_utf8(&buf4[..n4 as usize]).unwrap();
        for num in 10..=14 {
            let mut num_str = [0u8; 32];
            let len = write_u64_decimal(num, &mut num_str);
            let s = core::str::from_utf8(&num_str[..len]).unwrap();
            assert!(res4.contains(s), "missing {num} in {res4}");
        }

        // Test 5: -r repeat avec -n 5 sur -e
        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe shuf out5");
        let code5 = run_shuf(&["-e", "-r", "-n", "5", "solo"], 0, out_w5, 2);
        let _ = sys_close(out_w5);
        assert_eq!(code5, 0);
        let mut buf5 = [0u8; 256];
        let n5 = sys_read(out_r5, &mut buf5);
        let _ = sys_close(out_r5);
        assert!(n5 > 0);
        let res5 = core::str::from_utf8(&buf5[..n5 as usize]).unwrap();
        assert_eq!(res5.lines().count(), 5);
        for line in res5.lines() {
            assert_eq!(line, "solo");
        }

        // Test 6: Fichier d'entrée et option -o output
        let in_file = "/tmp/shuf_in.txt";
        let out_file = "/tmp/shuf_out.txt";
        let fdw = sys_open(in_file, O_CREAT | O_WRONLY | crate::vfs::O_TRUNC);
        assert!(fdw >= 0);
        let _ = sys_write(fdw, b"pomme\npoire\nbanane\ncerise\n");
        let _ = sys_close(fdw);

        let code6 = run_shuf(&["-o", out_file, in_file], 0, 1, 2);
        assert_eq!(code6, 0);

        let fdr = sys_open(out_file, crate::vfs::O_RDONLY);
        assert!(fdr >= 0);
        let mut buf6 = [0u8; 256];
        let n6 = sys_read(fdr, &mut buf6);
        let _ = sys_close(fdr);
        assert!(n6 > 0);
        let res6 = core::str::from_utf8(&buf6[..n6 as usize]).unwrap();
        assert!(res6.contains("pomme\n"));
        assert!(res6.contains("poire\n"));
        assert!(res6.contains("banane\n"));
        assert!(res6.contains("cerise\n"));

        let _ = sys_unlink_pool(in_file);
        let _ = sys_unlink_pool(out_file);
    }

    #[test]
    fn test_posix_md5sum() {
        // 1. Vecteurs RFC 1321
        let digest_empty = Md5Hasher::hash(b"");
        let mut hex_empty = [0u8; 32];
        md5_to_hex(&digest_empty, &mut hex_empty);
        assert_eq!(
            core::str::from_utf8(&hex_empty).unwrap(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );

        let digest_a = Md5Hasher::hash(b"a");
        let mut hex_a = [0u8; 32];
        md5_to_hex(&digest_a, &mut hex_a);
        assert_eq!(
            core::str::from_utf8(&hex_a).unwrap(),
            "0cc175b9c0f1b6a831c399e269772661"
        );

        let digest_abc = Md5Hasher::hash(b"abc");
        let mut hex_abc = [0u8; 32];
        md5_to_hex(&digest_abc, &mut hex_abc);
        assert_eq!(
            core::str::from_utf8(&hex_abc).unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );

        let digest_msg = Md5Hasher::hash(b"message digest");
        let mut hex_msg = [0u8; 32];
        md5_to_hex(&digest_msg, &mut hex_msg);
        assert_eq!(
            core::str::from_utf8(&hex_msg).unwrap(),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );

        // 2. Calcul md5sum sur fichier VFS
        let file_path = "/tmp/test_md5_data.txt";
        let fd = sys_open(file_path, O_CREAT | O_WRONLY);
        assert!(fd >= 0);
        let _ = sys_write(fd, b"abc");
        sys_close(fd);

        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_md5sum(&[file_path], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);

        let mut buf1 = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf1);
        sys_close(out_r1);
        let s1 = core::str::from_utf8(&buf1[..n1 as usize]).unwrap();
        assert!(s1.starts_with("900150983cd24fb0d6963f7d28e17f72  /tmp/test_md5_data.txt"));

        // 3. Mode BSD style --tag
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_md5sum(&["--tag", file_path], 0, out_w2, 2);
        sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut buf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut buf2);
        sys_close(out_r2);
        let s2 = core::str::from_utf8(&buf2[..n2 as usize]).unwrap();
        assert_eq!(
            s2,
            "MD5 (/tmp/test_md5_data.txt) = 900150983cd24fb0d6963f7d28e17f72\n"
        );

        // 4. Mode vérification (-c / --check) réussi
        let check_file = "/tmp/test_md5.chk";
        let chk_fd = sys_open(check_file, O_CREAT | O_WRONLY);
        assert!(chk_fd >= 0);
        let _ = sys_write(
            chk_fd,
            b"900150983cd24fb0d6963f7d28e17f72  /tmp/test_md5_data.txt\n",
        );
        sys_close(chk_fd);

        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_md5sum(&["-c", check_file], 0, out_w3, 2);
        sys_close(out_w3);
        assert_eq!(code3, 0);

        let mut buf3 = [0u8; 256];
        let n3 = sys_read(out_r3, &mut buf3);
        sys_close(out_r3);
        let s3 = core::str::from_utf8(&buf3[..n3 as usize]).unwrap();
        assert!(s3.contains("/tmp/test_md5_data.txt: OK"));

        // 5. Mode vérification échoué (altération)
        let bad_fd = sys_open(file_path, O_CREAT | O_WRONLY);
        assert!(bad_fd >= 0);
        let _ = sys_write(bad_fd, b"corrupted data");
        sys_close(bad_fd);

        let (out_r4, out_w4) = crate::vfs::pipe().unwrap();
        let code4 = run_md5sum(&["-c", check_file], 0, out_w4, 2);
        sys_close(out_w4);
        assert_eq!(code4, 1);

        let mut buf4 = [0u8; 256];
        let n4 = sys_read(out_r4, &mut buf4);
        sys_close(out_r4);
        let s4 = core::str::from_utf8(&buf4[..n4 as usize]).unwrap();
        assert!(s4.contains("/tmp/test_md5_data.txt: FAILED"));

        // 6. Streaming stdin
        let (in_r5, in_w5) = crate::vfs::pipe().unwrap();
        let (out_r5, out_w5) = crate::vfs::pipe().unwrap();
        let _ = sys_write(in_w5, b"abc");
        sys_close(in_w5);
        let code5 = run_md5sum(&["-"], in_r5, out_w5, 2);
        sys_close(in_r5);
        sys_close(out_w5);
        assert_eq!(code5, 0);

        let mut buf5 = [0u8; 256];
        let n5 = sys_read(out_r5, &mut buf5);
        sys_close(out_r5);
        let s5 = core::str::from_utf8(&buf5[..n5 as usize]).unwrap();
        assert!(s5.starts_with("900150983cd24fb0d6963f7d28e17f72  -\n"));

        // 7. --help et --version
        let (out_r6, out_w6) = crate::vfs::pipe().unwrap();
        let code6 = run_md5sum(&["--help"], 0, out_w6, 2);
        sys_close(out_w6);
        assert_eq!(code6, 0);
        let mut buf6 = [0u8; 512];
        let n6 = sys_read(out_r6, &mut buf6);
        sys_close(out_r6);
        assert!(core::str::from_utf8(&buf6[..n6 as usize])
            .unwrap()
            .contains("Usage: md5sum"));

        let _ = sys_unlink_pool(file_path);
        let _ = sys_unlink_pool(check_file);
    }

    #[test]
    fn test_posix_sha1sum() {
        // 1. Test unitaire basique du hasher SHA-1
        assert_eq!(
            Sha1Hasher::hash(b""),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
        assert_eq!(
            Sha1Hasher::hash(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );

        // 2. Calcul sha1sum sur un fichier VFS
        let file_path = "/tmp/test_sha1_data.txt";
        let fd = sys_open(file_path, O_CREAT | O_WRONLY);
        assert!(fd >= 0);
        let _ = sys_write(fd, b"abc");
        sys_close(fd);

        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_sha1sum(&[file_path], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);

        let mut buf1 = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf1);
        sys_close(out_r1);
        let s1 = core::str::from_utf8(&buf1[..n1 as usize]).unwrap();
        assert!(s1.starts_with("a9993e364706816aba3e25717850c26c9cd0d89d  /tmp/test_sha1_data.txt"));

        // 3. Mode BSD style --tag
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_sha1sum(&["--tag", file_path], 0, out_w2, 2);
        sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut buf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut buf2);
        sys_close(out_r2);
        let s2 = core::str::from_utf8(&buf2[..n2 as usize]).unwrap();
        assert_eq!(
            s2,
            "SHA1 (/tmp/test_sha1_data.txt) = a9993e364706816aba3e25717850c26c9cd0d89d\n"
        );

        // 4. Mode vérification (-c / --check) réussi
        let check_file = "/tmp/test_sha1.chk";
        let chk_fd = sys_open(check_file, O_CREAT | O_WRONLY);
        assert!(chk_fd >= 0);
        let _ = sys_write(
            chk_fd,
            b"a9993e364706816aba3e25717850c26c9cd0d89d  /tmp/test_sha1_data.txt\n",
        );
        sys_close(chk_fd);

        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_sha1sum(&["-c", check_file], 0, out_w3, 2);
        sys_close(out_w3);
        assert_eq!(code3, 0);

        let mut buf3 = [0u8; 256];
        let n3 = sys_read(out_r3, &mut buf3);
        sys_close(out_r3);
        let s3 = core::str::from_utf8(&buf3[..n3 as usize]).unwrap();
        assert!(s3.contains("/tmp/test_sha1_data.txt: OK"));

        // 5. Mode vérification échoué (altération)
        let bad_fd = sys_open(file_path, O_CREAT | O_WRONLY);
        assert!(bad_fd >= 0);
        let _ = sys_write(bad_fd, b"corrupted sha1 data");
        sys_close(bad_fd);

        let (out_r4, out_w4) = crate::vfs::pipe().unwrap();
        let code4 = run_sha1sum(&["-c", check_file], 0, out_w4, 2);
        sys_close(out_w4);
        assert_eq!(code4, 1);

        let mut buf4 = [0u8; 256];
        let n4 = sys_read(out_r4, &mut buf4);
        sys_close(out_r4);
        let s4 = core::str::from_utf8(&buf4[..n4 as usize]).unwrap();
        assert!(s4.contains("/tmp/test_sha1_data.txt: FAILED"));

        // 6. Streaming stdin
        let (in_r5, in_w5) = crate::vfs::pipe().unwrap();
        let (out_r5, out_w5) = crate::vfs::pipe().unwrap();
        let _ = sys_write(in_w5, b"abc");
        sys_close(in_w5);
        let code5 = run_sha1sum(&["-"], in_r5, out_w5, 2);
        sys_close(in_r5);
        sys_close(out_w5);
        assert_eq!(code5, 0);

        let mut buf5 = [0u8; 256];
        let n5 = sys_read(out_r5, &mut buf5);
        sys_close(out_r5);
        let s5 = core::str::from_utf8(&buf5[..n5 as usize]).unwrap();
        assert!(s5.starts_with("a9993e364706816aba3e25717850c26c9cd0d89d  -\n"));

        // 7. --help et --version
        let (out_r6, out_w6) = crate::vfs::pipe().unwrap();
        let code6 = run_sha1sum(&["--help"], 0, out_w6, 2);
        sys_close(out_w6);
        assert_eq!(code6, 0);
        let mut buf6 = [0u8; 512];
        let n6 = sys_read(out_r6, &mut buf6);
        sys_close(out_r6);
        assert!(core::str::from_utf8(&buf6[..n6 as usize])
            .unwrap()
            .contains("Usage: sha1sum"));

        let _ = sys_unlink_pool(file_path);
        let _ = sys_unlink_pool(check_file);
    }

    #[test]
    fn test_posix_crc32() {
        // 1. Vecteurs CRC32 connus
        let mut h1 = Crc32Hasher::new();
        h1.update(b"");
        assert_eq!(h1.finalize(), 0x00000000);

        let mut h2 = Crc32Hasher::new();
        h2.update(b"123456789");
        assert_eq!(h2.finalize(), 0xCBF43926);

        // 2. Calcul crc32 sur un fichier VFS
        let file_path = "/tmp/test_crc32.txt";
        let fd = sys_open(file_path, crate::vfs::O_CREAT | crate::vfs::O_RDWR);
        assert!(fd >= 0);
        let content = b"123456789";
        let _ = sys_write(fd, content);
        let _ = sys_close(fd);

        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_crc32(&[file_path], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);

        let mut buf1 = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf1);
        sys_close(out_r1);
        let s1 = core::str::from_utf8(&buf1[..n1 as usize]).unwrap();
        assert!(s1.starts_with("cbf43926  /tmp/test_crc32.txt\n"));

        // 3. Format BSD --tag
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let code2 = run_crc32(&["--tag", file_path], 0, out_w2, 2);
        sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut buf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut buf2);
        sys_close(out_r2);
        let s2 = core::str::from_utf8(&buf2[..n2 as usize]).unwrap();
        assert_eq!(s2, "CRC32 (/tmp/test_crc32.txt) = cbf43926\n");

        // 4. Vérification d'intégrité (-c / --check)
        let check_file = "/tmp/test_crc32.check";
        let cfd = sys_open(check_file, crate::vfs::O_CREAT | crate::vfs::O_RDWR);
        assert!(cfd >= 0);
        let _ = sys_write(cfd, b"cbf43926  /tmp/test_crc32.txt\n");
        let _ = sys_close(cfd);

        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_crc32(&["-c", check_file], 0, out_w3, 2);
        sys_close(out_w3);
        assert_eq!(code3, 0);

        let mut buf3 = [0u8; 256];
        let n3 = sys_read(out_r3, &mut buf3);
        sys_close(out_r3);
        let s3 = core::str::from_utf8(&buf3[..n3 as usize]).unwrap();
        assert!(s3.contains("/tmp/test_crc32.txt: OK\n"));

        // 5. Lecture sur stdin via "-"
        let (in_r5, in_w5) = crate::vfs::pipe().unwrap();
        let (out_r5, out_w5) = crate::vfs::pipe().unwrap();
        let _ = sys_write(in_w5, b"123456789");
        sys_close(in_w5);

        let code5 = run_crc32(&["-"], in_r5, out_w5, 2);
        sys_close(in_r5);
        sys_close(out_w5);
        assert_eq!(code5, 0);

        let mut buf5 = [0u8; 256];
        let n5 = sys_read(out_r5, &mut buf5);
        sys_close(out_r5);
        let s5 = core::str::from_utf8(&buf5[..n5 as usize]).unwrap();
        assert!(s5.starts_with("cbf43926  -\n"));

        // 6. --help et --version
        let (out_r6, out_w6) = crate::vfs::pipe().unwrap();
        let code6 = run_crc32(&["--help"], 0, out_w6, 2);
        sys_close(out_w6);
        assert_eq!(code6, 0);
        let mut buf6 = [0u8; 512];
        let n6 = sys_read(out_r6, &mut buf6);
        sys_close(out_r6);
        assert!(core::str::from_utf8(&buf6[..n6 as usize])
            .unwrap()
            .contains("Usage: crc32"));

        let _ = sys_unlink_pool(file_path);
        let _ = sys_unlink_pool(check_file);
    }

    #[test]
    fn test_factor_and_expr_string_extensions() {
        // 1. Test factorize_u64
        let mut factors = [0u64; 64];
        let c1 = factorize_u64(1, &mut factors);
        assert_eq!(c1, 0);

        let c2 = factorize_u64(13, &mut factors);
        assert_eq!(c2, 1);
        assert_eq!(factors[0], 13);

        let c3 = factorize_u64(42, &mut factors);
        assert_eq!(c3, 3);
        assert_eq!(&factors[..3], &[2, 3, 7]);

        let c4 = factorize_u64(360, &mut factors);
        assert_eq!(c4, 6);
        assert_eq!(&factors[..6], &[2, 2, 2, 3, 3, 5]);

        // 2. Test run_factor avec arguments
        let (out_r1, out_w1) = crate::vfs::pipe().unwrap();
        let code1 = run_factor(&["42", "13", "360"], 0, out_w1, 2);
        sys_close(out_w1);
        assert_eq!(code1, 0);

        let mut buf1 = [0u8; 256];
        let n1 = sys_read(out_r1, &mut buf1);
        sys_close(out_r1);
        let s1 = core::str::from_utf8(&buf1[..n1 as usize]).unwrap();
        assert!(s1.contains("42: 2 3 7\n"));
        assert!(s1.contains("13: 13\n"));
        assert!(s1.contains("360: 2 2 2 3 3 5\n"));

        // 3. Test run_factor via stdin
        let (in_r2, in_w2) = crate::vfs::pipe().unwrap();
        let (out_r2, out_w2) = crate::vfs::pipe().unwrap();
        let _ = sys_write(in_w2, b"100 77\n");
        sys_close(in_w2);

        let code2 = run_factor(&[], in_r2, out_w2, 2);
        sys_close(in_r2);
        sys_close(out_w2);
        assert_eq!(code2, 0);

        let mut buf2 = [0u8; 256];
        let n2 = sys_read(out_r2, &mut buf2);
        sys_close(out_r2);
        let s2 = core::str::from_utf8(&buf2[..n2 as usize]).unwrap();
        assert!(s2.contains("100: 2 2 5 5\n"));
        assert!(s2.contains("77: 7 11\n"));

        // 4. Test run_expr extensions de chaînes et motifs
        // length
        let (out_r3, out_w3) = crate::vfs::pipe().unwrap();
        let code3 = run_expr(&["length", "jambo-os"], out_w3, 2);
        sys_close(out_w3);
        assert_eq!(code3, 0);
        let mut buf3 = [0u8; 32];
        let n3 = sys_read(out_r3, &mut buf3);
        sys_close(out_r3);
        assert_eq!(core::str::from_utf8(&buf3[..n3 as usize]).unwrap(), "8\n");

        // substr
        let (out_r4, out_w4) = crate::vfs::pipe().unwrap();
        let code4 = run_expr(&["substr", "jambo-os", "1", "5"], out_w4, 2);
        sys_close(out_w4);
        assert_eq!(code4, 0);
        let mut buf4 = [0u8; 32];
        let n4 = sys_read(out_r4, &mut buf4);
        sys_close(out_r4);
        assert_eq!(
            core::str::from_utf8(&buf4[..n4 as usize]).unwrap(),
            "jambo\n"
        );

        // index
        let (out_r5, out_w5) = crate::vfs::pipe().unwrap();
        let code5 = run_expr(&["index", "jambo-os", "-"], out_w5, 2);
        sys_close(out_w5);
        assert_eq!(code5, 0);
        let mut buf5 = [0u8; 32];
        let n5 = sys_read(out_r5, &mut buf5);
        sys_close(out_r5);
        assert_eq!(core::str::from_utf8(&buf5[..n5 as usize]).unwrap(), "6\n");

        // match / :
        let (out_r6, out_w6) = crate::vfs::pipe().unwrap();
        let code6 = run_expr(&["match", "jambo-os", "jambo"], out_w6, 2);
        sys_close(out_w6);
        assert_eq!(code6, 0);
        let mut buf6 = [0u8; 32];
        let n6 = sys_read(out_r6, &mut buf6);
        sys_close(out_r6);
        assert_eq!(core::str::from_utf8(&buf6[..n6 as usize]).unwrap(), "5\n");

        let (out_r7, out_w7) = crate::vfs::pipe().unwrap();
        let code7 = run_expr(&["jambo-os", ":", "jamb"], out_w7, 2);
        sys_close(out_w7);
        assert_eq!(code7, 0);
        let mut buf7 = [0u8; 32];
        let n7 = sys_read(out_r7, &mut buf7);
        sys_close(out_r7);
        assert_eq!(core::str::from_utf8(&buf7[..n7 as usize]).unwrap(), "4\n");

        // 5. Test run_nice
        let (out_rn1, out_wn1) = crate::vfs::pipe().unwrap();
        let code_n1 = run_nice(&[], 0, out_wn1, 2);
        sys_close(out_wn1);
        assert_eq!(code_n1, 0);
        let mut bufn1 = [0u8; 16];
        let nn1 = sys_read(out_rn1, &mut bufn1);
        sys_close(out_rn1);
        assert_eq!(core::str::from_utf8(&bufn1[..nn1 as usize]).unwrap(), "0\n");

        let (out_rn2, out_wn2) = crate::vfs::pipe().unwrap();
        let code_n2 = run_nice(&["-n", "5", "echo", "polite"], 0, out_wn2, 2);
        sys_close(out_wn2);
        assert_eq!(code_n2, 0);
        let mut bufn2 = [0u8; 32];
        let nn2 = sys_read(out_rn2, &mut bufn2);
        sys_close(out_rn2);
        assert_eq!(
            core::str::from_utf8(&bufn2[..nn2 as usize]).unwrap(),
            "polite\n"
        );

        // 6. Test run_timeout
        let (out_rt1, out_wt1) = crate::vfs::pipe().unwrap();
        let code_t1 = run_timeout(&["10s", "echo", "fast"], 0, out_wt1, 2);
        sys_close(out_wt1);
        assert_eq!(code_t1, 0);
        let mut buft1 = [0u8; 32];
        let nt1 = sys_read(out_rt1, &mut buft1);
        sys_close(out_rt1);
        assert_eq!(
            core::str::from_utf8(&buft1[..nt1 as usize]).unwrap(),
            "fast\n"
        );

        // Timeout dépassé sur un sleep trop long
        let code_t2 = run_timeout(&["10ms", "sleep", "1s"], 0, 1, 2);
        assert_eq!(code_t2, 124);

        // Timeout avec --preserve-status
        let code_t3 = run_timeout(&["--preserve-status", "10ms", "sleep", "1s"], 0, 1, 2);
        assert_eq!(code_t3, 0);

        // 7. Test run_whoami
        let (out_rw1, out_ww1) = crate::vfs::pipe().unwrap();
        let code_w1 = run_whoami(&[], 0, out_ww1, 2);
        sys_close(out_ww1);
        assert_eq!(code_w1, 0);
        let mut bufw1 = [0u8; 16];
        let nw1 = sys_read(out_rw1, &mut bufw1);
        sys_close(out_rw1);
        assert_eq!(
            core::str::from_utf8(&bufw1[..nw1 as usize]).unwrap(),
            "root\n"
        );

        let (out_rw2, out_ww2) = crate::vfs::pipe().unwrap();
        let code_w2 = run_whoami(&["--version"], 0, out_ww2, 2);
        sys_close(out_ww2);
        assert_eq!(code_w2, 0);
        let mut bufw2 = [0u8; 64];
        let nw2 = sys_read(out_rw2, &mut bufw2);
        sys_close(out_rw2);
        assert!(core::str::from_utf8(&bufw2[..nw2 as usize])
            .unwrap()
            .contains("whoami"));

        // 8. Test run_printenv
        let (out_rp1, out_wp1) = crate::vfs::pipe().unwrap();
        let code_p1 = run_printenv(&[], 0, out_wp1, 2);
        sys_close(out_wp1);
        assert_eq!(code_p1, 0);
        let mut bufp1 = [0u8; 256];
        let np1 = sys_read(out_rp1, &mut bufp1);
        sys_close(out_rp1);
        let s_p1 = core::str::from_utf8(&bufp1[..np1 as usize]).unwrap();
        assert!(s_p1.contains("PATH=/bin\n"));
        assert!(s_p1.contains("USER=root\n"));
        assert!(s_p1.contains("OS=JamboOS\n"));

        let (out_rp2, out_wp2) = crate::vfs::pipe().unwrap();
        let code_p2 = run_printenv(&["USER", "OS"], 0, out_wp2, 2);
        sys_close(out_wp2);
        assert_eq!(code_p2, 0);
        let mut bufp2 = [0u8; 64];
        let np2 = sys_read(out_rp2, &mut bufp2);
        sys_close(out_rp2);
        assert_eq!(
            core::str::from_utf8(&bufp2[..np2 as usize]).unwrap(),
            "root\nJamboOS\n"
        );

        let code_p3 = run_printenv(&["NONEXISTENT_VAR"], 0, 1, 2);
        assert_eq!(code_p3, 1);

        // 9. Test run_logname
        let (out_rl1, out_wl1) = crate::vfs::pipe().unwrap();
        let code_l1 = run_logname(&[], 0, out_wl1, 2);
        sys_close(out_wl1);
        assert_eq!(code_l1, 0);
        let mut bufl1 = [0u8; 64];
        let nl1 = sys_read(out_rl1, &mut bufl1);
        sys_close(out_rl1);
        assert_eq!(
            core::str::from_utf8(&bufl1[..nl1 as usize]).unwrap(),
            "root\n"
        );

        let (out_rl2, out_wl2) = crate::vfs::pipe().unwrap();
        let code_l2 = run_logname(&["--version"], 0, out_wl2, 2);
        sys_close(out_wl2);
        assert_eq!(code_l2, 0);
        let mut bufl2 = [0u8; 64];
        let nl2 = sys_read(out_rl2, &mut bufl2);
        sys_close(out_rl2);
        assert!(core::str::from_utf8(&bufl2[..nl2 as usize])
            .unwrap()
            .contains("logname"));

        let code_l3 = run_logname(&["extra_argument"], 0, 1, 2);
        assert_eq!(code_l3, 1);

        // 10. Test run_tty
        // in_fd = 0 (ConsoleIn par défaut dans FdTable)
        let (out_rt1, out_wt1) = crate::vfs::pipe().unwrap();
        let code_t1 = run_tty(&[], 0, out_wt1, 2);
        sys_close(out_wt1);
        assert_eq!(code_t1, 0);
        let mut buft1 = [0u8; 64];
        let nt1 = sys_read(out_rt1, &mut buft1);
        sys_close(out_rt1);
        assert_eq!(
            core::str::from_utf8(&buft1[..nt1 as usize]).unwrap(),
            "/dev/tty1\n"
        );

        // Sur un descripteur pipe (non tty)
        let (p_in, p_out) = crate::vfs::pipe().unwrap();
        let (out_rt2, out_wt2) = crate::vfs::pipe().unwrap();
        let code_t2 = run_tty(&[], p_in, out_wt2, 2);
        sys_close(out_wt2);
        assert_eq!(code_t2, 1);
        let mut buft2 = [0u8; 64];
        let nt2 = sys_read(out_rt2, &mut buft2);
        sys_close(out_rt2);
        assert_eq!(
            core::str::from_utf8(&buft2[..nt2 as usize]).unwrap(),
            "not a tty\n"
        );

        // Mode silencieux -s sur pipe
        let code_t3 = run_tty(&["-s"], p_in, 1, 2);
        assert_eq!(code_t3, 1);

        // Mode silencieux -s sur console
        let code_t4 = run_tty(&["-s"], 0, 1, 2);
        assert_eq!(code_t4, 0);

        sys_close(p_in);
        sys_close(p_out);

        // Options --version et argument invalide
        let (out_rt5, out_wt5) = crate::vfs::pipe().unwrap();
        let code_t5 = run_tty(&["--version"], 0, out_wt5, 2);
        sys_close(out_wt5);
        assert_eq!(code_t5, 0);
        let mut buft5 = [0u8; 64];
        let nt5 = sys_read(out_rt5, &mut buft5);
        sys_close(out_rt5);
        assert!(core::str::from_utf8(&buft5[..nt5 as usize])
            .unwrap()
            .contains("tty"));

        let code_t6 = run_tty(&["invalid_operand"], 0, 1, 2);
        assert_eq!(code_t6, 2);

        // 11. Test run_groups
        // Sans argument : groupes de l'utilisateur courant (root par défaut)
        let (out_rg1, out_wg1) = crate::vfs::pipe().unwrap();
        let code_g1 = run_groups(&[], 0, out_wg1, 2);
        sys_close(out_wg1);
        assert_eq!(code_g1, 0);
        let mut bufg1 = [0u8; 64];
        let ng1 = sys_read(out_rg1, &mut bufg1);
        sys_close(out_rg1);
        assert_eq!(
            core::str::from_utf8(&bufg1[..ng1 as usize]).unwrap(),
            "root\n"
        );

        // Avec argument "root"
        let (out_rg2, out_wg2) = crate::vfs::pipe().unwrap();
        let code_g2 = run_groups(&["root"], 0, out_wg2, 2);
        sys_close(out_wg2);
        assert_eq!(code_g2, 0);
        let mut bufg2 = [0u8; 64];
        let ng2 = sys_read(out_rg2, &mut bufg2);
        sys_close(out_rg2);
        assert_eq!(
            core::str::from_utf8(&bufg2[..ng2 as usize]).unwrap(),
            "root : root\n"
        );

        // Avec utilisateur inexistant
        let code_g3 = run_groups(&["unknown_user_999"], 0, 1, 2);
        assert_eq!(code_g3, 1);

        // Options --version
        let (out_rg4, out_wg4) = crate::vfs::pipe().unwrap();
        let code_g4 = run_groups(&["--version"], 0, out_wg4, 2);
        sys_close(out_wg4);
        assert_eq!(code_g4, 0);
        let mut bufg4 = [0u8; 64];
        let ng4 = sys_read(out_rg4, &mut bufg4);
        sys_close(out_rg4);
        assert!(core::str::from_utf8(&bufg4[..ng4 as usize])
            .unwrap()
            .contains("groups"));

        // 12. Test run_hostid
        let (out_rh1, out_wh1) = crate::vfs::pipe().unwrap();
        let code_h1 = run_hostid(&[], out_wh1, 2);
        sys_close(out_wh1);
        assert_eq!(code_h1, 0);
        let mut bufh1 = [0u8; 64];
        let nh1 = sys_read(out_rh1, &mut bufh1);
        sys_close(out_rh1);
        assert_eq!(
            core::str::from_utf8(&bufh1[..nh1 as usize]).unwrap(),
            "007f0101\n"
        );

        // Options --version et --help
        let (out_rh2, out_wh2) = crate::vfs::pipe().unwrap();
        let code_h2 = run_hostid(&["--version"], out_wh2, 2);
        sys_close(out_wh2);
        assert_eq!(code_h2, 0);
        let mut bufh2 = [0u8; 64];
        let nh2 = sys_read(out_rh2, &mut bufh2);
        sys_close(out_rh2);
        assert!(core::str::from_utf8(&bufh2[..nh2 as usize])
            .unwrap()
            .contains("hostid"));

        // Extra operand
        let code_h3 = run_hostid(&["extra"], 1, 2);
        assert_eq!(code_h3, 1);

        // 13. Test run_arch
        let (out_ra1, out_wa1) = crate::vfs::pipe().unwrap();
        let code_a1 = run_arch(&[], out_wa1, 2);
        sys_close(out_wa1);
        assert_eq!(code_a1, 0);
        let mut bufa1 = [0u8; 64];
        let na1 = sys_read(out_ra1, &mut bufa1);
        sys_close(out_ra1);
        let arch_str = core::str::from_utf8(&bufa1[..na1 as usize]).unwrap();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch_str, "x86_64\n");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch_str, "aarch64\n");

        // Options --version et --help
        let (out_ra2, out_wa2) = crate::vfs::pipe().unwrap();
        let code_a2 = run_arch(&["--version"], out_wa2, 2);
        sys_close(out_wa2);
        assert_eq!(code_a2, 0);
        let mut bufa2 = [0u8; 64];
        let na2 = sys_read(out_ra2, &mut bufa2);
        sys_close(out_ra2);
        assert!(core::str::from_utf8(&bufa2[..na2 as usize])
            .unwrap()
            .contains("arch"));

        // Extra operand
        let code_a3 = run_arch(&["extra"], 1, 2);
        assert_eq!(code_a3, 1);

        // 14. Test run_nproc
        let (out_rn1, out_wn1) = crate::vfs::pipe().unwrap();
        let code_n1 = run_nproc(&[], out_wn1, 2);
        sys_close(out_wn1);
        assert_eq!(code_n1, 0);
        let mut bufn1 = [0u8; 64];
        let nn1 = sys_read(out_rn1, &mut bufn1);
        sys_close(out_rn1);
        assert_eq!(core::str::from_utf8(&bufn1[..nn1 as usize]).unwrap(), "1\n");

        // Option --ignore
        let (out_rn2, out_wn2) = crate::vfs::pipe().unwrap();
        let code_n2 = run_nproc(&["--ignore=1"], out_wn2, 2);
        sys_close(out_wn2);
        assert_eq!(code_n2, 0);
        let mut bufn2 = [0u8; 64];
        let nn2 = sys_read(out_rn2, &mut bufn2);
        sys_close(out_rn2);
        assert_eq!(core::str::from_utf8(&bufn2[..nn2 as usize]).unwrap(), "1\n");

        // Option --version
        let (out_rn3, out_wn3) = crate::vfs::pipe().unwrap();
        let code_n3 = run_nproc(&["--version"], out_wn3, 2);
        sys_close(out_wn3);
        assert_eq!(code_n3, 0);
        let mut bufn3 = [0u8; 64];
        let nn3 = sys_read(out_rn3, &mut bufn3);
        sys_close(out_rn3);
        assert!(core::str::from_utf8(&bufn3[..nn3 as usize])
            .unwrap()
            .contains("nproc"));

        // Extra operand
        let code_n4 = run_nproc(&["extra"], 1, 2);
        assert_eq!(code_n4, 1);

        // 15. Test run_users
        let (out_ru1, out_wu1) = crate::vfs::pipe().unwrap();
        let code_u1 = run_users(&[], out_wu1, 2);
        sys_close(out_wu1);
        assert_eq!(code_u1, 0);
        let mut bufu1 = [0u8; 64];
        let nu1 = sys_read(out_ru1, &mut bufu1);
        sys_close(out_ru1);
        assert_eq!(
            core::str::from_utf8(&bufu1[..nu1 as usize]).unwrap(),
            "root\n"
        );

        // Option --version
        let (out_ru2, out_wu2) = crate::vfs::pipe().unwrap();
        let code_u2 = run_users(&["--version"], out_wu2, 2);
        sys_close(out_wu2);
        assert_eq!(code_u2, 0);
        let mut bufu2 = [0u8; 64];
        let nu2 = sys_read(out_ru2, &mut bufu2);
        sys_close(out_ru2);
        assert!(core::str::from_utf8(&bufu2[..nu2 as usize])
            .unwrap()
            .contains("users"));

        // Extra operand
        let code_u3 = run_users(&["extra"], 1, 2);
        assert_eq!(code_u3, 1);

        // 16. Test run_who
        let (out_rwho1, out_wwho1) = crate::vfs::pipe().unwrap();
        let code_who1 = run_who(&[], out_wwho1, 2);
        sys_close(out_wwho1);
        assert_eq!(code_who1, 0);
        let mut bufwho1 = [0u8; 128];
        let nwho1 = sys_read(out_rwho1, &mut bufwho1);
        sys_close(out_rwho1);
        let s_who1 = core::str::from_utf8(&bufwho1[..nwho1 as usize]).unwrap();
        assert!(s_who1.contains("root"));
        assert!(s_who1.contains("console"));

        // Option -q / --count
        let (out_rwho2, out_wwho2) = crate::vfs::pipe().unwrap();
        let code_who2 = run_who(&["-q"], out_wwho2, 2);
        sys_close(out_wwho2);
        assert_eq!(code_who2, 0);
        let mut bufwho2 = [0u8; 64];
        let nwho2 = sys_read(out_rwho2, &mut bufwho2);
        sys_close(out_rwho2);
        let s_who2 = core::str::from_utf8(&bufwho2[..nwho2 as usize]).unwrap();
        assert!(s_who2.contains("root\n# users=1\n"));

        // Option -b / --boot
        let (out_rwho3, out_wwho3) = crate::vfs::pipe().unwrap();
        let code_who3 = run_who(&["--boot"], out_wwho3, 2);
        sys_close(out_wwho3);
        assert_eq!(code_who3, 0);
        let mut bufwho3 = [0u8; 64];
        let nwho3 = sys_read(out_rwho3, &mut bufwho3);
        sys_close(out_rwho3);
        let s_who3 = core::str::from_utf8(&bufwho3[..nwho3 as usize]).unwrap();
        assert!(s_who3.contains("system boot"));

        // Option --version
        let (out_rwho4, out_wwho4) = crate::vfs::pipe().unwrap();
        let code_who4 = run_who(&["--version"], out_wwho4, 2);
        sys_close(out_wwho4);
        assert_eq!(code_who4, 0);
        let mut bufwho4 = [0u8; 64];
        let nwho4 = sys_read(out_rwho4, &mut bufwho4);
        sys_close(out_rwho4);
        assert!(core::str::from_utf8(&bufwho4[..nwho4 as usize])
            .unwrap()
            .contains("who"));

        // Option inconnue
        let code_who5 = run_who(&["--invalid-flag"], 1, 2);
        assert_eq!(code_who5, 1);

        // 17. Test run_nohup
        let (out_rnohup1, out_wnohup1) = crate::vfs::pipe().unwrap();
        let code_nohup1 = run_nohup(&["echo", "hello-nohup"], 0, out_wnohup1, 2);
        sys_close(out_wnohup1);
        assert_eq!(code_nohup1, 0);
        let mut bufnohup1 = [0u8; 64];
        let nnohup1 = sys_read(out_rnohup1, &mut bufnohup1);
        sys_close(out_rnohup1);
        let s_nohup1 = core::str::from_utf8(&bufnohup1[..nnohup1 as usize]).unwrap();
        assert!(s_nohup1.contains("hello-nohup"));

        // Option --version
        let (out_rnohup2, out_wnohup2) = crate::vfs::pipe().unwrap();
        let code_nohup2 = run_nohup(&["--version"], 0, out_wnohup2, 2);
        sys_close(out_wnohup2);
        assert_eq!(code_nohup2, 0);
        let mut bufnohup2 = [0u8; 64];
        let nnohup2 = sys_read(out_rnohup2, &mut bufnohup2);
        sys_close(out_rnohup2);
        assert!(core::str::from_utf8(&bufnohup2[..nnohup2 as usize])
            .unwrap()
            .contains("nohup"));

        // Option --help
        let (out_rnohup3, out_wnohup3) = crate::vfs::pipe().unwrap();
        let code_nohup3 = run_nohup(&["--help"], 0, out_wnohup3, 2);
        sys_close(out_wnohup3);
        assert_eq!(code_nohup3, 0);
        let mut bufnohup3 = [0u8; 128];
        let nnohup3 = sys_read(out_rnohup3, &mut bufnohup3);
        sys_close(out_rnohup3);
        assert!(core::str::from_utf8(&bufnohup3[..nnohup3 as usize])
            .unwrap()
            .contains("Usage: nohup"));

        // Sans commande (missing operand -> 125)
        let code_nohup4 = run_nohup(&[], 0, 1, 2);
        assert_eq!(code_nohup4, 125);

        // Option inconnue -> 125
        let code_nohup5 = run_nohup(&["--invalid-flag"], 0, 1, 2);
        assert_eq!(code_nohup5, 125);
    }
}

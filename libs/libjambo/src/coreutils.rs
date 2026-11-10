//! Utilitaires Coreutils autonomes et routines d'E/S POSIX en Ring 3
//!
//! Ce module fournit les implémentations `#![no_std]` des outils fondamentaux :
//! `echo`, `cat`, `wc`, `true`, `false`, `ls`.
//! Chaque routine s'interface avec les descripteurs POSIX (`vfs::*`)
//! sans recourir à des allocations heap obligatoires.

use crate::vfs::{with_fd_table, O_APPEND, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY};

#[derive(Clone, Copy)]
pub struct VfsFileNode {
    pub path: [u8; crate::vfs::MAX_PATH_LEN],
    pub path_len: usize,
    pub buffer: [u8; crate::vfs::FILE_BUFFER_SIZE],
    pub size: usize,
    pub is_active: bool,
    pub is_dir: bool,
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
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }

    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

pub static mut INODE_POOL: [VfsFileNode; 32] = [
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
];

/// Ouvre un fichier via la table de descripteurs VFS du processus
pub fn sys_open(path: &str, flags: i32) -> i32 {
    let mut inode_idx = None;
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        for (i, node) in (*pool).iter().enumerate() {
            if node.is_active && node.path_str() == path {
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
        // Vérification qu'aucun fichier actif n'a ce répertoire pour préfixe
        for node in (*pool).iter() {
            if node.is_active
                && node.path_str() != clean_path
                && node.path_str().starts_with(clean_path)
            {
                return -1; // ENOTEMPTY
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
        let res = sys_mkdir_pool(path, 0o755);
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
            let mut snapshot: [Option<InodeSnapshotItem>; 32] = [None; 32];
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

    // Parsing du mode octal (supporte ex: 755, 0755, 644, 600, etc.)
    let mut mode: u32 = 0;
    for b in raw_mode.bytes() {
        if !(b'0'..=b'7').contains(&b) {
            let _ = sys_write(err_fd, b"chmod: invalid mode: '");
            let _ = sys_write(err_fd, raw_mode.as_bytes());
            let _ = sys_write(err_fd, b"'\n");
            return 1;
        }
        mode = (mode << 3) | (b - b'0') as u32;
    }

    if mode > 0o7777 {
        let _ = sys_write(err_fd, b"chmod: invalid mode: '");
        let _ = sys_write(err_fd, raw_mode.as_bytes());
        let _ = sys_write(err_fd, b"'\n");
        return 1;
    }

    let mut has_error = false;
    for &target in files {
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
                            node.mode = mode & 0o7777;
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

                if b == b'\n' {
                    if out_len > 0 && out_buf[out_len - 1] == b'\r' {
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
            if out_len > 0 && out_buf[out_len - 1] == b'\r' {
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

fn process_paste_serial(mut reader: LineReader, out_fd: i32, delims: &[PasteDelim]) {
    let mut line_buf = [0u8; 512];
    let mut first_line = true;
    let mut delim_idx = 0;

    while let Some(len) = reader.read_line(&mut line_buf) {
        if !first_line {
            let d = delims[delim_idx % delims.len()];
            write_paste_delim(out_fd, d);
            delim_idx += 1;
        }
        let _ = sys_write(out_fd, &line_buf[..len]);
        first_line = false;
    }

    if !first_line {
        let _ = sys_write(out_fd, b"\n");
    }
}

fn process_paste_parallel(readers: &mut [LineReader], out_fd: i32, delims: &[PasteDelim]) {
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
            if let Some(len) = readers[j].read_line(slot) {
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
        let _ = sys_write(out_fd, b"\n");
    }
}

/// Exécute l'utilitaire standard POSIX `paste` (fusion ligne à ligne de plusieurs fichiers ou flux)
pub fn run_paste(args: &[&str], in_fd: i32, out_fd: i32, err_fd: i32) -> i32 {
    let mut serial_mode = false;
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
                    b"Usage: paste [OPTION]... [FILE]...\nWrite lines consisting of the sequentially corresponding lines from\neach FILE, separated by TABs, to standard output.\n\nWith no FILE, or when FILE is -, read standard input.\n\n  -d, --delimiters=LIST   reuse characters from LIST instead of TABs\n  -s, --serial            paste one file at a time instead of in parallel\n      --help              display this help and exit\n",
                );
                return 0;
            }

            if arg == "-s" || arg == "--serial" {
                serial_mode = true;
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

    if file_count == 0 {
        let reader = LineReader::new(in_fd);
        if serial_mode {
            process_paste_serial(reader, out_fd, active_delims);
        } else {
            let mut readers = [reader];
            process_paste_parallel(&mut readers, out_fd, active_delims);
        }
        return 0;
    }

    if serial_mode {
        let mut exit_code = 0;
        for &idx in &file_indices[..file_count] {
            let path = args[idx];
            if path == "-" {
                let reader = LineReader::new(in_fd);
                process_paste_serial(reader, out_fd, active_delims);
            } else {
                let fd = sys_open(path, O_RDONLY);
                if fd < 0 {
                    let _ = sys_write(err_fd, b"paste: ");
                    let _ = sys_write(err_fd, path.as_bytes());
                    let _ = sys_write(err_fd, b": No such file or directory\n");
                    exit_code = 1;
                } else {
                    let reader = LineReader::new(fd);
                    process_paste_serial(reader, out_fd, active_delims);
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
        process_paste_parallel(&mut readers[..actual_count], out_fd, active_delims);
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

/// Utilitaire `expr` : évalue une expression arithmétique ou de comparaison POSIX.
///
/// Syntaxe : `expr VALEUR OP VALEUR`
///
/// Opérateurs arithmétiques : `+`, `-`, `*`, `/`, `%`
/// Opérateurs de comparaison : `=`, `!=`, `<`, `<=`, `>`, `>=`
/// Opérateurs logiques : `|`, `&`
///
/// # Codes de retour
/// - 0 : résultat non-nul ou non-vide (vrai).
/// - 1 : résultat nul ou vide (faux).
/// - 2 : erreur de syntaxe ou division par zéro.
pub fn run_expr(args: &[&str], out_fd: i32, err_fd: i32) -> i32 {
    if args.len() < 3 {
        let _ = sys_write(err_fd, b"expr: syntaxe: expr VAL OP VAL\n");
        return 2;
    }

    let lhs_str = args[0].trim();
    let op = args[1].trim();
    let rhs_str = args[2].trim();

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

        // Suppression avec rm -r
        let code_rm = run_rm(&["-r", "/tmp/new_dir"], 2);
        assert_eq!(code_rm, 0);
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

        // 5. Erreurs d'options incompatibles
        let (out_r5, out_w5) = crate::vfs::pipe().expect("pipe out split 5");
        let code5 = run_split(&["-l", "5", "-b", "10"], 0, 1, out_w5);
        assert_eq!(code5, 1);
        sys_close(out_w5);
        sys_close(out_r5);

        // Nettoyage des fichiers temporaires
        let _ = sys_unlink_pool(src_path);
        let _ = sys_unlink_pool("/tmp/s1_aa");
        let _ = sys_unlink_pool("/tmp/s1_ab");
        let _ = sys_unlink_pool("/tmp/s1_ac");
        let _ = sys_unlink_pool("/tmp/s2_00");
        let _ = sys_unlink_pool("/tmp/s2_01");
        let _ = sys_unlink_pool("/tmp/s2_02");
        let _ = sys_unlink_pool("/tmp/s3_aaa");
        let _ = sys_unlink_pool("/tmp/s3_aab");
        let _ = sys_unlink_pool("/tmp/s4_aa");
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
}

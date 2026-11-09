//! Utilitaires Coreutils autonomes et routines d'E/S POSIX en Ring 3
//!
//! Ce module fournit les implémentations `#![no_std]` des outils fondamentaux :
//! `echo`, `cat`, `wc`, `true`, `false`, `ls`.
//! Chaque routine s'interface avec les descripteurs POSIX (`vfs::*`)
//! sans recourir à des allocations heap obligatoires.

use crate::vfs::{with_fd_table, O_RDONLY};

#[derive(Clone, Copy)]
pub struct VfsFileNode {
    pub path: [u8; crate::vfs::MAX_PATH_LEN],
    pub path_len: usize,
    pub buffer: [u8; crate::vfs::FILE_BUFFER_SIZE],
    pub size: usize,
    pub is_active: bool,
    pub is_dir: bool,
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
}

//! Utilitaires Coreutils autonomes et routines d'E/S POSIX en Ring 3
//!
//! Ce module fournit les implémentations `#![no_std]` des outils fondamentaux :
//! `echo`, `cat`, `wc`, `true`, `false`, `ls`.
//! Chaque routine s'interface avec les descripteurs POSIX (`vfs::*`)
//! sans recourir à des allocations heap obligatoires.

use crate::vfs::{with_fd_table, O_RDONLY};

#[derive(Clone, Copy)]
struct VfsFileNode {
    path: [u8; crate::vfs::MAX_PATH_LEN],
    path_len: usize,
    buffer: [u8; crate::vfs::FILE_BUFFER_SIZE],
    size: usize,
    is_active: bool,
}

impl VfsFileNode {
    const fn empty() -> Self {
        Self {
            path: [0u8; crate::vfs::MAX_PATH_LEN],
            path_len: 0,
            buffer: [0u8; crate::vfs::FILE_BUFFER_SIZE],
            size: 0,
            is_active: false,
        }
    }

    fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

static mut INODE_POOL: [VfsFileNode; 16] = [
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
];

/// Ouvre un fichier via la table de descripteurs VFS du processus
pub fn sys_open(path: &str, flags: i32) -> i32 {
    let mut inode_idx = None;
    // SAFETY: Accès protégé au pool d'inodes virtuel
    unsafe {
        let pool = core::ptr::addr_of_mut!(INODE_POOL);
        for (i, node) in (*pool).iter().enumerate() {
            if node.is_active && node.path_str() == path {
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

    if !long_format {
        let _ = sys_write(out_fd, b"\n");
    }

    0
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
}

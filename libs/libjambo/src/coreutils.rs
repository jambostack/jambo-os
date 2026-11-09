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
}

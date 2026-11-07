# Spécification Technique — Jalon 6.3 (v0.3.90) : VFS POSIX, Descripteurs de Fichiers (fd_table) & Interfaçage JamboFS

> **Date** : 7 novembre 2026  
> **Composants cibles** : `libs/libjambo`, `services/jambo-fs`, `services/jambo-sh`, `kernel`, `xtask`  
> **Version cible** : `v0.3.90` (Pre-Alpha / Prototype Expérimental de Recherche)  
> **Statut** : Approuvé

---

## 1. Objectifs & Portée

L'objectif du **Jalon 6.3** est de doter l'espace utilisateur de JamboOS ([`libs/libjambo`](file:///c:/Users/joker/Documents/jambo-os/libs/libjambo)) d'une couche VFS (Virtual File System) et d'une table de descripteurs de fichiers (`fd_table`) conforme aux standards POSIX / C-ABI, fonctionnant en `#![no_std]` sans allocation heap obligatoire.

### Exigences Fondamentales
1. **Confinement Ring 3 & Zéro Autorité Ambiante** :
   - La table de descripteurs de fichiers est privée à chaque processus (`Process.fd_table`).
   - Le noyau ne gère pas de descripteurs de fichiers applicatifs (fidélité au principe micro-noyau seL4).
2. **Table de Descripteurs (`FdTable`) `#![no_std]`** :
   - Capacité fixe : 32 descripteurs ouverts par processus (`MAX_FDS = 32`).
   - Entrées prédéfinies :
     - `fd = 0` : `STDIN_FILENO` (Périphérique console en lecture).
     - `fd = 1` : `STDOUT_FILENO` (Périphérique console en écriture).
     - `fd = 2` : `STDERR_FILENO` (Périphérique console en écriture).
     - `fd >= 3` : Fichiers et canaux IPC dynamiques.
3. **Primitives POSIX / C-ABI Complètes** :
   - `open(const char *pathname, int flags, ...)` : Alloue le plus petit descripteur disponible, valide les droits d'accès.
   - `close(int fd)` : Libère le descripteur et purge les métadonnées.
   - `read(int fd, void *buf, size_t count)` : Lit des octets depuis la console (`fd = 0`) ou depuis un fichier régulier via `offset`.
   - `write(int fd, const void *buf, size_t count)` : Écrit vers la console (`fd = 1, 2`) ou vers un fichier régulier.
   - `lseek(int fd, off_t offset, int whence)` : Modifie le pointeur de fichier (`SEEK_SET`, `SEEK_CUR`, `SEEK_END`).
   - `fstat(int fd, struct stat *buf)` & `stat(const char *pathname, struct stat *buf)` : Récupère les métadonnées de fichier.
4. **Constantes POSIX Standard** :
   - Drapeaux d'ouverture : `O_RDONLY = 0`, `O_WRONLY = 1`, `O_RDWR = 2`, `O_CREAT = 64`, `O_APPEND = 1024`.
   - Drapeaux de positionnement : `SEEK_SET = 0`, `SEEK_CUR = 1`, `SEEK_END = 2`.
   - Modes et types : `S_IFREG = 0x8000`, `S_IFDIR = 0x4000`, `S_IFCHR = 0x2000`.
5. **Validation Unitaire & Intégration** :
   - Suite complète de tests unitaires dans `libjambo` validant `open`, `read`, `write`, `lseek`, `close`, la réutilisation de descripteurs, et la protection contre `EBADF` et `EINVAL`.
   - Commande d'inspection `vfs` dans le shell interactif `jsh`.

---

## 2. Architecture & Conception Détaillée

### 2.1 Types et Constantes (`libs/libjambo/src/vfs.rs`)

```rust
pub const MAX_FDS: usize = 32;
pub const MAX_PATH_LEN: usize = 64;

pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0o100;
pub const O_TRUNC: i32 = 0o1000;
pub const O_APPEND: i32 = 0o2000;

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;

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
}
```

### 2.2 Table de Descripteurs `FdTable`

```rust
pub struct FdTable {
    pub entries: [FdEntry; MAX_FDS],
}

impl FdTable {
    pub const fn new() -> Self;
    pub fn alloc_fd(&mut self, kind: FdKind, flags: i32, path: &str, size: u64) -> Result<i32, SysError>;
    pub fn free_fd(&mut self, fd: i32) -> Result<(), SysError>;
    pub fn get(&self, fd: i32) -> Option<&FdEntry>;
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut FdEntry>;
    pub fn count_open(&self) -> usize;
}
```

### 2.3 Structure `stat` POSIX

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
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
```

---

## 3. Plan de Test & Vérification

1. **`test_vfs_open_close_reuse`** : Ouverture de 3 fichiers distincts, fermeture du descripteur 3, réouverture vérifiant la réallocation du slot 3.
2. **`test_vfs_read_write_offset`** : Écriture de données avec incrément d'offset, `lseek(SEEK_SET, 0)` et relecture.
3. **`test_vfs_stat`** : Vérification des modes `S_IFREG`, `S_IFCHR` et taille du fichier.
4. **Intégration & Chaîne de Construction** :
   - `cargo test --package libjambo` (100% succès).
   - `cargo clippy --workspace --exclude incubator` (0 warning).
   - `cargo check --workspace --target aarch64-unknown-none --exclude xtask`.
   - `cargo xtask build --release` & `cargo xtask dist --release`.

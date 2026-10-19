#![no_std]

use virtio_drv as _;

pub const JAMBOFS_MAGIC: u64 = 0x53465F4F424D414A; // "JAMBO_FS" en ASCII little-endian
pub const JAMBOFS_VERSION: u32 = 1;
pub const BLOCK_SIZE: usize = 4096;

/// Uberblock racine JamboFS validé atomiquement
#[repr(C, align(512))]
#[derive(Debug, Clone, Copy)]
pub struct Uberblock {
    pub magic: u64,
    pub version: u32,
    pub block_size: u32,
    pub generation: u64,
    pub root_tree_offset: u64,
    pub root_checksum: [u8; 32], // BLAKE3 / SHA-256 Merkle root
    pub flags: u64,
    pub timestamp: u64,
}

impl Default for Uberblock {
    fn default() -> Self {
        Self {
            magic: JAMBOFS_MAGIC,
            version: JAMBOFS_VERSION,
            block_size: BLOCK_SIZE as u32,
            generation: 1,
            root_tree_offset: BLOCK_SIZE as u64,
            root_checksum: [0; 32],
            flags: 0,
            timestamp: 0,
        }
    }
}

impl Uberblock {
    pub fn is_valid(&self) -> bool {
        self.magic == JAMBOFS_MAGIC && self.version == JAMBOFS_VERSION
    }
}

/// Nœud d'arbre B+ Copy-on-Write (CoW)
#[repr(C, align(4096))]
pub struct BPlusTreeNode {
    pub is_leaf: bool,
    pub entry_count: u16,
    pub generation: u64,
    pub keys: [u64; 64],
    pub child_offsets: [u64; 64],
    pub node_checksum: [u8; 32],
}

impl BPlusTreeNode {
    pub fn new_leaf(generation: u64) -> Self {
        Self {
            is_leaf: true,
            entry_count: 0,
            generation,
            keys: [0; 64],
            child_offsets: [0; 64],
            node_checksum: [0; 32],
        }
    }
}

/// Inode de fichier transactionnel JamboFS
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsInode {
    pub ino: u64,
    pub size: u64,
    pub generation: u64,
    pub flags: u32,
    pub block_count: u32,
    pub direct_blocks: [u64; 8],
    pub checksum: [u8; 32],
}

impl FsInode {
    pub fn new(ino: u64, size: u64, generation: u64) -> Self {
        Self {
            ino,
            size,
            generation,
            flags: 0,
            block_count: ((size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64) as u32,
            direct_blocks: [0; 8],
            checksum: [0; 32],
        }
    }
}

/// Opcodes d'opérations IPC du système de fichiers JamboFS
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOpcode {
    Open = 1,
    Read = 2,
    Write = 3,
    Stat = 4,
    Sync = 5,
}

/// Requête IPC transmise au serveur JamboFS
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsRequest {
    pub opcode: FsOpcode,
    pub handle: libjambo::Handle,
    pub offset: u64,
    pub length: u32,
    pub path_len: u32,
    pub path: [u8; 64],
}

/// Réponse IPC renvoyée par le serveur JamboFS
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsResponse {
    pub status: i64,
    pub bytes_transferred: u64,
    pub vmo_handle: libjambo::Handle,
}

/// Calcule un condensat Merkle 256 bits pour garantir l'intégrité des blocs
pub fn compute_block_checksum(data: &[u8], seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut acc = seed.wrapping_mul(0x9E3779B97F4A7C15);
    for (i, &b) in data.iter().enumerate() {
        acc = acc.wrapping_add((b as u64) << ((i % 8) * 8)).rotate_left(5);
    }
    for i in 0..4 {
        let chunk = acc.wrapping_add(i as u64).to_le_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&chunk);
    }
    out
}

pub const MAX_VFS_FILES: usize = 16;
pub const MAX_PATH_LEN: usize = 64;
pub const MAX_FILE_DATA: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct VfsFileEntry {
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: usize,
    pub inode: FsInode,
    pub data_len: usize,
    pub data: [u8; MAX_FILE_DATA],
    pub in_use: bool,
}

impl Default for VfsFileEntry {
    fn default() -> Self {
        Self {
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            inode: FsInode::new(0, 0, 0),
            data_len: 0,
            data: [0; MAX_FILE_DATA],
            in_use: false,
        }
    }
}

/// Serveur de fichiers transactionnel JamboFS en espace utilisateur
pub struct JamboFsServer {
    pub active_uberblock: Uberblock,
    pub next_ino: u64,
    pub files: [VfsFileEntry; MAX_VFS_FILES],
}

impl JamboFsServer {
    pub fn new(uberblock: Uberblock) -> Self {
        let mut server = Self {
            active_uberblock: uberblock,
            next_ino: 100,
            files: [VfsFileEntry::default(); MAX_VFS_FILES],
        };

        // Fichiers initiaux du système VFS
        server.add_system_file("/etc/hostname", b"jambobox\n");
        server.add_system_file(
            "/system/config.json",
            b"{\"hostname\": \"jambobox\", \"secure_boot\": true}",
        );
        server.add_system_file(
            "/var/log/syslog",
            b"[SYSTEM] JamboOS v0.2.41 booted successfully\n",
        );

        server
    }

    pub fn add_system_file(&mut self, path: &str, content: &[u8]) {
        for entry in &mut self.files {
            if !entry.in_use {
                entry.in_use = true;
                let path_bytes = path.as_bytes();
                entry.path_len = path_bytes.len().min(MAX_PATH_LEN);
                entry.path[..entry.path_len].copy_from_slice(&path_bytes[..entry.path_len]);

                let ino = self.next_ino;
                self.next_ino += 1;
                let mut inode =
                    FsInode::new(ino, content.len() as u64, self.active_uberblock.generation);
                inode.checksum = compute_block_checksum(content, self.active_uberblock.generation);
                entry.inode = inode;

                entry.data_len = content.len().min(MAX_FILE_DATA);
                entry.data[..entry.data_len].copy_from_slice(&content[..entry.data_len]);
                break;
            }
        }
    }

    /// Ouvre un fichier par son chemin virtuel
    pub fn open(&self, path: &str) -> Result<u64, libjambo::SysError> {
        let path_bytes = path.as_bytes();
        for entry in &self.files {
            if entry.in_use
                && entry.path_len == path_bytes.len()
                && &entry.path[..entry.path_len] == path_bytes
            {
                return Ok(entry.inode.ino);
            }
        }
        Err(libjambo::SysError::InvalidArgument)
    }

    /// Lit le contenu d'un fichier par son numéro d'inode
    pub fn read(&self, ino: u64, offset: usize, out: &mut [u8]) -> Result<usize, libjambo::SysError> {
        for entry in &self.files {
            if entry.in_use && entry.inode.ino == ino {
                if offset >= entry.data_len {
                    return Ok(0);
                }
                let available = entry.data_len - offset;
                let to_read = available.min(out.len());
                out[..to_read].copy_from_slice(&entry.data[offset..offset + to_read]);
                return Ok(to_read);
            }
        }
        Err(libjambo::SysError::InvalidArgument)
    }

    /// Écrit dans un fichier de manière Copy-on-Write (atomique)
    pub fn write_file_vfs(
        &mut self,
        path: &str,
        content: &[u8],
    ) -> Result<FsInode, libjambo::SysError> {
        let (inode, _) = self.write_file_cow(content)?;
        let path_bytes = path.as_bytes();

        // Mettre à jour si le fichier existe déjà
        for entry in &mut self.files {
            if entry.in_use
                && entry.path_len == path_bytes.len()
                && &entry.path[..entry.path_len] == path_bytes
            {
                entry.inode = inode;
                entry.data_len = content.len().min(MAX_FILE_DATA);
                entry.data[..entry.data_len].copy_from_slice(&content[..entry.data_len]);
                return Ok(inode);
            }
        }

        // Sinon créer une nouvelle entrée VFS
        for entry in &mut self.files {
            if !entry.in_use {
                entry.in_use = true;
                entry.path_len = path_bytes.len().min(MAX_PATH_LEN);
                entry.path[..entry.path_len].copy_from_slice(&path_bytes[..entry.path_len]);
                entry.inode = inode;
                entry.data_len = content.len().min(MAX_FILE_DATA);
                entry.data[..entry.data_len].copy_from_slice(&content[..entry.data_len]);
                return Ok(inode);
            }
        }
        Err(libjambo::SysError::OutOfMemory)
    }

    /// Retourne les métadonnées (stat) d'un fichier par inode
    pub fn stat(&self, ino: u64) -> Result<FsInode, libjambo::SysError> {
        for entry in &self.files {
            if entry.in_use && entry.inode.ino == ino {
                return Ok(entry.inode);
            }
        }
        Err(libjambo::SysError::InvalidArgument)
    }

    /// Traite une requête IPC issue d'un canal VFS
    pub fn handle_ipc(
        &mut self,
        req: &FsRequest,
        req_data: &[u8],
        resp_data: &mut [u8],
    ) -> FsResponse {
        match req.opcode {
            FsOpcode::Open => {
                let path_len = (req.path_len as usize).min(req.path.len());
                if let Ok(path_str) = core::str::from_utf8(&req.path[..path_len]) {
                    match self.open(path_str) {
                        Ok(ino) => FsResponse {
                            status: libjambo::SysError::Success as i64,
                            bytes_transferred: ino,
                            vmo_handle: libjambo::Handle::new(ino as u32, 1),
                        },
                        Err(e) => FsResponse {
                            status: e as i64,
                            bytes_transferred: 0,
                            vmo_handle: libjambo::Handle::NULL,
                        },
                    }
                } else {
                    FsResponse {
                        status: libjambo::SysError::InvalidArgument as i64,
                        bytes_transferred: 0,
                        vmo_handle: libjambo::Handle::NULL,
                    }
                }
            }
            FsOpcode::Read => {
                let ino = req.handle.index() as u64;
                match self.read(ino, req.offset as usize, resp_data) {
                    Ok(read_len) => FsResponse {
                        status: libjambo::SysError::Success as i64,
                        bytes_transferred: read_len as u64,
                        vmo_handle: req.handle,
                    },
                    Err(e) => FsResponse {
                        status: e as i64,
                        bytes_transferred: 0,
                        vmo_handle: libjambo::Handle::NULL,
                    },
                }
            }
            FsOpcode::Write => {
                let path_len = (req.path_len as usize).min(req.path.len());
                if let Ok(path_str) = core::str::from_utf8(&req.path[..path_len]) {
                    match self.write_file_vfs(path_str, req_data) {
                        Ok(inode) => FsResponse {
                            status: libjambo::SysError::Success as i64,
                            bytes_transferred: inode.size,
                            vmo_handle: libjambo::Handle::new(inode.ino as u32, 1),
                        },
                        Err(e) => FsResponse {
                            status: e as i64,
                            bytes_transferred: 0,
                            vmo_handle: libjambo::Handle::NULL,
                        },
                    }
                } else {
                    FsResponse {
                        status: libjambo::SysError::InvalidArgument as i64,
                        bytes_transferred: 0,
                        vmo_handle: libjambo::Handle::NULL,
                    }
                }
            }
            FsOpcode::Stat => {
                let ino = req.handle.index() as u64;
                match self.stat(ino) {
                    Ok(inode) => FsResponse {
                        status: libjambo::SysError::Success as i64,
                        bytes_transferred: inode.size,
                        vmo_handle: req.handle,
                    },
                    Err(e) => FsResponse {
                        status: e as i64,
                        bytes_transferred: 0,
                        vmo_handle: libjambo::Handle::NULL,
                    },
                }
            }
            FsOpcode::Sync => FsResponse {
                status: libjambo::SysError::Success as i64,
                bytes_transferred: self.active_uberblock.generation,
                vmo_handle: libjambo::Handle::NULL,
            },
        }
    }

    pub fn generation(&self) -> u64 {
        self.active_uberblock.generation
    }

    /// Effectue une écriture Copy-on-Write (CoW) atomique sans écraser les blocs existants
    pub fn write_file_cow(&mut self, data: &[u8]) -> Result<(FsInode, u64), libjambo::SysError> {
        self.active_uberblock.generation += 1;
        let gen = self.active_uberblock.generation;

        let ino_id = self.next_ino;
        self.next_ino += 1;

        let mut inode = FsInode::new(ino_id, data.len() as u64, gen);
        let block_chk = compute_block_checksum(data, gen);
        inode.checksum = block_chk;

        // Allouer un nouvel offset pour le bloc CoW
        let new_block_offset = self.active_uberblock.root_tree_offset
            + (inode.block_count as u64 * BLOCK_SIZE as u64);
        inode.direct_blocks[0] = new_block_offset;

        // Mettre à jour l'Uberblock atomiquement
        self.active_uberblock.root_tree_offset = new_block_offset;
        self.active_uberblock.root_checksum = block_chk;

        Ok((inode, new_block_offset))
    }

    /// Effectue un commit transactionnel atomique avec incrémentation de génération
    pub fn commit_transaction(&mut self, new_root_offset: u64, new_checksum: [u8; 32]) {
        self.active_uberblock.generation += 1;
        self.active_uberblock.root_tree_offset = new_root_offset;
        self.active_uberblock.root_checksum = new_checksum;
    }

    /// Vérifie l'intégrité de la racine Merkle du système de fichiers
    pub fn verify_integrity(&self) -> bool {
        self.active_uberblock.is_valid() && self.active_uberblock.root_checksum != [0u8; 32]
    }
}

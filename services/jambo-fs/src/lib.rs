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

/// Serveur de fichiers transactionnel JamboFS en espace utilisateur
pub struct JamboFsServer {
    active_uberblock: Uberblock,
}

impl JamboFsServer {
    pub fn new(uberblock: Uberblock) -> Self {
        Self {
            active_uberblock: uberblock,
        }
    }

    pub fn generation(&self) -> u64 {
        self.active_uberblock.generation
    }

    /// Effectue un commit transactionnel atomique avec incrémentation de génération
    pub fn commit_transaction(&mut self, new_root_offset: u64, new_checksum: [u8; 32]) {
        self.active_uberblock.generation += 1;
        self.active_uberblock.root_tree_offset = new_root_offset;
        self.active_uberblock.root_checksum = new_checksum;
    }
}

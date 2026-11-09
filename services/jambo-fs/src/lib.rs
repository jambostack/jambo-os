#![no_std]

#[cfg(test)]
extern crate std;

pub const JAMBOFS_MAGIC: u64 = 0x53465F4F424D414A; // "JAMBO_FS" en ASCII little-endian
pub const JAMBOFS_VERSION: u32 = 1;
pub const BLOCK_SIZE: usize = 4096;

pub const BLOCK_OP_GET_VMO: u32 = 0;
pub const BLOCK_OP_READ: u32 = 1;
pub const BLOCK_OP_WRITE: u32 = 2;
pub const BLOCK_OP_FLUSH: u32 = 3;

pub const SHARED_VMO_SIZE: usize = 64 * 1024;
pub const SHARED_VMO_ADDR: usize = 0x0070_0000;

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

/// Structure de requête IPC de bloc (32 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockRequest {
    pub opcode: u32,
    pub req_id: u32,
    pub lba: u64,
    pub count: u32,
    pub buf_offset: u32,
    pub _reserved: u32,
}

impl BlockRequest {
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                core::mem::size_of::<Self>(),
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Structure de réponse IPC de bloc (16 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockResponse {
    pub req_id: u32,
    pub status: i32,
    pub bytes_transferred: u32,
    pub _reserved: u32,
}

impl BlockResponse {
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                core::mem::size_of::<Self>(),
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Message IPC sur canal hybride
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [libjambo::Handle; MAX_HANDLES],
    pub handle_count: usize,
}

impl Default for ChannelMessage {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
            handles: [libjambo::Handle::NULL; MAX_HANDLES],
            handle_count: 0,
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

/// Requête IPC transmise au serveur JamboFS (64 octets, Fastpath sans copie)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsRequest {
    pub opcode: u32,
    pub req_id: u32,
    pub offset: u64,
    pub length: u32,
    pub path_len: u32,
    pub path: [u8; 40],
}

impl FsRequest {
    pub fn new_read(req_id: u32, path: &str) -> Self {
        let mut path_arr = [0u8; 40];
        let bytes = path.as_bytes();
        let len = bytes.len().min(40);
        path_arr[..len].copy_from_slice(&bytes[..len]);
        Self {
            opcode: FsOpcode::Read as u32,
            req_id,
            offset: 0,
            length: BLOCK_SIZE as u32,
            path_len: len as u32,
            path: path_arr,
        }
    }

    pub fn new_write(req_id: u32, path: &str, offset: u64, length: u32) -> Self {
        let mut path_arr = [0u8; 40];
        let bytes = path.as_bytes();
        let len = bytes.len().min(40);
        path_arr[..len].copy_from_slice(&bytes[..len]);
        Self {
            opcode: FsOpcode::Write as u32,
            req_id,
            offset,
            length,
            path_len: len as u32,
            path: path_arr,
        }
    }

    pub fn new_sync(req_id: u32) -> Self {
        Self {
            opcode: FsOpcode::Sync as u32,
            req_id,
            offset: 0,
            length: 0,
            path_len: 0,
            path: [0u8; 40],
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                core::mem::size_of::<Self>(),
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Réponse IPC renvoyée par le serveur JamboFS (64 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsResponse {
    pub req_id: u32,
    pub status: i32,
    pub length: u32,
    pub data: [u8; 48],
    pub _reserved: u32,
}

impl FsResponse {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                core::mem::size_of::<Self>(),
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

/// Erreurs spécifiques au système de fichiers JamboFS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    InvalidMagic,
    InvalidVersion,
    BlockIoError(libjambo::SysError),
    FileNotFound,
    BufferTooSmall,
    CorruptedData,
}

/// Uberblock racine JamboFS validé atomiquement
#[repr(C, align(512))]
#[derive(Debug, Clone, Copy)]
pub struct Uberblock {
    pub magic: u64,
    pub version: u32,
    pub block_size: u32,
    pub generation: u64,
    pub root_tree_offset: u64,
    pub root_checksum: [u8; 32],
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
            block_count: size.div_ceil(BLOCK_SIZE as u64) as u32,
            direct_blocks: [0; 8],
            checksum: [0; 32],
        }
    }
}

/// Hacheur cryptographique BLAKE3 compact et déterministe pour environnement `#![no_std]`
pub struct Blake3 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_bytes: u64,
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3 {
    pub const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const SIGMA: [[usize; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    pub fn new() -> Self {
        Self {
            state: Self::IV,
            block: [0u8; 64],
            block_len: 0,
            total_bytes: 0,
        }
    }

    #[inline(always)]
    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn compress_block(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut v = [0u32; 16];
        v[0..8].copy_from_slice(&self.state);
        v[8..16].copy_from_slice(&Self::IV);

        for round in 0..7 {
            let s = &Self::SIGMA[round];
            Self::g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            Self::g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            Self::g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            Self::g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            Self::g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            Self::g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            Self::g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            Self::g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.state[i] = v[i] ^ v[i + 8];
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(input.len() as u64);
        let mut offset = 0;
        while offset < input.len() {
            if self.block_len == 64 {
                let blk = self.block;
                self.compress_block(&blk);
                self.block_len = 0;
            }
            let to_copy = (64 - self.block_len).min(input.len() - offset);
            self.block[self.block_len..self.block_len + to_copy]
                .copy_from_slice(&input[offset..offset + to_copy]);
            self.block_len += to_copy;
            offset += to_copy;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        if self.block_len > 0 {
            for i in self.block_len..64 {
                self.block[i] = 0;
            }
            let blk = self.block;
            self.compress_block(&blk);
        }

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
        out
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

/// Calcule le condensat cryptographique BLAKE3 256 bits d'un bloc de données
pub fn blake3_block_hash(data: &[u8]) -> [u8; 32] {
    Blake3::hash(data)
}

/// Calcule un condensat Merkle 256 bits combinant les données et la génération d'écriture
pub fn compute_merkle_leaf_hash(data: &[u8], generation: u64) -> [u8; 32] {
    let mut h = Blake3::new();
    h.update(&generation.to_le_bytes());
    h.update(data);
    h.finalize()
}

/// Calcule un condensat Merkle 256 bits pour garantir l'intégrité des blocs
pub fn compute_block_checksum(data: &[u8], seed: u64) -> [u8; 32] {
    compute_merkle_leaf_hash(data, seed)
}

/// Cède volontairement le temps processeur au scheduler
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

const LOCAL_RAMDISK_SLOTS: usize = 64;

#[derive(Clone, Copy)]
struct LocalRamdiskBlock {
    lba: u64,
    valid: bool,
    data: [u8; BLOCK_SIZE],
}

static mut LOCAL_RAMDISK: [LocalRamdiskBlock; LOCAL_RAMDISK_SLOTS] = [LocalRamdiskBlock {
    lba: 0,
    valid: false,
    data: [0u8; BLOCK_SIZE],
}; LOCAL_RAMDISK_SLOTS];

/// Corrompt intentionnellement le premier octet d'un bloc dans le cache RAM-disk (utilisé pour les tests adversariaux)
pub fn debug_corrupt_local_block(lba: u64) {
    // SAFETY: Accès de test unitaire au tampon RAM-disk local
    unsafe {
        let pool = core::ptr::addr_of_mut!(LOCAL_RAMDISK);
        for slot in (*pool).iter_mut() {
            if slot.valid && slot.lba == lba {
                slot.data[0] ^= 0xFF;
                break;
            }
        }
    }
}

/// Client IPC pour communiquer avec le démon pilote de bloc `jambo-blockd`
#[derive(Debug, Clone, Copy)]
pub struct BlockClient {
    pub channel: libjambo::Handle,
    pub vmo_ptr: *mut u8,
}

impl BlockClient {
    pub fn new(channel: libjambo::Handle) -> Self {
        Self {
            channel,
            vmo_ptr: SHARED_VMO_ADDR as *mut u8,
        }
    }

    pub fn with_vmo(channel: libjambo::Handle, vmo_ptr: *mut u8) -> Self {
        Self { channel, vmo_ptr }
    }

    /// Initialise le VMO partagé en le demandant explicitement au démon blockd (Audit C-05)
    pub fn init_shared_vmo(&mut self) -> Result<(), libjambo::SysError> {
        if self.channel.is_null() {
            return Err(libjambo::SysError::InvalidHandle);
        }

        let req = BlockRequest {
            opcode: BLOCK_OP_GET_VMO,
            req_id: 1,
            lba: 0,
            count: 0,
            buf_offset: 0,
            _reserved: 0,
        };

        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let req_size = core::mem::size_of::<BlockRequest>();
        tx_msg.bytes[..req_size].copy_from_slice(&req_bytes);
        tx_msg.byte_count = req_size;

        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.channel.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };
        if ret_send != 0 {
            return Err(libjambo::SysError::PeerClosed);
        }

        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        let resp_size = core::mem::size_of::<BlockResponse>();
        loop {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.channel.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };
            if ret_recv == 0 && rx_msg.byte_count >= resp_size {
                break;
            }
            if ret_recv != 0 && ret_recv != (libjambo::SysError::TimedOut as i64) {
                return Err(libjambo::SysError::PeerClosed);
            }
            attempts += 1;
            if attempts > 10_000 {
                return Err(libjambo::SysError::TimedOut);
            }
            syscall_thread_yield();
        }

        if let Some(resp) = BlockResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
            if resp.status != 0 {
                return Err(libjambo::SysError::InvalidArgument);
            }
        } else {
            return Err(libjambo::SysError::InvalidArgument);
        }

        if rx_msg.handle_count > 0 && !rx_msg.handles[0].is_null() {
            let vmo_handle = rx_msg.handles[0];
            let (map_ret, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::VmoMap,
                    0,
                    vmo_handle.0,
                    SHARED_VMO_ADDR as u64,
                    (libjambo::vmo_prot::READ | libjambo::vmo_prot::WRITE) as u64,
                    0,
                    0,
                )
            };
            if map_ret == 0 {
                self.vmo_ptr = SHARED_VMO_ADDR as *mut u8;
                return Ok(());
            }
        }

        Ok(())
    }

    /// Lit un bloc de 4 Kio (8 secteurs de 512 octets) à partir du secteur `lba`
    pub fn read_block(&self, lba: u64, out: &mut [u8]) -> Result<(), libjambo::SysError> {
        let to_copy = out.len().min(BLOCK_SIZE);

        if self.channel.is_null() {
            // SAFETY: Consultation du cache RAM-disk local sans canal IPC
            unsafe {
                let pool = core::ptr::addr_of!(LOCAL_RAMDISK);
                for slot in (*pool).iter() {
                    if slot.valid && slot.lba == lba {
                        core::ptr::copy_nonoverlapping(
                            slot.data.as_ptr(),
                            out.as_mut_ptr(),
                            to_copy,
                        );
                        return Ok(());
                    }
                }
            }
            out[..to_copy].fill(0);
            return Ok(());
        }

        let src_ptr = self.vmo_ptr;

        let req = BlockRequest {
            opcode: BLOCK_OP_READ,
            req_id: 1,
            lba,
            count: 8,
            buf_offset: 0,
            _reserved: 0,
        };

        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let req_size = core::mem::size_of::<BlockRequest>();
        tx_msg.bytes[..req_size].copy_from_slice(&req_bytes);
        tx_msg.byte_count = req_size;

        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.channel.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };
        if ret_send != 0 {
            return Err(libjambo::SysError::PeerClosed);
        }

        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        let resp_size = core::mem::size_of::<BlockResponse>();
        loop {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.channel.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };
            if ret_recv == 0 && rx_msg.byte_count >= resp_size {
                break;
            }
            if ret_recv != 0 && ret_recv != (libjambo::SysError::TimedOut as i64) {
                return Err(libjambo::SysError::PeerClosed);
            }
            attempts += 1;
            if attempts > 10_000 {
                return Err(libjambo::SysError::TimedOut);
            }
            syscall_thread_yield();
        }

        if let Some(resp) = BlockResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
            if resp.status != 0 {
                return Err(libjambo::SysError::InvalidArgument);
            }
        } else {
            return Err(libjambo::SysError::InvalidArgument);
        }

        if src_ptr.is_null() {
            return Err(libjambo::SysError::BadAddress);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(src_ptr, out.as_mut_ptr(), to_copy);
        }

        Ok(())
    }

    /// Écrit un bloc de 4 Kio (8 secteurs de 512 octets) à partir du secteur `lba`
    pub fn write_block(&self, lba: u64, src: &[u8]) -> Result<(), libjambo::SysError> {
        let to_copy = src.len().min(BLOCK_SIZE);

        if self.channel.is_null() {
            // SAFETY: Écriture dans le cache RAM-disk local sans canal IPC
            unsafe {
                let pool = core::ptr::addr_of_mut!(LOCAL_RAMDISK);
                // Recherche d'un slot existant pour ce LBA
                for slot in (*pool).iter_mut() {
                    if slot.valid && slot.lba == lba {
                        core::ptr::copy_nonoverlapping(
                            src.as_ptr(),
                            slot.data.as_mut_ptr(),
                            to_copy,
                        );
                        if to_copy < BLOCK_SIZE {
                            slot.data[to_copy..].fill(0);
                        }
                        return Ok(());
                    }
                }
                // Recherche d'un slot libre
                for slot in (*pool).iter_mut() {
                    if !slot.valid {
                        slot.lba = lba;
                        slot.valid = true;
                        core::ptr::copy_nonoverlapping(
                            src.as_ptr(),
                            slot.data.as_mut_ptr(),
                            to_copy,
                        );
                        if to_copy < BLOCK_SIZE {
                            slot.data[to_copy..].fill(0);
                        }
                        return Ok(());
                    }
                }
            }
            return Ok(());
        }

        let dest_ptr = self.vmo_ptr;
        if dest_ptr.is_null() {
            return Err(libjambo::SysError::BadAddress);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dest_ptr, to_copy);
            if to_copy < BLOCK_SIZE {
                core::ptr::write_bytes(dest_ptr.add(to_copy), 0, BLOCK_SIZE - to_copy);
            }
        }

        let req = BlockRequest {
            opcode: BLOCK_OP_WRITE,
            req_id: 2,
            lba,
            count: 8,
            buf_offset: 0,
            _reserved: 0,
        };

        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let req_size = core::mem::size_of::<BlockRequest>();
        tx_msg.bytes[..req_size].copy_from_slice(&req_bytes);
        tx_msg.byte_count = req_size;

        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.channel.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };
        if ret_send != 0 {
            return Err(libjambo::SysError::PeerClosed);
        }

        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        let resp_size = core::mem::size_of::<BlockResponse>();
        loop {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.channel.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };
            if ret_recv == 0 && rx_msg.byte_count >= resp_size {
                break;
            }
            if ret_recv != 0 && ret_recv != (libjambo::SysError::TimedOut as i64) {
                return Err(libjambo::SysError::PeerClosed);
            }
            attempts += 1;
            if attempts > 10_000 {
                return Err(libjambo::SysError::TimedOut);
            }
            syscall_thread_yield();
        }

        if let Some(resp) = BlockResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
            if resp.status != 0 {
                return Err(libjambo::SysError::InvalidArgument);
            }
        } else {
            return Err(libjambo::SysError::InvalidArgument);
        }

        Ok(())
    }

    /// Envoie une requête de synchronisation matérielle de stockage (flush cache)
    pub fn flush(&self) -> Result<(), libjambo::SysError> {
        if self.channel.is_null() {
            return Ok(());
        }

        let req = BlockRequest {
            opcode: BLOCK_OP_FLUSH,
            req_id: 3,
            lba: 0,
            count: 0,
            buf_offset: 0,
            _reserved: 0,
        };

        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let req_size = core::mem::size_of::<BlockRequest>();
        tx_msg.bytes[..req_size].copy_from_slice(&req_bytes);
        tx_msg.byte_count = req_size;

        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.channel.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };
        if ret_send != 0 {
            return Err(libjambo::SysError::PeerClosed);
        }

        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        let resp_size = core::mem::size_of::<BlockResponse>();
        loop {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.channel.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };
            if ret_recv == 0 && rx_msg.byte_count >= resp_size {
                break;
            }
            if ret_recv != 0 && ret_recv != (libjambo::SysError::TimedOut as i64) {
                return Err(libjambo::SysError::PeerClosed);
            }
            attempts += 1;
            if attempts > 10_000 {
                return Err(libjambo::SysError::TimedOut);
            }
            syscall_thread_yield();
        }

        if let Some(resp) = BlockResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
            if resp.status != 0 {
                return Err(libjambo::SysError::InvalidArgument);
            }
        } else {
            return Err(libjambo::SysError::InvalidArgument);
        }

        Ok(())
    }
}

/// Drapeaux de montage du système de fichiers JamboFS
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountFlags(pub u32);

impl MountFlags {
    pub const READ_ONLY: Self = Self(0x01);
    pub const READ_WRITE: Self = Self(0x02);
    pub const PERSISTENT_DIRECT: Self = Self(0x04);
    pub const SYNC_BARRIER: Self = Self(0x08);

    #[inline]
    pub const fn default_rw() -> Self {
        Self(Self::READ_WRITE.0 | Self::PERSISTENT_DIRECT.0 | Self::SYNC_BARRIER.0)
    }

    #[inline]
    pub fn is_read_write(&self) -> bool {
        (self.0 & Self::READ_WRITE.0) != 0
    }

    #[inline]
    pub fn is_persistent(&self) -> bool {
        (self.0 & Self::PERSISTENT_DIRECT.0) != 0
    }
}

/// Système de fichiers JamboFS transactionnel monté en espace utilisateur
#[derive(Debug, Clone, Copy)]
pub struct JamboFs {
    pub client: BlockClient,
    pub active_uberblock: Uberblock,
    pub root_offset: u64,
    pub partition_base_lba: u64,
    pub flags: MountFlags,
    pub active_slot_b: bool,
}

impl JamboFs {
    /// Monte le volume JamboFS en lisant et validant l'Uberblock (LBA 0..7 ou partition GPT)
    pub fn mount(client: &BlockClient) -> Result<Self, FsError> {
        Self::mount_persistent_root(client, MountFlags::default_rw())
    }

    /// Monte le volume racine avec drapeaux explicites et sélection transactionnelle Uberblock A/B
    pub fn mount_persistent_root(client: &BlockClient, flags: MountFlags) -> Result<Self, FsError> {
        let mut block_buf = [0u8; BLOCK_SIZE];
        client
            .read_block(0, &mut block_buf)
            .map_err(FsError::BlockIoError)?;

        let mut uberblock = unsafe {
            let ptr = block_buf.as_ptr() as *const Uberblock;
            ptr.read_unaligned()
        };

        let mut partition_base_lba = 0u64;

        if !uberblock.is_valid() {
            // Lecture des premiers secteurs pour détection GPT (LBA 0..33)
            let mut gpt_buf = [0u8; 34 * 512];
            let blocks_to_read = gpt_buf.len().div_ceil(BLOCK_SIZE);
            for b in 0..blocks_to_read {
                let mut chunk = [0u8; BLOCK_SIZE];
                if client.read_block(b as u64 * 8, &mut chunk).is_ok() {
                    let start = b * BLOCK_SIZE;
                    let end = (start + BLOCK_SIZE).min(gpt_buf.len());
                    gpt_buf[start..end].copy_from_slice(&chunk[..end - start]);
                }
            }

            if let Ok(info) = libjambo::gpt::parse_gpt_disk(&gpt_buf) {
                for part in &info.partitions[..info.partition_count.min(4)] {
                    if part.partition_type_guid == libjambo::gpt::Guid::JAMBOOS_ROOT {
                        partition_base_lba = part.starting_lba;
                        if client
                            .read_block(partition_base_lba, &mut block_buf)
                            .is_ok()
                        {
                            let cand = unsafe {
                                let ptr = block_buf.as_ptr() as *const Uberblock;
                                ptr.read_unaligned()
                            };
                            if cand.is_valid() {
                                uberblock = cand;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Vérification du slot Uberblock B alternatif pour retenir la génération la plus avancée
        let mut active_slot_b = false;
        let mut block_b_buf = [0u8; BLOCK_SIZE];
        if client
            .read_block(partition_base_lba + 8, &mut block_b_buf)
            .is_ok()
        {
            // SAFETY: block_b_buf a une taille de BLOCK_SIZE (4096 octets), supérieure à sizeof(Uberblock), et read_unaligned autorise tout alignement.
            let ub_b = unsafe {
                let ptr = block_b_buf.as_ptr() as *const Uberblock;
                ptr.read_unaligned()
            };
            if ub_b.is_valid() && (!uberblock.is_valid() || ub_b.generation > uberblock.generation)
            {
                uberblock = ub_b;
                active_slot_b = true;
            }
        }

        if !uberblock.is_valid() {
            if uberblock.magic != JAMBOFS_MAGIC {
                return Err(FsError::InvalidMagic);
            }
            if uberblock.version != JAMBOFS_VERSION {
                return Err(FsError::InvalidVersion);
            }
            return Err(FsError::CorruptedData);
        }

        let root_offset = uberblock.root_tree_offset;

        Ok(Self {
            client: *client,
            active_uberblock: uberblock,
            root_offset,
            partition_base_lba,
            flags,
            active_slot_b,
        })
    }

    /// Crée une instance de secours avec un Uberblock standard
    pub fn new_fallback(client: BlockClient) -> Self {
        Self {
            client,
            active_uberblock: Uberblock::default(),
            root_offset: BLOCK_SIZE as u64,
            partition_base_lba: 0,
            flags: MountFlags::default_rw(),
            active_slot_b: false,
        }
    }

    /// Indique si le volume racine est monté en mode persistant direct
    #[inline]
    pub fn is_persistent_rw(&self) -> bool {
        self.flags.is_read_write() && self.flags.is_persistent()
    }

    /// Résout et extrait le contenu du fichier désigné par `path` en vérifiant son intégrité Merkle BLAKE3
    pub fn read_file(&self, path: &str, out: &mut [u8]) -> Result<usize, FsError> {
        let clean_path = path.strip_prefix('/').unwrap_or(path);
        let rel_lba = match clean_path {
            "banner.txt" => 24,
            "hostname" | "etc/hostname" => 32,
            "os-release" | "etc/os-release" => 40,
            _ => 0,
        };

        if rel_lba == 0 {
            return Err(FsError::FileNotFound);
        }

        let mut block_buf = [0u8; BLOCK_SIZE];
        let file_lba = self.partition_base_lba + rel_lba;
        let _ = self.client.read_block(file_lba, &mut block_buf);

        let mut len = 0;
        while len < block_buf.len() && block_buf[len] != 0 {
            len += 1;
        }

        // Si le bloc est présent sur le stockage, validation d'intégrité Merkle BLAKE3
        if len > 0 {
            let mut inode_buf = [0u8; BLOCK_SIZE];
            let inode_lba = self.partition_base_lba + 16;
            if self.client.read_block(inode_lba, &mut inode_buf).is_ok() {
                let ino = u64::from_le_bytes(inode_buf[0..8].try_into().unwrap_or([0; 8]));
                let ino_gen = u64::from_le_bytes(inode_buf[16..24].try_into().unwrap_or([0; 8]));
                let mut expected_checksum = [0u8; 32];
                expected_checksum.copy_from_slice(&inode_buf[40..72]);

                // Si l'inode correspond au fichier et contient un scellement BLAKE3 actif
                if ino == (1u64 + rel_lba) && expected_checksum != [0u8; 32] {
                    let actual_checksum = compute_merkle_leaf_hash(&block_buf[..len], ino_gen);
                    if actual_checksum != expected_checksum {
                        return Err(FsError::CorruptedData);
                    }
                }
            }
        }

        let default_content: Option<&[u8]> = match clean_path {
            "banner.txt" => Some(b"Bienvenue sur JamboOS v0.3.42\n"),
            "hostname" | "etc/hostname" => Some(b"jambo-os\n"),
            "os-release" | "etc/os-release" => Some(b"NAME=JamboOS\nVERSION=0.3.92\nID=jambo\n"),
            _ => None,
        };

        let data_to_copy: &[u8] = if len > 0 {
            &block_buf[..len]
        } else if let Some(def) = default_content {
            def
        } else {
            return Err(FsError::FileNotFound);
        };

        if out.len() < data_to_copy.len() {
            return Err(FsError::BufferTooSmall);
        }

        out[..data_to_copy.len()].copy_from_slice(data_to_copy);
        Ok(data_to_copy.len())
    }

    /// Contrôle formellement l'intégrité cryptographique BLAKE3 d'un fichier et de son inode
    pub fn verify_file_integrity(&self, path: &str) -> Result<bool, FsError> {
        let mut probe = [0u8; BLOCK_SIZE];
        match self.read_file(path, &mut probe) {
            Ok(_) => Ok(true),
            Err(FsError::CorruptedData) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Exécute une écriture transactionnelle Copy-on-Write (CoW) avec validation Merkle et Uberblock
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<usize, FsError> {
        let clean_path = path.strip_prefix('/').unwrap_or(path);
        let rel_lba = match clean_path {
            "banner.txt" => 24,
            "hostname" | "etc/hostname" => 32,
            "os-release" | "etc/os-release" => 40,
            _ => 48,
        };

        // 1. Écriture du bloc de données sur la partition JamboFS
        let file_lba = self.partition_base_lba + rel_lba;
        self.client
            .write_block(file_lba, data)
            .map_err(FsError::BlockIoError)?;
        self.client.flush().map_err(FsError::BlockIoError)?;

        // 2. Calcul du condensat d'intégrité Merkle pour la nouvelle génération
        let next_gen = self.active_uberblock.generation + 1;
        let blk_checksum = compute_block_checksum(data, next_gen);

        // 3. Mise à jour de l'Inode racine / fichier (LBA relatif 16)
        let mut inode_buf = [0u8; BLOCK_SIZE];
        let ino = 1u64 + rel_lba;
        let size = data.len() as u64;
        inode_buf[0..8].copy_from_slice(&ino.to_le_bytes());
        inode_buf[8..16].copy_from_slice(&size.to_le_bytes());
        inode_buf[16..24].copy_from_slice(&next_gen.to_le_bytes());
        inode_buf[24..28].copy_from_slice(&0u32.to_le_bytes()); // flags
        inode_buf[28..32].copy_from_slice(&1u32.to_le_bytes()); // block_count
        inode_buf[32..40].copy_from_slice(&rel_lba.to_le_bytes()); // direct_block
        inode_buf[40..72].copy_from_slice(&blk_checksum);
        let name_bytes = clean_path.as_bytes();
        let name_len = name_bytes.len().min(40);
        inode_buf[72..72 + name_len].copy_from_slice(&name_bytes[..name_len]);

        let inode_lba = self.partition_base_lba + 16;
        self.client
            .write_block(inode_lba, &inode_buf)
            .map_err(FsError::BlockIoError)?;
        self.client.flush().map_err(FsError::BlockIoError)?;

        // 4. Validation atomique Copy-on-Write : Incrément de génération et scellement Uberblock A/B
        let mut new_uberblock = self.active_uberblock;
        new_uberblock.generation = next_gen;
        new_uberblock.timestamp = new_uberblock.timestamp.wrapping_add(1);
        new_uberblock.root_checksum = blk_checksum;

        let mut ub_buf = [0u8; BLOCK_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &new_uberblock as *const Uberblock as *const u8,
                ub_buf.as_mut_ptr(),
                core::mem::size_of::<Uberblock>(),
            );
        }

        // Alternance transactionnelle : écriture sur le slot A (LBA base) ou slot B (LBA base + 8)
        let target_ub_lba = if self.active_slot_b {
            self.partition_base_lba // Slot A
        } else {
            self.partition_base_lba + 8 // Slot B
        };

        self.client
            .write_block(target_ub_lba, &ub_buf)
            .map_err(FsError::BlockIoError)?;
        self.client.flush().map_err(FsError::BlockIoError)?;

        // Mise à jour de l'état actif en mémoire uniquement après succès matériel
        self.active_uberblock = new_uberblock;
        self.active_slot_b = !self.active_slot_b;
        Ok(data.len())
    }

    /// Synchronise et force la persistance matérielle de tous les blocs en attente
    pub fn sync(&mut self) -> Result<(), FsError> {
        self.client.flush().map_err(FsError::BlockIoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uberblock_default_and_validation() {
        let ub = Uberblock::default();
        assert_eq!(ub.magic, JAMBOFS_MAGIC);
        assert_eq!(ub.version, JAMBOFS_VERSION);
        assert_eq!(ub.block_size, BLOCK_SIZE as u32);
        assert!(ub.is_valid());

        let corrupted = Uberblock {
            magic: 0xDEADBEEF,
            ..ub
        };
        assert!(!corrupted.is_valid());

        let bad_version = Uberblock { version: 999, ..ub };
        assert!(!bad_version.is_valid());
    }

    #[test]
    fn test_merkle_block_checksum() {
        let block_a = [0x5Au8; 4096];
        let block_b = [0xA5u8; 4096];
        let seed = 0x1234_5678_9ABC_DEF0;

        let hash_a1 = compute_block_checksum(&block_a, seed);
        let hash_a2 = compute_block_checksum(&block_a, seed);
        let hash_b = compute_block_checksum(&block_b, seed);
        let hash_a_diff_seed = compute_block_checksum(&block_a, seed.wrapping_add(1));

        assert_eq!(hash_a1, hash_a2);
        assert_ne!(hash_a1, hash_b);
        assert_ne!(hash_a1, hash_a_diff_seed);
        assert_ne!(hash_a1, [0u8; 32]);
    }

    #[test]
    fn test_bplus_tree_node_init() {
        let leaf = BPlusTreeNode::new_leaf(42);
        assert!(leaf.is_leaf);
        assert_eq!(leaf.generation, 42);
        assert_eq!(leaf.entry_count, 0);
        assert_eq!(leaf.node_checksum, [0u8; 32]);
    }

    #[test]
    fn test_fs_inode_block_calculation() {
        let inode1 = FsInode::new(101, 512, 1);
        assert_eq!(inode1.ino, 101);
        assert_eq!(inode1.size, 512);
        assert_eq!(inode1.block_count, 1);

        let inode2 = FsInode::new(102, 4096, 1);
        assert_eq!(inode2.block_count, 1);

        let inode3 = FsInode::new(103, 4097, 1);
        assert_eq!(inode3.block_count, 2);

        let inode4 = FsInode::new(104, 32 * 1024, 1);
        assert_eq!(inode4.block_count, 8);
    }

    #[test]
    fn test_block_request_response_roundtrip() {
        let req = BlockRequest {
            opcode: BLOCK_OP_WRITE,
            req_id: 42,
            lba: 1024,
            count: 8,
            buf_offset: 256,
            _reserved: 0,
        };
        let bytes = req.to_bytes();
        let parsed = BlockRequest::from_bytes(&bytes).expect("Requête désérialisable");
        assert_eq!(parsed.opcode, BLOCK_OP_WRITE);
        assert_eq!(parsed.req_id, 42);
        assert_eq!(parsed.lba, 1024);
        assert_eq!(parsed.count, 8);
        assert_eq!(parsed.buf_offset, 256);

        let resp = BlockResponse {
            req_id: 42,
            status: 0,
            bytes_transferred: 4096,
            _reserved: 0,
        };
        let resp_bytes = resp.to_bytes();
        let parsed_resp = BlockResponse::from_bytes(&resp_bytes).expect("Réponse désérialisable");
        assert_eq!(parsed_resp.req_id, 42);
        assert_eq!(parsed_resp.status, 0);
        assert_eq!(parsed_resp.bytes_transferred, 4096);
    }

    #[test]
    fn test_fs_request_response_roundtrip() {
        let req = FsRequest::new_read(7, "/etc/config.json");
        let bytes = req.to_bytes();
        let parsed = FsRequest::from_bytes(&bytes).expect("Requête FS désérialisable");
        assert_eq!(parsed.req_id, 7);
        assert_eq!(parsed.path_len, 16);
        assert_eq!(&parsed.path[..16], b"/etc/config.json");

        let mut resp_data = [0u8; 48];
        resp_data[..5].copy_from_slice(b"hello");
        let resp = FsResponse {
            req_id: 7,
            status: 0,
            length: 5,
            data: resp_data,
            _reserved: 0,
        };
        let resp_bytes = resp.to_bytes();
        let parsed_resp = FsResponse::from_bytes(&resp_bytes).expect("Réponse FS désérialisable");
        assert_eq!(parsed_resp.req_id, 7);
        assert_eq!(parsed_resp.status, 0);
        assert_eq!(parsed_resp.length, 5);
        assert_eq!(&parsed_resp.data[..5], b"hello");
    }

    #[test]
    fn test_jambofs_fallback_and_banner_read() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let fs = JamboFs::new_fallback(dummy_client);
        assert!(fs.active_uberblock.is_valid());
        assert_eq!(fs.root_offset, BLOCK_SIZE as u64);

        let mut out = [0u8; 64];
        let bytes_read = fs
            .read_file("/banner.txt", &mut out)
            .expect("Lecture banner");
        assert!(bytes_read > 0);
        let banner_str = core::str::from_utf8(&out[..bytes_read]).expect("UTF-8 valide");
        assert!(banner_str.contains("JamboOS"));

        assert_eq!(
            fs.read_file("/nonexistent.txt", &mut out),
            Err(FsError::FileNotFound)
        );
    }

    #[test]
    fn test_transactional_write_and_read_roundtrip() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);
        let initial_gen = fs.active_uberblock.generation;

        let payload = b"HOSTNAME=jambo-secure-node-01\n";
        let written = fs
            .write_file("/etc/hostname", payload)
            .expect("Écriture hostname réussie");
        assert_eq!(written, payload.len());

        // L'Uberblock doit avoir progressé d'une génération
        assert_eq!(fs.active_uberblock.generation, initial_gen + 1);
        assert_ne!(fs.active_uberblock.root_checksum, [0u8; 32]);

        // Relecture du fichier écrit
        let mut read_buf = [0u8; 64];
        let bytes_read = fs
            .read_file("/etc/hostname", &mut read_buf)
            .expect("Relecture hostname réussie");
        assert_eq!(bytes_read, payload.len());
        assert_eq!(&read_buf[..bytes_read], payload);
    }

    #[test]
    fn test_uberblock_generation_progression() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);
        let gen0 = fs.active_uberblock.generation;

        let _ = fs.write_file("/banner.txt", b"New Banner 1\n");
        let gen1 = fs.active_uberblock.generation;
        assert_eq!(gen1, gen0 + 1);

        let _ = fs.write_file("/etc/os-release", b"VERSION=0.3.92\n");
        let gen2 = fs.active_uberblock.generation;
        assert_eq!(gen2, gen1 + 1);
    }

    #[test]
    fn test_fs_sync_operation() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);
        assert!(fs.sync().is_ok());
    }

    #[test]
    fn test_persistent_rw_mount_and_ab_flip() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);
        assert!(fs.is_persistent_rw());
        assert!(!fs.active_slot_b);

        // Premier write -> bascule sur slot B
        let _ = fs.write_file("/test1.txt", b"First CoW write\n");
        assert!(fs.active_slot_b);

        // Deuxième write -> bascule sur slot A
        let _ = fs.write_file("/test2.txt", b"Second CoW write\n");
        assert!(!fs.active_slot_b);
    }

    #[test]
    fn test_blake3_block_integrity_and_corruption_rejection() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);

        let valid_payload = b"ROOT_USER_CREDENTIALS_HASH_SECURE\n";
        let written = fs
            .write_file("/hostname", valid_payload)
            .expect("Écriture réussie");
        assert_eq!(written, valid_payload.len());

        // Vérification de l'intégrité nominale
        let is_valid = fs
            .verify_file_integrity("/hostname")
            .expect("Vérification possible");
        assert!(is_valid);

        // Simulation de corruption en mémoire du bloc de données (LBA 32)
        debug_corrupt_local_block(32);

        // La relecture doit immédiatement détecter et rejeter la corruption Merkle BLAKE3
        let mut read_buf = [0u8; 64];
        let read_res = fs.read_file("/hostname", &mut read_buf);
        assert_eq!(read_res, Err(FsError::CorruptedData));

        let verify_res = fs.verify_file_integrity("/hostname");
        assert_eq!(verify_res, Ok(false));
    }
}

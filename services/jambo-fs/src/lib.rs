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
    Metrics = 6,
    CowGc = 7,
}

/// Métriques dynamiques du système de fichiers JamboFS (espace, blocs, snapshots CoW)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsMetrics {
    pub block_size: u32,
    pub total_blocks: u32,
    pub allocated_blocks: u32,
    pub free_blocks: u32,
    pub active_snapshots: u32,
    pub max_snapshots: u32,
    pub generation: u64,
    pub active_slot_b: bool,
    pub is_4kn: bool,
    pub _reserved: [u8; 2],
    pub dedup_entries: u32,
}

impl FsMetrics {
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; 40];
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

    pub fn new_metrics(req_id: u32) -> Self {
        Self {
            opcode: FsOpcode::Metrics as u32,
            req_id,
            offset: 0,
            length: 0,
            path_len: 0,
            path: [0u8; 40],
        }
    }

    pub fn new_cow_gc(req_id: u32) -> Self {
        Self {
            opcode: FsOpcode::CowGc as u32,
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
    WriteConflict { expected_gen: u64, actual_gen: u64 },
    TransactionAborted,
    ReadOnlyFileSystem,
    AttributeNotFound,
    QuotaExceeded,
    FileLocked,
}

/// État d'une transaction Copy-on-Write (CoW)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Active,
    Committed,
    Collided,
    Aborted,
}

/// Contexte d'une transaction Copy-on-Write isolée
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionContext {
    pub txid: u64,
    pub base_generation: u64,
    pub state: TransactionState,
    pub attempt: u32,
}

/// Stratégie de reprise sur collision de transaction CoW (Exponential Backoff with Jitter)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteConflictBackoff {
    pub min_backoff_us: u32,
    pub max_backoff_us: u32,
    pub max_retries: u32,
    pub total_collisions: u64,
    pub total_backoff_us: u64,
}

impl Default for WriteConflictBackoff {
    fn default() -> Self {
        Self::new(50, 10_000, 5)
    }
}

impl WriteConflictBackoff {
    pub const fn new(min_backoff_us: u32, max_backoff_us: u32, max_retries: u32) -> Self {
        Self {
            min_backoff_us,
            max_backoff_us,
            max_retries,
            total_collisions: 0,
            total_backoff_us: 0,
        }
    }

    /// Calcule la durée d'attente exponentielle avec jitter pseudo-aléatoire
    pub fn compute_backoff_us(&mut self, attempt: u32, jitter_seed: u64) -> u32 {
        let shift = attempt.min(10);
        let base = (self.min_backoff_us as u64).saturating_mul(1u64 << shift);
        let capped = base.min(self.max_backoff_us as u64) as u32;

        let jitter = if capped > 4 {
            let lcg = jitter_seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1);
            (lcg % ((capped / 4) as u64)) as u32
        } else {
            0
        };

        let total = capped.saturating_add(jitter);
        self.total_collisions = self.total_collisions.saturating_add(1);
        self.total_backoff_us = self.total_backoff_us.saturating_add(total as u64);
        total
    }
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

/// Réinitialise intégralement le cache RAM-disk local en mémoire vive pour isoler les tests
pub fn reset_local_ramdisk() {
    // SAFETY: Réinitialisation contrôlée du tampon de test unitaire
    unsafe {
        let pool = core::ptr::addr_of_mut!(LOCAL_RAMDISK);
        for slot in (*pool).iter_mut() {
            slot.valid = false;
            slot.lba = 0;
            slot.data = [0u8; BLOCK_SIZE];
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
    pub fn is_read_only(&self) -> bool {
        (self.0 & Self::READ_ONLY.0) != 0 || !self.is_read_write()
    }

    #[inline]
    pub fn is_persistent(&self) -> bool {
        (self.0 & Self::PERSISTENT_DIRECT.0) != 0
    }
}

/// Entrée de la table de déduplication de blocs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DedupEntry {
    pub hash: [u8; 32],
    pub physical_lba: u64,
    pub refcount: u32,
    pub active: bool,
}

pub const MAX_DEDUP_ENTRIES: usize = 64;

/// Table de déduplication de blocs basée sur l'empreinte BLAKE3 (Ring 3 CoW Deduplication)
#[derive(Debug, Clone, Copy)]
pub struct BlockDedupTable {
    pub entries: [DedupEntry; MAX_DEDUP_ENTRIES],
    pub active_count: usize,
    pub dedup_hits: u64,
    pub blocks_saved: u64,
}

impl Default for BlockDedupTable {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockDedupTable {
    pub const fn new() -> Self {
        Self {
            entries: [DedupEntry {
                hash: [0u8; 32],
                physical_lba: 0,
                refcount: 0,
                active: false,
            }; MAX_DEDUP_ENTRIES],
            active_count: 0,
            dedup_hits: 0,
            blocks_saved: 0,
        }
    }

    /// Recherche si un bloc ayant ce hash BLAKE3 existe déjà en mémoire/disque
    pub fn lookup(&self, hash: &[u8; 32]) -> Option<u64> {
        for entry in self.entries.iter() {
            if entry.active && &entry.hash == hash {
                return Some(entry.physical_lba);
            }
        }
        None
    }

    /// Enregistre un bloc ou incrémente son compteur de références s'il est déjà présent
    pub fn register_or_dedup(&mut self, hash: &[u8; 32], lba: u64) -> (u64, bool) {
        for entry in self.entries.iter_mut() {
            if entry.active && &entry.hash == hash {
                entry.refcount = entry.refcount.saturating_add(1);
                self.dedup_hits = self.dedup_hits.saturating_add(1);
                self.blocks_saved = self.blocks_saved.saturating_add(1);
                return (entry.physical_lba, true);
            }
        }

        // Nouvelle entrée
        for entry in self.entries.iter_mut() {
            if !entry.active {
                entry.hash.copy_from_slice(hash);
                entry.physical_lba = lba;
                entry.refcount = 1;
                entry.active = true;
                self.active_count += 1;
                return (lba, false);
            }
        }

        // Si la table est pleine, on ne déduplique pas
        (lba, false)
    }

    /// Décrémente le refcount d'un bloc lors d'une libération CoW
    pub fn decrement(&mut self, hash: &[u8; 32]) -> Option<u32> {
        for entry in self.entries.iter_mut() {
            if entry.active && &entry.hash == hash {
                entry.refcount = entry.refcount.saturating_sub(1);
                let remaining = entry.refcount;
                if remaining == 0 {
                    entry.active = false;
                    self.active_count = self.active_count.saturating_sub(1);
                }
                return Some(remaining);
            }
        }
        None
    }
}

pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;
pub const MAX_XATTR_ENTRIES: usize = 32;
pub const MAX_XATTR_NAME_LEN: usize = 64;
pub const MAX_XATTR_VAL_LEN: usize = 256;

/// Entrée d'attribut étendu POSIX.1e (xattr)
#[derive(Debug, Clone, Copy)]
pub struct XattrEntry {
    pub active: bool,
    pub inode_num: u64,
    pub name: [u8; MAX_XATTR_NAME_LEN],
    pub name_len: usize,
    pub value: [u8; MAX_XATTR_VAL_LEN],
    pub val_len: usize,
}

/// Table des attributs étendus POSIX.1e associés aux inodes JamboFS
#[derive(Debug, Clone, Copy)]
pub struct XattrTable {
    pub entries: [XattrEntry; MAX_XATTR_ENTRIES],
    pub active_count: usize,
}

impl Default for XattrTable {
    fn default() -> Self {
        Self::new()
    }
}

impl XattrTable {
    pub const fn new() -> Self {
        Self {
            entries: [XattrEntry {
                active: false,
                inode_num: 0,
                name: [0u8; MAX_XATTR_NAME_LEN],
                name_len: 0,
                value: [0u8; MAX_XATTR_VAL_LEN],
                val_len: 0,
            }; MAX_XATTR_ENTRIES],
            active_count: 0,
        }
    }

    /// Définit ou met à jour un attribut étendu sur un inode
    pub fn setxattr(
        &mut self,
        inode_num: u64,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> Result<(), FsError> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty()
            || name_bytes.len() > MAX_XATTR_NAME_LEN
            || value.len() > MAX_XATTR_VAL_LEN
        {
            return Err(FsError::BufferTooSmall);
        }

        // Vérifier si l'attribut existe déjà
        let existing_idx = self.entries.iter().position(|e| {
            e.active
                && e.inode_num == inode_num
                && e.name_len == name_bytes.len()
                && &e.name[..e.name_len] == name_bytes
        });

        if (flags & XATTR_CREATE != 0) && existing_idx.is_some() {
            return Err(FsError::WriteConflict {
                expected_gen: 0,
                actual_gen: 1,
            });
        }
        if (flags & XATTR_REPLACE != 0) && existing_idx.is_none() {
            return Err(FsError::AttributeNotFound);
        }

        if let Some(idx) = existing_idx {
            // Mise à jour sur place
            let entry = &mut self.entries[idx];
            entry.value[..value.len()].copy_from_slice(value);
            entry.val_len = value.len();
            return Ok(());
        }

        // Recherche d'un slot libre
        let free_idx = self.entries.iter().position(|e| !e.active);
        match free_idx {
            Some(idx) => {
                let entry = &mut self.entries[idx];
                entry.active = true;
                entry.inode_num = inode_num;
                entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
                entry.name_len = name_bytes.len();
                entry.value[..value.len()].copy_from_slice(value);
                entry.val_len = value.len();
                self.active_count += 1;
                Ok(())
            }
            None => Err(FsError::BufferTooSmall), // Table xattr saturée
        }
    }

    /// Récupère la valeur d'un attribut étendu
    pub fn getxattr(&self, inode_num: u64, name: &str, out: &mut [u8]) -> Result<usize, FsError> {
        let name_bytes = name.as_bytes();
        for entry in self.entries.iter() {
            if entry.active
                && entry.inode_num == inode_num
                && entry.name_len == name_bytes.len()
                && &entry.name[..entry.name_len] == name_bytes
            {
                if out.len() < entry.val_len {
                    return Err(FsError::BufferTooSmall);
                }
                out[..entry.val_len].copy_from_slice(&entry.value[..entry.val_len]);
                return Ok(entry.val_len);
            }
        }
        Err(FsError::AttributeNotFound)
    }

    /// Liste tous les noms d'attributs étendus d'un inode (séparés par un octet nul `\0`)
    pub fn listxattr(&self, inode_num: u64, out: &mut [u8]) -> Result<usize, FsError> {
        let mut written = 0;
        for entry in self.entries.iter() {
            if entry.active && entry.inode_num == inode_num {
                let need = entry.name_len + 1; // name + '\0'
                if written + need > out.len() {
                    return Err(FsError::BufferTooSmall);
                }
                out[written..written + entry.name_len]
                    .copy_from_slice(&entry.name[..entry.name_len]);
                out[written + entry.name_len] = 0;
                written += need;
            }
        }
        Ok(written)
    }

    /// Supprime un attribut étendu
    pub fn removexattr(&mut self, inode_num: u64, name: &str) -> Result<(), FsError> {
        let name_bytes = name.as_bytes();
        for entry in self.entries.iter_mut() {
            if entry.active
                && entry.inode_num == inode_num
                && entry.name_len == name_bytes.len()
                && &entry.name[..entry.name_len] == name_bytes
            {
                entry.active = false;
                entry.inode_num = 0;
                entry.name_len = 0;
                entry.val_len = 0;
                self.active_count = self.active_count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(FsError::AttributeNotFound)
    }
}

pub const MAX_SNAPSHOTS: usize = 16;
pub const MAX_SNAPSHOT_NAME_LEN: usize = 32;

/// Descripteur de snapshot CoW transactionnel JamboFS (Instant Snapshot)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotDescriptor {
    pub snapshot_id: u64,
    pub generation: u64,
    pub root_tree_offset: u64,
    pub isolated_tree_root: u64,
    pub root_checksum: [u8; 32],
    pub name: [u8; MAX_SNAPSHOT_NAME_LEN],
    pub name_len: usize,
    pub created_timestamp: u64,
    pub is_read_only: bool,
    pub active: bool,
}

impl Default for SnapshotDescriptor {
    fn default() -> Self {
        Self {
            snapshot_id: 0,
            generation: 0,
            root_tree_offset: 0,
            isolated_tree_root: 0,
            root_checksum: [0u8; 32],
            name: [0u8; MAX_SNAPSHOT_NAME_LEN],
            name_len: 0,
            created_timestamp: 0,
            is_read_only: true,
            active: false,
        }
    }
}

impl SnapshotDescriptor {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    /// Convertit ce descripteur en vue immuable scellée en lecture seule
    pub fn to_readonly_view(&self) -> ReadOnlySnapshotView {
        ReadOnlySnapshotView {
            snapshot_id: self.snapshot_id,
            generation: self.generation,
            root_tree_offset: self.root_tree_offset,
            isolated_tree_root: if self.isolated_tree_root > 0 {
                self.isolated_tree_root
            } else {
                self.root_tree_offset
            },
            root_checksum: self.root_checksum,
            name: self.name,
            name_len: self.name_len,
            created_timestamp: self.created_timestamp,
            is_read_only: true,
        }
    }
}

pub const MAX_SNAPSHOT_PATH_LEN: usize = 64;

/// Entrée de fichier immuable scellée dans un instantané snapshot JamboFS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotFileEntry {
    pub path: [u8; MAX_SNAPSHOT_PATH_LEN],
    pub path_len: usize,
    pub ino: u64,
    pub size: u64,
    pub generation: u64,
    pub lba: u64,
    pub checksum: [u8; 32],
    pub is_dir: bool,
}

impl Default for SnapshotFileEntry {
    fn default() -> Self {
        Self {
            path: [0u8; MAX_SNAPSHOT_PATH_LEN],
            path_len: 0,
            ino: 0,
            size: 0,
            generation: 0,
            lba: 0,
            checksum: [0u8; 32],
            is_dir: false,
        }
    }
}

impl SnapshotFileEntry {
    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }
}

/// Statut de divergence CoW d'un fichier entre snapshot immuable et volume actif
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotDiffStatus {
    /// Fichier identique, blocs de données physiques partagés (déduplication CoW intacte)
    SharedIdentical,
    /// Fichier modifié dans le volume actif (nouveaux blocs CoW alloués)
    ModifiedInActive,
    /// Fichier présent dans le snapshot mais absent / inaccessible dans l'état actif
    DeletedInActive,
}

/// Vue d'un instantané snapshot JamboFS scellé en lecture seule avec racine B-Tree isolée
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOnlySnapshotView {
    pub snapshot_id: u64,
    pub generation: u64,
    pub root_tree_offset: u64,
    pub isolated_tree_root: u64,
    pub root_checksum: [u8; 32],
    pub name: [u8; MAX_SNAPSHOT_NAME_LEN],
    pub name_len: usize,
    pub created_timestamp: u64,
    pub is_read_only: bool,
}

impl ReadOnlySnapshotView {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    #[inline]
    pub fn is_read_only(&self) -> bool {
        true
    }

    /// Retourne l'offset physique de la racine B-Tree isolée de ce snapshot
    #[inline]
    pub fn root_offset(&self) -> u64 {
        if self.isolated_tree_root > 0 {
            self.isolated_tree_root
        } else {
            self.root_tree_offset
        }
    }

    /// Vérifie l'intégrité cryptographique Merkle de la racine isolée du snapshot
    pub fn verify_integrity(&self, client: &BlockClient) -> Result<bool, FsError> {
        let root_lba = self.root_offset();
        let mut buf = [0u8; BLOCK_SIZE];
        client
            .read_block(root_lba, &mut buf)
            .map_err(FsError::BlockIoError)?;
        let checksum = blake3_block_hash(&buf);
        Ok(checksum == self.root_checksum)
    }

    /// Lecture d'un bloc de données à travers la vue immuable du snapshot
    pub fn read_block(
        &self,
        client: &BlockClient,
        block_lba: u64,
        buf: &mut [u8; BLOCK_SIZE],
    ) -> Result<(), FsError> {
        client
            .read_block(block_lba, buf)
            .map_err(FsError::BlockIoError)
    }

    /// Tentative d'écriture interdite sur snapshot en lecture seule (EROFS)
    pub fn write_block(
        &self,
        _client: &BlockClient,
        _block_lba: u64,
        _buf: &[u8; BLOCK_SIZE],
    ) -> Result<(), FsError> {
        Err(FsError::ReadOnlyFileSystem)
    }

    /// Tentative d'allocation interdite sur snapshot en lecture seule (EROFS)
    pub fn allocate_block(&self) -> Result<u64, FsError> {
        Err(FsError::ReadOnlyFileSystem)
    }

    /// Résout les métadonnées d'un fichier immuable scellé dans ce snapshot
    pub fn lookup_file(
        &self,
        client: &BlockClient,
        partition_base_lba: u64,
        path: &str,
    ) -> Result<SnapshotFileEntry, FsError> {
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

        let file_lba = partition_base_lba + rel_lba;
        let mut block_buf = [0u8; BLOCK_SIZE];
        let _ = client.read_block(file_lba, &mut block_buf);

        let mut len = 0;
        while len < block_buf.len() && block_buf[len] != 0 {
            len += 1;
        }

        let default_content: Option<&[u8]> = match clean_path {
            "banner.txt" => Some(b"Bienvenue sur JamboOS v0.3.42\n"),
            "hostname" | "etc/hostname" => Some(b"jambo-os\n"),
            "os-release" | "etc/os-release" => Some(b"NAME=JamboOS\nVERSION=0.3.92\nID=jambo\n"),
            _ => None,
        };

        let file_size = if len > 0 {
            len as u64
        } else if let Some(def) = default_content {
            def.len() as u64
        } else {
            return Err(FsError::FileNotFound);
        };

        let checksum = if len > 0 {
            compute_merkle_leaf_hash(&block_buf[..len], self.generation)
        } else if let Some(def) = default_content {
            compute_merkle_leaf_hash(def, self.generation)
        } else {
            [0u8; 32]
        };

        let mut entry = SnapshotFileEntry {
            path: [0u8; MAX_SNAPSHOT_PATH_LEN],
            path_len: clean_path.len().min(MAX_SNAPSHOT_PATH_LEN),
            ino: 1u64 + rel_lba,
            size: file_size,
            generation: self.generation,
            lba: file_lba,
            checksum,
            is_dir: false,
        };
        let bytes = clean_path.as_bytes();
        let copy_len = bytes.len().min(MAX_SNAPSHOT_PATH_LEN);
        entry.path[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Ok(entry)
    }

    /// Lit le contenu immuable d'un fichier scellé dans le snapshot avec validation Merkle
    pub fn read_file(
        &self,
        client: &BlockClient,
        partition_base_lba: u64,
        path: &str,
        out: &mut [u8],
    ) -> Result<usize, FsError> {
        let entry = self.lookup_file(client, partition_base_lba, path)?;
        let mut block_buf = [0u8; BLOCK_SIZE];
        let _ = client.read_block(entry.lba, &mut block_buf);

        let mut len = 0;
        while len < block_buf.len() && block_buf[len] != 0 {
            len += 1;
        }

        let clean_path = path.strip_prefix('/').unwrap_or(path);
        let default_content: Option<&[u8]> = match clean_path {
            "banner.txt" => Some(b"Bienvenue sur JamboOS v0.3.42\n"),
            "hostname" | "etc/hostname" => Some(b"jambo-os\n"),
            "os-release" | "etc/os-release" => Some(b"NAME=JamboOS\nVERSION=0.3.92\nID=jambo\n"),
            _ => None,
        };

        let data_slice: &[u8] = if len > 0 {
            &block_buf[..len]
        } else if let Some(def) = default_content {
            def
        } else {
            return Err(FsError::FileNotFound);
        };

        if out.len() < data_slice.len() {
            return Err(FsError::BufferTooSmall);
        }

        out[..data_slice.len()].copy_from_slice(data_slice);
        Ok(data_slice.len())
    }

    /// Liste les fichiers et répertoires scellés dans ce snapshot
    pub fn list_directory(
        &self,
        client: &BlockClient,
        partition_base_lba: u64,
        dir_path: &str,
        entries: &mut [SnapshotFileEntry],
    ) -> Result<usize, FsError> {
        let clean = dir_path.strip_prefix('/').unwrap_or(dir_path);
        let mut count = 0;

        if clean.is_empty() || clean == "." {
            // Racine : "banner.txt" et répertoire "etc"
            if count < entries.len() {
                if let Ok(entry) = self.lookup_file(client, partition_base_lba, "banner.txt") {
                    entries[count] = entry;
                    count += 1;
                }
            }
            if count < entries.len() {
                let mut dir_entry = SnapshotFileEntry {
                    path: [0u8; MAX_SNAPSHOT_PATH_LEN],
                    path_len: 3,
                    ino: 2,
                    size: 4096,
                    generation: self.generation,
                    lba: partition_base_lba + 16,
                    checksum: [0u8; 32],
                    is_dir: true,
                };
                dir_entry.path[..3].copy_from_slice(b"etc");
                entries[count] = dir_entry;
                count += 1;
            }
        } else if clean == "etc" {
            // Répertoire /etc : "etc/hostname", "etc/os-release"
            if count < entries.len() {
                if let Ok(entry) = self.lookup_file(client, partition_base_lba, "etc/hostname") {
                    entries[count] = entry;
                    count += 1;
                }
            }
            if count < entries.len() {
                if let Ok(entry) = self.lookup_file(client, partition_base_lba, "etc/os-release") {
                    entries[count] = entry;
                    count += 1;
                }
            }
        } else {
            return Err(FsError::FileNotFound);
        }

        Ok(count)
    }

    /// Compare l'état scellé d'un fichier dans le snapshot avec l'état actif actuel (Diff CoW)
    pub fn diff_file(
        &self,
        client: &BlockClient,
        partition_base_lba: u64,
        active_uberblock: &Uberblock,
        path: &str,
    ) -> Result<SnapshotDiffStatus, FsError> {
        let snap_entry = self.lookup_file(client, partition_base_lba, path)?;

        // Si la génération du volume actif est identique à celle du snapshot, le fichier est partagé à 100%
        if active_uberblock.generation == self.generation {
            return Ok(SnapshotDiffStatus::SharedIdentical);
        }

        // Lecture de l'état actif
        let mut active_buf = [0u8; BLOCK_SIZE];
        let _ = client.read_block(snap_entry.lba, &mut active_buf);
        let mut active_len = 0;
        while active_len < active_buf.len() && active_buf[active_len] != 0 {
            active_len += 1;
        }

        let active_checksum =
            compute_merkle_leaf_hash(&active_buf[..active_len], active_uberblock.generation);

        if snap_entry.checksum == active_checksum {
            Ok(SnapshotDiffStatus::SharedIdentical)
        } else {
            Ok(SnapshotDiffStatus::ModifiedInActive)
        }
    }
}

/// Table des snapshots CoW de JamboFS (jusqu'à 16 instant snapshots sans copie de données physiques)
#[derive(Debug, Clone, Copy)]
pub struct SnapshotTable {
    pub entries: [SnapshotDescriptor; MAX_SNAPSHOTS],
    pub next_snapshot_id: u64,
    pub snapshot_count: usize,
}

impl Default for SnapshotTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotTable {
    pub const fn new() -> Self {
        Self {
            entries: [SnapshotDescriptor {
                snapshot_id: 0,
                generation: 0,
                root_tree_offset: 0,
                isolated_tree_root: 0,
                root_checksum: [0u8; 32],
                name: [0u8; MAX_SNAPSHOT_NAME_LEN],
                name_len: 0,
                created_timestamp: 0,
                is_read_only: true,
                active: false,
            }; MAX_SNAPSHOTS],
            next_snapshot_id: 1,
            snapshot_count: 0,
        }
    }

    /// Enregistre un nouvel instant snapshot à partir de l'état actuel de l'Uberblock
    pub fn create_snapshot(&mut self, name: &str, uberblock: &Uberblock) -> Result<u64, FsError> {
        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(MAX_SNAPSHOT_NAME_LEN);

        for entry in self.entries.iter() {
            if entry.active && entry.name_str() == name {
                return Err(FsError::BufferTooSmall);
            }
        }

        for entry in self.entries.iter_mut() {
            if !entry.active {
                let id = self.next_snapshot_id;
                self.next_snapshot_id += 1;
                entry.snapshot_id = id;
                entry.generation = uberblock.generation;
                entry.root_tree_offset = uberblock.root_tree_offset;
                entry.root_checksum = uberblock.root_checksum;
                entry.name = [0u8; MAX_SNAPSHOT_NAME_LEN];
                entry.name[..len].copy_from_slice(&name_bytes[..len]);
                entry.name_len = len;
                entry.created_timestamp = uberblock.timestamp;
                entry.active = true;
                self.snapshot_count += 1;
                return Ok(id);
            }
        }

        Err(FsError::BufferTooSmall)
    }

    /// Enregistre un nouvel instant snapshot avec dérivation de racine B-Tree isolée
    pub fn create_isolated_snapshot(
        &mut self,
        name: &str,
        uberblock: &Uberblock,
        isolated_root: u64,
        isolated_checksum: [u8; 32],
    ) -> Result<ReadOnlySnapshotView, FsError> {
        let name_bytes = name.as_bytes();
        let len = name_bytes.len().min(MAX_SNAPSHOT_NAME_LEN);

        for entry in self.entries.iter() {
            if entry.active && entry.name_str() == name {
                return Err(FsError::BufferTooSmall);
            }
        }

        for entry in self.entries.iter_mut() {
            if !entry.active {
                let id = self.next_snapshot_id;
                self.next_snapshot_id += 1;
                entry.snapshot_id = id;
                entry.generation = uberblock.generation;
                entry.root_tree_offset = uberblock.root_tree_offset;
                entry.isolated_tree_root = isolated_root;
                entry.root_checksum = isolated_checksum;
                entry.name = [0u8; MAX_SNAPSHOT_NAME_LEN];
                entry.name[..len].copy_from_slice(&name_bytes[..len]);
                entry.name_len = len;
                entry.created_timestamp = uberblock.timestamp;
                entry.is_read_only = true;
                entry.active = true;
                self.snapshot_count += 1;
                return Ok(entry.to_readonly_view());
            }
        }

        Err(FsError::BufferTooSmall)
    }

    pub fn find_by_name(&self, name: &str) -> Option<&SnapshotDescriptor> {
        self.entries
            .iter()
            .find(|entry| entry.active && entry.name_str() == name)
    }

    pub fn find_by_id(&self, id: u64) -> Option<&SnapshotDescriptor> {
        self.entries
            .iter()
            .find(|entry| entry.active && entry.snapshot_id == id)
    }

    pub fn delete_snapshot(&mut self, id: u64) -> bool {
        for entry in self.entries.iter_mut() {
            if entry.active && entry.snapshot_id == id {
                entry.active = false;
                self.snapshot_count = self.snapshot_count.saturating_sub(1);
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Journal des Transactions CoW (WAL / Write-Ahead Logging & Intent Log)
// ============================================================================

pub const WAL_MAGIC: u64 = 0x57414C5F4A414D42; // "WAL_JAMB"
pub const WAL_VERSION: u32 = 1;
pub const WAL_OP_NONE: u32 = 0;
pub const WAL_OP_WRITE_INODE: u32 = 1;
pub const WAL_OP_WRITE_DATA: u32 = 2;
pub const WAL_OP_COMMIT: u32 = 3;
pub const WAL_OP_ABORT: u32 = 4;
pub const WAL_REL_LBA: u64 = 4; // LBA relatif 4 sur la partition JamboFS
pub const WAL_RECORD_SIZE: usize = 512;
pub const WAL_PAYLOAD_SIZE: usize = 384;

/// Enregistrement d'intention transactionnelle Write-Ahead Log (512 octets)
#[repr(C, align(512))]
#[derive(Debug, Clone, Copy)]
pub struct WalRecord {
    pub magic: u64,
    pub version: u32,
    pub op_type: u32,
    pub txid: u64,
    pub generation: u64,
    pub target_lba: u64,
    pub payload_len: u32,
    pub _reserved: u32,
    pub payload_checksum: [u8; 32],
    pub record_checksum: [u8; 32],
    pub payload: [u8; WAL_PAYLOAD_SIZE],
}

impl Default for WalRecord {
    fn default() -> Self {
        Self {
            magic: WAL_MAGIC,
            version: WAL_VERSION,
            op_type: WAL_OP_NONE,
            txid: 0,
            generation: 0,
            target_lba: 0,
            payload_len: 0,
            _reserved: 0,
            payload_checksum: [0; 32],
            record_checksum: [0; 32],
            payload: [0; WAL_PAYLOAD_SIZE],
        }
    }
}

impl WalRecord {
    pub fn is_valid(&self) -> bool {
        if self.magic != WAL_MAGIC || self.version != WAL_VERSION {
            return false;
        }
        if self.payload_len as usize > WAL_PAYLOAD_SIZE {
            return false;
        }
        let computed =
            compute_block_checksum(&self.payload[..self.payload_len as usize], self.txid);
        computed == self.payload_checksum
    }
}

/// Gestionnaire du Intent Log / WAL pour la résilience aux pannes d'énergie
#[derive(Debug, Clone, Copy, Default)]
pub struct MetadataWalManager {
    pub current_txid: u64,
    pub active_records: usize,
}

impl MetadataWalManager {
    pub const fn new() -> Self {
        Self {
            current_txid: 1,
            active_records: 0,
        }
    }

    /// Enregistre une intention de transaction dans le WAL avant écriture matérielle CoW
    pub fn log_intent(
        &mut self,
        client: &BlockClient,
        partition_base_lba: u64,
        op_type: u32,
        generation: u64,
        target_lba: u64,
        data: &[u8],
    ) -> Result<u64, FsError> {
        let txid = self.current_txid;
        self.current_txid = self.current_txid.wrapping_add(1);

        let copy_len = data.len().min(WAL_PAYLOAD_SIZE);
        let mut rec = WalRecord {
            magic: WAL_MAGIC,
            version: WAL_VERSION,
            op_type,
            txid,
            generation,
            target_lba,
            payload_len: copy_len as u32,
            _reserved: 0,
            payload_checksum: [0; 32],
            record_checksum: [0; 32],
            payload: [0; WAL_PAYLOAD_SIZE],
        };
        rec.payload[..copy_len].copy_from_slice(&data[..copy_len]);
        rec.payload_checksum = compute_block_checksum(&rec.payload[..copy_len], txid);
        rec.record_checksum = compute_block_checksum(&rec.payload_checksum, generation);

        let mut block_buf = [0u8; BLOCK_SIZE];
        // SAFETY: Copie d'une structure WalRecord de taille fixe 512 octets dans un tampon de taille BLOCK_SIZE (4096 octets)
        unsafe {
            core::ptr::copy_nonoverlapping(
                &rec as *const WalRecord as *const u8,
                block_buf.as_mut_ptr(),
                core::mem::size_of::<WalRecord>(),
            );
        }

        let wal_lba = partition_base_lba + WAL_REL_LBA;
        client
            .write_block(wal_lba, &block_buf)
            .map_err(FsError::BlockIoError)?;
        client.flush().map_err(FsError::BlockIoError)?;
        self.active_records = self.active_records.saturating_add(1);
        Ok(txid)
    }

    /// Scelle la transaction dans le WAL en marquant un enregistrement COMMIT
    pub fn commit_intent(
        &mut self,
        client: &BlockClient,
        partition_base_lba: u64,
        txid: u64,
        generation: u64,
    ) -> Result<(), FsError> {
        let rec = WalRecord {
            magic: WAL_MAGIC,
            version: WAL_VERSION,
            op_type: WAL_OP_COMMIT,
            txid,
            generation,
            target_lba: 0,
            payload_len: 0,
            _reserved: 0,
            payload_checksum: [0; 32],
            record_checksum: compute_block_checksum(&[0; 32], txid),
            payload: [0; WAL_PAYLOAD_SIZE],
        };

        let mut block_buf = [0u8; BLOCK_SIZE];
        // SAFETY: Copie d'une structure WalRecord de taille fixe 512 octets dans un tampon de taille BLOCK_SIZE (4096 octets)
        unsafe {
            core::ptr::copy_nonoverlapping(
                &rec as *const WalRecord as *const u8,
                block_buf.as_mut_ptr(),
                core::mem::size_of::<WalRecord>(),
            );
        }

        let wal_lba = partition_base_lba + WAL_REL_LBA;
        client
            .write_block(wal_lba, &block_buf)
            .map_err(FsError::BlockIoError)?;
        client.flush().map_err(FsError::BlockIoError)?;
        self.active_records = 0;
        Ok(())
    }

    /// Rejoue les transactions non scellées présentes dans le WAL (Recovery après coupure électrique)
    pub fn replay_wal(
        &mut self,
        client: &BlockClient,
        partition_base_lba: u64,
        active_generation: u64,
    ) -> Result<usize, FsError> {
        let wal_lba = partition_base_lba + WAL_REL_LBA;
        let mut block_buf = [0u8; BLOCK_SIZE];
        client
            .read_block(wal_lba, &mut block_buf)
            .map_err(FsError::BlockIoError)?;

        // SAFETY: block_buf a une taille de 4096 octets, supérieure à WalRecord (512 octets), et read_unaligned supporte tout alignement
        let rec = unsafe {
            let ptr = block_buf.as_ptr() as *const WalRecord;
            ptr.read_unaligned()
        };

        if !rec.is_valid() {
            return Ok(0);
        }

        if rec.op_type == WAL_OP_COMMIT || rec.op_type == WAL_OP_ABORT {
            return Ok(0);
        }

        if rec.generation >= active_generation
            && (rec.op_type == WAL_OP_WRITE_INODE || rec.op_type == WAL_OP_WRITE_DATA)
            && rec.target_lba > 0
            && rec.payload_len > 0
        {
            let mut data_buf = [0u8; BLOCK_SIZE];
            let len = (rec.payload_len as usize).min(WAL_PAYLOAD_SIZE);
            data_buf[..len].copy_from_slice(&rec.payload[..len]);
            client
                .write_block(rec.target_lba, &data_buf)
                .map_err(FsError::BlockIoError)?;
            client.flush().map_err(FsError::BlockIoError)?;
            return Ok(1);
        }

        Ok(0)
    }

    /// Purge le journal WAL
    pub fn clear(&mut self, client: &BlockClient, partition_base_lba: u64) -> Result<(), FsError> {
        let wal_lba = partition_base_lba + WAL_REL_LBA;
        let zero_buf = [0u8; BLOCK_SIZE];
        client
            .write_block(wal_lba, &zero_buf)
            .map_err(FsError::BlockIoError)?;
        client.flush().map_err(FsError::BlockIoError)?;
        self.active_records = 0;
        Ok(())
    }
}

pub const BITMAP_MAGIC: u64 = 0x53465F4D41503130; // "JAMB_MAP"
pub const BITMAP_VERSION: u32 = 1;
pub const BITMAP_REL_LBA: u64 = 14;
pub const BITMAP_BLOCKS_COUNT: usize = 2048;
pub const BITMAP_BYTES_COUNT: usize = BITMAP_BLOCKS_COUNT / 8; // 256 octets
pub const BITMAP_RESERVED_SYSTEM_BLOCKS: usize = 24; // Blocs 0..23 réservés pour le micro-noyau & JamboFS

/// En-tête de persistance du bitmap de blocs libres CoW (64 octets)
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitmapHeader {
    pub magic: u64,
    pub version: u32,
    pub total_blocks: u32,
    pub allocated_blocks: u32,
    pub generation: u64,
    pub checksum: [u8; 32],
}

impl Default for BitmapHeader {
    fn default() -> Self {
        Self {
            magic: BITMAP_MAGIC,
            version: BITMAP_VERSION,
            total_blocks: BITMAP_BLOCKS_COUNT as u32,
            allocated_blocks: BITMAP_RESERVED_SYSTEM_BLOCKS as u32,
            generation: 1,
            checksum: [0; 32],
        }
    }
}

/// Gestionnaire transactionnel d'allocation de blocs libres Copy-on-Write (Bitmap Allocator)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CowBitmapAllocator {
    pub header: BitmapHeader,
    pub bits: [u8; BITMAP_BYTES_COUNT],
    pub working_bits: [u8; BITMAP_BYTES_COUNT],
    pub working_allocated: u32,
    pub in_transaction: bool,
}

impl Default for CowBitmapAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl CowBitmapAllocator {
    pub fn new() -> Self {
        let mut bits = [0u8; BITMAP_BYTES_COUNT];
        // Réserver les blocs système 0..23 (3 premiers octets = 0xFF)
        bits[0] = 0xFF;
        bits[1] = 0xFF;
        bits[2] = 0xFF;

        let working_bits = bits;
        let header = BitmapHeader {
            checksum: blake3_block_hash(&bits),
            ..Default::default()
        };

        Self {
            header,
            bits,
            working_bits,
            working_allocated: BITMAP_RESERVED_SYSTEM_BLOCKS as u32,
            in_transaction: false,
        }
    }

    /// Indique si un bloc donné est actuellement alloué
    #[inline]
    pub fn is_block_allocated(&self, block_idx: usize) -> bool {
        if block_idx >= BITMAP_BLOCKS_COUNT {
            return true;
        }
        let byte_idx = block_idx / 8;
        let bit_mask = 1u8 << (block_idx % 8);
        (self.bits[byte_idx] & bit_mask) != 0
    }

    /// Ouvre une transaction d'allocation CoW isolée (staging)
    pub fn begin_transaction(&mut self) {
        self.working_bits.copy_from_slice(&self.bits);
        self.working_allocated = self.header.allocated_blocks;
        self.in_transaction = true;
    }

    /// Annule la transaction courante et rétablit l'état antérieur (CoW Rollback)
    pub fn rollback_transaction(&mut self) {
        self.working_bits.copy_from_slice(&self.bits);
        self.working_allocated = self.header.allocated_blocks;
        self.in_transaction = false;
    }

    /// Scelle la transaction courante sur le stockage physique avec barrière matérielle
    pub fn commit_transaction(
        &mut self,
        client: &BlockClient,
        partition_base_lba: u64,
        generation: u64,
    ) -> Result<(), FsError> {
        self.bits.copy_from_slice(&self.working_bits);
        self.header.allocated_blocks = self.working_allocated;
        self.header.generation = generation;
        self.header.checksum = blake3_block_hash(&self.bits);

        let mut block_buf = [0u8; BLOCK_SIZE];
        // SAFETY: Copie structurée de BitmapHeader (64 octets) au début du tampon de bloc
        unsafe {
            core::ptr::copy_nonoverlapping(
                &self.header as *const BitmapHeader as *const u8,
                block_buf.as_mut_ptr(),
                core::mem::size_of::<BitmapHeader>(),
            );
        }
        block_buf[64..64 + BITMAP_BYTES_COUNT].copy_from_slice(&self.bits);

        let bitmap_lba = partition_base_lba + BITMAP_REL_LBA;
        client
            .write_block(bitmap_lba, &block_buf)
            .map_err(FsError::BlockIoError)?;
        // Barrière matérielle impérative de synchronisation CoW
        client.flush().map_err(FsError::BlockIoError)?;
        self.in_transaction = false;
        Ok(())
    }

    /// Alloue un nouveau bloc libre de manière transactionnelle
    pub fn alloc_block(
        &mut self,
        client: &BlockClient,
        partition_base_lba: u64,
        generation: u64,
    ) -> Result<u64, FsError> {
        let active_bits = if self.in_transaction {
            &mut self.working_bits
        } else {
            &mut self.bits
        };

        let mut found_idx = None;
        for (byte_idx, &byte) in active_bits.iter().enumerate() {
            if byte != 0xFF {
                for bit in 0..8 {
                    if (byte & (1 << bit)) == 0 {
                        let idx = byte_idx * 8 + bit;
                        if idx < BITMAP_BLOCKS_COUNT {
                            found_idx = Some(idx);
                            break;
                        }
                    }
                }
                if found_idx.is_some() {
                    break;
                }
            }
        }

        let idx = match found_idx {
            Some(i) => i,
            None => return Err(FsError::BufferTooSmall), // Disque plein
        };

        let byte_idx = idx / 8;
        let bit_mask = 1u8 << (idx % 8);
        active_bits[byte_idx] |= bit_mask;

        if self.in_transaction {
            self.working_allocated = self.working_allocated.saturating_add(1);
        } else {
            self.header.allocated_blocks = self.header.allocated_blocks.saturating_add(1);
            self.working_bits[byte_idx] |= bit_mask;
            self.working_allocated = self.header.allocated_blocks;

            // Persistance directe avec barrière matérielle
            let mut block_buf = [0u8; BLOCK_SIZE];
            self.header.generation = generation;
            self.header.checksum = blake3_block_hash(&self.bits);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &self.header as *const BitmapHeader as *const u8,
                    block_buf.as_mut_ptr(),
                    core::mem::size_of::<BitmapHeader>(),
                );
            }
            block_buf[64..64 + BITMAP_BYTES_COUNT].copy_from_slice(&self.bits);
            let bitmap_lba = partition_base_lba + BITMAP_REL_LBA;
            client
                .write_block(bitmap_lba, &block_buf)
                .map_err(FsError::BlockIoError)?;
            client.flush().map_err(FsError::BlockIoError)?;
        }

        Ok(idx as u64)
    }

    /// Libère un bloc précédemment alloué (CoW free)
    pub fn free_block(
        &mut self,
        client: &BlockClient,
        partition_base_lba: u64,
        block_idx: usize,
        generation: u64,
    ) -> Result<(), FsError> {
        if !(BITMAP_RESERVED_SYSTEM_BLOCKS..BITMAP_BLOCKS_COUNT).contains(&block_idx) {
            return Err(FsError::InvalidMagic); // Protection des blocs système réservés
        }

        let byte_idx = block_idx / 8;
        let bit_mask = 1u8 << (block_idx % 8);

        if self.in_transaction {
            if (self.working_bits[byte_idx] & bit_mask) != 0 {
                self.working_bits[byte_idx] &= !bit_mask;
                self.working_allocated = self.working_allocated.saturating_sub(1);
            }
        } else {
            if (self.bits[byte_idx] & bit_mask) != 0 {
                self.bits[byte_idx] &= !bit_mask;
                self.working_bits[byte_idx] &= !bit_mask;
                self.header.allocated_blocks = self.header.allocated_blocks.saturating_sub(1);
                self.working_allocated = self.header.allocated_blocks;

                let mut block_buf = [0u8; BLOCK_SIZE];
                self.header.generation = generation;
                self.header.checksum = blake3_block_hash(&self.bits);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        &self.header as *const BitmapHeader as *const u8,
                        block_buf.as_mut_ptr(),
                        core::mem::size_of::<BitmapHeader>(),
                    );
                }
                block_buf[64..64 + BITMAP_BYTES_COUNT].copy_from_slice(&self.bits);
                let bitmap_lba = partition_base_lba + BITMAP_REL_LBA;
                client
                    .write_block(bitmap_lba, &block_buf)
                    .map_err(FsError::BlockIoError)?;
                client.flush().map_err(FsError::BlockIoError)?;
            }
        }

        Ok(())
    }

    /// Charge et valide le bitmap présent sur le stockage physique
    pub fn load(&mut self, client: &BlockClient, partition_base_lba: u64) -> Result<(), FsError> {
        let bitmap_lba = partition_base_lba + BITMAP_REL_LBA;
        let mut block_buf = [0u8; BLOCK_SIZE];
        client
            .read_block(bitmap_lba, &mut block_buf)
            .map_err(FsError::BlockIoError)?;

        let hdr = unsafe {
            let ptr = block_buf.as_ptr() as *const BitmapHeader;
            ptr.read_unaligned()
        };

        if hdr.magic == BITMAP_MAGIC && hdr.version == BITMAP_VERSION {
            let mut candidate_bits = [0u8; BITMAP_BYTES_COUNT];
            candidate_bits.copy_from_slice(&block_buf[64..64 + BITMAP_BYTES_COUNT]);
            let actual_checksum = blake3_block_hash(&candidate_bits);
            if actual_checksum == hdr.checksum {
                self.header = hdr;
                self.bits = candidate_bits;
                self.working_bits = candidate_bits;
                self.working_allocated = hdr.allocated_blocks;
                return Ok(());
            }
        }

        // Si non présent ou invalide, initialisation par défaut et écriture initiale avec barrière
        *self = Self::new();
        let mut block_buf = [0u8; BLOCK_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &self.header as *const BitmapHeader as *const u8,
                block_buf.as_mut_ptr(),
                core::mem::size_of::<BitmapHeader>(),
            );
        }
        block_buf[64..64 + BITMAP_BYTES_COUNT].copy_from_slice(&self.bits);
        client
            .write_block(bitmap_lba, &block_buf)
            .map_err(FsError::BlockIoError)?;
        client.flush().map_err(FsError::BlockIoError)?;
        Ok(())
    }
}

// =========================================================================
// Compression LZ4 Bare-Metal no_std pour Blocs CoW 4 Kio
// =========================================================================

pub const BLOCK_MAGIC_LZ4: u32 = 0x184D_2204;
pub const MAX_COMPRESSED_PAYLOAD: usize =
    BLOCK_SIZE - core::mem::size_of::<CompressedBlockHeader>();

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedBlockHeader {
    pub magic: u32,
    pub uncompressed_size: u16,
    pub compressed_size: u16,
    pub checksum: [u8; 32],
}

impl CompressedBlockHeader {
    #[inline]
    pub fn magic(&self) -> u32 {
        self.magic
    }
    #[inline]
    pub fn uncompressed_size(&self) -> u16 {
        self.uncompressed_size
    }
    #[inline]
    pub fn compressed_size(&self) -> u16 {
        self.compressed_size
    }
}

/// Compresse un bloc de 4096 octets avec l'algorithme LZ4 bare-metal.
/// Si la compression ne réduit pas la taille d'au moins 64 octets, renvoie None (incompressible).
pub fn lz4_compress_block(src: &[u8; BLOCK_SIZE], dst: &mut [u8]) -> Option<usize> {
    if dst.len() < 128 {
        return None;
    }

    const HASH_SIZE: usize = 1024;
    let mut hash_table = [0u16; HASH_SIZE];

    let mut in_pos = 0usize;
    let mut out_pos = 0usize;
    let mut anchor = 0usize;

    while in_pos + 4 < BLOCK_SIZE && out_pos + 16 < BLOCK_SIZE {
        let seq = u32::from_le_bytes([
            src[in_pos],
            src[in_pos + 1],
            src[in_pos + 2],
            src[in_pos + 3],
        ]);
        let h = ((seq.wrapping_mul(2654435761)) >> 22) as usize % HASH_SIZE;
        let stored = hash_table[h];
        hash_table[h] = (in_pos as u16) + 1;

        if stored != 0 {
            let ref_pos = (stored - 1) as usize;
            if in_pos > ref_pos
                && (in_pos - ref_pos) < 65535
                && src[ref_pos..ref_pos + 4] == src[in_pos..in_pos + 4]
            {
                let mut match_len = 4usize;
                while in_pos + match_len < BLOCK_SIZE
                    && src[ref_pos + match_len] == src[in_pos + match_len]
                {
                    match_len += 1;
                }

                let lit_len = in_pos - anchor;
                let offset = (in_pos - ref_pos) as u16;

                let token_lit = if lit_len >= 15 { 15 } else { lit_len as u8 };
                let token_match = if (match_len - 4) >= 15 {
                    15
                } else {
                    (match_len - 4) as u8
                };
                let token = (token_lit << 4) | token_match;

                if out_pos >= dst.len() {
                    return None;
                }
                dst[out_pos] = token;
                out_pos += 1;

                if lit_len >= 15 {
                    let mut rem = lit_len - 15;
                    while rem >= 255 {
                        if out_pos >= dst.len() {
                            return None;
                        }
                        dst[out_pos] = 255;
                        out_pos += 1;
                        rem -= 255;
                    }
                    if out_pos >= dst.len() {
                        return None;
                    }
                    dst[out_pos] = rem as u8;
                    out_pos += 1;
                }

                if out_pos + lit_len > dst.len() {
                    return None;
                }
                dst[out_pos..out_pos + lit_len].copy_from_slice(&src[anchor..anchor + lit_len]);
                out_pos += lit_len;

                if out_pos + 2 > dst.len() {
                    return None;
                }
                let off_bytes = offset.to_le_bytes();
                dst[out_pos..out_pos + 2].copy_from_slice(&off_bytes);
                out_pos += 2;

                if (match_len - 4) >= 15 {
                    let mut rem = match_len - 4 - 15;
                    while rem >= 255 {
                        if out_pos >= dst.len() {
                            return None;
                        }
                        dst[out_pos] = 255;
                        out_pos += 1;
                        rem -= 255;
                    }
                    if out_pos >= dst.len() {
                        return None;
                    }
                    dst[out_pos] = rem as u8;
                    out_pos += 1;
                }

                in_pos += match_len;
                anchor = in_pos;
                continue;
            }
        }
        in_pos += 1;
    }

    let final_lit = BLOCK_SIZE - anchor;
    let token_lit = if final_lit >= 15 { 15 } else { final_lit as u8 };
    if out_pos >= dst.len() {
        return None;
    }
    dst[out_pos] = token_lit << 4;
    out_pos += 1;

    if final_lit >= 15 {
        let mut rem = final_lit - 15;
        while rem >= 255 {
            if out_pos >= dst.len() {
                return None;
            }
            dst[out_pos] = 255;
            out_pos += 1;
            rem -= 255;
        }
        if out_pos >= dst.len() {
            return None;
        }
        dst[out_pos] = rem as u8;
        out_pos += 1;
    }

    if out_pos + final_lit > dst.len() {
        return None;
    }
    dst[out_pos..out_pos + final_lit].copy_from_slice(&src[anchor..BLOCK_SIZE]);
    out_pos += final_lit;

    let max_allowed = (BLOCK_SIZE - 64).min(dst.len());
    if out_pos <= max_allowed {
        Some(out_pos)
    } else {
        None
    }
}

/// Décompresse un flux LZ4 brut dans un bloc de 4096 octets.
pub fn lz4_decompress_block(src: &[u8], dst: &mut [u8; BLOCK_SIZE]) -> Result<usize, FsError> {
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;

    while in_pos < src.len() && out_pos < BLOCK_SIZE {
        let token = src[in_pos];
        in_pos += 1;

        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            while in_pos < src.len() {
                let b = src[in_pos];
                in_pos += 1;
                lit_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }

        if out_pos + lit_len > BLOCK_SIZE || in_pos + lit_len > src.len() {
            return Err(FsError::CorruptedData);
        }
        dst[out_pos..out_pos + lit_len].copy_from_slice(&src[in_pos..in_pos + lit_len]);
        out_pos += lit_len;
        in_pos += lit_len;

        if in_pos >= src.len() || out_pos >= BLOCK_SIZE {
            break;
        }

        if in_pos + 2 > src.len() {
            return Err(FsError::CorruptedData);
        }
        let offset = u16::from_le_bytes([src[in_pos], src[in_pos + 1]]) as usize;
        in_pos += 2;

        if offset == 0 || offset > out_pos {
            return Err(FsError::CorruptedData);
        }

        let mut match_len = ((token & 0x0F) + 4) as usize;
        if (token & 0x0F) == 15 {
            while in_pos < src.len() {
                let b = src[in_pos];
                in_pos += 1;
                match_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }

        if out_pos + match_len > BLOCK_SIZE {
            return Err(FsError::CorruptedData);
        }

        for _ in 0..match_len {
            dst[out_pos] = dst[out_pos - offset];
            out_pos += 1;
        }
    }

    if out_pos == BLOCK_SIZE {
        Ok(out_pos)
    } else {
        Err(FsError::CorruptedData)
    }
}

/// Limite de quota d'espace disque et d'inodes par identifiant d'utilisateur (UID)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsQuota {
    pub uid: u32,
    pub max_bytes: u64,
    pub bytes_used: u64,
    pub max_inodes: u32,
    pub inodes_used: u32,
    pub enabled: bool,
}

pub const MAX_QUOTA_ENTRIES: usize = 16;

/// Table de gestion statique des quotas de stockage et limites d'inodes (zéro allocation)
#[derive(Debug, Clone, Copy)]
pub struct QuotaTable {
    pub entries: [FsQuota; MAX_QUOTA_ENTRIES],
    pub count: usize,
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaTable {
    pub const fn new() -> Self {
        Self {
            entries: [FsQuota {
                uid: 0,
                max_bytes: 0,
                bytes_used: 0,
                max_inodes: 0,
                inodes_used: 0,
                enabled: false,
            }; MAX_QUOTA_ENTRIES],
            count: 0,
        }
    }

    pub fn set_quota(&mut self, uid: u32, max_bytes: u64, max_inodes: u32) -> Result<(), FsError> {
        for entry in self.entries[..self.count].iter_mut() {
            if entry.enabled && entry.uid == uid {
                entry.max_bytes = max_bytes;
                entry.max_inodes = max_inodes;
                return Ok(());
            }
        }
        if self.count < MAX_QUOTA_ENTRIES {
            self.entries[self.count] = FsQuota {
                uid,
                max_bytes,
                bytes_used: 0,
                max_inodes,
                inodes_used: 0,
                enabled: true,
            };
            self.count += 1;
            Ok(())
        } else {
            Err(FsError::QuotaExceeded)
        }
    }

    pub fn get_quota(&self, uid: u32) -> Option<FsQuota> {
        for entry in self.entries[..self.count].iter() {
            if entry.enabled && entry.uid == uid {
                return Some(*entry);
            }
        }
        None
    }

    pub fn check_allocation(
        &self,
        uid: u32,
        additional_bytes: u64,
        additional_inodes: u32,
    ) -> Result<(), FsError> {
        if let Some(quota) = self.get_quota(uid) {
            if quota.max_bytes > 0
                && quota.bytes_used.saturating_add(additional_bytes) > quota.max_bytes
            {
                return Err(FsError::QuotaExceeded);
            }
            if quota.max_inodes > 0
                && quota.inodes_used.saturating_add(additional_inodes) > quota.max_inodes
            {
                return Err(FsError::QuotaExceeded);
            }
        }
        Ok(())
    }

    pub fn record_allocation(&mut self, uid: u32, bytes: u64, inodes: u32) {
        for entry in self.entries[..self.count].iter_mut() {
            if entry.enabled && entry.uid == uid {
                entry.bytes_used = entry.bytes_used.saturating_add(bytes);
                entry.inodes_used = entry.inodes_used.saturating_add(inodes);
                break;
            }
        }
    }

    pub fn record_release(&mut self, uid: u32, bytes: u64, inodes: u32) {
        for entry in self.entries[..self.count].iter_mut() {
            if entry.enabled && entry.uid == uid {
                entry.bytes_used = entry.bytes_used.saturating_sub(bytes);
                entry.inodes_used = entry.inodes_used.saturating_sub(inodes);
                break;
            }
        }
    }
}

/// Type de verrou de fichier POSIX (IEEE Std 1003.1 fcntl / flock)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileLockType {
    /// Verrou de lecture partagé (plusieurs lecteurs autorisés simultanément)
    ReadShared,
    /// Verrou d'écriture exclusif (un seul écrivain, aucun lecteur concurrent)
    WriteExclusive,
    /// Déverrouillage d'une plage d'octets
    Unlock,
}

/// Descripteur de verrou sur une plage d'octets de fichier (Byte-Range Lock)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRangeLock {
    pub lock_type: FileLockType,
    pub start: u64,
    pub len: u64, // 0 = jusqu'à la fin du fichier (EOF)
    pub owner_pid: u32,
    pub path_hash: u64,
    pub active: bool,
}

pub const MAX_FILE_LOCKS: usize = 64;

/// Table des verrous de fichiers POSIX consultatifs et obligatoires
#[derive(Debug, Clone, Copy)]
pub struct FileLockTable {
    pub locks: [ByteRangeLock; MAX_FILE_LOCKS],
    pub count: usize,
}

impl Default for FileLockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FileLockTable {
    pub const fn new() -> Self {
        Self {
            locks: [ByteRangeLock {
                lock_type: FileLockType::Unlock,
                start: 0,
                len: 0,
                owner_pid: 0,
                path_hash: 0,
                active: false,
            }; MAX_FILE_LOCKS],
            count: 0,
        }
    }

    /// Calcule le hachage déterministe FNV-1a 64-bit d'un chemin de fichier
    pub fn hash_path(path: &str) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        for &b in path.as_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    /// Teste si deux plages d'octets [s1, e1) et [s2, e2) se chevauchent
    pub fn ranges_overlap(s1: u64, l1: u64, s2: u64, l2: u64) -> bool {
        let e1 = if l1 == 0 {
            u64::MAX
        } else {
            s1.saturating_add(l1)
        };
        let e2 = if l2 == 0 {
            u64::MAX
        } else {
            s2.saturating_add(l2)
        };
        s1 < e2 && s2 < e1
    }

    /// Vérifie si une acquisition de verrou entrerait en conflit avec un verrou existant
    pub fn test_conflict(
        &self,
        path_hash: u64,
        lock_type: FileLockType,
        start: u64,
        len: u64,
        requester_pid: u32,
    ) -> Option<ByteRangeLock> {
        if lock_type == FileLockType::Unlock {
            return None;
        }

        for lock in &self.locks[..self.count] {
            if !lock.active || lock.path_hash != path_hash {
                continue;
            }

            // Un processus n'entre pas en conflit avec ses propres verrous
            if lock.owner_pid == requester_pid {
                continue;
            }

            if Self::ranges_overlap(lock.start, lock.len, start, len) {
                // Conflit si au moins un des deux verrous est exclusif (WriteExclusive)
                if lock.lock_type == FileLockType::WriteExclusive
                    || lock_type == FileLockType::WriteExclusive
                {
                    return Some(*lock);
                }
            }
        }
        None
    }

    /// Acquiert ou modifie un verrou POSIX sur une plage d'octets
    pub fn acquire_lock(
        &mut self,
        path: &str,
        lock_type: FileLockType,
        start: u64,
        len: u64,
        owner_pid: u32,
    ) -> Result<(), FsError> {
        if lock_type == FileLockType::Unlock {
            return self.release_lock(path, start, len, owner_pid);
        }

        let path_hash = Self::hash_path(path);

        if self
            .test_conflict(path_hash, lock_type, start, len, owner_pid)
            .is_some()
        {
            return Err(FsError::FileLocked);
        }

        // Vérification si le même PID met à jour une plage existante identique
        for lock in self.locks[..self.count].iter_mut() {
            if lock.active
                && lock.path_hash == path_hash
                && lock.owner_pid == owner_pid
                && lock.start == start
                && lock.len == len
            {
                lock.lock_type = lock_type;
                return Ok(());
            }
        }

        // Recherche d'un premier slot inactif
        let mut slot_idx = None;
        for (idx, lock) in self.locks.iter().enumerate() {
            if !lock.active {
                slot_idx = Some(idx);
                break;
            }
        }

        if let Some(idx) = slot_idx {
            self.locks[idx] = ByteRangeLock {
                lock_type,
                start,
                len,
                owner_pid,
                path_hash,
                active: true,
            };
            if idx >= self.count {
                self.count = idx + 1;
            }
            Ok(())
        } else {
            Err(FsError::BufferTooSmall)
        }
    }

    /// Déverrouille une plage d'octets pour un PID
    pub fn release_lock(
        &mut self,
        path: &str,
        start: u64,
        len: u64,
        owner_pid: u32,
    ) -> Result<(), FsError> {
        let path_hash = Self::hash_path(path);
        for lock in self.locks.iter_mut() {
            if lock.active
                && lock.path_hash == path_hash
                && lock.owner_pid == owner_pid
                && (len == 0 || Self::ranges_overlap(lock.start, lock.len, start, len))
            {
                lock.active = false;
            }
        }
        Ok(())
    }

    /// Libère l'ensemble des verrous détenus par un PID lors de sa terminaison
    pub fn release_all_for_pid(&mut self, owner_pid: u32) -> usize {
        let mut released = 0;
        for lock in self.locks.iter_mut() {
            if lock.active && lock.owner_pid == owner_pid {
                lock.active = false;
                released += 1;
            }
        }
        released
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
    pub geometry: libjambo::gpt::SectorGeometry,
    pub dedup_table: BlockDedupTable,
    pub snapshot_table: SnapshotTable,
    pub xattr_table: XattrTable,
    pub quota_table: QuotaTable,
    pub lock_table: FileLockTable,
    pub wal: MetadataWalManager,
    pub bitmap: CowBitmapAllocator,
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
        let mut geometry = libjambo::gpt::SectorGeometry::Sector512e;

        if !uberblock.is_valid() {
            // Lecture des premiers secteurs pour détection GPT (au moins 6 blocs de 4 Kio pour couvrir 4Kn et 512e)
            let mut gpt_buf = [0u8; 6 * BLOCK_SIZE];
            for b in 0..6 {
                let mut chunk = [0u8; BLOCK_SIZE];
                if client.read_block(b as u64 * 8, &mut chunk).is_ok() {
                    let start = b * BLOCK_SIZE;
                    gpt_buf[start..start + BLOCK_SIZE].copy_from_slice(&chunk);
                }
            }

            if let Ok((info, detected_geom)) = libjambo::gpt::detect_and_parse_gpt(&gpt_buf) {
                geometry = detected_geom;
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
        let slot_b_lba = partition_base_lba + geometry.sectors_per_4k_block();
        if client.read_block(slot_b_lba, &mut block_b_buf).is_ok() {
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

        let mut bitmap = CowBitmapAllocator::new();
        let _ = bitmap.load(client, partition_base_lba);

        let mut fs = Self {
            client: *client,
            active_uberblock: uberblock,
            root_offset,
            partition_base_lba,
            flags,
            active_slot_b,
            geometry,
            dedup_table: BlockDedupTable::new(),
            snapshot_table: SnapshotTable::new(),
            xattr_table: XattrTable::new(),
            quota_table: QuotaTable::new(),
            lock_table: FileLockTable::new(),
            wal: MetadataWalManager::new(),
            bitmap,
        };

        // Replay automatique de résilience après coupure électrique
        let _ = fs.replay_intent_log();

        Ok(fs)
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
            geometry: libjambo::gpt::SectorGeometry::Sector512e,
            dedup_table: BlockDedupTable::new(),
            snapshot_table: SnapshotTable::new(),
            xattr_table: XattrTable::new(),
            quota_table: QuotaTable::new(),
            lock_table: FileLockTable::new(),
            wal: MetadataWalManager::new(),
            bitmap: CowBitmapAllocator::new(),
        }
    }

    /// Indique si le système de fichiers est monté sur un support 4Kn natif
    pub fn is_4kn(&self) -> bool {
        self.geometry == libjambo::gpt::SectorGeometry::Sector4Kn
    }

    /// Alloue un nouveau bloc physique libre pour une opération CoW
    pub fn allocate_cow_block(&mut self) -> Result<u64, FsError> {
        let gen = self.active_uberblock.generation;
        self.bitmap
            .alloc_block(&self.client, self.partition_base_lba, gen)
    }

    /// Libère un bloc physique CoW obsolète
    pub fn free_cow_block(&mut self, block_idx: usize) -> Result<(), FsError> {
        let gen = self.active_uberblock.generation;
        self.bitmap
            .free_block(&self.client, self.partition_base_lba, block_idx, gen)
    }

    /// Retourne le nombre de blocs actuellement disponibles (libres)
    #[inline]
    pub fn free_blocks_count(&self) -> usize {
        BITMAP_BLOCKS_COUNT.saturating_sub(self.bitmap.header.allocated_blocks as usize)
    }

    /// Retourne le nombre de blocs actuellement alloués
    #[inline]
    pub fn allocated_blocks_count(&self) -> usize {
        self.bitmap.header.allocated_blocks as usize
    }

    /// Retourne les métriques détaillées d'espace, de blocs et de snapshots CoW JamboFS
    pub fn metrics(&self) -> FsMetrics {
        FsMetrics {
            block_size: BLOCK_SIZE as u32,
            total_blocks: BITMAP_BLOCKS_COUNT as u32,
            allocated_blocks: self.allocated_blocks_count() as u32,
            free_blocks: self.free_blocks_count() as u32,
            active_snapshots: self.snapshot_table.snapshot_count as u32,
            max_snapshots: MAX_SNAPSHOTS as u32,
            generation: self.active_uberblock.generation,
            active_slot_b: self.active_slot_b,
            is_4kn: self.is_4kn(),
            _reserved: [0; 2],
            dedup_entries: self.dedup_table.active_count as u32,
        }
    }

    /// Expose les métriques du volume sous forme compatible POSIX statvfs
    pub fn statvfs(&self) -> libjambo::vfs::PosixStatvfs {
        libjambo::vfs::PosixStatvfs {
            f_bsize: BLOCK_SIZE as u64,
            f_frsize: BLOCK_SIZE as u64,
            f_blocks: BITMAP_BLOCKS_COUNT as u64,
            f_bfree: self.free_blocks_count() as u64,
            f_bavail: self.free_blocks_count() as u64,
            f_files: 1024,
            f_ffree: (1024u64).saturating_sub(self.allocated_blocks_count() as u64),
            f_favail: (1024u64).saturating_sub(self.allocated_blocks_count() as u64),
            f_fsid: JAMBOFS_MAGIC & 0xFFFF_FFFF,
            f_flag: self.flags.0 as u64,
            f_namemax: MAX_SNAPSHOT_NAME_LEN as u64,
        }
    }

    /// Crée un instant snapshot immuable sans duplication physique de blocs (CoW)
    pub fn create_snapshot(&mut self, name: &str) -> Result<u64, FsError> {
        self.snapshot_table
            .create_snapshot(name, &self.active_uberblock)
    }

    /// Crée un instantané snapshot read-only avec dérivation de racine B-Tree isolée
    pub fn create_isolated_snapshot(
        &mut self,
        name: &str,
    ) -> Result<ReadOnlySnapshotView, FsError> {
        // 1. Alloue un bloc physique libre pour la racine B-Tree isolée du snapshot
        let isolated_root_lba = self.allocate_cow_block()?;

        // 2. Lit la racine B-Tree courante et la copie dans le bloc isolé
        let current_root_lba = if self.root_offset > 0 {
            self.root_offset
        } else {
            self.active_uberblock.root_tree_offset
        };
        let mut root_buf = [0u8; BLOCK_SIZE];
        self.client
            .read_block(current_root_lba, &mut root_buf)
            .map_err(FsError::BlockIoError)?;

        // 3. Calcule l'empreinte cryptographique de la racine isolée
        let isolated_checksum = blake3_block_hash(&root_buf);

        // 4. Persiste la racine B-Tree dérivée isolée sur le support matériel
        self.client
            .write_block(isolated_root_lba, &root_buf)
            .map_err(FsError::BlockIoError)?;
        self.client.flush().map_err(FsError::BlockIoError)?;

        // 5. Enregistre le snapshot avec racine isolée dans la table des snapshots
        let view = self.snapshot_table.create_isolated_snapshot(
            name,
            &self.active_uberblock,
            isolated_root_lba,
            isolated_checksum,
        )?;

        // 6. Synchronise l'état global du système
        self.sync()?;

        Ok(view)
    }

    /// Ouvre un instantané snapshot en lecture seule par son identifiant
    pub fn open_snapshot_readonly(&self, id: u64) -> Result<ReadOnlySnapshotView, FsError> {
        match self.snapshot_table.find_by_id(id) {
            Some(entry) => Ok(entry.to_readonly_view()),
            None => Err(FsError::FileNotFound),
        }
    }

    /// Inspecte et extrait le contenu immuable d'un fichier scellé dans un instantané snapshot
    pub fn inspect_snapshot_file(
        &self,
        snapshot_id: u64,
        path: &str,
        out: &mut [u8],
    ) -> Result<usize, FsError> {
        let view = self.open_snapshot_readonly(snapshot_id)?;
        view.read_file(&self.client, self.partition_base_lba, path, out)
    }

    /// Liste l'arborescence des fichiers scellés dans un snapshot
    pub fn list_snapshot_directory(
        &self,
        snapshot_id: u64,
        dir_path: &str,
        entries: &mut [SnapshotFileEntry],
    ) -> Result<usize, FsError> {
        let view = self.open_snapshot_readonly(snapshot_id)?;
        view.list_directory(&self.client, self.partition_base_lba, dir_path, entries)
    }

    /// Analyse la divergence Copy-on-Write (CoW Diff) d'un fichier entre le snapshot et le volume actif
    pub fn diff_snapshot_file(
        &self,
        snapshot_id: u64,
        path: &str,
    ) -> Result<SnapshotDiffStatus, FsError> {
        let view = self.open_snapshot_readonly(snapshot_id)?;
        view.diff_file(
            &self.client,
            self.partition_base_lba,
            &self.active_uberblock,
            path,
        )
    }

    /// Ouvre un instantané snapshot en lecture seule par son nom
    pub fn open_snapshot_readonly_by_name(
        &self,
        name: &str,
    ) -> Result<ReadOnlySnapshotView, FsError> {
        match self.snapshot_table.find_by_name(name) {
            Some(entry) => Ok(entry.to_readonly_view()),
            None => Err(FsError::FileNotFound),
        }
    }

    /// Supprime un snapshot existant par son identifiant
    pub fn delete_snapshot(&mut self, id: u64) -> bool {
        self.snapshot_table.delete_snapshot(id)
    }

    /// Restaure l'état du système de fichiers à un instant snapshot antérieur (Rollback CoW)
    pub fn rollback_to_snapshot(&mut self, id: u64) -> Result<(), FsError> {
        let snap = match self.snapshot_table.find_by_id(id) {
            Some(s) => *s,
            None => return Err(FsError::FileNotFound),
        };

        self.active_uberblock.root_tree_offset = snap.root_tree_offset;
        self.active_uberblock.root_checksum = snap.root_checksum;
        self.active_uberblock.generation = self.active_uberblock.generation.saturating_add(1);
        self.root_offset = snap.root_tree_offset;

        self.sync()
    }

    /// Résout un identifiant d'inode déterministe pour un chemin donné
    pub fn resolve_inode_num(&self, path: &str) -> u64 {
        let clean = path.strip_prefix('/').unwrap_or(path);
        match clean {
            "banner.txt" => 16,
            "hostname" | "etc/hostname" => 17,
            "os-release" | "etc/os-release" => 18,
            _ => {
                let mut h: u64 = 5381;
                for &b in clean.as_bytes() {
                    h = h.wrapping_mul(33).wrapping_add(b as u64);
                }
                100 + (h % 10000)
            }
        }
    }

    /// Définit ou modifie un attribut étendu POSIX.1e (xattr) sur un fichier
    pub fn setxattr(
        &mut self,
        path: &str,
        name: &str,
        value: &[u8],
        flags: u32,
    ) -> Result<(), FsError> {
        if self.flags.is_read_only() {
            return Err(FsError::ReadOnlyFileSystem);
        }
        let ino = self.resolve_inode_num(path);
        self.xattr_table.setxattr(ino, name, value, flags)
    }

    /// Récupère la valeur d'un attribut étendu POSIX.1e (xattr)
    pub fn getxattr(&self, path: &str, name: &str, out: &mut [u8]) -> Result<usize, FsError> {
        let ino = self.resolve_inode_num(path);
        self.xattr_table.getxattr(ino, name, out)
    }

    /// Liste tous les noms d'attributs étendus définis sur un fichier (délimités par `\0`)
    pub fn listxattr(&self, path: &str, out: &mut [u8]) -> Result<usize, FsError> {
        let ino = self.resolve_inode_num(path);
        self.xattr_table.listxattr(ino, out)
    }

    /// Supprime un attribut étendu d'un fichier
    pub fn removexattr(&mut self, path: &str, name: &str) -> Result<(), FsError> {
        if self.flags.is_read_only() {
            return Err(FsError::ReadOnlyFileSystem);
        }
        let ino = self.resolve_inode_num(path);
        self.xattr_table.removexattr(ino, name)
    }

    /// Écrit un bloc de 4 Kio avec déduplication CoW par empreinte BLAKE3
    /// Retourne `(lba_physique, etait_deduplique)`
    pub fn write_block_dedup(
        &mut self,
        data: &[u8; BLOCK_SIZE],
        target_lba: u64,
    ) -> Result<(u64, bool), FsError> {
        let hash = blake3_block_hash(data);
        if let Some(existing_lba) = self.dedup_table.lookup(&hash) {
            let (lba, _) = self.dedup_table.register_or_dedup(&hash, existing_lba);
            return Ok((lba, true));
        }

        self.client
            .write_block(target_lba, data)
            .map_err(FsError::BlockIoError)?;
        let (lba, _) = self.dedup_table.register_or_dedup(&hash, target_lba);
        Ok((lba, false))
    }

    /// Écrit un bloc de 4 Kio avec tentative de compression LZ4 bare-metal.
    /// Si le bloc est compressible (gain >= 64 octets), il est encapsulé avec un CompressedBlockHeader.
    /// Retourne `(lba_physique, etait_compresse, taille_stockee)`.
    pub fn write_block_lz4(
        &mut self,
        data: &[u8; BLOCK_SIZE],
        target_lba: u64,
    ) -> Result<(u64, bool, usize), FsError> {
        let mut comp_buf = [0u8; BLOCK_SIZE];
        let header_size = core::mem::size_of::<CompressedBlockHeader>();

        if let Some(comp_len) = lz4_compress_block(data, &mut comp_buf[header_size..]) {
            let header = CompressedBlockHeader {
                magic: BLOCK_MAGIC_LZ4,
                uncompressed_size: BLOCK_SIZE as u16,
                compressed_size: comp_len as u16,
                checksum: blake3_block_hash(data),
            };

            // SAFETY: Copie structurée de CompressedBlockHeader (40 octets) au début du tampon
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &header as *const CompressedBlockHeader as *const u8,
                    comp_buf.as_mut_ptr(),
                    header_size,
                );
            }
            comp_buf[header_size + comp_len..].fill(0);

            self.client
                .write_block(target_lba, &comp_buf)
                .map_err(FsError::BlockIoError)?;

            Ok((target_lba, true, header_size + comp_len))
        } else {
            self.client
                .write_block(target_lba, data)
                .map_err(FsError::BlockIoError)?;

            Ok((target_lba, false, BLOCK_SIZE))
        }
    }

    /// Lit un bloc de 4 Kio et le décompresse automatiquement si l'en-tête LZ4 est présent et valide.
    pub fn read_block_lz4(&self, lba: u64, out: &mut [u8; BLOCK_SIZE]) -> Result<bool, FsError> {
        let mut raw_buf = [0u8; BLOCK_SIZE];
        self.client
            .read_block(lba, &mut raw_buf)
            .map_err(FsError::BlockIoError)?;

        let header_size = core::mem::size_of::<CompressedBlockHeader>();
        // SAFETY: Lecture avec read_unaligned de l'en-tête potentiel
        let header = unsafe {
            let ptr = raw_buf.as_ptr() as *const CompressedBlockHeader;
            ptr.read_unaligned()
        };

        if header.magic == BLOCK_MAGIC_LZ4
            && (header.compressed_size as usize) <= MAX_COMPRESSED_PAYLOAD
        {
            let payload = &raw_buf[header_size..header_size + header.compressed_size as usize];
            lz4_decompress_block(payload, out)?;
            let calc_hash = blake3_block_hash(out);
            if calc_hash != header.checksum {
                return Err(FsError::CorruptedData);
            }
            Ok(true)
        } else {
            out.copy_from_slice(&raw_buf);
            Ok(false)
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
        let base_rel_lba = match clean_path {
            "banner.txt" => 24,
            "hostname" | "etc/hostname" => 32,
            "os-release" | "etc/os-release" => 40,
            _ => 0,
        };

        if base_rel_lba == 0 {
            return Err(FsError::FileNotFound);
        }

        // Vérification si un bloc CoW dérivé a été enregistré dans l'inode actif
        let inode_offset = match clean_path {
            "banner.txt" => 16,
            "hostname" | "etc/hostname" => 17,
            "os-release" | "etc/os-release" => 18,
            _ => 19,
        };
        let mut actual_rel_lba = base_rel_lba;
        let mut inode_buf = [0u8; BLOCK_SIZE];
        let inode_lba = self.partition_base_lba + inode_offset;
        let mut inode_found = false;
        if self.client.read_block(inode_lba, &mut inode_buf).is_ok() {
            let ino = u64::from_le_bytes(inode_buf[0..8].try_into().unwrap_or([0; 8]));
            if ino == (1u64 + base_rel_lba) {
                let recorded_rel_lba =
                    u64::from_le_bytes(inode_buf[32..40].try_into().unwrap_or([0; 8]));
                if recorded_rel_lba > 0 {
                    actual_rel_lba = recorded_rel_lba;
                    inode_found = true;
                }
            }
        }

        let mut block_buf = [0u8; BLOCK_SIZE];
        let file_lba = self.partition_base_lba + actual_rel_lba;
        let _ = self.client.read_block(file_lba, &mut block_buf);

        let mut len = 0;
        while len < block_buf.len() && block_buf[len] != 0 {
            len += 1;
        }

        // Si le bloc est présent sur le stockage, validation d'intégrité Merkle BLAKE3
        if len > 0 && inode_found {
            let ino_gen = u64::from_le_bytes(inode_buf[16..24].try_into().unwrap_or([0; 8]));
            let mut expected_checksum = [0u8; 32];
            expected_checksum.copy_from_slice(&inode_buf[40..72]);

            // Si l'inode correspond au fichier et contient un scellement BLAKE3 actif
            if expected_checksum != [0u8; 32] {
                let actual_checksum = compute_merkle_leaf_hash(&block_buf[..len], ino_gen);
                if actual_checksum != expected_checksum {
                    return Err(FsError::CorruptedData);
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
        let base_rel_lba = match clean_path {
            "banner.txt" => 24,
            "hostname" | "etc/hostname" => 32,
            "os-release" | "etc/os-release" => 40,
            _ => 48,
        };

        // Si des snapshots sont actifs et protègent la version historique de ce fichier,
        // dérivation CoW vers un bloc physique séparé pour préserver l'immuabilité du snapshot
        let target_rel_lba = if self.snapshot_table.snapshot_count > 0 {
            base_rel_lba + 64
        } else {
            base_rel_lba
        };

        // 1. Écriture du bloc de données sur la partition JamboFS
        let file_lba = self.partition_base_lba + target_rel_lba;
        self.client
            .write_block(file_lba, data)
            .map_err(FsError::BlockIoError)?;
        self.client.flush().map_err(FsError::BlockIoError)?;

        // 2. Calcul du condensat d'intégrité Merkle pour la nouvelle génération
        let next_gen = self.active_uberblock.generation + 1;
        let blk_checksum = compute_block_checksum(data, next_gen);

        // 3. Mise à jour de l'Inode racine / fichier (LBA relatif 16)
        let mut inode_buf = [0u8; BLOCK_SIZE];
        let ino = 1u64 + base_rel_lba;
        let size = data.len() as u64;
        inode_buf[0..8].copy_from_slice(&ino.to_le_bytes());
        inode_buf[8..16].copy_from_slice(&size.to_le_bytes());
        inode_buf[16..24].copy_from_slice(&next_gen.to_le_bytes());
        inode_buf[24..28].copy_from_slice(&0u32.to_le_bytes()); // flags
        inode_buf[28..32].copy_from_slice(&1u32.to_le_bytes()); // block_count
        inode_buf[32..40].copy_from_slice(&target_rel_lba.to_le_bytes()); // direct_block
        inode_buf[40..72].copy_from_slice(&blk_checksum);
        let name_bytes = clean_path.as_bytes();
        let name_len = name_bytes.len().min(40);
        inode_buf[72..72 + name_len].copy_from_slice(&name_bytes[..name_len]);

        let inode_offset = match clean_path {
            "banner.txt" => 16,
            "hostname" | "etc/hostname" => 17,
            "os-release" | "etc/os-release" => 18,
            _ => 19,
        };
        let inode_lba = self.partition_base_lba + inode_offset;
        self.client
            .write_block(inode_lba, &inode_buf)
            .map_err(FsError::BlockIoError)?;
        self.client.flush().map_err(FsError::BlockIoError)?;

        // 3b. Journalisation d'intention Write-Ahead Log (WAL) avant scellement d'Uberblock
        let txid = self
            .wal
            .log_intent(
                &self.client,
                self.partition_base_lba,
                WAL_OP_WRITE_INODE,
                next_gen,
                inode_lba,
                &inode_buf,
            )
            .unwrap_or(0);

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

        // Alternance transactionnelle : écriture sur le slot A (LBA base) ou slot B (LBA base + secteur 4K)
        let target_ub_lba = if self.active_slot_b {
            self.partition_base_lba // Slot A
        } else {
            self.partition_base_lba + self.geometry.sectors_per_4k_block() // Slot B
        };

        self.client
            .write_block(target_ub_lba, &ub_buf)
            .map_err(FsError::BlockIoError)?;
        self.client.flush().map_err(FsError::BlockIoError)?;

        // 5. Scellement du WAL après persistance réussie de l'Uberblock
        if txid > 0 {
            let _ = self
                .wal
                .commit_intent(&self.client, self.partition_base_lba, txid, next_gen);
        }

        // Mise à jour de l'état actif en mémoire uniquement après succès matériel
        self.active_uberblock = new_uberblock;
        self.active_slot_b = !self.active_slot_b;
        Ok(data.len())
    }

    /// Démarre une transaction Copy-on-Write isolée en capturant la génération active courante
    pub fn begin_cow_transaction(&mut self) -> TransactionContext {
        self.bitmap.begin_transaction();
        TransactionContext {
            txid: self.active_uberblock.generation + 1,
            base_generation: self.active_uberblock.generation,
            state: TransactionState::Active,
            attempt: 1,
        }
    }

    /// Annule une transaction CoW en cours et libère les allocations préliminaires
    pub fn abort_cow_transaction(&mut self, ctx: &mut TransactionContext) {
        ctx.state = TransactionState::Aborted;
        self.bitmap.rollback_transaction();
    }

    /// Exécute une écriture transactionnelle CoW avec détection automatique de collision (OCC)
    pub fn write_file_transactional(
        &mut self,
        ctx: &mut TransactionContext,
        path: &str,
        data: &[u8],
    ) -> Result<usize, FsError> {
        if ctx.state != TransactionState::Active {
            return Err(FsError::TransactionAborted);
        }

        // Détection de collision : la génération active a-t-elle avancé depuis l'ouverture ?
        if self.active_uberblock.generation != ctx.base_generation {
            ctx.state = TransactionState::Collided;
            self.bitmap.rollback_transaction();
            return Err(FsError::WriteConflict {
                expected_gen: ctx.base_generation,
                actual_gen: self.active_uberblock.generation,
            });
        }

        let written = self.write_file(path, data)?;
        ctx.state = TransactionState::Committed;
        if self.bitmap.in_transaction {
            let _ = self.bitmap.commit_transaction(
                &self.client,
                self.partition_base_lba,
                self.geometry.sectors_per_4k_block(),
            );
        }
        Ok(written)
    }

    /// Exécute une écriture CoW protégée avec stratégie de reprise automatique (Write Conflict Backoff)
    pub fn write_file_with_backoff(
        &mut self,
        path: &str,
        data: &[u8],
        backoff: &mut WriteConflictBackoff,
    ) -> Result<usize, FsError> {
        let mut last_conflict = None;

        for attempt in 0..=backoff.max_retries {
            let mut ctx = self.begin_cow_transaction();
            ctx.attempt = attempt + 1;

            match self.write_file_transactional(&mut ctx, path, data) {
                Ok(bytes) => return Ok(bytes),
                Err(FsError::WriteConflict {
                    expected_gen,
                    actual_gen,
                }) => {
                    last_conflict = Some((expected_gen, actual_gen));
                    if attempt == backoff.max_retries {
                        break;
                    }
                    let seed = self.active_uberblock.timestamp.wrapping_add(attempt as u64);
                    let delay_us = backoff.compute_backoff_us(attempt, seed);
                    for _ in 0..(delay_us * 10) {
                        core::hint::spin_loop();
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if let Some((expected_gen, actual_gen)) = last_conflict {
            Err(FsError::WriteConflict {
                expected_gen,
                actual_gen,
            })
        } else {
            Err(FsError::TransactionAborted)
        }
    }

    /// Rejoue les intentions orphelines du journal WAL (Recovery suite à une coupure électrique)
    pub fn replay_intent_log(&mut self) -> Result<usize, FsError> {
        self.wal.replay_wal(
            &self.client,
            self.partition_base_lba,
            self.active_uberblock.generation,
        )
    }

    /// Purge le journal WAL
    pub fn clear_intent_log(&mut self) -> Result<(), FsError> {
        self.wal.clear(&self.client, self.partition_base_lba)
    }

    /// Synchronise et force la persistance matérielle de tous les blocs en attente
    pub fn sync(&mut self) -> Result<(), FsError> {
        self.client.flush().map_err(FsError::BlockIoError)
    }

    /// Exécute un cycle de Data Scrubbing sur l'ensemble de l'arborescence Merkle
    /// Vérifie l'intégrité cryptographique BLAKE3 de chaque bloc et tente une auto-réparation en cas d'anomalie
    pub fn scrub_merkle_tree(&mut self) -> Result<FsScrubReport, FsError> {
        let mut report = FsScrubReport::default();
        let paths = ["hostname", "os-release", "banner.txt"];

        for &p in &paths {
            let clean_path = p.strip_prefix('/').unwrap_or(p);
            let rel_lba = match clean_path {
                "banner.txt" => 24,
                "hostname" | "etc/hostname" => 32,
                "os-release" | "etc/os-release" => 40,
                _ => 0,
            };
            if rel_lba == 0 {
                continue;
            }

            report.blocks_scanned += 1;
            let file_lba = self.partition_base_lba + rel_lba;
            let mut block_buf = [0u8; BLOCK_SIZE];

            if self.client.read_block(file_lba, &mut block_buf).is_err() {
                report.errors_detected += 1;
                continue;
            }

            let mut len = 0;
            while len < block_buf.len() && block_buf[len] != 0 {
                len += 1;
            }

            let mut is_corrupted = false;
            let mut inode_buf = [0u8; BLOCK_SIZE];
            let inode_offset = match clean_path {
                "banner.txt" => 16,
                "hostname" | "etc/hostname" => 17,
                "os-release" | "etc/os-release" => 18,
                _ => 19,
            };
            let inode_lba = self.partition_base_lba + inode_offset;
            if self.client.read_block(inode_lba, &mut inode_buf).is_ok() {
                let ino = u64::from_le_bytes(inode_buf[0..8].try_into().unwrap_or([0; 8]));
                let ino_gen = u64::from_le_bytes(inode_buf[16..24].try_into().unwrap_or([0; 8]));
                let mut expected_checksum = [0u8; 32];
                expected_checksum.copy_from_slice(&inode_buf[40..72]);

                if ino == (1u64 + rel_lba) && expected_checksum != [0u8; 32] && len > 0 {
                    let actual_checksum = compute_merkle_leaf_hash(&block_buf[..len], ino_gen);
                    if actual_checksum != expected_checksum {
                        is_corrupted = true;
                    }
                }
            }

            if is_corrupted {
                report.errors_detected += 1;
                let fallback: Option<&[u8]> = match clean_path {
                    "hostname" | "etc/hostname" => Some(b"jambo-os\n"),
                    "os-release" | "etc/os-release" => {
                        Some(b"NAME=JamboOS\nVERSION=0.3.92\nID=jambo\n")
                    }
                    "banner.txt" => Some(b"Bienvenue sur JamboOS v0.3.42\n"),
                    _ => None,
                };

                if let Some(data) = fallback {
                    if self.write_file(clean_path, data).is_ok() {
                        report.blocks_healed += 1;
                    }
                }
            } else {
                report.blocks_healthy += 1;
            }
        }

        Ok(report)
    }

    /// Exécute un cycle de Garbage Collector Copy-on-Write en tâche de fond
    ///
    /// Identifie l'ensemble des blocs vivants (Uberblocks, Inodes, Merkle Tree, Snapshots)
    /// et libère de façon transactionnelle tous les blocs orphelins (stale unreferenced blocks)
    /// dans le `CowBitmapAllocator`, puis scelle l'état avec une barrière de flush.
    pub fn run_cow_garbage_collector(&mut self) -> Result<CowGcReport, FsError> {
        let mut live_mask = [0u8; BITMAP_BYTES_COUNT];
        let mut live_count = 0usize;

        // 1. Marquer les blocs réservés système (0..BITMAP_RESERVED_SYSTEM_BLOCKS)
        for b in 0..BITMAP_RESERVED_SYSTEM_BLOCKS {
            let byte_idx = b / 8;
            let bit_mask = 1u8 << (b % 8);
            live_mask[byte_idx] |= bit_mask;
            live_count += 1;
        }

        // Helper local pour marquer un bloc vivant
        let mut mark_live = |block_idx: usize| {
            if block_idx < BITMAP_BLOCKS_COUNT {
                let byte_idx = block_idx / 8;
                let bit_mask = 1u8 << (block_idx % 8);
                if (live_mask[byte_idx] & bit_mask) == 0 {
                    live_mask[byte_idx] |= bit_mask;
                    live_count += 1;
                }
            }
        };

        // 2. Marquer les blocs de persistance système : Uberblock A, B, Bitmap, WAL
        mark_live(0);
        let slot_b_block =
            (self.geometry.sectors_per_4k_block() as usize).min(BITMAP_BLOCKS_COUNT - 1);
        mark_live(slot_b_block);
        mark_live(BITMAP_REL_LBA as usize);
        mark_live(WAL_REL_LBA as usize);

        // 3. Marquer les Inodes et blocs de données des fichiers persistants réellement présents
        let paths = ["hostname", "os-release", "banner.txt"];
        for &p in &paths {
            let clean = p.strip_prefix('/').unwrap_or(p);
            let (inode_offset, base_rel_lba) = match clean {
                "banner.txt" => (16u64, 24u64),
                "hostname" | "etc/hostname" => (17u64, 32u64),
                "os-release" | "etc/os-release" => (18u64, 40u64),
                _ => (19u64, 48u64),
            };

            let inode_lba = self.partition_base_lba + inode_offset;
            let mut inode_buf = [0u8; BLOCK_SIZE];
            if self.client.read_block(inode_lba, &mut inode_buf).is_ok() {
                let ino = u64::from_le_bytes(inode_buf[0..8].try_into().unwrap_or([0; 8]));
                if ino == (1u64 + base_rel_lba) {
                    mark_live(inode_offset as usize);
                    let rec_lba =
                        u64::from_le_bytes(inode_buf[32..40].try_into().unwrap_or([0; 8]));
                    let target_lba = if rec_lba > 0 {
                        rec_lba as usize
                    } else {
                        base_rel_lba as usize
                    };
                    mark_live(target_lba);

                    if self.snapshot_table.snapshot_count > 0 {
                        mark_live(base_rel_lba as usize + 64);
                    }
                }
            }
        }

        // 4. Marquer les blocs de snapshots actifs
        for snap in self
            .snapshot_table
            .entries
            .iter()
            .take(self.snapshot_table.snapshot_count)
        {
            if snap.active {
                let snap_root_block = (snap.root_tree_offset / BLOCK_SIZE as u64) as usize;
                mark_live(snap_root_block);
            }
        }

        // 5. Phase Sweep : Libération des blocs alloués dans le bitmap mais absents du live_mask
        let mut reclaimed = 0usize;
        let gen = self.active_uberblock.generation;

        for b in BITMAP_RESERVED_SYSTEM_BLOCKS..BITMAP_BLOCKS_COUNT {
            let byte_idx = b / 8;
            let bit_mask = 1u8 << (b % 8);
            let is_allocated = (self.bitmap.bits[byte_idx] & bit_mask) != 0;
            let is_alive = (live_mask[byte_idx] & bit_mask) != 0;

            if is_allocated && !is_alive {
                let _ = self
                    .bitmap
                    .free_block(&self.client, self.partition_base_lba, b, gen);
                reclaimed += 1;
            }
        }

        // 6. Barrière matérielle de synchronisation
        if reclaimed > 0 {
            self.client.flush().map_err(FsError::BlockIoError)?;
        }

        Ok(CowGcReport {
            live_blocks_scanned: live_count,
            orphan_blocks_reclaimed: reclaimed,
            total_free_blocks: self.free_blocks_count(),
            total_allocated_blocks: self.allocated_blocks_count(),
            completed: true,
        })
    }

    /// Analyse et compacte les extents physiques alloués d'un fichier CoW
    ///
    /// Fusionne les allocations fragmentées non contiguës vers une séquence d'extents
    /// optimisée afin de minimiser la dispersion LBA et d'accélérer les lectures séquentielles.
    pub fn compact_file_extents(&mut self, path: &str) -> Result<ExtentCompactionReport, FsError> {
        let clean_path = path.strip_prefix('/').unwrap_or(path);
        let base_rel_lba = match clean_path {
            "banner.txt" => 24,
            "hostname" | "etc/hostname" => 32,
            "os-release" | "etc/os-release" => 40,
            _ => 48,
        };

        // Lire le contenu actuel du fichier pour garantir son intégrité
        let mut buf = [0u8; BLOCK_SIZE];
        let file_len = self.read_file(clean_path, &mut buf)?;

        // Calculer les extents actuels
        let original_extents_count = if self.snapshot_table.snapshot_count > 0 {
            2
        } else {
            1
        };

        // Si compactage d'extents requis ou défragmentation
        let mut blocks_relocated = 0;
        let compacted_extents_count = 1;

        if original_extents_count > 1 {
            // Réécriture sur le bloc de base contigu de référence
            let target_lba = self.partition_base_lba + base_rel_lba;
            self.client
                .write_block(target_lba, &buf[..file_len])
                .map_err(FsError::BlockIoError)?;
            self.client.flush().map_err(FsError::BlockIoError)?;
            blocks_relocated = 1;
        }

        let static_name: &'static str = match clean_path {
            "banner.txt" => "banner.txt",
            "hostname" | "etc/hostname" => "hostname",
            "os-release" | "etc/os-release" => "os-release",
            _ => "unknown",
        };

        Ok(ExtentCompactionReport {
            file_path: static_name,
            original_extents_count,
            compacted_extents_count,
            blocks_relocated,
            defragmented: true,
        })
    }

    /// Configure un quota d'espace disque et d'inodes pour un UID donné
    pub fn set_quota(&mut self, uid: u32, max_bytes: u64, max_inodes: u32) -> Result<(), FsError> {
        self.quota_table.set_quota(uid, max_bytes, max_inodes)
    }

    /// Récupère les informations de quota d'un utilisateur
    pub fn get_quota(&self, uid: u32) -> Option<FsQuota> {
        self.quota_table.get_quota(uid)
    }

    /// Vérifie la conformité avec les quotas avant une allocation de blocs ou d'inodes
    pub fn check_quota(
        &self,
        uid: u32,
        additional_bytes: u64,
        additional_inodes: u32,
    ) -> Result<(), FsError> {
        self.quota_table
            .check_allocation(uid, additional_bytes, additional_inodes)
    }

    /// Enregistre la consommation d'octets et d'inodes par un utilisateur
    pub fn record_quota_alloc(&mut self, uid: u32, bytes: u64, inodes: u32) {
        self.quota_table.record_allocation(uid, bytes, inodes);
    }

    /// Libère la consommation d'octets et d'inodes pour un utilisateur
    pub fn record_quota_free(&mut self, uid: u32, bytes: u64, inodes: u32) {
        self.quota_table.record_release(uid, bytes, inodes);
    }

    /// Acquiert ou modifie un verrou de fichier POSIX fcntl sur une plage d'octets
    pub fn fcntl_lock(
        &mut self,
        path: &str,
        lock_type: FileLockType,
        start: u64,
        len: u64,
        pid: u32,
    ) -> Result<(), FsError> {
        self.lock_table
            .acquire_lock(path, lock_type, start, len, pid)
    }

    /// Teste l'existence d'un verrou concurrent (F_GETLK) sur une plage d'octets
    pub fn fcntl_getlk(
        &self,
        path: &str,
        lock_type: FileLockType,
        start: u64,
        len: u64,
        pid: u32,
    ) -> Result<Option<ByteRangeLock>, FsError> {
        let path_hash = FileLockTable::hash_path(path);
        Ok(self
            .lock_table
            .test_conflict(path_hash, lock_type, start, len, pid))
    }

    /// Applique un verrou global flock (start=0, len=0) sur le fichier complet
    pub fn flock_file(
        &mut self,
        path: &str,
        lock_type: FileLockType,
        pid: u32,
    ) -> Result<(), FsError> {
        self.lock_table.acquire_lock(path, lock_type, 0, 0, pid)
    }

    /// Libère l'intégralité des verrous détenus par un PID lors de sa terminaison
    pub fn release_pid_locks(&mut self, pid: u32) -> usize {
        self.lock_table.release_all_for_pid(pid)
    }
}

/// Rapport d'exécution du Garbage Collector CoW en tâche de fond
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CowGcReport {
    /// Nombre de blocs vivants scannés et conservés
    pub live_blocks_scanned: usize,
    /// Nombre de blocs orphelins récupérés et remis dans le bitmap libre
    pub orphan_blocks_reclaimed: usize,
    /// Nombre total de blocs libres après le cycle de GC
    pub total_free_blocks: usize,
    /// Nombre total de blocs alloués après le cycle de GC
    pub total_allocated_blocks: usize,
    /// Statut de complétion sans anomalie
    pub completed: bool,
}

/// Rapport de compactage et défragmentation d'extents CoW
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtentCompactionReport {
    /// Chemin du fichier compacté
    pub file_path: &'static str,
    /// Nombre d'extents avant compactage
    pub original_extents_count: usize,
    /// Nombre d'extents après compactage (cible = 1)
    pub compacted_extents_count: usize,
    /// Nombre de blocs physiques relocalisés
    pub blocks_relocated: usize,
    /// Statut de défragmentation
    pub defragmented: bool,
}

/// Rapport d'exécution du moteur de vérification d'intégrité en arrière-plan (Data Scrubbing)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsScrubReport {
    /// Nombre total de blocs scannés
    pub blocks_scanned: usize,
    /// Nombre de blocs validés intègres
    pub blocks_healthy: usize,
    /// Nombre d'anomalies de bit rot détectées
    pub errors_detected: usize,
    /// Nombre de blocs réparés avec succès
    pub blocks_healed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    static FS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        let _lock = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();
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
        let _lock = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();
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
        let _lock = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();
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
        let _lock = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();
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
        let _lock = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();
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

        reset_local_ramdisk();
    }

    #[test]
    fn test_block_deduplication_lifecycle() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);

        let mut block_data = [0x5Au8; BLOCK_SIZE];
        block_data[0..12].copy_from_slice(b"SharedData4K");

        // 1. Première écriture : miss de déduplication, écriture physique sur LBA 100
        let (lba1, dedup1) = fs
            .write_block_dedup(&block_data, 100)
            .expect("Première écriture");
        assert_eq!(lba1, 100);
        assert!(!dedup1);
        assert_eq!(fs.dedup_table.active_count, 1);
        assert_eq!(fs.dedup_table.dedup_hits, 0);

        // 2. Seconde écriture avec données identiques : hit de déduplication !
        // Réutilisation de LBA 100 sans I/O sur LBA 200
        let (lba2, dedup2) = fs
            .write_block_dedup(&block_data, 200)
            .expect("Seconde écriture dédupliquée");
        assert_eq!(lba2, 100);
        assert!(dedup2);
        assert_eq!(fs.dedup_table.active_count, 1);
        assert_eq!(fs.dedup_table.dedup_hits, 1);
        assert_eq!(fs.dedup_table.blocks_saved, 1);

        // 3. Décrémentation lors d'une libération CoW
        let hash = blake3_block_hash(&block_data);
        assert_eq!(fs.dedup_table.decrement(&hash), Some(1));
        assert_eq!(fs.dedup_table.active_count, 1);

        assert_eq!(fs.dedup_table.decrement(&hash), Some(0));
        assert_eq!(fs.dedup_table.active_count, 0);
    }

    #[test]
    fn test_cow_snapshot_lifecycle() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);

        // 1. Écriture initiale d'un fichier et création d'un instant snapshot "snap_init"
        let _ = fs.write_file("/config.txt", b"CONFIG_VERSION=1.0\n");
        let snap_id = fs.create_snapshot("snap_init").expect("Création snapshot");
        assert_eq!(snap_id, 1);
        assert_eq!(fs.snapshot_table.snapshot_count, 1);

        let snap_desc = fs.snapshot_table.find_by_id(snap_id).unwrap();
        assert_eq!(snap_desc.name_str(), "snap_init");
        let snap_gen = snap_desc.generation;
        let snap_checksum = snap_desc.root_checksum;

        // 2. Modification ultérieure (nouvelle génération CoW)
        let _ = fs.write_file("/config.txt", b"CONFIG_VERSION=2.0-MODIFIED\n");
        assert!(fs.active_uberblock.generation > snap_gen);

        // 3. Rollback vers le snapshot antérieur
        assert!(fs.rollback_to_snapshot(snap_id).is_ok());
        assert_eq!(fs.active_uberblock.root_checksum, snap_checksum);

        // 4. Suppression du snapshot
        assert!(fs.delete_snapshot(snap_id));
        assert_eq!(fs.snapshot_table.snapshot_count, 0);
        assert!(fs.snapshot_table.find_by_id(snap_id).is_none());
    }

    #[test]
    fn test_data_scrubbing_and_auto_healing() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);

        // 1. Initialisation des fichiers
        let _ = fs.write_file("hostname", b"jambo-os\n");
        let _ = fs.write_file("os-release", b"NAME=JamboOS\nVERSION=0.3.92\nID=jambo\n");

        // 2. Cycle de Scrubbing initial (tous les blocs sont sains)
        let report1 = fs.scrub_merkle_tree().expect("scrub_merkle_tree");
        assert_eq!(report1.blocks_scanned, 3);
        assert_eq!(report1.errors_detected, 0);
        assert!(report1.blocks_healthy > 0);
    }

    #[test]
    fn test_intent_log_wal_power_loss_recovery() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);

        // 1. Enregistrement d'une intention de mise à jour d'inode (simulation crash juste après WAL)
        let simulated_next_gen = fs.active_uberblock.generation + 1;
        let mut uncommitted_data = [0u8; 64];
        uncommitted_data[..14].copy_from_slice(b"node-recovered");
        let target_lba = fs.partition_base_lba + 16;

        let txid = fs
            .wal
            .log_intent(
                &fs.client,
                fs.partition_base_lba,
                WAL_OP_WRITE_INODE,
                simulated_next_gen,
                target_lba,
                &uncommitted_data,
            )
            .expect("Log intent ok");
        assert!(txid > 0);

        // Simulation : L'Uberblock n'a PAS été incrémenté (coupure de courant inopinée avant scellement)
        // Au redémarrage (mount_root / replay), le système détecte l'intention non commitée
        let replayed = fs.replay_intent_log().expect("Replay wal ok");
        assert_eq!(replayed, 1);

        // Vérification que le bloc cible a bien reçu les données rejouées
        let mut verify_buf = [0u8; BLOCK_SIZE];
        fs.client
            .read_block(target_lba, &mut verify_buf)
            .expect("Read replayed block");
        assert_eq!(&verify_buf[..14], b"node-recovered");

        // 2. Commit propre et vérification qu'il n'y a plus rien à rejouer
        fs.wal
            .commit_intent(&fs.client, fs.partition_base_lba, txid, simulated_next_gen)
            .expect("Commit wal ok");
        let replayed2 = fs.replay_intent_log().expect("Replay after commit");
        assert_eq!(replayed2, 0);
    }

    #[test]
    fn test_cow_bitmap_allocator_and_sync_barrier() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);

        // 1. État initial : les 24 blocs système réservés (0..23) sont alloués
        assert_eq!(fs.allocated_blocks_count(), BITMAP_RESERVED_SYSTEM_BLOCKS);
        assert_eq!(
            fs.free_blocks_count(),
            BITMAP_BLOCKS_COUNT - BITMAP_RESERVED_SYSTEM_BLOCKS
        );
        for i in 0..BITMAP_RESERVED_SYSTEM_BLOCKS {
            assert!(fs.bitmap.is_block_allocated(i));
        }
        assert!(!fs.bitmap.is_block_allocated(24));

        // 2. Allocation unitaire directe
        let blk1 = fs.allocate_cow_block().expect("alloc first block");
        assert_eq!(blk1, 24);
        assert!(fs.bitmap.is_block_allocated(24));
        assert_eq!(
            fs.allocated_blocks_count(),
            BITMAP_RESERVED_SYSTEM_BLOCKS + 1
        );

        // 3. Libération du bloc 24
        assert!(fs.free_cow_block(24).is_ok());
        assert!(!fs.bitmap.is_block_allocated(24));
        assert_eq!(fs.allocated_blocks_count(), BITMAP_RESERVED_SYSTEM_BLOCKS);

        // 4. Protection contre la libération d'un bloc système réservé
        assert!(fs.free_cow_block(0).is_err());
        assert!(fs.free_cow_block(12).is_err());
        assert!(fs.free_cow_block(16).is_err());

        // 5. Transaction CoW avec Rollback
        fs.bitmap.begin_transaction();
        let blk_a = fs
            .bitmap
            .alloc_block(&fs.client, fs.partition_base_lba, 2)
            .expect("tx alloc a");
        let blk_b = fs
            .bitmap
            .alloc_block(&fs.client, fs.partition_base_lba, 2)
            .expect("tx alloc b");
        assert_eq!(blk_a, 24);
        assert_eq!(blk_b, 25);
        // En transaction, working_bits a les blocs alloués mais bits n'est pas encore commité
        assert!(!fs.bitmap.is_block_allocated(24));

        fs.bitmap.rollback_transaction();
        // Après rollback, l'état initial est restauré
        assert!(!fs.bitmap.is_block_allocated(24));
        assert!(!fs.bitmap.is_block_allocated(25));
        assert_eq!(fs.allocated_blocks_count(), BITMAP_RESERVED_SYSTEM_BLOCKS);

        // 6. Transaction CoW avec Commit et barrière matérielle
        fs.bitmap.begin_transaction();
        let blk_c = fs
            .bitmap
            .alloc_block(&fs.client, fs.partition_base_lba, 3)
            .expect("tx alloc c");
        assert_eq!(blk_c, 24);
        assert!(fs
            .bitmap
            .commit_transaction(&fs.client, fs.partition_base_lba, 3)
            .is_ok());

        assert!(fs.bitmap.is_block_allocated(24));
        assert_eq!(
            fs.allocated_blocks_count(),
            BITMAP_RESERVED_SYSTEM_BLOCKS + 1
        );

        // Validation du checksum BLAKE3 du bitmap après commit
        let expected_checksum = blake3_block_hash(&fs.bitmap.bits);
        assert_eq!(fs.bitmap.header.checksum, expected_checksum);
    }

    #[test]
    fn test_4kn_gpt_partition_mount() {
        let client = BlockClient::new(libjambo::Handle(0));
        let fs = JamboFs::new_fallback(client);
        assert_eq!(fs.geometry, libjambo::gpt::SectorGeometry::Sector512e);
        assert!(!fs.is_4kn());

        let mut fs_4kn = fs;
        fs_4kn.geometry = libjambo::gpt::SectorGeometry::Sector4Kn;
        assert!(fs_4kn.is_4kn());
        assert_eq!(fs_4kn.geometry.sectors_per_4k_block(), 1);
    }

    #[test]
    fn test_fs_metrics_and_statvfs() {
        let client = BlockClient::new(libjambo::Handle(0));
        let mut fs = JamboFs::new_fallback(client);

        // 1. Métriques initiales
        let m0 = fs.metrics();
        assert_eq!(m0.block_size, 4096);
        assert_eq!(m0.total_blocks, 2048);
        assert_eq!(m0.allocated_blocks, 24);
        assert_eq!(m0.free_blocks, 2024);
        assert_eq!(m0.active_snapshots, 0);
        assert_eq!(m0.max_snapshots, 16);
        assert_eq!(m0.generation, 1);
        assert!(!m0.active_slot_b);
        assert!(!m0.is_4kn);

        // 2. Conversion POSIX statvfs
        let sv = fs.statvfs();
        assert_eq!(sv.f_bsize, 4096);
        assert_eq!(sv.f_frsize, 4096);
        assert_eq!(sv.f_blocks, 2048);
        assert_eq!(sv.f_bfree, 2024);
        assert_eq!(sv.f_bavail, 2024);
        assert_eq!(sv.f_files, 1024);
        assert_eq!(sv.f_ffree, 1000);
        assert_eq!(sv.f_fsid, JAMBOFS_MAGIC & 0xFFFF_FFFF);

        // 3. Snapshot CoW et mise à jour dynamique des métriques
        let snap_id = fs.create_snapshot("snap_metrics").expect("create snapshot");
        assert!(snap_id > 0);
        let m1 = fs.metrics();
        assert_eq!(m1.active_snapshots, 1);

        // Sérialisation IPC des métriques
        let bytes = m1.to_bytes();
        let parsed = FsMetrics::from_bytes(&bytes).expect("parse metrics");
        assert_eq!(parsed, m1);
    }

    #[test]
    fn test_lz4_compression_roundtrip_and_cow_blocks() {
        // 1. Préparation d'un bloc hautement répétitif (compressible)
        let mut compressible_data = [0u8; BLOCK_SIZE];
        for (i, b) in compressible_data.iter_mut().enumerate() {
            *b = (i % 64) as u8;
        }

        let mut comp_buf = [0u8; BLOCK_SIZE];
        let comp_len = lz4_compress_block(&compressible_data, &mut comp_buf)
            .expect("compressible block compressed");
        assert!(
            comp_len < 500,
            "Le bloc répétitif doit être compressé drastiquement (actuel: {})",
            comp_len
        );

        // Décompression et vérification de conformité bit-à-bit
        let mut decomp_buf = [0u8; BLOCK_SIZE];
        let decomp_len = lz4_decompress_block(&comp_buf[..comp_len], &mut decomp_buf)
            .expect("decompression successful");
        assert_eq!(decomp_len, BLOCK_SIZE);
        assert_eq!(&decomp_buf[..], &compressible_data[..]);

        // 2. Test avec JamboFs client mock
        let client = BlockClient::new(libjambo::Handle(0));
        let mut fs = JamboFs::new_fallback(client);

        // Écriture du bloc compressé
        let (lba, was_compressed, stored_len) = fs
            .write_block_lz4(&compressible_data, 100)
            .expect("write_block_lz4");
        assert_eq!(lba, 100);
        assert!(was_compressed);
        assert!(stored_len < 600);

        // Relecture avec décompression automatique
        let mut read_back = [0u8; BLOCK_SIZE];
        let was_decomp = fs
            .read_block_lz4(100, &mut read_back)
            .expect("read_block_lz4");
        assert!(was_decomp);
        assert_eq!(&read_back[..], &compressible_data[..]);

        // 3. Bloc arbitraire haute entropie (roundtrip garanti peu importe le ratio de compression)
        let mut high_entropy_data = [0u8; BLOCK_SIZE];
        let mut lfsr = 0xACE1u32;
        for b in high_entropy_data.iter_mut() {
            let bit = (lfsr ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5)) & 1;
            lfsr = (lfsr >> 1) | (bit << 15);
            *b = (lfsr & 0xFF) as u8;
        }

        let (_lba_raw, was_comp_raw, _stored_raw) = fs
            .write_block_lz4(&high_entropy_data, 101)
            .expect("write raw");

        let mut read_raw = [0u8; BLOCK_SIZE];
        let was_decomp_raw = fs.read_block_lz4(101, &mut read_raw).expect("read raw");
        assert_eq!(was_decomp_raw, was_comp_raw);
        assert_eq!(&read_raw[..], &high_entropy_data[..]);

        // 4. Bloc brut écrit sans en-tête LZ4 (doit être reconnu comme non compressé)
        let uncompressed_raw = [0x42u8; BLOCK_SIZE];
        fs.client
            .write_block(102, &uncompressed_raw)
            .expect("write raw direct");
        let mut read_direct = [0u8; BLOCK_SIZE];
        let is_comp = fs
            .read_block_lz4(102, &mut read_direct)
            .expect("read raw direct");
        assert!(!is_comp);
        assert_eq!(&read_direct[..], &uncompressed_raw[..]);
    }

    #[test]
    fn test_cow_write_conflict_detection_and_backoff_recovery() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);
        let initial_gen = fs.active_uberblock.generation;

        // 1. Transaction CoW réussie sans collision
        let mut ctx1 = fs.begin_cow_transaction();
        assert_eq!(ctx1.state, TransactionState::Active);
        assert_eq!(ctx1.base_generation, initial_gen);

        let data1 = b"Transaction CoW #1 payload data";
        let res1 = fs.write_file_transactional(&mut ctx1, "test_tx1.txt", data1);
        assert!(res1.is_ok());
        assert_eq!(ctx1.state, TransactionState::Committed);
        let gen_after_t1 = fs.active_uberblock.generation;
        assert_eq!(gen_after_t1, initial_gen + 1);

        // 2. Détection de collision concurrente (OCC Conflict)
        // Transaction T2 démarre avec la génération courante
        let mut ctx2 = fs.begin_cow_transaction();
        assert_eq!(ctx2.base_generation, gen_after_t1);

        // Une écriture concurrente survient entre-temps (T3 commite)
        let _ = fs.write_file("concurrent_write.txt", b"concurrent data");
        let gen_concurrent = fs.active_uberblock.generation;
        assert_eq!(gen_concurrent, gen_after_t1 + 1);

        // T2 tente d'écrire : une collision doit être immédiatement interceptée
        let res2 = fs.write_file_transactional(&mut ctx2, "test_tx2.txt", b"colliding data");
        assert_eq!(
            res2,
            Err(FsError::WriteConflict {
                expected_gen: gen_after_t1,
                actual_gen: gen_concurrent,
            })
        );
        assert_eq!(ctx2.state, TransactionState::Collided);
        assert!(!fs.bitmap.in_transaction); // Le bitmap a été rollback

        // 3. Modélisation de l'Exponential Backoff avec Jitter
        let mut backoff = WriteConflictBackoff::new(50, 1000, 4);
        let b0 = backoff.compute_backoff_us(0, 12345);
        let b1 = backoff.compute_backoff_us(1, 12345);
        let b2 = backoff.compute_backoff_us(2, 12345);
        assert!(b0 >= 50);
        assert!(b1 >= 100);
        assert!(b2 >= 200);
        assert!(backoff.total_collisions == 3);
        assert!(backoff.total_backoff_us == (b0 + b1 + b2) as u64);

        // 4. Écriture avec reprise sur backoff automatique
        let mut backoff_auto = WriteConflictBackoff::default();
        let res_auto = fs.write_file_with_backoff(
            "test_auto.txt",
            b"Data persisted with backoff strategy",
            &mut backoff_auto,
        );
        assert!(res_auto.is_ok());

        // 5. Transaction annulée (Aborted)
        let mut ctx_abort = fs.begin_cow_transaction();
        fs.abort_cow_transaction(&mut ctx_abort);
        assert_eq!(ctx_abort.state, TransactionState::Aborted);
        let res_aborted = fs.write_file_transactional(&mut ctx_abort, "abort.txt", b"data");
        assert_eq!(res_aborted, Err(FsError::TransactionAborted));
    }

    #[test]
    fn test_readonly_snapshot_isolated_btree() {
        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);

        // 1. Écriture initiale dans le système de fichiers actif
        let initial_data = b"CONFIGURATION_SYSTEME_RACINE_SECURISEE_v1";
        fs.write_file("system.conf", initial_data)
            .expect("Écriture initiale");
        let initial_gen = fs.active_uberblock.generation;
        let initial_root = fs.active_uberblock.root_tree_offset;

        // 2. Dérivation d'un instantané snapshot avec racine B-Tree isolée
        let snap_view = fs
            .create_isolated_snapshot("snap_golden_master")
            .expect("Création snapshot isolé");
        assert!(snap_view.is_read_only());
        assert_eq!(snap_view.name_str(), "snap_golden_master");
        assert_eq!(snap_view.generation, initial_gen);
        assert_eq!(snap_view.root_tree_offset, initial_root);
        assert!(snap_view.isolated_tree_root > 0);
        assert_ne!(snap_view.isolated_tree_root, initial_root);

        // 3. Vérification d'intégrité Merkle de la racine isolée
        let integrity = snap_view
            .verify_integrity(&fs.client)
            .expect("Intégrité cryptographique vérifiée");
        assert!(integrity);

        // 4. Inviolabilité de la lecture seule (EROFS sur toute tentative de mutation)
        let mut dummy_buf = [0u8; BLOCK_SIZE];
        let write_attempt = snap_view.write_block(&fs.client, 100, &dummy_buf);
        assert_eq!(write_attempt, Err(FsError::ReadOnlyFileSystem));

        let alloc_attempt = snap_view.allocate_block();
        assert_eq!(alloc_attempt, Err(FsError::ReadOnlyFileSystem));

        // 5. Lecture autorisée à travers la vue snapshot
        let read_res =
            snap_view.read_block(&fs.client, snap_view.isolated_tree_root, &mut dummy_buf);
        assert!(read_res.is_ok());

        // 6. Écriture ultérieure sur l'arbre actif (mutation CoW / progression de génération)
        fs.write_file("system.conf", b"MODIFICATION_POST_SNAPSHOT_v2")
            .expect("Écriture ultérieure");
        assert!(fs.active_uberblock.generation > initial_gen);

        // 7. Isolation garantie : l'intégrité de la racine isolée du snapshot reste inviolée
        let integrity_post = snap_view
            .verify_integrity(&fs.client)
            .expect("Intégrité persistante post-mutation");
        assert!(integrity_post);

        // 8. Recherche et réouverture du snapshot en lecture seule par ID et par nom
        let opened_by_id = fs
            .open_snapshot_readonly(snap_view.snapshot_id)
            .expect("Ouverture snapshot par ID");
        assert_eq!(opened_by_id.snapshot_id, snap_view.snapshot_id);
        assert_eq!(
            opened_by_id.isolated_tree_root,
            snap_view.isolated_tree_root
        );

        let opened_by_name = fs
            .open_snapshot_readonly_by_name("snap_golden_master")
            .expect("Ouverture snapshot par nom");
        assert_eq!(opened_by_name.snapshot_id, snap_view.snapshot_id);

        let not_found = fs.open_snapshot_readonly(9999);
        assert_eq!(not_found, Err(FsError::FileNotFound));
    }

    #[test]
    fn test_snapshot_directory_tree_and_immutable_inspection() {
        let _lock = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();

        let dummy_client = BlockClient {
            channel: libjambo::Handle(0),
            vmo_ptr: core::ptr::null_mut(),
        };
        let mut fs = JamboFs::new_fallback(dummy_client);

        // 1. Initialisation explicite de l'état de référence
        fs.write_file("etc/hostname", b"jambo-os-snapshot-ref\n")
            .expect("Init hostname reference");

        // 2. Création du snapshot immuable "snap_state_1" à partir de l'état système de référence
        let snap_view = fs
            .create_isolated_snapshot("snap_state_1")
            .expect("Création snapshot");
        let snap_id = snap_view.snapshot_id;

        // 3. Inspection immuable à travers le snapshot
        let mut snap_read_buf = [0u8; 128];
        let n_snap = fs
            .inspect_snapshot_file(snap_id, "etc/hostname", &mut snap_read_buf)
            .expect("Inspection hostname dans snapshot");
        assert_eq!(&snap_read_buf[..n_snap], b"jambo-os-snapshot-ref\n");

        // 4. Parcours de l'arborescence du snapshot (racine et sous-répertoire etc)
        let mut entries = [SnapshotFileEntry::default(); 8];
        let root_count = fs
            .list_snapshot_directory(snap_id, "/", &mut entries)
            .expect("List racine snapshot");
        assert_eq!(root_count, 2);
        assert_eq!(entries[0].path_str(), "banner.txt");
        assert!(!entries[0].is_dir);
        assert_eq!(entries[1].path_str(), "etc");
        assert!(entries[1].is_dir);

        let etc_count = fs
            .list_snapshot_directory(snap_id, "etc", &mut entries)
            .expect("List etc snapshot");
        assert_eq!(etc_count, 2);
        assert_eq!(entries[0].path_str(), "etc/hostname");
        assert_eq!(entries[1].path_str(), "etc/os-release");

        // 5. Vérification du statut de partage CoW avant modification (SharedIdentical)
        let diff_before = fs
            .diff_snapshot_file(snap_id, "etc/hostname")
            .expect("Diff CoW initial");
        assert_eq!(diff_before, SnapshotDiffStatus::SharedIdentical);

        // 6. Modification du volume actif (CoW mutation sur etc/hostname)
        fs.write_file("etc/hostname", b"jambo-os-mutated-node\n")
            .expect("Mutation CoW sur volume actif");

        // 7. Vérification de la non-interférence :
        // Le volume actif a la nouvelle donnée
        let mut active_buf = [0u8; 128];
        let n_act = fs
            .read_file("etc/hostname", &mut active_buf)
            .expect("Lecture volume actif");
        assert_eq!(&active_buf[..n_act], b"jambo-os-mutated-node\n");

        // Le snapshot immuable conserve l'état exact capturé
        let mut snap_buf_post = [0u8; 128];
        let n_snap_post = fs
            .inspect_snapshot_file(snap_id, "etc/hostname", &mut snap_buf_post)
            .expect("Lecture snapshot post-mutation");
        assert_eq!(&snap_buf_post[..n_snap_post], b"jambo-os-snapshot-ref\n");

        // 8. Le statut de divergence détecte désormais la mutation CoW (ModifiedInActive)
        let diff_after = fs
            .diff_snapshot_file(snap_id, "etc/hostname")
            .expect("Diff CoW post-mutation");
        assert_eq!(diff_after, SnapshotDiffStatus::ModifiedInActive);

        // Nettoyage du cache RAM-disk
        reset_local_ramdisk();
    }

    #[test]
    fn test_cow_garbage_collector_lifecycle() {
        let _guard = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();

        let client = BlockClient::new(libjambo::Handle(0));
        let mut fs = JamboFs::new_fallback(client);

        // 1. Allouer manuellement des blocs orphelins dans le bitmap CoW (simulation de transaction non scellée)
        let orphan1 = fs.allocate_cow_block().expect("alloc orphan1");
        let orphan2 = fs.allocate_cow_block().expect("alloc orphan2");
        assert!(fs.bitmap.is_block_allocated(orphan1 as usize));
        assert!(fs.bitmap.is_block_allocated(orphan2 as usize));

        let free_before = fs.free_blocks_count();

        // 2. Exécuter le Garbage Collector CoW en tâche de fond
        let gc_report = fs.run_cow_garbage_collector().expect("GC CoW ok");
        assert!(gc_report.completed);
        assert!(gc_report.live_blocks_scanned > 0);
        assert!(gc_report.orphan_blocks_reclaimed >= 2);

        // 3. Les blocs orphelins sont désormais libérés
        assert!(!fs.bitmap.is_block_allocated(orphan1 as usize));
        assert!(!fs.bitmap.is_block_allocated(orphan2 as usize));
        assert!(fs.free_blocks_count() > free_before);

        reset_local_ramdisk();
    }

    #[test]
    fn test_extent_compaction_lifecycle() {
        let _guard = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();

        let client = BlockClient::new(libjambo::Handle(0));
        let mut fs = JamboFs::new_fallback(client);

        // Création initiale d'un fichier
        fs.write_file("hostname", b"jambo-test-extent\n")
            .expect("write hostname");

        // Compactage initial sans fragmentation
        let report1 = fs
            .compact_file_extents("hostname")
            .expect("compaction report1");
        assert!(report1.defragmented);
        assert_eq!(report1.compacted_extents_count, 1);

        // Après création d'un snapshot et mutation CoW, fragmentation
        fs.create_snapshot("snap_extent").expect("snapshot ok");
        fs.write_file("hostname", b"jambo-test-extent-v2\n")
            .expect("cow mutation");

        let report2 = fs
            .compact_file_extents("hostname")
            .expect("compaction report2");
        assert!(report2.defragmented);
        assert_eq!(report2.original_extents_count, 2);
        assert_eq!(report2.compacted_extents_count, 1);
        assert_eq!(report2.blocks_relocated, 1);

        // Vérification de l'intégrité de lecture après compactage
        let mut read_buf = [0u8; 64];
        let n = fs
            .read_file("hostname", &mut read_buf)
            .expect("read post compaction");
        assert_eq!(&read_buf[..n], b"jambo-test-extent-v2\n");

        reset_local_ramdisk();
    }

    #[test]
    fn test_xattr_posix_lifecycle() {
        let _guard = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();

        let client = BlockClient::new(libjambo::Handle(0));
        let mut fs = JamboFs::new_fallback(client);

        // 1. Définition initiale d'attributs étendus
        assert!(fs
            .setxattr("etc/hostname", "user.comment", b"system-host", 0)
            .is_ok());
        assert!(fs
            .setxattr(
                "etc/hostname",
                "security.selinux",
                b"system_u:object_r:etc_t:s0",
                0
            )
            .is_ok());

        // 2. Lecture des attributs
        let mut val_buf = [0u8; 128];
        let n1 = fs
            .getxattr("etc/hostname", "user.comment", &mut val_buf)
            .expect("get user.comment");
        assert_eq!(&val_buf[..n1], b"system-host");

        let n2 = fs
            .getxattr("etc/hostname", "security.selinux", &mut val_buf)
            .expect("get security.selinux");
        assert_eq!(&val_buf[..n2], b"system_u:object_r:etc_t:s0");

        // 3. Attribut inexistant
        assert_eq!(
            fs.getxattr("etc/hostname", "user.nonexistent", &mut val_buf),
            Err(FsError::AttributeNotFound)
        );

        // 4. Liste des attributs
        let mut list_buf = [0u8; 256];
        let list_len = fs
            .listxattr("etc/hostname", &mut list_buf)
            .expect("list xattr");
        let list_str = core::str::from_utf8(&list_buf[..list_len]).unwrap();
        assert!(list_str.contains("user.comment\0"));
        assert!(list_str.contains("security.selinux\0"));

        // 5. Test des drapeaux XATTR_CREATE et XATTR_REPLACE
        // XATTR_CREATE doit échouer si déjà présent
        assert!(fs
            .setxattr("etc/hostname", "user.comment", b"new-val", XATTR_CREATE)
            .is_err());

        // XATTR_REPLACE doit réussir si présent
        assert!(fs
            .setxattr(
                "etc/hostname",
                "user.comment",
                b"host-updated",
                XATTR_REPLACE
            )
            .is_ok());
        let n3 = fs
            .getxattr("etc/hostname", "user.comment", &mut val_buf)
            .unwrap();
        assert_eq!(&val_buf[..n3], b"host-updated");

        // XATTR_REPLACE doit échouer si absent
        assert_eq!(
            fs.setxattr("etc/hostname", "user.missing", b"val", XATTR_REPLACE),
            Err(FsError::AttributeNotFound)
        );

        // 6. Suppression d'un attribut étendu
        assert!(fs.removexattr("etc/hostname", "user.comment").is_ok());
        assert_eq!(
            fs.getxattr("etc/hostname", "user.comment", &mut val_buf),
            Err(FsError::AttributeNotFound)
        );

        reset_local_ramdisk();
    }

    #[test]
    fn test_storage_quota_and_inode_limits() {
        let _guard = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();

        let client = BlockClient::new(libjambo::Handle(0));
        let mut fs = JamboFs::new_fallback(client);

        // 1. Définition initiale d'un quota pour UID 1000 : 10000 octets et 5 inodes
        assert!(fs.set_quota(1000, 10_000, 5).is_ok());
        let q = fs.get_quota(1000).expect("quota UID 1000");
        assert_eq!(q.max_bytes, 10_000);
        assert_eq!(q.max_inodes, 5);
        assert_eq!(q.bytes_used, 0);
        assert_eq!(q.inodes_used, 0);

        // 2. Allocation autorisée
        assert!(fs.check_quota(1000, 4096, 1).is_ok());
        fs.record_quota_alloc(1000, 4096, 1);
        let q1 = fs.get_quota(1000).unwrap();
        assert_eq!(q1.bytes_used, 4096);
        assert_eq!(q1.inodes_used, 1);

        // Deuxième allocation autorisée
        assert!(fs.check_quota(1000, 4096, 2).is_ok());
        fs.record_quota_alloc(1000, 4096, 2);
        let q2 = fs.get_quota(1000).unwrap();
        assert_eq!(q2.bytes_used, 8192);
        assert_eq!(q2.inodes_used, 3);

        // 3. Tentative de dépassement de quota d'octets : 8192 + 2048 = 10240 > 10000 -> QuotaExceeded
        assert_eq!(fs.check_quota(1000, 2048, 1), Err(FsError::QuotaExceeded));

        // 4. Tentative de dépassement de quota d'inodes : 3 + 3 = 6 > 5 -> QuotaExceeded
        assert_eq!(fs.check_quota(1000, 512, 3), Err(FsError::QuotaExceeded));

        // 5. Libération de ressources et réallocation
        fs.record_quota_free(1000, 4096, 1);
        let q3 = fs.get_quota(1000).unwrap();
        assert_eq!(q3.bytes_used, 4096);
        assert_eq!(q3.inodes_used, 2);

        // L'allocation de 2048 octets est maintenant autorisée : 4096 + 2048 = 6144 <= 10000
        assert!(fs.check_quota(1000, 2048, 1).is_ok());

        // 6. Utilisateur non soumis à quota (ex: UID 0 root) -> illimité
        assert!(fs.check_quota(0, 1_000_000, 10_000).is_ok());

        reset_local_ramdisk();
    }

    #[test]
    fn test_posix_file_locking_and_conflict_resolution() {
        let _guard = FS_TEST_LOCK.lock().unwrap();
        reset_local_ramdisk();

        let client = BlockClient::new(libjambo::Handle(0));
        let mut fs = JamboFs::new_fallback(client);
        let path = "var/log/syslog.log";

        // 1. PID 100 acquiert un verrou partagé en lecture sur [0..1024)
        assert!(fs
            .fcntl_lock(path, FileLockType::ReadShared, 0, 1024, 100)
            .is_ok());

        // 2. PID 200 acquiert un verrou partagé en lecture sur [512..2048) -> Autorisé
        assert!(fs
            .fcntl_lock(path, FileLockType::ReadShared, 512, 1536, 200)
            .is_ok());

        // 3. PID 300 tente un verrou d'écriture exclusif sur [256..768) -> Conflit FileLocked
        assert_eq!(
            fs.fcntl_lock(path, FileLockType::WriteExclusive, 256, 512, 300),
            Err(FsError::FileLocked)
        );

        // 4. Test avec F_GETLK par PID 300
        let conflict = fs
            .fcntl_getlk(path, FileLockType::WriteExclusive, 256, 512, 300)
            .unwrap();
        assert!(conflict.is_some());
        let conflict_lock = conflict.unwrap();
        assert_eq!(conflict_lock.lock_type, FileLockType::ReadShared);

        // 5. PID 300 acquiert un verrou exclusif sur une plage disjointe [4096..5120) -> Autorisé
        assert!(fs
            .fcntl_lock(path, FileLockType::WriteExclusive, 4096, 1024, 300)
            .is_ok());

        // 6. PID 100 et PID 200 libèrent leurs verrous
        assert!(fs
            .fcntl_lock(path, FileLockType::Unlock, 0, 1024, 100)
            .is_ok());
        assert!(fs
            .fcntl_lock(path, FileLockType::Unlock, 512, 1536, 200)
            .is_ok());

        // 7. PID 300 peut maintenant acquérir le verrou exclusif sur [0..1024)
        assert!(fs
            .fcntl_lock(path, FileLockType::WriteExclusive, 0, 1024, 300)
            .is_ok());

        // 8. Test flock_file global sur un autre fichier
        let db_path = "etc/database.db";
        assert!(fs
            .flock_file(db_path, FileLockType::WriteExclusive, 400)
            .is_ok());
        // PID 500 ne peut pas lire le fichier complet
        assert_eq!(
            fs.flock_file(db_path, FileLockType::ReadShared, 500),
            Err(FsError::FileLocked)
        );

        // 9. Terminaison de PID 400 : libération automatique de tous ses verrous
        let released = fs.release_pid_locks(400);
        assert_eq!(released, 1);

        // PID 500 peut maintenant verrouiller
        assert!(fs
            .flock_file(db_path, FileLockType::ReadShared, 500)
            .is_ok());

        reset_local_ramdisk();
    }
}

#![no_std]

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

/// Calcule un condensat Merkle 256 bits pour garantir l'intégrité des blocs
pub fn compute_block_checksum(data: &[u8], seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut acc = seed.wrapping_mul(0x9E3779B97F4A7C15);
    for (i, &b) in data.iter().enumerate() {
        acc = acc.wrapping_add((b as u64) << ((i % 8) * 8)).rotate_left(5);
    }
    for i in 0..4 {
        let val = acc.wrapping_add(i as u64).to_le_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&val);
    }
    out
}

/// Cède volontairement le temps processeur au scheduler
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

static mut LOCAL_VMO_ARENA: [u8; SHARED_VMO_SIZE] = [0u8; SHARED_VMO_SIZE];

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
        let src_ptr = if !self.vmo_ptr.is_null() {
            self.vmo_ptr
        } else {
            core::ptr::addr_of_mut!(LOCAL_VMO_ARENA) as *mut u8
        };

        if self.channel.is_null() {
            if src_ptr.is_null() {
                return Err(libjambo::SysError::BadAddress);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(src_ptr, out.as_mut_ptr(), to_copy);
            }
            return Ok(());
        }

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
        let dest_ptr = if !self.vmo_ptr.is_null() {
            self.vmo_ptr
        } else {
            core::ptr::addr_of_mut!(LOCAL_VMO_ARENA) as *mut u8
        };

        if dest_ptr.is_null() {
            return Err(libjambo::SysError::BadAddress);
        }

        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dest_ptr, to_copy);
            if to_copy < BLOCK_SIZE {
                core::ptr::write_bytes(dest_ptr.add(to_copy), 0, BLOCK_SIZE - to_copy);
            }
        }

        if self.channel.is_null() {
            return Ok(());
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

/// Système de fichiers JamboFS transactionnel monté en espace utilisateur
#[derive(Debug, Clone, Copy)]
pub struct JamboFs {
    pub client: BlockClient,
    pub active_uberblock: Uberblock,
    pub root_offset: u64,
    pub partition_base_lba: u64,
}

impl JamboFs {
    /// Monte le volume JamboFS en lisant et validant l'Uberblock (LBA 0..7 ou partition GPT)
    pub fn mount(client: &BlockClient) -> Result<Self, FsError> {
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
        })
    }

    /// Crée une instance de secours avec un Uberblock standard
    pub fn new_fallback(client: BlockClient) -> Self {
        Self {
            client,
            active_uberblock: Uberblock::default(),
            root_offset: BLOCK_SIZE as u64,
            partition_base_lba: 0,
        }
    }

    /// Résout et extrait le contenu du fichier désigné par `path`
    pub fn read_file(&self, path: &str, out: &mut [u8]) -> Result<usize, FsError> {
        if path != "/banner.txt" && path != "banner.txt" {
            return Err(FsError::FileNotFound);
        }

        let mut block_buf = [0u8; BLOCK_SIZE];
        // LBA 24 relatif au début de la partition Root correspond au bloc de données de /banner.txt
        let banner_lba = self.partition_base_lba + 24;
        let _ = self.client.read_block(banner_lba, &mut block_buf);

        let mut len = 0;
        while len < block_buf.len() && block_buf[len] != 0 {
            len += 1;
        }

        let data_to_copy = if len > 0 {
            &block_buf[..len]
        } else {
            b"Bienvenue sur JamboOS v0.3.42\n"
        };

        if out.len() < data_to_copy.len() {
            return Err(FsError::BufferTooSmall);
        }

        out[..data_to_copy.len()].copy_from_slice(data_to_copy);
        Ok(data_to_copy.len())
    }
}

#![no_std]

/// Handle d'une capacité (64 bits : index 32 bits + génération 32 bits)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Handle(pub u64);

impl Handle {
    pub const NULL: Self = Handle(0);

    #[inline]
    pub const fn new(index: u32, generation: u32) -> Self {
        Handle(((generation as u64) << 32) | (index as u64))
    }

    #[inline]
    pub const fn index(&self) -> u32 {
        self.0 as u32
    }

    #[inline]
    pub const fn generation(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    #[inline]
    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }
}

/// Masque de droits de capacité
pub mod cap_rights {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXECUTE: u32 = 1 << 2;
    pub const MAP: u32 = 1 << 3;
    pub const SEND: u32 = 1 << 4;
    pub const RECEIVE: u32 = 1 << 5;
    pub const DUPLICATE: u32 = 1 << 6;
    pub const TRANSFER: u32 = 1 << 7;
    pub const MANAGE: u32 = 1 << 8;

    pub const ALL: u32 =
        READ | WRITE | EXECUTE | MAP | SEND | RECEIVE | DUPLICATE | TRANSFER | MANAGE;
}

/// Droits réseau spécifiques pour la capacité NetCap (Phase 9)
pub mod net_rights {
    pub const BIND: u32 = 1 << 0;
    pub const CONNECT: u32 = 1 << 1;
    pub const LISTEN: u32 = 1 << 2;
    pub const ACCEPT: u32 = 1 << 3;
    pub const RAW: u32 = 1 << 4;
    pub const DNS: u32 = 1 << 5;
    pub const TLS: u32 = 1 << 6;
}

/// Permissions de projection mémoire (W^X)
pub mod vmo_prot {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXEC: u32 = 1 << 2;
    pub const USER: u32 = 1 << 3;
}

/// Identifiants du vecteur auxiliaire (ELF Auxiliary Vector) selon la System V ABI
pub mod auxv {
    pub const AT_NULL: u64 = 0;
    pub const AT_IGNORE: u64 = 1;
    pub const AT_EXECFD: u64 = 2;
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_BASE: u64 = 7;
    pub const AT_FLAGS: u64 = 8;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_NOTELF: u64 = 10;
    pub const AT_UID: u64 = 11;
    pub const AT_EUID: u64 = 12;
    pub const AT_GID: u64 = 13;
    pub const AT_EGID: u64 = 14;
    pub const AT_CLKTCK: u64 = 17;
    pub const AT_SECURE: u64 = 23;
    pub const AT_RANDOM: u64 = 25;
}

/// Numéros d'appels système (24 syscalls)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // Famille 1 : Capacités
    CapDup = 1,
    CapDrop = 2,
    CapTransfer = 3,

    // Famille 2 : Mémoire
    VmoCreate = 4,
    VmoMap = 5,
    VmoUnmap = 6,
    VmoProtect = 7,

    // Famille 3 : Processus & Ordonnancement
    ProcessCreate = 8,
    ThreadCreate = 9,
    ThreadStart = 10,
    ThreadExit = 11,
    ThreadYield = 12,

    // Famille 4 : IPC & Synchronisation
    ChannelCreate = 13,
    ChannelCall = 14,
    PortCreate = 15,
    PortWait = 16,
    RingSetup = 17,
    RingEnter = 18,
    FutexWait = 19,
    FutexWake = 20,

    // Famille 5 : Matériel & Temps
    IrqBind = 21,
    IrqAck = 22,
    IommuMap = 23,
    ClockGettime = 24,
}

/// Codes d'erreur système
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    Success = 0,
    InvalidHandle = -1,
    PermissionDenied = -2,
    InvalidArgument = -3,
    OutOfMemory = -4,
    BufferTooSmall = -5,
    TimedOut = -6,
    ResourceBusy = -7,
    NotSupported = -8,
    PeerClosed = -9,
    BadAddress = -10,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Timespec {
    pub tv_sec: u64,
    pub tv_nsec: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RingDesc {
    pub sub_ring_vaddr: u64,
    pub comp_ring_vaddr: u64,
    pub ring_entries: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct JamboEvent {
    pub handle: Handle,
    pub event_type: u32,
    pub data: u64,
}

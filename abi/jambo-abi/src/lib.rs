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

/// Identifiants d'horloges pour l'appel système ClockGettime
pub mod clocks {
    pub const CLOCK_REALTIME: u32 = 0;
    pub const CLOCK_MONOTONIC: u32 = 1;
    pub const CLOCK_BOOTTIME: u32 = 2;
}

/// Numéros d'appels système (29 syscalls)
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

    // Famille 6 : Console E/S & Système (Phase 42 - v0.2.40)
    ConsoleRead = 25,
    ConsoleWrite = 26,
    SysInfo = 27,
    SystemPoweroff = 28,

    // Famille 7 : Broker Matériel Sécurisé (Phase 45 - v0.3.82)
    DeviceIo = 29,
}

/// Codes d'opérations pour l'appel système DeviceIo (Syscall 29)
pub mod device_io_op {
    pub const PCI_READ32: u32 = 1;
    pub const PCI_WRITE32: u32 = 2;
    pub const PCI_READ16: u32 = 3;
    pub const PCI_WRITE16: u32 = 4;
    pub const PCI_READ8: u32 = 5;
    pub const PCI_WRITE8: u32 = 6;
    // MMIO Broker & Délégation granulaire MSI-X Ring 3
    pub const MSIX_ENABLE: u32 = 7;
    pub const MSIX_DISABLE: u32 = 8;
    pub const MSIX_SET_ENTRY: u32 = 9;
    pub const MSIX_GET_ENTRY: u32 = 10;
    pub const MSIX_MASK_ENTRY: u32 = 11;
    pub const MSIX_UNMASK_ENTRY: u32 = 12;
    pub const MSIX_DELEGATE_IRQ: u32 = 13;
}

/// Descripteur d'entrée de table MSI-X pour le broker matériel DeviceIo (Syscall 29)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsixEntryDescriptor {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_control: u32,
}

impl MsixEntryDescriptor {
    pub const fn new(addr_lo: u32, addr_hi: u32, data: u32, masked: bool) -> Self {
        Self {
            msg_addr_lo: addr_lo,
            msg_addr_hi: addr_hi,
            msg_data: data,
            vector_control: if masked { 1 } else { 0 },
        }
    }

    #[inline]
    pub const fn is_masked(&self) -> bool {
        (self.vector_control & 0x01) != 0
    }

    #[inline]
    pub const fn msg_address(&self) -> u64 {
        ((self.msg_addr_hi as u64) << 32) | (self.msg_addr_lo as u64)
    }
}

/// Requête de délégation granulaire d'interruption MSI-X vers un port de notification
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsixDelegateRequest {
    pub port_handle: Handle,
    pub cookie: u64,
    pub target_vector: u32,
}

/// Métriques système rapportées par l'appel système SysInfo (Syscall 27)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemInfo {
    pub total_pages: u64,
    pub free_pages: u64,
    pub allocated_pages: u64,
    pub active_processes: u64,
    pub active_threads: u64,
    pub uptime_seconds: u64,
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

pub mod event_types {
    pub const NONE: u32 = 0;
    pub const IRQ: u32 = 1;
    pub const USER: u32 = 2;
    pub const CHANNEL: u32 = 3;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JamboEvent {
    pub handle: Handle,
    pub event_type: u32,
    pub _pad: u32,
    pub data: u64,
}

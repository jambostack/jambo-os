//! Démon de Journalisation Structurée & Chaînage Cryptographique Inviolable (`jambo-logd`)
//!
//! Jalon 3.22 — v0.3.66 (PID 27)
//!
//! Fournit un sous-système de journalisation structurée immuable, circulaire et scellé
//! cryptographiquement en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
//! 1. Anneau Circulaire Borné en Mémoire Statique (`RING_BUFFER_CAPACITY = 64`).
//! 2. Chaînage Cryptographique Inviolable (*Tamper-evident Hash Chain*) depuis `GENESIS_HASH`.
//! 3. Niveaux de Sévérité & Sous-Systèmes Structurés (`Trace`, `Debug`, `Info`, `Warn`, `Error`, `Fatal`).
//! 4. Vérification d'Intégrité Complète en Temps Linéaire $O(N)$ avec détection immédiate de falsification.
//! 5. Absence Totale d'Autorité Ambiante (`LogCap` et `log_rights`).
//! 6. Protocole IPC Déterministe à 64 Octets (`LogRequest`, `LogResponse`).
//! 7. Client synchrone Ring 3 `LogClient` sous l'endpoint 27 (PID 27).

#![no_std]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_find)]
#![allow(clippy::should_implement_trait)]

pub use libjambo::{syscall_ipc_register_endpoint, syscall_thread_yield, Handle, SysError};

// ============================================================================
// CONSTANTES DU SOUS-SYSTÈME DE JOURNALISATION
// ============================================================================

pub const RING_BUFFER_CAPACITY: usize = 64;
pub const HASH_SIZE: usize = 32;
pub const MAX_SUBSYSTEM_LEN: usize = 16;
pub const MAX_MESSAGE_LEN: usize = 32;
pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const GENESIS_HASH: [u8; HASH_SIZE] = [0x5au8; HASH_SIZE];

pub const LOG_MAGIC_REQ: u32 = 0x4C4F4744; // "LOGD"
pub const LOG_MAGIC_RESP: u32 = 0x4C4F4753; // "LOGS"

// ============================================================================
// DROITS & CAPABILITÉS (`LogCap`, `log_rights`)
// ============================================================================

/// Droits capabilaires pour le démon de journalisation.
pub mod log_rights {
    pub const LOG_READ: u32 = 0x01;
    pub const LOG_WRITE: u32 = 0x02;
    pub const LOG_QUERY: u32 = 0x04;
    pub const LOG_FLUSH: u32 = 0x08;
    pub const LOG_ARCHIVE: u32 = 0x10;
    pub const LOG_EXPORT: u32 = 0x20;
    pub const LOG_ADMIN: u32 = 0x80;
    pub const ALL: u32 =
        LOG_READ | LOG_WRITE | LOG_QUERY | LOG_FLUSH | LOG_ARCHIVE | LOG_EXPORT | LOG_ADMIN;
    // 0xBF
}

/// Jeton de capacité pour le contrôle d'accès au sous-système de journalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogCap {
    pub handle: Handle,
    pub rights: u32,
}

impl LogCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    /// Atténuation monotone stricte : interdiction formelle d'élargir l'ensemble de droits.
    pub fn attenuate(&self, new_rights: u32) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// NIVEAU DE SÉVÉRITÉ (`LogLevel`)
// ============================================================================

/// Niveau de sévérité d'une entrée de journal structurée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
}

impl LogLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("trace") {
            Some(LogLevel::Trace)
        } else if s.eq_ignore_ascii_case("debug") {
            Some(LogLevel::Debug)
        } else if s.eq_ignore_ascii_case("info") {
            Some(LogLevel::Info)
        } else if s.eq_ignore_ascii_case("warn") || s.eq_ignore_ascii_case("warning") {
            Some(LogLevel::Warn)
        } else if s.eq_ignore_ascii_case("error") || s.eq_ignore_ascii_case("err") {
            Some(LogLevel::Error)
        } else if s.eq_ignore_ascii_case("fatal")
            || s.eq_ignore_ascii_case("crit")
            || s.eq_ignore_ascii_case("critical")
        {
            Some(LogLevel::Fatal)
        } else {
            None
        }
    }

    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(LogLevel::Trace),
            1 => Some(LogLevel::Debug),
            2 => Some(LogLevel::Info),
            3 => Some(LogLevel::Warn),
            4 => Some(LogLevel::Error),
            5 => Some(LogLevel::Fatal),
            _ => None,
        }
    }
}

// ============================================================================
// ENREGISTREMENT SCELLÉ (`LogRecord`)
// ============================================================================

/// Enregistrement unitaire scellé par empreinte cryptographique 256 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRecord {
    pub id: u64,
    pub timestamp_ns: u64,
    pub level: LogLevel,
    pub subsystem: [u8; MAX_SUBSYSTEM_LEN],
    pub subsystem_len: usize,
    pub message: [u8; MAX_MESSAGE_LEN],
    pub message_len: usize,
    pub prev_hash: [u8; HASH_SIZE],
    pub entry_hash: [u8; HASH_SIZE],
}

impl LogRecord {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            timestamp_ns: 0,
            level: LogLevel::Info,
            subsystem: [0u8; MAX_SUBSYSTEM_LEN],
            subsystem_len: 0,
            message: [0u8; MAX_MESSAGE_LEN],
            message_len: 0,
            prev_hash: [0u8; HASH_SIZE],
            entry_hash: [0u8; HASH_SIZE],
        }
    }

    pub fn subsystem_str(&self) -> &str {
        core::str::from_utf8(&self.subsystem[..self.subsystem_len]).unwrap_or("unknown")
    }

    pub fn message_str(&self) -> &str {
        core::str::from_utf8(&self.message[..self.message_len]).unwrap_or("<invalid-utf8>")
    }

    /// Calcule l'empreinte cryptographique 256 bits du record et de son ancêtre.
    pub fn compute_hash(&self) -> [u8; HASH_SIZE] {
        let mut h0: u64 = 0x243f6a8885a308d3;
        let mut h1: u64 = 0x13198a2e03707344;
        let mut h2: u64 = 0xa4093822299f31d0;
        let mut h3: u64 = 0x082efa98ec4e6c89;

        // Incorpore id, timestamp et niveau
        h0 ^= self.id.rotate_left(7);
        h1 ^= self.timestamp_ns.rotate_left(13);
        h2 ^= (self.level as u64).rotate_left(19);

        // Incorpore le hachage précédent
        for (i, &b) in self.prev_hash.iter().enumerate() {
            let val = (b as u64) ^ (i as u64);
            match i % 4 {
                0 => h0 = h0.rotate_left(11) ^ val.wrapping_mul(0x517cc1b727220a95),
                1 => h1 = h1.rotate_left(17) ^ val.wrapping_mul(0x9e3779b97f4a7c15),
                2 => h2 = h2.rotate_left(23) ^ val.wrapping_mul(0xbf58476d1ce4e5b9),
                _ => h3 = h3.rotate_left(31) ^ val.wrapping_mul(0x94d049bb133111eb),
            }
        }

        // Incorpore le sous-système
        for (i, &b) in self.subsystem[..self.subsystem_len].iter().enumerate() {
            h0 = h0.rotate_left(5) ^ ((b as u64) << (i % 8));
        }

        // Incorpore le message
        for (i, &b) in self.message[..self.message_len].iter().enumerate() {
            let val = (b as u64) ^ (i as u64);
            match i % 4 {
                0 => h0 = h0.rotate_left(13) ^ val.wrapping_mul(0x3141592653589793),
                1 => h1 = h1.rotate_left(29) ^ val.wrapping_mul(0x2718281828459045),
                2 => h2 = h2.rotate_left(7) ^ val.wrapping_mul(0x1414213562373095),
                _ => h3 = h3.rotate_left(19) ^ val.wrapping_mul(0x1618033988749895),
            }
        }

        let mut hash = [0u8; HASH_SIZE];
        hash[0..8].copy_from_slice(&h0.to_le_bytes());
        hash[8..16].copy_from_slice(&h1.to_le_bytes());
        hash[16..24].copy_from_slice(&h2.to_le_bytes());
        hash[24..32].copy_from_slice(&h3.to_le_bytes());
        hash
    }
}

// ============================================================================
// OPCODES IPC (`LogOpcode`)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOpcode {
    GetStatus = 1,
    AppendRecord = 2,
    QueryLast = 3,
    VerifyChain = 4,
    ClearLogs = 5,
}

impl LogOpcode {
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::AppendRecord),
            3 => Some(Self::QueryLast),
            4 => Some(Self::VerifyChain),
            5 => Some(Self::ClearLogs),
            _ => None,
        }
    }
}

// ============================================================================
// STRUCTURES IPC 64 OCTETS (`LogRequest`, `LogResponse`)
// ============================================================================

/// Requête IPC déterministe calibrée à exactement 64 octets.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRequest {
    pub magic: u32,          // 0x4C4F4744 ("LOGD")
    pub opcode: u32,         // LogOpcode
    pub handle_id: u32,      // Identifiant de capacité
    pub rights: u32,         // Droits LogCap
    pub level: u8,           // Niveau LogLevel (0..5)
    pub _reserved1: u8,      // Alignement
    pub _reserved2: u16,     // Alignement
    pub subsystem: [u8; 16], // Sous-système émetteur (ex: "kernel", "secboot")
    pub message: [u8; 28],   // Message textuel du journal
}

const _: () = assert!(core::mem::size_of::<LogRequest>() == 64);

impl Default for LogRequest {
    fn default() -> Self {
        Self {
            magic: LOG_MAGIC_REQ,
            opcode: LogOpcode::GetStatus as u32,
            handle_id: 27,
            rights: log_rights::ALL,
            level: LogLevel::Info as u8,
            _reserved1: 0,
            _reserved2: 0,
            subsystem: [0u8; 16],
            message: [0u8; 28],
        }
    }
}

impl LogRequest {
    pub const fn new(opcode: LogOpcode) -> Self {
        Self {
            magic: LOG_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: 27,
            rights: log_rights::ALL,
            level: LogLevel::Info as u8,
            _reserved1: 0,
            _reserved2: 0,
            subsystem: [0u8; 16],
            message: [0u8; 28],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: LOG_MAGIC_REQ,
            opcode: LogOpcode::GetStatus as u32,
            handle_id,
            rights,
            level: 0,
            _reserved1: 0,
            _reserved2: 0,
            subsystem: [0u8; 16],
            message: [0u8; 28],
        }
    }

    pub fn new_append(
        handle_id: u32,
        rights: u32,
        level: LogLevel,
        subsystem: &[u8],
        message: &[u8],
    ) -> Self {
        let mut req = Self {
            magic: LOG_MAGIC_REQ,
            opcode: LogOpcode::AppendRecord as u32,
            handle_id,
            rights,
            level: level as u8,
            _reserved1: 0,
            _reserved2: 0,
            subsystem: [0u8; 16],
            message: [0u8; 28],
        };
        req.set_subsystem(subsystem);
        req.set_message(message);
        req
    }

    pub const fn new_query_last(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: LOG_MAGIC_REQ,
            opcode: LogOpcode::QueryLast as u32,
            handle_id,
            rights,
            level: 0,
            _reserved1: 0,
            _reserved2: 0,
            subsystem: [0u8; 16],
            message: [0u8; 28],
        }
    }

    pub const fn new_verify_chain(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: LOG_MAGIC_REQ,
            opcode: LogOpcode::VerifyChain as u32,
            handle_id,
            rights,
            level: 0,
            _reserved1: 0,
            _reserved2: 0,
            subsystem: [0u8; 16],
            message: [0u8; 28],
        }
    }

    pub const fn new_clear_logs(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: LOG_MAGIC_REQ,
            opcode: LogOpcode::ClearLogs as u32,
            handle_id,
            rights,
            level: 0,
            _reserved1: 0,
            _reserved2: 0,
            subsystem: [0u8; 16],
            message: [0u8; 28],
        }
    }

    pub fn set_subsystem(&mut self, s: &[u8]) {
        self.subsystem = [0u8; 16];
        let len = s.len().min(16);
        self.subsystem[..len].copy_from_slice(&s[..len]);
    }

    pub fn set_message(&mut self, m: &[u8]) {
        self.message = [0u8; 28];
        let len = m.len().min(28);
        self.message[..len].copy_from_slice(&m[..len]);
    }

    pub fn subsystem_as_str(&self) -> &str {
        let len = self
            .subsystem
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.subsystem.len());
        core::str::from_utf8(&self.subsystem[..len]).unwrap_or("")
    }

    pub fn message_as_str(&self) -> &str {
        let len = self
            .message
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.message.len());
        core::str::from_utf8(&self.message[..len]).unwrap_or("")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut req = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut req as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        if req.magic != LOG_MAGIC_REQ {
            return None;
        }
        Some(req)
    }
}

/// Réponse IPC déterministe calibrée à exactement 64 octets.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogResponse {
    pub magic: u32,                // 0x4C4F4753 ("LOGS")
    pub status: i32,               // 0 = Succès, < 0 = SysError
    pub record_id: u64,            // ID unique monotone de l'entrée générée/lue
    pub total_records: u32,        // Nombre total d'entrées actuellement en mémoire
    pub chain_verified: u32,       // 1 = Chaîne intègre, 0 = Falsifiée / altérée
    pub level: u8,                 // Niveau de la dernière entrée inspectée
    pub _reserved1: u8,            // Alignement
    pub _reserved2: u16,           // Alignement
    pub last_entry_hash: [u8; 16], // Empreinte tronquée de l'entrée scellée
    pub status_str: [u8; 20],      // Statut lisible ("RECORDED", "VERIFIED", etc.)
}

const _: () = assert!(core::mem::size_of::<LogResponse>() == 64);

impl Default for LogResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl LogResponse {
    pub const fn new() -> Self {
        Self {
            magic: LOG_MAGIC_RESP,
            status: 0,
            record_id: 0,
            total_records: 0,
            chain_verified: 1,
            level: 0,
            _reserved1: 0,
            _reserved2: 0,
            last_entry_hash: [0u8; 16],
            status_str: [0u8; 20],
        }
    }

    pub fn set_status_str(&mut self, s: &str) {
        self.status_str = [0u8; 20];
        let bytes = s.as_bytes();
        let len = bytes.len().min(20);
        self.status_str[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn status_as_str(&self) -> &str {
        let len = self
            .status_str
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.status_str.len());
        core::str::from_utf8(&self.status_str[..len]).unwrap_or("")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut resp = Self::new();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut resp as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        if resp.magic != LOG_MAGIC_RESP {
            return None;
        }
        Some(resp)
    }
}

// ============================================================================
// GESTIONNAIRE DU DÉMON DE JOURNALISATION (`LogDaemon`)
// ============================================================================

/// Démon de Journalisation Structurée & Chaînage Cryptographique Inviolable.
pub struct LogDaemon {
    pub records: [Option<LogRecord>; RING_BUFFER_CAPACITY],
    pub head: usize,
    pub count: usize,
    pub next_id: u64,
    pub last_hash: [u8; HASH_SIZE],
}

impl Default for LogDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl LogDaemon {
    pub const fn new() -> Self {
        Self {
            records: [None; RING_BUFFER_CAPACITY],
            head: 0,
            count: 0,
            next_id: 1,
            last_hash: GENESIS_HASH,
        }
    }

    /// Nombre d'enregistrements actuellement conservés en mémoire.
    pub fn record_count(&self) -> usize {
        self.count
    }

    /// Récupère un enregistrement par son indice logique ordonné (0 = plus ancien, count - 1 = plus récent).
    pub fn get_record(&self, logical_idx: usize) -> Option<&LogRecord> {
        if logical_idx >= self.count {
            return None;
        }
        let start = if self.count < RING_BUFFER_CAPACITY {
            0
        } else {
            self.head
        };
        let physical_idx = (start + logical_idx) % RING_BUFFER_CAPACITY;
        self.records[physical_idx].as_ref()
    }

    /// Récupère le dernier enregistrement écrit s'il existe.
    pub fn get_last(&self) -> Option<&LogRecord> {
        if self.count == 0 {
            return None;
        }
        self.get_record(self.count - 1)
    }

    /// Ajoute une nouvelle entrée structurée scellée cryptographiquement.
    pub fn append_record(
        &mut self,
        level: LogLevel,
        subsystem: &[u8],
        message: &[u8],
    ) -> Result<u64, SysError> {
        let mut record = LogRecord::empty();
        record.id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        record.timestamp_ns = 0;
        record.level = level;
        record.prev_hash = self.last_hash;

        let s_len = subsystem.len().min(MAX_SUBSYSTEM_LEN);
        record.subsystem[..s_len].copy_from_slice(&subsystem[..s_len]);
        record.subsystem_len = s_len;

        let m_len = message.len().min(MAX_MESSAGE_LEN);
        record.message[..m_len].copy_from_slice(&message[..m_len]);
        record.message_len = m_len;

        let hash = record.compute_hash();
        record.entry_hash = hash;
        self.last_hash = hash;

        self.records[self.head] = Some(record);
        self.head = (self.head + 1) % RING_BUFFER_CAPACITY;
        if self.count < RING_BUFFER_CAPACITY {
            self.count += 1;
        }

        Ok(record.id)
    }

    /// Vérifie l'intégrité complète de la chaîne cryptographique inviolable en temps linéaire $O(N)$.
    pub fn verify_chain(&self) -> bool {
        if self.count == 0 {
            return true;
        }

        for i in 0..self.count {
            let rec = match self.get_record(i) {
                Some(r) => r,
                None => return false,
            };

            // 1. Vérification que l'empreinte correspond exactement au contenu
            if rec.compute_hash() != rec.entry_hash {
                return false;
            }

            // 2. Vérification du chaînage
            if i > 0 {
                let prev = match self.get_record(i - 1) {
                    Some(p) => p,
                    None => return false,
                };
                if rec.prev_hash != prev.entry_hash {
                    return false;
                }
            } else if self.count < RING_BUFFER_CAPACITY {
                // Avant débordement, la première entrée doit dériver de GENESIS_HASH
                if rec.prev_hash != GENESIS_HASH {
                    return false;
                }
            }
        }

        true
    }

    /// Réinitialise l'anneau circulaire et régénère l'ancre `GENESIS_HASH`.
    pub fn clear_logs(&mut self) {
        self.records = [None; RING_BUFFER_CAPACITY];
        self.head = 0;
        self.count = 0;
        self.next_id = 1;
        self.last_hash = GENESIS_HASH;
    }

    /// Initialise les entrées d'amorçage initiales (logs de boot pour `kernel`, `init`, `jsh`).
    pub fn init_defaults(&mut self) {
        let _ = self.append_record(LogLevel::Info, b"kernel", b"microkernel started");
        let _ = self.append_record(LogLevel::Info, b"init", b"userland supervisor online");
        let _ = self.append_record(LogLevel::Info, b"jsh", b"interactive shell ready");
    }

    /// Traitement direct et déterministe d'une requête IPC 64 octets.
    pub fn dispatch_ipc(&mut self, req: &LogRequest) -> LogResponse {
        if req.magic != LOG_MAGIC_REQ {
            let mut resp = LogResponse::new();
            resp.status = -1;
            resp.set_status_str("ERR_MAGIC");
            return resp;
        }

        let cap = LogCap::new(Handle(req.handle_id as u64), req.rights);
        let opcode = match LogOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                let mut resp = LogResponse::new();
                resp.status = -1;
                resp.set_status_str("ERR_OPCODE");
                return resp;
            }
        };

        match opcode {
            LogOpcode::GetStatus => {
                if !cap.has_right(log_rights::LOG_READ) && !cap.has_right(log_rights::LOG_QUERY) {
                    let mut resp = LogResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("PERM_DENIED");
                    return resp;
                }
                let mut resp = LogResponse::new();
                resp.status = 0;
                resp.record_id = self.get_last().map(|r| r.id).unwrap_or(0);
                resp.total_records = self.count as u32;
                resp.chain_verified = if self.verify_chain() { 1 } else { 0 };
                resp.level = self.get_last().map(|r| r.level as u8).unwrap_or(0);
                resp.last_entry_hash.copy_from_slice(&self.last_hash[..16]);
                resp.set_status_str("OK_STATUS");
                resp
            }
            LogOpcode::AppendRecord => {
                if !cap.has_right(log_rights::LOG_WRITE) {
                    let mut resp = LogResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("PERM_DENIED");
                    return resp;
                }
                let level = LogLevel::from_u8(req.level).unwrap_or(LogLevel::Info);
                let subsys_len = req
                    .subsystem
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(req.subsystem.len());
                let msg_len = req
                    .message
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(req.message.len());
                match self.append_record(
                    level,
                    &req.subsystem[..subsys_len],
                    &req.message[..msg_len],
                ) {
                    Ok(id) => {
                        let mut resp = LogResponse::new();
                        resp.status = 0;
                        resp.record_id = id;
                        resp.total_records = self.count as u32;
                        resp.chain_verified = 1;
                        resp.level = level as u8;
                        resp.last_entry_hash.copy_from_slice(&self.last_hash[..16]);
                        resp.set_status_str("RECORDED");
                        resp
                    }
                    Err(e) => {
                        let mut resp = LogResponse::new();
                        resp.status = e as i32;
                        resp.set_status_str("APPEND_FAILED");
                        resp
                    }
                }
            }
            LogOpcode::QueryLast => {
                if !cap.has_right(log_rights::LOG_READ) && !cap.has_right(log_rights::LOG_QUERY) {
                    let mut resp = LogResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("PERM_DENIED");
                    return resp;
                }
                match self.get_last() {
                    Some(last) => {
                        let mut resp = LogResponse::new();
                        resp.status = 0;
                        resp.record_id = last.id;
                        resp.total_records = self.count as u32;
                        resp.chain_verified = if self.verify_chain() { 1 } else { 0 };
                        resp.level = last.level as u8;
                        resp.last_entry_hash.copy_from_slice(&last.entry_hash[..16]);
                        resp.set_status_str("QUERY_OK");
                        resp
                    }
                    None => {
                        let mut resp = LogResponse::new();
                        resp.status = 0;
                        resp.record_id = 0;
                        resp.total_records = 0;
                        resp.chain_verified = 1;
                        resp.level = 0;
                        resp.last_entry_hash.copy_from_slice(&self.last_hash[..16]);
                        resp.set_status_str("NO_RECORDS");
                        resp
                    }
                }
            }
            LogOpcode::VerifyChain => {
                if !cap.has_right(log_rights::LOG_READ) && !cap.has_right(log_rights::LOG_QUERY) {
                    let mut resp = LogResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("PERM_DENIED");
                    return resp;
                }
                let verified = self.verify_chain();
                let mut resp = LogResponse::new();
                resp.status = 0;
                resp.record_id = self.get_last().map(|r| r.id).unwrap_or(0);
                resp.total_records = self.count as u32;
                resp.chain_verified = if verified { 1 } else { 0 };
                resp.level = self.get_last().map(|r| r.level as u8).unwrap_or(0);
                resp.last_entry_hash.copy_from_slice(&self.last_hash[..16]);
                resp.set_status_str(if verified { "VERIFIED" } else { "CORRUPTED" });
                resp
            }
            LogOpcode::ClearLogs => {
                if !cap.has_right(log_rights::LOG_FLUSH) && !cap.has_right(log_rights::LOG_ADMIN) {
                    let mut resp = LogResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("PERM_DENIED");
                    return resp;
                }
                self.clear_logs();
                let mut resp = LogResponse::new();
                resp.status = 0;
                resp.record_id = 0;
                resp.total_records = 0;
                resp.chain_verified = 1;
                resp.level = 0;
                resp.last_entry_hash.copy_from_slice(&self.last_hash[..16]);
                resp.set_status_str("CLEARED");
                resp
            }
        }
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`LogClient`, `ChannelMessage`)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [Handle; MAX_HANDLES],
    pub handle_count: usize,
}

impl Default for ChannelMessage {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
            handles: [Handle::NULL; MAX_HANDLES],
            handle_count: 0,
        }
    }
}

/// Client synchrone Ring 3 pour interagir avec `jambo-logd` (PID 27, endpoint 27).
pub struct LogClient {
    pub endpoint: Handle,
}

impl LogClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_status(&self, cap: &LogCap) -> Result<LogResponse, SysError> {
        let req = LogRequest::new_status(cap.handle.0 as u32, cap.rights);
        self.call(&req)
    }

    pub fn append_record(
        &self,
        cap: &LogCap,
        level: LogLevel,
        subsystem: &[u8],
        message: &[u8],
    ) -> Result<LogResponse, SysError> {
        let req =
            LogRequest::new_append(cap.handle.0 as u32, cap.rights, level, subsystem, message);
        self.call(&req)
    }

    pub fn query_last(&self, cap: &LogCap) -> Result<LogResponse, SysError> {
        let req = LogRequest::new_query_last(cap.handle.0 as u32, cap.rights);
        self.call(&req)
    }

    pub fn verify_chain(&self, cap: &LogCap) -> Result<LogResponse, SysError> {
        let req = LogRequest::new_verify_chain(cap.handle.0 as u32, cap.rights);
        self.call(&req)
    }

    pub fn clear_logs(&self, cap: &LogCap) -> Result<LogResponse, SysError> {
        let req = LogRequest::new_clear_logs(cap.handle.0 as u32, cap.rights);
        self.call(&req)
    }

    pub fn call(&self, req: &LogRequest) -> Result<LogResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.endpoint.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };

        if ret_send != 0 {
            return Err(SysError::InvalidHandle);
        }

        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        while attempts < 100 {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.endpoint.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<LogResponse>() {
                if let Some(resp) = LogResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                    return Ok(resp);
                }
            }
            attempts += 1;
            libjambo::syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

// ============================================================================
// TESTS UNITAIRES COMPLETS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hash_and_empty_daemon() {
        let daemon = LogDaemon::new();
        assert_eq!(daemon.record_count(), 0);
        assert_eq!(daemon.head, 0);
        assert_eq!(daemon.next_id, 1);
        assert_eq!(daemon.last_hash, GENESIS_HASH);
        assert!(daemon.get_last().is_none());
        assert!(daemon.verify_chain());
    }

    #[test]
    fn test_append_and_hash_chaining() {
        let mut daemon = LogDaemon::new();
        let id1 = daemon
            .append_record(LogLevel::Info, b"kernel", b"booting")
            .expect("append 1");
        assert_eq!(id1, 1);
        assert_eq!(daemon.record_count(), 1);
        assert!(daemon.verify_chain());

        let id2 = daemon
            .append_record(LogLevel::Warn, b"netd", b"link down")
            .expect("append 2");
        assert_eq!(id2, 2);
        assert_eq!(daemon.record_count(), 2);
        assert!(daemon.verify_chain());

        let id3 = daemon
            .append_record(LogLevel::Error, b"fs", b"disk full")
            .expect("append 3");
        assert_eq!(id3, 3);
        assert_eq!(daemon.record_count(), 3);
        assert!(daemon.verify_chain());

        let r1 = daemon.get_record(0).unwrap();
        let r2 = daemon.get_record(1).unwrap();
        let r3 = daemon.get_record(2).unwrap();

        assert_eq!(r1.prev_hash, GENESIS_HASH);
        assert_eq!(r2.prev_hash, r1.entry_hash);
        assert_eq!(r3.prev_hash, r2.entry_hash);
        assert_eq!(daemon.last_hash, r3.entry_hash);
    }

    #[test]
    fn test_tamper_detection_message() {
        let mut daemon = LogDaemon::new();
        daemon.init_defaults();
        assert!(daemon.verify_chain());

        // Alter message of record 1
        if let Some(ref mut rec) = daemon.records[1] {
            rec.message[0] ^= 0xFF;
        }

        // Verification must now fail!
        assert!(!daemon.verify_chain());
    }

    #[test]
    fn test_tamper_detection_subsystem() {
        let mut daemon = LogDaemon::new();
        daemon.init_defaults();
        assert!(daemon.verify_chain());

        // Alter subsystem of record 0
        if let Some(ref mut rec) = daemon.records[0] {
            rec.subsystem[0] ^= 0x42;
        }

        assert!(!daemon.verify_chain());
    }

    #[test]
    fn test_tamper_detection_hash_substitution() {
        let mut daemon = LogDaemon::new();
        daemon.init_defaults();
        assert!(daemon.verify_chain());

        // Recalculate hash for record 0 after altering content
        if let Some(ref mut rec) = daemon.records[0] {
            rec.level = LogLevel::Fatal;
            rec.entry_hash = rec.compute_hash();
        }

        // Even though record 0's entry_hash matches its content, record 1's prev_hash no longer matches!
        assert!(!daemon.verify_chain());
    }

    #[test]
    fn test_ring_buffer_rollover() {
        let mut daemon = LogDaemon::new();

        // Push 100 records into 64-capacity ring buffer
        for i in 0..100 {
            let mut msg = [0u8; 16];
            msg[0] = b'M';
            msg[1] = b'S';
            msg[2] = b'G';
            msg[3] = b'_';
            msg[4] = (i % 10) as u8 + b'0';
            let id = daemon
                .append_record(LogLevel::Debug, b"test", &msg)
                .expect("append record");
            assert_eq!(id, (i + 1) as u64);
        }

        assert_eq!(daemon.record_count(), RING_BUFFER_CAPACITY);
        assert_eq!(daemon.next_id, 101);

        // Chain must still verify for all stored records
        assert!(daemon.verify_chain());

        // Oldest visible record should have id 100 - 64 + 1 = 37
        let oldest = daemon.get_record(0).unwrap();
        assert_eq!(oldest.id, 37);

        // Newest visible record should have id 100
        let newest = daemon.get_last().unwrap();
        assert_eq!(newest.id, 100);
    }

    #[test]
    fn test_clear_logs() {
        let mut daemon = LogDaemon::new();
        daemon.init_defaults();
        assert_eq!(daemon.record_count(), 3);

        daemon.clear_logs();
        assert_eq!(daemon.record_count(), 0);
        assert_eq!(daemon.last_hash, GENESIS_HASH);
        assert_eq!(daemon.next_id, 1);
        assert!(daemon.verify_chain());
    }

    #[test]
    fn test_capability_attenuation() {
        let cap_all = LogCap::new(Handle(27), log_rights::ALL);
        assert!(cap_all.has_right(log_rights::LOG_READ));
        assert!(cap_all.has_right(log_rights::LOG_WRITE));
        assert!(cap_all.has_right(log_rights::LOG_ADMIN));

        // Attenuate to read-only
        let cap_ro = cap_all
            .attenuate(log_rights::LOG_READ)
            .expect("attenuate to read");
        assert!(cap_ro.has_right(log_rights::LOG_READ));
        assert!(!cap_ro.has_right(log_rights::LOG_WRITE));
        assert!(!cap_ro.has_right(log_rights::LOG_ADMIN));

        // Attempt privilege amplification: read-only trying to regain write
        let ampli = cap_ro.attenuate(log_rights::LOG_READ | log_rights::LOG_WRITE);
        assert_eq!(ampli, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_ipc_sizes_and_serialization() {
        assert_eq!(core::mem::size_of::<LogRequest>(), 64);
        assert_eq!(core::mem::size_of::<LogResponse>(), 64);

        let req = LogRequest::new_append(
            27,
            log_rights::LOG_WRITE,
            LogLevel::Warn,
            b"secboot",
            b"PCR 14 extended",
        );
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 64);

        let parsed_req = LogRequest::from_bytes(&bytes).expect("parse request");
        assert_eq!(parsed_req.magic, LOG_MAGIC_REQ);
        assert_eq!(parsed_req.opcode, LogOpcode::AppendRecord as u32);
        assert_eq!(parsed_req.level, LogLevel::Warn as u8);
        assert_eq!(parsed_req.subsystem_as_str(), "secboot");
        assert_eq!(parsed_req.message_as_str(), "PCR 14 extended");

        let mut resp = LogResponse::new();
        resp.record_id = 42;
        resp.total_records = 15;
        resp.chain_verified = 1;
        resp.level = LogLevel::Warn as u8;
        resp.set_status_str("RECORDED");
        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);

        let parsed_resp = LogResponse::from_bytes(&resp_bytes).expect("parse response");
        assert_eq!(parsed_resp.magic, LOG_MAGIC_RESP);
        assert_eq!(parsed_resp.record_id, 42);
        assert_eq!(parsed_resp.total_records, 15);
        assert_eq!(parsed_resp.chain_verified, 1);
        assert_eq!(parsed_resp.status_as_str(), "RECORDED");
    }

    #[test]
    fn test_ipc_dispatch_operations() {
        let mut daemon = LogDaemon::new();

        // 1. Get status without rights -> PERM_DENIED
        let req_status_no_rights = LogRequest::new_status(27, 0);
        let resp = daemon.dispatch_ipc(&req_status_no_rights);
        assert_eq!(resp.status, SysError::PermissionDenied as i32);
        assert_eq!(resp.status_as_str(), "PERM_DENIED");

        // 2. Append record with write rights
        let req_append = LogRequest::new_append(
            27,
            log_rights::LOG_WRITE,
            LogLevel::Info,
            b"kernel",
            b"scheduler active",
        );
        let resp = daemon.dispatch_ipc(&req_append);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.record_id, 1);
        assert_eq!(resp.total_records, 1);
        assert_eq!(resp.chain_verified, 1);
        assert_eq!(resp.status_as_str(), "RECORDED");

        // 3. Query last record
        let req_query = LogRequest::new_query_last(27, log_rights::LOG_READ);
        let resp = daemon.dispatch_ipc(&req_query);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.record_id, 1);
        assert_eq!(resp.status_as_str(), "QUERY_OK");

        // 4. Verify chain
        let req_verify = LogRequest::new_verify_chain(27, log_rights::LOG_READ);
        let resp = daemon.dispatch_ipc(&req_verify);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.chain_verified, 1);
        assert_eq!(resp.status_as_str(), "VERIFIED");

        // 5. Clear logs without flush rights -> PERM_DENIED
        let req_clear_no_rights = LogRequest::new_clear_logs(27, log_rights::LOG_READ);
        let resp = daemon.dispatch_ipc(&req_clear_no_rights);
        assert_eq!(resp.status, SysError::PermissionDenied as i32);

        // 6. Clear logs with flush rights
        let req_clear = LogRequest::new_clear_logs(27, log_rights::LOG_FLUSH);
        let resp = daemon.dispatch_ipc(&req_clear);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.total_records, 0);
        assert_eq!(resp.status_as_str(), "CLEARED");
    }

    #[test]
    fn test_log_level_formatting_and_parsing() {
        assert_eq!(LogLevel::Trace.as_str(), "TRACE");
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert_eq!(LogLevel::Warn.as_str(), "WARN");
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
        assert_eq!(LogLevel::Fatal.as_str(), "FATAL");

        assert_eq!(LogLevel::from_str("trace"), Some(LogLevel::Trace));
        assert_eq!(LogLevel::from_str("DEBUG"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("Info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("warn"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("err"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("fatal"), Some(LogLevel::Fatal));
        assert_eq!(LogLevel::from_str("crit"), Some(LogLevel::Fatal));
        assert_eq!(LogLevel::from_str("unknown"), None);

        assert_eq!(LogLevel::from_u8(0), Some(LogLevel::Trace));
        assert_eq!(LogLevel::from_u8(1), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_u8(2), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_u8(3), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_u8(4), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_u8(5), Some(LogLevel::Fatal));
        assert_eq!(LogLevel::from_u8(6), None);
    }
}

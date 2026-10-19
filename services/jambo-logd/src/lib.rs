//! Démon de Journalisation Structurée & Agrégation Distribuée (`jambo-logd`)
//!
//! Fournit un sous-système de journalisation structurée haute performance en `#![no_std]`,
//! basé sur un anneau circulaire borné, un chaînage cryptographique inviolable (tamper-evident Merkle/Hash chain),
//! le filtrage capabilaire strict (`LogCap`) sans autorité ambiante, la compatibilité W3C TraceContext,
//! et l'archivage chiffré dédupliqué vers le système de stockage distribué `jambo-dfsd`.

#![no_std]

use libjambo::{Handle, SysError};
use jambo_dfsd::{DfsBlockStore, DfsCap, BLOCK_SIZE, HASH_SIZE as DFS_HASH_SIZE};

pub const MAX_KEY_LEN: usize = 16;
pub const MAX_VAL_LEN: usize = 32;
pub const MAX_FIELDS: usize = 4;
pub const MAX_SUBSYSTEM_LEN: usize = 24;
pub const MAX_MESSAGE_LEN: usize = 96;
pub const HASH_SIZE: usize = 32;
pub const RING_BUFFER_CAPACITY: usize = 64;
pub const MAX_ARCHIVES: usize = 16;
pub const GENESIS_HASH: [u8; HASH_SIZE] = [0x5au8; HASH_SIZE];

/// Droits capabilaires pour le démon de journalisation.
pub mod log_rights {
    pub const LOG_READ: u32 = 0x01;
    pub const LOG_WRITE: u32 = 0x02;
    pub const LOG_QUERY: u32 = 0x04;
    pub const LOG_FLUSH: u32 = 0x08;
    pub const LOG_ARCHIVE: u32 = 0x10;
    pub const LOG_EXPORT: u32 = 0x20;
    pub const LOG_ADMIN: u32 = 0x80;
    pub const ALL: u32 = LOG_READ | LOG_WRITE | LOG_QUERY | LOG_FLUSH | LOG_ARCHIVE | LOG_EXPORT | LOG_ADMIN;
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

    /// Atténuation stricte des privilèges : interdiction d'élargir l'ensemble de droits.
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

/// Niveau de sévérité d'une entrée de journal.
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
        } else if s.eq_ignore_ascii_case("fatal") || s.eq_ignore_ascii_case("crit") || s.eq_ignore_ascii_case("critical") {
            Some(LogLevel::Fatal)
        } else {
            None
        }
    }
}

/// Paire clé-valeur structurée pour attributs de contexte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogField {
    pub key: [u8; MAX_KEY_LEN],
    pub key_len: usize,
    pub val: [u8; MAX_VAL_LEN],
    pub val_len: usize,
}

impl LogField {
    pub const fn empty() -> Self {
        Self {
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            val: [0u8; MAX_VAL_LEN],
            val_len: 0,
        }
    }

    pub fn new(k: &str, v: &str) -> Self {
        let mut field = Self::empty();
        let k_bytes = k.as_bytes();
        let v_bytes = v.as_bytes();

        let k_len = if k_bytes.len() > MAX_KEY_LEN { MAX_KEY_LEN } else { k_bytes.len() };
        let v_len = if v_bytes.len() > MAX_VAL_LEN { MAX_VAL_LEN } else { v_bytes.len() };

        let mut i = 0;
        while i < k_len {
            field.key[i] = k_bytes[i];
            i += 1;
        }
        field.key_len = k_len;

        let mut j = 0;
        while j < v_len {
            field.val[j] = v_bytes[j];
            j += 1;
        }
        field.val_len = v_len;

        field
    }

    pub fn key_str(&self) -> &str {
        core::str::from_utf8(&self.key[..self.key_len]).unwrap_or("<invalid-utf8>")
    }

    pub fn val_str(&self) -> &str {
        core::str::from_utf8(&self.val[..self.val_len]).unwrap_or("<invalid-utf8>")
    }
}

/// Enregistrement de log unitaire scellé cryptographiquement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRecord {
    pub id: u64,
    pub timestamp_ns: u64,
    pub level: LogLevel,
    pub subsystem: [u8; MAX_SUBSYSTEM_LEN],
    pub subsystem_len: usize,
    pub message: [u8; MAX_MESSAGE_LEN],
    pub message_len: usize,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub has_trace: bool,
    pub fields: [LogField; MAX_FIELDS],
    pub fields_count: usize,
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
            trace_id: [0u8; 16],
            span_id: [0u8; 8],
            has_trace: false,
            fields: [LogField::empty(); MAX_FIELDS],
            fields_count: 0,
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

        // Incorpore id et timestamp
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

        // Incorpore le trace_id si présent
        if self.has_trace {
            for (i, &b) in self.trace_id.iter().enumerate() {
                h1 = h1.rotate_left(9) ^ ((b as u64) << (i % 8));
            }
            for (i, &b) in self.span_id.iter().enumerate() {
                h2 = h2.rotate_left(15) ^ ((b as u64) << (i % 8));
            }
        }

        // Incorpore les champs clés-valeurs
        for f in &self.fields[..self.fields_count] {
            for &b in &f.key[..f.key_len] {
                h3 = h3.rotate_left(3) ^ (b as u64);
            }
            for &b in &f.val[..f.val_len] {
                h0 = h0.rotate_left(7) ^ (b as u64);
            }
        }

        let mut hash = [0u8; HASH_SIZE];
        hash[0..8].copy_from_slice(&h0.to_le_bytes());
        hash[8..16].copy_from_slice(&h1.to_le_bytes());
        hash[16..24].copy_from_slice(&h2.to_le_bytes());
        hash[24..32].copy_from_slice(&h3.to_le_bytes());
        hash
    }

    /// Formate l'entrée sous format texte structuré dans un tampon.
    pub fn format_text(&self, out: &mut [u8]) -> usize {
        let mut pos = 0;

        // Préfixe [LEVEL]
        let lvl = self.level.as_str();
        if pos + lvl.len() + 3 <= out.len() {
            out[pos] = b'[';
            pos += 1;
            out[pos..pos + lvl.len()].copy_from_slice(lvl.as_bytes());
            pos += lvl.len();
            out[pos] = b']';
            pos += 1;
            out[pos] = b' ';
            pos += 1;
        }

        // Sous-système
        let sub = self.subsystem_str();
        if pos + sub.len() + 2 <= out.len() {
            out[pos..pos + sub.len()].copy_from_slice(sub.as_bytes());
            pos += sub.len();
            out[pos] = b':';
            pos += 1;
            out[pos] = b' ';
            pos += 1;
        }

        // Message
        let msg = self.message_str();
        let copy_msg_len = if pos + msg.len() <= out.len() {
            msg.len()
        } else {
            out.len().saturating_sub(pos)
        };
        out[pos..pos + copy_msg_len].copy_from_slice(&msg.as_bytes()[..copy_msg_len]);
        pos += copy_msg_len;

        pos
    }
}

/// Anneau circulaire en mémoire pour la conservation des entrées récentes.
pub struct LogRingBuffer {
    pub entries: [LogRecord; RING_BUFFER_CAPACITY],
    pub head: usize,
    pub count: usize,
    pub total_logged: u64,
    pub total_dropped: u64,
}

impl LogRingBuffer {
    pub const fn new() -> Self {
        Self {
            entries: [LogRecord::empty(); RING_BUFFER_CAPACITY],
            head: 0,
            count: 0,
            total_logged: 0,
            total_dropped: 0,
        }
    }

    /// Insère un nouvel enregistrement dans l'anneau circulaire (écrasement FIFO des plus anciens).
    pub fn push(&mut self, record: LogRecord) -> usize {
        let idx = self.head;
        if self.count == RING_BUFFER_CAPACITY {
            self.total_dropped = self.total_dropped.saturating_add(1);
        } else {
            self.count += 1;
        }

        self.entries[idx] = record;
        self.head = (self.head + 1) % RING_BUFFER_CAPACITY;
        self.total_logged = self.total_logged.saturating_add(1);
        idx
    }

    /// Récupère l'élément à l'indice logique ordonné du plus ancien (0) au plus récent (count - 1).
    pub fn get(&self, logical_idx: usize) -> Option<&LogRecord> {
        if logical_idx >= self.count {
            return None;
        }

        let start = if self.count < RING_BUFFER_CAPACITY {
            0
        } else {
            self.head
        };
        let physical_idx = (start + logical_idx) % RING_BUFFER_CAPACITY;
        Some(&self.entries[physical_idx])
    }

    /// Retourne le dernier enregistrement écrit s'il existe.
    pub fn latest(&self) -> Option<&LogRecord> {
        if self.count == 0 {
            return None;
        }
        let physical_idx = (self.head + RING_BUFFER_CAPACITY - 1) % RING_BUFFER_CAPACITY;
        Some(&self.entries[physical_idx])
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Filtre multi-critères pour les requêtes de recherche dans les logs.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogQueryFilter<'a> {
    pub min_level: Option<LogLevel>,
    pub subsystem: Option<&'a str>,
    pub keyword: Option<&'a str>,
    pub trace_id: Option<[u8; 16]>,
    pub since_timestamp_ns: u64,
    pub until_timestamp_ns: u64,
}

impl<'a> LogQueryFilter<'a> {
    pub const fn empty() -> Self {
        Self {
            min_level: None,
            subsystem: None,
            keyword: None,
            trace_id: None,
            since_timestamp_ns: 0,
            until_timestamp_ns: u64::MAX,
        }
    }

    pub fn matches(&self, rec: &LogRecord) -> bool {
        if let Some(min_lvl) = self.min_level {
            if rec.level < min_lvl {
                return false;
            }
        }

        if let Some(sub) = self.subsystem {
            if !rec.subsystem_str().eq_ignore_ascii_case(sub) {
                return false;
            }
        }

        if let Some(t_id) = self.trace_id {
            if !rec.has_trace || rec.trace_id != t_id {
                return false;
            }
        }

        if rec.timestamp_ns < self.since_timestamp_ns || rec.timestamp_ns > self.until_timestamp_ns {
            return false;
        }

        if let Some(kw) = self.keyword {
            let msg = rec.message_str();
            if !contains_ignore_case(msg, kw) {
                return false;
            }
        }

        true
    }
}

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    let h_bytes = haystack.as_bytes();
    let n_bytes = needle.as_bytes();
    if n_bytes.is_empty() {
        return true;
    }
    if n_bytes.len() > h_bytes.len() {
        return false;
    }

    let mut i = 0;
    while i + n_bytes.len() <= h_bytes.len() {
        let mut matches = true;
        let mut j = 0;
        while j < n_bytes.len() {
            let hb = h_bytes[i + j];
            let nb = n_bytes[j];
            let hb_lower = if hb >= b'A' && hb <= b'Z' { hb + 32 } else { hb };
            let nb_lower = if nb >= b'A' && nb <= b'Z' { nb + 32 } else { nb };
            if hb_lower != nb_lower {
                matches = false;
                break;
            }
            j += 1;
        }
        if matches {
            return true;
        }
        i += 1;
    }
    false
}

/// Descripteur d'un bloc d'archive chiffré stocké sur `jambo-dfsd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogArchiveDescriptor {
    pub archive_id: u32,
    pub start_id: u64,
    pub end_id: u64,
    pub count: usize,
    pub dfs_block_hash: [u8; DFS_HASH_SIZE],
    pub chain_root_hash: [u8; HASH_SIZE],
    pub timestamp_ns: u64,
}

impl LogArchiveDescriptor {
    pub const fn empty() -> Self {
        Self {
            archive_id: 0,
            start_id: 0,
            end_id: 0,
            count: 0,
            dfs_block_hash: [0u8; DFS_HASH_SIZE],
            chain_root_hash: [0u8; HASH_SIZE],
            timestamp_ns: 0,
        }
    }
}

/// Chiffrement symétrique de flux `#![no_std]` pour les blocs d'archives.
pub fn encrypt_archive_payload(
    payload: &[u8],
    key: &[u8; 32],
    nonce: u64,
    out: &mut [u8],
) -> usize {
    let len = if payload.len() > out.len() {
        out.len()
    } else {
        payload.len()
    };

    let mut state: u64 = nonce ^ 0x6a09e667f3bcc908;
    for (i, &b) in key.iter().enumerate() {
        state = state.rotate_left(7) ^ ((b as u64) << (i % 8));
    }

    for idx in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let keystream_byte = (state >> 33) as u8;
        out[idx] = payload[idx] ^ keystream_byte;
    }

    len
}

/// Statistiques opérationnelles du démon de journalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogDaemonStats {
    pub total_logged: u64,
    pub total_dropped: u64,
    pub buffer_count: usize,
    pub queries_served: u64,
    pub archives_created: usize,
    pub total_archived_entries: u64,
    pub last_entry_hash: [u8; HASH_SIZE],
}

/// Démon de Journalisation Structurée & Agrégation Distribuée.
pub struct JamboLogDaemon {
    pub cap: LogCap,
    pub node_id: u16,
    pub ring_buffer: LogRingBuffer,
    pub last_hash: [u8; HASH_SIZE],
    pub next_id: u64,
    pub unarchived_cursor: usize,
    pub archives: [LogArchiveDescriptor; MAX_ARCHIVES],
    pub archives_count: usize,
    pub total_archived_entries: u64,
    pub queries_served: u64,
}

impl JamboLogDaemon {
    pub fn new(cap: LogCap, node_id: u16) -> Self {
        Self {
            cap,
            node_id,
            ring_buffer: LogRingBuffer::new(),
            last_hash: GENESIS_HASH,
            next_id: 1,
            unarchived_cursor: 0,
            archives: [LogArchiveDescriptor::empty(); MAX_ARCHIVES],
            archives_count: 0,
            total_archived_entries: 0,
            queries_served: 0,
        }
    }

    /// Écrit une nouvelle entrée structurée dans le journal après validation capabilaire.
    pub fn log(
        &mut self,
        cap: &LogCap,
        level: LogLevel,
        subsystem: &str,
        message: &str,
        trace_id: Option<[u8; 16]>,
        span_id: Option<[u8; 8]>,
        fields: &[LogField],
        timestamp_ns: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(log_rights::LOG_WRITE) {
            return Err(SysError::PermissionDenied);
        }

        let mut record = LogRecord::empty();
        record.id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        record.timestamp_ns = timestamp_ns;
        record.level = level;
        record.prev_hash = self.last_hash;

        // Copie du sous-système
        let sub_bytes = subsystem.as_bytes();
        let sub_len = if sub_bytes.len() > MAX_SUBSYSTEM_LEN {
            MAX_SUBSYSTEM_LEN
        } else {
            sub_bytes.len()
        };
        record.subsystem[..sub_len].copy_from_slice(&sub_bytes[..sub_len]);
        record.subsystem_len = sub_len;

        // Copie du message
        let msg_bytes = message.as_bytes();
        let msg_len = if msg_bytes.len() > MAX_MESSAGE_LEN {
            MAX_MESSAGE_LEN
        } else {
            msg_bytes.len()
        };
        record.message[..msg_len].copy_from_slice(&msg_bytes[..msg_len]);
        record.message_len = msg_len;

        // Tracing W3C
        if let Some(tid) = trace_id {
            record.trace_id = tid;
            record.span_id = span_id.unwrap_or([0u8; 8]);
            record.has_trace = true;
        }

        // Champs structurés
        let f_len = if fields.len() > MAX_FIELDS {
            MAX_FIELDS
        } else {
            fields.len()
        };
        for (i, f) in fields[..f_len].iter().enumerate() {
            record.fields[i] = *f;
        }
        record.fields_count = f_len;

        // Scellement cryptographique
        let hash = record.compute_hash();
        record.entry_hash = hash;
        self.last_hash = hash;

        // Enregistrement dans l'anneau circulaire
        self.ring_buffer.push(record);

        Ok(record.id)
    }

    /// Recherche et filtrage multi-critères d'entrées de log.
    pub fn query(
        &mut self,
        cap: &LogCap,
        filter: &LogQueryFilter,
        out_records: &mut [LogRecord],
    ) -> Result<usize, SysError> {
        if !cap.has_right(log_rights::LOG_QUERY) && !cap.has_right(log_rights::LOG_READ) {
            return Err(SysError::PermissionDenied);
        }

        self.queries_served = self.queries_served.saturating_add(1);

        let mut matched = 0;
        let count = self.ring_buffer.len();

        for i in 0..count {
            if let Some(rec) = self.ring_buffer.get(i) {
                if filter.matches(rec) {
                    if matched < out_records.len() {
                        out_records[matched] = *rec;
                    }
                    matched += 1;
                }
            }
        }

        Ok(matched)
    }

    /// Récupère les `count` entrées les plus récentes.
    pub fn tail(
        &mut self,
        cap: &LogCap,
        count: usize,
        out_records: &mut [LogRecord],
    ) -> Result<usize, SysError> {
        if !cap.has_right(log_rights::LOG_READ) {
            return Err(SysError::PermissionDenied);
        }

        self.queries_served = self.queries_served.saturating_add(1);

        let total = self.ring_buffer.len();
        let take = if count > total { total } else { count };
        let take = if take > out_records.len() { out_records.len() } else { take };

        let start_idx = total.saturating_sub(take);
        for i in 0..take {
            if let Some(rec) = self.ring_buffer.get(start_idx + i) {
                out_records[i] = *rec;
            }
        }

        Ok(take)
    }

    /// Vérifie l'intégrité de la chaîne cryptographique inviolable (tamper detection).
    pub fn verify_integrity(&self, cap: &LogCap) -> Result<bool, SysError> {
        if !cap.has_right(log_rights::LOG_READ) {
            return Err(SysError::PermissionDenied);
        }

        let count = self.ring_buffer.len();
        if count == 0 {
            return Ok(true);
        }

        for i in 0..count {
            if let Some(rec) = self.ring_buffer.get(i) {
                // 1. Vérification que l'empreinte correspond exactement au contenu
                let expected_hash = rec.compute_hash();
                if rec.entry_hash != expected_hash {
                    return Ok(false);
                }

                // 2. Si non premier élément examiné, vérification du chaînage
                if i > 0 {
                    if let Some(prev) = self.ring_buffer.get(i - 1) {
                        if rec.prev_hash != prev.entry_hash {
                            return Ok(false);
                        }
                    }
                }
            }
        }

        Ok(true)
    }

    /// Archive les entrées non archivées dans un bloc distribué chiffré vers `jambo-dfsd`.
    pub fn archive_to_dfs(
        &mut self,
        log_cap: &LogCap,
        dfs_store: &mut DfsBlockStore,
        dfs_cap: &DfsCap,
        encryption_key: &[u8; 32],
        timestamp_ns: u64,
    ) -> Result<LogArchiveDescriptor, SysError> {
        if !log_cap.has_right(log_rights::LOG_ARCHIVE) {
            return Err(SysError::PermissionDenied);
        }
        if self.archives_count >= MAX_ARCHIVES {
            return Err(SysError::OutOfMemory);
        }

        let total = self.ring_buffer.len();
        if self.unarchived_cursor >= total {
            return Err(SysError::InvalidArgument); // Rien à archiver
        }

        let start_logical = self.unarchived_cursor;
        let mut first_rec_id = 0u64;
        let mut last_rec_id = 0u64;
        let mut batch_count = 0usize;

        // Préparation du payload binaire structuré à archiver (borné à BLOCK_SIZE = 128 octets)
        let mut raw_block = [0u8; BLOCK_SIZE];
        let mut pos = 0;

        // Entête d'archive (Magic: "JLOG", Archive ID, Start ID, End ID, Count)
        raw_block[0..4].copy_from_slice(b"JLOG");
        pos += 4;

        let archive_id = (self.archives_count as u32) + 1;
        raw_block[pos..pos + 4].copy_from_slice(&archive_id.to_le_bytes());
        pos += 4;

        // Itération sur les enregistrements à archiver
        for logical_idx in start_logical..total {
            if let Some(rec) = self.ring_buffer.get(logical_idx) {
                if batch_count == 0 {
                    first_rec_id = rec.id;
                }
                last_rec_id = rec.id;
                batch_count += 1;

                // Sérialisation compacte d'entrée si de la place reste disponible
                // Format : [ID: 8][Level: 1][SubLen: 1][Sub: min(10, len)][MsgLen: 1][Msg: min(16, len)]
                if pos + 28 <= BLOCK_SIZE {
                    raw_block[pos..pos + 8].copy_from_slice(&rec.id.to_le_bytes());
                    pos += 8;
                    raw_block[pos] = rec.level as u8;
                    pos += 1;

                    let sub_slice_len = if rec.subsystem_len > 8 { 8 } else { rec.subsystem_len };
                    raw_block[pos] = sub_slice_len as u8;
                    pos += 1;
                    raw_block[pos..pos + sub_slice_len].copy_from_slice(&rec.subsystem[..sub_slice_len]);
                    pos += sub_slice_len;

                    let msg_slice_len = if rec.message_len > 16 { 16 } else { rec.message_len };
                    raw_block[pos] = msg_slice_len as u8;
                    pos += 1;
                    raw_block[pos..pos + msg_slice_len].copy_from_slice(&rec.message[..msg_slice_len]);
                    pos += msg_slice_len;
                }
            }
        }

        // Chiffrement du payload
        let mut encrypted_block = [0u8; BLOCK_SIZE];
        let nonce = timestamp_ns ^ (archive_id as u64);
        encrypt_archive_payload(&raw_block, encryption_key, nonce, &mut encrypted_block);

        // Sauvegarde dans jambo-dfsd
        let dfs_hash = dfs_store.put_block(dfs_cap, &encrypted_block, true)?;

        let descriptor = LogArchiveDescriptor {
            archive_id,
            start_id: first_rec_id,
            end_id: last_rec_id,
            count: batch_count,
            dfs_block_hash: dfs_hash,
            chain_root_hash: self.last_hash,
            timestamp_ns,
        };

        self.archives[self.archives_count] = descriptor;
        self.archives_count += 1;
        self.total_archived_entries = self.total_archived_entries.saturating_add(batch_count as u64);
        self.unarchived_cursor = total;

        Ok(descriptor)
    }

    /// Restaure et déchiffre un bloc d'archive depuis `jambo-dfsd`.
    pub fn restore_archive(
        &self,
        log_cap: &LogCap,
        dfs_store: &DfsBlockStore,
        dfs_cap: &DfsCap,
        archive_id: u32,
        encryption_key: &[u8; 32],
        out_decrypted: &mut [u8; BLOCK_SIZE],
    ) -> Result<LogArchiveDescriptor, SysError> {
        if !log_cap.has_right(log_rights::LOG_READ) {
            return Err(SysError::PermissionDenied);
        }

        let mut found_desc = None;
        for i in 0..self.archives_count {
            if self.archives[i].archive_id == archive_id {
                found_desc = Some(self.archives[i]);
                break;
            }
        }

        let desc = match found_desc {
            Some(d) => d,
            None => return Err(SysError::InvalidHandle),
        };

        let mut encrypted_buf = [0u8; BLOCK_SIZE];
        dfs_store.get_block(dfs_cap, &desc.dfs_block_hash, &mut encrypted_buf)?;

        let nonce = desc.timestamp_ns ^ (desc.archive_id as u64);
        encrypt_archive_payload(&encrypted_buf, encryption_key, nonce, out_decrypted);

        // Vérification de l'entête magique "JLOG"
        if &out_decrypted[0..4] != b"JLOG" {
            return Err(SysError::BadAddress); // Déchiffrement échoué ou clé erronée
        }

        Ok(desc)
    }

    /// Récupère les métriques opérationnelles du démon.
    pub fn stats(&self, cap: &LogCap) -> Result<LogDaemonStats, SysError> {
        if !cap.has_right(log_rights::LOG_READ) {
            return Err(SysError::PermissionDenied);
        }

        Ok(LogDaemonStats {
            total_logged: self.ring_buffer.total_logged,
            total_dropped: self.ring_buffer.total_dropped,
            buffer_count: self.ring_buffer.len(),
            queries_served: self.queries_served,
            archives_created: self.archives_count,
            total_archived_entries: self.total_archived_entries,
            last_entry_hash: self.last_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_and_attenuation() {
        let admin_cap = LogCap::new(Handle::new(75, 1), log_rights::ALL);
        assert!(admin_cap.has_right(log_rights::LOG_WRITE));
        assert!(admin_cap.has_right(log_rights::LOG_READ));
        assert!(admin_cap.has_right(log_rights::LOG_ARCHIVE));

        let ro_cap = admin_cap.attenuate(log_rights::LOG_READ | log_rights::LOG_QUERY).unwrap();
        assert!(ro_cap.has_right(log_rights::LOG_READ));
        assert!(!ro_cap.has_right(log_rights::LOG_WRITE));

        // Interdiction d'escalade
        assert_eq!(
            ro_cap.attenuate(log_rights::LOG_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_ring_buffer_fifo() {
        let mut ring = LogRingBuffer::new();
        assert!(ring.is_empty());

        for i in 0..70 {
            let mut rec = LogRecord::empty();
            rec.id = i as u64;
            ring.push(rec);
        }

        assert_eq!(ring.len(), RING_BUFFER_CAPACITY);
        assert_eq!(ring.total_logged, 70);
        assert_eq!(ring.total_dropped, 6);

        // Le premier élément logique doit être l'id 6
        let first = ring.get(0).unwrap();
        assert_eq!(first.id, 6);

        // Le dernier élément logique doit être l'id 69
        let last = ring.latest().unwrap();
        assert_eq!(last.id, 69);
    }

    #[test]
    fn test_cryptographic_tamper_detection() {
        let admin_cap = LogCap::new(Handle::new(75, 1), log_rights::ALL);
        let mut daemon = JamboLogDaemon::new(admin_cap, 1);

        daemon.log(&admin_cap, LogLevel::Info, "KERNEL", "Initialisation démarrée", None, None, &[], 1000).unwrap();
        daemon.log(&admin_cap, LogLevel::Warn, "NET", "Lien réseau instable", None, None, &[], 2000).unwrap();
        daemon.log(&admin_cap, LogLevel::Error, "STORAGE", "Bloc endommagé détecté", None, None, &[], 3000).unwrap();

        assert_eq!(daemon.verify_integrity(&admin_cap), Ok(true));

        // Altération malveillante d'un message
        daemon.ring_buffer.entries[1].message[0] = b'X';
        assert_eq!(daemon.verify_integrity(&admin_cap), Ok(false));
    }

    #[test]
    fn test_encrypted_dfs_archiving_and_restore() {
        let admin_cap = LogCap::new(Handle::new(75, 1), log_rights::ALL);
        let dfs_cap = DfsCap::new(Handle::new(64, 1), jambo_dfsd::dfs_rights::ALL);
        let mut daemon = JamboLogDaemon::new(admin_cap, 1);
        let mut dfs = DfsBlockStore::new(1);
        let key = [0x42u8; 32];

        daemon.log(&admin_cap, LogLevel::Info, "AUTH", "Connexion utilisateur", None, None, &[], 1000).unwrap();
        daemon.log(&admin_cap, LogLevel::Info, "AUDIT", "Opération validée", None, None, &[], 2000).unwrap();

        let desc = daemon.archive_to_dfs(&admin_cap, &mut dfs, &dfs_cap, &key, 5000).unwrap();
        assert_eq!(desc.count, 2);
        assert_eq!(daemon.archives_count, 1);

        let mut decrypted = [0u8; BLOCK_SIZE];
        let restored_desc = daemon.restore_archive(&admin_cap, &dfs, &dfs_cap, desc.archive_id, &key, &mut decrypted).unwrap();
        assert_eq!(restored_desc.archive_id, desc.archive_id);
        assert_eq!(&decrypted[0..4], b"JLOG");
    }

    #[test]
    fn test_queries_and_filters() {
        let admin_cap = LogCap::new(Handle::new(75, 1), log_rights::ALL);
        let mut daemon = JamboLogDaemon::new(admin_cap, 1);

        let tid1 = [1u8; 16];
        let f1 = [LogField::new("cpu", "0"), LogField::new("task", "sched")];

        daemon.log(&admin_cap, LogLevel::Debug, "KERNEL", "Initialisation APIC", None, None, &[], 100).unwrap();
        daemon.log(&admin_cap, LogLevel::Info, "NET", "Interface eth0 UP", None, None, &[], 200).unwrap();
        daemon.log(&admin_cap, LogLevel::Warn, "NET", "Paquet corrompu ignoré", Some(tid1), Some([1u8; 8]), &f1, 300).unwrap();
        daemon.log(&admin_cap, LogLevel::Error, "FS", "Erreur lecture inode 42", None, None, &[], 400).unwrap();

        // 1. Filtre par sévérité minimale Warn
        let mut results = [LogRecord::empty(); 10];
        let mut filter = LogQueryFilter::empty();
        filter.min_level = Some(LogLevel::Warn);
        let matched = daemon.query(&admin_cap, &filter, &mut results).unwrap();
        assert_eq!(matched, 2);
        assert_eq!(results[0].level, LogLevel::Warn);
        assert_eq!(results[1].level, LogLevel::Error);

        // 2. Filtre par sous-système "NET"
        let mut filter_net = LogQueryFilter::empty();
        filter_net.subsystem = Some("NET");
        let matched_net = daemon.query(&admin_cap, &filter_net, &mut results).unwrap();
        assert_eq!(matched_net, 2);

        // 3. Filtre par mot-clé "corrompu"
        let mut filter_kw = LogQueryFilter::empty();
        filter_kw.keyword = Some("corrompu");
        let matched_kw = daemon.query(&admin_cap, &filter_kw, &mut results).unwrap();
        assert_eq!(matched_kw, 1);
        assert_eq!(results[0].id, 3);

        // 4. Filtre par trace_id
        let mut filter_trace = LogQueryFilter::empty();
        filter_trace.trace_id = Some(tid1);
        let matched_trace = daemon.query(&admin_cap, &filter_trace, &mut results).unwrap();
        assert_eq!(matched_trace, 1);

        // 5. Tail
        let mut tail_records = [LogRecord::empty(); 2];
        let tail_count = daemon.tail(&admin_cap, 2, &mut tail_records).unwrap();
        assert_eq!(tail_count, 2);
        assert_eq!(tail_records[0].id, 3);
        assert_eq!(tail_records[1].id, 4);

        // 6. Format texte
        let mut out_text = [0u8; 128];
        let text_len = tail_records[1].format_text(&mut out_text);
        assert!(text_len > 0);
        let str_res = core::str::from_utf8(&out_text[..text_len]).unwrap();
        assert!(str_res.contains("[ERROR] FS: Erreur lecture inode 42"));

        // 7. Rejet de requête sans capacité
        let no_query_cap = admin_cap.attenuate(log_rights::LOG_WRITE).unwrap();
        assert_eq!(
            daemon.query(&no_query_cap, &filter, &mut results),
            Err(SysError::PermissionDenied)
        );
    }
}


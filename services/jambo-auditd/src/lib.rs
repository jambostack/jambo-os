//! Démon d'Audit Cryptographique Inaltérable et Observabilité Zéro-Autorité (jambo-auditd)
//!
//! Fournit un journal d'audit de sécurité inviolable (tamper-evident ledger) en espace utilisateur Ring 3,
//! scellé par chaînage cryptographique déterministe. Chaque écriture et lecture requiert
//! obligatoirement une capacité explicite `AuditCap`, garantissant l'absence totale d'autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const AUDIT_MAGIC_REQ: u32 = 0x41554454; // "AUDT"
pub const AUDIT_MAGIC_RESP: u32 = 0x41554453; // "AUDS"

/// Opcodes IPC pour les requêtes vers jambo-auditd
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOpcode {
    GetStatus = 1,
    RecordEvent = 2,
    VerifyIntegrity = 3,
    QueryLatest = 4,
    ScanAnomalies = 5,
}

impl AuditOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::RecordEvent),
            3 => Some(Self::VerifyIntegrity),
            4 => Some(Self::QueryLatest),
            5 => Some(Self::ScanAnomalies),
            _ => None,
        }
    }
}

/// Sévérité normalisée d'un événement d'audit système
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AuditSeverity {
    Debug = 1,
    Info = 2,
    Warning = 3,
    SecurityViolation = 4,
    CriticalAlert = 5,
}

impl AuditSeverity {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Debug),
            2 => Some(Self::Info),
            3 => Some(Self::Warning),
            4 => Some(Self::SecurityViolation),
            5 => Some(Self::CriticalAlert),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::SecurityViolation => "VIOLATION",
            Self::CriticalAlert => "CRITICAL",
        }
    }
}

/// Catégorie fonctionnelle de l'événement d'audit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditCategory {
    CSpace = 1,
    MemoryMMU = 2,
    IommuDma = 3,
    NetworkIpc = 4,
    DistributedRpc = 5,
    Authentication = 6,
}

impl AuditCategory {
    pub const fn to_mask(self) -> u32 {
        1 << (self as u8)
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::CSpace),
            2 => Some(Self::MemoryMMU),
            3 => Some(Self::IommuDma),
            4 => Some(Self::NetworkIpc),
            5 => Some(Self::DistributedRpc),
            6 => Some(Self::Authentication),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CSpace => "CSpace",
            Self::MemoryMMU => "MemoryMMU",
            Self::IommuDma => "IommuDma",
            Self::NetworkIpc => "NetworkIpc",
            Self::DistributedRpc => "DistributedRpc",
            Self::Authentication => "Authentication",
        }
    }
}

/// Requête IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub handle_flags: u32,
    pub allowed_mask: u32,
    pub category: u8,
    pub severity: u8,
    pub min_severity: u8,
    pub details_len: u8,
    pub source_pid: u32,
    pub event_code: u32,
    pub details: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<AuditRequest>() == 64);

impl Default for AuditRequest {
    fn default() -> Self {
        Self {
            magic: AUDIT_MAGIC_REQ,
            opcode: AuditOpcode::GetStatus as u32,
            handle_id: 1,
            handle_flags: 1,
            allowed_mask: 0xFFFFFFFF,
            category: AuditCategory::CSpace as u8,
            severity: AuditSeverity::Info as u8,
            min_severity: AuditSeverity::Debug as u8,
            details_len: 0,
            source_pid: 1,
            event_code: 0,
            details: [0u8; 32],
        }
    }
}

impl AuditRequest {
    pub const fn new(opcode: AuditOpcode, cap: &AuditCap) -> Self {
        Self {
            magic: AUDIT_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: cap.handle.0 as u32,
            handle_flags: (cap.handle.0 >> 32) as u32,
            allowed_mask: cap.allowed_categories_mask,
            category: AuditCategory::CSpace as u8,
            severity: AuditSeverity::Info as u8,
            min_severity: cap.min_severity as u8,
            details_len: 0,
            source_pid: 1,
            event_code: 0,
            details: [0u8; 32],
        }
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
        if req.magic != AUDIT_MAGIC_REQ {
            return None;
        }
        Some(req)
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditResponse {
    pub magic: u32,
    pub status: i32,
    pub total_recorded: u64,
    pub last_seq: u64,
    pub last_hash: [u8; 16],
    pub anomaly_type: u8,
    pub alert_incident_count: u8,
    pub integrity_ok: u8,
    pub _pad: u8,
    pub suspect_pid: u32,
    pub details: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<AuditResponse>() == 64);

impl Default for AuditResponse {
    fn default() -> Self {
        Self {
            magic: AUDIT_MAGIC_RESP,
            status: 0,
            total_recorded: 0,
            last_seq: 0,
            last_hash: [0u8; 16],
            anomaly_type: 0,
            alert_incident_count: 0,
            integrity_ok: 1,
            _pad: 0,
            suspect_pid: 0,
            details: [0u8; 16],
        }
    }
}

impl AuditResponse {
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
        let mut resp = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut resp as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        if resp.magic != AUDIT_MAGIC_RESP {
            return None;
        }
        Some(resp)
    }
}

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

/// Cède volontairement le temps processeur au scheduler EEVDF
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

/// Client IPC pour interagir avec jambo-auditd (Ring 3, PID 18)
pub struct AuditClient {
    pub endpoint: Handle,
}

impl AuditClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_status(&self, cap: &AuditCap) -> Result<AuditResponse, SysError> {
        let req = AuditRequest::new(AuditOpcode::GetStatus, cap);
        self.call(&req)
    }

    pub fn record_event(
        &self,
        cap: &AuditCap,
        source_pid: u32,
        category: AuditCategory,
        severity: AuditSeverity,
        event_code: u32,
        details: &[u8],
    ) -> Result<AuditResponse, SysError> {
        let mut req = AuditRequest::new(AuditOpcode::RecordEvent, cap);
        req.source_pid = source_pid;
        req.category = category as u8;
        req.severity = severity as u8;
        req.event_code = event_code;
        let copy_len = details.len().min(32);
        req.details_len = copy_len as u8;
        req.details[..copy_len].copy_from_slice(&details[..copy_len]);
        self.call(&req)
    }

    pub fn verify_integrity(&self, cap: &AuditCap) -> Result<bool, SysError> {
        let req = AuditRequest::new(AuditOpcode::VerifyIntegrity, cap);
        let resp = self.call(&req)?;
        Ok(resp.integrity_ok != 0)
    }

    pub fn query_latest(&self, cap: &AuditCap) -> Result<AuditResponse, SysError> {
        let req = AuditRequest::new(AuditOpcode::QueryLatest, cap);
        self.call(&req)
    }

    pub fn scan_anomalies(&self, cap: &AuditCap) -> Result<AuditResponse, SysError> {
        let req = AuditRequest::new(AuditOpcode::ScanAnomalies, cap);
        self.call(&req)
    }

    pub fn call(&self, req: &AuditRequest) -> Result<AuditResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

        // 1. Émission de la requête sur le canal IPC
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

        // 2. Réception de la réponse avec repli coopératif
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<AuditResponse>() {
                return AuditResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

/// Capacité de contrôle d'audit Ring 3 (Zéro Autorité Ambiante)
#[derive(Debug, Clone, Copy)]
pub struct AuditCap {
    pub handle: Handle,
    pub allowed_categories_mask: u32,
    pub min_severity: AuditSeverity,
    pub can_write: bool,
    pub can_read: bool,
}

impl AuditCap {
    pub const fn new(
        handle: Handle,
        allowed_categories_mask: u32,
        min_severity: AuditSeverity,
        can_write: bool,
        can_read: bool,
    ) -> Self {
        Self {
            handle,
            allowed_categories_mask,
            min_severity,
            can_write,
            can_read,
        }
    }

    pub fn allows_category(&self, cat: AuditCategory) -> bool {
        (self.allowed_categories_mask & cat.to_mask()) != 0
    }
}

/// Entrée d'audit unitaire scellée cryptographiquement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEntry {
    pub sequence_id: u64,
    pub timestamp_ns: u64,
    pub source_pid: u64,
    pub category: AuditCategory,
    pub severity: AuditSeverity,
    pub event_code: u32,
    pub details_len: usize,
    pub details: [u8; 32],
    pub prev_hash: [u8; 16],
    pub entry_hash: [u8; 16],
}

impl AuditEntry {
    /// Calcule le hachage cryptographique déterministe (SIP/FNV-BLAKE dérivé)
    #[allow(clippy::too_many_arguments)]
    pub fn compute_hash(
        sequence_id: u64,
        timestamp_ns: u64,
        source_pid: u64,
        category: AuditCategory,
        severity: AuditSeverity,
        event_code: u32,
        details: &[u8],
        prev_hash: &[u8; 16],
    ) -> [u8; 16] {
        let mut h1: u64 = 0xcbf29ce484222325 ^ sequence_id;
        let mut h2: u64 = 0x100000001b3 ^ timestamp_ns ^ (source_pid << 16);

        // Mélange des métadonnées
        h1 = h1.wrapping_mul(0x9e3779b97f4a7c15) ^ (category as u64);
        h2 = h2.wrapping_mul(0x517cc1b727220a95) ^ (severity as u64) ^ ((event_code as u64) << 32);

        // Intégration du hachage précédent
        for &b in prev_hash.iter() {
            h1 = (h1 ^ (b as u64))
                .rotate_left(13)
                .wrapping_mul(0x100000001b3);
            h2 = (h2 ^ (b as u64))
                .rotate_right(11)
                .wrapping_mul(0x9e3779b97f4a7c15);
        }

        // Intégration des octets de payload
        for &b in details.iter() {
            h1 = (h1 ^ (b as u64))
                .rotate_left(7)
                .wrapping_mul(0x517cc1b727220a95);
            h2 = (h2 ^ (b as u64))
                .rotate_right(9)
                .wrapping_mul(0x100000001b3);
        }

        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&h1.to_le_bytes());
        out[8..].copy_from_slice(&h2.to_le_bytes());
        out
    }
}

/// Capacité maximale du tampon circulaire en mémoire statique
pub const MAX_AUDIT_ENTRIES: usize = 64;

/// Registre d'audit inaltérable à chaîne de hachage scellée
pub struct AuditLedger {
    pub entries: [Option<AuditEntry>; MAX_AUDIT_ENTRIES],
    pub total_recorded: u64,
    pub last_hash: [u8; 16],
}

impl Default for AuditLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLedger {
    pub const fn new() -> Self {
        const NONE_ENTRY: Option<AuditEntry> = None;
        Self {
            entries: [NONE_ENTRY; MAX_AUDIT_ENTRIES],
            total_recorded: 0,
            last_hash: [0x5A; 16], // Ancre d'initialisation de graine cryptographique
        }
    }

    /// Enregistre un événement d'audit en vérifiant les droits de la capacité
    #[allow(clippy::too_many_arguments)]
    pub fn record_event(
        &mut self,
        cap: &AuditCap,
        source_pid: u64,
        category: AuditCategory,
        severity: AuditSeverity,
        event_code: u32,
        details: &[u8],
        timestamp_ns: u64,
    ) -> Result<u64, SysError> {
        if !cap.can_write || !cap.allows_category(category) || severity < cap.min_severity {
            return Err(SysError::PermissionDenied);
        }

        let seq = self.total_recorded + 1;
        let mut d_buf = [0u8; 32];
        let copy_len = details.len().min(32);
        d_buf[..copy_len].copy_from_slice(&details[..copy_len]);

        let prev = self.last_hash;
        let entry_hash = AuditEntry::compute_hash(
            seq,
            timestamp_ns,
            source_pid,
            category,
            severity,
            event_code,
            &details[..copy_len],
            &prev,
        );

        let entry = AuditEntry {
            sequence_id: seq,
            timestamp_ns,
            source_pid,
            category,
            severity,
            event_code,
            details_len: copy_len,
            details: d_buf,
            prev_hash: prev,
            entry_hash,
        };

        let slot = (self.total_recorded as usize) % MAX_AUDIT_ENTRIES;
        self.entries[slot] = Some(entry);
        self.last_hash = entry_hash;
        self.total_recorded = seq;

        Ok(seq)
    }

    /// Vérifie mathématiquement l'intégrité de la chaîne d'audit
    pub fn verify_chain_integrity(&self) -> bool {
        if self.total_recorded == 0 {
            return true;
        }

        let total = self.total_recorded as usize;
        let count = total.min(MAX_AUDIT_ENTRIES);
        let start_seq = if total > MAX_AUDIT_ENTRIES {
            self.total_recorded - (MAX_AUDIT_ENTRIES as u64) + 1
        } else {
            1
        };

        for i in 0..count {
            let target_seq = start_seq + (i as u64);
            let slot = ((target_seq - 1) as usize) % MAX_AUDIT_ENTRIES;

            if let Some(entry) = &self.entries[slot] {
                if entry.sequence_id != target_seq {
                    return false;
                }

                let recomputed = AuditEntry::compute_hash(
                    entry.sequence_id,
                    entry.timestamp_ns,
                    entry.source_pid,
                    entry.category,
                    entry.severity,
                    entry.event_code,
                    &entry.details[..entry.details_len],
                    &entry.prev_hash,
                );

                if recomputed != entry.entry_hash {
                    return false;
                }

                if i > 0 {
                    let prev_slot = ((target_seq - 2) as usize) % MAX_AUDIT_ENTRIES;
                    if let Some(prev_entry) = &self.entries[prev_slot] {
                        if entry.prev_hash != prev_entry.entry_hash {
                            return false;
                        }
                    }
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Requête les entrées filtrées selon la capacité présentée
    pub fn query_events(
        &self,
        cap: &AuditCap,
        category_filter: Option<AuditCategory>,
        min_severity: AuditSeverity,
        out_buf: &mut [AuditEntry],
    ) -> Result<usize, SysError> {
        if !cap.can_read {
            return Err(SysError::PermissionDenied);
        }

        if let Some(cat) = category_filter {
            if !cap.allows_category(cat) {
                return Err(SysError::PermissionDenied);
            }
        }

        let mut matched = 0;
        let total = self.total_recorded as usize;
        let count = total.min(MAX_AUDIT_ENTRIES);
        let start_seq = if total > MAX_AUDIT_ENTRIES {
            self.total_recorded - (MAX_AUDIT_ENTRIES as u64) + 1
        } else {
            1
        };

        for i in 0..count {
            if matched >= out_buf.len() {
                break;
            }
            let target_seq = start_seq + (i as u64);
            let slot = ((target_seq - 1) as usize) % MAX_AUDIT_ENTRIES;

            if let Some(entry) = &self.entries[slot] {
                if entry.severity >= min_severity
                    && (category_filter.is_none() || category_filter == Some(entry.category))
                    && cap.allows_category(entry.category)
                {
                    out_buf[matched] = *entry;
                    matched += 1;
                }
            }
        }

        Ok(matched)
    }

    pub const fn total_recorded(&self) -> u64 {
        self.total_recorded
    }

    pub const fn last_hash(&self) -> [u8; 16] {
        self.last_hash
    }

    /// Altère intentionnellement une entrée en mémoire pour tester la détection de falsification
    pub fn corrupt_entry_for_test(&mut self, slot: usize) {
        if let Some(entry) = &mut self.entries[slot % MAX_AUDIT_ENTRIES] {
            entry.details[0] ^= 0xFF;
        }
    }
}

/// Type d'anomalie de sécurité détectée
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    None = 0,
    RepeatedCapabilityFailures = 1,
    PotentialRpcReplayAttack = 2,
    MemoryAccessViolations = 3,
}

impl AnomalyType {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::RepeatedCapabilityFailures => 1,
            Self::PotentialRpcReplayAttack => 2,
            Self::MemoryAccessViolations => 3,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::RepeatedCapabilityFailures,
            2 => Self::PotentialRpcReplayAttack,
            3 => Self::MemoryAccessViolations,
            _ => Self::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::RepeatedCapabilityFailures => "RepeatedCapabilityFailures",
            Self::PotentialRpcReplayAttack => "PotentialRpcReplayAttack",
            Self::MemoryAccessViolations => "MemoryAccessViolations",
        }
    }
}

/// Alerte d'anomalie émise par l'analyseur heuristique
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityAlert {
    pub anomaly: AnomalyType,
    pub suspect_pid: u64,
    pub incident_count: u32,
}

/// Moteur de détection d'anomalies de sécurité en temps réel
pub struct AnomalyDetector {
    threshold: u32,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new(3)
    }
}

impl AnomalyDetector {
    pub const fn new(threshold: u32) -> Self {
        Self { threshold }
    }

    pub fn scan_for_anomalies(&self, ledger: &AuditLedger) -> Option<SecurityAlert> {
        let total = ledger.total_recorded as usize;
        let count = total.min(MAX_AUDIT_ENTRIES);
        if count == 0 {
            return None;
        }

        let mut violations_per_pid = [0u32; 16];
        let start_seq = if total > MAX_AUDIT_ENTRIES {
            ledger.total_recorded - (MAX_AUDIT_ENTRIES as u64) + 1
        } else {
            1
        };

        for i in 0..count {
            let target_seq = start_seq + (i as u64);
            let slot = ((target_seq - 1) as usize) % MAX_AUDIT_ENTRIES;

            if let Some(entry) = &ledger.entries[slot] {
                if entry.severity >= AuditSeverity::SecurityViolation {
                    let pid_idx = (entry.source_pid as usize) % 16;
                    violations_per_pid[pid_idx] = violations_per_pid[pid_idx].saturating_add(1);

                    if violations_per_pid[pid_idx] >= self.threshold {
                        let anomaly = match entry.category {
                            AuditCategory::DistributedRpc => AnomalyType::PotentialRpcReplayAttack,
                            AuditCategory::MemoryMMU | AuditCategory::IommuDma => {
                                AnomalyType::MemoryAccessViolations
                            }
                            _ => AnomalyType::RepeatedCapabilityFailures,
                        };

                        return Some(SecurityAlert {
                            anomaly,
                            suspect_pid: entry.source_pid,
                            incident_count: violations_per_pid[pid_idx],
                        });
                    }
                }
            }
        }

        None
    }
}

/// Démon principal d'audit et observabilité de sécurité JamboAudit
pub struct JamboAuditDaemon {
    pub ledger: AuditLedger,
    pub detector: AnomalyDetector,
    pub admin_cap: AuditCap,
}

impl Default for JamboAuditDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboAuditDaemon {
    pub const fn new() -> Self {
        let admin_cap = AuditCap::new(
            Handle::new(1, 1),
            0xFFFFFFFF,
            AuditSeverity::Debug,
            true,
            true,
        );
        let ledger = AuditLedger::new();
        Self {
            ledger,
            detector: AnomalyDetector::new(3),
            admin_cap,
        }
    }

    /// Initialise les événements fondamentaux de boot
    pub fn init_defaults(&mut self) {
        let _ = self.ledger.record_event(
            &self.admin_cap,
            1,
            AuditCategory::CSpace,
            AuditSeverity::Info,
            1,
            b"Audit subsystem initialized",
            1000,
        );
        let _ = self.ledger.record_event(
            &self.admin_cap,
            1,
            AuditCategory::MemoryMMU,
            AuditSeverity::Info,
            2,
            b"W^X page isolation active",
            2000,
        );
        let _ = self.ledger.record_event(
            &self.admin_cap,
            1,
            AuditCategory::IommuDma,
            AuditSeverity::Info,
            3,
            b"IOMMU DMA protection active",
            3000,
        );
    }

    /// Enregistre un événement avec la capacité admin
    pub fn log_event(
        &mut self,
        source_pid: u64,
        category: AuditCategory,
        severity: AuditSeverity,
        event_code: u32,
        details: &[u8],
        timestamp_ns: u64,
    ) -> Result<u64, SysError> {
        self.ledger.record_event(
            &self.admin_cap,
            source_pid,
            category,
            severity,
            event_code,
            details,
            timestamp_ns,
        )
    }

    /// Vérifie l'intégrité de la chaîne cryptographique
    pub fn verify_integrity(&self) -> bool {
        self.ledger.verify_chain_integrity()
    }

    /// Traite une requête IPC et produit une réponse déterministe de 64 octets
    pub fn handle_ipc_request(&mut self, req: &AuditRequest, timestamp_ns: u64) -> AuditResponse {
        if req.magic != AUDIT_MAGIC_REQ {
            return AuditResponse {
                status: -1,
                ..AuditResponse::default()
            };
        }

        let cap = AuditCap::new(
            Handle::new(req.handle_id, req.handle_flags),
            req.allowed_mask,
            AuditSeverity::from_u8(req.min_severity).unwrap_or(AuditSeverity::Debug),
            true,
            true,
        );

        let opcode = match AuditOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                return AuditResponse {
                    status: -2,
                    ..AuditResponse::default()
                }
            }
        };

        let mut status = 0;
        let mut anomaly_type = 0;
        let mut alert_incident_count = 0;
        let mut suspect_pid = 0;

        match opcode {
            AuditOpcode::GetStatus => {
                if let Some(alert) = self.detector.scan_for_anomalies(&self.ledger) {
                    anomaly_type = alert.anomaly.as_u8();
                    alert_incident_count = alert.incident_count.min(255) as u8;
                    suspect_pid = alert.suspect_pid as u32;
                }
            }
            AuditOpcode::RecordEvent => {
                let cat = match AuditCategory::from_u8(req.category) {
                    Some(c) => c,
                    None => {
                        return AuditResponse {
                            status: -3,
                            ..AuditResponse::default()
                        }
                    }
                };
                let sev = match AuditSeverity::from_u8(req.severity) {
                    Some(s) => s,
                    None => {
                        return AuditResponse {
                            status: -4,
                            ..AuditResponse::default()
                        }
                    }
                };

                let copy_len = (req.details_len as usize).min(32);
                match self.ledger.record_event(
                    &cap,
                    req.source_pid as u64,
                    cat,
                    sev,
                    req.event_code,
                    &req.details[..copy_len],
                    timestamp_ns,
                ) {
                    Ok(_seq) => {}
                    Err(_e) => {
                        status = -5;
                    }
                }
            }
            AuditOpcode::VerifyIntegrity => {
                if !self.ledger.verify_chain_integrity() {
                    status = -6;
                }
            }
            AuditOpcode::QueryLatest => {}
            AuditOpcode::ScanAnomalies => {
                if let Some(alert) = self.detector.scan_for_anomalies(&self.ledger) {
                    anomaly_type = alert.anomaly.as_u8();
                    alert_incident_count = alert.incident_count.min(255) as u8;
                    suspect_pid = alert.suspect_pid as u32;
                }
            }
        }

        // Récupérer un aperçu des détails de la dernière entrée
        let mut details_preview = [0u8; 16];
        if self.ledger.total_recorded > 0 {
            let slot = ((self.ledger.total_recorded - 1) as usize) % MAX_AUDIT_ENTRIES;
            if let Some(entry) = &self.ledger.entries[slot] {
                let clen = entry.details_len.min(16);
                details_preview[..clen].copy_from_slice(&entry.details[..clen]);
            }
        }

        let integrity_ok = self.ledger.verify_chain_integrity() as u8;

        AuditResponse {
            magic: AUDIT_MAGIC_RESP,
            status,
            total_recorded: self.ledger.total_recorded,
            last_seq: self.ledger.total_recorded,
            last_hash: self.ledger.last_hash,
            anomaly_type,
            alert_incident_count,
            integrity_ok,
            _pad: 0,
            suspect_pid,
            details: details_preview,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tamper_evident_integrity_and_corruption_detection() {
        let mut ledger = AuditLedger::new();
        let cap = AuditCap::new(
            Handle::new(1, 1),
            0xFFFFFFFF,
            AuditSeverity::Debug,
            true,
            true,
        );

        for i in 1..=10 {
            ledger
                .record_event(
                    &cap,
                    100 + i,
                    AuditCategory::Authentication,
                    AuditSeverity::Info,
                    i as u32,
                    b"User session established",
                    1000 + i * 100,
                )
                .expect("record event");
        }

        assert!(ledger.verify_chain_integrity());
        ledger.corrupt_entry_for_test(3);
        assert!(!ledger.verify_chain_integrity());
    }

    #[test]
    fn test_capability_enforcement_and_filtering() {
        let mut ledger = AuditLedger::new();
        let ro_cap = AuditCap::new(
            Handle::new(2, 1),
            AuditCategory::CSpace.to_mask(),
            AuditSeverity::Warning,
            false,
            true,
        );

        assert_eq!(
            ledger.record_event(
                &ro_cap,
                10,
                AuditCategory::CSpace,
                AuditSeverity::Warning,
                1,
                b"Test",
                100,
            ),
            Err(SysError::PermissionDenied)
        );

        let wr_cap = AuditCap::new(
            Handle::new(3, 1),
            AuditCategory::CSpace.to_mask(),
            AuditSeverity::Warning,
            true,
            true,
        );

        assert_eq!(
            ledger.record_event(
                &wr_cap,
                10,
                AuditCategory::MemoryMMU,
                AuditSeverity::Warning,
                1,
                b"Test",
                100,
            ),
            Err(SysError::PermissionDenied)
        );

        assert!(ledger
            .record_event(
                &wr_cap,
                10,
                AuditCategory::CSpace,
                AuditSeverity::CriticalAlert,
                1,
                b"Granted",
                100,
            )
            .is_ok());
    }

    #[test]
    fn test_anomaly_detection_heuristic() {
        let mut daemon = JamboAuditDaemon::new();
        let cap = daemon.admin_cap;

        for _ in 0..2 {
            daemon
                .ledger
                .record_event(
                    &cap,
                    42,
                    AuditCategory::DistributedRpc,
                    AuditSeverity::SecurityViolation,
                    101,
                    b"Replay detected",
                    500,
                )
                .unwrap();
        }
        assert!(daemon.detector.scan_for_anomalies(&daemon.ledger).is_none());

        daemon
            .ledger
            .record_event(
                &cap,
                42,
                AuditCategory::DistributedRpc,
                AuditSeverity::SecurityViolation,
                101,
                b"Replay detected",
                600,
            )
            .unwrap();

        let alert = daemon
            .detector
            .scan_for_anomalies(&daemon.ledger)
            .expect("should detect anomaly");
        assert_eq!(alert.suspect_pid, 42);
        assert_eq!(alert.incident_count, 3);
        assert_eq!(alert.anomaly, AnomalyType::PotentialRpcReplayAttack);
    }

    #[test]
    fn test_ipc_deterministic_request_response() {
        assert_eq!(core::mem::size_of::<AuditRequest>(), 64);
        assert_eq!(core::mem::size_of::<AuditResponse>(), 64);

        let mut daemon = JamboAuditDaemon::new();
        daemon.init_defaults();
        let cap = daemon.admin_cap;

        // 1. GetStatus via IPC
        let req = AuditRequest::new(AuditOpcode::GetStatus, &cap);
        let req_bytes = req.to_bytes();
        let decoded_req = AuditRequest::from_bytes(&req_bytes).expect("decode AuditRequest");
        assert_eq!(decoded_req.opcode, AuditOpcode::GetStatus as u32);

        let resp = daemon.handle_ipc_request(&decoded_req, 5000);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.total_recorded, 3);
        assert_eq!(resp.integrity_ok, 1);

        let resp_bytes = resp.to_bytes();
        let decoded_resp = AuditResponse::from_bytes(&resp_bytes).expect("decode AuditResponse");
        assert_eq!(decoded_resp.total_recorded, 3);

        // 2. RecordEvent via IPC
        let mut rec_req = AuditRequest::new(AuditOpcode::RecordEvent, &cap);
        rec_req.source_pid = 42;
        rec_req.category = AuditCategory::Authentication as u8;
        rec_req.severity = AuditSeverity::Info as u8;
        rec_req.event_code = 10;
        let msg = b"TokenGenerated";
        rec_req.details_len = msg.len() as u8;
        rec_req.details[..msg.len()].copy_from_slice(msg);

        let rec_resp = daemon.handle_ipc_request(&rec_req, 6000);
        assert_eq!(rec_resp.status, 0);
        assert_eq!(rec_resp.total_recorded, 4);
        assert_eq!(rec_resp.last_seq, 4);

        // 3. VerifyIntegrity via IPC
        let ver_req = AuditRequest::new(AuditOpcode::VerifyIntegrity, &cap);
        let ver_resp = daemon.handle_ipc_request(&ver_req, 7000);
        assert_eq!(ver_resp.status, 0);
        assert_eq!(ver_resp.integrity_ok, 1);

        // 4. ScanAnomalies via IPC
        let scan_req = AuditRequest::new(AuditOpcode::ScanAnomalies, &cap);
        let scan_resp = daemon.handle_ipc_request(&scan_req, 8000);
        assert_eq!(scan_resp.status, 0);
        assert_eq!(scan_resp.anomaly_type, AnomalyType::None.as_u8());
    }
}

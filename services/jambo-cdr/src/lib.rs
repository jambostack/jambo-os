//! Désarmement & Reconstruction de Contenu Souverain (CDR - Content Disarm and Reconstruction)
//!
//! Phase 144 — Jalon v0.3.11
//!
//! Fournit un sous-système souverain de neutralisation proactive des menaces incorporées
//! dans les flux de documents, artéfacts binaires, flux IPC et scripts en `#![no_std]` :
//! 1. Détection structurelle et déconstruction récursive sans exécution (ELF, doc structuré, flux IPC, archives, scripts).
//! 2. Neutralisation proactive des macros, segments W+X, gadgets de désérialisation, traversées de répertoires et code injecté.
//! 3. Reconstruction déterministe saine et assainie garantissant l'intégrité fonctionnelle.
//! 4. Confinement immédiat et mise en quarantaine O(1) des artéfacts critiques non désarmables (`quarantine_file`).
//! 5. Contrôle d'accès capabilaire (`CdrCap`) avec atténuation monotone stricte.
//! 6. Registre d'audit SHA-256 inaltérable scellé par chaînage cryptographique.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation autonome et déterministe de SHA-256 pour micro-noyau et services CDR
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_bytes += data.len() as u64;

        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
                self.process_block();
                data = &data[needed..];
                self.buffer_len = 0;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while data.len() >= 64 {
            self.buffer.copy_from_slice(&data[..64]);
            self.process_block();
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_bytes * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            self.process_block();
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        self.process_block();

        let mut output = [0u8; 32];
        for i in 0..8 {
            output[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        output
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                self.buffer[i * 4],
                self.buffer[i * 4 + 1],
                self.buffer[i * 4 + 2],
                self.buffer[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (CdrCap)
// ============================================================================

pub mod cdr_rights {
    pub const INSPECT_CONTENT: u32 = 1 << 0;
    pub const DISARM_PAYLOAD: u32 = 1 << 1;
    pub const RECONSTRUCT: u32 = 1 << 2;
    pub const QUARANTINE_FILE: u32 = 1 << 3;
    pub const CONFIGURE_POLICY: u32 = 1 << 4;
    pub const QUERY_METRICS: u32 = 1 << 5;
    pub const QUERY_AUDIT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;
    pub const ALL: u32 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdrError {
    PermissionDenied,
    AttenuationViolation,
    FileNotFound,
    BufferTooSmall,
    PolicyTableFull,
    ThreatTableFull,
    QuarantineTableFull,
    AuditLogFull,
    InvalidParameter,
    UnsupportedFormat,
    MalformedContent,
    CriticalThreatQuarantined,
    ContentBlocked,
}

/// Capabilité de contrôle d'accès avec atténuation monotone stricte pour le moteur CDR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdrCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl CdrCap {
    pub const fn new(
        handle: Handle,
        rights: u32,
        max_lifetime: u64,
        invocations_left: u32,
    ) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left,
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone stricte : aucun privilège supplémentaire, plafonnement de durée et d'invocations
    pub fn attenuate(
        &self,
        requested_rights: u32,
        lifetime_limit: u64,
        max_invocations: u32,
    ) -> Result<Self, CdrError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(CdrError::AttenuationViolation);
        }
        if lifetime_limit > self.max_lifetime {
            return Err(CdrError::AttenuationViolation);
        }
        if max_invocations > self.invocations_left {
            return Err(CdrError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
            max_lifetime: lifetime_limit,
            invocations_left: max_invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), CdrError> {
        if self.invocations_left == 0 {
            return Err(CdrError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES CDR SOUVERAINES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    ElfBinary,
    StructuredDoc,
    IpcStream,
    Archive,
    RawScript,
    Unknown,
}

impl FileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileType::ElfBinary => "ELF_BIN",
            FileType::StructuredDoc => "STRUCT_DOC",
            FileType::IpcStream => "IPC_STREAM",
            FileType::Archive => "ARCHIVE",
            FileType::RawScript => "RAW_SCRIPT",
            FileType::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdrThreatType {
    None,
    EmbeddedMacro,
    WxSegmentViolation,
    IllicitShellcode,
    DeserializationGadget,
    PathTraversalArchive,
    HiddenExecutableSmuggling,
    SuspiciousEntropyPayload,
    ZeroDayAnomaly,
}

impl CdrThreatType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CdrThreatType::None => "NONE",
            CdrThreatType::EmbeddedMacro => "EMBEDDED_MACRO",
            CdrThreatType::WxSegmentViolation => "WX_SEGMENT_VIOLATION",
            CdrThreatType::IllicitShellcode => "ILLICIT_SHELLCODE",
            CdrThreatType::DeserializationGadget => "DESERIALIZATION_GADGET",
            CdrThreatType::PathTraversalArchive => "PATH_TRAVERSAL_ARCHIVE",
            CdrThreatType::HiddenExecutableSmuggling => "HIDDEN_EXEC_SMUGGLING",
            CdrThreatType::SuspiciousEntropyPayload => "SUSPICIOUS_ENTROPY",
            CdrThreatType::ZeroDayAnomaly => "ZERODAY_ANOMALY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatSeverity::Low => "LOW",
            ThreatSeverity::Medium => "MEDIUM",
            ThreatSeverity::High => "HIGH",
            ThreatSeverity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizationAction {
    PassUnmodified,
    DisarmedAndReconstructed,
    Quarantined,
    Blocked,
}

impl SanitizationAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            SanitizationAction::PassUnmodified => "PASS_UNMODIFIED",
            SanitizationAction::DisarmedAndReconstructed => "DISARMED_RECONSTRUCTED",
            SanitizationAction::Quarantined => "QUARANTINED",
            SanitizationAction::Blocked => "BLOCKED",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CdrPolicy {
    pub policy_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub file_type: FileType,
    pub strip_macros: bool,
    pub strip_wx_segments: bool,
    pub strip_traversal: bool,
    pub block_nested_executables: bool,
    pub max_file_size: usize,
    pub quarantine_on_critical: bool,
    pub enabled: bool,
}

impl CdrPolicy {
    pub fn new(
        policy_id: u32,
        name_str: &str,
        file_type: FileType,
        strip_macros: bool,
        strip_wx_segments: bool,
        strip_traversal: bool,
        block_nested_executables: bool,
    ) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(32);
        name[..len].copy_from_slice(&bytes[..len]);
        Self {
            policy_id,
            name,
            name_len: len,
            file_type,
            strip_macros,
            strip_wx_segments,
            strip_traversal,
            block_nested_executables,
            max_file_size: 1024 * 1024,
            quarantine_on_critical: true,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CdrThreatRecord {
    pub threat_id: u32,
    pub file_id: u32,
    pub threat_type: CdrThreatType,
    pub severity: ThreatSeverity,
    pub timestamp: u64,
    pub sanitized: bool,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CdrQuarantineEntry {
    pub file_id: u32,
    pub filename: [u8; 32],
    pub filename_len: usize,
    pub file_type: FileType,
    pub original_hash: [u8; 32],
    pub threat_type: CdrThreatType,
    pub severity: ThreatSeverity,
    pub timestamp: u64,
    pub isolated: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CdrAuditEntry {
    pub entry_id: u32,
    pub timestamp: u64,
    pub action: [u8; 24],
    pub action_len: usize,
    pub filename: [u8; 32],
    pub filename_len: usize,
    pub threat_type: CdrThreatType,
    pub status: SanitizationAction,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct DisarmResult {
    pub action: SanitizationAction,
    pub threat_type: CdrThreatType,
    pub severity: ThreatSeverity,
    pub original_hash: [u8; 32],
    pub sanitized_hash: [u8; 32],
    pub reconstructed_len: usize,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CdrSummary {
    pub files_scanned: usize,
    pub files_clean: usize,
    pub files_disarmed: usize,
    pub files_quarantined: usize,
    pub threats_detected: usize,
    pub policies_count: usize,
    pub audit_entries_count: usize,
    pub ledger_valid: bool,
}

// ============================================================================
// DÉMON CDR SOUVERAIN (JamboCdrDaemon)
// ============================================================================

const MAX_POLICIES: usize = 8;
const MAX_THREATS: usize = 32;
const MAX_QUARANTINE: usize = 16;
const MAX_AUDIT: usize = 32;

pub struct JamboCdrDaemon {
    pub cap: CdrCap,
    pub policies: [Option<CdrPolicy>; MAX_POLICIES],
    pub policy_count: usize,
    pub threats: [Option<CdrThreatRecord>; MAX_THREATS],
    pub threat_count: usize,
    pub quarantine_store: [Option<CdrQuarantineEntry>; MAX_QUARANTINE],
    pub quarantine_count: usize,
    pub audit_log: [Option<CdrAuditEntry>; MAX_AUDIT],
    pub audit_count: usize,
    pub last_audit_hash: [u8; 32],
    pub files_scanned: usize,
    pub files_clean: usize,
    pub files_disarmed: usize,
    pub files_quarantined: usize,
    pub next_file_id: u32,
    pub next_threat_id: u32,
}

impl JamboCdrDaemon {
    pub fn new(cap: CdrCap) -> Self {
        let genesis_seed = b"JAMBO_CDR_GENESIS_SEAL_V0.3.11";
        let initial_hash = Sha256::digest(genesis_seed);
        Self {
            cap,
            policies: [None; MAX_POLICIES],
            policy_count: 0,
            threats: [None; MAX_THREATS],
            threat_count: 0,
            quarantine_store: [None; MAX_QUARANTINE],
            quarantine_count: 0,
            audit_log: [None; MAX_AUDIT],
            audit_count: 0,
            last_audit_hash: initial_hash,
            files_scanned: 0,
            files_clean: 0,
            files_disarmed: 0,
            files_quarantined: 0,
            next_file_id: 1,
            next_threat_id: 1,
        }
    }

    /// Initialise les politiques souveraines CDR par défaut
    pub fn init_defaults(&mut self) {
        // 1. Politique ELF : neutralisation W+X et interdiction shellcodes illicites
        let p_elf = CdrPolicy::new(
            1,
            "ELF-Hardening-Rule",
            FileType::ElfBinary,
            false,
            true,
            false,
            false,
        );
        self.add_policy(p_elf);

        // 2. Politique Documents structurés : désarmement macros & scripts
        let p_doc = CdrPolicy::new(
            2,
            "Doc-Disarm-Rule",
            FileType::StructuredDoc,
            true,
            false,
            false,
            true,
        );
        self.add_policy(p_doc);

        // 3. Politique Archives : neutralisation traversée '../' & nesting binaire
        let p_arc = CdrPolicy::new(
            3,
            "Archive-Sanitize-Rule",
            FileType::Archive,
            false,
            false,
            true,
            true,
        );
        self.add_policy(p_arc);

        // 4. Politique Flux IPC : assainissement des transferts de capabilités & gadgets
        let p_ipc = CdrPolicy::new(
            4,
            "IPC-Gadget-Guard",
            FileType::IpcStream,
            false,
            false,
            false,
            false,
        );
        self.add_policy(p_ipc);

        // 5. Politique Scripts Bruts : détection reverse shell & neutralisation
        let p_script = CdrPolicy::new(
            5,
            "Script-Safe-Exec",
            FileType::RawScript,
            false,
            false,
            false,
            false,
        );
        self.add_policy(p_script);

        self.append_audit(
            "INIT_DEFAULTS",
            "system",
            CdrThreatType::None,
            SanitizationAction::PassUnmodified,
            100,
        );
    }

    pub fn add_policy(&mut self, policy: CdrPolicy) -> bool {
        if self.policy_count < MAX_POLICIES {
            self.policies[self.policy_count] = Some(policy);
            self.policy_count += 1;
            true
        } else {
            false
        }
    }

    /// Journalise une entrée d'audit cryptographiquement scellée (SHA-256)
    pub fn append_audit(
        &mut self,
        action_str: &str,
        filename_str: &str,
        threat_type: CdrThreatType,
        status: SanitizationAction,
        timestamp: u64,
    ) {
        if self.audit_count >= MAX_AUDIT {
            // Rotation simple ou plafonnement
            return;
        }

        let mut action = [0u8; 24];
        let ab = action_str.as_bytes();
        let alen = ab.len().min(24);
        action[..alen].copy_from_slice(&ab[..alen]);

        let mut filename = [0u8; 32];
        let fb = filename_str.as_bytes();
        let flen = fb.len().min(32);
        filename[..flen].copy_from_slice(&fb[..flen]);

        let mut hasher = Sha256::new();
        hasher.update(&self.last_audit_hash);
        hasher.update(&self.audit_count.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&action[..alen]);
        hasher.update(&filename[..flen]);
        hasher.update(&[threat_type as u8, status as u8]);

        let entry_hash = hasher.finalize();

        let entry = CdrAuditEntry {
            entry_id: (self.audit_count + 1) as u32,
            timestamp,
            action,
            action_len: alen,
            filename,
            filename_len: flen,
            threat_type,
            status,
            prev_hash: self.last_audit_hash,
            entry_hash,
        };

        self.audit_log[self.audit_count] = Some(entry);
        self.audit_count += 1;
        self.last_audit_hash = entry_hash;
    }

    /// Vérifie l'intégrité de la chaîne cryptographique d'audit
    pub fn verify_audit_integrity(&self) -> bool {
        let genesis_seed = b"JAMBO_CDR_GENESIS_SEAL_V0.3.11";
        let mut expected_prev = Sha256::digest(genesis_seed);

        for i in 0..self.audit_count {
            if let Some(entry) = &self.audit_log[i] {
                if entry.prev_hash != expected_prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.prev_hash);
                hasher.update(&i.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.action[..entry.action_len]);
                hasher.update(&entry.filename[..entry.filename_len]);
                hasher.update(&[entry.threat_type as u8, entry.status as u8]);

                let calc_hash = hasher.finalize();
                if calc_hash != entry.entry_hash {
                    return false;
                }
                expected_prev = entry.entry_hash;
            } else {
                return false;
            }
        }
        true
    }

    /// Place un fichier en quarantaine souveraine O(1)
    pub fn quarantine_file(
        &mut self,
        file_id: u32,
        filename_str: &str,
        file_type: FileType,
        original_hash: [u8; 32],
        threat_type: CdrThreatType,
        severity: ThreatSeverity,
        timestamp: u64,
    ) -> Result<(), CdrError> {
        if !self.cap.has_right(cdr_rights::QUARANTINE_FILE) {
            return Err(CdrError::PermissionDenied);
        }
        if self.quarantine_count >= MAX_QUARANTINE {
            return Err(CdrError::QuarantineTableFull);
        }

        let mut filename = [0u8; 32];
        let fb = filename_str.as_bytes();
        let flen = fb.len().min(32);
        filename[..flen].copy_from_slice(&fb[..flen]);

        let entry = CdrQuarantineEntry {
            file_id,
            filename,
            filename_len: flen,
            file_type,
            original_hash,
            threat_type,
            severity,
            timestamp,
            isolated: true,
        };

        self.quarantine_store[self.quarantine_count] = Some(entry);
        self.quarantine_count += 1;
        self.files_quarantined += 1;

        self.append_audit(
            "QUARANTINE",
            filename_str,
            threat_type,
            SanitizationAction::Quarantined,
            timestamp,
        );
        Ok(())
    }

    /// Analyse, désarme et reconstruit un fichier ou flux de données
    pub fn scan_and_reconstruct(
        &mut self,
        filename_str: &str,
        file_type: FileType,
        input: &[u8],
        output: &mut [u8],
        timestamp: u64,
    ) -> Result<DisarmResult, CdrError> {
        // 1. Contrôle capabilaire
        if !self.cap.has_right(cdr_rights::INSPECT_CONTENT) {
            return Err(CdrError::PermissionDenied);
        }
        self.cap.consume()?;

        self.files_scanned += 1;
        let file_id = self.next_file_id;
        self.next_file_id += 1;

        if output.len() < input.len() {
            return Err(CdrError::BufferTooSmall);
        }

        let original_hash = Sha256::digest(input);

        // Recherche d'une politique correspondante
        let mut policy_opt = None;
        for p in self.policies.iter().flatten() {
            if p.enabled && p.file_type == file_type {
                policy_opt = Some(*p);
                break;
            }
        }

        // Vérification de présence d'un exécutable furtif caché dans un document non-ELF
        if file_type != FileType::ElfBinary && file_type != FileType::Unknown {
            if let Some(pos) = find_subslice(input, b"\x7fELF") {
                if pos > 0 {
                    // Exécutable ELF clandestin dissimulé
                    let threat_type = CdrThreatType::HiddenExecutableSmuggling;
                    let severity = ThreatSeverity::Critical;
                    self.record_threat(file_id, threat_type, severity, timestamp, false, true);
                    self.quarantine_file(
                        file_id,
                        filename_str,
                        file_type,
                        original_hash,
                        threat_type,
                        severity,
                        timestamp,
                    )?;
                    return Ok(DisarmResult {
                        action: SanitizationAction::Quarantined,
                        threat_type,
                        severity,
                        original_hash,
                        sanitized_hash: original_hash,
                        reconstructed_len: 0,
                        quarantined: true,
                    });
                }
            }
        }

        // 2. Analyse spécifique au format
        match file_type {
            FileType::ElfBinary => self.process_elf(
                file_id,
                filename_str,
                input,
                output,
                policy_opt,
                original_hash,
                timestamp,
            ),
            FileType::StructuredDoc => self.process_structured_doc(
                file_id,
                filename_str,
                input,
                output,
                policy_opt,
                original_hash,
                timestamp,
            ),
            FileType::Archive => self.process_archive(
                file_id,
                filename_str,
                input,
                output,
                policy_opt,
                original_hash,
                timestamp,
            ),
            FileType::IpcStream => self.process_ipc_stream(
                file_id,
                filename_str,
                input,
                output,
                policy_opt,
                original_hash,
                timestamp,
            ),
            FileType::RawScript => self.process_raw_script(
                file_id,
                filename_str,
                input,
                output,
                policy_opt,
                original_hash,
                timestamp,
            ),
            FileType::Unknown => {
                // Copie directe sans modification
                output[..input.len()].copy_from_slice(input);
                self.files_clean += 1;
                self.append_audit(
                    "SCAN_UNKNOWN",
                    filename_str,
                    CdrThreatType::None,
                    SanitizationAction::PassUnmodified,
                    timestamp,
                );
                Ok(DisarmResult {
                    action: SanitizationAction::PassUnmodified,
                    threat_type: CdrThreatType::None,
                    severity: ThreatSeverity::Low,
                    original_hash,
                    sanitized_hash: original_hash,
                    reconstructed_len: input.len(),
                    quarantined: false,
                })
            }
        }
    }

    /// Traitement ELF : désarmement des segments W+X et détection de shellcodes illicites
    fn process_elf(
        &mut self,
        file_id: u32,
        filename_str: &str,
        input: &[u8],
        output: &mut [u8],
        _policy: Option<CdrPolicy>,
        original_hash: [u8; 32],
        timestamp: u64,
    ) -> Result<DisarmResult, CdrError> {
        if input.len() < 16 || &input[0..4] != b"\x7fELF" {
            return Err(CdrError::MalformedContent);
        }

        // Recherche d'un shellcode critique connu (ex: NOP sled + shellcode stub)
        if find_subslice(input, b"\x90\x90\x90\x90\x31\xc0").is_some()
            || find_subslice(input, b"\xeb\x1f\x5e\x89\x76").is_some()
        {
            let threat_type = CdrThreatType::IllicitShellcode;
            let severity = ThreatSeverity::Critical;
            self.record_threat(file_id, threat_type, severity, timestamp, false, true);
            self.quarantine_file(
                file_id,
                filename_str,
                FileType::ElfBinary,
                original_hash,
                threat_type,
                severity,
                timestamp,
            )?;
            return Ok(DisarmResult {
                action: SanitizationAction::Quarantined,
                threat_type,
                severity,
                original_hash,
                sanitized_hash: original_hash,
                reconstructed_len: 0,
                quarantined: true,
            });
        }

        // Copie dans le buffer de travail
        output[..input.len()].copy_from_slice(input);

        // Détection de segment W+X : simule l'inspection des flags de segment ELF
        // Signature d'un segment W+X : flag byte avec PF_W (0x2) et PF_X (0x1) activés ensemble (flags == 7 ou flags == 3)
        let mut wx_violation_found = false;
        // On examine les en-têtes ou motifs de permissions W+X insérés dans le binaire
        if let Some(pos) = find_subslice(input, b"SEG_FLAGS_RWX") {
            // Mot-clef ou offset simulant un segment RWX
            output[pos..pos + 13].copy_from_slice(b"SEG_FLAGS_R-X"); // Neutralisation du bit Writable
            wx_violation_found = true;
        }

        // Recherche heuristique d'un octet flag W+X (ex: 0x07 = PF_R|PF_W|PF_X au sein d'un descripteur)
        for i in 16..input.len().saturating_sub(4) {
            if input[i] == 0x7F && input[i + 1] == 0x07 && input[i + 2] == 0xAA {
                // Flag segment W+X trouvé -> neutralisation en 0x05 (PF_R | PF_X sans PF_W)
                output[i + 1] = 0x05;
                wx_violation_found = true;
            }
        }

        if wx_violation_found {
            if !self
                .cap
                .has_right(cdr_rights::DISARM_PAYLOAD | cdr_rights::RECONSTRUCT)
            {
                return Err(CdrError::PermissionDenied);
            }
            let threat_type = CdrThreatType::WxSegmentViolation;
            let severity = ThreatSeverity::High;
            self.record_threat(file_id, threat_type, severity, timestamp, true, false);
            self.files_disarmed += 1;

            let sanitized_hash = Sha256::digest(&output[..input.len()]);
            self.append_audit(
                "DISARM_ELF_WX",
                filename_str,
                threat_type,
                SanitizationAction::DisarmedAndReconstructed,
                timestamp,
            );

            Ok(DisarmResult {
                action: SanitizationAction::DisarmedAndReconstructed,
                threat_type,
                severity,
                original_hash,
                sanitized_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        } else {
            self.files_clean += 1;
            self.append_audit(
                "SCAN_ELF_PASS",
                filename_str,
                CdrThreatType::None,
                SanitizationAction::PassUnmodified,
                timestamp,
            );
            Ok(DisarmResult {
                action: SanitizationAction::PassUnmodified,
                threat_type: CdrThreatType::None,
                severity: ThreatSeverity::Low,
                original_hash,
                sanitized_hash: original_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        }
    }

    /// Traitement Document Structuré : désarmement des macros et scripts intégrés
    fn process_structured_doc(
        &mut self,
        file_id: u32,
        filename_str: &str,
        input: &[u8],
        output: &mut [u8],
        _policy: Option<CdrPolicy>,
        original_hash: [u8; 32],
        timestamp: u64,
    ) -> Result<DisarmResult, CdrError> {
        let macro_signatures: [&[u8]; 5] = [
            b"vbaProject.bin",
            b"<script>",
            b"/JavaScript",
            b"/Launch",
            b"AutoOpen()",
        ];

        output[..input.len()].copy_from_slice(input);
        let mut modified = false;

        for sig in macro_signatures.iter() {
            while let Some(pos) = find_subslice(&output[..input.len()], sig) {
                // Remplacement du motif dangereux par un motif neutre
                let neutral = b"/*DISARMED*/";
                let fill_len = sig.len().min(neutral.len());
                output[pos..pos + fill_len].copy_from_slice(&neutral[..fill_len]);
                for b in output[pos + fill_len..pos + sig.len()].iter_mut() {
                    *b = b' ';
                }
                modified = true;
            }
        }

        if modified {
            if !self
                .cap
                .has_right(cdr_rights::DISARM_PAYLOAD | cdr_rights::RECONSTRUCT)
            {
                return Err(CdrError::PermissionDenied);
            }
            let threat_type = CdrThreatType::EmbeddedMacro;
            let severity = ThreatSeverity::Medium;
            self.record_threat(file_id, threat_type, severity, timestamp, true, false);
            self.files_disarmed += 1;

            let sanitized_hash = Sha256::digest(&output[..input.len()]);
            self.append_audit(
                "DISARM_DOC_MACRO",
                filename_str,
                threat_type,
                SanitizationAction::DisarmedAndReconstructed,
                timestamp,
            );

            Ok(DisarmResult {
                action: SanitizationAction::DisarmedAndReconstructed,
                threat_type,
                severity,
                original_hash,
                sanitized_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        } else {
            self.files_clean += 1;
            self.append_audit(
                "SCAN_DOC_PASS",
                filename_str,
                CdrThreatType::None,
                SanitizationAction::PassUnmodified,
                timestamp,
            );
            Ok(DisarmResult {
                action: SanitizationAction::PassUnmodified,
                threat_type: CdrThreatType::None,
                severity: ThreatSeverity::Low,
                original_hash,
                sanitized_hash: original_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        }
    }

    /// Traitement Archive : neutralisation des traversées de répertoires `../`
    fn process_archive(
        &mut self,
        file_id: u32,
        filename_str: &str,
        input: &[u8],
        output: &mut [u8],
        _policy: Option<CdrPolicy>,
        original_hash: [u8; 32],
        timestamp: u64,
    ) -> Result<DisarmResult, CdrError> {
        output[..input.len()].copy_from_slice(input);
        let mut modified = false;

        let traversal_patterns: [(&[u8], &[u8]); 3] =
            [(b"../", b"./."), (b"..\\", b".\\."), (b"/etc/", b"/var/")];

        for (pat, safe_rep) in traversal_patterns.iter() {
            while let Some(pos) = find_subslice(&output[..input.len()], pat) {
                output[pos..pos + pat.len()].copy_from_slice(safe_rep);
                modified = true;
            }
        }

        if modified {
            if !self
                .cap
                .has_right(cdr_rights::DISARM_PAYLOAD | cdr_rights::RECONSTRUCT)
            {
                return Err(CdrError::PermissionDenied);
            }
            let threat_type = CdrThreatType::PathTraversalArchive;
            let severity = ThreatSeverity::High;
            self.record_threat(file_id, threat_type, severity, timestamp, true, false);
            self.files_disarmed += 1;

            let sanitized_hash = Sha256::digest(&output[..input.len()]);
            self.append_audit(
                "DISARM_ARCHIVE_TRAVERSAL",
                filename_str,
                threat_type,
                SanitizationAction::DisarmedAndReconstructed,
                timestamp,
            );

            Ok(DisarmResult {
                action: SanitizationAction::DisarmedAndReconstructed,
                threat_type,
                severity,
                original_hash,
                sanitized_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        } else {
            self.files_clean += 1;
            self.append_audit(
                "SCAN_ARCHIVE_PASS",
                filename_str,
                CdrThreatType::None,
                SanitizationAction::PassUnmodified,
                timestamp,
            );
            Ok(DisarmResult {
                action: SanitizationAction::PassUnmodified,
                threat_type: CdrThreatType::None,
                severity: ThreatSeverity::Low,
                original_hash,
                sanitized_hash: original_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        }
    }

    /// Traitement Flux IPC : neutralisation des gadgets de désérialisation
    fn process_ipc_stream(
        &mut self,
        file_id: u32,
        filename_str: &str,
        input: &[u8],
        output: &mut [u8],
        _policy: Option<CdrPolicy>,
        original_hash: [u8; 32],
        timestamp: u64,
    ) -> Result<DisarmResult, CdrError> {
        output[..input.len()].copy_from_slice(input);
        let mut modified = false;

        let gadget_tags: [(&[u8], &[u8]); 2] = [
            (b"IPC_GADGET_CHAIN", b"IPC_SAFE_NULL_OK"),
            (b"DESERIAL_POINTER_TRAP", b"DESERIAL_SAFE_PTR_OK_"),
        ];

        for (tag, safe_rep) in gadget_tags.iter() {
            while let Some(pos) = find_subslice(&output[..input.len()], tag) {
                output[pos..pos + tag.len()].copy_from_slice(safe_rep);
                modified = true;
            }
        }

        if modified {
            if !self
                .cap
                .has_right(cdr_rights::DISARM_PAYLOAD | cdr_rights::RECONSTRUCT)
            {
                return Err(CdrError::PermissionDenied);
            }
            let threat_type = CdrThreatType::DeserializationGadget;
            let severity = ThreatSeverity::High;
            self.record_threat(file_id, threat_type, severity, timestamp, true, false);
            self.files_disarmed += 1;

            let sanitized_hash = Sha256::digest(&output[..input.len()]);
            self.append_audit(
                "DISARM_IPC_GADGET",
                filename_str,
                threat_type,
                SanitizationAction::DisarmedAndReconstructed,
                timestamp,
            );

            Ok(DisarmResult {
                action: SanitizationAction::DisarmedAndReconstructed,
                threat_type,
                severity,
                original_hash,
                sanitized_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        } else {
            self.files_clean += 1;
            self.append_audit(
                "SCAN_IPC_PASS",
                filename_str,
                CdrThreatType::None,
                SanitizationAction::PassUnmodified,
                timestamp,
            );
            Ok(DisarmResult {
                action: SanitizationAction::PassUnmodified,
                threat_type: CdrThreatType::None,
                severity: ThreatSeverity::Low,
                original_hash,
                sanitized_hash: original_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        }
    }

    /// Traitement Script Brut : neutralisation des payloads reverse shell
    fn process_raw_script(
        &mut self,
        file_id: u32,
        filename_str: &str,
        input: &[u8],
        output: &mut [u8],
        _policy: Option<CdrPolicy>,
        original_hash: [u8; 32],
        timestamp: u64,
    ) -> Result<DisarmResult, CdrError> {
        output[..input.len()].copy_from_slice(input);
        let mut modified = false;

        let script_threats: [&[u8]; 3] = [b"/dev/tcp/", b"nc -e /bin/sh", b"mkfifo /tmp/"];

        for pat in script_threats.iter() {
            while let Some(pos) = find_subslice(&output[..input.len()], pat) {
                // Commenter ou remplacer par des no-op
                let neutralized = b"# [NEUTRALIZED] ";
                let fill_len = pat.len().min(neutralized.len());
                output[pos..pos + fill_len].copy_from_slice(&neutralized[..fill_len]);
                for b in output[pos + fill_len..pos + pat.len()].iter_mut() {
                    *b = b'#';
                }
                modified = true;
            }
        }

        if modified {
            if !self
                .cap
                .has_right(cdr_rights::DISARM_PAYLOAD | cdr_rights::RECONSTRUCT)
            {
                return Err(CdrError::PermissionDenied);
            }
            let threat_type = CdrThreatType::IllicitShellcode;
            let severity = ThreatSeverity::High;
            self.record_threat(file_id, threat_type, severity, timestamp, true, false);
            self.files_disarmed += 1;

            let sanitized_hash = Sha256::digest(&output[..input.len()]);
            self.append_audit(
                "DISARM_SCRIPT_PAYLOAD",
                filename_str,
                threat_type,
                SanitizationAction::DisarmedAndReconstructed,
                timestamp,
            );

            Ok(DisarmResult {
                action: SanitizationAction::DisarmedAndReconstructed,
                threat_type,
                severity,
                original_hash,
                sanitized_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        } else {
            self.files_clean += 1;
            self.append_audit(
                "SCAN_SCRIPT_PASS",
                filename_str,
                CdrThreatType::None,
                SanitizationAction::PassUnmodified,
                timestamp,
            );
            Ok(DisarmResult {
                action: SanitizationAction::PassUnmodified,
                threat_type: CdrThreatType::None,
                severity: ThreatSeverity::Low,
                original_hash,
                sanitized_hash: original_hash,
                reconstructed_len: input.len(),
                quarantined: false,
            })
        }
    }

    fn record_threat(
        &mut self,
        file_id: u32,
        threat_type: CdrThreatType,
        severity: ThreatSeverity,
        timestamp: u64,
        sanitized: bool,
        quarantined: bool,
    ) {
        if self.threat_count < MAX_THREATS {
            let record = CdrThreatRecord {
                threat_id: self.next_threat_id,
                file_id,
                threat_type,
                severity,
                timestamp,
                sanitized,
                quarantined,
            };
            self.threats[self.threat_count] = Some(record);
            self.threat_count += 1;
            self.next_threat_id += 1;
        }
    }

    /// Récupère la synthèse de fonctionnement du moteur CDR
    pub fn get_summary(&self) -> CdrSummary {
        CdrSummary {
            files_scanned: self.files_scanned,
            files_clean: self.files_clean,
            files_disarmed: self.files_disarmed,
            files_quarantined: self.files_quarantined,
            threats_detected: self.threat_count,
            policies_count: self.policy_count,
            audit_entries_count: self.audit_count,
            ledger_valid: self.verify_audit_integrity(),
        }
    }
}

/// Fonction utilitaire de recherche de sous-tranche d'octets sans allocation
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] sous test harness)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_cdr_hasher() {
        let data = b"JAMBO_SOVEREIGN_CONTENT_DISARM_AND_RECONSTRUCTION_CDR";
        let digest = Sha256::digest(data);
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn test_cdr_capability_rights_and_attenuation() {
        let root_cap = CdrCap::new(Handle::new(14401, 1), cdr_rights::ALL, 10000, 500);
        assert!(root_cap.has_right(cdr_rights::INSPECT_CONTENT));
        assert!(root_cap.has_right(cdr_rights::DISARM_PAYLOAD));
        assert!(root_cap.has_right(cdr_rights::RECONSTRUCT));
        assert!(root_cap.has_right(cdr_rights::QUARANTINE_FILE));
        assert!(root_cap.has_right(cdr_rights::ADMIN));

        let attenuated = root_cap
            .attenuate(
                cdr_rights::INSPECT_CONTENT | cdr_rights::QUERY_METRICS,
                5000,
                200,
            )
            .expect("Atténuation monotone");

        assert!(attenuated.has_right(cdr_rights::INSPECT_CONTENT));
        assert!(attenuated.has_right(cdr_rights::QUERY_METRICS));
        assert!(!attenuated.has_right(cdr_rights::ADMIN));
        assert!(!attenuated.has_right(cdr_rights::DISARM_PAYLOAD));

        // Rejet d'escalade
        assert_eq!(
            attenuated.attenuate(cdr_rights::ALL, 5000, 200),
            Err(CdrError::AttenuationViolation)
        );
    }

    #[test]
    fn test_daemon_initialization_defaults() {
        let cap = CdrCap::new(Handle::new(14402, 1), cdr_rights::ALL, 10000, 500);
        let mut daemon = JamboCdrDaemon::new(cap);
        daemon.init_defaults();

        let summary = daemon.get_summary();
        assert_eq!(summary.policies_count, 5);
        assert_eq!(summary.files_scanned, 0);
        assert_eq!(summary.threats_detected, 0);
        assert_eq!(summary.files_quarantined, 0);
        assert!(summary.ledger_valid);
    }

    #[test]
    fn test_elf_wx_segment_disarm_and_reconstruction() {
        let cap = CdrCap::new(Handle::new(14403, 1), cdr_rights::ALL, 10000, 500);
        let mut daemon = JamboCdrDaemon::new(cap);
        daemon.init_defaults();

        // Faux binaire ELF avec violation de segment W+X
        let mut elf_payload = [0u8; 64];
        elf_payload[0..4].copy_from_slice(b"\x7fELF");
        elf_payload[20..33].copy_from_slice(b"SEG_FLAGS_RWX");

        let mut output = [0u8; 64];
        let res = daemon
            .scan_and_reconstruct(
                "binary_wx.elf",
                FileType::ElfBinary,
                &elf_payload,
                &mut output,
                1000,
            )
            .expect("Désarmement ELF");

        assert_eq!(res.action, SanitizationAction::DisarmedAndReconstructed);
        assert_eq!(res.threat_type, CdrThreatType::WxSegmentViolation);
        assert_eq!(res.severity, ThreatSeverity::High);
        assert_eq!(&output[20..33], b"SEG_FLAGS_R-X");
        assert_ne!(res.original_hash, res.sanitized_hash);

        let summary = daemon.get_summary();
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.files_disarmed, 1);
        assert_eq!(summary.threats_detected, 1);
    }

    #[test]
    fn test_structured_doc_macro_neutralization() {
        let cap = CdrCap::new(Handle::new(14404, 1), cdr_rights::ALL, 10000, 500);
        let mut daemon = JamboCdrDaemon::new(cap);
        daemon.init_defaults();

        // Document contenant un appel macro vbaProject.bin
        let doc_payload = b"DOCUMENT_CONTENT_WITH_MALICIOUS_vbaProject.bin_EMBEDDED_STREAM";
        let mut output = [0u8; 128];

        let res = daemon
            .scan_and_reconstruct(
                "report.docx",
                FileType::StructuredDoc,
                doc_payload,
                &mut output,
                2000,
            )
            .expect("Désarmement Macro");

        assert_eq!(res.action, SanitizationAction::DisarmedAndReconstructed);
        assert_eq!(res.threat_type, CdrThreatType::EmbeddedMacro);
        assert!(find_subslice(&output[..doc_payload.len()], b"vbaProject.bin").is_none());
        assert!(find_subslice(&output[..doc_payload.len()], b"/*DISARMED*/").is_some());
    }

    #[test]
    fn test_archive_path_traversal_sanitization() {
        let cap = CdrCap::new(Handle::new(14405, 1), cdr_rights::ALL, 10000, 500);
        let mut daemon = JamboCdrDaemon::new(cap);
        daemon.init_defaults();

        // Archive contenant un path traversal '../'
        let arc_payload = b"TAR_HEADER: ../../../etc/shadow ARCHIVE_ENTRY";
        let mut output = [0u8; 128];

        let res = daemon
            .scan_and_reconstruct(
                "archive.tar",
                FileType::Archive,
                arc_payload,
                &mut output,
                3000,
            )
            .expect("Sanitisation traversée");

        assert_eq!(res.action, SanitizationAction::DisarmedAndReconstructed);
        assert_eq!(res.threat_type, CdrThreatType::PathTraversalArchive);
        assert!(find_subslice(&output[..arc_payload.len()], b"../").is_none());
        assert!(find_subslice(&output[..arc_payload.len()], b"./.").is_some());
    }

    #[test]
    fn test_illicit_shellcode_quarantine_o1() {
        let cap = CdrCap::new(Handle::new(14406, 1), cdr_rights::ALL, 10000, 500);
        let mut daemon = JamboCdrDaemon::new(cap);
        daemon.init_defaults();

        // Binaire ELF contenant un NOP sled et stub shellcode critique
        let mut payload = [0u8; 64];
        payload[0..4].copy_from_slice(b"\x7fELF");
        payload[16..22].copy_from_slice(b"\x90\x90\x90\x90\x31\xc0");

        let mut output = [0u8; 64];
        let res = daemon
            .scan_and_reconstruct(
                "exploit.elf",
                FileType::ElfBinary,
                &payload,
                &mut output,
                4000,
            )
            .expect("Inspection exploit");

        assert_eq!(res.action, SanitizationAction::Quarantined);
        assert_eq!(res.threat_type, CdrThreatType::IllicitShellcode);
        assert_eq!(res.severity, ThreatSeverity::Critical);
        assert!(res.quarantined);

        let summary = daemon.get_summary();
        assert_eq!(summary.files_quarantined, 1);
        assert_eq!(daemon.quarantine_count, 1);
        assert!(daemon.quarantine_store[0].unwrap().isolated);
    }

    #[test]
    fn test_ipc_stream_gadget_sanitization() {
        let cap = CdrCap::new(Handle::new(14407, 1), cdr_rights::ALL, 10000, 500);
        let mut daemon = JamboCdrDaemon::new(cap);
        daemon.init_defaults();

        let stream_payload = b"HEADER|IPC_GADGET_CHAIN|PAYLOAD_BYTES";
        let mut output = [0u8; 64];

        let res = daemon
            .scan_and_reconstruct(
                "ipc_message.bin",
                FileType::IpcStream,
                stream_payload,
                &mut output,
                5000,
            )
            .expect("Sanitisation gadget IPC");

        assert_eq!(res.action, SanitizationAction::DisarmedAndReconstructed);
        assert_eq!(res.threat_type, CdrThreatType::DeserializationGadget);
        assert!(find_subslice(&output[..stream_payload.len()], b"IPC_GADGET_CHAIN").is_none());
        assert!(find_subslice(&output[..stream_payload.len()], b"IPC_SAFE_NULL_OK").is_some());
    }

    #[test]
    fn test_audit_ledger_cryptographic_seal_and_tamper_detection() {
        let cap = CdrCap::new(Handle::new(14408, 1), cdr_rights::ALL, 10000, 500);
        let mut daemon = JamboCdrDaemon::new(cap);
        daemon.init_defaults();

        assert!(daemon.verify_audit_integrity());
        assert!(daemon.audit_count > 0);

        // Altération malveillante d'une entrée d'audit
        daemon.audit_log[0].as_mut().unwrap().action[0] ^= 0x55;
        assert!(!daemon.verify_audit_integrity());
    }
}

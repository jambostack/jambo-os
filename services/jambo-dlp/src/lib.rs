//! Protection contre les Fuites de Données Souveraines (DLP - Data Loss Prevention)
//!
//! Phase 145 — Jalon v0.3.12
//!
//! Fournit un sous-système souverain de détection, classification en temps réel,
//! masquage dynamique et blocage des exfiltrations de données sensibles en `#![no_std]` :
//! 1. Détection structurelle et heuristique des flux de données sensibles (PII, secrets, clés privées, classifiés).
//! 2. Algorithme de Luhn pour la détection et la validation formelle des numéros de cartes bancaires.
//! 3. Calcul d'entropie de Shannon sur les flux pour repérer les secrets bruts et exfiltrations chiffrées clandestines.
//! 4. Masquage dynamique en vol (redaction) des données sensibles identifiées.
//! 5. Blocage immédiat et mise en quarantaine O(1) des flux critiques illicites (`quarantine_flow`).
//! 6. Contrôle d'accès capabilaire (`DlpCap`) avec atténuation monotone stricte.
//! 7. Registre d'audit SHA-256 inaltérable scellé par chaînage cryptographique.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation autonome et déterministe de SHA-256 pour micro-noyau et services DLP
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
// CONTRÔLE D'ACCÈS CAPABILAIRE (DlpCap)
// ============================================================================

pub mod dlp_rights {
    pub const INSPECT_FLOW: u32 = 1 << 0;
    pub const ANALYZE_ENTROPY: u32 = 1 << 1;
    pub const MASK_PAYLOAD: u32 = 1 << 2;
    pub const BLOCK_TRANSFER: u32 = 1 << 3;
    pub const QUARANTINE_FLOW: u32 = 1 << 4;
    pub const CONFIGURE_POLICY: u32 = 1 << 5;
    pub const QUERY_METRICS: u32 = 1 << 6;
    pub const QUERY_AUDIT: u32 = 1 << 7;
    pub const ADMIN: u32 = 1 << 8;
    pub const ALL: u32 = 0x1FF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpError {
    PermissionDenied,
    AttenuationViolation,
    FlowNotFound,
    BufferTooSmall,
    PolicyTableFull,
    ViolationTableFull,
    QuarantineTableFull,
    AuditLogFull,
    InvalidParameter,
    CriticalLeakQuarantined,
    TransferBlocked,
}

/// Capabilité de contrôle d'accès avec atténuation monotone stricte pour le moteur DLP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlpCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl DlpCap {
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
    ) -> Result<Self, DlpError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(DlpError::AttenuationViolation);
        }
        if lifetime_limit > self.max_lifetime {
            return Err(DlpError::AttenuationViolation);
        }
        if max_invocations > self.invocations_left {
            return Err(DlpError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
            max_lifetime: lifetime_limit,
            invocations_left: max_invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), DlpError> {
        if self.invocations_left == 0 {
            return Err(DlpError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES DLP SOUVERAINES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpDataType {
    None,
    PiiCreditCard,
    PiiNationalId,
    CryptoPrivateKey,
    ApiTokenOrSecret,
    SovereignDefenseSecret,
    HighEntropyExfiltration,
}

impl DlpDataType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DlpDataType::None => "NONE",
            DlpDataType::PiiCreditCard => "PII_CREDIT_CARD",
            DlpDataType::PiiNationalId => "PII_NATIONAL_ID",
            DlpDataType::CryptoPrivateKey => "CRYPTO_PRIVATE_KEY",
            DlpDataType::ApiTokenOrSecret => "API_TOKEN_SECRET",
            DlpDataType::SovereignDefenseSecret => "SOVEREIGN_DEFENSE_SECRET",
            DlpDataType::HighEntropyExfiltration => "HIGH_ENTROPY_EXFILTRATION",
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
pub enum DlpAction {
    Allow,
    Mask,
    Block,
    Quarantine,
}

impl DlpAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            DlpAction::Allow => "ALLOW",
            DlpAction::Mask => "MASK",
            DlpAction::Block => "BLOCK",
            DlpAction::Quarantine => "QUARANTINE",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DlpPolicy {
    pub policy_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub data_type: DlpDataType,
    pub severity: ThreatSeverity,
    pub action: DlpAction,
    pub min_entropy_threshold: u32, // En millibits (ex: 7200 pour 7.2 bits/octet)
    pub quarantine_on_match: bool,
    pub enabled: bool,
}

impl DlpPolicy {
    pub fn new(
        policy_id: u32,
        name_str: &str,
        data_type: DlpDataType,
        severity: ThreatSeverity,
        action: DlpAction,
        min_entropy_threshold: u32,
        quarantine_on_match: bool,
    ) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(32);
        name[..len].copy_from_slice(&bytes[..len]);
        Self {
            policy_id,
            name,
            name_len: len,
            data_type,
            severity,
            action,
            min_entropy_threshold,
            quarantine_on_match,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DlpViolationRecord {
    pub violation_id: u32,
    pub flow_id: u32,
    pub policy_id: u32,
    pub data_type: DlpDataType,
    pub severity: ThreatSeverity,
    pub action_taken: DlpAction,
    pub entropy_millibits: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct DlpQuarantineEntry {
    pub flow_id: u32,
    pub source: [u8; 32],
    pub source_len: usize,
    pub destination: [u8; 32],
    pub destination_len: usize,
    pub data_type: DlpDataType,
    pub severity: ThreatSeverity,
    pub payload_hash: [u8; 32],
    pub entropy_millibits: u32,
    pub timestamp: u64,
    pub isolated: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct DlpAuditEntry {
    pub entry_id: u32,
    pub timestamp: u64,
    pub action_str: [u8; 24],
    pub action_len: usize,
    pub source: [u8; 32],
    pub source_len: usize,
    pub data_type: DlpDataType,
    pub verdict: DlpAction,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct DlpInspectionResult {
    pub flow_id: u32,
    pub action: DlpAction,
    pub data_type: DlpDataType,
    pub severity: ThreatSeverity,
    pub entropy_millibits: u32,
    pub bytes_processed: usize,
    pub output_len: usize,
    pub original_hash: [u8; 32],
    pub sanitized_hash: [u8; 32],
    pub quarantined: bool,
    pub policy_id_triggered: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct DlpSummary {
    pub policies_count: usize,
    pub flows_scanned: usize,
    pub violations_detected: usize,
    pub payloads_masked: usize,
    pub flows_blocked: usize,
    pub flows_quarantined: usize,
    pub quarantine_count: usize,
    pub ledger_valid: bool,
}

// ============================================================================
// CALCULATEUR D'ENTROPIE DE SHANNON & VALIDATEUR LUHN (#![no_std])
// ============================================================================

/// Table de correspondance log2(1.0 + i / 32.0) * 1000 pour calcul d'entropie déterministe
const LOG2_32_TABLE: [u32; 33] = [
    0, 44, 87, 129, 170, 209, 248, 285, 322, 358, 392, 426, 459, 492, 524, 555, 585, 615, 644, 672,
    700, 728, 755, 781, 807, 833, 858, 883, 907, 931, 954, 977, 1000,
];

/// Calcule log2(x) en millibits (x > 0)
pub fn log2_millibits(x: u32) -> u32 {
    if x <= 1 {
        return 0;
    }
    let k = 31 - x.leading_zeros();
    let x0 = 1u32 << k;
    let rem = x - x0;
    let idx = ((rem as u64 * 32) / x0 as u64) as usize;
    if idx >= 32 {
        return (k + 1) * 1000;
    }
    let v0 = LOG2_32_TABLE[idx];
    let v1 = LOG2_32_TABLE[idx + 1];
    let step_x0 = (x0 as u64 + 31) / 32;
    let rem_sub = rem as u64 - (idx as u64 * x0 as u64) / 32;
    let interp = if step_x0 > 0 {
        ((v1 - v0) as u64 * rem_sub) / step_x0
    } else {
        0
    };
    (k * 1000) + v0 + (interp as u32)
}

/// Calcule l'entropie de Shannon d'un bloc de données en millibits (0..8000)
pub fn compute_shannon_entropy(data: &[u8]) -> u32 {
    let n = data.len();
    if n <= 1 {
        return 0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let log2_n = log2_millibits(n as u32);
    let mut weighted_sum: u64 = 0;
    for &c in counts.iter() {
        if c > 0 {
            let log2_c = log2_millibits(c);
            weighted_sum += (c as u64) * (log2_c as u64);
        }
    }
    let avg_log2_c = (weighted_sum / n as u64) as u32;
    if log2_n >= avg_log2_c {
        log2_n - avg_log2_c
    } else {
        0
    }
}

/// Algorithme de validation de somme de contrôle Luhn (norme ISO/IEC 7812)
pub fn check_luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut is_second = false;
    let mut digit_count = 0usize;

    for &ch in digits.iter().rev() {
        if ch == b' ' || ch == b'-' {
            continue;
        }
        if !ch.is_ascii_digit() {
            return false;
        }
        let mut d = (ch - b'0') as u32;
        if is_second {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        is_second = !is_second;
        digit_count += 1;
    }

    digit_count >= 13 && digit_count <= 19 && (sum % 10 == 0)
}

// ============================================================================
// DÉMON DLP PRINCIPAL (JamboDlpDaemon)
// ============================================================================

pub struct JamboDlpDaemon {
    pub cap: DlpCap,
    pub policies: [Option<DlpPolicy>; 16],
    pub policy_count: usize,
    pub quarantine_store: [Option<DlpQuarantineEntry>; 32],
    pub quarantine_count: usize,
    pub violations: [Option<DlpViolationRecord>; 32],
    pub violation_count: usize,
    pub audit_ledger: [Option<DlpAuditEntry>; 64],
    pub audit_count: usize,
    pub next_violation_id: u32,
    pub next_entry_id: u32,
    pub last_audit_hash: [u8; 32],
    pub flows_scanned: usize,
    pub payloads_masked: usize,
    pub flows_blocked: usize,
    pub flows_quarantined: usize,
}

impl JamboDlpDaemon {
    pub fn new(cap: DlpCap) -> Self {
        let genesis_seed = b"JAMBO_DLP_GENESIS_SEAL_V0.3.12";
        let initial_hash = Sha256::digest(genesis_seed);

        Self {
            cap,
            policies: [None; 16],
            policy_count: 0,
            quarantine_store: [None; 32],
            quarantine_count: 0,
            violations: [None; 32],
            violation_count: 0,
            audit_ledger: [None; 64],
            audit_count: 0,
            next_violation_id: 1,
            next_entry_id: 1,
            last_audit_hash: initial_hash,
            flows_scanned: 0,
            payloads_masked: 0,
            flows_blocked: 0,
            flows_quarantined: 0,
        }
    }

    /// Initialise les politiques DLP souveraines fondamentales
    pub fn init_defaults(&mut self) {
        let _ = self.register_policy(DlpPolicy::new(
            1,
            "Sovereign Classified Defense",
            DlpDataType::SovereignDefenseSecret,
            ThreatSeverity::Critical,
            DlpAction::Block,
            0,
            true,
        ));
        let _ = self.register_policy(DlpPolicy::new(
            2,
            "Private Key Leak Prevention",
            DlpDataType::CryptoPrivateKey,
            ThreatSeverity::Critical,
            DlpAction::Block,
            0,
            true,
        ));
        let _ = self.register_policy(DlpPolicy::new(
            3,
            "API Tokens & Secrets Exposure",
            DlpDataType::ApiTokenOrSecret,
            ThreatSeverity::High,
            DlpAction::Mask,
            0,
            false,
        ));
        let _ = self.register_policy(DlpPolicy::new(
            4,
            "PCI-DSS Credit Card Redaction",
            DlpDataType::PiiCreditCard,
            ThreatSeverity::High,
            DlpAction::Mask,
            0,
            false,
        ));
        let _ = self.register_policy(DlpPolicy::new(
            5,
            "National Identification PII",
            DlpDataType::PiiNationalId,
            ThreatSeverity::Medium,
            DlpAction::Mask,
            0,
            false,
        ));
        let _ = self.register_policy(DlpPolicy::new(
            6,
            "High Entropy Mass Exfiltration",
            DlpDataType::HighEntropyExfiltration,
            ThreatSeverity::Critical,
            DlpAction::Quarantine,
            7200, // 7.2 bits/octet
            true,
        ));
    }

    /// Enregistre une politique DLP
    pub fn register_policy(&mut self, policy: DlpPolicy) -> Result<(), DlpError> {
        if !self.cap.has_right(dlp_rights::CONFIGURE_POLICY) {
            return Err(DlpError::PermissionDenied);
        }
        if self.policy_count >= self.policies.len() {
            return Err(DlpError::PolicyTableFull);
        }
        for slot in self.policies.iter_mut() {
            if slot.is_none() {
                *slot = Some(policy);
                self.policy_count += 1;
                return Ok(());
            }
        }
        Err(DlpError::PolicyTableFull)
    }

    /// Recherche un motif d'octets dans un tampon
    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || needle.len() > haystack.len() {
            return None;
        }
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// Analyse et classe les flux de données sortants
    pub fn classify_payload(&self, payload: &[u8]) -> (DlpDataType, ThreatSeverity, usize, usize) {
        // 1. Secrets Souverains et Défense Nationale
        let sovereign_markers: [&[u8]; 5] = [
            b"CLASSIFIED//SOVEREIGN",
            b"SECRET-DEFENSE",
            b"RESTREINT-DEFENSE",
            b"TOP-SECRET-JAMBO",
            b"CONFIDENTIAL//NOFORN",
        ];
        for marker in sovereign_markers.iter() {
            if let Some(pos) = Self::find_subslice(payload, marker) {
                return (
                    DlpDataType::SovereignDefenseSecret,
                    ThreatSeverity::Critical,
                    pos,
                    marker.len(),
                );
            }
        }

        // 2. Clés Privées Cryptographiques
        let key_markers: [&[u8]; 4] = [
            b"-----BEGIN PRIVATE KEY-----",
            b"-----BEGIN RSA PRIVATE KEY-----",
            b"-----BEGIN EC PRIVATE KEY-----",
            b"-----BEGIN OPENSSH PRIVATE KEY-----",
        ];
        for marker in key_markers.iter() {
            if let Some(pos) = Self::find_subslice(payload, marker) {
                return (
                    DlpDataType::CryptoPrivateKey,
                    ThreatSeverity::Critical,
                    pos,
                    marker.len(),
                );
            }
        }

        // 3. Jetons d'API et Secrets d'Authentification
        let api_markers: [&[u8]; 5] = [
            b"sec_tok_",
            b"ghp_",
            b"token_api_",
            b"Bearer ",
            b"eyJhbGciOi", // Header JWT
        ];
        for marker in api_markers.iter() {
            if let Some(pos) = Self::find_subslice(payload, marker) {
                let end = (pos + marker.len() + 24).min(payload.len());
                return (
                    DlpDataType::ApiTokenOrSecret,
                    ThreatSeverity::High,
                    pos,
                    end - pos,
                );
            }
        }

        // 4. Cartes Bancaires (Luhn)
        let mut i = 0;
        while i < payload.len() {
            if payload[i].is_ascii_digit() {
                let start = i;
                let mut end = i;
                let mut digits_only = [0u8; 32];
                let mut digit_len = 0;

                while end < payload.len()
                    && (payload[end].is_ascii_digit()
                        || payload[end] == b'-'
                        || payload[end] == b' ')
                {
                    if payload[end].is_ascii_digit() && digit_len < digits_only.len() {
                        digits_only[digit_len] = payload[end];
                        digit_len += 1;
                    }
                    end += 1;
                }

                if digit_len >= 13 && digit_len <= 19 && check_luhn(&digits_only[..digit_len]) {
                    return (
                        DlpDataType::PiiCreditCard,
                        ThreatSeverity::High,
                        start,
                        end - start,
                    );
                }
                i = end;
            } else {
                i += 1;
            }
        }

        // 5. Numéros d'Identification Nationale (SSN: \d{3}-\d{2}-\d{4} ou NIR 13-15 chiffres)
        if payload.len() >= 11 {
            for idx in 0..=payload.len() - 11 {
                let chunk = &payload[idx..idx + 11];
                if chunk[0].is_ascii_digit()
                    && chunk[1].is_ascii_digit()
                    && chunk[2].is_ascii_digit()
                    && chunk[3] == b'-'
                    && chunk[4].is_ascii_digit()
                    && chunk[5].is_ascii_digit()
                    && chunk[6] == b'-'
                    && chunk[7].is_ascii_digit()
                    && chunk[8].is_ascii_digit()
                    && chunk[9].is_ascii_digit()
                    && chunk[10].is_ascii_digit()
                {
                    return (DlpDataType::PiiNationalId, ThreatSeverity::Medium, idx, 11);
                }
            }
        }

        // 6. Entropie élevée (Exfiltration chiffrée clandestine)
        if payload.len() >= 32 {
            let entropy = compute_shannon_entropy(payload);
            if entropy >= 7200 {
                return (
                    DlpDataType::HighEntropyExfiltration,
                    ThreatSeverity::Critical,
                    0,
                    payload.len(),
                );
            }
        }

        (DlpDataType::None, ThreatSeverity::Low, 0, 0)
    }

    /// Masque les données sensibles dans le tampon de sortie
    pub fn mask_payload(&self, payload: &[u8], out_buf: &mut [u8]) -> Result<usize, DlpError> {
        let (data_type, _, match_start, match_len) = self.classify_payload(payload);
        if data_type == DlpDataType::None {
            if out_buf.len() < payload.len() {
                return Err(DlpError::BufferTooSmall);
            }
            out_buf[..payload.len()].copy_from_slice(payload);
            return Ok(payload.len());
        }

        let replacement: &[u8] = match data_type {
            DlpDataType::PiiCreditCard => b"****-****-****-REDACTED",
            DlpDataType::PiiNationalId => b"XXX-XX-REDACTED",
            DlpDataType::ApiTokenOrSecret => b"[REDACTED_API_TOKEN]",
            DlpDataType::CryptoPrivateKey => b"-----BEGIN REDACTED PRIVATE KEY-----\n[REDACTED]\n-----END REDACTED PRIVATE KEY-----",
            DlpDataType::SovereignDefenseSecret => b"[SOVEREIGN-CLASSIFIED-REDACTED]",
            DlpDataType::HighEntropyExfiltration => b"[HIGH-ENTROPY-BLOCKED-REDACTED]",
            DlpDataType::None => b"",
        };

        let new_len = match_start + replacement.len() + (payload.len() - (match_start + match_len));
        if out_buf.len() < new_len {
            return Err(DlpError::BufferTooSmall);
        }

        // Copie pré-motif
        out_buf[..match_start].copy_from_slice(&payload[..match_start]);
        // Copie remplacement
        out_buf[match_start..match_start + replacement.len()].copy_from_slice(replacement);
        // Copie post-motif
        let post_start = match_start + match_len;
        let post_dest = match_start + replacement.len();
        let post_len = payload.len() - post_start;
        out_buf[post_dest..post_dest + post_len].copy_from_slice(&payload[post_start..]);

        Ok(new_len)
    }

    /// Met en quarantaine un flux suspect de manière instantanée O(1)
    pub fn quarantine_flow(
        &mut self,
        flow_id: u32,
        source: &str,
        destination: &str,
        data_type: DlpDataType,
        severity: ThreatSeverity,
        payload_hash: [u8; 32],
        entropy: u32,
        timestamp: u64,
    ) -> Result<(), DlpError> {
        if !self.cap.has_right(dlp_rights::QUARANTINE_FLOW) {
            return Err(DlpError::PermissionDenied);
        }
        if self.quarantine_count >= self.quarantine_store.len() {
            return Err(DlpError::QuarantineTableFull);
        }

        let mut src_buf = [0u8; 32];
        let src_bytes = source.as_bytes();
        let src_len = src_bytes.len().min(32);
        src_buf[..src_len].copy_from_slice(&src_bytes[..src_len]);

        let mut dst_buf = [0u8; 32];
        let dst_bytes = destination.as_bytes();
        let dst_len = dst_bytes.len().min(32);
        dst_buf[..dst_len].copy_from_slice(&dst_bytes[..dst_len]);

        let entry = DlpQuarantineEntry {
            flow_id,
            source: src_buf,
            source_len: src_len,
            destination: dst_buf,
            destination_len: dst_len,
            data_type,
            severity,
            payload_hash,
            entropy_millibits: entropy,
            timestamp,
            isolated: true,
        };

        for slot in self.quarantine_store.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.quarantine_count += 1;
                self.flows_quarantined += 1;
                return Ok(());
            }
        }

        Err(DlpError::QuarantineTableFull)
    }

    /// Enregistre une entrée dans le journal d'audit cryptographique inaltérable
    fn append_audit(
        &mut self,
        timestamp: u64,
        action_name: &str,
        source: &str,
        data_type: DlpDataType,
        verdict: DlpAction,
    ) -> Result<[u8; 32], DlpError> {
        if self.audit_count >= self.audit_ledger.len() {
            return Err(DlpError::AuditLogFull);
        }

        let mut act_buf = [0u8; 24];
        let act_bytes = action_name.as_bytes();
        let act_len = act_bytes.len().min(24);
        act_buf[..act_len].copy_from_slice(&act_bytes[..act_len]);

        let mut src_buf = [0u8; 32];
        let src_bytes = source.as_bytes();
        let src_len = src_bytes.len().min(32);
        src_buf[..src_len].copy_from_slice(&src_bytes[..src_len]);

        let entry_id = self.next_entry_id;
        self.next_entry_id += 1;

        // Scellement cryptographique par bloc SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&entry_id.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&act_buf[..act_len]);
        hasher.update(&src_buf[..src_len]);
        hasher.update(&[data_type as u8, verdict as u8]);
        hasher.update(&self.last_audit_hash);
        let entry_hash = hasher.finalize();

        let audit_entry = DlpAuditEntry {
            entry_id,
            timestamp,
            action_str: act_buf,
            action_len: act_len,
            source: src_buf,
            source_len: src_len,
            data_type,
            verdict,
            prev_hash: self.last_audit_hash,
            entry_hash,
        };

        for slot in self.audit_ledger.iter_mut() {
            if slot.is_none() {
                *slot = Some(audit_entry);
                self.audit_count += 1;
                self.last_audit_hash = entry_hash;
                return Ok(entry_hash);
            }
        }

        Err(DlpError::AuditLogFull)
    }

    /// Inspecte un flux réseau ou IPC et applique la politique DLP appropriée
    pub fn inspect_flow(
        &mut self,
        flow_id: u32,
        source: &str,
        destination: &str,
        payload: &[u8],
        output_buf: &mut [u8],
        timestamp: u64,
    ) -> Result<DlpInspectionResult, DlpError> {
        if !self.cap.has_right(dlp_rights::INSPECT_FLOW) {
            return Err(DlpError::PermissionDenied);
        }
        self.cap.consume()?;
        self.flows_scanned += 1;

        let orig_hash = Sha256::digest(payload);
        let entropy = compute_shannon_entropy(payload);
        let (data_type, severity, _, _) = self.classify_payload(payload);

        // Si aucune donnée sensible détectée
        if data_type == DlpDataType::None {
            if output_buf.len() < payload.len() {
                return Err(DlpError::BufferTooSmall);
            }
            output_buf[..payload.len()].copy_from_slice(payload);
            let _ = self.append_audit(
                timestamp,
                "FLOW_ALLOWED",
                source,
                data_type,
                DlpAction::Allow,
            );

            return Ok(DlpInspectionResult {
                flow_id,
                action: DlpAction::Allow,
                data_type: DlpDataType::None,
                severity: ThreatSeverity::Low,
                entropy_millibits: entropy,
                bytes_processed: payload.len(),
                output_len: payload.len(),
                original_hash: orig_hash,
                sanitized_hash: orig_hash,
                quarantined: false,
                policy_id_triggered: 0,
            });
        }

        // Trouver la politique correspondante
        let mut target_policy: Option<DlpPolicy> = None;
        for pol in self.policies.iter().flatten() {
            if pol.enabled && pol.data_type == data_type {
                target_policy = Some(*pol);
                break;
            }
        }

        let policy = match target_policy {
            Some(p) => p,
            None => {
                // Règle par défaut pour données non couvertes mais sensibles: Bloquer si Critique, Masquer sinon
                DlpPolicy::new(
                    99,
                    "Default Adaptive Fallback",
                    data_type,
                    severity,
                    if severity == ThreatSeverity::Critical {
                        DlpAction::Block
                    } else {
                        DlpAction::Mask
                    },
                    0,
                    severity == ThreatSeverity::Critical,
                )
            }
        };

        // Enregistrer la violation
        let v_id = self.next_violation_id;
        self.next_violation_id += 1;
        if self.violation_count < self.violations.len() {
            for slot in self.violations.iter_mut() {
                if slot.is_none() {
                    *slot = Some(DlpViolationRecord {
                        violation_id: v_id,
                        flow_id,
                        policy_id: policy.policy_id,
                        data_type,
                        severity,
                        action_taken: policy.action,
                        entropy_millibits: entropy,
                        timestamp,
                    });
                    self.violation_count += 1;
                    break;
                }
            }
        }

        let mut quarantined = false;
        if policy.quarantine_on_match || policy.action == DlpAction::Quarantine {
            let _ = self.quarantine_flow(
                flow_id,
                source,
                destination,
                data_type,
                severity,
                orig_hash,
                entropy,
                timestamp,
            );
            quarantined = true;
        }

        match policy.action {
            DlpAction::Allow => {
                if output_buf.len() < payload.len() {
                    return Err(DlpError::BufferTooSmall);
                }
                output_buf[..payload.len()].copy_from_slice(payload);
                let _ = self.append_audit(
                    timestamp,
                    "POLICY_ALLOW",
                    source,
                    data_type,
                    DlpAction::Allow,
                );

                Ok(DlpInspectionResult {
                    flow_id,
                    action: DlpAction::Allow,
                    data_type,
                    severity,
                    entropy_millibits: entropy,
                    bytes_processed: payload.len(),
                    output_len: payload.len(),
                    original_hash: orig_hash,
                    sanitized_hash: orig_hash,
                    quarantined,
                    policy_id_triggered: policy.policy_id,
                })
            }
            DlpAction::Mask => {
                if !self.cap.has_right(dlp_rights::MASK_PAYLOAD) {
                    return Err(DlpError::PermissionDenied);
                }
                let masked_len = self.mask_payload(payload, output_buf)?;
                let sanitized_hash = Sha256::digest(&output_buf[..masked_len]);
                self.payloads_masked += 1;
                let _ = self.append_audit(
                    timestamp,
                    "PAYLOAD_MASKED",
                    source,
                    data_type,
                    DlpAction::Mask,
                );

                Ok(DlpInspectionResult {
                    flow_id,
                    action: DlpAction::Mask,
                    data_type,
                    severity,
                    entropy_millibits: entropy,
                    bytes_processed: payload.len(),
                    output_len: masked_len,
                    original_hash: orig_hash,
                    sanitized_hash,
                    quarantined,
                    policy_id_triggered: policy.policy_id,
                })
            }
            DlpAction::Block => {
                self.flows_blocked += 1;
                let _ = self.append_audit(
                    timestamp,
                    "FLOW_BLOCKED",
                    source,
                    data_type,
                    DlpAction::Block,
                );

                Ok(DlpInspectionResult {
                    flow_id,
                    action: DlpAction::Block,
                    data_type,
                    severity,
                    entropy_millibits: entropy,
                    bytes_processed: payload.len(),
                    output_len: 0,
                    original_hash: orig_hash,
                    sanitized_hash: [0u8; 32],
                    quarantined,
                    policy_id_triggered: policy.policy_id,
                })
            }
            DlpAction::Quarantine => {
                let _ = self.append_audit(
                    timestamp,
                    "FLOW_QUARANTINED",
                    source,
                    data_type,
                    DlpAction::Quarantine,
                );

                Ok(DlpInspectionResult {
                    flow_id,
                    action: DlpAction::Quarantine,
                    data_type,
                    severity,
                    entropy_millibits: entropy,
                    bytes_processed: payload.len(),
                    output_len: 0,
                    original_hash: orig_hash,
                    sanitized_hash: [0u8; 32],
                    quarantined: true,
                    policy_id_triggered: policy.policy_id,
                })
            }
        }
    }

    /// Vérifie formellement l'intégrité de la chaîne cryptographique d'audit
    pub fn verify_audit_integrity(&self) -> bool {
        let genesis_seed = b"JAMBO_DLP_GENESIS_SEAL_V0.3.12";
        let mut expected_prev = Sha256::digest(genesis_seed);

        for slot in self.audit_ledger.iter().flatten() {
            if slot.prev_hash != expected_prev {
                return false;
            }

            let mut hasher = Sha256::new();
            hasher.update(&slot.entry_id.to_be_bytes());
            hasher.update(&slot.timestamp.to_be_bytes());
            hasher.update(&slot.action_str[..slot.action_len]);
            hasher.update(&slot.source[..slot.source_len]);
            hasher.update(&[slot.data_type as u8, slot.verdict as u8]);
            hasher.update(&slot.prev_hash);
            let calculated_hash = hasher.finalize();

            if slot.entry_hash != calculated_hash {
                return false;
            }

            expected_prev = slot.entry_hash;
        }

        true
    }

    /// Retourne un résumé d'état du démon DLP
    pub fn get_summary(&self) -> DlpSummary {
        DlpSummary {
            policies_count: self.policy_count,
            flows_scanned: self.flows_scanned,
            violations_detected: self.violation_count,
            payloads_masked: self.payloads_masked,
            flows_blocked: self.flows_blocked,
            flows_quarantined: self.flows_quarantined,
            quarantine_count: self.quarantine_count,
            ledger_valid: self.verify_audit_integrity(),
        }
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] / cargo test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_deterministic() {
        let digest1 = Sha256::digest(b"JAMBO_DLP_TEST_VECTOR");
        let digest2 = Sha256::digest(b"JAMBO_DLP_TEST_VECTOR");
        assert_eq!(digest1, digest2);
        assert_ne!(digest1, [0u8; 32]);
    }

    #[test]
    fn test_luhn_algorithm() {
        // Numéro de carte valide (Visa 16 digits test)
        assert!(check_luhn(b"4111111111111111"));
        assert!(check_luhn(b"4111-1111-1111-1111"));
        // AMEX 15 digits valide
        assert!(check_luhn(b"378282246310005"));
        // Numéro erroné (invalide)
        assert!(!check_luhn(b"4111111111111112"));
        assert!(!check_luhn(b"4111111111111119"));
    }

    #[test]
    fn test_shannon_entropy() {
        // Données répétées (entropie nulle)
        let zeros = [0xAAu8; 128];
        assert_eq!(compute_shannon_entropy(&zeros), 0);

        // Données variées (entropie élevée)
        let mut random_like = [0u8; 256];
        for i in 0..256 {
            random_like[i] = i as u8;
        }
        let entropy = compute_shannon_entropy(&random_like);
        assert!(entropy >= 7900, "Entropy should be close to 8000 millibits");
    }

    #[test]
    fn test_dlp_cap_attenuation() {
        let root_cap = DlpCap::new(Handle::new(145, 1), dlp_rights::ALL, 10000, 500);
        assert!(root_cap.has_right(dlp_rights::ADMIN));
        assert!(root_cap.has_right(dlp_rights::INSPECT_FLOW));

        // Atténuation monotone
        let limited_cap = root_cap
            .attenuate(
                dlp_rights::INSPECT_FLOW | dlp_rights::MASK_PAYLOAD | dlp_rights::QUERY_AUDIT,
                5000,
                200,
            )
            .expect("Atténuation");
        assert!(limited_cap.has_right(dlp_rights::INSPECT_FLOW));
        assert!(limited_cap.has_right(dlp_rights::MASK_PAYLOAD));
        assert!(!limited_cap.has_right(dlp_rights::ADMIN));
        assert!(!limited_cap.has_right(dlp_rights::BLOCK_TRANSFER));

        // Refus d'escalade
        assert_eq!(
            limited_cap.attenuate(dlp_rights::ALL, 5000, 200),
            Err(DlpError::AttenuationViolation)
        );
    }

    #[test]
    fn test_credit_card_masking() {
        let cap = DlpCap::new(Handle::new(145, 1), dlp_rights::ALL, 10000, 1000);
        let mut dlp = JamboDlpDaemon::new(cap);
        dlp.init_defaults();

        let payload = b"Transfer to card: 4111-1111-1111-1111 via payment gateway";
        let mut out = [0u8; 256];
        let res = dlp
            .inspect_flow(
                1001,
                "client_app",
                "ext_gateway",
                payload,
                &mut out,
                1735100000,
            )
            .expect("Inspect");

        assert_eq!(res.action, DlpAction::Mask);
        assert_eq!(res.data_type, DlpDataType::PiiCreditCard);
        assert_eq!(res.severity, ThreatSeverity::High);
        let out_str = core::str::from_utf8(&out[..res.output_len]).unwrap();
        assert!(out_str.contains("****-****-****-REDACTED"));
    }

    #[test]
    fn test_private_key_blocking() {
        let cap = DlpCap::new(Handle::new(145, 1), dlp_rights::ALL, 10000, 1000);
        let mut dlp = JamboDlpDaemon::new(cap);
        dlp.init_defaults();

        let payload =
            b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----";
        let mut out = [0u8; 256];
        let res = dlp
            .inspect_flow(
                1002,
                "backup_agent",
                "public_s3",
                payload,
                &mut out,
                1735100100,
            )
            .expect("Inspect");

        assert_eq!(res.action, DlpAction::Block);
        assert_eq!(res.data_type, DlpDataType::CryptoPrivateKey);
        assert_eq!(res.severity, ThreatSeverity::Critical);
        assert!(res.quarantined);
        assert_eq!(dlp.flows_blocked, 1);
        assert_eq!(dlp.quarantine_count, 1);
    }

    #[test]
    fn test_sovereign_classified_blocking() {
        let cap = DlpCap::new(Handle::new(145, 1), dlp_rights::ALL, 10000, 1000);
        let mut dlp = JamboDlpDaemon::new(cap);
        dlp.init_defaults();

        let payload = b"RAPPORT INTERNE: SECRET-DEFENSE OPERATION ANCRE BLEUE";
        let mut out = [0u8; 256];
        let res = dlp
            .inspect_flow(
                1003,
                "officer_console",
                "foreign_peer",
                payload,
                &mut out,
                1735100200,
            )
            .expect("Inspect");

        assert_eq!(res.action, DlpAction::Block);
        assert_eq!(res.data_type, DlpDataType::SovereignDefenseSecret);
        assert_eq!(res.severity, ThreatSeverity::Critical);
        assert!(res.quarantined);
    }

    #[test]
    fn test_high_entropy_quarantine() {
        let cap = DlpCap::new(Handle::new(145, 1), dlp_rights::ALL, 10000, 1000);
        let mut dlp = JamboDlpDaemon::new(cap);
        dlp.init_defaults();

        // 256 octets d'entropie maximale
        let mut high_entropy = [0u8; 256];
        for i in 0..256 {
            high_entropy[i] = i as u8;
        }

        let mut out = [0u8; 256];
        let res = dlp
            .inspect_flow(
                1004,
                "exfil_process",
                "c2_server",
                &high_entropy,
                &mut out,
                1735100300,
            )
            .expect("Inspect");

        assert_eq!(res.action, DlpAction::Quarantine);
        assert_eq!(res.data_type, DlpDataType::HighEntropyExfiltration);
        assert!(res.quarantined);
    }

    #[test]
    fn test_audit_integrity_verification() {
        let cap = DlpCap::new(Handle::new(145, 1), dlp_rights::ALL, 10000, 1000);
        let mut dlp = JamboDlpDaemon::new(cap);
        dlp.init_defaults();

        let mut out = [0u8; 256];
        let _ = dlp.inspect_flow(1, "app1", "app2", b"Hello Clean World", &mut out, 1000);
        let _ = dlp.inspect_flow(
            2,
            "app3",
            "app4",
            b"Token: sec_tok_1234567890abcdef1234",
            &mut out,
            1001,
        );

        assert!(dlp.verify_audit_integrity());
        assert_eq!(dlp.audit_count, 2);

        // Altération malveillante d'une entrée d'audit
        if let Some(entry) = dlp.audit_ledger[0].as_mut() {
            entry.timestamp = 999999;
        }
        assert!(!dlp.verify_audit_integrity());
    }
}

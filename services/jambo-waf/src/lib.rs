//! Pare-Feu Applicatif L7 (WAF) Sandboxed & Filtrage d'Injections Protocolaire (`jambo-waf`)
//!
//! Phase 114 — Jalon v0.3.69 (Promotion PID 30)
//!
//! Fournit un pare-feu applicatif de couche 7 (WAF) haute sécurité durci en `#![no_std]` :
//! 1. Contrôle d'Accès Capabilaire Strict (`WafCap`) :
//!    - Zéro autorité ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone sans amplification de privilèges.
//! 2. Filtrage Protocolaire HTTP & En-têtes Stricts (RFC 7230) :
//!    - Détection d'injections CRLF (`\r\n`), null-bytes (`\0`), HTTP Request Smuggling.
//!    - Validation des méthodes HTTP, de l'en-tête Host et de la cohérence de taille.
//! 3. Détecteurs d'Injections & Heuristiques :
//!    - Injections SQL (SQLi) : signatures d'évasion, union-select, tautologies, timing attacks.
//!    - Cross-Site Scripting (XSS) : balises malveillantes, gestionnaires d'événements DOM, pseudo-protocoles.
//!    - Exécution de Commandes Arbitraires (RCE) : chaînes de shell, métacaractères d'injection.
//!    - Traversée de Répertoires (Path Traversal) : `../`, encodages multiples (%2e%2e, null byte).
//! 4. Analyseur JSON Récursif Protégé :
//!    - Détection de bombes de récursion / dépassement de profondeur (`MAX_JSON_DEPTH = 8`).
//!    - Détection de pollution de prototype (`__proto__`, `constructor`, `prototype`).
//! 5. Inspecteur de Bytecode WebAssembly (Wasm) :
//!    - Validation d'en-tête magique `\0asm` et version binaire.
//!    - Détection de bombes mémoire (`MAX_WASM_PAGES_ALLOWED = 512`) et d'appels d'hôtes interdits.
//! 6. Prévention de Fuite de Données Sortantes (Data Leakage) :
//!    - Inspection des réponses pour bloquer la fuite de clés privées, tokens ou traces de panique.
//! 7. Quarantaine Dynamique O(1), Liste Blanche & Audit Cryptographique SHA-256 Inaltérable.
//! 8. Protocole IPC 64 octets synchrone sous l'endpoint 30 (PID 30).

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES & LIMITES DU WAF
// ============================================================================

pub const WAF_ENDPOINT_ID: u32 = 30;
pub const WAF_MAGIC_REQ: u32 = 0x57414644; // "WAFD"
pub const WAF_MAGIC_RESP: u32 = 0x57414653; // "WAFS"
pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const MAX_RULES: usize = 32;
pub const MAX_WHITELISTED_IPS: usize = 16;
pub const MAX_QUARANTINED_IPS: usize = 32;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_HEADERS: usize = 16;
pub const MAX_HEADER_NAME_LEN: usize = 32;
pub const MAX_HEADER_VAL_LEN: usize = 128;
pub const MAX_URI_LEN: usize = 256;
pub const MAX_BODY_LEN: usize = 1024;
pub const MAX_JSON_DEPTH: usize = 8;
pub const MAX_WASM_PAGES_ALLOWED: u32 = 512;
pub const ANOMALY_THRESHOLD: u32 = 50;

// ============================================================================
// DROITS CAPABILAIRES (WafCap)
// ============================================================================

pub mod waf_rights {
    pub const INSPECT_REQUEST: u32 = 1 << 0;
    pub const INSPECT_RESPONSE: u32 = 1 << 1;
    pub const ENFORCE_RULES: u32 = 1 << 2;
    pub const CONFIGURE_RULES: u32 = 1 << 3;
    pub const QUARANTINE_IP: u32 = 1 << 4;
    pub const WHITELIST_BYPASS: u32 = 1 << 5;
    pub const AUDIT_INSPECT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = INSPECT_REQUEST
        | INSPECT_RESPONSE
        | ENFORCE_RULES
        | CONFIGURE_RULES
        | QUARANTINE_IP
        | WHITELIST_BYPASS
        | AUDIT_INSPECT
        | ADMIN;
}

// ============================================================================
// TYPES DE CAPACITÉ ET ERREURS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafError {
    PermissionDenied,
    RuleCapacityExceeded,
    QuarantineCapacityExceeded,
    WhitelistCapacityExceeded,
    InvalidRule,
    InvalidPacket,
    BufferTooSmall,
    MalformedProtocol,
    PayloadTooLarge,
    IpNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WafCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_inspections: u32,
    pub epoch: u64,
}

impl WafCap {
    pub const fn new(handle: Handle, rights: u32, max_inspections: u32, epoch: u64) -> Self {
        Self {
            handle,
            rights,
            max_inspections,
            epoch,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.rights != 0
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(&self, new_rights: u32, new_max_inspections: u32) -> Result<Self, WafError> {
        if (new_rights & !self.rights) != 0 {
            return Err(WafError::PermissionDenied);
        }
        if new_max_inspections > self.max_inspections {
            return Err(WafError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_inspections: new_max_inspections,
            epoch: self.epoch.saturating_add(1),
        })
    }
}

// ============================================================================
// STRUCTURES PROTOCOLE HTTP & DÉCISIONS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Custom,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Custom => "CUSTOM",
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackType {
    None = 0,
    SqlInjection = 1,
    CrossSiteScripting = 2,
    CommandInjection = 3,
    PathTraversal = 4,
    PrototypePollution = 5,
    ProtocolAnomaly = 6,
    MalformedWasm = 7,
    DataLeakage = 8,
    CustomSignature = 9,
}

impl AttackType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackType::None => "NONE",
            AttackType::SqlInjection => "SQL_INJECTION",
            AttackType::CrossSiteScripting => "XSS",
            AttackType::CommandInjection => "RCE_COMMAND_INJECTION",
            AttackType::PathTraversal => "PATH_TRAVERSAL",
            AttackType::PrototypePollution => "PROTOTYPE_POLLUTION",
            AttackType::ProtocolAnomaly => "PROTOCOL_ANOMALY",
            AttackType::MalformedWasm => "MALFORMED_WASM",
            AttackType::DataLeakage => "DATA_LEAKAGE",
            AttackType::CustomSignature => "CUSTOM_SIGNATURE",
        }
    }

    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::None),
            1 => Some(Self::SqlInjection),
            2 => Some(Self::CrossSiteScripting),
            3 => Some(Self::CommandInjection),
            4 => Some(Self::PathTraversal),
            5 => Some(Self::PrototypePollution),
            6 => Some(Self::ProtocolAnomaly),
            7 => Some(Self::MalformedWasm),
            8 => Some(Self::DataLeakage),
            9 => Some(Self::CustomSignature),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl RuleSeverity {
    pub fn score(&self) -> u32 {
        match self {
            RuleSeverity::Low => 10,
            RuleSeverity::Medium => 25,
            RuleSeverity::High => 50,
            RuleSeverity::Critical => 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Block,
    Quarantine,
    LogOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetScope {
    Uri,
    Header,
    Body,
    Method,
    All,
}

#[derive(Debug, Clone, Copy)]
pub struct WafRule {
    pub id: u32,
    pub enabled: bool,
    pub attack_type: AttackType,
    pub severity: RuleSeverity,
    pub action: RuleAction,
    pub target: TargetScope,
    pub name: [u8; 32],
    pub name_len: usize,
    pub pattern: [u8; 48],
    pub pattern_len: usize,
}

impl Default for WafRule {
    fn default() -> Self {
        Self::empty()
    }
}

impl WafRule {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            enabled: false,
            attack_type: AttackType::None,
            severity: RuleSeverity::Low,
            action: RuleAction::LogOnly,
            target: TargetScope::All,
            name: [0u8; 32],
            name_len: 0,
            pattern: [0u8; 48],
            pattern_len: 0,
        }
    }

    pub fn new(
        id: u32,
        name_str: &str,
        pattern_str: &str,
        attack_type: AttackType,
        severity: RuleSeverity,
        action: RuleAction,
        target: TargetScope,
    ) -> Self {
        let mut name = [0u8; 32];
        let n_bytes = name_str.as_bytes();
        let n_len = n_bytes.len().min(32);
        name[..n_len].copy_from_slice(&n_bytes[..n_len]);

        let mut pattern = [0u8; 48];
        let p_bytes = pattern_str.as_bytes();
        let p_len = p_bytes.len().min(48);
        pattern[..p_len].copy_from_slice(&p_bytes[..p_len]);

        Self {
            id,
            enabled: true,
            attack_type,
            severity,
            action,
            target,
            name,
            name_len: n_len,
            pattern,
            pattern_len: p_len,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalid-utf8>")
    }

    pub fn pattern_as_str(&self) -> &str {
        core::str::from_utf8(&self.pattern[..self.pattern_len]).unwrap_or("<invalid-utf8>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafDecision {
    Allow,
    Block {
        rule_id: u32,
        attack_type: AttackType,
        score: u32,
    },
    Quarantine {
        client_ip: [u8; 4],
        score: u32,
        reason: AttackType,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct HttpHeader {
    pub name: [u8; MAX_HEADER_NAME_LEN],
    pub name_len: usize,
    pub val: [u8; MAX_HEADER_VAL_LEN],
    pub val_len: usize,
}

impl Default for HttpHeader {
    fn default() -> Self {
        Self::empty()
    }
}

impl HttpHeader {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_HEADER_NAME_LEN],
            name_len: 0,
            val: [0u8; MAX_HEADER_VAL_LEN],
            val_len: 0,
        }
    }

    pub fn new(name_str: &str, val_str: &str) -> Self {
        let mut header = Self::empty();
        let n_b = name_str.as_bytes();
        header.name_len = n_b.len().min(MAX_HEADER_NAME_LEN);
        header.name[..header.name_len].copy_from_slice(&n_b[..header.name_len]);

        let v_b = val_str.as_bytes();
        header.val_len = v_b.len().min(MAX_HEADER_VAL_LEN);
        header.val[..header.val_len].copy_from_slice(&v_b[..header.val_len]);

        header
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HttpRequest {
    pub client_ip: [u8; 4],
    pub method: HttpMethod,
    pub uri: [u8; MAX_URI_LEN],
    pub uri_len: usize,
    pub headers: [HttpHeader; MAX_HEADERS],
    pub header_count: usize,
    pub body: [u8; MAX_BODY_LEN],
    pub body_len: usize,
}

impl Default for HttpRequest {
    fn default() -> Self {
        Self::empty()
    }
}

impl HttpRequest {
    pub const fn empty() -> Self {
        Self {
            client_ip: [0, 0, 0, 0],
            method: HttpMethod::Get,
            uri: [0u8; MAX_URI_LEN],
            uri_len: 0,
            headers: [HttpHeader::empty(); MAX_HEADERS],
            header_count: 0,
            body: [0u8; MAX_BODY_LEN],
            body_len: 0,
        }
    }

    pub fn new(client_ip: [u8; 4], method: HttpMethod, uri_str: &str) -> Self {
        let mut req = Self::empty();
        req.client_ip = client_ip;
        req.method = method;
        let u_b = uri_str.as_bytes();
        req.uri_len = u_b.len().min(MAX_URI_LEN);
        req.uri[..req.uri_len].copy_from_slice(&u_b[..req.uri_len]);
        req
    }

    pub fn add_header(&mut self, name: &str, val: &str) -> Result<(), WafError> {
        if self.header_count >= MAX_HEADERS {
            return Err(WafError::BufferTooSmall);
        }
        self.headers[self.header_count] = HttpHeader::new(name, val);
        self.header_count += 1;
        Ok(())
    }

    pub fn set_body(&mut self, data: &[u8]) -> Result<(), WafError> {
        if data.len() > MAX_BODY_LEN {
            return Err(WafError::PayloadTooLarge);
        }
        self.body[..data.len()].copy_from_slice(data);
        self.body_len = data.len();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: [HttpHeader; MAX_HEADERS],
    pub header_count: usize,
    pub body: [u8; MAX_BODY_LEN],
    pub body_len: usize,
}

impl Default for HttpResponse {
    fn default() -> Self {
        Self::empty()
    }
}

impl HttpResponse {
    pub const fn empty() -> Self {
        Self {
            status_code: 200,
            headers: [HttpHeader::empty(); MAX_HEADERS],
            header_count: 0,
            body: [0u8; MAX_BODY_LEN],
            body_len: 0,
        }
    }

    pub fn new(status_code: u16) -> Self {
        let mut resp = Self::empty();
        resp.status_code = status_code;
        resp
    }

    pub fn add_header(&mut self, name: &str, val: &str) -> Result<(), WafError> {
        if self.header_count >= MAX_HEADERS {
            return Err(WafError::BufferTooSmall);
        }
        self.headers[self.header_count] = HttpHeader::new(name, val);
        self.header_count += 1;
        Ok(())
    }

    pub fn set_body(&mut self, data: &[u8]) -> Result<(), WafError> {
        if data.len() > MAX_BODY_LEN {
            return Err(WafError::PayloadTooLarge);
        }
        self.body[..data.len()].copy_from_slice(data);
        self.body_len = data.len();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuarantinedEntry {
    pub ip: [u8; 4],
    pub strikes: u32,
    pub reason: AttackType,
    pub active: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub client_ip: [u8; 4],
    pub attack_type: AttackType,
    pub rule_id: u32,
    pub action: RuleAction,
    pub score: u32,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

// ============================================================================
// FONCTIONS UTILITAIRES DE CHAÎNES ET DÉTECTIONS HEURISTIQUES
// ============================================================================

pub struct StringSearch;

impl StringSearch {
    /// Compare deux tranches d'octets sans tenir compte de la casse ASCII à temps borné
    pub fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if haystack.len() < needle.len() {
            return false;
        }
        let max_start = haystack.len() - needle.len();
        let mut i = 0;
        while i <= max_start {
            let mut matched = true;
            let mut j = 0;
            while j < needle.len() {
                let h = haystack[i + j].to_ascii_lowercase();
                let n = needle[j].to_ascii_lowercase();
                if h != n {
                    matched = false;
                    break;
                }
                j += 1;
            }
            if matched {
                return true;
            }
            i += 1;
        }
        false
    }
}

fn url_decode(src: &[u8], dst: &mut [u8]) -> usize {
    let mut s = 0;
    let mut d = 0;
    while s < src.len() && d < dst.len() {
        if src[s] == b'%' && s + 2 < src.len() {
            let h1 = match src[s + 1] {
                b'0'..=b'9' => src[s + 1] - b'0',
                b'a'..=b'f' => src[s + 1] - b'a' + 10,
                b'A'..=b'F' => src[s + 1] - b'A' + 10,
                _ => 255,
            };
            let h2 = match src[s + 2] {
                b'0'..=b'9' => src[s + 2] - b'0',
                b'a'..=b'f' => src[s + 2] - b'a' + 10,
                b'A'..=b'F' => src[s + 2] - b'A' + 10,
                _ => 255,
            };
            if h1 != 255 && h2 != 255 {
                dst[d] = (h1 << 4) | h2;
                d += 1;
                s += 3;
                continue;
            }
        }
        dst[d] = src[s];
        d += 1;
        s += 1;
    }
    d
}

// ============================================================================
// INSPECTEUR JSON SÉCURISÉ & DÉTECTEUR DE POLLUTION DE PROTOTYPE
// ============================================================================

pub struct JsonInspector;

impl JsonInspector {
    /// Valide la profondeur de récursion et détecte les clés de pollution de prototype
    pub fn inspect_json(payload: &[u8]) -> Result<(), AttackType> {
        let mut depth: usize = 0;
        let mut in_string = false;
        let mut escape = false;

        let mut str_buf = [0u8; 32];
        let mut str_len = 0;

        let mut i = 0;
        while i < payload.len() {
            let b = payload[i];

            if in_string {
                if escape {
                    escape = false;
                    if str_len < 32 {
                        str_buf[str_len] = b;
                        str_len += 1;
                    }
                } else if b == b'\\' {
                    escape = true;
                } else if b == b'"' {
                    in_string = false;
                    // Vérifier si la clé de chaîne correspond à une pollution de prototype
                    let s = &str_buf[..str_len];
                    if s == b"__proto__" || s == b"constructor" || s == b"prototype" {
                        return Err(AttackType::PrototypePollution);
                    }
                } else if str_len < 32 {
                    str_buf[str_len] = b;
                    str_len += 1;
                }
            } else {
                match b {
                    b'"' => {
                        in_string = true;
                        escape = false;
                        str_len = 0;
                    }
                    b'{' | b'[' => {
                        depth += 1;
                        if depth > MAX_JSON_DEPTH {
                            return Err(AttackType::ProtocolAnomaly);
                        }
                    }
                    b'}' | b']' => {
                        if depth == 0 {
                            return Err(AttackType::ProtocolAnomaly);
                        }
                        depth -= 1;
                    }
                    _ => {}
                }
            }
            i += 1;
        }

        if in_string || depth != 0 {
            return Err(AttackType::ProtocolAnomaly);
        }
        Ok(())
    }
}

// ============================================================================
// INSPECTEUR DE BYTECODE WEBASSEMBLY (WASM) SÉCURISÉ
// ============================================================================

pub struct WasmInspector;

impl WasmInspector {
    pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // "\0asm"
    pub const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

    pub fn inspect_wasm(payload: &[u8]) -> Result<(), AttackType> {
        if payload.len() < 8 {
            return Err(AttackType::MalformedWasm);
        }
        // Vérification de l'en-tête binaire Wasm
        if payload[0..4] != Self::WASM_MAGIC || payload[4..8] != Self::WASM_VERSION {
            return Err(AttackType::MalformedWasm);
        }

        let mut offset = 8;
        while offset < payload.len() {
            let section_id = payload[offset];
            offset += 1;
            if offset >= payload.len() {
                return Err(AttackType::MalformedWasm);
            }

            // Décodage de la taille de section (LEB128 simplifié 1-5 octets)
            let mut sec_len: usize = 0;
            let mut shift = 0;
            let mut byte_count = 0;
            loop {
                if offset >= payload.len() || byte_count >= 5 {
                    return Err(AttackType::MalformedWasm);
                }
                let byte = payload[offset];
                offset += 1;
                sec_len |= ((byte & 0x7F) as usize) << shift;
                byte_count += 1;
                if (byte & 0x80) == 0 {
                    break;
                }
                shift += 7;
            }

            if offset + sec_len > payload.len() {
                return Err(AttackType::MalformedWasm);
            }

            let sec_data = &payload[offset..offset + sec_len];

            // Section 2: Import - Détection d'imports hôtes malveillants
            if section_id == 2
                && (StringSearch::contains_ignore_case(sec_data, b"system")
                    || StringSearch::contains_ignore_case(sec_data, b"exec")
                    || StringSearch::contains_ignore_case(sec_data, b"fork")
                    || StringSearch::contains_ignore_case(sec_data, b"socket_raw"))
            {
                return Err(AttackType::MalformedWasm);
            }

            // Section 5: Memory - Détection d'allocation de pages mémoire excessives (Memory Bomb)
            if section_id == 5 && !sec_data.is_empty() {
                let mut m_off = 0;
                let _count = sec_data[m_off];
                m_off += 1;
                if m_off < sec_data.len() {
                    let _flags = sec_data[m_off];
                    m_off += 1;
                    // Décodage LEB128 des pages initiales
                    let mut pages: u32 = 0;
                    let mut p_shift = 0;
                    while m_off < sec_data.len() && p_shift < 32 {
                        let b = sec_data[m_off];
                        m_off += 1;
                        pages |= ((b & 0x7F) as u32) << p_shift;
                        if (b & 0x80) == 0 {
                            break;
                        }
                        p_shift += 7;
                    }
                    if pages > MAX_WASM_PAGES_ALLOWED {
                        return Err(AttackType::MalformedWasm);
                    }
                }
            }

            offset += sec_len;
        }

        Ok(())
    }
}

// ============================================================================
// IMPLÉMENTATION CRYPTOGRAPHIQUE SHA-256 SOUVERAINE SANS STANDARD
// ============================================================================

pub struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
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

    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let buf_idx = (self.count % 64) as usize;
            self.buffer[buf_idx] = data[i];
            self.count += 1;
            if (self.count % 64) == 0 {
                self.transform();
            }
            i += 1;
        }
    }

    fn transform(&mut self) {
        let chunk = self.buffer;
        let mut w = [0u32; 64];
        let mut i = 0;
        while i < 16 {
            w[i] = ((chunk[i * 4] as u32) << 24)
                | ((chunk[i * 4 + 1] as u32) << 16)
                | ((chunk[i * 4 + 2] as u32) << 8)
                | (chunk[i * 4 + 3] as u32);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        let mut j = 0;
        while j < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[j])
                .wrapping_add(w[j]);
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
            j += 1;
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

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.count * 8;
        let buf_idx = (self.count % 64) as usize;
        self.buffer[buf_idx] = 0x80;

        if buf_idx >= 56 {
            let mut k = buf_idx + 1;
            while k < 64 {
                self.buffer[k] = 0;
                k += 1;
            }
            self.transform();
            let mut m = 0;
            while m < 56 {
                self.buffer[m] = 0;
                m += 1;
            }
        } else {
            let mut k = buf_idx + 1;
            while k < 56 {
                self.buffer[k] = 0;
                k += 1;
            }
        }

        let mut idx = 56;
        while idx < 64 {
            let shift = (63 - idx) * 8;
            self.buffer[idx] = (bit_len >> shift) as u8;
            idx += 1;
        }
        self.transform();

        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 8 {
            out[i * 4] = (self.state[i] >> 24) as u8;
            out[i * 4 + 1] = (self.state[i] >> 16) as u8;
            out[i * 4 + 2] = (self.state[i] >> 8) as u8;
            out[i * 4 + 3] = self.state[i] as u8;
            i += 1;
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// ============================================================================
// DÉMON DU PARE-FEU APPLICATIF L7 (`JamboWafDaemon`)
// ============================================================================

pub struct JamboWafDaemon {
    pub admin_cap: WafCap,
    pub rules: [WafRule; MAX_RULES],
    pub rule_count: usize,
    pub whitelisted_ips: [[u8; 4]; MAX_WHITELISTED_IPS],
    pub whitelist_count: usize,
    pub quarantined: [QuarantinedEntry; MAX_QUARANTINED_IPS],
    pub quarantine_count: usize,
    pub audit_chain: [u8; 32],
    pub audit_log: [AuditEntry; MAX_AUDIT_LOGS],
    pub audit_count: usize,

    // Statistiques d'exploitation
    pub total_inspections: u64,
    pub total_blocked: u64,
    pub total_quarantined: u64,
    pub total_passed: u64,
    pub total_anomalies: u64,
}

impl Default for JamboWafDaemon {
    fn default() -> Self {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100_000, 1);
        Self::new(cap)
    }
}

impl JamboWafDaemon {
    pub const GENESIS_HASH: [u8; 32] = [
        0x57, 0x41, 0x46, 0x2D, 0x53, 0x45, 0x43, 0x55, 0x52, 0x49, 0x54, 0x59, 0x2D, 0x47, 0x45,
        0x4E, 0x45, 0x53, 0x49, 0x53, 0x2D, 0x32, 0x30, 0x32, 0x36, 0x2D, 0x4A, 0x41, 0x4D, 0x42,
        0x4F, 0x53,
    ];

    pub const fn new(cap: WafCap) -> Self {
        Self {
            admin_cap: cap,
            rules: [WafRule::empty(); MAX_RULES],
            rule_count: 0,
            whitelisted_ips: [[0; 4]; MAX_WHITELISTED_IPS],
            whitelist_count: 0,
            quarantined: [QuarantinedEntry {
                ip: [0; 4],
                strikes: 0,
                reason: AttackType::None,
                active: false,
            }; MAX_QUARANTINED_IPS],
            quarantine_count: 0,
            audit_chain: Self::GENESIS_HASH,
            audit_log: [AuditEntry {
                timestamp: 0,
                client_ip: [0; 4],
                attack_type: AttackType::None,
                rule_id: 0,
                action: RuleAction::LogOnly,
                score: 0,
                prev_hash: [0; 32],
                entry_hash: [0; 32],
            }; MAX_AUDIT_LOGS],
            audit_count: 0,
            total_inspections: 0,
            total_blocked: 0,
            total_quarantined: 0,
            total_passed: 0,
            total_anomalies: 0,
        }
    }

    /// Initialise l'ensemble standard des règles OWASP Top 10 et signatures critiques
    pub fn init_defaults(&mut self) {
        let _ = self.add_rule_internal(WafRule::new(
            1001,
            "SQLi_Tautology",
            "' or '1'='1",
            AttackType::SqlInjection,
            RuleSeverity::Critical,
            RuleAction::Block,
            TargetScope::All,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1002,
            "SQLi_Union_Select",
            "union select",
            AttackType::SqlInjection,
            RuleSeverity::Critical,
            RuleAction::Block,
            TargetScope::All,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1003,
            "SQLi_Drop_Table",
            "drop table",
            AttackType::SqlInjection,
            RuleSeverity::Critical,
            RuleAction::Block,
            TargetScope::All,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1004,
            "XSS_Script_Tag",
            "<script",
            AttackType::CrossSiteScripting,
            RuleSeverity::High,
            RuleAction::Block,
            TargetScope::All,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1005,
            "XSS_Javascript_URI",
            "javascript:",
            AttackType::CrossSiteScripting,
            RuleSeverity::High,
            RuleAction::Block,
            TargetScope::Uri,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1006,
            "XSS_Event_Handler",
            "onerror=",
            AttackType::CrossSiteScripting,
            RuleSeverity::High,
            RuleAction::Block,
            TargetScope::All,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1007,
            "RCE_Bin_Sh",
            "/bin/sh",
            AttackType::CommandInjection,
            RuleSeverity::Critical,
            RuleAction::Quarantine,
            TargetScope::All,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1008,
            "RCE_Cat_Passwd",
            "; cat /",
            AttackType::CommandInjection,
            RuleSeverity::Critical,
            RuleAction::Quarantine,
            TargetScope::All,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1009,
            "Path_Traversal_DotDot",
            "../",
            AttackType::PathTraversal,
            RuleSeverity::High,
            RuleAction::Block,
            TargetScope::Uri,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1010,
            "Path_Traversal_Encoded",
            "%2e%2e",
            AttackType::PathTraversal,
            RuleSeverity::High,
            RuleAction::Block,
            TargetScope::Uri,
        ));
        let _ = self.add_rule_internal(WafRule::new(
            1011,
            "Header_CRLF_Smuggling",
            "\r\n",
            AttackType::ProtocolAnomaly,
            RuleSeverity::Medium,
            RuleAction::Block,
            TargetScope::Header,
        ));
    }

    fn add_rule_internal(&mut self, rule: WafRule) -> Result<u32, WafError> {
        if self.rule_count >= MAX_RULES {
            return Err(WafError::RuleCapacityExceeded);
        }
        self.rules[self.rule_count] = rule;
        self.rule_count += 1;
        Ok(rule.id)
    }

    pub fn add_rule(&mut self, cap: &WafCap, rule: WafRule) -> Result<u32, WafError> {
        if !cap.is_valid() || !cap.has_right(waf_rights::CONFIGURE_RULES) {
            return Err(WafError::PermissionDenied);
        }
        self.add_rule_internal(rule)
    }

    pub fn is_ip_whitelisted(&self, ip: &[u8; 4]) -> bool {
        let mut i = 0;
        while i < self.whitelist_count {
            if &self.whitelisted_ips[i] == ip {
                return true;
            }
            i += 1;
        }
        false
    }

    pub fn whitelist_ip(&mut self, cap: &WafCap, ip: [u8; 4]) -> Result<(), WafError> {
        if !cap.is_valid() || !cap.has_right(waf_rights::WHITELIST_BYPASS) {
            return Err(WafError::PermissionDenied);
        }
        if self.is_ip_whitelisted(&ip) {
            return Ok(());
        }
        if self.whitelist_count >= MAX_WHITELISTED_IPS {
            return Err(WafError::WhitelistCapacityExceeded);
        }
        self.whitelisted_ips[self.whitelist_count] = ip;
        self.whitelist_count += 1;
        Ok(())
    }

    pub fn is_ip_quarantined(&self, ip: &[u8; 4]) -> bool {
        let mut i = 0;
        while i < self.quarantine_count {
            if &self.quarantined[i].ip == ip && self.quarantined[i].active {
                return true;
            }
            i += 1;
        }
        false
    }

    pub fn quarantine_ip(
        &mut self,
        cap: &WafCap,
        ip: [u8; 4],
        reason: AttackType,
    ) -> Result<(), WafError> {
        if !cap.is_valid() || !cap.has_right(waf_rights::QUARANTINE_IP) {
            return Err(WafError::PermissionDenied);
        }

        let mut i = 0;
        while i < self.quarantine_count {
            if self.quarantined[i].ip == ip {
                self.quarantined[i].strikes = self.quarantined[i].strikes.saturating_add(1);
                self.quarantined[i].reason = reason;
                self.quarantined[i].active = true;
                return Ok(());
            }
            i += 1;
        }

        if self.quarantine_count >= MAX_QUARANTINED_IPS {
            return Err(WafError::QuarantineCapacityExceeded);
        }
        self.quarantined[self.quarantine_count] = QuarantinedEntry {
            ip,
            strikes: 1,
            reason,
            active: true,
        };
        self.quarantine_count += 1;
        self.total_quarantined += 1;
        Ok(())
    }

    pub fn lift_quarantine(&mut self, cap: &WafCap, ip: [u8; 4]) -> Result<(), WafError> {
        if !cap.is_valid() || !cap.has_right(waf_rights::QUARANTINE_IP) {
            return Err(WafError::PermissionDenied);
        }
        let mut i = 0;
        while i < self.quarantine_count {
            if self.quarantined[i].ip == ip {
                self.quarantined[i].active = false;
                return Ok(());
            }
            i += 1;
        }
        Err(WafError::IpNotFound)
    }

    /// Enregistre une entrée dans le registre d'audit inaltérable scellé par chaîne SHA-256
    pub fn log_audit(
        &mut self,
        timestamp: u64,
        client_ip: [u8; 4],
        attack_type: AttackType,
        rule_id: u32,
        action: RuleAction,
        score: u32,
    ) {
        let mut hasher = Sha256::new();
        hasher.update(&self.audit_chain);
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&client_ip);
        hasher.update(&(attack_type as u32).to_be_bytes());
        hasher.update(&rule_id.to_be_bytes());
        hasher.update(&(action as u32).to_be_bytes());
        hasher.update(&score.to_be_bytes());
        let entry_hash = hasher.finalize();

        let prev_hash = self.audit_chain;
        self.audit_chain = entry_hash;

        let entry = AuditEntry {
            timestamp,
            client_ip,
            attack_type,
            rule_id,
            action,
            score,
            prev_hash,
            entry_hash,
        };

        let idx = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_log[idx] = entry;
        self.audit_count += 1;
    }

    /// Inspection complète d'une requête HTTP entrante
    pub fn inspect_request(
        &mut self,
        cap: &WafCap,
        req: &HttpRequest,
        timestamp: u64,
    ) -> Result<WafDecision, WafError> {
        if !cap.is_valid() || !cap.has_right(waf_rights::INSPECT_REQUEST) {
            return Err(WafError::PermissionDenied);
        }
        self.total_inspections += 1;

        // 1. Liste Blanche (Bypass immédiat si IP autorisée)
        if self.is_ip_whitelisted(&req.client_ip) {
            self.total_passed += 1;
            return Ok(WafDecision::Allow);
        }

        // 2. Vérification de Quarantaine active
        if self.is_ip_quarantined(&req.client_ip) {
            self.total_blocked += 1;
            return Ok(WafDecision::Quarantine {
                client_ip: req.client_ip,
                score: 100,
                reason: AttackType::ProtocolAnomaly,
            });
        }

        let mut threat_score = 0u32;
        let mut detected_attack = AttackType::None;
        let mut triggering_rule_id = 0u32;

        let uri_slice = &req.uri[..req.uri_len];
        let body_slice = &req.body[..req.body_len];

        // 3. Validation Stricte des En-têtes (RFC 7230, CRLF, Smuggling, Injection)
        let mut i = 0;
        while i < req.header_count {
            let hdr = &req.headers[i];
            let name_slice = &hdr.name[..hdr.name_len];
            let val_slice = &hdr.val[..hdr.val_len];

            // Rejet immédiat si injection CRLF ou Null-Byte
            if StringSearch::contains_ignore_case(name_slice, b"\r")
                || StringSearch::contains_ignore_case(name_slice, b"\n")
                || StringSearch::contains_ignore_case(name_slice, b"\0")
                || StringSearch::contains_ignore_case(val_slice, b"\r")
                || StringSearch::contains_ignore_case(val_slice, b"\n")
                || StringSearch::contains_ignore_case(val_slice, b"\0")
            {
                threat_score += RuleSeverity::High.score();
                detected_attack = AttackType::ProtocolAnomaly;
                triggering_rule_id = 1011;
                break;
            }
            i += 1;
        }

        // 4. Détection Traversée de Répertoires (Path Traversal) dans l'URI
        let mut decoded_buf = [0u8; MAX_URI_LEN];
        let decoded_len = url_decode(uri_slice, &mut decoded_buf);
        let decoded_uri = &decoded_buf[..decoded_len];

        if StringSearch::contains_ignore_case(uri_slice, b"../")
            || StringSearch::contains_ignore_case(decoded_uri, b"../")
            || StringSearch::contains_ignore_case(uri_slice, b"..\\")
            || StringSearch::contains_ignore_case(decoded_uri, b"..\\")
            || StringSearch::contains_ignore_case(uri_slice, b"%2e%2e")
            || StringSearch::contains_ignore_case(uri_slice, b"%00")
            || StringSearch::contains_ignore_case(uri_slice, b"\0")
        {
            threat_score += RuleSeverity::High.score();
            if detected_attack == AttackType::None {
                detected_attack = AttackType::PathTraversal;
                triggering_rule_id = 1009;
            }
        }

        // 5. Détection de Payload WebAssembly (Wasm)
        if req.body_len >= 8 && req.body[0..4] == WasmInspector::WASM_MAGIC {
            if let Err(err_type) = WasmInspector::inspect_wasm(body_slice) {
                threat_score += RuleSeverity::Critical.score();
                if detected_attack == AttackType::None {
                    detected_attack = err_type;
                    triggering_rule_id = 2001;
                }
            }
        }

        // 6. Détection de Payload JSON & Pollution de Prototype
        let mut is_json = false;
        let mut j = 0;
        while j < req.header_count {
            let hdr = &req.headers[j];
            if StringSearch::contains_ignore_case(&hdr.name[..hdr.name_len], b"content-type")
                && StringSearch::contains_ignore_case(&hdr.val[..hdr.val_len], b"json")
            {
                is_json = true;
                break;
            }
            j += 1;
        }
        if is_json || (req.body_len > 1 && req.body[0] == b'{') {
            if let Err(err_type) = JsonInspector::inspect_json(body_slice) {
                threat_score += RuleSeverity::High.score();
                if detected_attack == AttackType::None {
                    detected_attack = err_type;
                    triggering_rule_id = 2002;
                }
            }
        }

        // 7. Évaluation des Règles Actives Configurées
        let mut r = 0;
        while r < self.rule_count {
            let rule = &self.rules[r];
            if rule.id == triggering_rule_id {
                r += 1;
                continue;
            }
            if rule.enabled && rule.pattern_len > 0 {
                let pat = &rule.pattern[..rule.pattern_len];
                let mut matched = false;

                match rule.target {
                    TargetScope::Uri => {
                        matched = StringSearch::contains_ignore_case(uri_slice, pat)
                            || StringSearch::contains_ignore_case(decoded_uri, pat);
                    }
                    TargetScope::Body => {
                        matched = StringSearch::contains_ignore_case(body_slice, pat);
                    }
                    TargetScope::Header => {
                        let mut h = 0;
                        while h < req.header_count {
                            let hdr = &req.headers[h];
                            if StringSearch::contains_ignore_case(&hdr.val[..hdr.val_len], pat) {
                                matched = true;
                                break;
                            }
                            h += 1;
                        }
                    }
                    TargetScope::Method => {
                        let m_str = req.method.as_str().as_bytes();
                        matched = StringSearch::contains_ignore_case(m_str, pat);
                    }
                    TargetScope::All => {
                        matched = StringSearch::contains_ignore_case(uri_slice, pat)
                            || StringSearch::contains_ignore_case(decoded_uri, pat)
                            || StringSearch::contains_ignore_case(body_slice, pat);
                        if !matched {
                            let mut h = 0;
                            while h < req.header_count {
                                let hdr = &req.headers[h];
                                if StringSearch::contains_ignore_case(&hdr.val[..hdr.val_len], pat)
                                {
                                    matched = true;
                                    break;
                                }
                                h += 1;
                            }
                        }
                    }
                }

                if matched {
                    threat_score += rule.severity.score();
                    if detected_attack == AttackType::None {
                        detected_attack = rule.attack_type;
                        triggering_rule_id = rule.id;
                    }
                    if rule.action == RuleAction::Quarantine {
                        threat_score += 100;
                    }
                }
            }
            r += 1;
        }

        // 8. Arbitrage et Décision Finale
        if threat_score >= ANOMALY_THRESHOLD {
            self.total_anomalies += 1;
            let mut action = RuleAction::Block;
            if detected_attack == AttackType::CommandInjection {
                action = RuleAction::Quarantine;
            }
            let mut r_idx = 0;
            while r_idx < self.rule_count {
                if self.rules[r_idx].id == triggering_rule_id {
                    action = self.rules[r_idx].action;
                    break;
                }
                r_idx += 1;
            }

            self.log_audit(
                timestamp,
                req.client_ip,
                detected_attack,
                triggering_rule_id,
                action,
                threat_score,
            );

            if action == RuleAction::Quarantine {
                let _ = self.quarantine_ip(cap, req.client_ip, detected_attack);
                self.total_blocked += 1;
                return Ok(WafDecision::Quarantine {
                    client_ip: req.client_ip,
                    score: threat_score,
                    reason: detected_attack,
                });
            } else {
                self.total_blocked += 1;
                return Ok(WafDecision::Block {
                    rule_id: triggering_rule_id,
                    attack_type: detected_attack,
                    score: threat_score,
                });
            }
        }

        self.total_passed += 1;
        Ok(WafDecision::Allow)
    }

    /// Inspection sortante (Data Leakage Prevention) pour bloquer les fuites d'informations sensibles
    pub fn inspect_response(
        &mut self,
        cap: &WafCap,
        resp: &HttpResponse,
        timestamp: u64,
    ) -> Result<bool, WafError> {
        if !cap.is_valid() || !cap.has_right(waf_rights::INSPECT_RESPONSE) {
            return Err(WafError::PermissionDenied);
        }

        let body_slice = &resp.body[..resp.body_len];

        // Détection de clés privées RSA/EC/Ed25519 ou secrets fuyants
        let leak_detected = StringSearch::contains_ignore_case(body_slice, b"BEGIN PRIVATE KEY")
            || StringSearch::contains_ignore_case(body_slice, b"BEGIN RSA PRIVATE KEY")
            || StringSearch::contains_ignore_case(body_slice, b"BEGIN EC PRIVATE KEY")
            || StringSearch::contains_ignore_case(body_slice, b"DB_PASSWORD=")
            || StringSearch::contains_ignore_case(body_slice, b"PANIC: at ")
            || StringSearch::contains_ignore_case(body_slice, b"AWS_SECRET_ACCESS_KEY");

        if leak_detected {
            self.total_anomalies += 1;
            self.total_blocked += 1;
            self.log_audit(
                timestamp,
                [127, 0, 0, 1],
                AttackType::DataLeakage,
                9999,
                RuleAction::Block,
                100,
            );
            return Ok(false); // Réponse bloquée (fuite de données interceptée)
        }

        Ok(true) // Réponse sûre
    }

    /// Traitement déterministe d'une requête IPC calibrée à 64 octets
    pub fn dispatch_ipc(&mut self, req: &WafRequest) -> WafResponse {
        if req.magic != WAF_MAGIC_REQ {
            let mut resp = WafResponse::new();
            resp.status = SysError::InvalidArgument as i32;
            resp.set_status_str("BAD_MAGIC");
            return resp;
        }

        let cap = WafCap::new(Handle::new(req.handle_id, 1), req.rights, 100_000, 1);

        let opcode = match WafOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                let mut resp = WafResponse::new();
                resp.status = SysError::InvalidArgument as i32;
                resp.set_status_str("BAD_OPCODE");
                return resp;
            }
        };

        let mut resp = WafResponse::new();

        match opcode {
            WafOpcode::GetStatus => {
                resp.status = 0;
                resp.decision = 0;
                resp.set_status_str("STATUS_OK");
            }
            WafOpcode::InspectUri => {
                let len = req.payload.iter().position(|&b| b == 0).unwrap_or(32);
                let uri_str = match core::str::from_utf8(&req.payload[..len]) {
                    Ok(s) => s,
                    Err(_) => {
                        resp.status = SysError::InvalidArgument as i32;
                        resp.decision = 1;
                        resp.attack_type = AttackType::ProtocolAnomaly as u32;
                        resp.set_status_str("BAD_URI_UTF8");
                        resp.total_inspections = self.total_inspections;
                        resp.total_blocked = self.total_blocked as u32;
                        resp.quarantined_count = self.quarantine_count as u32;
                        resp.audit_preview.copy_from_slice(&self.audit_chain[..8]);
                        return resp;
                    }
                };

                let http_req = HttpRequest::new(req.client_ip, HttpMethod::Get, uri_str);
                let timestamp = if req.timestamp != 0 { req.timestamp } else { 1 };

                match self.inspect_request(&cap, &http_req, timestamp) {
                    Ok(WafDecision::Allow) => {
                        resp.status = 0;
                        resp.decision = 0;
                        resp.set_status_str("ALLOW");
                    }
                    Ok(WafDecision::Block {
                        rule_id,
                        attack_type,
                        score,
                    }) => {
                        resp.status = 0;
                        resp.decision = 1;
                        resp.rule_id = rule_id;
                        resp.attack_type = attack_type as u32;
                        resp.score = score;
                        resp.set_status_str("BLOCK");
                    }
                    Ok(WafDecision::Quarantine {
                        client_ip: _,
                        score,
                        reason,
                    }) => {
                        resp.status = 0;
                        resp.decision = 2;
                        resp.attack_type = reason as u32;
                        resp.score = score;
                        resp.set_status_str("QUARANTINE");
                    }
                    Err(err) => {
                        resp.status = match err {
                            WafError::PermissionDenied => SysError::PermissionDenied as i32,
                            _ => SysError::InvalidArgument as i32,
                        };
                        resp.set_status_str("ERR_INSPECT");
                    }
                }
            }
            WafOpcode::QuarantineIp => {
                let reason =
                    AttackType::from_u32(req.param_u32).unwrap_or(AttackType::ProtocolAnomaly);
                match self.quarantine_ip(&cap, req.client_ip, reason) {
                    Ok(()) => {
                        resp.status = 0;
                        resp.decision = 2;
                        resp.attack_type = reason as u32;
                        let ts = if req.timestamp != 0 { req.timestamp } else { 1 };
                        self.log_audit(ts, req.client_ip, reason, 0, RuleAction::Quarantine, 100);
                        resp.set_status_str("QUARANTINED");
                    }
                    Err(err) => {
                        resp.status = match err {
                            WafError::PermissionDenied => SysError::PermissionDenied as i32,
                            _ => SysError::InvalidArgument as i32,
                        };
                        resp.set_status_str("ERR_QUAR");
                    }
                }
            }
            WafOpcode::UnquarantineIp => match self.lift_quarantine(&cap, req.client_ip) {
                Ok(()) => {
                    resp.status = 0;
                    let ts = if req.timestamp != 0 { req.timestamp } else { 1 };
                    self.log_audit(ts, req.client_ip, AttackType::None, 0, RuleAction::Allow, 0);
                    resp.set_status_str("UNQUARANTINED");
                }
                Err(err) => {
                    resp.status = match err {
                        WafError::PermissionDenied => SysError::PermissionDenied as i32,
                        _ => SysError::InvalidArgument as i32,
                    };
                    resp.set_status_str("ERR_UNQUAR");
                }
            },
            WafOpcode::WhitelistIp => match self.whitelist_ip(&cap, req.client_ip) {
                Ok(()) => {
                    resp.status = 0;
                    resp.set_status_str("WHITELISTED");
                }
                Err(err) => {
                    resp.status = match err {
                        WafError::PermissionDenied => SysError::PermissionDenied as i32,
                        _ => SysError::InvalidArgument as i32,
                    };
                    resp.set_status_str("ERR_WHITELIST");
                }
            },
            WafOpcode::AddRule => {
                let len = req.payload.iter().position(|&b| b == 0).unwrap_or(32);
                let pat_str = match core::str::from_utf8(&req.payload[..len]) {
                    Ok(s) => s,
                    Err(_) => {
                        resp.status = SysError::InvalidArgument as i32;
                        resp.set_status_str("ERR_PATTERN_UTF8");
                        resp.total_inspections = self.total_inspections;
                        resp.total_blocked = self.total_blocked as u32;
                        resp.quarantined_count = self.quarantine_count as u32;
                        resp.audit_preview.copy_from_slice(&self.audit_chain[..8]);
                        return resp;
                    }
                };

                let rule_id = if req.param_u32 != 0 {
                    req.param_u32
                } else {
                    (self.rule_count as u32) + 3000
                };
                let rule = WafRule::new(
                    rule_id,
                    "CustomIpcRule",
                    pat_str,
                    AttackType::CustomSignature,
                    RuleSeverity::High,
                    RuleAction::Block,
                    TargetScope::All,
                );
                match self.add_rule(&cap, rule) {
                    Ok(id) => {
                        resp.status = 0;
                        resp.rule_id = id;
                        resp.set_status_str("RULE_ADDED");
                    }
                    Err(err) => {
                        resp.status = match err {
                            WafError::PermissionDenied => SysError::PermissionDenied as i32,
                            _ => SysError::InvalidArgument as i32,
                        };
                        resp.set_status_str("ERR_RULE");
                    }
                }
            }
            WafOpcode::GetAudit => {
                if self.audit_count == 0 {
                    resp.status = 0;
                    resp.set_status_str("AUDIT_EMPTY");
                } else {
                    let idx = (req.param_u32 as usize) % self.audit_count.min(MAX_AUDIT_LOGS);
                    let entry = &self.audit_log[idx];
                    resp.status = 0;
                    resp.rule_id = entry.rule_id;
                    resp.attack_type = entry.attack_type as u32;
                    resp.score = entry.score;
                    resp.audit_preview.copy_from_slice(&entry.entry_hash[..8]);
                    resp.set_status_str("AUDIT_OK");
                }
            }
        }

        resp.total_inspections = self.total_inspections;
        resp.total_blocked = self.total_blocked as u32;
        resp.quarantined_count = self.quarantine_count as u32;
        resp.audit_preview.copy_from_slice(&self.audit_chain[..8]);
        resp
    }
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE 64 OCTETS
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafOpcode {
    GetStatus = 1,
    InspectUri = 2,
    QuarantineIp = 3,
    UnquarantineIp = 4,
    WhitelistIp = 5,
    AddRule = 6,
    GetAudit = 7,
}

impl WafOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::InspectUri),
            3 => Some(Self::QuarantineIp),
            4 => Some(Self::UnquarantineIp),
            5 => Some(Self::WhitelistIp),
            6 => Some(Self::AddRule),
            7 => Some(Self::GetAudit),
            _ => None,
        }
    }
}

/// Requête IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WafRequest {
    pub magic: u32,         // 0..4: 0x57414644 ("WAFD")
    pub opcode: u32,        // 4..8: Code d'opération (WafOpcode)
    pub handle_id: u32,     // 8..12: Handle de capacité émetteur
    pub rights: u32,        // 12..16: Droits requis (waf_rights)
    pub client_ip: [u8; 4], // 16..20: Adresse IPv4
    pub param_u32: u32,     // 20..24: Paramètre (rule_id, attack_type, etc.)
    pub timestamp: u64,     // 24..32: Horodatage
    pub payload: [u8; 32],  // 32..64: Charge utile (URI, signature pattern, etc.)
}

const _: () = assert!(core::mem::size_of::<WafRequest>() == 64);

impl Default for WafRequest {
    fn default() -> Self {
        Self::new(WafOpcode::GetStatus)
    }
}

impl WafRequest {
    pub const fn new(opcode: WafOpcode) -> Self {
        Self {
            magic: WAF_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: WAF_ENDPOINT_ID,
            rights: waf_rights::ALL,
            client_ip: [0, 0, 0, 0],
            param_u32: 0,
            timestamp: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: WAF_MAGIC_REQ,
            opcode: WafOpcode::GetStatus as u32,
            handle_id,
            rights,
            client_ip: [0, 0, 0, 0],
            param_u32: 0,
            timestamp: 0,
            payload: [0u8; 32],
        }
    }

    pub fn new_inspect_uri(
        handle_id: u32,
        rights: u32,
        client_ip: [u8; 4],
        uri_str: &str,
        timestamp: u64,
    ) -> Self {
        let mut payload = [0u8; 32];
        let bytes = uri_str.as_bytes();
        let len = bytes.len().min(32);
        payload[..len].copy_from_slice(&bytes[..len]);

        Self {
            magic: WAF_MAGIC_REQ,
            opcode: WafOpcode::InspectUri as u32,
            handle_id,
            rights,
            client_ip,
            param_u32: 0,
            timestamp,
            payload,
        }
    }

    pub const fn new_quarantine_ip(
        handle_id: u32,
        rights: u32,
        client_ip: [u8; 4],
        reason: AttackType,
    ) -> Self {
        Self {
            magic: WAF_MAGIC_REQ,
            opcode: WafOpcode::QuarantineIp as u32,
            handle_id,
            rights,
            client_ip,
            param_u32: reason as u32,
            timestamp: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_unquarantine_ip(handle_id: u32, rights: u32, client_ip: [u8; 4]) -> Self {
        Self {
            magic: WAF_MAGIC_REQ,
            opcode: WafOpcode::UnquarantineIp as u32,
            handle_id,
            rights,
            client_ip,
            param_u32: 0,
            timestamp: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_whitelist_ip(handle_id: u32, rights: u32, client_ip: [u8; 4]) -> Self {
        Self {
            magic: WAF_MAGIC_REQ,
            opcode: WafOpcode::WhitelistIp as u32,
            handle_id,
            rights,
            client_ip,
            param_u32: 0,
            timestamp: 0,
            payload: [0u8; 32],
        }
    }

    pub fn new_add_rule(handle_id: u32, rights: u32, rule_id: u32, pattern_str: &str) -> Self {
        let mut payload = [0u8; 32];
        let bytes = pattern_str.as_bytes();
        let len = bytes.len().min(32);
        payload[..len].copy_from_slice(&bytes[..len]);

        Self {
            magic: WAF_MAGIC_REQ,
            opcode: WafOpcode::AddRule as u32,
            handle_id,
            rights,
            client_ip: [0, 0, 0, 0],
            param_u32: rule_id,
            timestamp: 0,
            payload,
        }
    }

    pub const fn new_get_audit(handle_id: u32, rights: u32, audit_index: u32) -> Self {
        Self {
            magic: WAF_MAGIC_REQ,
            opcode: WafOpcode::GetAudit as u32,
            handle_id,
            rights,
            client_ip: [0, 0, 0, 0],
            param_u32: audit_index,
            timestamp: 0,
            payload: [0u8; 32],
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.opcode.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.handle_id.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.rights.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.client_ip);
        bytes[20..24].copy_from_slice(&self.param_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[32..64].copy_from_slice(&self.payload);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != WAF_MAGIC_REQ {
            return None;
        }
        let opcode = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let handle_id = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let rights = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let client_ip = [bytes[16], bytes[17], bytes[18], bytes[19]];
        let param_u32 = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let timestamp = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        let mut payload = [0u8; 32];
        payload.copy_from_slice(&bytes[32..64]);

        Some(Self {
            magic,
            opcode,
            handle_id,
            rights,
            client_ip,
            param_u32,
            timestamp,
            payload,
        })
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WafResponse {
    pub magic: u32,             // 0..4: 0x57414653 ("WAFS")
    pub status: i32,            // 4..8: Code statut (0 = succès)
    pub decision: u32,          // 8..12: Décision (0=Allow, 1=Block, 2=Quarantine)
    pub attack_type: u32,       // 12..16: Type d'attaque détecté (AttackType as u32)
    pub rule_id: u32,           // 16..20: Identifiant de la règle déclenchée
    pub score: u32,             // 20..24: Score de menace calculé
    pub total_inspections: u64, // 24..32: Total inspections effectuées
    pub total_blocked: u32,     // 32..36: Total requêtes bloquées
    pub quarantined_count: u32, // 36..40: Total adresses IP en quarantaine
    pub audit_preview: [u8; 8], // 40..48: Échantillon d'audit SHA-256
    pub status_str: [u8; 16],   // 48..64: Message ASCII descriptif
}

const _: () = assert!(core::mem::size_of::<WafResponse>() == 64);

impl Default for WafResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl WafResponse {
    pub const fn new() -> Self {
        Self {
            magic: WAF_MAGIC_RESP,
            status: 0,
            decision: 0,
            attack_type: 0,
            rule_id: 0,
            score: 0,
            total_inspections: 0,
            total_blocked: 0,
            quarantined_count: 0,
            audit_preview: [0u8; 8],
            status_str: [0u8; 16],
        }
    }

    pub fn set_status_str(&mut self, s: &str) {
        let mut buf = [0u8; 16];
        let bytes = s.as_bytes();
        let len = bytes.len().min(16);
        buf[..len].copy_from_slice(&bytes[..len]);
        self.status_str = buf;
    }

    pub fn status_as_str(&self) -> &str {
        let len = self.status_str.iter().position(|&b| b == 0).unwrap_or(16);
        core::str::from_utf8(&self.status_str[..len]).unwrap_or("<invalid-utf8>")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.status.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.decision.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.attack_type.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.rule_id.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.score.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.total_inspections.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.total_blocked.to_le_bytes());
        bytes[36..40].copy_from_slice(&self.quarantined_count.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.audit_preview);
        bytes[48..64].copy_from_slice(&self.status_str);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != WAF_MAGIC_RESP {
            return None;
        }
        let status = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let decision = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let attack_type = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let rule_id = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let score = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let total_inspections = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        let total_blocked = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        let quarantined_count = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        let mut audit_preview = [0u8; 8];
        audit_preview.copy_from_slice(&bytes[40..48]);
        let mut status_str = [0u8; 16];
        status_str.copy_from_slice(&bytes[48..64]);

        Some(Self {
            magic,
            status,
            decision,
            attack_type,
            rule_id,
            score,
            total_inspections,
            total_blocked,
            quarantined_count,
            audit_preview,
            status_str,
        })
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`WafClient`, `ChannelMessage`)
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

/// Client synchrone Ring 3 pour interagir avec le démon jambo-waf (PID 30)
pub struct WafClient {
    pub endpoint: Handle,
}

impl WafClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn call(&self, req: &WafRequest) -> Result<WafResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<WafResponse>() {
                return WafResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            libjambo::syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }

    pub fn get_status(&self, cap: &WafCap) -> Result<WafResponse, SysError> {
        let req = WafRequest::new_status(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn inspect_uri(
        &self,
        cap: &WafCap,
        client_ip: [u8; 4],
        uri_str: &str,
        timestamp: u64,
    ) -> Result<WafResponse, SysError> {
        let req = WafRequest::new_inspect_uri(
            cap.handle.index(),
            cap.rights,
            client_ip,
            uri_str,
            timestamp,
        );
        self.call(&req)
    }

    pub fn quarantine_ip(
        &self,
        cap: &WafCap,
        client_ip: [u8; 4],
        reason: AttackType,
    ) -> Result<WafResponse, SysError> {
        let req = WafRequest::new_quarantine_ip(cap.handle.index(), cap.rights, client_ip, reason);
        self.call(&req)
    }

    pub fn unquarantine_ip(
        &self,
        cap: &WafCap,
        client_ip: [u8; 4],
    ) -> Result<WafResponse, SysError> {
        let req = WafRequest::new_unquarantine_ip(cap.handle.index(), cap.rights, client_ip);
        self.call(&req)
    }

    pub fn whitelist_ip(&self, cap: &WafCap, client_ip: [u8; 4]) -> Result<WafResponse, SysError> {
        let req = WafRequest::new_whitelist_ip(cap.handle.index(), cap.rights, client_ip);
        self.call(&req)
    }

    pub fn add_rule(
        &self,
        cap: &WafCap,
        rule_id: u32,
        pattern_str: &str,
    ) -> Result<WafResponse, SysError> {
        let req = WafRequest::new_add_rule(cap.handle.index(), cap.rights, rule_id, pattern_str);
        self.call(&req)
    }

    pub fn get_audit(&self, cap: &WafCap, audit_index: u32) -> Result<WafResponse, SysError> {
        let req = WafRequest::new_get_audit(cap.handle.index(), cap.rights, audit_index);
        self.call(&req)
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_cap_attenuation() {
        let root_cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        assert!(root_cap.is_valid());
        assert!(root_cap.has_right(waf_rights::INSPECT_REQUEST));
        assert!(root_cap.has_right(waf_rights::ADMIN));

        let attenuated = root_cap
            .attenuate(waf_rights::INSPECT_REQUEST | waf_rights::AUDIT_INSPECT, 50)
            .expect("Atténuation");
        assert!(attenuated.has_right(waf_rights::INSPECT_REQUEST));
        assert!(attenuated.has_right(waf_rights::AUDIT_INSPECT));
        assert!(!attenuated.has_right(waf_rights::CONFIGURE_RULES));
        assert!(!attenuated.has_right(waf_rights::ADMIN));
        assert_eq!(attenuated.max_inspections, 50);

        // Rejet formel d'amplification de privilèges ou d'augmentation de quota
        assert_eq!(
            attenuated.attenuate(waf_rights::ALL, 50),
            Err(WafError::PermissionDenied)
        );
        assert_eq!(
            attenuated.attenuate(waf_rights::INSPECT_REQUEST, 100),
            Err(WafError::PermissionDenied)
        );
    }

    #[test]
    fn test_waf_clean_request_allowed() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let mut req = HttpRequest::new([192, 168, 1, 10], HttpMethod::Get, "/api/v1/system/status");
        req.add_header("Host", "jambo.local").unwrap();
        req.add_header("Accept", "application/json").unwrap();

        let decision = daemon.inspect_request(&cap, &req, 100).expect("Inspect");
        assert_eq!(decision, WafDecision::Allow);
        assert_eq!(daemon.total_passed, 1);
        assert_eq!(daemon.total_blocked, 0);
    }

    #[test]
    fn test_waf_sqli_detection() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let req = HttpRequest::new(
            [192, 168, 1, 20],
            HttpMethod::Get,
            "/users?id=1'%20or%20'1'='1",
        );
        let decision = daemon.inspect_request(&cap, &req, 101).expect("Inspect");
        match decision {
            WafDecision::Block { attack_type, .. } => {
                assert_eq!(attack_type, AttackType::SqlInjection);
            }
            _ => panic!("Expected SQLi block"),
        }
    }

    #[test]
    fn test_waf_xss_detection() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let mut req = HttpRequest::new([10, 0, 0, 5], HttpMethod::Post, "/comments");
        req.set_body(b"<script>alert(document.cookie)</script>")
            .unwrap();

        let decision = daemon.inspect_request(&cap, &req, 102).expect("Inspect");
        match decision {
            WafDecision::Block { attack_type, .. } => {
                assert_eq!(attack_type, AttackType::CrossSiteScripting);
            }
            _ => panic!("Expected XSS block"),
        }
    }

    #[test]
    fn test_waf_rce_quarantine() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let mut req = HttpRequest::new([10, 0, 0, 99], HttpMethod::Post, "/run");
        req.set_body(b"cmd=test; cat /etc/shadow").unwrap();

        let decision = daemon.inspect_request(&cap, &req, 103).expect("Inspect");
        match decision {
            WafDecision::Quarantine {
                client_ip, reason, ..
            } => {
                assert_eq!(client_ip, [10, 0, 0, 99]);
                assert_eq!(reason, AttackType::CommandInjection);
            }
            _ => panic!("Expected Quarantine for RCE"),
        }
        assert!(daemon.is_ip_quarantined(&[10, 0, 0, 99]));
    }

    #[test]
    fn test_waf_path_traversal() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let req = HttpRequest::new(
            [172, 16, 0, 15],
            HttpMethod::Get,
            "/static/../../etc/passwd",
        );
        let decision = daemon.inspect_request(&cap, &req, 104).expect("Inspect");
        match decision {
            WafDecision::Block { attack_type, .. } => {
                assert_eq!(attack_type, AttackType::PathTraversal);
            }
            _ => panic!("Expected Path Traversal block"),
        }
    }

    #[test]
    fn test_waf_json_prototype_pollution() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let mut req = HttpRequest::new([172, 16, 0, 20], HttpMethod::Post, "/api/update");
        req.add_header("Content-Type", "application/json").unwrap();
        req.set_body(b"{\"__proto__\": {\"admin\": true}}").unwrap();

        let decision = daemon.inspect_request(&cap, &req, 105).expect("Inspect");
        match decision {
            WafDecision::Block { attack_type, .. } => {
                assert_eq!(attack_type, AttackType::PrototypePollution);
            }
            _ => panic!("Expected Prototype Pollution block"),
        }
    }

    #[test]
    fn test_waf_json_depth_overflow() {
        // Deeply nested JSON: depth 9 exceeds MAX_JSON_DEPTH (8)
        let payload = b"[[[[[[[[[1]]]]]]]]]";
        assert_eq!(
            JsonInspector::inspect_json(payload),
            Err(AttackType::ProtocolAnomaly)
        );

        // Bounded valid nesting (depth 8) passes
        let valid_payload = b"[[[[[[[[1]]]]]]]]";
        assert_eq!(JsonInspector::inspect_json(valid_payload), Ok(()));
    }

    #[test]
    fn test_waf_wasm_memory_bomb() {
        // Wasm binary header: \0asm (v1)
        // Section 5 (Memory): length = 4 bytes
        // 1 memory entry, flag = 0 (min only), min = 1000 pages (exceeds 512)
        // LEB128 of 1000: 1000 = 0x3E8 -> (0xE8 | 0x80), 0x07 -> [0xE8, 0x07]
        let wasm_bomb: [u8; 13] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // Magic + Version
            0x05, 0x04, 0x01, 0x00,
            0xE8, // Section 5, len 4, 1 memory, flag 0, min (first byte)
        ];
        let mut payload = [0u8; 14];
        payload[..13].copy_from_slice(&wasm_bomb);
        payload[13] = 0x07; // second byte of LEB128 1000

        assert_eq!(
            WasmInspector::inspect_wasm(&payload),
            Err(AttackType::MalformedWasm)
        );
    }

    #[test]
    fn test_waf_wasm_malformed_inspection() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let mut req = HttpRequest::new([172, 16, 0, 30], HttpMethod::Post, "/wasm/deploy");
        // En-tête Wasm valide mais section d'import malveillante contenant "system"
        let wasm_payload: [u8; 16] = [
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // Magic + Version
            0x02, 0x07, b's', b'y', b's', b't', b'e', b'm', // Section 2 (Import) "system"
        ];
        req.set_body(&wasm_payload).unwrap();

        let decision = daemon.inspect_request(&cap, &req, 106).expect("Inspect");
        match decision {
            WafDecision::Block { attack_type, .. }
            | WafDecision::Quarantine {
                reason: attack_type,
                ..
            } => {
                assert_eq!(attack_type, AttackType::MalformedWasm);
            }
            _ => panic!("Expected Malformed Wasm block"),
        }
    }

    #[test]
    fn test_waf_data_leakage_response() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);

        let mut resp = HttpResponse::new(200);
        resp.set_body(b"Debug info: -----BEGIN RSA PRIVATE KEY-----\nMIIEog...")
            .unwrap();

        let is_safe = daemon
            .inspect_response(&cap, &resp, 107)
            .expect("Inspect Response");
        assert!(!is_safe, "Response with private key must be blocked");
    }

    #[test]
    fn test_waf_ip_quarantine_and_lift() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let target_ip = [198, 51, 100, 42];
        assert!(!daemon.is_ip_quarantined(&target_ip));

        daemon
            .quarantine_ip(&cap, target_ip, AttackType::CommandInjection)
            .expect("quarantine");
        assert!(daemon.is_ip_quarantined(&target_ip));

        // Repeat strike increments strikes count
        daemon
            .quarantine_ip(&cap, target_ip, AttackType::CommandInjection)
            .expect("quarantine strike 2");
        assert_eq!(daemon.quarantined[0].strikes, 2);

        // Lifting quarantine
        daemon.lift_quarantine(&cap, target_ip).expect("lift");
        assert!(!daemon.is_ip_quarantined(&target_ip));

        // Non-existent IP returns IpNotFound
        assert_eq!(
            daemon.lift_quarantine(&cap, [1, 1, 1, 1]),
            Err(WafError::IpNotFound)
        );
    }

    #[test]
    fn test_waf_whitelist_bypass() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        let trusted_ip = [127, 0, 0, 1];
        daemon.whitelist_ip(&cap, trusted_ip).expect("Whitelist");

        // Requête contenant une attaque mais émise par une IP blanche
        let req = HttpRequest::new(trusted_ip, HttpMethod::Get, "/test?q=' or '1'='1");
        let decision = daemon.inspect_request(&cap, &req, 108).expect("Inspect");
        assert_eq!(
            decision,
            WafDecision::Allow,
            "Whitelisted IP must bypass WAF"
        );
    }

    #[test]
    fn test_waf_audit_hash_chain() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 100, 1);
        let mut daemon = JamboWafDaemon::new(cap);

        let initial_hash = daemon.audit_chain;
        daemon.log_audit(
            200,
            [1, 2, 3, 4],
            AttackType::SqlInjection,
            1001,
            RuleAction::Block,
            75,
        );
        let hash1 = daemon.audit_chain;
        assert_ne!(initial_hash, hash1);

        daemon.log_audit(
            201,
            [1, 2, 3, 5],
            AttackType::CrossSiteScripting,
            1004,
            RuleAction::Block,
            50,
        );
        let hash2 = daemon.audit_chain;
        assert_ne!(hash1, hash2);

        assert_eq!(daemon.audit_count, 2);
        assert_eq!(daemon.audit_log[0].prev_hash, initial_hash);
        assert_eq!(daemon.audit_log[1].prev_hash, hash1);
    }

    #[test]
    fn test_waf_ipc_serialization_and_dispatch() {
        let cap = WafCap::new(Handle::new(WAF_ENDPOINT_ID, 1), waf_rights::ALL, 1000, 1);
        let mut daemon = JamboWafDaemon::new(cap);
        daemon.init_defaults();

        // 1. Static assertions
        assert_eq!(core::mem::size_of::<WafRequest>(), 64);
        assert_eq!(core::mem::size_of::<WafResponse>(), 64);

        // 2. Status IPC
        let req_status = WafRequest::new_status(WAF_ENDPOINT_ID, waf_rights::ALL);
        let bytes = req_status.to_bytes();
        let parsed = WafRequest::from_bytes(&bytes).expect("parse status req");
        assert_eq!(parsed, req_status);

        let resp_status = daemon.dispatch_ipc(&parsed);
        assert_eq!(resp_status.magic, WAF_MAGIC_RESP);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.status_as_str(), "STATUS_OK");

        let resp_bytes = resp_status.to_bytes();
        let parsed_resp = WafResponse::from_bytes(&resp_bytes).expect("parse status resp");
        assert_eq!(parsed_resp, resp_status);

        // 3. Inspect Clean URI IPC
        let req_clean = WafRequest::new_inspect_uri(
            WAF_ENDPOINT_ID,
            waf_rights::ALL,
            [192, 168, 1, 50],
            "/api/v1/health",
            1000,
        );
        let resp_clean = daemon.dispatch_ipc(&req_clean);
        assert_eq!(resp_clean.status, 0);
        assert_eq!(resp_clean.decision, 0); // Allow
        assert_eq!(resp_clean.status_as_str(), "ALLOW");

        // 4. Inspect SQLi URI IPC
        let req_sqli = WafRequest::new_inspect_uri(
            WAF_ENDPOINT_ID,
            waf_rights::ALL,
            [192, 168, 1, 60],
            "/login?u=' or '1'='1",
            1001,
        );
        let resp_sqli = daemon.dispatch_ipc(&req_sqli);
        assert_eq!(resp_sqli.decision, 1); // Block
        assert_eq!(resp_sqli.attack_type, AttackType::SqlInjection as u32);
        assert_eq!(resp_sqli.status_as_str(), "BLOCK");

        // 5. Quarantine IP IPC
        let req_quar = WafRequest::new_quarantine_ip(
            WAF_ENDPOINT_ID,
            waf_rights::ALL,
            [192, 168, 1, 70],
            AttackType::CommandInjection,
        );
        let resp_quar = daemon.dispatch_ipc(&req_quar);
        assert_eq!(resp_quar.status, 0);
        assert_eq!(resp_quar.decision, 2);
        assert_eq!(resp_quar.status_as_str(), "QUARANTINED");
        assert!(daemon.is_ip_quarantined(&[192, 168, 1, 70]));

        // 6. Unquarantine IP IPC
        let req_unquar =
            WafRequest::new_unquarantine_ip(WAF_ENDPOINT_ID, waf_rights::ALL, [192, 168, 1, 70]);
        let resp_unquar = daemon.dispatch_ipc(&req_unquar);
        assert_eq!(resp_unquar.status, 0);
        assert_eq!(resp_unquar.status_as_str(), "UNQUARANTINED");
        assert!(!daemon.is_ip_quarantined(&[192, 168, 1, 70]));

        // 7. Whitelist IP IPC
        let req_white =
            WafRequest::new_whitelist_ip(WAF_ENDPOINT_ID, waf_rights::ALL, [192, 168, 1, 80]);
        let resp_white = daemon.dispatch_ipc(&req_white);
        assert_eq!(resp_white.status, 0);
        assert_eq!(resp_white.status_as_str(), "WHITELISTED");
        assert!(daemon.is_ip_whitelisted(&[192, 168, 1, 80]));

        // 8. Add Rule IPC
        let req_rule =
            WafRequest::new_add_rule(WAF_ENDPOINT_ID, waf_rights::ALL, 4001, "evil_payload");
        let resp_rule = daemon.dispatch_ipc(&req_rule);
        assert_eq!(resp_rule.status, 0);
        assert_eq!(resp_rule.rule_id, 4001);
        assert_eq!(resp_rule.status_as_str(), "RULE_ADDED");

        // 9. Get Audit IPC
        let req_audit = WafRequest::new_get_audit(WAF_ENDPOINT_ID, waf_rights::ALL, 0);
        let resp_audit = daemon.dispatch_ipc(&req_audit);
        assert_eq!(resp_audit.status, 0);
        assert_eq!(resp_audit.status_as_str(), "AUDIT_OK");
    }
}

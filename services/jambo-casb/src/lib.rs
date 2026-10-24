//! Courtier d'Accès Sécurisé Cloud Souverain (CASB) & Passerelle DLP d'Enclave
//!
//! Phase 154 — Jalon v0.3.21
//!
//! Fournit un système souverain Cloud Access Security Broker (CASB) et passerelle DLP d'enclave `#![no_std]` :
//! 1. Courtage d'admission et passerelle mandataire inverse d'admission inter-services & cloud souverain.
//! 2. Gestion de conformité multi-locataires (tenants) par compartimentage étanche, niveaux de conformité (SecNumCloud, SovereignDefense, etc.) et géo-fencing souverain.
//! 3. Interception et courtage des flux d'enclaves matérielles TEE (Intel SGX, AMD SEV-SNP, ARM CCA, Sovereign JamboEnclave).
//! 4. Inspection profonde L7 sans rupture de chiffrement souverain (Sovereign Blind Inspection) via enveloppes d'attestation et scellements cryptographiques déterministes.
//! 5. Moteur autonome de prévention des fuites de données (DLP) hybride :
//!    - Détection de numéros de cartes de paiement avec vérification de Luhn.
//!    - Détection de clés cryptographiques, secrets d'API, clés privées PEM.
//!    - Détection de secrets d'enclaves TEE (SEV-SNP VMPCKs, SGX Sealing Keys, Master Seeds, parts ML-KEM/PQC).
//!    - Détection de marqueurs de classification souveraine et identifiants PII/fiscaux.
//!    - Détection d'exfiltration et stéganographie sur buffers d'egress d'enclave (analyse d'entropie).
//! 6. Actions DLP en temps réel : Allow, Redact (masquage `*`), Block, QuarantineTenant, IsolateEnclave.
//! 7. Contrôle d'accès capabilaire (`CasbCap`) sans autorité ambiante avec atténuation monotone stricte.
//! 8. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256 déterministe.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation déterministe et autonome de SHA-256 pour micro-noyau et services
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

    fn transform_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
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

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes += data.len() as u64;
        let mut offset = 0;
        while offset < data.len() {
            let space = 64 - self.buffer_len;
            let chunk = (data.len() - offset).min(space);
            self.buffer[self.buffer_len..self.buffer_len + chunk]
                .copy_from_slice(&data[offset..offset + chunk]);
            self.buffer_len += chunk;
            offset += chunk;
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.transform_block(&block);
                self.buffer_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.transform_block(&block);
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.transform_block(&block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// CALCULATEUR D'ENTROPIE ENTIÈRE (#![no_std])
// ============================================================================

/// Calcule une approximation déterministe de l'entropie de Shannon en milli-bits (0..8000)
pub fn calculate_entropy_millibits(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as u32;
    let mut entropy_milli: u32 = 0;
    for &count in freq.iter() {
        if count > 0 {
            let log2_ratio = integer_log2_milli(n) - integer_log2_milli(count);
            entropy_milli = entropy_milli.saturating_add((count * log2_ratio) / n);
        }
    }
    entropy_milli
}

fn integer_log2_milli(val: u32) -> u32 {
    if val <= 1 {
        return 0;
    }
    let leading_zeros = val.leading_zeros();
    let int_part = (31 - leading_zeros) as u32;
    let lower = 1u32 << int_part;
    let fraction = ((val - lower) * 1000) / lower;
    (int_part * 1000).saturating_add(fraction)
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (CasbCap)
// ============================================================================

pub mod casb_rights {
    pub const INSPECT_TRAFFIC: u32 = 0x0001;
    pub const ENFORCE_DLP: u32 = 0x0002;
    pub const MANAGE_TENANTS: u32 = 0x0004;
    pub const CONFIGURE_POLICIES: u32 = 0x0008;
    pub const QUARANTINE_ACTION: u32 = 0x0010;
    pub const AUDIT_READ: u32 = 0x0020;
    pub const SEAL_LEDGER: u32 = 0x0040;
    pub const INTERCEPT_ENCLAVE: u32 = 0x0080;
    pub const BLIND_INSPECT: u32 = 0x0100;
    pub const MANAGE_HYBRID_CLOUD: u32 = 0x0200;
    pub const ISOLATE_ENCLAVE: u32 = 0x0400;
    pub const ADMIN: u32 = 0x8000;
    pub const ALL: u32 = 0xFFFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasbError {
    PermissionDenied,
    AttenuationViolation,
    TenantTableFull,
    DlpRuleTableFull,
    AuditLogFull,
    TenantNotFound,
    TenantQuarantined,
    DlpPolicyViolation,
    EncryptionRequired,
    PayloadTooLarge,
    InvalidParameter,
    EnclaveFlowTableFull,
    EnclaveNotFound,
    EnclaveIsolated,
    ZeroEgressViolation,
    GeoFencingViolation,
    AttestationValidationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CasbCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl CasbCap {
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

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        rights_mask: u32,
        lifetime: u64,
        invocations: u32,
    ) -> Result<Self, CasbError> {
        if (rights_mask & !self.rights) != 0 {
            return Err(CasbError::AttenuationViolation);
        }
        if lifetime > self.max_lifetime || invocations > self.invocations_left {
            return Err(CasbError::AttenuationViolation);
        }
        Ok(Self {
            handle: self.handle,
            rights: rights_mask,
            max_lifetime: lifetime,
            invocations_left: invocations,
        })
    }
}

// ============================================================================
// CONFORMITÉ, GÉO-FENCING & MULTI-LOCATAIRES (TENANTS)
// ============================================================================

/// Niveaux de conformité et d'isolation pour les locataires et flux cloud
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceTier {
    Community,
    Enterprise,
    FedRampHigh,
    SovereignDefense,
    SecNumCloudSovereign,
}

impl ComplianceTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Community => "COMMUNITY",
            Self::Enterprise => "ENTERPRISE",
            Self::FedRampHigh => "FEDRAMP_HIGH",
            Self::SovereignDefense => "SOVEREIGN_DEFENSE",
            Self::SecNumCloudSovereign => "SECNUMCLOUD_SOVEREIGN",
        }
    }
}

/// Zones géopolitiques souveraines pour le géo-fencing cloud
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoZone {
    SovereignSoil,
    EuropeanUnion,
    GlobalAirGapped,
    UntrustedForeign,
}

impl GeoZone {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SovereignSoil => "SOVEREIGN_SOIL",
            Self::EuropeanUnion => "EUROPEAN_UNION",
            Self::GlobalAirGapped => "GLOBAL_AIR_GAPPED",
            Self::UntrustedForeign => "UNTRUSTED_FOREIGN",
        }
    }

    pub fn is_sovereign_compliant(&self) -> bool {
        matches!(
            self,
            Self::SovereignSoil | Self::EuropeanUnion | Self::GlobalAirGapped
        )
    }
}

pub mod data_classes {
    pub const PUBLIC: u8 = 0x01;
    pub const INTERNAL: u8 = 0x02;
    pub const CONFIDENTIAL: u8 = 0x04;
    pub const SECRET: u8 = 0x08;
    pub const PII: u8 = 0x10;
    pub const FINANCIAL_PCI: u8 = 0x20;
    pub const CRYPTO_KEY: u8 = 0x40;
    pub const ENCLAVE_SECRET: u8 = 0x80;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Secret,
    Pii,
    FinancialPci,
    CryptoKey,
    EnclaveSecret,
}

impl DataClassification {
    pub fn bit_mask(&self) -> u8 {
        match self {
            Self::Public => data_classes::PUBLIC,
            Self::Internal => data_classes::INTERNAL,
            Self::Confidential => data_classes::CONFIDENTIAL,
            Self::Secret => data_classes::SECRET,
            Self::Pii => data_classes::PII,
            Self::FinancialPci => data_classes::FINANCIAL_PCI,
            Self::CryptoKey => data_classes::CRYPTO_KEY,
            Self::EnclaveSecret => data_classes::ENCLAVE_SECRET,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::Pii => "PII",
            Self::FinancialPci => "PCI_FINANCIAL",
            Self::CryptoKey => "CRYPTO_KEY",
            Self::EnclaveSecret => "ENCLAVE_SECRET",
        }
    }
}

/// Contexte et profil de sécurité d'un locataire (tenant)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantContext {
    pub tenant_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub tier: ComplianceTier,
    pub allowed_classifications: u8,
    pub require_encryption: bool,
    pub max_payload_bytes: usize,
    pub is_quarantined: bool,
    pub geo_zone: GeoZone,
    pub total_requests: u64,
    pub total_violations: u64,
}

impl TenantContext {
    pub fn new(
        tenant_id: u32,
        name_str: &str,
        tier: ComplianceTier,
        allowed_classifications: u8,
        require_encryption: bool,
        max_payload_bytes: usize,
    ) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(32);
        name[..len].copy_from_slice(&bytes[..len]);
        Self {
            tenant_id,
            name,
            name_len: len,
            tier,
            allowed_classifications,
            require_encryption,
            max_payload_bytes,
            is_quarantined: false,
            geo_zone: GeoZone::SovereignSoil,
            total_requests: 0,
            total_violations: 0,
        }
    }

    pub fn with_geo_zone(mut self, geo: GeoZone) -> Self {
        self.geo_zone = geo;
        self
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unknown")
    }

    pub fn is_classification_allowed(&self, class: DataClassification) -> bool {
        (self.allowed_classifications & class.bit_mask()) != 0
    }
}

// ============================================================================
// MOTEUR DE FLUX & COURTAGE D'ENCLAVES TEE (ENCLAVE BROKERAGE)
// ============================================================================

/// Type d'enclave matérielle ou isolat souverain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveType {
    SovereignJamboEnclave,
    AmdSevSnp,
    IntelSgx,
    ArmCca,
}

impl EnclaveType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SovereignJamboEnclave => "SOVEREIGN_JAMBO_ENCLAVE",
            Self::AmdSevSnp => "AMD_SEV_SNP",
            Self::IntelSgx => "INTEL_SGX",
            Self::ArmCca => "ARM_CCA",
        }
    }
}

/// Sens du flux de données transitant par la passerelle CASB
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveFlowDirection {
    Ingress,
    Egress,
    InterEnclave,
}

impl EnclaveFlowDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ingress => "INGRESS",
            Self::Egress => "EGRESS",
            Self::InterEnclave => "INTER_ENCLAVE",
        }
    }
}

/// Contexte de canal d'interception d'enclave matérielle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnclaveFlowContext {
    pub flow_id: u64,
    pub enclave_id: u32,
    pub enclave_type: EnclaveType,
    pub mrenclave: [u8; 32],
    pub security_version: u32,
    pub direction: EnclaveFlowDirection,
    pub destination_endpoint: [u8; 32],
    pub destination_len: usize,
    pub zero_egress_enforced: bool,
    pub isolated: bool,
    pub total_messages: u64,
    pub total_bytes: u64,
}

impl EnclaveFlowContext {
    pub fn dst_as_str(&self) -> &str {
        core::str::from_utf8(&self.destination_endpoint[..self.destination_len])
            .unwrap_or("unknown_endpoint")
    }
}

// ============================================================================
// INSPECTION PROFONDE L7 SANS RUPTURE DE CHIFFREMENT (SOVEREIGN BLIND INSPECTION)
// ============================================================================

/// Métadonnées scellées d'enveloppe souveraine pour inspection L7 aveugle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SovereignEnvelopeMetadata {
    pub session_id: u64,
    pub sender_enclave_id: u32,
    pub claimed_classification: DataClassification,
    pub blinded_payload_hash: [u8; 32],
    pub attestation_token_tag: [u8; 16],
    pub target_geo_zone: GeoZone,
    pub payload_entropy_millibits: u32,
    pub is_homomorphic_tagged: bool,
}

// ============================================================================
// MOTEUR DLP (DATA LOSS PREVENTION) HYBRIDE & ENCLAVES
// ============================================================================

/// Type de motif recherché par l'inspection de contenu et l'analyse heuristique
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpPatternType {
    CreditCardLuhn,
    ApiKeySecret,
    PrivateKeyPem,
    ClassifiedMarker,
    PiiTaxId,
    EnclaveVmpckLeak,
    SgxSealingKey,
    PqcSecretShare,
    HighEntropySteganography,
}

impl DlpPatternType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreditCardLuhn => "CREDIT_CARD_LUHN",
            Self::ApiKeySecret => "API_KEY_SECRET",
            Self::PrivateKeyPem => "PRIVATE_KEY_PEM",
            Self::ClassifiedMarker => "CLASSIFIED_MARKER",
            Self::PiiTaxId => "PII_TAX_ID",
            Self::EnclaveVmpckLeak => "ENCLAVE_VMPCK_LEAK",
            Self::SgxSealingKey => "SGX_SEALING_KEY",
            Self::PqcSecretShare => "PQC_SECRET_SHARE",
            Self::HighEntropySteganography => "HIGH_ENTROPY_STEGANO",
        }
    }
}

/// Action DLP déclenchée en cas d'inadéquation ou fuite détectée
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpAction {
    Allow,
    Redact,
    Block,
    QuarantineTenant,
    IsolateEnclave,
}

impl DlpAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Redact => "REDACT",
            Self::Block => "BLOCK",
            Self::QuarantineTenant => "QUARANTINE_TENANT",
            Self::IsolateEnclave => "ISOLATE_ENCLAVE",
        }
    }
}

/// Règle formelle DLP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlpRule {
    pub rule_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub pattern_type: DlpPatternType,
    pub target_classification: DataClassification,
    pub default_action: DlpAction,
    pub active: bool,
}

impl DlpRule {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unnamed_rule")
    }
}

/// Algorithme de Luhn pour valider les numéros de cartes bancaires (13-19 chiffres)
pub fn luhn_check(digits: &[u8]) -> bool {
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        if !d.is_ascii_digit() {
            return false;
        }
        let mut val = (d - b'0') as u32;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum = sum.wrapping_add(val);
        double = !double;
    }
    (sum % 10) == 0
}

/// Scanneur de motifs DLP d'enclave et contenu
pub struct DlpScanner;

impl DlpScanner {
    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || needle.len() > haystack.len() {
            return None;
        }
        for i in 0..=(haystack.len() - needle.len()) {
            if &haystack[i..i + needle.len()] == needle {
                return Some(i);
            }
        }
        None
    }

    pub fn scan_credit_card(payload: &[u8]) -> Option<(usize, usize)> {
        let len = payload.len();
        if len < 13 {
            return None;
        }
        let mut i = 0;
        while i < len {
            if payload[i].is_ascii_digit() {
                let start = i;
                let mut digit_buf = [0u8; 24];
                let mut d_len = 0;
                let mut cursor = start;
                while cursor < len && d_len < 24 {
                    let b = payload[cursor];
                    if b.is_ascii_digit() {
                        digit_buf[d_len] = b;
                        d_len += 1;
                        cursor += 1;
                    } else if (b == b'-' || b == b' ')
                        && cursor + 1 < len
                        && payload[cursor + 1].is_ascii_digit()
                    {
                        cursor += 1;
                    } else {
                        break;
                    }
                }
                if d_len >= 13 && d_len <= 19 && luhn_check(&digit_buf[..d_len]) {
                    return Some((start, cursor - start));
                }
                i = cursor.max(start + 1);
            } else {
                i += 1;
            }
        }
        None
    }

    pub fn scan_api_key(payload: &[u8]) -> Option<(usize, usize)> {
        const PATTERNS: [&[u8]; 4] = [b"jambokey_", b"Bearer eyJ", b"sk_live_", b"AKIA"];
        for pat in PATTERNS.iter() {
            if let Some(pos) = Self::find_subslice(payload, pat) {
                let mut len = pat.len();
                while pos + len < payload.len() && len < 48 {
                    let b = payload[pos + len];
                    if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' {
                        len += 1;
                    } else {
                        break;
                    }
                }
                return Some((pos, len));
            }
        }
        None
    }

    pub fn scan_private_key_pem(payload: &[u8]) -> Option<(usize, usize)> {
        const PATTERNS: [&[u8]; 3] = [
            b"-----BEGIN PRIVATE KEY-----",
            b"-----BEGIN RSA PRIVATE KEY-----",
            b"-----BEGIN EC PRIVATE KEY-----",
        ];
        for pat in PATTERNS.iter() {
            if let Some(pos) = Self::find_subslice(payload, pat) {
                return Some((pos, pat.len()));
            }
        }
        None
    }

    pub fn scan_classified_marker(payload: &[u8]) -> Option<(usize, usize)> {
        const PATTERNS: [&[u8]; 3] = [
            b"CONFIDENTIAL_JAMBO",
            b"TOP_SECRET_JAMBO",
            b"RESTRICTED_DEFENSE",
        ];
        for pat in PATTERNS.iter() {
            if let Some(pos) = Self::find_subslice(payload, pat) {
                return Some((pos, pat.len()));
            }
        }
        None
    }

    pub fn scan_pii_tax_id(payload: &[u8]) -> Option<(usize, usize)> {
        if payload.len() < 11 {
            return None;
        }
        for i in 0..=(payload.len() - 11) {
            if payload[i].is_ascii_digit()
                && payload[i + 1].is_ascii_digit()
                && payload[i + 2].is_ascii_digit()
                && payload[i + 3] == b'-'
                && payload[i + 4].is_ascii_digit()
                && payload[i + 5].is_ascii_digit()
                && payload[i + 6] == b'-'
                && payload[i + 7].is_ascii_digit()
                && payload[i + 8].is_ascii_digit()
                && payload[i + 9].is_ascii_digit()
                && payload[i + 10].is_ascii_digit()
            {
                return Some((i, 11));
            }
        }
        None
    }

    pub fn scan_enclave_vmpck(payload: &[u8]) -> Option<(usize, usize)> {
        const PATTERNS: [&[u8]; 3] = [b"VMPCK_", b"vmsa_secret_", b"sev_secret_"];
        for pat in PATTERNS.iter() {
            if let Some(pos) = Self::find_subslice(payload, pat) {
                let mut len = pat.len();
                while pos + len < payload.len() && len < 40 {
                    let b = payload[pos + len];
                    if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                        len += 1;
                    } else {
                        break;
                    }
                }
                return Some((pos, len));
            }
        }
        None
    }

    pub fn scan_sgx_sealing_key(payload: &[u8]) -> Option<(usize, usize)> {
        const PATTERNS: [&[u8]; 2] = [b"MRENCLAVE_SEAL_", b"sgx_seal_key_"];
        for pat in PATTERNS.iter() {
            if let Some(pos) = Self::find_subslice(payload, pat) {
                let mut len = pat.len();
                while pos + len < payload.len() && len < 40 {
                    let b = payload[pos + len];
                    if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                        len += 1;
                    } else {
                        break;
                    }
                }
                return Some((pos, len));
            }
        }
        None
    }

    pub fn scan_pqc_secret(payload: &[u8]) -> Option<(usize, usize)> {
        const PATTERNS: [&[u8]; 3] = [b"mlkem_priv_", b"pqc_priv_seed_", b"dilithium_priv_"];
        for pat in PATTERNS.iter() {
            if let Some(pos) = Self::find_subslice(payload, pat) {
                let mut len = pat.len();
                while pos + len < payload.len() && len < 48 {
                    let b = payload[pos + len];
                    if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                        len += 1;
                    } else {
                        break;
                    }
                }
                return Some((pos, len));
            }
        }
        None
    }

    pub fn scan_high_entropy(payload: &[u8], threshold_milli: u32) -> Option<(usize, usize)> {
        if payload.len() >= 32 {
            let ent = calculate_entropy_millibits(payload);
            if ent >= threshold_milli {
                return Some((0, payload.len()));
            }
        }
        None
    }
}

// ============================================================================
// PASSERELLE MANDATAIRE & COURTAGE D'ADMISSION (CASB PROXY)
// ============================================================================

/// Requête d'accès inter-services ou cloud soumise au courtier CASB
#[derive(Debug, Clone, Copy)]
pub struct CasbRequest {
    pub request_id: u64,
    pub tenant_id: u32,
    pub source_service: [u8; 32],
    pub source_service_len: usize,
    pub dest_service: [u8; 32],
    pub dest_service_len: usize,
    pub operation: [u8; 16],
    pub operation_len: usize,
    pub encrypted: bool,
    pub payload: [u8; 256],
    pub payload_len: usize,
}

impl CasbRequest {
    pub fn new(
        request_id: u64,
        tenant_id: u32,
        src: &str,
        dst: &str,
        op: &str,
        encrypted: bool,
        payload_data: &[u8],
    ) -> Self {
        let mut source_service = [0u8; 32];
        let s_len = src.as_bytes().len().min(32);
        source_service[..s_len].copy_from_slice(&src.as_bytes()[..s_len]);

        let mut dest_service = [0u8; 32];
        let d_len = dst.as_bytes().len().min(32);
        dest_service[..d_len].copy_from_slice(&dst.as_bytes()[..d_len]);

        let mut operation = [0u8; 16];
        let o_len = op.as_bytes().len().min(16);
        operation[..o_len].copy_from_slice(&op.as_bytes()[..o_len]);

        let mut payload = [0u8; 256];
        let p_len = payload_data.len().min(256);
        payload[..p_len].copy_from_slice(&payload_data[..p_len]);

        Self {
            request_id,
            tenant_id,
            source_service,
            source_service_len: s_len,
            dest_service,
            dest_service_len: d_len,
            operation,
            operation_len: o_len,
            encrypted,
            payload,
            payload_len: p_len,
        }
    }

    pub fn src_as_str(&self) -> &str {
        core::str::from_utf8(&self.source_service[..self.source_service_len]).unwrap_or("unknown")
    }

    pub fn dst_as_str(&self) -> &str {
        core::str::from_utf8(&self.dest_service[..self.dest_service_len]).unwrap_or("unknown")
    }

    pub fn op_as_str(&self) -> &str {
        core::str::from_utf8(&self.operation[..self.operation_len]).unwrap_or("unknown")
    }
}

/// Décision d'admission retournée par le courtier CASB
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    Approved {
        transaction_id: u64,
        sanitized_len: usize,
    },
    RedactedAndApproved {
        transaction_id: u64,
        redacted_count: usize,
        sanitized_len: usize,
    },
    Blocked {
        violation_code: u16,
        reason: &'static str,
    },
    Quarantined {
        reason: &'static str,
    },
    EnclaveIsolated {
        enclave_id: u32,
        reason: &'static str,
    },
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SHA-256 SCELLEMENT INVIOLABLE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasbAuditAction {
    TenantRegistered,
    TenantQuarantined,
    QuarantineLifted,
    DlpRuleRegistered,
    RequestApproved,
    RequestRedacted,
    RequestBlocked,
    LedgerSealed,
    EnclaveFlowRegistered,
    EnclaveIsolated,
    EnclaveIsolationLifted,
    BlindInspectionApproved,
    BlindInspectionBlocked,
    EnclaveDlpViolation,
}

impl CasbAuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TenantRegistered => "TenantRegistered",
            Self::TenantQuarantined => "TenantQuarantined",
            Self::QuarantineLifted => "QuarantineLifted",
            Self::DlpRuleRegistered => "DlpRuleRegistered",
            Self::RequestApproved => "RequestApproved",
            Self::RequestRedacted => "RequestRedacted",
            Self::RequestBlocked => "RequestBlocked",
            Self::LedgerSealed => "LedgerSealed",
            Self::EnclaveFlowRegistered => "EnclaveFlowRegistered",
            Self::EnclaveIsolated => "EnclaveIsolated",
            Self::EnclaveIsolationLifted => "EnclaveIsolationLifted",
            Self::BlindInspectionApproved => "BlindInspectionApproved",
            Self::BlindInspectionBlocked => "BlindInspectionBlocked",
            Self::EnclaveDlpViolation => "EnclaveDlpViolation",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CasbAuditEntry {
    pub timestamp: u64,
    pub action: CasbAuditAction,
    pub tenant_id: u32,
    pub detail: [u8; 32],
    pub detail_len: usize,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

// ============================================================================
// DÉMON CENTRAL CASB (`JamboCasbDaemon`)
// ============================================================================

pub struct JamboCasbDaemon {
    pub admin_cap: CasbCap,
    pub tenants: [Option<TenantContext>; 16],
    pub tenant_count: usize,
    pub dlp_rules: [Option<DlpRule>; 16],
    pub dlp_rule_count: usize,
    pub enclave_flows: [Option<EnclaveFlowContext>; 16],
    pub enclave_flow_count: usize,
    pub audit_log: [Option<CasbAuditEntry>; 64],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],
    pub next_tenant_id: u32,
    pub next_rule_id: u32,
    pub next_flow_id: u64,
    pub next_transaction_id: u64,
    pub total_inspections: u64,
    pub total_approvals: u64,
    pub total_redactions: u64,
    pub total_blocks: u64,
    pub total_quarantines: u64,
    pub total_enclave_flows: u64,
    pub total_blind_inspections: u64,
    pub total_enclave_isolations: u64,
}

impl JamboCasbDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0xCA; 32];

    pub fn new(admin_cap: CasbCap) -> Self {
        Self {
            admin_cap,
            tenants: [None; 16],
            tenant_count: 0,
            dlp_rules: [None; 16],
            dlp_rule_count: 0,
            enclave_flows: [None; 16],
            enclave_flow_count: 0,
            audit_log: [None; 64],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            next_tenant_id: 100,
            next_rule_id: 1,
            next_flow_id: 8000,
            next_transaction_id: 5000,
            total_inspections: 0,
            total_approvals: 0,
            total_redactions: 0,
            total_blocks: 0,
            total_quarantines: 0,
            total_enclave_flows: 0,
            total_blind_inspections: 0,
            total_enclave_isolations: 0,
        }
    }

    /// Journalise une action dans le registre immuable chaîné par SHA-256
    pub fn append_audit(
        &mut self,
        timestamp: u64,
        action: CasbAuditAction,
        tenant_id: u32,
        detail_str: &str,
    ) {
        if self.audit_count >= self.audit_log.len() {
            return;
        }

        let mut detail = [0u8; 32];
        let bytes = detail_str.as_bytes();
        let len = bytes.len().min(32);
        detail[..len].copy_from_slice(&bytes[..len]);

        let mut hasher = Sha256::new();
        hasher.update(&self.ledger_hash);
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(action.as_str().as_bytes());
        hasher.update(&tenant_id.to_be_bytes());
        hasher.update(&detail[..len]);
        let entry_hash = hasher.finalize();

        let entry = CasbAuditEntry {
            timestamp,
            action,
            tenant_id,
            detail,
            detail_len: len,
            prev_hash: self.ledger_hash,
            hash: entry_hash,
        };

        self.audit_log[self.audit_count] = Some(entry);
        self.audit_count += 1;
        self.ledger_hash = entry_hash;
    }

    /// Vérifie l'intégrité formelle de bout en bout de la chaîne d'audit SHA-256
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = Self::GENESIS_HASH;
        for i in 0..self.audit_count {
            if let Some(ref entry) = self.audit_log[i] {
                if entry.prev_hash != expected_prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.prev_hash);
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(entry.action.as_str().as_bytes());
                hasher.update(&entry.tenant_id.to_be_bytes());
                hasher.update(&entry.detail[..entry.detail_len]);
                let calc = hasher.finalize();
                if calc != entry.hash {
                    return false;
                }
                expected_prev = entry.hash;
            }
        }
        expected_prev == self.ledger_hash
    }

    /// Enregistre un nouveau locataire (tenant) avec profil de conformité
    pub fn register_tenant(
        &mut self,
        cap: &CasbCap,
        name: &str,
        tier: ComplianceTier,
        allowed_classifications: u8,
        require_encryption: bool,
        max_payload_bytes: usize,
        timestamp: u64,
    ) -> Result<u32, CasbError> {
        if !cap.has_right(casb_rights::MANAGE_TENANTS) {
            return Err(CasbError::PermissionDenied);
        }
        if self.tenant_count >= self.tenants.len() {
            return Err(CasbError::TenantTableFull);
        }

        let tenant_id = self.next_tenant_id;
        self.next_tenant_id = self.next_tenant_id.saturating_add(1);

        let tenant = TenantContext::new(
            tenant_id,
            name,
            tier,
            allowed_classifications,
            require_encryption,
            max_payload_bytes,
        );

        self.tenants[self.tenant_count] = Some(tenant);
        self.tenant_count += 1;

        self.append_audit(
            timestamp,
            CasbAuditAction::TenantRegistered,
            tenant_id,
            name,
        );

        Ok(tenant_id)
    }

    /// Enregistre une nouvelle règle formelle DLP
    pub fn register_dlp_rule(
        &mut self,
        cap: &CasbCap,
        name: &str,
        pattern_type: DlpPatternType,
        target_classification: DataClassification,
        default_action: DlpAction,
        timestamp: u64,
    ) -> Result<u32, CasbError> {
        if !cap.has_right(casb_rights::CONFIGURE_POLICIES) {
            return Err(CasbError::PermissionDenied);
        }
        if self.dlp_rule_count >= self.dlp_rules.len() {
            return Err(CasbError::DlpRuleTableFull);
        }

        let mut rname = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        rname[..len].copy_from_slice(&bytes[..len]);

        let rule_id = self.next_rule_id;
        self.next_rule_id = self.next_rule_id.saturating_add(1);

        let rule = DlpRule {
            rule_id,
            name: rname,
            name_len: len,
            pattern_type,
            target_classification,
            default_action,
            active: true,
        };

        self.dlp_rules[self.dlp_rule_count] = Some(rule);
        self.dlp_rule_count += 1;

        self.append_audit(timestamp, CasbAuditAction::DlpRuleRegistered, rule_id, name);

        Ok(rule_id)
    }

    /// Enregistre un flux d'enclave matérielle TEE pour courtage et contrôle de sortie
    pub fn register_enclave_flow(
        &mut self,
        cap: &CasbCap,
        enclave_id: u32,
        enclave_type: EnclaveType,
        mrenclave: [u8; 32],
        security_version: u32,
        direction: EnclaveFlowDirection,
        dst_endpoint: &str,
        zero_egress: bool,
        timestamp: u64,
    ) -> Result<u64, CasbError> {
        if !cap.has_right(casb_rights::INTERCEPT_ENCLAVE) {
            return Err(CasbError::PermissionDenied);
        }
        if self.enclave_flow_count >= self.enclave_flows.len() {
            return Err(CasbError::EnclaveFlowTableFull);
        }

        let flow_id = self.next_flow_id;
        self.next_flow_id = self.next_flow_id.saturating_add(1);

        let mut destination_endpoint = [0u8; 32];
        let d_bytes = dst_endpoint.as_bytes();
        let d_len = d_bytes.len().min(32);
        destination_endpoint[..d_len].copy_from_slice(&d_bytes[..d_len]);

        let flow = EnclaveFlowContext {
            flow_id,
            enclave_id,
            enclave_type,
            mrenclave,
            security_version,
            direction,
            destination_endpoint,
            destination_len: d_len,
            zero_egress_enforced: zero_egress,
            isolated: false,
            total_messages: 0,
            total_bytes: 0,
        };

        self.enclave_flows[self.enclave_flow_count] = Some(flow);
        self.enclave_flow_count += 1;
        self.total_enclave_flows = self.total_enclave_flows.saturating_add(1);

        self.append_audit(
            timestamp,
            CasbAuditAction::EnclaveFlowRegistered,
            enclave_id,
            dst_endpoint,
        );

        Ok(flow_id)
    }

    /// Isole immédiatement une enclave matérielle (arrêt O(1) de tout flux réseau/cloud)
    pub fn isolate_enclave(
        &mut self,
        cap: &CasbCap,
        enclave_id: u32,
        reason: &str,
        timestamp: u64,
    ) -> Result<(), CasbError> {
        if !cap.has_right(casb_rights::ISOLATE_ENCLAVE) {
            return Err(CasbError::PermissionDenied);
        }

        let mut found = false;
        for i in 0..self.enclave_flow_count {
            if let Some(ref mut flow) = self.enclave_flows[i] {
                if flow.enclave_id == enclave_id {
                    flow.isolated = true;
                    found = true;
                }
            }
        }

        if !found {
            return Err(CasbError::EnclaveNotFound);
        }

        self.total_enclave_isolations = self.total_enclave_isolations.saturating_add(1);
        self.append_audit(
            timestamp,
            CasbAuditAction::EnclaveIsolated,
            enclave_id,
            reason,
        );

        Ok(())
    }

    /// Lève l'isolation d'une enclave
    pub fn lift_enclave_isolation(
        &mut self,
        cap: &CasbCap,
        enclave_id: u32,
        timestamp: u64,
    ) -> Result<(), CasbError> {
        if !cap.has_right(casb_rights::ISOLATE_ENCLAVE) {
            return Err(CasbError::PermissionDenied);
        }

        let mut found = false;
        for i in 0..self.enclave_flow_count {
            if let Some(ref mut flow) = self.enclave_flows[i] {
                if flow.enclave_id == enclave_id {
                    flow.isolated = false;
                    found = true;
                }
            }
        }

        if !found {
            return Err(CasbError::EnclaveNotFound);
        }

        self.append_audit(
            timestamp,
            CasbAuditAction::EnclaveIsolationLifted,
            enclave_id,
            "Enclave isolation lifted",
        );

        Ok(())
    }

    /// Inspection L7 aveugle d'enveloppe chiffrée de bout en bout (Sovereign Blind Inspection)
    pub fn inspect_enclave_blind_envelope(
        &mut self,
        cap: &CasbCap,
        flow_id: u64,
        envelope: &SovereignEnvelopeMetadata,
        timestamp: u64,
    ) -> Result<AdmissionDecision, CasbError> {
        if !cap.has_right(casb_rights::BLIND_INSPECT) {
            return Err(CasbError::PermissionDenied);
        }

        self.total_blind_inspections = self.total_blind_inspections.saturating_add(1);
        self.total_inspections = self.total_inspections.saturating_add(1);

        // 1. Recherche du flux d'enclave
        let mut flow_idx = None;
        for i in 0..self.enclave_flow_count {
            if let Some(ref f) = self.enclave_flows[i] {
                if f.flow_id == flow_id {
                    flow_idx = Some(i);
                    break;
                }
            }
        }

        let fidx = match flow_idx {
            Some(idx) => idx,
            None => return Err(CasbError::EnclaveNotFound),
        };

        let flow = self.enclave_flows[fidx].unwrap();

        // 2. Vérification statut d'isolation
        if flow.isolated {
            self.total_blocks = self.total_blocks.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::BlindInspectionBlocked,
                flow.enclave_id,
                "Enclave is isolated",
            );
            return Ok(AdmissionDecision::EnclaveIsolated {
                enclave_id: flow.enclave_id,
                reason: "Enclave flow blocked: enclave is isolated",
            });
        }

        // 3. Vérification Zero-Egress
        if flow.zero_egress_enforced && flow.direction == EnclaveFlowDirection::Egress {
            self.total_blocks = self.total_blocks.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::BlindInspectionBlocked,
                flow.enclave_id,
                "Zero-egress policy violation",
            );
            return Ok(AdmissionDecision::Blocked {
                violation_code: 4051,
                reason: "Zero-egress policy strictly forbids cloud outbound flows",
            });
        }

        // 4. Contrôle de conformité géo-fencing souverain
        if !envelope.target_geo_zone.is_sovereign_compliant() {
            self.total_blocks = self.total_blocks.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::BlindInspectionBlocked,
                flow.enclave_id,
                "Geo-fencing foreign jurisdiction violation",
            );
            return Ok(AdmissionDecision::Blocked {
                violation_code: 4052,
                reason: "Target geo-zone violates Sovereign Cloud SecNumCloud geo-fencing",
            });
        }

        // 5. Vérification d'attestation token tag
        if envelope.attestation_token_tag == [0u8; 16] {
            self.total_blocks = self.total_blocks.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::BlindInspectionBlocked,
                flow.enclave_id,
                "Invalid zero-length attestation tag",
            );
            return Ok(AdmissionDecision::Blocked {
                violation_code: 4053,
                reason: "Enclave envelope missing valid hardware attestation token tag",
            });
        }

        // Mise à jour statistique du flux
        if let Some(ref mut f) = self.enclave_flows[fidx] {
            f.total_messages = f.total_messages.saturating_add(1);
        }

        let transaction_id = self.next_transaction_id;
        self.next_transaction_id = self.next_transaction_id.saturating_add(1);
        self.total_approvals = self.total_approvals.saturating_add(1);

        self.append_audit(
            timestamp,
            CasbAuditAction::BlindInspectionApproved,
            flow.enclave_id,
            "Blind L7 envelope approved",
        );

        Ok(AdmissionDecision::Approved {
            transaction_id,
            sanitized_len: 32,
        })
    }

    /// Met en quarantaine un locataire après incident de conformité ou fuite grave
    pub fn quarantine_tenant(
        &mut self,
        cap: &CasbCap,
        tenant_id: u32,
        reason: &str,
        timestamp: u64,
    ) -> Result<(), CasbError> {
        if !cap.has_right(casb_rights::QUARANTINE_ACTION) {
            return Err(CasbError::PermissionDenied);
        }

        let mut found = false;
        for i in 0..self.tenant_count {
            if let Some(ref mut t) = self.tenants[i] {
                if t.tenant_id == tenant_id {
                    t.is_quarantined = true;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(CasbError::TenantNotFound);
        }

        self.total_quarantines = self.total_quarantines.saturating_add(1);
        self.append_audit(
            timestamp,
            CasbAuditAction::TenantQuarantined,
            tenant_id,
            reason,
        );

        Ok(())
    }

    /// Lève la quarantaine d'un locataire
    pub fn lift_quarantine(
        &mut self,
        cap: &CasbCap,
        tenant_id: u32,
        timestamp: u64,
    ) -> Result<(), CasbError> {
        if !cap.has_right(casb_rights::QUARANTINE_ACTION) {
            return Err(CasbError::PermissionDenied);
        }

        let mut found = false;
        for i in 0..self.tenant_count {
            if let Some(ref mut t) = self.tenants[i] {
                if t.tenant_id == tenant_id {
                    t.is_quarantined = false;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(CasbError::TenantNotFound);
        }

        self.append_audit(
            timestamp,
            CasbAuditAction::QuarantineLifted,
            tenant_id,
            "Quarantine lifted",
        );

        Ok(())
    }

    /// Courtage, inspection de conformité et filtrage DLP d'une requête inter-services
    pub fn scan_and_broker_admission(
        &mut self,
        cap: &CasbCap,
        req: &CasbRequest,
        sanitized_payload: &mut [u8; 256],
        timestamp: u64,
    ) -> Result<AdmissionDecision, CasbError> {
        if !cap.has_right(casb_rights::INSPECT_TRAFFIC) {
            return Err(CasbError::PermissionDenied);
        }

        self.total_inspections = self.total_inspections.saturating_add(1);

        // 1. Recherche du locataire
        let mut tenant_idx: Option<usize> = None;
        for i in 0..self.tenant_count {
            if let Some(ref t) = self.tenants[i] {
                if t.tenant_id == req.tenant_id {
                    tenant_idx = Some(i);
                    break;
                }
            }
        }

        let tidx = match tenant_idx {
            Some(idx) => idx,
            None => return Err(CasbError::TenantNotFound),
        };

        // Mise à jour statistique requête
        if let Some(ref mut t) = self.tenants[tidx] {
            t.total_requests = t.total_requests.saturating_add(1);
        }

        let tenant_copy = self.tenants[tidx].unwrap();

        // 2. Vérification statut quarantaine
        if tenant_copy.is_quarantined {
            self.total_blocks = self.total_blocks.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::RequestBlocked,
                req.tenant_id,
                "Tenant is in quarantine",
            );
            return Ok(AdmissionDecision::Quarantined {
                reason: "Tenant is quarantined due to policy violation",
            });
        }

        // 3. Vérification de chiffrement obligatoire
        if tenant_copy.require_encryption && !req.encrypted {
            self.total_blocks = self.total_blocks.saturating_add(1);
            if let Some(ref mut t) = self.tenants[tidx] {
                t.total_violations = t.total_violations.saturating_add(1);
            }
            self.append_audit(
                timestamp,
                CasbAuditAction::RequestBlocked,
                req.tenant_id,
                "Encryption required by policy",
            );
            return Ok(AdmissionDecision::Blocked {
                violation_code: 4031,
                reason: "Unencrypted traffic forbidden for this compliance tier",
            });
        }

        // 4. Vérification taille maximale du payload
        if req.payload_len > tenant_copy.max_payload_bytes {
            self.total_blocks = self.total_blocks.saturating_add(1);
            if let Some(ref mut t) = self.tenants[tidx] {
                t.total_violations = t.total_violations.saturating_add(1);
            }
            self.append_audit(
                timestamp,
                CasbAuditAction::RequestBlocked,
                req.tenant_id,
                "Payload exceeds allowed size",
            );
            return Ok(AdmissionDecision::Blocked {
                violation_code: 4032,
                reason: "Payload exceeds tenant quota limit",
            });
        }

        // 5. Copie du payload brut dans le tampon de sortie pour assainissement
        sanitized_payload[..req.payload_len].copy_from_slice(&req.payload[..req.payload_len]);

        let mut total_redactions = 0usize;
        let mut block_reason: Option<&'static str> = None;
        let mut trigger_quarantine = false;
        let mut trigger_isolate_enclave = false;

        // 6. Évaluation des règles DLP actives
        for r_idx in 0..self.dlp_rule_count {
            if let Some(ref rule) = self.dlp_rules[r_idx] {
                if !rule.active {
                    continue;
                }

                let detection: Option<(usize, usize)> = match rule.pattern_type {
                    DlpPatternType::CreditCardLuhn => {
                        DlpScanner::scan_credit_card(&sanitized_payload[..req.payload_len])
                    }
                    DlpPatternType::ApiKeySecret => {
                        DlpScanner::scan_api_key(&sanitized_payload[..req.payload_len])
                    }
                    DlpPatternType::PrivateKeyPem => {
                        DlpScanner::scan_private_key_pem(&sanitized_payload[..req.payload_len])
                    }
                    DlpPatternType::ClassifiedMarker => {
                        DlpScanner::scan_classified_marker(&sanitized_payload[..req.payload_len])
                    }
                    DlpPatternType::PiiTaxId => {
                        DlpScanner::scan_pii_tax_id(&sanitized_payload[..req.payload_len])
                    }
                    DlpPatternType::EnclaveVmpckLeak => {
                        DlpScanner::scan_enclave_vmpck(&sanitized_payload[..req.payload_len])
                    }
                    DlpPatternType::SgxSealingKey => {
                        DlpScanner::scan_sgx_sealing_key(&sanitized_payload[..req.payload_len])
                    }
                    DlpPatternType::PqcSecretShare => {
                        DlpScanner::scan_pqc_secret(&sanitized_payload[..req.payload_len])
                    }
                    DlpPatternType::HighEntropySteganography => {
                        DlpScanner::scan_high_entropy(&sanitized_payload[..req.payload_len], 7800)
                    }
                };

                if let Some((offset, len)) = detection {
                    let allowed = tenant_copy.is_classification_allowed(rule.target_classification);

                    if !allowed {
                        match rule.default_action {
                            DlpAction::Allow => {}
                            DlpAction::Redact => {
                                for b in &mut sanitized_payload[offset..offset + len] {
                                    *b = b'*';
                                }
                                total_redactions += 1;
                            }
                            DlpAction::Block => {
                                block_reason = Some(rule.pattern_type.as_str());
                                break;
                            }
                            DlpAction::QuarantineTenant => {
                                trigger_quarantine = true;
                                block_reason =
                                    Some("Critical DLP leak triggered tenant quarantine");
                                break;
                            }
                            DlpAction::IsolateEnclave => {
                                trigger_isolate_enclave = true;
                                block_reason =
                                    Some("Critical enclave secret leak triggered isolation");
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 7. Prise de décision finale
        let transaction_id = self.next_transaction_id;
        self.next_transaction_id = self.next_transaction_id.saturating_add(1);

        if trigger_isolate_enclave {
            if let Some(ref mut t) = self.tenants[tidx] {
                t.total_violations = t.total_violations.saturating_add(1);
            }
            self.total_blocks = self.total_blocks.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::EnclaveDlpViolation,
                req.tenant_id,
                "Enclave Secret Exfiltration Detected",
            );
            return Ok(AdmissionDecision::EnclaveIsolated {
                enclave_id: req.tenant_id,
                reason: "Enclave secret exfiltration detected by DLP engine",
            });
        }

        if trigger_quarantine {
            if let Some(ref mut t) = self.tenants[tidx] {
                t.is_quarantined = true;
                t.total_violations = t.total_violations.saturating_add(1);
            }
            self.total_quarantines = self.total_quarantines.saturating_add(1);
            self.total_blocks = self.total_blocks.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::TenantQuarantined,
                req.tenant_id,
                "DLP Quarantine Triggered",
            );
            return Ok(AdmissionDecision::Quarantined {
                reason: "Tenant automatically quarantined due to sensitive credential leak",
            });
        }

        if let Some(reason) = block_reason {
            if let Some(ref mut t) = self.tenants[tidx] {
                t.total_violations = t.total_violations.saturating_add(1);
            }
            self.total_blocks = self.total_blocks.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::RequestBlocked,
                req.tenant_id,
                reason,
            );
            return Ok(AdmissionDecision::Blocked {
                violation_code: 4033,
                reason: "DLP policy blocked unauthorized sensitive data flow",
            });
        }

        if total_redactions > 0 {
            self.total_redactions = self.total_redactions.saturating_add(1);
            self.total_approvals = self.total_approvals.saturating_add(1);
            self.append_audit(
                timestamp,
                CasbAuditAction::RequestRedacted,
                req.tenant_id,
                "DLP Redacted Sensitive Fields",
            );
            return Ok(AdmissionDecision::RedactedAndApproved {
                transaction_id,
                redacted_count: total_redactions,
                sanitized_len: req.payload_len,
            });
        }

        self.total_approvals = self.total_approvals.saturating_add(1);
        self.append_audit(
            timestamp,
            CasbAuditAction::RequestApproved,
            req.tenant_id,
            "Request approved",
        );

        Ok(AdmissionDecision::Approved {
            transaction_id,
            sanitized_len: req.payload_len,
        })
    }

    /// Initialise la configuration par défaut du CASB souverain
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Locataire Souverain Défense (Autorisé: Public, Internal, Confidential, Secret, CryptoKey, EnclaveSecret)
        let _ = self.register_tenant(
            &cap,
            "sovereign.core",
            ComplianceTier::SovereignDefense,
            data_classes::PUBLIC
                | data_classes::INTERNAL
                | data_classes::CONFIDENTIAL
                | data_classes::SECRET
                | data_classes::CRYPTO_KEY
                | data_classes::ENCLAVE_SECRET,
            true, // Chiffrement obligatoire
            256,
            1000,
        );

        // 2. Locataire Entreprise SecNumCloud (Autorisé: Public, Internal, Confidential, FinancialPci)
        let _ = self.register_tenant(
            &cap,
            "enterprise.secnumcloud",
            ComplianceTier::SecNumCloudSovereign,
            data_classes::PUBLIC
                | data_classes::INTERNAL
                | data_classes::CONFIDENTIAL
                | data_classes::FINANCIAL_PCI,
            true,
            256,
            1001,
        );

        // 3. Locataire Communautaire Public (Autorisé: Public uniquement, pas de chiffrement requis)
        let _ = self.register_tenant(
            &cap,
            "community.guest",
            ComplianceTier::Community,
            data_classes::PUBLIC,
            false,
            128,
            1002,
        );

        // Règles DLP par défaut :
        // 1. Cartes bancaires (Redact par défaut)
        let _ = self.register_dlp_rule(
            &cap,
            "dlp_pci_cards",
            DlpPatternType::CreditCardLuhn,
            DataClassification::FinancialPci,
            DlpAction::Redact,
            1003,
        );

        // 2. Clés API (Quarantine immédiate)
        let _ = self.register_dlp_rule(
            &cap,
            "dlp_api_keys",
            DlpPatternType::ApiKeySecret,
            DataClassification::CryptoKey,
            DlpAction::QuarantineTenant,
            1004,
        );

        // 3. Clés privées PEM (Quarantine immédiate)
        let _ = self.register_dlp_rule(
            &cap,
            "dlp_pem_keys",
            DlpPatternType::PrivateKeyPem,
            DataClassification::CryptoKey,
            DlpAction::QuarantineTenant,
            1005,
        );

        // 4. Marqueurs secret défense (Block)
        let _ = self.register_dlp_rule(
            &cap,
            "dlp_secret_defense",
            DlpPatternType::ClassifiedMarker,
            DataClassification::Secret,
            DlpAction::Block,
            1006,
        );

        // 5. Numéros PII fiscaux (Redact)
        let _ = self.register_dlp_rule(
            &cap,
            "dlp_pii_tax",
            DlpPatternType::PiiTaxId,
            DataClassification::Pii,
            DlpAction::Redact,
            1007,
        );

        // 6. Fuite de clé d'enclave VMPCK AMD SEV-SNP (IsolateEnclave)
        let _ = self.register_dlp_rule(
            &cap,
            "dlp_enclave_vmpck",
            DlpPatternType::EnclaveVmpckLeak,
            DataClassification::EnclaveSecret,
            DlpAction::IsolateEnclave,
            1008,
        );

        // 7. Fuite de clé de scellement SGX (IsolateEnclave)
        let _ = self.register_dlp_rule(
            &cap,
            "dlp_sgx_sealing",
            DlpPatternType::SgxSealingKey,
            DataClassification::EnclaveSecret,
            DlpAction::IsolateEnclave,
            1009,
        );

        // 8. Fuite de part secrète ML-KEM post-quantique (IsolateEnclave)
        let _ = self.register_dlp_rule(
            &cap,
            "dlp_pqc_secret",
            DlpPatternType::PqcSecretShare,
            DataClassification::EnclaveSecret,
            DlpAction::IsolateEnclave,
            1010,
        );

        // Enregistrement d'un flux d'enclave souveraine par défaut (Sovereign JamboEnclave avec Zero-Egress)
        let default_mrenclave = [0x7A; 32];
        let _ = self.register_enclave_flow(
            &cap,
            7001,
            EnclaveType::SovereignJamboEnclave,
            default_mrenclave,
            1,
            EnclaveFlowDirection::Egress,
            "cloud.sovereign.vault",
            true, // Zero egress imposé
            1011,
        );
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] / std sous test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_casb_cap_attenuation() {
        let admin_cap = CasbCap::new(Handle::new(12401, 1), casb_rights::ALL, 5000, 100);
        assert!(admin_cap.has_right(casb_rights::INSPECT_TRAFFIC));
        assert!(admin_cap.has_right(casb_rights::MANAGE_TENANTS));
        assert!(admin_cap.has_right(casb_rights::ENFORCE_DLP));
        assert!(admin_cap.has_right(casb_rights::INTERCEPT_ENCLAVE));
        assert!(admin_cap.has_right(casb_rights::BLIND_INSPECT));
        assert!(admin_cap.has_right(casb_rights::ISOLATE_ENCLAVE));

        let attenuated = admin_cap
            .attenuate(
                casb_rights::INSPECT_TRAFFIC | casb_rights::AUDIT_READ,
                2000,
                50,
            )
            .expect("Atténuation monotone");

        assert!(attenuated.has_right(casb_rights::INSPECT_TRAFFIC));
        assert!(attenuated.has_right(casb_rights::AUDIT_READ));
        assert!(!attenuated.has_right(casb_rights::ADMIN));
        assert!(!attenuated.has_right(casb_rights::MANAGE_TENANTS));
        assert!(!attenuated.has_right(casb_rights::ISOLATE_ENCLAVE));

        // Rejet d'escalade
        assert_eq!(
            attenuated.attenuate(casb_rights::ALL, 2000, 50),
            Err(CasbError::AttenuationViolation)
        );
    }

    #[test]
    fn test_luhn_algorithm() {
        let valid_visa = b"4242424242424242";
        assert!(luhn_check(valid_visa));

        let invalid = b"4242424242424243";
        assert!(!luhn_check(invalid));
    }

    #[test]
    fn test_casb_dlp_and_admission() {
        let cap = CasbCap::new(Handle::new(12402, 1), casb_rights::ALL, 10000, 500);
        let mut daemon = JamboCasbDaemon::new(cap);
        daemon.init_defaults();

        assert_eq!(daemon.tenant_count, 3);
        assert_eq!(daemon.dlp_rule_count, 8);
        assert_eq!(daemon.enclave_flow_count, 1);
        assert!(daemon.verify_ledger_integrity());

        let mut sanitized = [0u8; 256];

        // 1. Requête légitime du locataire public sans données sensibles
        let req1 = CasbRequest::new(
            1,
            102, // community.guest
            "web_frontend",
            "search_api",
            "GET_PAGE",
            false,
            b"query=jambo_docs",
        );
        let res1 = daemon
            .scan_and_broker_admission(&cap, &req1, &mut sanitized, 2000)
            .expect("Admission OK");
        match res1 {
            AdmissionDecision::Approved { transaction_id, .. } => {
                assert!(transaction_id >= 5000);
            }
            _ => panic!("Requête 1 aurait dû être approuvée"),
        }

        // 2. Requête du locataire public contenant un numéro de carte bancaire valide -> Redact
        let req2 = CasbRequest::new(
            2,
            102,
            "web_frontend",
            "payment_gateway",
            "PAY",
            false,
            b"card=4242424242424242&amt=50",
        );
        let res2 = daemon
            .scan_and_broker_admission(&cap, &req2, &mut sanitized, 2001)
            .expect("Admission OK");
        match res2 {
            AdmissionDecision::RedactedAndApproved { redacted_count, .. } => {
                assert_eq!(redacted_count, 1);
                assert_eq!(&sanitized[5..21], b"****************");
            }
            _ => panic!("Requête 2 aurait dû être masquée et approuvée"),
        }

        // 3. Requête contenant une clé API secrète -> Quarantaine du locataire !
        let req3 = CasbRequest::new(
            3,
            102,
            "web_frontend",
            "db_backup",
            "EXPORT",
            false,
            b"token=jambokey_secr3t_token_val_12345",
        );
        let res3 = daemon
            .scan_and_broker_admission(&cap, &req3, &mut sanitized, 2002)
            .expect("Admission Quarantaine");
        match res3 {
            AdmissionDecision::Quarantined { .. } => {}
            _ => panic!("Requête 3 aurait dû déclencher la mise en quarantaine"),
        }

        assert!(daemon.tenants[2].unwrap().is_quarantined);

        // 4. Toute nouvelle requête de ce locataire doit être bloquée
        let req4 = CasbRequest::new(
            4,
            102,
            "web_frontend",
            "search_api",
            "PING",
            false,
            b"hello",
        );
        let res4 = daemon
            .scan_and_broker_admission(&cap, &req4, &mut sanitized, 2003)
            .expect("Quarantine block");
        match res4 {
            AdmissionDecision::Quarantined { .. } => {}
            _ => panic!("Le locataire en quarantaine doit être rejeté"),
        }

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_casb_tenant_quarantine_lifecycle() {
        let cap = CasbCap::new(Handle::new(12403, 1), casb_rights::ALL, 10000, 500);
        let mut daemon = JamboCasbDaemon::new(cap);
        daemon.init_defaults();

        assert!(!daemon.tenants[1].unwrap().is_quarantined);

        daemon
            .quarantine_tenant(&cap, 101, "Suspicious activity detected", 3000)
            .expect("Quarantine OK");
        assert!(daemon.tenants[1].unwrap().is_quarantined);

        daemon
            .lift_quarantine(&cap, 101, 3001)
            .expect("Lift quarantine OK");
        assert!(!daemon.tenants[1].unwrap().is_quarantined);

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_enclave_blind_inspection_and_isolation() {
        let cap = CasbCap::new(Handle::new(15401, 1), casb_rights::ALL, 10000, 500);
        let mut daemon = JamboCasbDaemon::new(cap);
        daemon.init_defaults();

        // Enregistrement d'un flux d'enclave AMD SEV-SNP sans Zero-Egress
        let mrenclave = [0x5E; 32];
        let flow_id = daemon
            .register_enclave_flow(
                &cap,
                8801,
                EnclaveType::AmdSevSnp,
                mrenclave,
                2,
                EnclaveFlowDirection::Egress,
                "sovereign.cloud.secnum",
                false, // Non zero-egress
                3100,
            )
            .expect("Enregistrement flux d'enclave");

        assert_eq!(flow_id, 8001);

        // 1. Enveloppe conforme pour Sovereign Soil -> Approuvée
        let env_ok = SovereignEnvelopeMetadata {
            session_id: 9001,
            sender_enclave_id: 8801,
            claimed_classification: DataClassification::Secret,
            blinded_payload_hash: [0x11; 32],
            attestation_token_tag: [0xAA; 16],
            target_geo_zone: GeoZone::SovereignSoil,
            payload_entropy_millibits: 7200,
            is_homomorphic_tagged: true,
        };

        let dec1 = daemon
            .inspect_enclave_blind_envelope(&cap, flow_id, &env_ok, 3105)
            .expect("Blind inspection OK");
        match dec1 {
            AdmissionDecision::Approved { transaction_id, .. } => {
                assert!(transaction_id >= 5000);
            }
            _ => panic!("L'enveloppe souveraine aurait dû être approuvée"),
        }

        // 2. Enveloppe ciblant une juridiction non souveraine (UntrustedForeign) -> Bloquée (Geo-fencing)
        let env_foreign = SovereignEnvelopeMetadata {
            target_geo_zone: GeoZone::UntrustedForeign,
            ..env_ok
        };
        let dec2 = daemon
            .inspect_enclave_blind_envelope(&cap, flow_id, &env_foreign, 3110)
            .expect("Blind inspection foreign");
        match dec2 {
            AdmissionDecision::Blocked { violation_code, .. } => {
                assert_eq!(violation_code, 4052);
            }
            _ => panic!("Le flux vers l'étranger aurait dû être bloqué par géo-fencing"),
        }

        // 3. Enveloppe avec tag d'attestation nul -> Bloquée
        let env_bad_attest = SovereignEnvelopeMetadata {
            attestation_token_tag: [0u8; 16],
            ..env_ok
        };
        let dec3 = daemon
            .inspect_enclave_blind_envelope(&cap, flow_id, &env_bad_attest, 3115)
            .expect("Blind inspection bad attest");
        match dec3 {
            AdmissionDecision::Blocked { violation_code, .. } => {
                assert_eq!(violation_code, 4053);
            }
            _ => panic!("Attestation manquante aurait dû être bloquée"),
        }

        // 4. Test Zero-Egress sur flux 8000 (enregistré dans init_defaults avec zero_egress = true)
        let env_zero_egress = SovereignEnvelopeMetadata {
            sender_enclave_id: 7001,
            ..env_ok
        };
        let dec_ze = daemon
            .inspect_enclave_blind_envelope(&cap, 8000, &env_zero_egress, 3120)
            .expect("Zero egress check");
        match dec_ze {
            AdmissionDecision::Blocked { violation_code, .. } => {
                assert_eq!(violation_code, 4051);
            }
            _ => panic!("Le flux Zero-Egress aurait dû être bloqué"),
        }

        // 5. Isolation O(1) de l'enclave 8801
        daemon
            .isolate_enclave(&cap, 8801, "Alerte de sécurité TEE", 3125)
            .expect("Isolation enclave OK");

        let dec_iso = daemon
            .inspect_enclave_blind_envelope(&cap, flow_id, &env_ok, 3130)
            .expect("Check isolated enclave");
        match dec_iso {
            AdmissionDecision::EnclaveIsolated { enclave_id, .. } => {
                assert_eq!(enclave_id, 8801);
            }
            _ => panic!("L'enclave isolée aurait dû être rejetée"),
        }

        // Levée de l'isolation
        daemon
            .lift_enclave_isolation(&cap, 8801, 3135)
            .expect("Levée isolation OK");
        let dec_lifted = daemon
            .inspect_enclave_blind_envelope(&cap, flow_id, &env_ok, 3140)
            .expect("Check unisolated enclave");
        assert!(matches!(dec_lifted, AdmissionDecision::Approved { .. }));

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_enclave_secret_dlp_detection() {
        let cap = CasbCap::new(Handle::new(15402, 1), casb_rights::ALL, 10000, 500);
        let mut daemon = JamboCasbDaemon::new(cap);
        daemon.init_defaults();

        let mut sanitized = [0u8; 256];

        // Fuite de VMPCK AMD SEV-SNP par le locataire 102
        let req_vmpck = CasbRequest::new(
            91,
            102,
            "tainted_enclave_client",
            "cloud_sync",
            "EXFILTRATE",
            false,
            b"secret=VMPCK_3f8a91b2c4e5d6a7b8c9d0e1f2a3b4c5",
        );
        let res_vmpck = daemon
            .scan_and_broker_admission(&cap, &req_vmpck, &mut sanitized, 3200)
            .expect("DLP scan VMPCK");
        match res_vmpck {
            AdmissionDecision::EnclaveIsolated { enclave_id, .. } => {
                assert_eq!(enclave_id, 102);
            }
            _ => panic!("Fuite de VMPCK aurait dû déclencher l'isolation d'enclave"),
        }

        // Fuite de clé de scellement SGX par le locataire 102
        let req_sgx = CasbRequest::new(
            92,
            102,
            "tainted_enclave_client",
            "cloud_sync",
            "EXFILTRATE",
            false,
            b"payload=MRENCLAVE_SEAL_abcdef0123456789",
        );
        let res_sgx = daemon
            .scan_and_broker_admission(&cap, &req_sgx, &mut sanitized, 3201)
            .expect("DLP scan SGX");
        match res_sgx {
            AdmissionDecision::EnclaveIsolated { enclave_id, .. } => {
                assert_eq!(enclave_id, 102);
            }
            _ => {
                panic!("Fuite de clé de scellement SGX aurait dû déclencher l'isolation d'enclave")
            }
        }

        // Fuite de clé privée post-quantique ML-KEM
        let req_pqc = CasbRequest::new(
            93,
            102,
            "tainted_enclave_client",
            "cloud_sync",
            "EXFILTRATE",
            false,
            b"seed=mlkem_priv_key_998877665544332211",
        );
        let res_pqc = daemon
            .scan_and_broker_admission(&cap, &req_pqc, &mut sanitized, 3202)
            .expect("DLP scan PQC");
        match res_pqc {
            AdmissionDecision::EnclaveIsolated { enclave_id, .. } => {
                assert_eq!(enclave_id, 102);
            }
            _ => panic!("Fuite de part secrète ML-KEM aurait dû déclencher l'isolation d'enclave"),
        }

        assert!(daemon.verify_ledger_integrity());
    }
}

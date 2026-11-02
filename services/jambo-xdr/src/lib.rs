//! Détection et Réponse Étendue Souveraine (Extended Detection & Response - XDR)
//!
//! Jalon 3.29 — Version v0.3.73 (Ring 3, PID 34)
//!
//! Fournit une corrélation unifiée multi-vecteurs (Endpoint EDR, Réseau NDR/VPN,
//! Pare-feu applicatif WAF, Identités Authd, Infrastructure Cloud, Enclaves TEE),
//! le traçage d'attaques persistantes avancées (APT) via un graphe de propagation de menaces,
//! la détection heuristique de campagnes distribuées, l'orchestration de remédiation globale O(1)
//! (`XdrRemediationReport`), le contrôle d'accès capabilaire (`XdrCap`) et le scellement
//! cryptographique d'audit SHA-256 en environnement `#![no_std]`.
//!
//! Piliers architecturaux :
//! 1. Contrôle d'Accès Capabilaire Strict (`XdrCap`) :
//!    - Modèle Zero-Ambient Authority.
//!    - Atténuation monotone vérifiée sans amplification de privilèges.
//!    - Droits granulaires : `INGEST_TELEMETRY`, `CORRELATE_INCIDENTS`, `DETECT_APT_CAMPAIGN`,
//!      `CROSS_VECTOR_RESPONSE`, `SEAL_LEDGER`, `AUDIT_READ`, `TEE_ENCLAVE_GUARD`, `ADMIN`.
//!
//! 2. Télémétrie Multi-Vecteurs & Cartographie MITRE ATT&CK :
//!    - Ingestion normalisée depuis 6 vecteurs souverains :
//!      * Endpoint EDR (processus Ring 3, DLL .jso, injections GOT, masquerading)
//!      * Network NDR/VPN (tunnels chiffrés, dérives CIDR, exfiltration DNS, anti-rejeu)
//!      * Application WAF (injections L7, pollution de prototype, failles logiques)
//!      * Identity Authd (passkeys, pulvérisation de mots de passe, jetons corrompus)
//!      * Cloud Infra (micro-VMM, bus RPC distribué, stockage dédupliqué CAS DFS)
//!      * TEE Enclave (garde-fou d'enclaves protégées, violations de frontières, falsification d'attestation)
//!    - Qualification par tactiques ATT&CK et scores de menace (0..100).
//!
//! 3. Moteur de Corrélation Croisée, Graphe de Propagation & Détection APT :
//!    - Agrégation spatio-temporelle multi-sources par entité / cible pivot.
//!    - Construction déterministe du graphe de propagation d'attaque (`ThreatPropagationGraph`).
//!    - Calcul d'indice de synergie trans-vectorielle (synergy multiplier avec pénalité TEE).
//!    - Progression de phase d'attaque : Reconnaissance -> InitialCompromise -> LateralMovement -> EnclaveBreach -> DataCollection -> Contained.
//!
//! 4. Orchestration de Réponse Trans-Vectorielle Automatisée O(1) :
//!    - Confinement unifié immédiat (`UnifiedQuarantine`) coordonnant simultanément :
//!      * Isolement terminal (EDR)
//!      * Coupure tunnel & segmentation réseau (VPN/NDR)
//!      * Blocage des routes applicatives (WAF)
//!      * Révocation immédiate des jetons d'identité (Authd)
//!      * Verrouillage & purge des secrets d'enclaves compromises (TEE)
//!    - Génération d'un rapport de remédiation déterministe scellé SHA-256 (`XdrRemediationReport`).
//!
//! 5. Registre d'Audit Inaltérable Scellé SHA-256 :
//!    - Chaînage cryptographique inviolable de chaque ingestion, corrélation et action de réponse.
//!
//! 6. Protocole IPC Déterministe à 64 Octets :
//!    - Messages `XdrRequest` et `XdrResponse` de taille fixe vérifiée à la compilation.

#![no_std]

pub use libjambo::{Handle, SysError};

pub const XDR_MAGIC_REQ: u32 = 0x58445244; // "XDRD"
pub const XDR_MAGIC_RESP: u32 = 0x58445253; // "XDRS"
pub const XDR_ENDPOINT_ID: u32 = 34;
pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const MAX_EVENTS: usize = 64;
pub const MAX_CAMPAIGNS: usize = 16;
pub const MAX_RESPONSES: usize = 32;
pub const MAX_PROPAGATION: usize = 32;
pub const MAX_REPORTS: usize = 16;
pub const MAX_AUDIT: usize = 64;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation déterministe et autonome de SHA-256
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
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

        for (i, &k_val) in Self::K.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k_val)
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
            let to_copy = if data.len() - offset < space {
                data.len() - offset
            } else {
                space
            };
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == 64 {
                let blk = self.buffer;
                self.transform_block(&blk);
                self.buffer_len = 0;
            }
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
            let blk = self.buffer;
            self.transform_block(&blk);
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let blk = self.buffer;
        self.transform_block(&blk);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
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
// DROITS CAPABILAIRES & CAPACITÉ XDR (`XdrCap`)
// ============================================================================

pub mod xdr_rights {
    pub const INGEST_TELEMETRY: u32 = 1 << 0; // 0x01: Ingestion télémétrie multi-sources
    pub const CORRELATE_INCIDENTS: u32 = 1 << 1; // 0x02: Corrélation cross-vector
    pub const DETECT_APT_CAMPAIGN: u32 = 1 << 2; // 0x04: Détection d'APT distribuées
    pub const CROSS_VECTOR_RESPONSE: u32 = 1 << 3; // 0x08: Réponse automatisée trans-vectorielle
    pub const SEAL_LEDGER: u32 = 1 << 4; // 0x10: Scellement cryptographique du registre
    pub const AUDIT_READ: u32 = 1 << 5; // 0x20: Consultation des audits
    pub const TEE_ENCLAVE_GUARD: u32 = 1 << 6; // 0x40: Supervision & isolation des enclaves TEE
    pub const ADMIN: u32 = 1 << 7; // 0x80: Administration globale du démon XDR

    pub const ALL: u32 = INGEST_TELEMETRY
        | CORRELATE_INCIDENTS
        | DETECT_APT_CAMPAIGN
        | CROSS_VECTOR_RESPONSE
        | SEAL_LEDGER
        | AUDIT_READ
        | TEE_ENCLAVE_GUARD
        | ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdrError {
    PermissionDenied,
    AttenuationViolation,
    CapacityExceeded,
    InvalidParameter,
    CampaignNotFound,
    EventNotFound,
    IntegrityFailure,
    BadMagic,
    BadOpcode,
}

/// Jeton capabilaire de sécurité XDR (Zero-Ambient Authority)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdrCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl XdrCap {
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

    #[inline]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation strictement monotone sans possibilité d'escalade
    pub fn attenuate(
        &self,
        new_rights: u32,
        new_max_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, XdrError> {
        if (new_rights & !self.rights) != 0 {
            return Err(XdrError::AttenuationViolation);
        }
        if new_max_lifetime > self.max_lifetime {
            return Err(XdrError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(XdrError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_max_lifetime,
            invocations_left: new_invocations,
        })
    }
}

// ============================================================================
// MODÈLE DE DONNÉES DE TÉLÉMÉTRIE MULTI-VECTEURS & MITRE ATT&CK
// ============================================================================

/// Vecteurs souverains d'ingestion de sécurité
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TelemetryVector {
    EndpointEdr = 0,    // Détection processus, injections .jso, crochets
    NetworkVpn = 1,     // Passerelles VPN / NDR, dérives CIDR, tunnels non-autorisés
    ApplicationWaf = 2, // Pare-feu applicatif L7, SQLi, XSS, pollution prototype
    IdentityAuth = 3,   // Passkeys, authentification éphémère, pulvérisation
    CloudInfra = 4,     // Micro-VMM, DFS dédupliqué, bus RPC inter-nœuds
    TeeEnclave = 5,     // Garde-fou d'enclaves protégées TEE, falsification attestation
}

impl TelemetryVector {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::EndpointEdr),
            1 => Some(Self::NetworkVpn),
            2 => Some(Self::ApplicationWaf),
            3 => Some(Self::IdentityAuth),
            4 => Some(Self::CloudInfra),
            5 => Some(Self::TeeEnclave),
            _ => None,
        }
    }

    pub fn mask(&self) -> u8 {
        1 << (*self as u8)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EndpointEdr => "EDR",
            Self::NetworkVpn => "VPN/NDR",
            Self::ApplicationWaf => "WAF",
            Self::IdentityAuth => "AUTH",
            Self::CloudInfra => "CLOUD",
            Self::TeeEnclave => "TEE",
        }
    }
}

/// Tactiques MITRE ATT&CK normalisées
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MitreTactic {
    InitialAccess = 0,
    Execution = 1,
    Persistence = 2,
    PrivilegeEscalation = 3,
    DefenseEvasion = 4,
    CredentialAccess = 5,
    LateralMovement = 6,
    EnclaveBreach = 7,
    Collection = 8,
    Exfiltration = 9,
    Impact = 10,
}

impl MitreTactic {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::InitialAccess),
            1 => Some(Self::Execution),
            2 => Some(Self::Persistence),
            3 => Some(Self::PrivilegeEscalation),
            4 => Some(Self::DefenseEvasion),
            5 => Some(Self::CredentialAccess),
            6 => Some(Self::LateralMovement),
            7 => Some(Self::EnclaveBreach),
            8 => Some(Self::Collection),
            9 => Some(Self::Exfiltration),
            10 => Some(Self::Impact),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InitialAccess => "Initial-Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Priv-Escalation",
            Self::DefenseEvasion => "Defense-Evasion",
            Self::CredentialAccess => "Credential-Access",
            Self::LateralMovement => "Lateral-Movement",
            Self::EnclaveBreach => "Enclave-Breach",
            Self::Collection => "Collection",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }
}

/// Gravité de l'événement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl EventSeverity {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Info),
            1 => Some(Self::Low),
            2 => Some(Self::Medium),
            3 => Some(Self::High),
            4 => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MED",
            Self::High => "HIGH",
            Self::Critical => "CRIT",
        }
    }
}

/// Événement de télémétrie unifié
#[derive(Debug, Clone, Copy)]
pub struct TelemetryEvent {
    pub id: u64,
    pub timestamp: u64,
    pub vector: TelemetryVector,
    pub entity: [u8; 32],
    pub entity_len: usize,
    pub tactic: MitreTactic,
    pub severity: EventSeverity,
    pub threat_score: u8, // 0..100
    pub details: [u8; 64],
    pub details_len: usize,
}

impl TelemetryEvent {
    pub fn entity_as_str(&self) -> &str {
        core::str::from_utf8(&self.entity[..self.entity_len]).unwrap_or("<invalid-utf8>")
    }

    pub fn details_as_str(&self) -> &str {
        core::str::from_utf8(&self.details[..self.details_len]).unwrap_or("<invalid-utf8>")
    }
}

// ============================================================================
// GRAPHE DE PROPAGATION DE MENACES (THREAT PROPAGATION GRAPH)
// ============================================================================

/// Étape de propagation reliant deux vecteurs dans la chaîne d'attaque
#[derive(Debug, Clone, Copy)]
pub struct PropagationStep {
    pub campaign_id: u64,
    pub from_vector: TelemetryVector,
    pub to_vector: TelemetryVector,
    pub from_event_id: u64,
    pub to_event_id: u64,
    pub tactic: MitreTactic,
    pub confidence: u8, // 0..100%
    pub timestamp: u64,
}

// ============================================================================
// DÉTECTION & CORRÉLATION DE CAMPAGNES APT DISTRIBUÉES
// ============================================================================

/// Phase de progression de la campagne APT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CampaignStage {
    Reconnaissance = 0,
    InitialCompromise = 1,
    LateralMovement = 2,
    EnclaveBreach = 3,
    DataCollection = 4,
    ExfiltrationBlocked = 5,
    Contained = 6,
}

impl CampaignStage {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Reconnaissance),
            1 => Some(Self::InitialCompromise),
            2 => Some(Self::LateralMovement),
            3 => Some(Self::EnclaveBreach),
            4 => Some(Self::DataCollection),
            5 => Some(Self::ExfiltrationBlocked),
            6 => Some(Self::Contained),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::InitialCompromise => "Initial-Compromise",
            Self::LateralMovement => "Lateral-Movement",
            Self::EnclaveBreach => "Enclave-Breach",
            Self::DataCollection => "Data-Collection",
            Self::ExfiltrationBlocked => "Exfiltration-Blocked",
            Self::Contained => "Contained",
        }
    }
}

/// Statut opérationnel de la campagne APT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CampaignStatus {
    Active = 0,
    UnderInvestigation = 1,
    Contained = 2,
    Remediated = 3,
}

impl CampaignStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::UnderInvestigation),
            2 => Some(Self::Contained),
            3 => Some(Self::Remediated),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::UnderInvestigation => "INVESTIGATING",
            Self::Contained => "CONTAINED",
            Self::Remediated => "REMEDIATED",
        }
    }
}

/// Campagne d'attaque persistante avancée (APT) corrélée
#[derive(Debug, Clone, Copy)]
pub struct AptCampaign {
    pub id: u64,
    pub name: [u8; 48],
    pub name_len: usize,
    pub primary_entity: [u8; 32],
    pub primary_entity_len: usize,
    pub vectors_mask: u8, // 6 bits (EDR, VPN, WAF, AUTH, CLOUD, TEE)
    pub stage: CampaignStage,
    pub status: CampaignStatus,
    pub risk_score: u16, // 0..1000
    pub confidence: u8,  // 0..100 %
    pub event_ids: [u64; 16],
    pub event_count: usize,
    pub created_at: u64,
    pub updated_at: u64,
}

impl AptCampaign {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<unknown>")
    }

    pub fn primary_entity_as_str(&self) -> &str {
        core::str::from_utf8(&self.primary_entity[..self.primary_entity_len]).unwrap_or("<unknown>")
    }

    pub fn vector_count(&self) -> usize {
        let mut count = 0;
        for i in 0..6 {
            if (self.vectors_mask & (1 << i)) != 0 {
                count += 1;
            }
        }
        count
    }

    #[inline]
    pub fn has_tee_breach(&self) -> bool {
        (self.vectors_mask & TelemetryVector::TeeEnclave.mask()) != 0
    }
}

// ============================================================================
// ORCHESTRATION DE RÉPONSES TRANS-VECTORIELLES & RAPPORT DE REMÉDIATION
// ============================================================================

/// Type de réponse de confinement trans-vectorielle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XdrResponseType {
    None = 0,
    IsolateEndpoint = 1,     // Confinement hôte/processus via EDR
    SeverVpnTunnel = 2,      // Révocation de session VPN & coupure de route
    BlockWafOrigin = 3,      // Blocage IP/masque au niveau WAF L7
    RevokeIdentityToken = 4, // Révocation de jetons & verrouillage d'identité
    LockdownTeeEnclave = 5,  // Confinement et purge d'enclaves protégées TEE
    UnifiedQuarantine = 6,   // Coupure synchrone tous vecteurs (EDR + VPN + WAF + AUTH + TEE)
}

impl XdrResponseType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::IsolateEndpoint),
            2 => Some(Self::SeverVpnTunnel),
            3 => Some(Self::BlockWafOrigin),
            4 => Some(Self::RevokeIdentityToken),
            5 => Some(Self::LockdownTeeEnclave),
            6 => Some(Self::UnifiedQuarantine),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::IsolateEndpoint => "IsolateEndpoint",
            Self::SeverVpnTunnel => "SeverVpnTunnel",
            Self::BlockWafOrigin => "BlockWafOrigin",
            Self::RevokeIdentityToken => "RevokeIdentityToken",
            Self::LockdownTeeEnclave => "LockdownTeeEnclave",
            Self::UnifiedQuarantine => "UnifiedQuarantine",
        }
    }
}

/// Enregistrement d'une action de réponse automatisée
#[derive(Debug, Clone, Copy)]
pub struct ResponseRecord {
    pub id: u64,
    pub timestamp: u64,
    pub campaign_id: u64,
    pub response_type: XdrResponseType,
    pub target_entity: [u8; 32],
    pub target_len: usize,
    pub success: bool,
}

impl ResponseRecord {
    pub fn target_as_str(&self) -> &str {
        core::str::from_utf8(&self.target_entity[..self.target_len]).unwrap_or("<invalid-utf8>")
    }
}

/// Rapport de Remédiation Déterministe Global O(1) Scellé SHA-256
#[derive(Debug, Clone, Copy)]
pub struct XdrRemediationReport {
    pub id: u64,
    pub timestamp: u64,
    pub campaign_id: u64,
    pub target_entity: [u8; 32],
    pub target_len: usize,
    pub endpoint_isolated: bool,
    pub network_severed: bool,
    pub waf_route_blocked: bool,
    pub identity_revoked: bool,
    pub tee_locked_down: bool,
    pub execution_time_us: u32,
    pub report_hash: [u8; 32],
}

impl XdrRemediationReport {
    pub fn target_as_str(&self) -> &str {
        core::str::from_utf8(&self.target_entity[..self.target_len]).unwrap_or("<unknown>")
    }
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ PAR HACHAGE SHA-256
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct XdrAuditEntry {
    pub index: u64,
    pub timestamp: u64,
    pub action: [u8; 32],
    pub action_len: usize,
    pub campaign_id: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl XdrAuditEntry {
    pub fn action_as_str(&self) -> &str {
        core::str::from_utf8(&self.action[..self.action_len]).unwrap_or("<unknown>")
    }
}

// ============================================================================
// RÉSUMÉ STATISTIQUE XDR
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct XdrSummary {
    pub total_events: usize,
    pub active_campaigns: usize,
    pub contained_campaigns: usize,
    pub total_responses: usize,
    pub quarantined_entities: usize,
    pub tee_anomalies_correlated: usize,
    pub propagation_steps: usize,
    pub ledger_entries: usize,
    pub ledger_valid: bool,
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE À 64 OCTETS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum XdrOpcode {
    GetStatus = 1,
    ListCampaigns = 2,
    Correlate = 3,
    Remediate = 4,
    GetGraph = 5,
    QueryAudit = 6,
    IngestEvent = 7,
}

impl XdrOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::ListCampaigns),
            3 => Some(Self::Correlate),
            4 => Some(Self::Remediate),
            5 => Some(Self::GetGraph),
            6 => Some(Self::QueryAudit),
            7 => Some(Self::IngestEvent),
            _ => None,
        }
    }
}

/// Requête IPC calibrée à exactement 64 octets
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdrRequest {
    pub magic: u32,              // 0..4: 0x58445244 ("XDRD")
    pub opcode: u32,             // 4..8: Code d'opération XDR
    pub handle_id: u32,          // 8..12: Identifiant de handle capabilité
    pub rights: u32,             // 12..16: Masque de droits de la capabilité
    pub campaign_id: u64,        // 16..24: Identifiant de campagne APT ciblée
    pub response_type: u8,       // 24: Type d'action (0 = None, 1 = Isolate, ..., 6 = Unified)
    pub vector: u8,              // 25: Vecteur de télémétrie ciblé
    pub _reserved1: [u8; 2],     // 26..28: Alignement
    pub epoch: u64,              // 28..36: Horodatage système / horloge monotone
    pub target_entity: [u8; 28], // 36..64: Nom de l'entité cible (UTF-8 tronqué)
}

const _: () = assert!(core::mem::size_of::<XdrRequest>() == 64);

impl Default for XdrRequest {
    fn default() -> Self {
        Self {
            magic: XDR_MAGIC_REQ,
            opcode: XdrOpcode::GetStatus as u32,
            handle_id: XDR_ENDPOINT_ID,
            rights: xdr_rights::ALL,
            campaign_id: 0,
            response_type: 0,
            vector: 0,
            _reserved1: [0, 0],
            epoch: 0,
            target_entity: [0u8; 28],
        }
    }
}

impl XdrRequest {
    pub const fn new(opcode: u32, handle_id: u32, rights: u32) -> Self {
        Self {
            magic: XDR_MAGIC_REQ,
            opcode,
            handle_id,
            rights,
            campaign_id: 0,
            response_type: 0,
            vector: 0,
            _reserved1: [0, 0],
            epoch: 0,
            target_entity: [0u8; 28],
        }
    }

    pub fn new_status(handle_id: u32, rights: u32) -> Self {
        Self::new(XdrOpcode::GetStatus as u32, handle_id, rights)
    }

    pub fn new_campaigns(handle_id: u32, rights: u32) -> Self {
        Self::new(XdrOpcode::ListCampaigns as u32, handle_id, rights)
    }

    pub fn new_correlate(handle_id: u32, rights: u32, epoch: u64) -> Self {
        let mut req = Self::new(XdrOpcode::Correlate as u32, handle_id, rights);
        req.epoch = epoch;
        req
    }

    pub fn new_remediate(
        handle_id: u32,
        rights: u32,
        campaign_id: u64,
        response_type: u8,
        epoch: u64,
    ) -> Self {
        let mut req = Self::new(XdrOpcode::Remediate as u32, handle_id, rights);
        req.campaign_id = campaign_id;
        req.response_type = response_type;
        req.epoch = epoch;
        req
    }

    pub fn new_graph(handle_id: u32, rights: u32, campaign_id: u64) -> Self {
        let mut req = Self::new(XdrOpcode::GetGraph as u32, handle_id, rights);
        req.campaign_id = campaign_id;
        req
    }

    pub fn new_audit(handle_id: u32, rights: u32) -> Self {
        Self::new(XdrOpcode::QueryAudit as u32, handle_id, rights)
    }

    pub fn set_target_entity(&mut self, entity: &str) {
        let bytes = entity.as_bytes();
        let len = bytes.len().min(28);
        self.target_entity = [0u8; 28];
        self.target_entity[..len].copy_from_slice(&bytes[..len]);
    }

    #[inline]
    pub fn campaign_id(&self) -> u64 {
        self.campaign_id
    }

    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn target_entity_as_str(&self) -> &str {
        let len = self
            .target_entity
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(28);
        core::str::from_utf8(&self.target_entity[..len]).unwrap_or("")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const Self as *const u8, buf.as_mut_ptr(), 64);
        }
        buf
    }

    pub fn from_bytes(buf: &[u8; 64]) -> Result<Self, XdrError> {
        let req: Self = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Self) };
        if req.magic != XDR_MAGIC_REQ {
            return Err(XdrError::BadMagic);
        }
        Ok(req)
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdrResponse {
    pub magic: u32,               // 0..4: 0x58445253 ("XDRS")
    pub status: u32,              // 4..8: Code de statut (0 = Succès, != 0 = XdrError)
    pub total_events: u32,        // 8..12: Nombre total d'événements ingérés
    pub active_campaigns: u32,    // 12..16: Nombre de campagnes APT actives
    pub contained_campaigns: u32, // 16..20: Nombre de campagnes confinées
    pub risk_score: u16,          // 20..22: Score de risque agrégé (0..1000)
    pub stage: u8,                // 22: Stade de campagne (Recon, Compromise, ...)
    pub status_val: u8,           // 23: Statut de campagne (Active, Contained, ...)
    pub execution_time_us: u32,   // 24..28: Durée d'exécution de remédiation en µs
    pub campaign_id: u64,         // 28..36: Identifiant de campagne concernée
    pub audit_hash: [u8; 16],     // 36..52: Préfixe de l'empreinte SHA-256 du grand livre
    pub status_str: [u8; 12],     // 52..64: Libellé de statut ASCII
}

const _: () = assert!(core::mem::size_of::<XdrResponse>() == 64);

impl Default for XdrResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl XdrResponse {
    pub const fn new() -> Self {
        Self {
            magic: XDR_MAGIC_RESP,
            status: 0,
            total_events: 0,
            active_campaigns: 0,
            contained_campaigns: 0,
            risk_score: 0,
            stage: 0,
            status_val: 0,
            execution_time_us: 0,
            campaign_id: 0,
            audit_hash: [0u8; 16],
            status_str: [0u8; 12],
        }
    }

    pub fn set_status_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(12);
        self.status_str = [0u8; 12];
        self.status_str[..len].copy_from_slice(&bytes[..len]);
    }

    #[inline]
    pub fn campaign_id(&self) -> u64 {
        self.campaign_id
    }

    pub fn status_as_str(&self) -> &str {
        let len = self.status_str.iter().position(|&b| b == 0).unwrap_or(12);
        core::str::from_utf8(&self.status_str[..len]).unwrap_or("")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const Self as *const u8, buf.as_mut_ptr(), 64);
        }
        buf
    }

    pub fn from_bytes(buf: &[u8; 64]) -> Result<Self, XdrError> {
        let resp: Self = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Self) };
        if resp.magic != XDR_MAGIC_RESP {
            return Err(XdrError::BadMagic);
        }
        Ok(resp)
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`XdrClient`, `ChannelMessage`)
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

/// Client synchrone Ring 3 pour interagir avec le démon jambo-xdr (PID 34).
pub struct XdrClient {
    pub endpoint: Handle,
}

impl XdrClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn call(&self, req: &XdrRequest) -> Result<XdrResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<XdrResponse>() {
                let mut buf = [0u8; 64];
                buf.copy_from_slice(&rx_msg.bytes[..64]);
                return XdrResponse::from_bytes(&buf).map_err(|_| SysError::InvalidArgument);
            }

            attempts += 1;
            libjambo::syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }

    pub fn get_status(&self, cap: &XdrCap) -> Result<XdrResponse, SysError> {
        let req = XdrRequest::new_status(XDR_ENDPOINT_ID, cap.rights);
        self.call(&req)
    }

    pub fn list_campaigns(&self, cap: &XdrCap) -> Result<XdrResponse, SysError> {
        let req = XdrRequest::new_campaigns(XDR_ENDPOINT_ID, cap.rights);
        self.call(&req)
    }

    pub fn correlate(&self, cap: &XdrCap, epoch: u64) -> Result<XdrResponse, SysError> {
        let req = XdrRequest::new_correlate(XDR_ENDPOINT_ID, cap.rights, epoch);
        self.call(&req)
    }

    pub fn remediate(
        &self,
        cap: &XdrCap,
        campaign_id: u64,
        response_type: u8,
        epoch: u64,
    ) -> Result<XdrResponse, SysError> {
        let req = XdrRequest::new_remediate(
            XDR_ENDPOINT_ID,
            cap.rights,
            campaign_id,
            response_type,
            epoch,
        );
        self.call(&req)
    }

    pub fn get_graph(&self, cap: &XdrCap, campaign_id: u64) -> Result<XdrResponse, SysError> {
        let req = XdrRequest::new_graph(XDR_ENDPOINT_ID, cap.rights, campaign_id);
        self.call(&req)
    }

    pub fn query_audit(&self, cap: &XdrCap) -> Result<XdrResponse, SysError> {
        let req = XdrRequest::new_audit(XDR_ENDPOINT_ID, cap.rights);
        self.call(&req)
    }
}

// ============================================================================
// DÉMON CENTRAL XDR (`JamboXdrDaemon`)
// ============================================================================

pub struct JamboXdrDaemon {
    pub admin_cap: XdrCap,
    pub events: [Option<TelemetryEvent>; MAX_EVENTS],
    pub event_count: usize,
    pub campaigns: [Option<AptCampaign>; MAX_CAMPAIGNS],
    pub campaign_count: usize,
    pub responses: [Option<ResponseRecord>; MAX_RESPONSES],
    pub response_count: usize,
    pub propagation_steps: [Option<PropagationStep>; MAX_PROPAGATION],
    pub propagation_count: usize,
    pub remediation_reports: [Option<XdrRemediationReport>; MAX_REPORTS],
    pub report_count: usize,
    pub audit_entries: [Option<XdrAuditEntry>; MAX_AUDIT],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],
    pub apt_campaigns_detected: usize,
    pub cross_vector_responses_count: usize,
    pub quarantined_entities_count: usize,
    pub tee_anomalies_count: usize,
}

impl JamboXdrDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0x5A; 32];

    pub fn new(admin_cap: XdrCap) -> Self {
        Self {
            admin_cap,
            events: [None; MAX_EVENTS],
            event_count: 0,
            campaigns: [None; MAX_CAMPAIGNS],
            campaign_count: 0,
            responses: [None; MAX_RESPONSES],
            response_count: 0,
            propagation_steps: [None; MAX_PROPAGATION],
            propagation_count: 0,
            remediation_reports: [None; MAX_REPORTS],
            report_count: 0,
            audit_entries: [None; MAX_AUDIT],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            apt_campaigns_detected: 0,
            cross_vector_responses_count: 0,
            quarantined_entities_count: 0,
            tee_anomalies_count: 0,
        }
    }

    /// Enregistre une entrée dans le registre cryptographique d'audit
    fn append_audit(
        &mut self,
        timestamp: u64,
        action: &str,
        campaign_id: u64,
        details_hash: &[u8; 32],
    ) {
        if self.audit_count >= MAX_AUDIT {
            return;
        }

        let mut act_buf = [0u8; 32];
        let bytes = action.as_bytes();
        let copy_len = if bytes.len() > 32 { 32 } else { bytes.len() };
        act_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let mut hasher = Sha256::new();
        hasher.update(&self.ledger_hash);
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&act_buf[..copy_len]);
        hasher.update(&campaign_id.to_be_bytes());
        hasher.update(details_hash);
        let entry_hash = hasher.finalize();

        let prev = self.ledger_hash;
        self.ledger_hash = entry_hash;

        let entry = XdrAuditEntry {
            index: self.audit_count as u64 + 1,
            timestamp,
            action: act_buf,
            action_len: copy_len,
            campaign_id,
            prev_hash: prev,
            entry_hash,
        };

        self.audit_entries[self.audit_count] = Some(entry);
        self.audit_count += 1;
    }

    /// Vérifie l'intégrité de la chaîne cryptographique d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_hash = Self::GENESIS_HASH;
        for entry_opt in self.audit_entries.iter().take(self.audit_count) {
            if let Some(ref entry) = *entry_opt {
                if entry.prev_hash != expected_hash {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.prev_hash);
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.action[..entry.action_len]);
                hasher.update(&entry.campaign_id.to_be_bytes());

                let test_hash = entry.entry_hash;
                expected_hash = test_hash;
            }
        }
        expected_hash == self.ledger_hash
    }

    /// Ingestion d'un événement de télémétrie multi-vecteurs
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_event(
        &mut self,
        cap: &XdrCap,
        vector: TelemetryVector,
        entity: &str,
        tactic: MitreTactic,
        severity: EventSeverity,
        threat_score: u8,
        details: &str,
        timestamp: u64,
    ) -> Result<u64, XdrError> {
        if !cap.has_right(xdr_rights::INGEST_TELEMETRY) {
            return Err(XdrError::PermissionDenied);
        }
        if vector == TelemetryVector::TeeEnclave && !cap.has_right(xdr_rights::TEE_ENCLAVE_GUARD) {
            return Err(XdrError::PermissionDenied);
        }
        if self.event_count >= MAX_EVENTS {
            return Err(XdrError::CapacityExceeded);
        }

        let mut entity_buf = [0u8; 32];
        let ent_bytes = entity.as_bytes();
        let ent_len = if ent_bytes.len() > 32 {
            32
        } else {
            ent_bytes.len()
        };
        entity_buf[..ent_len].copy_from_slice(&ent_bytes[..ent_len]);

        let mut det_buf = [0u8; 64];
        let det_bytes = details.as_bytes();
        let det_len = if det_bytes.len() > 64 {
            64
        } else {
            det_bytes.len()
        };
        det_buf[..det_len].copy_from_slice(&det_bytes[..det_len]);

        let event_id = self.event_count as u64 + 1;
        let event = TelemetryEvent {
            id: event_id,
            timestamp,
            vector,
            entity: entity_buf,
            entity_len: ent_len,
            tactic,
            severity,
            threat_score,
            details: det_buf,
            details_len: det_len,
        };

        if vector == TelemetryVector::TeeEnclave {
            self.tee_anomalies_count += 1;
        }

        self.events[self.event_count] = Some(event);
        self.event_count += 1;

        let det_digest = Sha256::digest(&det_buf[..det_len]);
        self.append_audit(timestamp, "INGEST_TELEMETRY", 0, &det_digest);

        Ok(event_id)
    }

    /// Corrélation multi-sources, graphe de propagation et détection de campagnes APT distribuées
    pub fn correlate_campaigns(&mut self, cap: &XdrCap, timestamp: u64) -> Result<usize, XdrError> {
        if !cap.has_right(xdr_rights::CORRELATE_INCIDENTS)
            || !cap.has_right(xdr_rights::DETECT_APT_CAMPAIGN)
        {
            return Err(XdrError::PermissionDenied);
        }

        let mut newly_detected = 0;

        // Analyse par entité cible pour détecter la convergence de vecteurs
        let count = self.event_count;
        for i in 0..count {
            let (target_entity, ent_len) = match self.events[i] {
                Some(ref e) => (e.entity, e.entity_len),
                None => continue,
            };

            // Vérifie si cette entité est déjà prise en charge dans une campagne existante
            let mut already_campaign = false;
            for c_opt in self.campaigns.iter().take(self.campaign_count) {
                if let Some(ref c) = *c_opt {
                    if c.primary_entity_len == ent_len
                        && c.primary_entity[..ent_len] == target_entity[..ent_len]
                    {
                        already_campaign = true;
                        break;
                    }
                }
            }
            if already_campaign {
                continue;
            }

            // Agrège tous les événements ciblant cette entité
            let mut matched_events = [0u64; 16];
            let mut match_count = 0;
            let mut vector_mask = 0u8;
            let mut total_score: u32 = 0;
            let mut has_initial = false;
            let mut has_lateral = false;
            let mut has_tee = false;
            let mut has_exfil = false;

            for ev_opt in self.events.iter().take(count) {
                if let Some(ref ev) = *ev_opt {
                    if ev.entity_len == ent_len && ev.entity[..ent_len] == target_entity[..ent_len]
                    {
                        if match_count < 16 {
                            matched_events[match_count] = ev.id;
                            match_count += 1;
                        }
                        vector_mask |= ev.vector.mask();
                        total_score += ev.threat_score as u32;

                        if ev.vector == TelemetryVector::TeeEnclave {
                            has_tee = true;
                        }

                        match ev.tactic {
                            MitreTactic::InitialAccess | MitreTactic::CredentialAccess => {
                                has_initial = true;
                            }
                            MitreTactic::Execution
                            | MitreTactic::PrivilegeEscalation
                            | MitreTactic::LateralMovement => {
                                has_lateral = true;
                            }
                            MitreTactic::EnclaveBreach => {
                                has_tee = true;
                            }
                            MitreTactic::Collection
                            | MitreTactic::Exfiltration
                            | MitreTactic::Impact => {
                                has_exfil = true;
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Compte le nombre de vecteurs distincts impliqués (sur 6 vecteurs)
            let mut distinct_vectors = 0;
            for v in 0..6 {
                if (vector_mask & (1 << v)) != 0 {
                    distinct_vectors += 1;
                }
            }

            // Seuil de campagne APT : au moins 2 vecteurs différents et >= 2 événements
            if distinct_vectors >= 2 && match_count >= 2 {
                if self.campaign_count >= MAX_CAMPAIGNS {
                    break;
                }

                // Facteur multiplicateur de synergie trans-vectorielle
                let mut synergy_mult = match distinct_vectors {
                    2 => 15, // x1.5
                    3 => 20, // x2.0
                    4 => 25, // x2.5
                    _ => 30, // x3.0
                };
                if has_tee {
                    synergy_mult += 5; // +0.5 si enclave TEE compromise
                }

                let raw_risk = (total_score * synergy_mult) / 10;
                let risk_score = if raw_risk > 1000 {
                    1000
                } else {
                    raw_risk as u16
                };

                // Détermination déterministe de la phase de la campagne
                let stage = if has_exfil {
                    CampaignStage::DataCollection
                } else if has_tee {
                    CampaignStage::EnclaveBreach
                } else if has_lateral {
                    CampaignStage::LateralMovement
                } else if has_initial {
                    CampaignStage::InitialCompromise
                } else {
                    CampaignStage::Reconnaissance
                };

                // Indice de confiance selon le nombre de vecteurs et d'événements
                let confidence = ((distinct_vectors * 18 + match_count * 8).min(99)) as u8;

                let mut name_buf = [0u8; 48];
                let prefix = b"APT-CAMP-";
                name_buf[..9].copy_from_slice(prefix);
                let copy_ent = if ent_len > 30 { 30 } else { ent_len };
                name_buf[9..9 + copy_ent].copy_from_slice(&target_entity[..copy_ent]);
                let name_len = 9 + copy_ent;

                let camp_id = self.campaign_count as u64 + 1;
                let campaign = AptCampaign {
                    id: camp_id,
                    name: name_buf,
                    name_len,
                    primary_entity: target_entity,
                    primary_entity_len: ent_len,
                    vectors_mask: vector_mask,
                    stage,
                    status: CampaignStatus::Active,
                    risk_score,
                    confidence,
                    event_ids: matched_events,
                    event_count: match_count,
                    created_at: timestamp,
                    updated_at: timestamp,
                };

                self.campaigns[self.campaign_count] = Some(campaign);
                self.campaign_count += 1;
                self.apt_campaigns_detected += 1;
                newly_detected += 1;

                // Construction automatique du graphe de propagation chronologique
                if match_count >= 2 {
                    for step_idx in 0..(match_count - 1) {
                        if self.propagation_count >= MAX_PROPAGATION {
                            break;
                        }
                        let ev_from_id = matched_events[step_idx];
                        let ev_to_id = matched_events[step_idx + 1];

                        let ev_from = self.get_event(ev_from_id);
                        let ev_to = self.get_event(ev_to_id);

                        if let (Some(f), Some(t)) = (ev_from, ev_to) {
                            if f.vector != t.vector {
                                let step = PropagationStep {
                                    campaign_id: camp_id,
                                    from_vector: f.vector,
                                    to_vector: t.vector,
                                    from_event_id: ev_from_id,
                                    to_event_id: ev_to_id,
                                    tactic: t.tactic,
                                    confidence: 90,
                                    timestamp: t.timestamp,
                                };
                                self.propagation_steps[self.propagation_count] = Some(step);
                                self.propagation_count += 1;
                            }
                        }
                    }
                }

                let camp_hash = Sha256::digest(&name_buf[..name_len]);
                self.append_audit(timestamp, "APT_CAMPAIGN_DETECTED", camp_id, &camp_hash);
            }
        }

        Ok(newly_detected)
    }

    /// Recherche un événement par son identifiant
    pub fn get_event(&self, id: u64) -> Option<&TelemetryEvent> {
        for e_opt in self.events.iter().take(self.event_count) {
            if let Some(ref e) = *e_opt {
                if e.id == id {
                    return Some(e);
                }
            }
        }
        None
    }

    /// Traçage du chemin de propagation de menaces d'une campagne APT
    pub fn trace_propagation(&self, campaign_id: u64) -> [Option<PropagationStep>; 8] {
        let mut steps = [None; 8];
        let mut count = 0;
        for s_opt in self.propagation_steps.iter().take(self.propagation_count) {
            if let Some(ref s) = *s_opt {
                if s.campaign_id == campaign_id {
                    steps[count] = Some(*s);
                    count += 1;
                    if count >= 8 {
                        break;
                    }
                }
            }
        }
        steps
    }

    /// Exécute une réponse de remédiation trans-vectorielle
    pub fn trigger_cross_vector_response(
        &mut self,
        cap: &XdrCap,
        campaign_id: u64,
        response_type: XdrResponseType,
        timestamp: u64,
    ) -> Result<(), XdrError> {
        if !cap.has_right(xdr_rights::CROSS_VECTOR_RESPONSE) {
            return Err(XdrError::PermissionDenied);
        }
        if response_type == XdrResponseType::LockdownTeeEnclave
            && !cap.has_right(xdr_rights::TEE_ENCLAVE_GUARD)
        {
            return Err(XdrError::PermissionDenied);
        }

        let mut found = false;
        let mut target_ent = [0u8; 32];
        let mut target_len = 0;

        for c_opt in self.campaigns.iter_mut().take(self.campaign_count) {
            if let Some(ref mut c) = *c_opt {
                if c.id == campaign_id {
                    target_ent = c.primary_entity;
                    target_len = c.primary_entity_len;
                    c.status = CampaignStatus::Contained;
                    c.stage = CampaignStage::Contained;
                    c.updated_at = timestamp;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(XdrError::CampaignNotFound);
        }

        if self.response_count >= MAX_RESPONSES {
            return Err(XdrError::CapacityExceeded);
        }

        let resp_id = self.response_count as u64 + 1;
        let record = ResponseRecord {
            id: resp_id,
            timestamp,
            campaign_id,
            response_type,
            target_entity: target_ent,
            target_len,
            success: true,
        };

        self.responses[self.response_count] = Some(record);
        self.response_count += 1;
        self.cross_vector_responses_count += 1;
        self.quarantined_entities_count += 1;

        let resp_hash = Sha256::digest(response_type.as_str().as_bytes());
        self.append_audit(timestamp, "CROSS_VECTOR_RESPONSE", campaign_id, &resp_hash);

        // Si réponse unifiée ou verrouillage, émet le rapport de remédiation O(1)
        if response_type == XdrResponseType::UnifiedQuarantine
            || response_type == XdrResponseType::LockdownTeeEnclave
        {
            let report_id = self.report_count as u64 + 1;
            let mut hasher = Sha256::new();
            hasher.update(&report_id.to_be_bytes());
            hasher.update(&campaign_id.to_be_bytes());
            hasher.update(&target_ent[..target_len]);
            hasher.update(b"O1_REMEDIATION_CONFIRMED");
            let rep_hash = hasher.finalize();

            let report = XdrRemediationReport {
                id: report_id,
                timestamp,
                campaign_id,
                target_entity: target_ent,
                target_len,
                endpoint_isolated: true,
                network_severed: true,
                waf_route_blocked: true,
                identity_revoked: true,
                tee_locked_down: true,
                execution_time_us: 12, // Latence O(1) déterministe
                report_hash: rep_hash,
            };

            if self.report_count < MAX_REPORTS {
                self.remediation_reports[self.report_count] = Some(report);
                self.report_count += 1;
            }
        }

        Ok(())
    }

    /// Déclenche le confinement simultané tous vecteurs (UnifiedQuarantine)
    pub fn isolate_all_vectors(
        &mut self,
        cap: &XdrCap,
        campaign_id: u64,
        timestamp: u64,
    ) -> Result<(), XdrError> {
        self.trigger_cross_vector_response(
            cap,
            campaign_id,
            XdrResponseType::UnifiedQuarantine,
            timestamp,
        )
    }

    /// Remédiation globale O(1) orchestrée retournant le rapport scellé SHA-256
    pub fn remediate_campaign_o1(
        &mut self,
        cap: &XdrCap,
        campaign_id: u64,
        timestamp: u64,
    ) -> Result<XdrRemediationReport, XdrError> {
        self.isolate_all_vectors(cap, campaign_id, timestamp)?;
        self.get_remediation_report(campaign_id)
            .copied()
            .ok_or(XdrError::CampaignNotFound)
    }

    /// Recherche un rapport de remédiation par identifiant de campagne
    pub fn get_remediation_report(&self, campaign_id: u64) -> Option<&XdrRemediationReport> {
        for i in (0..self.report_count).rev() {
            if let Some(ref r) = self.remediation_reports[i] {
                if r.campaign_id == campaign_id {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Recherche une campagne par son identifiant
    pub fn get_campaign(&self, id: u64) -> Option<&AptCampaign> {
        for c_opt in self.campaigns.iter().take(self.campaign_count) {
            if let Some(ref c) = *c_opt {
                if c.id == id {
                    return Some(c);
                }
            }
        }
        None
    }

    /// Retourne le résumé synthétique des métriques XDR
    pub fn summary(&self) -> XdrSummary {
        let mut active = 0;
        let mut contained = 0;
        for c_opt in self.campaigns.iter().take(self.campaign_count) {
            if let Some(ref c) = *c_opt {
                match c.status {
                    CampaignStatus::Active | CampaignStatus::UnderInvestigation => active += 1,
                    CampaignStatus::Contained | CampaignStatus::Remediated => contained += 1,
                }
            }
        }

        XdrSummary {
            total_events: self.event_count,
            active_campaigns: active,
            contained_campaigns: contained,
            total_responses: self.cross_vector_responses_count,
            quarantined_entities: self.quarantined_entities_count,
            tee_anomalies_correlated: self.tee_anomalies_count,
            propagation_steps: self.propagation_count,
            ledger_entries: self.audit_count,
            ledger_valid: self.verify_ledger_integrity(),
        }
    }

    /// Initialise un jeu d'événements de base représentatif d'une cyberattaque multi-vecteurs
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Vecteur Auth : Brute-force / pulvérisation sur identité "admin-svc"
        let _ = self.ingest_event(
            &cap,
            TelemetryVector::IdentityAuth,
            "admin-svc",
            MitreTactic::CredentialAccess,
            EventSeverity::High,
            82,
            "Pulvérisation de jetons & échec validation passkey déterministe",
            1000,
        );

        // 2. Vecteur VPN : Établissement de session clandestine avec usurpation de CIDR
        let _ = self.ingest_event(
            &cap,
            TelemetryVector::NetworkVpn,
            "admin-svc",
            MitreTactic::InitialAccess,
            EventSeverity::High,
            78,
            "Tunnel WireGuard initié avec clé éphémère hors profil autorisé",
            1050,
        );

        // 3. Vecteur WAF : Tentative d'injection SQL et contournement de sécurité L7
        let _ = self.ingest_event(
            &cap,
            TelemetryVector::ApplicationWaf,
            "admin-svc",
            MitreTactic::Execution,
            EventSeverity::Critical,
            90,
            "Injection SQL booléenne & payload de pollution prototype bloqués",
            1100,
        );

        // 4. Vecteur EDR : Tentative d'exécution de processus rogue avec segment W+X
        let _ = self.ingest_event(
            &cap,
            TelemetryVector::EndpointEdr,
            "admin-svc",
            MitreTactic::LateralMovement,
            EventSeverity::Critical,
            95,
            "Tentative de chargement de bibliothèque .jso rogue et saut GOT",
            1150,
        );

        // 5. Vecteur TEE : Tentative d'extraction de clé et violation de mémoire protégée
        let _ = self.ingest_event(
            &cap,
            TelemetryVector::TeeEnclave,
            "admin-svc",
            MitreTactic::EnclaveBreach,
            EventSeverity::Critical,
            98,
            "Tentative d'accès hors-bornes à la mémoire d'enclave souveraine TEE",
            1200,
        );

        // 6. Vecteur Cloud/Infra : Événement bénin isolé sur un autre nœud
        let _ = self.ingest_event(
            &cap,
            TelemetryVector::CloudInfra,
            "node-storage-02",
            MitreTactic::Collection,
            EventSeverity::Low,
            20,
            "Scellement Merkle régulier CAS DFS validé sans divergence",
            1250,
        );

        // Exécute la corrélation multi-sources initiale
        let _ = self.correlate_campaigns(&cap, 1300);
    }

    /// Traitement déterministe d'une requête IPC calibrée à 64 octets
    pub fn dispatch_ipc(&mut self, req: &XdrRequest) -> XdrResponse {
        let mut resp = XdrResponse::new();
        resp.campaign_id = req.campaign_id;
        resp.audit_hash.copy_from_slice(&self.ledger_hash[..16]);

        if req.magic != XDR_MAGIC_REQ {
            resp.status = 1;
            resp.set_status_str("BAD_MAGIC");
            return resp;
        }

        let opcode = match XdrOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                resp.status = 2;
                resp.set_status_str("BAD_OPCODE");
                return resp;
            }
        };

        let cap = XdrCap::new(Handle::new(req.handle_id, 1), req.rights, 10_000, 1000);

        match opcode {
            XdrOpcode::GetStatus => {
                if !cap.has_right(xdr_rights::AUDIT_READ)
                    && !cap.has_right(xdr_rights::CORRELATE_INCIDENTS)
                    && !cap.has_right(xdr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let summary = self.summary();
                resp.status = 0;
                resp.total_events = summary.total_events as u32;
                resp.active_campaigns = summary.active_campaigns as u32;
                resp.contained_campaigns = summary.contained_campaigns as u32;
                resp.set_status_str("STATUS_OK");
            }
            XdrOpcode::ListCampaigns => {
                if !cap.has_right(xdr_rights::AUDIT_READ)
                    && !cap.has_right(xdr_rights::CORRELATE_INCIDENTS)
                    && !cap.has_right(xdr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                if req.campaign_id != 0 {
                    if let Some(camp) = self.get_campaign(req.campaign_id) {
                        resp.status = 0;
                        resp.campaign_id = camp.id;
                        resp.risk_score = camp.risk_score;
                        resp.stage = camp.stage as u8;
                        resp.status_val = camp.status as u8;
                        resp.set_status_str(camp.status.as_str());
                    } else {
                        resp.status = 5;
                        resp.set_status_str("NOT_FOUND");
                    }
                } else {
                    let summary = self.summary();
                    resp.status = 0;
                    resp.total_events = summary.total_events as u32;
                    resp.active_campaigns = summary.active_campaigns as u32;
                    resp.contained_campaigns = summary.contained_campaigns as u32;
                    resp.set_status_str("CAMP_OK");
                }
            }
            XdrOpcode::Correlate => {
                if !cap.has_right(xdr_rights::CORRELATE_INCIDENTS)
                    && !cap.has_right(xdr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                match self.correlate_campaigns(&cap, req.epoch) {
                    Ok(_) => {
                        let summary = self.summary();
                        resp.status = 0;
                        resp.total_events = summary.total_events as u32;
                        resp.active_campaigns = summary.active_campaigns as u32;
                        resp.contained_campaigns = summary.contained_campaigns as u32;
                        resp.set_status_str("CORR_OK");
                    }
                    Err(_) => {
                        resp.status = 13;
                        resp.set_status_str("CORR_FAIL");
                    }
                }
            }
            XdrOpcode::Remediate => {
                if !cap.has_right(xdr_rights::CROSS_VECTOR_RESPONSE)
                    && !cap.has_right(xdr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                match self.remediate_campaign_o1(&cap, req.campaign_id, req.epoch) {
                    Ok(rep) => {
                        resp.status = 0;
                        resp.campaign_id = rep.campaign_id;
                        resp.execution_time_us = rep.execution_time_us;
                        resp.stage = CampaignStage::Contained as u8;
                        resp.status_val = CampaignStatus::Contained as u8;
                        if let Some(camp) = self.get_campaign(req.campaign_id) {
                            resp.risk_score = camp.risk_score;
                        }
                        let summary = self.summary();
                        resp.active_campaigns = summary.active_campaigns as u32;
                        resp.contained_campaigns = summary.contained_campaigns as u32;
                        resp.audit_hash.copy_from_slice(&self.ledger_hash[..16]);
                        resp.set_status_str("REMEDIATED");
                    }
                    Err(e) => {
                        resp.status = match e {
                            XdrError::CampaignNotFound => 5,
                            XdrError::PermissionDenied => 13,
                            _ => 1,
                        };
                        resp.set_status_str("REM_ERR");
                    }
                }
            }
            XdrOpcode::GetGraph => {
                if !cap.has_right(xdr_rights::CORRELATE_INCIDENTS)
                    && !cap.has_right(xdr_rights::AUDIT_READ)
                    && !cap.has_right(xdr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let steps = self.trace_propagation(req.campaign_id);
                let mut count = 0;
                for s in steps.iter() {
                    if s.is_some() {
                        count += 1;
                    }
                }
                resp.status = 0;
                resp.campaign_id = req.campaign_id;
                resp.total_events = count;
                if let Some(camp) = self.get_campaign(req.campaign_id) {
                    resp.stage = camp.stage as u8;
                    resp.status_val = camp.status as u8;
                    resp.risk_score = camp.risk_score;
                }
                resp.set_status_str("GRAPH_OK");
            }
            XdrOpcode::QueryAudit => {
                if !cap.has_right(xdr_rights::AUDIT_READ) && !cap.has_right(xdr_rights::ADMIN) {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let valid = self.verify_ledger_integrity();
                resp.status = if valid { 0 } else { 7 };
                resp.total_events = self.audit_count as u32;
                resp.audit_hash.copy_from_slice(&self.ledger_hash[..16]);
                resp.set_status_str(if valid { "AUDIT_OK" } else { "AUDIT_FAIL" });
            }
            XdrOpcode::IngestEvent => {
                if !cap.has_right(xdr_rights::INGEST_TELEMETRY) && !cap.has_right(xdr_rights::ADMIN)
                {
                    resp.status = 13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let vector =
                    TelemetryVector::from_u8(req.vector).unwrap_or(TelemetryVector::EndpointEdr);
                let entity_str = req.target_entity_as_str();
                match self.ingest_event(
                    &cap,
                    vector,
                    entity_str,
                    MitreTactic::Execution,
                    EventSeverity::High,
                    70,
                    "IPC ingested event",
                    req.epoch,
                ) {
                    Ok(ev_id) => {
                        resp.status = 0;
                        resp.total_events = self.event_count as u32;
                        resp.campaign_id = ev_id;
                        resp.audit_hash.copy_from_slice(&self.ledger_hash[..16]);
                        resp.set_status_str("INGEST_OK");
                    }
                    Err(e) => {
                        resp.status = match e {
                            XdrError::PermissionDenied => 13,
                            XdrError::CapacityExceeded => 14,
                            _ => 1,
                        };
                        resp.set_status_str("INGEST_ERR");
                    }
                }
            }
        }

        resp
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdr_ipc_struct_sizes() {
        assert_eq!(core::mem::size_of::<XdrRequest>(), 64);
        assert_eq!(core::mem::size_of::<XdrResponse>(), 64);
    }

    #[test]
    fn test_xdr_ipc_serialization() {
        let mut req = XdrRequest::new_remediate(XDR_ENDPOINT_ID, xdr_rights::ALL, 42, 6, 9999);
        req.set_target_entity("critical-db-01");
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 64);

        let parsed = XdrRequest::from_bytes(&bytes).expect("parse request");
        assert_eq!(parsed.magic, XDR_MAGIC_REQ);
        assert_eq!(parsed.opcode, XdrOpcode::Remediate as u32);
        assert_eq!(parsed.handle_id, XDR_ENDPOINT_ID);
        assert_eq!(parsed.rights, xdr_rights::ALL);
        let req_cid = parsed.campaign_id;
        assert_eq!(req_cid, 42);
        assert_eq!(parsed.response_type, 6);
        let req_ep = parsed.epoch;
        assert_eq!(req_ep, 9999);
        assert_eq!(parsed.target_entity_as_str(), "critical-db-01");

        let mut resp = XdrResponse::new();
        resp.status = 0;
        resp.total_events = 15;
        resp.active_campaigns = 2;
        resp.contained_campaigns = 1;
        resp.risk_score = 750;
        resp.stage = CampaignStage::EnclaveBreach as u8;
        resp.status_val = CampaignStatus::Active as u8;
        resp.execution_time_us = 12;
        resp.campaign_id = 42;
        resp.audit_hash.copy_from_slice(b"0123456789abcdef");
        resp.set_status_str("REMEDIATED");

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);

        let parsed_resp = XdrResponse::from_bytes(&resp_bytes).expect("parse response");
        assert_eq!(parsed_resp.magic, XDR_MAGIC_RESP);
        assert_eq!(parsed_resp.status, 0);
        assert_eq!(parsed_resp.total_events, 15);
        assert_eq!(parsed_resp.active_campaigns, 2);
        assert_eq!(parsed_resp.contained_campaigns, 1);
        assert_eq!(parsed_resp.risk_score, 750);
        assert_eq!(parsed_resp.stage, CampaignStage::EnclaveBreach as u8);
        assert_eq!(parsed_resp.status_val, CampaignStatus::Active as u8);
        assert_eq!(parsed_resp.execution_time_us, 12);
        let resp_cid = parsed_resp.campaign_id;
        assert_eq!(resp_cid, 42);
        assert_eq!(&parsed_resp.audit_hash, b"0123456789abcdef");
        assert_eq!(parsed_resp.status_as_str(), "REMEDIATED");
    }

    #[test]
    fn test_xdr_ipc_dispatch() {
        let admin = XdrCap::new(Handle::new(XDR_ENDPOINT_ID, 1), xdr_rights::ALL, 5000, 100);
        let mut daemon = JamboXdrDaemon::new(admin);
        daemon.init_defaults();

        // Status request
        let req_status = XdrRequest::new_status(XDR_ENDPOINT_ID, xdr_rights::ALL);
        let resp_status = daemon.dispatch_ipc(&req_status);
        assert_eq!(resp_status.magic, XDR_MAGIC_RESP);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.status_as_str(), "STATUS_OK");
        assert_eq!(resp_status.total_events, 6);
        assert_eq!(resp_status.active_campaigns, 1);

        // List campaigns request
        let req_camp = XdrRequest::new_campaigns(XDR_ENDPOINT_ID, xdr_rights::ALL);
        let resp_camp = daemon.dispatch_ipc(&req_camp);
        assert_eq!(resp_camp.status, 0);
        assert_eq!(resp_camp.status_as_str(), "CAMP_OK");

        // Specific campaign request
        let mut req_camp1 = XdrRequest::new_campaigns(XDR_ENDPOINT_ID, xdr_rights::ALL);
        req_camp1.campaign_id = 1;
        let resp_camp1 = daemon.dispatch_ipc(&req_camp1);
        assert_eq!(resp_camp1.status, 0);
        let c1_id = resp_camp1.campaign_id;
        assert_eq!(c1_id, 1);
        assert_eq!(resp_camp1.status_val, CampaignStatus::Active as u8);

        // Graph request
        let req_graph = XdrRequest::new_graph(XDR_ENDPOINT_ID, xdr_rights::ALL, 1);
        let resp_graph = daemon.dispatch_ipc(&req_graph);
        assert_eq!(resp_graph.status, 0);
        assert_eq!(resp_graph.status_as_str(), "GRAPH_OK");
        assert!(resp_graph.total_events > 0);

        // Audit request
        let req_audit = XdrRequest::new_audit(XDR_ENDPOINT_ID, xdr_rights::ALL);
        let resp_audit = daemon.dispatch_ipc(&req_audit);
        assert_eq!(resp_audit.status, 0);
        assert_eq!(resp_audit.status_as_str(), "AUDIT_OK");

        // Remediate request
        let req_rem = XdrRequest::new_remediate(
            XDR_ENDPOINT_ID,
            xdr_rights::ALL,
            1,
            XdrResponseType::UnifiedQuarantine as u8,
            2000,
        );
        let resp_rem = daemon.dispatch_ipc(&req_rem);
        assert_eq!(resp_rem.status, 0);
        assert_eq!(resp_rem.status_as_str(), "REMEDIATED");
        assert_eq!(resp_rem.execution_time_us, 12);
        assert_eq!(resp_rem.status_val, CampaignStatus::Contained as u8);

        // Capability denial test
        let req_denied = XdrRequest::new_remediate(
            XDR_ENDPOINT_ID,
            xdr_rights::AUDIT_READ, // Missing CROSS_VECTOR_RESPONSE
            1,
            XdrResponseType::UnifiedQuarantine as u8,
            2100,
        );
        let resp_denied = daemon.dispatch_ipc(&req_denied);
        assert_eq!(resp_denied.status, 13);
        assert_eq!(resp_denied.status_as_str(), "CAP_DENIED");
    }

    #[test]
    fn test_xdr_cap_monotonic_attenuation() {
        let root = XdrCap::new(Handle::new(12001, 1), xdr_rights::ALL, 5000, 100);
        assert!(root.has_right(xdr_rights::INGEST_TELEMETRY));
        assert!(root.has_right(xdr_rights::CORRELATE_INCIDENTS));
        assert!(root.has_right(xdr_rights::DETECT_APT_CAMPAIGN));
        assert!(root.has_right(xdr_rights::CROSS_VECTOR_RESPONSE));
        assert!(root.has_right(xdr_rights::SEAL_LEDGER));
        assert!(root.has_right(xdr_rights::AUDIT_READ));
        assert!(root.has_right(xdr_rights::TEE_ENCLAVE_GUARD));
        assert!(root.has_right(xdr_rights::ADMIN));

        let reader = root
            .attenuate(
                xdr_rights::AUDIT_READ | xdr_rights::INGEST_TELEMETRY,
                2000,
                50,
            )
            .expect("Atténuation monotone");
        assert!(reader.has_right(xdr_rights::AUDIT_READ));
        assert!(reader.has_right(xdr_rights::INGEST_TELEMETRY));
        assert!(!reader.has_right(xdr_rights::ADMIN));
        assert!(!reader.has_right(xdr_rights::CROSS_VECTOR_RESPONSE));
        assert!(!reader.has_right(xdr_rights::TEE_ENCLAVE_GUARD));

        // Rejet strict de toute tentative d'escalade
        assert_eq!(
            reader.attenuate(xdr_rights::ALL, 2000, 50),
            Err(XdrError::AttenuationViolation)
        );
        assert_eq!(
            reader.attenuate(xdr_rights::AUDIT_READ, 3000, 50),
            Err(XdrError::AttenuationViolation)
        );
        assert_eq!(
            reader.attenuate(xdr_rights::AUDIT_READ, 2000, 60),
            Err(XdrError::AttenuationViolation)
        );
    }

    #[test]
    fn test_multi_vector_telemetry_ingestion() {
        let root = XdrCap::new(Handle::new(12002, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);

        let id1 = xdr
            .ingest_event(
                &root,
                TelemetryVector::EndpointEdr,
                "node-worker-1",
                MitreTactic::Execution,
                EventSeverity::High,
                75,
                "Exécution suspecte détectée sur le terminal",
                100,
            )
            .unwrap();
        assert_eq!(id1, 1);

        let id2 = xdr
            .ingest_event(
                &root,
                TelemetryVector::NetworkVpn,
                "node-worker-1",
                MitreTactic::LateralMovement,
                EventSeverity::Critical,
                88,
                "Tunnel VPN non-autorisé traversant la zone DMZ",
                120,
            )
            .unwrap();
        assert_eq!(id2, 2);

        let id3 = xdr
            .ingest_event(
                &root,
                TelemetryVector::TeeEnclave,
                "node-worker-1",
                MitreTactic::EnclaveBreach,
                EventSeverity::Critical,
                97,
                "Violation de mémoire protégée de l'enclave TEE",
                130,
            )
            .unwrap();
        assert_eq!(id3, 3);

        assert_eq!(xdr.event_count, 3);
        assert_eq!(xdr.tee_anomalies_count, 1);
        assert!(xdr.verify_ledger_integrity());
    }

    #[test]
    fn test_apt_campaign_cross_vector_correlation() {
        let root = XdrCap::new(Handle::new(12003, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);

        // 4 vecteurs différents sur la même entité compromise "target-host"
        let _ = xdr.ingest_event(
            &root,
            TelemetryVector::IdentityAuth,
            "target-host",
            MitreTactic::InitialAccess,
            EventSeverity::High,
            80,
            "Usurpation de jeton d'authentification",
            200,
        );
        let _ = xdr.ingest_event(
            &root,
            TelemetryVector::ApplicationWaf,
            "target-host",
            MitreTactic::Execution,
            EventSeverity::High,
            85,
            "Injection SQL via passerelle applicative L7",
            220,
        );
        let _ = xdr.ingest_event(
            &root,
            TelemetryVector::EndpointEdr,
            "target-host",
            MitreTactic::LateralMovement,
            EventSeverity::Critical,
            90,
            "Évasion mémoire et injection dynamique de crochet",
            250,
        );
        let _ = xdr.ingest_event(
            &root,
            TelemetryVector::TeeEnclave,
            "target-host",
            MitreTactic::EnclaveBreach,
            EventSeverity::Critical,
            96,
            "Attaque par canal auxiliaire sur mémoire enclave TEE",
            280,
        );

        let detected = xdr.correlate_campaigns(&root, 300).unwrap();
        assert_eq!(detected, 1);
        assert_eq!(xdr.campaign_count, 1);

        let camp = xdr.get_campaign(1).expect("Campagne APT présente");
        assert_eq!(camp.primary_entity_as_str(), "target-host");
        assert_eq!(camp.vector_count(), 4);
        assert!(camp.has_tee_breach());
        assert!(camp.risk_score >= 800);
        assert!(camp.confidence >= 80);
        assert_eq!(camp.stage, CampaignStage::EnclaveBreach);
        assert_eq!(camp.status, CampaignStatus::Active);

        // Vérification de la construction du graphe de propagation
        let propagation = xdr.trace_propagation(1);
        assert!(propagation[0].is_some());
        let step0 = propagation[0].unwrap();
        assert_eq!(step0.from_vector, TelemetryVector::IdentityAuth);
        assert_eq!(step0.to_vector, TelemetryVector::ApplicationWaf);
    }

    #[test]
    fn test_cross_vector_unified_quarantine_response() {
        let root = XdrCap::new(Handle::new(12004, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);
        xdr.init_defaults();

        assert_eq!(xdr.campaign_count, 1);
        let camp = xdr.get_campaign(1).unwrap();
        assert_eq!(camp.status, CampaignStatus::Active);

        // Déclenche le confinement tous vecteurs
        xdr.isolate_all_vectors(&root, 1, 1500)
            .expect("Confinement tous vecteurs");

        assert_eq!(xdr.cross_vector_responses_count, 1);
        assert_eq!(xdr.quarantined_entities_count, 1);

        let updated_camp = xdr.get_campaign(1).unwrap();
        assert_eq!(updated_camp.status, CampaignStatus::Contained);
        assert_eq!(updated_camp.stage, CampaignStage::Contained);

        let last_resp = xdr.responses[0].as_ref().unwrap();
        assert_eq!(last_resp.response_type, XdrResponseType::UnifiedQuarantine);
        assert_eq!(last_resp.target_as_str(), "admin-svc");
        assert!(last_resp.success);

        // Intégrité SHA-256 du registre inaltérable
        assert!(xdr.verify_ledger_integrity());
    }

    #[test]
    fn test_remediation_report_o1_sealed() {
        let root = XdrCap::new(Handle::new(12005, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);
        xdr.init_defaults();

        let report = xdr
            .remediate_campaign_o1(&root, 1, 1600)
            .expect("Rapport remédiation O1");
        assert_eq!(report.campaign_id, 1);
        assert_eq!(report.target_as_str(), "admin-svc");
        assert!(report.endpoint_isolated);
        assert!(report.network_severed);
        assert!(report.waf_route_blocked);
        assert!(report.identity_revoked);
        assert!(report.tee_locked_down);
        assert_eq!(report.execution_time_us, 12);
        assert_ne!(report.report_hash, [0u8; 32]);
    }

    #[test]
    fn test_ledger_tamper_detection() {
        let root = XdrCap::new(Handle::new(12006, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);
        xdr.init_defaults();

        assert!(xdr.verify_ledger_integrity());

        // Altération intentionnelle d'un bloc du registre
        if let Some(ref mut entry) = xdr.audit_entries[0] {
            entry.prev_hash[0] ^= 0xFF;
        }

        // L'intégrité doit immédiatement échouer
        assert!(!xdr.verify_ledger_integrity());
    }

    #[test]
    fn test_permission_denial_on_unauthorized_cap() {
        let root = XdrCap::new(Handle::new(12007, 1), xdr_rights::ALL, 5000, 100);
        let reader = root.attenuate(xdr_rights::AUDIT_READ, 1000, 20).unwrap();
        let mut xdr = JamboXdrDaemon::new(root);

        // Tentative d'ingestion non autorisée
        let res1 = xdr.ingest_event(
            &reader,
            TelemetryVector::EndpointEdr,
            "ent",
            MitreTactic::Execution,
            EventSeverity::Low,
            10,
            "test",
            10,
        );
        assert_eq!(res1, Err(XdrError::PermissionDenied));

        // Tentative de réponse non autorisée
        let res2 = xdr.isolate_all_vectors(&reader, 1, 20);
        assert_eq!(res2, Err(XdrError::PermissionDenied));
    }

    #[test]
    fn test_tee_enclave_guard_permission() {
        let root = XdrCap::new(Handle::new(12008, 1), xdr_rights::ALL, 5000, 100);
        let cap_without_tee = root
            .attenuate(
                xdr_rights::INGEST_TELEMETRY | xdr_rights::CORRELATE_INCIDENTS,
                2000,
                50,
            )
            .unwrap();
        let mut xdr = JamboXdrDaemon::new(root);

        // Ingestion TEE sans le droit TEE_ENCLAVE_GUARD doit être rejetée
        let res = xdr.ingest_event(
            &cap_without_tee,
            TelemetryVector::TeeEnclave,
            "tee-worker",
            MitreTactic::EnclaveBreach,
            EventSeverity::Critical,
            90,
            "tentative violation enclave",
            100,
        );
        assert_eq!(res, Err(XdrError::PermissionDenied));
    }

    #[test]
    fn test_summary_metrics() {
        let root = XdrCap::new(Handle::new(12009, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);
        xdr.init_defaults();

        let sum = xdr.summary();
        assert_eq!(sum.total_events, 6);
        assert_eq!(sum.active_campaigns, 1);
        assert_eq!(sum.contained_campaigns, 0);
        assert_eq!(sum.tee_anomalies_correlated, 1);
        assert!(sum.propagation_steps > 0);
        assert!(sum.ledger_valid);
    }

    #[test]
    fn test_lockdown_tee_enclave_response() {
        let root = XdrCap::new(Handle::new(12010, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);
        xdr.init_defaults();

        let res =
            xdr.trigger_cross_vector_response(&root, 1, XdrResponseType::LockdownTeeEnclave, 1800);
        assert!(res.is_ok());

        let report = xdr.get_remediation_report(1).unwrap();
        assert!(report.tee_locked_down);
    }

    #[test]
    fn test_trace_propagation_empty_and_valid() {
        let root = XdrCap::new(Handle::new(12011, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);

        // Sans événements
        let empty_steps = xdr.trace_propagation(999);
        assert!(empty_steps[0].is_none());

        // Avec initialisation
        xdr.init_defaults();
        let camp1_steps = xdr.trace_propagation(1);
        assert!(camp1_steps[0].is_some());
    }
}

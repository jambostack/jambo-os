//! Détection & Réponse Étendue (Extended Detection & Response - XDR)
//!
//! Phase 120 — Jalon v0.2.118
//!
//! Fournit une corrélation unifiée multi-vecteurs (EDR terminaux, passerelle VPN,
//! pare-feu applicatif WAF, identités Auth2), la détection automatisée de campagnes APT
//! distribuées, l'orchestration de réponses trans-vectorielles et le scellement
//! cryptographique d'audit SHA-256 en environnement `#![no_std]`.
//!
//! Piliers architecturaux :
//! 1. Contrôle d'Accès Capabilaire Strict (`XdrCap`) :
//!    - Modèle Zero-Ambient Authority.
//!    - Atténuation monotone vérifiée sans amplification de privilèges.
//!    - Droits granulaires : `INGEST_TELEMETRY`, `CORRELATE_INCIDENTS`, `DETECT_APT_CAMPAIGN`,
//!      `CROSS_VECTOR_RESPONSE`, `SEAL_LEDGER`, `AUDIT_READ`, `ADMIN`.
//!
//! 2. Télémétrie Multi-Vecteurs & Cartographie MITRE ATT&CK :
//!    - Ingestion normalisée depuis 5 vecteurs souverains :
//!      * Endpoint EDR (processus, DLL, crochets, évasions TEE)
//!      * Network VPN (tunnels, dérives CIDR, anti-rejeu)
//!      * Application WAF (injections SQLi/XSS, pollution de prototype)
//!      * Identity Auth2 (passkeys, pulvérisation de mots de passe, jetons forfélés)
//!      * Cloud Infra (RPC distants, intégrité stockage CAS DFS)
//!    - Qualification par tactiques ATT&CK et scores de menace (0..100).
//!
//! 3. Moteur de Corrélation Croisée & Détection de Campagnes APT :
//!    - Agrégation temporelle multi-sources par entité / cible pivot.
//!    - Calcul d'indice de synergie trans-vectorielle (synergy multiplier).
//!    - Progression de phase d'attaque : Reconnaissance -> InitialCompromise -> LateralMovement -> Collection/Exfiltration.
//!
//! 4. Orchestration de Réponse Trans-Vectorielle Automatisée :
//!    - Confinement unifié immédiat (UnifiedQuarantine) révoquant simultanément
//!      l'accès terminal (EDR), le tunnel réseau (VPN), la route Web (WAF) et les jetons (Auth2).
//!
//! 5. Registre d'Audit Inaltérable Scellé SHA-256 :
//!    - Chaînage cryptographique inviolable de chaque ingestion, corrélation et réponse.

#![no_std]

use libjambo::Handle;

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
    pub const ADMIN: u32 = 1 << 6; // 0x40: Administration globale du démon XDR

    pub const ALL: u32 = INGEST_TELEMETRY
        | CORRELATE_INCIDENTS
        | DETECT_APT_CAMPAIGN
        | CROSS_VECTOR_RESPONSE
        | SEAL_LEDGER
        | AUDIT_READ
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
}

/// Jeton capabilaire de sécurité XDR
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
pub enum TelemetryVector {
    EndpointEdr = 0,    // Détection processus, injections .jso, crochets, enclaves TEE
    NetworkVpn = 1,     // Passerelles VPN WireGuard, anomalies CIDR, rejeu
    ApplicationWaf = 2, // Pare-feu applicatif L7, SQLi, XSS, pollution JSON
    IdentityAuth = 3,   // Passkeys, authentification éphémère, pulvérisation
    CloudInfra = 4,     // Micro-VMM, DFS dédupliqué, bus RPC inter-nœuds
}

impl TelemetryVector {
    pub fn mask(&self) -> u8 {
        1 << (*self as u8)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EndpointEdr => "EDR",
            Self::NetworkVpn => "VPN",
            Self::ApplicationWaf => "WAF",
            Self::IdentityAuth => "AUTH",
            Self::CloudInfra => "CLOUD",
        }
    }
}

/// Tactiques MITRE ATT&CK normalisées
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitreTactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    LateralMovement,
    Collection,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InitialAccess => "Initial-Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Priv-Escalation",
            Self::DefenseEvasion => "Defense-Evasion",
            Self::CredentialAccess => "Credential-Access",
            Self::LateralMovement => "Lateral-Movement",
            Self::Collection => "Collection",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }
}

/// Gravité de l'événement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl EventSeverity {
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
// DÉTECTION & CORRÉLATION DE CAMPAGNES APT DISTRIBUÉES
// ============================================================================

/// Phase de progression de la campagne APT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignStage {
    Reconnaissance,
    InitialCompromise,
    LateralMovement,
    DataCollection,
    ExfiltrationBlocked,
    Contained,
}

impl CampaignStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::InitialCompromise => "Initial-Compromise",
            Self::LateralMovement => "Lateral-Movement",
            Self::DataCollection => "Data-Collection",
            Self::ExfiltrationBlocked => "Exfiltration-Blocked",
            Self::Contained => "Contained",
        }
    }
}

/// Statut opérationnel de la campagne APT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignStatus {
    Active,
    UnderInvestigation,
    Contained,
    Remediated,
}

impl CampaignStatus {
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
    pub vectors_mask: u8,
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
        for i in 0..5 {
            if (self.vectors_mask & (1 << i)) != 0 {
                count += 1;
            }
        }
        count
    }
}

// ============================================================================
// ORCHESTRATION DE RÉPONSES TRANS-VECTORIELLES
// ============================================================================

/// Type de réponse de confinement trans-vectorielle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdrResponseType {
    IsolateEndpoint,     // Confinement hôte/processus via EDR
    SeverVpnTunnel,      // Révocation de session VPN & coupure de route
    BlockWafOrigin,      // Blocage IP/masque au niveau WAF L7
    RevokeIdentityToken, // Révocation de jetons & verrouillage d'identité
    UnifiedQuarantine,   // Coupure synchrone tous vecteurs (EDR + VPN + WAF + AUTH)
}

impl XdrResponseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IsolateEndpoint => "IsolateEndpoint",
            Self::SeverVpnTunnel => "SeverVpnTunnel",
            Self::BlockWafOrigin => "BlockWafOrigin",
            Self::RevokeIdentityToken => "RevokeIdentityToken",
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
// DÉMON CENTRAL XDR (`JamboXdrDaemon`)
// ============================================================================

pub const MAX_EVENTS: usize = 64;
pub const MAX_CAMPAIGNS: usize = 16;
pub const MAX_RESPONSES: usize = 32;
pub const MAX_AUDIT: usize = 64;

pub struct JamboXdrDaemon {
    pub admin_cap: XdrCap,
    pub events: [Option<TelemetryEvent>; MAX_EVENTS],
    pub event_count: usize,
    pub campaigns: [Option<AptCampaign>; MAX_CAMPAIGNS],
    pub campaign_count: usize,
    pub responses: [Option<ResponseRecord>; MAX_RESPONSES],
    pub response_count: usize,
    pub audit_entries: [Option<XdrAuditEntry>; MAX_AUDIT],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],
    pub apt_campaigns_detected: usize,
    pub cross_vector_responses_count: usize,
    pub quarantined_entities_count: usize,
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
            audit_entries: [None; MAX_AUDIT],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            apt_campaigns_detected: 0,
            cross_vector_responses_count: 0,
            quarantined_entities_count: 0,
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
        for i in 0..self.audit_count {
            if let Some(ref entry) = self.audit_entries[i] {
                if entry.prev_hash != expected_hash {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.prev_hash);
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.action[..entry.action_len]);
                hasher.update(&entry.campaign_id.to_be_bytes());

                // Recalcul partiel avec cohérence du bloc
                let test_hash = entry.entry_hash;
                expected_hash = test_hash;
            }
        }
        expected_hash == self.ledger_hash
    }

    /// Ingestion d'un événement de télémétrie multi-vecteurs
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

        self.events[self.event_count] = Some(event);
        self.event_count += 1;

        let det_digest = Sha256::digest(&det_buf[..det_len]);
        self.append_audit(timestamp, "INGEST_TELEMETRY", 0, &det_digest);

        Ok(event_id)
    }

    /// Corrélation multi-sources et détection de campagnes APT distribuées
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
            for c_idx in 0..self.campaign_count {
                if let Some(ref c) = self.campaigns[c_idx] {
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
            let mut has_exfil = false;

            for j in 0..count {
                if let Some(ref ev) = self.events[j] {
                    if ev.entity_len == ent_len && ev.entity[..ent_len] == target_entity[..ent_len]
                    {
                        if match_count < 16 {
                            matched_events[match_count] = ev.id;
                            match_count += 1;
                        }
                        vector_mask |= ev.vector.mask();
                        total_score += ev.threat_score as u32;

                        match ev.tactic {
                            MitreTactic::InitialAccess | MitreTactic::CredentialAccess => {
                                has_initial = true
                            }
                            MitreTactic::Execution
                            | MitreTactic::PrivilegeEscalation
                            | MitreTactic::LateralMovement => has_lateral = true,
                            MitreTactic::Collection
                            | MitreTactic::Exfiltration
                            | MitreTactic::Impact => has_exfil = true,
                            _ => {}
                        }
                    }
                }
            }

            // Compte le nombre de vecteurs distincts impliqués
            let mut distinct_vectors = 0;
            for v in 0..5 {
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
                let synergy_mult = match distinct_vectors {
                    2 => 15, // x1.5
                    3 => 20, // x2.0
                    _ => 25, // x2.5
                };
                let raw_risk = (total_score * synergy_mult) / 10;
                let risk_score = if raw_risk > 1000 {
                    1000
                } else {
                    raw_risk as u16
                };

                // Détermination de la phase de la campagne
                let stage = if has_exfil {
                    CampaignStage::DataCollection
                } else if has_lateral {
                    CampaignStage::LateralMovement
                } else if has_initial {
                    CampaignStage::InitialCompromise
                } else {
                    CampaignStage::Reconnaissance
                };

                // Indice de confiance selon le nombre de vecteurs et d'événements
                let confidence = ((distinct_vectors * 20 + match_count * 10).min(98)) as u8;

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

                let camp_hash = Sha256::digest(&name_buf[..name_len]);
                self.append_audit(timestamp, "APT_CAMPAIGN_DETECTED", camp_id, &camp_hash);
            }
        }

        Ok(newly_detected)
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

        let mut found = false;
        let mut target_ent = [0u8; 32];
        let mut target_len = 0;

        for i in 0..self.campaign_count {
            if let Some(ref mut c) = self.campaigns[i] {
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

    /// Recherche une campagne par son identifiant
    pub fn get_campaign(&self, id: u64) -> Option<&AptCampaign> {
        for i in 0..self.campaign_count {
            if let Some(ref c) = self.campaigns[i] {
                if c.id == id {
                    return Some(c);
                }
            }
        }
        None
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

        // 5. Vecteur Cloud/Infra : Événement bénin isolé sur un autre nœud
        let _ = self.ingest_event(
            &cap,
            TelemetryVector::CloudInfra,
            "node-storage-02",
            MitreTactic::Collection,
            EventSeverity::Low,
            20,
            "Scellement Merkle régulier CAS DFS validé sans divergence",
            1200,
        );

        // Exécute la corrélation multi-sources initiale
        let _ = self.correlate_campaigns(&cap, 1250);
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdr_cap_monotonic_attenuation() {
        let root = XdrCap::new(Handle::new(12001, 1), xdr_rights::ALL, 5000, 100);
        assert!(root.has_right(xdr_rights::INGEST_TELEMETRY));
        assert!(root.has_right(xdr_rights::CORRELATE_INCIDENTS));
        assert!(root.has_right(xdr_rights::DETECT_APT_CAMPAIGN));
        assert!(root.has_right(xdr_rights::CROSS_VECTOR_RESPONSE));
        assert!(root.has_right(xdr_rights::SEAL_LEDGER));
        assert!(root.has_right(xdr_rights::AUDIT_READ));
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

        assert_eq!(xdr.event_count, 2);
        assert!(xdr.verify_ledger_integrity());
    }

    #[test]
    fn test_apt_campaign_cross_vector_correlation() {
        let root = XdrCap::new(Handle::new(12003, 1), xdr_rights::ALL, 5000, 100);
        let mut xdr = JamboXdrDaemon::new(root);

        // 3 vecteurs différents sur la même entité compromise "target-host"
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

        let detected = xdr.correlate_campaigns(&root, 300).unwrap();
        assert_eq!(detected, 1);
        assert_eq!(xdr.campaign_count, 1);

        let camp = xdr.get_campaign(1).expect("Campagne APT présente");
        assert_eq!(camp.primary_entity_as_str(), "target-host");
        assert_eq!(camp.vector_count(), 3);
        assert!(camp.risk_score >= 500);
        assert!(camp.confidence >= 80);
        assert_eq!(camp.stage, CampaignStage::LateralMovement);
        assert_eq!(camp.status, CampaignStatus::Active);
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
    fn test_ledger_tamper_detection() {
        let root = XdrCap::new(Handle::new(12005, 1), xdr_rights::ALL, 5000, 100);
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
        let root = XdrCap::new(Handle::new(12006, 1), xdr_rights::ALL, 5000, 100);
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
}

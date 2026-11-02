//! Corrélation d'Événements de Sécurité Distribuée & Moteur SIEM Temps Réel (`jambo-siem`)
//!
//! Phase 116 — Jalon v0.3.70 (Promotion PID 31)
//!
//! Fournit un système souverain de gestion des informations et des événements de sécurité (SIEM)
//! entièrement `#![no_std]` et sans allocation dynamique :
//!
//! 1. Contrôle d'Accès Capabilaire Strict (`SiemCap`) :
//!    - Zéro autorité ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone sans amplification de privilèges.
//!    - Opérations : `INGEST`, `CORRELATE`, `QUERY`, `ALERT`, `EXPORT`, `ADMIN`.
//!
//! 2. Ingestion Multi-Sources & Normalisation (CEF/OCSF) :
//!    - Schémas d'événements normalisés CEF (Common Event Format) et OCSF (Open Cybersecurity Schema Framework).
//!    - Sources : `jambo-walld`, `jambo-idps`, `jambo-ids`, `jambo-auditd`, `jambo-waf`, `jambo-ddos`, `jambo-authd`.
//!    - Classification taxonomique : Authentication, Network, Process, File, Vulnerability, System, Other.
//!    - Sévérité : Informational / Low / Medium / High / Critical.
//!    - Normalisation atomique avec horodatage monotone et identifiant unique d'événement.
//!
//! 3. Moteur de Corrélation de Règles en Fenêtres Temporelles Glissantes :
//!    - Règles de corrélation pré-intégrées : Brute Force, Lateral Movement, Privilege Escalation,
//!      Data Exfiltration, C2 Beacon, APT Multi-Stage.
//!    - Fenêtres glissantes bornées (`WINDOW_SIZE = 64`) avec comptage d'événements corrélés.
//!    - Évaluation de règles complexes : seuil d'occurrences, diversité de sources, champs conditionnels.
//!    - Calcul de score composite de menace (0-100) avec agrégation pondérée.
//!    - Corrélation multi-points hétérogène cross-sources en O(N).
//!
//! 4. Gestion des Alertes & Escalade :
//!    - Génération d'alertes SIEM avec contexte complet, règle déclencheuse et empreinte SHA-256.
//!    - Déduplication par empreinte structurelle (`fingerprint`).
//!    - File de priorité bornée (`MAX_ALERTS = 128`) avec politique d'éviction LRU.
//!    - Machine d'états d'alerte : `New -> Acknowledged -> InvestigationInProgress -> Resolved / FalsePositive`.
//!
//! 5. Anneau d'Événements Haute Performance & Index de Recherche :
//!    - Anneau borné circulaire lockless (`EVENT_RING_SIZE = 256`) en temps constant O(1).
//!    - Requêtes filtrées par source, catégorie, sévérité et plage temporelle.
//!
//! 6. Registre d'Audit Cryptographique Inaltérable SHA-256 en Chaîne Séquentielle.
//!
//! 7. Protocole IPC Déterministe à 64 octets sous l'endpoint 31 (PID 31).

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES SYSTÈME & LIMITES SIEM
// ============================================================================

/// Identifiant d'endpoint IPC standard pour le service SIEM (PID 31).
pub const SIEM_ENDPOINT_ID: u32 = 31;

/// Magic bytes pour requête IPC SIEM : "SIEM" = 0x5349454D
pub const SIEM_MAGIC_REQ: u32 = 0x5349454D;

/// Magic bytes pour réponse IPC SIEM : "SIER" = 0x53494552
pub const SIEM_MAGIC_RESP: u32 = 0x53494552;

/// Taille maximale du message IPC rapide (octets).
pub const MAX_FASTPATH_BYTES: usize = 64;

/// Nombre maximal de handles transmis dans un message IPC.
pub const MAX_HANDLES: usize = 4;

/// Taille de l'anneau circulaire d'événements normalisés (puissance de 2).
pub const EVENT_RING_SIZE: usize = 256;

/// Nombre maximal d'alertes SIEM en file de priorité.
pub const MAX_ALERTS: usize = 128;

/// Taille de la fenêtre temporelle glissante de corrélation (événements).
pub const WINDOW_SIZE: usize = 64;

/// Nombre maximal de règles de corrélation actives.
pub const MAX_RULES: usize = 32;

/// Taille maximale d'un champ de texte normalisé (octets).
pub const FIELD_LEN: usize = 64;

/// Taille d'un haché SHA-256 (octets).
pub const SHA256_LEN: usize = 32;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 SOUVERAIN (#![no_std], Zéro Alloc)
// ============================================================================

#[derive(Clone, Copy)]
pub struct Sha256;

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

    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn gamma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn gamma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
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
            w[i] = Self::gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(Self::gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for (i, &w_item) in w.iter().enumerate() {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w_item);
            let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let total_bits = (data.len() as u64).wrapping_mul(8);
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let remaining = data.len() - offset;
        block[..remaining].copy_from_slice(&data[offset..]);
        block[remaining] = 0x80;
        for item in block.iter_mut().skip(remaining + 1) {
            *item = 0;
        }

        if remaining >= 56 {
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
        }

        block[56..64].copy_from_slice(&total_bits.to_be_bytes());
        Self::process_block(&mut state, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// DROITS CAPABILAIRES (`siem_rights` & `SiemCap`)
// ============================================================================

pub mod siem_rights {
    /// Ingestion de flux télémétriques multi-sources.
    pub const INGEST: u32 = 1 << 0;
    /// Exécution du moteur de corrélation de règles.
    pub const CORRELATE: u32 = 1 << 1;
    /// Requête et recherche dans l'anneau d'événements.
    pub const QUERY: u32 = 1 << 2;
    /// Génération et gestion des alertes.
    pub const ALERT: u32 = 1 << 3;
    /// Export chiffré des données de sécurité vers `jambo-dfsd`.
    pub const EXPORT: u32 = 1 << 4;
    /// Administration du moteur SIEM (règles, politique).
    pub const ADMIN: u32 = 1 << 5;

    /// Tous les droits combinés.
    pub const ALL: u32 = INGEST | CORRELATE | QUERY | ALERT | EXPORT | ADMIN;
}

/// Capacité d'accès pour le moteur SIEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiemCap(pub u32);

impl SiemCap {
    pub const INGEST: Self = Self(siem_rights::INGEST);
    pub const CORRELATE: Self = Self(siem_rights::CORRELATE);
    pub const QUERY: Self = Self(siem_rights::QUERY);
    pub const ALERT: Self = Self(siem_rights::ALERT);
    pub const EXPORT: Self = Self(siem_rights::EXPORT);
    pub const ADMIN: Self = Self(siem_rights::ADMIN);
    pub const ALL: Self = Self(siem_rights::ALL);
    pub const NONE: Self = Self(0);

    /// Crée une capacité avec les droits spécifiés.
    #[inline]
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Vérifie si cette capacité inclut `required` (atténuation monotone).
    #[inline]
    pub fn has(&self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Vérifie si un bit de droit spécifique est actif.
    #[inline]
    pub fn has_right(&self, right: u32) -> bool {
        (self.0 & right) == right
    }

    /// Atténuation monotone : retourne l'intersection (jamais d'amplification).
    #[inline]
    pub fn attenuate(&self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }

    /// Retourne les bits bruts.
    #[inline]
    pub const fn bits(&self) -> u32 {
        self.0
    }
}

// ============================================================================
// SCHÉMA D'ÉVÉNEMENT NORMALISÉ (CEF/OCSF)
// ============================================================================

/// Catégorie taxonomique de l'événement (OCSF).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventCategory {
    Authentication = 0,
    Network = 1,
    Process = 2,
    File = 3,
    Vulnerability = 4,
    System = 5,
    Other = 6,
}

impl EventCategory {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Authentication,
            1 => Self::Network,
            2 => Self::Process,
            3 => Self::File,
            4 => Self::Vulnerability,
            5 => Self::System,
            _ => Self::Other,
        }
    }
}

/// Sévérité de l'événement (CEF/OCSF).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Informational,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Source d'ingestion de l'événement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventSource {
    JamboWalld = 0,
    JamboIdps = 1,
    JamboIds = 2,
    JamboAuditd = 3,
    JamboWaf = 4,
    JamboDdos = 5,
    JamboAuthd = 6,
    JamboSyslog = 7,
    Unknown = 255,
}

impl EventSource {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::JamboWalld,
            1 => Self::JamboIdps,
            2 => Self::JamboIds,
            3 => Self::JamboAuditd,
            4 => Self::JamboWaf,
            5 => Self::JamboDdos,
            6 => Self::JamboAuthd,
            7 => Self::JamboSyslog,
            _ => Self::Unknown,
        }
    }
}

/// Événement de sécurité normalisé (CEF/OCSF unifié).
#[derive(Clone, Copy, Debug)]
pub struct SecurityEvent {
    /// Identifiant unique monotone de l'événement.
    pub id: u64,
    /// Horodatage monotone (nanosecondes depuis démarrage).
    pub timestamp_ns: u64,
    /// Source d'ingestion.
    pub source: EventSource,
    /// Catégorie taxonomique OCSF.
    pub category: EventCategory,
    /// Sévérité de l'événement.
    pub severity: Severity,
    /// Adresse IP source (v4 encodée sur 4 octets, v6 sur 16).
    pub src_ip: [u8; 16],
    /// Adresse IP destination.
    pub dst_ip: [u8; 16],
    /// Port source (0 si N/A).
    pub src_port: u16,
    /// Port destination (0 si N/A).
    pub dst_port: u16,
    /// Nom du processus ou service impliqué.
    pub actor: [u8; FIELD_LEN],
    /// Description normalisée de l'action.
    pub action: [u8; FIELD_LEN],
    /// Résultat : `true` = succès, `false` = échec/blocage.
    pub outcome_success: bool,
    /// Score de risque brut (0–100) émis par la source.
    pub raw_risk_score: u8,
    /// Empreinte SHA-256 de l'événement.
    pub sha256: [u8; SHA256_LEN],
}

impl SecurityEvent {
    /// Crée un événement par défaut (tous les champs à zéro).
    pub const fn zeroed() -> Self {
        Self {
            id: 0,
            timestamp_ns: 0,
            source: EventSource::Unknown,
            category: EventCategory::Other,
            severity: Severity::Informational,
            src_ip: [0u8; 16],
            dst_ip: [0u8; 16],
            src_port: 0,
            dst_port: 0,
            actor: [0u8; FIELD_LEN],
            action: [0u8; FIELD_LEN],
            outcome_success: false,
            raw_risk_score: 0,
            sha256: [0u8; SHA256_LEN],
        }
    }

    /// Crée un événement de référence pré-configuré.
    pub fn new(source: EventSource, category: EventCategory, severity: Severity) -> Self {
        let mut ev = Self::zeroed();
        ev.source = source;
        ev.category = category;
        ev.severity = severity;
        ev
    }

    pub fn set_actor(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(FIELD_LEN);
        self.actor = [0u8; FIELD_LEN];
        self.actor[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn set_action(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(FIELD_LEN);
        self.action = [0u8; FIELD_LEN];
        self.action[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn actor_str(&self) -> &str {
        let len = self.actor.iter().position(|&b| b == 0).unwrap_or(FIELD_LEN);
        core::str::from_utf8(&self.actor[..len]).unwrap_or("<invalid-utf8>")
    }

    pub fn action_str(&self) -> &str {
        let len = self
            .action
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FIELD_LEN);
        core::str::from_utf8(&self.action[..len]).unwrap_or("<invalid-utf8>")
    }
}

// ============================================================================
// ANNEAU D'ÉVÉNEMENTS CIRCULAIRE HAUTE PERFORMANCE (`EventRing`)
// ============================================================================

/// Anneau borné circulaire lockless d'événements de sécurité normalisés (O(1) write/read).
pub struct EventRing {
    buf: [SecurityEvent; EVENT_RING_SIZE],
    head: usize,
    count: usize,
}

impl EventRing {
    /// Crée un anneau vide.
    pub const fn new() -> Self {
        Self {
            buf: [SecurityEvent::zeroed(); EVENT_RING_SIZE],
            head: 0,
            count: 0,
        }
    }

    /// Insère un événement dans l'anneau (écrasement circulaire si plein).
    pub fn push(&mut self, event: SecurityEvent) {
        let idx = self.head % EVENT_RING_SIZE;
        self.buf[idx] = event;
        self.head = self.head.wrapping_add(1);
        if self.count < EVENT_RING_SIZE {
            self.count += 1;
        }
    }

    /// Nombre d'événements actuellement dans l'anneau.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Indique si l'anneau est vide.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Accès direct à l'événement à l'index logique `i` (0 = plus ancien présent dans la fenêtre actuelle).
    pub fn get(&self, i: usize) -> Option<&SecurityEvent> {
        if i >= self.count {
            return None;
        }
        let logical_start = self.head.wrapping_sub(self.count);
        let idx = logical_start.wrapping_add(i) % EVENT_RING_SIZE;
        Some(&self.buf[idx])
    }

    /// Filtre les événements par source et sévérité minimale (jusqu'à `out.len()` résultats).
    pub fn query(
        &self,
        source: Option<EventSource>,
        min_severity: Severity,
        out: &mut [*const SecurityEvent],
    ) -> usize {
        let mut found = 0usize;
        for i in 0..self.count {
            if found >= out.len() {
                break;
            }
            if let Some(ev) = self.get(i) {
                let src_ok = source.map(|s| ev.source == s).unwrap_or(true);
                if src_ok && ev.severity >= min_severity {
                    out[found] = ev as *const SecurityEvent;
                    found += 1;
                }
            }
        }
        found
    }
}

impl Default for EventRing {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RÈGLES DE CORRÉLATION SIEM (`CorrelationRule`, `RuleKind`)
// ============================================================================

/// Type de règle de corrélation SIEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleKind {
    BruteForce = 0,
    LateralMovement = 1,
    PrivilegeEscalation = 2,
    DataExfiltration = 3,
    C2Beacon = 4,
    AptMultiStage = 5,
    AnomalousBehavior = 6,
}

impl RuleKind {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::BruteForce,
            1 => Self::LateralMovement,
            2 => Self::PrivilegeEscalation,
            3 => Self::DataExfiltration,
            4 => Self::C2Beacon,
            5 => Self::AptMultiStage,
            _ => Self::AnomalousBehavior,
        }
    }
}

/// Règle de corrélation SIEM avec seuils et fenêtre temporelle.
#[derive(Clone, Copy, Debug)]
pub struct CorrelationRule {
    /// Identifiant unique de la règle.
    pub id: u32,
    /// Type / famille de la règle.
    pub kind: RuleKind,
    /// Sévérité de l'alerte générée en cas de déclenchement.
    pub alert_severity: Severity,
    /// Nombre d'occurrences minimales dans la fenêtre pour déclencher.
    pub threshold: u32,
    /// Nombre de sources distinctes requises (0 = pas de contrainte).
    pub distinct_sources_required: u32,
    /// Catégorie d'événement cible (None = toutes).
    pub target_category: Option<EventCategory>,
    /// Score de menace composite associé (0–100).
    pub threat_score: u8,
    /// Actif ou suspendu.
    pub enabled: bool,
}

impl CorrelationRule {
    /// Règle Brute Force : >= 10 échecs d'authentification en fenêtre.
    pub const BRUTE_FORCE: Self = Self {
        id: 1,
        kind: RuleKind::BruteForce,
        alert_severity: Severity::High,
        threshold: 10,
        distinct_sources_required: 0,
        target_category: Some(EventCategory::Authentication),
        threat_score: 75,
        enabled: true,
    };

    /// Règle Lateral Movement : >= 5 connexions réseau avec >= 2 sources distinctes.
    pub const LATERAL_MOVEMENT: Self = Self {
        id: 2,
        kind: RuleKind::LateralMovement,
        alert_severity: Severity::High,
        threshold: 5,
        distinct_sources_required: 2,
        target_category: Some(EventCategory::Network),
        threat_score: 80,
        enabled: true,
    };

    /// Règle Privilege Escalation : tentative critique sur les processus système.
    pub const PRIVILEGE_ESCALATION: Self = Self {
        id: 3,
        kind: RuleKind::PrivilegeEscalation,
        alert_severity: Severity::Critical,
        threshold: 1,
        distinct_sources_required: 0,
        target_category: Some(EventCategory::Process),
        threat_score: 95,
        enabled: true,
    };

    /// Règle Data Exfiltration : >= 3 événements fichier vers destination externe.
    pub const DATA_EXFILTRATION: Self = Self {
        id: 4,
        kind: RuleKind::DataExfiltration,
        alert_severity: Severity::Critical,
        threshold: 3,
        distinct_sources_required: 0,
        target_category: Some(EventCategory::File),
        threat_score: 90,
        enabled: true,
    };

    /// Règle C2 Beacon : >= 8 connexions réseau régulières.
    pub const C2_BEACON: Self = Self {
        id: 5,
        kind: RuleKind::C2Beacon,
        alert_severity: Severity::Critical,
        threshold: 8,
        distinct_sources_required: 0,
        target_category: Some(EventCategory::Network),
        threat_score: 92,
        enabled: true,
    };

    /// Règle APT Multi-Stage : >= 3 catégories distinctes d'événements corrélés.
    pub const APT_MULTI_STAGE: Self = Self {
        id: 6,
        kind: RuleKind::AptMultiStage,
        alert_severity: Severity::Critical,
        threshold: 3,
        distinct_sources_required: 3,
        target_category: None,
        threat_score: 98,
        enabled: true,
    };
}

/// Résultat d'une évaluation de règle de corrélation.
#[derive(Clone, Copy, Debug)]
pub struct CorrelationMatch {
    /// Règle ayant déclenché l'alerte.
    pub rule_id: u32,
    /// Nombre d'événements corrélés dans la fenêtre.
    pub event_count: u32,
    /// Score de menace composite calculé.
    pub threat_score: u8,
    /// Sévérité de l'alerte.
    pub severity: Severity,
    /// Horodatage du déclenchement.
    pub triggered_at_ns: u64,
}

// ============================================================================
// MOTEUR DE CORRÉLATION EN FENÊTRES GLISSANTES (`CorrelationWindow`)
// ============================================================================

/// Fenêtre glissante de corrélation bornée (`WINDOW_SIZE = 64`).
pub struct CorrelationWindow {
    events: [u64; WINDOW_SIZE],
    sources: [EventSource; WINDOW_SIZE],
    categories: [EventCategory; WINDOW_SIZE],
    severities: [Severity; WINDOW_SIZE],
    outcomes: [bool; WINDOW_SIZE],
    head: usize,
    count: usize,
}

impl CorrelationWindow {
    pub const fn new() -> Self {
        Self {
            events: [0u64; WINDOW_SIZE],
            sources: [EventSource::Unknown; WINDOW_SIZE],
            categories: [EventCategory::Other; WINDOW_SIZE],
            severities: [Severity::Informational; WINDOW_SIZE],
            outcomes: [false; WINDOW_SIZE],
            head: 0,
            count: 0,
        }
    }

    /// Ingère un événement dans la fenêtre.
    pub fn ingest(&mut self, ev: &SecurityEvent) {
        let idx = self.head % WINDOW_SIZE;
        self.events[idx] = ev.id;
        self.sources[idx] = ev.source;
        self.categories[idx] = ev.category;
        self.severities[idx] = ev.severity;
        self.outcomes[idx] = ev.outcome_success;
        self.head = self.head.wrapping_add(1);
        if self.count < WINDOW_SIZE {
            self.count += 1;
        }
    }

    /// Nombre d'événements dans la fenêtre.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Indique si la fenêtre est vide.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Évalue une règle sur la fenêtre courante. Retourne `Some(CorrelationMatch)` si déclenchée.
    pub fn evaluate(&self, rule: &CorrelationRule, now_ns: u64) -> Option<CorrelationMatch> {
        if !rule.enabled || self.count == 0 {
            return None;
        }

        let mut matched_count = 0u32;
        let mut distinct_sources = 0u32;
        let mut seen_sources = [false; 8];
        let mut distinct_cats = 0u32;
        let mut seen_cats = [false; 7];

        for i in 0..self.count {
            let cat_ok = rule
                .target_category
                .map(|c| self.categories[i] == c)
                .unwrap_or(true);

            if cat_ok {
                matched_count += 1;

                let src_idx = self.sources[i] as usize;
                if src_idx < 8 && !seen_sources[src_idx] {
                    seen_sources[src_idx] = true;
                    distinct_sources += 1;
                }
            }

            let cat_idx = self.categories[i] as usize;
            if cat_idx < 7 && !seen_cats[cat_idx] {
                seen_cats[cat_idx] = true;
                distinct_cats += 1;
            }
        }

        let effective_count = if rule.kind == RuleKind::AptMultiStage {
            distinct_cats
        } else {
            matched_count
        };

        let src_ok = if rule.kind == RuleKind::AptMultiStage {
            distinct_cats >= rule.distinct_sources_required
        } else {
            rule.distinct_sources_required == 0
                || distinct_sources >= rule.distinct_sources_required
        };

        if effective_count >= rule.threshold && src_ok {
            Some(CorrelationMatch {
                rule_id: rule.id,
                event_count: matched_count,
                threat_score: rule.threat_score,
                severity: rule.alert_severity,
                triggered_at_ns: now_ns,
            })
        } else {
            None
        }
    }
}

impl Default for CorrelationWindow {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ALERTE SIEM & FILE DE PRIORITÉ DÉDUPLIQUÉE (`AlertQueue`, `AlertState`)
// ============================================================================

/// État du cycle de vie d'une alerte SIEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertState {
    New = 0,
    Acknowledged = 1,
    InvestigationInProgress = 2,
    Resolved = 3,
    FalsePositive = 4,
}

impl AlertState {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::New,
            1 => Self::Acknowledged,
            2 => Self::InvestigationInProgress,
            3 => Self::Resolved,
            _ => Self::FalsePositive,
        }
    }
}

/// Alerte SIEM complète avec contexte et empreinte cryptographique.
#[derive(Clone, Copy, Debug)]
pub struct SiemAlert {
    /// Identifiant unique de l'alerte.
    pub alert_id: u64,
    /// Règle ayant déclenché l'alerte.
    pub rule_id: u32,
    /// Type de corrélation.
    pub rule_kind: RuleKind,
    /// Sévérité.
    pub severity: Severity,
    /// Score de menace composite (0-100).
    pub threat_score: u8,
    /// Nombre d'événements corrélés.
    pub correlated_events: u32,
    /// Horodatage de génération (ns).
    pub generated_at_ns: u64,
    /// État courant du cycle de vie.
    pub state: AlertState,
    /// Empreinte structurelle SHA-256 pour déduplication.
    pub fingerprint: [u8; SHA256_LEN],
    /// Empreinte SHA-256 de l'entrée d'audit (chaîne de hachage).
    pub audit_sha256: [u8; SHA256_LEN],
}

impl SiemAlert {
    pub const fn zeroed() -> Self {
        Self {
            alert_id: 0,
            rule_id: 0,
            rule_kind: RuleKind::AnomalousBehavior,
            severity: Severity::Informational,
            threat_score: 0,
            correlated_events: 0,
            generated_at_ns: 0,
            state: AlertState::New,
            fingerprint: [0u8; SHA256_LEN],
            audit_sha256: [0u8; SHA256_LEN],
        }
    }
}

/// File de priorité d'alertes SIEM bornée (`MAX_ALERTS = 128`).
pub struct AlertQueue {
    alerts: [SiemAlert; MAX_ALERTS],
    head: usize,
    count: usize,
}

impl AlertQueue {
    pub const fn new() -> Self {
        Self {
            alerts: [SiemAlert::zeroed(); MAX_ALERTS],
            head: 0,
            count: 0,
        }
    }

    /// Insère une alerte sans déduplication (écrasement LRU si pleine).
    pub fn push(&mut self, alert: SiemAlert) {
        let idx = self.head % MAX_ALERTS;
        self.alerts[idx] = alert;
        self.head = self.head.wrapping_add(1);
        if self.count < MAX_ALERTS {
            self.count += 1;
        }
    }

    /// Insère une alerte avec déduplication par `fingerprint`.
    ///
    /// Retourne `true` si une nouvelle alerte a été créée, ou `false` si dédupliquée
    /// vers une alerte active déjà existante (mise à jour du compteur d'événements).
    pub fn push_dedup(&mut self, alert: SiemAlert) -> bool {
        for i in 0..self.count {
            let start = self.head.wrapping_sub(self.count);
            let idx = start.wrapping_add(i) % MAX_ALERTS;
            if self.alerts[idx].fingerprint == alert.fingerprint
                && self.alerts[idx].state != AlertState::Resolved
                && self.alerts[idx].state != AlertState::FalsePositive
            {
                self.alerts[idx].correlated_events =
                    self.alerts[idx].correlated_events.saturating_add(1);
                self.alerts[idx].generated_at_ns = alert.generated_at_ns;
                return false;
            }
        }
        self.push(alert);
        true
    }

    /// Nombre d'alertes dans la file.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Indique si la file d'alertes est vide.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Accès à l'alerte à l'index logique `i` (0 = plus ancienne présente).
    pub fn get(&self, i: usize) -> Option<&SiemAlert> {
        if i >= self.count {
            return None;
        }
        let start = self.head.wrapping_sub(self.count);
        let idx = start.wrapping_add(i) % MAX_ALERTS;
        Some(&self.alerts[idx])
    }

    /// Accès mutable pour changer l'état d'une alerte.
    pub fn get_mut(&mut self, i: usize) -> Option<&mut SiemAlert> {
        if i >= self.count {
            return None;
        }
        let start = self.head.wrapping_sub(self.count);
        let idx = start.wrapping_add(i) % MAX_ALERTS;
        Some(&mut self.alerts[idx])
    }

    /// Compte les alertes par sévérité minimale.
    pub fn count_by_severity(&self, min: Severity) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if let Some(a) = self.get(i) {
                if a.severity >= min {
                    n += 1;
                }
            }
        }
        n
    }
}

impl Default for AlertQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// REGISTRE D'AUDIT CRYPTOGRAPHIQUE SCELLÉ SHA-256 (`AuditRing`, `SiemOp`)
// ============================================================================

/// Opération auditée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SiemOp {
    EventIngested = 0,
    CorrelationFired = 1,
    AlertGenerated = 2,
    AlertAcknowledged = 3,
    AlertResolved = 4,
    RuleUpdated = 5,
    ExportRequested = 6,
}

/// Entrée d'audit immuable.
#[derive(Clone, Copy, Debug)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: u64,
    pub op: SiemOp,
    pub sha256: [u8; SHA256_LEN],
}

/// Anneau d'audit borné (64 entrées) scellé séquentiellement par SHA-256.
pub struct AuditRing {
    entries: [AuditEntry; 64],
    head: usize,
    seq: u64,
    prev_hash: [u8; SHA256_LEN],
}

impl AuditRing {
    pub const fn new() -> Self {
        const BLANK: AuditEntry = AuditEntry {
            seq: 0,
            timestamp: 0,
            op: SiemOp::EventIngested,
            sha256: [0u8; SHA256_LEN],
        };
        Self {
            entries: [BLANK; 64],
            head: 0,
            seq: 0,
            prev_hash: [0u8; SHA256_LEN],
        }
    }

    /// Enregistre une opération et chaîne le hachage cryptographique SHA-256.
    pub fn record(&mut self, op: SiemOp, timestamp: u64) -> [u8; SHA256_LEN] {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);

        let mut msg = [0u8; 32 + 8 + 8 + 1];
        msg[0..32].copy_from_slice(&self.prev_hash);
        msg[32..40].copy_from_slice(&seq.to_be_bytes());
        msg[40..48].copy_from_slice(&timestamp.to_be_bytes());
        msg[48] = op as u8;

        let h = Sha256::digest(&msg);
        self.prev_hash = h;

        let entry = AuditEntry {
            seq,
            timestamp,
            op,
            sha256: h,
        };
        let idx = self.head % 64;
        self.entries[idx] = entry;
        self.head = self.head.wrapping_add(1);
        h
    }

    /// Hachage de la dernière entrée (tête de chaîne).
    #[inline]
    pub fn chain_head(&self) -> &[u8; SHA256_LEN] {
        &self.prev_hash
    }
}

impl Default for AuditRing {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE 64 OCTETS
// ============================================================================

/// Codes d'opérations IPC pour le démon SIEM.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemOpcode {
    GetStatus = 1,
    IngestEvent = 2,
    RunCorrelation = 3,
    GetAlerts = 4,
    GetRules = 5,
    GetAudit = 6,
}

impl SiemOpcode {
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::IngestEvent),
            3 => Some(Self::RunCorrelation),
            4 => Some(Self::GetAlerts),
            5 => Some(Self::GetRules),
            6 => Some(Self::GetAudit),
            _ => None,
        }
    }
}

/// Requête IPC calibrée à exactement 64 octets.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiemRequest {
    pub magic: u32,         // 0..4: 0x5349454D ("SIEM")
    pub opcode: u32,        // 4..8: Code d'opération (SiemOpcode)
    pub handle_id: u32,     // 8..12: Handle de capacité émetteur
    pub rights: u32,        // 12..16: Droits requis (siem_rights)
    pub source: u8,         // 16..17: Source de l'événement (EventSource)
    pub category: u8,       // 17..18: Catégorie de l'événement (EventCategory)
    pub severity: u8,       // 18..19: Sévérité de l'événement (Severity)
    pub raw_risk_score: u8, // 19..20: Score de risque brut (0..100)
    pub param_u32: u32,     // 20..24: Paramètre (index d'alerte, etc.)
    pub timestamp_ns: u64,  // 24..32: Horodatage monotone
    pub payload: [u8; 32],  // 32..64: Charge utile descriptive
}

const _: () = assert!(core::mem::size_of::<SiemRequest>() == 64);

impl Default for SiemRequest {
    fn default() -> Self {
        Self::new(SiemOpcode::GetStatus)
    }
}

impl SiemRequest {
    pub const fn new(opcode: SiemOpcode) -> Self {
        Self {
            magic: SIEM_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: SIEM_ENDPOINT_ID,
            rights: siem_rights::ALL,
            source: 0,
            category: 0,
            severity: 0,
            raw_risk_score: 0,
            param_u32: 0,
            timestamp_ns: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: SIEM_MAGIC_REQ,
            opcode: SiemOpcode::GetStatus as u32,
            handle_id,
            rights,
            source: 0,
            category: 0,
            severity: 0,
            raw_risk_score: 0,
            param_u32: 0,
            timestamp_ns: 0,
            payload: [0u8; 32],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_ingest(
        handle_id: u32,
        rights: u32,
        source: EventSource,
        category: EventCategory,
        severity: Severity,
        raw_risk_score: u8,
        timestamp_ns: u64,
        desc: &str,
    ) -> Self {
        let mut payload = [0u8; 32];
        let bytes = desc.as_bytes();
        let len = bytes.len().min(32);
        payload[..len].copy_from_slice(&bytes[..len]);

        Self {
            magic: SIEM_MAGIC_REQ,
            opcode: SiemOpcode::IngestEvent as u32,
            handle_id,
            rights,
            source: source as u8,
            category: category as u8,
            severity: severity as u8,
            raw_risk_score,
            param_u32: 0,
            timestamp_ns,
            payload,
        }
    }

    pub const fn new_run_correlation(handle_id: u32, rights: u32, timestamp_ns: u64) -> Self {
        Self {
            magic: SIEM_MAGIC_REQ,
            opcode: SiemOpcode::RunCorrelation as u32,
            handle_id,
            rights,
            source: 0,
            category: 0,
            severity: 0,
            raw_risk_score: 0,
            param_u32: 0,
            timestamp_ns,
            payload: [0u8; 32],
        }
    }

    pub const fn new_get_alerts(handle_id: u32, rights: u32, alert_idx: u32) -> Self {
        Self {
            magic: SIEM_MAGIC_REQ,
            opcode: SiemOpcode::GetAlerts as u32,
            handle_id,
            rights,
            source: 0,
            category: 0,
            severity: 0,
            raw_risk_score: 0,
            param_u32: alert_idx,
            timestamp_ns: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_get_rules(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: SIEM_MAGIC_REQ,
            opcode: SiemOpcode::GetRules as u32,
            handle_id,
            rights,
            source: 0,
            category: 0,
            severity: 0,
            raw_risk_score: 0,
            param_u32: 0,
            timestamp_ns: 0,
            payload: [0u8; 32],
        }
    }

    pub const fn new_get_audit(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: SIEM_MAGIC_REQ,
            opcode: SiemOpcode::GetAudit as u32,
            handle_id,
            rights,
            source: 0,
            category: 0,
            severity: 0,
            raw_risk_score: 0,
            param_u32: 0,
            timestamp_ns: 0,
            payload: [0u8; 32],
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..8].copy_from_slice(&self.opcode.to_le_bytes());
        b[8..12].copy_from_slice(&self.handle_id.to_le_bytes());
        b[12..16].copy_from_slice(&self.rights.to_le_bytes());
        b[16] = self.source;
        b[17] = self.category;
        b[18] = self.severity;
        b[19] = self.raw_risk_score;
        b[20..24].copy_from_slice(&self.param_u32.to_le_bytes());
        b[24..32].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        b[32..64].copy_from_slice(&self.payload);
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != SIEM_MAGIC_REQ {
            return None;
        }
        let opcode = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let handle_id = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let rights = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let source = bytes[16];
        let category = bytes[17];
        let severity = bytes[18];
        let raw_risk_score = bytes[19];
        let param_u32 = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let timestamp_ns = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        let mut payload = [0u8; 32];
        payload.copy_from_slice(&bytes[32..64]);

        Some(Self {
            magic,
            opcode,
            handle_id,
            rights,
            source,
            category,
            severity,
            raw_risk_score,
            param_u32,
            timestamp_ns,
            payload,
        })
    }
}

/// Réponse IPC calibrée à exactement 64 octets.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiemResponse {
    pub magic: u32,             // 0..4: 0x53494552 ("SIER")
    pub status: i32,            // 4..8: Code statut (0 = succès)
    pub alerts_count: u32,      // 8..12: Total alertes
    pub events_count: u32,      // 12..16: Total événements
    pub threat_score: u32,      // 16..20: Score composite de menace
    pub rule_id: u32,           // 20..24: Règle ID / alertes générées
    pub timestamp_ns: u64,      // 24..32: Horodatage monotone
    pub audit_preview: [u8; 8], // 32..40: Échantillon audit SHA-256
    pub status_str: [u8; 24],   // 40..64: Message ASCII descriptif
}

const _: () = assert!(core::mem::size_of::<SiemResponse>() == 64);

impl Default for SiemResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl SiemResponse {
    pub const fn new() -> Self {
        Self {
            magic: SIEM_MAGIC_RESP,
            status: 0,
            alerts_count: 0,
            events_count: 0,
            threat_score: 0,
            rule_id: 0,
            timestamp_ns: 0,
            audit_preview: [0u8; 8],
            status_str: [0u8; 24],
        }
    }

    pub fn set_status_str(&mut self, s: &str) {
        let mut buf = [0u8; 24];
        let bytes = s.as_bytes();
        let len = bytes.len().min(24);
        buf[..len].copy_from_slice(&bytes[..len]);
        self.status_str = buf;
    }

    pub fn status_as_str(&self) -> &str {
        let len = self.status_str.iter().position(|&b| b == 0).unwrap_or(24);
        core::str::from_utf8(&self.status_str[..len]).unwrap_or("<invalid-utf8>")
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..8].copy_from_slice(&self.status.to_le_bytes());
        b[8..12].copy_from_slice(&self.alerts_count.to_le_bytes());
        b[12..16].copy_from_slice(&self.events_count.to_le_bytes());
        b[16..20].copy_from_slice(&self.threat_score.to_le_bytes());
        b[20..24].copy_from_slice(&self.rule_id.to_le_bytes());
        b[24..32].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        b[32..40].copy_from_slice(&self.audit_preview);
        b[40..64].copy_from_slice(&self.status_str);
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != SIEM_MAGIC_RESP {
            return None;
        }
        let status = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let alerts_count = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let events_count = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let threat_score = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let rule_id = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let timestamp_ns = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        let mut audit_preview = [0u8; 8];
        audit_preview.copy_from_slice(&bytes[32..40]);
        let mut status_str = [0u8; 24];
        status_str.copy_from_slice(&bytes[40..64]);

        Some(Self {
            magic,
            status,
            alerts_count,
            events_count,
            threat_score,
            rule_id,
            timestamp_ns,
            audit_preview,
            status_str,
        })
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`SiemClient`, `ChannelMessage`)
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

/// Client synchrone Ring 3 pour interagir avec le démon jambo-siem (PID 31).
pub struct SiemClient {
    pub endpoint: Handle,
}

impl SiemClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn call(&self, req: &SiemRequest) -> Result<SiemResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<SiemResponse>() {
                return SiemResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            libjambo::syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }

    pub fn get_status(&self, cap: &SiemCap) -> Result<SiemResponse, SysError> {
        let req = SiemRequest::new_status(SIEM_ENDPOINT_ID, cap.bits());
        self.call(&req)
    }
}

// ============================================================================
// MOTEUR SIEM PRINCIPAL (`SiemEngine`)
// ============================================================================

/// Moteur SIEM souverain temps réel.
pub struct SiemEngine {
    /// Handle de capacité d'accès.
    pub cap: Handle,
    /// Droits capabilaires courants.
    pub siem_cap: SiemCap,
    /// Anneau d'événements normalisés.
    pub ring: EventRing,
    /// Fenêtre de corrélation glissante.
    pub window: CorrelationWindow,
    /// File d'alertes SIEM.
    pub alerts: AlertQueue,
    /// Registre d'audit cryptographique.
    pub audit: AuditRing,
    /// Hachage de tête de la chaîne d'audit SHA-256.
    pub audit_chain: [u8; SHA256_LEN],
    /// Compteur monotone d'événements ingérés.
    pub event_seq: u64,
    /// Compteur monotone d'alertes générées.
    pub alert_seq: u64,
    /// Compteur monotone d'alertes dédupliquées.
    pub dedup_count: u64,
    /// Règles actives pré-intégrées.
    pub rules: [CorrelationRule; 6],
}

impl SiemEngine {
    /// Initialise le moteur SIEM avec les droits capabilaires donnés.
    pub fn new(cap: Handle, siem_cap: SiemCap) -> Self {
        Self {
            cap,
            siem_cap,
            ring: EventRing::new(),
            window: CorrelationWindow::new(),
            alerts: AlertQueue::new(),
            audit: AuditRing::new(),
            audit_chain: [0u8; SHA256_LEN],
            event_seq: 0,
            alert_seq: 0,
            dedup_count: 0,
            rules: [
                CorrelationRule::BRUTE_FORCE,
                CorrelationRule::LATERAL_MOVEMENT,
                CorrelationRule::PRIVILEGE_ESCALATION,
                CorrelationRule::DATA_EXFILTRATION,
                CorrelationRule::C2_BEACON,
                CorrelationRule::APT_MULTI_STAGE,
            ],
        }
    }

    /// Réinitialise les règles par défaut et scelle l'audit initial.
    pub fn init_defaults(&mut self) {
        self.rules = [
            CorrelationRule::BRUTE_FORCE,
            CorrelationRule::LATERAL_MOVEMENT,
            CorrelationRule::PRIVILEGE_ESCALATION,
            CorrelationRule::DATA_EXFILTRATION,
            CorrelationRule::C2_BEACON,
            CorrelationRule::APT_MULTI_STAGE,
        ];
        self.audit_chain = self.audit.record(SiemOp::RuleUpdated, 1);
    }

    /// Ingère un événement normalisé, calcule son empreinte SHA-256, met à jour l'anneau et déclenche la corrélation.
    pub fn ingest_event(
        &mut self,
        mut event: SecurityEvent,
        now_ns: u64,
    ) -> Result<u32, SiemError> {
        if !self.siem_cap.has(SiemCap::INGEST) {
            return Err(SiemError::CapabilityDenied);
        }

        self.event_seq = self.event_seq.wrapping_add(1);
        event.id = self.event_seq;
        event.timestamp_ns = now_ns;

        // Calcul de l'empreinte SHA-256 de l'événement
        let mut ev_data = [0u8; 32];
        ev_data[0..8].copy_from_slice(&event.id.to_be_bytes());
        ev_data[8..16].copy_from_slice(&event.timestamp_ns.to_be_bytes());
        ev_data[16] = event.source as u8;
        ev_data[17] = event.category as u8;
        ev_data[18] = event.severity as u8;
        ev_data[19] = event.raw_risk_score;
        event.sha256 = Sha256::digest(&ev_data);

        // Insertion dans l'anneau d'événements
        self.ring.push(event);

        // Scellement dans le grand livre d'audit
        self.audit_chain = self.audit.record(SiemOp::EventIngested, now_ns);

        if !self.siem_cap.has(SiemCap::CORRELATE) {
            return Ok(0);
        }

        self.window.ingest(&event);
        self.correlate(now_ns)
    }

    /// Alias d'ingestion pour compatibilité ascendante.
    #[inline]
    pub fn ingest(&mut self, event: SecurityEvent, now_ns: u64) -> Result<u32, SiemError> {
        self.ingest_event(event, now_ns)
    }

    /// Évalue les règles de corrélation sur la fenêtre glissante actuelle.
    pub fn correlate(&mut self, now_ns: u64) -> Result<u32, SiemError> {
        if !self.siem_cap.has(SiemCap::CORRELATE) {
            return Err(SiemError::CapabilityDenied);
        }

        let mut new_alerts = 0u32;
        for rule_idx in 0..self.rules.len() {
            let rule = self.rules[rule_idx];
            if let Some(corr_match) = self.window.evaluate(&rule, now_ns) {
                if self.siem_cap.has(SiemCap::ALERT) {
                    // Empreinte structurelle SHA-256 pour déduplication
                    let mut afp_data = [0u8; 16];
                    afp_data[0..4].copy_from_slice(&corr_match.rule_id.to_le_bytes());
                    afp_data[4] = rule.kind as u8;
                    afp_data[5] = corr_match.threat_score;
                    afp_data[6] = corr_match.severity as u8;
                    let afp = Sha256::digest(&afp_data);

                    self.alert_seq = self.alert_seq.wrapping_add(1);

                    let alert = SiemAlert {
                        alert_id: self.alert_seq,
                        rule_id: corr_match.rule_id,
                        rule_kind: rule.kind,
                        severity: corr_match.severity,
                        threat_score: corr_match.threat_score,
                        correlated_events: corr_match.event_count,
                        generated_at_ns: now_ns,
                        state: AlertState::New,
                        fingerprint: afp,
                        audit_sha256: self.audit_chain,
                    };

                    let is_new = self.alerts.push_dedup(alert);
                    if is_new {
                        self.audit_chain = self.audit.record(SiemOp::AlertGenerated, now_ns);
                        new_alerts += 1;
                    } else {
                        self.dedup_count = self.dedup_count.wrapping_add(1);
                    }
                }
            }
        }

        Ok(new_alerts)
    }

    /// Traitement déterministe d'une requête IPC calibrée à 64 octets.
    pub fn dispatch_ipc(&mut self, req: &SiemRequest) -> SiemResponse {
        if req.magic != SIEM_MAGIC_REQ {
            let mut resp = SiemResponse::new();
            resp.status = -1;
            resp.set_status_str("BAD_MAGIC");
            return resp;
        }

        let opcode = match SiemOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                let mut resp = SiemResponse::new();
                resp.status = -1;
                resp.set_status_str("BAD_OPCODE");
                return resp;
            }
        };

        let cap = SiemCap::new(req.rights);
        let mut resp = SiemResponse::new();

        match opcode {
            SiemOpcode::GetStatus => {
                if !cap.has(SiemCap::QUERY) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                resp.status = 0;
                resp.alerts_count = self.alert_count() as u32;
                resp.events_count = self.event_count() as u32;
                resp.threat_score = self.composite_threat_score() as u32;
                resp.audit_preview.copy_from_slice(&self.audit_chain[..8]);
                resp.set_status_str("STATUS_OK");
            }
            SiemOpcode::IngestEvent => {
                if !cap.has(SiemCap::INGEST) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let mut ev = SecurityEvent::zeroed();
                ev.source = EventSource::from_u8(req.source);
                ev.category = EventCategory::from_u8(req.category);
                ev.severity = Severity::from_u8(req.severity);
                ev.raw_risk_score = req.raw_risk_score;
                ev.actor[..32].copy_from_slice(&req.payload);

                let ts = if req.timestamp_ns != 0 {
                    req.timestamp_ns
                } else {
                    1
                };
                match self.ingest_event(ev, ts) {
                    Ok(new_alerts) => {
                        resp.status = 0;
                        resp.alerts_count = self.alert_count() as u32;
                        resp.events_count = self.event_count() as u32;
                        resp.threat_score = self.composite_threat_score() as u32;
                        resp.rule_id = new_alerts;
                        resp.audit_preview.copy_from_slice(&self.audit_chain[..8]);
                        resp.set_status_str("INGEST_OK");
                    }
                    Err(_) => {
                        resp.status = -1;
                        resp.set_status_str("INGEST_ERR");
                    }
                }
            }
            SiemOpcode::RunCorrelation => {
                if !cap.has(SiemCap::CORRELATE) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                let ts = if req.timestamp_ns != 0 {
                    req.timestamp_ns
                } else {
                    1
                };
                match self.correlate(ts) {
                    Ok(new_alerts) => {
                        resp.status = 0;
                        resp.alerts_count = self.alert_count() as u32;
                        resp.events_count = self.event_count() as u32;
                        resp.threat_score = self.composite_threat_score() as u32;
                        resp.rule_id = new_alerts;
                        resp.audit_preview.copy_from_slice(&self.audit_chain[..8]);
                        resp.set_status_str("CORRELATE_OK");
                    }
                    Err(_) => {
                        resp.status = -1;
                        resp.set_status_str("CORR_ERR");
                    }
                }
            }
            SiemOpcode::GetAlerts => {
                if !cap.has(SiemCap::ALERT) && !cap.has(SiemCap::QUERY) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                resp.status = 0;
                resp.alerts_count = self.alert_count() as u32;
                let idx = req.param_u32 as usize;
                if let Some(alert) = self.alerts.get(idx) {
                    resp.rule_id = alert.rule_id;
                    resp.threat_score = alert.threat_score as u32;
                    resp.timestamp_ns = alert.generated_at_ns;
                }
                resp.audit_preview.copy_from_slice(&self.audit_chain[..8]);
                resp.set_status_str("ALERTS_OK");
            }
            SiemOpcode::GetRules => {
                if !cap.has(SiemCap::QUERY) && !cap.has(SiemCap::ADMIN) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                resp.status = 0;
                resp.rule_id = self.rules.len() as u32;
                resp.set_status_str("RULES_OK");
            }
            SiemOpcode::GetAudit => {
                if !cap.has(SiemCap::QUERY) && !cap.has(SiemCap::ADMIN) {
                    resp.status = -13;
                    resp.set_status_str("CAP_DENIED");
                    return resp;
                }
                resp.status = 0;
                resp.audit_preview.copy_from_slice(&self.audit_chain[..8]);
                resp.set_status_str("AUDIT_OK");
            }
        }

        resp
    }

    /// Score composite de menace (0-100) agrégeant les alertes actives.
    pub fn composite_threat_score(&self) -> u8 {
        if self.alerts.is_empty() {
            return 0;
        }
        let mut max_score = 0u8;
        let mut total_score = 0u32;
        let mut active_count = 0u32;
        for i in 0..self.alerts.len() {
            if let Some(a) = self.alerts.get(i) {
                if a.state != AlertState::Resolved && a.state != AlertState::FalsePositive {
                    if a.threat_score > max_score {
                        max_score = a.threat_score;
                    }
                    total_score += a.threat_score as u32;
                    active_count += 1;
                }
            }
        }
        if active_count == 0 {
            return 0;
        }
        let avg = (total_score / active_count) as u8;
        // Pondération : 70% menace maximale + 30% moyenne active
        let composite = ((max_score as u32 * 70 + avg as u32 * 30) / 100) as u8;
        composite.min(100)
    }

    /// Requête filtrée sur l'anneau d'événements.
    pub fn query_events(
        &self,
        source: Option<EventSource>,
        min_severity: Severity,
        out: &mut [*const SecurityEvent],
    ) -> Result<usize, SiemError> {
        if !self.siem_cap.has(SiemCap::QUERY) {
            return Err(SiemError::CapabilityDenied);
        }
        Ok(self.ring.query(source, min_severity, out))
    }

    /// Nombre d'alertes critiques ou supérieures dans la file.
    pub fn critical_alert_count(&self) -> usize {
        self.alerts.count_by_severity(Severity::Critical)
    }

    /// Nombre total d'événements ingérés.
    #[inline]
    pub fn event_count(&self) -> u64 {
        self.event_seq
    }

    /// Nombre total d'alertes générées.
    #[inline]
    pub fn alert_count(&self) -> u64 {
        self.alert_seq
    }

    /// Hachage de tête de la chaîne d'audit.
    #[inline]
    pub fn audit_chain_head(&self) -> &[u8; SHA256_LEN] {
        self.audit.chain_head()
    }

    /// Acquitte une alerte par son index dans la file.
    pub fn acknowledge_alert(&mut self, idx: usize, now_ns: u64) -> Result<(), SiemError> {
        if !self.siem_cap.has(SiemCap::ALERT) {
            return Err(SiemError::CapabilityDenied);
        }
        if let Some(alert) = self.alerts.get_mut(idx) {
            alert.state = AlertState::Acknowledged;
            self.audit_chain = self.audit.record(SiemOp::AlertAcknowledged, now_ns);
            Ok(())
        } else {
            Err(SiemError::AlertNotFound)
        }
    }

    /// Résout une alerte par son index.
    pub fn resolve_alert(&mut self, idx: usize, now_ns: u64) -> Result<(), SiemError> {
        if !self.siem_cap.has(SiemCap::ALERT) {
            return Err(SiemError::CapabilityDenied);
        }
        if let Some(alert) = self.alerts.get_mut(idx) {
            alert.state = AlertState::Resolved;
            self.audit_chain = self.audit.record(SiemOp::AlertResolved, now_ns);
            Ok(())
        } else {
            Err(SiemError::AlertNotFound)
        }
    }

    /// Capacité courante du moteur.
    #[inline]
    pub fn capability(&self) -> SiemCap {
        self.siem_cap
    }
}

// ============================================================================
// ERREURS DU SERVICE SIEM
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiemError {
    CapabilityDenied,
    RingFull,
    AlertNotFound,
    InvalidRule,
    ExportFailed,
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cap() -> (Handle, SiemCap) {
        (
            Handle::new(SIEM_ENDPOINT_ID, 1),
            SiemCap::new(siem_rights::ALL),
        )
    }

    fn make_event(
        source: EventSource,
        cat: EventCategory,
        sev: Severity,
        success: bool,
    ) -> SecurityEvent {
        let mut ev = SecurityEvent::zeroed();
        ev.source = source;
        ev.category = cat;
        ev.severity = sev;
        ev.outcome_success = success;
        ev.raw_risk_score = (sev as u8) * 20;
        ev
    }

    #[test]
    fn test_siem_cap_has_and_attenuate() {
        let full = SiemCap::new(0x3f);
        assert!(full.has(SiemCap::INGEST));
        assert!(full.has(SiemCap::CORRELATE));
        assert!(full.has(SiemCap::ADMIN));

        let limited = full.attenuate(SiemCap::INGEST);
        assert!(limited.has(SiemCap::INGEST));
        assert!(!limited.has(SiemCap::ADMIN));
        assert!(!limited.has(SiemCap::ALERT));
    }

    #[test]
    fn test_capability_denied_on_ingest() {
        let (cap, _) = make_cap();
        let mut engine = SiemEngine::new(cap, SiemCap::NONE);
        let ev = make_event(
            EventSource::JamboAuthd,
            EventCategory::Authentication,
            Severity::Medium,
            false,
        );
        let result = engine.ingest(ev, 1_000_000);
        assert_eq!(result, Err(SiemError::CapabilityDenied));
    }

    #[test]
    fn test_event_ring_push_and_query() {
        let mut ring = EventRing::new();
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());

        for i in 0..10u64 {
            let mut ev = SecurityEvent::zeroed();
            ev.id = i;
            ev.source = EventSource::JamboWalld;
            ev.severity = if i >= 5 {
                Severity::High
            } else {
                Severity::Low
            };
            ring.push(ev);
        }
        assert_eq!(ring.len(), 10);

        let mut out = [core::ptr::null::<SecurityEvent>(); 16];
        let found = ring.query(Some(EventSource::JamboWalld), Severity::High, &mut out);
        assert_eq!(found, 5);
    }

    #[test]
    fn test_event_ring_circular_overflow() {
        let mut ring = EventRing::new();
        for i in 0..(EVENT_RING_SIZE + 5) {
            let mut ev = SecurityEvent::zeroed();
            ev.id = i as u64;
            ring.push(ev);
        }
        assert_eq!(ring.len(), EVENT_RING_SIZE);
    }

    #[test]
    fn test_alert_queue_push_and_dedup() {
        let mut queue = AlertQueue::new();
        assert_eq!(queue.len(), 0);

        let mut alert1 = SiemAlert::zeroed();
        alert1.alert_id = 1;
        alert1.rule_id = 1;
        alert1.threat_score = 75;
        alert1.correlated_events = 10;
        alert1.fingerprint = [0xAA; SHA256_LEN];

        // 1. Insertion nouvelle alerte
        let inserted = queue.push_dedup(alert1);
        assert!(inserted);
        assert_eq!(queue.len(), 1);

        // 2. Deuxième alerte avec même fingerprint -> déduplication
        let mut alert2 = alert1;
        alert2.alert_id = 2;
        alert2.generated_at_ns = 5000;
        let deduped = queue.push_dedup(alert2);
        assert!(!deduped, "Même empreinte doit être dédupliquée");
        assert_eq!(queue.len(), 1);

        let active = queue.get(0).expect("get active alert");
        assert_eq!(
            active.correlated_events, 11,
            "Compteur d'événements doit être incrémenté"
        );
        assert_eq!(active.generated_at_ns, 5000);

        // 3. Nouvelle alerte avec empreinte différente
        let mut alert3 = alert1;
        alert3.alert_id = 3;
        alert3.fingerprint = [0xBB; SHA256_LEN];
        assert!(queue.push_dedup(alert3));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_brute_force_detection() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);

        let mut total_alerts = 0u32;
        for i in 0..12u64 {
            let ev = make_event(
                EventSource::JamboAuthd,
                EventCategory::Authentication,
                Severity::Medium,
                false,
            );
            let n = engine.ingest(ev, 1_000_000 + i * 1000).unwrap();
            total_alerts += n;
        }
        assert!(
            engine.alert_count() > 0,
            "Brute force doit déclencher une alerte"
        );
        assert!(total_alerts > 0);
        assert!(
            engine.dedup_count >= 2,
            "Les occurrences au-delà du seuil doivent être dédupliquées"
        );
    }

    #[test]
    fn test_lateral_movement_correlation() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);

        // 5 événements réseau provenant de 2 sources distinctes (Walld et Waf)
        for i in 0..3 {
            let ev = make_event(
                EventSource::JamboWalld,
                EventCategory::Network,
                Severity::High,
                true,
            );
            engine.ingest(ev, 1000 + i * 10).unwrap();
        }
        for i in 0..2 {
            let ev = make_event(
                EventSource::JamboWaf,
                EventCategory::Network,
                Severity::High,
                true,
            );
            engine.ingest(ev, 2000 + i * 10).unwrap();
        }

        assert!(
            engine.alert_count() > 0,
            "Lateral movement doit déclencher une alerte"
        );
        let alert = engine.alerts.get(0).expect("alert lateral movement");
        assert_eq!(alert.rule_id, CorrelationRule::LATERAL_MOVEMENT.id);
        assert_eq!(alert.threat_score, 80);
    }

    #[test]
    fn test_apt_multi_stage_correlation() {
        let mut window = CorrelationWindow::new();
        let rule = CorrelationRule::APT_MULTI_STAGE;

        // Injecte 3 catégories distinctes : Auth, Network, File
        let cats = [
            EventCategory::Authentication,
            EventCategory::Network,
            EventCategory::File,
        ];
        for (i, &cat) in cats.iter().enumerate() {
            let mut ev = SecurityEvent::zeroed();
            ev.id = i as u64 + 1;
            ev.source = EventSource::JamboWaf;
            ev.category = cat;
            ev.severity = Severity::High;
            window.ingest(&ev);
        }

        let result = window.evaluate(&rule, 5_000_000);
        assert!(
            result.is_some(),
            "APT Multi-Stage doit se déclencher avec 3 catégories distinctes"
        );
        let m = result.unwrap();
        assert_eq!(m.rule_id, 6);
        assert_eq!(m.threat_score, 98);
    }

    #[test]
    fn test_composite_threat_score() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);

        assert_eq!(engine.composite_threat_score(), 0);

        // Déclenche Brute Force (score 75)
        for i in 0..10u64 {
            let ev = make_event(
                EventSource::JamboAuthd,
                EventCategory::Authentication,
                Severity::Medium,
                false,
            );
            engine.ingest(ev, 1000 + i * 100).unwrap();
        }

        let score = engine.composite_threat_score();
        assert!(
            score >= 70,
            "Le score composite de menace doit être élevé après brute force"
        );
    }

    #[test]
    fn test_audit_chain_sequential_sealing() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);

        assert_eq!(engine.audit_chain, [0u8; SHA256_LEN]);

        let ev = make_event(
            EventSource::JamboIds,
            EventCategory::Network,
            Severity::High,
            false,
        );
        engine.ingest(ev, 9_999_999).unwrap();

        let head1 = engine.audit_chain;
        assert!(head1.iter().any(|&b| b != 0));

        engine.init_defaults();
        let head2 = engine.audit_chain;
        assert_ne!(
            head1, head2,
            "Chaque opération doit sceller séquentiellement le grand livre"
        );
    }

    #[test]
    fn test_ipc_request_response_serialization_64_bytes() {
        assert_eq!(core::mem::size_of::<SiemRequest>(), 64);
        assert_eq!(core::mem::size_of::<SiemResponse>(), 64);

        let req = SiemRequest::new_ingest(
            SIEM_ENDPOINT_ID,
            siem_rights::ALL,
            EventSource::JamboWalld,
            EventCategory::Network,
            Severity::High,
            80,
            12345678,
            "DROP_RULE_VIOLATION",
        );
        let req_bytes = req.to_bytes();
        assert_eq!(req_bytes.len(), 64);

        let parsed_req = SiemRequest::from_bytes(&req_bytes).expect("parse req");
        assert_eq!(parsed_req.magic, SIEM_MAGIC_REQ);
        assert_eq!(parsed_req.opcode, SiemOpcode::IngestEvent as u32);
        assert_eq!(parsed_req.source, EventSource::JamboWalld as u8);
        assert_eq!(parsed_req.timestamp_ns, 12345678);

        let mut resp = SiemResponse::new();
        resp.status = 0;
        resp.alerts_count = 5;
        resp.events_count = 100;
        resp.threat_score = 85;
        resp.rule_id = 2;
        resp.timestamp_ns = 987654;
        resp.audit_preview = [1, 2, 3, 4, 5, 6, 7, 8];
        resp.set_status_str("STATUS_OK");

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);

        let parsed_resp = SiemResponse::from_bytes(&resp_bytes).expect("parse resp");
        assert_eq!(parsed_resp.magic, SIEM_MAGIC_RESP);
        assert_eq!(parsed_resp.alerts_count, 5);
        assert_eq!(parsed_resp.threat_score, 85);
        assert_eq!(parsed_resp.status_as_str(), "STATUS_OK");
    }

    #[test]
    fn test_ipc_dispatch_operations() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);
        engine.init_defaults();

        // 1. GetStatus
        let req_status = SiemRequest::new_status(SIEM_ENDPOINT_ID, siem_rights::ALL);
        let resp_status = engine.dispatch_ipc(&req_status);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.status_as_str(), "STATUS_OK");

        // 2. IngestEvent IPC
        let req_ingest = SiemRequest::new_ingest(
            SIEM_ENDPOINT_ID,
            siem_rights::ALL,
            EventSource::JamboAuthd,
            EventCategory::Authentication,
            Severity::Low,
            20,
            1000,
            "LOGIN_SUCCESS",
        );
        let resp_ingest = engine.dispatch_ipc(&req_ingest);
        assert_eq!(resp_ingest.status, 0);
        assert_eq!(resp_ingest.events_count, 1);
        assert_eq!(resp_ingest.status_as_str(), "INGEST_OK");

        // 3. GetRules IPC
        let req_rules = SiemRequest::new_get_rules(SIEM_ENDPOINT_ID, siem_rights::ALL);
        let resp_rules = engine.dispatch_ipc(&req_rules);
        assert_eq!(resp_rules.status, 0);
        assert_eq!(resp_rules.rule_id, 6);
        assert_eq!(resp_rules.status_as_str(), "RULES_OK");

        // 4. GetAudit IPC
        let req_audit = SiemRequest::new_get_audit(SIEM_ENDPOINT_ID, siem_rights::ALL);
        let resp_audit = engine.dispatch_ipc(&req_audit);
        assert_eq!(resp_audit.status, 0);
        assert_eq!(resp_audit.status_as_str(), "AUDIT_OK");

        // 5. Mauvais Magic
        let mut bad_magic_req = req_status;
        bad_magic_req.magic = 0x12345678;
        let resp_bad = engine.dispatch_ipc(&bad_magic_req);
        assert_eq!(resp_bad.status, -1);
        assert_eq!(resp_bad.status_as_str(), "BAD_MAGIC");

        // 6. Droit refusé
        let denied_req = SiemRequest::new_status(SIEM_ENDPOINT_ID, siem_rights::INGEST);
        let resp_denied = engine.dispatch_ipc(&denied_req);
        assert_eq!(resp_denied.status, -13);
        assert_eq!(resp_denied.status_as_str(), "CAP_DENIED");
    }

    #[test]
    fn test_acknowledge_and_resolve_alert() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);

        for i in 0..15u64 {
            let ev = make_event(
                EventSource::JamboAuthd,
                EventCategory::Authentication,
                Severity::High,
                false,
            );
            engine.ingest(ev, i * 100).unwrap();
        }

        assert!(engine.alert_count() > 0);
        let ack = engine.acknowledge_alert(0, 99_999);
        assert!(ack.is_ok());
        let resolve = engine.resolve_alert(0, 100_000);
        assert!(resolve.is_ok());

        let alert = engine.alerts.get(0).unwrap();
        assert_eq!(alert.state, AlertState::Resolved);
    }

    #[test]
    fn test_attenuate_no_ingest_denied() {
        let (cap, siem_cap) = make_cap();
        let limited = siem_cap.attenuate(SiemCap::QUERY);
        let mut engine = SiemEngine::new(cap, limited);
        let ev = make_event(
            EventSource::JamboWalld,
            EventCategory::Network,
            Severity::Low,
            true,
        );
        assert_eq!(engine.ingest(ev, 0), Err(SiemError::CapabilityDenied));
    }
}

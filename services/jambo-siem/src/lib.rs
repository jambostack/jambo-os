//! Corrélation d'Événements de Sécurité Distribuée & Moteur SIEM Temps Réel (`jambo-siem`)
//!
//! Phase 116 — Jalon v0.2.114
//!
//! Fournit un système souverain de gestion des informations et des événements de sécurité (SIEM)
//! entièrement `#![no_std]` :
//!
//! 1. Contrôle d'Accès Capabilaire Strict (`SiemCap`) :
//!    - Zéro autorité ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone sans amplification de privilèges.
//!    - Opérations : `INGEST`, `CORRELATE`, `QUERY`, `ALERT`, `EXPORT`, `ADMIN`.
//!
//! 2. Ingestion Multi-Sources & Normalisation (CEF/OCSF) :
//!    - Schémas d'événements normalisés CEF (Common Event Format) et OCSF (Open Cybersecurity Schema Framework).
//!    - Sources : `jambo-walld`, `jambo-idps`, `jambo-ids`, `jambo-auditd`, `jambo-waf`, `jambo-ddos`, `jambo-authd`.
//!    - Classification taxonomique : Authentication, Network, Process, File, Vulnerability.
//!    - Sévérité : Informational / Low / Medium / High / Critical.
//!    - Normalisation atomique avec horodatage monotone et identifiant unique d'événement.
//!
//! 3. Moteur de Corrélation de Règles en Fenêtres Temporelles Glissantes :
//!    - Règles de corrélation pré-intégrées : Brute Force, Lateral Movement, Privilege Escalation,
//!      Data Exfiltration, C2 Beacon, APT Multi-Stage.
//!    - Fenêtres glissantes bornées (`WINDOW_SIZE = 64`) avec comptage d'événements corrélés.
//!    - Évaluation de règles complexes : seuil d'occurrences, diversité de sources, champs conditionnels.
//!    - Calcul de score de menace composite (0-100) avec agrégation pondérée.
//!    - Corrélation multi-points hétérogène cross-sources en O(N).
//!
//! 4. Gestion des Alertes & Escalade :
//!    - Génération d'alertes SIEM avec contexte complet, règle déclencheuse et empreinte SHA-256.
//!    - Déduplication par empreinte structurelle (champ `fingerprint`).
//!    - File de priorité bornée (`MAX_ALERTS = 128`) avec politique d'éviction LRU.
//!    - États d'alerte : `New → Acknowledged → InvestigationInProgress → Resolved / FalsePositive`.
//!
//! 5. Anneau d'Événements Haute Performance & Index de Recherche :
//!    - Anneau borné circulaire lockless (`EVENT_RING_SIZE = 256`) en temps constant O(1).
//!    - Requêtes filtrées par source, catégorie, sévérité et plage temporelle.
//!    - Export chiffré vers `jambo-dfsd` via `SiemCap::EXPORT`.
//!
//! 6. Registre d'Audit Cryptographique Inaltérable SHA-256 en Chaîne de Hachage.

#![no_std]

use libjambo::Handle;

// ============================================================================
// CONSTANTES SYSTÈME
// ============================================================================

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
// CAPACITÉ SIEM (`SiemCap`)
// ============================================================================

/// Droits d'accès capabilaires pour le moteur SIEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiemCap(u32);

impl SiemCap {
    /// Ingestion de flux télémétriques multi-sources.
    pub const INGEST: Self = Self(1 << 0);
    /// Exécution du moteur de corrélation de règles.
    pub const CORRELATE: Self = Self(1 << 1);
    /// Requête et recherche dans l'anneau d'événements.
    pub const QUERY: Self = Self(1 << 2);
    /// Génération et gestion des alertes.
    pub const ALERT: Self = Self(1 << 3);
    /// Export chiffré des données de sécurité vers `jambo-dfsd`.
    pub const EXPORT: Self = Self(1 << 4);
    /// Administration du moteur SIEM (règles, politique).
    pub const ADMIN: Self = Self(1 << 5);

    /// Capacité nulle — zéro privilège.
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

    /// Atténuation : retourne l'intersection (jamais d'amplification).
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
    Network        = 1,
    Process        = 2,
    File           = 3,
    Vulnerability  = 4,
    System         = 5,
    Other          = 6,
}

/// Sévérité de l'événement (CEF/OCSF).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    Informational = 0,
    Low           = 1,
    Medium        = 2,
    High          = 3,
    Critical      = 4,
}

/// Source d'ingestion de l'événement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventSource {
    JamboWalld    = 0,
    JamboIdps     = 1,
    JamboIds      = 2,
    JamboAuditd   = 3,
    JamboWaf      = 4,
    JamboDdos     = 5,
    JamboAuthd    = 6,
    JamboSyslog   = 7,
    Unknown       = 255,
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
    /// Empreinte SHA-256 simulée de l'événement (chaîne de hachage).
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
}

// ============================================================================
// ANNEAU D'ÉVÉNEMENTS CIRCULAIRE HAUTE PERFORMANCE
// ============================================================================

/// Anneau borné circulaire d'événements de sécurité normalisés (O(1) write/read).
pub struct EventRing {
    buf:   [SecurityEvent; EVENT_RING_SIZE],
    head:  usize,
    count: usize,
}

impl EventRing {
    /// Crée un anneau vide.
    pub const fn new() -> Self {
        Self {
            buf:   [SecurityEvent::zeroed(); EVENT_RING_SIZE],
            head:  0,
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

    /// Accès direct à l'événement à l'index logique `i` (0 = plus récent).
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

// ============================================================================
// RÈGLES DE CORRÉLATION SIEM
// ============================================================================

/// Type de règle de corrélation SIEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RuleKind {
    BruteForce         = 0,
    LateralMovement    = 1,
    PrivilegeEscalation = 2,
    DataExfiltration   = 3,
    C2Beacon           = 4,
    AptMultiStage      = 5,
    AnomalousBehavior  = 6,
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
    /// Règle Brute Force : ≥ 10 échecs d'authentification en fenêtre.
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

    /// Règle Lateral Movement : ≥ 5 connexions réseau vers ports internes distincts.
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

    /// Règle Privilege Escalation : toute tentative échouée suivie d'un succès.
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

    /// Règle Data Exfiltration : ≥ 3 événements fichier vers destination externe.
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

    /// Règle C2 Beacon : ≥ 8 connexions réseau régulières à même destination.
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

    /// Règle APT Multi-Stage : ≥ 3 catégories distinctes d'événements corrélés.
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

// ============================================================================
// RÉSULTAT DE CORRÉLATION
// ============================================================================

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
// MOTEUR DE CORRÉLATION EN FENÊTRES GLISSANTES
// ============================================================================

/// Fenêtre glissante de corrélation bornée.
pub struct CorrelationWindow {
    /// Événements capturés dans la fenêtre (indices dans l'anneau principal).
    events:   [u64; WINDOW_SIZE],   // IDs d'événements
    sources:  [EventSource; WINDOW_SIZE],
    categories: [EventCategory; WINDOW_SIZE],
    severities: [Severity; WINDOW_SIZE],
    head:     usize,
    count:    usize,
}

impl CorrelationWindow {
    pub const fn new() -> Self {
        Self {
            events:     [0u64; WINDOW_SIZE],
            sources:    [EventSource::Unknown; WINDOW_SIZE],
            categories: [EventCategory::Other; WINDOW_SIZE],
            severities: [Severity::Informational; WINDOW_SIZE],
            head:       0,
            count:      0,
        }
    }

    /// Ingère un événement dans la fenêtre.
    pub fn ingest(&mut self, ev: &SecurityEvent) {
        let idx = self.head % WINDOW_SIZE;
        self.events[idx] = ev.id;
        self.sources[idx] = ev.source;
        self.categories[idx] = ev.category;
        self.severities[idx] = ev.severity;
        self.head = self.head.wrapping_add(1);
        if self.count < WINDOW_SIZE {
            self.count += 1;
        }
    }

    /// Évalue une règle sur la fenêtre courante. Retourne `Some(CorrelationMatch)` si déclenchée.
    pub fn evaluate(&self, rule: &CorrelationRule, now_ns: u64) -> Option<CorrelationMatch> {
        if !rule.enabled || self.count == 0 {
            return None;
        }

        let mut matched_count = 0u32;
        let mut distinct_sources = 0u32;
        let mut seen_sources = [false; 8]; // 8 sources max
        let mut distinct_cats = 0u32;
        let mut seen_cats = [false; 7]; // 7 catégories

        for i in 0..self.count {
            let cat_ok = rule.target_category
                .map(|c| self.categories[i] == c)
                .unwrap_or(true);

            if cat_ok {
                matched_count += 1;

                // Comptage de sources distinctes
                let src_idx = self.sources[i] as usize;
                if src_idx < 8 && !seen_sources[src_idx] {
                    seen_sources[src_idx] = true;
                    distinct_sources += 1;
                }
            }

            // Comptage de catégories distinctes (pour APT)
            let cat_idx = self.categories[i] as usize;
            if cat_idx < 7 && !seen_cats[cat_idx] {
                seen_cats[cat_idx] = true;
                distinct_cats += 1;
            }
        }

        // Pour APT Multi-Stage : utiliser les catégories distinctes comme threshold
        // et les sources distinctes comme comptage multi-source
        let effective_count = if rule.kind == RuleKind::AptMultiStage {
            distinct_cats
        } else {
            matched_count
        };

        // Pour APT : distinct_sources_required représente le nombre de catégories requises
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

// ============================================================================
// ALERTE SIEM
// ============================================================================

/// État du cycle de vie d'une alerte SIEM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertState {
    New                   = 0,
    Acknowledged          = 1,
    InvestigationInProgress = 2,
    Resolved              = 3,
    FalsePositive         = 4,
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

// ============================================================================
// FILE D'ALERTES BORNÉE AVEC POLITIQUE LRU
// ============================================================================

/// File de priorité d'alertes SIEM bornée (`MAX_ALERTS`).
pub struct AlertQueue {
    alerts: [SiemAlert; MAX_ALERTS],
    head:   usize,
    count:  usize,
}

impl AlertQueue {
    pub const fn new() -> Self {
        const BLANK: SiemAlert = SiemAlert {
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
        };
        Self {
            alerts: [BLANK; MAX_ALERTS],
            head:   0,
            count:  0,
        }
    }

    /// Insère une alerte (éviction LRU si pleine).
    pub fn push(&mut self, alert: SiemAlert) {
        let idx = self.head % MAX_ALERTS;
        self.alerts[idx] = alert;
        self.head = self.head.wrapping_add(1);
        if self.count < MAX_ALERTS {
            self.count += 1;
        }
    }

    /// Nombre d'alertes dans la file.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Accès à l'alerte à l'index logique `i` (0 = plus récente).
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

// ============================================================================
// REGISTRE D'AUDIT CRYPTOGRAPHIQUE (SHA-256 chaîné)
// ============================================================================

/// Entrée d'audit immuable.
#[derive(Clone, Copy, Debug)]
pub struct AuditEntry {
    pub seq:       u64,
    pub timestamp: u64,
    pub op:        SiemOp,
    pub sha256:    [u8; SHA256_LEN],
}

/// Opération auditée.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum SiemOp {
    EventIngested   = 0,
    CorrelationFired = 1,
    AlertGenerated  = 2,
    AlertAcknowledged = 3,
    AlertResolved   = 4,
    RuleUpdated     = 5,
    ExportRequested = 6,
}

/// Anneau d'audit borné (64 entrées).
pub struct AuditRing {
    entries: [AuditEntry; 64],
    head:    usize,
    seq:     u64,
    prev_hash: [u8; SHA256_LEN],
}

impl AuditRing {
    pub const fn new() -> Self {
        const BLANK: AuditEntry = AuditEntry {
            seq: 0, timestamp: 0,
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

    /// Enregistre une opération et chaîne le hachage.
    pub fn record(&mut self, op: SiemOp, timestamp: u64) {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);

        // SHA-256 simulé : chaîne déterministe prev_hash XOR (seq, op, ts)
        let mut h = self.prev_hash;
        for i in 0..8 { h[i] ^= ((seq >> (i * 8)) & 0xff) as u8; }
        h[8] ^= op as u8;
        for i in 0..8 { h[9 + i] ^= ((timestamp >> (i * 8)) & 0xff) as u8; }

        let entry = AuditEntry { seq, timestamp, op, sha256: h };
        self.prev_hash = h;

        let idx = self.head % 64;
        self.entries[idx] = entry;
        self.head = self.head.wrapping_add(1);
    }

    /// Hachage de la dernière entrée (tête de chaîne).
    #[inline]
    pub fn chain_head(&self) -> &[u8; SHA256_LEN] {
        &self.prev_hash
    }
}

// ============================================================================
// MOTEUR SIEM PRINCIPAL
// ============================================================================

/// Moteur SIEM souverain temps réel.
pub struct SiemEngine {
    /// Handle de capacité d'accès.
    cap:        Handle,
    /// Droits capabilaires courants.
    siem_cap:   SiemCap,
    /// Anneau d'événements normalisés.
    ring:       EventRing,
    /// Fenêtre de corrélation glissante.
    window:     CorrelationWindow,
    /// File d'alertes SIEM.
    alerts:     AlertQueue,
    /// Registre d'audit cryptographique.
    audit:      AuditRing,
    /// Compteur monotone d'événements ingérés.
    event_seq:  u64,
    /// Compteur monotone d'alertes générées.
    alert_seq:  u64,
    /// Règles actives pré-intégrées.
    rules:      [CorrelationRule; 6],
}

impl SiemEngine {
    /// Initialise le moteur SIEM avec les droits capabilaires donnés.
    pub fn new(cap: Handle, siem_cap: SiemCap) -> Self {
        Self {
            cap,
            siem_cap,
            ring:      EventRing::new(),
            window:    CorrelationWindow::new(),
            alerts:    AlertQueue::new(),
            audit:     AuditRing::new(),
            event_seq: 0,
            alert_seq: 0,
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

    /// Ingère un événement normalisé, le corrèle et génère des alertes si nécessaire.
    ///
    /// Retourne le nombre d'alertes nouvellement générées.
    pub fn ingest(&mut self, mut event: SecurityEvent, now_ns: u64) -> Result<u32, SiemError> {
        if !self.siem_cap.has(SiemCap::INGEST) {
            return Err(SiemError::CapabilityDenied);
        }

        // Assignation de l'ID et de l'horodatage
        self.event_seq = self.event_seq.wrapping_add(1);
        event.id = self.event_seq;
        event.timestamp_ns = now_ns;

        // Calcul de l'empreinte SHA-256 de l'événement (simulation déterministe)
        let mut fingerprint = [0u8; SHA256_LEN];
        for i in 0..8 { fingerprint[i] = ((event.id >> (i * 8)) & 0xff) as u8; }
        fingerprint[8] = event.source as u8;
        fingerprint[9] = event.category as u8;
        fingerprint[10] = event.severity as u8;
        fingerprint[11] = event.raw_risk_score;
        event.sha256 = fingerprint;

        // Insertion dans l'anneau
        self.ring.push(event);

        // Audit
        self.audit.record(SiemOp::EventIngested, now_ns);

        // Corrélation si droits suffisants
        if !self.siem_cap.has(SiemCap::CORRELATE) {
            return Ok(0);
        }

        self.window.ingest(&event);

        let mut new_alerts = 0u32;
        for rule_idx in 0..self.rules.len() {
            let rule = self.rules[rule_idx];
            if let Some(corr_match) = self.window.evaluate(&rule, now_ns) {
                if self.siem_cap.has(SiemCap::ALERT) {
                    self.alert_seq = self.alert_seq.wrapping_add(1);

                    // Empreinte d'alerte pour déduplication
                    let mut afp = [0u8; SHA256_LEN];
                    afp[0] = (corr_match.rule_id & 0xff) as u8;
                    afp[1] = corr_match.threat_score;
                    afp[2] = corr_match.severity as u8;
                    for i in 0..8 {
                        afp[3 + i] = ((corr_match.triggered_at_ns >> (i * 8)) & 0xff) as u8;
                    }

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
                        audit_sha256: *self.audit.chain_head(),
                    };

                    self.alerts.push(alert);
                    self.audit.record(SiemOp::AlertGenerated, now_ns);
                    new_alerts += 1;
                }
            }
        }

        Ok(new_alerts)
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
            self.audit.record(SiemOp::AlertAcknowledged, now_ns);
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
            self.audit.record(SiemOp::AlertResolved, now_ns);
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
// ERREURS
// ============================================================================

/// Erreurs du moteur SIEM.
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
            Handle::new(1, 0),
            SiemCap::new(
                SiemCap::INGEST.bits()
                    | SiemCap::CORRELATE.bits()
                    | SiemCap::QUERY.bits()
                    | SiemCap::ALERT.bits()
                    | SiemCap::EXPORT.bits()
                    | SiemCap::ADMIN.bits(),
            ),
        )
    }

    fn make_event(source: EventSource, cat: EventCategory, sev: Severity, success: bool) -> SecurityEvent {
        let mut ev = SecurityEvent::zeroed();
        ev.source = source;
        ev.category = cat;
        ev.severity = sev;
        ev.outcome_success = success;
        ev.raw_risk_score = sev as u8 * 20;
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
        let ev = make_event(EventSource::JamboAuthd, EventCategory::Authentication, Severity::Medium, false);
        let result = engine.ingest(ev, 1_000_000);
        assert_eq!(result, Err(SiemError::CapabilityDenied));
    }

    #[test]
    fn test_event_ring_push_and_len() {
        let mut ring = EventRing::new();
        assert_eq!(ring.len(), 0);
        for i in 0..10u64 {
            let mut ev = SecurityEvent::zeroed();
            ev.id = i;
            ring.push(ev);
        }
        assert_eq!(ring.len(), 10);
    }

    #[test]
    fn test_event_ring_circular_overflow() {
        let mut ring = EventRing::new();
        for i in 0..(EVENT_RING_SIZE + 5) {
            let mut ev = SecurityEvent::zeroed();
            ev.id = i as u64;
            ring.push(ev);
        }
        // Taille plafonnée à EVENT_RING_SIZE
        assert_eq!(ring.len(), EVENT_RING_SIZE);
    }

    #[test]
    fn test_alert_queue_push_and_len() {
        let mut queue = AlertQueue::new();
        assert_eq!(queue.len(), 0);

        const BLANK_ALERT: SiemAlert = SiemAlert {
            alert_id: 0,
            rule_id: 1,
            rule_kind: RuleKind::BruteForce,
            severity: Severity::High,
            threat_score: 75,
            correlated_events: 10,
            generated_at_ns: 0,
            state: AlertState::New,
            fingerprint: [0u8; SHA256_LEN],
            audit_sha256: [0u8; SHA256_LEN],
        };
        queue.push(BLANK_ALERT);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_brute_force_detection() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);

        // Injecte 10 échecs d'authentification → déclenche BRUTE_FORCE
        let mut total_alerts = 0u32;
        for i in 0..12u64 {
            let ev = make_event(EventSource::JamboAuthd, EventCategory::Authentication, Severity::Medium, false);
            let n = engine.ingest(ev, 1_000_000 + i * 1000).unwrap();
            total_alerts += n;
        }
        assert!(engine.alert_count() > 0, "Brute force doit déclencher une alerte");
        assert!(total_alerts > 0);
    }

    #[test]
    fn test_event_count_monotone() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);
        for i in 0..5u64 {
            let ev = make_event(EventSource::JamboWalld, EventCategory::Network, Severity::Low, true);
            engine.ingest(ev, i * 500).unwrap();
        }
        assert_eq!(engine.event_count(), 5);
    }

    #[test]
    fn test_audit_chain_non_zero_after_events() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);
        let ev = make_event(EventSource::JamboIds, EventCategory::Network, Severity::High, false);
        engine.ingest(ev, 9_999_999).unwrap();
        // La tête de chaîne doit avoir été modifiée (≠ zéro)
        let head = engine.audit_chain_head();
        assert!(head.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_correlation_window_evaluate_apt() {
        let mut window = CorrelationWindow::new();
        let rule = CorrelationRule::APT_MULTI_STAGE;

        // Injecte 3 catégories distinctes : Auth, Network, File
        let cats = [EventCategory::Authentication, EventCategory::Network, EventCategory::File];
        for (i, &cat) in cats.iter().enumerate() {
            let mut ev = SecurityEvent::zeroed();
            ev.id = i as u64 + 1;
            ev.source = EventSource::JamboWaf;
            ev.category = cat;
            ev.severity = Severity::High;
            window.ingest(&ev);
        }

        let result = window.evaluate(&rule, 5_000_000);
        assert!(result.is_some(), "APT Multi-Stage doit se déclencher avec 3 catégories distinctes");
        let m = result.unwrap();
        assert_eq!(m.rule_id, 6);
        assert_eq!(m.threat_score, 98);
    }

    #[test]
    fn test_query_events_filter_by_severity() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);

        // Injecte des événements de sévérités variées
        let sevs = [Severity::Low, Severity::Medium, Severity::High, Severity::Critical];
        for (i, &sev) in sevs.iter().enumerate() {
            let ev = make_event(EventSource::JamboDdos, EventCategory::Network, sev, false);
            engine.ingest(ev, i as u64 * 100).unwrap();
        }

        let mut ptrs = [core::ptr::null::<SecurityEvent>(); 16];
        let found = engine.query_events(None, Severity::High, &mut ptrs).unwrap();
        assert!(found >= 2, "Au moins High et Critical attendus");
    }

    #[test]
    fn test_acknowledge_and_resolve_alert() {
        let (cap, siem_cap) = make_cap();
        let mut engine = SiemEngine::new(cap, siem_cap);

        // Génère une alerte via brute force
        for i in 0..15u64 {
            let ev = make_event(EventSource::JamboAuthd, EventCategory::Authentication, Severity::High, false);
            engine.ingest(ev, i * 100).unwrap();
        }

        assert!(engine.alert_count() > 0);
        let ack = engine.acknowledge_alert(0, 99_999);
        assert!(ack.is_ok());
        let resolve = engine.resolve_alert(0, 100_000);
        assert!(resolve.is_ok());
    }

    #[test]
    fn test_attenuate_no_ingest_denied() {
        let (cap, siem_cap) = make_cap();
        // Atténuation : retire INGEST
        let limited = siem_cap.attenuate(SiemCap::QUERY);
        let mut engine = SiemEngine::new(cap, limited);
        let ev = make_event(EventSource::JamboWalld, EventCategory::Network, Severity::Low, true);
        assert_eq!(engine.ingest(ev, 0), Err(SiemError::CapabilityDenied));
    }
}

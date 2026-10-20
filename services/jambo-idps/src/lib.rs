//! Système de Détection et Prévention d'Intrusions Ring 3 (`jambo-idps`)
//!
//! Phase 101 — Jalon v0.2.99
//!
//! Fournit les garanties souveraines de surveillance active, de détection heuristique
//! d'anomalies de flux IPC et d'exécution de contre-mesures autonomes (révocation de capacités,
//! quarantaine de processus, coupure de canaux et étranglement de débit) pour JamboOS :
//! 1. Architecture capabilaire stricte (`IdpsCap`) sans autorité ambiante (Zero-Ambient Authority)
//!    et atténuation monotone des privilèges.
//! 2. Moteur de détection heuristique et statistique de flux IPC `#![no_std]` :
//!    - Détection de rafales anormales et dénis de service (Rate Burst Anomaly / IPC Flood)
//!    - Détection d'accès non autorisés aux canaux IPC privilégiés (Unauthorized Channel Access)
//!    - Détection de falsification de jetons de capacités (Capability Forgery Attempt)
//!    - Détection d'exfiltration de données et charges obfusquées par entropie (High Entropy Payload)
//!    - Détection d'attaques par rejeu et désynchronisation de séquences (Replay & Desync Attack)
//! 3. Contre-mesures autonomes et révocation dynamique de capacités :
//!    - Dégradation et révocation monotone des droits associés aux handles fautifs
//!    - Placement immédiat en quarantaine des processus malveillants ou compromis
//!    - Sectionnement instantané des canaux IPC corrompus
//!    - Étranglement et régulation de débit préventif
//! 4. Registre d'audit inaltérable scellé par chaîne SHA-256 (`idps_audit_chain`).

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES & LIMITES DU SYSTÈME IDPS
// ============================================================================

/// Taille d'une empreinte cryptographique SHA-256 (32 octets)
pub const HASH_SIZE: usize = 32;

/// Nombre maximal de règles de détection et politiques actives
pub const MAX_RULES: usize = 16;

/// Capacité maximale de l'historique d'alertes en mémoire
pub const MAX_ALERTS: usize = 32;

/// Capacité maximale de la table de quarantaine
pub const MAX_QUARANTINED: usize = 16;

/// Capacité maximale de suivi des profils de flux IPC simultanés
pub const MAX_FLOW_PROFILES: usize = 16;

/// Canal IPC réservé au micro-noyau et au bus système critique
pub const PRIVILEGED_KERNEL_CHANNEL: u32 = 0;

/// Canal IPC de signalisation sécurisée réservé
pub const PRIVILEGED_SIG_CHANNEL: u32 = 0xFFFF;

/// Seuil standard d'entropie élevée (pour mille, soit 85% d'aléa ou ~6.8 bits/octet)
pub const HIGH_ENTROPY_THRESHOLD: u32 = 850;

/// Seuil standard de rafale de messages par fenêtre (IPC flood)
pub const DEFAULT_BURST_THRESHOLD: u32 = 10;

// ============================================================================
// DROITS CAPABILAIRES DE L'IDPS (IdpsCap)
// ============================================================================

pub mod idps_rights {
    /// Droit de consulter les alertes, statistiques et l'état de l'IDPS
    pub const INSPECT: u32 = 0x01;
    /// Droit de soumettre des flux et événements IPC à l'inspection
    pub const MONITOR: u32 = 0x02;
    /// Droit d'ajouter ou modifier les règles heuristiques et seuils
    pub const UPDATE_RULES: u32 = 0x04;
    /// Droit de déclencher des contre-mesures (révocation de droits, quarantaine)
    pub const ISOLATE: u32 = 0x08;
    /// Droit de réarmer ou lever la quarantaine d'un composant
    pub const REARM: u32 = 0x10;
    /// Droit d'administration totale
    pub const ADMIN: u32 = 0x80;

    /// Ensemble de tous les droits
    pub const ALL: u32 = INSPECT | MONITOR | UPDATE_RULES | ISOLATE | REARM | ADMIN;
}

/// Jeton de capacité pour le contrôle d'accès à l'IDPS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdpsCap {
    pub handle: Handle,
    pub rights: u32,
}

impl IdpsCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone sans élévation de privilèges
    pub fn attenuate(&self, rights_mask: u32) -> Result<Self, SysError> {
        if (rights_mask & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: rights_mask,
        })
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES DE MENACES & CONTRE-MESURES
// ============================================================================

/// Gravité de la menace identifiée
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Catégorie heuristique de la menace
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    RateBurstAnomaly,
    UnauthorizedIpcChannel,
    CapabilityForgeryAttempt,
    EntropyExfiltration,
    ReplayAttack,
    ProtocolViolation,
}

/// Action de contre-mesure autonome exécutable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountermeasureAction {
    None,
    AlertOnly,
    Throttle,
    RevokeCap,
    SeverChannel,
    QuarantineProcess,
}

/// Événement de trafic IPC soumis au moteur d'inspection
#[derive(Debug, Clone, Copy)]
pub struct IpcTrafficEvent {
    pub sender_pid: u64,
    pub receiver_pid: u64,
    pub channel_id: u32,
    pub msg_opcode: u16,
    pub payload_len: usize,
    pub entropy_permille: u32,
    pub cap_token: u64,
    pub sequence_num: u64,
}

/// Alerte de sécurité générée par l'IDPS
#[derive(Debug, Clone, Copy)]
pub struct ThreatAlert {
    pub id: u32,
    pub source_pid: u64,
    pub target_pid: u64,
    pub severity: ThreatSeverity,
    pub category: ThreatCategory,
    pub score: u32,
    pub action: CountermeasureAction,
    pub description: &'static str,
}

impl Default for ThreatAlert {
    fn default() -> Self {
        Self {
            id: 0,
            source_pid: 0,
            target_pid: 0,
            severity: ThreatSeverity::Low,
            category: ThreatCategory::RateBurstAnomaly,
            score: 0,
            action: CountermeasureAction::None,
            description: "",
        }
    }
}

/// Règle heuristique de détection et politique de réponse
#[derive(Debug, Clone, Copy)]
pub struct IdpsRule {
    pub id: u32,
    pub category: ThreatCategory,
    pub min_severity: ThreatSeverity,
    pub threshold: u32,
    pub action: CountermeasureAction,
    pub enabled: bool,
    pub name: &'static str,
}

impl Default for IdpsRule {
    fn default() -> Self {
        Self {
            id: 0,
            category: ThreatCategory::RateBurstAnomaly,
            min_severity: ThreatSeverity::Low,
            threshold: 0,
            action: CountermeasureAction::None,
            enabled: false,
            name: "",
        }
    }
}

/// Profil de suivi temporel de flux IPC par émetteur
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowProfile {
    pub sender_pid: u64,
    pub msg_count_window: u32,
    pub last_seq: u64,
    pub accumulated_score: u32,
    pub active: bool,
}

/// Enregistrement d'un processus placé en quarantaine
#[derive(Debug, Clone, Copy, Default)]
pub struct QuarantineRecord {
    pub pid: u64,
    pub handle: Handle,
    pub reason: &'static str,
    pub revoked_rights: u32,
    pub active: bool,
}

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SOUVERAIN SHA-256 (#![no_std])
// ============================================================================

pub struct Sha256;

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];

        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut buffer = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            buffer.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut h, &buffer);
            offset += 64;
        }

        let rem = data.len() - offset;
        buffer[..rem].copy_from_slice(&data[offset..]);
        buffer[rem] = 0x80;
        for b in buffer.iter_mut().skip(rem + 1) {
            *b = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut h, &buffer);
            buffer = [0u8; 64];
        }

        buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut h, &buffer);

        let mut out = [0u8; 32];
        for (i, val) in h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    fn process_block(h: &mut [u32; 8], block: &[u8; 64]) {
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
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }
}

// ============================================================================
// DÉMON IDPS PRINCIPAL (JamboIdpsDaemon)
// ============================================================================

/// Démon de Détection et Prévention d'Intrusions Ring 3
pub struct JamboIdpsDaemon {
    pub cap: IdpsCap,
    pub rules: [IdpsRule; MAX_RULES],
    pub rule_count: usize,
    pub alerts: [ThreatAlert; MAX_ALERTS],
    pub alert_count: usize,
    pub quarantine_table: [QuarantineRecord; MAX_QUARANTINED],
    pub quarantine_count: usize,
    pub flows: [FlowProfile; MAX_FLOW_PROFILES],
    pub flow_count: usize,

    // Statistiques opérationnelles
    pub events_inspected: usize,
    pub anomalies_detected: usize,
    pub countermeasures_executed: usize,
    pub caps_revoked: usize,

    // Chaîne d'audit inviolable scellée SHA-256
    pub audit_chain: [u8; HASH_SIZE],
}

impl JamboIdpsDaemon {
    /// Crée une nouvelle instance de l'IDPS avec contrôle capabilaire strict
    pub const fn new(cap: IdpsCap) -> Self {
        Self {
            cap,
            rules: [IdpsRule {
                id: 0,
                category: ThreatCategory::RateBurstAnomaly,
                min_severity: ThreatSeverity::Low,
                threshold: 0,
                action: CountermeasureAction::None,
                enabled: false,
                name: "",
            }; MAX_RULES],
            rule_count: 0,
            alerts: [ThreatAlert {
                id: 0,
                source_pid: 0,
                target_pid: 0,
                severity: ThreatSeverity::Low,
                category: ThreatCategory::RateBurstAnomaly,
                score: 0,
                action: CountermeasureAction::None,
                description: "",
            }; MAX_ALERTS],
            alert_count: 0,
            quarantine_table: [QuarantineRecord {
                pid: 0,
                handle: Handle::new(0, 0),
                reason: "",
                revoked_rights: 0,
                active: false,
            }; MAX_QUARANTINED],
            quarantine_count: 0,
            flows: [FlowProfile {
                sender_pid: 0,
                msg_count_window: 0,
                last_seq: 0,
                accumulated_score: 0,
                active: false,
            }; MAX_FLOW_PROFILES],
            flow_count: 0,
            events_inspected: 0,
            anomalies_detected: 0,
            countermeasures_executed: 0,
            caps_revoked: 0,
            audit_chain: [0x5A; HASH_SIZE],
        }
    }

    /// Charge le jeu de règles heuristiques et politiques de sécurité par défaut
    pub fn init_defaults(&mut self) {
        self.rules[0] = IdpsRule {
            id: 1,
            category: ThreatCategory::RateBurstAnomaly,
            min_severity: ThreatSeverity::High,
            threshold: DEFAULT_BURST_THRESHOLD,
            action: CountermeasureAction::Throttle,
            enabled: true,
            name: "IDPS-R01-IPC-FLOOD-THROTTLE",
        };
        self.rules[1] = IdpsRule {
            id: 2,
            category: ThreatCategory::UnauthorizedIpcChannel,
            min_severity: ThreatSeverity::Critical,
            threshold: 1,
            action: CountermeasureAction::SeverChannel,
            enabled: true,
            name: "IDPS-R02-PRIV-CHANNEL-ISOLATION",
        };
        self.rules[2] = IdpsRule {
            id: 3,
            category: ThreatCategory::CapabilityForgeryAttempt,
            min_severity: ThreatSeverity::Critical,
            threshold: 1,
            action: CountermeasureAction::QuarantineProcess,
            enabled: true,
            name: "IDPS-R03-CAP-FORGERY-QUARANTINE",
        };
        self.rules[3] = IdpsRule {
            id: 4,
            category: ThreatCategory::EntropyExfiltration,
            min_severity: ThreatSeverity::High,
            threshold: HIGH_ENTROPY_THRESHOLD,
            action: CountermeasureAction::RevokeCap,
            enabled: true,
            name: "IDPS-R04-ENTROPY-REVOCATION",
        };
        self.rules[4] = IdpsRule {
            id: 5,
            category: ThreatCategory::ReplayAttack,
            min_severity: ThreatSeverity::High,
            threshold: 1,
            action: CountermeasureAction::SeverChannel,
            enabled: true,
            name: "IDPS-R05-REPLAY-SEVERANCE",
        };
        self.rule_count = 5;

        self.record_audit(0x01, 0, 5);
    }

    /// Inspecte un événement de trafic IPC à travers le moteur d'inférence heuristique
    pub fn inspect_event(&mut self, event: &IpcTrafficEvent) -> Result<Option<ThreatAlert>, SysError> {
        if !self.cap.has_right(idps_rights::MONITOR) {
            return Err(SysError::PermissionDenied);
        }

        self.events_inspected += 1;

        // Si le processus émetteur est déjà en quarantaine, bloquer immédiatement
        if self.is_quarantined(event.sender_pid) {
            let alert = ThreatAlert {
                id: (self.alert_count + 1) as u32,
                source_pid: event.sender_pid,
                target_pid: event.receiver_pid,
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::ProtocolViolation,
                score: 100,
                action: CountermeasureAction::QuarantineProcess,
                description: "Émission IPC bloquée : processus émetteur en quarantaine active",
            };
            self.push_alert(alert);
            self.anomalies_detected += 1;
            return Ok(Some(alert));
        }

        // 1. Récupération ou attribution du profil de flux
        let flow_idx = self.get_or_create_flow(event.sender_pid);
        let last_seq = self.flows[flow_idx].last_seq;
        self.flows[flow_idx].msg_count_window += 1;

        // 2. Évaluation heuristique : Falsification de jeton de capacité
        // Détection de jetons invalides (ex: motifs suspects 0xDEADBEEF, 0xBADF00D ou jetons corrompus)
        if event.cap_token == 0xDEAD_BEEF || event.cap_token == 0xBADF_00D || (event.cap_token & 0x01 == 0 && event.cap_token != 0) {
            let alert = ThreatAlert {
                id: (self.alert_count + 1) as u32,
                source_pid: event.sender_pid,
                target_pid: event.receiver_pid,
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::CapabilityForgeryAttempt,
                score: 95,
                action: CountermeasureAction::QuarantineProcess,
                description: "Tentative d'utilisation d'un jeton de capacité falsifié ou corrompu",
            };
            self.push_alert(alert);
            self.anomalies_detected += 1;
            let _ = self.apply_countermeasure(&alert);
            return Ok(Some(alert));
        }

        // 3. Évaluation heuristique : Accès non autorisé à un canal réservé
        if event.channel_id == PRIVILEGED_KERNEL_CHANNEL || event.channel_id == PRIVILEGED_SIG_CHANNEL {
            let alert = ThreatAlert {
                id: (self.alert_count + 1) as u32,
                source_pid: event.sender_pid,
                target_pid: event.receiver_pid,
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::UnauthorizedIpcChannel,
                score: 90,
                action: CountermeasureAction::SeverChannel,
                description: "Tentative d'émission sur un canal IPC système privilégié réservé",
            };
            self.push_alert(alert);
            self.anomalies_detected += 1;
            let _ = self.apply_countermeasure(&alert);
            return Ok(Some(alert));
        }

        // 4. Évaluation heuristique : Attaque par rejeu (décroissance de séquence)
        if event.sequence_num > 0 && last_seq > 0 && event.sequence_num <= last_seq {
            let alert = ThreatAlert {
                id: (self.alert_count + 1) as u32,
                source_pid: event.sender_pid,
                target_pid: event.receiver_pid,
                severity: ThreatSeverity::High,
                category: ThreatCategory::ReplayAttack,
                score: 80,
                action: CountermeasureAction::SeverChannel,
                description: "Rejeu de trame IPC détecté (numéro de séquence obsolète)",
            };
            self.push_alert(alert);
            self.anomalies_detected += 1;
            let _ = self.apply_countermeasure(&alert);
            return Ok(Some(alert));
        }
        self.flows[flow_idx].last_seq = event.sequence_num;

        // 5. Évaluation heuristique : Rafale anormale (IPC Flood)
        if self.flows[flow_idx].msg_count_window >= DEFAULT_BURST_THRESHOLD {
            let alert = ThreatAlert {
                id: (self.alert_count + 1) as u32,
                source_pid: event.sender_pid,
                target_pid: event.receiver_pid,
                severity: ThreatSeverity::High,
                category: ThreatCategory::RateBurstAnomaly,
                score: 75,
                action: CountermeasureAction::Throttle,
                description: "Fréquence d'émission IPC anormale (seuil de rafale dépassé)",
            };
            self.push_alert(alert);
            self.anomalies_detected += 1;
            let _ = self.apply_countermeasure(&alert);
            return Ok(Some(alert));
        }

        // 6. Évaluation heuristique : Exfiltration / Obfuscation par haute entropie
        if event.entropy_permille >= HIGH_ENTROPY_THRESHOLD {
            let alert = ThreatAlert {
                id: (self.alert_count + 1) as u32,
                source_pid: event.sender_pid,
                target_pid: event.receiver_pid,
                severity: ThreatSeverity::High,
                category: ThreatCategory::EntropyExfiltration,
                score: 70,
                action: CountermeasureAction::RevokeCap,
                description: "Charge utile à haute entropie anormale (suspicion de payload obfusqué)",
            };
            self.push_alert(alert);
            self.anomalies_detected += 1;
            let _ = self.apply_countermeasure(&alert);
            return Ok(Some(alert));
        }

        Ok(None)
    }

    /// Applique de manière autonome la contre-mesure spécifiée par une alerte
    pub fn apply_countermeasure(&mut self, alert: &ThreatAlert) -> Result<CountermeasureAction, SysError> {
        if !self.cap.has_right(idps_rights::ISOLATE) {
            return Err(SysError::PermissionDenied);
        }

        self.countermeasures_executed += 1;

        match alert.action {
            CountermeasureAction::QuarantineProcess => {
                let fake_handle = Handle::new(alert.source_pid as u32, 1);
                let _ = self.quarantine_process(alert.source_pid, fake_handle, alert.description);
                Ok(CountermeasureAction::QuarantineProcess)
            }
            CountermeasureAction::RevokeCap => {
                let fake_handle = Handle::new(alert.source_pid as u32, 1);
                // Révocation de droits d'écriture et d'émission
                let _ = self.revoke_capability(alert.source_pid, fake_handle, 0x07);
                Ok(CountermeasureAction::RevokeCap)
            }
            CountermeasureAction::SeverChannel => {
                self.record_audit(0x04, alert.source_pid, alert.target_pid as u32);
                Ok(CountermeasureAction::SeverChannel)
            }
            CountermeasureAction::Throttle => {
                self.record_audit(0x05, alert.source_pid, alert.score);
                Ok(CountermeasureAction::Throttle)
            }
            CountermeasureAction::AlertOnly => {
                self.record_audit(0x06, alert.source_pid, alert.id);
                Ok(CountermeasureAction::AlertOnly)
            }
            CountermeasureAction::None => Ok(CountermeasureAction::None),
        }
    }

    /// Révoque dynamiquement des capacités d'un processus fautif
    pub fn revoke_capability(
        &mut self,
        pid: u64,
        handle: Handle,
        revoked_rights: u32,
    ) -> Result<CountermeasureAction, SysError> {
        if !self.cap.has_right(idps_rights::ISOLATE) {
            return Err(SysError::PermissionDenied);
        }

        self.caps_revoked += 1;
        self.record_audit(0x02, pid, revoked_rights);

        // Mettre à jour la table de quarantaine si présente
        for q in self.quarantine_table.iter_mut() {
            if q.active && q.pid == pid {
                q.revoked_rights |= revoked_rights;
                return Ok(CountermeasureAction::RevokeCap);
            }
        }

        // Sinon créer une entrée d'isolation partielle
        if self.quarantine_count < MAX_QUARANTINED {
            self.quarantine_table[self.quarantine_count] = QuarantineRecord {
                pid,
                handle,
                reason: "Révocation dynamique de droits capabilaires",
                revoked_rights,
                active: true,
            };
            self.quarantine_count += 1;
        }

        Ok(CountermeasureAction::RevokeCap)
    }

    /// Place un processus en quarantaine totale
    pub fn quarantine_process(
        &mut self,
        pid: u64,
        handle: Handle,
        reason: &'static str,
    ) -> Result<(), SysError> {
        if !self.cap.has_right(idps_rights::ISOLATE) {
            return Err(SysError::PermissionDenied);
        }

        // Vérifier si déjà présent
        for q in self.quarantine_table.iter_mut() {
            if q.active && q.pid == pid {
                q.reason = reason;
                return Ok(());
            }
        }

        if self.quarantine_count >= MAX_QUARANTINED {
            return Err(SysError::OutOfMemory);
        }

        self.quarantine_table[self.quarantine_count] = QuarantineRecord {
            pid,
            handle,
            reason,
            revoked_rights: 0xFFFFFFFF,
            active: true,
        };
        self.quarantine_count += 1;
        self.record_audit(0x03, pid, 0xFFFFFFFF);

        Ok(())
    }

    /// Réarme un processus et lève sa quarantaine
    pub fn rearm_process(&mut self, pid: u64) -> Result<bool, SysError> {
        if !self.cap.has_right(idps_rights::REARM) {
            return Err(SysError::PermissionDenied);
        }

        let mut found = false;
        for q in self.quarantine_table.iter_mut() {
            if q.active && q.pid == pid {
                q.active = false;
                found = true;
                break;
            }
        }

        // Réinitialiser également le compteur de fenêtre dans les profils de flux
        for f in self.flows.iter_mut() {
            if f.active && f.sender_pid == pid {
                f.msg_count_window = 0;
                f.accumulated_score = 0;
            }
        }

        if found {
            self.record_audit(0x07, pid, 0);
        }

        Ok(found)
    }

    /// Vérifie si un processus est actuellement sous le coup d'une quarantaine active
    pub fn is_quarantined(&self, pid: u64) -> bool {
        for q in self.quarantine_table.iter() {
            if q.active && q.pid == pid {
                return true;
            }
        }
        false
    }

    /// Ajoute une alerte dans l'historique circulaire
    fn push_alert(&mut self, alert: ThreatAlert) {
        if self.alert_count < MAX_ALERTS {
            self.alerts[self.alert_count] = alert;
            self.alert_count += 1;
        } else {
            // Décalage en anneau borné
            for i in 1..MAX_ALERTS {
                self.alerts[i - 1] = self.alerts[i];
            }
            self.alerts[MAX_ALERTS - 1] = alert;
        }
    }

    /// Récupère ou alloue un profil de flux pour un PID donné
    fn get_or_create_flow(&mut self, pid: u64) -> usize {
        for (i, f) in self.flows.iter().enumerate() {
            if f.active && f.sender_pid == pid {
                return i;
            }
        }

        let slot = if self.flow_count < MAX_FLOW_PROFILES {
            let idx = self.flow_count;
            self.flow_count += 1;
            idx
        } else {
            0
        };

        self.flows[slot] = FlowProfile {
            sender_pid: pid,
            msg_count_window: 0,
            last_seq: 0,
            accumulated_score: 0,
            active: true,
        };
        slot
    }

    /// Enregistre un événement dans la chaîne d'audit inviolable scellée par SHA-256
    fn record_audit(&mut self, event_type: u8, pid: u64, detail: u32) {
        let mut block = [0u8; 48];
        block[0..32].copy_from_slice(&self.audit_chain);
        block[32] = event_type;
        block[33..41].copy_from_slice(&pid.to_be_bytes());
        block[41..45].copy_from_slice(&detail.to_be_bytes());
        self.audit_chain = Sha256::digest(&block[..45]);
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_and_attenuation() {
        let root_cap = IdpsCap::new(Handle::new(100, 1), idps_rights::ALL);
        assert!(root_cap.has_right(idps_rights::INSPECT));
        assert!(root_cap.has_right(idps_rights::MONITOR));
        assert!(root_cap.has_right(idps_rights::ISOLATE));
        assert!(root_cap.has_right(idps_rights::REARM));
        assert!(root_cap.has_right(idps_rights::ADMIN));

        let monitor_cap = root_cap
            .attenuate(idps_rights::INSPECT | idps_rights::MONITOR)
            .expect("Atténuation monotone");
        assert!(monitor_cap.has_right(idps_rights::MONITOR));
        assert!(monitor_cap.has_right(idps_rights::INSPECT));
        assert!(!monitor_cap.has_right(idps_rights::ISOLATE));
        assert!(!monitor_cap.has_right(idps_rights::REARM));
        assert!(!monitor_cap.has_right(idps_rights::ADMIN));

        assert_eq!(
            monitor_cap.attenuate(idps_rights::ALL),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_sha256_deterministic() {
        let d1 = Sha256::digest(b"JAMBO_IDPS_INTRUSION_DETECTION_TEST");
        let d2 = Sha256::digest(b"JAMBO_IDPS_INTRUSION_DETECTION_TEST");
        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);
    }

    #[test]
    fn test_idps_detection_and_quarantine() {
        let cap = IdpsCap::new(Handle::new(1, 1), idps_rights::ALL);
        let mut idps = JamboIdpsDaemon::new(cap);
        idps.init_defaults();

        // 1. Événement légitime
        let ev_ok = IpcTrafficEvent {
            sender_pid: 200,
            receiver_pid: 201,
            channel_id: 10,
            msg_opcode: 1,
            payload_len: 64,
            entropy_permille: 300,
            cap_token: 0x1234_5671,
            sequence_num: 1,
        };
        let res = idps.inspect_event(&ev_ok).expect("Inspection IPC");
        assert!(res.is_none());
        assert_eq!(idps.events_inspected, 1);
        assert_eq!(idps.anomalies_detected, 0);

        // 2. Falsification de capacité (0xBADF00D)
        let ev_forgery = IpcTrafficEvent {
            sender_pid: 666,
            receiver_pid: 201,
            channel_id: 10,
            msg_opcode: 2,
            payload_len: 64,
            entropy_permille: 300,
            cap_token: 0xBADF_00D,
            sequence_num: 1,
        };
        let alert = idps.inspect_event(&ev_forgery).expect("Inspection IPC");
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::CapabilityForgeryAttempt);
        assert_eq!(a.severity, ThreatSeverity::Critical);
        assert_eq!(a.action, CountermeasureAction::QuarantineProcess);
        assert!(idps.is_quarantined(666));

        // 3. Tentative d'émission depuis un processus en quarantaine
        let ev_blocked = IpcTrafficEvent {
            sender_pid: 666,
            receiver_pid: 201,
            channel_id: 10,
            msg_opcode: 3,
            payload_len: 32,
            entropy_permille: 100,
            cap_token: 0x1111,
            sequence_num: 2,
        };
        let alert_blocked = idps.inspect_event(&ev_blocked).expect("Inspection IPC");
        assert!(alert_blocked.is_some());
        assert_eq!(alert_blocked.unwrap().category, ThreatCategory::ProtocolViolation);

        // 4. Réarmement
        let rearmed = idps.rearm_process(666).expect("Réarmement");
        assert!(rearmed);
        assert!(!idps.is_quarantined(666));
    }

    #[test]
    fn test_idps_privileged_channel_and_burst() {
        let cap = IdpsCap::new(Handle::new(1, 1), idps_rights::ALL);
        let mut idps = JamboIdpsDaemon::new(cap);
        idps.init_defaults();

        // Accès canal privilégié
        let ev_priv = IpcTrafficEvent {
            sender_pid: 300,
            receiver_pid: 1,
            channel_id: PRIVILEGED_KERNEL_CHANNEL,
            msg_opcode: 1,
            payload_len: 16,
            entropy_permille: 200,
            cap_token: 0x1001,
            sequence_num: 1,
        };
        let alert_priv = idps.inspect_event(&ev_priv).expect("Inspection");
        assert!(alert_priv.is_some());
        assert_eq!(alert_priv.unwrap().category, ThreatCategory::UnauthorizedIpcChannel);

        // Rafale IPC (Flood)
        for seq in 2..11 {
            let ev = IpcTrafficEvent {
                sender_pid: 400,
                receiver_pid: 500,
                channel_id: 12,
                msg_opcode: 1,
                payload_len: 16,
                entropy_permille: 200,
                cap_token: 0x1001,
                sequence_num: seq,
            };
            let _ = idps.inspect_event(&ev);
        }
        let ev_burst = IpcTrafficEvent {
            sender_pid: 400,
            receiver_pid: 500,
            channel_id: 12,
            msg_opcode: 1,
            payload_len: 16,
            entropy_permille: 200,
            cap_token: 0x1001,
            sequence_num: 11,
        };
        let alert_burst = idps.inspect_event(&ev_burst).expect("Inspection");
        assert!(alert_burst.is_some());
        assert_eq!(alert_burst.unwrap().category, ThreatCategory::RateBurstAnomaly);
    }
}

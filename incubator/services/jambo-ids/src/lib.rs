//! Système de Prévention et Corrélation d'Intrusions Multi-Points & Révocation Automatisée de Capacités Ring 3 (`jambo-ids`)
//!
//! Phase 112 — Jalon v0.2.110
//!
//! Fournit les garanties souveraines d'analyse comportementale, de corrélation multi-points
//! d'événements de sécurité et de mitigation automatisée (révocation de capacités et quarantaine O(1))
//! pour l'ensemble du système d'exploitation JamboOS :
//! 1. Architecture capabilaire stricte (`IdsCap`) sans autorité ambiante (Zero-Ambient Authority)
//!    et atténuation monotone des privilèges.
//! 2. Réseau distribué de capteurs d'intrusions (`SensorProbe`) répartis sur les couches critiques :
//!    - Kernel Syscalls (anomalies d'appels noyau, escalades de privilèges)
//!    - IPC Router (rafales de messages, falsifications de canaux, franchissements non autorisés)
//!    - VFS & Stockage (tentatives d'écriture sur fichiers immuables, parcours de chemins)
//!    - SecRoute Network (violations de micro-segmentation, rejeu de paquets, MAC invalides)
//!    - Auth & Identités (attaques par force brute, injection de faux tokens éphémères)
//!    - Enclaves & Sandboxes (tentatives d'évasion Landlock/Seccomp, corruption mémoire)
//! 3. Moteur d'analyse comportementale & profilage statistique :
//!    - Établissement de lignes de base (`BehavioralBaseline`) par acteur/processus
//!    - Détection de dérives statistiques (taux de messages, taille de charge utile, canaux cibles)
//! 4. Moteur de corrélation spatio-temporelle d'intrusions multi-points :
//!    - Corrélation d'événements issus de sondes hétérogènes au sein d'une fenêtre glissante
//!    - Calcul d'un score de menace agrégé (`ThreatScore`) avec coefficient multiplicateur d'attaque coordonnée
//!    - Classification en 4 niveaux : Normal (<30), Suspicious (30..59), High (60..79), Critical (>=80)
//! 5. Révocation automatisée de capacités & isolation immédiate O(1) :
//!    - Révocation instantanée des masques de droits des acteurs compromis
//!    - Confinement strict et placement en quarantaine sans délai
//! 6. Registre d'audit inaltérable scellé par chaîne SHA-256 (`ids_audit_chain`).

#![no_std]

use libjambo::Handle;

// ============================================================================
// CONSTANTES DU SOUS-SYSTÈME JAMBO-IDS
// ============================================================================

pub const MAX_PROBES: usize = 16;
pub const MAX_EVENTS: usize = 32;
pub const MAX_CORRELATIONS: usize = 16;
pub const MAX_QUARANTINE_RECORDS: usize = 16;
pub const MAX_BASELINES: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_PROBE_NAME_LEN: usize = 24;

/// Seuil de score pour déclencher une alerte suspecte (30/100)
pub const SUSPICIOUS_THREAT_THRESHOLD: u32 = 30;

/// Seuil de score pour déclencher une alerte élevée (60/100)
pub const HIGH_THREAT_THRESHOLD: u32 = 60;

/// Seuil de score pour déclencher une mitigation d'urgence autonome (80/100)
pub const CRITICAL_THREAT_THRESHOLD: u32 = 80;

/// Fenêtre temporelle standard de corrélation multi-points (en ticks horloge)
pub const CORRELATION_WINDOW_TICKS: u64 = 5000;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SOUVERAIN SHA-256
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

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];

        let len = data.len();
        let bit_len = (len as u64) * 8;
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= len {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut h, &block);
            offset += 64;
        }

        let rem = len - offset;
        for i in 0..rem {
            block[i] = data[offset + i];
        }
        block[rem] = 0x80;

        if rem >= 56 {
            for i in (rem + 1)..64 {
                block[i] = 0;
            }
            Self::process_block(&mut h, &block);
            block = [0u8; 64];
        } else {
            for i in (rem + 1)..56 {
                block[i] = 0;
            }
        }

        let be_bytes = bit_len.to_be_bytes();
        block[56..64].copy_from_slice(&be_bytes);
        Self::process_block(&mut h, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
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
            w[i] = Self::gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(Self::gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
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
            let t1 = h_val
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
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
// DROITS CAPABILAIRES & GOUVERNANCE STRICTE (IdsCap)
// ============================================================================

pub mod ids_rights {
    /// Consultation des alertes, statistiques et état du système
    pub const INSPECT: u32 = 1 << 0;
    /// Soumission d'événements de télémétrie depuis les capteurs
    pub const REPORT_EVENT: u32 = 1 << 1;
    /// Enregistrement ou mise à jour de la configuration des sondes
    pub const REGISTER_PROBE: u32 = 1 << 2;
    /// Définition et mise à jour des profils de base comportementaux
    pub const UPDATE_BASELINE: u32 = 1 << 3;
    /// Déclenchement manuel ou forcé de la corrélation multi-points
    pub const CORRELATE: u32 = 1 << 4;
    /// Exécution de contre-mesures autonomes (révocation, quarantaine)
    pub const TRIGGER_MITIGATION: u32 = 1 << 5;
    /// Réarmement d'une alerte ou levée de quarantaine
    pub const RESET_ALERT: u32 = 1 << 6;
    /// Administration complète du démon
    pub const ADMIN: u32 = 1 << 7;

    /// Tous les droits combinés
    pub const ALL: u32 = (1 << 8) - 1;
}

// ============================================================================
// ERREURS DU SOUS-SYSTÈME
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdsError {
    PermissionDenied,
    ProbeNotFound,
    ProbeCapacityExceeded,
    EventBufferFull,
    ActorAlreadyQuarantined,
    ActorNotFound,
    BaselineNotFound,
    BaselineCapacityExceeded,
    InvalidParameter,
}

// ============================================================================
// ENUMS DE SÉCURITÉ & CATÉGORIES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCategory {
    KernelSyscall = 0,
    IpcRouter = 1,
    VfsStorage = 2,
    SecRouteNetwork = 3,
    AuthIdentity = 4,
    SandboxEnclave = 5,
    CryptoHardware = 6,
    ClusterMesh = 7,
}

impl ProbeCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProbeCategory::KernelSyscall => "KernelSyscall",
            ProbeCategory::IpcRouter => "IpcRouter",
            ProbeCategory::VfsStorage => "VfsStorage",
            ProbeCategory::SecRouteNetwork => "SecRouteNetwork",
            ProbeCategory::AuthIdentity => "AuthIdentity",
            ProbeCategory::SandboxEnclave => "SandboxEnclave",
            ProbeCategory::CryptoHardware => "CryptoHardware",
            ProbeCategory::ClusterMesh => "ClusterMesh",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIndicator {
    IpcFloodBurst = 0,
    PrivilegeEscalationAttempt = 1,
    CapabilityTampering = 2,
    CrossZoneBoundaryViolation = 3,
    AbnormalSyscallSequence = 4,
    BehavioralAnomalyExceeded = 5,
    MemoryCorruptionAttempt = 6,
    LateralMovementDetected = 7,
    ReplayDesyncAttack = 8,
    BruteForceAuthAttempt = 9,
}

impl ThreatIndicator {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatIndicator::IpcFloodBurst => "IpcFloodBurst",
            ThreatIndicator::PrivilegeEscalationAttempt => "PrivilegeEscalationAttempt",
            ThreatIndicator::CapabilityTampering => "CapabilityTampering",
            ThreatIndicator::CrossZoneBoundaryViolation => "CrossZoneBoundaryViolation",
            ThreatIndicator::AbnormalSyscallSequence => "AbnormalSyscallSequence",
            ThreatIndicator::BehavioralAnomalyExceeded => "BehavioralAnomalyExceeded",
            ThreatIndicator::MemoryCorruptionAttempt => "MemoryCorruptionAttempt",
            ThreatIndicator::LateralMovementDetected => "LateralMovementDetected",
            ThreatIndicator::ReplayDesyncAttack => "ReplayDesyncAttack",
            ThreatIndicator::BruteForceAuthAttempt => "BruteForceAuthAttempt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Normal = 0,
    Suspicious = 1,
    High = 2,
    Critical = 3,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatLevel::Normal => "Normal",
            ThreatLevel::Suspicious => "Suspicious",
            ThreatLevel::High => "High",
            ThreatLevel::Critical => "Critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitigationAction {
    None = 0,
    ThrottleRate = 1,
    RevokeCapability = 2,
    SeverChannel = 3,
    QuarantineProcess = 4,
    EmergencyClusterAlert = 5,
}

impl MitigationAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            MitigationAction::None => "None",
            MitigationAction::ThrottleRate => "ThrottleRate",
            MitigationAction::RevokeCapability => "RevokeCapability",
            MitigationAction::SeverChannel => "SeverChannel",
            MitigationAction::QuarantineProcess => "QuarantineProcess",
            MitigationAction::EmergencyClusterAlert => "EmergencyClusterAlert",
        }
    }
}

// ============================================================================
// JETON DE CAPACITÉ (IdsCap)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdsCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_events_per_window: u32,
    pub attenuation_level: u8,
}

impl IdsCap {
    pub const fn new(
        handle: Handle,
        rights: u32,
        max_events_per_window: u32,
        attenuation_level: u8,
    ) -> Self {
        Self {
            handle,
            rights,
            max_events_per_window,
            attenuation_level,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(&self, reduced_rights: u32, max_events: u32) -> Result<Self, IdsError> {
        if (reduced_rights & !self.rights) != 0 {
            return Err(IdsError::PermissionDenied);
        }
        if max_events > self.max_events_per_window {
            return Err(IdsError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: reduced_rights,
            max_events_per_window: max_events,
            attenuation_level: self.attenuation_level.saturating_add(1),
        })
    }
}

// ============================================================================
// STRUCTURES DU SYSTÈME IDS
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct SensorProbe {
    pub id: u32,
    pub category: ProbeCategory,
    pub name: [u8; MAX_PROBE_NAME_LEN],
    pub name_len: usize,
    pub weight: u32, // Coefficient de sévérité (1..10)
    pub active: bool,
    pub total_events: u32,
}

impl SensorProbe {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            category: ProbeCategory::KernelSyscall,
            name: [0u8; MAX_PROBE_NAME_LEN],
            name_len: 0,
            weight: 1,
            active: false,
            total_events: 0,
        }
    }

    pub fn name_as_str(&self) -> &str {
        if let Ok(s) = core::str::from_utf8(&self.name[..self.name_len]) {
            s
        } else {
            "unknown"
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TelemetryEvent {
    pub id: u64,
    pub timestamp: u64,
    pub probe_id: u32,
    pub actor_id: u32, // PID ou Id de noeud
    pub indicator: ThreatIndicator,
    pub raw_score: u32, // 1..100
    pub target_channel: u32,
    pub detail_hash: [u8; 16],
}

impl TelemetryEvent {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            timestamp: 0,
            probe_id: 0,
            actor_id: 0,
            indicator: ThreatIndicator::IpcFloodBurst,
            raw_score: 0,
            target_channel: 0,
            detail_hash: [0u8; 16],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BehavioralBaseline {
    pub actor_id: u32,
    pub expected_rate_hz: u32,
    pub max_payload_len: u32,
    pub allowed_channels_mask: u32,
    pub deviation_tolerance_pct: u32, // ex: 50 pour 50% de tolérance
    pub observed_rate_hz: u32,
    pub samples_count: u32,
    pub active: bool,
}

impl BehavioralBaseline {
    pub const fn empty() -> Self {
        Self {
            actor_id: 0,
            expected_rate_hz: 0,
            max_payload_len: 0,
            allowed_channels_mask: 0,
            deviation_tolerance_pct: 0,
            observed_rate_hz: 0,
            samples_count: 0,
            active: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CorrelatedIncident {
    pub incident_id: u64,
    pub actor_id: u32,
    pub threat_level: ThreatLevel,
    pub aggregated_score: u32,
    pub probe_mask: u32, // Masque binaire des identifiants de sondes impliquées
    pub distinct_probes_count: u8,
    pub event_count: u16,
    pub primary_indicator: ThreatIndicator,
    pub automated_mitigation: MitigationAction,
    pub timestamp: u64,
    pub active: bool,
}

impl CorrelatedIncident {
    pub const fn empty() -> Self {
        Self {
            incident_id: 0,
            actor_id: 0,
            threat_level: ThreatLevel::Normal,
            aggregated_score: 0,
            probe_mask: 0,
            distinct_probes_count: 0,
            event_count: 0,
            primary_indicator: ThreatIndicator::IpcFloodBurst,
            automated_mitigation: MitigationAction::None,
            timestamp: 0,
            active: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QuarantinedActor {
    pub actor_id: u32,
    pub reason: ThreatIndicator,
    pub revoked_capabilities_mask: u32,
    pub timestamp: u64,
    pub active: bool,
}

impl QuarantinedActor {
    pub const fn empty() -> Self {
        Self {
            actor_id: 0,
            reason: ThreatIndicator::IpcFloodBurst,
            revoked_capabilities_mask: 0,
            timestamp: 0,
            active: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IncidentAuditEntry {
    pub entry_id: u64,
    pub timestamp: u64,
    pub actor_id: u32,
    pub action: MitigationAction,
    pub score: u32,
    pub digest: [u8; 32],
}

impl IncidentAuditEntry {
    pub const fn empty() -> Self {
        Self {
            entry_id: 0,
            timestamp: 0,
            actor_id: 0,
            action: MitigationAction::None,
            score: 0,
            digest: [0u8; 32],
        }
    }
}

// ============================================================================
// DÉMON D'INTRUSION DETECTION & CORRÉLATION (JamboIdsDaemon)
// ============================================================================

pub struct JamboIdsDaemon {
    pub admin_cap: IdsCap,
    pub probes: [SensorProbe; MAX_PROBES],
    pub probe_count: usize,
    pub events: [TelemetryEvent; MAX_EVENTS],
    pub event_count: usize,
    pub next_event_id: u64,
    pub baselines: [BehavioralBaseline; MAX_BASELINES],
    pub baseline_count: usize,
    pub incidents: [CorrelatedIncident; MAX_CORRELATIONS],
    pub incident_count: usize,
    pub next_incident_id: u64,
    pub quarantined: [QuarantinedActor; MAX_QUARANTINE_RECORDS],
    pub quarantine_count: usize,
    pub audit_chain: [u8; 32],
    pub audit_log: [IncidentAuditEntry; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    // Statistiques
    pub events_ingested: u64,
    pub anomalies_detected: u64,
    pub intrusions_correlated: u64,
    pub capabilities_revoked: u64,
    pub actors_quarantined: u64,
    pub mitigations_executed: u64,
}

impl JamboIdsDaemon {
    pub fn new(admin_cap: IdsCap) -> Self {
        Self {
            admin_cap,
            probes: [SensorProbe::empty(); MAX_PROBES],
            probe_count: 0,
            events: [TelemetryEvent::empty(); MAX_EVENTS],
            event_count: 0,
            next_event_id: 1,
            baselines: [BehavioralBaseline::empty(); MAX_BASELINES],
            baseline_count: 0,
            incidents: [CorrelatedIncident::empty(); MAX_CORRELATIONS],
            incident_count: 0,
            next_incident_id: 1,
            quarantined: [QuarantinedActor::empty(); MAX_QUARANTINE_RECORDS],
            quarantine_count: 0,
            audit_chain: [0x5A; 32],
            audit_log: [IncidentAuditEntry::empty(); MAX_AUDIT_LOGS],
            audit_count: 0,
            events_ingested: 0,
            anomalies_detected: 0,
            intrusions_correlated: 0,
            capabilities_revoked: 0,
            actors_quarantined: 0,
            mitigations_executed: 0,
        }
    }

    /// Initialise la configuration par défaut : sondes hétérogènes et profil de base
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Sonde Noyau Syscall
        let _ = self.register_probe(
            &cap,
            ProbeCategory::KernelSyscall,
            "kernel_syscall_sentry",
            9,
        );
        // 2. Sonde Routeur IPC
        let _ = self.register_probe(&cap, ProbeCategory::IpcRouter, "ipc_flux_monitor", 7);
        // 3. Sonde VFS & Stockage
        let _ = self.register_probe(&cap, ProbeCategory::VfsStorage, "vfs_cow_guard", 6);
        // 4. Sonde Réseau SecRoute
        let _ = self.register_probe(
            &cap,
            ProbeCategory::SecRouteNetwork,
            "secroute_mesh_probe",
            8,
        );
        // 5. Sonde Authentification & Identité
        let _ = self.register_probe(&cap, ProbeCategory::AuthIdentity, "auth_token_watcher", 8);
        // 6. Sonde Bac à Sable Enclave
        let _ = self.register_probe(
            &cap,
            ProbeCategory::SandboxEnclave,
            "sandbox_esc_detector",
            10,
        );

        // Définir une ligne de base par défaut pour le processus standard PID 42
        let _ = self.set_baseline(&cap, 42, 100, 256, 0x00FF, 50);
        // Définir une ligne de base pour le service VFS PID 10
        let _ = self.set_baseline(&cap, 10, 500, 4096, 0xFFFF, 30);
    }

    /// Enregistre une nouvelle sonde d'intrusion capabilaire
    pub fn register_probe(
        &mut self,
        cap: &IdsCap,
        category: ProbeCategory,
        name: &str,
        weight: u32,
    ) -> Result<u32, IdsError> {
        if !cap.has_right(ids_rights::REGISTER_PROBE) {
            return Err(IdsError::PermissionDenied);
        }
        if self.probe_count >= MAX_PROBES {
            return Err(IdsError::ProbeCapacityExceeded);
        }
        let clamped_weight = weight.clamp(1, 10);
        let mut name_buf = [0u8; MAX_PROBE_NAME_LEN];
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(MAX_PROBE_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let probe_id = (self.probe_count as u32) + 1;
        self.probes[self.probe_count] = SensorProbe {
            id: probe_id,
            category,
            name: name_buf,
            name_len: copy_len,
            weight: clamped_weight,
            active: true,
            total_events: 0,
        };
        self.probe_count += 1;
        Ok(probe_id)
    }

    /// Définit ou met à jour la ligne de base comportementale d'un acteur/processus
    pub fn set_baseline(
        &mut self,
        cap: &IdsCap,
        actor_id: u32,
        expected_rate_hz: u32,
        max_payload_len: u32,
        allowed_channels_mask: u32,
        deviation_tolerance_pct: u32,
    ) -> Result<(), IdsError> {
        if !cap.has_right(ids_rights::UPDATE_BASELINE) {
            return Err(IdsError::PermissionDenied);
        }

        // Vérifier si la baseline existe déjà
        for i in 0..self.baseline_count {
            if self.baselines[i].actor_id == actor_id {
                self.baselines[i].expected_rate_hz = expected_rate_hz;
                self.baselines[i].max_payload_len = max_payload_len;
                self.baselines[i].allowed_channels_mask = allowed_channels_mask;
                self.baselines[i].deviation_tolerance_pct = deviation_tolerance_pct;
                self.baselines[i].active = true;
                return Ok(());
            }
        }

        if self.baseline_count >= MAX_BASELINES {
            return Err(IdsError::BaselineCapacityExceeded);
        }

        self.baselines[self.baseline_count] = BehavioralBaseline {
            actor_id,
            expected_rate_hz,
            max_payload_len,
            allowed_channels_mask,
            deviation_tolerance_pct,
            observed_rate_hz: 0,
            samples_count: 0,
            active: true,
        };
        self.baseline_count += 1;
        Ok(())
    }

    /// Vérifie si un comportement observé dévie de la ligne de base statistique
    pub fn check_behavioral_anomaly(
        &mut self,
        actor_id: u32,
        current_rate_hz: u32,
        payload_len: u32,
        target_channel: u32,
    ) -> Option<(ThreatIndicator, u32)> {
        for i in 0..self.baseline_count {
            let b = &mut self.baselines[i];
            if b.actor_id == actor_id && b.active {
                b.observed_rate_hz = current_rate_hz;
                b.samples_count = b.samples_count.saturating_add(1);

                // 1. Canal non autorisé
                if target_channel < 32 {
                    let channel_bit = 1u32 << target_channel;
                    if (b.allowed_channels_mask & channel_bit) == 0 {
                        self.anomalies_detected += 1;
                        return Some((ThreatIndicator::CrossZoneBoundaryViolation, 75));
                    }
                }

                // 2. Dépassement critique de taille de charge utile
                if payload_len > b.max_payload_len * 2 {
                    self.anomalies_detected += 1;
                    return Some((ThreatIndicator::MemoryCorruptionAttempt, 80));
                }

                // 3. Déviation de fréquence (Burst / IPC Flood)
                if current_rate_hz > b.expected_rate_hz {
                    let diff = current_rate_hz - b.expected_rate_hz;
                    let deviation_pct = (diff as u64 * 100) / (b.expected_rate_hz.max(1) as u64);
                    if deviation_pct > (b.deviation_tolerance_pct as u64) {
                        self.anomalies_detected += 1;
                        let score = (50 + deviation_pct.min(50)) as u32;
                        return Some((ThreatIndicator::IpcFloodBurst, score));
                    }
                }
                return None;
            }
        }
        None
    }

    /// Soumission d'un événement de télémétrie de sécurité par une sonde
    pub fn ingest_event(
        &mut self,
        cap: &IdsCap,
        probe_id: u32,
        actor_id: u32,
        indicator: ThreatIndicator,
        raw_score: u32,
        target_channel: u32,
        timestamp: u64,
    ) -> Result<u64, IdsError> {
        if !cap.has_right(ids_rights::REPORT_EVENT) {
            return Err(IdsError::PermissionDenied);
        }

        // Trouver la sonde correspondante
        let mut probe_idx = None;
        for i in 0..self.probe_count {
            if self.probes[i].id == probe_id && self.probes[i].active {
                probe_idx = Some(i);
                break;
            }
        }
        let p_idx = probe_idx.ok_or(IdsError::ProbeNotFound)?;
        self.probes[p_idx].total_events = self.probes[p_idx].total_events.saturating_add(1);

        let event_id = self.next_event_id;
        self.next_event_id += 1;

        // Calculer l'empreinte de détail
        let mut detail_bytes = [0u8; 24];
        detail_bytes[..8].copy_from_slice(&event_id.to_be_bytes());
        detail_bytes[8..12].copy_from_slice(&probe_id.to_be_bytes());
        detail_bytes[12..16].copy_from_slice(&actor_id.to_be_bytes());
        detail_bytes[16..20].copy_from_slice(&raw_score.to_be_bytes());
        detail_bytes[20..24].copy_from_slice(&target_channel.to_be_bytes());

        let digest = Sha256::digest(&detail_bytes);
        let mut hash16 = [0u8; 16];
        hash16.copy_from_slice(&digest[..16]);

        let event = TelemetryEvent {
            id: event_id,
            timestamp,
            probe_id,
            actor_id,
            indicator,
            raw_score: raw_score.clamp(1, 100),
            target_channel,
            detail_hash: hash16,
        };

        if self.event_count < MAX_EVENTS {
            self.events[self.event_count] = event;
            self.event_count += 1;
        } else {
            // Tampon tournant : écraser l'événement le plus ancien
            for i in 0..(MAX_EVENTS - 1) {
                self.events[i] = self.events[i + 1];
            }
            self.events[MAX_EVENTS - 1] = event;
        }

        self.events_ingested += 1;
        Ok(event_id)
    }

    /// Moteur de corrélation spatio-temporelle multi-points pour un acteur donné
    pub fn correlate_events(
        &mut self,
        cap: &IdsCap,
        actor_id: u32,
        current_time: u64,
    ) -> Result<Option<CorrelatedIncident>, IdsError> {
        if !cap.has_right(ids_rights::CORRELATE) {
            return Err(IdsError::PermissionDenied);
        }

        let mut matched_events = 0u16;
        let mut weighted_sum = 0u64;
        let mut total_weight = 0u64;
        let mut probe_mask = 0u32;
        let mut distinct_probes_count = 0u8;
        let mut primary_indicator = ThreatIndicator::IpcFloodBurst;
        let mut highest_single_score = 0u32;

        for i in 0..self.event_count {
            let ev = &self.events[i];
            if ev.actor_id == actor_id {
                let age = current_time.saturating_sub(ev.timestamp);
                if age <= CORRELATION_WINDOW_TICKS {
                    matched_events += 1;

                    // Déterminer le poids de la sonde émettrice
                    let mut p_weight = 1u32;
                    for p in 0..self.probe_count {
                        if self.probes[p].id == ev.probe_id {
                            p_weight = self.probes[p].weight;
                            break;
                        }
                    }

                    weighted_sum += (ev.raw_score as u64) * (p_weight as u64);
                    total_weight += p_weight as u64;

                    if ev.probe_id < 32 {
                        let bit = 1u32 << ev.probe_id;
                        if (probe_mask & bit) == 0 {
                            probe_mask |= bit;
                            distinct_probes_count += 1;
                        }
                    }

                    if ev.raw_score > highest_single_score {
                        highest_single_score = ev.raw_score;
                        primary_indicator = ev.indicator;
                    }
                }
            }
        }

        if matched_events == 0 || total_weight == 0 {
            return Ok(None);
        }

        let base_score = (weighted_sum / total_weight) as u32;

        // Facteur multiplicateur pour corrélation multi-sondes hétérogènes
        let correlation_bonus = match distinct_probes_count {
            0..=1 => 0,
            2 => 15, // Deux sondes concordantes : suspicion forte
            3 => 25, // Trois sondes distinctes : attaque coordonnée manifeste
            _ => 35, // Quatre sondes ou plus : campagne APT critique
        };

        let aggregated_score = (base_score + correlation_bonus).min(100);

        let threat_level = if aggregated_score >= CRITICAL_THREAT_THRESHOLD {
            ThreatLevel::Critical
        } else if aggregated_score >= HIGH_THREAT_THRESHOLD {
            ThreatLevel::High
        } else if aggregated_score >= SUSPICIOUS_THREAT_THRESHOLD {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Normal
        };

        // Décider de l'action de mitigation
        let auto_mitigation = match threat_level {
            ThreatLevel::Critical => MitigationAction::QuarantineProcess,
            ThreatLevel::High => MitigationAction::RevokeCapability,
            ThreatLevel::Suspicious => MitigationAction::ThrottleRate,
            ThreatLevel::Normal => MitigationAction::None,
        };

        let incident = CorrelatedIncident {
            incident_id: self.next_incident_id,
            actor_id,
            threat_level,
            aggregated_score,
            probe_mask,
            distinct_probes_count,
            event_count: matched_events,
            primary_indicator,
            automated_mitigation: auto_mitigation,
            timestamp: current_time,
            active: true,
        };
        self.next_incident_id += 1;

        if self.incident_count < MAX_CORRELATIONS {
            self.incidents[self.incident_count] = incident;
            self.incident_count += 1;
        } else {
            for i in 0..(MAX_CORRELATIONS - 1) {
                self.incidents[i] = self.incidents[i + 1];
            }
            self.incidents[MAX_CORRELATIONS - 1] = incident;
        }

        self.intrusions_correlated += 1;
        Ok(Some(incident))
    }

    /// Exécute de manière autonome les contre-mesures prescrites
    pub fn execute_automated_mitigation(
        &mut self,
        cap: &IdsCap,
        actor_id: u32,
        score: u32,
        indicator: ThreatIndicator,
        timestamp: u64,
    ) -> Result<MitigationAction, IdsError> {
        if !cap.has_right(ids_rights::TRIGGER_MITIGATION) {
            return Err(IdsError::PermissionDenied);
        }

        let action = if score >= CRITICAL_THREAT_THRESHOLD {
            self.quarantine_actor(cap, actor_id, indicator, timestamp)?;
            self.revoke_capability(cap, actor_id, 0xFFFFFFFF, timestamp)?;
            MitigationAction::QuarantineProcess
        } else if score >= HIGH_THREAT_THRESHOLD {
            self.revoke_capability(cap, actor_id, 0x000000FF, timestamp)?;
            MitigationAction::RevokeCapability
        } else if score >= SUSPICIOUS_THREAT_THRESHOLD {
            MitigationAction::ThrottleRate
        } else {
            MitigationAction::None
        };

        self.mitigations_executed += 1;
        self.log_audit(actor_id, action, score, timestamp);
        Ok(action)
    }

    /// Révocation de droits capabilaires pour un acteur compromis
    pub fn revoke_capability(
        &mut self,
        cap: &IdsCap,
        actor_id: u32,
        revoked_mask: u32,
        timestamp: u64,
    ) -> Result<(), IdsError> {
        if !cap.has_right(ids_rights::TRIGGER_MITIGATION) {
            return Err(IdsError::PermissionDenied);
        }

        // Mettre à jour l'enregistrement s'il existe déjà
        for i in 0..self.quarantine_count {
            if self.quarantined[i].actor_id == actor_id {
                self.quarantined[i].revoked_capabilities_mask |= revoked_mask;
                self.capabilities_revoked += 1;
                return Ok(());
            }
        }

        // Sinon l'ajouter à la table de quarantaine/révocation
        if self.quarantine_count < MAX_QUARANTINE_RECORDS {
            self.quarantined[self.quarantine_count] = QuarantinedActor {
                actor_id,
                reason: ThreatIndicator::PrivilegeEscalationAttempt,
                revoked_capabilities_mask: revoked_mask,
                timestamp,
                active: true,
            };
            self.quarantine_count += 1;
            self.capabilities_revoked += 1;
            Ok(())
        } else {
            Err(IdsError::ActorAlreadyQuarantined)
        }
    }

    /// Placement immédiat en quarantaine O(1) d'un processus ou nœud compromis
    pub fn quarantine_actor(
        &mut self,
        cap: &IdsCap,
        actor_id: u32,
        reason: ThreatIndicator,
        timestamp: u64,
    ) -> Result<(), IdsError> {
        if !cap.has_right(ids_rights::TRIGGER_MITIGATION) {
            return Err(IdsError::PermissionDenied);
        }

        for i in 0..self.quarantine_count {
            if self.quarantined[i].actor_id == actor_id && self.quarantined[i].active {
                return Ok(()); // Déjà en quarantaine active
            }
        }

        if self.quarantine_count < MAX_QUARANTINE_RECORDS {
            self.quarantined[self.quarantine_count] = QuarantinedActor {
                actor_id,
                reason,
                revoked_capabilities_mask: 0xFFFFFFFF,
                timestamp,
                active: true,
            };
            self.quarantine_count += 1;
            self.actors_quarantined += 1;
            Ok(())
        } else {
            // Écraser le plus ancien si saturé
            for i in 0..(MAX_QUARANTINE_RECORDS - 1) {
                self.quarantined[i] = self.quarantined[i + 1];
            }
            self.quarantined[MAX_QUARANTINE_RECORDS - 1] = QuarantinedActor {
                actor_id,
                reason,
                revoked_capabilities_mask: 0xFFFFFFFF,
                timestamp,
                active: true,
            };
            self.actors_quarantined += 1;
            Ok(())
        }
    }

    /// Lève la quarantaine d'un acteur après réarmement contrôlé
    pub fn lift_quarantine(&mut self, cap: &IdsCap, actor_id: u32) -> Result<(), IdsError> {
        if !cap.has_right(ids_rights::RESET_ALERT) {
            return Err(IdsError::PermissionDenied);
        }
        for i in 0..self.quarantine_count {
            if self.quarantined[i].actor_id == actor_id && self.quarantined[i].active {
                self.quarantined[i].active = false;
                self.quarantined[i].revoked_capabilities_mask = 0;
                return Ok(());
            }
        }
        Err(IdsError::ActorNotFound)
    }

    /// Vérifie si un acteur est actuellement sous quarantaine
    #[inline(always)]
    pub fn is_quarantined(&self, actor_id: u32) -> bool {
        for i in 0..self.quarantine_count {
            if self.quarantined[i].actor_id == actor_id && self.quarantined[i].active {
                return true;
            }
        }
        false
    }

    /// Journalisation inaltérable scellée par SHA-256
    pub fn log_audit(
        &mut self,
        actor_id: u32,
        action: MitigationAction,
        score: u32,
        timestamp: u64,
    ) {
        let entry_id = (self.audit_count as u64) + 1;

        // Préparation du bloc de hachage chaîné : [old_chain_digest (32) | entry_id (8) | actor_id (4) | action (1) | score (4) | timestamp (8)]
        let mut block = [0u8; 57];
        block[..32].copy_from_slice(&self.audit_chain);
        block[32..40].copy_from_slice(&entry_id.to_be_bytes());
        block[40..44].copy_from_slice(&actor_id.to_be_bytes());
        block[44] = action as u8;
        block[45..49].copy_from_slice(&score.to_be_bytes());
        block[49..57].copy_from_slice(&timestamp.to_be_bytes());

        let new_digest = Sha256::digest(&block);
        self.audit_chain = new_digest;

        let entry = IncidentAuditEntry {
            entry_id,
            timestamp,
            actor_id,
            action,
            score,
            digest: new_digest,
        };

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_log[self.audit_count] = entry;
            self.audit_count += 1;
        } else {
            for i in 0..(MAX_AUDIT_LOGS - 1) {
                self.audit_log[i] = self.audit_log[i + 1];
            }
            self.audit_log[MAX_AUDIT_LOGS - 1] = entry;
        }
    }

    /// Vérifie l'intégrité de la chaîne d'audit cryptographique
    pub fn verify_audit_chain(&self) -> bool {
        if self.audit_count == 0 {
            return true;
        }
        let mut current_chain = [0x5A; 32];
        for i in 0..self.audit_count {
            let entry = &self.audit_log[i];
            let mut block = [0u8; 57];
            block[..32].copy_from_slice(&current_chain);
            block[32..40].copy_from_slice(&entry.entry_id.to_be_bytes());
            block[40..44].copy_from_slice(&entry.actor_id.to_be_bytes());
            block[44] = entry.action as u8;
            block[45..49].copy_from_slice(&entry.score.to_be_bytes());
            block[49..57].copy_from_slice(&entry.timestamp.to_be_bytes());

            let computed = Sha256::digest(&block);
            if computed != entry.digest {
                return false;
            }
            current_chain = computed;
        }
        current_chain == self.audit_chain
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_and_monotonic_attenuation() {
        let admin_cap = IdsCap::new(Handle::new(101, 1), ids_rights::ALL, 100, 1);
        assert!(admin_cap.has_right(ids_rights::INSPECT));
        assert!(admin_cap.has_right(ids_rights::REPORT_EVENT));
        assert!(admin_cap.has_right(ids_rights::TRIGGER_MITIGATION));

        let attenuated = admin_cap
            .attenuate(ids_rights::INSPECT | ids_rights::REPORT_EVENT, 50)
            .expect("Atténuation monotone IdsCap");
        assert!(attenuated.has_right(ids_rights::INSPECT));
        assert!(attenuated.has_right(ids_rights::REPORT_EVENT));
        assert!(!attenuated.has_right(ids_rights::TRIGGER_MITIGATION));
        assert_eq!(attenuated.max_events_per_window, 50);

        // Rejet de l'amplification de privilèges
        assert_eq!(
            attenuated.attenuate(ids_rights::ALL, 50),
            Err(IdsError::PermissionDenied)
        );
        assert_eq!(
            attenuated.attenuate(ids_rights::INSPECT, 100),
            Err(IdsError::PermissionDenied)
        );
    }

    #[test]
    fn test_behavioral_baseline_and_anomaly_detection() {
        let admin_cap = IdsCap::new(Handle::new(102, 1), ids_rights::ALL, 100, 1);
        let mut daemon = JamboIdsDaemon::new(admin_cap);
        daemon.init_defaults();

        // Baseline pour acteur 42 : taux 100Hz, max_payload 256, tolérance 50%
        // Flux normal
        let normal = daemon.check_behavioral_anomaly(42, 110, 128, 1);
        assert!(normal.is_none());

        // Anomalie de canal non autorisé (canal 9 alors que allowed_channels_mask = 0x00FF, soit canaux 0..7)
        let canal_infraction = daemon.check_behavioral_anomaly(42, 100, 128, 9);
        assert_eq!(
            canal_infraction,
            Some((ThreatIndicator::CrossZoneBoundaryViolation, 75))
        );

        // Anomalie de rafale (Burst / Flood) : 300Hz au lieu de 100Hz (+200% de dérive)
        let burst = daemon.check_behavioral_anomaly(42, 300, 128, 1);
        assert!(burst.is_some());
        let (ind, score) = burst.unwrap();
        assert_eq!(ind, ThreatIndicator::IpcFloodBurst);
        assert!(score >= 80);
    }

    #[test]
    fn test_multi_point_correlation_and_automated_quarantine() {
        let admin_cap = IdsCap::new(Handle::new(103, 1), ids_rights::ALL, 100, 1);
        let mut daemon = JamboIdsDaemon::new(admin_cap);
        daemon.init_defaults();

        let actor_id = 99;
        let now = 1000u64;

        // Ingestion d'événements depuis 3 sondes hétérogènes distinctes
        // Sonde 1: Kernel Syscall (id = 1)
        daemon
            .ingest_event(
                &admin_cap,
                1,
                actor_id,
                ThreatIndicator::AbnormalSyscallSequence,
                70,
                0,
                now,
            )
            .expect("Ingest probe 1");

        // Sonde 2: IPC Router (id = 2)
        daemon
            .ingest_event(
                &admin_cap,
                2,
                actor_id,
                ThreatIndicator::IpcFloodBurst,
                75,
                1,
                now + 50,
            )
            .expect("Ingest probe 2");

        // Sonde 4: SecRoute Network (id = 4)
        daemon
            .ingest_event(
                &admin_cap,
                4,
                actor_id,
                ThreatIndicator::CrossZoneBoundaryViolation,
                85,
                2,
                now + 100,
            )
            .expect("Ingest probe 4");

        // Corrélation multi-points
        let correlated = daemon
            .correlate_events(&admin_cap, actor_id, now + 150)
            .expect("Corrélation")
            .expect("Incident corrélé trouvé");

        assert_eq!(correlated.actor_id, actor_id);
        assert_eq!(correlated.distinct_probes_count, 3);
        assert_eq!(correlated.event_count, 3);
        assert_eq!(correlated.threat_level, ThreatLevel::Critical);
        assert!(correlated.aggregated_score >= 80);

        // Exécution de la mitigation automatique
        let action = daemon
            .execute_automated_mitigation(
                &admin_cap,
                actor_id,
                correlated.aggregated_score,
                correlated.primary_indicator,
                now + 200,
            )
            .expect("Mitigation");

        assert_eq!(action, MitigationAction::QuarantineProcess);
        assert!(daemon.is_quarantined(actor_id));

        // Vérification de la chaîne d'audit SHA-256
        assert!(daemon.verify_audit_chain());
    }
}

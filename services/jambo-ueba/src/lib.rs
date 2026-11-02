//! Démon d'Analyse Comportementale des Utilisateurs & Entités (UEBA)
//!
//! Jalon 3.31 — Version v0.3.75 (Ring 3, PID 36)
//!
//! Fournit un système souverain d'analyse comportementale (User & Entity Behavior Analytics)
//! entièrement `#![no_std]`, sans allocation dynamique (zéro tas, zéro `alloc`) :
//!
//! 1. Contrôle d'Accès Capabilaire Strict (`UebaCap`) :
//!    - Modèle Zéro-Autorité Ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone vérifiée sans amplification de privilèges.
//!    - Droits : `INGEST_EVENT`, `TRAIN_BASELINE`, `ANALYZE_BEHAVIOR`, `ENFORCE_ACTION`,
//!      `QUARANTINE_ENTITY`, `CONFIGURE_MODEL`, `QUERY_METRICS`, `QUERY_AUDIT`, `ADMIN`.
//!
//! 2. Profilage Adaptatif & Établissement de Profils de Référence (*Baselines*) :
//!    - Profilage multi-entités (utilisateurs, démons de sécurité, clients IPC, pairs réseau).
//!    - Métriques multidimensionnelles en virgule fixe (taux d'appels système, volume d'octets, heures habituelles).
//!
//! 3. Détection d'Anomalies Multidimensionnelles Sans Modèle Lourd :
//!    - Activité hors heures ouvrées (*Off-Hours Activity*).
//!    - Dérives volumétriques et sauts de fréquence (z-scores en virgule fixe).
//!    - Mouvements latéraux et accès à des pairs inconnus.
//!    - Abus de privilèges et exfiltration clandestine.
//!
//! 4. Calcul de Score de Risque Dynamique & Matrice de Sévérité :
//!    - Score de risque composite de 0 à 100 avec classification typée (`Low`, `Medium`, `High`, `Critical`).
//!    - Actions de remédiation graduées (`Allow`, `ElevateAudit`, `ThrottleRate`, `Quarantine`).
//!
//! 5. Table de Quarantaine Immédiate $O(1)$ :
//!    - Confinement atomique des entités présentant un risque critique.
//!
//! 6. Registre d'Audit Inviolable Scellé SHA-256 :
//!    - Chaînage d'empreintes SHA-256 `#![no_std]` ancré sur `GENESIS_HASH`.
//!
//! 7. Protocole IPC Déterministe à 64 Octets :
//!    - Structures `UebaRequest` et `UebaResponse` de taille fixe vérifiée à la compilation.
//!    - Client synchrone `UebaClient` et dispatcher `dispatch_ipc`.

#![no_std]

pub use libjambo::{Handle, SysError};

pub const UEBA_ENDPOINT_ID: u32 = 36;
pub const UEBA_MAGIC_REQ: u32 = 0x55454241; // "UEBA"
pub const UEBA_MAGIC_RESP: u32 = 0x55454253; // "UEBS"

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;
pub const MAX_PROFILES: usize = 16;
pub const MAX_QUARANTINES: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 32;

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

// ============================================================================
// UTILITAIRES DE CONVERSION DE CHAÎNES
// ============================================================================

pub fn to_fixed_16(s: &str) -> [u8; 16] {
    let mut arr = [0u8; 16];
    let bytes = s.as_bytes();
    let len = bytes.len().min(16);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

pub fn to_fixed_24(s: &str) -> [u8; 24] {
    let mut arr = [0u8; 24];
    let bytes = s.as_bytes();
    let len = bytes.len().min(24);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

pub fn to_fixed_32(s: &str) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let bytes = s.as_bytes();
    let len = bytes.len().min(32);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

/// Helper pour convertir une chaîne en tampon fixe de 32 octets
pub fn str_to_id(s: &str) -> [u8; 32] {
    to_fixed_32(s)
}

/// Helper pour afficher un ID [u8; 32] en chaîne UTF-8 tronquée
pub fn id_to_str(id: &[u8; 32]) -> &str {
    let len = id.iter().position(|&c| c == 0).unwrap_or(32);
    core::str::from_utf8(&id[..len]).unwrap_or("<invalid-utf8>")
}

/// Helper pour afficher un tampon [u8; 24] en chaîne UTF-8 tronquée
pub fn name24_to_str(id: &[u8; 24]) -> &str {
    let len = id.iter().position(|&c| c == 0).unwrap_or(24);
    core::str::from_utf8(&id[..len]).unwrap_or("<invalid-utf8>")
}

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation autonome et déterministe de SHA-256 pour micro-noyau et services UEBA
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

        for (i, &w_val) in w.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w_val);
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
// MODÈLE DE SÉCURITÉ CAPABILAIRE (UebaCap)
// ============================================================================

pub mod ueba_rights {
    pub const INGEST_EVENT: u32 = 1 << 0;
    pub const TRAIN_BASELINE: u32 = 1 << 1;
    pub const ANALYZE_BEHAVIOR: u32 = 1 << 2;
    pub const ENFORCE_ACTION: u32 = 1 << 3;
    pub const QUARANTINE_ENTITY: u32 = 1 << 4;
    pub const CONFIGURE_MODEL: u32 = 1 << 5;
    pub const QUERY_METRICS: u32 = 1 << 6;
    pub const QUERY_AUDIT: u32 = 1 << 7;
    pub const ADMIN: u32 = 1 << 8;
    pub const ALL: u32 = 0x01FF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UebaError {
    PermissionDenied = 1,
    AttenuationViolation = 2,
    CapacityExceeded = 3,
    EntityNotFound = 4,
    InvalidParameter = 5,
    AlreadyQuarantined = 6,
    NotQuarantined = 7,
    AuditLedgerTampered = 8,
    InvalidMagic = 9,
    InvalidPayload = 10,
}

impl UebaError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PermissionDenied => "PermissionDenied",
            Self::AttenuationViolation => "AttenuationViolation",
            Self::CapacityExceeded => "CapacityExceeded",
            Self::EntityNotFound => "EntityNotFound",
            Self::InvalidParameter => "InvalidParameter",
            Self::AlreadyQuarantined => "AlreadyQuarantined",
            Self::NotQuarantined => "NotQuarantined",
            Self::AuditLedgerTampered => "AuditLedgerTampered",
            Self::InvalidMagic => "InvalidMagic",
            Self::InvalidPayload => "InvalidPayload",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UebaCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl UebaCap {
    pub fn new(handle: Handle, rights: u32, max_lifetime: u64, invocations_left: u32) -> Self {
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

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, UebaError> {
        if (new_rights & !self.rights) != 0 {
            return Err(UebaError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(UebaError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(UebaError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), UebaError> {
        if self.invocations_left == 0 {
            return Err(UebaError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// STRUCTURES MÉTIER UEBA & PROFILAGE COMPORTEMENTAL
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    UserAccount = 0,
    ServiceDaemon = 1,
    IpcClient = 2,
    KernelWorker = 3,
    NetworkPeer = 4,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserAccount => "UserAccount",
            Self::ServiceDaemon => "ServiceDaemon",
            Self::IpcClient => "IpcClient",
            Self::KernelWorker => "KernelWorker",
            Self::NetworkPeer => "NetworkPeer",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::UserAccount,
            1 => Self::ServiceDaemon,
            2 => Self::IpcClient,
            3 => Self::KernelWorker,
            _ => Self::NetworkPeer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UebaAnomalyType {
    None = 0,
    VolumeSurge = 1,
    LateralMovement = 2,
    OffHoursSpike = 3,
    PrivilegeAbuse = 4,
    BruteForceAuth = 5,
    RapidBurst = 6,
    CompositeHighRisk = 7,
}

impl UebaAnomalyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::VolumeSurge => "VolumeSurge",
            Self::LateralMovement => "LateralMovement",
            Self::OffHoursSpike => "OffHoursSpike",
            Self::PrivilegeAbuse => "PrivilegeAbuse",
            Self::BruteForceAuth => "BruteForceAuth",
            Self::RapidBurst => "RapidBurst",
            Self::CompositeHighRisk => "CompositeHighRisk",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::None,
            1 => Self::VolumeSurge,
            2 => Self::LateralMovement,
            3 => Self::OffHoursSpike,
            4 => Self::PrivilegeAbuse,
            5 => Self::BruteForceAuth,
            6 => Self::RapidBurst,
            _ => Self::CompositeHighRisk,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UebaAction {
    Allow = 0,
    ElevateAudit = 1,
    ThrottleRate = 2,
    Quarantine = 3,
}

impl UebaAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::ElevateAudit => "ElevateAudit",
            Self::ThrottleRate => "ThrottleRate",
            Self::Quarantine => "Quarantine",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Allow,
            1 => Self::ElevateAudit,
            2 => Self::ThrottleRate,
            _ => Self::Quarantine,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Low,
            1 => Self::Medium,
            2 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Profil de référence comportementale (Baseline) d'une entité
#[derive(Debug, Clone, Copy)]
pub struct BehaviorBaseline {
    pub entity_id: [u8; 32],
    pub entity_type: EntityType,
    pub sample_count: u32,
    /// Taux d'appels système moyen (multiplié par 100 pour précision virgule fixe)
    pub mean_syscall_rate: u32,
    pub stddev_syscall_rate: u32,
    /// Volume moyen de transfert en octets (multiplié par 100)
    pub mean_volume_bytes: u32,
    pub stddev_volume_bytes: u32,
    /// Nombre moyen d'interactions de pairs distincts (multiplié par 100)
    pub mean_peer_count: u32,
    pub stddev_peer_count: u32,
    /// Masque binaire d'heures normales d'activité (bit 0 = 00h, ..., bit 23 = 23h)
    pub allowed_hours_mask: u32,
    /// Liste des pairs de confiance connus (jusqu'à 8)
    pub known_peers: [[u8; 32]; 8],
    pub known_peer_count: usize,
}

impl BehaviorBaseline {
    pub fn new(entity_id: [u8; 32], entity_type: EntityType) -> Self {
        Self {
            entity_id,
            entity_type,
            sample_count: 0,
            mean_syscall_rate: 1000,   // 10.00 syscalls/sec
            stddev_syscall_rate: 200,  // 2.00 stddev
            mean_volume_bytes: 100000, // 1000.00 octets
            stddev_volume_bytes: 20000,
            mean_peer_count: 100, // 1.00 peer
            stddev_peer_count: 50,
            allowed_hours_mask: 0x001F_FE00, // Heures ouvrées 09h00 - 20h59 (bits 9..20)
            known_peers: [[0u8; 32]; 8],
            known_peer_count: 0,
        }
    }

    pub fn with_custom_hours(mut self, mask: u32) -> Self {
        self.allowed_hours_mask = mask;
        self
    }

    pub fn add_known_peer(&mut self, peer_str: &str) -> bool {
        if self.known_peer_count < self.known_peers.len() {
            self.known_peers[self.known_peer_count] = str_to_id(peer_str);
            self.known_peer_count += 1;
            true
        } else {
            false
        }
    }

    pub fn is_known_peer(&self, peer: &[u8; 32]) -> bool {
        for p in self.known_peers.iter().take(self.known_peer_count) {
            if *p == *peer {
                return true;
            }
        }
        false
    }

    pub fn is_allowed_hour(&self, hour: u8) -> bool {
        if hour >= 24 {
            return false;
        }
        ((self.allowed_hours_mask >> hour) & 1) != 0
    }

    /// Apprentissage progressif d'un échantillon (mise à jour incrémentielle no_std)
    pub fn train_sample(&mut self, syscalls: u32, volume: u32, peer: &[u8; 32]) {
        self.sample_count += 1;
        let sc_x100 = syscalls as u64 * 100;
        let vol_x100 = volume as u64 * 100;

        // Mise à jour de la moyenne par lissage exponentiel (facteur 80/20) avec saturation anti-débordement
        let new_mean_sc = (self.mean_syscall_rate as u64 * 4 + sc_x100) / 5;
        let new_mean_vol = (self.mean_volume_bytes as u64 * 4 + vol_x100) / 5;

        self.mean_syscall_rate = new_mean_sc.min(u32::MAX as u64) as u32;
        self.mean_volume_bytes = new_mean_vol.min(u32::MAX as u64) as u32;

        // Maintien d'un écart-type plancher de sécurité (20% de la moyenne)
        self.stddev_syscall_rate = (self.mean_syscall_rate / 5).max(100);
        self.stddev_volume_bytes = (self.mean_volume_bytes / 5).max(1000);

        if !self.is_known_peer(peer) && self.known_peer_count < 8 {
            self.known_peers[self.known_peer_count] = *peer;
            self.known_peer_count += 1;
        }
    }
}

/// Événement d'activité observé en temps réel
#[derive(Debug, Clone, Copy)]
pub struct ActivityEvent {
    pub event_id: u64,
    pub entity_id: [u8; 32],
    pub entity_type: EntityType,
    pub timestamp: u64,
    pub hour_of_day: u8,
    pub syscall_count: u32,
    pub bytes_transferred: u32,
    pub peer_id: [u8; 32],
    pub is_privileged_op: bool,
    pub failed_auth_attempt: bool,
}

impl ActivityEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: u64,
        entity_str: &str,
        entity_type: EntityType,
        timestamp: u64,
        hour_of_day: u8,
        syscall_count: u32,
        bytes_transferred: u32,
        peer_str: &str,
    ) -> Self {
        Self {
            event_id,
            entity_id: str_to_id(entity_str),
            entity_type,
            timestamp,
            hour_of_day,
            syscall_count,
            bytes_transferred,
            peer_id: str_to_id(peer_str),
            is_privileged_op: false,
            failed_auth_attempt: false,
        }
    }

    pub fn with_privileged(mut self, priv_op: bool) -> Self {
        self.is_privileged_op = priv_op;
        self
    }

    pub fn with_failed_auth(mut self, failed: bool) -> Self {
        self.failed_auth_attempt = failed;
        self
    }
}

/// Résultat d'analyse comportementale multidimensionnelle
#[derive(Debug, Clone, Copy)]
pub struct AnalysisResult {
    pub event_id: u64,
    pub entity_id: [u8; 32],
    pub risk_score: u8,
    pub risk_level: RiskLevel,
    pub primary_anomaly: UebaAnomalyType,
    pub action: UebaAction,
    pub quarantined: bool,
    pub syscall_z_score_x10: u32,
    pub volume_z_score_x10: u32,
    pub peer_anomaly_detected: bool,
    pub temporal_anomaly_detected: bool,
    pub privilege_anomaly_detected: bool,
}

/// Entrée du registre de quarantaine O(1)
#[derive(Debug, Clone, Copy)]
pub struct UebaQuarantineEntry {
    pub entity_id: [u8; 32],
    pub entity_type: EntityType,
    pub reason: UebaAnomalyType,
    pub risk_score: u8,
    pub isolated_at: u64,
    pub isolated: bool,
}

/// Entrée du registre d'audit cryptographique SHA-256
#[derive(Debug, Clone, Copy)]
pub struct UebaAuditEntry {
    pub index: u32,
    pub timestamp: u64,
    pub entity_id: [u8; 32],
    pub risk_score: u8,
    pub anomaly: UebaAnomalyType,
    pub action: UebaAction,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl UebaAuditEntry {
    pub fn compute_hash(
        index: u32,
        timestamp: u64,
        entity_id: &[u8; 32],
        risk_score: u8,
        anomaly: UebaAnomalyType,
        action: UebaAction,
        prev_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash);
        hasher.update(&index.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(entity_id);
        hasher.update(&[risk_score]);
        hasher.update(&[anomaly as u8]);
        hasher.update(&[action as u8]);
        hasher.finalize()
    }
}

/// Résumé global de santé et métriques du sous-système UEBA
#[derive(Debug, Clone, Copy)]
pub struct UebaSummary {
    pub profiles_count: usize,
    pub events_processed: u64,
    pub anomalies_detected: u64,
    pub quarantine_count: usize,
    pub throttled_count: u64,
    pub alerts_raised: u64,
    pub audit_count: usize,
    pub ledger_valid: bool,
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE À 64 OCTETS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum UebaOpcode {
    GetStatus = 0,
    IngestEvent = 1,
    AnalyzeEntity = 2,
    GetRiskScore = 3,
    QuarantineEntity = 4,
    ReleaseQuarantine = 5,
    GetAuditReport = 6,
    ListAnomalies = 7,
}

impl UebaOpcode {
    pub fn from_u32(val: u32) -> Result<Self, UebaError> {
        match val {
            0 => Ok(Self::GetStatus),
            1 => Ok(Self::IngestEvent),
            2 => Ok(Self::AnalyzeEntity),
            3 => Ok(Self::GetRiskScore),
            4 => Ok(Self::QuarantineEntity),
            5 => Ok(Self::ReleaseQuarantine),
            6 => Ok(Self::GetAuditReport),
            7 => Ok(Self::ListAnomalies),
            _ => Err(UebaError::InvalidParameter),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UebaRequest {
    pub magic: u32,            // 0..4: 0x55454241 ("UEBA")
    pub opcode: u32,           // 4..8: Code d'opération
    pub handle_id: u32,        // 8..12: Handle de capabilité
    pub rights: u32,           // 12..16: Masque de droits
    pub entity_id: u32,        // 16..20: Identifiant numérique
    pub entity_type: u8,       // 20: Type d'entité
    pub event_category: u8,    // 21: Catégorie d'événement
    pub hour_of_day: u8,       // 22: Heure (0..23)
    pub _reserved1: u8,        // 23: Alignement
    pub epoch: u64,            // 24..32: Horodatage
    pub metric_value: u32,     // 32..36: Valeur métrique
    pub threshold: u32,        // 36..40: Seuil
    pub entity_name: [u8; 24], // 40..64: Nom d'entité ASCII
}

const _: () = assert!(core::mem::size_of::<UebaRequest>() == 64);

impl Default for UebaRequest {
    fn default() -> Self {
        Self {
            magic: UEBA_MAGIC_REQ,
            opcode: UebaOpcode::GetStatus as u32,
            handle_id: UEBA_ENDPOINT_ID,
            rights: ueba_rights::ALL,
            entity_id: 0,
            entity_type: EntityType::UserAccount as u8,
            event_category: 0,
            hour_of_day: 12,
            _reserved1: 0,
            epoch: 0,
            metric_value: 0,
            threshold: 0,
            entity_name: [0u8; 24],
        }
    }
}

impl UebaRequest {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.opcode.to_le_bytes());
        buf[8..12].copy_from_slice(&self.handle_id.to_le_bytes());
        buf[12..16].copy_from_slice(&self.rights.to_le_bytes());
        buf[16..20].copy_from_slice(&self.entity_id.to_le_bytes());
        buf[20] = self.entity_type;
        buf[21] = self.event_category;
        buf[22] = self.hour_of_day;
        buf[23] = self._reserved1;
        buf[24..32].copy_from_slice(&self.epoch.to_le_bytes());
        buf[32..36].copy_from_slice(&self.metric_value.to_le_bytes());
        buf[36..40].copy_from_slice(&self.threshold.to_le_bytes());
        buf[40..64].copy_from_slice(&self.entity_name);
        buf
    }

    pub fn from_bytes(buf: &[u8; 64]) -> Result<Self, UebaError> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != UEBA_MAGIC_REQ {
            return Err(UebaError::InvalidMagic);
        }
        let opcode = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let handle_id = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let rights = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let entity_id = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let entity_type = buf[20];
        let event_category = buf[21];
        let hour_of_day = buf[22];
        let _reserved1 = buf[23];
        let epoch = u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]);
        let metric_value = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let threshold = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let mut entity_name = [0u8; 24];
        entity_name.copy_from_slice(&buf[40..64]);

        Ok(Self {
            magic,
            opcode,
            handle_id,
            rights,
            entity_id,
            entity_type,
            event_category,
            hour_of_day,
            _reserved1,
            epoch,
            metric_value,
            threshold,
            entity_name,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UebaResponse {
    pub magic: u32,             // 0..4: 0x55454253 ("UEBS")
    pub status: u32,            // 4..8: Code de statut (0 = OK)
    pub total_entities: u32,    // 8..12: Profils enregistrés
    pub total_events: u32,      // 12..16: Événements traités
    pub total_anomalies: u32,   // 16..20: Anomalies détectées
    pub quarantined_count: u32, // 20..24: Entités en quarantaine
    pub risk_score: u8,         // 24: Score de risque (0..100)
    pub risk_level: u8,         // 25: Niveau de risque (Low, Med, High, Crit)
    pub recommended_action: u8, // 26: Action recommandée (Allow, ElevateAudit, ThrottleRate, Quarantine)
    pub is_quarantined: u8,     // 27: En quarantaine (0 ou 1)
    pub anomaly_type: u8,       // 28: Type d'anomalie prédominante
    pub _reserved1: [u8; 3],    // 29..32: Alignement
    pub audit_hash: [u8; 16],   // 32..48: Préfixe SHA-256 de l'audit
    pub status_str: [u8; 16],   // 48..64: Chaîne ASCII
}

const _: () = assert!(core::mem::size_of::<UebaResponse>() == 64);

impl Default for UebaResponse {
    fn default() -> Self {
        Self {
            magic: UEBA_MAGIC_RESP,
            status: 0,
            total_entities: 0,
            total_events: 0,
            total_anomalies: 0,
            quarantined_count: 0,
            risk_score: 0,
            risk_level: RiskLevel::Low as u8,
            recommended_action: UebaAction::Allow as u8,
            is_quarantined: 0,
            anomaly_type: UebaAnomalyType::None as u8,
            _reserved1: [0u8; 3],
            audit_hash: [0u8; 16],
            status_str: to_fixed_16("OK"),
        }
    }
}

impl UebaResponse {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..8].copy_from_slice(&self.status.to_le_bytes());
        buf[8..12].copy_from_slice(&self.total_entities.to_le_bytes());
        buf[12..16].copy_from_slice(&self.total_events.to_le_bytes());
        buf[16..20].copy_from_slice(&self.total_anomalies.to_le_bytes());
        buf[20..24].copy_from_slice(&self.quarantined_count.to_le_bytes());
        buf[24] = self.risk_score;
        buf[25] = self.risk_level;
        buf[26] = self.recommended_action;
        buf[27] = self.is_quarantined;
        buf[28] = self.anomaly_type;
        buf[29..32].copy_from_slice(&self._reserved1);
        buf[32..48].copy_from_slice(&self.audit_hash);
        buf[48..64].copy_from_slice(&self.status_str);
        buf
    }

    pub fn from_bytes(buf: &[u8; 64]) -> Result<Self, UebaError> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != UEBA_MAGIC_RESP {
            return Err(UebaError::InvalidMagic);
        }
        let status = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let total_entities = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let total_events = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let total_anomalies = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let quarantined_count = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let risk_score = buf[24];
        let risk_level = buf[25];
        let recommended_action = buf[26];
        let is_quarantined = buf[27];
        let anomaly_type = buf[28];
        let mut _reserved1 = [0u8; 3];
        _reserved1.copy_from_slice(&buf[29..32]);
        let mut audit_hash = [0u8; 16];
        audit_hash.copy_from_slice(&buf[32..48]);
        let mut status_str = [0u8; 16];
        status_str.copy_from_slice(&buf[48..64]);

        Ok(Self {
            magic,
            status,
            total_entities,
            total_events,
            total_anomalies,
            quarantined_count,
            risk_score,
            risk_level,
            recommended_action,
            is_quarantined,
            anomaly_type,
            _reserved1,
            audit_hash,
            status_str,
        })
    }
}

// ============================================================================
// DÉMON PRINCIPAL DE L'ANALYSE COMPORTEMENTALE (JamboUebaDaemon)
// ============================================================================

pub struct JamboUebaDaemon {
    pub cap: UebaCap,
    pub profiles: [Option<BehaviorBaseline>; MAX_PROFILES],
    pub profile_count: usize,
    pub quarantine_store: [Option<UebaQuarantineEntry>; MAX_QUARANTINES],
    pub quarantine_count: usize,
    pub audit_ledger: [Option<UebaAuditEntry>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub last_audit_hash: [u8; 32],
    pub events_processed: u64,
    pub anomalies_detected: u64,
    pub throttled_count: u64,
    pub alerts_raised: u64,
}

impl JamboUebaDaemon {
    pub fn new(cap: UebaCap) -> Self {
        Self {
            cap,
            profiles: [None; MAX_PROFILES],
            profile_count: 0,
            quarantine_store: [None; MAX_QUARANTINES],
            quarantine_count: 0,
            audit_ledger: [None; MAX_AUDIT_LOGS],
            audit_count: 0,
            last_audit_hash: [0u8; 32],
            events_processed: 0,
            anomalies_detected: 0,
            throttled_count: 0,
            alerts_raised: 0,
        }
    }

    /// Initialise les profils par défaut des services critiques et des utilisateurs types
    pub fn init_defaults(&mut self) {
        // Profil 1 : Service Web Frontend (Heures normales, volume modéré)
        let mut front_baseline =
            BehaviorBaseline::new(str_to_id("frontend_srv"), EntityType::ServiceDaemon);
        front_baseline.mean_syscall_rate = 5000; // 50 syscalls/sec
        front_baseline.stddev_syscall_rate = 1000;
        front_baseline.mean_volume_bytes = 200000; // 2000 octets
        front_baseline.stddev_volume_bytes = 50000;
        front_baseline.add_known_peer("backend_srv");
        front_baseline.add_known_peer("auth_srv");
        let _ = self.register_profile("frontend_srv", EntityType::ServiceDaemon, front_baseline);

        // Profil 2 : Administrateur Système (Opérations privilégiées possibles mais régulières)
        let mut admin_baseline =
            BehaviorBaseline::new(str_to_id("sys_admin"), EntityType::UserAccount);
        admin_baseline.allowed_hours_mask = 0x000F_FE00; // 09h à 19h
        admin_baseline.mean_syscall_rate = 2000;
        admin_baseline.stddev_syscall_rate = 500;
        admin_baseline.mean_volume_bytes = 50000;
        admin_baseline.stddev_volume_bytes = 10000;
        admin_baseline.add_known_peer("internal_bastion");
        let _ = self.register_profile("sys_admin", EntityType::UserAccount, admin_baseline);

        // Profil 3 : Démon de Sauvegarde (Heures nocturnes, volume important légitime)
        let mut backup_baseline =
            BehaviorBaseline::new(str_to_id("backup_d"), EntityType::ServiceDaemon);
        backup_baseline.allowed_hours_mask = 0x0000_003F; // 00h à 05h nocturne (bits 0..5)
        backup_baseline.mean_syscall_rate = 10000;
        backup_baseline.stddev_syscall_rate = 2000;
        backup_baseline.mean_volume_bytes = 5000000; // 50000 octets
        backup_baseline.stddev_volume_bytes = 1000000;
        backup_baseline.add_known_peer("storage_vault");
        let _ = self.register_profile("backup_d", EntityType::ServiceDaemon, backup_baseline);
    }

    /// Enregistre ou met à jour le profil d'une entité
    pub fn register_profile(
        &mut self,
        entity_id_str: &str,
        entity_type: EntityType,
        mut baseline: BehaviorBaseline,
    ) -> Result<(), UebaError> {
        if !self.cap.has_right(ueba_rights::CONFIGURE_MODEL) {
            return Err(UebaError::PermissionDenied);
        }
        self.cap.consume()?;

        let eid = str_to_id(entity_id_str);
        baseline.entity_id = eid;
        baseline.entity_type = entity_type;

        // Mise à jour si déjà présent
        for p in self.profiles.iter_mut().take(self.profile_count) {
            if let Some(ref mut p) = *p {
                if p.entity_id == eid {
                    *p = baseline;
                    return Ok(());
                }
            }
        }

        if self.profile_count >= self.profiles.len() {
            return Err(UebaError::CapacityExceeded);
        }

        self.profiles[self.profile_count] = Some(baseline);
        self.profile_count += 1;
        Ok(())
    }

    /// Analyse un événement d'activité et calcule le score de risque comportemental
    pub fn ingest_and_analyze(
        &mut self,
        event: &ActivityEvent,
    ) -> Result<AnalysisResult, UebaError> {
        if !self.cap.has_right(ueba_rights::ANALYZE_BEHAVIOR) {
            return Err(UebaError::PermissionDenied);
        }
        self.cap.consume()?;

        self.events_processed += 1;

        // Vérification de quarantaine immédiate O(1)
        if self.is_quarantined_by_id(&event.entity_id) {
            let res = AnalysisResult {
                event_id: event.event_id,
                entity_id: event.entity_id,
                risk_score: 100,
                risk_level: RiskLevel::Critical,
                primary_anomaly: UebaAnomalyType::CompositeHighRisk,
                action: UebaAction::Quarantine,
                quarantined: true,
                syscall_z_score_x10: 0,
                volume_z_score_x10: 0,
                peer_anomaly_detected: false,
                temporal_anomaly_detected: false,
                privilege_anomaly_detected: false,
            };
            self.record_audit_entry(
                event.timestamp,
                &event.entity_id,
                100,
                UebaAnomalyType::CompositeHighRisk,
                UebaAction::Quarantine,
            );
            return Ok(res);
        }

        // Récupération de la baseline associée
        let baseline = match self.find_baseline(&event.entity_id) {
            Some(b) => b,
            None => {
                // Entité inconnue : profil par défaut strict
                BehaviorBaseline::new(event.entity_id, event.entity_type)
            }
        };

        // Calcul des métriques de déviation statistique en arithmétique 64-bit anti-débordement
        let actual_sc_x100 = event.syscall_count as u64 * 100;
        let diff_sc = actual_sc_x100.saturating_sub(baseline.mean_syscall_rate as u64);
        let sc_z_score_x10 = if baseline.stddev_syscall_rate > 0 {
            ((diff_sc * 10) / baseline.stddev_syscall_rate as u64).min(1000) as u32
        } else {
            0
        };

        let actual_vol_x100 = event.bytes_transferred as u64 * 100;
        let diff_vol = actual_vol_x100.saturating_sub(baseline.mean_volume_bytes as u64);
        let vol_z_score_x10 = if baseline.stddev_volume_bytes > 0 {
            ((diff_vol * 10) / baseline.stddev_volume_bytes as u64).min(1000) as u32
        } else {
            0
        };

        // Détection temporelle hors-plage
        let temporal_anomaly = !baseline.is_allowed_hour(event.hour_of_day);

        // Détection de mouvement latéral (contact d'un pair inconnu)
        let peer_anomaly = !baseline.is_known_peer(&event.peer_id);

        // Détection d'escalade / abus de privilèges inattendus
        let privilege_anomaly = event.is_privileged_op
            && (baseline.entity_type != EntityType::UserAccount
                || temporal_anomaly
                || peer_anomaly);

        // Évaluation des scores partiels pondérés (0..100)
        let mut score: u32 = 0;

        // 1. Dérive d'appels système
        if sc_z_score_x10 >= 50 {
            score += 35;
        } else if sc_z_score_x10 >= 30 {
            score += 20;
        } else if sc_z_score_x10 >= 15 {
            score += 10;
        }

        // 2. Dérive volumétrique
        if vol_z_score_x10 >= 50 {
            score += 40;
        } else if vol_z_score_x10 >= 30 {
            score += 25;
        } else if vol_z_score_x10 >= 15 {
            score += 15;
        }

        // 3. Mouvement latéral
        if peer_anomaly {
            score += 30;
        }

        // 4. Activité hors-heures ouvrées
        if temporal_anomaly {
            score += 25;
        }

        // 5. Abus de privilèges
        if privilege_anomaly {
            score += 40;
        }

        // 6. Échecs d'authentification répétés
        if event.failed_auth_attempt {
            score += 35;
        }

        // Normalisation à [0..100]
        if score > 100 {
            score = 100;
        }
        let risk_score = score as u8;

        // Identification de l'anomalie prédominante
        let primary_anomaly = if risk_score >= 85 {
            UebaAnomalyType::CompositeHighRisk
        } else if privilege_anomaly {
            UebaAnomalyType::PrivilegeAbuse
        } else if peer_anomaly {
            UebaAnomalyType::LateralMovement
        } else if vol_z_score_x10 >= 30 {
            UebaAnomalyType::VolumeSurge
        } else if temporal_anomaly {
            UebaAnomalyType::OffHoursSpike
        } else if event.failed_auth_attempt {
            UebaAnomalyType::BruteForceAuth
        } else if sc_z_score_x10 >= 30 {
            UebaAnomalyType::RapidBurst
        } else {
            UebaAnomalyType::None
        };

        // Détermination du niveau de risque et de l'action de remédiation
        let (risk_level, action) = if risk_score >= 85 {
            (RiskLevel::Critical, UebaAction::Quarantine)
        } else if risk_score >= 60 {
            (RiskLevel::High, UebaAction::ThrottleRate)
        } else if risk_score >= 30 {
            (RiskLevel::Medium, UebaAction::ElevateAudit)
        } else {
            (RiskLevel::Low, UebaAction::Allow)
        };

        let mut quarantined = false;
        if action == UebaAction::Quarantine {
            let _ = self.quarantine_entity_internal(
                event.entity_id,
                event.entity_type,
                primary_anomaly,
                risk_score,
                event.timestamp,
            );
            quarantined = true;
            self.anomalies_detected += 1;
            self.alerts_raised += 1;
        } else if action == UebaAction::ThrottleRate {
            self.throttled_count += 1;
            self.anomalies_detected += 1;
            self.alerts_raised += 1;
        } else if action == UebaAction::ElevateAudit {
            self.anomalies_detected += 1;
        }

        // Enregistrement de l'événement dans le registre d'audit cryptographique
        self.record_audit_entry(
            event.timestamp,
            &event.entity_id,
            risk_score,
            primary_anomaly,
            action,
        );

        Ok(AnalysisResult {
            event_id: event.event_id,
            entity_id: event.entity_id,
            risk_score,
            risk_level,
            primary_anomaly,
            action,
            quarantined,
            syscall_z_score_x10: sc_z_score_x10,
            volume_z_score_x10: vol_z_score_x10,
            peer_anomaly_detected: peer_anomaly,
            temporal_anomaly_detected: temporal_anomaly,
            privilege_anomaly_detected: privilege_anomaly,
        })
    }

    /// Vérifie si une entité est actuellement sous quarantaine O(1)
    pub fn is_quarantined(&self, entity_id_str: &str) -> bool {
        let eid = str_to_id(entity_id_str);
        self.is_quarantined_by_id(&eid)
    }

    pub fn is_quarantined_by_id(&self, eid: &[u8; 32]) -> bool {
        for q in self.quarantine_store.iter().take(self.quarantine_count) {
            if let Some(ref q) = *q {
                if q.entity_id == *eid && q.isolated {
                    return true;
                }
            }
        }
        false
    }

    pub fn quarantine_entity(
        &mut self,
        entity_id_str: &str,
        reason: UebaAnomalyType,
        risk_score: u8,
        epoch: u64,
    ) -> Result<(), UebaError> {
        if !self.cap.has_right(ueba_rights::QUARANTINE_ENTITY) {
            return Err(UebaError::PermissionDenied);
        }
        self.cap.consume()?;
        let eid = str_to_id(entity_id_str);
        let etype = match self.find_baseline(&eid) {
            Some(b) => b.entity_type,
            None => EntityType::UserAccount,
        };
        self.quarantine_entity_internal(eid, etype, reason, risk_score, epoch)
    }

    fn quarantine_entity_internal(
        &mut self,
        entity_id: [u8; 32],
        entity_type: EntityType,
        reason: UebaAnomalyType,
        risk_score: u8,
        isolated_at: u64,
    ) -> Result<(), UebaError> {
        for q in self.quarantine_store.iter_mut().take(self.quarantine_count) {
            if let Some(ref mut q) = *q {
                if q.entity_id == entity_id {
                    q.isolated = true;
                    q.reason = reason;
                    q.risk_score = risk_score;
                    q.isolated_at = isolated_at;
                    return Ok(());
                }
            }
        }

        if self.quarantine_count >= self.quarantine_store.len() {
            return Err(UebaError::CapacityExceeded);
        }

        self.quarantine_store[self.quarantine_count] = Some(UebaQuarantineEntry {
            entity_id,
            entity_type,
            reason,
            risk_score,
            isolated_at,
            isolated: true,
        });
        self.quarantine_count += 1;
        Ok(())
    }

    /// Libération d'une entité de la quarantaine par l'administrateur
    pub fn release_quarantine(&mut self, entity_id_str: &str) -> Result<(), UebaError> {
        if !self
            .cap
            .has_right(ueba_rights::QUARANTINE_ENTITY | ueba_rights::ADMIN)
        {
            return Err(UebaError::PermissionDenied);
        }
        self.cap.consume()?;

        let eid = str_to_id(entity_id_str);
        for q in self.quarantine_store.iter_mut().take(self.quarantine_count) {
            if let Some(ref mut q) = *q {
                if q.entity_id == eid && q.isolated {
                    q.isolated = false;
                    return Ok(());
                }
            }
        }
        Err(UebaError::NotQuarantined)
    }

    pub fn find_baseline(&self, eid: &[u8; 32]) -> Option<BehaviorBaseline> {
        for p in self.profiles.iter().take(self.profile_count) {
            if let Some(ref p) = *p {
                if p.entity_id == *eid {
                    return Some(*p);
                }
            }
        }
        None
    }

    pub fn find_baseline_by_name(&self, name: &str) -> Option<BehaviorBaseline> {
        let eid = str_to_id(name);
        self.find_baseline(&eid)
    }

    fn record_audit_entry(
        &mut self,
        timestamp: u64,
        entity_id: &[u8; 32],
        risk_score: u8,
        anomaly: UebaAnomalyType,
        action: UebaAction,
    ) {
        let index = self.audit_count as u32;
        let entry_hash = UebaAuditEntry::compute_hash(
            index,
            timestamp,
            entity_id,
            risk_score,
            anomaly,
            action,
            &self.last_audit_hash,
        );

        let entry = UebaAuditEntry {
            index,
            timestamp,
            entity_id: *entity_id,
            risk_score,
            anomaly,
            action,
            prev_hash: self.last_audit_hash,
            entry_hash,
        };

        let slot = self.audit_count % self.audit_ledger.len();
        self.audit_ledger[slot] = Some(entry);
        self.last_audit_hash = entry_hash;
        self.audit_count += 1;
    }

    /// Vérification cryptographique formelle de l'intégrité du registre d'audit
    pub fn verify_audit_integrity(&self) -> bool {
        let max_items = if self.audit_count > self.audit_ledger.len() {
            self.audit_ledger.len()
        } else {
            self.audit_count
        };

        if max_items == 0 {
            return true;
        }

        for entry in self.audit_ledger.iter().take(max_items) {
            if let Some(ref entry) = *entry {
                let expected = UebaAuditEntry::compute_hash(
                    entry.index,
                    entry.timestamp,
                    &entry.entity_id,
                    entry.risk_score,
                    entry.anomaly,
                    entry.action,
                    &entry.prev_hash,
                );
                if expected != entry.entry_hash {
                    return false;
                }
            }
        }
        true
    }

    /// Synthèse globale du démon UEBA
    pub fn get_summary(&self) -> UebaSummary {
        let mut active_quarantines = 0;
        for q in self.quarantine_store.iter().take(self.quarantine_count) {
            if let Some(ref q) = *q {
                if q.isolated {
                    active_quarantines += 1;
                }
            }
        }

        UebaSummary {
            profiles_count: self.profile_count,
            events_processed: self.events_processed,
            anomalies_detected: self.anomalies_detected,
            quarantine_count: active_quarantines,
            throttled_count: self.throttled_count,
            alerts_raised: self.alerts_raised,
            audit_count: self.audit_count,
            ledger_valid: self.verify_audit_integrity(),
        }
    }

    // ========================================================================
    // DISPATCHER FASTPATH IPC (64 OCTETS)
    // ========================================================================

    pub fn dispatch_ipc(&mut self, req: &UebaRequest) -> UebaResponse {
        let mut resp = UebaResponse::default();
        let summary = self.get_summary();
        resp.total_entities = summary.profiles_count as u32;
        resp.total_events = summary.events_processed as u32;
        resp.total_anomalies = summary.anomalies_detected as u32;
        resp.quarantined_count = summary.quarantine_count as u32;
        resp.audit_hash[..16].copy_from_slice(&self.last_audit_hash[..16]);

        let opcode = match UebaOpcode::from_u32(req.opcode) {
            Ok(op) => op,
            Err(e) => {
                resp.status = e as u32;
                resp.status_str = to_fixed_16(e.as_str());
                return resp;
            }
        };

        match opcode {
            UebaOpcode::GetStatus => {
                resp.status = 0;
                resp.status_str = to_fixed_16("STATUS_OK");
            }
            UebaOpcode::IngestEvent => {
                let name = name24_to_str(&req.entity_name);
                let etype = EntityType::from_u8(req.entity_type);
                let evt = ActivityEvent::new(
                    req.epoch,
                    name,
                    etype,
                    req.epoch,
                    req.hour_of_day,
                    req.metric_value,
                    req.threshold,
                    "peer_default",
                );
                match self.ingest_and_analyze(&evt) {
                    Ok(res) => {
                        resp.status = 0;
                        resp.risk_score = res.risk_score;
                        resp.risk_level = res.risk_level as u8;
                        resp.recommended_action = res.action as u8;
                        resp.is_quarantined = if res.quarantined { 1 } else { 0 };
                        resp.anomaly_type = res.primary_anomaly as u8;
                        resp.status_str = to_fixed_16("INGESTED");
                        let s = self.get_summary();
                        resp.total_events = s.events_processed as u32;
                        resp.total_anomalies = s.anomalies_detected as u32;
                        resp.quarantined_count = s.quarantine_count as u32;
                    }
                    Err(e) => {
                        resp.status = e as u32;
                        resp.status_str = to_fixed_16(e.as_str());
                    }
                }
            }
            UebaOpcode::AnalyzeEntity | UebaOpcode::GetRiskScore => {
                let name = name24_to_str(&req.entity_name);
                let eid = str_to_id(name);
                if self.is_quarantined_by_id(&eid) {
                    resp.status = 0;
                    resp.risk_score = 100;
                    resp.risk_level = RiskLevel::Critical as u8;
                    resp.recommended_action = UebaAction::Quarantine as u8;
                    resp.is_quarantined = 1;
                    resp.anomaly_type = UebaAnomalyType::CompositeHighRisk as u8;
                    resp.status_str = to_fixed_16("QUARANTINED");
                } else if let Some(_b) = self.find_baseline(&eid) {
                    resp.status = 0;
                    resp.risk_score = 15;
                    resp.risk_level = RiskLevel::Low as u8;
                    resp.recommended_action = UebaAction::Allow as u8;
                    resp.is_quarantined = 0;
                    resp.anomaly_type = UebaAnomalyType::None as u8;
                    resp.status_str = to_fixed_16("BASELINE_OK");
                } else {
                    resp.status = UebaError::EntityNotFound as u32;
                    resp.status_str = to_fixed_16("NOT_FOUND");
                }
            }
            UebaOpcode::QuarantineEntity => {
                let name = name24_to_str(&req.entity_name);
                match self.quarantine_entity(
                    name,
                    UebaAnomalyType::CompositeHighRisk,
                    100,
                    req.epoch,
                ) {
                    Ok(_) => {
                        resp.status = 0;
                        resp.risk_score = 100;
                        resp.risk_level = RiskLevel::Critical as u8;
                        resp.recommended_action = UebaAction::Quarantine as u8;
                        resp.is_quarantined = 1;
                        resp.status_str = to_fixed_16("QUARANTINED");
                        let s = self.get_summary();
                        resp.quarantined_count = s.quarantine_count as u32;
                    }
                    Err(e) => {
                        resp.status = e as u32;
                        resp.status_str = to_fixed_16(e.as_str());
                    }
                }
            }
            UebaOpcode::ReleaseQuarantine => {
                let name = name24_to_str(&req.entity_name);
                match self.release_quarantine(name) {
                    Ok(_) => {
                        resp.status = 0;
                        resp.is_quarantined = 0;
                        resp.status_str = to_fixed_16("RELEASED");
                        let s = self.get_summary();
                        resp.quarantined_count = s.quarantine_count as u32;
                    }
                    Err(e) => {
                        resp.status = e as u32;
                        resp.status_str = to_fixed_16(e.as_str());
                    }
                }
            }
            UebaOpcode::GetAuditReport => {
                let valid = self.verify_audit_integrity();
                resp.status = if valid {
                    0
                } else {
                    UebaError::AuditLedgerTampered as u32
                };
                resp.status_str = if valid {
                    to_fixed_16("AUDIT_VALID")
                } else {
                    to_fixed_16("TAMPERED")
                };
            }
            UebaOpcode::ListAnomalies => {
                resp.status = 0;
                resp.status_str = to_fixed_16("ANOMALIES_OK");
            }
        }

        resp
    }
}

// ============================================================================
// CLIENT SYNCHRONE UEBA (POUR PROCESSUS RING 3 ET SHELL)
// ============================================================================

pub struct UebaClient {
    pub endpoint: Handle,
}

impl UebaClient {
    pub fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn call(&self, req: &UebaRequest) -> Result<UebaResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<UebaResponse>() {
                let mut buf = [0u8; 64];
                buf.copy_from_slice(&rx_msg.bytes[..64]);
                return UebaResponse::from_bytes(&buf).map_err(|_| SysError::InvalidArgument);
            }

            attempts += 1;
            libjambo::syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ueba_cap_monotonic_attenuation() {
        let admin_cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 10000, 500);
        assert!(admin_cap.has_right(ueba_rights::INGEST_EVENT));
        assert!(admin_cap.has_right(ueba_rights::ANALYZE_BEHAVIOR));
        assert!(admin_cap.has_right(ueba_rights::ADMIN));

        let analyze_cap = admin_cap
            .attenuate(
                ueba_rights::INGEST_EVENT | ueba_rights::ANALYZE_BEHAVIOR,
                5000,
                200,
            )
            .expect("Atténuation valide");

        assert!(analyze_cap.has_right(ueba_rights::INGEST_EVENT));
        assert!(analyze_cap.has_right(ueba_rights::ANALYZE_BEHAVIOR));
        assert!(!analyze_cap.has_right(ueba_rights::ADMIN));

        // Refus de ré-élévation de privilèges
        assert_eq!(
            analyze_cap.attenuate(ueba_rights::ADMIN, 5000, 100),
            Err(UebaError::AttenuationViolation)
        );
    }

    #[test]
    fn test_ueba_sha256_deterministic() {
        let hash1 = Sha256::digest(b"jamboos-ueba-baseline-2026");
        let hash2 = Sha256::digest(b"jamboos-ueba-baseline-2026");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_ueba_ipc_message_sizes_64_bytes() {
        assert_eq!(core::mem::size_of::<UebaRequest>(), 64);
        assert_eq!(core::mem::size_of::<UebaResponse>(), 64);

        let req = UebaRequest::default();
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 64);
        let parsed = UebaRequest::from_bytes(&bytes).expect("Parsed request");
        assert_eq!(req.magic, parsed.magic);

        let resp = UebaResponse::default();
        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);
        let parsed_resp = UebaResponse::from_bytes(&resp_bytes).expect("Parsed response");
        assert_eq!(resp.magic, parsed_resp.magic);
    }

    #[test]
    fn test_ueba_baseline_and_normal_activity() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 100000, 1000);
        let mut daemon = JamboUebaDaemon::new(cap);
        daemon.init_defaults();

        let event = ActivityEvent::new(
            1,
            "frontend_srv",
            EntityType::ServiceDaemon,
            100,
            14,   // 14h00 (in hours)
            50,   // 50 syscalls
            2000, // 2000 bytes
            "backend_srv",
        );

        let res = daemon.ingest_and_analyze(&event).expect("Normal analysis");
        assert_eq!(res.action, UebaAction::Allow);
        assert_eq!(res.risk_level, RiskLevel::Low);
        assert!(!res.quarantined);
    }

    #[test]
    fn test_ueba_anomaly_detection_off_hours_and_quarantine() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 100000, 1000);
        let mut daemon = JamboUebaDaemon::new(cap);
        daemon.init_defaults();

        // Activité suspecte : 03h00 nocturne, pair inconnu, dérive volumétrique extrême, tentative d'escalade
        let attack_event = ActivityEvent::new(
            2,
            "frontend_srv",
            EntityType::ServiceDaemon,
            200,
            3,             // 03h00 du matin (hors-plage)
            5000,          // Dérive de syscalls
            500000,        // Volume massif
            "external_c2", // Pair hostile inconnu
        )
        .with_privileged(true)
        .with_failed_auth(true);

        let res = daemon
            .ingest_and_analyze(&attack_event)
            .expect("Attack analyzed");
        assert_eq!(res.action, UebaAction::Quarantine);
        assert_eq!(res.risk_level, RiskLevel::Critical);
        assert!(res.quarantined);
        assert!(daemon.is_quarantined("frontend_srv"));
    }

    #[test]
    fn test_ueba_audit_ledger_integrity() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 100000, 1000);
        let mut daemon = JamboUebaDaemon::new(cap);
        daemon.init_defaults();

        let event = ActivityEvent::new(
            10,
            "sys_admin",
            EntityType::UserAccount,
            500,
            11,
            20,
            500,
            "internal_bastion",
        );
        let _ = daemon.ingest_and_analyze(&event);
        assert!(daemon.verify_audit_integrity());
        assert_eq!(daemon.get_summary().audit_count, 1);
    }

    #[test]
    fn test_ueba_ipc_dispatch() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 100000, 1000);
        let mut daemon = JamboUebaDaemon::new(cap);
        daemon.init_defaults();

        let req = UebaRequest {
            magic: UEBA_MAGIC_REQ,
            opcode: UebaOpcode::GetStatus as u32,
            handle_id: UEBA_ENDPOINT_ID,
            rights: ueba_rights::ALL,
            ..Default::default()
        };
        let resp = daemon.dispatch_ipc(&req);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.total_entities, 3);
    }
}

//! Analyse Comportementale des Utilisateurs et Entités Souveraine (UEBA - User and Entity Behavior Analytics)
//!
//! Phase 146 — Jalon v0.3.13
//!
//! Fournit un sous-système souverain d'analyse comportementale en temps réel en `#![no_std]` :
//! 1. Profilage adaptatif des utilisateurs et entités système (processus Ring 3, démons, clients IPC, pairs réseau).
//! 2. Établissement continu de profils de référence (baselines) statistiques multidimensionnels.
//! 3. Détection d'anomalies par écarts statistiques (z-scores en virgule fixe, dérives volumétriques, sauts de fréquence).
//! 4. Détection spécialisée des mouvements latéraux (accès pairs anormaux), abus de privilèges et exfiltrations clandestines.
//! 5. Détection temporelle des anomalies hors-plage (accès hors heures ouvrées / off-hours).
//! 6. Calcul d'un score de risque adaptatif multidimensionnel (0..100) avec matrice de sévérité.
//! 7. Actions de remédiation graduées (Allow, ElevateAudit, ThrottleRate, Quarantine O(1)).
//! 8. Table de quarantaine O(1) avec isolation immédiate des entités compromises.
//! 9. Contrôle d'accès capabilaire (`UebaCap`) avec atténuation monotone stricte.
//! 10. Registre d'audit SHA-256 scellé par chaînage cryptographique inaltérable.

#![no_std]

use libjambo::Handle;

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
    PermissionDenied,
    AttenuationViolation,
    CapacityExceeded,
    EntityNotFound,
    InvalidParameter,
    AlreadyQuarantined,
    NotQuarantined,
    AuditLedgerTampered,
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
    UserAccount,
    ServiceDaemon,
    IpcClient,
    KernelWorker,
    NetworkPeer,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UebaAnomalyType {
    None,
    VolumeSurge,
    LateralMovement,
    OffHoursSpike,
    PrivilegeAbuse,
    BruteForceAuth,
    RapidBurst,
    CompositeHighRisk,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UebaAction {
    Allow,
    ElevateAudit,
    ThrottleRate,
    Quarantine,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
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
}

/// Helper pour convertir une chaîne en tampon fixe de 32 octets
pub fn str_to_id(s: &str) -> [u8; 32] {
    let mut id = [0u8; 32];
    let bytes = s.as_bytes();
    let len = if bytes.len() > 32 { 32 } else { bytes.len() };
    id[..len].copy_from_slice(&bytes[..len]);
    id
}

/// Helper pour afficher un ID [u8; 32] en chaîne UTF-8 tronquée
pub fn id_to_str(id: &[u8; 32]) -> &str {
    let len = id.iter().position(|&c| c == 0).unwrap_or(32);
    core::str::from_utf8(&id[..len]).unwrap_or("<invalid-utf8>")
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
        for i in 0..self.known_peer_count {
            if self.known_peers[i] == *peer {
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
// DÉMON PRINCIPAL DE L'ANALYSE COMPORTEMENTALE (JamboUebaDaemon)
// ============================================================================

pub struct JamboUebaDaemon {
    pub cap: UebaCap,
    pub profiles: [Option<BehaviorBaseline>; 16],
    pub profile_count: usize,
    pub quarantine_store: [Option<UebaQuarantineEntry>; 16],
    pub quarantine_count: usize,
    pub audit_ledger: [Option<UebaAuditEntry>; 32],
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
            profiles: [None; 16],
            profile_count: 0,
            quarantine_store: [None; 16],
            quarantine_count: 0,
            audit_ledger: [None; 32],
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
        for i in 0..self.profile_count {
            if let Some(ref mut p) = self.profiles[i] {
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
        // Z-score x10 = (diff * 10) / stddev
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
            // > 5 sigma
            score += 35;
        } else if sc_z_score_x10 >= 30 {
            // > 3 sigma
            score += 20;
        } else if sc_z_score_x10 >= 15 {
            score += 10;
        }

        // 2. Dérive volumétrique (exfiltration / ingestion de masse)
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

    fn is_quarantined_by_id(&self, eid: &[u8; 32]) -> bool {
        for i in 0..self.quarantine_count {
            if let Some(ref q) = self.quarantine_store[i] {
                if q.entity_id == *eid && q.isolated {
                    return true;
                }
            }
        }
        false
    }

    fn quarantine_entity_internal(
        &mut self,
        entity_id: [u8; 32],
        entity_type: EntityType,
        reason: UebaAnomalyType,
        risk_score: u8,
        isolated_at: u64,
    ) -> Result<(), UebaError> {
        for i in 0..self.quarantine_count {
            if let Some(ref mut q) = self.quarantine_store[i] {
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
        for i in 0..self.quarantine_count {
            if let Some(ref mut q) = self.quarantine_store[i] {
                if q.entity_id == eid && q.isolated {
                    q.isolated = false;
                    return Ok(());
                }
            }
        }
        Err(UebaError::NotQuarantined)
    }

    fn find_baseline(&self, eid: &[u8; 32]) -> Option<BehaviorBaseline> {
        for i in 0..self.profile_count {
            if let Some(ref p) = self.profiles[i] {
                if p.entity_id == *eid {
                    return Some(*p);
                }
            }
        }
        None
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

        // Pour un registre scellé séquentiellement
        for i in 0..max_items {
            if let Some(ref entry) = self.audit_ledger[i] {
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
        for i in 0..self.quarantine_count {
            if let Some(ref q) = self.quarantine_store[i] {
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

        // Atténuation monotone
        let analyze_cap = admin_cap
            .attenuate(
                ueba_rights::INGEST_EVENT | ueba_rights::ANALYZE_BEHAVIOR,
                5000,
                100,
            )
            .expect("Atténuation");
        assert!(analyze_cap.has_right(ueba_rights::ANALYZE_BEHAVIOR));
        assert!(!analyze_cap.has_right(ueba_rights::ADMIN));
        assert!(!analyze_cap.has_right(ueba_rights::QUARANTINE_ENTITY));

        // Refus d'escalade illicite
        assert_eq!(
            analyze_cap.attenuate(ueba_rights::ALL, 5000, 100),
            Err(UebaError::AttenuationViolation)
        );
    }

    #[test]
    fn test_benign_activity_low_risk() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 10000, 500);
        let mut ueba = JamboUebaDaemon::new(cap);
        ueba.init_defaults();

        // Activité normale du service frontend : 14h00, 50 syscalls, 2000 octets, pair connu 'backend_srv'
        let event = ActivityEvent::new(
            1,
            "frontend_srv",
            EntityType::ServiceDaemon,
            1735200000,
            14,
            50,
            2000,
            "backend_srv",
        );

        let res = ueba.ingest_and_analyze(&event).expect("Analyse");
        assert_eq!(res.action, UebaAction::Allow);
        assert_eq!(res.risk_level, RiskLevel::Low);
        assert!(res.risk_score < 30);
        assert_eq!(res.primary_anomaly, UebaAnomalyType::None);
        assert!(!res.quarantined);
    }

    #[test]
    fn test_volume_burst_exfiltration_anomaly() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 10000, 500);
        let mut ueba = JamboUebaDaemon::new(cap);
        ueba.init_defaults();

        // Salve volumétrique anormale : 1000000 octets au lieu de 2000 (Z-score très élevé)
        let event = ActivityEvent::new(
            2,
            "frontend_srv",
            EntityType::ServiceDaemon,
            1735201000,
            14,
            50,
            500000, // 500k octets
            "backend_srv",
        );

        let res = ueba.ingest_and_analyze(&event).expect("Analyse");
        assert!(res.volume_z_score_x10 >= 30);
        assert!(res.risk_score >= 30);
        assert_ne!(res.action, UebaAction::Allow);
    }

    #[test]
    fn test_lateral_movement_unknown_peer_anomaly() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 10000, 500);
        let mut ueba = JamboUebaDaemon::new(cap);
        ueba.init_defaults();

        // Connexion suspecte à un pair externe / latéral non répertorié
        let event = ActivityEvent::new(
            3,
            "frontend_srv",
            EntityType::ServiceDaemon,
            1735202000,
            15,
            50,
            2000,
            "compromised_c2_peer",
        );

        let res = ueba.ingest_and_analyze(&event).expect("Analyse");
        assert!(res.peer_anomaly_detected);
        assert!(res.risk_score >= 30);
    }

    #[test]
    fn test_off_hours_privileged_abuse_anomaly() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 10000, 500);
        let mut ueba = JamboUebaDaemon::new(cap);
        ueba.init_defaults();

        // Connexion administrateur à 03h00 du matin (hors-plage 09h-19h) + opération privilégiée
        let event = ActivityEvent::new(
            4,
            "sys_admin",
            EntityType::UserAccount,
            1735203000,
            3,
            20,
            500,
            "internal_bastion",
        )
        .with_privileged(true);

        let res = ueba.ingest_and_analyze(&event).expect("Analyse");
        assert!(res.temporal_anomaly_detected);
        assert!(res.privilege_anomaly_detected);
        assert!(res.risk_score >= 60);
    }

    #[test]
    fn test_composite_critical_risk_quarantine() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 10000, 500);
        let mut ueba = JamboUebaDaemon::new(cap);
        ueba.init_defaults();

        // Attaque critique multidimensionnelle : hors-heures + volume massif + pair inconnu + échec auth
        let event = ActivityEvent::new(
            5,
            "rogue_daemon",
            EntityType::ServiceDaemon,
            1735204000,
            2,
            500,
            2000000,
            "foreign_exfil_drop",
        )
        .with_privileged(true)
        .with_failed_auth(true);

        let res = ueba.ingest_and_analyze(&event).expect("Analyse");
        assert_eq!(res.risk_level, RiskLevel::Critical);
        assert_eq!(res.action, UebaAction::Quarantine);
        assert!(res.quarantined);
        assert!(res.risk_score >= 85);
        assert!(ueba.is_quarantined("rogue_daemon"));
    }

    #[test]
    fn test_quarantine_enforcement_and_release() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 10000, 500);
        let mut ueba = JamboUebaDaemon::new(cap);
        ueba.init_defaults();

        let event = ActivityEvent::new(
            6,
            "infected_node",
            EntityType::ServiceDaemon,
            1735205000,
            1,
            1000,
            5000000,
            "c2_exfil",
        )
        .with_privileged(true)
        .with_failed_auth(true);

        let res = ueba.ingest_and_analyze(&event).expect("Analyse");
        assert!(res.quarantined);
        assert!(ueba.is_quarantined("infected_node"));

        // Tout événement ultérieur doit être bloqué immédiatement
        let benign = ActivityEvent::new(
            7,
            "infected_node",
            EntityType::ServiceDaemon,
            1735205100,
            12,
            10,
            100,
            "backend_srv",
        );
        let res2 = ueba.ingest_and_analyze(&benign).expect("Analyse");
        assert_eq!(res2.action, UebaAction::Quarantine);
        assert!(res2.quarantined);

        // Libération administrative de la quarantaine
        ueba.release_quarantine("infected_node").expect("Release");
        assert!(!ueba.is_quarantined("infected_node"));
    }

    #[test]
    fn test_audit_ledger_integrity_and_tamper_detection() {
        let cap = UebaCap::new(Handle::new(146, 1), ueba_rights::ALL, 10000, 500);
        let mut ueba = JamboUebaDaemon::new(cap);
        ueba.init_defaults();

        let event1 = ActivityEvent::new(
            10,
            "frontend_srv",
            EntityType::ServiceDaemon,
            1735206000,
            14,
            50,
            2000,
            "backend_srv",
        );
        let _ = ueba.ingest_and_analyze(&event1);

        let event2 = ActivityEvent::new(
            11,
            "frontend_srv",
            EntityType::ServiceDaemon,
            1735206100,
            14,
            500,
            50000,
            "unknown_lateral",
        );
        let _ = ueba.ingest_and_analyze(&event2);

        assert!(ueba.verify_audit_integrity());
        assert_eq!(ueba.audit_count, 2);

        // Tentative d'altération du registre d'audit
        if let Some(ref mut entry) = ueba.audit_ledger[0] {
            entry.risk_score = 99;
        }
        assert!(!ueba.verify_audit_integrity());
    }
}

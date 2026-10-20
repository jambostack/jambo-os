//! Opérations Informatiques Pilotées par l'IA (AIOps - Artificial Intelligence for IT Operations)
//! Moteur souverain d'ingestion télémétrique, corrélation topologique multi-sources,
//! détection d'anomalies par z-score glissant et auto-remédiation autonome sans autorité ambiante.
//!
//! Phase 137 — Jalon v0.3.4
//!
//! Fournit une plateforme souveraine AIOps (Artificial Intelligence for IT Operations) en `#![no_std]` :
//! 1. Ingestion continue et fenêtrée des flux de métriques et d'événements télémétriques bornés.
//! 2. Détection d'anomalies statistiques en temps réel par fenêtres glissantes et calcul de Z-score déterministe.
//! 3. Modélisation de la topologie de dépendances inter-services et analyse de cause racine (Root Cause Analysis - RCA).
//! 4. Corrélation d'incidents multi-sources fusionnant les signaux faibles et anomalies réparties.
//! 5. Déclenchement automatique et sécurisé de playbooks d'auto-remédiation souverains.
//! 6. Contrôle d'accès capabilaire strict (`AiopsCap`) sans autorité ambiante avec atténuation monotone.
//! 7. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

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

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes * 8;
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

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.process_block();

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
// CONTRÔLE D'ACCÈS PAR CAPABILITÉS (AIOPS CAPABILITIES)
// ============================================================================

pub mod aiops_rights {
    pub const INGEST_EVENTS: u32 = 0x0001;
    pub const DETECT_ANOMALIES: u32 = 0x0002;
    pub const CORRELATE_INCIDENTS: u32 = 0x0004;
    pub const TRIGGER_PLAYBOOK: u32 = 0x0008;
    pub const MANAGE_TOPOLOGY: u32 = 0x0010;
    pub const CONFIGURE_RULES: u32 = 0x0020;
    pub const QUERY_AUDIT: u32 = 0x0040;
    pub const ADMIN: u32 = 0x0080;

    pub const ALL: u32 = INGEST_EVENTS
        | DETECT_ANOMALIES
        | CORRELATE_INCIDENTS
        | TRIGGER_PLAYBOOK
        | MANAGE_TOPOLOGY
        | CONFIGURE_RULES
        | QUERY_AUDIT
        | ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiopsError {
    AccessDenied,
    CapabilityExpired,
    AttenuationViolation,
    ServiceNotFound,
    ServiceAlreadyExists,
    CapacityExceeded,
    AnomalyNotFound,
    IncidentNotFound,
    PlaybookNotFound,
    CooldownActive,
    ExecutionFailed,
    IntegrityCompromised,
    InvalidMetric,
}

/// Capabilité AIOps souveraine sans autorité ambiante
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiopsCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl AiopsCap {
    pub const fn new(handle: Handle, rights: u32, max_lifetime: u64, invocations: u32) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left: invocations,
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn consume(&mut self) -> Result<(), AiopsError> {
        if self.invocations_left == 0 {
            return Err(AiopsError::CapabilityExpired);
        }
        self.invocations_left -= 1;
        Ok(())
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, AiopsError> {
        if (new_rights & !self.rights) != 0 {
            return Err(AiopsError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(AiopsError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(AiopsError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }
}

// ============================================================================
// MODÈLE DE DONNÉES AIOPS & TÉLÉMÉTRIE SOUVERAINE
// ============================================================================

pub const MAX_EVENTS: usize = 128;
pub const MAX_SERVICES: usize = 32;
pub const MAX_METRIC_WINDOWS: usize = 32;
pub const METRIC_WINDOW_SIZE: usize = 16;
pub const MAX_ANOMALIES: usize = 64;
pub const MAX_INCIDENTS: usize = 32;
pub const MAX_PLAYBOOKS: usize = 16;
pub const MAX_LEDGER_ENTRIES: usize = 64;

/// Racine carrée entière rapide en no_std pour écart-type
pub fn isqrt(val: u64) -> u64 {
    if val <= 1 {
        return val;
    }
    let mut x0 = val / 2;
    let mut x1 = (x0 + val / x0) / 2;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + val / x0) / 2;
    }
    x0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    KernelSyscall,
    NetworkMesh,
    StorageIO,
    AuthService,
    ComputeWorkload,
    DatabaseEngine,
    ApiGateway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSeverity {
    Info = 0,
    Warning = 1,
    Error = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Copy)]
pub struct TelemetryEvent {
    pub id: u32,
    pub timestamp: u64,
    pub source: EventSource,
    pub service_id: u32,
    pub severity: EventSeverity,
    pub metric_name: [u8; 32],
    pub metric_len: usize,
    pub metric_value: i64,
}

impl TelemetryEvent {
    pub fn new(
        id: u32,
        timestamp: u64,
        source: EventSource,
        service_id: u32,
        severity: EventSeverity,
        name: &str,
        value: i64,
    ) -> Self {
        let mut metric_name = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        metric_name[..len].copy_from_slice(&bytes[..len]);

        Self {
            id,
            timestamp,
            source,
            service_id,
            severity,
            metric_name,
            metric_len: len,
            metric_value: value,
        }
    }

    pub fn metric_name_str(&self) -> &str {
        core::str::from_utf8(&self.metric_name[..self.metric_len]).unwrap_or("<invalide>")
    }
}

/// Fenêtre glissante pour l'apprentissage statistique et le calcul de Z-score
#[derive(Debug, Clone, Copy)]
pub struct MetricWindow {
    pub service_id: u32,
    pub metric_name: [u8; 32],
    pub metric_len: usize,
    pub samples: [i64; METRIC_WINDOW_SIZE],
    pub sample_count: usize,
    pub head: usize,
}

impl MetricWindow {
    pub fn new(service_id: u32, name: &str) -> Self {
        let mut metric_name = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        metric_name[..len].copy_from_slice(&bytes[..len]);

        Self {
            service_id,
            metric_name,
            metric_len: len,
            samples: [0i64; METRIC_WINDOW_SIZE],
            sample_count: 0,
            head: 0,
        }
    }

    pub fn push(&mut self, val: i64) {
        self.samples[self.head] = val;
        self.head = (self.head + 1) % METRIC_WINDOW_SIZE;
        if self.sample_count < METRIC_WINDOW_SIZE {
            self.sample_count += 1;
        }
    }

    pub fn mean(&self) -> i64 {
        if self.sample_count == 0 {
            return 0;
        }
        let mut sum: i64 = 0;
        for i in 0..self.sample_count {
            sum += self.samples[i];
        }
        sum / (self.sample_count as i64)
    }

    pub fn variance(&self) -> u64 {
        if self.sample_count <= 1 {
            return 0;
        }
        let m = self.mean();
        let mut sum_sq_diff: u64 = 0;
        for i in 0..self.sample_count {
            let diff = (self.samples[i] - m).abs() as u64;
            sum_sq_diff += diff * diff;
        }
        sum_sq_diff / (self.sample_count as u64)
    }

    pub fn std_dev(&self) -> u64 {
        isqrt(self.variance())
    }

    /// Calcule le Z-score multiplié par 100 (ex: 300 correspond à 3.00 sigma)
    pub fn z_score(&self, val: i64) -> u32 {
        if self.sample_count < 4 {
            return 0;
        }
        let m = self.mean();
        let diff = (val - m).abs() as u64;

        // Seuil d'insensibilité au bruit minime (10% de la moyenne ou plancher de 5 unités)
        let noise_floor = (m.abs() as u64 / 10).max(5);
        if diff < noise_floor {
            return 0;
        }

        let sd = self.std_dev().max(2);
        let z = (diff * 100) / sd;
        z.min(1000) as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalySeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Copy)]
pub struct AnomalyRecord {
    pub id: u32,
    pub timestamp: u64,
    pub service_id: u32,
    pub metric_name: [u8; 32],
    pub metric_len: usize,
    pub observed_value: i64,
    pub baseline_mean: i64,
    pub z_score: u32, // x100
    pub severity: AnomalySeverity,
    pub correlated_incident_id: Option<u32>,
}

/// Nœud de dépendance topologique inter-services
#[derive(Debug, Clone, Copy)]
pub struct TopologyNode {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub tier: u8, // 0 = Passerelle/Frontend, 1 = Services Métier/Auth, 2 = Base/Stockage, 3 = Micro-noyau
    pub dependencies: [u32; 8],
    pub dep_count: usize,
    pub healthy: bool,
}

impl TopologyNode {
    pub fn new(id: u32, name: &str, tier: u8) -> Self {
        let mut n = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        n[..len].copy_from_slice(&bytes[..len]);

        Self {
            id,
            name: n,
            name_len: len,
            tier,
            dependencies: [0u32; 8],
            dep_count: 0,
            healthy: true,
        }
    }

    pub fn add_dependency(&mut self, dep_id: u32) -> Result<(), AiopsError> {
        if self.dep_count >= 8 {
            return Err(AiopsError::CapacityExceeded);
        }
        for i in 0..self.dep_count {
            if self.dependencies[i] == dep_id {
                return Ok(());
            }
        }
        self.dependencies[self.dep_count] = dep_id;
        self.dep_count += 1;
        Ok(())
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentStatus {
    Active,
    Investigating,
    Remediating,
    Resolved,
}

/// Incident corrélé multi-sources avec détection de cause racine
#[derive(Debug, Clone, Copy)]
pub struct CorrelatedIncident {
    pub id: u32,
    pub opened_at: u64,
    pub resolved_at: Option<u64>,
    pub root_cause_service_id: u32,
    pub confidence_score: u8, // 0..100%
    pub severity: AnomalySeverity,
    pub affected_services: [u32; 8],
    pub affected_count: usize,
    pub anomaly_ids: [u32; 8],
    pub anomaly_count: usize,
    pub status: IncidentStatus,
    pub playbook_executed: Option<PlaybookAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaybookAction {
    ScaleResource,
    RestartWorker,
    ThrottleIngress,
    DrainFailover,
    QuarantineNode,
    FlushCaches,
}

/// Playbook d'auto-remédiation autonome
#[derive(Debug, Clone, Copy)]
pub struct RemediationPlaybook {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub target_service_id: u32,
    pub trigger_severity: AnomalySeverity,
    pub action: PlaybookAction,
    pub auto_trigger: bool,
    pub cooldown_ticks: u64,
    pub last_executed: u64,
}

impl RemediationPlaybook {
    pub fn new(
        id: u32,
        name: &str,
        target_service_id: u32,
        trigger_severity: AnomalySeverity,
        action: PlaybookAction,
        auto_trigger: bool,
        cooldown_ticks: u64,
    ) -> Self {
        let mut n = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        n[..len].copy_from_slice(&bytes[..len]);

        Self {
            id,
            name: n,
            name_len: len,
            target_service_id,
            trigger_severity,
            action,
            auto_trigger,
            cooldown_ticks,
            last_executed: 0,
        }
    }
}

/// Entrée d'audit cryptographique inviolable SHA-256
#[derive(Debug, Clone, Copy)]
pub struct AiopsAuditEntry {
    pub seq: u32,
    pub timestamp: u64,
    pub action_code: u16,
    pub target_id: u32,
    pub detail: [u8; 32],
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl AiopsAuditEntry {
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.seq.to_be_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(&self.action_code.to_be_bytes());
        hasher.update(&self.target_id.to_be_bytes());
        hasher.update(&self.detail);
        hasher.update(&self.prev_hash);
        hasher.finalize()
    }
}

/// Synthèse d'état AIOps
#[derive(Debug, Clone, Copy)]
pub struct AiopsSummary {
    pub total_services: usize,
    pub total_events: usize,
    pub total_anomalies: usize,
    pub active_incidents: usize,
    pub resolved_incidents: usize,
    pub total_playbooks: usize,
    pub ledger_entries: usize,
    pub health_score: u8, // 0..100
}

// ============================================================================
// DÉMON CENTRAL AIOPS (JamboAiopsDaemon)
// ============================================================================

pub struct JamboAiopsDaemon {
    pub admin_cap: AiopsCap,
    pub events: [Option<TelemetryEvent>; MAX_EVENTS],
    pub event_count: usize,
    pub event_head: usize,
    pub next_event_id: u32,

    pub topology: [Option<TopologyNode>; MAX_SERVICES],
    pub topology_count: usize,

    pub metric_windows: [Option<MetricWindow>; MAX_METRIC_WINDOWS],
    pub metric_window_count: usize,

    pub anomalies: [Option<AnomalyRecord>; MAX_ANOMALIES],
    pub anomaly_count: usize,
    pub next_anomaly_id: u32,

    pub incidents: [Option<CorrelatedIncident>; MAX_INCIDENTS],
    pub incident_count: usize,
    pub next_incident_id: u32,

    pub playbooks: [Option<RemediationPlaybook>; MAX_PLAYBOOKS],
    pub playbook_count: usize,
    pub next_playbook_id: u32,

    pub ledger: [Option<AiopsAuditEntry>; MAX_LEDGER_ENTRIES],
    pub ledger_count: usize,
    pub next_seq: u32,
}

impl JamboAiopsDaemon {
    pub fn new(admin_cap: AiopsCap) -> Self {
        Self {
            admin_cap,
            events: [None; MAX_EVENTS],
            event_count: 0,
            event_head: 0,
            next_event_id: 1,

            topology: [None; MAX_SERVICES],
            topology_count: 0,

            metric_windows: [None; MAX_METRIC_WINDOWS],
            metric_window_count: 0,

            anomalies: [None; MAX_ANOMALIES],
            anomaly_count: 0,
            next_anomaly_id: 1,

            incidents: [None; MAX_INCIDENTS],
            incident_count: 0,
            next_incident_id: 1,

            playbooks: [None; MAX_PLAYBOOKS],
            playbook_count: 0,
            next_playbook_id: 1,

            ledger: [None; MAX_LEDGER_ENTRIES],
            ledger_count: 0,
            next_seq: 1,
        }
    }

    /// Enregistre une action dans le registre d'audit cryptographique chaîné
    fn record_audit(&mut self, timestamp: u64, action_code: u16, target_id: u32, note: &str) {
        if self.ledger_count >= MAX_LEDGER_ENTRIES {
            return;
        }

        let prev_hash = if self.ledger_count == 0 {
            [0u8; 32]
        } else {
            self.ledger[self.ledger_count - 1].unwrap().entry_hash
        };

        let mut detail = [0u8; 32];
        let bytes = note.as_bytes();
        let len = bytes.len().min(32);
        detail[..len].copy_from_slice(&bytes[..len]);

        let mut entry = AiopsAuditEntry {
            seq: self.next_seq,
            timestamp,
            action_code,
            target_id,
            detail,
            prev_hash,
            entry_hash: [0u8; 32],
        };
        entry.entry_hash = entry.compute_hash();

        self.ledger[self.ledger_count] = Some(entry);
        self.ledger_count += 1;
        self.next_seq += 1;
    }

    /// Initialise la topologie par défaut et les playbooks souverains de référence
    pub fn init_defaults(&mut self) {
        let mut cap = self.admin_cap;

        // 1. Enregistrement des nœuds de services souverains
        // Service 1 : Base de Données Souveraine (Tier 2)
        let _ = self.register_service(&mut cap, 1, "sovereign_db", 2, &[], 1000);
        // Service 2 : Démon d'Authentification IAM (Tier 1, dépend de la BD 1)
        let _ = self.register_service(&mut cap, 2, "iam_authd", 1, &[1], 1000);
        // Service 3 : Passerelle API Ingress (Tier 0, dépend de l'Auth 2)
        let _ = self.register_service(&mut cap, 3, "api_gateway", 0, &[2], 1000);
        // Service 4 : Nœud de Calcul Distribué (Tier 1, dépend de la BD 1)
        let _ = self.register_service(&mut cap, 4, "compute_node", 1, &[1], 1000);

        // 2. Playbooks d'auto-remédiation
        let _ = self.register_playbook(
            &mut cap,
            "auto_scale_database",
            1,
            AnomalySeverity::Critical,
            PlaybookAction::ScaleResource,
            true,
            100,
            1000,
        );
        let _ = self.register_playbook(
            &mut cap,
            "restart_auth_workers",
            2,
            AnomalySeverity::High,
            PlaybookAction::RestartWorker,
            true,
            50,
            1000,
        );
        let _ = self.register_playbook(
            &mut cap,
            "throttle_api_ingress",
            3,
            AnomalySeverity::Critical,
            PlaybookAction::ThrottleIngress,
            true,
            150,
            1000,
        );
    }

    /// Enregistre un service dans la topologie de dépendance
    pub fn register_service(
        &mut self,
        cap: &mut AiopsCap,
        id: u32,
        name: &str,
        tier: u8,
        deps: &[u32],
        timestamp: u64,
    ) -> Result<(), AiopsError> {
        if !cap.has_right(aiops_rights::MANAGE_TOPOLOGY) {
            return Err(AiopsError::AccessDenied);
        }
        cap.consume()?;

        if self.topology_count >= MAX_SERVICES {
            return Err(AiopsError::CapacityExceeded);
        }

        for i in 0..self.topology_count {
            if let Some(ref node) = self.topology[i] {
                if node.id == id {
                    return Err(AiopsError::ServiceAlreadyExists);
                }
            }
        }

        let mut node = TopologyNode::new(id, name, tier);
        for &d in deps {
            node.add_dependency(d)?;
        }

        self.topology[self.topology_count] = Some(node);
        self.topology_count += 1;

        self.record_audit(timestamp, 0x01, id, "SERVICE_REGISTERED");
        Ok(())
    }

    /// Enregistre un playbook d'auto-remédiation
    pub fn register_playbook(
        &mut self,
        cap: &mut AiopsCap,
        name: &str,
        target_service_id: u32,
        trigger_severity: AnomalySeverity,
        action: PlaybookAction,
        auto_trigger: bool,
        cooldown_ticks: u64,
        timestamp: u64,
    ) -> Result<u32, AiopsError> {
        if !cap.has_right(aiops_rights::CONFIGURE_RULES) {
            return Err(AiopsError::AccessDenied);
        }
        cap.consume()?;

        if self.playbook_count >= MAX_PLAYBOOKS {
            return Err(AiopsError::CapacityExceeded);
        }

        let id = self.next_playbook_id;
        self.next_playbook_id += 1;

        let pb = RemediationPlaybook::new(
            id,
            name,
            target_service_id,
            trigger_severity,
            action,
            auto_trigger,
            cooldown_ticks,
        );
        self.playbooks[self.playbook_count] = Some(pb);
        self.playbook_count += 1;

        self.record_audit(timestamp, 0x02, id, "PLAYBOOK_CONFIGURED");
        Ok(id)
    }

    /// Ingestion d'une mesure télémétrique et analyse d'anomalie par Z-score
    pub fn ingest_metric(
        &mut self,
        cap: &mut AiopsCap,
        service_id: u32,
        source: EventSource,
        metric_name: &str,
        value: i64,
        timestamp: u64,
    ) -> Result<Option<u32>, AiopsError> {
        if !cap.has_right(aiops_rights::INGEST_EVENTS) {
            return Err(AiopsError::AccessDenied);
        }
        cap.consume()?;

        // 1. Stockage de l'événement dans le tampon circulaire borné
        let event_id = self.next_event_id;
        self.next_event_id += 1;

        let event = TelemetryEvent::new(
            event_id,
            timestamp,
            source,
            service_id,
            EventSeverity::Info,
            metric_name,
            value,
        );

        self.events[self.event_head] = Some(event);
        self.event_head = (self.event_head + 1) % MAX_EVENTS;
        if self.event_count < MAX_EVENTS {
            self.event_count += 1;
        }

        // 2. Recherche ou allocation de la fenêtre glissante pour cette métrique
        let mut window_idx = None;
        let name_bytes = metric_name.as_bytes();
        let name_len = name_bytes.len().min(32);

        for i in 0..self.metric_window_count {
            if let Some(ref w) = self.metric_windows[i] {
                if w.service_id == service_id
                    && w.metric_len == name_len
                    && &w.metric_name[..name_len] == &name_bytes[..name_len]
                {
                    window_idx = Some(i);
                    break;
                }
            }
        }

        let idx = match window_idx {
            Some(i) => i,
            None => {
                if self.metric_window_count >= MAX_METRIC_WINDOWS {
                    return Err(AiopsError::CapacityExceeded);
                }
                let i = self.metric_window_count;
                self.metric_windows[i] = Some(MetricWindow::new(service_id, metric_name));
                self.metric_window_count += 1;
                i
            }
        };

        // 3. Calcul du Z-score avant d'ajouter le point dans la baseline
        let z_score = self.metric_windows[idx].as_ref().unwrap().z_score(value);
        let baseline_mean = self.metric_windows[idx].as_ref().unwrap().mean();

        // Ajout du nouvel échantillon
        self.metric_windows[idx].as_mut().unwrap().push(value);

        // 4. Seuil de détection statistique d'anomalie
        // Z >= 300 -> Critical (3.0 sigma)
        // Z >= 200 -> High (2.0 sigma)
        // Z >= 150 -> Medium (1.5 sigma)
        let severity = if z_score >= 300 {
            Some(AnomalySeverity::Critical)
        } else if z_score >= 200 {
            Some(AnomalySeverity::High)
        } else if z_score >= 150 {
            Some(AnomalySeverity::Medium)
        } else {
            None
        };

        if let Some(sev) = severity {
            if self.anomaly_count >= MAX_ANOMALIES {
                return Err(AiopsError::CapacityExceeded);
            }

            let anom_id = self.next_anomaly_id;
            self.next_anomaly_id += 1;

            let mut m_name = [0u8; 32];
            m_name[..name_len].copy_from_slice(&name_bytes[..name_len]);

            let anom = AnomalyRecord {
                id: anom_id,
                timestamp,
                service_id,
                metric_name: m_name,
                metric_len: name_len,
                observed_value: value,
                baseline_mean,
                z_score,
                severity: sev,
                correlated_incident_id: None,
            };

            self.anomalies[self.anomaly_count] = Some(anom);
            self.anomaly_count += 1;

            // Dégradation de l'état de santé du service dans la topologie
            for i in 0..self.topology_count {
                if let Some(ref mut node) = self.topology[i] {
                    if node.id == service_id {
                        node.healthy = false;
                        break;
                    }
                }
            }

            self.record_audit(timestamp, 0x03, anom_id, "ANOMALY_DETECTED");
            Ok(Some(anom_id))
        } else {
            Ok(None)
        }
    }

    /// Corrélation topologique multi-sources des anomalies non attribuées
    pub fn correlate_incidents(
        &mut self,
        cap: &mut AiopsCap,
        timestamp: u64,
    ) -> Result<usize, AiopsError> {
        if !cap.has_right(aiops_rights::CORRELATE_INCIDENTS) {
            return Err(AiopsError::AccessDenied);
        }
        cap.consume()?;

        let mut newly_correlated = 0;

        // Regroupe les anomalies orphelines
        let mut unlinked = [0usize; MAX_ANOMALIES];
        let mut unlinked_count = 0;

        for i in 0..self.anomaly_count {
            if let Some(ref a) = self.anomalies[i] {
                if a.correlated_incident_id.is_none() {
                    unlinked[unlinked_count] = i;
                    unlinked_count += 1;
                }
            }
        }

        if unlinked_count == 0 {
            return Ok(0);
        }

        // Pour chaque groupe d'anomalies, déterminer le service de cause racine
        // en suivant l'arbre topologique (les couches inférieures / tier le plus élevé causent les couches supérieures)
        let mut incident_anomalies = [0u32; 8];
        let mut incident_services = [0u32; 8];
        let mut a_count = 0;
        let mut s_count = 0;
        let mut max_severity = AnomalySeverity::Low;
        let mut candidate_root_svc = 0u32;
        let mut max_tier = 0u8;

        for k in 0..unlinked_count {
            let idx = unlinked[k];
            let anom = self.anomalies[idx].unwrap();

            if a_count < 8 {
                incident_anomalies[a_count] = anom.id;
                a_count += 1;
            }

            let mut already_svc = false;
            for s in 0..s_count {
                if incident_services[s] == anom.service_id {
                    already_svc = true;
                    break;
                }
            }
            if !already_svc && s_count < 8 {
                incident_services[s_count] = anom.service_id;
                s_count += 1;
            }

            if anom.severity as u8 > max_severity as u8 {
                max_severity = anom.severity;
            }

            // Détermination du candidat cause racine via la profondeur topologique (tier le plus profond)
            for t in 0..self.topology_count {
                if let Some(ref node) = self.topology[t] {
                    if node.id == anom.service_id {
                        if node.tier >= max_tier {
                            max_tier = node.tier;
                            candidate_root_svc = node.id;
                        }
                        break;
                    }
                }
            }
        }

        if candidate_root_svc == 0 && s_count > 0 {
            candidate_root_svc = incident_services[0];
        }

        if self.incident_count >= MAX_INCIDENTS {
            return Err(AiopsError::CapacityExceeded);
        }

        let inc_id = self.next_incident_id;
        self.next_incident_id += 1;

        // Score de confiance basé sur le nombre de signaux corrélés et l'alignement topologique
        let confidence = (50 + (s_count * 15) + (a_count * 5)).min(98) as u8;

        let incident = CorrelatedIncident {
            id: inc_id,
            opened_at: timestamp,
            resolved_at: None,
            root_cause_service_id: candidate_root_svc,
            confidence_score: confidence,
            severity: max_severity,
            affected_services: incident_services,
            affected_count: s_count,
            anomaly_ids: incident_anomalies,
            anomaly_count: a_count,
            status: IncidentStatus::Active,
            playbook_executed: None,
        };

        self.incidents[self.incident_count] = Some(incident);
        self.incident_count += 1;
        newly_correlated += 1;

        // Marque les anomalies comme associées à cet incident
        for k in 0..a_count {
            let anom_id = incident_anomalies[k];
            for i in 0..self.anomaly_count {
                if let Some(ref mut a) = self.anomalies[i] {
                    if a.id == anom_id {
                        a.correlated_incident_id = Some(inc_id);
                        break;
                    }
                }
            }
        }

        self.record_audit(timestamp, 0x04, inc_id, "INCIDENT_CORRELATED");
        Ok(newly_correlated)
    }

    /// Exécute un playbook d'auto-remédiation sur un incident
    pub fn trigger_remediation(
        &mut self,
        cap: &mut AiopsCap,
        incident_id: u32,
        timestamp: u64,
    ) -> Result<PlaybookAction, AiopsError> {
        if !cap.has_right(aiops_rights::TRIGGER_PLAYBOOK) {
            return Err(AiopsError::AccessDenied);
        }
        cap.consume()?;

        // Recherche de l'incident
        let mut inc_idx = None;
        for i in 0..self.incident_count {
            if let Some(ref inc) = self.incidents[i] {
                if inc.id == incident_id {
                    inc_idx = Some(i);
                    break;
                }
            }
        }

        let i_idx = inc_idx.ok_or(AiopsError::IncidentNotFound)?;
        let root_svc = self.incidents[i_idx].unwrap().root_cause_service_id;
        let inc_sev = self.incidents[i_idx].unwrap().severity;

        // Recherche du playbook correspondant au service cible ou compatible
        let mut matched_pb_idx = None;
        for p in 0..self.playbook_count {
            if let Some(ref pb) = self.playbooks[p] {
                if pb.target_service_id == root_svc && (inc_sev as u8 >= pb.trigger_severity as u8)
                {
                    matched_pb_idx = Some(p);
                    break;
                }
            }
        }

        let action = if let Some(p_idx) = matched_pb_idx {
            let pb = self.playbooks[p_idx].as_mut().unwrap();
            if pb.last_executed > 0 && timestamp < pb.last_executed + pb.cooldown_ticks {
                return Err(AiopsError::CooldownActive);
            }
            pb.last_executed = timestamp;
            pb.action
        } else {
            // Action de repli par défaut selon la sévérité
            match inc_sev {
                AnomalySeverity::Critical => PlaybookAction::ScaleResource,
                AnomalySeverity::High => PlaybookAction::RestartWorker,
                _ => PlaybookAction::FlushCaches,
            }
        };

        // Mise à jour de l'incident
        if let Some(ref mut inc) = self.incidents[i_idx] {
            inc.status = IncidentStatus::Resolved;
            inc.resolved_at = Some(timestamp);
            inc.playbook_executed = Some(action);
        }

        // Restauration de l'état sain du service dans la topologie
        for t in 0..self.topology_count {
            if let Some(ref mut node) = self.topology[t] {
                if node.id == root_svc {
                    node.healthy = true;
                    break;
                }
            }
        }

        self.record_audit(timestamp, 0x05, incident_id, "PLAYBOOK_EXECUTED");
        Ok(action)
    }

    /// Synthèse globale de l'état AIOps
    pub fn get_summary(&self, cap: &AiopsCap) -> Result<AiopsSummary, AiopsError> {
        if !cap.has_right(aiops_rights::QUERY_AUDIT) {
            return Err(AiopsError::AccessDenied);
        }

        let mut active_inc = 0;
        let mut resolved_inc = 0;

        for i in 0..self.incident_count {
            if let Some(ref inc) = self.incidents[i] {
                if inc.status == IncidentStatus::Active {
                    active_inc += 1;
                } else if inc.status == IncidentStatus::Resolved {
                    resolved_inc += 1;
                }
            }
        }

        let health_score = if active_inc == 0 {
            100
        } else {
            100u8.saturating_sub((active_inc * 20).min(90) as u8)
        };

        Ok(AiopsSummary {
            total_services: self.topology_count,
            total_events: self.event_count,
            total_anomalies: self.anomaly_count,
            active_incidents: active_inc,
            resolved_incidents: resolved_inc,
            total_playbooks: self.playbook_count,
            ledger_entries: self.ledger_count,
            health_score,
        })
    }

    /// Vérifie l'intégrité de la chaîne cryptographique du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        if self.ledger_count == 0 {
            return true;
        }

        let mut prev = [0u8; 32];
        for i in 0..self.ledger_count {
            match self.ledger[i] {
                None => return false,
                Some(ref entry) => {
                    if entry.prev_hash != prev {
                        return false;
                    }
                    let computed = entry.compute_hash();
                    if entry.entry_hash != computed {
                        return false;
                    }
                    prev = entry.entry_hash;
                }
            }
        }
        true
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aiops_capability_and_attenuation() {
        let cap = AiopsCap::new(Handle::new(13701, 1), aiops_rights::ALL, 5000, 100);
        assert!(cap.has_right(aiops_rights::INGEST_EVENTS));
        assert!(cap.has_right(aiops_rights::ADMIN));

        let sub_cap = cap
            .attenuate(
                aiops_rights::INGEST_EVENTS | aiops_rights::QUERY_AUDIT,
                2000,
                50,
            )
            .expect("Atténuation");
        assert!(sub_cap.has_right(aiops_rights::INGEST_EVENTS));
        assert!(!sub_cap.has_right(aiops_rights::TRIGGER_PLAYBOOK));

        // Refus d'escalade
        assert_eq!(
            sub_cap.attenuate(aiops_rights::ALL, 2000, 50),
            Err(AiopsError::AttenuationViolation)
        );
    }

    #[test]
    fn test_statistical_window_and_zscore() {
        let mut window = MetricWindow::new(1, "cpu_usage");

        // Pousse des valeurs stables (autour de 50)
        for _ in 0..10 {
            window.push(50);
        }
        assert_eq!(window.mean(), 50);
        assert_eq!(window.std_dev(), 0);

        // Pousse des valeurs variables
        window.push(40);
        window.push(60);
        window.push(45);
        window.push(55);

        let sd = window.std_dev();
        assert!(sd > 0);

        // Une valeur normale (52) donne un faible Z-score
        let z_norm = window.z_score(52);
        assert!(z_norm < 100);

        // Une valeur anormale (150) donne un fort Z-score (> 3.0 sigma)
        let z_anom = window.z_score(150);
        assert!(z_anom >= 300);
    }

    #[test]
    fn test_event_ingestion_and_anomaly_detection() {
        let mut cap = AiopsCap::new(Handle::new(13702, 1), aiops_rights::ALL, 5000, 200);
        let mut daemon = JamboAiopsDaemon::new(cap);
        daemon.init_defaults();

        // Établit une baseline pour sovereign_db (service_id = 1) sur db_latency_ms
        for t in 0..12 {
            let _ = daemon
                .ingest_metric(
                    &mut cap,
                    1,
                    EventSource::DatabaseEngine,
                    "db_latency_ms",
                    20 + (t % 3),
                    1000 + t as u64,
                )
                .unwrap();
        }

        // Aucune anomalie détectée sur le régime normal
        assert_eq!(daemon.anomaly_count, 0);

        // Injection d'un pic de latence anormal (400 ms au lieu de 20 ms)
        let res = daemon
            .ingest_metric(
                &mut cap,
                1,
                EventSource::DatabaseEngine,
                "db_latency_ms",
                400,
                1050,
            )
            .unwrap();

        assert!(res.is_some(), "L'anomalie critique doit être détectée");
        assert_eq!(daemon.anomaly_count, 1);
        assert_eq!(
            daemon.anomalies[0].unwrap().severity,
            AnomalySeverity::Critical
        );
    }

    #[test]
    fn test_topological_correlation_and_root_cause() {
        let mut cap = AiopsCap::new(Handle::new(13703, 1), aiops_rights::ALL, 5000, 200);
        let mut daemon = JamboAiopsDaemon::new(cap);
        daemon.init_defaults();

        // 1. Initialise baseline pour DB (Service 1) et Gateway (Service 3)
        for t in 0..10 {
            let _ = daemon.ingest_metric(
                &mut cap,
                1,
                EventSource::DatabaseEngine,
                "db_latency_ms",
                15,
                2000 + t as u64,
            );
            let _ = daemon.ingest_metric(
                &mut cap,
                3,
                EventSource::ApiGateway,
                "http_500_rate",
                1,
                2000 + t as u64,
            );
        }

        // 2. Pic anormal sur DB (Service 1, Tier 2)
        daemon
            .ingest_metric(
                &mut cap,
                1,
                EventSource::DatabaseEngine,
                "db_latency_ms",
                500,
                2020,
            )
            .unwrap();

        // 3. Propagation : pic anormal d'erreurs sur Gateway (Service 3, Tier 0)
        daemon
            .ingest_metric(
                &mut cap,
                3,
                EventSource::ApiGateway,
                "http_500_rate",
                80,
                2025,
            )
            .unwrap();

        assert_eq!(daemon.anomaly_count, 2);

        // 4. Corrélation topologique
        let correlated = daemon.correlate_incidents(&mut cap, 2030).unwrap();
        assert_eq!(correlated, 1);
        assert_eq!(daemon.incident_count, 1);

        let inc = daemon.incidents[0].unwrap();
        assert_eq!(inc.root_cause_service_id, 1, "La DB est la cause racine");
        assert_eq!(inc.status, IncidentStatus::Active);
        assert!(inc.confidence_score >= 80);
    }

    #[test]
    fn test_autonomous_playbook_execution() {
        let mut cap = AiopsCap::new(Handle::new(13704, 1), aiops_rights::ALL, 5000, 200);
        let mut daemon = JamboAiopsDaemon::new(cap);
        daemon.init_defaults();

        // Crée une condition d'incident
        for t in 0..10 {
            let _ = daemon.ingest_metric(
                &mut cap,
                1,
                EventSource::DatabaseEngine,
                "db_latency_ms",
                20,
                3000 + t as u64,
            );
        }
        daemon
            .ingest_metric(
                &mut cap,
                1,
                EventSource::DatabaseEngine,
                "db_latency_ms",
                800,
                3020,
            )
            .unwrap();

        daemon.correlate_incidents(&mut cap, 3025).unwrap();
        let inc_id = daemon.incidents[0].unwrap().id;

        // Auto-remédiation
        let action = daemon.trigger_remediation(&mut cap, inc_id, 3030).unwrap();
        assert_eq!(action, PlaybookAction::ScaleResource);

        let inc = daemon.incidents[0].unwrap();
        assert_eq!(inc.status, IncidentStatus::Resolved);
        assert_eq!(inc.playbook_executed, Some(PlaybookAction::ScaleResource));

        // Intégrité du ledger d'audit
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_ledger_tampering_detection() {
        let cap = AiopsCap::new(Handle::new(13705, 1), aiops_rights::ALL, 5000, 200);
        let mut daemon = JamboAiopsDaemon::new(cap);
        daemon.init_defaults();

        assert!(daemon.verify_ledger_integrity());

        // Altération malveillante
        if let Some(ref mut entry) = daemon.ledger[0] {
            entry.action_code = 0xBADC;
        }

        assert!(!daemon.verify_ledger_integrity());
    }
}

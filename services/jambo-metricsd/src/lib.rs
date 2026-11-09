//! Moteur de Métriques Distribuées & Surveillance en Séries Temporelles (`jambo-metricsd`, Ring 3, PID 12)
//!
//! Fournit un système de télémétrie, métrologie et observabilité quantitative en temps réel pour JamboOS.
//! Collecte les séries temporelles dans des tampons annulaires déterministes O(1), évalue les règles
//! d'alerte à seuil et protège l'accès sans autorité ambiante via la capacité `MetricsCap`.
//! Expose un protocole IPC souverain à messages de 64 octets et un client `MetricsClient`.

#![no_std]
#![allow(clippy::needless_range_loop)]

use libjambo::{Handle, SysError};

pub const MAX_SERIES: usize = 16;
pub const RING_CAPACITY: usize = 32;
pub const MAX_ALERT_RULES: usize = 16;

/// Droits de capacité pour la télémétrie et les métriques système.
pub mod metrics_rights {
    pub const METRICS_INGEST: u32 = 0x01;
    pub const METRICS_QUERY: u32 = 0x02;
    pub const METRICS_ALERT: u32 = 0x04;
    pub const METRICS_ADMIN: u32 = 0x80;
    pub const ALL: u32 = METRICS_INGEST | METRICS_QUERY | METRICS_ALERT | METRICS_ADMIN;
}

/// Jeton de capacité pour l'accès aux métriques distribuées.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsCap {
    pub handle: Handle,
    pub rights: u32,
}

impl MetricsCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    pub fn attenuate(&self, new_rights: u32) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

/// Échantillon individuel horodaté.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricSample {
    pub timestamp: u64,
    pub value: u64,
}

impl MetricSample {
    pub const fn empty() -> Self {
        Self {
            timestamp: 0,
            value: 0,
        }
    }
}

/// Condition de déclenchement d'une règle d'alerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertCondition {
    GreaterThan,
    LessThan,
}

/// Règle d'alerte sur une série temporelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertRule {
    pub series_name: [u8; 32],
    pub condition: AlertCondition,
    pub threshold: u64,
    pub triggered: bool,
    pub allocated: bool,
}

impl AlertRule {
    pub const fn empty() -> Self {
        Self {
            series_name: [0u8; 32],
            condition: AlertCondition::GreaterThan,
            threshold: 0,
            triggered: false,
            allocated: false,
        }
    }
}

/// Série temporelle circulaire bornée en espace mémoire O(1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricSeries {
    pub name: [u8; 32],
    pub node_id: u16,
    pub samples: [MetricSample; RING_CAPACITY],
    pub head: usize,
    pub count: usize,
    pub min_val: u64,
    pub max_val: u64,
    pub sum_val: u64,
    pub allocated: bool,
}

impl MetricSeries {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; 32],
            node_id: 0,
            samples: [MetricSample::empty(); RING_CAPACITY],
            head: 0,
            count: 0,
            min_val: u64::MAX,
            max_val: 0,
            sum_val: 0,
            allocated: false,
        }
    }
}

/// Collecteur et moteur de requêtes de métriques.
pub struct MetricsCollector {
    pub series: [MetricSeries; MAX_SERIES],
    pub alerts: [AlertRule; MAX_ALERT_RULES],
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub const fn new() -> Self {
        Self {
            series: [MetricSeries::empty(); MAX_SERIES],
            alerts: [AlertRule::empty(); MAX_ALERT_RULES],
        }
    }

    /// Déclare une nouvelle série temporelle.
    pub fn register_series(
        &mut self,
        cap: &MetricsCap,
        name: &[u8],
        node_id: u16,
    ) -> Result<(), SysError> {
        if !cap.has_right(metrics_rights::METRICS_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        if name.is_empty() || name.len() > 32 {
            return Err(SysError::InvalidArgument);
        }

        let mut name_buf = [0u8; 32];
        name_buf[..name.len()].copy_from_slice(name);

        for s in self.series.iter() {
            if s.allocated && s.name == name_buf && s.node_id == node_id {
                return Ok(()); // Déjà enregistrée
            }
        }

        for s in self.series.iter_mut() {
            if !s.allocated {
                s.name = name_buf;
                s.node_id = node_id;
                s.head = 0;
                s.count = 0;
                s.min_val = u64::MAX;
                s.max_val = 0;
                s.sum_val = 0;
                s.allocated = true;
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Enregistre une règle d'alerte.
    pub fn register_alert(
        &mut self,
        cap: &MetricsCap,
        name: &[u8],
        condition: AlertCondition,
        threshold: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(metrics_rights::METRICS_ALERT) {
            return Err(SysError::PermissionDenied);
        }
        if name.is_empty() || name.len() > 32 {
            return Err(SysError::InvalidArgument);
        }

        let mut name_buf = [0u8; 32];
        name_buf[..name.len()].copy_from_slice(name);

        for a in self.alerts.iter_mut() {
            if !a.allocated {
                a.series_name = name_buf;
                a.condition = condition;
                a.threshold = threshold;
                a.triggered = false;
                a.allocated = true;
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Ingère un nouvel échantillon de métrique et évalue les alertes associées.
    pub fn ingest(
        &mut self,
        cap: &MetricsCap,
        name: &[u8],
        node_id: u16,
        timestamp: u64,
        value: u64,
    ) -> Result<bool, SysError> {
        if !cap.has_right(metrics_rights::METRICS_INGEST) {
            return Err(SysError::PermissionDenied);
        }
        if name.is_empty() || name.len() > 32 {
            return Err(SysError::InvalidArgument);
        }

        let mut name_buf = [0u8; 32];
        name_buf[..name.len()].copy_from_slice(name);

        let mut alert_triggered = false;

        // 1. Insertion dans la série temporelle
        let mut found = false;
        for s in self.series.iter_mut() {
            if s.allocated && s.name == name_buf && (node_id == 0 || s.node_id == node_id) {
                let slot = s.head;
                if s.count < RING_CAPACITY {
                    s.count += 1;
                    s.sum_val = s.sum_val.saturating_add(value);
                } else {
                    let old_val = s.samples[slot].value;
                    s.sum_val = s.sum_val.saturating_sub(old_val).saturating_add(value);
                }

                s.samples[slot] = MetricSample { timestamp, value };
                s.head = (s.head + 1) % RING_CAPACITY;

                if value < s.min_val {
                    s.min_val = value;
                }
                if value > s.max_val {
                    s.max_val = value;
                }

                found = true;
                break;
            }
        }

        if !found {
            return Err(SysError::InvalidHandle);
        }

        // 2. Évaluation des alertes
        for a in self.alerts.iter_mut() {
            if a.allocated && a.series_name == name_buf {
                let is_violation = match a.condition {
                    AlertCondition::GreaterThan => value > a.threshold,
                    AlertCondition::LessThan => value < a.threshold,
                };
                if is_violation {
                    a.triggered = true;
                    alert_triggered = true;
                } else {
                    a.triggered = false;
                }
            }
        }

        Ok(alert_triggered)
    }

    /// Interroge les statistiques agrégées (min, max, avg, last, count).
    pub fn query_stats(
        &self,
        cap: &MetricsCap,
        name: &[u8],
        node_id: u16,
    ) -> Result<(u64, u64, u64, u64, usize), SysError> {
        if !cap.has_right(metrics_rights::METRICS_QUERY) {
            return Err(SysError::PermissionDenied);
        }
        if name.is_empty() || name.len() > 32 {
            return Err(SysError::InvalidArgument);
        }

        let mut name_buf = [0u8; 32];
        name_buf[..name.len()].copy_from_slice(name);

        for s in self.series.iter() {
            if s.allocated && s.name == name_buf && (node_id == 0 || s.node_id == node_id) {
                if s.count == 0 {
                    return Ok((0, 0, 0, 0, 0));
                }
                let avg = s.sum_val / (s.count as u64);
                let last_idx = if s.head == 0 {
                    RING_CAPACITY - 1
                } else {
                    s.head - 1
                };
                let last = s.samples[last_idx].value;
                return Ok((s.min_val, s.max_val, avg, last, s.count));
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Vérifie si une alerte est actuellement active sur une série.
    pub fn is_alert_triggered(&self, cap: &MetricsCap, name: &[u8]) -> Result<bool, SysError> {
        if !cap.has_right(metrics_rights::METRICS_QUERY) {
            return Err(SysError::PermissionDenied);
        }
        let mut name_buf = [0u8; 32];
        if name.is_empty() || name.len() > 32 {
            return Err(SysError::InvalidArgument);
        }
        name_buf[..name.len()].copy_from_slice(name);

        for a in self.alerts.iter() {
            if a.allocated && a.series_name == name_buf {
                return Ok(a.triggered);
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Nombre de séries enregistrées.
    pub fn series_count(&self) -> usize {
        self.series.iter().filter(|s| s.allocated).count()
    }

    /// Nombre d'alertes actuellement actives (déclenchées).
    pub fn active_alerts_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| a.allocated && a.triggered)
            .count()
    }

    /// Nombre total de règles d'alerte enregistrées.
    pub fn alert_rules_count(&self) -> usize {
        self.alerts.iter().filter(|a| a.allocated).count()
    }
}

/// Démon orchestrateur de métriques et télémétrie distribuée (`jambo-metricsd`).
pub struct JamboMetricsDaemon {
    pub collector: MetricsCollector,
    pub cap: MetricsCap,
    pub samples_ingested: u64,
}

impl Default for JamboMetricsDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboMetricsDaemon {
    pub fn new() -> Self {
        let cap = MetricsCap::new(Handle::new(6701, 1), metrics_rights::ALL);
        let mut collector = MetricsCollector::new();
        let _ = collector.register_series(&cap, b"node_cpu", 1);
        let _ = collector.register_series(&cap, b"node_ram", 1);
        let _ = collector.register_alert(&cap, b"node_cpu", AlertCondition::GreaterThan, 90);
        let _ = collector.ingest(&cap, b"node_cpu", 1, 100, 25);
        let _ = collector.ingest(&cap, b"node_ram", 1, 100, 1024);
        Self {
            collector,
            cap,
            samples_ingested: 2,
        }
    }

    pub fn new_with_cap(cap: MetricsCap) -> Self {
        Self {
            collector: MetricsCollector::new(),
            cap,
            samples_ingested: 0,
        }
    }

    pub fn register_series(&mut self, name: &[u8], node_id: u16) -> Result<(), SysError> {
        self.collector.register_series(&self.cap, name, node_id)
    }

    pub fn register_alert(
        &mut self,
        name: &[u8],
        cond: AlertCondition,
        threshold: u64,
    ) -> Result<(), SysError> {
        self.collector
            .register_alert(&self.cap, name, cond, threshold)
    }

    pub fn ingest(
        &mut self,
        name: &[u8],
        node_id: u16,
        timestamp: u64,
        value: u64,
    ) -> Result<bool, SysError> {
        let effective_node = if node_id == 0 { 1 } else { node_id };

        // Auto-enregistrement si la série n'existe pas encore et que la capacité le permet
        let mut name_buf = [0u8; 32];
        if name.is_empty() || name.len() > 32 {
            return Err(SysError::InvalidArgument);
        }
        name_buf[..name.len()].copy_from_slice(name);

        let exists = self.collector.series.iter().any(|s| {
            s.allocated
                && s.name == name_buf
                && (effective_node == 0 || s.node_id == effective_node)
        });
        if !exists && self.cap.has_right(metrics_rights::METRICS_ADMIN) {
            let _ = self
                .collector
                .register_series(&self.cap, name, effective_node);
        }

        let alerted = self
            .collector
            .ingest(&self.cap, name, effective_node, timestamp, value)?;
        self.samples_ingested = self.samples_ingested.saturating_add(1);
        Ok(alerted)
    }

    pub fn query_stats(
        &self,
        name: &[u8],
        node_id: u16,
    ) -> Result<(u64, u64, u64, u64, usize), SysError> {
        self.collector.query_stats(&self.cap, name, node_id)
    }

    pub fn is_alert_triggered(&self, name: &[u8]) -> Result<bool, SysError> {
        self.collector.is_alert_triggered(&self.cap, name)
    }

    pub fn series_count(&self) -> usize {
        self.collector.series_count()
    }

    pub fn active_alerts_count(&self) -> usize {
        self.collector.active_alerts_count()
    }

    pub fn alert_rules_count(&self) -> usize {
        self.collector.alert_rules_count()
    }

    /// Traite une requête IPC souveraine et génère la réponse à 64 octets
    pub fn handle_ipc_request(&mut self, req: &MetricsRequest) -> MetricsResponse {
        let mut resp = MetricsResponse::default();

        match req.opcode {
            x if x == MetricsOpcode::GetStatus as u32 => {
                resp.status = METRICS_STATUS_OK;
                resp.series_count = self.collector.series_count() as u32;
                resp.active_alerts = self.collector.active_alerts_count() as u32;
                resp.total_samples = self.samples_ingested;
            }
            x if x == MetricsOpcode::QuerySeries as u32 => {
                let name_len =
                    if req.data_len > 0 && (req.data_len as usize) <= req.series_name.len() {
                        req.data_len as usize
                    } else {
                        req.series_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(req.series_name.len())
                    };
                let name = &req.series_name[..name_len];

                match self.collector.query_stats(&self.cap, name, req.node_id) {
                    Ok((min, max, avg, last, count)) => {
                        resp.status = METRICS_STATUS_OK;
                        resp.min_val = min;
                        resp.max_val = max;
                        resp.avg_val = avg;
                        resp.last_val = last;
                        resp.sample_count = count as u32;
                        resp.series_count = self.collector.series_count() as u32;
                        resp.total_samples = self.samples_ingested;
                        resp.active_alerts = self.collector.active_alerts_count() as u32;
                    }
                    Err(_) => {
                        resp.status = METRICS_STATUS_ERROR;
                    }
                }
            }
            x if x == MetricsOpcode::IngestSample as u32 => {
                let name_len =
                    if req.data_len > 0 && (req.data_len as usize) <= req.series_name.len() {
                        req.data_len as usize
                    } else {
                        req.series_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(req.series_name.len())
                    };
                let name = &req.series_name[..name_len];

                match self.ingest(name, req.node_id, req.timestamp, req.value) {
                    Ok(alerted) => {
                        resp.status = METRICS_STATUS_OK;
                        resp.alert_triggered = if alerted { 1 } else { 0 };
                        resp.series_count = self.collector.series_count() as u32;
                        resp.total_samples = self.samples_ingested;
                        resp.active_alerts = self.collector.active_alerts_count() as u32;
                        if let Ok((min, max, avg, last, count)) =
                            self.collector.query_stats(&self.cap, name, req.node_id)
                        {
                            resp.min_val = min;
                            resp.max_val = max;
                            resp.avg_val = avg;
                            resp.last_val = last;
                            resp.sample_count = count as u32;
                        }
                    }
                    Err(_) => {
                        resp.status = METRICS_STATUS_ERROR;
                    }
                }
            }
            x if x == MetricsOpcode::GetAlerts as u32 => {
                let name_len =
                    if req.data_len > 0 && (req.data_len as usize) <= req.series_name.len() {
                        req.data_len as usize
                    } else {
                        req.series_name.iter().position(|&b| b == 0).unwrap_or(0)
                    };

                resp.status = METRICS_STATUS_OK;
                resp.active_alerts = self.collector.active_alerts_count() as u32;
                resp.series_count = self.collector.series_count() as u32;
                resp.total_samples = self.samples_ingested;

                if name_len > 0 {
                    let name = &req.series_name[..name_len];
                    if let Ok(trig) = self.collector.is_alert_triggered(&self.cap, name) {
                        resp.alert_triggered = if trig { 1 } else { 0 };
                    }
                }
            }
            _ => {
                resp.status = METRICS_STATUS_ERROR;
            }
        }

        resp
    }
}

// ============================================================================
// PROTOCOLE IPC METRICSD (MetricsOpcode, MetricsRequest, MetricsResponse, MetricsClient)
// ============================================================================

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const METRICS_STATUS_OK: u32 = 1;
pub const METRICS_STATUS_ERROR: u32 = 0;

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

/// Cède volontairement le temps processeur au scheduler EEVDF
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

/// Opcodes du protocole IPC de télémétrie et métrologie système (METRICSD)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsOpcode {
    GetStatus = 1,
    QuerySeries = 2,
    IngestSample = 3,
    GetAlerts = 4,
}

/// Requête IPC transmise au démon `metricsd` (exactement 64 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsRequest {
    pub opcode: u32,           // MetricsOpcode
    pub node_id: u16,          // Node ID (par défaut 1)
    pub data_len: u16,         // Longueur du nom de série
    pub value: u64,            // Valeur d'échantillon pour IngestSample
    pub timestamp: u64,        // Horodatage pour IngestSample
    pub series_name: [u8; 32], // Nom de la série temporelle
    pub reserved: [u8; 8],     // Alignement et extension future
}

const _: () = assert!(core::mem::size_of::<MetricsRequest>() == 64);

impl MetricsRequest {
    pub const fn new(opcode: MetricsOpcode) -> Self {
        Self {
            opcode: opcode as u32,
            node_id: 1,
            data_len: 0,
            value: 0,
            timestamp: 0,
            series_name: [0u8; 32],
            reserved: [0u8; 8],
        }
    }

    pub fn new_query(name: &[u8], node_id: u16) -> Self {
        let mut req = Self::new(MetricsOpcode::QuerySeries);
        let copy_len = name.len().min(32);
        req.series_name[..copy_len].copy_from_slice(&name[..copy_len]);
        req.data_len = copy_len as u16;
        req.node_id = if node_id == 0 { 1 } else { node_id };
        req
    }

    pub fn new_ingest(name: &[u8], node_id: u16, timestamp: u64, value: u64) -> Self {
        let mut req = Self::new(MetricsOpcode::IngestSample);
        let copy_len = name.len().min(32);
        req.series_name[..copy_len].copy_from_slice(&name[..copy_len]);
        req.data_len = copy_len as u16;
        req.node_id = if node_id == 0 { 1 } else { node_id };
        req.timestamp = timestamp;
        req.value = value;
        req
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut req = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut req as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(req)
    }
}

/// Réponse IPC retournée par le démon `metricsd` (exactement 64 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsResponse {
    pub status: u32,          // 1 = OK, 0 = Erreur
    pub series_count: u32,    // Nombre de séries enregistrées
    pub active_alerts: u32,   // Nombre d'alertes actuellement actives
    pub sample_count: u32,    // Nombre d'échantillons dans la série interrogée
    pub min_val: u64,         // Valeur minimale
    pub max_val: u64,         // Valeur maximale
    pub avg_val: u64,         // Valeur moyenne
    pub last_val: u64,        // Dernière valeur ingérée
    pub total_samples: u64,   // Nombre cumulé d'échantillons ingérés
    pub alert_triggered: u32, // 1 si alerte déclenchée, 0 sinon
    pub reserved: [u8; 4],    // Alignement à 64 octets
}

const _: () = assert!(core::mem::size_of::<MetricsResponse>() == 64);

impl MetricsResponse {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut resp = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut resp as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(resp)
    }
}

/// Client IPC pour interagir avec le démon METRICS (jambo-metricsd, Ring 3, PID 12)
pub struct MetricsClient {
    pub endpoint: Handle,
}

impl MetricsClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    /// Récupère le statut global du collecteur de métriques
    pub fn get_status(&self) -> Result<MetricsResponse, SysError> {
        let req = MetricsRequest::new(MetricsOpcode::GetStatus);
        self.call(&req)
    }

    /// Interroge les statistiques (min, max, avg, last, count) d'une série temporelle
    pub fn query_series(&self, name: &[u8], node_id: u16) -> Result<MetricsResponse, SysError> {
        let req = MetricsRequest::new_query(name, node_id);
        self.call(&req)
    }

    /// Ingère un nouvel échantillon dans une série
    pub fn ingest_sample(
        &self,
        name: &[u8],
        node_id: u16,
        timestamp: u64,
        value: u64,
    ) -> Result<MetricsResponse, SysError> {
        let req = MetricsRequest::new_ingest(name, node_id, timestamp, value);
        self.call(&req)
    }

    /// Récupère l'état des alertes actives
    pub fn get_alerts(&self) -> Result<MetricsResponse, SysError> {
        let req = MetricsRequest::new(MetricsOpcode::GetAlerts);
        self.call(&req)
    }

    fn call(&self, req: &MetricsRequest) -> Result<MetricsResponse, SysError> {
        // 1. Envoi synchrone de la requête via ChannelCall
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

        // 2. Attente active coopérative de la réponse
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<MetricsResponse>() {
                return MetricsResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_ingest_and_query_stats() {
        let mut collector = MetricsCollector::new();
        let cap = MetricsCap::new(Handle::new(1, 1), metrics_rights::ALL);

        collector
            .register_series(&cap, b"node_cpu_utilization", 1)
            .unwrap();

        collector
            .ingest(&cap, b"node_cpu_utilization", 1, 1000, 20)
            .unwrap();
        collector
            .ingest(&cap, b"node_cpu_utilization", 1, 1001, 40)
            .unwrap();
        collector
            .ingest(&cap, b"node_cpu_utilization", 1, 1002, 60)
            .unwrap();

        let (min, max, avg, last, count) = collector
            .query_stats(&cap, b"node_cpu_utilization", 1)
            .unwrap();

        assert_eq!(min, 20);
        assert_eq!(max, 60);
        assert_eq!(avg, 40); // (20 + 40 + 60) / 3 = 40
        assert_eq!(last, 60);
        assert_eq!(count, 3);
    }

    #[test]
    fn test_metrics_ring_buffer_drop_oldest() {
        let mut collector = MetricsCollector::new();
        let cap = MetricsCap::new(Handle::new(1, 1), metrics_rights::ALL);

        collector
            .register_series(&cap, b"ipc_latency_nanos", 1)
            .unwrap();

        // Ingestion de plus d'échantillons que la capacité annulaire
        for i in 0..40 {
            collector
                .ingest(
                    &cap,
                    b"ipc_latency_nanos",
                    1,
                    1000 + i as u64,
                    i as u64 * 10,
                )
                .unwrap();
        }

        let (_, _, _, last, count) = collector
            .query_stats(&cap, b"ipc_latency_nanos", 1)
            .unwrap();

        assert_eq!(count, RING_CAPACITY); // Plafonné à 32
        assert_eq!(last, 390); // Dernier échantillon (39 * 10)
    }

    #[test]
    fn test_metrics_alert_trigger() {
        let mut collector = MetricsCollector::new();
        let cap = MetricsCap::new(Handle::new(1, 1), metrics_rights::ALL);

        collector
            .register_series(&cap, b"cluster_memory_bytes", 2)
            .unwrap();
        collector
            .register_alert(
                &cap,
                b"cluster_memory_bytes",
                AlertCondition::GreaterThan,
                80,
            )
            .unwrap();

        // Échantillon normal (75 <= 80)
        let alert1 = collector
            .ingest(&cap, b"cluster_memory_bytes", 2, 1000, 75)
            .unwrap();
        assert!(!alert1);
        assert!(!collector
            .is_alert_triggered(&cap, b"cluster_memory_bytes")
            .unwrap());

        // Échantillon critique (95 > 80) -> déclenche l'alerte !
        let alert2 = collector
            .ingest(&cap, b"cluster_memory_bytes", 2, 1001, 95)
            .unwrap();
        assert!(alert2);
        assert!(collector
            .is_alert_triggered(&cap, b"cluster_memory_bytes")
            .unwrap());
    }

    #[test]
    fn test_metrics_rights_attenuation() {
        let cap_full = MetricsCap::new(Handle::new(1, 1), metrics_rights::ALL);
        let cap_query_only = cap_full.attenuate(metrics_rights::METRICS_QUERY).unwrap();

        let mut collector = MetricsCollector::new();
        // Tentative d'ingestion avec capacité de lecture seule -> PermissionDenied
        let res = collector.ingest(&cap_query_only, b"test", 1, 1000, 50);
        assert_eq!(res, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_metrics_daemon() {
        let mut daemon = JamboMetricsDaemon::new();
        assert_eq!(daemon.series_count(), 2);
        assert_eq!(daemon.samples_ingested, 2);

        let (min, max, avg, last, count) = daemon.query_stats(b"node_cpu", 1).unwrap();
        assert_eq!(min, 25);
        assert_eq!(max, 25);
        assert_eq!(avg, 25);
        assert_eq!(last, 25);
        assert_eq!(count, 1);

        assert!(!daemon.is_alert_triggered(b"node_cpu").unwrap());
        // Déclenche l'alerte (> 90)
        let alert = daemon.ingest(b"node_cpu", 1, 101, 95).unwrap();
        assert!(alert);
        assert!(daemon.is_alert_triggered(b"node_cpu").unwrap());
    }

    #[test]
    fn test_ipc_request_response_size_and_serialization() {
        assert_eq!(core::mem::size_of::<MetricsRequest>(), 64);
        assert_eq!(core::mem::size_of::<MetricsResponse>(), 64);

        let req = MetricsRequest::new_ingest(b"cpu_load", 1, 1735000000, 75);
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 64);

        let decoded = MetricsRequest::from_bytes(&bytes).expect("decode MetricsRequest");
        assert_eq!(decoded.opcode, MetricsOpcode::IngestSample as u32);
        assert_eq!(decoded.node_id, 1);
        assert_eq!(decoded.timestamp, 1735000000);
        assert_eq!(decoded.value, 75);
        assert_eq!(&decoded.series_name[..8], b"cpu_load");

        let resp = MetricsResponse {
            status: METRICS_STATUS_OK,
            series_count: 3,
            active_alerts: 1,
            min_val: 10,
            max_val: 90,
            avg_val: 50,
            last_val: 75,
            total_samples: 42,
            alert_triggered: 1,
            ..Default::default()
        };

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);

        let decoded_resp =
            MetricsResponse::from_bytes(&resp_bytes).expect("decode MetricsResponse");
        assert_eq!(decoded_resp.status, METRICS_STATUS_OK);
        assert_eq!(decoded_resp.series_count, 3);
        assert_eq!(decoded_resp.active_alerts, 1);
        assert_eq!(decoded_resp.min_val, 10);
        assert_eq!(decoded_resp.max_val, 90);
        assert_eq!(decoded_resp.avg_val, 50);
        assert_eq!(decoded_resp.last_val, 75);
        assert_eq!(decoded_resp.total_samples, 42);
        assert_eq!(decoded_resp.alert_triggered, 1);
    }

    #[test]
    fn test_ipc_daemon_request_handling() {
        let cap = MetricsCap::new(Handle::new(12, 1), metrics_rights::ALL);
        let mut daemon = JamboMetricsDaemon::new_with_cap(cap);

        // 1. GetStatus initial
        let req_status = MetricsRequest::new(MetricsOpcode::GetStatus);
        let resp_status = daemon.handle_ipc_request(&req_status);
        assert_eq!(resp_status.status, METRICS_STATUS_OK);
        assert_eq!(resp_status.series_count, 0);
        assert_eq!(resp_status.total_samples, 0);

        // 2. Ingest via IPC (avec auto-enregistrement)
        let req_ingest1 = MetricsRequest::new_ingest(b"cpu_load", 1, 1000, 20);
        let resp_ingest1 = daemon.handle_ipc_request(&req_ingest1);
        assert_eq!(resp_ingest1.status, METRICS_STATUS_OK);
        assert_eq!(resp_ingest1.series_count, 1);
        assert_eq!(resp_ingest1.total_samples, 1);

        let req_ingest2 = MetricsRequest::new_ingest(b"cpu_load", 1, 1001, 40);
        let _ = daemon.handle_ipc_request(&req_ingest2);

        // 3. Query via IPC
        let req_query = MetricsRequest::new_query(b"cpu_load", 1);
        let resp_query = daemon.handle_ipc_request(&req_query);
        assert_eq!(resp_query.status, METRICS_STATUS_OK);
        assert_eq!(resp_query.min_val, 20);
        assert_eq!(resp_query.max_val, 40);
        assert_eq!(resp_query.avg_val, 30);
        assert_eq!(resp_query.last_val, 40);
        assert_eq!(resp_query.sample_count, 2);

        // 4. Alert rule et triggering
        daemon
            .register_alert(b"cpu_load", AlertCondition::GreaterThan, 50)
            .unwrap();
        let req_ingest3 = MetricsRequest::new_ingest(b"cpu_load", 1, 1002, 85);
        let resp_ingest3 = daemon.handle_ipc_request(&req_ingest3);
        assert_eq!(resp_ingest3.alert_triggered, 1);
        assert_eq!(resp_ingest3.active_alerts, 1);

        // 5. GetAlerts
        let req_alerts = MetricsRequest::new(MetricsOpcode::GetAlerts);
        let resp_alerts = daemon.handle_ipc_request(&req_alerts);
        assert_eq!(resp_alerts.status, METRICS_STATUS_OK);
        assert_eq!(resp_alerts.active_alerts, 1);
    }
}

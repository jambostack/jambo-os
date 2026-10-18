//! Moteur de Métriques Distribuées & Surveillance en Séries Temporelles (`jambo-metricsd`)
//!
//! Fournit un système de télémétrie et d'observabilité quantitative en temps réel pour le cluster JamboOS.
//! Collecte les séries temporelles dans des tampons annulaires déterministes, évalue les règles
//! d'alerte à seuil et protège l'accès sans autorité ambiante via la capacité `MetricsCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_SERIES: usize = 32;
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

/// Série temporelle circulaire bornée en espace mémoire.
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
            if s.allocated && s.name == name_buf && s.node_id == node_id {
                let slot = s.head;
                s.samples[slot] = MetricSample { timestamp, value };
                s.head = (s.head + 1) % RING_CAPACITY;
                if s.count < RING_CAPACITY {
                    s.count += 1;
                }

                if value < s.min_val {
                    s.min_val = value;
                }
                if value > s.max_val {
                    s.max_val = value;
                }
                s.sum_val = s.sum_val.saturating_add(value);
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
            if s.allocated && s.name == name_buf && s.node_id == node_id {
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
        if name.len() > 32 {
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
}

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
}

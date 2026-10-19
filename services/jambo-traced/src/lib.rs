//! Traçage Distribué, Propagation de Contexte & Analyse de Latence (`jambo-traced`)
//!
//! Fournit un moteur de portées d'exécution (*spans*), la propagation causale de contexte de traces,
//! le calcul déterministe de latence et le diagnostic d'arborescences de requêtes en `#![no_std]`.
//! L'accès et l'instrumentation sont strictement régis par la capacité `TraceCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_ACTIVE_SPANS: usize = 32;
pub const MAX_RECORDED_SPANS: usize = 64;
pub const MAX_SPAN_NAME_LEN: usize = 32;

/// Droits de capacité pour le sous-système de traçage distribué.
pub mod trace_rights {
    pub const TRACE_RECORD: u32 = 0x01;
    pub const TRACE_QUERY: u32 = 0x02;
    pub const TRACE_INJECT: u32 = 0x04;
    pub const TRACE_EXTRACT: u32 = 0x08;
    pub const TRACE_ADMIN: u32 = 0x80;
    pub const ALL: u32 = TRACE_RECORD | TRACE_QUERY | TRACE_INJECT | TRACE_EXTRACT | TRACE_ADMIN;
}

/// Drapeaux de contexte de trace.
pub mod trace_flags {
    pub const FLAG_SAMPLED: u8 = 0x01;
    pub const FLAG_DEBUG: u8 = 0x02;
}

/// Jeton de capacité pour le moteur de traçage distribué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceCap {
    pub handle: Handle,
    pub rights: u32,
}

impl TraceCap {
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

/// Statut d'achèvement d'une portée de trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanStatus {
    Active,
    Ok,
    Error,
    TimedOut,
}

/// Contexte de propagation causale de trace (W3C Trace Context compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: u64,
    pub parent_span_id: Option<u64>,
    pub flags: u8,
}

impl TraceContext {
    pub const fn new(
        trace_id: [u8; 16],
        span_id: u64,
        parent_span_id: Option<u64>,
        flags: u8,
    ) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id,
            flags,
        }
    }

    pub const fn is_sampled(&self) -> bool {
        (self.flags & trace_flags::FLAG_SAMPLED) != 0
    }

    /// Dérive un contexte enfant pour la propagation dans une sous-opération.
    pub const fn create_child(&self, next_span_id: u64) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id: next_span_id,
            parent_span_id: Some(self.span_id),
            flags: self.flags,
        }
    }

    /// Sérialise le contexte dans un tampon compact de 33 octets pour injection IPC / réseau.
    /// Format : [16 octets trace_id] [8 octets span_id BE] [8 octets parent_span_id BE (0 si None)] [1 octet flags]
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut buf = [0u8; 33];
        buf[0..16].copy_from_slice(&self.trace_id);
        buf[16..24].copy_from_slice(&self.span_id.to_be_bytes());
        let parent_raw = self.parent_span_id.unwrap_or(0);
        buf[24..32].copy_from_slice(&parent_raw.to_be_bytes());
        buf[32] = self.flags;
        buf
    }

    /// Désérialise un contexte de trace à partir d'un tampon compact de 33 octets.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SysError> {
        if bytes.len() < 33 {
            return Err(SysError::InvalidArgument);
        }
        let mut trace_id = [0u8; 16];
        trace_id.copy_from_slice(&bytes[0..16]);

        let mut span_bytes = [0u8; 8];
        span_bytes.copy_from_slice(&bytes[16..24]);
        let span_id = u64::from_be_bytes(span_bytes);

        let mut parent_bytes = [0u8; 8];
        parent_bytes.copy_from_slice(&bytes[24..32]);
        let parent_val = u64::from_be_bytes(parent_bytes);
        let parent_span_id = if parent_val != 0 {
            Some(parent_val)
        } else {
            None
        };

        let flags = bytes[32];

        Ok(Self {
            trace_id,
            span_id,
            parent_span_id,
            flags,
        })
    }
}

/// Portée d'exécution individuelle d'une opération système ou réseau.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceSpan {
    pub span_id: u64,
    pub trace_id: [u8; 16],
    pub parent_span_id: Option<u64>,
    pub name: [u8; MAX_SPAN_NAME_LEN],
    pub name_len: usize,
    pub start_time: u64,
    pub end_time: u64,
    pub status: SpanStatus,
}

impl TraceSpan {
    /// Calcule la durée de la portée en nanosecondes ou ticks d'horloge.
    pub fn duration(&self) -> Option<u64> {
        if self.status == SpanStatus::Active {
            None
        } else {
            Some(self.end_time.saturating_sub(self.start_time))
        }
    }
}

/// Collecteur de traçage distribué en mémoire bornée.
pub struct TraceCollector {
    active_spans: [Option<TraceSpan>; MAX_ACTIVE_SPANS],
    recorded_spans: [Option<TraceSpan>; MAX_RECORDED_SPANS],
    recorded_head: usize,
    total_recorded: u64,
    next_span_id: u64,
}

impl TraceCollector {
    pub const fn new() -> Self {
        Self {
            active_spans: [None; MAX_ACTIVE_SPANS],
            recorded_spans: [None; MAX_RECORDED_SPANS],
            recorded_head: 0,
            total_recorded: 0,
            next_span_id: 1,
        }
    }

    /// Démarre une nouvelle portée de trace et alloue un identifiant unique.
    pub fn start_span(
        &mut self,
        cap: &TraceCap,
        name: &[u8],
        context: &TraceContext,
        start_time: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(trace_rights::TRACE_RECORD) {
            return Err(SysError::PermissionDenied);
        }
        if name.is_empty() || name.len() > MAX_SPAN_NAME_LEN {
            return Err(SysError::InvalidArgument);
        }

        // Recherche d'un slot disponible parmi les portées actives
        for slot in self.active_spans.iter_mut() {
            if slot.is_none() {
                let span_id = context.span_id;
                let mut name_buf = [0u8; MAX_SPAN_NAME_LEN];
                name_buf[..name.len()].copy_from_slice(name);

                *slot = Some(TraceSpan {
                    span_id,
                    trace_id: context.trace_id,
                    parent_span_id: context.parent_span_id,
                    name: name_buf,
                    name_len: name.len(),
                    start_time,
                    end_time: 0,
                    status: SpanStatus::Active,
                });

                return Ok(span_id);
            }
        }

        Err(SysError::ResourceBusy)
    }

    /// Clôture une portée active et la stocke dans le tampon annulaire des portées enregistrées.
    pub fn finish_span(
        &mut self,
        cap: &TraceCap,
        span_id: u64,
        status: SpanStatus,
        end_time: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(trace_rights::TRACE_RECORD) {
            return Err(SysError::PermissionDenied);
        }
        if status == SpanStatus::Active {
            return Err(SysError::InvalidArgument);
        }

        // Trouver la portée active
        let mut finished_span = None;
        for slot in self.active_spans.iter_mut() {
            if let Some(s) = slot {
                if s.span_id == span_id {
                    let mut completed = *s;
                    completed.status = status;
                    completed.end_time = end_time;
                    finished_span = Some(completed);
                    *slot = None;
                    break;
                }
            }
        }

        let span = finished_span.ok_or(SysError::InvalidHandle)?;

        // Écriture dans le ring buffer borné
        self.recorded_spans[self.recorded_head] = Some(span);
        self.recorded_head = (self.recorded_head + 1) % MAX_RECORDED_SPANS;
        self.total_recorded = self.total_recorded.saturating_add(1);

        Ok(())
    }

    /// Recherche une portée archivée par son identifiant.
    pub fn find_recorded(
        &self,
        cap: &TraceCap,
        span_id: u64,
    ) -> Result<Option<TraceSpan>, SysError> {
        if !cap.has_right(trace_rights::TRACE_QUERY) {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.recorded_spans.iter().flatten() {
            if slot.span_id == span_id {
                return Ok(Some(*slot));
            }
        }
        Ok(None)
    }

    /// Récupère toutes les portées appartenant à une même trace_id (arborescence).
    pub fn query_by_trace(
        &self,
        cap: &TraceCap,
        trace_id: &[u8; 16],
        out_spans: &mut [TraceSpan],
    ) -> Result<usize, SysError> {
        if !cap.has_right(trace_rights::TRACE_QUERY) {
            return Err(SysError::PermissionDenied);
        }

        let mut count = 0;
        for slot in self.recorded_spans.iter().flatten() {
            if &slot.trace_id == trace_id {
                if count < out_spans.len() {
                    out_spans[count] = *slot;
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Génère un nouvel identifiant séquentiel de portée.
    pub fn allocate_span_id(&mut self) -> u64 {
        let id = self.next_span_id;
        self.next_span_id = self.next_span_id.wrapping_add(1);
        if self.next_span_id == 0 {
            self.next_span_id = 1;
        }
        id
    }

    /// Nombre de portées en cours d'exécution.
    pub fn active_count(&self) -> usize {
        self.active_spans.iter().filter(|s| s.is_some()).count()
    }

    /// Total cumulé des portées archivées.
    pub fn total_recorded(&self) -> u64 {
        self.total_recorded
    }
}

/// Démon orchestrateur de traçage distribué et analyse de latence (`jambo-traced`).
pub struct JamboTraceDaemon {
    pub collector: TraceCollector,
    pub cap: TraceCap,
    pub operations_count: u64,
}

impl Default for JamboTraceDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboTraceDaemon {
    pub fn new() -> Self {
        let cap = TraceCap::new(Handle::new(7001, 1), trace_rights::ALL);
        let mut collector = TraceCollector::new();

        // Trace initiale d'amorçage
        let trace_id = [0x70; 16];
        let span_id = collector.allocate_span_id();
        let ctx = TraceContext::new(trace_id, span_id, None, trace_flags::FLAG_SAMPLED);
        let _ = collector.start_span(&cap, b"boot.bootstrap", &ctx, 100);
        let _ = collector.finish_span(&cap, span_id, SpanStatus::Ok, 150);

        Self {
            collector,
            cap,
            operations_count: 1,
        }
    }

    pub fn start_span(
        &mut self,
        name: &[u8],
        context: &TraceContext,
        start_time: u64,
    ) -> Result<u64, SysError> {
        let span_id = self
            .collector
            .start_span(&self.cap, name, context, start_time)?;
        self.operations_count = self.operations_count.saturating_add(1);
        Ok(span_id)
    }

    pub fn finish_span(
        &mut self,
        span_id: u64,
        status: SpanStatus,
        end_time: u64,
    ) -> Result<(), SysError> {
        self.collector
            .finish_span(&self.cap, span_id, status, end_time)?;
        self.operations_count = self.operations_count.saturating_add(1);
        Ok(())
    }

    pub fn allocate_span_id(&mut self) -> u64 {
        self.collector.allocate_span_id()
    }

    pub fn find_recorded(&self, span_id: u64) -> Result<Option<TraceSpan>, SysError> {
        self.collector.find_recorded(&self.cap, span_id)
    }

    pub fn query_by_trace(
        &self,
        trace_id: &[u8; 16],
        out_spans: &mut [TraceSpan],
    ) -> Result<usize, SysError> {
        self.collector
            .query_by_trace(&self.cap, trace_id, out_spans)
    }

    pub fn active_count(&self) -> usize {
        self.collector.active_count()
    }

    pub fn total_recorded(&self) -> u64 {
        self.collector.total_recorded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_propagation_and_serialization() {
        let trace_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let root_ctx = TraceContext::new(trace_id, 1001, None, trace_flags::FLAG_SAMPLED);

        assert!(root_ctx.is_sampled());
        assert_eq!(root_ctx.parent_span_id, None);

        let child_ctx = root_ctx.create_child(1002);
        assert_eq!(child_ctx.trace_id, trace_id);
        assert_eq!(child_ctx.span_id, 1002);
        assert_eq!(child_ctx.parent_span_id, Some(1001));
        assert!(child_ctx.is_sampled());

        let bytes = child_ctx.to_bytes();
        let decoded = TraceContext::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, child_ctx);
    }

    #[test]
    fn test_span_lifecycle_and_duration() {
        let cap = TraceCap::new(Handle::new(1, 1), trace_rights::ALL);
        let mut collector = TraceCollector::new();

        let trace_id = [0xAA; 16];
        let span_id = collector.allocate_span_id();
        let ctx = TraceContext::new(trace_id, span_id, None, trace_flags::FLAG_SAMPLED);

        // Début de portée à t = 1000
        collector
            .start_span(&cap, b"http.ingress.request", &ctx, 1000)
            .unwrap();
        assert_eq!(collector.active_count(), 1);

        // Clôture de portée à t = 1250
        collector
            .finish_span(&cap, span_id, SpanStatus::Ok, 1250)
            .unwrap();
        assert_eq!(collector.active_count(), 0);
        assert_eq!(collector.total_recorded(), 1);

        let span = collector.find_recorded(&cap, span_id).unwrap().unwrap();
        assert_eq!(span.span_id, span_id);
        assert_eq!(span.status, SpanStatus::Ok);
        assert_eq!(span.duration(), Some(250));
    }

    #[test]
    fn test_query_by_trace_id() {
        let cap = TraceCap::new(Handle::new(1, 1), trace_rights::ALL);
        let mut collector = TraceCollector::new();

        let trace_1 = [0x11; 16];
        let trace_2 = [0x22; 16];

        let id1 = collector.allocate_span_id();
        let id2 = collector.allocate_span_id();
        let id3 = collector.allocate_span_id();

        let ctx1 = TraceContext::new(trace_1, id1, None, trace_flags::FLAG_SAMPLED);
        let ctx2 = ctx1.create_child(id2);
        let ctx3 = TraceContext::new(trace_2, id3, None, trace_flags::FLAG_SAMPLED);

        collector.start_span(&cap, b"op1", &ctx1, 100).unwrap();
        collector.start_span(&cap, b"op2", &ctx2, 110).unwrap();
        collector.start_span(&cap, b"op3", &ctx3, 120).unwrap();

        collector
            .finish_span(&cap, id1, SpanStatus::Ok, 200)
            .unwrap();
        collector
            .finish_span(&cap, id2, SpanStatus::Ok, 190)
            .unwrap();
        collector
            .finish_span(&cap, id3, SpanStatus::Ok, 150)
            .unwrap();

        let mut spans_out = [TraceSpan {
            span_id: 0,
            trace_id: [0; 16],
            parent_span_id: None,
            name: [0; MAX_SPAN_NAME_LEN],
            name_len: 0,
            start_time: 0,
            end_time: 0,
            status: SpanStatus::Active,
        }; 4];

        let found = collector
            .query_by_trace(&cap, &trace_1, &mut spans_out)
            .unwrap();
        assert_eq!(found, 2);
    }

    #[test]
    fn test_buffer_overflow_and_ring_eviction() {
        let cap = TraceCap::new(Handle::new(1, 1), trace_rights::ALL);
        let mut collector = TraceCollector::new();

        // Remplir au-delà de MAX_RECORDED_SPANS (64)
        for i in 0..70 {
            let id = collector.allocate_span_id();
            let ctx = TraceContext::new([i as u8; 16], id, None, trace_flags::FLAG_SAMPLED);
            collector.start_span(&cap, b"stress", &ctx, 100).unwrap();
            collector
                .finish_span(&cap, id, SpanStatus::Ok, 200)
                .unwrap();
        }

        assert_eq!(collector.total_recorded(), 70);
    }

    #[test]
    fn test_trace_cap_attenuation() {
        let cap_full = TraceCap::new(Handle::new(1, 1), trace_rights::ALL);
        let cap_query_only = cap_full.attenuate(trace_rights::TRACE_QUERY).unwrap();

        let mut collector = TraceCollector::new();
        let ctx = TraceContext::new([1; 16], 1, None, trace_flags::FLAG_SAMPLED);

        // Tentative d'enregistrement avec cap_query_only -> PermissionDenied
        assert_eq!(
            collector.start_span(&cap_query_only, b"test", &ctx, 100),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_trace_daemon() {
        let mut daemon = JamboTraceDaemon::new();
        assert_eq!(daemon.total_recorded(), 1);
        assert_eq!(daemon.active_count(), 0);

        let trace_id = [0x42; 16];
        let span_id = daemon.allocate_span_id();
        let ctx = TraceContext::new(trace_id, span_id, None, trace_flags::FLAG_SAMPLED);

        daemon.start_span(b"fs.read_block", &ctx, 200).unwrap();
        assert_eq!(daemon.active_count(), 1);

        daemon.finish_span(span_id, SpanStatus::Ok, 280).unwrap();
        assert_eq!(daemon.active_count(), 0);
        assert_eq!(daemon.total_recorded(), 2);

        let span = daemon.find_recorded(span_id).unwrap().unwrap();
        assert_eq!(span.span_id, span_id);
        assert_eq!(span.duration(), Some(80));

        let mut spans = [TraceSpan {
            span_id: 0,
            trace_id: [0; 16],
            parent_span_id: None,
            name: [0; MAX_SPAN_NAME_LEN],
            name_len: 0,
            start_time: 0,
            end_time: 0,
            status: SpanStatus::Active,
        }; 2];
        let n = daemon.query_by_trace(&trace_id, &mut spans).unwrap();
        assert_eq!(n, 1);
    }
}

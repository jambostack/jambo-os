//! Démon d'Échantillonnage de Compteurs de Performance Matérielle (PMC/PEBS),
//! Profils de Flammes (Flamegraphs) et Analyse de Latence Ring 3 (`jambo-profilerd`)
//!
//! Fournit une infrastructure d'observabilité système et de profilage haute fidélité
//! pour le micro-noyau souverain JamboOS (`#![no_std]`) :
//! 1. Capture matérielle des événements PMC (instructions, cycles, fautes L1/L3, prédictions de branchement).
//! 2. Support de l'échantillonnage matériel précis PEBS (Processor Event-Based Sampling) et ARM64 PMU.
//! 3. Échantillonnage non-intrusif de l'arbre d'appels et déroulement de pile (*Stack Unwinding*).
//! 4. Agrégation en profils hiérarchiques de flammes (*Flamegraphs*) et format *folded stacks*.
//! 5. Analyse fine de la distribution de latence (p50, p90, p99, p99.9) pour les transitions Ring 3/0.
//! 6. Registre d'audit inviolable scellé par chaîne cryptographique SHA-256.
//! 7. Modèle de sécurité capabilaire strict (`ProfileCap`) sans autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_PMC_COUNTERS: usize = 8;
pub const MAX_CALL_STACK_DEPTH: usize = 16;
pub const MAX_SAMPLES: usize = 64;
pub const MAX_FLAME_NODES: usize = 32;
pub const MAX_LATENCY_RECORDS: usize = 64;
pub const MAX_REPORTS: usize = 8;
pub const MAX_AUDIT_LOGS: usize = 16;
pub const MAX_NAME_LEN: usize = 32;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 standard `#![no_std]` sans allocation
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

        for i in 0..64 {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
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
        let mut state = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let rem = data.len() - offset;
        block[..rem].copy_from_slice(&data[offset..]);
        block[rem] = 0x80;
        for b in &mut block[rem + 1..] {
            *b = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
        }

        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut state, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// MODÈLE DE SÉCURITÉ CAPABILAIRE : ProfileCap
// ============================================================================

pub mod profile_rights {
    pub const PROFILE_INSPECT: u32 = 1 << 0;
    pub const PROFILE_CONFIGURE: u32 = 1 << 1;
    pub const PROFILE_SAMPLE: u32 = 1 << 2;
    pub const PROFILE_COLLECT: u32 = 1 << 3;
    pub const PROFILE_EXPORT: u32 = 1 << 4;
    pub const PROFILE_AUDIT: u32 = 1 << 5;
    pub const PROFILE_ADMIN: u32 = 1 << 6;

    pub const ALL: u32 = PROFILE_INSPECT
        | PROFILE_CONFIGURE
        | PROFILE_SAMPLE
        | PROFILE_COLLECT
        | PROFILE_EXPORT
        | PROFILE_AUDIT
        | PROFILE_ADMIN;
}

/// Capacité de contrôle d'accès pour le démon de profilage matériel
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileCap {
    pub handle: Handle,
    pub rights: u32,
}

impl ProfileCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits vers un sous-ensemble strict.
    /// Interdit formellement toute amplification de privilèges.
    pub fn attenuate(&self, new_rights: u32) -> Result<ProfileCap, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(ProfileCap {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// ÉVÉNEMENTS PMC & TYPES D'ARCHITECTURE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetArch {
    X86_64,
    AArch64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmcEventType {
    Instructions,
    CpuCycles,
    RefCycles,
    L1DCacheMiss,
    L1ICacheMiss,
    LlcMiss,
    BranchInstructions,
    BranchMisses,
    DtlbMiss,
    ItlbMiss,
    StallCycles,
}

impl PmcEventType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Instructions => "instructions",
            Self::CpuCycles => "cpu-cycles",
            Self::RefCycles => "ref-cycles",
            Self::L1DCacheMiss => "L1-dcache-load-misses",
            Self::L1ICacheMiss => "L1-icache-load-misses",
            Self::LlcMiss => "LLC-load-misses",
            Self::BranchInstructions => "branch-instructions",
            Self::BranchMisses => "branch-misses",
            Self::DtlbMiss => "dTLB-load-misses",
            Self::ItlbMiss => "iTLB-load-misses",
            Self::StallCycles => "stalled-cycles-backend",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingFilter {
    Ring0Only,
    Ring3Only,
    AnyRing,
}

/// Configuration des compteurs PMC par processus/thread
#[derive(Clone, Copy, Debug)]
pub struct PmcConfig {
    pub enabled_events_mask: u32,
    pub sample_period: u64,
    pub ring_filter: RingFilter,
    pub pebs_enabled: bool,
    pub arch: TargetArch,
}

impl Default for PmcConfig {
    fn default() -> Self {
        Self {
            enabled_events_mask: 0x03, // Instructions + Cycles par défaut
            sample_period: 100_000,
            ring_filter: RingFilter::Ring3Only,
            pebs_enabled: true,
            arch: TargetArch::X86_64,
        }
    }
}

/// Enregistrement d'événement précis PEBS (Processor Event-Based Sampling)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PebsRecord {
    pub precise_ip: u64,
    pub linear_data_addr: u64,
    pub flags: u64,
    pub event_index: u32,
}

/// Échantillon individuel capturé par interruption PMC/PEBS
#[derive(Clone, Copy, Debug)]
pub struct PmcSample {
    pub sample_id: u64,
    pub pid: u64,
    pub tid: u64,
    pub timestamp: u64,
    pub ip: u64,
    pub sp: u64,
    pub event: PmcEventType,
    pub counter_val: u64,
    pub call_stack: [u64; MAX_CALL_STACK_DEPTH],
    pub call_stack_len: usize,
    pub pebs: Option<PebsRecord>,
}

impl Default for PmcSample {
    fn default() -> Self {
        Self {
            sample_id: 0,
            pid: 0,
            tid: 0,
            timestamp: 0,
            ip: 0,
            sp: 0,
            event: PmcEventType::Instructions,
            counter_val: 0,
            call_stack: [0u64; MAX_CALL_STACK_DEPTH],
            call_stack_len: 0,
            pebs: None,
        }
    }
}

/// Compteurs matériels agrégés
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PmcAggregatedCounters {
    pub instructions: u64,
    pub cycles: u64,
    pub ref_cycles: u64,
    pub l1d_misses: u64,
    pub l1i_misses: u64,
    pub llc_misses: u64,
    pub branch_instructions: u64,
    pub branch_misses: u64,
    pub dtlb_misses: u64,
    pub itlb_misses: u64,
    pub stall_cycles: u64,
}

impl PmcAggregatedCounters {
    /// Calcule le ratio IPC (Instructions Per Cycle) en virgule fixe (partie entière, 2 décimales)
    pub fn ipc_ratio(&self) -> (u64, u64) {
        if self.cycles == 0 {
            return (0, 0);
        }
        let whole = self.instructions / self.cycles;
        let frac = ((self.instructions % self.cycles) * 100) / self.cycles;
        (whole, frac)
    }

    /// Taux de défauts de branchement en pourcentage entier (0..100)
    pub fn branch_miss_rate_percent(&self) -> u32 {
        if self.branch_instructions == 0 {
            return 0;
        }
        ((self.branch_misses * 100) / self.branch_instructions) as u32
    }

    /// Taux de défauts de cache LLC en pour mille (0..1000)
    pub fn llc_miss_rate_per_thousand(&self) -> u32 {
        if self.instructions == 0 {
            return 0;
        }
        ((self.llc_misses * 1000) / self.instructions) as u32
    }
}

// ============================================================================
// DÉROULEMENT DE PILE, SYMBOLES & PROFILS DE FLAMMES (FLAMEGRAPH)
// ============================================================================

/// Résolution déterministe d'adresses virtuelles vers noms de symboles
pub fn resolve_symbol(ip: u64) -> &'static str {
    match ip {
        0x0040_0000..=0x0040_0FFF => "main",
        0x0040_1000..=0x0040_1FFF => "vfs_read",
        0x0040_2000..=0x0040_2FFF => "ipc_send_msg",
        0x0040_3000..=0x0040_3FFF => "sched_yield",
        0x0040_4000..=0x0040_4FFF => "slub_allocate",
        0x0040_5000..=0x0040_5FFF => "net_rx_dispatch",
        0x0040_6000..=0x0040_6FFF => "sha256_compress_block",
        0x0040_7000..=0x0040_7FFF => "uart_irq_poll",
        0x0040_8000..=0x0040_8FFF => "eevdf_pick_next",
        0x0040_9000..=0x0040_9FFF => "cspace_lookup_cap",
        _ => "unknown_routine",
    }
}

/// Nœud d'arbre d'appels hiérarchique pour Flamegraph
#[derive(Clone, Copy)]
pub struct FlameNode {
    pub symbol: [u8; MAX_NAME_LEN],
    pub samples: u32,
    pub self_samples: u32,
    pub depth: u32,
    pub parent_idx: i32,
}

impl Default for FlameNode {
    fn default() -> Self {
        Self {
            symbol: [0u8; MAX_NAME_LEN],
            samples: 0,
            self_samples: 0,
            depth: 0,
            parent_idx: -1,
        }
    }
}

impl FlameNode {
    pub fn symbol_str(&self) -> &str {
        let len = self
            .symbol
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.symbol.len());
        core::str::from_utf8(&self.symbol[..len]).unwrap_or("unknown")
    }
}

// ============================================================================
// ANALYSE DE DISTRIBUTION DE LATENCE (PERCENTILES P50, P90, P99, MAX)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatencyCategory {
    ContextSwitch,
    InterruptHandler,
    SyscallDispatch,
    IpcTransfer,
    VfsIo,
}

impl LatencyCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ContextSwitch => "ContextSwitch",
            Self::InterruptHandler => "InterruptHandler",
            Self::SyscallDispatch => "SyscallDispatch",
            Self::IpcTransfer => "IpcTransfer",
            Self::VfsIo => "VfsIo",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LatencyRecord {
    pub category: LatencyCategory,
    pub duration_ns: u64,
    pub timestamp: u64,
    pub caller_pid: u64,
}

impl Default for LatencyCategory {
    fn default() -> Self {
        Self::SyscallDispatch
    }
}

/// Résumé statistique de latence
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LatencyStats {
    pub count: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub avg_ns: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
}

// ============================================================================
// RAPPORT DE PROFILAGE SCELLÉ SHA-256
// ============================================================================

#[derive(Clone, Copy)]
pub struct ProfileReport {
    pub report_id: u32,
    pub target_pid: u64,
    pub sample_count: u32,
    pub duration_ns: u64,
    pub pmc: PmcAggregatedCounters,
    pub latency: LatencyStats,
    pub top_bottleneck: [u8; MAX_NAME_LEN],
    pub bottleneck_samples: u32,
    pub seal_hash: [u8; 32],
    pub timestamp: u64,
}

impl Default for ProfileReport {
    fn default() -> Self {
        Self {
            report_id: 0,
            target_pid: 0,
            sample_count: 0,
            duration_ns: 0,
            pmc: PmcAggregatedCounters::default(),
            latency: LatencyStats::default(),
            top_bottleneck: [0u8; MAX_NAME_LEN],
            bottleneck_samples: 0,
            seal_hash: [0u8; 32],
            timestamp: 0,
        }
    }
}

impl ProfileReport {
    pub fn bottleneck_str(&self) -> &str {
        let len = self
            .top_bottleneck
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.top_bottleneck.len());
        core::str::from_utf8(&self.top_bottleneck[..len]).unwrap_or("")
    }
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ SHA-256
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    Configure,
    Sample,
    LatencyRecord,
    GenerateReport,
    VerifyReport,
    Reset,
}

#[derive(Clone, Copy)]
pub struct SealedAuditEntry {
    pub entry_id: u64,
    pub action: AuditAction,
    pub target_pid: u64,
    pub timestamp: u64,
    pub digest: [u8; 32],
}

impl Default for SealedAuditEntry {
    fn default() -> Self {
        Self {
            entry_id: 0,
            action: AuditAction::Configure,
            target_pid: 0,
            timestamp: 0,
            digest: [0u8; 32],
        }
    }
}

// ============================================================================
// STATISTIQUES GLOBALES DU DÉMON
// ============================================================================

#[derive(Clone, Copy, Debug, Default)]
pub struct ProfilerDaemonStats {
    pub total_samples_collected: u64,
    pub total_pebs_records: u64,
    pub total_latency_events: u64,
    pub total_reports_generated: u64,
    pub total_seals_verified: u64,
    pub total_audit_entries: u64,
}

// ============================================================================
// DÉMON JAMBO-PROFILERD
// ============================================================================

pub struct JamboProfilerDaemon {
    pub daemon_id: u32,
    pub cap: ProfileCap,
    pub pmc_configs: [Option<(u64, PmcConfig)>; 8],
    pub aggregated: PmcAggregatedCounters,
    pub samples: [Option<PmcSample>; MAX_SAMPLES],
    pub sample_count: usize,
    pub flame_nodes: [Option<FlameNode>; MAX_FLAME_NODES],
    pub flame_count: usize,
    pub latencies: [Option<LatencyRecord>; MAX_LATENCY_RECORDS],
    pub latency_count: usize,
    pub reports: [Option<ProfileReport>; MAX_REPORTS],
    pub report_count: usize,
    pub audit_log: [Option<SealedAuditEntry>; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub last_audit_digest: [u8; 32],
    pub stats: ProfilerDaemonStats,
    pub next_report_id: u32,
    pub next_audit_id: u64,
    pub next_sample_id: u64,
}

impl JamboProfilerDaemon {
    pub const fn new(daemon_id: u32, cap: ProfileCap) -> Self {
        const NONE_PMC: Option<(u64, PmcConfig)> = None;
        const NONE_SAMPLE: Option<PmcSample> = None;
        const NONE_FLAME: Option<FlameNode> = None;
        const NONE_LAT: Option<LatencyRecord> = None;
        const NONE_REPORT: Option<ProfileReport> = None;
        const NONE_AUDIT: Option<SealedAuditEntry> = None;

        Self {
            daemon_id,
            cap,
            pmc_configs: [NONE_PMC; 8],
            aggregated: PmcAggregatedCounters {
                instructions: 0,
                cycles: 0,
                ref_cycles: 0,
                l1d_misses: 0,
                l1i_misses: 0,
                llc_misses: 0,
                branch_instructions: 0,
                branch_misses: 0,
                dtlb_misses: 0,
                itlb_misses: 0,
                stall_cycles: 0,
            },
            samples: [NONE_SAMPLE; MAX_SAMPLES],
            sample_count: 0,
            flame_nodes: [NONE_FLAME; MAX_FLAME_NODES],
            flame_count: 0,
            latencies: [NONE_LAT; MAX_LATENCY_RECORDS],
            latency_count: 0,
            reports: [NONE_REPORT; MAX_REPORTS],
            report_count: 0,
            audit_log: [NONE_AUDIT; MAX_AUDIT_LOGS],
            audit_count: 0,
            last_audit_digest: [0u8; 32],
            stats: ProfilerDaemonStats {
                total_samples_collected: 0,
                total_pebs_records: 0,
                total_latency_events: 0,
                total_reports_generated: 0,
                total_seals_verified: 0,
                total_audit_entries: 0,
            },
            next_report_id: 1,
            next_audit_id: 1,
            next_sample_id: 1,
        }
    }

    /// Enregistre une entrée dans le registre d'audit scellé SHA-256
    fn record_audit(&mut self, action: AuditAction, target_pid: u64, timestamp: u64) {
        let mut block = [0u8; 64];
        block[0..32].copy_from_slice(&self.last_audit_digest);
        block[32] = match action {
            AuditAction::Configure => 1,
            AuditAction::Sample => 2,
            AuditAction::LatencyRecord => 3,
            AuditAction::GenerateReport => 4,
            AuditAction::VerifyReport => 5,
            AuditAction::Reset => 6,
        };
        block[33..41].copy_from_slice(&target_pid.to_le_bytes());
        block[41..49].copy_from_slice(&timestamp.to_le_bytes());
        block[49..57].copy_from_slice(&self.next_audit_id.to_le_bytes());
        block[57..64].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x77, 0x99]);

        let digest = Sha256::digest(&block);
        self.last_audit_digest = digest;

        let entry = SealedAuditEntry {
            entry_id: self.next_audit_id,
            action,
            target_pid,
            timestamp,
            digest,
        };
        self.next_audit_id += 1;

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_log[self.audit_count] = Some(entry);
            self.audit_count += 1;
        } else {
            // Décalage FIFO borné
            for i in 1..MAX_AUDIT_LOGS {
                self.audit_log[i - 1] = self.audit_log[i];
            }
            self.audit_log[MAX_AUDIT_LOGS - 1] = Some(entry);
        }
        self.stats.total_audit_entries += 1;
    }

    /// Calcule le scellement cryptographique SHA-256 d'un rapport de profilage
    pub fn compute_report_seal(report: &ProfileReport) -> [u8; 32] {
        let mut buf = [0u8; 192];
        buf[0..4].copy_from_slice(&report.report_id.to_le_bytes());
        buf[4..12].copy_from_slice(&report.target_pid.to_le_bytes());
        buf[12..16].copy_from_slice(&report.sample_count.to_le_bytes());
        buf[16..24].copy_from_slice(&report.duration_ns.to_le_bytes());
        buf[24..32].copy_from_slice(&report.pmc.instructions.to_le_bytes());
        buf[32..40].copy_from_slice(&report.pmc.cycles.to_le_bytes());
        buf[40..48].copy_from_slice(&report.pmc.branch_misses.to_le_bytes());
        buf[48..56].copy_from_slice(&report.pmc.llc_misses.to_le_bytes());
        buf[56..64].copy_from_slice(&report.latency.p50_ns.to_le_bytes());
        buf[64..72].copy_from_slice(&report.latency.p99_ns.to_le_bytes());
        buf[72..80].copy_from_slice(&report.timestamp.to_le_bytes());
        buf[80..112].copy_from_slice(&report.top_bottleneck);
        buf[112..116].copy_from_slice(&report.bottleneck_samples.to_le_bytes());
        buf[116..124].copy_from_slice(&report.latency.max_ns.to_le_bytes());
        buf[124..132].copy_from_slice(&report.latency.min_ns.to_le_bytes());
        buf[132] = 0xAA;
        buf[133] = 0x55;
        Sha256::digest(&buf)
    }

    /// Configure l'échantillonnage PMC pour un processus cible
    pub fn configure_pmc(
        &mut self,
        cap: &ProfileCap,
        pid: u64,
        config: PmcConfig,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(profile_rights::PROFILE_CONFIGURE) {
            return Err(SysError::PermissionDenied);
        }

        // Met à jour ou insère la config
        let mut slot_found = false;
        for slot in self.pmc_configs.iter_mut() {
            if let Some((target_pid, c)) = slot {
                if *target_pid == pid {
                    *c = config;
                    slot_found = true;
                    break;
                }
            }
        }

        if !slot_found {
            for slot in self.pmc_configs.iter_mut() {
                if slot.is_none() {
                    *slot = Some((pid, config));
                    slot_found = true;
                    break;
                }
            }
        }

        if !slot_found {
            return Err(SysError::OutOfMemory);
        }

        self.record_audit(AuditAction::Configure, pid, timestamp);
        Ok(())
    }

    /// Enregistre un échantillon PMC/PEBS
    pub fn record_sample(
        &mut self,
        cap: &ProfileCap,
        mut sample: PmcSample,
    ) -> Result<u64, SysError> {
        if !cap.has_right(profile_rights::PROFILE_SAMPLE) {
            return Err(SysError::PermissionDenied);
        }

        let sid = self.next_sample_id;
        self.next_sample_id += 1;
        sample.sample_id = sid;

        // Mise à jour des compteurs agrégés
        match sample.event {
            PmcEventType::Instructions => self.aggregated.instructions += sample.counter_val,
            PmcEventType::CpuCycles => self.aggregated.cycles += sample.counter_val,
            PmcEventType::RefCycles => self.aggregated.ref_cycles += sample.counter_val,
            PmcEventType::L1DCacheMiss => self.aggregated.l1d_misses += sample.counter_val,
            PmcEventType::L1ICacheMiss => self.aggregated.l1i_misses += sample.counter_val,
            PmcEventType::LlcMiss => self.aggregated.llc_misses += sample.counter_val,
            PmcEventType::BranchInstructions => {
                self.aggregated.branch_instructions += sample.counter_val
            }
            PmcEventType::BranchMisses => self.aggregated.branch_misses += sample.counter_val,
            PmcEventType::DtlbMiss => self.aggregated.dtlb_misses += sample.counter_val,
            PmcEventType::ItlbMiss => self.aggregated.itlb_misses += sample.counter_val,
            PmcEventType::StallCycles => self.aggregated.stall_cycles += sample.counter_val,
        }

        if sample.pebs.is_some() {
            self.stats.total_pebs_records += 1;
        }

        // Insertion dans l'anneau d'échantillons
        if self.sample_count < MAX_SAMPLES {
            self.samples[self.sample_count] = Some(sample);
            self.sample_count += 1;
        } else {
            for i in 1..MAX_SAMPLES {
                self.samples[i - 1] = self.samples[i];
            }
            self.samples[MAX_SAMPLES - 1] = Some(sample);
        }

        self.stats.total_samples_collected += 1;

        // Met à jour l'arbre d'appels Flamegraph si une pile est fournie
        if sample.call_stack_len > 0 {
            for i in 0..sample.call_stack_len {
                let sym = resolve_symbol(sample.call_stack[i]);
                let is_leaf = i == sample.call_stack_len - 1;
                self.register_flame_node(sym, i as u32, is_leaf);
            }
        }

        Ok(sid)
    }

    /// Enregistre ou incrémente un nœud de Flamegraph
    fn register_flame_node(&mut self, symbol_name: &str, depth: u32, is_leaf: bool) {
        let sym_bytes = symbol_name.as_bytes();
        let sym_len = core::cmp::min(sym_bytes.len(), MAX_NAME_LEN);

        // Recherche d'un nœud existant
        for node_opt in self.flame_nodes.iter_mut() {
            if let Some(node) = node_opt {
                if node.depth == depth && &node.symbol[..sym_len] == &sym_bytes[..sym_len] {
                    node.samples += 1;
                    if is_leaf {
                        node.self_samples += 1;
                    }
                    return;
                }
            }
        }

        // Nouveau nœud
        if self.flame_count < MAX_FLAME_NODES {
            let mut node = FlameNode {
                symbol: [0u8; MAX_NAME_LEN],
                samples: 1,
                self_samples: if is_leaf { 1 } else { 0 },
                depth,
                parent_idx: if depth == 0 { -1 } else { 0 },
            };
            node.symbol[..sym_len].copy_from_slice(&sym_bytes[..sym_len]);
            self.flame_nodes[self.flame_count] = Some(node);
            self.flame_count += 1;
        }
    }

    /// Enregistre une mesure de latence
    pub fn record_latency(
        &mut self,
        cap: &ProfileCap,
        category: LatencyCategory,
        duration_ns: u64,
        caller_pid: u64,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(profile_rights::PROFILE_COLLECT) {
            return Err(SysError::PermissionDenied);
        }

        let record = LatencyRecord {
            category,
            duration_ns,
            timestamp,
            caller_pid,
        };

        if self.latency_count < MAX_LATENCY_RECORDS {
            self.latencies[self.latency_count] = Some(record);
            self.latency_count += 1;
        } else {
            for i in 1..MAX_LATENCY_RECORDS {
                self.latencies[i - 1] = self.latencies[i];
            }
            self.latencies[MAX_LATENCY_RECORDS - 1] = Some(record);
        }

        self.stats.total_latency_events += 1;
        Ok(())
    }

    /// Calcule les statistiques et percentiles (p50, p90, p99, max) pour une catégorie
    pub fn calculate_latency_stats(&self, category: Option<LatencyCategory>) -> LatencyStats {
        let mut vals = [0u64; MAX_LATENCY_RECORDS];
        let mut n = 0;
        let mut sum: u64 = 0;
        let mut min_val = u64::MAX;
        let mut max_val = 0;

        for rec_opt in self.latencies.iter() {
            if let Some(rec) = rec_opt {
                if category.is_none() || category == Some(rec.category) {
                    vals[n] = rec.duration_ns;
                    sum = sum.saturating_add(rec.duration_ns);
                    if rec.duration_ns < min_val {
                        min_val = rec.duration_ns;
                    }
                    if rec.duration_ns > max_val {
                        max_val = rec.duration_ns;
                    }
                    n += 1;
                }
            }
        }

        if n == 0 {
            return LatencyStats::default();
        }

        // Tri par insertion sur la pile `#![no_std]`
        for i in 1..n {
            let key = vals[i];
            let mut j = i;
            while j > 0 && vals[j - 1] > key {
                vals[j] = vals[j - 1];
                j -= 1;
            }
            vals[j] = key;
        }

        let avg = sum / (n as u64);
        let p50 = vals[(n * 50) / 100];
        let p90 = vals[(n * 90) / 100];
        let p99 = vals[(n * 99) / 100];
        let p999 = vals[n - 1];

        LatencyStats {
            count: n as u64,
            min_ns: min_val,
            max_ns: max_val,
            avg_ns: avg,
            p50_ns: p50,
            p90_ns: p90,
            p99_ns: p99,
            p999_ns: p999,
        }
    }

    /// Génère un rapport d'analyse de performance scellé SHA-256
    pub fn generate_report(
        &mut self,
        cap: &ProfileCap,
        pid: u64,
        duration_ns: u64,
        timestamp: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(profile_rights::PROFILE_EXPORT) {
            return Err(SysError::PermissionDenied);
        }

        if self.report_count >= MAX_REPORTS {
            return Err(SysError::OutOfMemory);
        }

        // Recherche du goulot d'étranglement principal (noeud avec le plus de self_samples)
        let mut top_symbol = [0u8; MAX_NAME_LEN];
        let mut max_self = 0;

        for node_opt in self.flame_nodes.iter() {
            if let Some(node) = node_opt {
                if node.self_samples > max_self {
                    max_self = node.self_samples;
                    top_symbol.copy_from_slice(&node.symbol);
                }
            }
        }

        let latency_summary = self.calculate_latency_stats(None);
        let report_id = self.next_report_id;
        self.next_report_id += 1;

        let mut report = ProfileReport {
            report_id,
            target_pid: pid,
            sample_count: self.sample_count as u32,
            duration_ns,
            pmc: self.aggregated,
            latency: latency_summary,
            top_bottleneck: top_symbol,
            bottleneck_samples: max_self,
            seal_hash: [0u8; 32],
            timestamp,
        };

        report.seal_hash = Self::compute_report_seal(&report);

        for slot in self.reports.iter_mut() {
            if slot.is_none() {
                *slot = Some(report);
                self.report_count += 1;
                break;
            }
        }

        self.stats.total_reports_generated += 1;
        self.record_audit(AuditAction::GenerateReport, pid, timestamp);

        Ok(report_id)
    }

    /// Vérifie l'intégrité cryptographique du sceau d'un rapport
    pub fn verify_report_seal(
        &mut self,
        cap: &ProfileCap,
        report_id: u32,
    ) -> Result<bool, SysError> {
        if !cap.has_right(profile_rights::PROFILE_INSPECT) {
            return Err(SysError::PermissionDenied);
        }

        let report = self
            .reports
            .iter()
            .find_map(|r| r.as_ref().filter(|rep| rep.report_id == report_id))
            .ok_or(SysError::InvalidArgument)?;

        let computed = Self::compute_report_seal(report);
        let matches = computed == report.seal_hash;

        if matches {
            self.stats.total_seals_verified += 1;
        }

        Ok(matches)
    }

    /// Initialise le profileur avec des jeux de données réalistes pour Ring 3 (jambo-init, jambo-netd, etc.)
    pub fn init_defaults(&mut self) {
        let cap = self.cap;

        // Config PMC pour PID 1 (jambo-init) et PID 10 (jambo-netd)
        let _ = self.configure_pmc(
            &cap,
            1,
            PmcConfig {
                enabled_events_mask: 0xFF,
                sample_period: 50_000,
                ring_filter: RingFilter::Ring3Only,
                pebs_enabled: true,
                arch: TargetArch::X86_64,
            },
            100,
        );

        let _ = self.configure_pmc(
            &cap,
            10,
            PmcConfig {
                enabled_events_mask: 0xFF,
                sample_period: 10_000,
                ring_filter: RingFilter::AnyRing,
                pebs_enabled: true,
                arch: TargetArch::X86_64,
            },
            105,
        );

        // Enregistrement d'échantillons réalistes avec pile d'appels
        let sample1 = PmcSample {
            sample_id: 1,
            pid: 1,
            tid: 1,
            timestamp: 110,
            ip: 0x0040_1050,
            sp: 0x7FFF_0000,
            event: PmcEventType::Instructions,
            counter_val: 12_500_000,
            call_stack: [
                0x0040_0010,
                0x0040_1050,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            call_stack_len: 2,
            pebs: Some(PebsRecord {
                precise_ip: 0x0040_1050,
                linear_data_addr: 0x7FFF_0020,
                flags: 0x02,
                event_index: 0,
            }),
        };
        let _ = self.record_sample(&cap, sample1);

        let sample2 = PmcSample {
            sample_id: 2,
            pid: 1,
            tid: 1,
            timestamp: 120,
            ip: 0x0040_2050,
            sp: 0x7FFF_0000,
            event: PmcEventType::CpuCycles,
            counter_val: 8_200_000,
            call_stack: [
                0x0040_0010,
                0x0040_1050,
                0x0040_2050,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            call_stack_len: 3,
            pebs: Some(PebsRecord {
                precise_ip: 0x0040_2050,
                linear_data_addr: 0x7FFF_0080,
                flags: 0x02,
                event_index: 1,
            }),
        };
        let _ = self.record_sample(&cap, sample2);

        let sample3 = PmcSample {
            sample_id: 3,
            pid: 10,
            tid: 2,
            timestamp: 130,
            ip: 0x0040_6020,
            sp: 0x7FFF_1000,
            event: PmcEventType::BranchInstructions,
            counter_val: 3_100_000,
            call_stack: [
                0x0040_0010,
                0x0040_5050,
                0x0040_6020,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            call_stack_len: 3,
            pebs: None,
        };
        let _ = self.record_sample(&cap, sample3);

        let sample4 = PmcSample {
            sample_id: 4,
            pid: 10,
            tid: 2,
            timestamp: 140,
            ip: 0x0040_6020,
            sp: 0x7FFF_1000,
            event: PmcEventType::BranchMisses,
            counter_val: 62_000,
            call_stack: [
                0x0040_0010,
                0x0040_5050,
                0x0040_6020,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            call_stack_len: 3,
            pebs: None,
        };
        let _ = self.record_sample(&cap, sample4);

        let sample5 = PmcSample {
            sample_id: 5,
            pid: 10,
            tid: 2,
            timestamp: 150,
            ip: 0x0040_6020,
            sp: 0x7FFF_1000,
            event: PmcEventType::LlcMiss,
            counter_val: 15_400,
            call_stack: [
                0x0040_0010,
                0x0040_6020,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            call_stack_len: 2,
            pebs: None,
        };
        let _ = self.record_sample(&cap, sample5);

        // Latences réalistes de micro-noyau (en nanosecondes)
        let _ = self.record_latency(&cap, LatencyCategory::SyscallDispatch, 180, 1, 160);
        let _ = self.record_latency(&cap, LatencyCategory::SyscallDispatch, 210, 1, 161);
        let _ = self.record_latency(&cap, LatencyCategory::SyscallDispatch, 195, 1, 162);
        let _ = self.record_latency(&cap, LatencyCategory::ContextSwitch, 450, 1, 163);
        let _ = self.record_latency(&cap, LatencyCategory::ContextSwitch, 490, 10, 164);
        let _ = self.record_latency(&cap, LatencyCategory::IpcTransfer, 320, 10, 165);
        let _ = self.record_latency(&cap, LatencyCategory::IpcTransfer, 340, 10, 166);
        let _ = self.record_latency(&cap, LatencyCategory::InterruptHandler, 120, 10, 167);

        // Génération d'un rapport initial scellé
        let _ = self.generate_report(&cap, 1, 1_000_000, 200);
    }

    pub fn get_report(&self, report_id: u32) -> Option<&ProfileReport> {
        self.reports
            .iter()
            .find_map(|r| r.as_ref().filter(|rep| rep.report_id == report_id))
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_attenuation_and_amplification_denial() {
        let admin = ProfileCap::new(Handle::new(1, 1), profile_rights::ALL);
        assert!(admin.has_right(profile_rights::PROFILE_CONFIGURE));
        assert!(admin.has_right(profile_rights::PROFILE_SAMPLE));
        assert!(admin.has_right(profile_rights::PROFILE_ADMIN));

        let inspect_only = admin
            .attenuate(profile_rights::PROFILE_INSPECT)
            .expect("attenuate to inspect-only");
        assert!(inspect_only.has_right(profile_rights::PROFILE_INSPECT));
        assert!(!inspect_only.has_right(profile_rights::PROFILE_CONFIGURE));
        assert!(!inspect_only.has_right(profile_rights::PROFILE_ADMIN));

        // Refus formel d'amplification
        assert_eq!(
            inspect_only.attenuate(profile_rights::PROFILE_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_sha256_profiler() {
        let d1 = Sha256::digest(b"JamboOS Hardware Profiler Subsystem");
        let d2 = Sha256::digest(b"JamboOS Hardware Profiler Subsystem");
        assert_eq!(d1, d2);

        let d3 = Sha256::digest(b"JamboOS Hardware Profiler Subsystem Altered");
        assert_ne!(d1, d3);
    }

    #[test]
    fn test_pmc_event_counting_and_ipc() {
        let admin = ProfileCap::new(Handle::new(1, 1), profile_rights::ALL);
        let mut daemon = JamboProfilerDaemon::new(1, admin);

        let sample_inst = PmcSample {
            sample_id: 1,
            pid: 42,
            tid: 1,
            timestamp: 1000,
            ip: 0x0040_1000,
            sp: 0x7FFF_0000,
            event: PmcEventType::Instructions,
            counter_val: 20_000_000,
            call_stack: [0u64; MAX_CALL_STACK_DEPTH],
            call_stack_len: 0,
            pebs: None,
        };
        let _ = daemon.record_sample(&admin, sample_inst).unwrap();

        let sample_cyc = PmcSample {
            sample_id: 2,
            pid: 42,
            tid: 1,
            timestamp: 1001,
            ip: 0x0040_1000,
            sp: 0x7FFF_0000,
            event: PmcEventType::CpuCycles,
            counter_val: 10_000_000,
            call_stack: [0u64; MAX_CALL_STACK_DEPTH],
            call_stack_len: 0,
            pebs: None,
        };
        let _ = daemon.record_sample(&admin, sample_cyc).unwrap();

        let (whole, frac) = daemon.aggregated.ipc_ratio();
        assert_eq!(whole, 2);
        assert_eq!(frac, 0); // 20M / 10M = 2.00 IPC
    }

    #[test]
    fn test_call_stack_sampling_and_flame_nodes() {
        let admin = ProfileCap::new(Handle::new(1, 1), profile_rights::ALL);
        let mut daemon = JamboProfilerDaemon::new(1, admin);

        let stack = [0x0040_0000, 0x0040_1050, 0x0040_2050];
        let sample = PmcSample {
            sample_id: 1,
            pid: 50,
            tid: 1,
            timestamp: 2000,
            ip: 0x0040_2050,
            sp: 0x7FFF_0000,
            event: PmcEventType::Instructions,
            counter_val: 1_000,
            call_stack: [
                stack[0], stack[1], stack[2], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            call_stack_len: 3,
            pebs: None,
        };

        daemon.record_sample(&admin, sample).unwrap();
        assert_eq!(daemon.flame_count, 3);
        assert_eq!(daemon.flame_nodes[0].unwrap().symbol_str(), "main");
        assert_eq!(daemon.flame_nodes[1].unwrap().symbol_str(), "vfs_read");
        assert_eq!(daemon.flame_nodes[2].unwrap().symbol_str(), "ipc_send_msg");
        assert_eq!(daemon.flame_nodes[2].unwrap().self_samples, 1);
    }

    #[test]
    fn test_latency_percentiles() {
        let admin = ProfileCap::new(Handle::new(1, 1), profile_rights::ALL);
        let mut daemon = JamboProfilerDaemon::new(1, admin);

        for lat in [100, 150, 200, 250, 300, 400, 500, 600, 800, 1000] {
            daemon
                .record_latency(&admin, LatencyCategory::SyscallDispatch, lat, 1, 100)
                .unwrap();
        }

        let stats = daemon.calculate_latency_stats(Some(LatencyCategory::SyscallDispatch));
        assert_eq!(stats.count, 10);
        assert_eq!(stats.min_ns, 100);
        assert_eq!(stats.max_ns, 1000);
        assert_eq!(stats.p50_ns, 400); // Index 5 dans [100, 150, 200, 250, 300, 400, 500, 600, 800, 1000]
        assert!(stats.p90_ns >= 800);
        assert_eq!(stats.p999_ns, 1000);
    }

    #[test]
    fn test_report_generation_and_seal_verification() {
        let admin = ProfileCap::new(Handle::new(1, 1), profile_rights::ALL);
        let mut daemon = JamboProfilerDaemon::new(1, admin);
        daemon.init_defaults();

        let report_id = daemon
            .generate_report(&admin, 10, 2_000_000, 500)
            .expect("generate report");
        assert!(daemon.verify_report_seal(&admin, report_id).unwrap());
    }

    #[test]
    fn test_tamper_detection_in_report_seal() {
        let admin = ProfileCap::new(Handle::new(1, 1), profile_rights::ALL);
        let mut daemon = JamboProfilerDaemon::new(1, admin);
        daemon.init_defaults();

        let report_id = 1;
        assert!(daemon.verify_report_seal(&admin, report_id).unwrap());

        // Altération frauduleuse de l'IPC ou de la métrique
        if let Some(rep) = daemon.reports[0].as_mut() {
            rep.pmc.instructions ^= 0x1234;
        }

        // Le scellement SHA-256 détecte immédiatement l'altération
        assert!(!daemon.verify_report_seal(&admin, report_id).unwrap());
    }
}

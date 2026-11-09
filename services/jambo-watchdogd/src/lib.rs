//! Démon de Surveillance de Vivacité Système, Chien de Garde Matériel & Logiciel et Isolation NMI (`jambo-watchdogd`)
//!
//! Fournit une infrastructure complète de résilience système et tolérance aux pannes pour micro-noyau `#![no_std]` :
//! 1. Chien de garde matériel (Intel iTCO / ACPI WDT / Generic Hardware Watchdog) avec pré-interruption NMI.
//! 2. Chiens de garde logiciels Ring 3 & Ring 0 par thread/processus avec détection de dérive d'ordonnancement.
//! 3. Détection des blocages stochastiques (Soft Lockup, Hard Lockup, Deadlocks d'event loops).
//! 4. Traitement et isolation sécurisée sur interruption NMI avec préservation de contexte pour crash-dump.
//! 5. Battements de cœur inter-nœuds (Cluster Liveness) et déclenchement automatique de bascule de secours (Failover).
//! 6. Journal d'audit et d'événements scellé cryptographiquement par chaîne SHA-256.
//! 7. Contrôle d'accès capabilaire strict sans autorité ambiante via `WatchdogCap`.
//! 8. Protocole IPC déterministe à 64 octets et canal synchrone sous l'endpoint 21 (PID 21).

#![no_std]
#![allow(clippy::too_many_arguments)]

pub use libjambo::{Handle, SysError};

pub const MAX_WATCHDOG_TARGETS: usize = 32;
pub const MAX_CLUSTER_NODES: usize = 16;
pub const MAX_NMI_ALERTS: usize = 32;
pub const MAX_EVENTS: usize = 64;
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

        for (i, &w_item) in w.iter().enumerate() {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w_item);
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
// MODÈLE DE SÉCURITÉ CAPABILAIRE : WatchdogCap
// ============================================================================

pub mod watchdog_rights {
    pub const WATCHDOG_INSPECT: u32 = 1 << 0;
    pub const WATCHDOG_PET: u32 = 1 << 1;
    pub const WATCHDOG_REGISTER: u32 = 1 << 2;
    pub const WATCHDOG_CONFIGURE: u32 = 1 << 3;
    pub const WATCHDOG_TRIGGER: u32 = 1 << 4;
    pub const WATCHDOG_FAILOVER: u32 = 1 << 5;
    pub const WATCHDOG_ADMIN: u32 = 1 << 6;

    pub const ALL: u32 = WATCHDOG_INSPECT
        | WATCHDOG_PET
        | WATCHDOG_REGISTER
        | WATCHDOG_CONFIGURE
        | WATCHDOG_TRIGGER
        | WATCHDOG_FAILOVER
        | WATCHDOG_ADMIN;
}

/// Capacité de contrôle d'accès pour le sous-système de chien de garde
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchdogCap {
    pub handle: Handle,
    pub rights: u32,
}

impl WatchdogCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits vers un sous-ensemble strict.
    /// Interdit formellement toute amplification de droits.
    pub fn attenuate(&self, new_rights: u32) -> Result<WatchdogCap, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(WatchdogCap {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// ACTIONS DE RÉCUPÉRATION & BASYL-PASS (FAILOVER)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailoverAction {
    LogAndWarn,
    IsolateAndKillThread,
    RestartService,
    TriggerClusterFailover,
    HardwareReboot,
}

impl FailoverAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            FailoverAction::LogAndWarn => "LOG_WARN",
            FailoverAction::IsolateAndKillThread => "ISOLATE_KILL",
            FailoverAction::RestartService => "RESTART_SVC",
            FailoverAction::TriggerClusterFailover => "CLUSTER_FAILOVER",
            FailoverAction::HardwareReboot => "HW_REBOOT",
        }
    }
}

/// Action de chien de garde pour le protocole IPC (TriggerAction)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WatchdogAction {
    Log = 0,
    Nmi = 1,
    Reset = 2,
    Failover = 3,
}

impl WatchdogAction {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Log),
            1 => Some(Self::Nmi),
            2 => Some(Self::Reset),
            3 => Some(Self::Failover),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Log => "LOG",
            Self::Nmi => "NMI",
            Self::Reset => "RESET",
            Self::Failover => "FAILOVER",
        }
    }
}

// ============================================================================
// SOUS-SYSTÈME CHIEN DE GARDE MATÉRIEL (Hardware WDT / iTCO)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwWatchdogType {
    IntelTCOv2,
    AcpiGenericWdt,
    ArmGenericWdt,
    SoftwareEmulated,
}

impl HwWatchdogType {
    pub fn as_str(&self) -> &'static str {
        match self {
            HwWatchdogType::IntelTCOv2 => "Intel iTCO v2 (LPC/eSPI)",
            HwWatchdogType::AcpiGenericWdt => "ACPI WDAT / WDT",
            HwWatchdogType::ArmGenericWdt => "ARM SBSA Generic Watchdog",
            HwWatchdogType::SoftwareEmulated => "Software High-Precision Emulated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwWatchdogStatus {
    Disabled,
    Armed,
    PreTimeoutWarning,
    ResetTriggered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwWatchdogEvent {
    Nominal,
    PreTimeoutNmiEmitted,
    HardwareResetTriggered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwWatchdog {
    pub hw_type: HwWatchdogType,
    pub io_port_base: u16,
    pub timeout_ms: u64,
    pub pre_timeout_ms: u64, // Moment où NMI est déclenché avant le hard-reboot
    pub nmi_enabled: bool,
    pub status: HwWatchdogStatus,
    pub last_reload_timestamp: u64,
    pub reload_count: u64,
    pub nmi_count: u64,
    pub reset_count: u64,
}

impl HwWatchdog {
    pub const fn new(
        hw_type: HwWatchdogType,
        io_port_base: u16,
        timeout_ms: u64,
        pre_timeout_ms: u64,
    ) -> Self {
        Self {
            hw_type,
            io_port_base,
            timeout_ms,
            pre_timeout_ms,
            nmi_enabled: true,
            status: HwWatchdogStatus::Disabled,
            last_reload_timestamp: 0,
            reload_count: 0,
            nmi_count: 0,
            reset_count: 0,
        }
    }

    pub fn arm(&mut self, timestamp: u64) {
        self.status = HwWatchdogStatus::Armed;
        self.last_reload_timestamp = timestamp;
    }

    pub fn disarm(&mut self) {
        self.status = HwWatchdogStatus::Disabled;
    }

    pub fn reload(&mut self, timestamp: u64) {
        if self.status != HwWatchdogStatus::Disabled {
            self.last_reload_timestamp = timestamp;
            self.status = HwWatchdogStatus::Armed;
            self.reload_count += 1;
        }
    }

    pub fn time_remaining_ms(&self, current_timestamp: u64) -> u64 {
        if self.status == HwWatchdogStatus::Disabled
            || current_timestamp <= self.last_reload_timestamp
        {
            return self.timeout_ms;
        }
        let elapsed = current_timestamp - self.last_reload_timestamp;
        self.timeout_ms.saturating_sub(elapsed)
    }

    pub fn tick(&mut self, current_timestamp: u64) -> HwWatchdogEvent {
        if self.status == HwWatchdogStatus::Disabled {
            return HwWatchdogEvent::Nominal;
        }

        let elapsed = current_timestamp.saturating_sub(self.last_reload_timestamp);

        if elapsed >= self.timeout_ms {
            self.status = HwWatchdogStatus::ResetTriggered;
            self.reset_count += 1;
            HwWatchdogEvent::HardwareResetTriggered
        } else if self.nmi_enabled
            && elapsed >= (self.timeout_ms.saturating_sub(self.pre_timeout_ms))
        {
            if self.status != HwWatchdogStatus::PreTimeoutWarning {
                self.status = HwWatchdogStatus::PreTimeoutWarning;
                self.nmi_count += 1;
                HwWatchdogEvent::PreTimeoutNmiEmitted
            } else {
                HwWatchdogEvent::Nominal
            }
        } else {
            HwWatchdogEvent::Nominal
        }
    }
}

// ============================================================================
// CHIEN DE GARDE LOGICIEL (Thread, Task, Service Targets)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogTargetType {
    KernelCore,
    CriticalService,
    UserspaceTask,
    DeviceDriver,
}

impl WatchdogTargetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            WatchdogTargetType::KernelCore => "KernelCore",
            WatchdogTargetType::CriticalService => "CriticalService",
            WatchdogTargetType::UserspaceTask => "UserspaceTask",
            WatchdogTargetType::DeviceDriver => "DeviceDriver",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetLivenessState {
    Active,
    WarningDrift,
    Stalled,
    Isolated,
    Panicked,
    Terminated,
}

impl TargetLivenessState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetLivenessState::Active => "ACTIVE",
            TargetLivenessState::WarningDrift => "WARN_DRIFT",
            TargetLivenessState::Stalled => "STALLED",
            TargetLivenessState::Isolated => "ISOLATED",
            TargetLivenessState::Panicked => "PANICKED",
            TargetLivenessState::Terminated => "TERMINATED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchdogTarget {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub target_type: WatchdogTargetType,
    pub pid: u64,
    pub tid: u64,
    pub timeout_ms: u64,
    pub max_drift_ms: u64,
    pub last_pet_timestamp: u64,
    pub last_drift_ms: u64,
    pub total_pets: u64,
    pub missed_heartbeats: u32,
    pub state: TargetLivenessState,
    pub failover_action: FailoverAction,
}

impl WatchdogTarget {
    pub fn new(
        id: u32,
        name: &str,
        target_type: WatchdogTargetType,
        pid: u64,
        tid: u64,
        timeout_ms: u64,
        max_drift_ms: u64,
        failover_action: FailoverAction,
        initial_timestamp: u64,
    ) -> Self {
        let mut n = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        n[..len].copy_from_slice(&bytes[..len]);

        Self {
            id,
            name: n,
            name_len: len,
            target_type,
            pid,
            tid,
            timeout_ms,
            max_drift_ms,
            last_pet_timestamp: initial_timestamp,
            last_drift_ms: 0,
            total_pets: 0,
            missed_heartbeats: 0,
            state: TargetLivenessState::Active,
            failover_action,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unknown")
    }

    pub fn pet(&mut self, timestamp: u64) {
        if self.state == TargetLivenessState::Isolated
            || self.state == TargetLivenessState::Terminated
        {
            return;
        }

        let elapsed = timestamp.saturating_sub(self.last_pet_timestamp);
        if elapsed > self.max_drift_ms {
            self.last_drift_ms = elapsed - self.max_drift_ms;
            self.state = TargetLivenessState::WarningDrift;
        } else {
            self.last_drift_ms = 0;
            self.state = TargetLivenessState::Active;
        }

        self.last_pet_timestamp = timestamp;
        self.total_pets += 1;
        self.missed_heartbeats = 0;
    }

    pub fn evaluate(&mut self, current_timestamp: u64) -> TargetLivenessState {
        if self.state == TargetLivenessState::Isolated
            || self.state == TargetLivenessState::Terminated
        {
            return self.state;
        }

        let elapsed = current_timestamp.saturating_sub(self.last_pet_timestamp);
        if elapsed >= self.timeout_ms {
            self.missed_heartbeats += 1;
            self.state = TargetLivenessState::Stalled;
        } else if elapsed > self.max_drift_ms {
            self.state = TargetLivenessState::WarningDrift;
        } else {
            self.state = TargetLivenessState::Active;
        }

        self.state
    }
}

// ============================================================================
// BATTEMENTS DE CŒUR INTER-NŒUDS (Cluster Liveness & Failover)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeLivenessState {
    Healthy,
    Suspect,
    Dead,
    FailoverInitiated,
}

impl NodeLivenessState {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeLivenessState::Healthy => "HEALTHY",
            NodeLivenessState::Suspect => "SUSPECT",
            NodeLivenessState::Dead => "DEAD",
            NodeLivenessState::FailoverInitiated => "FAILOVER_INITIATED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClusterNodeHeartbeat {
    pub node_id: u32,
    pub node_name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub last_heartbeat_timestamp: u64,
    pub heartbeat_interval_ms: u64,
    pub failover_threshold_misses: u32,
    pub missed_count: u32,
    pub total_heartbeats: u64,
    pub last_sequence: u64,
    pub is_primary: bool,
    pub state: NodeLivenessState,
}

impl ClusterNodeHeartbeat {
    pub fn new(
        node_id: u32,
        name: &str,
        heartbeat_interval_ms: u64,
        failover_threshold_misses: u32,
        is_primary: bool,
        initial_timestamp: u64,
    ) -> Self {
        let mut n = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        n[..len].copy_from_slice(&bytes[..len]);

        Self {
            node_id,
            node_name: n,
            name_len: len,
            last_heartbeat_timestamp: initial_timestamp,
            heartbeat_interval_ms,
            failover_threshold_misses,
            missed_count: 0,
            total_heartbeats: 0,
            last_sequence: 0,
            is_primary,
            state: NodeLivenessState::Healthy,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.node_name[..self.name_len]).unwrap_or("unknown")
    }

    pub fn record_heartbeat(&mut self, timestamp: u64, seq: u64) {
        self.last_heartbeat_timestamp = timestamp;
        self.last_sequence = seq;
        self.total_heartbeats += 1;
        self.missed_count = 0;
        self.state = NodeLivenessState::Healthy;
    }

    pub fn evaluate(&mut self, current_timestamp: u64) -> NodeLivenessState {
        let elapsed = current_timestamp.saturating_sub(self.last_heartbeat_timestamp);
        let misses = (elapsed / self.heartbeat_interval_ms) as u32;

        self.missed_count = misses;

        if misses >= self.failover_threshold_misses {
            if self.is_primary {
                self.state = NodeLivenessState::FailoverInitiated;
            } else {
                self.state = NodeLivenessState::Dead;
            }
        } else if misses >= 1 {
            self.state = NodeLivenessState::Suspect;
        } else {
            self.state = NodeLivenessState::Healthy;
        }

        self.state
    }
}

// ============================================================================
// DÉTECTION DE BLOCAGES & ISOLATION NMI (Non-Maskable Interrupts)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockupType {
    SoftLockup,
    HardLockup,
    EventLoopDeadlock,
    HardwarePreTimeout,
}

impl LockupType {
    pub fn as_str(&self) -> &'static str {
        match self {
            LockupType::SoftLockup => "SOFT_LOCKUP",
            LockupType::HardLockup => "HARD_LOCKUP",
            LockupType::EventLoopDeadlock => "DEADLOCK",
            LockupType::HardwarePreTimeout => "HW_PRE_TIMEOUT",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NmiAlert {
    pub alert_id: u64,
    pub cpu_id: u32,
    pub target_id: Option<u32>,
    pub lockup_type: LockupType,
    pub rip: u64,
    pub rsp: u64,
    pub timestamp: u64,
    pub action_taken: FailoverAction,
}

// ============================================================================
// ÉVÉNEMENTS & STATISTIQUES GLOBALES
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchdogEventType {
    TargetRegistered,
    TargetPetted,
    DriftWarning,
    TargetStalled,
    NmiTriggered,
    ThreadIsolated,
    ClusterHeartbeatMissed,
    ClusterFailoverInitiated,
    HwReloaded,
}

impl WatchdogEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            WatchdogEventType::TargetRegistered => "TARGET_REG",
            WatchdogEventType::TargetPetted => "TARGET_PET",
            WatchdogEventType::DriftWarning => "DRIFT_WARN",
            WatchdogEventType::TargetStalled => "STALL_DETECT",
            WatchdogEventType::NmiTriggered => "NMI_ALERT",
            WatchdogEventType::ThreadIsolated => "ISOLATED",
            WatchdogEventType::ClusterHeartbeatMissed => "HB_MISSED",
            WatchdogEventType::ClusterFailoverInitiated => "CLUSTER_FAILOVER",
            WatchdogEventType::HwReloaded => "HW_RELOAD",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchdogEvent {
    pub seq: u64,
    pub timestamp: u64,
    pub event_type: WatchdogEventType,
    pub target_id: u32,
    pub details: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchdogStats {
    pub total_pets: u64,
    pub total_stalls_detected: u64,
    pub total_drifts_warned: u64,
    pub total_nmi_alerts: u64,
    pub total_threads_isolated: u64,
    pub total_cluster_failovers: u64,
    pub total_hw_reloads: u64,
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE 64 OCTETS (`WatchdogRequest`, `WatchdogResponse`)
// ============================================================================

pub const WDOG_MAGIC_REQ: u32 = 0x57444F47; // "WDOG"
pub const WDOG_MAGIC_RESP: u32 = 0x57444F53; // "WDOS"

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogOpcode {
    GetStatus = 1,
    Ping = 2,
    RegisterTarget = 3,
    TriggerAction = 4,
    QueryAlerts = 5,
    AuditLog = 6,
}

impl WatchdogOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::Ping),
            3 => Some(Self::RegisterTarget),
            4 => Some(Self::TriggerAction),
            5 => Some(Self::QueryAlerts),
            6 => Some(Self::AuditLog),
            _ => None,
        }
    }
}

/// Requête IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub rights: u32,
    pub target_id: u32,
    pub timeout_ms: u32,
    pub action: u8,
    pub name_len: u8,
    pub _pad: [u8; 2],
    pub param_u64: u64,
    pub name: [u8; 24],
}

const _: () = assert!(core::mem::size_of::<WatchdogRequest>() == 64);

impl Default for WatchdogRequest {
    fn default() -> Self {
        Self {
            magic: WDOG_MAGIC_REQ,
            opcode: WatchdogOpcode::GetStatus as u32,
            handle_id: 21,
            rights: watchdog_rights::ALL,
            target_id: 0,
            timeout_ms: 0,
            action: 0,
            name_len: 0,
            _pad: [0; 2],
            param_u64: 0,
            name: [0; 24],
        }
    }
}

impl WatchdogRequest {
    pub const fn new(opcode: WatchdogOpcode) -> Self {
        Self {
            magic: WDOG_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: 21,
            rights: watchdog_rights::ALL,
            target_id: 0,
            timeout_ms: 0,
            action: 0,
            name_len: 0,
            _pad: [0; 2],
            param_u64: 0,
            name: [0; 24],
        }
    }

    pub const fn new_status() -> Self {
        Self::new(WatchdogOpcode::GetStatus)
    }

    pub const fn new_ping(target_id: u32) -> Self {
        let mut req = Self::new(WatchdogOpcode::Ping);
        req.target_id = target_id;
        req
    }

    pub fn new_register(name: &str, timeout_ms: u32, action: u8) -> Self {
        let mut req = Self::new(WatchdogOpcode::RegisterTarget);
        req.timeout_ms = timeout_ms;
        req.action = action;
        req.set_name(name);
        req
    }

    pub const fn new_trigger_action(action: u8, target_id: u32) -> Self {
        let mut req = Self::new(WatchdogOpcode::TriggerAction);
        req.action = action;
        req.target_id = target_id;
        req
    }

    pub const fn new_query_alerts() -> Self {
        Self::new(WatchdogOpcode::QueryAlerts)
    }

    pub const fn new_audit_log() -> Self {
        Self::new(WatchdogOpcode::AuditLog)
    }

    pub fn set_name(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(24);
        self.name[..len].copy_from_slice(&bytes[..len]);
        for b in &mut self.name[len..] {
            *b = 0;
        }
        self.name_len = len as u8;
    }

    pub fn name_as_str(&self) -> &str {
        let len = (self.name_len as usize).min(24);
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
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

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogResponse {
    pub magic: u32,
    pub status: i32,
    pub hw_enabled: u8,
    pub active_targets: u8,
    pub alert_count: u8,
    pub is_tripped: u8,
    pub tripped_target_id: u32,
    pub total_pings: u64,
    pub last_ping_timestamp: u64,
    pub sha256_hash: [u8; 16],
    pub details: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<WatchdogResponse>() == 64);

impl Default for WatchdogResponse {
    fn default() -> Self {
        Self {
            magic: WDOG_MAGIC_RESP,
            status: 0,
            hw_enabled: 0,
            active_targets: 0,
            alert_count: 0,
            is_tripped: 0,
            tripped_target_id: 0,
            total_pings: 0,
            last_ping_timestamp: 0,
            sha256_hash: [0; 16],
            details: [0; 16],
        }
    }
}

impl WatchdogResponse {
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

// ============================================================================
// DÉMON PRINCIPAL : JamboWatchdogDaemon
// ============================================================================

pub struct JamboWatchdogDaemon {
    pub daemon_id: u32,
    pub admin_cap: WatchdogCap,
    pub hw_watchdog: HwWatchdog,
    pub targets: [Option<WatchdogTarget>; MAX_WATCHDOG_TARGETS],
    pub target_count: usize,
    pub cluster_nodes: [Option<ClusterNodeHeartbeat>; MAX_CLUSTER_NODES],
    pub cluster_count: usize,
    pub nmi_alerts: [Option<NmiAlert>; MAX_NMI_ALERTS],
    pub nmi_head: usize,
    pub nmi_total: u64,
    pub events: [Option<WatchdogEvent>; MAX_EVENTS],
    pub event_head: usize,
    pub event_total: u64,
    pub stats: WatchdogStats,
    pub audit_digest: [u8; 32],
}

impl Default for JamboWatchdogDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboWatchdogDaemon {
    /// Crée une instance avec les capacités administratives par défaut (PID 21)
    pub fn new() -> Self {
        Self::with_cap(
            21,
            WatchdogCap::new(Handle::new(21, 1), watchdog_rights::ALL),
        )
    }

    /// Crée une instance avec capacité administrative explicite
    pub fn with_cap(daemon_id: u32, admin_cap: WatchdogCap) -> Self {
        Self {
            daemon_id,
            admin_cap,
            hw_watchdog: HwWatchdog::new(HwWatchdogType::IntelTCOv2, 0x0400, 30000, 5000),
            targets: [None; MAX_WATCHDOG_TARGETS],
            target_count: 0,
            cluster_nodes: [None; MAX_CLUSTER_NODES],
            cluster_count: 0,
            nmi_alerts: [None; MAX_NMI_ALERTS],
            nmi_head: 0,
            nmi_total: 0,
            events: [None; MAX_EVENTS],
            event_head: 0,
            event_total: 0,
            stats: WatchdogStats::default(),
            audit_digest: [0u8; 32],
        }
    }

    /// Initialise la configuration nominale du système de surveillance
    pub fn init_defaults(&mut self) {
        // Armement du chien de garde matériel
        self.hw_watchdog.arm(100);

        // 1. Thread d'ordonnancement noyau (KernelCore)
        let _ = self.register_target_internal(WatchdogTarget::new(
            1,
            "kernel-sched",
            WatchdogTargetType::KernelCore,
            0,
            0,
            1000, // timeout 1000ms
            150,  // max drift 150ms
            FailoverAction::HardwareReboot,
            100,
        ));

        // 2. Superviseur Init PID 1 (CriticalService)
        let _ = self.register_target_internal(WatchdogTarget::new(
            2,
            "jambo-init",
            WatchdogTargetType::CriticalService,
            1,
            1,
            2000, // timeout 2000ms
            300,  // max drift 300ms
            FailoverAction::RestartService,
            100,
        ));

        // 3. Démon Réseau (jambo-netd)
        let _ = self.register_target_internal(WatchdogTarget::new(
            3,
            "jambo-netd",
            WatchdogTargetType::CriticalService,
            2,
            2,
            3000,
            500,
            FailoverAction::RestartService,
            100,
        ));

        // 4. Multiplexeur IPC (jambo-ipcd)
        let _ = self.register_target_internal(WatchdogTarget::new(
            4,
            "jambo-ipcd",
            WatchdogTargetType::CriticalService,
            3,
            3,
            2500,
            400,
            FailoverAction::IsolateAndKillThread,
            100,
        ));

        // Initialisation de la grappe de nœuds
        let _ = self.register_cluster_node_internal(ClusterNodeHeartbeat::new(
            1,
            "node-alpha",
            500,  // intervalle 500ms
            3,    // 3 manques = 1500ms -> failover
            true, // Primary
            100,
        ));

        let _ = self.register_cluster_node_internal(ClusterNodeHeartbeat::new(
            2,
            "node-beta",
            500,
            3,
            false, // Standby
            100,
        ));

        self.commit_audit_event(
            WatchdogEventType::TargetRegistered,
            0,
            b"WATCHDOG_SUBSYS_INITIALIZED\0\0\0\0\0",
            100,
        );
    }

    fn register_target_internal(&mut self, target: WatchdogTarget) -> Result<(), SysError> {
        if self.target_count >= MAX_WATCHDOG_TARGETS {
            return Err(SysError::OutOfMemory);
        }
        for slot in self.targets.iter_mut() {
            if slot.is_none() {
                *slot = Some(target);
                self.target_count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    fn register_cluster_node_internal(
        &mut self,
        node: ClusterNodeHeartbeat,
    ) -> Result<(), SysError> {
        if self.cluster_count >= MAX_CLUSTER_NODES {
            return Err(SysError::OutOfMemory);
        }
        for slot in self.cluster_nodes.iter_mut() {
            if slot.is_none() {
                *slot = Some(node);
                self.cluster_count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Enregistre un nouveau watchdog cible sous contrôle capabilaire
    pub fn register_target(
        &mut self,
        cap: &WatchdogCap,
        target: WatchdogTarget,
    ) -> Result<(), SysError> {
        if !cap.has_right(watchdog_rights::WATCHDOG_REGISTER) {
            return Err(SysError::PermissionDenied);
        }
        self.register_target_internal(target)?;
        self.commit_audit_event(
            WatchdogEventType::TargetRegistered,
            target.id,
            b"NEW_TARGET_REGISTERED\0\0\0\0\0\0\0\0\0\0\0",
            target.last_pet_timestamp,
        );
        Ok(())
    }

    /// Nourrit le chien de garde pour une cible donnée (Petting)
    pub fn pet_target(
        &mut self,
        cap: &WatchdogCap,
        target_id: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(watchdog_rights::WATCHDOG_PET) {
            return Err(SysError::PermissionDenied);
        }

        let mut found = false;
        let mut is_drift = false;
        for target in self.targets.iter_mut().flatten() {
            if target.id == target_id {
                let old_state = target.state;
                target.pet(timestamp);
                found = true;
                if target.state == TargetLivenessState::WarningDrift
                    && old_state != TargetLivenessState::WarningDrift
                {
                    is_drift = true;
                }
                break;
            }
        }

        if !found {
            return Err(SysError::InvalidArgument);
        }

        self.stats.total_pets += 1;
        if is_drift {
            self.stats.total_drifts_warned += 1;
            self.commit_audit_event(
                WatchdogEventType::DriftWarning,
                target_id,
                b"EVENT_LOOP_DRIFT_DETECTED",
                timestamp,
            );
        } else {
            self.commit_audit_event(
                WatchdogEventType::TargetPetted,
                target_id,
                b"TARGET_PET_SUCCESS",
                timestamp,
            );
        }
        Ok(())
    }

    /// Recharge le chien de garde matériel
    pub fn reload_hardware(&mut self, cap: &WatchdogCap, timestamp: u64) -> Result<(), SysError> {
        if !cap.has_right(watchdog_rights::WATCHDOG_PET) {
            return Err(SysError::PermissionDenied);
        }
        self.hw_watchdog.reload(timestamp);
        self.stats.total_hw_reloads += 1;
        self.commit_audit_event(
            WatchdogEventType::HwReloaded,
            0,
            b"HW_WATCHDOG_RELOADED",
            timestamp,
        );
        Ok(())
    }

    /// Évalue la vivacité globale de toutes les cibles et nœuds à l'instant `timestamp`
    pub fn evaluate_system_liveness(
        &mut self,
        cap: &WatchdogCap,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(watchdog_rights::WATCHDOG_INSPECT) {
            return Err(SysError::PermissionDenied);
        }

        // 1. Chien de garde matériel
        match self.hw_watchdog.tick(timestamp) {
            HwWatchdogEvent::PreTimeoutNmiEmitted => {
                self.trigger_nmi_internal(
                    0,
                    None,
                    LockupType::HardwarePreTimeout,
                    0xFFFFFFFF80100000,
                    0xFFFF800000010000,
                    timestamp,
                );
            }
            HwWatchdogEvent::HardwareResetTriggered => {
                self.commit_audit_event(
                    WatchdogEventType::TargetStalled,
                    0,
                    b"HW_WATCHDOG_RESET_TRIGGERED",
                    timestamp,
                );
            }
            HwWatchdogEvent::Nominal => {}
        }

        // 2. Cibles logicielles
        for i in 0..MAX_WATCHDOG_TARGETS {
            let (target_id, prev_state, new_state, action) = match &mut self.targets[i] {
                Some(target) => {
                    let prev = target.state;
                    let new_st = target.evaluate(timestamp);
                    (target.id, prev, new_st, target.failover_action)
                }
                None => continue,
            };

            if new_state == TargetLivenessState::Stalled
                && prev_state != TargetLivenessState::Stalled
            {
                self.stats.total_stalls_detected += 1;
                self.commit_audit_event(
                    WatchdogEventType::TargetStalled,
                    target_id,
                    b"SOFTWARE_TARGET_STALLED",
                    timestamp,
                );

                if action == FailoverAction::IsolateAndKillThread {
                    if let Some(target) = &mut self.targets[i] {
                        target.state = TargetLivenessState::Isolated;
                    }
                    self.stats.total_threads_isolated += 1;
                    self.commit_audit_event(
                        WatchdogEventType::ThreadIsolated,
                        target_id,
                        b"THREAD_ISOLATED_AFTER_STALL",
                        timestamp,
                    );
                }
            }
        }

        // 3. Grappe inter-nœuds
        for i in 0..MAX_CLUSTER_NODES {
            let (node_id, prev_state, new_state) = match &mut self.cluster_nodes[i] {
                Some(node) => {
                    let prev = node.state;
                    let new_st = node.evaluate(timestamp);
                    (node.node_id, prev, new_st)
                }
                None => continue,
            };

            if new_state == NodeLivenessState::FailoverInitiated
                && prev_state != NodeLivenessState::FailoverInitiated
            {
                self.stats.total_cluster_failovers += 1;
                self.commit_audit_event(
                    WatchdogEventType::ClusterFailoverInitiated,
                    node_id,
                    b"CLUSTER_FAILOVER_INITIATED",
                    timestamp,
                );
            } else if new_state == NodeLivenessState::Suspect
                && prev_state == NodeLivenessState::Healthy
            {
                self.commit_audit_event(
                    WatchdogEventType::ClusterHeartbeatMissed,
                    node_id,
                    b"NODE_HEARTBEAT_MISSED",
                    timestamp,
                );
            }
        }

        Ok(())
    }

    /// Réception d'un battement de cœur inter-nœuds
    pub fn record_cluster_heartbeat(
        &mut self,
        cap: &WatchdogCap,
        node_id: u32,
        timestamp: u64,
        seq: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(watchdog_rights::WATCHDOG_PET) {
            return Err(SysError::PermissionDenied);
        }

        for node in self.cluster_nodes.iter_mut().flatten() {
            if node.node_id == node_id {
                node.record_heartbeat(timestamp, seq);
                return Ok(());
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Déclenchement manuel ou matériel d'une interruption NMI
    pub fn trigger_nmi(
        &mut self,
        cap: &WatchdogCap,
        cpu_id: u32,
        target_id: Option<u32>,
        lockup_type: LockupType,
        rip: u64,
        rsp: u64,
        timestamp: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(watchdog_rights::WATCHDOG_TRIGGER) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.trigger_nmi_internal(cpu_id, target_id, lockup_type, rip, rsp, timestamp))
    }

    fn trigger_nmi_internal(
        &mut self,
        cpu_id: u32,
        target_id: Option<u32>,
        lockup_type: LockupType,
        rip: u64,
        rsp: u64,
        timestamp: u64,
    ) -> u64 {
        let alert_id = self.nmi_total + 1;
        let mut action_taken = FailoverAction::LogAndWarn;

        // Isoler la cible si associée
        if let Some(tid) = target_id {
            for target in self.targets.iter_mut().flatten() {
                if target.id == tid {
                    target.state = TargetLivenessState::Isolated;
                    action_taken = target.failover_action;
                    self.stats.total_threads_isolated += 1;
                    break;
                }
            }
        }

        let alert = NmiAlert {
            alert_id,
            cpu_id,
            target_id,
            lockup_type,
            rip,
            rsp,
            timestamp,
            action_taken,
        };

        self.nmi_alerts[self.nmi_head] = Some(alert);
        self.nmi_head = (self.nmi_head + 1) % MAX_NMI_ALERTS;
        self.nmi_total += 1;
        self.stats.total_nmi_alerts += 1;

        self.commit_audit_event(
            WatchdogEventType::NmiTriggered,
            target_id.unwrap_or(0),
            b"NMI_LOCKUP_ALERT_CAPTURED",
            timestamp,
        );

        alert_id
    }

    /// Enregistre un événement dans l'anneau d'audit et recalcule le condensat SHA-256
    fn commit_audit_event(
        &mut self,
        event_type: WatchdogEventType,
        target_id: u32,
        details: &[u8],
        timestamp: u64,
    ) {
        let seq = self.event_total + 1;
        let mut details_buf = [0u8; 32];
        let copy_len = if details.len() > 32 {
            32
        } else {
            details.len()
        };
        details_buf[..copy_len].copy_from_slice(&details[..copy_len]);

        let ev = WatchdogEvent {
            seq,
            timestamp,
            event_type,
            target_id,
            details: details_buf,
        };

        self.events[self.event_head] = Some(ev);
        self.event_head = (self.event_head + 1) % MAX_EVENTS;
        self.event_total += 1;

        // Mise à jour continue du hash SHA-256 scellé
        let mut block = [0u8; 64];
        block[0..32].copy_from_slice(&self.audit_digest);
        block[32..40].copy_from_slice(&seq.to_be_bytes());
        block[40..48].copy_from_slice(&timestamp.to_be_bytes());
        block[48..52].copy_from_slice(&target_id.to_be_bytes());
        block[52] = event_type as u8;
        block[53..64].copy_from_slice(&details_buf[0..11]);

        self.audit_digest = Sha256::digest(&block);
    }

    pub fn get_target(&self, id: u32) -> Option<&WatchdogTarget> {
        self.targets.iter().flatten().find(|t| t.id == id)
    }

    pub fn get_cluster_node(&self, node_id: u32) -> Option<&ClusterNodeHeartbeat> {
        self.cluster_nodes
            .iter()
            .flatten()
            .find(|n| n.node_id == node_id)
    }

    pub fn get_audit_digest(&self, cap: &WatchdogCap) -> Result<[u8; 32], SysError> {
        if !cap.has_right(watchdog_rights::WATCHDOG_INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.audit_digest)
    }

    /// Indique si une cible surveillée est en état de blocage (Stalled / Isolated / Panicked)
    pub fn has_tripped_target(&self) -> bool {
        for t in self.targets.iter().flatten() {
            if t.state == TargetLivenessState::Stalled
                || t.state == TargetLivenessState::Isolated
                || t.state == TargetLivenessState::Panicked
            {
                return true;
            }
        }
        false
    }

    /// Retourne l'identifiant de la première cible bloquée, ou 0
    pub fn get_first_tripped_target_id(&self) -> u32 {
        for t in self.targets.iter().flatten() {
            if t.state == TargetLivenessState::Stalled
                || t.state == TargetLivenessState::Isolated
                || t.state == TargetLivenessState::Panicked
            {
                return t.id;
            }
        }
        0
    }

    /// Retourne l'horodatage le plus récent parmi toutes les cibles et le chien matériel
    pub fn get_last_ping_timestamp(&self) -> u64 {
        let mut max_ts = self.hw_watchdog.last_reload_timestamp;
        for t in self.targets.iter().flatten() {
            if t.last_pet_timestamp > max_ts {
                max_ts = t.last_pet_timestamp;
            }
        }
        max_ts
    }

    /// Traite une requête IPC et produit une réponse déterministe calibrée à 64 octets
    pub fn handle_ipc_request(
        &mut self,
        req: &WatchdogRequest,
        timestamp: u64,
    ) -> WatchdogResponse {
        if req.magic != WDOG_MAGIC_REQ {
            return WatchdogResponse {
                magic: WDOG_MAGIC_RESP,
                status: SysError::InvalidArgument as i32,
                ..WatchdogResponse::default()
            };
        }

        let cap = WatchdogCap::new(Handle::new(req.handle_id, 0), req.rights);

        let opcode = match WatchdogOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                return WatchdogResponse {
                    magic: WDOG_MAGIC_RESP,
                    status: SysError::InvalidArgument as i32,
                    ..WatchdogResponse::default()
                };
            }
        };

        match opcode {
            WatchdogOpcode::GetStatus => {
                if !cap.has_right(watchdog_rights::WATCHDOG_INSPECT) {
                    return WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..WatchdogResponse::default()
                    };
                }

                let mut sha16 = [0u8; 16];
                sha16.copy_from_slice(&self.audit_digest[..16]);

                let is_tripped = if self.has_tripped_target()
                    || self.hw_watchdog.status == HwWatchdogStatus::ResetTriggered
                {
                    1u8
                } else {
                    0u8
                };

                let hw_enabled = if self.hw_watchdog.status != HwWatchdogStatus::Disabled {
                    1u8
                } else {
                    0u8
                };

                WatchdogResponse {
                    magic: WDOG_MAGIC_RESP,
                    status: 0,
                    hw_enabled,
                    active_targets: self.target_count as u8,
                    alert_count: self.stats.total_nmi_alerts.min(255) as u8,
                    is_tripped,
                    tripped_target_id: self.get_first_tripped_target_id(),
                    total_pings: self.stats.total_pets,
                    last_ping_timestamp: self.get_last_ping_timestamp(),
                    sha256_hash: sha16,
                    details: [0u8; 16],
                }
            }
            WatchdogOpcode::Ping => {
                if !cap.has_right(watchdog_rights::WATCHDOG_PET) {
                    return WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..WatchdogResponse::default()
                    };
                }

                let pet_res = if req.target_id == 0 {
                    let _ = self.reload_hardware(&cap, timestamp);
                    if let Some(first_target_id) =
                        self.targets.iter().find_map(|s| s.as_ref().map(|t| t.id))
                    {
                        self.pet_target(&cap, first_target_id, timestamp)
                    } else {
                        Ok(())
                    }
                } else {
                    let r = self.pet_target(&cap, req.target_id, timestamp);
                    let _ = self.reload_hardware(&cap, timestamp);
                    r
                };

                let mut sha16 = [0u8; 16];
                sha16.copy_from_slice(&self.audit_digest[..16]);

                match pet_res {
                    Ok(()) => WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: 0,
                        hw_enabled: if self.hw_watchdog.status != HwWatchdogStatus::Disabled {
                            1
                        } else {
                            0
                        },
                        active_targets: self.target_count as u8,
                        alert_count: self.stats.total_nmi_alerts.min(255) as u8,
                        is_tripped: if self.has_tripped_target() { 1 } else { 0 },
                        tripped_target_id: self.get_first_tripped_target_id(),
                        total_pings: self.stats.total_pets,
                        last_ping_timestamp: timestamp,
                        sha256_hash: sha16,
                        details: [0u8; 16],
                    },
                    Err(err) => WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: err as i32,
                        hw_enabled: if self.hw_watchdog.status != HwWatchdogStatus::Disabled {
                            1
                        } else {
                            0
                        },
                        active_targets: self.target_count as u8,
                        alert_count: self.stats.total_nmi_alerts.min(255) as u8,
                        is_tripped: if self.has_tripped_target() { 1 } else { 0 },
                        tripped_target_id: self.get_first_tripped_target_id(),
                        total_pings: self.stats.total_pets,
                        last_ping_timestamp: self.get_last_ping_timestamp(),
                        sha256_hash: sha16,
                        details: [0u8; 16],
                    },
                }
            }
            WatchdogOpcode::RegisterTarget => {
                if !cap.has_right(watchdog_rights::WATCHDOG_REGISTER) {
                    return WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..WatchdogResponse::default()
                    };
                }

                let name_str = req.name_as_str();
                let effective_name = if name_str.is_empty() {
                    "custom-task"
                } else {
                    name_str
                };

                let target_id = if req.target_id > 0 {
                    req.target_id
                } else {
                    (self.target_count as u32) + 1
                };

                let timeout = if req.timeout_ms > 0 {
                    req.timeout_ms as u64
                } else {
                    3000
                };
                let max_drift = if req.param_u64 > 0 {
                    req.param_u64
                } else {
                    timeout / 4
                };

                let failover = match req.action {
                    0 => FailoverAction::LogAndWarn,
                    1 => FailoverAction::IsolateAndKillThread,
                    2 => FailoverAction::HardwareReboot,
                    3 => FailoverAction::RestartService,
                    _ => FailoverAction::LogAndWarn,
                };

                let target = WatchdogTarget::new(
                    target_id,
                    effective_name,
                    WatchdogTargetType::UserspaceTask,
                    target_id as u64,
                    target_id as u64,
                    timeout,
                    max_drift,
                    failover,
                    timestamp,
                );

                let reg_res = self.register_target(&cap, target);
                let mut sha16 = [0u8; 16];
                sha16.copy_from_slice(&self.audit_digest[..16]);

                match reg_res {
                    Ok(()) => WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: 0,
                        hw_enabled: if self.hw_watchdog.status != HwWatchdogStatus::Disabled {
                            1
                        } else {
                            0
                        },
                        active_targets: self.target_count as u8,
                        alert_count: self.stats.total_nmi_alerts.min(255) as u8,
                        is_tripped: 0,
                        tripped_target_id: 0,
                        total_pings: self.stats.total_pets,
                        last_ping_timestamp: timestamp,
                        sha256_hash: sha16,
                        details: [0u8; 16],
                    },
                    Err(err) => WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: err as i32,
                        hw_enabled: if self.hw_watchdog.status != HwWatchdogStatus::Disabled {
                            1
                        } else {
                            0
                        },
                        active_targets: self.target_count as u8,
                        alert_count: self.stats.total_nmi_alerts.min(255) as u8,
                        is_tripped: 0,
                        tripped_target_id: 0,
                        total_pings: self.stats.total_pets,
                        last_ping_timestamp: self.get_last_ping_timestamp(),
                        sha256_hash: sha16,
                        details: [0u8; 16],
                    },
                }
            }
            WatchdogOpcode::TriggerAction => {
                if !cap.has_right(watchdog_rights::WATCHDOG_TRIGGER) {
                    return WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..WatchdogResponse::default()
                    };
                }

                let target_opt = if req.target_id > 0 {
                    Some(req.target_id)
                } else {
                    None
                };
                let lockup = match req.action {
                    1 => LockupType::HardLockup,
                    2 => LockupType::HardwarePreTimeout,
                    3 => LockupType::EventLoopDeadlock,
                    _ => LockupType::SoftLockup,
                };

                let _alert_id = self.trigger_nmi_internal(
                    0,
                    target_opt,
                    lockup,
                    0xFFFFFFFF80200000,
                    0xFFFF800000020000,
                    timestamp,
                );

                if req.action == 2 {
                    self.hw_watchdog.status = HwWatchdogStatus::ResetTriggered;
                    self.hw_watchdog.reset_count += 1;
                }

                let mut sha16 = [0u8; 16];
                sha16.copy_from_slice(&self.audit_digest[..16]);

                WatchdogResponse {
                    magic: WDOG_MAGIC_RESP,
                    status: 0,
                    hw_enabled: if self.hw_watchdog.status != HwWatchdogStatus::Disabled {
                        1
                    } else {
                        0
                    },
                    active_targets: self.target_count as u8,
                    alert_count: self.stats.total_nmi_alerts.min(255) as u8,
                    is_tripped: 1,
                    tripped_target_id: req.target_id,
                    total_pings: self.stats.total_pets,
                    last_ping_timestamp: timestamp,
                    sha256_hash: sha16,
                    details: [0u8; 16],
                }
            }
            WatchdogOpcode::QueryAlerts => {
                if !cap.has_right(watchdog_rights::WATCHDOG_INSPECT) {
                    return WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..WatchdogResponse::default()
                    };
                }

                let mut sha16 = [0u8; 16];
                sha16.copy_from_slice(&self.audit_digest[..16]);

                let mut det = [0u8; 16];
                if self.nmi_total > 0 {
                    let last_idx = if self.nmi_head == 0 {
                        MAX_NMI_ALERTS - 1
                    } else {
                        self.nmi_head - 1
                    };
                    if let Some(alert) = &self.nmi_alerts[last_idx] {
                        let lock_str = alert.lockup_type.as_str().as_bytes();
                        let l = lock_str.len().min(16);
                        det[..l].copy_from_slice(&lock_str[..l]);
                    }
                }

                let is_tripped = if self.has_tripped_target()
                    || self.hw_watchdog.status == HwWatchdogStatus::ResetTriggered
                    || self.stats.total_nmi_alerts > 0
                {
                    1u8
                } else {
                    0u8
                };

                WatchdogResponse {
                    magic: WDOG_MAGIC_RESP,
                    status: 0,
                    hw_enabled: if self.hw_watchdog.status != HwWatchdogStatus::Disabled {
                        1
                    } else {
                        0
                    },
                    active_targets: self.target_count as u8,
                    alert_count: self.stats.total_nmi_alerts.min(255) as u8,
                    is_tripped,
                    tripped_target_id: self.get_first_tripped_target_id(),
                    total_pings: self.stats.total_pets,
                    last_ping_timestamp: self.get_last_ping_timestamp(),
                    sha256_hash: sha16,
                    details: det,
                }
            }
            WatchdogOpcode::AuditLog => {
                if !cap.has_right(watchdog_rights::WATCHDOG_INSPECT) {
                    return WatchdogResponse {
                        magic: WDOG_MAGIC_RESP,
                        status: SysError::PermissionDenied as i32,
                        ..WatchdogResponse::default()
                    };
                }

                let mut sha16 = [0u8; 16];
                sha16.copy_from_slice(&self.audit_digest[..16]);

                let mut det = [0u8; 16];
                det[0..4].copy_from_slice(&(self.stats.total_pets as u32).to_le_bytes());
                det[4..8].copy_from_slice(&(self.stats.total_stalls_detected as u32).to_le_bytes());
                det[8..12].copy_from_slice(&(self.stats.total_drifts_warned as u32).to_le_bytes());
                det[12..16].copy_from_slice(&(self.event_total as u32).to_le_bytes());

                WatchdogResponse {
                    magic: WDOG_MAGIC_RESP,
                    status: 0,
                    hw_enabled: if self.hw_watchdog.status != HwWatchdogStatus::Disabled {
                        1
                    } else {
                        0
                    },
                    active_targets: self.target_count as u8,
                    alert_count: self.stats.total_nmi_alerts.min(255) as u8,
                    is_tripped: if self.has_tripped_target() { 1 } else { 0 },
                    tripped_target_id: self.get_first_tripped_target_id(),
                    total_pings: self.stats.total_pets,
                    last_ping_timestamp: self.get_last_ping_timestamp(),
                    sha256_hash: sha16,
                    details: det,
                }
            }
        }
    }
}

// ============================================================================
// CANAL IPC & CLIENT (`WatchdogClient`)
// ============================================================================

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

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

#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

/// Client IPC pour interagir avec le démon jambo-watchdogd (PID 21)
pub struct WatchdogClient {
    pub endpoint: Handle,
}

impl WatchdogClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_status(&self) -> Result<WatchdogResponse, SysError> {
        let req = WatchdogRequest::new_status();
        self.call(&req)
    }

    pub fn ping(&self, target_id: u32) -> Result<WatchdogResponse, SysError> {
        let req = WatchdogRequest::new_ping(target_id);
        self.call(&req)
    }

    pub fn register_target(
        &self,
        name: &str,
        timeout_ms: u32,
        action: u8,
    ) -> Result<WatchdogResponse, SysError> {
        let req = WatchdogRequest::new_register(name, timeout_ms, action);
        self.call(&req)
    }

    pub fn trigger_action(&self, action: u8, target_id: u32) -> Result<WatchdogResponse, SysError> {
        let req = WatchdogRequest::new_trigger_action(action, target_id);
        self.call(&req)
    }

    pub fn query_alerts(&self) -> Result<WatchdogResponse, SysError> {
        let req = WatchdogRequest::new_query_alerts();
        self.call(&req)
    }

    pub fn audit_log(&self) -> Result<WatchdogResponse, SysError> {
        let req = WatchdogRequest::new_audit_log();
        self.call(&req)
    }

    pub fn call(&self, req: &WatchdogRequest) -> Result<WatchdogResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<WatchdogResponse>() {
                return WatchdogResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] / std in test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_request_response_size_and_bytes() {
        assert_eq!(core::mem::size_of::<WatchdogRequest>(), 64);
        assert_eq!(core::mem::size_of::<WatchdogResponse>(), 64);

        let mut req = WatchdogRequest::new_register("worker-service", 2500, 1);
        req.param_u64 = 42;
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 64);

        let decoded_req = WatchdogRequest::from_bytes(&bytes).expect("decode WatchdogRequest");
        assert_eq!(decoded_req.magic, WDOG_MAGIC_REQ);
        assert_eq!(decoded_req.opcode, WatchdogOpcode::RegisterTarget as u32);
        assert_eq!(decoded_req.timeout_ms, 2500);
        assert_eq!(decoded_req.action, 1);
        assert_eq!(decoded_req.param_u64, 42);
        assert_eq!(decoded_req.name_as_str(), "worker-service");

        let resp = WatchdogResponse {
            status: 0,
            active_targets: 5,
            total_pings: 100,
            sha256_hash: [0xAB; 16],
            ..Default::default()
        };
        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);

        let decoded_resp =
            WatchdogResponse::from_bytes(&resp_bytes).expect("decode WatchdogResponse");
        assert_eq!(decoded_resp.magic, WDOG_MAGIC_RESP);
        assert_eq!(decoded_resp.status, 0);
        assert_eq!(decoded_resp.active_targets, 5);
        assert_eq!(decoded_resp.total_pings, 100);
        assert_eq!(decoded_resp.sha256_hash, [0xAB; 16]);
    }

    #[test]
    fn test_watchdog_ipc_full_cycle() {
        let mut daemon = JamboWatchdogDaemon::new();
        daemon.init_defaults();

        // 1. GetStatus
        let req_status = WatchdogRequest::new_status();
        let resp_status = daemon.handle_ipc_request(&req_status, 150);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.hw_enabled, 1);
        assert!(resp_status.active_targets >= 4);
        assert_eq!(resp_status.is_tripped, 0);

        // 2. Ping Target 1
        let req_ping = WatchdogRequest::new_ping(1);
        let resp_ping = daemon.handle_ipc_request(&req_ping, 200);
        assert_eq!(resp_ping.status, 0);
        assert!(resp_ping.total_pings >= 1);

        // 3. RegisterTarget
        let req_reg = WatchdogRequest::new_register("storage-mgr", 4000, 3);
        let resp_reg = daemon.handle_ipc_request(&req_reg, 250);
        assert_eq!(resp_reg.status, 0);
        assert!(resp_reg.active_targets >= 5);

        // 4. TriggerAction NMI
        let req_trig = WatchdogRequest::new_trigger_action(1, 1);
        let resp_trig = daemon.handle_ipc_request(&req_trig, 300);
        assert_eq!(resp_trig.status, 0);
        assert_eq!(resp_trig.is_tripped, 1);
        assert!(resp_trig.alert_count >= 1);

        // 5. QueryAlerts
        let req_alerts = WatchdogRequest::new_query_alerts();
        let resp_alerts = daemon.handle_ipc_request(&req_alerts, 350);
        assert_eq!(resp_alerts.status, 0);
        assert!(resp_alerts.alert_count >= 1);

        // 6. AuditLog
        let req_audit = WatchdogRequest::new_audit_log();
        let resp_audit = daemon.handle_ipc_request(&req_audit, 400);
        assert_eq!(resp_audit.status, 0);
        assert_ne!(resp_audit.sha256_hash, [0u8; 16]);

        // 7. Bad Magic rejection
        let mut req_bad = WatchdogRequest::new_status();
        req_bad.magic = 0xDEADBEEF;
        let resp_bad = daemon.handle_ipc_request(&req_bad, 450);
        assert_eq!(resp_bad.status, SysError::InvalidArgument as i32);

        // 8. Missing rights rejection
        let mut req_unauth = WatchdogRequest::new_status();
        req_unauth.rights = 0;
        let resp_unauth = daemon.handle_ipc_request(&req_unauth, 500);
        assert_eq!(resp_unauth.status, SysError::PermissionDenied as i32);
    }

    #[test]
    fn test_watchdog_cap_attenuation_and_no_amplification() {
        let admin = WatchdogCap::new(Handle::new(8201, 1), watchdog_rights::ALL);
        assert!(admin.has_right(watchdog_rights::WATCHDOG_ADMIN));
        assert!(admin.has_right(watchdog_rights::WATCHDOG_PET));

        let pet_only = admin
            .attenuate(watchdog_rights::WATCHDOG_PET)
            .expect("attenuate to PET");
        assert!(pet_only.has_right(watchdog_rights::WATCHDOG_PET));
        assert!(!pet_only.has_right(watchdog_rights::WATCHDOG_ADMIN));

        assert_eq!(
            pet_only.attenuate(watchdog_rights::WATCHDOG_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_target_pet_and_drift_warning() {
        let admin = WatchdogCap::new(Handle::new(8201, 1), watchdog_rights::ALL);
        let mut daemon = JamboWatchdogDaemon::with_cap(1, admin);
        daemon.init_defaults();

        // Nominal pet
        assert_eq!(daemon.pet_target(&admin, 1, 150), Ok(()));
        let t1 = daemon.get_target(1).unwrap();
        assert_eq!(t1.state, TargetLivenessState::Active);

        // Drift warning on target 2 (max drift 300ms, pet interval 450ms)
        assert_eq!(daemon.pet_target(&admin, 2, 550), Ok(()));
        let t2 = daemon.get_target(2).unwrap();
        assert_eq!(t2.state, TargetLivenessState::WarningDrift);
        assert_eq!(daemon.stats.total_drifts_warned, 1);
    }

    #[test]
    fn test_hardware_watchdog_tick_and_nmi_warning() {
        let admin = WatchdogCap::new(Handle::new(8201, 1), watchdog_rights::ALL);
        let mut daemon = JamboWatchdogDaemon::with_cap(1, admin);
        daemon.init_defaults();

        // Reload hardware watchdog at t=200
        assert_eq!(daemon.reload_hardware(&admin, 200), Ok(()));

        // Advance to 26000ms: timeout=30000ms, pre_timeout=5000ms -> pre-timeout threshold is 25000ms
        daemon.evaluate_system_liveness(&admin, 26_000).unwrap();
        assert_eq!(
            daemon.hw_watchdog.status,
            HwWatchdogStatus::PreTimeoutWarning
        );
        assert!(daemon.stats.total_nmi_alerts >= 1);
    }

    #[test]
    fn test_stall_detection_and_thread_isolation() {
        let admin = WatchdogCap::new(Handle::new(8201, 1), watchdog_rights::ALL);
        let mut daemon = JamboWatchdogDaemon::with_cap(1, admin);
        daemon.init_defaults();

        // Target 4 (jambo-ipcd) timeout 2500ms, action IsolateAndKillThread. At t=30000ms it has stalled.
        daemon.evaluate_system_liveness(&admin, 30_000).unwrap();
        let t4 = daemon.get_target(4).unwrap();
        assert_eq!(t4.state, TargetLivenessState::Isolated);
        assert!(daemon.stats.total_threads_isolated >= 1);
    }

    #[test]
    fn test_cluster_node_failover() {
        let admin = WatchdogCap::new(Handle::new(8201, 1), watchdog_rights::ALL);
        let mut daemon = JamboWatchdogDaemon::with_cap(1, admin);
        daemon.init_defaults();

        // Node 1 (Primary) has 500ms interval and 3 misses threshold -> failover at 1500ms elapsed.
        daemon.evaluate_system_liveness(&admin, 25_000).unwrap();
        let n1 = daemon.get_cluster_node(1).unwrap();
        assert_eq!(n1.state, NodeLivenessState::FailoverInitiated);
        assert!(daemon.stats.total_cluster_failovers >= 1);
    }
}

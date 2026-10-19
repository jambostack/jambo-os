//! Démon de Diagnostic Matériel Autonome, Auto-Réparation & Télémétrie de Pannes (`jambo-diagd`)
//!
//! Fournit un sous-système de surveillance proactive des bus (PCIe, NVMe, VirtIO, Mémoire ECC, CPU MCA),
//! d'application de stratégies d'auto-remédiation à chaud (Link Retraining, FLR, repli dégradé, bascule
//! sur périphérique de secours / Hot-Failover), d'audit cryptographique inviolable par journal scellé SHA-256,
//! et de contrôle d'accès capabilaire strict via `DiagCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_DEVICES: usize = 32;
pub const MAX_INCIDENTS: usize = 64;
pub const MAX_NAME_LEN: usize = 32;

pub const ECC_CORRECTABLE_THRESHOLD: u32 = 10;
pub const PCIE_AER_CORRECTABLE_THRESHOLD: u32 = 8;
pub const PCIE_AER_FATAL_THRESHOLD: u32 = 1;
pub const NVME_MEDIA_ERR_THRESHOLD: u32 = 5;
pub const VIRTIO_QUEUE_ERR_THRESHOLD: u32 = 3;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 standard `#![no_std]` sans allocation
#[derive(Clone, Copy)]
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
            0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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
// MODÈLE DE SÉCURITÉ CAPABILAIRE : DiagCap
// ============================================================================

pub mod diag_rights {
    pub const DIAG_INSPECT: u32 = 1 << 0;
    pub const DIAG_SCAN: u32 = 1 << 1;
    pub const DIAG_REMEDIATE: u32 = 1 << 2;
    pub const DIAG_RESET: u32 = 1 << 3;
    pub const DIAG_TELEMETRY: u32 = 1 << 4;
    pub const DIAG_ADMIN: u32 = 1 << 5;

    pub const ALL: u32 =
        DIAG_INSPECT | DIAG_SCAN | DIAG_REMEDIATE | DIAG_RESET | DIAG_TELEMETRY | DIAG_ADMIN;
}

/// Capacité d'administration et de diagnostic matériel sans autorité ambiante
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagCap {
    pub handle: Handle,
    pub rights: u32,
}

impl DiagCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les privilèges de la capacité vers un sous-ensemble strict.
    /// Interdit formellement toute amplification de privilèges.
    pub fn attenuate(&self, new_rights: u32) -> Result<DiagCap, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(DiagCap {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES DE TÉLÉMÉTRIE MATÉRIELLE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusType {
    Pcie,
    Nvme,
    Virtio,
    MemoryEcc,
    CpuMca,
}

impl BusType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BusType::Pcie => "PCIe",
            BusType::Nvme => "NVMe",
            BusType::Virtio => "VirtIO",
            BusType::MemoryEcc => "DDR-ECC",
            BusType::CpuMca => "CPU-MCA",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pcie" | "PCIe" => Some(BusType::Pcie),
            "nvme" | "NVMe" => Some(BusType::Nvme),
            "virtio" | "VirtIO" => Some(BusType::Virtio),
            "ecc" | "DDR-ECC" => Some(BusType::MemoryEcc),
            "mca" | "CPU-MCA" => Some(BusType::CpuMca),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStatus {
    Healthy,
    Warning,
    Degraded,
    Quarantined,
    Resetting,
    Failed,
    Remediated,
}

impl DeviceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceStatus::Healthy => "HEALTHY",
            DeviceStatus::Warning => "WARNING",
            DeviceStatus::Degraded => "DEGRADED",
            DeviceStatus::Quarantined => "QUARANTINED",
            DeviceStatus::Resetting => "RESETTING",
            DeviceStatus::Failed => "FAILED",
            DeviceStatus::Remediated => "REMEDIATED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemediationAction {
    None,
    LinkRetrained,
    FlrReset,
    DegradedModeFallback,
    HotFailoverExecuted,
    Quarantined,
}

impl RemediationAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            RemediationAction::None => "NONE",
            RemediationAction::LinkRetrained => "LINK_RETRAINED",
            RemediationAction::FlrReset => "FLR_RESET",
            RemediationAction::DegradedModeFallback => "DEGRADED_FALLBACK",
            RemediationAction::HotFailoverExecuted => "HOT_FAILOVER",
            RemediationAction::Quarantined => "QUARANTINED",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "none" | "NONE" => Some(RemediationAction::None),
            "retrain" | "link_retrain" | "LINK_RETRAINED" => Some(RemediationAction::LinkRetrained),
            "flr" | "reset" | "FLR_RESET" => Some(RemediationAction::FlrReset),
            "degraded" | "fallback" | "DEGRADED_FALLBACK" => Some(RemediationAction::DegradedModeFallback),
            "failover" | "hot_failover" | "HOT_FAILOVER" => Some(RemediationAction::HotFailoverExecuted),
            "quarantine" | "isolate" | "QUARANTINED" => Some(RemediationAction::Quarantined),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultSeverity {
    Info,
    Warning,
    Critical,
    Fatal,
}

impl FaultSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            FaultSeverity::Info => "INFO",
            FaultSeverity::Warning => "WARN",
            FaultSeverity::Critical => "CRIT",
            FaultSeverity::Fatal => "FATAL",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareErrorType {
    EccCorrectable,
    EccUncorrectable,
    PcieAerCorrectable,
    PcieAerFatal,
    NvmeMediaError,
    NvmeThermalThrottle,
    VirtioQueueDesync,
    VirtioDescCorrupt,
    CpuMcaBankError,
}

impl HardwareErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            HardwareErrorType::EccCorrectable => "ECC_CORRECTABLE",
            HardwareErrorType::EccUncorrectable => "ECC_UNCORRECTABLE",
            HardwareErrorType::PcieAerCorrectable => "PCIE_AER_CORR",
            HardwareErrorType::PcieAerFatal => "PCIE_AER_FATAL",
            HardwareErrorType::NvmeMediaError => "NVME_MEDIA_ERR",
            HardwareErrorType::NvmeThermalThrottle => "NVME_THERMAL",
            HardwareErrorType::VirtioQueueDesync => "VIRTIO_QUEUE_DESYNC",
            HardwareErrorType::VirtioDescCorrupt => "VIRTIO_DESC_CORRUPT",
            HardwareErrorType::CpuMcaBankError => "CPU_MCA_BANK_ERR",
        }
    }
}

/// Description et état opérationnel d'un composant matériel surveillé
#[derive(Clone, Copy, Debug)]
pub struct HardwareDevice {
    pub id: u32,
    pub bdf: (u8, u8, u8), // Bus, Device, Function (ex: 0, 1, 0)
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub bus_type: BusType,
    pub status: DeviceStatus,
    pub health_score: u8, // 0 à 100
    pub ecc_correctable_count: u32,
    pub ecc_uncorrectable_count: u32,
    pub pcie_aer_correctable_count: u32,
    pub pcie_aer_fatal_count: u32,
    pub nvme_errors_count: u32,
    pub virtio_errors_count: u32,
    pub remediation_count: u32,
    pub last_action: RemediationAction,
    pub is_spare: bool,
    pub spare_target_id: Option<u32>,
    pub is_active: bool,
}

impl HardwareDevice {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            bdf: (0, 0, 0),
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            bus_type: BusType::Pcie,
            status: DeviceStatus::Healthy,
            health_score: 100,
            ecc_correctable_count: 0,
            ecc_uncorrectable_count: 0,
            pcie_aer_correctable_count: 0,
            pcie_aer_fatal_count: 0,
            nvme_errors_count: 0,
            virtio_errors_count: 0,
            remediation_count: 0,
            last_action: RemediationAction::None,
            is_spare: false,
            spare_target_id: None,
            is_active: false,
        }
    }

    pub fn new(id: u32, name: &str, bus_type: BusType, bdf: (u8, u8, u8)) -> Self {
        let mut dev = Self::empty();
        dev.id = id;
        dev.set_name(name);
        dev.bus_type = bus_type;
        dev.bdf = bdf;
        dev.is_active = true;
        dev
    }

    pub fn set_name(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unknown")
    }

    pub fn recompute_health(&mut self) {
        if !self.is_active || self.status == DeviceStatus::Quarantined {
            self.health_score = 0;
            return;
        }

        if self.pcie_aer_fatal_count > 0 || self.ecc_uncorrectable_count > 0 {
            self.health_score = 0;
            self.status = DeviceStatus::Failed;
            return;
        }

        let mut score: i32 = 100;

        let ecc_pen = ((self.ecc_correctable_count as i32) * 2).min(30);
        let pcie_pen = ((self.pcie_aer_correctable_count as i32) * 3).min(30);
        let nvme_pen = ((self.nvme_errors_count as i32) * 8).min(50);
        let virt_pen = ((self.virtio_errors_count as i32) * 10).min(50);

        score -= ecc_pen + pcie_pen + nvme_pen + virt_pen;
        if score < 0 {
            score = 0;
        }

        self.health_score = score as u8;

        if self.health_score == 0 {
            self.status = DeviceStatus::Failed;
        } else if self.health_score < 40 {
            self.status = DeviceStatus::Degraded;
        } else if self.health_score < 80 {
            self.status = DeviceStatus::Warning;
        } else if self.last_action != RemediationAction::None {
            self.status = DeviceStatus::Remediated;
        } else {
            self.status = DeviceStatus::Healthy;
        }
    }
}

/// Incident matériel consigné dans le journal inviolable scellé par SHA-256
#[derive(Clone, Copy, Debug)]
pub struct FaultIncident {
    pub incident_id: u64,
    pub timestamp: u64,
    pub device_id: u32,
    pub device_name: [u8; MAX_NAME_LEN],
    pub device_name_len: usize,
    pub error_type: HardwareErrorType,
    pub severity: FaultSeverity,
    pub remediation: RemediationAction,
    pub incident_hash: [u8; 32],
}

impl FaultIncident {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.device_name[..self.device_name_len]).unwrap_or("unknown")
    }
}

/// Synthèse de scan de bus matériel
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanSummary {
    pub devices_scanned: usize,
    pub healthy_count: usize,
    pub warning_count: usize,
    pub degraded_count: usize,
    pub failed_count: usize,
    pub mean_health_score: u8,
}

/// Statistiques globales de diagnostic et remédiation
#[derive(Clone, Copy, Debug, Default)]
pub struct DiagStats {
    pub total_errors: u64,
    pub total_remediations: u64,
    pub link_retrains: u64,
    pub flr_resets: u64,
    pub hot_failovers: u64,
    pub quarantines: u64,
    pub degraded_fallbacks: u64,
}

// ============================================================================
// DÉMON PRINCIPAL : JamboDiagDaemon
// ============================================================================

pub struct JamboDiagDaemon {
    pub node_id: u64,
    pub admin_cap: DiagCap,
    pub devices: [Option<HardwareDevice>; MAX_DEVICES],
    pub device_count: usize,
    pub incidents: [Option<FaultIncident>; MAX_INCIDENTS],
    pub incident_head: usize,
    pub incident_total: u64,
    pub stats: DiagStats,
    pub latest_hash: [u8; 32],
    pub auto_remediation_enabled: bool,
}

impl JamboDiagDaemon {
    pub const fn empty(node_id: u64, admin_cap: DiagCap) -> Self {
        Self {
            node_id,
            admin_cap,
            devices: [None; MAX_DEVICES],
            device_count: 0,
            incidents: [None; MAX_INCIDENTS],
            incident_head: 0,
            incident_total: 0,
            stats: DiagStats {
                total_errors: 0,
                total_remediations: 0,
                link_retrains: 0,
                flr_resets: 0,
                hot_failovers: 0,
                quarantines: 0,
                degraded_fallbacks: 0,
            },
            latest_hash: [0u8; 32],
            auto_remediation_enabled: true,
        }
    }

    pub fn new(node_id: u64, admin_cap: DiagCap) -> Self {
        let mut d = Self::empty(node_id, admin_cap);
        d.latest_hash = Sha256::digest(b"JAMBO_DIAG_GENESIS_ROOT");
        d
    }

    /// Enregistre l'inventaire matériel par défaut du système
    pub fn init_defaults(&mut self) {
        let dev1 = HardwareDevice::new(1, "pcie-root-0", BusType::Pcie, (0, 0, 0));
        let mut dev2 = HardwareDevice::new(2, "virtio-net-0", BusType::Virtio, (0, 1, 0));
        dev2.spare_target_id = Some(3);

        let mut dev3 = HardwareDevice::new(3, "virtio-net-spare", BusType::Virtio, (0, 2, 0));
        dev3.is_spare = true;

        let mut dev4 = HardwareDevice::new(4, "nvme-ctrl-0", BusType::Nvme, (0, 3, 0));
        dev4.spare_target_id = Some(5);

        let mut dev5 = HardwareDevice::new(5, "nvme-ctrl-spare", BusType::Nvme, (0, 4, 0));
        dev5.is_spare = true;

        let dev6 = HardwareDevice::new(6, "ddr5-ecc-dimm0", BusType::MemoryEcc, (0, 0, 0));
        let dev7 = HardwareDevice::new(7, "virtio-blk-0", BusType::Virtio, (0, 5, 0));
        let dev8 = HardwareDevice::new(8, "cpu-mca-core0", BusType::CpuMca, (0, 0, 0));

        self.devices[0] = Some(dev1);
        self.devices[1] = Some(dev2);
        self.devices[2] = Some(dev3);
        self.devices[3] = Some(dev4);
        self.devices[4] = Some(dev5);
        self.devices[5] = Some(dev6);
        self.devices[6] = Some(dev7);
        self.devices[7] = Some(dev8);
        self.device_count = 8;
    }

    /// Enregistre un nouveau périphérique matériel sous contrôle capabilaire strict
    pub fn register_device(&mut self, cap: &DiagCap, dev: HardwareDevice) -> Result<u32, SysError> {
        if !cap.has_right(diag_rights::DIAG_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        if self.device_count >= MAX_DEVICES {
            return Err(SysError::OutOfMemory);
        }

        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                let id = dev.id;
                *slot = Some(dev);
                self.device_count += 1;
                return Ok(id);
            }
        }
        Err(SysError::OutOfMemory)
    }

    pub fn get_device(&self, id: u32) -> Option<&HardwareDevice> {
        for slot in self.devices.iter().flatten() {
            if slot.id == id {
                return Some(slot);
            }
        }
        None
    }

    pub fn get_device_mut(&mut self, id: u32) -> Option<&mut HardwareDevice> {
        for slot in self.devices.iter_mut().flatten() {
            if slot.id == id {
                return Some(slot);
            }
        }
        None
    }

    pub fn find_device_by_name(&self, name: &str) -> Option<&HardwareDevice> {
        for slot in self.devices.iter().flatten() {
            if slot.name_as_str() == name {
                return Some(slot);
            }
        }
        None
    }

    /// Calcule le score global de santé matérielle de la grappe (moyenne pondérée 0-100)
    pub fn global_health_score(&self) -> u8 {
        let mut total: u32 = 0;
        let mut count: u32 = 0;
        for dev in self.devices.iter().flatten() {
            if dev.is_active && !dev.is_spare {
                total += dev.health_score as u32;
                count += 1;
            }
        }
        if count == 0 {
            100
        } else {
            (total / count) as u8
        }
    }

    /// Active ou désactive le moteur d'auto-remédiation autonome
    pub fn set_auto_remediation(&mut self, cap: &DiagCap, enabled: bool) -> Result<(), SysError> {
        if !cap.has_right(diag_rights::DIAG_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        self.auto_remediation_enabled = enabled;
        Ok(())
    }

    /// Signale une erreur matérielle et déclenche le processus d'auto-remédiation
    pub fn record_error(
        &mut self,
        cap: &DiagCap,
        dev_id: u32,
        err_type: HardwareErrorType,
        timestamp: u64,
    ) -> Result<RemediationAction, SysError> {
        if !cap.has_right(diag_rights::DIAG_SCAN)
            && !cap.has_right(diag_rights::DIAG_REMEDIATE)
            && !cap.has_right(diag_rights::DIAG_ADMIN)
        {
            return Err(SysError::PermissionDenied);
        }

        let dev_idx = self
            .devices
            .iter()
            .position(|slot| slot.as_ref().map(|d| d.id) == Some(dev_id))
            .ok_or(SysError::InvalidArgument)?;

        let mut auto_action = RemediationAction::None;
        let severity;

        {
            let dev = self.devices[dev_idx].as_mut().unwrap();
            self.stats.total_errors += 1;

            match err_type {
                HardwareErrorType::EccCorrectable => {
                    dev.ecc_correctable_count += 1;
                    if dev.ecc_correctable_count >= ECC_CORRECTABLE_THRESHOLD {
                        auto_action = RemediationAction::DegradedModeFallback;
                        severity = FaultSeverity::Critical;
                    } else {
                        severity = FaultSeverity::Warning;
                    }
                }
                HardwareErrorType::EccUncorrectable => {
                    dev.ecc_uncorrectable_count += 1;
                    auto_action = RemediationAction::Quarantined;
                    severity = FaultSeverity::Fatal;
                }
                HardwareErrorType::PcieAerCorrectable => {
                    dev.pcie_aer_correctable_count += 1;
                    if dev.pcie_aer_correctable_count >= PCIE_AER_CORRECTABLE_THRESHOLD {
                        auto_action = RemediationAction::LinkRetrained;
                        severity = FaultSeverity::Critical;
                    } else {
                        severity = FaultSeverity::Warning;
                    }
                }
                HardwareErrorType::PcieAerFatal => {
                    dev.pcie_aer_fatal_count += 1;
                    if dev.pcie_aer_fatal_count >= 2 {
                        auto_action = RemediationAction::Quarantined;
                    } else {
                        auto_action = RemediationAction::FlrReset;
                    }
                    severity = FaultSeverity::Fatal;
                }
                HardwareErrorType::NvmeMediaError => {
                    dev.nvme_errors_count += 1;
                    if dev.nvme_errors_count >= NVME_MEDIA_ERR_THRESHOLD {
                        if dev.spare_target_id.is_some() {
                            auto_action = RemediationAction::HotFailoverExecuted;
                        } else {
                            auto_action = RemediationAction::DegradedModeFallback;
                        }
                        severity = FaultSeverity::Critical;
                    } else {
                        severity = FaultSeverity::Warning;
                    }
                }
                HardwareErrorType::NvmeThermalThrottle => {
                    dev.nvme_errors_count += 1;
                    auto_action = RemediationAction::DegradedModeFallback;
                    severity = FaultSeverity::Warning;
                }
                HardwareErrorType::VirtioQueueDesync | HardwareErrorType::VirtioDescCorrupt => {
                    dev.virtio_errors_count += 1;
                    if dev.virtio_errors_count >= VIRTIO_QUEUE_ERR_THRESHOLD {
                        if dev.spare_target_id.is_some() {
                            auto_action = RemediationAction::HotFailoverExecuted;
                        } else {
                            auto_action = RemediationAction::FlrReset;
                        }
                        severity = FaultSeverity::Critical;
                    } else {
                        auto_action = RemediationAction::FlrReset;
                        severity = FaultSeverity::Warning;
                    }
                }
                HardwareErrorType::CpuMcaBankError => {
                    auto_action = RemediationAction::Quarantined;
                    severity = FaultSeverity::Fatal;
                }
            }

            dev.recompute_health();
        }

        // Si l'auto-remédiation est activée et qu'une action est requise, on l'applique
        if self.auto_remediation_enabled && auto_action != RemediationAction::None {
            self.apply_remediation_internal(dev_id, auto_action)?;
        }

        // Consignation dans le journal d'incidents scellé
        let dev_name = {
            let dev = self.devices[dev_idx].as_ref().unwrap();
            let mut buf = [0u8; MAX_NAME_LEN];
            let len = dev.name_len;
            buf[..len].copy_from_slice(&dev.name[..len]);
            (buf, len)
        };

        self.record_incident(
            dev_id,
            dev_name.0,
            dev_name.1,
            err_type,
            severity,
            auto_action,
            timestamp,
        );

        Ok(auto_action)
    }

    /// Exécute explicitement une stratégie de remédiation sous contrôle capabilaire
    pub fn execute_remediation(
        &mut self,
        cap: &DiagCap,
        dev_id: u32,
        action: RemediationAction,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(diag_rights::DIAG_REMEDIATE) && !cap.has_right(diag_rights::DIAG_ADMIN) {
            return Err(SysError::PermissionDenied);
        }

        let dev_idx = self
            .devices
            .iter()
            .position(|slot| slot.as_ref().map(|d| d.id) == Some(dev_id))
            .ok_or(SysError::InvalidArgument)?;

        self.apply_remediation_internal(dev_id, action)?;

        let dev_name = {
            let dev = self.devices[dev_idx].as_ref().unwrap();
            let mut buf = [0u8; MAX_NAME_LEN];
            let len = dev.name_len;
            buf[..len].copy_from_slice(&dev.name[..len]);
            (buf, len)
        };

        self.record_incident(
            dev_id,
            dev_name.0,
            dev_name.1,
            HardwareErrorType::PcieAerCorrectable,
            FaultSeverity::Info,
            action,
            timestamp,
        );

        Ok(())
    }

    fn apply_remediation_internal(
        &mut self,
        dev_id: u32,
        action: RemediationAction,
    ) -> Result<(), SysError> {
        let dev_idx = self
            .devices
            .iter()
            .position(|slot| slot.as_ref().map(|d| d.id) == Some(dev_id))
            .ok_or(SysError::InvalidArgument)?;

        let mut spare_to_activate: Option<u32> = None;

        {
            let dev = self.devices[dev_idx].as_mut().unwrap();
            dev.remediation_count += 1;
            dev.last_action = action;
            self.stats.total_remediations += 1;

            match action {
                RemediationAction::None => {}
                RemediationAction::LinkRetrained => {
                    self.stats.link_retrains += 1;
                    dev.pcie_aer_correctable_count = 0;
                    dev.status = DeviceStatus::Remediated;
                    dev.health_score = 95;
                }
                RemediationAction::FlrReset => {
                    self.stats.flr_resets += 1;
                    dev.virtio_errors_count = 0;
                    dev.pcie_aer_fatal_count = 0;
                    dev.status = DeviceStatus::Remediated;
                    dev.health_score = 90;
                }
                RemediationAction::DegradedModeFallback => {
                    self.stats.degraded_fallbacks += 1;
                    dev.status = DeviceStatus::Degraded;
                    dev.health_score = 50;
                }
                RemediationAction::HotFailoverExecuted => {
                    self.stats.hot_failovers += 1;
                    spare_to_activate = dev.spare_target_id;
                    dev.status = DeviceStatus::Degraded;
                    dev.is_active = false;
                    dev.health_score = 30;
                }
                RemediationAction::Quarantined => {
                    self.stats.quarantines += 1;
                    dev.status = DeviceStatus::Quarantined;
                    dev.is_active = false;
                    dev.health_score = 0;
                }
            }
        }

        // Si une bascule vers un spare est demandée, on active le spare
        if let Some(spare_id) = spare_to_activate {
            for slot in self.devices.iter_mut().flatten() {
                if slot.id == spare_id {
                    slot.is_spare = false;
                    slot.is_active = true;
                    slot.status = DeviceStatus::Healthy;
                    slot.health_score = 100;
                    slot.last_action = RemediationAction::HotFailoverExecuted;
                    break;
                }
            }
        }

        Ok(())
    }

    fn record_incident(
        &mut self,
        dev_id: u32,
        name: [u8; MAX_NAME_LEN],
        name_len: usize,
        error_type: HardwareErrorType,
        severity: FaultSeverity,
        remediation: RemediationAction,
        timestamp: u64,
    ) {
        self.incident_total += 1;
        let inc_id = self.incident_total;

        // Calcul du hash chaîné SHA-256
        let mut hasher_input = [0u8; 64];
        hasher_input[..32].copy_from_slice(&self.latest_hash);
        hasher_input[32..40].copy_from_slice(&inc_id.to_be_bytes());
        hasher_input[40..48].copy_from_slice(&timestamp.to_be_bytes());
        hasher_input[48..52].copy_from_slice(&dev_id.to_be_bytes());
        hasher_input[52] = error_type as u8;
        hasher_input[53] = severity as u8;
        hasher_input[54] = remediation as u8;

        let inc_hash = Sha256::digest(&hasher_input);
        self.latest_hash = inc_hash;

        let incident = FaultIncident {
            incident_id: inc_id,
            timestamp,
            device_id: dev_id,
            device_name: name,
            device_name_len: name_len,
            error_type,
            severity,
            remediation,
            incident_hash: inc_hash,
        };

        let pos = self.incident_head % MAX_INCIDENTS;
        self.incidents[pos] = Some(incident);
        self.incident_head += 1;
    }

    /// Exécute un scan actif de l'ensemble des bus et périphériques
    pub fn trigger_scan(&mut self, cap: &DiagCap, _timestamp: u64) -> Result<ScanSummary, SysError> {
        if !cap.has_right(diag_rights::DIAG_SCAN) && !cap.has_right(diag_rights::DIAG_INSPECT) {
            return Err(SysError::PermissionDenied);
        }

        let mut summary = ScanSummary::default();
        let mut score_sum: u32 = 0;

        for dev in self.devices.iter_mut().flatten() {
            if dev.is_spare && !dev.is_active {
                continue;
            }
            summary.devices_scanned += 1;
            score_sum += dev.health_score as u32;

            match dev.status {
                DeviceStatus::Healthy | DeviceStatus::Remediated => summary.healthy_count += 1,
                DeviceStatus::Warning => summary.warning_count += 1,
                DeviceStatus::Degraded => summary.degraded_count += 1,
                DeviceStatus::Failed | DeviceStatus::Quarantined | DeviceStatus::Resetting => {
                    summary.failed_count += 1
                }
            }
        }

        if summary.devices_scanned > 0 {
            summary.mean_health_score = (score_sum / (summary.devices_scanned as u32)) as u8;
        } else {
            summary.mean_health_score = 100;
        }

        Ok(summary)
    }

    /// Extrait le condensat cryptographique d'intégrité de la télémétrie
    pub fn get_telemetry_digest(&self, cap: &DiagCap) -> Result<[u8; 32], SysError> {
        if !cap.has_right(diag_rights::DIAG_TELEMETRY) && !cap.has_right(diag_rights::DIAG_INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.latest_hash)
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] compatibles)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_attenuation_and_no_amplification() {
        let admin_cap = DiagCap::new(Handle::new(8001, 1), diag_rights::ALL);
        assert!(admin_cap.has_right(diag_rights::DIAG_INSPECT));
        assert!(admin_cap.has_right(diag_rights::DIAG_ADMIN));
        assert!(admin_cap.has_right(diag_rights::DIAG_REMEDIATE));

        // Atténuation légitime
        let inspect_only = admin_cap.attenuate(diag_rights::DIAG_INSPECT).unwrap();
        assert!(inspect_only.has_right(diag_rights::DIAG_INSPECT));
        assert!(!inspect_only.has_right(diag_rights::DIAG_ADMIN));

        // Rejet strict d'amplification
        assert_eq!(
            inspect_only.attenuate(diag_rights::DIAG_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_pcie_aer_remediation_link_retraining() {
        let admin_cap = DiagCap::new(Handle::new(8001, 1), diag_rights::ALL);
        let mut daemon = JamboDiagDaemon::new(1, admin_cap);
        daemon.init_defaults();

        let dev_id = 1; // pcie-root-0

        // Envoi d'erreurs correctes sous le seuil
        for t in 1..8 {
            let act = daemon
                .record_error(&admin_cap, dev_id, HardwareErrorType::PcieAerCorrectable, t)
                .unwrap();
            assert_eq!(act, RemediationAction::None);
        }

        // Atteinte du seuil (8) -> Link Retraining déclenché
        let act = daemon
            .record_error(&admin_cap, dev_id, HardwareErrorType::PcieAerCorrectable, 8)
            .unwrap();
        assert_eq!(act, RemediationAction::LinkRetrained);

        let dev = daemon.get_device(dev_id).unwrap();
        assert_eq!(dev.status, DeviceStatus::Remediated);
        assert_eq!(dev.health_score, 95);
        assert_eq!(daemon.stats.link_retrains, 1);
    }

    #[test]
    fn test_pcie_aer_fatal_error_flr_reset() {
        let admin_cap = DiagCap::new(Handle::new(8001, 1), diag_rights::ALL);
        let mut daemon = JamboDiagDaemon::new(1, admin_cap);
        daemon.init_defaults();

        let dev_id = 7; // virtio-blk-0

        let act = daemon
            .record_error(&admin_cap, dev_id, HardwareErrorType::PcieAerFatal, 10)
            .unwrap();
        assert_eq!(act, RemediationAction::FlrReset);

        let dev = daemon.get_device(dev_id).unwrap();
        assert_eq!(dev.status, DeviceStatus::Remediated);
        assert_eq!(dev.health_score, 90);
        assert_eq!(daemon.stats.flr_resets, 1);
    }

    #[test]
    fn test_nvme_media_error_hot_failover_to_spare() {
        let admin_cap = DiagCap::new(Handle::new(8001, 1), diag_rights::ALL);
        let mut daemon = JamboDiagDaemon::new(1, admin_cap);
        daemon.init_defaults();

        let primary_id = 4; // nvme-ctrl-0
        let spare_id = 5;   // nvme-ctrl-spare

        let spare_before = daemon.get_device(spare_id).unwrap();
        assert!(spare_before.is_spare);

        // Simulation de 5 erreurs de média NVMe
        for t in 1..=5 {
            daemon
                .record_error(&admin_cap, primary_id, HardwareErrorType::NvmeMediaError, t)
                .unwrap();
        }

        let primary_after = daemon.get_device(primary_id).unwrap();
        assert_eq!(primary_after.status, DeviceStatus::Degraded);
        assert!(!primary_after.is_active);

        let spare_after = daemon.get_device(spare_id).unwrap();
        assert!(!spare_after.is_spare);
        assert!(spare_after.is_active);
        assert_eq!(spare_after.status, DeviceStatus::Healthy);
        assert_eq!(spare_after.health_score, 100);
        assert_eq!(daemon.stats.hot_failovers, 1);
    }

    #[test]
    fn test_ecc_uncorrectable_error_quarantine() {
        let admin_cap = DiagCap::new(Handle::new(8001, 1), diag_rights::ALL);
        let mut daemon = JamboDiagDaemon::new(1, admin_cap);
        daemon.init_defaults();

        let dev_id = 6; // ddr5-ecc-dimm0
        let act = daemon
            .record_error(&admin_cap, dev_id, HardwareErrorType::EccUncorrectable, 100)
            .unwrap();
        assert_eq!(act, RemediationAction::Quarantined);

        let dev = daemon.get_device(dev_id).unwrap();
        assert_eq!(dev.status, DeviceStatus::Quarantined);
        assert_eq!(dev.health_score, 0);
        assert!(!dev.is_active);
    }

    #[test]
    fn test_telemetry_digest_chain() {
        let admin_cap = DiagCap::new(Handle::new(8001, 1), diag_rights::ALL);
        let mut daemon = JamboDiagDaemon::new(1, admin_cap);
        daemon.init_defaults();

        let d1 = daemon.get_telemetry_digest(&admin_cap).unwrap();
        daemon
            .record_error(&admin_cap, 1, HardwareErrorType::PcieAerCorrectable, 1)
            .unwrap();
        let d2 = daemon.get_telemetry_digest(&admin_cap).unwrap();

        assert_ne!(d1, d2);
    }
}

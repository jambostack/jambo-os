//! Démon de Synchronisation Horlogère Distribuée PTP/NTP (jambo-timed)
//!
//! Fournit une référence temporelle universelle, monotone et sub-microseconde
//! sans autorité ambiante. Les recalibrages de fréquence et asservissements d'horloge
//! sont strictement régis par la capacité `TimeSyncCap`. Garantit l'absence de régression
//! temporelle pour préserver l'ordre des audits cryptographiques et des expirations.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const TIME_MAGIC_REQ: u32 = 0x54494D45; // "TIME"
pub const TIME_MAGIC_RESP: u32 = 0x544D5253; // "TMRS"

/// Opcodes IPC pour les requêtes vers jambo-timed
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeOpcode {
    GetTime = 1,
    AdjustSlew = 2,
    StepTime = 3,
    PtpSync = 4,
    GetStatus = 5,
}

impl TimeOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetTime),
            2 => Some(Self::AdjustSlew),
            3 => Some(Self::StepTime),
            4 => Some(Self::PtpSync),
            5 => Some(Self::GetStatus),
            _ => None,
        }
    }
}

/// Requête IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub handle_flags: u32,
    pub domain_id: u32,
    pub rights: u32,
    pub param_i64: i64,
    pub t1_sec: u32,
    pub t1_ns: u32,
    pub t2_sec: u32,
    pub t2_ns: u32,
    pub t3_sec: u32,
    pub t3_ns: u32,
    pub t4_sec: u32,
    pub t4_ns: u32,
}

const _: () = assert!(core::mem::size_of::<TimeRequest>() == 64);

impl Default for TimeRequest {
    fn default() -> Self {
        Self {
            magic: TIME_MAGIC_REQ,
            opcode: TimeOpcode::GetTime as u32,
            handle_id: 0,
            handle_flags: 0,
            domain_id: 1,
            rights: time_rights::TIME_READ,
            param_i64: 0,
            t1_sec: 0,
            t1_ns: 0,
            t2_sec: 0,
            t2_ns: 0,
            t3_sec: 0,
            t3_ns: 0,
            t4_sec: 0,
            t4_ns: 0,
        }
    }
}

impl TimeRequest {
    pub const fn new(opcode: TimeOpcode, cap: TimeSyncCap) -> Self {
        Self {
            magic: TIME_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: cap.handle.0 as u32,
            handle_flags: (cap.handle.0 >> 32) as u32,
            domain_id: cap.domain_id,
            rights: cap.rights,
            param_i64: 0,
            t1_sec: 0,
            t1_ns: 0,
            t2_sec: 0,
            t2_ns: 0,
            t3_sec: 0,
            t3_ns: 0,
            t4_sec: 0,
            t4_ns: 0,
        }
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
        if req.magic != TIME_MAGIC_REQ {
            return None;
        }
        Some(req)
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeResponse {
    pub magic: u32,
    pub status: i32,
    pub seconds: u64,
    pub nanoseconds: u32,
    pub mode: u32,
    pub freq_ppm: i32,
    pub _pad: i32,
    pub offset_nanos: i64,
    pub delay_nanos: i64,
    pub sync_count: u64,
    pub monotonic_nanos: u64,
}

const _: () = assert!(core::mem::size_of::<TimeResponse>() == 64);

impl Default for TimeResponse {
    fn default() -> Self {
        Self {
            magic: TIME_MAGIC_RESP,
            status: 0,
            seconds: 0,
            nanoseconds: 0,
            mode: 0,
            freq_ppm: 0,
            _pad: 0,
            offset_nanos: 0,
            delay_nanos: 0,
            sync_count: 0,
            monotonic_nanos: 0,
        }
    }
}

impl TimeResponse {
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
        if resp.magic != TIME_MAGIC_RESP {
            return None;
        }
        Some(resp)
    }
}

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

/// Client IPC pour interagir avec jambo-timed (Ring 3, PID 17)
pub struct TimeClient {
    pub endpoint: Handle,
}

impl TimeClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_time(&self, cap: TimeSyncCap) -> Result<PreciseTime, SysError> {
        let req = TimeRequest::new(TimeOpcode::GetTime, cap);
        let resp = self.call(&req)?;
        if resp.status != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(PreciseTime::new(resp.seconds, resp.nanoseconds))
    }

    pub fn get_status(&self, cap: TimeSyncCap) -> Result<TimeResponse, SysError> {
        let req = TimeRequest::new(TimeOpcode::GetStatus, cap);
        self.call(&req)
    }

    pub fn adjust_slew(&self, cap: TimeSyncCap, offset_nanos: i64) -> Result<TimeResponse, SysError> {
        let mut req = TimeRequest::new(TimeOpcode::AdjustSlew, cap);
        req.param_i64 = offset_nanos;
        self.call(&req)
    }

    pub fn step_time(&self, cap: TimeSyncCap, offset_nanos: i64) -> Result<TimeResponse, SysError> {
        let mut req = TimeRequest::new(TimeOpcode::StepTime, cap);
        req.param_i64 = offset_nanos;
        self.call(&req)
    }

    pub fn call(&self, req: &TimeRequest) -> Result<TimeResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

        // 1. Émission de la requête sur le canal IPC
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

        // 2. Réception de la réponse avec repli coopératif
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<TimeResponse>() {
                return TimeResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

/// Droits capabilitaires pour le contrôle du temps et de la synchronisation
pub mod time_rights {
    pub const TIME_READ: u32 = 0x01;
    pub const TIME_ADJUST_FREQ: u32 = 0x02;
    pub const TIME_STEP: u32 = 0x04;
    pub const TIME_PTP_SYNC: u32 = 0x08;
    pub const ALL: u32 = TIME_READ | TIME_ADJUST_FREQ | TIME_STEP | TIME_PTP_SYNC;
}

/// Capacité de synchronisation horlogère
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSyncCap {
    pub handle: Handle,
    pub domain_id: u32,
    pub rights: u32,
}

impl TimeSyncCap {
    pub const fn new(handle: Handle, domain_id: u32, rights: u32) -> Self {
        Self {
            handle,
            domain_id,
            rights,
        }
    }

    pub fn can_read(&self) -> bool {
        (self.rights & time_rights::TIME_READ) != 0
    }

    pub fn can_adjust_freq(&self) -> bool {
        (self.rights & time_rights::TIME_ADJUST_FREQ) != 0
    }

    pub fn can_step(&self) -> bool {
        (self.rights & time_rights::TIME_STEP) != 0
    }

    pub fn can_ptp_sync(&self) -> bool {
        (self.rights & time_rights::TIME_PTP_SYNC) != 0
    }
}

/// Horodatage de haute précision (secondes et nanosecondes)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PreciseTime {
    pub seconds: u64,
    pub nanoseconds: u32,
}

impl PreciseTime {
    pub const NANOS_PER_SEC: u64 = 1_000_000_000;

    pub const fn new(seconds: u64, nanoseconds: u32) -> Self {
        Self {
            seconds: seconds + (nanoseconds as u64 / Self::NANOS_PER_SEC),
            nanoseconds: (nanoseconds as u64 % Self::NANOS_PER_SEC) as u32,
        }
    }

    pub fn from_nanos(total_nanos: u64) -> Self {
        Self {
            seconds: total_nanos / Self::NANOS_PER_SEC,
            nanoseconds: (total_nanos % Self::NANOS_PER_SEC) as u32,
        }
    }

    pub fn as_nanos(&self) -> u64 {
        self.seconds * Self::NANOS_PER_SEC + self.nanoseconds as u64
    }

    pub fn saturating_add_nanos(&self, nanos: u64) -> Self {
        let total = self.as_nanos().saturating_add(nanos);
        Self::from_nanos(total)
    }

    pub fn checked_sub(&self, other: &Self) -> Option<i64> {
        let self_nanos = self.as_nanos() as i64;
        let other_nanos = other.as_nanos() as i64;
        self_nanos.checked_sub(other_nanos)
    }
}

/// Type de message IEEE 1588 PTP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtpMessageType {
    Sync,
    FollowUp,
    DelayReq,
    DelayResp,
}

/// Échantillon d'horodatage PTP quadri-points (T1, T2, T3, T4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PtpSample {
    pub t1_master_tx: PreciseTime,
    pub t2_slave_rx: PreciseTime,
    pub t3_slave_tx: PreciseTime,
    pub t4_master_rx: PreciseTime,
}

impl PtpSample {
    /// Calcule le délai aller-retour moyen et l'écart d'horloge (offset)
    /// offset = ((t2 - t1) - (t4 - t3)) / 2
    /// delay = ((t4 - t1) - (t3 - t2)) / 2
    pub fn calculate_offset_and_delay(&self) -> Result<(i64, i64), SysError> {
        let t2_minus_t1 = self
            .t2_slave_rx
            .checked_sub(&self.t1_master_tx)
            .ok_or(SysError::InvalidArgument)?;
        let t4_minus_t3 = self
            .t4_master_rx
            .checked_sub(&self.t3_slave_tx)
            .ok_or(SysError::InvalidArgument)?;

        let t4_minus_t1 = self
            .t4_master_rx
            .checked_sub(&self.t1_master_tx)
            .ok_or(SysError::InvalidArgument)?;
        let t3_minus_t2 = self
            .t3_slave_tx
            .checked_sub(&self.t2_slave_rx)
            .ok_or(SysError::InvalidArgument)?;

        let offset = (t2_minus_t1 - t4_minus_t3) / 2;
        let delay = (t4_minus_t1 - t3_minus_t2) / 2;

        Ok((offset, delay))
    }
}

/// Mode d'asservissement d'horloge
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServoMode {
    Locked,
    Slewing,
    Stepping,
}

impl ServoMode {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Locked => 0,
            Self::Slewing => 1,
            Self::Stepping => 2,
        }
    }
}

/// Asservissement d'horloge à boucle PLL/FLL (Clock Servo)
#[derive(Debug, Clone, Copy)]
pub struct ClockServo {
    pub current_time: PreciseTime,
    pub last_monotonic_nanos: u64,
    pub freq_ppm: i32,
    pub mode: ServoMode,
    pub max_slewing_ppm: i32,
}

impl Default for ClockServo {
    fn default() -> Self {
        Self::new(PreciseTime::new(1792340000, 0))
    }
}

impl ClockServo {
    pub const fn new(initial_time: PreciseTime) -> Self {
        Self {
            current_time: initial_time,
            last_monotonic_nanos: 0,
            freq_ppm: 0,
            mode: ServoMode::Locked,
            max_slewing_ppm: 500, // Dérive max corrigée de +/- 500 PPM
        }
    }

    /// Avance le temps local en appliquant la dérive de fréquence (sans régression monotone)
    pub fn tick(&mut self, elapsed_nanos: u64) -> PreciseTime {
        // Ajustement selon freq_ppm : delta_nanos * (1 + ppm / 1_000_000)
        let adjustment = (elapsed_nanos as i64 * self.freq_ppm as i64) / 1_000_000;
        let effective_nanos = (elapsed_nanos as i64 + adjustment).max(1) as u64;

        let new_nanos = self.current_time.as_nanos().saturating_add(effective_nanos);
        let strictly_monotone_nanos = new_nanos.max(self.last_monotonic_nanos + 1);

        self.last_monotonic_nanos = strictly_monotone_nanos;
        self.current_time = PreciseTime::from_nanos(strictly_monotone_nanos);
        self.current_time
    }

    /// Ajuste progressivement la fréquence pour absorber un offset (Slewing)
    pub fn adjust_offset_slew(&mut self, offset_nanos: i64) {
        if offset_nanos == 0 {
            self.freq_ppm = 0;
            self.mode = ServoMode::Locked;
            return;
        }

        // Corrige vers le zéro offset dans la limite de max_slewing_ppm
        let target_ppm = if offset_nanos > 0 {
            // Horloge locale en retard -> accélérer
            self.max_slewing_ppm
        } else {
            // Horloge locale en avance -> décélérer
            -self.max_slewing_ppm
        };

        self.freq_ppm = target_ppm;
        self.mode = ServoMode::Slewing;
    }

    /// Effectue un saut discret si autorisé et nécessaire
    pub fn step_offset(&mut self, offset_nanos: i64) {
        let current = self.current_time.as_nanos() as i64;
        let target = current + offset_nanos;
        // Règle formelle : Ne jamais régresser sous le dernier temps monotone validé
        let safe_target = (target as u64).max(self.last_monotonic_nanos + 1);
        self.current_time = PreciseTime::from_nanos(safe_target);
        self.last_monotonic_nanos = safe_target;
        self.mode = ServoMode::Stepping;
    }
}

/// Serveur de gestion et synchronisation du temps
pub struct TimeSyncServer {
    pub domain_id: u32,
    pub servo: ClockServo,
    pub sync_count: u64,
    pub last_measured_delay: i64,
    pub last_measured_offset: i64,
}

impl TimeSyncServer {
    pub fn new(domain_id: u32, initial_time: PreciseTime) -> Self {
        Self {
            domain_id,
            servo: ClockServo::new(initial_time),
            sync_count: 0,
            last_measured_delay: 0,
            last_measured_offset: 0,
        }
    }

    /// Lit le temps précis courant (nécessite TIME_READ)
    pub fn read_time(&self, cap: &TimeSyncCap) -> Result<PreciseTime, SysError> {
        if !cap.can_read() || cap.domain_id != self.domain_id {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.servo.current_time)
    }

    /// Applique une synchronisation PTP calculée
    pub fn apply_ptp_sync(
        &mut self,
        cap: &TimeSyncCap,
        sample: &PtpSample,
    ) -> Result<(i64, i64), SysError> {
        if !cap.can_ptp_sync() || cap.domain_id != self.domain_id {
            return Err(SysError::PermissionDenied);
        }

        let (offset, delay) = sample.calculate_offset_and_delay()?;
        self.last_measured_offset = offset;
        self.last_measured_delay = delay;
        self.sync_count += 1;

        // Si l'écart dépasse 100 millisecondes et qu'on a le droit TIME_STEP, sauter
        if offset.abs() > 100_000_000 && cap.can_step() {
            self.servo.step_offset(offset);
        } else if cap.can_adjust_freq() {
            // Sinon, lisser par slewing
            self.servo.adjust_offset_slew(offset);
        }

        Ok((offset, delay))
    }

    /// Fait progresser l'horloge
    pub fn advance_time(&mut self, elapsed_nanos: u64) -> PreciseTime {
        self.servo.tick(elapsed_nanos)
    }
}

/// Démon orchestrateur de synchronisation horlogère PTP/NTP (Ring 3)
pub struct JamboTimeDaemon {
    pub server: TimeSyncServer,
    pub admin_cap: TimeSyncCap,
    pub read_cap: TimeSyncCap,
}

impl Default for JamboTimeDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboTimeDaemon {
    pub fn new() -> Self {
        let admin_cap = TimeSyncCap::new(Handle::new(58, 1), 1, time_rights::ALL);
        let read_cap = TimeSyncCap::new(Handle::new(58, 2), 1, time_rights::TIME_READ);
        let initial_time = PreciseTime::new(1792340000, 0); // Timestamp étalon (2026)
        Self {
            server: TimeSyncServer::new(1, initial_time),
            admin_cap,
            read_cap,
        }
    }

    /// Initialise le démon avec calibration PTP par défaut
    pub fn init_defaults(&mut self) {
        let sample = PtpSample {
            t1_master_tx: PreciseTime::new(1792340000, 0),
            t2_slave_rx: PreciseTime::new(1792340000, 10_000_000), // delay 8ms + offset 2ms
            t3_slave_tx: PreciseTime::new(1792340000, 20_000_000),
            t4_master_rx: PreciseTime::new(1792340000, 26_000_000), // delay 8ms - offset 2ms
        };
        let cap = self.admin_cap;
        let _ = self.server.apply_ptp_sync(&cap, &sample);
    }

    /// Lit l'heure précise actuelle
    pub fn get_time(&self) -> Result<PreciseTime, SysError> {
        self.server.read_time(&self.read_cap)
    }

    /// Avance le temps de 'nanos' nanosecondes
    pub fn advance_nanos(&mut self, nanos: u64) -> PreciseTime {
        self.server.advance_time(nanos)
    }

    /// Effectue une synchronisation PTP avec les 4 points d'échantillonnage
    pub fn sync_ptp(&mut self, sample: &PtpSample) -> Result<(i64, i64), SysError> {
        let cap = self.admin_cap;
        self.server.apply_ptp_sync(&cap, sample)
    }

    /// État du servo (Mode, Freq PPM, Offset, Delay, Sync Count)
    pub fn status(&self) -> (ServoMode, i32, i64, i64, u64) {
        (
            self.server.servo.mode,
            self.server.servo.freq_ppm,
            self.server.last_measured_offset,
            self.server.last_measured_delay,
            self.server.sync_count,
        )
    }

    /// Traite une requête IPC et produit une réponse de 64 octets
    pub fn handle_ipc_request(&mut self, req: &TimeRequest) -> TimeResponse {
        if req.magic != TIME_MAGIC_REQ {
            return TimeResponse {
                status: -1,
                ..TimeResponse::default()
            };
        }

        let cap = TimeSyncCap::new(
            Handle::new(req.handle_id, req.handle_flags),
            req.domain_id,
            req.rights,
        );

        let opcode = match TimeOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                return TimeResponse {
                    status: -2,
                    ..TimeResponse::default()
                }
            }
        };

        let mut status = 0;
        match opcode {
            TimeOpcode::GetTime => {
                if let Err(_e) = self.server.read_time(&cap) {
                    status = -3;
                }
            }
            TimeOpcode::AdjustSlew => {
                if !cap.can_adjust_freq() {
                    status = -4;
                } else {
                    self.server.servo.adjust_offset_slew(req.param_i64);
                }
            }
            TimeOpcode::StepTime => {
                if !cap.can_step() {
                    status = -5;
                } else {
                    self.server.servo.step_offset(req.param_i64);
                }
            }
            TimeOpcode::PtpSync => {
                let sample = PtpSample {
                    t1_master_tx: PreciseTime::new(req.t1_sec as u64, req.t1_ns),
                    t2_slave_rx: PreciseTime::new(req.t2_sec as u64, req.t2_ns),
                    t3_slave_tx: PreciseTime::new(req.t3_sec as u64, req.t3_ns),
                    t4_master_rx: PreciseTime::new(req.t4_sec as u64, req.t4_ns),
                };
                if let Err(_e) = self.server.apply_ptp_sync(&cap, &sample) {
                    status = -6;
                }
            }
            TimeOpcode::GetStatus => {
                if !cap.can_read() {
                    status = -7;
                }
            }
        }

        TimeResponse {
            magic: TIME_MAGIC_RESP,
            status,
            seconds: self.server.servo.current_time.seconds,
            nanoseconds: self.server.servo.current_time.nanoseconds,
            mode: self.server.servo.mode.as_u32(),
            freq_ppm: self.server.servo.freq_ppm,
            _pad: 0,
            offset_nanos: self.server.last_measured_offset,
            delay_nanos: self.server.last_measured_delay,
            sync_count: self.server.sync_count,
            monotonic_nanos: self.server.servo.last_monotonic_nanos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_sync_cap_rights() {
        let cap_full = TimeSyncCap::new(Handle::new(1, 0), 10, time_rights::ALL);
        assert!(cap_full.can_read());
        assert!(cap_full.can_adjust_freq());
        assert!(cap_full.can_step());
        assert!(cap_full.can_ptp_sync());

        let cap_ro = TimeSyncCap::new(Handle::new(2, 0), 10, time_rights::TIME_READ);
        assert!(cap_ro.can_read());
        assert!(!cap_ro.can_adjust_freq());
        assert!(!cap_ro.can_step());
        assert!(!cap_ro.can_ptp_sync());
    }

    #[test]
    fn test_precise_time_arithmetic() {
        let t1 = PreciseTime::new(10, 500_000_000);
        let t2 = t1.saturating_add_nanos(700_000_000);
        assert_eq!(t2.seconds, 11);
        assert_eq!(t2.nanoseconds, 200_000_000);

        let delta = t2.checked_sub(&t1);
        assert_eq!(delta, Some(700_000_000));
    }

    #[test]
    fn test_ptp_offset_and_delay_calculation() {
        let sample = PtpSample {
            t1_master_tx: PreciseTime::new(1000, 0),
            t2_slave_rx: PreciseTime::new(1000, 15_000_000),
            t3_slave_tx: PreciseTime::new(1000, 20_000_000),
            t4_master_rx: PreciseTime::new(1000, 25_000_000),
        };

        let (offset, delay) = sample
            .calculate_offset_and_delay()
            .expect("PTP calculation");
        assert_eq!(offset, 5_000_000); // 5 ms offset
        assert_eq!(delay, 10_000_000); // 10 ms delay
    }

    #[test]
    fn test_strict_monotonicity_guarantee() {
        let mut servo = ClockServo::new(PreciseTime::new(100, 0));

        let t1 = servo.tick(1_000_000);
        servo.step_offset(-500_000);
        let t2 = servo.tick(1_000);

        assert!(t2.as_nanos() > t1.as_nanos());
    }

    #[test]
    fn test_unauthorized_time_adjustment_rejected() {
        let unauth_cap = TimeSyncCap::new(Handle::new(1, 0), 1, 0); // 0 droit
        let mut server = TimeSyncServer::new(1, PreciseTime::new(10, 0));

        assert_eq!(
            server.read_time(&unauth_cap).err(),
            Some(SysError::PermissionDenied)
        );

        let sample = PtpSample::default();
        assert_eq!(
            server.apply_ptp_sync(&unauth_cap, &sample).err(),
            Some(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_time_daemon_lifecycle() {
        let mut daemon = JamboTimeDaemon::new();
        let t0 = daemon.get_time().expect("read time");
        assert_eq!(t0.seconds, 1792340000);

        daemon.init_defaults();
        let (mode, _ppm, offset, delay, syncs) = daemon.status();
        assert_eq!(syncs, 1);
        assert_eq!(offset, 2_000_000); // 2 ms offset
        assert_eq!(delay, 8_000_000); // 8 ms delay
        assert_eq!(mode, ServoMode::Slewing);

        let t1 = daemon.advance_nanos(1_000_000_000);
        assert!(t1.as_nanos() > t0.as_nanos());
    }

    #[test]
    fn test_ipc_deterministic_request_response() {
        assert_eq!(core::mem::size_of::<TimeRequest>(), 64);
        assert_eq!(core::mem::size_of::<TimeResponse>(), 64);

        let mut daemon = JamboTimeDaemon::new();
        let cap = daemon.admin_cap;

        // 1. GetTime via IPC
        let req = TimeRequest::new(TimeOpcode::GetTime, cap);
        let req_bytes = req.to_bytes();
        let decoded_req = TimeRequest::from_bytes(&req_bytes).expect("decode TimeRequest");
        assert_eq!(decoded_req.opcode, TimeOpcode::GetTime as u32);

        let resp = daemon.handle_ipc_request(&decoded_req);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.seconds, 1792340000);

        let resp_bytes = resp.to_bytes();
        let decoded_resp = TimeResponse::from_bytes(&resp_bytes).expect("decode TimeResponse");
        assert_eq!(decoded_resp.seconds, 1792340000);

        // 2. AdjustSlew via IPC
        let mut slew_req = TimeRequest::new(TimeOpcode::AdjustSlew, cap);
        slew_req.param_i64 = 15_000_000;
        let slew_resp = daemon.handle_ipc_request(&slew_req);
        assert_eq!(slew_resp.status, 0);
        assert_eq!(slew_resp.mode, ServoMode::Slewing.as_u32());
        assert_eq!(slew_resp.freq_ppm, 500);

        // 3. StepTime via IPC
        let mut step_req = TimeRequest::new(TimeOpcode::StepTime, cap);
        step_req.param_i64 = 5_000_000_000; // +5s
        let step_resp = daemon.handle_ipc_request(&step_req);
        assert_eq!(step_resp.status, 0);
        assert_eq!(step_resp.seconds, 1792340005);
        assert_eq!(step_resp.mode, ServoMode::Stepping.as_u32());

        // 4. Unauthorized rejection via IPC
        let unauth_cap = TimeSyncCap::new(Handle::new(99, 0), 1, 0);
        let unauth_req = TimeRequest::new(TimeOpcode::StepTime, unauth_cap);
        let unauth_resp = daemon.handle_ipc_request(&unauth_req);
        assert!(unauth_resp.status < 0);
    }
}

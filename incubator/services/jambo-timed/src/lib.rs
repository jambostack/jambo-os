//! Démon de Synchronisation Horlogère Distribuée PTP/NTP (jambo-timed)
//!
//! Fournit une référence temporelle universelle, monotone et sub-microseconde
//! sans autorité ambiante. Les recalibrages de fréquence et asservissements d'horloge
//! sont strictement régis par la capacité `TimeSyncCap`. Garantit l'absence de régression
//! temporelle pour préserver l'ordre des audits cryptographiques et des expirations.

#![no_std]

use libjambo::{Handle, SysError};

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
        // T1 = 1000s, T2 = 1000s + 15ms (délai 10ms + offset 5ms)
        // T3 = 1000s + 20ms, T4 = 1000s + 25ms (délai 10ms - offset 5ms)
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
        // Tenter un saut en arrière brutal (-500_000 ns)
        servo.step_offset(-500_000);
        let t2 = servo.tick(1_000);

        // Règle formelle : t2 doit être strictement supérieur à t1 (monotonicité garantie)
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

        // Advance time
        let t1 = daemon.advance_nanos(1_000_000_000);
        assert!(t1.as_nanos() > t0.as_nanos());
    }
}

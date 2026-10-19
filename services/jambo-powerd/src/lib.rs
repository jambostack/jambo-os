//! Démon de Gestion de l'Énergie Matérielle et ACPI en Espace Utilisateur (jambo-powerd)
//!
//! Assure le contrôle thermique, la surveillance des batteries, la régulation des C-States SMP
//! et l'extinction/veille ACPI (S3/S5) en Ring 3 sans aucune autorité ambiante,
//! strictement subordonné à la détention d'une capacité explicite `PowerCap`.

#![no_std]

use libjambo::{Handle, SysError};

/// Droits granulaires de la capacité de gestion énergétique
pub mod power_rights {
    pub const SHUTDOWN: u32 = 1 << 0;
    pub const REBOOT: u32 = 1 << 1;
    pub const SUSPEND: u32 = 1 << 2;
    pub const THROTTLE: u32 = 1 << 3;
    pub const BATTERY_QUERY: u32 = 1 << 4;
}

/// États d'alimentation système globaux (conformes ACPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    S0Working,
    S1CpuStandby,
    S3SuspendToRam,
    S4Hibernate,
    S5SoftOff,
}

/// États d'économie d'énergie des cœurs de calcul CPU (C-States)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPowerState {
    C0Active,
    C1Halt,
    C2StopClock,
    C3DeepSleep,
}

/// Capacité de contrôle d'énergie sans autorité ambiante (Ring 3)
#[derive(Debug, Clone, Copy)]
pub struct PowerCap {
    pub handle: Handle,
    pub rights: u32,
}

impl PowerCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }
}

/// Paramètres matériels FADT (Fixed ACPI Description Table) décodés en espace utilisateur
#[derive(Debug, Clone, Copy)]
pub struct AcpiFadtInfo {
    pub smi_cmd_port: u32,
    pub pm1a_cnt_blk: u32,
    pub pm1b_cnt_blk: u32,
    pub pm1_cnt_len: u8,
    pub slp_typa_s5: u16,
    pub slp_typb_s5: u16,
    pub reset_reg_supported: bool,
    pub reset_port: u32,
    pub reset_value: u8,
}

impl Default for AcpiFadtInfo {
    fn default() -> Self {
        Self {
            smi_cmd_port: 0x00B2,
            pm1a_cnt_blk: 0x0604, // Port standard QEMU ACPI PM1a_CNT
            pm1b_cnt_blk: 0x0000,
            pm1_cnt_len: 2,
            slp_typa_s5: 0x2000, // Code standard SLP_EN | (SLP_TYP << 10)
            slp_typb_s5: 0x0000,
            reset_reg_supported: true,
            reset_port: 0x0CF9, // Port standard de reset PCI
            reset_value: 0x06,
        }
    }
}

/// Télémétrie d'état de batterie physique ou virtuelle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatteryTelemetry {
    pub percentage: u8,
    pub is_charging: bool,
    pub health_percentage: u8,
    pub temperature_celsius: i16,
}

impl BatteryTelemetry {
    pub const fn new(
        percentage: u8,
        is_charging: bool,
        health_percentage: u8,
        temperature_celsius: i16,
    ) -> Self {
        Self {
            percentage,
            is_charging,
            health_percentage,
            temperature_celsius,
        }
    }

    pub fn is_critical(&self) -> bool {
        !self.is_charging && self.percentage <= 5
    }

    pub fn is_low(&self) -> bool {
        !self.is_charging && self.percentage <= 20
    }
}

/// Action préconisée par la politique de gestion d'énergie
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerPolicyAction {
    None,
    EngageBatterySaver,
    ThermalThrottle,
    EmergencyShutdown,
}

/// Nombre de cœurs CPU gérés par le sous-système d'alimentation
pub const MAX_SUPPORTED_CORES: usize = 4;

/// Gestionnaire d'alimentation ACPI en espace utilisateur
pub struct PowerManager {
    pub current_state: PowerState,
    pub fadt: AcpiFadtInfo,
    pub cpu_cstates: [CpuPowerState; MAX_SUPPORTED_CORES],
    pub battery: BatteryTelemetry,
    pub power_saver_active: bool,
    pub total_state_transitions: u64,
}

impl PowerManager {
    pub fn new(fadt: AcpiFadtInfo) -> Self {
        Self {
            current_state: PowerState::S0Working,
            fadt,
            cpu_cstates: [CpuPowerState::C0Active; MAX_SUPPORTED_CORES],
            battery: BatteryTelemetry::new(100, true, 100, 35),
            power_saver_active: false,
            total_state_transitions: 0,
        }
    }

    /// Effectue une transition d'état d'alimentation global en vérifiant la capacité
    pub fn transition_state(
        &mut self,
        cap: &PowerCap,
        target: PowerState,
    ) -> Result<PowerState, SysError> {
        let required_right = match target {
            PowerState::S0Working => 0,
            PowerState::S1CpuStandby | PowerState::S3SuspendToRam | PowerState::S4Hibernate => {
                power_rights::SUSPEND
            }
            PowerState::S5SoftOff => power_rights::SHUTDOWN,
        };

        if required_right != 0 && !cap.has_right(required_right) {
            return Err(SysError::PermissionDenied);
        }

        self.current_state = target;
        self.total_state_transitions = self.total_state_transitions.saturating_add(1);

        Ok(self.current_state)
    }

    /// Règle le C-State d'un cœur CPU logique spécifique
    pub fn set_core_cstate(
        &mut self,
        cap: &PowerCap,
        core_id: usize,
        state: CpuPowerState,
    ) -> Result<(), SysError> {
        if !cap.has_right(power_rights::THROTTLE) {
            return Err(SysError::PermissionDenied);
        }

        if core_id >= MAX_SUPPORTED_CORES {
            return Err(SysError::InvalidHandle);
        }

        self.cpu_cstates[core_id] = state;
        Ok(())
    }

    /// Met à jour la télémétrie de la batterie
    pub fn update_battery(
        &mut self,
        cap: &PowerCap,
        percentage: u8,
        is_charging: bool,
        temperature_c: i16,
    ) -> Result<(), SysError> {
        if !cap.has_right(power_rights::BATTERY_QUERY) {
            return Err(SysError::PermissionDenied);
        }

        self.battery.percentage = percentage.min(100);
        self.battery.is_charging = is_charging;
        self.battery.temperature_celsius = temperature_c;

        Ok(())
    }

    /// Évalue en continu la politique thermique et de sauvegarde d'énergie
    pub fn evaluate_policy(&mut self) -> PowerPolicyAction {
        // 1. Surchauffe critique (> 85°C) => régulation thermique immédiate
        if self.battery.temperature_celsius >= 85 {
            return PowerPolicyAction::ThermalThrottle;
        }

        // 2. Batterie critique (<= 5% et décharge) => extinction d'urgence ordonnée
        if self.battery.is_critical() {
            return PowerPolicyAction::EmergencyShutdown;
        }

        // 3. Batterie faible (<= 20% et décharge) => mode économie d'énergie
        if self.battery.is_low() && !self.power_saver_active {
            self.power_saver_active = true;
            return PowerPolicyAction::EngageBatterySaver;
        }

        PowerPolicyAction::None
    }
}

/// Démon orchestrateur de gestion énergétique et ACPI en espace utilisateur (Ring 3)
pub struct JamboPowerDaemon {
    pub manager: PowerManager,
    pub admin_cap: PowerCap,
}

impl Default for JamboPowerDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboPowerDaemon {
    pub fn new() -> Self {
        let admin_cap = PowerCap::new(
            Handle::new(1, 1),
            power_rights::SHUTDOWN
                | power_rights::REBOOT
                | power_rights::SUSPEND
                | power_rights::THROTTLE
                | power_rights::BATTERY_QUERY,
        );
        Self {
            manager: PowerManager::new(AcpiFadtInfo::default()),
            admin_cap,
        }
    }

    /// Initialise la configuration énergétique par défaut
    pub fn init_defaults(&mut self) {
        let _ = self.manager.update_battery(&self.admin_cap, 100, true, 32);
        for core in 0..MAX_SUPPORTED_CORES {
            let _ = self
                .manager
                .set_core_cstate(&self.admin_cap, core, CpuPowerState::C0Active);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power_cap_permission_denial() {
        let fadt = AcpiFadtInfo::default();
        let mut mgr = PowerManager::new(fadt);

        // Capacité avec seulement droit de lecture batterie
        let unauth_cap = PowerCap::new(Handle::new(10, 1), power_rights::BATTERY_QUERY);

        // Tentative d'extinction S5 interdite
        let res = mgr.transition_state(&unauth_cap, PowerState::S5SoftOff);
        assert_eq!(res, Err(SysError::PermissionDenied));

        // Tentative de mise en veille S3 interdite
        let res_s3 = mgr.transition_state(&unauth_cap, PowerState::S3SuspendToRam);
        assert_eq!(res_s3, Err(SysError::PermissionDenied));

        // Tentative de régulation de cœur CPU interdite
        let res_core = mgr.set_core_cstate(&unauth_cap, 1, CpuPowerState::C3DeepSleep);
        assert_eq!(res_core, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_power_state_transitions_and_cstates() {
        let fadt = AcpiFadtInfo::default();
        let mut mgr = PowerManager::new(fadt);

        let admin_cap = PowerCap::new(
            Handle::new(1, 1),
            power_rights::SHUTDOWN | power_rights::SUSPEND | power_rights::THROTTLE,
        );

        // Mise en veille S3
        assert_eq!(
            mgr.transition_state(&admin_cap, PowerState::S3SuspendToRam),
            Ok(PowerState::S3SuspendToRam)
        );

        // Réveil vers S0
        assert_eq!(
            mgr.transition_state(&admin_cap, PowerState::S0Working),
            Ok(PowerState::S0Working)
        );

        // Mise en sommeil profond d'un cœur AP inactif
        assert!(mgr
            .set_core_cstate(&admin_cap, 2, CpuPowerState::C3DeepSleep)
            .is_ok());
        assert_eq!(mgr.cpu_cstates[2], CpuPowerState::C3DeepSleep);
        assert_eq!(mgr.cpu_cstates[0], CpuPowerState::C0Active);

        // Extinction S5
        assert_eq!(
            mgr.transition_state(&admin_cap, PowerState::S5SoftOff),
            Ok(PowerState::S5SoftOff)
        );
        assert_eq!(mgr.total_state_transitions, 3);
    }

    #[test]
    fn test_battery_telemetry_and_emergency_policy() {
        let fadt = AcpiFadtInfo::default();
        let mut mgr = PowerManager::new(fadt);

        let cap = PowerCap::new(
            Handle::new(2, 1),
            power_rights::BATTERY_QUERY | power_rights::SHUTDOWN,
        );

        // 1. Batterie normale
        mgr.update_battery(&cap, 80, false, 35).unwrap();
        assert_eq!(mgr.evaluate_policy(), PowerPolicyAction::None);

        // 2. Batterie faible (15%) => engagement BatterySaver
        mgr.update_battery(&cap, 15, false, 38).unwrap();
        assert_eq!(mgr.evaluate_policy(), PowerPolicyAction::EngageBatterySaver);
        assert!(mgr.power_saver_active);

        // 3. Surchauffe (88°C) => ThermalThrottle
        mgr.update_battery(&cap, 50, true, 88).unwrap();
        assert_eq!(mgr.evaluate_policy(), PowerPolicyAction::ThermalThrottle);

        // 4. Niveau critique (3%) => EmergencyShutdown
        mgr.update_battery(&cap, 3, false, 40).unwrap();
        assert_eq!(mgr.evaluate_policy(), PowerPolicyAction::EmergencyShutdown);
    }
}

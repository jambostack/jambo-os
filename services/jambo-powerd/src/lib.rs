//! Démon de Gestion de l'Énergie Matérielle et ACPI en Espace Utilisateur (jambo-powerd)
//!
//! Assure le contrôle thermique, la surveillance des batteries, la régulation des C-States SMP,
//! les profils énergétiques (Eco, Balanced, HighPerformance) et l'extinction/veille ACPI (S3/S5)
//! en Ring 3 sans aucune autorité ambiante, strictement subordonné à la détention d'une
//! capacité explicite `PowerCap`.

#![no_std]

use libjambo::{Handle, SysError};

/// Droits granulaires de la capacité de gestion énergétique
pub mod power_rights {
    pub const SHUTDOWN: u32 = 1 << 0;
    pub const REBOOT: u32 = 1 << 1;
    pub const SUSPEND: u32 = 1 << 2;
    pub const THROTTLE: u32 = 1 << 3;
    pub const BATTERY_QUERY: u32 = 1 << 4;
    pub const SET_PROFILE: u32 = 1 << 5;
    pub const ALL: u32 = SHUTDOWN | REBOOT | SUSPEND | THROTTLE | BATTERY_QUERY | SET_PROFILE;
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

impl PowerState {
    pub fn as_u32(&self) -> u32 {
        match self {
            PowerState::S0Working => 0,
            PowerState::S1CpuStandby => 1,
            PowerState::S3SuspendToRam => 2,
            PowerState::S4Hibernate => 3,
            PowerState::S5SoftOff => 4,
        }
    }

    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(PowerState::S0Working),
            1 => Some(PowerState::S1CpuStandby),
            2 => Some(PowerState::S3SuspendToRam),
            3 => Some(PowerState::S4Hibernate),
            4 => Some(PowerState::S5SoftOff),
            _ => None,
        }
    }
}

/// États d'économie d'énergie des cœurs de calcul CPU (C-States)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPowerState {
    C0Active,
    C1Halt,
    C2StopClock,
    C3DeepSleep,
}

impl CpuPowerState {
    pub fn as_u8(&self) -> u8 {
        match self {
            CpuPowerState::C0Active => 0,
            CpuPowerState::C1Halt => 1,
            CpuPowerState::C2StopClock => 2,
            CpuPowerState::C3DeepSleep => 3,
        }
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(CpuPowerState::C0Active),
            1 => Some(CpuPowerState::C1Halt),
            2 => Some(CpuPowerState::C2StopClock),
            3 => Some(CpuPowerState::C3DeepSleep),
            _ => None,
        }
    }
}

/// Profils de performance et de consommation énergétique
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerProfile {
    Eco = 1,
    Balanced = 2,
    HighPerformance = 3,
}

impl PowerProfile {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::Eco),
            2 => Some(Self::Balanced),
            3 => Some(Self::HighPerformance),
            _ => None,
        }
    }
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
    pub current_profile: PowerProfile,
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
            current_profile: PowerProfile::Balanced,
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

    /// Modifie le profil énergétique global
    pub fn set_profile(
        &mut self,
        cap: &PowerCap,
        profile: PowerProfile,
    ) -> Result<PowerProfile, SysError> {
        if !cap.has_right(power_rights::SET_PROFILE) && !cap.has_right(power_rights::THROTTLE) {
            return Err(SysError::PermissionDenied);
        }

        self.current_profile = profile;
        match profile {
            PowerProfile::Eco => {
                self.power_saver_active = true;
            }
            PowerProfile::Balanced => {
                self.power_saver_active = false;
            }
            PowerProfile::HighPerformance => {
                self.power_saver_active = false;
                self.cpu_cstates.fill(CpuPowerState::C0Active);
            }
        }
        self.total_state_transitions = self.total_state_transitions.saturating_add(1);
        Ok(self.current_profile)
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
            Handle::new(11, 1), // PID 11
            power_rights::ALL,
        );
        Self {
            manager: PowerManager::new(AcpiFadtInfo::default()),
            admin_cap,
        }
    }

    /// Initialise la configuration énergétique par défaut
    pub fn init_defaults(&mut self) {
        let _ = self.manager.update_battery(&self.admin_cap, 100, true, 32);
        self.manager.current_profile = PowerProfile::Balanced;
        for core in 0..MAX_SUPPORTED_CORES {
            let _ = self
                .manager
                .set_core_cstate(&self.admin_cap, core, CpuPowerState::C0Active);
        }
    }
}

// ============================================================================
// PROTOCOLE IPC POWERD (PowerOpcode, PowerRequest, PowerResponse, PowerClient)
// ============================================================================

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const POWER_STATUS_OK: u32 = 1;
pub const POWER_STATUS_ERROR: u32 = 0;

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

/// Opcodes du protocole IPC de gestion d'énergie (powerd, PID 11)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerOpcode {
    GetStatus = 1,
    SetProfile = 2,
    SetCState = 3,
    GetBattery = 4,
    Shutdown = 5,
}

impl PowerOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::SetProfile),
            3 => Some(Self::SetCState),
            4 => Some(Self::GetBattery),
            5 => Some(Self::Shutdown),
            _ => None,
        }
    }
}

/// Requête IPC transmise au démon `powerd` (exactement 64 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerRequest {
    pub opcode: u32,
    pub target_core: u32,
    pub param: u32,
    pub flags: u32,
    pub data_len: u16,
    pub reserved: [u8; 2],
    pub payload: [u8; 44],
}

const _: () = assert!(core::mem::size_of::<PowerRequest>() == 64);

impl Default for PowerRequest {
    fn default() -> Self {
        Self {
            opcode: 0,
            target_core: 0,
            param: 0,
            flags: 0,
            data_len: 0,
            reserved: [0u8; 2],
            payload: [0u8; 44],
        }
    }
}

impl PowerRequest {
    pub const fn new(opcode: PowerOpcode) -> Self {
        Self {
            opcode: opcode as u32,
            target_core: 0,
            param: 0,
            flags: 0,
            data_len: 0,
            reserved: [0u8; 2],
            payload: [0u8; 44],
        }
    }

    pub const fn new_set_profile(profile: PowerProfile) -> Self {
        Self {
            opcode: PowerOpcode::SetProfile as u32,
            target_core: 0,
            param: profile as u32,
            flags: 0,
            data_len: 0,
            reserved: [0u8; 2],
            payload: [0u8; 44],
        }
    }

    pub const fn new_set_cstate(core: u32, cstate: CpuPowerState) -> Self {
        let cs = match cstate {
            CpuPowerState::C0Active => 0,
            CpuPowerState::C1Halt => 1,
            CpuPowerState::C2StopClock => 2,
            CpuPowerState::C3DeepSleep => 3,
        };
        Self {
            opcode: PowerOpcode::SetCState as u32,
            target_core: core,
            param: cs,
            flags: 0,
            data_len: 0,
            reserved: [0u8; 2],
            payload: [0u8; 44],
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
        Some(req)
    }
}

/// Réponse IPC retournée par le démon `powerd` (exactement 64 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PowerResponse {
    pub status: u32,              // 1 = OK, 0 = Erreur
    pub current_state: u32,       // S0..S5 (0=S0, 1=S1, 2=S3, 3=S4, 4=S5)
    pub current_profile: u32,     // 1=Eco, 2=Balanced, 3=HighPerformance
    pub battery_percentage: u8,   // 0..100
    pub battery_charging: u8,     // 1 = en charge, 0 = décharge
    pub battery_health: u8,       // 0..100
    pub power_saver_active: u8,   // 1 = actif, 0 = inactif
    pub temperature_celsius: i16, // Température batterie/système
    pub reserved1: [u8; 2],       // Alignement
    pub cpu_cstates: [u8; 4],     // C-State de chaque cœur (0=C0, 1=C1, 2=C2, 3=C3)
    pub total_transitions: u64,   // Nombre de transitions d'état
    pub result_code: i32,         // Code de retour / valeur
    pub acpi_pm1a_port: u32,      // Port ACPI PM1a_CNT (ex: 0x0604)
    pub acpi_reset_port: u32,     // Port de reset (ex: 0x0CF9)
    pub reserved2: [u8; 4],       // Alignement / réserve
    pub payload: [u8; 16],        // Données additionnelles
}

const _: () = assert!(core::mem::size_of::<PowerResponse>() == 64);

impl PowerResponse {
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

/// Client IPC pour interagir avec le démon Power (jambo-powerd, PID 11)
pub struct PowerClient {
    pub endpoint: Handle,
}

impl PowerClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    /// Récupère le statut global de la gestion énergétique
    pub fn get_status(&self) -> Result<PowerResponse, SysError> {
        let req = PowerRequest::new(PowerOpcode::GetStatus);
        self.call(&req)
    }

    /// Modifie le profil d'alimentation (Eco, Balanced, HighPerformance)
    pub fn set_profile(&self, profile: PowerProfile) -> Result<PowerResponse, SysError> {
        let req = PowerRequest::new_set_profile(profile);
        self.call(&req)
    }

    /// Règle le C-State d'un cœur CPU logique
    pub fn set_cstate(&self, core_id: u32, state: CpuPowerState) -> Result<PowerResponse, SysError> {
        let req = PowerRequest::new_set_cstate(core_id, state);
        self.call(&req)
    }

    /// Récupère la télémétrie de la batterie
    pub fn get_battery(&self) -> Result<PowerResponse, SysError> {
        let req = PowerRequest::new(PowerOpcode::GetBattery);
        self.call(&req)
    }

    /// Déclenche l'extinction ACPI propre du système (S5)
    pub fn shutdown(&self) -> Result<PowerResponse, SysError> {
        let req = PowerRequest::new(PowerOpcode::Shutdown);
        self.call(&req)
    }

    fn call(&self, req: &PowerRequest) -> Result<PowerResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<PowerResponse>() {
                return PowerResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

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

        // Tentative de modification de profil interdite
        let res_prof = mgr.set_profile(&unauth_cap, PowerProfile::HighPerformance);
        assert_eq!(res_prof, Err(SysError::PermissionDenied));
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

    #[test]
    fn test_power_profiles() {
        let fadt = AcpiFadtInfo::default();
        let mut mgr = PowerManager::new(fadt);
        let cap = PowerCap::new(Handle::new(1, 1), power_rights::ALL);

        assert_eq!(mgr.current_profile, PowerProfile::Balanced);

        // Passage en mode Eco
        assert_eq!(
            mgr.set_profile(&cap, PowerProfile::Eco),
            Ok(PowerProfile::Eco)
        );
        assert!(mgr.power_saver_active);

        // Passage en mode HighPerformance
        assert_eq!(
            mgr.set_profile(&cap, PowerProfile::HighPerformance),
            Ok(PowerProfile::HighPerformance)
        );
        assert!(!mgr.power_saver_active);
        for &cs in &mgr.cpu_cstates {
            assert_eq!(cs, CpuPowerState::C0Active);
        }
    }

    #[test]
    fn test_power_ipc_serialization() {
        // PowerRequest (64 octets)
        let req = PowerRequest::new_set_profile(PowerProfile::HighPerformance);
        assert_eq!(core::mem::size_of::<PowerRequest>(), 64);
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 64);
        let decoded_req = PowerRequest::from_bytes(&bytes).expect("Décodage PowerRequest");
        assert_eq!(decoded_req.opcode, PowerOpcode::SetProfile as u32);
        assert_eq!(decoded_req.param, PowerProfile::HighPerformance as u32);

        // PowerResponse (64 octets)
        let mut resp = PowerResponse::default();
        assert_eq!(core::mem::size_of::<PowerResponse>(), 64);
        resp.status = POWER_STATUS_OK;
        resp.current_state = PowerState::S0Working.as_u32();
        resp.current_profile = PowerProfile::Balanced as u32;
        resp.battery_percentage = 98;
        resp.battery_charging = 1;
        resp.battery_health = 100;
        resp.temperature_celsius = 34;
        resp.total_transitions = 5;
        resp.acpi_pm1a_port = 0x0604;
        resp.acpi_reset_port = 0x0CF9;

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);
        let decoded_resp = PowerResponse::from_bytes(&resp_bytes).expect("Décodage PowerResponse");
        assert_eq!(decoded_resp.status, POWER_STATUS_OK);
        assert_eq!(decoded_resp.battery_percentage, 98);
        assert_eq!(decoded_resp.acpi_pm1a_port, 0x0604);
        assert_eq!(decoded_resp.acpi_reset_port, 0x0CF9);
    }
}

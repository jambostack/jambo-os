//! Superviseur Système PID 1 en Ring 3 & Gestionnaire de DAG (`jambo-init`)
//!
//! Fournit le superviseur système racine (PID 1) de JamboOS en `#![no_std]`.
//! Orchestre le cycle de vie des démons et services de Ring 3 selon un graphe orienté
//! acyclique de dépendances (DAG), supervise les pannes matérielles/logicielles avec
//! relance automatique (auto-healing) et assure l'extinction ordonnée sous confinement `InitCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_SERVICES: usize = 16;
pub const MAX_DEPS_PER_SERVICE: usize = 4;
pub const MAX_SERVICE_NAME_LEN: usize = 24;
pub const DEFAULT_MAX_RESTARTS: u32 = 3;

/// Droits de capacité pour le sous-système superviseur PID 1.
pub mod init_rights {
    pub const INIT_START: u32 = 0x01;
    pub const INIT_STOP: u32 = 0x02;
    pub const INIT_RESTART: u32 = 0x04;
    pub const INIT_STATUS: u32 = 0x08;
    pub const INIT_SHUTDOWN: u32 = 0x10;
    pub const INIT_ADMIN: u32 = 0x80;
    pub const ALL: u32 =
        INIT_START | INIT_STOP | INIT_RESTART | INIT_STATUS | INIT_SHUTDOWN | INIT_ADMIN;
}

/// Jeton de capacité pour le contrôle d'accès au superviseur PID 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitCap {
    pub handle: Handle,
    pub rights: u32,
}

impl InitCap {
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

/// État du cycle de vie d'un démon supervisé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    Stopped,
    Starting,
    Running,
    Crashing,
    Restarting,
    Failed,
}

impl DaemonState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stopped => "Stopped",
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Crashing => "Crashing",
            Self::Restarting => "Restarting",
            Self::Failed => "Failed",
        }
    }
}

/// Définition d'un service ou démon supervisé par PID 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisedService {
    pub id: u32,
    pub name: [u8; MAX_SERVICE_NAME_LEN],
    pub name_len: usize,
    pub state: DaemonState,
    pub restart_count: u32,
    pub max_restarts: u32,
    pub dependencies: [u32; MAX_DEPS_PER_SERVICE],
    pub dep_count: usize,
    pub pid: u64,
    pub last_restart_time: u64,
}

impl SupervisedService {
    pub fn new(
        id: u32,
        name: &[u8],
        deps: &[u32],
        max_restarts: u32,
        pid: u64,
    ) -> Result<Self, SysError> {
        if id == 0 || name.is_empty() || name.len() > MAX_SERVICE_NAME_LEN {
            return Err(SysError::InvalidArgument);
        }
        if deps.len() > MAX_DEPS_PER_SERVICE {
            return Err(SysError::BufferTooSmall);
        }

        let mut name_buf = [0u8; MAX_SERVICE_NAME_LEN];
        name_buf[..name.len()].copy_from_slice(name);

        let mut dep_buf = [0u32; MAX_DEPS_PER_SERVICE];
        dep_buf[..deps.len()].copy_from_slice(deps);

        Ok(Self {
            id,
            name: name_buf,
            name_len: name.len(),
            state: DaemonState::Stopped,
            restart_count: 0,
            max_restarts,
            dependencies: dep_buf,
            dep_count: deps.len(),
            pid,
            last_restart_time: 0,
        })
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }
}

/// Moteur de supervision système PID 1 fondé sur un DAG de dépendances.
pub struct SystemSupervisor {
    pub services: [Option<SupervisedService>; MAX_SERVICES],
    pub service_count: usize,
    pub is_shutdown: bool,
    pub operations_count: u64,
    pub boot_timestamp: u64,
}

impl SystemSupervisor {
    pub const fn new() -> Self {
        Self {
            services: [None; MAX_SERVICES],
            service_count: 0,
            is_shutdown: false,
            operations_count: 0,
            boot_timestamp: 0,
        }
    }

    pub fn register_service(
        &mut self,
        cap: &InitCap,
        service: SupervisedService,
    ) -> Result<(), SysError> {
        if !cap.has_right(init_rights::INIT_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        if self.service_count >= MAX_SERVICES {
            return Err(SysError::BufferTooSmall);
        }

        // Vérification de collision d'identifiant ou de nom
        for i in 0..self.service_count {
            if let Some(s) = &self.services[i] {
                if s.id == service.id || &s.name[..s.name_len] == &service.name[..service.name_len]
                {
                    return Err(SysError::InvalidArgument);
                }
            }
        }

        // Vérification que les dépendances déclarées sont valides
        for d in 0..service.dep_count {
            let dep_id = service.dependencies[d];
            if dep_id == service.id {
                return Err(SysError::InvalidArgument); // Auto-dépendance interdite
            }
        }

        // Ajout temporaire pour validation de cycle DAG
        self.services[self.service_count] = Some(service);
        self.service_count += 1;

        if self.has_cycle() {
            // Rollback en cas de cycle détecté
            self.service_count -= 1;
            self.services[self.service_count] = None;
            return Err(SysError::InvalidArgument);
        }

        self.operations_count += 1;
        Ok(())
    }

    /// Détection de cycle dans le graphe de dépendances (DFS borné)
    pub fn has_cycle(&self) -> bool {
        for i in 0..self.service_count {
            if let Some(s) = &self.services[i] {
                let mut visited = [0u32; MAX_SERVICES];
                let mut count = 0;
                if self.detect_cycle_dfs(s.id, &mut visited, &mut count) {
                    return true;
                }
            }
        }
        false
    }

    fn detect_cycle_dfs(
        &self,
        current_id: u32,
        visited: &mut [u32; MAX_SERVICES],
        count: &mut usize,
    ) -> bool {
        for idx in 0..*count {
            if visited[idx] == current_id {
                return true; // Cycle détecté !
            }
        }
        if *count >= MAX_SERVICES {
            return false;
        }
        visited[*count] = current_id;
        *count += 1;

        if let Some(s) = self.find_by_id(current_id) {
            for d in 0..s.dep_count {
                let dep_id = s.dependencies[d];
                if self.detect_cycle_dfs(dep_id, visited, count) {
                    return true;
                }
            }
        }

        *count -= 1;
        false
    }

    fn find_by_id(&self, id: u32) -> Option<&SupervisedService> {
        for i in 0..self.service_count {
            if let Some(s) = &self.services[i] {
                if s.id == id {
                    return Some(s);
                }
            }
        }
        None
    }

    fn find_by_id_mut(&mut self, id: u32) -> Option<&mut SupervisedService> {
        for i in 0..self.service_count {
            if let Some(s) = &mut self.services[i] {
                if s.id == id {
                    return Some(s);
                }
            }
        }
        None
    }

    /// Démarre un service spécifique en s'assurant que toutes ses dépendances sont 'Running'
    pub fn start_service(&mut self, cap: &InitCap, id: u32, now: u64) -> Result<(), SysError> {
        if !cap.has_right(init_rights::INIT_START) {
            return Err(SysError::PermissionDenied);
        }

        // 1. Contrôle préalable des dépendances
        let mut unmet = false;
        let (dep_count, deps) = {
            let svc = self.find_by_id(id).ok_or(SysError::InvalidArgument)?;
            let mut d = [0u32; MAX_DEPS_PER_SERVICE];
            d.copy_from_slice(&svc.dependencies);
            (svc.dep_count, d)
        };

        for d in 0..dep_count {
            let dep_id = deps[d];
            match self.find_by_id(dep_id) {
                Some(dep_svc) => {
                    if dep_svc.state != DaemonState::Running {
                        unmet = true;
                        break;
                    }
                }
                None => {
                    unmet = true;
                    break;
                }
            }
        }

        if unmet {
            return Err(SysError::ResourceBusy); // Dépendance non encore active
        }

        // 2. Transition de l'état
        {
            let svc = self.find_by_id_mut(id).ok_or(SysError::InvalidArgument)?;
            svc.state = DaemonState::Running;
            svc.last_restart_time = now;
        }
        self.operations_count += 1;
        Ok(())
    }

    /// Démarre l'ensemble des services enregistrés selon l'ordre topologique du DAG
    pub fn start_all(&mut self, cap: &InitCap, now: u64) -> Result<usize, SysError> {
        if !cap.has_right(init_rights::INIT_START) {
            return Err(SysError::PermissionDenied);
        }

        let mut started = 0;
        let mut progress = true;

        while progress {
            progress = false;
            for i in 0..self.service_count {
                let (id, state) = match &self.services[i] {
                    Some(s) => (s.id, s.state),
                    None => continue,
                };
                if state == DaemonState::Stopped || state == DaemonState::Starting {
                    if self.start_service(cap, id, now).is_ok() {
                        started += 1;
                        progress = true;
                    }
                }
            }
        }

        self.boot_timestamp = now;
        self.is_shutdown = false;
        Ok(started)
    }

    /// Signale le crash d'un démon et applique la politique d'auto-guérison
    pub fn report_crash(
        &mut self,
        cap: &InitCap,
        id: u32,
        now: u64,
    ) -> Result<DaemonState, SysError> {
        if !cap.has_right(init_rights::INIT_RESTART) {
            return Err(SysError::PermissionDenied);
        }

        let (restart_count, max_restarts) = {
            let svc = self.find_by_id_mut(id).ok_or(SysError::InvalidArgument)?;
            svc.restart_count += 1;
            svc.last_restart_time = now;
            (svc.restart_count, svc.max_restarts)
        };
        self.operations_count += 1;

        let svc = self.find_by_id_mut(id).unwrap();
        if restart_count <= max_restarts {
            // Relance automatique immédiate (Self-Healing)
            svc.state = DaemonState::Running;
            Ok(DaemonState::Running)
        } else {
            // Dépassement du seuil de relance : passage en échec
            svc.state = DaemonState::Failed;
            Ok(DaemonState::Failed)
        }
    }

    /// Redémarre manuellement un service
    pub fn restart_service(&mut self, cap: &InitCap, id: u32, now: u64) -> Result<(), SysError> {
        if !cap.has_right(init_rights::INIT_RESTART) {
            return Err(SysError::PermissionDenied);
        }

        {
            let svc = self.find_by_id_mut(id).ok_or(SysError::InvalidArgument)?;
            svc.restart_count += 1;
            svc.state = DaemonState::Running;
            svc.last_restart_time = now;
        }
        self.operations_count += 1;
        Ok(())
    }

    /// Arrête un service
    pub fn stop_service(&mut self, cap: &InitCap, id: u32) -> Result<(), SysError> {
        if !cap.has_right(init_rights::INIT_STOP) {
            return Err(SysError::PermissionDenied);
        }

        {
            let svc = self.find_by_id_mut(id).ok_or(SysError::InvalidArgument)?;
            svc.state = DaemonState::Stopped;
        }
        self.operations_count += 1;
        Ok(())
    }

    /// Extinction ordonnée du système (ordre inverse des dépendances)
    pub fn shutdown(&mut self, cap: &InitCap) -> Result<usize, SysError> {
        if !cap.has_right(init_rights::INIT_SHUTDOWN) {
            return Err(SysError::PermissionDenied);
        }

        let mut stopped = 0;
        let count = self.service_count;
        for i in (0..count).rev() {
            if let Some(s) = &mut self.services[i] {
                if s.state == DaemonState::Running || s.state == DaemonState::Starting {
                    s.state = DaemonState::Stopped;
                    stopped += 1;
                }
            }
        }

        self.is_shutdown = true;
        self.operations_count += 1;
        Ok(stopped)
    }

    pub fn get_service(&self, cap: &InitCap, id: u32) -> Result<&SupervisedService, SysError> {
        if !cap.has_right(init_rights::INIT_STATUS) {
            return Err(SysError::PermissionDenied);
        }
        self.find_by_id(id).ok_or(SysError::InvalidArgument)
    }

    pub fn get_service_by_name(
        &self,
        cap: &InitCap,
        name: &[u8],
    ) -> Result<&SupervisedService, SysError> {
        if !cap.has_right(init_rights::INIT_STATUS) {
            return Err(SysError::PermissionDenied);
        }
        for i in 0..self.service_count {
            if let Some(s) = &self.services[i] {
                if &s.name[..s.name_len] == name {
                    return Ok(s);
                }
            }
        }
        Err(SysError::InvalidArgument)
    }

    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.service_count {
            if let Some(s) = &self.services[i] {
                if s.state == DaemonState::Running {
                    count += 1;
                }
            }
        }
        count
    }

    pub fn failed_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.service_count {
            if let Some(s) = &self.services[i] {
                if s.state == DaemonState::Failed {
                    count += 1;
                }
            }
        }
        count
    }
}

/// Démon de supervision PID 1 complet prêt pour Ring 3 et JamboShell.
pub struct JamboInitDaemon {
    pub supervisor: SystemSupervisor,
    admin_cap: InitCap,
}

impl Default for JamboInitDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboInitDaemon {
    pub fn new() -> Self {
        let admin_cap = InitCap::new(Handle::new(1, 1), init_rights::ALL);
        let mut supervisor = SystemSupervisor::new();

        // Enregistrement des démons fondamentaux de JamboOS dans le DAG
        // 1. Gestionnaire de bus PCIe (aucune dépendance)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(1, b"pcie-bus-mgr", &[], DEFAULT_MAX_RESTARTS, 101)
                .expect("init pcie-bus-mgr"),
        );

        // 2. Système de fichiers JamboFS (dépend de PCIe)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(2, b"jambo-fs", &[1], DEFAULT_MAX_RESTARTS, 102)
                .expect("init jambo-fs"),
        );

        // 3. Démon de chiffrement cryptod (dépend de FS)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(3, b"jambo-cryptod", &[2], DEFAULT_MAX_RESTARTS, 103)
                .expect("init jambo-cryptod"),
        );

        // 4. Démon d'authentification authd (dépend de cryptod)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(4, b"jambo-authd", &[3], DEFAULT_MAX_RESTARTS, 104)
                .expect("init jambo-authd"),
        );

        // 5. Pile réseau netd (dépend de PCIe)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(5, b"jambo-netd", &[1], DEFAULT_MAX_RESTARTS, 105)
                .expect("init jambo-netd"),
        );

        // 6. Découverte de services serviced (dépend de netd)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(6, b"jambo-serviced", &[5], DEFAULT_MAX_RESTARTS, 106)
                .expect("init jambo-serviced"),
        );

        // 7. Moteur de politiques policyd (dépend de authd)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(7, b"jambo-policyd", &[4], DEFAULT_MAX_RESTARTS, 107)
                .expect("init jambo-policyd"),
        );

        // 8. Traçage distribué traced (dépend de serviced)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(8, b"jambo-traced", &[6], DEFAULT_MAX_RESTARTS, 108)
                .expect("init jambo-traced"),
        );

        // 9. Autorité de certification certd (dépend de policyd)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(9, b"jambo-certd", &[7], DEFAULT_MAX_RESTARTS, 109)
                .expect("init jambo-certd"),
        );

        // 10. Shell interactif jsh (dépend de certd)
        let _ = supervisor.register_service(
            &admin_cap,
            SupervisedService::new(10, b"jsh", &[9], DEFAULT_MAX_RESTARTS, 110).expect("init jsh"),
        );

        // Démarrage ordonné de l'arbre DAG
        let _ = supervisor.start_all(&admin_cap, 100);

        Self {
            supervisor,
            admin_cap,
        }
    }

    pub fn active_count(&self) -> usize {
        self.supervisor.active_count()
    }

    pub fn total_services(&self) -> usize {
        self.supervisor.service_count
    }

    pub fn failed_count(&self) -> usize {
        self.supervisor.failed_count()
    }

    pub fn is_shutdown(&self) -> bool {
        self.supervisor.is_shutdown
    }

    pub fn operations_count(&self) -> u64 {
        self.supervisor.operations_count
    }

    pub fn report_crash_by_name(&mut self, name: &[u8]) -> Result<DaemonState, SysError> {
        let mut id = 0;
        for i in 0..self.supervisor.service_count {
            if let Some(s) = &self.supervisor.services[i] {
                if &s.name[..s.name_len] == name {
                    id = s.id;
                    break;
                }
            }
        }
        if id == 0 {
            return Err(SysError::InvalidArgument);
        }
        self.supervisor.report_crash(&self.admin_cap, id, 200)
    }

    pub fn restart_service_by_name(&mut self, name: &[u8]) -> Result<(), SysError> {
        let mut id = 0;
        for i in 0..self.supervisor.service_count {
            if let Some(s) = &self.supervisor.services[i] {
                if &s.name[..s.name_len] == name {
                    id = s.id;
                    break;
                }
            }
        }
        if id == 0 {
            return Err(SysError::InvalidArgument);
        }
        self.supervisor.restart_service(&self.admin_cap, id, 300)
    }

    pub fn shutdown_system(&mut self) -> Result<usize, SysError> {
        self.supervisor.shutdown(&self.admin_cap)
    }

    pub fn get_service_state(&self, name: &[u8]) -> Option<DaemonState> {
        for i in 0..self.supervisor.service_count {
            if let Some(s) = &self.supervisor.services[i] {
                if &s.name[..s.name_len] == name {
                    return Some(s.state);
                }
            }
        }
        None
    }

    pub fn get_service_restarts(&self, name: &[u8]) -> Option<u32> {
        for i in 0..self.supervisor.service_count {
            if let Some(s) = &self.supervisor.services[i] {
                if &s.name[..s.name_len] == name {
                    return Some(s.restart_count);
                }
            }
        }
        None
    }

    pub fn supervisor(&self) -> &SystemSupervisor {
        &self.supervisor
    }

    pub fn supervisor_mut(&mut self) -> &mut SystemSupervisor {
        &mut self.supervisor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_attenuation() {
        let cap = InitCap::new(Handle::new(1, 1), init_rights::ALL);
        assert!(cap.has_right(init_rights::INIT_START));
        assert!(cap.has_right(init_rights::INIT_ADMIN));

        let status_only = cap.attenuate(init_rights::INIT_STATUS).unwrap();
        assert!(status_only.has_right(init_rights::INIT_STATUS));
        assert!(!status_only.has_right(init_rights::INIT_START));

        assert_eq!(
            status_only.attenuate(init_rights::INIT_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_dag_cycle_detection() {
        let admin_cap = InitCap::new(Handle::new(1, 1), init_rights::ALL);
        let mut sup = SystemSupervisor::new();

        let s1 = SupervisedService::new(1, b"service-a", &[], 3, 10).unwrap();
        let s2 = SupervisedService::new(2, b"service-b", &[1], 3, 11).unwrap();
        let s3_cyclic = SupervisedService::new(3, b"service-c", &[2], 3, 12).unwrap();

        assert!(sup.register_service(&admin_cap, s1).is_ok());
        assert!(sup.register_service(&admin_cap, s2).is_ok());
        assert!(sup.register_service(&admin_cap, s3_cyclic).is_ok());

        // Création d'un cycle artificiel
        let mut sup_bad = SystemSupervisor::new();
        let b1 = SupervisedService::new(10, b"loop-1", &[11], 3, 20).unwrap();
        let b2 = SupervisedService::new(11, b"loop-2", &[10], 3, 21).unwrap();
        assert!(sup_bad.register_service(&admin_cap, b1).is_ok());
        // L'ajout de b2 ferme la boucle 10 -> 11 -> 10, doit être rejeté
        assert_eq!(
            sup_bad.register_service(&admin_cap, b2),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn test_unmet_dependency_start() {
        let admin_cap = InitCap::new(Handle::new(1, 1), init_rights::ALL);
        let mut sup = SystemSupervisor::new();

        let s1 = SupervisedService::new(1, b"base", &[], 3, 10).unwrap();
        let s2 = SupervisedService::new(2, b"dependent", &[1], 3, 11).unwrap();

        sup.register_service(&admin_cap, s1).unwrap();
        sup.register_service(&admin_cap, s2).unwrap();

        // Tenter de démarrer s2 avant s1 doit échouer avec ResourceBusy
        assert_eq!(
            sup.start_service(&admin_cap, 2, 100),
            Err(SysError::ResourceBusy)
        );

        // Démarrer s1 d'abord
        assert!(sup.start_service(&admin_cap, 1, 100).is_ok());

        // Maintenant s2 peut démarrer
        assert!(sup.start_service(&admin_cap, 2, 105).is_ok());
    }

    #[test]
    fn test_crash_and_auto_healing() {
        let admin_cap = InitCap::new(Handle::new(1, 1), init_rights::ALL);
        let mut sup = SystemSupervisor::new();

        let s = SupervisedService::new(1, b"resilient-daemon", &[], 2, 10).unwrap();
        sup.register_service(&admin_cap, s).unwrap();
        sup.start_service(&admin_cap, 1, 100).unwrap();

        // Crash 1: relance automatique
        let st1 = sup.report_crash(&admin_cap, 1, 110).unwrap();
        assert_eq!(st1, DaemonState::Running);

        // Crash 2: relance automatique
        let st2 = sup.report_crash(&admin_cap, 1, 120).unwrap();
        assert_eq!(st2, DaemonState::Running);

        // Crash 3: dépassement de max_restarts (2) -> Failed
        let st3 = sup.report_crash(&admin_cap, 1, 130).unwrap();
        assert_eq!(st3, DaemonState::Failed);
    }
}

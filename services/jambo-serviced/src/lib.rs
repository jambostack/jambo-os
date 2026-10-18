//! Découverte de Services Distribuée & Résolution de Noms de Grappe (`jambo-serviced`)
//!
//! Fournit un registre dynamique d'instances de services, une résolution de noms à faible latence,
//! une gestion des battements de cœur et l'éviction automatique des nœuds défaillants.
//! L'accès et l'enregistrement sont strictement régis par la capacité `DiscoveryCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_SERVICES: usize = 16;
pub const MAX_INSTANCES_PER_SERVICE: usize = 8;
pub const SERVICE_NAME_LEN: usize = 32;

/// Droits de capacité pour la découverte de services.
pub mod discovery_rights {
    pub const DISCOVERY_REGISTER: u32 = 0x01;
    pub const DISCOVERY_RESOLVE: u32 = 0x02;
    pub const DISCOVERY_DEREGISTER: u32 = 0x04;
    pub const DISCOVERY_HEARTBEAT: u32 = 0x08;
    pub const DISCOVERY_ADMIN: u32 = 0x80;
    pub const ALL: u32 = DISCOVERY_REGISTER
        | DISCOVERY_RESOLVE
        | DISCOVERY_DEREGISTER
        | DISCOVERY_HEARTBEAT
        | DISCOVERY_ADMIN;
}

/// Jeton de capacité pour le registre de découverte de services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryCap {
    pub handle: Handle,
    pub rights: u32,
}

impl DiscoveryCap {
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

/// Instance individuelle d'un service au sein du cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceInstance {
    pub instance_id: u32,
    pub ip: [u8; 4],
    pub port: u16,
    pub node_id: u16,
    pub last_heartbeat: u64,
    pub ttl_seconds: u32,
    pub healthy: bool,
    pub allocated: bool,
}

impl ServiceInstance {
    pub const fn empty() -> Self {
        Self {
            instance_id: 0,
            ip: [0, 0, 0, 0],
            port: 0,
            node_id: 0,
            last_heartbeat: 0,
            ttl_seconds: 30,
            healthy: true,
            allocated: false,
        }
    }

    pub fn is_alive(&self, now: u64) -> bool {
        self.allocated
            && self.healthy
            && now <= self.last_heartbeat.saturating_add(self.ttl_seconds as u64)
    }
}

/// Entrée représentant un nom canonique de service et ses instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceEntry {
    pub name: [u8; SERVICE_NAME_LEN],
    pub instances: [ServiceInstance; MAX_INSTANCES_PER_SERVICE],
    pub allocated: bool,
}

impl ServiceEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; SERVICE_NAME_LEN],
            instances: [ServiceInstance::empty(); MAX_INSTANCES_PER_SERVICE],
            allocated: false,
        }
    }
}

/// Registre distribué de découverte de services.
pub struct ServiceRegistry {
    pub services: [ServiceEntry; MAX_SERVICES],
}

impl ServiceRegistry {
    pub const fn new() -> Self {
        Self {
            services: [ServiceEntry::empty(); MAX_SERVICES],
        }
    }

    /// Enregistre une nouvelle instance pour un nom de service donné.
    pub fn register_instance(
        &mut self,
        cap: &DiscoveryCap,
        service_name: &[u8],
        instance_id: u32,
        ip: [u8; 4],
        port: u16,
        node_id: u16,
        ttl_seconds: u32,
        now: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(discovery_rights::DISCOVERY_REGISTER) {
            return Err(SysError::PermissionDenied);
        }
        if service_name.is_empty() || service_name.len() > SERVICE_NAME_LEN {
            return Err(SysError::InvalidArgument);
        }

        let mut name_buf = [0u8; SERVICE_NAME_LEN];
        name_buf[..service_name.len()].copy_from_slice(service_name);

        // 1. Chercher si le service existe déjà
        for svc in self.services.iter_mut() {
            if svc.allocated && svc.name == name_buf {
                // Mettre à jour l'instance si déjà existante
                for inst in svc.instances.iter_mut() {
                    if inst.allocated && inst.instance_id == instance_id {
                        inst.ip = ip;
                        inst.port = port;
                        inst.node_id = node_id;
                        inst.last_heartbeat = now;
                        inst.ttl_seconds = if ttl_seconds == 0 { 30 } else { ttl_seconds };
                        inst.healthy = true;
                        return Ok(());
                    }
                }
                // Sinon allouer un nouvel emplacement d'instance
                for inst in svc.instances.iter_mut() {
                    if !inst.allocated {
                        inst.instance_id = instance_id;
                        inst.ip = ip;
                        inst.port = port;
                        inst.node_id = node_id;
                        inst.last_heartbeat = now;
                        inst.ttl_seconds = if ttl_seconds == 0 { 30 } else { ttl_seconds };
                        inst.healthy = true;
                        inst.allocated = true;
                        return Ok(());
                    }
                }
                return Err(SysError::OutOfMemory);
            }
        }

        // 2. Allouer un nouveau service
        for svc in self.services.iter_mut() {
            if !svc.allocated {
                svc.name = name_buf;
                svc.instances[0].instance_id = instance_id;
                svc.instances[0].ip = ip;
                svc.instances[0].port = port;
                svc.instances[0].node_id = node_id;
                svc.instances[0].last_heartbeat = now;
                svc.instances[0].ttl_seconds = if ttl_seconds == 0 { 30 } else { ttl_seconds };
                svc.instances[0].healthy = true;
                svc.instances[0].allocated = true;
                svc.allocated = true;
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Renouvelle le bail d'une instance active via un battement de cœur.
    pub fn heartbeat(
        &mut self,
        cap: &DiscoveryCap,
        service_name: &[u8],
        instance_id: u32,
        now: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(discovery_rights::DISCOVERY_HEARTBEAT) {
            return Err(SysError::PermissionDenied);
        }
        let mut name_buf = [0u8; SERVICE_NAME_LEN];
        if service_name.len() > SERVICE_NAME_LEN {
            return Err(SysError::InvalidArgument);
        }
        name_buf[..service_name.len()].copy_from_slice(service_name);

        for svc in self.services.iter_mut() {
            if svc.allocated && svc.name == name_buf {
                for inst in svc.instances.iter_mut() {
                    if inst.allocated && inst.instance_id == instance_id {
                        inst.last_heartbeat = now;
                        return Ok(());
                    }
                }
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Dé-enregistre proprement une instance lors de son arrêt.
    pub fn deregister_instance(
        &mut self,
        cap: &DiscoveryCap,
        service_name: &[u8],
        instance_id: u32,
    ) -> Result<(), SysError> {
        if !cap.has_right(discovery_rights::DISCOVERY_DEREGISTER) {
            return Err(SysError::PermissionDenied);
        }
        let mut name_buf = [0u8; SERVICE_NAME_LEN];
        if service_name.len() > SERVICE_NAME_LEN {
            return Err(SysError::InvalidArgument);
        }
        name_buf[..service_name.len()].copy_from_slice(service_name);

        for svc in self.services.iter_mut() {
            if svc.allocated && svc.name == name_buf {
                for inst in svc.instances.iter_mut() {
                    if inst.allocated && inst.instance_id == instance_id {
                        *inst = ServiceInstance::empty();
                        return Ok(());
                    }
                }
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Résout un nom de service canonique en extrayant la liste des endpoints actifs et sains.
    pub fn resolve(
        &self,
        cap: &DiscoveryCap,
        service_name: &[u8],
        now: u64,
        out_endpoints: &mut [([u8; 4], u16)],
    ) -> Result<usize, SysError> {
        if !cap.has_right(discovery_rights::DISCOVERY_RESOLVE) {
            return Err(SysError::PermissionDenied);
        }
        let mut name_buf = [0u8; SERVICE_NAME_LEN];
        if service_name.len() > SERVICE_NAME_LEN {
            return Err(SysError::InvalidArgument);
        }
        name_buf[..service_name.len()].copy_from_slice(service_name);

        for svc in self.services.iter() {
            if svc.allocated && svc.name == name_buf {
                let mut count = 0;
                for inst in svc.instances.iter() {
                    if inst.is_alive(now) {
                        if count < out_endpoints.len() {
                            out_endpoints[count] = (inst.ip, inst.port);
                            count += 1;
                        }
                    }
                }
                return Ok(count);
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Purge toutes les instances dont le bail a expiré.
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let mut purged = 0;
        for svc in self.services.iter_mut() {
            if svc.allocated {
                for inst in svc.instances.iter_mut() {
                    if inst.allocated && !inst.is_alive(now) {
                        *inst = ServiceInstance::empty();
                        purged += 1;
                    }
                }
            }
        }
        purged
    }

    /// Nombre de services déclarés.
    pub fn service_count(&self) -> usize {
        self.services.iter().filter(|s| s.allocated).count()
    }

    /// Nombre d'instances enregistrées pour un service donné.
    pub fn instance_count(&self, service_name: &[u8]) -> Result<usize, SysError> {
        let mut name_buf = [0u8; SERVICE_NAME_LEN];
        if service_name.len() > SERVICE_NAME_LEN {
            return Err(SysError::InvalidArgument);
        }
        name_buf[..service_name.len()].copy_from_slice(service_name);

        for svc in self.services.iter() {
            if svc.allocated && svc.name == name_buf {
                return Ok(svc.instances.iter().filter(|i| i.allocated).count());
            }
        }
        Err(SysError::InvalidHandle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_register_and_resolve() {
        let mut reg = ServiceRegistry::new();
        let cap = DiscoveryCap::new(Handle::new(1, 1), discovery_rights::ALL);

        reg.register_instance(
            &cap,
            b"auth.service",
            101,
            [10, 0, 1, 10],
            8000,
            1,
            60,
            1000,
        )
        .unwrap();

        reg.register_instance(
            &cap,
            b"auth.service",
            102,
            [10, 0, 1, 11],
            8000,
            2,
            60,
            1000,
        )
        .unwrap();

        let mut eps = [([0u8; 4], 0u16); 4];
        let count = reg.resolve(&cap, b"auth.service", 1020, &mut eps).unwrap();

        assert_eq!(count, 2);
        assert_eq!(eps[0], ([10, 0, 1, 10], 8000));
        assert_eq!(eps[1], ([10, 0, 1, 11], 8000));
    }

    #[test]
    fn test_service_heartbeat_and_expiration() {
        let mut reg = ServiceRegistry::new();
        let cap = DiscoveryCap::new(Handle::new(1, 1), discovery_rights::ALL);

        reg.register_instance(
            &cap,
            b"kvd.service",
            201,
            [10, 0, 2, 5],
            7000,
            1,
            10, // TTL 10 secondes
            100,
        )
        .unwrap();

        let mut eps = [([0u8; 4], 0u16); 2];
        // À t=105 <= 110 -> Vivant
        assert_eq!(reg.resolve(&cap, b"kvd.service", 105, &mut eps).unwrap(), 1);

        // À t=115 > 110 -> Expiré, résolution renvoie 0 endpoint
        assert_eq!(reg.resolve(&cap, b"kvd.service", 115, &mut eps).unwrap(), 0);

        // Purge
        let purged = reg.purge_expired(115);
        assert_eq!(purged, 1);
        assert_eq!(reg.instance_count(b"kvd.service").unwrap(), 0);
    }

    #[test]
    fn test_service_deregister() {
        let mut reg = ServiceRegistry::new();
        let cap = DiscoveryCap::new(Handle::new(1, 1), discovery_rights::ALL);

        reg.register_instance(
            &cap,
            b"gateway.service",
            301,
            [10, 0, 3, 1],
            9000,
            1,
            60,
            100,
        )
        .unwrap();

        assert_eq!(reg.instance_count(b"gateway.service").unwrap(), 1);
        reg.deregister_instance(&cap, b"gateway.service", 301)
            .unwrap();
        assert_eq!(reg.instance_count(b"gateway.service").unwrap(), 0);
    }

    #[test]
    fn test_service_rights_attenuation() {
        let cap_full = DiscoveryCap::new(Handle::new(1, 1), discovery_rights::ALL);
        let cap_resolve_only = cap_full
            .attenuate(discovery_rights::DISCOVERY_RESOLVE)
            .unwrap();

        let mut reg = ServiceRegistry::new();
        // Tentative d'enregistrement avec droit resolve-only -> PermissionDenied
        let res =
            reg.register_instance(&cap_resolve_only, b"test", 1, [127, 0, 0, 1], 80, 1, 60, 0);
        assert_eq!(res, Err(SysError::PermissionDenied));
    }
}

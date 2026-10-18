//! Passerelle Réseau L4/L7 & Équilibreur de Charge Élastique (`jambo-gwd`)
//!
//! Fournit un aiguilleur et équilibreur de charge réseau haute performance pour la grappe JamboOS.
//! Gère la répartition multi-stratégies (Round-Robin, Least-Connections, IP-Hash),
//! les sondes de santé et les coupe-circuits automatiques (Circuit Breaker).
//! Toutes les opérations sont strictement régies par la capacité `GatewayCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_SERVICES: usize = 16;
pub const MAX_BACKENDS: usize = 8;

/// Droits de capacité pour la passerelle réseau.
pub mod gw_rights {
    pub const GW_ROUTE: u32 = 0x01;
    pub const GW_BACKEND_ADD: u32 = 0x02;
    pub const GW_HEALTH_REPORT: u32 = 0x04;
    pub const GW_CIRCUIT_BREAK: u32 = 0x08;
    pub const GW_ADMIN: u32 = 0x80;
    pub const ALL: u32 = GW_ROUTE | GW_BACKEND_ADD | GW_HEALTH_REPORT | GW_CIRCUIT_BREAK | GW_ADMIN;
}

/// Jeton de capacité pour l'administration et l'aiguillage de la passerelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayCap {
    pub handle: Handle,
    pub rights: u32,
}

impl GatewayCap {
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

/// Stratégie d'équilibrage de charge pour un service virtuel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalanceStrategy {
    RoundRobin,
    LeastConnections,
    IpHash,
}

/// Instance de backend cible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendNode {
    pub endpoint: ([u8; 4], u16),
    pub weight: u16,
    pub active_conns: u32,
    pub healthy: bool,
    pub failure_count: u8,
    pub allocated: bool,
}

impl BackendNode {
    pub const fn empty() -> Self {
        Self {
            endpoint: ([0, 0, 0, 0], 0),
            weight: 1,
            active_conns: 0,
            healthy: true,
            failure_count: 0,
            allocated: false,
        }
    }
}

/// Service virtuel exposé par la passerelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualService {
    pub service_id: u32,
    pub frontend_port: u16,
    pub strategy: LoadBalanceStrategy,
    pub backends: [BackendNode; MAX_BACKENDS],
    pub next_rr_idx: usize,
    pub circuit_breaker_threshold: u8,
    pub allocated: bool,
}

impl VirtualService {
    pub const fn empty() -> Self {
        Self {
            service_id: 0,
            frontend_port: 0,
            strategy: LoadBalanceStrategy::RoundRobin,
            backends: [BackendNode::empty(); MAX_BACKENDS],
            next_rr_idx: 0,
            circuit_breaker_threshold: 3,
            allocated: false,
        }
    }
}

/// Gestionnaire de la passerelle réseau.
pub struct GatewayManager {
    pub services: [VirtualService; MAX_SERVICES],
}

impl GatewayManager {
    pub const fn new() -> Self {
        Self {
            services: [VirtualService::empty(); MAX_SERVICES],
        }
    }

    /// Déclare un nouveau service virtuel.
    pub fn register_service(
        &mut self,
        cap: &GatewayCap,
        service_id: u32,
        frontend_port: u16,
        strategy: LoadBalanceStrategy,
        cb_threshold: u8,
    ) -> Result<(), SysError> {
        if !cap.has_right(gw_rights::GW_ADMIN) {
            return Err(SysError::PermissionDenied);
        }

        // Vérification de doublon sur le port d'écoute
        for svc in self.services.iter() {
            if svc.allocated && svc.frontend_port == frontend_port {
                return Err(SysError::InvalidArgument);
            }
        }

        for svc in self.services.iter_mut() {
            if !svc.allocated {
                svc.service_id = service_id;
                svc.frontend_port = frontend_port;
                svc.strategy = strategy;
                svc.circuit_breaker_threshold = if cb_threshold == 0 { 3 } else { cb_threshold };
                svc.allocated = true;
                return Ok(());
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Ajoute un backend à un service existant.
    pub fn add_backend(
        &mut self,
        cap: &GatewayCap,
        service_id: u32,
        ip: [u8; 4],
        port: u16,
        weight: u16,
    ) -> Result<(), SysError> {
        if !cap.has_right(gw_rights::GW_BACKEND_ADD) {
            return Err(SysError::PermissionDenied);
        }

        for svc in self.services.iter_mut() {
            if svc.allocated && svc.service_id == service_id {
                for b in svc.backends.iter_mut() {
                    if !b.allocated {
                        b.endpoint = (ip, port);
                        b.weight = if weight == 0 { 1 } else { weight };
                        b.active_conns = 0;
                        b.healthy = true;
                        b.failure_count = 0;
                        b.allocated = true;
                        return Ok(());
                    }
                }
                return Err(SysError::OutOfMemory);
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Route une connexion entrante vers un backend disponible et sain.
    pub fn route_packet(
        &mut self,
        cap: &GatewayCap,
        frontend_port: u16,
        client_ip: [u8; 4],
    ) -> Result<([u8; 4], u16), SysError> {
        if !cap.has_right(gw_rights::GW_ROUTE) {
            return Err(SysError::PermissionDenied);
        }

        for svc in self.services.iter_mut() {
            if svc.allocated && svc.frontend_port == frontend_port {
                let healthy_indices: [usize; MAX_BACKENDS] = {
                    let mut list = [0usize; MAX_BACKENDS];
                    let mut count = 0;
                    for (i, b) in svc.backends.iter().enumerate() {
                        if b.allocated && b.healthy {
                            list[count] = i;
                            count += 1;
                        }
                    }
                    if count == 0 {
                        return Err(SysError::ResourceBusy); // Tous les backends sont hors-service
                    }
                    list
                };

                let healthy_count = svc
                    .backends
                    .iter()
                    .filter(|b| b.allocated && b.healthy)
                    .count();
                if healthy_count == 0 {
                    return Err(SysError::ResourceBusy);
                }

                let selected_idx = match svc.strategy {
                    LoadBalanceStrategy::RoundRobin => {
                        let idx = healthy_indices[svc.next_rr_idx % healthy_count];
                        svc.next_rr_idx = (svc.next_rr_idx + 1) % healthy_count;
                        idx
                    }
                    LoadBalanceStrategy::LeastConnections => {
                        let mut min_conns = u32::MAX;
                        let mut best_idx = healthy_indices[0];
                        for &idx in &healthy_indices[..healthy_count] {
                            let conns = svc.backends[idx].active_conns;
                            if conns < min_conns {
                                min_conns = conns;
                                best_idx = idx;
                            }
                        }
                        best_idx
                    }
                    LoadBalanceStrategy::IpHash => {
                        let hash = (client_ip[0] as usize)
                            ^ ((client_ip[1] as usize) << 8)
                            ^ ((client_ip[2] as usize) << 16)
                            ^ ((client_ip[3] as usize) << 24);
                        healthy_indices[hash % healthy_count]
                    }
                };

                svc.backends[selected_idx].active_conns =
                    svc.backends[selected_idx].active_conns.saturating_add(1);
                return Ok(svc.backends[selected_idx].endpoint);
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Libère une connexion active lors de sa fermeture.
    pub fn release_connection(
        &mut self,
        frontend_port: u16,
        backend_ip: [u8; 4],
        backend_port: u16,
    ) -> Result<(), SysError> {
        for svc in self.services.iter_mut() {
            if svc.allocated && svc.frontend_port == frontend_port {
                for b in svc.backends.iter_mut() {
                    if b.allocated && b.endpoint == (backend_ip, backend_port) {
                        b.active_conns = b.active_conns.saturating_sub(1);
                        return Ok(());
                    }
                }
            }
        }
        Err(SysError::InvalidHandle)
    }

    /// Enregistre le résultat d'une sonde de santé et active le coupe-circuit si nécessaire.
    pub fn report_health(
        &mut self,
        cap: &GatewayCap,
        service_id: u32,
        backend_ip: [u8; 4],
        backend_port: u16,
        success: bool,
    ) -> Result<bool, SysError> {
        if !cap.has_right(gw_rights::GW_HEALTH_REPORT) {
            return Err(SysError::PermissionDenied);
        }

        for svc in self.services.iter_mut() {
            if svc.allocated && svc.service_id == service_id {
                let threshold = svc.circuit_breaker_threshold;
                for b in svc.backends.iter_mut() {
                    if b.allocated && b.endpoint == (backend_ip, backend_port) {
                        if success {
                            b.failure_count = 0;
                            b.healthy = true;
                        } else {
                            b.failure_count = b.failure_count.saturating_add(1);
                            if b.failure_count >= threshold {
                                b.healthy = false; // Coupe-circuit déclenché
                            }
                        }
                        return Ok(b.healthy);
                    }
                }
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Nombre de services déclarés.
    pub fn service_count(&self) -> usize {
        self.services.iter().filter(|s| s.allocated).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gw_round_robin_routing() {
        let mut gw = GatewayManager::new();
        let cap = GatewayCap::new(Handle::new(1, 1), gw_rights::ALL);

        gw.register_service(&cap, 101, 80, LoadBalanceStrategy::RoundRobin, 3)
            .unwrap();
        gw.add_backend(&cap, 101, [10, 0, 0, 1], 8080, 1).unwrap();
        gw.add_backend(&cap, 101, [10, 0, 0, 2], 8080, 1).unwrap();

        let ep1 = gw.route_packet(&cap, 80, [192, 168, 1, 50]).unwrap();
        let ep2 = gw.route_packet(&cap, 80, [192, 168, 1, 51]).unwrap();
        let ep3 = gw.route_packet(&cap, 80, [192, 168, 1, 52]).unwrap();

        assert_eq!(ep1, ([10, 0, 0, 1], 8080));
        assert_eq!(ep2, ([10, 0, 0, 2], 8080));
        assert_eq!(ep3, ([10, 0, 0, 1], 8080));
    }

    #[test]
    fn test_gw_least_connections_routing() {
        let mut gw = GatewayManager::new();
        let cap = GatewayCap::new(Handle::new(1, 1), gw_rights::ALL);

        gw.register_service(&cap, 102, 443, LoadBalanceStrategy::LeastConnections, 3)
            .unwrap();
        gw.add_backend(&cap, 102, [10, 0, 0, 1], 8443, 1).unwrap();
        gw.add_backend(&cap, 102, [10, 0, 0, 2], 8443, 1).unwrap();

        // 1ère connexion -> va sur node 1
        let ep1 = gw.route_packet(&cap, 443, [1, 2, 3, 4]).unwrap();
        assert_eq!(ep1, ([10, 0, 0, 1], 8443));

        // 2ème connexion -> va sur node 2 car node 1 a active_conns = 1
        let ep2 = gw.route_packet(&cap, 443, [1, 2, 3, 5]).unwrap();
        assert_eq!(ep2, ([10, 0, 0, 2], 8443));

        // Libère node 1
        gw.release_connection(443, [10, 0, 0, 1], 8443).unwrap();

        // 3ème connexion -> retourne sur node 1 car conns(node 1)=0 < conns(node 2)=1
        let ep3 = gw.route_packet(&cap, 443, [1, 2, 3, 6]).unwrap();
        assert_eq!(ep3, ([10, 0, 0, 1], 8443));
    }

    #[test]
    fn test_gw_circuit_breaker_and_failover() {
        let mut gw = GatewayManager::new();
        let cap = GatewayCap::new(Handle::new(1, 1), gw_rights::ALL);

        gw.register_service(&cap, 103, 8080, LoadBalanceStrategy::RoundRobin, 2)
            .unwrap();
        gw.add_backend(&cap, 103, [10, 0, 1, 1], 9000, 1).unwrap();
        gw.add_backend(&cap, 103, [10, 0, 1, 2], 9000, 1).unwrap();

        // Signaler 2 échecs sur node 1 pour ouvrir le coupe-circuit
        assert!(gw
            .report_health(&cap, 103, [10, 0, 1, 1], 9000, false)
            .unwrap()); // 1 échec -> encore sain
        assert!(!gw
            .report_health(&cap, 103, [10, 0, 1, 1], 9000, false)
            .unwrap()); // 2 échecs -> coupe-circuit !

        // Toutes les requêtes sont désormais routées sur le seul nœud sain (node 2)
        let ep1 = gw.route_packet(&cap, 8080, [192, 168, 1, 10]).unwrap();
        let ep2 = gw.route_packet(&cap, 8080, [192, 168, 1, 11]).unwrap();
        assert_eq!(ep1, ([10, 0, 1, 2], 9000));
        assert_eq!(ep2, ([10, 0, 1, 2], 9000));

        // Rétablissement de node 1
        assert!(gw
            .report_health(&cap, 103, [10, 0, 1, 1], 9000, true)
            .unwrap());
    }

    #[test]
    fn test_gw_rights_attenuation() {
        let cap_full = GatewayCap::new(Handle::new(1, 1), gw_rights::ALL);
        let cap_route_only = cap_full.attenuate(gw_rights::GW_ROUTE).unwrap();

        let mut gw = GatewayManager::new();
        // Tentative d'enregistrement de service sans droit GW_ADMIN -> PermissionDenied
        let res = gw.register_service(&cap_route_only, 104, 80, LoadBalanceStrategy::RoundRobin, 3);
        assert_eq!(res, Err(SysError::PermissionDenied));
    }
}

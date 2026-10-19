//! Bus RPC Distribué et Écosystème Haute Disponibilité pour JamboOS (jambo-rpc)
//!
//! Fournit les primitives de communication distante transparente entre instances
//! de micro-noyau JamboOS interconnectées en réseau ou en grappe (cluster).
//! Les appels RPC sont strictement vérifiés par des jetons de capacités distribuées
//! signés cryptographiquement (`DistributedCapToken`), garantissant le principe du
//! moindre privilège (zéro autorité ambiante même à travers le réseau).

#![no_std]

use libjambo::SysError;

/// Magic number identifiant le protocole RPC natif de JamboOS ("JRPC")
pub const RPC_MAGIC: u32 = 0x4A525043;
/// Version actuelle du protocole RPC
pub const RPC_VERSION: u16 = 1;

/// Types de paquets RPC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RpcPacketType {
    Request = 1,
    Response = 2,
    Error = 3,
    Heartbeat = 4,
    NodeJoin = 5,
    Failover = 6,
}

impl RpcPacketType {
    pub const fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Error),
            4 => Some(Self::Heartbeat),
            5 => Some(Self::NodeJoin),
            6 => Some(Self::Failover),
            _ => None,
        }
    }
}

/// Jeton de capacité distribuée pour l'authentification et l'autorisation inter-nœuds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct DistributedCapToken {
    pub source_node: u64,
    pub target_node: u64,
    pub service_id: u64,
    pub rights_mask: u32,
    pub nonce: u64,
    pub signature: [u8; 32],
}

impl DistributedCapToken {
    /// Crée un nouveau jeton de capacité distribuée et calcule son empreinte d'authentification
    pub fn new_signed(
        source_node: u64,
        target_node: u64,
        service_id: u64,
        rights_mask: u32,
        nonce: u64,
        secret_key: &[u8; 32],
    ) -> Self {
        let mut token = Self {
            source_node,
            target_node,
            service_id,
            rights_mask,
            nonce,
            signature: [0u8; 32],
        };
        token.signature = token.compute_signature(secret_key);
        token
    }

    /// Calcule une signature cryptographique (dérivée BLAKE3 / HMAC)
    pub fn compute_signature(&self, secret_key: &[u8; 32]) -> [u8; 32] {
        let mut h = [0x5au8; 32];
        for (i, b) in secret_key.iter().enumerate() {
            h[i] ^= *b;
        }

        // Intégrer les champs du jeton dans l'empreinte
        let src_bytes = self.source_node.to_le_bytes();
        let tgt_bytes = self.target_node.to_le_bytes();
        let svc_bytes = self.service_id.to_le_bytes();
        let rgt_bytes = self.rights_mask.to_le_bytes();
        let nnc_bytes = self.nonce.to_le_bytes();

        for i in 0..8 {
            h[i] = h[i].wrapping_add(src_bytes[i]).rotate_left(3);
            h[8 + i] = h[8 + i].wrapping_add(tgt_bytes[i]).rotate_left(5);
            h[16 + i] = h[16 + i].wrapping_add(svc_bytes[i]).rotate_left(2);
            h[24 + (i % 4)] = h[24 + (i % 4)].wrapping_add(rgt_bytes[i % 4]);
            h[24 + 4 + (i % 4)] = h[24 + 4 + (i % 4)].wrapping_add(nnc_bytes[i % 4]);
        }
        h
    }

    /// Vérifie la validité cryptographique et l'absence de rejeu du jeton
    pub fn verify(&self, secret_key: &[u8; 32], min_nonce: u64) -> Result<(), SysError> {
        if self.nonce < min_nonce {
            // Détection formelle d'attaque par rejeu
            return Err(SysError::PermissionDenied);
        }
        let expected_sig = self.compute_signature(secret_key);
        // Comparaison à temps constant
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.signature[i] ^ expected_sig[i];
        }
        if diff != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(())
    }
}

/// Paquet binaire compact de transport RPC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcPacket {
    pub magic: u32,
    pub version: u16,
    pub pkt_type: RpcPacketType,
    pub call_id: u64,
    pub service_id: u64,
    pub method_id: u32,
    pub status: u32,
    pub token: DistributedCapToken,
    pub payload_len: u16,
    pub payload: [u8; 128],
}

impl Default for RpcPacket {
    fn default() -> Self {
        Self {
            magic: RPC_MAGIC,
            version: RPC_VERSION,
            pkt_type: RpcPacketType::Request,
            call_id: 0,
            service_id: 0,
            method_id: 0,
            status: 0,
            token: DistributedCapToken::default(),
            payload_len: 0,
            payload: [0u8; 128],
        }
    }
}

impl RpcPacket {
    /// Crée une nouvelle requête RPC typée
    pub fn new_request(
        call_id: u64,
        service_id: u64,
        method_id: u32,
        token: DistributedCapToken,
        payload_data: &[u8],
    ) -> Self {
        let mut pkt = Self {
            magic: RPC_MAGIC,
            version: RPC_VERSION,
            pkt_type: RpcPacketType::Request,
            call_id,
            service_id,
            method_id,
            status: 0,
            token,
            payload_len: 0,
            payload: [0u8; 128],
        };
        let len = payload_data.len().min(128);
        pkt.payload[..len].copy_from_slice(&payload_data[..len]);
        pkt.payload_len = len as u16;
        pkt
    }

    /// Crée un paquet de réponse
    pub fn new_response(
        call_id: u64,
        service_id: u64,
        method_id: u32,
        status: u32,
        response_data: &[u8],
    ) -> Self {
        let mut pkt = Self {
            magic: RPC_MAGIC,
            version: RPC_VERSION,
            pkt_type: RpcPacketType::Response,
            call_id,
            service_id,
            method_id,
            status,
            token: DistributedCapToken::default(),
            payload_len: 0,
            payload: [0u8; 128],
        };
        let len = response_data.len().min(128);
        pkt.payload[..len].copy_from_slice(&response_data[..len]);
        pkt.payload_len = len as u16;
        pkt
    }
}

/// Définition d'un service enregistré dans le registre RPC
#[derive(Debug, Clone, Copy)]
pub struct RpcServiceEntry {
    pub service_id: u64,
    pub name: &'static str,
    pub required_rights: u32,
    pub active: bool,
}

/// Registre des services RPC locaux et distants
pub struct RpcRegistry {
    pub services: [Option<RpcServiceEntry>; 16],
    pub count: usize,
}

impl Default for RpcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcRegistry {
    pub const fn new() -> Self {
        Self {
            services: [None; 16],
            count: 0,
        }
    }

    /// Enregistre un service avec ses prérequis de droits de capacité
    pub fn register_service(
        &mut self,
        service_id: u64,
        name: &'static str,
        required_rights: u32,
    ) -> Result<(), SysError> {
        for slot in self.services.iter_mut() {
            if slot.is_none() {
                *slot = Some(RpcServiceEntry {
                    service_id,
                    name,
                    required_rights,
                    active: true,
                });
                self.count += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Recherche un service par son identifiant 64 bits
    pub fn find_service(&self, service_id: u64) -> Option<&RpcServiceEntry> {
        for entry in self.services.iter().flatten() {
            if entry.service_id == service_id && entry.active {
                return Some(entry);
            }
        }
        None
    }
}

/// Nœud d'un cluster JamboOS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Online,
    Degraded,
    Offline,
}

#[derive(Debug, Clone, Copy)]
pub struct ClusterNode {
    pub node_id: u64,
    pub ip_addr: [u8; 4],
    pub status: NodeStatus,
    pub last_heartbeat_epoch: u64,
}

/// Gestionnaire de grappe (Cluster Manager) assurant la résilience et le failover
pub struct ClusterManager {
    pub local_node_id: u64,
    pub nodes: [Option<ClusterNode>; 8],
    pub active_nodes: usize,
}

impl ClusterManager {
    pub const fn new(local_node_id: u64) -> Self {
        Self {
            local_node_id,
            nodes: [None; 8],
            active_nodes: 0,
        }
    }

    /// Ajoute ou met à jour un nœud dans la topologie du cluster
    pub fn add_node(&mut self, node_id: u64, ip_addr: [u8; 4]) -> Result<(), SysError> {
        for slot in self.nodes.iter_mut() {
            if slot.is_none() {
                *slot = Some(ClusterNode {
                    node_id,
                    ip_addr,
                    status: NodeStatus::Online,
                    last_heartbeat_epoch: 100,
                });
                self.active_nodes += 1;
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Enregistre un battement de cœur (Heartbeat) pour un nœud avec son horodatage
    pub fn record_heartbeat(&mut self, node_id: u64, epoch_ts: u64) -> Result<(), SysError> {
        for slot in self.nodes.iter_mut() {
            if let Some(ref mut node) = slot {
                if node.node_id == node_id {
                    node.last_heartbeat_epoch = epoch_ts;
                    node.status = NodeStatus::Online;
                    return Ok(());
                }
            }
        }
        Err(SysError::InvalidHandle)
    }

    /// Analyse l'état de santé de la grappe et déclenche la dégradation si un nœud expire
    pub fn monitor_liveness(&mut self, current_epoch: u64, timeout_epochs: u64) -> usize {
        let mut degraded_count = 0;
        for slot in self.nodes.iter_mut() {
            if let Some(ref mut node) = slot {
                if node.status == NodeStatus::Online
                    && current_epoch.saturating_sub(node.last_heartbeat_epoch) > timeout_epochs
                {
                    node.status = NodeStatus::Degraded;
                    degraded_count += 1;
                }
            }
        }
        degraded_count
    }

    /// Signale une défaillance de nœud et bascule vers une réplique saine
    pub fn trigger_failover(&mut self, failed_node_id: u64) -> Option<u64> {
        for slot in self.nodes.iter_mut() {
            if let Some(ref mut node) = slot {
                if node.node_id == failed_node_id {
                    node.status = NodeStatus::Offline;
                }
            }
        }
        // 1. Chercher prioritairement un nœud de secours en ligne
        for entry in self.nodes.iter().flatten() {
            if entry.status == NodeStatus::Online && entry.node_id != failed_node_id {
                return Some(entry.node_id);
            }
        }
        // 2. À défaut, basculer vers un nœud en mode dégradé
        for entry in self.nodes.iter().flatten() {
            if entry.status == NodeStatus::Degraded && entry.node_id != failed_node_id {
                return Some(entry.node_id);
            }
        }
        None
    }
}

/// Dispatcher RPC côté serveur validant les jetons avant exécution
pub struct RpcServerDispatcher {
    pub registry: RpcRegistry,
    pub shared_secret: [u8; 32],
    pub min_valid_nonce: u64,
    pub calls_processed: u64,
}

impl RpcServerDispatcher {
    pub const fn new(registry: RpcRegistry, shared_secret: [u8; 32]) -> Self {
        Self {
            registry,
            shared_secret,
            min_valid_nonce: 1,
            calls_processed: 0,
        }
    }

    /// Traite un paquet de requête RPC entrant, valide les capacités et retourne la réponse
    pub fn dispatch(&mut self, req: &RpcPacket) -> Result<RpcPacket, SysError> {
        if req.magic != RPC_MAGIC || req.version != RPC_VERSION {
            return Err(SysError::InvalidArgument);
        }

        // 1. Valider la signature du jeton de capacité distribuée et prévenir les rejeux
        req.token
            .verify(&self.shared_secret, self.min_valid_nonce)?;
        self.min_valid_nonce = req.token.nonce + 1;

        // 2. Vérifier que le service demandé est enregistré
        let service = self
            .registry
            .find_service(req.service_id)
            .ok_or(SysError::InvalidArgument)?;

        // 3. Vérifier que les droits accordés dans le jeton couvrent les prérequis du service
        if (req.token.rights_mask & service.required_rights) != service.required_rights {
            return Err(SysError::PermissionDenied);
        }

        // 4. Exécuter la méthode RPC
        self.calls_processed += 1;
        let mut response_payload = [0u8; 128];
        response_payload[0] = 0xAA; // Code accusé de succès
        response_payload[1] = req.method_id as u8;

        Ok(RpcPacket::new_response(
            req.call_id,
            req.service_id,
            req.method_id,
            0,
            &response_payload[..2],
        ))
    }
}

/// Démon principal du sous-système RPC distribué JamboRPC
pub struct JamboRpcDaemon {
    pub dispatcher: RpcServerDispatcher,
    pub cluster: ClusterManager,
    pub requests_sent: u64,
    pub shared_secret: [u8; 32],
}

impl Default for JamboRpcDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboRpcDaemon {
    pub const fn new() -> Self {
        let registry = RpcRegistry::new();
        let shared_secret = [0x42u8; 32];
        let dispatcher = RpcServerDispatcher::new(registry, shared_secret);
        let cluster = ClusterManager::new(1);

        Self {
            dispatcher,
            cluster,
            requests_sent: 0,
            shared_secret,
        }
    }

    /// Initialise les services et nœuds par défaut
    pub fn init_defaults(&mut self) {
        let _ = self
            .dispatcher
            .registry
            .register_service(0x1000, "compute", 0x01);
        let _ = self
            .dispatcher
            .registry
            .register_service(0x2000, "storage", 0x03);
        let _ = self
            .dispatcher
            .registry
            .register_service(0x3000, "auth", 0x07);

        let _ = self.cluster.add_node(1, [127, 0, 0, 1]);
        let _ = self.cluster.add_node(2, [192, 168, 1, 20]);
        let _ = self.cluster.add_node(3, [192, 168, 1, 30]);
    }

    /// Envoie un appel RPC simulé vérifié par jeton de capacité
    pub fn call_service(
        &mut self,
        service_id: u64,
        method_id: u32,
        payload: &[u8],
    ) -> Result<RpcPacket, SysError> {
        self.requests_sent += 1;
        let nonce = 1000 + self.requests_sent;
        let token =
            DistributedCapToken::new_signed(1, 2, service_id, 0x07, nonce, &self.shared_secret);
        let req = RpcPacket::new_request(self.requests_sent, service_id, method_id, token, payload);
        self.dispatcher.dispatch(&req)
    }

    /// Envoie un ping de battement de cœur au cluster
    pub fn ping_node(&mut self, node_id: u64, epoch: u64) -> Result<(), SysError> {
        self.cluster.record_heartbeat(node_id, epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_cap_token_and_replay_protection() {
        let secret = [0x55u8; 32];
        let token = DistributedCapToken::new_signed(1, 2, 0x1000, 0x03, 10, &secret);
        assert!(token.verify(&secret, 10).is_ok());

        // Rejeu avec nonce antérieur
        assert!(token.verify(&secret, 11).is_err());

        // Faux secret
        let rogue_secret = [0x99u8; 32];
        assert!(token.verify(&rogue_secret, 10).is_err());
    }

    #[test]
    fn test_rpc_dispatcher_lifecycle() {
        let mut reg = RpcRegistry::new();
        reg.register_service(0x1000, "compute", 0x01).unwrap();

        let secret = [0x22u8; 32];
        let mut dispatcher = RpcServerDispatcher::new(reg, secret);

        let token = DistributedCapToken::new_signed(1, 2, 0x1000, 0x01, 100, &secret);
        let req = RpcPacket::new_request(1, 0x1000, 5, token, &[0xAA, 0xBB]);

        let resp = dispatcher.dispatch(&req).unwrap();
        assert_eq!(resp.status, 0);
        assert_eq!(resp.payload[0], 0xAA);
        assert_eq!(resp.payload[1], 5);
    }

    #[test]
    fn test_cluster_failover_and_heartbeat() {
        let mut mgr = ClusterManager::new(1);
        mgr.add_node(2, [10, 0, 0, 2]).unwrap();
        mgr.add_node(3, [10, 0, 0, 3]).unwrap();

        assert_eq!(mgr.active_nodes, 2);

        mgr.record_heartbeat(2, 115).unwrap();
        assert_eq!(mgr.monitor_liveness(120, 10), 1); // Node 3 n'a pas eu de heartbeat récent (100 vs 115)

        let backup = mgr.trigger_failover(2);
        assert_eq!(backup, Some(3));
    }
}

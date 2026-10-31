//! Maillage Réseau Chiffré Distribué et Routage Zero-Trust (`jambo-meshd`)
//!
//! Fournit une couche de réseau maillé superposé (Overlay Mesh VPN) point-à-point,
//! chiffrée de bout en bout et sans autorité ambiante pour la grappe JamboOS.
//! L'encapsulation, le routage et la gestion des pairs sont régis par `MeshCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_PEERS: usize = 16;
pub const MAX_ROUTES: usize = 32;
pub const MAX_PACKET_SIZE: usize = 128;
pub const KEY_SIZE: usize = 32;
pub const MAC_TAG_SIZE: usize = 16;

/// Droits de capacité pour le maillage réseau chiffré.
pub mod mesh_rights {
    pub const MESH_TUNNEL: u32 = 0x01;
    pub const MESH_PEER_ADD: u32 = 0x02;
    pub const MESH_ROUTE: u32 = 0x04;
    pub const MESH_KEY_ROT: u32 = 0x08;
    pub const MESH_ADMIN: u32 = 0x80;
    pub const ALL: u32 = MESH_TUNNEL | MESH_PEER_ADD | MESH_ROUTE | MESH_KEY_ROT | MESH_ADMIN;
}

/// Jeton de capacité pour le maillage réseau.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshCap {
    pub handle: Handle,
    pub rights: u32,
}

impl MeshCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }
}

/// Nœud pair au sein du maillage de superposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshPeer {
    pub peer_id: u32,
    pub public_key: [u8; KEY_SIZE],
    pub virtual_ip: [u8; 4],
    pub physical_endpoint: ([u8; 4], u16),
    pub session_key: [u8; KEY_SIZE],
    pub tx_sequence: u64,
    pub rx_sequence: u64,
    pub active: bool,
}

/// Route virtuelle au sein du maillage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshRoute {
    pub destination_subnet: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub next_hop_peer_id: u32,
}

impl MeshRoute {
    pub fn matches(&self, ip: [u8; 4]) -> bool {
        for i in 0..4 {
            if (ip[i] & self.subnet_mask[i]) != (self.destination_subnet[i] & self.subnet_mask[i]) {
                return false;
            }
        }
        true
    }
}

/// Paquet réseau encapsulé et authentifié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshPacket {
    pub sender_peer_id: u32,
    pub dest_peer_id: u32,
    pub seq_id: u64,
    pub encrypted_data: [u8; MAX_PACKET_SIZE],
    pub data_len: usize,
    pub mac_tag: [u8; MAC_TAG_SIZE],
}

impl MeshPacket {
    pub fn data_bytes(&self) -> &[u8] {
        &self.encrypted_data[..self.data_len]
    }
}

/// Démon de maillage réseau sécurisé.
pub struct MeshNetwork {
    pub local_peer_id: u32,
    pub local_virtual_ip: [u8; 4],
    pub peers: [Option<MeshPeer>; MAX_PEERS],
    pub routes: [Option<MeshRoute>; MAX_ROUTES],
    pub packets_tunneled: u64,
}

impl MeshNetwork {
    pub const fn new(local_peer_id: u32, local_virtual_ip: [u8; 4]) -> Self {
        Self {
            local_peer_id,
            local_virtual_ip,
            peers: [None; MAX_PEERS],
            routes: [None; MAX_ROUTES],
            packets_tunneled: 0,
        }
    }

    /// Enrôle un nœud pair dans le maillage avec sa clé de session initiale.
    pub fn add_peer(
        &mut self,
        cap: &MeshCap,
        peer_id: u32,
        public_key: &[u8; KEY_SIZE],
        virtual_ip: [u8; 4],
        physical_endpoint: ([u8; 4], u16),
        initial_session_key: &[u8; KEY_SIZE],
    ) -> Result<(), SysError> {
        if !cap.has_right(mesh_rights::MESH_PEER_ADD) {
            return Err(SysError::PermissionDenied);
        }

        let slot = self
            .peers
            .iter_mut()
            .find(|p| p.is_none())
            .ok_or(SysError::OutOfMemory)?;

        *slot = Some(MeshPeer {
            peer_id,
            public_key: *public_key,
            virtual_ip,
            physical_endpoint,
            session_key: *initial_session_key,
            tx_sequence: 1,
            rx_sequence: 0,
            active: true,
        });

        Ok(())
    }

    /// Ajoute une route vers un sous-réseau virtuel de superposition.
    pub fn add_route(
        &mut self,
        cap: &MeshCap,
        subnet: [u8; 4],
        mask: [u8; 4],
        next_hop_peer_id: u32,
    ) -> Result<(), SysError> {
        if !cap.has_right(mesh_rights::MESH_ROUTE) {
            return Err(SysError::PermissionDenied);
        }

        let slot = self
            .routes
            .iter_mut()
            .find(|r| r.is_none())
            .ok_or(SysError::OutOfMemory)?;

        *slot = Some(MeshRoute {
            destination_subnet: subnet,
            subnet_mask: mask,
            next_hop_peer_id,
        });

        Ok(())
    }

    /// Encapsule, chiffre et signe un paquet réseau à destination d'une IP virtuelle.
    pub fn encapsulate_and_encrypt(
        &mut self,
        cap: &MeshCap,
        dest_virtual_ip: [u8; 4],
        plaintext: &[u8],
    ) -> Result<MeshPacket, SysError> {
        if !cap.has_right(mesh_rights::MESH_TUNNEL) {
            return Err(SysError::PermissionDenied);
        }

        if plaintext.len() > MAX_PACKET_SIZE {
            return Err(SysError::BufferTooSmall);
        }

        // Trouver le pair correspondant à l'IP de destination ou via une route
        let dest_peer_id = if let Some(peer) = self
            .peers
            .iter()
            .flatten()
            .find(|p| p.virtual_ip == dest_virtual_ip)
        {
            peer.peer_id
        } else if let Some(route) = self
            .routes
            .iter()
            .flatten()
            .find(|r| r.matches(dest_virtual_ip))
        {
            route.next_hop_peer_id
        } else {
            return Err(SysError::InvalidArgument);
        };

        let peer = self
            .peers
            .iter_mut()
            .find_map(|p| p.as_mut().filter(|peer| peer.peer_id == dest_peer_id))
            .ok_or(SysError::InvalidArgument)?;

        let seq = peer.tx_sequence;
        peer.tx_sequence += 1;

        let mut encrypted_data = [0u8; MAX_PACKET_SIZE];
        let len = plaintext.len();

        // Chiffrement de flux déterministe combiné à la clé de session et au seq_id
        for i in 0..len {
            let key_byte = peer.session_key[i % KEY_SIZE];
            let stream_byte = key_byte ^ ((seq >> ((i % 8) * 8)) as u8);
            encrypted_data[i] = plaintext[i] ^ stream_byte;
        }

        // Calcul du tag MAC d'intégrité (16 octets)
        let mut mac_tag = [0u8; MAC_TAG_SIZE];
        for i in 0..MAC_TAG_SIZE {
            let mut acc = peer.session_key[i] ^ ((seq >> ((i % 8) * 8)) as u8);
            for j in 0..len {
                acc = acc.wrapping_add(encrypted_data[j] ^ (j as u8));
            }
            mac_tag[i] = acc;
        }

        self.packets_tunneled += 1;

        Ok(MeshPacket {
            sender_peer_id: self.local_peer_id,
            dest_peer_id,
            seq_id: seq,
            encrypted_data,
            data_len: len,
            mac_tag,
        })
    }

    /// Vérifie, déchiffre et désencapsule un paquet reçu du maillage.
    pub fn decrypt_and_decapsulate(
        &mut self,
        cap: &MeshCap,
        packet: &MeshPacket,
        output_buf: &mut [u8],
    ) -> Result<usize, SysError> {
        if !cap.has_right(mesh_rights::MESH_TUNNEL) {
            return Err(SysError::PermissionDenied);
        }

        if output_buf.len() < packet.data_len {
            return Err(SysError::BufferTooSmall);
        }

        let peer = self
            .peers
            .iter_mut()
            .find_map(|p| {
                p.as_mut()
                    .filter(|peer| peer.peer_id == packet.sender_peer_id)
            })
            .ok_or(SysError::InvalidArgument)?;

        // Protection Anti-Rejeu : le numéro de séquence doit être strictement croissant
        if packet.seq_id <= peer.rx_sequence {
            return Err(SysError::InvalidArgument);
        }

        // Vérification de l'intégrité du tag MAC
        for i in 0..MAC_TAG_SIZE {
            let mut acc = peer.session_key[i] ^ ((packet.seq_id >> ((i % 8) * 8)) as u8);
            for j in 0..packet.data_len {
                acc = acc.wrapping_add(packet.encrypted_data[j] ^ (j as u8));
            }
            if mac_tag_compare(packet.mac_tag[i], acc) != 0 {
                return Err(SysError::InvalidArgument);
            }
        }

        // Déchiffrement
        for i in 0..packet.data_len {
            let key_byte = peer.session_key[i % KEY_SIZE];
            let stream_byte = key_byte ^ ((packet.seq_id >> ((i % 8) * 8)) as u8);
            output_buf[i] = packet.encrypted_data[i] ^ stream_byte;
        }

        peer.rx_sequence = packet.seq_id;
        Ok(packet.data_len)
    }

    /// Déclenche la rotation de la clé de session symétrique d'un pair.
    pub fn rotate_session_key(
        &mut self,
        cap: &MeshCap,
        peer_id: u32,
        new_key: &[u8; KEY_SIZE],
    ) -> Result<(), SysError> {
        if !cap.has_right(mesh_rights::MESH_KEY_ROT) {
            return Err(SysError::PermissionDenied);
        }

        let peer = self
            .peers
            .iter_mut()
            .find_map(|p| p.as_mut().filter(|peer| peer.peer_id == peer_id))
            .ok_or(SysError::InvalidArgument)?;

        peer.session_key = *new_key;
        peer.tx_sequence = 1;
        peer.rx_sequence = 0;
        Ok(())
    }
}

/// Démon orchestrateur de maillage réseau chiffré et routage Zero-Trust (`jambo-meshd`).
pub struct JamboMeshDaemon {
    pub net: MeshNetwork,
    pub cap: MeshCap,
}

impl Default for JamboMeshDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboMeshDaemon {
    pub fn new() -> Self {
        let cap = MeshCap::new(Handle::new(6301, 1), mesh_rights::ALL);
        let mut net = MeshNetwork::new(1, [10, 42, 0, 1]);
        let default_key = [0x5Au8; KEY_SIZE];
        let _ = net.add_peer(
            &cap,
            2,
            &[0x02u8; KEY_SIZE],
            [10, 42, 0, 2],
            ([192, 168, 1, 102], 51820),
            &default_key,
        );
        let _ = net.add_route(&cap, [10, 42, 0, 0], [255, 255, 0, 0], 2);
        Self { net, cap }
    }

    pub fn add_peer(
        &mut self,
        peer_id: u32,
        pub_key: &[u8; KEY_SIZE],
        vip: [u8; 4],
        endpoint: ([u8; 4], u16),
        session_key: &[u8; KEY_SIZE],
    ) -> Result<(), SysError> {
        self.net
            .add_peer(&self.cap, peer_id, pub_key, vip, endpoint, session_key)
    }

    pub fn send_packet(
        &mut self,
        dest_vip: [u8; 4],
        payload: &[u8],
    ) -> Result<MeshPacket, SysError> {
        self.net
            .encapsulate_and_encrypt(&self.cap, dest_vip, payload)
    }

    pub fn receive_packet(
        &mut self,
        packet: &MeshPacket,
        out_buf: &mut [u8],
    ) -> Result<usize, SysError> {
        self.net.decrypt_and_decapsulate(&self.cap, packet, out_buf)
    }

    pub fn active_peers_count(&self) -> usize {
        self.net
            .peers
            .iter()
            .filter(|p| match p {
                Some(peer) => peer.active,
                None => false,
            })
            .count()
    }

    pub fn routes_count(&self) -> usize {
        self.net.routes.iter().filter(|r| r.is_some()).count()
    }

    pub fn packets_tunneled(&self) -> u64 {
        self.net.packets_tunneled
    }
}

#[inline(never)]
fn mac_tag_compare(a: u8, b: u8) -> u8 {
    a ^ b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_permissions() {
        let mut net = MeshNetwork::new(1, [10, 42, 0, 1]);
        let unauth_cap = MeshCap::new(Handle::new(1, 1), 0);
        let peer_cap = MeshCap::new(Handle::new(2, 1), mesh_rights::MESH_PEER_ADD);

        let pub_key = [0xAA; 32];
        let session_key = [0x55; 32];

        // Rejet d'ajout de pair sans MESH_PEER_ADD
        assert_eq!(
            net.add_peer(
                &unauth_cap,
                2,
                &pub_key,
                [10, 42, 0, 2],
                ([192, 168, 1, 102], 51820),
                &session_key
            ),
            Err(SysError::PermissionDenied)
        );

        // Succès avec MESH_PEER_ADD
        assert!(net
            .add_peer(
                &peer_cap,
                2,
                &pub_key,
                [10, 42, 0, 2],
                ([192, 168, 1, 102], 51820),
                &session_key
            )
            .is_ok());
    }

    #[test]
    fn test_encryption_decryption_tunnel() {
        let mut node1 = MeshNetwork::new(1, [10, 42, 0, 1]);
        let mut node2 = MeshNetwork::new(2, [10, 42, 0, 2]);

        let all_cap = MeshCap::new(Handle::new(1, 1), mesh_rights::ALL);
        let session_key = [0x42; 32];

        node1
            .add_peer(
                &all_cap,
                2,
                &[0x02; 32],
                [10, 42, 0, 2],
                ([192, 168, 1, 20], 51820),
                &session_key,
            )
            .unwrap();
        node2
            .add_peer(
                &all_cap,
                1,
                &[0x01; 32],
                [10, 42, 0, 1],
                ([192, 168, 1, 10], 51820),
                &session_key,
            )
            .unwrap();

        let payload = b"JAMBO_MESH_ENCRYPTED_RPC_PAYLOAD";
        let packet = node1
            .encapsulate_and_encrypt(&all_cap, [10, 42, 0, 2], payload)
            .unwrap();

        // Le texte chiffré ne doit pas être identique au clair
        assert_ne!(packet.data_bytes(), payload);

        // Déchiffrement sur le nœud 2
        let mut decrypted_buf = [0u8; 64];
        let len = node2
            .decrypt_and_decapsulate(&all_cap, &packet, &mut decrypted_buf)
            .unwrap();

        assert_eq!(&decrypted_buf[..len], payload);

        // Test Anti-Rejeu : rejouer le même paquet doit échouer
        let replay_res = node2.decrypt_and_decapsulate(&all_cap, &packet, &mut decrypted_buf);
        assert_eq!(replay_res, Err(SysError::InvalidArgument));
    }

    #[test]
    fn test_key_rotation() {
        let mut node = MeshNetwork::new(1, [10, 42, 0, 1]);
        let all_cap = MeshCap::new(Handle::new(1, 1), mesh_rights::ALL);
        let key1 = [0x11; 32];
        let key2 = [0x22; 32];

        node.add_peer(
            &all_cap,
            2,
            &[0x02; 32],
            [10, 42, 0, 2],
            ([192, 168, 1, 20], 51820),
            &key1,
        )
        .unwrap();

        // Rotation de clé
        node.rotate_session_key(&all_cap, 2, &key2).unwrap();
        let peer = node.peers[0].unwrap();
        assert_eq!(peer.session_key, key2);
        assert_eq!(peer.tx_sequence, 1);
        assert_eq!(peer.rx_sequence, 0);
    }

    #[test]
    fn test_daemon_tunnel() {
        let mut daemon = JamboMeshDaemon::new();
        assert_eq!(daemon.active_peers_count(), 1);
        assert_eq!(daemon.routes_count(), 1);

        let packet = daemon
            .send_packet([10, 42, 0, 2], b"DAEMON_TUNNELED_PING")
            .unwrap();
        assert_eq!(daemon.packets_tunneled(), 1);
        assert_eq!(packet.dest_peer_id, 2);
        assert_eq!(packet.sender_peer_id, 1);
        assert_eq!(packet.data_len, 20);
    }
}

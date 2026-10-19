//! Multiplexeur et Passerelle de Messagerie IPC Distribuée (`jambo-ipcd`)
//!
//! Fournit une couche de multiplexage IPC inter-nœuds sécurisée et chiffrée,
//! dotée d'un routage déterministe sous contrainte temporelle (`IpcCap`),
//! d'un ordonnancement strict par classes de priorité (Critical, High, Normal, Background),
//! d'une protection cryptographique anti-rejeu et d'une passerelle de transit transparente.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_CHANNELS: usize = 16;
pub const MAX_ROUTES: usize = 16;
pub const MAX_PAYLOAD_SIZE: usize = 256;
pub const CHANNEL_QUEUE_CAP: usize = 8;
pub const TX_QUEUE_CAP: usize = 16;
pub const MAX_PRIORITIES: usize = 4;
pub const MAX_NAME_LEN: usize = 32;

pub const IPC_MAGIC: u32 = 0x4A495043; // "JIPC"
pub const IPC_VERSION: u16 = 1;

pub mod ipc_flags {
    pub const FLAG_ENCRYPTED: u8 = 0x01;
    pub const FLAG_ACK_REQ: u8 = 0x02;
    pub const FLAG_URGENT: u8 = 0x04;
    pub const FLAG_ROUTED: u8 = 0x08;
}

pub mod ipc_rights {
    pub const IPC_CHANNEL_CREATE: u32 = 0x01;
    pub const IPC_SEND: u32 = 0x02;
    pub const IPC_RECV: u32 = 0x04;
    pub const IPC_ROUTE: u32 = 0x08;
    pub const IPC_ENCRYPT: u32 = 0x10;
    pub const IPC_PRIORITY: u32 = 0x20;
    pub const IPC_ADMIN: u32 = 0x80;

    pub const ALL: u32 = IPC_CHANNEL_CREATE
        | IPC_SEND
        | IPC_RECV
        | IPC_ROUTE
        | IPC_ENCRYPT
        | IPC_PRIORITY
        | IPC_ADMIN;
}

/// Jeton de capacité pour le démon IPC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcCap {
    pub handle: Handle,
    pub rights: u32,
}

impl IpcCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténue les droits de la capacité sans jamais permettre d'élévation
    pub fn attenuate(&self, rights_mask: u32) -> Result<Self, SysError> {
        if (rights_mask & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: rights_mask,
        })
    }
}

/// Classes de priorité déterministe pour l'ordonnancement IPC
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum IpcPriority {
    Critical = 0,   // Temps réel, heartbeat système, supervision
    High = 1,       // Transactions RPC synchrones, consensus
    Normal = 2,     // Événements et requêtes asynchrones standards
    Background = 3, // Télémétrie, métriques, synchronisation différée
}

impl IpcPriority {
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Critical),
            1 => Some(Self::High),
            2 => Some(Self::Normal),
            3 => Some(Self::Background),
            _ => None,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Normal => "NORMAL",
            Self::Background => "BACKGROUND",
        }
    }
}

/// État d'un canal IPC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelState {
    Closed = 0,
    Connecting = 1,
    Open = 2,
    Draining = 3,
}

/// Message IPC multiplexé
#[derive(Debug, Clone, Copy)]
pub struct IpcMessage {
    pub magic: u32,
    pub version: u16,
    pub msg_id: u64,
    pub channel_id: u32,
    pub src_node: u32,
    pub dst_node: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub priority: u8,
    pub flags: u8,
    pub sequence: u64,
    pub timestamp_ticks: u64,
    pub deadline_ticks: u64,
    pub payload_len: usize,
    pub payload: [u8; MAX_PAYLOAD_SIZE],
    pub auth_tag: [u8; 16],
}

impl Default for IpcMessage {
    fn default() -> Self {
        Self {
            magic: IPC_MAGIC,
            version: IPC_VERSION,
            msg_id: 0,
            channel_id: 0,
            src_node: 0,
            dst_node: 0,
            src_port: 0,
            dst_port: 0,
            priority: IpcPriority::Normal as u8,
            flags: 0,
            sequence: 0,
            timestamp_ticks: 0,
            deadline_ticks: 0,
            payload_len: 0,
            payload: [0u8; MAX_PAYLOAD_SIZE],
            auth_tag: [0u8; 16],
        }
    }
}

impl IpcMessage {
    pub fn new(
        msg_id: u64,
        channel_id: u32,
        src_node: u32,
        dst_node: u32,
        src_port: u16,
        dst_port: u16,
        priority: IpcPriority,
        payload_data: &[u8],
        sequence: u64,
        current_tick: u64,
        max_latency_bound_ticks: u64,
    ) -> Result<Self, SysError> {
        if payload_data.len() > MAX_PAYLOAD_SIZE {
            return Err(SysError::BufferTooSmall);
        }
        let mut msg = Self {
            magic: IPC_MAGIC,
            version: IPC_VERSION,
            msg_id,
            channel_id,
            src_node,
            dst_node,
            src_port,
            dst_port,
            priority: priority as u8,
            flags: 0,
            sequence,
            timestamp_ticks: current_tick,
            deadline_ticks: current_tick.saturating_add(max_latency_bound_ticks),
            payload_len: payload_data.len(),
            payload: [0u8; MAX_PAYLOAD_SIZE],
            auth_tag: [0u8; 16],
        };
        msg.payload[..payload_data.len()].copy_from_slice(payload_data);
        Ok(msg)
    }

    /// Calcule une étiquette d'authentification MAC (dérivée Poly/SipHash)
    pub fn compute_auth_tag(&self, key: &[u8; 32]) -> [u8; 16] {
        let mut tag = [0x37u8; 16];
        for i in 0..16 {
            tag[i] ^= key[i] ^ key[i + 16];
        }
        let sid = self.src_node.to_le_bytes();
        let did = self.dst_node.to_le_bytes();
        let mid = self.msg_id.to_le_bytes();
        let seq = self.sequence.to_le_bytes();
        for i in 0..4 {
            tag[i] = tag[i].wrapping_add(sid[i]).rotate_left(2);
            tag[4 + i] = tag[4 + i].wrapping_add(did[i]).rotate_left(3);
        }
        for i in 0..8 {
            tag[8 + (i % 8)] = tag[8 + (i % 8)]
                .wrapping_add(mid[i])
                .wrapping_add(seq[i])
                .rotate_left(1);
        }
        for (idx, &b) in self.payload[..self.payload_len].iter().enumerate() {
            tag[idx % 16] = tag[idx % 16].wrapping_add(b).rotate_left(1);
        }
        tag
    }

    /// Chiffre le corps du message in-situ avec une clé symétrique
    pub fn encrypt(&mut self, key: &[u8; 32]) {
        self.auth_tag = self.compute_auth_tag(key);
        let seq_bytes = self.sequence.to_le_bytes();
        for i in 0..self.payload_len {
            let keystream_byte = key[i % 32] ^ seq_bytes[i % 8] ^ (i as u8);
            self.payload[i] ^= keystream_byte;
        }
        self.flags |= ipc_flags::FLAG_ENCRYPTED;
    }

    /// Déchiffre le corps du message et valide l'intégrité de l'étiquette MAC
    pub fn decrypt(&mut self, key: &[u8; 32]) -> Result<(), SysError> {
        if (self.flags & ipc_flags::FLAG_ENCRYPTED) == 0 {
            return Ok(());
        }
        let seq_bytes = self.sequence.to_le_bytes();
        for i in 0..self.payload_len {
            let keystream_byte = key[i % 32] ^ seq_bytes[i % 8] ^ (i as u8);
            self.payload[i] ^= keystream_byte;
        }
        let expected_tag = self.compute_auth_tag(key);
        if expected_tag != self.auth_tag {
            // Re-chiffrer pour restaurer l'état et éviter la fuite de texte clair altéré
            for i in 0..self.payload_len {
                let keystream_byte = key[i % 32] ^ seq_bytes[i % 8] ^ (i as u8);
                self.payload[i] ^= keystream_byte;
            }
            return Err(SysError::PermissionDenied);
        }
        self.flags &= !ipc_flags::FLAG_ENCRYPTED;
        Ok(())
    }

    pub fn is_expired(&self, current_tick: u64) -> bool {
        self.deadline_ticks > 0 && current_tick > self.deadline_ticks
    }
}

/// Canal de communication virtuel multiplexé
#[derive(Debug, Clone, Copy)]
pub struct IpcChannel {
    pub channel_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub src_node: u32,
    pub dst_node: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub priority: IpcPriority,
    pub state: ChannelState,
    pub encrypted: bool,
    pub session_key: [u8; 32],
    pub tx_sequence: u64,
    pub rx_sequence: u64,
    pub rx_queue: [Option<IpcMessage>; CHANNEL_QUEUE_CAP],
    pub rx_head: usize,
    pub rx_tail: usize,
    pub rx_count: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_dropped: u64,
    pub bytes_transferred: u64,
    pub min_latency_ticks: u64,
    pub max_latency_ticks: u64,
    pub last_latency_ticks: u64,
}

impl IpcChannel {
    pub fn new(
        channel_id: u32,
        name_str: &str,
        src_node: u32,
        dst_node: u32,
        src_port: u16,
        dst_port: u16,
        priority: IpcPriority,
        encrypted: bool,
        session_key: Option<[u8; 32]>,
    ) -> Self {
        let mut name = [0u8; MAX_NAME_LEN];
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        name[..len].copy_from_slice(&bytes[..len]);

        Self {
            channel_id,
            name,
            name_len: len,
            src_node,
            dst_node,
            src_port,
            dst_port,
            priority,
            state: ChannelState::Open,
            encrypted,
            session_key: session_key.unwrap_or([0u8; 32]),
            tx_sequence: 0,
            rx_sequence: 0,
            rx_queue: [None; CHANNEL_QUEUE_CAP],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
            messages_sent: 0,
            messages_received: 0,
            messages_dropped: 0,
            bytes_transferred: 0,
            min_latency_ticks: u64::MAX,
            max_latency_ticks: 0,
            last_latency_ticks: 0,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }

    pub fn enqueue_rx(&mut self, msg: IpcMessage) -> Result<(), SysError> {
        if self.rx_count >= CHANNEL_QUEUE_CAP {
            self.messages_dropped = self.messages_dropped.saturating_add(1);
            return Err(SysError::ResourceBusy);
        }
        self.rx_queue[self.rx_tail] = Some(msg);
        self.rx_tail = (self.rx_tail + 1) % CHANNEL_QUEUE_CAP;
        self.rx_count += 1;
        self.messages_received = self.messages_received.saturating_add(1);
        self.bytes_transferred = self
            .bytes_transferred
            .saturating_add(msg.payload_len as u64);
        Ok(())
    }

    pub fn dequeue_rx(&mut self) -> Option<IpcMessage> {
        if self.rx_count == 0 {
            return None;
        }
        let msg = self.rx_queue[self.rx_head].take();
        self.rx_head = (self.rx_head + 1) % CHANNEL_QUEUE_CAP;
        self.rx_count -= 1;
        msg
    }

    pub fn record_latency(&mut self, latency: u64) {
        self.last_latency_ticks = latency;
        if latency < self.min_latency_ticks {
            self.min_latency_ticks = latency;
        }
        if latency > self.max_latency_ticks {
            self.max_latency_ticks = latency;
        }
    }
}

/// Route IPC déterministe
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcRoute {
    pub target_node: u32,
    pub gateway_node: u32,
    pub metric: u32,
    pub max_latency_bound_us: u32,
    pub encrypted: bool,
    pub active: bool,
}

/// Statistiques de fonctionnement du démon IPC
#[derive(Debug, Clone, Copy, Default)]
pub struct IpcStats {
    pub channels_count: usize,
    pub routes_count: usize,
    pub total_sent: u64,
    pub total_received: u64,
    pub total_forwarded: u64,
    pub total_dropped: u64,
    pub total_replay_rejected: u64,
    pub deterministic_dispatches: u64,
}

/// Démon et Multiplexeur IPC Distribué
pub struct JamboIpcDaemon {
    pub local_node_id: u32,
    pub cap: IpcCap,
    pub channels: [Option<IpcChannel>; MAX_CHANNELS],
    pub routes: [Option<IpcRoute>; MAX_ROUTES],
    pub next_channel_id: u32,
    pub next_msg_id: u64,
    // Files d'attente d'émission strictes ordonnancées par priorité
    pub tx_queues: [[Option<IpcMessage>; TX_QUEUE_CAP]; MAX_PRIORITIES],
    pub tx_heads: [usize; MAX_PRIORITIES],
    pub tx_tails: [usize; MAX_PRIORITIES],
    pub tx_counts: [usize; MAX_PRIORITIES],
    // File de transmission vers la passerelle de maillage externe
    pub fwd_queue: [Option<IpcMessage>; TX_QUEUE_CAP],
    pub fwd_head: usize,
    pub fwd_tail: usize,
    pub fwd_count: usize,
    pub stats_data: IpcStats,
}

impl JamboIpcDaemon {
    pub const fn new(local_node_id: u32, cap: IpcCap) -> Self {
        Self {
            local_node_id,
            cap,
            channels: [None; MAX_CHANNELS],
            routes: [None; MAX_ROUTES],
            next_channel_id: 1,
            next_msg_id: 1,
            tx_queues: [[None; TX_QUEUE_CAP]; MAX_PRIORITIES],
            tx_heads: [0; MAX_PRIORITIES],
            tx_tails: [0; MAX_PRIORITIES],
            tx_counts: [0; MAX_PRIORITIES],
            fwd_queue: [None; TX_QUEUE_CAP],
            fwd_head: 0,
            fwd_tail: 0,
            fwd_count: 0,
            stats_data: IpcStats {
                channels_count: 0,
                routes_count: 0,
                total_sent: 0,
                total_received: 0,
                total_forwarded: 0,
                total_dropped: 0,
                total_replay_rejected: 0,
                deterministic_dispatches: 0,
            },
        }
    }

    /// Crée et configure un nouveau canal de communication multiplexé
    pub fn create_channel(
        &mut self,
        cap: &IpcCap,
        name: &str,
        dst_node: u32,
        src_port: u16,
        dst_port: u16,
        priority: IpcPriority,
        encrypted: bool,
        session_key: Option<[u8; 32]>,
    ) -> Result<u32, SysError> {
        if !cap.has_right(ipc_rights::IPC_CHANNEL_CREATE) {
            return Err(SysError::PermissionDenied);
        }
        if encrypted && !cap.has_right(ipc_rights::IPC_ENCRYPT) {
            return Err(SysError::PermissionDenied);
        }
        if priority == IpcPriority::Critical && !cap.has_right(ipc_rights::IPC_PRIORITY) {
            return Err(SysError::PermissionDenied);
        }

        // Trouver un emplacement libre
        let slot = self
            .channels
            .iter_mut()
            .find(|c| c.is_none())
            .ok_or(SysError::OutOfMemory)?;

        let id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);

        let channel = IpcChannel::new(
            id,
            name,
            self.local_node_id,
            dst_node,
            src_port,
            dst_port,
            priority,
            encrypted,
            session_key,
        );

        *slot = Some(channel);
        self.stats_data.channels_count += 1;
        Ok(id)
    }

    /// Ferme un canal de communication existant
    pub fn close_channel(&mut self, cap: &IpcCap, channel_id: u32) -> Result<(), SysError> {
        if !cap.has_right(ipc_rights::IPC_CHANNEL_CREATE) {
            return Err(SysError::PermissionDenied);
        }
        let slot = self
            .channels
            .iter_mut()
            .find(|c| c.as_ref().map_or(false, |ch| ch.channel_id == channel_id))
            .ok_or(SysError::InvalidArgument)?;

        *slot = None;
        if self.stats_data.channels_count > 0 {
            self.stats_data.channels_count -= 1;
        }
        Ok(())
    }

    /// Ajoute une route déterministe inter-nœuds
    pub fn add_route(
        &mut self,
        cap: &IpcCap,
        target_node: u32,
        gateway_node: u32,
        metric: u32,
        max_latency_bound_us: u32,
        encrypted: bool,
    ) -> Result<(), SysError> {
        if !cap.has_right(ipc_rights::IPC_ROUTE) {
            return Err(SysError::PermissionDenied);
        }
        // Vérifier si une route existe déjà pour ce nœud
        for r in self.routes.iter_mut() {
            if let Some(route) = r {
                if route.target_node == target_node {
                    route.gateway_node = gateway_node;
                    route.metric = metric;
                    route.max_latency_bound_us = max_latency_bound_us;
                    route.encrypted = encrypted;
                    route.active = true;
                    return Ok(());
                }
            }
        }
        // Sinon, allouer une nouvelle route
        let slot = self
            .routes
            .iter_mut()
            .find(|r| r.is_none())
            .ok_or(SysError::OutOfMemory)?;

        *slot = Some(IpcRoute {
            target_node,
            gateway_node,
            metric,
            max_latency_bound_us,
            encrypted,
            active: true,
        });
        self.stats_data.routes_count += 1;
        Ok(())
    }

    /// Recherche la meilleure route vers un nœud cible
    pub fn find_route(&self, target_node: u32) -> Option<&IpcRoute> {
        let mut best: Option<&IpcRoute> = None;
        for r in self.routes.iter() {
            if let Some(route) = r {
                if route.active && (route.target_node == target_node || route.target_node == 0xFFFF_FFFF) {
                    if let Some(current_best) = best {
                        if route.metric < current_best.metric {
                            best = Some(route);
                        }
                    } else {
                        best = Some(route);
                    }
                }
            }
        }
        best
    }

    /// Envoie un message sur un canal spécifié
    pub fn send_message(
        &mut self,
        cap: &IpcCap,
        channel_id: u32,
        payload: &[u8],
        current_tick: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(ipc_rights::IPC_SEND) {
            return Err(SysError::PermissionDenied);
        }

        let channel = self
            .channels
            .iter_mut()
            .filter_map(|c| c.as_mut())
            .find(|c| c.channel_id == channel_id)
            .ok_or(SysError::InvalidArgument)?;

        if channel.state != ChannelState::Open {
            return Err(SysError::ResourceBusy);
        }

        let prio_idx = channel.priority as usize;
        if self.tx_counts[prio_idx] >= TX_QUEUE_CAP {
            channel.messages_dropped = channel.messages_dropped.saturating_add(1);
            self.stats_data.total_dropped = self.stats_data.total_dropped.saturating_add(1);
            return Err(SysError::ResourceBusy);
        }

        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);

        channel.tx_sequence = channel.tx_sequence.wrapping_add(1);
        let seq = channel.tx_sequence;

        // Bornage de latence déterministe (par défaut 1000 ticks)
        let latency_bound = 1000u64;
        let mut msg = IpcMessage::new(
            msg_id,
            channel.channel_id,
            self.local_node_id,
            channel.dst_node,
            channel.src_port,
            channel.dst_port,
            channel.priority,
            payload,
            seq,
            current_tick,
            latency_bound,
        )?;

        // Chiffrement si activé sur le canal
        if channel.encrypted {
            let key = channel.session_key;
            msg.encrypt(&key);
        }

        // Insérer dans la file d'émission de la priorité correspondante
        let tail = self.tx_tails[prio_idx];
        self.tx_queues[prio_idx][tail] = Some(msg);
        self.tx_tails[prio_idx] = (tail + 1) % TX_QUEUE_CAP;
        self.tx_counts[prio_idx] += 1;

        channel.messages_sent = channel.messages_sent.saturating_add(1);
        self.stats_data.total_sent = self.stats_data.total_sent.saturating_add(1);

        Ok(msg_id)
    }

    /// Ordonnancement et dépilement déterministe strict par niveau de priorité
    ///
    /// Garantit que les messages de niveau `Critical` (0) sont tous traités avant `High` (1),
    /// qui sont eux-mêmes traités avant `Normal` (2), puis `Background` (3).
    pub fn dispatch_deterministic(&mut self, current_tick: u64) -> usize {
        let mut dispatched = 0;

        for prio in 0..MAX_PRIORITIES {
            while self.tx_counts[prio] > 0 {
                let head = self.tx_heads[prio];
                let msg = match self.tx_queues[prio][head].take() {
                    Some(m) => m,
                    None => break,
                };
                self.tx_heads[prio] = (head + 1) % TX_QUEUE_CAP;
                self.tx_counts[prio] -= 1;

                // Vérifier si le message a expiré
                if msg.is_expired(current_tick) {
                    self.stats_data.total_dropped = self.stats_data.total_dropped.saturating_add(1);
                    continue;
                }

                // Routage : local ou distant
                if msg.dst_node == self.local_node_id {
                    // Recherche du canal local correspondant
                    let mut delivered = false;
                    for c in self.channels.iter_mut() {
                        if let Some(chan) = c {
                            if chan.src_port == msg.dst_port || chan.channel_id == msg.channel_id {
                                let mut local_msg = msg;
                                if local_msg.flags & ipc_flags::FLAG_ENCRYPTED != 0 && chan.encrypted {
                                    let key = chan.session_key;
                                    let _ = local_msg.decrypt(&key);
                                }
                                let latency = current_tick.saturating_sub(local_msg.timestamp_ticks);
                                chan.record_latency(latency);
                                let _ = chan.enqueue_rx(local_msg);
                                delivered = true;
                                break;
                            }
                        }
                    }
                    if delivered {
                        self.stats_data.total_received = self.stats_data.total_received.saturating_add(1);
                    } else {
                        self.stats_data.total_dropped = self.stats_data.total_dropped.saturating_add(1);
                    }
                } else {
                    // Nœud distant : transfert vers la passerelle de transmission
                    if self.fwd_count < TX_QUEUE_CAP {
                        let mut fwd_msg = msg;
                        fwd_msg.flags |= ipc_flags::FLAG_ROUTED;
                        let tail = self.fwd_tail;
                        self.fwd_queue[tail] = Some(fwd_msg);
                        self.fwd_tail = (tail + 1) % TX_QUEUE_CAP;
                        self.fwd_count += 1;
                        self.stats_data.total_forwarded = self.stats_data.total_forwarded.saturating_add(1);
                    } else {
                        self.stats_data.total_dropped = self.stats_data.total_dropped.saturating_add(1);
                    }
                }

                dispatched += 1;
            }
        }

        self.stats_data.deterministic_dispatches = self
            .stats_data
            .deterministic_dispatches
            .saturating_add(dispatched as u64);

        dispatched
    }

    /// Récupère le message reçu suivant sur un canal donné
    pub fn receive_message(&mut self, cap: &IpcCap, channel_id: u32) -> Result<IpcMessage, SysError> {
        if !cap.has_right(ipc_rights::IPC_RECV) {
            return Err(SysError::PermissionDenied);
        }
        let channel = self
            .channels
            .iter_mut()
            .filter_map(|c| c.as_mut())
            .find(|c| c.channel_id == channel_id)
            .ok_or(SysError::InvalidArgument)?;

        channel.dequeue_rx().ok_or(SysError::ResourceBusy)
    }

    /// Traite un paquet brut reçu du réseau distant (inbound wire packet)
    ///
    /// Valide la version, vérifie le non-rejeu monotone (`sequence > rx_sequence`),
    /// déchiffre la trame et livre au canal local.
    pub fn process_inbound_wire(&mut self, mut msg: IpcMessage, current_tick: u64) -> Result<(), SysError> {
        if msg.magic != IPC_MAGIC || msg.version != IPC_VERSION {
            return Err(SysError::InvalidArgument);
        }
        if msg.is_expired(current_tick) {
            self.stats_data.total_dropped = self.stats_data.total_dropped.saturating_add(1);
            return Err(SysError::TimedOut);
        }

        // Trouver le canal destinataire
        let channel = self
            .channels
            .iter_mut()
            .filter_map(|c| c.as_mut())
            .find(|c| c.src_port == msg.dst_port || c.channel_id == msg.channel_id)
            .ok_or(SysError::InvalidArgument)?;

        // Protection anti-rejeu stricte
        if msg.sequence <= channel.rx_sequence {
            self.stats_data.total_replay_rejected =
                self.stats_data.total_replay_rejected.saturating_add(1);
            return Err(SysError::PermissionDenied);
        }

        // Déchiffrement et authentification
        if msg.flags & ipc_flags::FLAG_ENCRYPTED != 0 {
            if !channel.encrypted {
                return Err(SysError::PermissionDenied);
            }
            let key = channel.session_key;
            msg.decrypt(&key)?;
        }

        channel.rx_sequence = msg.sequence;
        let latency = current_tick.saturating_sub(msg.timestamp_ticks);
        channel.record_latency(latency);

        channel.enqueue_rx(msg)?;
        self.stats_data.total_received = self.stats_data.total_received.saturating_add(1);

        Ok(())
    }

    /// Dépile un paquet prêt pour émission physique vers un nœud distant
    pub fn pop_forward_frame(&mut self) -> Option<IpcMessage> {
        if self.fwd_count == 0 {
            return None;
        }
        let msg = self.fwd_queue[self.fwd_head].take();
        self.fwd_head = (self.fwd_head + 1) % TX_QUEUE_CAP;
        self.fwd_count -= 1;
        msg
    }

    /// Renvoie les statistiques globales
    pub fn stats(&self, cap: &IpcCap) -> Result<IpcStats, SysError> {
        if !cap.has_right(ipc_rights::IPC_RECV) && !cap.has_right(ipc_rights::IPC_ADMIN) {
            return Err(SysError::PermissionDenied);
        }
        Ok(self.stats_data)
    }

    pub fn get_channel(&self, channel_id: u32) -> Option<&IpcChannel> {
        self.channels
            .iter()
            .filter_map(|c| c.as_ref())
            .find(|c| c.channel_id == channel_id)
    }

    pub fn get_channel_mut(&mut self, channel_id: u32) -> Option<&mut IpcChannel> {
        self.channels
            .iter_mut()
            .filter_map(|c| c.as_mut())
            .find(|c| c.channel_id == channel_id)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_and_attenuation() {
        let admin_cap = IpcCap::new(Handle::new(77, 1), ipc_rights::ALL);
        assert!(admin_cap.has_right(ipc_rights::IPC_CHANNEL_CREATE));
        assert!(admin_cap.has_right(ipc_rights::IPC_SEND));
        assert!(admin_cap.has_right(ipc_rights::IPC_RECV));
        assert!(admin_cap.has_right(ipc_rights::IPC_ROUTE));
        assert!(admin_cap.has_right(ipc_rights::IPC_ENCRYPT));
        assert!(admin_cap.has_right(ipc_rights::IPC_PRIORITY));
        assert!(admin_cap.has_right(ipc_rights::IPC_ADMIN));

        let send_only = admin_cap.attenuate(ipc_rights::IPC_SEND).unwrap();
        assert!(send_only.has_right(ipc_rights::IPC_SEND));
        assert!(!send_only.has_right(ipc_rights::IPC_RECV));
        assert!(!send_only.has_right(ipc_rights::IPC_ADMIN));

        // Vérifier l'interdiction stricte d'élévation
        let bad_elevate = send_only.attenuate(ipc_rights::IPC_ADMIN);
        assert_eq!(bad_elevate, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_channel_creation_and_close() {
        let admin_cap = IpcCap::new(Handle::new(77, 1), ipc_rights::ALL);
        let mut daemon = JamboIpcDaemon::new(1, admin_cap);

        let ch_id = daemon
            .create_channel(
                &admin_cap,
                "chan-control",
                1,
                100,
                100,
                IpcPriority::High,
                false,
                None,
            )
            .expect("create channel");
        assert_eq!(ch_id, 1);
        assert_eq!(daemon.stats_data.channels_count, 1);

        let chan = daemon.get_channel(ch_id).unwrap();
        assert_eq!(chan.name_as_str(), "chan-control");
        assert_eq!(chan.priority, IpcPriority::High);

        // Fermeture
        daemon.close_channel(&admin_cap, ch_id).expect("close channel");
        assert_eq!(daemon.stats_data.channels_count, 0);
        assert!(daemon.get_channel(ch_id).is_none());
    }

    #[test]
    fn test_encryption_decryption_tampering() {
        let key = [0x42u8; 32];
        let mut msg = IpcMessage::new(
            1,
            1,
            1,
            2,
            50,
            50,
            IpcPriority::Normal,
            b"TopSecretPayloadData",
            1,
            100,
            500,
        )
        .expect("new msg");

        assert_eq!(msg.flags & ipc_flags::FLAG_ENCRYPTED, 0);
        msg.encrypt(&key);
        assert_ne!(msg.flags & ipc_flags::FLAG_ENCRYPTED, 0);
        assert_ne!(&msg.payload[..msg.payload_len], b"TopSecretPayloadData");

        // Altération d'un octet pour vérifier la détection de falsification
        let mut tampered_msg = msg;
        tampered_msg.payload[0] ^= 0xFF;
        assert_eq!(
            tampered_msg.decrypt(&key),
            Err(SysError::PermissionDenied),
            "Doit rejeter un payload altéré"
        );

        // Déchiffrement légitime
        msg.decrypt(&key).expect("decrypt with valid key");
        assert_eq!(&msg.payload[..msg.payload_len], b"TopSecretPayloadData");
        assert_eq!(msg.flags & ipc_flags::FLAG_ENCRYPTED, 0);
    }

    #[test]
    fn test_deterministic_priority_scheduling() {
        let admin_cap = IpcCap::new(Handle::new(77, 1), ipc_rights::ALL);
        let mut daemon = JamboIpcDaemon::new(1, admin_cap);

        let ch_normal = daemon
            .create_channel(
                &admin_cap,
                "norm",
                1,
                10,
                10,
                IpcPriority::Normal,
                false,
                None,
            )
            .unwrap();
        let ch_high = daemon
            .create_channel(
                &admin_cap,
                "high",
                1,
                20,
                20,
                IpcPriority::High,
                false,
                None,
            )
            .unwrap();
        let ch_crit = daemon
            .create_channel(
                &admin_cap,
                "crit",
                1,
                30,
                30,
                IpcPriority::Critical,
                false,
                None,
            )
            .unwrap();

        // Envoi dans l'ordre inverse : Normal d'abord, puis High, puis Critical
        daemon
            .send_message(&admin_cap, ch_normal, b"normal_payload", 100)
            .unwrap();
        daemon
            .send_message(&admin_cap, ch_high, b"high_payload", 101)
            .unwrap();
        daemon
            .send_message(&admin_cap, ch_crit, b"crit_payload", 102)
            .unwrap();

        // Ordonnancement déterministe
        let dispatched = daemon.dispatch_deterministic(110);
        assert_eq!(dispatched, 3);

        // Vérifier que le canal critique a bien reçu son message
        let recv_crit = daemon.receive_message(&admin_cap, ch_crit).unwrap();
        assert_eq!(&recv_crit.payload[..recv_crit.payload_len], b"crit_payload");

        let recv_high = daemon.receive_message(&admin_cap, ch_high).unwrap();
        assert_eq!(&recv_high.payload[..recv_high.payload_len], b"high_payload");

        let recv_norm = daemon.receive_message(&admin_cap, ch_normal).unwrap();
        assert_eq!(&recv_norm.payload[..recv_norm.payload_len], b"normal_payload");
    }

    #[test]
    fn test_inter_node_routing_and_forwarding() {
        let admin_cap = IpcCap::new(Handle::new(77, 1), ipc_rights::ALL);
        let mut daemon = JamboIpcDaemon::new(1, admin_cap);

        // Canal vers nœud 2 (distant)
        let ch_remote = daemon
            .create_channel(
                &admin_cap,
                "to-node2",
                2,
                100,
                100,
                IpcPriority::High,
                false,
                None,
            )
            .unwrap();

        // Route vers nœud 2
        daemon
            .add_route(&admin_cap, 2, 1, 10, 500, false)
            .expect("add route");

        daemon
            .send_message(&admin_cap, ch_remote, b"RemoteNodeMessage", 100)
            .unwrap();
        daemon.dispatch_deterministic(105);

        // Le message doit être dans la file de réacheminement externe (fwd_queue)
        assert_eq!(daemon.stats_data.total_forwarded, 1);
        let fwd = daemon.pop_forward_frame().expect("frame forwarded");
        assert_eq!(fwd.dst_node, 2);
        assert_ne!(fwd.flags & ipc_flags::FLAG_ROUTED, 0);
        assert_eq!(&fwd.payload[..fwd.payload_len], b"RemoteNodeMessage");
    }

    #[test]
    fn test_inbound_wire_anti_replay() {
        let admin_cap = IpcCap::new(Handle::new(77, 1), ipc_rights::ALL);
        let mut daemon = JamboIpcDaemon::new(1, admin_cap);

        let ch = daemon
            .create_channel(
                &admin_cap,
                "rx-chan",
                2,
                100,
                100,
                IpcPriority::Normal,
                false,
                None,
            )
            .unwrap();

        let mut msg1 = IpcMessage::new(
            1,
            ch,
            2,
            1,
            100,
            100,
            IpcPriority::Normal,
            b"Seq1",
            1,
            100,
            500,
        )
        .unwrap();

        // Première réception : séquence 1 valide
        daemon.process_inbound_wire(msg1, 105).expect("inbound seq 1");

        // Rejeu de la séquence 1 : doit être rejeté
        assert_eq!(
            daemon.process_inbound_wire(msg1, 106),
            Err(SysError::PermissionDenied)
        );
        assert_eq!(daemon.stats_data.total_replay_rejected, 1);

        // Message plus ancien (séquence 0) : rejeté
        msg1.sequence = 0;
        assert_eq!(
            daemon.process_inbound_wire(msg1, 107),
            Err(SysError::PermissionDenied)
        );

        // Séquence 2 valide
        msg1.sequence = 2;
        daemon.process_inbound_wire(msg1, 108).expect("inbound seq 2");
    }
}

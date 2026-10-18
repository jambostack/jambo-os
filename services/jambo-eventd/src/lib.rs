//! Bus d'Événements Pub/Sub Asynchrone Zéro-Copie (`jambo-eventd`)
//!
//! Fournit un bus de messagerie asynchrone découplé pour la grappe et les services Ring 3
//! de JamboOS en Rust `#![no_std]` sans autorité ambiante. L'émission et la réception
//! d'événements sont strictement régies par la capacité `EventCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_TOPIC_NAME: usize = 32;
pub const MAX_PAYLOAD: usize = 64;
pub const MAX_SUBSCRIPTIONS: usize = 16;
pub const MAX_QUEUE_LEN: usize = 8;

/// Droits de capacité pour le bus d'événements.
pub mod event_rights {
    pub const EVENT_PUBLISH: u32 = 0x01;
    pub const EVENT_SUBSCRIBE: u32 = 0x02;
    pub const EVENT_FILTER: u32 = 0x04;
    pub const EVENT_DRAIN: u32 = 0x08;
    pub const EVENT_ADMIN: u32 = 0x80;
    pub const ALL: u32 = EVENT_PUBLISH | EVENT_SUBSCRIBE | EVENT_FILTER | EVENT_DRAIN | EVENT_ADMIN;
}

/// Jeton de capacité pour le bus d'événements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventCap {
    pub handle: Handle,
    pub rights: u32,
}

impl EventCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }
}

/// Message d'événement asynchrone immuable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventMessage {
    pub topic: [u8; MAX_TOPIC_NAME],
    pub topic_len: usize,
    pub sender_pid: u32,
    pub seq_id: u64,
    pub timestamp_ms: u64,
    pub payload: [u8; MAX_PAYLOAD],
    pub payload_len: usize,
}

impl EventMessage {
    pub fn new(
        topic: &[u8],
        sender_pid: u32,
        seq_id: u64,
        timestamp_ms: u64,
        payload: &[u8],
    ) -> Self {
        let mut t_buf = [0u8; MAX_TOPIC_NAME];
        let mut p_buf = [0u8; MAX_PAYLOAD];
        let t_len = topic.len().min(MAX_TOPIC_NAME);
        let p_len = payload.len().min(MAX_PAYLOAD);
        t_buf[..t_len].copy_from_slice(&topic[..t_len]);
        p_buf[..p_len].copy_from_slice(&payload[..p_len]);

        Self {
            topic: t_buf,
            topic_len: t_len,
            sender_pid,
            seq_id,
            timestamp_ms,
            payload: p_buf,
            payload_len: p_len,
        }
    }

    pub fn topic_bytes(&self) -> &[u8] {
        &self.topic[..self.topic_len]
    }

    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }
}

/// File circulaire bornée par souscripteur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriberQueue {
    pub sub_id: u32,
    pub topic_filter: [u8; MAX_TOPIC_NAME],
    pub topic_filter_len: usize,
    pub is_prefix: bool,
    pub queue: [Option<EventMessage>; MAX_QUEUE_LEN],
    pub head: usize,
    pub tail: usize,
    pub count: usize,
    pub dropped_count: u64,
}

impl SubscriberQueue {
    pub fn new(sub_id: u32, filter: &[u8], is_prefix: bool) -> Self {
        let mut f_buf = [0u8; MAX_TOPIC_NAME];
        let copy_len = filter.len().min(MAX_TOPIC_NAME);
        f_buf[..copy_len].copy_from_slice(&filter[..copy_len]);

        Self {
            sub_id,
            topic_filter: f_buf,
            topic_filter_len: copy_len,
            is_prefix,
            queue: [None; MAX_QUEUE_LEN],
            head: 0,
            tail: 0,
            count: 0,
            dropped_count: 0,
        }
    }

    pub fn matches(&self, topic: &[u8]) -> bool {
        let filter = &self.topic_filter[..self.topic_filter_len];
        if self.is_prefix {
            topic.starts_with(filter)
        } else {
            topic == filter
        }
    }

    pub fn push(&mut self, msg: EventMessage) {
        if self.count >= MAX_QUEUE_LEN {
            // Drop-oldest : avance tail pour libérer le plus ancien
            self.tail = (self.tail + 1) % MAX_QUEUE_LEN;
            self.dropped_count += 1;
        } else {
            self.count += 1;
        }

        self.queue[self.head] = Some(msg);
        self.head = (self.head + 1) % MAX_QUEUE_LEN;
    }

    pub fn pop(&mut self) -> Option<EventMessage> {
        if self.count == 0 {
            return None;
        }

        let msg = self.queue[self.tail].take();
        self.tail = (self.tail + 1) % MAX_QUEUE_LEN;
        self.count -= 1;
        msg
    }
}

/// Bus d'événements asynchrone central.
pub struct EventBus {
    pub subscriptions: [Option<SubscriberQueue>; MAX_SUBSCRIPTIONS],
    pub next_sub_id: u32,
    pub next_seq_id: u64,
    pub published_count: u64,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub const fn new() -> Self {
        Self {
            subscriptions: [None; MAX_SUBSCRIPTIONS],
            next_sub_id: 1,
            next_seq_id: 1,
            published_count: 0,
        }
    }

    /// Enregistre une nouvelle souscription avec filtrage de sujet.
    pub fn subscribe(
        &mut self,
        cap: &EventCap,
        topic_filter: &[u8],
        is_prefix: bool,
    ) -> Result<u32, SysError> {
        if !cap.has_right(event_rights::EVENT_SUBSCRIBE) {
            return Err(SysError::PermissionDenied);
        }

        let free_slot = self
            .subscriptions
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(SysError::OutOfMemory)?;

        let id = self.next_sub_id;
        self.next_sub_id += 1;

        *free_slot = Some(SubscriberQueue::new(id, topic_filter, is_prefix));
        Ok(id)
    }

    /// Annule une souscription.
    pub fn unsubscribe(&mut self, cap: &EventCap, sub_id: u32) -> Result<(), SysError> {
        if !cap.has_right(event_rights::EVENT_SUBSCRIBE) {
            return Err(SysError::PermissionDenied);
        }

        let slot = self
            .subscriptions
            .iter_mut()
            .find(|s| match s {
                Some(sub) => sub.sub_id == sub_id,
                None => false,
            })
            .ok_or(SysError::InvalidArgument)?;

        *slot = None;
        Ok(())
    }

    /// Publie un événement et le diffuse à tous les abonnés correspondants.
    pub fn publish(
        &mut self,
        cap: &EventCap,
        sender_pid: u32,
        topic: &[u8],
        payload: &[u8],
        timestamp_ms: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(event_rights::EVENT_PUBLISH) {
            return Err(SysError::PermissionDenied);
        }

        let seq = self.next_seq_id;
        self.next_seq_id += 1;
        self.published_count += 1;

        let msg = EventMessage::new(topic, sender_pid, seq, timestamp_ms, payload);

        for s in self.subscriptions.iter_mut() {
            if let Some(sub) = s {
                if sub.matches(topic) {
                    sub.push(msg);
                }
            }
        }

        Ok(seq)
    }

    /// Récupère le prochain événement disponible pour un souscripteur.
    pub fn poll_event(
        &mut self,
        cap: &EventCap,
        sub_id: u32,
    ) -> Result<Option<EventMessage>, SysError> {
        if !cap.has_right(event_rights::EVENT_DRAIN) {
            return Err(SysError::PermissionDenied);
        }

        let sub = self
            .subscriptions
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|queue| queue.sub_id == sub_id))
            .ok_or(SysError::InvalidArgument)?;

        Ok(sub.pop())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_permissions() {
        let mut bus = EventBus::new();
        let unauth_cap = EventCap::new(Handle::new(1, 1), 0);
        let pub_cap = EventCap::new(Handle::new(2, 1), event_rights::EVENT_PUBLISH);
        let sub_cap = EventCap::new(
            Handle::new(3, 1),
            event_rights::EVENT_SUBSCRIBE | event_rights::EVENT_DRAIN,
        );

        // Rejet de souscription sans EVENT_SUBSCRIBE
        assert_eq!(
            bus.subscribe(&unauth_cap, b"sys/alerts", false),
            Err(SysError::PermissionDenied)
        );

        // Succès souscription
        let sub_id = bus.subscribe(&sub_cap, b"sys/alerts", false).unwrap();
        assert_eq!(sub_id, 1);

        // Rejet de publication sans EVENT_PUBLISH
        assert_eq!(
            bus.publish(&unauth_cap, 10, b"sys/alerts", b"ALERT_1", 100),
            Err(SysError::PermissionDenied)
        );

        // Succès publication
        let seq = bus
            .publish(&pub_cap, 10, b"sys/alerts", b"ALERT_1", 100)
            .unwrap();
        assert_eq!(seq, 1);

        // Récupération de l'événement
        let event = bus.poll_event(&sub_cap, sub_id).unwrap().unwrap();
        assert_eq!(event.payload_bytes(), b"ALERT_1");
        assert_eq!(event.sender_pid, 10);
    }

    #[test]
    fn test_prefix_filtering() {
        let mut bus = EventBus::new();
        let cap = EventCap::new(Handle::new(1, 1), event_rights::ALL);

        // Abonnement par préfixe : cluster/*
        let sub_cluster = bus.subscribe(&cap, b"cluster/", true).unwrap();
        // Abonnement exact : cluster/node1
        let sub_node1 = bus.subscribe(&cap, b"cluster/node1", false).unwrap();

        // Publication sur cluster/node2 -> seul sub_cluster doit recevoir
        bus.publish(&cap, 1, b"cluster/node2", b"HEARTBEAT_N2", 200)
            .unwrap();
        // Publication sur cluster/node1 -> les deux doivent recevoir
        bus.publish(&cap, 1, b"cluster/node1", b"HEARTBEAT_N1", 201)
            .unwrap();

        // sub_cluster a 2 événements
        let e1 = bus.poll_event(&cap, sub_cluster).unwrap().unwrap();
        let e2 = bus.poll_event(&cap, sub_cluster).unwrap().unwrap();
        assert_eq!(e1.payload_bytes(), b"HEARTBEAT_N2");
        assert_eq!(e2.payload_bytes(), b"HEARTBEAT_N1");

        // sub_node1 n'a reçu que HEARTBEAT_N1
        let en1 = bus.poll_event(&cap, sub_node1).unwrap().unwrap();
        assert_eq!(en1.payload_bytes(), b"HEARTBEAT_N1");
        assert!(bus.poll_event(&cap, sub_node1).unwrap().is_none());
    }

    #[test]
    fn test_drop_oldest_on_queue_overflow() {
        let mut bus = EventBus::new();
        let cap = EventCap::new(Handle::new(1, 1), event_rights::ALL);

        let sub_id = bus.subscribe(&cap, b"stream", false).unwrap();

        // Remplissage au-delà de MAX_QUEUE_LEN (8)
        for i in 0..10 {
            let mut payload = [0u8; 1];
            payload[0] = i as u8;
            bus.publish(&cap, 1, b"stream", &payload, 500 + i as u64)
                .unwrap();
        }

        // Vérification : les 2 premiers ont été écrasés (0 et 1), le premier disponible est 2
        let first = bus.poll_event(&cap, sub_id).unwrap().unwrap();
        assert_eq!(first.payload_bytes()[0], 2);
    }
}

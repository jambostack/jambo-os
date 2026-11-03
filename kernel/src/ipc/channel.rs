extern crate alloc;
use crate::cap::KernelObject;
use alloc::collections::VecDeque;
use jambo_abi::{Handle, SysError};
use spin::Mutex;

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

/// Message IPC brut tel qu'échangé en espace utilisateur
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

/// Message IPC en vol au sein du micro-noyau avec capacités protégées
#[derive(Clone)]
pub struct InFlightMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub caps: [Option<(KernelObject, u32)>; MAX_HANDLES],
    pub cap_count: usize,
}

impl InFlightMessage {
    pub const fn empty() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
            caps: [None, None, None, None],
            cap_count: 0,
        }
    }
}

impl From<ChannelMessage> for InFlightMessage {
    fn from(msg: ChannelMessage) -> Self {
        Self {
            bytes: msg.bytes,
            byte_count: msg.byte_count,
            caps: [None, None, None, None],
            cap_count: 0,
        }
    }
}

pub struct Channel {
    pub endpoint_a_queue: VecDeque<InFlightMessage>,
    pub endpoint_b_queue: VecDeque<InFlightMessage>,
    pub is_closed: bool,
}

impl Channel {
    pub fn new() -> Self {
        Self {
            endpoint_a_queue: VecDeque::with_capacity(16),
            endpoint_b_queue: VecDeque::with_capacity(16),
            is_closed: false,
        }
    }

    pub fn send(&mut self, is_endpoint_a: bool, msg: InFlightMessage) -> Result<(), SysError> {
        if self.is_closed {
            return Err(SysError::PeerClosed);
        }
        if msg.byte_count > MAX_FASTPATH_BYTES || msg.cap_count > MAX_HANDLES {
            return Err(SysError::InvalidArgument);
        }
        let target_queue = if is_endpoint_a {
            &mut self.endpoint_b_queue
        } else {
            &mut self.endpoint_a_queue
        };
        target_queue.push_back(msg);
        Ok(())
    }

    pub fn recv(&mut self, is_endpoint_a: bool) -> Result<Option<InFlightMessage>, SysError> {
        if self.is_closed {
            return Err(SysError::PeerClosed);
        }
        let my_queue = if is_endpoint_a {
            &mut self.endpoint_a_queue
        } else {
            &mut self.endpoint_b_queue
        };
        Ok(my_queue.pop_front())
    }
}

pub static CHANNEL_REGISTRY: Mutex<alloc::vec::Vec<Channel>> = Mutex::new(alloc::vec::Vec::new());

/// Extrémité de canal IPC typée et isolée pour le modèle de capacités
pub struct ChannelEndpoint {
    pub channel: alloc::sync::Arc<Mutex<Channel>>,
    pub is_endpoint_a: bool,
}

impl ChannelEndpoint {
    pub fn new(
        channel: alloc::sync::Arc<Mutex<Channel>>,
        is_endpoint_a: bool,
    ) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            channel,
            is_endpoint_a,
        })
    }

    pub fn send(&self, msg: InFlightMessage) -> Result<(), SysError> {
        self.channel.lock().send(self.is_endpoint_a, msg)
    }

    pub fn recv(&self) -> Result<Option<InFlightMessage>, SysError> {
        self.channel.lock().recv(self.is_endpoint_a)
    }

    pub fn is_peer_closed(&self) -> bool {
        self.channel.lock().is_closed
    }
}

impl Drop for ChannelEndpoint {
    fn drop(&mut self) {
        // Notifier la fermeture de l'extrémité opposée (PeerClosed)
        self.channel.lock().is_closed = true;
    }
}

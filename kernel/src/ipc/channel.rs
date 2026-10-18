extern crate alloc;
use alloc::collections::VecDeque;
use spin::Mutex;
use jambo_abi::{Handle, SysError};

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

#[derive(Clone)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [Handle; MAX_HANDLES],
    pub handle_count: usize,
}

pub struct Channel {
    pub endpoint_a_queue: VecDeque<ChannelMessage>,
    pub endpoint_b_queue: VecDeque<ChannelMessage>,
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

    pub fn send(&mut self, is_endpoint_a: bool, msg: ChannelMessage) -> Result<(), SysError> {
        if self.is_closed {
            return Err(SysError::PeerClosed);
        }
        let target_queue = if is_endpoint_a {
            &mut self.endpoint_b_queue
        } else {
            &mut self.endpoint_a_queue
        };
        target_queue.push_back(msg);
        Ok(())
    }

    pub fn recv(&mut self, is_endpoint_a: bool) -> Result<Option<ChannelMessage>, SysError> {
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

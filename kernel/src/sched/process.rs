extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use crate::mm::AddressSpace;
use super::thread::Thread;

pub struct Process {
    pub id: u64,
    pub aspace: Arc<AddressSpace>,
    pub threads: Mutex<Vec<Arc<Mutex<Thread>>>>,
}

impl Process {
    pub fn new(id: u64, aspace: Arc<AddressSpace>) -> Arc<Self> {
        Arc::new(Self {
            id,
            aspace,
            threads: Mutex::new(Vec::new()),
        })
    }
}

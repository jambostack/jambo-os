extern crate alloc;
use crate::sched::{Thread, ThreadState, SCHEDULER};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use jambo_abi::SysError;
use spin::Mutex;

/// Gestionnaire central des verrous légers espace utilisateur (Fast Userspace Mutex)
pub struct FutexManager {
    waiters: Mutex<BTreeMap<usize, Vec<Arc<Mutex<Thread>>>>>,
}

impl FutexManager {
    pub const fn new() -> Self {
        Self {
            waiters: Mutex::new(BTreeMap::new()),
        }
    }

    /// Suspend le thread courant si la valeur à uaddr est égale à expected_val
    pub fn wait(&self, uaddr: usize, expected_val: u32, current_val: u32) -> Result<(), SysError> {
        if current_val != expected_val {
            return Err(SysError::ResourceBusy);
        }

        let current_thread = {
            let sched = SCHEDULER.lock();
            sched.current.clone()
        };

        if let Some(thread) = current_thread {
            thread.lock().state = ThreadState::Blocked;
            let mut map = self.waiters.lock();
            map.entry(uaddr).or_insert_with(Vec::new).push(thread);
            drop(map);

            SCHEDULER.lock().reschedule();
            Ok(())
        } else {
            Err(SysError::InvalidArgument)
        }
    }

    /// Réveille jusqu'à `count` threads en attente sur l'adresse virtuelle `uaddr`
    pub fn wake(&self, uaddr: usize, count: u32) -> Result<u32, SysError> {
        if count == 0 {
            return Ok(0);
        }

        let mut map = self.waiters.lock();
        let mut woken = 0;

        if let Some(queue) = map.get_mut(&uaddr) {
            let to_wake = (count as usize).min(queue.len());
            for _ in 0..to_wake {
                if let Some(thread) = queue.pop() {
                    let mut t = thread.lock();
                    if t.state == ThreadState::Blocked {
                        t.state = ThreadState::Ready;
                        drop(t);
                        SCHEDULER.lock().enqueue(thread);
                        woken += 1;
                    }
                }
            }
            if queue.is_empty() {
                map.remove(&uaddr);
            }
        }

        Ok(woken)
    }

    /// Nombre de threads en attente sur une adresse donnée
    pub fn waiter_count(&self, uaddr: usize) -> usize {
        self.waiters.lock().get(&uaddr).map_or(0, |q| q.len())
    }
}

pub static FUTEX_MANAGER: FutexManager = FutexManager::new();

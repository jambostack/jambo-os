extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use jambo_abi::{JamboEvent, SysError};
use spin::Mutex;

use crate::sched::{EevdfScheduler, Thread, ThreadState, SCHEDULER};

/// Port asynchrone de notification et de multiplexage d'événements
pub struct Port {
    events: Mutex<VecDeque<JamboEvent>>,
    waiters: Mutex<Vec<Arc<Mutex<Thread>>>>,
}

impl Port {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Enfile un événement dans le port et réveille un thread en attente s'il existe
    pub fn queue(&self, event: JamboEvent) {
        let mut waiters = self.waiters.lock();
        if let Some(thread) = waiters.pop() {
            self.events.lock().push_back(event);
            let mut t = thread.lock();
            t.state = ThreadState::Ready;
            drop(t);
            SCHEDULER.lock().enqueue(thread);
        } else {
            self.events.lock().push_back(event);
        }
    }

    /// Attend un événement sur le port.
    /// Si un événement est déjà présent, il est immédiatement dépilé.
    /// Si timeout_ns == 0 et aucun événement n'est présent, renvoie Ok(None).
    /// Sinon, suspend le thread appelant en attente de notification.
    pub fn wait(&self, timeout_ns: u64) -> Result<Option<JamboEvent>, SysError> {
        // Vérifier si un événement est immédiatement consommable
        {
            let mut events = self.events.lock();
            if let Some(ev) = events.pop_front() {
                return Ok(Some(ev));
            }
        }

        // Si non bloquant (timeout == 0), retourner immédiatement
        if timeout_ns == 0 {
            return Ok(None);
        }

        // Suspendre le thread appelant
        let current_thread = {
            let sched = SCHEDULER.lock();
            sched.current.clone()
        };

        if let Some(thread) = current_thread {
            {
                let mut waiters = self.waiters.lock();
                waiters.push(thread.clone());
            }

            {
                let mut t = thread.lock();
                t.state = ThreadState::Blocked;
            }

            // Réordonnancement EEVDF
            EevdfScheduler::reschedule();

            // Au réveil, consommer l'événement disponible
            let mut events = self.events.lock();
            Ok(events.pop_front())
        } else {
            // Mode bootstrap/test unithread
            let mut events = self.events.lock();
            Ok(events.pop_front())
        }
    }

    /// Nombre d'événements actuellement en attente
    pub fn pending_count(&self) -> usize {
        self.events.lock().len()
    }
}

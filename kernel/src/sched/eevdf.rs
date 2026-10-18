extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use super::context::switch_context;
use super::thread::{Thread, ThreadState};

pub struct EevdfScheduler {
    runqueue: Vec<Arc<Mutex<Thread>>>,
    pub current: Option<Arc<Mutex<Thread>>>,
}

impl EevdfScheduler {
    pub const fn new() -> Self {
        Self {
            runqueue: Vec::new(),
            current: None,
        }
    }

    /// Ajoute un thread prêt à s'exécuter dans la file d'attente
    pub fn enqueue(&mut self, thread: Arc<Mutex<Thread>>) {
        thread.lock().state = ThreadState::Ready;
        self.runqueue.push(thread);
    }

    /// Sélectionne le thread ayant la plus petite échéance virtuelle (Earliest Eligible Virtual Deadline)
    pub fn pick_next(&mut self) -> Option<Arc<Mutex<Thread>>> {
        if self.runqueue.is_empty() {
            return None;
        }

        // Trouver l'index du thread avec la deadline minimale
        let mut min_idx = 0;
        let mut min_deadline = u64::MAX;

        for (i, t) in self.runqueue.iter().enumerate() {
            let thread = t.lock();
            if thread.state == ThreadState::Ready && thread.deadline < min_deadline {
                min_deadline = thread.deadline;
                min_idx = i;
            }
        }

        let next = self.runqueue.swap_remove(min_idx);
        next.lock().state = ThreadState::Running;
        Some(next)
    }

    /// Effectue un réordonnancement explicite (thread_yield ou fin de quantum)
    pub fn reschedule(&mut self) {
        let next_thread = match self.pick_next() {
            Some(t) => t,
            None => return, // Aucun autre thread prêt
        };

        let prev_current = self.current.take();
        if let Some(current) = prev_current {
            // Si le thread courant est toujours actif, le remettre dans la runqueue
            let mut curr = current.lock();
            if curr.state == ThreadState::Running {
                curr.state = ThreadState::Ready;
                curr.vruntime += 1;
                curr.deadline += 10;
                drop(curr);
                self.runqueue.push(current.clone());
            }

            let mut prev_guard = current.lock();
            let next_guard = next_thread.lock();

            let prev_rsp_ptr = &mut prev_guard.rsp as *mut u64;
            let next_rsp = next_guard.rsp;

            drop(prev_guard);
            drop(next_guard);

            self.current = Some(next_thread);

            unsafe {
                switch_context(prev_rsp_ptr, next_rsp);
            }
        } else {
            // Premier ordonnancement
            let mut dummy_rsp: u64 = 0;
            let next_rsp = next_thread.lock().rsp;
            self.current = Some(next_thread);

            unsafe {
                switch_context(&mut dummy_rsp, next_rsp);
            }
        }
    }
}

pub static SCHEDULER: Mutex<EevdfScheduler> = Mutex::new(EevdfScheduler::new());

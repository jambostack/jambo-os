extern crate alloc;
use super::context::switch_context;
use super::thread::{Thread, ThreadState};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

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

    /// Retire un thread de la file d'attente par son TID
    pub fn remove_thread(&mut self, tid: u64) {
        self.runqueue.retain(|t| t.lock().id != tid);
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

    /// Déclenché par le timer matériel (ex: APIC Timer à 100 Hz)
    pub fn on_timer_tick() {
        let should_reschedule = {
            if let Some(sched) = SCHEDULER.try_lock() {
                if let Some(ref curr) = sched.current {
                    let mut thread = curr.lock();
                    thread.vruntime += 1;
                    thread.vruntime >= thread.deadline && !sched.runqueue.is_empty()
                } else {
                    !sched.runqueue.is_empty()
                }
            } else {
                false
            }
        };

        if should_reschedule {
            Self::reschedule();
        }
    }

    /// Effectue un réordonnancement explicite (thread_yield ou fin de quantum)
    pub fn reschedule() {
        let (prev_rsp_ptr, next_rsp, next_aspace, next_stack_top) = {
            let mut sched = SCHEDULER.lock();
            let next_thread = match sched.pick_next() {
                Some(t) => t,
                None => return, // Aucun autre thread prêt
            };

            let prev_current = sched.current.take();
            if let Some(current) = prev_current {
                let mut curr = current.lock();
                if curr.state == ThreadState::Running {
                    curr.state = ThreadState::Ready;
                    curr.vruntime += 1;
                    curr.deadline += 10;
                    drop(curr);
                    sched.runqueue.push(current.clone());
                } else {
                    drop(curr);
                }

                let (next_rsp, next_aspace, next_stack_top) = {
                    let guard = next_thread.lock();
                    (guard.rsp, guard.aspace.clone(), guard.stack_top as u64)
                };
                sched.current = Some(next_thread);

                let prev_rsp_ptr = {
                    let mut prev_guard = current.lock();
                    &mut prev_guard.rsp as *mut u64
                };

                (prev_rsp_ptr, next_rsp, next_aspace, next_stack_top)
            } else {
                let (next_rsp, next_aspace, next_stack_top) = {
                    let guard = next_thread.lock();
                    (guard.rsp, guard.aspace.clone(), guard.stack_top as u64)
                };
                sched.current = Some(next_thread);
                (core::ptr::null_mut(), next_rsp, next_aspace, next_stack_top)
            }
        };

        if let Some(ref _aspace) = next_aspace {
            #[cfg(target_arch = "x86_64")]
            {
                crate::mm::paging::write_cr3(_aspace.pml4_paddr);
                crate::arch::set_kernel_stack(next_stack_top);
                crate::arch::set_current_kernel_stack(next_stack_top);
            }
        } else if next_stack_top != 0 {
            #[cfg(target_arch = "x86_64")]
            {
                crate::arch::set_kernel_stack(next_stack_top);
                crate::arch::set_current_kernel_stack(next_stack_top);
            }
        }

        if !prev_rsp_ptr.is_null() {
            unsafe {
                switch_context(prev_rsp_ptr, next_rsp);
            }
        } else {
            let mut dummy_rsp: u64 = 0;
            unsafe {
                switch_context(&mut dummy_rsp, next_rsp);
            }
        }
    }
}

pub static SCHEDULER: Mutex<EevdfScheduler> = Mutex::new(EevdfScheduler::new());

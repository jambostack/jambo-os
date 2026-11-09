extern crate alloc;
use super::context::switch_context;
use super::thread::{Thread, ThreadState};
use crate::kprintln;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

pub const MAX_CPUS: usize = 64;
pub const MAX_LAG: u64 = 50;
pub const MAX_WAIT_TICKS: u64 = 100;
pub const DEFAULT_QUANTUM_TICKS: u64 = 10;
pub const WAKEUP_LATENCY_SLA_US: u64 = 50;

/// Métriques de latence de réveil et respect du SLA temps-réel (< 50 µs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeupLatencyMetrics {
    pub min_wakeup_latency_us: u64,
    pub max_wakeup_latency_us: u64,
    pub total_wakeup_latency_us: u64,
    pub wakeup_count: u64,
    pub sla_violations_count: u64,
}

impl Default for WakeupLatencyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl WakeupLatencyMetrics {
    pub const fn new() -> Self {
        Self {
            min_wakeup_latency_us: u64::MAX,
            max_wakeup_latency_us: 0,
            total_wakeup_latency_us: 0,
            wakeup_count: 0,
            sla_violations_count: 0,
        }
    }

    #[inline]
    pub fn record_latency(&mut self, latency_us: u64) {
        self.wakeup_count = self.wakeup_count.saturating_add(1);
        self.total_wakeup_latency_us = self.total_wakeup_latency_us.saturating_add(latency_us);
        if latency_us < self.min_wakeup_latency_us {
            self.min_wakeup_latency_us = latency_us;
        }
        if latency_us > self.max_wakeup_latency_us {
            self.max_wakeup_latency_us = latency_us;
        }
        if latency_us > WAKEUP_LATENCY_SLA_US {
            self.sla_violations_count = self.sla_violations_count.saturating_add(1);
        }
    }
}

pub struct EevdfScheduler {
    pub runqueue: Vec<Arc<Mutex<Thread>>>,
    pub current_per_cpu: [Option<Arc<Mutex<Thread>>>; MAX_CPUS],
    pub idle_threads: [Option<Arc<Mutex<Thread>>>; MAX_CPUS],
    pub virtual_time: u64,
    pub metrics: WakeupLatencyMetrics,
}

impl EevdfScheduler {
    pub const fn new() -> Self {
        const NONE_THREAD: Option<Arc<Mutex<Thread>>> = None;
        Self {
            runqueue: Vec::new(),
            current_per_cpu: [NONE_THREAD; MAX_CPUS],
            idle_threads: [NONE_THREAD; MAX_CPUS],
            virtual_time: 0,
            metrics: WakeupLatencyMetrics::new(),
        }
    }

    /// Obtient le thread courant s'exécutant sur le processeur appelant
    #[inline]
    pub fn current(&self) -> Option<Arc<Mutex<Thread>>> {
        let cpu_id = crate::arch::current_cpu().cpu_id as usize;
        self.current_for_cpu(cpu_id)
    }

    /// Obtient le thread courant d'un processeur spécifique
    #[inline]
    pub fn current_for_cpu(&self, cpu_id: usize) -> Option<Arc<Mutex<Thread>>> {
        if cpu_id < MAX_CPUS {
            self.current_per_cpu[cpu_id].clone()
        } else {
            None
        }
    }

    /// Définit le thread courant pour le processeur appelant
    #[inline]
    pub fn set_current(&mut self, thread: Option<Arc<Mutex<Thread>>>) {
        let cpu_id = crate::arch::current_cpu().cpu_id as usize;
        self.set_current_for_cpu(cpu_id, thread);
    }

    /// Définit le thread courant pour un processeur spécifique
    #[inline]
    pub fn set_current_for_cpu(&mut self, cpu_id: usize, thread: Option<Arc<Mutex<Thread>>>) {
        if cpu_id < MAX_CPUS {
            self.current_per_cpu[cpu_id] = thread;
        }
    }

    /// Enregistre un thread idle dédié pour un processeur donné
    pub fn register_cpu_idle(&mut self, cpu_id: usize) {
        if cpu_id < MAX_CPUS && self.idle_threads[cpu_id].is_none() {
            if let Some(idle) = Thread::new_idle(cpu_id as u32) {
                self.idle_threads[cpu_id] = Some(idle.clone());
                if self.current_per_cpu[cpu_id].is_none() {
                    self.current_per_cpu[cpu_id] = Some(idle);
                }
            }
        }
    }

    /// Recalcule le temps virtuel système V (monotone, minimum des vruntimes prêts)
    pub fn update_virtual_time(&mut self) {
        let mut min_vruntime = u64::MAX;
        for t in &self.runqueue {
            let guard = t.lock();
            if guard.state == ThreadState::Ready && guard.vruntime < min_vruntime {
                min_vruntime = guard.vruntime;
            }
        }
        if min_vruntime != u64::MAX && min_vruntime > self.virtual_time {
            self.virtual_time = min_vruntime;
        }
    }

    /// Ajoute un thread prêt à s'exécuter dans la file d'attente avec bornage de lag
    pub fn enqueue(&mut self, thread: Arc<Mutex<Thread>>) {
        {
            let mut t = thread.lock();
            t.state = ThreadState::Ready;
            t.wait_ticks = 0;
            t.wake_timestamp_us = self.virtual_time;

            // Bornage du lag : clamp vruntime dans [V - MAX_LAG, V + MAX_LAG]
            let v = self.virtual_time;
            if t.vruntime < v.saturating_sub(MAX_LAG) {
                t.vruntime = v.saturating_sub(MAX_LAG);
            } else if t.vruntime > v.saturating_add(MAX_LAG) {
                t.vruntime = v.saturating_add(MAX_LAG);
            }

            // Calcul de la deadline virtuelle : d = vruntime + (quantum * 1024) / weight
            let quantum_weighted = (DEFAULT_QUANTUM_TICKS * 1024) / (t.weight as u64).max(1);
            t.deadline = t.vruntime.saturating_add(quantum_weighted);
            t.base_deadline = t.deadline;
        }

        self.runqueue.push(thread);
        self.update_virtual_time();
    }

    /// Retire un thread de la file d'attente par son TID
    pub fn remove_thread(&mut self, tid: u64) {
        self.runqueue.retain(|t| t.lock().id != tid);
        self.update_virtual_time();
    }

    /// Sélectionne le thread ayant la plus petite échéance virtuelle (Earliest Eligible Virtual Deadline)
    /// pour le processeur appelant.
    pub fn pick_next(&mut self) -> Option<Arc<Mutex<Thread>>> {
        let cpu_id = crate::arch::current_cpu().cpu_id as usize;
        self.pick_next_for_cpu(cpu_id)
    }

    /// Sélectionne le thread ayant la plus petite échéance virtuelle compatible avec un processeur
    pub fn pick_next_for_cpu(&mut self, cpu_id: usize) -> Option<Arc<Mutex<Thread>>> {
        if self.runqueue.is_empty() {
            return None;
        }

        self.update_virtual_time();
        let v = self.virtual_time;

        let mut best_idx = None;
        let mut min_deadline = u64::MAX;

        // Première passe : sélection parmi les threads éligibles (vruntime <= v ou wait_ticks >= MAX_WAIT_TICKS)
        for (i, t) in self.runqueue.iter().enumerate() {
            let mut thread = t.lock();
            if thread.state != ThreadState::Ready {
                continue;
            }

            // Vérification de l'affinité matérielle
            if let Some(target_cpu) = thread.cpu_affinity {
                if target_cpu as usize != cpu_id {
                    continue;
                }
            }

            // Anti-starvation aging : promotion d'urgence si attente excessive
            if thread.wait_ticks >= MAX_WAIT_TICKS {
                thread.deadline = v;
            }

            let is_eligible = thread.vruntime <= v || thread.wait_ticks >= MAX_WAIT_TICKS;

            if is_eligible {
                let better = match best_idx {
                    None => true,
                    Some(_) => {
                        if thread.deadline < min_deadline {
                            true
                        } else if thread.deadline == min_deadline {
                            thread.cpu_affinity.is_some()
                        } else {
                            false
                        }
                    }
                };
                if better {
                    min_deadline = thread.deadline;
                    best_idx = Some(i);
                }
            }
        }

        // Seconde passe de secours : si aucun thread éligible n'est prêt pour ce CPU, prendre le vruntime minimum
        if best_idx.is_none() {
            let mut min_vruntime = u64::MAX;
            for (i, t) in self.runqueue.iter().enumerate() {
                let thread = t.lock();
                if thread.state == ThreadState::Ready {
                    if let Some(target_cpu) = thread.cpu_affinity {
                        if target_cpu as usize != cpu_id {
                            continue;
                        }
                    }
                    let better = match best_idx {
                        None => true,
                        Some(_) => {
                            if thread.vruntime < min_vruntime {
                                true
                            } else if thread.vruntime == min_vruntime {
                                thread.cpu_affinity.is_some()
                            } else {
                                false
                            }
                        }
                    };
                    if better {
                        min_vruntime = thread.vruntime;
                        best_idx = Some(i);
                    }
                }
            }
        }

        let chosen_idx = best_idx?;
        let next = self.runqueue.swap_remove(chosen_idx);

        // Incrémenter wait_ticks pour les autres threads restés en file
        for t in &self.runqueue {
            let mut guard = t.lock();
            if guard.state == ThreadState::Ready {
                guard.wait_ticks = guard.wait_ticks.saturating_add(1);
            }
        }

        {
            let mut guard = next.lock();
            guard.state = ThreadState::Running;
            guard.wait_ticks = 0;
            guard.last_cpu = cpu_id as u32;
            let latency_us = self.virtual_time.saturating_sub(guard.wake_timestamp_us);
            self.metrics.record_latency(latency_us);
        }

        Some(next)
    }

    /// Déclenché par le timer matériel local (APIC Timer / GIC)
    pub fn on_timer_tick() {
        let cpu_id = crate::arch::current_cpu().cpu_id as usize;
        let should_reschedule = {
            if let Some(sched) = SCHEDULER.try_lock() {
                if let Some(curr) = sched.current_for_cpu(cpu_id) {
                    let mut thread = curr.lock();
                    let is_idle = thread.id >= 0x8000_0000_0000_0000;
                    if !is_idle {
                        let weight = (thread.weight as u64).max(1);
                        let vruntime_delta = 1024 / weight;
                        thread.vruntime = thread.vruntime.saturating_add(vruntime_delta.max(1));
                        thread.vruntime >= thread.deadline && !sched.runqueue.is_empty()
                    } else {
                        !sched.runqueue.is_empty()
                    }
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

    /// Effectue un réordonnancement explicite pour le processeur appelant
    pub fn reschedule() {
        let cpu_id = crate::arch::current_cpu().cpu_id as usize;

        let (prev_rsp_ptr, next_rsp, next_aspace, _next_stack_top) = {
            let mut sched = SCHEDULER.lock();

            // S'assurer de la présence d'un thread idle pour ce CPU
            if sched.idle_threads[cpu_id].is_none() {
                sched.register_cpu_idle(cpu_id);
            }

            let next_thread = match sched.pick_next_for_cpu(cpu_id) {
                Some(t) => t,
                None => {
                    // Aucun autre thread prêt pour ce CPU.
                    // Si le thread courant est un thread de calcul toujours Running, continuer son exécution
                    if let Some(ref curr) = sched.current_per_cpu[cpu_id] {
                        let guard = curr.lock();
                        if guard.state == ThreadState::Running {
                            return;
                        }
                    }
                    // Sinon basculer vers l'idle thread
                    sched.idle_threads[cpu_id]
                        .clone()
                        .expect("Thread idle requis")
                }
            };

            let prev_current = sched.current_per_cpu[cpu_id].take();
            if let Some(current) = prev_current {
                if Arc::ptr_eq(&current, &next_thread) {
                    sched.current_per_cpu[cpu_id] = Some(current);
                    return;
                }

                let mut curr = current.lock();
                let is_idle = curr.id >= 0x8000_0000_0000_0000;

                if curr.state == ThreadState::Running && !is_idle {
                    curr.state = ThreadState::Ready;
                    let quantum_weighted =
                        (DEFAULT_QUANTUM_TICKS * 1024) / (curr.weight as u64).max(1);
                    curr.deadline = curr.vruntime.saturating_add(quantum_weighted);
                    drop(curr);
                    sched.runqueue.push(current.clone());
                } else {
                    drop(curr);
                }

                let (next_rsp, next_aspace, next_stack_top) = {
                    let guard = next_thread.lock();
                    (guard.rsp, guard.aspace.clone(), guard.stack_top as u64)
                };
                sched.current_per_cpu[cpu_id] = Some(next_thread);

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
                sched.current_per_cpu[cpu_id] = Some(next_thread);
                (core::ptr::null_mut(), next_rsp, next_aspace, next_stack_top)
            }
        };

        if let Some(ref _aspace) = next_aspace {
            #[cfg(target_arch = "x86_64")]
            {
                crate::mm::paging::write_cr3(_aspace.pml4_paddr);
                crate::arch::set_kernel_stack(_next_stack_top);
                crate::arch::set_current_kernel_stack(_next_stack_top);
            }
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                let boot_cr3 = crate::mm::paging::boot_kernel_cr3();
                if boot_cr3 != 0 && crate::mm::paging::read_cr3() != boot_cr3 {
                    crate::mm::paging::write_cr3(boot_cr3);
                }
                if _next_stack_top != 0 {
                    crate::arch::set_kernel_stack(_next_stack_top);
                    crate::arch::set_current_kernel_stack(_next_stack_top);
                }
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            let cpu = crate::arch::current_cpu();
            let cpu_ptr = cpu as *const _ as u64;
            // SAFETY: Garantit que KERNEL_GS_BASE_MSR pointe toujours vers le PerCpuData du cœur local pour swapgs
            unsafe {
                crate::arch::x86_64::apic::wrmsr(
                    crate::arch::x86_64::cpu::IA32_KERNEL_GS_BASE_MSR,
                    cpu_ptr,
                );
            }
        }

        if !prev_rsp_ptr.is_null() {
            // SAFETY: switch_context effectue la sauvegarde et la restauration des registres callee-saved entre deux piles valides.
            unsafe {
                switch_context(prev_rsp_ptr, next_rsp);
            }
        } else {
            let mut dummy_rsp: u64 = 0;
            // SAFETY: switch_context effectue le premier saut vers la pile du thread cible (next_rsp).
            unsafe {
                switch_context(&mut dummy_rsp, next_rsp);
            }
        }
    }

    /// Point d'entrée de la boucle d'ordonnancement pour un cœur secondaire AP
    pub fn ap_entry(cpu_id: usize) -> ! {
        {
            let mut sched = SCHEDULER.lock();
            sched.register_cpu_idle(cpu_id);
        }

        kprintln!(
            "[SMP/AP] Cœur AP #{} a rejoint l'ordonnanceur EEVDF",
            cpu_id
        );

        super::thread::cpu_idle_trampoline();
    }
}

pub static SCHEDULER: Mutex<EevdfScheduler> = Mutex::new(EevdfScheduler::new());

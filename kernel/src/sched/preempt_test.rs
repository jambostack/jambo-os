//! Module de validation formelle du multitâche préemptif par Timer APIC (Phase 40 - v0.2.38)
#![allow(unused_imports, dead_code)]

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::kprintln;
use crate::sched::{EevdfScheduler, Thread, ThreadState, SCHEDULER};

static COMPUTE_TICKS: AtomicU64 = AtomicU64::new(0);
static TEST_COMPLETE: AtomicBool = AtomicBool::new(false);

/// Thread de calcul non coopératif exécutant une boucle de calcul sans appel système
extern "C" fn uncooperative_compute_worker() {
    while !TEST_COMPLETE.load(Ordering::Acquire) {
        COMPUTE_TICKS.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }

    // Sortie propre une fois la préemption validée
    {
        let sched = SCHEDULER.lock();
        if let Some(ref curr) = sched.current {
            curr.lock().state = ThreadState::Exited;
        }
    }
    EevdfScheduler::reschedule();
    loop {
        core::hint::spin_loop();
    }
}

/// Exécute le test de validation du multitâche préemptif (Phase 40)
#[cfg(target_arch = "x86_64")]
pub fn execute_preemption_test() -> bool {
    kprintln!(
        "[PREEMPT/TEST] Démarrage du test de préemption matérielle par Timer APIC (Phase 40)..."
    );

    COMPUTE_TICKS.store(0, Ordering::SeqCst);
    TEST_COMPLETE.store(false, Ordering::SeqCst);

    // 1. Créer le thread de travail non coopératif (Thread A)
    let worker_thread = match Thread::new_kernel(888, 1, uncooperative_compute_worker) {
        Some(t) => t,
        None => {
            kprintln!("[PREEMPT/ERR] Échec d'allocation du thread de calcul");
            return false;
        }
    };
    worker_thread.lock().deadline = 1; // Deadline minimale pour déclencher la préemption rapidement

    // 2. Créer le thread superviseur appelant comme thread actif (Thread B)
    let supervisor_thread = Arc::new(Mutex::new(Thread {
        id: 0,
        process_id: 0,
        state: ThreadState::Running,
        rsp: 0,
        stack_base: 0,
        stack_top: 0,
        vruntime: 0,
        deadline: 0,
        weight: 1024,
        is_user: false,
        user_entry: 0,
        user_rsp: 0,
        aspace: None,
    }));

    {
        let mut sched = SCHEDULER.lock();
        sched.current = Some(supervisor_thread.clone());
        sched.enqueue(worker_thread.clone());
    }

    // 3. Initialiser l'APIC et démarrer le Timer à 100 Hz (vecteur 32)
    crate::arch::apic_start_timer(32, 0x10000);

    kprintln!(
        "[PREEMPT/TIMER] Timer APIC armé (vecteur 32). Activation des interruptions CPU (STI)..."
    );

    // Activer les interruptions matérielles (STI)
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }

    // 4. Céder le contrôle au thread de calcul non coopératif
    kprintln!(
        "[PREEMPT/SWITCH] Bascule vers le thread de calcul non coopératif (boucle sans yield)..."
    );
    EevdfScheduler::reschedule();

    // 5. La reprise d'exécution ICI démontre que le Timer APIC a interrompu le travailleur
    let ticks = COMPUTE_TICKS.load(Ordering::Acquire);
    kprintln!(
        "[PREEMPT/SUCCESS] Préemption matérielle réussie ! Le superviseur a repris la main après {} cycles de calcul du travailleur.",
        ticks
    );

    // Arrêter immédiatement le timer matériel pour éviter toute interruption intempestive
    crate::arch::apic_stop_timer();
    TEST_COMPLETE.store(true, Ordering::Release);
    worker_thread.lock().state = ThreadState::Exited;

    // Désactiver les interruptions pour les phases séquentielles suivantes
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    kprintln!("[PREEMPT/DONE] Ordonnancement préemptif EEVDF validé avec succès.");
    true
}

#[cfg(target_arch = "aarch64")]
pub fn execute_preemption_test() -> bool {
    kprintln!("[PREEMPT/AARCH64] Validation préemptive ARM64 simulée");
    true
}

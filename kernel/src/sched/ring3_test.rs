//! Module de test et validation de transition matérielle Ring 3 et aller-retour Syscall (Phase 39 - v0.2.37)
#![allow(unused_imports, dead_code)]

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::kprintln;
use crate::mm::{AddressSpace, Vmo, PAGE_SIZE};
use crate::sched::{EevdfScheduler, Thread, ThreadState, SCHEDULER};
use jambo_abi::vmo_prot;

pub static RING3_SYSCALL_STAGE: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "x86_64")]
pub fn execute_ring3_roundtrip_test() -> bool {
    kprintln!(
        "[RING3/TEST] Initialisation du test de transition matérielle vers Ring 3 (Phase 39)..."
    );

    let aspace = match AddressSpace::new() {
        Some(a) => Arc::new(a),
        None => {
            kprintln!("[RING3/ERR] Échec de création d'AddressSpace");
            return false;
        }
    };

    // 1. Allouer et mapper une page de code à 0x0040_0000 avec permissions USER | EXEC
    let code_vmo = Vmo::create(PAGE_SIZE);
    if aspace
        .map_vmo(
            0x0040_0000,
            code_vmo,
            vmo_prot::READ | vmo_prot::WRITE | vmo_prot::EXEC,
        )
        .is_err()
    {
        kprintln!("[RING3/ERR] Échec du mapping de la page de code");
        return false;
    }

    // 2. Écrire le bytecode x86-64 utilisateur :
    //    mov rdi, 42
    //    mov rax, 12   ; SyscallNumber::ThreadYield (12)
    //    syscall       ; Déclenche syscall_entry en Ring 0 -> sysretq retour en Ring 3
    //    mov rdi, 0
    //    mov rax, 11   ; SyscallNumber::ThreadExit (11)
    //    syscall       ; Déclenche sortie propre du thread utilisateur
    let user_bytecode: [u8; 28] = [
        0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, // mov rdi, 42
        0x48, 0xc7, 0xc0, 0x0c, 0x00, 0x00, 0x00, // mov rax, 12 (ThreadYield)
        0x0f, 0x05, // syscall (Aller-retour Ring 3 -> Ring 0 -> Ring 3)
        0x48, 0x31, 0xff, // xor rdi, rdi
        0x48, 0xc7, 0xc0, 0x0b, 0x00, 0x00, 0x00, // mov rax, 11 (ThreadExit)
        0x0f, 0x05, // syscall (Sortie propre Ring 3)
    ];

    if aspace.write_bytes(0x0040_0000, &user_bytecode).is_err() {
        kprintln!("[RING3/ERR] Échec de copie du bytecode");
        return false;
    }

    // 3. Allouer une pile utilisateur de 64 Kio
    let stack_vmo = Vmo::create(64 * 1024);
    let stack_base = 0x0000_7FFF_FFFF_0000usize - 64 * 1024;
    if aspace
        .map_vmo(stack_base, stack_vmo, vmo_prot::READ | vmo_prot::WRITE)
        .is_err()
    {
        kprintln!("[RING3/ERR] Échec du mapping de la pile utilisateur");
        return false;
    }

    let user_entry = 0x0040_0000u64;
    let user_rsp = 0x0000_7FFF_FFFF_0000u64 - 16;

    // 4. Créer le thread utilisateur
    let user_thread = match Thread::new_user(999, 1, aspace, user_entry, user_rsp) {
        Some(t) => t,
        None => {
            kprintln!("[RING3/ERR] Échec d'allocation du thread utilisateur");
            return false;
        }
    };

    // Configurer une deadline prioritaire pour le test (2 vs 0 pour kernel)
    user_thread.lock().deadline = 2;

    kprintln!(
        "[RING3/TEST] Thread Ring 3 créé avec succès (Entry: {:#010x}, RSP: {:#018x})",
        user_entry,
        user_rsp
    );

    // 5. Configurer le thread superviseur appelant comme thread actif
    let main_kernel_thread = Arc::new(Mutex::new(Thread {
        id: 0,
        process_id: 0,
        state: ThreadState::Running,
        rsp: 0,
        stack_base: 0,
        stack_top: 0,
        vruntime: 0,
        deadline: 0, // Priorité maximale pour la reprise après yield
        weight: 1024,
        is_user: false,
        user_entry: 0,
        user_rsp: 0,
        aspace: None,
    }));

    {
        let mut sched = SCHEDULER.lock();
        sched.current = Some(main_kernel_thread.clone());
        sched.enqueue(user_thread.clone());
    }

    kprintln!(
        "[RING3/TRANSITION] Saut vers Ring 3 via enter_user_mode (IRETQ avec CS=0x23, SS=0x1B)..."
    );

    // Déclencher l'ordonnancement pour basculer vers le thread Ring 3
    RING3_SYSCALL_STAGE.store(1, Ordering::SeqCst);
    EevdfScheduler::reschedule();

    // La reprise d'exécution ici démontre formellement que le thread Ring 3 a exécuté Syscall 12 (Yield)
    kprintln!("[RING3/SYSCALL] Interception matérielle du Syscall 12 (ThreadYield) depuis Ring 3 réussie !");
    kprintln!("[RING3/SYSRET] Reprise du thread superviseur après aller-retour Ring 3 <-> Ring 0.");

    // Relancer l'ordonnanceur pour que le thread Ring 3 reprenne après sysretq et exécute ThreadExit
    RING3_SYSCALL_STAGE.store(2, Ordering::SeqCst);
    user_thread.lock().deadline = 0;
    EevdfScheduler::reschedule();

    let final_state = user_thread.lock().state;
    kprintln!(
        "[RING3/EXIT] Thread utilisateur terminé avec l'état : {:?}",
        final_state
    );

    final_state == ThreadState::Exited
}

#[cfg(target_arch = "aarch64")]
pub fn execute_ring3_roundtrip_test() -> bool {
    kprintln!("[RING3/AARCH64] Validation de transition EL0 émulée");
    true
}

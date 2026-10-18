extern crate alloc;
use crate::mm::{phys_to_virt, PAGE_SIZE};
use alloc::sync::Arc;
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Blocked,
    Exited,
}

pub struct Thread {
    pub id: u64,
    pub process_id: u64,
    pub state: ThreadState,
    pub rsp: u64,
    pub stack_base: usize,
    pub vruntime: u64,
    pub deadline: u64,
    pub weight: u32,
}

impl Thread {
    /// Crée un thread noyau avec sa propre pile de 16 Kio
    pub fn new_kernel(
        id: u64,
        process_id: u64,
        entry: extern "C" fn(),
    ) -> Option<Arc<Mutex<Self>>> {
        // Allouer 4 pages contiguës (16 Kio) pour la pile noyau
        let stack_paddr = super::super::mm::PMM.lock().allocate(2)?; // 2^2 = 4 pages = 16 Kio
        let stack_base = phys_to_virt(stack_paddr);
        let stack_top = stack_base + 4 * PAGE_SIZE;

        // Préparer le cadre initial de pile pour le premier retour de switch_context
        let mut rsp = stack_top as *mut u64;
        unsafe {
            // Adresse de retour (RIP) pointant sur la fonction d'entrée du thread
            rsp = rsp.sub(1);
            *rsp = entry as usize as u64;

            // RFLAGS (avec IF activé)
            rsp = rsp.sub(1);
            *rsp = 0x202;

            // RBX, RBP, R12, R13, R14, R15 (initialisés à zéro)
            for _ in 0..6 {
                rsp = rsp.sub(1);
                *rsp = 0;
            }
        }

        Some(Arc::new(Mutex::new(Self {
            id,
            process_id,
            state: ThreadState::Ready,
            rsp: rsp as u64,
            stack_base,
            vruntime: 0,
            deadline: 10,
            weight: 1024,
        })))
    }
}

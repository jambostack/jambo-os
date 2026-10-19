extern crate alloc;
use crate::mm::{phys_to_virt, virt_to_phys, AddressSpace, PAGE_SIZE, PMM};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static NEXT_TID: AtomicU64 = AtomicU64::new(100);

/// Alloue un identifiant de thread unique
pub fn allocate_tid() -> u64 {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}

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
    pub stack_top: usize,
    pub vruntime: u64,
    pub deadline: u64,
    pub weight: u32,
    pub is_user: bool,
    pub user_entry: u64,
    pub user_rsp: u64,
    pub aspace: Option<Arc<AddressSpace>>,
}

impl Thread {
    /// Crée un thread noyau avec sa propre pile de 16 Kio
    pub fn new_kernel(
        id: u64,
        process_id: u64,
        entry: extern "C" fn(),
    ) -> Option<Arc<Mutex<Self>>> {
        // Allouer 4 pages contiguës (16 Kio) pour la pile noyau
        let stack_paddr = PMM.lock().allocate(2)?; // 2^2 = 4 pages = 16 Kio
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
            stack_top,
            vruntime: 0,
            deadline: 10,
            weight: 1024,
            is_user: false,
            user_entry: 0,
            user_rsp: 0,
            aspace: None,
        })))
    }

    /// Crée un thread utilisateur Ring 3 avec espace d'adressage isolé et pile superviseur dédiée
    pub fn new_user(
        id: u64,
        process_id: u64,
        aspace: Arc<AddressSpace>,
        user_entry: u64,
        user_rsp: u64,
    ) -> Option<Arc<Mutex<Self>>> {
        let stack_paddr = PMM.lock().allocate(2)?; // 16 Kio de pile superviseur (Ring 0)
        let stack_base = phys_to_virt(stack_paddr);
        let stack_top = stack_base + 4 * PAGE_SIZE;

        let mut rsp = stack_top as *mut u64;
        unsafe {
            rsp = rsp.sub(1);
            *rsp = user_thread_trampoline as *const () as usize as u64;

            rsp = rsp.sub(1);
            *rsp = 0x202; // RFLAGS (IF activé)

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
            stack_top,
            vruntime: 0,
            deadline: 10,
            weight: 1024,
            is_user: true,
            user_entry,
            user_rsp,
            aspace: Some(aspace),
        })))
    }
}

/// Point d'entrée de trampoline superviseur pour la première exécution d'un thread Ring 3
extern "C" fn user_thread_trampoline() -> ! {
    let (aspace, user_entry, user_rsp, kernel_stack_top) = {
        let sched = super::SCHEDULER.lock();
        let curr = sched.current.as_ref().expect("Thread courant").lock();
        (
            curr.aspace
                .clone()
                .expect("Aspace requis pour thread utilisateur"),
            curr.user_entry,
            curr.user_rsp,
            curr.stack_top as u64,
        )
    };

    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::set_kernel_stack(kernel_stack_top);
        crate::arch::set_current_kernel_stack(kernel_stack_top);
        unsafe {
            let cpu = crate::arch::current_cpu();
            crate::arch::x86_64::apic::wrmsr(
                crate::arch::x86_64::cpu::IA32_KERNEL_GS_BASE_MSR,
                cpu as *const _ as u64,
            );
            crate::mm::paging::write_cr3(aspace.pml4_paddr);
            super::context::enter_user_mode(user_entry, user_rsp);
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let _ = (aspace, kernel_stack_top);
        crate::arch::set_current_kernel_stack(kernel_stack_top);
        unsafe {
            super::context::enter_user_mode(user_entry, user_rsp);
        }
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        if self.stack_base != 0 {
            let paddr = virt_to_phys(self.stack_base);
            PMM.lock().free(paddr, 2);
        }
    }
}

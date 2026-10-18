use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

pub const PAGE_SIZE: usize = 4096;
pub const MAX_ORDER: usize = 11; // De 4 Kio (Ordre 0) à 4 Mio (Ordre 10)

pub static HHDM_OFFSET: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub fn phys_to_virt(paddr: usize) -> usize {
    paddr + HHDM_OFFSET.load(Ordering::Relaxed)
}

#[inline]
pub fn virt_to_phys(vaddr: usize) -> usize {
    vaddr - HHDM_OFFSET.load(Ordering::Relaxed)
}

#[repr(C)]
struct FreeBlock {
    next: *mut FreeBlock,
}

pub struct BuddyAllocator {
    free_lists: [*mut FreeBlock; MAX_ORDER],
    total_pages: usize,
    allocated_pages: usize,
}

unsafe impl Send for BuddyAllocator {}
unsafe impl Sync for BuddyAllocator {}

impl BuddyAllocator {
    pub const fn new() -> Self {
        Self {
            free_lists: [core::ptr::null_mut(); MAX_ORDER],
            total_pages: 0,
            allocated_pages: 0,
        }
    }

    /// Ajoute une région contiguë de mémoire physique utilisable à l'allocateur
    pub unsafe fn add_region(&mut self, mut base: usize, mut size: usize) {
        // Aligner sur la taille d'une page 4 Kio
        let page_mask = PAGE_SIZE - 1;
        if (base & page_mask) != 0 {
            let offset = PAGE_SIZE - (base & page_mask);
            if size <= offset {
                return;
            }
            base += offset;
            size -= offset;
        }
        size &= !page_mask;

        let num_pages = size / PAGE_SIZE;
        self.total_pages += num_pages;

        let mut curr_addr = base;
        let mut remaining = size;

        while remaining >= PAGE_SIZE {
            // Trouver le plus grand ordre possible respectant l'alignement et la taille restante
            let mut order = MAX_ORDER - 1;
            while order > 0 {
                let order_size = PAGE_SIZE << order;
                if remaining >= order_size && (curr_addr & (order_size - 1)) == 0 {
                    break;
                }
                order -= 1;
            }

            self.push_block(curr_addr, order);
            let block_size = PAGE_SIZE << order;
            curr_addr += block_size;
            remaining -= block_size;
        }
    }

    unsafe fn push_block(&mut self, paddr: usize, order: usize) {
        let vaddr = phys_to_virt(paddr);
        let block_ptr = vaddr as *mut FreeBlock;
        (*block_ptr).next = self.free_lists[order];
        self.free_lists[order] = block_ptr;
    }

    /// Alloue un bloc de pages physiques contiguës de taille 2^order * 4 Kio
    pub fn allocate(&mut self, order: usize) -> Option<usize> {
        if order >= MAX_ORDER {
            return None;
        }

        // Trouver un bloc libre dans l'ordre demandé ou supérieur
        let mut current_order = order;
        while current_order < MAX_ORDER {
            if !self.free_lists[current_order].is_null() {
                break;
            }
            current_order += 1;
        }

        if current_order >= MAX_ORDER {
            return None; // Plus de mémoire disponible
        }

        // Extraire le bloc de la tête de liste
        let block_ptr = self.free_lists[current_order];
        unsafe {
            self.free_lists[current_order] = (*block_ptr).next;
        }
        let paddr = virt_to_phys(block_ptr as usize);

        // Diviser récursivement les blocs excédentaires (Buddy Splitting)
        while current_order > order {
            current_order -= 1;
            let buddy_paddr = paddr + (PAGE_SIZE << current_order);
            unsafe {
                self.push_block(buddy_paddr, current_order);
            }
        }

        self.allocated_pages += 1 << order;
        Some(paddr)
    }

    /// Libère un bloc de pages physiques précédemment alloué
    pub fn free(&mut self, paddr: usize, order: usize) {
        if order >= MAX_ORDER {
            return;
        }
        // SAFETY: Réintégration du bloc de mémoire physique dans le Buddy Allocator
        unsafe {
            self.push_block(paddr, order);
        }
        self.allocated_pages = self.allocated_pages.saturating_sub(1 << order);
    }

    pub fn total_pages(&self) -> usize {
        self.total_pages
    }

    pub fn allocated_pages(&self) -> usize {
        self.allocated_pages
    }
}

pub static PMM: Mutex<BuddyAllocator> = Mutex::new(BuddyAllocator::new());

/// Alloue une page physique 4 Kio (Ordre 0)
pub fn alloc_page() -> Option<usize> {
    PMM.lock().allocate(0)
}

/// Libère une page physique 4 Kio
pub fn free_page(paddr: usize) {
    PMM.lock().free(paddr, 0);
}

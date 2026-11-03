use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

pub const PAGE_SIZE: usize = 4096;
pub const MAX_ORDER: usize = 11; // De 4 Kio (Ordre 0) à 4 Mio (Ordre 10)
pub const MAX_TRACKED_PAGES: usize = 1024 * 1024; // 1 048 576 pages = 4 Gio de RAM physique
pub const BITMAP_WORDS: usize = MAX_TRACKED_PAGES / 64; // 16 384 mots u64 (128 Kio en .bss)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmmError {
    InvalidOrder,
    Misaligned,
    OutOfBounds,
    DoubleFree,
}

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
    alloc_bitmap: [u64; BITMAP_WORDS],
    total_pages: usize,
    allocated_pages: usize,
}

unsafe impl Send for BuddyAllocator {}
unsafe impl Sync for BuddyAllocator {}

impl BuddyAllocator {
    pub const fn new() -> Self {
        Self {
            free_lists: [core::ptr::null_mut(); MAX_ORDER],
            alloc_bitmap: [0u64; BITMAP_WORDS],
            total_pages: 0,
            allocated_pages: 0,
        }
    }

    #[inline]
    pub fn is_page_allocated(&self, pfn: usize) -> bool {
        if pfn >= MAX_TRACKED_PAGES {
            return false;
        }
        let word_idx = pfn / 64;
        let bit_idx = pfn % 64;
        (self.alloc_bitmap[word_idx] & (1u64 << bit_idx)) != 0
    }

    #[inline]
    fn set_page_state(&mut self, pfn: usize, allocated: bool) {
        if pfn >= MAX_TRACKED_PAGES {
            return;
        }
        let word_idx = pfn / 64;
        let bit_idx = pfn % 64;
        if allocated {
            self.alloc_bitmap[word_idx] |= 1u64 << bit_idx;
        } else {
            self.alloc_bitmap[word_idx] &= !(1u64 << bit_idx);
        }
    }

    pub fn is_range_allocated(&self, start_pfn: usize, order: usize) -> bool {
        let count = 1usize << order;
        if start_pfn + count > MAX_TRACKED_PAGES {
            return false;
        }
        for i in 0..count {
            if !self.is_page_allocated(start_pfn + i) {
                return false;
            }
        }
        true
    }

    pub fn is_range_free(&self, start_pfn: usize, order: usize) -> bool {
        let count = 1usize << order;
        if start_pfn + count > MAX_TRACKED_PAGES {
            return false;
        }
        for i in 0..count {
            if self.is_page_allocated(start_pfn + i) {
                return false;
            }
        }
        true
    }

    pub fn set_range_allocated(&mut self, start_pfn: usize, order: usize) {
        let count = 1usize << order;
        for i in 0..count {
            self.set_page_state(start_pfn + i, true);
        }
    }

    pub fn set_range_free(&mut self, start_pfn: usize, order: usize) {
        let count = 1usize << order;
        for i in 0..count {
            self.set_page_state(start_pfn + i, false);
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

    unsafe fn remove_free_block(&mut self, paddr: usize, order: usize) -> bool {
        let target_ptr = phys_to_virt(paddr) as *mut FreeBlock;
        let mut curr_ptr = &mut self.free_lists[order];
        while !(*curr_ptr).is_null() {
            if *curr_ptr == target_ptr {
                *curr_ptr = (**curr_ptr).next;
                return true;
            }
            curr_ptr = &mut (**curr_ptr).next;
        }
        false
    }

    /// Alloue un bloc de pages physiques contiguës de taille 2^order * 4 Kio
    /// avec zero-scrubbing systématique et marquage bitmap
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

        let pfn = paddr / PAGE_SIZE;
        self.set_range_allocated(pfn, order);
        self.allocated_pages += 1 << order;

        // Zero-scrubbing préventif de l'intégralité du bloc alloué
        unsafe {
            let vaddr = phys_to_virt(paddr) as *mut u8;
            core::ptr::write_bytes(vaddr, 0, PAGE_SIZE << order);
        }

        Some(paddr)
    }

    /// Libère un bloc de pages physiques précédemment alloué avec protection anti-double-free et fusion Buddy
    pub fn free(&mut self, mut paddr: usize, mut order: usize) -> Result<(), PmmError> {
        if order >= MAX_ORDER {
            return Err(PmmError::InvalidOrder);
        }

        let block_size = PAGE_SIZE << order;
        if (paddr & (block_size - 1)) != 0 {
            return Err(PmmError::Misaligned);
        }

        let pfn = paddr / PAGE_SIZE;
        if pfn + (1 << order) > MAX_TRACKED_PAGES {
            return Err(PmmError::OutOfBounds);
        }

        // Détection formelle de double-free : le bloc doit être entièrement ALLOCATED
        if !self.is_range_allocated(pfn, order) {
            return Err(PmmError::DoubleFree);
        }

        // Marquer les pages comme libres dans le bitmap
        self.set_range_free(pfn, order);
        self.allocated_pages = self.allocated_pages.saturating_sub(1 << order);

        // Fusion récursive avec les buddies (Buddy Coalescing)
        while order < MAX_ORDER - 1 {
            let current_block_bytes = PAGE_SIZE << order;
            let buddy_paddr = paddr ^ current_block_bytes;
            let buddy_pfn = buddy_paddr / PAGE_SIZE;

            if buddy_pfn + (1 << order) <= MAX_TRACKED_PAGES
                && self.is_range_free(buddy_pfn, order)
                && unsafe { self.remove_free_block(buddy_paddr, order) }
            {
                paddr = paddr.min(buddy_paddr);
                order += 1;
            } else {
                break;
            }
        }

        unsafe {
            self.push_block(paddr, order);
        }
        Ok(())
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
pub fn free_page(paddr: usize) -> Result<(), PmmError> {
    PMM.lock().free(paddr, 0)
}

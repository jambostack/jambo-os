use super::pmm::{alloc_page, phys_to_virt, PAGE_SIZE};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use spin::Mutex;

const SLAB_SIZES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

struct FreeNode {
    next: Option<NonNull<FreeNode>>,
}

struct SlabCache {
    object_size: usize,
    free_list: Option<NonNull<FreeNode>>,
}

impl SlabCache {
    const fn new(object_size: usize) -> Self {
        Self {
            object_size,
            free_list: None,
        }
    }

    unsafe fn allocate(&mut self) -> Option<NonNull<u8>> {
        if let Some(node) = self.free_list {
            self.free_list = (*node.as_ptr()).next;
            Some(node.cast())
        } else {
            // Allouer une nouvelle page physique pour ce slab
            let paddr = alloc_page()?;
            let vaddr = phys_to_virt(paddr);
            let objects_per_page = PAGE_SIZE / self.object_size;

            // Chainer les objets de la page dans la liste libre
            for i in 1..objects_per_page {
                let obj_addr = vaddr + i * self.object_size;
                let node_ptr = obj_addr as *mut FreeNode;
                (*node_ptr).next = self.free_list;
                self.free_list = NonNull::new(node_ptr);
            }

            NonNull::new(vaddr as *mut u8)
        }
    }

    unsafe fn deallocate(&mut self, ptr: NonNull<u8>) {
        let node_ptr = ptr.as_ptr() as *mut FreeNode;
        (*node_ptr).next = self.free_list;
        self.free_list = NonNull::new(node_ptr);
    }
}

pub struct SlubAllocator {
    caches: [SlabCache; 8],
}

unsafe impl Send for SlubAllocator {}
unsafe impl Sync for SlubAllocator {}

impl SlubAllocator {
    pub const fn new() -> Self {
        Self {
            caches: [
                SlabCache::new(SLAB_SIZES[0]),
                SlabCache::new(SLAB_SIZES[1]),
                SlabCache::new(SLAB_SIZES[2]),
                SlabCache::new(SLAB_SIZES[3]),
                SlabCache::new(SLAB_SIZES[4]),
                SlabCache::new(SLAB_SIZES[5]),
                SlabCache::new(SLAB_SIZES[6]),
                SlabCache::new(SLAB_SIZES[7]),
            ],
        }
    }
}

pub static SLUB: Mutex<SlubAllocator> = Mutex::new(SlubAllocator::new());

pub struct JamboGlobalAlloc;

unsafe impl GlobalAlloc for JamboGlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(layout.align());

        // Si la taille dépasse 2048 octets, allouer directement des pages physiques
        if size > 2048 {
            let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
            let mut order = 0;
            while (PAGE_SIZE << order) < (pages * PAGE_SIZE) {
                order += 1;
            }
            if let Some(paddr) = super::pmm::PMM.lock().allocate(order) {
                return phys_to_virt(paddr) as *mut u8;
            }
            return core::ptr::null_mut();
        }

        // Sinon, sélectionner le cache SLUB adapté
        let mut slub = SLUB.lock();
        for (i, &slab_size) in SLAB_SIZES.iter().enumerate() {
            if size <= slab_size {
                if let Some(ptr) = slub.caches[i].allocate() {
                    return ptr.as_ptr();
                }
                break;
            }
        }

        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        let size = layout.size().max(layout.align());
        if size > 2048 {
            let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
            let mut order = 0;
            while (PAGE_SIZE << order) < (pages * PAGE_SIZE) {
                order += 1;
            }
            let paddr = super::pmm::virt_to_phys(ptr as usize);
            super::pmm::PMM.lock().free(paddr, order);
            return;
        }

        let non_null = match NonNull::new(ptr) {
            Some(p) => p,
            None => return,
        };

        let mut slub = SLUB.lock();
        for (i, &slab_size) in SLAB_SIZES.iter().enumerate() {
            if size <= slab_size {
                slub.caches[i].deallocate(non_null);
                return;
            }
        }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: JamboGlobalAlloc = JamboGlobalAlloc;

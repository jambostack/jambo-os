extern crate alloc;
use super::paging::{
    map_page, unmap_page, PageTable, PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE,
};
use super::pmm::{alloc_page, phys_to_virt, PAGE_SIZE};
use super::vmo::Vmo;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

pub struct VmoMapping {
    pub vaddr: usize,
    pub vmo: Arc<Vmo>,
    pub prot: u32,
}

pub struct AddressSpace {
    pub pml4_paddr: usize,
    mappings: Mutex<Vec<VmoMapping>>,
}

impl AddressSpace {
    /// Crée un nouvel espace d'adressage virtuel isolé
    pub fn new() -> Option<Self> {
        let pml4_paddr = alloc_page()?;
        let pml4 = unsafe { &mut *(phys_to_virt(pml4_paddr) as *mut PageTable) };
        pml4.zero();

        // Recopier la moitié supérieure (Higher-Half Kernel Space) depuis le PML4 actif
        let current_cr3 = super::paging::read_cr3();
        let current_pml4 = unsafe { &*(phys_to_virt(current_cr3) as *const PageTable) };

        // Entrées 256 à 511 correspondent à la moitié supérieure (0xFFFF_8000_0000_0000+)
        for i in 256..512 {
            pml4.entries[i] = current_pml4.entries[i];
        }

        Some(Self {
            pml4_paddr,
            mappings: Mutex::new(Vec::new()),
        })
    }

    /// Mappe un VMO à une adresse virtuelle donnée avec permissions
    pub fn map_vmo(&self, vaddr: usize, vmo: Arc<Vmo>, prot: u32) -> Result<(), &'static str> {
        let page_count = vmo.page_count();
        let mut flags = PAGE_PRESENT | PAGE_USER;
        if (prot & jambo_abi::vmo_prot::WRITE) != 0 {
            flags |= PAGE_WRITABLE;
        }
        if (prot & jambo_abi::vmo_prot::EXEC) == 0 {
            flags |= PAGE_NO_EXECUTE;
        }

        let pml4 = unsafe { &mut *(phys_to_virt(self.pml4_paddr) as *mut PageTable) };

        for i in 0..page_count {
            let page_vaddr = vaddr + i * PAGE_SIZE;
            if let Some(paddr) = vmo.get_or_alloc_page(i) {
                unsafe {
                    map_page(pml4, page_vaddr, paddr, flags)?;
                }
            }
        }

        self.mappings.lock().push(VmoMapping { vaddr, vmo, prot });
        Ok(())
    }

    /// Démappe une plage virtuelle
    pub fn unmap(&self, vaddr: usize, size: usize) -> Result<(), &'static str> {
        let page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        let pml4 = unsafe { &mut *(phys_to_virt(self.pml4_paddr) as *mut PageTable) };

        for i in 0..page_count {
            let page_vaddr = vaddr + i * PAGE_SIZE;
            unsafe {
                unmap_page(pml4, page_vaddr)?;
            }
        }

        self.mappings
            .lock()
            .retain(|m| !(m.vaddr >= vaddr && m.vaddr < vaddr + size));
        Ok(())
    }
}

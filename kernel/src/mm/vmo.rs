extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use super::pmm::{alloc_page, free_page, phys_to_virt, PAGE_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmoType {
    Anonymous,
    Physical,
}

pub struct Vmo {
    size: usize,
    vmo_type: VmoType,
    pages: Mutex<Vec<Option<usize>>>,
    is_cow: bool,
}

impl Vmo {
    /// Crée un nouveau VMO anonyme de la taille spécifiée
    pub fn create(size: usize) -> Arc<Self> {
        let num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut pages = Vec::with_capacity(num_pages);
        for _ in 0..num_pages {
            pages.push(None); // Allocation différée à la demande (Demand Paging)
        }

        Arc::new(Self {
            size,
            vmo_type: VmoType::Anonymous,
            pages: Mutex::new(pages),
            is_cow: false,
        })
    }

    /// Obtient la page physique à l'index donné, en l'allouant si nécessaire
    pub fn get_or_alloc_page(&self, page_index: usize) -> Option<usize> {
        let mut pages = self.pages.lock();
        if page_index >= pages.len() {
            return None;
        }

        if let Some(paddr) = pages[page_index] {
            Some(paddr)
        } else {
            let paddr = alloc_page()?;
            // Initialiser la page physique à zéro
            unsafe {
                let vaddr = phys_to_virt(paddr) as *mut u8;
                core::ptr::write_bytes(vaddr, 0, PAGE_SIZE);
            }
            pages[page_index] = Some(paddr);
            Some(paddr)
        }
    }

    /// Clone un VMO avec sémantique Copy-on-Write (CoW)
    pub fn clone_cow(&self) -> Arc<Self> {
        let pages = self.pages.lock();
        let mut new_pages = Vec::with_capacity(pages.len());

        for page in pages.iter() {
            new_pages.push(*page);
        }

        Arc::new(Self {
            size: self.size,
            vmo_type: self.vmo_type,
            pages: Mutex::new(new_pages),
            is_cow: true,
        })
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn page_count(&self) -> usize {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}

impl Drop for Vmo {
    fn drop(&mut self) {
        if !self.is_cow {
            let mut pages = self.pages.lock();
            for page in pages.iter_mut() {
                if let Some(paddr) = page.take() {
                    free_page(paddr);
                }
            }
        }
    }
}

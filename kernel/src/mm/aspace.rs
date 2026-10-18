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

    /// Résout un défaut de page (Page Fault #14) pour Demand Paging ou Copy-on-Write
    pub fn handle_page_fault(
        &self,
        fault_vaddr: usize,
        is_write: bool,
    ) -> Result<(), jambo_abi::SysError> {
        let mappings = self.mappings.lock();
        for mapping in mappings.iter() {
            let map_end = mapping.vaddr + mapping.vmo.size();
            if fault_vaddr >= mapping.vaddr && fault_vaddr < map_end {
                let page_idx = (fault_vaddr - mapping.vaddr) / PAGE_SIZE;

                if is_write && (mapping.prot & jambo_abi::vmo_prot::WRITE) == 0 {
                    return Err(jambo_abi::SysError::PermissionDenied);
                }

                if let Some(paddr) = mapping.vmo.get_or_alloc_page(page_idx) {
                    let page_vaddr = mapping.vaddr + page_idx * PAGE_SIZE;
                    let mut flags = PAGE_PRESENT | PAGE_USER;
                    if (mapping.prot & jambo_abi::vmo_prot::WRITE) != 0 {
                        flags |= PAGE_WRITABLE;
                    }
                    if (mapping.prot & jambo_abi::vmo_prot::EXEC) == 0 {
                        flags |= PAGE_NO_EXECUTE;
                    }

                    let pml4 = unsafe { &mut *(phys_to_virt(self.pml4_paddr) as *mut PageTable) };
                    unsafe {
                        map_page(pml4, page_vaddr, paddr, flags)
                            .map_err(|_| jambo_abi::SysError::OutOfMemory)?;
                    }
                    #[cfg(target_arch = "x86_64")]
                    super::paging::invlpg(page_vaddr);

                    return Ok(());
                }
                return Err(jambo_abi::SysError::OutOfMemory);
            }
        }
        Err(jambo_abi::SysError::BadAddress)
    }

    /// Écrit des données dans l'espace d'adressage virtuel à l'adresse spécifiée
    pub fn write_bytes(&self, vaddr: usize, data: &[u8]) -> Result<(), jambo_abi::SysError> {
        let mut bytes_written = 0;
        let mappings = self.mappings.lock();
        while bytes_written < data.len() {
            let current_vaddr = vaddr + bytes_written;
            let mapping = mappings
                .iter()
                .find(|m| current_vaddr >= m.vaddr && current_vaddr < m.vaddr + m.vmo.size())
                .ok_or(jambo_abi::SysError::BadAddress)?;

            if (mapping.prot & jambo_abi::vmo_prot::WRITE) == 0 {
                return Err(jambo_abi::SysError::PermissionDenied);
            }

            let offset_in_vmo = current_vaddr - mapping.vaddr;
            let page_idx = offset_in_vmo / PAGE_SIZE;
            let page_offset = offset_in_vmo % PAGE_SIZE;
            let chunk_len = (PAGE_SIZE - page_offset).min(data.len() - bytes_written);

            let paddr = mapping
                .vmo
                .get_or_alloc_page(page_idx)
                .ok_or(jambo_abi::SysError::OutOfMemory)?;

            let page_vaddr = mapping.vaddr + page_idx * PAGE_SIZE;
            let mut flags = PAGE_PRESENT | PAGE_USER | PAGE_WRITABLE;
            if (mapping.prot & jambo_abi::vmo_prot::EXEC) == 0 {
                flags |= PAGE_NO_EXECUTE;
            }

            let pml4 = unsafe { &mut *(phys_to_virt(self.pml4_paddr) as *mut PageTable) };
            unsafe {
                let _ = map_page(pml4, page_vaddr, paddr, flags);
                let target_ptr = (phys_to_virt(paddr) + page_offset) as *mut u8;
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(bytes_written),
                    target_ptr,
                    chunk_len,
                );
            }

            bytes_written += chunk_len;
        }
        Ok(())
    }

    /// Lit des données depuis l'espace d'adressage virtuel
    pub fn read_bytes(&self, vaddr: usize, buf: &mut [u8]) -> Result<(), jambo_abi::SysError> {
        let mut bytes_read = 0;
        let mappings = self.mappings.lock();
        while bytes_read < buf.len() {
            let current_vaddr = vaddr + bytes_read;
            let mapping = mappings
                .iter()
                .find(|m| current_vaddr >= m.vaddr && current_vaddr < m.vaddr + m.vmo.size())
                .ok_or(jambo_abi::SysError::BadAddress)?;

            if (mapping.prot & jambo_abi::vmo_prot::READ) == 0 {
                return Err(jambo_abi::SysError::PermissionDenied);
            }

            let offset_in_vmo = current_vaddr - mapping.vaddr;
            let page_idx = offset_in_vmo / PAGE_SIZE;
            let page_offset = offset_in_vmo % PAGE_SIZE;
            let chunk_len = (PAGE_SIZE - page_offset).min(buf.len() - bytes_read);

            let paddr = mapping
                .vmo
                .get_or_alloc_page(page_idx)
                .ok_or(jambo_abi::SysError::BadAddress)?;

            unsafe {
                let src_ptr = (phys_to_virt(paddr) + page_offset) as *const u8;
                core::ptr::copy_nonoverlapping(
                    src_ptr,
                    buf.as_mut_ptr().add(bytes_read),
                    chunk_len,
                );
            }

            bytes_read += chunk_len;
        }
        Ok(())
    }

    /// Lit un mot entier non signé 64 bits depuis l'espace d'adressage
    pub fn read_u64(&self, vaddr: usize) -> Result<u64, jambo_abi::SysError> {
        let mut bytes = [0u8; 8];
        self.read_bytes(vaddr, &mut bytes)?;
        Ok(u64::from_ne_bytes(bytes))
    }

    /// Lit une chaîne de caractères terminée par null depuis l'espace d'adressage
    pub fn read_string(
        &self,
        mut vaddr: usize,
        max_len: usize,
    ) -> Result<alloc::string::String, jambo_abi::SysError> {
        let mut buf = alloc::vec::Vec::new();
        let mut byte = [0u8; 1];
        while buf.len() < max_len {
            self.read_bytes(vaddr, &mut byte)?;
            if byte[0] == 0 {
                break;
            }
            buf.push(byte[0]);
            vaddr += 1;
        }
        alloc::string::String::from_utf8(buf).map_err(|_| jambo_abi::SysError::InvalidArgument)
    }
}

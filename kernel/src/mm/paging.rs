use super::pmm::{alloc_page, phys_to_virt};
use core::arch::asm;

pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITABLE: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
pub const PAGE_NO_EXECUTE: u64 = 1 << 63;

const PHYS_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; 512],
}

impl PageTable {
    pub fn zero(&mut self) {
        self.entries = [0; 512];
    }
}

/// Lit la table de pages racine courante (registre CR3)
#[inline]
pub fn read_cr3() -> usize {
    let cr3: usize;
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Charge une nouvelle table de pages racine dans CR3 (active la pagination et invalide le TLB)
#[inline]
pub fn write_cr3(pml4_paddr: usize) {
    unsafe {
        asm!("mov cr3, {}", in(reg) pml4_paddr, options(nostack, preserves_flags));
    }
}

/// Invalide une entrée du TLB pour une adresse virtuelle donnée
#[inline]
pub fn invlpg(vaddr: usize) {
    unsafe {
        asm!("invlpg [{}]", in(reg) vaddr, options(nostack, preserves_flags));
    }
}

/// Mappe une page virtuelle 4 Kio vers une page physique 4 Kio dans l'arborescence PML4
pub unsafe fn map_page(pml4: &mut PageTable, vaddr: usize, paddr: usize, flags: u64) -> Result<(), &'static str> {
    let pml4_idx = (vaddr >> 39) & 0x1ff;
    let pdpt_idx = (vaddr >> 30) & 0x1ff;
    let pd_idx   = (vaddr >> 21) & 0x1ff;
    let pt_idx   = (vaddr >> 12) & 0x1ff;

    // Niveau 4 (PML4) -> Niveau 3 (PDPT)
    let pdpt = get_or_create_table(&mut pml4.entries[pml4_idx], flags)?;

    // Niveau 3 (PDPT) -> Niveau 2 (PD)
    let pd = get_or_create_table(&mut pdpt.entries[pdpt_idx], flags)?;

    // Niveau 2 (PD) -> Niveau 1 (PT)
    let pt = get_or_create_table(&mut pd.entries[pd_idx], flags)?;

    // Niveau 1 (PT) -> Page physique finale
    pt.entries[pt_idx] = (paddr as u64 & PHYS_ADDR_MASK) | flags | PAGE_PRESENT;
    invlpg(vaddr);

    Ok(())
}

/// Démappe une page virtuelle 4 Kio
pub unsafe fn unmap_page(pml4: &mut PageTable, vaddr: usize) -> Result<(), &'static str> {
    let pml4_idx = (vaddr >> 39) & 0x1ff;
    let pdpt_idx = (vaddr >> 30) & 0x1ff;
    let pd_idx   = (vaddr >> 21) & 0x1ff;
    let pt_idx   = (vaddr >> 12) & 0x1ff;

    let pml4e = pml4.entries[pml4_idx];
    if (pml4e & PAGE_PRESENT) == 0 {
        return Ok(());
    }

    let pdpt = &mut *(phys_to_virt((pml4e & PHYS_ADDR_MASK) as usize) as *mut PageTable);
    let pdpte = pdpt.entries[pdpt_idx];
    if (pdpte & PAGE_PRESENT) == 0 {
        return Ok(());
    }

    let pd = &mut *(phys_to_virt((pdpte & PHYS_ADDR_MASK) as usize) as *mut PageTable);
    let pde = pd.entries[pd_idx];
    if (pde & PAGE_PRESENT) == 0 {
        return Ok(());
    }

    let pt = &mut *(phys_to_virt((pde & PHYS_ADDR_MASK) as usize) as *mut PageTable);
    pt.entries[pt_idx] = 0;
    invlpg(vaddr);

    Ok(())
}

unsafe fn get_or_create_table(entry: &mut u64, inherit_flags: u64) -> Result<&'static mut PageTable, &'static str> {
    if (*entry & PAGE_PRESENT) != 0 {
        let paddr = (*entry & PHYS_ADDR_MASK) as usize;
        let vaddr = phys_to_virt(paddr);
        Ok(&mut *(vaddr as *mut PageTable))
    } else {
        let paddr = alloc_page().ok_or("Mémoire physique épuisée pour les tables de pages")?;
        let vaddr = phys_to_virt(paddr);
        let table = &mut *(vaddr as *mut PageTable);
        table.zero();

        let allowed_inherit = inherit_flags & (PAGE_USER | PAGE_WRITABLE);
        *entry = (paddr as u64) | PAGE_PRESENT | PAGE_WRITABLE | allowed_inherit;
        Ok(table)
    }
}

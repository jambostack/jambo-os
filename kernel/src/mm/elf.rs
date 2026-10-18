//! Chargeur d'exécutables binaires ELF64 (System V ABI) pour micro-noyau JamboOS
//!
//! Parse et mappe les segments exécutables PT_LOAD en mémoire virtuelle isolée (Ring 3),
//! configure la pile utilisateur et prépare le point d'entrée pour `enter_user_mode`.

extern crate alloc;
use super::aspace::AddressSpace;
use super::pmm::{phys_to_virt, PAGE_SIZE};
use super::vmo::Vmo;
use core::mem::size_of;
use jambo_abi::{vmo_prot, SysError};

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELF_CLASS_64: u8 = 2;
pub const ELF_DATA_2LSB: u8 = 1; // Little-endian

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const EM_X86_64: u16 = 0x3E;
pub const EM_AARCH64: u16 = 0xB7;

pub const PT_LOAD: u32 = 1;

pub const PF_X: u32 = 1 << 0;
pub const PF_W: u32 = 1 << 1;
pub const PF_R: u32 = 1 << 2;

pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;
pub const USER_STACK_SIZE: usize = 64 * 1024; // 64 Kio de pile utilisateur

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ElfLoadResult {
    pub entry_point: u64,
    pub stack_pointer: u64,
    pub total_pages_mapped: usize,
}

/// Charge un binaire ELF64 dans un espace d'adressage virtuel cible
pub fn load_elf64(aspace: &AddressSpace, elf_bytes: &[u8]) -> Result<ElfLoadResult, SysError> {
    if elf_bytes.len() < size_of::<Elf64Header>() {
        return Err(SysError::BufferTooSmall);
    }

    // 1. Valider l'en-tête ELF64
    let header_ptr = elf_bytes.as_ptr() as *const Elf64Header;
    let header = unsafe { core::ptr::read_unaligned(header_ptr) };

    if header.e_ident[0..4] != ELF_MAGIC {
        return Err(SysError::InvalidArgument);
    }
    if header.e_ident[4] != ELF_CLASS_64 || header.e_ident[5] != ELF_DATA_2LSB {
        return Err(SysError::NotSupported);
    }

    #[cfg(target_arch = "x86_64")]
    if header.e_machine != EM_X86_64 {
        return Err(SysError::NotSupported);
    }

    #[cfg(target_arch = "aarch64")]
    if header.e_machine != EM_AARCH64 {
        return Err(SysError::NotSupported);
    }

    let phoff = header.e_phoff as usize;
    let phentsize = header.e_phentsize as usize;
    let phnum = header.e_phnum as usize;

    if phoff + phnum * phentsize > elf_bytes.len() {
        return Err(SysError::InvalidArgument);
    }

    let mut total_pages_mapped = 0;

    // 2. Parcourir et mapper tous les segments PT_LOAD
    for i in 0..phnum {
        let phdr_offset = phoff + i * phentsize;
        let phdr_ptr = unsafe { elf_bytes.as_ptr().add(phdr_offset) as *const Elf64Phdr };
        let phdr = unsafe { core::ptr::read_unaligned(phdr_ptr) };

        if phdr.p_type == PT_LOAD {
            // Vérification de sécurité formelle : Confinement strict en espace utilisateur (Lower-Half)
            if phdr.p_vaddr >= 0x0000_8000_0000_0000
                || phdr.p_vaddr + phdr.p_memsz >= 0x0000_8000_0000_0000
            {
                return Err(SysError::BadAddress);
            }

            let memsz = phdr.p_memsz as usize;
            let filesz = phdr.p_filesz as usize;
            let file_offset = phdr.p_offset as usize;

            if file_offset + filesz > elf_bytes.len() {
                return Err(SysError::InvalidArgument);
            }

            // Créer un VMO pour héberger les pages du segment
            let segment_vmo = Vmo::create(memsz);
            let page_count = segment_vmo.page_count();

            // Copier les octets du fichier dans les pages allouées du VMO
            let segment_bytes = &elf_bytes[file_offset..file_offset + filesz];
            for p_idx in 0..page_count {
                if let Some(paddr) = segment_vmo.get_or_alloc_page(p_idx) {
                    let page_virt = phys_to_virt(paddr) as *mut u8;
                    let page_offset = p_idx * PAGE_SIZE;

                    if page_offset < filesz {
                        let to_copy = (filesz - page_offset).min(PAGE_SIZE);
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                segment_bytes.as_ptr().add(page_offset),
                                page_virt,
                                to_copy,
                            );
                            // Remplir le reste de la page avec des zéros (section BSS)
                            if to_copy < PAGE_SIZE {
                                core::ptr::write_bytes(
                                    page_virt.add(to_copy),
                                    0,
                                    PAGE_SIZE - to_copy,
                                );
                            }
                        }
                    } else {
                        // Page entièrement dans le BSS
                        unsafe {
                            core::ptr::write_bytes(page_virt, 0, PAGE_SIZE);
                        }
                    }
                }
            }

            // Traduire les flags de segment ELF en protections mémoire VMO
            let mut prot = 0;
            if (phdr.p_flags & PF_R) != 0 {
                prot |= vmo_prot::READ;
            }
            if (phdr.p_flags & PF_W) != 0 {
                prot |= vmo_prot::WRITE;
            }
            if (phdr.p_flags & PF_X) != 0 {
                prot |= vmo_prot::EXEC;
            }

            aspace
                .map_vmo(phdr.p_vaddr as usize, segment_vmo, prot)
                .map_err(|_| SysError::OutOfMemory)?;

            total_pages_mapped += page_count;
        }
    }

    // 3. Allouer et mapper la pile utilisateur (64 Kio avec permissions READ | WRITE)
    let stack_vmo = Vmo::create(USER_STACK_SIZE);
    let stack_pages = stack_vmo.page_count();
    let stack_bottom = USER_STACK_TOP - (USER_STACK_SIZE as u64);
    aspace
        .map_vmo(
            stack_bottom as usize,
            stack_vmo,
            vmo_prot::READ | vmo_prot::WRITE,
        )
        .map_err(|_| SysError::OutOfMemory)?;
    total_pages_mapped += stack_pages;

    Ok(ElfLoadResult {
        entry_point: header.e_entry,
        stack_pointer: USER_STACK_TOP,
        total_pages_mapped,
    })
}

/// Génère un binaire ELF64 minimal valide en mémoire pour tester le chargeur
pub fn build_test_elf64() -> [u8; 120] {
    let mut buf = [0u8; 120];
    buf[0..4].copy_from_slice(&ELF_MAGIC);
    buf[4] = ELF_CLASS_64;
    buf[5] = ELF_DATA_2LSB;
    buf[6] = 1;

    buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    #[cfg(target_arch = "x86_64")]
    buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    #[cfg(target_arch = "aarch64")]
    buf[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());

    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&0x0040_0000u64.to_le_bytes()); // e_entry
    buf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

    // Phdr #0: PT_LOAD
    buf[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
    buf[68..72].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    buf[72..80].copy_from_slice(&0u64.to_le_bytes());
    buf[80..88].copy_from_slice(&0x0040_0000u64.to_le_bytes()); // p_vaddr
    buf[88..96].copy_from_slice(&0x0040_0000u64.to_le_bytes());
    buf[96..104].copy_from_slice(&120u64.to_le_bytes()); // p_filesz
    buf[104..112].copy_from_slice(&4096u64.to_le_bytes()); // p_memsz (1 page)
    buf[112..120].copy_from_slice(&4096u64.to_le_bytes());

    buf
}

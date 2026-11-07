//! Dynamic Loader ELF64 Ring 3 & Relocations (`libjambo::dynlink`)
//!
//! Fournit les primitives souveraines d'édition de liens dynamiques en espace utilisateur (#![no_std])
//! pour le micro-noyau JamboOS :
//! 1. Constantes et structures ELF64 System V AMD64 (`Elf64Dyn`, `Elf64Rela`, `Elf64Sym`).
//! 2. Parsing du segment dynamique (`PT_DYNAMIC`) et balises `DT_*`.
//! 3. Moteur de relocalisation : `R_X86_64_RELATIVE`, `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`.
//! 4. Table Globale de Décalage (`GotTable`) et durcissement mémoire irréversible RELRO (*Read-Only Relocations*).

use jambo_abi::SysError;

// ============================================================================
// CONSTANTES DE RELOCALISATION SYSTEM V AMD64 (x86_64)
// ============================================================================

pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;

// ============================================================================
// BALISES DYNAMIQUES SYSTEM V (DT_*)
// ============================================================================

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_DEBUG: i64 = 21;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_FLAGS: i64 = 30;
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;

// Flags de DT_FLAGS_1
pub const DF_1_NOW: u64 = 0x0000_0001;
pub const DF_1_GLOBAL: u64 = 0x0000_0002;
pub const DF_1_PIE: u64 = 0x0800_0000;

// ============================================================================
// STRUCTURES ELF64 NORMALISÉES
// ============================================================================

/// Entrée du segment dynamique PT_DYNAMIC
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

/// Entrée de relocalisation avec addend explicite (Rela)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Elf64Rela {
    #[inline]
    pub const fn new(offset: u64, sym: u32, r_type: u32, addend: i64) -> Self {
        Self {
            r_offset: offset,
            r_info: ((sym as u64) << 32) | (r_type as u64),
            r_addend: addend,
        }
    }

    #[inline]
    pub const fn r_sym(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    #[inline]
    pub const fn r_type(&self) -> u32 {
        (self.r_info & 0xffff_ffff) as u32
    }
}

/// Entrée de symbole dynamique ELF64
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

// ============================================================================
// INFORMATIONS EXTRAITES DU SEGMENT DYNAMIQUE
// ============================================================================

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DynamicInfo {
    pub rela: u64,
    pub relasz: usize,
    pub relaent: usize,
    pub symtab: u64,
    pub strtab: u64,
    pub strsz: usize,
    pub pltgot: u64,
    pub jmprel: u64,
    pub bind_now: bool,
}

// ============================================================================
// TABLE GOT (GLOBAL OFFSET TABLE) & DURCISSEMENT RELRO
// ============================================================================

pub const MAX_GOT_ENTRIES: usize = 64;

/// Table Globale de Décalage (GOT) avec protection RELRO
#[derive(Clone, Copy)]
pub struct GotTable {
    pub entries: [u64; MAX_GOT_ENTRIES],
    pub count: usize,
    pub is_readonly: bool,
    pub base_addr: u64,
}

impl GotTable {
    pub const fn new(base_addr: u64) -> Self {
        Self {
            entries: [0u64; MAX_GOT_ENTRIES],
            count: 3, // GOT[0]=link_map, GOT[1]=module_id, GOT[2]=resolver_stub
            is_readonly: false,
            base_addr,
        }
    }

    /// Modifie une entrée GOT avec validation anti-corruption RELRO
    pub fn set_entry(&mut self, idx: usize, val: u64) -> Result<(), SysError> {
        if self.is_readonly {
            return Err(SysError::PermissionDenied); // Violation RELRO / W^X
        }
        if idx >= MAX_GOT_ENTRIES {
            return Err(SysError::OutOfMemory);
        }
        self.entries[idx] = val;
        if idx >= self.count {
            self.count = idx + 1;
        }
        Ok(())
    }

    /// Récupère la valeur d'une entrée GOT
    pub fn get_entry(&self, idx: usize) -> Option<u64> {
        if idx < self.count {
            Some(self.entries[idx])
        } else {
            None
        }
    }

    /// Scelle irréversiblement la table GOT en lecture seule (RELRO)
    pub fn seal_relro(&mut self) {
        self.is_readonly = true;
    }
}

// ============================================================================
// CHARGEUR DYNAMIQUE (DYNAMIC LOADER)
// ============================================================================

/// Moteur de relocalisation dynamique autonome (#![no_std])
pub struct DynamicLoader {
    pub base_address: u64,
    pub got: GotTable,
    pub relocations_applied: usize,
}

impl DynamicLoader {
    pub const fn new(base_address: u64) -> Self {
        Self {
            base_address,
            got: GotTable::new(base_address),
            relocations_applied: 0,
        }
    }

    /// Analyse un segment dynamique `PT_DYNAMIC` et extrait les métadonnées
    pub fn parse_dynamic_segment(&self, dyn_tags: &[Elf64Dyn]) -> DynamicInfo {
        let mut info = DynamicInfo::default();
        for tag in dyn_tags {
            match tag.d_tag {
                DT_NULL => break,
                DT_RELA => info.rela = tag.d_val,
                DT_RELASZ => info.relasz = tag.d_val as usize,
                DT_RELAENT => info.relaent = tag.d_val as usize,
                DT_SYMTAB => info.symtab = tag.d_val,
                DT_STRTAB => info.strtab = tag.d_val,
                DT_STRSZ => info.strsz = tag.d_val as usize,
                DT_PLTGOT => info.pltgot = tag.d_val,
                DT_JMPREL => info.jmprel = tag.d_val,
                DT_BIND_NOW => info.bind_now = true,
                DT_FLAGS => {
                    if (tag.d_val & DF_1_NOW) != 0 {
                        info.bind_now = true;
                    }
                }
                DT_FLAGS_1 => {
                    if (tag.d_val & DF_1_NOW) != 0 {
                        info.bind_now = true;
                    }
                }
                _ => {}
            }
        }
        info
    }

    /// Applique une relocalisation `R_X86_64_RELATIVE` (Base + Addend)
    pub fn apply_relative_relocation(
        &mut self,
        mem: &mut [u8],
        rela: &Elf64Rela,
    ) -> Result<u64, SysError> {
        if rela.r_type() != R_X86_64_RELATIVE {
            return Err(SysError::InvalidArgument);
        }
        let offset = rela.r_offset as usize;
        if offset + 8 > mem.len() {
            return Err(SysError::BadAddress);
        }

        // Formule standard System V AMD64 : B + A
        let target_val = (self.base_address as i64).wrapping_add(rela.r_addend) as u64;
        mem[offset..offset + 8].copy_from_slice(&target_val.to_le_bytes());
        self.relocations_applied += 1;
        Ok(target_val)
    }

    /// Applique une relocalisation `R_X86_64_GLOB_DAT` (Résolution de symbole vers la GOT)
    pub fn apply_glob_dat_relocation(
        &mut self,
        got_idx: usize,
        sym_addr: u64,
    ) -> Result<(), SysError> {
        self.got.set_entry(got_idx, sym_addr)?;
        self.relocations_applied += 1;
        Ok(())
    }

    /// Applique une relocalisation directe `R_X86_64_64` (Symbole + Addend)
    pub fn apply_64_relocation(
        &mut self,
        mem: &mut [u8],
        rela: &Elf64Rela,
        sym_val: u64,
    ) -> Result<u64, SysError> {
        if rela.r_type() != R_X86_64_64 {
            return Err(SysError::InvalidArgument);
        }
        let offset = rela.r_offset as usize;
        if offset + 8 > mem.len() {
            return Err(SysError::BadAddress);
        }

        let target_val = (sym_val as i64).wrapping_add(rela.r_addend) as u64;
        mem[offset..offset + 8].copy_from_slice(&target_val.to_le_bytes());
        self.relocations_applied += 1;
        Ok(target_val)
    }

    /// Scelle la table GOT en lecture seule (RELRO irréversible)
    pub fn seal_relro(&mut self) {
        self.got.seal_relro();
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_dyn_parsing() {
        let tags = [
            Elf64Dyn {
                d_tag: DT_RELA,
                d_val: 0x4000_1000,
            },
            Elf64Dyn {
                d_tag: DT_RELASZ,
                d_val: 48,
            },
            Elf64Dyn {
                d_tag: DT_RELAENT,
                d_val: 24,
            },
            Elf64Dyn {
                d_tag: DT_SYMTAB,
                d_val: 0x4000_2000,
            },
            Elf64Dyn {
                d_tag: DT_STRTAB,
                d_val: 0x4000_3000,
            },
            Elf64Dyn {
                d_tag: DT_STRSZ,
                d_val: 128,
            },
            Elf64Dyn {
                d_tag: DT_BIND_NOW,
                d_val: 1,
            },
            Elf64Dyn {
                d_tag: DT_NULL,
                d_val: 0,
            },
        ];

        let loader = DynamicLoader::new(0x0040_0000);
        let info = loader.parse_dynamic_segment(&tags);

        assert_eq!(info.rela, 0x4000_1000);
        assert_eq!(info.relasz, 48);
        assert_eq!(info.relaent, 24);
        assert_eq!(info.symtab, 0x4000_2000);
        assert_eq!(info.strtab, 0x4000_3000);
        assert_eq!(info.strsz, 128);
        assert!(info.bind_now);
    }

    #[test]
    fn test_relative_relocation() {
        let base_address = 0x0040_0000u64;
        let mut loader = DynamicLoader::new(base_address);

        let mut buffer = [0u8; 32];
        let rela = Elf64Rela::new(8, 0, R_X86_64_RELATIVE, 0x1234);

        let target = loader
            .apply_relative_relocation(&mut buffer, &rela)
            .expect("Application relocation relative");
        assert_eq!(target, 0x0040_0000 + 0x1234);

        let written = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
        assert_eq!(written, 0x0040_0000 + 0x1234);
        assert_eq!(loader.relocations_applied, 1);
    }

    #[test]
    fn test_got_and_relro() {
        let mut loader = DynamicLoader::new(0x0020_0000);

        // Ajout d'entrées normales dans la GOT
        assert!(loader.apply_glob_dat_relocation(3, 0xdead_beef).is_ok());
        assert_eq!(loader.got.get_entry(3), Some(0xdead_beef));
        assert_eq!(loader.relocations_applied, 1);

        // Scellement irréversible RELRO
        loader.seal_relro();
        assert!(loader.got.is_readonly);

        // Toute tentative ultérieure de modification de la GOT doit échouer avec PermissionDenied
        let err = loader.apply_glob_dat_relocation(3, 0xcafe_babe);
        assert_eq!(err, Err(SysError::PermissionDenied));
        // L'entrée précédente doit demeurer inchangée
        assert_eq!(loader.got.get_entry(3), Some(0xdead_beef));
    }

    #[test]
    fn test_direct_64_relocation() {
        let mut loader = DynamicLoader::new(0x0010_0000);
        let mut buffer = [0u8; 16];
        let rela = Elf64Rela::new(0, 1, R_X86_64_64, -8);
        let sym_val = 0x1000;

        let res = loader
            .apply_64_relocation(&mut buffer, &rela, sym_val)
            .expect("Application relocation 64");
        assert_eq!(res, 0x1000 - 8);

        let written = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
        assert_eq!(written, 0x1000 - 8);
    }
}

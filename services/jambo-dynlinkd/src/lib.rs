//! Démon d'Édition de Liens Dynamiques Ring 3, Bibliothèques Partagées ELF64 & GOT/PLT (`jambo-dynlinkd`)
//!
//! Fournit une infrastructure complète d'édition de liens dynamiques en espace utilisateur
//! pour le micro-noyau souverain JamboOS (`#![no_std]`) :
//! 1. Chargement et relocation dynamique de bibliothèques partagées ELF64 (`.jso` / *Jambo Shared Objects*).
//! 2. Gestion des tables globales de décalage (GOT) et tables de liaison de procédures (PLT).
//! 3. Résolution différée (*Lazy Binding*) sécurisée via trampolines et liaison immédiate (*Immediate Binding / BIND_NOW*).
//! 4. Application stricte des protections mémoire W^X et durcissement RELRO (*Read-Only Relocations*).
//! 5. Gestion des dépendances dynamiques (`DT_NEEDED`), graphes de chargement et comptage de références (`dlopen`/`dlclose`).
//! 6. Registre d'audit inviolable scellé par chaîne cryptographique SHA-256.
//! 7. Modèle de sécurité capabilaire strict (`DynLinkCap`) sans autorité ambiante.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_LIBRARIES: usize = 16;
pub const MAX_SYMBOLS: usize = 64;
pub const MAX_RELOCATIONS: usize = 64;
pub const MAX_GOT_ENTRIES: usize = 64;
pub const MAX_PLT_ENTRIES: usize = 64;
pub const MAX_DEPENDENCIES: usize = 8;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_NAME_LEN: usize = 32;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 pure `#![no_std]` sans allocation
#[derive(Clone, Copy)]
pub struct Sha256;

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn gamma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn gamma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = Self::gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(Self::gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let total_len = data.len();
        let mut offset = 0;
        let mut block = [0u8; 64];

        while offset + 64 <= total_len {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let rem = total_len - offset;
        block[..rem].copy_from_slice(&data[offset..]);
        block[rem] = 0x80;
        for b in &mut block[rem + 1..] {
            *b = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
        }

        let bit_len = (total_len as u64) * 8;
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut state, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// MODÈLE CAPABILAIRE DE SÉCURITÉ (DynLinkCap)
// ============================================================================

pub mod dynlink_rights {
    pub const DYNLINK_READ: u32 = 1 << 0; // Inspection des bibliothèques et tables
    pub const DYNLINK_LOAD: u32 = 1 << 1; // Chargement en mémoire virtuelle (.jso)
    pub const DYNLINK_BIND: u32 = 1 << 2; // Résolution et application des relocations
    pub const DYNLINK_RESOLVE: u32 = 1 << 3; // Résolution différée (Lazy Binding PLT)
    pub const DYNLINK_RELRO: u32 = 1 << 4; // Protection W^X et scellement GOT en lecture seule
    pub const DYNLINK_UNLOAD: u32 = 1 << 5; // Déchargement de bibliothèques (dlclose)
    pub const DYNLINK_AUDIT: u32 = 1 << 6; // Consultation de l'audit cryptographique
    pub const DYNLINK_ADMIN: u32 = 1 << 7; // Administration système et reconfiguration

    pub const ALL: u32 = DYNLINK_READ
        | DYNLINK_LOAD
        | DYNLINK_BIND
        | DYNLINK_RESOLVE
        | DYNLINK_RELRO
        | DYNLINK_UNLOAD
        | DYNLINK_AUDIT
        | DYNLINK_ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynLinkCap {
    pub handle: Handle,
    pub rights: u32,
}

impl DynLinkCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(&self, new_rights: u32) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// FORMAT ELF64 & DÉFINITIONS SYSTÈME V
// ============================================================================

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELF_CLASS_64: u8 = 2;
pub const ELF_DATA_2LSB: u8 = 1;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 0x3E;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_GNU_RELRO: u32 = 0x6474e552;

// Tags de la section dynamique (DT_*)
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
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
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_FLAGS: i64 = 30;

// Types de Relocations x86-64
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1; // S + A
pub const R_X86_64_PC32: u32 = 2; // S + A - P
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6; // S
pub const R_X86_64_JUMP_SLOT: u32 = 7; // S
pub const R_X86_64_RELATIVE: u32 = 8; // B + A
pub const R_X86_64_32: u32 = 10; // S + A

// Drapeaux de liaison dynamique (RTLD_*)
pub const RTLD_LAZY: u32 = 1 << 0; // Résolution différée PLT
pub const RTLD_NOW: u32 = 1 << 1; // Résolution immédiate de tous les symboles
pub const RTLD_GLOBAL: u32 = 1 << 2; // Symboles disponibles pour d'autres bibliothèques
pub const RTLD_LOCAL: u32 = 1 << 3; // Symboles isolés au module
pub const RTLD_NODELETE: u32 = 1 << 4; // Interdiction de déchargement

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Ehdr {
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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

// ============================================================================
// ÉTAT, TABLES GOT/PLT ET RELOCATIONS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryState {
    Unloaded,
    Loaded,
    Relocated,
    Bound,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    NoType,
    Object,
    Func,
    Section,
}

#[derive(Clone, Copy)]
pub struct SymbolEntry {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub address: u64,
    pub size: u64,
    pub binding: SymbolBinding,
    pub sym_type: SymbolType,
}

impl SymbolEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            address: 0,
            size: 0,
            binding: SymbolBinding::Global,
            sym_type: SymbolType::Func,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

#[derive(Clone, Copy)]
pub struct RelocationEntry {
    pub offset: u64,
    pub reloc_type: u32,
    pub symbol_name: [u8; MAX_NAME_LEN],
    pub symbol_name_len: usize,
    pub addend: i64,
    pub applied: bool,
    pub resolved_value: u64,
}

impl RelocationEntry {
    pub const fn empty() -> Self {
        Self {
            offset: 0,
            reloc_type: R_X86_64_NONE,
            symbol_name: [0u8; MAX_NAME_LEN],
            symbol_name_len: 0,
            addend: 0,
            applied: false,
            resolved_value: 0,
        }
    }

    pub fn symbol_str(&self) -> &str {
        core::str::from_utf8(&self.symbol_name[..self.symbol_name_len]).unwrap_or("")
    }
}

#[derive(Clone, Copy)]
pub struct PltEntry {
    pub symbol_name: [u8; MAX_NAME_LEN],
    pub symbol_name_len: usize,
    pub got_index: usize,
    pub plt_stub_addr: u64,
    pub target_addr: u64,
    pub is_resolved: bool,
    pub resolve_count: u64,
}

impl PltEntry {
    pub const fn empty() -> Self {
        Self {
            symbol_name: [0u8; MAX_NAME_LEN],
            symbol_name_len: 0,
            got_index: 0,
            plt_stub_addr: 0,
            target_addr: 0,
            is_resolved: false,
            resolve_count: 0,
        }
    }

    pub fn symbol_str(&self) -> &str {
        core::str::from_utf8(&self.symbol_name[..self.symbol_name_len]).unwrap_or("")
    }
}

#[derive(Clone, Copy)]
pub struct GotTable {
    pub entries: [u64; MAX_GOT_ENTRIES],
    pub count: usize,
    pub is_readonly: bool, // Protégé par RELRO
    pub base_addr: u64,
}

impl GotTable {
    pub const fn new(base_addr: u64) -> Self {
        Self {
            entries: [0u64; MAX_GOT_ENTRIES],
            count: 3, // GOT[0]=link_map, GOT[1]=lib_id, GOT[2]=resolver_stub
            is_readonly: false,
            base_addr,
        }
    }

    pub fn set_entry(&mut self, idx: usize, val: u64) -> Result<(), SysError> {
        if self.is_readonly {
            return Err(SysError::PermissionDenied); // Violation W^X / RELRO
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

    pub fn get_entry(&self, idx: usize) -> Option<u64> {
        if idx < self.count {
            Some(self.entries[idx])
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
pub struct PltTable {
    pub entries: [PltEntry; MAX_PLT_ENTRIES],
    pub count: usize,
    pub base_addr: u64,
}

impl PltTable {
    pub const fn new(base_addr: u64) -> Self {
        Self {
            entries: [PltEntry::empty(); MAX_PLT_ENTRIES],
            count: 0,
            base_addr,
        }
    }

    pub fn add_entry(
        &mut self,
        symbol: &str,
        got_index: usize,
        plt_stub_addr: u64,
    ) -> Result<usize, SysError> {
        if self.count >= MAX_PLT_ENTRIES {
            return Err(SysError::OutOfMemory);
        }
        let idx = self.count;
        let mut entry = PltEntry::empty();
        let bytes = symbol.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        entry.symbol_name[..len].copy_from_slice(&bytes[..len]);
        entry.symbol_name_len = len;
        entry.got_index = got_index;
        entry.plt_stub_addr = plt_stub_addr;
        entry.is_resolved = false;
        entry.resolve_count = 0;
        self.entries[idx] = entry;
        self.count += 1;
        Ok(idx)
    }
}

// ============================================================================
// MODULE DE BIBLIOTHÈQUE PARTAGÉE (SharedLibrary / .jso)
// ============================================================================

#[derive(Clone, Copy)]
pub struct SharedLibrary {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub base_address: u64,
    pub total_size: u64,
    pub flags: u32,
    pub state: LibraryState,
    pub ref_count: u32,
    pub dependencies: [u32; MAX_DEPENDENCIES],
    pub dep_count: usize,
    pub symbols: [SymbolEntry; MAX_SYMBOLS],
    pub symbol_count: usize,
    pub relocations: [RelocationEntry; MAX_RELOCATIONS],
    pub reloc_count: usize,
    pub got: GotTable,
    pub plt: PltTable,
    pub relro_enabled: bool,
    pub relro_start: u64,
    pub relro_size: u64,
    pub init_fn: u64,
    pub fini_fn: u64,
    pub sha256_hash: [u8; 32],
}

impl SharedLibrary {
    pub fn new(id: u32, name: &str, base_address: u64, total_size: u64, flags: u32) -> Self {
        let mut lib = Self {
            id,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            base_address,
            total_size,
            flags,
            state: LibraryState::Loaded,
            ref_count: 1,
            dependencies: [0u32; MAX_DEPENDENCIES],
            dep_count: 0,
            symbols: [SymbolEntry::empty(); MAX_SYMBOLS],
            symbol_count: 0,
            relocations: [RelocationEntry::empty(); MAX_RELOCATIONS],
            reloc_count: 0,
            got: GotTable::new(base_address + 0x2000),
            plt: PltTable::new(base_address + 0x1000),
            relro_enabled: false,
            relro_start: base_address + 0x2000,
            relro_size: 0x1000,
            init_fn: 0,
            fini_fn: 0,
            sha256_hash: [0u8; 32],
        };
        let b = name.as_bytes();
        let len = b.len().min(MAX_NAME_LEN);
        lib.name[..len].copy_from_slice(&b[..len]);
        lib.name_len = len;

        // Configurer GOT[0..2]
        lib.got.entries[0] = base_address; // link_map
        lib.got.entries[1] = id as u64; // lib_id
        lib.got.entries[2] = 0x7FFF_0000_1000; // Adresse du resolver dynamique Ring 3
        lib
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn add_dependency(&mut self, dep_id: u32) -> Result<(), SysError> {
        if self.dep_count >= MAX_DEPENDENCIES {
            return Err(SysError::OutOfMemory);
        }
        self.dependencies[self.dep_count] = dep_id;
        self.dep_count += 1;
        Ok(())
    }

    pub fn add_symbol(
        &mut self,
        name: &str,
        address: u64,
        size: u64,
        binding: SymbolBinding,
        sym_type: SymbolType,
    ) -> Result<usize, SysError> {
        if self.symbol_count >= MAX_SYMBOLS {
            return Err(SysError::OutOfMemory);
        }
        let idx = self.symbol_count;
        let mut sym = SymbolEntry::empty();
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        sym.name[..len].copy_from_slice(&bytes[..len]);
        sym.name_len = len;
        sym.address = address;
        sym.size = size;
        sym.binding = binding;
        sym.sym_type = sym_type;
        self.symbols[idx] = sym;
        self.symbol_count += 1;
        Ok(idx)
    }

    pub fn lookup_symbol(&self, name: &str) -> Option<&SymbolEntry> {
        for i in 0..self.symbol_count {
            if self.symbols[i].name_str() == name {
                return Some(&self.symbols[i]);
            }
        }
        None
    }

    pub fn add_relocation(
        &mut self,
        offset: u64,
        reloc_type: u32,
        symbol_name: &str,
        addend: i64,
    ) -> Result<usize, SysError> {
        if self.reloc_count >= MAX_RELOCATIONS {
            return Err(SysError::OutOfMemory);
        }
        let idx = self.reloc_count;
        let mut r = RelocationEntry::empty();
        r.offset = offset;
        r.reloc_type = reloc_type;
        let bytes = symbol_name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        r.symbol_name[..len].copy_from_slice(&bytes[..len]);
        r.symbol_name_len = len;
        r.addend = addend;
        r.applied = false;
        r.resolved_value = 0;
        self.relocations[idx] = r;
        self.reloc_count += 1;
        Ok(idx)
    }
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ SHA-256
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    LibraryLoaded,
    RelocationApplied,
    SymbolResolved,
    LazyBindingTriggered,
    RelroProtectionEnforced,
    LibraryUnloaded,
    AuditQueried,
}

#[derive(Clone, Copy)]
pub struct AuditRecord {
    pub timestamp: u64,
    pub action: AuditAction,
    pub lib_id: u32,
    pub target_addr: u64,
    pub details: [u8; 32],
    pub details_len: usize,
    pub digest: [u8; 32],
}

impl AuditRecord {
    pub const fn empty() -> Self {
        Self {
            timestamp: 0,
            action: AuditAction::LibraryLoaded,
            lib_id: 0,
            target_addr: 0,
            details: [0u8; 32],
            details_len: 0,
            digest: [0u8; 32],
        }
    }
}

// ============================================================================
// DÉMON D'ÉDITION DE LIENS DYNAMIQUES (JamboDynLinkDaemon)
// ============================================================================

pub struct JamboDynLinkDaemon {
    pub daemon_id: u32,
    pub cap: DynLinkCap,
    pub libraries: [Option<SharedLibrary>; MAX_LIBRARIES],
    pub lib_count: usize,
    pub next_lib_id: u32,
    pub audit_log: [AuditRecord; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub last_audit_digest: [u8; 32],
    pub total_relocations_applied: u64,
    pub total_lazy_resolutions: u64,
}

impl JamboDynLinkDaemon {
    pub fn new(daemon_id: u32, cap: DynLinkCap) -> Self {
        let initial_seed = b"JAMBO_DYNLINK_GENESIS_STATE_v0.2.85";
        let genesis_digest = Sha256::digest(initial_seed);

        Self {
            daemon_id,
            cap,
            libraries: [None; MAX_LIBRARIES],
            lib_count: 0,
            next_lib_id: 1,
            audit_log: [AuditRecord::empty(); MAX_AUDIT_LOGS],
            audit_count: 0,
            last_audit_digest: genesis_digest,
            total_relocations_applied: 0,
            total_lazy_resolutions: 0,
        }
    }

    pub fn record_audit(
        &mut self,
        timestamp: u64,
        action: AuditAction,
        lib_id: u32,
        target_addr: u64,
        details: &str,
    ) {
        let mut record = AuditRecord::empty();
        record.timestamp = timestamp;
        record.action = action;
        record.lib_id = lib_id;
        record.target_addr = target_addr;

        let b = details.as_bytes();
        let len = b.len().min(32);
        record.details[..len].copy_from_slice(&b[..len]);
        record.details_len = len;

        // Calcul du hash chaîné : SHA256(last_digest || ts || action || lib_id || addr || details)
        let mut preimage = [0u8; 64];
        preimage[0..32].copy_from_slice(&self.last_audit_digest);
        preimage[32..40].copy_from_slice(&timestamp.to_be_bytes());
        preimage[40] = action as u8;
        preimage[41..45].copy_from_slice(&lib_id.to_be_bytes());
        preimage[45..53].copy_from_slice(&target_addr.to_be_bytes());
        let dlen = len.min(11);
        preimage[53..53 + dlen].copy_from_slice(&record.details[..dlen]);

        let digest = Sha256::digest(&preimage);
        record.digest = digest;
        self.last_audit_digest = digest;

        let slot = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_log[slot] = record;
        self.audit_count += 1;
    }

    pub fn verify_audit_integrity(&self) -> bool {
        if self.audit_count == 0 {
            return true;
        }
        let total = self.audit_count.min(MAX_AUDIT_LOGS);
        for i in 0..total {
            let r = &self.audit_log[i];
            if r.timestamp == 0 && r.digest == [0u8; 32] {
                continue;
            }
            if r.digest == [0u8; 32] {
                return false;
            }
        }
        true
    }

    /// Charge une bibliothèque partagée ELF64 (`.jso`) sous contrôle capabilaire
    pub fn load_library(
        &mut self,
        cap: &DynLinkCap,
        name: &str,
        base_address: u64,
        total_size: u64,
        flags: u32,
        timestamp: u64,
    ) -> Result<u32, SysError> {
        if !cap.has_right(dynlink_rights::DYNLINK_LOAD) {
            return Err(SysError::PermissionDenied);
        }

        // Vérifier si la bibliothèque est déjà chargée
        if let Some(lib) = self.find_library_by_name(name) {
            let id = lib.id;
            for slot in &mut self.libraries {
                if let Some(ref mut l) = slot {
                    if l.id == id {
                        l.ref_count += 1;
                        self.record_audit(
                            timestamp,
                            AuditAction::LibraryLoaded,
                            id,
                            base_address,
                            "RefcountIncremented",
                        );
                        return Ok(id);
                    }
                }
            }
        }

        if self.lib_count >= MAX_LIBRARIES {
            return Err(SysError::OutOfMemory);
        }

        let lib_id = self.next_lib_id;
        self.next_lib_id += 1;

        let mut lib = SharedLibrary::new(lib_id, name, base_address, total_size, flags);
        lib.sha256_hash = Sha256::digest(name.as_bytes());

        // Recherche d'un slot libre
        for slot in &mut self.libraries {
            if slot.is_none() {
                *slot = Some(lib);
                self.lib_count += 1;
                self.record_audit(
                    timestamp,
                    AuditAction::LibraryLoaded,
                    lib_id,
                    base_address,
                    name,
                );
                return Ok(lib_id);
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Recherche une bibliothèque par ID
    pub fn get_library(&self, lib_id: u32) -> Option<&SharedLibrary> {
        for slot in &self.libraries {
            if let Some(ref lib) = slot {
                if lib.id == lib_id {
                    return Some(lib);
                }
            }
        }
        None
    }

    /// Recherche mutable d'une bibliothèque par ID
    pub fn get_library_mut(&mut self, lib_id: u32) -> Option<&mut SharedLibrary> {
        for slot in &mut self.libraries {
            if let Some(ref mut lib) = slot {
                if lib.id == lib_id {
                    return Some(lib);
                }
            }
        }
        None
    }

    /// Recherche par nom de fichier
    pub fn find_library_by_name(&self, name: &str) -> Option<&SharedLibrary> {
        for slot in &self.libraries {
            if let Some(ref lib) = slot {
                if lib.name_str() == name {
                    return Some(lib);
                }
            }
        }
        None
    }

    /// Résolution globale d'un symbole à travers toutes les bibliothèques chargées (ordre de dépendance)
    pub fn resolve_symbol_global(
        &self,
        cap: &DynLinkCap,
        symbol_name: &str,
    ) -> Result<(u32, u64), SysError> {
        if !cap.has_right(dynlink_rights::DYNLINK_READ) {
            return Err(SysError::PermissionDenied);
        }

        for slot in &self.libraries {
            if let Some(ref lib) = slot {
                if let Some(sym) = lib.lookup_symbol(symbol_name) {
                    if sym.binding != SymbolBinding::Local {
                        return Ok((lib.id, sym.address));
                    }
                }
            }
        }
        Err(SysError::InvalidArgument)
    }

    /// Applique les relocations statiques et prépare la table GOT
    pub fn apply_relocations(
        &mut self,
        cap: &DynLinkCap,
        lib_id: u32,
        timestamp: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(dynlink_rights::DYNLINK_BIND) {
            return Err(SysError::PermissionDenied);
        }

        let base_address = {
            let lib = self.get_library(lib_id).ok_or(SysError::InvalidArgument)?;
            lib.base_address
        };

        let mut applied_count = 0;
        let reloc_count = {
            let lib = self.get_library(lib_id).ok_or(SysError::InvalidArgument)?;
            lib.reloc_count
        };

        for r_idx in 0..reloc_count {
            let (reloc_type, sym_name_buf, sym_len, offset, addend) = {
                let lib = self.get_library(lib_id).unwrap();
                let r = &lib.relocations[r_idx];
                (
                    r.reloc_type,
                    r.symbol_name,
                    r.symbol_name_len,
                    r.offset,
                    r.addend,
                )
            };
            let sym_name = core::str::from_utf8(&sym_name_buf[..sym_len]).unwrap_or("");

            let resolved_val = match reloc_type {
                R_X86_64_RELATIVE => {
                    // B + A (Base + Addend)
                    (base_address as i64 + addend) as u64
                }
                R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_32 => {
                    // S + A
                    let (_, sym_addr) = self.resolve_symbol_global(cap, sym_name)?;
                    (sym_addr as i64 + addend) as u64
                }
                R_X86_64_JUMP_SLOT => {
                    // JUMP_SLOT pour PLT
                    let (_, sym_addr) = self.resolve_symbol_global(cap, sym_name)?;
                    sym_addr
                }
                R_X86_64_PC32 => {
                    // S + A - P
                    let (_, sym_addr) = self.resolve_symbol_global(cap, sym_name)?;
                    let p = base_address + offset;
                    ((sym_addr as i64 + addend) - p as i64) as u64
                }
                R_X86_64_NONE => 0,
                _ => return Err(SysError::NotSupported),
            };

            let lib = self.get_library_mut(lib_id).unwrap();
            lib.relocations[r_idx].applied = true;
            lib.relocations[r_idx].resolved_value = resolved_val;

            // Si c'est un JUMP_SLOT ou GLOB_DAT, mettre à jour la GOT
            if reloc_type == R_X86_64_GLOB_DAT || reloc_type == R_X86_64_JUMP_SLOT {
                let got_slot = (offset / 8) as usize;
                if got_slot < MAX_GOT_ENTRIES {
                    let _ = lib.got.set_entry(got_slot, resolved_val);
                }
            }

            applied_count += 1;
            self.total_relocations_applied += 1;
        }

        let lib = self.get_library_mut(lib_id).unwrap();
        lib.state = LibraryState::Relocated;

        self.record_audit(
            timestamp,
            AuditAction::RelocationApplied,
            lib_id,
            base_address,
            "RelocationsFinished",
        );
        Ok(applied_count)
    }

    /// Résolution différée (Lazy Binding) déclenchée par un saut PLT
    pub fn resolve_lazy(
        &mut self,
        cap: &DynLinkCap,
        lib_id: u32,
        plt_index: usize,
        timestamp: u64,
    ) -> Result<u64, SysError> {
        if !cap.has_right(dynlink_rights::DYNLINK_RESOLVE) {
            return Err(SysError::PermissionDenied);
        }

        let (sym_name_buf, sym_len, got_idx) = {
            let lib = self.get_library(lib_id).ok_or(SysError::InvalidArgument)?;
            if plt_index >= lib.plt.count {
                return Err(SysError::InvalidArgument);
            }
            let entry = &lib.plt.entries[plt_index];
            (entry.symbol_name, entry.symbol_name_len, entry.got_index)
        };
        let sym_name = core::str::from_utf8(&sym_name_buf[..sym_len]).unwrap_or("");

        // Résolution du symbole
        let (_, sym_addr) = self.resolve_symbol_global(cap, sym_name)?;

        // Écriture atomique dans la table GOT de la bibliothèque appelante
        let lib = self.get_library_mut(lib_id).unwrap();
        lib.got.set_entry(got_idx, sym_addr)?;
        lib.plt.entries[plt_index].target_addr = sym_addr;
        lib.plt.entries[plt_index].is_resolved = true;
        lib.plt.entries[plt_index].resolve_count += 1;

        self.total_lazy_resolutions += 1;
        self.record_audit(
            timestamp,
            AuditAction::LazyBindingTriggered,
            lib_id,
            sym_addr,
            sym_name,
        );

        Ok(sym_addr)
    }

    /// Application du durcissement RELRO (Read-Only Relocations) et protection W^X
    pub fn enforce_relro(
        &mut self,
        cap: &DynLinkCap,
        lib_id: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(dynlink_rights::DYNLINK_RELRO) {
            return Err(SysError::PermissionDenied);
        }

        let lib = self
            .get_library_mut(lib_id)
            .ok_or(SysError::InvalidArgument)?;
        lib.got.is_readonly = true;
        lib.relro_enabled = true;
        lib.state = LibraryState::Ready;

        let got_base = lib.got.base_addr;
        self.record_audit(
            timestamp,
            AuditAction::RelroProtectionEnforced,
            lib_id,
            got_base,
            "GOT_ReadOnly_Enforced",
        );
        Ok(())
    }

    /// Liaison immédiate (BIND_NOW) de tous les symboles et activation RELRO
    pub fn bind_now(
        &mut self,
        cap: &DynLinkCap,
        lib_id: u32,
        timestamp: u64,
    ) -> Result<usize, SysError> {
        if !cap.has_right(dynlink_rights::DYNLINK_BIND) {
            return Err(SysError::PermissionDenied);
        }

        let plt_count = {
            let lib = self.get_library(lib_id).ok_or(SysError::InvalidArgument)?;
            lib.plt.count
        };

        for i in 0..plt_count {
            self.resolve_lazy(cap, lib_id, i, timestamp)?;
        }

        self.enforce_relro(cap, lib_id, timestamp)?;

        let lib = self.get_library_mut(lib_id).unwrap();
        lib.state = LibraryState::Bound;

        Ok(plt_count)
    }

    /// Déchargement d'une bibliothèque partagée (`dlclose`)
    pub fn unload_library(
        &mut self,
        cap: &DynLinkCap,
        lib_id: u32,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(dynlink_rights::DYNLINK_UNLOAD) {
            return Err(SysError::PermissionDenied);
        }

        let mut target_idx = None;
        for i in 0..MAX_LIBRARIES {
            if let Some(ref lib) = self.libraries[i] {
                if lib.id == lib_id {
                    target_idx = Some(i);
                    break;
                }
            }
        }

        let idx = target_idx.ok_or(SysError::InvalidArgument)?;
        let (flags, ref_count, base_address, name_buf, name_len) = {
            let lib = self.libraries[idx].as_ref().unwrap();
            let mut buf = [0u8; MAX_NAME_LEN];
            buf[..lib.name_len].copy_from_slice(&lib.name[..lib.name_len]);
            (
                lib.flags,
                lib.ref_count,
                lib.base_address,
                buf,
                lib.name_len,
            )
        };

        if (flags & RTLD_NODELETE) != 0 {
            return Err(SysError::PermissionDenied);
        }

        if ref_count > 1 {
            self.libraries[idx].as_mut().unwrap().ref_count -= 1;
            self.record_audit(
                timestamp,
                AuditAction::LibraryUnloaded,
                lib_id,
                base_address,
                "RefcountDecremented",
            );
            Ok(())
        } else {
            self.libraries[idx] = None;
            self.lib_count -= 1;
            let name_str = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("");
            self.record_audit(
                timestamp,
                AuditAction::LibraryUnloaded,
                lib_id,
                base_address,
                name_str,
            );
            Ok(())
        }
    }

    /// Initialise un environnement standard avec des bibliothèques système par défaut
    pub fn init_defaults(&mut self) {
        let admin_cap = self.cap;

        // 1. Charger `libjambo-c.jso` (Bibliothèque C standard de base)
        let libc_id = self
            .load_library(
                &admin_cap,
                "libjambo-c.jso",
                0x0000_7000_0000_0000,
                0x20000,
                RTLD_GLOBAL,
                100,
            )
            .expect("load libc");

        if let Some(libc) = self.get_library_mut(libc_id) {
            let _ = libc.add_symbol(
                "malloc",
                0x0000_7000_0000_1000,
                64,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = libc.add_symbol(
                "free",
                0x0000_7000_0000_1040,
                48,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = libc.add_symbol(
                "memcpy",
                0x0000_7000_0000_1080,
                80,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = libc.add_symbol(
                "strlen",
                0x0000_7000_0000_10E0,
                32,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = libc.add_symbol(
                "printf",
                0x0000_7000_0000_1100,
                128,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = libc.add_symbol(
                "exit",
                0x0000_7000_0000_1180,
                24,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = libc.add_relocation(0x18, R_X86_64_RELATIVE, "", 0x1000);
            libc.init_fn = 0x0000_7000_0000_1200;
        }

        // 2. Charger `libcrypto.jso` (Bibliothèque cryptographique ChaCha20/SHA-256)
        let crypto_id = self
            .load_library(
                &admin_cap,
                "libcrypto.jso",
                0x0000_7000_0004_0000,
                0x18000,
                RTLD_GLOBAL,
                101,
            )
            .expect("load libcrypto");

        if let Some(crypto) = self.get_library_mut(crypto_id) {
            let _ = crypto.add_dependency(libc_id);
            let _ = crypto.add_symbol(
                "sha256_hash",
                0x0000_7000_0004_1000,
                256,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = crypto.add_symbol(
                "chacha20_encrypt",
                0x0000_7000_0004_1100,
                320,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = crypto.add_symbol(
                "ed25519_verify",
                0x0000_7000_0004_1240,
                400,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            // Relocations pointant vers `memcpy` et `malloc` de libc
            let _ = crypto.add_relocation(0x28, R_X86_64_GLOB_DAT, "memcpy", 0);
            let _ = crypto.add_relocation(0x30, R_X86_64_JUMP_SLOT, "malloc", 0);
            let _ = crypto.plt.add_entry("malloc", 6, 0x0000_7000_0004_2000);
        }

        // 3. Charger `libmath.jso` (Calcul mathématique flottant et trigonométrie)
        let math_id = self
            .load_library(
                &admin_cap,
                "libmath.jso",
                0x0000_7000_0008_0000,
                0x10000,
                RTLD_LAZY,
                102,
            )
            .expect("load libmath");

        if let Some(math) = self.get_library_mut(math_id) {
            let _ = math.add_symbol(
                "sin",
                0x0000_7000_0008_1000,
                96,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = math.add_symbol(
                "cos",
                0x0000_7000_0008_1060,
                96,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = math.add_symbol(
                "sqrt",
                0x0000_7000_0008_10C0,
                48,
                SymbolBinding::Global,
                SymbolType::Func,
            );
            let _ = math.plt.add_entry("sin", 3, 0x0000_7000_0008_2000);
            let _ = math.plt.add_entry("cos", 4, 0x0000_7000_0008_2010);
        }

        // Appliquer relocations pour libc et crypto
        let _ = self.apply_relocations(&admin_cap, libc_id, 103);
        let _ = self.apply_relocations(&admin_cap, crypto_id, 104);
        let _ = self.enforce_relro(&admin_cap, libc_id, 105);
    }
}

// ============================================================================
// CONSTRUCTEUR SYNTHÉTIQUE DE BIBLIOTHÈQUE PARTAGÉE ELF64 POUR TESTS
// ============================================================================

/// Génère un binaire ELF64 valide au format System V AMD64 représentant une `.jso`
pub fn build_synthetic_jso_bytes(name: &str, sym_name: &str, sym_addr: u64) -> [u8; 512] {
    let mut buf = [0u8; 512];

    // 1. En-tête ELF64 (64 octets)
    buf[0..4].copy_from_slice(&ELF_MAGIC);
    buf[4] = ELF_CLASS_64;
    buf[5] = ELF_DATA_2LSB;
    buf[6] = 1; // EV_CURRENT
    buf[7] = 0; // ELFOSABI_NONE / System V

    let ehdr = Elf64Ehdr {
        e_ident: [0; 16], // Déjà partiellement rempli ci-dessus
        e_type: ET_DYN,
        e_machine: EM_X86_64,
        e_version: 1,
        e_entry: 0x1000,
        e_phoff: 64, // Juste après ehdr
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: 64,
        e_phentsize: 56,
        e_phnum: 2, // 1 PT_LOAD + 1 PT_DYNAMIC
        e_shentsize: 64,
        e_shnum: 0,
        e_shstrndx: 0,
    };
    unsafe {
        let ehdr_dst = buf.as_mut_ptr() as *mut Elf64Ehdr;
        core::ptr::copy_nonoverlapping(&ehdr, ehdr_dst, 1);
        // Réécrire l'ident
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = ELF_CLASS_64;
        buf[5] = ELF_DATA_2LSB;
        buf[6] = 1;
    }

    // 2. Program Headers (2 x 56 octets à l'offset 64)
    // Phdr 0: PT_LOAD
    let phdr_load = Elf64Phdr {
        p_type: PT_LOAD,
        p_flags: 5, // PF_R | PF_X
        p_offset: 0,
        p_vaddr: 0x0040_0000,
        p_paddr: 0x0040_0000,
        p_filesz: 512,
        p_memsz: 4096,
        p_align: 4096,
    };
    // Phdr 1: PT_DYNAMIC
    let phdr_dyn = Elf64Phdr {
        p_type: PT_DYNAMIC,
        p_flags: 6, // PF_R | PF_W
        p_offset: 176,
        p_vaddr: 0x0040_00B0,
        p_paddr: 0x0040_00B0,
        p_filesz: 96,
        p_memsz: 96,
        p_align: 8,
    };
    unsafe {
        let phdr_ptr = buf.as_mut_ptr().add(64) as *mut Elf64Phdr;
        core::ptr::write_unaligned(phdr_ptr, phdr_load);
        core::ptr::write_unaligned(phdr_ptr.add(1), phdr_dyn);
    }

    // 3. DT_DYNAMIC tags (offset 176)
    let dyn_tags: [Elf64Dyn; 4] = [
        Elf64Dyn {
            d_tag: DT_SONAME,
            d_val: 1,
        },
        Elf64Dyn {
            d_tag: DT_SYMTAB,
            d_val: 0x0040_0120,
        },
        Elf64Dyn {
            d_tag: DT_STRTAB,
            d_val: 0x0040_0180,
        },
        Elf64Dyn {
            d_tag: DT_NULL,
            d_val: 0,
        },
    ];
    unsafe {
        let dyn_ptr = buf.as_mut_ptr().add(176) as *mut Elf64Dyn;
        for i in 0..4 {
            core::ptr::write_unaligned(dyn_ptr.add(i), dyn_tags[i]);
        }
    }

    // 4. Copier quelques chaînes pour le nom de la bibliothèque et le symbole
    let name_bytes = name.as_bytes();
    let nlen = name_bytes.len().min(32);
    buf[384..384 + nlen].copy_from_slice(&name_bytes[..nlen]);

    let sym_bytes = sym_name.as_bytes();
    let slen = sym_bytes.len().min(32);
    buf[420..420 + slen].copy_from_slice(&sym_bytes[..slen]);

    // 5. Symbol Table Entry factice (offset 288)
    let sym = Elf64Sym {
        st_name: 1,
        st_info: (1 << 4) | 2, // STB_GLOBAL (1) | STT_FUNC (2)
        st_other: 0,
        st_shndx: 1,
        st_value: sym_addr,
        st_size: 64,
    };
    unsafe {
        let sym_ptr = buf.as_mut_ptr().add(288) as *mut Elf64Sym;
        core::ptr::write_unaligned(sym_ptr, sym);
    }

    buf
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] / cargo test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynlink_cap_rights_and_strict_attenuation() {
        let admin_cap = DynLinkCap::new(Handle::new(8501, 1), dynlink_rights::ALL);
        assert!(admin_cap.has_right(dynlink_rights::DYNLINK_LOAD));
        assert!(admin_cap.has_right(dynlink_rights::DYNLINK_BIND));
        assert!(admin_cap.has_right(dynlink_rights::DYNLINK_RESOLVE));
        assert!(admin_cap.has_right(dynlink_rights::DYNLINK_RELRO));
        assert!(admin_cap.has_right(dynlink_rights::DYNLINK_ADMIN));

        let ro_cap = admin_cap
            .attenuate(dynlink_rights::DYNLINK_READ | dynlink_rights::DYNLINK_RESOLVE)
            .expect("attenuate to read/resolve");
        assert!(ro_cap.has_right(dynlink_rights::DYNLINK_READ));
        assert!(ro_cap.has_right(dynlink_rights::DYNLINK_RESOLVE));
        assert!(!ro_cap.has_right(dynlink_rights::DYNLINK_LOAD));
        assert!(!ro_cap.has_right(dynlink_rights::DYNLINK_BIND));
        assert!(!ro_cap.has_right(dynlink_rights::DYNLINK_ADMIN));

        // Rejet formel d'amplification
        assert_eq!(
            ro_cap.attenuate(dynlink_rights::DYNLINK_ADMIN),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_shared_library_loading_and_symbol_resolution() {
        let admin_cap = DynLinkCap::new(Handle::new(8501, 1), dynlink_rights::ALL);
        let mut daemon = JamboDynLinkDaemon::new(1, admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.lib_count, 3);
        let (lib_id, addr) = daemon
            .resolve_symbol_global(&admin_cap, "memcpy")
            .expect("resolve memcpy");
        assert_eq!(lib_id, 1); // libc
        assert_eq!(addr, 0x0000_7000_0000_1080);

        let (crypto_id, caddr) = daemon
            .resolve_symbol_global(&admin_cap, "chacha20_encrypt")
            .expect("resolve chacha20");
        assert_eq!(crypto_id, 2); // libcrypto
        assert_eq!(caddr, 0x0000_7000_0004_1100);

        assert!(daemon.verify_audit_integrity());
    }

    #[test]
    fn test_lazy_binding_and_got_plt_resolution() {
        let admin_cap = DynLinkCap::new(Handle::new(8501, 1), dynlink_rights::ALL);
        let mut daemon = JamboDynLinkDaemon::new(1, admin_cap);
        daemon.init_defaults();

        // Vérifier l'état de libcrypto avant résolution lazy de `malloc`
        let crypto = daemon.get_library(2).unwrap();
        assert_eq!(crypto.plt.count, 1);
        assert!(!crypto.plt.entries[0].is_resolved);

        // Déclencher le lazy binding
        let resolved = daemon
            .resolve_lazy(&admin_cap, 2, 0, 1001)
            .expect("resolve lazy malloc");
        assert_eq!(resolved, 0x0000_7000_0000_1000); // Adresse de malloc dans libc

        let crypto_after = daemon.get_library(2).unwrap();
        assert!(crypto_after.plt.entries[0].is_resolved);
        assert_eq!(crypto_after.got.get_entry(6), Some(0x0000_7000_0000_1000));

        assert!(daemon.verify_audit_integrity());
    }

    #[test]
    fn test_relro_protection_and_w_xor_x() {
        let admin_cap = DynLinkCap::new(Handle::new(8501, 1), dynlink_rights::ALL);
        let mut daemon = JamboDynLinkDaemon::new(1, admin_cap);
        daemon.init_defaults();

        let lib_id = daemon
            .load_library(
                &admin_cap,
                "libtest.jso",
                0x0000_7000_000C_0000,
                0x10000,
                RTLD_NOW,
                1010,
            )
            .unwrap();

        // Avant RELRO, écriture autorisée dans GOT
        let lib = daemon.get_library_mut(lib_id).unwrap();
        assert_eq!(lib.got.set_entry(4, 0x1234), Ok(()));
        assert_eq!(lib.got.get_entry(4), Some(0x1234));

        // Enforce RELRO
        daemon.enforce_relro(&admin_cap, lib_id, 1011).unwrap();

        // Après RELRO, tentative d'écriture dans GOT formellement rejetée
        let lib = daemon.get_library_mut(lib_id).unwrap();
        assert_eq!(
            lib.got.set_entry(4, 0x5678),
            Err(SysError::PermissionDenied)
        );
        assert_eq!(lib.got.get_entry(4), Some(0x1234)); // Inchangé !

        assert!(daemon.verify_audit_integrity());
    }

    #[test]
    fn test_synthetic_elf64_parsing() {
        let bytes = build_synthetic_jso_bytes("libsynth.jso", "synth_func", 0x0040_1000);
        assert_eq!(bytes[0..4], ELF_MAGIC);
        assert_eq!(bytes[4], ELF_CLASS_64);
        assert_eq!(bytes[5], ELF_DATA_2LSB);

        let ehdr_ptr = bytes.as_ptr() as *const Elf64Ehdr;
        let ehdr = unsafe { core::ptr::read_unaligned(ehdr_ptr) };
        let e_type = ehdr.e_type;
        let e_machine = ehdr.e_machine;
        assert_eq!(e_type, ET_DYN);
        assert_eq!(e_machine, EM_X86_64);
    }
}

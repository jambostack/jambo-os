# Spécification Technique — Jalon 6.2 (v0.3.89) : Dynamic Loader ELF Utilisateur Ring 3 & Relocations

> **Date** : 7 novembre 2026  
> **Composants cibles** : `libs/libjambo`, `kernel`, `xtask`, `services/jambo-sh`  
> **Version cible** : `v0.3.89` (Pre-Alpha / Prototype Expérimental de Recherche)  
> **Statut** : Approuvé

---

## 1. Objectifs & Portée

L'objectif du **Jalon 6.2** est d'équiper l'espace utilisateur de JamboOS ([`libs/libjambo`](file:///c:/Users/joker/Documents/jambo-os/libs/libjambo)) d'un moteur d'édition de liens et de relocalisation dynamique ELF64 (`ET_DYN` / PIE) en `#![no_std]`, respectant strictement le confinement Ring 3 et les contraintes temps-réel sans allocation dynamique obligatoire.

### Exigences Fondamentales
1. **Confinement Ring 3 & Iron Core** : Le noyau délègue la relocalisation applicative à `libjambo` en espace utilisateur. Le TCB Ring 0 demeure strictement sous 95 Kio.
2. **Support des Structures ELF64 System V AMD64** :
   - `Elf64Dyn` (balises dynamiques : `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, `DT_SYMTAB`, `DT_STRTAB`, `DT_PLTGOT`, `DT_JMPREL`).
   - `Elf64Rela` (entrées de relocalisation avec addend explicite).
   - `Elf64Sym` (symboles dynamiques).
3. **Moteur de Relocalisation Minimal** :
   - `R_X86_64_RELATIVE` (Base + Addend) : relocalisation des pointeurs internes aux binaires indépendants de la position (PIE).
   - `R_X86_64_GLOB_DAT` (Symbole) : initialisation des variables et fonctions globales dans la GOT.
   - `R_X86_64_JUMP_SLOT` (PLT) : initialisation des trampolines de liaison PLT.
   - `R_X86_64_64` / `R_X86_64_32` : relocalisations directes.
4. **Tables GOT/PLT & Scellement RELRO** :
   - Gestion de la Table Globale de Décalage (`GotTable`) et de la Table de Liaison de Procédures (`PltTable`).
   - Mécanisme de protection RELRO (*Read-Only Relocations*) simulant ou invoquant la protection lecture seule irréversible des entrées GOT après relocalisation.
5. **Validation Unitaire Exhaustive** :
   - Suite de tests unitaires dans `libjambo` validant le chargement d'un segment dynamique simulé, l'application exacte des formules mathématiques de relocalisation et la détection d'erreurs d'adresses invalides.

---

## 2. Architecture & Conception Détaillée

### 2.1 Nouveau Module `libs/libjambo/src/dynlink.rs`

Le module fournit les abstractions suivantes :

```rust
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_32: u32 = 10;

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTGOT: i64 = 3;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
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
```

### 2.2 Table GOT et Durcissement RELRO

```rust
pub const MAX_GOT_ENTRIES: usize = 64;

#[derive(Clone, Copy)]
pub struct GotTable {
    pub entries: [u64; MAX_GOT_ENTRIES],
    pub count: usize,
    pub is_readonly: bool,
    pub base_addr: u64,
}
```

- Initialisation : `entries[0]` (link_map), `entries[1]` (module_id), `entries[2]` (resolver_stub).
- `set_entry(idx, val)` : vérifie formellement `!self.is_readonly`, sinon renvoie `SysError::PermissionDenied`.
- `apply_relro()` : verrouille `is_readonly = true` de manière irréversible.

### 2.3 Moteur de Relocalisation `DynamicLoader`

```rust
pub struct DynamicLoader {
    base_address: u64,
    got: GotTable,
    relocations_applied: usize,
}

impl DynamicLoader {
    pub const fn new(base_address: u64) -> Self;
    pub fn apply_relative_relocation(&mut self, mem: &mut [u8], rela: &Elf64Rela) -> Result<u64, SysError>;
    pub fn apply_glob_dat_relocation(&mut self, got_idx: usize, sym_addr: u64) -> Result<(), SysError>;
    pub fn parse_dynamic_segment(&mut self, dyn_entries: &[Elf64Dyn]) -> Result<DynamicInfo, SysError>;
    pub fn seal_relro(&mut self);
}
```

---

## 3. Plan de Test & Vérification

1. **Test unitaire `test_elf_dyn_parsing`** : Validation du parcours des balises `DT_RELA`, `DT_RELASZ`, `DT_SYMTAB`, `DT_STRTAB`.
2. **Test unitaire `test_relative_relocation`** : Application de `R_X86_64_RELATIVE` sur un buffer simulant une zone mémoire relocalisable, calcul exact `base + addend`.
3. **Test unitaire `test_got_and_relro`** : Écriture dans la GOT, scellement RELRO, tentative d'écriture rejetée avec `PermissionDenied`.
4. **Intégration et chaîne de construction** :
   - `cargo test --package libjambo` (100% vert).
   - `cargo clippy --workspace --exclude incubator` (0 warning).
   - `cargo check --workspace --target aarch64-unknown-none --exclude xtask`.
   - `cargo xtask build --release` et `cargo xtask dist --release`.
   - Boot test sous QEMU avec affichage du statut `v0.3.89`.

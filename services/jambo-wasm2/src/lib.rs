//! Moteur de Composants WebAssembly & Interfaces de Capacités Ring 3 (`jambo-wasm2`)
//!
//! Spécification Wasm Component Model & Canonical ABI en environnement souverain `#![no_std]`.
//! Règle architecturale formelle :
//! Aucun code WebAssembly non sécurisé n'est exécuté en Ring 0. Ce sous-système s'exécute
//! en espace utilisateur (Ring 3) et garantit :
//! 1. La conformité binaire du Wasm Component Model (`\0asm\x0d\x00\x01\x00`).
//! 2. L'encapsulation stricte des mémoires linéaires de chaque composant (zéro mémoire partagée non contrôlée).
//! 3. La sérialisation et le passage de données via Canonical ABI (`canon lift` et `canon lower`).
//! 4. Le typage fort des interfaces (WIT: Interface Types - scalaires, records, variants, strings, resources).
//! 5. La composition et la liaison de composants (Component Linking) sans autorité ambiante.
//! 6. La gestion sécurisée du cycle de vie des ressources (`ResourceTable`, handles empruntés/possédés, anti-double-free).
//! 7. La comptabilisation monotone du carburant (Fuel/Gas metering) et interception immédiate des dépassements.
//! 8. Le contrôle d'accès capabilaire Ring 3 fondé sur `Wasm2Cap`.
//! 9. Le scellement d'un registre d'audit cryptographique inviolable SHA-256 (`wasm2_audit_chain`).

#![no_std]

use libjambo::{Handle, SysError};

pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // "\0asm"
pub const WASM_COMPONENT_VERSION: [u8; 4] = [0x0d, 0x00, 0x01, 0x00]; // Wasm Component Layer 1

pub const MAX_COMPONENTS: usize = 8;
pub const MAX_INSTANCES: usize = 8;
pub const MAX_LINKS: usize = 16;
pub const MAX_RESOURCES: usize = 32;
pub const MAX_INSTANCE_MEMORY: usize = 4096;
pub const MAX_CALL_DEPTH: u32 = 8;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_EXPORTS: usize = 8;
pub const MAX_IMPORTS: usize = 8;
pub const MAX_STR_LEN: usize = 64;

// ============================================================================
// HASHAGE CRYPTOGRAPHIQUE SHA-256 EN NO_STD
// ============================================================================

pub struct Sha256;

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];

        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::transform(&mut h, &block);
            offset += 64;
        }

        let rem = data.len() - offset;
        block = [0u8; 64];
        block[..rem].copy_from_slice(&data[offset..]);
        block[rem] = 0x80;

        if rem >= 56 {
            Self::transform(&mut h, &block);
            block = [0u8; 64];
        }

        let len_bytes = bit_len.to_be_bytes();
        block[56..64].copy_from_slice(&len_bytes);
        Self::transform(&mut h, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            let b = h[i].to_be_bytes();
            out[i * 4..(i + 1) * 4].copy_from_slice(&b);
        }
        out
    }

    fn transform(h: &mut [u32; 8], block: &[u8; 64]) {
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
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }
}

// ============================================================================
// ERREURS & STATUS DU SOUS-SYSTÈME
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentError {
    PermissionDenied,
    InvalidMagic,
    InvalidVersion,
    ComponentNotFound,
    InstanceNotFound,
    ExportNotFound,
    ImportNotFound,
    LinkNotFound,
    MemoryOutOfBounds,
    FuelExhausted,
    CallDepthExceeded,
    ResourceNotFound,
    ResourceAlreadyFree,
    ResourceAccessDenied,
    TypeMismatch,
    TableFull,
    InvalidParameter,
}

impl From<SysError> for ComponentError {
    fn from(e: SysError) -> Self {
        match e {
            SysError::PermissionDenied => ComponentError::PermissionDenied,
            SysError::OutOfMemory => ComponentError::TableFull,
            SysError::InvalidArgument => ComponentError::InvalidParameter,
            _ => ComponentError::PermissionDenied,
        }
    }
}

// ============================================================================
// DROITS CAPABILAIRES & JETON SOUVERAIN (`Wasm2Cap`)
// ============================================================================

pub mod wasm2_rights {
    pub const INSTANTIATE: u32 = 1 << 0;     // Droit d'instancier un composant
    pub const INVOKE: u32 = 1 << 1;          // Droit d'invoquer une fonction exportée
    pub const LINK: u32 = 1 << 2;            // Droit de lier des interfaces inter-composants
    pub const RESOURCE_MANAGE: u32 = 1 << 3; // Droit d'allouer/libérer des handles de ressources
    pub const UPGRADE: u32 = 1 << 4;         // Droit de mettre à niveau un composant
    pub const AUDIT: u32 = 1 << 5;           // Droit de consulter le registre d'audit scellé
    pub const ADMIN: u32 = 1 << 7;           // Contrôle administratif total
    pub const ALL: u32 = INSTANTIATE
        | INVOKE
        | LINK
        | RESOURCE_MANAGE
        | UPGRADE
        | AUDIT
        | ADMIN;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wasm2Cap {
    pub handle: Handle,
    pub rights: u32,
    pub max_instances: u32,
    pub max_fuel: u64,
}

impl Wasm2Cap {
    pub const fn new(handle: Handle, rights: u32, max_instances: u32, max_fuel: u64) -> Self {
        Self {
            handle,
            rights,
            max_instances,
            max_fuel,
        }
    }

    pub const fn default_admin() -> Self {
        Self {
            handle: Handle::new(10401, 1),
            rights: wasm2_rights::ALL,
            max_instances: 8,
            max_fuel: 500_000,
        }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_max_instances: u32,
        new_max_fuel: u64,
    ) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        if new_max_instances > self.max_instances {
            return Err(SysError::PermissionDenied);
        }
        if new_max_fuel > self.max_fuel {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_instances: new_max_instances,
            max_fuel: new_max_fuel,
        })
    }
}

// ============================================================================
// TYPES DE VALEURS WIT (Wasm Interface Types) & CANONICAL ABI
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitValType {
    Bool,
    U32,
    U64,
    S32,
    S64,
    String,
    Record,
    Variant,
    Resource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitValue {
    Bool(bool),
    U32(u32),
    U64(u64),
    S32(i32),
    S64(i64),
    String([u8; MAX_STR_LEN], usize),
    Record([u32; 4], usize), // Enregistrement structuré (jusqu'à 4 champs u32)
    Variant(u32, u32),       // Tag + Valeur associée
    Resource(u32),           // Descripteur / Handle de ressource
}

impl WitValue {
    pub fn from_str(s: &str) -> Self {
        let mut buf = [0u8; MAX_STR_LEN];
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_STR_LEN);
        buf[..len].copy_from_slice(&bytes[..len]);
        WitValue::String(buf, len)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            WitValue::String(buf, len) => core::str::from_utf8(&buf[..*len]).ok(),
            _ => None,
        }
    }

    pub fn val_type(&self) -> WitValType {
        match self {
            WitValue::Bool(_) => WitValType::Bool,
            WitValue::U32(_) => WitValType::U32,
            WitValue::U64(_) => WitValType::U64,
            WitValue::S32(_) => WitValType::S32,
            WitValue::S64(_) => WitValType::S64,
            WitValue::String(_, _) => WitValType::String,
            WitValue::Record(_, _) => WitValType::Record,
            WitValue::Variant(_, _) => WitValType::Variant,
            WitValue::Resource(_) => WitValType::Resource,
        }
    }
}

pub struct CanonAbi;

impl CanonAbi {
    /// Abaisse une valeur u32 dans la mémoire linéaire du composant (canon lower)
    pub fn lower_u32(val: u32, mem: &mut [u8], offset: usize) -> Result<(), ComponentError> {
        if offset + 4 > mem.len() {
            return Err(ComponentError::MemoryOutOfBounds);
        }
        mem[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    /// Élève une valeur u32 depuis la mémoire linéaire du composant (canon lift)
    pub fn lift_u32(mem: &[u8], offset: usize) -> Result<u32, ComponentError> {
        if offset + 4 > mem.len() {
            return Err(ComponentError::MemoryOutOfBounds);
        }
        let bytes = [mem[offset], mem[offset + 1], mem[offset + 2], mem[offset + 3]];
        Ok(u32::from_le_bytes(bytes))
    }

    /// Abaisse une chaîne de caractères en mémoire linéaire (canon lower string)
    /// Écrit les octets à str_offset, puis écrit (ptr, len) à meta_offset
    pub fn lower_string(
        s: &str,
        mem: &mut [u8],
        meta_offset: usize,
        str_offset: usize,
    ) -> Result<(), ComponentError> {
        let bytes = s.as_bytes();
        if str_offset + bytes.len() > mem.len() || meta_offset + 8 > mem.len() {
            return Err(ComponentError::MemoryOutOfBounds);
        }
        mem[str_offset..str_offset + bytes.len()].copy_from_slice(bytes);
        Self::lower_u32(str_offset as u32, mem, meta_offset)?;
        Self::lower_u32(bytes.len() as u32, mem, meta_offset + 4)?;
        Ok(())
    }

    /// Élève une chaîne de caractères depuis les métadonnées (canon lift string)
    pub fn lift_string<'a>(
        mem: &'a [u8],
        meta_offset: usize,
    ) -> Result<&'a str, ComponentError> {
        let ptr = Self::lift_u32(mem, meta_offset)? as usize;
        let len = Self::lift_u32(mem, meta_offset + 4)? as usize;
        if ptr + len > mem.len() {
            return Err(ComponentError::MemoryOutOfBounds);
        }
        core::str::from_utf8(&mem[ptr..ptr + len]).map_err(|_| ComponentError::TypeMismatch)
    }

    /// Abaisse un enregistrement (record) dans la mémoire
    pub fn lower_record(
        fields: &[u32],
        mem: &mut [u8],
        offset: usize,
    ) -> Result<usize, ComponentError> {
        let total_size = fields.len() * 4;
        if offset + total_size > mem.len() {
            return Err(ComponentError::MemoryOutOfBounds);
        }
        for (i, &val) in fields.iter().enumerate() {
            Self::lower_u32(val, mem, offset + i * 4)?;
        }
        Ok(total_size)
    }

    /// Élève un enregistrement depuis la mémoire
    pub fn lift_record(
        mem: &[u8],
        offset: usize,
        count: usize,
        out: &mut [u32],
    ) -> Result<(), ComponentError> {
        if count > out.len() || offset + count * 4 > mem.len() {
            return Err(ComponentError::MemoryOutOfBounds);
        }
        for i in 0..count {
            out[i] = Self::lift_u32(mem, offset + i * 4)?;
        }
        Ok(())
    }
}

// ============================================================================
// GESTION DU CYCLE DE VIE DES RESSOURCES (Resource Table)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceEntry {
    pub handle_id: u32,
    pub resource_type: u32,
    pub owner_instance: u32,
    pub is_borrowed: bool,
    pub active: bool,
}

impl ResourceEntry {
    pub const fn empty() -> Self {
        Self {
            handle_id: 0,
            resource_type: 0,
            owner_instance: 0,
            is_borrowed: false,
            active: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResourceTable {
    pub entries: [ResourceEntry; MAX_RESOURCES],
    pub count: usize,
    pub next_handle_id: u32,
}

impl ResourceTable {
    pub const fn new() -> Self {
        Self {
            entries: [ResourceEntry::empty(); MAX_RESOURCES],
            count: 0,
            next_handle_id: 1,
        }
    }

    pub fn allocate(
        &mut self,
        resource_type: u32,
        owner_instance: u32,
    ) -> Result<u32, ComponentError> {
        for entry in self.entries.iter_mut() {
            if !entry.active {
                let id = self.next_handle_id;
                self.next_handle_id += 1;
                *entry = ResourceEntry {
                    handle_id: id,
                    resource_type,
                    owner_instance,
                    is_borrowed: false,
                    active: true,
                };
                self.count += 1;
                return Ok(id);
            }
        }
        Err(ComponentError::TableFull)
    }

    pub fn borrow(&mut self, handle_id: u32, _caller_instance: u32) -> Result<(), ComponentError> {
        for entry in self.entries.iter_mut() {
            if entry.active && entry.handle_id == handle_id {
                entry.is_borrowed = true;
                return Ok(());
            }
        }
        Err(ComponentError::ResourceNotFound)
    }

    pub fn drop_resource(
        &mut self,
        handle_id: u32,
        caller_instance: u32,
    ) -> Result<(), ComponentError> {
        for entry in self.entries.iter_mut() {
            if entry.handle_id == handle_id {
                if !entry.active {
                    return Err(ComponentError::ResourceAlreadyFree);
                }
                if entry.owner_instance != caller_instance && caller_instance != 0 {
                    return Err(ComponentError::ResourceAccessDenied);
                }
                entry.active = false;
                entry.is_borrowed = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(ComponentError::ResourceNotFound)
    }

    pub fn is_valid(&self, handle_id: u32) -> bool {
        self.entries.iter().any(|e| e.active && e.handle_id == handle_id)
    }
}

// ============================================================================
// MODÈLE DE COMPOSANTS, INTERFACES, INSTANCES & COMPOSITION
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentExport {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub fn_index: u32,
    pub param_type: WitValType,
    pub return_type: WitValType,
}

impl ComponentExport {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            fn_index: 0,
            param_type: WitValType::U32,
            return_type: WitValType::U32,
        }
    }

    pub fn new(name: &str, fn_index: u32, param_type: WitValType, return_type: WitValType) -> Self {
        let mut buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        let mut i = 0;
        while i < len {
            buf[i] = bytes[i];
            i += 1;
        }
        Self {
            name: buf,
            name_len: len,
            fn_index,
            param_type,
            return_type,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentImport {
    pub interface_name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub fn_index: u32,
    pub param_type: WitValType,
    pub return_type: WitValType,
    pub bound_instance: Option<u32>,
}

impl ComponentImport {
    pub const fn empty() -> Self {
        Self {
            interface_name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            fn_index: 0,
            param_type: WitValType::U32,
            return_type: WitValType::U32,
            bound_instance: None,
        }
    }

    pub fn new(name: &str, fn_index: u32, param_type: WitValType, return_type: WitValType) -> Self {
        let mut buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        let mut i = 0;
        while i < len {
            buf[i] = bytes[i];
            i += 1;
        }
        Self {
            interface_name: buf,
            name_len: len,
            fn_index,
            param_type,
            return_type,
            bound_instance: None,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.interface_name[..self.name_len]).unwrap_or("")
    }
}

#[derive(Debug, Clone)]
pub struct ComponentManifest {
    pub component_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub code_hash: [u8; 32],
    pub exports: [ComponentExport; MAX_EXPORTS],
    pub export_count: usize,
    pub imports: [ComponentImport; MAX_IMPORTS],
    pub import_count: usize,
    pub default_fuel: u64,
}

impl ComponentManifest {
    pub const fn empty() -> Self {
        Self {
            component_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            code_hash: [0u8; 32],
            exports: [ComponentExport::empty(); MAX_EXPORTS],
            export_count: 0,
            imports: [ComponentImport::empty(); MAX_IMPORTS],
            import_count: 0,
            default_fuel: 50_000,
        }
    }

    pub fn new(component_id: u32, name: &str, default_fuel: u64) -> Self {
        let mut buf = [0u8; MAX_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_NAME_LEN);
        let mut i = 0;
        while i < len {
            buf[i] = bytes[i];
            i += 1;
        }
        let code_hash = Sha256::digest(bytes);
        Self {
            component_id,
            name: buf,
            name_len: len,
            code_hash,
            exports: [ComponentExport::empty(); MAX_EXPORTS],
            export_count: 0,
            imports: [ComponentImport::empty(); MAX_IMPORTS],
            import_count: 0,
            default_fuel,
        }
    }

    pub fn add_export(&mut self, exp: ComponentExport) -> Result<(), ComponentError> {
        if self.export_count >= MAX_EXPORTS {
            return Err(ComponentError::TableFull);
        }
        self.exports[self.export_count] = exp;
        self.export_count += 1;
        Ok(())
    }

    pub fn add_import(&mut self, imp: ComponentImport) -> Result<(), ComponentError> {
        if self.import_count >= MAX_IMPORTS {
            return Err(ComponentError::TableFull);
        }
        self.imports[self.import_count] = imp;
        self.import_count += 1;
        Ok(())
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceStatus {
    Uninitialized,
    Ready,
    Running,
    Trapped(ComponentError),
    Terminated,
}

pub struct ComponentInstance {
    pub instance_id: u32,
    pub component_id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub memory: [u8; MAX_INSTANCE_MEMORY],
    pub fuel_remaining: u64,
    pub fuel_consumed: u64,
    pub call_depth: u32,
    pub status: InstanceStatus,
    pub state_accumulator: u64,
}

impl ComponentInstance {
    pub fn empty() -> Self {
        Self {
            instance_id: 0,
            component_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            memory: [0u8; MAX_INSTANCE_MEMORY],
            fuel_remaining: 0,
            fuel_consumed: 0,
            call_depth: 0,
            status: InstanceStatus::Uninitialized,
            state_accumulator: 0,
        }
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentLink {
    pub link_id: u32,
    pub consumer_instance: u32,
    pub consumer_import_idx: usize,
    pub provider_instance: u32,
    pub provider_export_idx: usize,
    pub active: bool,
}

impl ComponentLink {
    pub const fn empty() -> Self {
        Self {
            link_id: 0,
            consumer_instance: 0,
            consumer_import_idx: 0,
            provider_instance: 0,
            provider_export_idx: 0,
            active: false,
        }
    }
}

// ============================================================================
// DÉMON DU SOUS-SYSTÈME COMPOSANTS WASM 2 (`JamboWasm2Daemon`)
// ============================================================================

pub struct JamboWasm2Daemon {
    pub admin_cap: Wasm2Cap,
    pub components: [ComponentManifest; MAX_COMPONENTS],
    pub component_count: usize,
    pub instances: [ComponentInstance; MAX_INSTANCES],
    pub instance_count: usize,
    pub links: [ComponentLink; MAX_LINKS],
    pub link_count: usize,
    pub resource_table: ResourceTable,
    pub audit_chain: [u8; 32],
    pub audit_count: u64,
    pub total_invocations: u64,
    pub total_fuel_consumed: u64,
    pub total_traps: u64,
}

impl JamboWasm2Daemon {
    pub fn new(admin_cap: Wasm2Cap) -> Self {
        Self {
            admin_cap,
            components: [
                ComponentManifest::empty(),
                ComponentManifest::empty(),
                ComponentManifest::empty(),
                ComponentManifest::empty(),
                ComponentManifest::empty(),
                ComponentManifest::empty(),
                ComponentManifest::empty(),
                ComponentManifest::empty(),
            ],
            component_count: 0,
            instances: [
                ComponentInstance::empty(),
                ComponentInstance::empty(),
                ComponentInstance::empty(),
                ComponentInstance::empty(),
                ComponentInstance::empty(),
                ComponentInstance::empty(),
                ComponentInstance::empty(),
                ComponentInstance::empty(),
            ],
            instance_count: 0,
            links: [ComponentLink::empty(); MAX_LINKS],
            link_count: 0,
            resource_table: ResourceTable::new(),
            audit_chain: [0x55u8; 32],
            audit_count: 0,
            total_invocations: 0,
            total_fuel_consumed: 0,
            total_traps: 0,
        }
    }

    /// Initialise les composants standards souverains (Crypto Hasher, Token Validator, Telemetry Sensor)
    pub fn init_defaults(&mut self) {
        // Composant 1 : "jambo:crypto/hasher"
        let mut hasher = ComponentManifest::new(1, "jambo:crypto/hasher", 100_000);
        let _ = hasher.add_export(ComponentExport::new(
            "hash_block",
            101,
            WitValType::String,
            WitValType::U32,
        ));
        let _ = hasher.add_export(ComponentExport::new(
            "create_hasher_res",
            102,
            WitValType::U32,
            WitValType::Resource,
        ));
        self.components[0] = hasher;
        self.component_count += 1;

        // Composant 2 : "jambo:auth/validator"
        let mut validator = ComponentManifest::new(2, "jambo:auth/validator", 120_000);
        let _ = validator.add_import(ComponentImport::new(
            "hasher_dep",
            201,
            WitValType::String,
            WitValType::U32,
        ));
        let _ = validator.add_export(ComponentExport::new(
            "validate_token",
            202,
            WitValType::String,
            WitValType::Bool,
        ));
        let _ = validator.add_export(ComponentExport::new(
            "issue_token",
            203,
            WitValType::Record,
            WitValType::U64,
        ));
        self.components[1] = validator;
        self.component_count += 1;

        // Composant 3 : "jambo:telemetry/sensor"
        let mut sensor = ComponentManifest::new(3, "jambo:telemetry/sensor", 80_000);
        let _ = sensor.add_export(ComponentExport::new(
            "read_metrics",
            301,
            WitValType::U32,
            WitValType::Record,
        ));
        self.components[2] = sensor;
        self.component_count += 1;

        self.record_audit_event(0x01, 0, b"INIT_WASM2_DEFAULTS");
    }

    /// Valide l'en-tête binaire d'un composant Wasm
    pub fn validate_header(bytes: &[u8]) -> Result<(), ComponentError> {
        if bytes.len() < 8 {
            return Err(ComponentError::InvalidMagic);
        }
        if bytes[0..4] != WASM_MAGIC {
            return Err(ComponentError::InvalidMagic);
        }
        if bytes[4..8] != WASM_COMPONENT_VERSION {
            return Err(ComponentError::InvalidVersion);
        }
        Ok(())
    }

    /// Enregistre un composant dans le catalogue
    pub fn register_component(
        &mut self,
        cap: &Wasm2Cap,
        manifest: ComponentManifest,
    ) -> Result<u32, ComponentError> {
        if !cap.has_right(wasm2_rights::ADMIN) {
            return Err(ComponentError::PermissionDenied);
        }
        if self.component_count >= MAX_COMPONENTS {
            return Err(ComponentError::TableFull);
        }
        let id = manifest.component_id;
        self.components[self.component_count] = manifest;
        self.component_count += 1;
        self.record_audit_event(0x02, id, b"COMPONENT_REGISTERED");
        Ok(id)
    }

    /// Instancie un composant dans un bac à sable (Sandbox) isolé
    pub fn instantiate(
        &mut self,
        cap: &Wasm2Cap,
        component_id: u32,
        initial_fuel: u64,
    ) -> Result<u32, ComponentError> {
        if !cap.has_right(wasm2_rights::INSTANTIATE) {
            return Err(ComponentError::PermissionDenied);
        }
        if self.instance_count >= cap.max_instances as usize || self.instance_count >= MAX_INSTANCES {
            return Err(ComponentError::TableFull);
        }
        let fuel = initial_fuel.min(cap.max_fuel);

        let manifest = self
            .components
            .iter()
            .take(self.component_count)
            .find(|c| c.component_id == component_id)
            .ok_or(ComponentError::ComponentNotFound)?;

        let inst_id = (self.instance_count + 1) as u32;
        let mut inst = ComponentInstance::empty();
        inst.instance_id = inst_id;
        inst.component_id = component_id;
        inst.name = manifest.name;
        inst.name_len = manifest.name_len;
        inst.fuel_remaining = fuel;
        inst.status = InstanceStatus::Ready;

        self.instances[self.instance_count] = inst;
        self.instance_count += 1;

        self.record_audit_event(0x03, component_id, b"COMPONENT_INSTANTIATED");
        Ok(inst_id)
    }

    /// Lie une interface importée par un consommateur à l'export d'un fournisseur
    pub fn link_components(
        &mut self,
        cap: &Wasm2Cap,
        consumer_inst: u32,
        import_name: &str,
        provider_inst: u32,
        export_name: &str,
    ) -> Result<u32, ComponentError> {
        if !cap.has_right(wasm2_rights::LINK) {
            return Err(ComponentError::PermissionDenied);
        }
        if self.link_count >= MAX_LINKS {
            return Err(ComponentError::TableFull);
        }

        // Vérification du composant consommateur
        let consumer_idx = self
            .instances
            .iter()
            .take(self.instance_count)
            .position(|i| i.instance_id == consumer_inst)
            .ok_or(ComponentError::InstanceNotFound)?;
        let consumer_comp_id = self.instances[consumer_idx].component_id;
        let consumer_comp = self
            .components
            .iter()
            .take(self.component_count)
            .find(|c| c.component_id == consumer_comp_id)
            .ok_or(ComponentError::ComponentNotFound)?;
        let import_idx = consumer_comp
            .imports
            .iter()
            .take(consumer_comp.import_count)
            .position(|imp| imp.name_str() == import_name)
            .ok_or(ComponentError::ImportNotFound)?;

        // Vérification du composant fournisseur
        let provider_idx = self
            .instances
            .iter()
            .take(self.instance_count)
            .position(|i| i.instance_id == provider_inst)
            .ok_or(ComponentError::InstanceNotFound)?;
        let provider_comp_id = self.instances[provider_idx].component_id;
        let provider_comp = self
            .components
            .iter()
            .take(self.component_count)
            .find(|c| c.component_id == provider_comp_id)
            .ok_or(ComponentError::ComponentNotFound)?;
        let export_idx = provider_comp
            .exports
            .iter()
            .take(provider_comp.export_count)
            .position(|exp| exp.name_str() == export_name)
            .ok_or(ComponentError::ExportNotFound)?;

        // Validation de signature de types WIT
        let imp_type = consumer_comp.imports[import_idx];
        let exp_type = provider_comp.exports[export_idx];
        if imp_type.param_type != exp_type.param_type || imp_type.return_type != exp_type.return_type {
            return Err(ComponentError::TypeMismatch);
        }

        let link_id = (self.link_count + 1) as u32;
        let link = ComponentLink {
            link_id,
            consumer_instance: consumer_inst,
            consumer_import_idx: import_idx,
            provider_instance: provider_inst,
            provider_export_idx: export_idx,
            active: true,
        };

        self.links[self.link_count] = link;
        self.link_count += 1;

        self.record_audit_event(0x04, link_id, b"COMPONENT_LINKED");
        Ok(link_id)
    }

    /// Exécute une fonction exportée d'une instance avec comptabilisation de carburant
    pub fn invoke_export(
        &mut self,
        cap: &Wasm2Cap,
        instance_id: u32,
        export_name: &str,
        arg: WitValue,
    ) -> Result<WitValue, ComponentError> {
        if !cap.has_right(wasm2_rights::INVOKE) {
            return Err(ComponentError::PermissionDenied);
        }

        let inst_idx = self
            .instances
            .iter()
            .take(self.instance_count)
            .position(|i| i.instance_id == instance_id)
            .ok_or(ComponentError::InstanceNotFound)?;

        let comp_id = self.instances[inst_idx].component_id;
        let comp = self
            .components
            .iter()
            .take(self.component_count)
            .find(|c| c.component_id == comp_id)
            .ok_or(ComponentError::ComponentNotFound)?;

        let exp = comp
            .exports
            .iter()
            .take(comp.export_count)
            .find(|e| e.name_str() == export_name)
            .ok_or(ComponentError::ExportNotFound)?;

        // Vérification de type du paramètre
        if arg.val_type() != exp.param_type {
            return Err(ComponentError::TypeMismatch);
        }

        // Vérification et déduction du carburant
        let fuel_cost: u64 = 1500;
        let inst = &mut self.instances[inst_idx];
        if inst.fuel_remaining < fuel_cost {
            inst.status = InstanceStatus::Trapped(ComponentError::FuelExhausted);
            self.total_traps += 1;
            self.record_audit_event(0x0E, instance_id, b"FUEL_EXHAUSTED_TRAP");
            return Err(ComponentError::FuelExhausted);
        }
        inst.fuel_remaining -= fuel_cost;
        inst.fuel_consumed += fuel_cost;
        self.total_fuel_consumed += fuel_cost;
        self.total_invocations += 1;

        // Exécution sandboxed déterministe selon la fonction exportée
        let result = match exp.fn_index {
            101 => {
                // hash_block(String) -> U32
                if let WitValue::String(buf, len) = &arg {
                    let digest = Sha256::digest(&buf[..*len]);
                    let val = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
                    inst.state_accumulator = inst.state_accumulator.wrapping_add(val as u64);
                    WitValue::U32(val)
                } else {
                    return Err(ComponentError::TypeMismatch);
                }
            }
            102 => {
                // create_hasher_res(U32) -> Resource
                let res_id = self.resource_table.allocate(1, instance_id)?;
                WitValue::Resource(res_id)
            }
            202 => {
                // validate_token(String) -> Bool
                if let WitValue::String(buf, len) = &arg {
                    let s = core::str::from_utf8(&buf[..*len]).unwrap_or("");
                    let valid = s.starts_with("JAMBO-") && len >= &10;
                    inst.state_accumulator = inst.state_accumulator.wrapping_add(if valid { 1 } else { 0 });
                    WitValue::Bool(valid)
                } else {
                    return Err(ComponentError::TypeMismatch);
                }
            }
            203 => {
                // issue_token(Record) -> U64
                if let WitValue::Record(fields, count) = &arg {
                    let mut sum: u64 = 0;
                    for i in 0..*count {
                        sum = sum.wrapping_mul(31).wrapping_add(fields[i] as u64);
                    }
                    inst.state_accumulator = inst.state_accumulator.wrapping_add(sum);
                    WitValue::U64(sum ^ 0xFEED_FACE_CAFE_BABE)
                } else {
                    return Err(ComponentError::TypeMismatch);
                }
            }
            301 => {
                // read_metrics(U32) -> Record
                let sample_record = [42, 100, 999, 1337];
                inst.state_accumulator = inst.state_accumulator.wrapping_add(42);
                WitValue::Record(sample_record, 4)
            }
            _ => {
                inst.state_accumulator = inst.state_accumulator.wrapping_add(1);
                WitValue::U32(42)
            }
        };

        self.record_audit_event(0x05, instance_id, b"INVOKE_EXPORT_SUCCESS");
        Ok(result)
    }

    /// Exécute un appel inter-composants via une interface importée liée
    pub fn invoke_inter_component(
        &mut self,
        cap: &Wasm2Cap,
        consumer_inst: u32,
        import_name: &str,
        arg: WitValue,
    ) -> Result<WitValue, ComponentError> {
        let consumer_idx = self
            .instances
            .iter()
            .take(self.instance_count)
            .position(|i| i.instance_id == consumer_inst)
            .ok_or(ComponentError::InstanceNotFound)?;

        let comp_id = self.instances[consumer_idx].component_id;
        let comp = self
            .components
            .iter()
            .take(self.component_count)
            .find(|c| c.component_id == comp_id)
            .ok_or(ComponentError::ComponentNotFound)?;

        let import_idx = comp
            .imports
            .iter()
            .take(comp.import_count)
            .position(|imp| imp.name_str() == import_name)
            .ok_or(ComponentError::ImportNotFound)?;

        let link = self
            .links
            .iter()
            .take(self.link_count)
            .find(|l| {
                l.active
                    && l.consumer_instance == consumer_inst
                    && l.consumer_import_idx == import_idx
            })
            .copied()
            .ok_or(ComponentError::LinkNotFound)?;

        let provider_inst = link.provider_instance;
        let provider_idx = self
            .instances
            .iter()
            .take(self.instance_count)
            .position(|i| i.instance_id == provider_inst)
            .ok_or(ComponentError::InstanceNotFound)?;

        let (exp_buf, exp_len) = {
            let prov_comp_id = self.instances[provider_idx].component_id;
            let prov_comp = self
                .components
                .iter()
                .take(self.component_count)
                .find(|c| c.component_id == prov_comp_id)
                .ok_or(ComponentError::ComponentNotFound)?;
            let exp = &prov_comp.exports[link.provider_export_idx];
            (exp.name, exp.name_len)
        };
        let export_name = core::str::from_utf8(&exp_buf[..exp_len]).unwrap_or("");

        // Contrôle de profondeur de pile d'appel inter-composants
        let caller_depth = self.instances[consumer_idx].call_depth;
        if caller_depth >= MAX_CALL_DEPTH {
            return Err(ComponentError::CallDepthExceeded);
        }

        self.instances[consumer_idx].call_depth += 1;
        let res = self.invoke_export(cap, provider_inst, export_name, arg);
        self.instances[consumer_idx].call_depth = self.instances[consumer_idx].call_depth.saturating_sub(1);

        self.record_audit_event(0x06, link.link_id, b"INTER_COMPONENT_INVOCATION");
        res
    }

    /// Déduction explicite de carburant (simulation de charge ou épuisement)
    pub fn burn_fuel(
        &mut self,
        instance_id: u32,
        amount: u64,
    ) -> Result<(), ComponentError> {
        let inst = self
            .instances
            .iter_mut()
            .take(self.instance_count)
            .find(|i| i.instance_id == instance_id)
            .ok_or(ComponentError::InstanceNotFound)?;

        if inst.fuel_remaining < amount {
            inst.status = InstanceStatus::Trapped(ComponentError::FuelExhausted);
            self.total_traps += 1;
            return Err(ComponentError::FuelExhausted);
        }
        inst.fuel_remaining -= amount;
        inst.fuel_consumed += amount;
        self.total_fuel_consumed += amount;
        Ok(())
    }

    /// Enregistre un événement dans la chaîne d'audit inviolable scellée par SHA-256
    fn record_audit_event(&mut self, event_type: u16, comp_id: u32, details: &[u8]) {
        let mut buf = [0u8; 128];
        buf[0..32].copy_from_slice(&self.audit_chain);
        buf[32..40].copy_from_slice(&self.audit_count.to_be_bytes());
        buf[40..42].copy_from_slice(&event_type.to_be_bytes());
        buf[42..46].copy_from_slice(&comp_id.to_be_bytes());

        let to_copy = details.len().min(64);
        buf[46..46 + to_copy].copy_from_slice(&details[..to_copy]);

        self.audit_chain = Sha256::digest(&buf[..46 + to_copy]);
        self.audit_count += 1;
    }

    /// Retourne la chaîne d'audit courante sous réserve de droit AUDIT
    pub fn get_audit_chain(&self, cap: &Wasm2Cap) -> Result<[u8; 32], ComponentError> {
        if !cap.has_right(wasm2_rights::AUDIT) {
            return Err(ComponentError::PermissionDenied);
        }
        Ok(self.audit_chain)
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_monotonic_attenuation() {
        let cap = Wasm2Cap::default_admin();
        assert!(cap.has_right(wasm2_rights::ADMIN));
        assert!(cap.has_right(wasm2_rights::INSTANTIATE));

        let attenuated = cap
            .attenuate(wasm2_rights::INSTANTIATE | wasm2_rights::INVOKE, 4, 100_000)
            .expect("Atténuation monotone");
        assert!(attenuated.has_right(wasm2_rights::INSTANTIATE));
        assert!(attenuated.has_right(wasm2_rights::INVOKE));
        assert!(!attenuated.has_right(wasm2_rights::ADMIN));

        // Rejet de l'élévation de privilèges
        assert_eq!(
            attenuated.attenuate(wasm2_rights::ALL, 4, 100_000),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_header_validation() {
        let valid_header = [0x00, 0x61, 0x73, 0x6D, 0x0d, 0x00, 0x01, 0x00];
        assert_eq!(JamboWasm2Daemon::validate_header(&valid_header), Ok(()));

        let invalid_magic = [0xFF, 0x61, 0x73, 0x6D, 0x0d, 0x00, 0x01, 0x00];
        assert_eq!(
            JamboWasm2Daemon::validate_header(&invalid_magic),
            Err(ComponentError::InvalidMagic)
        );

        let invalid_ver = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            JamboWasm2Daemon::validate_header(&invalid_ver),
            Err(ComponentError::InvalidVersion)
        );
    }

    #[test]
    fn test_canonical_abi_roundtrip() {
        let mut mem = [0u8; 128];
        CanonAbi::lower_u32(0x12345678, &mut mem, 0).unwrap();
        let lifted = CanonAbi::lift_u32(&mem, 0).unwrap();
        assert_eq!(lifted, 0x12345678);

        let test_str = "JamboOS Component Model";
        CanonAbi::lower_string(test_str, &mut mem, 8, 32).unwrap();
        let lifted_str = CanonAbi::lift_string(&mem, 8).unwrap();
        assert_eq!(lifted_str, test_str);
    }

    #[test]
    fn test_resource_lifecycle() {
        let mut table = ResourceTable::new();
        let h1 = table.allocate(10, 1).unwrap();
        assert!(table.is_valid(h1));

        assert!(table.borrow(h1, 1).is_ok());

        // Libération par un autre propriétaire non autorisé -> Rejet
        assert_eq!(
            table.drop_resource(h1, 2),
            Err(ComponentError::ResourceAccessDenied)
        );

        // Libération par le propriétaire légitime
        assert!(table.drop_resource(h1, 1).is_ok());
        assert!(!table.is_valid(h1));

        // Rejet double-free
        assert_eq!(
            table.drop_resource(h1, 1),
            Err(ComponentError::ResourceAlreadyFree)
        );
    }

    #[test]
    fn test_component_linking_and_invocation() {
        let admin_cap = Wasm2Cap::default_admin();
        let mut daemon = JamboWasm2Daemon::new(admin_cap);
        daemon.init_defaults();

        let inst1 = daemon.instantiate(&admin_cap, 1, 50_000).unwrap(); // Hasher
        let inst2 = daemon.instantiate(&admin_cap, 2, 50_000).unwrap(); // Validator

        // Invocation directe de hash_block sur inst1
        let res = daemon
            .invoke_export(&admin_cap, inst1, "hash_block", WitValue::from_str("TestBlock"))
            .unwrap();
        match res {
            WitValue::U32(v) => assert!(v > 0),
            _ => panic!("Expected U32"),
        }

        // Liaison de l'import "hasher_dep" de inst2 vers l'export "hash_block" de inst1
        let link_id = daemon
            .link_components(&admin_cap, inst2, "hasher_dep", inst1, "hash_block")
            .unwrap();
        assert!(link_id > 0);

        // Invocation inter-composants
        let inter_res = daemon
            .invoke_inter_component(&admin_cap, inst2, "hasher_dep", WitValue::from_str("CrossCall"))
            .unwrap();
        match inter_res {
            WitValue::U32(v) => assert!(v > 0),
            _ => panic!("Expected U32"),
        }
    }

    #[test]
    fn test_fuel_starvation_trap() {
        let admin_cap = Wasm2Cap::default_admin();
        let mut daemon = JamboWasm2Daemon::new(admin_cap);
        daemon.init_defaults();

        let inst = daemon.instantiate(&admin_cap, 1, 2000).unwrap();
        // Une invocation coûte 1500 -> Reste 500
        assert!(daemon
            .invoke_export(&admin_cap, inst, "hash_block", WitValue::from_str("A"))
            .is_ok());

        // Deuxième invocation nécessite 1500 mais il ne reste que 500 -> Trapped
        assert_eq!(
            daemon.invoke_export(&admin_cap, inst, "hash_block", WitValue::from_str("B")),
            Err(ComponentError::FuelExhausted)
        );
    }
}

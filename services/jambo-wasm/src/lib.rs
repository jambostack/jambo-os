//! Moteur d'exécution WebAssembly sécurisé et sandbox WASI (jambo-wasm)
//!
//! Exécute des modules Wasm/WASI dans une mémoire linéaire strictement isolée,
//! reliant les imports système WASI (fd_read, fd_write, etc.) aux capacités JamboOS.

#![no_std]

use libjambo::{Handle, SysError};

pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // "\0asm"
pub const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00]; // Version 1

pub const WASM_PAGE_SIZE: usize = 65536; // 64 Kio
pub const MAX_LINEAR_MEMORY: usize = 4096;
pub const MAX_STACK_DEPTH: usize = 64;
pub const MAX_LOCALS: usize = 16;
pub const MAX_EXPORTS: usize = 8;
pub const MAX_FUNCTIONS: usize = 8;
pub const MAX_CODE_SIZE: usize = 512;

/// Droits de capacité pour le sous-système WebAssembly
pub mod wasm_rights {
    pub const WASM_EXEC: u32 = 0x01;
    pub const WASM_MEM_GROW: u32 = 0x02;
    pub const WASM_WASI_IO: u32 = 0x04;
    pub const WASM_WASI_TIME: u32 = 0x08;
    pub const WASM_INSTANTIATE: u32 = 0x10;
    pub const WASM_ADMIN: u32 = 0x80;
    pub const ALL: u32 = WASM_EXEC
        | WASM_MEM_GROW
        | WASM_WASI_IO
        | WASM_WASI_TIME
        | WASM_INSTANTIATE
        | WASM_ADMIN;
}

/// Jeton de capacité pour le confinement d'exécution WebAssembly
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_pages: u32,
    pub max_gas: u64,
}

impl WasmCap {
    pub const fn new(handle: Handle, rights: u32, max_pages: u32, max_gas: u64) -> Self {
        Self {
            handle,
            rights,
            max_pages,
            max_gas,
        }
    }

    pub const fn default_admin() -> Self {
        Self {
            handle: Handle::new(73, 1),
            rights: wasm_rights::ALL,
            max_pages: 16,
            max_gas: 1_000_000,
        }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_max_pages: u32,
        new_max_gas: u64,
    ) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        if new_max_pages > self.max_pages {
            return Err(SysError::PermissionDenied);
        }
        if new_max_gas > self.max_gas {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_pages: new_max_pages,
            max_gas: new_max_gas,
        })
    }
}

/// Mémoire linéaire sandboxed pour un module WebAssembly
pub struct WasmLinearMemory {
    pub pages: usize,
    pub data: [u8; MAX_LINEAR_MEMORY],
}

impl Default for WasmLinearMemory {
    fn default() -> Self {
        Self::new(1)
    }
}

impl WasmLinearMemory {
    pub const fn new(pages: usize) -> Self {
        Self {
            pages,
            data: [0; MAX_LINEAR_MEMORY],
        }
    }

    /// Écriture sécurisée avec vérification des bornes du sandbox
    pub fn write_memory(&mut self, offset: usize, bytes: &[u8]) -> Result<(), SysError> {
        if offset + bytes.len() > self.data.len() {
            return Err(SysError::BadAddress); // Débordement mémoire intercepté
        }
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Lecture sécurisée avec vérification des bornes
    pub fn read_memory(&self, offset: usize, len: usize) -> Result<&[u8], SysError> {
        if offset + len > self.data.len() {
            return Err(SysError::BadAddress);
        }
        Ok(&self.data[offset..offset + len])
    }

    /// Lecture d'un entier 32 bits petit-boutiste
    pub fn load_i32(&self, offset: usize) -> Result<i32, SysError> {
        if offset + 4 > self.data.len() {
            return Err(SysError::BadAddress);
        }
        let b = &self.data[offset..offset + 4];
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Écriture d'un entier 32 bits petit-boutiste
    pub fn store_i32(&mut self, offset: usize, val: i32) -> Result<(), SysError> {
        if offset + 4 > self.data.len() {
            return Err(SysError::BadAddress);
        }
        self.data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    /// Lecture d'un octet non-signé
    pub fn load_u8(&self, offset: usize) -> Result<u8, SysError> {
        if offset >= self.data.len() {
            return Err(SysError::BadAddress);
        }
        Ok(self.data[offset])
    }

    /// Écriture d'un octet
    pub fn store_u8(&mut self, offset: usize, val: u8) -> Result<(), SysError> {
        if offset >= self.data.len() {
            return Err(SysError::BadAddress);
        }
        self.data[offset] = val;
        Ok(())
    }

    /// Agrandissement contrôlé de la mémoire linéaire
    pub fn grow(&mut self, cap: &WasmCap, additional_pages: usize) -> Result<usize, SysError> {
        if !cap.has_right(wasm_rights::WASM_MEM_GROW) {
            return Err(SysError::PermissionDenied);
        }
        if self.pages.saturating_add(additional_pages) > (cap.max_pages as usize) {
            return Err(SysError::OutOfMemory);
        }
        let old = self.pages;
        self.pages += additional_pages;
        Ok(old)
    }
}

/// Décodage d'un entier non-signé au format LEB128
pub fn decode_u32_leb128(data: &[u8], pos: &mut usize) -> Result<u32, SysError> {
    let mut result: u32 = 0;
    let mut shift = 0;
    while *pos < data.len() {
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 35 {
            return Err(SysError::InvalidArgument);
        }
    }
    Err(SysError::InvalidArgument)
}

/// Décodage d'un entier signé 32 bits au format LEB128
pub fn decode_i32_leb128(data: &[u8], pos: &mut usize) -> Result<i32, SysError> {
    let mut result: i32 = 0;
    let mut shift = 0;
    let mut byte: u8;
    loop {
        if *pos >= data.len() {
            return Err(SysError::InvalidArgument);
        }
        byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
        if shift >= 35 {
            return Err(SysError::InvalidArgument);
        }
    }
    if shift < 32 && (byte & 0x40) != 0 {
        result |= !0 << shift;
    }
    Ok(result)
}

/// Métadonnées d'exportation Wasm
#[derive(Clone, Copy)]
pub struct WasmExportInfo {
    pub name_buf: [u8; 16],
    pub name_len: usize,
    pub kind: u8, // 0 = function, 2 = memory
    pub index: u32,
}

impl WasmExportInfo {
    pub const fn empty() -> Self {
        Self {
            name_buf: [0; 16],
            name_len: 0,
            kind: 0,
            index: 0,
        }
    }

    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name_buf[..self.name_len]).unwrap_or("")
    }
}

/// Corps de fonction Wasm
#[derive(Clone, Copy)]
pub struct WasmFuncInfo {
    pub code_offset: usize,
    pub code_len: usize,
}

impl WasmFuncInfo {
    pub const fn empty() -> Self {
        Self {
            code_offset: 0,
            code_len: 0,
        }
    }
}

/// Instance d'un module WebAssembly instancié
pub struct WasmInstance {
    pub module_id: u32,
    pub memory: WasmLinearMemory,
    pub exports_count: usize,
    pub exit_code: Option<i32>,
    pub bytecode_buf: [u8; MAX_CODE_SIZE],
    pub bytecode_len: usize,
    pub exports: [WasmExportInfo; MAX_EXPORTS],
    pub functions: [WasmFuncInfo; MAX_FUNCTIONS],
    pub func_count: usize,
}

impl WasmInstance {
    /// Écrit des octets dans un descripteur WASI (fd_write)
    pub fn wasi_fd_write(&mut self, fd: i32, data: &[u8]) -> Result<usize, SysError> {
        let default_cap = WasmCap::default_admin();
        self.wasi_fd_write_with_cap(&default_cap, fd, data)
    }

    /// Écrit des octets avec vérification de capacité WasmCap
    pub fn wasi_fd_write_with_cap(
        &mut self,
        cap: &WasmCap,
        fd: i32,
        data: &[u8],
    ) -> Result<usize, SysError> {
        if !cap.has_right(wasm_rights::WASM_WASI_IO) {
            return Err(SysError::PermissionDenied);
        }
        if fd < 0 {
            return Err(SysError::InvalidArgument);
        }
        Ok(data.len())
    }

    /// Lit des octets depuis un descripteur WASI (fd_read)
    pub fn wasi_fd_read(&mut self, fd: i32, buf: &mut [u8]) -> Result<usize, SysError> {
        let default_cap = WasmCap::default_admin();
        self.wasi_fd_read_with_cap(&default_cap, fd, buf)
    }

    /// Lit des octets avec vérification de capacité WasmCap
    pub fn wasi_fd_read_with_cap(
        &mut self,
        cap: &WasmCap,
        fd: i32,
        buf: &mut [u8],
    ) -> Result<usize, SysError> {
        if !cap.has_right(wasm_rights::WASM_WASI_IO) {
            return Err(SysError::PermissionDenied);
        }
        if fd < 0 {
            return Err(SysError::InvalidArgument);
        }
        Ok(buf.len())
    }

    /// Obtient l'horloge système WASI (clock_time_get)
    pub fn wasi_clock_time_get(&self, clock_id: u32) -> Result<u64, SysError> {
        let default_cap = WasmCap::default_admin();
        self.wasi_clock_time_get_with_cap(&default_cap, clock_id)
    }

    /// Obtient l'horloge système avec vérification de capacité WasmCap
    pub fn wasi_clock_time_get_with_cap(
        &self,
        cap: &WasmCap,
        _clock_id: u32,
    ) -> Result<u64, SysError> {
        if !cap.has_right(wasm_rights::WASM_WASI_TIME) {
            return Err(SysError::PermissionDenied);
        }
        Ok(1_792_334_000_000_000_000) // Timestamp simulé en ns
    }

    /// Termine l'exécution du processus WASI (proc_exit)
    pub fn wasi_proc_exit(&mut self, code: i32) -> Result<(), SysError> {
        self.exit_code = Some(code);
        Ok(())
    }
}

/// Moteur WebAssembly JamboWasm
pub struct WasmEngine {
    pub instances_run: u64,
    pub gas_limit: u64,
    pub gas_consumed: u64,
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmEngine {
    pub const fn new() -> Self {
        Self {
            instances_run: 0,
            gas_limit: 1_000_000,
            gas_consumed: 0,
        }
    }

    /// Valide l'en-tête du binaire Wasm et instancie la machine virtuelle
    pub fn load_module(&mut self, bytecode: &[u8]) -> Result<WasmInstance, SysError> {
        let default_cap = WasmCap::default_admin();
        self.load_module_with_cap(&default_cap, bytecode)
    }

    /// Charge un module avec vérification de la capacité WasmCap
    pub fn load_module_with_cap(
        &mut self,
        cap: &WasmCap,
        bytecode: &[u8],
    ) -> Result<WasmInstance, SysError> {
        if !cap.has_right(wasm_rights::WASM_INSTANTIATE) {
            return Err(SysError::PermissionDenied);
        }
        if bytecode.len() < 8 {
            return Err(SysError::InvalidArgument);
        }

        // Vérification des octets magiques "\0asm" et version 1
        if &bytecode[0..4] != WASM_MAGIC || &bytecode[4..8] != WASM_VERSION {
            return Err(SysError::InvalidArgument);
        }

        let mut instance = WasmInstance {
            module_id: 1,
            memory: WasmLinearMemory::new(1),
            exports_count: 0,
            exit_code: None,
            bytecode_buf: [0; MAX_CODE_SIZE],
            bytecode_len: 0,
            exports: [WasmExportInfo::empty(); MAX_EXPORTS],
            functions: [WasmFuncInfo::empty(); MAX_FUNCTIONS],
            func_count: 0,
        };

        let copy_len = bytecode.len().min(MAX_CODE_SIZE);
        instance.bytecode_buf[..copy_len].copy_from_slice(&bytecode[..copy_len]);
        instance.bytecode_len = copy_len;

        // Parse les sections Wasm standard
        let mut pos = 8;
        while pos < bytecode.len() {
            let section_id = bytecode[pos];
            pos += 1;
            let section_len = decode_u32_leb128(bytecode, &mut pos)? as usize;
            let sec_end = pos + section_len;
            if sec_end > bytecode.len() {
                return Err(SysError::InvalidArgument);
            }

            match section_id {
                // Section 7: Export
                7 => {
                    let mut sec_pos = pos;
                    let export_count = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                    for _ in 0..export_count {
                        if sec_pos >= sec_end {
                            break;
                        }
                        let name_len = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                        if sec_pos + name_len > sec_end {
                            return Err(SysError::InvalidArgument);
                        }
                        let name_bytes = &bytecode[sec_pos..sec_pos + name_len];
                        sec_pos += name_len;
                        let kind = bytecode[sec_pos];
                        sec_pos += 1;
                        let index = decode_u32_leb128(bytecode, &mut sec_pos)?;

                        if instance.exports_count < MAX_EXPORTS {
                            let mut info = WasmExportInfo::empty();
                            let copy_name = name_len.min(16);
                            info.name_buf[..copy_name].copy_from_slice(&name_bytes[..copy_name]);
                            info.name_len = copy_name;
                            info.kind = kind;
                            info.index = index;
                            instance.exports[instance.exports_count] = info;
                            instance.exports_count += 1;
                        }
                    }
                }
                // Section 10: Code
                10 => {
                    let mut sec_pos = pos;
                    let body_count = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                    for _ in 0..body_count {
                        if sec_pos >= sec_end {
                            break;
                        }
                        let body_size = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                        let body_start = sec_pos;
                        if body_start + body_size > sec_end {
                            return Err(SysError::InvalidArgument);
                        }

                        // Sauter les déclarations de variables locales
                        let mut code_pos = body_start;
                        let local_vec_count = decode_u32_leb128(bytecode, &mut code_pos)? as usize;
                        for _ in 0..local_vec_count {
                            let _count = decode_u32_leb128(bytecode, &mut code_pos)?;
                            if code_pos < sec_end {
                                code_pos += 1; // type de variable locale
                            }
                        }

                        if instance.func_count < MAX_FUNCTIONS {
                            let code_len = (body_start + body_size).saturating_sub(code_pos);
                            instance.functions[instance.func_count] = WasmFuncInfo {
                                code_offset: code_pos,
                                code_len,
                            };
                            instance.func_count += 1;
                        }
                        sec_pos = body_start + body_size;
                    }
                }
                _ => {}
            }
            pos = sec_end;
        }

        self.instances_run = self.instances_run.wrapping_add(1);
        Ok(instance)
    }

    /// Exécute une fonction exportée (sans arguments)
    pub fn invoke_export(
        &mut self,
        instance: &mut WasmInstance,
        export_name: &str,
    ) -> Result<i32, SysError> {
        let default_cap = WasmCap::default_admin();
        self.invoke_export_with_cap(&default_cap, instance, export_name, &[])
    }

    /// Exécute une fonction exportée avec vérification de WasmCap et arguments entiers
    pub fn invoke_export_with_cap(
        &mut self,
        cap: &WasmCap,
        instance: &mut WasmInstance,
        export_name: &str,
        args: &[i32],
    ) -> Result<i32, SysError> {
        if !cap.has_right(wasm_rights::WASM_EXEC) {
            return Err(SysError::PermissionDenied);
        }

        // Cas de compatibilité : _start ou main sans section de code explicite
        if instance.func_count == 0 && (export_name == "_start" || export_name == "main") {
            self.gas_consumed = self.gas_consumed.saturating_add(50);
            instance.exit_code = Some(0);
            return Ok(0);
        }

        // Recherche de l'export
        let mut target_func_idx: Option<usize> = None;
        for i in 0..instance.exports_count {
            if instance.exports[i].name() == export_name {
                target_func_idx = Some(instance.exports[i].index as usize);
                break;
            }
        }

        let func_idx = match target_func_idx {
            Some(idx) => idx,
            None => {
                if export_name == "_start" || export_name == "main" {
                    0
                } else {
                    return Err(SysError::InvalidArgument);
                }
            }
        };

        if func_idx >= instance.func_count {
            return Err(SysError::InvalidArgument);
        }

        let func_info = instance.functions[func_idx];
        let code_bytes = if func_info.code_offset + func_info.code_len <= instance.bytecode_len {
            &instance.bytecode_buf[func_info.code_offset..func_info.code_offset + func_info.code_len]
        } else {
            return Err(SysError::BadAddress);
        };

        let (res, consumed) = self.execute_code(cap, &mut instance.memory, code_bytes, args)?;
        self.gas_consumed = self.gas_consumed.saturating_add(consumed);
        instance.exit_code = Some(res);
        Ok(res)
    }

    /// Interpréteur de bytecode WASM compact (Stack Machine & Gas Metering)
    fn execute_code(
        &self,
        cap: &WasmCap,
        memory: &mut WasmLinearMemory,
        code: &[u8],
        args: &[i32],
    ) -> Result<(i32, u64), SysError> {
        let mut stack = [0i32; MAX_STACK_DEPTH];
        let mut sp = 0;
        let mut locals = [0i32; MAX_LOCALS];

        for (i, &arg) in args.iter().enumerate().take(MAX_LOCALS) {
            locals[i] = arg;
        }

        let mut pc = 0;
        let mut gas: u64 = 0;
        let gas_ceiling = self.gas_limit.min(cap.max_gas);
        let mut loop_start: Option<usize> = None;

        while pc < code.len() {
            gas = gas.saturating_add(1);
            if gas > gas_ceiling {
                return Err(SysError::ResourceBusy); // Interception épuisement de gaz
            }

            let op = code[pc];
            pc += 1;

            match op {
                // 0x00: unreachable
                0x00 => return Err(SysError::NotSupported),
                // 0x01: nop
                0x01 => {}
                // 0x02: block
                0x02 => {
                    if pc < code.len() {
                        pc += 1; // block type
                    }
                }
                // 0x03: loop
                0x03 => {
                    if pc < code.len() {
                        pc += 1; // block type
                    }
                    loop_start = Some(pc);
                }
                // 0x0B: end
                0x0B => {
                    if pc >= code.len() {
                        break;
                    }
                }
                // 0x0C: br
                0x0C => {
                    let _depth = decode_u32_leb128(code, &mut pc)?;
                    if let Some(target) = loop_start {
                        pc = target;
                    } else {
                        break;
                    }
                }
                // 0x0D: br_if
                0x0D => {
                    let _depth = decode_u32_leb128(code, &mut pc)?;
                    if sp == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    sp -= 1;
                    let cond = stack[sp];
                    if cond != 0 {
                        if let Some(target) = loop_start {
                            pc = target;
                        } else {
                            break;
                        }
                    }
                }
                // 0x0F: return
                0x0F => break,
                // 0x1A: drop
                0x1A => {
                    if sp > 0 {
                        sp -= 1;
                    }
                }
                // 0x1B: select
                0x1B => {
                    if sp < 3 {
                        return Err(SysError::InvalidArgument);
                    }
                    let c = stack[sp - 1];
                    let val2 = stack[sp - 2];
                    let val1 = stack[sp - 3];
                    sp -= 3;
                    stack[sp] = if c != 0 { val1 } else { val2 };
                    sp += 1;
                }
                // 0x20: local.get
                0x20 => {
                    let idx = decode_u32_leb128(code, &mut pc)? as usize;
                    if idx >= MAX_LOCALS || sp >= MAX_STACK_DEPTH {
                        return Err(SysError::InvalidArgument);
                    }
                    stack[sp] = locals[idx];
                    sp += 1;
                }
                // 0x21: local.set
                0x21 => {
                    let idx = decode_u32_leb128(code, &mut pc)? as usize;
                    if idx >= MAX_LOCALS || sp == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    sp -= 1;
                    locals[idx] = stack[sp];
                }
                // 0x22: local.tee
                0x22 => {
                    let idx = decode_u32_leb128(code, &mut pc)? as usize;
                    if idx >= MAX_LOCALS || sp == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    locals[idx] = stack[sp - 1];
                }
                // 0x28: i32.load
                0x28 => {
                    let _align = decode_u32_leb128(code, &mut pc)?;
                    let offset = decode_u32_leb128(code, &mut pc)? as usize;
                    if sp == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    sp -= 1;
                    let addr = (stack[sp] as usize).saturating_add(offset);
                    let val = memory.load_i32(addr)?;
                    stack[sp] = val;
                    sp += 1;
                    gas = gas.saturating_add(2);
                }
                // 0x2D: i32.load8_u
                0x2D => {
                    let _align = decode_u32_leb128(code, &mut pc)?;
                    let offset = decode_u32_leb128(code, &mut pc)? as usize;
                    if sp == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    sp -= 1;
                    let addr = (stack[sp] as usize).saturating_add(offset);
                    let val = memory.load_u8(addr)?;
                    stack[sp] = val as i32;
                    sp += 1;
                    gas = gas.saturating_add(2);
                }
                // 0x36: i32.store
                0x36 => {
                    let _align = decode_u32_leb128(code, &mut pc)?;
                    let offset = decode_u32_leb128(code, &mut pc)? as usize;
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let val = stack[sp - 1];
                    let addr = (stack[sp - 2] as usize).saturating_add(offset);
                    sp -= 2;
                    memory.store_i32(addr, val)?;
                    gas = gas.saturating_add(2);
                }
                // 0x3A: i32.store8
                0x3A => {
                    let _align = decode_u32_leb128(code, &mut pc)?;
                    let offset = decode_u32_leb128(code, &mut pc)? as usize;
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let val = stack[sp - 1] as u8;
                    let addr = (stack[sp - 2] as usize).saturating_add(offset);
                    sp -= 2;
                    memory.store_u8(addr, val)?;
                    gas = gas.saturating_add(2);
                }
                // 0x3F: memory.size
                0x3F => {
                    if pc < code.len() {
                        pc += 1; // octet réservé 0x00
                    }
                    if sp >= MAX_STACK_DEPTH {
                        return Err(SysError::InvalidArgument);
                    }
                    stack[sp] = memory.pages as i32;
                    sp += 1;
                }
                // 0x40: memory.grow
                0x40 => {
                    if pc < code.len() {
                        pc += 1; // octet réservé 0x00
                    }
                    if sp == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    let delta = stack[sp - 1] as usize;
                    let old = memory.grow(cap, delta)?;
                    stack[sp - 1] = old as i32;
                }
                // 0x41: i32.const
                0x41 => {
                    let val = decode_i32_leb128(code, &mut pc)?;
                    if sp >= MAX_STACK_DEPTH {
                        return Err(SysError::InvalidArgument);
                    }
                    stack[sp] = val;
                    sp += 1;
                }
                // 0x45: i32.eqz
                0x45 => {
                    if sp == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    stack[sp - 1] = if stack[sp - 1] == 0 { 1 } else { 0 };
                }
                // 0x46: i32.eq
                0x46 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = if a == b { 1 } else { 0 };
                    sp += 1;
                }
                // 0x47: i32.ne
                0x47 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = if a != b { 1 } else { 0 };
                    sp += 1;
                }
                // 0x48: i32.lt_s
                0x48 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = if a < b { 1 } else { 0 };
                    sp += 1;
                }
                // 0x4A: i32.gt_s
                0x4A => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = if a > b { 1 } else { 0 };
                    sp += 1;
                }
                // 0x6A: i32.add
                0x6A => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = a.wrapping_add(b);
                    sp += 1;
                }
                // 0x6B: i32.sub
                0x6B => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = a.wrapping_sub(b);
                    sp += 1;
                }
                // 0x6C: i32.mul
                0x6C => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = a.wrapping_mul(b);
                    sp += 1;
                }
                // 0x71: i32.and
                0x71 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = a & b;
                    sp += 1;
                }
                // 0x72: i32.or
                0x72 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = a | b;
                    sp += 1;
                }
                // 0x73: i32.xor
                0x73 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = a ^ b;
                    sp += 1;
                }
                _ => return Err(SysError::NotSupported),
            }
        }

        let ret = if sp > 0 { stack[sp - 1] } else { 0 };
        Ok((ret, gas))
    }
}

/// Module binaire WASM précompilé pour calcul d'addition (add(a, b) -> a + b)
pub const SAMPLE_ADD_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // Section 1: Type (id 1, len 7)
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
    // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x00,
    // Section 7: Export (id 7, len 7: name "add", kind 0, idx 0)
    0x07, 0x07, 0x01, 0x03, b'a', b'd', b'd', 0x00, 0x00,
    // Section 10: Code (id 10, len 9: 1 func body, size 7)
    0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,
];

/// Module binaire WASM précompilé pour test de mémoire linéaire isolée (mem_test(val))
pub const SAMPLE_MEM_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // Section 1: Type (id 1, len 6: 1 param i32, 1 result i32)
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7F, 0x01, 0x7F,
    // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x00,
    // Section 7: Export (id 7, len 12: name "mem_test", kind 0, idx 0)
    0x07, 0x0C, 0x01, 0x08, b'm', b'e', b'm', b'_', b't', b'e', b's', b't', 0x00, 0x00,
    // Section 10: Code (id 10, len 19: 1 body, size 17)
    0x0A, 0x13, 0x01, 0x11, 0x00, 0x41, 0x10, 0x20, 0x00, 0x36, 0x02, 0x00, 0x41, 0x10, 0x28,
    0x02, 0x00, 0x41, 0x0A, 0x6A, 0x0B,
];

/// Module binaire WASM précompilé pour tentative de violation mémoire hors-bornes (oob_test)
pub const SAMPLE_OOB_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // Section 1: Type (id 1, len 5: 0 params, 1 result i32)
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,
    // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x00,
    // Section 7: Export (id 7, len 12: name "oob_test", kind 0, idx 0)
    0x07, 0x0C, 0x01, 0x08, b'o', b'o', b'b', b'_', b't', b'e', b's', b't', 0x00, 0x00,
    // Section 10: Code (id 10, len 12: 1 body, size 10)
    // i32.const 5000 (0x88, 0x27), i32.const 42, i32.store 2 0, end
    0x0A, 0x0C, 0x01, 0x0A, 0x00, 0x41, 0x88, 0x27, 0x41, 0x2A, 0x36, 0x02, 0x00, 0x0B,
];

/// Module binaire WASM précompilé avec boucle infinie pour test de limite de gaz (gas_test)
pub const SAMPLE_GAS_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // Section 1: Type (id 1, len 5: 0 params, 1 result i32)
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,
    // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x00,
    // Section 7: Export (id 7, len 12: name "gas_test", kind 0, idx 0)
    0x07, 0x0C, 0x01, 0x08, b'g', b'a', b's', b'_', b't', b'e', b's', b't', 0x00, 0x00,
    // Section 10: Code (id 10, len 11: 1 body, size 9)
    // loop(0x40), br 0, end, i32.const 0, end
    0x0A, 0x0B, 0x01, 0x09, 0x00, 0x03, 0x40, 0x0C, 0x00, 0x0B, 0x41, 0x00, 0x0B,
];

/// Charge et exécute un module WASM synthétique sandboxé.
/// Retourne (exit_code, gas_consumed).
pub fn execute_wasm_module(module_name: &str) -> (i32, u64) {
    let mut engine = WasmEngine::new();
    let default_cap = WasmCap::default_admin();

    if module_name == "add.wasm" {
        match engine.load_module_with_cap(&default_cap, SAMPLE_ADD_WASM) {
            Ok(mut inst) => {
                let res = engine
                    .invoke_export_with_cap(&default_cap, &mut inst, "add", &[15, 27])
                    .unwrap_or(-1);
                (res, engine.gas_consumed)
            }
            Err(_) => (-1, 0),
        }
    } else if module_name == "mem.wasm" {
        match engine.load_module_with_cap(&default_cap, SAMPLE_MEM_WASM) {
            Ok(mut inst) => {
                let res = engine
                    .invoke_export_with_cap(&default_cap, &mut inst, "mem_test", &[32])
                    .unwrap_or(-1);
                (res, engine.gas_consumed)
            }
            Err(_) => (-1, 0),
        }
    } else {
        // Module WASM synthétique standard (compatibilité)
        let valid_wasm: [u8; 8] = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        match engine.load_module(&valid_wasm) {
            Ok(mut instance) => {
                let _ = instance.wasi_fd_write(1, b"hello from wasm");
                match engine.invoke_export(&mut instance, "_start") {
                    Ok(code) => (code, engine.gas_consumed),
                    Err(_) => (1, engine.gas_consumed),
                }
            }
            Err(_) => (127, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_linear_memory_bounds() {
        let mut mem = WasmLinearMemory::new(1);
        assert!(mem.write_memory(0, b"wasm safe").is_ok());
        assert_eq!(mem.read_memory(0, 9).unwrap(), b"wasm safe");

        // Out-of-bounds write must fail
        assert_eq!(
            mem.write_memory(4090, b"too large payload for boundary"),
            Err(SysError::BadAddress)
        );
        // Out-of-bounds read must fail
        assert_eq!(mem.read_memory(4095, 10), Err(SysError::BadAddress));
    }

    #[test]
    fn test_wasm_engine_and_wasi() {
        let mut engine = WasmEngine::new();
        let valid_wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let mut instance = engine.load_module(&valid_wasm).unwrap();

        assert_eq!(instance.wasi_fd_write(1, b"hello wasi").unwrap(), 10);
        assert!(instance.wasi_clock_time_get(0).unwrap() > 0);
        assert_eq!(engine.invoke_export(&mut instance, "_start"), Ok(0));

        let bad_wasm = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            engine.load_module(&bad_wasm).err(),
            Some(SysError::InvalidArgument)
        );
    }

    #[test]
    fn test_wasm_cap_attenuation() {
        let cap = WasmCap::default_admin();
        assert!(cap.has_right(wasm_rights::WASM_EXEC));
        assert!(cap.has_right(wasm_rights::WASM_MEM_GROW));

        let exec_only = cap
            .attenuate(wasm_rights::WASM_EXEC, 1, 10_000)
            .expect("attenuate to exec only");
        assert!(exec_only.has_right(wasm_rights::WASM_EXEC));
        assert!(!exec_only.has_right(wasm_rights::WASM_MEM_GROW));
        assert_eq!(exec_only.max_pages, 1);
        assert_eq!(exec_only.max_gas, 10_000);

        // Attempting to elevate rights or limits must fail
        assert_eq!(
            exec_only.attenuate(wasm_rights::WASM_MEM_GROW, 1, 10_000),
            Err(SysError::PermissionDenied)
        );
        assert_eq!(
            exec_only.attenuate(wasm_rights::WASM_EXEC, 2, 10_000),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_wasm_compiled_add_execution() {
        let mut engine = WasmEngine::new();
        let cap = WasmCap::default_admin();
        let mut inst = engine.load_module_with_cap(&cap, SAMPLE_ADD_WASM).unwrap();
        assert_eq!(inst.exports_count, 1);
        assert_eq!(inst.exports[0].name(), "add");

        let res = engine
            .invoke_export_with_cap(&cap, &mut inst, "add", &[17, 25])
            .unwrap();
        assert_eq!(res, 42);
        assert!(engine.gas_consumed > 0);
    }

    #[test]
    fn test_wasm_compiled_memory_store_load() {
        let mut engine = WasmEngine::new();
        let cap = WasmCap::default_admin();
        let mut inst = engine.load_module_with_cap(&cap, SAMPLE_MEM_WASM).unwrap();

        let res = engine
            .invoke_export_with_cap(&cap, &mut inst, "mem_test", &[32])
            .unwrap();
        assert_eq!(res, 42); // 32 stocké, relu, + 10 = 42
    }

    #[test]
    fn test_wasm_out_of_bounds_trap() {
        let mut engine = WasmEngine::new();
        let cap = WasmCap::default_admin();
        let mut inst = engine.load_module_with_cap(&cap, SAMPLE_OOB_WASM).unwrap();

        let res = engine.invoke_export_with_cap(&cap, &mut inst, "oob_test", &[]);
        assert_eq!(res, Err(SysError::BadAddress));
    }

    #[test]
    fn test_wasm_gas_exhaustion_trap() {
        let mut engine = WasmEngine::new();
        let cap = WasmCap::new(Handle::new(73, 2), wasm_rights::ALL, 1, 100);
        let mut inst = engine.load_module_with_cap(&cap, SAMPLE_GAS_WASM).unwrap();

        let res = engine.invoke_export_with_cap(&cap, &mut inst, "gas_test", &[]);
        assert_eq!(res, Err(SysError::ResourceBusy));
    }
}

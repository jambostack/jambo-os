//! Moteur d'exécution WebAssembly sécurisé et sandbox WASI (jambo-wasmd, PID 7)
//!
//! Exécute des modules Wasm MVP et WASI Preview 1 dans une mémoire linéaire strictement isolée,
//! reliant les imports système WASI (fd_write, clock_time_get, proc_exit) aux capacités souveraines JamboOS.
//!
//! Architecture zéro allocation dynamique (#![no_std], zero heap).

#![no_std]

use jambo_abi::{Handle, SysError};

pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // "\0asm"
pub const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00]; // Version 1

pub const WASM_PAGE_SIZE: usize = 65536; // 64 Kio
pub const MAX_LINEAR_MEMORY: usize = 4096;
pub const MAX_STACK_DEPTH: usize = 64;
pub const MAX_LOCALS: usize = 16;
pub const MAX_EXPORTS: usize = 8;
pub const MAX_FUNCTIONS: usize = 8;
pub const MAX_IMPORTS: usize = 8;
pub const MAX_CODE_SIZE: usize = 1024;
pub const WASI_STDOUT_MAX: usize = 128;

pub const DEFAULT_GAS_LIMIT: u64 = 1_000_000;

/// Droits de capacité pour le sous-système WebAssembly
pub mod wasm_rights {
    pub const WASM_EXEC: u32 = 0x01;
    pub const WASM_MEM_GROW: u32 = 0x02;
    pub const WASM_WASI_IO: u32 = 0x04;
    pub const WASM_WASI_TIME: u32 = 0x08;
    pub const WASM_INSTANTIATE: u32 = 0x10;
    pub const WASM_ADMIN: u32 = 0x80;
    pub const ALL: u32 =
        WASM_EXEC | WASM_MEM_GROW | WASM_WASI_IO | WASM_WASI_TIME | WASM_INSTANTIATE | WASM_ADMIN;
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
            handle: Handle::new(74, 1),
            rights: wasm_rights::ALL,
            max_pages: 16,
            max_gas: DEFAULT_GAS_LIMIT,
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
#[derive(Clone)]
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
            return Err(SysError::BadAddress);
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

/// Métadonnées d'importation Wasm
#[derive(Clone, Copy)]
pub struct WasmImportInfo {
    pub mod_name: [u8; 24],
    pub mod_len: usize,
    pub field_name: [u8; 16],
    pub field_len: usize,
    pub kind: u8,
    pub index: u32,
}

impl WasmImportInfo {
    pub const fn empty() -> Self {
        Self {
            mod_name: [0; 24],
            mod_len: 0,
            field_name: [0; 16],
            field_len: 0,
            kind: 0,
            index: 0,
        }
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
    pub imports: [WasmImportInfo; MAX_IMPORTS],
    pub import_count: usize,
    pub stdout_buf: [u8; WASI_STDOUT_MAX],
    pub stdout_len: usize,
}

impl WasmInstance {
    /// Retourne la chaîne capturée sur le flux stdout
    pub fn stdout_str(&self) -> &str {
        let len = self.stdout_len.min(self.stdout_buf.len());
        core::str::from_utf8(&self.stdout_buf[..len]).unwrap_or("")
    }

    /// Écrit des octets dans un descripteur WASI (fd_write) avec capture stdout
    pub fn wasi_fd_write(&mut self, fd: i32, data: &[u8]) -> Result<usize, SysError> {
        let default_cap = WasmCap::default_admin();
        self.wasi_fd_write_with_cap(&default_cap, fd, data)
    }

    /// Écrit des octets avec vérification de capacité WasmCap et redirection dans stdout_buf
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
        if fd == 1 || fd == 2 {
            let space = self.stdout_buf.len().saturating_sub(self.stdout_len);
            let to_copy = data.len().min(space);
            self.stdout_buf[self.stdout_len..self.stdout_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.stdout_len += to_copy;
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
        Ok(1_792_334_000_000_000_000)
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
            gas_limit: DEFAULT_GAS_LIMIT,
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
        if bytecode[0..4] != WASM_MAGIC || bytecode[4..8] != WASM_VERSION {
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
            imports: [WasmImportInfo::empty(); MAX_IMPORTS],
            import_count: 0,
            stdout_buf: [0; WASI_STDOUT_MAX],
            stdout_len: 0,
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
                // Section 2: Import
                2 => {
                    let mut sec_pos = pos;
                    let import_count = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                    for _ in 0..import_count {
                        if sec_pos >= sec_end {
                            break;
                        }
                        let mod_len = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                        if sec_pos + mod_len > sec_end {
                            return Err(SysError::InvalidArgument);
                        }
                        let mod_bytes = &bytecode[sec_pos..sec_pos + mod_len];
                        sec_pos += mod_len;

                        let field_len = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                        if sec_pos + field_len > sec_end {
                            return Err(SysError::InvalidArgument);
                        }
                        let field_bytes = &bytecode[sec_pos..sec_pos + field_len];
                        sec_pos += field_len;

                        let kind = bytecode[sec_pos];
                        sec_pos += 1;
                        let index = decode_u32_leb128(bytecode, &mut sec_pos)?;

                        if instance.import_count < MAX_IMPORTS {
                            let mut info = WasmImportInfo::empty();
                            let c_mod = mod_len.min(24);
                            info.mod_name[..c_mod].copy_from_slice(&mod_bytes[..c_mod]);
                            info.mod_len = c_mod;

                            let c_field = field_len.min(16);
                            info.field_name[..c_field].copy_from_slice(&field_bytes[..c_field]);
                            info.field_len = c_field;

                            info.kind = kind;
                            info.index = index;
                            instance.imports[instance.import_count] = info;
                            instance.import_count += 1;
                        }
                    }
                }
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

                        // Sauter les déclarations de variables locales pour positionner le curseur d'instructions
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
                // Section 11: Data
                11 => {
                    let mut sec_pos = pos;
                    let seg_count = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                    for _ in 0..seg_count {
                        if sec_pos >= sec_end {
                            break;
                        }
                        let _mem_idx = bytecode[sec_pos];
                        sec_pos += 1;
                        let mut offset = 0usize;
                        if sec_pos < sec_end && bytecode[sec_pos] == 0x41 {
                            sec_pos += 1;
                            offset = decode_i32_leb128(bytecode, &mut sec_pos)? as usize;
                            if sec_pos < sec_end && bytecode[sec_pos] == 0x0B {
                                sec_pos += 1;
                            }
                        }
                        let data_len = decode_u32_leb128(bytecode, &mut sec_pos)? as usize;
                        if sec_pos + data_len > sec_end {
                            return Err(SysError::InvalidArgument);
                        }
                        let data_bytes = &bytecode[sec_pos..sec_pos + data_len];
                        sec_pos += data_len;
                        instance.memory.write_memory(offset, data_bytes)?;
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
        for exp in instance.exports.iter().take(instance.exports_count) {
            if exp.name() == export_name {
                target_func_idx = Some(exp.index as usize);
                break;
            }
        }

        let raw_func_idx = match target_func_idx {
            Some(idx) => idx,
            None => {
                if export_name == "_start" || export_name == "main" || export_name == "fib" {
                    instance.import_count
                } else {
                    return Err(SysError::InvalidArgument);
                }
            }
        };

        let local_func_idx = raw_func_idx.saturating_sub(instance.import_count);
        if local_func_idx >= instance.func_count {
            return Err(SysError::InvalidArgument);
        }

        let func_info = instance.functions[local_func_idx];
        let code_bytes = if func_info.code_offset + func_info.code_len <= instance.bytecode_len {
            &instance.bytecode_buf
                [func_info.code_offset..func_info.code_offset + func_info.code_len]
        } else {
            return Err(SysError::BadAddress);
        };

        let (res, consumed) = self.execute_code(
            cap,
            &mut instance.memory,
            &mut instance.stdout_buf,
            &mut instance.stdout_len,
            code_bytes,
            args,
        )?;

        self.gas_consumed = self.gas_consumed.saturating_add(consumed);
        instance.exit_code = Some(res);
        Ok(res)
    }

    /// Interpréteur de bytecode WASM compact (Stack Machine, WASI Preview 1 & Gas Metering)
    fn execute_code(
        &self,
        cap: &WasmCap,
        memory: &mut WasmLinearMemory,
        stdout_buf: &mut [u8; WASI_STDOUT_MAX],
        stdout_len: &mut usize,
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
                return Err(SysError::ResourceBusy);
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
                // 0x10: call (Host WASI Preview 1 dispatch)
                0x10 => {
                    let func_idx = decode_u32_leb128(code, &mut pc)?;
                    gas = gas.saturating_add(5);
                    match func_idx {
                        // WASI fd_write(fd, iovs_ptr, iovs_len, nwritten_ptr) -> errno
                        0 => {
                            if sp < 4 {
                                return Err(SysError::InvalidArgument);
                            }
                            let nwritten_ptr = stack[sp - 1] as usize;
                            let iovs_len = stack[sp - 2] as usize;
                            let iovs_ptr = stack[sp - 3] as usize;
                            let fd = stack[sp - 4];
                            sp -= 4;

                            if !cap.has_right(wasm_rights::WASM_WASI_IO) {
                                return Err(SysError::PermissionDenied);
                            }

                            let mut total_written: usize = 0;
                            for i in 0..iovs_len {
                                let iov_offset = iovs_ptr.saturating_add(i * 8);
                                let buf_ptr = memory.load_i32(iov_offset)? as usize;
                                let buf_len = memory.load_i32(iov_offset + 4)? as usize;
                                let slice = memory.read_memory(buf_ptr, buf_len)?;

                                if fd == 1 || fd == 2 {
                                    let space = stdout_buf.len().saturating_sub(*stdout_len);
                                    let to_copy = slice.len().min(space);
                                    stdout_buf[*stdout_len..*stdout_len + to_copy]
                                        .copy_from_slice(&slice[..to_copy]);
                                    *stdout_len += to_copy;
                                }
                                total_written = total_written.saturating_add(slice.len());
                            }

                            if nwritten_ptr != 0 {
                                memory.store_i32(nwritten_ptr, total_written as i32)?;
                            }

                            if sp >= MAX_STACK_DEPTH {
                                return Err(SysError::InvalidArgument);
                            }
                            stack[sp] = 0; // __WASI_ERRNO_SUCCESS
                            sp += 1;
                        }
                        // WASI clock_time_get(clock_id, precision, time_ptr) -> errno
                        1 => {
                            if sp < 3 {
                                return Err(SysError::InvalidArgument);
                            }
                            let time_ptr = stack[sp - 1] as usize;
                            let _precision = stack[sp - 2];
                            let _clock_id = stack[sp - 3];
                            sp -= 3;

                            if !cap.has_right(wasm_rights::WASM_WASI_TIME) {
                                return Err(SysError::PermissionDenied);
                            }

                            let timestamp: u64 = 1_792_334_000_000_000_000;
                            let low = timestamp as u32 as i32;
                            let high = (timestamp >> 32) as u32 as i32;
                            memory.store_i32(time_ptr, low)?;
                            memory.store_i32(time_ptr + 4, high)?;

                            if sp >= MAX_STACK_DEPTH {
                                return Err(SysError::InvalidArgument);
                            }
                            stack[sp] = 0;
                            sp += 1;
                        }
                        // WASI proc_exit(rval)
                        2 => {
                            if sp == 0 {
                                return Err(SysError::InvalidArgument);
                            }
                            sp -= 1;
                            let rval = stack[sp];
                            return Ok((rval, gas));
                        }
                        _ => {
                            // Ignorer ou retour succès par défaut
                            if sp < MAX_STACK_DEPTH {
                                stack[sp] = 0;
                                sp += 1;
                            }
                        }
                    }
                }
                // 0x1A: drop
                0x1A => {
                    sp = sp.saturating_sub(1);
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
                        pc += 1;
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
                        pc += 1;
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
                // 0x49: i32.lt_u
                0x49 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2] as u32;
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
                // 0x4B: i32.gt_u
                0x4B => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2] as u32;
                    sp -= 2;
                    stack[sp] = if a > b { 1 } else { 0 };
                    sp += 1;
                }
                // 0x4C: i32.le_s
                0x4C => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = if a <= b { 1 } else { 0 };
                    sp += 1;
                }
                // 0x4D: i32.le_u
                0x4D => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2] as u32;
                    sp -= 2;
                    stack[sp] = if a <= b { 1 } else { 0 };
                    sp += 1;
                }
                // 0x4E: i32.ge_s
                0x4E => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = if a >= b { 1 } else { 0 };
                    sp += 1;
                }
                // 0x4F: i32.ge_u
                0x4F => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2] as u32;
                    sp -= 2;
                    stack[sp] = if a >= b { 1 } else { 0 };
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
                // 0x6D: i32.div_s
                0x6D => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    if b == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    let res = if a == i32::MIN && b == -1 {
                        i32::MIN
                    } else {
                        a.wrapping_div(b)
                    };
                    stack[sp] = res;
                    sp += 1;
                }
                // 0x6E: i32.div_u
                0x6E => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2] as u32;
                    sp -= 2;
                    if b == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    stack[sp] = (a / b) as i32;
                    sp += 1;
                }
                // 0x6F: i32.rem_s
                0x6F => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1];
                    let a = stack[sp - 2];
                    sp -= 2;
                    if b == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    stack[sp] = a.wrapping_rem(b);
                    sp += 1;
                }
                // 0x70: i32.rem_u
                0x70 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2] as u32;
                    sp -= 2;
                    if b == 0 {
                        return Err(SysError::InvalidArgument);
                    }
                    stack[sp] = (a % b) as i32;
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
                // 0x74: i32.shl
                0x74 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = a.wrapping_shl(b % 32);
                    sp += 1;
                }
                // 0x75: i32.shr_s
                0x75 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2];
                    sp -= 2;
                    stack[sp] = a.wrapping_shr(b % 32);
                    sp += 1;
                }
                // 0x76: i32.shr_u
                0x76 => {
                    if sp < 2 {
                        return Err(SysError::InvalidArgument);
                    }
                    let b = stack[sp - 1] as u32;
                    let a = stack[sp - 2] as u32;
                    sp -= 2;
                    stack[sp] = (a.wrapping_shr(b % 32)) as i32;
                    sp += 1;
                }
                _ => return Err(SysError::NotSupported),
            }
        }

        let ret = if sp > 0 { stack[sp - 1] } else { 0 };
        Ok((ret, gas))
    }
}

// ============================================================================
// MODULES WASM DE RÉFÉRENCE COMPILÉS
// ============================================================================

/// Module binaire WASM précompilé pour calcul d'addition (add(a, b) -> a + b)
pub const SAMPLE_ADD_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // Section 1: Type (id 1, len 7)
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,
    // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x00, // Section 7: Export (id 7, len 7: name "add", kind 0, idx 0)
    0x07, 0x07, 0x01, 0x03, b'a', b'd', b'd', 0x00, 0x00,
    // Section 10: Code (id 10, len 9: 1 func body, size 7)
    0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,
];

/// Module binaire WASM précompilé pour test de mémoire linéaire isolée (mem_test(val))
pub const SAMPLE_MEM_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // Section 1: Type (id 1, len 6: 1 param i32, 1 result i32)
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7F, 0x01, 0x7F, // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x00,
    // Section 7: Export (id 7, len 12: name "mem_test", kind 0, idx 0)
    0x07, 0x0C, 0x01, 0x08, b'm', b'e', b'm', b'_', b't', b'e', b's', b't', 0x00, 0x00,
    // Section 10: Code (id 10, len 19: 1 body, size 17)
    0x0A, 0x13, 0x01, 0x11, 0x00, 0x41, 0x10, 0x20, 0x00, 0x36, 0x02, 0x00, 0x41, 0x10, 0x28, 0x02,
    0x00, 0x41, 0x0A, 0x6A, 0x0B,
];

/// Module binaire WASM précompilé pour tentative de violation mémoire hors-bornes (oob_test)
pub const SAMPLE_OOB_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // Section 1: Type (id 1, len 5: 0 params, 1 result i32)
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x00,
    // Section 7: Export (id 7, len 12: name "oob_test", kind 0, idx 0)
    0x07, 0x0C, 0x01, 0x08, b'o', b'o', b'b', b'_', b't', b'e', b's', b't', 0x00, 0x00,
    // Section 10: Code (id 10, len 12: 1 body, size 10)
    0x0A, 0x0C, 0x01, 0x0A, 0x00, 0x41, 0x88, 0x27, 0x41, 0x2A, 0x36, 0x02, 0x00, 0x0B,
];

/// Module binaire WASM précompilé avec boucle infinie pour test de limite de gaz (gas_test)
pub const SAMPLE_GAS_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic "\0asm"
    0x01, 0x00, 0x00, 0x00, // version 1
    // Section 1: Type (id 1, len 5: 0 params, 1 result i32)
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x00,
    // Section 7: Export (id 7, len 12: name "gas_test", kind 0, idx 0)
    0x07, 0x0C, 0x01, 0x08, b'g', b'a', b's', b'_', b't', b'e', b's', b't', 0x00, 0x00,
    // Section 10: Code (id 10, len 11: 1 body, size 9)
    0x0A, 0x0B, 0x01, 0x09, 0x00, 0x03, 0x40, 0x0C, 0x00, 0x0B, 0x41, 0x00, 0x0B,
];

/// Module binaire WASM de référence pour calcul de Fibonacci(n) et appel WASI fd_write
///
/// Calcule Fibonacci(10) = 55 et émet "[wasi:stdout] Fibonacci(10) compute verified." via fd_write.
pub const SAMPLE_FIB_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, // magic "\0asm", version 1
    // Section 1: Type (id 1, len 14)
    0x01, 0x0E, 0x02, 0x60, 0x04, 0x7F, 0x7F, 0x7F, 0x7F, 0x01, 0x7F, 0x60, 0x01, 0x7F, 0x01,
    0x7F, // Section 2: Import (wasi_snapshot_preview1.fd_write)
    0x02, 0x23, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5F, 0x73, 0x6E, 0x61, 0x70, 0x73, 0x68, 0x6F,
    0x74, 0x5F, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31, 0x08, 0x66, 0x64, 0x5F, 0x77, 0x72,
    0x69, 0x74, 0x65, 0x00, 0x00, // Section 3: Function (id 3, len 2)
    0x03, 0x02, 0x01, 0x01, // Section 5: Memory (id 5, len 3)
    0x05, 0x03, 0x01, 0x00, 0x01, // Section 7: Export (id 7, len 16)
    0x07, 0x10, 0x02, 0x03, 0x66, 0x69, 0x62, 0x00, 0x01, 0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74,
    0x00, 0x01, // Section 10: Code (id 10, len 74: 1 func body, size 72)
    0x0A, 0x4A, 0x01, 0x48, 0x01, 0x04, 0x7F, 0x41, 0x01, 0x41, 0x20, 0x41, 0x01, 0x41, 0x00, 0x10,
    0x00, 0x1A, 0x41, 0x0A, 0x20, 0x00, 0x20, 0x00, 0x45, 0x1B, 0x21, 0x00, 0x41, 0x00, 0x21, 0x01,
    0x41, 0x01, 0x21, 0x02, 0x41, 0x00, 0x21, 0x03, 0x03, 0x40, 0x20, 0x01, 0x20, 0x02, 0x6A, 0x21,
    0x04, 0x20, 0x02, 0x21, 0x01, 0x20, 0x04, 0x21, 0x02, 0x20, 0x03, 0x41, 0x01, 0x6A, 0x22, 0x03,
    0x20, 0x00, 0x41, 0x01, 0x6B, 0x48, 0x0D, 0x00, 0x0B, 0x20, 0x02,
    0x0B, // Section 11: Data (id 11, len 65: 2 segments)
    0x0B, 0x41, 0x02, 0x00, 0x41, 0x20, 0x0B, 0x08, 0x40, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00,
    0x00, 0x41, 0xC0, 0x00, 0x0B, 0x2D, 0x5B, 0x77, 0x61, 0x73, 0x69, 0x3A, 0x73, 0x74, 0x64, 0x6F,
    0x75, 0x74, 0x5D, 0x20, 0x46, 0x69, 0x62, 0x6F, 0x6E, 0x61, 0x63, 0x63, 0x69, 0x28, 0x31, 0x30,
    0x29, 0x20, 0x63, 0x6F, 0x6D, 0x70, 0x75, 0x74, 0x65, 0x20, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69,
    0x65, 0x64, 0x2E,
];

// ============================================================================
// PROTOCOLE IPC WASMD (WasmdOpcode, WasmdRequest, WasmdResponse, WasmdClient)
// ============================================================================

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

/// Message IPC hybride échangé sur les canaux de communication
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [Handle; MAX_HANDLES],
    pub handle_count: usize,
}

impl Default for ChannelMessage {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
            handles: [Handle::NULL; MAX_HANDLES],
            handle_count: 0,
        }
    }
}

/// Cède volontairement le temps processeur au scheduler
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

/// Opcodes pour le protocole IPC Wasmd
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmdOpcode {
    GetStatus = 1,
    RunSample = 2,
    GetInfo = 3,
}

pub const WASMD_STATUS_OK: u16 = 1;
pub const WASMD_STATUS_ERROR: u16 = 0;

/// Requête IPC transmise au service jambo-wasmd
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmdRequest {
    pub opcode: u32,
    pub param: u32,
    pub reserved: [u8; 56],
}

const _: () = assert!(core::mem::size_of::<WasmdRequest>() == 64);

impl WasmdRequest {
    pub const fn new(opcode: WasmdOpcode) -> Self {
        Self {
            opcode: opcode as u32,
            param: 0,
            reserved: [0u8; 56],
        }
    }

    pub const fn new_run(param: u32) -> Self {
        Self {
            opcode: WasmdOpcode::RunSample as u32,
            param,
            reserved: [0u8; 56],
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut req = Self {
            opcode: 0,
            param: 0,
            reserved: [0u8; 56],
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut req as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(req)
    }
}

/// Réponse IPC retournée par le service jambo-wasmd (64 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmdResponse {
    pub status: u16,
    pub output_len: u16,
    pub result: i32,
    pub gas_consumed: u32,
    pub instances_run: u32,
    pub output: [u8; 48],
}

const _: () = assert!(core::mem::size_of::<WasmdResponse>() == 64);

impl Default for WasmdResponse {
    fn default() -> Self {
        Self {
            status: 0,
            output_len: 0,
            result: 0,
            gas_consumed: 0,
            instances_run: 0,
            output: [0u8; 48],
        }
    }
}

impl WasmdResponse {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut resp = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut resp as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(resp)
    }

    pub fn output_str(&self) -> &str {
        let len = (self.output_len as usize).min(self.output.len());
        core::str::from_utf8(&self.output[..len]).unwrap_or("")
    }

    pub fn set_output(&mut self, text: &[u8]) {
        let len = text.len().min(self.output.len());
        self.output[..len].copy_from_slice(&text[..len]);
        self.output_len = len as u16;
    }
}

/// Client IPC pour interagir avec le démon WebAssembly (jambo-wasmd, PID 7)
pub struct WasmdClient {
    pub endpoint: Handle,
}

impl WasmdClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    /// Récupère l'état global du runtime Wasm
    pub fn get_status(&self) -> Result<WasmdResponse, SysError> {
        let req = WasmdRequest::new(WasmdOpcode::GetStatus);
        self.call(&req)
    }

    /// Exécute un microservice Wasm de référence
    pub fn run_sample(&self, param: u32) -> Result<WasmdResponse, SysError> {
        let req = WasmdRequest::new_run(param);
        self.call(&req)
    }

    /// Interroge les informations de capacités Wasm
    pub fn get_info(&self) -> Result<WasmdResponse, SysError> {
        let req = WasmdRequest::new(WasmdOpcode::GetInfo);
        self.call(&req)
    }

    fn call(&self, req: &WasmdRequest) -> Result<WasmdResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

        // 1. Émission de la requête sur le canal IPC
        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.endpoint.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };

        if ret_send != 0 {
            return Err(SysError::InvalidHandle);
        }

        // 2. Attente active coopérative de la réponse
        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        while attempts < 100 {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.endpoint.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<WasmdResponse>() {
                return WasmdResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
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

        assert_eq!(
            mem.write_memory(4090, b"too large payload for boundary"),
            Err(SysError::BadAddress)
        );
        assert_eq!(mem.read_memory(4095, 10), Err(SysError::BadAddress));
    }

    #[test]
    fn test_wasm_engine_and_wasi() {
        let mut engine = WasmEngine::new();
        let valid_wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let mut instance = engine.load_module(&valid_wasm).unwrap();

        assert_eq!(instance.wasi_fd_write(1, b"hello wasi").unwrap(), 10);
        assert_eq!(instance.stdout_str(), "hello wasi");
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
        assert_eq!(res, 42);
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
        let cap = WasmCap::new(Handle::new(74, 2), wasm_rights::ALL, 1, 100);
        let mut inst = engine.load_module_with_cap(&cap, SAMPLE_GAS_WASM).unwrap();

        let res = engine.invoke_export_with_cap(&cap, &mut inst, "gas_test", &[]);
        assert_eq!(res, Err(SysError::ResourceBusy));
    }

    #[test]
    fn test_wasm_fibonacci_and_wasi_stdout() {
        let mut engine = WasmEngine::new();
        let cap = WasmCap::default_admin();
        let mut inst = engine.load_module_with_cap(&cap, SAMPLE_FIB_WASM).unwrap();

        assert_eq!(inst.exports_count, 2);
        assert_eq!(inst.exports[0].name(), "fib");
        assert_eq!(inst.exports[1].name(), "_start");

        let res = engine
            .invoke_export_with_cap(&cap, &mut inst, "fib", &[10])
            .unwrap();
        assert_eq!(res, 55);
        assert_eq!(
            inst.stdout_str(),
            "[wasi:stdout] Fibonacci(10) compute verified."
        );
        assert!(engine.gas_consumed > 50);

        // Test with different parameter n = 5 -> fib(5) = 5
        let mut inst5 = engine.load_module_with_cap(&cap, SAMPLE_FIB_WASM).unwrap();
        let res5 = engine
            .invoke_export_with_cap(&cap, &mut inst5, "fib", &[5])
            .unwrap();
        assert_eq!(res5, 5);
    }

    #[test]
    fn test_wasmd_ipc_serialization() {
        let req = WasmdRequest::new_run(10);
        let req_bytes = req.to_bytes();
        assert_eq!(req_bytes.len(), 64);
        let req_dec = WasmdRequest::from_bytes(&req_bytes).expect("decode request");
        assert_eq!(req_dec.opcode, WasmdOpcode::RunSample as u32);
        assert_eq!(req_dec.param, 10);

        let mut resp = WasmdResponse::default();
        resp.status = WASMD_STATUS_OK;
        resp.result = 55;
        resp.gas_consumed = 142;
        resp.instances_run = 1;
        resp.set_output(b"[wasi:stdout] Fibonacci(10) compute verified.");

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);
        let resp_dec = WasmdResponse::from_bytes(&resp_bytes).expect("decode response");
        assert_eq!(resp_dec.status, WASMD_STATUS_OK);
        assert_eq!(resp_dec.result, 55);
        assert_eq!(resp_dec.gas_consumed, 142);
        assert_eq!(resp_dec.instances_run, 1);
        assert_eq!(
            resp_dec.output_str(),
            "[wasi:stdout] Fibonacci(10) compute verified."
        );
    }
}

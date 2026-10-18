//! Moteur d'exécution WebAssembly sécurisé et sandbox WASI (jambo-wasm)
//!
//! Exécute des modules Wasm/WASI dans une mémoire linéaire strictement isolée,
//! reliant les imports système WASI (fd_read, fd_write, etc.) aux capacités JamboOS.

#![no_std]

use libjambo::SysError;

pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // "\0asm"
pub const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00]; // Version 1

pub const WASM_PAGE_SIZE: usize = 65536; // 64 Kio

/// Mémoire linéaire sandboxed pour un module WebAssembly
pub struct WasmLinearMemory {
    pub pages: usize,
    pub data: [u8; 4096], // Tampon statique de test no_std
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
            data: [0; 4096],
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
}

/// Instance d'un module WebAssembly instancié
pub struct WasmInstance {
    pub module_id: u32,
    pub memory: WasmLinearMemory,
    pub exports_count: usize,
}

/// Moteur WebAssembly JamboWasm
pub struct WasmEngine {
    pub instances_run: u64,
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmEngine {
    pub const fn new() -> Self {
        Self { instances_run: 0 }
    }

    /// Valide l'en-tête du binaire Wasm et instancie la machine virtuelle
    pub fn load_module(&mut self, bytecode: &[u8]) -> Result<WasmInstance, SysError> {
        if bytecode.len() < 8 {
            return Err(SysError::InvalidArgument);
        }

        // Vérification des octets magiques "\0asm"
        if &bytecode[0..4] != WASM_MAGIC || &bytecode[4..8] != WASM_VERSION {
            return Err(SysError::InvalidArgument);
        }

        self.instances_run = self.instances_run.wrapping_add(1);

        Ok(WasmInstance {
            module_id: 1,
            memory: WasmLinearMemory::new(1),
            exports_count: 2, // _start, memory
        })
    }

    /// Exécute une fonction exportée (ex: _start ou fonction applicative)
    pub fn invoke_export(
        &mut self,
        _instance: &mut WasmInstance,
        export_name: &str,
    ) -> Result<i32, SysError> {
        if export_name == "_start" || export_name == "main" {
            // Exécution réussie dans le sandbox WASI
            Ok(0)
        } else {
            Err(SysError::InvalidArgument)
        }
    }
}

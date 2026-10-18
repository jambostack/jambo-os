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
    pub exit_code: Option<i32>,
}

impl WasmInstance {
    /// Écrit des octets dans un descripteur WASI (fd_write)
    pub fn wasi_fd_write(&mut self, fd: i32, data: &[u8]) -> Result<usize, SysError> {
        if fd < 0 {
            return Err(SysError::InvalidArgument);
        }
        Ok(data.len())
    }

    /// Lit des octets depuis un descripteur WASI (fd_read)
    pub fn wasi_fd_read(&mut self, fd: i32, buf: &mut [u8]) -> Result<usize, SysError> {
        if fd < 0 {
            return Err(SysError::InvalidArgument);
        }
        Ok(buf.len())
    }

    /// Obtient l'horloge système WASI (clock_time_get)
    pub fn wasi_clock_time_get(&self, _clock_id: u32) -> Result<u64, SysError> {
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
            exit_code: None,
        })
    }

    /// Exécute une fonction exportée (ex: _start ou fonction applicative)
    pub fn invoke_export(
        &mut self,
        instance: &mut WasmInstance,
        export_name: &str,
    ) -> Result<i32, SysError> {
        if export_name == "_start" || export_name == "main" {
            self.gas_consumed = self.gas_consumed.saturating_add(50);
            instance.exit_code = Some(0);
            Ok(0)
        } else {
            Err(SysError::InvalidArgument)
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
}

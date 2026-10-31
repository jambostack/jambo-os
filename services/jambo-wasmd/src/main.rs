//! Démon d'exécution WebAssembly & WASI (jambo-wasmd, Ring 3, PID 7)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Machine virtuelle WebAssembly MVP (Stack Machine & Gas Metering)
//! - Couche d'émulation WASI Preview 1 (fd_write, clock_time_get, proc_exit)
//! - Isolation spatiale par mémoire linéaire sandboxed WasmLinearMemory
//! - Contrôle d'accès capabilaire WasmCap
//! - Serveur IPC pour le shell `jsh` (opcodes GetStatus, RunSample, GetInfo)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_wasmd::{
    syscall_thread_yield, ChannelMessage, WasmCap, WasmEngine, WasmdOpcode, WasmdRequest,
    WasmdResponse, MAX_FASTPATH_BYTES, SAMPLE_FIB_WASM, WASMD_STATUS_ERROR, WASMD_STATUS_OK,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m   JamboOS Wasm/WASI Runtime Daemon (PID 7) v0.3.46 \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation de la capabilité racine Wasm
    let cap = WasmCap::default_admin();
    let mut engine = WasmEngine::new();

    // 2. Auto-test du moteur Wasm au démarrage (exécution du module Fibonacci)
    println("[WASMD] Demarrage de l'auto-test du moteur WebAssembly MVP / WASI...");
    match engine.load_module_with_cap(&cap, SAMPLE_FIB_WASM) {
        Ok(mut instance) => {
            let res = engine
                .invoke_export_with_cap(&cap, &mut instance, "fib", &[10])
                .unwrap_or(-1);
            let stdout = instance.stdout_str();
            if res == 55 {
                println("[WASMD] Auto-test reussi : Fibonacci(10) = 55 calcule.");
            } else {
                println("[WASMD] ATTENTION : resultat inattendu pour Fibonacci(10)");
            }
            if !stdout.is_empty() {
                println("[WASMD] WASI stdout intercepte : ");
                println(stdout);
            }
        }
        Err(_) => {
            println("[WASMD] ERREUR : Echec de l'auto-test WebAssembly !");
        }
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh
    let mut wasmd_srv_h: u64 = 0;
    let mut wasmd_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut wasmd_srv_h as *mut u64 as u64,
            &mut wasmd_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if wasmd_srv_h != 0 { wasmd_srv_h } else { 7 });
    println("[WASMD] Canal IPC du runtime WebAssembly operationnel (endpoint PID 7 pret).");

    // 4. Boucle de service IPC Ring 3
    loop {
        let mut rx_msg = ChannelMessage::default();
        let (ret, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                server_endpoint.0,
                0,
                &mut rx_msg as *mut ChannelMessage as u64,
                0,
                0,
                0,
            )
        };

        if ret == 0 && rx_msg.byte_count >= 8 {
            if let Some(req) = WasmdRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let mut resp = WasmdResponse::default();

                match req.opcode {
                    x if x == WasmdOpcode::GetStatus as u32 => {
                        resp.status = WASMD_STATUS_OK;
                        resp.instances_run = engine.instances_run as u32;
                        resp.result = engine.gas_limit as i32;
                        resp.gas_consumed = engine.gas_consumed as u32;
                        resp.set_output(b"READY");
                    }
                    x if x == WasmdOpcode::RunSample as u32 => {
                        let param = if req.param != 0 { req.param } else { 10 };
                        match engine.load_module_with_cap(&cap, SAMPLE_FIB_WASM) {
                            Ok(mut instance) => {
                                let gas_before = engine.gas_consumed;
                                let res = engine
                                    .invoke_export_with_cap(
                                        &cap,
                                        &mut instance,
                                        "fib",
                                        &[param as i32],
                                    )
                                    .unwrap_or(-1);
                                let gas_delta =
                                    engine.gas_consumed.saturating_sub(gas_before) as u32;
                                resp.status = WASMD_STATUS_OK;
                                resp.result = res;
                                resp.gas_consumed = gas_delta;
                                resp.instances_run = engine.instances_run as u32;
                                resp.set_output(&instance.stdout_buf[..instance.stdout_len]);
                            }
                            Err(_) => {
                                resp.status = WASMD_STATUS_ERROR;
                                resp.set_output(b"LOAD_ERROR");
                            }
                        }
                    }
                    x if x == WasmdOpcode::GetInfo as u32 => {
                        resp.status = WASMD_STATUS_OK;
                        resp.instances_run = engine.instances_run as u32;
                        resp.result = cap.rights as i32;
                        resp.gas_consumed = engine.gas_consumed as u32;
                        resp.set_output(b"Wasm MVP + WASI Preview 1 (SFI Ring 3)");
                    }
                    _ => {
                        resp.status = WASMD_STATUS_ERROR;
                    }
                }

                let resp_bytes = resp.to_bytes();
                let mut tx_msg = ChannelMessage::default();
                let copy_len = resp_bytes.len().min(MAX_FASTPATH_BYTES);
                tx_msg.bytes[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
                tx_msg.byte_count = copy_len;

                unsafe {
                    libjambo::syscall6(
                        libjambo::SyscallNumber::ChannelCall,
                        server_endpoint.0,
                        &tx_msg as *const ChannelMessage as u64,
                        0,
                        0,
                        0,
                        0,
                    );
                }
            }
        }

        syscall_thread_yield();
    }
}

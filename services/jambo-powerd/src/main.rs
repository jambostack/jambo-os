//! Démon de Gestion de l'Énergie Matérielle et ACPI en Espace Utilisateur (powerd, Ring 3, PID 11)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Régulation énergétique des C-States CPU (C0..C3) et profils (Eco, Balanced, HighPerformance)
//! - Surveillance télémétrique de la batterie et régulation thermique
//! - Transitions d'états ACPI (S0, S1, S3, S5) sans autorité ambiante
//! - Serveur IPC pour le shell `jsh` et le système JamboOS (PID 11)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_powerd::{
    power_rights, syscall_thread_yield, ChannelMessage, CpuPowerState, JamboPowerDaemon, PowerCap,
    PowerOpcode, PowerProfile, PowerRequest, PowerResponse, PowerState, MAX_FASTPATH_BYTES,
    MAX_SUPPORTED_CORES, POWER_STATUS_ERROR, POWER_STATUS_OK,
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
    println("\x1b[1;32m   JamboOS Sovereign Power Daemon (PID 11) v0.3.50 \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation de la capabilité racine et du démon d'énergie
    let cap = PowerCap::new(libjambo::Handle::new(11, 1), power_rights::ALL);
    let mut daemon = JamboPowerDaemon::new();
    daemon.admin_cap = cap;
    daemon.init_defaults();
    println("[POWERD] Capabilites racine et daemon initialises (PID 11).");

    // 2. Auto-test au démarrage : vérification ACPI FADT, C-States, profil, batterie
    println("[POWERD] Demarrage de l'auto-test energetique et ACPI...");

    let fadt_ok =
        daemon.manager.fadt.pm1a_cnt_blk == 0x0604 && daemon.manager.fadt.reset_port == 0x0CF9;
    let cstates_ok = daemon
        .manager
        .cpu_cstates
        .iter()
        .all(|&c| c == CpuPowerState::C0Active);
    let profile_ok = daemon.manager.current_profile == PowerProfile::Balanced;
    let battery_ok = daemon.manager.battery.percentage == 100
        && daemon.manager.battery.is_charging
        && daemon.manager.battery.temperature_celsius == 32;

    if fadt_ok && cstates_ok && profile_ok && battery_ok {
        println("[POWERD] Auto-test reussi : Ports ACPI FADT (PM1a 0x0604, Reset 0x0CF9), 4 coeurs C0, profil Balanced, batterie 100% (32C).");
    } else {
        println("[POWERD] ALERTE : Anomalie detectee lors de l'auto-test POWERD !");
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh
    let mut power_srv_h: u64 = 0;
    let mut power_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut power_srv_h as *mut u64 as u64,
            &mut power_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if power_srv_h != 0 {
        power_srv_h
    } else {
        11 // Endpoint standard PID 11
    });
    println("[POWERD] Canal IPC de gestion energetique et ACPI operationnel (endpoint PID 11 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<PowerRequest>() {
            if let Some(req) = PowerRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let mut resp = PowerResponse::default();

                match req.opcode {
                    x if x == PowerOpcode::GetStatus as u32 => {
                        resp.status = POWER_STATUS_OK;
                        resp.current_state = daemon.manager.current_state.as_u32();
                        resp.current_profile = daemon.manager.current_profile as u32;
                        resp.battery_percentage = daemon.manager.battery.percentage;
                        resp.battery_charging = if daemon.manager.battery.is_charging { 1 } else { 0 };
                        resp.battery_health = daemon.manager.battery.health_percentage;
                        resp.power_saver_active =
                            if daemon.manager.power_saver_active { 1 } else { 0 };
                        resp.temperature_celsius = daemon.manager.battery.temperature_celsius;
                        for i in 0..MAX_SUPPORTED_CORES {
                            resp.cpu_cstates[i] = daemon.manager.cpu_cstates[i].as_u8();
                        }
                        resp.total_transitions = daemon.manager.total_state_transitions;
                        resp.acpi_pm1a_port = daemon.manager.fadt.pm1a_cnt_blk;
                        resp.acpi_reset_port = daemon.manager.fadt.reset_port;
                        resp.result_code = 0;
                    }
                    x if x == PowerOpcode::SetProfile as u32 => {
                        if let Some(prof) = PowerProfile::from_u32(req.param) {
                            match daemon.manager.set_profile(&daemon.admin_cap, prof) {
                                Ok(new_prof) => {
                                    resp.status = POWER_STATUS_OK;
                                    resp.current_profile = new_prof as u32;
                                    resp.current_state = daemon.manager.current_state.as_u32();
                                    resp.power_saver_active =
                                        if daemon.manager.power_saver_active { 1 } else { 0 };
                                    resp.result_code = new_prof as i32;
                                }
                                Err(_) => {
                                    resp.status = POWER_STATUS_ERROR;
                                    resp.result_code = -1;
                                }
                            }
                        } else {
                            resp.status = POWER_STATUS_ERROR;
                            resp.result_code = -2;
                        }
                    }
                    x if x == PowerOpcode::SetCState as u32 => {
                        let core_id = req.target_core as usize;
                        if let Some(cstate) = CpuPowerState::from_u8(req.param as u8) {
                            match daemon
                                .manager
                                .set_core_cstate(&daemon.admin_cap, core_id, cstate)
                            {
                                Ok(()) => {
                                    resp.status = POWER_STATUS_OK;
                                    for i in 0..MAX_SUPPORTED_CORES {
                                        resp.cpu_cstates[i] = daemon.manager.cpu_cstates[i].as_u8();
                                    }
                                    resp.result_code = core_id as i32;
                                }
                                Err(_) => {
                                    resp.status = POWER_STATUS_ERROR;
                                    resp.result_code = -1;
                                }
                            }
                        } else {
                            resp.status = POWER_STATUS_ERROR;
                            resp.result_code = -2;
                        }
                    }
                    x if x == PowerOpcode::GetBattery as u32 => {
                        resp.status = POWER_STATUS_OK;
                        resp.battery_percentage = daemon.manager.battery.percentage;
                        resp.battery_charging = if daemon.manager.battery.is_charging { 1 } else { 0 };
                        resp.battery_health = daemon.manager.battery.health_percentage;
                        resp.temperature_celsius = daemon.manager.battery.temperature_celsius;
                        resp.power_saver_active =
                            if daemon.manager.power_saver_active { 1 } else { 0 };
                        resp.result_code = daemon.manager.battery.percentage as i32;
                    }
                    x if x == PowerOpcode::Shutdown as u32 => {
                        match daemon
                            .manager
                            .transition_state(&daemon.admin_cap, PowerState::S5SoftOff)
                        {
                            Ok(s) => {
                                println("[POWERD] Extinction systeme ACPI S5 amorcee.");
                                resp.status = POWER_STATUS_OK;
                                resp.current_state = s.as_u32();
                                resp.result_code = 0;
                            }
                            Err(_) => {
                                resp.status = POWER_STATUS_ERROR;
                                resp.result_code = -1;
                            }
                        }
                    }
                    _ => {
                        resp.status = POWER_STATUS_ERROR;
                        resp.result_code = -99;
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

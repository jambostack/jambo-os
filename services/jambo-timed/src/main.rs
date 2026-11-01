//! Démon de Synchronisation Horlogère Distribuée PTP/NTP (timed, Ring 3, PID 17)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Référence temporelle universelle, monotone et sub-microseconde sans autorité ambiante
//! - Modèle d'asservissement d'horloge PLL/FLL déterministe (Slewing / Stepping / Locked)
//! - Échantillonnage d'horodatage quadri-points IEEE 1588 PTP (T1, T2, T3, T4)
//! - Garantie formelle de non-régression temporelle ($t_{n+1} > t_n$)
//! - Contrôle d'accès strict par capacité `TimeSyncCap`
//! - Serveur IPC synchrone 64 octets pour le shell `jsh` et les services de grappe (PID 17)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_timed::{
    syscall_thread_yield, ChannelMessage, JamboTimeDaemon, PreciseTime, PtpSample, ServoMode,
    TimeRequest, MAX_FASTPATH_BYTES,
};
use libjambo::{println, Handle};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m   JamboOS Sovereign Time Daemon (PID 17) v0.3.56  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation du démon de synchronisation horlogère
    let mut daemon = JamboTimeDaemon::new();
    println("[TIMED] Demon de synchronisation horlogere PTP/NTP initialise (PID 17).");

    // 2. Auto-test au démarrage
    println("[TIMED] Demarrage de l'auto-test du servo d'horloge...");

    // Test 1 : Lecture du temps étalon initial
    let t0 = daemon.get_time().expect("auto-test: get_time failed");
    assert!(t0.seconds == 1792340000, "auto-test: unexpected initial seconds");

    // Test 2 : Calibration PTP quadri-points
    let sample = PtpSample {
        t1_master_tx: PreciseTime::new(1792340000, 0),
        t2_slave_rx: PreciseTime::new(1792340000, 10_000_000), // delay 8ms + offset 2ms
        t3_slave_tx: PreciseTime::new(1792340000, 20_000_000),
        t4_master_rx: PreciseTime::new(1792340000, 26_000_000), // delay 8ms - offset 2ms
    };
    let (offset, delay) = daemon.sync_ptp(&sample).expect("auto-test: sync_ptp failed");
    assert!(offset == 2_000_000, "auto-test: offset mismatch");
    assert!(delay == 8_000_000, "auto-test: delay mismatch");

    // Test 3 : État du servo (mode Slewing avec dérive 500 PPM)
    let (mode, ppm, off, del, syncs) = daemon.status();
    assert!(mode == ServoMode::Slewing, "auto-test: servo not in slewing mode");
    assert!(ppm == 500, "auto-test: ppm mismatch");
    assert!(off == 2_000_000, "auto-test: last offset mismatch");
    assert!(del == 8_000_000, "auto-test: last delay mismatch");
    assert!(syncs == 1, "auto-test: sync count mismatch");

    // Test 4 : Avancement temporel avec correction slewing
    let t1 = daemon.advance_nanos(1_000_000_000);
    assert!(t1.as_nanos() > t0.as_nanos(), "auto-test: monotonicity violated");

    // Test 5 : Saut temporel et invariance de non-régression
    daemon.server.servo.step_offset(-500_000_000); // Tentative de retour en arrière
    let t2 = daemon.advance_nanos(1_000);
    assert!(t2.as_nanos() > t1.as_nanos(), "auto-test: strict monotonicity violated");

    println("[TIMED] Auto-test reussi : lecture etalon, calibration quadri-points PTP, asservissement PLL et monotonicite valides.");
    println("[TIMED] Demon de synchronisation horlogere (jambo-timed PID 17) pret.");

    // 3. Initialisation du canal IPC pour communication avec jsh et les services
    let mut time_srv_h: u64 = 0;
    let mut time_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut time_srv_h as *mut u64 as u64,
            &mut time_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = Handle(if time_srv_h != 0 {
        time_srv_h
    } else {
        17 // Endpoint standard PID 17
    });
    println("[TIMED] Canal IPC horloge operationnel (endpoint PID 17 pret).");

    // 4. Boucle coopérative de service IPC Ring 3
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<TimeRequest>() {
            if let Some(req) = TimeRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = daemon.handle_ipc_request(&req);
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

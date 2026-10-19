//! Module de validation de la Synchronisation Horlogère Distribuée PTP/NTP (Phase 58 - v0.2.56)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_timed::{
    time_rights, ClockServo, JamboTimeDaemon, PreciseTime, PtpSample, ServoMode, TimeSyncCap,
    TimeSyncServer,
};

/// Exécute la suite de tests de synchronisation horlogère distribuée PTP/NTP et asservissement (Phase 58)
pub fn execute_time_sync_test() -> bool {
    kprintln!(
        "[TIME/TEST] Démarrage du test de synchronisation horlogère distribuée (Phase 58)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (TimeSyncCap)
    let admin_cap = TimeSyncCap::new(Handle::new(58, 1), 10, time_rights::ALL);
    assert!(admin_cap.can_read());
    assert!(admin_cap.can_adjust_freq());
    assert!(admin_cap.can_step());
    assert!(admin_cap.can_ptp_sync());

    let unauth_cap = TimeSyncCap::new(Handle::new(58, 2), 10, 0);
    assert!(!unauth_cap.can_read());
    assert!(!unauth_cap.can_adjust_freq());
    assert!(!unauth_cap.can_step());
    assert!(!unauth_cap.can_ptp_sync());

    let server = TimeSyncServer::new(10, PreciseTime::new(1792340000, 0));
    assert_eq!(
        server.read_time(&unauth_cap).err(),
        Some(SysError::PermissionDenied),
        "La lecture d'horloge sans droit TIME_READ doit être rejetée"
    );
    kprintln!("[TIME/CAP] Droits capabilitaires TimeSyncCap et confinement zéro-autorité validés");

    // 2. Validation de l'arithmétique de haute précision et de la monotonicité stricte
    let t_init = PreciseTime::new(1000, 500_000_000);
    let t_add = t_init.saturating_add_nanos(750_000_000);
    assert_eq!(t_add.seconds, 1001);
    assert_eq!(t_add.nanoseconds, 250_000_000);

    let mut servo = ClockServo::new(t_init);
    let t1 = servo.tick(500_000);
    // Tentative de saut rétrograde interdit (-2_000_000 ns)
    servo.step_offset(-2_000_000);
    let t2 = servo.tick(1_000);
    assert!(
        t2.as_nanos() > t1.as_nanos(),
        "L'asservissement d'horloge doit garantir une monotonicité strictement croissante"
    );
    kprintln!(
        "[TIME/MONO] Arithmétique sub-microseconde et garantie formelle d'anti-régression validées"
    );

    // 3. Validation de l'algorithme quadri-points PTP IEEE 1588
    let ptp_sample = PtpSample {
        t1_master_tx: PreciseTime::new(2000, 0),
        t2_slave_rx: PreciseTime::new(2000, 12_000_000), // delay 10ms + offset 2ms
        t3_slave_tx: PreciseTime::new(2000, 20_000_000),
        t4_master_rx: PreciseTime::new(2000, 28_000_000), // delay 10ms - offset 2ms
    };
    let (offset, delay) = ptp_sample.calculate_offset_and_delay().expect("calcul PTP");
    assert_eq!(offset, 2_000_000); // 2 ms offset
    assert_eq!(delay, 10_000_000); // 10 ms delay
    kprintln!("[TIME/PTP] Algorithme de filtrage quadri-points IEEE 1588 (Offset & Delay) validé");

    // 4. Validation du démon orchestrateur JamboTimeDaemon
    let mut daemon = JamboTimeDaemon::new();
    let read_res = daemon.get_time();
    assert!(read_res.is_ok());
    assert_eq!(read_res.unwrap().seconds, 1792340000);

    daemon.init_defaults();
    let (mode, _ppm, off, del, syncs) = daemon.status();
    assert_eq!(syncs, 1);
    assert_eq!(off, 2_000_000);
    assert_eq!(del, 8_000_000);
    assert_eq!(mode, ServoMode::Slewing);

    let t_adv = daemon.advance_nanos(1_000_000_000);
    assert!(t_adv.as_nanos() > 1792340000 * 1_000_000_000);
    kprintln!("[TIME/DAEMON] Démon JamboTimeDaemon opérationnel de bout en bout");

    // 5. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'time status'
    let (st_stat, len_stat) = shell.execute_line("time status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("SYNCHRONISATION HORLOGÈRE DISTRIBUÉE"));
    assert!(str_stat.contains("UTC/Étalon 2026"));
    assert!(str_stat.contains("Mode d'asservissement"));
    kprintln!("[TIME/SHELL] Commande 'time status' validée");

    // Commande 'time sync'
    let (st_sync, len_sync) = shell.execute_line("time sync", &mut out_buf);
    assert_eq!(st_sync, ShellStatus::Success);
    let str_sync = core::str::from_utf8(&out_buf[..len_sync]).unwrap_or("");
    assert!(str_sync.contains("Synchronisation quadri-points réussie"));
    kprintln!("[TIME/SHELL] Commande 'time sync' validée");

    // Commande 'time tick'
    let (st_tick, len_tick) = shell.execute_line("time tick 500000000", &mut out_buf);
    assert_eq!(st_tick, ShellStatus::Success);
    let str_tick = core::str::from_utf8(&out_buf[..len_tick]).unwrap_or("");
    assert!(str_tick.contains("Horloge avancée de 500000000 ns"));
    kprintln!("[TIME/SHELL] Commande 'time tick' validée");

    kprintln!(
        "[TIME/PASS] Synchronisation horlogère distribuée PTP/NTP & asservissement validés avec succès."
    );
    true
}

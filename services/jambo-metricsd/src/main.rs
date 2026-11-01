//! Démon de Métrologie et Observabilité Système en Espace Utilisateur (metricsd, Ring 3, PID 12)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Télémétrie et métrologie système en séries temporelles
//! - Tampons annulaires déterministes O(1)
//! - Règles d'alerte à seuil en temps réel
//! - Serveur IPC pour le shell `jsh` et les services JamboOS (PID 12)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_metricsd::{
    metrics_rights, syscall_thread_yield, AlertCondition, ChannelMessage, JamboMetricsDaemon,
    MetricsCap, MetricsRequest, MAX_FASTPATH_BYTES,
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
    println("\x1b[1;32m   JamboOS Sovereign Metrics Daemon (PID 12) v0.3.51 \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Initialisation de la capabilité racine et du démon
    let admin_cap = MetricsCap::new(libjambo::Handle::new(12, 1), metrics_rights::ALL);
    let mut daemon = JamboMetricsDaemon::new_with_cap(admin_cap);
    println("[METRICSD] Capabilites racine et daemon initialises (PID 12).");

    // 2. Auto-test au démarrage : enregistrement des séries système, ingestion, calculs min/max/avg, alerte
    println("[METRICSD] Demarrage de l'auto-test de telemetrie systeme...");

    let reg_cpu = daemon.register_series(b"cpu_load", 1).is_ok();
    let reg_ipc = daemon.register_series(b"ipc_latency_ns", 1).is_ok();
    let reg_vmo = daemon.register_series(b"vmo_usage_kb", 1).is_ok();
    let reg_alert = daemon
        .register_alert(b"cpu_load", AlertCondition::GreaterThan, 80)
        .is_ok();

    // Ingestion d'échantillons nominaux
    let _ = daemon.ingest(b"cpu_load", 1, 1000, 15);
    let _ = daemon.ingest(b"cpu_load", 1, 1001, 25);
    let _ = daemon.ingest(b"cpu_load", 1, 1002, 20);

    let _ = daemon.ingest(b"ipc_latency_ns", 1, 1000, 520);
    let _ = daemon.ingest(b"vmo_usage_kb", 1, 1000, 4096);

    let stats_cpu = daemon.query_stats(b"cpu_load", 1);
    let stats_ok = match stats_cpu {
        Ok((min, max, avg, last, count)) => {
            min == 15 && max == 25 && avg == 20 && last == 20 && count == 3
        }
        Err(_) => false,
    };

    let alert_initial = daemon.is_alert_triggered(b"cpu_load") == Ok(false);

    // Ingestion d'un échantillon critique (> 80) pour valider le déclenchement d'alerte
    let ing_alert = daemon.ingest(b"cpu_load", 1, 1003, 92);
    let alert_triggered_ok = match ing_alert {
        Ok(triggered) => triggered && daemon.is_alert_triggered(b"cpu_load") == Ok(true),
        Err(_) => false,
    };

    if reg_cpu && reg_ipc && reg_vmo && reg_alert && stats_ok && alert_initial && alert_triggered_ok
    {
        println("[METRICSD] Auto-test reussi : 3 series systeme (cpu_load, ipc_latency_ns, vmo_usage_kb) et regle d'alerte validees.");
    } else {
        println("[METRICSD] ALERTE : Anomalie detectee lors de l'auto-test METRICSD !");
    }

    // 3. Initialisation du canal IPC pour communication avec le shell jsh
    let mut metrics_srv_h: u64 = 0;
    let mut metrics_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut metrics_srv_h as *mut u64 as u64,
            &mut metrics_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = libjambo::Handle(if metrics_srv_h != 0 {
        metrics_srv_h
    } else {
        12 // Endpoint standard PID 12
    });
    println("[METRICSD] Canal IPC de telemetrie systeme operationnel (endpoint PID 12 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<MetricsRequest>() {
            if let Some(req) = MetricsRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
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

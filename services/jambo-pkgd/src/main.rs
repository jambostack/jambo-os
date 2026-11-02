//! Démon de Gestion Déclarative de Paquets, Dépôt CAS & Mises à Jour Transactionnelles A/B (pkgd, Ring 3, PID 23)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Gestion déclarative de paquets immuables JPkg (.jpkg)
//! - Dépôt CAS vérifié cryptographiquement
//! - Mises à jour transactionnelles A/B et rollback automatique
//! - Serveur IPC synchrone 64 octets sous l'endpoint 23 pour le shell `jsh` et services JamboOS (PID 23)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_pkgd::{
    pkg_rights, AbSlot, ChannelMessage, JamboPkgDaemon, JpkgManifest, PkgRequest,
    MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[pkgd] PANIC: bare-metal package daemon fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[pkgd] PANIC: bare-metal package daemon fault\n" {
            core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") *b, options(nomem, nostack));
        }
    }
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m   JamboOS Declarative Package Daemon (PID 23) v0.3.62   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation et initialisation par défaut
    let mut daemon = JamboPkgDaemon::new();
    daemon.init_defaults();
    println(
        "[PKGD] Demon de gestion declarative de paquets & mises a jour A/B initialise (PID 23).",
    );

    // 2. Auto-tests unitaires intégrés au boot
    println("[PKGD] Demarrage de l'auto-test du demon de paquets...");

    // Test 1 : Installation de 'sec-agent' v1.0.0
    let sec_agent = JpkgManifest::new("sec-agent", (1, 0, 0), [0x33u8; 32], pkg_rights::PKG_ADMIN);
    assert!(
        daemon.install_package(sec_agent).is_ok(),
        "auto-test: sec-agent installation failed"
    );
    assert!(
        daemon.find_package("sec-agent").is_some(),
        "auto-test: sec-agent not found in CAS store"
    );

    // Test 2 : Préparation de la génération 2 sur SlotB
    let gen2 = daemon
        .stage_update()
        .expect("auto-test: stage update failed");
    assert_eq!(gen2, 2, "auto-test: expected generation 2");
    assert_eq!(
        daemon.current_generation.active_slot,
        AbSlot::SlotB,
        "auto-test: expected active slot SlotB"
    );
    assert!(
        !daemon.current_generation.committed,
        "auto-test: staged generation must be uncommitted"
    );

    // Test 3 : Simulation de démarrages défaillants déclenchant le rollback automatique
    assert_eq!(
        daemon.record_boot_attempt(),
        Ok(false),
        "auto-test: attempt 1 should not rollback"
    );
    assert_eq!(
        daemon.record_boot_attempt(),
        Ok(false),
        "auto-test: attempt 2 should not rollback"
    );
    assert_eq!(
        daemon.record_boot_attempt(),
        Ok(false),
        "auto-test: attempt 3 should not rollback"
    );
    assert_eq!(
        daemon.record_boot_attempt(),
        Ok(true),
        "auto-test: attempt 4 must trigger automatic rollback"
    );
    assert_eq!(
        daemon.current_generation.active_slot,
        AbSlot::SlotA,
        "auto-test: slot after rollback must be SlotA"
    );
    assert_eq!(
        daemon.current_generation.generation_id, 1,
        "auto-test: generation after rollback must be 1"
    );

    // Test 4 : Nouvelle préparation et validation atomique (Commit)
    let gen2_commit = daemon
        .stage_update()
        .expect("auto-test: stage update re-try failed");
    assert_eq!(
        gen2_commit, 2,
        "auto-test: expected generation 2 on re-stage"
    );
    assert_eq!(
        daemon.current_generation.active_slot,
        AbSlot::SlotB,
        "auto-test: expected SlotB on re-stage"
    );
    assert!(
        daemon.commit_update().is_ok(),
        "auto-test: commit update failed"
    );
    assert!(
        daemon.current_generation.committed,
        "auto-test: generation must be marked committed"
    );
    assert!(
        daemon.current_generation.healthy,
        "auto-test: generation must be marked healthy"
    );

    println("[PKGD] Auto-test reussi : cycle de vie CAS, partitionnement A/B et rollback automatique valides.");
    println("[PKGD] Serveur Declaratif de Paquets (jambo-pkgd PID 23) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 23
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(23);
    println("[PKGD] Canal IPC Package Daemon operationnel (endpoint PID 23 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<PkgRequest>() {
            if let Some(req) = PkgRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = daemon.dispatch_ipc(&req);
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

        libjambo::syscall_thread_yield();
    }
}

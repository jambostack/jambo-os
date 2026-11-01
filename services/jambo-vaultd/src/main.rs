//! Démon de Coffre-Fort Cryptographique Distribué Ring 3 (vaultd, PID 20)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, zéro allocation) :
//! - Déverrouillage par quorum à seuil de Shamir (K parmi N parts)
//! - Chiffrement d'enveloppe des secrets avec baux temporels stricts
//! - Contrôle d'accès sans autorité ambiante régi par `VaultCap`
//! - Serveur IPC synchrone 64 octets pour le shell `jsh` et les services JamboOS (PID 20)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_vaultd::{
    syscall_thread_yield, vault_rights, ChannelMessage, Handle, JamboVaultDaemon, SysError,
    VaultCap, VaultRequest, VaultState, KEY_SIZE, MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[vaultd] PANIC: bare-metal vault fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[vaultd] PANIC: bare-metal vault fault\n" {
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
    println("\x1b[1;32m   JamboOS Sovereign Vault Daemon (PID 20) v0.3.59   \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation du coffre-fort et initialisation par défaut
    let mut daemon = JamboVaultDaemon::new();
    daemon.init_defaults();
    println("[VAULTD] Coffre-fort cryptographique souverain initialise (PID 20).");

    // 2. Auto-tests unitaires intégrés au boot
    println("[VAULTD] Demarrage de l'auto-test du coffre-fort distribue...");

    // Test 1 : État initial scellé
    assert!(
        daemon.vault.state == VaultState::Sealed,
        "auto-test: initial state must be Sealed"
    );
    assert!(
        !daemon.is_unsealed(),
        "auto-test: daemon should not be unsealed initially"
    );

    // Test 2 : Rejet de lecture/écriture en état scellé (ResourceBusy)
    let admin_cap = VaultCap::new(Handle::new(20, 1), vault_rights::ALL);
    let mut out_buf = [0u8; 32];
    assert_eq!(
        daemon
            .vault
            .put_secret(&admin_cap, b"boot/key", b"my_secret", 3600, 100),
        Err(SysError::ResourceBusy),
        "auto-test: put_secret must fail when sealed"
    );
    assert_eq!(
        daemon
            .vault
            .get_secret(&admin_cap, b"boot/key", 100, &mut out_buf),
        Err(SysError::ResourceBusy),
        "auto-test: get_secret must fail when sealed"
    );

    // Test 3 : Déverrouillage progressif par soumission de 2 parts valides (seuil 2 sur 3)
    let dummy_share = [0x11u8; KEY_SIZE];
    let state_after_1 = daemon
        .submit_unseal_share(0, &dummy_share)
        .expect("auto-test: share 0 failed");
    assert_eq!(
        state_after_1,
        VaultState::Unsealing,
        "auto-test: expected Unsealing after 1 share"
    );

    let state_after_2 = daemon
        .submit_unseal_share(1, &dummy_share)
        .expect("auto-test: share 1 failed");
    assert_eq!(
        state_after_2,
        VaultState::Unsealed,
        "auto-test: expected Unsealed after 2 shares"
    );
    assert!(daemon.is_unsealed(), "auto-test: daemon must be unsealed");

    // Test 4 : Stockage d'un secret avec bail temporel (PutSecret)
    let sec_ver = daemon
        .put_secret(b"db/master_pwd", b"s0v3r31gn_k3y", 300, 1000)
        .expect("auto-test: put_secret failed");
    assert_eq!(sec_ver, 1, "auto-test: initial secret version must be 1");
    assert_eq!(daemon.secret_count(), 1, "auto-test: secret count mismatch");

    // Test 5 : Lecture et vérification du secret déchiffré (GetSecret)
    let (sec_len, read_ver) = daemon
        .get_secret(b"db/master_pwd", 1050, &mut out_buf)
        .expect("auto-test: get_secret failed");
    assert_eq!(read_ver, 1, "auto-test: read version mismatch");
    assert_eq!(
        &out_buf[..sec_len],
        b"s0v3r31gn_k3y",
        "auto-test: decrypted secret data mismatch"
    );

    // Test 6 : Rescellement (Reseal) et vérification de la ré-isolation immédiate
    daemon.reseal().expect("auto-test: reseal failed");
    assert_eq!(
        daemon.vault.state,
        VaultState::Sealed,
        "auto-test: state must be Sealed after reseal"
    );
    assert!(
        !daemon.is_unsealed(),
        "auto-test: daemon must be sealed after reseal"
    );
    assert_eq!(
        daemon.get_secret(b"db/master_pwd", 1060, &mut out_buf),
        Err(SysError::ResourceBusy),
        "auto-test: get_secret must fail after reseal"
    );

    // Ré-unseal pour boucle opérationnelle (2 parts)
    let _ = daemon.submit_unseal_share(0, &dummy_share);
    let _ = daemon.submit_unseal_share(1, &dummy_share);
    assert!(
        daemon.is_unsealed(),
        "auto-test: re-unseal for operational loop failed"
    );

    println(
        "[VAULTD] Auto-test reussi : seuil de Shamir (2/3), chiffrement d'enveloppe et isolation valides.",
    );
    println("[VAULTD] Serveur Coffre-Fort de Secrets (jambo-vaultd PID 20) pret.");

    // 3. Initialisation du canal IPC pour communication avec le shell jsh et les services
    let mut vault_srv_h: u64 = 0;
    let mut vault_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut vault_srv_h as *mut u64 as u64,
            &mut vault_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let server_endpoint = Handle(if vault_srv_h != 0 {
        vault_srv_h
    } else {
        20 // Endpoint standard PID 20
    });
    println("[VAULTD] Canal IPC Vault operationnel (endpoint PID 20 pret).");

    // 4. Boucle de service IPC Ring 3
    let mut tick: u64 = 1000;
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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<VaultRequest>() {
            if let Some(req) = VaultRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = daemon.handle_ipc_request(&req, tick);
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

        tick = tick.wrapping_add(1);
        syscall_thread_yield();
    }
}

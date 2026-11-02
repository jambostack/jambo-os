//! Démon de Gestion et Séquestre de Clés Cryptographiques de Grappe (jambo-kms, Ring 3, PID 28)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Gestion de hiérarchies cryptographiques (MasterKey, DomainKey, DataKey, SessionKey)
//! - Dérivation déterministe HKDF (RFC 5869)
//! - Baux temporels et quotas d'utilisation stricts
//! - Zéroïsation garantie en mémoire volatile
//! - Serveur IPC synchrone 64 octets sous l'endpoint 28 pour le shell jsh et services JamboOS (PID 28)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_kms::{
    kms_rights, lease_ops, ChannelMessage, KeyLifecycleState, KeyType, KmsCap, KmsManager,
    KmsRequest, MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[kms] PANIC: bare-metal key management service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[kms] PANIC: bare-metal key management service fault\n" {
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
    println("\x1b[1;32m  JamboOS Key Management Service (PID 28) v0.3.67  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation du gestionnaire et initialisation des clés par défaut
    let mut manager = KmsManager::new();
    manager.init_defaults();
    println("[KMS] Magasin de cles cryptographiques initialise (PID 28).");

    // 2. Auto-tests intégrés au démarrage
    println("[KMS] Demarrage de l'auto-test du service KMS...");

    // Auto-test 1: Vérifier la clé maîtresse
    let master_data = {
        let master = manager.get_key(1).expect("auto-test: master key exists");
        assert_eq!(
            master.key_type,
            KeyType::Master,
            "auto-test: key 1 must be Master"
        );
        assert_eq!(
            master.state,
            KeyLifecycleState::Active,
            "auto-test: master key must be Active"
        );
        assert_eq!(
            master.name_as_str(),
            "cluster-root-kek",
            "auto-test: master key name mismatch"
        );
        master.key_data
    };
    println("[KMS] Auto-test: Cle maitresse 'cluster-root-kek' verifiee : OK.");

    // Auto-test 2: Dériver une clé de domaine via HKDF
    let cap = KmsCap::new(libjambo::Handle::new(28, 1), kms_rights::ALL, 0, 32);
    let dev_id = manager
        .derive_key(&cap, 1, b"selftest-domain", KeyType::Domain, 100)
        .expect("auto-test: derive domain key failed");
    {
        let dev_key = manager
            .get_key(dev_id)
            .expect("auto-test: derived key exists");
        assert_eq!(dev_key.parent_id, 1, "auto-test: parent ID mismatch");
        assert_ne!(
            dev_key.key_data, master_data,
            "auto-test: derived key material must differ"
        );
    }
    println("[KMS] Auto-test: Derivation HKDF RFC 5869 d'une cle enfant reussie.");

    // Auto-test 3: Octroi et consommation de bail
    let lease_id = manager
        .grant_lease(
            &cap,
            dev_id,
            lease_ops::OP_ENCRYPT | lease_ops::OP_DECRYPT,
            5,
            1000,
            100,
        )
        .expect("auto-test: grant lease failed");
    manager
        .consume_lease(lease_id, lease_ops::OP_ENCRYPT, 110)
        .expect("auto-test: consume lease failed");
    println("[KMS] Auto-test: Attribution et consommation de bail validees.");

    // Auto-test 4: Révocation de clé et vérification de la zéroïsation
    manager
        .revoke_key(&cap, dev_id)
        .expect("auto-test: revoke key failed");
    let rev_key = manager
        .get_key(dev_id)
        .expect("auto-test: key exists after revoke");
    assert_eq!(
        rev_key.state,
        KeyLifecycleState::Revoked,
        "auto-test: key state must be Revoked"
    );
    assert_eq!(
        rev_key.key_data, [0u8; 32],
        "auto-test: key data must be zeroized"
    );
    println("[KMS] Auto-test: Revocation et zeroisation volatile validee.");
    println("[KMS] Auto-test reussi : cycle de vie, HKDF et zeroisation valides.");
    println("[KMS] Serveur KMS (jambo-kms PID 28) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 28
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(28);
    println("[KMS] Canal IPC KMS operationnel (endpoint PID 28 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<KmsRequest>() {
            if let Some(req) = KmsRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                let resp = manager.dispatch_ipc(&req);
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

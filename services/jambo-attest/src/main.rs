//! Démon d'Attestation Cryptographique à Distance et Confinement Matériel de Grappe (jambo-attest, Ring 3, PID 29)
//!
//! Exécutable Ring 3 souverain sans tas (`#![no_std]`, `#![no_main]`, zéro allocation) :
//! - Attestation à distance multi-racines matérielles (TPM 2.0 PCR, Intel TDX, AMD SEV-SNP, ARM CCA Realm)
//! - Preuves ZKP Schnorr / Fiat-Shamir NIZKPoK sans divulgation de secrets matériels
//! - Confinement adaptatif de grappe (Sandboxed, Isolated, Ejected)
//! - Scellement cryptographique inaltérable d'audit SHA-256
//! - Serveur IPC synchrone 64 octets sous l'endpoint 29 pour le shell jsh et services JamboOS (PID 29)
//! - Ordonnancement coopératif via `syscall_thread_yield()`

#![no_std]
#![no_main]

use jambo_attest::{
    attest_rights, AttestCap, AttestRequest, ChannelMessage, ConfinementLevel, HardwareTrustRoot,
    JamboAttestDaemon, NodeStatus, ATTEST_ENDPOINT_ID, MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    println("[attest] PANIC: bare-metal remote attestation service fault");
    #[cfg(target_arch = "x86_64")]
    unsafe {
        for b in b"[attest] PANIC: bare-metal remote attestation service fault\n" {
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
    println("\x1b[1;32m  JamboOS Remote Attestation & ZKP Service (PID 29) v0.3.68  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Instanciation du gestionnaire d'attestation et initialisation des 4 nœuds par défaut
    let admin_cap = AttestCap::new(
        libjambo::Handle::new(ATTEST_ENDPOINT_ID, 1),
        attest_rights::ALL,
    );
    let mut daemon = JamboAttestDaemon::new(admin_cap);
    daemon.init_defaults();
    println("[ATTEST] Registre d'attestation et racines de confiance initialisees (PID 29).");

    // 2. Auto-tests intégrés au démarrage
    println("[ATTEST] Demarrage de l'auto-test du service d'attestation...");

    // Auto-test 1: Vérification du nœud contrôleur TDX
    let node1 = daemon
        .get_node(1)
        .expect("auto-test: node 1 (TDX) must exist");
    assert_eq!(
        node1.trust_root,
        HardwareTrustRoot::IntelTdx,
        "auto-test: node 1 trust root must be Intel TDX"
    );
    assert_eq!(
        node1.status,
        NodeStatus::Unverified,
        "auto-test: node 1 initial status must be Unverified"
    );
    assert_eq!(
        node1.confinement,
        ConfinementLevel::Sandboxed,
        "auto-test: node 1 initial confinement must be Sandboxed"
    );
    assert_eq!(
        node1.name_as_str(),
        "jambo-ctrl-01",
        "auto-test: node 1 name mismatch"
    );
    println("[ATTEST] Auto-test 1: Noeud controleur TDX 'jambo-ctrl-01' verifie : OK.");

    // Auto-test 2: Génération et vérification d'une revendication d'intégrité signée
    let claim1 = daemon
        .generate_claim(&admin_cap, 1)
        .expect("auto-test: generate claim for node 1 failed");
    assert_eq!(claim1.node_id, 1, "auto-test: claim node_id mismatch");
    let claim_verified = daemon
        .verify_claim(&admin_cap, &claim1)
        .expect("auto-test: verify claim failed");
    assert!(claim_verified, "auto-test: claim signature must be valid");
    let node1_after_claim = daemon.get_node(1).unwrap();
    assert_eq!(
        node1_after_claim.status,
        NodeStatus::PendingZkp,
        "auto-test: status must transition to PendingZkp"
    );
    println("[ATTEST] Auto-test 2: Revendication d'integrite signee HMAC validee : OK.");

    // Auto-test 3: Génération et validation d'une preuve ZKP Fiat-Shamir
    let n1_secret = 0x1337_4242_u64;
    let n1_blinding = 0x5544_3322_u64;
    let claim_digest = claim1.compute_digest();
    let proof = daemon
        .generate_zkp_proof(&admin_cap, 1, n1_secret, n1_blinding, claim_digest)
        .expect("auto-test: generate ZKP proof failed");
    assert!(
        proof.verify(),
        "auto-test: mathematical verification of Schnorr equation must pass"
    );
    let zkp_verified = daemon
        .verify_zkp_proof(&admin_cap, &proof)
        .expect("auto-test: daemon verify ZKP proof failed");
    assert!(zkp_verified, "auto-test: daemon must accept ZKP proof");
    let node1_trusted = daemon.get_node(1).unwrap();
    assert_eq!(
        node1_trusted.status,
        NodeStatus::VerifiedTrusted,
        "auto-test: status must be VerifiedTrusted"
    );
    assert_eq!(
        node1_trusted.confinement,
        ConfinementLevel::Unrestricted,
        "auto-test: confinement must be lifted to Unrestricted"
    );
    println("[ATTEST] Auto-test 3: Preuve ZKP Fiat-Shamir validee et confinement leve : OK.");

    // Auto-test 4: Confinement adaptatif d'un nœud et scellement d'audit
    let prev_audit = daemon.audit_chain;
    daemon
        .confine_node(
            &admin_cap,
            2,
            ConfinementLevel::Isolated,
            "Simulation quarantaine securite auto-test",
        )
        .expect("auto-test: isolate node 2 failed");
    let node2 = daemon.get_node(2).unwrap();
    assert_eq!(
        node2.confinement,
        ConfinementLevel::Isolated,
        "auto-test: node 2 confinement must be Isolated"
    );
    assert_eq!(
        node2.status,
        NodeStatus::Quarantined,
        "auto-test: node 2 status must be Quarantined"
    );
    assert_ne!(
        daemon.audit_chain, prev_audit,
        "auto-test: audit chain hash must be sequentially sealed"
    );
    println("[ATTEST] Auto-test 4: Confinement adaptatif et scellement d'audit valides : OK.");

    println("[ATTEST] Auto-test reussi : revendications, ZKP et confinement valides.");
    println("[ATTEST] Serveur d'Attestation (jambo-attest PID 29) pret.");

    // 3. Enregistrement de l'endpoint IPC standard 29
    let server_endpoint = libjambo::syscall_ipc_register_endpoint(ATTEST_ENDPOINT_ID as u64);
    println("[ATTEST] Canal IPC Attestation operationnel (endpoint PID 29 pret).");

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

        if ret == 0 && rx_msg.byte_count >= core::mem::size_of::<AttestRequest>() {
            if let Some(req) = AttestRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
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

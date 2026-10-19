//! Module de validation des Preuves à Divulgation Nulle de Connaissance (zk-SNARKs) & Systèmes R1CS (`jambo-zksnark`)
//! Phase 97 — Jalon v0.2.95
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_zksnark::{
    zksnark_rights, Fr, JamboZkSnarkDaemon, LinearCombination, R1csCircuit, ZkSnarkCap,
    ZkSnarkProof, MAX_CIRCUITS,
};

/// Exécute la suite complète de validation formelle du sous-système zk-SNARK souverain (Phase 97)
pub fn execute_zksnark_daemon_test() -> bool {
    kprintln!(
        "[ZKSNARK/TEST] Démarrage du test de validation des preuves Zero-Knowledge zk-SNARK & R1CS (Phase 97)..."
    );

    // 1. Contrôle d'accès capabilaire (ZkSnarkCap) et rejet formel de toute élévation de privilèges
    let admin_cap = ZkSnarkCap::new(Handle::new(9701, 1), zksnark_rights::ALL);
    assert!(admin_cap.has_right(zksnark_rights::SETUP));
    assert!(admin_cap.has_right(zksnark_rights::PROVE));
    assert!(admin_cap.has_right(zksnark_rights::VERIFY));
    assert!(admin_cap.has_right(zksnark_rights::INSPECT));
    assert!(admin_cap.has_right(zksnark_rights::ADMIN));

    let verifier_cap = admin_cap
        .attenuate(zksnark_rights::VERIFY | zksnark_rights::INSPECT)
        .expect("Atténuation monotone ZkSnarkCap");
    assert!(verifier_cap.has_right(zksnark_rights::VERIFY));
    assert!(verifier_cap.has_right(zksnark_rights::INSPECT));
    assert!(!verifier_cap.has_right(zksnark_rights::ADMIN));
    assert!(!verifier_cap.has_right(zksnark_rights::SETUP));
    assert!(!verifier_cap.has_right(zksnark_rights::PROVE));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        verifier_cap.attenuate(zksnark_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits ZkSnarkCap formellement rejetée"
    );
    kprintln!("[ZKSNARK/CAP] Contrôle d'accès capabilaire ZkSnarkCap et atténuation monotone validés");

    // 2. Initialisation du démon zk-SNARK et suite de circuits souverains
    let mut daemon = JamboZkSnarkDaemon::new(admin_cap);
    daemon.init_defaults();

    assert_eq!(daemon.circuits.iter().filter(|c| c.is_some()).count(), 4);
    assert_eq!(daemon.setup_count, 4);
    kprintln!("[ZKSNARK/INIT] Démon zk-SNARK initialisé (4 circuits R1CS & CRS compilés)");

    // 3. Preuve de connaissance de pré-image secrète (Circuit 0: s^3 + 5s + 7 = Y)
    let s = Fr::from_u64(3);
    let s2 = Fr::from_u64(9);
    let s3 = Fr::from_u64(27);
    let y = Fr::from_u64(49);
    let full_witness = [Fr::ONE, s, s2, s3, y];

    let proof_preimage = daemon
        .create_proof(&admin_cap, 0, &full_witness, 0x1234_5678)
        .expect("Génération preuve PreimageKnowledge");

    let is_valid = daemon
        .verify_proof(&verifier_cap, &proof_preimage)
        .expect("Vérification preuve PreimageKnowledge");
    assert!(is_valid, "Authenticité de la preuve zk-SNARK vérifiée avec succès");

    // 4. Test d'inviolabilité et robustesse (Soundness check)
    let mut tampered_proof = proof_preimage;
    tampered_proof.public_inputs[0] = Fr::from_u64(50); // Falsification du résultat public
    let is_tampered_valid = daemon
        .verify_proof(&verifier_cap, &tampered_proof)
        .expect("Vérification preuve altérée");
    assert!(
        !is_tampered_valid,
        "Rejet strict de toute preuve zk-SNARK avec entrée publique altérée"
    );
    kprintln!("[ZKSNARK/SOUNDNESS] Preuve de pré-image validée & falsification formellement bloquée");

    // 5. Preuve d'intervalle confidentielle (Circuit 1: RangeProof4Bit v in [0, 15])
    let v = Fr::from_u64(11); // 11 = 1 + 2 + 0 + 8
    let range_witness = [
        Fr::ONE,
        v,
        Fr::from_u64(1),
        Fr::from_u64(1),
        Fr::from_u64(0),
        Fr::from_u64(1),
    ];
    let proof_range = daemon
        .create_proof(&admin_cap, 1, &range_witness, 0x5555_6666)
        .expect("Génération RangeProof4Bit");
    assert!(
        daemon.verify_proof(&verifier_cap, &proof_range).unwrap(),
        "Vérification RangeProof4Bit réussie"
    );
    kprintln!("[ZKSNARK/RANGE] Preuve d'intervalle confidentielle 4-bit [0, 15] validée");

    // 6. Preuve de possession de jeton de capacité secret (Circuit 2: (k + 42)^2 = Hpub)
    let k_secret = Fr::from_u64(10);
    let h_pub = Fr::from_u64(2704); // 52^2
    let cap_witness = [Fr::ONE, k_secret, h_pub];
    let proof_cap = daemon
        .create_proof(&admin_cap, 2, &cap_witness, 0x7777_8888)
        .expect("Génération CapTokenProof");
    assert!(
        daemon.verify_proof(&verifier_cap, &proof_cap).unwrap(),
        "Vérification CapTokenProof réussie"
    );
    kprintln!("[ZKSNARK/CAP-TOKEN] Preuve Zero-Knowledge de détention de jeton capabilaire validée");

    // 7. Conservation d'actifs et transfert bilanciel confidentiel (Circuit 3: in1 + in2 = out1 + out2)
    let in1 = Fr::from_u64(100);
    let in2 = Fr::from_u64(250);
    let out1 = Fr::from_u64(175);
    let out2 = Fr::from_u64(175);
    let transfer_witness = [Fr::ONE, in1, in2, out1, out2];
    let proof_xfer = daemon
        .create_proof(&admin_cap, 3, &transfer_witness, 0x9999_aaaa)
        .expect("Génération ConfidentialTransfer");
    assert!(
        daemon.verify_proof(&verifier_cap, &proof_xfer).unwrap(),
        "Vérification ConfidentialTransfer réussie"
    );
    kprintln!("[ZKSNARK/TRANSFER] Preuve de transfert bilanciel confidentiel (conservation d'actifs) validée");

    // 8. Registre d'audit scellé par chaîne SHA-256
    assert_ne!(daemon.audit_chain, [0u8; 32]);
    kprintln!("[ZKSNARK/AUDIT] Chaîne d'audit cryptographique SHA-256 scellée et vérifiée");

    // 9. Intégration dans le Shell interactif Ring 3 (jsh)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (st1, len1) = shell.execute_line("zksnark status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    assert!(len1 > 0);

    let (st2, len2) = shell.execute_line("zksnark circuits", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    assert!(len2 > 0);

    let (st3, len3) = shell.execute_line("zksnark prove", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    assert!(len3 > 0);

    let (st4, len4) = shell.execute_line("zksnark verify", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    assert!(len4 > 0);

    let (st5, len5) = shell.execute_line("zksnark audit", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    assert!(len5 > 0);

    kprintln!("[ZKSNARK/SHELL] Commandes Ring 3 jsh 'zksnark' validées avec succès");
    true
}

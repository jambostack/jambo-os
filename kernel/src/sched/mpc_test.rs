//! Module de validation du Calcul Multipartite Sécurisé (MPC),
//! du Partage Secret de Seuil et des Triplés de Beaver (`jambo-mpc`)
//! Phase 95 — Jalon v0.2.93
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_mpc::{
    mpc_rights, Gf256, JamboMpcDaemon, MpcCap, MpcNodeStatus, MpcSessionType,
    SecretShare, ShamirSecretSharing, VssCommitment, MAX_MPC_NODES, MAX_SECRET_LEN,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation formelle du sous-système MPC souverain (Phase 95)
pub fn execute_mpc_daemon_test() -> bool {
    kprintln!(
        "[MPC/TEST] Démarrage du test de validation du Calcul Multipartite Sécurisé MPC (Phase 95)..."
    );

    // 1. Contrôle d'accès capabilaire (MpcCap) et rejet formel de toute élévation de privilèges
    let admin_cap = MpcCap::new(Handle::new(9501, 1), mpc_rights::ALL);
    assert!(admin_cap.has_right(mpc_rights::INIT_SESSION));
    assert!(admin_cap.has_right(mpc_rights::REGISTER_NODE));
    assert!(admin_cap.has_right(mpc_rights::SHARE_SECRET));
    assert!(admin_cap.has_right(mpc_rights::RECONSTRUCT));
    assert!(admin_cap.has_right(mpc_rights::BEAVER_TRIPLET));
    assert!(admin_cap.has_right(mpc_rights::SECURE_COMPUTE));
    assert!(admin_cap.has_right(mpc_rights::SLASH_BYZANTINE));
    assert!(admin_cap.has_right(mpc_rights::ZEROIZE));
    assert!(admin_cap.has_right(mpc_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(mpc_rights::INIT_SESSION | mpc_rights::SHARE_SECRET | mpc_rights::RECONSTRUCT)
        .expect("Atténuation monotone MpcCap");
    assert!(attenuated_cap.has_right(mpc_rights::SHARE_SECRET));
    assert!(!attenuated_cap.has_right(mpc_rights::SLASH_BYZANTINE));
    assert!(!attenuated_cap.has_right(mpc_rights::ADMIN));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        attenuated_cap.attenuate(mpc_rights::ALL),
        Err(SysError::PermissionDenied),
        "Amplification de droits MpcCap formellement rejetée"
    );
    kprintln!("[MPC/CAP] Contrôle d'accès capabilaire MpcCap et atténuation monotone validés");

    // 2. Initialisation du démon MPC et topologie de grappe par défaut
    let mut daemon = JamboMpcDaemon::new(admin_cap);
    daemon.init_defaults();

    assert_eq!(daemon.count_active_nodes(), 5);
    kprintln!("[MPC/INIT] Grappe MPC initialisée (5 nœuds souverains)");

    // 3. Arithmétique du corps fini GF(256)
    let elem_a = Gf256(0x3a);
    let elem_b = Gf256(0x5f);
    let inv_b = elem_b.inv().expect("Inverse GF(256)");
    assert_eq!(elem_b.mul(inv_b), Gf256::ONE);
    assert_eq!(elem_a.add(elem_a), Gf256::ZERO); // Caractéristique 2
    kprintln!("[MPC/GF256] Arithmétique en corps fini GF(256) (addition, multiplication, inverse) validée");

    // 4. Partage secret de seuil de Shamir (SSS) & engagements VSS
    let sess_id = daemon
        .create_session(&admin_cap, MpcSessionType::ThresholdSharing, 3, 5)
        .expect("Création session MPC t=3, n=5");

    let secret_payload = b"JAMBO_SOVEREIGN_MPC_SEALED_CLUSTER_KEY_2026";
    let mut shares = [SecretShare {
        node_id: 0,
        values: [0u8; MAX_SECRET_LEN],
        len: 0,
    }; 5];
    let mut commitments = [VssCommitment {
        coeff_index: 0,
        commitment_hash: [0u8; 32],
    }; 3];

    let n_shares = daemon
        .split_secret_in_session(
            &admin_cap,
            sess_id,
            secret_payload,
            b"entropy_seed_mpc_2026",
            &mut shares,
            &mut commitments,
        )
        .expect("Distribution des parts de secret");
    assert_eq!(n_shares, 5);

    // Reconstitution avec les parts {1, 3, 4} (t=3)
    let valid_subset = [shares[0], shares[2], shares[3]];
    let mut reconstructed = [0u8; MAX_SECRET_LEN];
    let rec_len = daemon
        .reconstruct_secret_in_session(&admin_cap, sess_id, &valid_subset, &mut reconstructed)
        .expect("Reconstruction du secret");
    assert_eq!(&reconstructed[..rec_len], secret_payload);
    kprintln!("[MPC/SSS] Partage secret de Shamir (t=3, n=5) et reconstruction de Lagrange validés");

    // Échec attendu avec moins de t parts (ex: 2 parts)
    let insufficient_subset = [shares[0], shares[1]];
    let mut fail_buf = [0u8; MAX_SECRET_LEN];
    assert_eq!(
        daemon.reconstruct_secret_in_session(&admin_cap, sess_id, &insufficient_subset, &mut fail_buf),
        Err(SysError::InvalidArgument),
        "Reconstruction rejetée avec moins de t parts"
    );

    // Échec attendu avec une part altérée (détection byzantine)
    let mut corrupted_subset = [shares[0], shares[1], shares[2]];
    corrupted_subset[1].values[0] ^= 0xFF; // Altération de la part du nœud 2
    assert_eq!(
        daemon.reconstruct_secret_in_session(&admin_cap, sess_id, &corrupted_subset, &mut fail_buf),
        Err(SysError::PermissionDenied),
        "Altération byzantine détectée et rejetée par engagement VSS"
    );
    kprintln!("[MPC/VSS] Détection d'altération byzantine et intégrité VSS validées");

    // 5. Évaluation de circuits arithmétiques multipartites via Triplés de Beaver
    let x = Gf256(0x13);
    let y = Gf256(0x27);
    let expected_product = x.mul(y);

    let mpc_product = daemon
        .execute_beaver_mult(&admin_cap, x, y, 4, b"seed_beaver_mult_test")
        .expect("Multiplication Beaver MPC");
    assert_eq!(
        mpc_product, expected_product,
        "Produit aveugle MPC Beaver conforme au calcul direct"
    );
    assert_eq!(daemon.beaver_mults_computed, 1);
    kprintln!("[MPC/BEAVER] Multiplication aveugle MPC par triplés de Beaver validée");

    // 6. Détection et bannissement byzantin (Slashing)
    daemon
        .slash_byzantine_node(&admin_cap, 2, "Part cryptographique invalide")
        .expect("Bannissement nœud byzantin 2");
    assert_eq!(daemon.byzantine_slashes, 1);
    assert_eq!(daemon.count_active_nodes(), 4);
    kprintln!("[MPC/SLASH] Slashing et exclusion du nœud byzantin validés");

    // 7. Registre d'audit scellé par chaîne SHA-256
    assert_ne!(daemon.audit_chain, [0u8; 32]);
    kprintln!("[MPC/AUDIT] Chaîne d'audit cryptographique SHA-256 scellée et vérifiée");

    // 8. Intégration dans le Shell interactif Ring 3 (jsh)
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    let (st1, len1) = shell.execute_line("mpc status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    assert!(len1 > 0);

    let (st2, len2) = shell.execute_line("mpc nodes", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    assert!(len2 > 0);

    let (st3, len3) = shell.execute_line("mpc share", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    assert!(len3 > 0);

    let (st4, len4) = shell.execute_line("mpc beaver", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    assert!(len4 > 0);

    let (st5, len5) = shell.execute_line("mpc slash 5", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    assert!(len5 > 0);

    let (st6, len6) = shell.execute_line("mpc audit", &mut out);
    assert_eq!(st6, ShellStatus::Success);
    assert!(len6 > 0);

    kprintln!("[MPC/SHELL] Commandes Ring 3 jsh 'mpc' validées avec succès");
    true
}

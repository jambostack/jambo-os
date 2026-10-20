//! Module de validation du Système Souverain de Gestion et Séquestre de Clés (`jambo-kms`)
//! Phase 108 — Jalon v0.2.106
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_sh::{JamboShell, ShellStatus};
use jambo_kms::{
    kms_rights, lease_ops, ClusterNode, EscrowPackage, EscrowStatus, JamboKmsDaemon,
    KeyAlgorithm, KeyEntry, KeyHierarchyLevel, KeyLease, KeyLifecycleState, KmsCap,
    KmsError, LeaseState, Sha256, KEY_DATA_LEN, MAX_KEYS, MAX_LEASES, MAX_ESCROWS,
    MAX_NODES,
};

/// Exécute la suite complète de validation formelle du KMS distribué et du séquestre cryptographique (Phase 108)
pub fn execute_kms_daemon_test() -> bool {
    kprintln!(
        "[KMS/TEST] Démarrage du test de validation de la gestion de clés et séquestre distribué (Phase 108)..."
    );

    // 1. Contrôle d'accès capabilaire (KmsCap) et atténuation monotone
    let admin_cap = KmsCap::new(Handle::new(10801, 1), kms_rights::ALL, 0, MAX_KEYS as u16);
    assert!(admin_cap.has_right(kms_rights::CREATE_KEY));
    assert!(admin_cap.has_right(kms_rights::DERIVE_KEY));
    assert!(admin_cap.has_right(kms_rights::GRANT_LEASE));
    assert!(admin_cap.has_right(kms_rights::RENEW_LEASE));
    assert!(admin_cap.has_right(kms_rights::ESCROW_KEY));
    assert!(admin_cap.has_right(kms_rights::RECOVER_KEY));
    assert!(admin_cap.has_right(kms_rights::ROTATE_KEY));
    assert!(admin_cap.has_right(kms_rights::REPLICATE));
    assert!(admin_cap.has_right(kms_rights::REVOKE_KEY));
    assert!(admin_cap.has_right(kms_rights::ZEROIZE_KEY));
    assert!(admin_cap.has_right(kms_rights::AUDIT_LOG));

    let operator_cap = admin_cap
        .attenuate(kms_rights::CREATE_KEY | kms_rights::DERIVE_KEY | kms_rights::GRANT_LEASE, 16)
        .expect("Atténuation monotone KmsCap");
    assert!(operator_cap.has_right(kms_rights::CREATE_KEY));
    assert!(operator_cap.has_right(kms_rights::GRANT_LEASE));
    assert!(!operator_cap.has_right(kms_rights::ESCROW_KEY));
    assert!(!operator_cap.has_right(kms_rights::ZEROIZE_KEY));

    // Rejet formel de toute tentative d'amplification
    assert_eq!(
        operator_cap.attenuate(kms_rights::ALL, 16),
        Err(KmsError::PermissionDenied),
        "Amplification de droits KmsCap formellement rejetée"
    );
    assert_eq!(
        operator_cap.attenuate(kms_rights::CREATE_KEY, 32),
        Err(KmsError::PermissionDenied),
        "Augmentation du quota de clés KmsCap formellement rejetée"
    );
    kprintln!("[KMS/CAP] Contrôle d'accès capabilaire KmsCap et atténuation monotone validés");

    // 2. Initialisation du démon KMS souverain
    let mut daemon = JamboKmsDaemon::new(admin_cap);
    daemon.init_defaults();
    assert!(daemon.key_count >= 3, "Clés par défaut initialisées");
    assert!(daemon.node_count >= 2, "Nœuds de grappe initialisés");
    assert!(daemon.lease_count >= 1, "Baux par défaut initialisés");
    kprintln!("[KMS/INIT] Démon KMS souverain et topologie de grappe initialisés");

    // 3. Hiérarchies cryptographiques & Dérivation HKDF RFC 5869
    let master_key = daemon.keys[0];
    assert_eq!(master_key.level, KeyHierarchyLevel::MasterKey);

    let session_key_id = daemon
        .derive_child_key(
            &admin_cap,
            master_key.key_id,
            b"test-session-token",
            KeyHierarchyLevel::DomainKey,
            KeyAlgorithm::Aes256,
            b"purpose=test-session,epoch=1",
        )
        .expect("Dérivation hiérarchique réussie");

    let session_key = *daemon.get_key(session_key_id).expect("Clé dérivée existante");
    assert_eq!(session_key.parent_id, master_key.key_id);
    assert_eq!(session_key.state, KeyLifecycleState::Active);

    // Tentative de dérivation avec élévation hiérarchique invalide
    assert_eq!(
        daemon.derive_child_key(
            &admin_cap,
            session_key_id,
            b"invalid-elevation",
            KeyHierarchyLevel::MasterKey,
            KeyAlgorithm::Aes256,
            b"unauthorized",
        ),
        Err(KmsError::InvalidHierarchy),
        "Élévation hiérarchique invalide formellement rejetée"
    );
    kprintln!("[KMS/HIERARCHY] Hiérarchies cryptographiques et dérivation HKDF validées");

    // 4. Baux temporels, quotas et renouvellement
    let lease_id = daemon
        .grant_lease(
            &admin_cap,
            session_key_id,
            0,
            lease_ops::OP_ENCRYPT | lease_ops::OP_DECRYPT,
            50,
            1000,
            daemon.current_ticks,
            2,
        )
        .expect("Octroi de bail");

    // Consommation d'opérations autorisées
    for _ in 0..10 {
        assert!(daemon.consume_lease_op(lease_id, daemon.current_ticks + 50, lease_ops::OP_ENCRYPT).is_ok());
    }
    assert_eq!(daemon.get_lease(lease_id).unwrap().used_ops, 10);

    // Tentative d'opération non permise par le bail
    assert_eq!(
        daemon.consume_lease_op(lease_id, daemon.current_ticks + 50, lease_ops::OP_SIGN),
        Err(KmsError::PermissionDenied),
        "Opération hors mandat de bail rejetée"
    );

    // Renouvellement de bail
    assert!(daemon.renew_lease(&admin_cap, lease_id, 500, daemon.current_ticks + 100).is_ok());
    assert_eq!(daemon.get_lease(lease_id).unwrap().renewed_count, 1);
    assert_eq!(daemon.get_lease(lease_id).unwrap().state, LeaseState::Renewed);
    kprintln!("[KMS/LEASE] Baux temporels, quotas d'opérations et renouvellement validés");

    // 5. Séquestre M-sur-N & Partage de Secret Shamir GF(256)
    let mut shares = [[0u8; KEY_DATA_LEN]; 3];
    let escrow_id = daemon
        .setup_escrow(&admin_cap, session_key_id, 2, 3, &mut shares)
        .expect("Configuration du séquestre");

    assert_eq!(
        daemon.get_key(session_key_id).unwrap().state,
        KeyLifecycleState::Escrowed,
        "Clé séquestrée passée en statut Escrowed"
    );

    // Dépôt de part 1
    let met1 = daemon
        .submit_escrow_share(&admin_cap, escrow_id, 0, &shares[0])
        .expect("Dépôt part 1");
    assert!(!met1, "Quorum 2/3 pas encore atteint");

    // Dépôt d'une fausse part corrompue (falsification)
    let bad_share = [0xEEu8; KEY_DATA_LEN];
    assert_eq!(
        daemon.submit_escrow_share(&admin_cap, escrow_id, 1, &bad_share),
        Err(KmsError::InvalidCustodianShare),
        "Part falsifiée rejetée par vérification d'engagement SHA-256"
    );

    // Dépôt de part 2 -> Quorum atteint
    let met2 = daemon
        .submit_escrow_share(&admin_cap, escrow_id, 1, &shares[1])
        .expect("Dépôt part 2");
    assert!(met2, "Quorum 2/3 atteint");

    // Restauration de la clé séquestrée
    let recovered_mat = daemon
        .recover_escrowed_key(&admin_cap, escrow_id)
        .expect("Restauration de la clé séquestrée");
    assert_eq!(recovered_mat, session_key.material, "Matériel cryptographique restauré intègre");
    assert_eq!(
        daemon.get_key(session_key_id).unwrap().state,
        KeyLifecycleState::Active,
        "Clé réactivée après recouvrement"
    );
    kprintln!("[KMS/ESCROW] Séquestre de clés M-sur-N et recouvrement Shamir GF(256) validés");

    // 6. Réplication chiffrée multi-nœuds (Enveloppes ChaCha20 + HMAC-SHA256)
    let env_id = daemon
        .create_replication_envelope(&admin_cap, session_key_id, 1)
        .expect("Création de l'enveloppe de réplication");

    let replicated_kid = daemon
        .receive_replication_envelope(&admin_cap, env_id)
        .expect("Réception et déballage de l'enveloppe");
    let rep_key = daemon.get_key(replicated_kid).expect("Clé répliquée présente");
    assert_eq!(rep_key.material, session_key.material, "Clé répliquée identique");
    kprintln!("[KMS/REPLICATION] Réplication chiffrée multi-nœuds et validation HMAC validées");

    // 7. Rotation de clés, révocation et zéroïsation
    let rotated_material = [0x5Au8; KEY_DATA_LEN];
    daemon
        .rotate_key(&admin_cap, session_key_id, &rotated_material)
        .expect("Rotation atomique de clé");
    assert_eq!(daemon.get_key(session_key_id).unwrap().rotation_count, 1);
    assert_eq!(daemon.get_key(session_key_id).unwrap().material, rotated_material);

    daemon
        .revoke_key(&admin_cap, session_key_id)
        .expect("Révocation de clé");
    assert_eq!(
        daemon.get_key(session_key_id).unwrap().state,
        KeyLifecycleState::Revoked
    );
    assert_eq!(
        daemon.get_lease(lease_id).unwrap().state,
        LeaseState::Revoked,
        "Baux associés révoqués en cascade"
    );

    daemon
        .zeroize_key(&admin_cap, session_key_id)
        .expect("Zéroïsation d'urgence de la clé");
    assert_eq!(
        daemon.get_key(session_key_id).unwrap().state,
        KeyLifecycleState::Destroyed
    );
    assert_eq!(
        daemon.get_key(session_key_id).unwrap().material,
        [0u8; KEY_DATA_LEN],
        "Mémoire volatile de la clé complètement scrubbée"
    );
    kprintln!("[KMS/LIFECYCLE] Rotation atomique, révocation en cascade et zéroïsation validées");

    // 8. Commandes Shell Ring 3 (jsh)
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 1024];

    let commands = [
        "kms status",
        "kms keys",
        "kms leases",
        "kms escrow",
        "kms replicate",
        "kms benchmark",
        "kms audit",
    ];

    for cmd in &commands {
        let (status, written) = shell.execute_line(cmd, &mut out_buf);
        assert_eq!(status, ShellStatus::Success, "Échec commande shell : {}", cmd);
        assert!(written > 0, "Sortie vide pour commande : {}", cmd);
    }
    kprintln!("[KMS/SHELL] Commandes interactives Shell jsh kms validées");

    kprintln!(
        "\x1b[1;32m[KMS/SUCCESS] Phase 108 - Gestion et Séquestre de Clés Distribuées (jambo-kms) validée avec succès !\x1b[0m"
    );
    true
}

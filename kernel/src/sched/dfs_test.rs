//! Module de validation du Stockage Distribué Adressé par le Contenu & Réplication par Blocs (Phase 64 - v0.2.62)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_dfsd::{
    compute_block_hash, dfs_rights, DfsBlockStore, DfsCap, JamboDfsDaemon, BLOCK_SIZE, HASH_SIZE,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du stockage distribué adressé par le contenu (Phase 64)
pub fn execute_dfs_storage_test() -> bool {
    kprintln!(
        "[DFS/TEST] Démarrage du test du stockage distribué adressé par le contenu (Phase 64)..."
    );

    // 1. Validation du contrôle d'accès capabilaire (DfsCap)
    let admin_cap = DfsCap::new(Handle::new(64, 1), dfs_rights::ALL);
    assert!(admin_cap.has_right(dfs_rights::DFS_READ));
    assert!(admin_cap.has_right(dfs_rights::DFS_WRITE));
    assert!(admin_cap.has_right(dfs_rights::DFS_PIN));
    assert!(admin_cap.has_right(dfs_rights::DFS_REPLICATE));
    assert!(admin_cap.has_right(dfs_rights::DFS_DELETE));

    let read_only_cap = admin_cap
        .attenuate(dfs_rights::DFS_READ)
        .expect("attenuate DfsCap to read-only");
    let mut raw_store = DfsBlockStore::new(1);
    let test_data = b"Microkernel Confined CAS Block Data 2026";
    assert_eq!(
        raw_store.put_block(&read_only_cap, test_data, false),
        Err(SysError::PermissionDenied),
        "Écriture sans droit DFS_WRITE doit être rejetée"
    );
    kprintln!("[DFS/CAP] Confinement capabilaire DfsCap et autorité ambiante zéro validés");

    // 2. Écriture & lecture CAS avec calcul d'empreinte 256 bits et intégrité
    let mut store = DfsBlockStore::new(1);
    let hash = store
        .put_block(&admin_cap, test_data, false)
        .expect("put_block CAS");
    let expected_hash = compute_block_hash(test_data);
    assert_eq!(
        hash, expected_hash,
        "L'empreinte retournée doit correspondre au hash CAS"
    );

    let mut read_buf = [0u8; 128];
    let n = store
        .get_block(&admin_cap, &hash, &mut read_buf)
        .expect("get_block CAS");
    assert_eq!(&read_buf[..n], test_data);
    assert_eq!(store.block_count(), 1);
    kprintln!("[DFS/CAS] Écriture et lecture avec vérification d'empreinte cryptographique 256 bits validées");

    // 3. Déduplication de blocs CAS & décompte de références
    let hash2 = store
        .put_block(&admin_cap, test_data, false)
        .expect("put_block duplicate CAS");
    assert_eq!(hash, hash2);
    assert_eq!(store.block_count(), 1, "Le bloc doit être dédupliqué");
    assert_eq!(store.dedup_count, 1);

    // Décrémentation de référence
    let deleted = store.delete_block(&admin_cap, &hash).expect("delete ref 1");
    assert!(
        !deleted,
        "Le bloc ne doit pas être supprimé car ref_count > 0"
    );
    assert_eq!(store.block_count(), 1);
    kprintln!("[DFS/DEDUP] Déduplication transparente CAS et comptage de références validés");

    // 4. Réplication distribuée multi-nœuds
    store
        .add_replica(&admin_cap, &hash, 2)
        .expect("add replica node 2");
    store
        .add_replica(&admin_cap, &hash, 4)
        .expect("add replica node 4");
    assert_eq!(
        store.replica_count(&hash).expect("replica count"),
        3,
        "Le bloc doit être répliqué sur le nœud local (1) + nœuds 2 et 4"
    );
    kprintln!("[DFS/REPLICA] Réplication de blocs multi-nœuds et masque de nœuds validés");

    // 5. Épinglage persistant et protection contre l'éviction
    store
        .pin_block(&admin_cap, &hash, true)
        .expect("pin block CAS");
    assert_eq!(
        store.delete_block(&admin_cap, &hash),
        Err(SysError::ResourceBusy),
        "Un bloc épinglé ne doit pas pouvoir être supprimé"
    );
    store
        .pin_block(&admin_cap, &hash, false)
        .expect("unpin block CAS");
    let physically_deleted = store
        .delete_block(&admin_cap, &hash)
        .expect("delete ref final");
    assert!(
        physically_deleted,
        "Le bloc déréférencé à 0 et dépinglé doit être supprimé"
    );
    assert_eq!(store.block_count(), 0);
    kprintln!("[DFS/PIN] Épinglage persistant et protection contre l'éviction validés");

    // 6. Démon orchestrateur JamboDfsDaemon
    let mut daemon = JamboDfsDaemon::new();
    let d_hash = daemon
        .put_block(b"Distributed Microkernel Shared Artifact", true)
        .expect("daemon put");
    assert_eq!(daemon.block_count(), 1);
    assert!(daemon.total_bytes() > 0);
    daemon.add_replica(&d_hash, 3).expect("daemon replica");
    assert_eq!(daemon.replica_count(&d_hash).expect("replica count"), 2);
    kprintln!("[DFS/DAEMON] Démon JamboDfsDaemon opérationnel");

    // 7. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'dfs status'
    let (st_stat, len_stat) = shell.execute_line("dfs status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("STOCKAGE DISTRIBUÉ ADRESSÉ PAR LE CONTENU"));
    assert!(str_stat.contains("Blocs CAS uniques"));
    assert!(str_stat.contains("DfsCap"));
    kprintln!("[DFS/SHELL] Commande 'dfs status' validée");

    // Commande 'dfs put'
    let (st_put, len_put) = shell.execute_line("dfs put CAS_TEST_DATA", &mut out_buf);
    assert_eq!(st_put, ShellStatus::Success);
    let str_put = core::str::from_utf8(&out_buf[..len_put]).unwrap_or("");
    assert!(str_put.contains("[DFS/CAS] Bloc stocké avec succès"));
    kprintln!("[DFS/SHELL] Commande 'dfs put' validée");

    // Commande 'dfs pin'
    let (st_pin, len_pin) = shell.execute_line("dfs pin", &mut out_buf);
    assert_eq!(st_pin, ShellStatus::Success);
    let str_pin = core::str::from_utf8(&out_buf[..len_pin]).unwrap_or("");
    assert!(str_pin.contains("[DFS/PIN] Bloc CAS épinglé"));
    kprintln!("[DFS/SHELL] Commande 'dfs pin' validée");

    // Commande 'dfs del'
    let (st_del, len_del) = shell.execute_line("dfs del", &mut out_buf);
    assert_eq!(st_del, ShellStatus::ExecutionFailed); // Car le bloc est épinglé !
    let str_del = core::str::from_utf8(&out_buf[..len_del]).unwrap_or("");
    assert!(str_del.contains("Aucun bloc libérable ou bloc épinglé"));
    kprintln!("[DFS/SHELL] Commande 'dfs del' validée");

    kprintln!(
        "[DFS/PASS] Stockage distribué adressé par le contenu et réplication validés avec succès."
    );
    true
}

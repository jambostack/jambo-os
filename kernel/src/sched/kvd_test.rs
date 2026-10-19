//! Module de validation de la Base de Données Clé-Valeur Transactionnelle Distribuée (Phase 60 - v0.2.58)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_kvd::{
    kv_rights, CompareOp, CompareTarget, JamboKvDaemon, KeyValue, KvCap, KvCompare, KvOp, KvStore,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests de la base clé-valeur transactionnelle distribuée (Phase 60)
pub fn execute_kvd_store_test() -> bool {
    kprintln!("[KVD/TEST] Démarrage du test du magasin clé-valeur transactionnel (Phase 60)...");

    // 1. Validation du contrôle d'accès capabilaire (KvCap)
    let admin_cap = KvCap::new(Handle::new(60, 1), kv_rights::ALL);
    assert!(admin_cap.has_right(kv_rights::KV_READ));
    assert!(admin_cap.has_right(kv_rights::KV_WRITE));
    assert!(admin_cap.has_right(kv_rights::KV_DELETE));
    assert!(admin_cap.has_right(kv_rights::KV_TXN));
    assert!(admin_cap.has_right(kv_rights::KV_LEASE));

    let unauth_cap = KvCap::new(Handle::new(60, 2), 0);
    let mut raw_store = KvStore::new();
    assert_eq!(
        raw_store.put(&unauth_cap, b"security/key", b"payload", None),
        Err(SysError::PermissionDenied),
        "Écriture sans droit KV_WRITE doit être rejetée"
    );
    assert_eq!(
        raw_store.get(&unauth_cap, b"security/key"),
        Err(SysError::PermissionDenied),
        "Lecture sans droit KV_READ doit être rejetée"
    );
    kprintln!("[KVD/CAP] Confinement capabilaire KvCap et autorité ambiante zéro validés");

    // 2. Cycle de vie MVCC et révisions monotones
    let rev1 = raw_store
        .put(&admin_cap, b"net/mtu", b"1500", None)
        .expect("put net/mtu");
    assert_eq!(rev1, 1);
    let val1 = raw_store.get(&admin_cap, b"net/mtu").expect("get").unwrap();
    assert_eq!(val1.value_bytes(), b"1500");
    assert_eq!(val1.version, 1);
    assert_eq!(val1.create_revision, 1);

    let rev2 = raw_store
        .put(&admin_cap, b"net/mtu", b"9000", None)
        .expect("update net/mtu");
    assert_eq!(rev2, 2);
    let val2 = raw_store.get(&admin_cap, b"net/mtu").expect("get").unwrap();
    assert_eq!(val2.value_bytes(), b"9000");
    assert_eq!(val2.version, 2);
    assert_eq!(val2.create_revision, 1);
    assert_eq!(val2.mod_revision, 2);

    let del_ok = raw_store.delete(&admin_cap, b"net/mtu").expect("delete");
    assert!(del_ok);
    assert!(raw_store
        .get(&admin_cap, b"net/mtu")
        .expect("get")
        .is_none());
    kprintln!("[KVD/MVCC] Cycle MVCC, révisions logiques et tombstones validés");

    // 3. Baux temporels et expiration automatique (Leases)
    let lease_id = raw_store
        .grant_lease(&admin_cap, 500, 1000)
        .expect("grant lease");
    raw_store
        .put(&admin_cap, b"heartbeat/node-2", b"alive", Some(lease_id))
        .expect("put with lease");

    assert_eq!(raw_store.purge_expired_leases(1200), 0);
    assert!(raw_store
        .get(&admin_cap, b"heartbeat/node-2")
        .unwrap()
        .is_some());

    assert_eq!(raw_store.purge_expired_leases(1600), 1);
    assert!(raw_store
        .get(&admin_cap, b"heartbeat/node-2")
        .unwrap()
        .is_none());
    kprintln!("[KVD/LEASE] Baux temporels et purge d'expiration validés");

    // 4. Transactions atomiques Compare-And-Swap (CAS)
    raw_store
        .put(&admin_cap, b"consensus/leader", b"node-alpha", None)
        .expect("put leader");
    let cmp = [KvCompare::new(
        b"consensus/leader",
        CompareTarget::from_value_bytes(b"node-alpha"),
        CompareOp::Equal,
    )];
    let succ = [KvOp::new_put(b"consensus/leader", b"node-beta", None)];
    let fail = [];
    let txn_res = raw_store.txn(&admin_cap, &cmp, &succ, &fail).expect("txn");
    assert!(txn_res.succeeded);
    assert_eq!(
        raw_store
            .get(&admin_cap, b"consensus/leader")
            .unwrap()
            .unwrap()
            .value_bytes(),
        b"node-beta"
    );
    kprintln!("[KVD/TXN] Transactions atomiques CAS multi-opérations validées");

    // 5. Démon orchestrateur JamboKvDaemon
    let mut daemon = JamboKvDaemon::new();
    assert_eq!(daemon.revision(), 3);
    assert_eq!(daemon.active_keys_count(), 3);
    let cl_name = daemon.get(b"cluster/name").unwrap().unwrap();
    assert_eq!(cl_name.value_bytes(), b"jambo-cluster-0");

    let cas_res = daemon
        .cas(b"cluster/name", b"jambo-cluster-0", b"jambo-cluster-prod")
        .unwrap();
    assert!(cas_res);
    let updated = daemon.get(b"cluster/name").unwrap().unwrap();
    assert_eq!(updated.value_bytes(), b"jambo-cluster-prod");
    kprintln!("[KVD/DAEMON] Démon JamboKvDaemon opérationnel");

    // 6. Commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'kv status'
    let (st_stat, len_stat) = shell.execute_line("kv status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("BASE CLÉ-VALEUR TRANSACTIONNELLE DISTRIBUÉE"));
    assert!(str_stat.contains("Révision courante (MVCC)"));
    assert!(str_stat.contains("Clés actives"));
    kprintln!("[KVD/SHELL] Commande 'kv status' validée");

    // Commande 'kv put' & 'kv get'
    let (st_put, len_put) = shell.execute_line("kv put sys/hostname jambobox", &mut out_buf);
    assert_eq!(st_put, ShellStatus::Success);
    let str_put = core::str::from_utf8(&out_buf[..len_put]).unwrap_or("");
    assert!(str_put.contains("[KV/OK] Écriture validée"));

    let (st_get, len_get) = shell.execute_line("kv get sys/hostname", &mut out_buf);
    assert_eq!(st_get, ShellStatus::Success);
    let str_get = core::str::from_utf8(&out_buf[..len_get]).unwrap_or("");
    assert!(str_get.contains("jambobox"));
    kprintln!("[KVD/SHELL] Commandes 'kv put' et 'kv get' validées");

    // Commande 'kv cas'
    let (st_cas, len_cas) =
        shell.execute_line("kv cas sys/hostname jambobox jambonode-1", &mut out_buf);
    assert_eq!(st_cas, ShellStatus::Success);
    let str_cas = core::str::from_utf8(&out_buf[..len_cas]).unwrap_or("");
    assert!(str_cas.contains("[KV/TXN] Transaction CAS réussie"));

    let (_, len_get2) = shell.execute_line("kv get sys/hostname", &mut out_buf);
    let str_get2 = core::str::from_utf8(&out_buf[..len_get2]).unwrap_or("");
    assert!(str_get2.contains("jambonode-1"));
    kprintln!("[KVD/SHELL] Commande 'kv cas' validée");

    // Commande 'kv del'
    let (st_del, len_del) = shell.execute_line("kv del sys/hostname", &mut out_buf);
    assert_eq!(st_del, ShellStatus::Success);
    let str_del = core::str::from_utf8(&out_buf[..len_del]).unwrap_or("");
    assert!(str_del.contains("[KV/OK] Clé supprimée"));
    kprintln!("[KVD/SHELL] Commande 'kv del' validée");

    kprintln!(
        "[KVD/PASS] Base de données clé-valeur transactionnelle distribuée validée avec succès."
    );
    true
}

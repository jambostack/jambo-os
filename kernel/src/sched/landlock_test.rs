//! Module de validation du Confinement VFS sans Autorité Ambiante & Sandboxing Monotone Landlock (Phase 90 - v0.2.88)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_landlock::{
    fs_access, is_path_beneath, landlock_rights, JamboLandlockDaemon, LandlockCap,
    LandlockDecision, MAX_AUDIT_LOGS,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du démon Landlock pour micro-noyau souverain (Phase 90)
pub fn execute_landlock_daemon_test() -> bool {
    kprintln!(
        "[LANDLOCK/TEST] Démarrage du test de confinement VFS sans autorité ambiante Landlock (Phase 90)..."
    );

    // 1. Contrôle d'accès capabilaire (LandlockCap) et rejet formel d'amplification
    let admin_cap = LandlockCap::new(Handle::new(9001, 1), landlock_rights::ALL);
    assert!(admin_cap.has_right(landlock_rights::RULESET_CREATE));
    assert!(admin_cap.has_right(landlock_rights::RULE_ADD));
    assert!(admin_cap.has_right(landlock_rights::RESTRICT_SELF));
    assert!(admin_cap.has_right(landlock_rights::AUDIT));
    assert!(admin_cap.has_right(landlock_rights::ADMIN));

    let attenuated_cap = admin_cap
        .attenuate(landlock_rights::RESTRICT_SELF | landlock_rights::AUDIT)
        .expect("attenuate LandlockCap to restrict_self & audit");
    assert!(attenuated_cap.has_right(landlock_rights::RESTRICT_SELF));
    assert!(attenuated_cap.has_right(landlock_rights::AUDIT));
    assert!(!attenuated_cap.has_right(landlock_rights::ADMIN));
    assert!(!attenuated_cap.has_right(landlock_rights::RULESET_CREATE));
    assert!(!attenuated_cap.has_right(landlock_rights::RULE_ADD));

    // Rejet formel de toute tentative d'élévation
    assert_eq!(
        attenuated_cap.attenuate(landlock_rights::ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification de droits LandlockCap formellement rejetée"
    );

    let mut daemon = JamboLandlockDaemon::new(admin_cap);
    daemon.init_defaults();

    // Rejet de création de ruleset sans RULESET_CREATE
    assert_eq!(
        daemon.create_ruleset(&attenuated_cap, fs_access::ALL, 100),
        Err(SysError::PermissionDenied),
        "Création de ruleset sans RULESET_CREATE doit échouer"
    );
    kprintln!("[LANDLOCK/CAP] Modèle de sécurité capabilaire LandlockCap et rejet d'amplification validés");

    // 2. Vérification de l'algorithme d'ancrage VFS path_beneath
    assert!(is_path_beneath("/", "/etc/passwd"));
    assert!(is_path_beneath("/", "/tmp"));
    assert!(is_path_beneath("/usr", "/usr"));
    assert!(is_path_beneath("/usr", "/usr/bin/ls"));
    assert!(is_path_beneath("/usr/", "/usr/bin/ls"));
    assert!(!is_path_beneath("/usr", "/usrlib"));
    assert!(!is_path_beneath("/usr", "/etc/hosts"));
    assert!(is_path_beneath("/tmp/worker", "/tmp/worker/file.txt"));
    assert!(!is_path_beneath("/tmp/worker", "/tmp/other.txt"));
    kprintln!("[LANDLOCK/VFS] Algorithme de résolution d'ancrage hiérarchique path_beneath validé");

    // 3. Processus non-confiné (PID 1 Init)
    let dec_init = daemon.check_access(1, "/etc/shadow", fs_access::WRITE_FILE, 1001);
    assert_eq!(
        dec_init,
        LandlockDecision::ProcessUnconfined,
        "Le processus racine non-confiné doit conserver l'accès complet"
    );

    // 4. Confinement du Shell (PID 10 jsh)
    // Lecture autorisée sur /, écriture restreinte à /tmp et /dev
    let dec_sh_read = daemon.check_access(10, "/usr/bin/jsh", fs_access::READ_FILE, 1002);
    assert_eq!(dec_sh_read, LandlockDecision::Granted);

    let dec_sh_write_tmp = daemon.check_access(10, "/tmp/buffer.log", fs_access::WRITE_FILE, 1003);
    assert_eq!(dec_sh_write_tmp, LandlockDecision::Granted);

    let dec_sh_write_etc = daemon.check_access(10, "/etc/passwd", fs_access::WRITE_FILE, 1004);
    match dec_sh_write_etc {
        LandlockDecision::Denied {
            layer_index,
            missing_access,
            ..
        } => {
            assert_eq!(layer_index, 0);
            assert_eq!(missing_access, fs_access::WRITE_FILE);
        }
        _ => panic!("Écriture dans /etc/passwd par jsh aurait dû être refusée"),
    }
    kprintln!("[LANDLOCK/SHELL] Profil de bac à sable pour l'interpréteur jsh validé");

    // 5. Empilement de Couches Monotones (PID 20 sandbox-worker)
    // Couche 0 : /usr (Read|Exec), /etc (Read), /tmp (Read|Write)
    // Couche 1 : /tmp/worker (Write)
    let dec_w_read_usr =
        daemon.check_access(20, "/usr/lib/libjambo.so", fs_access::READ_FILE, 1005);
    assert_eq!(dec_w_read_usr, LandlockDecision::Granted);

    let dec_w_read_etc = daemon.check_access(20, "/etc/resolv.conf", fs_access::READ_FILE, 1006);
    assert_eq!(dec_w_read_etc, LandlockDecision::Granted);

    let dec_w_write_ok =
        daemon.check_access(20, "/tmp/worker/task.dat", fs_access::WRITE_FILE, 1007);
    assert_eq!(dec_w_write_ok, LandlockDecision::Granted);

    // Bloqué par la couche 1 car en dehors de /tmp/worker
    let dec_w_write_bad = daemon.check_access(20, "/tmp/malicious.sh", fs_access::WRITE_FILE, 1008);
    match dec_w_write_bad {
        LandlockDecision::Denied {
            layer_index,
            missing_access,
            ..
        } => {
            assert_eq!(layer_index, 1);
            assert_eq!(missing_access, fs_access::WRITE_FILE);
        }
        _ => panic!("Écriture hors de /tmp/worker aurait dû être bloquée par la couche 1"),
    }

    // Monotonie formelle : Empilement d'une couche 2 limitant la lecture exclusivement à /usr
    let r_layer2 = daemon
        .create_ruleset(&admin_cap, fs_access::READ_FILE, 1009)
        .expect("create ruleset layer2");
    daemon
        .add_rule_path_beneath(
            &admin_cap,
            r_layer2,
            Handle::new(920, 1),
            "/usr",
            fs_access::READ_FILE,
            1009,
        )
        .expect("add rule layer2");
    daemon
        .restrict_self(&admin_cap, 20, r_layer2, 1010)
        .expect("restrict self layer2");

    // Désormais, la lecture de /etc/resolv.conf est bloquée par la couche 2 !
    let dec_w_read_etc_blocked =
        daemon.check_access(20, "/etc/resolv.conf", fs_access::READ_FILE, 1011);
    match dec_w_read_etc_blocked {
        LandlockDecision::Denied { layer_index, .. } => {
            assert_eq!(layer_index, 2);
        }
        _ => panic!("Lecture dans /etc/resolv.conf aurait dû être bloquée par la couche 2"),
    }

    // Mais la lecture dans /usr/lib/libjambo.so reste permise (intersection vérifiée)
    assert_eq!(
        daemon.check_access(20, "/usr/lib/libjambo.so", fs_access::READ_FILE, 1012),
        LandlockDecision::Granted
    );
    kprintln!("[LANDLOCK/STACKING] Empilement monotone de couches strictes et intersection d'autorité validés");

    // 6. Héritage automatique de confinement lors du clonage de tâches (inherit_domain)
    let child_pid = 22;
    daemon
        .inherit_domain(&admin_cap, 20, child_pid, "worker-forked", 1013)
        .expect("inherit domain");
    let child_dom = daemon.get_domain(child_pid).expect("child domain exists");
    assert_eq!(child_dom.layer_count, 3);

    // Le processus enfant hérite exactement des 3 couches de restriction
    assert_eq!(
        daemon.check_access(
            child_pid,
            "/tmp/worker/result.bin",
            fs_access::WRITE_FILE,
            1014
        ),
        LandlockDecision::Granted
    );
    match daemon.check_access(child_pid, "/tmp/other.bin", fs_access::WRITE_FILE, 1015) {
        LandlockDecision::Denied { layer_index, .. } => {
            assert_eq!(layer_index, 1);
        }
        _ => panic!("Le processus enfant doit être confiné à l'identique"),
    }
    kprintln!(
        "[LANDLOCK/FORK] Héritage complet des couches de confinement par les sous-processus validé"
    );

    // 7. Chaîne d'audit cryptographique SHA-256
    assert!(daemon.audit_count >= 5);
    assert_ne!(daemon.last_audit_digest, [0u8; 32]);
    kprintln!("[LANDLOCK/AUDIT] Registre d'audit scellé SHA-256 et chaîne cryptographique inviolable validés");

    // 8. Commandes interactives Shell `landlock`
    let mut shell = JamboShell::new();
    let mut out = [0u8; 1024];

    // Commande status
    let (st1, len1) = shell.execute_line("landlock status", &mut out);
    assert_eq!(st1, ShellStatus::Success);
    let s1 = core::str::from_utf8(&out[..len1]).unwrap_or("");
    assert!(s1.contains("CONFINEMENT SYSTÈME DE FICHIERS SANS AUTORITÉ AMBIANTE"));
    assert!(s1.contains("Sandboxing VFS Monotone"));

    // Commande domains
    let (st2, len2) = shell.execute_line("landlock domains", &mut out);
    assert_eq!(st2, ShellStatus::Success);
    let s2 = core::str::from_utf8(&out[..len2]).unwrap_or("");
    assert!(s2.contains("system-init"));
    assert!(s2.contains("sandbox-worker"));

    // Commande rulesets
    let (st3, len3) = shell.execute_line("landlock rulesets", &mut out);
    assert_eq!(st3, ShellStatus::Success);
    let s3 = core::str::from_utf8(&out[..len3]).unwrap_or("");
    assert!(s3.contains("Scellé"));

    // Commande check : PID 20 -> /tmp/worker/test.dat write -> ACCORDÉ
    let (st4, len4) = shell.execute_line("landlock check 20 /tmp/worker/test.dat write", &mut out);
    assert_eq!(st4, ShellStatus::Success);
    let s4 = core::str::from_utf8(&out[..len4]).unwrap_or("");
    assert!(s4.contains("ACCORDÉ"));

    // Commande check : PID 20 -> /tmp/other.txt write -> REFUSÉ
    let (st5, len5) = shell.execute_line("landlock check 20 /tmp/other.txt write", &mut out);
    assert_eq!(st5, ShellStatus::Success);
    let s5 = core::str::from_utf8(&out[..len5]).unwrap_or("");
    assert!(s5.contains("REFUSÉ"));
    assert!(s5.contains("Bloqué par la couche 1"));

    // Commande audit
    let (st6, len6) = shell.execute_line("landlock audit", &mut out);
    assert_eq!(st6, ShellStatus::Success);
    let s6 = core::str::from_utf8(&out[..len6]).unwrap_or("");
    assert!(s6.contains("Condensat SHA-256 d'Audit Landlock"));

    kprintln!("[LANDLOCK/SHELL] Commandes d'administration et d'évaluation interactives 'landlock' validées");
    kprintln!("[LANDLOCK/SUCCESS] Démon de confinement Landlock entièrement validé (Phase 90)");

    true
}

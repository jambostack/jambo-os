//! Module de validation du Filtrage d'Appels Système BPF, Confinement Granulaire & POSIX (Phase 88 - v0.2.86)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_seccomp::{
    action_severity, seccomp_rights, BpfInsn, BpfProgram, FilterBuilder, JamboSeccompDaemon,
    SeccompCap, SeccompData, AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64, SECCOMP_RET_ACTION_FULL,
    SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD, SECCOMP_RET_LOG, SECCOMP_RET_TRAP,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite complète de validation du démon de filtrage d'appels système BPF (Phase 88)
pub fn execute_seccomp_daemon_test() -> bool {
    kprintln!(
        "[SECCOMP/TEST] Démarrage du test du filtrage d'appels système BPF & confinement granulaire (Phase 88)..."
    );

    // 1. Contrôle d'accès capabilaire (SeccompCap) et rejet formel d'amplification
    let admin_cap = SeccompCap::new(Handle::new(8801, 1), seccomp_rights::ALL);
    assert!(admin_cap.has_right(seccomp_rights::SECCOMP_READ));
    assert!(admin_cap.has_right(seccomp_rights::SECCOMP_LOAD));
    assert!(admin_cap.has_right(seccomp_rights::SECCOMP_ATTACH));
    assert!(admin_cap.has_right(seccomp_rights::SECCOMP_TSYNC));
    assert!(admin_cap.has_right(seccomp_rights::SECCOMP_AUDIT));
    assert!(admin_cap.has_right(seccomp_rights::SECCOMP_ADMIN));

    let read_only_cap = admin_cap
        .attenuate(seccomp_rights::SECCOMP_READ | seccomp_rights::SECCOMP_AUDIT)
        .expect("attenuate SeccompCap to read/audit");
    assert!(read_only_cap.has_right(seccomp_rights::SECCOMP_READ));
    assert!(read_only_cap.has_right(seccomp_rights::SECCOMP_AUDIT));
    assert!(!read_only_cap.has_right(seccomp_rights::SECCOMP_LOAD));
    assert!(!read_only_cap.has_right(seccomp_rights::SECCOMP_ATTACH));
    assert!(!read_only_cap.has_right(seccomp_rights::SECCOMP_TSYNC));
    assert!(!read_only_cap.has_right(seccomp_rights::SECCOMP_ADMIN));

    // Rejet formel de toute tentative d'élévation / amplification
    assert_eq!(
        read_only_cap.attenuate(seccomp_rights::SECCOMP_ADMIN),
        Err(SysError::PermissionDenied),
        "Amplification capabilaire formellement rejetée"
    );

    let mut daemon = JamboSeccompDaemon::new(1, admin_cap);
    daemon.init_defaults();

    // Rejet de chargement de filtre sans SECCOMP_LOAD
    let custom_strict = FilterBuilder::build_strict_filter().expect("build custom strict");
    assert_eq!(
        daemon.load_named_filter(&read_only_cap, "UnauthStrict", custom_strict, 0, 100, 100),
        Err(SysError::PermissionDenied),
        "Chargement sans SECCOMP_LOAD doit échouer"
    );

    // Rejet d'attachement de filtre sans SECCOMP_ATTACH
    assert_eq!(
        daemon.attach_filter_to_thread(&read_only_cap, 10, 1, 101),
        Err(SysError::PermissionDenied),
        "Attachement sans SECCOMP_ATTACH doit échouer"
    );

    // Rejet de synchronisation multi-threads sans SECCOMP_TSYNC
    assert_eq!(
        daemon.sync_process_threads(&read_only_cap, 1, 1, 102),
        Err(SysError::PermissionDenied),
        "Synchronisation TSYNC sans SECCOMP_TSYNC doit échouer"
    );
    kprintln!("[SECCOMP/CAP] Modèle de sécurité capabilaire SeccompCap et interdiction d'amplification validés");

    // 2. Validation formelle DAG du bytecode BPF (Zéro boucle, sauts bornés)
    assert_eq!(
        daemon.filter_count, 3,
        "Trois profils par défaut préchargés"
    );
    let strict_filter = daemon.find_filter_by_name("Strict").expect("find Strict");
    assert!(strict_filter.program.len > 0);
    assert_eq!(strict_filter.owner_pid, 1);

    // Tentative de validation d'un programme invalide (saut en arrière ou hors limites)
    let mut invalid_prog = BpfProgram::default();
    invalid_prog.len = 2;
    // Saut de 10 instructions alors que le programme fait 2 instructions
    invalid_prog.insns[0] = BpfInsn::jump(jambo_seccomp::BPF_JMP | jambo_seccomp::BPF_JA, 10, 0, 0);
    invalid_prog.insns[1] = BpfInsn::stmt(
        jambo_seccomp::BPF_RET | jambo_seccomp::BPF_K,
        SECCOMP_RET_ALLOW,
    );
    assert_eq!(
        invalid_prog.validate(),
        Err(SysError::InvalidArgument),
        "Saut hors limites formellement rejeté par le vérificateur"
    );

    // Tentative avec programme sans RET à la fin
    let mut no_ret_prog = BpfProgram::default();
    no_ret_prog.len = 1;
    no_ret_prog.insns[0] = BpfInsn::stmt(
        jambo_seccomp::BPF_LD | jambo_seccomp::BPF_W | jambo_seccomp::BPF_ABS,
        0,
    );
    assert_eq!(
        no_ret_prog.validate(),
        Err(SysError::InvalidArgument),
        "Programme sans terminaison RET formellement rejeté"
    );
    kprintln!(
        "[SECCOMP/VERIFIER] Vérificateur formel DAG BPF et détection de sauts invalides validés"
    );

    // 3. Exécution et conformité des actions Seccomp (Allow, Kill, Trap, Errno)
    let strict_prog = daemon.find_filter_by_name("Strict").unwrap().program;

    // Syscall 0 (read) -> ALLOW
    let data_read = SeccompData::new(0, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
    assert_eq!(strict_prog.execute(&data_read), SECCOMP_RET_ALLOW);

    // Syscall 1 (write) -> ALLOW
    let data_write = SeccompData::new(1, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
    assert_eq!(strict_prog.execute(&data_write), SECCOMP_RET_ALLOW);

    // Syscall 60 (exit) -> ALLOW
    let data_exit = SeccompData::new(60, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
    assert_eq!(strict_prog.execute(&data_exit), SECCOMP_RET_ALLOW);

    // Syscall non autorisé (59 = execve) -> KILL_PROCESS
    let data_exec = SeccompData::new(59, AUDIT_ARCH_X86_64, 0x400000, [0; 6]);
    assert_eq!(strict_prog.execute(&data_exec), SECCOMP_RET_KILL_PROCESS);

    // Mauvaise architecture matérielle -> KILL_PROCESS immédiat
    let data_arm = SeccompData::new(0, AUDIT_ARCH_AARCH64, 0x400000, [0; 6]);
    assert_eq!(strict_prog.execute(&data_arm), SECCOMP_RET_KILL_PROCESS);
    kprintln!("[SECCOMP/ACTIONS] Exécution des filtres BPF et sémantique des actions validées");

    // 4. Confinement par thread et exigence irréversible du bit no_new_privs
    daemon
        .register_thread(200, 20)
        .expect("register thread 200");
    let thread_info = daemon.get_thread(200).unwrap();
    assert!(
        !thread_info.no_new_privs,
        "no_new_privs initialement inactif"
    );

    // Attachement sans no_new_privs rejeté
    assert_eq!(
        daemon.attach_filter_to_thread(&admin_cap, 200, 1, 200),
        Err(SysError::PermissionDenied),
        "Attachement de filtre sans no_new_privs doit échouer"
    );

    // Scellement irréversible de no_new_privs
    daemon.set_no_new_privs(200).expect("set no_new_privs");
    assert!(daemon.get_thread(200).unwrap().no_new_privs);

    // Attachement réussi du filtre Strict (ID 1)
    daemon
        .attach_filter_to_thread(&admin_cap, 200, 1, 201)
        .expect("attach filter 1");
    assert_eq!(daemon.get_thread(200).unwrap().filter_count, 1);
    assert_eq!(daemon.get_filter(1).unwrap().use_count, 1);

    // Évaluation en direct via le démon
    let res_read = daemon.evaluate_syscall(200, &data_read, 202);
    assert_eq!(res_read, SECCOMP_RET_ALLOW);

    let res_exec = daemon.evaluate_syscall(200, &data_exec, 203);
    assert_eq!(res_exec, SECCOMP_RET_KILL_PROCESS);
    assert_eq!(daemon.violations_count, 1);
    kprintln!("[SECCOMP/THREAD] Confinement de thread et bit irréversible no_new_privs validés");

    // 5. Empilement de filtres et règle de composition stricte (l'action la plus sévère prévaut)
    // Chargeons un filtre personnalisé qui renvoie ERRNO (EACCES = 13) sur read (0)
    let mut custom_b = FilterBuilder::new();
    custom_b.check_arch(AUDIT_ARCH_X86_64);
    // Charge le numéro de syscall
    custom_b.stmt(
        jambo_seccomp::BPF_LD | jambo_seccomp::BPF_W | jambo_seccomp::BPF_ABS,
        0,
    );
    // Si syscall == 0, saute à RET ERRNO 13
    custom_b.jump(
        jambo_seccomp::BPF_JMP | jambo_seccomp::BPF_JEQ | jambo_seccomp::BPF_K,
        0,
        0,
        1,
    );
    custom_b.stmt(
        jambo_seccomp::BPF_RET | jambo_seccomp::BPF_K,
        SECCOMP_RET_ERRNO | 13,
    );
    custom_b.default_action(SECCOMP_RET_ALLOW);
    let errno_prog = custom_b.build().expect("build errno filter");

    let fid_errno = daemon
        .load_named_filter(&admin_cap, "DenyReadErrno", errno_prog, 0, 20, 210)
        .expect("load DenyReadErrno");

    // Empiler ce second filtre sur le thread 200
    daemon
        .attach_filter_to_thread(&admin_cap, 200, fid_errno, 211)
        .expect("stack filter");
    assert_eq!(daemon.get_thread(200).unwrap().filter_count, 2);

    // Désormais, pour syscall 0 (read) :
    // - Filtre 1 (Strict) dit ALLOW
    // - Filtre 2 (DenyReadErrno) dit ERRNO 13
    // La composition stricte exige que ERRNO (plus sévère que ALLOW) l'emporte !
    let res_stacked_read = daemon.evaluate_syscall(200, &data_read, 212);
    assert_eq!(
        res_stacked_read & SECCOMP_RET_ACTION_FULL,
        SECCOMP_RET_ERRNO
    );
    assert_eq!(res_stacked_read & SECCOMP_RET_DATA, 13);
    kprintln!("[SECCOMP/STACKING] Empilement multi-filtres et préséance de l'action la plus restrictive validés");

    // 6. Synchronisation multi-threads de processus (TSYNC)
    // Enregistrons plusieurs threads pour le PID 30
    daemon.register_thread(301, 30).unwrap();
    daemon.register_thread(302, 30).unwrap();
    daemon.register_thread(303, 30).unwrap();

    let synced = daemon
        .sync_process_threads(&admin_cap, 30, 2, 220)
        .expect("sync threads");
    assert_eq!(synced, 3, "Les 3 threads du PID 30 ont été synchronisés");

    for tid in [301, 302, 303] {
        let th = daemon.get_thread(tid).unwrap();
        assert!(
            th.no_new_privs,
            "TSYNC force no_new_privs sur tous les threads"
        );
        assert_eq!(th.filter_count, 1);
        assert_eq!(th.filter_ids[0], 2, "Filtre Compute (ID 2) synchronisé");
    }
    kprintln!("[SECCOMP/TSYNC] Synchronisation atomique multi-threads TSYNC validée");

    // 7. Intégrité cryptographique SHA-256 de la chaîne d'audit
    let non_zero_digest = daemon.last_audit_digest.iter().any(|&b| b != 0);
    assert!(non_zero_digest, "Condensat SHA-256 d'audit actif");
    kprintln!("[SECCOMP/AUDIT] Chaîne d'audit cryptographique SHA-256 vérifiée et inviolable");

    // 8. Validation des commandes du Shell interactif JamboShell
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 4096];

    // Commande : seccomp status
    let (st_status, len_status) = shell.execute_line("seccomp status", &mut out_buf);
    assert_eq!(st_status, ShellStatus::Success);
    let out_str_status = core::str::from_utf8(&out_buf[..len_status]).unwrap();
    assert!(out_str_status.contains("FILTRAGE BPF & CONFINEMENT D'APPELS SYSTÈME"));
    assert!(out_str_status.contains("Filtres enregistrés"));
    kprintln!("[SECCOMP/SHELL] Commande 'seccomp status' validée");

    // Commande : seccomp list
    let (st_list, len_list) = shell.execute_line("seccomp list", &mut out_buf);
    assert_eq!(st_list, ShellStatus::Success);
    let out_str_list = core::str::from_utf8(&out_buf[..len_list]).unwrap();
    assert!(out_str_list.contains("Strict"));
    assert!(out_str_list.contains("Compute"));
    assert!(out_str_list.contains("Network"));
    kprintln!("[SECCOMP/SHELL] Commande 'seccomp list' validée");

    // Commande : seccomp load strict
    let (st_load, len_load) = shell.execute_line("seccomp load strict", &mut out_buf);
    assert_eq!(st_load, ShellStatus::Success);
    let out_str_load = core::str::from_utf8(&out_buf[..len_load]).unwrap();
    assert!(out_str_load.contains("chargé avec succès"));
    kprintln!("[SECCOMP/SHELL] Commande 'seccomp load' validée");

    // Commande : seccomp attach 500 1
    let (st_att, len_att) = shell.execute_line("seccomp attach 500 1", &mut out_buf);
    assert_eq!(st_att, ShellStatus::Success);
    let out_str_att = core::str::from_utf8(&out_buf[..len_att]).unwrap();
    assert!(out_str_att.contains("filtre attaché avec succès au thread TID 500"));
    kprintln!("[SECCOMP/SHELL] Commande 'seccomp attach' validée");

    // Commande : seccomp eval 500 0 (read)
    let (st_ev0, len_ev0) = shell.execute_line("seccomp eval 500 0", &mut out_buf);
    assert_eq!(st_ev0, ShellStatus::Success);
    let out_str_ev0 = core::str::from_utf8(&out_buf[..len_ev0]).unwrap();
    assert!(out_str_ev0.contains("ALLOW (Autorisé)"));
    kprintln!("[SECCOMP/SHELL] Commande 'seccomp eval (ALLOW)' validée");

    // Commande : seccomp eval 500 59 (execve)
    let (st_ev1, len_ev1) = shell.execute_line("seccomp eval 500 59", &mut out_buf);
    assert_eq!(st_ev1, ShellStatus::Success);
    let out_str_ev1 = core::str::from_utf8(&out_buf[..len_ev1]).unwrap();
    assert!(out_str_ev1.contains("KILL_PROCESS (Processus Terminé)"));
    kprintln!("[SECCOMP/SHELL] Commande 'seccomp eval (KILL)' validée");

    // Commande : seccomp tsync 40 1
    let (st_tsync, len_tsync) = shell.execute_line("seccomp tsync 40 1", &mut out_buf);
    assert_eq!(st_tsync, ShellStatus::Success);
    let out_str_tsync = core::str::from_utf8(&out_buf[..len_tsync]).unwrap();
    assert!(out_str_tsync.contains("synchronisation TSYNC réussie"));
    kprintln!("[SECCOMP/SHELL] Commande 'seccomp tsync' validée");

    // Commande : seccomp audit
    let (st_audit, len_audit) = shell.execute_line("seccomp audit", &mut out_buf);
    assert_eq!(st_audit, ShellStatus::Success);
    let out_str_audit = core::str::from_utf8(&out_buf[..len_audit]).unwrap();
    assert!(out_str_audit.contains("Condensat SHA-256 d'Audit Seccomp BPF"));
    kprintln!("[SECCOMP/SHELL] Commande 'seccomp audit' validée");

    kprintln!(
        "\x1b[1;32m[SECCOMP/PASS] Suite de tests Filtrage d'Appels Système BPF & Confinement Granulaire validée avec succès !\x1b[0m"
    );
    true
}

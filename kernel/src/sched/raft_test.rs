//! Module de validation du Moteur de Consensus Distribué Léger Raft (Phase 59 - v0.2.57)
#![allow(unused_imports, dead_code)]

extern crate alloc;

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_raft::{
    raft_rights, AppendEntriesArgs, JamboRaftDaemon, RaftCap, RaftNode, RaftRole, RequestVoteArgs,
    RequestVoteReply,
};
use jambo_sh::{JamboShell, ShellStatus};

/// Exécute la suite de tests du consensus distribué Raft et réplication d'état (Phase 59)
pub fn execute_raft_consensus_test() -> bool {
    kprintln!("[RAFT/TEST] Démarrage du test de consensus distribué Raft (Phase 59)...");

    // 1. Validation du contrôle d'accès capabilaire (RaftCap)
    let admin_cap = RaftCap::new(Handle::new(59, 1), 10, raft_rights::ALL);
    assert!(admin_cap.can_elect());
    assert!(admin_cap.can_append());
    assert!(admin_cap.can_change_config());
    assert!(admin_cap.can_read_state());

    let unauth_cap = RaftCap::new(Handle::new(59, 2), 10, 0);
    assert!(!unauth_cap.can_elect());
    assert!(!unauth_cap.can_append());
    assert!(!unauth_cap.can_change_config());
    assert!(!unauth_cap.can_read_state());

    let mut node_auth = RaftNode::new(1, 10);
    assert_eq!(
        node_auth.start_election(&unauth_cap).err(),
        Some(SysError::PermissionDenied),
        "Démarrer une élection sans droit RAFT_LEADER_ELECT doit être rejeté"
    );
    kprintln!("[RAFT/CAP] Droits capabilitaires RaftCap et confinement zéro-autorité validés");

    // 2. Validation de l'élection de Leader et formation du quorum majoritaire
    let mut node = RaftNode::new(1, 10);
    assert_eq!(node.role, RaftRole::Follower);

    let vote_args = node.start_election(&admin_cap).expect("start election");
    assert_eq!(node.role, RaftRole::Candidate);
    assert_eq!(node.current_term, 1);
    assert_eq!(vote_args.term, 1);
    assert_eq!(vote_args.candidate_id, 1);

    // Vote favorable d'un pair (Cluster de 3 nœuds, quorum = 2)
    let reply = RequestVoteReply {
        term: 1,
        vote_granted: true,
    };
    node.record_vote(&admin_cap, &reply, 3);
    assert_eq!(node.role, RaftRole::Leader);
    kprintln!("[RAFT/ELECTION] Transition Candidate -> Leader et quorum majoritaire validés");

    // 3. Validation de la réplication de journal (AppendEntries) et application de la machine à états
    let entry = node
        .propose_command(&admin_cap, 101, b"RAFT_CLUSTER_CONFIG_PAYLOAD")
        .expect("propose command");
    assert_eq!(entry.index, 1);
    assert_eq!(entry.term, 1);

    let mut follower = RaftNode::new(2, 10);
    let append_args = AppendEntriesArgs {
        term: 1,
        leader_id: 1,
        prev_log_index: 0,
        prev_log_term: 0,
        entry: Some(entry),
        leader_commit: 1,
    };
    let append_rep = follower
        .handle_append_entries(&admin_cap, &append_args)
        .expect("handle append");
    assert!(append_rep.success);
    assert_eq!(follower.commit_index, 1);

    let applied = follower.apply_committed();
    assert_eq!(applied, 1);
    assert_eq!(follower.last_applied, 1);
    kprintln!("[RAFT/REPLICATION] Réplication de journal, log matching et commit index validés");

    // 4. Validation du démon orchestrateur JamboRaftDaemon
    let mut daemon = JamboRaftDaemon::new();
    daemon.init_defaults();
    let (role, term, commit, log_len) = daemon.status();
    assert_eq!(role, RaftRole::Leader);
    assert_eq!(term, 1);
    assert_eq!(commit, 1);
    assert_eq!(log_len, 1);

    let new_idx = daemon
        .propose(20, b"CONFIG_TRANSACTION_PAYLOAD")
        .expect("propose");
    assert_eq!(new_idx, 2);
    assert_eq!(daemon.node.commit_index, 2);

    let next_term = daemon.trigger_election().expect("trigger election");
    assert_eq!(next_term, 2);
    assert_eq!(daemon.node.role, RaftRole::Leader);
    kprintln!("[RAFT/DAEMON] Démon JamboRaftDaemon opérationnel de bout en bout");

    // 5. Validation des commandes interactives du shell jsh
    let mut shell = JamboShell::new();
    let mut out_buf = [0u8; 2048];

    // Commande 'raft status'
    let (st_stat, len_stat) = shell.execute_line("raft status", &mut out_buf);
    assert_eq!(st_stat, ShellStatus::Success);
    let str_stat = core::str::from_utf8(&out_buf[..len_stat]).unwrap_or("");
    assert!(str_stat.contains("MOTEUR DE CONSENSUS DISTRIBUÉ RAFT"));
    assert!(str_stat.contains("Leader (Coordinateur actif)"));
    assert!(str_stat.contains("Term #"));
    kprintln!("[RAFT/SHELL] Commande 'raft status' validée");

    // Commande 'raft propose'
    let (st_prop, len_prop) = shell.execute_line("raft propose CLUSTER_STATE_CHANGE", &mut out_buf);
    assert_eq!(st_prop, ShellStatus::Success);
    let str_prop = core::str::from_utf8(&out_buf[..len_prop]).unwrap_or("");
    assert!(str_prop.contains("Commande répliquée avec succès (Index #"));
    kprintln!("[RAFT/SHELL] Commande 'raft propose' validée");

    // Commande 'raft elect'
    let (st_elect, len_elect) = shell.execute_line("raft elect", &mut out_buf);
    assert_eq!(st_elect, ShellStatus::Success);
    let str_elect = core::str::from_utf8(&out_buf[..len_elect]).unwrap_or("");
    assert!(str_elect.contains("Élection déclenchée avec succès -> Leader au Term #"));
    kprintln!("[RAFT/SHELL] Commande 'raft elect' validée");

    kprintln!(
        "[RAFT/PASS] Moteur de consensus distribué Raft & réplication d'état validés avec succès."
    );
    true
}

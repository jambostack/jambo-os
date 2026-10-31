//! Moteur de Consensus Distribué Léger et Réplication d'État (jambo-raft)
//!
//! Fournit une coordination distribuée haute disponibilité basée sur l'algorithme Raft
//! en espace utilisateur Ring 3 sans autorité ambiante. Chaque opération de réplication,
//! d'élection ou de mutation de configuration est régie par une capacité `RaftCap`.

#![no_std]

use libjambo::{Handle, SysError};

/// Droits de capacité pour le consensus distribué Raft
pub mod raft_rights {
    pub const RAFT_LEADER_ELECT: u32 = 0x01;
    pub const RAFT_APPEND_ENTRIES: u32 = 0x02;
    pub const RAFT_CONFIG_CHANGE: u32 = 0x04;
    pub const RAFT_STATE_READ: u32 = 0x08;
    pub const ALL: u32 =
        RAFT_LEADER_ELECT | RAFT_APPEND_ENTRIES | RAFT_CONFIG_CHANGE | RAFT_STATE_READ;
}

/// Capacité d'administration du consensus de cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaftCap {
    pub handle: Handle,
    pub cluster_id: u32,
    pub rights: u32,
}

impl RaftCap {
    pub const fn new(handle: Handle, cluster_id: u32, rights: u32) -> Self {
        Self {
            handle,
            cluster_id,
            rights,
        }
    }

    pub fn can_elect(&self) -> bool {
        (self.rights & raft_rights::RAFT_LEADER_ELECT) != 0
    }

    pub fn can_append(&self) -> bool {
        (self.rights & raft_rights::RAFT_APPEND_ENTRIES) != 0
    }

    pub fn can_change_config(&self) -> bool {
        (self.rights & raft_rights::RAFT_CONFIG_CHANGE) != 0
    }

    pub fn can_read_state(&self) -> bool {
        (self.rights & raft_rights::RAFT_STATE_READ) != 0
    }
}

/// Rôle d'un nœud au sein du cluster Raft
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

pub const MAX_LOG_ENTRIES: usize = 64;
pub const MAX_PAYLOAD_SIZE: usize = 32;

/// Entrée de journal répliqué Raft
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaftLogEntry {
    pub term: u64,
    pub index: u64,
    pub command_id: u32,
    pub data: [u8; MAX_PAYLOAD_SIZE],
    pub data_len: usize,
}

impl Default for RaftLogEntry {
    fn default() -> Self {
        Self {
            term: 0,
            index: 0,
            command_id: 0,
            data: [0u8; MAX_PAYLOAD_SIZE],
            data_len: 0,
        }
    }
}

impl RaftLogEntry {
    pub fn new(term: u64, index: u64, command_id: u32, payload: &[u8]) -> Self {
        let mut data = [0u8; MAX_PAYLOAD_SIZE];
        let copy_len = payload.len().min(MAX_PAYLOAD_SIZE);
        data[..copy_len].copy_from_slice(&payload[..copy_len]);

        Self {
            term,
            index,
            command_id,
            data,
            data_len: copy_len,
        }
    }
}

/// Paramètres de requête de vote RPC Raft
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestVoteArgs {
    pub term: u64,
    pub candidate_id: u32,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

/// Réponse à une requête de vote
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestVoteReply {
    pub term: u64,
    pub vote_granted: bool,
}

/// Paramètres de réplication de journal (AppendEntries RPC)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendEntriesArgs {
    pub term: u64,
    pub leader_id: u32,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entry: Option<RaftLogEntry>,
    pub leader_commit: u64,
}

/// Réponse à la réplication de journal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendEntriesReply {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
}

/// Nœud de consensus distribué Raft
pub struct RaftNode {
    pub node_id: u32,
    pub cluster_id: u32,
    pub current_term: u64,
    pub voted_for: Option<u32>,
    pub role: RaftRole,
    pub commit_index: u64,
    pub last_applied: u64,
    pub log: [Option<RaftLogEntry>; MAX_LOG_ENTRIES],
    pub log_len: usize,
    pub votes_received: u32,
}

impl RaftNode {
    pub const fn new(node_id: u32, cluster_id: u32) -> Self {
        Self {
            node_id,
            cluster_id,
            current_term: 0,
            voted_for: None,
            role: RaftRole::Follower,
            commit_index: 0,
            last_applied: 0,
            log: [None; MAX_LOG_ENTRIES],
            log_len: 0,
            votes_received: 0,
        }
    }

    /// Déclenche une élection de leader (passage en Candidate)
    pub fn start_election(&mut self, cap: &RaftCap) -> Result<RequestVoteArgs, SysError> {
        if !cap.can_elect() || cap.cluster_id != self.cluster_id {
            return Err(SysError::PermissionDenied);
        }

        self.current_term += 1;
        self.role = RaftRole::Candidate;
        self.voted_for = Some(self.node_id);
        self.votes_received = 1; // Vote pour soi-même

        let (last_idx, last_term) = self.last_log_info();

        Ok(RequestVoteArgs {
            term: self.current_term,
            candidate_id: self.node_id,
            last_log_index: last_idx,
            last_log_term: last_term,
        })
    }

    /// Traite un vote reçu d'un pair
    pub fn record_vote(&mut self, cap: &RaftCap, reply: &RequestVoteReply, cluster_size: usize) {
        if !cap.can_elect() || cap.cluster_id != self.cluster_id {
            return;
        }

        if self.role == RaftRole::Candidate && reply.term == self.current_term && reply.vote_granted
        {
            self.votes_received += 1;
            let quorum = (cluster_size / 2) + 1;
            if self.votes_received as usize >= quorum {
                self.role = RaftRole::Leader;
            }
        }
    }

    /// Traite une demande de vote RPC (RequestVote)
    pub fn handle_request_vote(
        &mut self,
        cap: &RaftCap,
        args: &RequestVoteArgs,
    ) -> Result<RequestVoteReply, SysError> {
        if !cap.can_elect() || cap.cluster_id != self.cluster_id {
            return Err(SysError::PermissionDenied);
        }

        if args.term > self.current_term {
            self.current_term = args.term;
            self.role = RaftRole::Follower;
            self.voted_for = None;
        }

        let mut vote_granted = false;
        if args.term == self.current_term
            && (self.voted_for.is_none() || self.voted_for == Some(args.candidate_id))
        {
            let (last_idx, last_term) = self.last_log_info();
            // Le journal du candidat doit être au moins aussi à jour que le nôtre
            let log_ok = args.last_log_term > last_term
                || (args.last_log_term == last_term && args.last_log_index >= last_idx);

            if log_ok {
                vote_granted = true;
                self.voted_for = Some(args.candidate_id);
            }
        }

        Ok(RequestVoteReply {
            term: self.current_term,
            vote_granted,
        })
    }

    /// Traite une demande d'ajout d'entrées (AppendEntries / Pulsation)
    pub fn handle_append_entries(
        &mut self,
        cap: &RaftCap,
        args: &AppendEntriesArgs,
    ) -> Result<AppendEntriesReply, SysError> {
        if !cap.can_append() || cap.cluster_id != self.cluster_id {
            return Err(SysError::PermissionDenied);
        }

        if args.term < self.current_term {
            return Ok(AppendEntriesReply {
                term: self.current_term,
                success: false,
                match_index: self.commit_index,
            });
        }

        if args.term > self.current_term || self.role == RaftRole::Candidate {
            self.current_term = args.term;
            self.role = RaftRole::Follower;
            self.voted_for = Some(args.leader_id);
        }

        // Vérifier l'invariant du log matching si prev_log_index > 0
        if args.prev_log_index > 0 {
            if args.prev_log_index > self.log_len as u64 {
                return Ok(AppendEntriesReply {
                    term: self.current_term,
                    success: false,
                    match_index: self.log_len as u64,
                });
            }
            if let Some(entry) = self.log[args.prev_log_index as usize - 1] {
                if entry.term != args.prev_log_term {
                    return Ok(AppendEntriesReply {
                        term: self.current_term,
                        success: false,
                        match_index: args.prev_log_index - 1,
                    });
                }
            }
        }

        // Insérer la nouvelle entrée si présente
        if let Some(new_entry) = args.entry {
            let insert_idx = new_entry.index as usize;
            if insert_idx <= MAX_LOG_ENTRIES {
                self.log[insert_idx - 1] = Some(new_entry);
                if insert_idx > self.log_len {
                    self.log_len = insert_idx;
                }
            }
        }

        // Mettre à jour le commit_index
        if args.leader_commit > self.commit_index {
            self.commit_index = args.leader_commit.min(self.log_len as u64);
        }

        Ok(AppendEntriesReply {
            term: self.current_term,
            success: true,
            match_index: self.log_len as u64,
        })
    }

    /// Propose une commande sur le leader pour réplication
    pub fn propose_command(
        &mut self,
        cap: &RaftCap,
        command_id: u32,
        payload: &[u8],
    ) -> Result<RaftLogEntry, SysError> {
        if !cap.can_append() || cap.cluster_id != self.cluster_id {
            return Err(SysError::PermissionDenied);
        }

        if self.role != RaftRole::Leader {
            return Err(SysError::ResourceBusy);
        }

        if self.log_len >= MAX_LOG_ENTRIES {
            return Err(SysError::OutOfMemory);
        }

        let new_index = (self.log_len + 1) as u64;
        let entry = RaftLogEntry::new(self.current_term, new_index, command_id, payload);
        self.log[self.log_len] = Some(entry);
        self.log_len += 1;

        Ok(entry)
    }

    /// Applique les entrées validées à la machine à états locale
    pub fn apply_committed(&mut self) -> usize {
        let mut applied_count = 0;
        while self.last_applied < self.commit_index {
            self.last_applied += 1;
            applied_count += 1;
        }
        applied_count
    }

    fn last_log_info(&self) -> (u64, u64) {
        if self.log_len == 0 {
            (0, 0)
        } else if let Some(last) = self.log[self.log_len - 1] {
            (last.index, last.term)
        } else {
            (0, 0)
        }
    }
}

/// Démon orchestrateur de consensus distribué Raft (Ring 3)
pub struct JamboRaftDaemon {
    pub node: RaftNode,
    pub admin_cap: RaftCap,
    pub cluster_size: usize,
}

impl Default for JamboRaftDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboRaftDaemon {
    pub fn new() -> Self {
        let admin_cap = RaftCap::new(Handle::new(59, 1), 1, raft_rights::ALL);
        Self {
            node: RaftNode::new(1, 1),
            admin_cap,
            cluster_size: 3,
        }
    }

    /// Initialise le nœud en tant que Leader avec une entrée initiale validée
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;
        if let Ok(_) = self.node.start_election(&cap) {
            let reply = RequestVoteReply {
                term: self.node.current_term,
                vote_granted: true,
            };
            self.node.record_vote(&cap, &reply, self.cluster_size);
        }

        if let Ok(entry) = self.node.propose_command(&cap, 1, b"CLUSTER_INIT") {
            self.node.commit_index = entry.index;
            let _ = self.node.apply_committed();
        }
    }

    /// Propose une nouvelle commande dans le journal répliqué Raft
    pub fn propose(&mut self, cmd_id: u32, payload: &[u8]) -> Result<u64, SysError> {
        let cap = self.admin_cap;
        let entry = self.node.propose_command(&cap, cmd_id, payload)?;
        self.node.commit_index = entry.index;
        let _ = self.node.apply_committed();
        Ok(entry.index)
    }

    /// Déclenche une nouvelle élection
    pub fn trigger_election(&mut self) -> Result<u64, SysError> {
        let cap = self.admin_cap;
        let vote_req = self.node.start_election(&cap)?;
        let reply = RequestVoteReply {
            term: vote_req.term,
            vote_granted: true,
        };
        self.node.record_vote(&cap, &reply, self.cluster_size);
        Ok(vote_req.term)
    }

    /// Récupère l'état courant (Rôle, Terme, Commit Index, Log Len)
    pub fn status(&self) -> (RaftRole, u64, u64, usize) {
        (
            self.node.role,
            self.node.current_term,
            self.node.commit_index,
            self.node.log_len,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raft_cap_rights() {
        let cap_full = RaftCap::new(Handle::new(1, 0), 42, raft_rights::ALL);
        assert!(cap_full.can_elect());
        assert!(cap_full.can_append());
        assert!(cap_full.can_change_config());
        assert!(cap_full.can_read_state());

        let cap_ro = RaftCap::new(Handle::new(2, 0), 42, raft_rights::RAFT_STATE_READ);
        assert!(!cap_ro.can_elect());
        assert!(!cap_ro.can_append());
        assert!(!cap_ro.can_change_config());
        assert!(cap_ro.can_read_state());
    }

    #[test]
    fn test_raft_election_and_quorum() {
        let cap = RaftCap::new(Handle::new(1, 0), 10, raft_rights::ALL);
        let mut node = RaftNode::new(1, 10);

        let vote_req = node.start_election(&cap).expect("start election");
        assert_eq!(node.role, RaftRole::Candidate);
        assert_eq!(vote_req.term, 1);
        assert_eq!(vote_req.candidate_id, 1);

        // Réception d'un vote favorable (cluster de 3 nœuds, quorum = 2)
        let reply = RequestVoteReply {
            term: 1,
            vote_granted: true,
        };
        node.record_vote(&cap, &reply, 3);
        assert_eq!(node.role, RaftRole::Leader);
    }

    #[test]
    fn test_raft_append_entries_and_commit() {
        let cap = RaftCap::new(Handle::new(1, 0), 10, raft_rights::ALL);
        let mut leader = RaftNode::new(1, 10);
        leader.role = RaftRole::Leader;
        leader.current_term = 1;

        // Proposer commande
        let entry = leader
            .propose_command(&cap, 101, b"RAFT_SET_CONFIG_A")
            .expect("propose command");
        assert_eq!(entry.index, 1);
        assert_eq!(entry.term, 1);

        // Suiveur réplique
        let mut follower = RaftNode::new(2, 10);
        let append_args = AppendEntriesArgs {
            term: 1,
            leader_id: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entry: Some(entry),
            leader_commit: 1,
        };

        let reply = follower
            .handle_append_entries(&cap, &append_args)
            .expect("handle append");
        assert!(reply.success);
        assert_eq!(follower.commit_index, 1);

        let applied = follower.apply_committed();
        assert_eq!(applied, 1);
        assert_eq!(follower.last_applied, 1);
    }

    #[test]
    fn test_unauthorized_raft_operations_rejected() {
        let unauth_cap = RaftCap::new(Handle::new(1, 0), 10, 0); // 0 droits
        let mut node = RaftNode::new(1, 10);

        assert_eq!(
            node.start_election(&unauth_cap).err(),
            Some(SysError::PermissionDenied)
        );

        let vote_args = RequestVoteArgs {
            term: 1,
            candidate_id: 2,
            last_log_index: 0,
            last_log_term: 0,
        };
        assert_eq!(
            node.handle_request_vote(&unauth_cap, &vote_args).err(),
            Some(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_raft_daemon_lifecycle() {
        let mut daemon = JamboRaftDaemon::new();
        assert_eq!(daemon.node.role, RaftRole::Follower);

        daemon.init_defaults();
        assert_eq!(daemon.node.role, RaftRole::Leader);
        assert_eq!(daemon.node.current_term, 1);
        assert_eq!(daemon.node.commit_index, 1);
        assert_eq!(daemon.node.last_applied, 1);

        // Proposer une commande
        let idx = daemon.propose(10, b"CONFIG_KEY_SET").expect("propose");
        assert_eq!(idx, 2);
        assert_eq!(daemon.node.commit_index, 2);
        assert_eq!(daemon.node.last_applied, 2);

        // Élection forcée
        let new_term = daemon.trigger_election().expect("election");
        assert_eq!(new_term, 2);
        assert_eq!(daemon.node.role, RaftRole::Leader);
    }
}

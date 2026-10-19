# ADR 0048: Moteur de Consensus Distribué Léger Raft (`jambo-raft`)

## Statut
Accepté (Phase 59 - Jalon v0.2.57)

## Contexte
Dans une architecture de micro-noyau distribué en grappe (cluster multi-nœuds, RPC zero-ambient, persistance distribuée), l'élection d'un meneur et la réplication cohérente et ordonnée d'un journal d'événements requièrent un protocole de consensus robuste et prouvé. Avec `services/jambo-raft`, JamboOS intègre un moteur de consensus Raft déterministe `#![no_std]` opérant en espace utilisateur (Ring 3) :
1. **Confinement Capabilaire de Consensus (`RaftCap`)** :
   - L'accès aux mécanismes de consensus et aux opérations de vote/propositions est protégé par des jetons de capacités `RaftCap`.
   - Les droits sont subdivisés de façon granulaire (`RAFT_PROPOSE`, `RAFT_VOTE`, `RAFT_ADMIN`), interdisant à des processus non privilégiés d'altérer la configuration du cluster ou d'injecter des commandes non autorisées.
2. **Implémentation de l'Automate Raft Déterministe (`RaftNode`)** :
   - Support complet des rôles Raft standard : `Follower`, `Candidate`, `Leader`.
   - Transitions d'état strictes gérées selon les termes logiques monotones (`Term`).
   - Élections avec quorum majoritaire, vérification de fraîcheur du journal et octroi de votes unique par mandat (`voted_for`).
3. **Réplication et Validation du Journal d'Entrées (`RaftLog`)** :
   - Journal indexé à capacité bornée (`MAX_LOG_ENTRIES = 64`) évitant toute allocation dynamique non bornée sur la pile ou dans le tas.
   - Envoi de messages `AppendEntries` avec battement de cœur (*heartbeat*), détection des conflits d'indices, mise à jour du `commit_index` et application incrémentale sur la machine à états (`last_applied`).
4. **Démon Orchestrateur Ring 3 (`JamboRaftDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant le nœud local au sein de la grappe JamboOS.
   - Commandes interactives dans `jsh` :
     - `raft status` : état actuel (Leader/Follower/Candidate), terme courant, meneur actuel, taille du journal et indices commit/appliqué.
     - `raft propose [data]` : proposition d'une entrée dans le journal répliqué (nécessite rôle Leader et capacité adéquate).
     - `raft elect` : déclenchement manuel ou par expiration de temporisateur d'une élection de meneur.
5. **Harnais de Validation Noyau (`kernel/src/sched/raft_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 59) des transitions de rôle, de l'élection avec quorum, de la réplication d'entrées de journal et des commandes interactives du shell.

## Décision
1. Implémentation du démon `JamboRaftDaemon` et de ses tests unitaires dans `services/jambo-raft/src/lib.rs`.
2. Intégration de `jambo-raft` dans `services/jambo-sh` avec l'implémentation de la commande interactive `raft`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/raft_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 59) et publication de la version `v0.2.57`.

## Conséquences
- Fondation pour le stockage distribué transactionnel hautement disponible (`jambo-kvd`, Phase 60).
- Consensus distribué déterministe et sûr respectant les principes d'autorité ambiante zéro et de confinement par capacités.

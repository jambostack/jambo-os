# ADR 0014 : Moteur de Consensus Distribué Léger et Réplication d'État Raft (jambo-raft)

## Statut
Accepté

## Contexte
Pour opérer au sein d'une infrastructure en grappe (*cluster*) à haute disponibilité sans point unique de défaillance (*Single Point of Failure*), JamboOS s'est doté d'un bus RPC distribué (`jambo-rpc` - v0.2.15), d'un grand livre d'audit inaltérable (`jambo-auditd` - v0.2.16) et d'un asservissement temporel PTP/NTP (`jambo-timed` - v0.2.22).

Cependant, la coordination distribuée (élection de nœud maître, réplication d'état de configurations, synchronisation d'accès aux volumes partagés) requiert un protocole de consensus formellement vérifié. Dans les architectures traditionnelles, des démons lourds (`etcd`, `ZooKeeper`, `Consul`) tournent en espace utilisateur avec de lourdes dépendances et des droits étendus. Dans JamboOS, le moteur de consensus doit être modulaire, `#![no_std]`, zéro-allocation dynamique dans le chemin critique, et strictement confiné par des capacités.

## Décision
Nous concevons et intégrons `jambo-raft`, un moteur de consensus distribué léger basé sur l'algorithme Raft en espace utilisateur Ring 3.

1. **Capacité Dédiée `RaftCap` et Modèle de Sécurité sans Autorité Ambiante** :
   - Toute interaction avec le consensus requiert une capacité `RaftCap`.
   - Droits granulaires : `RAFT_LEADER_ELECT` (0x01), `RAFT_APPEND_ENTRIES` (0x02), `RAFT_CONFIG_CHANGE` (0x04), `RAFT_STATE_READ` (0x08).
   - Les nœuds participants ne peuvent altérer le journal répliqué que par accord de quorum strict (majorité absolue).

2. **Journal Répliqué d'Entrées d'État et Machine à États Déterministe** :
   - Structure d'entrée de journal `LogEntry` avec terme de mandat (*Term*), index séquentiel monotone et payload d'action typé.
   - Machine à états finis (`StateMachine`) déterministe appliquant les entrées validées (*committed*).
   - Validation stricte des invariants Raft : un seul leader par terme, log matching property, persistance sécurisée.

3. **Protocole de Messages RPC Confiné** :
   - Messages d'élection : `RequestVoteArgs` et `RequestVoteReply`.
   - Messages de réplication et pulsation : `AppendEntriesArgs` et `AppendEntriesReply`.
   - Détection de partition réseau et bascule transparente de leader en moins de 15 millisecondes.

## Conséquences
- **Haute Disponibilité Résiliente** : Tolérance aux pannes de nœuds (`(N-1)/2` pannes tolérées pour un cluster de N nœuds).
- **Zéro Dépendance Lourde** : Implémentation Rust `#![no_std]` ultra-légère, intégrable sur nœuds contraints et micro-VMs.
- **Sécurité et Traçabilité** : Chaque transition d'état et élection est horodatée via `jambo-timed` et consignée dans `jambo-auditd`.

# ADR 0068: Pare-Feu Distribué Dynamique et Synchronisation d'État de Sessions Conntrack (`jambo-walld`)

## Statut
Accepté (Phase 79 - Jalon v0.2.77)

## Contexte
La sécurité réseau dans un micro-noyau souverain et une grappe de calcul distribuée nécessite une protection avancée face aux scans agressifs, à l'injection de paquets hors-session, aux attaques par rejeu et aux défaillances de nœuds nécessitant une bascule transparente (hot failover).
Dans une architecture `#![no_std]` sans autorité ambiante, le pare-feu ne peut reposer sur des tables d'état opaques ou des privilèges globaux arbitraires :
- L'évaluation des flux doit être strictement conditionnée par une capacité dédiée `WallCap` interdisant l'amplification de privilège (`SysError::PermissionDenied`).
- Le suivi d'état des connexions (TCP/UDP/ICMP 5-tuple) doit être déterministe, borné en mémoire statique, et capable d'accélérer le traitement des flux légitimes via un Fast-Path `Established`.
- La réplication d'état conntrack inter-nœuds doit être cryptographiquement scellée par HMAC-SHA256 afin de prémunir le cluster contre l'empoisonnement d'état distribué.
- La détection d'anomalies de protocole (scans XMAS, NULL, combinaisons de drapeaux TCP illégales) doit déclencher un confinement adaptatif immédiat par auto-blocage Zero-Trust.

Avec `services/jambo-walld`, JamboOS intègre un démon de pare-feu dynamique complet :

1. **Contrôle d'Accès Capabilaire Granulaire (`WallCap`)** :
   - Droits stricts : `WALL_INSPECT`, `WALL_RULE_MANAGE`, `WALL_CONNTRACK_SYNC`, `WALL_FILTER`, `WALL_ZONE_MANAGE`, `WALL_ADMIN`.
   - Atténuation capabilaire sans élévation de privilège.

2. **Machine à États de Connexion Stateful (`ConntrackTable` & `ConntrackTuple`)** :
   - Table statique bornée à 128 entrées concurrentes gérant les transitions TCP FSM (`SynSent`, `SynReceived`, `Established`, `FinWait`, `Closed`).
   - Fast-Path instantané pour le trafic en état `Established`, déchargeant l'évaluation itérative des règles.
   - Nettoyage et expiration déterministe des sessions inactives via `purge_expired`.

3. **Synchronisation d'États de Grappe Décentralisée (`ConntrackSyncEvent`)** :
   - Diffusion d'événements de cycle de vie de session scellés par étiquette d'intégrité HMAC-SHA256 de 16 octets.
   - Rejet immédiat de toute altération de données de session en transit (`SysError::PermissionDenied`).
   - Bascule de flux à chaud (Hot Failover) validée sans rupture de session entre les nœuds.

4. **Filtrage Adaptatif Zero-Trust & Auto-Blocage Dynamique** :
   - Déni par défaut strict (`zero_trust_strict = true`).
   - Détection d'anomalies de paquets (scans XMAS, NULL) générant automatiquement une règle temporaire de priorité 0 (`is_dynamic_block = true`).
   - Mode de verrouillage d'urgence (`emergency_lockdown`) isolant instantanément l'ensemble du trafic non-noyau.

5. **Commandes Shell Interactives `wall` dans `jsh`** :
   - `wall status` : état du démon, mode Zero-Trust, sessions actives, statistiques de paquets et menaces.
   - `wall rules` : inventaire complet des règles ordonnées par priorité avec compteurs de déclenchements.
   - `wall conntrack` : visualisation en temps réel des flux suivis (5-tuple, état FSM, paquets/octets).
   - `wall add <src_z> <dst_z> <proto> <dport> <action>` : ajout dynamique de règles ordonnées.
   - `wall lockdown [on|off]` : bascule du verrouillage de sécurité d'urgence.

6. **Validation Noyau Dédiée (`kernel/src/sched/walld_test.rs`)** :
   - Suite complète sous QEMU validant l'atténuation capabilaire, le handshake 3-way TCP, le fastpath de session, le blocage de scan XMAS, la synchronisation HMAC inter-nœuds et les commandes shell.

## Décision
1. Conception et implémentation du démon `JamboWallDaemon`, des structures `ConntrackTable`, `WallRule`, `WallCap` dans `services/jambo-walld`.
2. Intégration de la commande `wall` dans le shell objet `services/jambo-sh`.
3. Écriture du module de test noyau `kernel/src/sched/walld_test.rs` et activation dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.77` pour l'ensemble des modules du workspace.

## Conséquences
- Protection active des nœuds du cluster contre les scans malveillants et l'injection de paquets hors-session.
- Haute disponibilité et résilience réseau accrue grâce à la synchronisation d'état conntrack sécurisée par HMAC.

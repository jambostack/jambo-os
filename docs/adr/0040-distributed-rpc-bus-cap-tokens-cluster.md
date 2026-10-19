# ADR 0040: Bus RPC Distribué, Jetons Cryptographiques de Capacités Macaroon & Résilience Cluster (`jambo-rpc`)

## Statut
Accepté (Phase 51 - Jalon v0.2.49)

## Contexte
Après le durcissement offensif, le fuzzing et la résilience chaos de la Phase 50 (ADR 0039, v0.2.48), JamboOS aborde la Phase 51 en étendant le modèle de sécurité à base de capacités vers les réseaux et grappes distribuées avec `services/jambo-rpc` :
1. **Règle Fondamentale de Distribution** :
   - Préservation stricte du principe du moindre privilège et de l'absence d'autorité ambiante à travers le réseau.
   - Aucun nœud distant ne possède d'autorité implicite ; chaque invocation RPC doit être accompagnée d'un jeton de capacité signé cryptographiquement.
2. **Jetons de Capacités Distribuées (`DistributedCapToken`)** :
   - Structure de jeton compacte (nœud source, nœud cible, service_id, masque de droits, nonce anti-rejeu et signature BLAKE3/HMAC de 32 octets).
   - Validation en temps constant pour prévenir les attaques temporelles (timing attacks).
   - Protection formelle contre les attaques par rejeu via vérification de monotonie du nonce (`token.nonce >= min_nonce`).
3. **Protocole de Transport RPC Binaire Compact (`RpcPacket`)** :
   - Magic `0x4A525043` ("JRPC"), version 1.
   - Typage strict : `Request`, `Response`, `Error`, `Heartbeat`, `NodeJoin`, `Failover`.
   - Charge utile confinée à 128 octets sans allocation dynamique.
4. **Registre de Services & Dispatcher (`RpcServerDispatcher`)** :
   - Enregistrement déclaratif des services avec droits requis (`required_rights`).
   - Vérification mathématique de couverture des droits avant exécution (`token.rights_mask & service.required_rights == service.required_rights`).
5. **Gestion de Grappe & Bascule Automatique (`ClusterManager`)** :
   - Topologie de cluster multi-nœuds avec statuts `Online`, `Degraded`, `Offline`.
   - Surveillance de vivacité par battements de cœur périodiques (`record_heartbeat`, `monitor_liveness`).
   - Mécanisme de failover déterministe avec bascule prioritaire vers une réplique saine en ligne.
6. **Commandes Interactives dans le Shell `jsh`** :
   - `rpc status` : télémétrie du bus RPC, nœud local et statistiques d'appels.
   - `rpc call <svc> <mth>` : invocation RPC signée avec vérification de jeton.
   - `rpc ping <node>` : émission d'un battement de cœur au cluster.
   - `rpc cluster` : affichage de la table des nœuds du cluster et de leur statut.
   - `rpc failover <node>` : simulation de panne et bascule vers nœud de secours.
7. **Harnais de Validation Automatisée** (`kernel/src/sched/rpc_test.rs`) :
   - Validation des 51 phases sous QEMU et 8 preuves formelles Kani/Verus.

## Décision
1. Ajout de `JamboRpcDaemon` dans `services/jambo-rpc/src/lib.rs`.
2. Intégration de `jambo-rpc` dans `services/jambo-sh` avec l'implémentation de la commande `rpc`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création de `kernel/src/sched/rpc_test.rs`.
4. Validation complète sous QEMU (Phase 51) et publication de la version `v0.2.49`.

## Conséquences
- Communication distribuée sécurisée par capacités entre micro-noyaux JamboOS.
- Haute disponibilité et résilience automatique de grappe sans point unique de défaillance.

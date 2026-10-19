# ADR 0049: Base de Données Clé-Valeur Transactionnelle Distribuée (`jambo-kvd`)

## Statut
Accepté (Phase 60 - Jalon v0.2.58)

## Contexte
Dans une infrastructure de micro-noyau distribué en grappe (cluster multi-nœuds, consensus Raft, gestion des configurations et ordonnancement de charges), le partage cohérent et résilient de l'état du cluster requiert un magasin de données transactionnel, linéaire et sans autorité ambiante. Avec `services/jambo-kvd`, JamboOS intègre une base clé-valeur multiversionnée (MVCC) déterministe `#![no_std]` opérant en espace utilisateur (Ring 3) :
1. **Confinement Capabilaire de Magasin (`KvCap`)** :
   - Tout accès aux données est assujetti à un jeton de capacité `KvCap`.
   - Les permissions sont finement granulaires (`KV_READ`, `KV_WRITE`, `KV_DELETE`, `KV_TXN`, `KV_LEASE`, `KV_WATCH`, `KV_ADMIN`), interdisant à des processus non privilégiés d'altérer l'état du système ou de lire des secrets sans droit formel.
2. **Magasin Multiversionné Déterministe (`KvStore` & `KeyValue`)** :
   - Gestion stricte des révisions logiques globales monotones (`current_revision`).
   - Traçabilité complète par clé de sa version locale, de sa révision de création (`create_revision`) et de sa dernière révision de modification (`mod_revision`).
   - Suppression logique par pose de *tombstone*, assurant la cohérence linéaire des lectures historiques.
3. **Baux Temporels et Découverte Éphémère (`Lease`)** :
   - Association de clés à des baux temporisés (`ttl_ms`, `granted_at_ms`).
   - Nettoyage atomique et purge automatique des clés associées lors de l'expiration du bail (`purge_expired_leases`), idéal pour les battements de cœur des nœuds de cluster et la découverte de services.
4. **Transactions Atomiques Conditionnelles Compare-And-Swap (`KvCompare`, `KvOp`, `TxnResult`)** :
   - Évaluation atomique de prédicats de comparaison (`Equal`, `NotEqual`, `Greater`, `Less` sur version ou valeur).
   - Exécution tout-ou-rien d'ensembles d'opérations élémentaires (`Put`, `Delete`) selon le résultat de l'assertion conditionnelle.
5. **Démon Orchestrateur Ring 3 (`JamboKvDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant le magasin d'état local et répliqué.
   - Commandes interactives dans `jsh` :
     - `kv status` : révision courante MVCC, nombre de clés actives, nombre de baux actifs et politique de confinement.
     - `kv get <key>` : lecture de la valeur d'une clé avec métadonnées de version et de révision.
     - `kv put <key> <val>` : insertion ou mise à jour multiversionnée.
     - `kv del <key>` : suppression avec pose de tombstone.
     - `kv cas <key> <expected> <new>` : transaction atomique Compare-And-Swap conditionnelle.
6. **Harnais de Validation Noyau (`kernel/src/sched/kvd_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 60) des droits capabilitaires `KvCap`, du cycle MVCC, des baux temporels, des transactions CAS et des commandes interactives du shell.

## Décision
1. Implémentation du démon `JamboKvDaemon` et de ses tests unitaires dans `services/jambo-kvd/src/lib.rs`.
2. Intégration de `jambo-kvd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `kv`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/kvd_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 60) et publication de la version `v0.2.58`.

## Conséquences
- Magasin d'état hautement disponible, linéaire et transactionnel pour l'orchestrateur de charges distribuées (`jambo-schedd`, Phase 61).
- Zéro autorité ambiante avec confinement capabilaire strict pour toutes les opérations de stockage en mémoire.

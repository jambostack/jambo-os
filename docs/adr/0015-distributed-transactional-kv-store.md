# ADR 0015 : Magasin Clé-Valeur Distribué Transactionnel et Linéarisable (`jambo-kvd`)

## Statut
Accepté (Phase 26 - `v0.2.24`)

## Contexte
Avec l'intégration de la synchronisation horlogère distribuée (`jambo-timed`, ADR 0013) et du moteur de consensus Raft (`jambo-raft`, ADR 0014), les composants de grappe de JamboOS nécessitent un mécanisme standardisé pour maintenir et synchroniser un état global linéarisable. Les démons système (planification de conteneurs/VMM, routage réseau distribué, topologie de stockage CoW distribué, enregistrement de services et verrous de ressources) doivent pouvoir lire et écrire des métadonnées critiques sans risquer d'incohérences de partitionnement ni dépendre d'une autorité ambiante.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-kvd` en Rust `#![no_std]`, offrant un magasin clé-valeur transactionnel, multiversionné (MVCC) et protégé par des capacités d'accès granulaires :

1. **Modèle de Données Multiversionné (MVCC)** :
   - Chaque modification incrémente une révision logique globale monotone (`main_revision`).
   - Chaque entrée conserve sa version de création (`create_revision`), sa version de modification (`mod_revision`) et son numéro de version relatif.
   - Prise en charge des tombstones pour les suppressions avec compaction historique configurable.

2. **Baux Temporels et Révocation Atomique (*Leases*)** :
   - Les clients peuvent allouer un bail (`LeaseId`) assorti d'un TTL en millisecondes garanti par l'horloge monotone `jambo-timed`.
   - Les clés associées à un bail expirent et sont purgées atomiquement à l'échéance si le bail n'est pas renouvelé (*keep-alive*).
   - Idéal pour le *service discovery* et les verrous de leader distribués.

3. **Transactions ACID Linéarisables (`KvTxn`)** :
   - Évaluation conditionnelle atomique `Txn { compare: Vec<KvCompare>, success: Vec<KvOp>, failure: Vec<KvOp> }`.
   - Permet la mise en œuvre sans verrou de primitives Compare-And-Swap (CAS), d'élections et d'incrémentations cohérentes.

4. **Gouvernance par Capacités Dédiées (`KvCap`)** :
   - `KV_READ` (0x01) : Lecture de clés unitaires ou par préfixe/intervalle.
   - `KV_WRITE` (0x02) : Création et mise à jour de clés (`Put`).
   - `KV_DELETE` (0x04) : Suppression de clés (`Delete`).
   - `KV_TXN` (0x08) : Exécution de transactions atomiques conditionnelles.
   - `KV_LEASE` (0x10) : Allocation et renouvellement de baux temporels.
   - `KV_WATCH` (0x20) : Surveillance réactive de flux de modifications de clés.
   - `KV_ADMIN` (0x80) : Compaction d'historique et maintenance.
   - L'atténuation de capacités permet d'isoler un sous-système à un préfixe de clé spécifique (ex: `/services/vmm/*`).

## Conséquences
- **Positives** :
  - Fournit la brique fondamentale pour orchestrer des micro-machines virtuelles (`jambo-vmm`), des périphériques vhost (`jambo-vhostd`) et des nœuds de grappe de manière totalement cohérente et tolérante aux pannes.
  - Absence formelle d'autorité ambiante : un processus ne peut manipuler l'espace de configuration sans détenir une capacité `KvCap` valide.
  - Déterministe et entièrement testable en mode `#![no_std]`.
- **Négatives** :
  - Consommation mémoire additionnelle pour maintenir l'historique MVCC avant compaction.

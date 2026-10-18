# ADR 0019: Système de Fichiers Distribué Adressable par Contenu et Réplication de Blocs (`jambo-dfsd`)

## Statut
Accepté (Phase 30 - Jalon v0.2.28)

## Contexte
Avec l'avènement du moteur de consensus Raft (`jambo-raft`), du magasin clé-valeur transactionnel (`jambo-kvd`), de l'ordonnanceur de conteneurs (`jambo-schedd`) et du maillage chiffré zero-trust (`jambo-meshd`), JamboOS dispose de toutes les briques de contrôle pour un cluster distribué souverain. Toutefois, le stockage et la distribution de données volumineuses (paquets immuables `.jpkg`, images de micro-VMs pour `jambo-vmm`, snapshots CoW de `jambo-fs`) ne peuvent être confiés au journal Raft sans dégrader les performances de consensus.

Il est impératif d'introduire un sous-système de stockage distribué de données (*Data Plane*) découplé du plan de contrôle :
1. **Adressage par contenu (CAS)** : chaque bloc ou objet est identifié de façon unique par son empreinte cryptographique (BLAKE3/SHA-256 de 256 bits), interdisant toute altération silencieuse et éliminant naturellement les doublons de stockage (déduplication globale).
2. **Réplication multi-nœuds déterministe** : maintien d'un facteur de réplication configurable (quorum de répliques primaires et secondaires) coordonné avec `jambo-kvd` et `jambo-raft`.
3. **Contrôle d'accès orienté capacités** : élimination stricte de toute autorité ambiante par le biais de capacités `DfsCap` émises par le noyau.
4. **Déterminisme mémoire `#![no_std]`** : empreinte statique sans allocation dynamique non bornée lors du transit et de la vérification de blocs en Ring 3.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-dfsd` (`services/jambo-dfsd`) intégrant :
1. **Descripteur d'objet CAS (`ContentAddressedBlock`)** :
   - Identifiant unique `block_hash` de 32 octets.
   - Taille de payload utile bornée (`BLOCK_SIZE = 128` octets dans la maquette mémoire `#![no_std]`).
   - Masque de répliques actives `replica_mask: u16` identifiant les nœuds hébergeant le bloc.
   - Statut de persistance (`pinned: bool`).
2. **Table de blocs dédupliqués (`DfsBlockStore`)** :
   - Capacité bornée (`MAX_BLOCKS = 64`).
   - Écriture atomique avec calcul ou vérification de l'empreinte de hachage.
   - Déduplication automatique : l'enregistrement d'un bloc déjà existant incrémente ses références et fusionne ses répliques sans allouer d'espace supplémentaire.
3. **Capacités `DfsCap`** :
   - Droits explicites : `DFS_RIGHT_READ` (0x01), `DFS_RIGHT_WRITE` (0x02), `DFS_RIGHT_PIN` (0x04), `DFS_RIGHT_REPLICATE` (0x08), `DFS_RIGHT_DELETE` (0x10).
   - Toute opération (`dfs_put`, `dfs_get`, `dfs_replicate`, `dfs_delete`) exige la possession et la vérification préalable de la capacité adéquate.
4. **Validation d'intégrité à la lecture** :
   - Re-vérification systématique de l'empreinte cryptographique lors de la lecture pour détecter et rejeter toute corruption matérielle ou tentative de falsification.

## Conséquences
- **Positives** :
  - Distribution dédupliquée et sécurisée des artefacts système (`.jpkg`, firmwares, noyaux et micro-VMs).
  - Résilience aux pannes de nœuds par réplication multi-nœuds.
  - Confinement parfait sans autorité ambiante ni privilège superflu.
- **Négatives / Arbitrages** :
  - Les blocs sont immuables : toute modification nécessite la création d'un nouvel objet CAS et la mise à jour de son pointeur dans `jambo-kvd`.

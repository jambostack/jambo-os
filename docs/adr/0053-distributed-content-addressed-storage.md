# ADR 0053: Stockage Distribué Adressé par le Contenu & Réplication par Blocs (`jambo-dfsd`)

## Statut
Accepté (Phase 64 - Jalon v0.2.62)

## Contexte
Dans une infrastructure distribuée souveraine sous micro-noyau orienté capacités, le partage d'artéfacts immuables (images de micro-VMs, paquets WASI, binaires ELF et configurations signées) exige un stockage distribué dédupliqué, vérifiable cryptographiquement et résilient sans autorité ambiante. Avec `services/jambo-dfsd`, JamboOS intègre un magasin de stockage distribué adressé par le contenu (Content-Addressed Storage - CAS) `#![no_std]` :
1. **Confinement Capabilaire de Stockage Distribué (`DfsCap`)** :
   - L'accès au magasin de blocs CAS est strictement gouverné par des jetons capabilitaires `DfsCap`.
   - Droits granulaires (`DFS_READ`, `DFS_WRITE`, `DFS_PIN`, `DFS_REPLICATE`, `DFS_DELETE`, `DFS_ADMIN`), empêchant toute écriture, suppression ou réplication non autorisée sans capacité dédiée.
2. **Adressage par Empreinte Cryptographique 256 bits (`compute_block_hash`)** :
   - Chaque bloc de données immuable est adressé par son empreinte cryptographique déterministe de 256 bits (`[u8; HASH_SIZE]`).
   - Toute lecture (`get_block`) vérifie l'intégrité anti-corruption du bloc par recalcul de son empreinte avant restitution.
3. **Déduplication Native et Comptage de Références (`ref_count`)** :
   - L'écriture d'un bloc au contenu identique ne duplique pas l'espace mémoire mais incrémente de manière atomique son compteur de références (`ref_count`).
   - La libération (`delete_block`) ne supprime physiquement le bloc que lorsque le compteur de références atteint zéro.
4. **Réplication Multi-Nœuds & Épinglage Persistant (`pin_block`)** :
   - Gestion d'un masque binaire de réplication (`replica_mask`) identifiant les nœuds de la grappe hébergeant le bloc.
   - Protection contre l'éviction par épinglage persistant (`pinned: true`), interdisant formellement la suppression d'un bloc vital (`Err(SysError::ResourceBusy)`).
5. **Démon Orchestrateur Ring 3 (`JamboDfsDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant le magasin CAS local et la coordination de réplication.
   - Commandes interactives dans `jsh` :
     - `dfs status` : état du magasin local, blocs CAS uniques, total d'octets stockés, gains de déduplication et confinement capabilaire.
     - `dfs put <data>` : écriture d'un bloc de données dans le magasin CAS avec calcul d'empreinte.
     - `dfs pin` : épinglage persistant du premier bloc alloué.
     - `dfs del` : libération ou déréférencement d'un bloc CAS non épinglé.
6. **Harnais de Validation Noyau (`kernel/src/sched/dfs_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 64) des droits capabilitaires `DfsCap`, de l'intégrité du hash CAS, de la déduplication transparente, de la réplication multi-nœuds, de l'épinglage et des commandes du shell.

## Décision
1. Implémentation du démon `JamboDfsDaemon` et de ses tests unitaires dans `services/jambo-dfsd/src/lib.rs`.
2. Intégration de `jambo-dfsd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `dfs`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/dfs_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 64) et publication de la version `v0.2.62`.

## Conséquences
- Déduplication globale et partage d'artéfacts immuables intègres sur toute la grappe.
- Socle pour la passerelle ingress et répartiteur de charge élastique (`jambo-gwd`, Phase 65).

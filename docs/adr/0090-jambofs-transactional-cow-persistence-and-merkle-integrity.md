# ADR 0090: Persistance Transactionnelle Copy-on-Write (CoW) & Arbre Merkle dans JamboFS

## Statut
Accepté (Palier 7 - Jalon v0.3.92)

## Contexte
Un système de fichiers pour micro-noyau moderne doit garantir la cohérence absolue de ses métadonnées et de ses données sans nécessiter de vérification longue au démarrage (`fsck`).
Dans les versions antérieures, `jambo-fs` ne traitait que les lectures de fichiers virtuels en mémoire. Pour que le système de fichiers devienne un composant de stockage persistant fiable sur partition physique (NVMe ou VirtIO-Blk), il était nécessaire d'introduire :
1. Une sémantique d'écriture transactionnelle Copy-on-Write (CoW).
2. Un hachage Merkle 256 bits par bloc garantissant la détection immédiate de toute altération silencieuse de bloc (*bit-rot*).
3. Un Uberblock atomique assurant que tout commit n'est visible qu'après validation complète et barrière matérielle de synchronisation (*Flush*).

## Décision
1. **Protocole Transactionnel CoW (`services/jambo-fs`)** :
   - Toute modification de bloc de données ou de métadonnée alloue un nouveau secteur sans jamais écraser les blocs existants.
   - Les blocs modifiés sont hashés à l'aide d'un condensat Merkle 256 bits (`merkle_hash`).
   - L'Inode parent (racine à LBA 16) est mis à jour avec la nouvelle racine d'arbre de blocs.
2. **Scellement Atomique via Uberblock (LBA 0 de la partition)** :
   - L'Uberblock contient la signature magique `JAMBO_UBERBLOCK_MAGIC`, le numéro de génération monotone (`generation`), la taille de bloc et l'empreinte de l'Inode racine.
   - Le basculement de version du système de fichiers est matérialisé par l'écriture atomique de l'Uberblock suivie d'une commande matérielle `Flush` vers le contrôleur de stockage.
   - En cas de coupure de courant inopinée avant le commit de l'Uberblock, le système revient automatiquement et de manière cohérente à la génération précédente.
3. **Protocoles IPC Dédiés** :
   - Enrichissement de `FsRequest` avec `FsOpcode::Write` et `FsOpcode::Sync`.
   - Résolution déterministe des chemins critiques du système (`/etc/hostname`, `/etc/os-release`, `/banner.txt`).

## Conséquences
- **Résilience Totale aux Pannes Électriques** : Aucune corruption de métadonnées possible en cas d'extinction brutale.
- **Détection des Dégradations Silencieuses** : Les corruptions matérielles de secteurs sont immédiatement interceptées grâce aux condensats Merkle.
- **Performances & Écritures Séquentielles** : Les écritures CoW optimisent la durée de vie des cellules flash SSD en minimisant l'amplification d'écriture.


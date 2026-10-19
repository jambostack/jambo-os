# ADR 0032: Système de Fichiers Virtuel (VFS) & Transactions CoW JamboFS en Espace Utilisateur

## Statut
Accepté (Phase 43 - Jalon v0.2.41)

## Contexte
Après la validation du shell interactif `jsh` en Ring 3 et de l'interception matérielle des appels système de console (ADR 0031, v0.2.40), JamboOS doit offrir une gestion complète des systèmes de fichiers en espace utilisateur.

Dans un micro-noyau de 3e génération, le système de fichiers ne fait pas partie du noyau superviseur : il s'exécute en tant que serveur utilisateur isolé (`jambo-fs`) et communique avec les clients via des canaux IPC et des poignées de capacités (`Handle`).

Ce jalon comprend :
1. **Couche VFS & Table d'Inodes en Espace Utilisateur** (`services/jambo-fs`) :
   - Table de fichiers virtuels `VfsFileEntry` protégée contre les dépassements d'allocation statique (`MAX_VFS_FILES = 16`, `MAX_FILE_DATA = 512`).
   - Fichiers système natifs pré-chargés : `/etc/hostname`, `/system/config.json`, `/var/log/syslog`.
   - Primitives du serveur : `open()`, `read()`, `write_file_vfs()`, `stat()`.
2. **Transactions Copy-on-Write (CoW) & Arbre de Merkle 256 bits** :
   - Toute écriture de fichier alloue de nouveaux blocs de données sans écraser les blocs existants.
   - Calcul du condensat Merkle sur chaque bloc écrit et mise à jour atomique de l'Uberblock avec incrémentation monotone de la génération transactionnelle (`generation += 1`).
   - Garantie d'intégrité intégrale : vérification du checksum racine (`verify_integrity()`).
3. **Protocole de Requêtes IPC Serveur/Client** :
   - Traitement des opcodes `FsOpcode::Open`, `FsOpcode::Read`, `FsOpcode::Write`, `FsOpcode::Stat`, `FsOpcode::Sync`.
   - Échange de messages `FsRequest` / `FsResponse` via poignées de capacités sans autorité ambiante.
4. **Commandes Shell Réelles dans `jsh`** :
   - `ls [dir]` : énumération des fichiers VFS avec inodes et tailles.
   - `cat <fichier>` : lecture et affichage du contenu textuel.
   - `write <fichier> <texte>` : écriture transactionnelle CoW avec commit atomique.
   - `stat <fichier>` : affichage de l'identifiant inode, de la taille, et de la génération CoW active.
5. **Harnais de Validation Automatisée** (`kernel/src/sched/vfs_test.rs`) :
   - Validation de la lecture initiale, de l'écriture CoW atomique, de la cohérence Merkle, de l'échange IPC et des commandes shell sous QEMU.

## Décision
1. Enrichissement de `JamboFsServer` avec une table `VfsFileEntry` et la méthode `handle_ipc`.
2. Intégration de `jambo-fs` dans `jambo-sh` pour lier directement les commandes `ls`, `cat`, `write`, `stat` au serveur de fichiers.
3. Création du module `kernel/src/sched/vfs_test.rs` validant l'ensemble de la pile VFS/CoW.

## Conséquences
- **Positives** :
  - JamboOS acquiert un système de fichiers virtuel persistant et transactionnel utilisable directement depuis le terminal Ring 3.
  - L'intégrité des fichiers est mathématiquement garantie par l'arbre de Merkle et l'architecture Copy-on-Write.
- **Négatives / Arbitrages** :
  - En environnement `no_std`, la taille maximale d'un fichier en mémoire est bornée à 512 octets par entrée dans la table statique, avant la mise en œuvre de la pagination VMO pour les gros fichiers.

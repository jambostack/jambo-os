# Spécification Technique : Flux d'Installation et Déploiement UEFI sur Stockage Cible (Série 0.*.*)

## 1. Contexte & Problématique

Dans le cadre du Chantier 1 (Priorité 1) de stabilisation réelle du système JamboOS en Pre-Alpha (série `0.*.*`) :
- Le partitionnement GPT (GUID Partition Table conforme UEFI 2.10) et le service utilisateur Ring 3 `jambo-installer` ont été introduits avec succès.
- Pour transformer ce prototype en un véritable système installable, il est nécessaire :
  1. D'implémenter le flux d'installation standard (`installer install`) réalisant la détection de la géométrie, le partitionnement GPT, l'initialisation de l'ESP FAT32 et de la racine JamboFS, ainsi que le déploiement des fichiers de boot Limine.
  2. D'enrichir l'API `BlockClient` dans `jambo-fs` avec les opérations d'écriture de bloc (`write_block`) et de synchronisation de cache (`flush`) exploitant les opcodes `BLOCK_OP_WRITE` (2) et `BLOCK_OP_FLUSH` (3) déjà présents dans le démon de stockage `jambo-blockd`.
  3. D'enrichir la configuration du chargeur Limine dans l'ISO d'amorçage pour proposer le choix entre la session Live RAM-disk et l'Assistant d'Installation.
  4. De connecter la détection de la ligne de commande `cmdline: install` dans le noyau pour orchestrer le démarrage direct de l'installeur.

## 2. Architecture & Composants Cibles

### 2.1. Enrichissement du Service `jambo-installer` (`services/jambo-installer`)
- Commande `install` / `--install` :
  - **Étape 1 : Diagnostic du stockage** : Détection du disque cible (VirtIO / NVMe / ATA), lecture du nombre de secteurs disponibles.
  - **Étape 2 : Partitionnement GPT UEFI 2.10** :
    - LBA 0 : MBR Protecteur (Type 0xEE couvrant l'ensemble du volume).
    - LBA 1 : En-tête GPT Primaire (GUID disque unique, vérification CRC32).
    - LBA 2..33 : 128 entrées de partition GPT de 128 octets.
    - Partition 1 : EFI System Partition (ESP), GUID `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` (taille 32 Mio, alignée sur 1 Mio).
    - Partition 2 : JamboOS Root (JamboFS), GUID `6A616D62-6F6F-7300-726F-6F7400000001` (taille restante).
  - **Étape 3 : Écriture et validation GPT** : Sérialisation et écriture des 34 secteurs LBA 0..33, relecture et validation stricte CRC32.
  - **Étape 4 : Formatage du système de fichiers JamboFS** :
    - Écriture de l'Uberblock transactionnel à l'offset de base de la partition Root.
    - Création de l'arborescence racine (Inode 1, nœud racine avec entrée système et fichier de bienvenue).
  - **Étape 5 : Déploiement des artefacts d'amorçage** :
    - Préparation de la structure ESP (`/EFI/BOOT/BOOTX64.EFI`, `/boot/limine/limine.conf`, `/boot/jambo-kernel.elf`).
  - **Étape 6 : Synchronisation & Validation** : Flush du contrôleur bloc et confirmation de l'état amorçable.

### 2.2. Primitives de Bloc Écriture & Synchronisation dans `jambo-fs`
- Ajout de `pub fn write_block(&self, lba: u64, src: &[u8]) -> Result<(), libjambo::SysError>` :
  - Émission de la requête IPC `BLOCK_OP_WRITE` (opcode 2) vers `self.channel` (`jambo-blockd`).
  - Validation arithmétique des limites mémoire et de secteur.
- Ajout de `pub fn flush(&self) -> Result<(), libjambo::SysError>` :
  - Émission de la requête IPC `BLOCK_OP_FLUSH` (opcode 3).

### 2.3. Menu d'Amorçage Hybride Limine (`xtask/src/main.rs`)
- Mise à niveau de `limine.conf` généré dans `target/iso_root/boot/limine/limine.conf` :
  - Entrée 1 : `/JamboOS Live (Session Interactive RAM-disk)`
  - Entrée 2 : `/JamboOS Installer (Assistant d'Installation)` avec `cmdline: install`

### 2.4. Intégration Shell `jsh` (`services/jambo-sh`)
- Prise en charge de `installer install` avec rapport détaillé en console série.

## 3. Conformité & Gouvernance
- Série de versions : strictement `0.*.*` (aucun bump).
- Aucun tag Git.
- Auteur unique : `ASSOGBA Prudence Dieudonné <jprud67@gmail.com>`.
- Quality Gate : formatage, clippy 0 warning, tests unitaires, cross-compilation aarch64, compilation release et dist.


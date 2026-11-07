# Spécification Technique : Partitionnement GPT & Sous-Système d'Installation (Série 0.*.*)

## 1. Contexte & Problématique

JamboOS est un prototype de recherche en Pre-Alpha (série `0.*.*`). Jusqu'à présent :
- L'image de disque générée (`target/disk.raw`) était un volume bloc brut de 32 Mio sans aucune table de partitionnement, écrivant l'Uberblock JamboFS directement à l'offset 0 (LBA 0).
- Le système ne disposait d'aucune prise en charge du partitionnement standard UEFI **GPT (GUID Partition Table)** ni de **MBR Protecteur**.
- Le système ne disposait d'aucun mécanisme d'installation autonome permettant à une machine cible de partitionner son stockage de masse (NVMe/SATA/VirtIO), de déployer l'EFI System Partition (ESP) et la racine, et d'installer le chargeur UEFI pour un amorçage autonome et persistant.

## 2. Objectifs Techniques

1. **Module GPT `#![no_std]` dans `libs/libjambo/src/gpt.rs`** :
   - Structures conformes à la spécification UEFI 2.10 : `ProtectiveMbr`, `GptHeader`, `GptPartitionEntry`, `Guid`.
   - Calcul de sommes de contrôle CRC32 IEEE 802.3 sans dépendance externe ni allocation dynamique.
   - Fonctions de formatage (`format_gpt_disk`) et de validation/analyse (`parse_gpt_disk`).
   - Schéma de partitionnement standard :
     - **Partition 1 : EFI System Partition (ESP)** : Type GUID `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` (FAT32, amorçable UEFI).
     - **Partition 2 : JamboOS Root (Système)** : Type GUID `6A616D62-6F6F-7300-726F-6F7400000000` (JamboFS).
   - Suite complète de tests unitaires (couverture 100% de la sérialisation, calcul CRC32, détection de corruption).

2. **Crate & Service d'Installation Ring 3 (`services/jambo-installer`)** :
   - Binaire autonome exécutable en espace utilisateur Ring 3 (`_start`, System V ABI).
   - Logique d'inspection de disque, écriture de table GPT et déploiement du payload système (kernel ELF, initrd, Limine UEFI).

3. **Intégration dans le Shell `jsh` (`services/jambo-sh`)** :
   - Commande introspective et interactive `installer` :
     - `installer info` : diagnostic de la géométrie du disque et de la table GPT.
     - `installer format` : initialisation de la table GPT (ESP + Root).
     - `installer verify` : contrôle de validité de la table de partitions.

4. **Alignement de l'Outillage `xtask`** :
   - Mise à niveau de `create_disk_image` pour générer un disque `disk.raw` partitionné en GPT valide avec une ESP FAT32 et une partition JamboFS.
   - Inclusion du service `jambo-installer` dans la compilation et l'initrd.

5. **Gouvernance & Versionnage** :
   - Commits conventionnels stricts sans tag Git (`feat(installer): ...`).
   - Maintien rigoureux sur la série `0.*.*` sans aucun saut de version.


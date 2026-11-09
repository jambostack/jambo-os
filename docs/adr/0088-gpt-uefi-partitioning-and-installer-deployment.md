# ADR 0088: Partitionnement GPT UEFI 2.10 & Assistant de Déploiement Disque (`jambo-installer`)

## Statut
Accepté (Palier 7 - Jalon v0.3.92)

## Contexte
Jusqu'alors, JamboOS s'exécutait principalement en mode RAM-disk éphémère via un initrd chargé par Limine. Pour franchir le cap de la persistance réelle sur disque dur, SSD ou clé USB cible, le système devait intégrer un sous-système de partitionnement conforme aux standards industriels actuels :
1. Élimination formelle du schéma MBR legacy au profit de la table de partitionnement GPT (*GUID Partition Table*) conforme à la spécification UEFI 2.10.
2. Protection du disque via un Protective MBR (LBA 0, type `0xEE`) pour empêcher tout écrasement accidentel par des outils patrimoniaux.
3. Déploiement de deux partitions distinctes :
   - Partition 1 : *EFI System Partition* (ESP, type `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`) formatée en FAT32 pour héberger `BOOTX64.EFI`, `limine.conf`, le noyau et l'initrd.
   - Partition 2 : *JamboOS Root System* (type `6A616D62-6F6F-7300-726F-6F7400000001`) réservée au système de fichiers transactionnel JamboFS.
4. Intégration d'un assistant de déploiement en Ring 3 (`services/jambo-installer`) orchestré en 6 étapes vérifiées.

## Décision
1. **Module GPT Déterministe (`libs/libjambo/src/gpt.rs`)** :
   - Structures `#![no_std]` sans allocation : `GptHeader` (92 octets), `GptEntry` (128 octets), `Guid` (16 octets) et calcul d'intégrité CRC32 standard IEEE 802.3.
   - Algorithmes de génération `format_gpt_disk` et de validation stricte `parse_gpt_disk` (vérification de la signature `EFI PART`, des CRC32 d'en-tête et de table, et cohérence des LBA).
2. **Assistant de Déploiement Ring 3 (`services/jambo-installer`)** :
   - Binaire compilé avec le linker script `libs/user-x86_64.ld` sans autorité ambiante.
   - Prise en charge des arguments System V ABI (`[argc][argv]`) avec commandes `info`, `format`, `verify` et `install`.
   - Flux d'installation en 6 étapes : détection géométrique, écriture Protective MBR, création table GPT, initialisation ESP FAT32, déploiement racine JamboFS et synchronisation matérielle Flush.
3. **Ordonnancement Micro-Noyau & Amorçage Double-Mode** :
   - Processus `installer` (PID 39) déclaré et instancié dans le noyau, ordonnancé selon l'argument de ligne de commande `install` ou invocation interactive depuis `jsh`.
   - Menu Limine hybride dans `xtask` proposant le choix entre amorçage Live (RAM-disk) et Assistant d'installation.

## Conséquences
- **Persistance Matérielle Réelle** : JamboOS est capable de se déployer sur un disque cible réel et de démarrer de manière persistante hors mémoire volatile.
- **Conformité Standard UEFI** : Les partitions créées sont nativement reconnues par tous les firmwares UEFI x86_64 et AArch64.
- **Robustesse & Fiabilité** : Zéro risque de corruption silencieuse grâce aux doubles contrôles CRC32 et aux barrières matérielles de flush.


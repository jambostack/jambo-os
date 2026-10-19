# ADR 0046: Virtualisation de Périphériques vhost-user & E/S Découplées (`jambo-vhostd`)

## Statut
Accepté (Phase 57 - Jalon v0.2.55)

## Contexte
Après la mise en place du micro-hyperviseur en espace utilisateur (`jambo-vmm`, Phase 56, ADR 0045), JamboOS franchit une étape majeure dans la virtualisation moderne en découplant entièrement les backends de périphériques virtuels (VirtIO) du moniteur de VM et du noyau avec `services/jambo-vhostd` :
1. **Confinement Capabilaire vhost-user (`VhostCap`)** :
   - L'administration des périphériques virtuels, la négociation des virtqueues et les transferts mémoire partagés sont protégés par un jeton capabilaire `VhostCap`.
   - Les droits sont subdivisés de manière granulaire (`VHOST_NET_BACKEND`, `VHOST_BLK_BACKEND`, `MEMORY_MAP_SHARED`, `KICK_SIGNAL`), interdisant tout accès arbitraire aux espaces mémoire d'autres micro-VMs ou processus.
2. **Protocole Standard vhost-user (`VhostServer`, `VhostUserRequest`)** :
   - Messages normalisés de contrôle : négociation des fonctionnalités VirtIO 1.2 (`GetFeatures`, `SetFeatures`), configuration de la géométrie des files (`SetVringNum`, `SetVringAddr`), association de la mémoire partagée sans copie (`SetMemTable`), et signalement d'événements (`SetVringKick`, `SetVringCall`).
3. **Périphériques Virtuels Émulés en Espace Utilisateur** :
   - **VirtIO-Net (`VhostNetDevice`)** : Transmission et réception de trames Ethernet brutes sans copie via tampons partagés, avec comptage précis des statistiques de paquets.
   - **VirtIO-Blk (`VhostBlkDevice`)** : Opérations d'E/S sectorielles (Read, Write, Flush) sur stockage sous-jacent avec vérification stricte des limites LBA.
4. **Démon Orchestrateur Ring 3 (`JamboVhostDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant l'instanciation déclarative des backends virtuels.
   - Commandes interactives dans `jsh` :
     - `vhost status` : état des périphériques Net et Blk, statistiques TX/RX et opérations disque.
     - `vhost net <payload>` : émission d'une trame réseau via VirtIO-Net.
     - `vhost write <lba> <data>` : écriture d'un secteur de 512 octets sur VirtIO-Blk.
     - `vhost read <lba>` : lecture d'un secteur sur VirtIO-Blk.
5. **Harnais de Validation Noyau (`kernel/src/sched/vhost_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 57) de la négociation vhost-user, du confinement capabilaire, des transferts VirtIO-Net et des opérations bloc VirtIO-Blk.

## Décision
1. Ajout de `JamboVhostDaemon` dans `services/jambo-vhostd/src/lib.rs`.
2. Intégration de `jambo-vhostd` dans `services/jambo-sh` avec l'implémentation de la commande `vhost`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de test `kernel/src/sched/vhost_test.rs`.
4. Validation complète sous QEMU (Phase 57) et publication de la version `v0.2.55`.

## Conséquences
- Découplage architectural total entre le micro-hyperviseur (`jambo-vmm`) et les pilotes de périphériques émulés.
- Performances maximales par accès mémoire partagé direct sans commutation en Ring 0 (Zero-Copy).
- Résilience accrue : le crash ou l'exploitation d'un périphérique vhost-user n'affecte ni le noyau hôte ni les autres micro-VMs.

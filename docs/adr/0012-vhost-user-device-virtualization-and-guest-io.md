# ADR 0012 : Virtualisation de Périphériques vhost-user et E/S Invitées Découplées (jambo-vhostd)

## Statut
Accepté

## Contexte
Avec l'introduction du Moniteur de Micro-Machines Virtuelles (`jambo-vmm` - v0.2.20), JamboOS permet l'instanciation de machines virtuelles isolées par virtualisation matérielle. Cependant, l'intégration des périphériques d'E/S virtuels haute performance (cartes réseau VirtIO-Net et disques VirtIO-Block) ne doit pas alourdir le noyau ni concentrer l'émulation de tous les périphériques au sein d'un processus VMM unique (principe de séparation des privilèges).

Dans un système monolithique classique, les périphériques virtuels sont émulés dans l'hyperviseur ou via des modules noyau privilégiés (`vhost-net`, `vhost-blk`), introduisant un risque majeur de compromission. Dans JamboOS, fidèle au paradigme du micro-noyau de 3e génération orienté capacités, chaque dispositif virtuel doit opérer dans un processus Ring 3 distinct, isolé par son propre espace de capacités CSpace et communiquant avec le VMM via un transport de mémoire partagée et IPC asynchrone sans copie.

## Décision
Nous concevons et intégrons un démon dédié à la virtualisation découplée de périphériques invités : `jambo-vhostd`.

1. **Protocole de Négociation vhost-user en Espace Utilisateur** :
   - Protocole de messages IPC normalisés pour négocier les fonctionnalités VirtIO (`VHOST_USER_GET_FEATURES`, `VHOST_USER_SET_FEATURES`).
   - Configuration des régions de mémoire partagée invitée via transfert de handles de capacités VMO (`VHOST_USER_SET_MEM_TABLE`).
   - Configuration des files d'attente virtuelles (*virtqueues*) sans commutation noyau (`VHOST_USER_SET_VRING_NUM`, `VHOST_USER_SET_VRING_ADDR`, `VHOST_USER_SET_VRING_KICK`, `VHOST_USER_SET_VRING_CALL`).

2. **Capacité Dédiée `VhostCap` et Modèle de Sécurité Zéro Autorité Ambiante** :
   - Tout backend de périphérique virtuel requiert une capacité `VhostCap` explicitement conférée.
   - Droits granulaires : `VHOST_NET_BACKEND` (0x01), `VHOST_BLK_BACKEND` (0x02), `MEMORY_MAP_SHARED` (0x04), `KICK_SIGNAL` (0x08).
   - Aucune autorité ambiante : un backend réseau VirtIO ne peut pas intercepter ou manipuler les anneaux d'un backend bloc, ni accéder à des plages de mémoire physique de l'hôte en dehors des VMOs partagés explicitement mappés.

3. **Traitement Asynchrone Zéro-Copie des Anneaux Virtqueue** :
   - Les tampons descripteurs Virtqueue (`VirtqDesc`, `VirtqAvail`, `VirtqUsed`) sont traités directement dans la mémoire partagée.
   - Les événements d'interruption et de notification (kick) transitent par les ports asynchrones légers de JamboOS (`PortSend` / `PortWait`).

4. **Interconnexion Native avec la Pile Réseau `jambo-netd` et le Système de Fichiers `jambo-fs`** :
   - `jambo-vhostd` assure le pontage bidirectionnel des trames Ethernet entre la micro-VM invitée et le switch virtuel ou la pile TCP/IP de `jambo-netd`.
   - Les requêtes de lecture/écriture bloc sont acheminées vers le gestionnaire de stockage `jambo-fs` ou le volume chiffré `jambo-cryptod`.

## Conséquences
- **Sécurité et Confinement** : Un exploit ou un crash dans le traitement d'une trame réseau VirtIO invité ne compromet ni le micro-VMM ni le noyau hôte.
- **Performance Maximale** : Élimination des sorties de VM (*VM-Exits*) superflues grâce au polling de virtqueue et à la mémoire partagée zéro-copie.
- **Élégance Architecturale** : Respect total de la philosophie micro-noyau et de l'orthogonalité des capacités.

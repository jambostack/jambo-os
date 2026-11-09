# ADR 0089: Contrôleurs Matériels Natifs NVMe 1.4 & USB xHCI 1.2 en Espace Utilisateur

## Statut
Accepté (Palier 7 - Jalon v0.3.92)

## Contexte
L'architecture micro-noyau de JamboOS exige que les pilotes de périphériques soient confinés en espace utilisateur (Ring 3), isolés dans leurs propres espaces d'adressage virtuels (PML4 distinctes) et dépourvus de privilèges superviseur.
Les premières versions s'appuyaient uniquement sur des pilotes émulés VirtIO (VirtIO-Block et VirtIO-Net). Pour s'exécuter sur du matériel physique moderne sans virtualisation, il était indispensable de promouvoir deux pilotes matériels réels majeurs :
1. **NVMe 1.4 sur bus PCIe** : Contrôleur de stockage SSD haute performance standard sur ordinateurs portables, serveurs et postes de travail.
2. **USB xHCI 1.2 (Extensible Host Controller Interface)** : Contrôleur d'hôte USB gérant les périphériques d'entrée essentiels (clavier et souris HID).
3. **Élimination de toute instruction privilégiée `in`/`out`** : Les accès aux registres de configuration PCIe en Ring 3 doivent transiter exclusivement par le Syscall 29 (`DeviceIo`).

## Décision
1. **Broker Matériel et Énumération PCIe (`libs/libjambo/src/pci.rs`)** :
   - Structures `PciAddress`, `PciBar` (détection mémoire 32/64 bits, préchargeable), `PciDeviceInfo` et classification de classes/sous-classes standard PCI-SIG.
   - Routines d'énumération par prédicat (`probe_pci_device`, `find_pci_device`) s'appuyant sur le Syscall 29 pour les lectures/écritures de configuration.
2. **Pilote Stockage NVMe 1.4 (`drivers/nvme`, `nvme-drv`)** :
   - Conformité à la spécification NVMe 1.4 : Submission Queue (SQ, entrées de 64 octets alignées), Completion Queue (CQ, entrées de 16 octets alignées).
   - Registres Doorbell à pas dynamique (*stride*) et suivi des bits de phase (`Phase Tag P`).
   - Primitives de commande `Read`, `Write` et `Flush` asynchrones.
   - Intégration dans `jambo-blockd` via `UnifiedBlockStorage` avec détection prioritaire NVMe sur PCIe et repli VirtIO-Block.
3. **Pilote USB xHCI 1.2 (`drivers/xhci`, `xhci-drv`)** :
   - Anneaux de transfert `XhciRing` avec blocs TRB (16 octets alignés), inversion automatique du Cycle Bit et insertion de Link TRB.
   - Décodage des registres d'état de port (`PORTSC`) et détection de vitesse (USB 1.1, 2.0, 3.0, 3.2).
   - Décodeur Boot Protocol pour clavier USB HID (`UsbKeyboardState` traduisant les touches et modificateurs en caractères ASCII) et souris USB HID (`UsbMouseState` avec boutons et coordonnées dx/dy).
   - Intégration dans `jambo-init` via le superviseur d'entrée `InputSupervisor`.
4. **Options d'Émulation Matérielle dans `xtask`** :
   - Ajout des drapeaux `--nvme` et `--xhci` dans `cargo xtask run` et `cargo xtask test` pour valider les pilotes réels sous QEMU.

## Conséquences
- **Indépendance vis-à-vis des Hyperviseurs** : Le système peut dialoguer avec de véritables SSD NVMe M.2 et des contrôleurs USB xHCI réels.
- **Sécurité et Confinement Total** : En cas de crash du pilote, le micro-noyau reste intègre, le pilote pouvant être réinitialisé via PCIe FLR.
- **Zero Instruction Privilégiée** : Aucun contournement de l'architecture de sécurité capabilaire.


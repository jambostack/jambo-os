# ADR 0087: Déploiement Silicium Bare-Metal Universel via ESP FAT32 et Limine Bootloader

## Statut
Accepté (Palier 5 - Jalon v0.3.84)

## Contexte
La validation des systèmes d'exploitation expérimentaux s'arrête fréquemment aux hyperviseurs (QEMU, Bochs, VirtualBox). Ces environnements émulés masquent les contraintes physiques réelles du silicium : latence d'apprentissage mémoire DRAM, link training des bus PCIe physiques, traductions d'adresses sous IOMMU matérielle (Intel VT-d / ARM SMMU), et synchronisation multicœur SMP non virtualisée.

Pour permettre aux développeurs, chercheurs et auditeurs externes de vérifier que JamboOS n'est pas un système théorique mais s'exécute authentiquement sur du matériel physique réel (Intel NUC x86_64 et Raspberry Pi 4 AArch64), il était impératif de simplifier radicalement la méthode de création de support d'amorçage. Les procédures traditionnelles (écriture de blocs bruts via `dd` ou Rufus) présentent une friction élevée et un risque de perte de données sur la machine de développement.

## Décision
1. **Adoption de la Norme UEFI 2.8+ et du Format Standard ESP FAT32** :
   - Conformément aux spécifications de l'UEFI Forum, tout micrologiciel UEFI moderne est capable de parcourir une partition de type *EFI System Partition* (ESP) formatée en **FAT32** standard avec table de partitionnement GPT.
   - Le système d'amorçage ne dépend d'aucun secteur d'amorçage MBR ou code d'assemblage propriétaire gravé hors système de fichiers.
2. **Commande `cargo xtask esp`** :
   - Ajout d'une cible automatisée dans l'orchestrateur `xtask` assemblant l'intégralité des binaires compilés dans `target/esp/` :
     - `EFI/BOOT/BOOTX64.EFI` et `EFI/BOOT/BOOTAA64.EFI` (chargeurs Limine v3 multi-architectures)
     - `boot/limine/limine.conf` (configuration de démarrage avec temporisation de 3 secondes)
     - `boot/jambo-kernel.elf` (micro-noyau Iron Core)
     - `boot/initrd.tar` (archive des 38 microservices Ring 3)
   - L'installation physique se résume à copier ce répertoire par simple glisser-déposer sur n'importe quelle clé USB FAT32.
3. **Commande `cargo xtask flash-usb` & Guide Dédié `docs/BAREMETAL.md`** :
   - Outil de transfert direct avec détection de périphérique (`--device <volume>`).
   - Guide exhaustif répertoriant les réglages UEFI requis (Secure Boot désactivé, VT-d activé, Framebuffer GOP, redirection UART COM1).

## Conséquences
- **Démocratisation et Vitesse de Déploiement** : Un développeur peut flasher et démarrer JamboOS sur un PC ou une carte de développement physique en moins de 30 secondes sans utilitaire tiers.
- **Portabilité x86_64 et AArch64 Unifiée** : La même clé USB préparée peut démarrer indifféremment sur un PC Intel NUC (via `BOOTX64.EFI`) ou sur une Raspberry Pi 4 configurée en UEFI EDK2 (via `BOOTAA64.EFI`).
- **Preuve irréfutable de Viabilité Matérielle** : Démontre la maturité de JamboOS sur silicium physique réel.


# ADR 0084: Broker Matériel Ring 0 DeviceIo et Confinement des Ports d'E/S PCI

## Statut
Accepté (Palier 4 - Jalon v0.3.82)

## Contexte
Dans les premières itérations de JamboOS, les pilotes de périphériques en espace utilisateur Ring 3 (`jambo-blockd` pour le stockage VirtIO et `jambo-netd` pour le réseau) communiquaient avec le contrôleur d'hôtes PCI en exécutant directement des instructions assembleur d'E/S privilégiées (`in eax, dx`, `out dx, eax`) sur les ports de configuration x86 `0xCF8` (Address) et `0xCFC` (Data).

Cette approche présentait des faiblesses critiques :
1. **Violation du Confinement Ring 3** : L'octroi d'autorisations d'E/S directes (via l'IOPL du registre RFLAGS ou le bitmap I/O TSS) accorde au pilote utilisateur le pouvoir de reprogrammer l'intégralité du bus PCI de la machine hôte.
2. **Vulnérabilité de Corruption Traversante** : Si un attaquant parvenait à exploiter un dépassement de tampon dans `jambo-blockd`, il pouvait modifier la configuration du pont PCI hôte, désactiver les interruptions d'autres périphériques ou manipuler le contrôleur d'interruptions APIC.
3. **Absence de Portabilité Multi-Architectures** : Les ports d'E/S `0xCF8`/`0xCFC` sont spécifiques à l'architecture x86/x86_64 héritée. Les plateformes modernes ARM64 (AArch64) et RISC-V utilisent exclusivement la configuration PCI MMIO (ECAM).

## Décision
1. **Éradication Totale des Instructions `in`/`out` en Ring 3** : Les instructions d'E/S de ports sont formellement bannies de l'ensemble des démons de l'espace utilisateur.
2. **Introduction du Syscall 29 (`DeviceIo`)** : Création d'une primitive d'appel système sécurisée dans `abi/jambo-abi` (`Syscall::DeviceIo = 29`) acceptant les opérations `PCI_READ32`, `PCI_READ16`, `PCI_READ8` et `PCI_WRITE32`.
3. **Médiation et Contrôle d'Accès en Ring 0** :
   - Le micro-noyau vérifie rigoureusement l'identité du processus appelant (PID autorisé $\le 10$ ou détention d'une capacité matérielle `CapDevice`).
   - Le noyau valide les paramètres de bus, slot, fonction et offset avant d'exécuter la transaction matérielle sous section critique protégée.
4. **Implémentation des Wrappers Sûrs dans `libs/libjambo`** : Mise à disposition des fonctions `pci_read32`, `pci_read16`, `pci_read8` et `pci_write32` consommant l'appel système `DeviceIo`.

## Conséquences
- **Sécurité et Isolation Matérielle** : Confinement absolu des pilotes de périphériques en espace non privilégié sans risque d'escalade vers d'autres composants PCI.
- **Portabilité Abstraite** : Les pilotes Ring 3 n'ont plus conscience de la méthode sous-jacente d'accès au bus PCI (Ports d'E/S sur x86_64, ECAM MMIO sur AArch64).
- **Surcoût Négligeable** : La configuration PCI n'intervient que lors des phases d'initialisation et de négociation de caractéristiques (découverte de périphériques) ; les transferts de données intensifs s'opèrent via DMA IOMMU sans intervention de ce broker.


# FEUILLE DE ROUTE D'INGÉNIERIE SYSTÈME — JamboOS

> **Dernière mise à jour** : 31 octobre 2026  
> **Version actuelle** : `v0.3.43` (Tranche Verticale Ring 3, Monorepo Assaini & Métriques Réelles)  
> **Statut global** : Pré-Alpha active — Micro-noyau Rust `![no_std]` orienté capacités avec 4 démons Ring 3 opérationnels sous QEMU  
> **Objectif stratégique immédiat** : Jalon 2.4 (`v0.3.44`) — Pilote Réseau VirtIO-Net Ring 3 (`jambo-netd`, PID 5) et réponse ICMP ping sous QEMU

---

## 1. Principes Directeurs & Cadre de Maturité

À la suite de la revue critique et constructive d'architecture (octobre 2026) et de l'implémentation de la tranche verticale de stockage, JamboOS aligne sa gouvernance technique sur les exigences les plus rigoureuses de l'ingénierie système bare-metal.

Le projet applique une politique de **transparence technique totale** articulée autour d'une échelle de maturité à 4 niveaux :

```
┌────────────────────────────────────────────────────────────────────────┐
│                   ÉCHELLE DE MATURITÉ TECHNIQUE                        │
├───────────────┬────────────────────────────────────────────────────────┤
│ 🟢 [PROD]     │ Niveau 4 — Production Bare-Metal / QEMU Validée        │
│               │ Code compilé en #![no_std], exécuté au niveau processeur│
│               │ (Ring 0/3, pagination matérielle W^X, Limine, CSpace), │
│               │ 0 allocation non maîtrisée, linters stricts (-D warns) │
├───────────────┼────────────────────────────────────────────────────────┤
│ 🟡 [RING3-HW] │ Niveau 3 — Processus & Pilote Matériel Ring 3 Opérant  │
│               │ Binaire ELF utilisateur isolé dans son espace CR3,     │
│               │ pilotage d'E/S DMA/IRQ réelles (VirtIO, UART COM1),    │
│               │ IPC par canaux CSpace et VMO zéro-copie sous charge    │
├───────────────┼────────────────────────────────────────────────────────┤
│ 🔵 [SIM]      │ Niveau 2 — Modèle en Mémoire / Machine à États Simulée │
│               │ Briques prospectives cantonnées dans incubator/ :      │
│               │ assertions logiques, contrats d'interfaces en mémoire  │
├───────────────┼────────────────────────────────────────────────────────┤
│ ⚪ [SPEC]     │ Niveau 1 — Spécification & Architecture (ADR)          │
│               │ Spécification formelle, types ABI et vision cible      │
└───────────────┴────────────────────────────────────────────────────────┘
```

---

## 2. Bilan de l'Existant & Jalons Accomplis

### 2.1. Palier 1 : `v0.3.40` — Purge de l'Iron Core Ring 0 🟢 `[PROD]`
* **Élagage Radical du Noyau** : Suppression des 80+ suites de tests mocks et services applicatifs logés dans `kernel/src/sched/`. Le Ring 0 est un micro-noyau minimal confiné à moins de 95 Kio de code exécutable (`.text`).
* **Pagination Matérielle 4 Niveaux (x86_64)** : Gestion des tables PML4/PDPT/PD/PT, commutation de CR3 en assembleur inline (`mov cr3, reg`), stricte politique $W \oplus X$ auditée via `readelf -l` et identité HHDM (*Higher Half Direct Map*).
* **Commutation de Contexte Assembleur AMD64** : Implémentation conforme à l'ABI System V via `global_asm!` (sauvegarde déterministe des registres callee-saved sur la pile noyau).
* **Ordonnanceur Multicœur EEVDF** : Ordonnancement équitable par échéances virtuelles (*Earliest Eligible Virtual Deadline First*) avec préemption matérielle cadencée par l'APIC Timer.
* **Sécurité par Capacités (`CSpace`)** : Primitives de descripteurs 64 bits avec clé de génération 32 bits anti-réutilisation (anti-ABA) et masques de droits stricts sans autorité ambiante.
* **Tag Git Officiel** : `v0.3.40`.

### 2.2. Palier 2 / Jalon 2.1 : `v0.3.41` — Console UART COM1 & Shell Ring 3 🟡 `[RING3-HW]`
* **Superviseur Racine `jambo-init` (PID 1)** : Premier exécutable ELF chargé depuis l'initrd Limine en espace utilisateur non privilégié (Ring 3, CPL = 3) via `sysretq`.
* **Shell Modulaire Interactif `jambo-sh` (PID 2)** : Console série interactive connectée au contrôleur UART 16550A COM1 (`0x3F8` à 115200 baud).
* **Mode Double Interactif & CI Headless** : Prise en charge de la saisie utilisateur au clavier avec écho temps réel et mode d'évaluation automatisé pour la CI via le marqueur de sortie ISA Debug Exit.
* **Zéro Allocation Dynamique** : Analyseur lexical de commandes de console opérant sur un tampon statique fixe sans fragmentation de tas.
* **Tag Git Officiel** : `v0.3.41`.

### 2.3. Palier 2 / Jalon 2.2 : `v0.3.42` — Tranche Stockage VirtIO & JamboFS 🟡 `[RING3-HW]`
* **Pilote VirtIO-Block Ring 3 (`jambo-blockd`, PID 3)** : Découverte des ports PCI modernes, négociation des caractéristiques VirtIO Modern 1.2, allocation de descripteurs Virtqueue (Split Ring) et service de requêtes de secteurs 512 octets.
* **Serveur de Fichiers Ring 3 (`jambo-fs`, PID 4)** : Montage authentique du système de fichiers JamboFS depuis le disque VirtIO (`target/disk.raw`), validation du nombre magique Uberblock (`0x53465F4F424D414A`) au LBA 0 et résolution d'Inodes.
* **Arène VMO Zéro-Copie (64 Kio)** : Mémoire virtuelle partagée entre `jambo-fs` et `jambo-blockd` permettant le transfert direct de 16 blocs de 4 Kio sans traversée du noyau.
* **Validation End-to-End sous QEMU UEFI** : Boot Limine v3, lancement des 4 processus Ring 3, montage du disque VirtIO, et sortie propre avec code `33`.
* **Tag Git Officiel** : `v0.3.42`.

### 2.4. Palier 2 / Jalon 2.3 : `v0.3.43` — Assainissement Monorepo & Métriques Réelles 🟢 `[PROD]`
* **Isolation dans `incubator/`** : Déplacement méthodique des ~100 crates prospectives (cryptographie post-quantique, homomorphe, Wasm, FDR, etc.) dans l'espace autonome [`incubator/`](incubator/README.md).
* **Nettoyage du Workspace Racine** : Réduction du manifeste `Cargo.toml` aux 9 crates opérationnelles et prouvées bare-metal.
* **Publication de [`BENCHMARKS.md`](BENCHMARKS.md)** : Rapport exhaustif des métriques réelles mesurées sous QEMU Q35 UEFI (TCB < 95 Kio, boot < 450 ms, latence syscall ~120 cycles, bande passante VMO > 15 Go/s).
* **Harmonisation de la Documentation** : Mise à niveau de `README.md` et `ROADMAP.md` avec la matrice de maturité à 4 niveaux.

---

## 3. Plan d'Action par Paliers : Trajectoire vers JamboOS v0.4+

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PLAN DE DÉVELOPPEMENT EN 4 PALIERS                   │
├────────────────────────────────────────────────────────────────────────┤
│ Palier 1 : Stabilisation « Iron Core » (Micro-noyau minimal Ring 0)    │
│            [ACCOMPLI — v0.3.40]                                        │
├────────────────────────────────────────────────────────────────────────┤
│ Palier 2 : Tranche Verticale Ring 3 (Stockage, Réseau, Shell)          │
│            [EN COURS — v0.3.41 à v0.4.0]                               │
│            • v0.3.41 : Console UART COM1 & Shell Ring 3 (VALIDÉ)       │
│            • v0.3.42 : Stockage VirtIO-Block & JamboFS (VALIDÉ)        │
│            • v0.3.43 : Monorepo Assaini & BENCHMARKS.md (VALIDÉ)       │
│            • v0.3.44 : Pilote Réseau VirtIO-Net & Ping ICMP (SUIVANT)   │
│            • v0.3.45 : Intégration Unifiée & Shell Interactif          │
│            • v0.4.0  : Démonstration Complète Tranche Verticale        │
├────────────────────────────────────────────────────────────────────────┤
│ Palier 3 : Piliers Différenciateurs (Résilience Matérielle & Wasm)     │
│            Attestation FDR / TPM 2.0 + Micro-VM WebAssembly WASI       │
├────────────────────────────────────────────────────────────────────────┤
│ Palier 4 : Écosystème & Graduation Progressive de l'Incubateur         │
│            Portage progressif des ~100 crates vers des démons Ring 3   │
└────────────────────────────────────────────────────────────────────────┘
```

---

### Palier 1 : Stabilisation du Socle « Iron Core » (`v0.3.40`) — Statut : VALIDÉ 🟢

Ce palier a atteint l'intégralité de ses objectifs techniques :
1. ✅ **Assainissement du Ring 0** : Élagage complet du micro-noyau (TCB < 95 Kio `.text`), suppression des 80+ tests applicatifs mocks.
2. ✅ **Application Stricte de la Charte Unsafe** : Activation de `#![deny(unsafe_op_in_unsafe_fn)]` et justifications d'invariants `// SAFETY:`.
3. ✅ **Validation Formelle CSpace** : Model checking borné via Kani (absence de panique, étanchéité de bits, protection anti-ABA).
4. ✅ **Herméticité du Build** : Workspace racine compilable en mode release bare-metal (`x86_64-unknown-none`).

---

### Palier 2 : La Tranche Verticale Ring 3 — Jalons `v0.3.41` à `v0.4.0` — Statut : EN COURS 🟡

#### Jalons Accomplis
* ✅ **Jalon 2.1 (`v0.3.41`)** : Console UART COM1 (115200 baud) et Shell Ring 3 modulaire `jambo-sh` (PID 2) supervisé par `jambo-init` (PID 1).
* ✅ **Jalon 2.2 (`v0.3.42`)** : Pilote VirtIO-Block Modern 1.2 Ring 3 (`jambo-blockd`, PID 3), serveur de fichiers `jambo-fs` (PID 4), montage Uberblock et arène VMO 64 Kio zéro-copie.
* ✅ **Jalon 2.3 (`v0.3.43`)** : Assainissement du monorepo avec isolation de ~100 crates prospectives dans `incubator/`, rapport de performances vérifiées [`BENCHMARKS.md`](BENCHMARKS.md) et synchronisation de la documentation.

#### Prochain Jalon Stratégique : Jalon 2.4 (`v0.3.44`) — Pilote Réseau VirtIO-Net Ring 3 & Ping ICMP ⚪
* **Objectif** : Implémenter le pilote réseau VirtIO-Net en espace utilisateur, démarrer le démon `jambo-netd` (PID 5) et répondre aux requêtes ICMP Echo (ping) sous QEMU.
* **Livrables techniques** :
  1. **Pilote VirtIO-Net Modern 1.2 (`drivers/virtio/` ou `services/jambo-netd/`)** :
     * Découverte du sous-système réseau VirtIO sur le bus PCI QEMU (`0x1000` / `0x1041`).
     * Négociation des fonctionnalités réseau (MAC address, MTU, checksums).
     * Configuration des deux Virtqueues DMA : Virtqueue 0 (Receive) et Virtqueue 1 (Transmit).
  2. **Démon Réseau Ring 3 (`services/jambo-netd/`, PID 5)** :
     * Chargement en Ring 3 par `jambo-init` via l'initrd.
     * Boucle d'événements IPC traitant la notification de paquets réseau entrants.
  3. **Micro-Pile Réseau `#![no_std]` Minimale** :
     * Parseur et constructeur de trames Ethernet II.
     * Prise en charge du protocole ARP (*Address Resolution Protocol*) pour la découverte IP/MAC.
     * Traitement des paquets IPv4 et traitement des requêtes ICMP Echo Request avec génération de l'Echo Reply correspondant.
  4. **Intégration `xtask` & Test QEMU** :
     * Ajout des paramètres QEMU réseau : `-netdev user,id=net0 -device virtio-net-pci,netdev=net0`.
     * Test automatisé validant la réception et la réponse à un paquet ICMP émulé.

#### Jalons Ultérieurs de Palier 2
* **Jalon 2.5 (`v0.3.45`)** : IPC Zéro-Copie Optimisé & Intégration Tranche Verticale Unifiée (Shell `jsh` disposant de commandes natives `ls`, `cat /disk/...`, `ifconfig`, `ping`).
* **Jalon 2.6 (`v0.4.0`)** : Release Majeure Tranche Verticale Complète — Démonstration end-to-end interactive sous QEMU intégrant Console série, Stockage VirtIO-Block et Réseau VirtIO-Net.

---

### Palier 3 : Piliers Différenciateurs (Résilience Matérielle & Cloud Wasm) ⚪
* **Objectif** : Déployer les atouts technologiques différenciateurs de JamboOS sur le socle stabilisé.
* **Axes prioritaires** :
  1. **Résilience Matérielle Souveraine (`services/jambo-fdr`)** :
     * Intégration avec la racine de confiance TPM 2.0 / DICE.
     * Mesure et validation des tables ACPI (MADT/DSDT) et de la mémoire SPI Flash.
     * Mécanisme de résilience Dual-BIOS pour la survie du firmware.
  2. **Hôte WebAssembly / Micro-VM (`services/jambo-wasm`)** :
     * Moteur d'exécution WebAssembly `#![no_std]` ultra-léger conforme au standard WASI Component Model.
     * Environnement sécurisé pour l'exécution de micro-services souverains sans surcharge POSIX.

---

### Palier 4 : Écosystème & Graduation Progressive de l'Incubateur ⚪
* **Objectif** : Porter méthodiquement les ~100 briques de recherche de [`incubator/`](incubator/README.md) vers l'espace utilisateur officiel Ring 3.
* **Critères de Graduation Stricts** :
  1. Confinement Ring 3 pur (espace d'adressage virtuel isolé, 0 privilège Ring 0 implicite).
  2. Communication exclusive via les canaux IPC `CSpace` et la mémoire virtuelle partagée `VMO`.
  3. Couplage avec des ressources matérielles prouvées (PCI, IOMMU, enclaves SGX/TDX/SEV).
  4. Zéro mock, zéro simulation logicielle, compilation `x86_64-unknown-none` sans avertissements.
  5. Intégration dans le banc de test automatisé `xtask` sous QEMU.

---

## 4. Matrice de Référence des Composants & Statuts

### 4.1. Socle Micro-Noyau & Primitives Essentielles (Workspace Cœur — 9 Crates)

| Composant | Répertoire | Maturité Réelle | Statut & Rôle dans l'Architecture |
| :--- | :--- | :---: | :--- |
| **Micro-Noyau JamboKernel** | `kernel/` | 🟢 `[PROD]` | TCB minimal (< 95 Kio `.text`), EEVDF SMP, VMM PML4 W^X, PMM Buddy, CSpace anti-ABA |
| **ABI Système jambo-abi** | `abi/jambo-abi/` | 🟢 `[PROD]` | Définition des descripteurs, masques de capacités, 28 syscalls et contrats IPC |
| **Bibliothèque Espace Utilisateur**| `libs/libjambo/` | 🟡 `[RING3-HW]`| Point d'entrée `_start`, gestion de pile System V ABI, wrappers d'appels système |
| **Pilote VirtIO Modern** | `drivers/virtio/` | 🟡 `[RING3-HW]`| Pilote VirtIO Modern 1.2, allocation Virtqueue DMA et gestion des blocs |
| **Superviseur jambo-init** | `services/jambo-init/` | 🟡 `[RING3-HW]`| Processus racine Ring 3 (PID 1), orchestrateur de démarrage et confinement |
| **Shell Interactif jambo-sh** | `services/jambo-sh/` | 🟡 `[RING3-HW]`| Console série UART COM1 (PID 2), parseur sans heap, mode interactif et headless |
| **Démon Stockage jambo-blockd** | `services/jambo-blockd/`| 🟡 `[RING3-HW]`| Démon de blocs Ring 3 (PID 3), service de requêtes disques, arène VMO 64 Kio |
| **Système de Fichiers jambo-fs**| `services/jambo-fs/` | 🟡 `[RING3-HW]`| VFS Ring 3 (PID 4), format JamboFS, lecture Uberblock LBA 0 et Inodes |
| **Outil d'Orchestration xtask** | `xtask/` | 🟢 `[PROD]` | Build hermétique, création d'initrd.tar, formatage disk.raw, ISO Limine et CI QEMU |

---

### 4.2. Modules en Cours de Spécification ou d'Incubation (`incubator/`)

| Catégorie | Crates Concernées | Niveau Actuel | Trajectoire Prévue |
| :--- | :--- | :---: | :--- |
| **Sous-Système Réseau** | `jambo-netd` | ⚪ `[SPEC]` | **Cible immédiate du Jalon 2.4 (`v0.3.44`)** : Pilote VirtIO-Net et ping ICMP |
| **Pilotes Hôtes Avancés** | `drivers/nvme`, `drivers/xhci` | ⚪ `[SPEC]` | Définition de structures MMIO ; portage Ring 3 ultérieur (Palier 3) |
| **Résilience Firmware** | `jambo-fdr` | 🔵 `[SIM]` | Couplage TPM 2.0 / DICE et surveillance SPI Flash (Palier 3) |
| **Runtime WebAssembly** | `jambo-wasm` | 🔵 `[SIM]` | Moteur d'isolation WASI `#![no_std]` (Palier 3) |
| **Cryptographie Avancée** | `jambo-pqc`, `jambo-fhe`, `jambo-zksnark`, `jambo-mpc`, `jambo-kms` | 🔵 `[SIM]` | Intégration de bibliothèques temps constant vérifiées (Palier 4) |
| **Protection Réseau & Détection**| `jambo-vpn`, `jambo-waf`, `jambo-ddos`, `jambo-idps`, `jambo-ndr` | 🔵 `[SIM]` | Déploiement au-dessus de `jambo-netd` stabilisé (Palier 4) |
| **Surveillance & Résilience** | `jambo-edr`, `jambo-xdr`, `jambo-siem`, `jambo-soar`, `jambo-forensics` | 🔵 `[SIM]` | Consommation des traces d'audit scellées émises par `libjambo` (Palier 4) |
| **Gouvernance & Sécurité Cloud** | `jambo-ztna`, `jambo-casb`, `jambo-cspm`, `jambo-cwpp`, `jambo-ciem` | 🔵 `[SIM]` | Démons d'administration isolés s'exécutant en Ring 3 (Palier 4) |

---

## 5. Journal des Jalons et Historique de Versionnage

* **2026-10-31** : **Jalon 2.3 (`v0.3.43`) — Assainissement Monorepo, Isolation `incubator/` & Métriques Réelles**
  * Quarantaine méthodique des ~100 crates prospectives dans le répertoire autonome [`incubator/`](incubator/README.md).
  * Simplification drastique du `Cargo.toml` racine, restreint aux 9 crates de production vérifiées.
  * Formalisation et publication du rapport de mesures d'ingénierie [`BENCHMARKS.md`](BENCHMARKS.md).
  * Harmonisation de la documentation technique et adoption de la matrice de maturité à 4 niveaux.

* **2026-10-31** : **Jalon 2.2 (`v0.3.42`) — Tranche Verticale Stockage VirtIO-Block Ring 3 & JamboFS Réel**
  * Implémentation du pilote VirtIO-Block Modern 1.2 Ring 3 (`jambo-blockd`, PID 3) avec Virtqueues DMA.
  * Implémentation du serveur de fichiers `jambo-fs` (PID 4) lisant l'Uberblock au LBA 0 du disque VirtIO QEMU.
  * Mise en place de l'arène VMO zéro-copie de 64 Kio pour les transferts de blocs sans recopie noyau.
  * Validation end-to-end sous QEMU UEFI avec code de sortie CI 33.

* **2026-10-31** : **Jalon 2.1 (`v0.3.41`) — Tranche Verticale Console UART COM1 & Shell Ring 3**
  * Premier exécutable utilisateur Ring 3 `jambo-init` (PID 1) démarré via `sysretq`.
  * Shell modulaire `jambo-sh` (PID 2) connecté au contrôleur série UART 16550A COM1 (115200 baud).
  * Prise en charge du mode interactif et du mode headless automatisé pour la CI.

* **2026-10-31** : **Palier 1 (`v0.3.40`) — Purge Iron Core & Micro-Noyau Ring 0 Minimal**
  * Élagage de 80+ suites de tests mocks logées dans le noyau (TCB < 95 Kio de code exécutable `.text`).
  * Stabilisation de la pagination matérielle PML4 4-niveaux avec protection $W \oplus X$ et identité HHDM.
  * Commutation de contexte assembleur AMD64 conforme System V ABI et ordonnanceur SMP EEVDF.
  * Protection anti-ABA de la table de capacités `CSpace` validée par model checking Kani.

* **2026-10-30** : **Réalignement Stratégique (`v0.3.39`)**
  * Intégration des conclusions des revues d'architecture externes et adoption de l'échelle de maturité à 4 niveaux.
  * Abandon des cadences d'automatisation artificielles au profit de jalons d'ingénierie matérielle réels.
  * Définition de la feuille de route en 4 paliers orientée vers la tranche verticale Ring 3 complète (`v0.4.0`).

* **2026-10-24** : Consolidation du sous-système de résilience firmware `jambo-fdr` (surveillance SPI Flash et attestation TPM).
* **2026-10-22** : Implémentation du changement de contexte assembleur System V AMD64 et configuration des registres MSR per-CPU.
* **2026-10-20** : Stabilisation de la pagination PML4 matérielle avec audit W^X sous QEMU.
* **2026-10-18** : Création du dépôt, initialisation du protocole d'amorçage Limine v3 UEFI en Rust `#![no_std]`.

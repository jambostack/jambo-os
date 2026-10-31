<p align="center">
  <img src="docs/assets/banner.png" alt="JamboOS Banner" width="800">
</p>

<p align="center">
  <img src="docs/assets/logo.svg" alt="JamboOS Logo" width="110" height="110">
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <img src="docs/assets/mascot.svg" alt="JamboOS Mascot" width="110" height="110">
</p>

<h1 align="center"><strong>JamboOS (jambostack/jambo-os)</strong></h1>
<p align="center"><strong>Système d'Exploitation Micro-noyau de 3e Génération Orienté Capacités en Rust <code>#![no_std]</code></strong></p>

<p align="center">
  <a href="https://github.com/jambostack/jambo-os/actions/workflows/ci.yml"><img src="https://github.com/jambostack/jambo-os/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/jambostack/jambo-os"><img src="https://img.shields.io/badge/version-v0.3.43-blue.svg" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green.svg" alt="License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-nightly%20%23!%5Bno__std%5D-red.svg" alt="Rust"></a>
</p>

<p align="center">
  <em>Auteur & Architecte Principal</em> : <strong>ASSOGBA Prudence Dieudonné</strong> &bull;
  <em>Dépôt officiel</em> : <a href="https://github.com/jambostack/jambo-os">https://github.com/jambostack/jambo-os</a><br>
  <em>Architectures cibles</em> : x86_64 (Long Mode 64 bits) & AArch64 (ARM64) / Multicœur SMP / UEFI 2.11 (Protocole Limine v3)
</p>

---

> [!NOTE]
> **Statut du Projet : Version `v0.3.43` (Tranche Verticale Ring 3 Active & Monorepo Consolidé)**  
> JamboOS est un micro-noyau moderne orienté capacités de 3e génération, développé à partir de zéro en Rust bare-metal (`#![no_std]`).  
> 
> Le système est **authentiquement opérationnel sous QEMU UEFI** :
> * **Micro-noyau Ring 0 Minimal** : TCB confiné sous 95 Kio de code exécutable (`.text`), pagination 4 niveaux PML4 avec protection $W \oplus X$, ordonnanceur SMP EEVDF préemptif, et table de capacités `CSpace` protégée contre le problème ABA.
> * **Espace Utilisateur Ring 3 Isolé** : 4 processus distincts s'exécutent dans leurs propres espaces d'adressage virtuels : le superviseur racine `jambo-init` (PID 1), le shell série UART COM1 `jsh` (PID 2), le pilote VirtIO-Block moderne `jambo-blockd` (PID 3), et le serveur de fichiers transactionnel `jambo-fs` (PID 4).
> * **Stockage Réel & VMO Zéro-Copie** : Montage et lecture du système de fichiers JamboFS depuis un disque VirtIO QEMU émulé via une arène VMO partagée de 64 Kio.
> * **Isolation de l'Incubateur R&D** : Les ~100 briques logicielles et algorithmes prospectifs (cryptographie post-quantique, homomorphe, micro-VM Wasm, etc.) sont rigoureusement isolés dans le répertoire [`incubator/`](incubator/README.md) pour garantir un socle officiel épuré à 9 crates strictes.
> 
> 📊 **Métriques & Performances Vérifiées** : Consultez les mesures réelles (temps de boot, empreinte binaire, latence IPC) dans [`BENCHMARKS.md`](BENCHMARKS.md).  
> 🗺️ **Feuille de Route Détaillée** : Consultez notre planning transparent dans [`ROADMAP.md`](ROADMAP.md).

---

## 1. Vue d'Ensemble Architecturale

**JamboOS** applique les principes rigoureux des micro-noyaux de 3e génération (*Object-Capability Security Model*), inspirés de seL4, Fuchsia/Zircon et Genode. Le noyau priviligié (Ring 0 / EL1) est réduit à son strict minimum, tandis que les services système, le système de fichiers, la console et les pilotes matériels opèrent dans des espaces d'adressage isolés en espace utilisateur non privilégié (**Ring 3**).

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │  jambo-init  │  │   jambo-sh   │  │   jambo-fs   │  │jambo-blockd│  │
│  │   (PID 1)    │  │   (PID 2)    │  │   (PID 4)    │  │  (PID 3)   │  │
│  │ Superviseur  │  │ Console UART │  │  FS Merkle   │  │ Pilote BLK │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │
│         │                 │                 │                │         │
│         │                 │                 └─── VMO 64 Kio ─┘         │
│         │                 │                   (Zéro-Copie)             │
│         └─────────────────┼──────────────────────────────────┘         │
│                           │ Appels Système / IPC                       │
└───────────────────────────┼────────────────────────────────────────────┘
                            │ sysretq / syscall
┌───────────────────────────┴────────────────────────────────────────────┐
│                        ESPACE NOYAU (Ring 0)                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │               JAMBOKERNEL (TCB Minimalist < 95 Kio)              │  │
│  │  • Ordonnanceur EEVDF SMP            • Tables CSpace (Anti-ABA)  │  │
│  │  • Paging 4 Niveaux (W^X, CR3)       • Routage IPC & Fastpath    │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
└─────────────────────────────────────┼──────────────────────────────────┘
                                      │ MMIO / Port I/O / DMA
┌─────────────────────────────────────┴──────────────────────────────────┐
│                         MATÉRIEL / QEMU Q35 UEFI                       │
│  • CPU x86_64 SMP (4 vCPUs)     • UART 16550A COM1 (0x3F8)             │
│  • Disque VirtIO Modern 1.2     • Firmware OVMF UEFI (Boot Limine v3)  │
└────────────────────────────────────────────────────────────────────────┘
```

### Les 4 Piliers Fondamentaux

1. **Base Informatique de Confiance (TCB) Minimale** :
   Le micro-noyau superviseur (`kernel`) contient moins de 95 Kio de code exécutable en section `.text`. Il ne gère que les primitives irréductibles : commutation de contexte assembleur AMD64, pagination matérielle PML4 4-niveaux, ordonnanceur EEVDF multicœur, routage IPC et table de capacités `CSpace`.
2. **Communication Inter-Processus (IPC) Hybride Zéro-Copie** :
   - *Fastpath synchrone* par registres CPU pour les signaux de contrôle, notifications et transferts courts ($\approx 120$ cycles CPU).
   - *Anneaux de mémoire virtuelle partagée* (*VMO*) pour les flux de données volumineux (accès disques, blocs de 4 Kio), garantissant des transferts zéro-copie sans traversée de l'espace mémoire du noyau.
3. **Pilotes Matériels Isolés en Ring 3 Confinés par IOMMU** :
   Les pilotes matériels (comme le pilote de stockage VirtIO Modern `jambo-blockd`) s'exécutent en espace utilisateur non privilégié. Leurs accès directs à la mémoire (DMA) sont confinés par les mécanismes IOMMU (Intel VT-d / AMD-Vi), empêchant toute corruption de l'espace noyau ou des autres démons.
4. **Modèle de Sécurité par Capacités Pures (Zero Ambient Authority)** :
   Aucun processus ne détient de privilèges implicites. L'accès à toute ressource (page mémoire, objet mémoire VMO, canal IPC, port d'E/S) requiert un `Handle` de capacité 64 bits explicite, indexé dans la table `CSpace` et protégé contre la réutilisation (problème ABA) par un compteur de génération 32 bits.

---

## 2. Matrice de Maturité des Composants

Conformément à nos principes de rigueur et de transparence technique, chaque composant de JamboOS est classé selon une échelle de maturité à 4 niveaux :

| Niveau | Sigle | Désignation | Définition & Critères d'Ingénierie |
| :---: | :---: | :--- | :--- |
| 🟢 | **`[PROD]`** | **Production Bare-Metal** | Code compilé en `#![no_std]`, testé sous charge sous QEMU et bare-metal, 0 allocation dynamique non maîtrisée, linters stricts (`clippy -D warnings`). |
| 🟡 | **`[RING3-HW]`** | **Exécutable Ring 3 / Pilote Matériel** | Binaire utilisateur isolé dans son propre espace d'adressage virtuel (CR3), pilotant le matériel réel ou émulé (VirtIO, UART) via IPC et barrières IOMMU/DMA. |
| 🔵 | **`[SIM]`** | **Modèle en Mémoire / Machine à États** | Algorithmes et contrats d'interfaces validés logiquement en mémoire dans `incubator/`, en attente de couplage matériel Ring 3. |
| ⚪ | **`[SPEC]`** | **Spécification & Architecture** | Spécifications d'ABI, définitions de types d'interfaces et Architecture Decision Records (ADR). |

### État d'Avancement Réel des Sous-Systèmes (Jalon `v0.3.43`)

| Sous-Système | Rôle & Responsabilité Technique | Maturité | Emplacement | Statut |
| :--- | :--- | :---: | :--- | :--- |
| **Micro-Noyau JamboKernel** | TCB minimal (< 95 Kio `.text`), PMM Buddy, VMM PML4 W^X, EEVDF SMP, CSpace anti-ABA | 🟢 `[PROD]` | `kernel/` | 100% bare-metal, 0 mock, boot Limine UEFI |
| **ABI Système & IPC** | Contrats de syscalls System V AMD64, masques de capacités, canaux IPC, VMO partagés | 🟢 `[PROD]` | `abi/jambo-abi/` | Stabilisé, 28 syscalls x86_64 |
| **Runtime Espace Utilisateur** | Point d'entrée `_start`, gestion de pile System V, wrappers syscalls et IPC | 🟡 `[RING3-HW]` | `libs/libjambo/` | Opérationnel pour les 4 processus Ring 3 |
| **Superviseur `jambo-init`** | Processus racine Ring 3 (PID 1), orchestration de démarrage et isolation | 🟡 `[RING3-HW]` | `services/jambo-init/` | Opérationnel (chargé depuis initrd Limine) |
| **Shell Interactif `jambo-sh`** | Console série interactive UART COM1 (PID 2), commandes `cat`, `ps`, `sysinfo`, `exit` | 🟡 `[RING3-HW]` | `services/jambo-sh/` | Opérationnel (modes interactif et headless CI) |
| **Pilote VirtIO Modern** | Pilote VirtIO 1.2 Modern en espace utilisateur, queues DMA et découplage E/S | 🟡 `[RING3-HW]` | `drivers/virtio/` | Opérationnel (VirtIO Modern PCI/MMIO) |
| **Démon Stockage `jambo-blockd`** | Démon de blocs Ring 3 (PID 3), service de requêtes disques, arène VMO 64 Kio | 🟡 `[RING3-HW]` | `services/jambo-blockd/`| Opérationnel (connecté au disque QEMU 32 Mio) |
| **Serveur de Fichiers `jambo-fs`** | VFS Ring 3 (PID 4), format JamboFS, lecture Uberblock LBA 0 et résolution d'Inodes | 🟡 `[RING3-HW]` | `services/jambo-fs/` | Opérationnel (montage vérifié sous QEMU) |
| **Chaîne d'Outillage `xtask` & CI** | Build hermétique, création d'initrd.tar, formatage disk.raw, ISO Limine et runner QEMU | 🟢 `[PROD]` | `xtask/` | Opérationnel en CI (sortie automatique code 33) |
| **Pilote Réseau `jambo-netd`** | Démon réseau Ring 3 (PID 5), VirtIO-Net, résolutions ARP et ICMP ping | ⚪ `[SPEC]` | `incubator/` | Cible prioritaire du **Jalon 2.4 (`v0.3.44`)** |
| **Pilotes NVMe & USB xHCI** | Contrôleurs NVMe 1.4 et USB 3.0 xHCI | ⚪ `[SPEC]` | `incubator/drivers/` | Spécifications en attente de portage Ring 3 |
| **Incubateur Cybersécurité & IA** | ~100 microservices prospectifs (PQC, FHE, ZK, Wasm, FDR, CASB, EDR...) | 🔵 `[SIM]` | `incubator/services/` | Isolé dans `incubator/` (voir [`incubator/README.md`](incubator/README.md)) |

---

## 3. Métriques Réelles & Performances (`BENCHMARKS.md`)

Contrairement aux allégations théoriques, toutes les performances de JamboOS sont mesurées sur des binaires de production (`release`) exécutés sous QEMU UEFI avec accélération matérielle :

| Indicateur Clé | Valeur Mesurée | Conditions d'Exécution |
| :--- | :---: | :--- |
| **Taille Exécutable Kernel (`.text`)** | **94 634 octets** *(< 95 Kio)* | Mode release, LTO actif, micro-noyau minimal |
| **Temps d'Amorçage UEFI Limine** | **$< 150 \text{ ms}$** | Démarrage OVMF EDK2 $\to$ Premier message UART |
| **Initialisation Complète Ring 3** | **$< 450 \text{ ms}$** | 4 processus Ring 3 créés, JamboFS monté, disques prêts |
| **Cycle de Test Automatisé CI** | **$< 850 \text{ ms}$** | Exécution complète sous QEMU avec sortie code `33` |
| **Fastpath Appel Système (`syscall`)** | **$\approx 120 \text{ cycles}$** | Commutation Ring 3 $\to$ Ring 0 $\to$ Ring 3 |
| **Bande Passante Mémoire VMO** | **$> 15 \text{ Go/s}$** | Arène partagée 64 Kio (zéro-copie inter-processus) |

👉 Le rapport exhaustif détaillant l'environnement de mesure, l'empreinte de chaque binaire et les commandes de reproduction est disponible dans :  
📊 **[`BENCHMARKS.md`](BENCHMARKS.md)**

---

## 4. Isolation de l'Incubateur R&D (`incubator/`)

Dans le cadre du Jalon 2.3 (`v0.3.43`), JamboOS a assaini son architecture en séparant strictement :
1. **Le Workspace Racine Officiel (9 Crates)** : Le micro-noyau, la bibliothèque utilisateur, le pilote VirtIO, les 4 processus de la tranche verticale Ring 3, et l'orchestrateur `xtask`.
2. **L'Incubateur Autonome ([`incubator/`](incubator/README.md))** : Environ 100 crates prospectives couvrant la recherche cryptographique post-quantique (ML-KEM, Falcon), le chiffrement homomorphe, les bacs à sable WebAssembly, la défense firmware (`jambo-fdr`) et les pilotes hôtes (NVMe, xHCI).

Cette séparation garantit des temps de compilation records pour le système d'exploitation officiel, tout en conservant les briques de recherche dans un espace dédié soumis à des critères stricts de graduation (isolation Ring 3, couplage IPC authentique, validation matérielle, zéro mock).

Consultez la charte complète dans [`incubator/README.md`](incubator/README.md).

---

## 5. Arborescence du Projet

```
jambo-os/
├── abi/
│   └── jambo-abi/           # ABI binaire, définitions des syscalls et descripteurs de capacités
├── boot/
│   └── limine.cfg           # Configuration du chargeur d'amorçage UEFI Limine v3
├── docs/
│   ├── adr/                 # Architecture Decision Records (ADR-0001 à ADR-0026)
│   ├── assets/              # Identité visuelle, logos et bannières
│   ├── specs/               # Spécifications de la carte mémoire, ABI et charte unsafe
│   └── superpowers/         # Spécifications et plans d'implémentation SDD
├── drivers/
│   └── virtio/              # Pilote VirtIO Modern 1.2 (Block) en espace utilisateur
├── kernel/                  # Micro-noyau Ring 0 (TCB Minimalist < 95 Kio)
│   └── src/
│       ├── arch/x86_64/     # Initialisation matérielle, GDT, IDT, APIC, MSR
│       ├── cap/             # Gestionnaire de tables de capacités CSpace (anti-ABA)
│       ├── ipc/             # Fastpath registres et canaux de mémoire partagée
│       ├── mm/              # PMM Bitmap, pagination PML4 W^X, HHDM
│       ├── sched/           # Ordonnanceur multicœur EEVDF et commutation assembleur
│       └── syscall/         # Dispatcher des appels système sécurisés (28 syscalls)
├── libs/
│   └── libjambo/            # Runtime d'espace utilisateur Ring 3 et wrappers de syscalls
├── services/                # Les 4 Processus Actifs de la Tranche Verticale Ring 3
│   ├── jambo-init/          # Superviseur système PID 1 en Ring 3
│   ├── jambo-sh/            # Shell interactif sur console série UART COM1 (PID 2)
│   ├── jambo-blockd/        # Démon de stockage VirtIO-Block moderne (PID 3)
│   └── jambo-fs/            # Système de fichiers transactionnel JamboFS (PID 4)
├── incubator/               # ~100 Crates Prospectives & Recherche Avancée (Workspace Autonome)
│   ├── Cargo.toml           # Manifeste indépendant de l'incubateur
│   ├── README.md            # Charte, statuts [SIM]/[SPEC] et critères de graduation
│   ├── drivers/             # Pilotes en attente de validation matérielle (NVMe, xHCI)
│   ├── libs/                # Bibliothèques prospectives (jambo-sdk, jambo-ui)
│   └── services/            # Micro-services prospectifs (PQC, FHE, Wasm, FDR, VPN, etc.)
├── xtask/                   # Outil d'orchestration : compilation, initrd, disk.raw, ISO et runner QEMU
├── BENCHMARKS.md            # Métriques d'ingénierie réelles et vérifiées (boot, taille, IPC)
└── ROADMAP.md               # Feuille de route technique et journal des jalons vérifiés
```

---

## 6. Instructions de Compilation et d'Exécution

### Prérequis
* Rust **nightly** avec la cible `x86_64-unknown-none` :
  ```bash
  rustup target add x86_64-unknown-none
  rustup component add rust-src llvm-tools-preview clippy rustfmt
  ```
* Outils d'émulation et de virtualisation :
  * `qemu-system-x86_64` (avec support UEFI OVMF)
  * `xorriso` (génération d'images ISO hybrides amorçables)

### Commandes Principales via `xtask`

```bash
# 1. Compiler le noyau et les 4 processus Ring 3 en mode release
cargo xtask build --release

# 2. Générer l'initrd (initrd.tar) et formater le disque JamboFS (disk.raw)
cargo xtask prep-disk

# 3. Générer l'image ISO hybride UEFI amorçable (jamboos-x86_64.iso)
cargo xtask iso --release

# 4. Lancer la machine virtuelle sous QEMU (SMP 4 cœurs, OVMF UEFI, disque VirtIO)
cargo xtask qemu --release

# 5. Exécuter la suite automatisée de validation CI sous QEMU (code retour 33 attendu)
cargo xtask test --release
```

---

## 7. Feuille de Route & Prochaines Étapes

Pour connaître les détails du plan de travail en 4 paliers (stabilisation du socle *Iron Core*, réalisation de la tranche verticale `v0.4.0`, intégration réseau VirtIO-Net et accompagnement de l'incubateur), consultez le document de référence :  
👉 **[`ROADMAP.md`](ROADMAP.md)**

---

## 8. Licence

Le projet **JamboOS** est distribué sous double licence permissive [MIT](LICENSE) ou [Apache-2.0](LICENSE), au choix de l'utilisateur.

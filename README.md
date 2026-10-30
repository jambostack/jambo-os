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
  <a href="https://github.com/jambostack/jambo-os"><img src="https://img.shields.io/badge/version-v0.3.39-orange.svg" alt="Version"></a>
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
> **Statut du Projet : Version `v0.3.39` (Pré-Alpha active — Phase de Consolidation & Rationalisation)**  
> JamboOS est un projet d'ingénierie et de recherche système bare-metal. Le projet est actuellement en phase de consolidation : son **socle Ring 0 bare-metal est opérationnel sous QEMU** (amorçage UEFI Limine v3, pagination 4 niveaux W^X, commutation de contexte assembleur AMD64, CSpace anti-ABA), et le développement est concentré sur la **Tranche Verticale Ring 3 (`v0.4.0`)** (processus utilisateur `jambo-init`, pilote VirtIO-Block, VFS transactionnel et shell série interactif).  
> 
> Consultez notre feuille de route transparente : [`ROADMAP.md`](ROADMAP.md).

---

## 1. Vue d'Ensemble Architecturale

**JamboOS** est un système d'exploitation conçu à partir de zéro (*from scratch*) en Rust `#![no_std]` et Assembleur bare-metal, sans aucune dépendance externe tierce dans son socle. Contrairement aux systèmes monolithiques traditionnels dont des dizaines de millions de lignes de code s'exécutent en espace privilégié (Ring 0 / EL1), JamboOS applique une architecture de **micro-noyau de 3e génération orienté capacités** (*Object-Capability Security Model*), inspirée des travaux de seL4, Fuchsia/Zircon et Genode.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │   jambo-sh   │  │  jambo-init  │  │   jambo-fs   │  │ jambo-fdr  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │
│         │                 │                 │                │         │
│  ┌──────┴─────────────────┴─────────────────┴────────────────┴──────┐  │
│  │                 PILOTES ISOLÉS (VirtIO, NVMe, xHCI)              │  │
│  │               Protection DMA par Barrières IOMMU (VT-d)          │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
└─────────────────────────────────────┼──────────────────────────────────┘
                                      │ IPC / Syscalls
┌─────────────────────────────────────┴──────────────────────────────────┐
│                        ESPACE NOYAU (Ring 0)                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                     JAMBOKERNEL (TCB Minimal)                    │  │
│  │  • Ordonnanceur EEVDF SMP            • Tables CSpace (Anti-ABA)  │  │
│  │  • Paging 4 Niveaux (W^X, CR3)       • Anneaux IPC Zéro-Copie    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### Les 4 Piliers Fondamentaux

1. **Base Informatique de Confiance (TCB) Minimale** :
   Le micro-noyau superviseur (`JamboKernel`) est strictement confiné à moins de 25 000 lignes de code. Il ne gère que les primitives irréductibles : ordonnancement des threads, gestion des espaces d'adressage virtuels (PMM/VMM), validation des capacités (`CSpace`) et routage des interruptions/IPC.

2. **Communication Inter-Processus (IPC) Hybride Zéro-Copie** :
   - *Fastpath synchrone* par registres CPU pour les messages courts et signaux de contrôle.
   - *Anneaux de mémoire partagée* (*Shared Ring Buffers*) asynchrones pour les charges utiles volumineuses (I/O bloc, trames réseau), évitant toute recopie entre espaces d'adressage.

3. **Pilotes Matériels Isolés en Ring 3 Confinés par IOMMU** :
   Tous les pilotes de périphériques (VirtIO-Block, VirtIO-Net, NVMe, xHCI) s'exécutent en espace utilisateur non privilégié. Leurs accès directs à la mémoire (DMA) sont strictement limités aux pages allouées par des domaines IOMMU (Intel VT-d / AMD-Vi), protégeant le système contre les corruptions et attaques DMA.

4. **Modèle de Sécurité par Capacités Pures (Zero Ambient Authority)** :
   Aucun processus ne possède de privilèges implicites. L'accès à toute ressource (page mémoire, canal IPC, port d'E/S) requiert un `Handle` de capacité 64 bits explicite, protégé contre la réutilisation par un compteur de génération (*anti-ABA*).

---

## 2. Matrice de Maturité des Composants

En cohérence avec notre politique de transparence technique, chaque composant est classé selon son niveau d'avancement réel :

| Niveau | Désignation | Description |
| :---: | :--- | :--- |
| 🟢 | **`[CORE-HW]`** | **Opérationnel Bare-Metal / QEMU** : Code exécuté et vérifié au niveau matériel. |
| 🟡 | **`[RING3-DEV]`** | **En Cours d'Intégration Ring 3** : Processus isolé, pilotes d'E/S et IPC en cours de stabilisation. |
| 🔵 | **`[SIM-MEM]`** | **Modèle en Mémoire / Incubateur** : Contrats d'interfaces et logique validés par assertions logiques. |
| ⚪ | **`[SPEC-PLAN]`** | **Spécification & Architecture** : Définition des types ABI et Architecture Decision Records (ADRs). |

### État d'Avancement des Sous-Systèmes

| Sous-Système | Rôle & Responsabilité Technique | Maturité | Statut |
| :--- | :--- | :---: | :--- |
| **Amorçage UEFI Limine v3** | Passage en mode long 64 bits, HHDM, parsing de mémoire physique | 🟢 `[CORE-HW]` | Opérationnel (QEMU & bare-metal) |
| **Pagination Matérielle (MMU)** | Tables PML4 x86_64 à 4 niveaux, switch CR3 asm, protection W^X | 🟢 `[CORE-HW]` | Opérationnel (audité `readelf -l`) |
| **Commutation de Contexte** | Conforme ABI System V AMD64 via `global_asm!`, registres MSR per-CPU | 🟢 `[CORE-HW]` | Opérationnel |
| **Modèle de Capacités (CSpace)** | Descripteurs 64 bits, clés de génération anti-ABA, masques de droits | 🟢 `[CORE-HW]` | Opérationnel (model checking Kani) |
| **Chaîne d'Outillage `xtask` & CI** | Build hermétique, création d'ISO bootable Limine, tests automatisés QEMU | 🟢 `[CORE-HW]` | Opérationnel en CI |
| **Superviseur `jambo-init`** | Premier processus racine chargé en Ring 3 via `sysretq` / `iretq` | 🟡 `[RING3-DEV]` | En cours (Cible `v0.4.0`) |
| **Pilote VirtIO-Block / Net** | Requêtes d'E/S asynchrones DMA, Virtqueues et interruptions APIC | 🟡 `[RING3-DEV]` | En cours (Cible `v0.4.0`) |
| **Système de Fichiers `jambo-fs`** | VFS transactionnel Merkle Copy-on-Write connecté au disque VirtIO | 🟡 `[RING3-DEV]` | En cours (Cible `v0.4.0`) |
| **Shell Interactif `jambo-sh`** | Console série UART COM1 (115200 baud) avec commandes natives (`ps`, `caps`, `ls`) | 🟡 `[RING3-DEV]` | En cours (Cible `v0.4.0`) |
| **Résilience Firmware `jambo-fdr`** | Attestation TPM 2.0 / DICE, intégrité SPI Flash et tables ACPI | 🟡 `[RING3-DEV]` | En cours de portage Ring 3 |
| **Runtime Wasm `jambo-wasm`** | Exécuteur WebAssembly `#![no_std]`, bac à sable WASI Component Model | 🟡 `[RING3-DEV]` | En cours de consolidation |
| **Pilotes NVMe & USB xHCI** | Squelettes de descripteurs et structures de registres MMIO | 🔵 `[SIM-MEM]` | Ébauche / Contrats posés |
| **Incubateur Cybersécurité** | Microservices avancés (FHE, zk-SNARKs, CASB, EDR, PAM, Raft...) | 🔵 `[SIM-MEM]` | En incubateur (détail dans `ROADMAP.md`) |

> [!NOTE]
> **Vérification Formelle & Model Checking** :  
> Le projet s'appuie sur le vérificateur Kani (CBMC) pour prouver par *model checking borné à la compilation* des invariants critiques locaux (absence de panique, étanchéité de la table CSpace, non-chevauchement des allocations). Les méthodologies et résultats de tests sont documentés dans le répertoire `docs/verification/`.

---

## 3. Arborescence du Projet

```
jambo-os/
├── abi/
│   └── jambo-abi/           # ABI binaire, définitions des syscalls et descripteurs de capacités
├── boot/
│   └── limine.cfg           # Configuration du chargeur d'amorçage UEFI Limine v3
├── docs/
│   ├── adr/                 # Architecture Decision Records (ADR-0001 à ADR-0026)
│   ├── assets/              # Identité visuelle, logos et bannières
│   └── specs/               # Spécifications de la carte mémoire, ABI et charte unsafe
├── drivers/
│   ├── virtio/              # Pilotes VirtIO 1.1 (Block, Net, GPU) en espace utilisateur
│   ├── nvme/                # Contrôleur NVMe 1.4 Ring 3 (squelette d'interfaces)
│   └── xhci/                # Contrôleur USB 3.0 xHCI Ring 3 (squelette d'interfaces)
├── kernel/                  # Micro-noyau Ring 0 (TCB Minimal)
│   └── src/
│       ├── arch/x86_64/     # Initialisation matérielle, GDT, IDT, APIC, MSR
│       ├── cap/             # Gestionnaire de tables de capacités CSpace (anti-ABA)
│       ├── ipc/             # Fastpath registres et canaux de mémoire partagée
│       ├── mm/              # PMM Buddy, tas SLUB, pagination PML4 W^X
│       ├── sched/           # Ordonnanceur multicœur EEVDF et commutation assembleur
│       └── syscall/         # Dispatcher des appels système sécurisés
├── libs/
│   ├── libjambo/            # Runtime d'espace utilisateur et wrappers de syscalls
│   ├── jambo-sdk/           # SDK pour le développement d'applications natives
│   └── jambo-ui/            # Toolkit graphique déclaratif pour compositeur
├── services/                # Services Système & Tranche Verticale Ring 3
│   ├── jambo-init/          # Superviseur système PID 1 en Ring 3
│   ├── jambo-fs/            # Système de fichiers transactionnel Merkle CoW
│   ├── jambo-sh/            # Shell interactif sur console série UART COM1
│   ├── jambo-fdr/           # Défense firmware SPI Flash, TPM 2.0 et Dual-BIOS
│   ├── jambo-wasm/          # Runtime WebAssembly / bac à sable WASI
│   ├── pcie-bus-mgr/        # Gestionnaire de bus PCIe et isolation IOMMU
│   └── [...]                # Micro-services spécialisés en phase d'incubation
└── xtask/                   # Outil d'orchestration : compilation, ISO et tests QEMU
```

---

## 4. Instructions de Compilation et d'Exécution

### Prérequis
* Rust **nightly** avec la cible `x86_64-unknown-none` :
  ```bash
  rustup target add x86_64-unknown-none
  rustup component add rust-src llvm-tools-preview clippy rustfmt
  ```
* Outils d'émulation et de conteneurisation :
  * `qemu-system-x86_64` (avec support OVMF UEFI)
  * `xorriso` (pour la création d'images ISO amorçables)

### Commandes Principales via `xtask`

```bash
# 1. Compiler le noyau JamboKernel en mode release
cargo xtask build --release

# 2. Générer l'image ISO hybride UEFI amorçable (jamboos-x86_64.iso)
cargo xtask iso --release

# 3. Lancer la machine virtuelle sous QEMU (SMP multicœur, OVMF UEFI)
cargo xtask qemu --release

# 4. Exécuter la suite automatisée de validation CI (headless)
cargo xtask test --release
```

---

## 5. Feuille de Route & Prochaines Étapes

Pour connaître les détails du plan de travail en 4 paliers (stabilisation du socle *Iron Core*, réalisation de la tranche verticale `v0.4.0`, et accompagnement de l'incubateur de services), consultez le document de référence :  
👉 **[`ROADMAP.md`](ROADMAP.md)**

---

## 6. Licence

Le projet **JamboOS** est distribué sous double licence permissive [MIT](LICENSE) ou [Apache-2.0](LICENSE), au choix de l'utilisateur.

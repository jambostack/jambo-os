# FEUILLE DE ROUTE D'INGÉNIERIE SYSTÈME — JamboOS

> **Dernière mise à jour** : 30 octobre 2026  
> **Version actuelle** : `v0.3.39` (Phase de Consolidation & Rationalisation)  
> **Statut global** : Pré-Alpha active — Micro-noyau Rust `#![no_std]` de 3e génération orienté capacités  
> **Objectif stratégique immédiat** : Stabilisation du socle « Iron Core » et Tranche Verticale Ring 3 (`v0.4.0`)

---

## 1. Principes Directeurs & Cadre de Maturité

À la suite de la revue critique et constructive d'architecture (octobre 2026), JamboOS fait évoluer sa gouvernance technique pour s'aligner sur les exigences les plus rigoureuses de l'ingénierie système et de la communauté Rust OSDev. 

Le projet abandonne les cadences d'automatisation artificielles et le statut binaire « Validé » au profit d'une **transparence technique totale** structurée autour d'une échelle de maturité à 4 niveaux :

```
┌────────────────────────────────────────────────────────────────────────┐
│                   ÉCHELLE DE MATURITÉ TECHNIQUE                        │
├───────────────┬────────────────────────────────────────────────────────┤
│ 🟢 [CORE-HW]  │ Niveau 4 — Matériel / Émulation QEMU Validée           │
│               │ Exécution effective au niveau processeur (Ring 0/3,    │
│               │ pagination matérielle CR3, Limine, context-switch asm) │
├───────────────┼────────────────────────────────────────────────────────┤
│ 🟡 [RING3-DEV]│ Niveau 3 — En Cours d'Intégration Ring 3               │
│               │ Binaire ELF isolé, pilotes d'E/S DMA/IRQ réelles,      │
│               │ IPC par canaux CSpace sous charge                      │
├───────────────┼────────────────────────────────────────────────────────┤
│ 🔵 [SIM-MEM]  │ Niveau 2 — Modèle en Mémoire / Machine à États         │
│               │ Assertions de conformité logique, bitflags de droits   │
│               │ et contrats d'interfaces testés en mémoire             │
├───────────────┼────────────────────────────────────────────────────────┤
│ ⚪ [SPEC-PLAN] │ Niveau 1 — Spécification & Architecture (ADR)          │
│               │ Spécification formelle, types ABI et vision cible      │
└───────────────┴────────────────────────────────────────────────────────┘
```

---

## 2. Bilan de l'Existant & Décisions d'Assainissement

### 2.1. Les Fondations Réelles et Éprouvées 🟢 `[CORE-HW]`
* **Amorçage UEFI Limine v3** : Initialisation propre du mode long 64 bits (`#![no_main]`), récupération de la carte mémoire physique, framebuffer et HHDM (*Higher Half Direct Map*).
* **Pagination Matérielle 4 Niveaux (x86_64)** : Gestion des tables PML4/PDPT/PD/PT, rechargement CR3 via assembleur inline (`mov cr3, reg`), et stricte application de la politique W^X (*Write XOR Execute*) auditée en binaire ELF via `readelf -l`.
* **Commutation de Contexte Assembleur AMD64** : Implémentation conforme à l'ABI System V via `global_asm!` (sauvegarde de la pile, registres callee-saved, manipulation déterministe de `rsp`).
* **Structures Per-CPU & SMP** : Configuration des registres MSR modèles spécifiques (`IA32_GS_BASE_MSR`) pour l'isolation des données par cœur.
* **Sécurité par Capacités (CSpace)** : Primitives de descripteurs 64 bits avec clé de génération anti-réutilisation (anti-ABA) et masques de droits stricts sans autorité ambiante.
* **Chaîne d'Outillage `xtask` & CI** : Compilation sans dépendance externe tierce (`Cargo.toml` racine autonome), génération d'ISO bootable via `xorriso`/Limine et test d'amorçage automatisé sous QEMU headless.

### 2.2. Décisions de Refonte Immédiates (Résolution de la Dette Critique)
1. **Purge du Ring 0** : Sortie de l'ensemble des 80+ suites de tests applicatifs (`fhe_test.rs`, `casb_test.rs`, `ztna_test.rs`, etc.) actuellement logées dans `kernel/src/sched/`. Le Ring 0 doit redevenir un micro-noyau minimal strict (< 25 000 lignes de code).
2. **Création d'un dossier `incubator/`** : Déplacement des crates prospectives de haut niveau (chiffrement homomorphe FHE, zk-SNARKs, CASB, EDR, CWPP, PAM...) hors du workspace central pour libérer la maintenance et focaliser l'effort sur les sous-systèmes vitaux.
3. **Rectification du Vocabulaire Scientifique** : Les vérifications formelles actuelles s'appuient sur du *model checking borné à la compilation* via Kani (CBMC), qui valide des invariants locaux précis (absence de panique, étanchéité de bits). Elles ne doivent plus être qualifiées de « preuves formelles globales au boot » au sens seL4.
4. **Mesures et Benchmarks Publics** : Remplacement des affirmations non étayées par la création d'un fichier `BENCHMARKS.md` explicitant la méthodologie de test, la charge et les cycles réels mesurés sous QEMU et sur bare-metal.

---

## 3. Plan d'Action par Paliers : Trajectoire vers JamboOS v0.4+

```
┌────────────────────────────────────────────────────────────────────────┐
│                   PLAN DE DÉVELOPPEMENT EN 4 PALIERS                   │
├────────────────────────────────────────────────────────────────────────┤
│ Palier 1 : Stabilisation « Iron Core » (Micro-noyau minimal Ring 0)    │
│            Nettoyage kernel/, durcissement unsafe, Kani sur CSpace     │
├────────────────────────────────────────────────────────────────────────┤
│ Palier 2 : Tranche Verticale Ring 3 (Jalon v0.4.0)                     │
│            jambo-init (Ring 3) → virtio-blk (DMA/IRQ) → jambofs → jsh  │
├────────────────────────────────────────────────────────────────────────┤
│ Palier 3 : Piliers Différenciateurs (Résilience Firmware & Wasm Host)  │
│            Attestation FDR / TPM 2.0 + Micro-VM WebAssembly WASI       │
├────────────────────────────────────────────────────────────────────────┤
│ Palier 4 : Écosystème & Incubateur de Micro-Services                   │
│            Portage progressif des 80+ crates vers des démons Ring 3    │
└────────────────────────────────────────────────────────────────────────┘
```

---

### Palier 1 : Stabilisation du Socle « Iron Core » (`v0.3.40` – `v0.3.45`)
* **Objectif** : Rendre le micro-noyau Ring 0 irréprochable, auditable et strictement confiné à ses responsabilités premières.
* **Actions prioritaires** :
  1. **Assainissement du Ring 0** : Élaguer `kernel/src/sched/` et `kernel/src/main.rs` pour ne conserver que l'ordonnanceur EEVDF, la pagination PMM/VMM, la commutation de contexte et le bus IPC.
  2. **Application Stricte de la Charte Unsafe** :
     * Activer `#![deny(unsafe_op_in_unsafe_fn)]` sur l'ensemble du noyau et des pilotes.
     * Imposer la documentation obligatoire `// SAFETY: <justification d'invariant>` sur tout bloc `unsafe`.
  3. **Couverture CI Complète** :
     * Étendre `cargo clippy --workspace -D warnings` à tout le noyau et aux pilotes (et non plus seulement `jambo-abi` et `xtask`).
     * Mettre en place un contrôle de compilation strict pour la cible `aarch64-unknown-none`.
  4. **Model Checking Kani Structuré** :
     * Validation formelle de la table CSpace (absence de panique, étanchéité de l'atténuation monotone des droits, détection anti-ABA).
     * Publication des rapports de vérification Kani dans `docs/verification/`.

---

### Palier 2 : La Tranche Verticale Ring 3 — Jalon Majeur `v0.4.0`
* **Objectif** : Démontrer une exécution de bout en bout réelle, vérifiable en une seule commande (`cargo xtask run`).
* **Composants de la chaîne** :
  1. **`services/jambo-init` (Ring 3 réel)** :
     * Chargement du premier exécutable ELF en espace utilisateur non privilégié via `sysretq` / `iretq` (CPL = 3).
     * Première négociation de capacités via appels système.
  2. **`drivers/virtio` (Pilote Bloc & Console Ring 3)** :
     * Implémentation complète de la spécification VirtIO 1.1 MMIO/PCIe.
     * Allocation de tampons DMA physiquement contigus protégés par barrière IOMMU.
     * Traitement réel des interruptions matérielles APIC routées vers le thread du pilote.
  3. **`services/jambo-fs` (VFS CoW connecté au disque)** :
     * Lecture et écriture de blocs réels sur le disque VirtIO monté sous QEMU.
     * Arbre de Merkle pour la vérification d'intégrité des données au repos.
  4. **`services/jambo-sh` (Shell interactif sur UART COM1)** :
     * Boucle d'événements asynchrone sur le port série COM1 (115200 baud).
     * Commandes natives fonctionnelles : `help`, `ps` (liste des tâches Ring 3), `caps` (inspection CSpace), `ls` (parcours VFS), `fdr-status` (état firmware).
  5. **Dossier de Preuves `BENCHMARKS.md`** :
     * Mesure du temps d'amorçage jusqu'au prompt interactif.
     * Mesure de la latence IPC réelle (fast-path registres CPU vs tampons annulaires partagés).

---

### Palier 3 : Piliers Différenciateurs (Résilience Matérielle & Cloud Wasm)
* **Objectif** : Positionner JamboOS sur ses deux atouts stratégiques à haute valeur ajoutée.
* **Axes technologiques** :
  1. **Résilience Matérielle Souveraine (`services/jambo-fdr`)** :
     * Interaction avec la racine de confiance matérielle (RoT TPM 2.0 / DICE).
     * Mesure et vérification des tables ACPI (MADT/DSDT) et SMBIOS.
     * Surveillance de l'intégrité du firmware SPI Flash et mécanisme de restauration Dual-BIOS.
  2. **Hôte WebAssembly / Micro-VM Cloud (`services/jambo-wasm`)** :
     * Abandon de la chimère d'une compatibilité Linux POSIX complète (`jambo-linux`), trop lourde et incohérente avec un micro-noyau à capacités pures.
     * Implémentation d'un environnement d'exécution ultra-rapide pour composants WebAssembly (WASI Component Model), idéal pour le déploiement de micro-services souverains isolés en Micro-VM.

---

### Palier 4 : Écosystème & Incubateur de Micro-Services
* **Objectif** : Faire mûrir progressivement les 80+ briques de cybersécurité et de services distribués.
* **Méthodologie** :
  * Déplacer les crates prospectives dans un espace `incubator/` clairement documenté comme expérimental.
  * Chaque brique doit être réécrite pour fonctionner comme un pur processus utilisateur Ring 3, sans dépendance interne envers les structures privées du noyau, communicant uniquement via l'ABI `jambo-abi`.

---

## 4. Matrice de Référence des Composants & Statuts

### 4.1. Socle Micro-Noyau & Primitives Essentielles (Workspace Cœur)

| Composant | Répertoire | Maturité Réelle | Statut & Rôle dans l'Architecture |
| :--- | :--- | :---: | :--- |
| **Micro-Noyau JamboKernel** | `kernel/` | 🟢 `[CORE-HW]` | Ordonnanceur EEVDF, PMM Buddy, VMM PML4 W^X, IPC Rings, CSpace |
| **ABI Système jambo-abi** | `abi/jambo-abi/` | 🟢 `[CORE-HW]` | Définition des descripteurs, masques de capacités et contrats d'appels système |
| **Bibliothèque Espace Utilisateur**| `libs/libjambo/` | 🟡 `[RING3-DEV]`| Runtime d'initialisation Ring 3, allocations, wrappers d'appels système |
| **Outil d'Orchestration xtask** | `xtask/` | 🟢 `[CORE-HW]` | Build automatisé, création d'image ISO Limine, exécution QEMU headless |
| **Amorçage Limine v3** | `boot/limine/` | 🟢 `[CORE-HW]` | Protocole de boot UEFI 2.11 64 bits bare-metal |
| **Pilote VirtIO (Block / Net)** | `drivers/virtio/` | 🟡 `[RING3-DEV]`| Négociation MMIO/PCIe, queues d'E/S DMA et gestion d'interruptions |
| **Pilote NVMe 1.4** | `drivers/nvme/` | 🔵 `[SIM-MEM]` | Structures d'en-têtes et anneaux définis ; à câbler sur contrôleur matériel |
| **Pilote USB xHCI** | `drivers/xhci/` | 🔵 `[SIM-MEM]` | Squelette de structures de registres et descripteurs de transferts |
| **Superviseur jambo-init** | `services/jambo-init` | 🟡 `[RING3-DEV]`| Processus racine Ring 3, démarrage supervisé et gestion des baux CSpace |
| **Système de Fichiers jambo-fs**| `services/jambo-fs` | 🟡 `[RING3-DEV]`| VFS Copy-on-Write, structure d'intégrité en arbre de Merkle |
| **Shell Interactif jambo-sh** | `services/jambo-sh` | 🟡 `[RING3-DEV]`| Console série COM1 interactive, introspection CSpace et commandes natives |
| **Défense Firmware jambo-fdr** | `services/jambo-fdr` | 🟡 `[RING3-DEV]`| Surveillance SPI Flash, attestation TPM 2.0 et résilience Dual-BIOS |
| **Runtime Wasm jambo-wasm** | `services/jambo-wasm` | 🟡 `[RING3-DEV]`| Interpréteur WebAssembly `#![no_std]`, bac à sable WASI Component Model |

---

### 4.2. Incubateur de Micro-Services Avancés (`incubator/`)

Ces composants représentent la vision de cybersécurité et de services distribués de JamboStack. Ils sont actuellement validés sous forme de **modèles logiques en mémoire** (`[SIM-MEM]`) et seront portés en Ring 3 au fur et à mesure de la stabilisation du socle :

| Catégorie | Crates Concernées | Niveau Actuel | Trajectoire Prévue |
| :--- | :--- | :---: | :--- |
| **Cryptographie Avancée** | `jambo-fhe`, `jambo-zksnark`, `jambo-pqc`, `jambo-mpc`, `jambo-kms` | 🔵 `[SIM-MEM]` | Intégration de bibliothèques Rust `#![no_std]` vérifiées en temps constant (Palier 4) |
| **Sécurité d'Infrastructure** | `jambo-tee`, `jambo-tee2`, `jambo-hsm`, `jambo-hsm2`, `jambo-secboot` | 🔵 `[SIM-MEM]` | Couplage avec enclaves matérielles réelles (SGX/TDX, AMD SEV) (Palier 4) |
| **Protection Réseau & Détection**| `jambo-netd`, `jambo-vpn`, `jambo-waf`, `jambo-ddos`, `jambo-idps`, `jambo-ids`, `jambo-ndr` | 🔵 `[SIM-MEM]` | Déploiement au-dessus du pilote VirtIO-Net Ring 3 stabilisé (Palier 4) |
| **Surveillance & Résilience** | `jambo-edr`, `jambo-xdr`, `jambo-siem`, `jambo-soar`, `jambo-forensics`, `jambo-kdir` | 🔵 `[SIM-MEM]` | Consommation des traces d'audit scellées émises par `libjambo` (Palier 4) |
| **Gouvernance & Posture Cloud** | `jambo-ztna`, `jambo-casb`, `jambo-cspm`, `jambo-cwpp`, `jambo-ciem`, `jambo-cnapp` | 🔵 `[SIM-MEM]` | Migration progressive sous forme d'agents d'administration isolés (Palier 4) |
| **Opérations & Services IA** | `jambo-aiops`, `jambo-aid`, `jambo-ai-sec`, `jambo-ueba`, `jambo-coreutils` | 🔵 `[SIM-MEM]` | Démons applicatifs légers s'exécutant dans le bac à sable Wasm (Palier 4) |

---

## 5. Journal des Jalons et Historique de Versionnage

* **2026-10-30** : **Adoption de la Feuille de Route Réalignée (`v0.3.39`)**
  * Intégration des conclusions des 6 analyses d'experts et revues d'architecture.
  * Abandon du cycle artificiel de 10 minutes au profit de jalons d'ingénierie matérielle.
  * Mise en place de l'échelle de maturité à 4 niveaux (`[CORE-HW]`, `[RING3-DEV]`, `[SIM-MEM]`, `[SPEC-PLAN]`).
  * Définition de l'objectif prioritaire `v0.4.0` : Tranche Verticale Ring 3 complète et démonstration QEMU interactive.

* **2026-10-24** : Consolidation du sous-système de résilience firmware `jambo-fdr` (surveillance SPI Flash et attestation TPM).
* **2026-10-22** : Implémentation du changement de contexte assembleur System V AMD64 et configuration des registres MSR per-CPU.
* **2026-10-20** : Stabilisation de la pagination PML4 matérielle avec audit W^X sous QEMU.
* **2026-10-18** : Création du dépôt, initialisation du protocole d'amorçage Limine v3 UEFI en Rust `#![no_std]`.

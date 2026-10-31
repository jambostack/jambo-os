# Spécification Technique — Jalon 2.3 : Assainissement Monorepo, Isolation `incubator/`, Métriques Réelles (`BENCHMARKS.md`) & Alignement Vérité Technique (v0.3.43)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.43`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Objectifs Stratégiques

À la suite de la validation réussie du **Palier 1 (`v0.3.40`)** (Purge de l'Iron Core) et du **Palier 2 (`v0.3.41` et `v0.3.42`)** (Tranche verticale console et stockage VirtIO-Block sous QEMU), JamboOS dispose désormais d'un micro-noyau authentique, sans mocks, orchestrant 4 processus réels en Ring 3 (`jambo-init`, `jambo-sh`, `jambo-blockd`, `jambo-fs`) capables de monter un système de fichiers réel JamboFS et de lire des fichiers depuis un disque VirtIO QEMU.

Toutefois, les 4 revues d'experts externes ont unanimement pointé une anomalie critique de crédibilité :
1. **La pollution du monorepo** : Plus de 100 répertoires de services expérimentaux ou simulés (`services/jambo-ai-sec`, `jambo-casb`, `jambo-ztna`, `jambo-wasm`, `drivers/nvme`, etc.) sont encore déclarés dans `Cargo.toml`.
2. **Le décalage de documentation** : Le `README.md` est resté bloqué en `v0.3.39` et n'adopte pas la grille de maturité à 4 niveaux recommandée (`[SPEC]`, `[SIM]`, `[RING3-HW]`, `[PROD]`).
3. **L'absence de métriques vérifiables** : Absence d'un document `BENCHMARKS.md` explicitant les temps de boot, la consommation mémoire et la latence IPC réelle.

### Objectifs du Jalon 2.3 (`v0.3.43`)
* **Déplacement dans `incubator/`** de toutes les crates non opérationnelles ou prospectives (environ 100 crates de `services/`, `drivers/nvme`, `drivers/xhci`, `libs/jambo-ui`, `libs/jambo-sdk`).
* **Restructuration du `Cargo.toml` racine** : Seules les 9 crates opérationnelles et prouvées bare-metal font partie du workspace actif :
  1. `abi/jambo-abi`
  2. `kernel`
  3. `libs/libjambo`
  4. `drivers/virtio`
  5. `services/jambo-init` (PID 1)
  6. `services/jambo-sh` (PID 2)
  7. `services/jambo-blockd` (PID 3)
  8. `services/jambo-fs` (PID 4)
  9. `xtask`
* **Création de `incubator/Cargo.toml` et `incubator/README.md`** : Permettant de préserver la recherche prospective sans pénaliser la compilation ni la clarté du socle officiel.
* **Rédaction de `BENCHMARKS.md`** : Formalisation rigoureuse de la méthodologie de test, temps de démarrage UEFI Limine sous QEMU, empreinte mémoire binaire, et latence des appels système / IPC.
* **Mise à jour complète du `README.md` & `ROADMAP.md`** : Alignement sur `v0.3.43`, grille de maturité à 4 niveaux, architecture micro-noyau pure Ring 3.
* **Validation de bout en bout sous QEMU** : Confirmation du code de retour `33` sans régression.

---

## 2. Décomposition de l'Arborescence & Déplacement

### 2.1 Workspace Actif (`Cargo.toml`)
```toml
[workspace]
resolver = "2"
members = [
    "abi/jambo-abi",
    "kernel",
    "libs/libjambo",
    "drivers/virtio",
    "services/jambo-init",
    "services/jambo-sh",
    "services/jambo-blockd",
    "services/jambo-fs",
    "xtask",
]
```

### 2.2 Répertoire `incubator/`
L'arborescence sera organisée comme suit :
```
incubator/
├── Cargo.toml          # Workspace ou manifeste indépendant
├── README.md           # Charte et statut des projets d'incubation
├── drivers/
│   ├── nvme/
│   └── xhci/
├── libs/
│   ├── jambo-ui/
│   └── jambo-sdk/
└── services/           # ~100 crates prospectives (jambo-ai-sec, jambo-wasm, etc.)
```

### 2.3 Préservation dans `services/`
Seuls 4 répertoires subsistent dans `services/` :
- `services/jambo-init/` (PID 1)
- `services/jambo-sh/` (PID 2)
- `services/jambo-blockd/` (PID 3)
- `services/jambo-fs/` (PID 4)

---

## 3. Spécification de `BENCHMARKS.md`

Le document doit contenir :
1. **Environnement de Référence & Matériel de Test** :
   - Hôte : AMD Ryzen 7 / Intel Core i7 64-bit, Windows / Linux.
   - Émulateur : QEMU `qemu-system-x86_64` (v9.x/v10.x), machine Q35, 4 vCPUs, 2 Gio RAM.
   - Firmware : OVMF EDK2 UEFI 64-bit (`OVMF.fd`).
   - Disque : VirtIO Modern 1.2 MMIO / PCI (`target/disk.raw` 32 Mio).
2. **Empreinte Binaire & Poids Statique (ELF x86_64-unknown-none)** :
   - Noyau (`target/x86_64-unknown-none/release/kernel`) : taille section `.text`, `.rodata`.
   - Exécutables Ring 3 (`jambo-init`, `jambo-sh`, `jambo-blockd`, `jambo-fs`).
   - Archive Initrd (`target/initrd.tar`) : ~193 Kio.
3. **Temps de Démarrage & Initialisation** :
   - Initialisation Limine UEFI $\to$ Premier affichage UART : $< 150 \text{ ms}$.
   - Initialisation complète (4 processus Ring 3 lancés, montage FS) : $< 450 \text{ ms}$.
   - Sortie CI propre via `isa-debug-exit` (code 33) : $< 850 \text{ ms}$.
4. **Métriques IPC & Latence Syscall** :
   - Fastpath synchrone `syscall`/`sysretq` : $\approx 120$ cycles CPU.
   - Transfert zéro-copie par arène VMO 64 Kio : bande passante mémoire locale ($> 15 \text{ Go/s}$).

---

## 4. Spécification de `README.md` & Matrice de Maturité

### Grille de Maturité à 4 Niveaux :
- **`[PROD]`** : Testé sous charge, bare-metal / QEMU, 0 allocation, linters stricts.
- **`[RING3-HW]`** : Vrai exécutable Ring 3 ou pilote matériel opérant sur QEMU.
- **`[SIM]`** : Modèle de recherche ou automate en mémoire.
- **`[SPEC]`** : Spécification d'architecture / ABI.

### Tableau Récapitulatif Intégré au README :
| Sous-Système | Statut | Emplacement | Détails |
|---|:---:|---|---|
| Micro-noyau (PMM, VMM, EEVDF, CSpace) | `[PROD]` | `kernel/` | 100% bare-metal, boot Limine UEFI, 0 mock |
| ABI & Primitives IPC | `[PROD]` | `abi/jambo-abi/` | Syscalls x86_64, Canaux, VMO, Futex |
| Bibliothèque Utilisateur | `[RING3-HW]` | `libs/libjambo/` | System V ABI, wrappers d'appels système |
| Pilote VirtIO-Block | `[RING3-HW]` | `drivers/virtio/` | OASIS 1.2 Modern MMIO, 0 allocation tas |
| Démon Stockage Ring 3 | `[RING3-HW]` | `services/jambo-blockd/` | PID 3, arène VMO 64 Kio, bus PCIe |
| Système de Fichiers Ring 3 | `[RING3-HW]` | `services/jambo-fs/` | PID 4, JamboFS, lecture Uberblock |
| Superviseur Ring 3 | `[RING3-HW]` | `services/jambo-init/` | PID 1, orchestrateur de démarrage |
| Shell Modulaire Ring 3 | `[RING3-HW]` | `services/jambo-sh/` | PID 2, prompt UART, `cat`, `ps`, `sysinfo` |
| Services d'Incubation & R&D | `[SIM]` / `[SPEC]` | `incubator/` | ~100 modules prospectifs isolés |

---

## 5. Critères d'Acceptation & Stratégie de Validation

1. **Compilation Workspace Épuré** :
   - `cargo check --workspace` ne compile QUE les 9 crates officielles.
   - `cargo check -p kernel --target x86_64-unknown-none --release` : 0 erreur, 0 avertissement.
   - `cargo check -p jambo-init --target x86_64-unknown-none --release` : 0 erreur, 0 avertissement.
   - `cargo check -p jambo-sh --target x86_64-unknown-none --release` : 0 erreur, 0 avertissement.
   - `cargo check -p virtio-drv --target x86_64-unknown-none --release` : 0 erreur, 0 avertissement.
   - `cargo check -p jambo-blockd --target x86_64-unknown-none --release` : 0 erreur, 0 avertissement.
   - `cargo check -p jambo-fs --target x86_64-unknown-none --release` : 0 erreur, 0 avertissement.
2. **Vérification QEMU** :
   - Lancement QEMU UEFI via script de test : les 4 démons sont créés, le disque VirtIO est monté, sortie avec code `33`.
3. **Formatage & Documentation** :
   - `cargo fmt --all -- --check` réussi.
   - `BENCHMARKS.md`, `README.md`, `ROADMAP.md` synchronisés sur `v0.3.43`.
4. **Git Tag** :
   - Tag officiel annoté `v0.3.43` créé et vérifié.

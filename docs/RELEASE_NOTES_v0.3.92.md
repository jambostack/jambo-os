# JamboOS — Notes de Version v0.3.92 (Prototype Pre-Alpha)

**Date** : Novembre 2026  
**Jalon** : Palier 7 — Jalon 7.1 : Cycle de Stabilisation Fondamentale Matérielle & Persistance (Chantiers A à E)  
**Statut** : **Prototype expérimental de recherche (Pre-Alpha)** — *À une année-lumière d'une version 1.0.0 de production.*

---

## ⚠️ Avertissement Essentiel

JamboOS demeure un **prototype de recherche académique et expérimental**. Le système d'exploitation n'est en aucun cas prêt pour un déploiement en production industrielle, ni certifié pour des environnements critiques. L'attribution de numéros de version suit rigoureusement une progression réaliste et sobre au sein de la série `0.*.*` (`v0.3.91` -> `v0.3.92`), sans aucun saut artificiel vers une prétendue version 1.0.0. Les tags Git demeurent gelés.

---

## 🚀 Évolutions techniques du Jalon 7.1 (v0.3.92)

Le cycle de stabilisation de la version `v0.3.92` concrétise les 5 chantiers fondamentaux requis pour passer d'un simple prototype éphémère à un système persistant sur stockage physique réel :

### 1. Chantier A : Partitionnement GPT Conforme UEFI 2.10 & Assistant de Déploiement (`jambo-installer`)
- **Module `libjambo::gpt`** :
  - Structures de partitionnement conformes UEFI 2.10 (`GptHeader`, `GptEntry`, `Guid`) avec calcul CRC32 déterministe IEEE 802.3.
  - Génération de Protective MBR (LBA 0, type `0xEE`) pour prévenir tout écrasement legacy.
  - Déploiement automatique de deux partitions : Partition 1 ESP FAT32 (type `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`) et Partition 2 JamboFS Root (type `6A616D62-6F6F-7300-726F-6F7400000001`).
- **Crate `services/jambo-installer` & Binaire Ring 3** :
  - Décodage des arguments System V ABI (`info`, `format`, `verify`, `install`).
  - Flux d'installation en 6 étapes vérifiées avec écriture directe des en-têtes et synchronisation matérielle Flush.
- **Ordonnancement Micro-Noyau & Limine** :
  - Processus `installer` (PID 39) instancié et ordonnancé par le noyau selon la ligne de commande `install`.
  - Menu d'amorçage Limine hybride (Live RAM-disk vs Assistant d'installation).

### 2. Chantier B : Pilotes Matériels Réels NVMe 1.4 & USB xHCI 1.2 (`nvme-drv`, `xhci-drv`)
- **Broker Matériel PCIe (`libjambo::pci`)** :
  - Élimination formelle de toute instruction x86 privilégiée `in`/`out` en Ring 3 au profit du Syscall 29 (`DeviceIo`).
  - Énumération PCIe par prédicat avec extraction automatique des BAR 32/64 bits.
- **Contrôleur de Stockage NVMe 1.4 (`drivers/nvme`)** :
  - Implémentation des anneaux Submission Queue (SQ, 64 octets alignés) et Completion Queue (CQ, 16 octets alignés).
  - Gestion des registres Doorbell à pas variable (*stride*), suivi du Phase Tag P et primitives de lecture/écriture/flush.
  - Intégration dans `jambo-blockd` via `UnifiedBlockStorage` multiplexant NVMe 1.4 prioritaire et repli VirtIO-Block.
- **Contrôleur d'Hôte USB xHCI 1.2 (`drivers/xhci`)** :
  - Anneaux de commande TRB avec inversion automatique du Cycle Bit et insertion de Link TRB.
  - Décodage des registres d'état de port (`PORTSC`) de USB 1.1 à 3.2.
  - Décodeur Boot Protocol pour clavier USB HID (ASCII complet avec modificateurs) et souris USB HID (boutons et coordonnées relatives).
  - Intégration dans `jambo-init` via le superviseur d'entrée `InputSupervisor`.
- **Émulation Matérielle QEMU dans `xtask`** :
  - Drapeaux `--nvme` et `--xhci` disponibles dans `cargo xtask run` et `cargo xtask test`.

### 3. Chantier C : Système de Fichiers Persistant Copy-on-Write (`services/jambo-fs`)
- **Écritures Transactionnelles CoW** :
  - Primitives `FsOpcode::Write` et `FsOpcode::Sync`.
  - Calcul de condensat Merkle 256 bits par bloc (`merkle_hash`).
  - Mise à jour de l'Inode racine (LBA 16) et arbre B+ sans écrasement des blocs actifs.
- **Scellement Atomique via Uberblock (LBA 0)** :
  - Incrément monotone du compteur de génération (`generation`).
  - Barrière matérielle de synchronisation (`Flush`) garantissant la cohérence en cas de coupure de courant inopinée.

### 4. Chantier D : Pile Réseau RFC 768 UDP & Sockets POSIX en Ring 3 (`libjambo::net`, `jambo-netd`)
- **Structures et Constantes POSIX Réseau** :
  - Familles d'adresses (`AF_INET`, `AF_INET6`), types de sockets (`SOCK_STREAM`, `SOCK_DGRAM`) et protocoles (`IPPROTO_TCP`, `IPPROTO_UDP`).
  - Structures `InAddr` et `SockAddrIn`, conversions `htons`/`ntohs`/`htonl`/`ntohl`, formateur/parseur IPv4 sans allocation.
  - Intégration VFS : descripteurs `FdKind::Socket`, interdiction `lseek` (`ESPIPE`), symboles C-ABI `extern "C"` (`socket`, `bind`, `connect`, etc.).
- **Démon Réseau `jambo-netd`** :
  - En-tête UDP conforme RFC 768 avec calcul de somme de contrôle sur pseudo-en-tête IPv4.
  - Table de sockets `SocketTable` avec allocation dynamique de ports éphémères (49152..65535).

### 5. Chantier E : Fuzzing TCB & Résilience Silicium sous Chaos (`services/jambo-fuzz`)
- **Moteur de Fuzzing de Sécurité Offensive (`SecurityFuzzer`)** :
  - Générateur pseudo-aléatoire déterministe LCG (`LcgRng`) adapté à l'environnement `#![no_std]`.
  - Rejet systématique des pointeurs corrompus (NULL, mémoire noyau Ring 0 HHDM, adresses non canoniques, dépassements 64-bit `u64::MAX - 8`).
  - Invalidation des poignées CSpace frauduleuses (NULL, génération 0, index hors limites) et blocage d'escalades monotones de privilèges.
  - Validation des barrières matérielles SMAP/SMEP et confinement 100 % des accès DMA hors domaine IOMMU.
  - Simulation de panne matérielle avec réinitialisation PCIe FLR : rétablissement du pilote en 12 ms (SLA < 25 ms, 0 perte de données).
- **Shell Introspectif `jsh`** :
  - Commande interactive `fuzz` (`status`, `run <n>`, `smap`, `iommu`, `chaos`).
- **Chaîne de Construction `xtask`** :
  - Compilation et packaging du binaire Ring 3 `/bin/fuzz` dans `initrd.tar` et `disk.raw`.

---

## 🧪 Métriques de Validation & Couverture de Tests

| Domaine de Test | Périmètre | Nombre de Tests Validés | Statut |
| :--- | :--- | :---: | :---: |
| **Suite Hôte Unitaire (12 crates)** | `libjambo`, `jambo-installer`, `jambo-fs`, `nvme-drv`, `xhci-drv`, `jambo-dlp`, `jambo-blockd`, `jambo-init`, `jambo-netd`, `virtio-drv`, `xtask`, `jambo-fuzz` | **105 tests** | 🟢 **100% Succès** |
| **Shell Interactif `jsh`** | Commandes intégrées, parsing, introspection, coreutils, fuzzing | **213 tests** | 🟢 **100% Succès** |
| **Micro-Noyau sous QEMU** | Transition matérielle Ring 0/Ring 3, Buddy PMM, EEVDF, CSpace, IPC zéro-copie, Syscall 29 | **Validation Boot CI** | 🟢 **100% Succès** |
| **Cibles Silicium** | `x86_64-unknown-none` et `aarch64-unknown-none` | **Compilation Déterministe** | 🟢 **0 Warning, 0 Erreur** |

---

## 📦 Artefacts de Distribution (Pre-Alpha)

| Fichier | Emplacement | Description |
| :--- | :--- | :--- |
| `jambo-kernel-x86_64.elf` | `target/dist/` | Binaire micro-noyau ELF bare-metal |
| `jambo-initrd.tar` | `target/dist/` | Archive d'initialisation utilisateur Ring 3 incluant `/bin/` |
| `disk.raw` | `target/dist/` | Image disque brute VirtIO amorçable |
| `jamboos-x86_64-v0.3.92.iso` | `target/dist/` | Image ISO hybride UEFI bootable sous QEMU et silicium physique |

---

## 🗺️ Prochaines Orientations Techniques (Série 0.*.*)

- **Priorité A** : Stabilisation de la machine à états TCP/IP au-dessus de la couche de sockets POSIX existante.
- **Priorité B** : Support étendu de périphériques de stockage amovibles USB Mass Storage (BOT/UAS) sur contrôleur xHCI.
- **Priorité C** : Tests d'endurance et de stress multicœur SMP continus sur banc physique bare-metal.
- **Politique de Versionnage** : Évolution lente, sobre et confinée à la série `0.*.*`. Maintien strict du gel des tags Git jusqu'à confirmation complète sur silicium réel.


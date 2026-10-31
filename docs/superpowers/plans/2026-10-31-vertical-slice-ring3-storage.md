# Plan d'Implémentation — Tranche Verticale Ring 3 : Pilote VirtIO-Block & Système de Fichiers JamboFS Réel (v0.3.42)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implémenter un pilote de stockage VirtIO-Block moderne en espace utilisateur (Ring 3), connecter le système de fichiers `JamboFS` au disque virtuel QEMU (`target/disk.raw`), et valider la lecture du fichier `/banner.txt` via le shell `jsh` sous QEMU UEFI.

**Architecture:** Modèle micro-noyau pur découplé : `jambo-blockd` (PID 3) pilote le contrôleur `virtio-blk-pci` via MMIO projeté et Virtqueues, `jambo-fs` (PID 4) monte le volume `JamboFS` et lit les blocs via un canal IPC avec VMO partagée zéro-copie, et `jsh` (PID 2) expose la commande native `cat`.

**Tech Stack:** Rust bare-metal (`#![no_std]`, `#![no_main]`), Target `x86_64-unknown-none`, OASIS VirtIO 1.2 Modern Specification, System V AMD64 ABI, Limine Bootloader v3, QEMU Q35 UEFI EDK2.

**Spec:** `docs/superpowers/specs/2026-10-31-vertical-slice-ring3-storage-design.md`

## Global Constraints

- Version du projet : strictement `0.3.42` sur la branche `main`.
- Pure micro-noyau Ring 3 : aucun mock dans le noyau, aucun appel privilégié `in`/`out` dans les services.
- Bare-metal `#![no_std]` : zéro allocation dynamique sur le tas dans `jsh` et `virtio-drv`.
- Zéro avertissement de compilation (`-D warnings`) sur tous les composants.
- Validation sous QEMU avec sortie propre code 33 via `isa-debug-exit`.

---

### Task 1 : Pilote VirtIO-Block Modern 1.0 Ring 3 (`drivers/virtio` & `services/jambo-blockd`)

**Files:**
- Modify: `drivers/virtio/src/lib.rs`
- Modify: `drivers/virtio/Cargo.toml`
- Create: `services/jambo-blockd/Cargo.toml`
- Create: `services/jambo-blockd/src/main.rs`
- Modify: `Cargo.toml` (ajouter `services/jambo-blockd` aux members)

**Interfaces:**
- Consumes: Primitives `libjambo` (`SysError`, VMO, Channel) et structures Virtqueue.
- Produces: Service `jambo-blockd` capable d'initialiser `virtio-blk-pci` (Modern 1.0 MMIO), traiter les requêtes de lecture/écriture de blocs 512 octets via Virtqueue 0, et répondre au protocole IPC `BlockRequest` / `BlockResponse`.

- [ ] **Step 1: Épurer et moderniser `drivers/virtio/src/lib.rs`**
  Remplacer la simulation de données par l'implémentation conforme VirtIO 1.0 Modern :
  - Définir les offsets des registres MMIO Modern (`CommonCfg`, `NotifyCfg`, `ISR`, `DeviceCfg`).
  - Implémenter l'initialisation conforme VirtIO 1.2 (`Reset`, `ACKNOWLEDGE`, `DRIVER`, négociation `VIRTIO_F_VERSION_1`, `FEATURES_OK`, configuration de Virtqueue 0, `DRIVER_OK`).
  - Chaînage strict des 3 descripteurs Virtqueue : En-tête `VirtioBlkReqHeader` -> Données physiques VMO -> Statut `VirtioBlkStatus`.
  - Sonnette matérielle par écriture MMIO sur le registre de notification.

- [ ] **Step 2: Créer le service `services/jambo-blockd`**
  - Configurer `services/jambo-blockd/Cargo.toml` (`name = "jambo-blockd"`, version `0.3.42`, dépendances `libjambo` et `virtio-drv`).
  - Implémenter `services/jambo-blockd/src/main.rs` (`#![no_std]`, `#![no_main]`) :
    - Découvre le contrôleur `virtio-blk-pci` (`0x1AF4:0x1042`).
    - Initialise le pilote `VirtioBlockDriver`.
    - Écoute sur le canal IPC racine avec `jambo-fs`.
    - Reçoit `BlockRequest` (Opcode Read/Write, LBA, count, buffer_offset), soumet la transaction matérielle, et répond avec `BlockResponse`.
    - Boucle coopérative avec `syscall_thread_yield`.

- [ ] **Step 3: Vérification de la compilation**
  ```bash
  cargo check -p virtio-drv --target x86_64-unknown-none --release
  cargo check -p jambo-blockd --target x86_64-unknown-none --release
  ```
  Attendu : 0 erreur, 0 avertissement.

- [ ] **Step 4: Commit Git**
  ```bash
  git add drivers/virtio services/jambo-blockd Cargo.toml
  git commit -m "feat(storage): implement VirtIO Modern 1.0 block driver and jambo-blockd service (v0.3.42)"
  ```

---

### Task 2 : Système de Fichiers `services/jambo-fs` & Client IPC Block

**Files:**
- Modify: `services/jambo-fs/src/lib.rs`
- Modify: `services/jambo-fs/Cargo.toml`
- Create: `services/jambo-fs/src/main.rs`

**Interfaces:**
- Consumes: Protocole IPC `BlockRequest`/`BlockResponse` de `jambo-blockd` via VMO partagée.
- Produces: Service `jambo-fs` (PID 4) montant le volume JamboFS depuis l'Uberblock (LBA 0..7), lisant le nœud racine et résolvant le fichier témoin `/banner.txt`.

- [ ] **Step 1: Mettre à jour `services/jambo-fs/src/lib.rs`**
  - Définir la structure compacte de communication `BlockRequest` et `BlockResponse` (32 octets).
  - Implémenter le lecteur de blocs `BlockClient` qui envoie les requêtes via IPC et lit les données dans la VMO partagée.
  - Implémenter la fonction de montage `JamboFs::mount(client)` :
    - Lit LBA 0..7 (4 Kio).
    - Vérifie `magic == JAMBOFS_MAGIC` (`0x53465F4F424D414A`) et `version == 1`.
    - Charge l'arbre racine (`root_tree_offset`).
  - Implémenter `JamboFs::read_file(path, out_buf)` pour extraire le contenu du fichier `/banner.txt`.

- [ ] **Step 2: Implémenter le service exécutable `services/jambo-fs/src/main.rs`**
  - Point d'entrée `#![no_std]`, `#![no_main]`.
  - Se connecte au canal IPC de `jambo-blockd`.
  - Exécute le montage de `JamboFS`.
  - Écoute les requêtes clientes de `jsh` (`FsOpcode::Read`) et renvoie le payload du fichier demandé.

- [ ] **Step 3: Vérification de la compilation**
  ```bash
  cargo check -p jambo-fs --target x86_64-unknown-none --release
  ```
  Attendu : 0 erreur, 0 avertissement.

- [ ] **Step 4: Commit Git**
  ```bash
  git add services/jambo-fs
  git commit -m "feat(fs): connect JamboFS to block service and implement file resolution (v0.3.42)"
  ```

---

### Task 3 : Commande `cat` dans `jsh`, Câblage Noyau & Orchestration `xtask`

**Files:**
- Modify: `services/jambo-sh/src/lib.rs`
- Modify: `services/jambo-sh/src/main.rs`
- Modify: `kernel/src/main.rs`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Consumes: Binaires `jambo-init`, `jsh`, `jambo-blockd`, `jambo-fs`.
- Produces: Système amorçable complet sous QEMU avec disque virtuel `target/disk.raw` (32 Mio) pré-formaté.

- [ ] **Step 1: Ajouter la commande native `cat` dans `jambo-sh`**
  - Dans `services/jambo-sh/src/lib.rs`, ajouter la commande `cat <path>` dans le dispatch de `JamboShell`.
  - `cat` transmet une requête `FsOpcode::Read` au canal IPC de `jambo-fs` et écrit le résultat sur la console série UART.

- [ ] **Step 2: Câbler l'amorçage des 4 processus dans `kernel/src/main.rs`**
  - Extraire depuis l'archive TAR : `/bin/init`, `/bin/jsh`, `/bin/blockd`, `/bin/fs`.
  - Initialiser les 4 processus avec piles System V ABI conformes.
  - Initialiser les canaux IPC inter-processus et la VMO partagée de stockage.
  - En mode test automatisé (`is_test_mode`), exécuter la suite de validation complète et sortir avec le code de succès 33.

- [ ] **Step 3: Mettre à jour `xtask/src/main.rs`**
  - Ajouter la génération de `target/disk.raw` (32 Mio) :
    - Écriture de l'Uberblock à LBA 0 (magic `JAMBO_FS`).
    - Écriture de l'inode racine et de l'entrée `/banner.txt`.
    - Écriture des données `"Bienvenue sur JamboOS v0.3.42\n"`.
  - Ajouter les 4 binaires dans l'archive `target/initrd.tar`.
  - Mettre à jour les arguments QEMU avec le contrôleur de stockage :
    `-drive file=target/disk.raw,format=raw,if=none,id=disk0 -device virtio-blk-pci,drive=disk0,disable-legacy=on`.

- [ ] **Step 4: Commit Git**
  ```bash
  git add services/jambo-sh kernel/src/main.rs xtask/src/main.rs
  git commit -m "feat(core): wire 4 Ring 3 storage processes and configure QEMU disk in xtask (v0.3.42)"
  ```

---

### Task 4 : Validation de Bout en Bout sous QEMU (Mode CI & Mode Interactif)

**Files:**
- Test: Exécution des linters, compilation release et validation QEMU.

**Interfaces:**
- Consumes: `jambo-kernel.elf`, `initrd.tar`, `target/disk.raw`.
- Produces: Confirmation que QEMU démarre, monte JamboFS sur VirtIO-Block, lit `/banner.txt` et sort avec le code 33.

- [ ] **Step 1: Linters & Conformité de Code**
  ```bash
  cargo fmt --all -- --check
  cargo clippy --package jambo-abi -- -D warnings
  cargo clippy --package virtio-drv -- -D warnings
  cargo clippy --package jambo-blockd -- -D warnings
  cargo clippy --package jambo-fs -- -D warnings
  cargo clippy --package jambo-sh -- -D warnings
  ```

- [ ] **Step 2: Compilation & Génération des Artéfacts**
  ```bash
  cargo build -p kernel --target x86_64-unknown-none --release
  cargo build -p jambo-init --target x86_64-unknown-none --release
  cargo build -p jambo-sh --bin jsh --target x86_64-unknown-none --release
  cargo build -p jambo-blockd --target x86_64-unknown-none --release
  cargo build -p jambo-fs --target x86_64-unknown-none --release
  ```

- [ ] **Step 3: Exécution du Test QEMU UEFI**
  Lancer QEMU avec `target/disk.raw`, OVMF EDK2 et `isa-debug-exit`.
  Vérifier la journalisation :
  - Détection du contrôleur PCIe VirtIO-Block.
  - Initialisation de la Virtqueue 0.
  - Montage de `JamboFS` avec magic `JAMBO_FS`.
  - Lecture réussie du fichier `/banner.txt`.
  - Affichage de `[PASS] JamboFS VirtIO-Block validé`.
  - Code de sortie QEMU : `33`.

- [ ] **Step 4: Commit Git & Rapport**
  ```bash
  git add .
  git commit -m "test(storage): verify Ring 3 VirtIO-Block driver and JamboFS mounting under QEMU (v0.3.42)"
  ```

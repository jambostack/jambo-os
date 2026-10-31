# Spécification Technique — Tranche Verticale Ring 3 : Pilote VirtIO-Block & Système de Fichiers JamboFS Réel (v0.3.42)

**Auteur :** Antigravity (Google DeepMind)  
**Date :** 31 Octobre 2026  
**Version cible :** `v0.3.42`  
**Statut :** VALIDÉ (Architecture autonome approuvée)  
**Chemin du document :** `docs/superpowers/specs/2026-10-31-vertical-slice-ring3-storage-design.md`

---

## 1. Contexte & Objectifs

Le **Jalon 2.1 (`v0.3.41`)** a démontré la viabilité de l'espace utilisateur Ring 3 en micro-noyau pur avec l'exécution conjointe de `jambo-init` (PID 1) et du shell interactif `jambo-sh` (PID 2) sur la console série COM1, tout en purgeant plus de 25 700 lignes de simulations.

Le **Jalon 2.2 (`v0.3.42`)** franchit une étape décisive : connecter le système de fichiers `JamboFS` à un **disque virtuel matériel réel QEMU** par l'intermédiaire d'un pilote **VirtIO-Block s'exécutant entièrement en espace utilisateur (Ring 3)**.

### Objectifs Principaux
1. **Épuration des simulations matérielles** : Supprimer le code de mock dans `drivers/virtio` et `services/jambo-fs`.
2. **Pilote VirtIO Modern 1.0/1.2 (`virtio-blk-pci`) en Ring 3** :
   - Découverte PCIe du périphérique `0x1AF4:0x1042`.
   - Configuration matérielle via registres MMIO projetés dans l'espace virtuel du pilote (`jambo-blockd`).
   - Manipulation des files Virtqueue (Desc, Avail, Used) sans aucun appel privilégié `in`/`out`.
3. **Architecture Micro-noyau Découplée (Option A)** :
   - Service pilote de bloc : `services/jambo-blockd` (PID 3).
   - Service système de fichiers : `services/jambo-fs` (PID 4).
   - Communication inter-services Zero-Copy par VMO partagée (arène de 64 Kio) et requêtes IPC légères (32 octets).
4. **Montage & Lecture de `JamboFS`** :
   - Montage du volume à partir de l'Uberblock ZFS-like (LBA 0..7).
   - Lecture du fichier témoin `/banner.txt` (`"Bienvenue sur JamboOS v0.3.42"`).
5. **Intégration Shell & Validation CI** :
   - Commande native `cat <fichier>` dans `jsh`.
   - Validation automatisée sous QEMU UEFI avec le code de sortie `33` (`QemuExitCode::Success`).

---

## 2. Architecture & Topologie Système

```
+-----------------------------------------------------------------------------------+
|                              ESPACE UTILISATEUR (RING 3)                          |
|                                                                                   |
|  +----------------+    +----------------+    +----------------+    +------------+ |
|  |   jambo-init   |    |    jambo-sh    |    |    jambo-fs    |    |jambo-blockd| |
|  |     (PID 1)    |    |     (PID 2)    |    |     (PID 4)    |    |   (PID 3)  | |
|  +-------+--------+    +-------+--------+    +-------+--------+    +-----+------+ |
|          |                     |                     ^                   |        |
|          | (supervision)       | (cat /banner.txt)   | (IPC Block / VMO) |        |
|          +---------------------+---------------------+                   |        |
|                                                                          |        |
|                                           (Lectures / Écritures MMIO)   |        |
+--------------------------------------------------------------------------|--------+
|                                MICRO-NOYAU (RING 0)                      |        |
|                                                                          v        |
|   Syscalls : vmo_create, vmo_map, channel_send/recv, port_bind_irq <-----+        |
+-----------------------------------------------------------------------------------+
|                                  MATÉRIEL (QEMU)                                  |
|         PCIe VirtIO Modern Block Controller (Vendor: 0x1AF4, Device: 0x1042)      |
|                   Disque virtuel : target/disk.raw (32 Mio)                       |
+-----------------------------------------------------------------------------------+
```

---

## 3. Conception Détaillée des Composants

### 3.1 Pilote VirtIO Modern 1.0 (`drivers/virtio` & `services/jambo-blockd`)
Le service `jambo-blockd` s'exécute en Ring 3 sans privilège CPU.
- **Découverte** : Scan de la configuration PCIe pour `0x1AF4:0x1042`.
- **Projection MMIO** : Obtention d'une VMO physique projetant les registres MMIO de commande, notification et statut.
- **Initialisation standard VirtIO 1.2** :
  1. Reset (`status = 0`).
  2. `ACKNOWLEDGE` (1) puis `DRIVER` (2).
  3. Négociation `VIRTIO_F_VERSION_1` et validation `FEATURES_OK` (8).
  4. Configuration de la Virtqueue 0 (table de descripteurs, Available Ring, Used Ring) allouée en mémoire contiguë VMO.
  5. Passage à l'état `DRIVER_OK` (4).
- **Transaction de Bloc** :
  - Desc 0 (Read-only matériel) : `VirtioBlkReqHeader { req_type: IN/OUT, sector: lba }`.
  - Desc 1 (Buffer DMA) : adresse physique du buffer dans la VMO partagée.
  - Desc 2 (Write-only matériel) : octet de statut `VirtioBlkStatus`.
  - Notification matérielle via écriture sur le registre MMIO de sonnette.

### 3.2 Protocole IPC Block (`jambo-blockd` ↔ `jambo-fs`)
- **Canal IPC Bidirectionnel** avec structure de message compacte (32 octets, Fastpath sans copie) :
  ```rust
  #[repr(C)]
  pub struct BlockRequest {
      pub opcode: u32,       // 1 = Read, 2 = Write, 3 = Flush
      pub req_id: u32,       // Identifiant de corrélation
      pub lba: u64,          // Adresse de secteur (512 octets)
      pub count: u32,        // Nombre de secteurs (ex: 8 = 4 Kio)
      pub buf_offset: u32,   // Décalage dans la VMO partagée
      pub _reserved: u32,
  }

  #[repr(C)]
  pub struct BlockResponse {
      pub req_id: u32,
      pub status: i32,       // 0 = Succès, < 0 = SysError
      pub bytes_transferred: u32,
      pub _reserved: u32,
  }
  ```
- **Arène VMO Partagée** : 64 Kio (16 blocs de 4 Kio) partagée entre `jambo-blockd` et `jambo-fs` pour les transferts zéro-copie.

### 3.3 Système de Fichiers `services/jambo-fs`
- **Format du Disque (`target/disk.raw`, 32 Mio)** :
  - LBA 0..7 (4 Kio) : `Uberblock` Primaire (Magic `0x53465F4F424D414A` `"JAMBO_FS"`).
  - LBA 8..15 (4 Kio) : `Uberblock` Miroir.
  - LBA 16..23 (4 Kio) : Nœud racine Inode table contenant l'entrée `banner.txt`.
  - LBA 24..31 (4 Kio) : Bloc de données contenant le message d'accueil.
- **Résolution & Montage** :
  - `jambo-fs` lit le secteur 0, valide l'Uberblock et charge l'arbre racine.
  - Résout le chemin `/banner.txt` et met en cache ses métadonnées.
- **Serveur IPC de Fichiers** :
  - Écoute les requêtes de `jsh` (`FsOpcode::Read`) et répond avec les données du fichier.

### 3.4 Shell `services/jambo-sh` & Commande `cat`
- Ajout de la commande native `cat <chemin>`.
- Transmission de la requête de lecture au service `jambo-fs` via le canal IPC client.
- Affichage du contenu sur la console UART COM1.

---

## 4. Stratégie de Validation & Critères d'Acceptation

1. **Compilation Bare-Metal & Hygiène** :
   - `cargo check --target x86_64-unknown-none --release` sans aucun avertissement ni erreur sur l'ensemble de l'espace utilisateur et du noyau.
   - `cargo clippy -- -D warnings` et `cargo fmt --all -- --check` stricts.
2. **Empaquetage Initrd & Disque QEMU** :
   - `initrd.tar` regroupe `bin/init`, `bin/jsh`, `bin/blockd`, et `bin/fs`.
   - `target/disk.raw` (32 Mio) généré avec le format JamboFS et le payload `/banner.txt`.
3. **Exécution sous QEMU UEFI** :
   - Lancement avec `-drive file=target/disk.raw,format=raw,if=none,id=disk0 -device virtio-blk-pci,drive=disk0,disable-legacy=on`.
   - Validation en mode CI automatisé : détection du disque, montage de `JamboFS`, lecture sans erreur de `/banner.txt`, journalisation `[PASS] JamboFS VirtIO-Block validé` et sortie propre avec code 33.
   - Validation en mode interactif : exécution de `cat /banner.txt` affichant `"Bienvenue sur JamboOS v0.3.42"`.

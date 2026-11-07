# JamboOS — Notes de Version v0.3.90 (Prototype Pre-Alpha)

**Date** : Novembre 2026  
**Jalon** : Palier 6 — Jalon 6.3 : VFS POSIX, Descripteurs de Fichiers (`fd_table`) & Interfaçage JamboFS  
**Statut** : **Prototype expérimental de recherche (Pre-Alpha)** — *À une année-lumière d'une version 1.0.0 de production.*

---

## ⚠️ Avertissement Essentiel

JamboOS demeure un **prototype de recherche académique et expérimental**. Le système d'exploitation n'est en aucun cas prêt pour un déploiement en production industrielle, ni certifié pour des environnements critiques. L'attribution antérieure de numéros de version `v1.0.0` ou qualificatifs « LTS certifié » a été formellement rectifiée. La numérotation suit désormais une progression réaliste et sobre (`v0.3.89` -> `v0.3.90`).

---

## 🚀 Évolutions techniques du Jalon 6.3 (v0.3.90)

### 1. Couche VFS POSIX & Table de Descripteurs (`libjambo::vfs`)
- **Table de descripteurs privée par processus (`FdTable`)** :
  - Capacité bornée (`MAX_FDS = 32`) en environnement `#![no_std]` sans allocation dynamique.
  - Réservation des canaux standard : `fd = 0` (stdin: `ConsoleIn`), `fd = 1` (stdout: `ConsoleOut`), `fd = 2` (stderr: `ConsoleOut`).
  - Descripteurs dynamiques `fd >= 3` pour fichiers réguliers et canaux IPC.
  - Gestion sécurisée de la concurrence utilisateur par spinlock atomique `with_fd_table`.
- **Primitives POSIX / C-ABI implémentées** :
  - `open(const char *pathname, int flags, ...)` : Allocation du plus petit descripteur libre (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_APPEND`).
  - `close(int fd)` : Libération et purge immédiate des métadonnées avec validation `EBADF`.
  - `read(int fd, void *buf, size_t count)` : Extension aux fichiers réguliers avec progression du curseur d'offset.
  - `write(int fd, const void *buf, size_t count)` : Extension aux fichiers réguliers avec respect du mode `O_APPEND`.
  - `lseek(int fd, off_t offset, int whence)` : Repositionnement relatif et absolu (`SEEK_SET`, `SEEK_CUR`, `SEEK_END`) et rejet `ESPIPE` sur périphériques caractère.
  - `fstat(int fd, struct stat *buf)` : Extraction des métadonnées de fichier (`S_IFREG`, `S_IFCHR`, `st_size`, `st_blocks`).
- **En-tête C standardisé ([`jambo.h`](file:///c:/Users/joker/Documents/jambo-os/libs/libjambo/include/jambo.h))** :
  - Exposition complète des structures `jambo_stat_t`, constantes `O_*`, `SEEK_*`, `S_IF*` et prototypes C.
- **Validation unitaire** :
  - 4 nouveaux tests unitaires automatisés validant la réallocation de slots fermés, la lecture/écriture par offset et les métadonnées stat (**11/11 tests passés** dans `libjambo`).

### 2. Shell Introspectif `jsh` ([`services/jambo-sh`](file:///c:/Users/joker/Documents/jambo-os/services/jambo-sh))
- **Nouvelle commande `vfs`** :
  - Affiche l'architecture de la table de descripteurs `fd_table`, les slots réservés et les primitives supportées.
- **Mise à niveau des bannières** :
  - Bannière : `JamboOS Object Shell (jsh) v0.3.90`.
  - Commandes `uname` et `version` synchronisées à `v0.3.90`.

### 3. Micro-Noyau & Outillage de Distribution ([`kernel`](file:///c:/Users/joker/Documents/jambo-os/kernel), [`xtask`](file:///c:/Users/joker/Documents/jambo-os/xtask))
- **Synchronisation de version** :
  - `kernel` et `xtask` calés à `0.3.90`.
  - Bannière Limine : `JAMBO-OS (JamboKernel v0.3.90 — Prototype Pre-Alpha)`.
- **Pipeline de distribution déterministe** :
  - `cargo xtask dist --release` génère `jamboos-x86_64-v0.3.90.iso` et les archives de test avec sommes de contrôle SHA-256.

---

## 📦 Artefacts de Distribution (Pre-Alpha)

| Fichier | Emplacement | Description |
| :--- | :--- | :--- |
| `jambo-kernel-x86_64.elf` | `target/dist/` | Binaire micro-noyau ELF bare-metal |
| `jambo-initrd.tar` | `target/dist/` | Archive d'initialisation utilisateur Ring 3 |
| `disk.raw` | `target/dist/` | Image disque brute VirtIO amorçable |
| `jamboos-x86_64-v0.3.90.iso` | `target/dist/` | Image ISO UEFI bootable sous QEMU et silicium bare-metal |

---

## 🗺️ Feuille de Route Réaliste

| Palier | Version Cible | Objectif Majeur | Statut |
| :--- | :--- | :--- | :--- |
| **Palier 6 — Jalon 6.1** | `v0.3.88` | Primitives C-ABI / POSIX (`string`, `malloc`) & Shell introspectif | ✅ Validé |
| **Palier 6 — Jalon 6.2** | `v0.3.89` | Dynamic Loader ELF utilisateur Ring 3 & Relocations | ✅ Validé |
| **Palier 6 — Jalon 6.3** | `v0.3.90` | VFS POSIX, descripteurs de fichiers (`fd_table`) & interfaçage `jambo-fs` | ✅ **Terminé** |
| **Palier 6 — Jalon 6.4** | `v0.3.91` | Utilitaires Coreutils autonomes (`cat`, `ls`, `echo`, `wc`) en Ring 3 | ⏳ Suivant |
| **Palier 7** | `v0.5.0` | Pilotes matériels natifs (NVMe PCIe natif, USB xHCI, UART PL011 ARM64) | ⚪ Planifié |
| **Palier 8** | `v0.6.0` | Pile réseau complète TCP/IP & Socket API en Ring 3 | ⚪ Planifié |
| **Palier 9** | `v0.7.0` | Système de fichiers JamboFS avec journalisation CoW & persistance chiffrée | ⚪ Planifié |
| **Palier 10** | `v0.8.0` | Serveur d'affichage graphique & compositeur fenêtré en Ring 3 | ⚪ Planifié |
| **Palier 11** | `v0.9.0` | Campagne d'audit formel de sécurité, fuzzing TCB & SMP stress | ⚪ Planifié |
| **Palier 12** | `v1.0.0` | Version Long-Term Support (LTS) certifiée pour la production critique | ⚪ Horizon lointain |


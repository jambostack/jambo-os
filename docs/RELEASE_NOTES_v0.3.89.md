# JamboOS — Notes de Version v0.3.89 (Prototype Pre-Alpha)

**Date** : Novembre 2026  
**Jalon** : Palier 6 — Jalon 6.2 : Dynamic Loader ELF Utilisateur Ring 3 & Relocations  
**Statut** : **Prototype expérimental de recherche (Pre-Alpha)** — *À une année-lumière d'une version 1.0.0 de production.*

---

## ⚠️ Avertissement Essentiel

JamboOS demeure un **prototype de recherche académique et expérimental**. Le système d'exploitation n'est en aucun cas prêt pour un déploiement en production industrielle, ni certifié pour des environnements critiques. L'attribution antérieure de numéros de version `v1.0.0` ou qualificatifs « LTS certifié » a été formellement rectifiée. La numérotation suit désormais une progression réaliste et sobre (`v0.3.88` -> `v0.3.89`).

---

## 🚀 Évolutions techniques du Jalon 6.2 (v0.3.89)

### 1. Dynamic Loader ELF64 Ring 3 & Relocations (`libjambo::dynlink`)
- **Structures ELF64 System V AMD64 (`#![no_std]`)** :
  - `Elf64Dyn` : Entrées du segment `PT_DYNAMIC` (`DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, `DT_SYMTAB`, `DT_STRTAB`, `DT_PLTGOT`, `DT_JMPREL`, `DT_BIND_NOW`, `DT_FLAGS_1`).
  - `Elf64Rela` : Relocalisations avec addend explicite (`r_offset`, `r_info`, `r_addend`).
  - `Elf64Sym` : Entrées de symboles dynamiques (`st_name`, `st_info`, `st_other`, `st_shndx`, `st_value`, `st_size`).
- **Moteur de relocalisation System V AMD64** :
  - `R_X86_64_RELATIVE` (Formule $B + A$) : Relocalisation des pointeurs internes au binaire ou à la bibliothèque indépendante de la position (PIE).
  - `R_X86_64_GLOB_DAT` : Résolution directe vers la Table Globale de Décalage (GOT).
  - `R_X86_64_64` : Relocalisation directe 64-bit ($S + A$).
- **Table GOT et Durcissement RELRO (*Read-Only Relocations*)** :
  - Table Globale de Décalage (`GotTable`) d'une capacité configurable (64 entrées par processus).
  - Verrouillage irréversible `seal_relro()` : toute tentative de modification de la GOT post-liaison échoue avec `SysError::PermissionDenied`.
- **En-tête C ABI normalisé** :
  - Déclarations des constantes de relocalisation et structures `Elf64_Dyn`, `Elf64_Rela`, `Elf64_Sym` dans `libs/libjambo/include/jambo.h`.
- **Validation unitaire** :
  - 4 nouveaux tests unitaires automatisés validant le parsing `PT_DYNAMIC`, les relocalisations relatives et directes, ainsi que le durcissement RELRO (`7 passed; 0 failed`).

### 2. Shell Introspectif `jsh` (`services/jambo-sh`)
- **Nouvelle commande `dynlink` (alias `ldd`)** :
  - Affiche l'état du chargeur dynamique en espace utilisateur, les types de relocalisations supportés, les capacités GOT et le statut du scellement RELRO.
- **Bannière et commandes système mises à jour** :
  - Bannière : `JamboOS Object Shell (jsh) v0.3.89`.
  - Commandes `uname` et `version` alignées sur la version `v0.3.89`.

### 3. Micro-Noyau & Outillage de Distribution (`kernel`, `xtask`)
- **Synchronisation de version** :
  - `kernel` et `xtask` calés à `0.3.89`.
  - Bannière d'amorçage Limine : `JAMBO-OS (JamboKernel v0.3.89 — Prototype Pre-Alpha)`.
- **Pipeline de distribution déterministe** :
  - `cargo xtask dist --release` génère les archives et l'ISO `jamboos-x86_64-v0.3.89.iso` avec sommes de contrôle SHA-256.

---

## 📦 Artefacts de Distribution (Pre-Alpha)

| Fichier | Emplacement | Description |
| :--- | :--- | :--- |
| `jambo-kernel-x86_64.elf` | `target/dist/` | Binaire micro-noyau ELF bare-metal |
| `jambo-initrd.tar` | `target/dist/` | Archive d'initialisation utilisateur Ring 3 |
| `disk.raw` | `target/dist/` | Image disque brute VirtIO amorçable |
| `jamboos-x86_64-v0.3.89.iso` | `target/dist/` | Image ISO UEFI bootable sous QEMU et silicium bare-metal |

---

## 🗺️ Feuille de Route Réaliste

| Palier | Version Cible | Objectif Majeur | Statut |
| :--- | :--- | :--- | :--- |
| **Palier 6 — Jalon 6.1** | `v0.3.88` | Primitives C-ABI / POSIX (`string`, `malloc`) & Shell introspectif | ✅ Validé |
| **Palier 6 — Jalon 6.2** | `v0.3.89` | Dynamic Loader ELF utilisateur Ring 3 & Relocations | ✅ **Terminé** |
| **Palier 6 — Jalon 6.3** | `v0.3.90` | VFS POSIX, descripteurs de fichiers (`fd_table`) & interfaçage `jambo-fs` | ⏳ Suivant |
| **Palier 6 — Jalon 6.4** | `v0.3.91` | Utilitaires Coreutils autonomes (`cat`, `ls`, `echo`, `wc`) en Ring 3 | ⚪ Planifié |
| **Palier 7** | `v0.5.0` | Pilotes matériels natifs (NVMe PCIe natif, USB xHCI, UART PL011 ARM64) | ⚪ Planifié |
| **Palier 8** | `v0.6.0` | Pile réseau complète TCP/IP & Socket API en Ring 3 | ⚪ Planifié |
| **Palier 9** | `v0.7.0` | Système de fichiers JamboFS avec journalisation CoW & persistance chiffrée | ⚪ Planifié |
| **Palier 10** | `v0.8.0` | Serveur d'affichage graphique & compositeur fenêtré en Ring 3 | ⚪ Planifié |
| **Palier 11** | `v0.9.0` | Campagne d'audit formel de sécurité, fuzzing TCB & SMP stress | ⚪ Planifié |
| **Palier 12** | `v1.0.0` | Version Long-Term Support (LTS) certifiée pour la production critique | ⚪ Horizon lointain |


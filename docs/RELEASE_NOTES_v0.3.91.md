# JamboOS — Notes de Version v0.3.91 (Prototype Pre-Alpha)

**Date** : Novembre 2026  
**Jalon** : Palier 6 — Jalon 6.4 : Utilitaires Coreutils autonomes (`cat`, `ls`, `echo`, `wc`, `true`, `false`) en Ring 3 & Exécution capabilaire  
**Statut** : **Prototype expérimental de recherche (Pre-Alpha)** — *À une année-lumière d'une version 1.0.0 de production.*

---

## ⚠️ Avertissement Essentiel

JamboOS demeure un **prototype de recherche académique et expérimental**. Le système d'exploitation n'est en aucun cas prêt pour un déploiement en production industrielle, ni certifié pour des environnements critiques. L'attribution de numéros de version suit rigoureusement une progression réaliste et sobre (`v0.3.90` -> `v0.3.91`).

---

## 🚀 Évolutions techniques du Jalon 6.4 (v0.3.91)

### 1. Bibliothèque Utilisateur `libjambo::coreutils`
- **Moteur logique pour les utilitaires POSIX fondamentaux** :
  - `echo` (`run_echo`, `run_echo_slice`) : Support des arguments en ligne de commande, de l'option `-n` (omission du saut de ligne final), concaténation propre avec espacement standardisé.
  - `cat` (`run_cat`) : Lecture séquentielle de fichiers via la table de descripteurs `libjambo::vfs` et le pool d'in-memory inodes virtuels, lecture depuis standard input (`stdin`) avec buffering borné.
  - `wc` (`run_wc`, `count_buffer`) : Comptage précis des lignes (`-l`), mots (`-w`) et octets (`-c`). Gestion standardisée des délimiteurs d'espacement ASCII (espace, saut de ligne, retour chariot, tabulation).
  - `true` (`run_true`) / `false` (`run_false`) : Codes de retour déterministes POSIX (0 pour succès, 1 pour échec).
  - `ls` (`run_ls`) : Inspection des entrées de répertoire du pool d'in-memory inodes avec support de l'option détaillée (`-l`) affichant la taille en octets.
- **Cache virtuel d'inodes et persistance en mémoire (`INODE_POOL`)** :
  - Support natif des fichiers système virtuels (`/etc/hostname`, `/etc/os-release`, `/etc/motd`).
  - Prise en charge des fichiers réguliers créés dynamiquement avec sémantique `O_CREAT`.
- **Suite de tests unitaires** :
  - 10 nouveaux tests unitaires automatisés couvrant tous les cas limites (fichiers inexistants, options combinées, parsing stdin, zéro-allocation) portant la couverture de `libjambo` à **21/21 tests passés avec succès**.

### 2. Crate Dédié aux Binaires Autonomes Ring 3 (`services/jambo-coreutils`)
- **6 binaires ELF autonomes `#![no_std]` isolés** :
  - `echo` : `src/bin/echo.rs`
  - `cat` : `src/bin/cat.rs`
  - `wc` : `src/bin/wc.rs`
  - `true` : `src/bin/true.rs`
  - `false` : `src/bin/false.rs`
  - `ls` : `src/bin/ls.rs`
- **Extraction des arguments System V ABI (`parse_stack_args`)** :
  - Décodage sécurisé de la pile d'entrée `[argc][argv0]...[NULL]` sans allocation dynamique.
  - Terminaison propre des processus utilisateurs via l'appel système `ThreadExit` (`SyscallNumber::ThreadExit` = 11).
- **Compilation déterministe bare-metal** :
  - Script de liaison `libs/user-x86_64.ld` pour une segmentation mémoire ELF64 standardisée.

### 3. Shell Introspectif `jsh` (`services/jambo-sh`)
- **Routage direct et exécution capabilaire** :
  - Support de l'invocation directe (`echo`, `cat`, `wc`, `ls`, `true`, `false`) ou préfixée (`/bin/echo`, `bin/cat`).
  - Commande introspective dédiée `coreutils` décrivant les 6 utilitaires, leur isolation CSpace/PML4 et leur conformité POSIX.
- **Bannière et synchronisation** :
  - Bannière : `JamboOS Object Shell (jsh) v0.3.91`.
  - Commandes `uname` et `version` synchronisées à `v0.3.91`.

### 4. Micro-Noyau & Outillage de Distribution (`kernel`, `xtask`)
- **Mise à niveau du micro-noyau** :
  - Version `0.3.91` synchronisée dans `kernel/Cargo.toml`.
  - Bannière de démarrage mise à jour : `JAMBO-OS (JamboKernel v0.3.91 — Prototype Pre-Alpha)`.
  - Validation automatique sous QEMU : assertion `[PASS] Jalon 6.4 : Utilitaires Coreutils autonomes Ring 3 et execution capabilaire valides sous QEMU.`.
- **Intégration au pipeline de build `xtask`** :
  - Automatisation de la compilation des 6 binaires autonomes `jambo-coreutils`.
  - Intégration dans `initrd_stage/bin` et `initrd_stage/` pour inclusion dans `jambo-initrd.tar` et `disk.raw`.
  - Génération de l'image ISO de distribution `jamboos-x86_64-v0.3.91.iso`.

---

## 📦 Artefacts de Distribution (Pre-Alpha)

| Fichier | Emplacement | Description |
| :--- | :--- | :--- |
| `jambo-kernel-x86_64.elf` | `target/dist/` | Binaire micro-noyau ELF bare-metal |
| `jambo-initrd.tar` | `target/dist/` | Archive d'initialisation utilisateur Ring 3 incluant `/bin/` |
| `disk.raw` | `target/dist/` | Image disque brute VirtIO amorçable |
| `jamboos-x86_64-v0.3.91.iso` | `target/dist/` | Image ISO UEFI bootable sous QEMU et silicium bare-metal |

---

## 🗺️ Chantiers de Stabilisation Réelle (Série 0.*.*)

- **Priorité 1** : Conception d'une image ISO d'installation et de déploiement persistant (`jambo-installer`) assurant le partitionnement GPT cible.
- **Priorité 2** : Développement de pilotes matériels natifs concrets (NVMe PCIe, USB xHCI / clavier, UART).
- **Priorité 3** : Système de fichiers persistant sur disque physique (JamboFS).
- **Politique de Versionnage** : Évolution lente et confinée à la série `0.*.*`, gel total des tags Git jusqu'à validation sur matériel réel et disponibilité de l'installeur.


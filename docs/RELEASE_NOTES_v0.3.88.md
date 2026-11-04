# JamboOS — Notes de Version v0.3.88 (Prototype Pre-Alpha)

**Date** : Novembre 2026  
**Jalon** : Palier 6 — Jalon 6.1 : Primitives C-ABI / POSIX & Shell Introspectif  
**Statut** : **Prototype expérimental de recherche (Pre-Alpha)** — *À une année-lumière d'une version 1.0.0 de production.*

---

## ⚠️ Avertissement Essentiel

JamboOS demeure un **prototype de recherche académique et expérimental**. Le système d'exploitation n'est en aucun cas prêt pour un déploiement en production industrielle, ni certifié pour des environnements critiques. L'attribution antérieure de numéros de version `v1.0.0` ou qualificatifs « LTS certifié » a été formellement rectifiée. La numérotation suit désormais une progression réaliste et sobre (`v0.3.87` -> `v0.3.88`).

---

## 🚀 Évolutions techniques du Jalon 6.1 (v0.3.88)

### 1. Primitives C-ABI et Chaîne POSIX minimale (`libjambo`)
- **Primitives de manipulation de chaînes C standard** :
  - `strcmp(const char *s1, const char *s2) -> int`
  - `strncmp(const char *s1, const char *s2, size_t n) -> int`
  - `strncpy(char *dest, const char *src, size_t n) -> char *`
  - `strchr(const char *s, int c) -> char *`
  - `atoi(const char *nptr) -> int` (conversion ascii vers entier signée avec gestion des espaces)
- **Gestionnaire mémoire POSIX utilisateur minimal** :
  - `malloc(size_t size) -> void *` avec métadonnées d'en-tête de bloc (`AllocHeader`) et enrobage sur le syscall `mmap`.
  - `free(void *ptr)` avec validation de tag magique anti double-free et libération via `munmap`.
  - Isolation conditionnelle `#[cfg(not(test))]` pour prévenir toute collision avec le runtime MSVC hôte.
- **En-tête C standardisé** :
  - Mise à jour de `libs/libjambo/include/jambo.h` exposant l'ensemble des nouveaux prototypes C-ABI.

### 2. Shell Introspectif Enrichi (`jambo-sh` / `jsh`)
- **Nouvelles commandes intégrées d'inspection système** :
  - `uname` : Affiche l'identification formelle du micro-noyau et de l'architecture (`JamboOS x86_64 v0.3.88 (pre-alpha-research)`).
  - `version` : Détaille la version, le palier de développement actif (Palier 6 Jalon 6.1) et l'avertissement de prototype.
  - `uptime` : Introspection du compteur de ticks d'horloge du système.
  - `caps` : Énumère les capacités de sécurité accordées au processus shell interactif.
- **Mise à jour des bannières interactives** :
  - Alignement sur `JamboOS Object Shell (jsh) v0.3.88`.

### 3. Outillage & Intégration Continue (`xtask`)
- Validation automatique des builds x86_64 et aarch64 bare-metal.
- Génération d'artefacts reproductibles dans `target/dist/` avec sommes de contrôle SHA-256.

---

## 📦 Artefacts de Distribution (Pre-Alpha)

| Fichier | Emplacement | Description |
| :--- | :--- | :--- |
| `jambo-kernel-x86_64.elf` | `target/dist/` | Binaire micro-noyau ELF bare-metal |
| `jambo-initrd.tar` | `target/dist/` | Archive d'initialisation utilisateur Ring 3 |
| `disk.raw` | `target/dist/` | Image disque brute VirtIO amorçable |

---

## 🗺️ Feuille de Route Réaliste

| Palier | Version Cible | Objectif Majeur | Statut |
| :--- | :--- | :--- | :--- |
| **Palier 6 — Jalon 6.1** | `v0.3.88` | Primitives C-ABI / POSIX (`string`, `malloc`) & Shell introspectif | ✅ **Terminé** |
| **Palier 6 — Jalon 6.2** | `v0.3.89` | Dynamic Loader ELF utilisateur Ring 3 & Relocations | ⏳ Suivant |
| **Palier 7** | `v0.4.0` | Pile TCP native sans tas, socket IPC & routage | ⚪ Planifié |
| **Palier 8** | `v0.5.0` | Système de fichiers distribué chiffré & tolérance aux pannes | ⚪ Planifié |
| **Palier 9** | `v0.6.0` | Isolation matérielle par hyperviseur Ring -1 (Type-1 bare-metal) | ⚪ Planifié |
| **Palier 10** | `v0.8.0` | Serveur d'affichage graphique & compositeur fenêtré en Ring 3 | ⚪ Planifié |
| **Palier 11** | `v0.9.0` | Campagne d'audit formel de sécurité, fuzzing TCB & SMP stress | ⚪ Planifié |
| **Palier 12** | `v1.0.0` | Version Long-Term Support (LTS) certifiée pour la production critique | ⚪ Horizon lointain |

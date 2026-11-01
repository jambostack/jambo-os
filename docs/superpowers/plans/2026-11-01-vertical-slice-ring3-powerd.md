# Plan d'Implémentation — Jalon 3.6 : Gestion de l'Énergie & Fréquence CPU en Ring 3 (PID 11), Démon `jambo-powerd` & Commandes `power` (v0.3.50)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 1er Novembre 2026  
**Cible :** `v0.3.50`  
**Méthodologie :** Subagent-Driven Development (SDD) avec paires Implementer/Reviewer par tâche, puis Whole-Branch Review.

---

## 1. Découpage en 4 Tâches Opérationnelles

### Tâche 1 : Promotion `jambo-powerd` & Démon Ring 3 (`powerd`, PID 11)
- **Objectif** : Promouvoir `incubator/services/jambo-powerd` vers `services/jambo-powerd`, ajouter la crate au workspace racine `Cargo.toml`.
- **Implémentation** :
  - Définir le protocole IPC (structures `PowerRequest` et `PowerResponse` à 64 octets, opcodes `GetStatus`, `SetProfile`, `SetCState`, `GetBattery`, `Shutdown`).
  - Implémenter le client IPC `PowerClient` et le serveur IPC.
  - Implémenter le point d'entrée exécutable `src/main.rs` avec `_start() -> !` sans tas (`#![no_std]`, `#![no_main]`).
  - Initialiser le démon avec capabilités racines, auto-test au démarrage (vérification FADT, cœurs C-States, profil énergétique, télémétrie batterie).
  - Boucle d'événements IPC coopérative avec `syscall_thread_yield()`.
- **Critères Reviewer** : `#![no_std]`, zéro allocation dynamique, conformité System V ABI, assertions statiques 64 octets IPC, compilation bare-metal `x86_64-unknown-none`.

### Tâche 2 : Commandes `power` dans le Shell `jsh` (PID 2) & Listing 11 Processus
- **Objectif** : Ajouter les commandes interactives `power` et mettre à jour `ps` pour afficher les 11 processus Ring 3.
- **Implémentation** :
  - Mettre à jour `services/jambo-sh/Cargo.toml` pour dépendre de `jambo-powerd`.
  - Implémenter `power status`, `power profile [eco|balanced|perf]`, `power cstate <core> <c0|c1|c2|c3>`, `power battery`.
  - Mettre à jour `ps` pour lister les 11 PIDs (1 à 11).
  - Actualiser la bannière et l'aide `help` pour afficher `v0.3.50`.
- **Critères Reviewer** : Aucune allocation dynamique, parsing no_std robuste, affichage lisible et soigné, vérification des 11 processus dans `ps`.

### Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`
- **Objectif** : Intégrer le binaire `/bin/powerd` dans l'orchestrateur `xtask` et charger le PID 11 dans le micro-noyau.
- **Implémentation** :
  - `kernel/Cargo.toml` bumped à `0.3.50`.
  - Dans `kernel/src/main.rs` : extraire `/bin/powerd` de l'initrd, allouer l'espace virtuel, pile Ring 3 alignée à 16 octets (`assert_eq!(powerd_sp % 16, 0)`), enfiler le PID 11 dans l'ordonnanceur EEVDF, émettre le message UART `[PASS] Gestion Énergie & Fréquence CPU (jambo-powerd PID 11) validée sous QEMU.`.
  - Dans `xtask/src/main.rs` : compiler `jambo-powerd` avec `libs/user-x86_64.ld`, empaqueter dans `target/initrd.tar`, actualiser le disque `target/disk.raw` avec la bannière `"Bienvenue sur JamboOS v0.3.50\n"`.
- **Critères Reviewer** : Respect strict du TCB minimal, alignement pile 16 octets garanti, empaquetage TAR propre des 11 binaires utilisateur.

### Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.50`
- **Objectif** : Valider la compilation complète bare-metal, exécuter le test automatisé QEMU UEFI avec le code de sortie 33, auditer les logs et clore le cycle.
- **Implémentation** :
  - `cargo fmt --all -- --check`
  - `cargo clippy` sur les crates modifiées
  - Compilation release des 12 binaires bare-metal
  - Exécution du runner QEMU UEFI automatisé
  - Vérification de l'exit code 33 (`isa-debug-exit`) et du journal UART avec les 11 processus démarrés.
- **Critères Reviewer** : Sortie code 33 validée, zero régression sur les PIDs 1..10.

---

## 2. Whole-Branch Review & Clôture
- Audit exhaustif de tous les commits du Jalon 3.6.
- Suppression de l'espace de travail SDD temporaire.
- Création du tag officiel annoté `v0.3.50`.
- `git push origin main --tags`.
- Mise à jour de l'artefact de feuille de route stratégique.


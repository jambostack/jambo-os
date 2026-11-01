# Plan d'Implémentation — Jalon 3.5 : Confinement Mémoire & Forensics Volatile en Ring 3 (PID 10), Démon `jambo-forensics` & Commandes `forensics` (v0.3.49)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 1er Novembre 2026  
**Cible :** `v0.3.49`  
**Méthodologie :** Subagent-Driven Development (SDD) avec paires Implementer/Reviewer par tâche, puis Whole-Branch Review.

---

## 1. Découpage en 4 Tâches Opérationnelles

### Tâche 1 : Promotion `jambo-forensics` & Démon Ring 3 (`forensics`, PID 10)
- **Objectif** : Promouvoir `incubator/services/jambo-forensics` vers `services/jambo-forensics`, ajouter la crate au workspace racine `Cargo.toml`.
- **Implémentation** :
  - Définir le protocole IPC (structures `ForensicsRequest` et `ForensicsResponse` à 64 octets, opcodes `GetStatus`, `DumpProcess`, `GetTimeline`, `QuarantineProcess`).
  - Implémenter le client IPC `ForensicsClient` et le serveur IPC.
  - Implémenter le point d'entrée exécutable `src/main.rs` avec `_start() -> !` sans tas (`#![no_std]`, `#![no_main]`).
  - Initialiser le démon avec capabilités racines, effectuer un auto-test au démarrage (capture de mémoire volatile témoin, scellement cryptographique BLAKE3/SHA-256/Ed25519, chaîne de garde).
  - Boucle d'événements IPC coopérative avec `syscall_thread_yield()`.
- **Critères Reviewer** : `#![no_std]`, zéro allocation dynamique, conformité System V ABI, assertions statiques 64 octets IPC, compilation bare-metal `x86_64-unknown-none`.

### Tâche 2 : Commandes `forensics` dans le Shell `jsh` (PID 2) & Listing 10 Processus
- **Objectif** : Ajouter les commandes interactives `forensics` et mettre à jour `ps` pour afficher les 10 processus Ring 3.
- **Implémentation** :
  - Mettre à jour `services/jambo-sh/Cargo.toml` pour dépendre de `jambo-forensics`.
  - Implémenter `forensics status`, `forensics dump <pid>`, `forensics timeline`, `forensics quarantine <pid>`.
  - Mettre à jour `ps` pour lister les 10 PIDs (1 à 10).
  - Actualiser la bannière et l'aide `help` pour afficher `v0.3.49`.
- **Critères Reviewer** : Aucune allocation dynamique, parsing no_std robuste, affichage lisible et soigné, vérification des 10 processus dans `ps`.

### Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`
- **Objectif** : Intégrer le binaire `/bin/forensics` dans l'orchestrateur `xtask` et charger le PID 10 dans le micro-noyau.
- **Implémentation** :
  - `kernel/Cargo.toml` bumped à `0.3.49`.
  - Dans `kernel/src/main.rs` : extraire `/bin/forensics` de l'initrd, allouer l'espace virtuel, pile Ring 3 alignée à 16 octets (`assert_eq!(forensics_sp % 16, 0)`), enfiler le PID 10 dans l'ordonnanceur EEVDF, émettre le message UART `[PASS] Confinement Memoire & Forensics Volatile (jambo-forensics PID 10) validee sous QEMU.`.
  - Dans `xtask/src/main.rs` : compiler `jambo-forensics` avec `libs/user-x86_64.ld`, empaqueter dans `target/initrd.tar`, actualiser le disque `target/disk.raw` avec la bannière `"Bienvenue sur JamboOS v0.3.49\n"`.
- **Critères Reviewer** : Respect strict du TCB minimal, alignement pile 16 octets garanti, empaquetage TAR propre.

### Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.49`
- **Objectif** : Valider la compilation complète bare-metal, exécuter le test automatisé QEMU UEFI avec le code de sortie 33, auditer les logs et clore le cycle.
- **Implémentation** :
  - `cargo fmt --all -- --check`
  - `cargo clippy` sur les crates modifiées
  - Compilation release des 11 binaires bare-metal
  - Exécution du runner QEMU UEFI automatisé
  - Vérification de l'exit code 33 (`isa-debug-exit`) et du journal UART avec les 10 processus démarrés.
- **Critères Reviewer** : Sortie code 33 validée, zero régression sur les PIDs 1..9.

---

## 2. Whole-Branch Review & Clôture
- Audit exhaustif de tous les commits du Jalon 3.5.
- Suppression de l'espace de travail SDD temporaire.
- Création du tag officiel annoté `v0.3.49`.
- `git push origin main --tags`.
- Mise à jour de l'artefact de feuille de route stratégique.


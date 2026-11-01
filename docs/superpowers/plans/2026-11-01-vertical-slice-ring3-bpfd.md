# Plan d'Implémentation — Jalon 3.8 : Sandboxing eBPF & Filtrage Réseau XDP en Ring 3 (PID 13), Démon `jambo-bpfd` & Commandes `bpf` (v0.3.52)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 1er Novembre 2026  
**Cible :** `v0.3.52`  
**Méthodologie :** Subagent-Driven Development (SDD) avec paires Implementer/Reviewer par tâche, puis Whole-Branch Review.

---

## 1. Découpage en 4 Tâches Opérationnelles

### Tâche 1 : Promotion `jambo-bpfd` & Démon Ring 3 (`bpfd`, PID 13)
- **Objectif** : Promouvoir `incubator/services/jambo-bpfd` vers `services/jambo-bpfd`, ajouter la crate au workspace racine `Cargo.toml`.
- **Implémentation** :
  - Définir le protocole IPC (structures `BpfRequest` et `BpfResponse` à 64 octets, opcodes `GetStatus`, `VerifyProgram`, `RunProgram`, `FilterPacket`, `GetStats`).
  - Implémenter le client IPC `BpfClient` et le serveur IPC.
  - Implémenter le point d'entrée exécutable `src/main.rs` avec `_start() -> !` sans tas (`#![no_std]`, `#![no_main]`).
  - Initialiser le démon avec capabilités racines, auto-test au démarrage (chargement d'un filtre XDP par défaut, vérification formelle DAG réussie, exécution de paquet test avec verdict `XDP_PASS` et comptage de cycles).
  - Boucle d'événements IPC coopérative avec `syscall_thread_yield()`.
- **Critères Reviewer** : `#![no_std]`, zéro allocation dynamique, conformité System V ABI, assertions statiques 64 octets IPC, compilation bare-metal `x86_64-unknown-none`.

### Tâche 2 : Commandes `bpf` dans le Shell `jsh` (PID 2) & Listing 13 Processus
- **Objectif** : Ajouter les commandes interactives `bpf` et mettre à jour `ps` pour afficher les 13 processus Ring 3.
- **Implémentation** :
  - Mettre à jour `services/jambo-sh/Cargo.toml` pour dépendre de `jambo-bpfd`.
  - Implémenter `bpf status`, `bpf verify`, `bpf run <prog_id>`, `bpf filter <packet_len>`.
  - Mettre à jour `ps` pour lister les 13 PIDs (1 à 13).
  - Actualiser la bannière et l'aide `help` pour afficher `v0.3.52`.
- **Critères Reviewer** : Aucune allocation dynamique, parsing no_std robuste, affichage lisible et soigné, vérification des 13 processus dans `ps`.

### Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`
- **Objectif** : Intégrer le binaire `/bin/bpfd` dans l'orchestrateur `xtask` et charger le PID 13 dans le micro-noyau.
- **Implémentation** :
  - `kernel/Cargo.toml` bumped à `0.3.52`.
  - Dans `kernel/src/main.rs` : extraire `/bin/bpfd` de l'initrd, allouer l'espace virtuel, pile Ring 3 alignée à 16 octets (`assert_eq!(bpfd_sp % 16, 0)`), enfiler le PID 13 dans l'ordonnanceur EEVDF, émettre le message UART `[PASS] Sandboxing eBPF & Filtrage Réseau XDP (jambo-bpfd PID 13) validée sous QEMU.`.
  - Dans `xtask/src/main.rs` : compiler `jambo-bpfd` avec `libs/user-x86_64.ld`, empaqueter dans `target/initrd.tar`, actualiser le disque `target/disk.raw` avec la bannière `"Bienvenue sur JamboOS v0.3.52\n"`.
- **Critères Reviewer** : Respect strict du TCB minimal, alignement pile 16 octets garanti, empaquetage TAR propre des 13 binaires utilisateur.

### Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.52`
- **Objectif** : Valider la compilation complète bare-metal, exécuter le test automatisé QEMU UEFI avec le code de sortie 33, auditer les logs et clore le cycle.
- **Implémentation** :
  - `cargo fmt --all -- --check`
  - `cargo clippy` sur les crates modifiées
  - Compilation release des 14 binaires bare-metal
  - Exécution du runner QEMU UEFI automatisé
  - Vérification de l'exit code 33 (`isa-debug-exit`) et du journal UART avec les 13 processus démarrés.
- **Critères Reviewer** : Sortie code 33 validée, zero régression sur les PIDs 1..12.

---

## 2. Whole-Branch Review & Clôture
- Audit exhaustif de tous les commits du Jalon 3.8.
- Suppression de l'espace de travail SDD temporaire.
- Création du tag officiel annoté `v0.3.52`.
- `git push origin main --tags`.
- Mise à jour de l'artefact de feuille de route stratégique.


# Plan d'Implémentation — Jalon 3.7 : Métrologie Système & Télémétrie en Ring 3 (PID 12), Démon `jambo-metrics` & Commandes `metrics` (v0.3.51)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 1er Novembre 2026  
**Cible :** `v0.3.51`  
**Méthodologie :** Subagent-Driven Development (SDD) avec paires Implementer/Reviewer par tâche, puis Whole-Branch Review.

---

## 1. Découpage en 4 Tâches Opérationnelles

### Tâche 1 : Promotion `jambo-metricsd` & Démon Ring 3 (`metricsd`, PID 12)
- **Objectif** : Promouvoir `incubator/services/jambo-metricsd` vers `services/jambo-metricsd`, ajouter la crate au workspace racine `Cargo.toml`.
- **Implémentation** :
  - Définir le protocole IPC (structures `MetricsRequest` et `MetricsResponse` à 64 octets, opcodes `GetStatus`, `QuerySeries`, `IngestSample`, `GetAlerts`).
  - Implémenter le client IPC `MetricsClient` et le serveur IPC.
  - Implémenter le point d'entrée exécutable `src/main.rs` avec `_start() -> !` sans tas (`#![no_std]`, `#![no_main]`).
  - Initialiser le démon avec capabilités racines, auto-test au démarrage (séries temporelles préconfigurées, ingestion d'échantillons nominaux, calcul des agrégats min/max/avg, vérification d'alerte).
  - Boucle d'événements IPC coopérative avec `syscall_thread_yield()`.
- **Critères Reviewer** : `#![no_std]`, zéro allocation dynamique, conformité System V ABI, assertions statiques 64 octets IPC, compilation bare-metal `x86_64-unknown-none`.

### Tâche 2 : Commandes `metrics` dans le Shell `jsh` (PID 2) & Listing 12 Processus
- **Objectif** : Ajouter les commandes interactives `metrics` et mettre à jour `ps` pour afficher les 12 processus Ring 3.
- **Implémentation** :
  - Mettre à jour `services/jambo-sh/Cargo.toml` pour dépendre de `jambo-metricsd`.
  - Implémenter `metrics status`, `metrics query <series>`, `metrics ingest <series> <val>`, `metrics alerts`.
  - Mettre à jour `ps` pour lister les 12 PIDs (1 à 12).
  - Actualiser la bannière et l'aide `help` pour afficher `v0.3.51`.
- **Critères Reviewer** : Aucune allocation dynamique, parsing no_std robuste, affichage lisible et soigné, vérification des 12 processus dans `ps`.

### Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`
- **Objectif** : Intégrer le binaire `/bin/metricsd` dans l'orchestrateur `xtask` et charger le PID 12 dans le micro-noyau.
- **Implémentation** :
  - `kernel/Cargo.toml` bumped à `0.3.51`.
  - Dans `kernel/src/main.rs` : extraire `/bin/metricsd` de l'initrd, allouer l'espace virtuel, pile Ring 3 alignée à 16 octets (`assert_eq!(metricsd_sp % 16, 0)`), enfiler le PID 12 dans l'ordonnanceur EEVDF, émettre le message UART `[PASS] Métrologie Système & Télémétrie Haute Précision (jambo-metrics PID 12) validée sous QEMU.`.
  - Dans `xtask/src/main.rs` : compiler `jambo-metricsd` avec `libs/user-x86_64.ld`, empaqueter dans `target/initrd.tar`, actualiser le disque `target/disk.raw` avec la bannière `"Bienvenue sur JamboOS v0.3.51\n"`.
- **Critères Reviewer** : Respect strict du TCB minimal, alignement pile 16 octets garanti, empaquetage TAR propre des 12 binaires utilisateur.

### Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.51`
- **Objectif** : Valider la compilation complète bare-metal, exécuter le test automatisé QEMU UEFI avec le code de sortie 33, auditer les logs et clore le cycle.
- **Implémentation** :
  - `cargo fmt --all -- --check`
  - `cargo clippy` sur les crates modifiées
  - Compilation release des 13 binaires bare-metal
  - Exécution du runner QEMU UEFI automatisé
  - Vérification de l'exit code 33 (`isa-debug-exit`) et du journal UART avec les 12 processus démarrés.
- **Critères Reviewer** : Sortie code 33 validée, zero régression sur les PIDs 1..11.

---

## 2. Whole-Branch Review & Clôture
- Audit exhaustif de tous les commits du Jalon 3.7.
- Suppression de l'espace de travail SDD temporaire.
- Création du tag officiel annoté `v0.3.51`.
- `git push origin main --tags`.
- Mise à jour de l'artefact de feuille de route stratégique.

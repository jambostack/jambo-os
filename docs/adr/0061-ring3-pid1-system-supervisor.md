# ADR 0061: Superviseur Système PID 1 en Ring 3 & Gestionnaire de DAG (`jambo-init`)

## Statut
Accepté (Phase 72 - Jalon v0.2.70)

## Contexte
Dans une architecture de micro-noyau souverain orienté capacités (`#![no_std]`), le premier processus de l'espace utilisateur (PID 1) a pour responsabilité critique d'orchestrer l'ensemble des démons et pilotes de périphériques Ring 3 tout en respectant le principe de moindre privilège et du zéro autorité ambiante. Avec `services/jambo-init`, JamboOS met en œuvre un superviseur de 3e génération nativement résilient :
1. **Confinement Capabilaire de Supervision (`InitCap`)** :
   - Le contrôle du cycle de vie du système est scellé par des jetons de capacités `InitCap`.
   - Droits granulaires (`INIT_START`, `INIT_STOP`, `INIT_RESTART`, `INIT_STATUS`, `INIT_SHUTDOWN`, `INIT_ADMIN`), interdisant tout arrêt ou redémarrage non autorisé de démons système.
2. **Gestion Déterministe des Dépendances (DAG)** :
   - Modélisation du graphe orienté acyclique (DAG) entre services (`SupervisedService`).
   - Détection formelle de cycles via parcours DFS borné interdisant les interblocages au démarrage.
   - Résolution topologique stricte : aucun démon ne peut être démarré si l'intégralité de ses dépendances n'est pas dans l'état `Running` (`ResourceBusy`).
3. **Auto-guérison et Relance Automatique (Self-Healing)** :
   - Détection des crashs de processus via `report_crash` et relance automatique immédiate sans intervention humaine.
   - Quota de tolérance configurable (`DEFAULT_MAX_RESTARTS = 3`) : au-delà du seuil, bascule en état `Failed` pour éviter l'épuisement des ressources système par boucle de crash.
4. **Extinction Ordonnée du Système (`shutdown`)** :
   - Arrêt ordonné et séquentiel de tous les démons selon l'ordre topologique inverse exact du DAG, préservant l'intégrité du système de fichiers CoW et des flux réseau.
5. **Démon PID 1 Complet (`JamboInitDaemon`) & Commandes Shell `init`** :
   - Initialisation et démarrage ordonné des 10 démons fondateurs de l'écosystème (`pcie-bus-mgr`, `jambo-fs`, `jambo-cryptod`, `jambo-authd`, `jambo-netd`, `jambo-serviced`, `jambo-policyd`, `jambo-traced`, `jambo-certd`, `jsh`).
   - Commandes interactives dans `jsh` :
     - `init status` : affiche l'état d'activité, le nombre de relances et la topologie du superviseur.
     - `init restart <daemon>` : relance ciblée d'un service supervisé.
     - `init shutdown` : extinction ordonnée de tous les services du système.
6. **Harnais de Validation Noyau (`kernel/src/sched/init_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 72) de l'atténuation `InitCap`, de la détection de cycles, du blocage des dépendances prématurées, de l'auto-guérison sur crash, du basculement en échec et des commandes du shell.

## Décision
1. Conception et implémentation de la bibliothèque `SystemSupervisor`, de `JamboInitDaemon` et de leurs tests unitaires dans `services/jambo-init/src/lib.rs`.
2. Découplage du cycle de dépendances entre `jambo-init` et `jambo-sh` par utilisation directe de `jambo-coreutils`.
3. Intégration de `jambo-init` dans `services/jambo-sh` avec l'implémentation de la commande interactive `init`.
4. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/init_test.rs`.
5. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 72) et publication de la version `v0.2.70`.

## Conséquences
- Disponibilité d'un superviseur système PID 1 souverain, déterministe et capable d'auto-guérison en espace utilisateur Ring 3.
- Fondation robuste pour l'exécution d'applications complexes et de runtimes isolés (WASM, POSIX, micro-VMM) avec supervision de santé continue.

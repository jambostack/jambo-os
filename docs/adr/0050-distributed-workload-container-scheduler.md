# ADR 0050: Ordonnanceur de Charges de Travail & Conteneurs Distribués (`jambo-schedd`)

## Statut
Accepté (Phase 61 - Jalon v0.2.59)

## Contexte
Dans une grappe de calcul distribuée JamboOS (nœuds SMP multiples, micro-hyperviseurs Ring 3, machines virtuelles légères et sandboxes WebAssembly), le placement déterministe, l'allocation équilibrée des ressources matérielles et la gestion du cycle de vie des charges applicatives requièrent un ordonnanceur de cluster distribué zéro-autorité ambiante. Avec `services/jambo-schedd`, JamboOS intègre un moteur d'orchestration déclaratif `#![no_std]` opérant en espace utilisateur (Ring 3) :
1. **Confinement Capabilaire d'Ordonnancement (`SchedCap`)** :
   - Toute opération d'orchestration (soumission, annulation, drainage, migration) requiert un jeton de capacité `SchedCap`.
   - Droits granulaires (`SCHED_SUBMIT`, `SCHED_CANCEL`, `SCHED_QUERY`, `SCHED_MIGRATE`, `SCHED_DRAIN`, `SCHED_ADMIN`), empêchant toute prise de contrôle sauvage ou déni de service de ressources matérielles.
2. **Support Multimode des Runtimes (`RuntimeType`)** :
   - Support unifié des runtimes hétérogènes de JamboOS : micro-hyperviseur Type-2 (`MicroVmm`), sandbox WebAssembly (`Wasm`) et processus compatibles POSIX (`Posix`).
   - Spécification déclarative des besoins (`TaskSpec`) : quotas vCPUs, pages mémoire MMU et affinité préférentielle de nœud (`preferred_node`).
3. **Algorithme de Placement Déterministe (Least-Allocated Node Scoring)** :
   - Calcul de score basé sur la charge relative normalisée des cœurs de calcul et de la mémoire physique.
   - Respect strict des contraintes d'allocation (`can_fit`, `allocate`, `release`), évitant les surallocations non autorisées.
4. **Mobilité et Résilience : Migration à Chaud et Drainage de Nœuds** :
   - Déplacement transparent de tâches actives d'un nœud source vers un nœud cible (`migrate_task`).
   - Procédure de drainage ordonné (`drain_node`) : éviction contrôlée des tâches d'un nœud en maintenance ou défaillant, transition vers l'état `Pending` et réordonnancement automatique sur les nœuds sains restants.
5. **Démon Orchestrateur Ring 3 (`JamboSchedDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant la topologie de cluster et la boucle de réconciliation.
   - Commandes interactives dans `jsh` :
     - `sched status` : topologie de grappe, nœuds actifs, tâches en cours et algorithme de placement.
     - `sched submit <name> <vcpus> <pages>` : soumission déclarative d'une charge.
     - `sched run` : déclenchement du cycle de réconciliation et placement des tâches en attente.
     - `sched cancel <id>` : résiliation contrôlée et restitution des quotas matériels.
     - `sched drain <node>` : éviction et drainage d'un nœud de calcul.
6. **Harnais de Validation Noyau (`kernel/src/sched/schedd_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 61) des droits capabilitaires `SchedCap`, du placement déclaratif, de la migration, du drainage et des commandes interactives du shell.

## Décision
1. Implémentation du démon `JamboSchedDaemon` et de ses tests unitaires dans `services/jambo-schedd/src/lib.rs`.
2. Intégration de `jambo-schedd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `sched`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/schedd_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 61) et publication de la version `v0.2.59`.

## Conséquences
- Fondation pour le bus d'événements asynchrone sans copie (`jambo-eventd`, Phase 62).
- Orchestration de conteneurs et de micro-VMs résiliente, déterministe et strictement confinée par capacités.

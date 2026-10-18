# ADR 0016 : Ordonnanceur de Charges de Travail et de Conteneurs Distribués (`jambo-schedd`)

## Statut
Accepté (Phase 27 - `v0.2.25`)

## Contexte
Après l'intégration des runtimes d'exécution (`jambo-vmm` pour les micro-machines virtuelles Type-2, `jambo-wasm` pour les modules WebAssembly sandboxed, `jambo-linux` pour la compatibilité POSIX) et de la coordination de grappe (`jambo-timed` pour les horloges synchronisées, `jambo-raft` pour le consensus et `jambo-kvd` pour le magasin clé-valeur transactionnel), JamboOS nécessite un moteur d'orchestration distribué. Les nœuds de calcul doivent pouvoir planifier, placer, équilibrer et surveiller les charges de travail distribuées sans autorité ambiante.

## Décision
Nous concevons et implémentons le démon d'espace utilisateur `jambo-schedd` en Rust `#![no_std]`, offrant un ordonnancement déclaratif de micro-charges de travail basé sur les capacités `SchedCap` :

1. **Modèle de Travail Déclaratif (*Jobs* & *Tasks*)** :
   - Chaque tâche spécifie ses exigences en ressources (cœurs virtuels CPU, mémoire en pages de 4 Kio, type de runtime : VMM, WASM ou POSIX).
   - États de cycle de vie déterministes : `Pending`, `Running`, `Completed`, `Failed`, `Evicted`.

2. **Équilibrage de Charge & Politiques de Placement** :
   - Algorithme de placement multicritère à score de charge (*Least-Allocated Node Score*).
   - Prise en charge des contraintes d'affinité de nœud et d'anti-affinité pour la tolérance aux pannes.
   - Mécanisme de drainage de nœud (*Drain*) pour maintenance sans interruption de service.

3. **Boucle de Réconciliation Autonome (*Reconciliation Loop*)** :
   - Surveillance périodique de l'état de santé des nœuds et des conteneurs.
   - En cas de perte de battement de cœur d'un nœud ou de défaillance matérielle, réaffectation atomique (*rescheduling*) des tâches vers des nœuds survivants.

4. **Gouvernance par Capacités Dédiées (`SchedCap`)** :
   - `SCHED_SUBMIT` (0x01) : Soumission de nouvelles tâches et conteneurs.
   - `SCHED_CANCEL` (0x02) : Annulation ou interruption forcée de tâches.
   - `SCHED_QUERY` (0x04) : Inspection de la file d'attente et de la charge des nœuds.
   - `SCHED_MIGRATE` (0x08) : Migration de charge d'un nœud vers un autre.
   - `SCHED_DRAIN` (0x10) : Isolement et vidage progressif d'un nœud.
   - `SCHED_ADMIN` (0x80) : Administration globale des quotas et des politiques.
   - Aucun processus ne peut soumettre ou perturber une charge de travail sans présenter une capacité `SchedCap` valide dotée des permissions requises.

## Conséquences
- **Positives** :
  - Orchestration fluide des micro-VMs et applications WASM sur l'ensemble de la grappe de calcul.
  - Déterministe, robuste aux défaillances et hautement disponible sans point unique de panne.
  - Respect absolu du principe de moindre privilège (*Least Privilege*) et zéro autorité ambiante.
- **Négatives** :
  - Nécessite la synchronisation périodique des métadonnées de placement avec `jambo-kvd`.

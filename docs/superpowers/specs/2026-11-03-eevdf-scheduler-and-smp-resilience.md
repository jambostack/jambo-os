# Spécification Technique : Ordonnancement EEVDF & Résilience SMP Multicœur (v0.3.80)

**Date :** 3 novembre 2026  
**Auteur :** Antigravity & Équipe JamboOS  
**Statut :** Approuvé pour Implémentation  
**Version Cible :** `v0.3.80`  
**Contexte de Durcissement :** Résolution formelle de l'Audit Technique **A-04** et sécurisation de l'ordonnanceur EEVDF (Earliest Eligible Virtual Deadline First) face aux famines, inversions de priorité et au blocage des cœurs secondaires AP (Application Processors).

---

## 1. Contexte & Problématique (Audit A-04)

### 1.1 Le Constat de l'Audit Technique
L'audit technique (`JAMBO_OS_TECHNICAL_AUDIT.md`, Section A-04) a identifié une lacune majeure dans l'implémentation SMP :
> *"Dans `kernel/src/main.rs`, le point d'entrée `ap_start` initialise les structures CPU puis entre dans une boucle `hlt` (x86_64) ou `wfi` (AArch64). Les cœurs secondaires ne rejoignent pas une boucle d'ordonnancement ni un mécanisme de prise de travail.*  
> *La détection et l'initialisation de plusieurs processeurs ne suffisent donc pas à démontrer un ordonnanceur SMP opérationnel. Le code observé ressemble à une mise en ligne des AP suivie de leur mise en attente permanente."*

En complément, l'état d'ordonnancement souffrait de trois vulnérabilités structurelles :
1. **Absence d'état par CPU** : `SCHEDULER.current` était une variable unique scalaire (`Option<Arc<Mutex<Thread>>>`), incapable de suivre simultanément l'exécution de multiples threads sur $N$ cœurs physiques.
2. **Vulnérabilité aux Famines (Starvation)** : L'ordonnanceur EEVDF sélectionnait la deadline minimale sans borner le retard virtuel (*lag*) ni comptabiliser la durée d'attente en file (`wait_ticks`), permettant à des tâches à haute fréquence ou haute priorité de monopoliser le CPU au détriment des threads de fond.
3. **Inversion de Priorité non atténuée** : Aucun mécanisme d'héritage ou d'amplification temporaire de priorité n'était disponible pour les threads serveurs Ring 3 ou les verrous noyau.

---

## 2. Objectifs d'Architecture

1. **Intégration Active des Cœurs Secondaires (AP Core Scheduling Entry)** :
   - Éliminer la boucle d'attente passive `loop { hlt }` dans `ap_start`.
   - Faire converger les AP vers la boucle d'ordonnancement active `EevdfScheduler::ap_entry(cpu_id)`.
   - Chaque cœur dispose d'une boucle idle matérielle interruptible (`cpu_idle_loop(cpu_id)`), permettant la prise en charge immédiate de travail prêt dès l'arrivée d'un tick ou d'un réveil.

2. **État Per-CPU & Runqueue Synchronisée Multicœur** :
   - Tableau `current_per_cpu: [Option<Arc<Mutex<Thread>>>; MAX_CPUS]` indexé par l'ID physique du processeur (`arch::current_cpu().cpu_id`).
   - Méthodes d'accès sécurisées `current()` et `current_for_cpu(cpu_id)`.
   - File d'attente globale synchronisée avec filtrage d'affinité CPU (`thread.cpu_affinity: Option<u32>`).
   - Allocation et enregistrement d'un `idle_thread` dédié par cœur pour des transitions de contexte déterministes.

3. **Ordonnancement EEVDF Durci & Temps Virtuel Système ($V$)** :
   - Suivi d'un temps virtuel système $V$ strictement monotone :
     $$V = \min_{t \in \text{Ready}} t.\text{vruntime}$$
   - **Critère d'Éligibilité** : Un thread $T$ est éligible si et seulement si :
     $$T.\text{vruntime} \le V$$
     (si aucun thread ne remplit cette condition, $V$ est avancé au minimum des vruntimes prêts).
   - **Sélection EEVDF** : Parmi l'ensemble des threads éligibles dont l'affinité matérielle inclut le CPU appelant, sélection du thread avec la plus petite deadline virtuelle $d_i$ :
     $$d_i = \text{vruntime}_i + \frac{q \times 1024}{w_i}$$
   - **Bornage du Lag Virtuel (Anti-Monopolisation)** :
     Lors du réveil ou de l'insertion d'un thread, son $vruntime$ est borné dans l'intervalle $[V - \text{MAX\_LAG}, V + \text{MAX\_LAG}]$ avec $\text{MAX\_LAG} = 50$, empêchant un thread dormant d'acquérir un crédit infini.

4. **Résilience contre la Famine (Anti-Starvation Aging)** :
   - Chaque tick d'horloge incrémente `wait_ticks` pour tous les threads en attente dans la runqueue.
   - Si `wait_ticks >= MAX_WAIT_TICKS` (seuil fixé à 100 ticks), le thread subit une promotion d'urgence : sa deadline est ramenée à $V$, le rendant immédiatement prioritaire face aux tâches calculatoires.
   - À l'exécution, `wait_ticks` est réinitialisé à 0.

5. **Résilience aux Inversions de Priorité (Priority Inheritance Primitives)** :
   - Primitives `Thread::boost_priority(target_weight, target_deadline)` et `Thread::restore_priority()`.
   - Permet à un thread serveur traitant un message IPC pour le compte d'un client de rang supérieur d'exécuter son quantum avec la priorité et la deadline du demandeur.

---

## 3. Spécification Détaillée des Structures et Interfaces

### 3.1 Structure `Thread` (`kernel/src/sched/thread.rs`)
```rust
pub struct Thread {
    pub id: u64,
    pub process_id: u64,
    pub state: ThreadState,
    pub rsp: u64,
    pub stack_base: usize,
    pub stack_top: usize,
    pub vruntime: u64,
    pub deadline: u64,
    pub weight: u32,
    pub base_weight: u32,          // Poids nominal avant boost
    pub base_deadline: u64,        // Deadline nominale avant boost
    pub wait_ticks: u64,           // Compteur de ticks passés en file (anti-famine)
    pub cpu_affinity: Option<u32>, // None = tout cœur, Some(id) = épinglé
    pub last_cpu: u32,             // Dernier processeur d'exécution
    pub is_user: bool,
    pub user_entry: u64,
    pub user_rsp: u64,
    pub aspace: Option<Arc<AddressSpace>>,
    pub cspace: Option<Arc<Mutex<CSpace>>>,
}
```

### 3.2 Structure `EevdfScheduler` (`kernel/src/sched/eevdf.rs`)
```rust
pub const MAX_CPUS: usize = 64;
pub const MAX_LAG: u64 = 50;
pub const MAX_WAIT_TICKS: u64 = 100;
pub const DEFAULT_QUANTUM_TICKS: u64 = 10;

pub struct EevdfScheduler {
    runqueue: Vec<Arc<Mutex<Thread>>>,
    pub current_per_cpu: [Option<Arc<Mutex<Thread>>>; MAX_CPUS],
    pub idle_threads: [Option<Arc<Mutex<Thread>>>; MAX_CPUS],
    pub virtual_time: u64,
}
```

### 3.3 Points d'Entrée & Boucle SMP (`kernel/src/main.rs`)
- `ap_start` :
  1. `arch::init_gdt_ap()`
  2. `arch::init_idt()`
  3. `arch::init_per_cpu(info.processor_id, info.lapic_id, false)`
  4. `ACTIVE_CPUS.fetch_add(1, Ordering::SeqCst)`
  5. Enregistrement du thread idle pour ce CPU : `EevdfScheduler::register_cpu_idle(info.processor_id as usize)`
  6. Transition vers `EevdfScheduler::ap_entry(info.processor_id as usize) -> !`

---

## 4. Stratégie de Validation & Critères d'Acceptation

1. **Test SMP Multi-Core Concurrence** :
   - Enfilement de deux workers calculatoires épinglés respectivement sur CPU 0 et CPU 1 (`cpu_affinity = Some(0)` et `Some(1)`), ainsi qu'un worker flottant (`cpu_affinity = None`).
   - Vérification que les deux processeurs progressent concurremment sans interblocage.
2. **Test EEVDF Éligibilité & Deadlines** :
   - Insertion de threads de poids variables (512, 1024, 2048). Vérification de l'ordonnancement par deadline la plus proche parmi les éligibles.
3. **Test Anti-Famine (Wait Aging)** :
   - Maintien d'un thread basse priorité bloqué par une charge continue. Déclenchement de la promotion lorsque `wait_ticks >= MAX_WAIT_TICKS` et exécution garantie.
4. **Test Héritage de Priorité** :
   - Test unitaire validant `boost_priority` et `restore_priority`.
5. **Boot QEMU Bare-Metal** :
   - Démarrage complet avec bannière `JamboKernel v0.3.80 — Iron Core`.
   - Détection et activation des cœurs secondaires sans panique.
   - Validation de la ligne exacte :
     `[PASS] Ordonnanceur EEVDF et resilience SMP multicoeur valides sous QEMU.`


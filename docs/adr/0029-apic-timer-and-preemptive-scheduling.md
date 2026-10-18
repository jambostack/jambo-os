# ADR 0029: Programmation du Timer APIC Local & Ordonnancement Préemptif EEVDF

## Statut
Accepté (Phase 40 - Jalon v0.2.38)

## Contexte
Après la validation du saut en Ring 3 et du roundtrip d'appels système (ADR 0028, v0.2.37), JamboOS repose encore sur un modèle d'ordonnancement coopératif où les threads doivent volontairement appeler `ThreadYield` (Syscall 12) ou bloquer sur un IPC pour céder le processeur. Un thread malicieux ou bloqué dans une boucle de calcul infinie peut monopoliser le CPU indéfiniment.

Pour achever la transition vers un système d'exploitation moderne et résilient, le micro-noyau doit imposer la **préemption matérielle** :
1. **Source d'interruption périodique haute précision** : Configuration du Timer APIC Local (vecteur IDT 32, IRQ 0) en mode périodique avec division de fréquence matérielle.
2. **Gestionnaire d'interruption temps réel (ISR 32)** : Capture du tick d'interruption, envoi immédiat de l'acquittement EOI (*End Of Interrupt*) à l'APIC local et notification du sous-système d'ordonnancement.
3. **Mise à jour du temps virtuel EEVDF** : Incrémentation du temps virtuel (`vruntime`) du thread en cours d'exécution. Si le quantum alloué est dépassé (`vruntime >= deadline`), déclenchement d'une commutation de contexte préemptive.
4. **Commutation sous interruption & Restauration de contexte** : Sauvegarde de l'état complet du thread interrompu (`TrapFrame`), commutation des répertoires de pages `CR3` et mise à jour de la pile superviseur `TSS.rsp0` / `PerCpuData.kernel_stack_top` avant de restituer le processeur au thread élu.

## Décision
1. **Contrôleur APIC & Timer Local** (`kernel/src/arch/x86_64/apic.rs`) :
   - Prise en charge unifiée des modes xAPIC (MMIO) et x2APIC (MSR).
   - Méthodes `apic_start_timer(vector, initial_count)` et `apic_eoi()`.
   - Configuration du diviseur APIC par 16 et fréquence de tick calibrée pour QEMU (100 Hz / ~10 ms).
2. **Vecteur d'interruption 32 & Handler dans l'IDT** (`kernel/src/arch/x86_64/idt.rs`) :
   - Enregistrement de `isr32` dans l'IDT comme porte d'interruption 64-bit (0x8E).
   - Routage vers `timer_interrupt_handler` avec acquittement EOI systématique.
3. **Ordonnancement Préemptif EEVDF** (`kernel/src/sched/eevdf.rs`) :
   - Fonction `on_timer_tick()` avec `SCHEDULER.try_lock()` anti-interblocage pour incrémenter le quantum.
   - Si préemption nécessaire, bascule immédiate via `switch_context` avec mise à jour de CR3 et des pointeurs de pile superviseur.
4. **Validation Expérimentale Préemptive** (`kernel/src/sched/preempt_test.rs`) :
   - Lancement d'un thread de calcul non coopératif exécutant une boucle de spin infinie sans aucun appel système.
   - Validation que le timer APIC interrompt matériellement le thread et permet l'exécution du thread superviseur.

## Conséquences
- **Positives** :
  - Préemption matérielle garantie : aucun thread espace utilisateur ou superviseur ne peut monopoliser un cœur logique.
  - Équité stricte garantie par les garanties mathématiques de l'algorithme EEVDF (Earliest Eligible Virtual Deadline First).
  - Robustesse face aux boucles infinies et aux dénis de service (DoS).
- **Négatives / Arbitrages** :
  - Nécessite l'utilisation prudente de verrous réentrants ou avec interruption masquée dans les sections critiques de l'ordonnanceur.

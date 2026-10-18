# ADR 0028: Exécution en Espace Utilisateur, Transition Ring 3 & Aller-Retour Syscall

## Statut
Accepté (Phase 39 - Jalon v0.2.37)

## Contexte
Après la mise en place de l'archive d'amorçage Initrd et de la détection de modules Limine (ADR 0027, v0.2.36), le superviseur JamboOS dispose des binaires d'espace utilisateur en mémoire. Cependant, pour qu'un micro-noyau soit véritablement opérationnel, le matériel CPU doit franchir la frontière de privilège entre le superviseur (Ring 0 / EL1) et l'espace utilisateur non privilégié (Ring 3 / EL0).

Cette transition implique :
1. **Application stricte des privilèges de pagination (`PagingFlags::USER`)** : Les pages virtuelles de code et de pile du processus doivent être accessibles avec le niveau de privilège CPL = 3.
2. **Transition matérielle de niveau de privilège (`enter_user_mode`)** : Utilisation de l'instruction `IRETQ` avec les sélecteurs de segment GDT utilisateur `USER_CODE_SEL` (0x20 | 3 = 0x23) et `USER_DATA_SEL` (0x18 | 3 = 0x1B).
3. **Capture matérielle des appels système (`syscall` / `sysretq`)** :
   - Sauvegarde de `RIP` dans `RCX` et `RFLAGS` dans `R11`.
   - Échange de pile sécurisé via `swapgs` pour basculer de la pile utilisateur vers la pile noyau dédiée du thread (`PerCpuData.kernel_stack_top`).
   - Routage vers `dispatch_syscall` et retour déterministe en Ring 3 via `sysretq`.
4. **Aller-retour préemptif et commutation de contexte** : Validation formelle qu'un processus utilisateur peut émettre des syscalls (ex: `ThreadYield`, `ThreadExit`), céder le contrôle au superviseur et être repris sans altération de registres ou d'état.

## Décision
Nous implémentons le sous-système de validation et d'exécution Ring 3 (`kernel/src/sched/ring3_test.rs`) :
1. **Allocation et isolation mémoire Ring 3** :
   - Création d'un `AddressSpace` dédié avec PML4 cloné pour l'espace supérieur.
   - Mapping d'un VMO de code à `0x0040_0000` et d'une pile utilisateur de 16 Kio à `0x0000_7FFF_FFFF_0000 - 16 Kio`.
2. **Émission et exécution de bytecode x86-64 en Ring 3** :
   - Exécution séquentielle de `mov rax, 12; syscall` (`ThreadYield`) et `mov rax, 11; syscall` (`ThreadExit`).
3. **Gestion matérielle de l'aller-retour** :
   - Pointage de `TSS.rsp0` et `PerCpuData.kernel_stack_top` sur la pile superviseur du thread.
   - L'ordonnanceur EEVDF sauvegarde le thread superviseur appelant, bascule sur le thread Ring 3 via `enter_user_mode` (`iretq`), intercepte le syscall 12 via `syscall_entry`, restitue la main au thread superviseur, puis reprend le thread utilisateur via `sysretq` jusqu'à son `ThreadExit`.

## Conséquences
- **Positives** :
  - Preuve matérielle et mathématique du fonctionnement du saut Ring 0 $\to$ Ring 3 et du retour Ring 3 $\to$ Ring 0 sous QEMU.
  - La pile système, l'échange `swapgs` et l'instruction `sysretq` sont validés en conditions réelles d'exécution.
- **Négatives / Arbitrages** :
  - Requiert une synchronisation rigoureuse de la pile noyau dans `PerCpuData` avant chaque saut en mode utilisateur.

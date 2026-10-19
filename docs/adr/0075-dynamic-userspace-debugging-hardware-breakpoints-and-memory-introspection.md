# ADR 0075: Débogage Dynamique d'Espace Utilisateur, Registres de Points d'Arrêt Matériels DR0..DR7 & Introspection Mémoire (`jambo-dbg`)

## Statut
Accepté (Phase 86 - Jalon v0.2.84)

## Contexte
Dans l'écosystème d'ingénierie système souverain de JamboOS (`#![no_std]`), le diagnostic dynamique en temps réel, l'analyse d'incidents et l'inspection de processus Ring 3 sans modification statique du code source requièrent un sous-système de débogage souverain et sécurisé sous contrôle capabilaire :
1. **Gestion des exceptions matérielles de débogage (INT1 / #DB et INT3 / #BP)** :
   - Traitement des interruptions logicielles INT3 (`0xCC`) avec rembobinage automatique du pointeur d'instruction RIP vers l'adresse exacte du point d'arrêt, détection du point d'arrêt associé et notification de la session.
   - Restauration déterministe de l'octet d'instruction originel lors de la désactivation ou de la suppression du point d'arrêt.
   - Traitement des exceptions matérielles INT1 émises lors de l'activation des registres de points d'arrêt DR0..DR3 ou lors du pas à pas.
2. **Registres matériels de débogage x86-64 DR0..DR7** :
   - Prise en charge des registres DR0, DR1, DR2 et DR3 pour les points d'arrêt d'exécution et les points de surveillance mémoire (*Watchpoints* en écriture ou lecture/écriture).
   - Configuration précise du registre de contrôle DR7 (bits d'activation locale L0..L3, conditions RW0..RW3 et longueurs LEN0..LEN3 de 1, 2, 4 ou 8 octets).
   - Décodage instantané du registre d'état DR6 (détection des drapeaux B0..B3 pour les adresses matérielles et du drapeau BS pour l'interruption de pas à pas).
3. **Exécution pas à pas (*Single-Stepping*) matérielle** :
   - Manipulation du drapeau *Trap Flag* (TF, bit 8) dans le registre RFLAGS du thread supervisé.
   - Décodage compact de l'instruction courante (NOP, CALL, RET, JMP, SYSCALL, MOV) et avancée contrôlée du pointeur d'instruction.
4. **Introspection et modification de la mémoire virtuelle et des registres** :
   - Lecture et écriture sécurisées et bornées de la mémoire virtuelle d'un processus supervisé sous le contrôle des droits capabilaires `DBG_MEM_READ` et `DBG_MEM_WRITE`.
   - Inspection et modification de l'état complet des registres de threads utilisateur (RAX..R15, RIP, RSP, RBP, RFLAGS, CR2).
5. **Chaîne d'audit cryptographique inviolable SHA-256** :
   - Enregistrement séquentiel chaîné et scellé de toute action de débogage (attachement, détachement, insertion/suppression de points d'arrêt, pas à pas, lecture/écriture de mémoire et de registres).
   - Vérification mathématique d'intégrité interdisant toute injection clandestine ou altération malveillante.
6. **Modèle de sécurité capabilaire strict (`DbgCap`)** :
   - Droits granulaires sans autorité ambiante : `DBG_INSPECT`, `DBG_ATTACH`, `DBG_BREAKPOINT`, `DBG_STEP`, `DBG_MEM_READ`, `DBG_MEM_WRITE`, `DBG_REG_READ`, `DBG_REG_WRITE`, `DBG_AUDIT`, `DBG_ADMIN`.
   - Atténuation capabilaire sans amplification de privilèges.

## Décision
1. Implémentation du démon `JamboDebuggerDaemon` et des types associés (`DbgCap`, `DrSlot`, `DrCondition`, `DrLength`, `HardwareDrConfig`, `Dr6Status`, `ThreadRegisters`, `Breakpoint`, `DebugThread`, `DebugSession`, `MemoryRegion`) dans le module `services/jambo-dbg`.
2. Intégration de la commande `dbg` / `debugger` dans le shell interactif `services/jambo-sh` avec les sous-commandes `status`, `attach`, `detach`, `bp [add|del|list]`, `regs`, `mem`, `step`, `cont`, `digest`.
3. Écriture du module de test noyau `kernel/src/sched/dbg_test.rs` et inclusion dans la suite de validation de démarrage de `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.84` pour l'ensemble des modules du workspace.

## Conséquences
- Débogage dynamique et introspection mémoire à chaud sans autorité ambiante.
- Prise en charge transparente des points d'arrêt matériels (DR0..DR7) et logiciels (INT3).
- Traçabilité et intégrité cryptographique SHA-256 prouvée de toutes les opérations de diagnostic.

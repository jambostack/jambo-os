# ADR 0077: Filtrage d'Appels Système BPF Granulaire, Confinement par Application & Conformité POSIX (`jambo-seccomp`)

## Statut
Accepté (Phase 88 - Jalon v0.2.86)

## Contexte
Dans l'architecture du micro-noyau souverain JamboOS (`#![no_std]`), la minimisation de la surface d'attaque en Ring 3 requiert un sous-système de confinement granulaire au niveau des appels système, inspiré des garanties de Seccomp-BPF sous Linux et étendu au modèle capabilaire :
1. **Filtres BPF Classiques Étendus (cBPF / DAG)** :
   - Représentation structurée d'instructions BPF (`BpfInsn` : code, jt, jf, k).
   - Validateur formel vérifiant statiquement l'absence de boucles (terminaison stricte en O(N)), la validité des sauts strictement vers l'avant, l'interdiction de division par zéro et la présence d'une terminaison `BPF_RET`.
2. **Sémantique d'actions Seccomp normalisées** :
   - Actions granulaires : `SECCOMP_RET_ALLOW`, `SECCOMP_RET_KILL_PROCESS`, `SECCOMP_RET_KILL_THREAD`, `SECCOMP_RET_TRAP`, `SECCOMP_RET_ERRNO`, `SECCOMP_RET_LOG`, `SECCOMP_RET_USER_NOTIF`.
   - Modèle hiérarchique de sévérité : en cas d'évaluation multi-filtres, l'action la plus stricte (la plus restrictive) l'emporte obligatoirement.
3. **Confinement par thread et bit irréversible `no_new_privs`** :
   - Exigence stricte du bit `no_new_privs` pour interdire toute acquisition ou amplification ultérieure de privilèges.
   - Empilement de filtres par thread (`MAX_STACKED_FILTERS = 8`).
4. **Synchronisation atomique multi-threads de processus (`TSYNC`)** :
   - Synchronisation de la pile de filtres sur tous les threads appartenant au même processus cible (`SECCOMP_FILTER_FLAG_TSYNC`).
5. **Profils déclaratifs standard (`Strict`, `Compute`, `Network`)** :
   - Profil `Strict` : seuls read, write, exit, rt_sigreturn autorisés (KILL_PROCESS par défaut).
   - Profil `Compute` : strict + gestion mémoire brk, mmap, munmap (ERRNO par défaut).
   - Profil `Network` : sockets, connect, accept, sendto, recvfrom, read, write (ERRNO par défaut).
6. **Chaîne d'audit cryptographique inviolable SHA-256** :
   - Enregistrement séquentiel de chaque chargement, attachement, synchronisation TSYNC et violation d'appel système.
7. **Modèle de sécurité capabilaire strict (`SeccompCap`)** :
   - Droits granulaires sans autorité ambiante : `SECCOMP_READ`, `SECCOMP_LOAD`, `SECCOMP_ATTACH`, `SECCOMP_TSYNC`, `SECCOMP_AUDIT`, `SECCOMP_ADMIN`.
   - Atténuation capabilaire sans amplification possible.

## Décision
1. Implémentation du micro-service `services/jambo-seccomp` (`SeccompCap`, `BpfInsn`, `SeccompData`, `BpfProgram`, `FilterBuilder`, `JamboSeccompDaemon`).
2. Intégration de la commande `seccomp` dans le shell interactif `services/jambo-sh` (`status`, `list`, `load`, `attach`, `tsync`, `eval`, `audit`).
3. Écriture du module de test noyau `kernel/src/sched/seccomp_test.rs` et inclusion dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.86` pour l'ensemble des modules du workspace.

## Conséquences
- Confinement granulaire sans privilèges pour les applications Ring 3.
- Garantie formelle de terminaison et d'absence de boucles dans les filtres BPF.
- Conformité POSIX renforcée et traçabilité cryptographique SHA-256 intégrale.

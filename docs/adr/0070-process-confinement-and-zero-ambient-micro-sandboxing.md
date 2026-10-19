# ADR 0070: Confinement de Processus et Micro-Bacs à Sable Zero-Ambient (`jambo-sandd`)

## Statut
Accepté (Phase 81 - Jalon v0.2.79)

## Contexte
Dans une architecture de micro-noyau de 3e génération orienté capacités (`#![no_std]`), le principe de moindre privilège (*Least Privilege*) et l'absence d'autorité ambiante (*Zero-Ambient Authority*) sont des piliers fondamentaux.
Cependant, l'exécution de charges de travail hétérogènes et non fiables (modules WebAssembly, greffons tiers, processus réseau exposés, conteneurs non privilégiés) nécessite une couche de micro-isolation dynamique et déterministe, analogue aux sous-systèmes Seccomp et Landlock :
1. **Filtrage granulaire des appels système** :
   - Capacité de restreindre l'accès aux 28 appels système du noyau par masque binaire O(1) ultra-rapide.
   - Filtrage sémantique fin sur les arguments (valeur exacte, masque binaire, plage de valeurs, inégalités) pour des appels sensibles tels que `VmoMap` (interdiction d'écriture W^X) ou `ChannelCall`.
   - Actions configurables par règle : `Allow`, `Deny(SysError)`, `Trap`, `Kill`, `LogAndAllow`.
2. **Arbre hiérarchique de profils et Invariant de resserrement monotone** :
   - Les profils de restriction s'organisent en arbre de dérivation (ex: `Strict`, `ComputeOnly`, `NetworkWorker`, `UntrustedPlugin`).
   - Un profil enfant dérivé d'un parent ne peut **JAMAIS** assouplir ou élargir les droits accordés par son ascendant (`(child_mask & !parent_mask) == 0`). Toute tentative d'amplification est rejetée avec `SysError::PermissionDenied`.
   - Préservation stricte du drapeau `no_new_privs`.
3. **Confinement de chemins et ressources Landlock-like** :
   - Restriction des accès au système de fichiers et chemins VFS par correspondance de préfixes.
   - Masque de droits granulaires (`READ`, `WRITE`, `EXECUTE`, `CREATE`, `DELETE`).
   - Tout chemin non explicitement couvert par une règle est interdit par défaut (*Deny-by-default*).
4. **Modèle capabilaire strict (`SandCap`)** :
   - Droits granulaires : `SAND_INSPECT`, `SAND_CREATE`, `SAND_APPLY`, `SAND_RESTRICT`, `SAND_KILL`, `SAND_AUDIT`, `SAND_ADMIN`.
   - Atténuation formelle sans amplification de privilèges.
5. **Audit cryptographique inviolable SHA-256** :
   - Anneau circulaire borné à 64 violations historiques horodatées avec PID, syscall et action corrective.
   - Condensat cryptographique SHA-256 scellant l'état des profils, bacs à sable et violations.

## Décision
1. Implémentation du démon `JamboSandDaemon` et des structures associées (`SandCap`, `SandboxProfile`, `SandboxInstance`, `SyscallRule`, `LandlockPathRule`, `SandboxViolation`) dans `services/jambo-sandd`.
2. Intégration de la commande `sand` / `sandbox` dans le shell objet interactif `services/jambo-sh`.
3. Écriture du module de test noyau `kernel/src/sched/sandd_test.rs` et activation dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.79` pour l'ensemble des modules du workspace.

## Conséquences
- Confinement hermétique des charges non fiables avec zéro fuite d'autorité ambiante.
- Preuve formelle d'atténuation et de non-amplification des privilèges à travers la hiérarchie de bacs à sable.
- Observabilité et traçabilité inaltérables des tentatives de violation de confinement.

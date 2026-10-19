# ADR 0072: Capture d'État Post-Mortem, Crash Dumps ELF Scellés et Télémétrie Post-Crash (`jambo-cored`)

## Statut
Accepté (Phase 83 - Jalon v0.2.81)

## Contexte
Dans une architecture de micro-noyau robuste et orientée capacités (`#![no_std]`), la survenance d'une faute critique non récupérable (faute de page invalide, panique noyau, violation de protection générale, instruction illégale ou expiration de chien de garde) exige une conservation immédiate, déterministe et inviolable de l'état système pour l'analyse forensique post-mortem et l'auto-guérison de la grappe :
1. **Capture d'état multi-architectures déterministe** :
   - Sauvegarde structurée de l'ensemble des registres CPU d'exécution pour x86-64 (`X86_64Registers` : RIP, RSP, RBP, RAX, CR2, CR3, RFLAGS, sélecteurs de segments) et ARM64 (`AArch64Registers` : X0..X30, SP, PC, PSTATE, Fault Address, ESR).
   - Échantillonnage de la pile d'exécution (jusqu'à 256 octets) et extraction de la trace d'appels (*Call Trace* / backtrace).
2. **Génération de fichiers Core Dump conformes à la spécification binaire ELF64** :
   - Format standard `ET_CORE` (type 4), machine `EM_X86_64` (62) ou `EM_AARCH64` (183).
   - Segments de notes `PT_NOTE` structurés contenant `NT_PRSTATUS` (signal, pid, registres complets), `NT_PRPSINFO` (nom de l'exécutable, état d'exécution) et `NT_SIGINFO` (numéro de signal POSIX/Jambo, adresse de faute).
   - Segments mémoires `PT_LOAD` encapsulant l'instantané de la pile et des VMO mappées avec projection exacte des drapeaux `PF_R`, `PF_W` et `PF_X`.
3. **Scellement cryptographique inviolable & Détection de falsification** :
   - Condensat cryptographique SHA-256 scellant en continu chaque rapport de crash et son binaire ELF associé.
   - Détection formelle et immédiate de toute altération de contenu en mémoire ou en transit.
4. **Confinement & Mise en quarantaine immédiate de la mémoire** :
   - Isolation des pages mémoire associées au processus crashé pour prévenir toute réallocation prématurée, contamination inter-domaines ou exploitation de failles post-crash.
5. **Télémétrie post-crash et recommandations d'auto-guérison** :
   - Dispatching de métriques et alertes pour le superviseur PID 1 (`jambo-init`) et l'orchestrateur de grappe (`jambo-schedd`).
   - Recommandations automatisées adaptées à la gravité du crash (`RestartProcess`, `IsolateAndRespawnService`, `NodeFailover`, `KernelPanicHalt`, `QuarantineOnly`).
6. **Modèle de sécurité capabilaire strict (`CoreCap`)** :
   - Droits granulaires : `CORE_INSPECT`, `CORE_CAPTURE`, `CORE_GENERATE`, `CORE_SEAL`, `CORE_QUARANTINE`, `CORE_TELEMETRY`, `CORE_PURGE`, `CORE_ADMIN`.
   - Atténuation capabilaire sans amplification de privilèges.

## Décision
1. Implémentation du démon `JamboCoreDaemon` et des structures associées (`CoreCap`, `ArchRegisters`, `CrashReason`, `CoreMemoryRegion`, `Elf64Generator`, `SealedCrashReport`, `PostCrashTelemetry`) dans `services/jambo-cored`.
2. Intégration de la commande `core` / `corectl` dans le shell interactif `services/jambo-sh` avec les sous-commandes `status`, `list`, `view`, `quarantine`, `telemetry`, `verify`, `elf`, `digest`.
3. Écriture du module de test noyau `kernel/src/sched/cored_test.rs` et intégration dans la boucle de test de `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.81` pour l'ensemble des modules du workspace.

## Conséquences
- Disponibilité immédiate de crash dumps ELF64 exploitables par les outils forensiques sans arrêt forcé du noyau.
- Détection et confinement étanche des pannes mémoire évitant la corruption en cascade.
- Traçabilité cryptographique garantie par le registre d'audit chaîné SHA-256.

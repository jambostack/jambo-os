# ADR 0074: Échantillonnage de Compteurs de Performance Matérielle (PMC/PEBS), Profils de Flammes et Analyse de Latence Ring 3 (`jambo-profilerd`)

## Statut
Accepté (Phase 85 - Jalon v0.2.83)

## Contexte
Dans les micro-noyaux souverains de 3e génération orientés capacités (`#![no_std]`) et les systèmes distribués haute performance sous JamboOS, l'observabilité fine de l'exécution, l'optimisation des chemins critiques et la détection des goulots d'étranglement matériels nécessitent des mécanismes de profilage continu à faible surcharge (*Low-Overhead Continuous Profiling*) :
1. **Échantillonnage de compteurs de performance matérielle (PMC & PEBS)** :
   - Capture périodique et par interruption des compteurs processeur : instructions retirées (`Instructions`), cycles processeur (`CpuCycles`), cycles de référence, fautes de cache L1D / L1I / LLC (Last Level Cache), fautes TLB (`dTLB`/`iTLB`), prédictions et défauts de branchement (`BranchMisses`), et cycles de gel du pipeline (`StallCycles`).
   - Prise en charge de l'échantillonnage précis d'événements PEBS (Processor Event-Based Sampling) sur x86-64 et PMCCNTR_EL0/PMEVTYPER sur ARM64, capturant l'adresse d'instruction exacte et les adresses de données linéaires sans dérive d'interruption (*Interrupt Skid*).
2. **Arbre d'appels (Call Graph) et Profils de Flammes (*Flamegraphs*)** :
   - Déroulement non-intrusif de la pile d'exécution (*Frame Pointer Walking*) jusqu'à 16 niveaux d'empilement.
   - Résolution déterministe d'adresses virtuelles vers les symboles d'espace utilisateur (`main`, `vfs_read`, `ipc_send_msg`, `slub_allocate`, `sha256_compress_block`, etc.).
   - Agrégation hiérarchique en nœuds d'arbre d'appels (`FlameNode`) et format compact *folded stacks* pour l'analyse visuelle de l'utilisation CPU.
3. **Analyse statistique de distribution de latence (p50, p90, p99, p99.9)** :
   - Mesure temporelle haute précision en nanosecondes des transitions critiques : commutations de contexte (`ContextSwitch`), traitement des interruptions matérielles (`InterruptHandler`), dispatch d'appels système (`SyscallDispatch`), transferts IPC asynchrones et synchrones (`IpcTransfer`), et accès VFS (`VfsIo`).
   - Calcul sans allocation dynamique de la latence minimale, maximale, moyenne et des percentiles p50 (médiane), p90, p99 et p99.9 via tri sur pile bornée.
4. **Scellement cryptographique et Registre d'audit SHA-256** :
   - Génération de rapports structurés `ProfileReport` intégrant compteurs PMC, ratios IPC, détection du goulot d'étranglement principal et résumé de latence.
   - Scellement cryptographique inviolable par condensat SHA-256 garantissant l'intégrité formelle des métriques de performance face aux attaques par falsification de télémétrie.
   - Registre d'audit séquentiel chaîné enregistrant chaque étape (`Configure`, `Sample`, `LatencyRecord`, `GenerateReport`, `VerifyReport`, `Reset`).
5. **Modèle de sécurité capabilaire strict (`ProfileCap`)** :
   - Droits granulaires sans autorité ambiante : `PROFILE_INSPECT`, `PROFILE_CONFIGURE`, `PROFILE_SAMPLE`, `PROFILE_COLLECT`, `PROFILE_EXPORT`, `PROFILE_AUDIT`, `PROFILE_ADMIN`.
   - Atténuation capabilaire sans amplification de privilèges.

## Décision
1. Implémentation du démon `JamboProfilerDaemon` et des structures associées (`ProfileCap`, `PmcConfig`, `PmcSample`, `PebsRecord`, `FlameNode`, `LatencyRecord`, `LatencyStats`, `ProfileReport`, `SealedAuditEntry`) dans `services/jambo-profilerd`.
2. Intégration de la commande `profiler` / `perfctl` dans le shell interactif `services/jambo-sh` avec les sous-commandes `status`, `pmc`, `sample`, `flame`, `latency`, `report`, `verify`, `digest`.
3. Écriture du module de test noyau `kernel/src/sched/profilerd_test.rs` et inclusion dans la suite de validation de `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.83` pour l'ensemble des modules du workspace.

## Conséquences
- Observabilité matérielle précise sans autorité ambiante dans Ring 3.
- Détection immédiate des régressions de latence et des congestions de cache/branchement.
- Intégrité cryptographique prouvée de tous les profils de performance générés.

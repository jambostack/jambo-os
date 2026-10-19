# ADR 0073: Rechargement à Chaud en Espace Utilisateur, Injection Atomique de Trampolines et Conformité ABI (`jambo-patchd`)

## Statut
Accepté (Phase 84 - Jalon v0.2.82)

## Contexte
Dans les systèmes distribués haute disponibilité et les infrastructures critiques pilotées par JamboOS, le redémarrage des services d'espace utilisateur (*Ring 3*) pour l'application de correctifs de sécurité critiques (CVE), d'optimisations algorithmiques ou de résolutions de bugs entraîne une rupture de session, une invalidation de caches et une dégradation temporaire de la qualité de service. Le micro-noyau orienté capacités (`#![no_std]`) exige une solution formelle de mise à jour à chaud (*Livepatching*) garantissant une innocuité totale :
1. **Remplacement atomique de symboles et fonctions exécutables à chaud** :
   - Redirection immédiate du flot d'exécution au point d'entrée d'une fonction vers un code de remplacement sans interruption de service.
   - Génération dynamique de trampolines multi-architectures : sauts relatifs x86-64 `0xE9 rel32` (5 octets) pour les sauts dans un rayon de +-2 Gio, sauts indirects x86-64 absolus `0xFF 0x25 <u64>` (14 octets), sauts directs ARM64 `B imm26` (4 octets) et sauts indirects ARM64 `LDR X16, #8; BR X16; <u64>` (16 octets).
2. **Quiescence des threads et barrière de synchronisation sans interblocage** :
   - Analyse dynamique du pointeur d'instruction (`RIP`/`PC`) de chaque thread enregistré pour le processus cible.
   - Confinement et détection des threads situés dans la zone critique du trampoline `[target_vaddr, target_vaddr + trampoline_len)`.
   - Suspension sécurisée et attente active ou passive jusqu'à l'atteinte d'un état de quiescence formelle avant toute modification de la mémoire d'instructions.
3. **Vérification statique et dynamique de conformité ABI** :
   - Contrôle strict des conventions d'appel System V AMD64 ABI et ARM64 AAPCS.
   - Validation de la longueur minimale du prologue pour prévenir la troncature accidentelle d'instructions multi-octets.
   - Vérification de l'alignement strict de la pile (16 octets) et de l'alignement des adresses d'instruction pour ARM64 (multiple de 4).
   - Détection d'instructions dangereuses au point d'injection (ex: `RET` immédiat, branchements relatifs tronqués).
4. **Préservation d'état des VMO et mécanisme de restauration atomique (*Rollback*)** :
   - Conservation inaltérable du prologue d'origine (jusqu'à 16 octets) dans le descripteur de patch.
   - Restauration atomique garantie en cas d'anomalie post-déploiement sans perte de données ni altération de l'état des objets VMO.
5. **Scellement cryptographique inviolable & Registre d'audit SHA-256** :
   - Calcul d'un condensat SHA-256 scellant l'ensemble des métadonnées du patch (adresses, hashs de code, trampolines, timestamps).
   - Registre d'audit en chaîne chaînant chaque action (`Prepare`, `Quiesce`, `Apply`, `Revert`, `Verify`) pour une traçabilité totale et la détection immédiate de falsifications en mémoire.
6. **Modèle de sécurité capabilaire strict (`PatchCap`)** :
   - Droits granulaires : `PATCH_INSPECT`, `PATCH_PREPARE`, `PATCH_QUIESCE`, `PATCH_APPLY`, `PATCH_REVERT`, `PATCH_AUDIT`, `PATCH_ADMIN`.
   - Atténuation capabilaire sans amplification de privilèges.

## Décision
1. Implémentation du démon `JamboPatchDaemon` et de ses composants associés (`PatchCap`, `TrampolineGenerator`, `AbiComplianceChecker`, `PatchRecord`, `TargetThread`, `SealedAuditEntry`) dans `services/jambo-patchd`.
2. Intégration de la commande `patch` / `patchctl` dans le shell interactif `services/jambo-sh` avec les sous-commandes `status`, `list`, `view`, `quiesce`, `apply`, `revert`, `verify`, `digest`.
3. Écriture du module de test noyau `kernel/src/sched/patchd_test.rs` et intégration dans la boucle de test de `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.82` pour l'ensemble des modules du workspace.

## Conséquences
- Déploiement instantané de correctifs de sécurité sans redémarrage des démons Ring 3.
- Garantie formelle d'intégrité mémoire grâce à la synchronisation par quiescence des threads.
- Traçabilité cryptographique garantie par le registre d'audit chaîné SHA-256.

# ADR 0079: Confinement du Système de Fichiers sans Autorité Ambiante & Sandboxing Monotone (`jambo-landlock`)

## Statut
Accepté (Phase 90 - Jalon v0.2.88)

## Contexte
Dans l'architecture de micro-noyau orienté capacités de JamboOS (`#![no_std]`), la sécurité des processus non privilégiés et des démons isolés repose sur le principe de moindre privilège sans autorité ambiante. Le sous-système de sandboxing de système de fichiers `jambo-landlock` résout le problème de confinement VFS granulaire :
1. **Élimination de l'Autorité Ambiante** :
   - Tout accès au système de fichiers est restreint à des sous-arborescences déclarées (`path_beneath`) ancrées sur des descripteurs VFS (`parent_handle`).
   - L'algorithme de résolution hiérarchique évalue formellement la position du chemin cible par rapport aux ancres autorisées sans autorité ambiante.
2. **Masques de Permissions Granulaires (`fs_access`)** :
   - Distinction formelle entre opérations de lecture (`READ_FILE`, `READ_DIR`), d'écriture (`WRITE_FILE`, `REMOVE_DIR`, `REMOVE_FILE`, `MAKE_REG`, `MAKE_DIR`, etc.) et d'exécution (`EXECUTE`).
3. **Empilement de Couches de Restriction Monotones (`LandlockLayer` / `LandlockDomain`)** :
   - Chaque appel à `restrict_self` ajoute une nouvelle couche de règles au domaine du processus.
   - **Propriété d'intersection stricte et monotonie** : Une opération demandée n'est accordée que si TOUTES les couches empilées l'autorisent ($Domain_{k+1} = Domain_k \cap Ruleset_{k+1}$).
   - **Irréversibilité** : Une couche empilée ne peut jamais être retirée, ni élargir des droits interdits par une couche précédente (interdiction mathématique de déconfinement).
4. **Héritage Automatique de Confinement (`inherit_domain`)** :
   - Tout fil d'exécution ou processus créé par clonage/fork hérite de l'intégralité des couches empilées du parent.
5. **Gouvernance Capabilaire (`LandlockCap`)** :
   - Droits granulaires (`RULESET_CREATE`, `RULE_ADD`, `RESTRICT_SELF`, `AUDIT`, `ADMIN`).
   - Atténuation stricte avec rejet d'amplification d'autorité.
6. **Registre d'Audit Scellé SHA-256** :
   - Traçabilité cryptographique inviolable chaînée par condensats SHA-256 pour chaque création de ruleset, restriction de domaine et violation de politique.

## Décision
1. Implémentation du service `services/jambo-landlock` (`LandlockCap`, `LandlockRuleset`, `LandlockLayer`, `LandlockDomain`, `PathBeneathRule`, `JamboLandlockDaemon`).
2. Intégration de la commande `landlock` dans `services/jambo-sh` (`status`, `domains`, `rulesets`, `check`, `audit`).
3. Écriture du module de test d'intégration noyau `kernel/src/sched/landlock_test.rs` et inclusion dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.88` pour l'ensemble des modules du workspace.

## Conséquences
- Isolation étanche des processus applicatifs et démons système au niveau VFS.
- Prévention radicale des compromissions latérales et de l'exfiltration de fichiers hors des répertoires accordés.
- Confinement autonome et traçable mathématiquement vérifié sous QEMU.

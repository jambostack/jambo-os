# ADR 0034: Pipelines d'Objets Structurés & Utilitaires Système Confinés (`jambo-coreutils`)

## Statut
Accepté (Phase 45 - Jalon v0.2.43)

## Contexte
Après l'implémentation de la pile réseau modulaire en espace utilisateur (`jambo-netd`, ADR 0033, v0.2.42), JamboOS franchit une étape charnière dans l'ergonomie et la sécurité de son espace utilisateur : le remplacement des flux textuels bruts traditionnels (Unix pipes) par des **Pipelines d'Objets Structurés** (*Object Pipelines*) combinés à des utilitaires système natifs confinés par capacités (`services/jambo-coreutils`).

Dans les systèmes monolithiques conventionnels, les pipelines de shell (`|`) reposent sur des flux d'octets textuels non structurés (`stdout` -> `stdin`), nécessitant des analyseurs syntaxiques fragiles (`grep`, `awk`, `sed`) sujets aux failles d'injection et aux incohérences de formatage.

Dans JamboOS :
1. **Pipelines d'Objets Typés (`StructuredPipeline`, `ObjectRecord`)** :
   - Échange d'enregistrements en mémoire sans désérialisation non sécurisée ni allocation dynamique non bornée (`MAX_PIPELINE_RECORDS = 16`).
   - Variantes typées natives : `ObjectRecord::Process`, `ObjectRecord::Capability`, `ObjectRecord::FileEntry`, `ObjectRecord::Metric`.
2. **Utilitaires Système Confinés (`services/jambo-coreutils`)** :
   - `CmdPs` : Énumération structurée des tâches système (`PID`, `Name`, `State`, `Threads`, `Caps`, `MemoryPages`) sous forme d'un `StructuredPipeline`.
   - `CmdCapStat` : Audit et inspection de la table des capacités (`CSpace`) d'un processus (`VMO`, `Channel`, `IommuDomain`, `NetCap`) avec affichage des droits binaires.
   - `CmdFilter` : Filtrage prédictif d'objets structurés dans un pipeline (`--min-caps`, `--min-mem`, `--prefix`).
   - `CmdTop` : Statistiques d'ordonnancement en temps réel (pourcentage d'utilisation CPU, pages physiques libres du PMM Buddy Allocator, allocations du SLUB Slab Allocator).
   - `CmdJpkg` : Vérification d'intégrité cryptographique BLAKE3 de paquets logiciels immuables.
   - `CmdCat` : Lecture confinée de ressources via le jeton de capacité `ArgumentCapability` (rejet immédiat `SysError::PermissionDenied` si le droit `cap_rights::READ` fait défaut).
3. **Intégration Shell `jsh`** :
   - Prise en charge native de la syntaxe de pipeline `|` (`ps | filter --min-caps 8`, `ps | filter --min-mem 32`, `ps | filter --prefix jambo`).
   - Commandes interactives dédiées : `capstat <pid>`, `top`, `jpkg verify <pkg>`.
4. **Harnais de Validation Automatisée** (`kernel/src/sched/coreutils_test.rs`) :
   - Validation du cycle complet de production, filtrage et rendu d'objets.
   - Confinement strict sans autorité ambiante pour la lecture de données.
   - Exécution sous QEMU des commandes shell unitaires et chaînées par pipeline.

## Décision
1. Découplage de `jambo-coreutils` vis-à-vis de `jambo-sh` en déplaçant les structures `ArgumentCapability`, `ObjectRecord`, et `StructuredPipeline` au sein de `jambo-coreutils`.
2. Intégration de `jambo-coreutils` dans `jambo-sh` avec l'implémentation de `execute_pipeline()` et des commandes `capstat`, `top`, `jpkg`.
3. Création du module de validation `kernel/src/sched/coreutils_test.rs`.
4. Validation sous QEMU et publication de la version `v0.2.43`.

## Conséquences
- Élimination des erreurs d'interprétation textuelle dans les chaînes de traitement du shell.
- Confinement strict des accès aux fichiers et ressources selon le principe du moindre privilège (*Least Privilege*).
- Transparence et observabilité totales de la CSpace des processus pour l'administrateur système.

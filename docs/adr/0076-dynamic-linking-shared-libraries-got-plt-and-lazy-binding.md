# ADR 0076: Édition de Liens Dynamiques Ring 3, Bibliothèques Partagées ELF64 .jso, Tables GOT/PLT & Résolution Différée (`jambo-dynlinkd`)

## Statut
Accepté (Phase 87 - Jalon v0.2.85)

## Contexte
Dans l'écosystème d'ingénierie système souverain de JamboOS (`#![no_std]`), l'exécution efficace d'applications modulaires en espace utilisateur sans duplication inutile de code mémoire requiert un éditeur de liens dynamiques souverain (*Dynamic Linker / Loader*) sous contrôle capabilaire strict :
1. **Bibliothèques partagées ELF64 (`.jso` / *Jambo Shared Objects*)** :
   - Prise en charge des fichiers binaires dynamiques ELF64 (`ET_DYN`) avec segments de charge `PT_LOAD` et segment dynamique `PT_DYNAMIC`.
   - Traitement des balises dynamiques System V AMD64 : `DT_NEEDED` (dépendances inter-modules), `DT_SYMTAB`, `DT_STRTAB`, `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, `DT_PLTGOT`, `DT_JMPREL`, `DT_INIT`, `DT_FINI`, `DT_BIND_NOW`.
2. **Tables Globales de Décalage (GOT) et Tables de Liaison de Procédures (PLT)** :
   - Emplacement protégé pour les adresses résolues de fonctions et variables externes.
   - Entrées réservées `GOT[0]` (descripteur de module / link_map), `GOT[1]` (identifiant de bibliothèque) et `GOT[2]` (trampoline vers le résolveur dynamique).
   - Stubs PLT permettant l'appel indirect sécurisé à travers la GOT.
3. **Résolution différée (*Lazy Binding*) vs Liaison immédiate (*BIND_NOW*)** :
   - Mode paresseux (*Lazy*) : initialisation des entrées GOT pointant vers le stub PLT résolveur, résolution à la première invocation puis mise à jour atomique de l'entrée GOT.
   - Mode immédiat (*Immediate / BIND_NOW*) : résolution de toutes les relocations PLT dès le chargement du module.
4. **Application des protections mémoire W^X et durcissement RELRO** :
   - Application de la politique Write XOR Execute (W^X).
   - Scellement RELRO (*Read-Only Relocations*) : passage en lecture seule irréversible de la table GOT une fois les relocations terminées, interdisant toute tentative ultérieure d'altération malveillante.
5. **Gestion du cycle de vie des bibliothèques (`dlopen` / `dlclose`)** :
   - Graphe de dépendances ordonné, comptage de références et protection contre le déchargement non désiré via le drapeau `RTLD_NODELETE`.
6. **Chaîne d'audit cryptographique inviolable SHA-256** :
   - Traçabilité totale et scellement séquentiel chaîné de chaque chargement, relocation, résolution différée et durcissement RELRO.
7. **Modèle de sécurité capabilaire strict (`DynLinkCap`)** :
   - Droits granulaires sans autorité ambiante : `DYNLINK_READ`, `DYNLINK_LOAD`, `DYNLINK_BIND`, `DYNLINK_RESOLVE`, `DYNLINK_RELRO`, `DYNLINK_UNLOAD`, `DYNLINK_AUDIT`, `DYNLINK_ADMIN`.
   - Atténuation capabilaire sans amplification de privilèges.

## Décision
1. Implémentation du démon `JamboDynLinkDaemon` et des types associés (`DynLinkCap`, `SharedLibrary`, `GotTable`, `PltTable`, `PltEntry`, `RelocationEntry`, `SymbolEntry`, `Elf64Ehdr`, `Elf64Phdr`, `Elf64Dyn`, `Elf64Sym`, `Elf64Rela`) dans le module `services/jambo-dynlinkd`.
2. Intégration des commandes `dynlink` et `ldd` dans le shell interactif `services/jambo-sh` avec les sous-commandes `status`, `list`, `load`, `resolve`, `lazy`, `relro`, `unload`, `ldd`, `digest`.
3. Écriture du module de test noyau `kernel/src/sched/dynlink_test.rs` et inclusion dans la suite de validation de démarrage de `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.85` pour l'ensemble des modules du workspace.

## Conséquences
- Édition de liens dynamiques Ring 3 et partage efficace de bibliothèques `.jso` sans autorité ambiante.
- Protection mémoire W^X renforcée via le scellement RELRO de la table GOT.
- Traçabilité et intégrité cryptographique SHA-256 prouvée de toutes les résolutions de symboles.

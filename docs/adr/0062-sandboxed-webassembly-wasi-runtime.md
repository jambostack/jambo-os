# ADR 0062: Moteur d'Exécution Sandboxed WebAssembly `#![no_std]` & WASI (`jambo-wasm`)

## Statut
Accepté (Phase 73 - Jalon v0.2.71)

## Contexte
L'exécution de code tiers non fiable et d'extensions applicatives au sein d'un micro-noyau souverain orienté capacités requiert un environnement de bac à sable (*sandbox*) formellement étanche, économe en mémoire et dénué de toute autorité ambiante. Avec `services/jambo-wasm`, JamboOS se dote d'un interpréteur WebAssembly V1 `#![no_std]` complet :

1. **Confinement Capabilaire d'Exécution (`WasmCap`)** :
   - L'instanciation, la manipulation mémoire et l'accès aux interfaces système sont conditionnés par un jeton de capacité `WasmCap`.
   - Droits granulaires (`WASM_EXEC`, `WASM_MEM_GROW`, `WASM_WASI_IO`, `WASM_WASI_TIME`, `WASM_INSTANTIATE`, `WASM_ADMIN`).
   - Quotas dynamiques stricts de mémoire (`max_pages`) et de budget de calcul (`max_gas`) avec atténuation vérifiée interdisant toute amplification de privilèges.

2. **Isolation Stricte de la Mémoire Linéaire (Bounds Checking)** :
   - Mémoire linéaire sandboxed (`WasmLinearMemory`) bornée à 4096 octets (1 page active) pour préserver l'empreinte de la pile système.
   - Opérations de chargement et d'écriture mémoire (`load_i32`, `store_i32`, `load_u8`, `store_u8`, `write_memory`, `read_memory`) interceptant tout accès hors-bornes par un piège immédiat `SysError::BadAddress`.
   - Agrandissement mémoire (`grow`) contrôlé sous autorisation expresse `WASM_MEM_GROW` et plafond `max_pages`.

3. **Machine à Pile WebAssembly V1 & Gas Metering Déterministe** :
   - Interpréteur complet de pile d'opérandes (`MAX_STACK_DEPTH = 64`) et de variables locales (`MAX_LOCALS = 16`).
   - Support des opcodes standards : arithmétique (`i32.add`, `sub`, `mul`, `div_s`, `div_u`, `rem_s`), logique binaire (`and`, `or`, `xor`, `shl`, `shr_s`, `shr_u`), comparaisons (`eqz`, `eq`, `ne`, `lt_s`, `lt_u`, `gt_s`), contrôle de flot (`block`, `loop`, `br`, `br_if`, `return`, `end`, `select`, `drop`) et constantes signées LEB128 (`i32.const`).
   - Décompte systématique de gaz d'instruction prévenant les boucles infinies et les dénis de service par arrêt déterministe (`SysError::ResourceBusy`).

4. **Couche WASI Preview 1 Confinée** :
   - Liaison des descripteurs d'E/S (`wasi_fd_write_with_cap`, `wasi_fd_read_with_cap`) soumise au droit `WASM_WASI_IO`.
   - Accès horloge déterministe (`wasi_clock_time_get_with_cap`) conditionné par `WASM_WASI_TIME`.

5. **Commandes Shell Interactives `wasm` dans `jsh`** :
   - `wasm status` / `wasm info` : télémétrie de la sandbox, statut WasmCap et quotas de gaz.
   - `wasm run <module>` : exécution de modules Wasm avec rapport du code retour et gaz consommé.
   - `wasm test` : exécution de la suite de modules binaires de validation (`add.wasm`, `mem.wasm`).

6. **Harnais de Validation Noyau (`kernel/src/sched/wasm_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 73) de l'atténuation `WasmCap`, du parsing de sections binaires Wasm, de l'exécution sur pile (`add(15, 27) = 42`), des opérations mémoire (`mem_test(32) = 42`), de l'interception des traps (débordement mémoire et épuisement de gaz), des permissions WASI et des commandes shell.

## Décision
1. Implémentation du moteur Wasm complet, de `WasmCap`, du gas metering et des modules de test dans `services/jambo-wasm/src/lib.rs`.
2. Intégration dans `services/jambo-sh/src/lib.rs` des commandes étendues `wasm [status | run | test]`.
3. Création du banc de test noyau `kernel/src/sched/wasm_test.rs` et branchement dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.71` sur l'ensemble de l'espace de travail.

## Conséquences
- Disponibilité d'un exécuteur WebAssembly sandboxed natif et souverain `#![no_std]` pour charges isolées.
- Garantie de sécurité matérielle et logicielle contre les dépassements de mémoire linéaire et les épuisements de CPU.

# ADR 0036: Couche de Compatibilité Linux POSIX (`jambo-linux`) & Runtime Sandboxed WASI/Wasm (`jambo-wasm`)

## Statut
Accepté (Phase 47 - Jalon v0.2.45)

## Contexte
Après la stabilisation du compositeur graphique Ring 3 et de JamboUI (ADR 0035, v0.2.44), JamboOS intègre l'exécution d'applications hétérogènes sans introduire la moindre dette POSIX dans le Ring 0 :
1. **Couche de Traduction POSIX en Espace Utilisateur (`services/jambo-linux`)** :
   - Émulateur d'appels système Linux x86-64 (`LinuxProcessEmulator`) traduisant les requêtes POSIX (`read`, `write`, `open`, `close`, `mmap`, `brk`, `getpid`, `uname`, `exit`) en requêtes de capacités sur le micro-noyau JamboKernel.
   - Confinement strict des descripteurs de fichiers (`PosixFd`) indexés par des handles de capacités CSpace (stdin R/O, stdout W/O, pas d'autorité ambiante).
   - Point d'entrée `emulate_linux_elf_binary` permettant l'exécution sandboxée de binaires ELF Linux statiques.
2. **Moteur d'Exécution WebAssembly & Sandbox WASI (`services/jambo-wasm`)** :
   - Mémoire linéaire isolée (`WasmLinearMemory`) avec vérification stricte des bornes d'adresses (rejet immédiat de tout débordement mémoire avec `SysError::BadAddress`).
   - Moteur WASM (`WasmEngine`) vérifiant l'intégrité du bytecode standard (Magic `\0asm`, Version 1) et comptabilisant les ressources via **Gas Metering**.
   - Shims des imports système WASI (`wasi_fd_write`, `wasi_clock_time_get`, `wasi_proc_exit`) relayés de manière sécurisée vers les capacités JamboOS.
   - Point d'entrée `execute_wasm_module` pour l'exécution confinée de modules WebAssembly.
3. **Commandes Shell `compat` et `wasm` dans `jsh`** :
   - `compat status` : statut de la couche de traduction Linux x86-64.
   - `compat run <elf>` : émulation et exécution d'un binaire ELF avec compte-rendu des syscalls interceptés.
   - `wasm info` : statut du runtime WASI sandboxed.
   - `wasm run <module>` : exécution d'un module WebAssembly avec comptage de gaz.
4. **Harnais de Validation Automatisée** (`kernel/src/sched/compat_test.rs`) :
   - Validation de l'isolation des descripteurs de fichiers POSIX et des shims syscalls.
   - Validation du cycle de vie des binaires ELF Linux synthétiques.
   - Validation de la protection de la mémoire linéaire WASM et du gas metering.
   - Validation des commandes interactives du shell `jsh`.

## Décision
1. Intégration de `jambo-linux` et `jambo-wasm` dans `jambo-sh` avec l'implémentation des commandes `compat` et `wasm`.
2. Ajout des dépendances dans `kernel/Cargo.toml` et création de `kernel/src/sched/compat_test.rs`.
3. Validation complète sous QEMU (Phase 47) et publication de la version `v0.2.45`.

## Conséquences
- Compatibilité binaire Linux x86-64 et portabilité WASM universelle sans compromettre la sécurité par capacités ni l'architecture micro-noyau.
- Protection mémoire formelle et isolation matérielle contre les modules non fiables.

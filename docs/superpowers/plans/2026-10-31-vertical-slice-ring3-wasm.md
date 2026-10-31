# Plan d'Implémentation — Jalon 3.2 : Exécution de Microservices WebAssembly / WASI en Ring 3 (PID 7), Runtime `jambo-wasmd` & Commandes `wasm` (v0.3.46)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.46`  
**Statut :** PROPOSÉ  

---

## 1. Découpage en Tâches SDD

Le jalon est découpé en 4 tâches séquentielles, exécutées selon le workflow SDD (Implementer / Reviewer par tâche, puis Whole-Branch Review) :

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SUITE SDD JALON 3.2                             │
│                                                                        │
│  [Tâche 1] Promotion `jambo-wasmd` & Démon Ring 3 (PID 7)              │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 2] Commandes `wasm` dans `jsh` & Affichage 7 Processus `ps`    │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 3] Micro-Noyau `kernel` & Outillage `xtask` (7 Binaires)       │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 4] Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.46`    │
│       │                                                                │
│       ▼                                                                │
│  [Whole-Branch Review] Audit Complet & Tagging Git                     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Tâche 1 : Promotion `jambo-wasmd` & Démon Ring 3 (`wasmd`, PID 7)

### Objectifs
1. Créer `services/jambo-wasmd` dans le workspace principal (`Cargo.toml`).
2. S'appuyer sur la logique de base éprouvée de `incubator/services/jambo-wasm` pour concevoir une crate souveraine complète :
   - `services/jambo-wasmd/Cargo.toml` (`jambo_wasmd` lib + `wasmd` bin, version `0.3.46`).
   - `services/jambo-wasmd/src/lib.rs` :
     * Types de capacités `WasmCap` et masques de droits.
     * Décodeur LEB128 & parseur de sections Wasm standard.
     * Mémoire linéaire `WasmLinearMemory` bornée et protégée.
     * Interpréteur de bytecode Wasm stack machine avec comptabilisation de carburant (Gas metering).
     * Sandbox WASI Preview 1 (`fd_write`, `clock_time_get`, `proc_exit`).
     * Opcodes IPC (`WasmdOpcode`), messages (`WasmdRequest`, `WasmdResponse`), et client IPC (`WasmdClient`).
     * Module d'exemple Wasm de référence (calcul itératif/récursif ou écho WASI).
   - `services/jambo-wasmd/src/main.rs` :
     * Point d'entrée `_start` Ring 3 (`#![no_std]`, `#![no_main]`).
     * Bannière de démarrage sur console série via `libjambo::println`.
     * Initialisation de la machine virtuelle et du sandbox WASI.
     * Boucle IPC coopérative avec `syscall_thread_yield()`.
3. Valider la compilation bare-metal :
   ```bash
   cargo check --target x86_64-unknown-none -p jambo-wasmd --release
   ```

### Critères de Revue
- Aucun appel à un allocateur dynamique de mémoire (zero heap).
- Strict respect de l'isolation mémoire Wasm (bounds checking).
- Pas de mocks matériels dans le Ring 0.

---

## Tâche 2 : Commandes `wasm` dans le Shell `jsh` (PID 2)

### Objectifs
1. Mettre à jour `services/jambo-sh/Cargo.toml` :
   - Dépendance vers `jambo-wasmd = { path = "../jambo-wasmd" }`.
   - Version bump à `0.3.46`.
2. Implémenter les commandes `wasm` dans `services/jambo-sh/src/main.rs` :
   - `wasm status` : affiche la version du runtime, la conformité Wasm MVP / WASI, le plafond de gaz et les instances exécutées.
   - `wasm run [demo|fib]` : exécute un microservice Wasm via `WasmdClient` et affiche le résultat, le gaz consommé et la sortie WASI.
   - `wasm info` : affiche les droits de capacité et les interfaces WASI exportées.
3. Actualiser la commande `ps` pour lister les **7 processus Ring 3** :
   - PID 1 : `/bin/init` (supervisor)
   - PID 2 : `/bin/jsh` (shell)
   - PID 3 : `/bin/blockd` (virtio-blk)
   - PID 4 : `/bin/fs` (jambofs)
   - PID 5 : `/bin/netd` (virtio-net)
   - PID 6 : `/bin/fdr` (defense-resilience)
   - PID 7 : `/bin/wasmd` (wasm-microservices)
4. Mettre à jour la bannière d'accueil et le menu `help` pour afficher `v0.3.46`.

### Critères de Revue
- Consommation zéro tas dans `jsh` pour les commandes `wasm`.
- Gestion des erreurs et affichage soigné.

---

## Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`

### Objectifs
1. **Micro-Noyau (`kernel/src/main.rs`)** :
   - Extraire `/bin/wasmd` depuis `initrd.tar`.
   - Créer le processus Ring 3 PID 7 avec pile System V ABI (alignement 16 octets `RSP % 16 == 0`).
   - Enfiler PID 7 dans l'ordonnanceur EEVDF.
   - Dans le mode de test CI sous QEMU : valider l'initialisation des 7 démons et afficher :
     `[PASS] Wasm Microservices Runtime (jambo-wasmd PID 7) validé sous QEMU.`
   - Mettre à jour `kernel/Cargo.toml` à la version `0.3.46`.
2. **Outillage de compilation (`xtask/src/main.rs`)** :
   - Définir `build_wasmd()` compilant `services/jambo-wasmd` avec `libs/user-x86_64.ld`.
   - Empaqueter `target/initrd.tar` avec les 7 exécutables : `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`.

### Critères de Revue
- Alignement 16-octets de la pile de PID 7 garanti.
- Packaging TAR sans préfixe de chemin.

---

## Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.46`

### Objectifs
1. Contrôles qualité : `cargo fmt --all -- --check` et `cargo clippy --package jambo-abi -- -D warnings`.
2. Compilation de tous les binaires release : `kernel` + 7 démons utilisateur.
3. Packaging de l'Initrd `target/initrd.tar` et synchronisation du lecteur FAT virtuel `target/iso_root`.
4. Exécution de QEMU UEFI avec OVMF EDK2 et `isa-debug-exit`.
5. Vérifier le code de sortie `33` et inspecter `target/qemu_output.log` attestant du lancement des 7 processus.
6. Rédiger le rapport complet de validation.

---

## Whole-Branch Review & Taggage

1. Audit global de l'écart `v0.3.45..HEAD`.
2. Nettoyage du répertoire SDD `.superpowers/sdd/2026-10-31-vertical-slice-ring3-wasm/`.
3. Création du tag officiel annoté :
   ```bash
   git tag -a v0.3.46 -m "release: v0.3.46 - Sovereign WebAssembly & WASI Microservices Runtime (jambo-wasmd PID 7)"
   ```
4. Vérification avec `git describe --tags`.

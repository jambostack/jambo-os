# Spécification Technique — Jalon 3.2 : Exécution de Microservices WebAssembly / WASI en Ring 3 (PID 7), Runtime `jambo-wasmd` & Commandes `wasm` (v0.3.46)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.46`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Positionnement Stratégique

À la suite du succès du **Jalon 3.1 (`v0.3.45`)** validant la résilience matérielle `jambo-fdr` (PID 6), le hachage SHA-256 no_std et les banques PCR TPM 2.0 sous QEMU UEFI, JamboOS franchit une étape charnière du **Palier 3 (« Robustesse Système & Différenciateurs Souverains »)** : **le positionnement Cloud-Native & Micro-VM via WebAssembly**.

Les rapports d'experts ont formulé une recommandation stratégique unanime :
> *Ne pas tenter de recréer un Linux complet avec 400 syscalls POSIX, mais faire de JamboOS un hyperviseur/unikernel bare-metal ultra-sécurisé pour charges utiles Cloud-Native sandboxed (Wasm/WASI).*

L'objectif du **Jalon 3.2 (`v0.3.46`)** est d'établir le démon d'exécution WebAssembly / WASI **`jambo-wasmd` en Ring 3 (PID 7)** :
- Isolation logicielle par défaut (SFI) couplée à l'isolation matérielle (Ring 3 x86_64 + pagination PML4).
- Interpréteur de bytecode Wasm MVP et sandbox WASI Preview 1 en pur `#![no_std]` sans allocation dynamique.
- Mesure monotone du carburant (Gas/Fuel metering) pour garantir la terminaison déterministe.
- Exposition de commandes interactives `wasm status`, `wasm run`, `wasm info` dans le shell `jsh`.
- Intégration dans le micro-noyau (PID 7 dans l'ordonnanceur EEVDF) et validation de bout en bout sous QEMU UEFI.

---

## 2. Architecture & Fonctionnalités de `jambo-wasmd`

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌───────────────────────────────┐  │
│  │     jsh      │ ◄───────────────► │      jambo-wasmd (PID 7)      │  │
│  │ (wasm status,│                   │ • Wasm MVP Bytecode VM        │  │
│  │  wasm run,   │                   │ • WASI Preview 1 (fd_write...)│  │
│  │  wasm info)  │                   │ • Mémoire Linéaire Sandboxed  │  │
│  └──────────────┘                   │ • Gas / Fuel Metering         │  │
│                                     │ • Capabilités WasmCap         │  │
│                                     └───────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ Syscalls x86_64
┌─────────────────────────────────────────────────────┼──────────────────┘
│                        MICRO-NOYAU (Ring 0)         ▼                  │
│               Ordonnanceur Multicœur EEVDF (PID 1 à 7)                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Moteur d'Exécution Wasm / WASI (`#![no_std]`, Zéro Tas)
1. **Machine Virtuelle à Pile (Stack Machine)** :
   - Décodage des sections binaires Wasm (`Type`, `Function`, `Memory`, `Export`, `Code`).
   - Instructions supportées : arithmétique `i32` (`add`, `sub`, `mul`, `and`, `or`, `xor`, `shl`, `shr`), contrôle de flux (`block`, `loop`, `br`, `br_if`, `return`), gestion des variables locales (`local.get`, `local.set`, `local.tee`), et accès mémoire linéaire (`i32.load`, `i32.store`).
2. **Mémoire Linéaire Isolée (`WasmLinearMemory`)** :
   - Espace mémoire borné avec vérification stricte de dépassement (`SysError::BadAddress`).
   - Confinement spatial étanche interdisant toute corruption de l'espace d'adressage de l'hôte.
3. **Couche d'Émulation WASI Preview 1** :
   - `fd_write` : écriture dans les flux standards (stdout/stderr) interceptée et canalisée dans un tampon de log d'exécution.
   - `clock_time_get` : interrogation temporelle déterministe.
   - `proc_exit` : terminaison ordonnée avec code de sortie.
4. **Comptabilisation du Gaz (Fuel/Gas Metering)** :
   - Décrémentation à chaque instruction de bytecode.
   - Interception immédiate en cas de boucle infinie (`SysError::ResourceBusy`).
5. **Protocole IPC (`WasmdRequest` / `WasmdResponse`)** :
   - `WasmdOpcode::GetStatus = 1` : état de santé, instances exécutées, limite de gaz, mémoire disponible.
   - `WasmdOpcode::RunSample = 2` : exécution d'un microservice Wasm de référence (calcul de Fibonacci ou écho WASI) et retour du résultat, du gaz consommé et du flux de sortie.
   - `WasmdOpcode::GetInfo = 3` : capacités actives, droits accordés, version de la spécification.

---

## 3. Commandes Shell `jsh` (PID 2)

Dans `services/jambo-sh` :
1. **`wasm status`** :
   ```text
   JamboWasm Runtime Engine Status:
     Engine Version    : v0.3.46 (Sovereign WASI Engine)
     Spec Compliance   : Wasm MVP (Binary 0x01) + WASI Preview 1
     Isolation Level   : SFI + Ring 3 (Hardware PML4 Paginated)
     Memory Arena      : Sandboxed Linear Memory (Max 64 Kio/instance)
     Gas Limit Ceiling : 1,000,000 instructions
     Instances Run     : 1
     Active Sandbox    : READY
   ```
2. **`wasm run [demo|fib]`** :
   ```text
   Executing sovereign WebAssembly microservice:
     Module            : fibonacci_compute.wasm
     Parameters        : n = 10
     Result            : 55
     Gas Consumed      : 142 instructions
     Exit Code         : 0 (Success)
     WASI Output       : "[wasi:stdout] Fibonacci(10) compute verified."
   ```
3. **`wasm info`** :
   Affichage des capabilités et droits `WasmCap` (`WASM_EXEC`, `WASM_MEM_GROW`, `WASM_WASI_IO`, etc.).
4. **`ps`** :
   Affichage actualisé des **7 processus Ring 3** :
   - PID 1 : `init`
   - PID 2 : `jsh`
   - PID 3 : `blockd`
   - PID 4 : `fs`
   - PID 5 : `netd`
   - PID 6 : `fdr`
   - PID 7 : `wasmd`

---

## 4. Intégration Micro-Noyau (`kernel`) & Outillage (`xtask`)

1. **Micro-Noyau (`kernel/src/main.rs`)** :
   - Extraction de `/bin/wasmd` depuis `initrd.tar`.
   - Création et ordonnancement de PID 7 avec pile 16-octets System V ABI.
   - En mode test CI sous QEMU : validation de l'initialisation des 7 démons et affichage de :
     `[PASS] Wasm Microservices Runtime (jambo-wasmd PID 7) validé sous QEMU.`
2. **Build & Initrd (`xtask/src/main.rs`)** :
   - Fonction `build_wasmd()` compilant `services/jambo-wasmd` avec `libs/user-x86_64.ld`.
   - Packaging de `target/initrd.tar` avec les 7 exécutables : `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`.

---

## 5. Critères d'Acceptation & Validation

1. **Compilation & Linters** :
   - `cargo fmt --all -- --check` sans erreur.
   - `cargo clippy --package jambo-abi -- -D warnings` sans erreur.
   - Compilation bare-metal des 8 binaires release (`kernel` + 7 démons utilisateur) avec 0 avertissement.
2. **Validation QEMU UEFI** :
   - Exécution sous QEMU UEFI avec OVMF EDK2 et isa-debug-exit.
   - Code de retour 33 attestant du succès total.
   - Traces de boot confirmant l'initialisation et l'ordonnancement de PID 1 à 7.
3. **Revue Complète & Tag Git** :
   - Whole-Branch Review validée (APPROVED).
   - Tag Git annoté officiel : `v0.3.46`.

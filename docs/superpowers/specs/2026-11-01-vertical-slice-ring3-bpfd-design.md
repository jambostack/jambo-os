# Spécification Technique — Jalon 3.8 : Sandboxing eBPF & Filtrage Réseau XDP en Ring 3 (PID 13), Démon `jambo-bpfd` & Commandes `bpf` (v0.3.52)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 1er Novembre 2026  
**Cible :** `v0.3.52`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Positionnement Stratégique

Après les jalons 3.1 (`v0.3.45` - Résilience Matérielle FDR & TPM 2.0), 3.2 (`v0.3.46` - Runtime WebAssembly/WASI), 3.3 (`v0.3.47` - Cryptographie Post-Quantique ML-KEM/ML-DSA), 3.4 (`v0.3.48` - Surveillance d'Intégrité Noyau KDIR), 3.5 (`v0.3.49` - Confinement Mémoire & Forensics Volatile), 3.6 (`v0.3.50` - Gestion Énergie & Fréquence CPU) et 3.7 (`v0.3.51` - Métrologie Système & Télémétrie), JamboOS aborde la huitième étape majeure du **Palier 3 (« Robustesse Système & Différenciateurs Souverains »)** : **le Sandboxing eBPF, Vérificateur Formel DAG & Filtrage Réseau XDP en Espace Utilisateur (`jambo-bpfd` PID 13)**.

Dans une architecture micro-noyau moderne :
> *L'exécution de code dynamique (filtrage de paquets réseau, instrumentation, sondes d'observabilité) ne doit jamais s'exécuter sans garde-fou ni encombrer le Ring 0. Le bytecode eBPF doit faire l'objet d'une vérification formelle de terminaison (graphe orienté acyclique / DAG sans boucles infinies) et s'exécuter dans une machine virtuelle sandboxed en Ring 3 sans tas (`#![no_std]`, Zero Heap), avec un quota de cycles strict et des structures partagées (maps Array, HashMap, RingBuf).*

L'objectif du **Jalon 3.8 (`v0.3.52`)** est d'établir le démon **`jambo-bpfd` en Ring 3 (PID 13)** :
1. Interpréteur de bytecode eBPF complet conforme RFC / standard eBPF 64-bit (instructions ALU, ALU64, JMP, LD, ST, RET).
2. Vérificateur formel statique de terminaison (`BpfVerifier`) assurant l'absence de boucles infinies, la validité des accès mémoire et l'initialisation des registres.
3. Machine virtuelle bornée (`BpfVm`) avec pile fixe de 512 octets, 11 registres 64-bit et limite d'exécution à 10 000 cycles pour parer aux dénis de service.
4. Structures de données partagées de taille fixe (`BpfMap` : Array, HashMap, RingBuf).
5. Crochets d'attachement (`BpfAttachment`) pour le filtrage de paquets réseau XDP (`filter_packet`) et l'instrumentation.
6. Contrôle d'accès capabilaire strict (`BpfCap`) avec droits granulaires (`BPF_PROG_LOAD`, `BPF_PROG_RUN`, `BPF_MAP_CREATE`, `BPF_MAP_ACCESS`, `BPF_ATTACH`, `BPF_ADMIN`).
7. Protocole IPC déterministe à 64 octets avec assertions statiques `size_of == 64`.
8. Commandes interactives dans le shell `jsh` : `bpf status`, `bpf verify`, `bpf run <prog_id>`, `bpf filter <packet_len>`.
9. Listing complet des **13 processus Ring 3** actifs dans la commande `ps`.
10. Intégration dans le micro-noyau `kernel` (PID 13, alignement 16 octets System V ABI, ordonnancement EEVDF) et validation QEMU UEFI avec le code de sortie 33.

---

## 2. Architecture & Fonctionnalités de `jambo-bpfd`

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌───────────────────────────────┐  │
│  │     jsh      │ ◄───────────────► │       jambo-bpfd (PID 13)     │  │
│  │ (bpf status, │                   │ • Interpréteur eBPF 64-bit    │  │
│  │  bpf verify, │                   │ • Vérificateur Formel DAG    │  │
│  │   bpf run,   │                   │ • Sandboxing & Limite Cycles  │  │
│  │  bpf filter) │                   │ • Filtrage Réseau XDP         │  │
│  └──────────────┘                   │ • Maps Array/HashMap/RingBuf  │  │
│                                     │ • Capabilités BpfCap          │  │
│                                     └───────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ Syscalls x86_64
┌─────────────────────────────────────────────────────┼──────────────────┘
│                        MICRO-NOYAU (Ring 0)         ▼                  │
│               Ordonnanceur Multicœur EEVDF (PID 1 à 13)                │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Moteur eBPF Souverain (`#![no_std]`, Zéro Tas)
1. **Contrôle d'Accès par Capabilités (`BpfCap`)** :
   - Droits stricts sans autorité ambiante.
2. **Vérification Formelle Statique (`BpfVerifier`)** :
   - Analyse de flot de contrôle statique (CFG/DAG), validation de chaque branchement.
   - Détection des accès mémoire hors limites et instructions illégales avant toute exécution.
3. **Machine Virtuelle Bounded Execution (`BpfVm`)** :
   - 11 registres virtuels 64-bit ($R_0$ à $R_{10}$, $R_{10}$ étant le pointeur de cadre en lecture seule).
   - Quota monotone de 10 000 instructions par appel.
4. **Filtrage Réseau XDP (`filter_packet`)** :
   - Verdicts rapides : `XDP_PASS = 0`, `XDP_DROP = 1`, `XDP_TX = 2`, `XDP_REDIRECT = 3`.
5. **Protocole IPC Déterministe (64 octets)** :
   - Opcodes : `GetStatus = 1`, `VerifyProgram = 2`, `RunProgram = 3`, `FilterPacket = 4`, `GetStats = 5`.
   - Structures `BpfRequest` et `BpfResponse` calibrées à 64 octets exactement.

---

## 3. Commandes Shell `jsh` (PID 2)

- `bpf status` : Affiche l'état du moteur eBPF, nombre de programmes chargés, maps allouées, points d'attache et cycles exécutés.
- `bpf verify` : Déclenche l'analyse formelle DAG sur le jeu de programmes de test et affiche le rapport de vérification.
- `bpf run <prog_id>` : Exécute le programme eBPF sandboxed identifié et affiche le code retour $R_0$ et les cycles consommés.
- `bpf filter <packet_len>` : Simule le passage d'un paquet réseau à travers le crochet XDP et affiche le verdict (`PASS` ou `DROP`).
- `ps` : Liste complète des **13 processus Ring 3** :
  `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`, `forensics`, `powerd`, `metricsd`, `bpfd`.

---

## 4. Intégration Micro-Noyau (`kernel`) & `xtask`

- `kernel/Cargo.toml` : version `0.3.52`.
- Extraction de `/bin/bpfd` de l'Initrd USTAR.
- Allocation de pile Ring 3 avec validation de l'alignement System V ABI : `assert_eq!(bpfd_sp % 16, 0)`.
- Ordonnancement du PID 13 dans l'ordonnanceur EEVDF.
- Journal UART : `[PASS] Sandboxing eBPF & Filtrage Réseau XDP (jambo-bpfd PID 13) validée sous QEMU.`
- `xtask` : Compilation de `jambo-bpfd` avec `libs/user-x86_64.ld` à `0x00400000`, empaquetage dans `target/initrd.tar`, bannière de disque `"Bienvenue sur JamboOS v0.3.52\n"`.
- Test QEMU automatisé avec code de sortie 33 (`isa-debug-exit`).

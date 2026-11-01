# Spécification Technique — Jalon 3.6 : Gestion de l'Énergie & Fréquence CPU en Ring 3 (PID 11), Démon `jambo-powerd` & Commandes `power` (v0.3.50)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 1er Novembre 2026  
**Cible :** `v0.3.50`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Positionnement Stratégique

Après les jalons 3.1 (`v0.3.45` - Résilience Matérielle FDR & TPM 2.0), 3.2 (`v0.3.46` - Runtime WebAssembly/WASI), 3.3 (`v0.3.47` - Cryptographie Post-Quantique ML-KEM/ML-DSA), 3.4 (`v0.3.48` - Surveillance d'Intégrité Noyau KDIR) et 3.5 (`v0.3.49` - Confinement Mémoire & Forensics Volatile), JamboOS aborde la sixième étape majeure du **Palier 3 (« Robustesse Système & Différenciateurs Souverains »)** : **la Gestion Énergétique, Régulation Thermique & Contrôle ACPI / CPU en Espace Utilisateur (`jambo-powerd` PID 11)**.

Dans les architectures de micro-noyau modernes (seL4, Fuchsia, QNX), la gestion de l'énergie et des états matériels ACPI ne doit pas encombrer le Ring 0 :
> *L'accès aux ports d'I/O ACPI (PM1a_CNT, reset control) et la régulation des états de veille CPU (C-States / P-States) doivent être délégués à un démon Ring 3 strictement capabilaire (`PowerCap`). Le noyau se limite à offrir les primitives d'ordonnancement et de communication sans autorité ambiante.*

L'objectif du **Jalon 3.6 (`v0.3.50`)** est d'établir le démon **`jambo-powerd` en Ring 3 (PID 11)** :
1. Découplage ACPI & régulation énergétique en Ring 3 sans privilèges globaux arbitraires.
2. Gestion fine des états C-States SMP (C0 actif, C1 halt, C2 stop clock, C3 deep sleep) pour les cœurs logiques 0..3.
3. Profils énergétiques configurables : `Eco`, `Balanced`, `HighPerformance`.
4. Télémétrie de batterie (taux de charge, santé, température) et surveillance thermique continue avec politiques de throttle automatique.
5. Gestion des transitions globales d'états ACPI (S0 travail, S1 veille CPU, S3 mise en veille RAM, S5 arrêt ordonné).
6. Protocole IPC déterministe à 64 octets avec assertions statiques `size_of == 64`.
7. Commandes interactives dans le shell `jsh` : `power status`, `power profile [eco|balanced|perf]`, `power cstate <core> <c0|c1|c2|c3>`, `power battery`.
8. Listing complet des **11 processus Ring 3** actifs dans la commande `ps`.
9. Intégration dans le micro-noyau `kernel` (PID 11, alignement 16 octets System V ABI, ordonnancement EEVDF) et validation QEMU UEFI avec le code de sortie 33.

---

## 2. Architecture & Fonctionnalités de `jambo-powerd`

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌───────────────────────────────┐  │
│  │     jsh      │ ◄───────────────► │      jambo-powerd (PID 11)    │  │
│  │(power status,│                   │ • Régulation C-States C0..C3  │  │
│  │power profile,│                   │ • Profils Eco / Balanced /    │  │
│  │power cstate, │                   │   HighPerformance             │  │
│  │power battery)│                   │ • Télémétrie Batterie & Temp  │  │
│  └──────────────┘                   │ • Décodage FADT / ACPI PM1a   │  │
│                                     │ • Capabilités PowerCap        │  │
│                                     └───────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ Syscalls x86_64
┌─────────────────────────────────────────────────────┼──────────────────┘
│                        MICRO-NOYAU (Ring 0)         ▼                  │
│               Ordonnanceur Multicœur EEVDF (PID 1 à 11)                │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Moteur Énergétique Souverain (`#![no_std]`, Zéro Tas)
1. **Contrôle d'Accès par Capabilités (`PowerCap`)** :
   - Droits granulaires : `SHUTDOWN`, `REBOOT`, `SUSPEND`, `THROTTLE`, `BATTERY_QUERY`.
   - Zéro autorité ambiante.
2. **Gestion des Profils Énergétiques (`PowerProfile`)** :
   - `Eco` : Maximise l'économie d'énergie (C2/C3 sur cœurs inactifs, limitation d'activité).
   - `Balanced` : Compromis idéal charge / consommation d'énergie.
   - `HighPerformance` : Cœurs maintenus en C0 pour une latence IPC minimale.
3. **Surveillance Thermique & Batterie** :
   - Évaluation de politiques dynamiques : `ThermalThrottle` si température >= 85°C, `EmergencyShutdown` si batterie <= 5%.
4. **Protocole IPC Déterministe (64 octets)** :
   - Opcodes : `GetStatus = 1`, `SetProfile = 2`, `SetCState = 3`, `GetBattery = 4`, `Shutdown = 5`.
   - Structures `PowerRequest` et `PowerResponse` calibrées à 64 octets exactement.

---

## 3. Commandes Shell `jsh` (PID 2)

- `power status` : Affiche l'état d'alimentation global (S0..S5), le profil actif, l'état des cœurs C-States 0..3 et la température.
- `power profile [eco|balanced|perf]` : Modifie le profil énergétique global du système.
- `power cstate <core> <c0|c1|c2|c3>` : Règle l'état d'économie d'énergie pour un cœur CPU spécifique.
- `power battery` : Affiche la télémétrie de la batterie (pourcentage, charge, santé, température).
- `ps` : Liste complète des **11 processus Ring 3** :
  `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`, `forensics`, `powerd`.

---

## 4. Intégration Micro-Noyau (`kernel`) & `xtask`

- `kernel/Cargo.toml` : version `0.3.50`.
- Extraction de `/bin/powerd` de l'Initrd USTAR.
- Allocation de pile Ring 3 avec validation de l'alignement System V ABI : `assert_eq!(powerd_sp % 16, 0)`.
- Ordonnancement du PID 11 dans l'ordonnanceur EEVDF.
- Journal UART : `[PASS] Gestion Énergie & Fréquence CPU (jambo-powerd PID 11) validée sous QEMU.`
- `xtask` : Compilation de `jambo-powerd` avec `libs/user-x86_64.ld` à `0x00400000`, empaquetage dans `target/initrd.tar`, bannière de disque `"Bienvenue sur JamboOS v0.3.50\n"`.
- Test QEMU automatisé avec code de sortie 33 (`isa-debug-exit`).

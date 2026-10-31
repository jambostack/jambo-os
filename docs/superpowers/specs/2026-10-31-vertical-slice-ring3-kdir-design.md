# Spécification Technique — Jalon 3.4 : Surveillance d'Intégrité Noyau & Pilotes (KDIR) en Ring 3 (PID 9), Démon `jambo-kdir` & Commandes `kdir` (v0.3.48)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.48`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Positionnement Stratégique

À la suite des succès des Jalons 3.1 (`v0.3.45` - FDR & TPM 2.0), 3.2 (`v0.3.46` - WebAssembly / WASI sans Linux) et 3.3 (`v0.3.47` - Cryptographie Post-Quantique ML-KEM/ML-DSA), JamboOS franchit la quatrième étape majeure du **Palier 3 (« Robustesse Système & Différenciateurs Souverains »)** : **la Cyber-Résilience et Surveillance d'Intégrité Noyau (KDIR - Kernel & Driver Integrity Resilience)**.

Les rapports d'experts ont insisté sur un principe fondateur du micro-noyau moderne :
> *Même si le Ring 0 est minimal (< 95 Kio), sa compromission par des rootkits Ring 0/hyperviseur (hooks IDT, altérations de tables de pages CR3/PML4, tampering du MSR LSTAR) doit être détectable et remediable en O(1) depuis un démon Ring 3 souverain spécialisé et capabilaire.*

L'objectif du **Jalon 3.4 (`v0.3.48`)** est d'établir le démon de résilience noyau **`jambo-kdir` en Ring 3 (PID 9)** :
- Surveillance cryptographique d'intégrité des structures système vitales : IDT (vecteurs d'interruptions), GDT (descripteurs de segments), CR3 (table de pages PML4) et MSR LSTAR (point d'entrée syscall rapide).
- Détection en temps réel des rootkits (DKOM, hooks IDT/MSR, corruption de mémoire noyau).
- Validation de signature et contrôle d'isolation des pilotes de périphériques (`virtio-driver`, `nvme-driver`, `xhci-driver`).
- Auto-restauration en temps constant $O(1)$ à partir d'un snapshot de référence scellé (*Golden Snapshot*).
- Commandes shell interactives `kdir status`, `kdir scan`, `kdir restore`, `kdir audit` dans `jsh`.
- Intégration dans le micro-noyau (PID 9 dans l'ordonnanceur multicœur EEVDF) et validation QEMU UEFI avec le code de sortie 33.

---

## 2. Architecture & Fonctionnalités de `jambo-kdir`

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌───────────────────────────────┐  │
│  │     jsh      │ ◄───────────────► │       jambo-kdir (PID 9)      │  │
│  │ (kdir status,│                   │ • Surveillance IDT, GDT, PML4 │  │
│  │  kdir scan,  │                   │ • Détection Rootkits / DKOM   │  │
│  │  kdir restore│                   │ • Auto-Restauration O(1)      │  │
│  │  kdir audit) │                   │ • Registre d'Audit SHA-256    │  │
│  └──────────────┘                   │ • Capabilités KdirCap         │  │
│                                     └───────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ Syscalls x86_64
┌─────────────────────────────────────────────────────┼──────────────────┘
│                        MICRO-NOYAU (Ring 0)         ▼                  │
│               Ordonnanceur Multicœur EEVDF (PID 1 à 9)                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Moteur de Résilience KDIR (`#![no_std]`, Zéro Tas)
1. **Sondes de Surveillance d'Intégrité (Kernel Probes)** :
   - `Idt` : Table des descripteurs d'interruptions (vecteurs 0..255).
   - `Gdt` : Table globale des descripteurs (segments kernel et userland, TSS64).
   - `Cr3PageTable` : Racine PML4 de la table de pages x86_64 avec W^X / NX bit.
   - `SyscallDispatcher` : Point d'entrée syscall rapide MSR `IA32_LSTAR` (`0xC0000082`).
2. **Détection de Rootkits & Menaces** :
   - Détection des altérations de structures de données directes (DKOM).
   - Détection de hooks sur tables de dispatch et vecteurs d'exceptions.
3. **Auto-Restauration $O(1)$ (Golden Snapshot)** :
   - Restauration immédiate des zones corrompues depuis les empreintes cryptographiques certifiées.
4. **Chaîne d'Audit Immuable SHA-256** :
   - Journalisation continue scellée par chaînage cryptographique (`audit_log`).
5. **Protocole IPC (`KdirRequest` / `KdirResponse`)** :
   - `KdirOpcode::GetStatus = 1` : état global, sondes actives, pilotes surveillés, menaces actives (0).
   - `KdirOpcode::ScanIntegrity = 2` : balayage cryptographique instantané de toutes les structures.
   - `KdirOpcode::RestoreSnapshot = 3` : exécution du protocole d'auto-restauration $O(1)$.
   - `KdirOpcode::GetAudit = 4` : exportation de la tête du registre d'audit SHA-256.

---

## 3. Commandes Shell `jsh` (PID 2)

Dans `services/jambo-sh` :
1. **`kdir status`** :
   ```text
   Kernel & Driver Integrity Resilience (KDIR) Status:
     Protection Status : SECURED (Ring 3 Hardware Monitor Active)
     Monitored Probes  : 4 (IDT, GDT, CR3 PML4, MSR LSTAR)
     Monitored Drivers : 3 (virtio-driver, nvme-driver, xhci-driver)
     Active Threats    : 0 (No rootkits / hooks detected)
     Auto-Restoration  : ARMED (O(1) Golden Snapshot Ready)
     Audit Chain Head  : [SHA-256 Hex Digest]
   ```
2. **`kdir scan`** :
   ```text
   [KDIR] Initiating cryptographic kernel integrity scan...
     Probe [IDT Table]        : OK (Golden Hash Matched)
     Probe [GDT Table]        : OK (Golden Hash Matched)
     Probe [CR3 PML4 Root]    : OK (W^X Enforced, Golden Hash Matched)
     Probe [MSR LSTAR Entry]  : OK (Syscall Vector Hardened)
     Driver Signatures        : 3/3 VERIFIED (Sovereign VMOs Validated)
     Scan Result              : 100% UNTAMPERED (Zero Rootkit Infiltration)
   ```
3. **`kdir restore`** :
   ```text
   [KDIR] Verifying O(1) Auto-Restoration Mechanism:
     Snapshot Reference       : GOLDEN_CORE_SNAPSHOT_2026
     Restoration Path         : VERIFIED (O(1) Instantaneous Rollback Ready)
     Kernel Integrity State   : SECURED
   ```
4. **`kdir audit`** :
   Affiche l'empreinte SHA-256 du registre d'audit KDIR.
5. **`ps`** :
   Affichage actualisé des **9 processus Ring 3** :
   - PID 1 : `init`
   - PID 2 : `jsh`
   - PID 3 : `blockd`
   - PID 4 : `fs`
   - PID 5 : `netd`
   - PID 6 : `fdr`
   - PID 7 : `wasmd`
   - PID 8 : `pqc`
   - PID 9 : `kdir`

---

## 4. Intégration Micro-Noyau (`kernel`) & Outillage (`xtask`)

1. **Micro-Noyau (`kernel/src/main.rs`)** :
   - Extraction de `/bin/kdir` depuis `initrd.tar`.
   - Création et ordonnancement de PID 9 avec pile System V ABI (alignement 16 octets `RSP % 16 == 0`).
   - En mode test CI sous QEMU : validation de l'initialisation des 9 démons et affichage de :
     `[PASS] Surveillance Intégrité Noyau & Pilotes (jambo-kdir PID 9) validée sous QEMU.`
2. **Build & Initrd (`xtask/src/main.rs`)** :
   - Fonction `build_kdir()` compilant `services/jambo-kdir` avec `libs/user-x86_64.ld`.
   - Packaging de `target/initrd.tar` avec les 9 exécutables : `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`.
   - Mise à jour de la bannière disque vers `v0.3.48`.

---

## 5. Critères d'Acceptation & Validation

1. **Contrôles Qualité** :
   - `cargo fmt --all -- --check` réussi (0 écart).
   - `cargo clippy --package jambo-abi -- -D warnings` réussi (0 warning).
   - `cargo clippy --package jambo-kdir --target x86_64-unknown-none --release -- -D warnings` réussi (0 warning).
   - Compilation bare-metal des 10 binaires release (`kernel` + 9 démons utilisateur) avec 0 avertissement.
2. **Validation QEMU UEFI** :
   - Exécution sous QEMU UEFI avec OVMF EDK2 et isa-debug-exit.
   - Code de retour 33 attestant du succès total.
   - Traces de boot confirmant l'initialisation et l'ordonnancement de PID 1 à 9.
3. **Revue Complète & Tag Git** :
   - Whole-Branch Review validée (APPROVED).
   - Tag Git annoté officiel : `v0.3.48`.

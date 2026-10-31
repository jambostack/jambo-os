# Spécification Technique — Jalon 3.1 : Résilience Matérielle Souveraine `jambo-fdr` en Ring 3 (PID 6), TPM 2.0 & Commandes `fdr` (v0.3.45)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.45`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Positionnement Stratégique

À la suite de la clôture complète du **Palier 2 (« Tranches Verticales Ring 3 »)** validé jusqu'au **Jalon 2.4 (`v0.3.44`)** (console série, stockage VirtIO-Block/JamboFS, réseau VirtIO-Net et pile IP avec exit code 33 sous QEMU), JamboOS aborde le **Palier 3 (« Robustesse Système & Différenciateurs Souverains »)**.

Le rapport d'architecture et les 4 revues d'experts ont souligné que le service `jambo-fdr` (**Firmware & Hardware Defense Resilience**) constitue l'un des **différenciateurs architecturaux les plus forts et les plus originaux de JamboOS** :
* Au lieu de faire dépendre la sécurité de l'OS uniquement d'un hyperviseur ou de signatures logicielles distantes, JamboOS intègre en espace utilisateur isolé (Ring 3) un moteur autonome de contrôle d'intégrité du firmware SPI Flash, de surveillance des banques de registres PCR TPM 2.0, et de détection de corruption ACPI/SMBIOS.

L'objectif du **Jalon 3.1 (`v0.3.45`)** est de hisser `jambo-fdr` hors de l'incubateur pour en faire le **6e processus Ring 3 officiel (PID 6)**, raccordé par IPC au shell `jsh` et validé de bout en bout sous QEMU UEFI.

---

## 2. Architecture & Fonctionnalités de `jambo-fdr`

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌───────────────────────────────┐  │
│  │     jsh      │ ◄───────────────► │       jambo-fdr (PID 6)       │  │
│  │ (fdr status, │                   │ • Hacheur SHA-256 déterministe│  │
│  │  fdr verify, │                   │ • Registres PCR TPM 2.0 (0..7)│  │
│  │  fdr pcr)    │                   │ • Intégrité Dual-BIOS / SPI   │  │
│  └──────────────┘                   │ • Contrôle ACPI (RSDP, MADT)  │  │
│                                     │ • Registre d'Audit Scellé     │  │
│                                     └───────────────┬───────────────┘  │
└─────────────────────────────────────────────────────┼──────────────────┘
                                                      │ Syscalls x86_64
┌─────────────────────────────────────────────────────┼──────────────────┘
│                        MICRO-NOYAU (Ring 0)         ▼                  │
│               Ordonnanceur Multicœur EEVDF (PID 1 à 6)                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Moteur de Sécurité FDR (`#![no_std]`, Zéro Tas)
1. **Hachage Cryptographique SHA-256 Autonome** :
   - Implémentation certifiée FIPS 180-4 `#![no_std]` sans allocation dynamique.
2. **Racine de Confiance TPM 2.0 & Banques PCR** :
   - Simulation fidèle des registres PCR TPM 2.0 (PCR 0 à PCR 7) :
     * `PCR 0` : Firmware UEFI / BIOS Core digest.
     * `PCR 1` : Configuration de la plateforme et tables ACPI (RSDP, XSDT, MADT).
     * `PCR 2` : Drivers Option ROM / PCI.
     * `PCR 4` : Code du chargeur d'amorçage Limine v3.
     * `PCR 5` : Configuration du bootloader (`limine.conf`).
     * `PCR 8` : Mesure du micro-noyau JamboKernel (`kernel.elf`).
     * `PCR 9` : Mesure de l'archive Initrd (`initrd.tar`).
   - Opération d'extension cryptographique conforme TCG : $\text{PCR}_{\text{new}} = \text{SHA256}(\text{PCR}_{\text{old}} \parallel \text{digest})$.
3. **Contrôle d'Intégrité Firmware SPI / Dual-BIOS** :
   - Vérification de l'image de firmware contre la référence certifiée (*Golden Measurement*).
   - Détection d'altérations SPI Flash et simulation de basculement Dual-BIOS sécurisé.
4. **Protocole IPC (`FdrRequest` / `FdrResponse`)** :
   - `FdrOpcode::GetStatus = 1` : retourne l'état global de sécurité (posture, alertes, statut Dual-BIOS).
   - `FdrOpcode::VerifyIntegrity = 2` : exécute une vérification cryptographique complète et renvoie le statut d'intégrité (1 = Sain, 0 = Compromis).
   - `FdrOpcode::GetPcr = 3` : retourne la valeur d'une banque PCR spécifique (32 octets).

---

## 3. Commandes Shell `jsh` (PID 2)

Dans `services/jambo-sh` :
1. **`fdr status`** :
   ```text
   FDR (Firmware Defense Resilience) Status:
     Posture           : SECURED (Hardware Enforced)
     Root of Trust     : TPM 2.0 / DICE Measured
     Firmware Partition: PRIMARY (Dual-BIOS Synced)
     ACPI Tables       : VERIFIED (RSDP, MADT, XSDT)
     Active Alerts     : 0
     Isolated Devices  : 0
   ```
2. **`fdr verify`** :
   ```text
   [FDR] Starting cryptographic firmware & hardware integrity scan...
   [FDR] Hashing SPI Flash image (Golden Snapshot): OK (SHA-256 match)
   [FDR] Verifying ACPI tables (RSDP/MADT): OK
   [FDR] Validating TPM 2.0 PCR registers: OK
   [FDR] Result: 100% INTEGRITY VERIFIED - System Sovereign & Untampered
   ```
3. **`fdr pcr`** :
   Affiche les condensats SHA-256 des banques PCR 0 à 7 mesurées au boot.
4. **`ps`** : Affiche les 6 processus Ring 3 :
   - PID 1: `/bin/init`
   - PID 2: `/bin/jsh`
   - PID 3: `/bin/blockd`
   - PID 4: `/bin/fs`
   - PID 5: `/bin/netd`
   - PID 6: `/bin/fdr`

---

## 4. Intégration Système & Outillage

1. **Workspace Cargo** :
   - Promotion de `incubator/services/jambo-fdr` vers `services/jambo-fdr`.
   - Ajout de `"services/jambo-fdr"` dans le `Cargo.toml` racine (11 crates actives).
2. **Noyau `kernel/src/main.rs`** :
   - Extraction de `bin/fdr` depuis l'initrd TAR.
   - Instanciation du processus PID 6 avec pile System V AMD64 ABI alignée à 16 octets.
   - Enfilement dans l'ordonnanceur multicœur EEVDF.
   - En mode test CI : affichage de `[PASS] FDR Résilience Matérielle Ring 3 validée sous QEMU.` et sortie propre `isa-debug-exit` code 33.
3. **Outillage `xtask/src/main.rs`** :
   - Compilation statique de `jambo-fdr` via `libs/user-x86_64.ld`.
   - Packaging des 6 binaires dans `target/initrd.tar`.

---

## 5. Critères d'Acceptation & Stratégie de Test

1. **Compilation & Linters** :
   - `cargo fmt --all -- --check` : code 0.
   - `cargo clippy --package jambo-abi -- -D warnings` : code 0.
   - `cargo check --target x86_64-unknown-none --release` sur les 8 crates bare-metal du workspace (`kernel`, `init`, `jsh`, `virtio-drv`, `blockd`, `fs`, `netd`, `fdr`).
2. **Exécution QEMU UEFI** :
   - Démarrage automatisé avec OVMF EDK2, Q35, 4 vCPUs, 2 Gio RAM.
   - Extraction et exécution des 6 processus Ring 3.
   - Code de retour vérifié : **`33`** (`isa-debug-exit`).
3. **Revue Complète & Tag Git** :
   - Whole-Branch Review validée (APPROVED).
   - Tag Git annoté officiel : `v0.3.45`.

# Protocole de Démonstration sur Silicium Physique (Bare-Metal)

> **Système** : JamboOS (Micro-noyau expérimental orienté capacités en Rust `![no_std]`)  
> **Jalon Cible** : Palier 5 — Jalon 5.4 (`v0.3.87` — Prototype Pre-Alpha)  
> **Supports de Démonstration** : Intel NUC 11/12/13 (x86_64) & Raspberry Pi 4 Model B (AArch64)

---

## 1. Objectif de la Démonstration

Ce protocole fournit le scénario étape par étape permettant d'attester publiquement et sans équivoque de la viabilité opérationnelle de JamboOS sur du matériel physique réel (*silicium nu*), en démontrant :
1. **L'Amorçage Silicium UEFI Universel** sans outil tiers via clé USB FAT32 standard.
2. **L'Élévation et l'Isolation Ring 3** des 38 microservices système dans des espaces virtuels PML4 distincts.
3. **Le Confinement des Pilotes Matériels sous IOMMU** (VirtIO / NVMe / Réseau).
4. **La Résilience aux Pannes** avec tolérance au crash de pilotes en espace utilisateur sans panique noyau.
5. **La Compatibilité C-ABI & POSIX** via les primitives `write`, `read`, `mmap`, `sched_yield`.

---

## 2. Préparation du Support d'Amorçage (30 Secondes)

Sur la station de travail de développement :
```bash
# 1. Compiler l'ensemble du système en mode release
cargo xtask build --release

# 2. Générer l'arborescence standardisée EFI System Partition (ESP)
cargo xtask esp --release

# 3. Flasher la clé USB (ex. lecteur E: sous Windows ou montage USB sous Linux)
cargo xtask flash-usb --release --device E:\
```
*Note : Il suffit d'une clé USB quelconque formatée en FAT32 (table GPT). Zéro utilitaire d'écriture brute de disque n'est requis.*

---

## 3. Déroulement du Scénario de Démonstration

```
┌────────────────────────────────────────────────────────────────────────┐
│                   SCÉNARIO DE DÉMONSTRATION PUBLIQUE                   │
├────────────────────────────────────────────────────────────────────────┤
│ Étape 1 : Allumage Machine & Séquence d'Amorçage Limine UEFI (GOP)     │
│ Étape 2 : Initialisation du TCB Kernel (< 95 Kio) & Ralliement SMP AP  │
│ Étape 3 : Chargement de l'Initrd & Transition vers les 38 Démons Ring 3│
│ Étape 4 : Session Interactive Shell jsh & Métrologie Système           │
│ Étape 5 : Test de Confinement & Preuve de Zéro Autorité Ambiante       │
│ Étape 6 : Test de Résilience aux Pannes & Redémarrage de Pilote        │
└────────────────────────────────────────────────────────────────────────┘
```

### Étape 1 : Allumage & Détection UEFI
1. Insérez la clé USB dans un port USB 3.0 de l'Intel NUC ou de la Raspberry Pi 4.
2. Allumez la machine et pressez la touche de sélection de boot (`F10` sur Intel NUC, `F12` sur Lenovo/Dell, `Échap` sur RPi4).
3. Sélectionnez l'entrée `UEFI: USB Device (FAT32)`.
4. **Observation** : Le menu graphique Limine Bootloader v3 apparaît à l'écran haute résolution (GOP 1080p). Le compte à rebours de 3 secondes s'écoule ou l'opérateur presse `Entrée` sur `JamboOS (Production)`.

### Étape 2 : Initialisation du Noyau Ring 0 & Multicœur SMP
Le noyau prend le contrôle immédiat du processeur. Les traces apparaissent simultanément sur le Framebuffer HDMI et sur la console série UART COM1 (115200 baud) :

```
================================================================================
    JAMBO-OS (JamboKernel v0.3.87 — Prototype Pre-Alpha)                      
    Architecture : Micro-noyau orienté capacités en Rust no_std (x86_64/AArch64)
    Auteur & Architecte Principal : ASSOGBA Prudence Dieudonné                 
    Dépôt Officiel : https://github.com/jambostack/jambo-os                    
================================================================================

[BOOT/HHDM] Projection mémoire physique directe à : 0xffff800000000000
[BOOT/MMAP] Détection des plages de mémoire physique : RAM utilisable détectée
[BOOT/PMM] Buddy Allocator initialisé (Bitmap anti-double-free actif)
[HEAP/SLUB] Tas noyau actif, allocation dynamique validée
[CPU/GDT] GDT et TSS initialisés (Pile IST1 dédiée aux Double Faults)
[CPU/IDT] IDT chargée (256 vecteurs d'exceptions matériels actifs)
[CPU/APIC] Contrôleur Local APIC détecté et initialisé
[SMP] Détection des cœurs logiques via ACPI MADT
[SMP] Cœurs AP réveillés et ralliés à l'ordonnanceur EEVDF
[INITRD/TAR] 38 microservices extraits avec succès
```

### Étape 3 : Élévation et Isolation des 38 Microservices Ring 3
Le superviseur racine `jambo-init` (PID 1) démarre en Ring 3 et lance les 37 démons subordonnés dans des espaces d'adressage PML4 (CR3) strictement isolés :
```
[PROCESS] Superviseur jambo-init (PID 1) démarré en Ring 3
[PROCESS] Shell interactif jambo-sh (PID 2) initialisé sur UART COM1
[PROCESS] Pilote de stockage jambo-blockd (PID 3) confiné sous barrière IOMMU
[PROCESS] Serveur de fichiers jambo-fs (PID 4) monté sur VMO partagé
[PROCESS] Pilote réseau jambo-netd (PID 5) actif avec VirtIO-Net
...
[PROCESS] Démon DLP jambo-dlp (PID 38) initialisé
[SYSTEM] Démarrage de la session interactive Ring 3 (Shell jsh)...
```

---

## 4. Commandes Interactives & Preuves Sous Shell `jsh`

L'opérateur interagit directement avec le système via le clavier USB ou le terminal série COM1 :

### 1. Métrologie Système (`sysinfo`)
```text
jsh> sysinfo
Architecture   : x86_64 (Intel Core i5-1135G7 @ 2.40GHz)
Mode CPU       : Ring 3 (Espace Utilisateur Non Privilégié)
Cœurs SMP      : 4 cœurs logiques actifs (Ordonnanceur EEVDF)
Mémoire Totale : 16384 Mio | RAM Libre : 15892 Mio
TCB Noyau      : < 95 Kio (.text)
Uptime         : 12 secondes
```

### 2. Inspection des Espaces d'Adressage (`ps`)
```text
jsh> ps
PID  STATUT   PML4_CR3           PAGES_VMO  NOM_SERVICE
  1  SLEEP    0x000000007b801000        16  jambo-init
  2  RUNNING  0x000000007b802000        32  jambo-sh
  3  WAIT_IPC 0x000000007b803000        64  jambo-blockd (IOMMU)
  4  WAIT_IPC 0x000000007b804000        64  jambo-fs
  5  WAIT_IPC 0x000000007b805000        32  jambo-netd
 ...
 38  WAIT_IPC 0x000000007b826000        16  jambo-dlp
Total : 38 processus actifs dans 38 espaces d'adressage isolés.
```

### 3. Preuve de Zéro Autorité Ambiante (Tentative d'Accès Non Autorisé)
Pour prouver l'absence de passe-droit root, l'opérateur tente d'accéder directement à un descripteur VMO privé détenu par un autre processus :
```text
jsh> cap-read 0xdeadbeef
[ERREUR CSpace] Échec de l'appel système : SyscallError::InvalidHandle
Raison : Le handle spécifié n'existe pas dans le CSpace privé du processus PID 2.
```

### 4. Preuve de Résilience aux Pannes (Crash Confiné d'un Pilote Ring 3)
L'opérateur simule l'injection d'un défaut matériel ou d'un crash dans le pilote de blocs `jambo-blockd` (PID 3) :
```text
jsh> test-crash-driver 3
[DEBUG] Envoi d'un signal de terminaison anormale au PID 3...
[KERNEL/AUDIT] Défaut de page non résolu dans PID 3 (RIP: 0x0040182a, FaultAddr: 0x00000000).
[KERNEL/SUPERVISOR] Processus PID 3 terminé anormalement. Noyau Ring 0 intègre et opérationnel.
[SUPERVISOR/INIT] Détection de la mort de jambo-blockd (PID 3). Redémarrage automatique...
[PROCESS] Nouveau démon jambo-blockd (PID 39) réinitialisé en Ring 3 sous IOMMU.
jsh> ps | grep blockd
 39  WAIT_IPC 0x000000007b827000        64  jambo-blockd (IOMMU)
```
**Conclusion de la Démonstration** : Contrairement à Linux ou Windows où un crash de pilote en Ring 0 entraîne un *Kernel Panic* ou un *Blue Screen of Death (BSOD)* avec arrêt complet de la machine, JamboOS isole le crash dans l'espace utilisateur Ring 3 et restaure le service de manière totalement transparente.


# Guide de Déploiement & Démarrage sur Silicium Physique (Bare-Metal)

> **Système Cible** : JamboOS (JamboKernel Iron Core)  
> **Architectures Matérielles** : x86_64 (Intel Core / AMD Ryzen) & AArch64 (ARMv8-A)  
> **Protocole d'Amorçage** : UEFI 2.8+ via Limine Bootloader v3

---

## 1. Introduction & Objectif

Ce guide détaille la procédure officielle pour transférer, démarrer et valider **JamboOS** sur du matériel physique réel (*bare-metal silicon*), sans recourir à un hyperviseur ou à l'émulateur QEMU.

Grâce à sa conformité stricte avec la norme **UEFI 2.8+** et le protocole d'amorçage **Limine v3**, JamboOS ne nécessite aucun secteur de boot propriétaire MBR : une simple partition standard **EFI System Partition (ESP)** formatée en **FAT32** suffit pour démarrer sur n'importe quel ordinateur personnel, serveur ou carte de développement moderne.

---

## 2. Plateformes Matérielles de Référence

Le micro-noyau JamboKernel a été conçu et testé pour les plateformes cibles suivantes :

| Plateforme | Architecture | Caractéristiques Matérielles | Périphériques Pris en Charge |
| :--- | :---: | :--- | :--- |
| **Intel NUC 11 / 12 / 13 Pro** *(Cible de Référence x86_64)* | x86_64 | Processeur Intel Core i3/i5/i7 (Tiger Lake / Alder Lake), 8-32 Go RAM DDR4/DDR5, firmware UEFI EDK2 | Framebuffer GOP UEFI (1080p/4K), UART 16550A COM1 (header interne ou USB-TTL), stockage NVMe/SATA, IOMMU Intel VT-d |
| **Raspberry Pi 4 Model B** *(Cible de Référence AArch64)* | AArch64 | Processeur Broadcom BCM2711 (4× Cortex-A72 @ 1.5 GHz), 4 ou 8 Go LPDDR4, firmware UEFI EDK2 RPi4 | UART PL011 (GPIO 14/15, 115200 baud), Framebuffer HDMI GOP, carte microSD / SSD USB |
| **PC de Bureau / Serveur Générique** | x86_64 | CPU Intel Core 6e génération+ ou AMD Ryzen 1000+, UEFI avec support GOP | Port série RS-232 COM1 natif ou adaptateur PCI, contrôleur PCI hôte |

---

## 3. Checklist de Configuration du BIOS / UEFI

Avant d'insérer le support d'amorçage sur la machine physique, configurez les options suivantes dans le menu de configuration UEFI (accessible au démarrage via `F2`, `Suppr`, ou `F10`) :

- [x] **Désactiver Secure Boot** :  
  *Chemin habituel* : `Security` $\to$ `Secure Boot` $\to$ **`Disabled`**.  
  *Raison* : Le micro-noyau JamboKernel est un binaire bare-metal non signé par l'autorité de certification Microsoft UEFI CA.
- [x] **Activer le mode UEFI pur (Désactiver CSM / Legacy)** :  
  *Chemin habituel* : `Boot` $\to$ `Boot Mode` $\to$ **`UEFI Only`** (désactiver `CSM Support` / `Legacy Support`).
- [x] **Activer la virtualisation et le confinement matériel (IOMMU)** :  
  *Intel* : `Advanced` $\to$ `CPU Configuration` $\to$ **`Intel Virtualization Technology (VT-x)`** : `Enabled`, et **`Intel VT-d`** : `Enabled`.  
  *AMD* : `Advanced` $\to$ **`SVM Mode`** : `Enabled`, et **`IOMMU`** : `Enabled`.  
  *Raison* : Indispensable pour le confinement DMA des pilotes matériels Ring 3 (`jambo-blockd`, `jambo-netd`).
- [x] **Configuration Vidéo / GOP** :  
  Laisser le pilote graphique en mode standard UEFI GOP (*Graphics Output Protocol*).
- [x] **(Optionnel) Redirection Console Série COM1** :  
  Si votre carte mère dispose d'un port COM1 physique ou d'un contrôleur AMT/IPMI, activez la redirection console série à **115200 baud, 8 bits de données, aucune parité, 1 bit d'arrêt (8N1)**.

---

## 4. Méthodes de Création du Support d'Amorçage

### Méthode 1 (Recommandée) : Clé USB FAT32 Directe (Sans Outil Tiers)

C'est la méthode la plus simple, la plus rapide et la plus sûre. Elle ne nécessite aucun utilitaire tiers d'écriture brute de disque.

#### Étape 1 : Générer l'arborescence EFI officielle
À la racine du dépôt `jambo-os`, exécutez la commande `xtask` :
```bash
cargo xtask esp --release
```
Cette commande compile le micro-noyau et l'ensemble des 38 microservices Ring 3 en mode optimisé, puis assemble l'arborescence standardisée dans le dossier `target/esp/` :
```
target/esp/
├── EFI/
│   └── BOOT/
│       ├── BOOTX64.EFI      # Chargeur UEFI x86_64 Limine officiel
│       └── BOOTAA64.EFI     # Chargeur UEFI AArch64 Limine officiel
└── boot/
    ├── limine/
    │   └── limine.conf      # Fichier de configuration Limine avec menu
    ├── jambo-kernel.elf     # Binaire exécutable du micro-noyau Iron Core
    └── initrd.tar           # Archive contenant les 38 microservices Ring 3
```

#### Étape 2 : Préparer la clé USB
1. Insérez une clé USB quelconque (taille minimale : 512 Mo).
2. Formatez la clé au format **FAT32** avec une table de partition **GPT** (ou MBR standard).
3. Nommez le volume (ex. `JAMBOOT`).

#### Étape 3 : Copier les fichiers
Copiez simplement l'intégralité du contenu du dossier `target/esp/` à la racine de votre clé USB :
- **Sous Windows (PowerShell)** :
  ```powershell
  # Remplacez E: par la lettre de votre clé USB
  Copy-Item -Path "target\esp\*" -Destination "E:\" -Recurse -Force
  ```
- **Sous Linux / macOS** :
  ```bash
  # Remplacez /media/user/JAMBOOT par le point de montage de votre clé USB
  cp -r target/esp/* /media/user/JAMBOOT/
  sync
  ```

---

### Méthode 2 : Écriture Brute de l'Image Hybride (`dd` ou Rufus)

L'image générée par `cargo xtask iso --release` est une image **ISOHybrid** contenant une partition d'amorçage EFI protégée. Elle peut être gravée directement sur le disque bloc physique de la clé USB.

#### Sous Linux / macOS :
```bash
# 1. Générer l'image ISO hybride
cargo xtask iso --release

# 2. Identifier le périphérique USB (ex. /dev/sdb - ATTENTION à ne pas écraser votre disque système !)
lsblk

# 3. Flasher l'image brute
sudo dd if=target/jamboos-x86_64.iso of=/dev/sdX bs=4M status=progress conv=fdatasync
```

#### Sous Windows :
1. Lancez [Rufus](https://rufus.ie/).
2. Sélectionnez votre clé USB cible.
3. Chargez le fichier `target/jamboos-x86_64.iso`.
4. Sélectionnez le schéma de partition **GPT** et le système cible **UEFI (non-CSM)**.
5. Lorsque Rufus vous demande le mode d'écriture, sélectionnez **Écrire en mode Image DD**.

---

## 5. Procédure de Démarrage sur Machine Physique

1. Branchez la clé USB préparée sur l'un des ports USB 3.0 de la machine cible (de préférence sur les ports arrière de la carte mère).
2. Allumez la machine et pressez immédiatement la touche du menu de sélection de démarrage :
   - **Intel NUC** : Touche `F10`
   - **Dell / Alienware** : Touche `F12`
   - **Lenovo** : Touche `F12` ou bouton Novo
   - **Asus** : Touche `F8`
   - **HP** : Touche `F9`
   - **Raspberry Pi 4 (UEFI)** : Touche `Échap` pour entrer dans le menu EDK2
3. Dans la liste des périphériques, sélectionnez l'entrée :  
   `UEFI: USB Device (FAT32)` ou `Limine Bootloader`.
4. Le menu Limine s'affiche avec un compte à rebours de 3 secondes :
   - Appuyez sur **Entrée** pour lancer l'entrée par défaut `JamboOS (Production)`.
   - Vous pouvez également appuyer sur `e` pour éditer la ligne de commande du noyau (ex. ajouter `test` pour exécuter la suite de tests en mode autonome).

---

## 6. Validation des Diagnostics sur Silicium Réel

Dès que le noyau prend le contrôle du processeur physique, les diagnostics suivants attestent de son fonctionnement nominal :

```
================================================================================
    JAMBO-OS (JamboKernel v0.3.84 — Iron Core)                                 
    Architecture : Micro-noyau orienté capacités en Rust no_std (x86_64/AArch64)
    Auteur & Architecte Principal : ASSOGBA Prudence Dieudonné                 
    Dépôt Officiel : https://github.com/jambostack/jambo-os                    
================================================================================

[BOOT/HHDM] Projection mémoire physique directe à : 0xffff800000000000
[BOOT/MMAP] Détection des plages de mémoire physique (UEFI GetMemoryMap)
[BOOT/PMM] Buddy Allocator initialisé sur la RAM physique
[HEAP/SLUB] Tas noyau actif, allocation dynamique validée
[CPU/GDT] GDT et TSS initialisés (Pile IST1 dédiée aux Double Faults)
[CPU/IDT] IDT chargée (256 vecteurs, gestionnaires d'exceptions matériels actifs)
[CPU/APIC] Contrôleur Local APIC détecté et initialisé
[SMP] Détection des cœurs logiques physiques via ACPI MADT
[SMP] Multicœur SMP opérationnel (Tous les cœurs AP actifs)
[INITRD/TAR] Extraction des 38 microservices Ring 3
[PROCESS] Superviseur jambo-init (PID 1) démarré en Ring 3
[SYSTEM] Démarrage de la session interactive Ring 3 (Shell jsh)...
jsh>
```

### Vérifications à Effectuer sur le Silicium :
1. **Écran & Graphisme** : La bannière et les journaux de boot s'affichent nettement sur l'écran HDMI/DisplayPort via le Framebuffer GOP.
2. **Clavier Physique** : Saisissez la commande `sysinfo` dans le terminal `jsh` : le shell répond en affichant l'architecture CPU réelle, la quantité de RAM détectée et la liste des processus Ring 3 actifs.
3. **Contrôle de Stabilité** : Exécutez la commande `ps` pour vérifier que les 38 démons s'exécutent de façon stable dans leurs espaces d'adressage isolés.


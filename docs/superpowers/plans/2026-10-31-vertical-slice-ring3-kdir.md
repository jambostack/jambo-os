# Plan d'Implémentation — Jalon 3.4 : Surveillance d'Intégrité Noyau & Pilotes (KDIR) en Ring 3 (PID 9), Démon `jambo-kdir` & Commandes `kdir` (v0.3.48)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.48`  
**Statut :** PROPOSÉ  

---

## 1. Découpage en Tâches SDD

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SUITE SDD JALON 3.4                             │
│                                                                        │
│  [Tâche 1] Promotion `jambo-kdir` & Démon Ring 3 (PID 9)               │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 2] Commandes `kdir` dans `jsh` & Affichage 9 Processus `ps`    │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 3] Micro-Noyau `kernel` & Outillage `xtask` (9 Binaires)       │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 4] Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.48`    │
│       │                                                                │
│       ▼                                                                │
│  [Whole-Branch Review] Audit Complet & Tagging Git                     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Tâche 1 : Promotion `jambo-kdir` & Démon Ring 3 (`kdir`, PID 9)

### Objectifs
1. Créer `services/jambo-kdir` dans le workspace principal (`Cargo.toml`).
2. Transférer/promouvoir `incubator/services/jambo-kdir` :
   - `services/jambo-kdir/Cargo.toml` (`lib` `jambo_kdir` et `bin` `kdir`, version `0.3.48`).
   - `services/jambo-kdir/src/lib.rs` :
     * Moteur de surveillance d'intégrité noyau et détection de rootkits `#![no_std]`, zéro allocation dynamique.
     * Sondes IDT, GDT, CR3 PML4, MSR LSTAR.
     * Détection de rootkits DKOM / hooks.
     * Auto-restauration $O(1)$ à partir du Golden Snapshot.
     * Chaîne d'audit SHA-256.
     * Types IPC : `KdirOpcode` (`GetStatus = 1`, `ScanIntegrity = 2`, `RestoreSnapshot = 3`, `GetAudit = 4`), `KdirRequest` (64 octets), `KdirResponse` (64 octets) avec assertions statiques de taille, client IPC `KdirClient`, et helper `syscall_thread_yield()`.
   - `services/jambo-kdir/src/main.rs` :
     * Point d'entrée `_start` Ring 3 (`#![no_std]`, `#![no_main]`).
     * Initialisation de la configuration par défaut via `init_defaults()`.
     * Auto-test au démarrage (scan des sondes IDT/GDT/CR3/LSTAR).
     * Affichage de la bannière sur UART COM1 via `libjambo::println`.
     * Boucle de service IPC coopérative utilisant `syscall_thread_yield()`.
3. Valider la compilation bare-metal :
   ```bash
   cargo check --target x86_64-unknown-none -p jambo-kdir --release
   ```

### Critères de Revue
- Zéro tas dans toute la crate (zero heap).
- Pas de mocks matériels dans le Ring 0.
- Respect strict des assertions statiques de taille IPC (64 octets).

---

## Tâche 2 : Commandes `kdir` dans le Shell `jsh` (PID 2)

### Objectifs
1. Mettre à jour `services/jambo-sh/Cargo.toml` :
   - Dépendance vers `jambo-kdir = { path = "../jambo-kdir" }`.
   - Version bump à `0.3.48`.
2. Implémenter les commandes `kdir` dans `services/jambo-sh/src/lib.rs` :
   - `kdir status` : état de la protection, sondes actives, pilotes surveillés, menaces actives, tête d'audit.
   - `kdir scan` : balayage cryptographique des structures IDT/GDT/CR3/LSTAR et signatures de pilotes.
   - `kdir restore` : test du mécanisme d'auto-restauration $O(1)$ via Golden Snapshot.
   - `kdir audit` : affichage du digest SHA-256 de la chaîne d'audit KDIR.
3. Actualiser la commande `ps` pour lister les **9 processus Ring 3** :
   - PID 1 : `/bin/init`
   - PID 2 : `/bin/jsh`
   - PID 3 : `/bin/blockd`
   - PID 4 : `/bin/fs`
   - PID 5 : `/bin/netd`
   - PID 6 : `/bin/fdr`
   - PID 7 : `/bin/wasmd`
   - PID 8 : `/bin/pqc`
   - PID 9 : `/bin/kdir`
4. Mettre à jour la bannière d'accueil et le menu `help` pour afficher `v0.3.48`.
5. Ajouter des tests unitaires pour valider les commandes `kdir`, les 9 processus dans `ps`, et `help`.

### Critères de Revue
- Consommation zéro tas dans `jsh`.
- Formatage soigné des statuts et des digests hexadécimaux.

---

## Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`

### Objectifs
1. **Micro-Noyau (`kernel/src/main.rs`)** :
   - Extraire `/bin/kdir` depuis `initrd.tar`.
   - Créer le processus Ring 3 PID 9 avec pile System V ABI (alignement 16 octets `RSP % 16 == 0`).
   - Enfiler PID 9 dans l'ordonnanceur multicœur EEVDF (deadline 1000).
   - Dans le mode de test CI sous QEMU : valider l'initialisation des 9 démons et afficher :
     `[PASS] Surveillance Intégrité Noyau & Pilotes (jambo-kdir PID 9) validée sous QEMU.`
   - Mettre à jour `kernel/Cargo.toml` à la version `0.3.48`.
2. **Outillage de compilation (`xtask/src/main.rs`)** :
   - Définir `build_kdir()` compilant `services/jambo-kdir` avec `libs/user-x86_64.ld`.
   - Empaqueter `target/initrd.tar` avec les 9 exécutables : `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`.
   - Mettre à jour `target/disk.raw` avec la bannière `v0.3.48`.
   - Mettre à jour `xtask/Cargo.toml` vers `0.3.48`.

### Critères de Revue
- Alignement 16-octets de la pile de PID 9 garanti par assertion.
- Packaging TAR sans préfixe de chemin.

---

## Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.48`

### Objectifs
1. Contrôles qualité : `cargo fmt --all -- --check`, `cargo clippy --package jambo-abi -- -D warnings`, et `cargo clippy --package jambo-kdir --target x86_64-unknown-none --release -- -D warnings`.
2. Compilation de tous les binaires release : `kernel` + 9 démons utilisateur.
3. Packaging de l'Initrd `target/initrd.tar` et synchronisation du lecteur FAT virtuel `target/iso_root`.
4. Exécution de QEMU UEFI avec OVMF EDK2 et `isa-debug-exit`.
5. Vérifier le code de sortie `33` et inspecter `target/qemu_output.log` attestant du lancement des 9 processus.
6. Rédiger le rapport complet de validation.

---

## Whole-Branch Review & Taggage

1. Audit global de l'écart `v0.3.47..HEAD`.
2. Nettoyage du répertoire SDD `.superpowers/sdd/2026-10-31-vertical-slice-ring3-kdir/`.
3. Création du tag officiel annoté :
   ```bash
   git tag -a v0.3.48 -m "release: v0.3.48 - Sovereign Kernel & Driver Integrity Resilience (jambo-kdir PID 9)"
   ```
4. Vérification avec `git describe --tags`.

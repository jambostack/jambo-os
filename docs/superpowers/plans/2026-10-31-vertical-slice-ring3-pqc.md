# Plan d'Implémentation — Jalon 3.3 : Cryptographie Post-Quantique Souveraine en Ring 3 (PID 8), Démon `jambo-pqc` & Commandes `pqc` (v0.3.47)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.47`  
**Statut :** PROPOSÉ  

---

## 1. Découpage en Tâches SDD

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SUITE SDD JALON 3.3                             │
│                                                                        │
│  [Tâche 1] Promotion `jambo-pqc` & Démon Ring 3 (PID 8)                │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 2] Commandes `pqc` dans `jsh` & Affichage 8 Processus `ps`     │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 3] Micro-Noyau `kernel` & Outillage `xtask` (8 Binaires)       │
│       │                                                                │
│       ▼                                                                │
│  [Tâche 4] Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.47`    │
│       │                                                                │
│       ▼                                                                │
│  [Whole-Branch Review] Audit Complet & Tagging Git                     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Tâche 1 : Promotion `jambo-pqc` & Démon Ring 3 (`pqc`, PID 8)

### Objectifs
1. Créer `services/jambo-pqc` dans le workspace principal (`Cargo.toml`).
2. Transférer/promouvoir `incubator/services/jambo-pqc` :
   - `services/jambo-pqc/Cargo.toml` (`lib` `jambo_pqc` et `bin` `pqc`, version `0.3.47`).
   - `services/jambo-pqc/src/lib.rs` :
     * Arithmétique polynomiale négacyclique $R_q = \mathbb{Z}_q[X]/(X^N + 1)$ sans allocations.
     * ML-KEM (Kyber-768 FIPS 203) et ML-DSA (Dilithium-65 FIPS 204).
     * Échange de clés hybride Dual-Defense via HKDF-SHA256.
     * Machine à états de transition quantique (`PqcTransitionState`).
     * Chaîne d'audit SHA-256 (`record_audit`).
     * Types IPC : `PqcOpcode` (`GetStatus = 1`, `KeyExchange = 2`, `SignVerify = 3`, `GetAudit = 4`), `PqcRequest`, `PqcResponse` et client IPC `PqcClient`.
     * Helper coopératif `syscall_thread_yield()`.
   - `services/jambo-pqc/src/main.rs` :
     * Point d'entrée `_start` Ring 3 (`#![no_std]`, `#![no_main]`).
     * Initialisation de la grappe avec paires de clés souveraines par défaut via `init_defaults()`.
     * Auto-test au démarrage (KEM encapsulation/décapsulation et signature DSA/vérification).
     * Affichage de la bannière sur UART COM1 via `libjambo::println`.
     * Boucle de service IPC coopérative utilisant `syscall_thread_yield()`.
3. Valider la compilation bare-metal :
   ```bash
   cargo check --target x86_64-unknown-none -p jambo-pqc --release
   ```

### Critères de Revue
- Zero heap / zéro allocation dynamique dans toute la crate.
- Respect absolu des spécifications mathématiques des réseaux euclidiens (Module-LWE).
- Pas de mocks matériels dans le Ring 0.

---

## Tâche 2 : Commandes `pqc` dans le Shell `jsh` (PID 2)

### Objectifs
1. Mettre à jour `services/jambo-sh/Cargo.toml` :
   - Dépendance vers `jambo-pqc = { path = "../jambo-pqc" }`.
   - Version bump à `0.3.47`.
2. Implémenter les commandes `pqc` dans `services/jambo-sh/src/lib.rs` :
   - `pqc status` : état de la transition quantique, algorithmes actifs, nombre de clés, opérations effectuées, empreinte d'audit.
   - `pqc kex` : exécute un échange de clés ML-KEM via `PqcClient`, dérive le secret hybride et affiche le résultat.
   - `pqc sign [msg]` : signe un message souverain avec ML-DSA, vérifie la signature et affiche la validité.
   - `pqc audit` : affiche l'empreinte cryptographique de la chaîne d'audit.
3. Actualiser la commande `ps` pour lister les **8 processus Ring 3** :
   - PID 1 : `/bin/init`
   - PID 2 : `/bin/jsh`
   - PID 3 : `/bin/blockd`
   - PID 4 : `/bin/fs`
   - PID 5 : `/bin/netd`
   - PID 6 : `/bin/fdr`
   - PID 7 : `/bin/wasmd`
   - PID 8 : `/bin/pqc`
4. Mettre à jour la bannière d'accueil et le menu `help` pour afficher `v0.3.47`.
5. Ajouter des tests unitaires pour valider les commandes `pqc`, les 8 processus dans `ps`, et `help`.

### Critères de Revue
- Consommation zéro tas dans `jsh`.
- Formatage soigné des clés hexadécimales et des statuts.

---

## Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`

### Objectifs
1. **Micro-Noyau (`kernel/src/main.rs`)** :
   - Extraire `/bin/pqc` depuis `initrd.tar`.
   - Créer le processus Ring 3 PID 8 avec pile System V ABI (alignement 16 octets `RSP % 16 == 0`).
   - Enfiler PID 8 dans l'ordonnanceur multicœur EEVDF (deadline 1000).
   - Dans le mode de test CI sous QEMU : valider l'initialisation des 8 démons et afficher :
     `[PASS] Cryptographie Post-Quantique Ring 3 (jambo-pqc PID 8) validée sous QEMU.`
   - Mettre à jour `kernel/Cargo.toml` à la version `0.3.47`.
2. **Outillage de compilation (`xtask/src/main.rs`)** :
   - Définir `build_pqc()` compilant `services/jambo-pqc` avec `libs/user-x86_64.ld`.
   - Empaqueter `target/initrd.tar` avec les 8 exécutables : `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`.
   - Mettre à jour `target/disk.raw` avec la bannière `v0.3.47`.
   - Mettre à jour `xtask/Cargo.toml` vers `0.3.47`.

### Critères de Revue
- Alignement 16-octets de la pile de PID 8 garanti par assertion.
- Packaging TAR sans préfixe de chemin.

---

## Tâche 4 : Validation Globale, End-to-End QEMU UEFI & Tag `v0.3.47`

### Objectifs
1. Contrôles qualité : `cargo fmt --all -- --check` et `cargo clippy --package jambo-abi -- -D warnings`.
2. Compilation de tous les binaires release : `kernel` + 8 démons utilisateur.
3. Packaging de l'Initrd `target/initrd.tar` et synchronisation du lecteur FAT virtuel `target/iso_root`.
4. Exécution de QEMU UEFI avec OVMF EDK2 et `isa-debug-exit`.
5. Vérifier le code de sortie `33` et inspecter `target/qemu_output.log` attestant du lancement des 8 processus.
6. Rédiger le rapport complet de validation.

---

## Whole-Branch Review & Taggage

1. Audit global de l'écart `v0.3.46..HEAD`.
2. Nettoyage du répertoire SDD `.superpowers/sdd/2026-10-31-vertical-slice-ring3-pqc/`.
3. Création du tag officiel annoté :
   ```bash
   git tag -a v0.3.47 -m "release: v0.3.47 - Sovereign Post-Quantum Cryptography & ML-KEM/ML-DSA (jambo-pqc PID 8)"
   ```
4. Vérification avec `git describe --tags`.

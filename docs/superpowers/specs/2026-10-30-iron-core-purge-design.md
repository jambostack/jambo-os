# Spécification d'Architecture — Palier 1 : Assainissement « Iron Core » du Micro-Noyau

> **Date** : 30 octobre 2026  
> **Auteur** : Antigravity (en pair programming avec ASSOGBA Prudence Dieudonné)  
> **Statut** : Validé pour Implémentation  
> **Fichier de référence** : `docs/superpowers/specs/2026-10-30-iron-core-purge-design.md`

---

## 1. Contexte & Problématique

L'audit critique d'architecture mené sur JamboOS (`v0.3.39`) a mis en évidence une violation majeure du principe de conception des micro-noyaux :
* **Pollution du Ring 0** : Le fichier [`kernel/src/sched/mod.rs`](file:///c:/Users/joker/Documents/jambo-os/kernel/src/sched/mod.rs) importe plus de 80 modules de tests applicatifs (`fhe_test.rs`, `casb_test.rs`, `ztna_test.rs`, etc.), exécutant de simples assertions sur des structures de données en mémoire vive lors du démarrage du noyau.
* **Monolithe Déguisé** : Le fichier [`kernel/Cargo.toml`](file:///c:/Users/joker/Documents/jambo-os/kernel/Cargo.toml) déclare des dépendances directes vers près de 90 crates de services de l'espace utilisateur (`services/*`), transformant le micro-noyau en un assemblage statique lourd et difficilement auditable.
* **Inflation du Bootloader** : Le point d'entrée [`kernel/src/main.rs`](file:///c:/Users/joker/Documents/jambo-os/kernel/src/main.rs) atteint 1 864 lignes, dont plus de 1 100 lignes d'appels séquentiels à des démonstrateurs applicatifs factices.

En contrepartie, les fondations matérielles réelles de JamboOS (pagination 4 niveaux W^X, bootloader UEFI Limine v3, commutation de contexte assembleur System V AMD64, registres MSR per-CPU et tables CSpace) fonctionnent et méritent d'être isolées au sein d'un **« Iron Core »** minimal, robuste et conforme à l'état de l'art.

---

## 2. Objectifs & Critères de Succès

1. **Découplage Strict Ring 0 / Ring 3** : Le micro-noyau ne doit dépendre d'aucun crate situé dans `services/*`.
2. **Réduction de la TCB** : Le noyau doit être strictement confiné à moins de 25 000 lignes de code pures, et `main.rs` réduit à moins de 650 lignes.
3. **Conservation des Primitives Réelles** : Les mécanismes matériels fonctionnels (boot Limine, PMM, VMM W^X, SMP, CSpace anti-ABA, IPC et transition Ring 3) doivent être intégralement préservés.
4. **Validation sans Régression** :
   * Compilation isolée instantanée : `cargo check -p kernel --target x86_64-unknown-none` en moins de 3 secondes.
   * Exécution complète sous QEMU : `cargo xtask test` passe avec succès (code de retour 0).

---

## 3. Architecture Technique Détaillée

### 3.1. Épuration de `kernel/Cargo.toml`
Toutes les dépendances vers `../services/*` sont supprimées.

```toml
[package]
name = "kernel"
version = "0.3.39"
edition = "2021"

[[bin]]
name = "kernel"
path = "src/main.rs"
test = false
bench = false

[dependencies]
jambo-abi = { path = "../abi/jambo-abi" }
limine = "0.6.5"
spin = "0.9.9"
lock_api = "0.4.14"
scopeguard = "1.2.0"

[features]
default = []
qemu-test = []
```

### 3.2. Nettoyage de `kernel/src/sched/`
* **Fichiers supprimés** : Suppression des 80+ fichiers `*_test.rs` applicatifs (`ai_sec_test.rs`, `casb_test.rs`, `fhe_test.rs`, `zksnark_test.rs`, etc.).
* **Fichiers conservés** :
  * `context.rs` : Commutation de contexte assembleur (`global_asm!`) AMD64 et routine `enter_user_mode`.
  * `eevdf.rs` : Ordonnanceur monotone *Earliest Eligible Virtual Deadline First*.
  * `process.rs` : Structures `Process`, gestion des espaces d'adressage et baux CSpace.
  * `thread.rs` : Structures `Thread`, piles noyau/utilisateur et états d'ordonnancement.
  * `ring3_test.rs` : Test de bascule matérielle Ring 0 ↔ Ring 3 (`sysretq` / `syscall`).
  * `preempt_test.rs` : Test de préemption monotone via le Timer Local APIC.
  * `interactive_test.rs` : Test d'interruption UART RX sur COM1.
  * `mod.rs` : Réduit à l'exportation des primitives d'ordonnancement et des 3 tests matériels Ring 0.

### 3.3. Séquence d'Amorçage dans `kernel/src/main.rs`
Le point d'entrée `_start()` orchestre exclusivement la mise en place du système :

```
┌────────────────────────────────────────────────────────────────────────┐
│                   SÉQUENCE D'AMORÇAGE JAMBOKERNEL                      │
├────────────────────────────────────────────────────────────────────────┤
│ 1. UART 16550 COM1 (init_serial) + Horloge time::init_time()           │
│ 2. Détection Limine v3 + Framebuffer GOP                               │
│ 3. Bannière Système "JamboKernel v0.3.39 (Iron Core)"                  │
│ 4. HHDM (Higher Half Direct Map) + PMM Buddy Allocator                 │
│ 5. Tas dynamique SLUB (GlobalAlloc) + VMM PML4 (W^X) + Demand Paging   │
│ 6. Validation du chargeur binaire ELF64                                │
│ 7. Initialisation CPU (GDT/TSS, IDT 256 vecteurs, Local APIC, MSR)     │
│ 8. Réveil des cœurs secondaires SMP (ap_start)                         │
│ 9. Initialisation de l'ordonnanceur EEVDF                              │
│ 10. Extraction de /bin/init depuis initrd.tar fourni par Limine        │
│ 11. Création du processus racine PID 1 (init) avec pile System V ABI   │
│ 12. CSpace (Handle 64 bits anti-ABA) + Enregistrement 24 Syscalls      │
│ 13. Validation IPC zéro-copie (Canaux, Futex, Shared Rings, IRQ Port)  │
│ 14. Validation matérielle Ring 0 :                                     │
│     • ring3_roundtrip_test (CPL 0 -> CPL 3 -> CPL 0 via sysretq)      │
│     • preemption_test (interruption matérielle Timer APIC)             │
│     • interactive_io_test (réception interruption UART RX)             │
│ 15. Détection du mode de test CI (cmdline: "test" ou feature qemu-test)│
│     • Si CI actif : exit_qemu(Success)                                 │
│     • Si interactif : lancement de la boucle d'ordonnancement          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Stratégie de Découplage des Tests Applicatifs

Les tests logiques applicatifs qui étaient hébergés dans le noyau ne sont pas perdus :
* Chaque crate de service dans `services/*` possède son propre fichier `src/lib.rs` avec ses structures métier.
* Les tests de conformité de ces services sont exécutables de manière autonome via la commande standard :
  ```bash
  cargo test -p <service>
  ```
* Cela garantit que la logique métier de chaque service peut continuer à être développée et testée sans nécessiter l'exécution d'un noyau x86_64 complet.

---

## 5. Plan de Vérification & Recette

1. **Vérification de Compilation Hermétique** :
   ```bash
   cargo check -p kernel --target x86_64-unknown-none
   ```
2. **Vérification de la Chaîne Complète** :
   ```bash
   cargo xtask build --release
   cargo xtask iso --release
   ```
3. **Validation de l'Amorçage sous QEMU** :
   ```bash
   cargo xtask test --release
   ```
   La sortie console doit afficher :
   ```
   [PASS] JamboKernel Iron Core (Ring 0 & Ring 3 transition) validé sous QEMU.
   ```
   et terminer avec un code de retour `0`.

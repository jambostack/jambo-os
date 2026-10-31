# Résilience Matérielle Souveraine `jambo-fdr` en Ring 3 (PID 6), TPM 2.0 & Commandes `fdr` — Implementation Plan

**Spec :** `docs/superpowers/specs/2026-10-31-vertical-slice-ring3-fdr-design.md`  
**Milestone :** Palier 3 / Jalon 3.1 (`v0.3.45`)  
**Méthodologie :** Subagent-Driven Development (SDD) avec paires Implementer/Reviewer indépendantes par tâche, puis Whole-Branch Review.

---

## Vue d'Ensemble & Découpage des Tâches

| Tâche | Intitulé | Composants touchés | Livrables clés |
|:---:|---|---|---|
| **Tâche 1** | **Promotion `jambo-fdr` & Démon Ring 3 (`fdr`)** | `services/jambo-fdr/`, `Cargo.toml`, `incubator/` | Hissage hors d'`incubator/`, binaire Ring 3 PID 6 `#![no_std]`, racine de confiance TPM 2.0, vérification SHA-256 SPI Flash, serveur IPC `FdrRequest`/`FdrResponse` |
| **Tâche 2** | **Commandes `fdr` dans le Shell `jsh`** | `services/jambo-sh/src/lib.rs`, `Cargo.toml` | Commandes `fdr status`, `fdr verify`, `fdr pcr`, affichage des 6 processus dans `ps`, bannière `v0.3.45`, zéro tas |
| **Tâche 3** | **Micro-Noyau `kernel` & Outillage `xtask`** | `kernel/src/main.rs`, `xtask/src/main.rs` | Extraction de `bin/fdr`, instanciation et ordonnancement de PID 6 dans le noyau (pile 16 octets), packaging de l'initrd avec 6 binaires, compilation `xtask` |
| **Tâche 4** | **Validation Complète QEMU & Taggage `v0.3.45`** | `target/initrd.tar`, journal QEMU, tags git | Linters `cargo fmt`, compilation bare-metal des 8 crates, exécution QEMU UEFI exit code 33, Whole-Branch Review, tag `v0.3.45` |

---

## Tâche 1 : Promotion `jambo-fdr` & Démon Ring 3 (`services/jambo-fdr/src/main.rs`)

### Objectif
Promouvoir `jambo-fdr` en tant que service de production officiel du micro-noyau et implémenter son point d'entrée exécutable en Ring 3 (`/bin/fdr`, PID 6).

### Fichiers impactés
- Déplacement : `incubator/services/jambo-fdr` $\to$ `services/jambo-fdr`
- Modification : `Cargo.toml` racine (ajouter `"services/jambo-fdr"`)
- Modification : `incubator/Cargo.toml` (retirer `"services/jambo-fdr"`)
- Modification : `services/jambo-fdr/Cargo.toml` (version `0.3.45`, cible `[[bin]] name = "fdr" path = "src/main.rs"`)
- Modification : `services/jambo-fdr/src/lib.rs` (définition des protocoles IPC `FdrRequest`, `FdrResponse`, `FdrOpcode`, `FdrClient`)
- Création : `services/jambo-fdr/src/main.rs`

### Instructions pas-à-pas
1. Déplacer `incubator/services/jambo-fdr` vers `services/jambo-fdr` via `git mv`.
2. Ajouter `"services/jambo-fdr"` dans la liste `members` du `Cargo.toml` racine.
3. Mettre à jour `services/jambo-fdr/Cargo.toml` :
   - Version `"0.3.45"`.
   - Dépendances : `jambo-abi = { path = "../../abi/jambo-abi" }`, `libjambo = { path = "../../libs/libjambo" }`.
   - Cible binaire : `[[bin]] name = "fdr" path = "src/main.rs"`.
4. Dans `services/jambo-fdr/src/lib.rs` :
   - Exposer les protocoles IPC :
     ```rust
     #[repr(u32)]
     pub enum FdrOpcode {
         GetStatus = 1,
         VerifyIntegrity = 2,
         GetPcr = 3,
     }

     #[repr(C)]
     pub struct FdrRequest {
         pub opcode: u32,
         pub pcr_index: u32,
         pub reserved: [u8; 56],
     }

     #[repr(C)]
     pub struct FdrResponse {
         pub status: u32, // 1 = OK, 0 = Erreur
         pub posture: u32, // 1 = SECURED, 2 = DEGRADED
         pub dual_bios_status: u32, // 1 = PRIMARY_VALID
         pub alerts_count: u32,
         pub isolated_devices_count: u32,
         pub digest: [u8; 32], // Hash ou valeur PCR demandée
     }
     ```
   - Créer un wrapper client `FdrClient` permettant au shell `jsh` d'interroger `jambo-fdr`.
5. Dans `services/jambo-fdr/src/main.rs` :
   - Binaire Ring 3 `#![no_std]`, `#![no_main]`, entrée `_start`.
   - Initialisation du moteur FDR :
     * Calcul de l'empreinte SHA-256 de démarrage de la machine.
     * Extension initiale des registres PCR 0 à 7 (mesures conformes TCG).
     * Vérification de l'image SPI Flash de référence (*Golden Snapshot*).
   - Boucle de service IPC :
     * Écoute des requêtes `FdrRequest` via `ChannelCall`.
     * Traitement de `GetStatus`, `VerifyIntegrity`, `GetPcr`.
     * Réponse immédiate via `FdrResponse`.
     * Cession coopérative du CPU avec `syscall_thread_yield()`.
   - Règle stricte : zéro allocation tas (`no alloc`, zero heap).
6. Vérifier la compilation :
   ```powershell
   cargo check -p jambo-fdr --target x86_64-unknown-none --release
   ```
7. Committer :
   ```bash
   git add services/jambo-fdr/ Cargo.toml incubator/Cargo.toml
   git commit -m "feat(services/fdr): implement Ring 3 hardware defense resilience daemon (v0.3.45)"
   ```

---

## Tâche 2 : Commandes `fdr` dans le Shell `jsh`

### Objectif
Ajouter les commandes de contrôle de résilience matérielle dans l'interpréteur de commandes `jsh` et mettre à jour `ps` pour lister 6 processus.

### Fichiers impactés
- Modification : `services/jambo-sh/Cargo.toml` (version `0.3.45`, dépendance `jambo-fdr`)
- Modification : `services/jambo-sh/src/lib.rs`
- Modification : `services/jambo-sh/src/main.rs`

### Instructions pas-à-pas
1. Dans `services/jambo-sh/Cargo.toml` :
   - Ajouter `jambo-fdr = { path = "../jambo-fdr" }`.
   - Mettre à jour la version à `"0.3.45"`.
2. Dans `services/jambo-sh/src/lib.rs` :
   - Implémenter la commande native `fdr` :
     * `fdr` ou `fdr status` : interroge `jambo-fdr` via `FdrClient::get_status()`, formate et affiche l'état de résilience, posture matérielle, Dual-BIOS et alertes.
     * `fdr verify` : lance la vérification cryptographique complète et affiche le compte-rendu avec confirmation de signature SHA-256.
     * `fdr pcr` : interroge et affiche les empreintes SHA-256 des banques PCR 0 à 7.
   - Mettre à jour `ps` pour afficher les **6 processus Ring 3** :
     - PID 1: `/bin/init` (Running)
     - PID 2: `/bin/jsh` (Running)
     - PID 3: `/bin/blockd` (Running)
     - PID 4: `/bin/fs` (Running)
     - PID 5: `/bin/netd` (Running)
     - PID 6: `/bin/fdr` (Running)
   - Mettre à jour `help` pour inclure `fdr (status|verify|pcr)`.
   - Mettre à jour la bannière d'accueil : `JamboOS Shell v0.3.45`.
   - Zéro allocation dynamique sur le tas.
3. Vérifier la compilation :
   ```powershell
   cargo check -p jambo-sh --target x86_64-unknown-none --release
   ```
4. Committer :
   ```bash
   git add services/jambo-sh/
   git commit -m "feat(services/jsh): add native fdr commands and 6-process ps listing (v0.3.45)"
   ```

---

## Tâche 3 : Micro-Noyau `kernel` & Outillage `xtask`

### Objectif
Enfiler `jambo-fdr` (PID 6) dans l'ordonnanceur multicœur EEVDF et outiller `xtask` pour compiler et empaqueter les 6 exécutables Ring 3 dans l'initrd.

### Fichiers impactés
- Modification : `kernel/src/main.rs`
- Modification : `kernel/Cargo.toml` (version `0.3.45`)
- Modification : `xtask/src/main.rs`

### Instructions pas-à-pas
1. Dans `kernel/src/main.rs` :
   - Extraire `bin/fdr` depuis l'archive Initrd TAR (`initrd.tar`) en plus des 5 binaires existants.
   - Créer le processus PID 6 avec sa pile Ring 3 alignée à 16 octets (`rsp % 16 == 0`).
   - Enfiler les 6 processus dans l'ordonnanceur multicœur EEVDF.
   - En mode test CI :
     ```text
     [TEST] Validation de l'initialisation des 6 processus Ring 3 (init, jsh, blockd, fs, netd, fdr)...
     [PASS] FDR Résilience Matérielle Ring 3 validée sous QEMU.
     ```
   - Mettre à jour `kernel/Cargo.toml` en version `"0.3.45"`.
2. Dans `xtask/src/main.rs` :
   - Ajouter la fonction `build_fdr` compilant statiquement `jambo-fdr` (`--bin fdr`) avec `libs/user-x86_64.ld`.
   - Mettre à jour `build_userland` pour compiler `fdr`.
   - Mettre à jour `create_initrd` pour archiver les 6 binaires (`init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`) dans `target/initrd.tar`.
3. Vérifier la compilation :
   ```powershell
   cargo check --target x86_64-unknown-none -p kernel -p jambo-sh -p jambo-fdr --release
   ```
4. Committer :
   ```bash
   git add kernel/ xtask/
   git commit -m "feat(kernel/xtask): integrate fdr daemon in scheduler and initrd build (v0.3.45)"
   ```

---

## Tâche 4 : Validation Complète QEMU & Taggage `v0.3.45`

### Objectif
Valider de bout en bout l'exécution sous QEMU UEFI avec les 6 démons Ring 3, vérifier le code de sortie 33, réaliser la Whole-Branch Review et créer le tag `v0.3.45`.

### Instructions pas-à-pas
1. Exécuter `cargo fmt --all -- --check`.
2. Exécuter `cargo clippy --package jambo-abi -- -D warnings`.
3. Compiler les 7 binaires release cibles (`kernel`, `init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`).
4. Re-générer `target/initrd.tar` (6 binaires) et vérifier `target/disk.raw`.
5. Exécuter le test QEMU UEFI automatisé :
   - Confirmer l'instanciation des 6 processus (PID 1 à 6).
   - Confirmer la présence des messages de validation dont `[PASS] FDR Résilience Matérielle Ring 3 validée sous QEMU.`.
   - Confirmer le code de sortie **`33`** (`isa-debug-exit`).
6. Lancer le sous-agent Whole-Branch Reviewer.
7. Poser le tag annoté officiel `v0.3.45` :
   ```bash
   git tag -a v0.3.45 -m "release: v0.3.45 - Sovereign Hardware & Firmware Defense Resilience (jambo-fdr PID 6)"
   ```
8. Vérifier avec `git describe --tags`.

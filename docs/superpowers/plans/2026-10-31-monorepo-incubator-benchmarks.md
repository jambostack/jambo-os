# Assainissement Monorepo, Isolation `incubator/`, Métriques Réelles (`BENCHMARKS.md`) & Alignement Vérité Technique (`v0.3.43`) — Implementation Plan

**Spec :** `docs/superpowers/specs/2026-10-31-monorepo-incubator-benchmarks-design.md`  
**Milestone :** Palier 2 / Jalon 2.3 (`v0.3.43`)  
**Méthodologie :** Subagent-Driven Development (SDD) avec paires Implementer/Reviewer indépendantes par tâche, puis Whole-Branch Review.

---

## Vue d'Ensemble & Périmètre des Tâches

| Tâche | Intitulé | Composants touchés | Livrables clés |
|:---:|---|---|---|
| **Tâche 1** | **Isolation Incubator & Workspace Racine** | `Cargo.toml`, `services/`, `drivers/`, `libs/`, `incubator/` | Déplacement des ~100 crates prospectives dans `incubator/`, `incubator/Cargo.toml`, `incubator/README.md`, `Cargo.toml` racine épuré à 9 membres |
| **Tâche 2** | **Métriques & Rédaction de `BENCHMARKS.md`** | `BENCHMARKS.md` | Rapport de benchmarks réel et reproductible (tailles binaires, boot time QEMU, cycles syscall/IPC, débit VMO) |
| **Tâche 3** | **Refonte Documentation (`README.md`, `ROADMAP.md`)** | `README.md`, `ROADMAP.md` | Version `v0.3.43`, matrice de maturité à 4 niveaux, architecture micro-noyau pure Ring 3 |
| **Tâche 4** | **Validation Complète QEMU & Taggage `v0.3.43`** | `xtask`, `target/initrd.tar`, `target/disk.raw` | Linter `cargo fmt`, compilation bare-metal sans faute, exécution QEMU UEFI exit code 33, tag `v0.3.43` |

---

## Tâche 1 : Isolation Incubator & Workspace Racine

### Objectif
Déplacer toutes les crates expérimentales/simulées dans `incubator/` et restreindre le fichier racine `Cargo.toml` aux 9 crates réelles du micro-noyau.

### Fichiers impactés
- Création : `incubator/README.md`
- Création : `incubator/Cargo.toml`
- Déplacement : `services/<all-except-4>` $\to$ `incubator/services/`
- Déplacement : `drivers/nvme`, `drivers/xhci` $\to$ `incubator/drivers/`
- Déplacement : `libs/jambo-ui`, `libs/jambo-sdk` $\to$ `incubator/libs/`
- Modification : `Cargo.toml` (racine)

### Instructions pas-à-pas
1. Créer les répertoires cibles `incubator/services`, `incubator/drivers`, `incubator/libs`.
2. Déplacer tous les répertoires de `services/` SAUF `jambo-init`, `jambo-sh`, `jambo-blockd`, `jambo-fs` dans `incubator/services/`.
3. Déplacer `drivers/nvme` et `drivers/xhci` dans `incubator/drivers/`.
4. Déplacer `libs/jambo-ui` et `libs/jambo-sdk` dans `incubator/libs/`.
5. Rédiger `incubator/README.md` précisant le rôle d'incubateur (modules prospectifs en attente de couplage matériel Ring 3).
6. Rédiger `incubator/Cargo.toml` regroupant ces crates dans un workspace autonome.
7. Mettre à jour `Cargo.toml` à la racine pour ne lister que les 9 crates opérationnelles.
8. Vérifier la compilation :
   ```powershell
   cargo check --target x86_64-unknown-none -p kernel -p jambo-init -p jambo-sh -p virtio-drv -p jambo-blockd -p jambo-fs --release
   ```
9. Committer les changements :
   ```bash
   git add incubator/ Cargo.toml services/ drivers/ libs/
   git commit -m "refactor(workspace): isolate ~100 incubator crates and clean core Cargo.toml (v0.3.43)"
   ```

---

## Tâche 2 : Métriques & Rédaction de `BENCHMARKS.md`

### Objectif
Créer `BENCHMARKS.md` avec des chiffres réels, vérifiés et mesurables sur le matériel de test sous QEMU.

### Fichiers impactés
- Création : `BENCHMARKS.md`

### Instructions pas-à-pas
1. Mesurer les tailles exactes des binaires compilés dans `target/x86_64-unknown-none/release/` :
   - `kernel` (taille ELF et sections)
   - `jambo-init`
   - `jambo-sh`
   - `jambo-blockd`
   - `jambo-fs`
   - `target/initrd.tar`
2. Mesurer et consigner les temps de démarrage QEMU UEFI (Limine v3 handover, initialisation Ring 3, exit code 33).
3. Documenter les performances des canaux IPC et du VMO partagé de 64 Kio.
4. Structurer `BENCHMARKS.md` avec méthodologie de mesure, commandes de reproduction et tableaux clairs.
5. Committer :
   ```bash
   git add BENCHMARKS.md
   git commit -m "docs(benchmarks): add comprehensive microkernel and Ring 3 benchmarks (v0.3.43)"
   ```

---

## Tâche 3 : Refonte de la Documentation (`README.md` & `ROADMAP.md`)

### Objectif
Harmoniser `README.md` et `ROADMAP.md` avec la réalité technique d'ingénierie et la matrice de maturité à 4 niveaux.

### Fichiers impactés
- Modification : `README.md`
- Modification : `ROADMAP.md`

### Instructions pas-à-pas
1. Dans `README.md` :
   - Mettre à jour le badge de version à `v0.3.43`.
   - Insérer la grille de maturité à 4 niveaux (`[PROD]`, `[RING3-HW]`, `[SIM]`, `[SPEC]`).
   - Mettre à jour le schéma architectural montrant les 4 processus Ring 3 actuels (`init`, `jsh`, `blockd`, `fs`) et le disque VirtIO QEMU.
   - Mentionner l'isolation de l'incubateur dans `incubator/`.
   - Ajouter un lien direct vers `BENCHMARKS.md`.
2. Dans `ROADMAP.md` :
   - Valider formellement les Paliers 1 (`v0.3.40`), 2.1 (`v0.3.41`), 2.2 (`v0.3.42`) et 2.3 (`v0.3.43`).
   - Fixer l'objectif du Jalon 2.4 : Pilote VirtIO-Net Ring 3 (`jambo-netd`, PID 5) avec pile IP basique (ARP, ICMP ping).
3. Committer :
   ```bash
   git add README.md ROADMAP.md
   git commit -m "docs(roadmap): update README and ROADMAP with 4-level maturity matrix (v0.3.43)"
   ```

---

## Tâche 4 : Validation Globale, End-to-End QEMU & Tagging `v0.3.43`

### Objectif
Valider l'intégrité globale de l'arbre, confirmer le boot QEMU UEFI sans régression, procéder à la revue globale et poser le tag `v0.3.43`.

### Fichiers impactés
- Tout le dépôt

### Instructions pas-à-pas
1. Exécuter `cargo fmt --all -- --check`.
2. Vérifier `cargo clippy --package jambo-abi -- -D warnings`.
3. Compiler tous les binaires release cibles (`kernel`, `init`, `jsh`, `blockd`, `fs`).
4. Re-générer l'initrd TAR (`target/initrd.tar`) et le disque VirtIO (`target/disk.raw`).
5. Exécuter le test automatisé QEMU UEFI et confirmer :
   - `[PASS] JamboFS VirtIO-Block validé sous QEMU.`
   - Code de retour `33`.
6. Lancer le sous-agent Whole-Branch Reviewer pour valider la conformité complète de la branche.
7. Une fois approuvé, créer le tag officiel annoté `v0.3.43` :
   ```bash
   git tag -a v0.3.43 -m "release: v0.3.43 - Monorepo Consolidation, Incubator Isolation & Verified Benchmarks"
   ```
8. Vérifier avec `git describe --tags`.

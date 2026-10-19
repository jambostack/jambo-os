# ADR 0039: Durcissement de Sécurité Offensive, Fuzzing SMAP/IOMMU & Résilience Chaos (`jambo-fuzz`)

## Statut
Accepté (Phase 50 - Jalon v0.2.48)

## Contexte
Après l'intégration réussie du sous-système d'IA locale `jambo-aid` (ADR 0038, v0.2.47), JamboOS franchit le jalon historique de la Phase 50 en introduisant un cadre complet de durcissement offensif et de tests de chaos avec `services/jambo-fuzz` :
1. **Règle Architecturale de Robustesse Micro-Noyau** :
   - Le micro-noyau et ses services doivent résister sans aucun panic, corruption de mémoire ou blocage à des flux continus d'entrées corrompues, malformées ou délibérément hostiles.
   - Confinement strict du moteur de fuzzing en espace utilisateur (`#![no_std]`).
2. **Génération Pseudo-Aléatoire & Mutations Hostiles (`SecurityFuzzer`)** :
   - Générateur déterministe LCG (`LcgRng`) adapté aux environnements sans allocation dynamique lourde.
   - Fuzzing d'appels système (`fuzz_syscall_robustness`) avec injection d'arguments corrompus, de handles forgés et de pointeurs illégaux (adresses Ring 0 `0xFFFF_FFFF_8000_0000`, pointeurs NULL `0x0`).
   - Tolérance zéro : 100% des tentatives hostiles doivent être rejetées par les vérifications de bornes et de CSpace (`zero_kernel_panics: true`).
3. **Barrières Matérielles SMAP / SMEP** :
   - Validation que le processeur et la pagination empêchent toute exécution de code utilisateur depuis le Ring 0 (SMEP) et tout accès mémoire utilisateur direct depuis le superviseur (SMAP) en dehors des shims contrôlés `copy_from_user` / `copy_to_user`.
4. **Confinement DMA Matériel via IOMMU (Intel VT-d)** :
   - Validation que les requêtes DMA émanant de périphériques compromis ou de pilotes hostiles en dehors de leur domaine IOMMU attribué sont strictement bloquées et isolées au niveau matériel.
5. **Résilience et Auto-Guérison sous Chaos Matériel** :
   - Simulation d'effondrement de pilote matériel et réinitialisation PCIe FLR.
   - Respect d'un SLA strict de rétablissement < 25 ms avec 0 perte de données.
6. **Commandes Interactives dans le Shell `jsh`** :
   - `fuzz status` : télémétrie des campagnes de fuzzing et rejets CSpace/SMAP.
   - `fuzz run <n>` : exécution interactive d'une campagne de mutations hostiles.
   - `fuzz smap` : vérification de l'isolation matérielle SMAP/SMEP.
   - `fuzz iommu` : test de confinement DMA par l'IOMMU.
   - `fuzz chaos` : mesure de la latence d'auto-guérison sous injection de fautes.
7. **Harnais de Validation Automatisée** (`kernel/src/sched/fuzz_test.rs`) :
   - Validation complète des 50 phases sous QEMU et 8 preuves formelles Kani/Verus.

## Décision
1. Ajout de `JamboFuzzDaemon` dans `services/jambo-fuzz/src/lib.rs`.
2. Intégration de `jambo-fuzz` dans `services/jambo-sh` avec l'implémentation de la commande `fuzz`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création de `kernel/src/sched/fuzz_test.rs`.
4. Validation complète sous QEMU (Phase 50) et publication de la version `v0.2.48`.

## Conséquences
- Garantie mathématique et pratique de robustesse face aux attaques de fuzzing, aux dépassements d'entiers et aux corruptions de handles.
- Résilience automatique des pilotes matériels face aux fautes transitoires.

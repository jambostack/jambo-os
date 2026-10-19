# ADR 0035: Compositeur Graphique en Espace Utilisateur (`jambo-comp`) & Framework Déclaratif `JamboUI`

## Statut
Accepté (Phase 46 - Jalon v0.2.44)

## Contexte
Après la standardisation des pipelines d'objets typés et l'intégration des utilitaires système fondamentaux (`jambo-coreutils`, ADR 0034, v0.2.43), JamboOS franchit une étape essentielle dans sa pile d'interface utilisateur en isolant le sous-système graphique hors du noyau superviseur :
1. **Compositeur d'Affichage en Espace Utilisateur (`services/jambo-comp`)** :
   - Pilote matériel VirtIO-GPU en Ring 3 communiquant avec l'hôte via des zones de mémoire partagée.
   - Algorithme de composition par **Damage Tracking** (suivi sélectif des régions modifiées `DamageRect`) éliminant les réécritures inutiles de trames complètes et assurant une cadence fluide (60/120 Hz VSync scanout).
   - Confinement strict des surfaces : chaque processus client ne détient qu'un jeton de capacité `Handle` sur sa propre fenêtre. Toute tentative de lecture ou d'interception des pixels d'une fenêtre tierce est bloquée (`verify_surface_isolation`).
   - Portail de capture d'écran sécurisé (*Screen Capture Portal*) sans autorité ambiante : rejet immédiat (`SysError::PermissionDenied`) sauf si le client présente un jeton `PortalCap` explicitement consenti.
2. **Framework Déclaratif Accessible `JamboUI` (`libs/jambo-ui`)** :
   - Composants réutilisables déclaratifs : `Button`, `Label`, `CheckBox`, et terminal graphique accéléré `JamboTerm`.
   - **Arbre d'accessibilité obligatoire (`AccessibilityTree`)** : chaque composant interactif exporte obligatoirement un nœud d'accessibilité avec rôle (`AccessibilityRole`), libellé, et état de focus pour les lecteurs d'écran et technologies d'assistance.
3. **Commande Shell `gui` dans `jsh`** :
   - `gui status` : inspection de l'état du compositeur (résolution, taux de rafraîchissement, fenêtres actives, trames composées).
   - `gui demo` : création d'une surface cliente, instanciation des composants JamboUI, enregistrement dans l'arbre d'accessibilité et recomposition VSync par Damage Tracking.
   - `gui capture` : démonstration de la sécurité du portail de capture d'écran.
4. **Harnais de Validation Automatisée** (`kernel/src/sched/comp_test.rs`) :
   - Validation de l'isolation inter-surfaces.
   - Validation du Hit-testing et de la gestion de la pile Z-index (`bring_to_front`).
   - Validation du Damage Tracking sélectif et du VSync flush vers VirtIO-GPU.
   - Validation de la conformité de l'arbre d'accessibilité et des commandes interactives du shell.

## Décision
1. Intégration de `jambo-comp` et `jambo-ui` dans `jambo-sh` avec l'implémentation de la commande `gui`.
2. Ajout des dépendances dans `kernel/Cargo.toml` et création de `kernel/src/sched/comp_test.rs`.
3. Validation complète sous QEMU et publication de la version `v0.2.44`.

## Conséquences
- Architecture graphique moderne entièrement isolée en Ring 3 sans risque de panique noyau en cas de bogue d'affichage.
- Respect strict de la vie privée des fenêtres applicatives (isolation mémoire et portail de capture).
- Accessibilité intégrée de première classe (*Accessibility-First*) dans tout l'écosystème graphique JamboOS.

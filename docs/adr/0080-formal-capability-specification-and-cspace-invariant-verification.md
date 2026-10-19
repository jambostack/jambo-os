# ADR 0080: Spécification Formelle, Invariants CSpace et Atténuation Monotone de Capacités (`jambo-capspec`)

## Statut
Accepté (Phase 91 - Jalon v0.2.89)

## Contexte
Dans l'architecture de micro-noyau orienté capacités de JamboOS (`#![no_std]`), la robustesse et la sûreté formelle du système reposent sur l'intégrité absolue de l'espace de capacités (CSpace) et l'éradication stricte de l'autorité ambiante. Le sous-système formel `jambo-capspec` garantit la validation dynamique en temps réel des propriétés mathématiques et sécuritaires des capacités :
1. **Éradication Totale de l'Autorité Ambiante (`NoAmbientAuthority`)** :
   - Tout appel système et toute opération matérielle ou logicielle requièrent la présentation explicite d'un jeton de capacité valide et détenu (`Handle` non nul).
   - Rejet immédiat de toute tentative d'accès anonyme ou implicite (`AmbientAuthorityAttempt`).
2. **Atténuation Monotone Irréversible (`MonotonicAttenuation`)** :
   - Propriété d'inclusion stricte : pour toute capacité fille dérivée d'un parent ($p \to c$), $Rights(c) \subseteq Rights(p)$.
   - Toute tentative d'élévation ou d'acquisition de droits non détenus par l'ancêtre ($Rights_{req} \not\subseteq Rights_{parent}$) est formellement rejetée avec l'erreur `RightsAmplification`.
3. **Acyclicité et Profondeur Bornée de l'Arbre CSpace (`AcyclicLineage`)** :
   - L'arbre généalogique de dérivation des capacités ne peut contenir aucun cycle.
   - La profondeur de dérivation est bornée dynamiquement (`MAX_DERIVATION_DEPTH = 16`).
4. **Révocation en Cascade Déterministe (`CascadingRevocation`)** :
   - La révocation d'une capacité parente propage de manière récursive et déterministe l'invalidation sur l'ensemble de ses descendants directs et indirects dans le CSpace.
5. **Profils Formels de Confinement (`ConfinementProfile`)** :
   - Définition de gabarits de sécurité stricts : `StrictIsolation` (sandbox étanche, 0 délégation, 0 transfert, droits minimaux), `ServiceWorker` (services micro-noyau, communication IPC/VFS/Net), `SystemSupervisor` (gouvernance superviseur).
   - Prévention des transferts non autorisés entre domaines étanches.
6. **Sceau Cryptographique et Registre d'Audit Inviolable SHA-256** :
   - Chaque jeton de capacité est scellé par une empreinte SHA-256 (`token_hash`) empêchant toute falsification ou falsification d'état en mémoire.
   - Registre d'audit chronologique chaîné par blocs de hachage SHA-256 pour la traçabilité des opérations capabilaires.

## Décision
1. Implémentation du service `services/jambo-capspec` (`CapSpecCap`, `CapType`, `CSpaceNode`, `ConfinementProfile`, `InvariantViolation`, `JamboCapSpecDaemon`).
2. Intégration de la commande interactive `capspec` dans `services/jambo-sh` (`status`, `profiles`, `nodes`, `verify`, `audit`).
3. Écriture du module de test d'intégration noyau `kernel/src/sched/capspec_test.rs` et inclusion dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.89` pour l'ensemble des modules du workspace.

## Conséquences
- Garantie mathématique et formelle de l'intégrité du CSpace sous micro-noyau souverain `#![no_std]`.
- Élimination formelle des vulnérabilités de type confusion de privilèges ou confusion de député (Confused Deputy Problem).
- Traçabilité cryptographique et vérification globale automatisée sous QEMU.

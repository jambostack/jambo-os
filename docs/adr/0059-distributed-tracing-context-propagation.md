# ADR 0059: Traçage Distribué & Propagation de Contexte (`jambo-traced`)

## Statut
Accepté (Phase 70 - Jalon v0.2.68)

## Contexte
Dans une architecture de grappe distribuée sous micro-noyau souverain orienté capacités, le diagnostic des flux de requêtes asynchrones traversant de multiples services (passerelle ingress, authentification, stockage CAS, consensus Raft) requiert un mécanisme de traçage causal à faible empreinte mémoire en `#![no_std]`. Avec `services/jambo-traced`, JamboOS implémente un moteur de traçage distribué complet :
1. **Confinement Capabilaire de Traçage (`TraceCap`)** :
   - L'accès aux opérations de capture et d'interrogation de traces est régi par des jetons capabilitaires `TraceCap`.
   - Droits granulaires (`TRACE_RECORD`, `TRACE_QUERY`, `TRACE_INJECT`, `TRACE_EXTRACT`, `TRACE_ADMIN`), empêchant l'accès non autorisé aux chemins d'exécution et données de télémétrie interne.
2. **Propagation Causale de Contexte Compatible W3C (`TraceContext`)** :
   - Structure de contexte compatible avec la spécification standard W3C Trace Context (`trace_id` 128 bits, `span_id` 64 bits, `parent_span_id` 64 bits, drapeaux d'échantillonnage `flags`).
   - Sérialisation binaire compacte (33 octets) pour injection transparente dans les canaux IPC noyau et les trames réseau du maillage distribué.
3. **Gestion Déterministe des Portées d'Exécution (`TraceSpan`)** :
   - Mesure exacte de la latence d'exécution (durée en nanosecondes / ticks) par soustraction déterministe `end_time - start_time`.
   - Cycle de vie d'une portée : active, complétée avec succès (`Ok`), en erreur (`Error`) ou expirée (`TimedOut`).
4. **Tampon Annulaire Circulaire Borné (`TraceCollector`)** :
   - Conservation des portées actives (`MAX_ACTIVE_SPANS = 32`) et archivage circulaire borné (`MAX_RECORDED_SPANS = 64`) avec politique d'éviction prédictive *drop-oldest*.
   - Élimination absolue de tout risque de fuite ou de saturation mémoire lors de pointes de trafic.
5. **Démon Orchestrateur Ring 3 (`JamboTraceDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur pré-initialisant la portée d'amorçage racine (`boot.bootstrap`).
   - Commandes interactives dans `jsh` :
     - `trace status` : nombre de portées actives, total archivé, format de contexte et confinement capabilaire.
     - `trace span <name>` : création et complétion d'une portée d'exécution avec calcul de durée.
     - `trace query <span_id>` : interrogation d'une portée archivée avec restitution de son statut et de sa latence.
6. **Harnais de Validation Noyau (`kernel/src/sched/traced_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 70) du contrôle capabilaire `TraceCap`, de la propagation et sérialisation du contexte W3C, du calcul de latence, de la recherche d'arborescences de traces et des commandes du shell.

## Décision
1. Implémentation du démon `JamboTraceDaemon` et de ses tests unitaires dans `services/jambo-traced/src/lib.rs`.
2. Intégration de `jambo-traced` dans `services/jambo-sh` avec l'implémentation de la commande interactive `trace`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/traced_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 70) et publication de la version `v0.2.68`.

## Conséquences
- Visibilité causale de bout en bout et diagnostic de latence à l'échelle de la grappe sans perturbation du système.
- Socle pour l'autorité de certification distribuée et mTLS (`jambo-certd`, Phase 71).

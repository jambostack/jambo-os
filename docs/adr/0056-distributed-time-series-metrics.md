# ADR 0056: Métriques Chronologiques & Télémétrie de Grappe (`jambo-metricsd`)

## Statut
Accepté (Phase 67 - Jalon v0.2.65)

## Contexte
Dans une architecture de grappe distribuée sous micro-noyau souverain orienté capacités, l'observabilité quantitative en temps réel (utilisation CPU, pression mémoire, latence IPC, débits réseau) requiert un moteur de séries temporelles léger, déterministe et strictement confiné sans autorité ambiante. Avec `services/jambo-metricsd`, JamboOS intègre un collecteur de métriques et moteur de surveillance `#![no_std]` :
1. **Confinement Capabilaire de Télémétrie (`MetricsCap`)** :
   - L'accès aux opérations de télémétrie est strictement gouverné par des jetons capabilitaires `MetricsCap`.
   - Droits granulaires (`METRICS_INGEST`, `METRICS_QUERY`, `METRICS_ALERT`, `METRICS_ADMIN`), empêchant l'altération de métriques ou l'accès non autorisé aux statistiques d'infrastructure.
2. **Tampons Annulaires Circulaires Déterministes (`MetricSeries`)** :
   - Chaque série temporelle est stockée dans un tampon annulaire circulaire borné (`RING_CAPACITY = 32`).
   - Politique d'éviction prédictive *drop-oldest* évitant tout risque d'épuisement mémoire ou d'allocation dynamique incontrôlée.
   - Calcul en temps réel des statistiques agrégées (min, max, moyenne cumulative, dernière valeur).
3. **Évaluation Temps-Réel de Règles d'Alerte Dynamiques (`AlertRule`)** :
   - Définition de règles d'alerte à seuil (`AlertCondition::GreaterThan`, `AlertCondition::LessThan`).
   - Détection instantanée dès l'ingestion d'un échantillon déviant, positionnant l'état d'alerte (`triggered: true`).
4. **Démon Orchestrateur Ring 3 (`JamboMetricsDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant l'ingestion locale et l'évaluation continue des règles d'alerte.
   - Commandes interactives dans `jsh` :
     - `metrics status` : séries enregistrées, échantillons ingérés, capacité annulaire et confinement capabilaire.
     - `metrics query <name>` : interrogation des statistiques agrégées (min, max, moyenne, dernier).
     - `metrics ingest <name> <val>` : ingestion manuelle d'un échantillon avec détection d'alerte en direct.
5. **Harnais de Validation Noyau (`kernel/src/sched/metrics_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 67) du contrôle capabilaire `MetricsCap`, des calculs statistiques, du comportement du tampon circulaire borné, du déclencheur d'alertes et des commandes du shell.

## Décision
1. Implémentation du démon `JamboMetricsDaemon` et de ses tests unitaires dans `services/jambo-metricsd/src/lib.rs`.
2. Intégration de `jambo-metricsd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `metrics`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/metrics_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 67) et publication de la version `v0.2.65`.

## Conséquences
- Visibilité quantitative immédiate et surveillance prédictive de la grappe sans dépendance externe.
- Socle pour la découverte de services distribuée et résolution de noms (`jambo-serviced`, Phase 68).

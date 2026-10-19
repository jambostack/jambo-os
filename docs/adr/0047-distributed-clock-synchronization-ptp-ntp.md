# ADR 0047: Synchronisation Horlogère Distribuée PTP/NTP & Asservissement Monotone (`jambo-timed`)

## Statut
Accepté (Phase 58 - Jalon v0.2.56)

## Contexte
Dans une architecture de micro-noyau distribué à haute intégrité (cluster, consensus Raft, audit cryptographique immuable), la cohérence temporelle est un invariant fondamental. Avec `services/jambo-timed`, JamboOS intègre un démon de synchronisation horlogère sub-microseconde opérant en espace utilisateur (Ring 3) :
1. **Confinement Capabilaire d'Horloge (`TimeSyncCap`)** :
   - L'accès à la référence temporelle et l'asservissement d'horloge sont protégés par des jetons de capacités `TimeSyncCap`.
   - Les droits sont subdivisés de manière granulaire (`TIME_READ`, `TIME_ADJUST_FREQ`, `TIME_STEP`, `TIME_PTP_SYNC`), interdisant à des processus non privilégiés de modifier la fréquence du quartz ou de provoquer des sauts temporels.
2. **Garantie Formelle de Monotonicité Stricte (Anti-Régression)** :
   - Même lors de corrections ou recalibrages brutaux, l'asservissement d'horloge (`ClockServo`) interdit formellement tout retour en arrière du temps (`t_next > t_prev`).
   - Cette invariance protège les horodatages des entrées du grand livre d'audit cryptographique (`jambo-auditd`) et la validité des jetons capabilitaires (`SessionTokenCap`).
3. **Algorithme de Synchronisation Quadri-Points IEEE 1588 PTP (`PtpSample`)** :
   - Mesure précise de l'écart d'horloge (*offset*) et du délai aller-retour réseau (*round-trip delay*) à partir de 4 horodatages matériels (T1, T2, T3, T4).
   - Boucle d'asservissement PLL/FLL : lissage continu par dérive de fréquence progressive (*slewing*, jusqu'à +/- 500 PPM) pour les faibles dérives, ou saut discret (*stepping*) contrôlé si autorisé par capacité.
4. **Démon Orchestrateur Ring 3 (`JamboTimeDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant l'horloge système et les synchronisations distribuées.
   - Commandes interactives dans `jsh` :
     - `time status` : heure précise UTC/Étalon, mode d'asservissement (Locked/Slewing/Stepping), dérive de fréquence (PPM), offset et délai.
     - `time sync` : exécution d'un échantillonnage PTP quadri-points et asservissement du servo.
     - `time tick [nanos]` : progression déterministe de l'horloge.
5. **Harnais de Validation Noyau (`kernel/src/sched/time_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 58) du filtrage PTP quadri-points, de la monotonicité stricte, du confinement capabilaire et des commandes du shell interactif.

## Décision
1. Ajout de `JamboTimeDaemon` dans `services/jambo-timed/src/lib.rs`.
2. Intégration de `jambo-timed` dans `services/jambo-sh` avec l'implémentation de la commande `time`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de test `kernel/src/sched/time_test.rs`.
4. Validation complète sous QEMU (Phase 58) et publication de la version `v0.2.56`.

## Conséquences
- Horloge universelle distribuée de haute précision sans dépendance envers une autorité ambiante.
- Protection mathématique contre les failles d'invalidation temporelle et de réordonnancement d'événements cryptographiques.

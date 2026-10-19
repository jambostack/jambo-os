# ADR 0042: Gestion de l'Énergie Matérielle ACPI, C-States Dynamiques & Régulation Thermique (`jambo-powerd`)

## Statut
Accepté (Phase 53 - Jalon v0.2.51)

## Contexte
Après la mise en place du grand livre d'audit cryptographique et de l'observabilité zéro-autorité de la Phase 52 (ADR 0041, v0.2.50), JamboOS franchit une nouvelle étape d'autonomie matérielle avec `services/jambo-powerd`, confiant la gestion énergétique, la régulation thermique et les transitions d'état ACPI à un démon d'espace utilisateur (Ring 3) strictement confiné par capacités :
1. **Règle Fondamentale de Confinement Énergétique** :
   - Conformément au principe du moindre privilège et à l'absence totale d'autorité ambiante, aucun processus ne peut commander le matériel énergétique (I/O ports ACPI, C-States CPU, réveil, veille ou extinction) sans détenir une capacité explicite `PowerCap`.
   - Droits granulaires de la capacité : `SHUTDOWN`, `REBOOT`, `SUSPEND`, `THROTTLE`, `BATTERY_QUERY`.
2. **Gestionnaire d'Alimentation ACPI (`PowerManager`)** :
   - Décodage des descripteurs matériels FADT (Fixed ACPI Description Table) : `pm1a_cnt_blk`, `smi_cmd_port`, codes d'activation `slp_typa_s5` et reset port PCI.
   - Transitions d'état d'alimentation global contrôlées : `S0Working`, `S1CpuStandby`, `S3SuspendToRam`, `S4Hibernate`, `S5SoftOff`.
3. **Régulation Granulaire des C-States CPU Multi-Cœurs (SMP)** :
   - Gestion indépendante des cœurs logiques (`C0Active`, `C1Halt`, `C2StopClock`, `C3DeepSleep`).
   - Permet la mise en sommeil profond des cœurs secondaires (AP) inactifs pour réduire l'empreinte thermique et énergétique.
4. **Télémétrie Batterie & Politiques Énergétiques Automatisées** :
   - Télémétrie de batterie (`BatteryTelemetry`) intégrant pourcentage, état de charge, santé et sonde thermique.
   - Évaluation en boucle fermée de politiques réactives :
     - Surchauffe (>= 85°C) -> Déclenchement immédiat du bridage thermique (`ThermalThrottle`).
     - Batterie faible (<= 20% en décharge) -> Activation du mode économie d'énergie (`EngageBatterySaver`).
     - Batterie critique (<= 5% en décharge) -> Déclenchement de l'extinction d'urgence ordonnée (`EmergencyShutdown`).
5. **Commandes Interactives dans le Shell `jsh`** :
   - `power status` : état ACPI global, télémétrie batterie, mode économie et matrice des C-states CPU.
   - `power state <s0..s5>` : demande de transition d'état ACPI contrôlée par `PowerCap`.
   - `power cstate <core> <c0..c3>` : configuration du C-State d'un cœur CPU spécifique.
   - `power policy` : évaluation et diagnostic des règles de politique énergétique.
6. **Harnais de Validation Noyau (`kernel/src/sched/power_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 53) du confinement des droits, des transitions ACPI, des C-States et des politiques thermiques.

## Décision
1. Ajout de `JamboPowerDaemon` dans `services/jambo-powerd/src/lib.rs`.
2. Intégration de `jambo-powerd` dans `services/jambo-sh` avec l'implémentation de la commande `power`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création de `kernel/src/sched/power_test.rs`.
4. Validation complète sous QEMU (Phase 53) et publication de la version `v0.2.51`.

## Conséquences
- Gestion fine et sécurisée de l'énergie et de la thermique matérielle en Ring 3 sans privilèges ambiants.
- Résilience accrue du matériel face aux surchauffes et épuisements de batterie.

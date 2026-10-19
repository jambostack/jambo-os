# ADR 0069: Diagnostic Matériel Autonome, Auto-Réparation & Télémétrie de Pannes (`jambo-diagd`)

## Statut
Accepté (Phase 80 - Jalon v0.2.78)

## Contexte
Dans une infrastructure de calcul distribuée et souveraine exploitant un micro-noyau de 3e génération orienté capacités, la résilience matérielle ne peut dépendre d'interventions manuelles lentes ou de paniques du noyau dès l'apparition d'erreurs transitoires ou de défaillances de composants.
Dans une architecture `#![no_std]` sans autorité ambiante :
- La surveillance active des bus matériels (PCIe, NVMe, VirtIO, Mémoire ECC, CPU MCA) doit s'effectuer de manière continue, avec confinement strict des privilèges via une capacité dédiée `DiagCap` interdisant toute amplification de droits (`SysError::PermissionDenied`).
- La détection d'erreurs doit distinguer les anomalies corrigibles des défaillances fatales (PCIe AER correctable vs fatal, ECC correctable vs uncorrectable, erreurs de médias NVMe, désynchronisation de files d'attente VirtIO).
- Les mécanismes d'auto-remédiation autonome doivent s'exécuter à chaud sans interruption globale du système : réapprentissage de liaison (*Link Retraining*), réinitialisation de fonction (*Function-Level Reset - FLR*), repli en mode dégradé (*Degraded Mode Fallback*), et bascule transparente vers un périphérique de secours (*Hot-Failover*).
- L'audit et la traçabilité des incidents doivent être inviolables grâce à un journal d'incidents scellé cryptographiquement par une chaîne de condensats SHA-256.

Avec `services/jambo-diagd`, JamboOS intègre un démon complet de diagnostic et de remédiation matérielle :

1. **Modèle de Sécurité Capabilaire (`DiagCap`)** :
   - Droits granulaires : `DIAG_INSPECT`, `DIAG_SCAN`, `DIAG_REMEDIATE`, `DIAG_RESET`, `DIAG_TELEMETRY`, `DIAG_ADMIN`.
   - Atténuation stricte interdisant formellement l'amplification de privilège (`SysError::PermissionDenied`).

2. **Inventaire et Télémétrie des Bus Matériels (`HardwareDevice`, `BusType`, `DeviceStatus`)** :
   - Prise en charge des bus PCIe, NVMe, VirtIO, mémoire DDR ECC et CPU Machine Check Architecture (MCA).
   - Calcul dynamique du score de santé (0 à 100%) selon des pénalités pondérées et déterministes.
   - Classification fine des états : `Healthy`, `Warning`, `Degraded`, `Remediated`, `Failed`, `Quarantined`.

3. **Moteur d'Auto-Remédiation Autonome à Chaud (`RemediationAction`)** :
   - *PCIe AER Link Retraining* : ré-entraînement de la liaison PCIe dès que les erreurs corrigibles atteignent le seuil critique (8 erreurs), réinitialisant le compteur et rétablissant le score de santé à 95%.
   - *Function-Level Reset (FLR)* : réinitialisation matérielle ciblée sans crash système lors de fautes fatales ou de désynchronisation de files VirtIO.
   - *Hot-Failover NVMe/VirtIO vers Spare* : bascule automatique de trafic et désactivation transparente du contrôleur défaillant au profit d'un contrôleur de secours actif sans interruption de service.
   - *Quarantaine Mémoire ECC & CPU MCA* : isolement immédiat des pages mémoire ou cœurs défaillants sans compromettre l'intégrité du cluster.

4. **Journal d'Incidents Scellé par Condensat SHA-256 (`FaultIncident`)** :
   - Anneau circulaire borné à 64 incidents historiques avec horodatage, sévérité, code d'erreur et action corrective.
   - Hachage cryptographique chaîné SHA-256 garantissant la non-répudiation et l'intégrité de la télémétrie de grappe.

5. **Commandes Shell Interactives `diag` dans `jsh`** :
   - `diag status` : vue synthétique du nœud, score global de santé, état d'auto-réparation et métriques.
   - `diag devices` / `diag list` : inventaire exhaustif des périphériques avec BDF, bus, santé, statut et présence de secours.
   - `diag inspect <id|nom>` : télémétrie détaillée (compteurs ECC, AER, NVMe, VirtIO, dernière action).
   - `diag scan` : déclenchement d'un scan actif de diagnostic de l'ensemble des bus.
   - `diag remediate <id|nom> <action>` : déclenchement manuel d'une remédiation autorisée.
   - `diag incidents` : historique des incidents consignés avec horodatage et action appliquée.
   - `diag digest` : affichage du condensat SHA-256 d'intégrité de télémétrie.

6. **Validation Noyau Dédiée (`kernel/src/sched/diagd_test.rs`)** :
   - Suite complète sous QEMU validant l'atténuation capabilaire, le seuil de Link Retraining, le reset FLR, la bascule Hot-Failover NVMe, la quarantaine ECC, le journal scellé SHA-256 et l'ensemble des commandes shell.

## Décision
1. Implémentation du démon `JamboDiagDaemon`, des structures `HardwareDevice`, `DiagCap`, `FaultIncident` dans `services/jambo-diagd`.
2. Intégration de la commande `diag` dans le shell objet `services/jambo-sh`.
3. Écriture du module de test noyau `kernel/src/sched/diagd_test.rs` et activation dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.78` pour l'ensemble des modules du workspace.

## Conséquences
- Haute résilience matérielle et auto-guérison sans arrêt de service ni panique noyau.
- Observabilité et traçabilité inaltérables des pannes matérielles au sein de la grappe JamboOS.

# ADR 0071: Surveillance de Vivacité, Chien de Garde Matériel & Logiciel et Isolation NMI (`jambo-watchdogd`)

## Statut
Accepté (Phase 82 - Jalon v0.2.80)

## Contexte
Dans une architecture de micro-noyau distribué à haute disponibilité (`#![no_std]`), la résilience du système face aux blocages stochastiques (boucles infinies, interblocages, famines de ressources) et aux fautes matérielles nécessite une détection précoce et une remédiation déterministe :
1. **Chien de garde matériel (Hardware Watchdog WDT / iTCO v2)** :
   - Prise en charge des registres WDT compatibles Intel iTCO v2 (LPC/eSPI), ACPI WDAT et génériques.
   - Délai de garde matériel (ex: 30 000 ms) avec mécanisme de pré-timeout (ex: 5 000 ms avant réinitialisation matérielle).
   - Déclenchement d'une interruption non masquable (NMI) avant toute réinitialisation physique pour capturer l'état des registres et de la mémoire.
2. **Surveillance logicielle Ring 3 et Ring 0 (Targets)** :
   - Chiens de garde granulaires par thread, processus et service micro-noyau (`kernel-sched`, `jambo-init`, `jambo-netd`, `jambo-ipcd`).
   - Mécanisme de rechargement périodique (*Petting*) avec mesure précise de la dérive temporelle (*Event Loop Drift*).
   - Détection des blocages souples (*Soft Lockup*) et bascule en état `WarningDrift` ou `Stalled`.
   - Actions correctives automatiques (`LogAndWarn`, `IsolateAndKillThread`, `RestartService`, `TriggerClusterFailover`, `HardwareReboot`).
3. **Battements de cœur inter-nœuds (Cluster Liveness)** :
   - Surveillance active de l'état de santé des nœuds de la grappe (`Healthy`, `Suspect`, `Dead`, `FailoverInitiated`).
   - Tolérance configurable aux battements manqués et bascule automatique de rôle (*Failover*) vers les nœuds de secours en cas de perte du nœud primaire.
4. **Modèle capabilaire strict (`WatchdogCap`)** :
   - Droits granulaires : `WATCHDOG_INSPECT`, `WATCHDOG_PET`, `WATCHDOG_REGISTER`, `WATCHDOG_CONFIGURE`, `WATCHDOG_TRIGGER`, `WATCHDOG_FAILOVER`, `WATCHDOG_ADMIN`.
   - Atténuation formelle sans amplification de privilèges.
5. **Audit cryptographique inviolable SHA-256** :
   - Condensat cryptographique SHA-256 scellant en continu l'ensemble des événements de vivacité, recharges matérielles, alertes NMI et actions d'isolation.

## Décision
1. Implémentation du démon `JamboWatchdogDaemon` et des structures associées (`WatchdogCap`, `HwWatchdog`, `WatchdogTarget`, `ClusterNodeHeartbeat`, `NmiAlert`, `WatchdogEvent`) dans `services/jambo-watchdogd`.
2. Intégration de la commande `watchdog` / `watchdogctl` dans le shell interactif `services/jambo-sh`.
3. Écriture du module de test noyau `kernel/src/sched/watchdogd_test.rs` et validation dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.80` pour l'ensemble des modules du workspace.

## Conséquences
- Détection ultra-rapide des blocages matériels et logiciels sans dépendance envers l'ordonnanceur préemptif classique.
- Isolation préventive des threads défaillants sur interruption NMI avant crash complet de la machine.
- Garantie de haute disponibilité de grappe grâce à la détection de défaillance de nœuds et bascule automatisée.

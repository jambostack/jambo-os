# ADR 0054: Passerelle Ingress & Répartiteur de Charge Élastique (`jambo-gwd`)

## Statut
Accepté (Phase 65 - Jalon v0.2.63)

## Contexte
Dans une architecture de grappe distribuée sous micro-noyau souverain orienté capacités, l'exposition des services internes et la répartition du trafic réseau nécessitent une passerelle L4/L7 hautement résiliente, modulaire et découplée sans autorité ambiante. Avec `services/jambo-gwd`, JamboOS intègre une passerelle ingress et un équilibreur de charge élastique `#![no_std]` :
1. **Confinement Capabilaire de Passerelle Ingress (`GatewayCap`)** :
   - L'accès à la configuration des services et au routage est strictement gouverné par des jetons capabilitaires `GatewayCap`.
   - Droits granulaires (`GW_ROUTE`, `GW_BACKEND_ADD`, `GW_HEALTH_REPORT`, `GW_CIRCUIT_BREAK`, `GW_ADMIN`), interdisant tout détournement de trafic ou modification de topologie sans capacité dédiée.
2. **Stratégies de Répartition Multi-Algorithmes (`LoadBalanceStrategy`)** :
   - Prise en charge déterministe de multiples politiques d'aiguillage :
     - *Round-Robin* : distribution cyclique équitable entre backends sains.
     - *Least-Connections* : affectation prioritaire au backend hébergeant le moins de connexions actives.
     - *IP-Hash* : affinité de session déterministe calculée sur l'adresse IP cliente.
3. **Sondes de Santé Actives & Coupe-Circuit Automatique (`Circuit Breaker`)** :
   - Surveillance continue de la santé des nœuds cibles (`report_health`).
   - Déclenchement automatique du coupe-circuit dès qu'un seuil paramétrable d'échecs consécutifs (`circuit_breaker_threshold`) est atteint.
   - Éviction immédiate du backend défaillant et bascule transparente (*failover*) vers les nœuds résiduels sains.
   - Rétablissement à chaud dès détection du premier succès de sonde.
4. **Démon Orchestrateur Ring 3 (`JamboGatewayDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant les tables de services virtuels et les métriques de trafic.
   - Commandes interactives dans `jsh` :
     - `gw status` : état des services virtuels déclarés, backends actifs, volume de requêtes acheminées et confinement capabilaire.
     - `gw route` : simulation d'aiguillage d'une requête cliente entrante vers un backend sain.
     - `gw cb` : simulation de rupture et déclenchement de coupe-circuit avec bascule de trafic.
5. **Harnais de Validation Noyau (`kernel/src/sched/gwd_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 65) du contrôle capabilaire `GatewayCap`, des algorithmes de répartition, des sondes de santé, du coupe-circuit et des commandes du shell.

## Décision
1. Implémentation du démon `JamboGatewayDaemon` et de ses tests unitaires dans `services/jambo-gwd/src/lib.rs`.
2. Intégration de `jambo-gwd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `gw`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/gwd_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 65) et publication de la version `v0.2.63`.

## Conséquences
- Haute disponibilité et répartition élastique des flux de travail de la grappe sans composants tiers.
- Socle pour le coffre-fort de secrets distribué et déverrouillage à seuil (`jambo-vaultd`, Phase 66).

# ADR 0057: Découverte de Services & Résolution de Noms Distribuée (`jambo-serviced`)

## Statut
Accepté (Phase 68 - Jalon v0.2.66)

## Contexte
Dans une architecture de grappe distribuée sous micro-noyau souverain orienté capacités, la localisation dynamique des instances de services (bases de données, serveurs RPC, passerelles ingress, démons de stockage) requiert un registre de services distribué, résilient et strictement confiné sans autorité ambiante. Avec `services/jambo-serviced`, JamboOS intègre un moteur de découverte et de résolution de noms `#![no_std]` :
1. **Confinement Capabilaire de Découverte (`DiscoveryCap`)** :
   - L'accès aux opérations de registre et de résolution est strictement gouverné par des jetons capabilitaires `DiscoveryCap`.
   - Droits granulaires (`DISCOVERY_REGISTER`, `DISCOVERY_RESOLVE`, `DISCOVERY_DEREGISTER`, `DISCOVERY_HEARTBEAT`, `DISCOVERY_ADMIN`), interdisant l'usurpation de services ou l'empoisonnement de registre par des entités non autorisées.
2. **Enregistrement Multi-Instances & Résolution Sémantique (`ServiceRegistry`)** :
   - Support d'instances multiples par service (`MAX_INSTANCES_PER_SERVICE = 8`) sur un ensemble borné de services (`MAX_SERVICES = 16`).
   - Résolution sémantique de noms canoniques (`ServiceName`) renvoyant la liste des points de terminaison (IP, port) actifs et sains.
3. **Gestion Déterministe des Baux Temporels & Éviction par TTL** :
   - Chaque instance est assortie d'un horodatage de dernier battement de cœur (`last_heartbeat`) et d'une durée de validité (`ttl_seconds`).
   - Renouvellement périodique par battement de cœur (`heartbeat`). Éviction automatique et purge prédictive des instances dont le bail a expiré (`purge_expired`).
4. **Démon Orchestrateur Ring 3 (`JamboServiceDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant le cycle de vie des services clusterisés avec pré-enregistrement de services système (`kvd.service`, `meshd.service`).
   - Commandes interactives dans `jsh` :
     - `service status` : services déclarés, opérations traitées, stratégie de résolution et confinement capabilaire.
     - `service resolve <name>` : résolution sémantique d'un service et affichage des instances saines (IP:Port).
     - `service register <name> <id>` : enregistrement explicite d'une instance avec bail TTL.
     - `service heartbeat <name> <id>` : renouvellement du bail d'une instance active.
     - `service deregister <name> <id>` : retrait ordonné d'une instance lors de son arrêt gracieux.
5. **Harnais de Validation Noyau (`kernel/src/sched/serviced_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 68) du contrôle capabilaire `DiscoveryCap`, de l'enregistrement multi-instances, de la résolution de noms, de l'éviction par expiration de TTL, du dé-enregistrement et des commandes du shell.

## Décision
1. Implémentation du démon `JamboServiceDaemon` et de ses tests unitaires dans `services/jambo-serviced/src/lib.rs`.
2. Intégration de `jambo-serviced` dans `services/jambo-sh` avec l'implémentation de la commande interactive `service`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/serviced_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 68) et publication de la version `v0.2.66`.

## Conséquences
- Découverte dynamique décentralisée et routage sémantique sans point unique de défaillance.
- Socle pour le moteur déclaratif de politiques de sécurité de grappe (`jambo-policyd`, Phase 69).

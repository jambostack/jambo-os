# ADR 0051: Bus d'Événements Pub/Sub Asynchrone Zéro-Copie (`jambo-eventd`)

## Statut
Accepté (Phase 62 - Jalon v0.2.60)

## Contexte
Dans une architecture de micro-noyau distribué découplé (synchronisation temporelle, consensus Raft, magasin transactionnel et ordonnancement de conteneurs), les composants système et les applications Ring 3 requièrent un mécanisme de communication asynchrone non-bloquant à faible latence sans autorité ambiante. Avec `services/jambo-eventd`, JamboOS intègre un bus de publication/souscription (Pub/Sub) zéro-copie déterministe `#![no_std]` :
1. **Confinement Capabilaire d'Événements (`EventCap`)** :
   - L'accès au bus d'événements est strictement gouverné par des jetons capabilitaires `EventCap`.
   - Droits granulaires (`EVENT_PUBLISH`, `EVENT_SUBSCRIBE`, `EVENT_FILTER`, `EVENT_DRAIN`, `EVENT_ADMIN`), interdisant l'écoute indiscrète (*eavesdropping*) ou l'injection de faux signaux sans capacité dédiée.
2. **Messages Immuables Zéro-Copie (`EventMessage`)** :
   - Structure d'événement compacte à taille bornée (`MAX_TOPIC_NAME = 32`, `MAX_PAYLOAD = 64`).
   - Horodatage strict et séquence logique monotone (`seq_id`) garantissant l'ordre partiel causal des événements sur le bus.
3. **Filtrage Hiérarchique Flexible (Exact & Préfixe)** :
   - Routage précis par sujet (*topic*) exact ou hiérarchique par préfixe (`topic.ends_with('/')`), permettant par exemple de souscrire à l'ensemble du sous-arbre `cluster/` ou `system/`.
4. **Files Circulaires Bornées & Politique de Débordement Drop-Oldest (`SubscriberQueue`)** :
   - File circulaire indépendante par abonné (`MAX_QUEUE_LEN = 8`) évitant toute famine de mémoire ou interférence entre consommateurs lents et rapides.
   - Politique *drop-oldest* déterministe en cas de saturation de file avec comptabilisation des pertes (`dropped_count`).
5. **Démon Orchestrateur Ring 3 (`JamboEventDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant le bus local et le sous-système de distribution d'événements.
   - Commandes interactives dans `jsh` :
     - `event status` : état du bus, nombre d'abonnements actifs, total d'événements publiés et confinement capabilaire.
     - `event pub <topic> <payload>` : diffusion d'un événement sur un sujet donné.
     - `event sub <topic>` : enregistrement d'une souscription avec filtrage.
     - `event poll [sub_id]` : dépilage du prochain message en attente dans la file d'un souscripteur.
     - `event unsub <id>` : résiliation d'un abonnement.
6. **Harnais de Validation Noyau (`kernel/src/sched/event_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 62) des droits capabilitaires `EventCap`, du filtrage par préfixe, de la politique de dépassement drop-oldest et des commandes interactives du shell.

## Décision
1. Implémentation du démon `JamboEventDaemon` et de ses tests unitaires dans `services/jambo-eventd/src/lib.rs`.
2. Intégration de `jambo-eventd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `event`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/event_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 62) et publication de la version `v0.2.60`.

## Conséquences
- Découplage asynchrone des services de grappe sans autorité ambiante.
- Socle pour le réseau maillé chiffré distribué et routage Zero-Trust (`jambo-meshd`, Phase 63).

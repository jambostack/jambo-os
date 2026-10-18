# ADR 0020: Passerelle Réseau L4/L7 & Équilibreur de Charge Élastique (`jambo-gwd`)

## Statut
Accepté (Phase 31 - Jalon v0.2.29)

## Contexte
Après la mise en place du consensus distribué (`jambo-raft`), du magasin de configuration (`jambo-kvd`), de l'ordonnanceur de charges (`jambo-schedd`), du bus d'événements (`jambo-eventd`), du réseau maillé (`jambo-meshd`) et du stockage CAS (`jambo-dfsd`), la grappe de calcul JamboOS héberge de multiples instances de services réparties dynamiquement sur les nœuds.

Pour exposer ces services aux clients externes et router le trafic inter-services de manière fluide et résiliente, un composant d'aiguillage réseau haute performance est requis :
1. **Équilibrage de charge multi-stratégies (L4/L7)** : répartition du trafic réseau selon Round-Robin pondéré, Least-Connections ou hachage déterministe du flux.
2. **Coupe-circuit (*Circuit Breaker*) & Sondes de santé** : détection immédiate des pannes de backends pour stopper l'acheminement des requêtes vers les nœuds instables sans saturer le réseau maillé.
3. **Sécurité orientée capacités (`GatewayCap`)** : interdiction stricte de modifier les tables de routage ou d'ajouter des backends sans détention préalable d'une capacité explicite octroyée par le système.
4. **Déterminisme mémoire `#![no_std]`** : fonctionnement sans allocation dynamique non bornée en Ring 3.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-gwd` (`services/jambo-gwd`) intégrant :
1. **Descripteur de backend (`BackendNode`)** :
   - Adresse IP virtuelle (`[u8; 4]`) et port (`u16`).
   - Poids relatif (`weight: u16`) pour la pondération du trafic.
   - Compteur de connexions actives (`active_conns: u32`).
   - Statut de santé opérationnelle (`healthy: bool`) et compteur d'échecs consécutifs (`failure_count: u8`).
2. **Table de services virtuels (`VirtualService`)** :
   - Port d'écoute frontal (`frontend_port: u16`).
   - Stratégie d'équilibrage (`LoadBalanceStrategy: RoundRobin, WeightedRoundRobin, LeastConnections, IpHash`).
   - Liste bornée de backends (`MAX_BACKENDS = 8`).
   - Seuil de déclenchement du coupe-circuit (`circuit_breaker_threshold: u8`).
3. **Contrôle d'accès sans autorité ambiante (`GatewayCap`)** :
   - Droits fins : `GW_ROUTE` (0x01), `GW_BACKEND_ADD` (0x02), `GW_HEALTH_REPORT` (0x04), `GW_CIRCUIT_BREAK` (0x08), `GW_ADMIN` (0x80).
4. **Algorithme d'aiguillage déterministe** :
   - Sélection O(1) du backend cible parmi les cibles saines (*healthy*).
   - Bascule automatique (*failover*) vers les nœuds survivants en cas d'ouverture du coupe-circuit.

## Conséquences
- **Positives** :
  - Haute disponibilité et absorption des montées en charge sur le cluster.
  - Confinement strict du plan de données réseau sans autorité ambiante.
  - Résilience automatique face aux pannes transitoires ou permanentes de services.
- **Négatives / Arbitrages** :
  - La taille des tables de services et de backends est statiquement bornée en Ring 3 pour respecter l'empreinte mémoire prévisible.

# ADR 0023: Découverte de Services Distribuée & Résolution de Noms de Grappe (`jambo-serviced`)

## Statut
Accepté (Phase 34 - Jalon v0.2.32)

## Contexte
Avec l'émergence d'une grappe JamboOS multi-nœuds exécutant des charges de travail distribuées dynamiques (`jambo-schedd`), des liaisons réseau chiffrées (`jambo-meshd`) et des passerelles d'équilibrage (`jambo-gwd`), les services et micro-VMs ont des adresses IP virtuelles et des ports dynamiques qui évoluent au cours du cycle de vie des conteneurs.

Pour permettre la communication inter-services sans configuration statique fragile, un registre de découverte de services distribué doit fournir :
1. **Enregistrement dynamique d'instances** : association d'un nom de service canonique (ex: `auth.service`, `db.primary`) à un ensemble d'endpoints avec métadonnées de version et de santé.
2. **Résolution de noms à faible latence** : résolution locale O(1) avec mise en cache déterministe et baux de validité (TTL).
3. **Sélection par étiquettes (*Label Selectors*)** : filtrage fin des cibles opérationnelles par attributs clés-valeurs.
4. **Contrôle d'accès orienté capacités (`DiscoveryCap`)** : interdiction d'usurpation ou d'altération de noms de services sans autorisation explicite.
5. **Déterminisme mémoire `#![no_std]`** : structures de données bornées garantissant l'absence de saturation mémoire.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-serviced` (`services/jambo-serviced`) intégrant :
1. **Instance de service (`ServiceInstance`)** :
   - Identifiant unique `instance_id: u32`.
   - Adresse IP (`[u8; 4]`) et port (`u16`).
   - Nœud hôte `node_id: u16`.
   - Étiquettes simples clés-valeurs (ex: `zone`, `role`).
   - Horodatage du dernier battement de cœur (`last_heartbeat: u64`) et TTL.
2. **Table de services enregistrés (`ServiceRegistry`)** :
   - Capacité bornée (`MAX_SERVICES = 16`, `MAX_INSTANCES_PER_SERVICE = 8`).
   - Méthodes d'enregistrement, de dé-enregistrement et d'interrogation.
3. **Contrôle d'accès par capacités (`DiscoveryCap`)** :
   - Droits explicites : `DISCOVERY_REGISTER` (0x01), `DISCOVERY_RESOLVE` (0x02), `DISCOVERY_DEREGISTER` (0x04), `DISCOVERY_ADMIN` (0x80).
4. **Éviction automatique des instances expirées** :
   - Nettoyage préventif des instances n'ayant pas renouvelé leur battement de cœur dans le délai imparti.

## Conséquences
- **Positives** :
  - Découplage complet entre l'emplacement physique des conteneurs et leur invocation par les clients.
  - Résilience accrue grâce à la purge automatique des nœuds défaillants.
  - Sécurité sans autorité ambiante interdisant le squatting ou le détournement de services.
- **Négatives / Arbitrages** :
  - Le nombre maximum de services et d'instances par service est statiquement plafonné en `#![no_std]`.

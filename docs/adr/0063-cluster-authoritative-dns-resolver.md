# ADR 0063: Résolveur et Serveur DNS d'Autorité de Grappe `#![no_std]` & Wire Format RFC 1035 (`jambo-dnsd`)

## Statut
Accepté (Phase 74 - Jalon v0.2.72)

## Contexte
Dans une architecture de micro-noyau distribuée orientée capacités, la localisation réseau des services de grappe, des nœuds de calcul et des passerelles d'entrée requiert un système de résolution de noms universel, déterministe et conforme aux standards de l'Internet, tout en interdisant formellement l'autorité ambiante. Avec `services/jambo-dnsd`, JamboOS se dote d'un résolveur et serveur DNS faisant autorité complet en `#![no_std]` :

1. **Confinement Capabilaire DNS (`DnsCap`)** :
   - L'interrogation, l'enregistrement d'enregistrements, la mise à jour de zone et l'administration sont conditionnés par un jeton de capacité `DnsCap`.
   - Droits granulaires (`DNS_RESOLVE`, `DNS_REGISTER`, `DNS_ZONE_UPDATE`, `DNS_RECURSE`, `DNS_ADMIN`).
   - Atténuation capabilaire stricte (`attenuate`) interdisant toute amplification de privilèges.

2. **Zone d'Autorité Locale Souveraine (`.jambo`) & Records Typés** :
   - Support natif des types d'enregistrements majeurs : `A` (IPv4), `AAAA` (IPv6), `SRV` (priorité, poids, port, cible de service), `CNAME` (nom canonique), `TXT` (métadonnées et chaînes textuelles), et `PTR` (résolution inverse).
   - Gestion d'autorité stricte avec positionnement du drapeau `AA` (*Authoritative Answer*) pour tous les domaines appartenant à l'espace `.jambo`.
   - Cache DNS local avec respect des durées de vie (`TTL`) et mécanisme d'éviction déterministe.

3. **Traitement Binaire Wire Format Standard RFC 1035** :
   - Décodage complet des trames DNS binaires : en-tête standard (12 octets, ID, drapeaux QR/AA/RD/RA/RCODE, QDCOUNT), décodage des labels de noms de domaine avec pointeurs de compression (0xC0).
   - Encodage de trames de réponse RFC 1035 avec sections Question et Answer complètes et conformes pour toute pile réseau ou client UDP/TCP.

4. **Synchronisation Transparente avec la Découverte de Services (`jambo-serviced`)** :
   - Passerelle directe permettant de synchroniser automatiquement les instances saines enregistrées dans `ServiceRegistry` en enregistrements DNS A (`<nom>.jambo`) et SRV (`_<nom>._tcp.jambo`).
   - Élimination de toute divergence d'état entre le registre de découverte dynamique et la couche de nommage réseau.

5. **Commandes Shell Interactives `dns` dans `jsh`** :
   - `dns status` / `dns info` : statistiques de résolution, enregistrements actifs et état du confinement DnsCap.
   - `dns zone` / `dns list` : consultation tabulaire des enregistrements configurés dans la zone `.jambo`.
   - `dns resolve <domaine> [A|AAAA|SRV|TXT]` : résolution locale immédiate sous contrôle capabilaire.
   - `dns sync` : synchronisation instantanée depuis `jambo-serviced`.
   - Rétrocompatibilité transparente pour la résolution DoT externe (`dns <domaine_externe>`).

6. **Harnais de Validation Noyau (`kernel/src/sched/dnsd_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 74) du contrôle d'accès `DnsCap`, de la zone `.jambo`, de la résolution multi-types, du wire-format RFC 1035, de la synchronisation de découverte et des commandes shell.

## Décision
1. Implémentation du démon `JamboDnsDaemon`, de `DnsCap`, du parser/builder wire-format RFC 1035 et du cache local dans `services/jambo-dnsd/src/lib.rs`.
2. Intégration du démon dans `services/jambo-sh/src/lib.rs` avec extension de la commande `dns`.
3. Création du banc de test noyau `kernel/src/sched/dnsd_test.rs` et branchement dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.72` sur l'ensemble de l'espace de travail.

## Conséquences
- Disponibilité d'une résolution de noms standard RFC 1035 au sein de la grappe souveraine JamboOS.
- Intégration transparente entre découverte de services Ring-3 et résolution DNS de cluster.

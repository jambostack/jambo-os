# ADR 0018 : Maillage Réseau Chiffré Distribué et Routage Zero-Trust (`jambo-meshd`)

## Statut
Accepté (Phase 29 - `v0.2.27`)

## Contexte
Après le déploiement du bus d'événements Pub/Sub asynchrone (`jambo-eventd`, ADR 0017) et de l'ordonnanceur distribué (`jambo-schedd`, ADR 0016), les nœuds de calcul, micro-machines virtuelles (`jambo-vmm`) et conteneurs de JamboOS doivent s'interconnecter à travers des réseaux physiques hétérogènes et non sécurisés. Les protocoles traditionnels (tunnels VPN monolithiques en Ring 0, daemons avec autorité ambiante root) violent les principes de sécurité d'isolation de JamboOS. Le système exige un maillage de superposition (*overlay mesh network*) chiffré de bout en bout, point-à-point, déterministe et régi par des capacités d'accès strictes.

## Décision
Nous concevons et implémentons le démon d'espace utilisateur `jambo-meshd` en Rust `#![no_std]`, offrant un réseau maillé chiffré Zero-Trust, sans autorité ambiante et gouverné par la capacité `MeshCap` :

1. **Architecture de Superposition Point-à-Point (*P2P Overlay Mesh*)** :
   - Chaque nœud pair dispose d'une identité cryptographique statique (clé publique 256 bits) et d'une adresse IP virtuelle de maillage.
   - Routage direct pair-à-pair sans passerelle centrale obligatoire (découverte dynamique des points de terminaison physiques).

2. **Chiffrement de Bout en Bout et Protection Anti-Rejeu** :
   - Dérivation de clés de session symétriques éphémères (256 bits) par échange Diffie-Hellman type Noise Protocol.
   - Chiffrement authentifié des paquets réseau avec tag MAC d'intégrité et compteur de séquence monotone anti-rejeu.
   - Rotation automatique des clés de session après un volume de données ou une durée d'inactivité.

3. **Gouvernance par Capacités Dédiées (`MeshCap`)** :
   - `MESH_TUNNEL` (0x01) : Droit d'encapsuler et d'acheminer des paquets chiffrés.
   - `MESH_PEER_ADD` (0x02) : Droit d'enrôler ou de révoquer des nœuds pairs.
   - `MESH_ROUTE` (0x04) : Droit d'inspecter ou de modifier la table de routage virtuelle.
   - `MESH_KEY_ROT` (0x08) : Droit de déclencher la rotation cryptographique des clés.
   - `MESH_ADMIN` (0x80) : Administration générale du maillage et des quotas d'I/O.
   - Aucun paquet réseau ne peut traverser l'interface de superposition sans présentation préalable d'une capacité `MeshCap` valide.

## Conséquences
- **Positives** :
  - Interconnexion sécurisée, transparente et hautement résiliente des nœuds de cluster, micro-VMs et démons.
  - Absence formelle d'autorité ambiante : isolation stricte de la couche réseau maillée en espace utilisateur Ring 3.
  - Conception `#![no_std]` déterministe sans allocation dynamique arbitraire au cours de l'acheminement de paquets.
- **Négatives** :
  - Surcoût d'encapsulation (en-tête de maillage + tag d'authentification MAC) réduisant légèrement la MTU utile.

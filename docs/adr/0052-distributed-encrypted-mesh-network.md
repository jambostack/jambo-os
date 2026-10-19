# ADR 0052: Réseau Maillé Chiffré Distribué & Routage Zero-Trust (`jambo-meshd`)

## Statut
Accepté (Phase 63 - Jalon v0.2.61)

## Contexte
Dans une architecture de micro-noyau distribué multinoeuds, la communication inter-nœuds nécessite une couche de réseau maillé résiliente, chiffrée de bout en bout et protégée contre le rejeu sans autorité ambiante. Avec `services/jambo-meshd`, JamboOS intègre un réseau maillé sécurisé déterministe `#![no_std]` :
1. **Confinement Capabilaire de Réseau Maillé (`MeshCap`)** :
   - L'accès au réseau maillé est strictement gouverné par des jetons capabilitaires `MeshCap`.
   - Droits granulaires (`MESH_DISCOVER`, `MESH_ROUTE`, `MESH_SEND`, `MESH_RECV`, `MESH_ENCRYPT`, `MESH_ADMIN`), interdisant la transmission non autorisée ou la modification de la table de routage sans capacité dédiée.
2. **Chiffrement Authentifié Symétrique et Protection Anti-Rejeu (`MeshPacket`)** :
   - Chiffrement symétrique par clé partagée de 256 bits avec compteur de séquence monotone (`seq_id`).
   - Rejet immédiat des paquets en rejeu ou hors séquence (`seq_id <= peer.rx_sequence`).
   - Signature de payload par condensation d'intégrité (HMAC-like checksum).
3. **Table de Routage Distribuée et Gestion Multi-Sauts (`MeshRoute`)** :
   - Table de routage dynamique associant un identifiant de nœud distant à un saut suivant (*next hop*) et à une métrique de coût.
   - Routage direct ou multi-sauts avec gestion de la connectivité et des chemins de secours.
4. **Démon Orchestrateur Ring 3 (`JamboMeshDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant le nœud local, les pairs autorisés et la topologie du maillage.
   - Commandes interactives dans `jsh` :
     - `mesh status` : état du nœud local, nœuds pairs actifs, routes enregistrées et confinement capabilaire.
     - `mesh ping <target_node_id>` : test d'acheminement chiffré vers un nœud du réseau maillé.
     - `mesh peers` : énumération des nœuds pairs connectés avec métriques de transmission.
5. **Harnais de Validation Noyau (`kernel/src/sched/mesh_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 63) du chiffrement des paquets, du routage multi-sauts, de la protection anti-rejeu et des commandes interactives du shell.

## Décision
1. Implémentation du démon `JamboMeshDaemon` et de ses tests unitaires dans `services/jambo-meshd/src/lib.rs`.
2. Intégration de `jambo-meshd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `mesh`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/mesh_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 63) et publication de la version `v0.2.61`.

## Conséquences
- Communication sécurisée et autonome entre nœuds sans autorité de certification centrale permanente.
- Socle pour le stockage distribué adressé par le contenu (`jambo-dfsd`, Phase 64).

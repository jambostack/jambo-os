# ADR 0066: Multiplexeur et Passerelle de Messagerie IPC Distribuée (`jambo-ipcd`)

## Statut
Accepté (Phase 77 - Jalon v0.2.75)

## Contexte
La communication inter-services au sein d'un micro-noyau moderne de 3e génération (`#![no_std]`) dépasse le cadre d'une machine isolée lors du passage à l'échelle en grappe (cluster). L'échange de messages inter-nœuds nécessite un multiplexeur transparent, sécurisé et déterministe capable de :
1. Multiplexer de multiples canaux virtuels sur une connexion réseau physique ou superposée tout en isolant strictement les flux.
2. Garantir un ordonnancement déterministe sous contrainte temporelle, empêchant la famine des flux critiques (heartbeat, contrôle de supervision, consensus) par rapport aux flux standards ou de télémétrie.
3. Chiffrer de bout en bout les charges utiles avec authentification cryptographique (MAC) et assurer une protection stricte contre les attaques par rejeu ou corruption de paquets.
4. Conformer chaque interaction au principe de moindre privilège sans autorité ambiante grâce à une capacité dédiée `IpcCap`.

Avec `services/jambo-ipcd`, JamboOS se dote d'une passerelle IPC distribuée souveraine :

1. **Contrôle d'Accès Capabilaire Strict (`IpcCap`)** :
   - Droits granulaires : `IPC_CHANNEL_CREATE`, `IPC_SEND`, `IPC_RECV`, `IPC_ROUTE`, `IPC_ENCRYPT`, `IPC_PRIORITY`, `IPC_ADMIN`.
   - Atténuation capabilaire sans possibilité d'élévation de privilège (`SysError::PermissionDenied`).

2. **Multiplexage de Canaux IPC Virtuels (`IpcChannel`)** :
   - Jusqu'à 16 canaux multiplexés simultanés par nœud avec files d'attente FIFO bornées (`CHANNEL_QUEUE_CAP = 8`).
   - Métadonnées complètes : nœud source/destination, ports logiques, priorité, état (`Open`, `Connecting`, `Closed`, `Draining`).
   - Mesures de latence déterministe en temps réel (latence minimale, maximale et dernière valeur enregistrée en ticks).

3. **Ordonnancement Déterministe Strict par Priorité (`IpcPriority`)** :
   - 4 classes de priorité : `Critical` (0), `High` (1), `Normal` (2), `Background` (3).
   - Dépilement déterministe : les messages `Critical` sont systématiquement acheminés en priorité absolue avant tout message de rang inférieur.
   - Contrôle d'expiration par échéance (`deadline_ticks`).

4. **Chiffrement Symétrique et Protection Anti-Rejeu** :
   - Chiffrement in-situ combinant flux pseudo-aléatoire et clé de session 256 bits.
   - Empreinte d'authentification MAC (16 octets) garantissant l'intégrité absolue de la charge utile.
   - Séquences monotones strictement croissantes (`sequence > rx_sequence`) éliminant le rejeu de trames.

5. **Passerelle de Transit & Routage Inter-Nœuds (`IpcRoute`)** :
   - Table de routage dynamique vers les nœuds de la grappe avec métriques de coût et bornes de latence maximale (`max_latency_bound_us`).
   - Acheminement local direct ou mise en file de transit (`fwd_queue`) pour les paquets destinés à d'autres nœuds.

6. **Commandes Shell Interactives `ipc` dans `jsh`** :
   - `ipc status` : métriques globales, compteurs d'émission, de réception, de réacheminement et rejets anti-rejeu.
   - `ipc channels` / `ipc list` : inventaire des canaux multiplexés actifs, états et compteurs de séquence.
   - `ipc routes` : table des routes inter-nœuds avec passerelles et métriques.
   - `ipc send <chan_id> <msg>` : injection de message dans la file d'émission du canal.
   - `ipc dispatch` : exécution explicite de l'ordonnanceur déterministe par priorité.

7. **Validation Noyau Dédiée (`kernel/src/sched/ipcd_test.rs`)** :
   - Couverture complète exécutée sous QEMU lors du cycle autonome (Phase 77).

## Décision
1. Conception et implémentation du démon `JamboIpcDaemon`, de la capacité `IpcCap`, des canaux multiplexés et des tables de routage dans `services/jambo-ipcd`.
2. Intégration du composant dans l'interpréteur de commandes `services/jambo-sh`.
3. Écriture du module de tests noyau `kernel/src/sched/ipcd_test.rs` et activation dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.75` pour l'ensemble des modules du workspace.

## Conséquences
- Disponibilité d'une couche de communication inter-nœuds déterministe, chiffrée et hautement sécurisée.
- Garantie de priorité absolue pour les communications critiques du système en environnement distribué.

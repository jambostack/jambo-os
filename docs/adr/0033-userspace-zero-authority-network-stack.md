# ADR 0033: Pile Réseau en Espace Utilisateur Sans Autorité Ambiante (jambo-netd) & Sockets NetCap

## Statut
Accepté (Phase 44 - Jalon v0.2.42)

## Contexte
Après la validation du système de fichiers VFS transactionnel CoW en espace utilisateur (ADR 0032, v0.2.41), JamboOS doit implémenter une pile réseau de micro-noyau moderne et sécurisée.

Dans l'architecture JamboOS (micro-noyau de 3e génération avec sécurité par capabilités et confinement sans autorité ambiante - Zero Ambient Authority), le réseau n'appartient pas au noyau superviseur :
1. **Pile Réseau en Espace Utilisateur (`jambo-netd`)** :
   - Fonctionne comme un serveur isolé communiquant par IPC et transfert de tampons mémoire partagée (Zero-Copy VMO ring buffers).
   - Ne dispose d'aucun privilège matériel par défaut ; les flux entrants/sortants sont contrôlés par des objets de capacité réseau (`NetworkCapability` / `NetCap`).
2. **Contrôle d'Accès Zéro-Autorité & NetCap** :
   - Toute opération réseau (`open_tcp_stream`, `resolve_dns_over_tls`, `establish_tls13_handshake`, `ping`) requiert la présentation explicite d'un jeton `NetworkCapability` accordé dans le CSpace du processus appelant.
   - Si la capacité est nulle ou dépourvue des droits requis (`net_rights::CONNECT`, `LISTEN`, `DNS`, `TLS`, `RAW`), le démon rejette immédiatement l'opération avec `SysError::PermissionDenied`.
3. **Protocole de Transport, TLS 1.3 & DoT** :
   - Support des sockets TCP, écoute et connexion.
   - Handshake TLS 1.3 chiffré intégré de bout en bout.
   - Résolution DNS chiffrée DNS-over-TLS (DoT, port 853) via résolveur sécurisé.
   - Requêtes d'écho ICMP Ping avec mesure RTT.
4. **Commandes Shell Réseau dans `jsh`** :
   - `ip` : affichage des adresses IPv4, masque, passerelle, adresse MAC et statut de la capacité NetCap active.
   - `ping <ip>` : émission de requêtes d'écho ICMP avec calcul RTT et affichage utilisateur.
   - `netstat` : inspection des sockets actives, état TCP (`ESTABLISHED`), ports locaux et distants.
   - `dns <domaine>` : résolution chiffrée DNS-over-TLS via le démon réseau `jambo-netd`.
5. **Harnais de Validation Automatisée** (`kernel/src/sched/net_test.rs`) :
   - Validation du rejet des appels sans capacité réseau.
   - Validation de l'ouverture de socket TCP et négociation TLS 1.3.
   - Validation de la résolution DNS-over-TLS et du Ping ICMP.
   - Validation de l'exécution des commandes réseau du shell `jsh`.

## Décision
1. Enrichissement du service `jambo-netd` avec `ping()`, `ip_config()`, et `active_sockets()`.
2. Intégration de `jambo-netd` dans `jambo-sh` et implémentation des commandes `ip`, `ping`, `netstat`, `dns`.
3. Création du module `kernel/src/sched/net_test.rs` et validation formelle de l'ensemble sous QEMU.
4. Publication du jalon `v0.2.42`.

## Conséquences
- Confinement absolu de la couche réseau hors du noyau (Ring 3).
- Élimination des vulnérabilités réseau au niveau Ring 0.
- Intégration complète des commandes d'administration réseau dans le shell interactif `jsh`.

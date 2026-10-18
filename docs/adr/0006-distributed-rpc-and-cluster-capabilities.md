# ADR-0006: Bus RPC Distribué et Capacités Clusterisées (jambo-rpc)

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
Dans les micro-noyaux traditionnels, la communication inter-processus (IPC) est limitée à une seule machine physique. Pour créer un écosystème hautement disponible et distribué sans altérer les invariants de sécurité du micro-noyau, un mécanisme de transport RPC transparent et sécurisé est indispensable en espace utilisateur.

## Décision
Implémenter le bus RPC distribué (`jambo-rpc`) en espace utilisateur Ring 3, s'appuyant sur :
1. **Jetons de capacités distribuées cryptographiques (`DistributedCapToken`)** : Signés au moyen de clés de grappe secrètes et de condensats BLAKE3/HMAC, incluant un masque de droits stricts, un nœud source, un nœud cible et un nonce anti-rejeu.
2. **Protocole binaire compact JamboIDL** : En-têtes typés fixes avec sérialisation sans allocation dynamique non bornée.
3. **Dispatcher et registre de services** : Vérification systématique du jeton et des droits avant transmission aux gestionnaires de méthodes.
4. **Gestionnaire de grappe et résilience** : Surveillance des battements de cœur (heartbeat) et bascule automatique (failover) transparente vers des répliques saines en cas d'incident réseau.

## Conséquences
- Élimination de toute autorité ambiante à travers le réseau : un nœud distant ne peut exécuter que les méthodes pour lesquelles il détient un jeton valide.
- Protection cryptographique contre les attaques par rejeu et la falsification.
- Aucun code réseau ni RPC n'est introduit en Ring 0 (le micro-noyau reste strictement minimal).

# ADR-0010: Identité Cryptographique et Isolation des Sessions Utilisateur (jambo-authd)

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
Les systèmes d'exploitation hérités (UNIX, Linux, POSIX) fondent leur modèle de sécurité sur des identifiants statiques numériques (`UID` et `GID`) associés à un utilisateur tout-puissant (`root`, UID 0). Ce paradigme engendre des failles critiques (élévation de privilèges, autorité ambiante des démons, confusion de permissions `setuid`). Pour un micro-noyau de 3e génération orienté capacités, le concept même d'UID monolithique doit être aboli.

## Décision
Implémenter le démon de gestion d'identité cryptographique et de sessions isolées (`jambo-authd`) en espace utilisateur Ring 3, reposant sur :
1. **Identité Basée sur des Clés Cryptographiques Asymétriques** : Chaque utilisateur ou entité système est identifié par une clé publique Ed25519 immuable, sans compte administrateur implicite en Ring 0.
2. **Authentification par Défi-Réponse Zéro-Connaissance** : Les authentifications s'effectuent par signature cryptographique de défis à usage unique (nonces 256 bits), éliminant tout stockage ou transit de mots de passe en clair en mémoire.
3. **Jetons de Session Capabilitaires (`SessionTokenCap`)** : La réussite de l'authentification délivre un jeton de session typé délimitant un sous-ensemble strict de capacités (lecture, exécution, réseau, stockage) et assorti d'une durée de validité bornée.
4. **Isolation Stricte des Tables de Capacités et Destruction sans Résidu** : Chaque session active opère dans une table CSpace dédiée. Lors de la fermeture ou de l'invalidation de la session, toutes les capacités sont révoquées atomiquement en cascade (CDT) et les structures mémoire sont effacées de manière sécurisée (*zeroization*).

## Conséquences
- Élimination définitive du concept de super-utilisateur `root` et des vulnérabilités associées.
- Confinement absolu entre sessions multi-utilisateurs.
- Aucune dette de gestion d'identité dans le noyau Ring 0.

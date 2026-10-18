# ADR-0005: Système de Fichiers Transactionnel CoW JamboFS

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
La corruption du système de fichiers suite à des coupures d'alimentation impromptues ou des mises à jour partielles compromet la disponibilité des systèmes informatiques.

## Décision
Concevoir un système de fichiers natif en Ring 3, `JamboFS` :
1. Architecture en B+Tree Copy-on-Write (CoW) avec validation atomique via pointeur d'Uberblock.
2. Arbre de Merkle avec sommes de contrôle cryptographiques BLAKE3 intégrées pour garantir l'intégrité de bout en bout contre les altérations silencieuses (*bit rot*).
3. Instantanés atomiques en temps O(1) et mises à jour transactionnelles réversibles (A/B) avec retour arrière instantané.

## Conséquences
- Garantie absolue contre les corruptions d'état disque.
- 0 % d'échec de démarrage suite à une mise à jour interrompue.

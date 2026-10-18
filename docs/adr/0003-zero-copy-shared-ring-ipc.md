# ADR-0003: IPC Hybride Synchrone Fastpath et Anneaux Partagés Zéro-Copie

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
La communication interprocessus synchrone classique à base de copies mémoire multiples constitue le principal frein de performance des micro-noyaux traditionnels (Mach, L4 première génération).

## Décision
Implémenter un mécanisme IPC hybride à deux vitesses :
1. **Fastpath synchrone par registres** (< 500 cycles CPU) pour les messages courts (<= 64 octets et jusqu'à 4 Handles) avec bascule directe de thread sans réordonnancement global (*Direct Process Switch*).
2. **Anneaux partagés zéro-copie (Shared Rings)** inspirés de `io_uring` et VirtIO pour les flux I/O intensifs (stockage, réseau, affichage), éliminant jusqu'à 75 % des transitions Ring 3 -> Ring 0.

## Conséquences
- Débit I/O proche des systèmes monolithiques tout en préservant le confinement micro-noyau.
- Gestion requise des barrières mémoire Acquire/Release pour les anneaux partagés.

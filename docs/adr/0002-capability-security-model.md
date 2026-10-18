# ADR-0002: Modèle de Sécurité Fondé sur les Capacités Pures (CSpace)

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
Le modèle d'autorité ambiante Unix (DAC/POSIX, utilisateur `root` UID 0) permet à tout processus d'hériter de tous les privilèges de l'utilisateur, facilitant les attaques par confusion de député (*Confused Deputy*) et les élévations de privilèges.

## Décision
Adopter un modèle orienté capacités pures :
1. Aucun super-utilisateur `root` et aucune autorité ambiante.
2. Tout accès à une ressource noyau ou utilisateur exige la possession explicite d'un `Handle` 64 bits (32 bits d'index dans le `CSpace` local + 32 bits de génération anti-ABA).
3. Chaque Handle est assorti d'un masque de droits immuable ou atténuable (READ, WRITE, EXECUTE, MAP, SEND, RECEIVE, DUPLICATE, TRANSFER, MANAGE).
4. La délégation de capacité ne peut que réduire ou conserver les droits, jamais les amplifier.

## Conséquences
- Confinement natif de chaque processus et service.
- Élimination des vulnérabilités de confusion de député.
- Traçabilité et révocation fine des accès système.

# ADR-0007: Journal d'Audit Cryptographique Inaltérable et Observabilité Zéro-Autorité (jambo-auditd)

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
Dans les systèmes d'exploitation monolithiques conventionnels (Linux, BSD, Windows), les mécanismes de journalisation et d'audit (`syslog`, `auditd`, `dmesg`, `EventLog`) reposent sur une autorité globale ou le compte super-utilisateur (`root`). Un attaquant compromettant un composant privilégié peut modifier rétroactivement les traces ou corrompre l'historique d'audit pour dissimuler ses activités malveillantes. De surcroît, n'importe quel processus dispose d'une visibilité excessive sur les logs système, violant le principe de moindre privilège.

## Décision
Concevoir et implémenter le démon d'audit de sécurité et d'observabilité (`jambo-auditd`) en espace utilisateur Ring 3, fondé sur les principes stricts de JamboOS :
1. **Zéro Autorité Ambiante via `AuditCap`** : L'accès en écriture (enregistrement d'événements) et en lecture (requête, inspection, streaming) nécessite impérativement une capacité de contrôle d'audit (`AuditCap`) délimitant les catégories et niveaux autorisés.
2. **Chaîne de blocs d'audit inaltérable (*Tamper-Evident Ledger*)** : Chaque entrée d'événement intègre le hachage cryptographique de l'entrée précédente (chaîne de condensats déterministe avec calculs de signatures), rendant mathématiquement impossible toute modification, suppression ou réorganisation rétroactive non détectée.
3. **Buffer circulaire sans allocation dynamique débridée** : Structure mémoire en `#![no_std]` garantissant des performances d'enregistrement déterministes à latence ultra-faible sans impacter le fastpath système.
4. **Moteur d'analyse heuristique des anomalies en temps réel (`AnomalyDetector`)** : Détection proactive de motifs d'attaque (violations de mémoire répétées, attaques par rejeu RPC, rafales de dénis de capacités) et déclenchement d'alertes de confinement immédiates.

## Conséquences
- Garantie d'intégrité formelle des journaux d'audit même en cas de tentative d'altération en mémoire.
- Préservation rigoureuse du micro-noyau Ring 0 qui reste totalement vierge de toute complexité de journalisation.
- Observabilité granulaire conforme au modèle de sécurité par capacités de 3e génération.

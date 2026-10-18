# ADR-0008: Gestion de l'Énergie Matérielle et ACPI en Espace Utilisateur (jambo-powerd)

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
La gestion énergétique d'une machine (extinction propre ACPI, redémarrage, mise en veille S3 Suspend-to-RAM, régulation thermique et surveillance des batteries) est traditionnellement confinée dans le Ring 0 monolithique ou confiée à des démons disposant d'un accès administrateur absolu (`root`). Une compromission de ces mécanismes permet des attaques par déni de service physique, surchauffe ou falsification de l'état du matériel.

## Décision
Implémenter le gestionnaire d'énergie et d'événements matériels ACPI (`jambo-powerd`) en espace utilisateur Ring 3 selon les piliers stricts de JamboOS :
1. **Capacités de Contrôle d'Énergie (`PowerCap`)** : L'émission d'ordres de transition énergétique (extinction S5, redémarrage, suspension S3, modulation de fréquence P-state) requiert obligatoirement une capacité explicite sans autorité ambiante.
2. **Décodage Sécurisé des Tables ACPI** : Lecture et analyse des tables ACPI (RSDP, XSDT/RSDT, FADT) projetées en espace utilisateur via des objets mémoire VMO strictement restreints en lecture seule.
3. **Machine à États d'Alimentation Déterministe** : Transition conforme entre les états de veille ACPI (G0/S0 actif, G1/S3 veille en RAM, G2/S5 arrêt doux).
4. **Gestion Énergétique Dynamique des Cœurs SMP** : Coopération avec l'ordonnanceur EEVDF pour placer les cœurs AP inactifs en sommeil profond (C-States C1/C2/C3) et réguler les enveloppes thermiques.
5. **Gestionnaire de Batterie et Stratégie d'Urgence** : Émission d'alertes IPC en cas de niveau critique de batterie et déclenchement d'un repli ordonné sans corruption du système de fichiers JamboFS.

## Conséquences
- Confinement absolu : aucune logique d'interprétation ACPI complexe ni gestion d'énergie de haut niveau dans le micro-noyau Ring 0.
- Protection stricte contre les arrêts sauvages ou les manipulations hostiles d'alimentation.
- Économie d'énergie optimisée et traçabilité complète intégrée avec le grand livre d'audit `jambo-auditd`.

# ADR-0011: Moniteur de Micro-Machines Virtuelles en Espace Utilisateur (jambo-vmm)

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
La virtualisation matérielle (Intel VT-x, AMD-V, ARM64 Stage-2) est historiquement implémentée dans les noyaux monolithiques via des sous-systèmes tentaculaires (Linux KVM, Windows Hyper-V) introduisant des centaines de milliers de lignes de code privilégié en Ring 0. Cette approche viole les principes d'une base de confiance minimale (TCB) et expose l'ensemble du système d'exploitation à des vulnérabilités critiques de fuite d'invité (*VM escape*).

## Décision
Implémenter le moniteur de micro-machines virtuelles (`jambo-vmm`) en espace utilisateur Ring 3, s'appuyant sur :
1. **Capacités de Virtualisation Explicites (`VmCap`)** : La création d'une micro-machine virtuelle, la projection de sa mémoire physique invitée (*Guest Physical Address* - GPA) et l'exécution de ses processeurs virtuels (*vCPU*) requièrent obligatoirement une capacité sans autorité ambiante.
2. **Mémoire Invitée Confinée par EPT / VMO** : L'espace GPA est strictement délimité par des objets de mémoire virtuelle VMO dédiés et des tables de pagination imbriquée (*Extended Page Tables* - EPT), garantissant l'isolation physique totale vis-à-vis du micro-noyau et des autres processus Ring 3.
3. **Traitement Déterministe des VM-Exits en Espace Utilisateur** : Les interruptions de l'invité (accès MMIO, instructions de contrôle d'E/S, requêtes CPUID, arrêts HALT) sont interceptées et résolues en Ring 3 sans aucune logique d'émulation superflue dans le micro-noyau.
4. **Support d'Unikernels Sandboxed Ultra-Légers** : Amorçage déterministe de micro-environnements invités en moins de 5 ms avec une empreinte mémoire inférieure à 2 Mo.

## Conséquences
- Garantie d'étanchéité matérielle : même en cas de compromission totale du système d'exploitation invité, l'hyperviseur s'exécute sans privilèges en Ring 3 et ne peut compromettre le micro-noyau superviseur.
- Préservation de la pureté du Ring 0 qui ne conserve que le strict multiplexage matériel du contexte CPU guest/host.

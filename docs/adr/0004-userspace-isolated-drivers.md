# ADR-0004: Pilotes Matériels Isolés en Espace Utilisateur et Auto-Guérison

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
Plus de 70 % des pannes de noyaux conventionnels (Kernel Panic, BSOD) proviennent de bogues situés dans les pilotes de périphériques tiers.

## Décision
1. Tous les pilotes (PCIe, VirtIO, NVMe, USB xHCI, réseau, GPU) s'exécutent strictement en espace utilisateur (Ring 3).
2. L'accès DMA matériel est strictement filtré et isolé par unité IOMMU (Intel VT-d / ARM SMMUv3) configurée par le noyau.
3. En cas d'anomalie ou de crash du pilote, `jambo-init` effectue un *Function Level Reset* (FLR) du composant PCIe et redémarre le pilote en moins de 15 à 25 ms, sans interruption du noyau.

## Conséquences
- Résilience système exceptionnelle : 99,9 % de survie aux pannes matérielles/logicielles périphériques.
- Découplage complet du cycle de vie des pilotes et du micro-noyau.

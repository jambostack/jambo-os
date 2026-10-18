# ADR-0001: Architecture Micro-Noyau Orienté Capacités (JamboKernel)

- **Statut** : Accepté
- **Date** : 2026-10-18
- **Auteur** : ASSOGBA Prudence Dieudonné

## Contexte
Les systèmes d'exploitation monolithiques (Linux, BSD) intègrent des dizaines de millions de lignes de code en Ring 0 (superviseur), exposant l'ensemble du système à toute défaillance de pilote ou vulnérabilité mémoire.

## Décision
Adopter une architecture de micro-noyau pragmatique de 3e génération orienté capacités (`JamboKernel`) écrit en Rust `#![no_std]` avec une Base Informatique de Confiance (TCB) inférieure à 25 000 lignes de code.

Le noyau conserve strictement 5 responsabilités :
1. Gestion de la mémoire virtuelle et physique (Buddy Allocator, VMM, VMO)
2. Ordonnancement préemptif multicœur (EEVDF)
3. Application stricte des tables de capacités (CSpace)
4. Transport IPC synchrone (Fastpath registres) et asynchrone (Zero-Copy Rings)
5. Gestion des interruptions matérielles de bas niveau et configuration IOMMU

Tous les pilotes (VirtIO, NVMe, USB, réseau, GPU) et serveurs (système de fichiers JamboFS, réseau jambo-netd, compositeur JamboComp) s'exécutent en espace utilisateur isolé (Ring 3).

## Conséquences
- Confinement strict des pannes matérielles et logicielles
- Surface d'attaque minimale en Ring 0
- Nécessité d'un mécanisme IPC haute performance sans copie pour éliminer les surcoûts micro-noyau historiques

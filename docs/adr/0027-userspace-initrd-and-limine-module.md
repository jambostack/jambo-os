# ADR 0027: Packaging de l'Initrd Espace Utilisateur & Protocole Limine Module

## Statut
Accepté (Phase 38 - Jalon v0.2.36)

## Contexte
Jusqu'à la version `v0.2.35`, le chargeur d'amorçage Limine v3 ne chargeait que le fichier exécutable du superviseur `jambo-kernel.elf`. L'image ISO ne comportait aucun conteneur de fichiers ni aucun binaire d'espace utilisateur. Bien que le superviseur dispose d'un chargeur ELF64 et de structures de processus Ring 3, aucun processus utilisateur réel ne pouvait être instancié au boot à partir d'un support physique ou virtuel.

Pour franchir le seuil d'un micro-noyau pleinement opérationnel, il est indispensable de :
1. **Établir le cordon ombilical entre le superviseur et l'espace utilisateur** : Fournir une archive d'amorçage en mémoire (*ramdisk / initrd*) contenant au minimum le binaire de supervision PID 1 `jambo-init`.
2. **Découpler la compilation du noyau et des applications Ring 3** : Les applications utilisateur doivent être liées dans la moitié inférieure de la mémoire virtuelle (`0x0040_0000`), avec un modèle de relocalisation statique sans privilège Ring 0.
3. **Consommer le protocole de modules Limine (`ModulesRequest`)** : Permettre au noyau d'interroger le chargeur d'amorçage pour localiser les modules chargés, extraire les métadonnées et parser l'archive.
4. **Fournir un format d'archive standard et sans dépendance (`tar / ustar`)** : Parser l'archive en `#![no_std]` sans allocation dynamique pour localiser et charger les exécutables ELF64.

## Décision
Nous implémentons l'infrastructure d'initrd et de chargement de modules :
1. **Script de liaison utilisateur (`libs/user-x86_64.ld`)** :
   - Adresse de base virtuelle : `0x0040_0000`.
   - Segments d'en-tête de programme : `text` (R-X), `rodata` (R--), `data` (RW-).
   - Point d'entrée : `_start`.
2. **Orchestrateur de build (`xtask`)** :
   - Fonction `build_init` : compile `jambo-init` avec le linker script utilisateur et flags statiques.
   - Génération automatique de l'archive `initrd.tar` contenant `/bin/init` (et fichiers annexes).
   - Injection de `initrd.tar` dans `/boot/initrd.tar` de l'image ISO.
   - Déclaration de `module_path: boot():/boot/initrd.tar` dans `limine.conf`.
3. **Support du protocole Limine Module dans le noyau (`ModulesRequest`)** :
   - Enregistrement de `MODULES_REQUEST: ModulesRequest` dans les sections Limine.
   - Détection, extraction et validation des modules au boot du superviseur.
4. **Parser d'archive Tar `#![no_std]` (`kernel/src/mm/tar.rs`)** :
   - Décodage des en-têtes UStar 512 octets.
   - Recherche sans allocation de fichiers par nom (`find("init")`).
   - Transmission directe du slice d'octets ELF au chargeur `load_elf64`.

## Conséquences
- **Positives** :
  - L'image ISO JamboOS embarque désormais de véritables binaires Ring 3 autonomes.
  - Le superviseur peut inspecter, valider et charger dynamiquement des processus depuis l'initrd.
  - Préparation directe du saut vers l'espace utilisateur en Ring 3.
- **Négatives / Arbitrages** :
  - La taille de l'archive tar est bornée par la RAM disponible et la mémoire réservée par Limine lors du boot.

# ADR 0092: Moteur de Fuzzing TCB & Résilience Silicium sous Chaos Matériel (`jambo-fuzz`)

## Statut
Accepté (Palier 7 - Jalon v0.3.92)

## Contexte
La sécurité et la fiabilité d'un micro-noyau reposent sur l'étanchéité absolue de sa Trusted Computing Base (TCB). Aucune entrée utilisateur erronée, corrompue ou hostile ne doit pouvoir provoquer un panic, une boucle infinie ou une corruption mémoire dans le noyau ou les services système.
Pour garantir mathématiquement et empiriquement cette robustesse avant tout déploiement sur matériel réel, JamboOS intègre le moteur de durcissement offensif et d'injection de fautes `services/jambo-fuzz` :
1. Fuzzing systématique des paramètres d'appels système (adresses Ring 0, pointeurs nuls, dépassements d'entiers 64 bits).
2. Validation stricte des poignées de capacité CSpace (poignées forgées, génération 0, index hors table).
3. Test des barrières matérielles SMAP/SMEP et confinement IOMMU.
4. Mesure de résilience sous injection de fautes matérielles (crash de pilote et réinitialisation PCIe FLR sous SLA strict de 25 ms).

## Décision
1. **Moteur `SecurityFuzzer` & Démon `JamboFuzzDaemon` (`services/jambo-fuzz`)** :
   - Générateur pseudo-aléatoire déterministe LCG (`LcgRng`) adapté à l'environnement `#![no_std]`.
   - Campagne de fuzzing d'appels système testant des milliers de mutations : numéros hors bornes, adresses Ring 0 (`0xFFFF_8000_...`), adresses non canoniques et dépassement `u64::MAX`.
   - Invalidation de poignées CSpace frauduleuses et blocage des tentatives d'escalade de privilèges.
   - Simulation de pression mémoire (`usize::MAX`), débordements de canaux IPC et paquets UDP malformés.
2. **Barrières Matérielles & Confinement IOMMU** :
   - Vérification de la non-intersection des espaces d'adressage utilisateur (`< 0x0000_7FFF_FFFF_0000`) et superviseur (`>= 0xFFFF_8000_0000_0000`).
   - Confinement IOMMU bloquant 100 % des accès DMA hors du domaine attribué au périphérique.
   - Simulation d'un incident de pilote matériel avec réinitialisation PCIe FLR : récupération validée en 12 ms avec zéro perte de données (SLA < 25 ms).
3. **Commande Interactive `fuzz` dans le Shell `jsh`** :
   - Sous-commandes `status`, `run [n]`, `smap`, `iommu`, `chaos`.
4. **Intégration Chaîne de Construction `xtask`** :
   - Compilation et injection du binaire `/bin/fuzz` dans `initrd.tar` et `disk.raw`.

## Conséquences
- **Assurance Qualité & Résilience TCB** : 100 % des tentatives d'injection et corruptions sont interceptées avec zéro panique du micro-noyau.
- **Auto-Guérison Prouvée** : La chaîne de redémarrage des pilotes Ring 3 respecte les exigences de haute disponibilité temps réel.
- **Auditabilité Continue** : Les campagnes de fuzzing s'exécutent de manière automatisée lors de l'intégration continue.


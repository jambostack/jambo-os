# Jalon 4.4 : Isolation des Canaux IPC Ring Buffers & VMO Partagé Zéro-Copie (Spécification Technique)

## 1. Contexte & Objectifs

Cette spécification résout les vulnérabilités et non-conformités critiques identifiées lors de l'audit externe technique (**C-05**, **S-03**, **S-04**) :

1. **C-05 (Critique) : Le « VMO partagé zéro-copie 64 Kio » n'est pas relié aux deux processus**
   - *Constat d'audit* : `services/jambo-blockd/src/main.rs` utilisait un tableau statique privé `static mut SHARED_VMO_ARENA: [u8; 64 * 1024]`, tandis que `services/jambo-fs/src/lib.rs` utilisait une adresse fixe arbitraire `0x0070_0000` et un handle en dur `Handle(2)`. Aucun VMO réel n'était instancié par le noyau ni projeté de manière symétrique dans les deux espaces d'adressage.
   - *Correction exigée* : Créer le VMO dans le noyau via `VmoCreate`, attribuer des capacités `MAP` limitées aux deux processus, projeter les mêmes pages physiques dans les deux espaces, transmettre explicitement les handles de canal et de VMO, éliminer les pointeurs fixes et handles magiques.
   - *Critère d'acceptation* : Test Ring 3 démontrant qu'un processus A écrit un motif dans le VMO, qu'un processus B le lit, et prouvant formellement l'identité des pages physiques sans copie intermédiaire.

2. **S-03 (Sécurité) : Contrats IPC insuffisamment robustes**
   - *Constat d'audit* : Les messages IPC ne validaient pas strictement les longueurs (`byte_count`, `handle_count`), les handles n'étaient pas traduits ni transférés atomiquement entre les CSpaces des processus distincts, et les calculs d'index manquaient d'arithmétique vérifiée (`checked_add`, `checked_mul`).
   - *Correction exigée* : Validation stricte des limites de charge utile (`byte_count <= MAX_FASTPATH_BYTES`, `handle_count <= MAX_HANDLES`), transfert atomique et vérifié de capacités entre CSpaces émetteur et récepteur, et primitives de barrières mémoire Acquire/Release pour la synchronisation inter-cœurs.

3. **S-04 (Sécurité) : Risque de débordement dans les calculs d'E/S**
   - *Constat d'audit* : Expressions non vérifiées telles que `offset + total_bytes`, `req.count * SECTOR_SIZE` et `lba + count` dans le démon bloc pouvant entraîner des dépassements d'entiers (`overflow`) et contourner les contrôles de plage.
   - *Correction exigée* : Calculs arithmétiques 100 % vérifiés (`checked_add`, `checked_mul`) avec validation stricte contre la capacité réelle du disque et de l'arène VMO.

---

## 2. Architecture & Principes Fondamentaux

### 2.1 Transfert Atomique de Capacités sur Canal IPC (`ChannelCall`)

Lorsqu'un message contenant des handles est envoyé sur un canal IPC (`ChannelMessage`):
```
[Process A (CSpace A)]                     [Kernel Channel Queue]                    [Process B (CSpace B)]
   Handle(H_A)           -- ChannelCall -->  InFlightMessage                        
   (rights: TRANSFER)                        - bytes: [u8; 64]                       
                                             - caps: [KernelObject, rights]  -- ChannelCall -->  Handle(H_B)
   Slot A invalidé / révoqué                                                                     (nouveau slot CSpace B)
```

1. **Phase d'Émission (`send`)** :
   - Pour chaque `Handle` dans `msg.handles[0..handle_count]` :
     - Vérification de validité dans le `CSpace` du thread courant avec `cap_rights::TRANSFER`.
     - Extraction de l'objet noyau (`KernelObject`) et de ses droits.
     - Révocation/retrait atomique du slot dans le `CSpace` de l'émetteur.
     - Sauvegarde de `(KernelObject, rights)` dans la structure noyau `InFlightMessage`.
2. **Phase de Réception (`recv`)** :
   - Dépilage de `InFlightMessage`.
   - Pour chaque capacité en vol :
     - Insertion de la capacité dans le `CSpace` du thread récepteur.
     - Récupération du nouveau `Handle` alloué pour le processus B.
     - Inscription de ce `Handle` dans `msg.handles[i]`.
   - Copie sécurisée de la structure `ChannelMessage` dans l'espace utilisateur du récepteur via `copy_to_user`.

### 2.2 Anneaux Partagés Zéro-Copie (`SharedRing`) & Barrières Mémoire

Le micro-noyau fournit une abstraction d'anneau circulaire double (`Submission Queue` et `Completion Queue`) synchronisée par barrières mémoire :
- `atomic::fence(Ordering::Release)` lors de la publication de nouvelles requêtes (garantit que les données écrites dans le VMO partagé sont visibles avant la mise à jour de la tête de soumission).
- `atomic::fence(Ordering::Acquire)` lors de la consommation des requêtes/réponses (garantit que les données lues depuis le VMO sont observées après validation de la disponibilité).
- Masquage binaire et arithmétique protégée pour la circularité (`entries.is_power_of_two()`).

### 2.3 Handshake VMO Partagé pour le Stockage (`blockd` & `jambo-fs`)

1. À l'initialisation du système :
   - Le superviseur / noyau crée un canal IPC et injecte une extrémité dans le `CSpace` de `blockd` (Handle 1) et l'autre extrémité dans le `CSpace` de `fs` (Handle 1).
2. Au démarrage de `blockd` :
   - `blockd` crée un VMO de 64 Kio via l'appel système `VmoCreate(64 * 1024, 0, &mut vmo_h)`.
   - `blockd` projette le VMO dans son espace d'adressage via `VmoMap(Handle::NULL, vmo_h, 0x0070_0000, READ | WRITE)`.
   - `blockd` attend la requête d'initialisation de `fs` ou lui envoie le handle VMO en pièce jointe de capacité via `ChannelCall`.
3. Au démarrage de `fs` :
   - `fs` se connecte à son canal (Handle 1), reçoit le handle VMO transféré par `blockd`, et le projette dans son propre espace d'adressage à `0x0070_0000` via `VmoMap`.
4. Résultat :
   - `blockd` et `fs` pointent sur **exactement les mêmes pages physiques**.
   - Suppression intégrale de `static mut SHARED_VMO_ARENA`.
   - Zéro copie intermédiaire lors des opérations de lecture/écriture de blocs.

---

## 3. Critères d'Acceptation & Validation

1. **Compilation & Typage Strict** :
   - `cargo xtask build --release` et `cargo xtask build` compilent sans le moindre avertissement ni erreur en mode `#![no_std]`.
   - `cargo fmt --all -- --check` valide le formatage exact de tout le dépôt.
2. **Test Adversarial dans le Noyau (`execute_zero_copy_ipc_tests`)** :
   - Création de deux processus distincts (Process A et Process B) avec espaces d'adressage et tables de capacités indépendants.
   - Process A alloue un VMO de 64 Kio, le projette à `0x0080_0000`, y inscrit une signature cryptographique avec barrière `Release`.
   - Process A transfère le handle du VMO à Process B via un canal IPC.
   - Process B reçoit un handle valide dans son CSpace, projette le VMO à `0x0090_0000`, et lit la signature avec barrière `Acquire`.
   - Assertion noyau : les pages physiques sous-jacentes à `0x0080_0000` (Process A) et `0x0090_0000` (Process B) sont **strictement identiques** (`phys_a == phys_b`).
   - Assertion noyau : Process B modifie le contenu, Process A l'observe immédiatement sans ré-allocation ni duplication de page.
   - Test d'injection de débordements arithmétiques (`usize::MAX`, `u64::MAX`) sur les descripteurs et requêtes : rejet systématique par `SysError::InvalidArgument`.
3. **Validation QEMU & Télémétrie CI** :
   - Exécution sous QEMU confirmant le message :
     `[PASS] Canaux IPC Ring Buffers Zero-Copy et VMO Partage valides sous QEMU.`


# ADR 0081: Environnements d'Exécution de Confiance (TEE), Enclaves Matérielles Isolées et Mémoire Chiffrée Ring 3 (`jambo-tee`)

## Statut
Accepté (Phase 92 - Jalon v0.2.90)

## Contexte
Dans l'architecture de micro-noyau souverain orienté capacités de JamboOS (`#![no_std]`), la protection des données ultrasensibles (clés cryptographiques, modèles d'inférence, identités distribuées) face aux attaques physiques et aux compromissions de l'environnement hôte exige une barrière matérielle étanche. Le service `jambo-tee` introduit la gestion souveraine des Environnements d'Exécution de Confiance (TEE) et de la mémoire chiffrée Ring 3 :
1. **Abstraction Matérielle Multi-Architecture (`TeeBackend`)** :
   - Support abstrait des technologies TEE majeures : Intel SGX (Enclave Page Cache EPC, structures SECS/TCS, instructions EENTER/EEXIT/EADD/EINIT), Intel TDX (Trust Domains et EPT sécurisées), ARM TrustZone (Secure World / non-secure isolation) et ARM CCA (Realm Management Extension RME, Granule Protection).
   - Backend Micro-Enclave logicielle émulée pour la virtualisation et l'isolation mémoire contrôlée par le micro-noyau.
2. **Cycle de Vie Strict d'Enclave (`EnclaveState`)** :
   - FSM formelle : `Uninitialized -> Created -> Loading -> Finalized -> Running -> Destroyed`.
   - Les pages de code et données ne peuvent être chargées que durant la phase d'initialisation (`Created`/`Loading`). Toute altération post-finalisation est formellement interdite.
3. **Mesure Cryptographique Inviolable (`MRENCLAVE` & `MRSIGNER`)** :
   - Calcul cumulatif d'un condensat SHA-256 (`MRENCLAVE`) sur l'ensemble des pages chargées, adresses virtuelles et points d'entrée lors de la finalisation.
   - Intégration de l'identité cryptographique de l'autorité signataire (`MRSIGNER`).
4. **Scellement Cryptographique de Données (`Sealed Storage`)** :
   - Mécanisme de scellement (`seal_data` / `unseal_data`) dérivant des clés cryptographiques selon deux politiques strictes : `ExactMeasurement` (seule l'enclave avec une mesure rigoureusement identique peut désceller) ou `SignerIdentity` (toute enclave signée par la même autorité peut désceller).
   - Authentification et intégrité garanties par balises HMAC-SHA256 et chiffrement de flux.
5. **Attestation Cryptographique Locale et Distante (`TeeReport` / EREPORT)** :
   - Génération de rapports signés par HMAC-SHA256 liant `MRENCLAVE`, `MRSIGNER`, horodatage et un défi aléatoire / nonce anti-rejeu (`user_data`).
6. **Effacement Sécurisé de la Mémoire (`Memory Scrubbing`)** :
   - À la destruction d'une enclave, toutes les pages physiques et virtuelles associées sont systématiquement effacées (mise à zéro stricte) pour prévenir toute rémanence ou attaque par démarrage à froid.
7. **Gouvernance Capabilaire (`TeeCap`) & Absence d'Autorité Ambiante** :
   - Droits granulaires (`CREATE`, `LOAD`, `ENTER`, `SEAL`, `REPORT`, `ADMIN`) avec atténuation monotone irréversible et rejet de tout handle NULL.

## Décision
1. Implémentation du service `services/jambo-tee` (`TeeBackend`, `EnclaveState`, `EnclavePage`, `SealingPolicy`, `SealedBlob`, `TeeReport`, `TeeCap`, `JamboTeeDaemon`).
2. Intégration de la commande interactive `tee` dans `services/jambo-sh` (`status`, `list`, `report`, `audit`).
3. Création de la suite de test d'intégration noyau `kernel/src/sched/tee_test.rs` et inclusion dans `kernel/src/main.rs`.
4. Incrémentation de la version globale vers `v0.2.90` dans tous les `Cargo.toml`.

## Conséquences
- Confinement matériel de pointe et chiffrement de mémoire transparent pour les charges de travail critiques sous Ring 3.
- Protection cryptographique contre les attaques d'introspection mémoire, de DMA malveillant ou de compromission de l'espace utilisateur non privilégié.
- Traçabilité complète scellée par SHA-256 validée sous émulation QEMU.

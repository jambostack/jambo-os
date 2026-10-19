# ADR 0043: Chiffrement de Bloc Transparent & Scellement Matériel TPM 2.0 (`jambo-cryptod`)

## Statut
Accepté (Phase 54 - Jalon v0.2.52)

## Contexte
Après la gestion énergétique matérielle ACPI et la régulation des C-States de la Phase 53 (ADR 0042, v0.2.51), JamboOS aborde la protection cryptographique au repos du stockage persistant avec `services/jambo-cryptod`, garantissant le chiffrement transparent à la volée des secteurs de disque et l'attestation mesurée TPM 2.0 (Measured Boot) sous le contrôle strict de capacités d'espace utilisateur :
1. **Règle Fondamentale de Confinement Cryptographique** :
   - Conformément au principe du moindre privilège et à l'absence totale d'autorité ambiante, aucun accès en lecture ou écriture aux secteurs bruts d'un volume chiffré n'est possible sans détenir une capacité explicite `CryptoVolumeCap`.
   - Droits granulaires de la capacité : `READ_SECTOR`, `WRITE_SECTOR`, `ROTATE_KEY`, `SEAL_TPM`, cantonnés à un identifiant de volume spécifique (`volume_id`).
2. **Chiffrement de Bloc Déterministe (`ChaCha20SectorCipher`)** :
   - Chiffrement de flux haute performance sans allocation dynamique (`#![no_std]`), basé sur ChaCha20 (RFC 8439) à 20 tours (10 doubles tours de colonnes et diagonales).
   - Dérivation de sous-clés et keystream par adresse LBA (`lba` 64 bits combiné au compteur de blocs et au nonce JamboOS), garantissant qu'un même contenu en clair écrit à deux secteurs distincts produit deux blocs chiffrés totalement dissemblables.
3. **Scellement Cryptographique Matériel TPM 2.0 (`TpmSealEngine`)** :
   - Modèle d'attestation de démarrage mesuré (Measured Boot) combinant les registres PCR 0 à 7 (Firmware, Configuration, Option ROM, Boot Policy, Limine Loader, Table GPT, Resume State, Secure Boot).
   - Calcul de condensat composite PCR par dispersion et rotation non-linéaire (`compute_composite_pcr_digest`).
   - Le blob scellé (`SealedKeyBlob`) ne peut être descellé que si l'empreinte composite des registres PCR de la plateforme hôte est rigoureusement identique à celle enregistrée lors du scellement.
   - Toute altération de la chaîne de démarrage (ex: injection de code dans le bootloader) produit un rejet immédiat (`PermissionDenied`).
4. **Commandes Interactives dans le Shell `jsh`** :
   - `crypto status` : état du volume chiffré, nombre de secteurs traités, statut du scellement TPM et algorithme actif.
   - `crypto encrypt <lba> [msg]` : chiffrement et écriture d'un secteur test de 512 octets.
   - `crypto seal` : scellement de la clé maîtresse sous l'état matériel actuel des PCR TPM.
   - `crypto verify` : vérification de l'intégrité de la plateforme et tentative de descellement.
5. **Harnais de Validation Noyau (`kernel/src/sched/crypto_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 54) du chiffrement/déchiffrement de secteur, de la diversité LBA, du confinement des droits `CryptoVolumeCap` et de la détection d'altération PCR.

## Décision
1. Ajout de `JamboCryptoDaemon` dans `services/jambo-cryptod/src/lib.rs`.
2. Intégration de `jambo-cryptod` dans `services/jambo-sh` avec l'implémentation de la commande `crypto`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création de `kernel/src/sched/crypto_test.rs`.
4. Validation complète sous QEMU (Phase 54) et publication de la version `v0.2.52`.

## Conséquences
- Chiffrement transparent et sécurisé du stockage au repos sans dépendance de privilèges superviseur Ring 0.
- Protection formelle contre le vol physique et la falsification de l'environnement d'amorçage via TPM 2.0.

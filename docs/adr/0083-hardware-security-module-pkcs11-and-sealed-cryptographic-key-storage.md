# ADR 0083: Module de Sécurité Matériel HSM Ring 3, Dérivation PKCS#11 et Stockage de Clés Cryptographiques Scellées (`jambo-hsm`)

## Statut
Accepté (Phase 94 - Jalon v0.2.92)

## Contexte
Dans l'architecture de micro-noyau sécurisé sans autorité ambiante de JamboOS (`#![no_std]`), la manipulation de clés cryptographiques maîtresses (chiffrement de stockage, signatures de grappe, identités de nœuds) nécessite un confinement matériel strict :
1. **Émulation et Abstraction HSM Souverain (`HsmSlot`, `HsmToken`)** :
   - Isolation étanche des clés privées et secrètes au sein de slots matériels (Slot 0 physique souverain, Slot 1 enclave virtuelle TEE).
2. **Alignement et Conformité PKCS#11 v2.40 (Cryptographic Token Interface)** :
   - Gestion de sessions publiques et privées (états `RoPublicSession`, `RoUserFunctions`, `RwPublicSession`, `RwUserFunctions`, `RwSoFunctions`).
   - Authentification par code PIN distinct pour l'Officier de Sécurité (`CKU_SO`) et l'Utilisateur (`CKU_USER`), avec verrouillage automatique après tentatives infructueuses (anti-bruteforce).
3. **Hiérarchie et Dérivation de Clés HKDF-SHA256 (RFC 5869 Extract & Expand)** :
   - Dérivation déterministe de sous-clés (DEK de stockage, clés de tunnel IPC, clés de signature éphémères) depuis une Clé Maîtresse HSM (Master Key / KEK) qui ne quitte JAMAIS la mémoire sécurisée du HSM.
4. **Attributs et Politiques de Protection d'Objets (`HsmKeyAttributes`)** :
   - `CKA_SENSITIVE` : interdiction formelle d'extraire la clé en clair.
   - `CKA_EXTRACTABLE = false` : interdiction stricte de wrapping ou d'exportation non autorisée.
   - Contrôle d'usage exclusif : `encrypt`, `decrypt`, `sign`, `verify`, `wrap`, `unwrap`, `derive`.
5. **Enveloppement et Scellement Cryptographique de Clés (Key Wrapping & Unwrapping)** :
   - Enveloppement symétrique de clés sous la clé KEK racine avec contrôle d'intégrité HMAC-SHA256.
6. **Zéroïsation d'Urgence (Emergency Hardware Zeroization)** :
   - En cas d'intrusion physique ou d'alerte critique, effacement destructif et sécurisé de toutes les clés matérielles et verrouillage définitif en temps O(1).
7. **Chaîne d'Audit Scellée SHA-256 (`hsm_audit_chain`)** :
   - Traçabilité cryptographique inaltérable de toutes les opérations de génération, dérivation, signature et zéroïsation.
8. **Gouvernance Capabilaire Stricte (`HsmCap`)** :
   - Droits granulaires (`hsm_rights::ALL`, `OPEN_SESSION`, `LOGIN`, `GENERATE_KEY`, `DERIVE_KEY`, `CRYPTO_OP`, `WRAP_KEY`, `UNWRAP_KEY`, `DESTROY_KEY`, `ZEROIZE`, `ADMIN`) avec atténuation monotone irréversible.

## Décision
1. Implémentation de la crate `services/jambo-hsm` (`Sha256`, `HkdfSha256`, `ChaCha20Hsm`, `HsmMechanism`, `HsmObjectClass`, `HsmKeyType`, `HsmUserType`, `HsmKeyAttributes`, `HsmSlot`, `HsmToken`, `HsmSession`, `HsmObject`, `HsmCap`, `JamboHsmDaemon`).
2. Intégration de la commande shell `hsm` dans `services/jambo-sh` (`status`, `slots`, `objects`, `derive`, `wrap`, `zeroize`, `audit`).
3. Création de la suite de test d'intégration noyau `kernel/src/sched/hsm_test.rs` et inclusion dans `kernel/src/main.rs`.
4. Incrémentation de la version globale vers `v0.2.92` dans tous les `Cargo.toml`.

## Conséquences
- Sécurité cryptographique absolue pour les clés souveraines de JamboOS, confinées au sein du HSM Ring 3.
- Conformité architecturale PKCS#11 et dérivation normalisée RFC 5869 HKDF-SHA256.
- Résistance matérielle aux effractions via zéroïsation d'urgence en O(1).
- Validation formelle complète éprouvée sous QEMU.

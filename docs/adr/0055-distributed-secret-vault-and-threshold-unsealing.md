# ADR 0055: Coffre-Fort de Secrets Distribué & Déverrouillage à Seuil Shamir (`jambo-vaultd`)

## Statut
Accepté (Phase 66 - Jalon v0.2.64)

## Contexte
Dans une architecture de grappe distribuée sous micro-noyau souverain orienté capacités, le stockage et la gestion du cycle de vie des secrets cryptographiques (certificats TLS, clés privées asymétriques, jetons de capacités et mots de passe d'infrastructure) requièrent un coffre-fort hautement sécurisé sans autorité ambiante. Avec `services/jambo-vaultd`, JamboOS intègre un magasin de secrets chiffré à déverrouillage distribué `#![no_std]` :
1. **Confinement Capabilaire de Coffre-Fort (`VaultCap`)** :
   - L'accès et la gestion du coffre sont strictement gouvernés par des jetons capabilitaires `VaultCap`.
   - Droits granulaires (`VAULT_READ`, `VAULT_WRITE`, `VAULT_ROTATE`, `VAULT_UNSEAL`, `VAULT_ADMIN`), interdisant la lecture indiscrète ou la rotation non autorisée de secrets sans capacité dédiée.
2. **Déverrouillage par Quorum de Clés à Seuil Shamir (K sur N Parts)** :
   - La clé maîtresse du coffre ne réside jamais en clair en mémoire tant que le quorum à seuil (`threshold` parts parmi `total_shares`) n'a pas été formellement réuni (`submit_unseal_share`).
   - Tout accès prématuré sous état scellé (`Sealed` ou `Unsealing`) est formellement bloqué (`Err(SysError::ResourceBusy)`).
3. **Chiffrement d'Enveloppe & Contrôle Strict des Baux Temporels (`lease_expires_at`)** :
   - Chaque secret est chiffré individuellement avec la clé maîtresse sous chiffrement d'enveloppe symétrique 256 bits.
   - Durée de vie bornée par bail temporel déterministe ; toute tentative de lecture au-delà de l'expiration du bail échoue (`Err(SysError::TimedOut)`).
   - Versionnement automatique des secrets (`version`) et rotation dynamique (`rotate_secret`).
4. **Rescellement Atomique (`reseal`) & Révocation Immédiate (`revoke_secret`)** :
   - Possibilité de rescellemenet d'urgence réinitialisant immédiatement les parts soumises et verrouillant le magasin en mémoire.
   - Révocation physique immédiate d'un secret avec effacement sécurisé.
5. **Démon Orchestrateur Ring 3 (`JamboVaultDaemon`) & Commandes `jsh`** :
   - Démon orchestrateur gérant le coffre local et l'interface de contrôle du quorum.
   - Commandes interactives dans `jsh` :
     - `vault status` : état du coffre (scellé / déverrouillé), secrets stockés, quorum Shamir et confinement capabilaire.
     - `vault put <path> <val>` : stockage sécurisé d'un secret avec bail temporel.
     - `vault get <path>` : lecture et déchiffrement d'un secret actif.
     - `vault reseal` : verrouillage immédiat du coffre.
     - `vault unseal` : soumission des parts de quorum et déverrouillage du coffre.
6. **Harnais de Validation Noyau (`kernel/src/sched/vault_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 66) des droits capabilitaires `VaultCap`, du quorum de déverrouillage Shamir, du chiffrement d'enveloppe, du contrôle de baux, du rescellement et des commandes du shell.

## Décision
1. Implémentation du démon `JamboVaultDaemon` et de ses tests unitaires dans `services/jambo-vaultd/src/lib.rs`.
2. Intégration de `jambo-vaultd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `vault`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/vault_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 66) et publication de la version `v0.2.64`.

## Conséquences
- Protection cryptographique de niveau militaire des secrets de la grappe avec tolérance aux compromissions partielles.
- Socle pour les métriques chronologiques distribuées et télémétrie de grappe (`jambo-metricsd`, Phase 67).

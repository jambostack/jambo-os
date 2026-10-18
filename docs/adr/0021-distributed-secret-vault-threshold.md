# ADR 0021: Coffre-Fort de Secrets Distribué & Déverrouillage par Partage à Seuil (`jambo-vaultd`)

## Statut
Accepté (Phase 32 - Jalon v0.2.30)

## Contexte
Au sein d'un cluster JamboOS hautement sécurisé, les différents services (`jambo-authd`, `jambo-cryptod`, `jambo-meshd`, `jambo-pkgd`, `jambo-gwd`) manipulent des données hautement critiques : clés privées Ed25519, certificats TLS racine, clés de chiffrement de volume ChaCha20 et jetons de cluster. 

Laisser ces secrets en clair dans `jambo-kvd` ou dépendre d'une clé maîtresse unique détenue par un seul nœud introduirait un point unique de compromission (*Single Point of Compromise*) ou de défaillance.

Un sous-système de coffre-fort distribué doit répondre aux exigences suivantes :
1. **Partage de clé maîtresse à seuil (*Threshold Secret Sharing*)** : division de la clé de déchiffrement racine en $N$ parts (parts de Shamir ou fractions déterministes) exigeant la réunion d'au moins $K$ parts ($K \le N$) pour déverrouiller le coffre (*unseal*).
2. **Chiffrement d'enveloppe (*Envelope Encryption*)** : chaque secret est chiffré individuellement avec une clé dérivée unique (DEK) scellée par la clé maîtresse du cluster (KEK).
3. **Baux temporels & Révocation automatique** : chaque secret concédé est associé à une durée de validité stricte (*lease*), révocable à tout moment.
4. **Contrôle d'accès sans autorité ambiante (`VaultCap`)** : aucune lecture ou écriture de secret n'est accordée sans possession de la capacité adéquate.
5. **Déterminisme mémoire `#![no_std]`** : allocations bornées et sécurisées en mémoire avec nettoyage à zéro (*zeroize*) lors de la suppression.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-vaultd` (`services/jambo-vaultd`) intégrant :
1. **Gestionnaire d'état de scellement (*Seal Status*)** :
   - États : `Sealed` (verrouillé), `Unsealing` (en cours avec accumulation de parts), `Unsealed` (déverrouillé).
   - Seuil de quorum $K$ (par ex. 3 parts sur 5 requises).
2. **Table de secrets chiffrés (`VaultSecretEntry`)** :
   - Capacité bornée (`MAX_SECRETS = 32`).
   - Identifiant unique `path: [u8; 32]`.
   - Charge utile chiffrée avec masque de dérivation de clé.
   - Durée de bail temporel (`lease_expires_at: u64`) et version de rotation (`version: u32`).
3. **Contrôle d'accès orienté capacités (`VaultCap`)** :
   - Droits explicites : `VAULT_READ` (0x01), `VAULT_WRITE` (0x02), `VAULT_ROTATE` (0x04), `VAULT_UNSEAL` (0x08), `VAULT_ADMIN` (0x80).
4. **API Ring 3 sécurisée** :
   - `submit_unseal_share` : accumulation progressive des parts de quorum.
   - `put_secret` / `get_secret` : accès chiffré conditionné au déverrouillage et à la validité du bail.
   - `rotate_secret` : incrémentation de version et ré-encapsulation.

## Conséquences
- **Positives** :
  - Aucun nœud isolé ne détient le secret racine.
  - Résilience aux compromissions partielles grâce au quorum $K$ sur $N$.
  - Confinement absolu conforme à la philosophie zéro-autorité de JamboOS.
- **Négatives / Arbitrages** :
  - Tant que le quorum de parts n'est pas atteint, les services dépendants de secrets scellés sont temporairement mis en attente.

# ADR 0060: Autorité de Certification Éphémère & mTLS (`jambo-certd`)

## Statut
Accepté (Phase 71 - Jalon v0.2.69)

## Contexte
Dans une architecture de grappe distribuée sous micro-noyau souverain orienté capacités, la sécurisation des communications inter-nœuds et des canaux IPC distants requiert une infrastructure à clés publiques (PKI) ultra-légère, éphémère et déterministe en `#![no_std]`. Avec `services/jambo-certd`, JamboOS fournit une autorité de certification (CA) de cluster native :
1. **Confinement Capabilaire de Certification (`CertCap`)** :
   - L'accès aux fonctions cryptographiques de la CA est scellé par des jetons capabilitaires `CertCap`.
   - Droits granulaires (`CERT_ISSUE`, `CERT_REVOKE`, `CERT_VERIFY`, `CERT_INSPECT`, `CERT_ADMIN`), interdisant toute émission ou révocation arbitraire de certificats sans délégation explicite.
2. **Certificats Éphémères Signés Cryptographiquement (`EphemeralCert`)** :
   - Certificats de format compact (numéro de série 64 bits, identifiant CN / FQDN jusqu'à 48 octets, clé publique 256 bits, fenêtres temporelles `not_before` / `not_after`).
   - Signature d'intégrité cryptographique SHA-256 calculée déterministement avec la clé racine secrète de la CA du cluster (`ClusterCa`).
3. **Validation Temporelle et Révocation Instantanée (`is_revoked`, CRL intégrée)** :
   - Vérification stricte des fenêtres de validité temporelle (`not_before <= t <= not_after`).
   - Révocation immédiate avec horodatage et code de motif, invalidant instantanément tout certificat compromis dans la table de révocation (`MAX_REVOKED_CERTS = 16`).
4. **Table Active Circulaire Bornée (`ClusterCa`)** :
   - Maintien borné en mémoire statique (`MAX_ACTIVE_CERTS = 32`) avec footprint total inférieur à 5 Ko.
   - Zéro allocation dynamique sur le chemin critique, garantissant l'absence de saturation mémoire ou d'attaques par épuisement de ressources.
5. **Démon Orchestrateur Ring 3 (`JamboCertDaemon`) & Commandes Shell `cert`** :
   - Démon initialisant un certificat éphémère par défaut pour le nœud local (`node-0.cluster.local`, serial 1000).
   - Commandes interactives dans `jsh` :
     - `cert status` : affiche le nombre de certificats actifs, révoqués et l'état de l'autorité racine.
     - `cert issue <serial> <cn> <not_before> <not_after>` : émission d'un certificat éphémère signé.
     - `cert verify <serial> <timestamp>` : vérification cryptographique, temporelle et d'absence de révocation.
     - `cert revoke <serial> <timestamp>` : révocation immédiate d'un certificat.
6. **Harnais de Validation Noyau (`kernel/src/sched/certd_test.rs`)** :
   - Validation bout-en-bout sous QEMU (Phase 71) de l'atténuation des capacités `CertCap`, de la vérification de signature SHA-256, de l'expiration temporelle, de la révocation et des commandes du shell.

## Décision
1. Conception et implémentation du démon `JamboCertDaemon` et de ses tests unitaires dans `services/jambo-certd/src/lib.rs`.
2. Intégration de `jambo-certd` dans `services/jambo-sh` avec l'implémentation de la commande interactive `cert`.
3. Ajout de la dépendance dans `kernel/Cargo.toml` et création du module de validation `kernel/src/sched/certd_test.rs`.
4. Intégration dans `kernel/src/main.rs`, validation complète sous QEMU (Phase 71) et publication de la version `v0.2.69`.

## Conséquences
- Établissement d'une identité cryptographique forte et éphémère pour chaque service et nœud de la grappe JamboOS.
- Fondation pour l'authentification mutuelle (mTLS) et le chiffrement transparent de bout en bout des liaisons réseau.

# ADR 0026: Infrastructure à Clés Publiques Éphémères & Gestion des Certificats de Grappe (`jambo-certd`)

## Statut
Accepté (Phase 37 - Jalon v0.2.35)

## Contexte
Dans la grappe distribuée JamboOS, les services (`jambo-serviced`), les nœuds de calcul (`jambo-schedd`), le maillage chiffré (`jambo-meshd`) et les passerelles d'entrée (`jambo-gwd`) échangent des flux de données hautement sensibles.

Si `jambo-authd` fournit des défis-réponses de session locale et `jambo-vaultd` stocke des secrets statiques, la communication sécurisée inter-services et inter-nœuds Zero-Trust requiert une infrastructure de certificats éphémères :
1. **Certificats à courte durée de vie (Short-Lived Ephemeral Certificates)** : élimination des risques liés au vol de certificats longue durée grâce à des baux stricts (ex: 1 heure à 24 heures).
2. **Attestation et signature cryptographique d'identité** : association non-répudiable d'un nom de service canonique (SAN), d'un identifiant de nœud et d'une clé publique à une signature d'autorité.
3. **Vérification cryptographique instantanée `#![no_std]`** : validation de chaîne de confiance, de dates de validité et de contraintes d'usage sans allocation dynamique non bornée.
4. **Révocation proactive et listes d'exclusion** : invalidation immédiate d'un certificat compromis avant son terme normal d'expiration.
5. **Contrôle d'accès sans autorité ambiante (`CertCap`)** : seules les entités détentrices de capacités explicites peuvent émettre, signer ou révoquer des identités de grappe.

## Décision
Nous implémentons le démon d'espace utilisateur `jambo-certd` (`services/jambo-certd`) intégrant :
1. **Certificat éphémère compact (`EphemeralCert`)** :
   - Numéro de série unique `serial: u64`.
   - Sujet / SAN (`subject: [u8; 32]`, `subject_len: usize`).
   - Clé publique du sujet (`public_key: [u8; 32]`).
   - Fenêtre de validité temporelle (`not_before: u64`, `not_after: u64`).
   - Masque d'usages autorisés `key_usage: u32` (ex: `USAGE_SERVER_AUTH`, `USAGE_CLIENT_AUTH`, `USAGE_CODE_SIGN`, `USAGE_MESH_ROUTING`).
   - Empreinte cryptographique de signature d'autorité (`ca_signature: [u8; 32]`).
2. **Autorité de certification de grappe (`ClusterCa`)** :
   - Identifiant d'autorité `ca_id: u32`.
   - Clé publique d'autorité (`ca_public_key: [u8; 32]`).
   - Capacité bornée (`MAX_ACTIVE_CERTS = 32`, `MAX_REVOKED_CERTS = 16`).
   - Méthodes d'émission (`issue_cert`), de vérification (`verify_cert`), de révocation (`revoke_cert`) et de purge des certificats expirés (`purge_expired`).
3. **Contrôle d'accès par capacités (`CertCap`)** :
   - Droits explicites : `CERT_ISSUE` (0x01), `CERT_VERIFY` (0x02), `CERT_REVOKE` (0x04), `CERT_AUDIT` (0x08), `CERT_ADMIN` (0x80).

## Conséquences
- **Positives** :
  - Identité Zero-Trust native pour tous les services, nœuds et micro-VMs de JamboOS.
  - Résilience contre le vol d'identifiants grâce aux certificats à validité éphémère.
  - Fonctionnement autonome et déterministe en `#![no_std]` sans dépendance externe lourde.
- **Négatives / Arbitrages** :
  - Le nombre maximum de certificats actifs et de révocations simultanées est statiquement plafonné en mémoire système.

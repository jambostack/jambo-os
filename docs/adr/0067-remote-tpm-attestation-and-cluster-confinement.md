# ADR 0067: Attestation Matérielle Distante TPM 2.0 et Confinement de Grappe (`jambo-secpolicyd`)

## Statut
Accepté (Phase 78 - Jalon v0.2.76)

## Contexte
L'intégrité cryptographique de la chaîne de démarrage et la résilience face aux menaces avancées (bootkits UEFI, rootkits noyau, chargeurs altérés, falsification de politiques) nécessitent une attestation matérielle distante inviolable avant d'autoriser tout nœud à participer aux échanges réseau et aux opérations en grappe.
Dans un micro-noyau souverain `#![no_std]` orienté capacités, cette sécurité doit être assurée sans autorité ambiante, sans allocations dynamiques non bornées, et avec une isolation stricte des systèmes compromis.

Avec `services/jambo-secpolicyd`, JamboOS intègre un démon de sécurité matérielle TPM 2.0 et de confinement souverain :

1. **Contrôle d'Accès Capabilaire Strict (`SecPolicyCap`)** :
   - Droits granulaires : `ATTEST_READ`, `ATTEST_CHALLENGE`, `PCR_EXTEND`, `POLICY_ENFORCE`, `CONFINEMENT_MANAGE`, `ADMIN`.
   - Atténuation capabilaire sans possibilité d'élévation de privilège (`SysError::PermissionDenied`).

2. **Banque de Registres PCR TPM 2.0 (`PcrBank`) & Extensions Cryptographiques SHA-256** :
   - 24 registres PCR (PCR 0 à 23) de 32 octets chacun, conformes aux spécifications TCG PC Client.
   - Algorithme d'extension standard : `PCR[i] = SHA256(PCR[i] || event_digest)`.
   - Journal d'événements de démarrage mesuré borné (`EventLog`) en mémoire statique pour l'auditabilité complète.

3. **Citations Signées Asymétriques (`TpmQuote`) & Protection Anti-Rejeu** :
   - Protocole de défi-réponse par nonce frais aléatoire émis par le vérificateur (`fresh challenge nonce`).
   - Calcul de l'empreinte composite cryptographique (`composite_digest`) combinant les PCRs sélectionnés par masque binaire et le nonce.
   - Signature asymétrique de citation (`TpmAttestationKey`) liée à la clé d'attestation AK du nœud.

4. **Vérification Inter-Nœuds et Confinement Automatique Zero-Trust** :
   - Comparaison déterministe avec la référence intègre du cluster (Golden Baseline Measurements).
   - Détection instantanée des falsifications de chargeur (PCR 4) ou de micro-noyau (PCR 8).
   - Bascule automatique et immédiate des nœuds compromis en état de `Quarantine` ou `Revoked`.
   - Dégradation des droits réseau et révocation des capacités d'accès aux services sensibles du cluster.

5. **Commandes Shell Interactives `secpolicy` dans `jsh`** :
   - `secpolicy status` : état de l'attestation locale, métriques TPM, télémétrie des citations et inventaire des nœuds.
   - `secpolicy pcrs` : affichage des registres PCR 0..15 et de leurs empreintes SHA-256 actives.
   - `secpolicy verify <node_id>` : exécution d'un défi-réponse d'attestation matérielle distante.
   - `secpolicy confine <node_id> <mode>` : application explicite de confinement (`trusted`, `strict`, `quarantine`, `revoked`).

6. **Validation Noyau Dédiée (`kernel/src/sched/secpolicyd_test.rs`)** :
   - Suite complète sous QEMU validant les droits capabilitaires, l'extension PCR, la signature de citation, la détection de bootkit et l'isolation automatique.

## Décision
1. Conception et implémentation du démon `JamboSecPolicyDaemon`, des structures `PcrBank`, `TpmQuote`, `SecPolicyCap` dans `services/jambo-secpolicyd`.
2. Intégration de la commande `secpolicy` dans le shell objet `services/jambo-sh`.
3. Écriture du module de test noyau `kernel/src/sched/secpolicyd_test.rs` et activation dans `kernel/src/main.rs`.
4. Incrémentation de version vers `v0.2.76` pour l'ensemble des modules du workspace.

## Conséquences
- Confinement automatisé des nœuds dont le démarrage mesuré présente une altération.
- Protection cryptographique certifiée par TPM 2.0 contre les attaques par rejeu et les falsifications de bas niveau.

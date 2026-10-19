# ADR 0082: Attestation Cryptographique à Distance, Preuves Zero-Knowledge (ZKP) et Confinement Matériel de Grappe (`jambo-attest`)

## Statut
Accepté (Phase 93 - Jalon v0.2.91)

## Contexte
Dans l'architecture distribuée sans autorité ambiante de JamboOS (`#![no_std]`), l'admission, le maintien et la collaboration de nœuds hétérogènes au sein d'une grappe souveraine nécessitent une vérification d'intégrité stricte, continue et sans divulgation de secrets sensibles (clés maîtresses, topologie mémoire, données propriétaires). Le service `jambo-attest` introduit les mécanismes suivants :
1. **Attestation Cryptographique Distante Multi-Architecture (`HardwareTrustRoot`)** :
   - Support abstrait des racines de confiance matérielles : TPM 2.0 (PCR), Intel TDX (Trust Domains), AMD SEV-SNP, ARM CCA (Realms RME) et enclaves souveraines `jambo-tee`.
2. **Preuves d'Intégrité Zero-Knowledge (ZKP) Schnorr / Fiat-Shamir (NIZKPoK)** :
   - Preuve de possession de clés ou de conformité d'état sans divulgation du témoin secret $x$ sur un corps premier 64 bits $p = 2^{64} - 59$ avec générateur multiplicatif $g = 3$.
   - Engagement $t = g^v \pmod p$, Défi Fiat-Shamir $c = H(g \parallel y \parallel t \parallel \text{claim\_digest} \parallel \text{cluster\_challenge}) \pmod{(p - 1)}$, et Réponse $r = (v + c \cdot x) \pmod{(p - 1)}$.
   - Vérification $g^r \equiv t \cdot y^c \pmod p$ sans fuite d'information.
3. **Revendications d'Intégrité Signées (`NodeIntegrityClaim`) & Défi Anti-Rejeu** :
   - Horodatage par époque de grappe, signature HMAC-SHA256 et validation de nonce défi inter-nœuds anti-rejeu.
4. **Confinement Matériel Adaptatif de Grappe (`ConfinementLevel`)** :
   - Niveaux : `Unrestricted` (libre accès réseau/IPC), `Sandboxed` (canaux restreints), `Isolated` (quarantaine mémoire/réseau immédiate), `Ejected` (révocation matérielle définitive).
   - Bascule automatique en état `Quarantined` et confinement `Isolated` dès la détection d'une mesure divergente, d'une signature corrompue ou d'un nonce périmé.
5. **Chaîne d'Audit Cryptographique Inaltérable Scellée par SHA-256 (`audit_chain`)** :
   - Traçabilité complète de l'enregistrement, des revendications, des preuves ZKP et des confinements.
6. **Gouvernance Capabilaire Stricte (`AttestCap`)** :
   - Droits granulaires (`GENERATE_CLAIM`, `VERIFY_CLAIM`, `GENERATE_ZKP`, `VERIFY_ZKP`, `CONFINE_NODE`, `ADMIN`) avec atténuation monotone irréversible et rejet de l'amplification.

## Décision
1. Implémentation de la crate `services/jambo-attest` (`Sha256`, `zkp`, `HardwareTrustRoot`, `NodeStatus`, `ConfinementLevel`, `NodeIntegrityClaim`, `NodeRecord`, `AttestCap`, `JamboAttestDaemon`).
2. Intégration de la commande shell `attest` dans `services/jambo-sh` (`status`, `nodes`, `verify`, `confine`, `rotate`, `audit`).
3. Création de la suite de test d'intégration noyau `kernel/src/sched/attest_test.rs` et inclusion dans `kernel/src/main.rs`.
4. Incrémentation de la version globale vers `v0.2.91` dans tous les `Cargo.toml`.

## Conséquences
- Sécurité renforcée des grappes distribuées JamboOS sans risque d'exfiltration de clés d'attestation grâce aux preuves ZKP.
- Confinement matériel proactif et quarantaine automatique dès détection d'anomalie.
- Validation formelle éprouvée sous QEMU.

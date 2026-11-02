# Conception & Spécification Technique — Jalon 3.29 : Détection et Réponse Étendue Souveraine XDR (Ring 3, PID 34)

> **Version** : v0.3.73  
> **Composant** : `services/jambo-xdr`  
> **Processus Ring 3** : PID 34 (`xdr`)  
> **Statut** : Spécification Technique & Architecture  
> **Date** : Novembre 2026  

---

## 1. Objectifs & Vision Stratégique

Après l'intégration des briques de sécurité souveraines individuelles (WAF L7 PID 30, SIEM PID 31, EDR PID 32, NDR PID 33), le **Jalon 3.29** franchit le cap de l'orchestration unifiée avec **`jambo-xdr`** (PID 34) : le démon souverain de **Détection et Réponse Étendue (Extended Detection & Response - XDR)** de JamboOS.

`jambo-xdr` opère strictement en espace utilisateur (**Ring 3**, CPL 3), en pure `#![no_std]` sans tas (**zero dynamic allocation**), et fusionne la télémétrie multi-vectorielle pour traquer les campagnes d'attaques persistantes avancées (APT) et piloter une remédiation automatisée trans-vectorielle instantanée $O(1)$.

### Piliers Fondamentaux :
1. **Corrélation Multi-Vecteurs & Cartographie MITRE ATT&CK** :
   - Ingestion normalisée depuis 6 vecteurs souverains : Endpoint EDR, Network NDR/VPN, Application WAF, Identity Authd, Cloud Micro-VMM/DFS, Enclaves TEE.
   - Qualification des événements par tactiques MITRE ATT&CK (`InitialAccess`, `Execution`, `LateralMovement`, `EnclaveBreach`, `Exfiltration`, etc.) et scores de menace (0..100).
2. **Graphe de Propagation de Menaces (`ThreatPropagationGraph`) & Détection APT** :
   - Corrélation spatio-temporelle reliant les vecteurs dans une chaîne d'attaque causale.
   - Calcul d'un indice de synergie trans-vectorielle (synergy multiplier avec pénalité TEE).
   - Progression des stades d'attaque : `Reconnaissance` $\rightarrow$ `InitialCompromise` $\rightarrow$ `LateralMovement` $\rightarrow$ `EnclaveBreach` $\rightarrow$ `DataCollection` $\rightarrow$ `Contained`.
3. **Orchestration de Réponse Trans-Vectorielle $O(1)$ (`XdrRemediationReport`)** :
   - Confinement unifié immédiat (`UnifiedQuarantine`) coordonnant simultanément :
     * Isolation d'hôte / processus (EDR)
     * Coupure de route & suspension de tunnel (VPN/NDR)
     * Blocage d'origine applicative (WAF)
     * Révocation de jetons & verrouillage d'identité (Authd)
     * Confinement & purge de secrets d'enclaves compromises (TEE)
   - Rapport déterministe scellé par empreinte SHA-256 avec temps d'exécution mesuré en microsecondes.
4. **Contrôle d'Accès Capabilaire Monotone (`XdrCap`)** :
   - Modèle Zéro-Autorité Ambiante (ZAA).
   - Masque de droits stricts : `INGEST_TELEMETRY`, `CORRELATE_INCIDENTS`, `DETECT_APT_CAMPAIGN`, `CROSS_VECTOR_RESPONSE`, `SEAL_LEDGER`, `AUDIT_READ`, `TEE_ENCLAVE_GUARD`, `ADMIN`.
   - Atténuation strictement irréversible interdisant toute amplification de privilèges.
5. **Registre d'Audit Cryptographique Inviolable SHA-256** :
   - Chaînage d'empreintes SHA-256 `#![no_std]` ancré sur `GENESIS_HASH`.
   - Détection temps-réel de toute altération d'un bloc d'historique.
6. **Protocole IPC Déterministe à 64 Octets** :
   - `XdrRequest` et `XdrResponse` de taille fixe vérifiée à la compilation.

---

## 2. Architecture & Protocole IPC (64 Octets)

Le protocole IPC de `jambo-xdr` est calibré pour le canal FastPath du micro-noyau (64 octets).

### 2.1 Structure `XdrRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdrRequest {
    pub magic: u32,             // 0x58445244 ("XDRD")
    pub opcode: u32,            // Code d'opération XDR
    pub handle_id: u32,         // Identifiant de handle capabilité
    pub rights: u32,            // Masque de droits de la capabilité
    pub campaign_id: u64,       // Identifiant de campagne APT ciblée
    pub response_type: u8,      // Type d'action (0 = None, 1 = Isolate, 2 = Sever, ..., 6 = Unified)
    pub vector: u8,             // Vecteur de télémétrie ciblé
    pub _reserved1: [u8; 2],    // Alignement
    pub epoch: u64,             // Horodatage système / horloge monotone
    pub target_entity: [u8; 28],// Nom de l'entité cible (UTF-8 tronqué)
}
```
*Taille exacte vérifiée : $4 + 4 + 4 + 4 + 8 + 1 + 1 + 2 + 8 + 28 = 64$ octets.*

### 2.2 Structure `XdrResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdrResponse {
    pub magic: u32,             // 0x58445253 ("XDRS")
    pub status: u32,            // Code de statut (0 = Succès, != 0 = XdrError)
    pub total_events: u32,      // Nombre total d'événements ingérés
    pub active_campaigns: u32,  // Nombre de campagnes APT actives
    pub contained_campaigns: u32,// Nombre de campagnes confinées
    pub risk_score: u16,        // Score de risque agrégé (0..1000)
    pub stage: u8,              // Stade de campagne (Recon, Compromise, ...)
    pub status_val: u8,         // Statut de campagne (Active, Contained, ...)
    pub execution_time_us: u32, // Durée d'exécution de remédiation en µs
    pub campaign_id: u64,       // Identifiant de campagne concernée
    pub audit_hash: [u8; 16],   // Préfixe de l'empreinte SHA-256 du grand livre
    pub status_str: [u8; 12],   // Libellé de statut ASCII
}
```
*Taille exacte vérifiée : $4 + 4 + 4 + 4 + 4 + 2 + 1 + 1 + 4 + 8 + 16 + 12 = 64$ octets.*

---

## 3. Intégration Système & Espace Utilisateur

### 3.1 Kernel & Scheduler
- Attribution du PID 34 à `jambo-xdr`.
- Extraction de `/bin/xdr` depuis l'archive initrd TAR.
- Alignement System V ABI (`user_rsp % 16 == 0`), échéance EEVDF `deadline = 1000`.
- Log UART officiel :
  `[PROCESS] Demon Surveillance & Reponse XDR xdr (PID 34) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
- Validation CI des 34 processus Ring 3 et chaîne de confirmation :
  `[PASS] Detection & Reponse Etendue XDR (jambo-xdr PID 34) validee sous QEMU.`

### 3.2 Shell Interactif `jsh`
- Commande native `xdr` avec les sous-commandes :
  - `xdr status` : État global du moteur, événements, campagnes actives, entités confinées, intégrité d'audit SHA-256.
  - `xdr campaigns` : Tableau récapitulatif des campagnes APT (ID, nom, entité cible, vecteurs, stade, risque, statut).
  - `xdr correlate` : Déclenche l'évaluation de corrélation spatio-temporelle et affiche les campagnes détectées.
  - `xdr remediate <id>` : Déclenche le confinement unifié tous vecteurs $O(1)$ pour la campagne et scelle le rapport.
  - `xdr graph [id]` : Affiche les étapes du graphe de propagation de menaces inter-vecteurs.
  - `xdr audit` : Vérification cryptographique de l'intégrité du grand livre SHA-256.
- Extension de la table des processus dans `ps` : affichage des 34 processus actifs.

### 3.3 Chaîne d'Intégration `xtask`
- Compilation bare-metal `services/jambo-xdr` avec cible `x86_64-unknown-none` et script de liaison `libs/user-x86_64.ld`.
- Empaquetage de `bin/xdr` et `xdr` dans `initrd.tar`.
- Mise à jour des bannières disque et des vérifications CI QEMU.

# Conception & Spécification Technique — Jalon 3.28 : Détection et Réponse Réseau Souveraine NDR (Ring 3, PID 33)

> **Version** : v0.3.72  
> **Composant** : `services/jambo-ndr`  
> **Processus Ring 3** : PID 33 (`ndr`)  
> **Statut** : Spécification Technique & Architecture  
> **Date** : Novembre 2026  

---

## 1. Objectifs & Vision Stratégique

Dans la lignée des jalons de sécurité de défense en profondeur (WAF PID 30, SIEM PID 31, EDR PID 32), le **Jalon 3.28** introduit **`jambo-ndr`** (PID 33) : le démon souverain de **Détection et Réponse Réseau (Network Detection & Response)** et de **micro-segmentation dynamique Zero-Trust** de JamboOS.

`jambo-ndr` opère strictement en espace utilisateur non privilégié (**Ring 3**, CPL 3), sans runtime dynamique, sans tas (**pure `#![no_std]` / zero heap**), et s'interface avec les démons `jambo-netd` (VirtIO-Net), `jambo-bpfd` (filtrage XDP) et `jambo-waf` (L7 HTTP) pour garantir l'étanchéité des flux réseau.

### Piliers Fondamentaux :
1. **Surveillance & Analyse de Flux (L2 à L7)** : Suivi d'état des connexions réseau inter-processus et périphériques via un `FlowTracker` déterministe à mémoire statique (`MAX_FLOWS = 64`).
2. **Détection d'Anomalies Comportementales Avancées** :
   - Balisage C2 (*C2 beaconing*) : Détection d'intervalles temporels réguliers (faible gigue / low jitter) entre un service et un nœud distant.
   - Exfiltration massive de données : Détection de dépassement de quotas volumétriques par fenêtre temporelle.
   - Tunneling DNS : Détection de requêtes DNS haute entropie et longueurs anormales via des canaux dissimulés (*covert channels*).
   - Balayage de ports (*Port Scanning*) et reconnaissance réseau furtive.
   - Déplacement latéral non autorisé (*Lateral Movement*) entre zones de sécurité.
3. **Micro-segmentation Dynamique Zero-Trust** :
   - Partitionnement en 6 zones de sécurité distinctes : `ZoneKernel` (Ring 0), `ZoneCoreServices` (Ring 3 privilégié), `ZoneCryptographic` (KMS/TEE), `ZoneUserApps`, `ZoneExternalNetwork` (WAN), `ZoneQuarantine`.
   - Évaluation de politiques matricielles strictes : par défaut, aucun trafic n'est autorisé entre zones non explicitement maillées (*Deny-by-default*).
4. **Confinement & Neutralisation Immédiate $O(1)$** :
   - Isolation instantanée d'un point d'accès ou d'une adresse IP compromise (`quarantine_endpoint`).
   - Coupure immédiate des flux associés et blocage de toute nouvelle tentative de communication (`NdrError::FlowBlocked`).
5. **Contrôle d'Accès Capabilaire Monotone (`NdrCap`)** :
   - Zéro-Autorité Ambiante (ZAA).
   - Masque de droits de surveillance et d'administration avec interdiction formelle d'amplification de privilèges ou d'extension de baux.
6. **Journal d'Audit Cryptographique Inviolable SHA-256** :
   - Chaînage d'empreintes SHA-256 no_std ancré sur `GENESIS_HASH`.
   - Détection instantanée de toute altération de l'historique d'audit.
7. **Protocole IPC Déterministe à 64 Octets** :
   - `NdrRequest` et `NdrResponse` à taille fixe garantie par assertions au moment de la compilation.

---

## 2. Architecture & Protocole IPC (64 Octets)

Le protocole IPC de `jambo-ndr` exploite le canal FastPath du micro-noyau (exactement 64 octets).

### 2.1 Structure `NdrRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NdrRequest {
    pub magic: u32,             // 0x4E445244 ("NDRD")
    pub opcode: u32,            // Code d'opération NDR
    pub handle_id: u32,         // Identifiant de handle capabilité
    pub rights: u32,            // Masque de droits de la capabilité
    pub flow_id: u32,           // Identifiant de flux réseau cible (ou 0)
    pub endpoint_ip: [u8; 4],   // Adresse IPv4 du point d'accès cible
    pub action: u8,             // 0 = Aucun, 1 = Allow, 2 = Deny, 3 = Quarantine
    pub zone: u8,               // Zone de sécurité associée
    pub _reserved1: [u8; 2],    // Alignement
    pub epoch: u64,             // Horodatage système / horloge monotone
    pub reason: [u8; 28],       // Motif textuel UTF-8 ASCII tronqué
}
```
*Taille exacte vérifiée : $4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 2 + 8 + 28 = 64$ octets.*

### 2.2 Structure `NdrResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NdrResponse {
    pub magic: u32,             // 0x4E445253 ("NDRS")
    pub status: u32,            // Code de statut (0 = Succès, != 0 = NdrError)
    pub active_flows: u32,      // Nombre de flux actuellement surveillés
    pub quarantined_count: u32, // Nombre de points d'accès confinés
    pub threats_detected: u32,  // Nombre total d'anomalies/menaces détectées
    pub flow_action: u8,        // Action de filtrage (0 = Allow, 1 = Deny, 2 = Quarantine)
    pub threat_severity: u8,    // Sévérité de la menace (0 = Clean, 1 = Low, ..., 4 = Critical)
    pub _reserved1: [u8; 2],    // Alignement
    pub flow_id: u32,           // Identifiant de flux concerné
    pub audit_hash: [u8; 16],   // Préfixe de l'empreinte SHA-256 du journal d'audit
    pub status_str: [u8; 20],   // Libellé de statut ASCII
}
```
*Taille exacte vérifiée : $4 + 4 + 4 + 4 + 4 + 1 + 1 + 2 + 4 + 16 + 20 = 64$ octets.*

---

## 3. Intégration Système & Espace Utilisateur

### 3.1 Kernel & Scheduler
- Assignation du PID 32 à `jambo-edr`, et promotion de PID 33 à `jambo-ndr`.
- Chargement d'`edr` et `ndr` depuis l'archive initrd TAR.
- Alignement de pile System V ABI (`user_rsp % 16 == 0`), échéance EEVDF `deadline = 1000`.
- Log UART officiel :
  `[PROCESS] Demon Surveillance & Reponse NDR ndr (PID 33) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
- Validation CI des 33 processus Ring 3 et chaîne de confirmation :
  `[PASS] Detection & Reponse Reseau NDR (jambo-ndr PID 33) validee sous QEMU.`

### 3.2 Shell Interactif `jsh`
- Commande native `ndr` avec les sous-commandes :
  - `ndr status` : État global du moteur, flux actifs, anomalies détectées, endpoints confinés, hash d'audit SHA-256.
  - `ndr flows` : Tableau récapitulatif des flux surveillés (ID, source, destination, ports, protocole, état).
  - `ndr inspect <flow_id>` : Analyse détaillée d'un flux (octets, paquets, gigue, sévérité de menace).
  - `ndr isolate <ip>` : Confinement immédiat $O(1)$ d'une adresse IP, révocation des flux et scellement d'audit.
  - `ndr alerts` : Liste des menaces interceptées (balisage C2, exfiltration, DNS tunneling).
  - `ndr audit` : Vérification cryptographique de l'intégrité du journal SHA-256.
- Mise à jour de la table des processus dans `ps` : affichage des 33 processus actifs.

### 3.3 Chaîne d'Intégration `xtask`
- Compilation bare-metal `services/jambo-ndr` avec cible `x86_64-unknown-none` et script de liaison `libs/user-x86_64.ld`.
- Empaquetage de `bin/ndr` et `ndr` dans `initrd.tar`.
- Mise à jour des bannières disque et des vérifications CI QEMU.


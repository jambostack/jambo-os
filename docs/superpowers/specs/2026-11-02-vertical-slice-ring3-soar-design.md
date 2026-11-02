# Conception & Spécification Technique — Jalon 3.30 : Orchestration, Automatisation & Réponse aux Incidents SOAR (Ring 3, PID 35)

> **Version** : v0.3.74  
> **Composant** : `services/jambo-soar`  
> **Processus Ring 3** : PID 35 (`soar`)  
> **Statut** : Spécification Technique & Architecture  
> **Date** : Novembre 2026  

---

## 1. Objectifs & Vision Stratégique

Après l'orchestration multi-vectorielle introduite par XDR (PID 34), le **Jalon 3.30** apporte le couronnement de la posture cyber-résiliente de JamboOS avec **`jambo-soar`** (PID 35) : le démon souverain d'**Orchestration de Sécurité, Automatisation et Réponse aux Incidents (Security Orchestration, Automation and Response - SOAR)**.

`jambo-soar` s'exécute strictement en espace utilisateur (**Ring 3**, CPL 3), en pure `#![no_std]` sans allocation dynamique (**zero heap**), et fournit un moteur déterministe d'exécution de playbooks conditionnels en graphe acyclique dirigé (DAG) pour piloter la remédiation automatique et coordonner l'ensemble des démons de sécurité de l'OS (`walld`, `waf`, `siem`, `edr`, `ndr`, `xdr`, `kdir`, `fdr`).

### Piliers Fondamentaux :
1. **Contrôle d'Accès Capabilaire Strict (`SoarCap`)** :
   - Modèle Zéro-Autorité Ambiante (ZAA).
   - Droits granulaires : `EXECUTE_PLAYBOOK`, `TRIGGER_INCIDENT`, `REGISTER_PLAYBOOK`, `MANAGE_INTEGRATIONS`, `ISOLATE_ENTITY`, `REVOKE_CAPABILITY`, `AUDIT_INSPECT`, `ADMIN`.
   - Atténuation monotone vérifiée sans amplification de privilèges.
2. **Gestion d'Incidents Multi-Sources & Cycle de Vie Typé** :
   - Modélisation typée (`IncidentSeverity`, `IncidentCategory`, `IncidentStatus` : New, InProgress, Mitigated, Closed, Escalated).
   - Ingestion et corrélation automatique vers les playbooks associés avec calcul de l'empreinte cryptographique de l'incident.
3. **Moteur de Playbooks & Workflows DAG (Directed Acyclic Graph)** :
   - Ordonnancement topologique Kahn avec vérification formelle d'absence de cycles.
   - 6 playbooks intégrés par défaut :
     * Atténuation DDoS & filtrage volumétrique (`DdosMitigation`)
     * Neutralisation d'injections WAF & bannissement IP (`WafInjectionResponse`)
     * Révocation d'autorité & confinement capabilaire (`CapabilityRevocation`)
     * Endiguement de fuite de données DLP & assainissement (`DlpLeakContainment`)
     * Réponse aux anomalies comportementales UEBA (`UebaAnomalyResponse`)
     * Restauration de l'intégrité du noyau KDIR depuis Golden Snapshot (`KdirIntegrityRestore`)
   - Actions chirurgicales typées : `BlockIp`, `ApplyRateLimit`, `QuarantineWafPattern`, `RevokeCapability`, `IsolateProcess`, `CaptureMemoryForensics`, `QuarantineEntity`, `RestoreGoldenKernelSnapshot`, `TriggerDlpSanitization`, etc.
4. **Mesure de Performance & Temps Moyen de Réponse (MTTR)** :
   - Évaluation de latence d'exécution sub-milliseconde pour chaque étape de remédiation automatisée.
5. **Grand Livre d'Audit Inviolable Scellé SHA-256** :
   - Chaînage d'empreintes SHA-256 `#![no_std]` ancré sur `GENESIS_HASH`.
6. **Protocole IPC Déterministe à 64 Octets** :
   - `SoarRequest` et `SoarResponse` de taille fixe vérifiée à la compilation.

---

## 2. Architecture & Protocole IPC (64 Octets)

Le protocole IPC de `jambo-soar` exploite le canal FastPath du micro-noyau (64 octets).

### 2.1 Structure `SoarRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoarRequest {
    pub magic: u32,             // 0x534F4152 ("SOAR")
    pub opcode: u32,            // Code d'opération SOAR
    pub handle_id: u32,         // Identifiant de handle capabilité
    pub rights: u32,            // Masque de droits de la capabilité
    pub playbook_id: u32,       // Identifiant du playbook cible
    pub incident_id: u32,       // Identifiant de l'incident cible
    pub action_type: u8,        // Type d'action de remédiation
    pub severity: u8,           // Sévérité de l'incident (Low, Med, High, Crit)
    pub _reserved1: [u8; 2],    // Alignement
    pub epoch: u64,             // Horodatage système / horloge monotone
    pub target_entity: [u8; 28],// Cible de remédiation (UTF-8 tronqué)
}
```
*Taille exacte vérifiée : $4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 2 + 8 + 28 = 64$ octets.*

### 2.2 Structure `SoarResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoarResponse {
    pub magic: u32,             // 0x534F5253 ("SORS")
    pub status: u32,            // Code de statut (0 = Succès, != 0 = SoarError)
    pub total_playbooks: u32,   // Nombre total de playbooks enregistrés
    pub total_incidents: u32,   // Nombre d'incidents gérés
    pub executed_actions: u32,  // Nombre d'actions automatisées exécutées
    pub playbook_id: u32,       // Identifiant de playbook concerné
    pub incident_status: u8,    // Statut de l'incident (New, Mitigated, Closed, etc.)
    pub execution_status: u8,   // Statut de l'exécution (Success, Failed, Skipped)
    pub _reserved1: [u8; 2],    // Alignement
    pub execution_time_us: u32, // Durée d'exécution de la réponse en µs
    pub audit_hash: [u8; 16],   // Préfixe de l'empreinte SHA-256 du grand livre
    pub status_str: [u8; 16],   // Libellé de statut ASCII
}
```
*Taille exacte vérifiée : $4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 2 + 4 + 16 + 16 = 64$ octets.*

---

## 3. Intégration Système & Espace Utilisateur

### 3.1 Kernel & Scheduler
- Attribution du PID 35 à `jambo-soar`.
- Extraction de `/bin/soar` depuis l'archive initrd TAR.
- Alignement System V ABI (`user_rsp % 16 == 0`), échéance EEVDF `deadline = 1000`.
- Log UART officiel :
  `[PROCESS] Demon Surveillance & Reponse SOAR soar (PID 35) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
- Validation CI des 35 processus Ring 3 et chaîne de confirmation :
  `[PASS] Orchestration & Reponse aux Incidents SOAR (jambo-soar PID 35) validee sous QEMU.`

### 3.2 Shell Interactif `jsh`
- Commande native `soar` avec les sous-commandes :
  - `soar status` : État global du moteur, playbooks, incidents actifs/clos, actions exécutées, intégrité d'audit SHA-256.
  - `soar playbooks` : Tableau récapitulatif des playbooks DAG (ID, nom, déclencheur, étapes, statut).
  - `soar trigger <playbook_id>` : Déclenche l'exécution manuelle ou automatisée d'un playbook et affiche le rapport d'étapes.
  - `soar incidents` : Liste des incidents de sécurité (ID, sévérité, catégorie, entité cible, statut, playbook assigné).
  - `soar audit` : Vérification cryptographique de l'intégrité du grand livre SHA-256.
- Extension de la table des processus dans `ps` : affichage des 35 processus actifs.

### 3.3 Chaîne d'Intégration `xtask`
- Compilation bare-metal `services/jambo-soar` avec cible `x86_64-unknown-none` et script de liaison `libs/user-x86_64.ld`.
- Empaquetage de `bin/soar` et `soar` dans `initrd.tar`.
- Mise à jour des bannières disque et des vérifications CI QEMU.

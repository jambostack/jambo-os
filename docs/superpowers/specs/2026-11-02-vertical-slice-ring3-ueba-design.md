# Conception & Spécification Technique — Jalon 3.31 : Analyse Comportementale des Utilisateurs & Entités UEBA (Ring 3, PID 36)

> **Version** : v0.3.75  
> **Composant** : `services/jambo-ueba`  
> **Processus Ring 3** : PID 36 (`ueba`)  
> **Statut** : Spécification Technique & Architecture  
> **Date** : Novembre 2026  

---

## 1. Objectifs & Vision Stratégique

Après l'orchestration et la réponse automatisée aux incidents introduites par `jambo-soar` (PID 35), le **Jalon 3.31** enrichit la cyber-résilience de JamboOS avec **`jambo-ueba`** (PID 36) : le démon souverain d'**Analyse Comportementale des Utilisateurs et des Entités (User and Entity Behavior Analytics - UEBA)**.

`jambo-ueba` s'exécute strictement en espace utilisateur (**Ring 3**, CPL 3), en pure `#![no_std]` sans allocation dynamique (**zero heap**), et fournit un moteur déterministe de profilage statistique continu, d'établissement de profils de référence (*baselines*), de calcul de scores de risque bayésiens dynamiques (0..100) et d'isolation immédiate en $O(1)$ des entités compromises.

### Piliers Fondamentaux :
1. **Contrôle d'Accès Capabilaire Strict (`UebaCap`)** :
   - Modèle Zéro-Autorité Ambiante (ZAA).
   - Droits granulaires : `INGEST_EVENT`, `TRAIN_BASELINE`, `ANALYZE_BEHAVIOR`, `ENFORCE_ACTION`, `QUARANTINE_ENTITY`, `CONFIGURE_MODEL`, `QUERY_METRICS`, `QUERY_AUDIT`, `ADMIN`.
   - Atténuation monotone vérifiée interdisant l'amplification de privilèges.
2. **Profilage Adaptatif & Établissement de Profils de Référence (*Baselines*)** :
   - Profilage multi-entités : Processus système Ring 3, démons de sécurité, utilisateurs logiques et canaux IPC.
   - Métriques multidimensionnelles en virgule fixe sans tas : taux moyen de requêtes, volume moyen d'octets, écart-type, plages horaires habituelles d'activité (masque binaire 24h).
3. **Détection d'Anomalies Comportementales Sans Modèle Lourd** :
   - Détection d'accès hors heures ouvrées (*Off-Hours Activity*).
   - Détection de sauts volumétriques ou de fréquence (*Volume / Frequency Spikes* via z-score en virgule fixe).
   - Détection de mouvements latéraux anormaux (*Lateral Movement* / accès pairs anormaux).
   - Détection d'abus de privilèges et de tentatives d'exfiltration clandestine.
4. **Calcul de Score de Risque Dynamique & Matrice de Sévérité** :
   - Score composite normalisé sur une échelle 0..100 avec classification typée (`RiskLevel::Low`, `Medium`, `High`, `Critical`).
   - Actions de remédiation graduées : `Allow`, `ElevateAudit`, `ThrottleRate`, `Quarantine`.
5. **Table de Quarantaine Immédiate $O(1)$** :
   - Confinement atomique des entités présentant un score de risque critique sans impacter le reste du système.
6. **Grand Livre d'Audit Inviolable Scellé SHA-256** :
   - Chaînage d'empreintes SHA-256 `#![no_std]` ancré sur `GENESIS_HASH`.
7. **Protocole IPC Déterministe à 64 Octets** :
   - Structures `UebaRequest` et `UebaResponse` de taille fixe vérifiée à la compilation.

---

## 2. Architecture & Protocole IPC (64 Octets)

Le protocole IPC de `jambo-ueba` exploite le canal FastPath du micro-noyau (64 octets).

### 2.1 Structure `UebaRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UebaRequest {
    pub magic: u32,             // 0x55454241 ("UEBA")
    pub opcode: u32,            // Code d'opération UEBA (0 = Status, 1 = Ingest, 2 = Analyze, etc.)
    pub handle_id: u32,         // Identifiant de handle capabilité
    pub rights: u32,            // Masque de droits de la capabilité
    pub entity_id: u32,         // Identifiant numérique de l'entité
    pub entity_type: u8,        // Type d'entité (User, Process, ServiceDaemon, NetworkPeer)
    pub event_category: u8,     // Catégorie d'événement (Auth, FileAccess, NetworkFlow, Syscall, Ipc)
    pub hour_of_day: u8,        // Heure de l'événement (0..23)
    pub _reserved1: u8,         // Alignement
    pub epoch: u64,             // Horodatage monotone / horloge système
    pub metric_value: u32,      // Valeur métrique observée (volume octets, fréquence)
    pub threshold: u32,         // Seuil d'anomalie configuré
    pub entity_name: [u8; 24],  // Nom de l'entité (ASCII / UTF-8 tronqué)
}
```
*Taille exacte vérifiée : $4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 8 + 4 + 4 + 24 = 64$ octets.*

### 2.2 Structure `UebaResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UebaResponse {
    pub magic: u32,             // 0x55454253 ("UEBS")
    pub status: u32,            // Code de statut (0 = Succès, != 0 = UebaError)
    pub total_entities: u32,    // Nombre d'entités profilées
    pub total_events: u32,      // Nombre total d'événements ingérés
    pub total_anomalies: u32,   // Nombre d'anomalies détectées
    pub quarantined_count: u32, // Nombre d'entités en quarantaine
    pub risk_score: u8,         // Score de risque dynamique calculé (0..100)
    pub risk_level: u8,         // Niveau de risque (0=Low, 1=Medium, 2=High, 3=Critical)
    pub recommended_action: u8, // Action recommandée (Allow, ElevateAudit, ThrottleRate, Quarantine)
    pub is_quarantined: u8,     // Indicateur booléen de quarantaine (0 ou 1)
    pub anomaly_type: u8,       // Type d'anomalie dominant détecté
    pub _reserved1: [u8; 3],    // Alignement
    pub audit_hash: [u8; 16],   // Préfixe de l'empreinte SHA-256 du grand livre d'audit
    pub status_str: [u8; 16],   // Libellé de statut ASCII
}
```
*Taille exacte vérifiée : $4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 1 + 3 + 16 + 16 = 64$ octets.*

---

## 3. Intégration Système & Espace Utilisateur

### 3.1 Kernel & Scheduler
- Attribution du PID 36 à `jambo-ueba`.
- Extraction de `/bin/ueba` depuis l'archive initrd TAR.
- Alignement System V ABI (`user_rsp % 16 == 0`), échéance EEVDF `deadline = 1000`.
- Log UART officiel :
  `[PROCESS] Demon Analyse Comportementale UEBA ueba (PID 36) initialise avec pile System V ABI (RSP: {:#018x}) et enfile`
- Validation CI des 36 processus Ring 3 et confirmation :
  `[PASS] Analyse Comportementale UEBA (jambo-ueba PID 36) validee sous QEMU.`

### 3.2 Shell Interactif `jsh`
- Commande native `ueba` avec les sous-commandes :
  - `ueba status` : Affiche l'état global, nombre d'entités, événements, anomalies, entités en quarantaine, intégrité d'audit SHA-256.
  - `ueba profile <name>` : Affiche le profil de référence d'une entité (moyenne, écart-type, heures autorisées, score de risque).
  - `ueba anomalies` : Affiche la liste des anomalies comportementales détectées.
  - `ueba score <entity_id>` : Calcule et affiche le score de risque dynamique et l'action recommandée.
  - `ueba quarantine <entity_id>` : Isole immédiatement une entité dans la table de quarantaine $O(1)$.
  - `ueba audit` : Vérifie l'intégrité cryptographique du grand livre d'audit SHA-256.
- Extension de la table des processus dans `ps` : affichage des 36 processus actifs.

### 3.3 Chaîne d'Intégration `xtask`
- Compilation bare-metal `services/jambo-ueba` avec cible `x86_64-unknown-none` et script de liaison `libs/user-x86_64.ld`.
- Empaquetage de `bin/ueba` et `ueba` dans `initrd.tar`.
- Mise à jour des bannières disque et des vérifications CI QEMU.


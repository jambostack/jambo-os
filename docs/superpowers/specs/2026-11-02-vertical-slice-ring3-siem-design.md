# Spécification de Conception — Jalon 3.26 (v0.3.70)
# `jambo-siem` : Corrélation d'Événements de Sécurité Distribuée & Moteur SIEM Temps Réel (PID 31)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.26 (`v0.3.70`)** dote **JamboOS** de son **31ᵉ processus en espace utilisateur Ring 3** : **`jambo-siem`** sous le **PID 31**.

Dans une infrastructure distribuée à micro-noyau et confiance zéro (*Zero-Trust*), chaque sous-système de sécurité génère des flux d'événements spécialisés : le pare-feu réseau (`jambo-walld`), le pare-feu applicatif L7 (`jambo-waf`), l'audit inaltérable (`jambo-auditd`), le gestionnaire d'identité (`jambo-authd`), l'attestation cryptographique (`jambo-attest`) ou le confinement forensique (`jambo-forensics`). Cependant, les attaques contemporaines les plus dévastatrices (attaques ciblées persistantes - APT, mouvements latéraux, exfiltration lente, élévation furtive de privilèges) fragmentent leurs signaux faibles sur plusieurs plans d'exécution et plusieurs couches protocolaires. Sans corrélation temps réel centralisée, ces attaques passent inaperçues.

`jambo-siem` implémente un système souverain de gestion des informations et des événements de sécurité (SIEM) entièrement durci en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Contrôle d'Accès Capabilaire Strict (`SiemCap`)** :
   - Zéro autorité ambiante (*Zero-Ambient Authority*).
   - Droits atomiques : `INGEST`, `CORRELATE`, `QUERY`, `ALERT`, `EXPORT`, `ADMIN`.
   - Atténuation monotone irréversible empêchant toute escalade de privilèges.
2. **Ingestion Multi-Sources & Schéma Normalisé (CEF/OCSF)** :
   - Normalisation d'événements hétérogènes (`SecurityEvent`) : horodatage monotone, identifiant unique, source (`Walld`, `Waf`, `Auditd`, `Authd`, `Attest`, `Kms`, etc.), catégorie taxonomique (`Authentication`, `Network`, `Process`, `File`, `Vulnerability`), sévérité (`Informational`, `Low`, `Medium`, `High`, `Critical`), et message contextuel borné (`FIELD_LEN = 64`).
3. **Anneau Circulaire d'Événements Lockless Haute Performance** :
   - Tampon circulaire statique (`EVENT_RING_SIZE = 256`) avec ingestion en temps constant $O(1)$ sans verrouillage bloquant.
   - Indexation chronologique et filtrage par masque de critères.
4. **Moteur de Corrélation en Fenêtres Temporelles Glissantes** :
   - Fenêtre glissante bornée (`WINDOW_SIZE = 64`) avec détection d'attaques multi-étapes :
     - *Brute Force Authentication* : échecs répétés d'authentification inter-nœuds.
     - *Lateral Movement* : traversée non autorisée de segments réseau de grappe.
     - *Privilege Escalation* : abus de capabilités ou tentatives d'accès non autorisées.
     - *Data Exfiltration* : transferts volumétriques anormaux ou fuite de secrets.
     - *C2 Beacon* : motifs périodiques suspects vers des nœuds non vérifiés.
     - *APT Multi-Stage* : corrélation conjointe d'injections WAF, échecs d'authentification et alertes d'intégrité TPM.
   - Calcul de score composite de menace (0 à 100) avec agrégation pondérée.
5. **Gestionnaire d'Alertes Dédupliquées & Cycle de Vie d'Incident** :
   - File de priorité bornée (`MAX_ALERTS = 128`) avec empreinte de déduplication SHA-256 (`fingerprint`).
   - Machine à états finis d'alerte : `New` → `Acknowledged` → `InvestigationInProgress` → `Resolved` / `FalsePositive`.
6. **Grand Livre d'Audit Cryptographique Inaltérable** :
   - Chaîne de hachage SHA-256 séquentielle (`audit_chain`) scellant chaque opération critique du SIEM.
7. **Protocole IPC Déterministe à 64 Octets** :
   - Messages `SiemRequest` et `SiemResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`SiemOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemOpcode {
    GetStatus = 1,
    IngestEvent = 2,
    RunCorrelation = 3,
    GetAlerts = 4,
    GetRules = 5,
    GetAudit = 6,
}
```

### 2.2 Droits de Capabilités (`SiemCap`)

```rust
pub mod siem_rights {
    pub const INGEST: u32 = 1 << 0;
    pub const CORRELATE: u32 = 1 << 1;
    pub const QUERY: u32 = 1 << 2;
    pub const ALERT: u32 = 1 << 3;
    pub const EXPORT: u32 = 1 << 4;
    pub const ADMIN: u32 = 1 << 5;

    pub const ALL: u32 = INGEST | CORRELATE | QUERY | ALERT | EXPORT | ADMIN;
}
```

### 2.3 Structure `SiemRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiemRequest {
    pub magic: u32,               // 0x5349454D ("SIEM")
    pub opcode: u32,              // SiemOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits SiemCap
    pub event_source: u8,         // Source (0: Walld, 1: Waf, 2: Auditd, etc.)
    pub event_category: u8,       // Catégorie (0: Auth, 1: Network, etc.)
    pub severity: u8,             // Sévérité (0: Info, 1: Low, etc.)
    pub _reserved1: u8,           // Alignement
    pub epoch: u64,               // Époque d'horodatage
    pub message: [u8; 36],        // Extrait de message normalisé
}

const _: () = assert!(core::mem::size_of::<SiemRequest>() == 64);
```

### 2.4 Structure `SiemResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiemResponse {
    pub magic: u32,               // 0x53494552 ("SIER")
    pub status: i32,              // 0 = Succès, < 0 = SiemError
    pub total_events: u32,        // Total d'événements ingérés
    pub total_alerts: u32,        // Total d'alertes générées
    pub active_rules: u32,        // Nombre de règles actives
    pub correlated_count: u32,    // Nombre d'événements corrélés
    pub threat_score: u32,        // Score de menace composite (0-100)
    pub top_severity: u8,         // Sévérité maximale courante (0..4)
    pub _reserved1: [u8; 3],      // Alignement
    pub audit_hash: [u8; 16],     // Empreinte SHA-256 tronquée de la chaîne d'audit
    pub status_str: [u8; 16],     // Chaîne d'état ASCII ("NORMAL", "THREAT_HIGH", etc.)
}

const _: () = assert!(core::mem::size_of::<SiemResponse>() == 64);
```

---

## 3. Intégration dans le Shell `jsh`

Le shell `jsh` intègre la commande native `siem` :
- `siem status` (ou `siem`) : Affiche le bilan d'activité du SIEM, total d'événements, alertes générées, règles actives, score composite de menace (0-100), niveau de sévérité maximale et empreinte d'audit SHA-256.
- `siem ingest <source> <cat> <sev> <msg>` : Simule l'ingestion d'un événement de sécurité normalisé et actualise l'anneau circulaire.
- `siem alerts` : Liste les alertes de sécurité prioritaires dans la file avec ID, règle déclenchée, sévérité, score de menace et statut d'enquête.
- `siem correlate` : Déclenche un cycle d'évaluation des règles de corrélation sur la fenêtre temporelle glissante et affiche les règles déclenchées.
- `siem rules` : Liste les règles de corrélation configurées (Brute Force, Lateral Movement, Privilege Escalation, Data Exfiltration, C2 Beacon, APT Multi-Stage).
- `siem audit` : Affiche l'historique récent des événements de sécurité scellés et l'empreinte de la chaîne d'audit.

La commande `ps` liste les **31 processus actifs** incluant :
```text
31 | siem | Ring 3 | Ready | 1000 | Security Information & Event Management
```

---

## 4. Intégration Noyau & Pipeline `xtask`

- `kernel/src/main.rs` :
  - Extraction de `/bin/siem` depuis l'archive TAR `initrd`.
  - Spawning du processus utilisateur PID 31 `siem`.
  - Validation de l'alignement de pile System V ABI (`RSP % 16 == 0`).
  - Deadline EEVDF fixée à 1000.
  - Assertions CI validant 31 processus et émission de la ligne PASS officielle :
    `[PASS] Moteur SIEM & Correlation Evenements (jambo-siem PID 31) validee sous QEMU.`
- `xtask/src/main.rs` :
  - Compilation bare-metal `build_siem()` pour `x86_64-unknown-none`.
  - Extension de `build_userland()` au 31-uplet.
  - Empaquettage de `bin/siem` dans `initrd.tar`.
  - Validation de la chaîne PASS sous QEMU.


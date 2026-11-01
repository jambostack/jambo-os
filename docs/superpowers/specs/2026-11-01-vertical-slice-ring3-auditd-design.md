# Spécification de Conception — Jalon 3.13 (v0.3.57)
# `jambo-auditd` : Audit Cryptographique Inaltérable & Observabilité Zéro-Autorité (PID 18)

## 1. Contexte et Objectifs

`jambo-auditd` est le démon d'audit de sécurité et de journalisation cryptographique souverain de JamboOS. Il implémente un registre d'audit inviolable (*tamper-evident ledger*) en espace utilisateur Ring 3, scellé séquentiellement par une chaîne de hachage déterministe (SIP/FNV-BLAKE dérivé). 

L'accès à l'écriture et à la lecture du registre d'audit requiert obligatoirement une capacité explicite `AuditCap` (masque de catégories autorisées et seuil de sévérité minimal), garantissant l'éradication totale de toute autorité ambiante. Le démon intègre également un moteur heuristique de détection d'anomalies de sécurité en temps réel (dépassements de seuils, attaques par rejeu, violations répétées de mémoire ou de capacités).

**Rôle dans l'architecture** : PID 18, Ring 3, cible `x86_64-unknown-none`, `#![no_std]`, `#![no_main]`, zéro heap (aucun allocateur dynamique).

---

## 2. Protocole IPC (64 octets exactement)

Le protocole IPC de communication avec `jambo-auditd` est déterministe et calibré exactement sur 64 octets pour les requêtes et les réponses.

### Opcodes IPC (`AuditOpcode`)

| Valeur | Identifiant        | Description                                                          |
|--------|--------------------|----------------------------------------------------------------------|
| `1`    | `GetStatus`        | Lecture de l'état du registre (total, dernier hash, alertes actives) |
| `2`    | `RecordEvent`      | Enregistrement scellé d'un événement de sécurité                     |
| `3`    | `VerifyIntegrity`  | Vérification formelle de la chaîne cryptographique complète          |
| `4`    | `QueryLatest`      | Lecture de la dernière entrée scellée du registre                   |
| `5`    | `ScanAnomalies`    | Analyse heuristique des anomalies et détection d'attaques            |

---

### `AuditRequest` — 64 octets

| Champ          | Type      | Offset | Taille | Description                                            |
|----------------|-----------|--------|--------|--------------------------------------------------------|
| `magic`        | `u32`     | 0      | 4      | Nombre magique de validation : `0x41554454` (`"AUDT"`) |
| `opcode`       | `u32`     | 4      | 4      | Opcode : 1=GetStatus, 2=RecordEvent, 3=Verify, etc.   |
| `handle_id`    | `u32`     | 8      | 4      | Identifiant du handle de la capacité `AuditCap`        |
| `handle_flags` | `u32`     | 12     | 4      | Drapeaux du handle de la capacité                      |
| `allowed_mask` | `u32`     | 16     | 4      | Masque de catégories autorisées (`AuditCategory`)      |
| `category`     | `u8`      | 20     | 1      | Catégorie de l'événement (1..6)                        |
| `severity`     | `u8`      | 21     | 1      | Sévérité de l'événement (1..5)                         |
| `min_severity` | `u8`      | 22     | 1      | Sévérité minimale autorisée par la capacité            |
| `details_len`  | `u8`      | 23     | 1      | Longueur du texte du payload de détails (0..32)        |
| `source_pid`   | `u32`     | 24     | 4      | PID source à l'origine de l'événement                  |
| `event_code`   | `u32`     | 28     | 4      | Code numérique de l'événement                          |
| `details`      | `[u8; 32]`| 32     | 32     | Payload textuel ou binaire de l'événement (32 octets)  |

**Total** : 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 1 + 4 + 4 + 32 = **64 octets** ✅

---

### `AuditResponse` — 64 octets

| Champ                  | Type      | Offset | Taille | Description                                             |
|------------------------|-----------|--------|--------|---------------------------------------------------------|
| `magic`                | `u32`     | 0      | 4      | Nombre magique de réponse : `0x41554453` (`"AUDS"`)     |
| `status`               | `i32`     | 4      | 4      | Statut de l'opération (0 = Succès, < 0 = `SysError`)    |
| `total_recorded`       | `u64`     | 8      | 8      | Nombre total d'événements enregistrés dans l'anneau     |
| `last_seq`             | `u64`     | 16     | 8      | Numéro de séquence de la dernière entrée scellée        |
| `last_hash`            | `[u8; 16]`| 24     | 16     | Empreinte cryptographique courante de la chaîne         |
| `anomaly_type`         | `u8`      | 40     | 1      | Type d'anomalie détectée (0=Aucune, 1=Cap, 2=Rpc, 3=Mem)|
| `alert_incident_count` | `u8`      | 41     | 1      | Compteur d'incidents déclencheurs d'alerte              |
| `integrity_ok`         | `u8`      | 42     | 1      | Booléen d'intégrité globale (1 = Intègre, 0 = Altéré)   |
| `_pad`                 | `u8`      | 43     | 1      | Alignement strict sur 4 octets                          |
| `suspect_pid`          | `u32`     | 44     | 4      | PID suspect identifié par le détecteur d'anomalies      |
| `details`              | `[u8; 16]`| 48     | 16     | Aperçu textuel ou métadonnées de la dernière entrée     |

**Total** : 4 + 4 + 8 + 8 + 16 + 1 + 1 + 1 + 1 + 4 + 16 = **64 octets** ✅

---

### Assertions statiques à la compilation

```rust
const _: () = {
    assert!(core::mem::size_of::<AuditRequest>() == 64);
    assert!(core::mem::size_of::<AuditResponse>() == 64);
};
```

---

## 3. Architecture du Démon `jambo-auditd` (`src/main.rs`)

```
_start()
  └── JamboAuditDaemon::new()
  └── [AUTO-TEST INTÉGRÉ AU DÉMARRAGE]
        ├── Test 1 : Vérification de la graine d'initialisation (0x5A..5A)
        ├── Test 2 : Enregistrement de 3 événements fondamentaux (CSpace, MMU, IOMMU)
        ├── Test 3 : Vérification formelle de la chaîne cryptographique (100% Intègre)
        ├── Test 4 : Simulation de falsification mémoire et détection d'altération
        └── Test 5 : Détection heuristique d'anomalies de sécurité (seuil de violations)
  └── Affichage du statut d'auto-test UART COM1
  └── Canal IPC (Endpoint PID 18) :
        ├── ChannelRead(18) -> AuditRequest
        ├── handle_ipc_request(&req) -> AuditResponse
        ├── ChannelWrite(client)
        └── sys_thread_yield()
```

---

## 4. Commandes Shell `jsh` (`services/jambo-sh`)

Le shell modulaire `jsh` intègre le sous-système `audit` :

- `audit status` : Affiche l'état du grand livre (total d'événements, dernier hash, statut d'intégrité, alertes).
- `audit record <cat> <sev> <msg>` : Enregistre un nouvel événement d'audit scellé.
- `audit verify` : Vérifie l'intégrité mathématique de l'intégralité de la chaîne d'audit.
- `audit tail` : Affiche la dernière entrée enregistrée.
- `audit scan` : Déclenche une analyse heuristique pour détecter des anomalies de comportement.
- `ps` : Mise à jour du listing pour 18 processus Ring 3 (`/bin/auditd` PID 18, `RUNNING`, priorité 1000).

---

## 5. Ordonnancement & Matrice de Déploiement

| Attribut                | Spécification                                      |
|-------------------------|----------------------------------------------------|
| **PID**                 | 18                                                 |
| **Binaire initrd**      | `/bin/auditd` et `/bin/jambo-auditd`               |
| **Niveau de Privilège** | Ring 3 (CPL 3, User Mode)                          |
| **Alignement Pile**     | System V ABI (`RSP % 16 == 0`)                     |
| **Ordonnanceur**        | EEVDF (Deadline 1000)                              |
| **Validation QEMU**     | Exit code 33 (`isa-debug-exit`) avec message PASS  |

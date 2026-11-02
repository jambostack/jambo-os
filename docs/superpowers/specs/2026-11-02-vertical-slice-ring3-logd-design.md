# Spécification de Conception — Jalon 3.22 (v0.3.66)
# `jambo-logd` : Journalisation Structurée, Chaînage Cryptographique Inviolable & Observabilité Haute Précision (PID 27)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.22 (`v0.3.66`)** dote **JamboOS** de son **27ᵉ processus en espace utilisateur Ring 3** : **`jambo-logd`** sous le **PID 27**.

Dans un système distribué à micro-noyau et sécurité souveraine, la journalisation ne peut être un simple flux texte non ordonné ni un fichier plat modifiable sans preuve. Toute tentative d'effacement de traces, de falsification rétroactive ou d'injection de fausses entrées compromet la confiance d'investigation post-incident (*forensics*).

`jambo-logd` apporte un sous-système de journalisation structurée immuable, circulaire et scellé cryptographiquement en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Anneau Circulaire Borné en Mémoire Statique (`RING_BUFFER_CAPACITY = 64`)** : Stockage déterministe en mémoire vive sans risque d'épuisement mémoire (`OutOfMemory`), avec écrasement circulaire des plus anciennes entrées et comptage monotone global des identifiants (`next_id`).
2. **Chaînage Cryptographique Inviolable (*Tamper-evident Hash Chain*)** : Chaque entrée de journal intègre et scelle cryptographiquement l'empreinte de l'entrée précédente depuis la graine initiale (`GENESIS_HASH = [0x5au8; 32]`). Toute modification d'un octet dans l'historique invalide instantanément la chaîne lors de la vérification.
3. **Niveaux de Sévérité & Sous-Systèmes Structurés** : Six niveaux stricts (`Trace = 0`, `Debug = 1`, `Info = 2`, `Warn = 3`, `Error = 4`, `Fatal = 5`) et partitionnement par sous-système identifié (jusqu'à 16 octets).
4. **Vérification d'Intégrité Complète en Temps Linéaire $O(N)$** : Parcours et recomposition de la chaîne de hachage permettant de confirmer la non-répudiation et l'absence d'altération.
5. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (écriture, lecture, requête, vidage, audit) sont régies par des capacités explicites `LogCap` (`LOG_READ`, `LOG_WRITE`, `LOG_QUERY`, `LOG_FLUSH`, `LOG_ARCHIVE`, `LOG_EXPORT`, `LOG_ADMIN`).
6. **Protocole IPC Déterministe à 64 Octets** : Messages `LogRequest` et `LogResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`LogOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOpcode {
    GetStatus = 1,
    AppendRecord = 2,
    QueryLast = 3,
    VerifyChain = 4,
    ClearLogs = 5,
}
```

### 2.2 Droits de Capabilités (`LogCap`)

```rust
pub mod log_rights {
    pub const LOG_READ: u32 = 0x01;
    pub const LOG_WRITE: u32 = 0x02;
    pub const LOG_QUERY: u32 = 0x04;
    pub const LOG_FLUSH: u32 = 0x08;
    pub const LOG_ARCHIVE: u32 = 0x10;
    pub const LOG_EXPORT: u32 = 0x20;
    pub const LOG_ADMIN: u32 = 0x80;
    pub const ALL: u32 =
        LOG_READ | LOG_WRITE | LOG_QUERY | LOG_FLUSH | LOG_ARCHIVE | LOG_EXPORT | LOG_ADMIN;
}
```

### 2.3 Structure `LogRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRequest {
    pub magic: u32,               // 0x4C4F4744 ("LOGD")
    pub opcode: u32,              // LogOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits LogCap
    pub level: u8,                // Niveau LogLevel (0..5)
    pub _reserved1: u8,           // Alignement
    pub _reserved2: u16,          // Alignement
    pub subsystem: [u8; 16],      // Sous-système émetteur (ex: "kernel", "secboot")
    pub message: [u8; 32],        // Message textuel du journal
}

const _: () = assert!(core::mem::size_of::<LogRequest>() == 64);
```

### 2.4 Structure `LogResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogResponse {
    pub magic: u32,               // 0x4C4F4753 ("LOGS")
    pub status: i32,              // 0 = Succès, < 0 = SysError
    pub record_id: u64,           // ID unique monotone de l'entrée générée/lue
    pub total_records: u32,       // Nombre total d'entrées actuellement en mémoire
    pub chain_verified: u32,      // 1 = Chaîne intègre, 0 = Falsifiée / altérée
    pub level: u8,                // Niveau de la dernière entrée inspectée
    pub _reserved1: u8,           // Alignement
    pub _reserved2: u16,          // Alignement
    pub last_entry_hash: [u8; 16],// Empreinte tronquée de l'entrée scellée
    pub status_str: [u8; 20],     // Statut lisible ("RECORDED", "VERIFIED", etc.)
}

const _: () = assert!(core::mem::size_of::<LogResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-logd` (PID 27)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie le gestionnaire de journalisation `LogDaemon::new()`.
- Initialise les entrées d'amorçage initiales (`init_defaults()` : logs de boot pour `kernel`, `init`, `jsh`).
- Exécute une séquence complète d'auto-test au démarrage :
  1. Vérification de l'intégrité de la chaîne cryptographique initiale (`verify_chain() -> true`).
  2. Écriture d'un message structuré `[INFO] netd: VirtIO-Net 1.2 link UP`.
  3. Vérification de la mise à jour de l'empreinte et de la chaîne de hachage.
  4. Confirmation que la vérification cryptographique continue de valider l'intégrité de bout en bout.
- Enregistre son canal de communication IPC sous l'endpoint 27 via `syscall_ipc_register_endpoint(27)`.
- Boucle coopérative de réception des requêtes IPC et `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `log` avec les commandes suivantes :
- `log status` : Affiche l'état du démon de journalisation, le total d'entrées et la vérification de la chaîne.
- `log append <level> <subsys> <msg>` : Enregistre une nouvelle entrée de journal structurée.
- `log tail [n]` : Affiche les `n` dernières entrées du tampon circulaire avec niveau et sous-système.
- `log verify` : Vérifie l'intégrité cryptographique de l'ensemble de la chaîne de journalisation.
- `log clear` : Réinitialise le tampon circulaire et régénère l'ancre `GENESIS_HASH`.
- Commande `ps` : Mise à jour de la table des processus pour lister **27 processus actifs**.

---

## 5. Intégration Noyau & Pipeline de Construction

- **Micro-Noyau (`kernel/src/main.rs`)** :
  - Extraction du binaire `/bin/logd` depuis l'archive TAR initrd.
  - Instanciation du processus `logd` sous le PID 27.
  - Respect strict de l'ABI System V x86-64 : alignement de la pile utilisateur `RSP % 16 == 0`.
  - Enregistrement dans l'ordonnanceur EEVDF avec deadline 1000.
  - Message de boot : `[OK] Ring 3 logd daemon running (PID 27, Structured Logging & Tamper-Evident Hash Chain)`.
- **Orchestrateur `xtask` (`xtask/src/main.rs`)** :
  - Compilation du binaire `logd` en mode bare-metal `x86_64-unknown-none`.
  - Intégration dans le tuple de 27 binaires utilisateur pour la génération de l'archive `initrd.img`.
  - Vérification automatisée dans `run_test` du message officiel QEMU.

# Spécification de Conception — Jalon 3.23 (v0.3.67)
# `jambo-kms` : Gestionnaire et Séquestre de Clés Cryptographiques de Grappe (PID 28)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.23 (`v0.3.67`)** dote **JamboOS** de son **28ᵉ processus en espace utilisateur Ring 3** : **`jambo-kms`** sous le **PID 28**.

Dans une infrastructure distribuée à micro-noyau et confiance zéro (*Zero-Trust*), la gestion décentralisée des clés de chiffrement de stockage, de transport et d'identité représente le pivot de sécurité le plus critique. L'éparpillement des clés en mémoire vive, l'absence de baux temporels stricts ou l'impossibilité de révoquer et zéroïser une clé instantanément exposent le système à des attaques par vol de mémoire volatile (*cold boot*, compromission d'enclave).

`jambo-kms` implémente un système complet de gestion de clés conforme NIST SP 800-108 et HKDF RFC 5869 en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Hiérarchie Cryptographique à 4 Niveaux** :
   - `MasterKey` (Niveau 0) : Racine de confiance inviolable de la grappe.
   - `DomainKey` (Niveau 1) : Clé de partitionnement de domaine / sous-système.
   - `DataKey` (Niveau 2) : Clé de chiffrement effectif de données et blocs disque.
   - `SessionKey` (Niveau 3) : Clé éphémère de session inter-processus.
   - `EscrowKey` : Clé séquestrée de secours d'urgence.
2. **Dérivation Déterministe HKDF (RFC 5869 / SHA-256)** : Dérivation cryptographique non-inversible garantissant l'indépendance des clés dérivées même en cas de compromission d'une clé fille.
3. **Baux Temporels & Quotas d'Utilisation Bornés** : Attribution de baux d'opération (`OP_ENCRYPT`, `OP_DECRYPT`, `OP_SIGN`, `OP_DERIVE`) régis par des compteurs d'opérations autorisées (`max_ops`) et une fenêtre de validité (`valid_until_ticks`).
4. **Zéroïsation Volatile Mémoire Garantie** : Effacement sécurisé (`write_volatile`, `compiler_fence`) des secrets cryptographiques lors de la destruction ou révocation d'une clé.
5. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (création, dérivation, bail, rotation, révocation, audit) sont soumises à la détention d'une capacité explicite `KmsCap` (`CREATE_KEY`, `DERIVE_KEY`, `GRANT_LEASE`, `RENEW_LEASE`, `ESCROW_KEY`, `ROTATE_KEY`, `REVOKE_KEY`, `ZEROIZE_KEY`, `AUDIT_LOG`).
6. **Protocole IPC Déterministe à 64 Octets** : Messages `KmsRequest` et `KmsResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`KmsOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsOpcode {
    GetStatus = 1,
    CreateKey = 2,
    DeriveKey = 3,
    GrantLease = 4,
    RotateKey = 5,
    RevokeKey = 6,
}
```

### 2.2 Droits de Capabilités (`KmsCap`)

```rust
pub mod kms_rights {
    pub const CREATE_KEY: u32 = 1 << 0;
    pub const DERIVE_KEY: u32 = 1 << 1;
    pub const GRANT_LEASE: u32 = 1 << 2;
    pub const RENEW_LEASE: u32 = 1 << 3;
    pub const ESCROW_KEY: u32 = 1 << 4;
    pub const ROTATE_KEY: u32 = 1 << 5;
    pub const REVOKE_KEY: u32 = 1 << 6;
    pub const ZEROIZE_KEY: u32 = 1 << 7;
    pub const AUDIT_LOG: u32 = 1 << 8;
    pub const ADMIN: u32 = 0x8000;
    pub const ALL: u32 = (1 << 9) - 1 | ADMIN;
}
```

### 2.3 Structure `KmsRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KmsRequest {
    pub magic: u32,               // 0x4B4D5344 ("KMSD")
    pub opcode: u32,              // KmsOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits KmsCap
    pub key_id: u32,              // Identifiant de clé cible
    pub parent_key_id: u32,       // Clé parente pour dérivation
    pub key_type: u8,             // 0 = Master, 1 = Domain, 2 = Data, 3 = Session, 4 = Escrow
    pub algorithm: u8,            // 0 = ChaCha20, 1 = AES-256, 2 = HMAC-SHA256, 3 = Ed25519
    pub _reserved1: u16,          // Alignement
    pub lease_ops: u32,           // Masque d'opérations autorisées
    pub validity_ticks: u64,      // Durée du bail en ticks
    pub key_name: [u8; 24],       // Nom identifiant la clé
}

const _: () = assert!(core::mem::size_of::<KmsRequest>() == 64);
```

### 2.4 Structure `KmsResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KmsResponse {
    pub magic: u32,               // 0x4B4D5353 ("KMSS")
    pub status: i32,              // 0 = Succès, < 0 = SysError
    pub key_id: u32,              // ID de clé créée ou inspectée
    pub lease_id: u32,            // ID de bail accordé
    pub total_keys: u32,          // Total de clés actives
    pub active_leases: u32,       // Total de baux actifs
    pub key_version: u32,         // Version de la clé
    pub state: u8,                // État de cycle de vie (Active, Revoked, etc.)
    pub _reserved1: u8,           // Alignement
    pub _reserved2: u16,          // Alignement
    pub key_hash: [u8; 16],       // Empreinte SHA-256 tronquée de la clé
    pub status_str: [u8; 16],     // "ACTIVE", "REVOKED", "DESTROYED", etc.
}

const _: () = assert!(core::mem::size_of::<KmsResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-kms` (PID 28)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie le gestionnaire de clés `KmsManager::new()`.
- Initialise les clés racine fondamentales (`init_defaults()` : `cluster-root-kek`, `storage-domain-kek`, `net-session-key`).
- Exécute une séquence complète d'auto-test au démarrage :
  1. Vérification de la clé racine `cluster-root-kek` (Niveau 0).
  2. Dérivation d'une sous-clé de domaine `vault-kek` via HKDF-SHA256.
  3. Octroi d'un bail temporel borné (50 opérations de chiffrement/déchiffrement).
  4. Révocation de la clé et confirmation de la zéroïsation mémoire immédiate.
- Enregistre son canal de communication IPC sous l'endpoint 28 via `syscall_ipc_register_endpoint(28)`.
- Boucle coopérative de réception des requêtes IPC et `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `kms` avec les commandes suivantes :
- `kms status` : Affiche l'état du KMS, le nombre de clés actives et de baux en cours.
- `kms list` : Liste les clés actives avec ID, nom, type, version et état.
- `kms create <type> <name>` : Crée une nouvelle clé cryptographique souveraine.
- `kms derive <parent_id> <name>` : Dérive une clé fille hiérarchique via HKDF.
- `kms lease <key_id> <ops>` : Accorde un bail temporel d'opérations sur une clé.
- `kms rotate <key_id>` : Effectue la rotation atomique d'une clé vers une nouvelle version.
- `kms revoke <key_id>` : Révoque et zéroïse immédiatement une clé en mémoire.
- Commande `ps` : Mise à jour de la table des processus pour lister **28 processus actifs**.

---

## 5. Intégration Noyau & Pipeline de Construction

- **Micro-Noyau (`kernel/src/main.rs`)** :
  - Extraction du binaire `/bin/kms` depuis l'archive TAR initrd.
  - Instanciation du processus `kms` sous le PID 28.
  - Respect strict de l'ABI System V x86-64 : alignement de la pile utilisateur `RSP % 16 == 0`.
  - Enregistrement dans l'ordonnanceur EEVDF avec deadline 1000.
  - Message de boot : `[OK] Ring 3 kms daemon running (PID 28, Key Management Service & HKDF Derivation)`.
- **Orchestrateur `xtask` (`xtask/src/main.rs`)** :
  - Compilation du binaire `kms` en mode bare-metal `x86_64-unknown-none`.
  - Intégration dans le tuple de 28 binaires utilisateur pour la génération de l'archive `initrd.img`.
  - Vérification automatisée dans `run_test` du message officiel QEMU.

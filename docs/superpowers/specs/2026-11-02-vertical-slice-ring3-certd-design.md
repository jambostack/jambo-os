# Spécification de Conception — Jalon 3.19 (v0.3.63)
# `jambo-certd` : Infrastructure à Clés Publiques Éphémères, Gestion des Certificats & mTLS de Grappe (PID 24)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.19 (`v0.3.63`)** dote **JamboOS** de son **24ᵉ processus en espace utilisateur Ring 3** : **`jambo-certd`** sous le **PID 24**.

Dans une architecture distribuée à micro-noyau et confiance zéro (*Zero-Trust*), la sécurité inter-services repose sur l'authentification mutuelle stricte (mTLS, Mesh cryptographique, signatures de paquets et binaires). Les architectures PKI monolithiques traditionnelles (certificats statiques à longue durée de vie, autorités centralisées opaques) introduisent une lourdeur opérationnelle et une vulnérabilité critique en cas de compromission de clé.

`jambo-certd` fournit une autorité de certification de grappe (*Cluster CA*) autonome, souveraine, déterministe et s'exécutant intégralement en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Certificats Éphémères à Courte Durée de Vie** : Émission de certificats temporaires (`EphemeralCert`, durée par défaut 3600 secondes) limitant drastiquement la fenêtre d'exposition en cas de fuite de clé éphémère.
2. **Autorité de Grappe Déterministe (`ClusterCa`)** : Signature cryptographique instantanée des certificats (`[u8; 32]`) via graine maîtresse de la grappe, numérotation sérielle monotone (`next_serial >= 1000`) et stockage en mémoire statique bornée (`MAX_ACTIVE_CERTS = 32`).
3. **Contrôle d'Usages de Clés Granulaire** : Validation stricte des politiques d'utilisation (`USAGE_SERVER_AUTH`, `USAGE_CLIENT_AUTH`, `USAGE_CODE_SIGN`, `USAGE_MESH_ROUTING`) pour empêcher tout détournement de fonction.
4. **Révocation Instantanée & Gestion CRL Borneée** : Révocation immédiate par numéro de série avec mise en liste de révocation statique (`MAX_REVOKED_CERTS = 16`).
5. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (émission, vérification, révocation, audit) sont subordonnées à la détention d'une capacité explicite `CertCap` (`CERT_ISSUE`, `CERT_VERIFY`, `CERT_REVOKE`, `CERT_AUDIT`, `CERT_ADMIN`).
6. **Protocole IPC Déterministe à 64 Octets** : Messages `CertRequest` et `CertResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`CertOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertOpcode {
    GetStatus = 1,
    IssueCert = 2,
    VerifyCert = 3,
    RevokeCert = 4,
    ListCerts = 5,
}
```

### 2.2 Droits de Capabilités (`CertCap`)

```rust
pub mod cert_rights {
    pub const CERT_ISSUE: u32 = 0x01;
    pub const CERT_VERIFY: u32 = 0x02;
    pub const CERT_REVOKE: u32 = 0x04;
    pub const CERT_AUDIT: u32 = 0x08;
    pub const CERT_ADMIN: u32 = 0x80;
    pub const ALL: u32 = CERT_ISSUE | CERT_VERIFY | CERT_REVOKE | CERT_AUDIT | CERT_ADMIN;
}
```

### 2.3 Structure `CertRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertRequest {
    pub magic: u32,               // 0x43455254 ("CERT")
    pub opcode: u32,              // CertOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits CertCap
    pub serial: u64,              // Numéro de série (pour verify/revoke)
    pub key_usage: u32,           // Masque d'usages autorisés
    pub validity_seconds: u32,    // Durée de validité en secondes
    pub public_key: [u8; 16],     // Empreinte compacte de clé publique
    pub subject: [u8; 16],        // Nom du service / sujet (ex: "netd.jambo", "pkgd.jambo")
}

const _: () = assert!(core::mem::size_of::<CertRequest>() == 64);
```

### 2.4 Structure `CertResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertResponse {
    pub magic: u32,               // 0x43455253 ("CERS")
    pub status: i32,              // 0 = Succès, < 0 = SysError
    pub serial: u64,              // Numéro de série émis ou inspecté
    pub active_certs: u32,        // Nombre total de certificats actifs
    pub revoked_certs: u32,       // Nombre de certificats révoqués
    pub cert_status: u32,         // 0 = Valid, 1 = Expired, 2 = Revoked, 3 = InvalidSig, 4 = UsageMismatch
    pub key_usage: u32,           // Masque d'usages du certificat
    pub signature_preview: [u8; 16], // Signature cryptographique tronquée
    pub status_str: [u8; 16],     // Statut lisible ("VALID", "REVOKED", "EXPIRED", etc.)
}

const _: () = assert!(core::mem::size_of::<CertResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-certd` (PID 24)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie l'autorité de certification de grappe `ClusterCa::new()`.
- Initialise les certificats systèmes par défaut (`init_defaults()` : certificats mTLS pour `kernel.jambo`, `jsh.jambo`, `pkgd.jambo`).
- Exécute une séquence complète d'auto-test :
  1. Émission d'un certificat éphémère pour `netd.jambo` (usage `USAGE_SERVER_AUTH | USAGE_CLIENT_AUTH`).
  2. Vérification cryptographique et validation temporelle du certificat émis (`CertStatus::Valid`).
  3. Révocation explicite du certificat par son numéro de série.
  4. Confirmation que la vérification post-révocation renvoie immédiatement `CertStatus::Revoked`.
- Enregistre son canal de communication IPC sous l'endpoint 24 via `syscall_ipc_register_endpoint(24)`.
- Boucle coopérative de réception des requêtes IPC et `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `cert` avec les commandes suivantes :
- `cert status` : Affiche l'état de l'autorité de grappe, le nombre de certificats actifs et révoqués, ainsi que le dernier numéro de série attribué.
- `cert list` : Liste les certificats actifs avec numéro de série, sujet, usage de clé et validité.
- `cert issue <subject> [usage]` : Émet un nouveau certificat éphémère pour un service.
- `cert verify <serial>` : Vérifie la validité cryptographique, l'expiration et l'absence de révocation d'un certificat.
- `cert revoke <serial>` : Révoque immédiatement un certificat par son numéro de série.
- Commande `ps` : Mise à jour de la table des processus pour lister **24 processus actifs**.

---

## 5. Intégration Noyau & Pipeline de Construction

- **Micro-Noyau (`kernel/src/main.rs`)** :
  - Extraction du binaire `/bin/certd` depuis l'archive TAR initrd.
  - Instanciation du processus `certd` sous le PID 24.
  - Respect strict de l'ABI System V x86-64 : alignement de la pile utilisateur `RSP % 16 == 0`.
  - Enregistrement dans l'ordonnanceur EEVDF avec deadline 1000.
  - Message de boot : `[OK] Ring 3 certd daemon running (PID 24, Ephemeral PKI & Cluster mTLS)`.
- **Orchestrateur `xtask` (`xtask/src/main.rs`)** :
  - Compilation du binaire `certd` en mode bare-metal `x86_64-unknown-none`.
  - Intégration dans le tuple de 24 binaires utilisateur pour la génération de l'archive `initrd.img`.
  - Vérification automatisée dans `run_test` du message officiel QEMU.


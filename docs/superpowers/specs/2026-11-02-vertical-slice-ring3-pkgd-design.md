# Spécification de Conception — Jalon 3.18 (v0.3.62)
# `jambo-pkgd` : Gestion Déclarative de Paquets, Dépôt CAS & Mises à Jour Transactionnelles A/B (PID 23)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.18 (`v0.3.62`)** dote **JamboOS** de son **23ᵉ processus en espace utilisateur Ring 3** : **`jambo-pkgd`** sous le **PID 23**.

Dans les systèmes d'exploitation modernes et les micro-noyaux souverains, la mise à jour logicielle et la distribution de paquets représentent une surface de vulnérabilité critique. Les mécanismes conventionnels (remplacement de binaires en place, écriture directe sur la partition active, dépendance à un gestionnaire de paquets impératif) exposent le système à des états corrompus, des pannes d'amorçage et des attaques de la chaîne logistique logicielle.

`jambo-pkgd` résout ces défis fondamentaux par une architecture déclarative, immuable et atomique :
1. **Magasin Adressé par le Contenu (CAS - Content-Addressed Storage)** : Les paquets logiciels (`.jpkg`) sont indexés et stockés selon l'empreinte cryptographique SHA-256 de leur contenu et scellés par signature asymétrique Ed25519 (`MAX_STORE_PACKAGES = 16`).
2. **Partitionnement Transactionnel A/B sans Interruption** : Deux fentes système (`SlotA` et `SlotB`) permettent de déployer les nouvelles générations logicielles sur la fente inactive pendant que le système s'exécute de façon ininterrompue sur la fente active.
3. **Bascule Atomique $O(1)$ & Rollback Instantané (< 2s)** : Le passage à une nouvelle génération s'effectue en une commutation atomique de pointeur. En cas de dysfonctionnement ou d'échec de validation au démarrage, un rollback instantané restaure l'ancienne génération stable.
4. **Surveillance Automatique des Tentatives de Démarrage** : Détection des boucles de redémarrage (*bootloops*). Si une génération non validée dépasse son quota maximal (`max_boot_attempts: 3`), un retour en arrière automatique est déclenché.
5. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (inspection, installation, staging, commit, rollback) sont régies par des capacités explicites `PkgCap` (`PKG_INSPECT`, `PKG_INSTALL`, `PKG_STAGE`, `PKG_COMMIT`, `PKG_ROLLBACK`, `PKG_ADMIN`).
6. **Protocole IPC Déterministe à 64 Octets** : Messages `PkgRequest` et `PkgResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`PkgOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgOpcode {
    GetStatus = 1,
    InstallPackage = 2,
    QueryPackage = 3,
    StageUpdate = 4,
    CommitUpdate = 5,
    Rollback = 6,
    UninstallPackage = 7,
}
```

### 2.2 Droits de Capabilités (`PkgCap`)

```rust
pub struct PkgCap;
impl PkgCap {
    pub const PKG_INSPECT: u32 = 0x01;
    pub const PKG_INSTALL: u32 = 0x02;
    pub const PKG_STAGE: u32 = 0x04;
    pub const PKG_COMMIT: u32 = 0x08;
    pub const PKG_ROLLBACK: u32 = 0x10;
    pub const PKG_ADMIN: u32 = 0xFF;
}
```

### 2.3 Structure `PkgRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkgRequest {
    pub magic: u32,              // 0x504B4744 ("PKGD")
    pub opcode: u32,             // PkgOpcode
    pub handle_id: u32,          // Identifiant de capacité
    pub rights: u32,             // Droits PkgCap
    pub version_major: u16,      // Version majeure du paquet
    pub version_minor: u16,      // Version mineure du paquet
    pub version_patch: u16,      // Version patch du paquet
    pub _reserved1: u16,         // Alignement
    pub content_hash: [u8; 16],  // Empreinte SHA-256 tronquée du contenu
    pub pkg_name: [u8; 24],      // Nom du paquet (ex: "sec-agent", "jsh-suite")
}

const _: () = assert!(core::mem::size_of::<PkgRequest>() == 64);
```

### 2.4 Structure `PkgResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkgResponse {
    pub magic: u32,              // 0x504B4753 ("PKGS")
    pub status: i32,             // 0 = Succès, < 0 = SysError
    pub current_generation: u64, // Numéro de génération active (1, 2, ...)
    pub active_slot: u32,        // 0 = SlotA, 1 = SlotB
    pub package_count: u32,      // Nombre total de paquets installés dans le CAS
    pub healthy: u32,            // 1 = Sain, 0 = En observation/dégradé
    pub committed: u32,          // 1 = Validé/engagé, 0 = Étape préliminaire
    pub boot_attempts: u32,      // Nombre de tentatives de boot sur la génération
    pub max_boot_attempts: u32,  // Quota maximal avant rollback automatique (3)
    pub content_hash: [u8; 16],  // Empreinte du dernier paquet manipulé
    pub slot_str: [u8; 8],       // "SlotA" ou "SlotB"
}

const _: () = assert!(core::mem::size_of::<PkgResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-pkgd` (PID 23)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie `JamboPkgDaemon::new()`.
- Initialise les paquets système par défaut (`core-system`, `jsh-suite`, `net-stack`).
- Exécute une séquence complète d'auto-test :
  1. Installation d'un paquet vérifié `sec-agent` v1.0.0 avec empreinte SHA-256.
  2. Préparation d'une mise à jour transactionnelle A/B vers `SlotB` (génération 2).
  3. Simulation de 3 démarrages échoués non-engagés, puis déclenchement du rollback automatique vers `SlotA` au 4ᵉ boot.
  4. Ré-amorçage de la mise à jour et validation (`commit`) de la génération 2 sur `SlotB`.
- Enregistre son canal de communication IPC sous l'endpoint 23 via `syscall_ipc_register_endpoint(23)`.
- Boucle coopérative de réception des requêtes IPC et `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `pkg` avec les commandes suivantes :
- `pkg status` : Affiche l'état de la génération active, la fente en cours (SlotA/SlotB), la santé, l'état de commit et le total des paquets.
- `pkg list` : Liste les paquets installés dans le magasin CAS avec version et empreinte.
- `pkg install <name>` : Installe un paquet vérifié dans le magasin CAS.
- `pkg stage` : Prépare une mise à jour système transactionnelle dans la fente inactive.
- `pkg commit` : Valide définitivement la génération système active.
- `pkg rollback` : Déclenche un retour en arrière immédiat vers la génération stable précédente.
- Commande `ps` : Mise à jour de la table des processus pour lister **23 processus actifs**.

---

## 5. Intégration Noyau & Pipeline de Construction

- **Micro-Noyau (`kernel/src/main.rs`)** :
  - Extraction du binaire `/bin/pkgd` depuis l'archive TAR initrd.
  - Instanciation du processus `pkgd` sous le PID 23.
  - Respect strict de l'ABI System V x86-64 : alignement de la pile utilisateur `RSP % 16 == 0`.
  - Enregistrement dans l'ordonnanceur EEVDF avec deadline 1000.
  - Message de boot : `[OK] Ring 3 pkgd daemon running (PID 23, CAS package store & A/B updates)`.
- **Orchestrateur `xtask` (`xtask/src/main.rs`)** :
  - Compilation du binaire `pkgd` en mode bare-metal `x86_64-unknown-none`.
  - Intégration dans le tuple de 23 binaires utilisateur pour la génération de l'archive `initrd.img`.
  - Vérification automatisée dans `run_test` du message officiel QEMU.

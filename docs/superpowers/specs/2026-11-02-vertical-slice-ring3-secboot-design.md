# Spécification de Conception — Jalon 3.21 (v0.3.65)
# `jambo-secboot` : Chaîne de Confiance Initiale, Démarrage Mesuré TPM 2.0 PCR & Scellement Cryptographique (PID 26)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.21 (`v0.3.65`)** dote **JamboOS** de son **26ᵉ processus en espace utilisateur Ring 3** : **`jambo-secboot`** sous le **PID 26**.

Dans une architecture souveraine et résiliente, la sécurité du système dépend de la garantie formelle qu'aucun bootkit, implant UEFI ou charge malveillante n'a altéré les phases précoces d'amorçage. Les contrôles traditionnels purement logiciels en Ring 0 ou Ring 3 sont insuffisants si la racine de confiance matérielle (*Root of Trust*) n'est pas mesurée et vérifiable.

`jambo-secboot` implémente un sous-système de démarrage mesuré conforme aux spécifications TCG 2.0 en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Banque Complète de Registres PCR (0..23)** : Simulation et gestion déterministe des 24 registres de configuration de plateforme (*Platform Configuration Registers*) avec opération d'extension cryptographique SHA-256 : `PCR[i] = SHA256(PCR[i] || event_digest)`.
2. **Chaîne de Mesure Standard JamboOS** :
   - PCR 0 : CRTM & Matériel plateforme
   - PCR 1 : Firmware UEFI / BIOS
   - PCR 4 : Chargeur de démarrage Limine Bootloader
   - PCR 8 : Micro-noyau JamboKernel ELF64
   - PCR 9 : Initrd Ramdisk & modules de démarrage
   - PCR 11 : Ligne directrice de politique de sécurité & confinement
   - PCR 12 : Superviseur d'espace utilisateur Ring 3 `jambo-init`
3. **Journal d'Événements Mesurés Immuable (*Measured Boot Event Log*)** : Enregistrement chronologique inaltérable des composants mesurés (`MAX_BOOT_EVENTS = 32`) avec scellement cryptographique par chaîne SHA-256.
4. **Hiérarchie de Clés Secure Boot Souveraines** : Gestion des clés Platform Key (PK), Key Exchange Key (KEK), Authorized Database (DB) et Forbidden Database (DBX).
5. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (mesure, vérification, scellement, inspection) sont subordonnées à la détention d'une capacité explicite `SecBootCap` (`MEASURE`, `VERIFY`, `SEAL`, `UNSEAL`, `UPDATE_DB`, `INSPECT`, `ADMIN`).
6. **Protocole IPC Déterministe à 64 Octets** : Messages `SecBootRequest` et `SecBootResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`SecBootOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecBootOpcode {
    GetStatus = 1,
    ReadPcr = 2,
    ExtendPcr = 3,
    VerifyChain = 4,
    ListEvents = 5,
}
```

### 2.2 Droits de Capabilités (`SecBootCap`)

```rust
pub mod secboot_rights {
    pub const MEASURE: u32 = 0x01;
    pub const VERIFY: u32 = 0x02;
    pub const SEAL: u32 = 0x04;
    pub const UNSEAL: u32 = 0x08;
    pub const UPDATE_DB: u32 = 0x10;
    pub const INSPECT: u32 = 0x20;
    pub const ADMIN: u32 = 0x80;
    pub const ALL: u32 = MEASURE | VERIFY | SEAL | UNSEAL | UPDATE_DB | INSPECT | ADMIN;
}
```

### 2.3 Structure `SecBootRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecBootRequest {
    pub magic: u32,               // 0x53424F54 ("SBOT")
    pub opcode: u32,              // SecBootOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits SecBootCap
    pub pcr_index: u32,           // Index du PCR (0..23)
    pub event_type: u32,          // Type d'événement de boot
    pub digest: [u8; 32],         // Empreinte SHA-256 de l'événement / composant
    pub component_name: [u8; 12], // Nom abrégé du composant (ex: "kernel", "limine")
}

const _: () = assert!(core::mem::size_of::<SecBootRequest>() == 64);
```

### 2.4 Structure `SecBootResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecBootResponse {
    pub magic: u32,               // 0x53424F53 ("SBOS")
    pub status: i32,              // 0 = Succès, < 0 = SysError
    pub pcr_index: u32,           // Index du PCR inspecté
    pub total_events: u32,        // Nombre total d'événements enregistrés
    pub chain_verified: u32,      // 1 = Chaîne intègre, 0 = Non intègre / altérée
    pub current_pcr_digest: [u8; 32], // Valeur actuelle du registre PCR
    pub pcr_status_str: [u8; 12], // "VERIFIED", "UNTRUSTED", "EXTENDED", etc.
}

const _: () = assert!(core::mem::size_of::<SecBootResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-secboot` (PID 26)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie le gestionnaire de démarrage sécurisé `SecureBootManager::new()`.
- Initialise les mesures de la chaîne de confiance fondamentale (`init_defaults()` : PCR 0 CRTM, PCR 4 Limine, PCR 8 Kernel, PCR 9 Initrd, PCR 11 Policy, PCR 12 Init).
- Exécute une séquence complète d'auto-test au démarrage :
  1. Vérification de l'intégrité de la chaîne de confiance mesurée (`verify_measured_chain() -> true`).
  2. Extension cryptographique du PCR 14 avec une mesure synthétique (`ExtendPcr`).
  3. Lecture et validation de la nouvelle valeur du PCR 14 étendu.
  4. Confirmation que la chaîne critique (PCR 0, 4, 8, 9, 11, 12) demeure intègre et non altérée.
- Enregistre son canal de communication IPC sous l'endpoint 26 via `syscall_ipc_register_endpoint(26)`.
- Boucle coopérative de réception des requêtes IPC et `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `secboot` avec les commandes suivantes :
- `secboot status` : Affiche l'état de la chaîne de confiance, le total des événements de boot et la conformité globale.
- `secboot pcr <index>` : Lit et affiche l'empreinte SHA-256 actuelle du registre PCR spécifié (0..23).
- `secboot measure <pcr> <name> [digest]` : Étend un registre PCR avec la mesure d'un composant.
- `secboot events` : Liste l'ensemble des événements enregistrés dans le journal de boot mesuré.
- `secboot verify` : Vérifie formellement la conformité de l'ensemble de la chaîne de démarrage.
- Commande `ps` : Mise à jour de la table des processus pour lister **26 processus actifs**.

---

## 5. Intégration Noyau & Pipeline de Construction

- **Micro-Noyau (`kernel/src/main.rs`)** :
  - Extraction du binaire `/bin/secboot` depuis l'archive TAR initrd.
  - Instanciation du processus `secboot` sous le PID 26.
  - Respect strict de l'ABI System V x86-64 : alignement de la pile utilisateur `RSP % 16 == 0`.
  - Enregistrement dans l'ordonnanceur EEVDF avec deadline 1000.
  - Message de boot : `[OK] Ring 3 secboot daemon running (PID 26, TPM 2.0 Measured Boot & Secure Trust Chain)`.
- **Orchestrateur `xtask` (`xtask/src/main.rs`)** :
  - Compilation du binaire `secboot` en mode bare-metal `x86_64-unknown-none`.
  - Intégration dans le tuple de 26 binaires utilisateur pour la génération de l'archive `initrd.img`.
  - Vérification automatisée dans `run_test` du message officiel QEMU.

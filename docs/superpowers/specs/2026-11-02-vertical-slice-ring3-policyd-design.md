# Spécification de Conception — Jalon 3.20 (v0.3.64)
# `jambo-policyd` : Moteur de Politiques de Sécurité Déclaratives, Contrôle d'Admission ABAC/RBAC & Zéro-Autorité Ambiante (PID 25)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.20 (`v0.3.64`)** dote **JamboOS** de son **25ᵉ processus en espace utilisateur Ring 3** : **`jambo-policyd`** sous le **PID 25**.

Dans une infrastructure distribuée à micro-noyau et zéro-confiance (*Zero-Trust*), chaque requête sensible (création de charges utiles, accès aux secrets de grappe, enregistrement de services, montage de volumes ou modification de règles réseau) doit être soumise à une décision d'admission formelle et déterministe. Les mécanismes de contrôle d'accès ad hoc ou dispersés augmentent la surface d'attaque et favorisent les élévations de privilèges accidentelles.

`jambo-policyd` fournit un moteur d'évaluation de politiques ABAC/RBAC déclaratif, souverain et déterministe en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Principe Fondamental de Déni par Défaut (*Deny-by-default*)** : Toute action non explicitement autorisée par au moins une règle active est systématiquement rejetée.
2. **Préséance Absolue des Refus Explicites (*Explicit Deny Precedence*)** : Si une règle de refus s'applique à une requête, elle prévaut inconditionnellement sur toute règle d'autorisation, quel que soit le niveau de priorité.
3. **Évaluation Hiérarchique Multi-Critères (ABAC/RBAC)** : Prise en compte conjointe du rôle du sujet (`ROLE_SYSTEM`, `ROLE_OPERATOR`, `ROLE_WORKLOAD`, `ROLE_GUEST`), du masque d'action (`SPAWN_WORKLOAD`, `ACCESS_SECRET`, `REGISTER_SERVICE`, `ROUTE_TRAFFIC`, `STORAGE_MOUNT`, `ADMIN`), et du préfixe de chemin de la ressource (`resource_prefix` jusqu'à 32 octets).
4. **Baux Temporels d'Expiration des Règles (`expires_at`)** : Possibilité d'assigner des permissions éphémères s'annulant automatiquement une fois leur délai expiré.
5. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (évaluation, ajout, suppression, audit de règles) sont régies par des capacités explicites `PolicyCap` (`POLICY_EVALUATE`, `POLICY_RULE_ADD`, `POLICY_RULE_DEL`, `POLICY_AUDIT`, `POLICY_ADMIN`).
6. **Protocole IPC Déterministe à 64 Octets** : Messages `PolicyRequest` et `PolicyResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`PolicyOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOpcode {
    GetStatus = 1,
    EvaluateAdmission = 2,
    AddRule = 3,
    DeleteRule = 4,
    ListRules = 5,
}
```

### 2.2 Droits de Capabilités (`PolicyCap`)

```rust
pub mod policy_rights {
    pub const POLICY_EVALUATE: u32 = 0x01;
    pub const POLICY_RULE_ADD: u32 = 0x02;
    pub const POLICY_RULE_DEL: u32 = 0x04;
    pub const POLICY_AUDIT: u32 = 0x08;
    pub const POLICY_ADMIN: u32 = 0x80;
    pub const ALL: u32 =
        POLICY_EVALUATE | POLICY_RULE_ADD | POLICY_RULE_DEL | POLICY_AUDIT | POLICY_ADMIN;
}
```

### 2.3 Structure `PolicyRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRequest {
    pub magic: u32,               // 0x504F4C44 ("POLD")
    pub opcode: u32,              // PolicyOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits PolicyCap
    pub subject_role: u16,        // Rôle du sujet (ROLE_SYSTEM, ROLE_OPERATOR, etc.)
    pub priority: u8,             // Priorité de la règle (0..255)
    pub effect: u8,               // Effet : 0 = Allow, 1 = Deny
    pub action_mask: u32,         // Masque d'actions sensibles
    pub rule_id: u32,             // Identifiant de règle (pour delete ou ajout)
    pub expires_at: u64,          // Horodatage d'expiration (0 = permanent)
    pub resource_prefix: [u8; 32],// Préfixe de la ressource protégée
}

const _: () = assert!(core::mem::size_of::<PolicyRequest>() == 64);
```

### 2.4 Structure `PolicyResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyResponse {
    pub magic: u32,               // 0x504F4C53 ("POLS")
    pub status: i32,              // 0 = Succès, < 0 = SysError
    pub eval_count: u64,          // Nombre total d'évaluations réalisées
    pub allow_count: u64,         // Total des admissions accordées
    pub deny_count: u64,          // Total des admissions refusées
    pub decision: u32,            // 0 = Allowed, 1 = Denied
    pub active_rules: u32,        // Nombre de règles actives en mémoire
    pub matching_rule_id: u32,    // Règle ayant dicté la décision (0 si déni par défaut)
    pub _reserved: u32,           // Alignement 64 octets
    pub decision_str: [u8; 16],   // "ALLOWED", "DENIED_DEFAULT", "DENIED_EXPLICIT"
}

const _: () = assert!(core::mem::size_of::<PolicyResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-policyd` (PID 25)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie le moteur de politiques `PolicyEngine::new()`.
- Initialise les règles de sécurité fondamentales (`init_defaults()` : règles pour `system/*`, `workload/*`, et `vault/*`).
- Exécute une séquence complète d'auto-test au démarrage :
  1. Évaluation d'une action autorisée (`ROLE_SYSTEM` accédant à `system/kernel`). Décision attendue : `Allowed`.
  2. Évaluation d'une ressource inconnue sans règle explicite. Décision attendue : `Denied` (déni par défaut).
  3. Ajout d'une règle d'exclusion explicite (`Deny` prioritaire) sur `secret/master`.
  4. Confirmation que même un `ROLE_SYSTEM` est refusé sur `secret/master` (préséance de déni explicite).
- Enregistre son canal de communication IPC sous l'endpoint 25 via `syscall_ipc_register_endpoint(25)`.
- Boucle coopérative de réception des requêtes IPC et `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `policy` avec les commandes suivantes :
- `policy status` : Affiche les métriques d'évaluation (total, accords, refus, règles actives).
- `policy eval <role> <action> <resource>` : Soumet une requête d'évaluation d'admission.
- `policy rule add <id> <role> <action> <resource> <allow|deny> [priority]` : Ajoute une règle déclarative.
- `policy rule del <id>` : Supprime une règle par son identifiant.
- `policy list` : Liste l'ensemble des règles déclaratives actives en mémoire.
- Commande `ps` : Mise à jour de la table des processus pour lister **25 processus actifs**.

---

## 5. Intégration Noyau & Pipeline de Construction

- **Micro-Noyau (`kernel/src/main.rs`)** :
  - Extraction du binaire `/bin/policyd` depuis l'archive TAR initrd.
  - Instanciation du processus `policyd` sous le PID 25.
  - Respect strict de l'ABI System V x86-64 : alignement de la pile utilisateur `RSP % 16 == 0`.
  - Enregistrement dans l'ordonnanceur EEVDF avec deadline 1000.
  - Message de boot : `[OK] Ring 3 policyd daemon running (PID 25, Security Policy Engine & Admission Control)`.
- **Orchestrateur `xtask` (`xtask/src/main.rs`)** :
  - Compilation du binaire `policyd` en mode bare-metal `x86_64-unknown-none`.
  - Intégration dans le tuple de 25 binaires utilisateur pour la génération de l'archive `initrd.img`.
  - Vérification automatisée dans `run_test` du message officiel QEMU.

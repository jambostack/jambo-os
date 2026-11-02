# Spécification de Conception — Jalon 3.24 (v0.3.68)
# `jambo-attest` : Attestation Cryptographique Distante, Preuves Zero-Knowledge (ZKP) & Confinement Matériel de Grappe (PID 29)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.24 (`v0.3.68`)** dote **JamboOS** de son **29ᵉ processus en espace utilisateur Ring 3** : **`jambo-attest`** sous le **PID 29**.

Dans une architecture distribuée à micro-noyau et confiance zéro (*Zero-Trust*), la confiance accordée à un nœud de grappe ne peut reposer sur une déclaration d'identité arbitraire ou un secret statique. Chaque machine ou enclave doit prouver mathématiquement son intégrité matérielle et logicielle avant de pouvoir participer au plan de contrôle, échanger des messages IPC ou accéder à la mémoire partagée.

`jambo-attest` implémente un système complet d'attestation cryptographique et de confinement adaptatif en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Attestation Distante Multi-Architecture (Racines Matérielles de Confiance)** :
   - TPM 2.0 (PCR, Platform Configuration Registers)
   - Intel TDX (Trust Domains)
   - AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
   - ARM CCA (Realm Management Extension - RME)
   - Enclaves TEE souveraines JamboOS (`jambo-tee`)
2. **Preuves d'Intégrité à Divulgation Nulle de Connaissance (Zero-Knowledge Proofs - ZKP)** :
   - Protocole de Schnorr / Fiat-Shamir (NIZKPoK) : preuve non-interactive de possession d'un secret d'intégrité / mesure sans jamais révéler la clé ni le secret.
   - Validation en temps constant sans allocation mémoire.
3. **Revendications d'Intégrité Signées (`NodeIntegrityClaim`)** :
   - Condensat canonique SHA-256 scellé par signature HMAC-SHA256 avec défi d'aléa anti-rejeu inter-nœuds (`challenge_nonce`, `epoch`).
4. **Confinement Matériel Adaptatif de Grappe (`ConfinementLevel`)** :
   - `Unrestricted` : Accès complet aux ressources et IPC de grappe.
   - `Sandboxed` : Accès restreint (canaux IPC filtrés).
   - `Isolated` : Réseau et IPC coupés, quarantaine forensique immédiate.
   - `Ejected` : Exclusion totale de la grappe et révocation des clés.
5. **Registre d'Audit Inaltérable Scellé par Chaîne Cryptographique (`audit_chain`)** :
   - Scellement séquentiel de chaque événement (enregistrement, revendication, preuve ZKP, confinement) par chaînage SHA-256 cumulatif.
6. **Contrôle d'Accès par Capabilités Explicites (`AttestCap`)** :
   - Zéro autorité ambiante avec droits granulaires (`GENERATE_CLAIM`, `VERIFY_CLAIM`, `GENERATE_ZKP`, `VERIFY_ZKP`, `CONFINE_NODE`, `ADMIN`).
7. **Protocole IPC Déterministe à 64 Octets** :
   - Messages `AttestRequest` et `AttestResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`AttestOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestOpcode {
    GetStatus = 1,
    ClaimIntegrity = 2,
    VerifyClaim = 3,
    GenerateZkp = 4,
    VerifyZkp = 5,
    ConfineNode = 6,
    RotateChallenge = 7,
}
```

### 2.2 Droits de Capabilités (`AttestCap`)

```rust
pub mod attest_rights {
    pub const GENERATE_CLAIM: u32 = 1 << 0;
    pub const VERIFY_CLAIM: u32 = 1 << 1;
    pub const GENERATE_ZKP: u32 = 1 << 2;
    pub const VERIFY_ZKP: u32 = 1 << 3;
    pub const CONFINE_NODE: u32 = 1 << 4;
    pub const ADMIN: u32 = 1 << 5;

    pub const ALL: u32 =
        GENERATE_CLAIM | VERIFY_CLAIM | GENERATE_ZKP | VERIFY_ZKP | CONFINE_NODE | ADMIN;
}
```

### 2.3 Structure `AttestRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestRequest {
    pub magic: u32,               // 0x41545453 ("ATTS")
    pub opcode: u32,              // AttestOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits AttestCap
    pub node_id: u32,             // Identifiant du nœud cible
    pub trust_root: u8,           // Racine de confiance (0..4)
    pub confinement_level: u8,    // Niveau de confinement cible (0..3)
    pub _reserved1: [u8; 2],      // Alignement
    pub epoch: u64,               // Époque de défi
    pub node_name: [u8; 32],      // Nom du nœud (tronqué à 32 octets)
}

const _: () = assert!(core::mem::size_of::<AttestRequest>() == 64);
```

### 2.4 Structure `AttestResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestResponse {
    pub magic: u32,               // 0x41545452 ("ATTR")
    pub status: i32,              // 0 = Succès, < 0 = SysError
    pub node_id: u32,             // ID de nœud concerné
    pub total_nodes: u32,         // Total de nœuds enregistrés
    pub total_claims: u32,        // Total de revendications vérifiées
    pub total_zkp: u32,           // Total de preuves ZKP vérifiées
    pub total_violations: u32,    // Total d'anomalies / violations
    pub node_status: u8,          // Statut du nœud (0..4)
    pub confinement_level: u8,    // Niveau de confinement actuel (0..3)
    pub _reserved1: [u8; 2],      // Alignement
    pub audit_hash: [u8; 16],     // Empreinte SHA-256 tronquée de la chaîne d'audit
    pub status_str: [u8; 16],     // Chaîne d'état ASCII ("TRUSTED", "QUARANTINED", etc.)
}

const _: () = assert!(core::mem::size_of::<AttestResponse>() == 64);
```

---

## 3. Primitives ZKP de Schnorr / Fiat-Shamir (#![no_std])

Le module de preuve à divulgation nulle de connaissance implémente le protocole de Schnorr avec transformation non-interactive de Fiat-Shamir sur un groupe cyclique $\mathbb{Z}_p^*$ sans arithmétique dynamique :
- Générateur $g$, ordre $q$, premier $p$.
- Déclaration publique $y = g^x \pmod p$ où $x$ est le secret d'intégrité de mesure du nœud.
- Engagement de l'attestateur : $t = g^v \pmod p$ pour un aléa éphémère $v$.
- Défi de Fiat-Shamir : $c = \text{SHA256}(g \parallel y \parallel t \parallel \text{challenge})$.
- Réponse : $r = v + c \cdot x \pmod q$.
- Vérification : $g^r \stackrel{?}{=} t \cdot y^c \pmod p$.

Toutes les exponentiations modulaires sont calculées par l'algorithme d'exponentiation binaire à temps constant pour prévenir les attaques par canal auxiliaire.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre la commande native `attest` :
- `attest status` (ou `attest`) : Affiche le bilan de grappe, nœuds totaux, revendications, ZKP, violations et empreinte d'audit.
- `attest list` : Liste tabulaire de tous les nœuds avec ID, Nom, Racine de confiance, Statut et Confinement.
- `attest claim <node_id>` : Déclenche la génération d'une revendication d'intégrité signée pour le nœud.
- `attest verify <node_id>` : Vérifie la signature et les mesures cryptographiques de la revendication.
- `attest zkp <node_id>` : Génère et valide une preuve Zero-Knowledge Schnorr / Fiat-Shamir pour le nœud.
- `attest confine <node_id> <unrestricted|sandboxed|isolated|ejected>` : Applique un niveau de confinement matériel adaptatif.
- `attest audit` : Affiche l'historique récent des événements scellés et l'empreinte de chaîne d'audit courante.

La commande `ps` liste les **29 processus actifs** incluant :
```text
29 | attest | Ring 3 | Ready | 1000 | Remote Attestation & Zero-Knowledge Proofs
```

---

## 5. Intégration Noyau & Pipeline `xtask`

- `kernel/src/main.rs` :
  - Extraction de `/bin/attest` depuis l'archive TAR `initrd`.
  - Spawning du processus utilisateur PID 29 `attest`.
  - Validation de l'alignement de pile System V ABI (`RSP % 16 == 0`).
  - Deadline EEVDF fixée à 1000.
  - Assertions CI validant 29 processus et émission de la ligne PASS officielle :
    `[PASS] Attestation Cryptographique Distante & Preuves ZKP (jambo-attest PID 29) validee sous QEMU.`
- `xtask/src/main.rs` :
  - Compilation bare-metal `build_attest()` pour `x86_64-unknown-none`.
  - Extension de `build_userland()` au 29-uplet.
  - Empaquettage de `bin/attest` dans `initrd.tar`.
  - Validation de la chaîne PASS sous QEMU.

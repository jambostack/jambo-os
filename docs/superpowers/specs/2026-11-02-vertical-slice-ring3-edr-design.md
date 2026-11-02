# Spécification de Conception — Jalon 3.27 (v0.3.71)
# `jambo-edr` : Détection et Réponse sur les Terminaux Souveraine EDR (PID 32)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.27 (`v0.3.71`)** dote **JamboOS** de son **32ᵉ processus en espace utilisateur Ring 3** : **`jambo-edr`** sous le **PID 32**.

Dans une architecture distribuée et modulaire à micro-noyau, la compromission potentielle d'un processus utilisateur ou d'un service réseau doit être détectée et neutralisée au plus près du terminal d'exécution sans nécessiter une panique du noyau ni une interruption globale du système. Alors que `jambo-forensics` capture les preuves après incident et `jambo-siem` corrèle les journaux de grappe, `jambo-edr` constitue la sentinelle active en temps réel sur les processus locaux.

`jambo-edr` implémente un système complet de surveillance comportementale, d'inspection d'injections et de remédiation en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Contrôle d'Accès Capabilaire Strict (`EdrCap`)** :
   - Modèle Zero-Ambient Authority (ZAA).
   - Droits granulaires : `MONITOR_PROCESS`, `DETECT_INJECTION`, `ENCLAVE_GUARD`, `SYSTEM_HOOK_INSPECT`, `RESPOND_ISOLATE`, `SEAL_REPORT`, `AUDIT_READ`, `SCAN_MEMORY`, `ADMIN`.
   - Atténuation monotone irréversible : impossibilité d'acquérir des droits supérieurs ou d'augmenter le quota d'invocations.
2. **Surveillance Comportementale d'Arborescence & Télémétrie Syscalls** :
   - Suivi des filiations parent-enfant (PID/PPID), détection des anomalies de lignage (ex: démon réseau engendrant un shell interactif).
   - Détection des bombes de processus (fork-bombs) et des motifs anormaux d'appels système.
   - Calcul dynamique d'indice de menace (0..100) par processus.
3. **Moteur d'Interception d'Injections Dynamiques (.jso / GOT-PLT / W+X)** :
   - Détection des bibliothèques dynamiques non-approuvées et segments mémoire interdits (Writable & Executable).
   - Détection de détournement de tables de saut GOT/PLT.
   - Détection de Process Hollowing (altération d'en-tête ELF et divergence du point d'entrée).
4. **Scanneur de Shellcode en Mémoire Vive** :
   - Détection d'atterrissages NOP sled (séries d'octets 0x90).
   - Détection de pièges INT3 (0xCC), boucles de syscalls furtifs (0x0F 0x05) et pivots de pile ROP (`pop rsp; ret`).
5. **Garde-Fou d'Enclave Matérielle / TEE (`EnclaveGuard`)** :
   - Détection heuristique de franchissement des frontières d'isolation d'enclave.
   - Blocage des accès illicites aux MSRs privilégiés (IA32_LSTAR, IA32_EFER) et zones mémoires sensibles.
6. **Inspection de Crochets Système (`HookInspector`)** :
   - Détection d'injections de trampolines de saut (JMP 0xE9 / indirect CALL) dans les tables d'appels système.
7. **Confinement $O(1)$ Instantané & Remédiation Déterministe (`EdrRemediationReport`)** :
   - Quarantaine immédiate, révocation instantanée des capabilités, suspension ou terminaison du processus déviant.
8. **Registre d'Audit Inaltérable Scellé SHA-256 (`EdrSummary`)** :
   - Chaînage cryptographique inviolable de chaque alerte et action de remédiation.
9. **Protocole IPC Déterministe à 64 Octets** :
   - Messages `EdrRequest` et `EdrResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`EdrOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdrOpcode {
    GetStatus = 1,
    ScanProcess = 2,
    IsolateProcess = 3,
    GetProcessTree = 4,
    GetAlerts = 5,
    GetAudit = 6,
}
```

### 2.2 Droits de Capabilités (`EdrCap`)

```rust
pub mod edr_rights {
    pub const MONITOR_PROCESS: u32 = 1 << 0;
    pub const DETECT_INJECTION: u32 = 1 << 1;
    pub const ENCLAVE_GUARD: u32 = 1 << 2;
    pub const SYSTEM_HOOK_INSPECT: u32 = 1 << 3;
    pub const RESPOND_ISOLATE: u32 = 1 << 4;
    pub const SEAL_REPORT: u32 = 1 << 5;
    pub const AUDIT_READ: u32 = 1 << 6;
    pub const SCAN_MEMORY: u32 = 1 << 7;
    pub const ADMIN: u32 = 1 << 8;
    pub const ALL: u32 = 0x1FF;
}
```

### 2.3 Structure `EdrRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdrRequest {
    pub magic: u32,               // 0x45445244 ("EDRD")
    pub opcode: u32,              // EdrOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits EdrCap
    pub target_pid: u32,          // PID cible
    pub action: u8,               // 0: Monitor, 1: Isolate, 2: Suspend, 3: Terminate
    pub scan_mode: u8,            // 0: Quick, 1: Deep, 2: Shellcode, 3: Enclave
    pub _reserved1: [u8; 2],      // Alignement
    pub epoch: u64,               // Époque de requête
    pub reason: [u8; 32],         // Motif textuel court
}

const _: () = assert!(core::mem::size_of::<EdrRequest>() == 64);
```

### 2.4 Structure `EdrResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdrResponse {
    pub magic: u32,               // 0x45445253 ("EDRS")
    pub status: i32,              // 0 = Succès, < 0 = EdrError
    pub monitored_pids: u32,      // Total de processus surveillés
    pub total_alerts: u32,        // Total d'alertes générées
    pub isolated_pids: u32,       // Total de processus isolés
    pub threat_score: u32,        // Score de menace global / cible (0..100)
    pub target_status: u8,        // Statut du processus cible
    pub detected_anomaly: u8,     // Anomalie détectée (0..4)
    pub _reserved1: [u8; 2],      // Alignement
    pub audit_hash: [u8; 16],     // Empreinte SHA-256 tronquée de la chaîne d'audit
    pub status_str: [u8; 16],     // Chaîne d'état ASCII ("CLEAN", "ISOLATED", etc.)
}

const _: () = assert!(core::mem::size_of::<EdrResponse>() == 64);
```

---

## 3. Intégration dans le Shell `jsh`

Le shell `jsh` intègre la commande native `edr` :
- `edr status` (ou `edr`) : Affiche le bilan d'activité de l'EDR, processus surveillés, alertes actives, processus isolés, score moyen de menace et empreinte d'audit SHA-256.
- `edr scan <pid>` : Déclenche l'inspection approfondie d'un processus (shellcode en mémoire vive, segments W+X, crochets système, filiation anormale) et affiche le verdict.
- `edr isolate <pid>` : Isole immédiatement un processus déviant en $O(1)$ (révocation de capabilités, quarantaine, suspension) et génère le rapport de remédiation.
- `edr tree` : Affiche l'arborescence des processus avec PID, PPID, statut de sécurité et indice de menace.
- `edr alerts` : Liste les alertes de sécurité EDR actives avec sévérité, action de remédiation et processus cible.
- `edr audit` : Affiche le journal d'audit scellé par empreintes SHA-256 cumulatives.

La commande `ps` liste les **32 processus actifs** incluant :
```text
32 | edr | Ring 3 | Ready | 1000 | Endpoint Detection & Response Daemon
```

---

## 4. Intégration Noyau & Pipeline `xtask`

- `kernel/src/main.rs` :
  - Extraction de `/bin/edr` depuis l'archive TAR `initrd`.
  - Spawning du processus utilisateur PID 32 `edr`.
  - Validation de l'alignement de pile System V ABI (`RSP % 16 == 0`).
  - Deadline EEVDF fixée à 1000.
  - Assertions CI validant 32 processus et émission de la ligne PASS officielle :
    `[PASS] Detection & Reponse sur Terminaux EDR (jambo-edr PID 32) validee sous QEMU.`
- `xtask/src/main.rs` :
  - Compilation bare-metal `build_edr()` pour `x86_64-unknown-none`.
  - Extension de `build_userland()` au 32-uplet.
  - Empaquettage de `bin/edr` dans `initrd.tar`.
  - Validation de la chaîne PASS sous QEMU.

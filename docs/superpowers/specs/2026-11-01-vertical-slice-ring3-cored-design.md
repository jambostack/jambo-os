# Spécification de Conception — Jalon 3.17 (v0.3.61)
# `jambo-cored` : Capture d'État Post-Mortem, Crash Dumps ELF64 & Analyse Forensique (PID 22)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.17 (`v0.3.61`)** dote **JamboOS** de son **22ᵉ processus en espace utilisateur Ring 3** : **`jambo-cored`** sous le **PID 22**.

Dans un micro-noyau moderne hautement résilient, les pannes logicielles (fautes de page, fautes de protection générale GPF, dépassements de pile, assertions violées) ne doivent ni corrompre le reste du système, ni disparaître sans trace forensique exploitable :
1. **Capture Déterministe d'État Post-Mortem** : Capture instantanée de l'état des registres processeur (RIP, RSP, RBP, RFLAGS, CR2, CR3 sur x86-64), de l'instantané de la pile mémoire (`MAX_STACK_BYTES = 256`) et de la trace d'appels (`MAX_CALL_TRACE = 16`).
2. **Génération de Core Dumps ELF64 Standard Sans Tas** : Construction d'un fichier ELF64 valide (`ET_CORE`) comprenant le segment `PT_NOTE` avec les notes Linux standard (`NT_PRSTATUS`, `NT_PRPSINFO`, `NT_SIGINFO`) et les segments mémoire `PT_LOAD` (`zero heap`).
3. **Scellement Cryptographique SHA-256 & Non-Répudiation** : Chaque rapport de crash généré est scellé par une empreinte SHA-256 intégrée, rendant toute altération ou falsification immédiatement détectable.
4. **Confinement & Quarantaine VMO Automatique** : Mise en quarantaine immédiate des segments de mémoire virtuelle défaillants (`quarantined = true`, `PROT_NONE`) pour éradiquer tout risque de corruption mémoire inter-domaines.
5. **Recommandations d'Auto-Guérison de Grappe** : Analyse heuristique de la cause du crash proposant des stratégies automatiques de remédiation (`RestartProcess`, `RebindVirtIO`, `QuarantineVmo`, `IsolateClusterNode`).
6. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (capture, inspection, quarantaine, génération de dumps, purge) sont régies par des capacités explicites `CoreCap` (`CORE_INSPECT`, `CORE_CAPTURE`, `CORE_GENERATE`, `CORE_SEAL`, `CORE_QUARANTINE`, `CORE_ADMIN`).
7. **Protocole IPC Déterministe à 64 Octets** : Messages `CoreRequest` et `CoreResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`CoreOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreOpcode {
    GetStatus = 1,
    TriggerDump = 2,
    QueryReport = 3,
    VerifyReport = 4,
    Quarantine = 5,
    Purge = 6,
}
```

### 2.2 Structure `CoreRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreRequest {
    pub magic: u32,              // 0x434F5245 ("CORE")
    pub opcode: u32,             // CoreOpcode
    pub handle_id: u32,          // Identifiant de capacité
    pub rights: u32,             // Droits CoreCap
    pub target_pid: u64,         // PID du processus cible
    pub reason_code: u32,        // Code de cause de crash (1..9)
    pub report_id: u32,          // ID de rapport
    pub fault_addr: u64,         // Adresse de faute (CR2)
    pub param_u64: u64,          // Horodatage ou flags
    pub proc_name: [u8; 20],     // Nom du binaire défaillant
}

const _: () = assert!(core::mem::size_of::<CoreRequest>() == 64);
```

### 2.3 Structure `CoreResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreResponse {
    pub magic: u32,              // 0x434F5253 ("CORS")
    pub status: i32,             // 0 = Succès, < 0 = SysError
    pub total_reports: u32,      // Nombre total de rapports enregistrés
    pub quarantined_regions: u32,// Nombre de régions mémoire en quarantaine
    pub last_crash_pid: u64,     // PID du dernier crash capturé
    pub last_rip: u64,           // Pointeur d'instruction (RIP) au moment du crash
    pub last_fault_addr: u64,    // Adresse de faute (CR2)
    pub sha256_seal: [u8; 16],   // Sceau cryptographique SHA-256 tronqué
    pub reason_str: [u8; 8],     // Raison textuelle abrégée ("PAGE_FLT", "GPF", etc.)
}

const _: () = assert!(core::mem::size_of::<CoreResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-cored` (PID 22)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie le gestionnaire `JamboCoreDaemon::new()`.
- Initialise les structures par défaut (`init_defaults()`).
- Exécute un auto-test complet au démarrage :
  1. Capture d'un rapport de crash synthétique pour un processus test (faute de page CR2 `0xdeadbeef`).
  2. Génération du Core Dump ELF64 en mémoire statique (`ElfCoreGenerator`).
  3. Vérification des en-têtes ELF (`ELF_MAGIC`, `ET_CORE`, notes `NT_PRSTATUS`, `NT_PRPSINFO`, `NT_SIGINFO`).
  4. Validation du scellement SHA-256 et détection de falsification.
  5. Mise en quarantaine d'un segment VMO et recommandation d'auto-guérison.
- Enregistre le canal de communication IPC sous l'endpoint 22.
- Boucle de service coopérative via `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `core` avec les sous-commandes suivantes :
- `core status` : Affiche l'état du démon, total des crash reports, régions en quarantaine et dernier crash capturé.
- `core dump <pid> [reason]` : Déclenche manuellement la capture d'un crash dump pour un PID cible.
- `core list` : Liste les rapports de crash enregistrés (ID, PID, RIP, adresse de faute, cause).
- `core verify <id>` : Valide l'intégrité cryptographique SHA-256 d'un rapport de crash.
- `core quarantine` : Affiche les régions mémoires VMO actuellement confinées.
- `core purge` : Réinitialise et purge les rapports de crash.

Le listing `ps` est porté à **22 processus actifs** :
```
 22  ACTIF    /bin/cored (Capture Crash Dumps ELF64 & Forensique Ring 3)
```

---

## 5. Intégration Noyau & Pipeline `xtask`

1. **Noyau (`kernel/`)** :
   - Extraction de `/bin/cored` depuis le TAR `initrd`.
   - Création du processus PID 22 (`cored`).
   - Alignement de la pile System V ABI (`RSP % 16 == 0`).
   - Enregistrement dans l'ordonnanceur EEVDF avec une deadline de 1000.
   - Émission du message de test QEMU officiel :
     `\x1b[1;32m[PASS] Capture Crash Dumps ELF64 & Forensique (jambo-cored PID 22) validee sous QEMU.\x1b[0m`

2. **Pipeline `xtask/`** :
   - Fonction `build_cored(release: bool) -> anyhow::Result<PathBuf>`.
   - `build_userland` étendu à un 22-tuple.
   - Empaquetage de `/bin/cored` et `/bin/jambo-cored` dans `initrd.tar`.
   - Mise à jour de la bannière vers `v0.3.61`.
   - Harnais `run_test` configuré pour valider le message `[PASS] Capture Crash Dumps ELF64 & Forensique`.

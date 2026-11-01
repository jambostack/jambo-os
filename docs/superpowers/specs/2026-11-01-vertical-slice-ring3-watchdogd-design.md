# Spécification de Conception — Jalon 3.16 (v0.3.60)
# `jambo-watchdogd` : Surveillance de Vivacité Système, Chien de Garde Matériel & Auto-Guérison (PID 21)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.16 (`v0.3.60`)** franchit un nouveau palier de haute disponibilité et d'auto-guérison pour **JamboOS** en promouvant le **21ᵉ processus Ring 3** : **`jambo-watchdogd`** sous le **PID 21**.

Dans un système d'exploitation souverain pour infrastructures critiques et micro-noyaux bare-metal, la résilience aux pannes matérielles, aux boucles infinies logiques, aux blocages d'ordonnancement (Soft/Hard Lockup) et aux interblocages d'événements (Deadlocks) est un impératif absolu :
1. **Chien de Garde Matériel & Pré-Interruption NMI** : Gestion et armement du timer matériel de surveillance (Intel iTCO / ACPI WDT / Generic Hardware Watchdog). En cas de non-rafraîchissement avant échéance, déclenchement d'une pré-interruption non masquable (NMI) pour capturer l'état des registres et de la mémoire avant le redémarrage d'urgence.
2. **Surveillance Multi-Niveaux par Processus/Thread** : Enregistrement de cibles logicielles (`MAX_WATCHDOG_TARGETS = 32`) avec quotas de rafraîchissement (`timeout_ms`). Chaque service système doit signaler sa vivacité (`ping`) périodiquement.
3. **Détection des Blocages Stochastiques** : Détection automatique des dérives temporelles d'ordonnancement et des boucles bloquantes sans allocation dynamique de mémoire (`zero heap`).
4. **Journal d'Audit Scellé par Chaîne Cryptographique SHA-256** : Enregistrement infalsifiable des événements de vivacité, des alertes de dérive et des interventions d'auto-guérison scellés séquentiellement.
5. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (signalement de vivacité, enregistrement de cibles, reconfiguration, déclenchement d'actions) sont soumises à la vérification stricte de la capacité `WatchdogCap` (`WDOG_PING`, `WDOG_REGISTER`, `WDOG_CONFIGURE`, `WDOG_TRIGGER`, `WDOG_ADMIN`).
6. **Protocole IPC Déterministe à 64 Octets** : Messages `WatchdogRequest` et `WatchdogResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`WatchdogOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogOpcode {
    GetStatus = 1,
    Ping = 2,
    RegisterTarget = 3,
    TriggerAction = 4,
    QueryAlerts = 5,
    AuditLog = 6,
}
```

### 2.2 Structure `WatchdogRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogRequest {
    pub magic: u32,              // 0x57444F47 ("WDOG")
    pub opcode: u32,             // WatchdogOpcode
    pub handle_id: u32,          // Identifiant de capacité
    pub rights: u32,             // Droits de la capacité WatchdogCap
    pub target_id: u32,          // Cible surveillée (0 = global)
    pub timeout_ms: u32,         // Quota de temps imparti (ms)
    pub action: u8,              // 0=Log, 1=NMI, 2=Reset, 3=Failover
    pub name_len: u8,            // Longueur du libellé de cible (<= 32)
    pub _pad: [u8; 2],           // Rembourrage d'alignement
    pub param_u64: u64,          // Paramètre temporel ou flags
    pub name: [u8; 32],          // Nom du service / thread surveillé
}

const _: () = assert!(core::mem::size_of::<WatchdogRequest>() == 64);
```

### 2.3 Structure `WatchdogResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogResponse {
    pub magic: u32,              // 0x57444F53 ("WDOS")
    pub status: i32,             // 0 = Succès, < 0 = SysError
    pub hw_enabled: u8,          // 1 si chien de garde matériel armé
    pub active_targets: u8,      // Nombre de cibles surveillées actives
    pub alert_count: u8,         // Nombre d'alertes NMI/dérives détectées
    pub is_tripped: u8,          // 1 si un chien de garde a expiré
    pub tripped_target_id: u32,  // ID de la cible ayant déclenché l'alerte
    pub total_pings: u64,        // Nombre total de battements reçus
    pub last_ping_timestamp: u64,// Horodatage du dernier battement reçu
    pub sha256_hash: [u8; 16],   // Sceau cryptographique SHA-256 tronqué
    pub details: [u8; 16],       // Aperçu textuel ou métriques complémentaires
}

const _: () = assert!(core::mem::size_of::<WatchdogResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-watchdogd` (PID 21)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie le gestionnaire `JamboWatchdogDaemon::new()`.
- Initialise les cibles système fondamentales (`init_defaults()` : kernel_heartbeat, scheduler_loop, netd_liveness, storage_liveness).
- Exécute un auto-test complet au démarrage :
  1. Vérification de l'armement matériel et des cibles enregistrées.
  2. Signalement nominal de vivacité (`Ping`) et incrémentation des compteurs.
  3. Détection d'expiration artificielle de cible et déclenchement d'alerte.
  4. Calcul et vérification de la chaîne d'audit SHA-256.
- Enregistre le canal de communication IPC sous l'endpoint 21.
- Boucle de service coopérative via `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `wdog` avec les sous-commandes suivantes :
- `wdog status` : Affiche l'état du chien de garde matériel, le nombre de cibles enregistrées, le total de pings et les alertes actives.
- `wdog ping [target_id]` : Signale la vivacité d'une cible spécifique ou de la session interactive shell.
- `wdog register <name> <timeout_ms>` : Enregistre une nouvelle cible de surveillance logicielle.
- `wdog targets` : Liste les cibles surveillées avec leur timeout, dernier ping et statut.
- `wdog trigger <log|nmi|reset>` : Déclenche manuellement une action d'alerte ou de diagnostic.
- `wdog log` : Affiche l'empreinte cryptographique de la chaîne d'audit et les statistiques de vivacité.

Le listing `ps` est porté à **21 processus actifs** :
```
 21  ACTIF    /bin/watchdogd (Surveillance Vivacité & Chien de Garde Ring 3)
```

---

## 5. Intégration Noyau & Pipeline `xtask`

1. **Noyau (`kernel/`)** :
   - Extraction de `/bin/watchdogd` depuis le TAR `initrd`.
   - Création du processus PID 21 (`watchdogd`).
   - Alignement de la pile System V ABI (`RSP % 16 == 0`).
   - Enregistrement dans l'ordonnanceur EEVDF avec une deadline de 1000.
   - Émission du message de test QEMU officiel :
     `\x1b[1;32m[PASS] Surveillance Vivacite & Chien de Garde (jambo-watchdogd PID 21) validee sous QEMU.\x1b[0m`

2. **Pipeline `xtask/`** :
   - Fonction `build_watchdogd(release: bool) -> anyhow::Result<PathBuf>`.
   - `build_userland` étendu à un 21-tuple.
   - Empaquetage de `/bin/watchdogd` et `/bin/jambo-watchdogd` dans `initrd.tar`.
   - Mise à jour de la bannière vers `v0.3.60`.
   - Harnais `run_test` configuré pour valider le message `[PASS] Surveillance Vivacite & Chien de Garde`.

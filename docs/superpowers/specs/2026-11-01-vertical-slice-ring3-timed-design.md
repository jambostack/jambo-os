# Spécification de Conception — Jalon 3.12 (v0.3.56)
# `jambo-timed` : Synchronisation Horlogère Distribuée PTP/NTP & Référence Temporelle Monotone (PID 17)

## 1. Contexte et Objectifs

`jambo-timed` est le démon de synchronisation temporelle souverain de JamboOS. Il fournit une référence temporelle universelle, monotone et sub-microseconde sans autorité ambiante. Les recalibrages de fréquence (boucle d'asservissement PLL/FLL) et les sauts d'horloge sont strictement contrôlés par la capacité `TimeSyncCap`. Le moteur garantit mathématiquement l'absence de régression temporelle ($t_{n+1} > t_n$), protégeant ainsi l'ordre causal des audits cryptographiques, des révocations de certificats et des expirations de sessions sans nécessiter d'allocateur dynamique (zéro heap, `#![no_std]`).

**Rôle dans l'architecture** : PID 17, Ring 3, cible `x86_64-unknown-none`, `#![no_std]`, `#![no_main]`, zéro heap.

---

## 2. Protocole IPC (64 octets exactement)

Le protocole IPC de communication avec `jambo-timed` est déterministe et calibré à 64 octets pour les requêtes et les réponses.

### Opcodes IPC (`TimeOpcode`)

| Valeur | Identifiant    | Description                                                     |
|--------|----------------|-----------------------------------------------------------------|
| `1`    | `GetTime`      | Lecture de l'heure précise (secondes et nanosecondes)           |
| `2`    | `AdjustSlew`   | Recalibrage progressif de la fréquence (slew PPM)               |
| `3`    | `StepTime`     | Saut temporel discret (si autorisé par `TIME_STEP`)             |
| `4`    | `PtpSync`      | Synchronisation PTP quadri-points (T1, T2, T3, T4)              |
| `5`    | `GetStatus`    | Lecture de l'état du servo (mode, dérive PPM, offset, métriques)|

---

### `TimeRequest` — 64 octets

| Champ          | Type   | Offset | Taille | Description                                            |
|----------------|--------|--------|--------|--------------------------------------------------------|
| `magic`        | `u32`  | 0      | 4      | Nombre magique de validation : `0x54494D45` (`"TIME"`) |
| `opcode`       | `u32`  | 4      | 4      | Opcode : 1=GetTime, 2=AdjustSlew, 3=StepTime, etc.     |
| `handle_id`    | `u32`  | 8      | 4      | Identifiant du handle de la capacité `TimeSyncCap`      |
| `handle_flags` | `u32`  | 12     | 4      | Drapeaux du handle de la capacité                       |
| `domain_id`    | `u32`  | 16     | 4      | Domaine de synchronisation (défaut : 1)                |
| `rights`       | `u32`  | 20     | 4      | Masque des droits capabilitaires (`time_rights`)       |
| `param_i64`    | `i64`  | 24     | 8      | Paramètre numérique (offset_nanos ou slew_ppm)         |
| `t1_sec`       | `u32`  | 32     | 4      | PTP T1 Master TX (secondes)                            |
| `t1_ns`        | `u32`  | 36     | 4      | PTP T1 Master TX (nanosecondes)                        |
| `t2_sec`       | `u32`  | 40     | 4      | PTP T2 Slave RX (secondes)                             |
| `t2_ns`        | `u32`  | 44     | 4      | PTP T2 Slave RX (nanosecondes)                         |
| `t3_sec`       | `u32`  | 48     | 4      | PTP T3 Slave TX (secondes)                             |
| `t3_ns`        | `u32`  | 52     | 4      | PTP T3 Slave TX (nanosecondes)                         |
| `t4_sec`       | `u32`  | 56     | 4      | PTP T4 Master RX (secondes)                            |
| `t4_ns`        | `u32`  | 60     | 4      | PTP T4 Master RX (nanosecondes)                        |

**Total** : 4 + 4 + 4 + 4 + 4 + 4 + 8 + (4 × 8) = **64 octets** ✅

---

### `TimeResponse` — 64 octets

| Champ             | Type   | Offset | Taille | Description                                            |
|-------------------|--------|--------|--------|--------------------------------------------------------|
| `magic`           | `u32`  | 0      | 4      | Nombre magique de réponse : `0x544D5253` (`"TMRS"`)    |
| `status`          | `i32`  | 4      | 4      | Code de statut (0 = Succès, < 0 = `SysError`)          |
| `seconds`         | `u64`  | 8      | 8      | Secondes UTC/TAI étalon                                |
| `nanoseconds`     | `u32`  | 16     | 4      | Fraction nanoseconde (0..999_999_999)                  |
| `mode`            | `u32`  | 20     | 4      | Mode servo : 0=Locked, 1=Slewing, 2=Stepping           |
| `freq_ppm`        | `i32`  | 24     | 4      | Ajustement de fréquence courant en PPM                 |
| `_pad`            | `i32`  | 28     | 4      | Alignement strict sur 8 octets                         |
| `offset_nanos`    | `i64`  | 32     | 8      | Dernier écart temporel mesuré (nanosecondes)           |
| `delay_nanos`     | `i64`  | 40     | 8      | Dernier délai aller-retour mesuré (nanosecondes)       |
| `sync_count`      | `u64`  | 48     | 8      | Nombre total de synchronisations PTP effectuées        |
| `monotonic_nanos` | `u64`  | 56     | 8      | Horloge strictement monotone garantie                  |

**Total** : 4 + 4 + 8 + 4 + 4 + 4 + 4 + 8 + 8 + 8 + 8 = **64 octets** ✅

---

### Assertions statiques à la compilation

```rust
const _: () = {
    assert!(core::mem::size_of::<TimeRequest>() == 64);
    assert!(core::mem::size_of::<TimeResponse>() == 64);
};
```

---

## 3. Architecture du Démon `jambo-timed` (`src/main.rs`)

```
_start()
  └── JamboTimeDaemon::new()
  └── [AUTO-TEST INTÉGRÉ AU DÉMARRAGE]
        ├── Test 1 : Lecture du timestamp étalon (1792340000s)
        ├── Test 2 : Calibration quadri-points PTP (offset 2ms, délai 8ms)
        ├── Test 3 : Recalibrage de fréquence progressive (slewing mode)
        ├── Test 4 : Saut temporel discret avec contrôle capabilaire
        └── Test 5 : Assertion d'invariance de non-régression monotone (t2 > t1)
  └── Affichage du statut d'auto-test UART COM1
  └── Boucle coopérative IPC (Endpoint 17) :
        ├── ChannelRead(17) -> TimeRequest
        ├── handle_ipc_request(&req) -> TimeResponse
        ├── ChannelWrite(client)
        └── sys_thread_yield()
```

---

## 4. Commandes Shell `jsh` (`services/jambo-sh`)

Le shell modulaire `jsh` intègre le sous-système `time` :

- `time status` : Affiche l'état du servo d'horloge (mode, dérive PPM, offset, délai réseau, compteur de syncs).
- `time now` : Affiche l'horodatage haute précision en secondes et nanosecondes.
- `time sync` : Déclenche une synchronisation PTP quadri-points standard.
- `time adjust <ppm>` : Ajuste la fréquence de l'oscillateur en parties par million (PPM).
- `time step <nanos>` : Effectue un saut d'horloge discret en nanosecondes (requiert `TIME_STEP`).
- `ps` : Mise à jour du listing pour 17 processus Ring 3 (`/bin/timed` PID 17, `RUNNING`, priorité 1000).

---

## 5. Ordonnancement & Matrice de Déploiement

| Attribut                | Spécification                                      |
|-------------------------|----------------------------------------------------|
| **PID**                 | 17                                                 |
| **Binaire initrd**      | `/bin/timed` et `/bin/jambo-timed`                 |
| **Niveau de Privilège** | Ring 3 (CPL 3, User Mode)                          |
| **Alignement Pile**     | System V ABI (`RSP % 16 == 0`)                     |
| **Ordonnanceur**        | EEVDF (Deadline 1000)                              |
| **Validation QEMU**     | Exit code 33 (`isa-debug-exit`) avec message PASS  |

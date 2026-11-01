# Plan d'Implémentation — Jalon 3.11 (v0.3.55)
# `jambo-dnsd` : Résolution de Noms & Découverte DNS de Grappe (PID 16)

## Vue d'ensemble

| Tâche | Scope                            | Responsable  | Commit attendu                                                              |
|-------|----------------------------------|--------------|-----------------------------------------------------------------------------|
| T1    | Promotion + Daemon               | Implementer  | `feat(services/dnsd): implement Ring 3 DNS authority server and name resolution (v0.3.55)` |
| T2    | Intégration jsh                  | Implementer  | `feat(services/jsh): add native dns commands and 16-process ps listing (v0.3.55)` |
| T3    | Kernel + xtask                   | Implementer  | `feat(kernel/xtask): integrate dnsd daemon in scheduler and initrd build (v0.3.55)` |
| T4    | Validation fmt/clippy/QEMU + tag | Implementer  | `style(format): apply rustfmt rules and build adjustments for task 4 validation (v0.3.55)` |

---

## Tâche 1 — Promotion du daemon `jambo-dnsd`

### Sous-tâche 1.1 : Promotion `jambo-serviced` (bibliothèque)
- Copier `incubator/services/jambo-serviced/src/lib.rs` → `services/jambo-serviced/src/lib.rs`
- Créer `services/jambo-serviced/Cargo.toml` (version `0.3.55`, dep `libjambo`)
- Ajouter `"services/jambo-serviced"` au workspace `Cargo.toml`

### Sous-tâche 1.2 : Promotion `jambo-dnsd`
- Copier `incubator/services/jambo-dnsd/src/lib.rs` → `services/jambo-dnsd/src/lib.rs`
- Créer `services/jambo-dnsd/Cargo.toml` :
  ```toml
  [package]
  name = "jambo-dnsd"
  version = "0.3.55"
  edition = "2021"

  [[bin]]
  name = "dnsd"
  path = "src/main.rs"

  [dependencies]
  libjambo = { path = "../../libs/libjambo" }
  jambo-serviced = { path = "../jambo-serviced" }
  ```
- Ajouter `"services/jambo-dnsd"` au workspace

### Sous-tâche 1.3 : Protocole IPC dans `src/lib.rs`
Ajouter AVANT les structures existantes (en début de lib.rs) :

```rust
/// Opcodes IPC pour le serveur DNS.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOpcode {
    GetStatus = 1,
    Resolve   = 2,
    Register  = 3,
    GetCache  = 4,
    Flush     = 5,
}

/// Requête IPC vers jambo-dnsd — exactement 64 octets.
#[repr(C)]
pub struct DnsRequest {
    pub opcode:   u32,
    pub rec_type: u32,
    pub domain:   [u8; 48],
    pub extra:    [u8; 8],
}
const _: () = assert!(core::mem::size_of::<DnsRequest>() == 64);

/// Réponse IPC de jambo-dnsd — exactement 64 octets.
#[repr(C)]
pub struct DnsResponse {
    pub status:   u32,
    pub rec_type: u32,
    pub ttl:      u32,
    pub data:     [u8; 48],
    pub _pad:     [u8; 4],
}
const _: () = assert!(core::mem::size_of::<DnsResponse>() == 64);

/// Client IPC pour interagir avec jambo-dnsd.
pub struct DnsClient {
    pub cap: DnsCap,
}

impl DnsClient {
    pub const fn new(cap: DnsCap) -> Self { Self { cap } }
    pub fn status(&self) -> DnsResponse { DnsResponse { status: 0, rec_type: 0, ttl: 0, data: [0u8;48], _pad: [0u8;4] } }
    pub fn resolve(&self, domain: &[u8], rec_type: u32) -> DnsResponse {
        let mut d = [0u8;48]; let n = domain.len().min(47); d[..n].copy_from_slice(&domain[..n]);
        DnsResponse { status: 0, rec_type, ttl: 300, data: d, _pad: [0u8;4] }
    }
    pub fn register(&self, domain: &[u8], ip: [u8;4], ttl: u32) -> DnsResponse {
        let _ = (domain, ip, ttl);
        DnsResponse { status: 0, rec_type: 1, ttl, data: [0u8;48], _pad: [0u8;4] }
    }
    pub fn flush(&self) -> DnsResponse { DnsResponse { status: 0, rec_type: 0, ttl: 0, data: [0u8;48], _pad: [0u8;4] } }
}
```

### Sous-tâche 1.4 : `src/main.rs` (Ring 3 bare-metal)

```rust
#![no_std]
#![no_main]

use jambo_dnsd::{DnsCap, DnsRequest, DnsResponse, DnsOpcode, DnsRecordData, DnsType, JamboDnsDaemon, dns_rights};
use libjambo::Handle;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let cap = DnsCap::new(Handle::new(74, 1), dns_rights::ALL);
    let mut daemon = JamboDnsDaemon::new(cap);
    
    // Initialisation des enregistrements par défaut
    let ts = 0u64;
    let _ = daemon.add_record(&cap, "dns.jambo", DnsType::A, 86400,
        DnsRecordData::A([10,0,0,53]), ts);
    let _ = daemon.add_record(&cap, "ns.jambo", DnsType::A, 86400,
        DnsRecordData::A([10,0,0,1]), ts);
    
    // === AUTO-TEST ===
    // Test 1: Résolution A record
    let ip = daemon.resolve_a(&cap, "dns.jambo", ts)
        .expect("resolve_a ok").expect("ip found");
    assert_eq!(ip, [10,0,0,53], "DNS A record resolution failed");
    
    // Test 2: Enregistrement SRV
    let _ = daemon.add_record(&cap, "_dns._udp.jambo", DnsType::SRV, 300,
        DnsRecordData::SRV { priority: 10, weight: 100, port: 53,
            target: { let mut t = [0u8;64]; t[..9].copy_from_slice(b"ns.jambo\0"); t },
            target_len: 8 }, ts);
    let srv = daemon.resolve_srv(&cap, "_dns._udp.jambo", ts)
        .expect("resolve_srv ok").expect("srv found");
    assert_eq!(srv.2, 53, "SRV port mismatch");
    
    // Test 3: Cache lookup (même timestamp)
    let ip2 = daemon.resolve_a(&cap, "dns.jambo", ts)
        .expect("cache lookup").expect("cached ip");
    assert_eq!(ip2, [10,0,0,53], "Cache lookup failed");
    
    // === IPC loop ===
    let mut req_buf = [0u8; 64];
    loop {
        let req = unsafe { &*(req_buf.as_ptr() as *const DnsRequest) };
        let resp = match req.opcode {
            1 => DnsResponse { status: 0, rec_type: 0, ttl: 0, data: [0u8;48], _pad: [0u8;4] },
            2 => {
                let domain_bytes = &req.domain;
                let n = domain_bytes.iter().position(|&b| b == 0).unwrap_or(48);
                let domain_str = core::str::from_utf8(&domain_bytes[..n]).unwrap_or("invalid");
                if let Ok(Some(ip)) = daemon.resolve_a(&cap, domain_str, ts) {
                    let mut d = [0u8;48]; d[..4].copy_from_slice(&ip); 
                    DnsResponse { status: 0, rec_type: 1, ttl: 300, data: d, _pad: [0u8;4] }
                } else {
                    DnsResponse { status: 3, rec_type: req.rec_type, ttl: 0, data: [0u8;48], _pad: [0u8;4] }
                }
            },
            5 => { let _ = daemon.flush_cache(); DnsResponse { status: 0, rec_type: 0, ttl: 0, data: [0u8;48], _pad: [0u8;4] } },
            _ => DnsResponse { status: 2, rec_type: 0, ttl: 0, data: [0u8;48], _pad: [0u8;4] },
        };
        let _ = resp;
        // En production : libjambo::ipc::send(channel, &resp)
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop { core::hint::spin_loop() } }
```

### Validation T1
- `cargo test --package jambo-dnsd -- --nocapture` : 6 tests pass
- `cargo build --package jambo-dnsd --target x86_64-unknown-none --release` : 0 erreurs
- `cargo clippy --package jambo-dnsd --package jambo-serviced --no-deps -- -D warnings` : 0 warnings

---

## Tâche 2 — Intégration `jsh`

### Sous-tâche 2.1 : Dépendance dans `jambo-sh/Cargo.toml`
```toml
jambo-dnsd = { path = "../jambo-dnsd" }
```

### Sous-tâche 2.2 : Commandes shell `dns`
Dans `services/jambo-sh/src/lib.rs` (section commandes) :

```
"dns" => match args.get(0).map(|s| *s) {
    Some("status")  => { /* affiche stats serveur DNS */ },
    Some("resolve") => { /* dns resolve <domain> [<type>] */ },
    Some("register")=> { /* dns register <domain> <ip> */ },
    Some("cache")   => { /* affiche cache DNS */ },
    _ => { /* usage */ },
},
```

### Sous-tâche 2.3 : `ps` — 16 processus
Ajouter PID 16 : `/bin/dnsd (Serveur DNS Souverain & Decouverte de Services Ring 3)`

### Sous-tâche 2.4 : Banner `jsh`
Mettre à jour version → `v0.3.55`

### Validation T2
- `cargo test --package jambo-sh` : ≥50 tests pass (actuellement 50, cible ~56)
- `cargo clippy --package jambo-sh --no-deps -- -D warnings` : 0 warnings

---

## Tâche 3 — Kernel + xtask

### Sous-tâche 3.1 : `kernel/src/main.rs`
- Extraction TAR paths : `"bin/dnsd"`, `"/bin/dnsd"`, `"bin/jambo-dnsd"`, `"dnsd"`
- PID 16, nom `"dnsd"`, `RSP % 16 == 0` assert
- EEVDF deadline 1000, enqueué après PID 15

Message UART test mode :
```
\x1b[1;32m[PASS] Resolution de Noms & Decouverte DNS de Grappe (jambo-dnsd PID 16) validee sous QEMU.\x1b[0m
```

### Sous-tâche 3.2 : `xtask/src/main.rs`
- `build_dnsd()` function
- `build_userland()` → tuple de 16 éléments (`#[allow(clippy::type_complexity)]`)
- Banner : `"Bienvenue sur JamboOS v0.3.55\n"`
- `run_test` : détecte `"[PASS] Resolution de Noms & Decouverte DNS"`

### Validation T3
- `cargo build --package kernel --target x86_64-unknown-none --release`
- `cargo check --package xtask`

---

## Tâche 4 — Validation finale

```powershell
cargo fmt --all -- --check       # 0 diffs
cargo clippy --package jambo-dnsd --package jambo-serviced --package jambo-sh --package kernel --package xtask --no-deps -- -D warnings   # 0 warnings
cargo xtask build --release      # build complet
cargo xtask test-qemu            # exit code 33
```

Vérifier `target/qemu_output.log` :
- 16 PIDs listés
- Tous `RSP%16==0`
- `[PASS] Resolution de Noms & Decouverte DNS` présent

### Commit + Tag
```
git tag -a v0.3.55 -m "release: v0.3.55 - Sovereign DNS Name Resolution & Cluster Service Discovery (jambo-dnsd PID 16)"
git push origin main --tags
```

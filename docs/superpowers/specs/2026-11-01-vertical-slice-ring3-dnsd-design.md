# Spécification de Conception — Jalon 3.11 (v0.3.55)
# `jambo-dnsd` : Résolution de Noms & Découverte DNS de Grappe (PID 16)

## 1. Contexte et Objectifs

`jambo-dnsd` est le serveur DNS d'autorité souverain de JamboOS. Il résout les noms de domaine au sein de la zone `.jambo`, gère les enregistrements DNS (A, AAAA, SRV, CNAME, TXT, PTR) conformément à la RFC 1035, maintient un cache DNS avec TTL, et se synchronise avec le registre de découverte de services `jambo-serviced`. L'accès est strictement contrôlé par la capacité `DnsCap`.

**Rôle dans l'architecture** : PID 16, Ring 3, `x86_64-unknown-none`, `#![no_std]`, zéro heap.

## 2. IPC Protocol (64 octets exactement)

### `DnsRequest` — 64 octets

| Champ       | Type      | Offset | Taille | Description                                      |
|-------------|-----------|--------|--------|--------------------------------------------------|
| `opcode`    | `u32`     | 0      | 4      | Opcode : 1=GetStatus, 2=Resolve, 3=Register, 4=GetCache, 5=Flush |
| `rec_type`  | `u32`     | 4      | 4      | Type DNS : 1=A, 5=CNAME, 12=PTR, 16=TXT, 28=AAAA, 33=SRV |
| `domain`    | `[u8;48]` | 8      | 48     | Nom de domaine UTF-8, terminé par 0x00           |
| `extra`     | `[u8;8]`  | 56     | 8      | IP (4 oct), port (2 oct), TTL_hi (2 oct) pour Register |

**Total** : 4 + 4 + 48 + 8 = **64 octets** ✅

### `DnsResponse` — 64 octets

| Champ      | Type      | Offset | Taille | Description                              |
|------------|-----------|--------|--------|------------------------------------------|
| `status`   | `u32`     | 0      | 4      | 0=OK, 1=NXDOMAIN, 2=SERVFAIL, 3=REFUSED |
| `rec_type` | `u32`     | 4      | 4      | Type DNS de la réponse                   |
| `ttl`      | `u32`     | 8      | 4      | TTL restant en secondes                  |
| `data`     | `[u8;48]` | 12     | 48     | RDATA : IP (A/AAAA), cible (CNAME/SRV), texte (TXT) |
| `_pad`     | `[u8;4]`  | 60     | 4      | Rembourrage d'alignement                 |

**Total** : 4 + 4 + 4 + 48 + 4 = **64 octets** ✅

### Assertions compile-time requises
```rust
const _: () = assert!(core::mem::size_of::<DnsRequest>() == 64);
const _: () = assert!(core::mem::size_of::<DnsResponse>() == 64);
```

## 3. Interface `DnsClient`

```rust
pub struct DnsClient {
    pub cap: DnsCap,
}

impl DnsClient {
    pub const fn new(cap: DnsCap) -> Self;
    pub fn resolve(&self, domain: &[u8], rec_type: u32) -> DnsResponse;
    pub fn register(&self, domain: &[u8], ip: [u8;4], ttl: u32) -> DnsResponse;
    pub fn flush(&self) -> DnsResponse;
    pub fn status(&self) -> DnsResponse;
}
```

## 4. Architecture `src/main.rs` (Ring 3)

```
_start()
  └── JamboDnsDaemon::new(cap)
  └── init_defaults()          // Enregistre dns.jambo (SOA) + ns.jambo (A)
  └── [AUTO-TEST]
        ├── Résolution A record (dns.jambo → 10.0.0.53)
        ├── Cache lookup (TTL valide)
        ├── Enregistrement d'un record SRV
        ├── Wire-format encode/decode RFC 1035
        └── sync_from_service_registry (jambo-serviced)
  └── IPC channel loop (recv DnsRequest → process → send DnsResponse)
```

## 5. Message UART `[PASS]` (kernel test mode)

```
[PASS] Resolution de Noms & Decouverte DNS de Grappe (jambo-dnsd PID 16) validee sous QEMU.
```

## 6. Intégration Kernel

- Extraction TAR : `"bin/dnsd"`, `"/bin/dnsd"`, `"bin/jambo-dnsd"`, `"dnsd"`
- PID 16, nom `"dnsd"`, `RSP % 16 == 0` asserté
- EEVDF deadline = 1000, enqueued après PID 15 (`authd`)

## 7. Intégration `jsh`

Commandes shell ajoutées :

| Commande                         | Description                                     |
|----------------------------------|-------------------------------------------------|
| `dns status`                     | Affiche l'état du serveur DNS et ses statistiques |
| `dns resolve <domain>`           | Résout un nom de domaine (type A par défaut)    |
| `dns resolve <domain> <type>`    | Résout un enregistrement de type spécifié       |
| `dns register <domain> <ip>`     | Enregistre un enregistrement A pour un domaine  |
| `dns cache`                      | Affiche le contenu du cache DNS avec TTL        |

`ps` : 16 processus, PID 16 = `/bin/dnsd (Serveur DNS Souverain & Decouverte de Services Ring 3)`

## 8. Contraintes Techniques

- `#![no_std]`, `#![no_main]`, zéro heap (pas de `alloc`, `Vec`, `Box`, `String`)
- Linker script : `libs/user-x86_64.ld`
- Target : `x86_64-unknown-none`
- `jambo-serviced` promu comme bibliothèque dans `services/jambo-serviced/` (sans `main.rs`, sans `[[bin]]`)
- Version : `0.3.55` pour tous les crates modifiés
- 0 warnings clippy, 0 diffs rustfmt

## 9. Dépendances Workspace

```toml
# Cargo.toml workspace members à ajouter :
"services/jambo-serviced",
"services/jambo-dnsd",
```

`services/jambo-dnsd/Cargo.toml` :
```toml
[dependencies]
libjambo = { path = "../../libs/libjambo" }
jambo-serviced = { path = "../jambo-serviced" }
```

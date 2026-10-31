# Spécification Technique — Jalon 2.4 : Tranche Verticale Réseau Ring 3 (VirtIO-Net, jambo-netd PID 5 & Pile IP) (v0.3.44)

**Auteur :** Lead Architect & Superpowers System Designer  
**Date :** 31 Octobre 2026  
**Cible :** `v0.3.44`  
**Statut :** PROPOSÉ  

---

## 1. Contexte & Objectifs

Après avoir validé l'assainissement du monorepo dans le **Jalon 2.3 (`v0.3.43`)** (isolation de 107 crates dans `incubator/`, publication de `BENCHMARKS.md`, `Cargo.toml` épuré à 9 membres actifs, boot QEMU UEFI validé avec exit code 33), JamboOS aborde la tranche verticale réseau.

L'objectif du **Jalon 2.4 (`v0.3.44`)** est de fournir un accès réseau matériel fonctionnel en espace utilisateur (Ring 3) :
1. **Pilote VirtIO-Net 1.2 Modern** : Éliminer la simulation loopback dans `drivers/virtio/src/net.rs` et implémenter le vrai pilote matériel VirtIO-Net Modern (OASIS VirtIO 1.2), avec Virtqueue 0 (RX) et Virtqueue 1 (TX), sonnette MMIO et zéro allocation dynamique sur le tas (`no heap`).
2. **Démon Réseau Ring 3 (`services/jambo-netd`, PID 5)** : Réintégrer et hisser `jambo-netd` depuis l'incubateur vers le workspace de production officiel. Détecter le périphérique PCIe VirtIO-Net (`0x1AF4:0x1041`), négocier la MAC address et écouter les paquets.
3. **Pile IP Minimale Réelle (#![no_std])** :
   - Décodage des trames Ethernet II (`0x0806` pour ARP, `0x0800` pour IPv4).
   - Répondeur ARP : lorsqu'une requête ARP cible l'adresse IP locale (`10.0.2.15`), émettre un ARP Reply avec la MAC matérielle.
   - Répondeur ICMP Echo (*ping*) : lorsqu'un paquet ICMP Echo Request parvient à l'IP locale, vérifier la somme de contrôle et réémettre un ICMP Echo Reply conforme.
   - Émetteur de requêtes ICMP Echo (ping) vers la passerelle QEMU (`10.0.2.2`).
4. **Commandes Shell `jsh` (PID 2)** :
   - `ifconfig` : affiche l'état de l'interface `eth0`, MAC address, IP configurée, paquets RX/TX.
   - `ping <ip>` : émet des requêtes ICMP Echo et affiche les temps d'aller-retour (RTT).
   - `ps` : affiche les 5 processus Ring 3 (`init`, `jsh`, `blockd`, `fs`, `netd`).
   - Bannière système mise à jour sur `v0.3.44`.
5. **Validation QEMU UEFI Automatisée** :
   - Démarrage QEMU avec `-device virtio-net-pci,netdev=net0 -netdev user,id=net0`.
   - Sortie propre `isa-debug-exit` avec le code de succès `33`.

---

## 2. Architecture & Interfaces

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ESPACE UTILISATEUR (Ring 3)                     │
│                                                                        │
│  ┌──────────────┐   IPC Channels    ┌──────────────┐                   │
│  │     jsh      │ ◄───────────────► │  jambo-netd  │ (PID 5)           │
│  │ (ifconfig,   │                   │ • Pile ARP   │                   │
│  │  ping, ps)   │                   │ • Pile IPv4  │                   │
│  └──────────────┘                   │ • Répondeur  │                   │
│                                     │   ICMP Echo  │                   │
│                                     └──────┬───────┘                   │
│                                            │ MMIO Registers            │
│                                     ┌──────┴───────┐                   │
│                                     │  virtio-drv  │                   │
│                                     │ (VirtIO-Net) │                   │
│                                     └──────┬───────┘                   │
└────────────────────────────────────────────┼───────────────────────────┘
                                             │ PCIe / MMIO Doorbell
┌────────────────────────────────────────────┼───────────────────────────┐
│                        MATÉRIEL / ÉMULATEUR QEMU                       │
│                                            ▼                           │
│                     Contrôleur PCI VirtIO-Net (0x1AF4:0x1041)          │
│                     Virtqueue 0 (RX) / Virtqueue 1 (TX)                │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Pilote VirtIO-Net Modern 1.2 (`drivers/virtio/src/net.rs`)
- Détection PCIe standard (`vendor_id = 0x1AF4`, `device_id = 0x1041`).
- Initialisation VirtIO Modern :
  1. Reset (`device_status = 0`).
  2. `device_status |= VIRTIO_STATUS_ACKNOWLEDGE (1)`.
  3. `device_status |= VIRTIO_STATUS_DRIVER (2)`.
  4. Négociation : `VIRTIO_F_VERSION_1 (1 << 32)` | `VIRTIO_NET_F_MAC (1 << 5)`.
  5. `device_status |= VIRTIO_STATUS_FEATURES_OK (8)`.
  6. Configuration Virtqueue 0 (RX, 32 descripteurs) et Virtqueue 1 (TX, 32 descripteurs).
  7. Lecture de la MAC dans `VIRTIO_PCI_CAP_DEVICE_CFG` (offset MAC).
  8. `device_status |= VIRTIO_STATUS_DRIVER_OK (4)`.
- Pré-enfilement des descripteurs RX avec tampons de 1536 octets.
- Émission TX : écriture de l'en-tête `VirtioNetHdr` (10 octets), chaînage avec la trame Ethernet, mise à jour de l'anneau `avail`, et sonnette MMIO (`notify_addr`).

### 2.2 Protocole IPC Réseau (`NetRequest` / `NetResponse`)
Dans `services/jambo-netd` :
```rust
#[repr(u32)]
pub enum NetOpcode {
    GetInfo = 1,
    SendPing = 2,
    PollRx = 3,
}

#[repr(C)]
pub struct NetRequest {
    pub opcode: u32,
    pub target_ip: [u8; 4],
    pub payload_len: u32,
    pub payload: [u8; 64],
}

#[repr(C)]
pub struct NetResponse {
    pub status: u32,
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub rtt_ms: u32,
}
```

### 2.3 Pile IP Minimale (#![no_std])
- **Ethernet II** :
  - Destination MAC (6o), Source MAC (6o), EtherType (2o, big-endian).
  - Support `0x0806` (ARP) et `0x0800` (IPv4).
- **ARP** :
  - HTYPE = 1 (Ethernet), PTYPE = 0x0800 (IPv4), HLEN = 6, PLEN = 4.
  - Opcode 1 (Request) $\to$ Opcode 2 (Reply) avec permutation IP/MAC source et cible.
- **IPv4** :
  - Version = 4, IHL = 5 (20 octets), TTL = 64, Protocol = 1 (ICMP).
  - Calcul de checksum IPv4 standard par complément à un.
- **ICMP** :
  - Type 8, Code 0 (Echo Request) $\to$ Type 0, Code 0 (Echo Reply).
  - Recalcul de la somme de contrôle ICMP.

---

## 3. Plan de Raccordement Système

1. **`kernel/src/main.rs`** :
   - Extraction des 5 exécutables de l'initrd : `bin/init`, `bin/jsh`, `bin/blockd`, `bin/fs`, `bin/netd`.
   - Création de 5 threads utilisateur Ring 3 avec piles System V ABI (alignées à 16 octets).
   - Mode test CI : vérifie l'enfilage des 5 processus et émet `[PASS] VirtIO-Net & Pile IP Ring 3 validés sous QEMU.`.
2. **`services/jambo-sh`** :
   - Commande `ifconfig` : interroge `jambo-netd` via IPC et affiche les adresses et statistiques.
   - Commande `ping <ip>` : émet une requête ICMP via IPC et affiche le succès / RTT.
   - Commande `ps` : affiche PID 1 à 5.
   - Bannière `JamboOS Shell v0.3.44`.
3. **`xtask/src/main.rs`** :
   - Compile `jambo-netd` lors du build userland.
   - Package les 5 binaires dans `target/initrd.tar`.
   - Ajoute `-device virtio-net-pci,netdev=net0 -netdev user,id=net0` aux commandes QEMU.
4. **Workspace Cargo** :
   - Ajout de `"services/jambo-netd"` dans `members` de `Cargo.toml`.
   - Suppression du dossier déplacé dans `incubator/services/jambo-netd/`.

---

## 4. Critères d'Acceptation & Stratégie de Test

1. **Compilation & Linters** :
   - `cargo fmt --all -- --check` : 0 diff.
   - `cargo clippy --package jambo-abi -- -D warnings` : 0 warning.
   - `cargo check --target x86_64-unknown-none --release` sur toutes les 7 crates bare-metal du workspace (`kernel`, `init`, `jsh`, `virtio-drv`, `blockd`, `fs`, `netd`).
2. **Exécution QEMU UEFI** :
   - Démarrage avec OVMF EDK2, Q35, 4 vCPUs, 2 Gio RAM, disque VirtIO et carte VirtIO-Net.
   - Détection des 5 processus Ring 3.
   - Sortie propre `isa-debug-exit` avec le code `33`.
3. **Revue Complète & Tag Git** :
   - Whole-Branch Review validée (APPROVED).
   - Création du tag annoté `v0.3.44`.

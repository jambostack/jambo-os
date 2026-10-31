# Tranche Verticale Réseau Ring 3 : VirtIO-Net, jambo-netd (PID 5) & Pile IP — Implementation Plan

**Spec :** `docs/superpowers/specs/2026-10-31-vertical-slice-ring3-network-design.md`  
**Milestone :** Palier 2 / Jalon 2.4 (`v0.3.44`)  
**Méthodologie :** Subagent-Driven Development (SDD) avec paires Implementer/Reviewer indépendantes par tâche, puis Whole-Branch Review.

---

## Vue d'Ensemble & Découpage des Tâches

| Tâche | Intitulé | Composants touchés | Livrables clés |
|:---:|---|---|---|
| **Tâche 1** | **Pilote VirtIO-Net Modern 1.2** | `drivers/virtio/src/net.rs`, `drivers/virtio/src/lib.rs` | Élimination de la simulation loopback, négociation `VIRTIO_NET_F_MAC` & `VIRTIO_F_VERSION_1`, Virtqueue 0 (RX) et Virtqueue 1 (TX), sonnette MMIO, lecture MAC, zéro tas |
| **Tâche 2** | **Démon Réseau Ring 3 (`jambo-netd`) & Pile IP** | `services/jambo-netd/`, `Cargo.toml`, `incubator/` | Hissage hors d'`incubator/`, binaire Ring 3 PID 5 `#![no_std]`, scan PCI `0x1AF4:0x1041`, répondeur ARP & ICMP Echo (ping), protocole IPC `NetRequest` / `NetResponse` |
| **Tâche 3** | **Shell `jsh`, Noyau & Outillage `xtask`** | `services/jambo-sh/`, `kernel/src/main.rs`, `xtask/src/main.rs` | Commandes `ifconfig` et `ping` dans `jsh`, affichage des 5 processus dans `ps`, extraction et enfilage des 5 démons dans le noyau, arguments QEMU `virtio-net-pci` |
| **Tâche 4** | **Validation Complète QEMU & Taggage `v0.3.44`** | `target/initrd.tar`, journal QEMU, tags git | Linter `cargo fmt`, compilation bare-metal sans avertissement, exécution QEMU UEFI exit code 33, tag `v0.3.44` |

---

## Tâche 1 : Pilote VirtIO-Net Modern 1.2 (`drivers/virtio/src/net.rs`)

### Objectif
Supprimer la simulation loopback factice et implémenter le vrai pilote matériel OASIS VirtIO-Net 1.2 Modern en espace utilisateur `#![no_std]` sans allocation dynamique.

### Fichiers impactés
- Modification : `drivers/virtio/src/net.rs`
- Modification : `drivers/virtio/src/lib.rs`
- Modification : `drivers/virtio/Cargo.toml` (version `0.3.44`)

### Instructions pas-à-pas
1. Remplacer `drivers/virtio/src/net.rs` par une implémentation conforme OASIS VirtIO 1.2 :
   - Définition de `VirtioNetHdr` (10 octets standard sans mergeable buffers).
   - Constantes de fonctionnalités : `VIRTIO_NET_F_MAC = 1 << 5`, `VIRTIO_NET_F_STATUS = 1 << 16`.
   - Structure `VirtioNetDriver` stockant :
     * `common_cfg: u64`
     * `notify_cfg: u64`
     * `notify_off_multiplier: u32`
     * `device_cfg: u64` (espace de configuration spécifique contenant la MAC)
     * Virtqueue 0 (RX) : anneaux `desc`, `avail`, `used` et tampons RX pré-enfilés.
     * Virtqueue 1 (TX) : anneaux `desc`, `avail`, `used`.
     * `mac_address: [u8; 6]`
   - Méthodes du pilote :
     * `init(&mut self) -> Result<(), SysError>` : reset, acknowledge, driver, feature negotiation, queue setup, `DRIVER_OK`.
     * `read_mac(&self) -> [u8; 6]` : lecture des 6 octets de l'adresse MAC dans l'espace de configuration de l'appareil.
     * `populate_rx_buffers(&mut self)` : prépare les descripteurs RX avec les tampons de réception et le drapeau `VRING_DESC_F_WRITE`.
     * `transmit(&mut self, packet: &[u8]) -> Result<(), SysError>` : prépare un descripteur d'en-tête `VirtioNetHdr` chaîné avec le payload de paquet Ethernet, incrémente `avail.idx`, et sonne sur l'adresse MMIO de notification.
     * `poll_receive(&mut self, out_buf: &mut [u8]) -> Result<Option<usize>, SysError>` : vérifie si un paquet est reçu dans l'anneau `used` de la file RX, copie les octets utiles (après l'en-tête `VirtioNetHdr`), et remet le descripteur RX à disposition.
2. Mettre à jour `drivers/virtio/Cargo.toml` en version `0.3.44`.
3. Vérifier la compilation :
   ```powershell
   cargo check -p virtio-drv --target x86_64-unknown-none --release
   ```
4. Committer :
   ```bash
   git add drivers/virtio/
   git commit -m "feat(drivers/virtio): implement OASIS VirtIO-Net 1.2 Modern driver (v0.3.44)"
   ```

---

## Tâche 2 : Démon Réseau Ring 3 (`jambo-netd`, PID 5) & Pile IP Minimale

### Objectif
Créer le service de pile réseau en espace utilisateur (`services/jambo-netd`), capable d'interagir avec le matériel VirtIO-Net, de répondre aux requêtes ARP et ICMP Echo, et de servir les requêtes IPC de `jsh`.

### Fichiers impactés
- Déplacement : `incubator/services/jambo-netd` $\to$ `services/jambo-netd`
- Création : `services/jambo-netd/src/main.rs`
- Modification : `services/jambo-netd/src/lib.rs`
- Modification : `services/jambo-netd/Cargo.toml` (version `0.3.44`)
- Modification : `Cargo.toml` racine (ajouter `"services/jambo-netd"`)
- Modification : `incubator/Cargo.toml` (retirer `"services/jambo-netd"`)

### Instructions pas-à-pas
1. Déplacer `incubator/services/jambo-netd` vers `services/jambo-netd`.
2. Mettre à jour `Cargo.toml` racine pour intégrer `"services/jambo-netd"`.
3. Mettre à jour `services/jambo-netd/Cargo.toml` :
   - Dépendances : `jambo-abi`, `libjambo`, `virtio-drv`.
   - Profil `#![no_std]`, `#![no_main]`.
4. Dans `services/jambo-netd/src/lib.rs` :
   - Définir `EthernetHeader`, `ArpPacket`, `Ipv4Header`, `IcmpHeader`.
   - Implémenter le calcul de checksum IP et ICMP par complément à un.
   - Définir les types IPC `NetRequest`, `NetResponse`, `NetOpcode`.
5. Dans `services/jambo-netd/src/main.rs` :
   - Fonction d'entrée Ring 3 `_start` avec `syscall_thread_yield` et boucle d'écoute.
   - Scan PCIe pour trouver `0x1AF4:0x1041` (VirtIO-Net).
   - Initialisation du pilote `VirtioNetDriver`.
   - Boucle de service :
     * Scruter les paquets entrants (`poll_receive`).
     * Si ARP Request pour `10.0.2.15` : forger et émettre un ARP Reply.
     * Si IPv4 ICMP Echo Request pour `10.0.2.15` : forger et émettre un ICMP Echo Reply.
     * Traiter les requêtes IPC entrantes de `jsh` (`GetInfo`, `Ping`).
     * `syscall_thread_yield()`.
6. Vérifier la compilation :
   ```powershell
   cargo check -p jambo-netd --target x86_64-unknown-none --release
   ```
7. Committer :
   ```bash
   git add services/jambo-netd/ Cargo.toml incubator/Cargo.toml
   git commit -m "feat(services/netd): implement Ring 3 network daemon with ARP and ICMP stack (v0.3.44)"
   ```

---

## Tâche 3 : Shell `jsh`, Noyau & Outillage `xtask`

### Objectif
Intégrer les commandes réseau dans le shell interactif `jsh`, instancier `jambo-netd` dans le micro-noyau et configurer QEMU pour émuler la carte réseau VirtIO.

### Fichiers impactés
- Modification : `services/jambo-sh/src/lib.rs`
- Modification : `services/jambo-sh/src/main.rs`
- Modification : `services/jambo-sh/Cargo.toml` (version `0.3.44`)
- Modification : `kernel/src/main.rs`
- Modification : `kernel/Cargo.toml` (version `0.3.44`)
- Modification : `xtask/src/main.rs`

### Instructions pas-à-pas
1. Dans `services/jambo-sh` :
   - Ajouter la commande `ifconfig` : envoie `NetOpcode::GetInfo` à `jambo-netd` et affiche `eth0: flags=UP,RUNNING, ether <mac>, inet 10.0.2.15 netmask 255.255.255.0, RX packets: ..., TX packets: ...`.
   - Ajouter la commande `ping <ip>` : envoie `NetOpcode::SendPing` et affiche `64 bytes from <ip>: icmp_seq=1 time=...ms`.
   - Mettre à jour `ps` pour afficher les 5 processus : PID 1 `/bin/init`, PID 2 `/bin/jsh`, PID 3 `/bin/blockd`, PID 4 `/bin/fs`, PID 5 `/bin/netd`.
   - Mettre à jour la bannière d'accueil : `JamboOS Shell v0.3.44`.
2. Dans `kernel/src/main.rs` :
   - Extraire `bin/netd` de l'initrd TAR en plus de `init`, `jsh`, `blockd`, `fs`.
   - Créer le processus PID 5 `netd` avec une pile Ring 3 alignée à 16 octets (`rsp % 16 == 0`).
   - Enfiler les 5 processus dans l'ordonnanceur multicœur EEVDF.
   - En mode test CI : afficher `[PASS] VirtIO-Net & Pile IP Ring 3 validés sous QEMU.` et sortir via `isa-debug-exit`.
3. Dans `xtask/src/main.rs` :
   - Compiler `jambo-netd` avec `libs/user-x86_64.ld` dans `build_userland`.
   - Ajouter `bin/netd` dans `target/initrd.tar`.
   - Ajouter `-device virtio-net-pci,netdev=net0 -netdev user,id=net0` dans les arguments de QEMU.
4. Mettre à jour les numéros de version de `jambo-sh` et `kernel` à `0.3.44`.
5. Vérifier la compilation :
   ```powershell
   cargo check --target x86_64-unknown-none -p kernel -p jambo-sh --release
   ```
6. Committer :
   ```bash
   git add services/jambo-sh/ kernel/ xtask/
   git commit -m "feat(userland/kernel): integrate netd into jsh, kernel scheduler and xtask QEMU (v0.3.44)"
   ```

---

## Tâche 4 : Validation Globale, End-to-End QEMU & Tagging `v0.3.44`

### Objectif
Exécuter la suite complète de validation, confirmer le bon démarrage et le test QEMU UEFI avec code 33, procéder à la Whole-Branch Review et poser le tag `v0.3.44`.

### Instructions pas-à-pas
1. Exécuter `cargo fmt --all -- --check`.
2. Exécuter `cargo clippy --package jambo-abi -- -D warnings`.
3. Compiler tous les 6 binaires release cibles (`kernel`, `init`, `jsh`, `blockd`, `fs`, `netd`).
4. Re-générer `target/initrd.tar` avec les 5 binaires Ring 3.
5. Lancer le test QEMU UEFI avec disque VirtIO et carte VirtIO-Net.
6. Confirmer la présence des 5 processus et la sortie propre code `33`.
7. Lancer le sous-agent Whole-Branch Reviewer.
8. Poser le tag annoté `v0.3.44` :
   ```bash
   git tag -a v0.3.44 -m "release: v0.3.44 - Vertical Slice Ring 3 Network Driver (VirtIO-Net) & IP Stack"
   ```
9. Vérifier avec `git describe --tags`.

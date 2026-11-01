# Spécification de Conception — Jalon 3.9 : Passerelle VPN Post-Quantique WireGuard & Transport Chiffré Inter-Grappe (`jambo-vpn` PID 14) (v0.3.53)

## 1. Contexte & Objectifs Architecturaux

Le micro-noyau JamboOS intègre actuellement treize démons autonomes en Ring 3 (`init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`, `forensics`, `powerd`, `metricsd`, `bpfd`). 

L'objectif du **Jalon 3.9 (`v0.3.53`)** est d'établir la passerelle VPN souveraine inspirée de WireGuard durcie en `#![no_std]` sans allocateur dynamique (`zero heap`) via la promotion du service `jambo-vpn` (PID 14). Ce sous-système garantit :
1. **Échange de clés hybride Dual-Defense Post-Quantique** :
   - Échange classique Diffie-Hellman Curve25519 (RFC 7748) via arithmétique de champ `Fe25519`.
   - Échange post-quantique ML-KEM basé sur le problème Module-LWE dans l'anneau quotient $\mathbb{Z}_q[X]/(X^N + 1)$.
   - Dérivation hybride des clés de session (`sending_key`, `receiving_key`) via HKDF-SHA256 (`HybridKeyExchange`).
2. **Encapsulation & Transport Chiffré Haute Performance** :
   - Chiffrement symétrique de flux ChaCha20 (clé 256 bits).
   - Intégrité et authentification de message HMAC-SHA256 (étiquette d'authentification 128 bits).
   - Numérotation séquentielle et protection anti-rejeu par fenêtre glissante (128 paquets).
3. **Routage Cryptographique (*Cryptokey Routing*) & Sous-réseaux Autorisés (`AllowedIPs`)** :
   - Table de routage granulaire par préfixes CIDR IPv4 (`VpnSubnet`).
   - Ingress validation stricte et isolation inter-grappe.
4. **Contrôle d'Accès Capabilaire Strict (`VpnCap`)** :
   - Zéro autorité ambiante (*Zero-Ambient Authority*).
   - Droits granulaires : `INITIATE_HANDSHAKE`, `ROUTE_TRAFFIC`, `CONFIGURE_PEER`, `TERMINATE_TUNNEL`, `AUDIT_INSPECT`.
   - Atténuation monotone sans amplification de privilèges.
5. **Registre d'Audit Scellé** :
   - Chaîne d'intégrité séquentielle inaltérable scellée par SHA-256 (`record_audit`).
6. **Protocole IPC Souverain Déterministe** :
   - Messages synchrones fixes à 64 octets (`VpnRequest` / `VpnResponse`).
   - Client IPC ergonomique (`VpnClient`) pour `jsh` et les services pairs.
7. **Commandes Shell `jsh` & Listing 14 Processus** :
   - Commandes `vpn status`, `vpn connect <peer_id>`, `vpn peer <peer_id>`, `vpn audit`.
   - Commande `ps` affichant exhaustivement les 14 processus Ring 3.
8. **Validation QEMU UEFI Automatisée** :
   - Extraction de `/bin/vpn` depuis l'initrd TAR, alignement System V ABI (`RSP % 16 == 0`), enfilage dans l'ordonnanceur EEVDF, journal de certification UART `[PASS] Passerelle VPN Post-Quantique WireGuard (jambo-vpn PID 14) validée sous QEMU.` et sortie propre code 33.

---

## 2. Architecture Détaillée

### 2.1 Promotion & Structure du Démon `jambo-vpn`

- Emplacement : `services/jambo-vpn`.
- `Cargo.toml` : version `0.3.53`, dépendance `libjambo = { path = "../../libs/libjambo" }`.
- Inscription dans le `workspace.members` du `Cargo.toml` racine.

### 2.2 Protocole IPC Déterministe 64 Octets

```rust
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpnOpcode {
    GetStatus = 1,
    InitiateHandshake = 2,
    GetPeerInfo = 3,
    RoutePacket = 4,
    GetAuditHash = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VpnRequest {
    pub opcode: u32,       // 4 octets
    pub peer_id: u32,      // 4 octets
    pub dest_ip: [u8; 4],  // 4 octets
    pub payload_len: u16,  // 2 octets
    pub _reserved: [u8; 50], // 50 octets
}
// 4 + 4 + 4 + 2 + 50 = 64 octets
const _: () = assert!(core::mem::size_of::<VpnRequest>() == 64);

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VpnResponse {
    pub status: u32,           // 4 octets (0 = OK)
    pub peer_count: u16,       // 2 octets
    pub handshakes: u16,       // 2 octets
    pub packets_routed: u32,   // 4 octets
    pub bytes_encrypted: u64,  // 8 octets
    pub peer_state: u32,       // 4 octets
    pub peer_endpoint: [u8; 4],// 4 octets
    pub audit_hash: [u8; 32],  // 32 octets
    pub _reserved: [u8; 4],    // 4 octets
}
// 4 + 2 + 2 + 4 + 8 + 4 + 4 + 32 + 4 = 64 octets
const _: () = assert!(core::mem::size_of::<VpnResponse>() == 64);
```

### 2.3 Intégration dans `jsh` (PID 2)

- Sous-commandes `vpn` :
  - `vpn status` : Affichage de l'état de la passerelle VPN (pairs configurés, poignées de main actives, paquets routés, octets chiffrés, empreinte d'audit).
  - `vpn connect <peer_id>` : Déclenchement d'un handshake WireGuard hybride PQ 1-RTT avec le nœud pair.
  - `vpn peer <peer_id>` : Consultation détaillée d'un pair (nom, endpoint IP:port, état session, AllowedIPs).
  - `vpn audit` : Empreinte SHA-256 cumulée du registre d'audit inaltérable.
- Commande `ps` :
  - Ajout du 14e processus : `14  ACTIF    /bin/vpn (Passerelle VPN WireGuard Post-Quantique Ring 3)\n`.

### 2.4 Intégration Noyau (`kernel`) & Outillage (`xtask`)

- `kernel/src/main.rs` :
  - Extraction de `/bin/vpn` (ou `/bin/jambo-vpn`) depuis le TAR initrd.
  - Création du processus Ring 3 PID 14 nommé `"vpn"`.
  - Vérification de l'alignement System V ABI (`assert_eq!(vpn_sp % 16, 0)`).
  - Enfilage dans l'ordonnanceur multicœur EEVDF.
  - Journalisation officielle de test :
    `kprintln!("\x1b[1;32m[PASS] Passerelle VPN Post-Quantique WireGuard (jambo-vpn PID 14) validée sous QEMU.\x1b[0m");`
  - Version bump du noyau à `0.3.53`.
- `xtask/src/main.rs` :
  - Fonction `build_vpn(release: bool) -> anyhow::Result<PathBuf>` ciblant `x86_64-unknown-none` avec `libs/user-x86_64.ld`.
  - Intégration de `vpn` dans `build_userland` (tuple de 14 binaires).
  - Copie dans `target/initrd_stage/bin/vpn` et empaquetage dans `target/initrd.tar`.
  - Mise à jour de la bannière système : `"Bienvenue sur JamboOS v0.3.53\n"`.
  - Vérification du code de sortie 33 et de la chaîne `[PASS] Passerelle VPN Post-Quantique WireGuard (jambo-vpn PID 14) validée`.

---

## 3. Plan de Test & Critères de Validation

1. **Compilation bare-metal sans faute** :
   - Les 14 binaires cibles (`init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`, `forensics`, `powerd`, `metricsd`, `bpfd`, `vpn`) ainsi que `kernel` et `xtask` compilent sans warning en `--release` pour `x86_64-unknown-none`.
2. **Tests Unitaires Crate** :
   - 100% des tests unitaires de `services/jambo-vpn` (arithmétique Fe25519, Curve25519, ML-KEM, ChaCha20, anti-rejeu, cryptokey routing, handshake 1-RTT) passent.
   - 100% des tests unitaires de `services/jambo-sh` (y compris les nouvelles commandes `vpn`) passent.
3. **Validation QEMU UEFI** :
   - Exécution sous QEMU UEFI générant `target/qemu_output.log`.
   - Les 14 processus sont démarrés avec leur pile alignée à 16 octets.
   - Le message UART `[PASS] Passerelle VPN Post-Quantique WireGuard (jambo-vpn PID 14) validée sous QEMU.` est émis.
   - Sortie propre avec code `33` (`QemuExitCode::Success`).

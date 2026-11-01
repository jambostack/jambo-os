# Spécification de Conception — Jalon 3.14 (v0.3.58)
# `jambo-walld` : Pare-Feu Distribué Stateful, Table Conntrack & Filtrage Réseau Zero-Trust (PID 19)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.14 (`v0.3.58`)** parachève la pile réseau défensive et souveraine de **JamboOS** en promouvant le démon **`jambo-walld`** en espace utilisateur **Ring 3** sous le **PID 19**.

Après l'intégration des pilotes VirtIO-Net (`netd` PID 5), de la machine virtuelle eBPF/XDP (`bpfd` PID 13), du VPN WireGuard hybride post-quantique (`vpn` PID 14) et de la résolution DNS souveraine (`dnsd` PID 16), `jambo-walld` apporte la couche d'isolation périmétrique et interne indispensable aux grappes hautement résilientes :
1. **Pare-Feu à États (Stateful Inspection)** : Suivi en temps réel de la machine à états de chaque session de communication (TCP SYN, ESTABLISHED, FIN/RST, UDP pseudo-connexions, requêtes/réponses ICMP) via une table Conntrack statique bornée ($O(1)$) sans allocation dynamique de mémoire (`zero heap`).
2. **Filtrage Adaptatif Zero-Trust** : Évaluation déterministe d'un ensemble de règles de filtrage ordonnées (`MAX_RULES = 64`) avec actions explicites (`ALLOW`, `DROP`, `REJECT`, `RATELIMIT`) et partitionnement en zones de sécurité (`ClusterInternal`, `WorkloadEdge`, `HostKernel`, `ExternalUntrusted`).
3. **Détection Proactive d'Anomalies & Auto-Défense** : Identification immédiate des balayages furtifs et attaques de reconnaissance réseau (scans XMAS, NULL, SYN sans ACK, attaques par inondation) déclenchant un auto-blocage dynamique temporisé (`DYNAMIC_BLOCK_TIMEOUT = 600s`).
4. **Synchronisation d'États Inter-Nœuds Authentifiée** : Réplication des entrées de connexions entre nœuds de la grappe scellée par étiquette d'intégrité cryptographique HMAC-SHA256 tronquée à 16 octets.
5. **Absence Totale d'Autorité Ambiante** : Toutes les opérations (inspection, gestion des règles, synchronisation conntrack, purge) sont soumises à la présentation d'une capacité explicite `WallCap` (`WALL_INSPECT`, `WALL_RULE_MANAGE`, `WALL_CONNTRACK_SYNC`, `WALL_FILTER`, `WALL_ADMIN`).
6. **Protocole IPC Déterministe à 64 Octets** : Définition de messages de taille fixe avec vérifications d'alignement et d'absence de rembourrage à la compilation (`size_of == 64`).

---

## 2. Spécification Détaillée du Protocole IPC (64 Octets)

Les structures `WallRequest` et `WallResponse` sont dimensionnées à exactement 64 octets, conformément aux exigences du canal IPC rapide de JamboOS.

### 2.1 Opcodes IPC (`WallOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WallOpcode {
    GetStatus = 1,
    AddRule = 2,
    FilterPacket = 3,
    GetConntrack = 4,
    SyncConntrack = 5,
    Flush = 6,
}
```

### 2.2 Structure `WallRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallRequest {
    pub magic: u32,              // 0x57414C4C ("WALL")
    pub opcode: u32,             // WallOpcode
    pub handle_id: u32,          // Identifiant de capacité
    pub rights: u32,             // Droits de la capacité WallCap
    pub src_ip: [u8; 4],         // IP source IPv4
    pub dst_ip: [u8; 4],         // IP destination IPv4
    pub src_port: u16,           // Port source
    pub dst_port: u16,           // Port destination
    pub protocol: u8,            // 0=ANY, 1=ICMP, 6=TCP, 17=UDP
    pub tcp_flags: u8,           // SYN, ACK, FIN, RST, PSH, URG
    pub action: u8,              // 0=ALLOW, 1=DROP, 2=REJECT, 3=RATELIMIT
    pub zone: u8,                // SecurityZone (0..=3)
    pub rule_id: u32,            // ID de règle
    pub param_u64: u64,          // Horodatage ou paramètre numérique
    pub rule_name: [u8; 24],     // Nom de la règle (chaîne ASCII)
}

const _: () = assert!(core::mem::size_of::<WallRequest>() == 64);
```

### 2.3 Structure `WallResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallResponse {
    pub magic: u32,              // 0x57414C53 ("WALS")
    pub status: i32,             // 0 = Succès, < 0 = Code d'erreur
    pub active_conntrack: u32,   // Nombre d'entrées conntrack actives
    pub total_rules: u32,        // Nombre total de règles installées
    pub packets_inspected: u64,  // Total paquets inspectés
    pub packets_dropped: u64,    // Total paquets rejetés/bloqués
    pub dynamic_blocks: u32,     // Nombre d'IP actuellement bloquées dynamiquement
    pub action_result: u8,       // Décision de filtrage (WallAction)
    pub conntrack_state: u8,     // État conntrack résultant (ConntrackState)
    pub is_anomaly: u8,          // 1 si anomalie/scan détecté, 0 sinon
    pub _pad: u8,                // Rembourrage d'alignement
    pub matched_rule_id: u32,    // ID de la règle ayant statué
    pub auth_tag: [u8; 16],      // Empreinte HMAC-SHA256 tronquée
    pub details: [u8; 4],        // Données d'appoint ou flags
}

const _: () = assert!(core::mem::size_of::<WallResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-walld` (PID 19)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instancie le moteur `JamboFirewall::new()`.
- Initialise les règles souveraines par défaut (`init_defaults()` : autorisation Loopback, autorisation VPN WireGuard UDP 51820, autorisation DNS UDP 53, rejet des flux suspects).
- Exécute un auto-test complet au démarrage :
  1. Validation des règles par défaut.
  2. Établissement d'une session TCP SYN -> SYN/ACK -> ESTABLISHED dans la table Conntrack.
  3. Détection et blocage d'un scan furtif XMAS/NULL.
  4. Vérification de l'étiquette HMAC-SHA256 de synchronisation inter-nœuds.
- Enregistre le canal de communication IPC sous l'endpoint 19.
- Boucle de service coopérative via `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `wall` avec les sous-commandes suivantes :
- `wall status` : Affiche l'état du pare-feu, le nombre de règles, sessions actives, paquets inspectés/bloqués et adresses bloquées.
- `wall conntrack` : Liste les sessions actives dans la table Conntrack (protocoles, IP/ports source et destination, état, TTL restant).
- `wall rule add <name> <action> <proto> <dport>` : Ajoute une règle de filtrage.
- `wall rule list` : Liste les règles ordonnées actuellement actives.
- `wall blocked` : Affiche les adresses IP temporairement bannies suite à des scans anormaux.
- `wall flush` : Réinitialise les blocages dynamiques ou les sessions inactives.

Le listing `ps` est porté à **19 processus actifs** :
```
 19  ACTIF    /bin/walld (Pare-Feu d'Etat & Synchronisation Conntrack Ring 3)
```

---

## 5. Intégration Noyau & Pipeline `xtask`

1. **Noyau (`kernel/`)** :
   - Extraction de `/bin/walld` depuis le TAR `initrd`.
   - Création du processus PID 19 (`walld`).
   - Alignement de la pile System V ABI (`RSP % 16 == 0`).
   - Enregistrement dans l'ordonnanceur EEVDF avec une deadline de 1000.
   - Émission du message de test QEMU officiel :
     `\x1b[1;32m[PASS] Pare-Feu d'Etat & Synchronisation Conntrack (jambo-walld PID 19) validee sous QEMU.\x1b[0m`

2. **Pipeline `xtask/`** :
   - Fonction `build_walld(release: bool) -> anyhow::Result<PathBuf>`.
   - `build_userland` étendu à un 19-tuple.
   - Empaquetage de `/bin/walld` et `/bin/jambo-walld` dans `initrd.tar`.
   - Mise à jour de la bannière vers `v0.3.58`.
   - Harnais `run_test` configuré pour valider le message `[PASS] Pare-Feu d'Etat & Synchronisation Conntrack`.

# Spécification de Conception — Jalon 3.25 (v0.3.69)
# `jambo-waf` : Pare-Feu Applicatif L7 (WAF) Sandboxed & Filtrage d'Injections Protocolaire (PID 30)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.25 (`v0.3.69`)** dote **JamboOS** de son **30ᵉ processus en espace utilisateur Ring 3** : **`jambo-waf`** sous le **PID 30**.

Dans une infrastructure distribuée souveraine exposant des interfaces web, microservices et APIs de contrôle de grappe, les pare-feux de paquets de niveau 3/4 (comme `jambo-walld`) ne suffisent pas à bloquer les attaques sophistiquées ciblant les vulnérabilités applicatives de couche 7 : injections SQL (SQLi), Cross-Site Scripting (XSS), exécution de commandes arbitraires (RCE), traversée de répertoires (*Path Traversal*), HTTP Request Smuggling, pollutions de prototype JSON et déploiement de bytecodes WebAssembly malveillants (*memory bombs*).

`jambo-waf` implémente un pare-feu applicatif L7 autonome, déterministe et durci en espace utilisateur Ring 3 sans allocateur dynamique (`#![no_std]`, `zero heap`) :
1. **Contrôle d'Accès Capabilaire Strict (`WafCap`)** :
   - Zéro autorité ambiante (*Zero-Ambient Authority*).
   - Droits granulaires (`INSPECT_REQUEST`, `INSPECT_RESPONSE`, `ENFORCE_RULES`, `CONFIGURE_RULES`, `QUARANTINE_IP`, `WHITELIST_BYPASS`, `AUDIT_INSPECT`, `ADMIN`).
   - Atténuation monotone irréversible empêchant toute élévation de privilèges.
2. **Filtrage Protocolaire HTTP Strict (RFC 7230)** :
   - Détection d'injections CRLF (`\r\n`), null-bytes (`\0`) et désynchronisation HTTP (*Request Smuggling*).
   - Validation stricte des méthodes HTTP (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`), des en-têtes et de la taille des corps.
3. **Moteur Heuristique Anti-Injections L7** :
   - SQLi : détection de tautologies (`' OR '1'='1`), unions, commentaires injectés (`--`, `/*`), fonctions d'évasion.
   - XSS : détection de balises `<script>`, attributs d'événements (`onload=`, `onerror=`), pseudo-protocoles (`javascript:`).
   - RCE : détection de métacaractères shell (`|`, `;`, `&&`, `` ` ``), binaires suspects (`/bin/sh`, `cmd.exe`).
   - Path Traversal : détection de séquences `../`, encodages multiples (`%2e%2e`, `%2f`).
4. **Analyseur JSON Récursif Borné & Anti-Pollution de Prototype** :
   - Contrôle strict de la profondeur maximale (`MAX_JSON_DEPTH = 8`) neutralisant les attaques par récursion infinie.
   - Détection et rejet des clés malveillantes (`__proto__`, `constructor`, `prototype`).
5. **Inspecteur de Bytecode WebAssembly (Wasm)** :
   - Vérification de l'en-tête magique `\0asm` et de la version binaire.
   - Détection de bombes mémoire (dépassement du quota de pages `MAX_WASM_PAGES_ALLOWED = 512`) et d'imports interdits.
6. **Prévention des Fuites de Données Sortantes (*Data Leakage Prevention*)** :
   - Filtrage des réponses HTTP bloquant la divulgation de clés privées, jetons d'authentification ou traces de panique noyau.
7. **Quarantaine IP Dynamique $O(1)$ & Grand Livre d'Audit SHA-256 Inviolable** :
   - Table de quarantaine rapide (`MAX_QUARANTINED_IPS = 32`) avec levée temporisée ou administrative.
   - Liste blanche prioritaire (`MAX_WHITELISTED_IPS = 16`).
   - Registre d'audit séquentiel scellé par chaîne de hachage SHA-256 cumulée (`audit_chain`).
8. **Protocole IPC Déterministe à 64 Octets** :
   - Messages `WafRequest` et `WafResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`WafOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafOpcode {
    GetStatus = 1,
    InspectUri = 2,
    QuarantineIp = 3,
    UnquarantineIp = 4,
    WhitelistIp = 5,
    AddRule = 6,
    GetAudit = 7,
}
```

### 2.2 Droits de Capabilités (`WafCap`)

```rust
pub mod waf_rights {
    pub const INSPECT_REQUEST: u32 = 1 << 0;
    pub const INSPECT_RESPONSE: u32 = 1 << 1;
    pub const ENFORCE_RULES: u32 = 1 << 2;
    pub const CONFIGURE_RULES: u32 = 1 << 3;
    pub const QUARANTINE_IP: u32 = 1 << 4;
    pub const WHITELIST_BYPASS: u32 = 1 << 5;
    pub const AUDIT_INSPECT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = INSPECT_REQUEST
        | INSPECT_RESPONSE
        | ENFORCE_RULES
        | CONFIGURE_RULES
        | QUARANTINE_IP
        | WHITELIST_BYPASS
        | AUDIT_INSPECT
        | ADMIN;
}
```

### 2.3 Structure `WafRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WafRequest {
    pub magic: u32,               // 0x57414644 ("WAFD")
    pub opcode: u32,              // WafOpcode
    pub handle_id: u32,           // Identifiant de capacité
    pub rights: u32,              // Droits WafCap
    pub src_ip: [u8; 4],          // Adresse IPv4 source
    pub http_method: u8,          // 0: GET, 1: POST, 2: PUT, 3: DELETE, etc.
    pub rule_action: u8,          // Action de règle cible
    pub _reserved1: [u8; 2],      // Alignement
    pub epoch: u64,               // Époque de requête
    pub payload: [u8; 32],        // Extrait d'URI ou motif à inspecter
}

const _: () = assert!(core::mem::size_of::<WafRequest>() == 64);
```

### 2.4 Structure `WafResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WafResponse {
    pub magic: u32,               // 0x57414653 ("WAFS")
    pub status: i32,              // 0 = Succès, < 0 = WafError
    pub decision: u8,             // 0: Allow, 1: Block, 2: Quarantine, 3: Challenge
    pub attack_type: u8,          // 0: None, 1: SQLi, 2: XSS, 3: RCE, 4: PathTraversal, etc.
    pub _reserved1: [u8; 2],      // Alignement
    pub total_inspections: u32,   // Total de requêtes inspectées
    pub blocked_requests: u32,    // Total de requêtes bloquées
    pub quarantined_ips: u32,     // Nombre d'adresses IP en quarantaine
    pub total_rules: u32,         // Nombre de règles L7 actives
    pub anomaly_score: u32,       // Score d'anomalie de la requête
    pub audit_hash: [u8; 16],     // Empreinte SHA-256 tronquée de la chaîne d'audit
    pub status_str: [u8; 16],     // Chaîne d'état ASCII ("ALLOWED", "BLOCKED", etc.)
}

const _: () = assert!(core::mem::size_of::<WafResponse>() == 64);
```

---

## 3. Intégration dans le Shell `jsh`

Le shell `jsh` intègre la commande native `waf` :
- `waf status` (ou `waf`) : Affiche le bilan d'activité du pare-feu, total des requêtes inspectées, requêtes bloquées, IPs en quarantaine, règles actives et empreinte d'audit SHA-256.
- `waf inspect <uri> [body]` : Simule l'inspection d'une requête HTTP avec détection des attaques (SQLi, XSS, RCE, Path Traversal) et affiche la décision (Allow/Block/Quarantine) et le score d'anomalie.
- `waf quarantine <ip>` : Place manuellement une adresse IPv4 en quarantaine stricte $O(1)$.
- `waf unquarantine <ip>` : Lève la quarantaine d'une adresse IPv4.
- `waf rules` : Liste l'ensemble des règles de détection L7 configurées.
- `waf audit` : Affiche l'historique récent des événements de sécurité scellés et l'empreinte de la chaîne d'audit.

La commande `ps` liste les **30 processus actifs** incluant :
```text
30 | waf | Ring 3 | Ready | 1000 | L7 Web Application Firewall & Injection Filter
```

---

## 4. Intégration Noyau & Pipeline `xtask`

- `kernel/src/main.rs` :
  - Extraction de `/bin/waf` depuis l'archive TAR `initrd`.
  - Spawning du processus utilisateur PID 30 `waf`.
  - Validation de l'alignement de pile System V ABI (`RSP % 16 == 0`).
  - Deadline EEVDF fixée à 1000.
  - Assertions CI validant 30 processus et émission de la ligne PASS officielle :
    `[PASS] Pare-Feu Applicatif L7 & Filtrage Injections (jambo-waf PID 30) validee sous QEMU.`
- `xtask/src/main.rs` :
  - Compilation bare-metal `build_waf()` pour `x86_64-unknown-none`.
  - Extension de `build_userland()` au 30-uplet.
  - Empaquettage de `bin/waf` dans `initrd.tar`.
  - Validation de la chaîne PASS sous QEMU.

# Conception Technique — Jalon 3.33 : Prévention des Fuites de Données DLP (Ring 3, PID 38)

## 1. Contexte & Objectifs

Le Jalon 3.33 de la feuille de route opérationnelle (Palier 3 — Sécurité Avancée & Surveillance Souveraine) promeut le sous-système de Prévention des Fuites de Données (**DLP — Data Loss Prevention**) au statut de démon de production Ring 3 sous le nom `jambo-dlp` (PID 38).

### Objectifs Clés
1. **Démon de Production Ring 3 (`services/jambo-dlp`)** :
   - Migration de `incubator/services/jambo-dlp` vers `services/jambo-dlp`.
   - Mode pure `#![no_std]`, `#![no_main]`, zéro allocation dynamique (`alloc`, `Vec`, `Box`, `String` strictement proscrits).
   - Contrôle d'accès sans autorité ambiante (ZAA) par capabilités `DlpCap` avec atténuation monotone.
   - Classification multi-vectorielle en temps réel des flux sensibles :
     - Secrets Souverains & Défense Nationale (`CLASSIFIED//SOVEREIGN`, `SECRET-DEFENSE`, etc.)
     - Clés Privées Cryptographiques (`-----BEGIN PRIVATE KEY-----`, RSA, EC, OpenSSH)
     - Jetons d'API et secrets d'authentification (`sec_tok_`, `ghp_`, `token_api_`, JWT)
     - Numéros de cartes bancaires avec validation formelle par algorithme de Luhn (ISO/IEC 7812)
     - Identifiants nationaux (SSN, NIR)
     - Exfiltration clandestine à haute entropie de Shannon ($\ge 7.2$ bits/octet soit $\ge 7200$ millibits)
   - Politiques d'application strictes :
     - Masquage dynamique en vol (*Redaction*)
     - Blocage immédiat de transfert (*Block*)
     - Mise en quarantaine atomique $O(1)$ (*Quarantine*)
   - Grand livre d'audit cryptographique inviolable avec chaînage SHA-256 no_std.
   - Protocole IPC souverain déterministe à 64 octets (`DlpRequest`, `DlpResponse`) avec assertions statiques de compilation (`size_of == 64`).

2. **Intégration Shell (`services/jambo-sh`)** :
   - Commandes natives `dlp` : `status`, `inspect <text>`, `rules`, `incidents`, `audit`.
   - Extension de la commande `ps` à **38 processus Ring 3** actifs.
   - Documentation de `dlp` dans `help`.

3. **Ordonnanceur Noyau & Packaging (`kernel` & `xtask`)** :
   - Initialisation du PID 38 dans `kernel/src/main.rs` avec pile System V ABI alignée sur 16 octets (`user_rsp % 16 == 0`) et deadline EEVDF 1000.
   - Compilation et packaging de `/bin/dlp` dans `initrd.tar` (avec alias `jambo-dlp`).
   - Image disque VirtIO `target/disk.raw` (32 Mio).
   - Validation QEMU UEFI avec ligne exacte :
     `[PASS] Prevention des Fuites de Donnees DLP (jambo-dlp PID 38) validee sous QEMU.`

---

## 2. Architecture IPC Déterministe (64 Octets)

### 2.1 Identifiants et Constantes
- **PID / Endpoint ID** : `DLP_ENDPOINT_ID: u64 = 38`
- **Magic Requête** : `DLP_REQ_MAGIC: u32 = 0x444C5052` ("DLPR")
- **Magic Réponse** : `DLP_RESP_MAGIC: u32 = 0x444C5053` ("DLPS")

### 2.2 Opcodes IPC
1. `GetStatus = 1` : Récupération du résumé d'état opérationnel du moteur DLP.
2. `InspectFlow = 2` : Inspection et classification d'un flux de données avec application de la politique.
3. `MaskPayload = 3` : Masquage direct d'un tampon contenant des données sensibles.
4. `QuarantineFlow = 4` : Confinement et isolement immédiat $O(1)$ d'un flux compromis.
5. `ListRules = 5` : Énumération des politiques et règles de détection DLP actives.
6. `ListIncidents = 6` : Consultation de l'historique des violations et mises en quarantaine.
7. `AuditLedger = 7` : Vérification et rapport d'intégrité de la chaîne cryptographique d'audit.

### 2.3 Structure de Requête IPC (`DlpRequest` — 64 octets)
```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlpRequest {
    pub magic: u32,                  //  0..4   : DLP_REQ_MAGIC (0x444C5052)
    pub opcode: u32,                 //  4..8   : Code opération
    pub handle_id: u64,              //  8..16  : Handle ou endpoint appelant
    pub rights: u32,                 // 16..20  : Droits capabilaires transmis
    pub flow_id: u32,                // 20..24  : Identifiant de flux réseau/IPC
    pub payload_preview: [u8; 32],   // 24..56  : Aperçu du contenu à inspecter/masquer
    pub param: u32,                  // 56..60  : Paramètre contextuel (longueur/options)
    pub epoch: u32,                  // 60..64  : Horodatage / Epoch de requête
}
const _: () = assert!(core::mem::size_of::<DlpRequest>() == 64);
```

### 2.4 Structure de Réponse IPC (`DlpResponse` — 64 octets)
```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlpResponse {
    pub magic: u32,                  //  0..4   : DLP_RESP_MAGIC (0x444C5053)
    pub status: u32,                 //  4..8   : Statut d'exécution (0 = succès)
    pub flow_id: u32,                //  8..12  : Identifiant de flux traité
    pub action: u8,                  // 12..13  : Action appliquée (Allow/Mask/Block/Quarantine)
    pub data_type: u8,               // 13..14  : Type de données sensibles détecté
    pub severity: u8,                // 14..15  : Sévérité de la menace
    pub quarantined: u8,             // 15..16  : Indicateur de mise en quarantaine (0 ou 1)
    pub entropy_millibits: u32,      // 16..20  : Entropie de Shannon mesurée (millibits)
    pub output_hash_preview: [u8; 32],// 20..52 : Hachage SHA-256 du résultat ou empreinte
    pub violations_count: u32,       // 52..56  : Nombre cumulé de violations
    pub flows_scanned: u32,          // 56..60  : Nombre cumulé de flux analysés
    pub quarantine_count: u32,       // 60..64  : Nombre d'entrées en quarantaine
}
const _: () = assert!(core::mem::size_of::<DlpResponse>() == 64);
```

---

## 3. Matrice de Classification et Politiques Par Défaut

| ID | Nom de Règle | Type de Données | Sévérité | Action | Entropie Min | Quarantaine |
|----|--------------|-----------------|----------|--------|--------------|-------------|
| 1  | Sovereign Classified Defense | `SovereignDefenseSecret` | Critical | Block | 0 | Oui |
| 2  | Private Key Leak Prevention | `CryptoPrivateKey` | Critical | Block | 0 | Oui |
| 3  | API Tokens & Secrets Exposure | `ApiTokenOrSecret` | High | Mask | 0 | Non |
| 4  | PCI-DSS Credit Card Redaction | `PiiCreditCard` | High | Mask | 0 | Non |
| 5  | National Identification PII | `PiiNationalId` | Medium | Mask | 0 | Non |
| 6  | High Entropy Mass Exfiltration | `HighEntropyExfiltration` | Critical | Quarantine | 7200 | Oui |

---

## 4. Intégration Noyau, Initrd et Shell

- **Micro-Noyau (`kernel/src/main.rs`)** :
  - Extraction de `/bin/dlp` depuis `initrd.tar`.
  - Création du processus utilisateur PID 38 (`/bin/dlp`).
  - Alignement System V ABI vérifié : `assert_eq!(dlp_sp % 16, 0)`.
  - Deadline ordonnanceur EEVDF : `1000`.
- **Shell (`services/jambo-sh`)** :
  - Commande `dlp` avec sous-commandes :
    - `dlp status` : vue d'ensemble du sous-système DLP.
    - `dlp inspect <text>` : classification et masquage d'un échantillon textuel.
    - `dlp rules` : liste des 6 politiques fondamentales.
    - `dlp incidents` : liste des violations et flux isolés.
    - `dlp audit` : vérification formelle de la chaîne SHA-256 d'audit.
  - Table des processus `ps` actualisée à 38 démons.
- **Construction (`xtask/src/main.rs`)** :
  - Fonction `build_dlp`.
  - Intégration dans `build_userland` (38 binaires).
  - Copie dans `/bin/dlp`, `/bin/jambo-dlp`, `/dlp`, `/jambo-dlp`.
  - Validation QEMU UEFI avec code de sortie 33 (`isa-debug-exit`).


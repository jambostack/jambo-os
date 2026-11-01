# Spécification de Conception — Jalon 3.15 (v0.3.59)
# `jambo-vaultd` : Coffre-Fort Cryptographique Distribué, Partage de Secrets à Seuil & Baux Temporels (PID 20)

## 1. Vision et Objectifs Architecturaux

Le **Jalon 3.15 (`v0.3.59`)** franchit un cap historique pour **JamboOS** en promouvant le **20ᵉ processus en espace utilisateur Ring 3** : **`jambo-vaultd`** sous le **PID 20**.

Dans une architecture souveraine à zéro autorité ambiante, le stockage et la distribution des secrets cryptographiques (clés de session, certificats, jetons, secrets inter-services) ne doivent dépendre d'aucun super-utilisateur monolithique, ni d'un fichier en clair sur le disque :
1. **Verrouillage à Seuil de Shamir (Quorum $K$ parmi $N$)** : La clé maîtresse du coffre-fort ne réside jamais assemblée de façon persistante. Son déverrouillage exige la soumission d'au moins $K$ parts distinctes parmi $N$ administrateurs/nœuds de la grappe (`threshold = 3`, `total_shares = 5`).
2. **Chiffrement d'Enveloppe des Secrets** : Chaque secret stocké est chiffré individuellement avec la clé maîtresse reconstituée et associé à un chemin hiérarchique unique (`MAX_SECRETS = 32`).
3. **Baux Temporels Déterministes & Révocation Atomique** : Chaque secret est assorti d'une date d'expiration stricte (`lease_expires_at`). Tout secret dont le bail est échu est immédiatement inaccessible, et la révocation purge instantanément les données en mémoire vive par zéroïsation (absence totale de rémanence).
4. **Contrôle d'Accès par Capabilités `VaultCap`** : Les droits d'accès (`VAULT_READ`, `VAULT_WRITE`, `VAULT_ROTATE`, `VAULT_UNSEAL`, `VAULT_ADMIN`) sont strictement vérifiés à chaque appel, sans autorité ambiante.
5. **Protocole IPC Déterministe à 64 Octets** : Messages `VaultRequest` et `VaultResponse` calibrés à exactement 64 octets avec assertions statiques de compilation (`size_of == 64`).

---

## 2. Protocole IPC Déterministe (64 Octets)

### 2.1 Opcodes IPC (`VaultOpcode`)

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultOpcode {
    GetStatus = 1,
    SubmitShare = 2,
    Reseal = 3,
    PutSecret = 4,
    GetSecret = 5,
    RevokeSecret = 6,
}
```

### 2.2 Structure `VaultRequest` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultRequest {
    pub magic: u32,              // 0x5641554C ("VAUL")
    pub opcode: u32,             // VaultOpcode
    pub handle_id: u32,          // Identifiant de capacité
    pub rights: u32,             // Droits de la capacité VaultCap
    pub share_id: u8,            // ID de la part soumise (0..MAX_SHARES-1)
    pub path_len: u8,            // Longueur du chemin du secret (<= 16)
    pub payload_len: u8,         // Longueur du payload (<= 20)
    pub _pad: u8,                // Rembourrage d'alignement
    pub lease_duration: u64,     // Durée du bail en secondes
    pub path: [u8; 16],          // Chemin du secret (ex: "keys/db")
    pub payload: [u8; 20],       // Données du secret
}

const _: () = assert!(core::mem::size_of::<VaultRequest>() == 64);
```

### 2.3 Structure `VaultResponse` (64 octets)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultResponse {
    pub magic: u32,              // 0x56415553 ("VAUS")
    pub status: i32,             // 0 = Succès, < 0 = Code d'erreur SysError
    pub state: u8,               // 0=Sealed, 1=Unsealing, 2=Unsealed
    pub submitted_count: u8,     // Nombre de parts soumises
    pub threshold: u8,           // Quorum requis
    pub total_shares: u8,        // Nombre total de parts configurées
    pub total_secrets: u32,      // Nombre total de secrets enregistrés
    pub version: u32,            // Version du secret lu/écrit
    pub payload_len: u8,         // Longueur des données renvoyées
    pub _pad: [u8; 3],           // Rembourrage d'alignement
    pub lease_expires_at: u64,   // Horodatage d'expiration du bail
    pub payload: [u8; 32],       // Données déchiffrées du secret
}

const _: () = assert!(core::mem::size_of::<VaultResponse>() == 64);
```

---

## 3. Architecture du Démon Bare-Metal `jambo-vaultd` (PID 20)

### 3.1 Point d'entrée `_start()`
Le démon s'exécute en mode `#![no_std]`, `#![no_main]`, sans allocateur dynamique (`zero heap`) :
- Instanciation de `JamboVaultDaemon::new()`.
- Initialisation avec les valeurs par défaut souveraines (`init_defaults()` : seuil 2 parmi 3 parts, clé maîtresse d'amorce).
- Exécution des auto-tests au boot :
  1. État initial scellé (`Sealed`).
  2. Rejet de lecture/écriture en état scellé (`ResourceBusy`).
  3. Déverrouillage progressif par soumission de 2 parts valides (`Unsealing` -> `Unsealed`).
  4. Stockage d'un secret avec bail temporel (`PutSecret`).
  5. Lecture et vérification du secret déchiffré (`GetSecret`).
  6. Rescellement (`Reseal`) et vérification de la ré-isolation immédiate.
- Configuration du canal de communication IPC sur l'endpoint PID 20.
- Boucle de service coopérative via `syscall_thread_yield()`.

---

## 4. Intégration dans le Shell `jsh`

Le shell `jsh` intègre le sous-système `vault` avec les sous-commandes suivantes :
- `vault status` : Affiche l'état du coffre (SEALED / UNSEALING / UNSEALED), le quorum de parts soumises ($K/N$) et le nombre de secrets scellés.
- `vault unseal <share_id>` : Soumet une part de déverrouillage pour reconstituer la clé maîtresse.
- `vault seal` : Verrouille immédiatement le coffre et purge les parts actives.
- `vault store <path> <val> [lease_sec]` : Enregistre un secret chiffré sous bail temporel.
- `vault get <path>` : Lit et déchiffre un secret valide.
- `vault revoke <path>` : Supprime et zéroïse un secret du coffre.

Le listing `ps` est porté à **20 processus actifs** :
```
 20  ACTIF    /bin/vaultd (Coffre-Fort de Secrets Distribué Ring 3)
```

---

## 5. Intégration Noyau & Pipeline `xtask`

1. **Noyau (`kernel/`)** :
   - Extraction de `/bin/vaultd` depuis le TAR `initrd`.
   - Création du processus PID 20 (`vaultd`).
   - Alignement de la pile System V ABI (`RSP % 16 == 0`).
   - Enregistrement dans l'ordonnanceur EEVDF avec une deadline de 1000.
   - Émission du message de test QEMU officiel :
     `\x1b[1;32m[PASS] Coffre-Fort de Secrets Distribue (jambo-vaultd PID 20) validee sous QEMU.\x1b[0m`

2. **Pipeline `xtask/`** :
   - Fonction `build_vaultd(release: bool) -> anyhow::Result<PathBuf>`.
   - `build_userland` étendu à un 20-tuple.
   - Empaquetage de `/bin/vaultd` et `/bin/jambo-vaultd` dans `initrd.tar`.
   - Mise à jour de la bannière vers `v0.3.59`.
   - Harnais `run_test` configuré pour valider le message `[PASS] Coffre-Fort de Secrets Distribue`.

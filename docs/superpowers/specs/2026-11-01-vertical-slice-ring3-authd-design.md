# Spécification de Conception — Jalon 3.10 : Authentification Cryptographique & Jetons de Session Capabilitaires (`jambo-authd` PID 15) (v0.3.54)

## 1. Contexte & Objectifs Architecturaux

Le micro-noyau JamboOS intègre actuellement quatorze démons autonomes en Ring 3 (`init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`, `forensics`, `powerd`, `metricsd`, `bpfd`, `vpn`).

L'objectif du **Jalon 3.10 (`v0.3.54`)** est de bannir définitivement le modèle d'autorité monolithique Unix (UID/GID et super-utilisateur `root` omnipotent) au profit d'un modèle d'identité souverain fondé sur la cryptographie asymétrique et les capabilités temporelles en Ring 3, via la promotion du service `jambo-authd` (PID 15). Ce sous-système garantit :
1. **Éradication du modèle Root & Autorité Zéro-Ambiante** :
   - Aucun compte super-utilisateur `root` n'existe dans JamboOS.
   - Les identités sont des entités cryptographiques immuables (`UserIdentity`) possédant une clé publique asymétrique (Ed25519) et un masque de droits strict (`allowed_rights_mask`).
   - Rôles fonctionnels granulaires : `Guest`, `StandardUser`, `SystemOperator`, `SecurityAuditor`.
2. **Authentification par Défis-Réponses Sans Mot de Passe en Clair** :
   - Génération de défis imprévisibles déterministes (`CryptoAuthEngine::generate_challenge`).
   - Signature asymétrique du défi avec la clé privée de l'utilisateur (`CryptoAuthEngine::sign_challenge`).
   - Vérification mathématique de la signature avec la clé publique enregistrée (`CryptoAuthEngine::verify_signature`).
3. **Jetons de Session Capabilitaires Déterminés (`SessionTokenCap`)** :
   - Délivrance d'un jeton capabilaire non forgeable lors d'une authentification réussie.
   - Fenêtre de validité temporelle stricte (`issued_at_ns` .. `expires_at_ns`).
   - Révocation atomique immédiate et destruction en mémoire sans résidu (*Zero-Remanence / Zeroize*).
4. **Protocole IPC Souverain Déterministe** :
   - Messages synchrones fixes à 64 octets (`AuthRequest` / `AuthResponse`).
   - Client IPC ergonomique (`AuthClient`) pour le shell `jsh` et les services pairs.
5. **Commandes Shell `jsh` & Listing 15 Processus** :
   - Commandes `auth status`, `auth login <username>`, `auth token`, `auth revoke <session_id>`.
   - Commande `ps` affichant exhaustivement les 15 processus Ring 3.
6. **Validation QEMU UEFI Automatisée** :
   - Extraction de `/bin/authd` depuis l'initrd TAR, alignement System V ABI (`RSP % 16 == 0`), enfilage dans l'ordonnanceur EEVDF, journal de certification UART `[PASS] Identite Cryptographique & Jetons de Session (jambo-authd PID 15) validee sous QEMU.` et sortie propre code 33.

---

## 2. Architecture Détaillée

### 2.1 Promotion & Structure du Démon `jambo-authd`

- Emplacement : `services/jambo-authd`.
- `Cargo.toml` : version `0.3.54`, dépendance `libjambo = { path = "../../libs/libjambo" }`.
- Inscription dans le `workspace.members` du `Cargo.toml` racine.

### 2.2 Protocole IPC Déterministe 64 Octets

```rust
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthOpcode {
    GetStatus = 1,
    Authenticate = 2,
    ValidateToken = 3,
    RevokeSession = 4,
    GetUserInfo = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AuthRequest {
    pub opcode: u32,             // 4 octets (offset 0)
    pub user_id: u32,            // 4 octets (offset 4)
    pub session_id: u64,         // 8 octets (offset 8)
    pub username: [u8; 16],      // 16 octets (offset 16)
    pub challenge_seed: u64,     // 8 octets (offset 32)
    pub _reserved: [u8; 24],     // 24 octets (offset 40)
}
// 4 + 4 + 8 + 16 + 8 + 24 = 64 octets
const _: () = assert!(core::mem::size_of::<AuthRequest>() == 64);

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AuthResponse {
    pub status: u32,             // 4 octets (offset 0, 0 = OK)
    pub user_id: u32,            // 4 octets (offset 4)
    pub session_id: u64,         // 8 octets (offset 8)
    pub role: u32,               // 4 octets (offset 16)
    pub active_sessions: u16,    // 2 octets (offset 20)
    pub registered_users: u16,   // 2 octets (offset 22)
    pub expires_in_sec: u32,     // 4 octets (offset 24)
    pub session_handle: u64,     // 8 octets (offset 28..32 alignment -> offset 32)
    pub token_hash: [u8; 24],    // 24 octets (offset 40)
}
// 4 + 4 + 8 + 4 + 2 + 2 + 4 + 8 + 24 = 64 octets
const _: () = assert!(core::mem::size_of::<AuthResponse>() == 64);
```

### 2.3 Intégration dans `jsh` (PID 2)

- Sous-commandes `auth` :
  - `auth status` : Affichage de l'état du sous-système d'identité (utilisateurs enregistrés, sessions actives, détails de la session courante).
  - `auth login <username>` : Authentification par défi-réponse sans mot de passe en clair pour l'identité demandée (`operator`, `auditor`, `guest`), délivrance d'un jeton `SessionTokenCap`.
  - `auth token` : Détails du jeton de session courant (ID session, rôle utilisateur, handle capabilaire, validité temporelle).
  - `auth revoke <session_id>` : Révocation atomique immédiate de la session spécifiée et purge mémoire zero-remanence.
- Commande `ps` :
  - Ajout du 15e processus : `15  ACTIF    /bin/authd (Demon Identite & Jetons de Session Capabilitaires Ring 3)\n`.

### 2.4 Intégration Noyau (`kernel`) & Outillage (`xtask`)

- `kernel/src/main.rs` :
  - Extraction de `/bin/authd` depuis le TAR initrd.
  - Création du processus Ring 3 PID 15 nommé `"authd"`.
  - Vérification de l'alignement System V ABI (`assert_eq!(authd_sp % 16, 0)`).
  - Enfilage dans l'ordonnanceur multicœur EEVDF.
  - Journalisation officielle de test :
    `kprintln!("\x1b[1;32m[PASS] Identite Cryptographique & Jetons de Session (jambo-authd PID 15) validee sous QEMU.\x1b[0m");`
  - Version bump du noyau à `0.3.54`.
- `xtask/src/main.rs` :
  - Fonction `build_authd(release: bool) -> anyhow::Result<PathBuf>` ciblant `x86_64-unknown-none` avec `libs/user-x86_64.ld`.
  - Intégration de `authd` dans `build_userland` (tuple de 15 binaires).
  - Copie dans `target/initrd_stage/bin/authd` et empaquetage dans `target/initrd.tar`.
  - Mise à jour de la bannière système : `"Bienvenue sur JamboOS v0.3.54\n"`.
  - Vérification du code de sortie 33 et de la chaîne `[PASS] Identite Cryptographique & Jetons de Session (jambo-authd PID 15) validee`.

---

## 3. Plan de Test & Critères de Validation

1. **Compilation bare-metal sans faute** :
   - Les 15 binaires cibles (`init`, `jsh`, `blockd`, `fs`, `netd`, `fdr`, `wasmd`, `pqc`, `kdir`, `forensics`, `powerd`, `metricsd`, `bpfd`, `vpn`, `authd`) ainsi que `kernel` et `xtask` compilent sans warning en `--release` pour `x86_64-unknown-none`.
2. **Tests Unitaires Crate** :
   - 100% des tests de `services/jambo-authd` (défis-réponses, signature, cycle de vie session, révocation, IPC) passent.
   - 100% des tests de `services/jambo-sh` (y compris les nouvelles commandes `auth`) passent.
3. **Validation QEMU UEFI** :
   - Exécution sous QEMU UEFI avec traces dans `target/qemu_output.log`.
   - Les 15 processus sont démarrés avec leur pile alignée à 16 octets.
   - Le message UART certifié est émis.
   - Sortie propre avec code `33` (`QemuExitCode::Success`).


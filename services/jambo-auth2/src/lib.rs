//! Démon d'Authentification Biométrique, Passkeys WebAuthn & Jetons d'Accès Éphémères (`jambo-auth2`)
//!
//! Phase 110 — Jalon v0.2.108
//!
//! Fournit une infrastructure d'authentification sans mot de passe haute sécurité :
//! 1. Clés d'Accès Passkeys / FIDO2 / WebAuthn Level 3 (`PasskeyCredential`) :
//!    - Élimination des identifiants statiques et mots de passe au profit de paires asymétriques.
//!    - Validation biométrique matérielle (Empreinte, Iris, Enclave Sécurisée, PIN matériel).
//!    - Drapeaux d'authentificateur : Présence Utilisateur (`UP`), Vérification Biométrique (`UV`).
//! 2. Signatures Schnorr Déterministes & Vérification d'Assertion ZKP :
//!    - Protocole Schnorr non-interactif / Fiat-Shamir (`g^s == t * y^e mod p`).
//!    - Défis cryptographiques horodatés (`AuthChallenge`) anti-rejeu à usage unique.
//!    - Protection anti-clonage via compteur d'assertion strictement monotone (`sign_count`).
//! 3. Jetons d'Accès Cryptographiques Éphémères (`EphemeralToken`) :
//!    - Jetons d'accès bornés dans le temps (TTL court) signés par HMAC-SHA256.
//!    - Atténuation capabilaire strictement monotone des portées et durées de vie.
//! 4. Révocation Instantanée O(1) & Époques de Sécurité :
//!    - Révocation granulaire de jeton, révocation globale par utilisateur et bascule d'époque O(1).
//! 5. Contrôle d'Accès Capabilaire Monotone (`Auth2Cap`) :
//!    - Architecture Zero-Ambient Authority avec rejet formel de toute amplification de droits.
//! 6. Registre d'Audit Inaltérable :
//!    - Chaîne d'audit cryptographique SHA-256 scellée et infalsifiable.

#![no_std]

use libjambo::Handle;

// ============================================================================
// CONSTANTES DU SOUS-SYSTÈME JAMBO-AUTH2
// ============================================================================

pub const MAX_PASSKEYS: usize = 32;
pub const MAX_TOKENS: usize = 64;
pub const MAX_REVOKED_TOKENS: usize = 64;
pub const MAX_CHALLENGES: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_RP_ID_LEN: usize = 64;
pub const MAX_USER_NAME_LEN: usize = 32;
pub const MAX_USERS: usize = 16;

// ============================================================================
// DROITS CAPABILAIRES & GOUVERNANCE STRICTE
// ============================================================================

pub mod auth2_rights {
    pub const REGISTER_PASSKEY: u32 = 1 << 0;
    pub const AUTHENTICATE_WEBAUTHN: u32 = 1 << 1;
    pub const ISSUE_TOKEN: u32 = 1 << 2;
    pub const VERIFY_TOKEN: u32 = 1 << 3;
    pub const ATTENUATE_TOKEN: u32 = 1 << 4;
    pub const REVOKE_TOKEN: u32 = 1 << 5;
    pub const REVOKE_USER: u32 = 1 << 6;
    pub const BUMP_EPOCH: u32 = 1 << 7;
    pub const AUDIT_LOG: u32 = 1 << 8;
    pub const ALL: u32 = (1 << 9) - 1;
}

// ============================================================================
// PORTÉES D'ACCÈS DES JETONS ÉPHÉMÈRES (TOKEN SCOPES)
// ============================================================================

pub mod token_scopes {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXEC: u32 = 1 << 2;
    pub const DELEGATE: u32 = 1 << 3;
    pub const CROSS_ENCLAVE: u32 = 1 << 4;
    pub const ADMIN: u32 = 1 << 5;
    pub const ALL: u32 = (1 << 6) - 1;
}

// ============================================================================
// DRAPEAUX AUTHENTICATEUR WEBAUTHN / FIDO2
// ============================================================================

pub mod webauthn_flags {
    /// Présence Utilisateur constatée (User Present)
    pub const FLAG_UP: u8 = 1 << 0;
    /// Vérification Biométrique / PIN validée (User Verified)
    pub const FLAG_UV: u8 = 1 << 2;
    /// Clé éligible à la sauvegarde (Backup Eligible)
    pub const FLAG_BE: u8 = 1 << 3;
    /// Clé actuellement sauvegardée (Backup State)
    pub const FLAG_BS: u8 = 1 << 4;
    /// Données d'attestation incluses (Attested Credential Data)
    pub const FLAG_AT: u8 = 1 << 6;
    /// Données d'extension présentes (Extension Data)
    pub const FLAG_ED: u8 = 1 << 7;
}

// ============================================================================
// TYPES, ÉNUMÉRATIONS ET STRUCTURES DE DONNÉES
// ============================================================================

/// Facteur biométrique / physique d'authentification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricFactor {
    None = 0,
    Fingerprint = 1,
    IrisScan = 2,
    SecureEnclaveBio = 3,
    HardwarePin = 4,
}

impl BiometricFactor {
    pub fn as_str(&self) -> &'static str {
        match self {
            BiometricFactor::None => "None (PIN-less)",
            BiometricFactor::Fingerprint => "Fingerprint (Empreinte)",
            BiometricFactor::IrisScan => "IrisScan (Biométrie Oculaire)",
            BiometricFactor::SecureEnclaveBio => "SecureEnclaveBio (TPM/TEE)",
            BiometricFactor::HardwarePin => "HardwarePin (FIDO2 PIN)",
        }
    }
}

/// Canal de transport de la clé Passkey
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyTransport {
    InternalPlatform = 0,
    UsbHid = 1,
    Nfc = 2,
    Ble = 3,
}

impl PasskeyTransport {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasskeyTransport::InternalPlatform => "Internal (Platform TPM/Enclave)",
            PasskeyTransport::UsbHid => "USB (Security Key HID)",
            PasskeyTransport::Nfc => "NFC (Contactless)",
            PasskeyTransport::Ble => "BLE (Wireless)",
        }
    }
}

/// Motif de révocation d'un jeton ou d'une session
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    ExplicitLogout,
    CompromisedCredential,
    SecurityEpochBump,
    PolicyViolation,
    BiometricFailure,
}

impl RevocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationReason::ExplicitLogout => "Déconnexion explicite de l'utilisateur",
            RevocationReason::CompromisedCredential => "Compromission suspectée du support Passkey",
            RevocationReason::SecurityEpochBump => "Bascule globale d'époque de sécurité de grappe",
            RevocationReason::PolicyViolation => "Violation de politique de confinement Zero-Ambient",
            RevocationReason::BiometricFailure => "Échec de ré-authentification biométrique",
        }
    }
}

/// Erreurs spécifiques au sous-système jambo-auth2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth2Error {
    PermissionDenied,
    QuotaExceeded,
    CredentialNotFound,
    CredentialAlreadyExists,
    InvalidSignature,
    ReplayAttackDetected,
    ChallengeExpired,
    ChallengeNotFound,
    TokenExpired,
    TokenRevoked,
    InvalidScope,
    BiometricRequired,
    InvalidInput,
    CapacityExceeded,
}

/// Capacité de gouvernance pour l'authentification et les jetons
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth2Cap {
    pub handle: Handle,
    pub rights: u32,
    pub owner_id: u32,
    pub quota_remaining: u16,
}

impl Auth2Cap {
    pub const fn new(handle: Handle, rights: u32, owner_id: u32, quota: u16) -> Self {
        Self {
            handle,
            rights,
            owner_id,
            quota_remaining: quota,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone irréversible
    pub fn attenuate(&self, new_rights: u32, new_quota: u16) -> Result<Self, Auth2Error> {
        if (new_rights & !self.rights) != 0 {
            return Err(Auth2Error::PermissionDenied);
        }
        if new_quota > self.quota_remaining {
            return Err(Auth2Error::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            owner_id: self.owner_id,
            quota_remaining: new_quota,
        })
    }
}

// ============================================================================
// ARITHMÉTIQUE SCHNORR & FONCTIONS DE HACHAGE SHA-256 / HMAC
// ============================================================================

/// Hachage cryptographique SHA-256 souverain `#![no_std]`
pub struct Sha256;

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    #[inline(always)]
    fn rotr(x: u32, n: u32) -> u32 {
        (x >> n) | (x << (32 - n))
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = [
            0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;
        let mut block = [0u8; 64];
        let mut idx = 0;

        while idx + 64 <= data.len() {
            block.copy_from_slice(&data[idx..idx + 64]);
            Self::process_block(&mut h, &block);
            idx += 64;
        }

        let rem = data.len() - idx;
        for i in 0..rem {
            block[i] = data[idx + i];
        }
        block[rem] = 0x80;
        for i in (rem + 1)..64 {
            block[i] = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut h, &block);
            block = [0u8; 64];
        }

        let len_bytes = bit_len.to_be_bytes();
        block[56..64].copy_from_slice(&len_bytes);
        Self::process_block(&mut h, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }

    fn process_block(h: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = Self::rotr(w[i - 15], 7) ^ Self::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = Self::rotr(w[i - 2], 17) ^ Self::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = Self::rotr(e, 6) ^ Self::rotr(e, 11) ^ Self::rotr(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = Self::rotr(a, 2) ^ Self::rotr(a, 13) ^ Self::rotr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
}

/// Code d'Authentification de Message HMAC-SHA256
pub struct HmacSha256;

impl HmacSha256 {
    pub fn mac(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let h = Sha256::digest(key);
            k_pad[..32].copy_from_slice(&h);
        } else {
            k_pad[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; 64];
        let mut opad = [0u8; 64];
        for i in 0..64 {
            ipad[i] = k_pad[i] ^ 0x36;
            opad[i] = k_pad[i] ^ 0x5c;
        }

        // Inner hash: H(ipad || message)
        let mut inner_buf = [0u8; 256];
        let inner_len = 64 + message.len();
        if inner_len <= inner_buf.len() {
            inner_buf[..64].copy_from_slice(&ipad);
            inner_buf[64..inner_len].copy_from_slice(message);
            let inner_hash = Sha256::digest(&inner_buf[..inner_len]);

            // Outer hash: H(opad || inner_hash)
            let mut outer_buf = [0u8; 64 + 32];
            outer_buf[..64].copy_from_slice(&opad);
            outer_buf[64..64 + 32].copy_from_slice(&inner_hash);
            Sha256::digest(&outer_buf)
        } else {
            // Repli sur clé directe si message volumineux
            Sha256::digest(message)
        }
    }
}

/// Module arithmétique pour signatures Schnorr déterministes (Fiat-Shamir ZKP)
pub mod schnorr {
    use super::Sha256;

    /// Nombre premier p = 2^64 - 59
    pub const PRIME_P: u64 = 0xFFFF_FFFF_FFFF_FFC5;
    /// Ordre du sous-groupe multiplicatif : q = p - 1
    pub const ORDER_Q: u64 = PRIME_P - 1;
    /// Générateur de base g = 3
    pub const GEN_G: u64 = 3;

    #[inline(always)]
    pub fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
        ((a as u128 * b as u128) % m as u128) as u64
    }

    pub fn pow_mod(mut base: u64, mut exp: u64, m: u64) -> u64 {
        if m == 1 {
            return 0;
        }
        let mut res = 1u64;
        base %= m;
        while exp > 0 {
            if (exp & 1) == 1 {
                res = mul_mod(res, base, m);
            }
            base = mul_mod(base, base, m);
            exp >>= 1;
        }
        res
    }

    /// Calcule la clé publique y = g^x mod p à partir du secret x
    pub fn compute_public_key(secret_x: u64) -> u64 {
        pow_mod(GEN_G, secret_x % ORDER_Q, PRIME_P)
    }

    /// Signe de manière déterministe un condensat M avec le secret x (RFC 6979 style)
    pub fn sign_deterministic(secret_x: u64, message_digest: &[u8; 32]) -> (u64, u64) {
        let x_bytes = secret_x.to_be_bytes();
        let mut k_input = [0u8; 48];
        k_input[..8].copy_from_slice(&x_bytes);
        k_input[8..40].copy_from_slice(message_digest);
        k_input[40..48].copy_from_slice(b"JAMBOSCH");
        let k_hash = Sha256::digest(&k_input);

        let mut k_val = u64::from_be_bytes([
            k_hash[0], k_hash[1], k_hash[2], k_hash[3], k_hash[4], k_hash[5], k_hash[6],
            k_hash[7],
        ]);
        if k_val == 0 || k_val >= ORDER_Q {
            k_val = 1337 + (k_val % (ORDER_Q - 2000));
        }

        // Engagement t = g^k mod p
        let t = pow_mod(GEN_G, k_val, PRIME_P);
        let y = compute_public_key(secret_x);

        // Défi e = H(g || y || t || M) mod (p - 1)
        let e = compute_challenge(y, t, message_digest);

        // Réponse s = (k + e * x) mod (p - 1)
        let s = (k_val + mul_mod(e, secret_x % ORDER_Q, ORDER_Q)) % ORDER_Q;
        (t, s)
    }

    /// Calcule le défi de Fiat-Shamir
    pub fn compute_challenge(public_y: u64, commitment_t: u64, message_digest: &[u8; 32]) -> u64 {
        let mut buf = [0u8; 56];
        buf[0..8].copy_from_slice(&GEN_G.to_be_bytes());
        buf[8..16].copy_from_slice(&public_y.to_be_bytes());
        buf[16..24].copy_from_slice(&commitment_t.to_be_bytes());
        buf[24..56].copy_from_slice(message_digest);

        let h = Sha256::digest(&buf);
        let val = u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
        val % ORDER_Q
    }

    /// Vérifie l'équation de Schnorr : g^s == t * y^e (mod p)
    pub fn verify(public_y: u64, message_digest: &[u8; 32], t: u64, s: u64) -> bool {
        if public_y == 0 || public_y >= PRIME_P || t == 0 || t >= PRIME_P || s >= ORDER_Q {
            return false;
        }
        let e = compute_challenge(public_y, t, message_digest);
        let lhs = pow_mod(GEN_G, s, PRIME_P);
        let rhs = mul_mod(t, pow_mod(public_y, e, PRIME_P), PRIME_P);
        lhs == rhs
    }
}

// ============================================================================
// MODÈLE DE DONNÉES PASKEY, DÉFIS & JETONS ÉPHÉMÈRES
// ============================================================================

/// Identifiant de clé d'accès Passkey
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasskeyCredential {
    pub cred_id: [u8; 32],
    pub user_id: u32,
    pub rp_id: [u8; MAX_RP_ID_LEN],
    pub rp_id_len: usize,
    pub user_name: [u8; MAX_USER_NAME_LEN],
    pub user_name_len: usize,
    pub public_key_statement: u64,
    pub factor: BiometricFactor,
    pub transport: PasskeyTransport,
    pub flags: u8,
    pub sign_count: u32,
    pub created_at_ticks: u64,
    pub is_active: bool,
}

impl PasskeyCredential {
    pub fn rp_id_str(&self) -> &str {
        core::str::from_utf8(&self.rp_id[..self.rp_id_len]).unwrap_or("<invalide>")
    }

    pub fn user_name_str(&self) -> &str {
        core::str::from_utf8(&self.user_name[..self.user_name_len]).unwrap_or("<invalide>")
    }
}

/// Défi d'authentification WebAuthn éphémère anti-rejeu
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthChallenge {
    pub challenge_id: u64,
    pub user_id: u32,
    pub rp_id_hash: [u8; 32],
    pub challenge_nonce: [u8; 32],
    pub issued_at_ticks: u64,
    pub expires_at_ticks: u64,
    pub consumed: bool,
}

/// Jeton d'accès cryptographique éphémère (`EphemeralToken`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralToken {
    pub token_id: u64,
    pub user_id: u32,
    pub cred_id: [u8; 32],
    pub scopes: u32,
    pub issued_at_ticks: u64,
    pub expires_at_ticks: u64,
    pub user_epoch: u32,
    pub parent_token_id: u64,
    pub token_signature: [u8; 32],
    pub revoked: bool,
}

impl EphemeralToken {
    #[inline(always)]
    pub fn is_valid(&self, required_scope: u32, current_ticks: u64, current_user_epoch: u32) -> bool {
        if self.revoked {
            return false;
        }
        if self.user_epoch < current_user_epoch {
            return false;
        }
        if current_ticks > self.expires_at_ticks {
            return false;
        }
        if (self.scopes & required_scope) != required_scope {
            return false;
        }
        true
    }
}

/// Enregistrement de jeton révoqué
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokedTokenEntry {
    pub token_id: u64,
    pub user_id: u32,
    pub revoked_at_ticks: u64,
    pub reason: RevocationReason,
}

/// Données de l'authentificateur WebAuthn (AuthenticatorData)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
}

impl AuthenticatorData {
    pub fn to_bytes(&self) -> [u8; 37] {
        let mut buf = [0u8; 37];
        buf[..32].copy_from_slice(&self.rp_id_hash);
        buf[32] = self.flags;
        buf[33..37].copy_from_slice(&self.sign_count.to_be_bytes());
        buf
    }
}

// ============================================================================
// DÉMON PRINCIPAL JAMBO-AUTH2
// ============================================================================

pub struct JamboAuth2Daemon {
    pub admin_cap: Auth2Cap,
    pub passkeys: [PasskeyCredential; MAX_PASSKEYS],
    pub passkey_count: usize,
    pub challenges: [AuthChallenge; MAX_CHALLENGES],
    pub challenge_count: usize,
    pub tokens: [EphemeralToken; MAX_TOKENS],
    pub token_count: usize,
    pub revoked_tokens: [RevokedTokenEntry; MAX_REVOKED_TOKENS],
    pub revoked_count: usize,
    pub user_epochs: [u32; MAX_USERS],
    pub cluster_security_epoch: u32,
    pub server_hmac_secret: [u8; 32],
    pub next_token_id: u64,
    pub next_challenge_id: u64,
    pub current_time_ticks: u64,
    pub successful_auths: u64,
    pub failed_auths: u64,
    pub total_tokens_issued: u64,
    pub audit_chain: [u8; 32],
    pub audit_count: u64,
}

impl JamboAuth2Daemon {
    pub fn new(admin_cap: Auth2Cap) -> Self {
        let dummy_passkey = PasskeyCredential {
            cred_id: [0u8; 32],
            user_id: 0,
            rp_id: [0u8; MAX_RP_ID_LEN],
            rp_id_len: 0,
            user_name: [0u8; MAX_USER_NAME_LEN],
            user_name_len: 0,
            public_key_statement: 0,
            factor: BiometricFactor::None,
            transport: PasskeyTransport::InternalPlatform,
            flags: 0,
            sign_count: 0,
            created_at_ticks: 0,
            is_active: false,
        };

        let dummy_challenge = AuthChallenge {
            challenge_id: 0,
            user_id: 0,
            rp_id_hash: [0u8; 32],
            challenge_nonce: [0u8; 32],
            issued_at_ticks: 0,
            expires_at_ticks: 0,
            consumed: false,
        };

        let dummy_token = EphemeralToken {
            token_id: 0,
            user_id: 0,
            cred_id: [0u8; 32],
            scopes: 0,
            issued_at_ticks: 0,
            expires_at_ticks: 0,
            user_epoch: 0,
            parent_token_id: 0,
            token_signature: [0u8; 32],
            revoked: false,
        };

        let dummy_revocation = RevokedTokenEntry {
            token_id: 0,
            user_id: 0,
            revoked_at_ticks: 0,
            reason: RevocationReason::ExplicitLogout,
        };

        let initial_audit = Sha256::digest(b"JAMBO_AUTH2_GENESIS_ROOT_V0.2.108");
        let initial_secret = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0x76, 0x2e, 0x71, 0x60, 0xaf, 0xcd, 0x25, 0x40, 0x62, 0xd8, 0x55, 0x10,
            0x91, 0x4b, 0x55, 0x89,
        ];

        Self {
            admin_cap,
            passkeys: [dummy_passkey; MAX_PASSKEYS],
            passkey_count: 0,
            challenges: [dummy_challenge; MAX_CHALLENGES],
            challenge_count: 0,
            tokens: [dummy_token; MAX_TOKENS],
            token_count: 0,
            revoked_tokens: [dummy_revocation; MAX_REVOKED_TOKENS],
            revoked_count: 0,
            user_epochs: [1; MAX_USERS],
            cluster_security_epoch: 1,
            server_hmac_secret: initial_secret,
            next_token_id: 10001,
            next_challenge_id: 1,
            current_time_ticks: 100,
            successful_auths: 0,
            failed_auths: 0,
            total_tokens_issued: 0,
            audit_chain: initial_audit,
            audit_count: 1,
        }
    }

    /// Initialise les identités et Passkeys par défaut du système souverain
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // Passkey 1 : Administrateur Système (Enclave Sécurisée + Biométrie Empreinte)
        let admin_secret = 0xABCD_EF01_2345_6789;
        let admin_pub = schnorr::compute_public_key(admin_secret);
        let _ = self.register_passkey(
            &cap,
            1, // Root / SecOps Admin
            "auth.jambo.internal",
            "jambo-admin",
            admin_pub,
            BiometricFactor::SecureEnclaveBio,
            PasskeyTransport::InternalPlatform,
            webauthn_flags::FLAG_UP | webauthn_flags::FLAG_UV | webauthn_flags::FLAG_BE,
        );

        // Passkey 2 : Opérateur Cluster (Clé matérielle FIDO2 USB + PIN matériel)
        let op_secret = 0x1122_3344_5566_7788;
        let op_pub = schnorr::compute_public_key(op_secret);
        let _ = self.register_passkey(
            &cap,
            2,
            "cluster.jambo.internal",
            "cluster-op",
            op_pub,
            BiometricFactor::HardwarePin,
            PasskeyTransport::UsbHid,
            webauthn_flags::FLAG_UP | webauthn_flags::FLAG_UV,
        );
    }

    /// Enregistre une nouvelle clé Passkey FIDO2 / WebAuthn
    pub fn register_passkey(
        &mut self,
        cap: &Auth2Cap,
        user_id: u32,
        rp_id: &str,
        user_name: &str,
        public_key_statement: u64,
        factor: BiometricFactor,
        transport: PasskeyTransport,
        flags: u8,
    ) -> Result<[u8; 32], Auth2Error> {
        if !cap.has_right(auth2_rights::REGISTER_PASSKEY) {
            return Err(Auth2Error::PermissionDenied);
        }
        if self.passkey_count >= MAX_PASSKEYS {
            return Err(Auth2Error::CapacityExceeded);
        }
        if rp_id.len() > MAX_RP_ID_LEN || user_name.len() > MAX_USER_NAME_LEN {
            return Err(Auth2Error::InvalidInput);
        }

        // Dérivation d'un Credential ID unique et déterministe
        let mut id_buf = [0u8; 96];
        id_buf[..4].copy_from_slice(&user_id.to_be_bytes());
        id_buf[4..12].copy_from_slice(&public_key_statement.to_be_bytes());
        let rp_bytes = rp_id.as_bytes();
        let copy_len = rp_bytes.len().min(48);
        id_buf[12..12 + copy_len].copy_from_slice(&rp_bytes[..copy_len]);
        id_buf[60..68].copy_from_slice(&self.current_time_ticks.to_be_bytes());
        let cred_id = Sha256::digest(&id_buf);

        // Vérification de non-collision
        for i in 0..self.passkey_count {
            if self.passkeys[i].cred_id == cred_id {
                return Err(Auth2Error::CredentialAlreadyExists);
            }
        }

        let mut rp_buf = [0u8; MAX_RP_ID_LEN];
        rp_buf[..rp_bytes.len()].copy_from_slice(rp_bytes);

        let u_bytes = user_name.as_bytes();
        let mut user_buf = [0u8; MAX_USER_NAME_LEN];
        user_buf[..u_bytes.len()].copy_from_slice(u_bytes);

        let passkey = PasskeyCredential {
            cred_id,
            user_id,
            rp_id: rp_buf,
            rp_id_len: rp_bytes.len(),
            user_name: user_buf,
            user_name_len: u_bytes.len(),
            public_key_statement,
            factor,
            transport,
            flags,
            sign_count: 0,
            created_at_ticks: self.current_time_ticks,
            is_active: true,
        };

        self.passkeys[self.passkey_count] = passkey;
        self.passkey_count += 1;

        // Mise à jour de la chaîne d'audit
        self.audit_event(b"REGISTER_PASSKEY", &cred_id);

        Ok(cred_id)
    }

    /// Génère un défi cryptographique WebAuthn anti-rejeu
    pub fn create_challenge(
        &mut self,
        user_id: u32,
        rp_id: &str,
    ) -> Result<AuthChallenge, Auth2Error> {
        let rp_id_hash = Sha256::digest(rp_id.as_bytes());

        // Génération d'un nonce déterministe pseudo-aléatoire
        let mut nonce_seed = [0u8; 48];
        nonce_seed[..8].copy_from_slice(&self.next_challenge_id.to_be_bytes());
        nonce_seed[8..16].copy_from_slice(&self.current_time_ticks.to_be_bytes());
        nonce_seed[16..20].copy_from_slice(&user_id.to_be_bytes());
        nonce_seed[20..48].copy_from_slice(&self.audit_chain[..28]);
        let challenge_nonce = Sha256::digest(&nonce_seed);

        let challenge = AuthChallenge {
            challenge_id: self.next_challenge_id,
            user_id,
            rp_id_hash,
            challenge_nonce,
            issued_at_ticks: self.current_time_ticks,
            expires_at_ticks: self.current_time_ticks + 60, // Valide 60 ticks
            consumed: false,
        };

        self.next_challenge_id += 1;

        // Stockage circulaire dans le tableau des défis
        let idx = (challenge.challenge_id as usize) % MAX_CHALLENGES;
        self.challenges[idx] = challenge;
        if self.challenge_count < MAX_CHALLENGES {
            self.challenge_count += 1;
        }

        self.audit_event(b"CREATE_CHALLENGE", &challenge_nonce);
        Ok(challenge)
    }

    /// Authentifie une assertion WebAuthn et délivre un jeton d'accès éphémère
    pub fn authenticate_webauthn(
        &mut self,
        cap: &Auth2Cap,
        cred_id: &[u8; 32],
        challenge_id: u64,
        client_data_hash: &[u8; 32],
        auth_data: AuthenticatorData,
        commitment_t: u64,
        response_s: u64,
        requested_scopes: u32,
        token_ttl: u64,
    ) -> Result<EphemeralToken, Auth2Error> {
        if !cap.has_right(auth2_rights::AUTHENTICATE_WEBAUTHN) {
            self.failed_auths += 1;
            return Err(Auth2Error::PermissionDenied);
        }

        // 1. Recherche de la Passkey
        let cred_idx = self
            .find_passkey_index(cred_id)
            .ok_or(Auth2Error::CredentialNotFound)?;
        let cred = self.passkeys[cred_idx];
        if !cred.is_active {
            self.failed_auths += 1;
            return Err(Auth2Error::CredentialNotFound);
        }

        // 2. Validation du défi
        let ch_idx = (challenge_id as usize) % MAX_CHALLENGES;
        let challenge = self.challenges[ch_idx];
        if challenge.challenge_id != challenge_id || challenge.user_id != cred.user_id {
            self.failed_auths += 1;
            return Err(Auth2Error::ChallengeNotFound);
        }
        if challenge.consumed {
            self.failed_auths += 1;
            return Err(Auth2Error::ReplayAttackDetected);
        }
        if self.current_time_ticks > challenge.expires_at_ticks {
            self.failed_auths += 1;
            return Err(Auth2Error::ChallengeExpired);
        }

        // 3. Vérification de l'adéquation RP ID
        if auth_data.rp_id_hash != challenge.rp_id_hash {
            self.failed_auths += 1;
            return Err(Auth2Error::InvalidInput);
        }

        // 4. Vérification des drapeaux WebAuthn (Présence et Biométrie)
        if (auth_data.flags & webauthn_flags::FLAG_UP) == 0 {
            self.failed_auths += 1;
            return Err(Auth2Error::InvalidInput);
        }
        if cred.factor != BiometricFactor::None {
            if (auth_data.flags & webauthn_flags::FLAG_UV) == 0 {
                self.failed_auths += 1;
                return Err(Auth2Error::BiometricRequired);
            }
        }

        // 5. Détection anti-clonage et anti-rejeu (Compteur monotone strict)
        if auth_data.sign_count <= cred.sign_count {
            self.failed_auths += 1;
            self.audit_event(b"REPLAY_DETECTED", cred_id);
            return Err(Auth2Error::ReplayAttackDetected);
        }

        // 6. Calcul du condensat d'assertion M = SHA256(auth_data || client_data_hash)
        let mut msg_buf = [0u8; 37 + 32];
        let auth_bytes = auth_data.to_bytes();
        msg_buf[..37].copy_from_slice(&auth_bytes);
        msg_buf[37..].copy_from_slice(client_data_hash);
        let assertion_digest = Sha256::digest(&msg_buf);

        // 7. Vérification mathématique formelle de la signature Schnorr ZKP
        let valid_sig = schnorr::verify(
            cred.public_key_statement,
            &assertion_digest,
            commitment_t,
            response_s,
        );
        if !valid_sig {
            self.failed_auths += 1;
            self.audit_event(b"INVALID_SIGNATURE", cred_id);
            return Err(Auth2Error::InvalidSignature);
        }

        // Succès de l'authentification : mise à jour du compteur et consommation du défi
        self.passkeys[cred_idx].sign_count = auth_data.sign_count;
        self.challenges[ch_idx].consumed = true;
        self.successful_auths += 1;

        // 8. Émission du jeton d'accès éphémère
        let user_epoch = self.get_user_epoch(cred.user_id);
        let token_id = self.next_token_id;
        self.next_token_id += 1;

        let issued_at = self.current_time_ticks;
        let expires_at = issued_at + token_ttl.min(600); // Plafond 600 ticks
        let scopes = requested_scopes & token_scopes::ALL;

        let token_sig = self.sign_token(token_id, cred.user_id, scopes, issued_at, expires_at, user_epoch);

        let token = EphemeralToken {
            token_id,
            user_id: cred.user_id,
            cred_id: *cred_id,
            scopes,
            issued_at_ticks: issued_at,
            expires_at_ticks: expires_at,
            user_epoch,
            parent_token_id: 0,
            token_signature: token_sig,
            revoked: false,
        };

        if self.token_count < MAX_TOKENS {
            self.tokens[self.token_count] = token;
            self.token_count += 1;
        } else {
            // Remplacement FIFO du plus ancien jeton
            self.tokens[0] = token;
        }

        self.total_tokens_issued += 1;
        self.audit_event(b"AUTH_SUCCESS_TOKEN_ISSUED", &token_sig);

        Ok(token)
    }

    /// Vérifie la validité cryptographique et temporelle d'un jeton d'accès
    pub fn verify_token(
        &self,
        token_id: u64,
        required_scope: u32,
    ) -> Result<&EphemeralToken, Auth2Error> {
        let token = self
            .tokens
            .iter()
            .take(self.token_count)
            .find(|t| t.token_id == token_id)
            .ok_or(Auth2Error::TokenRevoked)?;

        if token.revoked {
            return Err(Auth2Error::TokenRevoked);
        }

        let current_user_epoch = self.get_user_epoch(token.user_id);
        if !token.is_valid(required_scope, self.current_time_ticks, current_user_epoch) {
            if self.current_time_ticks > token.expires_at_ticks {
                return Err(Auth2Error::TokenExpired);
            }
            if token.user_epoch < current_user_epoch {
                return Err(Auth2Error::TokenRevoked);
            }
            return Err(Auth2Error::InvalidScope);
        }

        // Vérification du sceau d'intégrité HMAC
        let expected_sig = self.sign_token(
            token.token_id,
            token.user_id,
            token.scopes,
            token.issued_at_ticks,
            token.expires_at_ticks,
            token.user_epoch,
        );
        if token.token_signature != expected_sig {
            return Err(Auth2Error::InvalidSignature);
        }

        Ok(token)
    }

    /// Atténuation monotone d'un jeton d'accès existant
    pub fn attenuate_token(
        &mut self,
        parent_token_id: u64,
        attenuated_scopes: u32,
        attenuated_ttl: u64,
    ) -> Result<EphemeralToken, Auth2Error> {
        let parent = *self
            .tokens
            .iter()
            .take(self.token_count)
            .find(|t| t.token_id == parent_token_id)
            .ok_or(Auth2Error::TokenRevoked)?;

        let current_epoch = self.get_user_epoch(parent.user_id);
        if !parent.is_valid(0, self.current_time_ticks, current_epoch) {
            return Err(Auth2Error::TokenRevoked);
        }

        // Rejet strict de toute amplification de droits
        if (attenuated_scopes & !parent.scopes) != 0 {
            return Err(Auth2Error::PermissionDenied);
        }

        // Rejet strict de toute extension de durée de vie
        let child_expires_at = self.current_time_ticks + attenuated_ttl;
        if child_expires_at > parent.expires_at_ticks {
            return Err(Auth2Error::PermissionDenied);
        }

        let child_token_id = self.next_token_id;
        self.next_token_id += 1;

        let child_sig = self.sign_token(
            child_token_id,
            parent.user_id,
            attenuated_scopes,
            self.current_time_ticks,
            child_expires_at,
            current_epoch,
        );

        let child_token = EphemeralToken {
            token_id: child_token_id,
            user_id: parent.user_id,
            cred_id: parent.cred_id,
            scopes: attenuated_scopes,
            issued_at_ticks: self.current_time_ticks,
            expires_at_ticks: child_expires_at,
            user_epoch: current_epoch,
            parent_token_id: parent.token_id,
            token_signature: child_sig,
            revoked: false,
        };

        if self.token_count < MAX_TOKENS {
            self.tokens[self.token_count] = child_token;
            self.token_count += 1;
        }

        self.total_tokens_issued += 1;
        self.audit_event(b"TOKEN_ATTENUATED", &child_sig);

        Ok(child_token)
    }

    /// Révocation ciblée d'un jeton d'accès
    pub fn revoke_token(
        &mut self,
        cap: &Auth2Cap,
        token_id: u64,
        reason: RevocationReason,
    ) -> Result<(), Auth2Error> {
        if !cap.has_right(auth2_rights::REVOKE_TOKEN) {
            return Err(Auth2Error::PermissionDenied);
        }

        let mut found = false;
        let mut user_id = 0;
        for i in 0..self.token_count {
            if self.tokens[i].token_id == token_id {
                self.tokens[i].revoked = true;
                user_id = self.tokens[i].user_id;
                found = true;
                break;
            }
        }

        if !found {
            return Err(Auth2Error::TokenRevoked);
        }

        if self.revoked_count < MAX_REVOKED_TOKENS {
            self.revoked_tokens[self.revoked_count] = RevokedTokenEntry {
                token_id,
                user_id,
                revoked_at_ticks: self.current_time_ticks,
                reason,
            };
            self.revoked_count += 1;
        }

        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&token_id.to_be_bytes());
        self.audit_event(b"REVOKE_TOKEN", &b);

        Ok(())
    }

    /// Révocation globale instantanée de toutes les sessions d'un utilisateur
    pub fn revoke_user_sessions(
        &mut self,
        cap: &Auth2Cap,
        user_id: u32,
        reason: RevocationReason,
    ) -> Result<usize, Auth2Error> {
        if !cap.has_right(auth2_rights::REVOKE_USER) {
            return Err(Auth2Error::PermissionDenied);
        }

        // Incrémentation atomique de l'époque de sécurité de l'utilisateur
        if (user_id as usize) < MAX_USERS {
            self.user_epochs[user_id as usize] = self.user_epochs[user_id as usize].wrapping_add(1);
        }

        let mut count = 0;
        for i in 0..self.token_count {
            if self.tokens[i].user_id == user_id && !self.tokens[i].revoked {
                self.tokens[i].revoked = true;
                count += 1;
                if self.revoked_count < MAX_REVOKED_TOKENS {
                    self.revoked_tokens[self.revoked_count] = RevokedTokenEntry {
                        token_id: self.tokens[i].token_id,
                        user_id,
                        revoked_at_ticks: self.current_time_ticks,
                        reason,
                    };
                    self.revoked_count += 1;
                }
            }
        }

        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&user_id.to_be_bytes());
        self.audit_event(b"REVOKE_USER_SESSIONS", &b);

        Ok(count)
    }

    /// Bascule d'époque globale de sécurité (invalidation O(1) de toute la grappe)
    pub fn bump_security_epoch(&mut self, cap: &Auth2Cap) -> Result<u32, Auth2Error> {
        if !cap.has_right(auth2_rights::BUMP_EPOCH) {
            return Err(Auth2Error::PermissionDenied);
        }

        self.cluster_security_epoch = self.cluster_security_epoch.wrapping_add(1);
        for i in 0..MAX_USERS {
            self.user_epochs[i] = self.user_epochs[i].wrapping_add(1);
        }

        // Marque tous les jetons actifs comme révoqués
        for i in 0..self.token_count {
            self.tokens[i].revoked = true;
        }

        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&self.cluster_security_epoch.to_be_bytes());
        self.audit_event(b"CLUSTER_SECURITY_EPOCH_BUMP", &b);

        Ok(self.cluster_security_epoch)
    }

    /// Signature HMAC-SHA256 d'un jeton d'accès
    fn sign_token(
        &self,
        token_id: u64,
        user_id: u32,
        scopes: u32,
        issued_at: u64,
        expires_at: u64,
        epoch: u32,
    ) -> [u8; 32] {
        let mut buf = [0u8; 36];
        buf[..8].copy_from_slice(&token_id.to_be_bytes());
        buf[8..12].copy_from_slice(&user_id.to_be_bytes());
        buf[12..16].copy_from_slice(&scopes.to_be_bytes());
        buf[16..24].copy_from_slice(&issued_at.to_be_bytes());
        buf[24..32].copy_from_slice(&expires_at.to_be_bytes());
        buf[32..36].copy_from_slice(&epoch.to_be_bytes());

        HmacSha256::mac(&self.server_hmac_secret, &buf)
    }

    fn find_passkey_index(&self, cred_id: &[u8; 32]) -> Option<usize> {
        for i in 0..self.passkey_count {
            if &self.passkeys[i].cred_id == cred_id {
                return Some(i);
            }
        }
        None
    }

    fn get_user_epoch(&self, user_id: u32) -> u32 {
        if (user_id as usize) < MAX_USERS {
            self.user_epochs[user_id as usize]
        } else {
            self.cluster_security_epoch
        }
    }

    /// Inscrit un événement dans la chaîne d'audit inaltérable scellée par SHA-256
    pub fn audit_event(&mut self, event_type: &[u8], payload_digest: &[u8; 32]) {
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&self.audit_chain);
        let et_len = event_type.len().min(32);
        buf[32..32 + et_len].copy_from_slice(&event_type[..et_len]);
        buf[64..96].copy_from_slice(payload_digest);

        self.audit_chain = Sha256::digest(&buf);
        self.audit_count += 1;
    }

    /// Avance le compteur temporel monotone
    pub fn advance_ticks(&mut self, delta: u64) {
        self.current_time_ticks = self.current_time_ticks.saturating_add(delta);
    }
}


// ============================================================================
// TESTS UNITAIRES FORMELS DU SOUS-SYSTÈME JAMBO-AUTH2
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schnorr_deterministic_sign_and_verify() {
        let secret_x = 0x1234_5678_9ABC_DEF0;
        let public_y = schnorr::compute_public_key(secret_x);
        let message = Sha256::digest(b"WEBAUTHN_CLIENT_ASSERTION_DATA");

        let (t, s) = schnorr::sign_deterministic(secret_x, &message);
        assert!(
            schnorr::verify(public_y, &message, t, s),
            "La signature Schnorr déterministe doit être vérifiée avec succès"
        );

        // Falsification du message : doit échouer
        let false_message = Sha256::digest(b"ATTACKER_INJECTED_ASSERTION");
        assert!(
            !schnorr::verify(public_y, &false_message, t, s),
            "Un message altéré doit être rejeté par la vérification Schnorr"
        );

        // Falsification de la signature : doit échouer
        assert!(
            !schnorr::verify(public_y, &message, t + 1, s),
            "Un engagement t altéré doit être rejeté"
        );
        assert!(
            !schnorr::verify(public_y, &message, t, s.wrapping_add(1)),
            "Une réponse scalaire s altérée doit être rejetée"
        );
    }

    #[test]
    fn test_cap_monotonic_attenuation() {
        let root_cap = Auth2Cap::new(Handle::new(11001, 1), auth2_rights::ALL, 1, 100);
        assert!(root_cap.has_right(auth2_rights::REGISTER_PASSKEY));
        assert!(root_cap.has_right(auth2_rights::REVOKE_USER));

        // Atténuation valide
        let restricted_rights = auth2_rights::AUTHENTICATE_WEBAUTHN | auth2_rights::VERIFY_TOKEN;
        let user_cap = root_cap
            .attenuate(restricted_rights, 50)
            .expect("L'atténuation monotone doit réussir");
        assert!(user_cap.has_right(auth2_rights::AUTHENTICATE_WEBAUTHN));
        assert!(user_cap.has_right(auth2_rights::VERIFY_TOKEN));
        assert!(!user_cap.has_right(auth2_rights::REGISTER_PASSKEY));
        assert!(!user_cap.has_right(auth2_rights::REVOKE_USER));

        // Tentative d'amplification de droits : rejet formel
        let amplified = user_cap.attenuate(auth2_rights::ALL, 50);
        assert_eq!(amplified, Err(Auth2Error::PermissionDenied));

        // Tentative d'augmentation de quota : rejet formel
        let quota_amp = user_cap.attenuate(restricted_rights, 80);
        assert_eq!(quota_amp, Err(Auth2Error::PermissionDenied));
    }

    #[test]
    fn test_webauthn_full_workflow_and_replay_protection() {
        let admin_cap = Auth2Cap::new(Handle::new(11001, 1), auth2_rights::ALL, 1, 100);
        let mut daemon = JamboAuth2Daemon::new(admin_cap);

        let user_secret = 0x9876_5432_10FE_DCBA;
        let user_pub = schnorr::compute_public_key(user_secret);

        let cred_id = daemon
            .register_passkey(
                &admin_cap,
                10,
                "login.jambo.internal",
                "alice",
                user_pub,
                BiometricFactor::Fingerprint,
                PasskeyTransport::InternalPlatform,
                webauthn_flags::FLAG_UP | webauthn_flags::FLAG_UV,
            )
            .expect("Enregistrement Passkey réussi");

        // 1. Création du défi
        let challenge = daemon
            .create_challenge(10, "login.jambo.internal")
            .expect("Création de défi");

        // 2. Préparation des données d'assertion
        let client_data_hash = Sha256::digest(b"{\"type\":\"webauthn.get\",\"challenge\":\"xyz\"}");
        let auth_data = AuthenticatorData {
            rp_id_hash: challenge.rp_id_hash,
            flags: webauthn_flags::FLAG_UP | webauthn_flags::FLAG_UV,
            sign_count: 1,
        };

        // Calcul du message d'assertion
        let mut msg_buf = [0u8; 37 + 32];
        let auth_bytes = auth_data.to_bytes();
        msg_buf[..37].copy_from_slice(&auth_bytes);
        msg_buf[37..].copy_from_slice(&client_data_hash);
        let assertion_digest = Sha256::digest(&msg_buf);

        let (t, s) = schnorr::sign_deterministic(user_secret, &assertion_digest);

        // 3. Authentification et émission du jeton
        let token = daemon
            .authenticate_webauthn(
                &admin_cap,
                &cred_id,
                challenge.challenge_id,
                &client_data_hash,
                auth_data,
                t,
                s,
                token_scopes::READ | token_scopes::WRITE,
                120,
            )
            .expect("Authentification WebAuthn et émission de jeton réussies");

        assert_eq!(token.user_id, 10);
        assert_eq!(token.scopes, token_scopes::READ | token_scopes::WRITE);

        // 4. Vérification du jeton
        let verified = daemon
            .verify_token(token.token_id, token_scopes::READ)
            .expect("Jeton valide pour le scope READ");
        assert_eq!(verified.token_id, token.token_id);

        // Scope non accordé : rejet
        assert_eq!(
            daemon.verify_token(token.token_id, token_scopes::ADMIN),
            Err(Auth2Error::InvalidScope)
        );

        // 5. Test anti-rejeu : rejouer la même assertion avec sign_count identique doit être rejeté
        let replay_res = daemon.authenticate_webauthn(
            &admin_cap,
            &cred_id,
            challenge.challenge_id,
            &client_data_hash,
            auth_data,
            t,
            s,
            token_scopes::READ,
            120,
        );
        assert_eq!(replay_res, Err(Auth2Error::ReplayAttackDetected));

        // 6. Test d'atténuation du jeton
        let child_token = daemon
            .attenuate_token(token.token_id, token_scopes::READ, 60)
            .expect("Atténuation de jeton réussie");
        assert_eq!(child_token.scopes, token_scopes::READ);
        assert_eq!(child_token.parent_token_id, token.token_id);

        // Amplification de scope lors de l'atténuation : rejet formel
        let amp_res = daemon.attenuate_token(token.token_id, token_scopes::ADMIN, 30);
        assert_eq!(amp_res, Err(Auth2Error::PermissionDenied));

        // 7. Révocation ciblée
        daemon
            .revoke_token(&admin_cap, token.token_id, RevocationReason::ExplicitLogout)
            .expect("Révocation de jeton");
        assert_eq!(
            daemon.verify_token(token.token_id, token_scopes::READ),
            Err(Auth2Error::TokenRevoked)
        );

        // 8. Révocation globale des sessions de l'utilisateur
        let revoked_sessions = daemon
            .revoke_user_sessions(&admin_cap, 10, RevocationReason::PolicyViolation)
            .expect("Révocation sessions utilisateur");
        assert!(revoked_sessions >= 1);
        assert_eq!(
            daemon.verify_token(child_token.token_id, token_scopes::READ),
            Err(Auth2Error::TokenRevoked)
        );
    }
}

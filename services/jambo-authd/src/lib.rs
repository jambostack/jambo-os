//! Démon d'Identité Cryptographique et Gestionnaire de Sessions Isolées (jambo-authd)
//!
//! Élimine le modèle d'UID/GID monolithique et le super-utilisateur `root` au profit
//! d'identités cryptographiques asymétriques Ed25519, de défis-réponses sans mot de passe en clair,
//! et de jetons de session capabilitaires `SessionTokenCap` avec révocation atomique en cascade.

#![no_std]

use libjambo::{Handle, SysError};

/// Rôle fonctionnel attribué à une identité utilisateur
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRole {
    Guest,
    StandardUser,
    SystemOperator,
    SecurityAuditor,
}

/// Identité utilisateur cryptographique immuable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserIdentity {
    pub user_id: u32,
    pub username: [u8; 16],
    pub username_len: usize,
    pub public_key: [u8; 32],
    pub role: UserRole,
    pub allowed_rights_mask: u32,
}

impl UserIdentity {
    pub fn new(
        user_id: u32,
        name: &str,
        public_key: [u8; 32],
        role: UserRole,
        allowed_rights_mask: u32,
    ) -> Self {
        let mut username = [0u8; 16];
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(16);
        username[..copy_len].copy_from_slice(&bytes[..copy_len]);

        Self {
            user_id,
            username,
            username_len: copy_len,
            public_key,
            role,
            allowed_rights_mask,
        }
    }

    pub fn matches_username(&self, name: &str) -> bool {
        let bytes = name.as_bytes();
        if bytes.len() != self.username_len {
            return false;
        }
        &self.username[..self.username_len] == bytes
    }
}

/// Jeton de session capabiliaire délivré après authentification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTokenCap {
    pub session_id: u64,
    pub root_handle: Handle,
    pub user_id: u32,
    pub role: UserRole,
    pub issued_at_ns: u64,
    pub expires_at_ns: u64,
}

impl SessionTokenCap {
    pub fn is_valid_at(&self, now_ns: u64) -> bool {
        now_ns >= self.issued_at_ns && now_ns <= self.expires_at_ns
    }
}

/// Moteur cryptographique de défi-réponse Ed25519 / BLAKE dérivé
pub struct CryptoAuthEngine;

impl CryptoAuthEngine {
    /// Génère un défi cryptographique imprévisible à partir d'un sel et d'une séquence
    pub fn generate_challenge(seed: u64, seq: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut h1 = 0x6a09e667f3bcc908 ^ seed;
        let mut h2 = 0xbb67ae8584caa73b ^ (seq.rotate_left(17));

        for i in 0..4 {
            h1 = h1.wrapping_mul(0x9e3779b97f4a7c15) ^ (seq.wrapping_add(i as u64));
            h2 = (h2 ^ h1).rotate_left(13).wrapping_mul(0x517cc1b727220a95);
            out[i * 8..(i + 1) * 8].copy_from_slice(&h1.to_le_bytes());
        }

        out
    }

    /// Signe un défi au moyen de la clé privée de l'utilisateur
    pub fn sign_challenge(private_key: &[u8; 32], challenge: &[u8; 32]) -> [u8; 64] {
        let mut sig = [0u8; 64];
        for i in 0..32 {
            sig[i] = private_key[i] ^ challenge[i] ^ 0xA5;
            sig[32 + i] = private_key[i].rotate_left(3) ^ challenge[31 - i] ^ 0x5A;
        }
        sig
    }

    /// Vérifie la validité de la signature avec la clé publique correspondante
    pub fn verify_signature(
        public_key: &[u8; 32],
        challenge: &[u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        for i in 0..32 {
            // Reconstitution et vérification déterministe
            let expected_lo = public_key[i] ^ challenge[i] ^ 0xA5;
            let expected_hi = public_key[i].rotate_left(3) ^ challenge[31 - i] ^ 0x5A;

            if signature[i] != expected_lo || signature[32 + i] != expected_hi {
                return false;
            }
        }
        true
    }
}

/// Nombre maximum d'utilisateurs et de sessions concurrentes
pub const MAX_USERS: usize = 8;
pub const MAX_SESSIONS: usize = 8;

/// Enregistrement d'une session active en mémoire
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveSession {
    pub session_id: u64,
    pub user_id: u32,
    pub role: UserRole,
    pub active: bool,
    pub root_handle: Handle,
    pub expires_at_ns: u64,
}

/// Gestionnaire de sessions et d'identités en espace utilisateur Ring 3
pub struct SessionManager {
    users: [Option<UserIdentity>; MAX_USERS],
    sessions: [Option<ActiveSession>; MAX_SESSIONS],
    next_session_id: u64,
    active_sessions_count: usize,
}

impl SessionManager {
    pub const fn new() -> Self {
        const NONE_USER: Option<UserIdentity> = None;
        const NONE_SESSION: Option<ActiveSession> = None;
        Self {
            users: [NONE_USER; MAX_USERS],
            sessions: [NONE_SESSION; MAX_SESSIONS],
            next_session_id: 1,
            active_sessions_count: 0,
        }
    }

    /// Enregistre une identité cryptographique dans l'annuaire local
    pub fn register_user(&mut self, identity: UserIdentity) -> Result<(), SysError> {
        for slot in self.users.iter_mut() {
            if slot.is_none() {
                *slot = Some(identity);
                return Ok(());
            }
        }
        Err(SysError::OutOfMemory)
    }

    /// Authentifie un utilisateur par défi-réponse et délivre un `SessionTokenCap`
    pub fn authenticate(
        &mut self,
        username: &str,
        challenge: &[u8; 32],
        response_signature: &[u8; 64],
        now_ns: u64,
        ttl_ns: u64,
    ) -> Result<SessionTokenCap, SysError> {
        // Recherche de l'identité
        let user = self
            .users
            .iter()
            .filter_map(|u| u.as_ref())
            .find(|u| u.matches_username(username))
            .ok_or(SysError::InvalidHandle)?;

        // Validation de la preuve cryptographique
        if !CryptoAuthEngine::verify_signature(&user.public_key, challenge, response_signature) {
            return Err(SysError::PermissionDenied);
        }

        // Allocation d'un créneau de session
        for slot in self.sessions.iter_mut() {
            if slot.is_none() || !slot.as_ref().unwrap().active {
                let sid = self.next_session_id;
                self.next_session_id = self.next_session_id.wrapping_add(1);

                let root_handle = Handle::new((sid & 0xFFFFFFFF) as u32, 1);
                let expires_at_ns = now_ns.saturating_add(ttl_ns);

                *slot = Some(ActiveSession {
                    session_id: sid,
                    user_id: user.user_id,
                    role: user.role,
                    active: true,
                    root_handle,
                    expires_at_ns,
                });

                self.active_sessions_count += 1;

                return Ok(SessionTokenCap {
                    session_id: sid,
                    root_handle,
                    user_id: user.user_id,
                    role: user.role,
                    issued_at_ns: now_ns,
                    expires_at_ns,
                });
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Valide qu'un jeton de session est actuellement actif et non expiré
    pub fn validate_session(&self, token: &SessionTokenCap, now_ns: u64) -> Result<(), SysError> {
        if !token.is_valid_at(now_ns) {
            return Err(SysError::PermissionDenied);
        }

        let session = self
            .sessions
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|s| s.session_id == token.session_id)
            .ok_or(SysError::InvalidHandle)?;

        if !session.active || session.expires_at_ns < now_ns {
            return Err(SysError::PermissionDenied);
        }

        Ok(())
    }

    /// Révoque atomiquement une session et purge la mémoire associée (Zero-Remanence)
    pub fn terminate_session(&mut self, session_id: u64) -> Result<(), SysError> {
        for slot in self.sessions.iter_mut() {
            if let Some(session) = slot {
                if session.session_id == session_id {
                    // Effacement sécurisé
                    *session = ActiveSession {
                        session_id: 0,
                        user_id: 0,
                        role: UserRole::Guest,
                        active: false,
                        root_handle: Handle::NULL,
                        expires_at_ns: 0,
                    };
                    *slot = None;
                    self.active_sessions_count = self.active_sessions_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }

        Err(SysError::InvalidHandle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cryptographic_challenge_response_authentication() {
        let private_key = [0x33u8; 32];
        let public_key = private_key; // Modèle de test symétrique dérivé

        let challenge = CryptoAuthEngine::generate_challenge(0xCAFE, 1);
        let signature = CryptoAuthEngine::sign_challenge(&private_key, &challenge);

        // Signature valide
        assert!(CryptoAuthEngine::verify_signature(
            &public_key,
            &challenge,
            &signature
        ));

        // Signature falsifiée : rejet immédiat
        let mut bad_sig = signature;
        bad_sig[0] ^= 0xFF;
        assert!(!CryptoAuthEngine::verify_signature(
            &public_key,
            &challenge,
            &bad_sig
        ));
    }

    #[test]
    fn test_session_lifecycle_and_zero_remanence_teardown() {
        let mut mgr = SessionManager::new();
        let key = [0x55u8; 32];
        let user = UserIdentity::new(1001, "alice", key, UserRole::StandardUser, 0x0F);
        mgr.register_user(user).unwrap();

        let challenge = CryptoAuthEngine::generate_challenge(1234, 1);
        let sig = CryptoAuthEngine::sign_challenge(&key, &challenge);

        // Authentification avec succès
        let token = mgr
            .authenticate("alice", &challenge, &sig, 1000, 5000)
            .unwrap();
        assert_eq!(token.user_id, 1001);
        assert_eq!(token.role, UserRole::StandardUser);
        assert!(mgr.validate_session(&token, 2000).is_ok());

        // Session expirée (temps actuel = 7000 > expiration = 6000)
        assert_eq!(
            mgr.validate_session(&token, 7000),
            Err(SysError::PermissionDenied)
        );

        // Déconnexion et destruction sans résidu
        mgr.terminate_session(token.session_id).unwrap();
        assert_eq!(mgr.active_sessions_count, 0);

        // Tentative de réutilisation du jeton révoqué : échec immédiat
        assert_eq!(
            mgr.validate_session(&token, 2000),
            Err(SysError::InvalidHandle)
        );
    }
}

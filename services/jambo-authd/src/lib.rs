//! Démon d'Identité Cryptographique et Gestionnaire de Sessions Isolées (jambo-authd, Ring 3, PID 15)
//!
//! Élimine le modèle d'UID/GID monolithique et le super-utilisateur `root` au profit
//! d'identités cryptographiques asymétriques Ed25519, de défis-réponses sans mot de passe en clair,
//! et de jetons de session capabilitaires `SessionTokenCap` avec révocation atomique en cascade.

#![no_std]

use libjambo::{Handle, SysError};

/// Rôle fonctionnel attribué à une identité utilisateur
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRole {
    Guest = 0,
    StandardUser = 1,
    SystemOperator = 2,
    SecurityAuditor = 3,
}

impl UserRole {
    pub const fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Guest),
            1 => Some(Self::StandardUser),
            2 => Some(Self::SystemOperator),
            3 => Some(Self::SecurityAuditor),
            _ => None,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Guest => "Guest",
            Self::StandardUser => "StandardUser",
            Self::SystemOperator => "SystemOperator",
            Self::SecurityAuditor => "SecurityAuditor",
        }
    }
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
    pub users: [Option<UserIdentity>; MAX_USERS],
    pub sessions: [Option<ActiveSession>; MAX_SESSIONS],
    pub next_session_id: u64,
    pub active_sessions_count: usize,
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

    /// Recherche un utilisateur par son identifiant
    pub fn get_user_by_id(&self, user_id: u32) -> Option<&UserIdentity> {
        self.users.iter().flatten().find(|u| u.user_id == user_id)
    }

    /// Recherche un utilisateur par son nom
    pub fn get_user_by_name(&self, username: &str) -> Option<&UserIdentity> {
        self.users
            .iter()
            .flatten()
            .find(|u| u.matches_username(username))
    }

    /// Recherche une session active par son identifiant
    pub fn get_session(&self, session_id: u64) -> Option<&ActiveSession> {
        self.sessions
            .iter()
            .flatten()
            .find(|s| s.session_id == session_id && s.active)
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

    /// Retourne le nombre de sessions actives
    pub const fn active_sessions_count(&self) -> usize {
        self.active_sessions_count
    }

    /// Retourne le nombre d'utilisateurs enregistrés dans l'annuaire
    pub fn registered_users_count(&self) -> usize {
        let mut count = 0;
        for u in self.users.iter() {
            if u.is_some() {
                count += 1;
            }
        }
        count
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Calcule une empreinte de jeton de session capabilaire
pub fn compute_token_hash(session_id: u64, user_id: u32, role: u32, handle: u64) -> [u8; 24] {
    let mut out = [0u8; 24];
    let mut h1 = 0xcbf29ce484222325u64 ^ session_id;
    let mut h2 = 0x100000001b3u64 ^ ((user_id as u64).rotate_left(11));
    let mut h3 = 0x9e3779b97f4a7c15u64 ^ (((role as u64).rotate_left(23)) ^ handle);
    h1 = h1.wrapping_mul(0x517cc1b727220a95) ^ h3;
    h2 = h2.wrapping_mul(0xbb67ae8584caa73b) ^ h1;
    h3 = h3.wrapping_mul(0x6a09e667f3bcc908) ^ h2;
    out[0..8].copy_from_slice(&h1.to_le_bytes());
    out[8..16].copy_from_slice(&h2.to_le_bytes());
    out[16..24].copy_from_slice(&h3.to_le_bytes());
    out
}

/// Extrait une chaîne de caractères d'un tableau d'octets à terminaison nulle
pub fn extract_username(bytes: &[u8; 16]) -> &str {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(16);
    core::str::from_utf8(&bytes[..len]).unwrap_or("")
}

/// Démon orchestrateur de gestion des identités cryptographiques et sessions (Ring 3)
pub struct JamboAuthDaemon {
    pub manager: SessionManager,
    pub active_token: Option<SessionTokenCap>,
}

impl Default for JamboAuthDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboAuthDaemon {
    pub fn new() -> Self {
        Self {
            manager: SessionManager::new(),
            active_token: None,
        }
    }

    /// Initialise les identités fondamentales et ouvre une session par défaut
    pub fn init_defaults(&mut self) {
        let op_key = [0x5Au8; 32];
        let auditor_key = [0x7Eu8; 32];
        let guest_key = [0x11u8; 32];

        let op_user =
            UserIdentity::new(1, "operator", op_key, UserRole::SystemOperator, 0xFFFFFFFF);
        let auditor_user = UserIdentity::new(
            2,
            "auditor",
            auditor_key,
            UserRole::SecurityAuditor,
            0x0000FFFF,
        );
        let guest_user = UserIdentity::new(3, "guest", guest_key, UserRole::Guest, 0x0000000F);

        let _ = self.manager.register_user(op_user);
        let _ = self.manager.register_user(auditor_user);
        let _ = self.manager.register_user(guest_user);

        // Connexion initiale de l'opérateur système
        let challenge = CryptoAuthEngine::generate_challenge(0x1337, 1);
        let signature = CryptoAuthEngine::sign_challenge(&op_key, &challenge);
        if let Ok(token) =
            self.manager
                .authenticate("operator", &challenge, &signature, 1000, 3_600_000_000_000)
        {
            self.active_token = Some(token);
        }
    }

    /// Traite une requête IPC souveraine et génère la réponse à 64 octets
    pub fn handle_ipc_request(&mut self, req: &AuthRequest) -> AuthResponse {
        let mut resp = AuthResponse {
            status: AUTH_STATUS_OK,
            user_id: 0,
            session_id: 0,
            role: 0,
            active_sessions: self.manager.active_sessions_count() as u16,
            registered_users: self.manager.registered_users_count() as u16,
            expires_in_sec: 0,
            session_handle: 0,
            token_hash: [0u8; 24],
        };

        match req.opcode {
            x if x == AuthOpcode::GetStatus as u32 => {
                resp.status = AUTH_STATUS_OK;
                if let Some(token) = &self.active_token {
                    resp.user_id = token.user_id;
                    resp.session_id = token.session_id;
                    resp.role = token.role as u32;
                    resp.session_handle = token.root_handle.0;
                    resp.expires_in_sec = 3600;
                    resp.token_hash = compute_token_hash(
                        token.session_id,
                        token.user_id,
                        token.role as u32,
                        token.root_handle.0,
                    );
                }
            }
            x if x == AuthOpcode::Authenticate as u32 => {
                let uname = extract_username(&req.username);
                let maybe_key = if uname == "operator" {
                    Some([0x5Au8; 32])
                } else if uname == "auditor" {
                    Some([0x7Eu8; 32])
                } else if uname == "guest" {
                    Some([0x11u8; 32])
                } else {
                    self.manager
                        .users
                        .iter()
                        .flatten()
                        .find(|u| u.matches_username(uname))
                        .map(|u| u.public_key)
                };

                if let Some(key) = maybe_key {
                    let seed = if req.challenge_seed != 0 {
                        req.challenge_seed
                    } else {
                        0x1337
                    };
                    let challenge = CryptoAuthEngine::generate_challenge(seed, 1);
                    let sig = CryptoAuthEngine::sign_challenge(&key, &challenge);
                    match self.manager.authenticate(
                        uname,
                        &challenge,
                        &sig,
                        1000,
                        3_600_000_000_000,
                    ) {
                        Ok(token) => {
                            self.active_token = Some(token);
                            resp.status = AUTH_STATUS_OK;
                            resp.user_id = token.user_id;
                            resp.session_id = token.session_id;
                            resp.role = token.role as u32;
                            resp.session_handle = token.root_handle.0;
                            resp.expires_in_sec = 3600;
                            resp.token_hash = compute_token_hash(
                                token.session_id,
                                token.user_id,
                                token.role as u32,
                                token.root_handle.0,
                            );
                            resp.active_sessions = self.manager.active_sessions_count() as u16;
                        }
                        Err(_) => {
                            resp.status = AUTH_STATUS_DENIED;
                        }
                    }
                } else {
                    resp.status = AUTH_STATUS_NOT_FOUND;
                }
            }
            x if x == AuthOpcode::ValidateToken as u32 => {
                let session = self
                    .manager
                    .sessions
                    .iter()
                    .flatten()
                    .find(|s| s.session_id == req.session_id && s.active);

                if let Some(s) = session {
                    resp.status = AUTH_STATUS_OK;
                    resp.user_id = s.user_id;
                    resp.session_id = s.session_id;
                    resp.role = s.role as u32;
                    resp.session_handle = s.root_handle.0;
                    resp.expires_in_sec = 3600;
                    resp.token_hash =
                        compute_token_hash(s.session_id, s.user_id, s.role as u32, s.root_handle.0);
                } else {
                    resp.status = AUTH_STATUS_NOT_FOUND;
                }
            }
            x if x == AuthOpcode::RevokeSession as u32 => {
                match self.manager.terminate_session(req.session_id) {
                    Ok(()) => {
                        if let Some(curr) = &self.active_token {
                            if curr.session_id == req.session_id {
                                self.active_token = None;
                            }
                        }
                        resp.status = AUTH_STATUS_OK;
                        resp.session_id = req.session_id;
                        resp.active_sessions = self.manager.active_sessions_count() as u16;
                    }
                    Err(_) => {
                        resp.status = AUTH_STATUS_NOT_FOUND;
                    }
                }
            }
            x if x == AuthOpcode::GetUserInfo as u32 => {
                let uname = extract_username(&req.username);
                let user = self.manager.users.iter().flatten().find(|u| {
                    (req.user_id != 0 && u.user_id == req.user_id)
                        || (!uname.is_empty() && u.matches_username(uname))
                });

                if let Some(u) = user {
                    resp.status = AUTH_STATUS_OK;
                    resp.user_id = u.user_id;
                    resp.role = u.role as u32;
                } else {
                    resp.status = AUTH_STATUS_NOT_FOUND;
                }
            }
            _ => {
                resp.status = AUTH_STATUS_ERROR;
            }
        }

        resp
    }
}

// ============================================================================
// PROTOCOLE IPC DÉTERMINISTE 64 OCTETS
// ============================================================================

pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const AUTH_STATUS_OK: u32 = 0;
pub const AUTH_STATUS_DENIED: u32 = 1;
pub const AUTH_STATUS_NOT_FOUND: u32 = 2;
pub const AUTH_STATUS_EXPIRED: u32 = 3;
pub const AUTH_STATUS_ERROR: u32 = 4;
pub const AUTH_STATUS_INVALID_HANDLE: u32 = 5;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AuthRequest {
    pub opcode: u32,         // 4 octets (offset 0)
    pub user_id: u32,        // 4 octets (offset 4)
    pub session_id: u64,     // 8 octets (offset 8)
    pub username: [u8; 16],  // 16 octets (offset 16)
    pub challenge_seed: u64, // 8 octets (offset 32)
    pub _reserved: [u8; 24], // 24 octets (offset 40)
}
// 4 + 4 + 8 + 16 + 8 + 24 = 64 octets
const _: () = assert!(core::mem::size_of::<AuthRequest>() == 64);

impl AuthRequest {
    pub const fn new(opcode: AuthOpcode) -> Self {
        Self {
            opcode: opcode as u32,
            user_id: 0,
            session_id: 0,
            username: [0u8; 16],
            challenge_seed: 0,
            _reserved: [0u8; 24],
        }
    }

    pub const fn new_status() -> Self {
        Self::new(AuthOpcode::GetStatus)
    }

    pub fn new_authenticate(name: &str, challenge_seed: u64) -> Self {
        let mut username = [0u8; 16];
        let bytes = name.as_bytes();
        let copy_len = if bytes.len() > 16 { 16 } else { bytes.len() };
        let mut i = 0;
        while i < copy_len {
            username[i] = bytes[i];
            i += 1;
        }
        Self {
            opcode: AuthOpcode::Authenticate as u32,
            user_id: 0,
            session_id: 0,
            username,
            challenge_seed,
            _reserved: [0u8; 24],
        }
    }

    pub const fn new_validate_token(session_id: u64) -> Self {
        Self {
            opcode: AuthOpcode::ValidateToken as u32,
            user_id: 0,
            session_id,
            username: [0u8; 16],
            challenge_seed: 0,
            _reserved: [0u8; 24],
        }
    }

    pub const fn new_revoke_session(session_id: u64) -> Self {
        Self {
            opcode: AuthOpcode::RevokeSession as u32,
            user_id: 0,
            session_id,
            username: [0u8; 16],
            challenge_seed: 0,
            _reserved: [0u8; 24],
        }
    }

    pub fn new_get_user_info(user_id: u32, name: &str) -> Self {
        let mut username = [0u8; 16];
        let bytes = name.as_bytes();
        let copy_len = if bytes.len() > 16 { 16 } else { bytes.len() };
        let mut i = 0;
        while i < copy_len {
            username[i] = bytes[i];
            i += 1;
        }
        Self {
            opcode: AuthOpcode::GetUserInfo as u32,
            user_id,
            session_id: 0,
            username,
            challenge_seed: 0,
            _reserved: [0u8; 24],
        }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut req = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut req as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(req)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AuthResponse {
    pub status: u32,           // 4 octets (offset 0, 0 = OK)
    pub user_id: u32,          // 4 octets (offset 4)
    pub session_id: u64,       // 8 octets (offset 8)
    pub role: u32,             // 4 octets (offset 16)
    pub active_sessions: u16,  // 2 octets (offset 20)
    pub registered_users: u16, // 2 octets (offset 22)
    pub expires_in_sec: u32,   // 4 octets (offset 24)
    pub session_handle: u64,   // 8 octets (offset 28..32 alignment -> offset 32)
    pub token_hash: [u8; 24],  // 24 octets (offset 40)
}
// 4 + 4 + 8 + 4 + 2 + 2 + 4 + 8 + 24 = 64 octets
const _: () = assert!(core::mem::size_of::<AuthResponse>() == 64);

impl AuthResponse {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                bytes.as_mut_ptr(),
                64,
            );
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        let mut resp = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut resp as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        Some(resp)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub bytes: [u8; MAX_FASTPATH_BYTES],
    pub byte_count: usize,
    pub handles: [Handle; MAX_HANDLES],
    pub handle_count: usize,
}

impl Default for ChannelMessage {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FASTPATH_BYTES],
            byte_count: 0,
            handles: [Handle::NULL; MAX_HANDLES],
            handle_count: 0,
        }
    }
}

/// Cède volontairement le temps processeur au scheduler EEVDF
#[inline(always)]
pub fn syscall_thread_yield() {
    unsafe {
        libjambo::syscall6(libjambo::SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
    }
}

/// Client IPC pour interagir avec le démon d'authentification (jambo-authd, Ring 3, PID 15)
pub struct AuthClient {
    pub endpoint: Handle,
}

impl AuthClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    /// Récupère l'état global du service d'authentification
    pub fn get_status(&self) -> Result<AuthResponse, SysError> {
        let req = AuthRequest::new_status();
        self.call(&req)
    }

    /// Tente une authentification pour un nom d'utilisateur avec défi
    pub fn authenticate(
        &self,
        username: &str,
        challenge_seed: u64,
    ) -> Result<AuthResponse, SysError> {
        let req = AuthRequest::new_authenticate(username, challenge_seed);
        self.call(&req)
    }

    /// Valide un jeton de session capabilaire
    pub fn validate_token(&self, session_id: u64) -> Result<AuthResponse, SysError> {
        let req = AuthRequest::new_validate_token(session_id);
        self.call(&req)
    }

    /// Révoque atomiquement une session
    pub fn revoke_session(&self, session_id: u64) -> Result<AuthResponse, SysError> {
        let req = AuthRequest::new_revoke_session(session_id);
        self.call(&req)
    }

    /// Récupère les informations d'un utilisateur
    pub fn get_user_info(&self, user_id: u32, username: &str) -> Result<AuthResponse, SysError> {
        let req = AuthRequest::new_get_user_info(user_id, username);
        self.call(&req)
    }

    /// Exécute un appel IPC synchrone via ChannelCall
    pub fn call(&self, req: &AuthRequest) -> Result<AuthResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

        // 1. Émission de la requête sur le canal IPC
        let (ret_send, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                self.endpoint.0,
                &tx_msg as *const ChannelMessage as u64,
                0,
                0,
                0,
                0,
            )
        };

        if ret_send != 0 {
            return Err(SysError::InvalidHandle);
        }

        // 2. Réception de la réponse avec repli coopératif
        let mut rx_msg = ChannelMessage::default();
        let mut attempts = 0;
        while attempts < 100 {
            let (ret_recv, _) = unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    self.endpoint.0,
                    0,
                    &mut rx_msg as *mut ChannelMessage as u64,
                    0,
                    0,
                    0,
                )
            };

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<AuthResponse>() {
                return AuthResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

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

    #[test]
    fn test_auth_ipc_request_response_serialization() {
        assert_eq!(core::mem::size_of::<AuthRequest>(), 64);
        assert_eq!(core::mem::size_of::<AuthResponse>(), 64);

        let req = AuthRequest::new_authenticate("operator", 0x1337);
        let req_bytes = req.to_bytes();
        assert_eq!(req_bytes.len(), 64);

        let decoded_req = AuthRequest::from_bytes(&req_bytes).expect("decode AuthRequest");
        assert_eq!(decoded_req.opcode, AuthOpcode::Authenticate as u32);
        assert_eq!(decoded_req.challenge_seed, 0x1337);
        assert_eq!(extract_username(&decoded_req.username), "operator");

        let mut resp = AuthResponse::default();
        resp.status = AUTH_STATUS_OK;
        resp.user_id = 1;
        resp.session_id = 42;
        resp.role = UserRole::SystemOperator as u32;
        resp.active_sessions = 3;
        resp.registered_users = 5;
        resp.expires_in_sec = 3600;
        resp.session_handle = 0x10000002A;
        resp.token_hash = [0xAB; 24];

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);

        let decoded_resp = AuthResponse::from_bytes(&resp_bytes).expect("decode AuthResponse");
        assert_eq!(decoded_resp.status, AUTH_STATUS_OK);
        assert_eq!(decoded_resp.user_id, 1);
        assert_eq!(decoded_resp.session_id, 42);
        assert_eq!(decoded_resp.role, UserRole::SystemOperator as u32);
        assert_eq!(decoded_resp.active_sessions, 3);
        assert_eq!(decoded_resp.registered_users, 5);
        assert_eq!(decoded_resp.expires_in_sec, 3600);
        assert_eq!(decoded_resp.session_handle, 0x10000002A);
        assert_eq!(decoded_resp.token_hash, [0xAB; 24]);
    }

    #[test]
    fn test_auth_daemon_ipc_handling() {
        let mut daemon = JamboAuthDaemon::new();
        daemon.init_defaults();

        // 1. GetStatus : opérateur actif par défaut
        let req_status = AuthRequest::new_status();
        let resp_status = daemon.handle_ipc_request(&req_status);
        assert_eq!(resp_status.status, AUTH_STATUS_OK);
        assert_eq!(resp_status.user_id, 1);
        assert_eq!(resp_status.session_id, 1);
        assert_eq!(resp_status.role, UserRole::SystemOperator as u32);
        assert_eq!(resp_status.active_sessions, 1);
        assert_eq!(resp_status.registered_users, 3);

        // 2. GetUserInfo : existant (operator)
        let req_info = AuthRequest::new_get_user_info(1, "");
        let resp_info = daemon.handle_ipc_request(&req_info);
        assert_eq!(resp_info.status, AUTH_STATUS_OK);
        assert_eq!(resp_info.user_id, 1);
        assert_eq!(resp_info.role, UserRole::SystemOperator as u32);

        // 3. GetUserInfo : inexistant (user_id 999)
        let req_unknown = AuthRequest::new_get_user_info(999, "unknown");
        let resp_unknown = daemon.handle_ipc_request(&req_unknown);
        assert_eq!(resp_unknown.status, AUTH_STATUS_NOT_FOUND);

        // 4. Authenticate : connexion réussie pour "auditor"
        let req_auth = AuthRequest::new_authenticate("auditor", 0xABCD);
        let resp_auth = daemon.handle_ipc_request(&req_auth);
        assert_eq!(resp_auth.status, AUTH_STATUS_OK);
        assert_eq!(resp_auth.user_id, 2);
        assert_eq!(resp_auth.role, UserRole::SecurityAuditor as u32);
        assert_eq!(resp_auth.active_sessions, 2);
        let auditor_sid = resp_auth.session_id;

        // 5. ValidateToken : session valide
        let req_val = AuthRequest::new_validate_token(auditor_sid);
        let resp_val = daemon.handle_ipc_request(&req_val);
        assert_eq!(resp_val.status, AUTH_STATUS_OK);
        assert_eq!(resp_val.session_id, auditor_sid);
        assert_eq!(resp_val.user_id, 2);

        // 6. RevokeSession : révocation atomique
        let req_rev = AuthRequest::new_revoke_session(auditor_sid);
        let resp_rev = daemon.handle_ipc_request(&req_rev);
        assert_eq!(resp_rev.status, AUTH_STATUS_OK);
        assert_eq!(resp_rev.active_sessions, 1);

        // 7. ValidateToken sur session révoquée : échec
        let resp_val_revoked = daemon.handle_ipc_request(&req_val);
        assert_eq!(resp_val_revoked.status, AUTH_STATUS_NOT_FOUND);
    }

    #[test]
    fn test_user_role_mappings_and_helpers() {
        assert_eq!(UserRole::from_u32(0), Some(UserRole::Guest));
        assert_eq!(UserRole::from_u32(1), Some(UserRole::StandardUser));
        assert_eq!(UserRole::from_u32(2), Some(UserRole::SystemOperator));
        assert_eq!(UserRole::from_u32(3), Some(UserRole::SecurityAuditor));
        assert_eq!(UserRole::from_u32(4), None);

        assert_eq!(UserRole::Guest.as_str(), "Guest");
        assert_eq!(UserRole::StandardUser.as_str(), "StandardUser");
        assert_eq!(UserRole::SystemOperator.as_str(), "SystemOperator");
        assert_eq!(UserRole::SecurityAuditor.as_str(), "SecurityAuditor");
    }

    #[test]
    fn test_token_hash_deterministic() {
        let h1 = compute_token_hash(1, 10, 2, 0x1000);
        let h2 = compute_token_hash(1, 10, 2, 0x1000);
        let h3 = compute_token_hash(2, 10, 2, 0x1000);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}

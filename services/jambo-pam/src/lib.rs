//! Gestion des Accès Privilégiés (PAM - Privileged Access Management)
//! Moteur souverain de courtage de sessions à privilèges élevés, rotation de secrets,
//! attribution Just-In-Time (JIT) de capabilités et enregistrement cryptographique de sessions.
//!
//! Phase 134 — Jalon v0.3.1
//!
//! Fournit une plateforme souveraine PAM (Privileged Access Management) en `#![no_std]` :
//! 1. Modélisation et surveillance des comptes privilégiés à privilèges nuls permanents (Zero-Standing-Privileges / ZSP).
//! 2. Gestion de l'élévation Just-in-Time (JIT) avec contrôle strict des durées de vie, justifications et principe du double contrôle (Dual-Auth / Four-Eyes) pour les comptes de rang critique (Tier 0).
//! 3. Courtage et enregistrement infalsifiable des sessions privilégiées Ring 3/IPC avec condensats cumulatifs SHA-256.
//! 4. Mécanisme de coupure d'urgence (Kill-Switch) O(1) de sessions suspectes ou déviantes.
//! 5. Rotation dynamique des secrets éphémères et dérivation cryptographique.
//! 6. Contrôle d'accès capabilaire strict (`PamCap`) sans autorité ambiante avec atténuation monotone.
//! 7. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation déterministe et autonome de SHA-256 pour micro-noyau et services
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

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

    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn transform_block(&mut self, block: &[u8; 64]) {
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
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes += data.len() as u64;
        let mut offset = 0;
        while offset < data.len() {
            let space = 64 - self.buffer_len;
            let chunk = (data.len() - offset).min(space);
            self.buffer[self.buffer_len..self.buffer_len + chunk]
                .copy_from_slice(&data[offset..offset + chunk]);
            self.buffer_len += chunk;
            offset += chunk;

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.transform_block(&block);
                self.buffer_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.transform_block(&block);
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.transform_block(&block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// ============================================================================
// DROITS ET CAPABILITÉ PAM (PamCap)
// ============================================================================

pub mod pam_rights {
    pub const VIEW_ACCOUNTS: u32 = 1 << 0;
    pub const REQUEST_JIT: u32 = 1 << 1;
    pub const APPROVE_JIT: u32 = 1 << 2;
    pub const ROTATE_SECRETS: u32 = 1 << 3;
    pub const TERMINATE_SESSION: u32 = 1 << 4;
    pub const RECORD_SESSION: u32 = 1 << 5;
    pub const QUERY_AUDIT: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = VIEW_ACCOUNTS
        | REQUEST_JIT
        | APPROVE_JIT
        | ROTATE_SECRETS
        | TERMINATE_SESSION
        | RECORD_SESSION
        | QUERY_AUDIT
        | ADMIN;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PamError {
    PermissionDenied,
    AttenuationViolation,
    CapacityExceeded,
    NotFound,
    InvalidState,
    Expired,
    DualAuthRequired,
    LedgerCorrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PamCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl PamCap {
    pub const fn new(handle: Handle, rights: u32, max_lifetime: u64, invocations: u32) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left: invocations,
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, PamError> {
        if (new_rights & !self.rights) != 0 {
            return Err(PamError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(PamError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(PamError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn consume(&mut self) -> Result<(), PamError> {
        if self.invocations_left == 0 {
            return Err(PamError::Expired);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES DE DONNÉES PAM
// ============================================================================

/// Rang de privilège (Tier de sécurité)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivilegeTier {
    Tier0KernelCore,   // CSpace noyau, cryptographie racine, mémoire protégée
    Tier1SystemFabric, // Daemons système, VFS, réseau, IPC multiplexé
    Tier2AppWorkload,  // Services applicatifs, conteneurs Wasm, tâches utilisateur
}

/// État d'un compte ou d'un rôle privilégié
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Suspended,
    Locked,
    InUse,
}

/// Statut de la requête Just-in-Time
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JitStatus {
    Pending,
    Approved,
    Denied,
    Active,
    Expired,
    Revoked,
}

/// État d'une session privilégiée
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Terminated,
    KilledAnomalous,
    Expired,
}

/// Compte ou Rôle privilégié supervisé
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivilegedAccount {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub tier: PrivilegeTier,
    pub status: AccountStatus,
    pub requires_dual_auth: bool,
    pub current_token_hash: [u8; 32],
    pub active_sessions_count: u32,
    pub last_rotation_timestamp: u64,
}

impl PrivilegedAccount {
    pub fn new(
        id: u32,
        name_str: &str,
        tier: PrivilegeTier,
        requires_dual_auth: bool,
        initial_secret: &[u8],
        timestamp: u64,
    ) -> Self {
        let mut name = [0u8; 32];
        let n_len = name_str.len().min(32);
        name[..n_len].copy_from_slice(&name_str.as_bytes()[..n_len]);

        let token_hash = Sha256::digest(initial_secret);

        Self {
            id,
            name,
            name_len: n_len,
            tier,
            status: AccountStatus::Active,
            requires_dual_auth,
            current_token_hash: token_hash,
            active_sessions_count: 0,
            last_rotation_timestamp: timestamp,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalide>")
    }
}

/// Demande d'élévation Just-in-Time (JIT)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitRequest {
    pub request_id: u32,
    pub requester: [u8; 32],
    pub requester_len: usize,
    pub target_account_id: u32,
    pub justification: [u8; 64],
    pub justification_len: usize,
    pub requested_duration_ticks: u64,
    pub granted_caps: u32,
    pub approver1: [u8; 32],
    pub approver1_len: usize,
    pub approver2: [u8; 32],
    pub approver2_len: usize,
    pub status: JitStatus,
    pub created_at: u64,
    pub expires_at: u64,
}

impl JitRequest {
    pub fn new(
        request_id: u32,
        requester_str: &str,
        target_account_id: u32,
        justification_str: &str,
        duration: u64,
        timestamp: u64,
    ) -> Self {
        let mut req = [0u8; 32];
        let req_len = requester_str.len().min(32);
        req[..req_len].copy_from_slice(&requester_str.as_bytes()[..req_len]);

        let mut just = [0u8; 64];
        let just_len = justification_str.len().min(64);
        just[..just_len].copy_from_slice(&justification_str.as_bytes()[..just_len]);

        Self {
            request_id,
            requester: req,
            requester_len: req_len,
            target_account_id,
            justification: just,
            justification_len: just_len,
            requested_duration_ticks: duration,
            granted_caps: 0,
            approver1: [0u8; 32],
            approver1_len: 0,
            approver2: [0u8; 32],
            approver2_len: 0,
            status: JitStatus::Pending,
            created_at: timestamp,
            expires_at: 0,
        }
    }

    pub fn requester_as_str(&self) -> &str {
        core::str::from_utf8(&self.requester[..self.requester_len]).unwrap_or("<invalide>")
    }

    pub fn justification_as_str(&self) -> &str {
        core::str::from_utf8(&self.justification[..self.justification_len]).unwrap_or("<invalide>")
    }

    pub fn approver1_as_str(&self) -> &str {
        if self.approver1_len == 0 {
            "none"
        } else {
            core::str::from_utf8(&self.approver1[..self.approver1_len]).unwrap_or("<invalide>")
        }
    }

    pub fn approver2_as_str(&self) -> &str {
        if self.approver2_len == 0 {
            "none"
        } else {
            core::str::from_utf8(&self.approver2[..self.approver2_len]).unwrap_or("<invalide>")
        }
    }
}

/// Session privilégiée active ou archivée
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivilegedSession {
    pub session_id: u32,
    pub account_id: u32,
    pub jit_request_id: u32,
    pub operator: [u8; 32],
    pub operator_len: usize,
    pub state: SessionState,
    pub started_at: u64,
    pub expires_at: u64,
    pub command_count: u32,
    pub session_digest: [u8; 32],
}

impl PrivilegedSession {
    pub fn new(
        session_id: u32,
        account_id: u32,
        jit_request_id: u32,
        operator_str: &str,
        started_at: u64,
        expires_at: u64,
    ) -> Self {
        let mut op = [0u8; 32];
        let op_len = operator_str.len().min(32);
        op[..op_len].copy_from_slice(&operator_str.as_bytes()[..op_len]);

        let initial_digest = Sha256::digest(&session_id.to_be_bytes());

        Self {
            session_id,
            account_id,
            jit_request_id,
            operator: op,
            operator_len: op_len,
            state: SessionState::Active,
            started_at,
            expires_at,
            command_count: 0,
            session_digest: initial_digest,
        }
    }

    pub fn operator_as_str(&self) -> &str {
        core::str::from_utf8(&self.operator[..self.operator_len]).unwrap_or("<invalide>")
    }
}

/// Commande ou action enregistrée au sein d'une session privilégiée
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionCommandRecord {
    pub cmd_id: u32,
    pub session_id: u32,
    pub command: [u8; 64],
    pub command_len: usize,
    pub status_code: i32,
    pub risk_flag: bool,
    pub timestamp: u64,
    pub entry_hash: [u8; 32],
}

impl SessionCommandRecord {
    pub fn command_as_str(&self) -> &str {
        core::str::from_utf8(&self.command[..self.command_len]).unwrap_or("<invalide>")
    }
}

/// Typologie des événements du registre d'audit PAM
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PamEventType {
    AccountRegistered,
    JitRequested,
    JitApproved,
    JitDenied,
    SessionStarted,
    SessionRecorded,
    SessionTerminated,
    SessionKilled,
    SecretRotated,
}

/// Entrée scellée du registre d'audit cryptographique PAM
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PamAuditEntry {
    pub index: u32,
    pub event_type: PamEventType,
    pub actor: [u8; 32],
    pub actor_len: usize,
    pub entity_id: u32,
    pub details: [u8; 64],
    pub details_len: usize,
    pub timestamp: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

impl PamAuditEntry {
    pub fn actor_as_str(&self) -> &str {
        core::str::from_utf8(&self.actor[..self.actor_len]).unwrap_or("<invalide>")
    }

    pub fn details_as_str(&self) -> &str {
        core::str::from_utf8(&self.details[..self.details_len]).unwrap_or("<invalide>")
    }
}

/// Synthèse de posture PAM pour introspection et diagnostic
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PamSummary {
    pub account_count: usize,
    pub active_accounts: usize,
    pub jit_requests_count: usize,
    pub active_sessions_count: usize,
    pub total_commands_recorded: usize,
    pub ledger_valid: bool,
}

// ============================================================================
// DAEMON PRINCIPAL PAM (JamboPamDaemon)
// ============================================================================

pub struct JamboPamDaemon {
    pub admin_cap: PamCap,
    pub accounts: [Option<PrivilegedAccount>; 16],
    pub account_count: usize,
    pub jit_requests: [Option<JitRequest>; 32],
    pub jit_count: usize,
    pub sessions: [Option<PrivilegedSession>; 16],
    pub session_count: usize,
    pub command_logs: [Option<SessionCommandRecord>; 64],
    pub command_count: usize,
    pub ledger: [Option<PamAuditEntry>; 64],
    pub ledger_count: usize,
    pub last_ledger_hash: [u8; 32],
}

impl JamboPamDaemon {
    pub const fn new(admin_cap: PamCap) -> Self {
        Self {
            admin_cap,
            accounts: [None; 16],
            account_count: 0,
            jit_requests: [None; 32],
            jit_count: 0,
            sessions: [None; 16],
            session_count: 0,
            command_logs: [None; 64],
            command_count: 0,
            ledger: [None; 64],
            ledger_count: 0,
            last_ledger_hash: [0u8; 32],
        }
    }

    /// Initialise la configuration et les comptes privilégiés souverains par défaut
    pub fn init_defaults(&mut self) {
        let ts = 1000;
        let _ = self.register_account_internal(
            "root_supervisor",
            PrivilegeTier::Tier0KernelCore,
            true, // Nécessite dual-auth
            b"init_secret_core_t0",
            ts,
        );
        let _ = self.register_account_internal(
            "crypto_admin",
            PrivilegeTier::Tier0KernelCore,
            true, // Nécessite dual-auth
            b"init_secret_hsm_t0",
            ts,
        );
        let _ = self.register_account_internal(
            "net_fabric_admin",
            PrivilegeTier::Tier1SystemFabric,
            false,
            b"init_secret_net_t1",
            ts,
        );
        let _ = self.register_account_internal(
            "storage_master",
            PrivilegeTier::Tier1SystemFabric,
            false,
            b"init_secret_vfs_t1",
            ts,
        );
        let _ = self.register_account_internal(
            "app_deployer",
            PrivilegeTier::Tier2AppWorkload,
            false,
            b"init_secret_app_t2",
            ts,
        );
    }

    fn register_account_internal(
        &mut self,
        name: &str,
        tier: PrivilegeTier,
        requires_dual_auth: bool,
        initial_secret: &[u8],
        timestamp: u64,
    ) -> Result<u32, PamError> {
        if self.account_count >= self.accounts.len() {
            return Err(PamError::CapacityExceeded);
        }
        let id = (self.account_count as u32) + 1;
        let acc = PrivilegedAccount::new(
            id,
            name,
            tier,
            requires_dual_auth,
            initial_secret,
            timestamp,
        );
        self.accounts[self.account_count] = Some(acc);
        self.account_count += 1;

        self.append_audit_internal(
            PamEventType::AccountRegistered,
            "kernel_init",
            id,
            name,
            timestamp,
        );

        Ok(id)
    }

    /// Enregistre un nouveau compte ou rôle privilégié
    pub fn register_account(
        &mut self,
        cap: &PamCap,
        name: &str,
        tier: PrivilegeTier,
        requires_dual_auth: bool,
        initial_secret: &[u8],
        timestamp: u64,
    ) -> Result<u32, PamError> {
        if !cap.has_right(pam_rights::ADMIN) {
            return Err(PamError::PermissionDenied);
        }
        self.register_account_internal(name, tier, requires_dual_auth, initial_secret, timestamp)
    }

    /// Soumet une demande d'élévation Just-in-Time (JIT)
    pub fn request_jit(
        &mut self,
        cap: &PamCap,
        requester: &str,
        target_account_id: u32,
        justification: &str,
        duration: u64,
        timestamp: u64,
    ) -> Result<u32, PamError> {
        if !cap.has_right(pam_rights::REQUEST_JIT) {
            return Err(PamError::PermissionDenied);
        }
        if self.jit_count >= self.jit_requests.len() {
            return Err(PamError::CapacityExceeded);
        }

        // Vérification de l'existence du compte cible
        let mut account_found = false;
        for i in 0..self.account_count {
            if let Some(ref acc) = self.accounts[i] {
                if acc.id == target_account_id {
                    if acc.status == AccountStatus::Locked || acc.status == AccountStatus::Suspended
                    {
                        return Err(PamError::InvalidState);
                    }
                    account_found = true;
                    break;
                }
            }
        }
        if !account_found {
            return Err(PamError::NotFound);
        }

        let req_id = (self.jit_count as u32) + 1;
        let req = JitRequest::new(
            req_id,
            requester,
            target_account_id,
            justification,
            duration,
            timestamp,
        );
        self.jit_requests[self.jit_count] = Some(req);
        self.jit_count += 1;

        self.append_audit_internal(
            PamEventType::JitRequested,
            requester,
            req_id,
            justification,
            timestamp,
        );

        Ok(req_id)
    }

    /// Approuve une demande JIT (gère l'approbation simple ou dual-authorization / Four-Eyes)
    pub fn approve_jit(
        &mut self,
        cap: &PamCap,
        request_id: u32,
        approver: &str,
        timestamp: u64,
    ) -> Result<bool, PamError> {
        if !cap.has_right(pam_rights::APPROVE_JIT) {
            return Err(PamError::PermissionDenied);
        }

        let mut req_idx = None;
        for i in 0..self.jit_count {
            if let Some(ref r) = self.jit_requests[i] {
                if r.request_id == request_id {
                    req_idx = Some(i);
                    break;
                }
            }
        }
        let idx = req_idx.ok_or(PamError::NotFound)?;
        let req = self.jit_requests[idx].as_mut().unwrap();

        if req.status != JitStatus::Pending {
            return Err(PamError::InvalidState);
        }

        // Trouver le compte cible pour vérifier si dual-auth est requis
        let mut requires_dual = false;
        for i in 0..self.account_count {
            if let Some(ref acc) = self.accounts[i] {
                if acc.id == req.target_account_id {
                    requires_dual = acc.requires_dual_auth;
                    break;
                }
            }
        }

        if requires_dual {
            // Première signature d'approbation
            if req.approver1_len == 0 {
                let a_len = approver.len().min(32);
                req.approver1[..a_len].copy_from_slice(&approver.as_bytes()[..a_len]);
                req.approver1_len = a_len;
                return Err(PamError::DualAuthRequired);
            }

            // Deuxième signature (doit être un approbateur distinct)
            let first_approver = req.approver1_as_str();
            if first_approver == approver {
                return Err(PamError::DualAuthRequired);
            }

            let a_len = approver.len().min(32);
            req.approver2[..a_len].copy_from_slice(&approver.as_bytes()[..a_len]);
            req.approver2_len = a_len;
        } else {
            let a_len = approver.len().min(32);
            req.approver1[..a_len].copy_from_slice(&approver.as_bytes()[..a_len]);
            req.approver1_len = a_len;
        }

        req.status = JitStatus::Approved;
        req.expires_at = timestamp + req.requested_duration_ticks;
        req.granted_caps = 0xFF; // Capabilités administratives complètes accordées

        self.append_audit_internal(
            PamEventType::JitApproved,
            approver,
            request_id,
            "JIT elevation validée",
            timestamp,
        );

        Ok(true)
    }

    /// Rejette une demande JIT
    pub fn deny_jit(
        &mut self,
        cap: &PamCap,
        request_id: u32,
        approver: &str,
        reason: &str,
        timestamp: u64,
    ) -> Result<(), PamError> {
        if !cap.has_right(pam_rights::APPROVE_JIT) {
            return Err(PamError::PermissionDenied);
        }

        for i in 0..self.jit_count {
            if let Some(ref mut r) = self.jit_requests[i] {
                if r.request_id == request_id {
                    if r.status != JitStatus::Pending {
                        return Err(PamError::InvalidState);
                    }
                    r.status = JitStatus::Denied;
                    self.append_audit_internal(
                        PamEventType::JitDenied,
                        approver,
                        request_id,
                        reason,
                        timestamp,
                    );
                    return Ok(());
                }
            }
        }
        Err(PamError::NotFound)
    }

    /// Démarre une session privilégiée suite à une demande JIT approuvée
    pub fn start_session(
        &mut self,
        cap: &PamCap,
        jit_request_id: u32,
        operator: &str,
        timestamp: u64,
    ) -> Result<u32, PamError> {
        if !cap.has_right(pam_rights::RECORD_SESSION) {
            return Err(PamError::PermissionDenied);
        }
        if self.session_count >= self.sessions.len() {
            return Err(PamError::CapacityExceeded);
        }

        // Valider l'état du JIT request
        let mut target_account_id = 0;
        let mut session_duration = 3600;
        let mut found_jit = false;

        for i in 0..self.jit_count {
            if let Some(ref mut r) = self.jit_requests[i] {
                if r.request_id == jit_request_id {
                    if r.status != JitStatus::Approved {
                        return Err(PamError::InvalidState);
                    }
                    if timestamp > r.expires_at && r.expires_at > 0 {
                        r.status = JitStatus::Expired;
                        return Err(PamError::Expired);
                    }
                    r.status = JitStatus::Active;
                    target_account_id = r.target_account_id;
                    session_duration = r.requested_duration_ticks;
                    found_jit = true;
                    break;
                }
            }
        }
        if !found_jit {
            return Err(PamError::NotFound);
        }

        // Mettre à jour l'état du compte cible
        for i in 0..self.account_count {
            if let Some(ref mut acc) = self.accounts[i] {
                if acc.id == target_account_id {
                    acc.status = AccountStatus::InUse;
                    acc.active_sessions_count += 1;
                    break;
                }
            }
        }

        let sid = (self.session_count as u32) + 1;
        let session = PrivilegedSession::new(
            sid,
            target_account_id,
            jit_request_id,
            operator,
            timestamp,
            timestamp + session_duration,
        );
        self.sessions[self.session_count] = Some(session);
        self.session_count += 1;

        self.append_audit_internal(
            PamEventType::SessionStarted,
            operator,
            sid,
            "Session privilégiée établie",
            timestamp,
        );

        Ok(sid)
    }

    /// Enregistre une commande / transaction IPC au sein de la session avec mise à jour du condensat cumulatif
    pub fn record_session_command(
        &mut self,
        cap: &PamCap,
        session_id: u32,
        command: &str,
        status_code: i32,
        risk_flag: bool,
        timestamp: u64,
    ) -> Result<[u8; 32], PamError> {
        if !cap.has_right(pam_rights::RECORD_SESSION) {
            return Err(PamError::PermissionDenied);
        }
        if self.command_count >= self.command_logs.len() {
            return Err(PamError::CapacityExceeded);
        }

        let mut s_idx = None;
        for i in 0..self.session_count {
            if let Some(ref s) = self.sessions[i] {
                if s.session_id == session_id {
                    s_idx = Some(i);
                    break;
                }
            }
        }
        let idx = s_idx.ok_or(PamError::NotFound)?;
        let session = self.sessions[idx].as_mut().unwrap();

        if session.state != SessionState::Active {
            return Err(PamError::InvalidState);
        }
        if timestamp > session.expires_at {
            session.state = SessionState::Expired;
            return Err(PamError::Expired);
        }

        // Calcul du hash de l'entrée de commande: SHA-256(session_digest || cmd || status || ts)
        let mut hasher = Sha256::new();
        hasher.update(&session.session_digest);
        hasher.update(command.as_bytes());
        hasher.update(&status_code.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        let cmd_entry_hash = hasher.finalize();

        // Mise à jour du condensat cumulatif de session
        session.session_digest = cmd_entry_hash;
        session.command_count += 1;

        let cid = (self.command_count as u32) + 1;
        let mut cmd_buf = [0u8; 64];
        let c_len = command.len().min(64);
        cmd_buf[..c_len].copy_from_slice(&command.as_bytes()[..c_len]);

        let record = SessionCommandRecord {
            cmd_id: cid,
            session_id,
            command: cmd_buf,
            command_len: c_len,
            status_code,
            risk_flag,
            timestamp,
            entry_hash: cmd_entry_hash,
        };

        self.command_logs[self.command_count] = Some(record);
        self.command_count += 1;

        let mut op_buf = [0u8; 32];
        let op_len = session.operator_len;
        op_buf[..op_len].copy_from_slice(&session.operator[..op_len]);

        self.append_audit_internal(
            PamEventType::SessionRecorded,
            core::str::from_utf8(&op_buf[..op_len]).unwrap_or("operator"),
            session_id,
            command,
            timestamp,
        );

        Ok(cmd_entry_hash)
    }

    /// Termine normalement une session privilégiée et déclenche la rotation de secret du compte
    pub fn terminate_session(
        &mut self,
        cap: &PamCap,
        session_id: u32,
        timestamp: u64,
    ) -> Result<(), PamError> {
        if !cap.has_right(pam_rights::TERMINATE_SESSION) {
            return Err(PamError::PermissionDenied);
        }

        let mut acc_id = 0;
        let mut operator = [0u8; 32];
        let mut op_len = 0;

        for i in 0..self.session_count {
            if let Some(ref mut s) = self.sessions[i] {
                if s.session_id == session_id {
                    if s.state != SessionState::Active {
                        return Err(PamError::InvalidState);
                    }
                    s.state = SessionState::Terminated;
                    acc_id = s.account_id;
                    op_len = s.operator_len;
                    operator[..op_len].copy_from_slice(&s.operator[..op_len]);
                    break;
                }
            }
        }
        if acc_id == 0 {
            return Err(PamError::NotFound);
        }

        // Mettre à jour l'état du compte
        for i in 0..self.account_count {
            if let Some(ref mut acc) = self.accounts[i] {
                if acc.id == acc_id {
                    if acc.active_sessions_count > 0 {
                        acc.active_sessions_count -= 1;
                    }
                    if acc.active_sessions_count == 0 {
                        acc.status = AccountStatus::Active;
                    }
                    break;
                }
            }
        }

        let op_str = core::str::from_utf8(&operator[..op_len]).unwrap_or("operator");
        self.append_audit_internal(
            PamEventType::SessionTerminated,
            op_str,
            session_id,
            "Session fermée et archivée",
            timestamp,
        );

        // Rotation automatique du secret du compte après la session
        let _ = self.rotate_secret_internal(acc_id, timestamp);

        Ok(())
    }

    /// Interruption d'urgence (Kill-Switch) O(1) d'une session suspecte
    pub fn kill_session(
        &mut self,
        cap: &PamCap,
        session_id: u32,
        reason: &str,
        timestamp: u64,
    ) -> Result<(), PamError> {
        if !cap.has_right(pam_rights::TERMINATE_SESSION) {
            return Err(PamError::PermissionDenied);
        }

        let mut acc_id = 0;
        for i in 0..self.session_count {
            if let Some(ref mut s) = self.sessions[i] {
                if s.session_id == session_id {
                    s.state = SessionState::KilledAnomalous;
                    acc_id = s.account_id;
                    break;
                }
            }
        }
        if acc_id == 0 {
            return Err(PamError::NotFound);
        }

        // Verrouillage du compte pour investigation de sécurité
        for i in 0..self.account_count {
            if let Some(ref mut acc) = self.accounts[i] {
                if acc.id == acc_id {
                    acc.status = AccountStatus::Locked;
                    if acc.active_sessions_count > 0 {
                        acc.active_sessions_count -= 1;
                    }
                    break;
                }
            }
        }

        self.append_audit_internal(
            PamEventType::SessionKilled,
            "secops_killswitch",
            session_id,
            reason,
            timestamp,
        );

        // Révocation et rotation immédiate
        let _ = self.rotate_secret_internal(acc_id, timestamp);

        Ok(())
    }

    fn rotate_secret_internal(
        &mut self,
        account_id: u32,
        timestamp: u64,
    ) -> Result<[u8; 32], PamError> {
        for i in 0..self.account_count {
            if let Some(ref mut acc) = self.accounts[i] {
                if acc.id == account_id {
                    let mut hasher = Sha256::new();
                    hasher.update(&acc.current_token_hash);
                    hasher.update(&timestamp.to_be_bytes());
                    hasher.update(b"pam_ephemeral_rotation_entropy");
                    let new_hash = hasher.finalize();

                    acc.current_token_hash = new_hash;
                    acc.last_rotation_timestamp = timestamp;

                    let mut name_buf = [0u8; 32];
                    let n_len = acc.name_len;
                    name_buf[..n_len].copy_from_slice(&acc.name[..n_len]);

                    self.append_audit_internal(
                        PamEventType::SecretRotated,
                        core::str::from_utf8(&name_buf[..n_len]).unwrap_or("account"),
                        account_id,
                        "Rotation de secret éphémère",
                        timestamp,
                    );

                    return Ok(new_hash);
                }
            }
        }
        Err(PamError::NotFound)
    }

    /// Rotation forcée du secret d'un compte privilégié
    pub fn rotate_secret(
        &mut self,
        cap: &PamCap,
        account_id: u32,
        timestamp: u64,
    ) -> Result<[u8; 32], PamError> {
        if !cap.has_right(pam_rights::ROTATE_SECRETS) {
            return Err(PamError::PermissionDenied);
        }
        self.rotate_secret_internal(account_id, timestamp)
    }

    fn append_audit_internal(
        &mut self,
        event_type: PamEventType,
        actor_str: &str,
        entity_id: u32,
        details_str: &str,
        timestamp: u64,
    ) {
        if self.ledger_count >= self.ledger.len() {
            // Tampon circulaire pour l'audit en environnement contraint
            for i in 1..self.ledger.len() {
                self.ledger[i - 1] = self.ledger[i];
            }
            self.ledger_count = self.ledger.len() - 1;
        }

        let idx = (self.ledger_count as u32) + 1;
        let mut actor = [0u8; 32];
        let a_len = actor_str.len().min(32);
        actor[..a_len].copy_from_slice(&actor_str.as_bytes()[..a_len]);

        let mut details = [0u8; 64];
        let d_len = details_str.len().min(64);
        details[..d_len].copy_from_slice(&details_str.as_bytes()[..d_len]);

        let mut hasher = Sha256::new();
        hasher.update(&self.last_ledger_hash);
        hasher.update(&idx.to_be_bytes());
        hasher.update(&(event_type as u32).to_be_bytes());
        hasher.update(&actor[..a_len]);
        hasher.update(&entity_id.to_be_bytes());
        hasher.update(&details[..d_len]);
        hasher.update(&timestamp.to_be_bytes());
        let entry_hash = hasher.finalize();

        let entry = PamAuditEntry {
            index: idx,
            event_type,
            actor,
            actor_len: a_len,
            entity_id,
            details,
            details_len: d_len,
            timestamp,
            prev_hash: self.last_ledger_hash,
            entry_hash,
        };

        self.ledger[self.ledger_count] = Some(entry);
        self.ledger_count += 1;
        self.last_ledger_hash = entry_hash;
    }

    /// Vérifie formellement l'intégrité de la chaîne cryptographique du grand livre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = [0u8; 32];
        for i in 0..self.ledger_count {
            if let Some(ref entry) = self.ledger[i] {
                if entry.prev_hash != expected_prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.prev_hash);
                hasher.update(&entry.index.to_be_bytes());
                hasher.update(&(entry.event_type as u32).to_be_bytes());
                hasher.update(&entry.actor[..entry.actor_len]);
                hasher.update(&entry.entity_id.to_be_bytes());
                hasher.update(&entry.details[..entry.details_len]);
                hasher.update(&entry.timestamp.to_be_bytes());
                let computed = hasher.finalize();

                if computed != entry.entry_hash {
                    return false;
                }
                expected_prev = entry.entry_hash;
            } else {
                return false;
            }
        }
        true
    }

    /// Renvoie la synthèse globale de l'état PAM
    pub fn get_summary(&self, cap: &PamCap) -> Result<PamSummary, PamError> {
        if !cap.has_right(pam_rights::VIEW_ACCOUNTS) {
            return Err(PamError::PermissionDenied);
        }

        let mut active_accounts = 0;
        for i in 0..self.account_count {
            if let Some(ref a) = self.accounts[i] {
                if a.status == AccountStatus::Active || a.status == AccountStatus::InUse {
                    active_accounts += 1;
                }
            }
        }

        let mut active_sessions = 0;
        for i in 0..self.session_count {
            if let Some(ref s) = self.sessions[i] {
                if s.state == SessionState::Active {
                    active_sessions += 1;
                }
            }
        }

        Ok(PamSummary {
            account_count: self.account_count,
            active_accounts,
            jit_requests_count: self.jit_count,
            active_sessions_count: active_sessions,
            total_commands_recorded: self.command_count,
            ledger_valid: self.verify_ledger_integrity(),
        })
    }
}

// ============================================================================
// TESTS UNITAIRES (#![no_std] COMPLIANT)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_daemon() -> JamboPamDaemon {
        let cap = PamCap::new(Handle::new(1, 0), pam_rights::ALL, 100000, 1000);
        let mut daemon = JamboPamDaemon::new(cap);
        daemon.init_defaults();
        daemon
    }

    #[test]
    fn test_init_defaults_and_summary() {
        let daemon = create_test_daemon();
        let cap = daemon.admin_cap;
        let summary = daemon.get_summary(&cap).expect("get_summary failed");

        assert_eq!(summary.account_count, 5);
        assert_eq!(summary.active_accounts, 5);
        assert_eq!(summary.active_sessions_count, 0);
        assert_eq!(summary.total_commands_recorded, 0);
        assert!(summary.ledger_valid);
    }

    #[test]
    fn test_jit_elevation_standard_tier1() {
        let mut daemon = create_test_daemon();
        let cap = daemon.admin_cap;

        // Requête JIT pour net_fabric_admin (ID 3, Tier 1, pas de dual-auth)
        let req_id = daemon
            .request_jit(
                &cap,
                "operator_bob",
                3,
                "Maintenance pont VirtIO",
                1800,
                2000,
            )
            .expect("request_jit failed");
        assert_eq!(req_id, 1);

        // Approbation par un superviseur
        let approved = daemon
            .approve_jit(&cap, req_id, "sec_supervisor", 2010)
            .expect("approve_jit failed");
        assert!(approved);

        // Démarrage de session
        let sid = daemon
            .start_session(&cap, req_id, "operator_bob", 2020)
            .expect("start_session failed");
        assert_eq!(sid, 1);

        // Enregistrement de commandes
        let hash1 = daemon
            .record_session_command(&cap, sid, "ip link set dev jnet0 up", 0, false, 2030)
            .expect("record command 1 failed");
        let hash2 = daemon
            .record_session_command(&cap, sid, "iptables -A FORWARD -j ACCEPT", 0, false, 2040)
            .expect("record command 2 failed");

        assert_ne!(hash1, hash2);

        // Fermeture de session
        daemon
            .terminate_session(&cap, sid, 2050)
            .expect("terminate_session failed");

        let summary = daemon.get_summary(&cap).expect("get_summary failed");
        assert_eq!(summary.active_sessions_count, 0);
        assert_eq!(summary.total_commands_recorded, 2);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_jit_dual_authorization_tier0() {
        let mut daemon = create_test_daemon();
        let cap = daemon.admin_cap;

        // Requête JIT pour root_supervisor (ID 1, Tier 0, dual-auth requis)
        let req_id = daemon
            .request_jit(
                &cap,
                "sysadmin_alice",
                1,
                "Mise à jour table EPT noyau",
                900,
                3000,
            )
            .expect("request_jit failed");

        // Premier approbateur
        let err1 = daemon.approve_jit(&cap, req_id, "approver_one", 3010);
        assert_eq!(err1, Err(PamError::DualAuthRequired));

        // Le même approbateur essaie à nouveau -> refus
        let err_same = daemon.approve_jit(&cap, req_id, "approver_one", 3020);
        assert_eq!(err_same, Err(PamError::DualAuthRequired));

        // Deuxième approbateur distinct -> approbation réussie
        let ok = daemon
            .approve_jit(&cap, req_id, "approver_two", 3030)
            .expect("second approval failed");
        assert!(ok);

        let sid = daemon
            .start_session(&cap, req_id, "sysadmin_alice", 3040)
            .expect("start_session failed");
        assert_eq!(sid, 1);
    }

    #[test]
    fn test_emergency_killswitch() {
        let mut daemon = create_test_daemon();
        let cap = daemon.admin_cap;

        let req_id = daemon
            .request_jit(&cap, "untrusted_dev", 4, "Dump mémoire VFS", 1200, 4000)
            .expect("request_jit failed");
        daemon
            .approve_jit(&cap, req_id, "approver", 4010)
            .expect("approval failed");
        let sid = daemon
            .start_session(&cap, req_id, "untrusted_dev", 4020)
            .expect("start failed");

        // Détection d'anomalie et déclenchement du kill switch
        daemon
            .kill_session(
                &cap,
                sid,
                "Tentative de lecture non autorisée hors-baux",
                4030,
            )
            .expect("kill_session failed");

        // La session doit être dans l'état KilledAnomalous
        let session = daemon.sessions[0].unwrap();
        assert_eq!(session.state, SessionState::KilledAnomalous);

        // Toute nouvelle commande sur cette session doit échouer
        let err = daemon.record_session_command(&cap, sid, "rm -rf /", -1, true, 4040);
        assert_eq!(err, Err(PamError::InvalidState));

        // Le compte associé doit être verrouillé
        let acc = daemon.accounts[3].unwrap();
        assert_eq!(acc.status, AccountStatus::Locked);

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_secret_rotation() {
        let mut daemon = create_test_daemon();
        let cap = daemon.admin_cap;

        let acc_before = daemon.accounts[0].unwrap();
        let hash_before = acc_before.current_token_hash;

        let new_hash = daemon
            .rotate_secret(&cap, 1, 5000)
            .expect("rotate_secret failed");
        assert_ne!(hash_before, new_hash);

        let acc_after = daemon.accounts[0].unwrap();
        assert_eq!(acc_after.current_token_hash, new_hash);
        assert_eq!(acc_after.last_rotation_timestamp, 5000);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_monotonic_capability_attenuation() {
        let daemon = create_test_daemon();
        let cap = daemon.admin_cap;

        let attenuated = cap
            .attenuate(pam_rights::VIEW_ACCOUNTS | pam_rights::REQUEST_JIT, 500, 10)
            .expect("attenuate failed");

        assert!(attenuated.has_right(pam_rights::VIEW_ACCOUNTS));
        assert!(attenuated.has_right(pam_rights::REQUEST_JIT));
        assert!(!attenuated.has_right(pam_rights::APPROVE_JIT));
        assert!(!attenuated.has_right(pam_rights::ADMIN));

        // Tentative d'escalade interdite
        let bad_escalate = attenuated.attenuate(pam_rights::ALL, 500, 10);
        assert_eq!(bad_escalate, Err(PamError::AttenuationViolation));
    }

    #[test]
    fn test_ledger_tampering_detection() {
        let mut daemon = create_test_daemon();
        assert!(daemon.verify_ledger_integrity());

        // Altération intentionnelle du registre d'audit
        if let Some(ref mut entry) = daemon.ledger[0] {
            entry.details[0] ^= 0xFF; // Corrompre les octets de détails
        }

        // L'intégrité doit être invalidée
        assert!(!daemon.verify_ledger_integrity());
    }
}

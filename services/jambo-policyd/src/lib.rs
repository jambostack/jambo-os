//! Moteur de Politiques de Sécurité Déclaratives & Contrôle d'Admission de Grappe (`jambo-policyd`)
//!
//! Fournit un moteur d'évaluation de politiques ABAC/RBAC déterministe en `#![no_std]`.
//! Garantit le principe de déni par défaut (*Deny-by-default*), la préséance des refus explicites,
//! l'expiration temporelle de baux de politiques, et l'auditabilité sans autorité ambiante via `PolicyCap`.
//! Protocole IPC 64 octets sous l'endpoint 25 (PID 25) et client synchrone `PolicyClient`.

#![no_std]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_find)]

pub use libjambo::{syscall_ipc_register_endpoint, syscall_thread_yield, Handle, SysError};

pub const MAX_RULES: usize = 32;
pub const MAX_RESOURCE_LEN: usize = 32;
pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const POLICY_MAGIC_REQ: u32 = 0x504F4C44; // "POLD"
pub const POLICY_MAGIC_RESP: u32 = 0x504F4C53; // "POLS"

// ============================================================================
// DROITS & CAPABILITÉS (`PolicyCap`, `policy_rights`)
// ============================================================================

/// Droits de capacité pour la gouvernance de politiques.
pub mod policy_rights {
    pub const POLICY_EVALUATE: u32 = 0x01;
    pub const POLICY_RULE_ADD: u32 = 0x02;
    pub const POLICY_RULE_DEL: u32 = 0x04;
    pub const POLICY_AUDIT: u32 = 0x08;
    pub const POLICY_ADMIN: u32 = 0x80;
    pub const ALL: u32 =
        POLICY_EVALUATE | POLICY_RULE_ADD | POLICY_RULE_DEL | POLICY_AUDIT | POLICY_ADMIN;
}

/// Rôles standards pour l'évaluation de sujets.
pub mod roles {
    pub const ROLE_SYSTEM: u16 = 0x0001;
    pub const ROLE_OPERATOR: u16 = 0x0002;
    pub const ROLE_WORKLOAD: u16 = 0x0004;
    pub const ROLE_GUEST: u16 = 0x0008;
    pub const ROLE_ANY: u16 = 0xFFFF;

    pub fn as_str(role: u16) -> &'static str {
        match role {
            ROLE_SYSTEM => "system",
            ROLE_OPERATOR => "operator",
            ROLE_WORKLOAD => "workload",
            ROLE_GUEST => "guest",
            ROLE_ANY => "any",
            _ => "unknown",
        }
    }

    pub fn from_str(s: &str) -> Option<u16> {
        match s {
            "system" | "sys" => Some(ROLE_SYSTEM),
            "operator" | "op" => Some(ROLE_OPERATOR),
            "workload" | "work" => Some(ROLE_WORKLOAD),
            "guest" => Some(ROLE_GUEST),
            "any" | "*" => Some(ROLE_ANY),
            _ => None,
        }
    }
}

/// Types d'actions sensibles soumises à admission.
pub mod actions {
    pub const ACTION_SPAWN_WORKLOAD: u32 = 0x0001;
    pub const ACTION_ACCESS_SECRET: u32 = 0x0002;
    pub const ACTION_REGISTER_SERVICE: u32 = 0x0004;
    pub const ACTION_ROUTE_TRAFFIC: u32 = 0x0008;
    pub const ACTION_STORAGE_MOUNT: u32 = 0x0010;
    pub const ACTION_ADMIN: u32 = 0x8000;

    pub fn as_str(action: u32) -> &'static str {
        match action {
            ACTION_SPAWN_WORKLOAD => "spawn_workload",
            ACTION_ACCESS_SECRET => "access_secret",
            ACTION_REGISTER_SERVICE => "register_service",
            ACTION_ROUTE_TRAFFIC => "route_traffic",
            ACTION_STORAGE_MOUNT => "storage_mount",
            ACTION_ADMIN => "admin",
            _ => "custom",
        }
    }

    pub fn from_str(s: &str) -> Option<u32> {
        match s {
            "spawn" | "spawn_workload" => Some(ACTION_SPAWN_WORKLOAD),
            "secret" | "access_secret" => Some(ACTION_ACCESS_SECRET),
            "register" | "register_service" => Some(ACTION_REGISTER_SERVICE),
            "route" | "route_traffic" => Some(ACTION_ROUTE_TRAFFIC),
            "storage" | "storage_mount" | "mount" => Some(ACTION_STORAGE_MOUNT),
            "admin" => Some(ACTION_ADMIN),
            _ => None,
        }
    }
}

/// Jeton de capacité pour le moteur de politiques de sécurité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyCap {
    pub handle: Handle,
    pub rights: u32,
}

impl PolicyCap {
    pub const POLICY_EVALUATE: u32 = policy_rights::POLICY_EVALUATE;
    pub const POLICY_RULE_ADD: u32 = policy_rights::POLICY_RULE_ADD;
    pub const POLICY_RULE_DEL: u32 = policy_rights::POLICY_RULE_DEL;
    pub const POLICY_AUDIT: u32 = policy_rights::POLICY_AUDIT;
    pub const POLICY_ADMIN: u32 = policy_rights::POLICY_ADMIN;
    pub const ALL: u32 = policy_rights::ALL;

    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    pub fn attenuate(&self, new_rights: u32) -> Result<Self, SysError> {
        if (new_rights & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
        })
    }
}

// ============================================================================
// MODÈLE DE DONNÉES DE POLITIQUES
// ============================================================================

/// Effet d'une règle de sécurité.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow = 0,
    Deny = 1,
}

impl PolicyEffect {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
        }
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Allow),
            1 => Some(Self::Deny),
            _ => None,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "allow" | "ALLOW" => Some(Self::Allow),
            "deny" | "DENY" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// Règle de politique déclarative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRule {
    pub rule_id: u32,
    pub subject_role: u16,
    pub action_mask: u32,
    pub resource_prefix: [u8; MAX_RESOURCE_LEN],
    pub resource_len: usize,
    pub effect: PolicyEffect,
    pub priority: u8,
    pub expires_at: u64, // 0 = permanent
}

impl PolicyRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: u32,
        subject_role: u16,
        action_mask: u32,
        resource: &[u8],
        effect: PolicyEffect,
        priority: u8,
        expires_at: u64,
    ) -> Result<Self, SysError> {
        if resource.len() > MAX_RESOURCE_LEN {
            return Err(SysError::InvalidArgument);
        }
        let mut prefix = [0u8; MAX_RESOURCE_LEN];
        prefix[..resource.len()].copy_from_slice(resource);

        Ok(Self {
            rule_id,
            subject_role,
            action_mask,
            resource_prefix: prefix,
            resource_len: resource.len(),
            effect,
            priority,
            expires_at,
        })
    }

    /// Vérifie si la règle s'applique à la requête d'admission donnée.
    pub fn matches(&self, req: &AdmissionRequest) -> bool {
        // Vérification d'expiration temporelle
        if self.expires_at > 0 && req.timestamp > self.expires_at {
            return false;
        }

        // Vérification de rôle (masque de bits ou ROLE_ANY)
        if self.subject_role != roles::ROLE_ANY && (self.subject_role & req.role) == 0 {
            return false;
        }

        // Vérification d'action
        if (self.action_mask & req.action) == 0 {
            return false;
        }

        // Vérification de préfixe de ressource
        if self.resource_len > req.resource_len {
            return false;
        }

        self.resource_prefix[..self.resource_len] == req.resource[..self.resource_len]
    }

    /// Retourne le préfixe de ressource sous forme de chaîne `&str`.
    pub fn resource_str(&self) -> &str {
        core::str::from_utf8(&self.resource_prefix[..self.resource_len]).unwrap_or("")
    }
}

/// Requête d'admission soumise au moteur de politiques.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub subject_id: u32,
    pub role: u16,
    pub action: u32,
    pub resource: [u8; MAX_RESOURCE_LEN],
    pub resource_len: usize,
    pub timestamp: u64,
}

impl AdmissionRequest {
    pub fn new(
        subject_id: u32,
        role: u16,
        action: u32,
        resource: &[u8],
        timestamp: u64,
    ) -> Result<Self, SysError> {
        if resource.len() > MAX_RESOURCE_LEN {
            return Err(SysError::InvalidArgument);
        }
        let mut res = [0u8; MAX_RESOURCE_LEN];
        res[..resource.len()].copy_from_slice(resource);

        Ok(Self {
            subject_id,
            role,
            action,
            resource: res,
            resource_len: resource.len(),
            timestamp,
        })
    }

    /// Retourne la ressource sous forme de chaîne `&str`.
    pub fn resource_str(&self) -> &str {
        core::str::from_utf8(&self.resource[..self.resource_len]).unwrap_or("")
    }
}

/// Décision d'admission retournée par le moteur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    Allowed,
    Denied {
        reason: &'static str,
        matching_rule_id: Option<u32>,
    },
}

// ============================================================================
// CODES D'OPÉRATIONS IPC (`PolicyOpcode`)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOpcode {
    GetStatus = 1,
    EvaluateAdmission = 2,
    AddRule = 3,
    DeleteRule = 4,
    ListRules = 5,
}

impl PolicyOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::EvaluateAdmission),
            3 => Some(Self::AddRule),
            4 => Some(Self::DeleteRule),
            5 => Some(Self::ListRules),
            _ => None,
        }
    }
}

// ============================================================================
// STRUCTURES IPC EXACTEMENT 64 OCTETS (`PolicyRequest`, `PolicyResponse`)
// ============================================================================

/// Requête IPC calibrée à exactement 64 octets.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub rights: u32,
    pub subject_role: u16,
    pub priority: u8,
    pub effect: u8,
    pub action_mask: u32,
    pub rule_id: u32,
    pub expires_at: u32,
    pub resource_prefix: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<PolicyRequest>() == 64);

impl Default for PolicyRequest {
    fn default() -> Self {
        Self {
            magic: POLICY_MAGIC_REQ,
            opcode: PolicyOpcode::GetStatus as u32,
            handle_id: 25,
            rights: policy_rights::ALL,
            subject_role: roles::ROLE_ANY,
            priority: 0,
            effect: PolicyEffect::Allow as u8,
            action_mask: 0,
            rule_id: 0,
            expires_at: 0,
            resource_prefix: [0u8; 32],
        }
    }
}

impl PolicyRequest {
    pub const fn new(opcode: PolicyOpcode) -> Self {
        Self {
            magic: POLICY_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: 25,
            rights: policy_rights::ALL,
            subject_role: roles::ROLE_ANY,
            priority: 0,
            effect: PolicyEffect::Allow as u8,
            action_mask: 0,
            rule_id: 0,
            expires_at: 0,
            resource_prefix: [0u8; 32],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: POLICY_MAGIC_REQ,
            opcode: PolicyOpcode::GetStatus as u32,
            handle_id,
            rights,
            subject_role: 0,
            priority: 0,
            effect: 0,
            action_mask: 0,
            rule_id: 0,
            expires_at: 0,
            resource_prefix: [0u8; 32],
        }
    }

    pub fn new_eval(
        handle_id: u32,
        rights: u32,
        role: u16,
        action: u32,
        resource: &[u8],
        timestamp: u64,
    ) -> Self {
        let mut req = Self {
            magic: POLICY_MAGIC_REQ,
            opcode: PolicyOpcode::EvaluateAdmission as u32,
            handle_id,
            rights,
            subject_role: role,
            priority: 0,
            effect: 0,
            action_mask: action,
            rule_id: 0,
            expires_at: timestamp as u32,
            resource_prefix: [0u8; 32],
        };
        req.set_resource(resource);
        req
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_add_rule(
        handle_id: u32,
        rights: u32,
        rule_id: u32,
        role: u16,
        action_mask: u32,
        resource: &[u8],
        effect: u8,
        priority: u8,
        expires_at: u64,
    ) -> Self {
        let mut req = Self {
            magic: POLICY_MAGIC_REQ,
            opcode: PolicyOpcode::AddRule as u32,
            handle_id,
            rights,
            subject_role: role,
            priority,
            effect,
            action_mask,
            rule_id,
            expires_at: expires_at as u32,
            resource_prefix: [0u8; 32],
        };
        req.set_resource(resource);
        req
    }

    pub const fn new_delete_rule(handle_id: u32, rights: u32, rule_id: u32) -> Self {
        Self {
            magic: POLICY_MAGIC_REQ,
            opcode: PolicyOpcode::DeleteRule as u32,
            handle_id,
            rights,
            subject_role: 0,
            priority: 0,
            effect: 0,
            action_mask: 0,
            rule_id,
            expires_at: 0,
            resource_prefix: [0u8; 32],
        }
    }

    pub const fn new_list(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: POLICY_MAGIC_REQ,
            opcode: PolicyOpcode::ListRules as u32,
            handle_id,
            rights,
            subject_role: 0,
            priority: 0,
            effect: 0,
            action_mask: 0,
            rule_id: 0,
            expires_at: 0,
            resource_prefix: [0u8; 32],
        }
    }

    pub fn set_resource(&mut self, res: &[u8]) {
        let len = res.len().min(self.resource_prefix.len());
        self.resource_prefix = [0u8; 32];
        self.resource_prefix[..len].copy_from_slice(&res[..len]);
    }

    pub fn resource_as_str(&self) -> &str {
        let len = self
            .resource_prefix
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.resource_prefix.len());
        core::str::from_utf8(&self.resource_prefix[..len]).unwrap_or("")
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
        if req.magic != POLICY_MAGIC_REQ {
            return None;
        }
        Some(req)
    }
}

/// Réponse IPC calibrée à exactement 64 octets.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyResponse {
    pub magic: u32,
    pub status: i32,
    pub eval_count: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub decision: u32, // 0 = Allowed, 1 = Denied
    pub active_rules: u32,
    pub matching_rule_id: u32,
    pub _reserved: u32,
    pub decision_str: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<PolicyResponse>() == 64);

impl Default for PolicyResponse {
    fn default() -> Self {
        Self {
            magic: POLICY_MAGIC_RESP,
            status: 0,
            eval_count: 0,
            allow_count: 0,
            deny_count: 0,
            decision: 0,
            active_rules: 0,
            matching_rule_id: 0,
            _reserved: 0,
            decision_str: [0u8; 16],
        }
    }
}

impl PolicyResponse {
    pub const fn new() -> Self {
        Self {
            magic: POLICY_MAGIC_RESP,
            status: 0,
            eval_count: 0,
            allow_count: 0,
            deny_count: 0,
            decision: 0,
            active_rules: 0,
            matching_rule_id: 0,
            _reserved: 0,
            decision_str: [0u8; 16],
        }
    }

    pub fn set_decision_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(self.decision_str.len());
        self.decision_str = [0u8; 16];
        self.decision_str[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn decision_as_str(&self) -> &str {
        let len = self
            .decision_str
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.decision_str.len());
        core::str::from_utf8(&self.decision_str[..len]).unwrap_or("")
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
        let mut resp = Self::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut resp as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            );
        }
        if resp.magic != POLICY_MAGIC_RESP {
            return None;
        }
        Some(resp)
    }
}

// ============================================================================
// MOTEUR DE POLITIQUES (`PolicyEngine`)
// ============================================================================

/// Moteur de politiques d'admission pour la grappe JamboOS.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub rules: [Option<PolicyRule>; MAX_RULES],
    pub eval_count: u64,
    pub allow_count: u64,
    pub deny_count: u64,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        let mut engine = Self::new();
        engine.init_defaults();
        engine
    }
}

impl PolicyEngine {
    pub const fn new() -> Self {
        Self {
            rules: [None; MAX_RULES],
            eval_count: 0,
            allow_count: 0,
            deny_count: 0,
        }
    }

    /// Initialise les règles par défaut de la grappe : `system/*`, `workload/*`, et `vault/*`.
    pub fn init_defaults(&mut self) {
        let cap = PolicyCap::new(Handle::new(25, 1), policy_rights::ALL);

        // Règle 1 : SYSTEM a les droits d'administration et secrets sur system/
        let rule_sys = PolicyRule::new(
            1,
            roles::ROLE_SYSTEM,
            actions::ACTION_ADMIN
                | actions::ACTION_ACCESS_SECRET
                | actions::ACTION_REGISTER_SERVICE,
            b"system/",
            PolicyEffect::Allow,
            100,
            0,
        )
        .unwrap();
        let _ = self.add_rule(&cap, rule_sys);

        // Règle 2 : OPERATOR peut spawner des workloads, router et monter sur workload/
        let rule_op = PolicyRule::new(
            2,
            roles::ROLE_OPERATOR,
            actions::ACTION_SPAWN_WORKLOAD
                | actions::ACTION_ROUTE_TRAFFIC
                | actions::ACTION_STORAGE_MOUNT,
            b"workload/",
            PolicyEffect::Allow,
            50,
            0,
        )
        .unwrap();
        let _ = self.add_rule(&cap, rule_op);

        // Règle 3 : WORKLOAD peut accéder aux secrets dans vault/
        let rule_vault = PolicyRule::new(
            3,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ACCESS_SECRET,
            b"vault/",
            PolicyEffect::Allow,
            10,
            0,
        )
        .unwrap();
        let _ = self.add_rule(&cap, rule_vault);
    }

    /// Ajoute ou met à jour une règle déclarative dans le moteur.
    pub fn add_rule(&mut self, cap: &PolicyCap, rule: PolicyRule) -> Result<(), SysError> {
        if !cap.has_right(policy_rights::POLICY_RULE_ADD) {
            return Err(SysError::PermissionDenied);
        }

        // Si la règle existe déjà, mise à jour en place
        for slot in self.rules.iter_mut() {
            if let Some(r) = slot {
                if r.rule_id == rule.rule_id {
                    *slot = Some(rule);
                    return Ok(());
                }
            }
        }

        // Sinon, recherche d'un emplacement libre
        for slot in self.rules.iter_mut() {
            if slot.is_none() {
                *slot = Some(rule);
                return Ok(());
            }
        }

        Err(SysError::ResourceBusy)
    }

    /// Supprime une règle par son identifiant unique.
    pub fn delete_rule(&mut self, cap: &PolicyCap, rule_id: u32) -> Result<(), SysError> {
        if !cap.has_right(policy_rights::POLICY_RULE_DEL) {
            return Err(SysError::PermissionDenied);
        }

        for slot in self.rules.iter_mut() {
            if let Some(r) = slot {
                if r.rule_id == rule_id {
                    *slot = None;
                    return Ok(());
                }
            }
        }

        Err(SysError::InvalidHandle)
    }

    /// Alias pour `delete_rule`.
    pub fn remove_rule(&mut self, cap: &PolicyCap, rule_id: u32) -> Result<(), SysError> {
        self.delete_rule(cap, rule_id)
    }

    /// Évalue une requête d'admission selon le principe de déni par défaut et préséance du Deny.
    pub fn evaluate(
        &mut self,
        cap: &PolicyCap,
        req: &AdmissionRequest,
    ) -> Result<AdmissionDecision, SysError> {
        if !cap.has_right(policy_rights::POLICY_EVALUATE) {
            return Err(SysError::PermissionDenied);
        }

        self.eval_count = self.eval_count.saturating_add(1);

        let mut highest_deny: Option<PolicyRule> = None;
        let mut highest_allow: Option<PolicyRule> = None;

        for slot in self.rules.iter().flatten() {
            if slot.matches(req) {
                match slot.effect {
                    PolicyEffect::Deny => {
                        if highest_deny.is_none() || slot.priority >= highest_deny.unwrap().priority
                        {
                            highest_deny = Some(*slot);
                        }
                    }
                    PolicyEffect::Allow => {
                        if highest_allow.is_none()
                            || slot.priority > highest_allow.unwrap().priority
                        {
                            highest_allow = Some(*slot);
                        }
                    }
                }
            }
        }

        // Préséance stricte du refus explicite (Deny)
        if let Some(deny_rule) = highest_deny {
            self.deny_count = self.deny_count.saturating_add(1);
            return Ok(AdmissionDecision::Denied {
                reason: "Explicit policy Deny matched",
                matching_rule_id: Some(deny_rule.rule_id),
            });
        }

        // Si une règle d'autorisation correspond
        if highest_allow.is_some() {
            self.allow_count = self.allow_count.saturating_add(1);
            return Ok(AdmissionDecision::Allowed);
        }

        // Déni par défaut (Deny-by-default)
        self.deny_count = self.deny_count.saturating_add(1);
        Ok(AdmissionDecision::Denied {
            reason: "Default Deny: no matching allow rule",
            matching_rule_id: None,
        })
    }

    /// Purge les règles dont le bail temporel a expiré.
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let mut purged = 0;
        for slot in self.rules.iter_mut() {
            if let Some(r) = slot {
                if r.expires_at > 0 && now > r.expires_at {
                    *slot = None;
                    purged += 1;
                }
            }
        }
        purged
    }

    /// Retourne les statistiques d'audit (évaluations, autorisations, dénis).
    pub fn stats(&self, cap: &PolicyCap) -> Result<(u64, u64, u64), SysError> {
        if !cap.has_right(policy_rights::POLICY_AUDIT) {
            return Err(SysError::PermissionDenied);
        }
        Ok((self.eval_count, self.allow_count, self.deny_count))
    }

    /// Nombre de règles actuellement actives dans le moteur.
    pub fn rule_count(&self) -> usize {
        self.rules.iter().filter(|r| r.is_some()).count()
    }

    /// Retourne une référence vers la règle au slot `index` si présente.
    pub fn get_rule(&self, index: usize) -> Option<&PolicyRule> {
        self.rules.get(index).and_then(|r| r.as_ref())
    }

    /// Recherche une règle active par son identifiant unique.
    pub fn get_rule_by_id(&self, rule_id: u32) -> Option<&PolicyRule> {
        self.rules.iter().flatten().find(|r| r.rule_id == rule_id)
    }

    /// Traitement direct et déterministe d'une requête IPC 64 octets.
    pub fn dispatch_ipc(&mut self, req: &PolicyRequest) -> PolicyResponse {
        if req.magic != POLICY_MAGIC_REQ {
            let mut resp = PolicyResponse::new();
            resp.status = -1;
            resp.set_decision_str("ERR_MAGIC");
            return resp;
        }

        let cap = PolicyCap::new(Handle::new(req.handle_id, 1), req.rights);
        let opcode = match PolicyOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                let mut resp = PolicyResponse::new();
                resp.status = -1;
                resp.set_decision_str("ERR_OPCODE");
                return resp;
            }
        };

        match opcode {
            PolicyOpcode::GetStatus => {
                if !cap.has_right(policy_rights::POLICY_AUDIT) {
                    let mut resp = PolicyResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_decision_str("PERM_DENIED");
                    return resp;
                }
                let mut resp = PolicyResponse::new();
                resp.status = 0;
                resp.eval_count = self.eval_count;
                resp.allow_count = self.allow_count;
                resp.deny_count = self.deny_count;
                resp.active_rules = self.rule_count() as u32;
                resp.set_decision_str("OK_STATUS");
                resp
            }
            PolicyOpcode::EvaluateAdmission => {
                if !cap.has_right(policy_rights::POLICY_EVALUATE) {
                    let mut resp = PolicyResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_decision_str("PERM_DENIED");
                    return resp;
                }
                let res_len = req
                    .resource_prefix
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(req.resource_prefix.len());
                let adm_req = match AdmissionRequest::new(
                    req.handle_id,
                    req.subject_role,
                    req.action_mask,
                    &req.resource_prefix[..res_len],
                    req.expires_at as u64,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        let mut resp = PolicyResponse::new();
                        resp.status = e as i32;
                        resp.set_decision_str("INVALID_ARG");
                        return resp;
                    }
                };

                let decision = match self.evaluate(&cap, &adm_req) {
                    Ok(d) => d,
                    Err(e) => {
                        let mut resp = PolicyResponse::new();
                        resp.status = e as i32;
                        resp.set_decision_str("EVAL_ERROR");
                        return resp;
                    }
                };

                let mut resp = PolicyResponse::new();
                resp.status = 0;
                resp.eval_count = self.eval_count;
                resp.allow_count = self.allow_count;
                resp.deny_count = self.deny_count;
                resp.active_rules = self.rule_count() as u32;

                match decision {
                    AdmissionDecision::Allowed => {
                        resp.decision = 0;
                        resp.matching_rule_id = 0;
                        resp.set_decision_str("ALLOWED");
                    }
                    AdmissionDecision::Denied {
                        reason: _,
                        matching_rule_id,
                    } => {
                        resp.decision = 1;
                        resp.matching_rule_id = matching_rule_id.unwrap_or(0);
                        resp.set_decision_str("DENIED");
                    }
                }
                resp
            }
            PolicyOpcode::AddRule => {
                if !cap.has_right(policy_rights::POLICY_RULE_ADD) {
                    let mut resp = PolicyResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_decision_str("PERM_DENIED");
                    return resp;
                }
                let effect = match PolicyEffect::from_u8(req.effect) {
                    Some(eff) => eff,
                    None => {
                        let mut resp = PolicyResponse::new();
                        resp.status = SysError::InvalidArgument as i32;
                        resp.set_decision_str("INVALID_EFFECT");
                        return resp;
                    }
                };
                let res_len = req
                    .resource_prefix
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(req.resource_prefix.len());
                let rule = match PolicyRule::new(
                    req.rule_id,
                    req.subject_role,
                    req.action_mask,
                    &req.resource_prefix[..res_len],
                    effect,
                    req.priority,
                    req.expires_at as u64,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        let mut resp = PolicyResponse::new();
                        resp.status = e as i32;
                        resp.set_decision_str("INVALID_RULE");
                        return resp;
                    }
                };

                match self.add_rule(&cap, rule) {
                    Ok(()) => {
                        let mut resp = PolicyResponse::new();
                        resp.status = 0;
                        resp.active_rules = self.rule_count() as u32;
                        resp.matching_rule_id = req.rule_id;
                        resp.set_decision_str("RULE_ADDED");
                        resp
                    }
                    Err(e) => {
                        let mut resp = PolicyResponse::new();
                        resp.status = e as i32;
                        resp.set_decision_str("ADD_FAILED");
                        resp
                    }
                }
            }
            PolicyOpcode::DeleteRule => {
                if !cap.has_right(policy_rights::POLICY_RULE_DEL) {
                    let mut resp = PolicyResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_decision_str("PERM_DENIED");
                    return resp;
                }
                match self.delete_rule(&cap, req.rule_id) {
                    Ok(()) => {
                        let mut resp = PolicyResponse::new();
                        resp.status = 0;
                        resp.active_rules = self.rule_count() as u32;
                        resp.matching_rule_id = req.rule_id;
                        resp.set_decision_str("RULE_DELETED");
                        resp
                    }
                    Err(e) => {
                        let mut resp = PolicyResponse::new();
                        resp.status = e as i32;
                        resp.set_decision_str("DEL_FAILED");
                        resp
                    }
                }
            }
            PolicyOpcode::ListRules => {
                if !cap.has_right(policy_rights::POLICY_AUDIT) {
                    let mut resp = PolicyResponse::new();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_decision_str("PERM_DENIED");
                    return resp;
                }
                let mut resp = PolicyResponse::new();
                resp.status = 0;
                resp.active_rules = self.rule_count() as u32;
                resp.set_decision_str("RULES_LISTED");
                resp
            }
        }
    }
}

// ============================================================================
// COMPATIBILITÉ ORCHESTRATEUR INCUBATEUR (`JamboPolicyDaemon`)
// ============================================================================

/// Démon orchestrateur de politiques de sécurité et contrôle d'admission (`jambo-policyd`).
pub struct JamboPolicyDaemon {
    pub engine: PolicyEngine,
    pub cap: PolicyCap,
    pub operations_count: u64,
}

impl Default for JamboPolicyDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboPolicyDaemon {
    pub fn new() -> Self {
        let cap = PolicyCap::new(Handle::new(25, 1), policy_rights::ALL);
        let mut engine = PolicyEngine::new();
        engine.init_defaults();

        Self {
            engine,
            cap,
            operations_count: 3,
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) -> Result<(), SysError> {
        self.engine.add_rule(&self.cap, rule)?;
        self.operations_count = self.operations_count.saturating_add(1);
        Ok(())
    }

    pub fn remove_rule(&mut self, rule_id: u32) -> Result<(), SysError> {
        self.engine.delete_rule(&self.cap, rule_id)?;
        self.operations_count = self.operations_count.saturating_add(1);
        Ok(())
    }

    pub fn evaluate(&mut self, req: &AdmissionRequest) -> Result<AdmissionDecision, SysError> {
        let res = self.engine.evaluate(&self.cap, req)?;
        self.operations_count = self.operations_count.saturating_add(1);
        Ok(res)
    }

    pub fn stats(&self) -> Result<(u64, u64, u64), SysError> {
        self.engine.stats(&self.cap)
    }

    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    pub fn purge_expired(&mut self, now: u64) -> usize {
        let purged = self.engine.purge_expired(now);
        self.operations_count = self.operations_count.saturating_add(purged as u64);
        purged
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`PolicyClient`, `ChannelMessage`)
// ============================================================================

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

/// Client synchrone Ring 3 pour communiquer avec `jambo-policyd` (endpoint 25).
pub struct PolicyClient {
    pub endpoint: Handle,
}

impl PolicyClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_status(&self, cap: &PolicyCap) -> Result<PolicyResponse, SysError> {
        if !cap.has_right(policy_rights::POLICY_AUDIT) {
            return Err(SysError::PermissionDenied);
        }
        let req = PolicyRequest::new_status(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn evaluate_admission(
        &self,
        cap: &PolicyCap,
        role: u16,
        action: u32,
        resource: &[u8],
        timestamp: u64,
    ) -> Result<PolicyResponse, SysError> {
        if !cap.has_right(policy_rights::POLICY_EVALUATE) {
            return Err(SysError::PermissionDenied);
        }
        let req = PolicyRequest::new_eval(
            cap.handle.index(),
            cap.rights,
            role,
            action,
            resource,
            timestamp,
        );
        self.call(&req)
    }

    pub fn add_rule(&self, cap: &PolicyCap, rule: &PolicyRule) -> Result<PolicyResponse, SysError> {
        if !cap.has_right(policy_rights::POLICY_RULE_ADD) {
            return Err(SysError::PermissionDenied);
        }
        let req = PolicyRequest::new_add_rule(
            cap.handle.index(),
            cap.rights,
            rule.rule_id,
            rule.subject_role,
            rule.action_mask,
            &rule.resource_prefix[..rule.resource_len],
            rule.effect as u8,
            rule.priority,
            rule.expires_at,
        );
        self.call(&req)
    }

    pub fn delete_rule(&self, cap: &PolicyCap, rule_id: u32) -> Result<PolicyResponse, SysError> {
        if !cap.has_right(policy_rights::POLICY_RULE_DEL) {
            return Err(SysError::PermissionDenied);
        }
        let req = PolicyRequest::new_delete_rule(cap.handle.index(), cap.rights, rule_id);
        self.call(&req)
    }

    pub fn list_rules(&self, cap: &PolicyCap) -> Result<PolicyResponse, SysError> {
        if !cap.has_right(policy_rights::POLICY_AUDIT) {
            return Err(SysError::PermissionDenied);
        }
        let req = PolicyRequest::new_list(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn call(&self, req: &PolicyRequest) -> Result<PolicyResponse, SysError> {
        let mut tx_msg = ChannelMessage::default();
        let req_bytes = req.to_bytes();
        let copy_len = req_bytes.len().min(MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<PolicyResponse>() {
                if let Some(resp) = PolicyResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                    return Ok(resp);
                }
            }
            libjambo::syscall_thread_yield();
            attempts += 1;
        }

        Err(SysError::ResourceBusy)
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deny_by_default() {
        let cap = PolicyCap::new(Handle::new(1, 1), policy_rights::ALL);
        let mut engine = PolicyEngine::new();

        let req = AdmissionRequest::new(
            100,
            roles::ROLE_WORKLOAD,
            actions::ACTION_SPAWN_WORKLOAD,
            b"workloads/microvm-1",
            1000,
        )
        .unwrap();

        let decision = engine.evaluate(&cap, &req).unwrap();
        assert_eq!(
            decision,
            AdmissionDecision::Denied {
                reason: "Default Deny: no matching allow rule",
                matching_rule_id: None
            }
        );

        let (evals, allows, denies) = engine.stats(&cap).unwrap();
        assert_eq!(evals, 1);
        assert_eq!(allows, 0);
        assert_eq!(denies, 1);
    }

    #[test]
    fn test_allow_rule() {
        let cap = PolicyCap::new(Handle::new(1, 1), policy_rights::ALL);
        let mut engine = PolicyEngine::new();

        let rule = PolicyRule::new(
            1,
            roles::ROLE_OPERATOR,
            actions::ACTION_SPAWN_WORKLOAD | actions::ACTION_ACCESS_SECRET,
            b"workloads/",
            PolicyEffect::Allow,
            10,
            0,
        )
        .unwrap();

        engine.add_rule(&cap, rule).unwrap();
        assert_eq!(engine.rule_count(), 1);

        let req_valid = AdmissionRequest::new(
            200,
            roles::ROLE_OPERATOR,
            actions::ACTION_SPAWN_WORKLOAD,
            b"workloads/batch-task",
            1000,
        )
        .unwrap();

        let decision = engine.evaluate(&cap, &req_valid).unwrap();
        assert_eq!(decision, AdmissionDecision::Allowed);

        // Ressource non couverte -> Deny-by-default
        let req_invalid_res = AdmissionRequest::new(
            200,
            roles::ROLE_OPERATOR,
            actions::ACTION_SPAWN_WORKLOAD,
            b"secrets/keys",
            1000,
        )
        .unwrap();
        assert_eq!(
            engine.evaluate(&cap, &req_invalid_res).unwrap(),
            AdmissionDecision::Denied {
                reason: "Default Deny: no matching allow rule",
                matching_rule_id: None
            }
        );
    }

    #[test]
    fn test_explicit_deny_precedence() {
        let cap = PolicyCap::new(Handle::new(1, 1), policy_rights::ALL);
        let mut engine = PolicyEngine::new();

        // Règle 1 : Allow large pour workload/
        let rule_allow = PolicyRule::new(
            1,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ACCESS_SECRET,
            b"workload/",
            PolicyEffect::Allow,
            5,
            0,
        )
        .unwrap();

        // Règle 2 : Deny explicite ciblé sur workload/restricted
        let rule_deny = PolicyRule::new(
            2,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ACCESS_SECRET,
            b"workload/restricted",
            PolicyEffect::Deny,
            10,
            0,
        )
        .unwrap();

        engine.add_rule(&cap, rule_allow).unwrap();
        engine.add_rule(&cap, rule_deny).unwrap();

        let req_allowed = AdmissionRequest::new(
            101,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ACCESS_SECRET,
            b"workload/public-app",
            1000,
        )
        .unwrap();
        assert_eq!(
            engine.evaluate(&cap, &req_allowed).unwrap(),
            AdmissionDecision::Allowed
        );

        let req_denied = AdmissionRequest::new(
            102,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ACCESS_SECRET,
            b"workload/restricted/db",
            1000,
        )
        .unwrap();
        assert_eq!(
            engine.evaluate(&cap, &req_denied).unwrap(),
            AdmissionDecision::Denied {
                reason: "Explicit policy Deny matched",
                matching_rule_id: Some(2)
            }
        );
    }

    #[test]
    fn test_rule_expiration() {
        let cap = PolicyCap::new(Handle::new(1, 1), policy_rights::ALL);
        let mut engine = PolicyEngine::new();

        let rule = PolicyRule::new(
            10,
            roles::ROLE_ANY,
            actions::ACTION_ROUTE_TRAFFIC,
            b"routes/",
            PolicyEffect::Allow,
            1,
            1500, // expire à t = 1500
        )
        .unwrap();

        engine.add_rule(&cap, rule).unwrap();

        // Avant expiration (t=1400) -> Allowed
        let req_before = AdmissionRequest::new(
            50,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ROUTE_TRAFFIC,
            b"routes/mesh-1",
            1400,
        )
        .unwrap();
        assert_eq!(
            engine.evaluate(&cap, &req_before).unwrap(),
            AdmissionDecision::Allowed
        );

        // Après expiration (t=1600) -> Denied
        let req_after = AdmissionRequest::new(
            50,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ROUTE_TRAFFIC,
            b"routes/mesh-1",
            1600,
        )
        .unwrap();
        assert_eq!(
            engine.evaluate(&cap, &req_after).unwrap(),
            AdmissionDecision::Denied {
                reason: "Default Deny: no matching allow rule",
                matching_rule_id: None
            }
        );

        // Purge
        let purged = engine.purge_expired(1600);
        assert_eq!(purged, 1);
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_capability_attenuation() {
        let cap_full = PolicyCap::new(Handle::new(1, 1), policy_rights::ALL);
        let cap_eval_only = cap_full.attenuate(policy_rights::POLICY_EVALUATE).unwrap();

        // Atténuation valide
        assert!(cap_eval_only.has_right(policy_rights::POLICY_EVALUATE));
        assert!(!cap_eval_only.has_right(policy_rights::POLICY_RULE_ADD));

        // Rejet de l'amplification de privilèges
        assert_eq!(
            cap_eval_only.attenuate(policy_rights::POLICY_ADMIN),
            Err(SysError::PermissionDenied)
        );

        let mut engine = PolicyEngine::new();
        let rule = PolicyRule::new(
            1,
            roles::ROLE_SYSTEM,
            actions::ACTION_ADMIN,
            b"admin/",
            PolicyEffect::Allow,
            10,
            0,
        )
        .unwrap();

        // Tentative d'ajout de règle avec cap_eval_only -> PermissionDenied
        assert_eq!(
            engine.add_rule(&cap_eval_only, rule),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_ipc_serialization_and_dispatch() {
        assert_eq!(core::mem::size_of::<PolicyRequest>(), 64);
        assert_eq!(core::mem::size_of::<PolicyResponse>(), 64);

        let mut engine = PolicyEngine::new();
        engine.init_defaults();
        assert_eq!(engine.rule_count(), 3);

        // 1. GetStatus via IPC
        let req_status = PolicyRequest::new_status(25, policy_rights::ALL);
        let bytes_status = req_status.to_bytes();
        let req_deser = PolicyRequest::from_bytes(&bytes_status).unwrap();
        assert_eq!(req_deser.opcode, PolicyOpcode::GetStatus as u32);

        let resp_status = engine.dispatch_ipc(&req_deser);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.active_rules, 3);
        assert_eq!(resp_status.decision_as_str(), "OK_STATUS");

        // 2. EvaluateAdmission via IPC -> system/ allowed
        let req_eval = PolicyRequest::new_eval(
            25,
            policy_rights::ALL,
            roles::ROLE_SYSTEM,
            actions::ACTION_ADMIN,
            b"system/kernel",
            100,
        );
        let resp_eval = engine.dispatch_ipc(&req_eval);
        assert_eq!(resp_eval.status, 0);
        assert_eq!(resp_eval.decision, 0); // Allowed
        assert_eq!(resp_eval.decision_as_str(), "ALLOWED");

        // 3. EvaluateAdmission via IPC -> unknown resource denied
        let req_eval_deny = PolicyRequest::new_eval(
            25,
            policy_rights::ALL,
            roles::ROLE_GUEST,
            actions::ACTION_ACCESS_SECRET,
            b"secrets/token",
            100,
        );
        let resp_eval_deny = engine.dispatch_ipc(&req_eval_deny);
        assert_eq!(resp_eval_deny.status, 0);
        assert_eq!(resp_eval_deny.decision, 1); // Denied
        assert_eq!(resp_eval_deny.decision_as_str(), "DENIED");

        // 4. AddRule via IPC -> Deny rule
        let req_add = PolicyRequest::new_add_rule(
            25,
            policy_rights::ALL,
            4,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ACCESS_SECRET,
            b"vault/forbidden",
            PolicyEffect::Deny as u8,
            80,
            0,
        );
        let resp_add = engine.dispatch_ipc(&req_add);
        assert_eq!(resp_add.status, 0);
        assert_eq!(resp_add.active_rules, 4);
        assert_eq!(resp_add.decision_as_str(), "RULE_ADDED");

        // 5. DeleteRule via IPC
        let req_del = PolicyRequest::new_delete_rule(25, policy_rights::ALL, 4);
        let resp_del = engine.dispatch_ipc(&req_del);
        assert_eq!(resp_del.status, 0);
        assert_eq!(resp_del.active_rules, 3);
        assert_eq!(resp_del.decision_as_str(), "RULE_DELETED");

        // 6. ListRules via IPC
        let req_list = PolicyRequest::new_list(25, policy_rights::ALL);
        let resp_list = engine.dispatch_ipc(&req_list);
        assert_eq!(resp_list.status, 0);
        assert_eq!(resp_list.active_rules, 3);
        assert_eq!(resp_list.decision_as_str(), "RULES_LISTED");
    }

    #[test]
    fn test_policy_defaults_and_deletion() {
        let cap = PolicyCap::new(Handle::new(25, 1), policy_rights::ALL);
        let mut engine = PolicyEngine::default();
        assert_eq!(engine.rule_count(), 3);

        // Vérification des 3 règles par défaut
        assert!(engine.get_rule_by_id(1).is_some());
        assert_eq!(engine.get_rule_by_id(1).unwrap().resource_str(), "system/");
        assert!(engine.get_rule_by_id(2).is_some());
        assert_eq!(
            engine.get_rule_by_id(2).unwrap().resource_str(),
            "workload/"
        );
        assert!(engine.get_rule_by_id(3).is_some());
        assert_eq!(engine.get_rule_by_id(3).unwrap().resource_str(), "vault/");

        // Suppression de la règle 2
        engine.delete_rule(&cap, 2).unwrap();
        assert_eq!(engine.rule_count(), 2);
        assert!(engine.get_rule_by_id(2).is_none());

        // Suppression d'une règle inexistante -> InvalidHandle
        assert_eq!(engine.delete_rule(&cap, 999), Err(SysError::InvalidHandle));
    }
}

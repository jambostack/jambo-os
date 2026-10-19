//! Moteur de Politiques de Sécurité Déclaratives & Contrôle d'Admission de Grappe (`jambo-policyd`)
//!
//! Fournit un moteur d'évaluation de politiques ABAC/RBAC déterministe en `#![no_std]`.
//! Garantit le principe de déni par défaut (*Deny-by-default*), la préséance des refus explicites,
//! l'expiration temporelle de baux de politiques, et l'auditabilité sans autorité ambiante via `PolicyCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_RULES: usize = 32;
pub const MAX_RESOURCE_LEN: usize = 32;

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
}

/// Types d'actions sensibles soumises à admission.
pub mod actions {
    pub const ACTION_SPAWN_WORKLOAD: u32 = 0x0001;
    pub const ACTION_ACCESS_SECRET: u32 = 0x0002;
    pub const ACTION_REGISTER_SERVICE: u32 = 0x0004;
    pub const ACTION_ROUTE_TRAFFIC: u32 = 0x0008;
    pub const ACTION_STORAGE_MOUNT: u32 = 0x0010;
    pub const ACTION_ADMIN: u32 = 0x8000;
}

/// Jeton de capacité pour le moteur de politiques de sécurité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyCap {
    pub handle: Handle,
    pub rights: u32,
}

impl PolicyCap {
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

/// Effet d'une règle de sécurité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
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

        &self.resource_prefix[..self.resource_len] == &req.resource[..self.resource_len]
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

/// Moteur de politiques d'admission pour la grappe JamboOS.
pub struct PolicyEngine {
    rules: [Option<PolicyRule>; MAX_RULES],
    eval_count: u64,
    allow_count: u64,
    deny_count: u64,
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
    pub fn remove_rule(&mut self, cap: &PolicyCap, rule_id: u32) -> Result<(), SysError> {
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
        if let Some(_) = highest_allow {
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
}

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
        let cap = PolicyCap::new(Handle::new(6901, 1), policy_rights::ALL);
        let mut engine = PolicyEngine::new();
        // Règles par défaut : Le rôle SYSTEM a accès à admin/ et secrets/
        let rule_sys = PolicyRule::new(
            1,
            roles::ROLE_SYSTEM,
            actions::ACTION_ADMIN | actions::ACTION_ACCESS_SECRET,
            b"admin/",
            PolicyEffect::Allow,
            100,
            0,
        )
        .unwrap();
        let _ = engine.add_rule(&cap, rule_sys);

        // Les opérateurs ont accès à workloads/
        let rule_op = PolicyRule::new(
            2,
            roles::ROLE_OPERATOR,
            actions::ACTION_SPAWN_WORKLOAD | actions::ACTION_ROUTE_TRAFFIC,
            b"workloads/",
            PolicyEffect::Allow,
            10,
            0,
        )
        .unwrap();
        let _ = engine.add_rule(&cap, rule_op);

        Self {
            engine,
            cap,
            operations_count: 2,
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) -> Result<(), SysError> {
        self.engine.add_rule(&self.cap, rule)?;
        self.operations_count = self.operations_count.saturating_add(1);
        Ok(())
    }

    pub fn remove_rule(&mut self, rule_id: u32) -> Result<(), SysError> {
        self.engine.remove_rule(&self.cap, rule_id)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_deny_by_default() {
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
    fn test_policy_allow_rule() {
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

        // Tentative sur une autre ressource non couverte -> Deny-by-default
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
    fn test_policy_explicit_deny_priority() {
        let cap = PolicyCap::new(Handle::new(1, 1), policy_rights::ALL);
        let mut engine = PolicyEngine::new();

        // Règle 1 : Allow large pour workloads/
        let rule_allow = PolicyRule::new(
            1,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ACCESS_SECRET,
            b"workloads/",
            PolicyEffect::Allow,
            5,
            0,
        )
        .unwrap();

        // Règle 2 : Deny explicite ciblé sur workloads/restricted
        let rule_deny = PolicyRule::new(
            2,
            roles::ROLE_WORKLOAD,
            actions::ACTION_ACCESS_SECRET,
            b"workloads/restricted",
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
            b"workloads/public-app",
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
            b"workloads/restricted/db",
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
    fn test_policy_expiration() {
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

        // Requête avant expiration (t=1400) -> Allowed
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

        // Requête après expiration (t=1600) -> Denied
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
    fn test_policy_rights_attenuation() {
        let cap_full = PolicyCap::new(Handle::new(1, 1), policy_rights::ALL);
        let cap_eval_only = cap_full.attenuate(policy_rights::POLICY_EVALUATE).unwrap();

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
    fn test_policy_daemon() {
        let mut daemon = JamboPolicyDaemon::new();
        assert_eq!(daemon.rule_count(), 2);

        let (evals, allows, denies) = daemon.stats().unwrap();
        assert_eq!(evals, 0);
        assert_eq!(allows, 0);
        assert_eq!(denies, 0);

        let req_sys = AdmissionRequest::new(
            1,
            roles::ROLE_SYSTEM,
            actions::ACTION_ADMIN,
            b"admin/subsystem",
            100,
        )
        .unwrap();
        assert_eq!(
            daemon.evaluate(&req_sys).unwrap(),
            AdmissionDecision::Allowed
        );

        let req_denied = AdmissionRequest::new(
            2,
            roles::ROLE_GUEST,
            actions::ACTION_ACCESS_SECRET,
            b"secrets/keys",
            100,
        )
        .unwrap();
        match daemon.evaluate(&req_denied).unwrap() {
            AdmissionDecision::Denied { .. } => {}
            _ => panic!("Guest access must be denied by default"),
        }

        let (evals2, allows2, denies2) = daemon.stats().unwrap();
        assert_eq!(evals2, 2);
        assert_eq!(allows2, 1);
        assert_eq!(denies2, 1);
    }
}

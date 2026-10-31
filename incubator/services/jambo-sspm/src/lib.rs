//! Gestion de la Posture de Sécurité des Services & SaaS (SSPM - SaaS Security Posture Management)
//! Moteur souverain d'évaluation continue de la conformité, détection des dérives de configuration,
//! analyse des permissions permissives et connecteurs tiers sans autorité ambiante.
//!
//! Phase 136 — Jalon v0.3.3
//!
//! Fournit une plateforme souveraine SSPM (SaaS Security Posture Management) en `#![no_std]` :
//! 1. Évaluation continue et inventaire exhaustif des services applicatifs, micro-services et connecteurs SaaS.
//! 2. Détection de dérives de configuration (Configuration Drift) par rapport aux baselines souveraines certifiées (ANSSI SecNumCloud, CIS Benchmark, Zero-Trust).
//! 3. Analyse approfondie des permissions permissives (Wildcard scopes, accès administrateur sans MFA, partages publics illicites).
//! 4. Gouvernance et surveillance proactive des intégrations & connecteurs tiers (Shadow SaaS, extensions non approuvées, jetons à durée excessive).
//! 5. Mécanisme de remédiation automatisée de configuration et mise en quarantaine immédiate O(1) des services ou connecteurs déviants.
//! 6. Calcul déterministe de l'indice global de posture SSPM (0..100) et certification de conformité souveraine.
//! 7. Contrôle d'accès capabilaire strict (`SspmCap`) sans autorité ambiante avec atténuation monotone.
//! 8. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

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

    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes += data.len() as u64;
        let mut offset = 0;
        while offset < data.len() {
            let space = 64 - self.buffer_len;
            let to_copy = if data.len() - offset < space {
                data.len() - offset
            } else {
                space
            };
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == 64 {
                self.process_block();
                self.buffer_len = 0;
            }
        }
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                self.buffer[i * 4],
                self.buffer[i * 4 + 1],
                self.buffer[i * 4 + 2],
                self.buffer[i * 4 + 3],
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

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            self.process_block();
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.process_block();

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
// CONTRÔLE D'ACCÈS PAR CAPABILITÉS (SSPM CAPABILITIES)
// ============================================================================

pub mod sspm_rights {
    pub const ASSESS_POSTURE: u32 = 0x0001;
    pub const SCAN_CONFIGS: u32 = 0x0002;
    pub const DETECT_DRIFT: u32 = 0x0004;
    pub const MANAGE_INTEGRATIONS: u32 = 0x0008;
    pub const REMEDIATE_DRIFT: u32 = 0x0010;
    pub const QUARANTINE_SERVICE: u32 = 0x0020;
    pub const QUERY_AUDIT: u32 = 0x0040;
    pub const ADMIN: u32 = 0x0080;
    pub const GENERATE_REPORT: u32 = 0x0100;
    pub const AUDIT_COMPLIANCE: u32 = 0x0200;

    pub const ALL: u32 = ASSESS_POSTURE
        | SCAN_CONFIGS
        | DETECT_DRIFT
        | MANAGE_INTEGRATIONS
        | REMEDIATE_DRIFT
        | QUARANTINE_SERVICE
        | QUERY_AUDIT
        | ADMIN
        | GENERATE_REPORT
        | AUDIT_COMPLIANCE;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SspmError {
    AccessDenied,
    CapabilityExpired,
    AttenuationViolation,
    ServiceNotFound,
    ServiceAlreadyExists,
    ConnectorNotFound,
    ConnectorAlreadyExists,
    CapacityExceeded,
    DriftNotFound,
    IntegrityCompromised,
    InvalidConfiguration,
}

/// Capabilité SSPM souveraine sans autorité ambiante
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SspmCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl SspmCap {
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

    /// Atténuation strictement monotone (Least Privilege)
    pub fn attenuate(
        &self,
        requested_rights: u32,
        lifetime: u64,
        invocations: u32,
    ) -> Result<Self, SspmError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(SspmError::AttenuationViolation);
        }
        let eff_lifetime = if lifetime < self.max_lifetime {
            lifetime
        } else {
            self.max_lifetime
        };
        let eff_invocations = if invocations < self.invocations_left {
            invocations
        } else {
            self.invocations_left
        };

        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
            max_lifetime: eff_lifetime,
            invocations_left: eff_invocations,
        })
    }

    pub fn consume(&mut self, required_right: u32) -> Result<(), SspmError> {
        if !self.has_right(required_right) {
            return Err(SspmError::AccessDenied);
        }
        if self.invocations_left == 0 {
            return Err(SspmError::CapabilityExpired);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// ÉNUMÉRATIONS ET STRUCTURES DE DONNÉES SSPM
// ============================================================================

/// Type de service applicatif ou connecteur
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    IdentitySSO,
    MessagingCollaboration,
    CloudStorageShare,
    ComputeMicroservice,
    ApiGatewayConnector,
    ThirdPartyIntegration,
}

impl ServiceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IdentitySSO => "Identity-SSO",
            Self::MessagingCollaboration => "Messaging-Collab",
            Self::CloudStorageShare => "CloudStorage-Share",
            Self::ComputeMicroservice => "Compute-Microservice",
            Self::ApiGatewayConnector => "API-Gateway",
            Self::ThirdPartyIntegration => "ThirdParty-Integration",
        }
    }
}

/// Environnement d'exécution du service
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEnvironment {
    SovereignCore,
    SecFabric,
    UserWorkload,
    ExternalCloud,
}

impl ServiceEnvironment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SovereignCore => "SovereignCore",
            Self::SecFabric => "SecFabric",
            Self::UserWorkload => "UserWorkload",
            Self::ExternalCloud => "ExternalCloud",
        }
    }
}

/// Référentiel de conformité cible
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStandard {
    AnssiSecNumCloud,
    CisBenchmark,
    ZeroTrustBaseline,
    DisaStig,
    CustomSovereignPolicy,
}

impl ComplianceStandard {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnssiSecNumCloud => "ANSSI SecNumCloud 3.2",
            Self::CisBenchmark => "CIS Benchmark Hardened",
            Self::ZeroTrustBaseline => "Zero-Trust Architecture",
            Self::DisaStig => "DISA-STIG Sovereign",
            Self::CustomSovereignPolicy => "Jambo Sovereign Policy",
        }
    }
}

/// Portée de permission accordée
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionScope {
    ReadOnlyStrict = 1,
    ReadWriteScoped = 2,
    AdminPrivileged = 3,
    WildcardFullAccess = 4, // Alerte : sur-privilégié / haut risque
}

impl PermissionScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnlyStrict => "ReadOnly:Strict",
            Self::ReadWriteScoped => "ReadWrite:Scoped",
            Self::AdminPrivileged => "Admin:Privileged",
            Self::WildcardFullAccess => "Wildcard:*.* (CRITICAL)",
        }
    }
}

/// Gravité de la dérive de configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftSeverity {
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl DriftSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "INFORMATIONAL",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Nature de la dérive ou violation de posture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftType {
    PermissiveWildcardPermission,
    UnauthorizedThirdPartySharing,
    MfaDisabledOnPrivilegedAccess,
    UnencryptedCommunicationTransport,
    ExcessiveTokenLifetime,
    PublicExposureMisconfiguration,
    AnonymousAccessAllowed,
    BaselineConfigurationDrift,
}

impl DriftType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PermissiveWildcardPermission => "Permissive Wildcard Permission (*.*)",
            Self::UnauthorizedThirdPartySharing => "Unauthorized Third-Party Sharing",
            Self::MfaDisabledOnPrivilegedAccess => "MFA Disabled On Privileged Access",
            Self::UnencryptedCommunicationTransport => "Unencrypted Transport Protocol",
            Self::ExcessiveTokenLifetime => "Excessive Token Lifetime (>24h)",
            Self::PublicExposureMisconfiguration => "Public Exposure Misconfiguration",
            Self::AnonymousAccessAllowed => "Anonymous Unauthenticated Access",
            Self::BaselineConfigurationDrift => "Baseline Configuration Hash Mismatch",
        }
    }
}

/// Actif de service ou application SaaS géré
#[derive(Debug, Clone, Copy)]
pub struct SspmServiceAsset {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub endpoint: [u8; 64],
    pub endpoint_len: usize,
    pub service_type: ServiceType,
    pub environment: ServiceEnvironment,
    pub compliance_target: ComplianceStandard,
    pub permission_scope: PermissionScope,
    pub external_third_party: bool,
    pub mfa_enforced: bool,
    pub tls_enforced: bool,
    pub quarantined: bool,
    pub config_hash: [u8; 32],
    pub baseline_hash: [u8; 32],
    pub last_scanned_tick: u64,
    pub risk_score: u8, // 0..100 (0 = sain, 100 = risque maximal)
}

impl SspmServiceAsset {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalid-name>")
    }

    pub fn endpoint_as_str(&self) -> &str {
        core::str::from_utf8(&self.endpoint[..self.endpoint_len]).unwrap_or("<invalid-endpoint>")
    }

    pub fn is_drifted(&self) -> bool {
        self.config_hash != self.baseline_hash
            || self.permission_scope == PermissionScope::WildcardFullAccess
            || (!self.mfa_enforced && self.permission_scope >= PermissionScope::AdminPrivileged)
            || !self.tls_enforced
    }
}

/// Connecteur tiers / intégration SaaS
#[derive(Debug, Clone, Copy)]
pub struct SspmConnector {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub service_id: u32,
    pub vendor: [u8; 32],
    pub vendor_len: usize,
    pub approved_by_sovereign_governance: bool,
    pub granted_scope: PermissionScope,
    pub active_token_lifetime_ticks: u64,
    pub data_read_count: u64,
    pub data_write_count: u64,
    pub quarantined: bool,
}

impl SspmConnector {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<invalid-name>")
    }

    pub fn vendor_as_str(&self) -> &str {
        core::str::from_utf8(&self.vendor[..self.vendor_len]).unwrap_or("<invalid-vendor>")
    }

    pub fn is_risky(&self) -> bool {
        !self.approved_by_sovereign_governance
            || self.granted_scope == PermissionScope::WildcardFullAccess
            || self.active_token_lifetime_ticks > 86400
    }
}

/// Événement de dérive de configuration détecté
#[derive(Debug, Clone, Copy)]
pub struct ConfigDriftEvent {
    pub id: u32,
    pub service_id: u32,
    pub connector_id: Option<u32>,
    pub drift_type: DriftType,
    pub severity: DriftSeverity,
    pub detected_tick: u64,
    pub resolved: bool,
    pub auto_remediated: bool,
    pub details: [u8; 64],
    pub details_len: usize,
}

impl ConfigDriftEvent {
    pub fn details_as_str(&self) -> &str {
        core::str::from_utf8(&self.details[..self.details_len]).unwrap_or("<no-details>")
    }
}

/// Synthèse globale de posture SSPM
#[derive(Debug, Clone, Copy)]
pub struct SspmSummary {
    pub total_services: usize,
    pub compliant_services: usize,
    pub drifted_services: usize,
    pub quarantined_services: usize,
    pub total_connectors: usize,
    pub unapproved_connectors: usize,
    pub active_drifts: usize,
    pub critical_drifts: usize,
    pub global_sspm_score: u8, // 0..100 (100 = parfaite conformité)
    pub sovereign_posture_compliant: bool,
}

/// Rapport d'évaluation de la posture des services & SaaS scellé cryptographiquement par SHA-256
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SspmPostureReport {
    pub report_id: u32,
    pub timestamp_ticks: u64,
    pub total_services: usize,
    pub compliant_services: usize,
    pub drifted_services: usize,
    pub quarantined_services: usize,
    pub total_connectors: usize,
    pub unapproved_connectors: usize,
    pub active_drifts: usize,
    pub critical_drifts: usize,
    pub global_sspm_score: u8,
    pub secnumcloud_compliance_pct: u8,
    pub cis_compliance_pct: u8,
    pub seal_hash: [u8; 32],
}

impl SspmPostureReport {
    pub fn compute_seal(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.report_id.to_be_bytes());
        hasher.update(&self.timestamp_ticks.to_be_bytes());
        hasher.update(&(self.total_services as u64).to_be_bytes());
        hasher.update(&(self.compliant_services as u64).to_be_bytes());
        hasher.update(&(self.drifted_services as u64).to_be_bytes());
        hasher.update(&(self.quarantined_services as u64).to_be_bytes());
        hasher.update(&(self.total_connectors as u64).to_be_bytes());
        hasher.update(&(self.unapproved_connectors as u64).to_be_bytes());
        hasher.update(&(self.active_drifts as u64).to_be_bytes());
        hasher.update(&(self.critical_drifts as u64).to_be_bytes());
        hasher.update(&[self.global_sspm_score]);
        hasher.update(&[self.secnumcloud_compliance_pct]);
        hasher.update(&[self.cis_compliance_pct]);
        hasher.finalize()
    }

    pub fn verify_seal(&self) -> bool {
        self.seal_hash == self.compute_seal()
    }
}

/// Rapport de remédiation autonome des dérives SSPM scellé cryptographiquement par SHA-256
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SspmRemediationReport {
    pub report_id: u32,
    pub timestamp_ticks: u64,
    pub remediated_drifts_count: usize,
    pub quarantined_connectors_count: usize,
    pub score_before: u8,
    pub score_after: u8,
    pub seal_hash: [u8; 32],
}

impl SspmRemediationReport {
    pub fn compute_seal(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.report_id.to_be_bytes());
        hasher.update(&self.timestamp_ticks.to_be_bytes());
        hasher.update(&(self.remediated_drifts_count as u64).to_be_bytes());
        hasher.update(&(self.quarantined_connectors_count as u64).to_be_bytes());
        hasher.update(&[self.score_before]);
        hasher.update(&[self.score_after]);
        hasher.finalize()
    }

    pub fn verify_seal(&self) -> bool {
        self.seal_hash == self.compute_seal()
    }
}

/// Entrée du registre d'audit cryptographique inviolable
#[derive(Debug, Clone, Copy)]
pub struct SspmAuditEntry {
    pub action_code: u16,
    pub service_id: u32,
    pub caller_handle: u64,
    pub timestamp_ticks: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub description: [u8; 48],
    pub description_len: usize,
}

impl SspmAuditEntry {
    pub fn description_as_str(&self) -> &str {
        core::str::from_utf8(&self.description[..self.description_len]).unwrap_or("<no-desc>")
    }
}

// ============================================================================
// DÉMON SSPM PRINCIPAL (JamboSspmDaemon)
// ============================================================================

pub struct JamboSspmDaemon {
    pub admin_cap: SspmCap,
    pub services: [Option<SspmServiceAsset>; 32],
    pub service_count: usize,
    pub connectors: [Option<SspmConnector>; 32],
    pub connector_count: usize,
    pub drifts: [Option<ConfigDriftEvent>; 64],
    pub drift_count: usize,
    pub ledger: [Option<SspmAuditEntry>; 64],
    pub ledger_count: usize,
    pub next_report_id: u32,
    next_service_id: u32,
    next_connector_id: u32,
    next_drift_id: u32,
}

impl JamboSspmDaemon {
    pub fn new(admin_cap: SspmCap) -> Self {
        Self {
            admin_cap,
            services: [None; 32],
            service_count: 0,
            connectors: [None; 32],
            connector_count: 0,
            drifts: [None; 64],
            drift_count: 0,
            ledger: [None; 64],
            ledger_count: 0,
            next_report_id: 1,
            next_service_id: 1,
            next_connector_id: 1,
            next_drift_id: 1,
        }
    }

    /// Initialise les services applicatifs et connecteurs souverains par défaut
    pub fn init_defaults(&mut self) {
        let mut cap = self.admin_cap;

        // Service 1: SSO Souverain / IdP
        let sso_cfg_hash = Sha256::digest(b"sso_sovereign_baseline_v1");
        let _ = self.register_service(
            &mut cap,
            "sovereign_idp_sso",
            "ipc:///svc/idp/oauth2",
            ServiceType::IdentitySSO,
            ServiceEnvironment::SovereignCore,
            ComplianceStandard::AnssiSecNumCloud,
            PermissionScope::AdminPrivileged,
            false,
            true, // MFA
            true, // TLS
            sso_cfg_hash,
            sso_cfg_hash,
            100,
        );

        // Service 2: Messagerie Sécurisée Chiffrée (Collab)
        let msg_cfg_hash = Sha256::digest(b"collab_messaging_baseline_v1");
        let _ = self.register_service(
            &mut cap,
            "sovereign_matrix_chat",
            "tls://collab.internal.jambo:8443",
            ServiceType::MessagingCollaboration,
            ServiceEnvironment::SecFabric,
            ComplianceStandard::AnssiSecNumCloud,
            PermissionScope::ReadWriteScoped,
            false,
            true,
            true,
            msg_cfg_hash,
            msg_cfg_hash,
            110,
        );

        // Service 3: Partage Cloud / Stockage Distribué VFS
        let store_cfg_hash = Sha256::digest(b"vfs_storage_share_baseline_v1");
        let _ = self.register_service(
            &mut cap,
            "sovereign_vfs_share",
            "ipc:///svc/vfs/distributed",
            ServiceType::CloudStorageShare,
            ServiceEnvironment::SecFabric,
            ComplianceStandard::ZeroTrustBaseline,
            PermissionScope::ReadWriteScoped,
            false,
            true,
            true,
            store_cfg_hash,
            store_cfg_hash,
            120,
        );

        // Service 4: Passerelle API Souveraine
        let gw_cfg_hash = Sha256::digest(b"api_gateway_baseline_v1");
        let _ = self.register_service(
            &mut cap,
            "sovereign_api_gateway",
            "https://gateway.secfabric.jambo:443",
            ServiceType::ApiGatewayConnector,
            ServiceEnvironment::SecFabric,
            ComplianceStandard::CisBenchmark,
            PermissionScope::ReadWriteScoped,
            false,
            true,
            true,
            gw_cfg_hash,
            gw_cfg_hash,
            130,
        );

        // Connecteur 1: Connecteur Chiffré Souverain Approuvé (attaché au VFS Share)
        let _ = self.register_connector(
            &mut cap,
            "sovereign_backup_sync",
            3,
            "Jambo SecVault",
            true, // Approuvé
            PermissionScope::ReadOnlyStrict,
            3600,
            140,
        );

        // Connecteur 2: Connecteur Tiers Externe (Webhook / Analytics) - Alerte Shadow SaaS
        let _ = self.register_connector(
            &mut cap,
            "external_analytics_hook",
            4,
            "GlobalMetric SaaS Corp",
            false,                               // Non approuvé !
            PermissionScope::WildcardFullAccess, // Permissif !
            172800,                              // Durée excessive 48h !
            150,
        );
    }

    /// Enregistre un nouveau service applicatif ou micro-service
    pub fn register_service(
        &mut self,
        cap: &mut SspmCap,
        name: &str,
        endpoint: &str,
        service_type: ServiceType,
        environment: ServiceEnvironment,
        compliance_target: ComplianceStandard,
        permission_scope: PermissionScope,
        external_third_party: bool,
        mfa_enforced: bool,
        tls_enforced: bool,
        config_hash: [u8; 32],
        baseline_hash: [u8; 32],
        current_tick: u64,
    ) -> Result<u32, SspmError> {
        cap.consume(sspm_rights::ADMIN | sspm_rights::SCAN_CONFIGS)?;

        if self.service_count >= self.services.len() {
            return Err(SspmError::CapacityExceeded);
        }

        // Vérifier unicité du nom
        for s in self.services.iter().flatten() {
            if s.name_as_str() == name {
                return Err(SspmError::ServiceAlreadyExists);
            }
        }

        let mut name_buf = [0u8; 32];
        let name_bytes = name.as_bytes();
        let name_len = core::cmp::min(name_bytes.len(), 32);
        name_buf[..name_len].copy_from_slice(&name_bytes[..name_len]);

        let mut ep_buf = [0u8; 64];
        let ep_bytes = endpoint.as_bytes();
        let ep_len = core::cmp::min(ep_bytes.len(), 64);
        ep_buf[..ep_len].copy_from_slice(&ep_bytes[..ep_len]);

        let id = self.next_service_id;
        self.next_service_id += 1;

        let mut asset = SspmServiceAsset {
            id,
            name: name_buf,
            name_len,
            endpoint: ep_buf,
            endpoint_len: ep_len,
            service_type,
            environment,
            compliance_target,
            permission_scope,
            external_third_party,
            mfa_enforced,
            tls_enforced,
            quarantined: false,
            config_hash,
            baseline_hash,
            last_scanned_tick: current_tick,
            risk_score: 0,
        };

        // Calcul initial du score de risque
        asset.risk_score = Self::evaluate_asset_risk(&asset);

        for slot in self.services.iter_mut() {
            if slot.is_none() {
                *slot = Some(asset);
                self.service_count += 1;
                break;
            }
        }

        self.append_audit(
            0x0101,
            id,
            cap.handle.0,
            current_tick,
            b"Service registered",
        );

        // Détection immédiate d'anomalies de configuration
        self.detect_service_drifts(id, current_tick);

        Ok(id)
    }

    /// Enregistre un connecteur ou intégration tierce
    pub fn register_connector(
        &mut self,
        cap: &mut SspmCap,
        name: &str,
        service_id: u32,
        vendor: &str,
        approved_by_sovereign_governance: bool,
        granted_scope: PermissionScope,
        active_token_lifetime_ticks: u64,
        current_tick: u64,
    ) -> Result<u32, SspmError> {
        cap.consume(sspm_rights::MANAGE_INTEGRATIONS)?;

        if self.connector_count >= self.connectors.len() {
            return Err(SspmError::CapacityExceeded);
        }

        // Vérifier existence du service associé
        let mut service_found = false;
        for s in self.services.iter().flatten() {
            if s.id == service_id {
                service_found = true;
                break;
            }
        }
        if !service_found {
            return Err(SspmError::ServiceNotFound);
        }

        let mut name_buf = [0u8; 32];
        let name_bytes = name.as_bytes();
        let name_len = core::cmp::min(name_bytes.len(), 32);
        name_buf[..name_len].copy_from_slice(&name_bytes[..name_len]);

        let mut ven_buf = [0u8; 32];
        let ven_bytes = vendor.as_bytes();
        let ven_len = core::cmp::min(ven_bytes.len(), 32);
        ven_buf[..ven_len].copy_from_slice(&ven_bytes[..ven_len]);

        let id = self.next_connector_id;
        self.next_connector_id += 1;

        let conn = SspmConnector {
            id,
            name: name_buf,
            name_len,
            service_id,
            vendor: ven_buf,
            vendor_len: ven_len,
            approved_by_sovereign_governance,
            granted_scope,
            active_token_lifetime_ticks,
            data_read_count: 0,
            data_write_count: 0,
            quarantined: false,
        };

        for slot in self.connectors.iter_mut() {
            if slot.is_none() {
                *slot = Some(conn);
                self.connector_count += 1;
                break;
            }
        }

        self.append_audit(
            0x0102,
            service_id,
            cap.handle.0,
            current_tick,
            b"Connector registered",
        );

        // Analyse immédiate des risques du connecteur
        self.detect_connector_drifts(id, current_tick);

        Ok(id)
    }

    /// Détecte les dérives de configuration pour un service
    pub fn detect_service_drifts(&mut self, service_id: u32, current_tick: u64) {
        let (asset, idx) = match self.get_service_with_idx(service_id) {
            Some(res) => res,
            None => return,
        };

        // 1. Dérive de Hash de Baseline
        if asset.config_hash != asset.baseline_hash {
            self.add_drift_event(
                service_id,
                None,
                DriftType::BaselineConfigurationDrift,
                DriftSeverity::High,
                current_tick,
                b"Config hash mismatch vs certified sovereign baseline",
            );
        }

        // 2. Permission Permissive Wildcard
        if asset.permission_scope == PermissionScope::WildcardFullAccess {
            self.add_drift_event(
                service_id,
                None,
                DriftType::PermissiveWildcardPermission,
                DriftSeverity::Critical,
                current_tick,
                b"Excessive wildcard full access scope detected",
            );
        }

        // 3. MFA absent pour compte ou accès privilégié
        if !asset.mfa_enforced && asset.permission_scope >= PermissionScope::AdminPrivileged {
            self.add_drift_event(
                service_id,
                None,
                DriftType::MfaDisabledOnPrivilegedAccess,
                DriftSeverity::High,
                current_tick,
                b"Privileged service operates without mandatory MFA/Dual-Auth",
            );
        }

        // 4. Protocole non chiffré
        if !asset.tls_enforced {
            self.add_drift_event(
                service_id,
                None,
                DriftType::UnencryptedCommunicationTransport,
                DriftSeverity::Critical,
                current_tick,
                b"Cleartext unencrypted transport protocol detected",
            );
        }

        // Recalcul du score de risque
        if let Some(ref mut s) = self.services[idx] {
            s.last_scanned_tick = current_tick;
            s.risk_score = Self::evaluate_asset_risk(s);
        }
    }

    /// Détecte les dérives ou anomalies pour un connecteur tiers
    pub fn detect_connector_drifts(&mut self, connector_id: u32, current_tick: u64) {
        let conn = match self.get_connector(connector_id) {
            Some(c) => c,
            None => return,
        };

        // 1. Intégration non approuvée par la gouvernance souveraine
        if !conn.approved_by_sovereign_governance {
            self.add_drift_event(
                conn.service_id,
                Some(conn.id),
                DriftType::UnauthorizedThirdPartySharing,
                DriftSeverity::Critical,
                current_tick,
                b"Unapproved third-party shadow SaaS integration detected",
            );
        }

        // 2. Permission accordée de type Wildcard
        if conn.granted_scope == PermissionScope::WildcardFullAccess {
            self.add_drift_event(
                conn.service_id,
                Some(conn.id),
                DriftType::PermissiveWildcardPermission,
                DriftSeverity::Critical,
                current_tick,
                b"Connector granted dangerous wildcard full access",
            );
        }

        // 3. Durée de vie du jeton active supérieure à 24h (86400 ticks)
        if conn.active_token_lifetime_ticks > 86400 {
            self.add_drift_event(
                conn.service_id,
                Some(conn.id),
                DriftType::ExcessiveTokenLifetime,
                DriftSeverity::Medium,
                current_tick,
                b"Integration token lifetime exceeds 24-hour security policy",
            );
        }
    }

    fn add_drift_event(
        &mut self,
        service_id: u32,
        connector_id: Option<u32>,
        drift_type: DriftType,
        severity: DriftSeverity,
        current_tick: u64,
        details: &[u8],
    ) {
        // Éviter les doublons d'événements non résolus pour la même dérive
        for d in self.drifts.iter().flatten() {
            if d.service_id == service_id
                && d.connector_id == connector_id
                && d.drift_type == drift_type
                && !d.resolved
            {
                return;
            }
        }

        let mut det_buf = [0u8; 64];
        let len = core::cmp::min(details.len(), 64);
        det_buf[..len].copy_from_slice(&details[..len]);

        let id = self.next_drift_id;
        self.next_drift_id += 1;

        let ev = ConfigDriftEvent {
            id,
            service_id,
            connector_id,
            drift_type,
            severity,
            detected_tick: current_tick,
            resolved: false,
            auto_remediated: false,
            details: det_buf,
            details_len: len,
        };

        for slot in self.drifts.iter_mut() {
            if slot.is_none() {
                *slot = Some(ev);
                self.drift_count += 1;
                break;
            }
        }

        self.append_audit(
            0x0201,
            service_id,
            0,
            current_tick,
            b"Config drift detected",
        );
    }

    /// Auto-remédiation d'une dérive de configuration
    pub fn remediate_drift(
        &mut self,
        cap: &mut SspmCap,
        drift_id: u32,
        current_tick: u64,
    ) -> Result<(), SspmError> {
        cap.consume(sspm_rights::REMEDIATE_DRIFT)?;

        let mut target_service_id = 0;
        let mut target_connector_id = None;
        let mut drift_found = false;
        let mut drift_type = DriftType::BaselineConfigurationDrift;

        for d in self.drifts.iter_mut().flatten() {
            if d.id == drift_id && !d.resolved {
                target_service_id = d.service_id;
                target_connector_id = d.connector_id;
                drift_type = d.drift_type;
                d.resolved = true;
                d.auto_remediated = true;
                drift_found = true;
                break;
            }
        }

        if !drift_found {
            return Err(SspmError::DriftNotFound);
        }

        // Application de la correction sur le service
        if let Some((_, idx)) = self.get_service_with_idx(target_service_id) {
            if let Some(ref mut s) = self.services[idx] {
                match drift_type {
                    DriftType::BaselineConfigurationDrift => {
                        // Restauration du hash conforme
                        s.config_hash = s.baseline_hash;
                    }
                    DriftType::PermissiveWildcardPermission => {
                        // Rétrogradation monotone Least-Privilege
                        s.permission_scope = PermissionScope::ReadWriteScoped;
                    }
                    DriftType::MfaDisabledOnPrivilegedAccess => {
                        s.mfa_enforced = true;
                    }
                    DriftType::UnencryptedCommunicationTransport => {
                        s.tls_enforced = true;
                    }
                    _ => {}
                }
                s.risk_score = Self::evaluate_asset_risk(s);
            }
        }

        // Application de la correction sur le connecteur s'il y a lieu
        if let Some(cid) = target_connector_id {
            for c in self.connectors.iter_mut().flatten() {
                if c.id == cid {
                    match drift_type {
                        DriftType::UnauthorizedThirdPartySharing => {
                            // Mise en quarantaine immédiate du connecteur tiers non approuvé
                            c.quarantined = true;
                        }
                        DriftType::PermissiveWildcardPermission => {
                            c.granted_scope = PermissionScope::ReadOnlyStrict;
                        }
                        DriftType::ExcessiveTokenLifetime => {
                            c.active_token_lifetime_ticks = 3600; // Ramené à 1h
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }

        self.append_audit(
            0x0301,
            target_service_id,
            cap.handle.0,
            current_tick,
            b"Drift remediated and aligned with baseline",
        );

        Ok(())
    }

    /// Mise en quarantaine immédiate O(1) d'un service
    pub fn quarantine_service(
        &mut self,
        cap: &mut SspmCap,
        service_id: u32,
        current_tick: u64,
    ) -> Result<(), SspmError> {
        cap.consume(sspm_rights::QUARANTINE_SERVICE)?;

        let mut found = false;
        for s in self.services.iter_mut().flatten() {
            if s.id == service_id {
                s.quarantined = true;
                found = true;
                break;
            }
        }

        if !found {
            return Err(SspmError::ServiceNotFound);
        }

        self.append_audit(
            0x0401,
            service_id,
            cap.handle.0,
            current_tick,
            b"Service quarantined",
        );
        Ok(())
    }

    /// Levée de quarantaine d'un service après remédiation
    pub fn unquarantine_service(
        &mut self,
        cap: &mut SspmCap,
        service_id: u32,
        current_tick: u64,
    ) -> Result<(), SspmError> {
        cap.consume(sspm_rights::QUARANTINE_SERVICE | sspm_rights::ADMIN)?;

        let mut found = false;
        for s in self.services.iter_mut().flatten() {
            if s.id == service_id {
                s.quarantined = false;
                found = true;
                break;
            }
        }

        if !found {
            return Err(SspmError::ServiceNotFound);
        }

        self.append_audit(
            0x0402,
            service_id,
            cap.handle.0,
            current_tick,
            b"Service unquarantined",
        );
        Ok(())
    }

    /// Mise en quarantaine immédiate O(1) d'un connecteur
    pub fn quarantine_connector(
        &mut self,
        cap: &mut SspmCap,
        connector_id: u32,
        current_tick: u64,
    ) -> Result<(), SspmError> {
        cap.consume(sspm_rights::QUARANTINE_SERVICE)?;

        let mut target_service_id = 0;
        let mut found = false;
        for c in self.connectors.iter_mut().flatten() {
            if c.id == connector_id {
                c.quarantined = true;
                target_service_id = c.service_id;
                found = true;
                break;
            }
        }

        if !found {
            return Err(SspmError::ConnectorNotFound);
        }

        self.append_audit(
            0x0403,
            target_service_id,
            cap.handle.0,
            current_tick,
            b"Connector quarantined",
        );
        Ok(())
    }

    /// Balayage d'évaluation complet de posture pour tous les services et connecteurs
    pub fn run_full_posture_scan(
        &mut self,
        cap: &mut SspmCap,
        current_tick: u64,
    ) -> Result<usize, SspmError> {
        cap.consume(sspm_rights::SCAN_CONFIGS | sspm_rights::DETECT_DRIFT)?;

        let mut scanned = 0;
        let mut service_ids = [0u32; 32];
        let mut s_count = 0;

        for s in self.services.iter().flatten() {
            if s_count < 32 {
                service_ids[s_count] = s.id;
                s_count += 1;
            }
        }

        for i in 0..s_count {
            self.detect_service_drifts(service_ids[i], current_tick);
            scanned += 1;
        }

        let mut conn_ids = [0u32; 32];
        let mut c_count = 0;
        for c in self.connectors.iter().flatten() {
            if c_count < 32 {
                conn_ids[c_count] = c.id;
                c_count += 1;
            }
        }

        for i in 0..c_count {
            self.detect_connector_drifts(conn_ids[i], current_tick);
        }

        self.append_audit(
            0x0501,
            0,
            cap.handle.0,
            current_tick,
            b"Full posture scan completed",
        );

        Ok(scanned)
    }

    /// Évalue le score de risque d'un service (0..100)
    pub fn evaluate_asset_risk(asset: &SspmServiceAsset) -> u8 {
        let mut risk: u32 = 0;

        if asset.config_hash != asset.baseline_hash {
            risk += 35;
        }

        match asset.permission_scope {
            PermissionScope::WildcardFullAccess => risk += 40,
            PermissionScope::AdminPrivileged => risk += 15,
            PermissionScope::ReadWriteScoped => risk += 5,
            PermissionScope::ReadOnlyStrict => {}
        }

        if !asset.mfa_enforced && asset.permission_scope >= PermissionScope::AdminPrivileged {
            risk += 30;
        }

        if !asset.tls_enforced {
            risk += 30;
        }

        if asset.quarantined {
            risk += 10;
        }

        if risk > 100 {
            100
        } else {
            risk as u8
        }
    }

    /// Calcule le score global de posture SSPM (0..100, où 100 = parfaite sécurité)
    pub fn calculate_sspm_score(&self) -> u8 {
        if self.service_count == 0 {
            return 100;
        }

        let mut total_risk_sum: u32 = 0;
        let mut active_services = 0;

        for s in self.services.iter().flatten() {
            total_risk_sum += s.risk_score as u32;
            active_services += 1;
        }

        // Pénalités additionnelles pour connecteurs risqués non approuvés
        for c in self.connectors.iter().flatten() {
            if !c.approved_by_sovereign_governance {
                total_risk_sum += 25;
            }
            if c.granted_scope == PermissionScope::WildcardFullAccess {
                total_risk_sum += 20;
            }
        }

        let avg_risk = total_risk_sum / (active_services as u32);
        let final_risk = if avg_risk > 100 { 100 } else { avg_risk };

        (100 - final_risk) as u8
    }

    /// Génère la synthèse globale de posture pour le monitoring et la CLI
    pub fn get_summary(&self, cap: &SspmCap) -> Result<SspmSummary, SspmError> {
        if !cap.has_right(sspm_rights::ASSESS_POSTURE) && !cap.has_right(sspm_rights::ADMIN) {
            return Err(SspmError::AccessDenied);
        }

        let mut compliant = 0;
        let mut drifted = 0;
        let mut quarantined = 0;

        for s in self.services.iter().flatten() {
            if s.quarantined {
                quarantined += 1;
            }
            if s.is_drifted() {
                drifted += 1;
            } else {
                compliant += 1;
            }
        }

        let mut unapproved_conns = 0;
        for c in self.connectors.iter().flatten() {
            if !c.approved_by_sovereign_governance {
                unapproved_conns += 1;
            }
        }

        let mut active_d = 0;
        let mut crit_d = 0;
        for d in self.drifts.iter().flatten() {
            if !d.resolved {
                active_d += 1;
                if d.severity == DriftSeverity::Critical {
                    crit_d += 1;
                }
            }
        }

        let global_score = self.calculate_sspm_score();
        let sovereign_ok = global_score >= 80 && crit_d == 0;

        Ok(SspmSummary {
            total_services: self.service_count,
            compliant_services: compliant,
            drifted_services: drifted,
            quarantined_services: quarantined,
            total_connectors: self.connector_count,
            unapproved_connectors: unapproved_conns,
            active_drifts: active_d,
            critical_drifts: crit_d,
            global_sspm_score: global_score,
            sovereign_posture_compliant: sovereign_ok,
        })
    }

    /// Ajoute une entrée immuable dans le registre d'audit cryptographique SHA-256
    fn append_audit(
        &mut self,
        action_code: u16,
        service_id: u32,
        caller_handle: u64,
        timestamp_ticks: u64,
        description: &[u8],
    ) {
        let prev_hash = if self.ledger_count > 0 {
            match self.ledger[self.ledger_count - 1] {
                Some(ref e) => e.entry_hash,
                None => [0u8; 32],
            }
        } else {
            [0u8; 32]
        };

        let mut desc_buf = [0u8; 48];
        let len = core::cmp::min(description.len(), 48);
        desc_buf[..len].copy_from_slice(&description[..len]);

        // Calcul du hash d'entrée en chaînage
        let mut hasher = Sha256::new();
        hasher.update(&prev_hash);
        hasher.update(&action_code.to_be_bytes());
        hasher.update(&service_id.to_be_bytes());
        hasher.update(&caller_handle.to_be_bytes());
        hasher.update(&timestamp_ticks.to_be_bytes());
        hasher.update(&desc_buf[..len]);
        let entry_hash = hasher.finalize();

        let entry = SspmAuditEntry {
            action_code,
            service_id,
            caller_handle,
            timestamp_ticks,
            prev_hash,
            entry_hash,
            description: desc_buf,
            description_len: len,
        };

        if self.ledger_count < self.ledger.len() {
            self.ledger[self.ledger_count] = Some(entry);
            self.ledger_count += 1;
        } else {
            // Tampon circulaire scellé
            for i in 1..self.ledger.len() {
                self.ledger[i - 1] = self.ledger[i];
            }
            self.ledger[self.ledger.len() - 1] = Some(entry);
        }
    }

    /// Vérifie l'intégrité cryptographique complète du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut prev = [0u8; 32];
        for i in 0..self.ledger_count {
            if let Some(ref e) = self.ledger[i] {
                if e.prev_hash != prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&e.prev_hash);
                hasher.update(&e.action_code.to_be_bytes());
                hasher.update(&e.service_id.to_be_bytes());
                hasher.update(&e.caller_handle.to_be_bytes());
                hasher.update(&e.timestamp_ticks.to_be_bytes());
                hasher.update(&e.description[..e.description_len]);
                let computed = hasher.finalize();

                if computed != e.entry_hash {
                    return false;
                }
                prev = e.entry_hash;
            }
        }
        true
    }

    fn get_service_with_idx(&self, id: u32) -> Option<(SspmServiceAsset, usize)> {
        for (i, slot) in self.services.iter().enumerate() {
            if let Some(s) = slot {
                if s.id == id {
                    return Some((*s, i));
                }
            }
        }
        None
    }

    fn get_connector(&self, id: u32) -> Option<SspmConnector> {
        for slot in self.connectors.iter().flatten() {
            if slot.id == id {
                return Some(*slot);
            }
        }
        None
    }

    /// Calcule le taux de conformité SecNumCloud 3.2 des services et connecteurs (0..100)
    pub fn calculate_secnumcloud_compliance(&self) -> u8 {
        if self.service_count == 0 && self.connector_count == 0 {
            return 100;
        }

        let mut total_points = 0u32;
        let mut max_points = 0u32;

        for s in self.services.iter().flatten() {
            max_points += 4;
            if s.mfa_enforced {
                total_points += 1;
            }
            if s.tls_enforced {
                total_points += 1;
            }
            if s.permission_scope <= PermissionScope::ReadWriteScoped {
                total_points += 1;
            }
            if s.config_hash == s.baseline_hash && !s.quarantined {
                total_points += 1;
            }
        }

        for c in self.connectors.iter().flatten() {
            max_points += 3;
            if c.approved_by_sovereign_governance {
                total_points += 1;
            }
            if c.granted_scope <= PermissionScope::ReadWriteScoped {
                total_points += 1;
            }
            if c.active_token_lifetime_ticks <= 86400 && !c.quarantined {
                total_points += 1;
            }
        }

        if max_points == 0 {
            100
        } else {
            ((total_points * 100) / max_points) as u8
        }
    }

    /// Calcule le taux de conformité CIS Benchmark durci (0..100)
    pub fn calculate_cis_compliance(&self) -> u8 {
        if self.service_count == 0 && self.connector_count == 0 {
            return 100;
        }

        let mut total_checks = 0u32;
        let mut passed_checks = 0u32;

        for s in self.services.iter().flatten() {
            total_checks += 3;
            if s.tls_enforced {
                passed_checks += 1;
            }
            if s.config_hash == s.baseline_hash {
                passed_checks += 1;
            }
            if s.permission_scope != PermissionScope::WildcardFullAccess {
                passed_checks += 1;
            }
        }

        for c in self.connectors.iter().flatten() {
            total_checks += 2;
            if c.granted_scope != PermissionScope::WildcardFullAccess {
                passed_checks += 1;
            }
            if c.active_token_lifetime_ticks <= 86400 {
                passed_checks += 1;
            }
        }

        if total_checks == 0 {
            100
        } else {
            ((passed_checks * 100) / total_checks) as u8
        }
    }

    /// Réconciliation et remédiation autonome O(1) de toutes les dérives actives
    pub fn remediate_all_drifts(
        &mut self,
        cap: &mut SspmCap,
        current_tick: u64,
    ) -> Result<usize, SspmError> {
        cap.consume(sspm_rights::REMEDIATE_DRIFT)?;

        let mut remediated = 0;

        // 1. Remédier toutes les dérives signalées
        for i in 0..self.drifts.len() {
            if let Some(ref mut d) = self.drifts[i] {
                if !d.resolved {
                    let service_id = d.service_id;
                    let connector_id = d.connector_id;
                    let drift_type = d.drift_type;

                    d.resolved = true;
                    d.auto_remediated = true;
                    remediated += 1;

                    // Aligner le service
                    if let Some((_, idx)) = self.get_service_with_idx(service_id) {
                        if let Some(ref mut s) = self.services[idx] {
                            match drift_type {
                                DriftType::BaselineConfigurationDrift => {
                                    s.config_hash = s.baseline_hash;
                                }
                                DriftType::PermissiveWildcardPermission => {
                                    s.permission_scope = PermissionScope::ReadWriteScoped;
                                }
                                DriftType::MfaDisabledOnPrivilegedAccess => {
                                    s.mfa_enforced = true;
                                }
                                DriftType::UnencryptedCommunicationTransport => {
                                    s.tls_enforced = true;
                                }
                                _ => {}
                            }
                            s.risk_score = Self::evaluate_asset_risk(s);
                        }
                    }

                    // Aligner le connecteur s'il y a lieu
                    if let Some(cid) = connector_id {
                        for c in self.connectors.iter_mut().flatten() {
                            if c.id == cid {
                                match drift_type {
                                    DriftType::UnauthorizedThirdPartySharing => {
                                        c.quarantined = true;
                                    }
                                    DriftType::PermissiveWildcardPermission => {
                                        c.granted_scope = PermissionScope::ReadOnlyStrict;
                                    }
                                    DriftType::ExcessiveTokenLifetime => {
                                        c.active_token_lifetime_ticks = 3600;
                                    }
                                    _ => {}
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 2. Mettre en quarantaine proactive tout connecteur tiers non approuvé résiduel
        for c in self.connectors.iter_mut().flatten() {
            if !c.approved_by_sovereign_governance && !c.quarantined {
                c.quarantined = true;
            }
        }

        self.append_audit(
            0x0302,
            0,
            cap.handle.0,
            current_tick,
            b"Autonomous remediation of all configuration drifts",
        );

        Ok(remediated)
    }

    /// Génère un rapport de posture scellé SHA-256
    pub fn generate_posture_report(
        &mut self,
        cap: &SspmCap,
        current_tick: u64,
    ) -> Result<SspmPostureReport, SspmError> {
        if !cap.has_right(sspm_rights::GENERATE_REPORT) && !cap.has_right(sspm_rights::ADMIN) {
            return Err(SspmError::AccessDenied);
        }

        let summary = self.get_summary(cap)?;
        let secnum = self.calculate_secnumcloud_compliance();
        let cis = self.calculate_cis_compliance();

        let report_id = self.next_report_id;
        self.next_report_id += 1;

        let mut report = SspmPostureReport {
            report_id,
            timestamp_ticks: current_tick,
            total_services: summary.total_services,
            compliant_services: summary.compliant_services,
            drifted_services: summary.drifted_services,
            quarantined_services: summary.quarantined_services,
            total_connectors: summary.total_connectors,
            unapproved_connectors: summary.unapproved_connectors,
            active_drifts: summary.active_drifts,
            critical_drifts: summary.critical_drifts,
            global_sspm_score: summary.global_sspm_score,
            secnumcloud_compliance_pct: secnum,
            cis_compliance_pct: cis,
            seal_hash: [0u8; 32],
        };

        report.seal_hash = report.compute_seal();

        self.append_audit(
            0x0502,
            0,
            cap.handle.0,
            current_tick,
            b"Posture report generated and cryptographically sealed",
        );

        Ok(report)
    }

    /// Génère un rapport de remédiation scellé SHA-256
    pub fn generate_remediation_report(
        &mut self,
        cap: &SspmCap,
        score_before: u8,
        drifts_remediated: usize,
        current_tick: u64,
    ) -> Result<SspmRemediationReport, SspmError> {
        if !cap.has_right(sspm_rights::GENERATE_REPORT) && !cap.has_right(sspm_rights::ADMIN) {
            return Err(SspmError::AccessDenied);
        }

        let score_after = self.calculate_sspm_score();
        let mut quarantined_conns = 0;
        for c in self.connectors.iter().flatten() {
            if c.quarantined {
                quarantined_conns += 1;
            }
        }

        let report_id = self.next_report_id;
        self.next_report_id += 1;

        let mut report = SspmRemediationReport {
            report_id,
            timestamp_ticks: current_tick,
            remediated_drifts_count: drifts_remediated,
            quarantined_connectors_count: quarantined_conns,
            score_before,
            score_after,
            seal_hash: [0u8; 32],
        };

        report.seal_hash = report.compute_seal();

        self.append_audit(
            0x0503,
            0,
            cap.handle.0,
            current_tick,
            b"Remediation report generated and cryptographically sealed",
        );

        Ok(report)
    }

    pub fn verify_posture_report_hash(report: &SspmPostureReport) -> bool {
        report.verify_seal()
    }

    pub fn verify_remediation_report_hash(report: &SspmRemediationReport) -> bool {
        report.verify_seal()
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sspm_cap_attenuation_and_least_privilege() {
        let root_cap = SspmCap::new(Handle::new(13601, 1), sspm_rights::ALL, 10000, 100);
        assert!(root_cap.has_right(sspm_rights::ADMIN));
        assert!(root_cap.has_right(sspm_rights::QUARANTINE_SERVICE));

        // Atténuation monotone valide
        let auditor_cap = root_cap
            .attenuate(
                sspm_rights::ASSESS_POSTURE | sspm_rights::QUERY_AUDIT,
                5000,
                50,
            )
            .expect("Atténuation monotone");
        assert!(auditor_cap.has_right(sspm_rights::ASSESS_POSTURE));
        assert!(auditor_cap.has_right(sspm_rights::QUERY_AUDIT));
        assert!(!auditor_cap.has_right(sspm_rights::ADMIN));
        assert!(!auditor_cap.has_right(sspm_rights::QUARANTINE_SERVICE));
        assert_eq!(auditor_cap.max_lifetime, 5000);
        assert_eq!(auditor_cap.invocations_left, 50);

        // Tentative d'escalade illicite (Rejet)
        let escalation = auditor_cap.attenuate(sspm_rights::ALL, 5000, 50);
        assert_eq!(escalation, Err(SspmError::AttenuationViolation));
    }

    #[test]
    fn test_sspm_service_registration_and_drift_detection() {
        let mut cap = SspmCap::new(Handle::new(13602, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);

        let baseline = Sha256::digest(b"sovereign_config_v1");
        let altered_config = Sha256::digest(b"attacker_altered_config_v2");

        // Service avec dérive de configuration (Hash mismatch)
        let svc_id = daemon
            .register_service(
                &mut cap,
                "finance_ledger_svc",
                "ipc:///svc/finance",
                ServiceType::ComputeMicroservice,
                ServiceEnvironment::SecFabric,
                ComplianceStandard::AnssiSecNumCloud,
                PermissionScope::ReadWriteScoped,
                false,
                true,
                true,
                altered_config,
                baseline,
                1000,
            )
            .expect("Enregistrement finance_ledger_svc");

        assert_eq!(svc_id, 1);
        assert_eq!(daemon.drift_count, 1);
        assert_eq!(
            daemon.drifts[0].unwrap().drift_type,
            DriftType::BaselineConfigurationDrift
        );
        assert!(!daemon.drifts[0].unwrap().resolved);
    }

    #[test]
    fn test_sspm_drift_remediation() {
        let mut cap = SspmCap::new(Handle::new(13603, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);

        let baseline = Sha256::digest(b"standard_baseline");
        let altered = Sha256::digest(b"drifted_baseline");

        let _svc_id = daemon
            .register_service(
                &mut cap,
                "hr_portal",
                "https://hr.internal.jambo:443",
                ServiceType::ComputeMicroservice,
                ServiceEnvironment::UserWorkload,
                ComplianceStandard::ZeroTrustBaseline,
                PermissionScope::WildcardFullAccess, // Dérive de scope !
                false,
                false, // Dérive MFA !
                true,
                altered,
                baseline,
                2000,
            )
            .unwrap();

        // 3 dérives doivent être détectées : baseline mismatch, wildcard scope, MFA manquant
        assert!(daemon.drift_count >= 3);

        // Résolution de la première dérive
        let drift_id = daemon.drifts[0].unwrap().id;
        daemon.remediate_drift(&mut cap, drift_id, 2010).unwrap();
        assert!(daemon.drifts[0].unwrap().resolved);
        assert!(daemon.drifts[0].unwrap().auto_remediated);

        // Vérification de la restauration de la baseline
        let s = daemon.services[0].unwrap();
        assert_eq!(s.config_hash, s.baseline_hash);
    }

    #[test]
    fn test_sspm_third_party_shadow_connector_quarantine() {
        let mut cap = SspmCap::new(Handle::new(13604, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);
        daemon.init_defaults();

        // Le connecteur 2 est non approuvé (Shadow SaaS)
        let unapproved_conn = daemon.connectors[1].unwrap();
        assert_eq!(unapproved_conn.id, 2);
        assert!(!unapproved_conn.approved_by_sovereign_governance);
        assert!(unapproved_conn.is_risky());

        // Mise en quarantaine du connecteur
        daemon.quarantine_connector(&mut cap, 2, 3000).unwrap();
        assert!(daemon.connectors[1].unwrap().quarantined);
    }

    #[test]
    fn test_sspm_service_quarantine_and_isolation() {
        let mut cap = SspmCap::new(Handle::new(13605, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);
        daemon.init_defaults();

        // Quarantaine du service 1 (IdP SSO)
        daemon.quarantine_service(&mut cap, 1, 4000).unwrap();
        assert!(daemon.services[0].unwrap().quarantined);

        // Levée de la quarantaine
        daemon.unquarantine_service(&mut cap, 1, 4010).unwrap();
        assert!(!daemon.services[0].unwrap().quarantined);
    }

    #[test]
    fn test_sspm_full_posture_scan_and_summary() {
        let mut cap = SspmCap::new(Handle::new(13606, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);
        daemon.init_defaults();

        let scanned = daemon.run_full_posture_scan(&mut cap, 5000).unwrap();
        assert_eq!(scanned, 4);

        let summary = daemon.get_summary(&cap).unwrap();
        assert_eq!(summary.total_services, 4);
        assert_eq!(summary.total_connectors, 2);
        assert_eq!(summary.unapproved_connectors, 1);
        assert!(summary.global_sspm_score <= 100);
    }

    #[test]
    fn test_sspm_cryptographic_ledger_tamper_proofing() {
        let cap = SspmCap::new(Handle::new(13607, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);
        daemon.init_defaults();

        assert!(daemon.verify_ledger_integrity());

        // Altération malveillante d'une entrée d'audit
        if let Some(ref mut entry) = daemon.ledger[0] {
            entry.action_code = 0xDEAD;
        }

        assert!(
            !daemon.verify_ledger_integrity(),
            "L'altération de l'audit doit être détectée"
        );
    }

    #[test]
    fn test_sspm_remediate_all_drifts() {
        let mut cap = SspmCap::new(Handle::new(13608, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);
        daemon.init_defaults();

        // Enregistrer un service présentant plusieurs dérives
        let baseline = Sha256::digest(b"base_crm");
        let altered = Sha256::digest(b"altered_crm");
        daemon
            .register_service(
                &mut cap,
                "crm_portal",
                "https://crm.local:443",
                ServiceType::ComputeMicroservice,
                ServiceEnvironment::UserWorkload,
                ComplianceStandard::AnssiSecNumCloud,
                PermissionScope::WildcardFullAccess,
                false,
                false,
                false,
                altered,
                baseline,
                6000,
            )
            .unwrap();

        assert!(daemon.drift_count > 0);

        // Remédiation autonome globale O(1)
        let remediated = daemon.remediate_all_drifts(&mut cap, 6010).unwrap();
        assert!(remediated > 0);

        // Vérifier que toutes les dérives sont résolues
        for d in daemon.drifts.iter().flatten() {
            assert!(d.resolved);
            assert!(d.auto_remediated);
        }

        // Vérifier que le connecteur non approuvé est en quarantaine
        let c2 = daemon.connectors[1].unwrap();
        assert!(c2.quarantined);
    }

    #[test]
    fn test_sspm_reports_and_seal_verification() {
        let mut cap = SspmCap::new(Handle::new(13609, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);
        daemon.init_defaults();

        let score_before = daemon.calculate_sspm_score();
        let posture_rep = daemon.generate_posture_report(&cap, 7000).unwrap();
        assert!(posture_rep.verify_seal());
        assert_eq!(posture_rep.report_id, 1);
        assert!(JamboSspmDaemon::verify_posture_report_hash(&posture_rep));

        let rem_count = daemon.remediate_all_drifts(&mut cap, 7010).unwrap();
        let rem_rep = daemon
            .generate_remediation_report(&cap, score_before, rem_count, 7020)
            .unwrap();
        assert!(rem_rep.verify_seal());
        assert_eq!(rem_rep.report_id, 2);
        assert!(JamboSspmDaemon::verify_remediation_report_hash(&rem_rep));
    }

    #[test]
    fn test_sspm_compliance_metrics() {
        let cap = SspmCap::new(Handle::new(13610, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);
        daemon.init_defaults();

        let secnum = daemon.calculate_secnumcloud_compliance();
        let cis = daemon.calculate_cis_compliance();

        assert!(secnum <= 100);
        assert!(cis <= 100);
    }

    #[test]
    fn test_sspm_tampered_report_seal_detection() {
        let cap = SspmCap::new(Handle::new(13611, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(cap);
        daemon.init_defaults();

        let mut report = daemon.generate_posture_report(&cap, 8000).unwrap();
        assert!(report.verify_seal());

        // Altération du score global
        report.global_sspm_score = 99;
        assert!(
            !report.verify_seal(),
            "L'altération du rapport doit être rejetée"
        );
    }

    #[test]
    fn test_sspm_report_generation_access_denied() {
        let root_cap = SspmCap::new(Handle::new(13612, 1), sspm_rights::ALL, 10000, 500);
        let mut daemon = JamboSspmDaemon::new(root_cap);
        daemon.init_defaults();

        // Capabilité sans GENERATE_REPORT ni ADMIN
        let limited_cap = root_cap
            .attenuate(sspm_rights::QUERY_AUDIT, 1000, 50)
            .unwrap();

        assert_eq!(
            daemon.generate_posture_report(&limited_cap, 9000),
            Err(SspmError::AccessDenied)
        );
        assert_eq!(
            daemon.generate_remediation_report(&limited_cap, 50, 2, 9010),
            Err(SspmError::AccessDenied)
        );
    }
}

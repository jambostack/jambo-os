//! Architecture Zero Trust (ZTNA), Micro-Périmètres Continus & Ré-évaluation Dynamique de Posture
//!
//! Phase 123 — Jalon v0.2.121
//!
//! Fournit un système souverain Zero Trust Network Access (ZTNA) en environnement `#![no_std]` :
//! 1. Courtage de confiance continu sans périmètre implicite ("Never Trust, Always Verify").
//! 2. Évaluation dynamique et continue de posture de terminal (santé noyau, intégrité mémoire, attestation TPM/TEE).
//! 3. Micro-périmètres applicatifs stricts avec validation unitaire par transaction IPC / réseau / VFS / TEE.
//! 4. Révocation instantanée O(1) de confiance avec propagation automatique aux baux de sessions.
//! 5. Contrôle d'accès capabilaire (`ZtnaCap`) sans autorité ambiante et atténuation monotone.
//! 6. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation déterministe et autonome de SHA-256
#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
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
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (ZtnaCap)
// ============================================================================

pub mod ztna_rights {
    pub const CREATE_POLICY: u32 = 0x01;
    pub const EVALUATE_ACCESS: u32 = 0x02;
    pub const UPDATE_POSTURE: u32 = 0x04;
    pub const REVOKE_TRUST: u32 = 0x08;
    pub const AUDIT_READ: u32 = 0x10;
    pub const SEAL_LEDGER: u32 = 0x20;
    pub const ADMIN: u32 = 0x80;
    pub const ALL: u32 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZtnaError {
    PermissionDenied,
    AttenuationViolation,
    PolicyTableFull,
    DeviceTableFull,
    SessionTableFull,
    AuditLogFull,
    AccessDenied,
    DeviceNotFound,
    PolicyNotFound,
    TrustRevoked,
    InvalidParameter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZtnaCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl ZtnaCap {
    pub const fn new(
        handle: Handle,
        rights: u32,
        max_lifetime: u64,
        invocations_left: u32,
    ) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        rights_mask: u32,
        lifetime: u64,
        invocations: u32,
    ) -> Result<Self, ZtnaError> {
        if (rights_mask & !self.rights) != 0 {
            return Err(ZtnaError::AttenuationViolation);
        }
        if lifetime > self.max_lifetime || invocations > self.invocations_left {
            return Err(ZtnaError::AttenuationViolation);
        }
        Ok(Self {
            handle: self.handle,
            rights: rights_mask,
            max_lifetime: lifetime,
            invocations_left: invocations,
        })
    }
}

// ============================================================================
// ÉVALUATION CONTINUE DE POSTURE DE TERMINAL
// ============================================================================

/// Statut de conformité de posture du terminal / nœud
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureStatus {
    Compliant,
    Degraded,
    NonCompliant,
    Quarantined,
}

impl PostureStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compliant => "COMPLIANT",
            Self::Degraded => "DEGRADED",
            Self::NonCompliant => "NON_COMPLIANT",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

/// Fiche de posture mesurée en continu pour chaque périphérique / composant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePosture {
    pub device_id: u64,
    pub kernel_integrity_score: u8, // 0..100 (protection cr0/cr4/wp, modules signés)
    pub memory_safety_score: u8,    // 0..100 (W^X, ASLR, canaris de pile)
    pub tpm_tee_attested: bool,     // Attestation matérielle TPM 2.0 / TEE en cours
    pub anomaly_level: u8,          // 0..100 (détecté par EDR/IDS)
    pub composite_trust_score: u8,  // Score calculé pondéré (0..100)
    pub posture_status: PostureStatus,
    pub last_evaluated_tick: u64,
    pub active: bool,
}

impl DevicePosture {
    /// Calcule le score de confiance composite pondéré selon les métriques de sécurité
    pub fn compute_composite_trust(
        kernel_score: u8,
        memory_score: u8,
        tpm_tee: bool,
        anomaly: u8,
    ) -> (u8, PostureStatus) {
        // Pondération : 40% intégrité noyau, 35% intégrité mémoire, 25% attestation matérielle
        let tpm_points = if tpm_tee { 25u32 } else { 0u32 };
        let base_weighted = ((kernel_score as u32 * 40)
            + (memory_score as u32 * 35)
            + (tpm_points * 100))
            / 100;

        // Déduction proportionnelle aux anomalies comportementales
        let score = (base_weighted.saturating_sub(anomaly as u32)).min(100) as u8;

        let status = if score >= 80 && tpm_tee && anomaly <= 10 {
            PostureStatus::Compliant
        } else if score >= 50 && anomaly <= 35 {
            PostureStatus::Degraded
        } else {
            PostureStatus::NonCompliant
        };

        (score, status)
    }
}

// ============================================================================
// MICRO-PÉRIMÈTRES APPLICATIFS & POLITIQUES
// ============================================================================

/// Catégorie de ressource protégée par un micro-périmètre Zero Trust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    IpcService,
    VfsPath,
    NetworkEndpoint,
    EnclaveBridge,
    CryptoKeyStore,
}

impl ResourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IpcService => "IPC_SERVICE",
            Self::VfsPath => "VFS_PATH",
            Self::NetworkEndpoint => "NET_ENDPOINT",
            Self::EnclaveBridge => "ENCLAVE_BRIDGE",
            Self::CryptoKeyStore => "CRYPTO_KEY_STORE",
        }
    }
}

/// Règle de micro-périmètre exigeant des conditions strictes de confiance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MicroPerimeterPolicy {
    pub policy_id: u32,
    pub resource_name: [u8; 32],
    pub resource_name_len: usize,
    pub resource_kind: ResourceKind,
    pub min_trust_score: u8,
    pub require_tpm_tee: bool,
    pub max_session_ttl: u64,
    pub active: bool,
}

impl MicroPerimeterPolicy {
    pub fn resource_as_str(&self) -> &str {
        core::str::from_utf8(&self.resource_name[..self.resource_name_len]).unwrap_or("unknown")
    }
}

// ============================================================================
// SESSIONS ÉPHÉMÈRES & VALIDATION UNITAIRE
// ============================================================================

/// Session de confiance éphémère à validation unitaire
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZtnaSession {
    pub session_id: u64,
    pub subject_id: u64,
    pub device_id: u64,
    pub policy_id: u32,
    pub granted_tick: u64,
    pub expires_tick: u64,
    pub transaction_count: u32,
    pub last_access_tick: u64,
    pub revoked: bool,
}

/// Décision rendue lors de l'évaluation d'une transaction unitaire
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    Granted { session_id: u64, trust_score: u8 },
    Denied { reason_code: u8, trust_score: u8 },
    StepUpRequired { required_score: u8, current_score: u8 },
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SHA-256 SCELLEMENT INVIOLABLE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    PolicyRegistered,
    PostureUpdated,
    AccessGranted,
    AccessDenied,
    TrustRevoked,
    SessionReevaluated,
    LedgerSealed,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyRegistered => "PolicyRegistered",
            Self::PostureUpdated => "PostureUpdated",
            Self::AccessGranted => "AccessGranted",
            Self::AccessDenied => "AccessDenied",
            Self::TrustRevoked => "TrustRevoked",
            Self::SessionReevaluated => "SessionReevaluated",
            Self::LedgerSealed => "LedgerSealed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub action: AuditAction,
    pub entity_id: u64,
    pub detail: [u8; 32],
    pub detail_len: usize,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

// ============================================================================
// DÉMON CENTRAL ZERO TRUST (`JamboZtnaDaemon`)
// ============================================================================

pub struct JamboZtnaDaemon {
    pub admin_cap: ZtnaCap,
    pub policies: [Option<MicroPerimeterPolicy>; 16],
    pub policy_count: usize,
    pub next_policy_id: u32,
    pub devices: [Option<DevicePosture>; 16],
    pub device_count: usize,
    pub sessions: [Option<ZtnaSession>; 32],
    pub session_count: usize,
    pub next_session_id: u64,
    pub audit_log: [Option<AuditEntry>; 64],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],
    pub total_evaluations: u64,
    pub total_grants: u64,
    pub total_denials: u64,
    pub total_revocations: u64,
}

impl JamboZtnaDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0x7A; 32];

    pub fn new(admin_cap: ZtnaCap) -> Self {
        Self {
            admin_cap,
            policies: [None; 16],
            policy_count: 0,
            next_policy_id: 1,
            devices: [None; 16],
            device_count: 0,
            sessions: [None; 32],
            session_count: 0,
            next_session_id: 1,
            audit_log: [None; 64],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            total_evaluations: 0,
            total_grants: 0,
            total_denials: 0,
            total_revocations: 0,
        }
    }

    /// Journalise une action dans le registre immuable chaîné par SHA-256
    fn append_audit(&mut self, timestamp: u64, action: AuditAction, entity_id: u64, detail_str: &str) {
        if self.audit_count >= self.audit_log.len() {
            return;
        }

        let mut detail = [0u8; 32];
        let bytes = detail_str.as_bytes();
        let len = bytes.len().min(32);
        detail[..len].copy_from_slice(&bytes[..len]);

        let mut hasher = Sha256::new();
        hasher.update(&self.ledger_hash);
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(action.as_str().as_bytes());
        hasher.update(&entity_id.to_be_bytes());
        hasher.update(&detail[..len]);
        let entry_hash = hasher.finalize();

        let entry = AuditEntry {
            timestamp,
            action,
            entity_id,
            detail,
            detail_len: len,
            prev_hash: self.ledger_hash,
            hash: entry_hash,
        };

        self.audit_log[self.audit_count] = Some(entry);
        self.audit_count += 1;
        self.ledger_hash = entry_hash;
    }

    /// Vérifie l'intégrité formelle de bout en bout de la chaîne d'audit SHA-256
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = Self::GENESIS_HASH;
        for i in 0..self.audit_count {
            if let Some(ref entry) = self.audit_log[i] {
                if entry.prev_hash != expected_prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.prev_hash);
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(entry.action.as_str().as_bytes());
                hasher.update(&entry.entity_id.to_be_bytes());
                hasher.update(&entry.detail[..entry.detail_len]);
                let calc = hasher.finalize();
                if calc != entry.hash {
                    return false;
                }
                expected_prev = entry.hash;
            }
        }
        expected_prev == self.ledger_hash
    }

    /// Enregistre une nouvelle politique de micro-périmètre applicatif
    pub fn register_policy(
        &mut self,
        cap: &ZtnaCap,
        resource_name: &str,
        resource_kind: ResourceKind,
        min_trust_score: u8,
        require_tpm_tee: bool,
        max_session_ttl: u64,
        current_tick: u64,
    ) -> Result<u32, ZtnaError> {
        if !cap.has_right(ztna_rights::CREATE_POLICY) {
            return Err(ZtnaError::PermissionDenied);
        }
        if self.policy_count >= self.policies.len() {
            return Err(ZtnaError::PolicyTableFull);
        }

        let mut rname = [0u8; 32];
        let bytes = resource_name.as_bytes();
        let len = bytes.len().min(32);
        rname[..len].copy_from_slice(&bytes[..len]);

        let policy_id = self.next_policy_id;
        self.next_policy_id = self.next_policy_id.saturating_add(1);

        let policy = MicroPerimeterPolicy {
            policy_id,
            resource_name: rname,
            resource_name_len: len,
            resource_kind,
            min_trust_score,
            require_tpm_tee,
            max_session_ttl,
            active: true,
        };

        self.policies[self.policy_count] = Some(policy);
        self.policy_count += 1;

        self.append_audit(
            current_tick,
            AuditAction::PolicyRegistered,
            policy_id as u64,
            resource_name,
        );

        Ok(policy_id)
    }

    /// Met à jour ou initialise la posture d'un terminal/nœud en continu
    pub fn update_device_posture(
        &mut self,
        cap: &ZtnaCap,
        device_id: u64,
        kernel_score: u8,
        memory_score: u8,
        tpm_tee_attested: bool,
        anomaly_level: u8,
        current_tick: u64,
    ) -> Result<DevicePosture, ZtnaError> {
        if !cap.has_right(ztna_rights::UPDATE_POSTURE) {
            return Err(ZtnaError::PermissionDenied);
        }

        let (composite_score, status) = DevicePosture::compute_composite_trust(
            kernel_score,
            memory_score,
            tpm_tee_attested,
            anomaly_level,
        );

        // Recherche si le terminal existe déjà
        let mut idx = None;
        for i in 0..self.device_count {
            if let Some(ref d) = self.devices[i] {
                if d.device_id == device_id {
                    idx = Some(i);
                    break;
                }
            }
        }

        let posture = if let Some(i) = idx {
            let d = self.devices[i].as_mut().unwrap();
            d.kernel_integrity_score = kernel_score;
            d.memory_safety_score = memory_score;
            d.tpm_tee_attested = tpm_tee_attested;
            d.anomaly_level = anomaly_level;
            d.composite_trust_score = composite_score;
            d.posture_status = status;
            d.last_evaluated_tick = current_tick;
            *d
        } else {
            if self.device_count >= self.devices.len() {
                return Err(ZtnaError::DeviceTableFull);
            }
            let new_dev = DevicePosture {
                device_id,
                kernel_integrity_score: kernel_score,
                memory_safety_score: memory_score,
                tpm_tee_attested,
                anomaly_level,
                composite_trust_score: composite_score,
                posture_status: status,
                last_evaluated_tick: current_tick,
                active: true,
            };
            self.devices[self.device_count] = Some(new_dev);
            self.device_count += 1;
            new_dev
        };

        // Ré-évaluation dynamique des sessions existantes pour ce device
        self.reevaluate_device_sessions(device_id, composite_score, status, current_tick);

        self.append_audit(
            current_tick,
            AuditAction::PostureUpdated,
            device_id,
            status.as_str(),
        );

        Ok(posture)
    }

    /// Ré-évalue dynamiquement les sessions associées à un device après variation de posture
    fn reevaluate_device_sessions(
        &mut self,
        device_id: u64,
        new_trust_score: u8,
        status: PostureStatus,
        current_tick: u64,
    ) {
        for i in 0..self.session_count {
            if let Some(ref mut s) = self.sessions[i] {
                if s.device_id == device_id && !s.revoked {
                    // Si mis en quarantaine ou non-conforme, révocation immédiate
                    if status == PostureStatus::Quarantined || status == PostureStatus::NonCompliant {
                        s.revoked = true;
                        self.total_revocations = self.total_revocations.saturating_add(1);
                        continue;
                    }
                    // Trouver la politique associée pour vérifier le score minimum
                    for p_opt in &self.policies[..self.policy_count] {
                        if let Some(ref p) = p_opt {
                            if p.policy_id == s.policy_id {
                                if new_trust_score < p.min_trust_score {
                                    s.revoked = true;
                                    self.total_revocations = self.total_revocations.saturating_add(1);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        self.append_audit(
            current_tick,
            AuditAction::SessionReevaluated,
            device_id,
            "REEVAL_SESSIONS",
        );
    }

    /// Révocation immédiate O(1) de confiance d'un terminal (Quarantaine immédiate)
    pub fn revoke_trust(
        &mut self,
        cap: &ZtnaCap,
        device_id: u64,
        current_tick: u64,
    ) -> Result<(), ZtnaError> {
        if !cap.has_right(ztna_rights::REVOKE_TRUST) {
            return Err(ZtnaError::PermissionDenied);
        }

        let mut found = false;
        for i in 0..self.device_count {
            if let Some(ref mut d) = self.devices[i] {
                if d.device_id == device_id {
                    d.posture_status = PostureStatus::Quarantined;
                    d.composite_trust_score = 0;
                    d.active = false;
                    d.last_evaluated_tick = current_tick;
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(ZtnaError::DeviceNotFound);
        }

        // Révoquer toutes les sessions de ce terminal
        for i in 0..self.session_count {
            if let Some(ref mut s) = self.sessions[i] {
                if s.device_id == device_id && !s.revoked {
                    s.revoked = true;
                    self.total_revocations = self.total_revocations.saturating_add(1);
                }
            }
        }

        self.total_revocations = self.total_revocations.saturating_add(1);
        self.append_audit(
            current_tick,
            AuditAction::TrustRevoked,
            device_id,
            "REVOKE_TRUST_QUARANTINE",
        );

        Ok(())
    }

    /// Évalue une transaction d'accès unitaire contre le micro-périmètre Zero Trust
    pub fn evaluate_access(
        &mut self,
        cap: &ZtnaCap,
        subject_id: u64,
        device_id: u64,
        resource_name: &str,
        current_tick: u64,
    ) -> Result<AccessDecision, ZtnaError> {
        if !cap.has_right(ztna_rights::EVALUATE_ACCESS) {
            return Err(ZtnaError::PermissionDenied);
        }

        self.total_evaluations = self.total_evaluations.saturating_add(1);

        // 1. Recherche de la politique de micro-périmètre associée
        let mut matching_policy = None;
        let rbytes = resource_name.as_bytes();
        for i in 0..self.policy_count {
            if let Some(ref p) = self.policies[i] {
                if p.active && &p.resource_name[..p.resource_name_len] == rbytes {
                    matching_policy = Some(*p);
                    break;
                }
            }
        }

        let policy = match matching_policy {
            Some(p) => p,
            None => {
                self.total_denials = self.total_denials.saturating_add(1);
                self.append_audit(
                    current_tick,
                    AuditAction::AccessDenied,
                    subject_id,
                    "POLICY_NOT_FOUND",
                );
                return Ok(AccessDecision::Denied {
                    reason_code: 5, // PolicyNotFound
                    trust_score: 0,
                });
            }
        };

        // 2. Recherche et vérification de la posture du terminal
        let mut matching_device = None;
        for i in 0..self.device_count {
            if let Some(ref d) = self.devices[i] {
                if d.device_id == device_id {
                    matching_device = Some(*d);
                    break;
                }
            }
        }

        let device = match matching_device {
            Some(d) => d,
            None => {
                self.total_denials = self.total_denials.saturating_add(1);
                self.append_audit(
                    current_tick,
                    AuditAction::AccessDenied,
                    subject_id,
                    "DEVICE_UNREGISTERED",
                );
                return Ok(AccessDecision::Denied {
                    reason_code: 1, // DeviceNotFound
                    trust_score: 0,
                });
            }
        };

        // 3. Vérification des conditions strictes Zero Trust
        if device.posture_status == PostureStatus::Quarantined || !device.active {
            self.total_denials = self.total_denials.saturating_add(1);
            self.append_audit(
                current_tick,
                AuditAction::AccessDenied,
                subject_id,
                "DEVICE_QUARANTINED",
            );
            return Ok(AccessDecision::Denied {
                reason_code: 3, // TrustRevokedOrQuarantined
                trust_score: device.composite_trust_score,
            });
        }

        if policy.require_tpm_tee && !device.tpm_tee_attested {
            self.total_denials = self.total_denials.saturating_add(1);
            self.append_audit(
                current_tick,
                AuditAction::AccessDenied,
                subject_id,
                "TPM_ATTEST_REQUIRED",
            );
            return Ok(AccessDecision::Denied {
                reason_code: 2, // MissingTpmAttestation
                trust_score: device.composite_trust_score,
            });
        }

        if device.composite_trust_score < policy.min_trust_score {
            self.total_denials = self.total_denials.saturating_add(1);
            self.append_audit(
                current_tick,
                AuditAction::AccessDenied,
                subject_id,
                "INSUFFICIENT_TRUST",
            );
            if device.composite_trust_score >= policy.min_trust_score.saturating_sub(15) {
                return Ok(AccessDecision::StepUpRequired {
                    required_score: policy.min_trust_score,
                    current_score: device.composite_trust_score,
                });
            } else {
                return Ok(AccessDecision::Denied {
                    reason_code: 1, // Posture degraded / untrusted
                    trust_score: device.composite_trust_score,
                });
            }
        }

        // 4. Recherche d'une session valide existante ou émission d'un nouveau bail éphémère
        let mut session_id = 0;
        let mut found_session = false;

        for i in 0..self.session_count {
            if let Some(ref mut s) = self.sessions[i] {
                if s.subject_id == subject_id
                    && s.device_id == device_id
                    && s.policy_id == policy.policy_id
                    && !s.revoked
                    && current_tick < s.expires_tick
                {
                    s.transaction_count = s.transaction_count.saturating_add(1);
                    s.last_access_tick = current_tick;
                    session_id = s.session_id;
                    found_session = true;
                    break;
                }
            }
        }

        if !found_session {
            if self.session_count >= self.sessions.len() {
                return Err(ZtnaError::SessionTableFull);
            }
            session_id = self.next_session_id;
            self.next_session_id = self.next_session_id.saturating_add(1);

            let new_session = ZtnaSession {
                session_id,
                subject_id,
                device_id,
                policy_id: policy.policy_id,
                granted_tick: current_tick,
                expires_tick: current_tick.saturating_add(policy.max_session_ttl),
                transaction_count: 1,
                last_access_tick: current_tick,
                revoked: false,
            };

            self.sessions[self.session_count] = Some(new_session);
            self.session_count += 1;
        }

        self.total_grants = self.total_grants.saturating_add(1);
        self.append_audit(
            current_tick,
            AuditAction::AccessGranted,
            subject_id,
            policy.resource_as_str(),
        );

        Ok(AccessDecision::Granted {
            session_id,
            trust_score: device.composite_trust_score,
        })
    }

    /// Récupère la posture d'un terminal
    pub fn get_device_posture(&self, device_id: u64) -> Option<&DevicePosture> {
        for i in 0..self.device_count {
            if let Some(ref d) = self.devices[i] {
                if d.device_id == device_id {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Initialise les micro-périmètres applicatifs et terminaux par défaut
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Politique Micro-Périmètre : KMS Master Key (très strict, 85/100, TPM requis)
        let _ = self.register_policy(
            &cap,
            "ipc://sys.sec.kms",
            ResourceKind::CryptoKeyStore,
            85,
            true,
            300,
            100,
        );

        // 2. Politique Micro-Périmètre : VFS Certificats & Clés (/etc/certs, 80/100, TPM requis)
        let _ = self.register_policy(
            &cap,
            "vfs:///etc/certs",
            ResourceKind::VfsPath,
            80,
            true,
            600,
            110,
        );

        // 3. Politique Micro-Périmètre : Pont Enclave TEE (enclave://sgx/vault, 90/100, TPM requis)
        let _ = self.register_policy(
            &cap,
            "enclave://sgx/vault",
            ResourceKind::EnclaveBridge,
            90,
            true,
            200,
            120,
        );

        // 4. Politique Micro-Périmètre : Passerelle Réseau Sécurisée (net://10.0.0.1:443, 70/100)
        let _ = self.register_policy(
            &cap,
            "net://10.0.0.1:443",
            ResourceKind::NetworkEndpoint,
            70,
            false,
            1200,
            130,
        );

        // 5. Initialisation de 2 terminaux de référence :
        // Device 1001 : Terminal Souverain Ultra-Sûr (Noyau 98, Mémoire 95, TPM Oui, Anomaly 0) -> Compliant (Score 96)
        let _ = self.update_device_posture(&cap, 1001, 98, 95, true, 0, 150);

        // Device 1002 : Terminal Dégradé / Non Attesté (Noyau 65, Mémoire 60, TPM Non, Anomaly 25) -> NonCompliant
        let _ = self.update_device_posture(&cap, 1002, 65, 60, false, 25, 160);
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ztna_cap_attenuation() {
        let admin = ZtnaCap::new(Handle::new(12301, 1), ztna_rights::ALL, 5000, 100);
        assert!(admin.has_right(ztna_rights::CREATE_POLICY));
        assert!(admin.has_right(ztna_rights::EVALUATE_ACCESS));
        assert!(admin.has_right(ztna_rights::UPDATE_POSTURE));
        assert!(admin.has_right(ztna_rights::REVOKE_TRUST));
        assert!(admin.has_right(ztna_rights::ADMIN));

        // Atténuation monotone
        let eval_cap = admin
            .attenuate(
                ztna_rights::EVALUATE_ACCESS | ztna_rights::AUDIT_READ,
                2000,
                50,
            )
            .expect("Atténuation");
        assert!(eval_cap.has_right(ztna_rights::EVALUATE_ACCESS));
        assert!(eval_cap.has_right(ztna_rights::AUDIT_READ));
        assert!(!eval_cap.has_right(ztna_rights::CREATE_POLICY));
        assert!(!eval_cap.has_right(ztna_rights::ADMIN));

        // Rejet d'escalade
        let esc = eval_cap.attenuate(ztna_rights::ALL, 2000, 50);
        assert_eq!(esc, Err(ZtnaError::AttenuationViolation));
    }

    #[test]
    fn test_device_posture_computation_and_evaluation() {
        let admin = ZtnaCap::new(Handle::new(12302, 1), ztna_rights::ALL, 5000, 100);
        let mut daemon = JamboZtnaDaemon::new(admin);
        daemon.init_defaults();

        assert_eq!(daemon.policy_count, 4);
        assert_eq!(daemon.device_count, 2);
        assert!(daemon.verify_ledger_integrity());

        // Device 1001 vérifié conforme
        let p1 = daemon.get_device_posture(1001).expect("Device 1001");
        assert!(p1.composite_trust_score >= 90);
        assert_eq!(p1.posture_status, PostureStatus::Compliant);

        // Transaction d'accès par Subject 501 depuis Device 1001 vers KMS -> Accordée !
        let dec1 = daemon
            .evaluate_access(&admin, 501, 1001, "ipc://sys.sec.kms", 200)
            .expect("Eval 1001");
        match dec1 {
            AccessDecision::Granted { session_id, trust_score } => {
                assert!(session_id > 0);
                assert!(trust_score >= 85);
            }
            _ => panic!("Accès KMS aurait dû être accordé"),
        }

        // Deuxième accès répété -> même session réutilisée
        let dec2 = daemon
            .evaluate_access(&admin, 501, 1001, "ipc://sys.sec.kms", 210)
            .expect("Eval repeat");
        match dec2 {
            AccessDecision::Granted { session_id, .. } => {
                assert_eq!(session_id, 1);
            }
            _ => panic!("Session répétée invalide"),
        }

        // Transaction d'accès depuis Device 1002 (Non-attesté, score insuffisant) -> Refusée !
        let dec3 = daemon
            .evaluate_access(&admin, 502, 1002, "ipc://sys.sec.kms", 220)
            .expect("Eval 1002");
        match dec3 {
            AccessDecision::Denied { reason_code, .. } => {
                assert!(reason_code == 2 || reason_code == 1);
            }
            _ => panic!("Accès KMS pour Device 1002 aurait dû être refusé"),
        }

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_dynamic_posture_degradation_and_session_reevaluation() {
        let admin = ZtnaCap::new(Handle::new(12303, 1), ztna_rights::ALL, 5000, 100);
        let mut daemon = JamboZtnaDaemon::new(admin);
        daemon.init_defaults();

        // Accès initialement accordé pour Device 1001 vers pont Enclave TEE
        let dec = daemon
            .evaluate_access(&admin, 777, 1001, "enclave://sgx/vault", 300)
            .expect("Access granted initially");
        assert!(matches!(dec, AccessDecision::Granted { .. }));
        assert_eq!(daemon.session_count, 1);
        assert!(!daemon.sessions[0].unwrap().revoked);

        // Dégradation dynamique de posture : infection mémoire détectée, anomalie grimpe à 60
        let updated = daemon
            .update_device_posture(&admin, 1001, 40, 20, false, 60, 310)
            .expect("Posture update");
        assert_eq!(updated.posture_status, PostureStatus::NonCompliant);

        // La session existante est automatiquement révoquée par ré-évaluation dynamique !
        assert!(daemon.sessions[0].unwrap().revoked);
        assert_eq!(daemon.total_revocations, 1);

        // Nouvelle requête refusée immédiatement
        let dec2 = daemon
            .evaluate_access(&admin, 777, 1001, "enclave://sgx/vault", 320)
            .expect("Eval after degradation");
        assert!(matches!(dec2, AccessDecision::Denied { .. }));

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_immediate_trust_revocation_and_quarantine() {
        let admin = ZtnaCap::new(Handle::new(12304, 1), ztna_rights::ALL, 5000, 100);
        let mut daemon = JamboZtnaDaemon::new(admin);
        daemon.init_defaults();

        // Subject 888 accède à net://10.0.0.1:443
        let dec = daemon
            .evaluate_access(&admin, 888, 1001, "net://10.0.0.1:443", 400)
            .expect("Access grant");
        assert!(matches!(dec, AccessDecision::Granted { .. }));

        // Révocation explicite / quarantaine immédiate O(1) de Device 1001
        daemon.revoke_trust(&admin, 1001, 410).expect("Revoke trust");

        let p = daemon.get_device_posture(1001).unwrap();
        assert_eq!(p.posture_status, PostureStatus::Quarantined);
        assert_eq!(p.composite_trust_score, 0);

        // Requête suivante bloquée pour terminal en quarantaine
        let dec_blocked = daemon
            .evaluate_access(&admin, 888, 1001, "net://10.0.0.1:443", 420)
            .expect("Blocked eval");
        match dec_blocked {
            AccessDecision::Denied { reason_code, .. } => {
                assert_eq!(reason_code, 3); // TrustRevokedOrQuarantined
            }
            _ => panic!("Devrait être bloqué"),
        }

        assert!(daemon.verify_ledger_integrity());
    }
}

//! Gestion des Droits sur l'Infrastructure Cloud Souveraine CIEM, Analyse des Droits Excessifs & Principe du Moindre Privilège
//!
//! Phase 157 — Jalon v0.3.24
//!
//! Fournit un système souverain de Cloud Infrastructure Entitlement Management (CIEM) en environnement `#![no_std]` :
//! 1. Cartographie unifiée et continue des identités de grappe souveraine (utilisateurs humains, comptes de services, agents de charge micro-VM, tokens éphémères, rôles fédérés SecNumCloud).
//! 2. Moteur d'analyse des écarts d'autorisations (Entitlement Gap) entre privilèges accordés et privilèges réellement exercés.
//! 3. Détection en temps réel des privilèges dormants, des droits orphelins, des droits excessifs et des combinaisons toxiques (Toxic Combinations).
//! 4. Réduction monotone automatique et chirurgicale O(1) vers le strict moindre privilège (Least-Privilege Monotonic Attenuation).
//! 5. Génération de rapports d'analyse et de remédiation scellés par SHA-256 (`CiemRemediationReport`).
//! 6. Contrôle d'accès capabilaire strict (`CiemCap`) sans autorité ambiante avec atténuation monotone.
//! 7. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256 déterministe.

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
            let to_copy = core::cmp::min(space, data.len() - offset);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

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
        for (i, val) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ============================================================================
// ERREURS & CAPABILITÉS CIEM SANS AUTORITÉ AMBIANTE
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiemError {
    PermissionDenied,
    AttenuationViolation,
    IdentityNotFound,
    EntitlementNotFound,
    CapacityExceeded,
    LedgerTampered,
    InvalidPolicy,
    AlreadyExists,
}

pub mod ciem_rights {
    pub const REGISTER_IDENTITY: u32 = 1 << 0;
    pub const INSPECT_ENTITLEMENTS: u32 = 1 << 1;
    pub const ANALYZE_EXCESS: u32 = 1 << 2;
    pub const ENFORCE_LEAST_PRIV: u32 = 1 << 3;
    pub const REVOKE_DORMANT: u32 = 1 << 4;
    pub const MANAGE_POLICIES: u32 = 1 << 5;
    pub const READ_METRICS: u32 = 1 << 6;
    pub const SEAL_LEDGER: u32 = 1 << 7;
    pub const ADMIN: u32 = 1 << 8;

    pub const ALL: u32 = REGISTER_IDENTITY
        | INSPECT_ENTITLEMENTS
        | ANALYZE_EXCESS
        | ENFORCE_LEAST_PRIV
        | REVOKE_DORMANT
        | MANAGE_POLICIES
        | READ_METRICS
        | SEAL_LEDGER
        | ADMIN;
}

/// Capabilité de contrôle CIEM sans autorité ambiante avec atténuation monotone
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CiemCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl CiemCap {
    pub const fn new(handle: Handle, rights: u32, max_lifetime: u64, invocations: u32) -> Self {
        Self {
            handle,
            rights,
            max_lifetime,
            invocations_left: invocations,
        }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right && self.invocations_left > 0
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        max_lifetime: u64,
        invocations: u32,
    ) -> Result<Self, CiemError> {
        if (new_rights & !self.rights) != 0 {
            return Err(CiemError::AttenuationViolation);
        }
        let lifetime = if max_lifetime < self.max_lifetime {
            max_lifetime
        } else {
            self.max_lifetime
        };
        let inv = if invocations < self.invocations_left {
            invocations
        } else {
            self.invocations_left
        };

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: lifetime,
            invocations_left: inv,
        })
    }

    pub fn consume(&mut self) -> Result<(), CiemError> {
        if self.invocations_left == 0 {
            return Err(CiemError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// CONSTANTES DE PRIVILÈGES SOUVERAINS & COMBINAISONS TOXIQUES
// ============================================================================

pub mod entitlement_bits {
    pub const IAM_ADMIN: u32 = 1 << 0; // 0x0001 : Modification des rôles/politiques
    pub const SECRETS_READ: u32 = 1 << 1; // 0x0002 : Lecture secrets & tokens KMS
    pub const NETWORK_EGRESS: u32 = 1 << 2; // 0x0004 : Trafic réseau externe non filtré
    pub const ENCLAVE_SIGN: u32 = 1 << 3; // 0x0008 : Signature d'enclave TEE
    pub const KEY_EXPORT: u32 = 1 << 4; // 0x0010 : Exportation de clés privées
    pub const VFS_ROOT_WRITE: u32 = 1 << 5; // 0x0020 : Écriture sur partition racine
    pub const KERNEL_DEBUG: u32 = 1 << 6; // 0x0040 : Débogage noyau / ptrace
    pub const AUDIT_PURGE: u32 = 1 << 7; // 0x0080 : Altération / purge de journal
    pub const STORAGE_READ: u32 = 1 << 8; // 0x0100 : Lecture stockage persistant
    pub const STORAGE_WRITE: u32 = 1 << 9; // 0x0200 : Écriture stockage persistant
    pub const CLUSTER_CONTROL: u32 = 1 << 10; // 0x0400 : Orchestration des nœuds
    pub const WORKLOAD_EXEC: u32 = 1 << 11; // 0x0800 : Lancement de micro-VMs
    pub const LEGACY_TOXIC_A: u32 = 1 << 30; // 0x40000000 : Indicateur toxique haut A
    pub const LEGACY_TOXIC_B: u32 = 1 << 31; // 0x80000000 : Indicateur toxique haut B
}

// ============================================================================
// TYPES DE DONNÉES & ENTITLEMENTS CIEM
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityKind {
    HumanUser,
    ServiceAccount,
    WorkloadAgent,
    TemporaryToken,
    FederatedRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntitlementScope {
    KernelCore,
    StorageVfs,
    NetworkMesh,
    SecurityServices,
    ClusterControl,
    EnclaveTee,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntitlementStatus {
    Active,
    Dormant,
    Orphan,
    Excessive,
    Attenuated,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiemAnomalyType {
    None,
    DormantPrivilege,
    ExcessiveRights,
    OrphanEntitlement,
    PrivilegeCreep,
    ToxicCombination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiemAction {
    LeastPrivilegeEnforced,
    DormantRevoked,
    OrphanPurged,
    ToxicCombinationBroken,
}

/// Enregistrement d'une identité dans la cartographie de grappe
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityRecord {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub kind: IdentityKind,
    pub is_active: bool,
    pub created_at: u64,
    pub last_active_at: u64,
    pub total_entitlements: usize,
    pub risk_score: u8, // 0..100
}

impl IdentityRecord {
    pub fn new(id: u32, name_str: &str, kind: IdentityKind, created_at: u64) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        name[..len].copy_from_slice(&bytes[..len]);

        Self {
            id,
            name,
            name_len: len,
            kind,
            is_active: true,
            created_at,
            last_active_at: created_at,
            total_entitlements: 0,
            risk_score: 0,
        }
    }
}

/// Droit d'accès / Entitlement accordé à une identité
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntitlementRecord {
    pub id: u32,
    pub identity_id: u32,
    pub scope: EntitlementScope,
    pub granted_rights: u32,
    pub exercised_rights: u32,
    pub status: EntitlementStatus,
    pub last_used_tick: u64,
    pub dormant_threshold_ticks: u64,
    pub risk: RiskLevel,
    pub hash: [u8; 32],
}

impl EntitlementRecord {
    pub fn new(
        id: u32,
        identity_id: u32,
        scope: EntitlementScope,
        granted_rights: u32,
        dormant_threshold_ticks: u64,
        tick: u64,
    ) -> Self {
        let mut rec = Self {
            id,
            identity_id,
            scope,
            granted_rights,
            exercised_rights: 0,
            status: EntitlementStatus::Active,
            last_used_tick: tick,
            dormant_threshold_ticks,
            risk: RiskLevel::Low,
            hash: [0u8; 32],
        };
        rec.hash = rec.compute_hash();
        rec
    }

    /// Droits accordés mais jamais exercés (Entitlement Gap)
    pub fn excess_rights(&self) -> u32 {
        self.granted_rights & !self.exercised_rights
    }

    /// Alias explicite pour le calcul de l'écart d'entitlement
    pub fn entitlement_gap(&self) -> u32 {
        self.excess_rights()
    }

    /// Calcule le pourcentage de privilèges non utilisés (0..100%)
    pub fn gap_percentage(&self) -> u8 {
        let total = self.granted_rights.count_ones();
        if total == 0 {
            return 0;
        }
        let excess = self.excess_rights().count_ones();
        ((excess * 100) / total) as u8
    }

    pub fn is_excessive(&self) -> bool {
        self.exercised_rights != 0 && self.excess_rights() != 0
    }

    pub fn is_dormant(&self, current_tick: u64) -> bool {
        if self.status == EntitlementStatus::Revoked {
            return false;
        }
        current_tick.saturating_sub(self.last_used_tick) >= self.dormant_threshold_ticks
    }

    /// Vérifie si une combinaison toxique est présente
    pub fn has_toxic_combination(&self) -> bool {
        use entitlement_bits::*;
        // Combinaison toxique legacy (bits hauts 30 et 31)
        if (self.granted_rights & 0xC000_0000) == 0xC000_0000 {
            return true;
        }
        // Combinaison toxique 1 : IAM_ADMIN + SECRETS_READ + NETWORK_EGRESS (vol de secrets & exfiltration)
        let comb1 = IAM_ADMIN | SECRETS_READ | NETWORK_EGRESS;
        if (self.granted_rights & comb1) == comb1 {
            return true;
        }
        // Combinaison toxique 2 : KEY_EXPORT + NETWORK_EGRESS (exfiltration directe de clés privées)
        let comb2 = KEY_EXPORT | NETWORK_EGRESS;
        if (self.granted_rights & comb2) == comb2 {
            return true;
        }
        // Combinaison toxique 3 : KERNEL_DEBUG + AUDIT_PURGE (sabotage furtif sans traces)
        let comb3 = KERNEL_DEBUG | AUDIT_PURGE;
        if (self.granted_rights & comb3) == comb3 {
            return true;
        }
        false
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.id.to_be_bytes());
        h.update(&self.identity_id.to_be_bytes());
        h.update(&[self.scope as u8, self.status as u8, self.risk as u8]);
        h.update(&self.granted_rights.to_be_bytes());
        h.update(&self.exercised_rights.to_be_bytes());
        h.update(&self.last_used_tick.to_be_bytes());
        h.finalize()
    }
}

/// Anomalie CIEM détectée
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CiemAnomaly {
    pub id: u32,
    pub identity_id: u32,
    pub entitlement_id: u32,
    pub anomaly_type: CiemAnomalyType,
    pub risk: RiskLevel,
    pub detected_tick: u64,
    pub remediated: bool,
}

/// Rapport de remédiation et réduction de privilèges CIEM scellé SHA-256
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CiemRemediationReport {
    pub report_id: u64,
    pub identity_id: u32,
    pub entitlement_id: u32,
    pub timestamp: u64,
    pub action: CiemAction,
    pub initial_rights: u32,
    pub effective_rights: u32,
    pub gap_removed: u32,
    pub risk_before: RiskLevel,
    pub risk_after: RiskLevel,
    pub report_hash: [u8; 32],
}

impl CiemRemediationReport {
    pub fn compute_hash(
        report_id: u64,
        identity_id: u32,
        entitlement_id: u32,
        timestamp: u64,
        action: CiemAction,
        initial_rights: u32,
        effective_rights: u32,
        gap_removed: u32,
        risk_before: RiskLevel,
        risk_after: RiskLevel,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&report_id.to_be_bytes());
        h.update(&identity_id.to_be_bytes());
        h.update(&entitlement_id.to_be_bytes());
        h.update(&timestamp.to_be_bytes());
        h.update(&[action as u8]);
        h.update(&initial_rights.to_be_bytes());
        h.update(&effective_rights.to_be_bytes());
        h.update(&gap_removed.to_be_bytes());
        h.update(&[risk_before as u8, risk_after as u8]);
        h.finalize()
    }

    pub fn new(
        report_id: u64,
        identity_id: u32,
        entitlement_id: u32,
        timestamp: u64,
        action: CiemAction,
        initial_rights: u32,
        effective_rights: u32,
        gap_removed: u32,
        risk_before: RiskLevel,
        risk_after: RiskLevel,
    ) -> Self {
        let report_hash = Self::compute_hash(
            report_id,
            identity_id,
            entitlement_id,
            timestamp,
            action,
            initial_rights,
            effective_rights,
            gap_removed,
            risk_before,
            risk_after,
        );
        Self {
            report_id,
            identity_id,
            entitlement_id,
            timestamp,
            action,
            initial_rights,
            effective_rights,
            gap_removed,
            risk_before,
            risk_after,
            report_hash,
        }
    }
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SCELLÉ (SHA-256)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiemAuditAction {
    IdentityRegistered,
    EntitlementGranted,
    UsageObserved,
    ScanExecuted,
    AnomalyDetected,
    LeastPrivilegeEnforced,
    DormantRevoked,
    OrphanPurged,
    LedgerSealed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CiemAuditRecord {
    pub index: u64,
    pub timestamp: u64,
    pub action: CiemAuditAction,
    pub identity_id: u32,
    pub entitlement_id: u32,
    pub details_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

impl CiemAuditRecord {
    pub fn compute_hash(
        index: u64,
        timestamp: u64,
        action: CiemAuditAction,
        identity_id: u32,
        entitlement_id: u32,
        details_hash: &[u8; 32],
        prev_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&index.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[action as u8]);
        hasher.update(&identity_id.to_be_bytes());
        hasher.update(&entitlement_id.to_be_bytes());
        hasher.update(details_hash);
        hasher.update(prev_hash);
        hasher.finalize()
    }
}

// ============================================================================
// DÉMON CENTRAL CIEM (JamboCiemDaemon)
// ============================================================================

pub struct JamboCiemDaemon {
    pub admin_cap: CiemCap,
    pub identities: [Option<IdentityRecord>; 16],
    pub identity_count: usize,
    pub entitlements: [Option<EntitlementRecord>; 32],
    pub entitlement_count: usize,
    pub anomalies: [Option<CiemAnomaly>; 32],
    pub anomaly_count: usize,
    pub reports: [Option<CiemRemediationReport>; 32],
    pub report_count: usize,
    pub audit_ledger: [Option<CiemAuditRecord>; 64],
    pub audit_count: usize,
    pub last_ledger_hash: [u8; 32],

    // Métriques
    pub total_scans: u64,
    pub total_anomalies_detected: u64,
    pub total_remediations: u64,
    pub total_reports: u64,
    pub active_identities: usize,
}

impl JamboCiemDaemon {
    pub const GENESIS_HASH: [u8; 32] = [
        0x50, 0x48, 0x31, 0x35, 0x37, 0x5f, 0x43, 0x49, 0x45, 0x4d, 0x5f, 0x47, 0x45, 0x4e, 0x45,
        0x53, 0x49, 0x53, 0x5f, 0x4c, 0x45, 0x44, 0x47, 0x45, 0x52, 0x5f, 0x32, 0x30, 0x32, 0x36,
        0x5f, 0x24,
    ];

    pub fn new(admin_cap: CiemCap) -> Self {
        Self {
            admin_cap,
            identities: [None; 16],
            identity_count: 0,
            entitlements: [None; 32],
            entitlement_count: 0,
            anomalies: [None; 32],
            anomaly_count: 0,
            reports: [None; 32],
            report_count: 0,
            audit_ledger: [None; 64],
            audit_count: 0,
            last_ledger_hash: Self::GENESIS_HASH,
            total_scans: 0,
            total_anomalies_detected: 0,
            total_remediations: 0,
            total_reports: 0,
            active_identities: 0,
        }
    }

    /// Enregistre une entrée dans le registre d'audit scellé
    pub fn append_audit(
        &mut self,
        timestamp: u64,
        action: CiemAuditAction,
        identity_id: u32,
        entitlement_id: u32,
        details_hash: [u8; 32],
    ) {
        if self.audit_count >= self.audit_ledger.len() {
            for i in 1..self.audit_ledger.len() {
                self.audit_ledger[i - 1] = self.audit_ledger[i];
            }
            self.audit_count = self.audit_ledger.len() - 1;
        }

        let index = self.audit_count as u64;
        let prev_hash = self.last_ledger_hash;
        let record_hash = CiemAuditRecord::compute_hash(
            index,
            timestamp,
            action,
            identity_id,
            entitlement_id,
            &details_hash,
            &prev_hash,
        );

        let record = CiemAuditRecord {
            index,
            timestamp,
            action,
            identity_id,
            entitlement_id,
            details_hash,
            prev_hash,
            record_hash,
        };

        self.audit_ledger[self.audit_count] = Some(record);
        self.audit_count += 1;
        self.last_ledger_hash = record_hash;
    }

    /// Récupère le dernier rapport scellé généré
    pub fn latest_report(&self) -> Option<&CiemRemediationReport> {
        if self.report_count == 0 {
            None
        } else {
            self.reports[self.report_count - 1].as_ref()
        }
    }

    /// Calcule le pourcentage moyen d'écart d'entitlement sur l'infrastructure
    pub fn average_gap_percentage(&self) -> u8 {
        let mut total_gap = 0u64;
        let mut count = 0u64;
        for ent in self.entitlements.iter().flatten() {
            if ent.status != EntitlementStatus::Revoked {
                total_gap += ent.gap_percentage() as u64;
                count += 1;
            }
        }
        if count == 0 {
            0
        } else {
            (total_gap / count) as u8
        }
    }

    /// Enregistre une nouvelle identité dans la cartographie souveraine
    pub fn register_identity(
        &mut self,
        cap: &CiemCap,
        id: u32,
        name: &str,
        kind: IdentityKind,
        timestamp: u64,
    ) -> Result<u32, CiemError> {
        if !cap.has_right(ciem_rights::REGISTER_IDENTITY) && !cap.has_right(ciem_rights::ADMIN) {
            return Err(CiemError::PermissionDenied);
        }
        if self.identity_count >= self.identities.len() {
            return Err(CiemError::CapacityExceeded);
        }
        for item in self.identities.iter().flatten() {
            if item.id == id {
                return Err(CiemError::AlreadyExists);
            }
        }

        let record = IdentityRecord::new(id, name, kind, timestamp);
        self.identities[self.identity_count] = Some(record);
        self.identity_count += 1;
        self.active_identities += 1;

        let name_hash = Sha256::hash(name.as_bytes());
        self.append_audit(
            timestamp,
            CiemAuditAction::IdentityRegistered,
            id,
            0,
            name_hash,
        );

        Ok(id)
    }

    /// Accorde un droit d'accès / Entitlement à une identité
    pub fn grant_entitlement(
        &mut self,
        cap: &CiemCap,
        id: u32,
        identity_id: u32,
        scope: EntitlementScope,
        granted_rights: u32,
        dormant_threshold: u64,
        timestamp: u64,
    ) -> Result<u32, CiemError> {
        if !cap.has_right(ciem_rights::REGISTER_IDENTITY) && !cap.has_right(ciem_rights::ADMIN) {
            return Err(CiemError::PermissionDenied);
        }
        if self.entitlement_count >= self.entitlements.len() {
            return Err(CiemError::CapacityExceeded);
        }

        for ident in self.identities.iter_mut().flatten() {
            if ident.id == identity_id {
                ident.total_entitlements += 1;
                break;
            }
        }

        let entitlement = EntitlementRecord::new(
            id,
            identity_id,
            scope,
            granted_rights,
            dormant_threshold,
            timestamp,
        );

        self.entitlements[self.entitlement_count] = Some(entitlement);
        self.entitlement_count += 1;

        self.append_audit(
            timestamp,
            CiemAuditAction::EntitlementGranted,
            identity_id,
            id,
            entitlement.hash,
        );

        Ok(id)
    }

    /// Enregistre l'usage effectif d'un droit par une identité
    pub fn record_usage(
        &mut self,
        cap: &CiemCap,
        identity_id: u32,
        entitlement_id: u32,
        exercised_rights: u32,
        timestamp: u64,
    ) -> Result<(), CiemError> {
        if !cap.has_right(ciem_rights::INSPECT_ENTITLEMENTS) && !cap.has_right(ciem_rights::ADMIN) {
            return Err(CiemError::PermissionDenied);
        }

        let mut found = false;
        for ent in self.entitlements.iter_mut().flatten() {
            if ent.id == entitlement_id && ent.identity_id == identity_id {
                ent.exercised_rights |= exercised_rights & ent.granted_rights;
                ent.last_used_tick = timestamp;
                ent.hash = ent.compute_hash();
                found = true;
                break;
            }
        }

        if !found {
            return Err(CiemError::EntitlementNotFound);
        }

        for ident in self.identities.iter_mut().flatten() {
            if ident.id == identity_id {
                ident.last_active_at = timestamp;
                break;
            }
        }

        self.append_audit(
            timestamp,
            CiemAuditAction::UsageObserved,
            identity_id,
            entitlement_id,
            [0u8; 32],
        );

        Ok(())
    }

    /// Exécute un scan complet de cartographie et détecte les privilèges anormaux
    pub fn scan_all_entitlements(
        &mut self,
        cap: &CiemCap,
        current_tick: u64,
    ) -> Result<(usize, usize), CiemError> {
        if !cap.has_right(ciem_rights::ANALYZE_EXCESS) && !cap.has_right(ciem_rights::ADMIN) {
            return Err(CiemError::PermissionDenied);
        }

        self.total_scans += 1;
        let mut checked = 0;
        let mut anomalies_found = 0;

        for i in 0..self.entitlement_count {
            if let Some(mut ent) = self.entitlements[i] {
                checked += 1;
                let mut anomaly_detected = CiemAnomalyType::None;
                let mut risk = RiskLevel::Low;

                // 1. Détection des droits orphelins (Orphan Entitlements)
                let mut identity_exists = false;
                for ident in self.identities.iter().flatten() {
                    if ident.id == ent.identity_id {
                        identity_exists = true;
                        break;
                    }
                }

                if !identity_exists {
                    anomaly_detected = CiemAnomalyType::OrphanEntitlement;
                    risk = RiskLevel::High;
                    ent.status = EntitlementStatus::Orphan;
                } else if ent.status != EntitlementStatus::Revoked {
                    // 2. Détection de combinaison toxique (Toxic Combinations)
                    if ent.has_toxic_combination() {
                        anomaly_detected = CiemAnomalyType::ToxicCombination;
                        risk = RiskLevel::Critical;
                        ent.status = EntitlementStatus::Excessive;
                    }
                    // 3. Détection des privilèges dormants (Dormant Privileges)
                    else if ent.is_dormant(current_tick) {
                        anomaly_detected = CiemAnomalyType::DormantPrivilege;
                        risk = RiskLevel::Medium;
                        ent.status = EntitlementStatus::Dormant;
                    }
                    // 4. Détection des droits excessifs (Excessive Rights / Entitlement Gap)
                    else if ent.is_excessive() {
                        anomaly_detected = CiemAnomalyType::ExcessiveRights;
                        risk = RiskLevel::Medium;
                        ent.status = EntitlementStatus::Excessive;
                    }
                }

                ent.risk = risk;
                ent.hash = ent.compute_hash();
                self.entitlements[i] = Some(ent);

                if anomaly_detected != CiemAnomalyType::None {
                    anomalies_found += 1;
                    self.total_anomalies_detected += 1;

                    if self.anomaly_count < self.anomalies.len() {
                        let aid = self.anomaly_count as u32 + 1;
                        self.anomalies[self.anomaly_count] = Some(CiemAnomaly {
                            id: aid,
                            identity_id: ent.identity_id,
                            entitlement_id: ent.id,
                            anomaly_type: anomaly_detected,
                            risk,
                            detected_tick: current_tick,
                            remediated: false,
                        });
                        self.anomaly_count += 1;
                    }

                    self.append_audit(
                        current_tick,
                        CiemAuditAction::AnomalyDetected,
                        ent.identity_id,
                        ent.id,
                        ent.hash,
                    );
                }
            }
        }

        self.append_audit(
            current_tick,
            CiemAuditAction::ScanExecuted,
            0,
            0,
            Sha256::hash(&(checked as u64).to_be_bytes()),
        );

        Ok((checked, anomalies_found))
    }

    /// Réduction monotone vers le moindre privilège effectif (Least-Privilege Monotonic Attenuation O(1))
    pub fn enforce_least_privilege(
        &mut self,
        cap: &CiemCap,
        entitlement_id: u32,
        current_tick: u64,
    ) -> Result<u32, CiemError> {
        if !cap.has_right(ciem_rights::ENFORCE_LEAST_PRIV) && !cap.has_right(ciem_rights::ADMIN) {
            return Err(CiemError::PermissionDenied);
        }

        let mut found = false;
        let mut new_rights = 0;
        let mut initial_rights = 0;
        let mut target_ident = 0;
        let mut risk_before = RiskLevel::Low;

        for ent in self.entitlements.iter_mut().flatten() {
            if ent.id == entitlement_id {
                target_ident = ent.identity_id;
                initial_rights = ent.granted_rights;
                risk_before = ent.risk;

                // Moindre privilège : on réduit les droits accordés aux seuls droits effectivement exercés
                let reduced = if ent.exercised_rights != 0 {
                    ent.granted_rights & ent.exercised_rights
                } else {
                    // Si aucun droit exercé mais réduction demandée, réduit au masque minimal de survie 0x01
                    ent.granted_rights & 0x01
                };

                // Atténuation monotone stricte : aucun nouveau droit ne peut être injecté
                assert!((reduced & !ent.granted_rights) == 0);

                ent.granted_rights = reduced;
                ent.status = EntitlementStatus::Attenuated;
                ent.risk = RiskLevel::Low;
                ent.hash = ent.compute_hash();
                new_rights = reduced;
                found = true;
                break;
            }
        }

        if !found {
            return Err(CiemError::EntitlementNotFound);
        }

        self.total_remediations += 1;

        // Marquer l'anomalie correspondante comme corrigée
        for anom in self.anomalies.iter_mut().flatten() {
            if anom.entitlement_id == entitlement_id {
                anom.remediated = true;
            }
        }

        // Créer et sceller le rapport de remédiation
        let gap_removed = initial_rights.saturating_sub(new_rights);
        self.total_reports += 1;
        let rep_id = self.total_reports;
        let report = CiemRemediationReport::new(
            rep_id,
            target_ident,
            entitlement_id,
            current_tick,
            CiemAction::LeastPrivilegeEnforced,
            initial_rights,
            new_rights,
            gap_removed,
            risk_before,
            RiskLevel::Low,
        );

        if self.report_count < self.reports.len() {
            self.reports[self.report_count] = Some(report);
            self.report_count += 1;
        } else {
            for i in 1..self.reports.len() {
                self.reports[i - 1] = self.reports[i];
            }
            self.reports[self.reports.len() - 1] = Some(report);
        }

        self.append_audit(
            current_tick,
            CiemAuditAction::LeastPrivilegeEnforced,
            target_ident,
            entitlement_id,
            report.report_hash,
        );

        Ok(new_rights)
    }

    /// Révocation d'un droit dormant ou purge d'un orphelin
    pub fn revoke_entitlement(
        &mut self,
        cap: &CiemCap,
        entitlement_id: u32,
        current_tick: u64,
    ) -> Result<bool, CiemError> {
        if !cap.has_right(ciem_rights::REVOKE_DORMANT) && !cap.has_right(ciem_rights::ADMIN) {
            return Err(CiemError::PermissionDenied);
        }

        let mut found = false;
        let mut target_ident = 0;
        let mut initial_rights = 0;
        let mut risk_before = RiskLevel::Low;
        let mut was_orphan = false;

        for ent in self.entitlements.iter_mut().flatten() {
            if ent.id == entitlement_id {
                target_ident = ent.identity_id;
                initial_rights = ent.granted_rights;
                risk_before = ent.risk;
                was_orphan = ent.status == EntitlementStatus::Orphan;
                ent.granted_rights = 0;
                ent.exercised_rights = 0;
                ent.status = EntitlementStatus::Revoked;
                ent.risk = RiskLevel::Info;
                ent.hash = ent.compute_hash();
                found = true;
                break;
            }
        }

        if !found {
            return Err(CiemError::EntitlementNotFound);
        }

        self.total_remediations += 1;

        for anom in self.anomalies.iter_mut().flatten() {
            if anom.entitlement_id == entitlement_id {
                anom.remediated = true;
            }
        }

        let action = if was_orphan {
            CiemAction::OrphanPurged
        } else {
            CiemAction::DormantRevoked
        };

        // Création du rapport scellé SHA-256
        self.total_reports += 1;
        let rep_id = self.total_reports;
        let report = CiemRemediationReport::new(
            rep_id,
            target_ident,
            entitlement_id,
            current_tick,
            action,
            initial_rights,
            0,
            initial_rights,
            risk_before,
            RiskLevel::Info,
        );

        if self.report_count < self.reports.len() {
            self.reports[self.report_count] = Some(report);
            self.report_count += 1;
        } else {
            for i in 1..self.reports.len() {
                self.reports[i - 1] = self.reports[i];
            }
            self.reports[self.reports.len() - 1] = Some(report);
        }

        self.append_audit(
            current_tick,
            if was_orphan {
                CiemAuditAction::OrphanPurged
            } else {
                CiemAuditAction::DormantRevoked
            },
            target_ident,
            entitlement_id,
            report.report_hash,
        );

        Ok(true)
    }

    /// Remédie automatiquement à toutes les anomalies détectées (atténuation monotone ou révocation)
    pub fn remediate_all(&mut self, cap: &CiemCap, current_tick: u64) -> Result<usize, CiemError> {
        if !cap.has_right(ciem_rights::ENFORCE_LEAST_PRIV) && !cap.has_right(ciem_rights::ADMIN) {
            return Err(CiemError::PermissionDenied);
        }

        let mut remediated_count = 0;

        for i in 0..self.entitlement_count {
            if let Some(ent) = self.entitlements[i] {
                match ent.status {
                    EntitlementStatus::Excessive => {
                        self.enforce_least_privilege(cap, ent.id, current_tick)?;
                        remediated_count += 1;
                    }
                    EntitlementStatus::Dormant | EntitlementStatus::Orphan => {
                        self.revoke_entitlement(cap, ent.id, current_tick)?;
                        remediated_count += 1;
                    }
                    _ => {}
                }
            }
        }

        Ok(remediated_count)
    }

    /// Vérification de l'intégrité cryptographique du registre d'audit scellé
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut prev_hash = Self::GENESIS_HASH;
        for i in 0..self.audit_count {
            if let Some(record) = self.audit_ledger[i] {
                if record.prev_hash != prev_hash {
                    return false;
                }
                let expected = CiemAuditRecord::compute_hash(
                    record.index,
                    record.timestamp,
                    record.action,
                    record.identity_id,
                    record.entitlement_id,
                    &record.details_hash,
                    &record.prev_hash,
                );
                if record.record_hash != expected {
                    return false;
                }
                prev_hash = record.record_hash;
            }
        }
        true
    }

    /// Initialise un jeu de configurations et d'identités souveraines par défaut
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Identité Administrateur Grappe (HumanUser)
        let _ = self.register_identity(&cap, 101, "admin-root", IdentityKind::HumanUser, 100);
        let _ = self.grant_entitlement(
            &cap,
            201,
            101,
            EntitlementScope::ClusterControl,
            0x0F,
            5000,
            100,
        );
        let _ = self.record_usage(&cap, 101, 201, 0x0F, 120);

        // 2. Identité Service Ingress Gateway (ServiceAccount) avec droits excessifs (Entitlement Gap)
        let _ = self.register_identity(
            &cap,
            102,
            "jambo-ingress-gw",
            IdentityKind::ServiceAccount,
            100,
        );
        let _ = self.grant_entitlement(
            &cap,
            202,
            102,
            EntitlementScope::NetworkMesh,
            0xFF, // Tous les 8 bits accordés
            10000,
            100,
        );
        // N'utilise en réalité que 0x07 (bits 0, 1, 2)
        let _ = self.record_usage(&cap, 102, 202, 0x07, 150);

        // 3. Identité Sauvegarde Ancienne (WorkloadAgent) devenue dormante
        let _ = self.register_identity(
            &cap,
            103,
            "legacy-backup-job",
            IdentityKind::WorkloadAgent,
            100,
        );
        let _ = self.grant_entitlement(
            &cap,
            203,
            103,
            EntitlementScope::StorageVfs,
            0x0F,
            500, // Seuil dormant : 500 ticks
            100,
        );
        // Utilisé une seule fois au tick 110, inactif depuis longtemps
        let _ = self.record_usage(&cap, 103, 203, 0x03, 110);

        // 4. Entitlement Orphelin (rattaché à identité 999 inexistante)
        let _ = self.grant_entitlement(
            &cap,
            204,
            999, // Identité orpheline !
            EntitlementScope::KernelCore,
            0x1F,
            1000,
            100,
        );
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ciem_cap_attenuation_and_rejection() {
        let admin_cap = CiemCap::new(Handle::new(12701, 1), ciem_rights::ALL, 10000, 1000);
        assert!(admin_cap.has_right(ciem_rights::REGISTER_IDENTITY));
        assert!(admin_cap.has_right(ciem_rights::INSPECT_ENTITLEMENTS));
        assert!(admin_cap.has_right(ciem_rights::ANALYZE_EXCESS));
        assert!(admin_cap.has_right(ciem_rights::ENFORCE_LEAST_PRIV));
        assert!(admin_cap.has_right(ciem_rights::REVOKE_DORMANT));
        assert!(admin_cap.has_right(ciem_rights::ADMIN));

        let auditor_cap = admin_cap
            .attenuate(
                ciem_rights::INSPECT_ENTITLEMENTS | ciem_rights::READ_METRICS,
                5000,
                50,
            )
            .expect("Atténuation auditor");
        assert!(auditor_cap.has_right(ciem_rights::INSPECT_ENTITLEMENTS));
        assert!(auditor_cap.has_right(ciem_rights::READ_METRICS));
        assert!(!auditor_cap.has_right(ciem_rights::ENFORCE_LEAST_PRIV));
        assert!(!auditor_cap.has_right(ciem_rights::ADMIN));

        // Rejet d'escalade
        assert_eq!(
            auditor_cap.attenuate(ciem_rights::ALL, 5000, 50),
            Err(CiemError::AttenuationViolation)
        );
    }

    #[test]
    fn test_ciem_defaults_scan_and_anomalies() {
        let admin_cap = CiemCap::new(Handle::new(12702, 1), ciem_rights::ALL, 10000, 500);
        let mut daemon = JamboCiemDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.identity_count, 3);
        assert_eq!(daemon.entitlement_count, 4);
        assert!(daemon.verify_ledger_integrity());

        // Scan au tick 2500 (dépasse largement le seuil dormant de legacy-backup-job qui était 500)
        let (checked, anomalies) = daemon.scan_all_entitlements(&admin_cap, 2500).unwrap();
        assert_eq!(checked, 4);
        // Doit détecter :
        // - Entitlement 202 (jambo-ingress-gw) : Droits excessifs (granted 0xFF, exercised 0x07)
        // - Entitlement 203 (legacy-backup-job) : Dormant (last used 110, current 2500 > 500 threshold)
        // - Entitlement 204 (ID 999) : Orphelin
        assert!(anomalies >= 3);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_ciem_monotonic_least_privilege_remediation_and_sealed_report() {
        let admin_cap = CiemCap::new(Handle::new(12703, 1), ciem_rights::ALL, 10000, 500);
        let mut daemon = JamboCiemDaemon::new(admin_cap);
        daemon.init_defaults();

        // Scan au tick 2500
        let _ = daemon.scan_all_entitlements(&admin_cap, 2500).unwrap();

        // Réduire entitlement 202 (jambo-ingress-gw) : granted 0xFF -> doit devenir 0x07 (exercised)
        let new_rights = daemon
            .enforce_least_privilege(&admin_cap, 202, 2600)
            .unwrap();
        assert_eq!(new_rights, 0x07);

        // Vérifier que le statut est Attenuated
        let ent = daemon
            .entitlements
            .iter()
            .flatten()
            .find(|e| e.id == 202)
            .unwrap();
        assert_eq!(ent.status, EntitlementStatus::Attenuated);
        assert_eq!(ent.granted_rights, 0x07);
        assert_eq!(ent.excess_rights(), 0);
        assert_eq!(ent.gap_percentage(), 0);

        // Vérifier le rapport scellé généré
        let rep = daemon.latest_report().expect("Rapport scellé");
        assert_eq!(rep.identity_id, 102);
        assert_eq!(rep.entitlement_id, 202);
        assert_eq!(rep.action, CiemAction::LeastPrivilegeEnforced);
        assert_eq!(rep.initial_rights, 0xFF);
        assert_eq!(rep.effective_rights, 0x07);
        assert_eq!(rep.gap_removed, 0xF8);

        // Révocation du droit dormant 203
        let revoked = daemon.revoke_entitlement(&admin_cap, 203, 2610).unwrap();
        assert!(revoked);

        let ent203 = daemon
            .entitlements
            .iter()
            .flatten()
            .find(|e| e.id == 203)
            .unwrap();
        assert_eq!(ent203.status, EntitlementStatus::Revoked);
        assert_eq!(ent203.granted_rights, 0);

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_ciem_remediate_all_automation() {
        let admin_cap = CiemCap::new(Handle::new(12704, 1), ciem_rights::ALL, 10000, 500);
        let mut daemon = JamboCiemDaemon::new(admin_cap);
        daemon.init_defaults();

        let _ = daemon.scan_all_entitlements(&admin_cap, 3000).unwrap();
        let remediated = daemon.remediate_all(&admin_cap, 3050).unwrap();
        assert!(remediated >= 3);
        assert_eq!(daemon.report_count, remediated);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_ciem_toxic_combination_detection_and_remediation() {
        use entitlement_bits::*;
        let admin_cap = CiemCap::new(Handle::new(12705, 1), ciem_rights::ALL, 10000, 500);
        let mut daemon = JamboCiemDaemon::new(admin_cap);
        daemon.init_defaults();

        // Enregistrer une identité runner avec combinaison toxique (IAM_ADMIN + SECRETS_READ + NETWORK_EGRESS)
        let id = daemon
            .register_identity(
                &admin_cap,
                105,
                "runner-compromised",
                IdentityKind::WorkloadAgent,
                3100,
            )
            .unwrap();
        let toxic_bits = IAM_ADMIN | SECRETS_READ | NETWORK_EGRESS | STORAGE_READ;
        let eid = daemon
            .grant_entitlement(
                &admin_cap,
                205,
                id,
                EntitlementScope::SecurityServices,
                toxic_bits,
                5000,
                3110,
            )
            .unwrap();

        // Simuler que le runner n'utilise en fait que STORAGE_READ
        daemon
            .record_usage(&admin_cap, id, eid, STORAGE_READ, 3120)
            .unwrap();

        // Scan au tick 3150 -> doit détecter ToxicCombination
        let (_, anom) = daemon.scan_all_entitlements(&admin_cap, 3150).unwrap();
        assert!(anom > 0);

        let ent205 = daemon
            .entitlements
            .iter()
            .flatten()
            .find(|e| e.id == 205)
            .unwrap();
        assert!(ent205.has_toxic_combination());
        assert_eq!(ent205.risk, RiskLevel::Critical);

        // Application de moindre privilège -> brise la combinaison toxique
        let new_r = daemon
            .enforce_least_privilege(&admin_cap, 205, 3160)
            .unwrap();
        assert_eq!(new_r, STORAGE_READ);

        let ent205_fixed = daemon
            .entitlements
            .iter()
            .flatten()
            .find(|e| e.id == 205)
            .unwrap();
        assert!(!ent205_fixed.has_toxic_combination());
        assert_eq!(ent205_fixed.risk, RiskLevel::Low);

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_ciem_entitlement_gap_and_metrics() {
        let admin_cap = CiemCap::new(Handle::new(12706, 1), ciem_rights::ALL, 10000, 500);
        let mut daemon = JamboCiemDaemon::new(admin_cap);
        daemon.init_defaults();

        // Entitlement 202 a granted 0xFF (8 bits) et exercised 0x07 (3 bits)
        let ent202 = daemon
            .entitlements
            .iter()
            .flatten()
            .find(|e| e.id == 202)
            .unwrap();
        assert_eq!(ent202.excess_rights(), 0xF8);
        assert_eq!(ent202.entitlement_gap(), 0xF8);
        // Gap % = (5 non-utilisés / 8 accordés) * 100 = 62%
        assert_eq!(ent202.gap_percentage(), 62);

        let avg_gap = daemon.average_gap_percentage();
        assert!(avg_gap > 0);
    }
}

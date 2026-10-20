//! Plateforme Intégrée de Protection des Applications Cloud Natives (CNAPP)
//! Corrélation Contextuelle CSPM + CWPP + CIEM & Score de Risque Unifié
//!
//! Phase 128 — Jalon v0.2.126
//!
//! Fournit une plateforme souveraine CNAPP (Cloud-Native Application Protection Platform) en `#![no_std]` :
//! 1. Corrélation contextuelle multidimensionnelle : Posture & Configuration (CSPM),
//!    Surveillance & Confinement Temps Réel (CWPP), et Gestion des Privilèges & Droits (CIEM).
//! 2. Détection des Combinaisons Toxiques (Toxic Combinations) & Modélisation de Graphes d'Attaque (Attack Paths).
//! 3. Calcul unifié et déterministe du Score de Risque de Grappe (0..100).
//! 4. Orchestration autonome de la remédiation unifiée (confinement CWPP, atténuation CIEM, durcissement CSPM).
//! 5. Contrôle d'accès capabilaire (`CnappCap`) sans autorité ambiante.
//! 6. Registre d'audit cryptographique inviolable scellé par chaînage SHA-256.

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
        let total_bits = self.total_bytes * 8;
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

        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.transform_block(&block);

        let mut digest = [0u8; 32];
        for i in 0..8 {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        digest
    }

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ============================================================================
// ERREURS & MODÈLE DE CAPABILITÉ (CnappCap)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnappError {
    PermissionDenied,
    AttenuationViolation,
    WorkloadNotFound,
    PathNotFound,
    CapacityExceeded,
    LedgerTampered,
    InvalidSignal,
}

pub mod cnapp_rights {
    pub const INGEST_SIGNALS: u32 = 1 << 0;
    pub const CORRELATE_RISK: u32 = 1 << 1;
    pub const BUILD_ATTACK_GRAPH: u32 = 1 << 2;
    pub const ORCHESTRATE_REMEDIATION: u32 = 1 << 3;
    pub const QUERY_POSTURE: u32 = 1 << 4;
    pub const READ_METRICS: u32 = 1 << 5;
    pub const SEAL_LEDGER: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;

    pub const ALL: u32 = INGEST_SIGNALS
        | CORRELATE_RISK
        | BUILD_ATTACK_GRAPH
        | ORCHESTRATE_REMEDIATION
        | QUERY_POSTURE
        | READ_METRICS
        | SEAL_LEDGER
        | ADMIN;
}

/// Capabilité de contrôle CNAPP sans autorité ambiante
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CnappCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl CnappCap {
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
    ) -> Result<Self, CnappError> {
        if (new_rights & !self.rights) != 0 {
            return Err(CnappError::AttenuationViolation);
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

    pub fn consume(&mut self) -> Result<(), CnappError> {
        if self.invocations_left == 0 {
            return Err(CnappError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// MODÈLE DE DONNÉES & SIGNAUX CNAPP MULTIDIMENSIONNELS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnappSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalSource {
    CspmPosture,
    CwppRuntime,
    CiemEntitlement,
    NetworkMesh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrchestrationAction {
    NoAction,
    IsolateWorkload,
    AttenuateEntitlements,
    RemediatePosture,
    FullUnifiedContainment,
}

/// Signal unitaire de vulnérabilité, dérive ou menace ingéré
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CnappFinding {
    pub id: u32,
    pub workload_id: u32,
    pub source: SignalSource,
    pub severity: CnappSeverity,
    pub score: u8, // 0..100
    pub title: [u8; 48],
    pub title_len: usize,
    pub remediated: bool,
    pub tick: u64,
}

impl CnappFinding {
    pub fn new(
        id: u32,
        workload_id: u32,
        source: SignalSource,
        severity: CnappSeverity,
        score: u8,
        title_str: &str,
        tick: u64,
    ) -> Self {
        let mut title = [0u8; 48];
        let bytes = title_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 48);
        title[..len].copy_from_slice(&bytes[..len]);

        Self {
            id,
            workload_id,
            source,
            severity,
            score,
            title,
            title_len: len,
            remediated: false,
            tick,
        }
    }
}

/// Nœud de charge de travail au sein du graphe d'attaque CNAPP
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttackPathNode {
    pub workload_id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub is_internet_exposed: bool,
    pub has_posture_drift: bool,    // CSPM
    pub has_excess_privilege: bool, // CIEM
    pub has_runtime_anomaly: bool,  // CWPP
    pub privilege_level: u8,        // 0=Worker, 1=Service, 2=ClusterOperator, 3=Kernel/Enclave
    pub unified_risk_score: u8,     // 0..100
    pub is_toxic_combination: bool,
    pub is_quarantined: bool,
}

impl AttackPathNode {
    pub fn new(
        workload_id: u32,
        name_str: &str,
        is_internet_exposed: bool,
        privilege_level: u8,
    ) -> Self {
        let mut name = [0u8; 32];
        let bytes = name_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        name[..len].copy_from_slice(&bytes[..len]);

        Self {
            workload_id,
            name,
            name_len: len,
            is_internet_exposed,
            has_posture_drift: false,
            has_excess_privilege: false,
            has_runtime_anomaly: false,
            privilege_level,
            unified_risk_score: 0,
            is_toxic_combination: false,
            is_quarantined: false,
        }
    }

    /// Calcule le score unifié de risque en corrélant les signaux multidimensionnels
    pub fn recalculate_risk(&mut self) -> u8 {
        if self.is_quarantined {
            self.unified_risk_score = 5;
            self.is_toxic_combination = false;
            return self.unified_risk_score;
        }

        let mut score: u16 = 0;

        // Facteur d'exposition Internet / Maille ingress
        if self.is_internet_exposed {
            score += 15;
        }

        // Niveau d'autorité / sensibilité des privilèges
        score += (self.privilege_level as u16) * 10;

        // Signaux de posture (CSPM)
        if self.has_posture_drift {
            score += 20;
        }

        // Droits excessifs ou orphelins (CIEM)
        if self.has_excess_privilege {
            score += 25;
        }

        // Menaces actives à l'exécution (CWPP)
        if self.has_runtime_anomaly {
            score += 35;
        }

        // Combinaison toxique : Dérive CSPM + Droits CIEM + Menace CWPP
        if self.has_posture_drift && self.has_excess_privilege && self.has_runtime_anomaly {
            self.is_toxic_combination = true;
            score += 30; // Pénalité critique de synergie offensive
        } else {
            self.is_toxic_combination = false;
        }

        if score > 100 {
            score = 100;
        }

        self.unified_risk_score = score as u8;
        self.unified_risk_score
    }
}

/// Chemin / Vecteur d'attaque corrélé dans le graphe
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttackPath {
    pub id: u32,
    pub source_id: u32,
    pub target_id: u32,
    pub hops: u8,
    pub severity: CnappSeverity,
    pub toxic_combination: bool,
    pub active: bool,
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SCELLÉ (SHA-256)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnappAuditAction {
    WorkloadRegistered,
    SignalIngested,
    CorrelationExecuted,
    AttackPathDiscovered,
    RiskScored,
    RemediationOrchestrated,
    LedgerSealed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CnappAuditRecord {
    pub index: u64,
    pub timestamp: u64,
    pub action: CnappAuditAction,
    pub workload_id: u32,
    pub details_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

impl CnappAuditRecord {
    pub fn compute_hash(
        index: u64,
        timestamp: u64,
        action: CnappAuditAction,
        workload_id: u32,
        details_hash: &[u8; 32],
        prev_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&index.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&[action as u8]);
        hasher.update(&workload_id.to_be_bytes());
        hasher.update(details_hash);
        hasher.update(prev_hash);
        hasher.finalize()
    }
}

// ============================================================================
// DÉMON CENTRAL CNAPP (JamboCnappDaemon)
// ============================================================================

pub struct JamboCnappDaemon {
    pub admin_cap: CnappCap,
    pub nodes: [Option<AttackPathNode>; 16],
    pub node_count: usize,
    pub findings: [Option<CnappFinding>; 32],
    pub finding_count: usize,
    pub attack_paths: [Option<AttackPath>; 16],
    pub path_count: usize,
    pub audit_ledger: [Option<CnappAuditRecord>; 32],
    pub audit_count: usize,
    pub last_block_hash: [u8; 32],
    pub total_correlations: u64,
    pub total_remediations: u64,
    pub toxic_combinations_count: usize,
    pub average_cluster_risk: u8,
}

impl JamboCnappDaemon {
    pub const fn new(admin_cap: CnappCap) -> Self {
        Self {
            admin_cap,
            nodes: [None; 16],
            node_count: 0,
            findings: [None; 32],
            finding_count: 0,
            attack_paths: [None; 16],
            path_count: 0,
            audit_ledger: [None; 32],
            audit_count: 0,
            last_block_hash: [0u8; 32],
            total_correlations: 0,
            total_remediations: 0,
            toxic_combinations_count: 0,
            average_cluster_risk: 0,
        }
    }

    /// Enregistre un nœud de charge de travail dans la topologie de grappe
    pub fn register_workload(
        &mut self,
        cap: &CnappCap,
        workload_id: u32,
        name: &str,
        is_internet_exposed: bool,
        privilege_level: u8,
        tick: u64,
    ) -> Result<(), CnappError> {
        if !cap.has_right(cnapp_rights::ADMIN) && !cap.has_right(cnapp_rights::BUILD_ATTACK_GRAPH) {
            return Err(CnappError::PermissionDenied);
        }
        if self.node_count >= self.nodes.len() {
            return Err(CnappError::CapacityExceeded);
        }

        // Vérifier si le nœud existe déjà
        for opt in self.nodes.iter() {
            if let Some(ref node) = opt {
                if node.workload_id == workload_id {
                    return Ok(());
                }
            }
        }

        let mut node = AttackPathNode::new(workload_id, name, is_internet_exposed, privilege_level);
        node.recalculate_risk();

        self.nodes[self.node_count] = Some(node);
        self.node_count += 1;

        let details = Sha256::hash(name.as_bytes());
        self.append_audit_record(
            CnappAuditAction::WorkloadRegistered,
            workload_id,
            &details,
            tick,
        )?;

        Ok(())
    }

    /// Ingère un signal de sécurité issu de CSPM, CWPP ou CIEM
    pub fn ingest_finding(
        &mut self,
        cap: &CnappCap,
        finding: CnappFinding,
    ) -> Result<u32, CnappError> {
        if !cap.has_right(cnapp_rights::INGEST_SIGNALS) && !cap.has_right(cnapp_rights::ADMIN) {
            return Err(CnappError::PermissionDenied);
        }
        if self.finding_count >= self.findings.len() {
            return Err(CnappError::CapacityExceeded);
        }

        // Mettre à jour l'état du nœud correspondant
        let mut found = false;
        for opt in self.nodes.iter_mut() {
            if let Some(ref mut node) = opt {
                if node.workload_id == finding.workload_id {
                    found = true;
                    match finding.source {
                        SignalSource::CspmPosture => node.has_posture_drift = true,
                        SignalSource::CwppRuntime => node.has_runtime_anomaly = true,
                        SignalSource::CiemEntitlement => node.has_excess_privilege = true,
                        SignalSource::NetworkMesh => {}
                    }
                    node.recalculate_risk();
                    break;
                }
            }
        }
        if !found {
            return Err(CnappError::WorkloadNotFound);
        }

        self.findings[self.finding_count] = Some(finding);
        self.finding_count += 1;

        let fid = finding.id;
        let details = Sha256::hash(&finding.title[..finding.title_len]);
        self.append_audit_record(
            CnappAuditAction::SignalIngested,
            finding.workload_id,
            &details,
            finding.tick,
        )?;

        Ok(fid)
    }

    /// Exécute la corrélation multidimensionnelle, identifie les combinaisons toxiques et met à jour les graphes d'attaque
    pub fn correlate_signals(
        &mut self,
        cap: &CnappCap,
        tick: u64,
    ) -> Result<(usize, usize), CnappError> {
        if !cap.has_right(cnapp_rights::CORRELATE_RISK) && !cap.has_right(cnapp_rights::ADMIN) {
            return Err(CnappError::PermissionDenied);
        }

        self.total_correlations += 1;
        self.toxic_combinations_count = 0;
        let mut total_score: u32 = 0;

        // 1. Recalculer les scores de tous les nœuds et compter les combinaisons toxiques
        for opt in self.nodes.iter_mut() {
            if let Some(ref mut node) = opt {
                let score = node.recalculate_risk();
                total_score += score as u32;
                if node.is_toxic_combination {
                    self.toxic_combinations_count += 1;
                }
            }
        }

        if self.node_count > 0 {
            self.average_cluster_risk = (total_score / (self.node_count as u32)) as u8;
        } else {
            self.average_cluster_risk = 0;
        }

        // 2. Construire ou mettre à jour les chemins d'attaque corrélés
        // Ex: si un nœud exposé Internet a un risque moyen/élevé et peut communiquer vers un nœud interne avec combinaison toxique
        self.path_count = 0;
        let mut discovered_paths = 0;

        for i in 0..self.node_count {
            if let Some(src) = self.nodes[i] {
                if src.is_internet_exposed {
                    for j in 0..self.node_count {
                        if i != j {
                            if let Some(tgt) = self.nodes[j] {
                                // Si le nœud cible a des privilèges élevés ou une combinaison toxique
                                if tgt.privilege_level >= 2 || tgt.is_toxic_combination {
                                    if self.path_count < self.attack_paths.len() {
                                        let severity = if tgt.is_toxic_combination {
                                            CnappSeverity::Critical
                                        } else if tgt.unified_risk_score >= 70 {
                                            CnappSeverity::High
                                        } else {
                                            CnappSeverity::Medium
                                        };

                                        self.attack_paths[self.path_count] = Some(AttackPath {
                                            id: 300 + self.path_count as u32,
                                            source_id: src.workload_id,
                                            target_id: tgt.workload_id,
                                            hops: 2,
                                            severity,
                                            toxic_combination: tgt.is_toxic_combination,
                                            active: !tgt.is_quarantined,
                                        });
                                        self.path_count += 1;
                                        discovered_paths += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut hash_input = [0u8; 16];
        hash_input[0..4].copy_from_slice(&(self.path_count as u32).to_be_bytes());
        hash_input[4..8].copy_from_slice(&(self.toxic_combinations_count as u32).to_be_bytes());
        hash_input[8..12].copy_from_slice(&(self.average_cluster_risk as u32).to_be_bytes());
        hash_input[12..16].copy_from_slice(&(discovered_paths as u32).to_be_bytes());

        let details = Sha256::hash(&hash_input);
        self.append_audit_record(CnappAuditAction::CorrelationExecuted, 0, &details, tick)?;

        Ok((discovered_paths, self.toxic_combinations_count))
    }

    /// Orchestre une remédiation unifiée autonome sur une charge de travail
    pub fn orchestrate_remediation(
        &mut self,
        cap: &CnappCap,
        workload_id: u32,
        tick: u64,
    ) -> Result<OrchestrationAction, CnappError> {
        if !cap.has_right(cnapp_rights::ORCHESTRATE_REMEDIATION)
            && !cap.has_right(cnapp_rights::ADMIN)
        {
            return Err(CnappError::PermissionDenied);
        }

        let mut action = OrchestrationAction::NoAction;

        for opt in self.nodes.iter_mut() {
            if let Some(ref mut node) = opt {
                if node.workload_id == workload_id {
                    if node.is_toxic_combination {
                        // Combinaison toxique : confinement d'urgence total (CWPP + CIEM + CSPM)
                        action = OrchestrationAction::FullUnifiedContainment;
                        node.is_quarantined = true;
                        node.has_runtime_anomaly = false;
                        node.has_excess_privilege = false;
                        node.has_posture_drift = false;
                    } else if node.has_runtime_anomaly {
                        action = OrchestrationAction::IsolateWorkload;
                        node.is_quarantined = true;
                        node.has_runtime_anomaly = false;
                    } else if node.has_excess_privilege {
                        action = OrchestrationAction::AttenuateEntitlements;
                        node.has_excess_privilege = false;
                    } else if node.has_posture_drift {
                        action = OrchestrationAction::RemediatePosture;
                        node.has_posture_drift = false;
                    }
                    node.recalculate_risk();
                    break;
                }
            }
        }

        if action == OrchestrationAction::NoAction {
            return Err(CnappError::WorkloadNotFound);
        }

        // Remédier les findings associés
        for opt in self.findings.iter_mut() {
            if let Some(ref mut finding) = opt {
                if finding.workload_id == workload_id {
                    finding.remediated = true;
                }
            }
        }

        // Désactiver les chemins d'attaque ciblant cette charge
        for opt in self.attack_paths.iter_mut() {
            if let Some(ref mut path) = opt {
                if path.target_id == workload_id {
                    path.active = false;
                }
            }
        }

        self.total_remediations += 1;

        let mut details = [0u8; 32];
        details[0] = action as u8;
        details[1..5].copy_from_slice(&workload_id.to_be_bytes());
        let digest = Sha256::hash(&details);

        self.append_audit_record(
            CnappAuditAction::RemediationOrchestrated,
            workload_id,
            &digest,
            tick,
        )?;

        Ok(action)
    }

    /// Remédie automatiquement toutes les charges en état critique ou combinaison toxique
    pub fn remediate_all_critical(
        &mut self,
        cap: &CnappCap,
        tick: u64,
    ) -> Result<usize, CnappError> {
        if !cap.has_right(cnapp_rights::ORCHESTRATE_REMEDIATION)
            && !cap.has_right(cnapp_rights::ADMIN)
        {
            return Err(CnappError::PermissionDenied);
        }

        let mut critical_ids = [0u32; 16];
        let mut count = 0;

        for opt in self.nodes.iter() {
            if let Some(ref node) = opt {
                if (node.is_toxic_combination || node.unified_risk_score >= 75)
                    && !node.is_quarantined
                {
                    critical_ids[count] = node.workload_id;
                    count += 1;
                }
            }
        }

        let mut remediated = 0;
        for i in 0..count {
            let wid = critical_ids[i];
            let _ = self.orchestrate_remediation(cap, wid, tick)?;
            remediated += 1;
        }

        // Recalculer la corrélation après remédiation
        let _ = self.correlate_signals(cap, tick + 10)?;

        Ok(remediated)
    }

    /// Ajoute un enregistrement d'audit scellé cryptographiquement (SHA-256)
    fn append_audit_record(
        &mut self,
        action: CnappAuditAction,
        workload_id: u32,
        details_hash: &[u8; 32],
        timestamp: u64,
    ) -> Result<(), CnappError> {
        let index = self.audit_count as u64;
        let prev_hash = self.last_block_hash;

        let record_hash = CnappAuditRecord::compute_hash(
            index,
            timestamp,
            action,
            workload_id,
            details_hash,
            &prev_hash,
        );

        let record = CnappAuditRecord {
            index,
            timestamp,
            action,
            workload_id,
            details_hash: *details_hash,
            prev_hash,
            record_hash,
        };

        if self.audit_count < self.audit_ledger.len() {
            self.audit_ledger[self.audit_count] = Some(record);
            self.audit_count += 1;
        } else {
            // Rotation circulaire FIFO du ledger pour préserver la mémoire #![no_std]
            for i in 1..self.audit_ledger.len() {
                self.audit_ledger[i - 1] = self.audit_ledger[i];
            }
            self.audit_ledger[self.audit_ledger.len() - 1] = Some(record);
        }

        self.last_block_hash = record_hash;
        Ok(())
    }

    /// Vérifie l'intégrité cryptographique absolue du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        let mut prev = [0u8; 32];
        for i in 0..self.audit_count {
            if let Some(ref rec) = self.audit_ledger[i] {
                if rec.prev_hash != prev {
                    return false;
                }
                let expected = CnappAuditRecord::compute_hash(
                    rec.index,
                    rec.timestamp,
                    rec.action,
                    rec.workload_id,
                    &rec.details_hash,
                    &rec.prev_hash,
                );
                if rec.record_hash != expected {
                    return false;
                }
                prev = rec.record_hash;
            }
        }
        true
    }

    /// Initialise la topologie de référence représentative pour tests et démonstrations
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Ingress Gateway : Exposée Internet, Privilèges intermédiaires
        let _ = self.register_workload(&cap, 101, "jambo-ingress-gw", true, 1, 100);

        // 2. Microservice Paiement / Traitement : Interne, Privilège service
        let _ = self.register_workload(&cap, 102, "payment-processor", false, 1, 100);

        // 3. Opérateur de Grappe / Contrôleur Kernel : Interne, Privilège Cluster/Opérateur
        let _ = self.register_workload(&cap, 103, "cluster-operator", false, 2, 100);

        // 4. Agent Métriques & Surveillance : Interne, Privilège minimal Worker
        let _ = self.register_workload(&cap, 104, "metrics-collector", false, 0, 100);

        // Ingérer les signaux multidimensionnels :
        // Signal A (CSPM) sur 101: Dérive de conformité (Port externe non durci)
        let _ = self.ingest_finding(
            &cap,
            CnappFinding::new(
                201,
                101,
                SignalSource::CspmPosture,
                CnappSeverity::Medium,
                45,
                "CIS-1.2: Ingress TLS Cipher Suite Drift",
                120,
            ),
        );

        // Signal B (CIEM) sur 103: Droits excessifs / privilège non restreint
        let _ = self.ingest_finding(
            &cap,
            CnappFinding::new(
                202,
                103,
                SignalSource::CiemEntitlement,
                CnappSeverity::High,
                70,
                "CIEM: ClusterRole Excessive Full-Admin Access",
                130,
            ),
        );

        // Signal C (CSPM) sur 103: Dérive de durcissement (SecNumCloud baseline non conforme)
        let _ = self.ingest_finding(
            &cap,
            CnappFinding::new(
                203,
                103,
                SignalSource::CspmPosture,
                CnappSeverity::High,
                65,
                "ANSSI-3.1: Kernel Namespace Isolation Drift",
                140,
            ),
        );

        // Signal D (CWPP) sur 103: Tentative d'exploitation en mémoire (ROP / Injection)
        let _ = self.ingest_finding(
            &cap,
            CnappFinding::new(
                204,
                103,
                SignalSource::CwppRuntime,
                CnappSeverity::Critical,
                90,
                "CWPP: Runtime RIP Divergence Exploit Detected",
                150,
            ),
        );

        // Corrélation initiale des signaux
        let _ = self.correlate_signals(&cap, 160);
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS (#![no_std])
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cnapp_cap_attenuation_and_enforcement() {
        let admin_cap = CnappCap::new(Handle::new(12801, 1), cnapp_rights::ALL, 10000, 1000);
        assert!(admin_cap.has_right(cnapp_rights::INGEST_SIGNALS));
        assert!(admin_cap.has_right(cnapp_rights::CORRELATE_RISK));
        assert!(admin_cap.has_right(cnapp_rights::BUILD_ATTACK_GRAPH));
        assert!(admin_cap.has_right(cnapp_rights::ORCHESTRATE_REMEDIATION));
        assert!(admin_cap.has_right(cnapp_rights::ADMIN));

        let auditor_cap = admin_cap
            .attenuate(
                cnapp_rights::QUERY_POSTURE | cnapp_rights::READ_METRICS,
                5000,
                100,
            )
            .expect("Atténuation auditor");
        assert!(auditor_cap.has_right(cnapp_rights::QUERY_POSTURE));
        assert!(auditor_cap.has_right(cnapp_rights::READ_METRICS));
        assert!(!auditor_cap.has_right(cnapp_rights::ORCHESTRATE_REMEDIATION));
        assert!(!auditor_cap.has_right(cnapp_rights::ADMIN));

        // Rejet d'escalade
        assert_eq!(
            auditor_cap.attenuate(cnapp_rights::ALL, 5000, 100),
            Err(CnappError::AttenuationViolation)
        );
    }

    #[test]
    fn test_cnapp_correlation_and_toxic_combination() {
        let admin_cap = CnappCap::new(Handle::new(12802, 1), cnapp_rights::ALL, 10000, 500);
        let mut daemon = JamboCnappDaemon::new(admin_cap);
        daemon.init_defaults();

        assert_eq!(daemon.node_count, 4);
        assert_eq!(daemon.finding_count, 4);
        assert!(daemon.verify_ledger_integrity());

        // Le nœud 103 ("cluster-operator") possède CSPM drift + CIEM excess rights + CWPP runtime exploit
        // Il doit être identifié en COMBINAISON TOXIQUE (Toxic Combination) avec score 100
        let node103 = daemon
            .nodes
            .iter()
            .flatten()
            .find(|n| n.workload_id == 103)
            .unwrap();
        assert!(node103.is_toxic_combination);
        assert_eq!(node103.unified_risk_score, 100);

        // Au moins 1 chemin d'attaque critique découvert
        assert!(daemon.path_count >= 1);
        assert_eq!(daemon.toxic_combinations_count, 1);
    }

    #[test]
    fn test_cnapp_unified_risk_score_calculation() {
        let admin_cap = CnappCap::new(Handle::new(12803, 1), cnapp_rights::ALL, 10000, 500);
        let mut daemon = JamboCnappDaemon::new(admin_cap);
        daemon.init_defaults();

        // Nœud 101 ("jambo-ingress-gw") : Exposé Internet (+15) + Service (+10) + Posture drift (+20) = 45
        let node101 = daemon
            .nodes
            .iter()
            .flatten()
            .find(|n| n.workload_id == 101)
            .unwrap();
        assert_eq!(node101.unified_risk_score, 45);
        assert!(!node101.is_toxic_combination);

        // Nœud 104 ("metrics-collector") : Worker interne propre = 0
        let node104 = daemon
            .nodes
            .iter()
            .flatten()
            .find(|n| n.workload_id == 104)
            .unwrap();
        assert_eq!(node104.unified_risk_score, 0);
        assert!(!node104.is_toxic_combination);
    }

    #[test]
    fn test_cnapp_orchestrated_remediation_and_audit_ledger() {
        let admin_cap = CnappCap::new(Handle::new(12804, 1), cnapp_rights::ALL, 10000, 500);
        let mut daemon = JamboCnappDaemon::new(admin_cap);
        daemon.init_defaults();

        // Remédiation autonome de la combinaison toxique critique sur 103
        let action = daemon
            .orchestrate_remediation(&admin_cap, 103, 200)
            .expect("Remédiation unifiée");
        assert_eq!(action, OrchestrationAction::FullUnifiedContainment);

        let node103 = daemon
            .nodes
            .iter()
            .flatten()
            .find(|n| n.workload_id == 103)
            .unwrap();
        assert!(node103.is_quarantined);
        assert!(!node103.is_toxic_combination);
        assert!(node103.unified_risk_score <= 10);

        // Remédier tout le reste
        let rem_count = daemon.remediate_all_critical(&admin_cap, 250).unwrap();
        assert_eq!(rem_count, 0); // Déjà remédié

        // Intégrité du ledger cryptographique SHA-256
        assert!(daemon.verify_ledger_integrity());
    }
}

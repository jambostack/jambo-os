//! Gestion de la Surface d'Attaque Externe (EASM - External Attack Surface Management)
//! & Découverte Continue d'Actifs Numériques
//!
//! Phase 131 — Jalon v0.2.129
//!
//! Fournit une plateforme souveraine EASM (External Attack Surface Management) en `#![no_std]` :
//! 1. Recensement dynamique des actifs numériques exposés (domaines DNS, adresses IP, ports, certificats TLS, buckets de stockage).
//! 2. Découverte continue de Shadow IT, sous-domaines orphelins (Dangling DNS) et interfaces d'administration exposées.
//! 3. Analyse proactive des configurations périmétriques défaillantes, expirations de certificats et fuites d'informations.
//! 4. Calcul déterministe de l'Indice d'Exposition Externe (Exposure Index 0..100) et hiérarchisation des risques.
//! 5. Remédiation automatisée des vulnérabilités périmétriques et durcissement Zero-Trust.
//! 6. Contrôle d'accès capabilaire strict (`EasmCap`) sans autorité ambiante avec atténuation monotone.
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
            self.buffer = [0u8; 64];
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
// CONTRÔLE D'ACCÈS CAPABILAIRE (EasmCap)
// ============================================================================

pub mod easm_rights {
    pub const DISCOVER_ASSETS: u32 = 1 << 0;
    pub const SCAN_PERIMETER: u32 = 1 << 1;
    pub const QUERY_SURFACE: u32 = 1 << 2;
    pub const MANAGE_ASSETS: u32 = 1 << 3;
    pub const REMEDIATE_EXPOSURE: u32 = 1 << 4;
    pub const EXPORT_INVENTORY: u32 = 1 << 5;
    pub const SEAL_LEDGER: u32 = 1 << 6;
    pub const ADMIN: u32 = 1 << 7;
    pub const ALL: u32 = 0xFF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EasmError {
    PermissionDenied,
    AttenuationViolation,
    AssetNotFound,
    FindingNotFound,
    CapacityExceeded,
    LedgerCorrupted,
    InvalidParameter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EasmCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl EasmCap {
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

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, EasmError> {
        if (new_rights & !self.rights) != 0 {
            return Err(EasmError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(EasmError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(EasmError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn check_and_consume(&mut self, required_right: u32) -> Result<(), EasmError> {
        if !self.has_right(required_right) {
            return Err(EasmError::PermissionDenied);
        }
        if self.invocations_left == 0 {
            return Err(EasmError::PermissionDenied);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// MODÈLES DE DONNÉES EASM
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetType {
    DomainName,
    IpAddress,
    PortService,
    TlsCertificate,
    StorageBucket,
    ApiEndpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposureLevel {
    PublicHardened,
    PublicVulnerable,
    RestrictedAccess,
    ShadowItOrphaned,
    InternalLeaked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingCategory {
    DanglingDnsTakeover,
    ExpiredOrWeakTls,
    ExposedAdminInterface,
    ExposedStorageBucket,
    InformationLeakage,
    OpenInsecurePort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus {
    Open,
    Remediated,
    Suppressed,
    FalsePositive,
}

#[derive(Clone, Copy)]
pub struct DiscoveredAsset {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub target: [u8; 48],
    pub target_len: usize,
    pub asset_type: AssetType,
    pub exposure: ExposureLevel,
    pub port: u16,
    pub risk_score: u8,
    pub is_shadow_it: bool,
    pub tls_valid_days: i16,
    pub last_scanned: u64,
}

impl DiscoveredAsset {
    pub fn new(
        id: u32,
        name_str: &str,
        target_str: &str,
        asset_type: AssetType,
        exposure: ExposureLevel,
        port: u16,
        is_shadow_it: bool,
        tls_valid_days: i16,
        timestamp: u64,
    ) -> Self {
        let mut name = [0u8; 32];
        let n_bytes = name_str.as_bytes();
        let n_len = core::cmp::min(n_bytes.len(), 32);
        name[..n_len].copy_from_slice(&n_bytes[..n_len]);

        let mut target = [0u8; 48];
        let t_bytes = target_str.as_bytes();
        let t_len = core::cmp::min(t_bytes.len(), 48);
        target[..t_len].copy_from_slice(&t_bytes[..t_len]);

        let initial_risk = match exposure {
            ExposureLevel::ShadowItOrphaned => 90,
            ExposureLevel::InternalLeaked => 85,
            ExposureLevel::PublicVulnerable => 75,
            ExposureLevel::PublicHardened => 20,
            ExposureLevel::RestrictedAccess => 5,
        };

        Self {
            id,
            name,
            name_len: n_len,
            target,
            target_len: t_len,
            asset_type,
            exposure,
            port,
            risk_score: initial_risk,
            is_shadow_it,
            tls_valid_days,
            last_scanned: timestamp,
        }
    }

    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<unknown>")
    }

    pub fn target_as_str(&self) -> &str {
        core::str::from_utf8(&self.target[..self.target_len]).unwrap_or("<unknown>")
    }
}

#[derive(Clone, Copy)]
pub struct PerimeterFinding {
    pub id: u32,
    pub asset_id: u32,
    pub title: [u8; 48],
    pub title_len: usize,
    pub category: FindingCategory,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub remediation_action: [u8; 48],
    pub remediation_action_len: usize,
    pub discovered_at: u64,
    pub remediated_at: u64,
}

impl PerimeterFinding {
    pub fn new(
        id: u32,
        asset_id: u32,
        title_str: &str,
        category: FindingCategory,
        severity: FindingSeverity,
        remediation_str: &str,
        discovered_at: u64,
    ) -> Self {
        let mut title = [0u8; 48];
        let t_bytes = title_str.as_bytes();
        let t_len = core::cmp::min(t_bytes.len(), 48);
        title[..t_len].copy_from_slice(&t_bytes[..t_len]);

        let mut rem = [0u8; 48];
        let r_bytes = remediation_str.as_bytes();
        let r_len = core::cmp::min(r_bytes.len(), 48);
        rem[..r_len].copy_from_slice(&r_bytes[..r_len]);

        Self {
            id,
            asset_id,
            title,
            title_len: t_len,
            category,
            severity,
            status: FindingStatus::Open,
            remediation_action: rem,
            remediation_action_len: r_len,
            discovered_at,
            remediated_at: 0,
        }
    }

    pub fn title_as_str(&self) -> &str {
        core::str::from_utf8(&self.title[..self.title_len]).unwrap_or("<unknown>")
    }

    pub fn remediation_as_str(&self) -> &str {
        core::str::from_utf8(&self.remediation_action[..self.remediation_action_len])
            .unwrap_or("<unknown>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackSurfaceSummary {
    pub total_assets: usize,
    pub public_assets: usize,
    pub shadow_it_count: usize,
    pub open_findings_count: usize,
    pub critical_findings_count: usize,
    pub exposure_index: u8,
}

#[derive(Clone, Copy)]
pub struct AuditLogEntry {
    pub entry_id: u32,
    pub action: [u8; 24],
    pub action_len: usize,
    pub target_id: u32,
    pub result_code: u16,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub timestamp: u64,
}

// ============================================================================
// DÉMON CENTRAL EASM (JamboEasmDaemon)
// ============================================================================

pub struct JamboEasmDaemon {
    pub admin_cap: EasmCap,
    pub assets: [Option<DiscoveredAsset>; 16],
    pub asset_count: usize,
    pub findings: [Option<PerimeterFinding>; 24],
    pub finding_count: usize,
    pub ledger: [Option<AuditLogEntry>; 32],
    pub ledger_count: usize,
    pub latest_ledger_hash: [u8; 32],
    pub exposure_index: u8,
    next_asset_id: u32,
    next_finding_id: u32,
}

impl JamboEasmDaemon {
    pub fn new(admin_cap: EasmCap) -> Self {
        Self {
            admin_cap,
            assets: [None; 16],
            asset_count: 0,
            findings: [None; 24],
            finding_count: 0,
            ledger: [None; 32],
            ledger_count: 0,
            latest_ledger_hash: [0u8; 32],
            exposure_index: 0,
            next_asset_id: 1,
            next_finding_id: 1,
        }
    }

    pub fn log_audit_action(
        &mut self,
        action_str: &str,
        target_id: u32,
        result_code: u16,
        timestamp: u64,
    ) -> Result<(), EasmError> {
        let entry_id = (self.ledger_count + 1) as u32;

        let mut action = [0u8; 24];
        let bytes = action_str.as_bytes();
        let len = core::cmp::min(bytes.len(), 24);
        action[..len].copy_from_slice(&bytes[..len]);

        let prev_hash = self.latest_ledger_hash;

        let mut hasher = Sha256::new();
        hasher.update(&entry_id.to_be_bytes());
        hasher.update(&action[..len]);
        hasher.update(&target_id.to_be_bytes());
        hasher.update(&result_code.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&prev_hash);
        let entry_hash = hasher.finalize();

        let entry = AuditLogEntry {
            entry_id,
            action,
            action_len: len,
            target_id,
            result_code,
            prev_hash,
            entry_hash,
            timestamp,
        };

        if self.ledger_count < self.ledger.len() {
            self.ledger[self.ledger_count] = Some(entry);
            self.ledger_count += 1;
        } else {
            // Tampon annulaire
            for i in 1..self.ledger.len() {
                self.ledger[i - 1] = self.ledger[i];
            }
            self.ledger[self.ledger.len() - 1] = Some(entry);
        }

        self.latest_ledger_hash = entry_hash;
        Ok(())
    }

    pub fn verify_ledger_integrity(&self) -> bool {
        let mut expected_prev = [0u8; 32];
        for i in 0..self.ledger_count {
            if let Some(entry) = &self.ledger[i] {
                if entry.prev_hash != expected_prev {
                    return false;
                }
                let mut hasher = Sha256::new();
                hasher.update(&entry.entry_id.to_be_bytes());
                hasher.update(&entry.action[..entry.action_len]);
                hasher.update(&entry.target_id.to_be_bytes());
                hasher.update(&entry.result_code.to_be_bytes());
                hasher.update(&entry.timestamp.to_be_bytes());
                hasher.update(&entry.prev_hash);
                let computed = hasher.finalize();
                if computed != entry.entry_hash {
                    return false;
                }
                expected_prev = entry.entry_hash;
            }
        }
        true
    }

    pub fn recalculate_exposure_index(&mut self) {
        if self.asset_count == 0 {
            self.exposure_index = 0;
            return;
        }

        let mut total_risk: u32 = 0;
        for i in 0..self.asset_count {
            if let Some(asset) = &self.assets[i] {
                total_risk += asset.risk_score as u32;
            }
        }

        let mut finding_penalties: u32 = 0;
        for i in 0..self.finding_count {
            if let Some(f) = &self.findings[i] {
                if f.status == FindingStatus::Open {
                    let penalty = match f.severity {
                        FindingSeverity::Critical => 25,
                        FindingSeverity::High => 15,
                        FindingSeverity::Medium => 8,
                        FindingSeverity::Low => 3,
                        FindingSeverity::Info => 1,
                    };
                    finding_penalties += penalty;
                }
            }
        }

        let base_score = total_risk / (self.asset_count as u32);
        let final_score = core::cmp::min(100, base_score + finding_penalties);
        self.exposure_index = final_score as u8;
    }

    pub fn register_asset(
        &mut self,
        cap: &EasmCap,
        name: &str,
        target: &str,
        asset_type: AssetType,
        exposure: ExposureLevel,
        port: u16,
        is_shadow_it: bool,
        tls_valid_days: i16,
        timestamp: u64,
    ) -> Result<u32, EasmError> {
        if !cap.has_right(easm_rights::MANAGE_ASSETS) {
            return Err(EasmError::PermissionDenied);
        }
        if self.asset_count >= self.assets.len() {
            return Err(EasmError::CapacityExceeded);
        }

        let id = self.next_asset_id;
        self.next_asset_id += 1;

        let asset = DiscoveredAsset::new(
            id,
            name,
            target,
            asset_type,
            exposure,
            port,
            is_shadow_it,
            tls_valid_days,
            timestamp,
        );

        self.assets[self.asset_count] = Some(asset);
        self.asset_count += 1;

        self.recalculate_exposure_index();
        self.log_audit_action("ASSET_DISCOVERED", id, 0, timestamp)?;
        Ok(id)
    }

    pub fn add_finding(
        &mut self,
        cap: &EasmCap,
        asset_id: u32,
        title: &str,
        category: FindingCategory,
        severity: FindingSeverity,
        remediation: &str,
        timestamp: u64,
    ) -> Result<u32, EasmError> {
        if !cap.has_right(easm_rights::SCAN_PERIMETER) {
            return Err(EasmError::PermissionDenied);
        }
        if self.finding_count >= self.findings.len() {
            return Err(EasmError::CapacityExceeded);
        }

        // Vérifier l'existence de l'actif
        let mut exists = false;
        for i in 0..self.asset_count {
            if let Some(a) = &self.assets[i] {
                if a.id == asset_id {
                    exists = true;
                    break;
                }
            }
        }
        if !exists {
            return Err(EasmError::AssetNotFound);
        }

        let fid = self.next_finding_id;
        self.next_finding_id += 1;

        let finding = PerimeterFinding::new(
            fid,
            asset_id,
            title,
            category,
            severity,
            remediation,
            timestamp,
        );

        self.findings[self.finding_count] = Some(finding);
        self.finding_count += 1;

        self.recalculate_exposure_index();
        self.log_audit_action("FINDING_DETECTED", fid, 0, timestamp)?;
        Ok(fid)
    }

    pub fn scan_perimeter(
        &mut self,
        cap: &EasmCap,
        timestamp: u64,
    ) -> Result<AttackSurfaceSummary, EasmError> {
        if !cap.has_right(easm_rights::SCAN_PERIMETER) {
            return Err(EasmError::PermissionDenied);
        }

        // Actualiser l'état des actifs
        for i in 0..self.asset_count {
            if let Some(asset) = &mut self.assets[i] {
                asset.last_scanned = timestamp;
                // Si Shadow IT ou certificat expiré, maintenir un risque élevé
                if asset.is_shadow_it {
                    asset.risk_score = core::cmp::max(asset.risk_score, 85);
                } else if asset.tls_valid_days < 0 {
                    asset.risk_score = core::cmp::max(asset.risk_score, 75);
                }
            }
        }

        self.recalculate_exposure_index();
        self.log_audit_action("PERIMETER_SCANNED", 0, self.exposure_index as u16, timestamp)?;
        self.get_summary(cap)
    }

    pub fn remediate_finding(
        &mut self,
        cap: &EasmCap,
        finding_id: u32,
        timestamp: u64,
    ) -> Result<(), EasmError> {
        if !cap.has_right(easm_rights::REMEDIATE_EXPOSURE) {
            return Err(EasmError::PermissionDenied);
        }

        let mut target_asset_id = None;
        let mut found = false;

        for i in 0..self.finding_count {
            if let Some(f) = &mut self.findings[i] {
                if f.id == finding_id {
                    f.status = FindingStatus::Remediated;
                    f.remediated_at = timestamp;
                    target_asset_id = Some(f.asset_id);
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(EasmError::FindingNotFound);
        }

        // Durcir l'actif associé
        if let Some(aid) = target_asset_id {
            for i in 0..self.asset_count {
                if let Some(asset) = &mut self.assets[i] {
                    if asset.id == aid {
                        if asset.is_shadow_it {
                            asset.is_shadow_it = false;
                            asset.exposure = ExposureLevel::RestrictedAccess;
                            asset.risk_score = 15;
                        } else if asset.exposure == ExposureLevel::PublicVulnerable {
                            asset.exposure = ExposureLevel::PublicHardened;
                            asset.risk_score = 20;
                        } else {
                            asset.risk_score = asset.risk_score.saturating_sub(25);
                        }
                    }
                }
            }
        }

        self.recalculate_exposure_index();
        self.log_audit_action("FINDING_REMEDIATED", finding_id, 0, timestamp)?;
        Ok(())
    }

    pub fn get_summary(&self, cap: &EasmCap) -> Result<AttackSurfaceSummary, EasmError> {
        if !cap.has_right(easm_rights::QUERY_SURFACE) {
            return Err(EasmError::PermissionDenied);
        }

        let mut public_count = 0;
        let mut shadow_count = 0;
        for i in 0..self.asset_count {
            if let Some(a) = &self.assets[i] {
                if a.exposure == ExposureLevel::PublicHardened
                    || a.exposure == ExposureLevel::PublicVulnerable
                {
                    public_count += 1;
                }
                if a.is_shadow_it {
                    shadow_count += 1;
                }
            }
        }

        let mut open_findings = 0;
        let mut critical_findings = 0;
        for i in 0..self.finding_count {
            if let Some(f) = &self.findings[i] {
                if f.status == FindingStatus::Open {
                    open_findings += 1;
                    if f.severity == FindingSeverity::Critical {
                        critical_findings += 1;
                    }
                }
            }
        }

        Ok(AttackSurfaceSummary {
            total_assets: self.asset_count,
            public_assets: public_count,
            shadow_it_count: shadow_count,
            open_findings_count: open_findings,
            critical_findings_count: critical_findings,
            exposure_index: self.exposure_index,
        })
    }

    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;
        let now = 1000;

        // Actifs de référence
        let _ = self.register_asset(
            &cap,
            "api-gw",
            "api.jambo.net",
            AssetType::DomainName,
            ExposureLevel::PublicHardened,
            443,
            false,
            180,
            now,
        );

        let _ = self.register_asset(
            &cap,
            "web-portal",
            "portal.jambo.net",
            AssetType::DomainName,
            ExposureLevel::PublicHardened,
            443,
            false,
            90,
            now,
        );

        let shadow_id = self
            .register_asset(
                &cap,
                "dev-admin-portal",
                "dev-admin.jambo.net",
                AssetType::DomainName,
                ExposureLevel::ShadowItOrphaned,
                9090,
                true,
                -10, // Expiré il y a 10 jours
                now,
            )
            .unwrap_or(3);

        let bucket_id = self
            .register_asset(
                &cap,
                "casb-backup-store",
                "storage.casb.jambo.net",
                AssetType::StorageBucket,
                ExposureLevel::PublicVulnerable,
                443,
                false,
                45,
                now,
            )
            .unwrap_or(4);

        let _ = self.register_asset(
            &cap,
            "dns-over-tls",
            "dns.jambo.net",
            AssetType::PortService,
            ExposureLevel::RestrictedAccess,
            853,
            false,
            300,
            now,
        );

        // Vulnérabilités & Expositions initiales
        let _ = self.add_finding(
            &cap,
            shadow_id,
            "Exposed Unauthenticated Admin Portal",
            FindingCategory::ExposedAdminInterface,
            FindingSeverity::Critical,
            "Restreindre port 9090 via Zero-Trust & Walld",
            now + 10,
        );

        let _ = self.add_finding(
            &cap,
            shadow_id,
            "Expired TLS Certificate (-10 days)",
            FindingCategory::ExpiredOrWeakTls,
            FindingSeverity::High,
            "Renouveler certificat PKI souverain",
            now + 15,
        );

        let _ = self.add_finding(
            &cap,
            bucket_id,
            "Publicly Readable Cloud Storage Bucket",
            FindingCategory::ExposedStorageBucket,
            FindingSeverity::High,
            "Appliquer ACL privée CASB & chiffrement ChaCha20",
            now + 20,
        );

        let _ = self.add_finding(
            &cap,
            1,
            "Server Banner Version Leakage",
            FindingCategory::InformationLeakage,
            FindingSeverity::Low,
            "Supprimer header Server dans Jambo-WAF",
            now + 25,
        );

        self.recalculate_exposure_index();
    }
}

// ============================================================================
// SUITE DE TESTS FORMELS & DÉTERMINISTES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_easm_cap_attenuation() {
        let admin_cap = EasmCap::new(Handle::new(13101, 1), easm_rights::ALL, 10000, 500);
        assert!(admin_cap.has_right(easm_rights::DISCOVER_ASSETS));
        assert!(admin_cap.has_right(easm_rights::SCAN_PERIMETER));
        assert!(admin_cap.has_right(easm_rights::QUERY_SURFACE));
        assert!(admin_cap.has_right(easm_rights::MANAGE_ASSETS));
        assert!(admin_cap.has_right(easm_rights::REMEDIATE_EXPOSURE));
        assert!(admin_cap.has_right(easm_rights::EXPORT_INVENTORY));
        assert!(admin_cap.has_right(easm_rights::SEAL_LEDGER));
        assert!(admin_cap.has_right(easm_rights::ADMIN));

        let monitor_cap = admin_cap
            .attenuate(
                easm_rights::QUERY_SURFACE | easm_rights::SCAN_PERIMETER,
                5000,
                100,
            )
            .expect("Atténuation monotone");
        assert!(monitor_cap.has_right(easm_rights::QUERY_SURFACE));
        assert!(monitor_cap.has_right(easm_rights::SCAN_PERIMETER));
        assert!(!monitor_cap.has_right(easm_rights::MANAGE_ASSETS));
        assert!(!monitor_cap.has_right(easm_rights::REMEDIATE_EXPOSURE));
        assert!(!monitor_cap.has_right(easm_rights::ADMIN));

        // Escalade illégale
        assert_eq!(
            monitor_cap.attenuate(easm_rights::ALL, 5000, 100),
            Err(EasmError::AttenuationViolation)
        );
    }

    #[test]
    fn test_asset_discovery_and_inventory() {
        let admin_cap = EasmCap::new(Handle::new(13102, 1), easm_rights::ALL, 10000, 500);
        let mut easm = JamboEasmDaemon::new(admin_cap);

        let a1 = easm.register_asset(
            &admin_cap,
            "main-web",
            "www.jambo.org",
            AssetType::DomainName,
            ExposureLevel::PublicHardened,
            443,
            false,
            120,
            100,
        );
        assert!(a1.is_ok());
        assert_eq!(easm.asset_count, 1);

        let asset = easm.assets[0].unwrap();
        assert_eq!(asset.name_as_str(), "main-web");
        assert_eq!(asset.target_as_str(), "www.jambo.org");
        assert_eq!(asset.exposure, ExposureLevel::PublicHardened);
    }

    #[test]
    fn test_perimeter_scan_and_shadow_it() {
        let admin_cap = EasmCap::new(Handle::new(13103, 1), easm_rights::ALL, 10000, 500);
        let mut easm = JamboEasmDaemon::new(admin_cap);
        easm.init_defaults();

        assert_eq!(easm.asset_count, 5);
        assert_eq!(easm.finding_count, 4);

        let summary = easm.scan_perimeter(&admin_cap, 2000).expect("Scan");
        assert_eq!(summary.total_assets, 5);
        assert_eq!(summary.shadow_it_count, 1);
        assert_eq!(summary.open_findings_count, 4);
        assert_eq!(summary.critical_findings_count, 1);
        assert!(summary.exposure_index > 50); // Risque élevé dû au Shadow IT & failles
    }

    #[test]
    fn test_finding_remediation_and_score_update() {
        let admin_cap = EasmCap::new(Handle::new(13104, 1), easm_rights::ALL, 10000, 500);
        let mut easm = JamboEasmDaemon::new(admin_cap);
        easm.init_defaults();

        let initial_summary = easm.get_summary(&admin_cap).expect("Summary initial");
        let initial_score = initial_summary.exposure_index;

        // Remédier la faille critique (Finding #1 : Admin Portal)
        assert!(easm.remediate_finding(&admin_cap, 1, 3000).is_ok());

        // Remédier la faille TLS (Finding #2 : Expired cert)
        assert!(easm.remediate_finding(&admin_cap, 2, 3005).is_ok());

        // Remédier la faille de stockage (Finding #3 : Cloud Storage Bucket)
        assert!(easm.remediate_finding(&admin_cap, 3, 3010).is_ok());

        // Remédier la fuite de bannière (Finding #4 : Banner)
        assert!(easm.remediate_finding(&admin_cap, 4, 3015).is_ok());

        let post_summary = easm.get_summary(&admin_cap).expect("Summary post");
        assert_eq!(post_summary.open_findings_count, 0);
        assert_eq!(post_summary.critical_findings_count, 0);
        assert!(post_summary.exposure_index < initial_score);
    }

    #[test]
    fn test_audit_ledger_integrity_and_tampering() {
        let admin_cap = EasmCap::new(Handle::new(13105, 1), easm_rights::ALL, 10000, 500);
        let mut easm = JamboEasmDaemon::new(admin_cap);
        easm.init_defaults();

        assert!(easm.verify_ledger_integrity());

        // Altération intentionnelle
        if let Some(entry) = &mut easm.ledger[1] {
            entry.result_code = 999;
        }
        assert!(!easm.verify_ledger_integrity());
    }
}

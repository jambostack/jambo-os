//! Cyber-Déception, Honeypots Haute Fidélité, Canaris Système & Pièges d'Évasion TEE
//!
//! Phase 152 — Jalon v0.3.19
//!
//! Fournit un système souverain de défense par cyber-déception et contre-ingérence en environnement `#![no_std]` :
//! 1. Déploiement dynamique de leurres de haute fidélité (HoneyCaps avec jetons piégés, objets de mémoire VMO
//!    délibérément vulnérables avec faux secrets déchiffrés, fausses clés privées Ring 3 Ed25519/AES-XTS).
//! 2. Détection en temps constant O(1) de mouvements latéraux (`LateralMovementDecoy`) et canaris d'infrastructure.
//! 3. Pièges d'évasion d'enclaves matérielles TEE (SEV-SNP VMSA poisoning, Intel TDX #VE handler tamper, SGX EPC breaches).
//! 4. Notification immédiate O(1) vers XDR/SOAR avec corrélation MITRE ATT&CK et recommandations de confinement coordonnées.
//! 5. Profilage comportemental progressif des attaquants (scores de menace cumulatifs 0..100, classification APT, quarantaine automatique).
//! 6. Contrôle d'accès capabilaire strict (`DeceptionCap`) sans autorité ambiante avec atténuation monotone.
//! 7. Scellement cryptographique d'audit inviolable par chaînage SHA-256 déterministe.

#![no_std]

use libjambo::Handle;

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation déterministe et autonome de SHA-256 (#![no_std])
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
        let mut offset = 0;
        self.total_bytes += data.len() as u64;

        if self.buffer_len > 0 {
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

        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            self.transform_block(&block);
            offset += 64;
        }

        if offset < data.len() {
            let chunk = data.len() - offset;
            self.buffer[..chunk].copy_from_slice(&data[offset..]);
            self.buffer_len = chunk;
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
// CONTRÔLE D'ACCÈS CAPABILAIRE (DeceptionCap)
// ============================================================================

pub mod deception_rights {
    pub const DEPLOY_DECOY: u32 = 0x0001;
    pub const TRIGGER_ALERT: u32 = 0x0002;
    pub const PROBE_DECOY: u32 = 0x0004;
    pub const PROFILE_ATTACKER: u32 = 0x0008;
    pub const QUARANTINE: u32 = 0x0010;
    pub const SEAL_LEDGER: u32 = 0x0020;
    pub const AUDIT_READ: u32 = 0x0040;
    pub const XDR_DISPATCH: u32 = 0x0080;
    pub const TEE_TRAP_MANAGE: u32 = 0x0100;
    pub const ADMIN: u32 = 0x0200;
    pub const ALL: u32 = 0x03FF;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeceptionError {
    PermissionDenied,
    AttenuationViolation,
    DecoyTableFull,
    DecoyNotFound,
    ProfileTableFull,
    AlertTableFull,
    AuditLogFull,
    XdrQueueFull,
    InvalidParameter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeceptionCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl DeceptionCap {
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
    ) -> Result<Self, DeceptionError> {
        if (rights_mask & !self.rights) != 0 {
            return Err(DeceptionError::AttenuationViolation);
        }
        if lifetime > self.max_lifetime || invocations > self.invocations_left {
            return Err(DeceptionError::AttenuationViolation);
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
// DÉFINITION DES LEURRES, CANARIS & MENACES
// ============================================================================

/// Type de leurre / canari déployé dans le système
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyKind {
    /// Faux jeton de capacité (ex: faux RootCap, faux MasterKeyCap)
    HoneyCap,
    /// Objet de mémoire VMO délibérément vulnérable (faux identifiants, fausse table de pages)
    VmoDecoy,
    /// Faux secret Ring 3 (ex: clé privée Ed25519 leurre, secret de chiffrement AES-XTS)
    Ring3FakeKey,
    /// Faux endpoint IPC/RPC silencieux ("sys.crypto.master", "cluster.admin.rpc")
    IpcEndpointDecoy,
    /// Piège à évasion d'enclave TEE / SGX / TDX (détection d'exploitation hyperviseur)
    EnclaveTrapDecoy,
    /// Fichier canari VFS hautement attractif ("/etc/master.key", "/etc/shadow.bak")
    CanaryFileDecoy,
    /// Leurre de mouvement latéral réseau / maillage ("mesh://cluster/node9/admin")
    LateralMovementDecoy,
}

impl DecoyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HoneyCap => "HoneyCap",
            Self::VmoDecoy => "VmoDecoy",
            Self::Ring3FakeKey => "Ring3FakeKey",
            Self::IpcEndpointDecoy => "IpcEndpointDecoy",
            Self::EnclaveTrapDecoy => "EnclaveTrapDecoy",
            Self::CanaryFileDecoy => "CanaryFileDecoy",
            Self::LateralMovementDecoy => "LateralMovementDecoy",
        }
    }
}

/// Action de sonde ou d'attaque déclenchant le piège
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAction {
    InvokeHoneyCap,
    ReadVmoMemory,
    WriteVmoMemory,
    IpcConnect,
    EnclaveEscapeAttempt,
    FileAccess,
    LateralMovementScan,
    FakeKeyExfiltration,
    TeeVmsaTamper,
}

impl ProbeAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvokeHoneyCap => "InvokeHoneyCap",
            Self::ReadVmoMemory => "ReadVmoMemory",
            Self::WriteVmoMemory => "WriteVmoMemory",
            Self::IpcConnect => "IpcConnect",
            Self::EnclaveEscapeAttempt => "EnclaveEscapeAttempt",
            Self::FileAccess => "FileAccess",
            Self::LateralMovementScan => "LateralMovementScan",
            Self::FakeKeyExfiltration => "FakeKeyExfiltration",
            Self::TeeVmsaTamper => "TeeVmsaTamper",
        }
    }
}

/// Sévérité de la menace associée au leurre
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Niveau de dangerosité comportementale de l'attaquant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackerLevel {
    Benign,
    Reconnaissance,
    ActiveProbe,
    LateralMovement,
    PrivilegeEscalation,
    EnclaveEscapeAttempt,
    HighRiskAPT,
}

impl AttackerLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Benign => "Benign",
            Self::Reconnaissance => "Reconnaissance",
            Self::ActiveProbe => "ActiveProbe",
            Self::LateralMovement => "LateralMovement",
            Self::PrivilegeEscalation => "PrivilegeEscalation",
            Self::EnclaveEscapeAttempt => "EnclaveEscapeAttempt",
            Self::HighRiskAPT => "HighRiskAPT",
        }
    }
}

/// Vecteurs d'évasion d'enclaves matérielles TEE protégées
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeTrapVector {
    /// Altération de la zone de sauvegarde VMSA AMD SEV-SNP
    SevSnpVmsaPoisoning,
    /// Interception ou détournement du gestionnaire d'exception de virtualisation #VE Intel TDX
    TdxVeHandlerTamper,
    /// Violation des frontières de pages chiffrées EPC Intel SGX
    SgxEnclavePageBreach,
    /// Accès illicite aux registres MMIO virtuels piégés de l'enclave
    TeeMmioTrap,
}

impl TeeTrapVector {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SevSnpVmsaPoisoning => "AMD-SEV-SNP/VMSA-Poisoning",
            Self::TdxVeHandlerTamper => "Intel-TDX/#VE-Handler-Tamper",
            Self::SgxEnclavePageBreach => "Intel-SGX/EPC-PageBreach",
            Self::TeeMmioTrap => "TEE/MMIO-VirtualTrap",
        }
    }
}

/// Actions de confinement recommandées pour transmission XDR/SOAR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeceptionContainmentAction {
    NoAction,
    MonitorAndTrace,
    ImmediateProcessQuarantine,
    IsolateEnclave,
    RevokeHoneyCap,
    BlockLateralSubnet,
}

impl DeceptionContainmentAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoAction => "NO_ACTION",
            Self::MonitorAndTrace => "MONITOR_AND_TRACE",
            Self::ImmediateProcessQuarantine => "IMMEDIATE_PROCESS_QUARANTINE",
            Self::IsolateEnclave => "ISOLATE_ENCLAVE",
            Self::RevokeHoneyCap => "REVOKE_HONEY_CAP",
            Self::BlockLateralSubnet => "BLOCK_LATERAL_SUBNET",
        }
    }
}

/// Charge utile haute fidélité associée à un leurre
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoyPayload {
    pub data: [u8; 64],
    pub data_len: usize,
    pub canary_tag: u64,
    pub trap_action_mask: u32,
}

impl DecoyPayload {
    pub const fn empty() -> Self {
        Self {
            data: [0u8; 64],
            data_len: 0,
            canary_tag: 0,
            trap_action_mask: 0,
        }
    }

    pub fn new(bait_str: &str, canary_tag: u64, trap_mask: u32) -> Self {
        let mut data = [0u8; 64];
        let bytes = bait_str.as_bytes();
        let len = bytes.len().min(64);
        data[..len].copy_from_slice(&bytes[..len]);
        Self {
            data,
            data_len: len,
            canary_tag,
            trap_action_mask: trap_mask,
        }
    }

    pub fn data_as_str(&self) -> &str {
        core::str::from_utf8(&self.data[..self.data_len]).unwrap_or("")
    }
}

/// Entrée de leurre enregistrée dans la table des pièges
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoyEntry {
    pub id: u32,
    pub kind: DecoyKind,
    pub name: [u8; 32],
    pub name_len: usize,
    pub location: [u8; 48],
    pub location_len: usize,
    pub created_tick: u64,
    pub severity: ThreatSeverity,
    pub silent_alarm: bool,
    pub active: bool,
    pub hit_count: u32,
    pub payload: DecoyPayload,
}

impl DecoyEntry {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("unknown")
    }

    pub fn location_as_str(&self) -> &str {
        core::str::from_utf8(&self.location[..self.location_len]).unwrap_or("unknown")
    }
}

/// Alerte instantanée générée par le déclenchement d'un canari
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeceptionAlert {
    pub alert_id: u64,
    pub timestamp: u64,
    pub decoy_id: u32,
    pub decoy_kind: DecoyKind,
    pub attacker_source: u64,
    pub action: ProbeAction,
    pub severity: ThreatSeverity,
    pub silent: bool,
    pub canary_breached: bool,
}

/// Notification en temps constant O(1) transmise à XDR / SOAR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdrDeceptionNotification {
    pub dispatch_id: u64,
    pub timestamp: u64,
    pub decoy_id: u32,
    pub attacker_source: u64,
    pub decoy_kind: DecoyKind,
    pub probe_action: ProbeAction,
    pub severity: ThreatSeverity,
    pub mitre_technique: [u8; 12],
    pub mitre_len: usize,
    pub recommended_action: DeceptionContainmentAction,
    pub dispatched: bool,
}

impl XdrDeceptionNotification {
    pub fn mitre_as_str(&self) -> &str {
        core::str::from_utf8(&self.mitre_technique[..self.mitre_len]).unwrap_or("T0000")
    }
}

/// Fiche de profilage comportemental de l'attaquant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackerProfile {
    pub source_id: u64,
    pub first_seen_tick: u64,
    pub last_seen_tick: u64,
    pub hit_count: u32,
    pub threat_score: u32,
    pub level: AttackerLevel,
    pub quarantined: bool,
    pub last_decoy_id: u32,
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SHA-256 SCELLEMENT INVIOLABLE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    DeployDecoy,
    TripwireFired,
    AttackerProfiled,
    QuarantineEnacted,
    DecoyDeactivated,
    LedgerSealed,
    XdrAlertDispatched,
    TeeTrapTriggered,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeployDecoy => "DeployDecoy",
            Self::TripwireFired => "TripwireFired",
            Self::AttackerProfiled => "AttackerProfiled",
            Self::QuarantineEnacted => "QuarantineEnacted",
            Self::DecoyDeactivated => "DecoyDeactivated",
            Self::LedgerSealed => "LedgerSealed",
            Self::XdrAlertDispatched => "XdrAlertDispatched",
            Self::TeeTrapTriggered => "TeeTrapTriggered",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub action: AuditAction,
    pub target_id: u64,
    pub detail: [u8; 32],
    pub detail_len: usize,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

// ============================================================================
// DÉMON CENTRAL DE CYBER-DÉCEPTION (`JamboDeceptionDaemon`)
// ============================================================================

pub struct JamboDeceptionDaemon {
    pub admin_cap: DeceptionCap,
    pub decoys: [Option<DecoyEntry>; 32],
    pub decoy_count: usize,
    pub next_decoy_id: u32,
    pub alerts: [Option<DeceptionAlert>; 64],
    pub alert_count: usize,
    pub next_alert_id: u64,
    pub profiles: [Option<AttackerProfile>; 16],
    pub profile_count: usize,
    pub audit_log: [Option<AuditEntry>; 64],
    pub audit_count: usize,
    pub ledger_hash: [u8; 32],
    pub total_probes: u64,
    pub total_quarantines: u64,
    pub xdr_dispatches: [Option<XdrDeceptionNotification>; 32],
    pub xdr_dispatch_count: usize,
    pub next_dispatch_id: u64,
    pub total_xdr_notifications: u64,
    pub tee_traps_fired: u32,
}

impl JamboDeceptionDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0x5A; 32];

    pub fn new(admin_cap: DeceptionCap) -> Self {
        Self {
            admin_cap,
            decoys: [None; 32],
            decoy_count: 0,
            next_decoy_id: 1,
            alerts: [None; 64],
            alert_count: 0,
            next_alert_id: 1,
            profiles: [None; 16],
            profile_count: 0,
            audit_log: [None; 64],
            audit_count: 0,
            ledger_hash: Self::GENESIS_HASH,
            total_probes: 0,
            total_quarantines: 0,
            xdr_dispatches: [None; 32],
            xdr_dispatch_count: 0,
            next_dispatch_id: 1,
            total_xdr_notifications: 0,
            tee_traps_fired: 0,
        }
    }

    /// Journalise une action dans le registre immuable chaîné par SHA-256
    fn append_audit(
        &mut self,
        timestamp: u64,
        action: AuditAction,
        target_id: u64,
        detail_str: &str,
    ) {
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
        hasher.update(&target_id.to_be_bytes());
        hasher.update(&detail[..len]);
        let entry_hash = hasher.finalize();

        let entry = AuditEntry {
            timestamp,
            action,
            target_id,
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
                hasher.update(&entry.target_id.to_be_bytes());
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

    /// Déploie un nouveau leurre ou canari dans le système
    pub fn deploy_decoy(
        &mut self,
        cap: &DeceptionCap,
        name: &str,
        kind: DecoyKind,
        location: &str,
        severity: ThreatSeverity,
        current_tick: u64,
    ) -> Result<u32, DeceptionError> {
        self.deploy_decoy_with_payload(
            cap,
            name,
            kind,
            location,
            severity,
            DecoyPayload::empty(),
            current_tick,
        )
    }

    /// Déploie un nouveau leurre avec charge utile et canari cryptographique
    pub fn deploy_decoy_with_payload(
        &mut self,
        cap: &DeceptionCap,
        name: &str,
        kind: DecoyKind,
        location: &str,
        severity: ThreatSeverity,
        payload: DecoyPayload,
        current_tick: u64,
    ) -> Result<u32, DeceptionError> {
        if !cap.has_right(deception_rights::DEPLOY_DECOY) {
            return Err(DeceptionError::PermissionDenied);
        }
        if self.decoy_count >= self.decoys.len() {
            return Err(DeceptionError::DecoyTableFull);
        }

        let mut name_buf = [0u8; 32];
        let nbytes = name.as_bytes();
        let nlen = nbytes.len().min(32);
        name_buf[..nlen].copy_from_slice(&nbytes[..nlen]);

        let mut loc_buf = [0u8; 48];
        let lbytes = location.as_bytes();
        let llen = lbytes.len().min(48);
        loc_buf[..llen].copy_from_slice(&lbytes[..llen]);

        let id = self.next_decoy_id;
        self.next_decoy_id = self.next_decoy_id.saturating_add(1);

        let entry = DecoyEntry {
            id,
            kind,
            name: name_buf,
            name_len: nlen,
            location: loc_buf,
            location_len: llen,
            created_tick: current_tick,
            severity,
            silent_alarm: true,
            active: true,
            hit_count: 0,
            payload,
        };

        self.decoys[self.decoy_count] = Some(entry);
        self.decoy_count += 1;

        self.append_audit(current_tick, AuditAction::DeployDecoy, id as u64, name);
        Ok(id)
    }

    /// Génère dynamiquement un faux jeton de capacité (HoneyCap)
    pub fn generate_honey_cap(
        &mut self,
        cap: &DeceptionCap,
        name: &str,
        fake_slot: u32,
        canary_tag: u64,
        current_tick: u64,
    ) -> Result<u32, DeceptionError> {
        let payload = DecoyPayload::new("HONEY_CAP_TRAP_SLOT", canary_tag, 0x01);
        let mut loc_buf = [0u8; 48];
        let prefix = b"cspace://slot/0x";
        loc_buf[..prefix.len()].copy_from_slice(prefix);
        let mut b = [0u8; 10];
        let slot_str = format_u32_hex(fake_slot, &mut b);
        let slot_bytes = slot_str.as_bytes();
        let total_len = prefix.len() + slot_bytes.len();
        loc_buf[prefix.len()..total_len].copy_from_slice(slot_bytes);
        let loc_str = core::str::from_utf8(&loc_buf[..total_len]).unwrap_or("cspace://slot/trap");

        self.deploy_decoy_with_payload(
            cap,
            name,
            DecoyKind::HoneyCap,
            loc_str,
            ThreatSeverity::Critical,
            payload,
            current_tick,
        )
    }

    /// Déploie un faux secret Ring 3 (ex: clé privée Ed25519 ou secret de coffre)
    pub fn generate_fake_secret(
        &mut self,
        cap: &DeceptionCap,
        name: &str,
        secret_content: &str,
        location: &str,
        canary_tag: u64,
        current_tick: u64,
    ) -> Result<u32, DeceptionError> {
        let payload = DecoyPayload::new(secret_content, canary_tag, 0x02);
        self.deploy_decoy_with_payload(
            cap,
            name,
            DecoyKind::Ring3FakeKey,
            location,
            ThreatSeverity::Critical,
            payload,
            current_tick,
        )
    }

    /// Déploie un leurre mémoire VMO piégé
    pub fn generate_trapped_vmo(
        &mut self,
        cap: &DeceptionCap,
        name: &str,
        vmo_name: &str,
        canary_tag: u64,
        current_tick: u64,
    ) -> Result<u32, DeceptionError> {
        let payload = DecoyPayload::new("VMO_POISON_PAGE_DATA", canary_tag, 0x04);
        self.deploy_decoy_with_payload(
            cap,
            name,
            DecoyKind::VmoDecoy,
            vmo_name,
            ThreatSeverity::High,
            payload,
            current_tick,
        )
    }

    /// Déploie un piège d'évasion d'enclave matérielle TEE
    pub fn deploy_tee_trap(
        &mut self,
        cap: &DeceptionCap,
        enclave_id: u32,
        vector: TeeTrapVector,
        current_tick: u64,
    ) -> Result<u32, DeceptionError> {
        if !cap.has_right(deception_rights::TEE_TRAP_MANAGE) {
            return Err(DeceptionError::PermissionDenied);
        }
        let payload = DecoyPayload::new(vector.as_str(), enclave_id as u64, 0x08);
        self.deploy_decoy_with_payload(
            cap,
            vector.as_str(),
            DecoyKind::EnclaveTrapDecoy,
            "tee://enclave/trap_vector",
            ThreatSeverity::Critical,
            payload,
            current_tick,
        )
    }

    /// Déploie un leurre pour la détection de mouvements latéraux
    pub fn deploy_lateral_decoy(
        &mut self,
        cap: &DeceptionCap,
        name: &str,
        endpoint_uri: &str,
        current_tick: u64,
    ) -> Result<u32, DeceptionError> {
        let payload = DecoyPayload::new("LATERAL_PROBE_INTERCEPT", 0xCAFE_BABE, 0x10);
        self.deploy_decoy_with_payload(
            cap,
            name,
            DecoyKind::LateralMovementDecoy,
            endpoint_uri,
            ThreatSeverity::High,
            payload,
            current_tick,
        )
    }

    /// Déclenchement d'un canari / fil-piège (Tripwire) en temps constant O(1)
    /// L'alerte est silencieuse et enregistrée sans notifier le processus sondé.
    pub fn trigger_decoy(
        &mut self,
        cap: &DeceptionCap,
        decoy_id: u32,
        attacker_source: u64,
        action: ProbeAction,
        current_tick: u64,
    ) -> Result<DeceptionAlert, DeceptionError> {
        if !cap.has_right(deception_rights::TRIGGER_ALERT) {
            return Err(DeceptionError::PermissionDenied);
        }

        let mut found_decoy = None;
        for i in 0..self.decoy_count {
            if let Some(ref mut d) = self.decoys[i] {
                if d.id == decoy_id && d.active {
                    d.hit_count = d.hit_count.saturating_add(1);
                    found_decoy = Some(*d);
                    break;
                }
            }
        }

        let decoy = found_decoy.ok_or(DeceptionError::DecoyNotFound)?;

        self.total_probes = self.total_probes.saturating_add(1);

        let alert_id = self.next_alert_id;
        self.next_alert_id = self.next_alert_id.saturating_add(1);

        let canary_breached = decoy.payload.canary_tag != 0;

        let alert = DeceptionAlert {
            alert_id,
            timestamp: current_tick,
            decoy_id,
            decoy_kind: decoy.kind,
            attacker_source,
            action,
            severity: decoy.severity,
            silent: decoy.silent_alarm,
            canary_breached,
        };

        if self.alert_count < self.alerts.len() {
            self.alerts[self.alert_count] = Some(alert);
            self.alert_count += 1;
        }

        // Mise à jour ou création du profil comportemental de l'attaquant
        self.update_attacker_profile(attacker_source, decoy, action, current_tick);

        // Envoi automatique d'une notification à destination de XDR/SOAR
        self.queue_xdr_notification(decoy, attacker_source, action, current_tick);

        self.append_audit(
            current_tick,
            AuditAction::TripwireFired,
            decoy_id as u64,
            decoy.name_as_str(),
        );

        Ok(alert)
    }

    /// Déclenchement d'un piège d'évasion d'enclave matérielle TEE
    pub fn trigger_tee_escape_trap(
        &mut self,
        cap: &DeceptionCap,
        decoy_id: u32,
        vector: TeeTrapVector,
        attacker_source: u64,
        current_tick: u64,
    ) -> Result<DeceptionAlert, DeceptionError> {
        self.tee_traps_fired = self.tee_traps_fired.saturating_add(1);
        self.append_audit(
            current_tick,
            AuditAction::TeeTrapTriggered,
            decoy_id as u64,
            vector.as_str(),
        );
        self.trigger_decoy(
            cap,
            decoy_id,
            attacker_source,
            ProbeAction::EnclaveEscapeAttempt,
            current_tick,
        )
    }

    /// Mise à jour du profil comportemental avec calcul de score de menace cumulatif
    fn update_attacker_profile(
        &mut self,
        source_id: u64,
        decoy: DecoyEntry,
        action: ProbeAction,
        current_tick: u64,
    ) {
        let score_increment = match decoy.kind {
            DecoyKind::EnclaveTrapDecoy => 50,
            DecoyKind::HoneyCap => 35,
            DecoyKind::Ring3FakeKey => 40,
            DecoyKind::IpcEndpointDecoy => 30,
            DecoyKind::LateralMovementDecoy => 35,
            DecoyKind::VmoDecoy => 25,
            DecoyKind::CanaryFileDecoy => 20,
        };

        // Recherche d'un profil existant
        let mut idx = None;
        for i in 0..self.profile_count {
            if let Some(ref p) = self.profiles[i] {
                if p.source_id == source_id {
                    idx = Some(i);
                    break;
                }
            }
        }

        if let Some(i) = idx {
            if let Some(ref mut p) = self.profiles[i] {
                p.last_seen_tick = current_tick;
                p.hit_count = p.hit_count.saturating_add(1);
                p.threat_score = (p.threat_score + score_increment).min(100);
                p.last_decoy_id = decoy.id;

                if action == ProbeAction::EnclaveEscapeAttempt
                    || action == ProbeAction::TeeVmsaTamper
                {
                    p.level = AttackerLevel::EnclaveEscapeAttempt;
                } else if action == ProbeAction::LateralMovementScan {
                    p.level = AttackerLevel::LateralMovement;
                } else if action == ProbeAction::InvokeHoneyCap {
                    p.level = AttackerLevel::PrivilegeEscalation;
                } else if p.threat_score >= 80 {
                    p.level = AttackerLevel::HighRiskAPT;
                } else if p.threat_score >= 50 {
                    p.level = AttackerLevel::ActiveProbe;
                } else {
                    p.level = AttackerLevel::Reconnaissance;
                }

                // Déclenchement automatique de la mise en quarantaine si seuil franchi
                if p.threat_score >= 70 && !p.quarantined {
                    p.quarantined = true;
                    self.total_quarantines = self.total_quarantines.saturating_add(1);
                    self.append_audit(
                        current_tick,
                        AuditAction::QuarantineEnacted,
                        source_id,
                        "AUTO_QUARANTINE_APT",
                    );
                }
            }
        } else if self.profile_count < self.profiles.len() {
            let initial_score = score_increment.min(100);
            let initial_level = if action == ProbeAction::EnclaveEscapeAttempt
                || action == ProbeAction::TeeVmsaTamper
            {
                AttackerLevel::EnclaveEscapeAttempt
            } else if action == ProbeAction::LateralMovementScan {
                AttackerLevel::LateralMovement
            } else if action == ProbeAction::InvokeHoneyCap {
                AttackerLevel::PrivilegeEscalation
            } else if initial_score >= 50 {
                AttackerLevel::ActiveProbe
            } else {
                AttackerLevel::Reconnaissance
            };
            let quarantined = initial_score >= 70;

            let p = AttackerProfile {
                source_id,
                first_seen_tick: current_tick,
                last_seen_tick: current_tick,
                hit_count: 1,
                threat_score: initial_score,
                level: initial_level,
                quarantined,
                last_decoy_id: decoy.id,
            };

            if quarantined {
                self.total_quarantines = self.total_quarantines.saturating_add(1);
                self.append_audit(
                    current_tick,
                    AuditAction::QuarantineEnacted,
                    source_id,
                    "AUTO_QUARANTINE_NEW_ACTOR",
                );
            }

            self.profiles[self.profile_count] = Some(p);
            self.profile_count += 1;
            self.append_audit(
                current_tick,
                AuditAction::AttackerProfiled,
                source_id,
                "PROFILE_CREATED",
            );
        }
    }

    /// Enfile une notification O(1) prête pour ingestion par XDR / SOAR
    fn queue_xdr_notification(
        &mut self,
        decoy: DecoyEntry,
        attacker_source: u64,
        action: ProbeAction,
        current_tick: u64,
    ) {
        if self.xdr_dispatch_count >= self.xdr_dispatches.len() {
            return;
        }

        let (mitre, rec_action) = match (decoy.kind, action) {
            (DecoyKind::EnclaveTrapDecoy, _) => (
                b"T1211\0\0\0\0\0\0\0",
                DeceptionContainmentAction::IsolateEnclave,
            ),
            (DecoyKind::HoneyCap, _) => (
                b"T1078\0\0\0\0\0\0\0",
                DeceptionContainmentAction::RevokeHoneyCap,
            ),
            (DecoyKind::LateralMovementDecoy, _) => (
                b"T1021\0\0\0\0\0\0\0",
                DeceptionContainmentAction::BlockLateralSubnet,
            ),
            (DecoyKind::Ring3FakeKey, _) => (
                b"T1552\0\0\0\0\0\0\0",
                DeceptionContainmentAction::ImmediateProcessQuarantine,
            ),
            (DecoyKind::VmoDecoy, _) => (
                b"T1055\0\0\0\0\0\0\0",
                DeceptionContainmentAction::ImmediateProcessQuarantine,
            ),
            _ => (
                b"T1000\0\0\0\0\0\0\0",
                DeceptionContainmentAction::MonitorAndTrace,
            ),
        };

        let mut mitre_buf = [0u8; 12];
        mitre_buf[..7].copy_from_slice(&mitre[..7]);

        let notif = XdrDeceptionNotification {
            dispatch_id: self.next_dispatch_id,
            timestamp: current_tick,
            decoy_id: decoy.id,
            attacker_source,
            decoy_kind: decoy.kind,
            probe_action: action,
            severity: decoy.severity,
            mitre_technique: mitre_buf,
            mitre_len: 5,
            recommended_action: rec_action,
            dispatched: false,
        };

        self.next_dispatch_id = self.next_dispatch_id.saturating_add(1);
        self.xdr_dispatches[self.xdr_dispatch_count] = Some(notif);
        self.xdr_dispatch_count += 1;
        self.total_xdr_notifications = self.total_xdr_notifications.saturating_add(1);
    }

    /// Récupère et dépile la prochaine notification en attente vers XDR/SOAR
    pub fn pop_pending_xdr_notification(
        &mut self,
        cap: &DeceptionCap,
    ) -> Result<Option<XdrDeceptionNotification>, DeceptionError> {
        if !cap.has_right(deception_rights::XDR_DISPATCH) {
            return Err(DeceptionError::PermissionDenied);
        }

        for i in 0..self.xdr_dispatch_count {
            if let Some(ref mut notif) = self.xdr_dispatches[i] {
                if !notif.dispatched {
                    notif.dispatched = true;
                    return Ok(Some(*notif));
                }
            }
        }
        Ok(None)
    }

    /// Récupère la fiche de profilage d'un attaquant identifié
    pub fn get_attacker_profile(&self, source_id: u64) -> Option<&AttackerProfile> {
        for i in 0..self.profile_count {
            if let Some(ref p) = self.profiles[i] {
                if p.source_id == source_id {
                    return Some(p);
                }
            }
        }
        None
    }

    /// Confinement et quarantaine manuelle immédiate d'un processus suspect
    pub fn quarantine_attacker(
        &mut self,
        cap: &DeceptionCap,
        source_id: u64,
        current_tick: u64,
    ) -> Result<bool, DeceptionError> {
        if !cap.has_right(deception_rights::QUARANTINE) {
            return Err(DeceptionError::PermissionDenied);
        }

        for i in 0..self.profile_count {
            if let Some(ref mut p) = self.profiles[i] {
                if p.source_id == source_id {
                    if !p.quarantined {
                        p.quarantined = true;
                        p.threat_score = 100;
                        p.level = AttackerLevel::HighRiskAPT;
                        self.total_quarantines = self.total_quarantines.saturating_add(1);
                        self.append_audit(
                            current_tick,
                            AuditAction::QuarantineEnacted,
                            source_id,
                            "MANUAL_QUARANTINE_CAP",
                        );
                        return Ok(true);
                    }
                    return Ok(false);
                }
            }
        }
        Err(DeceptionError::InvalidParameter)
    }

    /// Désactive un leurre existant
    pub fn deactivate_decoy(
        &mut self,
        cap: &DeceptionCap,
        decoy_id: u32,
        current_tick: u64,
    ) -> Result<(), DeceptionError> {
        if !cap.has_right(deception_rights::DEPLOY_DECOY) {
            return Err(DeceptionError::PermissionDenied);
        }

        for i in 0..self.decoy_count {
            if let Some(ref mut d) = self.decoys[i] {
                if d.id == decoy_id {
                    d.active = false;
                    self.append_audit(
                        current_tick,
                        AuditAction::DecoyDeactivated,
                        decoy_id as u64,
                        "DECOY_DEACTIVATED",
                    );
                    return Ok(());
                }
            }
        }
        Err(DeceptionError::DecoyNotFound)
    }

    /// Déploie les canaris et leurres souverains par défaut (Phase 152)
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. HoneyCap : Faux jeton RootCap appâtant les requêtes d'escalade
        let _ = self.deploy_decoy(
            &cap,
            "HoneyCap-Root",
            DecoyKind::HoneyCap,
            "cspace://slot/0xDEAD",
            ThreatSeverity::Critical,
            100,
        );

        // 2. VMO Decoy : Mémoire leurre avec faux secrets déchiffrés
        let _ = self.deploy_decoy(
            &cap,
            "DecoyVmo-ShadowVault",
            DecoyKind::VmoDecoy,
            "vmo://sec/vault_cache",
            ThreatSeverity::High,
            110,
        );

        // 3. Faux endpoint IPC/RPC administratif
        let _ = self.deploy_decoy(
            &cap,
            "DecoyRpc-MasterKey",
            DecoyKind::IpcEndpointDecoy,
            "ipc://sys.crypto.master",
            ThreatSeverity::High,
            120,
        );

        // 4. Piège à évasion d'enclave TEE / Hyperviseur
        let _ = self.deploy_decoy(
            &cap,
            "EnclaveTrap-EscapePoint",
            DecoyKind::EnclaveTrapDecoy,
            "tee://enclave/0/trap_page",
            ThreatSeverity::Critical,
            130,
        );

        // 5. Canari de fichier VFS attractif
        let _ = self.deploy_decoy(
            &cap,
            "CanaryFile-ShadowBak",
            DecoyKind::CanaryFileDecoy,
            "/etc/shadow.bak",
            ThreatSeverity::Critical,
            140,
        );

        // 6. Fausse clé privée Ring 3 (Ed25519)
        let _ = self.generate_fake_secret(
            &cap,
            "FakeSecret-Ed25519Root",
            "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgDEADBEEFCAFEBABE",
            "sec://ring3/ed25519_root.key",
            0xDECA_FBAD,
            150,
        );

        // 7. Leurre de mouvement latéral réseau / maillage
        let _ = self.deploy_lateral_decoy(
            &cap,
            "LateralDecoy-ClusterNode9",
            "mesh://cluster/node9/admin",
            160,
        );
    }
}

// ============================================================================
// FORMATTEURS UTILITAIRES NO_STD
// ============================================================================

fn format_u32_hex<'a>(mut val: u32, buf: &'a mut [u8; 10]) -> &'a str {
    if val == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap_or("0");
    }
    let hex_chars = b"0123456789abcdef";
    let mut i = 0;
    let mut temp = [0u8; 8];
    while val > 0 && i < 8 {
        temp[i] = hex_chars[(val & 0xF) as usize];
        val >>= 4;
        i += 1;
    }
    for j in 0..i {
        buf[j] = temp[i - 1 - j];
    }
    core::str::from_utf8(&buf[..i]).unwrap_or("0")
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deception_cap_attenuation() {
        let admin = DeceptionCap::new(Handle::new(15201, 1), deception_rights::ALL, 5000, 100);
        assert!(admin.has_right(deception_rights::DEPLOY_DECOY));
        assert!(admin.has_right(deception_rights::TRIGGER_ALERT));
        assert!(admin.has_right(deception_rights::QUARANTINE));
        assert!(admin.has_right(deception_rights::XDR_DISPATCH));
        assert!(admin.has_right(deception_rights::TEE_TRAP_MANAGE));
        assert!(admin.has_right(deception_rights::ADMIN));

        // Atténuation monotone
        let monitor = admin
            .attenuate(
                deception_rights::TRIGGER_ALERT | deception_rights::AUDIT_READ,
                2000,
                50,
            )
            .expect("Atténuation");
        assert!(monitor.has_right(deception_rights::TRIGGER_ALERT));
        assert!(monitor.has_right(deception_rights::AUDIT_READ));
        assert!(!monitor.has_right(deception_rights::DEPLOY_DECOY));
        assert!(!monitor.has_right(deception_rights::ADMIN));
        assert!(!monitor.has_right(deception_rights::XDR_DISPATCH));

        // Rejet d'escalade
        let esc = monitor.attenuate(deception_rights::ALL, 2000, 50);
        assert_eq!(esc, Err(DeceptionError::AttenuationViolation));
    }

    #[test]
    fn test_daemon_initialization_and_tripwire() {
        let admin = DeceptionCap::new(Handle::new(15202, 1), deception_rights::ALL, 5000, 100);
        let mut daemon = JamboDeceptionDaemon::new(admin);
        daemon.init_defaults();

        assert_eq!(daemon.decoy_count, 7);
        assert_eq!(daemon.total_probes, 0);
        assert!(daemon.verify_ledger_integrity());

        // Attaquant PID 4001 sonde le faux RootCap (HoneyCap #1)
        let alert1 = daemon
            .trigger_decoy(&admin, 1, 4001, ProbeAction::InvokeHoneyCap, 200)
            .expect("Trigger HoneyCap");
        assert_eq!(alert1.decoy_id, 1);
        assert_eq!(alert1.attacker_source, 4001);
        assert_eq!(alert1.severity, ThreatSeverity::Critical);
        assert!(alert1.silent);

        // Profilage de l'attaquant
        let profile1 = daemon.get_attacker_profile(4001).expect("Profil 4001");
        assert_eq!(profile1.hit_count, 1);
        assert_eq!(profile1.threat_score, 35);
        assert_eq!(profile1.level, AttackerLevel::PrivilegeEscalation);
        assert!(!profile1.quarantined);

        // Attaquant PID 4001 déclenche maintenant le leurre RPC (Decoy #3)
        let _alert2 = daemon
            .trigger_decoy(&admin, 3, 4001, ProbeAction::IpcConnect, 210)
            .expect("Trigger RPC Decoy");
        let profile2 = daemon.get_attacker_profile(4001).expect("Profil 4001");
        assert_eq!(profile2.hit_count, 2);
        assert_eq!(profile2.threat_score, 65);
        assert_eq!(profile2.level, AttackerLevel::ActiveProbe);

        // Attaquant déclenche le leurre VMO (Decoy #2) -> score dépasse 70 -> quarantaine automatique !
        let _alert3 = daemon
            .trigger_decoy(&admin, 2, 4001, ProbeAction::ReadVmoMemory, 220)
            .expect("Trigger VMO Decoy");
        let profile3 = daemon.get_attacker_profile(4001).expect("Profil 4001");
        assert_eq!(profile3.hit_count, 3);
        assert_eq!(profile3.threat_score, 90);
        assert_eq!(profile3.level, AttackerLevel::HighRiskAPT);
        assert!(profile3.quarantined);
        assert_eq!(daemon.total_quarantines, 1);

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_enclave_escape_tripwire_and_immediate_high_risk() {
        let admin = DeceptionCap::new(Handle::new(15203, 1), deception_rights::ALL, 5000, 100);
        let mut daemon = JamboDeceptionDaemon::new(admin);
        daemon.init_defaults();

        // Attaquant PID 7777 tente une évasion d'enclave TEE sur Decoy #4
        let alert = daemon
            .trigger_decoy(&admin, 4, 7777, ProbeAction::EnclaveEscapeAttempt, 500)
            .expect("Trigger Enclave Trap");
        assert_eq!(alert.decoy_kind, DecoyKind::EnclaveTrapDecoy);

        let prof = daemon.get_attacker_profile(7777).expect("Profil 7777");
        assert_eq!(prof.level, AttackerLevel::EnclaveEscapeAttempt);
        assert_eq!(prof.threat_score, 50);

        // Deuxième tentative -> quarantaine immédiate
        daemon
            .trigger_decoy(&admin, 4, 7777, ProbeAction::EnclaveEscapeAttempt, 550)
            .expect("Second trigger");
        let prof_after = daemon.get_attacker_profile(7777).expect("Profil 7777");
        assert_eq!(prof_after.threat_score, 100);
        assert!(prof_after.quarantined);

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_manual_quarantine_and_deactivation() {
        let admin = DeceptionCap::new(Handle::new(15204, 1), deception_rights::ALL, 5000, 100);
        let mut daemon = JamboDeceptionDaemon::new(admin);
        daemon.init_defaults();

        // Attaquant PID 9999
        daemon
            .trigger_decoy(&admin, 5, 9999, ProbeAction::FileAccess, 300)
            .expect("File canary");
        let prof = daemon.get_attacker_profile(9999).unwrap();
        assert!(!prof.quarantined);

        // Quarantaine manuelle
        let res = daemon
            .quarantine_attacker(&admin, 9999, 310)
            .expect("Quarantine");
        assert!(res);
        let prof2 = daemon.get_attacker_profile(9999).unwrap();
        assert!(prof2.quarantined);
        assert_eq!(prof2.threat_score, 100);

        // Désactivation d'un leurre
        daemon
            .deactivate_decoy(&admin, 5, 320)
            .expect("Deactivate decoy");
        // Le déclenchement sur un leurre inactif échoue
        let err = daemon.trigger_decoy(&admin, 5, 9999, ProbeAction::FileAccess, 330);
        assert_eq!(err, Err(DeceptionError::DecoyNotFound));

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_dynamic_bait_generation_and_payloads() {
        let admin = DeceptionCap::new(Handle::new(15205, 1), deception_rights::ALL, 5000, 100);
        let mut daemon = JamboDeceptionDaemon::new(admin);

        // Génération dynamique d'un HoneyCap
        let honey_id = daemon
            .generate_honey_cap(&admin, "HoneyCap-DynamicAdmin", 0xBEEF, 0x1234_5678, 100)
            .expect("Generate HoneyCap");
        assert_eq!(honey_id, 1);

        // Génération d'une fausse clé secrète Ring 3
        let secret_id = daemon
            .generate_fake_secret(
                &admin,
                "FakeKey-JwtMaster",
                "SUPER_SECRET_SOVEREIGN_SIGNING_TOKEN",
                "sec://auth/jwt_key",
                0x9999_8888,
                110,
            )
            .expect("Generate Fake Secret");
        assert_eq!(secret_id, 2);

        // Génération d'un leurre mémoire VMO piégé
        let vmo_id = daemon
            .generate_trapped_vmo(
                &admin,
                "Vmo-KdirBait",
                "vmo://kdir/shadow_idt",
                0xAAAA_BBBB,
                120,
            )
            .expect("Generate Trapped VMO");
        assert_eq!(vmo_id, 3);

        assert_eq!(daemon.decoy_count, 3);
        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_xdr_soar_o1_dispatch_and_mitre_mapping() {
        let admin = DeceptionCap::new(Handle::new(15206, 1), deception_rights::ALL, 5000, 100);
        let mut daemon = JamboDeceptionDaemon::new(admin);
        daemon.init_defaults();

        // Attaquant touche le HoneyCap #1
        daemon
            .trigger_decoy(&admin, 1, 5555, ProbeAction::InvokeHoneyCap, 200)
            .expect("Trigger HoneyCap");

        assert_eq!(daemon.xdr_dispatch_count, 1);
        let notif = daemon
            .pop_pending_xdr_notification(&admin)
            .expect("Pop XDR")
            .expect("Notification présente");
        assert_eq!(notif.decoy_id, 1);
        assert_eq!(notif.attacker_source, 5555);
        assert_eq!(notif.mitre_as_str(), "T1078");
        assert_eq!(
            notif.recommended_action,
            DeceptionContainmentAction::RevokeHoneyCap
        );

        // Deuxième tentative : queue vide
        let empty = daemon
            .pop_pending_xdr_notification(&admin)
            .expect("Pop XDR");
        assert!(empty.is_none());
    }

    #[test]
    fn test_tee_escape_trap_sev_snp() {
        let admin = DeceptionCap::new(Handle::new(15207, 1), deception_rights::ALL, 5000, 100);
        let mut daemon = JamboDeceptionDaemon::new(admin);
        daemon.init_defaults();

        // Piège TEE matériel spécifique
        let alert = daemon
            .trigger_tee_escape_trap(&admin, 4, TeeTrapVector::SevSnpVmsaPoisoning, 9991, 300)
            .expect("TEE Trap");
        assert_eq!(alert.decoy_kind, DecoyKind::EnclaveTrapDecoy);
        assert_eq!(alert.severity, ThreatSeverity::Critical);
        assert_eq!(daemon.tee_traps_fired, 1);

        // Vérification de la notification XDR avec MITRE T1211
        let notif = daemon
            .pop_pending_xdr_notification(&admin)
            .expect("Pop XDR")
            .expect("Notification TEE XDR");
        assert_eq!(notif.mitre_as_str(), "T1211");
        assert_eq!(
            notif.recommended_action,
            DeceptionContainmentAction::IsolateEnclave
        );
    }

    #[test]
    fn test_lateral_movement_detection() {
        let admin = DeceptionCap::new(Handle::new(15208, 1), deception_rights::ALL, 5000, 100);
        let mut daemon = JamboDeceptionDaemon::new(admin);
        daemon.init_defaults();

        // Leurre #7 est le LateralDecoy
        let alert = daemon
            .trigger_decoy(&admin, 7, 6666, ProbeAction::LateralMovementScan, 400)
            .expect("Trigger Lateral Decoy");
        assert_eq!(alert.decoy_kind, DecoyKind::LateralMovementDecoy);

        let prof = daemon.get_attacker_profile(6666).expect("Profil 6666");
        assert_eq!(prof.level, AttackerLevel::LateralMovement);

        let notif = daemon
            .pop_pending_xdr_notification(&admin)
            .expect("Pop XDR")
            .unwrap();
        assert_eq!(notif.mitre_as_str(), "T1021");
        assert_eq!(
            notif.recommended_action,
            DeceptionContainmentAction::BlockLateralSubnet
        );
    }
}

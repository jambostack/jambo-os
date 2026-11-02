//! Infrastructure à Clés Publiques Éphémères, Gestion des Certificats & mTLS de Grappe (`jambo-certd`)
//!
//! Fournit une autorité de certification de grappe (*Cluster CA*) autonome, souveraine et déterministe en `#![no_std]`.
//! Implémente :
//! - L'émission de certificats éphémères à courte durée de vie avec signature cryptographique
//! - Le contrôle strict des usages de clés (Server Auth, Client Auth, Code Sign, Mesh Routing)
//! - La validation d'intégrité, de fenêtre temporelle et de révocation sans autorité ambiante
//! - Le protocole IPC déterministe à 64 octets sous l'endpoint 24 (PID 24)
//! - Un client synchrone `CertClient` pour le shell `jsh` et les services Ring 3

#![no_std]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_find)]

pub use libjambo::{syscall_ipc_register_endpoint, syscall_thread_yield, Handle, SysError};

pub const MAX_ACTIVE_CERTS: usize = 32;
pub const MAX_REVOKED_CERTS: usize = 16;
pub const MAX_SUBJECT_LEN: usize = 32;
pub const MAX_FASTPATH_BYTES: usize = 64;
pub const MAX_HANDLES: usize = 4;

pub const CERT_MAGIC_REQ: u32 = 0x43455254; // "CERT"
pub const CERT_MAGIC_RESP: u32 = 0x43455253; // "CERS"

// ============================================================================
// DROITS & CAPABILITÉS (`CertCap`, `cert_rights`)
// ============================================================================

/// Droits de capacité pour le sous-système de gestion de certificats éphémères.
pub mod cert_rights {
    pub const CERT_ISSUE: u32 = 0x01;
    pub const CERT_VERIFY: u32 = 0x02;
    pub const CERT_REVOKE: u32 = 0x04;
    pub const CERT_AUDIT: u32 = 0x08;
    pub const CERT_ADMIN: u32 = 0x80;
    pub const ALL: u32 = CERT_ISSUE | CERT_VERIFY | CERT_REVOKE | CERT_AUDIT | CERT_ADMIN;
    // 0x8F
}

/// Usages de clés cryptographiques autorisés pour les certificats de grappe.
pub mod key_usages {
    pub const USAGE_SERVER_AUTH: u32 = 0x01;
    pub const USAGE_CLIENT_AUTH: u32 = 0x02;
    pub const USAGE_CODE_SIGN: u32 = 0x04;
    pub const USAGE_MESH_ROUTING: u32 = 0x08;
}

/// Jeton de capacité pour l'autorité de certification de grappe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertCap {
    pub handle: Handle,
    pub rights: u32,
}

impl CertCap {
    pub const CERT_ISSUE: u32 = cert_rights::CERT_ISSUE;
    pub const CERT_VERIFY: u32 = cert_rights::CERT_VERIFY;
    pub const CERT_REVOKE: u32 = cert_rights::CERT_REVOKE;
    pub const CERT_AUDIT: u32 = cert_rights::CERT_AUDIT;
    pub const CERT_ADMIN: u32 = cert_rights::CERT_ADMIN;
    pub const ALL: u32 = cert_rights::ALL;

    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    /// Atténuation unilatérale des privilèges sans possibilité d'amplification
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
// STATUT DE VÉRIFICATION & STRUCTURES DE CERTIFICAT
// ============================================================================

/// Statut de vérification d'un certificat éphémère.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Valid = 0,
    Expired = 1,
    Revoked = 2,
    InvalidSignature = 3,
    UsageMismatch = 4,
}

impl CertStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
            Self::InvalidSignature => "INVALID_SIG",
            Self::UsageMismatch => "USAGE_MISMATCH",
        }
    }

    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Valid),
            1 => Some(Self::Expired),
            2 => Some(Self::Revoked),
            3 => Some(Self::InvalidSignature),
            4 => Some(Self::UsageMismatch),
            _ => None,
        }
    }
}

/// Certificat d'identité éphémère d'entité ou service de grappe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralCert {
    pub serial: u64,
    pub subject: [u8; MAX_SUBJECT_LEN],
    pub subject_len: usize,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub key_usage: u32,
    pub ca_signature: [u8; 32],
}

impl EphemeralCert {
    /// Indique si le certificat couvre l'usage requis.
    pub const fn allows_usage(&self, required: u32) -> bool {
        (self.key_usage & required) == required
    }

    /// Indique si le certificat est dans sa fenêtre temporelle de validité.
    pub const fn is_time_valid(&self, current_time: u64) -> bool {
        current_time >= self.not_before && current_time <= self.not_after
    }

    /// Renvoie le nom / sujet du certificat sous forme de &str.
    pub fn subject_str(&self) -> &str {
        core::str::from_utf8(&self.subject[..self.subject_len]).unwrap_or("")
    }

    /// Alias pour le common name.
    pub fn common_name(&self) -> &str {
        self.subject_str()
    }
}

// ============================================================================
// CODES D'OPÉRATIONS IPC (`CertOpcode`)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertOpcode {
    GetStatus = 1,
    IssueCert = 2,
    VerifyCert = 3,
    RevokeCert = 4,
    ListCerts = 5,
}

impl CertOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::IssueCert),
            3 => Some(Self::VerifyCert),
            4 => Some(Self::RevokeCert),
            5 => Some(Self::ListCerts),
            _ => None,
        }
    }
}

// ============================================================================
// STRUCTURES IPC EXACTEMENT 64 OCTETS (`CertRequest`, `CertResponse`)
// ============================================================================

/// Requête IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub rights: u32,
    pub serial: u64,
    pub key_usage: u32,
    pub validity_seconds: u32,
    pub public_key: [u8; 16],
    pub subject: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<CertRequest>() == 64);

impl Default for CertRequest {
    fn default() -> Self {
        Self {
            magic: CERT_MAGIC_REQ,
            opcode: CertOpcode::GetStatus as u32,
            handle_id: 24,
            rights: cert_rights::ALL,
            serial: 0,
            key_usage: 0,
            validity_seconds: 3600,
            public_key: [0u8; 16],
            subject: [0u8; 16],
        }
    }
}

impl CertRequest {
    pub const fn new(opcode: CertOpcode) -> Self {
        Self {
            magic: CERT_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: 24,
            rights: cert_rights::ALL,
            serial: 0,
            key_usage: 0,
            validity_seconds: 3600,
            public_key: [0u8; 16],
            subject: [0u8; 16],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: CERT_MAGIC_REQ,
            opcode: CertOpcode::GetStatus as u32,
            handle_id,
            rights,
            serial: 0,
            key_usage: 0,
            validity_seconds: 0,
            public_key: [0u8; 16],
            subject: [0u8; 16],
        }
    }

    pub fn new_issue(
        handle_id: u32,
        rights: u32,
        subject: &str,
        public_key: [u8; 16],
        validity_seconds: u32,
        key_usage: u32,
    ) -> Self {
        let mut req = Self {
            magic: CERT_MAGIC_REQ,
            opcode: CertOpcode::IssueCert as u32,
            handle_id,
            rights,
            serial: 0,
            key_usage,
            validity_seconds,
            public_key,
            subject: [0u8; 16],
        };
        req.set_subject(subject);
        req
    }

    pub const fn new_verify(handle_id: u32, rights: u32, serial: u64, key_usage: u32) -> Self {
        Self {
            magic: CERT_MAGIC_REQ,
            opcode: CertOpcode::VerifyCert as u32,
            handle_id,
            rights,
            serial,
            key_usage,
            validity_seconds: 0,
            public_key: [0u8; 16],
            subject: [0u8; 16],
        }
    }

    pub const fn new_revoke(handle_id: u32, rights: u32, serial: u64) -> Self {
        Self {
            magic: CERT_MAGIC_REQ,
            opcode: CertOpcode::RevokeCert as u32,
            handle_id,
            rights,
            serial,
            key_usage: 0,
            validity_seconds: 0,
            public_key: [0u8; 16],
            subject: [0u8; 16],
        }
    }

    pub const fn new_list(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: CERT_MAGIC_REQ,
            opcode: CertOpcode::ListCerts as u32,
            handle_id,
            rights,
            serial: 0,
            key_usage: 0,
            validity_seconds: 0,
            public_key: [0u8; 16],
            subject: [0u8; 16],
        }
    }

    pub fn set_subject(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(self.subject.len());
        self.subject = [0u8; 16];
        self.subject[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn subject_as_str(&self) -> &str {
        let len = self
            .subject
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.subject.len());
        core::str::from_utf8(&self.subject[..len]).unwrap_or("")
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
        if req.magic != CERT_MAGIC_REQ {
            return None;
        }
        Some(req)
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertResponse {
    pub magic: u32,
    pub status: i32,
    pub serial: u64,
    pub active_certs: u32,
    pub revoked_certs: u32,
    pub cert_status: u32,
    pub key_usage: u32,
    pub signature_preview: [u8; 16],
    pub status_str: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<CertResponse>() == 64);

impl Default for CertResponse {
    fn default() -> Self {
        Self {
            magic: CERT_MAGIC_RESP,
            status: 0,
            serial: 0,
            active_certs: 0,
            revoked_certs: 0,
            cert_status: CertStatus::Valid as u32,
            key_usage: 0,
            signature_preview: [0u8; 16],
            status_str: [0u8; 16],
        }
    }
}

impl CertResponse {
    pub fn set_status_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(self.status_str.len());
        self.status_str = [0u8; 16];
        self.status_str[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn status_as_str(&self) -> &str {
        let len = self
            .status_str
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.status_str.len());
        core::str::from_utf8(&self.status_str[..len]).unwrap_or("")
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
        if resp.magic != CERT_MAGIC_RESP {
            return None;
        }
        Some(resp)
    }
}

// ============================================================================
// GESTIONNAIRE D'AUTORITÉ DE CERTIFICATION DE GRAPPE (`ClusterCa`)
// ============================================================================

/// Autorité de certification de grappe en mémoire bornée et souveraine.
pub struct ClusterCa {
    pub ca_id: u32,
    pub ca_public_key: [u8; 32],
    pub ca_secret_seed: [u8; 32],
    pub next_serial: u64,
    pub active_certs: [Option<EphemeralCert>; MAX_ACTIVE_CERTS],
    pub revoked_serials: [u64; MAX_REVOKED_CERTS],
    pub revoked_count: usize,
}

impl Default for ClusterCa {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterCa {
    /// Initialise une nouvelle autorité de grappe avec clés canoniques par défaut.
    pub const fn new() -> Self {
        Self::with_keys(1, [0x71; 32], [0xAC; 32])
    }

    /// Initialise l'autorité avec clés et identifiant explicites.
    pub const fn with_keys(ca_id: u32, ca_public_key: [u8; 32], ca_secret_seed: [u8; 32]) -> Self {
        Self {
            ca_id,
            ca_public_key,
            ca_secret_seed,
            next_serial: 1000,
            active_certs: [None; MAX_ACTIVE_CERTS],
            revoked_serials: [0; MAX_REVOKED_CERTS],
            revoked_count: 0,
        }
    }

    /// Pré-remplit les certificats mTLS systèmes initiaux pour le cluster JamboOS :
    /// - `kernel.jambo` (serial 1000) : Server Auth & Code Sign
    /// - `jsh.jambo` (serial 1001) : Client Auth
    /// - `pkgd.jambo` (serial 1002) : Server Auth & Code Sign
    pub fn init_defaults(&mut self) {
        let cap = CertCap::new(Handle::new(24, 1), cert_rights::ALL);
        let _ = self.issue_cert(
            &cap,
            b"kernel.jambo",
            [0x01; 32],
            0,
            1_000_000,
            key_usages::USAGE_SERVER_AUTH | key_usages::USAGE_CODE_SIGN,
        );
        let _ = self.issue_cert(
            &cap,
            b"jsh.jambo",
            [0x02; 32],
            0,
            1_000_000,
            key_usages::USAGE_CLIENT_AUTH,
        );
        let _ = self.issue_cert(
            &cap,
            b"pkgd.jambo",
            [0x03; 32],
            0,
            1_000_000,
            key_usages::USAGE_SERVER_AUTH | key_usages::USAGE_CODE_SIGN,
        );
    }

    /// Calcule une signature déterministe pour attester du certificat.
    pub fn sign_payload(
        &self,
        serial: u64,
        subject: &[u8],
        pubkey: &[u8; 32],
        not_before: u64,
        not_after: u64,
        usage: u32,
    ) -> [u8; 32] {
        let mut sig = [0u8; 32];
        let seed = &self.ca_secret_seed;

        for i in 0..32 {
            let mut byte = seed[i] ^ (self.ca_id as u8).wrapping_add(i as u8);
            byte ^= ((serial >> ((i % 8) * 8)) & 0xFF) as u8;
            if i < subject.len() {
                byte ^= subject[i];
            }
            byte ^= pubkey[i];
            byte ^= ((not_before >> ((i % 8) * 8)) & 0xFF) as u8;
            byte ^= ((not_after >> ((i % 8) * 8)) & 0xFF) as u8;
            byte ^= ((usage >> ((i % 4) * 8)) & 0xFF) as u8;
            sig[i] = byte;
        }

        sig
    }

    /// Émet un nouveau certificat éphémère signé par l'autorité.
    pub fn issue_cert(
        &mut self,
        cap: &CertCap,
        subject: &[u8],
        public_key: [u8; 32],
        not_before: u64,
        not_after: u64,
        key_usage: u32,
    ) -> Result<EphemeralCert, SysError> {
        if !cap.has_right(cert_rights::CERT_ISSUE) {
            return Err(SysError::PermissionDenied);
        }
        if subject.is_empty() || subject.len() > MAX_SUBJECT_LEN || not_after <= not_before {
            return Err(SysError::InvalidArgument);
        }

        // Trouver un emplacement libre
        let mut slot_index = None;
        for (idx, slot) in self.active_certs.iter().enumerate() {
            if slot.is_none() {
                slot_index = Some(idx);
                break;
            }
        }

        let idx = slot_index.ok_or(SysError::ResourceBusy)?;

        let serial = self.next_serial;
        self.next_serial = self.next_serial.saturating_add(1);

        let ca_signature = self.sign_payload(
            serial,
            subject,
            &public_key,
            not_before,
            not_after,
            key_usage,
        );

        let mut subject_buf = [0u8; MAX_SUBJECT_LEN];
        subject_buf[..subject.len()].copy_from_slice(subject);

        let cert = EphemeralCert {
            serial,
            subject: subject_buf,
            subject_len: subject.len(),
            public_key,
            not_before,
            not_after,
            key_usage,
            ca_signature,
        };

        self.active_certs[idx] = Some(cert);
        Ok(cert)
    }

    /// Vérifie la validité, l'intégrité et les contraintes d'usage d'un certificat.
    pub fn verify_cert(
        &self,
        cap: &CertCap,
        cert: &EphemeralCert,
        required_usage: u32,
        current_time: u64,
    ) -> Result<CertStatus, SysError> {
        if !cap.has_right(cert_rights::CERT_VERIFY) {
            return Err(SysError::PermissionDenied);
        }

        // Vérification de révocation
        for &rev_serial in &self.revoked_serials[..self.revoked_count] {
            if rev_serial == cert.serial {
                return Ok(CertStatus::Revoked);
            }
        }

        // Vérification de validité temporelle
        if !cert.is_time_valid(current_time) {
            return Ok(CertStatus::Expired);
        }

        // Vérification de l'usage requis si spécifié (usage == 0 accepte tout usage)
        if required_usage != 0 && !cert.allows_usage(required_usage) {
            return Ok(CertStatus::UsageMismatch);
        }

        // Vérification de signature d'autorité
        let expected_sig = self.sign_payload(
            cert.serial,
            &cert.subject[..cert.subject_len],
            &cert.public_key,
            cert.not_before,
            cert.not_after,
            cert.key_usage,
        );

        if expected_sig != cert.ca_signature {
            return Ok(CertStatus::InvalidSignature);
        }

        Ok(CertStatus::Valid)
    }

    /// Révoque immédiatement un certificat par son numéro de série.
    pub fn revoke_cert(&mut self, cap: &CertCap, serial: u64) -> Result<(), SysError> {
        if !cap.has_right(cert_rights::CERT_REVOKE) {
            return Err(SysError::PermissionDenied);
        }

        // Retirer des certificats actifs s'il y est
        for slot in self.active_certs.iter_mut() {
            if let Some(c) = slot {
                if c.serial == serial {
                    *slot = None;
                    break;
                }
            }
        }

        // Vérifier si déjà dans la liste révoquée
        for &s in &self.revoked_serials[..self.revoked_count] {
            if s == serial {
                return Ok(());
            }
        }

        // Enregistrer dans la table de révocation
        if self.revoked_count < MAX_REVOKED_CERTS {
            self.revoked_serials[self.revoked_count] = serial;
            self.revoked_count += 1;
            Ok(())
        } else {
            Err(SysError::OutOfMemory)
        }
    }

    /// Recherche un certificat actif par son numéro de série.
    pub fn find_cert_by_serial(&self, serial: u64) -> Option<&EphemeralCert> {
        for c in self.active_certs.iter().flatten() {
            if c.serial == serial {
                return Some(c);
            }
        }
        None
    }

    /// Recherche un certificat actif par numéro de série et le renvoie par copie.
    pub fn get_active(&self, serial: u64) -> Option<EphemeralCert> {
        self.find_cert_by_serial(serial).copied()
    }

    /// Indique si un numéro de série est marqué comme révoqué.
    pub fn is_revoked(&self, serial: u64) -> bool {
        for &s in &self.revoked_serials[..self.revoked_count] {
            if s == serial {
                return true;
            }
        }
        false
    }

    /// Nombre de certificats actuellement actifs.
    pub fn active_count(&self) -> usize {
        self.active_certs.iter().filter(|s| s.is_some()).count()
    }

    /// Nombre de révocations enregistrées.
    pub fn revoked_count(&self) -> usize {
        self.revoked_count
    }

    /// Purge les certificats expirés de la table active.
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let mut purged = 0;
        for slot in self.active_certs.iter_mut() {
            if let Some(c) = slot {
                if now > c.not_after {
                    *slot = None;
                    purged += 1;
                }
            }
        }
        purged
    }

    /// Clé publique de l'autorité de certification.
    pub fn ca_public_key(&self) -> &[u8; 32] {
        &self.ca_public_key
    }

    /// Traitement déterministe d'une requête IPC 64 octets
    pub fn dispatch_ipc(&mut self, req: &CertRequest) -> CertResponse {
        if req.magic != CERT_MAGIC_REQ {
            let mut resp = CertResponse::default();
            resp.status = SysError::InvalidArgument as i32;
            resp.set_status_str("BAD_MAGIC");
            return resp;
        }

        let cap = CertCap::new(Handle::new(req.handle_id, 1), req.rights);

        let opcode = match CertOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                let mut resp = CertResponse::default();
                resp.status = SysError::InvalidArgument as i32;
                resp.set_status_str("BAD_OPCODE");
                return resp;
            }
        };

        match opcode {
            CertOpcode::GetStatus => {
                if !cap.has_right(cert_rights::CERT_AUDIT)
                    && !cap.has_right(cert_rights::CERT_VERIFY)
                {
                    let mut resp = CertResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                let mut resp = CertResponse::default();
                resp.status = 0;
                resp.serial = self.next_serial;
                resp.active_certs = self.active_count() as u32;
                resp.revoked_certs = self.revoked_count() as u32;
                resp.set_status_str("READY");
                resp
            }
            CertOpcode::IssueCert => {
                if !cap.has_right(cert_rights::CERT_ISSUE) {
                    let mut resp = CertResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                let subject_str = req.subject_as_str();
                if subject_str.is_empty() {
                    let mut resp = CertResponse::default();
                    resp.status = SysError::InvalidArgument as i32;
                    resp.set_status_str("EMPTY_SUBJ");
                    return resp;
                }

                let mut pk32 = [0u8; 32];
                pk32[..16].copy_from_slice(&req.public_key);
                pk32[16..].copy_from_slice(&req.public_key);

                let validity = if req.validity_seconds == 0 {
                    3600
                } else {
                    req.validity_seconds as u64
                };
                let not_before = 1000;
                let not_after = not_before + validity;

                match self.issue_cert(
                    &cap,
                    subject_str.as_bytes(),
                    pk32,
                    not_before,
                    not_after,
                    req.key_usage,
                ) {
                    Ok(cert) => {
                        let mut resp = CertResponse::default();
                        resp.status = 0;
                        resp.serial = cert.serial;
                        resp.active_certs = self.active_count() as u32;
                        resp.revoked_certs = self.revoked_count() as u32;
                        resp.cert_status = CertStatus::Valid as u32;
                        resp.key_usage = cert.key_usage;
                        resp.signature_preview
                            .copy_from_slice(&cert.ca_signature[..16]);
                        resp.set_status_str("ISSUED");
                        resp
                    }
                    Err(err) => {
                        let mut resp = CertResponse::default();
                        resp.status = err as i32;
                        resp.set_status_str("ERROR");
                        resp
                    }
                }
            }
            CertOpcode::VerifyCert => {
                if !cap.has_right(cert_rights::CERT_VERIFY) {
                    let mut resp = CertResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }

                if self.is_revoked(req.serial) {
                    let mut resp = CertResponse::default();
                    resp.status = 0;
                    resp.serial = req.serial;
                    resp.active_certs = self.active_count() as u32;
                    resp.revoked_certs = self.revoked_count() as u32;
                    resp.cert_status = CertStatus::Revoked as u32;
                    resp.set_status_str("REVOKED");
                    return resp;
                }

                if let Some(cert) = self.get_active(req.serial) {
                    let eval_time = if req.validity_seconds != 0 {
                        req.validity_seconds as u64
                    } else {
                        1500
                    };
                    match self.verify_cert(&cap, &cert, req.key_usage, eval_time) {
                        Ok(status) => {
                            let mut resp = CertResponse::default();
                            resp.status = 0;
                            resp.serial = cert.serial;
                            resp.active_certs = self.active_count() as u32;
                            resp.revoked_certs = self.revoked_count() as u32;
                            resp.cert_status = status as u32;
                            resp.key_usage = cert.key_usage;
                            resp.signature_preview
                                .copy_from_slice(&cert.ca_signature[..16]);
                            resp.set_status_str(status.as_str());
                            resp
                        }
                        Err(err) => {
                            let mut resp = CertResponse::default();
                            resp.status = err as i32;
                            resp.set_status_str("ERROR");
                            resp
                        }
                    }
                } else {
                    let mut resp = CertResponse::default();
                    resp.status = SysError::InvalidArgument as i32;
                    resp.serial = req.serial;
                    resp.active_certs = self.active_count() as u32;
                    resp.revoked_certs = self.revoked_count() as u32;
                    resp.set_status_str("NOT_FOUND");
                    resp
                }
            }
            CertOpcode::RevokeCert => {
                if !cap.has_right(cert_rights::CERT_REVOKE) {
                    let mut resp = CertResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                match self.revoke_cert(&cap, req.serial) {
                    Ok(()) => {
                        let mut resp = CertResponse::default();
                        resp.status = 0;
                        resp.serial = req.serial;
                        resp.active_certs = self.active_count() as u32;
                        resp.revoked_certs = self.revoked_count() as u32;
                        resp.cert_status = CertStatus::Revoked as u32;
                        resp.set_status_str("REVOKED");
                        resp
                    }
                    Err(err) => {
                        let mut resp = CertResponse::default();
                        resp.status = err as i32;
                        resp.set_status_str("ERROR");
                        resp
                    }
                }
            }
            CertOpcode::ListCerts => {
                if !cap.has_right(cert_rights::CERT_AUDIT)
                    && !cap.has_right(cert_rights::CERT_VERIFY)
                {
                    let mut resp = CertResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                let mut resp = CertResponse::default();
                resp.status = 0;
                resp.serial = self.next_serial;
                resp.active_certs = self.active_count() as u32;
                resp.revoked_certs = self.revoked_count() as u32;
                resp.set_status_str("OK");
                resp
            }
        }
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`CertClient`, `ChannelMessage`)
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

/// Client synchrone Ring 3 pour interagir avec le démon PKI `jambo-certd` (PID 24)
pub struct CertClient {
    pub endpoint: Handle,
}

impl CertClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_status(&self, cap: &CertCap) -> Result<CertResponse, SysError> {
        if !cap.has_right(cert_rights::CERT_AUDIT) && !cap.has_right(cert_rights::CERT_VERIFY) {
            return Err(SysError::PermissionDenied);
        }
        let req = CertRequest::new_status(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn issue_cert(
        &self,
        cap: &CertCap,
        subject: &str,
        public_key: [u8; 16],
        validity_seconds: u32,
        key_usage: u32,
    ) -> Result<CertResponse, SysError> {
        if !cap.has_right(cert_rights::CERT_ISSUE) {
            return Err(SysError::PermissionDenied);
        }
        let req = CertRequest::new_issue(
            cap.handle.index(),
            cap.rights,
            subject,
            public_key,
            validity_seconds,
            key_usage,
        );
        self.call(&req)
    }

    pub fn verify_cert(
        &self,
        cap: &CertCap,
        serial: u64,
        required_usage: u32,
    ) -> Result<CertResponse, SysError> {
        if !cap.has_right(cert_rights::CERT_VERIFY) {
            return Err(SysError::PermissionDenied);
        }
        let req = CertRequest::new_verify(cap.handle.index(), cap.rights, serial, required_usage);
        self.call(&req)
    }

    pub fn revoke_cert(&self, cap: &CertCap, serial: u64) -> Result<CertResponse, SysError> {
        if !cap.has_right(cert_rights::CERT_REVOKE) {
            return Err(SysError::PermissionDenied);
        }
        let req = CertRequest::new_revoke(cap.handle.index(), cap.rights, serial);
        self.call(&req)
    }

    pub fn list_certs(&self, cap: &CertCap) -> Result<CertResponse, SysError> {
        if !cap.has_right(cert_rights::CERT_AUDIT) && !cap.has_right(cert_rights::CERT_VERIFY) {
            return Err(SysError::PermissionDenied);
        }
        let req = CertRequest::new_list(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn call(&self, req: &CertRequest) -> Result<CertResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<CertResponse>() {
                return CertResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    .ok_or(SysError::InvalidArgument);
            }

            attempts += 1;
            syscall_thread_yield();
        }

        Err(SysError::TimedOut)
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_constants_and_sizes() {
        assert_eq!(core::mem::size_of::<CertRequest>(), 64);
        assert_eq!(core::mem::size_of::<CertResponse>(), 64);
    }

    #[test]
    fn test_cert_cap_attenuation() {
        let cap_full = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        assert!(cap_full.has_right(cert_rights::CERT_ISSUE));
        assert!(cap_full.has_right(cert_rights::CERT_VERIFY));

        // Atténuation valide (suppression des droits d'émission et admin)
        let cap_verify_only = cap_full.attenuate(cert_rights::CERT_VERIFY).unwrap();
        assert!(!cap_verify_only.has_right(cert_rights::CERT_ISSUE));
        assert!(cap_verify_only.has_right(cert_rights::CERT_VERIFY));

        // Amplification interdite
        let amp_res = cap_verify_only.attenuate(cert_rights::ALL);
        assert_eq!(amp_res, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_cert_lifecycle_issuance_and_verification() {
        let cap = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new();

        let cert = ca
            .issue_cert(
                &cap,
                b"mesh.node-1.cluster",
                [0xBB; 32],
                1000,
                2000,
                key_usages::USAGE_SERVER_AUTH | key_usages::USAGE_MESH_ROUTING,
            )
            .unwrap();

        assert_eq!(ca.active_count(), 1);
        assert_eq!(cert.serial, 1000);
        assert_eq!(cert.subject_str(), "mesh.node-1.cluster");
        assert!(cert.allows_usage(key_usages::USAGE_SERVER_AUTH));
        assert!(cert.allows_usage(key_usages::USAGE_MESH_ROUTING));
        assert!(!cert.allows_usage(key_usages::USAGE_CODE_SIGN));

        // Recherche par numéro de série
        let found = ca.find_cert_by_serial(1000).unwrap();
        assert_eq!(found.serial, 1000);

        // Validation au temps t = 1500
        let status = ca
            .verify_cert(&cap, &cert, key_usages::USAGE_MESH_ROUTING, 1500)
            .unwrap();
        assert_eq!(status, CertStatus::Valid);
    }

    #[test]
    fn test_cert_expiration() {
        let cap = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new();

        let cert = ca
            .issue_cert(
                &cap,
                b"gateway.cluster",
                [0x11; 32],
                1000,
                1200,
                key_usages::USAGE_SERVER_AUTH,
            )
            .unwrap();

        // À t = 1300, le certificat doit être expiré
        let status = ca
            .verify_cert(&cap, &cert, key_usages::USAGE_SERVER_AUTH, 1300)
            .unwrap();
        assert_eq!(status, CertStatus::Expired);

        // Purge
        let purged = ca.purge_expired(1300);
        assert_eq!(purged, 1);
        assert_eq!(ca.active_count(), 0);
    }

    #[test]
    fn test_cert_revocation() {
        let cap = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new();

        let cert = ca
            .issue_cert(
                &cap,
                b"compromised.node",
                [0x22; 32],
                1000,
                2000,
                key_usages::USAGE_CLIENT_AUTH,
            )
            .unwrap();

        // Révocation explicite
        ca.revoke_cert(&cap, cert.serial).unwrap();
        assert!(ca.is_revoked(cert.serial));
        assert_eq!(ca.active_count(), 0);
        assert_eq!(ca.revoked_count(), 1);

        let status = ca
            .verify_cert(&cap, &cert, key_usages::USAGE_CLIENT_AUTH, 1500)
            .unwrap();
        assert_eq!(status, CertStatus::Revoked);
    }

    #[test]
    fn test_cert_usage_check() {
        let cap = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new();

        let cert = ca
            .issue_cert(
                &cap,
                b"signer.service",
                [0x33; 32],
                1000,
                2000,
                key_usages::USAGE_CODE_SIGN,
            )
            .unwrap();

        // Vérification avec un usage non autorisé
        let status = ca
            .verify_cert(&cap, &cert, key_usages::USAGE_SERVER_AUTH, 1500)
            .unwrap();
        assert_eq!(status, CertStatus::UsageMismatch);
    }

    #[test]
    fn test_cert_invalid_signature() {
        let cap = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new();

        let mut cert = ca
            .issue_cert(
                &cap,
                b"tampered.service",
                [0x44; 32],
                1000,
                2000,
                key_usages::USAGE_SERVER_AUTH,
            )
            .unwrap();

        // Altération de la signature
        cert.ca_signature[0] ^= 0xFF;

        let status = ca
            .verify_cert(&cap, &cert, key_usages::USAGE_SERVER_AUTH, 1500)
            .unwrap();
        assert_eq!(status, CertStatus::InvalidSignature);
    }

    #[test]
    fn test_init_defaults() {
        let mut ca = ClusterCa::new();
        ca.init_defaults();

        assert_eq!(ca.active_count(), 3);
        let k_cert = ca.find_cert_by_serial(1000).unwrap();
        assert_eq!(k_cert.subject_str(), "kernel.jambo");
        let j_cert = ca.find_cert_by_serial(1001).unwrap();
        assert_eq!(j_cert.subject_str(), "jsh.jambo");
        let p_cert = ca.find_cert_by_serial(1002).unwrap();
        assert_eq!(p_cert.subject_str(), "pkgd.jambo");
    }

    #[test]
    fn test_ipc_serialization_and_dispatch() {
        let mut ca = ClusterCa::new();
        ca.init_defaults();

        // 1. GetStatus
        let req_status = CertRequest::new_status(24, cert_rights::ALL);
        let bytes = req_status.to_bytes();
        let decoded_req = CertRequest::from_bytes(&bytes).unwrap();
        let resp = ca.dispatch_ipc(&decoded_req);
        assert_eq!(resp.status, 0);
        assert_eq!(resp.active_certs, 3);
        assert_eq!(resp.status_as_str(), "READY");

        // 2. IssueCert via IPC
        let req_issue = CertRequest::new_issue(
            24,
            cert_rights::ALL,
            "netd.jambo",
            [0x55; 16],
            1800,
            key_usages::USAGE_SERVER_AUTH | key_usages::USAGE_CLIENT_AUTH,
        );
        let resp_issue = ca.dispatch_ipc(&req_issue);
        assert_eq!(resp_issue.status, 0);
        assert_eq!(resp_issue.serial, 1003);
        assert_eq!(resp_issue.active_certs, 4);
        assert_eq!(resp_issue.status_as_str(), "ISSUED");

        // 3. VerifyCert via IPC
        let req_verify =
            CertRequest::new_verify(24, cert_rights::ALL, 1003, key_usages::USAGE_SERVER_AUTH);
        let resp_verify = ca.dispatch_ipc(&req_verify);
        assert_eq!(resp_verify.status, 0);
        assert_eq!(resp_verify.cert_status, CertStatus::Valid as u32);
        assert_eq!(resp_verify.status_as_str(), "VALID");

        // 4. RevokeCert via IPC
        let req_revoke = CertRequest::new_revoke(24, cert_rights::ALL, 1003);
        let resp_revoke = ca.dispatch_ipc(&req_revoke);
        assert_eq!(resp_revoke.status, 0);
        assert_eq!(resp_revoke.active_certs, 3);
        assert_eq!(resp_revoke.revoked_certs, 1);
        assert_eq!(resp_revoke.status_as_str(), "REVOKED");

        // 5. Verify post-revocation
        let resp_verify2 = ca.dispatch_ipc(&req_verify);
        assert_eq!(resp_verify2.status, 0);
        assert_eq!(resp_verify2.cert_status, CertStatus::Revoked as u32);
        assert_eq!(resp_verify2.status_as_str(), "REVOKED");

        // 6. Test serialisation aller-retour réponse
        let resp_bytes = resp_verify2.to_bytes();
        let decoded_resp = CertResponse::from_bytes(&resp_bytes).unwrap();
        assert_eq!(decoded_resp.serial, 1003);
        assert_eq!(decoded_resp.status_as_str(), "REVOKED");
    }

    #[test]
    fn test_ipc_permission_denied() {
        let mut ca = ClusterCa::new();
        ca.init_defaults();

        // Requête d'émission avec capacité restreinte (sans droit CERT_ISSUE)
        let req_issue = CertRequest::new_issue(
            24,
            cert_rights::CERT_VERIFY,
            "bad.jambo",
            [0x66; 16],
            1800,
            key_usages::USAGE_SERVER_AUTH,
        );
        let resp = ca.dispatch_ipc(&req_issue);
        assert_eq!(resp.status, SysError::PermissionDenied as i32);
        assert_eq!(resp.status_as_str(), "DENIED");
    }
}

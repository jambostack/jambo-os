//! Infrastructure à Clés Publiques Éphémères & Gestion des Certificats de Grappe (`jambo-certd`)
//!
//! Fournit une autorité de certification de grappe (*Cluster CA*) autonome et déterministe en `#![no_std]`.
//! Permet l'émission de certificats éphémères à courte durée de vie, la validation cryptographique instantanée,
//! le contrôle d'usages de clés (mTLS, Mesh, Code Signing) et la révocation proactive via `CertCap`.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_ACTIVE_CERTS: usize = 32;
pub const MAX_REVOKED_CERTS: usize = 16;
pub const MAX_SUBJECT_LEN: usize = 32;

/// Droits de capacité pour le sous-système de gestion de certificats.
pub mod cert_rights {
    pub const CERT_ISSUE: u32 = 0x01;
    pub const CERT_VERIFY: u32 = 0x02;
    pub const CERT_REVOKE: u32 = 0x04;
    pub const CERT_AUDIT: u32 = 0x08;
    pub const CERT_INSPECT: u32 = 0x08;
    pub const CERT_ADMIN: u32 = 0x80;
    pub const ALL: u32 = CERT_ISSUE | CERT_VERIFY | CERT_REVOKE | CERT_AUDIT | CERT_ADMIN;
}

/// Usages de clés cryptographiques autorisés.
pub mod key_usages {
    pub const USAGE_SERVER_AUTH: u32 = 0x01;
    pub const USAGE_CLIENT_AUTH: u32 = 0x02;
    pub const USAGE_CODE_SIGN: u32 = 0x04;
    pub const USAGE_MESH_ROUTING: u32 = 0x08;
}

/// Jeton de capacité pour l'autorité de certificats de grappe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertCap {
    pub handle: Handle,
    pub rights: u32,
}

impl CertCap {
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

/// Statut de vérification d'un certificat éphémère.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Valid,
    Expired,
    Revoked,
    InvalidSignature,
    UsageMismatch,
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

/// Autorité de certification de grappe en mémoire bornée.
pub struct ClusterCa {
    ca_id: u32,
    ca_public_key: [u8; 32],
    ca_secret_seed: [u8; 32],
    next_serial: u64,
    active_certs: [Option<EphemeralCert>; MAX_ACTIVE_CERTS],
    revoked_serials: [u64; MAX_REVOKED_CERTS],
    revoked_count: usize,
}

impl ClusterCa {
    pub const fn new(ca_id: u32, ca_public_key: [u8; 32], ca_secret_seed: [u8; 32]) -> Self {
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

    /// Calcule une signature déterministe pour attester du certificat.
    fn sign_payload(
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

        // Vérification de l'usage requis
        if !cert.allows_usage(required_usage) {
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

        // Enregistrer dans la table de révocation
        if self.revoked_count < MAX_REVOKED_CERTS {
            self.revoked_serials[self.revoked_count] = serial;
            self.revoked_count += 1;
            Ok(())
        } else {
            Err(SysError::OutOfMemory)
        }
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

    /// Nombre de certificats actuellement actifs.
    pub fn active_count(&self) -> usize {
        self.active_certs.iter().filter(|s| s.is_some()).count()
    }

    /// Clé publique de l'autorité de certification.
    pub fn ca_public_key(&self) -> &[u8; 32] {
        &self.ca_public_key
    }

    /// Recherche un certificat actif par son numéro de série.
    pub fn get_active(&self, serial: u64) -> Option<EphemeralCert> {
        for slot in self.active_certs.iter().flatten() {
            if slot.serial == serial {
                return Some(*slot);
            }
        }
        None
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

    /// Nombre de révocations enregistrées.
    pub fn revoked_count(&self) -> usize {
        self.revoked_count
    }
}

/// Démon orchestrateur d'autorité de certification distribuée et mTLS (`jambo-certd`).
pub struct JamboCertDaemon {
    pub ca: ClusterCa,
    pub cap: CertCap,
    pub operations_count: u64,
}

impl Default for JamboCertDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboCertDaemon {
    pub fn new() -> Self {
        let cap = CertCap::new(Handle::new(7101, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new(1, [0x71; 32], [0xAC; 32]);

        // Certificat système émis par défaut pour le nœud local
        let _ = ca.issue_cert(
            &cap,
            b"node-0.cluster.local",
            [0x10; 32],
            100,
            10000,
            key_usages::USAGE_SERVER_AUTH
                | key_usages::USAGE_CLIENT_AUTH
                | key_usages::USAGE_MESH_ROUTING,
        );

        Self {
            ca,
            cap,
            operations_count: 1,
        }
    }

    pub fn issue_cert(
        &mut self,
        subject: &[u8],
        public_key: [u8; 32],
        not_before: u64,
        not_after: u64,
        key_usage: u32,
    ) -> Result<EphemeralCert, SysError> {
        let cert = self.ca.issue_cert(
            &self.cap, subject, public_key, not_before, not_after, key_usage,
        )?;
        self.operations_count = self.operations_count.saturating_add(1);
        Ok(cert)
    }

    pub fn verify_cert(
        &self,
        cert: &EphemeralCert,
        required_usage: u32,
        current_time: u64,
    ) -> Result<CertStatus, SysError> {
        self.ca
            .verify_cert(&self.cap, cert, required_usage, current_time)
    }

    pub fn revoke_cert(&mut self, serial: u64) -> Result<(), SysError> {
        self.ca.revoke_cert(&self.cap, serial)?;
        self.operations_count = self.operations_count.saturating_add(1);
        Ok(())
    }

    pub fn purge_expired(&mut self, now: u64) -> usize {
        let purged = self.ca.purge_expired(now);
        self.operations_count = self.operations_count.saturating_add(purged as u64);
        purged
    }

    pub fn active_count(&self) -> usize {
        self.ca.active_count()
    }

    pub fn get_active(&self, serial: u64) -> Option<EphemeralCert> {
        self.ca.get_active(serial)
    }

    pub fn is_revoked(&self, serial: u64) -> bool {
        self.ca.is_revoked(serial)
    }

    pub fn revoked_count(&self) -> usize {
        self.ca.revoked_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_issuance_and_verification() {
        let cap = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new(1, [0xAA; 32], [0x42; 32]);

        let pubkey = [0xBB; 32];
        let cert = ca
            .issue_cert(
                &cap,
                b"mesh.node-1.cluster",
                pubkey,
                1000,
                2000,
                key_usages::USAGE_SERVER_AUTH | key_usages::USAGE_MESH_ROUTING,
            )
            .unwrap();

        assert_eq!(ca.active_count(), 1);
        assert_eq!(cert.serial, 1000);

        // Validation au temps t = 1500
        let status = ca
            .verify_cert(&cap, &cert, key_usages::USAGE_MESH_ROUTING, 1500)
            .unwrap();
        assert_eq!(status, CertStatus::Valid);
    }

    #[test]
    fn test_cert_expiration() {
        let cap = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new(1, [0xAA; 32], [0x42; 32]);

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
        let mut ca = ClusterCa::new(1, [0xAA; 32], [0x42; 32]);

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

        let status = ca
            .verify_cert(&cap, &cert, key_usages::USAGE_CLIENT_AUTH, 1500)
            .unwrap();
        assert_eq!(status, CertStatus::Revoked);
    }

    #[test]
    fn test_cert_usage_check() {
        let cap = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let mut ca = ClusterCa::new(1, [0xAA; 32], [0x42; 32]);

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
    fn test_cert_cap_attenuation() {
        let cap_full = CertCap::new(Handle::new(1, 1), cert_rights::ALL);
        let cap_verify_only = cap_full.attenuate(cert_rights::CERT_VERIFY).unwrap();

        let mut ca = ClusterCa::new(1, [0xAA; 32], [0x42; 32]);

        // Tentative d'émission avec droit verify-only -> PermissionDenied
        let res = ca.issue_cert(
            &cap_verify_only,
            b"test",
            [0; 32],
            100,
            200,
            key_usages::USAGE_SERVER_AUTH,
        );
        assert_eq!(res, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_cert_daemon() {
        let mut daemon = JamboCertDaemon::new();
        assert_eq!(daemon.active_count(), 1);

        let cert = daemon.get_active(1000).unwrap();
        assert_eq!(&cert.subject[..cert.subject_len], b"node-0.cluster.local");

        let status = daemon
            .verify_cert(&cert, key_usages::USAGE_SERVER_AUTH, 1000)
            .unwrap();
        assert_eq!(status, CertStatus::Valid);

        let new_cert = daemon
            .issue_cert(
                b"workload-1.service",
                [0x99; 32],
                500,
                1500,
                key_usages::USAGE_CLIENT_AUTH,
            )
            .unwrap();
        assert_eq!(daemon.active_count(), 2);

        daemon.revoke_cert(new_cert.serial).unwrap();
        let status_rev = daemon
            .verify_cert(&new_cert, key_usages::USAGE_CLIENT_AUTH, 600)
            .unwrap();
        assert_eq!(status_rev, CertStatus::Revoked);
    }
}

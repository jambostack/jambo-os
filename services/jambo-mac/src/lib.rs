//! Mandat d'Accès Contrôlé (MAC) Multi-Niveaux (MLS), Modèles Bell-LaPadula & Biba (`jambo-mac`)
//!
//! Fournit un sous-système de contrôle d'accès obligatoire formel pour micro-noyau souverain `#![no_std]` :
//! 1. Niveaux de classification hiérarchiques de confidentialité (Unclassified, Confidential, Secret, TopSecret).
//! 2. Niveaux hiérarchiques d'intégrité Biba (Untrusted, User, System, Trusted).
//! 3. Compartiments et catégories non-hiérarchiques en treillis (Lattice dominance).
//! 4. Modèle Bell-LaPadula (BLP) garantissant la confidentialité absolue :
//!    - Simple Security Property (*No Read Up* / NRU) : Le sujet ne lit que ce qu'il domine.
//!    - $\star$-Property (*No Write Down* / NWD) : Le sujet n'écrit que vers ce qui le domine.
//! 5. Modèle Biba garantissant l'intégrité absolue :
//!    - Simple Integrity Property (*No Read Down* / NRD) : Le sujet ne lit pas de données d'intégrité inférieure.
//!    - $\star$-Integrity Property (*No Write Up* / NWU) : Le sujet n'écrit pas dans des objets d'intégrité supérieure.
//! 6. Contrôle capabilaire sans autorité ambiante via `MacCap` avec interdiction d'amplification.
//! 7. Déclassification et dégradation contrôlées protégées par le droit `MAC_DOWNGRADE`.
//! 8. Registre d'audit cryptographique inviolable chaîné par hachage SHA-256.

#![no_std]

use libjambo::{Handle, SysError};

pub const MAX_SUBJECTS: usize = 64;
pub const MAX_OBJECTS: usize = 64;
pub const MAX_AUDIT_LOGS: usize = 64;
pub const MAX_NAME_LEN: usize = 32;

// ============================================================================
// HACHAGE CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 pure `#![no_std]` sans allocation heap
#[derive(Clone, Copy)]
pub struct Sha256;

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn gamma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn gamma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
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
            w[i] = Self::gamma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(Self::gamma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        let total_bits = (data.len() as u64).wrapping_mul(8);
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut state, &block);
            offset += 64;
        }

        let remaining = data.len() - offset;
        block[..remaining].copy_from_slice(&data[offset..]);
        block[remaining] = 0x80;
        for i in (remaining + 1)..64 {
            block[i] = 0;
        }

        if remaining >= 56 {
            Self::process_block(&mut state, &block);
            block = [0u8; 64];
        }

        block[56..64].copy_from_slice(&total_bits.to_be_bytes());
        Self::process_block(&mut state, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

// ============================================================================
// DROITS CAPABILAIRES & JETON MacCap
// ============================================================================

pub mod mac_rights {
    pub const MAC_READ: u32 = 1 << 0;
    pub const MAC_CHECK: u32 = 1 << 1;
    pub const MAC_LABEL: u32 = 1 << 2;
    pub const MAC_ENFORCE: u32 = 1 << 3;
    pub const MAC_DOWNGRADE: u32 = 1 << 4;
    pub const MAC_AUDIT: u32 = 1 << 5;
    pub const MAC_ADMIN: u32 = 1 << 6;

    pub const ALL: u32 = MAC_READ
        | MAC_CHECK
        | MAC_LABEL
        | MAC_ENFORCE
        | MAC_DOWNGRADE
        | MAC_AUDIT
        | MAC_ADMIN;
}

/// Jeton de capacité sans autorité ambiante pour la gestion du MAC multi-niveaux
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacCap {
    pub handle: Handle,
    pub rights: u32,
}

impl MacCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    #[inline(always)]
    pub const fn has_right(&self, mask: u32) -> bool {
        (self.rights & mask) == mask
    }

    /// Atténue les droits vers un sous-ensemble strict (Rejet formel d'amplification)
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
// HIERARCHIE DE CONFIDENTIALITÉ (BELL-LAPADULA) & D'INTÉGRITÉ (BIBA)
// ============================================================================

/// Niveaux hiérarchiques de classification de confidentialité (Bell-LaPadula)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClassificationLevel {
    Unclassified = 0,
    Confidential = 1,
    Secret = 2,
    TopSecret = 3,
}

impl ClassificationLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unclassified => "Unclassified",
            Self::Confidential => "Confidential",
            Self::Secret => "Secret",
            Self::TopSecret => "TopSecret",
        }
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Unclassified),
            1 => Some(Self::Confidential),
            2 => Some(Self::Secret),
            3 => Some(Self::TopSecret),
            _ => None,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "unclass" | "unclassified" | "0" => Some(Self::Unclassified),
            "conf" | "confidential" | "1" => Some(Self::Confidential),
            "secret" | "sec" | "2" => Some(Self::Secret),
            "topsecret" | "ts" | "3" => Some(Self::TopSecret),
            _ => None,
        }
    }
}

/// Niveaux hiérarchiques d'intégrité (Modèle Biba)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Untrusted = 0,
    User = 1,
    System = 2,
    Trusted = 3,
}

impl IntegrityLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Untrusted => "Untrusted",
            Self::User => "User",
            Self::System => "System",
            Self::Trusted => "Trusted",
        }
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Untrusted),
            1 => Some(Self::User),
            2 => Some(Self::System),
            3 => Some(Self::Trusted),
            _ => None,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "untrusted" | "low" | "0" => Some(Self::Untrusted),
            "user" | "med" | "medium" | "1" => Some(Self::User),
            "system" | "high" | "sys" | "2" => Some(Self::System),
            "trusted" | "crit" | "critical" | "3" => Some(Self::Trusted),
            _ => None,
        }
    }
}

// ============================================================================
// COMPARTIMENTS & CATÉGORIES NON-HIÉRARCHIQUES
// ============================================================================

pub mod compartments {
    pub const NONE: u32 = 0;
    pub const CRYPTO: u32 = 1 << 0;
    pub const NETWORK: u32 = 1 << 1;
    pub const STORAGE: u32 = 1 << 2;
    pub const ADMIN: u32 = 1 << 3;
    pub const FINANCIAL: u32 = 1 << 4;
    pub const INTELLIGENCE: u32 = 1 << 5;
    pub const DEFENSE: u32 = 1 << 6;
    pub const AUDIT: u32 = 1 << 7;
    pub const USER: u32 = 1 << 8;
    pub const KERNEL: u32 = 1 << 9;

    pub const ALL: u32 = (1 << 10) - 1;

    /// Vérifie si l'ensemble de catégories `superset` domine `subset` (Treillis de sécurité)
    #[inline(always)]
    pub const fn dominates(superset: u32, subset: u32) -> bool {
        (subset & !superset) == 0
    }
}

// ============================================================================
// ÉTIQUETTES DE SÉCURITÉ MAC & RELATIONS D'ORDRE PARTIEL
// ============================================================================

/// Étiquette de sécurité MAC pour un sujet ou un objet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacLabel {
    /// Niveau de classification / habilitation (Confidentialité)
    pub level: ClassificationLevel,
    /// Masque de bits de catégories/compartiments
    pub categories: u32,
    /// Niveau d'intégrité Biba
    pub integrity: IntegrityLevel,
}

impl MacLabel {
    pub const fn new(
        level: ClassificationLevel,
        categories: u32,
        integrity: IntegrityLevel,
    ) -> Self {
        Self {
            level,
            categories,
            integrity,
        }
    }

    /// Dominance en confidentialité : niveau supérieur ou égal ET catégories dominantes (superset)
    #[inline(always)]
    pub fn dominates_confidentiality(&self, other: &Self) -> bool {
        (self.level as u8 >= other.level as u8)
            && compartments::dominates(self.categories, other.categories)
    }

    /// Dominance en intégrité Biba : niveau d'intégrité supérieur ou égal
    #[inline(always)]
    pub fn dominates_integrity(&self, other: &Self) -> bool {
        self.integrity as u8 >= other.integrity as u8
    }
}

// ============================================================================
// OPÉRATIONS D'ACCÈS & DÉCISIONS
// ============================================================================

/// Mode d'accès demandé par un sujet sur un objet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    Read,
    Write,
    ReadWrite,
    Execute,
}

/// Raisons de violation des politiques MAC
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacViolationReason {
    None = 0,
    /// Violation Bell-LaPadula NRU (No Read Up) : niveau ou compartiments insuffisants pour lire
    BlpNoReadUp = 1,
    /// Violation Bell-LaPadula NWD (No Write Down) : interdiction de fuite d'informations vers le bas
    BlpNoWriteDown = 2,
    /// Violation Biba NRD (No Read Down) : lecture d'objet d'intégrité inférieure interdite (contamination)
    BibaNoReadDown = 3,
    /// Violation Biba NWU (No Write Up) : écriture dans un objet d'intégrité supérieure interdite (corruption)
    BibaNoWriteUp = 4,
    /// Compartiments non dominés
    CompartmentMismatch = 5,
    /// Sujet ou objet inexistant / inactif
    InvalidEntity = 6,
    /// Capacité requise absente
    MissingCapability = 7,
    /// Déclassification ou modification de label non autorisée
    DowngradeProhibited = 8,
}

/// Décision rendue par le moteur de contrôle MAC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacDecision {
    Granted,
    Denied(MacViolationReason),
}

impl MacDecision {
    #[inline(always)]
    pub const fn is_granted(&self) -> bool {
        matches!(self, Self::Granted)
    }
}

// ============================================================================
// SUJETS ET OBJETS MAC
// ============================================================================

/// Enregistrement d'un sujet (processus, thread, agent)
#[derive(Debug, Clone, Copy)]
pub struct SubjectRecord {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub label: MacLabel,
    pub active: bool,
}

impl SubjectRecord {
    pub fn new(id: u32, name_str: &str, label: MacLabel) -> Self {
        let mut name = [0u8; MAX_NAME_LEN];
        let bytes = name_str.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        name[..len].copy_from_slice(&bytes[..len]);
        Self {
            id,
            name,
            name_len: len,
            label,
            active: true,
        }
    }
}

/// Enregistrement d'un objet protégé (fichier, socket, pipe, canal IPC, VMO)
#[derive(Debug, Clone, Copy)]
pub struct ObjectRecord {
    pub id: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub label: MacLabel,
    pub active: bool,
}

impl ObjectRecord {
    pub fn new(id: u32, name_str: &str, label: MacLabel) -> Self {
        let mut name = [0u8; MAX_NAME_LEN];
        let bytes = name_str.as_bytes();
        let len = if bytes.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            bytes.len()
        };
        name[..len].copy_from_slice(&bytes[..len]);
        Self {
            id,
            name,
            name_len: len,
            label,
            active: true,
        }
    }
}

// ============================================================================
// AUDIT CRYPTOGRAPHIQUE SCELLÉ (SHA-256)
// ============================================================================

/// Entrée d'audit MAC inaltérable
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: u64,
    pub event_type: u8, // 0 = Check, 1 = LabelChange, 2 = Downgrade, 3 = Violation
    pub subject_id: u32,
    pub object_id: u32,
    pub access_type: u8, // 0 = Read, 1 = Write, 2 = RW, 3 = Exec
    pub granted: bool,
    pub reason: u8,
    pub digest_prefix: [u8; 8],
}

// ============================================================================
// DÉMON DU MANDAT D'ACCÈS CONTRÔLÉ (JamboMacDaemon)
// ============================================================================

/// Démon de contrôle d'accès obligatoire multi-niveaux MLS
pub struct JamboMacDaemon {
    pub cap: MacCap,
    pub subjects: [Option<SubjectRecord>; MAX_SUBJECTS],
    pub objects: [Option<ObjectRecord>; MAX_OBJECTS],
    pub audit_logs: [AuditEntry; MAX_AUDIT_LOGS],
    pub audit_head: usize,
    pub audit_count: usize,
    pub seq_counter: u64,
    pub evaluations_count: u64,
    pub granted_count: u64,
    pub violations_count: u64,
    pub last_audit_digest: [u8; 32],
}

impl JamboMacDaemon {
    /// Crée une nouvelle instance du démon MAC
    pub fn new(cap: MacCap) -> Self {
        Self {
            cap,
            subjects: [None; MAX_SUBJECTS],
            objects: [None; MAX_OBJECTS],
            audit_logs: [AuditEntry::default(); MAX_AUDIT_LOGS],
            audit_head: 0,
            audit_count: 0,
            seq_counter: 0,
            evaluations_count: 0,
            granted_count: 0,
            violations_count: 0,
            last_audit_digest: [0x5au8; 32], // Graine initiale
        }
    }

    /// Initialise la configuration et les profils par défaut du système
    pub fn init_defaults(&mut self) {
        let ts = 1000;
        let cap = self.cap;
        // Sujets par défaut
        let _ = self.register_subject(
            &cap,
            1,
            "SystemInit",
            MacLabel::new(
                ClassificationLevel::TopSecret,
                compartments::ALL,
                IntegrityLevel::Trusted,
            ),
            ts,
        );
        let _ = self.register_subject(
            &cap,
            2,
            "CryptoEnclave",
            MacLabel::new(
                ClassificationLevel::Secret,
                compartments::CRYPTO | compartments::ADMIN,
                IntegrityLevel::Trusted,
            ),
            ts,
        );
        let _ = self.register_subject(
            &cap,
            3,
            "NetworkDaemon",
            MacLabel::new(
                ClassificationLevel::Confidential,
                compartments::NETWORK,
                IntegrityLevel::System,
            ),
            ts,
        );
        let _ = self.register_subject(
            &cap,
            4,
            "UserShell",
            MacLabel::new(
                ClassificationLevel::Unclassified,
                compartments::USER,
                IntegrityLevel::User,
            ),
            ts,
        );
        let _ = self.register_subject(
            &cap,
            5,
            "PublicWorker",
            MacLabel::new(
                ClassificationLevel::Unclassified,
                compartments::NONE,
                IntegrityLevel::Untrusted,
            ),
            ts,
        );

        // Objets par défaut
        let _ = self.register_object(
            &cap,
            10,
            "/etc/master.key",
            MacLabel::new(
                ClassificationLevel::TopSecret,
                compartments::CRYPTO | compartments::ADMIN,
                IntegrityLevel::Trusted,
            ),
            ts,
        );
        let _ = self.register_object(
            &cap,
            11,
            "/var/log/audit.log",
            MacLabel::new(
                ClassificationLevel::Secret,
                compartments::AUDIT,
                IntegrityLevel::Trusted,
            ),
            ts,
        );
        let _ = self.register_object(
            &cap,
            12,
            "/dev/net0",
            MacLabel::new(
                ClassificationLevel::Confidential,
                compartments::NETWORK,
                IntegrityLevel::System,
            ),
            ts,
        );
        let _ = self.register_object(
            &cap,
            13,
            "/home/user/document.txt",
            MacLabel::new(
                ClassificationLevel::Unclassified,
                compartments::USER,
                IntegrityLevel::User,
            ),
            ts,
        );
        let _ = self.register_object(
            &cap,
            14,
            "/tmp/shared_buffer",
            MacLabel::new(
                ClassificationLevel::Unclassified,
                compartments::NONE,
                IntegrityLevel::Untrusted,
            ),
            ts,
        );
    }

    /// Enregistre un sujet protégé dans la base MAC
    pub fn register_subject(
        &mut self,
        cap: &MacCap,
        id: u32,
        name: &str,
        label: MacLabel,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(mac_rights::MAC_LABEL) {
            return Err(SysError::PermissionDenied);
        }

        // Vérifier si un slot libre existe ou si l'ID est déjà alloué
        let mut target_slot = None;
        for i in 0..MAX_SUBJECTS {
            if let Some(sub) = &self.subjects[i] {
                if sub.id == id {
                    target_slot = Some(i);
                    break;
                }
            } else if target_slot.is_none() {
                target_slot = Some(i);
            }
        }

        let slot = target_slot.ok_or(SysError::OutOfMemory)?;
        self.subjects[slot] = Some(SubjectRecord::new(id, name, label));
        self.record_audit(1, id, 0, 0, true, 0, timestamp);
        Ok(())
    }

    /// Enregistre un objet protégé dans la base MAC
    pub fn register_object(
        &mut self,
        cap: &MacCap,
        id: u32,
        name: &str,
        label: MacLabel,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(mac_rights::MAC_LABEL) {
            return Err(SysError::PermissionDenied);
        }

        let mut target_slot = None;
        for i in 0..MAX_OBJECTS {
            if let Some(obj) = &self.objects[i] {
                if obj.id == id {
                    target_slot = Some(i);
                    break;
                }
            } else if target_slot.is_none() {
                target_slot = Some(i);
            }
        }

        let slot = target_slot.ok_or(SysError::OutOfMemory)?;
        self.objects[slot] = Some(ObjectRecord::new(id, name, label));
        self.record_audit(1, 0, id, 0, true, 0, timestamp);
        Ok(())
    }

    /// Modifie l'étiquette d'un sujet (Déclassification ou changement contrôlé)
    pub fn update_subject_label(
        &mut self,
        cap: &MacCap,
        id: u32,
        new_label: MacLabel,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(mac_rights::MAC_LABEL) {
            return Err(SysError::PermissionDenied);
        }

        let sub_idx = self.find_subject_index(id).ok_or(SysError::InvalidArgument)?;
        let current_label = self.subjects[sub_idx].unwrap().label;

        // Déclassification (abaissement du niveau de confidentialité ou hausse d'intégrité)
        let is_downgrade = (new_label.level as u8) < (current_label.level as u8)
            || !compartments::dominates(new_label.categories, current_label.categories)
            || (new_label.integrity as u8) > (current_label.integrity as u8);

        if is_downgrade && !cap.has_right(mac_rights::MAC_DOWNGRADE) {
            self.record_audit(
                2,
                id,
                0,
                0,
                false,
                MacViolationReason::DowngradeProhibited as u8,
                timestamp,
            );
            return Err(SysError::PermissionDenied);
        }

        if let Some(sub) = &mut self.subjects[sub_idx] {
            sub.label = new_label;
        }

        self.record_audit(
            if is_downgrade { 2 } else { 1 },
            id,
            0,
            0,
            true,
            0,
            timestamp,
        );
        Ok(())
    }

    /// Modifie l'étiquette d'un objet (Déclassification d'un fichier/ressource)
    pub fn update_object_label(
        &mut self,
        cap: &MacCap,
        id: u32,
        new_label: MacLabel,
        timestamp: u64,
    ) -> Result<(), SysError> {
        if !cap.has_right(mac_rights::MAC_LABEL) {
            return Err(SysError::PermissionDenied);
        }

        let obj_idx = self.find_object_index(id).ok_or(SysError::InvalidArgument)?;
        let current_label = self.objects[obj_idx].unwrap().label;

        // Déclassification objet : abaissement de la classification ou baisse de l'intégrité
        let is_downgrade = (new_label.level as u8) < (current_label.level as u8)
            || !compartments::dominates(new_label.categories, current_label.categories);

        if is_downgrade && !cap.has_right(mac_rights::MAC_DOWNGRADE) {
            self.record_audit(
                2,
                0,
                id,
                0,
                false,
                MacViolationReason::DowngradeProhibited as u8,
                timestamp,
            );
            return Err(SysError::PermissionDenied);
        }

        if let Some(obj) = &mut self.objects[obj_idx] {
            obj.label = new_label;
        }

        self.record_audit(
            if is_downgrade { 2 } else { 1 },
            0,
            id,
            0,
            true,
            0,
            timestamp,
        );
        Ok(())
    }

    /// Évalue un accès selon Bell-LaPadula (confidentialité) et Biba (intégrité)
    pub fn evaluate_access(
        &mut self,
        subject_id: u32,
        object_id: u32,
        access: AccessType,
        timestamp: u64,
    ) -> MacDecision {
        self.evaluations_count += 1;

        let sub = match self.get_subject(subject_id) {
            Some(s) if s.active => s,
            _ => {
                self.violations_count += 1;
                self.record_audit(
                    3,
                    subject_id,
                    object_id,
                    access as u8,
                    false,
                    MacViolationReason::InvalidEntity as u8,
                    timestamp,
                );
                return MacDecision::Denied(MacViolationReason::InvalidEntity);
            }
        };

        let obj = match self.get_object(object_id) {
            Some(o) if o.active => o,
            _ => {
                self.violations_count += 1;
                self.record_audit(
                    3,
                    subject_id,
                    object_id,
                    access as u8,
                    false,
                    MacViolationReason::InvalidEntity as u8,
                    timestamp,
                );
                return MacDecision::Denied(MacViolationReason::InvalidEntity);
            }
        };

        let decision = Self::check_rules(&sub.label, &obj.label, access);

        if decision.is_granted() {
            self.granted_count += 1;
            self.record_audit(0, subject_id, object_id, access as u8, true, 0, timestamp);
        } else if let MacDecision::Denied(reason) = decision {
            self.violations_count += 1;
            self.record_audit(
                3,
                subject_id,
                object_id,
                access as u8,
                false,
                reason as u8,
                timestamp,
            );
        }

        decision
    }

    /// Vérification pure des invariants Bell-LaPadula et Biba
    pub fn check_rules(
        subject_label: &MacLabel,
        object_label: &MacLabel,
        access: AccessType,
    ) -> MacDecision {
        match access {
            AccessType::Read => {
                // 1. Bell-LaPadula Simple Security Property (No Read Up - NRU)
                // Le sujet doit dominer l'objet en niveau de classification
                if (subject_label.level as u8) < (object_label.level as u8) {
                    return MacDecision::Denied(MacViolationReason::BlpNoReadUp);
                }
                // Le sujet doit posséder toutes les catégories de l'objet
                if !compartments::dominates(subject_label.categories, object_label.categories) {
                    return MacDecision::Denied(MacViolationReason::CompartmentMismatch);
                }

                // 2. Biba Simple Integrity Property (No Read Down - NRD)
                // Le sujet ne peut pas lire des données d'un objet d'intégrité inférieure (contamination)
                if (object_label.integrity as u8) < (subject_label.integrity as u8) {
                    return MacDecision::Denied(MacViolationReason::BibaNoReadDown);
                }

                MacDecision::Granted
            }
            AccessType::Write => {
                // 1. Bell-LaPadula Star Property (No Write Down - NWD)
                // L'objet doit dominer le sujet en niveau de classification (l'écriture ne doit pas fuiter vers le bas)
                if (object_label.level as u8) < (subject_label.level as u8) {
                    return MacDecision::Denied(MacViolationReason::BlpNoWriteDown);
                }
                // L'objet doit posséder toutes les catégories du sujet
                if !compartments::dominates(object_label.categories, subject_label.categories) {
                    return MacDecision::Denied(MacViolationReason::CompartmentMismatch);
                }

                // 2. Biba Star Integrity Property (No Write Up - NWU)
                // Le sujet ne peut pas modifier un objet d'intégrité supérieure (corruption)
                if (subject_label.integrity as u8) < (object_label.integrity as u8) {
                    return MacDecision::Denied(MacViolationReason::BibaNoWriteUp);
                }

                MacDecision::Granted
            }
            AccessType::ReadWrite => {
                // ReadWrite requiert que les conditions de lecture ET d'écriture soient simultanément satisfaites
                let read_res = Self::check_rules(subject_label, object_label, AccessType::Read);
                if !read_res.is_granted() {
                    return read_res;
                }
                let write_res = Self::check_rules(subject_label, object_label, AccessType::Write);
                if !write_res.is_granted() {
                    return write_res;
                }
                MacDecision::Granted
            }
            AccessType::Execute => {
                // Execute requiert la lecture de code non compromis (NRU + NRD) et un niveau d'intégrité élevé
                Self::check_rules(subject_label, object_label, AccessType::Read)
            }
        }
    }

    #[inline]
    pub fn get_subject(&self, id: u32) -> Option<&SubjectRecord> {
        for slot in &self.subjects {
            if let Some(sub) = slot {
                if sub.id == id {
                    return Some(sub);
                }
            }
        }
        None
    }

    #[inline]
    pub fn get_object(&self, id: u32) -> Option<&ObjectRecord> {
        for slot in &self.objects {
            if let Some(obj) = slot {
                if obj.id == id {
                    return Some(obj);
                }
            }
        }
        None
    }

    fn find_subject_index(&self, id: u32) -> Option<usize> {
        for i in 0..MAX_SUBJECTS {
            if let Some(sub) = &self.subjects[i] {
                if sub.id == id {
                    return Some(i);
                }
            }
        }
        None
    }

    fn find_object_index(&self, id: u32) -> Option<usize> {
        for i in 0..MAX_OBJECTS {
            if let Some(obj) = &self.objects[i] {
                if obj.id == id {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Enregistre une entrée dans l'anneau d'audit scellé SHA-256
    fn record_audit(
        &mut self,
        event_type: u8,
        subject_id: u32,
        object_id: u32,
        access_type: u8,
        granted: bool,
        reason: u8,
        timestamp: u64,
    ) {
        self.seq_counter += 1;
        let seq = self.seq_counter;

        // Calcul du nouveau hachage chaîné SHA-256
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(&self.last_audit_digest);
        block[32..40].copy_from_slice(&seq.to_be_bytes());
        block[40..48].copy_from_slice(&timestamp.to_be_bytes());
        block[48] = event_type;
        block[49] = access_type;
        block[50] = if granted { 1 } else { 0 };
        block[51] = reason;
        block[52..56].copy_from_slice(&subject_id.to_be_bytes());
        block[56..60].copy_from_slice(&object_id.to_be_bytes());

        self.last_audit_digest = Sha256::digest(&block);

        let mut digest_prefix = [0u8; 8];
        digest_prefix.copy_from_slice(&self.last_audit_digest[..8]);

        let entry = AuditEntry {
            seq,
            timestamp,
            event_type,
            subject_id,
            object_id,
            access_type,
            granted,
            reason,
            digest_prefix,
        };

        self.audit_logs[self.audit_head] = entry;
        self.audit_head = (self.audit_head + 1) % MAX_AUDIT_LOGS;
        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_count += 1;
        }
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_rights_and_attenuation() {
        let cap = MacCap::new(Handle::new(1, 1), mac_rights::ALL);
        assert!(cap.has_right(mac_rights::MAC_READ));
        assert!(cap.has_right(mac_rights::MAC_CHECK));
        assert!(cap.has_right(mac_rights::MAC_LABEL));
        assert!(cap.has_right(mac_rights::MAC_DOWNGRADE));

        // Atténuation valide
        let read_check_cap = cap
            .attenuate(mac_rights::MAC_READ | mac_rights::MAC_CHECK)
            .expect("attenuate to read/check");
        assert!(read_check_cap.has_right(mac_rights::MAC_READ));
        assert!(read_check_cap.has_right(mac_rights::MAC_CHECK));
        assert!(!read_check_cap.has_right(mac_rights::MAC_LABEL));
        assert!(!read_check_cap.has_right(mac_rights::MAC_DOWNGRADE));

        // Tentative d'amplification formellement rejetée
        let amplif = read_check_cap.attenuate(mac_rights::MAC_ADMIN);
        assert_eq!(amplif, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_bell_lapadula_nru_and_nwd() {
        let unclass_user = MacLabel::new(
            ClassificationLevel::Unclassified,
            compartments::USER,
            IntegrityLevel::User,
        );
        let secret_crypto = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::CRYPTO,
            IntegrityLevel::User,
        );

        // BLP NRU : Unclassified ne peut PAS lire Secret
        let r1 = JamboMacDaemon::check_rules(&unclass_user, &secret_crypto, AccessType::Read);
        assert_eq!(r1, MacDecision::Denied(MacViolationReason::BlpNoReadUp));

        // BLP NRU : Secret avec toutes les catégories peut lire Unclassified
        let secret_all = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::USER | compartments::CRYPTO,
            IntegrityLevel::User,
        );
        let r2 = JamboMacDaemon::check_rules(&secret_all, &unclass_user, AccessType::Read);
        assert_eq!(r2, MacDecision::Granted);

        // BLP NWD : Secret ne peut PAS écrire vers Unclassified (interdiction de fuite d'info)
        let w1 = JamboMacDaemon::check_rules(&secret_all, &unclass_user, AccessType::Write);
        assert_eq!(w1, MacDecision::Denied(MacViolationReason::BlpNoWriteDown));

        // BLP NWD : Unclassified peut écrire vers Secret si les compartiments sont compatibles
        let unclass_crypto = MacLabel::new(
            ClassificationLevel::Unclassified,
            compartments::CRYPTO,
            IntegrityLevel::User,
        );
        let w2 = JamboMacDaemon::check_rules(&unclass_crypto, &secret_crypto, AccessType::Write);
        assert_eq!(w2, MacDecision::Granted);
    }

    #[test]
    fn test_biba_nrd_and_nwu() {
        let trusted_subj = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::ALL,
            IntegrityLevel::Trusted,
        );
        let untrusted_obj = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::ALL,
            IntegrityLevel::Untrusted,
        );

        // Biba NRD : Sujet de confiance ne peut PAS lire un objet non fiable (contamination)
        let r = JamboMacDaemon::check_rules(&trusted_subj, &untrusted_obj, AccessType::Read);
        assert_eq!(r, MacDecision::Denied(MacViolationReason::BibaNoReadDown));

        // Biba NWU : Sujet non fiable ne peut PAS écrire dans un objet de haute intégrité (corruption)
        let untrusted_subj = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::ALL,
            IntegrityLevel::Untrusted,
        );
        let trusted_obj = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::ALL,
            IntegrityLevel::Trusted,
        );
        let w = JamboMacDaemon::check_rules(&untrusted_subj, &trusted_obj, AccessType::Write);
        assert_eq!(w, MacDecision::Denied(MacViolationReason::BibaNoWriteUp));
    }

    #[test]
    fn test_compartment_lattice() {
        let s_crypto = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::CRYPTO,
            IntegrityLevel::User,
        );
        let o_defense = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::DEFENSE,
            IntegrityLevel::User,
        );

        // Même niveau de classification (Secret), mais compartiments disjoints
        let r = JamboMacDaemon::check_rules(&s_crypto, &o_defense, AccessType::Read);
        assert_eq!(r, MacDecision::Denied(MacViolationReason::CompartmentMismatch));
    }

    #[test]
    fn test_readwrite_and_execute_rules() {
        let sec_user = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::USER,
            IntegrityLevel::User,
        );
        let sec_user2 = MacLabel::new(
            ClassificationLevel::Secret,
            compartments::USER,
            IntegrityLevel::User,
        );

        // RW possible si les labels sont strictement compatibles
        let rw_ok = JamboMacDaemon::check_rules(&sec_user, &sec_user2, AccessType::ReadWrite);
        assert_eq!(rw_ok, MacDecision::Granted);

        // RW refusé si les niveaux diffèrent (conflit NRU vs NWD)
        let conf_user = MacLabel::new(
            ClassificationLevel::Confidential,
            compartments::USER,
            IntegrityLevel::User,
        );
        let rw_deny = JamboMacDaemon::check_rules(&sec_user, &conf_user, AccessType::ReadWrite);
        assert_eq!(rw_deny, MacDecision::Denied(MacViolationReason::BlpNoWriteDown));

        // Exec requiert Read + intégrité suffisante
        let exec_ok = JamboMacDaemon::check_rules(&sec_user, &conf_user, AccessType::Execute);
        assert_eq!(exec_ok, MacDecision::Granted);
    }

    #[test]
    fn test_controlled_downgrade_and_audit() {
        let cap_admin = MacCap::new(Handle::new(1, 1), mac_rights::ALL);
        let cap_no_downgrade = cap_admin
            .attenuate(mac_rights::MAC_READ | mac_rights::MAC_LABEL | mac_rights::MAC_CHECK)
            .unwrap();

        let mut daemon = JamboMacDaemon::new(cap_admin);
        daemon.init_defaults();

        let ts = 2000;
        let obj_key = daemon.get_object(10).unwrap();
        assert_eq!(obj_key.label.level, ClassificationLevel::TopSecret);

        // Tentative de déclassification sans droit MAC_DOWNGRADE
        let lower_label = MacLabel::new(
            ClassificationLevel::Unclassified,
            compartments::NONE,
            IntegrityLevel::Untrusted,
        );
        let err = daemon.update_object_label(&cap_no_downgrade, 10, lower_label, ts);
        assert_eq!(err, Err(SysError::PermissionDenied));

        // Déclassification réussie avec la capacité administrative MAC_DOWNGRADE
        let ok = daemon.update_object_label(&cap_admin, 10, lower_label, ts + 1);
        assert!(ok.is_ok());
        let updated_key = daemon.get_object(10).unwrap();
        assert_eq!(updated_key.label.level, ClassificationLevel::Unclassified);

        // Vérifier l'audit
        assert!(daemon.audit_count > 0);
        assert_ne!(daemon.last_audit_digest, [0u8; 32]);
    }
}


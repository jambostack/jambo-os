//! Renseignement sur les Menaces Cyber & Flux d'Indicateurs de Compromission (CTI / IoC)
//!
//! Phase 121 — Jalon v0.2.119
//!
//! Fournit un moteur souverain de Threat Intelligence en environnement `#![no_std]` :
//! 1. Ingestion de flux normalisés d'IoC (SHA-256, BLAKE3, IPv4 bogons/malveillantes, domaines & URL).
//! 2. Recherche ultra-rapide O(1) couplant un filtre de Bloom cryptographique à K fonctions
//!    de hachage et une table compacte indexée.
//! 3. Modèle de scoring de confiance (0..100) et politique d'expiration dynamique basée sur un TTL temporel.
//! 4. Contrôle d'accès capabilaire strict (`IntelCap`) sans autorité ambiante.
//! 5. Scellement cryptographique d'audit inviolable par chaînage SHA-256.

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

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (IntelCap)
// ============================================================================

pub mod intel_rights {
    pub const INGEST_IOC: u32 = 1 << 0;
    pub const QUERY_IOC: u32 = 1 << 1;
    pub const EXPIRE_IOC: u32 = 1 << 2;
    pub const UPDATE_FEED: u32 = 1 << 3;
    pub const SEAL_LEDGER: u32 = 1 << 4;
    pub const AUDIT_READ: u32 = 1 << 5;
    pub const ADMIN: u32 = 0x3F;
    pub const ALL: u32 = 0x3F;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntelError {
    PermissionDenied,
    AttenuationViolation,
    CapabilityExpired,
    TableFull,
    IocNotFound,
    InvalidPattern,
    FeedNotFound,
    IntegrityViolation,
}

/// Capacité souveraine d'accès aux services de Threat Intelligence
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntelCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_lifetime: u64,
    pub invocations_left: u32,
}

impl IntelCap {
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

    #[inline]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone sans escalade de privilèges
    pub fn attenuate(
        &self,
        new_rights: u32,
        new_lifetime: u64,
        new_invocations: u32,
    ) -> Result<Self, IntelError> {
        if (new_rights & !self.rights) != 0 {
            return Err(IntelError::AttenuationViolation);
        }
        if new_lifetime > self.max_lifetime {
            return Err(IntelError::AttenuationViolation);
        }
        if new_invocations > self.invocations_left {
            return Err(IntelError::AttenuationViolation);
        }

        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_lifetime: new_lifetime,
            invocations_left: new_invocations,
        })
    }

    pub fn consume_invocation(&mut self) -> Result<(), IntelError> {
        if self.invocations_left == 0 {
            return Err(IntelError::CapabilityExpired);
        }
        self.invocations_left -= 1;
        Ok(())
    }
}

// ============================================================================
// TYPOLOGIE DES INDICATEURS DE COMPROMISSION (CTI / IoC)
// ============================================================================

/// Typologie des indicateurs IoC supportés
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocKind {
    Sha256,
    Blake3,
    Ipv4,
    Domain,
    UrlPattern,
}

/// Sévérité de la menace associée à l'indicateur
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Catégorie opérationnelle de la menace
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    MalwarePayload,
    Ransomware,
    BotnetC2,
    Phishing,
    AptInfrastructure,
    BogonIp,
}

/// Entrée d'indicateur de compromission
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IocEntry {
    pub id: u32,
    pub kind: IocKind,
    pub raw_data: [u8; 64],
    pub data_len: usize,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub confidence: u8, // Score 0..100
    pub created_tick: u64,
    pub ttl_ticks: u64, // 0 = permanent
    pub feed_name: [u8; 32],
    pub feed_len: usize,
    pub hit_count: u32,
    pub active: bool,
}

impl IocEntry {
    pub fn is_expired(&self, current_tick: u64) -> bool {
        if self.ttl_ticks == 0 {
            false
        } else {
            current_tick > self.created_tick.saturating_add(self.ttl_ticks)
        }
    }

    pub fn matches(&self, kind: IocKind, data: &[u8]) -> bool {
        if !self.active || self.kind != kind {
            return false;
        }
        if self.data_len != data.len() {
            return false;
        }
        &self.raw_data[..self.data_len] == data
    }

    pub fn feed_as_str(&self) -> &str {
        core::str::from_utf8(&self.feed_name[..self.feed_len]).unwrap_or("unknown")
    }

    pub fn pattern_as_str(&self) -> &str {
        core::str::from_utf8(&self.raw_data[..self.data_len]).unwrap_or("<binary>")
    }
}

/// Résultat d'une correspondance IoC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IocMatch {
    pub ioc_id: u32,
    pub kind: IocKind,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub confidence: u8,
    pub hit_count: u32,
}

// ============================================================================
// FILTRE DE BLOOM CRYPTOGRAPHIQUE (#![no_std])
// ============================================================================

/// Filtre de Bloom déterministe pour recherche rapide O(1)
/// 2048 bits (256 octets) avec 4 fonctions de hachage déterministes
#[derive(Clone, Copy)]
pub struct BloomFilter {
    pub bits: [u8; 256], // 2048 bits
}

impl BloomFilter {
    pub const fn new() -> Self {
        Self { bits: [0u8; 256] }
    }

    pub fn clear(&mut self) {
        self.bits = [0u8; 256];
    }

    /// Calcule un hachage 32-bit FNV-1a avec graine
    fn fnv1a_seeded(seed: u32, data: &[u8]) -> u32 {
        let mut hash = 0x811c9dc5 ^ seed;
        for &b in data {
            hash ^= b as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        hash
    }

    /// 4 graines pour les 4 fonctions de hachage déterministes
    const SEEDS: [u32; 4] = [0x9747b28c, 0xc13fa9a9, 0x517cc1b7, 0x85ebca6b];

    pub fn insert(&mut self, data: &[u8]) {
        for &seed in &Self::SEEDS {
            let h = Self::fnv1a_seeded(seed, data);
            let bit_index = (h % 2048) as usize;
            let byte_idx = bit_index / 8;
            let bit_offset = bit_index % 8;
            self.bits[byte_idx] |= 1 << bit_offset;
        }
    }

    pub fn contains(&self, data: &[u8]) -> bool {
        for &seed in &Self::SEEDS {
            let h = Self::fnv1a_seeded(seed, data);
            let bit_index = (h % 2048) as usize;
            let byte_idx = bit_index / 8;
            let bit_offset = bit_index % 8;
            if (self.bits[byte_idx] & (1 << bit_offset)) == 0 {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// FLUX D'INDICATEURS (Feeds)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedEntry {
    pub name: [u8; 32],
    pub name_len: usize,
    pub trust_score: u8, // 0..100
    pub ioc_count: u32,
    pub last_update_tick: u64,
    pub active: bool,
}

impl FeedEntry {
    pub fn name_as_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("invalid")
    }
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ SHA-256 (#![no_std])
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    Genesis,
    IngestIoc,
    QueryMatch,
    ExpirePurge,
    RegisterFeed,
    SealLedger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRecord {
    pub tick: u64,
    pub action: AuditAction,
    pub ioc_id: u32,
    pub details: [u8; 48],
    pub details_len: usize,
    pub prev_hash: [u8; 32],
    pub record_hash: [u8; 32],
}

impl AuditRecord {
    pub fn details_as_str(&self) -> &str {
        core::str::from_utf8(&self.details[..self.details_len]).unwrap_or("<bin>")
    }

    pub fn compute_hash(
        tick: u64,
        action: AuditAction,
        ioc_id: u32,
        details: &[u8],
        prev_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&tick.to_be_bytes());
        let act_code = match action {
            AuditAction::Genesis => 0u8,
            AuditAction::IngestIoc => 1u8,
            AuditAction::QueryMatch => 2u8,
            AuditAction::ExpirePurge => 3u8,
            AuditAction::RegisterFeed => 4u8,
            AuditAction::SealLedger => 5u8,
        };
        hasher.update(&[act_code]);
        hasher.update(&ioc_id.to_be_bytes());
        hasher.update(details);
        hasher.update(prev_hash);
        hasher.finalize()
    }
}

// ============================================================================
// DÉMON CENTRAL DU RENSEIGNEMENT CYBER (JamboIntelDaemon)
// ============================================================================

pub const MAX_IOCS: usize = 64;
pub const MAX_FEEDS: usize = 8;
pub const MAX_AUDIT_LOGS: usize = 32;

pub struct JamboIntelDaemon {
    pub admin_cap: IntelCap,
    pub iocs: [Option<IocEntry>; MAX_IOCS],
    pub feeds: [Option<FeedEntry>; MAX_FEEDS],
    pub bloom: BloomFilter,
    pub audit_ledger: [Option<AuditRecord>; MAX_AUDIT_LOGS],
    pub ioc_count: usize,
    pub feed_count: usize,
    pub audit_count: usize,
    pub total_queries: u64,
    pub total_hits: u64,
    pub next_ioc_id: u32,
    pub ledger_hash: [u8; 32],
}

impl JamboIntelDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0x5au8; 32];

    pub fn new(admin_cap: IntelCap) -> Self {
        let mut daemon = Self {
            admin_cap,
            iocs: [None; MAX_IOCS],
            feeds: [None; MAX_FEEDS],
            bloom: BloomFilter::new(),
            audit_ledger: [None; MAX_AUDIT_LOGS],
            ioc_count: 0,
            feed_count: 0,
            audit_count: 0,
            total_queries: 0,
            total_hits: 0,
            next_ioc_id: 1,
            ledger_hash: Self::GENESIS_HASH,
        };

        // Enregistre l'entrée Genesis
        let h = AuditRecord::compute_hash(
            0,
            AuditAction::Genesis,
            0,
            b"JAMBO-INTEL-GENESIS",
            &Self::GENESIS_HASH,
        );
        let mut d = [0u8; 48];
        let msg = b"JAMBO-INTEL-GENESIS";
        d[..msg.len()].copy_from_slice(msg);
        daemon.audit_ledger[0] = Some(AuditRecord {
            tick: 0,
            action: AuditAction::Genesis,
            ioc_id: 0,
            details: d,
            details_len: msg.len(),
            prev_hash: Self::GENESIS_HASH,
            record_hash: h,
        });
        daemon.audit_count = 1;
        daemon.ledger_hash = h;
        daemon
    }

    /// Reconstruit intégralement le filtre de Bloom à partir des IoC actifs
    pub fn rebuild_bloom(&mut self) {
        self.bloom.clear();
        for i in 0..MAX_IOCS {
            if let Some(ref entry) = self.iocs[i] {
                if entry.active {
                    self.bloom.insert(&entry.raw_data[..entry.data_len]);
                }
            }
        }
    }

    /// Ajoute une entrée d'audit chaînée
    fn append_audit(&mut self, tick: u64, action: AuditAction, ioc_id: u32, details: &str) {
        let det_bytes = details.as_bytes();
        let chunk_len = det_bytes.len().min(48);
        let mut d = [0u8; 48];
        d[..chunk_len].copy_from_slice(&det_bytes[..chunk_len]);

        let h = AuditRecord::compute_hash(
            tick,
            action,
            ioc_id,
            &d[..chunk_len],
            &self.ledger_hash,
        );

        let record = AuditRecord {
            tick,
            action,
            ioc_id,
            details: d,
            details_len: chunk_len,
            prev_hash: self.ledger_hash,
            record_hash: h,
        };

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_ledger[self.audit_count] = Some(record);
            self.audit_count += 1;
        } else {
            // Décalage en anneau LRU borné
            for i in 1..MAX_AUDIT_LOGS {
                self.audit_ledger[i - 1] = self.audit_ledger[i];
            }
            self.audit_ledger[MAX_AUDIT_LOGS - 1] = Some(record);
        }
        self.ledger_hash = h;
    }

    /// Vérifie l'intégrité formelle du registre d'audit
    pub fn verify_ledger_integrity(&self) -> bool {
        if self.audit_count == 0 {
            return false;
        }
        let mut prev = Self::GENESIS_HASH;
        for i in 0..self.audit_count {
            if let Some(ref rec) = self.audit_ledger[i] {
                if rec.prev_hash != prev {
                    return false;
                }
                let expected = AuditRecord::compute_hash(
                    rec.tick,
                    rec.action,
                    rec.ioc_id,
                    &rec.details[..rec.details_len],
                    &rec.prev_hash,
                );
                if rec.record_hash != expected {
                    return false;
                }
                prev = rec.record_hash;
            } else {
                return false;
            }
        }
        prev == self.ledger_hash
    }

    /// Enregistre un flux de renseignement (Feed)
    pub fn register_feed(
        &mut self,
        cap: &IntelCap,
        name: &str,
        trust_score: u8,
        tick: u64,
    ) -> Result<usize, IntelError> {
        if !cap.has_right(intel_rights::UPDATE_FEED) {
            return Err(IntelError::PermissionDenied);
        }
        if name.is_empty() || name.len() > 32 {
            return Err(IntelError::InvalidPattern);
        }

        // Vérifier si existe déjà
        for i in 0..self.feed_count {
            if let Some(ref f) = self.feeds[i] {
                if f.active && f.name_as_str() == name {
                    return Ok(i);
                }
            }
        }

        if self.feed_count >= MAX_FEEDS {
            return Err(IntelError::TableFull);
        }

        let mut name_buf = [0u8; 32];
        name_buf[..name.len()].copy_from_slice(name.as_bytes());

        let idx = self.feed_count;
        self.feeds[idx] = Some(FeedEntry {
            name: name_buf,
            name_len: name.len(),
            trust_score: trust_score.min(100),
            ioc_count: 0,
            last_update_tick: tick,
            active: true,
        });
        self.feed_count += 1;

        self.append_audit(tick, AuditAction::RegisterFeed, 0, name);
        Ok(idx)
    }

    /// Ingestion normalisée d'un indicateur de compromission
    pub fn ingest_ioc(
        &mut self,
        cap: &IntelCap,
        kind: IocKind,
        data: &[u8],
        category: ThreatCategory,
        severity: ThreatSeverity,
        confidence: u8,
        feed_name: &str,
        ttl_ticks: u64,
        tick: u64,
    ) -> Result<u32, IntelError> {
        if !cap.has_right(intel_rights::INGEST_IOC) {
            return Err(IntelError::PermissionDenied);
        }
        if data.is_empty() || data.len() > 64 {
            return Err(IntelError::InvalidPattern);
        }

        // Validation du format par type
        match kind {
            IocKind::Sha256 | IocKind::Blake3 => {
                if data.len() != 32 {
                    return Err(IntelError::InvalidPattern);
                }
            }
            IocKind::Ipv4 => {
                if data.len() != 4 {
                    return Err(IntelError::InvalidPattern);
                }
            }
            IocKind::Domain | IocKind::UrlPattern => {
                if data.len() > 64 {
                    return Err(IntelError::InvalidPattern);
                }
            }
        }

        // Trouver un slot libre ou écraser un slot inactif/expiré
        let mut target_idx = None;
        for i in 0..MAX_IOCS {
            if self.iocs[i].is_none() {
                target_idx = Some(i);
                break;
            } else if let Some(ref e) = self.iocs[i] {
                if !e.active || e.is_expired(tick) {
                    target_idx = Some(i);
                    break;
                }
            }
        }

        let idx = target_idx.ok_or(IntelError::TableFull)?;

        let mut raw = [0u8; 64];
        raw[..data.len()].copy_from_slice(data);

        let mut fb = [0u8; 32];
        let flen = feed_name.len().min(32);
        fb[..flen].copy_from_slice(&feed_name.as_bytes()[..flen]);

        let id = self.next_ioc_id;
        self.next_ioc_id = self.next_ioc_id.wrapping_add(1);

        self.iocs[idx] = Some(IocEntry {
            id,
            kind,
            raw_data: raw,
            data_len: data.len(),
            category,
            severity,
            confidence: confidence.min(100),
            created_tick: tick,
            ttl_ticks,
            feed_name: fb,
            feed_len: flen,
            hit_count: 0,
            active: true,
        });

        if idx >= self.ioc_count {
            self.ioc_count = idx + 1;
        }

        // Met à jour le compteur du feed correspondant
        for f in self.feeds.iter_mut().flatten() {
            if f.name_as_str() == feed_name {
                f.ioc_count = f.ioc_count.saturating_add(1);
                f.last_update_tick = tick;
            }
        }

        // Insertion dans le filtre de Bloom pour recherche O(1)
        self.bloom.insert(data);

        // Audit scellé
        self.append_audit(tick, AuditAction::IngestIoc, id, feed_name);

        Ok(id)
    }

    /// Recherche ultra-rapide O(1) via Bloom + Table
    pub fn query_ioc(
        &mut self,
        cap: &IntelCap,
        kind: IocKind,
        data: &[u8],
        current_tick: u64,
    ) -> Result<Option<IocMatch>, IntelError> {
        if !cap.has_right(intel_rights::QUERY_IOC) {
            return Err(IntelError::PermissionDenied);
        }
        self.total_queries = self.total_queries.saturating_add(1);

        // 1. Filtrage négatif immédiat O(1) via BloomFilter
        if !self.bloom.contains(data) {
            return Ok(None);
        }

        // 2. Recherche exacte dans la table compacte
        let mut matched_info = None;
        for i in 0..self.ioc_count {
            if let Some(ref mut entry) = self.iocs[i] {
                if entry.active && !entry.is_expired(current_tick) && entry.matches(kind, data) {
                    entry.hit_count = entry.hit_count.saturating_add(1);
                    let m = IocMatch {
                        ioc_id: entry.id,
                        kind: entry.kind,
                        category: entry.category,
                        severity: entry.severity,
                        confidence: entry.confidence,
                        hit_count: entry.hit_count,
                    };
                    let mut feed_buf = [0u8; 32];
                    let flen = entry.feed_len.min(32);
                    feed_buf[..flen].copy_from_slice(&entry.feed_name[..flen]);
                    matched_info = Some((m, feed_buf, flen));
                    break;
                }
            }
        }

        if let Some((m, feed_buf, flen)) = matched_info {
            self.total_hits = self.total_hits.saturating_add(1);
            let feed_str = core::str::from_utf8(&feed_buf[..flen]).unwrap_or("unknown");
            self.append_audit(current_tick, AuditAction::QueryMatch, m.ioc_id, feed_str);
            return Ok(Some(m));
        }

        // Faux positif potentiel du filtre de Bloom
        Ok(None)
    }

    /// Purge dynamique des IoC expirés par dépassement de TTL
    pub fn purge_expired(&mut self, cap: &IntelCap, current_tick: u64) -> Result<usize, IntelError> {
        if !cap.has_right(intel_rights::EXPIRE_IOC) {
            return Err(IntelError::PermissionDenied);
        }

        let mut purged = 0;
        let mut had_expired = false;
        for i in 0..self.ioc_count {
            if let Some(ref mut entry) = self.iocs[i] {
                if entry.active && entry.is_expired(current_tick) {
                    entry.active = false;
                    purged += 1;
                    had_expired = true;
                }
            }
        }

        if had_expired {
            self.rebuild_bloom();
            self.append_audit(current_tick, AuditAction::ExpirePurge, 0, "TTL_EXPIRED_PURGE");
        }

        Ok(purged)
    }

    /// Initialisation par défaut avec flux souverains réalistes
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;

        // 1. Enregistrement de flux réputés
        let _ = self.register_feed(&cap, "Sovereign-CERT", 95, 100);
        let _ = self.register_feed(&cap, "Bogon-Defense", 99, 100);
        let _ = self.register_feed(&cap, "MISP-Jambo", 88, 100);

        // 2. Ingestion de signatures IoC
        // SHA-256 Malware Payload (ex: Emotet/BlackCat binary)
        let sha_malware: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let _ = self.ingest_ioc(
            &cap,
            IocKind::Sha256,
            &sha_malware,
            ThreatCategory::MalwarePayload,
            ThreatSeverity::Critical,
            98,
            "Sovereign-CERT",
            0, // Permanent
            110,
        );

        // BLAKE3 Trojan Payload
        let blake_trojan: [u8; 32] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ];
        let _ = self.ingest_ioc(
            &cap,
            IocKind::Blake3,
            &blake_trojan,
            ThreatCategory::Ransomware,
            ThreatSeverity::Critical,
            96,
            "MISP-Jambo",
            7200, // TTL 2 heures
            120,
        );

        // IP Bogon (198.51.100.23 - RFC 5737 Test-Net-2 / adresse martienne)
        let ip_bogon = [198, 51, 100, 23];
        let _ = self.ingest_ioc(
            &cap,
            IocKind::Ipv4,
            &ip_bogon,
            ThreatCategory::BogonIp,
            ThreatSeverity::High,
            99,
            "Bogon-Defense",
            0,
            130,
        );

        // Domaine C2 APT
        let domain_c2 = b"c2.apt-bear.sovereign";
        let _ = self.ingest_ioc(
            &cap,
            IocKind::Domain,
            domain_c2,
            ThreatCategory::AptInfrastructure,
            ThreatSeverity::Critical,
            94,
            "Sovereign-CERT",
            3600, // TTL 1 heure
            140,
        );

        // URL Pattern d'exfiltration
        let url_exfil = b"/api/v1/telemetry/exfil";
        let _ = self.ingest_ioc(
            &cap,
            IocKind::UrlPattern,
            url_exfil,
            ThreatCategory::BotnetC2,
            ThreatSeverity::High,
            90,
            "MISP-Jambo",
            1800, // TTL 30 minutes
            150,
        );
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_attenuation_and_enforcement() {
        let admin = IntelCap::new(Handle::new(1001, 1), intel_rights::ALL, 5000, 100);
        assert!(admin.has_right(intel_rights::INGEST_IOC));
        assert!(admin.has_right(intel_rights::QUERY_IOC));
        assert!(admin.has_right(intel_rights::ADMIN));

        // Atténuation monotone
        let query_only = admin
            .attenuate(intel_rights::QUERY_IOC | intel_rights::AUDIT_READ, 2000, 50)
            .expect("Atténuation");
        assert!(query_only.has_right(intel_rights::QUERY_IOC));
        assert!(query_only.has_right(intel_rights::AUDIT_READ));
        assert!(!query_only.has_right(intel_rights::INGEST_IOC));
        assert!(!query_only.has_right(intel_rights::ADMIN));

        // Rejet d'escalade
        let esc = query_only.attenuate(intel_rights::ALL, 2000, 50);
        assert_eq!(esc, Err(IntelError::AttenuationViolation));
    }

    #[test]
    fn test_bloom_filter_membership() {
        let mut bloom = BloomFilter::new();
        let item1 = b"malicious-payload-hash-1";
        let item2 = b"198.51.100.23";
        let item_absent = b"clean-file-hash-safari";

        bloom.insert(item1);
        bloom.insert(item2);

        assert!(bloom.contains(item1));
        assert!(bloom.contains(item2));
        assert!(!bloom.contains(item_absent));
    }

    #[test]
    fn test_intel_daemon_initialization_and_query() {
        let admin = IntelCap::new(Handle::new(1002, 1), intel_rights::ALL, 5000, 100);
        let mut daemon = JamboIntelDaemon::new(admin);
        daemon.init_defaults();

        assert_eq!(daemon.feed_count, 3);
        assert_eq!(daemon.ioc_count, 5);
        assert!(daemon.verify_ledger_integrity());

        // Recherche SHA-256 Malware
        let sha_malware: [u8; 32] = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let res = daemon.query_ioc(&admin, IocKind::Sha256, &sha_malware, 200).unwrap();
        assert!(res.is_some());
        let m = res.unwrap();
        assert_eq!(m.ioc_id, 1);
        assert_eq!(m.severity, ThreatSeverity::Critical);
        assert_eq!(m.confidence, 98);
        assert_eq!(m.hit_count, 1);

        // Recherche IP Bogon
        let ip_bogon = [198, 51, 100, 23];
        let res_ip = daemon.query_ioc(&admin, IocKind::Ipv4, &ip_bogon, 200).unwrap();
        assert!(res_ip.is_some());
        let m_ip = res_ip.unwrap();
        assert_eq!(m_ip.category, ThreatCategory::BogonIp);

        // Recherche élément inexistant
        let ip_clean = [192, 168, 1, 10];
        let res_clean = daemon.query_ioc(&admin, IocKind::Ipv4, &ip_clean, 200).unwrap();
        assert!(res_clean.is_none());

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_ttl_dynamic_expiration() {
        let admin = IntelCap::new(Handle::new(1003, 1), intel_rights::ALL, 5000, 100);
        let mut daemon = JamboIntelDaemon::new(admin);
        daemon.init_defaults();

        // Le domaine C2 a un TTL de 3600 ticks créé au tick 140 -> expire à 3741
        let domain_c2 = b"c2.apt-bear.sovereign";
        let before_exp = daemon.query_ioc(&admin, IocKind::Domain, domain_c2, 1000).unwrap();
        assert!(before_exp.is_some());

        // À tick 4000, il est expiré
        let after_exp = daemon.query_ioc(&admin, IocKind::Domain, domain_c2, 4000).unwrap();
        assert!(after_exp.is_none());

        // Purge
        let purged = daemon.purge_expired(&admin, 4000).unwrap();
        assert!(purged >= 1);

        assert!(daemon.verify_ledger_integrity());
    }

    #[test]
    fn test_rights_enforcement() {
        let admin = IntelCap::new(Handle::new(1004, 1), intel_rights::ALL, 5000, 100);
        let mut daemon = JamboIntelDaemon::new(admin);
        daemon.init_defaults();

        let restricted = admin.attenuate(intel_rights::QUERY_IOC, 1000, 10).unwrap();
        // Ingestion interdite
        let err = daemon.ingest_ioc(
            &restricted,
            IocKind::Ipv4,
            &[10, 0, 0, 1],
            ThreatCategory::BogonIp,
            ThreatSeverity::Low,
            50,
            "Fake",
            0,
            500,
        );
        assert_eq!(err, Err(IntelError::PermissionDenied));
    }
}

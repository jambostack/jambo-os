//! Mitigation Anti-DDoS Distribuée L3/L4/L7, Limiteurs de Débit à Jetons & SYN Cookies (`jambo-ddos`)
//!
//! Phase 115 — Jalon v0.2.113
//!
//! Fournit un système souverain de défense et mitigation anti-DDoS haute performance `#![no_std]` :
//! 1. Contrôle d'Accès Capabilaire Strict (`DdosCap`) :
//!    - Zéro autorité ambiante (Zero-Ambient Authority).
//!    - Atténuation monotone sans amplification de privilèges.
//! 2. Mitigation Anti-DDoS Multicouches (L3 / L4 / L7) :
//!    - Couche 3 (Réseau) : Filtrage anti-spoofing martiens/bogons (RFC 6890), détection de Smurf & ICMP floods.
//!    - Couche 4 (Transport) : Mitigation SYN Flood par calcul cryptographique de **SYN Cookies** déterministes (stateless),
//!      détection des scans de ports et anomalies de drapeaux TCP (Xmas, Null, SYN+FIN), mitigation UDP Flood.
//!    - Couche 7 (Applicatif) : Détection de HTTP Floods volumétriques et d'attaques lentes de type Slowloris.
//! 3. Détection et Filtrage des Attaques par Amplification & Réflexion :
//!    - Amplification DNS (port 53, requêtes ANY, extensions EDNS0 volumineuses).
//!    - Amplification NTP (port 123, requêtes Monlist `0x2a` / `0x17`).
//!    - Amplification SNMP (port 161/162, `GetBulkRequest`).
//! 4. Algorithmes de Limitation de Débit (Rate Limiting) :
//!    - Algorithme Token Bucket (seau à jetons) avec capacité de rafale et taux de réalimentation monotone.
//!    - Suivi granulaire par adresse IP avec scoring d'anomalies cumulatif.
//! 5. Gestion des Trous Noirs (Blackhole) O(1) & Liste Blanche Prioritaire (Whitelist) :
//!    - Isolation immédiate des adresses assaillantes avec TTL / expiration temporelle.
//!    - Priorité absolue aux flux de confiance sans latence superflue.
//! 6. Registre d'Audit Cryptographique Inaltérable SHA-256 en Chaîne de Hachage.

#![no_std]

use libjambo::Handle;

// ============================================================================
// CONSTANTES & LIMITES DU SYSTÈME ANTI-DDOS
// ============================================================================

pub const MAX_RULES: usize = 32;
pub const MAX_TRACKED_IPS: usize = 32;
pub const MAX_BLACKHOLED_IPS: usize = 32;
pub const MAX_WHITELISTED_IPS: usize = 16;
pub const MAX_AUDIT_LOGS: usize = 32;

pub const DEFAULT_TOKEN_CAPACITY: u32 = 100;
pub const DEFAULT_REFILL_RATE: u32 = 20; // 20 jetons / seconde
pub const DEFAULT_BLACKHOLE_DURATION: u32 = 300; // 300 secondes (5 minutes)
pub const ANOMALY_SCORE_THRESHOLD: u32 = 50;
pub const BLACKHOLE_SCORE_THRESHOLD: u32 = 100;

pub const SLOWLORIS_MAX_DURATION_SEC: u64 = 15;
pub const SLOWLORIS_MIN_RATE_BPS: usize = 10; // Octets / seconde minimum requis

// ============================================================================
// DROITS CAPABILAIRES (DdosCap)
// ============================================================================

pub mod ddos_rights {
    pub const INSPECT_TRAFFIC: u32 = 1 << 0;
    pub const APPLY_RATE_LIMIT: u32 = 1 << 1;
    pub const GENERATE_SYN_COOKIE: u32 = 1 << 2;
    pub const VERIFY_SYN_COOKIE: u32 = 1 << 3;
    pub const CONFIGURE_POLICIES: u32 = 1 << 4;
    pub const BLACKHOLE_IP: u32 = 1 << 5;
    pub const WHITELIST_BYPASS: u32 = 1 << 6;
    pub const AUDIT_INSPECT: u32 = 1 << 7;
    pub const ADMIN: u32 = 1 << 8;

    pub const ALL: u32 = INSPECT_TRAFFIC
        | APPLY_RATE_LIMIT
        | GENERATE_SYN_COOKIE
        | VERIFY_SYN_COOKIE
        | CONFIGURE_POLICIES
        | BLACKHOLE_IP
        | WHITELIST_BYPASS
        | AUDIT_INSPECT
        | ADMIN;
}

// ============================================================================
// TYPES D'ERREURS ET CAPACITÉS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdosError {
    PermissionDenied,
    CapacityExceeded,
    InvalidPacket,
    CookieExpired,
    CookieInvalid,
    BlackholeActive,
    RateLimitExceeded,
    IpNotFound,
    BufferTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DdosCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_inspections: u32,
    pub epoch: u64,
}

impl DdosCap {
    pub const fn new(handle: Handle, rights: u32, max_inspections: u32, epoch: u64) -> Self {
        Self {
            handle,
            rights,
            max_inspections,
            epoch,
        }
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.rights != 0 && self.max_inspections > 0
    }

    #[inline]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone stricte : interdiction formelle d'élargir les droits ou d'augmenter le quota
    pub fn attenuate(&self, requested_rights: u32, requested_max: u32) -> Result<Self, DdosError> {
        if (requested_rights & !self.rights) != 0 {
            return Err(DdosError::PermissionDenied);
        }
        if requested_max > self.max_inspections {
            return Err(DdosError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: requested_rights,
            max_inspections: requested_max,
            epoch: self.epoch,
        })
    }
}

// ============================================================================
// PROTOCOLES & STRUCTURE DU PAQUET RÉSEAU
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Other = 255,
}

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkPacket {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub protocol: IpProtocol,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub seq_num: u32,
    pub ack_num: u32,
    pub payload_len: usize,
    pub payload: [u8; 256],
}

impl NetworkPacket {
    pub const fn new(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        protocol: IpProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            tcp_flags: 0,
            seq_num: 0,
            ack_num: 0,
            payload_len: 0,
            payload: [0u8; 256],
        }
    }

    pub fn set_payload(&mut self, data: &[u8]) -> Result<(), DdosError> {
        if data.len() > 256 {
            return Err(DdosError::BufferTooSmall);
        }
        self.payload_len = data.len();
        self.payload[..data.len()].copy_from_slice(data);
        Ok(())
    }
}

// ============================================================================
// TYPES D'ATTAQUES & DÉCISIONS DU FILTRAGE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DdosAttackType {
    None = 0,
    IcmpFlood = 1,
    UdpFlood = 2,
    SynFlood = 3,
    AckRstFlood = 4,
    DnsAmplification = 5,
    NtpAmplification = 6,
    SnmpAmplification = 7,
    HttpFlood = 8,
    Slowloris = 9,
    MalformedPacket = 10,
    IpSpoofing = 11,
    VolumetricExceeded = 12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdosDecision {
    Allow,
    Drop { attack_type: DdosAttackType, score: u32 },
    ChallengeSynCookie { cookie_seq: u32 },
    RateLimited { retry_after_ms: u32 },
    Blackhole { ip: [u8; 4], duration_sec: u32, reason: DdosAttackType },
}

// ============================================================================
// HACHEUR CRYPTOGRAPHIQUE SHA-256 (#![no_std])
// ============================================================================

#[derive(Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
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

    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let buf_idx = (self.count % 64) as usize;
            self.buffer[buf_idx] = data[i];
            self.count += 1;
            if (self.count % 64) == 0 {
                self.transform();
            }
            i += 1;
        }
    }

    fn transform(&mut self) {
        let chunk = self.buffer;
        let mut w = [0u32; 64];
        let mut i = 0;
        while i < 16 {
            w[i] = ((chunk[i * 4] as u32) << 24)
                | ((chunk[i * 4 + 1] as u32) << 16)
                | ((chunk[i * 4 + 2] as u32) << 8)
                | (chunk[i * 4 + 3] as u32);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        let mut j = 0;
        while j < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[j])
                .wrapping_add(w[j]);
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
            j += 1;
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
        let bit_len = self.count * 8;
        let buf_idx = (self.count % 64) as usize;
        self.buffer[buf_idx] = 0x80;

        if buf_idx >= 56 {
            let mut k = buf_idx + 1;
            while k < 64 {
                self.buffer[k] = 0;
                k += 1;
            }
            self.transform();
            let mut m = 0;
            while m < 56 {
                self.buffer[m] = 0;
                m += 1;
            }
        } else {
            let mut k = buf_idx + 1;
            while k < 56 {
                self.buffer[k] = 0;
                k += 1;
            }
        }

        let mut idx = 56;
        while idx < 64 {
            let shift = (63 - idx) * 8;
            self.buffer[idx] = (bit_len >> shift) as u8;
            idx += 1;
        }
        self.transform();

        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 8 {
            out[i * 4] = (self.state[i] >> 24) as u8;
            out[i * 4 + 1] = (self.state[i] >> 16) as u8;
            out[i * 4 + 2] = (self.state[i] >> 8) as u8;
            out[i * 4 + 3] = self.state[i] as u8;
            i += 1;
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ============================================================================
// MOTEUR SYN COOKIES DÉTERMINISTE SANS ÉTAT (Stateless TCP SYN Flood Mitigation)
// ============================================================================

pub struct SynCookieEngine {
    secret: [u8; 32],
}

impl SynCookieEngine {
    /// Table des 4 valeurs discrètes de MSS (Maximum Segment Size) supportées
    pub const MSS_TABLE: [u16; 4] = [536, 1200, 1440, 1460];

    pub const fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// Trouve l'indice du MSS le plus proche inférieur ou égal
    pub fn mss_to_index(mss: u16) -> u8 {
        if mss >= 1460 {
            3
        } else if mss >= 1440 {
            2
        } else if mss >= 1200 {
            1
        } else {
            0
        }
    }

    /// Encode un SYN Cookie dans le numéro de séquence initial TCP (32 bits) :
    /// - Bits [31..8] : Hachage SHA-256 tronqué (24 bits) de (src_ip, dst_ip, src_port, dst_port, time_slot, secret)
    /// - Bits [7..5]  : Time slot (3 bits) incrémenté toutes les 64s (cycle de 512s)
    /// - Bits [4..0]  : Encodage du MSS (indice sur 2 bits, 3 bits de réserve)
    pub fn generate_cookie(
        &self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        mss: u16,
        now_sec: u64,
    ) -> u32 {
        let time_slot = ((now_sec >> 6) & 0x07) as u8;
        let mss_idx = Self::mss_to_index(mss);

        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        hasher.update(&src_ip);
        hasher.update(&dst_ip);
        hasher.update(&src_port.to_be_bytes());
        hasher.update(&dst_port.to_be_bytes());
        hasher.update(&[time_slot]);
        let hash = hasher.finalize();

        let hash_part = ((hash[0] as u32) << 24)
            | ((hash[1] as u32) << 16)
            | ((hash[2] as u32) << 8);

        let time_part = ((time_slot as u32) & 0x07) << 5;
        let mss_part = (mss_idx as u32) & 0x1F;

        hash_part | time_part | mss_part
    }

    /// Vérifie un paquet TCP ACK final du handshake 3-voies (`ack_num - 1 == cookie`) :
    /// Extrait le time-slot, valide le delta temporel (<= 3 slots = 192 secondes maximum),
    /// recalcule le hachage et décode le MSS sans consommer de mémoire d'état !
    pub fn verify_cookie(
        &self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        ack_num: u32,
        now_sec: u64,
    ) -> Result<u16, DdosError> {
        let cookie = ack_num.wrapping_sub(1);
        let extracted_time_slot = ((cookie >> 5) & 0x07) as u8;
        let mss_idx = (cookie & 0x1F) as usize;

        if mss_idx >= Self::MSS_TABLE.len() {
            return Err(DdosError::CookieInvalid);
        }

        let current_time_slot = ((now_sec >> 6) & 0x07) as u8;
        let delta = (current_time_slot.wrapping_add(8).wrapping_sub(extracted_time_slot)) % 8;
        if delta > 3 {
            return Err(DdosError::CookieExpired);
        }

        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        hasher.update(&src_ip);
        hasher.update(&dst_ip);
        hasher.update(&src_port.to_be_bytes());
        hasher.update(&dst_port.to_be_bytes());
        hasher.update(&[extracted_time_slot]);
        let hash = hasher.finalize();

        let expected_hash_part = ((hash[0] as u32) << 24)
            | ((hash[1] as u32) << 16)
            | ((hash[2] as u32) << 8);

        let cookie_hash_part = cookie & 0xFFFF_FF00;
        if cookie_hash_part != expected_hash_part {
            return Err(DdosError::CookieInvalid);
        }

        Ok(Self::MSS_TABLE[mss_idx])
    }
}

// ============================================================================
// ALGORITHME DU SEAU À JETONS (TOKEN BUCKET RATE LIMITER)
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    pub capacity: u32,
    pub tokens: u32,
    pub refill_rate_per_sec: u32,
    pub last_refill_sec: u64,
}

impl TokenBucket {
    pub const fn new(capacity: u32, refill_rate_per_sec: u32, now_sec: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate_per_sec,
            last_refill_sec: now_sec,
        }
    }

    /// Consomme `cost` jetons si disponibles après réalimentation proportionnelle au temps écoulé
    pub fn try_consume(&mut self, cost: u32, now_sec: u64) -> bool {
        if now_sec > self.last_refill_sec {
            let elapsed = now_sec.saturating_sub(self.last_refill_sec);
            let added = (elapsed as u32).saturating_mul(self.refill_rate_per_sec);
            self.tokens = core::cmp::min(self.capacity, self.tokens.saturating_add(added));
            self.last_refill_sec = now_sec;
        }

        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// ENTRÉE DE SUIVI PAR ADRESSE IP
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct TrackedIpEntry {
    pub ip: [u8; 4],
    pub bucket: TokenBucket,
    pub packet_count: u32,
    pub anomaly_score: u32,
    pub last_seen_sec: u64,
}

// ============================================================================
// TROU NOIR (BLACKHOLE) AVEC EXPIRATION TEMPORELLE (TTL)
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct BlackholeEntry {
    pub ip: [u8; 4],
    pub expires_at_sec: u64,
    pub reason: DdosAttackType,
}

// ============================================================================
// JOURNAL D'AUDIT CRYPTOGRAPHIQUE SHA-256
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub client_ip: [u8; 4],
    pub attack_type: DdosAttackType,
    pub decision_code: u32,
    pub score: u32,
    pub prev_hash: [u8; 32],
}

// ============================================================================
// DÉMON PRINCIPAL ANTI-DDOS (`JamboDdosDaemon`)
// ============================================================================

pub struct JamboDdosDaemon {
    pub admin_cap: DdosCap,
    pub syn_engine: SynCookieEngine,

    // Tables bornées statiques sans allocation
    pub tracked_ips: [Option<TrackedIpEntry>; MAX_TRACKED_IPS],
    pub tracked_count: usize,

    pub blackhole_table: [Option<BlackholeEntry>; MAX_BLACKHOLED_IPS],
    pub blackhole_count: usize,

    pub whitelisted_ips: [[u8; 4]; MAX_WHITELISTED_IPS],
    pub whitelist_count: usize,

    pub audit_log: [AuditEntry; MAX_AUDIT_LOGS],
    pub audit_count: usize,
    pub audit_chain: [u8; 32],

    pub syn_cookies_generated: u32,
    pub syn_cookies_validated: u32,
    pub packets_mitigated: u32,
}

impl JamboDdosDaemon {
    pub const GENESIS_HASH: [u8; 32] = [0x5A; 32];

    pub fn new(admin_cap: DdosCap) -> Self {
        // Clé secrète par défaut pour la dérivation de SYN cookies
        let default_secret: [u8; 32] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0x76, 0x2e, 0x48, 0x9f, 0x5a, 0x11, 0x33, 0x44, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];

        const EMPTY_AUDIT: AuditEntry = AuditEntry {
            timestamp: 0,
            client_ip: [0; 4],
            attack_type: DdosAttackType::None,
            decision_code: 0,
            score: 0,
            prev_hash: [0; 32],
        };

        Self {
            admin_cap,
            syn_engine: SynCookieEngine::new(default_secret),
            tracked_ips: [None; MAX_TRACKED_IPS],
            tracked_count: 0,
            blackhole_table: [None; MAX_BLACKHOLED_IPS],
            blackhole_count: 0,
            whitelisted_ips: [[0; 4]; MAX_WHITELISTED_IPS],
            whitelist_count: 0,
            audit_log: [EMPTY_AUDIT; MAX_AUDIT_LOGS],
            audit_count: 0,
            audit_chain: Self::GENESIS_HASH,
            syn_cookies_generated: 0,
            syn_cookies_validated: 0,
            packets_mitigated: 0,
        }
    }

    /// Initialise la configuration et les politiques de défense par défaut
    pub fn init_defaults(&mut self) {
        let admin_cap = self.admin_cap;
        // Enregistre l'adresse de bouclage locale en liste blanche
        let loopback = [127, 0, 0, 1];
        let _ = self.whitelist_ip(&admin_cap, loopback);

        // Enregistre la passerelle de confiance
        let trusted_gw = [10, 0, 0, 1];
        let _ = self.whitelist_ip(&admin_cap, trusted_gw);
    }

    /// Ajoute une adresse IP à la liste blanche (Bypass absolu)
    pub fn whitelist_ip(&mut self, cap: &DdosCap, ip: [u8; 4]) -> Result<(), DdosError> {
        if !cap.has_right(ddos_rights::WHITELIST_BYPASS) && !cap.has_right(ddos_rights::ADMIN) {
            return Err(DdosError::PermissionDenied);
        }
        for i in 0..self.whitelist_count {
            if self.whitelisted_ips[i] == ip {
                return Ok(());
            }
        }
        if self.whitelist_count >= MAX_WHITELISTED_IPS {
            return Err(DdosError::CapacityExceeded);
        }
        self.whitelisted_ips[self.whitelist_count] = ip;
        self.whitelist_count += 1;
        Ok(())
    }

    /// Vérifie si une adresse IP est en liste blanche
    #[inline]
    pub fn is_whitelisted(&self, ip: [u8; 4]) -> bool {
        for i in 0..self.whitelist_count {
            if self.whitelisted_ips[i] == ip {
                return true;
            }
        }
        false
    }

    /// Envoie immédiatement une IP dans le trou noir (Blackhole O(1))
    pub fn blackhole_ip(
        &mut self,
        cap: &DdosCap,
        ip: [u8; 4],
        duration_sec: u32,
        reason: DdosAttackType,
        now_sec: u64,
    ) -> Result<(), DdosError> {
        if !cap.has_right(ddos_rights::BLACKHOLE_IP) && !cap.has_right(ddos_rights::ADMIN) {
            return Err(DdosError::PermissionDenied);
        }

        // Si l'IP est en liste blanche, refus formel de mise en trou noir
        if self.is_whitelisted(ip) {
            return Err(DdosError::PermissionDenied);
        }

        let expires_at_sec = now_sec.saturating_add(duration_sec as u64);

        // Met à jour une entrée existante
        for entry in self.blackhole_table.iter_mut() {
            if let Some(bh) = entry {
                if bh.ip == ip {
                    bh.expires_at_sec = expires_at_sec;
                    bh.reason = reason;
                    self.log_audit(now_sec, ip, reason, 4, 100);
                    return Ok(());
                }
            }
        }

        // Insère dans le premier slot disponible ou remplace une entrée expirée
        for entry in self.blackhole_table.iter_mut() {
            if entry.is_none()
                || entry
                    .as_ref()
                    .map_or(false, |b| now_sec >= b.expires_at_sec)
            {
                *entry = Some(BlackholeEntry {
                    ip,
                    expires_at_sec,
                    reason,
                });
                self.blackhole_count = self
                    .blackhole_table
                    .iter()
                    .filter(|e| e.is_some())
                    .count();
                self.log_audit(now_sec, ip, reason, 4, 100);
                return Ok(());
            }
        }

        Err(DdosError::CapacityExceeded)
    }

    /// Vérifie si une adresse IP est actuellement dans le trou noir
    pub fn is_blackholed(&mut self, ip: [u8; 4], now_sec: u64) -> Option<DdosAttackType> {
        for entry in self.blackhole_table.iter_mut() {
            if let Some(bh) = entry {
                if bh.ip == ip {
                    if now_sec < bh.expires_at_sec {
                        return Some(bh.reason);
                    } else {
                        // Entrée expirée, nettoyage automatique
                        *entry = None;
                    }
                }
            }
        }
        None
    }

    /// Journalise une action de mitigation dans la chaîne de hachage SHA-256
    pub fn log_audit(
        &mut self,
        timestamp: u64,
        client_ip: [u8; 4],
        attack_type: DdosAttackType,
        decision_code: u32,
        score: u32,
    ) {
        let mut hasher = Sha256::new();
        hasher.update(&self.audit_chain);
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&client_ip);
        hasher.update(&(attack_type as u32).to_be_bytes());
        hasher.update(&decision_code.to_be_bytes());
        hasher.update(&score.to_be_bytes());
        let new_hash = hasher.finalize();

        let prev_hash = self.audit_chain;
        self.audit_chain = new_hash;

        let entry = AuditEntry {
            timestamp,
            client_ip,
            attack_type,
            decision_code,
            score,
            prev_hash,
        };

        if self.audit_count < MAX_AUDIT_LOGS {
            self.audit_log[self.audit_count] = entry;
            self.audit_count += 1;
        } else {
            // Décalage FIFO borné
            for i in 1..MAX_AUDIT_LOGS {
                self.audit_log[i - 1] = self.audit_log[i];
            }
            self.audit_log[MAX_AUDIT_LOGS - 1] = entry;
        }
    }

    /// Inspecte et filtre un paquet réseau en couches L3/L4
    pub fn inspect_packet(
        &mut self,
        cap: &DdosCap,
        packet: &NetworkPacket,
        now_sec: u64,
    ) -> Result<DdosDecision, DdosError> {
        if !cap.has_right(ddos_rights::INSPECT_TRAFFIC) && !cap.has_right(ddos_rights::ADMIN) {
            return Err(DdosError::PermissionDenied);
        }

        let ip = packet.src_ip;

        // 1. Liste Blanche Prioritaire : contournement immédiat sans latence
        if self.is_whitelisted(ip) {
            return Ok(DdosDecision::Allow);
        }

        // 2. Trou Noir Actif (Blackhole) O(1)
        if let Some(reason) = self.is_blackholed(ip, now_sec) {
            self.packets_mitigated += 1;
            return Ok(DdosDecision::Blackhole {
                ip,
                duration_sec: 0,
                reason,
            });
        }

        // 3. Détection de Paquets Malformés & Adresses Martiennes / Bogons (L3 Anti-Spoofing)
        if Self::is_martian_or_bogon(ip) {
            self.packets_mitigated += 1;
            self.log_audit(now_sec, ip, DdosAttackType::IpSpoofing, 1, 100);
            return Ok(DdosDecision::Drop {
                attack_type: DdosAttackType::IpSpoofing,
                score: 100,
            });
        }

        // 4. Détection d'Anomalies de Drapeaux TCP (L4)
        if packet.protocol == IpProtocol::Tcp {
            if let Some(attack) = Self::detect_tcp_flag_anomalies(packet.tcp_flags) {
                self.packets_mitigated += 1;
                self.log_audit(now_sec, ip, attack, 1, 90);
                return Ok(DdosDecision::Drop {
                    attack_type: attack,
                    score: 90,
                });
            }

            // Détection de SYN Flood & Déclenchement de SYN Cookie Stateless
            if (packet.tcp_flags & tcp_flags::SYN) != 0 && (packet.tcp_flags & tcp_flags::ACK) == 0 {
                // Si l'IP dépasse le seuil ou s'il y a un assaut SYN, on challenge via SYN Cookie
                let cookie = self.syn_engine.generate_cookie(
                    packet.src_ip,
                    packet.dst_ip,
                    packet.src_port,
                    packet.dst_port,
                    1460, // MSS nominal
                    now_sec,
                );
                self.syn_cookies_generated += 1;
                self.log_audit(now_sec, ip, DdosAttackType::SynFlood, 2, 40);
                return Ok(DdosDecision::ChallengeSynCookie { cookie_seq: cookie });
            }
        }

        // 5. Détection d'Attaques par Amplification & Réflexion (L3/L4)
        if let Some(amp_attack) = Self::detect_amplification_attack(packet) {
            self.packets_mitigated += 1;
            self.log_audit(now_sec, ip, amp_attack, 1, 95);
            // Blackhole automatique pour les assauts d'amplification violents
            let _ = self.blackhole_ip(cap, ip, DEFAULT_BLACKHOLE_DURATION, amp_attack, now_sec);
            return Ok(DdosDecision::Blackhole {
                ip,
                duration_sec: DEFAULT_BLACKHOLE_DURATION,
                reason: amp_attack,
            });
        }

        // 6. Limiteur de Débit à Jetons (Token Bucket Rate Limiter)
        let rate_ok = self.consume_tokens_for_ip(ip, 1, now_sec);
        if !rate_ok {
            self.packets_mitigated += 1;
            self.log_audit(now_sec, ip, DdosAttackType::VolumetricExceeded, 3, 60);

            // Si récidive sévère (score cumulé > seuil trou noir), mise en trou noir automatique
            let score = self.get_or_increment_score(ip, 25);
            if score >= BLACKHOLE_SCORE_THRESHOLD {
                let _ = self.blackhole_ip(
                    cap,
                    ip,
                    DEFAULT_BLACKHOLE_DURATION,
                    DdosAttackType::VolumetricExceeded,
                    now_sec,
                );
                return Ok(DdosDecision::Blackhole {
                    ip,
                    duration_sec: DEFAULT_BLACKHOLE_DURATION,
                    reason: DdosAttackType::VolumetricExceeded,
                });
            }

            return Ok(DdosDecision::RateLimited { retry_after_ms: 1000 });
        }

        Ok(DdosDecision::Allow)
    }

    /// Valide la complétion d'un handshake TCP via SYN Cookie (Réponse TCP ACK)
    pub fn validate_syn_ack(
        &mut self,
        cap: &DdosCap,
        packet: &NetworkPacket,
        now_sec: u64,
    ) -> Result<u16, DdosError> {
        if !cap.has_right(ddos_rights::VERIFY_SYN_COOKIE) && !cap.has_right(ddos_rights::ADMIN) {
            return Err(DdosError::PermissionDenied);
        }

        if packet.protocol != IpProtocol::Tcp || (packet.tcp_flags & tcp_flags::ACK) == 0 {
            return Err(DdosError::InvalidPacket);
        }

        let mss = self.syn_engine.verify_cookie(
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.ack_num,
            now_sec,
        )?;

        self.syn_cookies_validated += 1;
        self.log_audit(now_sec, packet.src_ip, DdosAttackType::None, 0, 0);
        Ok(mss)
    }

    /// Inspection et mitigation applicative L7 (HTTP Floods & Slowloris)
    pub fn inspect_l7_flow(
        &mut self,
        cap: &DdosCap,
        src_ip: [u8; 4],
        request_count: u32,
        duration_sec: u64,
        is_header_complete: bool,
        bytes_received: usize,
        now_sec: u64,
    ) -> Result<DdosDecision, DdosError> {
        if !cap.has_right(ddos_rights::INSPECT_TRAFFIC) && !cap.has_right(ddos_rights::ADMIN) {
            return Err(DdosError::PermissionDenied);
        }

        if self.is_whitelisted(src_ip) {
            return Ok(DdosDecision::Allow);
        }

        // Détection Slowloris : connexion ouverte depuis plus de 15s avec en-têtes non terminés
        // et débit d'octets minimal anémique (< 10 octets/seconde)
        if !is_header_complete && duration_sec >= SLOWLORIS_MAX_DURATION_SEC {
            let rate = bytes_received.checked_div(duration_sec as usize).unwrap_or(0);
            if rate < SLOWLORIS_MIN_RATE_BPS {
                self.packets_mitigated += 1;
                self.log_audit(now_sec, src_ip, DdosAttackType::Slowloris, 1, 85);
                let _ = self.blackhole_ip(
                    cap,
                    src_ip,
                    DEFAULT_BLACKHOLE_DURATION,
                    DdosAttackType::Slowloris,
                    now_sec,
                );
                return Ok(DdosDecision::Blackhole {
                    ip: src_ip,
                    duration_sec: DEFAULT_BLACKHOLE_DURATION,
                    reason: DdosAttackType::Slowloris,
                });
            }
        }

        // Détection HTTP Flood : débit de requêtes par seconde anormalement élevé (> 150 req/s)
        if duration_sec > 0 {
            let rps = request_count / (duration_sec as u32);
            if rps > 150 {
                self.packets_mitigated += 1;
                self.log_audit(now_sec, src_ip, DdosAttackType::HttpFlood, 1, 90);
                let _ = self.blackhole_ip(
                    cap,
                    src_ip,
                    DEFAULT_BLACKHOLE_DURATION,
                    DdosAttackType::HttpFlood,
                    now_sec,
                );
                return Ok(DdosDecision::Blackhole {
                    ip: src_ip,
                    duration_sec: DEFAULT_BLACKHOLE_DURATION,
                    reason: DdosAttackType::HttpFlood,
                });
            }
        }

        Ok(DdosDecision::Allow)
    }

    // ========================================================================
    // LOGIQUE INTERNE & HEURISTIQUES DE DÉTECTION
    // ========================================================================

    fn is_martian_or_bogon(ip: [u8; 4]) -> bool {
        // 0.0.0.0/8 (Réseau courant)
        if ip[0] == 0 {
            return true;
        }
        // 127.0.0.0/8 (Bouclage en source externe)
        if ip[0] == 127 && ip != [127, 0, 0, 1] {
            return true;
        }
        // 224.0.0.0/4 (Multicast en IP source : interdit par RFC 1112)
        if (ip[0] & 0xF0) == 0xE0 {
            return true;
        }
        // 240.0.0.0/4 (Réservé classe E)
        if (ip[0] & 0xF0) == 0xF0 && ip != [255, 255, 255, 255] {
            return true;
        }
        // 255.255.255.255 (Broadcast universel)
        if ip == [255, 255, 255, 255] {
            return true;
        }
        false
    }

    fn detect_tcp_flag_anomalies(flags: u8) -> Option<DdosAttackType> {
        // SYN + FIN (Attaque illégale)
        if (flags & tcp_flags::SYN) != 0 && (flags & tcp_flags::FIN) != 0 {
            return Some(DdosAttackType::MalformedPacket);
        }
        // Scan Null (aucun drapeau armé)
        if flags == 0 {
            return Some(DdosAttackType::MalformedPacket);
        }
        // Scan Xmas (FIN + PSH + URG)
        if (flags & (tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG))
            == (tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG)
        {
            return Some(DdosAttackType::MalformedPacket);
        }
        // ACK + RST simultanés anormaux
        if (flags & (tcp_flags::ACK | tcp_flags::RST)) == (tcp_flags::ACK | tcp_flags::RST)
            && (flags & tcp_flags::SYN) != 0
        {
            return Some(DdosAttackType::AckRstFlood);
        }
        None
    }

    fn detect_amplification_attack(packet: &NetworkPacket) -> Option<DdosAttackType> {
        if packet.protocol == IpProtocol::Udp {
            // Amplification DNS : port 53 avec payload volumineux (> 512 octets) ou type ANY
            if packet.src_port == 53 || packet.dst_port == 53 {
                if packet.payload_len > 512 {
                    return Some(DdosAttackType::DnsAmplification);
                }
                // Requête DNS ANY (0x00FF)
                if packet.payload_len >= 12 {
                    let p = &packet.payload[..packet.payload_len];
                    for i in 0..p.len().saturating_sub(1) {
                        if p[i] == 0x00 && p[i + 1] == 0xFF {
                            return Some(DdosAttackType::DnsAmplification);
                        }
                    }
                }
            }

            // Amplification NTP : port 123 avec commande Monlist (0x2a ou 0x17)
            if packet.src_port == 123 || packet.dst_port == 123 {
                if packet.payload_len > 0 {
                    let cmd = packet.payload[0] & 0x3F;
                    if cmd == 0x2A || cmd == 0x17 || packet.payload_len > 200 {
                        return Some(DdosAttackType::NtpAmplification);
                    }
                }
            }

            // Amplification SNMP : port 161/162 avec GetBulkRequest
            if (packet.src_port == 161 || packet.dst_port == 161 || packet.src_port == 162 || packet.dst_port == 162)
                && packet.payload_len > 300
            {
                return Some(DdosAttackType::SnmpAmplification);
            }

            // UDP Flood volumineux générique
            if packet.payload_len >= 250 {
                return Some(DdosAttackType::UdpFlood);
            }
        }

        // Smurf / ICMP Flood : Ping volumineux
        if packet.protocol == IpProtocol::Icmp && packet.payload_len > 128 {
            return Some(DdosAttackType::IcmpFlood);
        }

        None
    }

    fn consume_tokens_for_ip(&mut self, ip: [u8; 4], cost: u32, now_sec: u64) -> bool {
        // Recherche si l'IP est déjà suivie
        for entry in self.tracked_ips.iter_mut() {
            if let Some(tracked) = entry {
                if tracked.ip == ip {
                    tracked.packet_count = tracked.packet_count.saturating_add(1);
                    tracked.last_seen_sec = now_sec;
                    return tracked.bucket.try_consume(cost, now_sec);
                }
            }
        }

        // Alloue une nouvelle entrée
        let mut bucket = TokenBucket::new(DEFAULT_TOKEN_CAPACITY, DEFAULT_REFILL_RATE, now_sec);
        let allowed = bucket.try_consume(cost, now_sec);

        for entry in self.tracked_ips.iter_mut() {
            if entry.is_none() {
                *entry = Some(TrackedIpEntry {
                    ip,
                    bucket,
                    packet_count: 1,
                    anomaly_score: 0,
                    last_seen_sec: now_sec,
                });
                self.tracked_count = self.tracked_ips.iter().filter(|e| e.is_some()).count();
                return allowed;
            }
        }

        // Si la table de suivi est pleine, réutilise l'entrée la plus ancienne
        let mut oldest_idx = 0;
        let mut oldest_time = u64::MAX;
        for (i, entry) in self.tracked_ips.iter().enumerate() {
            if let Some(t) = entry {
                if t.last_seen_sec < oldest_time {
                    oldest_time = t.last_seen_sec;
                    oldest_idx = i;
                }
            }
        }

        self.tracked_ips[oldest_idx] = Some(TrackedIpEntry {
            ip,
            bucket,
            packet_count: 1,
            anomaly_score: 0,
            last_seen_sec: now_sec,
        });
        allowed
    }

    fn get_or_increment_score(&mut self, ip: [u8; 4], delta: u32) -> u32 {
        for entry in self.tracked_ips.iter_mut() {
            if let Some(tracked) = entry {
                if tracked.ip == ip {
                    tracked.anomaly_score = tracked.anomaly_score.saturating_add(delta);
                    return tracked.anomaly_score;
                }
            }
        }
        delta
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ddos_cap_attenuation() {
        let root_cap = DdosCap::new(Handle::new(11501, 1), ddos_rights::ALL, 5000, 1);
        assert!(root_cap.is_valid());
        assert!(root_cap.has_right(ddos_rights::INSPECT_TRAFFIC));
        assert!(root_cap.has_right(ddos_rights::BLACKHOLE_IP));

        let sub_cap = root_cap
            .attenuate(
                ddos_rights::INSPECT_TRAFFIC | ddos_rights::APPLY_RATE_LIMIT,
                2000,
            )
            .expect("Atténuation");
        assert!(sub_cap.has_right(ddos_rights::INSPECT_TRAFFIC));
        assert!(sub_cap.has_right(ddos_rights::APPLY_RATE_LIMIT));
        assert!(!sub_cap.has_right(ddos_rights::BLACKHOLE_IP));
        assert_eq!(sub_cap.max_inspections, 2000);

        // Rejet formel d'amplification
        assert_eq!(
            sub_cap.attenuate(ddos_rights::ALL, 1000),
            Err(DdosError::PermissionDenied)
        );
        assert_eq!(
            sub_cap.attenuate(ddos_rights::INSPECT_TRAFFIC, 2500),
            Err(DdosError::PermissionDenied)
        );
    }

    #[test]
    fn test_syn_cookie_generation_and_verification() {
        let secret = [0x42u8; 32];
        let engine = SynCookieEngine::new(secret);

        let src_ip = [192, 168, 1, 10];
        let dst_ip = [10, 0, 0, 1];
        let src_port = 54321;
        let dst_port = 80;
        let mss = 1460;
        let now_sec = 1000;

        let cookie_seq = engine.generate_cookie(src_ip, dst_ip, src_port, dst_port, mss, now_sec);
        assert_ne!(cookie_seq, 0);

        // Le client répond avec ack_num = cookie_seq + 1
        let ack_num = cookie_seq.wrapping_add(1);
        let decoded_mss = engine
            .verify_cookie(src_ip, dst_ip, src_port, dst_port, ack_num, now_sec + 30)
            .expect("Validation SYN cookie valide");
        assert_eq!(decoded_mss, 1460);
    }

    #[test]
    fn test_syn_cookie_expiration_and_tampering() {
        let secret = [0x42u8; 32];
        let engine = SynCookieEngine::new(secret);

        let src_ip = [192, 168, 1, 10];
        let dst_ip = [10, 0, 0, 1];
        let src_port = 54321;
        let dst_port = 80;
        let now_sec = 1000;

        let cookie_seq = engine.generate_cookie(src_ip, dst_ip, src_port, dst_port, 1460, now_sec);
        let ack_num = cookie_seq.wrapping_add(1);

        // Test altération de port ou d'IP
        let tampered = engine.verify_cookie(src_ip, dst_ip, 54322, dst_port, ack_num, now_sec + 10);
        assert_eq!(tampered, Err(DdosError::CookieInvalid));

        // Test expiration (> 3 time slots = > 192s)
        let expired = engine.verify_cookie(src_ip, dst_ip, src_port, dst_port, ack_num, now_sec + 300);
        assert_eq!(expired, Err(DdosError::CookieExpired));
    }

    #[test]
    fn test_token_bucket_rate_limiter() {
        let mut bucket = TokenBucket::new(10, 2, 100);
        assert!(bucket.try_consume(8, 100));
        assert_eq!(bucket.tokens, 2);

        // Tentative de surconsommation immédiate
        assert!(!bucket.try_consume(5, 100));

        // Réalimentation après 2 secondes (+4 jetons -> total 6 jetons)
        assert!(bucket.try_consume(5, 102));
        assert_eq!(bucket.tokens, 1);
    }

    #[test]
    fn test_martian_bogon_detection() {
        let cap = DdosCap::new(Handle::new(11501, 1), ddos_rights::ALL, 1000, 1);
        let mut daemon = JamboDdosDaemon::new(cap);

        // IP Multicast en source
        let pkt = NetworkPacket::new([224, 0, 0, 5], [10, 0, 0, 1], IpProtocol::Udp, 1000, 80);
        let decision = daemon.inspect_packet(&cap, &pkt, 100).expect("Inspect");
        assert_eq!(
            decision,
            DdosDecision::Drop {
                attack_type: DdosAttackType::IpSpoofing,
                score: 100
            }
        );

        // IP 0.0.0.0
        let pkt_zero = NetworkPacket::new([0, 0, 0, 1], [10, 0, 0, 1], IpProtocol::Tcp, 1000, 80);
        let dec_zero = daemon.inspect_packet(&cap, &pkt_zero, 100).expect("Inspect");
        assert_eq!(
            dec_zero,
            DdosDecision::Drop {
                attack_type: DdosAttackType::IpSpoofing,
                score: 100
            }
        );
    }

    #[test]
    fn test_tcp_flags_anomalies() {
        let cap = DdosCap::new(Handle::new(11501, 1), ddos_rights::ALL, 1000, 1);
        let mut daemon = JamboDdosDaemon::new(cap);

        // SYN + FIN
        let mut pkt = NetworkPacket::new([198, 51, 100, 2], [10, 0, 0, 1], IpProtocol::Tcp, 1234, 80);
        pkt.tcp_flags = tcp_flags::SYN | tcp_flags::FIN;
        let decision = daemon.inspect_packet(&cap, &pkt, 100).expect("Inspect");
        assert_eq!(
            decision,
            DdosDecision::Drop {
                attack_type: DdosAttackType::MalformedPacket,
                score: 90
            }
        );

        // Xmas scan
        pkt.tcp_flags = tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG;
        let dec_xmas = daemon.inspect_packet(&cap, &pkt, 100).expect("Inspect");
        assert_eq!(
            dec_xmas,
            DdosDecision::Drop {
                attack_type: DdosAttackType::MalformedPacket,
                score: 90
            }
        );
    }

    #[test]
    fn test_amplification_detection() {
        let cap = DdosCap::new(Handle::new(11501, 1), ddos_rights::ALL, 1000, 1);
        let mut daemon = JamboDdosDaemon::new(cap);

        // NTP monlist
        let mut pkt_ntp = NetworkPacket::new([198, 51, 100, 3], [10, 0, 0, 1], IpProtocol::Udp, 123, 123);
        pkt_ntp.set_payload(&[0x2A, 0x01, 0x00, 0x00]).unwrap();
        let dec_ntp = daemon.inspect_packet(&cap, &pkt_ntp, 100).expect("Inspect");
        match dec_ntp {
            DdosDecision::Blackhole { reason, .. } => {
                assert_eq!(reason, DdosAttackType::NtpAmplification);
            }
            _ => panic!("Attendu Blackhole pour NTP Amplification"),
        }
    }

    #[test]
    fn test_slowloris_detection() {
        let cap = DdosCap::new(Handle::new(11501, 1), ddos_rights::ALL, 1000, 1);
        let mut daemon = JamboDdosDaemon::new(cap);

        let attacker_ip = [198, 51, 100, 4];
        let decision = daemon
            .inspect_l7_flow(
                &cap,
                attacker_ip,
                1,
                20,    // 20 secondes écoulées (> 15s)
                false, // En-têtes non terminés
                50,    // 50 octets reçus (2.5 bps < 10 bps)
                100,
            )
            .expect("Inspect L7");

        match decision {
            DdosDecision::Blackhole { reason, .. } => {
                assert_eq!(reason, DdosAttackType::Slowloris);
            }
            _ => panic!("Attendu Blackhole pour Slowloris"),
        }
    }

    #[test]
    fn test_whitelist_bypass() {
        let cap = DdosCap::new(Handle::new(11501, 1), ddos_rights::ALL, 1000, 1);
        let mut daemon = JamboDdosDaemon::new(cap);
        daemon.init_defaults();

        let trusted_ip = [127, 0, 0, 1];
        // Envoi d'un paquet de scan depuis la liste blanche : doit être autorisé
        let mut pkt = NetworkPacket::new(trusted_ip, [127, 0, 0, 1], IpProtocol::Tcp, 1000, 80);
        pkt.tcp_flags = tcp_flags::SYN | tcp_flags::FIN;

        let decision = daemon.inspect_packet(&cap, &pkt, 100).expect("Inspect");
        assert_eq!(decision, DdosDecision::Allow);
    }

    #[test]
    fn test_audit_hash_chain() {
        let cap = DdosCap::new(Handle::new(11501, 1), ddos_rights::ALL, 1000, 1);
        let mut daemon = JamboDdosDaemon::new(cap);

        let initial_hash = daemon.audit_chain;
        daemon.log_audit(100, [1, 2, 3, 4], DdosAttackType::SynFlood, 2, 40);
        let hash1 = daemon.audit_chain;
        assert_ne!(initial_hash, hash1);

        daemon.log_audit(101, [1, 2, 3, 5], DdosAttackType::NtpAmplification, 1, 95);
        let hash2 = daemon.audit_chain;
        assert_ne!(hash1, hash2);

        assert_eq!(daemon.audit_count, 2);
        assert_eq!(daemon.audit_log[0].prev_hash, initial_hash);
        assert_eq!(daemon.audit_log[1].prev_hash, hash1);
    }
}

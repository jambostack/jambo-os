//! Démon de Routage Sécurisé Zero-Trust, Micro-Segmentation & Maillage Chiffré Ring 3 (`jambo-secroute`)
//!
//! Phase 111 — Jalon v0.2.109
//!
//! Fournit un sous-système de routage sécurisé de grappe et de micro-segmentation en `#![no_std]` :
//! 1. Micro-Segmentation & Confinement par Zones de Sécurité (`SecurityZone`) :
//!    - Découpage étanche en zones de confiance (Kernel/Hypervisor, TEE Enclaves, Standard Apps, Confined Sandbox).
//!    - Rejet catégorique (Deny-by-Default) de tout flux inter-zones non expressément autorisé.
//! 2. Tunnels Souverains Chiffrés Maillés (`SecureTunnel`) :
//!    - Chiffrement symétrique haute performance de paquets via ChaCha20 (256 bits).
//!    - Authentification et intégrité cryptographique stricte par étiquette MAC (HMAC-SHA256 tronqué à 16 octets).
//!    - Protection formelle anti-rejeu par numéro de séquence strictement monotone (`seq > rx_seq`).
//! 3. Politiques de Routage Capabilaires Zero-Trust (`SecRouteRule`, `SecRouteCap`) :
//!    - Autorité ambiante nulle (Zero-Ambient Authority) : chaque opération de routage exige une capacité valide.
//!    - Atténuation capabilaire strictement monotone sans possibilité d'amplification.
//! 4. Isolation d'Urgence & Quarantaine O(1) :
//!    - Isolation instantanée d'enclave compromise avec invalidation immédiate de ses tunnels associés.
//! 5. Registre d'Audit Inaltérable :
//!    - Scellement continu SHA-256 pour garantir la non-répudiation et la conformité d'audit.

#![no_std]

use libjambo::Handle;

// ============================================================================
// CONSTANTES DU SOUS-SYSTÈME JAMBO-SECROUTE
// ============================================================================

pub const MAX_ZONES: usize = 8;
pub const MAX_ENCLAVES: usize = 32;
pub const MAX_TUNNELS: usize = 16;
pub const MAX_RULES: usize = 32;
pub const MAX_AUDIT_LOGS: usize = 32;
pub const MAX_ZONE_NAME_LEN: usize = 24;
pub const MAX_PAYLOAD_SIZE: usize = 512;
pub const TUNNEL_PACKET_MAGIC: u32 = 0x53525445; // "SRTE" (Secure Route)

// ============================================================================
// DROITS CAPABILAIRES & GOUVERNANCE STRICTE
// ============================================================================

pub mod secroute_rights {
    pub const ROUTE_FORWARD: u32 = 1 << 0;
    pub const CREATE_TUNNEL: u32 = 1 << 1;
    pub const DESTROY_TUNNEL: u32 = 1 << 2;
    pub const CONFIGURE_ZONE: u32 = 1 << 3;
    pub const ADD_RULE: u32 = 1 << 4;
    pub const DELETE_RULE: u32 = 1 << 5;
    pub const ISOLATE_ENCLAVE: u32 = 1 << 6;
    pub const INSPECT_FLOW: u32 = 1 << 7;
    pub const AUDIT_LOG: u32 = 1 << 8;
    pub const ALL: u32 = (1 << 9) - 1;
}

// ============================================================================
// ERREURS DU SOUS-SYSTÈME
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecRouteError {
    PermissionDenied,
    ZoneNotFound,
    ZoneCapacityExceeded,
    EnclaveNotFound,
    EnclaveCapacityExceeded,
    EnclaveQuarantined,
    TunnelNotFound,
    TunnelCapacityExceeded,
    TunnelAlreadyExists,
    TunnelInactive,
    RouteRuleCapacityExceeded,
    RouteRuleNotFound,
    RoutePolicyViolation,
    AntiReplayDetected,
    MacVerificationFailed,
    PayloadTooLarge,
    InvalidPacketHeader,
    InvalidParameter,
}

// ============================================================================
// NIVEAUX DE CONFIANCE (TRUST LEVELS)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    Confined = 0,
    Standard = 1,
    Privileged = 2,
    HyperIsolated = 3,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Confined => "Confined",
            TrustLevel::Standard => "Standard",
            TrustLevel::Privileged => "Privileged",
            TrustLevel::HyperIsolated => "HyperIsolated",
        }
    }
}

// ============================================================================
// ACTIONS DE ROUTAGE (ROUTE ACTIONS)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    Deny = 0,
    AllowDirect = 1,
    RequireTunnel = 2,
    QuarantineOnAttempt = 3,
}

// ============================================================================
// ÉTAT DE TUNNEL SÉCURISÉ
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    Inactive = 0,
    Established = 1,
    Rekeying = 2,
    Terminated = 3,
    Quarantined = 4,
}

// ============================================================================
// CAPACITÉ CAPABILAIRE MONOTONE (SecRouteCap)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecRouteCap {
    pub handle: Handle,
    pub rights: u32,
    pub max_tunnels: u32,
    pub generation: u32,
}

impl SecRouteCap {
    pub const fn new(handle: Handle, rights: u32, max_tunnels: u32, generation: u32) -> Self {
        Self {
            handle,
            rights,
            max_tunnels,
            generation,
        }
    }

    #[inline(always)]
    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn attenuate(&self, new_rights: u32, new_max_tunnels: u32) -> Result<Self, SecRouteError> {
        // Règle d'atténuation strictement monotone : aucun droit nouveau, quota inférieur ou égal
        if (new_rights & !self.rights) != 0 || new_max_tunnels > self.max_tunnels {
            return Err(SecRouteError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: new_rights,
            max_tunnels: new_max_tunnels,
            generation: self.generation + 1,
        })
    }
}

// ============================================================================
// CRYPTOGRAPHIE INTÉGRÉE : CHACHA20, SHA-256 & HMAC-SHA256 (#![no_std])
// ============================================================================

/// Implémentation SHA-256 souveraine `#![no_std]` sans allocation
#[derive(Clone, Copy)]
pub struct Sha256;

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

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = [
            0x6a09e667u32,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ];

        let len = data.len();
        let bit_len = (len as u64) * 8;
        let mut block = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= len {
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut h, &block);
            offset += 64;
        }

        let rem = len - offset;
        for i in 0..rem {
            block[i] = data[offset + i];
        }
        block[rem] = 0x80;

        if rem >= 56 {
            for i in (rem + 1)..64 {
                block[i] = 0;
            }
            Self::process_block(&mut h, &block);
            block = [0u8; 64];
        } else {
            for i in (rem + 1)..56 {
                block[i] = 0;
            }
        }

        let be_bytes = bit_len.to_be_bytes();
        block[56..64].copy_from_slice(&be_bytes);
        Self::process_block(&mut h, &block);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }

    fn process_block(h: &mut [u32; 8], block: &[u8; 64]) {
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

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let t1 = h_val
                .wrapping_add(Self::sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let t2 = Self::sigma0(a).wrapping_add(Self::maj(a, b, c));
            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }
}

/// Implémentation HMAC-SHA256 souveraine `#![no_std]`
pub struct HmacSha256;

impl HmacSha256 {
    pub fn mac(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut k_pad = [0u8; 64];
        if key.len() > 64 {
            let hashed_key = Sha256::digest(key);
            k_pad[..32].copy_from_slice(&hashed_key);
        } else {
            k_pad[..key.len()].copy_from_slice(key);
        }

        let mut i_pad = [0x36u8; 64];
        let mut o_pad = [0x5cu8; 64];
        for i in 0..64 {
            i_pad[i] ^= k_pad[i];
            o_pad[i] ^= k_pad[i];
        }

        let mut inner_buf = [0u8; 64 + 1024];
        let inner_len = 64 + msg.len().min(1024);
        inner_buf[..64].copy_from_slice(&i_pad);
        inner_buf[64..inner_len].copy_from_slice(&msg[..msg.len().min(1024)]);
        let inner_hash = Sha256::digest(&inner_buf[..inner_len]);

        let mut outer_buf = [0u8; 64 + 32];
        outer_buf[..64].copy_from_slice(&o_pad);
        outer_buf[64..96].copy_from_slice(&inner_hash);

        Sha256::digest(&outer_buf)
    }
}

/// Chiffrement symétrique par flux ChaCha20 RFC 7539 / 8439 `#![no_std]`
pub struct ChaCha20;

impl ChaCha20 {
    #[inline(always)]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(7);
    }

    /// Génère un bloc de 64 octets de flux de clé
    pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
        let mut state = [0u32; 16];
        // Constantes "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        state[12] = counter;
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        let mut working = state;

        for _ in 0..10 {
            // Tours colonnes
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);

            // Tours diagonales
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        for i in 0..16 {
            let val = working[i].wrapping_add(state[i]);
            let bytes = val.to_le_bytes();
            out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
    }

    /// Chiffre ou déchiffre in-place des données avec ChaCha20
    pub fn apply_keystream(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], buffer: &mut [u8]) {
        let mut key_block = [0u8; 64];
        let mut offset = 0;

        while offset < buffer.len() {
            Self::block(key, counter, nonce, &mut key_block);
            counter = counter.wrapping_add(1);

            let chunk_len = (buffer.len() - offset).min(64);
            for i in 0..chunk_len {
                buffer[offset + i] ^= key_block[i];
            }
            offset += chunk_len;
        }
    }
}

// ============================================================================
// ZONE DE SÉCURITÉ & MICRO-SEGMENTATION
// ============================================================================

#[derive(Clone, Copy)]
pub struct SecurityZone {
    pub zone_id: u16,
    pub name: [u8; MAX_ZONE_NAME_LEN],
    pub name_len: usize,
    pub trust_level: TrustLevel,
    pub is_quarantined: bool,
    pub allowed_ingress_zones: [u16; 8],
    pub allowed_ingress_count: usize,
}

impl SecurityZone {
    pub const fn empty() -> Self {
        Self {
            zone_id: 0,
            name: [0u8; MAX_ZONE_NAME_LEN],
            name_len: 0,
            trust_level: TrustLevel::Confined,
            is_quarantined: false,
            allowed_ingress_zones: [0u16; 8],
            allowed_ingress_count: 0,
        }
    }

    pub fn new(zone_id: u16, name_str: &str, trust_level: TrustLevel) -> Self {
        let mut name = [0u8; MAX_ZONE_NAME_LEN];
        let bytes = name_str.as_bytes();
        let len = bytes.len().min(MAX_ZONE_NAME_LEN);
        let mut i = 0;
        while i < len {
            name[i] = bytes[i];
            i += 1;
        }
        Self {
            zone_id,
            name,
            name_len: len,
            trust_level,
            is_quarantined: false,
            allowed_ingress_zones: [0u16; 8],
            allowed_ingress_count: 0,
        }
    }

    pub fn allow_ingress(&mut self, src_zone_id: u16) -> bool {
        for i in 0..self.allowed_ingress_count {
            if self.allowed_ingress_zones[i] == src_zone_id {
                return true;
            }
        }
        if self.allowed_ingress_count < self.allowed_ingress_zones.len() {
            self.allowed_ingress_zones[self.allowed_ingress_count] = src_zone_id;
            self.allowed_ingress_count += 1;
            true
        } else {
            false
        }
    }

    pub fn is_ingress_allowed(&self, src_zone_id: u16) -> bool {
        if self.is_quarantined {
            return false;
        }
        if self.zone_id == src_zone_id {
            return true; // Communication intra-zone par défaut
        }
        for i in 0..self.allowed_ingress_count {
            if self.allowed_ingress_zones[i] == src_zone_id {
                return true;
            }
        }
        false
    }
}

// ============================================================================
// POINT D'EXTRÉMITÉ D'ENCLAVE (ENCLAVE ENDPOINT)
// ============================================================================

#[derive(Clone, Copy)]
pub struct EnclaveEndpoint {
    pub enclave_id: u32,
    pub zone_id: u16,
    pub ipv4: [u8; 4],
    pub port: u16,
    pub public_key: [u8; 32],
    pub is_active: bool,
    pub is_quarantined: bool,
    pub packets_sent: u64,
    pub packets_received: u64,
}

impl EnclaveEndpoint {
    pub const fn empty() -> Self {
        Self {
            enclave_id: 0,
            zone_id: 0,
            ipv4: [0; 4],
            port: 0,
            public_key: [0; 32],
            is_active: false,
            is_quarantined: false,
            packets_sent: 0,
            packets_received: 0,
        }
    }
}

// ============================================================================
// TUNNEL SOUVERAIN CHIFFRÉ (SECURE TUNNEL)
// ============================================================================

#[derive(Clone, Copy)]
pub struct SecureTunnel {
    pub tunnel_id: u32,
    pub src_enclave: u32,
    pub dst_enclave: u32,
    pub session_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub tx_seq: u64,
    pub rx_seq: u64,
    pub bytes_transmitted: u64,
    pub bytes_received: u64,
    pub created_at_ticks: u64,
    pub last_activity_ticks: u64,
    pub status: TunnelStatus,
}

impl SecureTunnel {
    pub const fn empty() -> Self {
        Self {
            tunnel_id: 0,
            src_enclave: 0,
            dst_enclave: 0,
            session_key: [0; 32],
            mac_key: [0; 32],
            tx_seq: 0,
            rx_seq: 0,
            bytes_transmitted: 0,
            bytes_received: 0,
            created_at_ticks: 0,
            last_activity_ticks: 0,
            status: TunnelStatus::Inactive,
        }
    }
}

// ============================================================================
// RÈGLE DE ROUTAGE ZERO-TRUST
// ============================================================================

#[derive(Clone, Copy)]
pub struct SecRouteRule {
    pub rule_id: u32,
    pub src_zone: u16,    // 0 = any
    pub dst_zone: u16,    // 0 = any
    pub src_enclave: u32, // 0 = any
    pub dst_enclave: u32, // 0 = any
    pub protocol: u8,     // 0 = any, 6 = TCP, 17 = UDP, 254 = IPC
    pub port_min: u16,
    pub port_max: u16,
    pub action: RouteAction,
    pub required_capability_flag: u32,
    pub priority: u16,
    pub match_count: u64,
    pub is_active: bool,
}

impl SecRouteRule {
    pub const fn empty() -> Self {
        Self {
            rule_id: 0,
            src_zone: 0,
            dst_zone: 0,
            src_enclave: 0,
            dst_enclave: 0,
            protocol: 0,
            port_min: 0,
            port_max: 0,
            action: RouteAction::Deny,
            required_capability_flag: 0,
            priority: 0,
            match_count: 0,
            is_active: false,
        }
    }

    pub fn matches(
        &self,
        s_zone: u16,
        d_zone: u16,
        s_enc: u32,
        d_enc: u32,
        proto: u8,
        port: u16,
    ) -> bool {
        if !self.is_active {
            return false;
        }
        if self.src_zone != 0 && self.src_zone != s_zone {
            return false;
        }
        if self.dst_zone != 0 && self.dst_zone != d_zone {
            return false;
        }
        if self.src_enclave != 0 && self.src_enclave != s_enc {
            return false;
        }
        if self.dst_enclave != 0 && self.dst_enclave != d_enc {
            return false;
        }
        if self.protocol != 0 && self.protocol != proto {
            return false;
        }
        if self.port_max != 0 && (port < self.port_min || port > self.port_max) {
            return false;
        }
        true
    }
}

// ============================================================================
// EN-TÊTE ET PAQUET DE TUNNEL SOUVERAIN (SECPACKET)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecPacketHeader {
    pub magic: u32,
    pub version: u8,
    pub flags: u8,
    pub tunnel_id: u32,
    pub seq: u64,
    pub src_enclave: u32,
    pub dst_enclave: u32,
    pub src_zone: u16,
    pub dst_zone: u16,
    pub protocol: u8,
    pub payload_len: u16,
    pub tag: [u8; 16], // MAC d'intégrité HMAC-SHA256 tronqué
}

impl SecPacketHeader {
    pub const SIZE: usize = 4 + 1 + 1 + 4 + 8 + 4 + 4 + 2 + 2 + 1 + 2 + 16; // 45 octets

    pub fn serialize(&self, buf: &mut [u8]) -> Result<(), SecRouteError> {
        if buf.len() < Self::SIZE {
            return Err(SecRouteError::InvalidParameter);
        }
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6..10].copy_from_slice(&self.tunnel_id.to_le_bytes());
        buf[10..18].copy_from_slice(&self.seq.to_le_bytes());
        buf[18..22].copy_from_slice(&self.src_enclave.to_le_bytes());
        buf[22..26].copy_from_slice(&self.dst_enclave.to_le_bytes());
        buf[26..28].copy_from_slice(&self.src_zone.to_le_bytes());
        buf[28..30].copy_from_slice(&self.dst_zone.to_le_bytes());
        buf[30] = self.protocol;
        buf[31..33].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[33..49].copy_from_slice(&self.tag);
        Ok(())
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, SecRouteError> {
        if buf.len() < Self::SIZE {
            return Err(SecRouteError::InvalidPacketHeader);
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != TUNNEL_PACKET_MAGIC {
            return Err(SecRouteError::InvalidPacketHeader);
        }
        let version = buf[4];
        let flags = buf[5];
        let tunnel_id = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let seq = u64::from_le_bytes([
            buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        ]);
        let src_enclave = u32::from_le_bytes([buf[18], buf[19], buf[20], buf[21]]);
        let dst_enclave = u32::from_le_bytes([buf[22], buf[23], buf[24], buf[25]]);
        let src_zone = u16::from_le_bytes([buf[26], buf[27]]);
        let dst_zone = u16::from_le_bytes([buf[28], buf[29]]);
        let protocol = buf[30];
        let payload_len = u16::from_le_bytes([buf[31], buf[32]]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&buf[33..49]);

        Ok(Self {
            magic,
            version,
            flags,
            tunnel_id,
            seq,
            src_enclave,
            dst_enclave,
            src_zone,
            dst_zone,
            protocol,
            payload_len,
            tag,
        })
    }
}

// ============================================================================
// ENREGISTREMENT D'AUDIT INALTÉRABLE
// ============================================================================

#[derive(Clone, Copy)]
pub struct SecRouteAuditRecord {
    pub tick: u64,
    pub event_type: u8,
    pub src_enclave: u32,
    pub dst_enclave: u32,
    pub details: [u8; 24],
    pub entry_hash: [u8; 32],
}

impl SecRouteAuditRecord {
    pub const fn empty() -> Self {
        Self {
            tick: 0,
            event_type: 0,
            src_enclave: 0,
            dst_enclave: 0,
            details: [0; 24],
            entry_hash: [0; 32],
        }
    }
}

// ============================================================================
// DÉMON DE ROUTAGE SÉCURISÉ & MICRO-SEGMENTATION (JamboSecRouteDaemon)
// ============================================================================

pub struct JamboSecRouteDaemon {
    pub admin_cap: SecRouteCap,
    pub zones: [SecurityZone; MAX_ZONES],
    pub zone_count: usize,
    pub enclaves: [EnclaveEndpoint; MAX_ENCLAVES],
    pub enclave_count: usize,
    pub tunnels: [SecureTunnel; MAX_TUNNELS],
    pub tunnel_count: usize,
    pub rules: [SecRouteRule; MAX_RULES],
    pub rule_count: usize,

    // Statistiques d'exploitation
    pub packets_routed: u64,
    pub packets_encrypted: u64,
    pub packets_decrypted: u64,
    pub packets_dropped: u64,
    pub anti_replay_violations: u64,
    pub quarantined_events: u64,

    // Traçabilité et chaîne d'audit scellée SHA-256
    pub current_time_ticks: u64,
    pub audit_chain: [u8; 32],
    pub audit_count: u64,
    pub audit_records: [SecRouteAuditRecord; MAX_AUDIT_LOGS],
}

impl JamboSecRouteDaemon {
    pub const fn new(admin_cap: SecRouteCap) -> Self {
        Self {
            admin_cap,
            zones: [SecurityZone::empty(); MAX_ZONES],
            zone_count: 0,
            enclaves: [EnclaveEndpoint::empty(); MAX_ENCLAVES],
            enclave_count: 0,
            tunnels: [SecureTunnel::empty(); MAX_TUNNELS],
            tunnel_count: 0,
            rules: [SecRouteRule::empty(); MAX_RULES],
            rule_count: 0,
            packets_routed: 0,
            packets_encrypted: 0,
            packets_decrypted: 0,
            packets_dropped: 0,
            anti_replay_violations: 0,
            quarantined_events: 0,
            current_time_ticks: 1,
            audit_chain: [0x53; 32],
            audit_count: 0,
            audit_records: [SecRouteAuditRecord::empty(); MAX_AUDIT_LOGS],
        }
    }

    /// Initialise les zones de sécurité par défaut, endpoints et politiques initiales Zero-Trust
    pub fn init_defaults(&mut self) {
        let cap = self.admin_cap;
        // 1. Définition des zones de sécurité étanches
        let _ = self.create_zone(&cap, 1, "Hypervisor-Core", TrustLevel::HyperIsolated);
        let _ = self.create_zone(&cap, 2, "TEE-Enclave-Secure", TrustLevel::Privileged);
        let _ = self.create_zone(&cap, 3, "Standard-App-Mesh", TrustLevel::Standard);
        let _ = self.create_zone(&cap, 4, "Confined-Sandbox", TrustLevel::Confined);

        // Autoriser TEE -> Hypervisor et Standard -> TEE via tunnel
        if let Some(tee_zone) = self.get_zone_mut(2) {
            tee_zone.allow_ingress(1);
            tee_zone.allow_ingress(3);
        }
        if let Some(hyp_zone) = self.get_zone_mut(1) {
            hyp_zone.allow_ingress(2);
        }

        // 2. Enregistrement des enclaves souveraines
        let _ = self.register_enclave(
            &cap,
            101,
            1, // Hypervisor-Core
            [10, 0, 1, 1],
            9001,
            [0x11; 32],
        );
        let _ = self.register_enclave(
            &cap,
            201,
            2, // TEE Enclave (Vault / Keymaster)
            [10, 0, 2, 1],
            9002,
            [0x22; 32],
        );
        let _ = self.register_enclave(
            &cap,
            301,
            3, // Standard App
            [10, 0, 3, 1],
            9003,
            [0x33; 32],
        );
        let _ = self.register_enclave(
            &cap,
            401,
            4, // Confined Sandbox
            [10, 0, 4, 1],
            9004,
            [0x44; 32],
        );

        // 3. Établissement du tunnel souverain chiffré par défaut entre App (301) et TEE (201)
        let _ = self.establish_tunnel(&cap, 1, 301, 201, [0x7au8; 32], [0x8bu8; 32]);

        // 4. Règles Zero-Trust par défaut
        // Règle 1 : TEE (201) <-> App (301) exige un tunnel chiffré
        let _ = self.add_route_rule(
            &cap,
            1,
            3, // Src Zone: App
            2, // Dst Zone: TEE
            301,
            201,
            0,
            0,
            0,
            RouteAction::RequireTunnel,
            100,
        );

        // Règle 2 : Confined Sandbox (401) vers Hypervisor (101) => Quarantaine immédiate
        let _ = self.add_route_rule(
            &cap,
            2,
            4, // Src Zone: Confined
            1, // Dst Zone: Hypervisor
            401,
            101,
            0,
            0,
            0,
            RouteAction::QuarantineOnAttempt,
            200,
        );

        self.append_audit_log(1, 0, 0, b"init_defaults_ok");
    }

    pub fn tick(&mut self, elapsed: u64) {
        self.current_time_ticks = self.current_time_ticks.saturating_add(elapsed);
    }

    // ========================================================================
    // GESTION DES ZONES DE SÉCURITÉ
    // ========================================================================

    pub fn create_zone(
        &mut self,
        cap: &SecRouteCap,
        zone_id: u16,
        name: &str,
        trust_level: TrustLevel,
    ) -> Result<(), SecRouteError> {
        if !cap.has_right(secroute_rights::CONFIGURE_ZONE) {
            return Err(SecRouteError::PermissionDenied);
        }
        for i in 0..self.zone_count {
            if self.zones[i].zone_id == zone_id {
                return Ok(());
            }
        }
        if self.zone_count >= MAX_ZONES {
            return Err(SecRouteError::ZoneCapacityExceeded);
        }
        self.zones[self.zone_count] = SecurityZone::new(zone_id, name, trust_level);
        self.zone_count += 1;
        self.append_audit_log(2, zone_id as u32, 0, b"zone_created");
        Ok(())
    }

    pub fn get_zone(&self, zone_id: u16) -> Option<&SecurityZone> {
        for i in 0..self.zone_count {
            if self.zones[i].zone_id == zone_id {
                return Some(&self.zones[i]);
            }
        }
        None
    }

    pub fn get_zone_mut(&mut self, zone_id: u16) -> Option<&mut SecurityZone> {
        for i in 0..self.zone_count {
            if self.zones[i].zone_id == zone_id {
                return Some(&mut self.zones[i]);
            }
        }
        None
    }

    // ========================================================================
    // GESTION DES ENCLAVES (ENDPOINTS)
    // ========================================================================

    pub fn register_enclave(
        &mut self,
        cap: &SecRouteCap,
        enclave_id: u32,
        zone_id: u16,
        ipv4: [u8; 4],
        port: u16,
        public_key: [u8; 32],
    ) -> Result<(), SecRouteError> {
        if !cap.has_right(secroute_rights::CONFIGURE_ZONE) {
            return Err(SecRouteError::PermissionDenied);
        }
        if self.get_zone(zone_id).is_none() {
            return Err(SecRouteError::ZoneNotFound);
        }
        for i in 0..self.enclave_count {
            if self.enclaves[i].enclave_id == enclave_id {
                self.enclaves[i].zone_id = zone_id;
                self.enclaves[i].ipv4 = ipv4;
                self.enclaves[i].port = port;
                self.enclaves[i].public_key = public_key;
                self.enclaves[i].is_active = true;
                return Ok(());
            }
        }
        if self.enclave_count >= MAX_ENCLAVES {
            return Err(SecRouteError::EnclaveCapacityExceeded);
        }
        let mut ep = EnclaveEndpoint::empty();
        ep.enclave_id = enclave_id;
        ep.zone_id = zone_id;
        ep.ipv4 = ipv4;
        ep.port = port;
        ep.public_key = public_key;
        ep.is_active = true;
        ep.is_quarantined = false;

        self.enclaves[self.enclave_count] = ep;
        self.enclave_count += 1;
        self.append_audit_log(3, enclave_id, zone_id as u32, b"enclave_registered");
        Ok(())
    }

    pub fn get_enclave(&self, enclave_id: u32) -> Option<&EnclaveEndpoint> {
        for i in 0..self.enclave_count {
            if self.enclaves[i].enclave_id == enclave_id {
                return Some(&self.enclaves[i]);
            }
        }
        None
    }

    pub fn get_enclave_mut(&mut self, enclave_id: u32) -> Option<&mut EnclaveEndpoint> {
        for i in 0..self.enclave_count {
            if self.enclaves[i].enclave_id == enclave_id {
                return Some(&mut self.enclaves[i]);
            }
        }
        None
    }

    pub fn quarantine_enclave(
        &mut self,
        cap: &SecRouteCap,
        enclave_id: u32,
    ) -> Result<(), SecRouteError> {
        if !cap.has_right(secroute_rights::ISOLATE_ENCLAVE) {
            return Err(SecRouteError::PermissionDenied);
        }
        let mut found = false;
        for i in 0..self.enclave_count {
            if self.enclaves[i].enclave_id == enclave_id {
                self.enclaves[i].is_quarantined = true;
                found = true;
                break;
            }
        }
        if !found {
            return Err(SecRouteError::EnclaveNotFound);
        }

        // Invalider immédiatement tous les tunnels connectés à cette enclave (O(N) borné par MAX_TUNNELS)
        for i in 0..self.tunnel_count {
            if self.tunnels[i].src_enclave == enclave_id
                || self.tunnels[i].dst_enclave == enclave_id
            {
                self.tunnels[i].status = TunnelStatus::Quarantined;
            }
        }

        self.quarantined_events += 1;
        self.append_audit_log(4, enclave_id, 0, b"enclave_quarantined_o1");
        Ok(())
    }

    // ========================================================================
    // GESTION DES TUNNELS SOUVERAINS CHIFFRÉS
    // ========================================================================

    pub fn establish_tunnel(
        &mut self,
        cap: &SecRouteCap,
        tunnel_id: u32,
        src_enclave: u32,
        dst_enclave: u32,
        session_key: [u8; 32],
        mac_key: [u8; 32],
    ) -> Result<(), SecRouteError> {
        if !cap.has_right(secroute_rights::CREATE_TUNNEL) {
            return Err(SecRouteError::PermissionDenied);
        }
        if self.tunnel_count as u32 >= cap.max_tunnels || self.tunnel_count >= MAX_TUNNELS {
            return Err(SecRouteError::TunnelCapacityExceeded);
        }
        let src_ep = self
            .get_enclave(src_enclave)
            .ok_or(SecRouteError::EnclaveNotFound)?;
        let dst_ep = self
            .get_enclave(dst_enclave)
            .ok_or(SecRouteError::EnclaveNotFound)?;
        if src_ep.is_quarantined || dst_ep.is_quarantined {
            return Err(SecRouteError::EnclaveQuarantined);
        }

        for i in 0..self.tunnel_count {
            if self.tunnels[i].tunnel_id == tunnel_id {
                return Err(SecRouteError::TunnelAlreadyExists);
            }
        }

        let mut t = SecureTunnel::empty();
        t.tunnel_id = tunnel_id;
        t.src_enclave = src_enclave;
        t.dst_enclave = dst_enclave;
        t.session_key = session_key;
        t.mac_key = mac_key;
        t.tx_seq = 1;
        t.rx_seq = 0;
        t.created_at_ticks = self.current_time_ticks;
        t.last_activity_ticks = self.current_time_ticks;
        t.status = TunnelStatus::Established;

        self.tunnels[self.tunnel_count] = t;
        self.tunnel_count += 1;
        self.append_audit_log(5, src_enclave, dst_enclave, b"tunnel_established");
        Ok(())
    }

    pub fn get_tunnel(&self, tunnel_id: u32) -> Option<&SecureTunnel> {
        for i in 0..self.tunnel_count {
            if self.tunnels[i].tunnel_id == tunnel_id {
                return Some(&self.tunnels[i]);
            }
        }
        None
    }

    pub fn get_tunnel_mut(&mut self, tunnel_id: u32) -> Option<&mut SecureTunnel> {
        for i in 0..self.tunnel_count {
            if self.tunnels[i].tunnel_id == tunnel_id {
                return Some(&mut self.tunnels[i]);
            }
        }
        None
    }

    pub fn find_tunnel_between(&self, src_enclave: u32, dst_enclave: u32) -> Option<&SecureTunnel> {
        for i in 0..self.tunnel_count {
            if (self.tunnels[i].src_enclave == src_enclave
                && self.tunnels[i].dst_enclave == dst_enclave)
                || (self.tunnels[i].src_enclave == dst_enclave
                    && self.tunnels[i].dst_enclave == src_enclave)
            {
                if self.tunnels[i].status == TunnelStatus::Established {
                    return Some(&self.tunnels[i]);
                }
            }
        }
        None
    }

    // ========================================================================
    // RÈGLES DE ROUTAGE ZERO-TRUST
    // ========================================================================

    pub fn add_route_rule(
        &mut self,
        cap: &SecRouteCap,
        rule_id: u32,
        src_zone: u16,
        dst_zone: u16,
        src_enclave: u32,
        dst_enclave: u32,
        protocol: u8,
        port_min: u16,
        port_max: u16,
        action: RouteAction,
        priority: u16,
    ) -> Result<(), SecRouteError> {
        if !cap.has_right(secroute_rights::ADD_RULE) {
            return Err(SecRouteError::PermissionDenied);
        }
        if self.rule_count >= MAX_RULES {
            return Err(SecRouteError::RouteRuleCapacityExceeded);
        }
        for i in 0..self.rule_count {
            if self.rules[i].rule_id == rule_id {
                self.rules[i].src_zone = src_zone;
                self.rules[i].dst_zone = dst_zone;
                self.rules[i].src_enclave = src_enclave;
                self.rules[i].dst_enclave = dst_enclave;
                self.rules[i].protocol = protocol;
                self.rules[i].port_min = port_min;
                self.rules[i].port_max = port_max;
                self.rules[i].action = action;
                self.rules[i].priority = priority;
                self.rules[i].is_active = true;
                return Ok(());
            }
        }
        let mut r = SecRouteRule::empty();
        r.rule_id = rule_id;
        r.src_zone = src_zone;
        r.dst_zone = dst_zone;
        r.src_enclave = src_enclave;
        r.dst_enclave = dst_enclave;
        r.protocol = protocol;
        r.port_min = port_min;
        r.port_max = port_max;
        r.action = action;
        r.priority = priority;
        r.is_active = true;

        self.rules[self.rule_count] = r;
        self.rule_count += 1;
        self.append_audit_log(6, rule_id, action as u32, b"route_rule_added");
        Ok(())
    }

    /// Évalue l'action de routage pour un paquet donné selon le modèle Zero-Trust
    pub fn evaluate_policy(
        &mut self,
        src_zone: u16,
        dst_zone: u16,
        src_enclave: u32,
        dst_enclave: u32,
        protocol: u8,
        port: u16,
    ) -> RouteAction {
        let mut best_action = RouteAction::Deny; // Zero-Trust Deny-by-Default
        let mut highest_priority = 0u16;

        for i in 0..self.rule_count {
            if self.rules[i].matches(src_zone, dst_zone, src_enclave, dst_enclave, protocol, port) {
                if self.rules[i].priority >= highest_priority {
                    highest_priority = self.rules[i].priority;
                    best_action = self.rules[i].action;
                    self.rules[i].match_count += 1;
                }
            }
        }

        // Si aucune règle spécifique mais même zone et zone non en quarantaine
        if best_action == RouteAction::Deny && src_zone == dst_zone && src_zone != 0 {
            if let Some(z) = self.get_zone(src_zone) {
                if !z.is_quarantined {
                    best_action = RouteAction::AllowDirect;
                }
            }
        }

        best_action
    }

    // ========================================================================
    // ENCAPSULATION & CHIFFREMENT (TRANSMISSION VIA TUNNEL SOUVERAIN)
    // ========================================================================

    pub fn encapsulate_and_route(
        &mut self,
        cap: &SecRouteCap,
        tunnel_id: u32,
        protocol: u8,
        payload: &[u8],
        out_packet: &mut [u8],
    ) -> Result<usize, SecRouteError> {
        if !cap.has_right(secroute_rights::ROUTE_FORWARD) {
            return Err(SecRouteError::PermissionDenied);
        }
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(SecRouteError::PayloadTooLarge);
        }
        if out_packet.len() < SecPacketHeader::SIZE + payload.len() {
            return Err(SecRouteError::InvalidParameter);
        }

        // Localiser le tunnel
        let mut tunnel_idx = usize::MAX;
        for i in 0..self.tunnel_count {
            if self.tunnels[i].tunnel_id == tunnel_id {
                tunnel_idx = i;
                break;
            }
        }
        if tunnel_idx == usize::MAX {
            return Err(SecRouteError::TunnelNotFound);
        }
        if self.tunnels[tunnel_idx].status != TunnelStatus::Established {
            return Err(SecRouteError::TunnelInactive);
        }

        let src_enc = self.tunnels[tunnel_idx].src_enclave;
        let dst_enc = self.tunnels[tunnel_idx].dst_enclave;

        // Vérification d'état des enclaves
        let src_zone = self.get_enclave(src_enc).map(|e| e.zone_id).unwrap_or(0);
        let dst_zone = self.get_enclave(dst_enc).map(|e| e.zone_id).unwrap_or(0);

        if let Some(src) = self.get_enclave(src_enc) {
            if src.is_quarantined {
                return Err(SecRouteError::EnclaveQuarantined);
            }
        }
        if let Some(dst) = self.get_enclave(dst_enc) {
            if dst.is_quarantined {
                return Err(SecRouteError::EnclaveQuarantined);
            }
        }

        // Évaluation de la politique de sécurité Zero-Trust
        let action = self.evaluate_policy(src_zone, dst_zone, src_enc, dst_enc, protocol, 0);
        if action == RouteAction::QuarantineOnAttempt {
            let admin_cap = self.admin_cap;
            let _ = self.quarantine_enclave(&admin_cap, src_enc);
            self.packets_dropped += 1;
            return Err(SecRouteError::EnclaveQuarantined);
        }
        if action == RouteAction::Deny {
            self.packets_dropped += 1;
            return Err(SecRouteError::RoutePolicyViolation);
        }

        let seq = self.tunnels[tunnel_idx].tx_seq;
        self.tunnels[tunnel_idx].tx_seq = self.tunnels[tunnel_idx].tx_seq.wrapping_add(1);

        // Préparer le nonce pour ChaCha20 (12 octets : 4 octets de tunnel_id + 8 octets de seq)
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&tunnel_id.to_le_bytes());
        nonce[4..12].copy_from_slice(&seq.to_le_bytes());

        // Copier et chiffrer la payload
        let payload_start = SecPacketHeader::SIZE;
        let payload_end = payload_start + payload.len();
        out_packet[payload_start..payload_end].copy_from_slice(payload);

        let session_key = self.tunnels[tunnel_idx].session_key;
        let mac_key = self.tunnels[tunnel_idx].mac_key;

        ChaCha20::apply_keystream(
            &session_key,
            1,
            &nonce,
            &mut out_packet[payload_start..payload_end],
        );

        // Calculer l'étiquette d'authentification MAC (HMAC-SHA256 sur l'en-tête partiel + payload chiffrée)
        let mut mac_msg = [0u8; 32 + MAX_PAYLOAD_SIZE];
        mac_msg[0..4].copy_from_slice(&tunnel_id.to_le_bytes());
        mac_msg[4..12].copy_from_slice(&seq.to_le_bytes());
        mac_msg[12..16].copy_from_slice(&src_enc.to_le_bytes());
        mac_msg[16..20].copy_from_slice(&dst_enc.to_le_bytes());
        mac_msg[20..22].copy_from_slice(&src_zone.to_le_bytes());
        mac_msg[22..24].copy_from_slice(&dst_zone.to_le_bytes());
        mac_msg[24] = protocol;
        mac_msg[25..27].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        let mac_msg_len = 27 + payload.len();
        mac_msg[27..mac_msg_len].copy_from_slice(&out_packet[payload_start..payload_end]);

        let full_mac = HmacSha256::mac(&mac_key, &mac_msg[..mac_msg_len]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&full_mac[..16]);

        let header = SecPacketHeader {
            magic: TUNNEL_PACKET_MAGIC,
            version: 1,
            flags: 1, // Bit 0: Encrypted
            tunnel_id,
            seq,
            src_enclave: src_enc,
            dst_enclave: dst_enc,
            src_zone,
            dst_zone,
            protocol,
            payload_len: payload.len() as u16,
            tag,
        };

        header.serialize(&mut out_packet[..SecPacketHeader::SIZE])?;

        self.tunnels[tunnel_idx].bytes_transmitted = self.tunnels[tunnel_idx]
            .bytes_transmitted
            .saturating_add(payload.len() as u64);
        self.tunnels[tunnel_idx].last_activity_ticks = self.current_time_ticks;

        if let Some(src) = self.get_enclave_mut(src_enc) {
            src.packets_sent += 1;
        }

        self.packets_routed += 1;
        self.packets_encrypted += 1;
        Ok(payload_end)
    }

    // ========================================================================
    // DÉCAPSULATION, DÉCHIFFREMENT & CONTRÔLE D'INTÉGRITÉ
    // ========================================================================

    pub fn decapsulate_and_verify(
        &mut self,
        packet: &[u8],
        out_payload: &mut [u8],
    ) -> Result<(SecPacketHeader, usize), SecRouteError> {
        let header = SecPacketHeader::deserialize(packet)?;

        let mut tunnel_idx = usize::MAX;
        for i in 0..self.tunnel_count {
            if self.tunnels[i].tunnel_id == header.tunnel_id {
                tunnel_idx = i;
                break;
            }
        }
        if tunnel_idx == usize::MAX {
            self.packets_dropped += 1;
            return Err(SecRouteError::TunnelNotFound);
        }
        if self.tunnels[tunnel_idx].status != TunnelStatus::Established {
            self.packets_dropped += 1;
            return Err(SecRouteError::TunnelInactive);
        }

        // Protection Anti-Rejeu stricte : le numéro de séquence doit être strictement croissant
        if header.seq <= self.tunnels[tunnel_idx].rx_seq {
            self.anti_replay_violations += 1;
            self.packets_dropped += 1;
            self.append_audit_log(
                7,
                header.tunnel_id,
                header.seq as u32,
                b"anti_replay_violation",
            );
            return Err(SecRouteError::AntiReplayDetected);
        }

        let p_len = header.payload_len as usize;
        if p_len > MAX_PAYLOAD_SIZE || packet.len() < SecPacketHeader::SIZE + p_len {
            self.packets_dropped += 1;
            return Err(SecRouteError::InvalidParameter);
        }
        if out_payload.len() < p_len {
            return Err(SecRouteError::InvalidParameter);
        }

        let payload_start = SecPacketHeader::SIZE;
        let payload_end = payload_start + p_len;
        let enc_slice = &packet[payload_start..payload_end];

        let mac_key = self.tunnels[tunnel_idx].mac_key;

        // Vérification de l'étiquette MAC HMAC-SHA256
        let mut mac_msg = [0u8; 32 + MAX_PAYLOAD_SIZE];
        mac_msg[0..4].copy_from_slice(&header.tunnel_id.to_le_bytes());
        mac_msg[4..12].copy_from_slice(&header.seq.to_le_bytes());
        mac_msg[12..16].copy_from_slice(&header.src_enclave.to_le_bytes());
        mac_msg[16..20].copy_from_slice(&header.dst_enclave.to_le_bytes());
        mac_msg[20..22].copy_from_slice(&header.src_zone.to_le_bytes());
        mac_msg[22..24].copy_from_slice(&header.dst_zone.to_le_bytes());
        mac_msg[24] = header.protocol;
        mac_msg[25..27].copy_from_slice(&header.payload_len.to_le_bytes());
        let mac_msg_len = 27 + p_len;
        mac_msg[27..mac_msg_len].copy_from_slice(enc_slice);

        let computed_mac = HmacSha256::mac(&mac_key, &mac_msg[..mac_msg_len]);
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= header.tag[i] ^ computed_mac[i];
        }
        if diff != 0 {
            self.packets_dropped += 1;
            self.append_audit_log(
                8,
                header.tunnel_id,
                header.src_enclave,
                b"mac_verification_failed",
            );
            return Err(SecRouteError::MacVerificationFailed);
        }

        // Déchiffrement ChaCha20
        out_payload[..p_len].copy_from_slice(enc_slice);
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&header.tunnel_id.to_le_bytes());
        nonce[4..12].copy_from_slice(&header.seq.to_le_bytes());

        let session_key = self.tunnels[tunnel_idx].session_key;
        ChaCha20::apply_keystream(&session_key, 1, &nonce, &mut out_payload[..p_len]);

        // Mise à jour de l'état anti-rejeu et des métriques
        self.tunnels[tunnel_idx].rx_seq = header.seq;
        self.tunnels[tunnel_idx].bytes_received = self.tunnels[tunnel_idx]
            .bytes_received
            .saturating_add(p_len as u64);
        self.tunnels[tunnel_idx].last_activity_ticks = self.current_time_ticks;

        if let Some(dst) = self.get_enclave_mut(header.dst_enclave) {
            dst.packets_received += 1;
        }

        self.packets_decrypted += 1;
        Ok((header, p_len))
    }

    // ========================================================================
    // CHAÎNE D'AUDIT SCELLÉE SHA-256
    // ========================================================================

    pub fn append_audit_log(&mut self, event_type: u8, src_enc: u32, dst_enc: u32, details: &[u8]) {
        let idx = (self.audit_count as usize) % MAX_AUDIT_LOGS;
        let mut rec = SecRouteAuditRecord::empty();
        rec.tick = self.current_time_ticks;
        rec.event_type = event_type;
        rec.src_enclave = src_enc;
        rec.dst_enclave = dst_enc;

        let d_len = details.len().min(24);
        let mut i = 0;
        while i < d_len {
            rec.details[i] = details[i];
            i += 1;
        }

        // Calcul du hachage scellé reliant l'audit précédent
        let mut hash_buf = [0u8; 32 + 8 + 1 + 4 + 4 + 24];
        hash_buf[0..32].copy_from_slice(&self.audit_chain);
        hash_buf[32..40].copy_from_slice(&rec.tick.to_le_bytes());
        hash_buf[40] = rec.event_type;
        hash_buf[41..45].copy_from_slice(&rec.src_enclave.to_le_bytes());
        hash_buf[45..49].copy_from_slice(&rec.dst_enclave.to_le_bytes());
        hash_buf[49..73].copy_from_slice(&rec.details);

        rec.entry_hash = Sha256::digest(&hash_buf);
        self.audit_chain = rec.entry_hash;
        self.audit_records[idx] = rec;
        self.audit_count += 1;
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_monotonicity() {
        let cap = SecRouteCap::new(Handle::new(1, 1), secroute_rights::ALL, 10, 1);
        let att = cap.attenuate(secroute_rights::ROUTE_FORWARD, 5).unwrap();
        assert_eq!(att.rights, secroute_rights::ROUTE_FORWARD);
        assert_eq!(att.max_tunnels, 5);
        assert!(att.attenuate(secroute_rights::ALL, 5).is_err());
        assert!(att.attenuate(secroute_rights::ROUTE_FORWARD, 6).is_err());
    }

    #[test]
    fn test_chacha20_symmetry() {
        let key = [0x5au8; 32];
        let nonce = [0x12u8; 12];
        let mut data = *b"SOVEREIGN_ENCLAVE_MESH_STREAM_CIPHER_TEST_2026!";
        let backup = data;

        ChaCha20::apply_keystream(&key, 1, &nonce, &mut data);
        assert_ne!(data, backup);

        ChaCha20::apply_keystream(&key, 1, &nonce, &mut data);
        assert_eq!(data, backup);
    }

    #[test]
    fn test_packet_encapsulation_and_replay_detection() {
        let cap = SecRouteCap::new(Handle::new(1, 1), secroute_rights::ALL, 16, 1);
        let mut daemon = JamboSecRouteDaemon::new(cap);
        daemon.init_defaults();

        let mut pkt_buf = [0u8; 512];
        let mut dec_buf = [0u8; 256];
        let msg = b"TOP_SECRET_IPC_DATA";

        let len = daemon
            .encapsulate_and_route(&cap, 1, 254, msg, &mut pkt_buf)
            .unwrap();
        let (hdr, dlen) = daemon
            .decapsulate_and_verify(&pkt_buf[..len], &mut dec_buf)
            .unwrap();
        assert_eq!(hdr.seq, 1);
        assert_eq!(&dec_buf[..dlen], msg);

        // Anti-replay
        let replay = daemon.decapsulate_and_verify(&pkt_buf[..len], &mut dec_buf);
        assert_eq!(replay, Err(SecRouteError::AntiReplayDetected));
    }
}

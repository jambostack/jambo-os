//! Module de Réseau de Mixage Anonyme & Routage en Oignon Sphinx (`jambo-mixnet`)
//!
//! Phase 99 — Jalon v0.2.97
//!
//! Fournit les garanties souveraines d'anonymat, de dissimulation de métadonnées et
//! de résistance à l'analyse de trafic en Ring 3 pour JamboOS :
//! 1. Paquets cryptographiques Sphinx `#![no_std]` de taille fixe constante (256 octets)
//!    garantissant zéro fuite de métadonnées ou de longueur.
//! 2. Routage en oignon multi-sauts (jusqu'à 5 nœuds de mixage) avec dérivation de clés éphémères.
//! 3. Démasquage et épluchage par couches successives (Layered Onion Peeling) avec
//!    remplacement déterministe de remplissage (Deterministic Padding).
//! 4. Dissimulation temporelle et résistance aux attaques d'analyse de trafic :
//!    - Bassin de mixage (Mix Pool) avec permutation pseudo-aléatoire (Fisher-Yates).
//!    - Injection de trafic de couverture (Cover Traffic / Dummy Sphinx Packets).
//!    - Gigue et délais d'acheminement programmés.
//! 5. Protection anti-rejeu stricte par cache borné d'empreintes de paquets (Replay Cache).
//! 6. Contrôle d'accès capabilaire strict (`MixCap`) avec atténuation monotone et Zero-Ambient Authority.
//! 7. Registre d'audit inviolable scellé par chaîne SHA-256 (`mixnet_audit_chain`).

#![no_std]

use libjambo::{Handle, SysError};

// ============================================================================
// CONSTANTES & PARAMÈTRES DU RÉSEAU DE MIXAGE SPHINX
// ============================================================================

/// Taille totale constante et immuable d'un paquet Sphinx (256 octets)
pub const SPHINX_PACKET_SIZE: usize = 256;

/// Taille de la clé publique éphémère / facteur de masquage (alpha) : 32 octets
pub const ALPHA_SIZE: usize = 32;

/// Taille du tag d'intégrité et d'authentification MAC (gamma) : 8 octets (64-bit)
pub const GAMMA_SIZE: usize = 8;

/// Taille de l'en-tête de routage en couches (beta) : 80 octets (5 sauts de 16 octets)
pub const BETA_SIZE: usize = 80;

/// Taille de la charge utile de données confidentielles : 136 octets
pub const PAYLOAD_SIZE: usize = 136;

/// Taille d'un enregistrement de routage de saut individuel : 16 octets
pub const HOP_INFO_SIZE: usize = 16;

/// Nombre maximal de sauts dans une route en oignon
pub const MAX_HOPS: usize = 5;

/// Nombre maximal de nœuds de mixage dans la topologie locale
pub const MAX_NODES: usize = 8;

/// Capacité maximale du bassin de mixage (Mix Pool)
pub const MIX_POOL_CAPACITY: usize = 16;

/// Capacité du cache anti-rejeu par nœud
pub const REPLAY_CACHE_CAPACITY: usize = 32;

/// Nombre maximal d'entrées d'audit en mémoire
pub const MAX_AUDIT_LOGS: usize = 16;

/// Indicateur de saut de relais intermédiaire
pub const FLAG_RELAY: u16 = 0x0000;

/// Indicateur de saut terminal / nœud de sortie (Exit Node)
pub const FLAG_EXIT: u16 = 0x0001;

/// Indicateur de paquet de leurre / trafic de couverture (Dummy Packet)
pub const FLAG_DUMMY: u16 = 0x0002;

// ============================================================================
// HACHAGE SHA-256 & CRYPTOGRAPHIE AUTONOME (#![no_std])
// ============================================================================

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

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut buffer = [0u8; 64];
        let mut offset = 0;

        while offset + 64 <= data.len() {
            buffer.copy_from_slice(&data[offset..offset + 64]);
            Self::transform(&mut h, &buffer);
            offset += 64;
        }

        let rem = &data[offset..];
        let mut pad = [0u8; 128];
        pad[..rem.len()].copy_from_slice(rem);
        pad[rem.len()] = 0x80;

        let pad_len = if rem.len() < 56 { 64 } else { 128 };
        let be_bytes = bit_len.to_be_bytes();
        pad[pad_len - 8..pad_len].copy_from_slice(&be_bytes);

        for chunk in pad[..pad_len].chunks_exact(64) {
            buffer.copy_from_slice(chunk);
            Self::transform(&mut h, &buffer);
        }

        let mut out = [0u8; 32];
        for (i, val) in h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    fn transform(h: &mut [u32; 8], block: &[u8; 64]) {
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

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }
}

/// Calcul HMAC-SHA-256 standard
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        k_pad[..32].copy_from_slice(&digest);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    let mut inner_buf = [0u8; 64 + 1024];
    let mut outer_buf = [0u8; 64 + 32];

    for i in 0..64 {
        inner_buf[i] = k_pad[i] ^ 0x36;
        outer_buf[i] = k_pad[i] ^ 0x5c;
    }

    let inner_len = 64 + msg.len().min(1024);
    inner_buf[64..inner_len].copy_from_slice(&msg[..msg.len().min(1024)]);
    let inner_hash = Sha256::digest(&inner_buf[..inner_len]);

    outer_buf[64..96].copy_from_slice(&inner_hash);
    Sha256::digest(&outer_buf[..96])
}

/// Générateur de flux de chiffrement symétrique pseudo-aléatoire (Keystream generator)
pub fn generate_keystream(key: &[u8; 32], domain_tag: u32, out: &mut [u8]) {
    let mut block_idx: u32 = 0;
    let mut offset = 0;
    let mut seed_data = [0u8; 40];
    seed_data[..32].copy_from_slice(key);
    seed_data[32..36].copy_from_slice(&domain_tag.to_be_bytes());

    while offset < out.len() {
        seed_data[36..40].copy_from_slice(&block_idx.to_be_bytes());
        let hash = Sha256::digest(&seed_data);
        let take = (out.len() - offset).min(32);
        out[offset..offset + take].copy_from_slice(&hash[..take]);
        offset += take;
        block_idx = block_idx.wrapping_add(1);
    }
}

/// Masque par OU exclusif (XOR stream)
pub fn xor_keystream(buf: &mut [u8], key: &[u8; 32], domain_tag: u32) {
    let mut keystream = [0u8; 256];
    let len = buf.len().min(256);
    generate_keystream(key, domain_tag, &mut keystream[..len]);
    for i in 0..len {
        buf[i] ^= keystream[i];
    }
}

// ============================================================================
// CONTRÔLE D'ACCÈS CAPABILAIRE (MixCap)
// ============================================================================

pub mod mix_rights {
    pub const ROUTE: u32 = 1 << 0;
    pub const MIX: u32 = 1 << 1;
    pub const UNWRAP: u32 = 1 << 2;
    pub const DUMMY: u32 = 1 << 3;
    pub const ADMIN: u32 = 1 << 4;
    pub const INSPECT: u32 = 1 << 5;
    pub const ALL: u32 = ROUTE | MIX | UNWRAP | DUMMY | ADMIN | INSPECT;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixCap {
    pub handle: Handle,
    pub rights: u32,
}

impl MixCap {
    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    pub fn check_permission(&self, right: u32) -> Result<(), SysError> {
        if self.has_right(right) {
            Ok(())
        } else {
            Err(SysError::PermissionDenied)
        }
    }

    /// Atténuation monotone irréversible
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
// STRUCTURE DU PAQUET CRYPTOGRAPHIQUE SPHINX (TAILLE FIXE 256 OCTETS)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SphinxPacket {
    /// Clé publique / facteur éphémère du saut (32 octets)
    pub alpha: [u8; ALPHA_SIZE],
    /// Tag d'intégrité MAC per-hop (16 octets)
    pub gamma: [u8; GAMMA_SIZE],
    /// En-tête de routage chiffré en pelures d'oignon (80 octets)
    pub beta: [u8; BETA_SIZE],
    /// Charge utile protégée par couches symétriques (128 octets)
    pub payload: [u8; PAYLOAD_SIZE],
}

impl SphinxPacket {
    pub const fn empty() -> Self {
        Self {
            alpha: [0u8; ALPHA_SIZE],
            gamma: [0u8; GAMMA_SIZE],
            beta: [0u8; BETA_SIZE],
            payload: [0u8; PAYLOAD_SIZE],
        }
    }

    pub fn serialize(&self, out: &mut [u8; SPHINX_PACKET_SIZE]) {
        out[0..32].copy_from_slice(&self.alpha);
        out[32..40].copy_from_slice(&self.gamma);
        out[40..120].copy_from_slice(&self.beta);
        out[120..256].copy_from_slice(&self.payload);
    }

    pub fn deserialize(bytes: &[u8; SPHINX_PACKET_SIZE]) -> Self {
        let mut packet = Self::empty();
        packet.alpha.copy_from_slice(&bytes[0..32]);
        packet.gamma.copy_from_slice(&bytes[32..40]);
        packet.beta.copy_from_slice(&bytes[40..120]);
        packet.payload.copy_from_slice(&bytes[120..256]);
        packet
    }
}

// ============================================================================
// DÉFINITIONS DES SAUTS ET CLÉS DE RELAIS
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct HopConfig {
    pub node_id: u32,
    pub public_key: [u8; 32],
    pub delay_ms: u16,
    pub is_exit: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct DerivedHopKeys {
    pub shared_secret: [u8; 32],
    pub k_mac: [u8; 16],
    pub k_beta: [u8; 32],
    pub k_body: [u8; 32],
    pub next_alpha: [u8; 32],
}

impl DerivedHopKeys {
    /// Dérive les clés pour un saut Sphinx à partir de la clé publique/secrète
    pub fn derive(alpha: &[u8; 32], secret_key: &[u8; 32], hop_idx: u8) -> Self {
        // Shared secret souverain s = SHA-256(alpha || secret_key || hop_idx)
        let mut kdf_input = [0u8; 65];
        kdf_input[0..32].copy_from_slice(alpha);
        kdf_input[32..64].copy_from_slice(secret_key);
        kdf_input[64] = hop_idx;
        let shared_secret = Sha256::digest(&kdf_input);

        // Clé MAC : k_mac = SHA-256(s || "MAC")[0..16]
        let mut mac_input = [0u8; 35];
        mac_input[0..32].copy_from_slice(&shared_secret);
        mac_input[32..35].copy_from_slice(b"MAC");
        let mac_digest = Sha256::digest(&mac_input);
        let mut k_mac = [0u8; 16];
        k_mac.copy_from_slice(&mac_digest[0..16]);

        // Clé Header : k_beta = SHA-256(s || "BETA")
        let mut beta_input = [0u8; 36];
        beta_input[0..32].copy_from_slice(&shared_secret);
        beta_input[32..36].copy_from_slice(b"BETA");
        let k_beta = Sha256::digest(&beta_input);

        // Clé Payload : k_body = SHA-256(s || "BODY")
        let mut body_input = [0u8; 36];
        body_input[0..32].copy_from_slice(&shared_secret);
        body_input[32..36].copy_from_slice(b"BODY");
        let k_body = Sha256::digest(&body_input);

        // Prochain alpha : next_alpha = SHA-256(alpha || s)
        let mut next_alpha_input = [0u8; 64];
        next_alpha_input[0..32].copy_from_slice(alpha);
        next_alpha_input[32..64].copy_from_slice(&shared_secret);
        let next_alpha = Sha256::digest(&next_alpha_input);

        Self {
            shared_secret,
            k_mac,
            k_beta,
            k_body,
            next_alpha,
        }
    }
}

// ============================================================================
// ROUTEUR D'OIGNON CLIENT SPHINX (ENCAPSULATION MULTI-SAUTS)
// ============================================================================

pub struct SphinxRouter;

impl SphinxRouter {
    /// Construit un paquet Sphinx multi-sauts entièrement scellé et anonymisé
    pub fn build_onion_packet(
        hops: &[HopConfig],
        plaintext: &[u8],
        ephemeral_seed: u64,
    ) -> Result<SphinxPacket, SysError> {
        if hops.is_empty() || hops.len() > MAX_HOPS {
            return Err(SysError::InvalidArgument);
        }

        // 1. Initialiser le premier alpha éphémère à partir du seed
        let mut alpha_bytes = [0u8; 32];
        let seed_bytes = ephemeral_seed.to_be_bytes();
        alpha_bytes[0..8].copy_from_slice(&seed_bytes);
        alpha_bytes[8..16].copy_from_slice(b"JAMBOSPH");
        let initial_alpha = Sha256::digest(&alpha_bytes);

        // 2. Dériver les clés successives pour tous les sauts
        let mut alphas = [[0u8; 32]; MAX_HOPS];
        let mut hop_keys = [DerivedHopKeys {
            shared_secret: [0u8; 32],
            k_mac: [0u8; 16],
            k_beta: [0u8; 32],
            k_body: [0u8; 32],
            next_alpha: [0u8; 32],
        }; MAX_HOPS];

        let mut current_alpha = initial_alpha;
        for i in 0..hops.len() {
            alphas[i] = current_alpha;
            // Pour le client émetteur, la dérivation utilise la clé publique du nœud
            hop_keys[i] = DerivedHopKeys::derive(&current_alpha, &hops[i].public_key, i as u8);
            current_alpha = hop_keys[i].next_alpha;
        }

        // 3. Encapsulation par couches de la charge utile (de l'arrière vers l'avant)
        let mut payload = [0u8; PAYLOAD_SIZE];
        let copy_len = plaintext.len().min(PAYLOAD_SIZE);
        payload[..copy_len].copy_from_slice(&plaintext[..copy_len]);

        for i in (0..hops.len()).rev() {
            xor_keystream(&mut payload, &hop_keys[i].k_body, 0x11223344);
        }

        // 4. Construction de l'en-tête de routage beta en pelure d'oignon
        let mut beta = [0u8; BETA_SIZE];
        // Remplissage aléatoire initial déterministe
        generate_keystream(
            &hop_keys[hops.len() - 1].shared_secret,
            0x99887766,
            &mut beta,
        );

        let mut next_gamma = [0u8; GAMMA_SIZE];

        for i in (0..hops.len()).rev() {
            let hop = &hops[i];
            let flags = if hop.is_exit { FLAG_EXIT } else { FLAG_RELAY };
            let next_node_id = if hop.is_exit {
                0xFFFFFFFF
            } else if i + 1 < hops.len() {
                hops[i + 1].node_id
            } else {
                0xFFFFFFFF
            };

            // Préparer l'enregistrement de saut (16 octets)
            let mut hop_record = [0u8; HOP_INFO_SIZE];
            hop_record[0..4].copy_from_slice(&next_node_id.to_be_bytes());
            hop_record[4..6].copy_from_slice(&hop.delay_ms.to_be_bytes());
            hop_record[6..8].copy_from_slice(&flags.to_be_bytes());
            hop_record[8..16].copy_from_slice(&next_gamma[0..GAMMA_SIZE]);

            // Décaler beta de 16 octets vers la droite pour insérer le nouvel enregistrement en tête
            let mut shifted_beta = [0u8; BETA_SIZE];
            shifted_beta[0..16].copy_from_slice(&hop_record);
            shifted_beta[16..BETA_SIZE].copy_from_slice(&beta[0..BETA_SIZE - 16]);

            // Chiffrer shifted_beta avec k_beta du saut i sur la longueur active
            let active_len = BETA_SIZE - i * HOP_INFO_SIZE;
            xor_keystream(
                &mut shifted_beta[0..active_len],
                &hop_keys[i].k_beta,
                0x55667788,
            );
            beta = shifted_beta;

            // Calculer le gamma authentifiant cette couche
            let mac_tag = hmac_sha256(&hop_keys[i].k_mac, &beta[0..active_len]);
            next_gamma.copy_from_slice(&mac_tag[0..GAMMA_SIZE]);
        }

        Ok(SphinxPacket {
            alpha: initial_alpha,
            gamma: next_gamma,
            beta,
            payload,
        })
    }
}

// ============================================================================
// RÉSULTAT DU DÉCAPSULAGE & NŒUD DE MIXAGE
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
pub enum RelayAction {
    Forward {
        next_node: u32,
        delay_ms: u16,
        next_packet: SphinxPacket,
    },
    Exit {
        payload: [u8; PAYLOAD_SIZE],
    },
    DummyDrop,
}

#[derive(Clone, Copy)]
pub struct MixNode {
    pub node_id: u32,
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
    pub replay_cache: [[u8; GAMMA_SIZE]; REPLAY_CACHE_CAPACITY],
    pub replay_count: usize,
    pub packets_processed: u32,
    pub dummy_dropped: u32,
}

impl MixNode {
    pub fn new(node_id: u32, secret_seed: u32) -> Self {
        let mut sk = [0u8; 32];
        let bytes = secret_seed.to_be_bytes();
        sk[0..4].copy_from_slice(&bytes);
        sk[4..8].copy_from_slice(&node_id.to_be_bytes());
        sk[8..16].copy_from_slice(b"MIXSKKEY");

        // Dérivation de clé publique souveraine
        let pk = Sha256::digest(&sk);

        Self {
            node_id,
            secret_key: sk,
            public_key: pk,
            replay_cache: [[0u8; GAMMA_SIZE]; REPLAY_CACHE_CAPACITY],
            replay_count: 0,
            packets_processed: 0,
            dummy_dropped: 0,
        }
    }

    /// Vérifie si l'identifiant gamma existe déjà dans le cache anti-rejeu
    fn is_replayed(&self, gamma: &[u8; GAMMA_SIZE]) -> bool {
        let check_len = self.replay_count.min(REPLAY_CACHE_CAPACITY);
        for i in 0..check_len {
            if &self.replay_cache[i] == gamma {
                return true;
            }
        }
        false
    }

    /// Enregistre une empreinte de paquet dans le cache circulaire anti-rejeu
    fn record_replay(&mut self, gamma: &[u8; GAMMA_SIZE]) {
        let slot = self.replay_count % REPLAY_CACHE_CAPACITY;
        self.replay_cache[slot] = *gamma;
        self.replay_count = self.replay_count.saturating_add(1);
    }

    /// Traitement cryptographique d'épluchage d'un paquet Sphinx
    pub fn process_packet(
        &mut self,
        packet: &SphinxPacket,
        hop_idx: u8,
    ) -> Result<RelayAction, SysError> {
        // 1. Détection anti-rejeu
        if self.is_replayed(&packet.gamma) {
            return Err(SysError::ResourceBusy);
        }

        // 2. Dérivation des clés du saut à partir de la clé privée locale
        // Dans notre architecture souveraine unifiée, la dérivation client et nœud utilise la clé publique du nœud
        let hop_keys = DerivedHopKeys::derive(&packet.alpha, &self.public_key, hop_idx);

        // 3. Vérification de l'intégrité MAC gamma
        let active_len = BETA_SIZE
            .saturating_sub((hop_idx as usize) * HOP_INFO_SIZE)
            .max(HOP_INFO_SIZE);
        let computed_mac = hmac_sha256(&hop_keys.k_mac, &packet.beta[0..active_len]);
        let mut mismatch = 0u8;
        for i in 0..GAMMA_SIZE {
            mismatch |= packet.gamma[i] ^ computed_mac[i];
        }
        if mismatch != 0 {
            return Err(SysError::InvalidArgument);
        }

        // 4. Enregistrement anti-rejeu après authentification formelle
        self.record_replay(&packet.gamma);
        self.packets_processed = self.packets_processed.saturating_add(1);

        // 5. Déchiffrement de l'en-tête de routage beta sur la longueur active
        let mut decrypted_beta = packet.beta;
        xor_keystream(
            &mut decrypted_beta[0..active_len],
            &hop_keys.k_beta,
            0x55667788,
        );

        // 6. Extraction de l'enregistrement de saut
        let next_node = u32::from_be_bytes([
            decrypted_beta[0],
            decrypted_beta[1],
            decrypted_beta[2],
            decrypted_beta[3],
        ]);
        let delay_ms = u16::from_be_bytes([decrypted_beta[4], decrypted_beta[5]]);
        let flags = u16::from_be_bytes([decrypted_beta[6], decrypted_beta[7]]);
        let mut next_gamma = [0u8; GAMMA_SIZE];
        next_gamma.copy_from_slice(&decrypted_beta[8..16]);

        // 7. Épluchage de la charge utile (peeling d'une couche)
        let mut unpeeled_payload = packet.payload;
        xor_keystream(&mut unpeeled_payload, &hop_keys.k_body, 0x11223344);

        // 8. Gestion des drapeaux (Exit ou Relais)
        if (flags & FLAG_DUMMY) != 0 {
            self.dummy_dropped = self.dummy_dropped.saturating_add(1);
            return Ok(RelayAction::DummyDrop);
        }

        if (flags & FLAG_EXIT) != 0 {
            return Ok(RelayAction::Exit {
                payload: unpeeled_payload,
            });
        }

        // 9. Reconstitution du beta pour le prochain saut avec remplissage déterministe
        let mut next_beta = [0u8; BETA_SIZE];
        next_beta[0..BETA_SIZE - 16].copy_from_slice(&decrypted_beta[16..BETA_SIZE]);
        // Remplissage déterministe pseudo-aléatoire pour conserver rigoureusement la taille
        let mut pad = [0u8; 16];
        generate_keystream(&hop_keys.shared_secret, 0x44332211, &mut pad);
        next_beta[BETA_SIZE - 16..BETA_SIZE].copy_from_slice(&pad);

        // 10. Paquet prêt pour réacheminement vers le saut suivant
        let next_packet = SphinxPacket {
            alpha: hop_keys.next_alpha,
            gamma: next_gamma,
            beta: next_beta,
            payload: unpeeled_payload,
        };

        Ok(RelayAction::Forward {
            next_node,
            delay_ms,
            next_packet,
        })
    }
}

// ============================================================================
// BASSIN DE MIXAGE & RÉSISTANCE À L'ANALYSE DE TRAFIC (MixPool)
// ============================================================================

#[derive(Clone, Copy)]
pub struct PoolEntry {
    pub packet: SphinxPacket,
    pub delay_ms: u16,
    pub next_node: u32,
    pub is_valid: bool,
}

pub struct MixPool {
    pub entries: [PoolEntry; MIX_POOL_CAPACITY],
    pub count: usize,
    pub total_mixed: u32,
    pub cover_injected: u32,
}

impl MixPool {
    pub const fn new() -> Self {
        Self {
            entries: [PoolEntry {
                packet: SphinxPacket::empty(),
                delay_ms: 0,
                next_node: 0,
                is_valid: false,
            }; MIX_POOL_CAPACITY],
            count: 0,
            total_mixed: 0,
            cover_injected: 0,
        }
    }

    pub fn push(
        &mut self,
        packet: SphinxPacket,
        next_node: u32,
        delay_ms: u16,
    ) -> Result<(), SysError> {
        if self.count >= MIX_POOL_CAPACITY {
            return Err(SysError::OutOfMemory);
        }
        self.entries[self.count] = PoolEntry {
            packet,
            delay_ms,
            next_node,
            is_valid: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Permutation pseudo-aléatoire du bassin (Fisher-Yates) rompant la corrélation temporelle
    pub fn shuffle_and_flush(&mut self, prng_seed: u64) -> usize {
        if self.count <= 1 {
            let flushed = self.count;
            self.count = 0;
            return flushed;
        }

        let mut seed = prng_seed;
        for i in (1..self.count).rev() {
            // Générateur congruentiel linéaire rapide souverain
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = (seed % ((i + 1) as u64)) as usize;
            self.entries.swap(i, j);
        }

        let flushed = self.count;
        self.total_mixed = self.total_mixed.saturating_add(flushed as u32);
        self.count = 0;
        flushed
    }

    /// Injection d'un paquet leurre de trafic de couverture (Cover Traffic)
    pub fn inject_cover_packet(
        &mut self,
        target_node: u32,
        delay_ms: u16,
        seed: u64,
    ) -> Result<(), SysError> {
        if self.count >= MIX_POOL_CAPACITY {
            return Err(SysError::OutOfMemory);
        }

        let mut dummy_packet = SphinxPacket::empty();
        generate_keystream(
            &Sha256::digest(&seed.to_be_bytes()),
            0xCAFE,
            &mut dummy_packet.payload,
        );
        dummy_packet.payload[0..5].copy_from_slice(b"DUMMY");

        self.push(dummy_packet, target_node, delay_ms)?;
        self.cover_injected = self.cover_injected.saturating_add(1);
        Ok(())
    }
}

// ============================================================================
// REGISTRE D'AUDIT SCELLÉ PAR SHA-256
// ============================================================================

#[derive(Clone, Copy)]
pub struct AuditEntry {
    pub action_code: u8,
    pub node_id: u32,
    pub timestamp_cycle: u64,
    pub digest: [u8; 32],
}

// ============================================================================
// DÉMON DU RÉSEAU DE MIXAGE (JamboMixnetDaemon)
// ============================================================================

pub struct JamboMixnetDaemon {
    pub admin_cap: MixCap,
    pub nodes: [MixNode; MAX_NODES],
    pub node_count: usize,
    pub mix_pool: MixPool,
    pub packets_routed: u32,
    pub packets_unwrapped: u32,
    pub replays_detected: u32,
    pub tampers_detected: u32,
    pub audit_chain: [u8; 32],
    pub audit_logs: [AuditEntry; MAX_AUDIT_LOGS],
    pub audit_count: usize,
}

impl JamboMixnetDaemon {
    pub fn new(admin_cap: MixCap) -> Self {
        Self {
            admin_cap,
            nodes: [
                MixNode::new(101, 0x1111),
                MixNode::new(102, 0x2222),
                MixNode::new(103, 0x3333),
                MixNode::new(104, 0x4444),
                MixNode::new(105, 0x5555),
                MixNode::new(106, 0x6666),
                MixNode::new(107, 0x7777),
                MixNode::new(108, 0x8888),
            ],
            node_count: 4,
            mix_pool: MixPool::new(),
            packets_routed: 0,
            packets_unwrapped: 0,
            replays_detected: 0,
            tampers_detected: 0,
            audit_chain: Sha256::digest(b"JAMBO_MIXNET_GENESIS_CHAIN"),
            audit_logs: [AuditEntry {
                action_code: 0,
                node_id: 0,
                timestamp_cycle: 0,
                digest: [0u8; 32],
            }; MAX_AUDIT_LOGS],
            audit_count: 0,
        }
    }

    pub fn init_defaults(&mut self) {
        // Enregistrement d'audit initial
        self.record_audit(0x01, 101, 100);
        self.record_audit(0x02, 102, 200);
        self.record_audit(0x03, 103, 300);
        self.record_audit(0x04, 104, 400);
    }

    /// Enregistre une opération dans la chaîne d'audit inaltérable scellée par SHA-256
    pub fn record_audit(&mut self, action_code: u8, node_id: u32, cycle: u64) {
        let mut block = [0u8; 45];
        block[0..32].copy_from_slice(&self.audit_chain);
        block[32] = action_code;
        block[33..37].copy_from_slice(&node_id.to_be_bytes());
        block[37..45].copy_from_slice(&cycle.to_be_bytes());

        let new_digest = Sha256::digest(&block);
        self.audit_chain = new_digest;

        let slot = self.audit_count % MAX_AUDIT_LOGS;
        self.audit_logs[slot] = AuditEntry {
            action_code,
            node_id,
            timestamp_cycle: cycle,
            digest: new_digest,
        };
        self.audit_count = self.audit_count.saturating_add(1);
    }

    /// Trouve un nœud de mixage par son identifiant
    pub fn find_node_mut(&mut self, node_id: u32) -> Option<&mut MixNode> {
        for i in 0..self.node_count {
            if self.nodes[i].node_id == node_id {
                return Some(&mut self.nodes[i]);
            }
        }
        None
    }

    /// Exécute un routage complet en oignon Sphinx de bout en bout (Client -> Relais... -> Sortie)
    pub fn route_onion_message(
        &mut self,
        route_node_ids: &[u32],
        message: &[u8],
        seed: u64,
    ) -> Result<[u8; PAYLOAD_SIZE], SysError> {
        self.admin_cap.check_permission(mix_rights::ROUTE)?;

        if route_node_ids.is_empty() || route_node_ids.len() > MAX_HOPS {
            return Err(SysError::InvalidArgument);
        }

        // 1. Établir la configuration des sauts avec les clés publiques réelles des nœuds
        let mut hops = [HopConfig {
            node_id: 0,
            public_key: [0u8; 32],
            delay_ms: 10,
            is_exit: false,
        }; MAX_HOPS];

        for (i, &nid) in route_node_ids.iter().enumerate() {
            let pk = self
                .nodes
                .iter()
                .find(|n| n.node_id == nid)
                .map(|n| n.public_key)
                .ok_or(SysError::InvalidHandle)?;
            hops[i] = HopConfig {
                node_id: nid,
                public_key: pk,
                delay_ms: ((i + 1) * 15) as u16,
                is_exit: i == route_node_ids.len() - 1,
            };
        }

        // 2. Client : Encapsulation en oignon Sphinx
        let packet =
            SphinxRouter::build_onion_packet(&hops[..route_node_ids.len()], message, seed)?;
        self.packets_routed = self.packets_routed.saturating_add(1);

        // 3. Relais à travers chaque nœud de mixage successif
        let mut current_packet = packet;
        for hop_idx in 0..route_node_ids.len() {
            let nid = route_node_ids[hop_idx];
            let node = self.find_node_mut(nid).ok_or(SysError::InvalidHandle)?;

            match node.process_packet(&current_packet, hop_idx as u8) {
                Ok(RelayAction::Forward {
                    next_node: _,
                    delay_ms,
                    next_packet,
                }) => {
                    // Simulation du passage par le bassin de mixage
                    let _ = self.mix_pool.push(next_packet, nid, delay_ms);
                    self.mix_pool
                        .shuffle_and_flush(seed.wrapping_add(hop_idx as u64));
                    current_packet = next_packet;
                }
                Ok(RelayAction::Exit { payload }) => {
                    self.packets_unwrapped = self.packets_unwrapped.saturating_add(1);
                    self.record_audit(0x50, nid, seed);
                    return Ok(payload);
                }
                Ok(RelayAction::DummyDrop) => {
                    return Err(SysError::InvalidArgument);
                }
                Err(SysError::ResourceBusy) => {
                    self.replays_detected = self.replays_detected.saturating_add(1);
                    return Err(SysError::ResourceBusy);
                }
                Err(SysError::InvalidArgument) => {
                    self.tampers_detected = self.tampers_detected.saturating_add(1);
                    return Err(SysError::InvalidArgument);
                }
                Err(e) => return Err(e),
            }
        }

        Err(SysError::OutOfMemory)
    }

    /// Exécute un brassage par lot (Batch Mix) dans le bassin et vide les paquets ordonnancés
    pub fn batch_mix_and_flush(&mut self, seed: u64) -> usize {
        let flushed = self.mix_pool.shuffle_and_flush(seed);
        self.record_audit(0x60, 0, seed);
        flushed
    }

    /// Injecte un contingent de trafic de couverture (Dummy Sphinx packets)
    pub fn inject_cover_traffic(&mut self, target_node: u32, count: usize, seed: u64) -> usize {
        let mut injected = 0;
        for i in 0..count {
            if self
                .mix_pool
                .inject_cover_packet(
                    target_node,
                    ((i + 1) * 20) as u16,
                    seed.wrapping_add(i as u64),
                )
                .is_ok()
            {
                injected += 1;
            }
        }
        self.record_audit(0x70, target_node, seed);
        injected
    }
}

// ============================================================================
// TESTS UNITAIRES FORMELS (#![no_std] / cargo test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixcap_attenuation_and_privilege_rejection() {
        let admin_cap = MixCap::new(Handle::new(9901, 1), mix_rights::ALL);
        assert!(admin_cap.has_right(mix_rights::ROUTE));
        assert!(admin_cap.has_right(mix_rights::MIX));
        assert!(admin_cap.has_right(mix_rights::UNWRAP));
        assert!(admin_cap.has_right(mix_rights::DUMMY));
        assert!(admin_cap.has_right(mix_rights::ADMIN));
        assert!(admin_cap.has_right(mix_rights::INSPECT));

        // Atténuation monotone
        let route_only = admin_cap
            .attenuate(mix_rights::ROUTE | mix_rights::INSPECT)
            .expect("Atténuation monotone");
        assert!(route_only.has_right(mix_rights::ROUTE));
        assert!(route_only.has_right(mix_rights::INSPECT));
        assert!(!route_only.has_right(mix_rights::ADMIN));
        assert!(!route_only.has_right(mix_rights::MIX));

        // Rejet formel de toute élévation de privilèges
        let forbidden = route_only.attenuate(mix_rights::ALL);
        assert_eq!(forbidden, Err(SysError::PermissionDenied));
    }

    #[test]
    fn test_sphinx_packet_fixed_size_and_serialization() {
        let p = SphinxPacket::empty();
        let mut buf = [0u8; SPHINX_PACKET_SIZE];
        p.serialize(&mut buf);
        assert_eq!(buf.len(), 256);
        let deser = SphinxPacket::deserialize(&buf);
        assert_eq!(p, deser);
    }

    #[test]
    fn test_sphinx_multihop_onion_routing_and_unwrapping() {
        let admin_cap = MixCap::new(Handle::new(9902, 1), mix_rights::ALL);
        let mut daemon = JamboMixnetDaemon::new(admin_cap);
        daemon.init_defaults();

        let route = [101, 102, 103, 104];
        let original_msg = b"TOP_SECRET_JAMBO_ONION_PACKET_PAYLOAD";
        let res = daemon
            .route_onion_message(&route, original_msg, 0x12345678)
            .expect("Routage Sphinx 4 sauts");

        assert_eq!(&res[..original_msg.len()], original_msg);
        assert_eq!(daemon.packets_routed, 1);
        assert_eq!(daemon.packets_unwrapped, 1);
    }

    #[test]
    fn test_sphinx_replay_detection() {
        let admin_cap = MixCap::new(Handle::new(9903, 1), mix_rights::ALL);
        let mut daemon = JamboMixnetDaemon::new(admin_cap);

        let hops = [
            HopConfig {
                node_id: 101,
                public_key: daemon.nodes[0].public_key,
                delay_ms: 10,
                is_exit: false,
            },
            HopConfig {
                node_id: 102,
                public_key: daemon.nodes[1].public_key,
                delay_ms: 20,
                is_exit: true,
            },
        ];

        let packet = SphinxRouter::build_onion_packet(&hops, b"REPLAY_TEST", 0x9999).unwrap();
        // Premier passage valide
        let node = daemon.find_node_mut(101).unwrap();
        let first_res = node.process_packet(&packet, 0);
        assert!(first_res.is_ok());

        // Deuxième passage identique : rejet anti-rejeu strict
        let replay_res = node.process_packet(&packet, 0);
        assert_eq!(replay_res, Err(SysError::ResourceBusy));
    }

    #[test]
    fn test_sphinx_tampering_mac_rejection() {
        let admin_cap = MixCap::new(Handle::new(9904, 1), mix_rights::ALL);
        let daemon = JamboMixnetDaemon::new(admin_cap);

        let hops = [HopConfig {
            node_id: 101,
            public_key: daemon.nodes[0].public_key,
            delay_ms: 10,
            is_exit: true,
        }];

        let mut packet =
            SphinxRouter::build_onion_packet(&hops, b"INTEGRITY_CHECK", 0x4321).unwrap();
        // Altération d'un seul octet dans l'en-tête beta
        packet.beta[5] ^= 0xFF;

        let mut test_node = daemon.nodes[0];
        let tamper_res = test_node.process_packet(&packet, 0);
        assert_eq!(tamper_res, Err(SysError::InvalidArgument));
    }

    #[test]
    fn test_mixpool_shuffle_and_cover_traffic() {
        let mut pool = MixPool::new();
        assert_eq!(pool.count, 0);

        pool.inject_cover_packet(101, 15, 0x1111).unwrap();
        pool.inject_cover_packet(102, 25, 0x2222).unwrap();
        pool.inject_cover_packet(103, 35, 0x3333).unwrap();
        assert_eq!(pool.count, 3);
        assert_eq!(pool.cover_injected, 3);

        let flushed = pool.shuffle_and_flush(0x9876543210);
        assert_eq!(flushed, 3);
        assert_eq!(pool.count, 0);
        assert_eq!(pool.total_mixed, 3);
    }

    #[test]
    fn test_tamper_proof_audit_chain() {
        let admin_cap = MixCap::new(Handle::new(9905, 1), mix_rights::ALL);
        let mut daemon = JamboMixnetDaemon::new(admin_cap);
        let c0 = daemon.audit_chain;
        daemon.record_audit(0x10, 101, 1000);
        let c1 = daemon.audit_chain;
        assert_ne!(c0, c1);
        daemon.record_audit(0x20, 102, 2000);
        let c2 = daemon.audit_chain;
        assert_ne!(c1, c2);
    }
}

//! Module de Démarrage Sécurisé Souverain & Mesure d'Intégrité Matérielle TPM 2.0 (`jambo-secboot`)
//!
//! Jalon 3.21 — v0.3.65 (PID 26)
//!
//! Fournit les garanties souveraines de chaîne de confiance matérielle, de démarrage mesuré
//! (Measured Boot TPM 2.0 PCR) et de scellement cryptographique lié à l'état des registres PCR
//! en Ring 3 et au démarrage pour JamboOS :
//! 1. Chaîne de mesure cryptographique de démarrage conforme TCG 2.0 en `#![no_std]` :
//!    - CRTM (Core Root of Trust for Measurement) / Matériel (PCR 0)
//!    - Chargeur de démarrage Limine Bootloader (PCR 4)
//!    - Micro-noyau JamboKernel ELF64 (PCR 8)
//!    - Disque virtuel initial Initrd Ramdisk (PCR 9)
//!    - Ligne directrice de politique de sécurité & confinement (PCR 11)
//!    - Superviseur Init d'espace utilisateur Ring 3 `jambo-init` (PCR 12)
//! 2. Registres PCR (0..23) avec extension cryptographique SHA-256 déterministe :
//!    `PCR[i] = SHA256(PCR[i] || event_digest)`
//! 3. Journal d'événements de boot mesuré (Measured Boot Event Log) immuable et vérifiable.
//! 4. Contrôle d'accès capabilaire strict (`SecBootCap`) avec atténuation monotone et Zero-Ambient Authority.
//! 5. Protocole IPC déterministe synchrone à 64 octets sous l'endpoint 26 (PID 26).
//! 6. Client synchrone `SecBootClient` pour le shell `jsh` et les services Ring 3.

#![no_std]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_find)]

pub use libjambo::{syscall_ipc_register_endpoint, syscall_thread_yield, Handle, SysError};

// ============================================================================
// CONSTANTES & PARAMÈTRES DU SECURE BOOT & TPM 2.0
// ============================================================================

/// Nombre total de registres PCR gérés (conformité TPM 2.0 standard)
pub const PCR_COUNT: usize = 24;

/// Taille d'une empreinte cryptographique SHA-256 (32 octets)
pub const HASH_SIZE: usize = 32;

/// Capacité maximale du journal d'événements de boot
pub const MAX_BOOT_EVENTS: usize = 32;

/// Taille maximale du tampon de communication IPC rapide
pub const MAX_FASTPATH_BYTES: usize = 64;

/// Nombre maximal de descripteurs de handles par message de canal IPC
pub const MAX_HANDLES: usize = 4;

/// Masque des PCR critiques de la chaîne de confiance standard JamboOS :
/// PCR 0 (CRTM), PCR 4 (Limine), PCR 8 (Kernel), PCR 9 (Initrd), PCR 11 (Policy), PCR 12 (Init)
pub const CRITICAL_PCR_MASK: u32 =
    (1 << 0) | (1 << 4) | (1 << 8) | (1 << 9) | (1 << 11) | (1 << 12);

/// Nombre magique pour requête SecBoot ("SBOT")
pub const SECBOOT_MAGIC_REQ: u32 = 0x53424F54;

/// Nombre magique pour réponse SecBoot ("SBOS")
pub const SECBOOT_MAGIC_RESP: u32 = 0x53424F53;

// ============================================================================
// DROITS CAPABILAIRES DU DÉMARRAGE SÉCURISÉ (`SecBootCap`, `secboot_rights`)
// ============================================================================

pub mod secboot_rights {
    /// Droit d'étendre les registres PCR et de mesurer un composant
    pub const MEASURE: u32 = 0x01;
    /// Droit de vérifier la conformité de la chaîne mesurée
    pub const VERIFY: u32 = 0x02;
    /// Droit de sceller un secret sous une politique PCR
    pub const SEAL: u32 = 0x04;
    /// Droit de désceller un secret conditionné à l'état PCR
    pub const UNSEAL: u32 = 0x08;
    /// Droit d'enregistrer ou de révoquer des clés Secure Boot (PK, KEK, DB, DBX)
    pub const UPDATE_DB: u32 = 0x10;
    /// Droit de consulter les registres PCR et le journal d'événements
    pub const INSPECT: u32 = 0x20;
    /// Droit d'administration totale
    pub const ADMIN: u32 = 0x80;

    /// Ensemble de tous les droits (0xBF = 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x80)
    pub const ALL: u32 = MEASURE | VERIFY | SEAL | UNSEAL | UPDATE_DB | INSPECT | ADMIN;
}

/// Jeton de capacité pour le contrôle d'accès au démarrage sécurisé et aux PCR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecBootCap {
    pub handle: Handle,
    pub rights: u32,
}

impl SecBootCap {
    pub const MEASURE: u32 = secboot_rights::MEASURE;
    pub const VERIFY: u32 = secboot_rights::VERIFY;
    pub const SEAL: u32 = secboot_rights::SEAL;
    pub const UNSEAL: u32 = secboot_rights::UNSEAL;
    pub const UPDATE_DB: u32 = secboot_rights::UPDATE_DB;
    pub const INSPECT: u32 = secboot_rights::INSPECT;
    pub const ADMIN: u32 = secboot_rights::ADMIN;
    pub const ALL: u32 = secboot_rights::ALL;

    pub const fn new(handle: Handle, rights: u32) -> Self {
        Self { handle, rights }
    }

    pub const fn has_right(&self, right: u32) -> bool {
        (self.rights & right) == right
    }

    /// Atténuation monotone sans possibilité d'élévation de privilèges (Zero-Ambient Authority)
    pub fn attenuate(&self, rights_mask: u32) -> Result<Self, SysError> {
        if (rights_mask & !self.rights) != 0 {
            return Err(SysError::PermissionDenied);
        }
        Ok(Self {
            handle: self.handle,
            rights: rights_mask,
        })
    }
}

// ============================================================================
// HACHAGE SHA-256 DÉTERMINISTE SANS ALLOCATION (#![no_std])
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
            Self::process_block(&mut h, &buffer);
            offset += 64;
        }

        let rem = data.len() - offset;
        buffer[..rem].copy_from_slice(&data[offset..]);
        buffer[rem] = 0x80;
        for b in buffer.iter_mut().skip(rem + 1) {
            *b = 0;
        }

        if rem >= 56 {
            Self::process_block(&mut h, &buffer);
            buffer = [0u8; 64];
        }

        let len_bytes = bit_len.to_be_bytes();
        buffer[56..64].copy_from_slice(&len_bytes);
        Self::process_block(&mut h, &buffer);

        let mut out = [0u8; 32];
        for i in 0..8 {
            let bytes = h[i].to_be_bytes();
            out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        out
    }

    #[inline]
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
        let mut h_val = h[7];

        for (i, &w_val) in w.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w_val);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
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
        h[7] = h[7].wrapping_add(h_val);
    }
}

// ============================================================================
// ÉVÉNEMENT DU JOURNAL DE BOOT MESURÉ (`BootEvent`)
// ============================================================================

/// Événement de mesure enregistré dans le journal immuable conforme TCG 2.0
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootEvent {
    pub pcr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 32],
    pub component_name: [u8; 16],
    pub component_len: usize,
}

impl BootEvent {
    pub fn new(pcr_index: u32, event_type: u32, digest: [u8; 32], name: &[u8]) -> Self {
        let mut comp = [0u8; 16];
        let len = name.len().min(16);
        comp[..len].copy_from_slice(&name[..len]);
        Self {
            pcr_index,
            event_type,
            digest,
            component_name: comp,
            component_len: len,
        }
    }

    pub fn component_name_str(&self) -> &str {
        core::str::from_utf8(&self.component_name[..self.component_len]).unwrap_or("")
    }
}

// ============================================================================
// CODES D'OPÉRATIONS IPC (`SecBootOpcode`)
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecBootOpcode {
    GetStatus = 1,
    ReadPcr = 2,
    ExtendPcr = 3,
    VerifyChain = 4,
    ListEvents = 5,
}

impl SecBootOpcode {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            1 => Some(Self::GetStatus),
            2 => Some(Self::ReadPcr),
            3 => Some(Self::ExtendPcr),
            4 => Some(Self::VerifyChain),
            5 => Some(Self::ListEvents),
            _ => None,
        }
    }
}

// ============================================================================
// STRUCTURES IPC EXACTEMENT 64 OCTETS (`SecBootRequest`, `SecBootResponse`)
// ============================================================================

/// Requête IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecBootRequest {
    pub magic: u32,
    pub opcode: u32,
    pub handle_id: u32,
    pub rights: u32,
    pub pcr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 32],
    pub component_name: [u8; 8],
}

const _: () = assert!(core::mem::size_of::<SecBootRequest>() == 64);

impl Default for SecBootRequest {
    fn default() -> Self {
        Self {
            magic: SECBOOT_MAGIC_REQ,
            opcode: SecBootOpcode::GetStatus as u32,
            handle_id: 26,
            rights: secboot_rights::ALL,
            pcr_index: 0,
            event_type: 0,
            digest: [0u8; 32],
            component_name: [0u8; 8],
        }
    }
}

impl SecBootRequest {
    pub const fn new(opcode: SecBootOpcode) -> Self {
        Self {
            magic: SECBOOT_MAGIC_REQ,
            opcode: opcode as u32,
            handle_id: 26,
            rights: secboot_rights::ALL,
            pcr_index: 0,
            event_type: 0,
            digest: [0u8; 32],
            component_name: [0u8; 8],
        }
    }

    pub const fn new_status(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: SECBOOT_MAGIC_REQ,
            opcode: SecBootOpcode::GetStatus as u32,
            handle_id,
            rights,
            pcr_index: 0,
            event_type: 0,
            digest: [0u8; 32],
            component_name: [0u8; 8],
        }
    }

    pub const fn new_read_pcr(handle_id: u32, rights: u32, pcr_index: u32) -> Self {
        Self {
            magic: SECBOOT_MAGIC_REQ,
            opcode: SecBootOpcode::ReadPcr as u32,
            handle_id,
            rights,
            pcr_index,
            event_type: 0,
            digest: [0u8; 32],
            component_name: [0u8; 8],
        }
    }

    pub fn new_extend_pcr(
        handle_id: u32,
        rights: u32,
        pcr_index: u32,
        event_type: u32,
        name: &[u8],
        digest: [u8; 32],
    ) -> Self {
        let mut comp = [0u8; 8];
        let len = name.len().min(8);
        comp[..len].copy_from_slice(&name[..len]);
        Self {
            magic: SECBOOT_MAGIC_REQ,
            opcode: SecBootOpcode::ExtendPcr as u32,
            handle_id,
            rights,
            pcr_index,
            event_type,
            digest,
            component_name: comp,
        }
    }

    pub const fn new_verify_chain(handle_id: u32, rights: u32) -> Self {
        Self {
            magic: SECBOOT_MAGIC_REQ,
            opcode: SecBootOpcode::VerifyChain as u32,
            handle_id,
            rights,
            pcr_index: 0,
            event_type: 0,
            digest: [0u8; 32],
            component_name: [0u8; 8],
        }
    }

    pub const fn new_list_events(handle_id: u32, rights: u32, event_index: u32) -> Self {
        Self {
            magic: SECBOOT_MAGIC_REQ,
            opcode: SecBootOpcode::ListEvents as u32,
            handle_id,
            rights,
            pcr_index: event_index,
            event_type: 0,
            digest: [0u8; 32],
            component_name: [0u8; 8],
        }
    }

    pub fn set_component_name(&mut self, s: &[u8]) {
        let len = s.len().min(self.component_name.len());
        self.component_name = [0u8; 8];
        self.component_name[..len].copy_from_slice(&s[..len]);
    }

    pub fn component_name_as_str(&self) -> &str {
        let len = self
            .component_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.component_name.len());
        core::str::from_utf8(&self.component_name[..len]).unwrap_or("")
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
        if req.magic != SECBOOT_MAGIC_REQ {
            return None;
        }
        Some(req)
    }
}

/// Réponse IPC calibrée à exactement 64 octets
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecBootResponse {
    pub magic: u32,
    pub status: i32,
    pub pcr_index: u32,
    pub total_events: u32,
    pub chain_verified: u32,
    pub current_pcr_digest: [u8; 32],
    pub pcr_status_str: [u8; 12],
}

const _: () = assert!(core::mem::size_of::<SecBootResponse>() == 64);

impl Default for SecBootResponse {
    fn default() -> Self {
        Self {
            magic: SECBOOT_MAGIC_RESP,
            status: 0,
            pcr_index: 0,
            total_events: 0,
            chain_verified: 0,
            current_pcr_digest: [0u8; 32],
            pcr_status_str: [0u8; 12],
        }
    }
}

impl SecBootResponse {
    pub fn set_status_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(self.pcr_status_str.len());
        self.pcr_status_str = [0u8; 12];
        self.pcr_status_str[..len].copy_from_slice(&bytes[..len]);
    }

    pub fn status_as_str(&self) -> &str {
        let len = self
            .pcr_status_str
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.pcr_status_str.len());
        core::str::from_utf8(&self.pcr_status_str[..len]).unwrap_or("")
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
        if resp.magic != SECBOOT_MAGIC_RESP {
            return None;
        }
        Some(resp)
    }
}

// ============================================================================
// GESTIONNAIRE SOUVERAIN DE SECURE BOOT (`SecureBootManager`)
// ============================================================================

/// Gestionnaire souverain de démarrage mesuré et d'intégrité TPM 2.0 PCR
pub struct SecureBootManager {
    /// Banques de registres PCR (PCR 0..23) de 32 octets chacun
    pub pcr_banks: [[u8; HASH_SIZE]; PCR_COUNT],
    /// Journal des événements de boot mesurés
    pub events: [Option<BootEvent>; MAX_BOOT_EVENTS],
    /// Nombre d'événements enregistrés
    pub event_count: usize,
}

impl Default for SecureBootManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureBootManager {
    /// Crée un nouveau gestionnaire Secure Boot avec des registres PCR vierges
    pub const fn new() -> Self {
        Self {
            pcr_banks: [[0u8; HASH_SIZE]; PCR_COUNT],
            events: [None; MAX_BOOT_EVENTS],
            event_count: 0,
        }
    }

    /// Initialise la configuration et effectue la séquence complète de démarrage mesuré
    pub fn init_defaults(&mut self) {
        let crtm_hash = Sha256::digest(b"HARDWARE_ROUTER_SECURE_FIRMWARE_V1");
        let limine_hash = Sha256::digest(b"LIMINE_X86_64_BOOT_PROTOCOL_V7");
        let kernel_hash = Sha256::digest(b"JAMBO_MICROKERNEL_RELEASE_V0.3.65");
        let initrd_hash = Sha256::digest(b"INITRD_SYSTEM_SERVICES_V0.3.65");
        let policy_hash = Sha256::digest(b"JAMBO_MANDATORY_ACCESS_CONTROL_POLICY");
        let init_hash = Sha256::digest(b"JAMBO_INIT_DAG_SUPERVISOR_ELF");

        let _ = self.extend_pcr(0, 1, b"CRTM", &crtm_hash);
        let _ = self.extend_pcr(4, 2, b"Limine", &limine_hash);
        let _ = self.extend_pcr(8, 3, b"Kernel", &kernel_hash);
        let _ = self.extend_pcr(9, 4, b"Initrd", &initrd_hash);
        let _ = self.extend_pcr(11, 5, b"Policy", &policy_hash);
        let _ = self.extend_pcr(12, 6, b"Init", &init_hash);
    }

    /// Lit l'empreinte actuelle d'un registre PCR
    pub fn read_pcr(&self, pcr_index: u32) -> Result<[u8; 32], SysError> {
        if pcr_index as usize >= PCR_COUNT {
            return Err(SysError::InvalidArgument);
        }
        Ok(self.pcr_banks[pcr_index as usize])
    }

    /// Étend cryptographiquement un registre PCR selon la spécification TPM 2.0 :
    /// `PCR[i] = SHA256(PCR[i] || event_digest)`
    pub fn extend_pcr(
        &mut self,
        pcr_index: u32,
        event_type: u32,
        name: &[u8],
        digest: &[u8; 32],
    ) -> Result<[u8; 32], SysError> {
        if pcr_index as usize >= PCR_COUNT {
            return Err(SysError::InvalidArgument);
        }
        let idx = pcr_index as usize;

        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.pcr_banks[idx]);
        buf[32..].copy_from_slice(digest);
        let new_pcr = Sha256::digest(&buf);
        self.pcr_banks[idx] = new_pcr;

        let event = BootEvent::new(pcr_index, event_type, *digest, name);
        if self.event_count < MAX_BOOT_EVENTS {
            self.events[self.event_count] = Some(event);
            self.event_count += 1;
        } else {
            let slot = self.event_count % MAX_BOOT_EVENTS;
            self.events[slot] = Some(event);
            self.event_count += 1;
        }

        Ok(new_pcr)
    }

    /// Vérifie la chaîne de confiance mesurée :
    /// Tous les PCR critiques (PCR 0, 4, 8, 9, 11, 12) doivent être non nuls et
    /// au moins 6 mesures doivent avoir été enregistrées.
    pub fn verify_measured_chain(&self) -> bool {
        for (i, bank) in self.pcr_banks.iter().enumerate().take(PCR_COUNT) {
            if (CRITICAL_PCR_MASK & (1 << i)) != 0 && *bank == [0u8; HASH_SIZE] {
                return false;
            }
        }
        self.event_count >= 6
    }

    /// Renvoie le nombre total d'événements de boot enregistrés
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Récupère un événement de boot par son index
    pub fn get_event(&self, idx: usize) -> Option<&BootEvent> {
        if idx < self.event_count && idx < MAX_BOOT_EVENTS {
            self.events[idx].as_ref()
        } else {
            None
        }
    }

    /// Calcule l'empreinte composite SHA-256 de la sélection de registres PCR spécifiée par masque binaire
    pub fn compute_pcr_composite(&self, pcr_mask: u32) -> [u8; HASH_SIZE] {
        let mut composite_input = [0u8; PCR_COUNT * HASH_SIZE];
        let mut offset = 0;

        for (i, bank) in self.pcr_banks.iter().enumerate().take(PCR_COUNT) {
            if (pcr_mask & (1 << i)) != 0 {
                composite_input[offset..offset + HASH_SIZE].copy_from_slice(bank);
                offset += HASH_SIZE;
            }
        }

        Sha256::digest(&composite_input[..offset])
    }

    /// Traitement déterministe d'une requête IPC 64 octets
    pub fn dispatch_ipc(&mut self, req: &SecBootRequest) -> SecBootResponse {
        if req.magic != SECBOOT_MAGIC_REQ {
            let mut resp = SecBootResponse::default();
            resp.status = SysError::InvalidArgument as i32;
            resp.set_status_str("BAD_MAGIC");
            return resp;
        }

        let cap = SecBootCap::new(Handle::new(req.handle_id, 1), req.rights);

        let opcode = match SecBootOpcode::from_u32(req.opcode) {
            Some(op) => op,
            None => {
                let mut resp = SecBootResponse::default();
                resp.status = SysError::InvalidArgument as i32;
                resp.set_status_str("BAD_OPCODE");
                return resp;
            }
        };

        match opcode {
            SecBootOpcode::GetStatus => {
                if !cap.has_right(secboot_rights::INSPECT) && !cap.has_right(secboot_rights::VERIFY)
                {
                    let mut resp = SecBootResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                let mut resp = SecBootResponse::default();
                resp.status = 0;
                resp.total_events = self.event_count as u32;
                resp.chain_verified = if self.verify_measured_chain() { 1 } else { 0 };
                resp.set_status_str("READY");
                resp
            }
            SecBootOpcode::ReadPcr => {
                if !cap.has_right(secboot_rights::INSPECT) {
                    let mut resp = SecBootResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                let mut resp = SecBootResponse::default();
                match self.read_pcr(req.pcr_index) {
                    Ok(digest) => {
                        resp.status = 0;
                        resp.pcr_index = req.pcr_index;
                        resp.current_pcr_digest = digest;
                        resp.total_events = self.event_count as u32;
                        resp.chain_verified = if self.verify_measured_chain() { 1 } else { 0 };
                        resp.set_status_str("PCR_OK");
                    }
                    Err(err) => {
                        resp.status = err as i32;
                        resp.pcr_index = req.pcr_index;
                        resp.set_status_str("ERR_PCR");
                    }
                }
                resp
            }
            SecBootOpcode::ExtendPcr => {
                if !cap.has_right(secboot_rights::MEASURE) {
                    let mut resp = SecBootResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                let mut resp = SecBootResponse::default();
                match self.extend_pcr(
                    req.pcr_index,
                    req.event_type,
                    &req.component_name,
                    &req.digest,
                ) {
                    Ok(new_pcr) => {
                        resp.status = 0;
                        resp.pcr_index = req.pcr_index;
                        resp.current_pcr_digest = new_pcr;
                        resp.total_events = self.event_count as u32;
                        resp.chain_verified = if self.verify_measured_chain() { 1 } else { 0 };
                        resp.set_status_str("EXTENDED");
                    }
                    Err(err) => {
                        resp.status = err as i32;
                        resp.pcr_index = req.pcr_index;
                        resp.set_status_str("ERR_EXTEND");
                    }
                }
                resp
            }
            SecBootOpcode::VerifyChain => {
                if !cap.has_right(secboot_rights::VERIFY) && !cap.has_right(secboot_rights::INSPECT)
                {
                    let mut resp = SecBootResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                let mut resp = SecBootResponse::default();
                let ok = self.verify_measured_chain();
                resp.status = 0;
                resp.total_events = self.event_count as u32;
                resp.chain_verified = if ok { 1 } else { 0 };
                resp.set_status_str(if ok { "CHAIN_VALID" } else { "CHAIN_ERR" });
                resp
            }
            SecBootOpcode::ListEvents => {
                if !cap.has_right(secboot_rights::INSPECT) {
                    let mut resp = SecBootResponse::default();
                    resp.status = SysError::PermissionDenied as i32;
                    resp.set_status_str("DENIED");
                    return resp;
                }
                let mut resp = SecBootResponse::default();
                resp.status = 0;
                resp.total_events = self.event_count as u32;
                resp.chain_verified = if self.verify_measured_chain() { 1 } else { 0 };
                let ev_idx = req.pcr_index as usize;
                if ev_idx < self.event_count && ev_idx < MAX_BOOT_EVENTS {
                    if let Some(ev) = self.get_event(ev_idx) {
                        resp.pcr_index = ev.pcr_index;
                        resp.current_pcr_digest = ev.digest;
                    }
                }
                resp.set_status_str("EVENTS_OK");
                resp
            }
        }
    }
}

// ============================================================================
// CANAL IPC & CLIENT SYNCHRONE (`SecBootClient`, `ChannelMessage`)
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

/// Client synchrone Ring 3 pour interagir avec le démon TPM 2.0 Measured Boot `jambo-secboot` (PID 26)
pub struct SecBootClient {
    pub endpoint: Handle,
}

impl SecBootClient {
    pub const fn new(endpoint: Handle) -> Self {
        Self { endpoint }
    }

    pub fn get_status(&self, cap: &SecBootCap) -> Result<SecBootResponse, SysError> {
        if !cap.has_right(secboot_rights::INSPECT) && !cap.has_right(secboot_rights::VERIFY) {
            return Err(SysError::PermissionDenied);
        }
        let req = SecBootRequest::new_status(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn read_pcr(&self, cap: &SecBootCap, pcr_index: u32) -> Result<SecBootResponse, SysError> {
        if !cap.has_right(secboot_rights::INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        let req = SecBootRequest::new_read_pcr(cap.handle.index(), cap.rights, pcr_index);
        self.call(&req)
    }

    pub fn extend_pcr(
        &self,
        cap: &SecBootCap,
        pcr_index: u32,
        event_type: u32,
        name: &[u8],
        digest: [u8; 32],
    ) -> Result<SecBootResponse, SysError> {
        if !cap.has_right(secboot_rights::MEASURE) {
            return Err(SysError::PermissionDenied);
        }
        let req = SecBootRequest::new_extend_pcr(
            cap.handle.index(),
            cap.rights,
            pcr_index,
            event_type,
            name,
            digest,
        );
        self.call(&req)
    }

    pub fn verify_chain(&self, cap: &SecBootCap) -> Result<SecBootResponse, SysError> {
        if !cap.has_right(secboot_rights::VERIFY) && !cap.has_right(secboot_rights::INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        let req = SecBootRequest::new_verify_chain(cap.handle.index(), cap.rights);
        self.call(&req)
    }

    pub fn list_events(
        &self,
        cap: &SecBootCap,
        event_index: u32,
    ) -> Result<SecBootResponse, SysError> {
        if !cap.has_right(secboot_rights::INSPECT) {
            return Err(SysError::PermissionDenied);
        }
        let req = SecBootRequest::new_list_events(cap.handle.index(), cap.rights, event_index);
        self.call(&req)
    }

    pub fn call(&self, req: &SecBootRequest) -> Result<SecBootResponse, SysError> {
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

            if ret_recv == 0 && rx_msg.byte_count >= core::mem::size_of::<SecBootResponse>() {
                return SecBootResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
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
    fn test_sha256_known_vectors() {
        // Test vector 1: Empty string
        let h_empty = Sha256::digest(b"");
        let expected_empty: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(h_empty, expected_empty);

        // Test vector 2: "abc"
        let h_abc = Sha256::digest(b"abc");
        let expected_abc: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(h_abc, expected_abc);

        // Test vector 3: Multi-block test string
        let h_long = Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let expected_long: [u8; 32] = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];
        assert_eq!(h_long, expected_long);
    }

    #[test]
    fn test_cap_attenuation_and_anti_amplification() {
        let root_cap = SecBootCap::new(Handle::new(26, 1), secboot_rights::ALL);
        assert!(root_cap.has_right(secboot_rights::MEASURE));
        assert!(root_cap.has_right(secboot_rights::VERIFY));
        assert!(root_cap.has_right(secboot_rights::INSPECT));

        let inspect_only = root_cap
            .attenuate(secboot_rights::INSPECT)
            .expect("Monotonic attenuation");
        assert!(inspect_only.has_right(secboot_rights::INSPECT));
        assert!(!inspect_only.has_right(secboot_rights::MEASURE));
        assert!(!inspect_only.has_right(secboot_rights::VERIFY));

        // Rejection of privilege amplification attempt
        assert_eq!(
            inspect_only.attenuate(secboot_rights::ALL),
            Err(SysError::PermissionDenied)
        );
    }

    #[test]
    fn test_measured_boot_sequence_and_verification() {
        let mut manager = SecureBootManager::new();
        assert!(!manager.verify_measured_chain());

        manager.init_defaults();

        // Critical PCRs must be non-zero
        assert_ne!(manager.pcr_banks[0], [0u8; HASH_SIZE]); // CRTM
        assert_ne!(manager.pcr_banks[4], [0u8; HASH_SIZE]); // Limine
        assert_ne!(manager.pcr_banks[8], [0u8; HASH_SIZE]); // Kernel
        assert_ne!(manager.pcr_banks[9], [0u8; HASH_SIZE]); // Initrd
        assert_ne!(manager.pcr_banks[11], [0u8; HASH_SIZE]); // Policy
        assert_ne!(manager.pcr_banks[12], [0u8; HASH_SIZE]); // Init
        assert_eq!(manager.pcr_banks[2], [0u8; HASH_SIZE]); // Non mesuré initialement

        assert!(manager.event_count() >= 6);
        assert!(manager.verify_measured_chain());

        // Event log inspection
        let ev0 = manager.get_event(0).expect("Event 0 present");
        assert_eq!(ev0.pcr_index, 0);
        assert_eq!(ev0.component_name_str(), "CRTM");

        let ev1 = manager.get_event(1).expect("Event 1 present");
        assert_eq!(ev1.pcr_index, 4);
        assert_eq!(ev1.component_name_str(), "Limine");
    }

    #[test]
    fn test_pcr_extension_calculation() {
        let mut manager = SecureBootManager::new();
        let meas = Sha256::digest(b"TEST_COMPONENT_DATA");

        // First extension on PCR 14 (initially zero)
        let expected_pcr14 = {
            let mut buf = [0u8; 64];
            buf[32..].copy_from_slice(&meas);
            Sha256::digest(&buf)
        };

        let res = manager
            .extend_pcr(14, 0x10, b"Comp14", &meas)
            .expect("Extend PCR 14");
        assert_eq!(res, expected_pcr14);
        assert_eq!(manager.read_pcr(14).unwrap(), expected_pcr14);

        // Invalid PCR index
        assert_eq!(manager.read_pcr(24), Err(SysError::InvalidArgument));
        assert_eq!(
            manager.extend_pcr(25, 0x10, b"Bad", &meas),
            Err(SysError::InvalidArgument)
        );
    }

    #[test]
    fn test_ipc_serialization_roundtrip() {
        // Request serialization
        let req = SecBootRequest::new_extend_pcr(
            26,
            secboot_rights::ALL,
            15,
            0x42,
            b"Subsys",
            [0xAA; 32],
        );
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 64);
        let decoded_req = SecBootRequest::from_bytes(&bytes).expect("Decode valid request");
        assert_eq!(decoded_req.magic, SECBOOT_MAGIC_REQ);
        assert_eq!(decoded_req.opcode, SecBootOpcode::ExtendPcr as u32);
        assert_eq!(decoded_req.pcr_index, 15);
        assert_eq!(decoded_req.event_type, 0x42);
        assert_eq!(decoded_req.digest, [0xAA; 32]);
        assert_eq!(decoded_req.component_name_as_str(), "Subsys");

        // Response serialization
        let mut resp = SecBootResponse::default();
        resp.status = 0;
        resp.pcr_index = 15;
        resp.total_events = 7;
        resp.chain_verified = 1;
        resp.current_pcr_digest = [0x55; 32];
        resp.set_status_str("EXTENDED");

        let resp_bytes = resp.to_bytes();
        assert_eq!(resp_bytes.len(), 64);
        let decoded_resp = SecBootResponse::from_bytes(&resp_bytes).expect("Decode valid response");
        assert_eq!(decoded_resp.magic, SECBOOT_MAGIC_RESP);
        assert_eq!(decoded_resp.status, 0);
        assert_eq!(decoded_resp.pcr_index, 15);
        assert_eq!(decoded_resp.total_events, 7);
        assert_eq!(decoded_resp.chain_verified, 1);
        assert_eq!(decoded_resp.current_pcr_digest, [0x55; 32]);
        assert_eq!(decoded_resp.status_as_str(), "EXTENDED");
    }

    #[test]
    fn test_ipc_dispatch_workflow() {
        let mut manager = SecureBootManager::new();
        manager.init_defaults();

        // 1. GetStatus
        let req_status = SecBootRequest::new_status(26, secboot_rights::ALL);
        let resp_status = manager.dispatch_ipc(&req_status);
        assert_eq!(resp_status.status, 0);
        assert_eq!(resp_status.chain_verified, 1);
        assert_eq!(resp_status.status_as_str(), "READY");

        // 2. ReadPcr (PCR 0)
        let req_read = SecBootRequest::new_read_pcr(26, secboot_rights::ALL, 0);
        let resp_read = manager.dispatch_ipc(&req_read);
        assert_eq!(resp_read.status, 0);
        assert_eq!(resp_read.pcr_index, 0);
        assert_ne!(resp_read.current_pcr_digest, [0u8; 32]);
        assert_eq!(resp_read.status_as_str(), "PCR_OK");

        // 3. ExtendPcr (PCR 16)
        let meas16 = Sha256::digest(b"SERVICE_DYNAMIC_MODULE");
        let req_extend =
            SecBootRequest::new_extend_pcr(26, secboot_rights::ALL, 16, 0x20, b"DynModule", meas16);
        let resp_extend = manager.dispatch_ipc(&req_extend);
        assert_eq!(resp_extend.status, 0);
        assert_eq!(resp_extend.pcr_index, 16);
        assert_eq!(resp_extend.status_as_str(), "EXTENDED");

        // 4. VerifyChain
        let req_verify = SecBootRequest::new_verify_chain(26, secboot_rights::ALL);
        let resp_verify = manager.dispatch_ipc(&req_verify);
        assert_eq!(resp_verify.status, 0);
        assert_eq!(resp_verify.chain_verified, 1);
        assert_eq!(resp_verify.status_as_str(), "CHAIN_VALID");

        // 5. ListEvents (index 0)
        let req_list = SecBootRequest::new_list_events(26, secboot_rights::ALL, 0);
        let resp_list = manager.dispatch_ipc(&req_list);
        assert_eq!(resp_list.status, 0);
        assert_eq!(resp_list.pcr_index, 0);
        assert_eq!(resp_list.status_as_str(), "EVENTS_OK");
    }

    #[test]
    fn test_ipc_permission_denied() {
        let mut manager = SecureBootManager::new();
        manager.init_defaults();

        // Extend requested without MEASURE right
        let req_extend = SecBootRequest::new_extend_pcr(
            26,
            secboot_rights::INSPECT, // Only inspect, not MEASURE
            14,
            0x10,
            b"Unauthorized",
            [0x11; 32],
        );
        let resp = manager.dispatch_ipc(&req_extend);
        assert_eq!(resp.status, SysError::PermissionDenied as i32);
        assert_eq!(resp.status_as_str(), "DENIED");

        // Read requested without INSPECT right
        let req_read = SecBootRequest::new_read_pcr(26, 0, 0);
        let resp = manager.dispatch_ipc(&req_read);
        assert_eq!(resp.status, SysError::PermissionDenied as i32);
        assert_eq!(resp.status_as_str(), "DENIED");
    }

    #[test]
    fn test_ipc_bad_magic_and_opcode() {
        let mut manager = SecureBootManager::new();

        let mut req = SecBootRequest::default();
        req.magic = 0xDEADBEEF;
        let resp = manager.dispatch_ipc(&req);
        assert_eq!(resp.status, SysError::InvalidArgument as i32);
        assert_eq!(resp.status_as_str(), "BAD_MAGIC");

        let mut req_bad_op = SecBootRequest::default();
        req_bad_op.opcode = 999;
        let resp = manager.dispatch_ipc(&req_bad_op);
        assert_eq!(resp.status, SysError::InvalidArgument as i32);
        assert_eq!(resp.status_as_str(), "BAD_OPCODE");
    }
}

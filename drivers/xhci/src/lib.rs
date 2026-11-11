//! Pilote de contrôleur d'hôte USB xHCI (eXtensible Host Controller Interface) 1.2
//! et sous-système de périphériques d'entrée HID (Clavier / Souris) en espace utilisateur (Ring 3).
//!
//! Assure la gestion conforme des anneaux Command / Event / Transfer (TRBs), l'énumération
//! des ports USB root-hub, la configuration des slots et contextes de périphériques,
//! le calcul sécurisé des registres Doorbell, ainsi que le décodage matériel des rapports
//! Boot Protocol du clavier et de la souris HID, sans aucune instruction d'E/S privilégiée
//! directe en Ring 3.

#![no_std]
#![allow(clippy::too_many_arguments)]

#[cfg(test)]
extern crate std;

use libjambo::pci::PciDeviceInfo;
use libjambo::SysError;

// ============================================================================
// Types et Constantes TRB (Transfer Request Block) - Spécification xHCI 1.2
// ============================================================================

pub const TRB_TYPE_NORMAL: u32 = 1;
pub const TRB_TYPE_SETUP_STAGE: u32 = 2;
pub const TRB_TYPE_DATA_STAGE: u32 = 3;
pub const TRB_TYPE_STATUS_STAGE: u32 = 4;
pub const TRB_TYPE_ISOCH: u32 = 5;
pub const TRB_TYPE_LINK: u32 = 6;
pub const TRB_TYPE_EVENT_DATA: u32 = 7;
pub const TRB_TYPE_NOOP_TRANSFER: u32 = 8;
pub const TRB_TYPE_ENABLE_SLOT: u32 = 9;
pub const TRB_TYPE_DISABLE_SLOT: u32 = 10;
pub const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
pub const TRB_TYPE_CONFIGURE_EP: u32 = 12;
pub const TRB_TYPE_EVALUATE_CONTEXT: u32 = 13;
pub const TRB_TYPE_RESET_EP: u32 = 14;
pub const TRB_TYPE_STOP_EP: u32 = 15;
pub const TRB_TYPE_SET_TR_DEQUEUE: u32 = 16;
pub const TRB_TYPE_RESET_DEVICE: u32 = 17;
pub const TRB_TYPE_NOOP_CMD: u32 = 23;

pub const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
pub const TRB_TYPE_CMD_COMPLETION_EVENT: u32 = 33;
pub const TRB_TYPE_PORT_STATUS_CHANGE: u32 = 34;
pub const TRB_TYPE_BANDWIDTH_REQUEST: u32 = 35;
pub const TRB_TYPE_DOORBELL_EVENT: u32 = 36;
pub const TRB_TYPE_HOST_CONTROLLER_EVENT: u32 = 37;
pub const TRB_TYPE_DEVICE_NOTIFICATION: u32 = 38;
pub const TRB_TYPE_MFINDEX_WRAP: u32 = 39;

// Registres xHCI Runtime & Synchronisation Microtrames (MFINDEX)
pub const REG_MFINDEX_OFFSET: usize = 0x0000;
pub const MFINDEX_MASK: u32 = 0x3FFF; // 14 bits (0..16383 microframes)
pub const MFINDEX_MICROFRAME_US: u32 = 125; // 125 us par microframe USB

// Codes de complétion TRB standard
pub const TRB_COMP_INVALID: u8 = 0;
pub const TRB_COMP_SUCCESS: u8 = 1;
pub const TRB_COMP_DATA_BUFFER_ERROR: u8 = 2;
pub const TRB_COMP_BABBLE_ERROR: u8 = 3;
pub const TRB_COMP_USB_TRANSACTION_ERROR: u8 = 4;
pub const TRB_COMP_TRB_ERROR: u8 = 5;
pub const TRB_COMP_STALL_ERROR: u8 = 6;
pub const TRB_COMP_RESOURCE_ERROR: u8 = 7;
pub const TRB_COMP_BANDWIDTH_ERROR: u8 = 8;
pub const TRB_COMP_NO_SLOTS_AVAILABLE: u8 = 9;
pub const TRB_COMP_RING_UNDERRUN: u8 = 15;
pub const TRB_COMP_RING_OVERRUN: u8 = 16;
pub const TRB_COMP_COMMAND_ABORTED: u8 = 18;
pub const TRB_COMP_EVENT_RING_FULL: u8 = 21;
pub const TRB_COMP_MISSED_SERVICE_ERROR: u8 = 31;
pub const TRB_COMP_ISOCH_BUFFER_OVERRUN: u8 = 33;

// Drapeaux de contrôle TRB de transfert USB 3.0
pub const TRB_FLAG_CYCLE: u32 = 1 << 0;
pub const TRB_FLAG_ENT: u32 = 1 << 1; // Evaluate Next TRB
pub const TRB_FLAG_ISP: u32 = 1 << 2; // Interrupt on Short Packet
pub const TRB_FLAG_NSNOOP: u32 = 1 << 3; // No Snoop
pub const TRB_FLAG_CH: u32 = 1 << 4; // Chain bit
pub const TRB_FLAG_IOC: u32 = 1 << 5; // Interrupt On Completion
pub const TRB_FLAG_IDT: u32 = 1 << 6; // Immediate Data
pub const TRB_FLAG_BEI: u32 = 1 << 9; // Block Event Interrupt
pub const TRB_FLAG_SIA: u32 = 1 << 31; // Start Isoch ASAP

pub const RING_ENTRIES: usize = 32;
pub const MAX_ENDPOINTS: usize = 8;
pub const MAX_STREAMS_PER_ENDPOINT: usize = 4;

/// Segment d'une liste Scatter-Gather pour les transferts DMA discontinus USB 3.0
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SgSegment {
    pub iova: u64,
    pub length: u32,
}

impl SgSegment {
    pub const fn new(iova: u64, length: u32) -> Self {
        Self { iova, length }
    }
}

/// Contexte de Stream xHCI (16 octets, pointant vers l'anneau de transfert du flux)
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamContext {
    /// Adresse IOVA de l'anneau de transfert TRB (bits 63:4) + flags SCT (bits 3:1) + DCS (bit 0)
    pub tr_dequeue_pointer: u64,
    pub reserved1: u32,
    pub reserved2: u32,
}

impl StreamContext {
    pub const fn new(ring_iova: u64, cycle: bool) -> Self {
        let dcs = if cycle { 1 } else { 0 };
        let sct_primary = 1 << 1; // Stream Context Type = Primary
        Self {
            tr_dequeue_pointer: (ring_iova & !0xF) | sct_primary | dcs,
            reserved1: 0,
            reserved2: 0,
        }
    }
}

/// Anneau de transfert xHCI dédié à un flux Bulk spécifique (Block Stream / UAS)
pub struct BulkStreamRing {
    pub stream_id: u16,
    pub ring: XhciRing,
    pub active: bool,
    pub total_bytes_transferred: u64,
    pub last_status: TransferStatus,
}

impl Default for BulkStreamRing {
    fn default() -> Self {
        Self::new(0)
    }
}

impl BulkStreamRing {
    pub const fn new(stream_id: u16) -> Self {
        Self {
            stream_id,
            ring: XhciRing::new(),
            active: false,
            total_bytes_transferred: 0,
            last_status: TransferStatus {
                trb_idx: 0,
                bytes_transferred: 0,
                completed: false,
                completion_code: 0,
            },
        }
    }

    pub fn reset(&mut self) {
        self.ring.reset();
        self.active = false;
        self.total_bytes_transferred = 0;
        self.last_status = TransferStatus::default();
    }
}

/// État d'un transfert USB 3.0 en attente ou complété
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransferStatus {
    pub trb_idx: usize,
    pub bytes_transferred: u32,
    pub completed: bool,
    pub completion_code: u8,
}

/// Anneau de transfert xHCI dédié à un endpoint spécifique (Bulk, Isochrone ou Interruption)
pub struct EndpointTransferRing {
    pub endpoint_id: u8,
    pub ring: XhciRing,
    pub is_isoch: bool,
    pub is_interrupt: bool,
    pub active: bool,
    pub total_bytes_transferred: u64,
    pub last_status: TransferStatus,
    pub streams_enabled: bool,
    pub streams: [BulkStreamRing; MAX_STREAMS_PER_ENDPOINT],
}

impl Default for EndpointTransferRing {
    fn default() -> Self {
        Self::new(0, false)
    }
}

impl EndpointTransferRing {
    pub const fn new(endpoint_id: u8, is_isoch: bool) -> Self {
        Self {
            endpoint_id,
            ring: XhciRing::new(),
            is_isoch,
            is_interrupt: false,
            active: false,
            total_bytes_transferred: 0,
            last_status: TransferStatus {
                trb_idx: 0,
                bytes_transferred: 0,
                completed: false,
                completion_code: 0,
            },
            streams_enabled: false,
            streams: [
                BulkStreamRing::new(0),
                BulkStreamRing::new(0),
                BulkStreamRing::new(0),
                BulkStreamRing::new(0),
            ],
        }
    }

    pub const fn new_interrupt(endpoint_id: u8) -> Self {
        Self {
            endpoint_id,
            ring: XhciRing::new(),
            is_isoch: false,
            is_interrupt: true,
            active: false,
            total_bytes_transferred: 0,
            last_status: TransferStatus {
                trb_idx: 0,
                bytes_transferred: 0,
                completed: false,
                completion_code: 0,
            },
            streams_enabled: false,
            streams: [
                BulkStreamRing::new(0),
                BulkStreamRing::new(0),
                BulkStreamRing::new(0),
                BulkStreamRing::new(0),
            ],
        }
    }

    /// Réinitialise le Transfer Ring de l'endpoint
    pub fn reset(&mut self) {
        self.ring.reset();
        self.active = false;
        self.is_interrupt = false;
        self.total_bytes_transferred = 0;
        self.last_status = TransferStatus::default();
        self.streams_enabled = false;
        let mut idx = 0;
        while idx < self.streams.len() {
            self.streams[idx].reset();
            idx += 1;
        }
    }
}

/// Bloc de requête de transfert TRB (16 octets, alignement matériel 16 octets).
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    /// Construit un TRB standard à partir de ses composantes.
    #[inline]
    pub fn new(parameter: u64, status: u32, trb_type: u32, cycle: bool) -> Self {
        let control = ((trb_type & 0x3F) << 10) | if cycle { 1 } else { 0 };
        Self {
            parameter,
            status,
            control,
        }
    }

    /// Construit un TRB Normal pour transfert Bulk USB 3.0
    #[inline]
    pub fn normal(data_iova: u64, length: u32, cycle: bool, ioc: bool, isp: bool) -> Self {
        Self::normal_chained(data_iova, length, cycle, false, ioc, isp)
    }

    /// Construit un TRB Normal chaîné (avec bit CH - Chain bit) pour le scatter-gather
    #[inline]
    pub fn normal_chained(
        data_iova: u64,
        length: u32,
        cycle: bool,
        chain: bool,
        ioc: bool,
        isp: bool,
    ) -> Self {
        let mut control = ((TRB_TYPE_NORMAL & 0x3F) << 10) | if cycle { 1 } else { 0 };
        if chain {
            control |= TRB_FLAG_CH;
        }
        if ioc {
            control |= TRB_FLAG_IOC;
        }
        if isp {
            control |= TRB_FLAG_ISP;
        }
        let status = length & 0x1FFFF;
        Self {
            parameter: data_iova,
            status,
            control,
        }
    }

    /// Construit un TRB Isochrone USB 3.0 avec horodatage de trame (Frame ID) ou exécution immédiate (SIA)
    #[inline]
    pub fn isoch(
        data_iova: u64,
        length: u32,
        frame_id: u32,
        sia: bool,
        cycle: bool,
        ioc: bool,
        isp: bool,
    ) -> Self {
        let mut control = ((TRB_TYPE_ISOCH & 0x3F) << 10) | if cycle { 1 } else { 0 };
        if ioc {
            control |= TRB_FLAG_IOC;
        }
        if isp {
            control |= TRB_FLAG_ISP;
        }
        if sia {
            control |= TRB_FLAG_SIA;
        } else {
            control |= (frame_id & 0x7FF) << 20;
        }
        let status = length & 0x1FFFF;
        Self {
            parameter: data_iova,
            status,
            control,
        }
    }

    /// Construit un TRB de liaison (Link TRB) vers un pointeur d'anneau avec bascule de bit de cycle (TC).
    #[inline]
    pub fn link(target_iova: u64, cycle: bool, toggle_cycle: bool) -> Self {
        let mut control = ((TRB_TYPE_LINK & 0x3F) << 10) | if cycle { 1 } else { 0 };
        if toggle_cycle {
            control |= 1 << 1; // Bit TC (Toggle Cycle)
        }
        Self {
            parameter: target_iova,
            status: 0,
            control,
        }
    }

    /// Construit un TRB Setup Stage pour transfert de contrôle xHCI (Endpoint 0).
    /// `setup` contient les 8 octets du paquet USB Setup (bmRequestType, bRequest, wValue, wIndex, wLength).
    /// `trt` spécifie le Transfer Type : 0 = No Data Stage, 2 = OUT Data Stage, 3 = IN Data Stage.
    #[inline]
    pub fn setup_stage(setup: &UsbSetupPacket, trt: u32, cycle: bool) -> Self {
        let mut control = ((TRB_TYPE_SETUP_STAGE & 0x3F) << 10) | if cycle { 1 } else { 0 };
        control |= TRB_FLAG_IDT; // Les 8 octets de setup sont toujours stockés en direct dans parameter
        control |= (trt & 0x03) << 16; // Bits TRT (Transfer Type) : bits 17:16

        Self {
            parameter: setup.to_raw_u64(),
            status: 8, // Longueur fixe du setup packet : 8 octets
            control,
        }
    }

    /// Construit un TRB Data Stage pour transfert de contrôle xHCI.
    /// `data_iova` : adresse physique du buffer mémoire.
    /// `length` : taille du transfert en octets.
    /// `is_in` : vrai pour IN (Device to Host), faux pour OUT.
    #[inline]
    pub fn data_stage(
        data_iova: u64,
        length: u32,
        is_in: bool,
        cycle: bool,
        ioc: bool,
        isp: bool,
    ) -> Self {
        let mut control = ((TRB_TYPE_DATA_STAGE & 0x3F) << 10) | if cycle { 1 } else { 0 };
        if is_in {
            control |= 1 << 16; // Bit DIR (Direction) : 1 = IN, 0 = OUT
        }
        if ioc {
            control |= TRB_FLAG_IOC;
        }
        if isp {
            control |= TRB_FLAG_ISP;
        }
        let status = length & 0x1FFFF;
        Self {
            parameter: data_iova,
            status,
            control,
        }
    }

    /// Construit un TRB Status Stage pour transfert de contrôle xHCI.
    /// `is_in` : vrai pour un handshake IN (après un OUT data ou sans données), faux pour OUT.
    #[inline]
    pub fn status_stage(is_in: bool, cycle: bool, ioc: bool) -> Self {
        let mut control = ((TRB_TYPE_STATUS_STAGE & 0x3F) << 10) | if cycle { 1 } else { 0 };
        if is_in {
            control |= 1 << 16; // Bit DIR : 1 = IN, 0 = OUT
        }
        if ioc {
            control |= TRB_FLAG_IOC;
        }
        Self {
            parameter: 0,
            status: 0,
            control,
        }
    }

    /// Indique si le bit de cycle (Cycle Bit - C) est actif.
    #[inline]
    pub fn cycle_bit(&self) -> bool {
        (self.control & 1) != 0
    }

    /// Extrait le type de TRB (bits 15:10).
    #[inline]
    pub fn trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    /// Extrait le code de complétion d'un Event TRB (bits 31:24 du champ status).
    #[inline]
    pub fn completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }

    /// Extrait la longueur restante d'un Transfer Event TRB (bits 23:0 du champ status).
    #[inline]
    pub fn transfer_remainder(&self) -> u32 {
        self.status & 0xFF_FFFF
    }

    /// Extrait l'identifiant de slot d'une commande ou d'un événement (bits 31:24 du champ control).
    #[inline]
    pub fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }

    /// Extrait l'identifiant d'endpoint d'un événement de transfert (bits 20:16 du champ control).
    #[inline]
    pub fn endpoint_id(&self) -> u8 {
        ((self.control >> 16) & 0x1F) as u8
    }
}

/// Anneau circulaire de TRBs (Command Ring ou Transfer Ring).
pub struct XhciRing {
    pub trbs: [Trb; RING_ENTRIES],
    pub enqueue_idx: usize,
    pub cycle_bit: bool,
}

impl Default for XhciRing {
    fn default() -> Self {
        Self::new()
    }
}

impl XhciRing {
    pub const fn new() -> Self {
        Self {
            trbs: [Trb {
                parameter: 0,
                status: 0,
                control: 0,
            }; RING_ENTRIES],
            enqueue_idx: 0,
            cycle_bit: true,
        }
    }

    /// Pousse un TRB sur l'anneau et gère automatiquement l'insertion du Link TRB et le cycle bit.
    pub fn push(&mut self, parameter: u64, status: u32, trb_type: u32) -> Result<usize, SysError> {
        let idx = self.enqueue_idx;
        let next_idx = (idx + 1) % RING_ENTRIES;

        if next_idx == 0 {
            // Insérer un Link TRB avec Toggle Cycle pour reboucler sur le début de l'anneau
            let link_trb = Trb::link(0, self.cycle_bit, true);
            self.trbs[idx] = link_trb;
            self.cycle_bit = !self.cycle_bit;
            self.enqueue_idx = 0;
            return Ok(idx);
        }

        self.trbs[idx] = Trb::new(parameter, status, trb_type, self.cycle_bit);
        self.enqueue_idx = next_idx;
        Ok(idx)
    }

    /// Réinitialise l'anneau dans son état initial.
    pub fn reset(&mut self) {
        self.enqueue_idx = 0;
        self.cycle_bit = true;
        for trb in self.trbs.iter_mut() {
            *trb = Trb::default();
        }
    }
}

// ============================================================================
// Décodage Registre Port Status & Control (PORTSC)
// ============================================================================

/// Masques de bits et drapeaux de changement d'état du registre PORTSC (Section 5.4.8 de la spec xHCI 1.2)
pub const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
pub const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
pub const PORTSC_OCA: u32 = 1 << 3; // Over-current Active
pub const PORTSC_PR: u32 = 1 << 4; // Port Reset
pub const PORTSC_PLS_SHIFT: u32 = 5; // Port Link State Shift (bits 8:5)
pub const PORTSC_PLS_MASK: u32 = 0x0F << PORTSC_PLS_SHIFT;
pub const PORTSC_PP: u32 = 1 << 9; // Port Power
pub const PORTSC_SPEED_SHIFT: u32 = 10; // Port Speed Shift (bits 13:10)
pub const PORTSC_SPEED_MASK: u32 = 0x0F << PORTSC_SPEED_SHIFT;
pub const PORTSC_PIC_SHIFT: u32 = 14; // Port Indicator Control (bits 15:14)
pub const PORTSC_PIC_MASK: u32 = 0x03 << PORTSC_PIC_SHIFT;
pub const PORTSC_LWS: u32 = 1 << 16; // Port Link State Write Strobe
pub const PORTSC_CSC: u32 = 1 << 17; // Connect Status Change (RW1C)
pub const PORTSC_PEC: u32 = 1 << 18; // Port Enabled/Disabled Change (RW1C)
pub const PORTSC_WRC: u32 = 1 << 19; // Warm Port Reset Change (RW1C)
pub const PORTSC_OCC: u32 = 1 << 20; // Over-current Change (RW1C)
pub const PORTSC_PRC: u32 = 1 << 21; // Port Reset Change (RW1C)
pub const PORTSC_PLC: u32 = 1 << 22; // Port Link State Change (RW1C)
pub const PORTSC_CEC: u32 = 1 << 23; // Port Config Error Change (RW1C)
pub const PORTSC_CAS: u32 = 1 << 24; // Cold Attach Status
pub const PORTSC_WCE: u32 = 1 << 25; // Wake on Connect Enable
pub const PORTSC_WDE: u32 = 1 << 26; // Wake on Disconnect Enable
pub const PORTSC_WOE: u32 = 1 << 27; // Wake on Over-current Enable
pub const PORTSC_DR: u32 = 1 << 30; // Device Removable
pub const PORTSC_WPR: u32 = 1 << 31; // Warm Port Reset (RW)

// Valeurs du Port Link State (PLS, spec xHCI 1.2 section 5.4.8)
pub const PLS_U0: u8 = 0; // Operational state
pub const PLS_U1: u8 = 1; // Low power standby state 1
pub const PLS_U2: u8 = 2; // Low power standby state 2
pub const PLS_U3: u8 = 3; // Suspend state
pub const PLS_DISABLED: u8 = 4; // Port disabled
pub const PLS_RXDETECT: u8 = 5; // Receiver detection
pub const PLS_INACTIVE: u8 = 6; // Port inactive
pub const PLS_POLLING: u8 = 7; // Link polling
pub const PLS_RECOVERY: u8 = 8; // Link recovery
pub const PLS_HOT_RESET: u8 = 9; // Hot reset
pub const PLS_COMPLIANCE_MODE: u8 = 10; // Compliance mode
pub const PLS_TEST_MODE: u8 = 11; // Test mode
pub const PLS_RESUME: u8 = 15; // Resume state

// ============================================================================
// Registre PORTPMSC (Port Power Management Status & Control) - xHCI 1.2 section 5.4.9
// ============================================================================

/// Masque et décalage pour le timeout d'inactivité USB 3.0 U1 (bits 7:0 de PORTPMSC USB3)
pub const PORTPMSC_U1_TIMEOUT_SHIFT: u32 = 0;
pub const PORTPMSC_U1_TIMEOUT_MASK: u32 = 0xFF << PORTPMSC_U1_TIMEOUT_SHIFT;

/// Masque et décalage pour le timeout d'inactivité USB 3.0 U2 (bits 15:8 de PORTPMSC USB3)
pub const PORTPMSC_U2_TIMEOUT_SHIFT: u32 = 8;
pub const PORTPMSC_U2_TIMEOUT_MASK: u32 = 0xFF << PORTPMSC_U2_TIMEOUT_SHIFT;

/// Flag Force Link PM Accept (FLA, bit 16 de PORTPMSC USB3)
pub const PORTPMSC_FLA: u32 = 1 << 16;

/// Masque et décalage pour le délai d'abandon de paquet de transfert USB 3.0 (Transfer Packet Pending Timeouts / TPP, bits 23:17 de PORTPMSC USB3)
pub const PORTPMSC_USB3_TPP_TIMEOUT_SHIFT: u32 = 17;
pub const PORTPMSC_USB3_TPP_TIMEOUT_MASK: u32 = 0x7F << PORTPMSC_USB3_TPP_TIMEOUT_SHIFT;

/// Masques pour USB 2.0 Link Power Management (L1 / LPM dans PORTPMSC USB2)
/// LPM Device Response / Best Effort Service Latency (BESL / L1S, bits 2:0)
pub const PORTPMSC_L1S_SHIFT: u32 = 0;
pub const PORTPMSC_L1S_MASK: u32 = 0x03 << PORTPMSC_L1S_SHIFT;
/// HIRD (Host Initiated Resume Duration, bits 7:4 - ou bits 5:2 selon révision LPM)
pub const PORTPMSC_HIRD_SHIFT: u32 = 4;
pub const PORTPMSC_HIRD_MASK: u32 = 0x0F << PORTPMSC_HIRD_SHIFT;
/// Remote Wakeup Enable pour USB 2.0 L1 (bit 8)
pub const PORTPMSC_RWE: u32 = 1 << 8;

// ============================================================================
// Registre PORTLI (Port Link Info) - xHCI 1.2 section 5.4.10
// ============================================================================

/// Masque et décalage pour le compteur d'erreurs de couche liaison USB 3.0 (Link Error Count / LEC, bits 15:0 de PORTLI)
pub const PORTLI_LINK_ERROR_COUNT_SHIFT: u32 = 0;
pub const PORTLI_LINK_ERROR_COUNT_MASK: u32 = 0xFFFF << PORTLI_LINK_ERROR_COUNT_SHIFT;

/// Masque et décalage pour les drapeaux d'état de couche liaison (Link State / Flags, bits 31:16 de PORTLI)
pub const PORTLI_RX_LANES_SHIFT: u32 = 16;
pub const PORTLI_RX_LANES_MASK: u32 = 0x0F << PORTLI_RX_LANES_SHIFT;
pub const PORTLI_TX_LANES_SHIFT: u32 = 20;
pub const PORTLI_TX_LANES_MASK: u32 = 0x0F << PORTLI_TX_LANES_SHIFT;

/// Télémétrie d'intégrité de trames et d'erreurs de couche liaison USB 3.0 (PORTLI)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortLinkInfo {
    /// Nombre d'erreurs de couche liaison détectées (8b/10b, 128b/132b, CRC, paquet corrompu)
    pub link_error_count: u16,
    /// Nombre de voies RX actives négociées (Gen 1x1, 2x1, 2x2...)
    pub rx_lanes: u8,
    /// Nombre de voies TX actives négociées
    pub tx_lanes: u8,
}

impl PortLinkInfo {
    /// Décode la valeur brute 32-bit lue depuis le registre PORTLI
    pub const fn parse(raw_portli: u32) -> Self {
        let link_error_count = (raw_portli & PORTLI_LINK_ERROR_COUNT_MASK) as u16;
        let rx_lanes = ((raw_portli & PORTLI_RX_LANES_MASK) >> PORTLI_RX_LANES_SHIFT) as u8;
        let tx_lanes = ((raw_portli & PORTLI_TX_LANES_MASK) >> PORTLI_TX_LANES_SHIFT) as u8;
        Self {
            link_error_count,
            rx_lanes,
            tx_lanes,
        }
    }

    /// Encode une structure PortLinkInfo en valeur de registre PORTLI 32-bit
    pub const fn to_raw(&self) -> u32 {
        ((self.link_error_count as u32) & PORTLI_LINK_ERROR_COUNT_MASK)
            | (((self.rx_lanes as u32) << PORTLI_RX_LANES_SHIFT) & PORTLI_RX_LANES_MASK)
            | (((self.tx_lanes as u32) << PORTLI_TX_LANES_SHIFT) & PORTLI_TX_LANES_MASK)
    }

    /// Indique si la liaison physique présente une dégradation anormale (> seuil d'erreurs)
    pub const fn is_degraded(&self, threshold: u16) -> bool {
        self.link_error_count > threshold
    }
}

// ============================================================================
// Registre PORTHLPMC (Port Hardware LPM Control) - xHCI 1.2 section 5.4.11
// ============================================================================

// Bits HLE (Hardware LPM Enable, bit 0) : active le contrôle matériel LPM
// Bits L1Timeout (bits 15:8) : délai d'inactivité avant transition L1 (unité = 128 μs)
// Bits BESLD (Best Effort Service Latency Deep, bits 11:8) : latence de service optimale profonde
// Bits HirdBesl (HIRD/BESL, bits 7:4) : valeur HIRD/BESL pour LPM L1
// Bits L1DS (L1 Device Slot, bits 23:16) : slot de périphérique pour LPM L1
// Bits HLE (Hardware LPM Enable, bit 0)

/// Hardware LPM Enable (HLE, bit 0 de PORTHLPMC) : active la gestion matérielle de l'état de lien L1
pub const PORTHLPMC_HLE_BIT: u32 = 1 << 0;

/// Décalage et masque HIRD/BESL (bits 5:2 de PORTHLPMC) : valeur HIRD ou BESL pour la négociation LPM L1
pub const PORTHLPMC_HIRD_BESL_SHIFT: u32 = 2;
pub const PORTHLPMC_HIRD_BESL_MASK: u32 = 0xF << PORTHLPMC_HIRD_BESL_SHIFT;

/// Décalage et masque L1 Timeout (bits 15:8 de PORTHLPMC) : délai d'inactivité avant transition L1, en unités de 128 μs
pub const PORTHLPMC_L1_TIMEOUT_SHIFT: u32 = 8;
pub const PORTHLPMC_L1_TIMEOUT_MASK: u32 = 0xFF << PORTHLPMC_L1_TIMEOUT_SHIFT;

/// Décalage et masque Best Effort Service Latency Deep (bits 19:16 de PORTHLPMC) : latence BESLD pour LPM
pub const PORTHLPMC_BEST_EFFORT_SVC_LATENCY_SHIFT: u32 = 16;
pub const PORTHLPMC_BEST_EFFORT_SVC_LATENCY_MASK: u32 =
    0xF << PORTHLPMC_BEST_EFFORT_SVC_LATENCY_SHIFT;

/// Paramètres de contrôle matériel USB 3.1 LPM décodés depuis le registre PORTHLPMC (section 5.4.11).
///
/// Ce registre contrôle la gestion automatique des transitions de lien L1 (USB 2.0 LPM) par le
/// matériel xHCI, permettant de réduire la consommation énergétique sans intervention logicielle
/// pour chaque transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortHlpmc {
    /// Active la gestion matérielle LPM (Hardware LPM Enable, bit 0)
    pub hle_enabled: bool,
    /// Valeur HIRD/BESL négociée pour la transition L1 (bits 5:2, 4 bits)
    pub hird_besl: u8,
    /// Délai d'inactivité avant transition automatique en L1 (bits 15:8), en unités de 128 μs
    pub l1_timeout_128us: u8,
    /// Latence de service optimale profonde BESLD (bits 19:16, 4 bits)
    pub best_effort_latency: u8,
}

impl PortHlpmc {
    /// Décode la valeur brute 32-bit lue depuis le registre PORTHLPMC.
    pub const fn parse(raw: u32) -> Self {
        let hle_enabled = (raw & PORTHLPMC_HLE_BIT) != 0;
        let hird_besl = ((raw & PORTHLPMC_HIRD_BESL_MASK) >> PORTHLPMC_HIRD_BESL_SHIFT) as u8;
        let l1_timeout_128us =
            ((raw & PORTHLPMC_L1_TIMEOUT_MASK) >> PORTHLPMC_L1_TIMEOUT_SHIFT) as u8;
        let best_effort_latency = ((raw & PORTHLPMC_BEST_EFFORT_SVC_LATENCY_MASK)
            >> PORTHLPMC_BEST_EFFORT_SVC_LATENCY_SHIFT) as u8;
        Self {
            hle_enabled,
            hird_besl,
            l1_timeout_128us,
            best_effort_latency,
        }
    }

    /// Encode la structure en valeur de registre PORTHLPMC 32-bit.
    pub const fn encode(&self) -> u32 {
        let hle = if self.hle_enabled {
            PORTHLPMC_HLE_BIT
        } else {
            0
        };
        let hird =
            ((self.hird_besl as u32) << PORTHLPMC_HIRD_BESL_SHIFT) & PORTHLPMC_HIRD_BESL_MASK;
        let timeout = ((self.l1_timeout_128us as u32) << PORTHLPMC_L1_TIMEOUT_SHIFT)
            & PORTHLPMC_L1_TIMEOUT_MASK;
        let besld = ((self.best_effort_latency as u32) << PORTHLPMC_BEST_EFFORT_SVC_LATENCY_SHIFT)
            & PORTHLPMC_BEST_EFFORT_SVC_LATENCY_MASK;
        hle | hird | timeout | besld
    }

    /// Retourne le délai d'inactivité L1 en microsecondes (l1_timeout_128us × 128).
    pub const fn l1_timeout_us(&self) -> u32 {
        self.l1_timeout_128us as u32 * 128
    }
}

/// Masque RW1C (Read-Write 1 to Clear) regroupant tous les bits de changement d'état xHCI
pub const PORTSC_ALL_CHANGES_MASK: u32 =
    PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;

/// Vitesse de négociation du port USB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    Unknown(u8),
    FullSpeed,      // 12 Mb/s (USB 1.1 / 2.0)
    LowSpeed,       // 1.5 Mb/s (USB 1.0 / 2.0)
    HighSpeed,      // 480 Mb/s (USB 2.0)
    SuperSpeed,     // 5 Gb/s (USB 3.0 / 3.1 Gen 1)
    SuperSpeedPlus, // 10 Gb/s (USB 3.1 Gen 2 / 3.2)
}

impl Default for UsbSpeed {
    fn default() -> Self {
        UsbSpeed::Unknown(0)
    }
}

/// État décodé d'un port Root-Hub xHCI incluant la télémétrie des changements dynamiques (CSC/PPC/PEC/PRC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortStatus {
    pub connected: bool,
    pub enabled: bool,
    pub reset: bool,
    pub powered: bool,
    pub over_current: bool,
    pub speed: UsbSpeed,
    pub link_state: u8,
    // Bits de changement d'état (Change Indicators)
    pub change_connect: bool,      // CSC (bit 17)
    pub change_enable: bool,       // PEC (bit 18)
    pub change_warm_reset: bool,   // WRC (bit 19)
    pub change_over_current: bool, // OCC (bit 20)
    pub change_reset: bool,        // PRC (bit 21)
    pub change_link_state: bool,   // PLC (bit 22)
    pub change_config_error: bool, // CEC (bit 23)
}

impl PortStatus {
    /// Décode la valeur brute du registre 32 bits PORTSC.
    pub fn parse(raw: u32) -> Self {
        let connected = (raw & PORTSC_CCS) != 0;
        let enabled = (raw & PORTSC_PED) != 0;
        let over_current = (raw & PORTSC_OCA) != 0;
        let reset = (raw & PORTSC_PR) != 0;
        let link_state = ((raw >> 5) & 0x0F) as u8;
        let powered = (raw & PORTSC_PP) != 0;
        let speed_raw = ((raw >> 10) & 0x0F) as u8;

        let speed = match speed_raw {
            1 => UsbSpeed::FullSpeed,
            2 => UsbSpeed::LowSpeed,
            3 => UsbSpeed::HighSpeed,
            4 => UsbSpeed::SuperSpeed,
            5 => UsbSpeed::SuperSpeedPlus,
            other => UsbSpeed::Unknown(other),
        };

        Self {
            connected,
            enabled,
            reset,
            powered,
            over_current,
            speed,
            link_state,
            change_connect: (raw & PORTSC_CSC) != 0,
            change_enable: (raw & PORTSC_PEC) != 0,
            change_warm_reset: (raw & PORTSC_WRC) != 0,
            change_over_current: (raw & PORTSC_OCC) != 0,
            change_reset: (raw & PORTSC_PRC) != 0,
            change_link_state: (raw & PORTSC_PLC) != 0,
            change_config_error: (raw & PORTSC_CEC) != 0,
        }
    }

    /// Calcule la valeur d'acquittement RW1C (Read-Write 1 to Clear) pour réinitialiser
    /// les drapeaux de notification matérielle sans altérer les bits de contrôle d'alimentation ou de reset.
    pub fn acknowledge_changes_mask(&self) -> u32 {
        let mut mask = 0u32;
        if self.change_connect {
            mask |= PORTSC_CSC;
        }
        if self.change_enable {
            mask |= PORTSC_PEC;
        }
        if self.change_warm_reset {
            mask |= PORTSC_WRC;
        }
        if self.change_over_current {
            mask |= PORTSC_OCC;
        }
        if self.change_reset {
            mask |= PORTSC_PRC;
        }
        if self.change_link_state {
            mask |= PORTSC_PLC;
        }
        if self.change_config_error {
            mask |= PORTSC_CEC;
        }
        mask
    }

    /// Calcule la nouvelle valeur 32 bits de PORTSC pour initier une transition d'état de lien de port
    /// (ex: U3 Suspend, Resume U0, RxDetect) selon la spécification xHCI 1.2.
    ///
    /// Conserve les bits d'état stables (PP), positionne le bit stroboscopique LWS (Port Link State Write Strobe),
    /// affecte le champ PLS (bits 8:5) et efface les bits RW1C pour éviter un acquittement accidentel.
    pub fn build_port_link_state_write(raw_portsc: u32, target_pls: u8) -> u32 {
        // Préserve le bit PP (Port Power)
        let pp_bit = raw_portsc & PORTSC_PP;
        // Efface les bits RW1C (changes), le bit de reset PR, le strobe LWS et l'ancien PLS
        let preserved = pp_bit;
        // Positionne LWS et le nouveau PLS
        preserved | PORTSC_LWS | (((target_pls as u32) & 0x0F) << PORTSC_PLS_SHIFT)
    }

    /// Calcule la valeur 32 bits de PORTSC pour commuter l'alimentation du port (Port Power Down ou Power Up).
    /// Si `power_on` est vrai, positionne le bit PP (1 << 9). Si faux, le bit PP est effacé (Power Down).
    /// Tous les bits RW1C sont masqués (mis à zéro) afin de préserver les interruptions en cours.
    pub fn build_port_power_write(raw_portsc: u32, power_on: bool) -> u32 {
        let mut val = 0u32;
        if power_on {
            val |= PORTSC_PP;
        }
        // Préserver le PLS actuel s'il était alimenté, sinon RxDetect / Disabled
        if power_on {
            val |= raw_portsc & PORTSC_PLS_MASK;
        }
        // Ne jamais réécrire les bits RW1C ni PR
        val
    }

    /// Calcule la valeur d'écriture pour acquitter une condition de surintensité (OCC - Over-Current Change, bit 20).
    ///
    /// Conserve le statut d'alimentation (PP) et écrit 1 sur OCC pour acquitter l'interruption matérielle,
    /// tout en maintenant à 0 les autres drapeaux RW1C pour éviter d'effacer les événements concurrents.
    pub fn build_over_current_ack_write(raw_portsc: u32) -> u32 {
        let pp_bit = raw_portsc & PORTSC_PP;
        pp_bit | PORTSC_OCC
    }

    /// Vérifie si le port est actuellement dans un état de surintensité active (OCA, bit 3)
    /// ou si un changement de surintensité non acquitté est en attente (OCC, bit 20).
    pub fn is_over_current_active(raw_portsc: u32) -> bool {
        (raw_portsc & PORTSC_OCA) != 0 || (raw_portsc & PORTSC_OCC) != 0
    }

    /// Vérifie si l'état de lien actuel du port correspond au mode de conformité (Compliance Mode, PLS = 10).
    pub fn is_compliance_mode(raw_portsc: u32) -> bool {
        ((raw_portsc & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT) as u8 == PLS_COMPLIANCE_MODE
    }

    /// Calcule la commande de récupération pour forcer la sortie du mode de conformité (Compliance Mode)
    /// vers l'état RxDetect (PLS 5) ou Disabled (PLS 4) avec assertion du strobe LWS,
    /// permettant au lien SuperSpeed de tenter une nouvelle séquence de synchronisation et de training.
    pub fn build_exit_compliance_write(raw_portsc: u32) -> u32 {
        let pp_bit = raw_portsc & PORTSC_PP;
        pp_bit | PORTSC_LWS | (((PLS_RXDETECT as u32) & 0x0F) << PORTSC_PLS_SHIFT)
    }

    /// Calcule la commande d'amorce de reprise forcée de veille (Force Port Resume - FPR, transition U3 -> Resume).
    ///
    /// Selon la spec xHCI 1.2 section 4.19.1.1, pour réveiller un port suspendu en U3 (PLS = 3),
    /// le logiciel écrit la valeur PLS = 15 (Resume) dans PORTSC avec le bit LWS positionné.
    /// Pour un port USB 2.0 (High-Speed / Full-Speed / Low-Speed), cela envoie le signal K-state de Resume
    /// pendant au moins 20 ms. Pour un port SuperSpeed USB 3.x, cela déclenche le trainage LFPS U3 Wakeup.
    pub fn build_force_port_resume_write(raw_portsc: u32) -> u32 {
        let pp_bit = raw_portsc & PORTSC_PP;
        pp_bit | PORTSC_LWS | (((PLS_RESUME as u32) & 0x0F) << PORTSC_PLS_SHIFT)
    }

    /// Calcule la commande de finalisation de reprise de veille (transition Resume -> U0 opérationnel).
    ///
    /// Après l'expiration du délai de reprise matérielle (ex: 20 ms pour USB 2.0 ou fin d'handshake LFPS USB 3.0),
    /// le logiciel écrit la valeur PLS = 0 (U0) dans PORTSC avec LWS=1 pour basculer le lien en mode opérationnel actif.
    pub fn build_complete_port_resume_write(raw_portsc: u32) -> u32 {
        let pp_bit = raw_portsc & PORTSC_PP;
        pp_bit | PORTSC_LWS | (((PLS_U0 as u32) & 0x0F) << PORTSC_PLS_SHIFT)
    }

    /// Évalue si la transition de reprise U3 -> U0 a dépassé le délai maximum de synchronisation (timeout).
    ///
    /// - `elapsed_micros` : Temps écoulé depuis le début de la séquence de reprise en microsecondes.
    /// - `speed` : Vitesse négociée du port.
    ///
    /// Selon la spécification USB 2.0 / USB 3.2 et xHCI 1.2 :
    /// - En USB 2.0 (HS/FS/LS), la séquence de signalisation Resume dure 20 ms (20 000 µs), timeout d'échec fixé à 50 ms (50 000 µs).
    /// - En USB 3.x SuperSpeed / SuperSpeedPlus, le réveil LFPS U3 Wakeup s'effectue en moins de 10 ms (10 000 µs), timeout d'échec à 20 ms (20 000 µs).
    pub fn is_resume_timed_out(elapsed_micros: u64, speed: UsbSpeed) -> bool {
        match speed {
            UsbSpeed::SuperSpeed | UsbSpeed::SuperSpeedPlus => elapsed_micros > 20_000,
            _ => elapsed_micros > 50_000,
        }
    }

    /// Vérifie si le lien a atteint avec succès l'état U0 opérationnel actif.
    pub fn is_link_operational_u0(raw_portsc: u32) -> bool {
        let pls = ((raw_portsc & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT) as u8;
        pls == PLS_U0 && (raw_portsc & PORTSC_PED) != 0
    }

    /// Calcule la valeur d'écriture pour le registre PORTPMSC (USB 3.0 / SuperSpeed)
    /// afin de configurer les timers d'inactivité matérielle pour l'entrée automatique en veille U1 et U2.
    ///
    /// Selon la spec xHCI 1.2 section 5.4.9.1 :
    /// - `u1_timeout` : Délai d'inactivité avant transition U0 -> U1 (0 = désactivé, 1..=127 = 1 µs à 127 µs, 0xFF = infini).
    /// - `u2_timeout` : Délai d'inactivité avant transition U1 -> U2 (0 = désactivé, 1..=254 = multiple de 256 µs, 0xFF = infini).
    /// - `force_link_pm_accept` (FLA) : Force l'acceptation des requêtes de mise en veille U1/U2 initiées par le périphérique.
    pub fn build_usb3_portpmsc_write(
        u1_timeout: u8,
        u2_timeout: u8,
        force_link_pm_accept: bool,
    ) -> u32 {
        Self::build_usb3_portpmsc_full_write(u1_timeout, u2_timeout, force_link_pm_accept, 0)
    }

    /// Calcule la valeur d'écriture complète pour le registre PORTPMSC (USB 3.0 / SuperSpeed)
    /// incluant la configuration du délai d'abandon de paquet de transfert (Transfer Packet Pending Timeouts / TPP).
    ///
    /// Selon la spec xHCI 1.2 section 5.4.9.1 :
    /// - `u1_timeout` : Délai d'inactivité avant transition U0 -> U1 (0 = désactivé, 1..=127 = 1 µs à 127 µs, 0xFF = infini).
    /// - `u2_timeout` : Délai d'inactivité avant transition U1 -> U2 (0 = désactivé, 1..=254 = multiple de 256 µs, 0xFF = infini).
    /// - `force_link_pm_accept` (FLA) : Force l'acceptation des requêtes de mise en veille U1/U2.
    /// - `tpp_timeout` : Transfer Packet Pending Timeout (bits 23:17, 0..=127 en multiples de 8 µs ou 128 µs selon vitesse du lien).
    pub fn build_usb3_portpmsc_full_write(
        u1_timeout: u8,
        u2_timeout: u8,
        force_link_pm_accept: bool,
        tpp_timeout: u8,
    ) -> u32 {
        let mut val = (u1_timeout as u32) << PORTPMSC_U1_TIMEOUT_SHIFT;
        val |= (u2_timeout as u32) << PORTPMSC_U2_TIMEOUT_SHIFT;
        if force_link_pm_accept {
            val |= PORTPMSC_FLA;
        }
        val |= ((tpp_timeout & 0x7F) as u32) << PORTPMSC_USB3_TPP_TIMEOUT_SHIFT;
        val
    }

    /// Calcule la valeur d'écriture pour le registre PORTPMSC (USB 2.0 / LPM - Link Power Management)
    /// pour configurer la mise en veille L1 et la durée de reprise initiée par l'hôte (HIRD).
    ///
    /// Selon la spec xHCI 1.2 section 5.4.9.2 et USB 2.0 Link Power Management ECN :
    /// - `hird` : Host Initiated Resume Duration (valeur de 0 à 15 représentant le délai de réveil en pas de 50 µs).
    /// - `remote_wake_enable` (RWE) : Autorise le périphérique USB 2.0 à sortir de veille L1 par lui-même.
    /// - `l1_device_state` (L1S) : Statut ou cible L1 (0 = L1 Disabled/Invalid, 1 = L1 Success/Go).
    pub fn build_usb2_lpm_portpmsc_write(
        hird: u8,
        remote_wake_enable: bool,
        l1_device_state: u8,
    ) -> u32 {
        let mut val = ((l1_device_state & 0x03) as u32) << PORTPMSC_L1S_SHIFT;
        val |= ((hird & 0x0F) as u32) << PORTPMSC_HIRD_SHIFT;
        if remote_wake_enable {
            val |= PORTPMSC_RWE;
        }
        val
    }

    /// Valide si les seuils de temporisation U1/U2 sont conformes aux spécifications SuperSpeed USB 3.0 / xHCI 1.2.
    ///
    /// - U1 timeout ne doit pas excéder 127 µs (ou 0xFF pour désactivation infinie).
    /// - U2 timeout ne doit pas excéder 254 (en unités de 256 µs, soit ~65 ms). Si fixé à 0xFF, cela représente l'inactivité infinie (désactivation).
    ///
    /// Selon la spec xHCI 1.2, les valeurs valides pour U1 sont 0x00..=0x7F ainsi que 0xFF, et pour U2 0x00..=0xFE ainsi que 0xFF.
    pub fn validate_u1_u2_timers(u1_timeout: u8, u2_timeout: u8) -> bool {
        (u1_timeout <= 127 || u1_timeout == 0xFF) && (u2_timeout <= 254 || u2_timeout == 0xFF)
    }

    /// Vérifie si le port présente une erreur de configuration (Configuration Error Change - bit CEC de PORTSC).
    ///
    /// Selon la spécification xHCI 1.2 section 5.4.8, le bit CEC (bit 23) indique qu'une tentative
    /// d'entraînement de lien USB 3.0 SuperSpeed a échoué car le contrôleur et le périphérique
    /// n'ont pas pu s'accorder sur une configuration de lien valide (ex: échec d'échange de paquets TS1/TS2).
    pub fn is_config_error(raw_portsc: u32) -> bool {
        (raw_portsc & PORTSC_CEC) != 0
    }

    /// Construit la valeur d'écriture pour acquitter le bit de changement d'erreur de configuration (CEC).
    ///
    /// Préserve l'alimentation du port (PP) tout en évitant d'effacer les autres bits RW1C.
    pub fn build_config_error_ack_write(raw_portsc: u32) -> u32 {
        let pp_bit = raw_portsc & PORTSC_PP;
        pp_bit | PORTSC_CEC
    }
}

// ============================================================================
// Descripteurs et Protocole USB Hub (USB 2.0 & SuperSpeed Hub USB 3.0)
// ============================================================================

pub const USB_DESC_TYPE_HUB: u8 = 0x29;
pub const USB_DESC_TYPE_SS_HUB: u8 = 0x2A;

pub const HUB_REQ_GET_STATUS: u8 = 0x00;
pub const HUB_REQ_CLEAR_FEATURE: u8 = 0x01;
pub const HUB_REQ_SET_FEATURE: u8 = 0x03;
pub const HUB_REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const HUB_REQ_SET_DESCRIPTOR: u8 = 0x07;

pub const PORT_FEAT_CONNECTION: u16 = 0;
pub const PORT_FEAT_ENABLE: u16 = 1;
pub const PORT_FEAT_SUSPEND: u16 = 2;
pub const PORT_FEAT_OVER_CURRENT: u16 = 3;
pub const PORT_FEAT_RESET: u16 = 4;
pub const PORT_FEAT_POWER: u16 = 8;
pub const PORT_FEAT_C_CONNECTION: u16 = 16;
pub const PORT_FEAT_C_ENABLE: u16 = 17;
pub const PORT_FEAT_C_SUSPEND: u16 = 18;
pub const PORT_FEAT_C_OVER_CURRENT: u16 = 19;
pub const PORT_FEAT_C_RESET: u16 = 20;

/// Descripteur de concentrateur USB Hub 2.0 (RFC USB 2.0 Section 11.23.2.1)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbHubDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub num_ports: u8,
    pub characteristics: u16,
    pub power_on_to_power_good: u8,
    pub hub_controller_current: u8,
    pub device_removable: u8,
}

impl UsbHubDescriptor {
    #[inline]
    pub fn ports(&self) -> u8 {
        self.num_ports
    }
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.descriptor_type == USB_DESC_TYPE_HUB && self.length >= 7
    }
}

/// Descripteur de concentrateur SuperSpeed USB 3.0 (USB 3.0 Section 10.13.2.1)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbSsHubDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub num_ports: u8,
    pub characteristics: u16,
    pub power_on_to_power_good: u8,
    pub hub_controller_current: u8,
    pub hub_hdr_dec_lat: u8,
    pub hub_delay: u16,
    pub device_removable: u16,
}

impl UsbSsHubDescriptor {
    #[inline]
    pub fn ports(&self) -> u8 {
        self.num_ports
    }
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.descriptor_type == USB_DESC_TYPE_SS_HUB && self.length >= 12
    }
}

/// Statut d'un Hub USB et changements d'état
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsbHubStatus {
    pub local_power_lost: bool,
    pub over_current: bool,
    pub change_local_power: bool,
    pub change_over_current: bool,
}

impl UsbHubStatus {
    pub fn parse(status_raw: u16, change_raw: u16) -> Self {
        Self {
            local_power_lost: (status_raw & 1) != 0,
            over_current: (status_raw & 2) != 0,
            change_local_power: (change_raw & 1) != 0,
            change_over_current: (change_raw & 2) != 0,
        }
    }
}

/// Statut détaillé et drapeaux de changement d'un port Hub
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HubPortStatusAndChange {
    pub connected: bool,
    pub enabled: bool,
    pub suspend: bool,
    pub over_current: bool,
    pub reset: bool,
    pub powered: bool,
    pub low_speed: bool,
    pub high_speed: bool,
    pub speed: UsbSpeed,
    pub change_connect: bool,
    pub change_enable: bool,
    pub change_suspend: bool,
    pub change_over_current: bool,
    pub change_reset: bool,
}

impl HubPortStatusAndChange {
    pub fn parse(status_raw: u16, change_raw: u16) -> Self {
        let connected = (status_raw & (1 << 0)) != 0;
        let enabled = (status_raw & (1 << 1)) != 0;
        let suspend = (status_raw & (1 << 2)) != 0;
        let over_current = (status_raw & (1 << 3)) != 0;
        let reset = (status_raw & (1 << 4)) != 0;
        let powered = (status_raw & (1 << 8)) != 0;
        let low_speed = (status_raw & (1 << 9)) != 0;
        let high_speed = (status_raw & (1 << 10)) != 0;

        let speed = if high_speed {
            UsbSpeed::HighSpeed
        } else if low_speed {
            UsbSpeed::LowSpeed
        } else if enabled {
            UsbSpeed::FullSpeed
        } else {
            UsbSpeed::Unknown(0)
        };

        Self {
            connected,
            enabled,
            suspend,
            over_current,
            reset,
            powered,
            low_speed,
            high_speed,
            speed,
            change_connect: (change_raw & (1 << 0)) != 0,
            change_enable: (change_raw & (1 << 1)) != 0,
            change_suspend: (change_raw & (1 << 2)) != 0,
            change_over_current: (change_raw & (1 << 3)) != 0,
            change_reset: (change_raw & (1 << 4)) != 0,
        }
    }
}

// ============================================================================
// Descripteurs USB Standard & Décodage des Flux Isochronous et Bulk (USB 2.0 / 3.x)
// ============================================================================

pub const USB_DESC_TYPE_DEVICE: u8 = 0x01;
pub const USB_DESC_TYPE_CONFIGURATION: u8 = 0x02;
pub const USB_DESC_TYPE_STRING: u8 = 0x03;
pub const USB_DESC_TYPE_INTERFACE: u8 = 0x04;
pub const USB_DESC_TYPE_ENDPOINT: u8 = 0x05;
pub const USB_DESC_TYPE_HID: u8 = 0x21;
pub const USB_DESC_TYPE_HID_REPORT: u8 = 0x22;
pub const USB_DESC_TYPE_SS_ENDPOINT_COMPANION: u8 = 0x30;

pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_SUBCLASS_BOOT_INTERFACE: u8 = 0x01;
pub const USB_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const USB_PROTOCOL_MOUSE: u8 = 0x02;

pub const USB_EP_DIR_MASK: u8 = 0x80;
pub const USB_EP_DIR_IN: u8 = 0x80;
pub const USB_EP_DIR_OUT: u8 = 0x00;

pub const USB_EP_ATTR_TYPE_MASK: u8 = 0x03;
pub const USB_EP_ATTR_CONTROL: u8 = 0x00;
pub const USB_EP_ATTR_ISOCHRONOUS: u8 = 0x01;
pub const USB_EP_ATTR_BULK: u8 = 0x02;
pub const USB_EP_ATTR_INTERRUPT: u8 = 0x03;

/// Direction de transfert d'un point d'accès USB (Endpoint Direction)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsbEndpointDirection {
    #[default]
    Out = 0,
    In = 1,
}

/// Type de transfert de point d'accès USB (Endpoint Transfer Type)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsbEndpointType {
    #[default]
    Control = 0,
    Isochronous = 1,
    Bulk = 2,
    Interrupt = 3,
}

/// Descripteur de Configuration USB Standard (RFC USB 2.0 / USB 3.2 section 9.6.3)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbConfigurationDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub configuration_string: u8,
    pub attributes: u8,
    pub max_power: u8,
}

impl UsbConfigurationDescriptor {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.length >= 9 && self.descriptor_type == USB_DESC_TYPE_CONFIGURATION
    }

    #[inline]
    pub fn max_power_ma(&self) -> u16 {
        (self.max_power as u16) * 2
    }
}

/// Descripteur d'Interface USB Standard (Section 9.6.5)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbInterfaceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub interface_string: u8,
}

impl UsbInterfaceDescriptor {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.length >= 9 && self.descriptor_type == USB_DESC_TYPE_INTERFACE
    }
}

/// Descripteur de Point d'Accès Endpoint USB Standard (Section 9.6.6)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbEndpointDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub endpoint_address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl UsbEndpointDescriptor {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.length >= 7 && self.descriptor_type == USB_DESC_TYPE_ENDPOINT
    }

    #[inline]
    pub fn endpoint_number(&self) -> u8 {
        self.endpoint_address & 0x0F
    }

    #[inline]
    pub fn direction(&self) -> UsbEndpointDirection {
        if (self.endpoint_address & USB_EP_DIR_MASK) != 0 {
            UsbEndpointDirection::In
        } else {
            UsbEndpointDirection::Out
        }
    }

    #[inline]
    pub fn transfer_type(&self) -> UsbEndpointType {
        match self.attributes & USB_EP_ATTR_TYPE_MASK {
            USB_EP_ATTR_CONTROL => UsbEndpointType::Control,
            USB_EP_ATTR_ISOCHRONOUS => UsbEndpointType::Isochronous,
            USB_EP_ATTR_BULK => UsbEndpointType::Bulk,
            USB_EP_ATTR_INTERRUPT => UsbEndpointType::Interrupt,
            _ => UsbEndpointType::Control,
        }
    }

    #[inline]
    pub fn packet_size(&self) -> u16 {
        self.max_packet_size & 0x07FF
    }

    #[inline]
    pub fn mult(&self) -> u8 {
        ((self.max_packet_size >> 11) & 0x03) as u8
    }

    #[inline]
    pub fn is_bulk(&self) -> bool {
        self.transfer_type() == UsbEndpointType::Bulk
    }

    #[inline]
    pub fn is_isochronous(&self) -> bool {
        self.transfer_type() == UsbEndpointType::Isochronous
    }

    #[inline]
    pub fn is_interrupt(&self) -> bool {
        self.transfer_type() == UsbEndpointType::Interrupt
    }
}

/// Descripteur SuperSpeed Endpoint Companion (USB 3.0 section 9.6.7)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbSsEndpointCompanionDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub max_burst: u8,
    pub attributes: u8,
    pub bytes_per_interval: u16,
}

impl UsbSsEndpointCompanionDescriptor {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.length >= 6 && self.descriptor_type == USB_DESC_TYPE_SS_ENDPOINT_COMPANION
    }

    #[inline]
    pub fn max_streams(&self) -> u8 {
        let raw = self.attributes & 0x1F;
        if raw > 0 {
            1 << raw
        } else {
            0
        }
    }

    #[inline]
    pub fn mult(&self) -> u8 {
        (self.attributes & 0x03) + 1
    }
}

/// Descripteur fonctionnel USB HID Standard (USB HID Spec 1.11 Section 6.2.1)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbHidDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub bcd_hid: u16,
    pub country_code: u8,
    pub num_descriptors: u8,
    pub report_descriptor_type: u8,
    pub report_descriptor_length: u16,
}

impl UsbHidDescriptor {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.length >= 9 && self.descriptor_type == USB_DESC_TYPE_HID
    }
}

/// Point d'accès USB décodé avec sémantique xHCI (Device Context Index calculé)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsbDecodedEndpoint {
    pub endpoint_address: u8,
    pub ep_number: u8,
    pub direction: UsbEndpointDirection,
    pub ep_type: UsbEndpointType,
    pub max_packet_size: u16,
    pub interval: u8,
    pub mult: u8,
    pub max_burst: u8,
    pub max_streams: u8,
    pub dci: u8,
}

impl UsbDecodedEndpoint {
    #[inline]
    pub fn is_bulk(&self) -> bool {
        self.ep_type == UsbEndpointType::Bulk
    }

    #[inline]
    pub fn is_isochronous(&self) -> bool {
        self.ep_type == UsbEndpointType::Isochronous
    }

    #[inline]
    pub fn is_interrupt(&self) -> bool {
        self.ep_type == UsbEndpointType::Interrupt
    }

    #[inline]
    pub fn is_in(&self) -> bool {
        self.direction == UsbEndpointDirection::In
    }

    #[inline]
    pub fn is_out(&self) -> bool {
        self.direction == UsbEndpointDirection::Out
    }
}

/// Interface USB décodée contenant ses endpoints associés
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsbDecodedInterface {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub hid_descriptor: Option<UsbHidDescriptor>,
    pub endpoints: [UsbDecodedEndpoint; 8],
    pub endpoint_count: usize,
}

impl UsbDecodedInterface {
    /// Indique si l'interface correspond à la classe USB HID
    #[inline]
    pub fn is_hid(&self) -> bool {
        self.class == USB_CLASS_HID
    }

    /// Indique si l'interface est un clavier HID Boot Protocol
    #[inline]
    pub fn is_hid_keyboard(&self) -> bool {
        self.is_hid()
            && self.subclass == USB_SUBCLASS_BOOT_INTERFACE
            && self.protocol == USB_PROTOCOL_KEYBOARD
    }

    /// Indique si l'interface est une souris HID Boot Protocol
    #[inline]
    pub fn is_hid_mouse(&self) -> bool {
        self.is_hid()
            && self.subclass == USB_SUBCLASS_BOOT_INTERFACE
            && self.protocol == USB_PROTOCOL_MOUSE
    }

    /// Indique si l'interface correspond à la classe USB Mass Storage avec transport Bulk-Only Transport (BOT)
    pub fn is_mass_storage_bot(&self) -> bool {
        self.class == 0x08
            && (self.subclass == 0x06 || self.subclass == 0x05 || self.subclass == 0x01)
            && self.protocol == 0x50
    }

    /// Détecte la paire d'endpoints Bulk IN et Bulk OUT pour l'interface de stockage
    pub fn find_bot_endpoints(&self) -> Option<(u8, u8)> {
        let mut bulk_in = None;
        let mut bulk_out = None;
        for ep in &self.endpoints[..self.endpoint_count] {
            if ep.is_bulk() {
                if ep.is_in() && bulk_in.is_none() {
                    bulk_in = Some(ep.ep_number);
                } else if ep.is_out() && bulk_out.is_none() {
                    bulk_out = Some(ep.ep_number);
                }
            }
        }
        match (bulk_in, bulk_out) {
            (Some(i), Some(o)) => Some((i, o)),
            _ => None,
        }
    }
}

/// Configuration USB décodée avec arbre d'interfaces et d'endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsbDecodedConfiguration {
    pub configuration_value: u8,
    pub attributes: u8,
    pub max_power_ma: u16,
    pub interfaces: [UsbDecodedInterface; 4],
    pub interface_count: usize,
}

impl UsbDecodedConfiguration {
    pub fn total_endpoints(&self) -> usize {
        let mut count = 0;
        for iface in &self.interfaces[..self.interface_count] {
            count += iface.endpoint_count;
        }
        count
    }

    /// Recherche la paire de points d'accès Bulk (Bulk IN, Bulk OUT)
    pub fn find_bulk_endpoints(&self) -> (Option<UsbDecodedEndpoint>, Option<UsbDecodedEndpoint>) {
        let mut bulk_in = None;
        let mut bulk_out = None;

        for iface in &self.interfaces[..self.interface_count] {
            for ep in &iface.endpoints[..iface.endpoint_count] {
                if ep.is_bulk() {
                    if ep.is_in() && bulk_in.is_none() {
                        bulk_in = Some(*ep);
                    } else if ep.is_out() && bulk_out.is_none() {
                        bulk_out = Some(*ep);
                    }
                }
            }
        }
        (bulk_in, bulk_out)
    }

    /// Extrait les points d'accès Isochronous de la configuration
    pub fn find_isochronous_endpoints(&self, out: &mut [UsbDecodedEndpoint; 4]) -> usize {
        let mut count = 0;
        for iface in &self.interfaces[..self.interface_count] {
            for ep in &iface.endpoints[..iface.endpoint_count] {
                if ep.is_isochronous() && count < out.len() {
                    out[count] = *ep;
                    count += 1;
                }
            }
        }
        count
    }

    /// Extrait les interfaces HID et leurs points d'accès Interruption IN associés
    pub fn find_hid_endpoints(
        &self,
        out: &mut [(UsbDecodedInterface, UsbDecodedEndpoint); 4],
    ) -> usize {
        let mut count = 0;
        for iface in &self.interfaces[..self.interface_count] {
            if iface.is_hid() {
                for ep in &iface.endpoints[..iface.endpoint_count] {
                    if ep.is_interrupt() && ep.is_in() && count < out.len() {
                        out[count] = (*iface, *ep);
                        count += 1;
                    }
                }
            }
        }
        count
    }
}

/// Décodeur et analyseur de descripteurs de configuration USB sans allocation sur le tas
pub struct UsbConfigParser;

impl UsbConfigParser {
    /// Analyse un flux d'octets de descripteur de configuration USB complet (Configuration + Interfaces + Endpoints)
    pub fn parse_configuration(bytes: &[u8]) -> Result<UsbDecodedConfiguration, SysError> {
        if bytes.len() < 9 {
            return Err(SysError::InvalidArgument);
        }

        let config_len = bytes[0] as usize;
        let config_type = bytes[1];
        if config_len < 9 || config_type != USB_DESC_TYPE_CONFIGURATION {
            return Err(SysError::InvalidArgument);
        }

        let total_length = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        if total_length < 9 || total_length > bytes.len() {
            return Err(SysError::InvalidArgument);
        }

        let mut decoded = UsbDecodedConfiguration {
            configuration_value: bytes[5],
            attributes: bytes[7],
            max_power_ma: (bytes[8] as u16) * 2,
            interfaces: [UsbDecodedInterface::default(); 4],
            interface_count: 0,
        };

        let mut pos = config_len;
        let mut current_iface_idx: Option<usize> = None;
        let mut current_ep_idx: Option<usize> = None;

        while pos < total_length {
            if pos + 2 > total_length {
                break;
            }
            let desc_len = bytes[pos] as usize;
            let desc_type = bytes[pos + 1];

            if desc_len < 2 || pos + desc_len > total_length {
                return Err(SysError::InvalidArgument);
            }

            let desc_slice = &bytes[pos..pos + desc_len];

            match desc_type {
                USB_DESC_TYPE_INTERFACE => {
                    if desc_len >= 9 && decoded.interface_count < decoded.interfaces.len() {
                        let idx = decoded.interface_count;
                        decoded.interfaces[idx] = UsbDecodedInterface {
                            interface_number: desc_slice[2],
                            alternate_setting: desc_slice[3],
                            class: desc_slice[5],
                            subclass: desc_slice[6],
                            protocol: desc_slice[7],
                            hid_descriptor: None,
                            endpoints: [UsbDecodedEndpoint::default(); 8],
                            endpoint_count: 0,
                        };
                        decoded.interface_count += 1;
                        current_iface_idx = Some(idx);
                        current_ep_idx = None;
                    }
                }
                USB_DESC_TYPE_HID if desc_len >= 9 => {
                    if let Some(iface_idx) = current_iface_idx {
                        let bcd_hid = u16::from_le_bytes([desc_slice[2], desc_slice[3]]);
                        let country_code = desc_slice[4];
                        let num_descriptors = desc_slice[5];
                        let report_descriptor_type = desc_slice[6];
                        let report_descriptor_length =
                            u16::from_le_bytes([desc_slice[7], desc_slice[8]]);

                        decoded.interfaces[iface_idx].hid_descriptor = Some(UsbHidDescriptor {
                            length: desc_len as u8,
                            descriptor_type: desc_type,
                            bcd_hid,
                            country_code,
                            num_descriptors,
                            report_descriptor_type,
                            report_descriptor_length,
                        });
                    }
                }
                USB_DESC_TYPE_ENDPOINT => {
                    if desc_len >= 7 {
                        if let Some(iface_idx) = current_iface_idx {
                            let iface = &mut decoded.interfaces[iface_idx];
                            if iface.endpoint_count < iface.endpoints.len() {
                                let ep_idx = iface.endpoint_count;
                                let ep_addr = desc_slice[2];
                                let ep_num = ep_addr & 0x0F;
                                let is_in = (ep_addr & USB_EP_DIR_MASK) != 0;
                                let raw_type = desc_slice[3] & USB_EP_ATTR_TYPE_MASK;
                                let ep_type = match raw_type {
                                    USB_EP_ATTR_CONTROL => UsbEndpointType::Control,
                                    USB_EP_ATTR_ISOCHRONOUS => UsbEndpointType::Isochronous,
                                    USB_EP_ATTR_BULK => UsbEndpointType::Bulk,
                                    USB_EP_ATTR_INTERRUPT => UsbEndpointType::Interrupt,
                                    _ => UsbEndpointType::Control,
                                };
                                let max_pkt_raw =
                                    u16::from_le_bytes([desc_slice[4], desc_slice[5]]);
                                let pkt_size = max_pkt_raw & 0x07FF;
                                let mult = ((max_pkt_raw >> 11) & 0x03) as u8;
                                let interval = desc_slice[6];
                                // Calcul du Device Context Index xHCI (DCI = 2 * ep_num + if IN 1 else 0)
                                let dci = (ep_num * 2) + if is_in { 1 } else { 0 };

                                iface.endpoints[ep_idx] = UsbDecodedEndpoint {
                                    endpoint_address: ep_addr,
                                    ep_number: ep_num,
                                    direction: if is_in {
                                        UsbEndpointDirection::In
                                    } else {
                                        UsbEndpointDirection::Out
                                    },
                                    ep_type,
                                    max_packet_size: pkt_size,
                                    interval,
                                    mult,
                                    max_burst: 0,
                                    max_streams: 0,
                                    dci,
                                };
                                iface.endpoint_count += 1;
                                current_ep_idx = Some(ep_idx);
                            }
                        }
                    }
                }
                USB_DESC_TYPE_SS_ENDPOINT_COMPANION if desc_len >= 6 => {
                    if let (Some(iface_idx), Some(ep_idx)) = (current_iface_idx, current_ep_idx) {
                        let ep = &mut decoded.interfaces[iface_idx].endpoints[ep_idx];
                        let burst = desc_slice[2];
                        let attr = desc_slice[3];
                        ep.max_burst = burst;
                        if ep.is_bulk() {
                            let stream_shift = attr & 0x1F;
                            if stream_shift > 0 {
                                ep.max_streams = 1 << stream_shift;
                            }
                        } else if ep.is_isochronous() {
                            ep.mult = (attr & 0x03) + 1;
                        }
                    }
                }
                _ => {}
            }

            pos += desc_len;
        }

        Ok(decoded)
    }
}

// ============================================================================
// USB Mass Storage Bulk-Only Transport (BOT) & Commandes SCSI Transparentes
// ============================================================================

pub const CBW_SIGNATURE: u32 = 0x4342_5355; // "USBC"
pub const CSW_SIGNATURE: u32 = 0x5342_5355; // "USBS"

pub const CBW_FLAG_DATA_IN: u8 = 0x80;
pub const CBW_FLAG_DATA_OUT: u8 = 0x00;

pub const CSW_STATUS_PASSED: u8 = 0x00;
pub const CSW_STATUS_FAILED: u8 = 0x01;
pub const CSW_STATUS_PHASE_ERROR: u8 = 0x02;

pub const SCSI_CMD_TEST_UNIT_READY: u8 = 0x00;
pub const SCSI_CMD_REQUEST_SENSE: u8 = 0x03;
pub const SCSI_CMD_INQUIRY: u8 = 0x12;
pub const SCSI_CMD_MODE_SELECT_6: u8 = 0x15;
pub const SCSI_CMD_MODE_SENSE_6: u8 = 0x1A;
pub const SCSI_CMD_START_STOP_UNIT: u8 = 0x1B;
pub const SCSI_CMD_PREVENT_ALLOW_MEDIUM_REMOVAL: u8 = 0x1E;
pub const SCSI_CMD_READ_CAPACITY_10: u8 = 0x25;
pub const SCSI_CMD_READ_10: u8 = 0x28;
pub const SCSI_CMD_WRITE_10: u8 = 0x2A;
pub const SCSI_CMD_VERIFY_10: u8 = 0x2F;
pub const SCSI_CMD_SYNCHRONIZE_CACHE_10: u8 = 0x35;
pub const SCSI_CMD_READ_DEFECT_DATA_10: u8 = 0x37;
pub const SCSI_CMD_UNMAP: u8 = 0x42;
pub const SCSI_CMD_MODE_SELECT_10: u8 = 0x55;
pub const SCSI_CMD_MODE_SENSE_10: u8 = 0x5A;
pub const SCSI_CMD_READ_16: u8 = 0x88;
pub const SCSI_CMD_WRITE_16: u8 = 0x8E;
pub const SCSI_CMD_VERIFY_16: u8 = 0x8F;
pub const SCSI_CMD_SYNCHRONIZE_CACHE_16: u8 = 0x91;
pub const SCSI_CMD_SERVICE_ACTION_IN_16: u8 = 0x9E;
pub const SCSI_CMD_REPORT_LUNS: u8 = 0xA0;
pub const SCSI_CMD_RECEIVE_DIAGNOSTIC_RESULTS: u8 = 0x1C;
pub const SCSI_CMD_SEND_DIAGNOSTIC: u8 = 0x1D;
pub const SCSI_SA_READ_CAPACITY_16: u8 = 0x10;
pub const SCSI_PAGE_CACHING: u8 = 0x08;
/// Page de contrôle des exceptions d'information SCSI (Page 0x1C - Informational Exceptions Control / SMART SPC-4)
pub const SCSI_PAGE_INFORMATIONAL_EXCEPTIONS: u8 = 0x1C;

pub const SCSI_REPORT_LUNS_ALL: u8 = 0x00;
pub const SCSI_REPORT_LUNS_WELL_KNOWN: u8 = 0x01;
pub const SCSI_REPORT_LUNS_ALL_EXCEPT_WELL_KNOWN: u8 = 0x02;

pub const SCSI_DEFECT_FORMAT_BLOCK: u8 = 0x00;
pub const SCSI_DEFECT_FORMAT_BYTES_FROM_INDEX: u8 = 0x04;
pub const SCSI_DEFECT_FORMAT_PHYSICAL_SECTOR: u8 = 0x05;

pub const SCSI_SELF_TEST_CODE_DEFAULT: u8 = 0x00;
pub const SCSI_SELF_TEST_CODE_BACKGROUND_SHORT: u8 = 0x01;
pub const SCSI_SELF_TEST_CODE_BACKGROUND_EXTENDED: u8 = 0x02;
pub const SCSI_SELF_TEST_CODE_ABORT_BACKGROUND: u8 = 0x04;
pub const SCSI_SELF_TEST_CODE_FOREGROUND_SHORT: u8 = 0x05;
pub const SCSI_SELF_TEST_CODE_FOREGROUND_EXTENDED: u8 = 0x06;

/// Page de diagnostic SCSI Translate Address (Page 0x40 - Diagnostic Results)
pub const SCSI_DIAG_PAGE_TRANSLATE_ADDRESS: u8 = 0x40;
/// Page de diagnostic SCSI Device Status (Page 0x00 - Supported Pages)
pub const SCSI_DIAG_PAGE_SUPPORTED_PAGES: u8 = 0x00;

/// En-tête de réponse SCSI RECEIVE DIAGNOSTIC RESULTS (SPC-4)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiDiagnosticResultsHeader {
    /// Code de la page diagnostique retournée
    pub page_code: u8,
    /// Longueur de la page diagnostique en octets (hors en-tête de 4 octets)
    pub page_length: u16,
    /// Indicateur d'auto-test réussi (Self-Test OK)
    pub self_test_passed: bool,
}

/// Résultat d'analyse de la page SCSI Translate Address (Page 0x40 - SPC-4 Diagnostic Results)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiTranslateAddressPage {
    /// Code de page (0x40)
    pub page_code: u8,
    /// Format d'adresse retourné (0x00 = Bloc LBA, 0x04 = Octets depuis index, 0x05 = Secteur physique)
    pub address_format: u8,
    /// LBA physique ou logique traduit (64 bits)
    pub translated_lba: u64,
    /// Numéro de cylindre ou tête physique (le cas échéant)
    pub cylinder: u32,
    pub head: u8,
    pub sector: u32,
}

/// Paramètres de la page SCSI Informational Exceptions Control (Page 0x1C - SMART T10 SPC-4)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiInformationalExceptionsPage {
    /// Code de la page (0x1C)
    pub page_code: u8,
    /// Longueur de la page (typiquement 10 octets)
    pub page_length: u8,
    /// Performance bit (perf: true = temporisation autorisée)
    pub perf: bool,
    /// Enable Warning bit (ewasc: true = avertissements prédictifs SMART activés)
    pub ewasc: bool,
    /// Disable Exception Control (dexcpt: true = exceptions désactivées, false = exceptions actives)
    pub dexcpt: bool,
    /// Method of Reporting Informational Exceptions (MRIE) :
    /// 0x00 = Pas de rapport, 0x01 = Asynchronous event reporting,
    /// 0x02 = Generate unit attention, 0x03 = Conditionally generate recovered error,
    /// 0x04 = Unconditionally generate recovered error, 0x05 = Generate sense data,
    /// 0x06 = Only on request (polling via REQUEST SENSE).
    pub mrie: u8,
    /// Intervalle de scrutation/interval timer (en unités de 100 ms)
    pub interval_timer: u32,
    /// Compteur d'occurrences de l'événement (report count)
    pub report_count: u32,
}

/// En-tête de réponse SCSI REPORT LUNS (SPC-4) (8 octets minimum)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiReportLunsHeader {
    /// Longueur totale de la liste de LUNs en octets (n * 8 octets)
    pub lun_list_length: u32,
    /// Nombre de descripteurs LUN retournés
    pub lun_count: usize,
}

/// En-tête de réponse SCSI READ DEFECT DATA (10) (SBC-3) (4 octets minimum)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiDefectDataHeader10 {
    /// Format de la liste de défauts (bits 0-2)
    pub defect_list_format: u8,
    /// Indicateur liste primaire (P) présente
    pub primary_defect_list: bool,
    /// Indicateur liste de croissance (G) présente
    pub grown_defect_list: bool,
    /// Longueur de la liste de défauts en octets
    pub defect_list_length: u16,
}

/// En-tête des paramètres retournés par SCSI MODE SENSE (6) (4 octets minimum)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiModeParameterHeader6 {
    pub mode_data_length: u8,
    pub medium_type: u8,
    pub device_specific_parameter: u8,
    pub write_protected: bool,
    pub block_descriptor_length: u8,
}

/// En-tête des paramètres retournés par SCSI MODE SENSE (10) (8 octets minimum)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiModeParameterHeader10 {
    pub mode_data_length: u16,
    pub medium_type: u8,
    pub device_specific_parameter: u8,
    pub write_protected: bool,
    pub long_lba: bool,
    pub block_descriptor_length: u16,
}

/// Paramètres de la page SCSI Caching Mode Page (Page 0x08, SPC-4 / SBC-3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiCachingModePage {
    pub page_code: u8,
    pub page_length: u8,
    pub write_cache_enabled: bool,
    pub read_cache_disable: bool,
    pub multiplication_factor: bool,
}

/// Paquet de requête Setup standard USB (8 octets, USB 2.0 / USB 3.x)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsbSetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl UsbSetupPacket {
    pub fn new(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> Self {
        Self {
            request_type,
            request,
            value,
            index,
            length,
        }
    }

    #[inline]
    pub fn request_type(&self) -> u8 {
        self.request_type
    }

    #[inline]
    pub fn request(&self) -> u8 {
        self.request
    }

    #[inline]
    pub fn value(&self) -> u16 {
        self.value
    }

    #[inline]
    pub fn index(&self) -> u16 {
        self.index
    }

    #[inline]
    pub fn length(&self) -> u16 {
        self.length
    }

    /// Convertit le paquet de contrôle en mot de 64 bits pour les champs TRB Setup Stage
    pub fn to_raw_u64(&self) -> u64 {
        let b = [
            self.request_type,
            self.request,
            (self.value & 0xFF) as u8,
            ((self.value >> 8) & 0xFF) as u8,
            (self.index & 0xFF) as u8,
            ((self.index >> 8) & 0xFF) as u8,
            (self.length & 0xFF) as u8,
            ((self.length >> 8) & 0xFF) as u8,
        ];
        u64::from_le_bytes(b)
    }
}

/// Étape de la procédure de réinitialisation et de recouvrement d'erreur BOT (Bulk-Only Reset Recovery)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbBotResetStep {
    Step1MassStorageReset,
    Step2ClearHaltIn,
    Step3ClearHaltOut,
    Completed,
}

/// Erreurs de transport USB Mass Storage BOT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbBotError {
    InvalidSignature,
    TagMismatch,
    PhaseError,
    CommandFailed { residue: u32 },
    ResidueOverflow,
    DeviceNotReady,
    WriteProtected,
}

/// Données décodées de requête SCSI REQUEST SENSE (18 octets standard)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiSenseData {
    pub response_code: u8,
    pub sense_key: u8,
    pub asc: u8,
    pub ascq: u8,
    pub information: u32,
}

impl ScsiSenseData {
    #[inline]
    pub fn is_valid(&self) -> bool {
        (self.response_code & 0x70) == 0x70
    }

    #[inline]
    pub fn is_unit_attention(&self) -> bool {
        (self.sense_key & 0x0F) == 0x06
    }

    #[inline]
    pub fn is_not_ready(&self) -> bool {
        (self.sense_key & 0x0F) == 0x02
    }

    #[inline]
    pub fn is_write_protected(&self) -> bool {
        (self.sense_key & 0x0F) == 0x07 || (self.asc == 0x27 && self.ascq == 0x00)
    }
}

/// Command Block Wrapper (31 octets, USB Mass Storage Class BOT RFC 1.0)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandBlockWrapper {
    pub signature: u32,
    pub tag: u32,
    pub data_transfer_length: u32,
    pub flags: u8,
    pub lun: u8,
    pub cb_length: u8,
    pub cb: [u8; 16],
}

impl CommandBlockWrapper {
    pub fn new(tag: u32, transfer_length: u32, is_in: bool, lun: u8, cb_len: u8) -> Self {
        Self {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_length: transfer_length,
            flags: if is_in {
                CBW_FLAG_DATA_IN
            } else {
                CBW_FLAG_DATA_OUT
            },
            lun: lun & 0x0F,
            cb_length: cb_len.min(16),
            cb: [0u8; 16],
        }
    }

    #[inline]
    pub fn signature(&self) -> u32 {
        self.signature
    }

    #[inline]
    pub fn tag(&self) -> u32 {
        self.tag
    }

    #[inline]
    pub fn data_transfer_length(&self) -> u32 {
        self.data_transfer_length
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    #[inline]
    pub fn lun(&self) -> u8 {
        self.lun
    }

    #[inline]
    pub fn cb_length(&self) -> u8 {
        self.cb_length
    }

    #[inline]
    pub fn is_data_in(&self) -> bool {
        (self.flags & CBW_FLAG_DATA_IN) != 0
    }

    /// Exporte la structure CBW sous forme de tableau d'octets contigu (31 octets)
    pub fn as_bytes(&self) -> [u8; 31] {
        let mut buf = [0u8; 31];
        // SAFETY: Copie mémoire de 31 octets depuis self vers buf
        unsafe {
            core::ptr::copy_nonoverlapping(self as *const Self as *const u8, buf.as_mut_ptr(), 31);
        }
        buf
    }
}

/// Command Status Wrapper (13 octets)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommandStatusWrapper {
    pub signature: u32,
    pub tag: u32,
    pub data_residue: u32,
    pub status: u8,
}

impl CommandStatusWrapper {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 13 {
            return None;
        }
        let mut csw = Self::default();
        // SAFETY: Copie mémoire de 13 octets depuis bytes vers csw
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), &mut csw as *mut Self as *mut u8, 13);
        }
        if csw.signature == CSW_SIGNATURE {
            Some(csw)
        } else {
            None
        }
    }
}

/// Données décodées SCSI INQUIRY (36 octets)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScsiInquiryInfo {
    pub peripheral_device_type: u8,
    pub is_removable: bool,
    pub vendor_id: [u8; 8],
    pub product_id: [u8; 16],
    pub product_rev: [u8; 4],
}

/// Capacité géométrique retournée par SCSI READ CAPACITY (10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiCapacity10 {
    pub last_lba: u32,
    pub block_size: u32,
    pub total_sectors: u64,
    pub total_bytes: u64,
}

/// Capacité géométrique retournée par SCSI READ CAPACITY (16) (pour supports > 2 To)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiCapacity16 {
    pub last_lba: u64,
    pub block_size: u32,
    pub total_sectors: u64,
    pub total_bytes: u64,
    pub prot_en: bool,
    pub p_type: u8,
}

/// Gestionnaire de transport USB Mass Storage BOT
#[derive(Debug, Clone, Copy)]
pub struct UsbMassStorageBot {
    pub slot_id: u8,
    pub bulk_in_ep: u8,
    pub bulk_out_ep: u8,
    pub lun: u8,
    pub current_tag: u32,
    pub sector_size: u32,
    pub total_sectors: u64,
    pub is_ready: bool,
}

impl UsbMassStorageBot {
    pub fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8) -> Self {
        Self {
            slot_id,
            bulk_in_ep,
            bulk_out_ep,
            lun: 0,
            current_tag: 1,
            sector_size: 512,
            total_sectors: 0,
            is_ready: false,
        }
    }

    fn next_tag(&mut self) -> u32 {
        let tag = self.current_tag;
        self.current_tag = self.current_tag.wrapping_add(1);
        if self.current_tag == 0 {
            self.current_tag = 1;
        }
        tag
    }

    /// Construit un CBW pour SCSI TEST UNIT READY (0 octet de données)
    pub fn build_cbw_test_unit_ready(&mut self) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 0, false, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_TEST_UNIT_READY;
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI INQUIRY (36 octets attendus)
    pub fn build_cbw_inquiry(&mut self) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 36, true, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_INQUIRY;
        cbw.cb[4] = 36; // Allocation length
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI READ CAPACITY (10) (8 octets attendus)
    pub fn build_cbw_read_capacity_10(&mut self) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 8, true, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_READ_CAPACITY_10;
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI READ (10)
    pub fn build_cbw_read_10(&mut self, lba: u32, block_count: u16) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let byte_len = (block_count as u32) * self.sector_size;
        let mut cbw = CommandBlockWrapper::new(tag, byte_len, true, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_READ_10;
        let lba_be = lba.to_be_bytes();
        cbw.cb[2..6].copy_from_slice(&lba_be);
        let blocks_be = block_count.to_be_bytes();
        cbw.cb[7..9].copy_from_slice(&blocks_be);
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI WRITE (10)
    pub fn build_cbw_write_10(&mut self, lba: u32, block_count: u16) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let byte_len = (block_count as u32) * self.sector_size;
        let mut cbw = CommandBlockWrapper::new(tag, byte_len, false, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_WRITE_10;
        let lba_be = lba.to_be_bytes();
        cbw.cb[2..6].copy_from_slice(&lba_be);
        let blocks_be = block_count.to_be_bytes();
        cbw.cb[7..9].copy_from_slice(&blocks_be);
        (cbw, tag)
    }

    /// Décode la réponse standard SCSI INQUIRY (36 octets)
    pub fn parse_inquiry_response(&self, data: &[u8]) -> Option<ScsiInquiryInfo> {
        if data.len() < 36 {
            return None;
        }
        let peripheral_device_type = data[0] & 0x1F;
        let is_removable = (data[1] & 0x80) != 0;
        let mut vendor_id = [0u8; 8];
        let mut product_id = [0u8; 16];
        let mut product_rev = [0u8; 4];

        vendor_id.copy_from_slice(&data[8..16]);
        product_id.copy_from_slice(&data[16..32]);
        product_rev.copy_from_slice(&data[32..36]);

        Some(ScsiInquiryInfo {
            peripheral_device_type,
            is_removable,
            vendor_id,
            product_id,
            product_rev,
        })
    }

    /// Décode la réponse READ CAPACITY (10) (8 octets : LBA u32 BE, BlockSize u32 BE)
    pub fn parse_read_capacity_10(&mut self, data: &[u8]) -> Option<ScsiCapacity10> {
        if data.len() < 8 {
            return None;
        }
        let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let total_sectors = (last_lba as u64).saturating_add(1);
        let total_bytes = total_sectors * (block_size as u64);

        self.sector_size = if block_size != 0 { block_size } else { 512 };
        self.total_sectors = total_sectors;
        self.is_ready = true;

        Some(ScsiCapacity10 {
            last_lba,
            block_size,
            total_sectors,
            total_bytes,
        })
    }

    /// Construit un CBW pour SCSI SYNCHRONIZE CACHE (10) (vidage matériel du cache CoW)
    pub fn build_cbw_synchronize_cache_10(
        &mut self,
        lba: u32,
        block_count: u16,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 0, false, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_SYNCHRONIZE_CACHE_10;
        let lba_be = lba.to_be_bytes();
        cbw.cb[2..6].copy_from_slice(&lba_be);
        let blocks_be = block_count.to_be_bytes();
        cbw.cb[7..9].copy_from_slice(&blocks_be);
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI READ (16) (Adressage LBA 64-bit et gros transferts)
    pub fn build_cbw_read_16(&mut self, lba: u64, block_count: u32) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let byte_len = (block_count as u64).saturating_mul(self.sector_size as u64);
        let transfer_len = if byte_len > u32::MAX as u64 {
            u32::MAX
        } else {
            byte_len as u32
        };
        let mut cbw = CommandBlockWrapper::new(tag, transfer_len, true, self.lun, 16);
        cbw.cb[0] = SCSI_CMD_READ_16;
        cbw.cb[1] = 0; // Flags / DPO / FUA
        cbw.cb[2..10].copy_from_slice(&lba.to_be_bytes());
        cbw.cb[10..14].copy_from_slice(&block_count.to_be_bytes());
        cbw.cb[14] = 0; // Group number
        cbw.cb[15] = 0; // Control
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI WRITE (16) (Adressage LBA 64-bit et gros transferts)
    pub fn build_cbw_write_16(&mut self, lba: u64, block_count: u32) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let byte_len = (block_count as u64).saturating_mul(self.sector_size as u64);
        let transfer_len = if byte_len > u32::MAX as u64 {
            u32::MAX
        } else {
            byte_len as u32
        };
        let mut cbw = CommandBlockWrapper::new(tag, transfer_len, false, self.lun, 16);
        cbw.cb[0] = SCSI_CMD_WRITE_16;
        cbw.cb[1] = 0;
        cbw.cb[2..10].copy_from_slice(&lba.to_be_bytes());
        cbw.cb[10..14].copy_from_slice(&block_count.to_be_bytes());
        cbw.cb[14] = 0;
        cbw.cb[15] = 0;
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI START STOP UNIT (0x1B) (Gestion d'énergie, spin-down et éjection)
    pub fn build_cbw_start_stop_unit(
        &mut self,
        immed: bool,
        load_eject: bool,
        start: bool,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 0, false, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_START_STOP_UNIT;
        cbw.cb[1] = if immed { 0x01 } else { 0x00 };
        cbw.cb[2] = 0;
        cbw.cb[3] = 0;
        let mut action_byte = 0u8;
        if load_eject {
            action_byte |= 0x02; // Bit 1: LOEJ (Load/Eject)
        }
        if start {
            action_byte |= 0x01; // Bit 0: START
        }
        cbw.cb[4] = action_byte;
        cbw.cb[5] = 0; // Control
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI UNMAP (0x42) (Désallocation de blocs / TRIM CoW)
    pub fn build_cbw_unmap(&mut self, parameter_list_length: u16) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw =
            CommandBlockWrapper::new(tag, parameter_list_length as u32, false, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_UNMAP;
        cbw.cb[1] = 0; // Anchor = 0
        cbw.cb[2..6].fill(0);
        cbw.cb[6] = 0; // Group number
        cbw.cb[7..9].copy_from_slice(&parameter_list_length.to_be_bytes());
        cbw.cb[9] = 0; // Control
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI READ CAPACITY (16) (LBA 64 bits pour volumes > 2 To)
    pub fn build_cbw_read_capacity_16(&mut self) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 32, true, self.lun, 16);
        cbw.cb[0] = SCSI_CMD_SERVICE_ACTION_IN_16;
        cbw.cb[1] = SCSI_SA_READ_CAPACITY_16;
        let alloc_len = 32u32.to_be_bytes();
        cbw.cb[10..14].copy_from_slice(&alloc_len);
        (cbw, tag)
    }

    /// Décode la réponse READ CAPACITY (16) (au moins 32 octets)
    pub fn parse_read_capacity_16(&mut self, data: &[u8]) -> Option<ScsiCapacity16> {
        if data.len() < 32 {
            return None;
        }
        let last_lba = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let block_size = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let prot_en = (data[12] & 0x01) != 0;
        let p_type = (data[12] >> 1) & 0x07;

        let total_sectors = last_lba.saturating_add(1);
        let total_bytes = total_sectors.saturating_mul(block_size as u64);

        self.sector_size = if block_size != 0 { block_size } else { 512 };
        self.total_sectors = total_sectors;
        self.is_ready = true;

        Some(ScsiCapacity16 {
            last_lba,
            block_size,
            total_sectors,
            total_bytes,
            prot_en,
            p_type,
        })
    }

    /// Valide un Command Status Wrapper (CSW) reçu en réponse d'une commande
    pub fn verify_csw(&self, expected_tag: u32, data: &[u8]) -> Result<u32, SysError> {
        let csw = CommandStatusWrapper::from_bytes(data).ok_or(SysError::InvalidArgument)?;
        if csw.tag != expected_tag {
            return Err(SysError::InvalidArgument);
        }
        if csw.status == CSW_STATUS_PASSED {
            Ok(csw.data_residue)
        } else {
            Err(SysError::BadAddress)
        }
    }

    /// Construit un CBW pour SCSI REQUEST SENSE (18 octets attendus)
    pub fn build_cbw_request_sense(&mut self) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 18, true, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_REQUEST_SENSE;
        cbw.cb[4] = 18; // Allocation length
        (cbw, tag)
    }

    /// Décode les données reçues en réponse à SCSI REQUEST SENSE (18 octets)
    pub fn parse_request_sense_response(&self, data: &[u8]) -> Option<ScsiSenseData> {
        if data.len() < 18 {
            return None;
        }
        let response_code = data[0] & 0x7F;
        let sense_key = data[2] & 0x0F;
        let info = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
        let asc = data[12];
        let ascq = data[13];

        Some(ScsiSenseData {
            response_code,
            sense_key,
            asc,
            ascq,
            information: info,
        })
    }

    /// Construit un CBW pour SCSI MODE SENSE (6) (détection d'écriture protégée / cache)
    pub fn build_cbw_mode_sense_6(&mut self, page_code: u8) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 192, true, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_MODE_SENSE_6;
        cbw.cb[2] = page_code & 0x3F;
        cbw.cb[4] = 192; // Allocation length
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI MODE SENSE (10) (supports de grande capacité et pages étendues)
    pub fn build_cbw_mode_sense_10(
        &mut self,
        page_code: u8,
        alloc_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, alloc_len as u32, true, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_MODE_SENSE_10;
        cbw.cb[2] = page_code & 0x3F;
        let len_bytes = alloc_len.to_be_bytes();
        cbw.cb[7] = len_bytes[0];
        cbw.cb[8] = len_bytes[1];
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI MODE SELECT (6) (configuration des paramètres et du cache WCE)
    pub fn build_cbw_mode_select_6(
        &mut self,
        pf: bool,
        sp: bool,
        param_len: u8,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, param_len as u32, false, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_MODE_SELECT_6;
        cbw.cb[1] = ((pf as u8) << 4) | (sp as u8);
        cbw.cb[4] = param_len;
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI MODE SELECT (10) (configuration étendue de périphériques blocs)
    pub fn build_cbw_mode_select_10(
        &mut self,
        pf: bool,
        sp: bool,
        param_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, param_len as u32, false, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_MODE_SELECT_10;
        cbw.cb[1] = ((pf as u8) << 4) | (sp as u8);
        let len_bytes = param_len.to_be_bytes();
        cbw.cb[7] = len_bytes[0];
        cbw.cb[8] = len_bytes[1];
        (cbw, tag)
    }

    /// Sérialise un en-tête SCSI Mode Parameter Header (6) dans le tampon fourni (4 octets)
    pub fn serialize_mode_select_6_header(
        medium_type: u8,
        dsp: u8,
        block_desc_len: u8,
        buf: &mut [u8],
    ) -> usize {
        if buf.len() < 4 {
            return 0;
        }
        buf[0] = 0; // Mode Data Length réservé (défini à 0 pour MODE SELECT)
        buf[1] = medium_type;
        buf[2] = dsp;
        buf[3] = block_desc_len;
        4
    }

    /// Sérialise un en-tête SCSI Mode Parameter Header (10) dans le tampon fourni (8 octets)
    pub fn serialize_mode_select_10_header(
        medium_type: u8,
        dsp: u8,
        block_desc_len: u16,
        buf: &mut [u8],
    ) -> usize {
        if buf.len() < 8 {
            return 0;
        }
        buf[0] = 0; // Réservé pour MODE SELECT
        buf[1] = 0; // Réservé pour MODE SELECT
        buf[2] = medium_type;
        buf[3] = dsp;
        buf[4] = 0; // Flags réservés / DPOFUA
        buf[5] = 0; // Réservé
        let bdl = block_desc_len.to_be_bytes();
        buf[6] = bdl[0];
        buf[7] = bdl[1];
        8
    }

    /// Sérialise une page de mode de mise en cache SCSI Caching Mode Page (Page 0x08, SPC-4 / SBC-3)
    /// Page de 10 octets de données utiles (longueur totale 12 octets avec code et longueur).
    pub fn serialize_caching_page(wce: bool, rcd: bool, buf: &mut [u8]) -> usize {
        if buf.len() < 12 {
            return 0;
        }
        buf[0] = SCSI_PAGE_CACHING; // 0x08
        buf[1] = 0x0A; // 10 octets de paramètres utiles
        let mut flags = 0u8;
        if wce {
            flags |= 0x04; // Write Cache Enable
        }
        if rcd {
            flags |= 0x01; // Read Cache Disable
        }
        buf[2] = flags;
        for b in &mut buf[3..12] {
            *b = 0;
        }
        12
    }

    /// Formate la charge utile complète pour SCSI MODE SELECT (6) avec en-tête et page de cache (16 octets)
    pub fn build_caching_mode_select_6_payload(wce: bool, rcd: bool, buf: &mut [u8]) -> usize {
        if buf.len() < 16 {
            return 0;
        }
        let h_len = Self::serialize_mode_select_6_header(0x00, 0x00, 0x00, buf);
        let p_len = Self::serialize_caching_page(wce, rcd, &mut buf[h_len..]);
        h_len + p_len
    }

    /// Formate la charge utile complète pour SCSI MODE SELECT (10) avec en-tête et page de cache (20 octets)
    pub fn build_caching_mode_select_10_payload(wce: bool, rcd: bool, buf: &mut [u8]) -> usize {
        if buf.len() < 20 {
            return 0;
        }
        let h_len = Self::serialize_mode_select_10_header(0x00, 0x00, 0x00, buf);
        let p_len = Self::serialize_caching_page(wce, rcd, &mut buf[h_len..]);
        h_len + p_len
    }

    /// Construit un CBW pour SCSI PREVENT ALLOW MEDIUM REMOVAL (verrouillage matériel du média)
    pub fn build_cbw_prevent_allow_medium_removal(
        &mut self,
        prevent: bool,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 0, false, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_PREVENT_ALLOW_MEDIUM_REMOVAL;
        cbw.cb[4] = if prevent { 0x01 } else { 0x00 };
        (cbw, tag)
    }

    /// Analyse l'en-tête retourné par MODE SENSE (6) pour déterminer si le support est en lecture seule (Write-Protected)
    pub fn parse_mode_sense_6_write_protect(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        // Byte 2 : Device-Specific Parameter. Bit 7 = WP (Write Protect)
        (data[2] & 0x80) != 0
    }

    /// Analyse l'en-tête complet des paramètres SCSI MODE SENSE (6)
    pub fn parse_mode_sense_6_header(&self, data: &[u8]) -> Option<ScsiModeParameterHeader6> {
        if data.len() < 4 {
            return None;
        }
        Some(ScsiModeParameterHeader6 {
            mode_data_length: data[0],
            medium_type: data[1],
            device_specific_parameter: data[2],
            write_protected: (data[2] & 0x80) != 0,
            block_descriptor_length: data[3],
        })
    }

    /// Analyse l'en-tête complet des paramètres SCSI MODE SENSE (10)
    pub fn parse_mode_sense_10_header(&self, data: &[u8]) -> Option<ScsiModeParameterHeader10> {
        if data.len() < 8 {
            return None;
        }
        let mode_data_length = u16::from_be_bytes([data[0], data[1]]);
        let medium_type = data[2];
        let dsp = data[3];
        let long_lba = (data[4] & 0x01) != 0;
        let block_descriptor_length = u16::from_be_bytes([data[6], data[7]]);

        Some(ScsiModeParameterHeader10 {
            mode_data_length,
            medium_type,
            device_specific_parameter: dsp,
            write_protected: (dsp & 0x80) != 0,
            long_lba,
            block_descriptor_length,
        })
    }

    /// Analyse la page de mode de mise en cache SCSI (Caching Mode Page 0x08)
    pub fn parse_caching_page(
        &self,
        data: &[u8],
        page_offset: usize,
    ) -> Option<ScsiCachingModePage> {
        if data.len() < page_offset + 3 {
            return None;
        }
        let page_code = data[page_offset] & 0x3F;
        if page_code != SCSI_PAGE_CACHING {
            return None;
        }
        let page_length = data[page_offset + 1];
        let flags = data[page_offset + 2];
        let write_cache_enabled = (flags & 0x04) != 0;
        let multiplication_factor = (flags & 0x02) != 0;
        let read_cache_disable = (flags & 0x01) != 0;

        Some(ScsiCachingModePage {
            page_code,
            page_length,
            write_cache_enabled,
            read_cache_disable,
            multiplication_factor,
        })
    }

    /// Construit un CBW pour SCSI REPORT LUNS (SPC-4, Opcode 0xA0) pour énumérer les LUNs disponibles
    pub fn build_cbw_report_luns(
        &mut self,
        select_report: u8,
        alloc_len: u32,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, alloc_len, true, self.lun, 12);
        cbw.cb[0] = SCSI_CMD_REPORT_LUNS;
        cbw.cb[2] = select_report;
        let len_bytes = alloc_len.to_be_bytes();
        cbw.cb[6] = len_bytes[0];
        cbw.cb[7] = len_bytes[1];
        cbw.cb[8] = len_bytes[2];
        cbw.cb[9] = len_bytes[3];
        (cbw, tag)
    }

    /// Analyse l'en-tête retourné par SCSI REPORT LUNS (8 premiers octets)
    pub fn parse_report_luns_header(&self, data: &[u8]) -> Option<ScsiReportLunsHeader> {
        if data.len() < 8 {
            return None;
        }
        let lun_list_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let lun_count = (lun_list_length as usize) / 8;
        Some(ScsiReportLunsHeader {
            lun_list_length,
            lun_count,
        })
    }

    /// Extrait un LUN (64 bits) à l'indice spécifié depuis les données REPORT LUNS
    pub fn parse_report_luns_entry(&self, data: &[u8], index: usize) -> Option<u64> {
        let offset = 8 + index * 8;
        if data.len() < offset + 8 {
            return None;
        }
        Some(u64::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]))
    }

    /// Construit un CBW pour SCSI READ DEFECT DATA (10) (SBC-3, Opcode 0x37)
    pub fn build_cbw_read_defect_data_10(
        &mut self,
        plist: bool,
        glist: bool,
        defect_format: u8,
        alloc_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, alloc_len as u32, true, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_READ_DEFECT_DATA_10;
        let flags = ((plist as u8) << 4) | ((glist as u8) << 3) | (defect_format & 0x07);
        cbw.cb[2] = flags;
        let len_bytes = alloc_len.to_be_bytes();
        cbw.cb[7] = len_bytes[0];
        cbw.cb[8] = len_bytes[1];
        (cbw, tag)
    }

    /// Analyse l'en-tête de réponse SCSI READ DEFECT DATA (10) (4 octets)
    pub fn parse_defect_data_10_header(&self, data: &[u8]) -> Option<ScsiDefectDataHeader10> {
        if data.len() < 4 {
            return None;
        }
        let flags = data[1];
        let defect_list_format = flags & 0x07;
        let grown_defect_list = (flags & 0x08) != 0;
        let primary_defect_list = (flags & 0x10) != 0;
        let defect_list_length = u16::from_be_bytes([data[2], data[3]]);

        Some(ScsiDefectDataHeader10 {
            defect_list_format,
            primary_defect_list,
            grown_defect_list,
            defect_list_length,
        })
    }

    /// Construit un CBW pour SCSI VERIFY (10) (SBC-3, Opcode 0x2F) pour vérifier l'intégrité sans transfert
    pub fn build_cbw_verify_10(
        &mut self,
        lba: u32,
        num_blocks: u16,
        bytchk: bool,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 0, false, self.lun, 10);
        cbw.cb[0] = SCSI_CMD_VERIFY_10;
        cbw.cb[1] = if bytchk { 0x02 } else { 0x00 };
        cbw.cb[2..6].copy_from_slice(&lba.to_be_bytes());
        cbw.cb[7..9].copy_from_slice(&num_blocks.to_be_bytes());
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI VERIFY (16) (SBC-3, Opcode 0x8F) pour vérifier l'intégrité LBA 64 bits
    pub fn build_cbw_verify_16(
        &mut self,
        lba: u64,
        num_blocks: u32,
        bytchk: bool,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 0, false, self.lun, 16);
        cbw.cb[0] = SCSI_CMD_VERIFY_16;
        cbw.cb[1] = if bytchk { 0x02 } else { 0x00 };
        cbw.cb[2..10].copy_from_slice(&lba.to_be_bytes());
        cbw.cb[10..14].copy_from_slice(&num_blocks.to_be_bytes());
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI SYNCHRONIZE CACHE (16) (SBC-3, Opcode 0x91) LBA 64-bit pour supports > 2 To
    pub fn build_cbw_synchronize_cache_16(
        &mut self,
        lba: u64,
        block_count: u32,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, 0, false, self.lun, 16);
        cbw.cb[0] = SCSI_CMD_SYNCHRONIZE_CACHE_16;
        cbw.cb[2..10].copy_from_slice(&lba.to_be_bytes());
        cbw.cb[10..14].copy_from_slice(&block_count.to_be_bytes());
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI SEND DIAGNOSTIC (SPC-4, Opcode 0x1D) pour déclencher l'auto-test matériel
    pub fn build_cbw_send_diagnostic(
        &mut self,
        self_test_code: u8,
        param_list_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let xfer_len = param_list_len as u32;
        let mut cbw = CommandBlockWrapper::new(tag, xfer_len, false, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_SEND_DIAGNOSTIC;
        // Byte 1: Self-Test Code (bits 7-5), SelfTest bit (bit 2 = 1 si self_test_code == 0)
        let self_test_bit = if self_test_code == SCSI_SELF_TEST_CODE_DEFAULT {
            0x04
        } else {
            0x00
        };
        cbw.cb[1] = ((self_test_code & 0x07) << 5) | self_test_bit;
        cbw.cb[3..5].copy_from_slice(&param_list_len.to_be_bytes());
        (cbw, tag)
    }

    /// Construit un CBW pour SCSI RECEIVE DIAGNOSTIC RESULTS (SPC-4, Opcode 0x1C) pour lire les diagnostics
    pub fn build_cbw_receive_diagnostic_results(
        &mut self,
        pcv: bool,
        page_code: u8,
        alloc_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        let tag = self.next_tag();
        let mut cbw = CommandBlockWrapper::new(tag, alloc_len as u32, true, self.lun, 6);
        cbw.cb[0] = SCSI_CMD_RECEIVE_DIAGNOSTIC_RESULTS;
        cbw.cb[1] = if pcv { 0x01 } else { 0x00 };
        cbw.cb[2] = page_code;
        cbw.cb[3..5].copy_from_slice(&alloc_len.to_be_bytes());
        (cbw, tag)
    }

    /// Décode l'en-tête retourné par SCSI RECEIVE DIAGNOSTIC RESULTS (SPC-4)
    pub fn parse_diagnostic_results_header(
        &self,
        data: &[u8],
    ) -> Option<ScsiDiagnosticResultsHeader> {
        if data.len() < 4 {
            return None;
        }
        let page_code = data[0];
        let page_length = u16::from_be_bytes([data[2], data[3]]);
        let self_test_passed = (data[1] & 0x01) == 0; // 0 = Passed, 1 = Error
        Some(ScsiDiagnosticResultsHeader {
            page_code,
            page_length,
            self_test_passed,
        })
    }

    /// Décode la page de diagnostic SCSI Translate Address (Page 0x40 - SPC-4 Diagnostic Results)
    pub fn parse_translate_address_page(&self, data: &[u8]) -> Option<ScsiTranslateAddressPage> {
        if data.len() < 14 {
            return None;
        }
        let page_code = data[0];
        if page_code != SCSI_DIAG_PAGE_TRANSLATE_ADDRESS {
            return None;
        }
        let address_format = data[4] & 0x07;
        let translated_lba = u64::from_be_bytes([
            data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13],
        ]);
        let (cylinder, head, sector) = if data.len() >= 22 {
            let cyl = u32::from_be_bytes([0, data[14], data[15], data[16]]);
            let h = data[17];
            let sec = u32::from_be_bytes([data[18], data[19], data[20], data[21]]);
            (cyl, h, sec)
        } else {
            (0, 0, 0)
        };

        Some(ScsiTranslateAddressPage {
            page_code,
            address_format,
            translated_lba,
            cylinder,
            head,
            sector,
        })
    }

    /// Décode une page SCSI Informational Exceptions Control (Page 0x1C - SPC-4 SMART)
    pub fn parse_informational_exceptions_page(
        &self,
        data: &[u8],
        page_offset: usize,
    ) -> Option<ScsiInformationalExceptionsPage> {
        if data.len() < page_offset + 12 {
            return None;
        }
        let page_code = data[page_offset] & 0x3F;
        if page_code != SCSI_PAGE_INFORMATIONAL_EXCEPTIONS {
            return None;
        }
        let page_length = data[page_offset + 1];
        let byte2 = data[page_offset + 2];
        let perf = (byte2 & 0x80) != 0;
        let ewasc = (byte2 & 0x10) != 0;
        let dexcpt = (byte2 & 0x08) != 0;
        let mrie = data[page_offset + 3] & 0x0F;
        let interval_timer = u32::from_be_bytes([
            data[page_offset + 4],
            data[page_offset + 5],
            data[page_offset + 6],
            data[page_offset + 7],
        ]);
        let report_count = u32::from_be_bytes([
            data[page_offset + 8],
            data[page_offset + 9],
            data[page_offset + 10],
            data[page_offset + 11],
        ]);

        Some(ScsiInformationalExceptionsPage {
            page_code,
            page_length,
            perf,
            ewasc,
            dexcpt,
            mrie,
            interval_timer,
            report_count,
        })
    }

    /// Sérialise une page SCSI Informational Exceptions Control (Page 0x1C) dans un tampon (12 octets)
    pub fn serialize_informational_exceptions_page(
        page: &ScsiInformationalExceptionsPage,
        buf: &mut [u8],
    ) -> usize {
        if buf.len() < 12 {
            return 0;
        }
        buf[0] = SCSI_PAGE_INFORMATIONAL_EXCEPTIONS; // 0x1C
        buf[1] = 10; // Page length (toujours 10 octets pour SPC-4 Page 0x1C)
        let mut byte2 = 0u8;
        if page.perf {
            byte2 |= 0x80;
        }
        if page.ewasc {
            byte2 |= 0x10;
        }
        if page.dexcpt {
            byte2 |= 0x08;
        }
        buf[2] = byte2;
        buf[3] = page.mrie & 0x0F;
        buf[4..8].copy_from_slice(&page.interval_timer.to_be_bytes());
        buf[8..12].copy_from_slice(&page.report_count.to_be_bytes());
        12
    }

    /// Construit le paquet Setup pour la réinitialisation de classe BOT (Bulk-Only Mass Storage Reset)
    pub fn build_bot_reset_packet(&self, interface_number: u8) -> UsbSetupPacket {
        UsbSetupPacket::new(0x21, 0xFF, 0, interface_number as u16, 0)
    }

    /// Construit le paquet Setup standard Clear Feature (ENDPOINT_HALT) pour débloquer un endpoint après STALL
    pub fn build_clear_feature_halt_packet(&self, is_in: bool) -> UsbSetupPacket {
        let ep_addr = if is_in {
            self.bulk_in_ep | 0x80
        } else {
            self.bulk_out_ep
        };
        UsbSetupPacket::new(0x02, 0x01, 0x0000, ep_addr as u16, 0)
    }

    /// Fait progresser l'automate de réinitialisation BOT vers l'étape suivante
    pub fn advance_reset_recovery(&mut self, step: UsbBotResetStep) -> UsbBotResetStep {
        match step {
            UsbBotResetStep::Step1MassStorageReset => UsbBotResetStep::Step2ClearHaltIn,
            UsbBotResetStep::Step2ClearHaltIn => UsbBotResetStep::Step3ClearHaltOut,
            UsbBotResetStep::Step3ClearHaltOut => UsbBotResetStep::Completed,
            UsbBotResetStep::Completed => UsbBotResetStep::Completed,
        }
    }

    /// Vérification complète et rigoureuse d'un CSW selon la spécification USB BOT 1.0 (Section 6.3)
    pub fn verify_csw_full(
        &self,
        expected_tag: u32,
        expected_transfer_len: u32,
        data: &[u8],
    ) -> Result<u32, UsbBotError> {
        let csw = CommandStatusWrapper::from_bytes(data).ok_or(UsbBotError::InvalidSignature)?;
        if csw.signature != CSW_SIGNATURE {
            return Err(UsbBotError::InvalidSignature);
        }
        if csw.tag != expected_tag {
            return Err(UsbBotError::TagMismatch);
        }
        if csw.data_residue > expected_transfer_len {
            return Err(UsbBotError::ResidueOverflow);
        }
        match csw.status {
            CSW_STATUS_PASSED => Ok(csw.data_residue),
            CSW_STATUS_FAILED => Err(UsbBotError::CommandFailed {
                residue: csw.data_residue,
            }),
            CSW_STATUS_PHASE_ERROR => Err(UsbBotError::PhaseError),
            _ => Err(UsbBotError::PhaseError),
        }
    }
}

/// Descripteur de bloc SCSI UNMAP (16 octets selon spécification T10 SBC-3)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScsiUnmapBlockDescriptor {
    /// Premier bloc LBA à déallouer
    pub unmap_lba: u64,
    /// Nombre de blocs logiques consécutifs
    pub num_blocks: u32,
    /// Champ réservé (0)
    pub reserved: u32,
}

impl ScsiUnmapBlockDescriptor {
    pub const fn new(lba: u64, num_blocks: u32) -> Self {
        Self {
            unmap_lba: lba,
            num_blocks,
            reserved: 0,
        }
    }
}

/// Disque de stockage de masse USB géré (USB Mass Storage Drive)
#[derive(Debug, Clone, Copy)]
pub struct UsbMassStorageDisk {
    pub bot: UsbMassStorageBot,
    pub inquiry: ScsiInquiryInfo,
    pub is_write_protected: bool,
    pub is_removable: bool,
    pub mounted: bool,
    pub write_cache_enabled: bool,
}

impl UsbMassStorageDisk {
    pub fn new(bot: UsbMassStorageBot, inquiry: ScsiInquiryInfo) -> Self {
        Self {
            bot,
            inquiry,
            is_write_protected: false,
            is_removable: inquiry.is_removable,
            mounted: false,
            write_cache_enabled: true,
        }
    }

    /// Capacité totale en octets
    #[inline]
    pub fn capacity_bytes(&self) -> u64 {
        self.bot.total_sectors * (self.bot.sector_size as u64)
    }

    /// Taille de secteur physique/logique
    #[inline]
    pub fn sector_size(&self) -> u32 {
        self.bot.sector_size
    }

    /// Nombre total de secteurs
    #[inline]
    pub fn total_sectors(&self) -> u64 {
        self.bot.total_sectors
    }

    /// Vérifie si l'adresse de bloc LBA et le compte de secteurs sont dans les limites du disque
    pub fn validate_lba_range(&self, lba: u64, count: u32) -> bool {
        if count == 0 {
            return false;
        }
        lba.checked_add(count as u64)
            .map(|end| end <= self.bot.total_sectors)
            .unwrap_or(false)
    }

    /// Construit un CBW pour SCSI TEST UNIT READY (vérifie si l'unité est prête aux transferts I/O)
    #[inline]
    pub fn build_test_unit_ready_cbw(&mut self) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_test_unit_ready()
    }

    /// Construit un CBW pour SCSI MODE SENSE (10)
    pub fn build_mode_sense_10_cbw(
        &mut self,
        page_code: u8,
        alloc_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_mode_sense_10(page_code, alloc_len)
    }

    /// Construit un CBW pour SCSI MODE SELECT (6)
    #[inline]
    pub fn build_mode_select_6_cbw(
        &mut self,
        pf: bool,
        sp: bool,
        param_len: u8,
    ) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_mode_select_6(pf, sp, param_len)
    }

    /// Construit un CBW pour SCSI MODE SELECT (10)
    #[inline]
    pub fn build_mode_select_10_cbw(
        &mut self,
        pf: bool,
        sp: bool,
        param_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_mode_select_10(pf, sp, param_len)
    }

    /// Construit un CBW pour SCSI PREVENT ALLOW MEDIUM REMOVAL (protection contre l'éjection intempestive)
    pub fn build_prevent_allow_cbw(&mut self, prevent: bool) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_prevent_allow_medium_removal(prevent)
    }

    /// Indique si le disque est en mode lecture seule (Write-Protected)
    #[inline]
    pub fn is_write_protected(&self) -> bool {
        self.is_write_protected
    }

    /// Met à jour l'état de protection en écriture
    #[inline]
    pub fn set_write_protected(&mut self, wp: bool) {
        self.is_write_protected = wp;
    }

    /// Indique si la mise en cache en écriture (Write Cache Enable) est active sur l'unité
    #[inline]
    pub fn is_write_cache_enabled(&self) -> bool {
        self.write_cache_enabled
    }

    /// Met à jour l'état local de mise en cache en écriture
    #[inline]
    pub fn set_write_cache_enabled(&mut self, enabled: bool) {
        self.write_cache_enabled = enabled;
    }

    /// Configure la politique de cache WCE (Write Cache Enable) via SCSI MODE SELECT (6).
    /// Si WCE est désactivé (false), tout accès disque devient write-through immédiat,
    /// immunisant l'Uberblock CoW contre les micro-coupures de courant.
    pub fn build_configure_write_cache_cbw(
        &mut self,
        enable_write_cache: bool,
        buffer: &mut [u8],
    ) -> Option<(CommandBlockWrapper, u32, usize)> {
        if buffer.len() < 16 {
            return None;
        }
        let payload_len = UsbMassStorageBot::build_caching_mode_select_6_payload(
            enable_write_cache,
            false,
            buffer,
        );
        let (cbw, tag) = self.build_mode_select_6_cbw(true, false, payload_len as u8);
        self.write_cache_enabled = enable_write_cache;
        Some((cbw, tag, payload_len))
    }

    /// Construit un CBW pour forcer la synchronisation matérielle du cache (Barrière de persistance CoW)
    #[inline]
    pub fn build_sync_cache_cbw(&mut self) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_synchronize_cache_10(0, 0)
    }

    /// Construit un CBW pour SCSI REPORT LUNS afin de détecter les unités logiques supplémentaires
    #[inline]
    pub fn build_report_luns_cbw(&mut self, alloc_len: u32) -> (CommandBlockWrapper, u32) {
        self.bot
            .build_cbw_report_luns(SCSI_REPORT_LUNS_ALL, alloc_len)
    }

    /// Construit un CBW pour SCSI READ DEFECT DATA (10) afin d'auditer l'état des secteurs défectueux
    #[inline]
    pub fn build_read_defect_data_cbw(
        &mut self,
        plist: bool,
        glist: bool,
        alloc_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        self.bot
            .build_cbw_read_defect_data_10(plist, glist, SCSI_DEFECT_FORMAT_BLOCK, alloc_len)
    }

    /// Construit un CBW pour SCSI VERIFY (10) afin de vérifier l'intégrité de secteurs physiques
    #[inline]
    pub fn build_verify_10_cbw(&mut self, lba: u32, num_blocks: u16) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_verify_10(lba, num_blocks, false)
    }

    /// Construit un CBW pour SCSI VERIFY (16) afin de vérifier l'intégrité de secteurs 64-bit
    #[inline]
    pub fn build_verify_16_cbw(&mut self, lba: u64, num_blocks: u32) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_verify_16(lba, num_blocks, false)
    }

    /// Construit un CBW pour SCSI SYNCHRONIZE CACHE (16) pour le vidage persistant LBA 64-bit (> 2 To)
    #[inline]
    pub fn build_sync_cache_16_cbw(
        &mut self,
        lba: u64,
        block_count: u32,
    ) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_synchronize_cache_16(lba, block_count)
    }

    /// Construit un CBW pour SCSI SEND DIAGNOSTIC afin de lancer un auto-test matériel (fond ou premier plan)
    #[inline]
    pub fn build_send_diagnostic_cbw(&mut self, self_test_code: u8) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_send_diagnostic(self_test_code, 0)
    }

    /// Construit un CBW pour SCSI RECEIVE DIAGNOSTIC RESULTS afin de collecter les résultats d'auto-test
    #[inline]
    pub fn build_receive_diagnostic_results_cbw(
        &mut self,
        page_code: u8,
        alloc_len: u16,
    ) -> (CommandBlockWrapper, u32) {
        self.bot
            .build_cbw_receive_diagnostic_results(page_code != 0, page_code, alloc_len)
    }

    /// Décode l'en-tête de résultats de diagnostic
    #[inline]
    pub fn parse_diagnostic_results_header(
        &self,
        data: &[u8],
    ) -> Option<ScsiDiagnosticResultsHeader> {
        self.bot.parse_diagnostic_results_header(data)
    }

    /// Décode la page de diagnostic SCSI Translate Address (Page 0x40 - SPC-4)
    #[inline]
    pub fn parse_translate_address_page(&self, data: &[u8]) -> Option<ScsiTranslateAddressPage> {
        self.bot.parse_translate_address_page(data)
    }

    /// Décode la page SCSI Informational Exceptions Control (Page 0x1C - SPC-4 SMART)
    #[inline]
    pub fn parse_informational_exceptions_page(
        &self,
        data: &[u8],
        page_offset: usize,
    ) -> Option<ScsiInformationalExceptionsPage> {
        self.bot
            .parse_informational_exceptions_page(data, page_offset)
    }

    /// Met à jour la géométrie du disque via les données décodées de READ CAPACITY (16)
    pub fn update_capacity_16(&mut self, cap: ScsiCapacity16) {
        self.bot.total_sectors = cap.total_sectors;
        self.bot.sector_size = cap.block_size;
    }

    /// Construit le CBW optimal pour une lecture (READ 10 ou READ 16 selon LBA et capacité)
    pub fn build_read_cbw(&mut self, lba: u64, count: u32) -> (CommandBlockWrapper, u32) {
        if lba <= 0xFFFF_FFFF && count <= 0xFFFF && self.bot.total_sectors <= 0x1_0000_0000 {
            self.bot.build_cbw_read_10(lba as u32, count as u16)
        } else {
            self.bot.build_cbw_read_16(lba, count)
        }
    }

    /// Construit le CBW optimal pour une écriture (WRITE 10 ou WRITE 16 selon LBA et capacité)
    pub fn build_write_cbw(&mut self, lba: u64, count: u32) -> (CommandBlockWrapper, u32) {
        if lba <= 0xFFFF_FFFF && count <= 0xFFFF && self.bot.total_sectors <= 0x1_0000_0000 {
            self.bot.build_cbw_write_10(lba as u32, count as u16)
        } else {
            self.bot.build_cbw_write_16(lba, count)
        }
    }

    /// Construit un CBW pour démarrer ou arrêter l'unité (spin-up / spin-down / éjection)
    pub fn build_start_stop_cbw(&mut self, start: bool, eject: bool) -> (CommandBlockWrapper, u32) {
        self.bot.build_cbw_start_stop_unit(false, eject, start)
    }

    /// Construit un CBW pour SCSI UNMAP et sérialise la liste de descripteurs dans le buffer de données fourni
    pub fn build_unmap_cbw(
        &mut self,
        descriptors: &[ScsiUnmapBlockDescriptor],
        out_buf: &mut [u8],
    ) -> Result<(CommandBlockWrapper, u32, usize), SysError> {
        let count = descriptors.len();
        let desc_data_len = (count * 16) as u16;
        let data_len = 6 + desc_data_len; // 8 octets d'en-tête - 2 octets du premier champ
        let total_param_len = 8 + (count * 16);

        if out_buf.len() < total_param_len {
            return Err(SysError::BufferTooSmall);
        }

        // UNMAP Data Length (Big-Endian, octets 0..2)
        out_buf[0..2].copy_from_slice(&data_len.to_be_bytes());
        // UNMAP Block Descriptor Data Length (Big-Endian, octets 2..4)
        out_buf[2..4].copy_from_slice(&desc_data_len.to_be_bytes());
        // Reserved (octets 4..8)
        out_buf[4..8].fill(0);

        // Copie des descripteurs
        let mut offset = 8;
        for desc in descriptors {
            out_buf[offset..offset + 8].copy_from_slice(&desc.unmap_lba.to_be_bytes());
            out_buf[offset + 8..offset + 12].copy_from_slice(&desc.num_blocks.to_be_bytes());
            out_buf[offset + 12..offset + 16].fill(0);
            offset += 16;
        }

        let (cbw, tag) = self.bot.build_cbw_unmap(total_param_len as u16);
        Ok((cbw, tag, total_param_len))
    }
}

// ============================================================================
// Interrupter & Anneau d'Événements xHCI (ERST / ERDP) - Spécification xHCI 1.2
// ============================================================================

/// Entrée dans la table de segments de l'anneau d'événements (Event Ring Segment Table Entry - ERSTE, 16 octets)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventRingSegmentTableEntry {
    pub ring_segment_base_address: u64,
    pub ring_segment_size: u32,
    pub reserved: u32,
}

/// Registres de gestion d'un Interrupter xHCI (Section 5.5.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciInterrupter {
    pub iman: u32,
    pub imod: u32,
    pub erstsz: u32,
    pub erstba: u64,
    pub erdp: u64,
    pub cycle_bit: bool,
    pub dequeue_idx: usize,
    pub ring_size: usize,
    pub events_handled: u64,
    pub active: bool,
}

impl Default for XhciInterrupter {
    fn default() -> Self {
        Self::new()
    }
}

impl XhciInterrupter {
    pub const fn new() -> Self {
        Self {
            iman: 0,
            imod: 0,
            erstsz: 0,
            erstba: 0,
            erdp: 0,
            cycle_bit: true,
            dequeue_idx: 0,
            ring_size: RING_ENTRIES,
            events_handled: 0,
            active: false,
        }
    }

    /// Active les interruptions matérielles sur cet interrupter (bit 1 IE de IMAN).
    pub fn enable_interrupts(&mut self) {
        self.iman |= 1 << 1;
    }

    /// Désactive les interruptions matérielles.
    pub fn disable_interrupts(&mut self) {
        self.iman &= !(1 << 1);
    }

    /// Vérifie si une interruption est en attente (bit 0 IP de IMAN).
    pub fn is_interrupt_pending(&self) -> bool {
        (self.iman & 1) != 0
    }

    /// Acquitte l'interruption en cours (écriture 1 sur IP).
    pub fn acknowledge_interrupt(&mut self) {
        self.iman |= 1; // RW1C
    }

    /// Met à jour le pointeur de dépilement ERDP et acquitte le bit EHB (Event Handler Busy).
    pub fn advance_erdp(&mut self, next_trb_addr: u64) {
        // Bit 3 = EHB (écrire 1 pour effacer), bits 63:4 = adresse du TRB
        self.erdp = (next_trb_addr & !0x0F) | (1 << 3);
        self.dequeue_idx = (self.dequeue_idx + 1) % self.ring_size;
        if self.dequeue_idx == 0 {
            self.cycle_bit = !self.cycle_bit;
        }
        self.events_handled = self.events_handled.wrapping_add(1);
    }

    /// Configure le registre de modération matérielle des interruptions IMOD (Spécification xHCI 1.2 section 5.5.2.2).
    /// `interval_250ns` spécifie la période de modération minimale en unités de 250 nanosecondes (ex: 4000 = 1000 µs = 1 ms).
    pub fn set_moderation(&mut self, interval_250ns: u16) {
        self.imod = (self.imod & 0xFFFF_0000) | (interval_250ns as u32);
    }

    /// Retourne l'intervalle de modération configuré en nanosecondes.
    pub fn moderation_interval_ns(&self) -> u32 {
        (self.imod & 0xFFFF) * 250
    }

    /// Retourne l'intervalle de modération configuré en microsecondes.
    pub fn moderation_interval_us(&self) -> u32 {
        self.moderation_interval_ns() / 1000
    }
}

/// Événement de détection à chaud (Hot-Plug) sur un port root-hub USB
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortHotPlugEvent {
    NoChange,
    DeviceConnected {
        port_id: u8,
        speed: UsbSpeed,
        change_connect: bool,
    },
    DeviceDisconnected {
        port_id: u8,
        slot_id: Option<u8>,
        change_connect: bool,
    },
    PortResetCompleted {
        port_id: u8,
        speed: UsbSpeed,
    },
    PortOverCurrentDetected {
        port_id: u8,
        active: bool,
    },
    ComplianceModeEntered {
        port_id: u8,
    },
    PortLinkStateChanged {
        port_id: u8,
        link_state: u8,
    },
    PortConfigErrorDetected {
        port_id: u8,
    },
}

// ============================================================================
// Décodeurs USB HID Boot Protocol (Clavier & Souris)
// ============================================================================

/// État du clavier USB HID conforme au Boot Protocol standard (Rapport de 8 octets).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbKeyboardState {
    pub left_ctrl: bool,
    pub left_shift: bool,
    pub left_alt: bool,
    pub left_gui: bool,
    pub right_ctrl: bool,
    pub right_shift: bool,
    pub right_alt: bool,
    pub right_gui: bool,
    pub keycodes: [u8; 6],
}

impl UsbKeyboardState {
    /// Décode un rapport de clavier Boot Protocol (8 octets).
    pub fn decode_report(&mut self, report: &[u8]) {
        if report.len() < 8 {
            return;
        }

        let modifiers = report[0];
        self.left_ctrl = (modifiers & (1 << 0)) != 0;
        self.left_shift = (modifiers & (1 << 1)) != 0;
        self.left_alt = (modifiers & (1 << 2)) != 0;
        self.left_gui = (modifiers & (1 << 3)) != 0;
        self.right_ctrl = (modifiers & (1 << 4)) != 0;
        self.right_shift = (modifiers & (1 << 5)) != 0;
        self.right_alt = (modifiers & (1 << 6)) != 0;
        self.right_gui = (modifiers & (1 << 7)) != 0;

        self.keycodes.copy_from_slice(&report[2..8]);
    }

    /// Indique si la touche Shift (gauche ou droite) est actuellement enfoncée.
    #[inline]
    pub fn is_shift_pressed(&self) -> bool {
        self.left_shift || self.right_shift
    }

    /// Convertit le premier code touche valide en caractère ASCII.
    pub fn first_ascii_char(&self) -> Option<char> {
        let is_shift = self.is_shift_pressed();

        for &kc in self.keycodes.iter() {
            if kc == 0 {
                continue;
            }

            let ch = match kc {
                // Lettres A-Z (0x04..=0x1D)
                0x04..=0x1D => {
                    let offset = kc - 0x04;
                    let base = if is_shift { b'A' } else { b'a' };
                    Some((base + offset) as char)
                }
                // Chiffres 1-9 (0x1E..=0x26)
                0x1E => Some(if is_shift { '!' } else { '1' }),
                0x1F => Some(if is_shift { '@' } else { '2' }),
                0x20 => Some(if is_shift { '#' } else { '3' }),
                0x21 => Some(if is_shift { '$' } else { '4' }),
                0x22 => Some(if is_shift { '%' } else { '5' }),
                0x23 => Some(if is_shift { '^' } else { '6' }),
                0x24 => Some(if is_shift { '&' } else { '7' }),
                0x25 => Some(if is_shift { '*' } else { '8' }),
                0x26 => Some(if is_shift { '(' } else { '9' }),
                0x27 => Some(if is_shift { ')' } else { '0' }),
                // Touches spéciales et ponctuation
                0x28 => Some('\n'),   // Enter
                0x29 => Some('\x1b'), // Escape
                0x2A => Some('\x08'), // Backspace
                0x2B => Some('\t'),   // Tab
                0x2C => Some(' '),    // Espace
                0x2D => Some(if is_shift { '_' } else { '-' }),
                0x2E => Some(if is_shift { '+' } else { '=' }),
                0x2F => Some(if is_shift { '{' } else { '[' }),
                0x30 => Some(if is_shift { '}' } else { ']' }),
                0x31 => Some(if is_shift { '|' } else { '\\' }),
                0x33 => Some(if is_shift { ':' } else { ';' }),
                0x34 => Some(if is_shift { '"' } else { '\'' }),
                0x35 => Some(if is_shift { '~' } else { '`' }),
                0x36 => Some(if is_shift { '<' } else { ',' }),
                0x37 => Some(if is_shift { '>' } else { '.' }),
                0x38 => Some(if is_shift { '?' } else { '/' }),
                _ => None,
            };

            if ch.is_some() {
                return ch;
            }
        }

        None
    }
}

/// État de la souris USB HID (Rapports 3 octets Boot, 4 octets IntelliMouse, 5 octets Explorer 5 boutons + Molette H/V).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbMouseState {
    pub left_button: bool,
    pub right_button: bool,
    pub middle_button: bool,
    pub button4: bool, // Bouton latéral 1 (Précédent / Back)
    pub button5: bool, // Bouton latéral 2 (Suivant / Forward)
    pub dx: i8,
    pub dy: i8,
    pub wheel: i8,  // Molette verticale (axe Z)
    pub hwheel: i8, // Molette horizontale (axe W / Pan / Tilt)
}

impl UsbMouseState {
    /// Décode un rapport de souris standard ou étendu (3 à 5 octets).
    pub fn decode_report(&mut self, report: &[u8]) {
        if report.len() < 3 {
            return;
        }

        let buttons = report[0];
        self.left_button = (buttons & (1 << 0)) != 0;
        self.right_button = (buttons & (1 << 1)) != 0;
        self.middle_button = (buttons & (1 << 2)) != 0;
        self.button4 = (buttons & (1 << 3)) != 0;
        self.button5 = (buttons & (1 << 4)) != 0;

        self.dx = report[1] as i8;
        self.dy = report[2] as i8;

        if report.len() == 4 {
            // Protocole IntelliMouse 4 octets standard :
            self.wheel = report[3] as i8;
            self.hwheel = 0;
        } else if report.len() >= 5 {
            // Protocole étendu 5 octets (IntelliMouse Explorer avec boutons 4 & 5 et roulette horizontale/pan)
            self.wheel = report[3] as i8;
            self.hwheel = report[4] as i8;
        } else {
            self.wheel = 0;
            self.hwheel = 0;
        }
    }
}

pub const MAX_TOUCH_CONTACTS: usize = 10;

/// Contact individuel d'une surface multi-touches USB HID (Digitizer / Touchscreen / Touchpad)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbTouchContact {
    pub contact_id: u8,
    pub tip_switch: bool, // Contact effectif sur la surface
    pub in_range: bool,   // Détection à proximité
    pub confidence: bool, // Contact intentionnel validé
    pub x: u16,           // Coordonnée absolue horizontale
    pub y: u16,           // Coordonnée absolue verticale
    pub pressure: u16,    // Pression mesurée (0..1023)
    pub contact_width: u16,
    pub contact_height: u16,
}

/// État d'une surface multi-touches USB HID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbMultiTouchState {
    pub contact_count: u8,
    pub contacts: [UsbTouchContact; MAX_TOUCH_CONTACTS],
    pub scan_time: u16,
    pub button_down: bool,
}

impl Default for UsbMultiTouchState {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbMultiTouchState {
    pub const fn new() -> Self {
        const EMPTY_CONTACT: UsbTouchContact = UsbTouchContact {
            contact_id: 0,
            tip_switch: false,
            in_range: false,
            confidence: false,
            x: 0,
            y: 0,
            pressure: 0,
            contact_width: 0,
            contact_height: 0,
        };
        Self {
            contact_count: 0,
            contacts: [EMPTY_CONTACT; MAX_TOUCH_CONTACTS],
            scan_time: 0,
            button_down: false,
        }
    }

    /// Décode un rapport multi-touches conforme USB HID Digitizer (Usage Page 0x0D)
    pub fn decode_report(&mut self, report: &[u8]) {
        if report.len() < 2 {
            return;
        }

        self.button_down = (report[0] & 0x01) != 0;
        let count = (report[1] as usize).min(MAX_TOUCH_CONTACTS);
        self.contact_count = count as u8;

        for c in self.contacts.iter_mut() {
            *c = UsbTouchContact::default();
        }

        let mut offset = 2;
        let contact_stride = 6;

        for contact in self.contacts.iter_mut().take(count) {
            if offset + contact_stride > report.len() {
                break;
            }

            let flags_id = report[offset];
            let tip = (flags_id & 0x01) != 0;
            let in_range = (flags_id & 0x02) != 0;
            let confidence = (flags_id & 0x04) != 0;
            let contact_id = (flags_id >> 4) & 0x0F;

            let x = u16::from_le_bytes([report[offset + 1], report[offset + 2]]);
            let y = u16::from_le_bytes([report[offset + 3], report[offset + 4]]);
            let pressure = report[offset + 5] as u16;

            *contact = UsbTouchContact {
                contact_id,
                tip_switch: tip,
                in_range,
                confidence,
                x,
                y,
                pressure,
                contact_width: 0,
                contact_height: 0,
            };

            offset += contact_stride;
        }

        if offset + 2 <= report.len() {
            self.scan_time = u16::from_le_bytes([report[offset], report[offset + 1]]);
        }
    }

    /// Nombre de contacts actifs (doigts appuyés sur la surface)
    pub fn active_contacts_count(&self) -> usize {
        self.contacts
            .iter()
            .take(self.contact_count as usize)
            .filter(|c| c.tip_switch)
            .count()
    }

    /// Détecte un défilement / panoramique à deux doigts (Pan/Scroll)
    pub fn detect_two_finger_scroll(&self, prev: &Self) -> Option<(i16, i16)> {
        if self.active_contacts_count() < 2 || prev.active_contacts_count() < 2 {
            return None;
        }

        let c1_cur = &self.contacts[0];
        let c2_cur = &self.contacts[1];
        let c1_prev = &prev.contacts[0];
        let c2_prev = &prev.contacts[1];

        if !c1_cur.tip_switch || !c2_cur.tip_switch || !c1_prev.tip_switch || !c2_prev.tip_switch {
            return None;
        }

        let dx1 = c1_cur.x as i32 - c1_prev.x as i32;
        let dy1 = c1_cur.y as i32 - c1_prev.y as i32;
        let dx2 = c2_cur.x as i32 - c2_prev.x as i32;
        let dy2 = c2_cur.y as i32 - c2_prev.y as i32;

        if (dx1 * dx2 >= 0) && (dy1 * dy2 >= 0) {
            let avg_dx = ((dx1 + dx2) / 2) as i16;
            let avg_dy = ((dy1 + dy2) / 2) as i16;
            Some((avg_dx, avg_dy))
        } else {
            None
        }
    }

    /// Détecte un geste de pincement / zoom à deux doigts (Pinch/Zoom)
    /// Valeur positive : écartement (Zoom In), valeur négative : rapprochement (Zoom Out)
    pub fn detect_pinch_zoom(&self, prev: &Self) -> Option<i16> {
        if self.active_contacts_count() < 2 || prev.active_contacts_count() < 2 {
            return None;
        }

        let c1_cur = &self.contacts[0];
        let c2_cur = &self.contacts[1];
        let c1_prev = &prev.contacts[0];
        let c2_prev = &prev.contacts[1];

        let cur_dist =
            (c1_cur.x as i32 - c2_cur.x as i32).abs() + (c1_cur.y as i32 - c2_cur.y as i32).abs();
        let prev_dist = (c1_prev.x as i32 - c2_prev.x as i32).abs()
            + (c1_prev.y as i32 - c2_prev.y as i32).abs();

        let delta = (cur_dist - prev_dist) as i16;
        if delta.abs() > 4 {
            Some(delta)
        } else {
            None
        }
    }
}

/// État des touches de contrôle multimédia / consommateur HID (Usage Page 0x0C - Consumer Controls)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbConsumerControlState {
    pub play_pause: bool,
    pub scan_next_track: bool,
    pub scan_previous_track: bool,
    pub stop: bool,
    pub volume_increment: bool,
    pub volume_decrement: bool,
    pub mute: bool,
    pub bass_boost: bool,
}

impl UsbConsumerControlState {
    /// Décode un masque d'octets de touches multimédia standard (Usage Page 0x0C)
    pub fn decode_mask(&mut self, mask: u16) {
        self.play_pause = (mask & (1 << 0)) != 0;
        self.scan_next_track = (mask & (1 << 1)) != 0;
        self.scan_previous_track = (mask & (1 << 2)) != 0;
        self.stop = (mask & (1 << 3)) != 0;
        self.volume_increment = (mask & (1 << 4)) != 0;
        self.volume_decrement = (mask & (1 << 5)) != 0;
        self.mute = (mask & (1 << 6)) != 0;
        self.bass_boost = (mask & (1 << 7)) != 0;
    }

    /// Décode un rapport binaire HID Consumer Control
    pub fn decode_report(&mut self, report: &[u8]) {
        if report.is_empty() {
            return;
        }
        let raw = if report.len() >= 2 {
            u16::from_le_bytes([report[0], report[1]])
        } else {
            report[0] as u16
        };
        self.decode_mask(raw);
    }
}

/// Événement du bouton d'alimentation ou de mise en veille ACPI / HID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPowerEvent {
    PowerDown,
    Sleep,
    WakeUp,
    ColdRestart,
    WarmRestart,
    D3Hot,
    D3Cold,
}

/// État des commutateurs d'alimentation et touches système ACPI HID (Usage Page 0x01 - Generic Desktop: System Controls)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbSystemControlState {
    pub power_down: bool,
    pub sleep: bool,
    pub wake_up: bool,
    pub cold_restart: bool,
    pub warm_restart: bool,
    pub dock: bool,
}

impl UsbSystemControlState {
    /// Décode un masque binaire de contrôle d'alimentation système (Usage 0x81 à 0x86)
    pub fn decode_mask(&mut self, mask: u8) {
        self.power_down = (mask & (1 << 0)) != 0;
        self.sleep = (mask & (1 << 1)) != 0;
        self.wake_up = (mask & (1 << 2)) != 0;
        self.cold_restart = (mask & (1 << 3)) != 0;
        self.warm_restart = (mask & (1 << 4)) != 0;
        self.dock = (mask & (1 << 5)) != 0;
    }

    /// Décode un rapport binaire HID System Control
    pub fn decode_report(&mut self, report: &[u8]) {
        if report.is_empty() {
            return;
        }
        self.decode_mask(report[0]);
    }

    /// Convertit l'état actif en événement système ACPI prioritaire
    pub fn primary_event(&self) -> Option<SystemPowerEvent> {
        if self.power_down {
            Some(SystemPowerEvent::PowerDown)
        } else if self.cold_restart {
            Some(SystemPowerEvent::ColdRestart)
        } else if self.warm_restart {
            Some(SystemPowerEvent::WarmRestart)
        } else if self.sleep {
            Some(SystemPowerEvent::Sleep)
        } else if self.wake_up {
            Some(SystemPowerEvent::WakeUp)
        } else {
            None
        }
    }
}

/// Indicateurs d'état et LEDs du clavier USB HID (Usage Page 0x08 - LEDs)
/// et commutateurs de verrouillage matériel (NumLock, CapsLock, ScrollLock, Compose, Kana, Fn-Lock).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbKeyboardLedState {
    pub num_lock: bool,
    pub caps_lock: bool,
    pub scroll_lock: bool,
    pub compose: bool,
    pub kana: bool,
    pub fn_lock: bool,
}

impl UsbKeyboardLedState {
    /// Masque binaire standard USB HID pour les LEDs (Bit 0: NumLock, 1: CapsLock, 2: ScrollLock, 3: Compose, 4: Kana, 5: FnLock)
    pub const MASK_NUM_LOCK: u8 = 1 << 0;
    pub const MASK_CAPS_LOCK: u8 = 1 << 1;
    pub const MASK_SCROLL_LOCK: u8 = 1 << 2;
    pub const MASK_COMPOSE: u8 = 1 << 3;
    pub const MASK_KANA: u8 = 1 << 4;
    pub const MASK_FN_LOCK: u8 = 1 << 5;

    /// Crée un état de LEDs avec les verrous spécifiés
    pub const fn new(num_lock: bool, caps_lock: bool, scroll_lock: bool) -> Self {
        Self {
            num_lock,
            caps_lock,
            scroll_lock,
            compose: false,
            kana: false,
            fn_lock: false,
        }
    }

    /// Décode un masque d'octets de rapport de sortie (SET_REPORT / Output Report)
    pub fn decode_mask(&mut self, mask: u8) {
        self.num_lock = (mask & Self::MASK_NUM_LOCK) != 0;
        self.caps_lock = (mask & Self::MASK_CAPS_LOCK) != 0;
        self.scroll_lock = (mask & Self::MASK_SCROLL_LOCK) != 0;
        self.compose = (mask & Self::MASK_COMPOSE) != 0;
        self.kana = (mask & Self::MASK_KANA) != 0;
        self.fn_lock = (mask & Self::MASK_FN_LOCK) != 0;
    }

    /// Encode l'état des LEDs en octet de rapport de sortie pour le périphérique HID
    pub const fn encode_mask(&self) -> u8 {
        let mut mask = 0u8;
        if self.num_lock {
            mask |= Self::MASK_NUM_LOCK;
        }
        if self.caps_lock {
            mask |= Self::MASK_CAPS_LOCK;
        }
        if self.scroll_lock {
            mask |= Self::MASK_SCROLL_LOCK;
        }
        if self.compose {
            mask |= Self::MASK_COMPOSE;
        }
        if self.kana {
            mask |= Self::MASK_KANA;
        }
        if self.fn_lock {
            mask |= Self::MASK_FN_LOCK;
        }
        mask
    }

    /// Bascule l'état d'un verrou lors d'un appui touche
    pub fn toggle_num_lock(&mut self) -> bool {
        self.num_lock = !self.num_lock;
        self.num_lock
    }

    pub fn toggle_caps_lock(&mut self) -> bool {
        self.caps_lock = !self.caps_lock;
        self.caps_lock
    }

    pub fn toggle_scroll_lock(&mut self) -> bool {
        self.scroll_lock = !self.scroll_lock;
        self.scroll_lock
    }

    pub fn toggle_fn_lock(&mut self) -> bool {
        self.fn_lock = !self.fn_lock;
        self.fn_lock
    }

    /// Prépare le paquet SETUP USB HID pour la commande standard `SET_REPORT` (Output Report sur Endpoint 0)
    pub fn build_set_report_setup_packet(&self, interface_id: u8) -> [u8; 8] {
        let mut setup = [0u8; 8];
        setup[0] = 0x21; // bmRequestType: Host to Device | Class | Interface
        setup[1] = 0x09; // bRequest: SET_REPORT
        setup[2] = 0x00; // wValue LSB: Report ID (0)
        setup[3] = 0x02; // wValue MSB: Report Type = Output (0x02)
        setup[4] = interface_id; // wIndex LSB: Interface Number
        setup[5] = 0x00; // wIndex MSB
        setup[6] = 0x01; // wLength LSB: 1 octet de payload
        setup[7] = 0x00; // wLength MSB
        setup
    }
}

// ============================================================================
// Gestion des Flux Isochrones et Synchronisation de Trames (Audio / Vidéo)
// ============================================================================

/// Type de flux multimédia isochrone temps réel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsochMediaType {
    AudioPcm,
    VideoUvc,
    GenericStream,
}

/// Contexte de synchronisation et de métriques d'un flux Isochrone xHCI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsochStreamContext {
    pub endpoint_id: u8,
    pub media_type: IsochMediaType,
    pub interval_microframes: u32,
    pub max_packet_size: u32,
    pub mult: u8,
    pub max_burst: u8,
    pub last_scheduled_frame_id: u32,
    pub synced_packets: u64,
    pub dropped_packets: u64,
    pub total_bytes: u64,
}

/// Résultat de la planification d'un paquet isochrone synchronisé
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsochScheduleResult {
    pub trb_idx: usize,
    pub frame_id: u32,
    pub is_sia: bool,
    pub scheduled_microframe: u32,
}

/// Résultat du traitement d'un événement de transfert Isochrone
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsochEventStatus {
    pub trb_idx: usize,
    pub bytes_transferred: u32,
    pub completed: bool,
    pub missed_service: bool,
    pub buffer_overrun: bool,
    pub ring_underrun: bool,
    pub completion_code: u8,
}

// ============================================================================
// Modération Matérielle et Throttling des Endpoints d'Interruption HID (Clavier / Souris)
// ============================================================================

/// Contexte de modération matérielle et de limitation de débit (throttling) pour un endpoint d'interruption HID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidInterruptThrottleContext {
    pub endpoint_id: u8,
    pub is_mouse: bool,
    pub b_interval: u8,
    pub min_interval_us: u32,
    pub last_dispatched_microframe: u32,
    pub total_interrupts: u64,
    pub throttled_count: u64,
    pub delivered_count: u64,
    pub debounce_enabled: bool,
    pub last_report: [u8; 8],
    pub last_report_len: usize,
}

impl HidInterruptThrottleContext {
    pub const fn new(
        endpoint_id: u8,
        is_mouse: bool,
        b_interval: u8,
        min_interval_us: u32,
        debounce_enabled: bool,
    ) -> Self {
        Self {
            endpoint_id,
            is_mouse,
            b_interval,
            min_interval_us,
            last_dispatched_microframe: 0,
            total_interrupts: 0,
            throttled_count: 0,
            delivered_count: 0,
            debounce_enabled,
            last_report: [0u8; 8],
            last_report_len: 0,
        }
    }
}

// ============================================================================
// Contrôleur xHCI en Espace Utilisateur (Ring 3)
// ============================================================================

/// Contrôleur USB xHCI en espace utilisateur.
pub struct XhciController {
    pub bar0_base: u64,
    pub cap_length: u8,
    pub max_slots: u8,
    pub max_ports: u8,
    pub doorbell_array_offset: u32,
    pub runtime_offset: u32,
    pub mfindex: u32,
    pub cmd_ring: XhciRing,
    pub ep_rings: [EndpointTransferRing; MAX_ENDPOINTS],
    pub isoch_streams: [Option<IsochStreamContext>; MAX_ENDPOINTS],
    pub hid_throttles: [Option<HidInterruptThrottleContext>; MAX_ENDPOINTS],
    pub keyboard: UsbKeyboardState,
    pub mouse: UsbMouseState,
    pub multitouch: UsbMultiTouchState,
    pub interrupter: XhciInterrupter,
    pub port_slots: [Option<u8>; 16],
    pub ready: bool,
}

impl Default for XhciController {
    fn default() -> Self {
        Self::new()
    }
}

impl XhciController {
    /// Construit une nouvelle instance non initialisée du contrôleur xHCI.
    pub const fn new() -> Self {
        const EMPTY_EP: EndpointTransferRing = EndpointTransferRing::new(0, false);
        let mut ep_rings = [EMPTY_EP; MAX_ENDPOINTS];
        let mut i = 0;
        while i < MAX_ENDPOINTS {
            ep_rings[i] = EndpointTransferRing::new(i as u8, false);
            i += 1;
        }

        Self {
            bar0_base: 0,
            cap_length: 0x20, // Valeur standard CAPLENGTH xHCI
            max_slots: 16,
            max_ports: 8,
            doorbell_array_offset: 0x2000, // Décalage Doorbell standard
            runtime_offset: 0x1000,        // Décalage RTSOFF standard
            mfindex: 0,
            cmd_ring: XhciRing::new(),
            ep_rings,
            isoch_streams: [None; MAX_ENDPOINTS],
            hid_throttles: [None; MAX_ENDPOINTS],
            keyboard: UsbKeyboardState {
                left_ctrl: false,
                left_shift: false,
                left_alt: false,
                left_gui: false,
                right_ctrl: false,
                right_shift: false,
                right_alt: false,
                right_gui: false,
                keycodes: [0; 6],
            },
            mouse: UsbMouseState {
                left_button: false,
                right_button: false,
                middle_button: false,
                button4: false,
                button5: false,
                dx: 0,
                dy: 0,
                wheel: 0,
                hwheel: 0,
            },
            multitouch: UsbMultiTouchState::new(),
            interrupter: XhciInterrupter::new(),
            port_slots: [None; 16],
            ready: false,
        }
    }

    /// Initialise le contrôleur xHCI à partir d'un périphérique PCIe validé (`PciDeviceInfo`).
    pub fn init(&mut self, pci_dev: &PciDeviceInfo) -> Result<(), SysError> {
        let bar0 = pci_dev.bar0.ok_or(SysError::BadAddress)?;
        self.bar0_base = bar0.base_address;
        self.cap_length = 0x20;
        self.doorbell_array_offset = 0x2000;
        self.runtime_offset = 0x1000;
        self.ready = true;
        Ok(())
    }

    /// Configure et active le Transfer Ring d'un endpoint (Bulk ou Isochrone).
    pub fn configure_endpoint_ring(&mut self, ep_id: u8, is_isoch: bool) -> Result<(), SysError> {
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        ep.reset();
        ep.endpoint_id = ep_id;
        ep.is_isoch = is_isoch;
        ep.is_interrupt = false;
        ep.active = true;
        Ok(())
    }

    /// Configure et active un endpoint d'interruption HID (Clavier ou Souris) avec contexte de modération/throttling.
    pub fn configure_hid_interrupt_endpoint(
        &mut self,
        ep_id: u8,
        is_mouse: bool,
        b_interval: u8,
        min_interval_us: u32,
        debounce_enabled: bool,
    ) -> Result<(), SysError> {
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        ep.reset();
        ep.endpoint_id = ep_id;
        ep.is_isoch = false;
        ep.is_interrupt = true;
        ep.active = true;

        self.hid_throttles[ep_id as usize] = Some(HidInterruptThrottleContext::new(
            ep_id,
            is_mouse,
            b_interval,
            min_interval_us,
            debounce_enabled,
        ));
        Ok(())
    }

    /// Configure automatiquement les Transfer Rings des endpoints Bulk, Isochrone et Interruption
    /// à partir d'une configuration USB décodée par UsbConfigParser.
    /// Retourne le nombre d'anneaux de transfert configurés.
    pub fn configure_endpoints_from_decoded_config(
        &mut self,
        config: &UsbDecodedConfiguration,
    ) -> Result<usize, SysError> {
        let mut configured = 0;
        for iface in &config.interfaces[..config.interface_count] {
            for ep in &iface.endpoints[..iface.endpoint_count] {
                if ep.is_bulk() || ep.is_isochronous() || ep.is_interrupt() {
                    let ep_id = ep.dci;
                    if (ep_id as usize) < MAX_ENDPOINTS {
                        if ep.is_interrupt() {
                            let is_mouse = (ep.max_packet_size & 0x07FF) <= 4;
                            let b_interval = ep.interval;
                            self.configure_hid_interrupt_endpoint(
                                ep_id, is_mouse, b_interval, 1000, true,
                            )?;
                        } else {
                            self.configure_endpoint_ring(ep_id, ep.is_isochronous())?;
                        }
                        configured += 1;
                    }
                }
            }
        }
        Ok(configured)
    }

    /// Soumet un transfert Bulk USB 3.0 (TRB Normal) sur l'anneau de transfert de l'endpoint.
    pub fn queue_bulk_transfer(
        &mut self,
        ep_id: u8,
        data_iova: u64,
        length: u32,
        ioc: bool,
        isp: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active {
            return Err(SysError::InvalidArgument);
        }

        let cycle = ep.ring.cycle_bit;
        let normal_trb = Trb::normal(data_iova, length, cycle, ioc, isp);
        let idx = ep.ring.enqueue_idx;
        let next_idx = (idx + 1) % RING_ENTRIES;

        if next_idx == 0 {
            let link = Trb::link(0, ep.ring.cycle_bit, true);
            ep.ring.trbs[idx] = link;
            ep.ring.cycle_bit = !ep.ring.cycle_bit;
            ep.ring.enqueue_idx = 0;
            return Ok(idx);
        }

        ep.ring.trbs[idx] = normal_trb;
        ep.ring.enqueue_idx = next_idx;
        Ok(idx)
    }

    /// Soumet un transfert Bulk avec liste Scatter-Gather (segments mémoire discontinus).
    /// Chaque segment intermédiaire possède le bit `CH` (Chain bit), et le dernier segment
    /// porte les drapeaux de complétion `ioc` et `isp`.
    pub fn queue_bulk_scatter_gather(
        &mut self,
        ep_id: u8,
        segments: &[SgSegment],
        ioc: bool,
        isp: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_id as usize >= MAX_ENDPOINTS || segments.is_empty() {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active {
            return Err(SysError::InvalidArgument);
        }

        let first_idx = ep.ring.enqueue_idx;
        for (k, seg) in segments.iter().enumerate() {
            let is_last = k == segments.len() - 1;
            let chain = !is_last;
            let seg_ioc = is_last && ioc;
            let seg_isp = is_last && isp;

            let cycle = ep.ring.cycle_bit;
            let trb = Trb::normal_chained(seg.iova, seg.length, cycle, chain, seg_ioc, seg_isp);
            let idx = ep.ring.enqueue_idx;
            let next_idx = (idx + 1) % RING_ENTRIES;

            if next_idx == 0 {
                let link = Trb::link(0, ep.ring.cycle_bit, true);
                ep.ring.trbs[idx] = link;
                ep.ring.cycle_bit = !ep.ring.cycle_bit;
                ep.ring.enqueue_idx = 0;
                let new_cycle = ep.ring.cycle_bit;
                let re_trb =
                    Trb::normal_chained(seg.iova, seg.length, new_cycle, chain, seg_ioc, seg_isp);
                let cur = ep.ring.enqueue_idx;
                ep.ring.trbs[cur] = re_trb;
                ep.ring.enqueue_idx = (cur + 1) % RING_ENTRIES;
            } else {
                ep.ring.trbs[idx] = trb;
                ep.ring.enqueue_idx = next_idx;
            }
        }
        Ok(first_idx)
    }

    /// Configure un flux Bulk (Block Stream / UAS) sur un endpoint supportant le streaming.
    pub fn configure_bulk_stream(&mut self, ep_id: u8, stream_id: u16) -> Result<(), SysError> {
        if ep_id as usize >= MAX_ENDPOINTS || stream_id == 0 {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active {
            return Err(SysError::InvalidArgument);
        }
        ep.streams_enabled = true;

        let mut target_idx = None;
        for (i, stream) in ep.streams.iter().enumerate() {
            if stream.active && stream.stream_id == stream_id {
                target_idx = Some(i);
                break;
            }
        }
        if target_idx.is_none() {
            for (i, stream) in ep.streams.iter().enumerate() {
                if !stream.active {
                    target_idx = Some(i);
                    break;
                }
            }
        }
        let idx = target_idx.ok_or(SysError::OutOfMemory)?;
        let s = &mut ep.streams[idx];
        s.reset();
        s.stream_id = stream_id;
        s.active = true;
        Ok(())
    }

    /// Soumet un transfert Bulk sur un flux de données (Stream) spécifique d'un endpoint.
    pub fn queue_stream_bulk_transfer(
        &mut self,
        ep_id: u8,
        stream_id: u16,
        data_iova: u64,
        length: u32,
        ioc: bool,
        isp: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_id as usize >= MAX_ENDPOINTS || stream_id == 0 {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active || !ep.streams_enabled {
            return Err(SysError::InvalidArgument);
        }

        let stream = ep
            .streams
            .iter_mut()
            .find(|s| s.active && s.stream_id == stream_id)
            .ok_or(SysError::InvalidArgument)?;

        let cycle = stream.ring.cycle_bit;
        let normal_trb = Trb::normal(data_iova, length, cycle, ioc, isp);
        let idx = stream.ring.enqueue_idx;
        let next_idx = (idx + 1) % RING_ENTRIES;

        if next_idx == 0 {
            let link = Trb::link(0, stream.ring.cycle_bit, true);
            stream.ring.trbs[idx] = link;
            stream.ring.cycle_bit = !stream.ring.cycle_bit;
            stream.ring.enqueue_idx = 0;
            return Ok(idx);
        }

        stream.ring.trbs[idx] = normal_trb;
        stream.ring.enqueue_idx = next_idx;
        Ok(idx)
    }

    /// Soumet un transfert Scatter-Gather sur un flux de données (Stream) d'un endpoint.
    pub fn queue_stream_scatter_gather(
        &mut self,
        ep_id: u8,
        stream_id: u16,
        segments: &[SgSegment],
        ioc: bool,
        isp: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_id as usize >= MAX_ENDPOINTS || stream_id == 0 || segments.is_empty() {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active || !ep.streams_enabled {
            return Err(SysError::InvalidArgument);
        }

        let stream = ep
            .streams
            .iter_mut()
            .find(|s| s.active && s.stream_id == stream_id)
            .ok_or(SysError::InvalidArgument)?;

        let first_idx = stream.ring.enqueue_idx;
        for (k, seg) in segments.iter().enumerate() {
            let is_last = k == segments.len() - 1;
            let chain = !is_last;
            let seg_ioc = is_last && ioc;
            let seg_isp = is_last && isp;

            let cycle = stream.ring.cycle_bit;
            let trb = Trb::normal_chained(seg.iova, seg.length, cycle, chain, seg_ioc, seg_isp);
            let idx = stream.ring.enqueue_idx;
            let next_idx = (idx + 1) % RING_ENTRIES;

            if next_idx == 0 {
                let link = Trb::link(0, stream.ring.cycle_bit, true);
                stream.ring.trbs[idx] = link;
                stream.ring.cycle_bit = !stream.ring.cycle_bit;
                stream.ring.enqueue_idx = 0;
                let new_cycle = stream.ring.cycle_bit;
                let re_trb =
                    Trb::normal_chained(seg.iova, seg.length, new_cycle, chain, seg_ioc, seg_isp);
                let cur = stream.ring.enqueue_idx;
                stream.ring.trbs[cur] = re_trb;
                stream.ring.enqueue_idx = (cur + 1) % RING_ENTRIES;
            } else {
                stream.ring.trbs[idx] = trb;
                stream.ring.enqueue_idx = next_idx;
            }
        }
        Ok(first_idx)
    }

    /// Traite un événement de transfert pour un Stream xHCI et met à jour ses métriques.
    pub fn handle_stream_transfer_event(
        &mut self,
        ep_id: u8,
        stream_id: u16,
        trb: &Trb,
    ) -> Result<TransferStatus, SysError> {
        let comp_code = trb.completion_code();
        if (ep_id as usize) >= MAX_ENDPOINTS || stream_id == 0 {
            return Err(SysError::InvalidArgument);
        }

        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active || !ep.streams_enabled {
            return Err(SysError::InvalidArgument);
        }

        let stream = ep
            .streams
            .iter_mut()
            .find(|s| s.active && s.stream_id == stream_id)
            .ok_or(SysError::InvalidArgument)?;

        let remaining = trb.transfer_remainder();
        let requested_bytes = if stream.ring.enqueue_idx > 0 {
            stream.ring.trbs[stream.ring.enqueue_idx - 1].status & 0x1FFFF
        } else {
            0
        };

        let transferred = requested_bytes.saturating_sub(remaining);
        stream.total_bytes_transferred += transferred as u64;

        let status = TransferStatus {
            trb_idx: stream.ring.enqueue_idx.saturating_sub(1),
            bytes_transferred: transferred,
            completed: comp_code == TRB_COMP_SUCCESS,
            completion_code: comp_code,
        };

        stream.last_status = status;
        if comp_code == TRB_COMP_SUCCESS {
            Ok(status)
        } else {
            Err(SysError::BadAddress)
        }
    }

    /// Soumet un transfert Isochrone USB 3.0 sur l'anneau de transfert de l'endpoint.
    pub fn queue_isoch_transfer(
        &mut self,
        ep_id: u8,
        data_iova: u64,
        length: u32,
        frame_id: u32,
        sia: bool,
        ioc: bool,
        isp: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active || !ep.is_isoch {
            return Err(SysError::InvalidArgument);
        }

        let cycle = ep.ring.cycle_bit;
        let isoch_trb = Trb::isoch(data_iova, length, frame_id, sia, cycle, ioc, isp);
        let idx = ep.ring.enqueue_idx;
        let next_idx = (idx + 1) % RING_ENTRIES;

        if next_idx == 0 {
            let link = Trb::link(0, ep.ring.cycle_bit, true);
            ep.ring.trbs[idx] = link;
            ep.ring.cycle_bit = !ep.ring.cycle_bit;
            ep.ring.enqueue_idx = 0;
            return Ok(idx);
        }

        ep.ring.trbs[idx] = isoch_trb;
        ep.ring.enqueue_idx = next_idx;
        Ok(idx)
    }

    /// Traite un événement de transfert TRB (Transfer Event) et met à jour les métriques de l'endpoint.
    pub fn handle_transfer_event(&mut self, trb: &Trb) -> Result<TransferStatus, SysError> {
        let ep_id = trb.endpoint_id();
        let comp_code = trb.completion_code();

        if (ep_id as usize) >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }

        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active {
            return Err(SysError::InvalidArgument);
        }

        let remaining = trb.transfer_remainder();
        let requested_bytes = if ep.ring.enqueue_idx > 0 {
            ep.ring.trbs[ep.ring.enqueue_idx - 1].status & 0x1FFFF
        } else {
            0
        };

        let transferred = requested_bytes.saturating_sub(remaining);
        ep.total_bytes_transferred += transferred as u64;

        let status = TransferStatus {
            trb_idx: ep.ring.enqueue_idx.saturating_sub(1),
            bytes_transferred: transferred,
            completed: comp_code == TRB_COMP_SUCCESS,
            completion_code: comp_code,
        };

        ep.last_status = status;
        if comp_code == TRB_COMP_SUCCESS {
            Ok(status)
        } else {
            Err(SysError::BadAddress)
        }
    }

    /// Lit la valeur courante du registre de microtrame MFINDEX (14 bits)
    #[inline]
    pub fn read_mfindex(&self) -> u32 {
        self.mfindex & MFINDEX_MASK
    }

    /// Retourne le numéro de trame (Frame ID) USB courant [0..2047] dérivé de MFINDEX (microframe >> 3)
    #[inline]
    pub fn current_frame_id(&self) -> u32 {
        (self.read_mfindex() >> 3) & 0x7FF
    }

    /// Avance le compteur de microtrames de `microframes` et signale si un bouclage (wrap-around) a eu lieu
    pub fn step_mfindex(&mut self, microframes: u32) -> (u32, bool) {
        let old = self.mfindex;
        let sum = old + microframes;
        let new = sum & MFINDEX_MASK;
        let wrapped = sum > MFINDEX_MASK;
        self.mfindex = new;
        (new, wrapped)
    }

    /// Construit un TRB d'événement de bouclage de microtrame (MFINDEX Wrap Event, type 39)
    #[inline]
    pub fn create_mfindex_wrap_trb(&self) -> Trb {
        Trb {
            parameter: 0,
            status: 0,
            control: ((TRB_TYPE_MFINDEX_WRAP & 0x3F) << 10) | 1,
        }
    }

    /// Enregistre et initialise un flux isochrone temps réel (Audio / Vidéo / Streaming) sur un endpoint dédié
    pub fn register_isoch_stream(
        &mut self,
        ep_id: u8,
        media_type: IsochMediaType,
        interval: u8,
        max_packet_size: u32,
        mult: u8,
        max_burst: u8,
    ) -> Result<(), SysError> {
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        self.configure_endpoint_ring(ep_id, true)?;

        let interval_microframes = 1u32 << interval.saturating_sub(1).min(15);
        let stream_ctx = IsochStreamContext {
            endpoint_id: ep_id,
            media_type,
            interval_microframes,
            max_packet_size,
            mult: mult.clamp(1, 3),
            max_burst: max_burst.min(15),
            last_scheduled_frame_id: self.current_frame_id(),
            synced_packets: 0,
            dropped_packets: 0,
            total_bytes: 0,
        };
        self.isoch_streams[ep_id as usize] = Some(stream_ctx);
        Ok(())
    }

    /// Planifie l'envoi ou la réception d'un paquet isochrone synchronisé avec l'horloge MFINDEX
    pub fn schedule_isoch_packet(
        &mut self,
        ep_id: u8,
        data_iova: u64,
        length: u32,
        target_frame_id: Option<u32>,
        ioc: bool,
        isp: bool,
    ) -> Result<IsochScheduleResult, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }

        let is_sia;
        let fid;
        let cur_frame = self.current_frame_id();

        if let Some(target) = target_frame_id {
            let target_fid = target & 0x7FF;
            // Vérification de la fenêtre temporelle dans l'anneau modulo 2048 :
            // Si la trame cible est déjà écoulée de plus de 1024 trames en arrière, elle est en retard critique
            let delta = target_fid.wrapping_sub(cur_frame) & 0x7FF;
            if delta > 1024 && delta != 0 {
                if let Some(stream) = &mut self.isoch_streams[ep_id as usize] {
                    stream.dropped_packets += 1;
                }
                return Err(SysError::ResourceBusy); // Fenêtre temporelle dépassée (missed service)
            }
            is_sia = false;
            fid = target_fid;
        } else {
            is_sia = true;
            fid = (cur_frame + 4) & 0x7FF; // 4 trames d'avance par défaut
        }

        let trb_idx = self.queue_isoch_transfer(ep_id, data_iova, length, fid, is_sia, ioc, isp)?;

        if let Some(stream) = &mut self.isoch_streams[ep_id as usize] {
            stream.last_scheduled_frame_id = fid;
        }

        Ok(IsochScheduleResult {
            trb_idx,
            frame_id: fid,
            is_sia,
            scheduled_microframe: self.read_mfindex(),
        })
    }

    /// Traite un événement de transfert Isochrone et met à jour les métriques de gigue et de synchronisation
    pub fn handle_isoch_transfer_event(&mut self, trb: &Trb) -> Result<IsochEventStatus, SysError> {
        let ep_id = trb.endpoint_id();
        let comp_code = trb.completion_code();

        if (ep_id as usize) >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }

        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active || !ep.is_isoch {
            return Err(SysError::InvalidArgument);
        }

        let remaining = trb.transfer_remainder();
        let requested_bytes = if ep.ring.enqueue_idx > 0 {
            ep.ring.trbs[ep.ring.enqueue_idx - 1].status & 0x1FFFF
        } else {
            0
        };

        let transferred = requested_bytes.saturating_sub(remaining);
        ep.total_bytes_transferred += transferred as u64;

        let missed = comp_code == TRB_COMP_MISSED_SERVICE_ERROR;
        let overrun = comp_code == TRB_COMP_ISOCH_BUFFER_OVERRUN;
        let underrun = comp_code == TRB_COMP_RING_UNDERRUN;
        let success = comp_code == TRB_COMP_SUCCESS;

        if let Some(stream) = &mut self.isoch_streams[ep_id as usize] {
            if success {
                stream.synced_packets += 1;
                stream.total_bytes += transferred as u64;
            } else if missed || overrun || underrun {
                stream.dropped_packets += 1;
            }
        }

        let status = IsochEventStatus {
            trb_idx: ep.ring.enqueue_idx.saturating_sub(1),
            bytes_transferred: transferred,
            completed: success,
            missed_service: missed,
            buffer_overrun: overrun,
            ring_underrun: underrun,
            completion_code: comp_code,
        };

        if success {
            Ok(status)
        } else {
            Err(SysError::ResourceBusy)
        }
    }

    /// Calcule le décalage mémoire du registre Doorbell pour un slot donné.
    #[inline]
    pub fn doorbell_offset(&self, slot_id: u8) -> usize {
        (self.doorbell_array_offset as usize) + (slot_id as usize * 4)
    }

    /// Calcule la valeur d'écriture pour sonner la sonnette Doorbell vers un slot et endpoint.
    #[inline]
    pub fn doorbell_payload(&self, target_endpoint: u8, stream_id: u16) -> u32 {
        (target_endpoint as u32 & 0xFF) | ((stream_id as u32) << 16)
    }

    /// Émet une commande Enable Slot sur le Command Ring.
    pub fn enable_slot(&mut self) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        self.cmd_ring.push(0, 0, TRB_TYPE_ENABLE_SLOT)
    }

    /// Émet une commande Disable Slot sur le Command Ring.
    pub fn disable_slot(&mut self, slot_id: u8) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        let control_extra = (slot_id as u32) << 24;
        self.cmd_ring.push(0, control_extra, TRB_TYPE_DISABLE_SLOT)
    }

    /// Émet une commande Address Device sur le Command Ring.
    pub fn address_device(&mut self, input_ctx_iova: u64, slot_id: u8) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        let control_extra = (slot_id as u32) << 24;
        self.cmd_ring
            .push(input_ctx_iova, control_extra, TRB_TYPE_ADDRESS_DEVICE)
    }

    /// Émet une commande Configure Endpoint sur le Command Ring.
    pub fn configure_endpoint(
        &mut self,
        input_ctx_iova: u64,
        slot_id: u8,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        let control_extra = (slot_id as u32) << 24;
        self.cmd_ring
            .push(input_ctx_iova, control_extra, TRB_TYPE_CONFIGURE_EP)
    }

    /// Soumet un transfert d'interruption HID (TRB Normal avec drapeau IOC optionnel) sur l'anneau d'interruption.
    pub fn queue_interrupt_transfer(
        &mut self,
        ep_id: u8,
        data_iova: u64,
        length: u32,
        ioc: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active || !ep.is_interrupt {
            return Err(SysError::ResourceBusy);
        }

        let cycle = ep.ring.cycle_bit;
        let normal_trb = Trb::normal(data_iova, length, cycle, ioc, true);
        let idx = ep.ring.enqueue_idx;
        let next_idx = (idx + 1) % RING_ENTRIES;

        if next_idx == 0 {
            let link = Trb::link(0, ep.ring.cycle_bit, true);
            ep.ring.trbs[idx] = link;
            ep.ring.cycle_bit = !ep.ring.cycle_bit;
            ep.ring.enqueue_idx = 0;
            return Ok(idx);
        }

        ep.ring.trbs[idx] = normal_trb;
        ep.ring.enqueue_idx = next_idx;
        Ok(idx)
    }

    /// Soumet un transfert de contrôle asynchrone complet en 2 ou 3 étapes sur un endpoint de contrôle (Endpoint 0).
    ///
    /// Génère :
    /// 1. Un TRB `Setup Stage` encapsulant le paquet de requête USB `setup`.
    /// 2. Zéro ou un TRB `Data Stage` si `data_length > 0` pointant vers `data_iova` avec direction IN/OUT.
    /// 3. Un TRB `Status Stage` avec la direction opposée et drapeau d'interruption `ioc`.
    ///
    /// Renvoie l'indice du premier TRB inséré sur l'anneau de transfert de l'endpoint.
    pub fn queue_control_transfer(
        &mut self,
        ep_id: u8,
        setup: &UsbSetupPacket,
        data_iova: u64,
        data_length: u32,
        is_in: bool,
        ioc: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }
        let ep = &mut self.ep_rings[ep_id as usize];
        if !ep.active {
            return Err(SysError::ResourceBusy);
        }

        let first_idx = ep.ring.enqueue_idx;
        let trt = if data_length == 0 {
            0 // No data stage
        } else if is_in {
            3 // IN data stage
        } else {
            2 // OUT data stage
        };

        // 1. Setup Stage TRB
        let setup_trb = Trb::setup_stage(setup, trt, ep.ring.cycle_bit);
        let s_idx = ep.ring.enqueue_idx;
        let s_next = (s_idx + 1) % RING_ENTRIES;
        if s_next == 0 {
            let link = Trb::link(0, ep.ring.cycle_bit, true);
            ep.ring.trbs[s_idx] = link;
            ep.ring.cycle_bit = !ep.ring.cycle_bit;
            ep.ring.enqueue_idx = 0;
            // Réinsère setup en tête
            let s2_idx = ep.ring.enqueue_idx;
            let setup_trb2 = Trb::setup_stage(setup, trt, ep.ring.cycle_bit);
            ep.ring.trbs[s2_idx] = setup_trb2;
            ep.ring.enqueue_idx = (s2_idx + 1) % RING_ENTRIES;
        } else {
            ep.ring.trbs[s_idx] = setup_trb;
            ep.ring.enqueue_idx = s_next;
        }

        // 2. Data Stage TRB (si transfert de données)
        if data_length > 0 {
            let data_trb = Trb::data_stage(
                data_iova,
                data_length,
                is_in,
                ep.ring.cycle_bit,
                false,
                true,
            );
            let d_idx = ep.ring.enqueue_idx;
            let d_next = (d_idx + 1) % RING_ENTRIES;
            if d_next == 0 {
                let link = Trb::link(0, ep.ring.cycle_bit, true);
                ep.ring.trbs[d_idx] = link;
                ep.ring.cycle_bit = !ep.ring.cycle_bit;
                ep.ring.enqueue_idx = 0;
                let d2_idx = ep.ring.enqueue_idx;
                let data_trb2 = Trb::data_stage(
                    data_iova,
                    data_length,
                    is_in,
                    ep.ring.cycle_bit,
                    false,
                    true,
                );
                ep.ring.trbs[d2_idx] = data_trb2;
                ep.ring.enqueue_idx = (d2_idx + 1) % RING_ENTRIES;
            } else {
                ep.ring.trbs[d_idx] = data_trb;
                ep.ring.enqueue_idx = d_next;
            }
        }

        // 3. Status Stage TRB (direction opposée aux données, ou IN si pas de données)
        let status_is_in = if data_length == 0 { true } else { !is_in };
        let status_trb = Trb::status_stage(status_is_in, ep.ring.cycle_bit, ioc);
        let st_idx = ep.ring.enqueue_idx;
        let st_next = (st_idx + 1) % RING_ENTRIES;
        if st_next == 0 {
            let link = Trb::link(0, ep.ring.cycle_bit, true);
            ep.ring.trbs[st_idx] = link;
            ep.ring.cycle_bit = !ep.ring.cycle_bit;
            ep.ring.enqueue_idx = 0;
            let st2_idx = ep.ring.enqueue_idx;
            let status_trb2 = Trb::status_stage(status_is_in, ep.ring.cycle_bit, ioc);
            ep.ring.trbs[st2_idx] = status_trb2;
            ep.ring.enqueue_idx = (st2_idx + 1) % RING_ENTRIES;
        } else {
            ep.ring.trbs[st_idx] = status_trb;
            ep.ring.enqueue_idx = st_next;
        }

        Ok(first_idx)
    }

    /// Traite un rapport USB HID reçu d'un périphérique (clavier ou souris).
    pub fn handle_hid_input(&mut self, is_mouse: bool, report: &[u8]) {
        if is_mouse {
            self.mouse.decode_report(report);
        } else {
            self.keyboard.decode_report(report);
        }
    }

    /// Traite un rapport tactile / multi-touches reçu d'un numériseur HID (Digitizer / Touchscreen).
    pub fn handle_touch_input(&mut self, report: &[u8]) {
        self.multitouch.decode_report(report);
    }

    /// Filtre et traite un rapport HID avec throttling et modération temporelle matérielle.
    /// Renvoie `Ok(true)` si le rapport a été admis et délivré, ou `Ok(false)` s'il a été modéré/bloqué.
    pub fn process_hid_interrupt_report(
        &mut self,
        ep_id: u8,
        report: &[u8],
        current_microframe: u32,
    ) -> Result<bool, SysError> {
        if ep_id as usize >= MAX_ENDPOINTS {
            return Err(SysError::InvalidArgument);
        }

        let is_mouse;
        let should_throttle;

        {
            let throttle = match self.hid_throttles[ep_id as usize].as_mut() {
                Some(ctx) => ctx,
                None => return Err(SysError::InvalidArgument),
            };

            throttle.total_interrupts = throttle.total_interrupts.wrapping_add(1);
            is_mouse = throttle.is_mouse;

            let elapsed_microframes = (current_microframe
                .wrapping_sub(throttle.last_dispatched_microframe))
                & MFINDEX_MASK;
            let min_microframes_required = throttle.min_interval_us / MFINDEX_MICROFRAME_US;

            let is_duplicate = throttle.debounce_enabled
                && throttle.last_report_len == report.len()
                && throttle.last_report[..report.len().min(8)] == report[..report.len().min(8)];

            if (throttle.delivered_count > 0 && elapsed_microframes < min_microframes_required)
                || is_duplicate
            {
                throttle.throttled_count = throttle.throttled_count.wrapping_add(1);
                should_throttle = true;
            } else {
                throttle.delivered_count = throttle.delivered_count.wrapping_add(1);
                throttle.last_dispatched_microframe = current_microframe;
                let copy_len = report.len().min(8);
                throttle.last_report[..copy_len].copy_from_slice(&report[..copy_len]);
                throttle.last_report_len = report.len();
                should_throttle = false;
            }
        }

        if !should_throttle {
            self.handle_hid_input(is_mouse, report);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Analyse un événement TRB de complétion et retourne le code de complétion.
    pub fn handle_event_trb(&mut self, trb: &Trb) -> Result<u8, SysError> {
        let code = trb.completion_code();
        if code == TRB_COMP_SUCCESS {
            Ok(code)
        } else {
            Err(SysError::BadAddress)
        }
    }

    /// Récupération après crash (Auto-guérison et réinitialisation de l'anneau de commande et des endpoints).
    pub fn recover_from_crash(&mut self) -> Result<(), SysError> {
        self.cmd_ring.reset();
        for ep in self.ep_rings.iter_mut() {
            ep.reset();
        }
        for throttle in self.hid_throttles.iter_mut() {
            *throttle = None;
        }
        self.ready = true;
        Ok(())
    }

    /// Initialise l'Interrupter primaire et lie la table de segments ERST et le pointeur de dépilement ERDP.
    pub fn init_primary_interrupter(
        &mut self,
        erst_iova: u64,
        ring_iova: u64,
        ring_entries: u32,
    ) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if (erst_iova & 0x3F) != 0 || (ring_iova & 0x3F) != 0 {
            // Doit être aligné sur 64 octets
            return Err(SysError::BadAddress);
        }
        self.interrupter.erstba = erst_iova;
        self.interrupter.erstsz = 1; // 1 segment
        self.interrupter.erdp = ring_iova | (1 << 3); // initial EHB
        self.interrupter.ring_size = ring_entries as usize;
        self.interrupter.dequeue_idx = 0;
        self.interrupter.cycle_bit = true;
        self.interrupter.enable_interrupts();
        self.interrupter.active = true;
        Ok(())
    }

    /// Acquitte la consommation d'un événement sur ERDP.
    pub fn acknowledge_erdp(&mut self, next_trb_addr: u64) {
        self.interrupter.advance_erdp(next_trb_addr);
    }

    /// Associe un numéro de slot à un port USB (après Enable Slot / Address Device).
    pub fn bind_port_slot(&mut self, port_id: u8, slot_id: u8) -> Result<(), SysError> {
        if port_id == 0 || port_id as usize > self.port_slots.len() {
            return Err(SysError::InvalidArgument);
        }
        self.port_slots[port_id as usize - 1] = Some(slot_id);
        Ok(())
    }

    /// Calcule l'adresse MMIO du registre PORTHLPMC pour le port donné (1-based).
    ///
    /// Selon la spec xHCI 1.2, les registres de port commencent à `op_base + 0x400`,
    /// chaque groupe de port occupe 0x10 octets, et PORTHLPMC est à l'offset 0x0C.
    ///
    /// # Panics
    ///
    /// Panique si `port_id == 0` (les ports sont numérotés à partir de 1).
    #[inline]
    fn porthlpmc_addr(&self, port_id: u8) -> u64 {
        debug_assert!(port_id >= 1, "port_id est 1-based (>= 1)");
        let op_base = self.bar0_base + self.cap_length as u64;
        op_base + 0x400 + (port_id as u64 - 1) * 0x10 + 0x0C
    }

    /// Lit le registre PORTHLPMC du port spécifié et retourne les paramètres LPM décodés.
    ///
    /// # Safety (contrat SAFETY interne)
    ///
    /// Cette fonction effectue une lecture volatile MMIO. L'appelant doit s'assurer que
    /// `bar0_base` pointe vers un espace MMIO xHCI valide et mappé, et que `port_id` est
    /// un numéro de port valide pour ce contrôleur (1 ≤ port_id ≤ max_ports).
    pub fn read_port_hlpmc(&self, port: u8) -> PortHlpmc {
        if port == 0 || port > self.max_ports {
            return PortHlpmc::default();
        }
        let addr = self.porthlpmc_addr(port);
        // SAFETY: bar0_base est initialisé via init() depuis un BAR PCI valide et mappé
        // en MMIO. L'adresse calculée pointe vers le registre PORTHLPMC du port demandé,
        // dans l'espace opérationnel xHCI. La lecture volatile garantit l'absence de
        // réordonnancement par le compilateur.
        let raw = unsafe { core::ptr::read_volatile(addr as *const u32) };
        PortHlpmc::parse(raw)
    }

    /// Configure la gestion matérielle LPM (Link Power Management) USB 3.1 sur un port xHCI.
    ///
    /// Active ou désactive le Hardware LPM Enable (HLE) et règle le délai d'inactivité
    /// avant transition automatique en état L1 (`l1_timeout_128us` × 128 μs).
    ///
    /// # Errors
    ///
    /// Retourne [`SysError::InvalidArgument`] si `port` est hors de la plage valide.
    pub fn configure_port_lpm(
        &mut self,
        port: u8,
        enable: bool,
        l1_timeout_128us: u8,
    ) -> Result<(), SysError> {
        if port == 0 || port > self.max_ports {
            return Err(SysError::InvalidArgument);
        }
        let addr = self.porthlpmc_addr(port);
        // SAFETY: bar0_base est initialisé via init() depuis un BAR PCI valide et mappé
        // en MMIO. L'adresse calculée pointe vers le registre PORTHLPMC du port demandé.
        // La lecture-modification-écriture volatile garantit la cohérence avec le matériel.
        let raw = unsafe { core::ptr::read_volatile(addr as *const u32) };
        let mut hlpmc = PortHlpmc::parse(raw);
        hlpmc.hle_enabled = enable;
        hlpmc.l1_timeout_128us = l1_timeout_128us;
        // SAFETY: même contrat que la lecture ci-dessus. L'écriture volatile dans le
        // registre PORTHLPMC est atomique au sens matériel (registre 32-bit aligné).
        unsafe { core::ptr::write_volatile(addr as *mut u32, hlpmc.encode()) };
        Ok(())
    }

    /// Traite un TRB de changement de statut de port (Port Status Change Event, Type 34)
    /// et retourne l'événement de détection à chaud (Hot-Plug) avec télémétrie CSC/PRC.
    pub fn handle_port_status_change_trb(
        &mut self,
        trb: &Trb,
        raw_portsc: u32,
    ) -> Result<PortHotPlugEvent, SysError> {
        if trb.trb_type() != TRB_TYPE_PORT_STATUS_CHANGE {
            return Err(SysError::InvalidArgument);
        }

        let port_id = ((trb.parameter >> 24) & 0xFF) as u8;
        if port_id == 0 || port_id as usize > self.port_slots.len() {
            return Err(SysError::InvalidArgument);
        }

        let status = PortStatus::parse(raw_portsc);

        // Détection de condition de surintensité (OCA active ou OCC changé)
        if status.over_current || status.change_over_current {
            return Ok(PortHotPlugEvent::PortOverCurrentDetected {
                port_id,
                active: status.over_current,
            });
        }

        // Détection de basculement en mode de conformité (Compliance Mode)
        if status.link_state == PLS_COMPLIANCE_MODE {
            return Ok(PortHotPlugEvent::ComplianceModeEntered { port_id });
        }

        // Détection de réinitialisation terminée (PRC=1 et PR=0)
        if status.change_reset && !status.reset && status.connected {
            return Ok(PortHotPlugEvent::PortResetCompleted {
                port_id,
                speed: status.speed,
            });
        }

        // Détection d'erreur de configuration matérielle de lien USB 3.0 (CEC=1)
        if status.change_config_error {
            return Ok(PortHotPlugEvent::PortConfigErrorDetected { port_id });
        }

        // Détection de changement d'état de lien (PLC=1, ex: reprise de veille U3 -> U0 ou U3 -> Resume)
        if status.change_link_state {
            return Ok(PortHotPlugEvent::PortLinkStateChanged {
                port_id,
                link_state: status.link_state,
            });
        }

        // Détection de connexion (CCS=1)
        if status.connected {
            Ok(PortHotPlugEvent::DeviceConnected {
                port_id,
                speed: status.speed,
                change_connect: status.change_connect,
            })
        } else {
            // Déconnexion détectée (Hot-Unplug : CCS=0)
            let current_slot = self.port_slots[port_id as usize - 1];
            Ok(PortHotPlugEvent::DeviceDisconnected {
                port_id,
                slot_id: current_slot,
                change_connect: status.change_connect,
            })
        }
    }

    /// Traite la déconnexion à chaud (Hot-Unplug) d'un périphérique :
    /// désactive le slot de périphérique, réinitialise les anneaux de transfert associés
    /// et libère l'allocation de ressources Ring 3.
    pub fn handle_hotplug_disconnect(&mut self, port_id: u8) -> Result<Option<u8>, SysError> {
        if port_id == 0 || port_id as usize > self.port_slots.len() {
            return Err(SysError::InvalidArgument);
        }

        let slot_id = self.port_slots[port_id as usize - 1];
        if let Some(sid) = slot_id {
            // Émission de la commande de désactivation de slot
            let _ = self.disable_slot(sid);
            // Réinitialisation des endpoints
            for ep in self.ep_rings.iter_mut() {
                if ep.active {
                    ep.reset();
                }
            }
            self.port_slots[port_id as usize - 1] = None;
            Ok(Some(sid))
        } else {
            Ok(None)
        }
    }

    /// Soumet un Command Block Wrapper (CBW) sur l'endpoint Bulk OUT d'un périphérique Mass Storage BOT.
    pub fn submit_bot_cbw(
        &mut self,
        bot: &UsbMassStorageBot,
        cbw_iova: u64,
        ioc: bool,
    ) -> Result<usize, SysError> {
        self.queue_bulk_transfer(bot.bulk_out_ep, cbw_iova, 31, ioc, false)
    }

    /// Soumet un transfert de données entrant (Data IN) pour une transaction BOT.
    pub fn submit_bot_data_in(
        &mut self,
        bot: &UsbMassStorageBot,
        data_iova: u64,
        length: u32,
        ioc: bool,
    ) -> Result<usize, SysError> {
        self.queue_bulk_transfer(bot.bulk_in_ep, data_iova, length, ioc, true)
    }

    /// Soumet un transfert de données sortant (Data OUT) pour une transaction BOT.
    pub fn submit_bot_data_out(
        &mut self,
        bot: &UsbMassStorageBot,
        data_iova: u64,
        length: u32,
        ioc: bool,
    ) -> Result<usize, SysError> {
        self.queue_bulk_transfer(bot.bulk_out_ep, data_iova, length, ioc, false)
    }

    /// Soumet la réception d'un Command Status Wrapper (CSW, 13 octets) sur l'endpoint Bulk IN.
    pub fn submit_bot_csw(
        &mut self,
        bot: &UsbMassStorageBot,
        csw_iova: u64,
        ioc: bool,
    ) -> Result<usize, SysError> {
        self.queue_bulk_transfer(bot.bulk_in_ep, csw_iova, 13, ioc, false)
    }
}

// ============================================================================
// Tests Unitaires (Host & CI)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};
    use libjambo::pci::{PciAddress, PciBar, PciBarType};

    #[test]
    fn test_trb_layout_and_fields() {
        assert_eq!(size_of::<Trb>(), 16);
        assert_eq!(align_of::<Trb>(), 16);

        let trb = Trb::new(0x1000_2000, 0x0100_0000, TRB_TYPE_ENABLE_SLOT, true);
        assert!(trb.cycle_bit());
        assert_eq!(trb.trb_type(), TRB_TYPE_ENABLE_SLOT);
        assert_eq!(trb.completion_code(), 1);

        let link = Trb::link(0x4000_0000, false, true);
        assert_eq!(link.parameter, 0x4000_0000);
        assert_eq!(link.trb_type(), TRB_TYPE_LINK);
        assert!(!link.cycle_bit());
        assert_eq!(link.control & (1 << 1), 2); // Toggle Cycle bit actif
    }

    #[test]
    fn test_command_ring_wrap_and_link() {
        let mut ring = XhciRing::new();
        assert_eq!(ring.enqueue_idx, 0);
        assert!(ring.cycle_bit);

        // Remplir l'anneau jusqu'à la dernière entrée
        for i in 0..(RING_ENTRIES - 1) {
            let res = ring.push(i as u64, 0, TRB_TYPE_NORMAL);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), i);
        }

        assert_eq!(ring.enqueue_idx, RING_ENTRIES - 1);
        assert!(ring.cycle_bit);

        // La prochaine insertion doit déclencher l'écriture du Link TRB et inverser le cycle bit
        let res = ring.push(0xFFFF, 0, TRB_TYPE_NORMAL);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), RING_ENTRIES - 1);
        assert_eq!(ring.trbs[RING_ENTRIES - 1].trb_type(), TRB_TYPE_LINK);
        assert_eq!(ring.enqueue_idx, 0);
        assert!(!ring.cycle_bit); // Cycle bit inversé
    }

    #[test]
    fn test_keyboard_report_and_ascii_translation() {
        let mut kbd = UsbKeyboardState::default();

        // 1. Touche 'a' minuscule sans modifier
        let report_a = [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        kbd.decode_report(&report_a);
        assert!(!kbd.is_shift_pressed());
        assert_eq!(kbd.first_ascii_char(), Some('a'));

        // 2. Touche 'a' avec Shift gauche -> 'A'
        let report_shift_a = [0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        kbd.decode_report(&report_shift_a);
        assert!(kbd.left_shift);
        assert!(kbd.is_shift_pressed());
        assert_eq!(kbd.first_ascii_char(), Some('A'));

        // 3. Touche '1' avec Shift -> '!'
        let report_shift_1 = [0x02, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00];
        kbd.decode_report(&report_shift_1);
        assert_eq!(kbd.first_ascii_char(), Some('!'));

        // 4. Touche Enter
        let report_enter = [0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00];
        kbd.decode_report(&report_enter);
        assert_eq!(kbd.first_ascii_char(), Some('\n'));

        // 5. Touche Espace
        let report_space = [0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00];
        kbd.decode_report(&report_space);
        assert_eq!(kbd.first_ascii_char(), Some(' '));
    }

    #[test]
    fn test_mouse_report_decoding() {
        let mut mouse = UsbMouseState::default();

        // Clic gauche avec déplacement dx=+10, dy=-5 et molette=+1
        let report = [0x01, 10, (-5i8) as u8, 1];
        mouse.decode_report(&report);

        assert!(mouse.left_button);
        assert!(!mouse.right_button);
        assert!(!mouse.middle_button);
        assert!(!mouse.button4);
        assert!(!mouse.button5);
        assert_eq!(mouse.dx, 10);
        assert_eq!(mouse.dy, -5);
        assert_eq!(mouse.wheel, 1);
        assert_eq!(mouse.hwheel, 0);
    }

    #[test]
    fn test_mouse_5button_and_horizontal_wheel_decoding() {
        let mut mouse = UsbMouseState::default();

        // Rapport 5 octets : Clic Droit + Bouton 4 (Back) + Bouton 5 (Forward)
        // dx = -12, dy = 24, wheel = -2 (scroll down), hwheel = 3 (tilt right)
        let buttons = (1 << 1) | (1 << 3) | (1 << 4);
        let report = [buttons, (-12i8) as u8, 24, (-2i8) as u8, 3];
        mouse.decode_report(&report);

        assert!(!mouse.left_button);
        assert!(mouse.right_button);
        assert!(!mouse.middle_button);
        assert!(mouse.button4);
        assert!(mouse.button5);
        assert_eq!(mouse.dx, -12);
        assert_eq!(mouse.dy, 24);
        assert_eq!(mouse.wheel, -2);
        assert_eq!(mouse.hwheel, 3);
    }

    #[test]
    fn test_multitouch_digitizer_and_gestures() {
        let mut touch = UsbMultiTouchState::new();

        // Trame multi-touches : Bouton cliqué (0x01), 2 contacts
        // Contact 0 : ID 1, Tip=1, InRange=1, X=1000, Y=2000, Pressure=250
        // Contact 1 : ID 2, Tip=1, InRange=1, X=1500, Y=2000, Pressure=200
        // Scan time = 12345
        let c0_flags = 0x01 | 0x02 | (1 << 4);
        let c1_flags = 0x01 | 0x02 | (2 << 4);
        let report1 = [
            0x01, // Button down
            2,    // 2 contacts
            c0_flags,
            (1000u16 & 0xFF) as u8,
            (1000u16 >> 8) as u8,
            (2000u16 & 0xFF) as u8,
            (2000u16 >> 8) as u8,
            250,
            c1_flags,
            (1500u16 & 0xFF) as u8,
            (1500u16 >> 8) as u8,
            (2000u16 & 0xFF) as u8,
            (2000u16 >> 8) as u8,
            200,
            (12345u16 & 0xFF) as u8,
            (12345u16 >> 8) as u8,
        ];

        touch.decode_report(&report1);
        assert!(touch.button_down);
        assert_eq!(touch.contact_count, 2);
        assert_eq!(touch.active_contacts_count(), 2);
        assert_eq!(touch.contacts[0].contact_id, 1);
        assert_eq!(touch.contacts[0].x, 1000);
        assert_eq!(touch.contacts[0].y, 2000);
        assert_eq!(touch.contacts[1].contact_id, 2);
        assert_eq!(touch.contacts[1].x, 1500);
        assert_eq!(touch.contacts[1].y, 2000);
        assert_eq!(touch.scan_time, 12345);

        // Déplacement simultané vers le bas (+50 sur Y) -> Pan/Scroll
        let mut touch2 = touch;
        let report2 = [
            0x01,
            2,
            c0_flags,
            (1000u16 & 0xFF) as u8,
            (1000u16 >> 8) as u8,
            (2050u16 & 0xFF) as u8,
            (2050u16 >> 8) as u8,
            250,
            c1_flags,
            (1500u16 & 0xFF) as u8,
            (1500u16 >> 8) as u8,
            (2050u16 & 0xFF) as u8,
            (2050u16 >> 8) as u8,
            200,
            (12355u16 & 0xFF) as u8,
            (12355u16 >> 8) as u8,
        ];
        touch2.decode_report(&report2);

        let scroll = touch2.detect_two_finger_scroll(&touch);
        assert_eq!(scroll, Some((0, 50)));

        // Écartement horizontal (Pinch to zoom in)
        let mut touch3 = touch;
        let report3 = [
            0x01,
            2,
            c0_flags,
            (900u16 & 0xFF) as u8,
            (900u16 >> 8) as u8,
            (2000u16 & 0xFF) as u8,
            (2000u16 >> 8) as u8,
            250,
            c1_flags,
            (1600u16 & 0xFF) as u8,
            (1600u16 >> 8) as u8,
            (2000u16 & 0xFF) as u8,
            (2000u16 >> 8) as u8,
            200,
            (12365u16 & 0xFF) as u8,
            (12365u16 >> 8) as u8,
        ];
        touch3.decode_report(&report3);

        let zoom = touch3.detect_pinch_zoom(&touch);
        assert!(zoom.is_some());
        assert!(zoom.unwrap() > 0); // Écartement (distance passe de 500 à 700)
    }

    #[test]
    fn test_portsc_parsing() {
        // Port connecté (CCS=1), activé (PED=1), alimenté (PP=1), SuperSpeed (Speed=4)
        let raw_portsc = 1 | (1 << 1) | (1 << 9) | (4 << 10);
        let status = PortStatus::parse(raw_portsc);

        assert!(status.connected);
        assert!(status.enabled);
        assert!(status.powered);
        assert_eq!(status.speed, UsbSpeed::SuperSpeed);
    }

    #[test]
    fn test_controller_lifecycle_and_doorbell() {
        let mut ctrl = XhciController::new();
        assert!(!ctrl.ready);

        let pci_info = PciDeviceInfo {
            address: PciAddress::new(0, 4, 0),
            vendor_id: 0x8086,
            device_id: 0x15EC,
            class_code: 0x0C,
            subclass: 0x03,
            prog_if: 0x30,
            revision: 1,
            bar0: Some(PciBar {
                index: 0,
                bar_type: PciBarType::Memory64,
                base_address: 0xFE80_0000,
                prefetchable: false,
            }),
        };

        let init_res = ctrl.init(&pci_info);
        assert!(init_res.is_ok());
        assert!(ctrl.ready);
        assert_eq!(ctrl.bar0_base, 0xFE80_0000);

        // Vérification calcul Doorbell
        assert_eq!(ctrl.doorbell_offset(0), 0x2000);
        assert_eq!(ctrl.doorbell_offset(1), 0x2004);
        assert_eq!(ctrl.doorbell_payload(1, 0), 1);

        // Émission commande Enable Slot
        let slot_cmd_idx = ctrl.enable_slot().unwrap();
        assert_eq!(
            ctrl.cmd_ring.trbs[slot_cmd_idx].trb_type(),
            TRB_TYPE_ENABLE_SLOT
        );

        // Émission commande Address Device
        let addr_cmd_idx = ctrl.address_device(0x3000_1000, 1).unwrap();
        assert_eq!(
            ctrl.cmd_ring.trbs[addr_cmd_idx].trb_type(),
            TRB_TYPE_ADDRESS_DEVICE
        );
        assert_eq!(ctrl.cmd_ring.trbs[addr_cmd_idx].parameter, 0x3000_1000);

        // Événement de complétion positif
        let event_trb = Trb::new(
            0,
            (TRB_COMP_SUCCESS as u32) << 24,
            TRB_TYPE_CMD_COMPLETION_EVENT,
            true,
        );
        assert_eq!(ctrl.handle_event_trb(&event_trb), Ok(TRB_COMP_SUCCESS));

        // Auto-guérison après crash
        assert!(ctrl.recover_from_crash().is_ok());
        assert_eq!(ctrl.cmd_ring.enqueue_idx, 0);
    }

    #[test]
    fn test_bulk_transfer_submission_and_event() {
        let mut ctrl = XhciController::new();
        ctrl.ready = true;

        // Configuration d'un endpoint Bulk OUT (EP 2)
        assert!(ctrl.configure_endpoint_ring(2, false).is_ok());
        assert!(ctrl.ep_rings[2].active);
        assert!(!ctrl.ep_rings[2].is_isoch);

        // Soumission d'un transfert Bulk de 4096 octets
        let data_iova = 0x2000_8000u64;
        let trb_idx = ctrl
            .queue_bulk_transfer(2, data_iova, 4096, true, true)
            .expect("Queue bulk transfer");
        assert_eq!(trb_idx, 0);

        let queued_trb = ctrl.ep_rings[2].ring.trbs[0];
        assert_eq!(queued_trb.parameter, data_iova);
        assert_eq!(queued_trb.trb_type(), TRB_TYPE_NORMAL);
        assert_eq!(queued_trb.status & 0x1FFFF, 4096);
        assert!((queued_trb.control & TRB_FLAG_IOC) != 0);
        assert!((queued_trb.control & TRB_FLAG_ISP) != 0);

        // Traitement de l'événement de complétion de transfert
        // Transfer Event TRB : endpoint 2 (bits 20:16), code SUCCESS (bits 31:24), remainder = 0
        let event_control = ((TRB_TYPE_TRANSFER_EVENT & 0x3F) << 10) | (2 << 16) | 1;
        let event_status = (TRB_COMP_SUCCESS as u32) << 24; // 0 octet restant
        let event_trb = Trb {
            parameter: data_iova,
            status: event_status,
            control: event_control,
        };

        let status = ctrl.handle_transfer_event(&event_trb).expect("Event ok");
        assert!(status.completed);
        assert_eq!(status.bytes_transferred, 4096);
        assert_eq!(ctrl.ep_rings[2].total_bytes_transferred, 4096);
    }

    #[test]
    fn test_isochronous_transfer_submission_with_frame_and_sia() {
        let mut ctrl = XhciController::new();
        ctrl.ready = true;

        // Configuration d'un endpoint Isochrone IN (EP 4)
        assert!(ctrl.configure_endpoint_ring(4, true).is_ok());
        assert!(ctrl.ep_rings[4].active);
        assert!(ctrl.ep_rings[4].is_isoch);

        // Soumission d'un paquet isochrone avec SIA (Start Isoch ASAP)
        let data_iova = 0x3000_0000u64;
        let trb_idx = ctrl
            .queue_isoch_transfer(4, data_iova, 1024, 0, true, true, false)
            .expect("Queue isoch SIA");
        assert_eq!(trb_idx, 0);

        let isoch_trb = ctrl.ep_rings[4].ring.trbs[0];
        assert_eq!(isoch_trb.trb_type(), TRB_TYPE_ISOCH);
        assert!((isoch_trb.control & TRB_FLAG_SIA) != 0);

        // Soumission d'un paquet isochrone calé sur un Frame ID spécifique (ex: Frame 128)
        let trb_idx2 = ctrl
            .queue_isoch_transfer(4, data_iova + 1024, 512, 128, false, true, false)
            .expect("Queue isoch Frame ID");
        assert_eq!(trb_idx2, 1);

        let isoch_trb2 = ctrl.ep_rings[4].ring.trbs[1];
        assert_eq!(isoch_trb2.trb_type(), TRB_TYPE_ISOCH);
        assert_eq!((isoch_trb2.control >> 20) & 0x7FF, 128);
    }

    #[test]
    fn test_interrupter_erst_and_erdp() {
        let mut ctrl = XhciController::new();
        ctrl.ready = true;

        let erst_iova = 0x4000_1000u64; // aligné 64
        let ring_iova = 0x4000_2000u64; // aligné 64
        assert!(ctrl
            .init_primary_interrupter(erst_iova, ring_iova, 32)
            .is_ok());

        assert!(ctrl.interrupter.active);
        assert_eq!(ctrl.interrupter.erstba, erst_iova);
        assert_eq!(ctrl.interrupter.erstsz, 1);
        assert_eq!(ctrl.interrupter.erdp, ring_iova | (1 << 3));
        assert!(ctrl.interrupter.cycle_bit);

        // Simulation de consommation de 2 événements
        let next_event_addr1 = ring_iova + 16;
        ctrl.acknowledge_erdp(next_event_addr1);
        assert_eq!(ctrl.interrupter.dequeue_idx, 1);
        assert_eq!(ctrl.interrupter.events_handled, 1);
        assert_eq!(ctrl.interrupter.erdp, next_event_addr1 | (1 << 3));

        let next_event_addr2 = ring_iova + 32;
        ctrl.acknowledge_erdp(next_event_addr2);
        assert_eq!(ctrl.interrupter.dequeue_idx, 2);
        assert_eq!(ctrl.interrupter.events_handled, 2);
    }

    #[test]
    fn test_hotplug_connect_and_disconnect_handling() {
        let mut ctrl = XhciController::new();
        ctrl.ready = true;

        // Configuration d'un endpoint pour tester la réinitialisation
        assert!(ctrl.configure_endpoint_ring(1, false).is_ok());
        assert!(ctrl.ep_rings[1].active);

        // 1. Événement Port Status Change : Port 1 connecté en SuperSpeed avec CSC=1 (raw PORTSC: CCS=1, PED=1, PP=1, Speed=4, CSC=bit 17)
        let raw_connect = 1 | (1 << 1) | (1 << 9) | (4 << 10) | PORTSC_CSC;
        let trb_connect = Trb {
            parameter: 1 << 24, // Port ID 1 dans bits 31:24
            status: (TRB_COMP_SUCCESS as u32) << 24,
            control: (TRB_TYPE_PORT_STATUS_CHANGE << 10) | 1,
        };

        let ev_connect = ctrl
            .handle_port_status_change_trb(&trb_connect, raw_connect)
            .expect("Port status change ok");
        assert_eq!(
            ev_connect,
            PortHotPlugEvent::DeviceConnected {
                port_id: 1,
                speed: UsbSpeed::SuperSpeed,
                change_connect: true,
            }
        );

        let status_conn = PortStatus::parse(raw_connect);
        assert!(status_conn.change_connect);
        assert_eq!(status_conn.acknowledge_changes_mask(), PORTSC_CSC);

        // Attribution du slot 3 au port 1
        assert!(ctrl.bind_port_slot(1, 3).is_ok());
        assert_eq!(ctrl.port_slots[0], Some(3));

        // 2. Événement Déconnexion à chaud (Hot-Unplug) : CCS=0 (déconnecté) et CSC=1
        let raw_disconnect = (1 << 9) | PORTSC_CSC; // Alim active mais CCS=0 avec bit CSC
        let trb_disconnect = Trb {
            parameter: 1 << 24, // Port ID 1
            status: (TRB_COMP_SUCCESS as u32) << 24,
            control: (TRB_TYPE_PORT_STATUS_CHANGE << 10) | 1,
        };

        let ev_disconnect = ctrl
            .handle_port_status_change_trb(&trb_disconnect, raw_disconnect)
            .expect("Port status disconnect ok");
        assert_eq!(
            ev_disconnect,
            PortHotPlugEvent::DeviceDisconnected {
                port_id: 1,
                slot_id: Some(3),
                change_connect: true,
            }
        );

        // Exécution de la déconnexion et libération du slot
        let freed_slot = ctrl.handle_hotplug_disconnect(1).expect("Disconnect ok");
        assert_eq!(freed_slot, Some(3));
        assert_eq!(ctrl.port_slots[0], None);
        assert!(!ctrl.ep_rings[1].active); // Endpoint réinitialisé

        // 3. Événement Réinitialisation de Port terminée (PRC=1, PR=0, CCS=1)
        let raw_reset_done = 1 | (1 << 1) | (1 << 9) | (4 << 10) | PORTSC_PRC;
        let trb_reset = Trb {
            parameter: 1 << 24,
            status: (TRB_COMP_SUCCESS as u32) << 24,
            control: (TRB_TYPE_PORT_STATUS_CHANGE << 10) | 1,
        };
        let ev_reset = ctrl
            .handle_port_status_change_trb(&trb_reset, raw_reset_done)
            .expect("Port reset done ok");
        assert_eq!(
            ev_reset,
            PortHotPlugEvent::PortResetCompleted {
                port_id: 1,
                speed: UsbSpeed::SuperSpeed,
            }
        );
    }

    #[test]
    fn test_bulk_scatter_gather_and_streams() {
        let mut ctrl = XhciController::new();
        ctrl.ready = true;

        assert!(ctrl.configure_endpoint_ring(2, false).is_ok());

        // 1. Test Scatter-Gather sur Endpoint 2 (3 segments non contigus)
        let segments = [
            SgSegment::new(0x1000_0000, 2048),
            SgSegment::new(0x2000_0000, 4096),
            SgSegment::new(0x3000_0000, 1024),
        ];

        let sg_idx = ctrl
            .queue_bulk_scatter_gather(2, &segments, true, true)
            .expect("queue scatter gather");
        assert_eq!(sg_idx, 0);

        let ep = &ctrl.ep_rings[2];
        // Premier segment : Chain bit = 1, IOC = 0
        assert_eq!(ep.ring.trbs[0].parameter, 0x1000_0000);
        assert_ne!(ep.ring.trbs[0].control & TRB_FLAG_CH, 0);
        assert_eq!(ep.ring.trbs[0].control & TRB_FLAG_IOC, 0);

        // Deuxième segment : Chain bit = 1, IOC = 0
        assert_eq!(ep.ring.trbs[1].parameter, 0x2000_0000);
        assert_ne!(ep.ring.trbs[1].control & TRB_FLAG_CH, 0);
        assert_eq!(ep.ring.trbs[1].control & TRB_FLAG_IOC, 0);

        // Troisième segment : Chain bit = 0, IOC = 1, ISP = 1
        assert_eq!(ep.ring.trbs[2].parameter, 0x3000_0000);
        assert_eq!(ep.ring.trbs[2].control & TRB_FLAG_CH, 0);
        assert_ne!(ep.ring.trbs[2].control & TRB_FLAG_IOC, 0);
        assert_ne!(ep.ring.trbs[2].control & TRB_FLAG_ISP, 0);

        // 2. Test Bulk Stream (UAS - Stream ID 1 et 2)
        assert!(ctrl.configure_bulk_stream(2, 1).is_ok());
        assert!(ctrl.configure_bulk_stream(2, 2).is_ok());
        assert!(ctrl.ep_rings[2].streams_enabled);

        // Soumission de transfert sur Stream 1
        let s1_idx = ctrl
            .queue_stream_bulk_transfer(2, 1, 0x5000_0000, 4096, true, false)
            .expect("queue stream 1");
        assert_eq!(s1_idx, 0);

        // Soumission de transfert scatter-gather sur Stream 2
        let stream_sg = [
            SgSegment::new(0x6000_0000, 512),
            SgSegment::new(0x7000_0000, 1536),
        ];
        let s2_idx = ctrl
            .queue_stream_scatter_gather(2, 2, &stream_sg, true, false)
            .expect("queue stream 2 sg");
        assert_eq!(s2_idx, 0);

        // Complétion de stream 1
        let trb_ev = Trb {
            parameter: 0x5000_0000,
            status: (TRB_COMP_SUCCESS as u32) << 24, // 0 bytes remaining
            control: (TRB_TYPE_TRANSFER_EVENT << 10) | (2 << 16) | 1,
        };
        let status = ctrl
            .handle_stream_transfer_event(2, 1, &trb_ev)
            .expect("stream 1 completion");
        assert!(status.completed);
        assert_eq!(status.bytes_transferred, 4096);
        assert_eq!(ctrl.ep_rings[2].streams[0].total_bytes_transferred, 4096);
    }

    #[test]
    fn test_usb_hub_descriptors_and_status() {
        // Test UsbHubDescriptor
        let hub_desc = UsbHubDescriptor {
            length: 9,
            descriptor_type: USB_DESC_TYPE_HUB,
            num_ports: 4,
            characteristics: 0x0009,
            power_on_to_power_good: 50,
            hub_controller_current: 100,
            device_removable: 0,
        };
        assert!(hub_desc.is_valid());
        assert_eq!(hub_desc.ports(), 4);

        // Test UsbSsHubDescriptor
        let ss_hub_desc = UsbSsHubDescriptor {
            length: 12,
            descriptor_type: USB_DESC_TYPE_SS_HUB,
            num_ports: 8,
            characteristics: 0x0008,
            power_on_to_power_good: 32,
            hub_controller_current: 0,
            hub_hdr_dec_lat: 4,
            hub_delay: 160,
            device_removable: 0,
        };
        assert!(ss_hub_desc.is_valid());
        assert_eq!(ss_hub_desc.ports(), 8);

        // Test UsbHubStatus
        let status = UsbHubStatus::parse(0x0001, 0x0002);
        assert!(status.local_power_lost);
        assert!(!status.over_current);
        assert!(!status.change_local_power);
        assert!(status.change_over_current);

        // Test HubPortStatusAndChange (Port connecté, alimenté, SuperSpeed, changement connect)
        let port_sc = HubPortStatusAndChange::parse(0x0103, 0x0001);
        assert!(port_sc.connected);
        assert!(port_sc.enabled);
        assert!(port_sc.powered);
        assert!(port_sc.change_connect);
    }

    #[test]
    fn test_mass_storage_bot_cbw_csw_roundtrip() {
        let mut bot = UsbMassStorageBot::new(1, 1, 2);
        assert_eq!(bot.sector_size, 512);

        // 1. SCSI TEST UNIT READY
        let (cbw_tur, tag_tur) = bot.build_cbw_test_unit_ready();
        assert_eq!(cbw_tur.signature(), CBW_SIGNATURE);
        assert_eq!(cbw_tur.tag(), tag_tur);
        assert_eq!(cbw_tur.data_transfer_length(), 0);
        assert_eq!(cbw_tur.cb[0], SCSI_CMD_TEST_UNIT_READY);

        // 2. SCSI INQUIRY
        let (cbw_inq, tag_inq) = bot.build_cbw_inquiry();
        assert_eq!(cbw_inq.tag(), tag_inq);
        assert_eq!(cbw_inq.data_transfer_length(), 36);
        assert_eq!(cbw_inq.cb[0], SCSI_CMD_INQUIRY);
        assert_eq!(cbw_inq.flags(), CBW_FLAG_DATA_IN);

        let mut inq_resp = [0u8; 36];
        inq_resp[0] = 0x00; // Direct Access Block Device
        inq_resp[1] = 0x80; // Removable
        inq_resp[8..16].copy_from_slice(b"JAMBO_OS");
        inq_resp[16..32].copy_from_slice(b"USB FLASH DRIVE ");
        inq_resp[32..36].copy_from_slice(b"1.00");

        let inq_info = bot
            .parse_inquiry_response(&inq_resp)
            .expect("valid inquiry");
        assert_eq!(inq_info.peripheral_device_type, 0);
        assert!(inq_info.is_removable);
        assert_eq!(&inq_info.vendor_id, b"JAMBO_OS");
        assert_eq!(&inq_info.product_id, b"USB FLASH DRIVE ");

        // 3. SCSI READ CAPACITY (10)
        let (cbw_cap, tag_cap) = bot.build_cbw_read_capacity_10();
        assert_eq!(cbw_cap.tag(), tag_cap);
        assert_eq!(cbw_cap.data_transfer_length(), 8);

        // Réponse: Dernier LBA = 0x001E847F (1 999 999 -> 2 000 000 secteurs), Taille de bloc = 512
        let cap_resp: [u8; 8] = [
            0x00, 0x1E, 0x84, 0x7F, // LBA
            0x00, 0x00, 0x02, 0x00, // 512 octets
        ];
        let cap = bot.parse_read_capacity_10(&cap_resp).expect("valid cap");
        assert_eq!(cap.last_lba, 1_999_999);
        assert_eq!(cap.block_size, 512);
        assert_eq!(cap.total_sectors, 2_000_000);
        assert_eq!(cap.total_bytes, 1_024_000_000); // 1.024 Go
        assert!(bot.is_ready);

        // 4. SCSI READ (10) et vérification CSW
        let (cbw_read, tag_read) = bot.build_cbw_read_10(100, 8);
        assert_eq!(cbw_read.data_transfer_length(), 8 * 512);
        assert_eq!(cbw_read.cb[0], SCSI_CMD_READ_10);

        let csw_bytes = [
            0x55,
            0x53,
            0x42,
            0x53, // "USBS" signature
            (tag_read & 0xFF) as u8,
            ((tag_read >> 8) & 0xFF) as u8,
            ((tag_read >> 16) & 0xFF) as u8,
            ((tag_read >> 24) & 0xFF) as u8,
            0x00,
            0x00,
            0x00,
            0x00, // data residue = 0
            0x00, // CSW_STATUS_PASSED
        ];
        let residue = bot.verify_csw(tag_read, &csw_bytes).expect("csw passed");
        assert_eq!(residue, 0);

        // 5. Test Controller BOT submission
        let mut ctrl = XhciController::new();
        ctrl.ready = true;
        assert!(ctrl.configure_endpoint_ring(1, false).is_ok()); // Bulk IN
        assert!(ctrl.configure_endpoint_ring(2, false).is_ok()); // Bulk OUT

        let cbw_idx = ctrl
            .submit_bot_cbw(&bot, 0x1000_0000, true)
            .expect("cbw submit");
        assert_eq!(cbw_idx, 0);

        let data_idx = ctrl
            .submit_bot_data_in(&bot, 0x2000_0000, 4096, true)
            .expect("data in submit");
        assert_eq!(data_idx, 0);

        let csw_idx = ctrl
            .submit_bot_csw(&bot, 0x3000_0000, true)
            .expect("csw submit");
        assert_eq!(csw_idx, 1); // 2nd TRB on Bulk IN
    }

    #[test]
    fn test_usb_config_descriptor_parsing_bulk_and_isoch() {
        // Blob binaire conforme USB 3.0 / USB 2.0 (54 octets au total)
        // [0..9]   Configuration Descriptor (total_length = 54, 2 interfaces)
        // [9..18]  Interface 0 Descriptor (Mass Storage BOT, 2 endpoints)
        // [18..25] Endpoint 1 Bulk OUT (addr 0x02, attr 0x02, max_packet 512)
        // [25..32] Endpoint 1 Bulk IN  (addr 0x81, attr 0x02, max_packet 512)
        // [32..41] Interface 1 Descriptor (Streaming Isochronous, 1 endpoint)
        // [41..48] Endpoint 2 Isochronous IN (addr 0x82, attr 0x01, max_packet 1024, interval 1)
        // [48..54] SuperSpeed Endpoint Companion (burst 3, mult 2)
        let config_raw: [u8; 54] = [
            // Configuration Descriptor (9 bytes)
            0x09, 0x02, 54, 0x00, 0x02, 0x01, 0x00, 0xC0,
            0x32, // Interface 0 (Mass Storage, 9 bytes)
            0x09, 0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00,
            // Endpoint 2 Bulk OUT (7 bytes, addr 0x02)
            0x07, 0x05, 0x02, 0x02, 0x00, 0x02, 0x00,
            // Endpoint 1 Bulk IN (7 bytes, addr 0x81)
            0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00, // Interface 1 (Streaming, 9 bytes)
            0x09, 0x04, 0x01, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00,
            // Endpoint 2 Isochronous IN (7 bytes, addr 0x82)
            0x07, 0x05, 0x82, 0x01, 0x00, 0x04, 0x01,
            // SuperSpeed Companion (6 bytes, max_burst = 3, attr = 1 => mult 2)
            0x06, 0x30, 0x03, 0x01, 0x00, 0x0C,
        ];

        let parsed = UsbConfigParser::parse_configuration(&config_raw)
            .expect("Parsing configuration valide");
        assert_eq!(parsed.configuration_value, 1);
        assert_eq!(parsed.max_power_ma, 100);
        assert_eq!(parsed.interface_count, 2);
        assert_eq!(parsed.total_endpoints(), 3);

        // Vérification Interface 0 (Mass Storage Bulk)
        let iface0 = &parsed.interfaces[0];
        assert_eq!(iface0.class, 0x08);
        assert_eq!(iface0.endpoint_count, 2);

        let (bulk_in, bulk_out) = parsed.find_bulk_endpoints();
        assert!(bulk_in.is_some());
        assert!(bulk_out.is_some());
        let b_in = bulk_in.unwrap();
        let b_out = bulk_out.unwrap();
        assert_eq!(b_in.endpoint_address, 0x81);
        assert_eq!(b_in.dci, 3); // DCI = 1*2 + 1 = 3
        assert!(b_in.is_bulk());
        assert!(b_in.is_in());
        assert_eq!(b_in.max_packet_size, 512);

        assert_eq!(b_out.endpoint_address, 0x02);
        assert_eq!(b_out.dci, 4); // DCI = 2*2 + 0 = 4
        assert!(b_out.is_bulk());
        assert!(b_out.is_out());
        assert_eq!(b_out.max_packet_size, 512);

        // Vérification Interface 1 (Isochronous Streaming)
        let mut isoch_eps = [UsbDecodedEndpoint::default(); 4];
        let isoch_count = parsed.find_isochronous_endpoints(&mut isoch_eps);
        assert_eq!(isoch_count, 1);
        let iso_ep = isoch_eps[0];
        assert_eq!(iso_ep.endpoint_address, 0x82);
        assert_eq!(iso_ep.dci, 5); // DCI = 2*2 + 1 = 5
        assert!(iso_ep.is_isochronous());
        assert!(iso_ep.is_in());
        assert_eq!(iso_ep.max_packet_size, 1024);
        assert_eq!(iso_ep.max_burst, 3);
        assert_eq!(iso_ep.mult, 2);

        // Test configuration xHCI automatique
        let mut ctrl = XhciController::new();
        ctrl.ready = true;
        let configured = ctrl
            .configure_endpoints_from_decoded_config(&parsed)
            .expect("Config controllers endpoints");
        assert_eq!(configured, 3);
        assert!(ctrl.ep_rings[3].active && !ctrl.ep_rings[3].is_isoch); // Bulk IN DCI 3
        assert!(ctrl.ep_rings[4].active && !ctrl.ep_rings[4].is_isoch); // Bulk OUT DCI 4
        assert!(ctrl.ep_rings[5].active && ctrl.ep_rings[5].is_isoch); // Isoch IN DCI 5

        // Test rejet de descripteur tronqué
        let truncated = &config_raw[..20];
        assert!(UsbConfigParser::parse_configuration(truncated).is_err());

        // Test rejet de descripteur corrompu (longueur déclarée impossible)
        let mut corrupted = config_raw;
        corrupted[18] = 0; // desc_len = 0
        assert!(UsbConfigParser::parse_configuration(&corrupted).is_err());
    }

    #[test]
    fn test_usb_config_descriptor_parsing_hid_composite() {
        // Blob binaire pour périphérique composite Clavier Boot + Souris Multimédia
        // Total : 9 (Config) + 9 (Interface 0 KB) + 9 (HID Desc KB) + 7 (EP 1 IN) + 9 (Interface 1 Mouse) + 9 (HID Desc Mouse) + 7 (EP 2 IN) = 59 octets
        let config_raw: [u8; 59] = [
            // Configuration Descriptor (9 bytes)
            0x09,
            0x02,
            59,
            0x00,
            0x02,
            0x01,
            0x00,
            0xA0,
            0x32,
            // Interface 0 Descriptor (HID Keyboard, 9 bytes)
            0x09,
            0x04,
            0x00,
            0x00,
            0x01,
            USB_CLASS_HID,
            USB_SUBCLASS_BOOT_INTERFACE,
            USB_PROTOCOL_KEYBOARD,
            0x00,
            // HID Descriptor Interface 0 (9 bytes)
            0x09,
            USB_DESC_TYPE_HID,
            0x11,
            0x01,
            0x00,
            0x01,
            USB_DESC_TYPE_HID_REPORT,
            65,
            0x00,
            // Endpoint 1 Interrupt IN (7 bytes, addr 0x81, interval 10ms)
            0x07,
            USB_DESC_TYPE_ENDPOINT,
            0x81,
            USB_EP_ATTR_INTERRUPT,
            0x08,
            0x00,
            10,
            // Interface 1 Descriptor (HID Mouse, 9 bytes)
            0x09,
            0x04,
            0x01,
            0x00,
            0x01,
            USB_CLASS_HID,
            USB_SUBCLASS_BOOT_INTERFACE,
            USB_PROTOCOL_MOUSE,
            0x00,
            // HID Descriptor Interface 1 (9 bytes)
            0x09,
            USB_DESC_TYPE_HID,
            0x11,
            0x01,
            0x00,
            0x01,
            USB_DESC_TYPE_HID_REPORT,
            52,
            0x00,
            // Endpoint 2 Interrupt IN (7 bytes, addr 0x82, interval 8ms)
            0x07,
            USB_DESC_TYPE_ENDPOINT,
            0x82,
            USB_EP_ATTR_INTERRUPT,
            0x08,
            0x00,
            8,
        ];

        let parsed = UsbConfigParser::parse_configuration(&config_raw)
            .expect("Parsing configuration HID valide");
        assert_eq!(parsed.configuration_value, 1);
        assert_eq!(parsed.interface_count, 2);
        assert_eq!(parsed.total_endpoints(), 2);

        // Interface 0 (Clavier)
        let iface0 = &parsed.interfaces[0];
        assert!(iface0.is_hid());
        assert!(iface0.is_hid_keyboard());
        assert!(!iface0.is_hid_mouse());
        let hid0 = iface0.hid_descriptor.expect("HID descriptor iface 0");
        let bcd0 = hid0.bcd_hid;
        let rpt_len0 = hid0.report_descriptor_length;
        assert_eq!(bcd0, 0x0111);
        assert_eq!(rpt_len0, 65);
        assert_eq!(iface0.endpoint_count, 1);
        let ep0 = &iface0.endpoints[0];
        assert!(ep0.is_interrupt());
        assert!(ep0.is_in());
        assert_eq!(ep0.dci, 3); // 1*2 + 1 = 3

        // Interface 1 (Souris)
        let iface1 = &parsed.interfaces[1];
        assert!(iface1.is_hid());
        assert!(!iface1.is_hid_keyboard());
        assert!(iface1.is_hid_mouse());
        let hid1 = iface1.hid_descriptor.expect("HID descriptor iface 1");
        let bcd1 = hid1.bcd_hid;
        let rpt_len1 = hid1.report_descriptor_length;
        assert_eq!(bcd1, 0x0111);
        assert_eq!(rpt_len1, 52);
        assert_eq!(iface1.endpoint_count, 1);
        let ep1 = &iface1.endpoints[0];
        assert!(ep1.is_interrupt());
        assert!(ep1.is_in());
        assert_eq!(ep1.dci, 5); // 2*2 + 1 = 5

        // find_hid_endpoints
        let mut hid_eps = [(
            UsbDecodedInterface::default(),
            UsbDecodedEndpoint::default(),
        ); 4];
        let hid_count = parsed.find_hid_endpoints(&mut hid_eps);
        assert_eq!(hid_count, 2);
        assert_eq!(hid_eps[0].1.dci, 3);
        assert_eq!(hid_eps[1].1.dci, 5);

        // Décodage Consumer Controls multimédia
        let mut consumer = UsbConsumerControlState::default();
        consumer.decode_report(&[0x01, 0x00]); // Play/Pause
        assert!(consumer.play_pause);
        assert!(!consumer.mute);

        consumer.decode_report(&[0x50, 0x00]); // Volume Up (bit 4) | Mute (bit 6)
        assert!(consumer.volume_increment);
        assert!(consumer.mute);
        assert!(!consumer.play_pause);

        // Décodage System Controls (Touches marche/arrêt et veille ACPI)
        let mut sys_ctl = UsbSystemControlState::default();
        sys_ctl.decode_report(&[0x01]); // Power Down
        assert!(sys_ctl.power_down);
        assert_eq!(sys_ctl.primary_event(), Some(SystemPowerEvent::PowerDown));

        sys_ctl.decode_report(&[0x02]); // Sleep
        assert!(sys_ctl.sleep);
        assert_eq!(sys_ctl.primary_event(), Some(SystemPowerEvent::Sleep));

        sys_ctl.decode_report(&[0x04]); // Wake Up
        assert!(sys_ctl.wake_up);
        assert_eq!(sys_ctl.primary_event(), Some(SystemPowerEvent::WakeUp));

        sys_ctl.decode_report(&[0x08]); // Cold Restart
        assert!(sys_ctl.cold_restart);
        assert_eq!(sys_ctl.primary_event(), Some(SystemPowerEvent::ColdRestart));

        sys_ctl.decode_report(&[0x10]); // Warm Restart
        assert!(sys_ctl.warm_restart);
        assert_eq!(sys_ctl.primary_event(), Some(SystemPowerEvent::WarmRestart));

        // Décodage et contrôle des indicateurs d'état et LEDs du clavier (Caps/Num/Scroll lock et Fn-Lock)
        let mut leds = UsbKeyboardLedState::default();
        assert_eq!(leds.encode_mask(), 0);

        // Activation de NumLock
        assert!(leds.toggle_num_lock());
        assert_eq!(leds.encode_mask(), UsbKeyboardLedState::MASK_NUM_LOCK);

        // Activation combinée CapsLock + ScrollLock + FnLock
        leds.caps_lock = true;
        leds.scroll_lock = true;
        leds.fn_lock = true;
        let expected_mask = UsbKeyboardLedState::MASK_NUM_LOCK
            | UsbKeyboardLedState::MASK_CAPS_LOCK
            | UsbKeyboardLedState::MASK_SCROLL_LOCK
            | UsbKeyboardLedState::MASK_FN_LOCK;
        assert_eq!(leds.encode_mask(), expected_mask);

        // Décodage inverse
        let mut decoded_leds = UsbKeyboardLedState::default();
        decoded_leds.decode_mask(expected_mask);
        assert!(decoded_leds.num_lock);
        assert!(decoded_leds.caps_lock);
        assert!(decoded_leds.scroll_lock);
        assert!(decoded_leds.fn_lock);
        assert!(!decoded_leds.compose);
        assert!(!decoded_leds.kana);

        // Génération du paquet SETUP USB SET_REPORT
        let setup_pkt = leds.build_set_report_setup_packet(0);
        assert_eq!(setup_pkt[0], 0x21); // Class request
        assert_eq!(setup_pkt[1], 0x09); // SET_REPORT
        assert_eq!(setup_pkt[3], 0x02); // Output Report
        assert_eq!(setup_pkt[4], 0x00); // Interface 0
        assert_eq!(setup_pkt[6], 0x01); // 1 byte
    }

    #[test]
    fn test_xhci_mfindex_and_isoch_audio_video_synchronization() {
        let mut ctrl = XhciController::new();
        ctrl.ready = true;

        // 1. Test du registre MFINDEX et de la conversion en Frame ID USB
        assert_eq!(ctrl.read_mfindex(), 0);
        assert_eq!(ctrl.current_frame_id(), 0);

        // 8 microtrames de 125 us = 1 trame (1 ms)
        let (mf1, wrap1) = ctrl.step_mfindex(8);
        assert_eq!(mf1, 8);
        assert!(!wrap1);
        assert_eq!(ctrl.current_frame_id(), 1);

        // Avance jusqu'à la limite du masque 14 bits (16383)
        let (mf2, wrap2) = ctrl.step_mfindex(16375);
        assert_eq!(mf2, 16383);
        assert!(!wrap2);
        assert_eq!(ctrl.current_frame_id(), 2047);

        // Bouclage (Wrap-around) modulo 16384
        let (mf3, wrap3) = ctrl.step_mfindex(1);
        assert_eq!(mf3, 0);
        assert!(wrap3);
        assert_eq!(ctrl.current_frame_id(), 0);

        // Génération du TRB MFINDEX Wrap Event
        let wrap_trb = ctrl.create_mfindex_wrap_trb();
        assert_eq!(wrap_trb.trb_type(), TRB_TYPE_MFINDEX_WRAP);

        // 2. Enregistrement d'un flux audio PCM (EP 4, interval = 1 ms, 192 bytes/packet)
        assert!(ctrl
            .register_isoch_stream(4, IsochMediaType::AudioPcm, 1, 192, 1, 0)
            .is_ok());
        let audio_stream = ctrl.isoch_streams[4].unwrap();
        assert_eq!(audio_stream.media_type, IsochMediaType::AudioPcm);
        assert_eq!(audio_stream.interval_microframes, 1);
        assert_eq!(audio_stream.max_packet_size, 192);

        // 3. Planification synchronisée avec Target Frame ID (+8 ms dans le futur)
        let cur_fid = ctrl.current_frame_id();
        let target_fid = (cur_fid + 8) & 0x7FF;
        let res1 = ctrl
            .schedule_isoch_packet(4, 0x1000_2000, 192, Some(target_fid), true, false)
            .expect("Schedule isoch audio packet");
        assert_eq!(res1.frame_id, target_fid);
        assert!(!res1.is_sia);

        // 4. Planification avec Start Isoch ASAP (SIA)
        let res2 = ctrl
            .schedule_isoch_packet(4, 0x1000_20C0, 192, None, true, false)
            .expect("Schedule isoch ASAP");
        assert!(res2.is_sia);

        // 5. Détection de paquet périmé (target frame déjà passée dans le passé critique)
        let expired_fid = cur_fid.wrapping_sub(20) & 0x7FF;
        let expired_res =
            ctrl.schedule_isoch_packet(4, 0x1000_3000, 192, Some(expired_fid), true, false);
        assert_eq!(expired_res, Err(SysError::ResourceBusy));
        assert_eq!(ctrl.isoch_streams[4].unwrap().dropped_packets, 1);

        // 6. Traitement d'un événement de transfert Isochrone réussi
        let success_event = Trb {
            parameter: 0x1000_2000,
            status: (TRB_COMP_SUCCESS as u32) << 24, // 0 bytes remainder
            control: (4u32 << 16) | (TRB_TYPE_TRANSFER_EVENT << 10),
        };
        let ev_status = ctrl
            .handle_isoch_transfer_event(&success_event)
            .expect("Isoch transfer event success");
        assert!(ev_status.completed);
        assert_eq!(ev_status.bytes_transferred, 192);
        assert_eq!(ctrl.isoch_streams[4].unwrap().synced_packets, 1);
        assert_eq!(ctrl.isoch_streams[4].unwrap().total_bytes, 192);

        // 7. Traitement d'un événement d'échec Missed Service Error (0x1F)
        let missed_event = Trb {
            parameter: 0x1000_3000,
            status: (TRB_COMP_MISSED_SERVICE_ERROR as u32) << 24,
            control: (4u32 << 16) | (TRB_TYPE_TRANSFER_EVENT << 10),
        };
        let missed_res = ctrl.handle_isoch_transfer_event(&missed_event);
        assert_eq!(missed_res, Err(SysError::ResourceBusy));
        assert_eq!(ctrl.isoch_streams[4].unwrap().dropped_packets, 2);

        // 8. Enregistrement d'un flux vidéo UVC (EP 6, mult=3, burst=7, 1024 bytes)
        assert!(ctrl
            .register_isoch_stream(6, IsochMediaType::VideoUvc, 3, 1024, 3, 7)
            .is_ok());
        let uvc_stream = ctrl.isoch_streams[6].unwrap();
        assert_eq!(uvc_stream.media_type, IsochMediaType::VideoUvc);
        assert_eq!(uvc_stream.mult, 3);
        assert_eq!(uvc_stream.max_burst, 7);
    }

    #[test]
    fn test_hid_interrupt_endpoints_and_hardware_throttling() {
        let mut ctrl = XhciController::new();
        ctrl.ready = true;

        // 1. Test du registre matériel de modération IMOD
        ctrl.interrupter.set_moderation(4000); // 4000 * 250ns = 1 ms
        assert_eq!(ctrl.interrupter.moderation_interval_ns(), 1_000_000);
        assert_eq!(ctrl.interrupter.moderation_interval_us(), 1000);

        // 2. Configuration d'un endpoint d'interruption HID Clavier (EP 1, IN)
        assert!(ctrl
            .configure_hid_interrupt_endpoint(1, false, 8, 1000, true)
            .is_ok());
        assert!(ctrl.ep_rings[1].active);
        assert!(ctrl.ep_rings[1].is_interrupt);
        assert!(!ctrl.ep_rings[1].is_isoch);

        // 3. Soumission d'un transfert d'interruption TRB Normal avec IOC
        let trb_idx = ctrl
            .queue_interrupt_transfer(1, 0x2000_1000, 8, true)
            .expect("Queue interrupt transfer");
        assert_eq!(trb_idx, 0);
        let trb = ctrl.ep_rings[1].ring.trbs[0];
        assert_eq!(trb.parameter, 0x2000_1000);
        assert_eq!(trb.trb_type(), TRB_TYPE_NORMAL);
        assert!((trb.control & TRB_FLAG_IOC) != 0);

        // 4. Premier rapport clavier à la microtrame 0 : Touche 'A' (code 0x04)
        let report_a = [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let res1 = ctrl
            .process_hid_interrupt_report(1, &report_a, 0)
            .expect("Process report 1");
        assert!(res1, "Le premier rapport doit être admis et délivré");
        assert_eq!(ctrl.keyboard.first_ascii_char(), Some('a'));

        // 5. Deuxième rapport à la microtrame 2 (delta = 2 < 8 microtrames requises) : Touche 'B' (code 0x05)
        let report_b = [0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let res2 = ctrl
            .process_hid_interrupt_report(1, &report_b, 2)
            .expect("Process report 2");
        assert!(!res2, "Le rapport trop rapide doit être modéré/throttlé");
        // Le clavier conserve l'état antérieur
        assert_eq!(ctrl.keyboard.first_ascii_char(), Some('a'));

        // 6. Troisième rapport après écoulement du délai de throttling (microtrame 10 >= 0 + 8)
        let res3 = ctrl
            .process_hid_interrupt_report(1, &report_b, 10)
            .expect("Process report 3");
        assert!(res3, "Le rapport après le délai minimal doit être délivré");
        assert_eq!(ctrl.keyboard.first_ascii_char(), Some('b'));

        // 7. Filtrage anti-rebond matériel (debounce) sur un rapport identique à microtrame 20
        let res4 = ctrl
            .process_hid_interrupt_report(1, &report_b, 20)
            .expect("Process report 4 (duplicate)");
        assert!(
            !res4,
            "Le rapport identique consécutif doit être filtré par le debounce"
        );

        // 8. Vérification des statistiques de throttling
        let throttle_kb = ctrl.hid_throttles[1].unwrap();
        assert_eq!(throttle_kb.total_interrupts, 4);
        assert_eq!(throttle_kb.delivered_count, 2);
        assert_eq!(throttle_kb.throttled_count, 2);

        // 9. Configuration d'un endpoint Souris HID (EP 3, IN, interval 4 microtrames, sans debounce)
        assert!(ctrl
            .configure_hid_interrupt_endpoint(3, true, 4, 500, false)
            .is_ok());
        let mouse_report = [0x01, 15, (-8i8) as u8, 1]; // Clic gauche, dx=15, dy=-8, wheel=1
        let res_m = ctrl
            .process_hid_interrupt_report(3, &mouse_report, 0)
            .expect("Process mouse report");
        assert!(res_m);
        assert!(ctrl.mouse.left_button);
        assert!(!ctrl.mouse.right_button);
        assert_eq!(ctrl.mouse.dx, 15);
        assert_eq!(ctrl.mouse.dy, -8);
        assert_eq!(ctrl.mouse.wheel, 1);

        // 10. Récupération après crash : nettoyage complet des contextes
        assert!(ctrl.recover_from_crash().is_ok());
        assert!(ctrl.hid_throttles[1].is_none());
        assert!(ctrl.hid_throttles[3].is_none());
        assert!(!ctrl.ep_rings[1].active);
    }

    #[test]
    fn test_usb_mass_storage_bot_full_transport_and_recovery() {
        let mut iface = UsbDecodedInterface {
            interface_number: 0,
            alternate_setting: 0,
            class: 0x08,    // Mass Storage
            subclass: 0x06, // SCSI Transparent
            protocol: 0x50, // Bulk-Only Transport
            hid_descriptor: None,
            endpoints: [UsbDecodedEndpoint::default(); 8],
            endpoint_count: 2,
        };
        iface.endpoints[0] = UsbDecodedEndpoint {
            endpoint_address: 0x81,
            ep_number: 1,
            direction: UsbEndpointDirection::In,
            ep_type: UsbEndpointType::Bulk,
            max_packet_size: 512,
            interval: 0,
            mult: 0,
            max_burst: 0,
            max_streams: 0,
            dci: 3,
        };
        iface.endpoints[1] = UsbDecodedEndpoint {
            endpoint_address: 0x02,
            ep_number: 2,
            direction: UsbEndpointDirection::Out,
            ep_type: UsbEndpointType::Bulk,
            max_packet_size: 512,
            interval: 0,
            mult: 0,
            max_burst: 0,
            max_streams: 0,
            dci: 4,
        };

        // 1. Détection d'interface BOT et extraction d'endpoints
        assert!(iface.is_mass_storage_bot());
        let (in_ep, out_ep) = iface.find_bot_endpoints().expect("find bot endpoints");
        assert_eq!(in_ep, 1);
        assert_eq!(out_ep, 2);

        let mut bot = UsbMassStorageBot::new(1, in_ep, out_ep);

        // 2. Requête Setup BOT Reset et Clear Feature
        let reset_pkt = bot.build_bot_reset_packet(0);
        assert_eq!(reset_pkt.request_type(), 0x21);
        assert_eq!(reset_pkt.request(), 0xFF);
        assert_eq!(reset_pkt.value(), 0);
        assert_eq!(reset_pkt.index(), 0);

        let clear_halt_in = bot.build_clear_feature_halt_packet(true);
        assert_eq!(clear_halt_in.request_type(), 0x02);
        assert_eq!(clear_halt_in.request(), 0x01);
        assert_eq!(clear_halt_in.value(), 0x0000);
        assert_eq!(clear_halt_in.index(), 0x81);

        // 3. Automate de récupération après erreur
        let mut step = UsbBotResetStep::Step1MassStorageReset;
        step = bot.advance_reset_recovery(step);
        assert_eq!(step, UsbBotResetStep::Step2ClearHaltIn);
        step = bot.advance_reset_recovery(step);
        assert_eq!(step, UsbBotResetStep::Step3ClearHaltOut);
        step = bot.advance_reset_recovery(step);
        assert_eq!(step, UsbBotResetStep::Completed);

        // 4. SCSI REQUEST SENSE
        let (cbw_sense, tag_sense) = bot.build_cbw_request_sense();
        assert_eq!(cbw_sense.cb[0], SCSI_CMD_REQUEST_SENSE);
        assert_eq!(cbw_sense.data_transfer_length(), 18);

        let mut sense_buf = [0u8; 18];
        sense_buf[0] = 0x70; // Current error, fixed format
        sense_buf[2] = 0x02; // NOT READY
        sense_buf[12] = 0x3A; // MEDIUM NOT PRESENT
        sense_buf[13] = 0x00;

        let sense = bot
            .parse_request_sense_response(&sense_buf)
            .expect("parse sense");
        assert!(sense.is_valid());
        assert!(sense.is_not_ready());
        assert_eq!(sense.asc, 0x3A);

        // 5. SCSI MODE SENSE (6) & Write Protect
        let (cbw_mode, _) = bot.build_cbw_mode_sense_6(0x3F);
        assert_eq!(cbw_mode.cb[0], SCSI_CMD_MODE_SENSE_6);

        let mode_buf_ro = [0x03, 0x00, 0x80, 0x00]; // WP bit = 1
        assert!(bot.parse_mode_sense_6_write_protect(&mode_buf_ro));

        let mode_buf_rw = [0x03, 0x00, 0x00, 0x00]; // WP bit = 0
        assert!(!bot.parse_mode_sense_6_write_protect(&mode_buf_rw));

        // 6. Validation CSW complète (Spécification RFC BOT 1.0)
        let mut valid_csw = [0u8; 13];
        valid_csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        valid_csw[4..8].copy_from_slice(&tag_sense.to_le_bytes());
        valid_csw[8..12].copy_from_slice(&0u32.to_le_bytes()); // residue = 0
        valid_csw[12] = CSW_STATUS_PASSED;

        let residue = bot
            .verify_csw_full(tag_sense, 18, &valid_csw)
            .expect("verify csw passed");
        assert_eq!(residue, 0);

        // Test Tag Mismatch
        let bad_tag_res = bot.verify_csw_full(tag_sense + 1, 18, &valid_csw);
        assert_eq!(bad_tag_res, Err(UsbBotError::TagMismatch));

        // Test Phase Error
        valid_csw[12] = CSW_STATUS_PHASE_ERROR;
        assert_eq!(
            bot.verify_csw_full(tag_sense, 18, &valid_csw),
            Err(UsbBotError::PhaseError)
        );

        // 7. UsbMassStorageDisk
        let inq = ScsiInquiryInfo {
            peripheral_device_type: 0,
            is_removable: true,
            vendor_id: *b"KINGSTON",
            product_id: *b"DATATRAVELER 3.0",
            product_rev: *b"PMAP",
        };
        bot.total_sectors = 15_625_000;
        bot.sector_size = 512;
        let mut disk = UsbMassStorageDisk::new(bot, inq);
        assert_eq!(disk.total_sectors(), 15_625_000);
        assert_eq!(disk.sector_size(), 512);
        assert_eq!(disk.capacity_bytes(), 15_625_000 * 512);
        assert!(disk.validate_lba_range(0, 100));
        assert!(disk.validate_lba_range(15_624_900, 100));
        assert!(!disk.validate_lba_range(15_625_000, 1));
        assert!(!disk.validate_lba_range(0, 0));

        // 8. SCSI SYNCHRONIZE CACHE (10) (Barrière CoW)
        let (cbw_sync, tag_sync) = disk.build_sync_cache_cbw();
        assert_eq!(cbw_sync.cb[0], SCSI_CMD_SYNCHRONIZE_CACHE_10);
        assert_eq!(cbw_sync.data_transfer_length(), 0);
        assert!(!cbw_sync.is_data_in());
        assert_eq!(cbw_sync.tag(), tag_sync);

        // 9. SCSI READ CAPACITY (16) (Supports > 2 To)
        let (cbw_cap16, tag_cap16) = bot.build_cbw_read_capacity_16();
        assert_eq!(cbw_cap16.cb[0], SCSI_CMD_SERVICE_ACTION_IN_16);
        assert_eq!(cbw_cap16.cb[1], SCSI_SA_READ_CAPACITY_16);
        assert_eq!(cbw_cap16.data_transfer_length(), 32);
        assert!(cbw_cap16.is_data_in());
        assert_eq!(cbw_cap16.tag(), tag_cap16);

        let mut cap16_buf = [0u8; 32];
        let max_lba_val: u64 = 7_814_037_167; // Disque de 4 To (4096 octets/secteur)
        cap16_buf[0..8].copy_from_slice(&max_lba_val.to_be_bytes());
        cap16_buf[8..12].copy_from_slice(&4096u32.to_be_bytes());
        cap16_buf[12] = 0x01; // prot_en = true

        let cap16 = bot.parse_read_capacity_16(&cap16_buf).expect("parse cap16");
        assert_eq!(cap16.last_lba, max_lba_val);
        assert_eq!(cap16.block_size, 4096);
        assert_eq!(cap16.total_sectors, max_lba_val + 1);
        assert_eq!(cap16.total_bytes, (max_lba_val + 1) * 4096);
        assert!(cap16.prot_en);

        disk.update_capacity_16(cap16);
        assert_eq!(disk.total_sectors(), max_lba_val + 1);
        assert_eq!(disk.sector_size(), 4096);
        assert_eq!(disk.capacity_bytes(), (max_lba_val + 1) * 4096);

        // 10. SCSI READ (16) et WRITE (16) (Adressage 64-bit)
        let lba_64: u64 = 5_000_000_000;
        let (cbw_r16, tag_r16) = disk.build_read_cbw(lba_64, 64);
        assert_eq!(cbw_r16.cb[0], SCSI_CMD_READ_16);
        assert_eq!(cbw_r16.data_transfer_length(), 64 * 4096);
        assert!(cbw_r16.is_data_in());
        assert_eq!(cbw_r16.tag(), tag_r16);
        let extracted_lba = u64::from_be_bytes([
            cbw_r16.cb[2],
            cbw_r16.cb[3],
            cbw_r16.cb[4],
            cbw_r16.cb[5],
            cbw_r16.cb[6],
            cbw_r16.cb[7],
            cbw_r16.cb[8],
            cbw_r16.cb[9],
        ]);
        assert_eq!(extracted_lba, lba_64);
        let extracted_blocks = u32::from_be_bytes([
            cbw_r16.cb[10],
            cbw_r16.cb[11],
            cbw_r16.cb[12],
            cbw_r16.cb[13],
        ]);
        assert_eq!(extracted_blocks, 64);

        let (cbw_w16, tag_w16) = disk.build_write_cbw(lba_64, 128);
        assert_eq!(cbw_w16.cb[0], SCSI_CMD_WRITE_16);
        assert_eq!(cbw_w16.data_transfer_length(), 128 * 4096);
        assert!(!cbw_w16.is_data_in());
        assert_eq!(cbw_w16.tag(), tag_w16);

        // Disque standard 32-bit (<= 2 To) -> bascule vers READ (10) / WRITE (10)
        bot.total_sectors = 1_000_000;
        bot.sector_size = 512;
        let mut disk_small = UsbMassStorageDisk::new(bot, inq);
        let (cbw_r10, _) = disk_small.build_read_cbw(100, 16);
        assert_eq!(cbw_r10.cb[0], SCSI_CMD_READ_10);
        let (cbw_w10, _) = disk_small.build_write_cbw(100, 16);
        assert_eq!(cbw_w10.cb[0], SCSI_CMD_WRITE_10);

        // 11. SCSI START STOP UNIT (Gestion d'énergie et éjection)
        let (cbw_stop, _) = disk.build_start_stop_cbw(false, false);
        assert_eq!(cbw_stop.cb[0], SCSI_CMD_START_STOP_UNIT);
        assert_eq!(cbw_stop.cb[4], 0x00); // Stop, no eject
        assert_eq!(cbw_stop.data_transfer_length(), 0);

        let (cbw_eject, _) = disk.build_start_stop_cbw(false, true);
        assert_eq!(cbw_eject.cb[0], SCSI_CMD_START_STOP_UNIT);
        assert_eq!(cbw_eject.cb[4], 0x02); // LOEJ = 1, START = 0 (Eject)

        let (cbw_start, _) = disk.build_start_stop_cbw(true, false);
        assert_eq!(cbw_start.cb[4], 0x01); // START = 1 (Spin up)

        // 12. SCSI UNMAP (TRIM / Déallocation CoW)
        let unmap_descs = [
            ScsiUnmapBlockDescriptor::new(1000, 50),
            ScsiUnmapBlockDescriptor::new(5000, 200),
        ];
        let mut unmap_buf = [0u8; 64];
        let (cbw_unmap, tag_unmap, total_bytes) = disk
            .build_unmap_cbw(&unmap_descs, &mut unmap_buf)
            .expect("build unmap cbw");
        assert_eq!(cbw_unmap.cb[0], SCSI_CMD_UNMAP);
        assert_eq!(cbw_unmap.tag(), tag_unmap);
        assert_eq!(total_bytes, 8 + 2 * 16); // 40 octets
        assert_eq!(cbw_unmap.data_transfer_length(), 40);

        // Vérification de l'en-tête UNMAP
        let unmap_data_len = u16::from_be_bytes([unmap_buf[0], unmap_buf[1]]);
        let unmap_desc_len = u16::from_be_bytes([unmap_buf[2], unmap_buf[3]]);
        assert_eq!(unmap_data_len, 38);
        assert_eq!(unmap_desc_len, 32);

        // Vérification du descripteur 0
        let desc0_lba = u64::from_be_bytes([
            unmap_buf[8],
            unmap_buf[9],
            unmap_buf[10],
            unmap_buf[11],
            unmap_buf[12],
            unmap_buf[13],
            unmap_buf[14],
            unmap_buf[15],
        ]);
        let desc0_cnt =
            u32::from_be_bytes([unmap_buf[16], unmap_buf[17], unmap_buf[18], unmap_buf[19]]);
        assert_eq!(desc0_lba, 1000);
        assert_eq!(desc0_cnt, 50);

        // Vérification du descripteur 1
        let desc1_lba = u64::from_be_bytes([
            unmap_buf[24],
            unmap_buf[25],
            unmap_buf[26],
            unmap_buf[27],
            unmap_buf[28],
            unmap_buf[29],
            unmap_buf[30],
            unmap_buf[31],
        ]);
        let desc1_cnt =
            u32::from_be_bytes([unmap_buf[32], unmap_buf[33], unmap_buf[34], unmap_buf[35]]);
        assert_eq!(desc1_lba, 5000);
        assert_eq!(desc1_cnt, 200);

        // 13. SCSI MODE SENSE (10), PREVENT ALLOW & Caching Mode Page
        let (cbw_prev, tag_prev) = disk.build_prevent_allow_cbw(true);
        assert_eq!(cbw_prev.cb[0], SCSI_CMD_PREVENT_ALLOW_MEDIUM_REMOVAL);
        assert_eq!(cbw_prev.cb[4], 0x01); // Prevent = true
        assert_eq!(cbw_prev.tag(), tag_prev);
        assert_eq!(cbw_prev.data_transfer_length(), 0);

        let (cbw_allow, _) = disk.build_prevent_allow_cbw(false);
        assert_eq!(cbw_allow.cb[4], 0x00); // Prevent = false (Allow removal)

        let (cbw_m10, tag_m10) = disk.build_mode_sense_10_cbw(SCSI_PAGE_CACHING, 256);
        assert_eq!(cbw_m10.cb[0], SCSI_CMD_MODE_SENSE_10);
        assert_eq!(cbw_m10.cb[2], SCSI_PAGE_CACHING);
        assert_eq!(cbw_m10.cb[7], 1);
        assert_eq!(cbw_m10.cb[8], 0); // 256 = 0x0100
        assert_eq!(cbw_m10.tag(), tag_m10);
        assert_eq!(cbw_m10.data_transfer_length(), 256);

        // Parsing MODE SENSE (6) header
        let ms6_buf = [0x0B, 0x00, 0x80, 0x08]; // 12 octets total, WP=1, BlockDescLen=8
        let ms6_hdr = bot
            .parse_mode_sense_6_header(&ms6_buf)
            .expect("parse ms6 header");
        assert_eq!(ms6_hdr.mode_data_length, 0x0B);
        assert!(ms6_hdr.write_protected);
        assert_eq!(ms6_hdr.block_descriptor_length, 8);

        // Parsing MODE SENSE (10) header
        let ms10_buf = [0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10]; // DataLen=32, WP=0, LongLBA=1, BDDLen=16
        let ms10_hdr = bot
            .parse_mode_sense_10_header(&ms10_buf)
            .expect("parse ms10 header");
        assert_eq!(ms10_hdr.mode_data_length, 32);
        assert!(!ms10_hdr.write_protected);
        assert!(ms10_hdr.long_lba);
        assert_eq!(ms10_hdr.block_descriptor_length, 16);

        // Parsing Caching Mode Page (0x08)
        let cache_page_buf = [
            SCSI_PAGE_CACHING,
            0x12, // 18 octets
            0x04, // WCE = 1 (bit 2), RCD = 0, MF = 0
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
        let cache_page = bot
            .parse_caching_page(&cache_page_buf, 0)
            .expect("parse cache page");
        assert_eq!(cache_page.page_code, SCSI_PAGE_CACHING);
        assert_eq!(cache_page.page_length, 0x12);
        assert!(cache_page.write_cache_enabled);
        assert!(!cache_page.read_cache_disable);
        assert!(!cache_page.multiplication_factor);

        disk.set_write_protected(true);
        assert!(disk.is_write_protected());
        disk.set_write_protected(false);
        assert!(!disk.is_write_protected());

        // 14. SCSI TEST UNIT READY & SCSI MODE SELECT (6/10) avec contrôle de cache WCE
        let (cbw_tur_d, tag_tur_d) = disk.build_test_unit_ready_cbw();
        assert_eq!(cbw_tur_d.cb[0], SCSI_CMD_TEST_UNIT_READY);
        assert_eq!(cbw_tur_d.tag(), tag_tur_d);
        assert_eq!(cbw_tur_d.data_transfer_length(), 0);
        assert_eq!(cbw_tur_d.flags(), CBW_FLAG_DATA_OUT);

        // MODE SELECT (6) direct
        let (cbw_ms6, tag_ms6) = bot.build_cbw_mode_select_6(true, false, 16);
        assert_eq!(cbw_ms6.cb[0], SCSI_CMD_MODE_SELECT_6);
        assert_eq!(cbw_ms6.cb[1], 0x10); // PF = 1 (Page Format), SP = 0
        assert_eq!(cbw_ms6.cb[4], 16);
        assert_eq!(cbw_ms6.flags(), CBW_FLAG_DATA_OUT);
        assert_eq!(cbw_ms6.data_transfer_length(), 16);
        assert_eq!(cbw_ms6.tag(), tag_ms6);

        // MODE SELECT (10) direct
        let (cbw_ms10, tag_ms10) = bot.build_cbw_mode_select_10(true, true, 20);
        assert_eq!(cbw_ms10.cb[0], SCSI_CMD_MODE_SELECT_10);
        assert_eq!(cbw_ms10.cb[1], 0x11); // PF = 1, SP = 1
        assert_eq!(cbw_ms10.cb[7], 0);
        assert_eq!(cbw_ms10.cb[8], 20);
        assert_eq!(cbw_ms10.flags(), CBW_FLAG_DATA_OUT);
        assert_eq!(cbw_ms10.data_transfer_length(), 20);
        assert_eq!(cbw_ms10.tag(), tag_ms10);

        // Sérialisation des en-têtes et de la page de cache
        let mut p6_buf = [0u8; 16];
        let p6_len =
            UsbMassStorageBot::build_caching_mode_select_6_payload(false, true, &mut p6_buf);
        assert_eq!(p6_len, 16);
        assert_eq!(p6_buf[0], 0); // Réservé
        assert_eq!(p6_buf[1], 0); // Medium type
        assert_eq!(p6_buf[2], 0); // DSP
        assert_eq!(p6_buf[3], 0); // Block desc len
        assert_eq!(p6_buf[4], SCSI_PAGE_CACHING);
        assert_eq!(p6_buf[5], 0x0A); // Page length
        assert_eq!(p6_buf[6], 0x01); // WCE=0, RCD=1

        let mut p10_buf = [0u8; 20];
        let p10_len =
            UsbMassStorageBot::build_caching_mode_select_10_payload(true, false, &mut p10_buf);
        assert_eq!(p10_len, 20);
        assert_eq!(p10_buf[0], 0);
        assert_eq!(p10_buf[1], 0);
        assert_eq!(p10_buf[8], SCSI_PAGE_CACHING);
        assert_eq!(p10_buf[9], 0x0A);
        assert_eq!(p10_buf[10], 0x04); // WCE=1, RCD=0

        // Configuration du cache via UsbMassStorageDisk (désactivation WCE pour durcissement CoW)
        assert!(disk.is_write_cache_enabled());
        let mut cfg_buf = [0u8; 32];
        let (cbw_cfg, tag_cfg, plen) = disk
            .build_configure_write_cache_cbw(false, &mut cfg_buf)
            .expect("configure write cache");
        assert_eq!(plen, 16);
        assert_eq!(cbw_cfg.cb[0], SCSI_CMD_MODE_SELECT_6);
        assert_eq!(cbw_cfg.tag(), tag_cfg);
        assert_eq!(cbw_cfg.data_transfer_length(), 16);
        assert!(!disk.is_write_cache_enabled()); // Mise à jour vérifiée

        // 15. SCSI REPORT LUNS & SCSI READ DEFECT DATA (10)
        let (cbw_rl, tag_rl) = disk.build_report_luns_cbw(256);
        assert_eq!(cbw_rl.cb[0], SCSI_CMD_REPORT_LUNS);
        assert_eq!(cbw_rl.cb[2], SCSI_REPORT_LUNS_ALL);
        assert_eq!(cbw_rl.tag(), tag_rl);
        assert_eq!(cbw_rl.data_transfer_length(), 256);
        assert_eq!(cbw_rl.flags(), CBW_FLAG_DATA_IN);

        // Simulation de réponse REPORT LUNS avec 2 LUNs (LUN 0 et LUN 1)
        let mut rl_resp = [0u8; 24];
        let rl_len: u32 = 16; // 2 * 8 octets
        rl_resp[0..4].copy_from_slice(&rl_len.to_be_bytes());
        let lun1: u64 = 0x0001_0000_0000_0000;
        rl_resp[16..24].copy_from_slice(&lun1.to_be_bytes());

        let rl_hdr = bot
            .parse_report_luns_header(&rl_resp)
            .expect("parse rl header");
        assert_eq!(rl_hdr.lun_list_length, 16);
        assert_eq!(rl_hdr.lun_count, 2);
        assert_eq!(bot.parse_report_luns_entry(&rl_resp, 0), Some(0));
        assert_eq!(bot.parse_report_luns_entry(&rl_resp, 1), Some(lun1));
        assert_eq!(bot.parse_report_luns_entry(&rl_resp, 2), None);

        // READ DEFECT DATA (10)
        let (cbw_dd, tag_dd) = disk.build_read_defect_data_cbw(true, true, 64);
        assert_eq!(cbw_dd.cb[0], SCSI_CMD_READ_DEFECT_DATA_10);
        assert_eq!(cbw_dd.cb[2], 0x18 | SCSI_DEFECT_FORMAT_BLOCK);
        assert_eq!(cbw_dd.tag(), tag_dd);
        assert_eq!(cbw_dd.data_transfer_length(), 64);
        assert_eq!(cbw_dd.flags(), CBW_FLAG_DATA_IN);

        // Simulation réponse READ DEFECT DATA (10)
        let mut dd_resp = [0u8; 8];
        dd_resp[0] = 0;
        dd_resp[1] = 0x18 | SCSI_DEFECT_FORMAT_BLOCK;
        dd_resp[2] = 0;
        dd_resp[3] = 4;
        let dd_hdr = bot
            .parse_defect_data_10_header(&dd_resp)
            .expect("parse defect header");
        assert!(dd_hdr.primary_defect_list);
        assert!(dd_hdr.grown_defect_list);
        assert_eq!(dd_hdr.defect_list_format, SCSI_DEFECT_FORMAT_BLOCK);
        assert_eq!(dd_hdr.defect_list_length, 4);

        // 16. SCSI VERIFY (10), VERIFY (16) & SYNCHRONIZE CACHE (16)
        let (cbw_v10, tag_v10) = disk.build_verify_10_cbw(0x1234, 16);
        assert_eq!(cbw_v10.cb[0], SCSI_CMD_VERIFY_10);
        assert_eq!(cbw_v10.cb[1], 0); // bytchk = false
        assert_eq!(
            u32::from_be_bytes([cbw_v10.cb[2], cbw_v10.cb[3], cbw_v10.cb[4], cbw_v10.cb[5]]),
            0x1234
        );
        assert_eq!(u16::from_be_bytes([cbw_v10.cb[7], cbw_v10.cb[8]]), 16);
        assert_eq!(cbw_v10.tag(), tag_v10);
        assert_eq!(cbw_v10.data_transfer_length(), 0);

        let (cbw_v16, tag_v16) = disk.build_verify_16_cbw(0x0001_8000_0000, 128);
        assert_eq!(cbw_v16.cb[0], SCSI_CMD_VERIFY_16);
        assert_eq!(cbw_v16.cb[1], 0);
        let lba16 = u64::from_be_bytes([
            cbw_v16.cb[2],
            cbw_v16.cb[3],
            cbw_v16.cb[4],
            cbw_v16.cb[5],
            cbw_v16.cb[6],
            cbw_v16.cb[7],
            cbw_v16.cb[8],
            cbw_v16.cb[9],
        ]);
        assert_eq!(lba16, 0x0001_8000_0000);
        let cnt16 = u32::from_be_bytes([
            cbw_v16.cb[10],
            cbw_v16.cb[11],
            cbw_v16.cb[12],
            cbw_v16.cb[13],
        ]);
        assert_eq!(cnt16, 128);
        assert_eq!(cbw_v16.tag(), tag_v16);

        let (cbw_sc16, tag_sc16) = disk.build_sync_cache_16_cbw(0x0002_0000_0000, 64);
        assert_eq!(cbw_sc16.cb[0], SCSI_CMD_SYNCHRONIZE_CACHE_16);
        let sc_lba = u64::from_be_bytes([
            cbw_sc16.cb[2],
            cbw_sc16.cb[3],
            cbw_sc16.cb[4],
            cbw_sc16.cb[5],
            cbw_sc16.cb[6],
            cbw_sc16.cb[7],
            cbw_sc16.cb[8],
            cbw_sc16.cb[9],
        ]);
        assert_eq!(sc_lba, 0x0002_0000_0000);
        assert_eq!(cbw_sc16.tag(), tag_sc16);
        assert_eq!(cbw_sc16.data_transfer_length(), 0);

        // 17. SCSI SEND DIAGNOSTIC & RECEIVE DIAGNOSTIC RESULTS
        let (cbw_diag, tag_diag) =
            disk.build_send_diagnostic_cbw(SCSI_SELF_TEST_CODE_BACKGROUND_SHORT);
        assert_eq!(cbw_diag.cb[0], SCSI_CMD_SEND_DIAGNOSTIC);
        assert_eq!(
            cbw_diag.cb[1],
            (SCSI_SELF_TEST_CODE_BACKGROUND_SHORT & 0x07) << 5
        );
        assert_eq!(cbw_diag.tag(), tag_diag);
        assert_eq!(cbw_diag.data_transfer_length(), 0);

        let (cbw_recv_diag, tag_recv_diag) =
            disk.build_receive_diagnostic_results_cbw(SCSI_DIAG_PAGE_TRANSLATE_ADDRESS, 16);
        assert_eq!(cbw_recv_diag.cb[0], SCSI_CMD_RECEIVE_DIAGNOSTIC_RESULTS);
        assert_eq!(cbw_recv_diag.cb[1], 0x01); // pcv = true
        assert_eq!(cbw_recv_diag.cb[2], SCSI_DIAG_PAGE_TRANSLATE_ADDRESS);
        assert_eq!(
            u16::from_be_bytes([cbw_recv_diag.cb[3], cbw_recv_diag.cb[4]]),
            16
        );
        assert_eq!(cbw_recv_diag.tag(), tag_recv_diag);
        assert_eq!(cbw_recv_diag.data_transfer_length(), 16);

        // Parsing en-tête diagnostic
        let diag_raw = [SCSI_DIAG_PAGE_TRANSLATE_ADDRESS, 0x00, 0x00, 0x0C];
        let diag_hdr = disk.parse_diagnostic_results_header(&diag_raw).unwrap();
        assert_eq!(diag_hdr.page_code, SCSI_DIAG_PAGE_TRANSLATE_ADDRESS);
        assert_eq!(diag_hdr.page_length, 12);
        assert!(diag_hdr.self_test_passed);

        // 18. Parsing page SCSI Translate Address (Page 0x40)
        let mut trans_page_raw = [0u8; 22];
        trans_page_raw[0] = SCSI_DIAG_PAGE_TRANSLATE_ADDRESS;
        trans_page_raw[1] = 0x00; // Status OK
        trans_page_raw[2] = 0x00;
        trans_page_raw[3] = 18; // Page Length
        trans_page_raw[4] = SCSI_DEFECT_FORMAT_BLOCK; // 0x00
        trans_page_raw[6..14].copy_from_slice(&0x0003_1234_5678u64.to_be_bytes()); // Translated LBA
        trans_page_raw[14..17].copy_from_slice(&[0x01, 0x02, 0x03]); // Cylinder
        trans_page_raw[17] = 4; // Head
        trans_page_raw[18..22].copy_from_slice(&128u32.to_be_bytes()); // Sector

        let trans_res = disk.parse_translate_address_page(&trans_page_raw).unwrap();
        assert_eq!(trans_res.page_code, SCSI_DIAG_PAGE_TRANSLATE_ADDRESS);
        assert_eq!(trans_res.address_format, SCSI_DEFECT_FORMAT_BLOCK);
        assert_eq!(trans_res.translated_lba, 0x0003_1234_5678);
        assert_eq!(trans_res.cylinder, 0x0001_0203);
        assert_eq!(trans_res.head, 4);
        assert_eq!(trans_res.sector, 128);

        // 19. Parsing et sérialisation de la page SCSI Informational Exceptions Control (Page 0x1C - SMART SPC-4)
        let info_page = ScsiInformationalExceptionsPage {
            page_code: SCSI_PAGE_INFORMATIONAL_EXCEPTIONS,
            page_length: 10,
            perf: true,
            ewasc: true,
            dexcpt: false,
            mrie: 0x06,          // Only on request
            interval_timer: 300, // 30 secondes
            report_count: 5,
        };

        let mut raw_info = [0u8; 12];
        let ser_len =
            UsbMassStorageBot::serialize_informational_exceptions_page(&info_page, &mut raw_info);
        assert_eq!(ser_len, 12);
        assert_eq!(raw_info[0], SCSI_PAGE_INFORMATIONAL_EXCEPTIONS);
        assert_eq!(raw_info[1], 10);
        assert_eq!(raw_info[2], 0x90); // perf (0x80) | ewasc (0x10)
        assert_eq!(raw_info[3], 0x06); // mrie

        let parsed_info = disk
            .parse_informational_exceptions_page(&raw_info, 0)
            .expect("parse informational exceptions page");
        assert_eq!(parsed_info.page_code, SCSI_PAGE_INFORMATIONAL_EXCEPTIONS);
        assert_eq!(parsed_info.page_length, 10);
        assert!(parsed_info.perf);
        assert!(parsed_info.ewasc);
        assert!(!parsed_info.dexcpt);
        assert_eq!(parsed_info.mrie, 0x06);
        assert_eq!(parsed_info.interval_timer, 300);
        assert_eq!(parsed_info.report_count, 5);

        // 20. Transferts de Contrôle Asynchrones & Transitions d'Énergie de Port (Suspend / Resume / Power Down)
        let setup_pkt = UsbSetupPacket::new(0x80, 0x06, 0x0100, 0, 18); // GET_DESCRIPTOR (Device)
        assert_eq!(setup_pkt.request_type(), 0x80);
        assert_eq!(setup_pkt.request(), 0x06);
        assert_eq!(setup_pkt.length(), 18);

        let mut ctrl = XhciController::new();
        ctrl.ready = true;

        // Configuration d'un Endpoint de contrôle (Endpoint 0)
        assert!(ctrl.configure_endpoint_ring(0, false).is_ok());
        let q_ctrl_idx = ctrl
            .queue_control_transfer(0, &setup_pkt, 0x8000_0000, 18, true, true)
            .expect("queue control transfer");
        assert_eq!(q_ctrl_idx, 0);

        let ep0 = &ctrl.ep_rings[0];
        // TRB Setup Stage : Type=2, IDT=1, TRT=3 (IN Data Stage)
        assert_eq!(ep0.ring.trbs[0].trb_type(), TRB_TYPE_SETUP_STAGE);
        assert_eq!(ep0.ring.trbs[0].status, 8);
        assert_ne!(ep0.ring.trbs[0].control & TRB_FLAG_IDT, 0);
        assert_eq!((ep0.ring.trbs[0].control >> 16) & 0x03, 3);

        // TRB Data Stage : Type=3, Length=18, DIR=IN (bit 16 = 1), ISP=1
        assert_eq!(ep0.ring.trbs[1].trb_type(), TRB_TYPE_DATA_STAGE);
        assert_eq!(ep0.ring.trbs[1].parameter, 0x8000_0000);
        assert_eq!(ep0.ring.trbs[1].status & 0x1FFFF, 18);
        assert_ne!(ep0.ring.trbs[1].control & (1 << 16), 0);
        assert_ne!(ep0.ring.trbs[1].control & TRB_FLAG_ISP, 0);

        // TRB Status Stage : Type=4, DIR=OUT (bit 16 = 0), IOC=1
        assert_eq!(ep0.ring.trbs[2].trb_type(), TRB_TYPE_STATUS_STAGE);
        assert_eq!(ep0.ring.trbs[2].control & (1 << 16), 0);
        assert_ne!(ep0.ring.trbs[2].control & TRB_FLAG_IOC, 0);

        // Transitions d'alimentation et d'état de lien de port xHCI
        let raw_operational = 1 | (1 << 1) | (1 << 9) | ((PLS_U0 as u32) << PORTSC_PLS_SHIFT);
        let write_suspend = PortStatus::build_port_link_state_write(raw_operational, PLS_U3);
        assert_ne!(write_suspend & PORTSC_LWS, 0);
        assert_eq!(
            (write_suspend & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT,
            PLS_U3 as u32
        );
        assert_ne!(write_suspend & PORTSC_PP, 0);
        assert_eq!(write_suspend & PORTSC_ALL_CHANGES_MASK, 0);

        let write_power_down = PortStatus::build_port_power_write(raw_operational, false);
        assert_eq!(write_power_down & PORTSC_PP, 0);
        assert_eq!(write_power_down & PORTSC_ALL_CHANGES_MASK, 0);

        let write_power_up = PortStatus::build_port_power_write(write_power_down, true);
        assert_ne!(write_power_up & PORTSC_PP, 0);
        assert_eq!(write_power_up & PORTSC_ALL_CHANGES_MASK, 0);

        // 21. Détection de surintensité (OCA / OCC) et Sortie du mode de conformité (Compliance Mode)
        let raw_overcurrent = PORTSC_PP | PORTSC_OCA | PORTSC_OCC;
        assert!(PortStatus::is_over_current_active(raw_overcurrent));
        let ack_occ = PortStatus::build_over_current_ack_write(raw_overcurrent);
        assert_ne!(ack_occ & PORTSC_OCC, 0);
        assert_ne!(ack_occ & PORTSC_PP, 0);
        assert_eq!(ack_occ & PORTSC_CSC, 0);

        let trb_oc = Trb {
            parameter: 1 << 24, // Port 1
            status: 0,
            control: (TRB_TYPE_PORT_STATUS_CHANGE << 10) | 1,
        };
        let ev_oc = ctrl
            .handle_port_status_change_trb(&trb_oc, raw_overcurrent)
            .expect("Over-current event handled");
        assert_eq!(
            ev_oc,
            PortHotPlugEvent::PortOverCurrentDetected {
                port_id: 1,
                active: true,
            }
        );

        let raw_compliance = PORTSC_PP | ((PLS_COMPLIANCE_MODE as u32) << PORTSC_PLS_SHIFT);
        assert!(PortStatus::is_compliance_mode(raw_compliance));
        let exit_compliance = PortStatus::build_exit_compliance_write(raw_compliance);
        assert_ne!(exit_compliance & PORTSC_LWS, 0);
        assert_eq!(
            (exit_compliance & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT,
            PLS_RXDETECT as u32
        );
        assert_ne!(exit_compliance & PORTSC_PP, 0);
        assert_eq!(exit_compliance & PORTSC_ALL_CHANGES_MASK, 0);

        // 22. Contrôle de Reprise de Veille Forcée (Force Port Resume FPR) et Timers U3 -> U0
        let raw_u3_suspended =
            PORTSC_PP | PORTSC_CCS | PORTSC_PED | ((PLS_U3 as u32) << PORTSC_PLS_SHIFT);
        let fpr_write = PortStatus::build_force_port_resume_write(raw_u3_suspended);
        assert_ne!(fpr_write & PORTSC_LWS, 0);
        assert_eq!(
            (fpr_write & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT,
            PLS_RESUME as u32
        );
        assert_ne!(fpr_write & PORTSC_PP, 0);
        assert_eq!(fpr_write & PORTSC_ALL_CHANGES_MASK, 0);

        let resume_complete_write = PortStatus::build_complete_port_resume_write(raw_u3_suspended);
        assert_ne!(resume_complete_write & PORTSC_LWS, 0);
        assert_eq!(
            (resume_complete_write & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT,
            PLS_U0 as u32
        );

        // Validation des timeouts de reprise selon la vitesse (USB 2.0 vs SuperSpeed)
        assert!(!PortStatus::is_resume_timed_out(
            15_000,
            UsbSpeed::SuperSpeed
        ));
        assert!(PortStatus::is_resume_timed_out(
            25_000,
            UsbSpeed::SuperSpeed
        ));
        assert!(!PortStatus::is_resume_timed_out(
            30_000,
            UsbSpeed::HighSpeed
        ));
        assert!(PortStatus::is_resume_timed_out(55_000, UsbSpeed::HighSpeed));

        // Validation de l'état opérationnel U0
        let raw_u0_active =
            PORTSC_PP | PORTSC_CCS | PORTSC_PED | ((PLS_U0 as u32) << PORTSC_PLS_SHIFT);
        assert!(PortStatus::is_link_operational_u0(raw_u0_active));
        assert!(!PortStatus::is_link_operational_u0(raw_u3_suspended));

        // Détection de l'événement de changement d'état de lien (PLC=1)
        let raw_plc_event = raw_u0_active | PORTSC_PLC;
        let trb_plc = Trb {
            parameter: 1 << 24, // Port 1
            status: 0,
            control: (TRB_TYPE_PORT_STATUS_CHANGE << 10) | 1,
        };
        let ev_plc = ctrl
            .handle_port_status_change_trb(&trb_plc, raw_plc_event)
            .expect("PLC event handled");
        assert_eq!(
            ev_plc,
            PortHotPlugEvent::PortLinkStateChanged {
                port_id: 1,
                link_state: PLS_U0,
            }
        );

        // 23. Configuration des seuils d'inactivité de lien U1/U2 et négociation LPM (PORTPMSC)
        let pmsc_u1_u2 = PortStatus::build_usb3_portpmsc_write(10, 64, true);
        assert_eq!(pmsc_u1_u2 & PORTPMSC_U1_TIMEOUT_MASK, 10);
        assert_eq!((pmsc_u1_u2 & PORTPMSC_U2_TIMEOUT_MASK) >> 8, 64);
        assert_ne!(pmsc_u1_u2 & PORTPMSC_FLA, 0);

        let pmsc_lpm = PortStatus::build_usb2_lpm_portpmsc_write(4, true, 1);
        assert_eq!((pmsc_lpm & PORTPMSC_HIRD_MASK) >> PORTPMSC_HIRD_SHIFT, 4);
        assert_ne!(pmsc_lpm & PORTPMSC_RWE, 0);
        assert_eq!(pmsc_lpm & PORTPMSC_L1S_MASK, 1);

        assert!(PortStatus::validate_u1_u2_timers(10, 64));
        assert!(PortStatus::validate_u1_u2_timers(127, 254));
        assert!(PortStatus::validate_u1_u2_timers(0xFF, 0xFF));
        assert!(!PortStatus::validate_u1_u2_timers(128, 64));
        assert!(!PortStatus::validate_u1_u2_timers(200, 64));

        // 24. Détection et validation d'erreur de configuration (CEC) & Timeout TPP
        let pmsc_tpp = PortStatus::build_usb3_portpmsc_full_write(15, 30, true, 42);
        assert_eq!(
            (pmsc_tpp & PORTPMSC_USB3_TPP_TIMEOUT_MASK) >> PORTPMSC_USB3_TPP_TIMEOUT_SHIFT,
            42
        );
        assert_eq!(pmsc_tpp & PORTPMSC_U1_TIMEOUT_MASK, 15);
        assert_eq!((pmsc_tpp & PORTPMSC_U2_TIMEOUT_MASK) >> 8, 30);
        assert_ne!(pmsc_tpp & PORTPMSC_FLA, 0);

        let raw_cec = PORTSC_PP | PORTSC_CEC;
        assert!(PortStatus::is_config_error(raw_cec));
        let ack_cec = PortStatus::build_config_error_ack_write(raw_cec);
        assert_eq!(ack_cec, PORTSC_PP | PORTSC_CEC);

        let trb_cec = Trb {
            parameter: 1 << 24, // Port ID 1
            status: 0,
            control: (TRB_TYPE_PORT_STATUS_CHANGE << 10) | 1,
        };
        let ev_cec = ctrl
            .handle_port_status_change_trb(&trb_cec, raw_cec)
            .expect("CEC event handled");
        assert_eq!(
            ev_cec,
            PortHotPlugEvent::PortConfigErrorDetected { port_id: 1 }
        );

        // 25. Télémétrie d'intégrité de liaison physique et erreurs de couche liaison (PORTLI)
        let raw_li = 0x0021_0007; // 7 erreurs de lien, 1 voie RX, 2 voies TX
        let li = PortLinkInfo::parse(raw_li);
        assert_eq!(li.link_error_count, 7);
        assert_eq!(li.rx_lanes, 1);
        assert_eq!(li.tx_lanes, 2);
        assert_eq!(li.to_raw(), raw_li);
        assert!(!li.is_degraded(10));
        assert!(li.is_degraded(5));
    }

    #[test]
    fn test_porthlpmc_lpm_control() {
        // 1. Vérification du round-trip parse/encode avec tous les champs
        let hlpmc_full = PortHlpmc {
            hle_enabled: true,
            hird_besl: 0xA,           // 4 bits, valeur 10
            l1_timeout_128us: 0x5,    // délai = 5 × 128 = 640 μs
            best_effort_latency: 0x3, // BESLD = 3
        };
        let encoded = hlpmc_full.encode();
        let decoded = PortHlpmc::parse(encoded);
        assert_eq!(decoded, hlpmc_full, "round-trip parse/encode PORTHLPMC");

        // 2. Vérification du calcul de timeout en μs
        assert_eq!(hlpmc_full.l1_timeout_us(), 640);

        let hlpmc_zero = PortHlpmc {
            hle_enabled: false,
            hird_besl: 0,
            l1_timeout_128us: 0,
            best_effort_latency: 0,
        };
        assert_eq!(hlpmc_zero.encode(), 0);
        assert_eq!(hlpmc_zero.l1_timeout_us(), 0);

        // 3. Vérification des masques de bits individuels
        // HLE seul (bit 0)
        let raw_hle = PORTHLPMC_HLE_BIT;
        let parsed_hle = PortHlpmc::parse(raw_hle);
        assert!(parsed_hle.hle_enabled);
        assert_eq!(parsed_hle.hird_besl, 0);
        assert_eq!(parsed_hle.l1_timeout_128us, 0);
        assert_eq!(parsed_hle.best_effort_latency, 0);

        // HIRD/BESL = 0xF (bits 5:2 = 0b111100 = 0x3C)
        let raw_hird = 0xF << PORTHLPMC_HIRD_BESL_SHIFT;
        let parsed_hird = PortHlpmc::parse(raw_hird);
        assert!(!parsed_hird.hle_enabled);
        assert_eq!(parsed_hird.hird_besl, 0xF);

        // L1 Timeout = 0xFF (bits 15:8)
        let raw_timeout = 0xFF << PORTHLPMC_L1_TIMEOUT_SHIFT;
        let parsed_timeout = PortHlpmc::parse(raw_timeout);
        assert_eq!(parsed_timeout.l1_timeout_128us, 0xFF);
        assert_eq!(parsed_timeout.l1_timeout_us(), 0xFF * 128);

        // BESLD = 0xF (bits 19:16)
        let raw_besld = 0xF << PORTHLPMC_BEST_EFFORT_SVC_LATENCY_SHIFT;
        let parsed_besld = PortHlpmc::parse(raw_besld);
        assert_eq!(parsed_besld.best_effort_latency, 0xF);

        // 4. Vérification de configure_port_lpm : port hors plage → erreur
        let mut ctrl = XhciController::new();
        // Port 0 est invalide
        assert!(ctrl.configure_port_lpm(0, true, 5).is_err());
        // Port > max_ports (8 par défaut) est invalide
        assert!(ctrl.configure_port_lpm(9, true, 5).is_err());

        // 5. read_port_hlpmc sur port invalide retourne la valeur par défaut
        let default_hlpmc = ctrl.read_port_hlpmc(0);
        assert_eq!(default_hlpmc, PortHlpmc::default());
        let default_hlpmc2 = ctrl.read_port_hlpmc(9);
        assert_eq!(default_hlpmc2, PortHlpmc::default());
    }
}

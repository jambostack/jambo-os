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

// ============================================================================
// Contextes de Slot, d'Endpoint et d'Entrée xHCI 1.2 (Sections 6.2 & 6.2.5)
// ============================================================================

/// Contexte de Slot xHCI 32 octets (xHCI 1.2 Section 6.2.2)
#[repr(C, align(32))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlotContext {
    /// dword 0: Route String (19:0), Speed (23:20), MTT (25), Hub (26), Context Entries (31:27)
    pub info1: u32,
    /// dword 1: Max Exit Latency (15:0), Root Hub Port Number (23:16), Number of Ports (31:24)
    pub info2: u32,
    /// dword 2: TT Hub Slot ID (7:0), TT Port Number (15:8), TTT (17:16), Interrupter Target (31:22)
    pub tt_info: u32,
    /// dword 3: USB Device Address (7:0), Slot State (31:27)
    pub state_info: u32,
    pub reserved: [u32; 4],
}

impl SlotContext {
    pub const fn new(entries: u8, speed: u8, root_port: u8) -> Self {
        let info1 = ((entries as u32 & 0x1F) << 27) | ((speed as u32 & 0x0F) << 20);
        let info2 = (root_port as u32 & 0xFF) << 16;
        Self {
            info1,
            info2,
            tt_info: 0,
            state_info: 0,
            reserved: [0; 4],
        }
    }

    pub fn context_entries(&self) -> u8 {
        ((self.info1 >> 27) & 0x1F) as u8
    }

    pub fn speed(&self) -> u8 {
        ((self.info1 >> 20) & 0x0F) as u8
    }

    pub fn root_hub_port(&self) -> u8 {
        ((self.info2 >> 16) & 0xFF) as u8
    }

    pub fn device_address(&self) -> u8 {
        (self.state_info & 0xFF) as u8
    }

    pub fn slot_state(&self) -> u8 {
        ((self.state_info >> 27) & 0x1F) as u8
    }

    pub fn set_device_address(&mut self, addr: u8) {
        self.state_info = (self.state_info & !0xFF) | (addr as u32);
    }

    pub fn set_slot_state(&mut self, state: u8) {
        self.state_info = (self.state_info & !(0x1F << 27)) | ((state as u32 & 0x1F) << 27);
    }
}

/// Contexte de Point d'Accès (Endpoint Context) xHCI 32 octets (xHCI 1.2 Section 6.2.3)
#[repr(C, align(32))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EndpointContext {
    /// dword 0: EP State (2:0), Mult (9:8), Max Primary Streams (14:10), Linear Stream Array (15), Interval (23:16), Max ESIT Payload Hi (31:24)
    pub ep_info1: u32,
    /// dword 1: Force Event (0), Error Count (2:1), EP Type (5:3), Host Initiate Disable (7), Max Packet Size (31:16)
    pub ep_info2: u32,
    /// dwords 2 & 3: TR Dequeue Pointer (63:4) + DCS (0)
    pub tr_dequeue_ptr: u64,
    /// dword 4: Average TRB Length (15:0), Max ESIT Payload Low (31:16)
    pub tx_info: u32,
    pub reserved: [u32; 3],
}

impl EndpointContext {
    /// Construit un contexte d'endpoint configuré
    pub const fn new(
        ep_type: u8,
        max_packet_size: u16,
        tr_dequeue_ptr: u64,
        interval: u8,
        cerr: u8,
    ) -> Self {
        let ep_info1 = (interval as u32) << 16;
        let ep_info2 = ((max_packet_size as u32) << 16)
            | ((ep_type as u32 & 0x07) << 3)
            | ((cerr as u32 & 0x03) << 1);
        Self {
            ep_info1,
            ep_info2,
            tr_dequeue_ptr: tr_dequeue_ptr | 1, // Cycle bit DCS = 1
            tx_info: 0x0000_0008,               // Average TRB Length = 8 bytes
            reserved: [0; 3],
        }
    }

    pub fn ep_state(&self) -> u8 {
        (self.ep_info1 & 0x07) as u8
    }

    pub fn ep_type(&self) -> u8 {
        ((self.ep_info2 >> 3) & 0x07) as u8
    }

    pub fn max_packet_size(&self) -> u16 {
        ((self.ep_info2 >> 16) & 0xFFFF) as u16
    }

    pub fn error_count(&self) -> u8 {
        ((self.ep_info2 >> 1) & 0x03) as u8
    }

    pub fn interval(&self) -> u8 {
        ((self.ep_info1 >> 16) & 0xFF) as u8
    }

    pub fn dequeue_ptr(&self) -> u64 {
        self.tr_dequeue_ptr & !0x0F
    }

    pub fn dequeue_cycle_state(&self) -> bool {
        (self.tr_dequeue_ptr & 1) != 0
    }
}

/// Contexte de Contrôle d'Entrée xHCI (Input Control Context) 32 octets (xHCI 1.2 Section 6.2.5.1)
#[repr(C, align(32))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputControlContext {
    /// Drop Context Flags : A[1] pour EP0, A[n] pour EP n
    pub drop_flags: u32,
    /// Add Context Flags : A[0] pour Slot Context, A[1] pour EP0, A[n] pour EP n
    pub add_flags: u32,
    pub reserved: [u32; 6],
}

impl InputControlContext {
    pub const fn new() -> Self {
        Self {
            drop_flags: 0,
            add_flags: 0,
            reserved: [0; 6],
        }
    }

    /// Active l'ajout du contexte de slot (bit 0)
    pub fn enable_slot(&mut self) {
        self.add_flags |= 1 << 0;
    }

    /// Active l'ajout d'un point d'accès dci (1..31)
    pub fn enable_endpoint(&mut self, dci: u8) {
        if dci < 32 {
            self.add_flags |= 1 << dci;
        }
    }

    /// Marque la désactivation d'un point d'accès dci (1..31)
    pub fn drop_endpoint(&mut self, dci: u8) {
        if dci < 32 {
            self.drop_flags |= 1 << dci;
        }
    }
}

// ============================================================================
// Capacités Étendues xHCI 1.2 Extended Capabilities (xHCI 1.2 Section 7)
// ============================================================================

/// Identifiants standard de capacités étendues xHCI (Section 7.1)
pub const XHCI_EXT_CAP_USB_LEGACY_SUPPORT: u8 = 1;
pub const XHCI_EXT_CAP_SUPPORTED_PROTOCOL: u8 = 2;
pub const XHCI_EXT_CAP_EXTENDED_POWER_MGMT: u8 = 3;
pub const XHCI_EXT_CAP_IO_VIRTUALIZATION: u8 = 4;
pub const XHCI_EXT_CAP_LOCAL_MEMORY: u8 = 5;
pub const XHCI_EXT_CAP_USB_DEBUG_CAPABILITY: u8 = 10;
pub const XHCI_EXT_CAP_EXTENDED_POWER_MGMT_LPM: u8 = 15;
pub const XHCI_EXT_CAP_EXTENDED_MESSAGE_INTERRUPT: u8 = 17;
pub const XHCI_EXT_CAP_SECONDARY_BANDWIDTH: u8 = 18;
pub const XHCI_EXT_CAP_PORT_PROTOCOL_HIERARCHY: u8 = 19;
pub const XHCI_EXT_CAP_EXTENDED_CAPABILITY_TABLE: u8 = 20;
pub const XHCI_EXT_CAP_DEVICE_VIRTUALIZATION: u8 = 21;
pub const XHCI_EXT_CAP_HUB_VIRTUALIZATION: u8 = 22;
pub const XHCI_EXT_CAP_CONTROLLER_CAPABILITY_CONTEXT: u8 = 23;
pub const XHCI_EXT_CAP_BANDWIDTH_NEGOTIATION: u8 = 24;
pub const XHCI_EXT_CAP_LATENCY_TOLERANCE_MESSAGING: u8 = 25;
pub const XHCI_EXT_CAP_ENDPOINT_POLLING_OVERRIDE: u8 = 26;
pub const XHCI_EXT_CAP_INTERRUPTER_MODERATION_OVERRIDE: u8 = 27;
pub const XHCI_EXT_CAP_PORT_SPEED_MAPPING_OVERRIDE: u8 = 28;
pub const XHCI_EXT_CAP_EXTENDED_ENERGY_EFFICIENT_USB: u8 = 29;
pub const XHCI_EXT_CAP_OPTICAL_LOGICAL_LINK: u8 = 30;
pub const XHCI_EXT_CAP_DBC_TELEMETRY: u8 = 31;
pub const XHCI_EXT_CAP_SUBLINK_SPEED_ROUTING: u8 = 32;
pub const XHCI_EXT_CAP_EXTENDED_MESSAGE_INTERRUPT_VECTOR: u8 = 33;
pub const XHCI_EXT_CAP_EXTENDED_PORT_STATUS_CONTROL: u8 = 34;
pub const XHCI_EXT_CAP_FIRMWARE_DEBUG_TRACE: u8 = 35;
pub const XHCI_EXT_CAP_OFFLOAD_BUFFER_MANAGEMENT: u8 = 36;
pub const XHCI_EXT_CAP_HOST_CONTROLLER_SYSTEM_POWER: u8 = 37;
pub const XHCI_EXT_CAP_ROOT_HUB_TOPOLOGY_DESCRIPTOR: u8 = 38;
pub const XHCI_EXT_CAP_USB4_PCIE_TUNNELING: u8 = 39;
pub const XHCI_EXT_CAP_USB4_DISPLAYPORT_TUNNELING: u8 = 40;
pub const XHCI_EXT_CAP_USB4_HOST_INTERFACE_MANAGEMENT: u8 = 41;
pub const XHCI_EXT_CAP_USB4_ROUTER_CONFIGURATION: u8 = 42;
pub const XHCI_EXT_CAP_USB4_TIME_SYNCHRONIZATION_UNIT: u8 = 43;
pub const XHCI_EXT_CAP_USB4_POWER_MANAGEMENT_TUNNELING: u8 = 44;
/// Capacité étendue xHCI 1.2 / USB4 DisplayPort Alternate Mode Configuration Interface (§7.37)
pub const XHCI_EXT_CAP_USB4_DP_ALT_MODE_CONFIGURATION: u8 = 45;
/// Capacité étendue xHCI 1.2 / USB4 Security and Encryption Control Capability (§7.38)
pub const XHCI_EXT_CAP_USB4_SECURITY_CONFIGURATION: u8 = 46;
/// Capacité étendue xHCI 1.2 / USB4 Inter-Domain Transport Interface Capability (§7.39)
pub const XHCI_EXT_CAP_USB4_INTER_DOMAIN_TRANSPORT: u8 = 47;
/// Capacité étendue xHCI 1.2 / USB4 PCIe Tunneling Adapter Configuration Interface (§7.40)
pub const XHCI_EXT_CAP_USB4_PCIE_ADAPTER_CONFIGURATION: u8 = 48;
pub const XHCI_EXT_CAP_USB4_DP_ADAPTER_CONFIGURATION: u8 = 49;
/// Capacité étendue xHCI 1.2 / USB4 Buffer Allocation Interface Capability (§7.42)
pub const XHCI_EXT_CAP_USB4_BUFFER_ALLOCATION_INTERFACE: u8 = 50;
/// Capacité étendue xHCI 1.2 / USB4 Optical Interface Management Capability (§7.43)
pub const XHCI_EXT_CAP_USB4_OPTICAL_INTERFACE_MANAGEMENT: u8 = 51;
/// Capacité étendue xHCI 1.2 / USB4 Inter-Domain DMA Transport Capability (§7.44)
pub const XHCI_EXT_CAP_USB4_INTER_DOMAIN_DMA: u8 = 52;
/// Capacité étendue xHCI 1.2 / USB4 Router Operations and Configuration Interface (§7.45)
pub const XHCI_EXT_CAP_USB4_ROUTER_OPERATIONS: u8 = 53;
/// Capacité étendue xHCI 1.2 / USB4 Protocol Tunneling Statistics Interface (§7.46)
pub const XHCI_EXT_CAP_USB4_PROTOCOL_TUNNELING_STATS: u8 = 54;
/// Capacité étendue xHCI 1.2 / USB4 Host-to-Host Packet Tunneling Interface (§7.47)
pub const XHCI_EXT_CAP_USB4_HOST_TO_HOST_PACKET_TUNNELING: u8 = 55;
/// Capacité étendue xHCI 1.2 / USB4 Host Interface Discovery and Notification Capability (§7.48)
pub const XHCI_EXT_CAP_USB4_HOST_INTERFACE_DISCOVERY: u8 = 56;
/// Capacité étendue xHCI 1.2 / USB4 Sleep and Wake Notification Capability (§7.49)
pub const XHCI_EXT_CAP_USB4_SLEEP_WAKE_NOTIFICATION: u8 = 57;
/// Capacité étendue xHCI 1.2 / USB4 PCIe Adapter Configuration Interface (§7.50)
pub const XHCI_EXT_CAP_USB4_PCIE_ADAPTER_CONFIGURATION_INTERFACE: u8 = 58;
/// Capacité étendue xHCI 1.2 / USB4 DP Adapter Configuration Interface (§7.51)
pub const XHCI_EXT_CAP_USB4_DP_ADAPTER_CONFIGURATION_INTERFACE: u8 = 59;

/// Masques de registres USB Legacy Support (xHCI 1.2 Section 7.1)
/// Registre USBLEGSUP (Offset 0x00)
pub const USBLEGSUP_CAP_ID_MASK: u32 = 0xFF;
pub const USBLEGSUP_NEXT_PTR_MASK: u32 = 0xFF00;
pub const USBLEGSUP_BIOS_OWNED: u32 = 1 << 16;
pub const USBLEGSUP_OS_OWNED: u32 = 1 << 24;

/// Registre USBLEGCTLSTS (Offset 0x04) - USB Legacy Support Control/Status
pub const USBLEGCTLSTS_SMI_ENABLE: u32 = 1 << 0;
pub const USBLEGCTLSTS_SMI_OWNERSHIP_CHANGE_ENABLE: u32 = 1 << 13;
pub const USBLEGCTLSTS_SMI_PCI_COMMAND_ENABLE: u32 = 1 << 14;
pub const USBLEGCTLSTS_SMI_BAR_ENABLE: u32 = 1 << 15;
pub const USBLEGCTLSTS_SMI_OWNERSHIP_CHANGE_EVENT: u32 = 1 << 29;
pub const USBLEGCTLSTS_SMI_PCI_COMMAND_EVENT: u32 = 1 << 30;
pub const USBLEGCTLSTS_SMI_BAR_EVENT: u32 = 1 << 31;

/// Structure décodée de la capacité USB Legacy Support (xHCI 1.2 Section 7.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XhciLegacySupport {
    /// Pointeur dword vers la prochaine capacité étendue (0 = dernière)
    pub next_ptr_dwords: u8,
    /// Sémaphore de possession par le BIOS / Firmware UEFI (bit 16 de USBLEGSUP)
    pub bios_owned: bool,
    /// Sémaphore de possession par le Système d'Exploitation (bit 24 de USBLEGSUP)
    pub os_owned: bool,
    /// Interruption SMI activée sur le contrôleur (bit 0 de USBLEGCTLSTS)
    pub smi_enabled: bool,
    /// SMI activée sur transition d'appartenance OS/BIOS (bit 13 de USBLEGCTLSTS)
    pub smi_ownership_change_enable: bool,
    /// Événement SMI de changement d'appartenance en attente (bit 29 de USBLEGCTLSTS)
    pub smi_ownership_change_event: bool,
}

impl XhciLegacySupport {
    /// Parse les deux registres 32 bits USBLEGSUP et USBLEGCTLSTS
    pub const fn parse(usblegsup: u32, usblegctlsts: u32) -> Self {
        Self {
            next_ptr_dwords: ((usblegsup >> 8) & 0xFF) as u8,
            bios_owned: (usblegsup & USBLEGSUP_BIOS_OWNED) != 0,
            os_owned: (usblegsup & USBLEGSUP_OS_OWNED) != 0,
            smi_enabled: (usblegctlsts & USBLEGCTLSTS_SMI_ENABLE) != 0,
            smi_ownership_change_enable: (usblegctlsts & USBLEGCTLSTS_SMI_OWNERSHIP_CHANGE_ENABLE)
                != 0,
            smi_ownership_change_event: (usblegctlsts & USBLEGCTLSTS_SMI_OWNERSHIP_CHANGE_EVENT)
                != 0,
        }
    }

    /// Encode le mot 32-bit USBLEGSUP en préservant le pointeur de chaînage
    pub const fn encode_usblegsup(&self) -> u32 {
        let mut val =
            (XHCI_EXT_CAP_USB_LEGACY_SUPPORT as u32) | ((self.next_ptr_dwords as u32) << 8);
        if self.bios_owned {
            val |= USBLEGSUP_BIOS_OWNED;
        }
        if self.os_owned {
            val |= USBLEGSUP_OS_OWNED;
        }
        val
    }

    /// Calcule la valeur de requête d'appropriation OS (claim) pour USBLEGSUP
    pub const fn build_os_claim_usblegsup(raw_usblegsup: u32) -> u32 {
        raw_usblegsup | USBLEGSUP_OS_OWNED
    }

    /// Calcule la valeur de libération d'appropriation OS (release) pour USBLEGSUP
    pub const fn build_os_release_usblegsup(raw_usblegsup: u32) -> u32 {
        raw_usblegsup & !USBLEGSUP_OS_OWNED
    }

    /// Calcule la valeur d'extinction des événements SMI et désactivation des interruptions SMI
    /// pour le registre USBLEGCTLSTS (évite les traps SMI intempestifs une fois l'OS maître).
    pub const fn build_quiesce_smi_control(raw_usblegctlsts: u32) -> u32 {
        let mut val = raw_usblegctlsts
            & !(USBLEGCTLSTS_SMI_ENABLE | USBLEGCTLSTS_SMI_OWNERSHIP_CHANGE_ENABLE);
        // Écriture de 1 sur les bits RW1C pour acquitter tout événement en attente
        val |= USBLEGCTLSTS_SMI_OWNERSHIP_CHANGE_EVENT
            | USBLEGCTLSTS_SMI_PCI_COMMAND_EVENT
            | USBLEGCTLSTS_SMI_BAR_EVENT;
        val
    }

    /// Indique si le handoff OS/BIOS est pleinement accompli (OS=1 et BIOS=0)
    pub const fn is_os_owned(&self) -> bool {
        self.os_owned && !self.bios_owned
    }
}

/// Masques de registres USB Power Management Extended Capability (xHCI 1.2 Section 7.3)
/// Registre USBPMR (Offset 0x00)
pub const USBPMR_CAP_ID_MASK: u32 = 0xFF;
pub const USBPMR_NEXT_PTR_MASK: u32 = 0xFF00;
pub const USBPMR_PMIC_OFFSET_MASK: u32 = 0x00FF_0000;
pub const USBPMR_PORT_POWER_CONTROL: u32 = 1 << 24;
pub const USBPMR_POWER_SOURCE_VALID: u32 = 1 << 25;

/// Registre USBPMCSR (Offset 0x04) - USB Power Management Control/Status
pub const USBPMCSR_POWER_STATE_MASK: u32 = 0x03; // D0 (00b), D1 (01b), D2 (10b), D3hot (11b)
pub const USBPMCSR_PME_ENABLE: u32 = 1 << 8;
pub const USBPMCSR_DATA_SCALE_MASK: u32 = 0x6000;
pub const USBPMCSR_PME_STATUS: u32 = 1 << 15;

/// États de gestion d'énergie de périphérique xHCI Power Management (D0..D3hot)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhciPowerState {
    D0 = 0b00,
    D1 = 0b01,
    D2 = 0b10,
    D3Hot = 0b11,
}

impl XhciPowerState {
    pub const fn from_raw(raw: u8) -> Self {
        match raw & 0x03 {
            0b00 => Self::D0,
            0b01 => Self::D1,
            0b10 => Self::D2,
            _ => Self::D3Hot,
        }
    }

    pub const fn to_raw(self) -> u8 {
        self as u8
    }
}

/// Structure décodée de la capacité USB Power Management (xHCI 1.2 Section 7.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XhciPowerManagement {
    /// Pointeur dword vers la prochaine capacité étendue (0 = dernière)
    pub next_ptr_dwords: u8,
    /// Offset du contrôleur d'alimentation PMIC en dwords
    pub pmic_offset_dwords: u8,
    /// Capacité matérielle de contrôle d'alimentation par port (bit 24 de USBPMR)
    pub port_power_control_supported: bool,
    /// Indique que la source d'alimentation est stable et valide (bit 25 de USBPMR)
    pub power_source_valid: bool,
    /// État d'alimentation courant (D0, D1, D2, D3hot)
    pub current_power_state: u8,
    /// Interruption d'événement de réveil Power Management Event (PME) activée
    pub pme_enabled: bool,
    /// Événement PME en attente d'acquittement (bit 15 RW1C de USBPMCSR)
    pub pme_status: bool,
}

impl XhciPowerManagement {
    /// Parse les deux registres 32-bit USBPMR et USBPMCSR
    pub const fn parse(usbpmr: u32, usbpmcsr: u32) -> Self {
        Self {
            next_ptr_dwords: ((usbpmr >> 8) & 0xFF) as u8,
            pmic_offset_dwords: ((usbpmr >> 16) & 0xFF) as u8,
            port_power_control_supported: (usbpmr & USBPMR_PORT_POWER_CONTROL) != 0,
            power_source_valid: (usbpmr & USBPMR_POWER_SOURCE_VALID) != 0,
            current_power_state: (usbpmcsr & USBPMCSR_POWER_STATE_MASK) as u8,
            pme_enabled: (usbpmcsr & USBPMCSR_PME_ENABLE) != 0,
            pme_status: (usbpmcsr & USBPMCSR_PME_STATUS) != 0,
        }
    }

    /// Encode le registre USBPMR en préservant le chaînage et l'offset PMIC
    pub const fn encode_usbpmr(&self) -> u32 {
        let mut val = (XHCI_EXT_CAP_EXTENDED_POWER_MGMT as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.pmic_offset_dwords as u32) << 16);
        if self.port_power_control_supported {
            val |= USBPMR_PORT_POWER_CONTROL;
        }
        if self.power_source_valid {
            val |= USBPMR_POWER_SOURCE_VALID;
        }
        val
    }

    /// Calcule la valeur d'écriture pour commuter l'état d'énergie cible (D0..D3hot)
    pub const fn build_power_state_transition(raw_usbpmcsr: u32, target: XhciPowerState) -> u32 {
        (raw_usbpmcsr & !USBPMCSR_POWER_STATE_MASK) | (target.to_raw() as u32)
    }

    /// Calcule la valeur d'écriture pour acquitter le drapeau PME Status (bit 15 RW1C)
    pub const fn build_pme_ack(raw_usbpmcsr: u32) -> u32 {
        raw_usbpmcsr | USBPMCSR_PME_STATUS
    }

    /// Indique si le contrôleur est actuellement en état opérationnel D0
    pub const fn is_d0_active(&self) -> bool {
        self.current_power_state == (XhciPowerState::D0 as u8)
    }
}

/// Structure de parsing d'en-tête de capacité étendue xHCI (Section 7.0)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciExtendedCapHeader {
    /// Capability ID (bits 7:0)
    pub cap_id: u8,
    /// Next Capability Pointer in dwords (bits 15:8, 0 = dernier élément)
    pub next_dwords: u8,
    /// Capability-specific register (bits 31:16)
    pub specific: u16,
}

impl XhciExtendedCapHeader {
    pub const fn parse(raw: u32) -> Self {
        Self {
            cap_id: (raw & 0xFF) as u8,
            next_dwords: ((raw >> 8) & 0xFF) as u8,
            specific: ((raw >> 16) & 0xFFFF) as u16,
        }
    }

    pub const fn encode(&self) -> u32 {
        (self.cap_id as u32) | ((self.next_dwords as u32) << 8) | ((self.specific as u32) << 16)
    }
}

/// Capacité Étendue Supported Protocol (USB 2.0 / USB 3.x) - xHCI 1.2 Section 7.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciSupportedProtocol {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Numéro de révision majeure (ex: 2 pour USB 2.0, 3 pour USB 3.x)
    pub major_rev: u8,
    /// Numéro de révision mineure (ex: 0x00, 0x10, 0x20)
    pub minor_rev: u8,
    /// Chaîne d'identification de 4 octets ("USB ")
    pub name_string: [u8; 4],
    /// Numéro du premier port compatible (index 1-based)
    pub compatible_port_offset: u8,
    /// Nombre de ports consécutifs régis par ce protocole
    pub compatible_port_count: u8,
    /// Champ Protocol Defined (vitesses de slot, PSI count, Hub Depth, etc.)
    pub protocol_defined: u16,
}

impl XhciSupportedProtocol {
    /// Parse les 3 premiers dwords d'une capacité étendue Supported Protocol
    pub const fn parse(dwords: &[u32; 3]) -> Self {
        let dw0 = dwords[0];
        let dw1 = dwords[1];
        let dw2 = dwords[2];

        let next_ptr_dwords = ((dw0 >> 8) & 0xFF) as u8;
        let minor_rev = ((dw0 >> 16) & 0xFF) as u8;
        let major_rev = ((dw0 >> 24) & 0xFF) as u8;

        let name_string = [
            (dw1 & 0xFF) as u8,
            ((dw1 >> 8) & 0xFF) as u8,
            ((dw1 >> 16) & 0xFF) as u8,
            ((dw1 >> 24) & 0xFF) as u8,
        ];

        let compatible_port_offset = (dw2 & 0xFF) as u8;
        let compatible_port_count = ((dw2 >> 8) & 0xFF) as u8;
        let protocol_defined = ((dw2 >> 16) & 0xFFFF) as u16;

        Self {
            next_ptr_dwords,
            major_rev,
            minor_rev,
            name_string,
            compatible_port_offset,
            compatible_port_count,
            protocol_defined,
        }
    }

    /// Encode les 3 dwords de base de la structure Supported Protocol
    pub const fn encode(&self) -> [u32; 3] {
        let dw0 = (XHCI_EXT_CAP_SUPPORTED_PROTOCOL as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.minor_rev as u32) << 16)
            | ((self.major_rev as u32) << 24);

        let dw1 = (self.name_string[0] as u32)
            | ((self.name_string[1] as u32) << 8)
            | ((self.name_string[2] as u32) << 16)
            | ((self.name_string[3] as u32) << 24);

        let dw2 = (self.compatible_port_offset as u32)
            | ((self.compatible_port_count as u32) << 8)
            | ((self.protocol_defined as u32) << 16);

        [dw0, dw1, dw2]
    }

    /// Indique si cette révision correspond à la famille USB 3.x (SuperSpeed / SuperSpeedPlus)
    pub fn is_usb3(&self) -> bool {
        self.major_rev == 3 && &self.name_string == b"USB "
    }

    /// Indique si cette révision correspond à la famille USB 2.0 (High-Speed / Full-Speed / Low-Speed)
    pub fn is_usb2(&self) -> bool {
        self.major_rev == 2 && &self.name_string == b"USB "
    }

    /// Vérifie si un port donné (1-based) est dans la plage couverte par cette capacité
    pub const fn contains_port(&self, port_num: u8) -> bool {
        let start = self.compatible_port_offset;
        let count = self.compatible_port_count;
        port_num >= start && (port_num as u16) < (start as u16 + count as u16)
    }

    /// Détermine la vitesse par défaut associée à ce protocole
    pub const fn default_speed(&self) -> UsbSpeed {
        match self.major_rev {
            3 => UsbSpeed::SuperSpeed,
            2 => UsbSpeed::HighSpeed,
            _ => UsbSpeed::Unknown(0),
        }
    }
}

/// Description du protocole supporté par un port racine physique xHCI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciPortProtocolInfo {
    pub port_num: u8,
    pub major_rev: u8,
    pub minor_rev: u8,
    pub default_speed: UsbSpeed,
    pub is_usb3: bool,
    pub is_usb2: bool,
}

/// Capacité Étendue xHCI I/O Virtualization (xHCI 1.2 Section 7.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciIoVirtualization {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Nombre de fonctions virtuelles (VF) supportées
    pub num_vfs: u16,
}

impl XhciIoVirtualization {
    /// Parse les 2 premiers dwords d'une capacité étendue I/O Virtualization
    pub const fn parse(dwords: &[u32; 2]) -> Self {
        let dw0 = dwords[0];
        let dw1 = dwords[1];
        let next_ptr_dwords = ((dw0 >> 8) & 0xFF) as u8;
        let num_vfs = (dw1 & 0xFFFF) as u16;
        Self {
            next_ptr_dwords,
            num_vfs,
        }
    }

    /// Encode les 2 dwords de la structure I/O Virtualization
    pub const fn encode(&self) -> [u32; 2] {
        let dw0 = (XHCI_EXT_CAP_IO_VIRTUALIZATION as u32) | ((self.next_ptr_dwords as u32) << 8);
        let dw1 = self.num_vfs as u32;
        [dw0, dw1]
    }
}

/// Capacité Étendue xHCI Local Memory (xHCI 1.2 Section 7.5)
///
/// Permet à l'hôte d'identifier et d'exploiter la mémoire SRAM/RAM locale du contrôleur
/// pour stocker les anneaux de transfert, contextes ou buffers de paquets sans passer
/// par le bus PCIe système hôte (gain de latence et bande passante).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciLocalMemory {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Numéro de BAR PCI contenant la mémoire locale (0..=5)
    pub bar_index: u8,
    /// Offset en dwords dans le BAR
    pub mem_offset_dwords: u32,
    /// Taille de la mémoire locale en Kio (kilooctets)
    pub size_kib: u32,
}

impl XhciLocalMemory {
    /// Parse les 2 premiers dwords de la capacité Local Memory
    pub const fn parse(dwords: &[u32; 2]) -> Self {
        let dw0 = dwords[0];
        let dw1 = dwords[1];
        let next_ptr_dwords = ((dw0 >> 8) & 0xFF) as u8;
        let bar_index = ((dw0 >> 16) & 0x07) as u8;
        let mem_offset_dwords = (dw0 >> 19) & 0x1FFF;
        let size_kib = dw1;
        Self {
            next_ptr_dwords,
            bar_index,
            mem_offset_dwords,
            size_kib,
        }
    }

    /// Encode les 2 dwords de la structure Local Memory
    pub const fn encode(&self) -> [u32; 2] {
        let dw0 = (XHCI_EXT_CAP_LOCAL_MEMORY as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | (((self.bar_index & 0x07) as u32) << 16)
            | ((self.mem_offset_dwords & 0x1FFF) << 19);
        let dw1 = self.size_kib;
        [dw0, dw1]
    }

    /// Retourne la taille en octets de la mémoire locale xHCI
    pub const fn size_bytes(&self) -> u64 {
        (self.size_kib as u64) * 1024
    }

    /// Retourne l'offset en octets par rapport à la base du BAR
    pub const fn offset_bytes(&self) -> u64 {
        (self.mem_offset_dwords as u64) * 4
    }
}

/// Capacité Étendue xHCI Message Signaled Interrupts Extended (MSI-X / xHCI 1.2 section 7.6)
///
/// Permet au contrôleur xHCI de configurer et découpler les vecteurs d'interruption
/// MSI-X dédiés pour les anneaux d'événements de transfert et de commandes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciExtendedMessageInterrupt {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Indique si les interruptions MSI-X étendues sont activées
    pub enabled: bool,
    /// Numéro de BAR PCI contenant la table MSI-X
    pub table_bar: u8,
    /// Offset en dwords dans le BAR pour la table MSI-X
    pub table_offset_dwords: u32,
    /// Nombre de vecteurs d'interruption supportés
    pub table_size: u16,
    /// Numéro de BAR PCI contenant le PBA (Pending Bit Array)
    pub pba_bar: u8,
    /// Offset en dwords dans le BAR pour le PBA
    pub pba_offset_dwords: u32,
}

impl XhciExtendedMessageInterrupt {
    /// Parse les 4 dwords d'une capacité étendue Extended Message Interrupt (MSI-X)
    pub const fn parse(dwords: &[u32; 4]) -> Self {
        let dw0 = dwords[0];
        let dw1 = dwords[1];
        let dw2 = dwords[2];
        let dw3 = dwords[3];

        let next_ptr_dwords = ((dw0 >> 8) & 0xFF) as u8;
        let enabled = (dw0 & (1 << 31)) != 0;
        let table_size = (dw1 & 0x7FF) as u16 + 1; // N - 1 encodé sur bits [10:0]
        let table_bar = (dw2 & 0x07) as u8;
        let table_offset_dwords = (dw2 >> 3) & 0x1FFF_FFFF;
        let pba_bar = (dw3 & 0x07) as u8;
        let pba_offset_dwords = (dw3 >> 3) & 0x1FFF_FFFF;

        Self {
            next_ptr_dwords,
            enabled,
            table_bar,
            table_offset_dwords,
            table_size,
            pba_bar,
            pba_offset_dwords,
        }
    }

    /// Encode les 4 dwords de la structure Extended Message Interrupt
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_EXTENDED_MESSAGE_INTERRUPT as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | if self.enabled { 1 << 31 } else { 0 };
        let dw1 = ((self.table_size.saturating_sub(1)) & 0x7FF) as u32;
        let dw2 =
            ((self.table_bar & 0x07) as u32) | ((self.table_offset_dwords & 0x1FFF_FFFF) << 3);
        let dw3 = ((self.pba_bar & 0x07) as u32) | ((self.pba_offset_dwords & 0x1FFF_FFFF) << 3);
        [dw0, dw1, dw2, dw3]
    }

    /// Calcule l'offset absolu en octets de la table MSI-X
    pub const fn table_offset_bytes(&self) -> u64 {
        (self.table_offset_dwords as u64) * 4
    }

    /// Calcule l'offset absolu en octets du PBA
    pub const fn pba_offset_bytes(&self) -> u64 {
        (self.pba_offset_dwords as u64) * 4
    }
}

/// Gestionnaire de routage et découplage des vecteurs d'interruption MSI-X pour xHCI.
///
/// Permet d'associer des vecteurs d'interruption distincts pour les événements
/// de transfert de données (endpoints USB) et les événements de gestion de commandes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciMsixRouter {
    /// Vecteur CPU assigné aux événements de commandes (Command Completion)
    pub cmd_vector: u8,
    /// Vecteur CPU assigné aux événements de transfert (Transfer Events / Bulk / Isochronous)
    pub transfer_vector: u8,
    /// Masque de routage actif
    pub enabled: bool,
    /// Compteur d'interruptions de commandes reçues
    pub cmd_interrupts: u64,
    /// Compteur d'interruptions de transfert reçues
    pub transfer_interrupts: u64,
}

impl Default for XhciMsixRouter {
    fn default() -> Self {
        Self::new(48, 49)
    }
}

impl XhciMsixRouter {
    /// Crée un routeur découplé pour xHCI avec vecteurs séparés
    pub const fn new(cmd_vector: u8, transfer_vector: u8) -> Self {
        Self {
            cmd_vector,
            transfer_vector,
            enabled: false,
            cmd_interrupts: 0,
            transfer_interrupts: 0,
        }
    }

    /// Active le routage découplé
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Désactive le routage découplé
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Déroute un vecteur d'interruption reçu vers la catégorie appropriée :
    /// `Some(true)` pour transfert, `Some(false)` pour commande, `None` si inconnu.
    pub fn route_interrupt(&mut self, vector: u8) -> Option<bool> {
        if !self.enabled {
            return None;
        }
        if vector == self.transfer_vector {
            self.transfer_interrupts = self.transfer_interrupts.saturating_add(1);
            Some(true)
        } else if vector == self.cmd_vector {
            self.cmd_interrupts = self.cmd_interrupts.saturating_add(1);
            Some(false)
        } else {
            None
        }
    }
}

/// Entrée individuelle de la table d'interruption MSI-X (PCI-SIG / xHCI 1.2 §7.9)
/// Chaque entrée fait 16 octets (4 Dwords) :
/// - Msg Address Low (Dword 0) : Adresse mémoire 32-bit basse (bits [31:2], bits [1:0]=0)
/// - Msg Address High (Dword 1) : Adresse mémoire 32-bit haute
/// - Msg Data (Dword 2) : Vecteur d'interruption et flags CPU architecture
/// - Vector Control (Dword 3) : Bit 0 = Masked (1 = masqué, 0 = non masqué)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciMsixTableEntry {
    /// Adresse destination MSI (Message Address 64-bit)
    pub msg_address: u64,
    /// Donnée MSI (Message Data 32-bit : vecteur, delivery mode, trigger mode)
    pub msg_data: u32,
    /// Vecteur d'interruption masqué
    pub masked: bool,
}

impl Default for XhciMsixTableEntry {
    fn default() -> Self {
        Self {
            msg_address: 0,
            msg_data: 0,
            masked: true, // Masqué par défaut selon la spécification PCI / xHCI
        }
    }
}

impl XhciMsixTableEntry {
    /// Crée une nouvelle entrée MSI-X configurée
    pub const fn new(msg_address: u64, msg_data: u32, masked: bool) -> Self {
        Self {
            msg_address,
            msg_data,
            masked,
        }
    }

    /// Parse une entrée MSI-X à partir de 4 dwords MMIO
    pub const fn parse(dwords: &[u32; 4]) -> Self {
        let msg_addr_lo = dwords[0] & !0x03; // Bits [1:0] réservés/forcés à 0
        let msg_addr_hi = dwords[1];
        let msg_address = (msg_addr_lo as u64) | ((msg_addr_hi as u64) << 32);
        let msg_data = dwords[2];
        let masked = (dwords[3] & 0x01) != 0;
        Self {
            msg_address,
            msg_data,
            masked,
        }
    }

    /// Encode l'entrée en 4 dwords MMIO
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (self.msg_address & 0xFFFF_FFFC) as u32;
        let dw1 = (self.msg_address >> 32) as u32;
        let dw2 = self.msg_data;
        let dw3 = if self.masked { 0x01 } else { 0x00 };
        [dw0, dw1, dw2, dw3]
    }

    /// Récupère le vecteur CPU associé (bits [7:0] de msg_data)
    pub const fn vector(&self) -> u8 {
        (self.msg_data & 0xFF) as u8
    }
}

/// Table de routage d'interruptions MSI-X étendue pour xHCI 1.2 §7.9
///
/// Gère jusqu'à 32 vecteurs MSI-X découplés (Interrupters 0..31),
/// associant chaque anneau d'événement xHCI à un cœur CPU et vecteur dédié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciMsixRoutingTable {
    /// Capacité maximale supportée par l'hôte (1..32)
    pub capacity: u16,
    /// Table statique de 32 entrées MSI-X sans allocation
    pub entries: [XhciMsixTableEntry; 32],
    /// Masque global de la fonction MSI-X (Function Mask, bit 30 de Message Control)
    pub function_masked: bool,
    /// Activation globale du mode MSI-X
    pub enabled: bool,
}

impl Default for XhciMsixRoutingTable {
    fn default() -> Self {
        Self::new(32)
    }
}

impl XhciMsixRoutingTable {
    /// Initialise une table de routage MSI-X étendue
    pub const fn new(capacity: u16) -> Self {
        let cap = if capacity > 32 {
            32
        } else if capacity == 0 {
            1
        } else {
            capacity
        };
        Self {
            capacity: cap,
            entries: [XhciMsixTableEntry {
                msg_address: 0,
                msg_data: 0,
                masked: true,
            }; 32],
            function_masked: false,
            enabled: false,
        }
    }

    /// Active la table MSI-X
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Désactive la table MSI-X
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Configure le masquage global (Function Mask)
    pub fn set_function_mask(&mut self, mask: bool) {
        self.function_masked = mask;
    }

    /// Configure une entrée spécifique dans la table
    pub fn set_entry(&mut self, index: usize, entry: XhciMsixTableEntry) -> bool {
        if index < self.capacity as usize {
            self.entries[index] = entry;
            true
        } else {
            false
        }
    }

    /// Lit une entrée spécifique de la table
    pub const fn get_entry(&self, index: usize) -> Option<XhciMsixTableEntry> {
        if index < self.capacity as usize {
            Some(self.entries[index])
        } else {
            None
        }
    }

    /// Détermine si un interrupteur est actif et démasqué pour délivrance
    pub const fn is_interrupter_deliverable(&self, index: usize) -> bool {
        if !self.enabled || self.function_masked || index >= self.capacity as usize {
            return false;
        }
        !self.entries[index].masked && self.entries[index].msg_address != 0
    }

    /// Encode une tranche de dwords MMIO pour la table MSI-X
    pub fn write_mmio_dwords(&self, index: usize, out: &mut [u32; 4]) -> bool {
        if let Some(entry) = self.get_entry(index) {
            *out = entry.encode();
            true
        } else {
            false
        }
    }
}

/// Structure de bande passante par domaine/protocole xHCI 1.2 §7.10
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciDomainBandwidth {
    /// Identifiant du domaine ou port (1..255)
    pub domain_id: u8,
    /// Pourcentage ou bande passante allouée en Mb/s
    pub allocated_mbps: u32,
    /// Bande passante maximale réservable en Mb/s
    pub max_mbps: u32,
    /// Indique si la bande passante est active/engagée
    pub active: bool,
}

impl XhciDomainBandwidth {
    /// Crée un domaine de bande passante avec allocation maximale
    pub const fn new(domain_id: u8, max_mbps: u32) -> Self {
        Self {
            domain_id,
            allocated_mbps: 0,
            max_mbps,
            active: false,
        }
    }

    /// Réserve une quantité de bande passante en Mb/s
    pub fn reserve(&mut self, mbps: u32) -> bool {
        if self.allocated_mbps.saturating_add(mbps) <= self.max_mbps {
            self.allocated_mbps += mbps;
            self.active = true;
            true
        } else {
            false
        }
    }

    /// Libère une quantité de bande passante en Mb/s
    pub fn release(&mut self, mbps: u32) {
        self.allocated_mbps = self.allocated_mbps.saturating_sub(mbps);
        if self.allocated_mbps == 0 {
            self.active = false;
        }
    }

    /// Bande passante restante disponible
    pub const fn available_mbps(&self) -> u32 {
        self.max_mbps.saturating_sub(self.allocated_mbps)
    }
}

/// Capacité Étendue xHCI 1.2 §7.10 : Bande Passante Secondaire (Secondary Bandwidth / Inter-Host USB Bridge)
///
/// Modélise le partage et l'arbitrage de débit USB 3.x inter-hôtes ou multi-domaines,
/// permettant la coexistence équitable et le pontage sans interférence de contention de bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciSecondaryBandwidth {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Nombre de domaines de bande passante gérés (1..8)
    pub num_domains: u8,
    /// Table statique des domaines de bande passante
    pub domains: [XhciDomainBandwidth; 8],
    /// Mode pont inter-hôtes activé (Inter-Host Bridge Enable)
    pub inter_host_bridge_enabled: bool,
    /// Débit total agrégé de la structure en Mb/s
    pub total_bus_mbps: u32,
}

impl Default for XhciSecondaryBandwidth {
    fn default() -> Self {
        Self::new(4, 10000) // SuperSpeed 10 Gbps (10 000 Mb/s) par défaut
    }
}

impl XhciSecondaryBandwidth {
    /// Initialise une nouvelle capacité de bande passante secondaire
    pub const fn new(num_domains: u8, total_bus_mbps: u32) -> Self {
        let n = if num_domains > 8 {
            8
        } else if num_domains == 0 {
            1
        } else {
            num_domains
        };

        let mut domains = [XhciDomainBandwidth::new(0, 0); 8];
        let share_mbps = total_bus_mbps / (n as u32);
        let mut i = 0usize;
        while i < (n as usize) {
            domains[i] = XhciDomainBandwidth::new((i + 1) as u8, share_mbps);
            i += 1;
        }

        Self {
            next_ptr_dwords: 0,
            num_domains: n,
            domains,
            inter_host_bridge_enabled: false,
            total_bus_mbps,
        }
    }

    /// Parse les registres MMIO de la capacité étendue Secondary Bandwidth
    ///
    /// - `dwords[0]`: CapID [7:0], NextPtr [15:8], NumDomains [23:16], BridgeEnable [31]
    /// - `dwords[1]`: Total Bus Bandwidth (Mb/s)
    pub fn parse(dwords: &[u32; 2]) -> Self {
        let cap_id = (dwords[0] & 0xFF) as u8;
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let num_domains = ((dwords[0] >> 16) & 0xFF) as u8;
        let bridge_enabled = (dwords[0] & (1 << 31)) != 0;
        let total_mbps = dwords[1];

        let _ = cap_id;
        let mut cap = Self::new(num_domains, total_mbps);
        cap.next_ptr_dwords = next_ptr;
        cap.inter_host_bridge_enabled = bridge_enabled;
        cap
    }

    /// Encode la capacité en 2 dwords MMIO
    pub const fn encode(&self) -> [u32; 2] {
        let dw0 = (XHCI_EXT_CAP_SECONDARY_BANDWIDTH as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.num_domains as u32) << 16)
            | (if self.inter_host_bridge_enabled {
                1 << 31
            } else {
                0
            });
        let dw1 = self.total_bus_mbps;
        [dw0, dw1]
    }

    /// Active ou désactive le mode pont inter-hôte USB
    pub fn set_inter_host_bridge(&mut self, enable: bool) {
        self.inter_host_bridge_enabled = enable;
    }

    /// Réserve de la bande passante sur un domaine particulier
    pub fn reserve_domain_bandwidth(&mut self, domain_id: u8, mbps: u32) -> bool {
        for d in self.domains[..self.num_domains as usize].iter_mut() {
            if d.domain_id == domain_id {
                return d.reserve(mbps);
            }
        }
        false
    }

    /// Libère de la bande passante sur un domaine particulier
    pub fn release_domain_bandwidth(&mut self, domain_id: u8, mbps: u32) {
        for d in self.domains[..self.num_domains as usize].iter_mut() {
            if d.domain_id == domain_id {
                d.release(mbps);
                return;
            }
        }
    }

    /// Calcule la somme de la bande passante actuellement allouée sur tous les domaines
    pub fn total_allocated_mbps(&self) -> u32 {
        let mut total = 0u32;
        for d in &self.domains[..self.num_domains as usize] {
            total = total.saturating_add(d.allocated_mbps);
        }
        total
    }
}

/// Type de protocole de port USB dans la hiérarchie (§7.11)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhciPortProtocolType {
    /// Port USB 2.0 (Low-Speed, Full-Speed, High-Speed)
    Usb2,
    /// Port USB 3.x Gen 1 (SuperSpeed 5 Gbps)
    Usb3Gen1,
    /// Port USB 3.x Gen 2 (SuperSpeedPlus 10 Gbps)
    Usb3Gen2,
    /// Port USB4 / Gen 3x2 (SuperSpeedPlus 20/40 Gbps)
    Usb4,
    /// Protocole inconnu ou personnalisé
    Unknown(u8),
}

impl XhciPortProtocolType {
    /// Convertit un code de protocole brut 4 bits en type énuméré
    pub const fn from_raw(val: u8) -> Self {
        match val & 0x0F {
            0 => Self::Usb2,
            1 => Self::Usb3Gen1,
            2 => Self::Usb3Gen2,
            3 => Self::Usb4,
            other => Self::Unknown(other),
        }
    }

    /// Convertit le type de protocole en code 4 bits
    pub const fn to_raw(&self) -> u8 {
        match self {
            Self::Usb2 => 0,
            Self::Usb3Gen1 => 1,
            Self::Usb3Gen2 => 2,
            Self::Usb4 => 3,
            Self::Unknown(v) => *v & 0x0F,
        }
    }
}

/// Entrée de mappage de route d'un port USB (§7.11)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciPortRouteEntry {
    /// Numéro logique du port physique xHCI (1..=255)
    pub port_id: u8,
    /// Type de protocole assigné
    pub protocol: XhciPortProtocolType,
    /// Identifiant du hub racine ou contrôleur parent (Root Tier / Hub Depth)
    pub tier_level: u8,
    /// Port actif et routable
    pub is_active: bool,
}

impl XhciPortRouteEntry {
    /// Crée une entrée de route de port par défaut
    pub const fn new(port_id: u8, protocol: XhciPortProtocolType, tier_level: u8) -> Self {
        Self {
            port_id,
            protocol,
            tier_level,
            is_active: true,
        }
    }

    /// Encode l'entrée de port en un mot 16-bit :
    /// - [7:0] : Port ID
    /// - [11:8] : Protocol Type (4 bits)
    /// - [14:12] : Tier Level (3 bits)
    /// - [15] : Active flag
    pub const fn encode_u16(&self) -> u16 {
        (self.port_id as u16)
            | (((self.protocol.to_raw() as u16) & 0x0F) << 8)
            | (((self.tier_level as u16) & 0x07) << 12)
            | (if self.is_active { 1 << 15 } else { 0 })
    }

    /// Décode une entrée 16-bit
    pub const fn decode_u16(val: u16) -> Self {
        let port_id = (val & 0xFF) as u8;
        let protocol = XhciPortProtocolType::from_raw(((val >> 8) & 0x0F) as u8);
        let tier_level = ((val >> 12) & 0x07) as u8;
        let is_active = (val & (1 << 15)) != 0;
        Self {
            port_id,
            protocol,
            tier_level,
            is_active,
        }
    }
}

/// Capacité Étendue xHCI 1.2 §7.11 : USB Subsystem Hierarchy & Port Protocol Route Maps
///
/// Fournit la cartographie hiérarchique de routage des ports USB du sous-système xHCI,
/// permettant l'association déterministe entre ports physiques, protocoles pris en charge
/// et niveaux de hiérarchie (Root Ports, Tier 1 Hub, Multi-Root Bridges).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciSubsystemHierarchy {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Nombre de ports cartographiés dans cette instance (1..=16)
    pub port_count: u8,
    /// Table statique de mappage de route des ports (jusqu'à 16 ports)
    pub routes: [XhciPortRouteEntry; 16],
    /// Masque de routage haute vitesse / compatibilité USB4
    pub routing_control: u16,
}

impl Default for XhciSubsystemHierarchy {
    fn default() -> Self {
        Self::new(4)
    }
}

impl XhciSubsystemHierarchy {
    /// Crée une nouvelle structure de hiérarchie pour `count` ports (max 16)
    pub const fn new(count: u8) -> Self {
        let c = if count > 16 {
            16
        } else if count == 0 {
            1
        } else {
            count
        };

        let mut routes = [XhciPortRouteEntry::new(0, XhciPortProtocolType::Usb2, 0); 16];
        let mut i = 0usize;
        while i < (c as usize) {
            let proto = if (i % 2) == 0 {
                XhciPortProtocolType::Usb3Gen2
            } else {
                XhciPortProtocolType::Usb2
            };
            routes[i] = XhciPortRouteEntry::new((i + 1) as u8, proto, 0);
            i += 1;
        }

        Self {
            next_ptr_dwords: 0,
            port_count: c,
            routes,
            routing_control: 0,
        }
    }

    /// Décode la capacité depuis les dwords MMIO :
    /// - `dwords[0]` : CapID [7:0], NextPtr [15:8], PortCount [23:16], RoutingCtrl [31:24] (partiel)
    /// - `dwords[1..=8]` : Paires de routes de ports encodées en 16 bits chacune (2 routes par dword)
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 2 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_PORT_PROTOCOL_HIERARCHY {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let port_count = (((dwords[0] >> 16) & 0xFF) as u8).min(16);
        let routing_ctrl = ((dwords[0] >> 24) & 0xFF) as u16;

        let mut cap = Self::new(port_count);
        cap.next_ptr_dwords = next_ptr;
        cap.routing_control = routing_ctrl;

        let mut route_idx = 0usize;
        let mut dw_idx = 1usize;
        while dw_idx < dwords.len() && route_idx < (port_count as usize) {
            let dw = dwords[dw_idx];
            let r0 = XhciPortRouteEntry::decode_u16((dw & 0xFFFF) as u16);
            cap.routes[route_idx] = r0;
            route_idx += 1;

            if route_idx < (port_count as usize) {
                let r1 = XhciPortRouteEntry::decode_u16(((dw >> 16) & 0xFFFF) as u16);
                cap.routes[route_idx] = r1;
                route_idx += 1;
            }
            dw_idx += 1;
        }

        Some(cap)
    }

    /// Encode la capacité en un tableau de dwords MMIO (taille variable selon port_count)
    /// Retourne un tableau fixe de 9 dwords maximum (1 header + 8 dwords pour 16 routes)
    pub fn encode(&self) -> ([u32; 9], usize) {
        let mut dwords = [0u32; 9];
        dwords[0] = (XHCI_EXT_CAP_PORT_PROTOCOL_HIERARCHY as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.port_count as u32) << 16)
            | (((self.routing_control as u32) & 0xFF) << 24);

        let pairs = (self.port_count as usize).div_ceil(2);
        let mut i = 0usize;
        while i < pairs {
            let r0 = self.routes[i * 2].encode_u16() as u32;
            let r1 = if (i * 2 + 1) < (self.port_count as usize) {
                self.routes[i * 2 + 1].encode_u16() as u32
            } else {
                0
            };
            dwords[1 + i] = r0 | (r1 << 16);
            i += 1;
        }

        (dwords, 1 + pairs)
    }

    /// Recherche le type de protocole assigné à un port physique
    pub fn find_protocol_for_port(&self, port_id: u8) -> Option<XhciPortProtocolType> {
        for r in &self.routes[..self.port_count as usize] {
            if r.port_id == port_id && r.is_active {
                return Some(r.protocol);
            }
        }
        None
    }

    /// Associe un nouveau protocole à un port spécifique
    pub fn set_port_route(
        &mut self,
        port_id: u8,
        protocol: XhciPortProtocolType,
        tier: u8,
    ) -> bool {
        for r in self.routes[..self.port_count as usize].iter_mut() {
            if r.port_id == port_id {
                r.protocol = protocol;
                r.tier_level = tier;
                r.is_active = true;
                return true;
            }
        }
        false
    }
}

/// Entrée individuelle de pointeur de capacité étendue xHCI (§7.12)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciExtendedCapPointerEntry {
    /// Identifiant de capacité xHCI (bits 7:0)
    pub cap_id: u8,
    /// Offset relatif en dwords vers la capacité (bits 15:8)
    pub offset_dwords: u8,
    /// Drapeaux / propriétés de la capacité (bits 31:16)
    pub flags: u16,
    /// Capacité présente et valide dans la table
    pub is_valid: bool,
}

impl XhciExtendedCapPointerEntry {
    /// Crée une entrée de pointeur de capacité
    pub const fn new(cap_id: u8, offset_dwords: u8, flags: u16) -> Self {
        Self {
            cap_id,
            offset_dwords,
            flags,
            is_valid: true,
        }
    }

    /// Encode l'entrée en mot 32-bit MMIO
    pub const fn encode_u32(&self) -> u32 {
        (self.cap_id as u32)
            | ((self.offset_dwords as u32) << 8)
            | ((self.flags as u32) << 16)
            | (if self.is_valid { 1 << 31 } else { 0 })
    }

    /// Décode un mot 32-bit MMIO en entrée de pointeur
    pub const fn decode_u32(val: u32) -> Self {
        let cap_id = (val & 0xFF) as u8;
        let offset_dwords = ((val >> 8) & 0xFF) as u8;
        let flags = ((val >> 16) & 0x7FFF) as u16;
        let is_valid = (val & (1 << 31)) != 0;
        Self {
            cap_id,
            offset_dwords,
            flags,
            is_valid,
        }
    }
}

/// Capacité Étendue xHCI 1.2 §7.12 : Extended Capability Descriptor Tables & USB Capability Pointers
///
/// Modélise la table d'indexation accélérée des capacités étendues de l'hôte xHCI 1.2,
/// permettant un parcours direct O(1) de l'ensemble des descripteurs de capacités sans
/// traverser séquentiellement la liste chaînée MMIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciExtendedCapabilityTable {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Nombre d'entrées de pointeurs présentes dans la table (1..=16)
    pub entry_count: u8,
    /// Table statique des descripteurs de pointeurs (jusqu'à 16 entrées)
    pub entries: [XhciExtendedCapPointerEntry; 16],
    /// Masque de contrôle global d'accès direct
    pub table_control: u16,
}

impl Default for XhciExtendedCapabilityTable {
    fn default() -> Self {
        Self::new(4)
    }
}

impl XhciExtendedCapabilityTable {
    /// Crée une nouvelle table de descripteurs pour `count` entrées (max 16)
    pub const fn new(count: u8) -> Self {
        let c = if count > 16 {
            16
        } else if count == 0 {
            1
        } else {
            count
        };

        let mut entries = [XhciExtendedCapPointerEntry::new(0, 0, 0); 16];
        let mut i = 0usize;
        while i < (c as usize) {
            let cap_id = match i {
                0 => XHCI_EXT_CAP_USB_LEGACY_SUPPORT,
                1 => XHCI_EXT_CAP_SUPPORTED_PROTOCOL,
                2 => XHCI_EXT_CAP_EXTENDED_POWER_MGMT,
                3 => XHCI_EXT_CAP_USB_DEBUG_CAPABILITY,
                4 => XHCI_EXT_CAP_EXTENDED_POWER_MGMT_LPM,
                5 => XHCI_EXT_CAP_EXTENDED_MESSAGE_INTERRUPT,
                6 => XHCI_EXT_CAP_SECONDARY_BANDWIDTH,
                7 => XHCI_EXT_CAP_PORT_PROTOCOL_HIERARCHY,
                _ => (i + 1) as u8,
            };
            entries[i] = XhciExtendedCapPointerEntry::new(cap_id, ((i + 1) * 4) as u8, 0x01);
            i += 1;
        }

        Self {
            next_ptr_dwords: 0,
            entry_count: c,
            entries,
            table_control: 0,
        }
    }

    /// Décode une table de descripteurs à partir d'un buffer de dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 2 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_EXTENDED_CAPABILITY_TABLE {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let entry_count = (((dwords[0] >> 16) & 0xFF) as u8).min(16);
        let table_ctrl = ((dwords[0] >> 24) & 0xFF) as u16;

        let mut table = Self::new(entry_count);
        table.next_ptr_dwords = next_ptr;
        table.table_control = table_ctrl;

        let mut entry_idx = 0usize;
        let mut dw_idx = 1usize;
        while dw_idx < dwords.len() && entry_idx < (entry_count as usize) {
            let entry = XhciExtendedCapPointerEntry::decode_u32(dwords[dw_idx]);
            table.entries[entry_idx] = entry;
            entry_idx += 1;
            dw_idx += 1;
        }

        Some(table)
    }

    /// Encode la structure en un tableau de mots MMIO (1 header + jusqu'à 16 entrées)
    pub fn encode(&self) -> ([u32; 17], usize) {
        let mut dwords = [0u32; 17];
        dwords[0] = (XHCI_EXT_CAP_EXTENDED_CAPABILITY_TABLE as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.entry_count as u32) << 16)
            | (((self.table_control as u32) & 0xFF) << 24);

        let mut i = 0usize;
        while i < (self.entry_count as usize) {
            dwords[1 + i] = self.entries[i].encode_u32();
            i += 1;
        }

        (dwords, 1 + (self.entry_count as usize))
    }

    /// Recherche l'offset dword d'une capacité par son Cap ID
    pub fn find_offset_for_cap(&self, cap_id: u8) -> Option<u8> {
        for e in &self.entries[..self.entry_count as usize] {
            if e.cap_id == cap_id && e.is_valid {
                return Some(e.offset_dwords);
            }
        }
        None
    }

    /// Ajoute ou met à jour une entrée de pointeur de capacité
    pub fn set_entry(&mut self, cap_id: u8, offset_dwords: u8, flags: u16) -> bool {
        for e in self.entries[..self.entry_count as usize].iter_mut() {
            if e.cap_id == cap_id {
                e.offset_dwords = offset_dwords;
                e.flags = flags;
                e.is_valid = true;
                return true;
            }
        }
        if (self.entry_count as usize) < 16 {
            let idx = self.entry_count as usize;
            self.entries[idx] = XhciExtendedCapPointerEntry::new(cap_id, offset_dwords, flags);
            self.entry_count += 1;
            return true;
        }
        false
    }
}

/// Capacité Étendue xHCI 1.2 §7.13 : USB Device Virtualization & Secondary Host Controller Interface
///
/// Permet l'assignation directe, le partitionnement et le multiplexage matériel sécurisé
/// des fonctions USB xHCI entre partitions hôtes, machines virtuelles invitées ou conteneurs
/// de micro-noyau sans recours à l'émulation logicielle en Ring 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciDeviceVirtualization {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Indique si la virtualisation de périphériques USB est matériellement activée
    pub enabled: bool,
    /// Nombre de contrôleurs hôtes secondaires (SHCI / Virtual Functions) supportés (0..=16)
    pub num_secondary_controllers: u8,
    /// Nombre de slots de périphériques réservés/alloués à la virtualisation (0..=255)
    pub num_virtual_device_slots: u8,
    /// Registre de contrôle matériel de virtualisation (VCTRL)
    pub virt_control: u32,
    /// Registre de statut matériel de virtualisation (VSTS)
    pub virt_status: u32,
}

impl Default for XhciDeviceVirtualization {
    fn default() -> Self {
        Self::new(2, 16)
    }
}

impl XhciDeviceVirtualization {
    /// Crée une nouvelle structure de virtualisation de périphériques xHCI 1.2 §7.13
    pub const fn new(num_secondary_controllers: u8, num_virtual_device_slots: u8) -> Self {
        let sec = if num_secondary_controllers > 16 {
            16
        } else {
            num_secondary_controllers
        };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            num_secondary_controllers: sec,
            num_virtual_device_slots,
            virt_control: 0,
            virt_status: 0,
        }
    }

    /// Décode la capacité Device Virtualization à partir de 3 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 3 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_DEVICE_VIRTUALIZATION {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let num_sec = (((dwords[0] >> 16) & 0xFF) as u8).min(16);
        let num_slots = ((dwords[0] >> 24) & 0xFF) as u8;

        let vctrl = dwords[1];
        let vsts = dwords[2];
        let enabled = (vctrl & 0x01) != 0;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            num_secondary_controllers: num_sec,
            num_virtual_device_slots: num_slots,
            virt_control: vctrl,
            virt_status: vsts,
        })
    }

    /// Encode la capacité en 3 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 3] {
        let dw0 = (XHCI_EXT_CAP_DEVICE_VIRTUALIZATION as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.num_secondary_controllers as u32) << 16)
            | ((self.num_virtual_device_slots as u32) << 24);
        let dw1 = (self.virt_control & !0x01) | (if self.enabled { 1 } else { 0 });
        let dw2 = self.virt_status;
        [dw0, dw1, dw2]
    }

    /// Active ou désactive la virtualisation xHCI matérielle
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.virt_control |= 0x01;
        } else {
            self.virt_control &= !0x01;
        }
    }

    /// Vérifie si un index de contrôleur secondaire donné est valide
    pub const fn is_secondary_controller_valid(&self, index: u8) -> bool {
        index < self.num_secondary_controllers
    }

    /// Vérifie si un slot de périphérique virtuel donné est éligible à l'assignation
    pub const fn is_slot_assignable(&self, slot_id: u8) -> bool {
        self.enabled && slot_id > 0 && slot_id <= self.num_virtual_device_slots
    }
}

/// Capacité Étendue xHCI 1.2 §7.14 : USB Shared USB Device / Hub Virtualization Architecture
///
/// Modélise la virtualisation matérielle des concentrateurs (Hubs) USB et le partage
/// direct de périphériques USB (Shared USB Device / Virtual Hub) entre le contrôleur hôte
/// primaire et les contrôleurs hôtes secondaires (Secondary Host Controller Interface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciHubVirtualization {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Indique si la virtualisation des hubs USB est matériellement activée
    pub enabled: bool,
    /// Nombre de ports downstream virtualisés pour ce hub virtuel (0..=127)
    pub num_downstream_ports: u8,
    /// Identifiant de contrôleur secondaire propriétaire / assigné (0 = contrôleur primaire)
    pub assigned_secondary_id: u8,
    /// Registre de contrôle matériel du hub virtuel (VHUBCTRL)
    pub hub_control: u32,
    /// Registre de statut matériel et drapeaux d'état de routage (VHUBSTS)
    pub hub_status: u32,
}

impl Default for XhciHubVirtualization {
    fn default() -> Self {
        Self::new(4, 0)
    }
}

impl XhciHubVirtualization {
    /// Crée une nouvelle structure de virtualisation de concentrateur xHCI 1.2 §7.14
    pub const fn new(num_downstream_ports: u8, assigned_secondary_id: u8) -> Self {
        let ports = if num_downstream_ports > 127 {
            127
        } else {
            num_downstream_ports
        };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            num_downstream_ports: ports,
            assigned_secondary_id,
            hub_control: 0,
            hub_status: 0,
        }
    }

    /// Décode la capacité Hub Virtualization à partir de 3 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 3 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_HUB_VIRTUALIZATION {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ports = (((dwords[0] >> 16) & 0xFF) as u8).min(127);
        let sec_id = ((dwords[0] >> 24) & 0xFF) as u8;

        let hctrl = dwords[1];
        let hsts = dwords[2];
        let enabled = (hctrl & 0x01) != 0;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            num_downstream_ports: ports,
            assigned_secondary_id: sec_id,
            hub_control: hctrl,
            hub_status: hsts,
        })
    }

    /// Encode la capacité en 3 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 3] {
        let dw0 = (XHCI_EXT_CAP_HUB_VIRTUALIZATION as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.num_downstream_ports as u32) << 16)
            | ((self.assigned_secondary_id as u32) << 24);
        let dw1 = (self.hub_control & !0x01) | (if self.enabled { 1 } else { 0 });
        let dw2 = self.hub_status;
        [dw0, dw1, dw2]
    }

    /// Active ou désactive la virtualisation du hub USB
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.hub_control |= 0x01;
        } else {
            self.hub_control &= !0x01;
        }
    }

    /// Assigne ce hub virtuel à un contrôleur secondaire donné
    pub fn assign_secondary_controller(&mut self, secondary_id: u8) {
        self.assigned_secondary_id = secondary_id;
    }

    /// Vérifie si un numéro de port downstream donné (1-based) est valide et routable
    pub const fn is_downstream_port_valid(&self, port_idx: u8) -> bool {
        self.enabled && port_idx > 0 && port_idx <= self.num_downstream_ports
    }
}

/// Capacité Étendue xHCI 1.2 §7.15 : USB Controller Capability Context Structure
///
/// Modélise la structure de contexte de capacité de contrôleur xHCI et les descripteurs
/// étendus du Root Hub (Root Hub Descriptor Extensions).
/// Permet l'exposition précise des paramètres de topologie du concentrateur racine,
/// le support du partitionnement matériel multi-ports, des descripteurs de puissance par port,
/// et les extensions d'identification de topologie USB 2.0 / USB 3.x / USB4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciControllerCapabilityContext {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Indique si les extensions du descripteur Root Hub sont activées
    pub enabled: bool,
    /// Nombre total de ports racine (Root Ports) supervisés (0..=255)
    pub root_port_count: u8,
    /// Nombre de descripteurs de sous-ensembles de ports (Root Hub Partitions)
    pub partition_count: u8,
    /// Registre de contrôle des capacités du contrôleur (CTRL_CAP_CTRL)
    pub cap_control: u32,
    /// Registre de statut et caractéristiques Root Hub (CTRL_CAP_STS)
    pub cap_status: u32,
    /// Masque de configuration d'alimentation et de signalisation Root Hub
    pub root_hub_power_flags: u16,
}

impl Default for XhciControllerCapabilityContext {
    fn default() -> Self {
        Self::new(4, 1)
    }
}

impl XhciControllerCapabilityContext {
    /// Crée un nouveau contexte de capacité de contrôleur xHCI 1.2 §7.15
    pub const fn new(root_port_count: u8, partition_count: u8) -> Self {
        let partitions = if partition_count == 0 {
            1
        } else {
            partition_count
        };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            root_port_count,
            partition_count: partitions,
            cap_control: 0,
            cap_status: 0,
            root_hub_power_flags: 0,
        }
    }

    /// Décode le contexte de capacité de contrôleur à partir de 4 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 4 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_CONTROLLER_CAPABILITY_CONTEXT {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let root_port_count = ((dwords[0] >> 16) & 0xFF) as u8;
        let partition_count = (((dwords[0] >> 24) & 0xFF) as u8).max(1);

        let ctrl = dwords[1];
        let sts = dwords[2];
        let pwr = (dwords[3] & 0xFFFF) as u16;
        let enabled = (ctrl & 0x01) != 0;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            root_port_count,
            partition_count,
            cap_control: ctrl,
            cap_status: sts,
            root_hub_power_flags: pwr,
        })
    }

    /// Encode le contexte de capacité de contrôleur en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_CONTROLLER_CAPABILITY_CONTEXT as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.root_port_count as u32) << 16)
            | ((self.partition_count as u32) << 24);
        let dw1 = (self.cap_control & !0x01) | (if self.enabled { 1 } else { 0 });
        let dw2 = self.cap_status;
        let dw3 = self.root_hub_power_flags as u32;
        [dw0, dw1, dw2, dw3]
    }

    /// Active ou désactive le contexte d'extension Root Hub
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.cap_control |= 0x01;
        } else {
            self.cap_control &= !0x01;
        }
    }

    /// Vérifie si un numéro de port racine (1-based) est valide dans le descripteur Root Hub
    pub const fn is_root_port_valid(&self, port_idx: u8) -> bool {
        self.enabled && port_idx > 0 && port_idx <= self.root_port_count
    }

    /// Vérifie si une partition matérielle Root Hub (0-based) est valide
    pub const fn is_partition_valid(&self, partition_idx: u8) -> bool {
        partition_idx < self.partition_count
    }

    /// Définit les drapeaux de gestion d'énergie Root Hub
    pub fn set_power_flags(&mut self, flags: u16) {
        self.root_hub_power_flags = flags;
    }
}

/// Capacité Étendue xHCI 1.2 §7.16 : USB Extended TDM / Bandwidth Negotiation Context Structure
///
/// Modélise les mécanismes d'allocation de bande passante déterministe et de multiplexage
/// temporel (TDM) pour flux périodiques USB (isochrones / interrupt), garantissant la
/// réservation prédictible de créneaux et l'arbitrage sans famine de bande passante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciBandwidthNegotiation {
    /// Déplacement du pointeur vers la capacité étendue suivante (en dwords)
    pub next_ptr_dwords: u8,
    /// Activation globale de la négociation matérielle de bande passante
    pub enabled: bool,
    /// Nombre de canaux TDM périodiques supportés par le contrôleur (1..=64)
    pub tdm_channel_count: u8,
    /// Pourcentage maximal de bande passante allouable aux flux isochrones (1..=100)
    pub max_isochronous_bw_percent: u8,
    /// Registre de contrôle de négociation de bande passante (BW_NEG_CTRL)
    pub bw_control: u32,
    /// Registre d'état et drapeaux d'arbitrage de bande passante (BW_NEG_STS)
    pub bw_status: u32,
    /// Bande passante actuellement allouée en kilobits par micro-trame (125 µs)
    pub allocated_bw_kb_per_uframe: u16,
}

impl Default for XhciBandwidthNegotiation {
    fn default() -> Self {
        Self::new(8, 80)
    }
}

impl XhciBandwidthNegotiation {
    /// Crée une nouvelle structure de négociation de bande passante xHCI 1.2 §7.16
    pub const fn new(tdm_channel_count: u8, max_isochronous_bw_percent: u8) -> Self {
        let channels = if tdm_channel_count == 0 {
            1
        } else if tdm_channel_count > 64 {
            64
        } else {
            tdm_channel_count
        };
        let max_pct = if max_isochronous_bw_percent == 0 {
            1
        } else if max_isochronous_bw_percent > 100 {
            100
        } else {
            max_isochronous_bw_percent
        };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            tdm_channel_count: channels,
            max_isochronous_bw_percent: max_pct,
            bw_control: 0,
            bw_status: 0,
            allocated_bw_kb_per_uframe: 0,
        }
    }

    /// Décode le contexte de négociation de bande passante à partir de 4 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 4 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_BANDWIDTH_NEGOTIATION {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let tdm_channels = (((dwords[0] >> 16) & 0xFF) as u8).clamp(1, 64);
        let max_pct = (((dwords[0] >> 24) & 0xFF) as u8).clamp(1, 100);

        let ctrl = dwords[1];
        let sts = dwords[2];
        let alloc_bw = (dwords[3] & 0xFFFF) as u16;
        let enabled = (ctrl & 0x01) != 0;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            tdm_channel_count: tdm_channels,
            max_isochronous_bw_percent: max_pct,
            bw_control: ctrl,
            bw_status: sts,
            allocated_bw_kb_per_uframe: alloc_bw,
        })
    }

    /// Encode le contexte de négociation de bande passante en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_BANDWIDTH_NEGOTIATION as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.tdm_channel_count as u32) << 16)
            | ((self.max_isochronous_bw_percent as u32) << 24);
        let dw1 = (self.bw_control & !0x01) | (if self.enabled { 1 } else { 0 });
        let dw2 = self.bw_status;
        let dw3 = self.allocated_bw_kb_per_uframe as u32;
        [dw0, dw1, dw2, dw3]
    }

    /// Active ou désactive le moteur de négociation TDM / Bandwidth
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.bw_control |= 0x01;
        } else {
            self.bw_control &= !0x01;
        }
    }

    /// Vérifie si un canal TDM périodique (0-based) est valide
    pub const fn is_tdm_channel_valid(&self, channel_idx: u8) -> bool {
        self.enabled && channel_idx < self.tdm_channel_count
    }

    /// Tente d'allouer une tranche de bande passante en kb/µframe
    pub fn allocate_bandwidth(&mut self, kb_per_uframe: u16, max_limit: u16) -> bool {
        if !self.enabled {
            return false;
        }
        let effective_limit =
            ((max_limit as u32) * (self.max_isochronous_bw_percent as u32) / 100) as u16;
        if let Some(new_total) = self.allocated_bw_kb_per_uframe.checked_add(kb_per_uframe) {
            if new_total <= effective_limit {
                self.allocated_bw_kb_per_uframe = new_total;
                return true;
            }
        }
        false
    }

    /// Libère une tranche de bande passante précédemment allouée
    pub fn release_bandwidth(&mut self, kb_per_uframe: u16) {
        self.allocated_bw_kb_per_uframe = self
            .allocated_bw_kb_per_uframe
            .saturating_sub(kb_per_uframe);
    }
}

/// Capacité Étendue xHCI USB Latency Tolerance Messaging (LTM / xHCI 1.2 §7.17)
///
/// Permet la gestion fine de la tolérance à la latence (LTM) pour les périphériques SuperSpeed / SuperSpeedPlus.
/// Définit les valeurs de latence maximale acceptables (BELT - Best Effort Latency Tolerance)
/// pour optimiser les transitions d'états d'alimentation basse consommation C-states et U-states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciLatencyToleranceMessaging {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// LTM activé au niveau du contrôleur hôte
    pub enabled: bool,
    /// Nombre de ports prenant en charge LTM (1..=64)
    pub ltm_port_count: u8,
    /// Échelle de tolérance de latence (0 = 1 ns, 1 = 32 ns, 2 = 1024 ns, 3 = 32768 ns, etc.)
    pub latency_tolerance_scale: u8,
    /// Registre de contrôle LTM
    pub ltm_control: u32,
    /// Registre de statut LTM
    pub ltm_status: u32,
    /// Valeur maximale de tolérance de latence (BELT en unités d'échelle)
    pub max_belt_latency: u16,
}

impl XhciLatencyToleranceMessaging {
    /// Crée un nouveau contexte LTM initialisé
    pub const fn new(port_count: u8, tolerance_scale: u8) -> Self {
        let ports = if port_count == 0 {
            1
        } else if port_count > 64 {
            64
        } else {
            port_count
        };
        let scale = if tolerance_scale > 7 {
            7
        } else {
            tolerance_scale
        };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            ltm_port_count: ports,
            latency_tolerance_scale: scale,
            ltm_control: 0,
            ltm_status: 0,
            max_belt_latency: 0,
        }
    }

    /// Décode le contexte LTM à partir de 4 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 4 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_LATENCY_TOLERANCE_MESSAGING {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ports = (((dwords[0] >> 16) & 0xFF) as u8).clamp(1, 64);
        let scale = (((dwords[0] >> 24) & 0x07) as u8).min(7);

        let ctrl = dwords[1];
        let sts = dwords[2];
        let belt = (dwords[3] & 0xFFFF) as u16;
        let enabled = (ctrl & 0x01) != 0;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            ltm_port_count: ports,
            latency_tolerance_scale: scale,
            ltm_control: ctrl,
            ltm_status: sts,
            max_belt_latency: belt,
        })
    }

    /// Encode le contexte LTM en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_LATENCY_TOLERANCE_MESSAGING as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.ltm_port_count as u32) << 16)
            | (((self.latency_tolerance_scale & 0x07) as u32) << 24);
        let dw1 = (self.ltm_control & !0x01) | (if self.enabled { 1 } else { 0 });
        let dw2 = self.ltm_status;
        let dw3 = self.max_belt_latency as u32;
        [dw0, dw1, dw2, dw3]
    }

    /// Active ou désactive le moteur Latency Tolerance Messaging
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.ltm_control |= 0x01;
        } else {
            self.ltm_control &= !0x01;
        }
    }

    /// Vérifie si un port LTM (1-based) est valide
    pub const fn is_ltm_port_valid(&self, port_num: u8) -> bool {
        self.enabled && port_num >= 1 && port_num <= self.ltm_port_count
    }

    /// Configure la valeur BELT maximale
    pub fn set_max_belt_latency(&mut self, belt: u16) {
        self.max_belt_latency = belt;
    }

    /// Calcule la latence en nanosecondes selon l'échelle LTM standard USB 3.0 / xHCI 1.2
    /// Échelle :
    /// - 0 : 1 ns * belt
    /// - 1 : 32 ns * belt
    /// - 2 : 1 024 ns * belt
    /// - 3 : 32 768 ns * belt
    /// - 4 : 1 048 576 ns * belt
    /// - 5 : 33 554 432 ns * belt
    /// - Autres : non défini / saturé
    pub const fn compute_latency_ns(&self) -> u64 {
        let belt = self.max_belt_latency as u64;
        match self.latency_tolerance_scale {
            0 => belt,
            1 => belt.saturating_mul(32),
            2 => belt.saturating_mul(1024),
            3 => belt.saturating_mul(32768),
            4 => belt.saturating_mul(1048576),
            5 => belt.saturating_mul(33554432),
            _ => belt.saturating_mul(1073741824),
        }
    }
}

/// Capacité Étendue xHCI Endpoint / Stream Context Extension & Polling Interval Overrides (xHCI 1.2 §7.18)
///
/// Permet la surcharge fine et dynamique de l'intervalle de polling matériel (`bInterval` / ESIT)
/// et des paramètres de streams USB 3.x pour optimiser les performances des flux isochrones et UAS/Bulk Streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciEndpointStreamOverride {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Surcharge active (Override Enable)
    pub enabled: bool,
    /// Identifiant de Slot cible (1..=255)
    pub slot_id: u8,
    /// Identifiant d'Endpoint cible (1..=31, DCI)
    pub endpoint_id: u8,
    /// Intervalle de polling de substitution (0..=15, exprimé en puissances de microframes 2^(interval-1) * 125 µs)
    pub polling_interval_override: u8,
    /// Nombre maximal de flux primaires autorisés (Primary Stream Array exponent 2^k)
    pub max_primary_streams: u8,
    /// Drapeaux de contrôle de flux (ex: Linear Stream Array, Stream Reset)
    pub stream_control: u32,
    /// Statut et compteurs de streams actifs
    pub stream_status: u32,
}

impl XhciEndpointStreamOverride {
    /// Initialise une nouvelle surcharge d'endpoint / stream context
    pub const fn new(slot_id: u8, endpoint_id: u8, interval_override: u8) -> Self {
        let ep = if endpoint_id == 0 {
            1
        } else if endpoint_id > 31 {
            31
        } else {
            endpoint_id
        };
        let interval = if interval_override > 15 {
            15
        } else {
            interval_override
        };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            slot_id,
            endpoint_id: ep,
            polling_interval_override: interval,
            max_primary_streams: 0,
            stream_control: 0,
            stream_status: 0,
        }
    }

    /// Décode la capacité étendue depuis 4 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 4 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_ENDPOINT_POLLING_OVERRIDE {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let slot = ((dwords[0] >> 16) & 0xFF) as u8;
        let ep = (((dwords[0] >> 24) & 0x1F) as u8).clamp(1, 31);

        let ctrl = dwords[1];
        let sts = dwords[2];
        let _dw3 = dwords[3];

        let enabled = (ctrl & 0x01) != 0;
        let interval = ((ctrl >> 8) & 0x0F) as u8;
        let max_streams = ((ctrl >> 16) & 0x0F) as u8;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            slot_id: slot,
            endpoint_id: ep,
            polling_interval_override: interval,
            max_primary_streams: max_streams,
            stream_control: ctrl,
            stream_status: sts,
        })
    }

    /// Encode en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_ENDPOINT_POLLING_OVERRIDE as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.slot_id as u32) << 16)
            | (((self.endpoint_id & 0x1F) as u32) << 24);
        let ctrl_flags = (self.stream_control & !0x000F_0F01)
            | (if self.enabled { 1 } else { 0 })
            | (((self.polling_interval_override & 0x0F) as u32) << 8)
            | (((self.max_primary_streams & 0x0F) as u32) << 16);
        let dw1 = ctrl_flags;
        let dw2 = self.stream_status;
        let dw3 = 0u32;
        [dw0, dw1, dw2, dw3]
    }

    /// Active ou désactive la surcharge matérielle
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.stream_control |= 0x01;
        } else {
            self.stream_control &= !0x01;
        }
    }

    /// Configure l'intervalle de polling surchargé (0..=15)
    pub fn set_polling_interval(&mut self, interval: u8) {
        let val = interval.min(15);
        self.polling_interval_override = val;
        self.stream_control = (self.stream_control & !(0x0F << 8)) | ((val as u32) << 8);
    }

    /// Configure le nombre d'exposant max de flux primaires
    pub fn set_max_primary_streams(&mut self, max_streams: u8) {
        let val = max_streams.min(15);
        self.max_primary_streams = val;
        self.stream_control = (self.stream_control & !(0x0F << 16)) | ((val as u32) << 16);
    }

    /// Calcule la période de polling en microsecondes (125 µs * 2^(interval-1) pour interval >= 1)
    pub const fn compute_period_us(&self) -> u32 {
        if self.polling_interval_override == 0 {
            125 // 1 microframe = 125 µs
        } else {
            let shift = (self.polling_interval_override - 1) as u32;
            if shift >= 15 {
                125 << 14
            } else {
                125 << shift
            }
        }
    }

    /// Calcule la capacité maximale de streams allouables (2^max_primary_streams)
    pub const fn max_streams_count(&self) -> u32 {
        if self.max_primary_streams == 0 {
            1
        } else {
            1 << (self.max_primary_streams as u32)
        }
    }
}

/// Capacité Étendue xHCI Interrupter Moderation & Vector Override (xHCI 1.2 §7.19)
///
/// Permet de surcharger dynamiquement le vecteur d'interruption et le taux de modération
/// matérielle IMOD (Intervalle en unités de 250 ns et compteur de décrémentation)
/// par interrupteur xHCI ou vecteur étendu sans reconfiguration complète du contrôleur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciInterrupterModerationOverride {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Activation de la surcharge matérielle de modération
    pub enabled: bool,
    /// Index de l'interrupteur xHCI ciblé (0..=1023)
    pub interrupter_idx: u16,
    /// Vecteur MSI-X étendu assigné (0..=2047)
    pub msix_vector: u16,
    /// Intervalle de modération IMOD en unités de 250 ns (0..=65535)
    pub moderation_interval_250ns: u16,
    /// Compteur matériel IMOD (temps restant avant interruption active en 250 ns)
    pub moderation_counter_250ns: u16,
    /// Registre de contrôle brut MMIO (Dword 1)
    pub override_control: u32,
    /// Registre de statut brut MMIO (Dword 2)
    pub override_status: u32,
}

impl XhciInterrupterModerationOverride {
    /// Crée une instance avec valeurs par défaut
    pub const fn new(interrupter_idx: u16, msix_vector: u16, imod_interval_250ns: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            interrupter_idx,
            msix_vector,
            moderation_interval_250ns: imod_interval_250ns,
            moderation_counter_250ns: 0,
            override_control: 0,
            override_status: 0,
        }
    }

    /// Décode la capacité étendue depuis 4 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 4 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_INTERRUPTER_MODERATION_OVERRIDE {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let interrupter = ((dwords[0] >> 16) & 0x03FF) as u16;

        let ctrl = dwords[1];
        let sts = dwords[2];
        let imod_dw = dwords[3];

        let enabled = (ctrl & 0x01) != 0;
        let vector = ((ctrl >> 16) & 0x07FF) as u16;
        let interval = (imod_dw & 0xFFFF) as u16;
        let counter = ((imod_dw >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            interrupter_idx: interrupter,
            msix_vector: vector,
            moderation_interval_250ns: interval,
            moderation_counter_250ns: counter,
            override_control: ctrl,
            override_status: sts,
        })
    }

    /// Encode en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_INTERRUPTER_MODERATION_OVERRIDE as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | (((self.interrupter_idx & 0x03FF) as u32) << 16);
        let ctrl_flags = (self.override_control & !0x07FF_0001)
            | (if self.enabled { 1 } else { 0 })
            | (((self.msix_vector & 0x07FF) as u32) << 16);
        let dw1 = ctrl_flags;
        let dw2 = self.override_status;
        let dw3 = (self.moderation_interval_250ns as u32)
            | ((self.moderation_counter_250ns as u32) << 16);
        [dw0, dw1, dw2, dw3]
    }

    /// Active ou désactive la surcharge matérielle
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.override_control |= 0x01;
        } else {
            self.override_control &= !0x01;
        }
    }

    /// Configure l'intervalle de modération en tranches de 250 ns
    pub fn set_moderation_interval(&mut self, interval_250ns: u16) {
        self.moderation_interval_250ns = interval_250ns;
    }

    /// Configure le vecteur MSI-X (0..=2047)
    pub fn set_msix_vector(&mut self, vector: u16) {
        let v = vector.min(2047);
        self.msix_vector = v;
        self.override_control = (self.override_control & !(0x07FF << 16)) | ((v as u32) << 16);
    }

    /// Calcule l'intervalle de modération en nanosecondes (interval * 250 ns)
    pub const fn moderation_interval_ns(&self) -> u64 {
        (self.moderation_interval_250ns as u64) * 250
    }

    /// Calcule l'intervalle de modération en microsecondes
    pub const fn moderation_interval_us(&self) -> u64 {
        self.moderation_interval_ns() / 1000
    }

    /// Calcule le taux maximal théorique d'interruptions par seconde (si interval > 0)
    pub const fn max_interrupts_per_sec(&self) -> u64 {
        let ns = self.moderation_interval_ns();
        match 1_000_000_000u64.checked_div(ns) {
            Some(rate) => rate,
            None => 4_000_000, // Taux maximal non bridé (fréquence 4 MHz à 250 ns)
        }
    }
}

/// Capacité Étendue xHCI USB Protocol Speed Identification & Port Speed Mapping Overrides (xHCI 1.2 §7.20)
///
/// Permet de surcharger dynamiquement le mappage des vitesses USB (PSI - Protocol Speed ID)
/// pour chaque port physique ou racine USB (Full-Speed 12 Mbps, High-Speed 480 Mbps,
/// SuperSpeed Gen1x1 5 Gbps, Gen1x2 / Gen2x1 10 Gbps, Gen2x2 20 Gbps) avec contrôle duplex (Rx/Tx).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciPortSpeedMappingOverride {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Activation de la surcharge matérielle de vitesse (Override Enable)
    pub enabled: bool,
    /// Identifiant de port physique xHCI (1..=255)
    pub port_num: u8,
    /// Protocole USB associé (USB 2.0 = 2, USB 3.x = 3, USB4 = 4)
    pub protocol_revision: u8,
    /// Protocol Speed ID ciblé (PSI 1..=15)
    pub speed_id: u8,
    /// Multiplicateur de débit (Bit Rate Exponent: 0=Bps, 1=Kbps, 2=Mbps, 3=Gbps)
    pub exponent: u8,
    /// Valeur mantisse de débit (Bit Rate Mantissa, 16 bits)
    pub mantissa: u16,
    /// Mode Full-Duplex (true) ou Half-Duplex (false)
    pub full_duplex: bool,
    /// Registre de contrôle brut MMIO (Dword 1)
    pub override_control: u32,
    /// Registre de statut brut MMIO (Dword 2)
    pub override_status: u32,
}

impl XhciPortSpeedMappingOverride {
    /// Crée une nouvelle surcharge de vitesse de port
    pub const fn new(
        port_num: u8,
        speed_id: u8,
        mantissa: u16,
        exponent: u8,
        full_duplex: bool,
    ) -> Self {
        let p = if port_num == 0 { 1 } else { port_num };
        let sid = if speed_id == 0 {
            1
        } else if speed_id > 15 {
            15
        } else {
            speed_id
        };
        let exp = if exponent > 3 { 3 } else { exponent };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            port_num: p,
            protocol_revision: 3, // USB 3.x par défaut
            speed_id: sid,
            exponent: exp,
            mantissa,
            full_duplex,
            override_control: 0,
            override_status: 0,
        }
    }

    /// Décode la capacité étendue depuis 4 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 4 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_PORT_SPEED_MAPPING_OVERRIDE {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let port = ((dwords[0] >> 16) & 0xFF) as u8;
        let proto = ((dwords[0] >> 24) & 0xFF) as u8;

        let ctrl = dwords[1];
        let sts = dwords[2];
        let speed_dw = dwords[3];

        let enabled = (ctrl & 0x01) != 0;
        let sid = ((ctrl >> 8) & 0x0F) as u8;
        let fduplex = ((ctrl >> 12) & 0x01) != 0;
        let exp = ((speed_dw >> 16) & 0x03) as u8;
        let mant = (speed_dw & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            port_num: if port == 0 { 1 } else { port },
            protocol_revision: proto,
            speed_id: if sid == 0 { 1 } else { sid },
            exponent: exp,
            mantissa: mant,
            full_duplex: fduplex,
            override_control: ctrl,
            override_status: sts,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_PORT_SPEED_MAPPING_OVERRIDE as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.port_num as u32) << 16)
            | ((self.protocol_revision as u32) << 24);
        let ctrl_flags = (self.override_control & !0x0000_1F01)
            | (if self.enabled { 1 } else { 0 })
            | (((self.speed_id & 0x0F) as u32) << 8)
            | (if self.full_duplex { 1 << 12 } else { 0 });
        let dw1 = ctrl_flags;
        let dw2 = self.override_status;
        let dw3 = (self.mantissa as u32) | (((self.exponent & 0x03) as u32) << 16);
        [dw0, dw1, dw2, dw3]
    }

    /// Active ou désactive la surcharge matérielle de vitesse
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.override_control |= 0x01;
        } else {
            self.override_control &= !0x01;
        }
    }

    /// Configure le débit (mantisse et exposant 0=Bps, 1=Kbps, 2=Mbps, 3=Gbps)
    pub fn set_bitrate(&mut self, mantissa: u16, exponent: u8) {
        self.mantissa = mantissa;
        self.exponent = exponent.min(3);
    }

    /// Configure le mode Full Duplex
    pub fn set_full_duplex(&mut self, full_duplex: bool) {
        self.full_duplex = full_duplex;
        if full_duplex {
            self.override_control |= 1 << 12;
        } else {
            self.override_control &= !(1 << 12);
        }
    }

    /// Calcule le débit binaire théorique en Mégabits par seconde (Mbps)
    pub const fn bitrate_mbps(&self) -> u64 {
        let m = self.mantissa as u64;
        match self.exponent {
            0 => m / 1_000_000,
            1 => m / 1_000,
            2 => m,
            3 => m.saturating_mul(1000),
            _ => m,
        }
    }
}

/// Capacité Étendue xHCI Extended Energy Efficient USB (EEE / xHCI 1.2 §7.21)
///
/// Permet la gestion matérielle avancée de la transition basse consommation
/// L1/L2, les temporisateurs d'inactivité de lien et les états d'économie d'énergie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciExtendedEnergyEfficientUsb {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Activation de la gestion EEE (Energy Efficient Enable)
    pub enabled: bool,
    /// Nombre de ports physiques supportant l'extension EEE (1..=255)
    pub port_count: u8,
    /// Temporisateur d'inactivité L1 en microsecondes (0..=65535 µs)
    pub l1_inactivity_timer_us: u16,
    /// Seuil de réveil rapide (Fast Wake-Up latency threshold en 128 ns)
    pub fast_wake_threshold_128ns: u8,
    /// Support du Deep Sleep Controller (DSC)
    pub deep_sleep_supported: bool,
    /// Registre de contrôle brut MMIO
    pub eee_control: u32,
    /// Registre de statut brut MMIO
    pub eee_status: u32,
}

impl XhciExtendedEnergyEfficientUsb {
    /// Crée un nouveau descripteur étendu EEE
    pub const fn new(port_count: u8, l1_timer_us: u16, fast_wake_128ns: u8) -> Self {
        let count = if port_count == 0 { 1 } else { port_count };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            port_count: count,
            l1_inactivity_timer_us: l1_timer_us,
            fast_wake_threshold_128ns: fast_wake_128ns,
            deep_sleep_supported: true,
            eee_control: 0,
            eee_status: 0,
        }
    }

    /// Décode la capacité étendue depuis 4 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 4 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_EXTENDED_ENERGY_EFFICIENT_USB {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ports = ((dwords[0] >> 16) & 0xFF) as u8;
        let fw_thresh = ((dwords[0] >> 24) & 0xFF) as u8;

        let ctrl = dwords[1];
        let sts = dwords[2];
        let timer = (dwords[3] & 0xFFFF) as u16;
        let dsc = (dwords[3] & (1 << 16)) != 0;

        let enabled = (ctrl & 0x01) != 0;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            port_count: if ports == 0 { 1 } else { ports },
            l1_inactivity_timer_us: timer,
            fast_wake_threshold_128ns: fw_thresh,
            deep_sleep_supported: dsc,
            eee_control: ctrl,
            eee_status: sts,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_EXTENDED_ENERGY_EFFICIENT_USB as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.port_count as u32) << 16)
            | ((self.fast_wake_threshold_128ns as u32) << 24);
        let ctrl_flags = (self.eee_control & !0x01) | (if self.enabled { 1 } else { 0 });
        let dw1 = ctrl_flags;
        let dw2 = self.eee_status;
        let dw3 = (self.l1_inactivity_timer_us as u32)
            | (if self.deep_sleep_supported {
                1 << 16
            } else {
                0
            });
        [dw0, dw1, dw2, dw3]
    }

    /// Active ou désactive l'efficacité énergétique EEE
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.eee_control |= 0x01;
        } else {
            self.eee_control &= !0x01;
        }
    }

    /// Configure le temporisateur d'inactivité L1 (en microsecondes)
    pub fn set_l1_inactivity_timer(&mut self, timer_us: u16) {
        self.l1_inactivity_timer_us = timer_us;
    }

    /// Calcule la latence de réveil rapide en nanosecondes
    pub const fn fast_wake_latency_ns(&self) -> u64 {
        (self.fast_wake_threshold_128ns as u64) * 128
    }

    /// Vérifie si un port donné est dans la plage couverte par cette capacité EEE
    pub const fn is_port_in_range(&self, port: u8) -> bool {
        port >= 1 && port <= self.port_count
    }
}

/// Capacité Étendue xHCI Optical Logical Link Control (OLLC / xHCI 1.2 §7.22)
///
/// Modélise le contrôle et la télémétrie des liaisons optiques USB actives (Active Optical Cables - AOC),
/// la détection de dispersion chromatique, l'atténuation optique en dBm et le budget de liaison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciOpticalLogicalLink {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Activation du contrôleur de liaison optique
    pub enabled: bool,
    /// Numéro de port optique xHCI physique (1..=255)
    pub port_num: u8,
    /// Atténuation du signal optique mesurée en centièmes de dBm (0..=65535, ex: 150 = 1.50 dBm)
    pub optical_attenuation_cdbm: u16,
    /// Longueur d'onde optique nominale en nanomètres (ex: 850 nm VCSEL, 1310 nm DFB)
    pub wavelength_nm: u16,
    /// Alerte de perte de signal optique (LOS - Loss Of Signal)
    pub loss_of_signal: bool,
    /// Registre de contrôle brut MMIO (Dword 1)
    pub link_control: u32,
    /// Registre d'état et télémétrie brut MMIO (Dword 2)
    pub link_status: u32,
}

impl XhciOpticalLogicalLink {
    /// Crée un nouveau descripteur étendu de liaison optique xHCI §7.22
    pub const fn new(port_num: u8, wavelength_nm: u16, attenuation_cdbm: u16) -> Self {
        let p = if port_num == 0 { 1 } else { port_num };
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            port_num: p,
            optical_attenuation_cdbm: attenuation_cdbm,
            wavelength_nm,
            loss_of_signal: false,
            link_control: 0,
            link_status: 0,
        }
    }

    /// Décode la capacité étendue depuis 4 dwords MMIO
    pub fn parse(dwords: &[u32]) -> Option<Self> {
        if dwords.len() < 4 {
            return None;
        }
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_OPTICAL_LOGICAL_LINK {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let port = ((dwords[0] >> 16) & 0xFF) as u8;
        let wl = (dwords[0] >> 24) as u8; // 8 bits réservés / format compact

        let ctrl = dwords[1];
        let sts = dwords[2];
        let attenuation = (dwords[3] & 0xFFFF) as u16;
        let wavelength = ((dwords[3] >> 16) & 0xFFFF) as u16;

        let enabled = (ctrl & 0x01) != 0;
        let los = (sts & 0x01) != 0;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            port_num: if port == 0 { 1 } else { port },
            optical_attenuation_cdbm: attenuation,
            wavelength_nm: if wavelength != 0 {
                wavelength
            } else {
                (wl as u16) * 10
            },
            loss_of_signal: los,
            link_control: ctrl,
            link_status: sts,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_OPTICAL_LOGICAL_LINK as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.port_num as u32) << 16)
            | (((self.wavelength_nm / 10) as u32 & 0xFF) << 24);
        let ctrl_flags = (self.link_control & !0x01) | (if self.enabled { 1 } else { 0 });
        let dw1 = ctrl_flags;
        let dw2 = (self.link_status & !0x01) | (if self.loss_of_signal { 1 } else { 0 });
        let dw3 = (self.optical_attenuation_cdbm as u32) | ((self.wavelength_nm as u32) << 16);
        [dw0, dw1, dw2, dw3]
    }

    /// Active ou désactive le contrôleur de liaison optique
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.link_control |= 0x01;
        } else {
            self.link_control &= !0x01;
        }
    }

    /// Définit l'état de perte de signal optique (LOS)
    pub fn set_loss_of_signal(&mut self, los: bool) {
        self.loss_of_signal = los;
        if los {
            self.link_status |= 0x01;
        } else {
            self.link_status &= !0x01;
        }
    }

    /// Calcule si la liaison optique est saine (active et sans perte de signal)
    pub const fn is_link_healthy(&self) -> bool {
        self.enabled && !self.loss_of_signal
    }

    /// Calcule l'atténuation optique en décibels (dB) entiers
    pub const fn attenuation_db(&self) -> u16 {
        self.optical_attenuation_cdbm / 100
    }
}

/// Capacité Étendue xHCI DbC Telemetry & Hardware Diagnostics (§7.23 / USB Debug Capability Telemetry)
///
/// Modélise les registres matériels xHCI pour la télémétrie haute fidélité du DbC,
/// le suivi des traces d'exécution PCIe, les compteurs d'échantillonnage de paquets de débogage
/// et la détection d'erreurs d'intégrité de liaison physique sans interruption d'ordonnancement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciDbcTelemetry {
    /// Pointeur dword vers la prochaine capacité étendue (0 = dernière)
    pub next_ptr_dwords: u8,
    /// Activation de la télémétrie DbC (bit 0 du registre de contrôle)
    pub enabled: bool,
    /// Mode de trace en boucle circulaire (bit 1 du registre de contrôle)
    pub circular_buffer: bool,
    /// Débordement de trace détecté (bit 2 du registre d'état)
    pub trace_overflow: bool,
    /// Numéro de port xHCI physique surveillé
    pub port_num: u8,
    /// Fréquence d'échantillonnage de télémétrie en kHz (1..=1000)
    pub sampling_rate_khz: u16,
    /// Compteur d'événements de trace diagnostique capturés
    pub trace_event_count: u32,
    /// Registre de contrôle brut (DWORD 1)
    pub control: u32,
    /// Registre d'état brut (DWORD 2)
    pub status: u32,
}

impl XhciDbcTelemetry {
    /// Crée une nouvelle configuration de télémétrie DbC
    pub const fn new(port_num: u8, sampling_rate_khz: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            circular_buffer: true,
            trace_overflow: false,
            port_num,
            sampling_rate_khz,
            trace_event_count: 0,
            control: 0x02, // circular_buffer activé par défaut
            status: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue xHCI DbC Telemetry (§7.23)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_DBC_TELEMETRY {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let port = ((dwords[0] >> 16) & 0xFF) as u8;

        let ctrl = dwords[1];
        let sts = dwords[2];
        let rate = (dwords[3] & 0xFFFF) as u16;
        let events = dwords[2]; // status contient également le compteur d'événements ou DWORD 3

        let enabled = (ctrl & 0x01) != 0;
        let circular = (ctrl & 0x02) != 0;
        let overflow = (sts & 0x04) != 0;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            circular_buffer: circular,
            trace_overflow: overflow,
            port_num: if port == 0 { 1 } else { port },
            sampling_rate_khz: if rate == 0 { 100 } else { rate },
            trace_event_count: events >> 8,
            control: ctrl,
            status: sts,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_DBC_TELEMETRY as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.port_num as u32) << 16);
        let mut ctrl = self.control & !0x03;
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.circular_buffer {
            ctrl |= 0x02;
        }
        let mut sts = (self.status & !0x04) | ((self.trace_event_count & 0x00FF_FFFF) << 8);
        if self.trace_overflow {
            sts |= 0x04;
        }
        let dw3 = (self.sampling_rate_khz as u32) & 0xFFFF;
        [dw0, ctrl, sts, dw3]
    }

    /// Active ou désactive la capture de télémétrie DbC
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.control |= 0x01;
        } else {
            self.control &= !0x01;
        }
    }

    /// Enregistre l'arrivée d'un événement de trace diagnostique
    pub fn record_event(&mut self) {
        if !self.enabled {
            return;
        }
        if self.trace_event_count == 0x00FF_FFFF && !self.circular_buffer {
            self.trace_overflow = true;
            self.status |= 0x04;
        } else {
            self.trace_event_count = (self.trace_event_count + 1) & 0x00FF_FFFF;
        }
    }

    /// Réinitialise les compteurs de trace
    pub fn reset_trace(&mut self) {
        self.trace_event_count = 0;
        self.trace_overflow = false;
        self.status &= !0x04;
    }

    /// Vérifie si la télémétrie est opérationnelle sans perte de paquets
    pub const fn is_telemetry_healthy(&self) -> bool {
        self.enabled && !self.trace_overflow
    }
}

/// Capacité Étendue xHCI Sublink Speed Routing (SSRC / xHCI 1.2 §7.24)
///
/// Permet la négociation et l'assignation granulaire des sous-liens PCIe/USB
/// (Sublink Speed Attributes) pour les architectures multi-voies (USB 3.2 Gen 1x2, 2x2 et USB4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciSublinkSpeedRouting {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Routage des sous-liens activé
    pub enabled: bool,
    /// Support de la topologie asymétrique de débit Rx/Tx
    pub asymmetric_rates_supported: bool,
    /// Numéro de port xHCI assigné
    pub port_num: u8,
    /// Débit de sous-lien amont sélectionné (en multiples de 100 Mbps)
    pub upstream_sublink_rate: u16,
    /// Débit de sous-lien aval sélectionné (en multiples de 100 Mbps)
    pub downstream_sublink_rate: u16,
    /// Registre de contrôle brut (DWORD 1)
    pub control: u32,
    /// Registre de statut brut (DWORD 2)
    pub status: u32,
}

impl XhciSublinkSpeedRouting {
    /// Crée une nouvelle configuration de routage de vitesse sous-liens
    pub const fn new(port_num: u8, symmetric_rate_100mbps: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            asymmetric_rates_supported: true,
            port_num,
            upstream_sublink_rate: symmetric_rate_100mbps,
            downstream_sublink_rate: symmetric_rate_100mbps,
            control: 0x02, // Asymmetric support activé par défaut
            status: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue xHCI Sublink Speed Routing (§7.24)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_SUBLINK_SPEED_ROUTING {
            return None;
        }
        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let port = ((dwords[0] >> 16) & 0xFF) as u8;

        let ctrl = dwords[1];
        let sts = dwords[2];
        let rates = dwords[3];

        let enabled = (ctrl & 0x01) != 0;
        let asymmetric = (ctrl & 0x02) != 0;
        let up_rate = (rates & 0xFFFF) as u16;
        let down_rate = ((rates >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            asymmetric_rates_supported: asymmetric,
            port_num: if port == 0 { 1 } else { port },
            upstream_sublink_rate: if up_rate == 0 { 50 } else { up_rate },
            downstream_sublink_rate: if down_rate == 0 { 50 } else { down_rate },
            control: ctrl,
            status: sts,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_SUBLINK_SPEED_ROUTING as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.port_num as u32) << 16);
        let mut ctrl = self.control & !0x03;
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.asymmetric_rates_supported {
            ctrl |= 0x02;
        }
        let sts = self.status;
        let dw3 =
            (self.upstream_sublink_rate as u32) | ((self.downstream_sublink_rate as u32) << 16);
        [dw0, ctrl, sts, dw3]
    }

    /// Active ou désactive le routage dynamique de sous-lien
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.control |= 0x01;
        } else {
            self.control &= !0x01;
        }
    }

    /// Met à jour les débits amont / aval
    pub fn configure_rates(&mut self, upstream: u16, downstream: u16) {
        self.upstream_sublink_rate = upstream;
        self.downstream_sublink_rate = downstream;
    }

    /// Vérifie si le lien opère en mode symétrique
    pub const fn is_symmetric(&self) -> bool {
        self.upstream_sublink_rate == self.downstream_sublink_rate
    }
}

/// Capacité Étendue xHCI Extended Message Interrupt Vector Table (MIVT / xHCI 1.2 §7.25)
///
/// Permet l'assignation granulaire des vecteurs d'interruption MSI-X étendus
/// et le masquage individuel par interrupteur xHCI (jusqu'à 2048 interrupteurs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciExtendedMessageInterruptVector {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Fonctionnalité MIVT activée globalement
    pub enabled: bool,
    /// Nombre d'entrées de table de vecteurs supportées
    pub table_size: u16,
    /// Index d'interrupteur primaire configuré
    pub primary_interrupter_index: u16,
    /// Masque d'interruption global
    pub global_mask: bool,
    /// Registre de contrôle brut (DWORD 1)
    pub control: u32,
    /// Registre d'offset de table BIR/Offset (DWORD 2)
    pub table_offset_bir: u32,
}

impl XhciExtendedMessageInterruptVector {
    /// Crée une nouvelle configuration MIVT avec la taille de table spécifiée
    pub const fn new(table_size: u16, primary_interrupter: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            table_size,
            primary_interrupter_index: primary_interrupter,
            global_mask: false,
            control: 0,
            table_offset_bir: 0, // BIR 0, offset 0 par défaut
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue MIVT (§7.25)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_EXTENDED_MESSAGE_INTERRUPT_VECTOR {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let global_mask = (ctrl & 0x02) != 0;
        let table_size = ((ctrl >> 16) & 0x07FF) as u16; // 11 bits (jusqu'à 2048)

        let offset_bir = dwords[2];
        let primary_interrupter = (dwords[3] & 0x07FF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            table_size: if table_size == 0 { 1 } else { table_size },
            primary_interrupter_index: primary_interrupter,
            global_mask,
            control: ctrl,
            table_offset_bir: offset_bir,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_EXTENDED_MESSAGE_INTERRUPT_VECTOR as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (self.control & !0x07FF_0003) | (((self.table_size & 0x07FF) as u32) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.global_mask {
            ctrl |= 0x02;
        }
        let dw2 = self.table_offset_bir;
        let dw3 = (self.primary_interrupter_index & 0x07FF) as u32;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le routage d'interruption MIVT
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.control |= 0x01;
        } else {
            self.control &= !0x01;
        }
    }

    /// Active ou désactive le masque global d'interruption
    pub fn set_global_mask(&mut self, mask: bool) {
        self.global_mask = mask;
        if mask {
            self.control |= 0x02;
        } else {
            self.control &= !0x02;
        }
    }

    /// Configure l'interrupteur primaire
    pub fn set_primary_interrupter(&mut self, index: u16) {
        self.primary_interrupter_index = index & 0x07FF;
    }

    /// Retourne le Base Address Register (BIR) utilisé par la table (bits [2:0])
    pub const fn bir(&self) -> u8 {
        (self.table_offset_bir & 0x07) as u8
    }

    /// Retourne l'offset d'alignement de la table dans le BAR (bits [31:3] alignés sur 8 octets)
    pub const fn table_offset(&self) -> u32 {
        self.table_offset_bir & !0x07
    }
}

/// Capacité Étendue xHCI Extended Port Status and Control (EPSC / xHCI 1.2 §7.26)
///
/// Permet la lecture et configuration avancée des états étendus des ports USB (vitesse,
/// conformité de signalisation, mode test et contrôle de lien symétrique/asymétrique).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciExtendedPortStatusControl {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Numéro de port physique cible (1..=255)
    pub port_num: u8,
    /// Fonctionnalité de contrôle étendu activée
    pub enabled: bool,
    /// Mode test de conformité activé (Test Mode Selector)
    pub test_mode: u8,
    /// Registre de contrôle brut (DWORD 1)
    pub control: u32,
    /// Registre de statut étendu (DWORD 2)
    pub status: u32,
    /// Vitesse de lien négociée (ex: Gen 1x1, Gen 1x2, Gen 2x1, Gen 2x2)
    pub link_speed_protocol: u8,
}

impl XhciExtendedPortStatusControl {
    /// Crée une nouvelle configuration EPSC pour un port physique donné
    pub const fn new(port_num: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            port_num,
            enabled: false,
            test_mode: 0,
            control: 0,
            status: 0,
            link_speed_protocol: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue EPSC (§7.26)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_EXTENDED_PORT_STATUS_CONTROL {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let port_num = ((dwords[0] >> 16) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let test_mode = ((ctrl >> 16) & 0x0F) as u8;
        let status = dwords[2];
        let link_speed = (dwords[3] & 0x0F) as u8;

        Some(Self {
            next_ptr_dwords: next_ptr,
            port_num,
            enabled,
            test_mode,
            control: ctrl,
            status,
            link_speed_protocol: link_speed,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_EXTENDED_PORT_STATUS_CONTROL as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.port_num as u32) << 16);
        let mut ctrl = (self.control & !0x000F_0001) | (((self.test_mode & 0x0F) as u32) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        let dw2 = self.status;
        let dw3 = (self.link_speed_protocol & 0x0F) as u32;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le contrôle étendu du port
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.control |= 0x01;
        } else {
            self.control &= !0x01;
        }
    }

    /// Définit le sélecteur de mode test de conformité
    pub fn set_test_mode(&mut self, mode: u8) {
        self.test_mode = mode & 0x0F;
        self.control = (self.control & !0x000F_0000) | (((mode & 0x0F) as u32) << 16);
    }

    /// Configure la vitesse de lien négociée
    pub fn set_link_speed_protocol(&mut self, speed: u8) {
        self.link_speed_protocol = speed & 0x0F;
    }
}

/// Capacité Étendue xHCI Firmware Debug and Trace (FDT / xHCI 1.2 §7.27)
///
/// Permet l'exposition d'un canal de trace matériel et journalisation du firmware
/// interne du contrôleur xHCI (niveaux de sévérité, verbosité, masquage de sous-systèmes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciFirmwareDebugTrace {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Fonctionnalité de traçage de firmware activée
    pub enabled: bool,
    /// Niveau de sévérité de trace (0 = Panic/Fatal, 1 = Error, 2 = Warn, 3 = Info, 4 = Debug, 5 = Verbose)
    pub trace_level: u8,
    /// Masque de sous-systèmes de trace activés (bits 0..=15)
    pub subsystem_mask: u16,
    /// Registre de contrôle brut (DWORD 1)
    pub control: u32,
    /// Registre de statut / compteur de perte de trace (DWORD 2)
    pub status: u32,
    /// Taille du tampon circulaire de trace firmware en Kio (DWORD 3 [15:0])
    pub buffer_size_kb: u16,
    /// Nombre de messages de trace consignés (DWORD 3 [31:16])
    pub trace_counter: u16,
}

impl XhciFirmwareDebugTrace {
    /// Crée une nouvelle configuration Firmware Debug Trace
    pub const fn new(buffer_size_kb: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            trace_level: 1, // Error par défaut
            subsystem_mask: 0xFFFF,
            control: 0,
            status: 0,
            buffer_size_kb,
            trace_counter: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue FDT (§7.27)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_FIRMWARE_DEBUG_TRACE {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let trace_level = ((ctrl >> 8) & 0x0F) as u8;
        let subsystem_mask = ((ctrl >> 16) & 0xFFFF) as u16;
        let status = dwords[2];
        let buffer_size_kb = (dwords[3] & 0xFFFF) as u16;
        let trace_counter = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            trace_level,
            subsystem_mask,
            control: ctrl,
            status,
            buffer_size_kb,
            trace_counter,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_FIRMWARE_DEBUG_TRACE as u32) | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (self.control & !0xFFFF_0F01)
            | (((self.trace_level & 0x0F) as u32) << 8)
            | (((self.subsystem_mask as u32) & 0xFFFF) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        let dw2 = self.status;
        let dw3 = (self.buffer_size_kb as u32) | (((self.trace_counter as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le traçage du firmware
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.control |= 0x01;
        } else {
            self.control &= !0x01;
        }
    }

    /// Définit le niveau de verbosité de trace
    pub fn set_trace_level(&mut self, level: u8) {
        self.trace_level = level & 0x0F;
        self.control = (self.control & !0x0000_0F00) | (((level & 0x0F) as u32) << 8);
    }

    /// Configure le masque de sous-systèmes tracés
    pub fn set_subsystem_mask(&mut self, mask: u16) {
        self.subsystem_mask = mask;
        self.control = (self.control & !0xFFFF_0000) | (((mask as u32) & 0xFFFF) << 16);
    }
}

/// Capacité Étendue xHCI Offload Buffer Management (OBM / xHCI 1.2 §7.28)
///
/// Permet la gestion matérielle des tampons de déchargement DMA directs
/// pour les flux isochrones et flux de données audio/vidéo haute performance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciOffloadBufferManagement {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Fonctionnalité de déchargement de tampon activée
    pub enabled: bool,
    /// Nombre d'anneaux de tampons de déchargement alloués (bits 8..=15)
    pub buffer_ring_count: u8,
    /// Seuil de filigrane d'interruption DMA en Kio (bits 16..=31)
    pub watermark_threshold_kb: u16,
    /// Registre de contrôle brut (DWORD 1)
    pub control: u32,
    /// Registre d'état du moteur de déchargement (DWORD 2)
    pub status: u32,
    /// Alignement de bloc en octets (DWORD 3 [15:0])
    pub block_alignment: u16,
    /// Taille maximale de segment DMA allouable en Kio (DWORD 3 [31:16])
    pub max_segment_kb: u16,
}

impl XhciOffloadBufferManagement {
    /// Crée une nouvelle configuration Offload Buffer Management
    pub const fn new(buffer_ring_count: u8, max_segment_kb: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            buffer_ring_count,
            watermark_threshold_kb: 64,
            control: 0,
            status: 0,
            block_alignment: 4096, // Pages de 4 Kio standard
            max_segment_kb,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue OBM (§7.28)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_OFFLOAD_BUFFER_MANAGEMENT {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let buffer_ring_count = ((ctrl >> 8) & 0xFF) as u8;
        let watermark_threshold_kb = ((ctrl >> 16) & 0xFFFF) as u16;
        let status = dwords[2];
        let block_alignment = (dwords[3] & 0xFFFF) as u16;
        let max_segment_kb = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            buffer_ring_count,
            watermark_threshold_kb,
            control: ctrl,
            status,
            block_alignment,
            max_segment_kb,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 =
            (XHCI_EXT_CAP_OFFLOAD_BUFFER_MANAGEMENT as u32) | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (self.control & !0xFFFF_FF01)
            | (((self.buffer_ring_count as u32) & 0xFF) << 8)
            | (((self.watermark_threshold_kb as u32) & 0xFFFF) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        let dw2 = self.status;
        let dw3 = (self.block_alignment as u32) | (((self.max_segment_kb as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le déchargement de tampons
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        if enable {
            self.control |= 0x01;
        } else {
            self.control &= !0x01;
        }
    }

    /// Configure le seuil de filigrane d'alerte en Kio
    pub fn set_watermark_threshold(&mut self, threshold_kb: u16) {
        self.watermark_threshold_kb = threshold_kb;
        self.control = (self.control & !0xFFFF_0000) | (((threshold_kb as u32) & 0xFFFF) << 16);
    }
}

/// Capacité Étendue xHCI Host Controller System Power (HC-SP / xHCI 1.2 §7.29)
///
/// Modélise le contrôle matériel des états d'alimentation système du contrôleur d'hôte,
/// incluant le support du réveil PME (Power Management Event), les seuils de coupure
/// d'alimentation D0/D3hot/D3cold et les minuteries matérielles de réveil autonome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciHostControllerSystemPower {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Fonctionnalité de gestion fine de l'alimentation système activée (bit 0)
    pub enabled: bool,
    /// Support PME (Power Management Event) activé (bit 1)
    pub pme_enabled: bool,
    /// État d'alimentation cible (0 = D0, 1 = D1, 2 = D2, 3 = D3hot, 4 = D3cold)
    pub power_state: u8,
    /// Délai de réveil en microsecondes (bits 16..=31 de DWORD 1)
    pub wakeup_delay_us: u16,
    /// Registre d'état matériel de l'alimentation (DWORD 2)
    pub status: u32,
    /// Masque de réveil par port ou événement (DWORD 3 [15:0])
    pub wake_mask: u16,
    /// Minuterie de suspension automatique en millisecondes (DWORD 3 [31:16])
    pub auto_suspend_ms: u16,
}

impl XhciHostControllerSystemPower {
    /// Crée une nouvelle configuration Host Controller System Power
    pub const fn new(power_state: u8, wakeup_delay_us: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            pme_enabled: false,
            power_state,
            wakeup_delay_us,
            status: 0,
            wake_mask: 0x00FF,    // Ports 1..=8 autorisés au réveil par défaut
            auto_suspend_ms: 100, // 100 ms par défaut
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue HC-SP (§7.29)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_HOST_CONTROLLER_SYSTEM_POWER {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let pme_enabled = (ctrl & 0x02) != 0;
        let power_state = ((ctrl >> 8) & 0x07) as u8;
        let wakeup_delay_us = ((ctrl >> 16) & 0xFFFF) as u16;
        let status = dwords[2];
        let wake_mask = (dwords[3] & 0xFFFF) as u16;
        let auto_suspend_ms = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            pme_enabled,
            power_state,
            wakeup_delay_us,
            status,
            wake_mask,
            auto_suspend_ms,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_HOST_CONTROLLER_SYSTEM_POWER as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.power_state as u32) & 0x07) << 8)
            | (((self.wakeup_delay_us as u32) & 0xFFFF) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.pme_enabled {
            ctrl |= 0x02;
        }
        let dw2 = self.status;
        let dw3 = (self.wake_mask as u32) | (((self.auto_suspend_ms as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le sous-système d'alimentation
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive la signalisation PME
    pub fn set_pme_enabled(&mut self, enable: bool) {
        self.pme_enabled = enable;
    }

    /// Définit l'état d'alimentation matériel cible (0=D0, 3=D3hot, etc.)
    pub fn set_power_state(&mut self, state: u8) {
        self.power_state = state & 0x07;
    }

    /// Configure la minuterie de suspension automatique
    pub fn set_auto_suspend_ms(&mut self, ms: u16) {
        self.auto_suspend_ms = ms;
    }
}

/// Capacité Étendue xHCI Root Hub Topology Descriptor (RHTD / xHCI 1.2 §7.30)
///
/// Modélise la description topologique matérielle du concentrateur racine (Root Hub),
/// incluant le nombre total de ports exposés, le partitionnement USB 2.0 vs USB 3.x/USB4,
/// les masques de tiers de routage et les caractéristiques d'alimentation gérées par le contrôleur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciRootHubTopologyDescriptor {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Sous-système topologique actif et validé par le contrôleur matériel (bit 0)
    pub enabled: bool,
    /// Support du routage multi-tier USB (bit 1)
    pub multi_tier_routing: bool,
    /// Nombre de ports descendants USB 2.0 (High-Speed / Full-Speed / Low-Speed) (bits 8..=15)
    pub usb2_port_count: u8,
    /// Nombre de ports descendants USB 3.x / USB4 (SuperSpeed / SuperSpeedPlus) (bits 16..=23)
    pub usb3_port_count: u8,
    /// Registre de statut matériel de topologie (DWORD 2)
    pub status: u32,
    /// Masque de routage des ports amont/aval (DWORD 3 [15:0])
    pub routing_mask: u16,
    /// Puissance maximale par port en unités de 2 mA (DWORD 3 [31:16], ex: 250 = 500 mA, 450 = 900 mA)
    pub max_port_power_2ma: u16,
}

impl XhciRootHubTopologyDescriptor {
    /// Crée une nouvelle description topologique Root Hub
    pub const fn new(usb2_ports: u8, usb3_ports: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            multi_tier_routing: false,
            usb2_port_count: usb2_ports,
            usb3_port_count: usb3_ports,
            status: 0,
            routing_mask: 0xFFFF,
            max_port_power_2ma: 450, // 900 mA par défaut pour SuperSpeed
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue RHTD (§7.30)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_ROOT_HUB_TOPOLOGY_DESCRIPTOR {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let multi_tier_routing = (ctrl & 0x02) != 0;
        let usb2_port_count = ((ctrl >> 8) & 0xFF) as u8;
        let usb3_port_count = ((ctrl >> 16) & 0xFF) as u8;
        let status = dwords[2];
        let routing_mask = (dwords[3] & 0xFFFF) as u16;
        let max_port_power_2ma = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            multi_tier_routing,
            usb2_port_count,
            usb3_port_count,
            status,
            routing_mask,
            max_port_power_2ma,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_ROOT_HUB_TOPOLOGY_DESCRIPTOR as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.usb2_port_count as u32) & 0xFF) << 8)
            | (((self.usb3_port_count as u32) & 0xFF) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.multi_tier_routing {
            ctrl |= 0x02;
        }
        let dw2 = self.status;
        let dw3 = (self.routing_mask as u32) | (((self.max_port_power_2ma as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le décodage topologique matériel
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive le support du routage multi-tier
    pub fn set_multi_tier_routing(&mut self, enable: bool) {
        self.multi_tier_routing = enable;
    }

    /// Configure la puissance électrique maximale par port
    pub fn set_max_port_power_2ma(&mut self, power_2ma: u16) {
        self.max_port_power_2ma = power_2ma;
    }
}

/// Capacité Étendue xHCI USB4 PCIe Tunneling (§7.31 / USB4 Specification v1.0/v2.0)
///
/// Modélise la négociation matérielle d'encapsulation de paquets PCIe Gen3/Gen4 au travers
/// des routeurs de tunnellisation USB4 et xHCI hôte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4PcieTunneling {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Tunneling PCIe activé (bit 0 du registre de contrôle DWORD 1)
    pub enabled: bool,
    /// Support de l'asymétrie de bande passante USB4 (bit 1)
    pub asymmetric_bandwidth_supported: bool,
    /// Nombre d'adaptateurs PCIe tunnelisés configurés (bits 8..=15)
    pub adapter_count: u8,
    /// Vitesse de négociation PCIe (Gen1=1, Gen2=2, Gen3=3, Gen4=4) (bits 16..=19)
    pub link_speed_gen: u8,
    /// Largeur de lien PCIe négociée (x1=1, x2=2, x4=4, x8=8, x16=16) (bits 20..=24)
    pub link_width: u8,
    /// Statut matériel de tunnellisation (DWORD 2)
    pub status: u32,
    /// Bande passante allouée en amont (Mbit/s) (DWORD 3 [15:0])
    pub upstream_bandwidth_mbps: u16,
    /// Bande passante allouée en aval (Mbit/s) (DWORD 3 [31:16])
    pub downstream_bandwidth_mbps: u16,
}

impl XhciUsb4PcieTunneling {
    /// Crée une nouvelle capacité de tunnellisation PCIe USB4
    pub const fn new(adapter_count: u8, link_speed_gen: u8, link_width: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            asymmetric_bandwidth_supported: false,
            adapter_count,
            link_speed_gen,
            link_width,
            status: 0,
            upstream_bandwidth_mbps: 10000,   // 10 Gbit/s par défaut
            downstream_bandwidth_mbps: 10000, // 10 Gbit/s par défaut
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 PCIe Tunneling (§7.31)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_PCIE_TUNNELING {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let asymmetric_bandwidth_supported = (ctrl & 0x02) != 0;
        let adapter_count = ((ctrl >> 8) & 0xFF) as u8;
        let link_speed_gen = ((ctrl >> 16) & 0x0F) as u8;
        let link_width = ((ctrl >> 20) & 0x1F) as u8;
        let status = dwords[2];
        let upstream_bandwidth_mbps = (dwords[3] & 0xFFFF) as u16;
        let downstream_bandwidth_mbps = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            asymmetric_bandwidth_supported,
            adapter_count,
            link_speed_gen,
            link_width,
            status,
            upstream_bandwidth_mbps,
            downstream_bandwidth_mbps,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_PCIE_TUNNELING as u32) | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.adapter_count as u32) & 0xFF) << 8)
            | (((self.link_speed_gen as u32) & 0x0F) << 16)
            | (((self.link_width as u32) & 0x1F) << 20);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.asymmetric_bandwidth_supported {
            ctrl |= 0x02;
        }
        let dw2 = self.status;
        let dw3 = (self.upstream_bandwidth_mbps as u32)
            | (((self.downstream_bandwidth_mbps as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le tunnel PCIe
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive le support d'allocation asymétrique
    pub fn set_asymmetric_bandwidth_supported(&mut self, supported: bool) {
        self.asymmetric_bandwidth_supported = supported;
    }

    /// Configure les bandes passantes allouées (Mbit/s)
    pub fn set_bandwidth(&mut self, upstream_mbps: u16, downstream_mbps: u16) {
        self.upstream_bandwidth_mbps = upstream_mbps;
        self.downstream_bandwidth_mbps = downstream_mbps;
    }
}

/// Capacité Étendue xHCI USB4 DisplayPort Tunneling (§7.32 / USB4 & DP Alt Mode v2.1)
///
/// Modélise l'encapsulation et le transport de flux vidéo DisplayPort (SST/MST)
/// au travers de la fabrique de paquets USB4 du contrôleur xHCI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4DisplayPortTunneling {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Tunneling DisplayPort activé (bit 0 du registre de contrôle DWORD 1)
    pub enabled: bool,
    /// Support Multi-Stream Transport (MST) (bit 1)
    pub mst_supported: bool,
    /// Nombre d'adaptateurs DisplayPort OUT/IN configurés (bits 8..=15)
    pub adapter_count: u8,
    /// Taux de liaison DisplayPort (RBR=1, HBR=2, HBR2=3, HBR3=4, UHBR10=5, UHBR20=6) (bits 16..=19)
    pub dp_link_rate: u8,
    /// Nombre de voies vidéo actives (x1=1, x2=2, x4=4) (bits 20..=23)
    pub lane_count: u8,
    /// Statut matériel de la liaison DisplayPort (DWORD 2)
    pub status: u32,
    /// Bande passante vidéo allouée en Mbit/s (DWORD 3 [15:0])
    pub allocated_bandwidth_mbps: u16,
    /// Résolution maximale supportée (bpp / bits par pixel) (DWORD 3 [31:16])
    pub max_color_depth_bpp: u16,
}

impl XhciUsb4DisplayPortTunneling {
    /// Crée une nouvelle capacité de tunnellisation DisplayPort USB4
    pub const fn new(adapter_count: u8, dp_link_rate: u8, lane_count: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            mst_supported: false,
            adapter_count,
            dp_link_rate,
            lane_count,
            status: 0,
            allocated_bandwidth_mbps: 21600, // 21.6 Gbps (DP HBR3)
            max_color_depth_bpp: 30,         // 10-bit HDR (30 bpp)
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 DisplayPort Tunneling (§7.32)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_DISPLAYPORT_TUNNELING {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let mst_supported = (ctrl & 0x02) != 0;
        let adapter_count = ((ctrl >> 8) & 0xFF) as u8;
        let dp_link_rate = ((ctrl >> 16) & 0x0F) as u8;
        let lane_count = ((ctrl >> 20) & 0x0F) as u8;
        let status = dwords[2];
        let allocated_bandwidth_mbps = (dwords[3] & 0xFFFF) as u16;
        let max_color_depth_bpp = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            mst_supported,
            adapter_count,
            dp_link_rate,
            lane_count,
            status,
            allocated_bandwidth_mbps,
            max_color_depth_bpp,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 =
            (XHCI_EXT_CAP_USB4_DISPLAYPORT_TUNNELING as u32) | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.adapter_count as u32) & 0xFF) << 8)
            | (((self.dp_link_rate as u32) & 0x0F) << 16)
            | (((self.lane_count as u32) & 0x0F) << 20);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.mst_supported {
            ctrl |= 0x02;
        }
        let dw2 = self.status;
        let dw3 = (self.allocated_bandwidth_mbps as u32)
            | (((self.max_color_depth_bpp as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le tunnel DisplayPort
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive le support Multi-Stream Transport (MST)
    pub fn set_mst_supported(&mut self, supported: bool) {
        self.mst_supported = supported;
    }

    /// Configure la bande passante allouée (Mbit/s) et la profondeur de couleur
    pub fn set_display_config(&mut self, bandwidth_mbps: u16, color_depth_bpp: u16) {
        self.allocated_bandwidth_mbps = bandwidth_mbps;
        self.max_color_depth_bpp = color_depth_bpp;
    }
}

/// Capacité Étendue xHCI USB4 Host Interface Management / Inter-Domain (§7.33 / USB4 Router & D2D)
///
/// Modélise la gestion de l'interface hôte du routeur USB4 (Host Interface)
/// et les liens de communication inter-domaines (Host-to-Host / Inter-Domain networking).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4HostInterfaceManagement {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Interface hôte USB4 activée (bit 0 du registre de contrôle DWORD 1)
    pub enabled: bool,
    /// Support de communication inter-domaine activé (bit 1)
    pub interdomain_enabled: bool,
    /// Identifiant de domaine hôte local (bits 8..=15)
    pub local_domain_id: u8,
    /// Identifiant de domaine pair distant connecté (bits 16..=23)
    pub peer_domain_id: u8,
    /// Taux de liaison USB4 négocié (Gen2x1=1, Gen2x2=2, Gen3x1=3, Gen3x2=4, Gen4=5) (bits 24..=27)
    pub link_speed_gen: u8,
    /// Statut matériel de l'interface d'inter-domaine (DWORD 2)
    pub status: u32,
    /// MTU maximal des paquets réseau inter-domaine en octets (DWORD 3 [15:0])
    pub max_mtu_bytes: u16,
    /// Débit maximal de transfert inter-domaine en Mbit/s (DWORD 3 [31:16])
    pub max_bandwidth_mbps: u16,
}

impl XhciUsb4HostInterfaceManagement {
    /// Crée une nouvelle capacité de gestion d'interface hôte USB4 / Inter-Domain
    pub const fn new(local_domain_id: u8, link_speed_gen: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            interdomain_enabled: false,
            local_domain_id,
            peer_domain_id: 0,
            link_speed_gen,
            status: 0,
            max_mtu_bytes: 4096,       // MTU 4096 octets standard USB4 Net
            max_bandwidth_mbps: 40000, // 40 Gbps Gen3x2
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Host Interface Management (§7.33)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_HOST_INTERFACE_MANAGEMENT {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let interdomain_enabled = (ctrl & 0x02) != 0;
        let local_domain_id = ((ctrl >> 8) & 0xFF) as u8;
        let peer_domain_id = ((ctrl >> 16) & 0xFF) as u8;
        let link_speed_gen = ((ctrl >> 24) & 0x0F) as u8;
        let status = dwords[2];
        let max_mtu_bytes = (dwords[3] & 0xFFFF) as u16;
        let max_bandwidth_mbps = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            interdomain_enabled,
            local_domain_id,
            peer_domain_id,
            link_speed_gen,
            status,
            max_mtu_bytes,
            max_bandwidth_mbps,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_HOST_INTERFACE_MANAGEMENT as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.local_domain_id as u32) & 0xFF) << 8)
            | (((self.peer_domain_id as u32) & 0xFF) << 16)
            | (((self.link_speed_gen as u32) & 0x0F) << 24);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.interdomain_enabled {
            ctrl |= 0x02;
        }
        let dw2 = self.status;
        let dw3 = (self.max_mtu_bytes as u32) | (((self.max_bandwidth_mbps as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'interface hôte
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive la liaison inter-domaine
    pub fn set_interdomain_enabled(&mut self, enable: bool) {
        self.interdomain_enabled = enable;
    }

    /// Établit la liaison avec un domaine distant
    pub fn establish_peer_link(&mut self, peer_id: u8, mtu_bytes: u16, bandwidth_mbps: u16) {
        self.peer_domain_id = peer_id;
        self.max_mtu_bytes = mtu_bytes;
        self.max_bandwidth_mbps = bandwidth_mbps;
        self.interdomain_enabled = true;
    }
}

/// Capacité Étendue xHCI USB4 Router Configuration (§7.34 / USB4 Capability Table)
///
/// Modélise la configuration du routeur USB4 intégré au contrôleur xHCI,
/// comprenant la topologie des adaptateurs internes, le support Time Synchronization (TMU),
/// les priorités QoS et la profondeur maximale de commutation dans le réseau USB4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4RouterConfiguration {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Routeur USB4 actif et initialisé (bit 0 du registre de contrôle DWORD 1)
    pub enabled: bool,
    /// Support de l'unité de synchronisation temporelle (TMU - Time Synchronization Unit) (bit 1)
    pub tmu_supported: bool,
    /// Support de la priorisation QoS / Bandwidth Allocation (bit 2)
    pub qos_supported: bool,
    /// Nombre d'adaptateurs internes pris en charge par le routeur (bits 8..=15)
    pub max_adapters: u8,
    /// Profondeur maximale de topologie supportée (hop count / USB4 tree depth) (bits 16..=23)
    pub max_topology_depth: u8,
    /// Version de la spécification de routage USB4 supportée (bits 24..=27, ex: 1 = USB4 1.0, 2 = USB4 2.0)
    pub router_revision: u8,
    /// Statut matériel du routeur USB4 (DWORD 2)
    pub status: u32,
    /// Bande passante totale agrégée du switch en Mbit/s (DWORD 3 [15:0])
    pub total_bandwidth_gbps: u16,
    /// Nombre d'adaptateurs actuellement connectés/actifs (DWORD 3 [31:16])
    pub active_adapters: u16,
}

impl XhciUsb4RouterConfiguration {
    /// Crée une nouvelle capacité de configuration du routeur USB4
    pub const fn new(max_adapters: u8, max_topology_depth: u8, router_revision: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            tmu_supported: true,
            qos_supported: true,
            max_adapters,
            max_topology_depth,
            router_revision,
            status: 0,
            total_bandwidth_gbps: 80, // 80 Gbps agrégé standard USB4
            active_adapters: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Router Configuration (§7.34)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_ROUTER_CONFIGURATION {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let tmu_supported = (ctrl & 0x02) != 0;
        let qos_supported = (ctrl & 0x04) != 0;
        let max_adapters = ((ctrl >> 8) & 0xFF) as u8;
        let max_topology_depth = ((ctrl >> 16) & 0xFF) as u8;
        let router_revision = ((ctrl >> 24) & 0x0F) as u8;
        let status = dwords[2];
        let total_bandwidth_gbps = (dwords[3] & 0xFFFF) as u16;
        let active_adapters = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            tmu_supported,
            qos_supported,
            max_adapters,
            max_topology_depth,
            router_revision,
            status,
            total_bandwidth_gbps,
            active_adapters,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 =
            (XHCI_EXT_CAP_USB4_ROUTER_CONFIGURATION as u32) | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.max_adapters as u32) & 0xFF) << 8)
            | (((self.max_topology_depth as u32) & 0xFF) << 16)
            | (((self.router_revision as u32) & 0x0F) << 24);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.tmu_supported {
            ctrl |= 0x02;
        }
        if self.qos_supported {
            ctrl |= 0x04;
        }
        let dw2 = self.status;
        let dw3 =
            (self.total_bandwidth_gbps as u32) | (((self.active_adapters as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le routeur USB4
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Configure la connectivité des adaptateurs actifs
    pub fn update_active_topology(&mut self, active_adapters: u16, total_bw_gbps: u16) {
        self.active_adapters = active_adapters;
        self.total_bandwidth_gbps = total_bw_gbps;
    }
}

/// Capacité Étendue xHCI USB4 Time Synchronization Unit / TMU Management (§7.35 / USB4 Spec TMU)
///
/// Modélise l'unité de synchronisation temporelle (TMU) matérielle du routeur USB4,
/// permettant la distribution d'une horloge grandmaster déterministe, le calcul du temps
/// de propagation (propagation delay) entre routeurs et adaptateurs, et la synchronisation
/// temporelle sub-nanoseconde (mode High Accuracy / Low Accuracy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4TimeSyncUnit {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Unité TMU activée et synchronisée (bit 0 de TMU_CTRL DWORD 1)
    pub enabled: bool,
    /// Mode Haute Précision activé (HiFi / High Accuracy mode) (bit 1)
    pub high_accuracy_mode: bool,
    /// Rôle de l'horloge : false = Follower (esclave), true = Grandmaster (maître) (bit 2)
    pub is_grandmaster: bool,
    /// Fréquence de rafraîchissement des paquets de synchronisation temporelle (bits 8..=11, en ms)
    pub sync_interval_ms: u8,
    /// Délai de propagation moyen mesuré en nanosecondes (bits 16..=31 de DWORD 1)
    pub propagation_delay_ns: u16,
    /// Statut matériel de la synchronisation temporelle (DWORD 2)
    pub status: u32,
    /// Horloge de référence haute précision USB4 TMU (partie basse 32-bit en ns, DWORD 3)
    pub reference_time_lo: u32,
}

impl XhciUsb4TimeSyncUnit {
    /// Crée une nouvelle capacité TMU USB4
    pub const fn new(is_grandmaster: bool, sync_interval_ms: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            high_accuracy_mode: true,
            is_grandmaster,
            sync_interval_ms,
            propagation_delay_ns: 25, // 25 ns nominal pour liens internes USB4
            status: 0,
            reference_time_lo: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Time Synchronization Unit (§7.35)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_TIME_SYNCHRONIZATION_UNIT {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let high_accuracy_mode = (ctrl & 0x02) != 0;
        let is_grandmaster = (ctrl & 0x04) != 0;
        let sync_interval_ms = ((ctrl >> 8) & 0x0F) as u8;
        let propagation_delay_ns = ((ctrl >> 16) & 0xFFFF) as u16;
        let status = dwords[2];
        let reference_time_lo = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            high_accuracy_mode,
            is_grandmaster,
            sync_interval_ms,
            propagation_delay_ns,
            status,
            reference_time_lo,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_TIME_SYNCHRONIZATION_UNIT as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.sync_interval_ms as u32) & 0x0F) << 8)
            | (((self.propagation_delay_ns as u32) & 0xFFFF) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.high_accuracy_mode {
            ctrl |= 0x02;
        }
        if self.is_grandmaster {
            ctrl |= 0x04;
        }
        let dw2 = self.status;
        let dw3 = self.reference_time_lo;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'unité TMU
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Règle le délai de propagation mesuré
    pub fn update_propagation_delay(&mut self, delay_ns: u16) {
        self.propagation_delay_ns = delay_ns;
    }

    /// Met à jour l'horloge de référence
    pub fn set_reference_time(&mut self, time_lo: u32) {
        self.reference_time_lo = time_lo;
    }
}

/// Capacité Étendue xHCI USB4 Power Management and Tunneling Control (§7.36 / USB4 Specification v1.0/v2.0)
///
/// Gère la politique d'économie d'énergie (états CL0, CL1, CL2), les transitions de veille
/// et l'arbitrage dynamique d'allocation de bandes passantes pour les tunnels USB4 actifs
/// (PCIe, DisplayPort, Host-to-Host et USB3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4PowerManagementTunneling {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Contrôle d'économie d'énergie USB4 activé (PMTC_EN, bit 0 de DWORD 1)
    pub enabled: bool,
    /// Support des états de basse consommation CL0s / CL1 / CL2 (bits 1..=3 de DWORD 1)
    pub cl_states_supported: u8,
    /// Mode d'arbitrage de bande passante automatique / QoS dynamique (bit 4 de DWORD 1)
    pub dynamic_bandwidth_allocation: bool,
    /// Seuil de veille profonde en microsecondes (bits 8..=15 de DWORD 1)
    pub sleep_threshold_us: u8,
    /// Priorité de tunneling PCIe (0 = basse, 3 = temps-réel prioritaire) (bits 16..=17 de DWORD 1)
    pub pcie_tunnel_priority: u8,
    /// Priorité de tunneling DisplayPort (0 = basse, 3 = temps-réel prioritaire) (bits 18..=19 de DWORD 1)
    pub dp_tunnel_priority: u8,
    /// Priorité de tunneling USB3 (0 = basse, 3 = temps-réel prioritaire) (bits 20..=21 de DWORD 1)
    pub usb3_tunnel_priority: u8,
    /// Registre de statut matériel d'alimentation USB4 (DWORD 2)
    pub status: u32,
    /// Répartition de bande passante allouée en Gbps (PCIe [7:0], DP [15:8], USB3 [23:16], marge [31:24]) (DWORD 3)
    pub allocated_bandwidth: u32,
}

impl XhciUsb4PowerManagementTunneling {
    /// Crée une nouvelle capacité USB4 Power Management & Tunneling Control
    pub const fn new(cl_states: u8, dynamic_bw: bool) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            cl_states_supported: cl_states & 0x07,
            dynamic_bandwidth_allocation: dynamic_bw,
            sleep_threshold_us: 50,  // 50 us par défaut
            pcie_tunnel_priority: 2, // Priorité haute
            dp_tunnel_priority: 3,   // Priorité temps réel
            usb3_tunnel_priority: 1, // Priorité normale
            status: 0,
            allocated_bandwidth: 0x0A14_2800, // 40 Gbps alloué (DP: 20, PCIe: 10, USB3: 10)
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Power Management and Tunneling Control (§7.36)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_POWER_MANAGEMENT_TUNNELING {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let cl_states_supported = ((ctrl >> 1) & 0x07) as u8;
        let dynamic_bandwidth_allocation = (ctrl & 0x10) != 0;
        let sleep_threshold_us = ((ctrl >> 8) & 0xFF) as u8;
        let pcie_tunnel_priority = ((ctrl >> 16) & 0x03) as u8;
        let dp_tunnel_priority = ((ctrl >> 18) & 0x03) as u8;
        let usb3_tunnel_priority = ((ctrl >> 20) & 0x03) as u8;
        let status = dwords[2];
        let allocated_bandwidth = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            cl_states_supported,
            dynamic_bandwidth_allocation,
            sleep_threshold_us,
            pcie_tunnel_priority,
            dp_tunnel_priority,
            usb3_tunnel_priority,
            status,
            allocated_bandwidth,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_POWER_MANAGEMENT_TUNNELING as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.cl_states_supported as u32) & 0x07) << 1)
            | (((self.sleep_threshold_us as u32) & 0xFF) << 8)
            | (((self.pcie_tunnel_priority as u32) & 0x03) << 16)
            | (((self.dp_tunnel_priority as u32) & 0x03) << 18)
            | (((self.usb3_tunnel_priority as u32) & 0x03) << 20);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.dynamic_bandwidth_allocation {
            ctrl |= 0x10;
        }
        let dw2 = self.status;
        let dw3 = self.allocated_bandwidth;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le contrôle PMTC
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Configure les priorités de bande passante des tunnels USB4
    pub fn set_tunnel_priorities(&mut self, pcie: u8, dp: u8, usb3: u8) {
        self.pcie_tunnel_priority = pcie & 0x03;
        self.dp_tunnel_priority = dp & 0x03;
        self.usb3_tunnel_priority = usb3 & 0x03;
    }

    /// Règle le seuil de veille basse consommation
    pub fn set_sleep_threshold(&mut self, threshold_us: u8) {
        self.sleep_threshold_us = threshold_us;
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 DisplayPort Alternate Mode Configuration Interface (§7.37, Cap ID 45)
///
/// Permet la négociation matérielle et le routage des voies DisplayPort (DP Alt Mode)
/// sur le bus USB Type-C et les tunnels USB4 natifs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4DpAltModeConfig {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Mode DP Alt Mode activé sur le contrôleur (bit 0 de DWORD 1)
    pub enabled: bool,
    /// Nombre de voies DP physiques configurées (1, 2 ou 4 voies) (bits 1..=2 de DWORD 1)
    pub lane_count: u8,
    /// Débit par voie : 0 = RBR (1.62 Gbps), 1 = HBR (2.7 Gbps), 2 = HBR2 (5.4 Gbps), 3 = HBR3 (8.1 Gbps), 4 = UHBR10 (10 Gbps) (bits 3..=5 de DWORD 1)
    pub link_rate: u8,
    /// Support Multi-Stream Transport (MST) (bit 6 de DWORD 1)
    pub mst_supported: bool,
    /// Support High-bandwidth Digital Content Protection (HDCP 2.3) (bit 7 de DWORD 1)
    pub hdcp_supported: bool,
    /// Index du port physique Type-C / USB4 associé (bits 8..=15 de DWORD 1)
    pub physical_port_id: u8,
    /// Registre de statut du récepteur DP (DWORD 2)
    pub status: u32,
    /// Configuration des voies auxiliaires (AUX CH) et égalisation de canal (DWORD 3)
    pub aux_channel_config: u32,
}

impl XhciUsb4DpAltModeConfig {
    /// Crée une nouvelle instance de capacité DP Alt Mode
    pub const fn new(port_id: u8, lanes: u8, rate: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            lane_count: if lanes == 1 || lanes == 2 || lanes == 4 {
                lanes
            } else {
                4
            },
            link_rate: rate & 0x07,
            mst_supported: true,
            hdcp_supported: true,
            physical_port_id: port_id,
            status: 0,
            aux_channel_config: 0x0000_0101, // Voies AUX activées et configurées
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 DP Alt Mode (§7.37)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_DP_ALT_MODE_CONFIGURATION {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let lane_bits = ((ctrl >> 1) & 0x03) as u8;
        let lane_count = match lane_bits {
            0 => 1,
            1 => 2,
            _ => 4,
        };
        let link_rate = ((ctrl >> 3) & 0x07) as u8;
        let mst_supported = (ctrl & 0x40) != 0;
        let hdcp_supported = (ctrl & 0x80) != 0;
        let physical_port_id = ((ctrl >> 8) & 0xFF) as u8;
        let status = dwords[2];
        let aux_channel_config = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            lane_count,
            link_rate,
            mst_supported,
            hdcp_supported,
            physical_port_id,
            status,
            aux_channel_config,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_DP_ALT_MODE_CONFIGURATION as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let lane_bits = match self.lane_count {
            1 => 0u32,
            2 => 1u32,
            _ => 2u32,
        };
        let mut ctrl = (lane_bits << 1)
            | (((self.link_rate as u32) & 0x07) << 3)
            | (((self.physical_port_id as u32) & 0xFF) << 8);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.mst_supported {
            ctrl |= 0x40;
        }
        if self.hdcp_supported {
            ctrl |= 0x80;
        }
        let dw2 = self.status;
        let dw3 = self.aux_channel_config;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le mode DP Alt Mode
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Configure la topologie des voies DP et le taux de transfert
    pub fn configure_lanes(&mut self, lanes: u8, rate: u8) {
        self.lane_count = if lanes == 1 || lanes == 2 || lanes == 4 {
            lanes
        } else {
            4
        };
        self.link_rate = rate & 0x07;
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Security and Encryption Control Capability (§7.38)
///
/// Gère le niveau de sécurité du domaine USB4 (SL0 à SL3), l'authentification
/// matérielle cryptographique basée sur certificats et le chiffrement de lien (Link Encryption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4SecurityConfig {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Chiffrement de lien activé sur les tunnels USB4 (Bit 0)
    pub link_encryption_enabled: bool,
    /// Niveau de sécurité USB4 : 0 = SL0 (Aucun), 1 = SL1 (User Approval), 2 = SL2 (Secure Connect), 3 = SL3 (DP Only)
    pub security_level: u8,
    /// Authentification matérielle par certificat crypto requise (Bit 4)
    pub cert_auth_required: bool,
    /// Protection d'accès direct à la mémoire (DMA Guard / IOMMU protection active) (Bit 5)
    pub dma_guard_enabled: bool,
    /// Algorithme cryptographique pris en charge (0 = None, 1 = AES-128-GCM, 2 = AES-256-GCM, 3 = ChaCha20-Poly1305)
    pub crypto_cipher: u8,
    /// Identifiant du domaine ou port physique cible
    pub domain_id: u8,
    /// Registre d'état matériel de sécurité (Status Register)
    pub status: u32,
    /// Hachage / Clé de session cryptographique (Security Session Key Token 32-bit)
    pub session_token: u32,
}

impl XhciUsb4SecurityConfig {
    /// Crée une nouvelle configuration de sécurité USB4
    pub const fn new(sec_level: u8, domain_id: u8, cipher: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            link_encryption_enabled: false,
            security_level: sec_level & 0x03,
            cert_auth_required: sec_level >= 2,
            dma_guard_enabled: true,
            crypto_cipher: cipher & 0x07,
            domain_id,
            status: 0,
            session_token: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Security Configuration (§7.38)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_SECURITY_CONFIGURATION {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let link_encryption_enabled = (ctrl & 0x01) != 0;
        let security_level = ((ctrl >> 1) & 0x03) as u8;
        let cert_auth_required = (ctrl & 0x10) != 0;
        let dma_guard_enabled = (ctrl & 0x20) != 0;
        let crypto_cipher = ((ctrl >> 6) & 0x07) as u8;
        let domain_id = ((ctrl >> 16) & 0xFF) as u8;
        let status = dwords[2];
        let session_token = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            link_encryption_enabled,
            security_level,
            cert_auth_required,
            dma_guard_enabled,
            crypto_cipher,
            domain_id,
            status,
            session_token,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_SECURITY_CONFIGURATION as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = (((self.security_level as u32) & 0x03) << 1)
            | (((self.crypto_cipher as u32) & 0x07) << 6)
            | (((self.domain_id as u32) & 0xFF) << 16);
        if self.link_encryption_enabled {
            ctrl |= 0x01;
        }
        if self.cert_auth_required {
            ctrl |= 0x10;
        }
        if self.dma_guard_enabled {
            ctrl |= 0x20;
        }
        let dw2 = self.status;
        let dw3 = self.session_token;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le chiffrement de lien (Link Encryption)
    pub fn set_encryption(&mut self, enable: bool) {
        self.link_encryption_enabled = enable;
    }

    /// Configure le niveau de sécurité et la protection DMA
    pub fn set_security_level(&mut self, level: u8, dma_guard: bool) {
        self.security_level = level & 0x03;
        self.cert_auth_required = self.security_level >= 2;
        self.dma_guard_enabled = dma_guard;
    }

    /// Met à jour le jeton de session cryptographique
    pub fn set_session_token(&mut self, token: u32) {
        self.session_token = token;
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Inter-Domain Transport Interface Capability (§7.39, Cap ID 47)
///
/// Permet l'échange de paquets inter-domaines (protocoles réseau XDomain / DMA peer-to-peer)
/// entre plusieurs routeurs USB4 hôtes ou domaines de virtualisation autonomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4InterDomainTransport {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Interface de transport inter-domaine activée (bit 0)
    pub transport_enabled: bool,
    /// Prise en charge du protocole XDomain Network (bit 1)
    pub xdomain_net_supported: bool,
    /// Support de la négociation de bande passante asymétrique (bit 2)
    pub asymmetric_bw_supported: bool,
    /// Interruption sur trame de découverte inter-domaine active (bit 3)
    pub discovery_irq_enabled: bool,
    /// Identifiant de domaine distant (Peer Domain ID, bits [15:8])
    pub peer_domain_id: u8,
    /// Identifiant de routeur cible (Peer Router ID, bits [23:16])
    pub peer_router_id: u8,
    /// Index de porte de sonnette inter-domaine (Doorbell Index, bits [31:24])
    pub doorbell_index: u8,
    /// Registre de statut d'échange et de handshake (Status Dword 2)
    pub status: u32,
    /// Capacité maximale de MTU du tunnel en octets (ex: 4096 octets)
    pub max_packet_size: u16,
    /// Nombre de canaux de transport inter-domaine configurés (bits [23:16] de Dword 3)
    pub channel_count: u8,
}

impl XhciUsb4InterDomainTransport {
    /// Crée une nouvelle configuration de transport inter-domaine USB4
    pub const fn new(peer_domain_id: u8, peer_router_id: u8, max_packet_size: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            transport_enabled: false,
            xdomain_net_supported: true,
            asymmetric_bw_supported: true,
            discovery_irq_enabled: false,
            peer_domain_id,
            peer_router_id,
            doorbell_index: 0,
            status: 0,
            max_packet_size,
            channel_count: 1,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Inter-Domain Transport (§7.39)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_INTER_DOMAIN_TRANSPORT {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let transport_enabled = (ctrl & 0x01) != 0;
        let xdomain_net_supported = (ctrl & 0x02) != 0;
        let asymmetric_bw_supported = (ctrl & 0x04) != 0;
        let discovery_irq_enabled = (ctrl & 0x08) != 0;
        let peer_domain_id = ((ctrl >> 8) & 0xFF) as u8;
        let peer_router_id = ((ctrl >> 16) & 0xFF) as u8;
        let doorbell_index = ((ctrl >> 24) & 0xFF) as u8;

        let status = dwords[2];
        let dw3 = dwords[3];
        let max_packet_size = (dw3 & 0xFFFF) as u16;
        let channel_count = ((dw3 >> 16) & 0xFF) as u8;

        Some(Self {
            next_ptr_dwords: next_ptr,
            transport_enabled,
            xdomain_net_supported,
            asymmetric_bw_supported,
            discovery_irq_enabled,
            peer_domain_id,
            peer_router_id,
            doorbell_index,
            status,
            max_packet_size,
            channel_count,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_INTER_DOMAIN_TRANSPORT as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.peer_domain_id as u32) << 8)
            | ((self.peer_router_id as u32) << 16)
            | ((self.doorbell_index as u32) << 24);
        if self.transport_enabled {
            ctrl |= 0x01;
        }
        if self.xdomain_net_supported {
            ctrl |= 0x02;
        }
        if self.asymmetric_bw_supported {
            ctrl |= 0x04;
        }
        if self.discovery_irq_enabled {
            ctrl |= 0x08;
        }
        let dw2 = self.status;
        let dw3 = (self.max_packet_size as u32) | ((self.channel_count as u32) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'interface de transport inter-domaine
    pub fn set_transport_enabled(&mut self, enable: bool) {
        self.transport_enabled = enable;
    }

    /// Configure la cible d'inter-domaine (domaine distant et routeur distant)
    pub fn set_peer_target(&mut self, domain_id: u8, router_id: u8, doorbell: u8) {
        self.peer_domain_id = domain_id;
        self.peer_router_id = router_id;
        self.doorbell_index = doorbell;
    }

    /// Met à jour la taille de paquet maximale (MTU) et le nombre de canaux
    pub fn configure_channels(&mut self, max_pkt: u16, channels: u8) {
        self.max_packet_size = max_pkt;
        self.channel_count = channels;
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 PCIe Tunneling Adapter Configuration Interface (§7.40 / Cap ID 48)
///
/// Modélise le contrôle matériel fin et la négociation de chaque adaptateur PCIe tunnelisé (Downstream / Upstream)
/// au travers du routeur USB4 : routage des interruptions MSI/MSI-X virtuelles, gestion de l'état ASPM L1/L2,
/// crédits de flux de paquets TLP et politique d'allocation de liens PCIe Gen3/Gen4/Gen5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4PcieAdapterConfig {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Adaptateur PCIe activé et lié au tunnel USB4 (bit 0 de DWORD 1)
    pub adapter_enabled: bool,
    /// Support de la virtualisation d'interruptions MSI/MSI-X PCIe (bit 1)
    pub msi_virtualization_supported: bool,
    /// Gestion de l'alimentation active ASPM L1.1/L1.2 activée (bit 2)
    pub aspm_l1_enabled: bool,
    /// Filtre TLP pour la sécurité DMA PCIe activé (bit 3)
    pub tlp_filtering_enabled: bool,
    /// Numéro d'adaptateur physique PCIe dans le routeur USB4 (bits 8..=15)
    pub adapter_num: u8,
    /// Numéro de routeur USB4 hôte ou périphérique (bits 16..=23)
    pub router_id: u8,
    /// Crédits de buffer de paquets TLP disponibles (bits 24..=31)
    pub tlp_buffer_credits: u8,
    /// Registre de statut matériel PCIe Adapter (DWORD 2)
    pub status: u32,
    /// Bande passante garantie allouée en Mbit/s (DWORD 3 [15:0])
    pub guaranteed_bandwidth_mbps: u16,
    /// Débit de négociation PCIe maximal supporté (DWORD 3 [23:16] : Gen1=1, Gen2=2, Gen3=3, Gen4=4, Gen5=5)
    pub max_link_gen: u8,
    /// Largeur de lien PCIe maximale autorisée (DWORD 3 [31:24] : x1=1, x2=2, x4=4, x8=8, x16=16)
    pub max_link_width: u8,
}

impl XhciUsb4PcieAdapterConfig {
    /// Crée une nouvelle capacité USB4 PCIe Adapter Configuration (§7.40)
    pub const fn new(adapter_num: u8, router_id: u8, max_link_gen: u8, max_link_width: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            adapter_enabled: false,
            msi_virtualization_supported: true,
            aspm_l1_enabled: false,
            tlp_filtering_enabled: true,
            adapter_num,
            router_id,
            tlp_buffer_credits: 64, // 64 crédits TLP initiaux
            status: 0,
            guaranteed_bandwidth_mbps: 16000, // 16 Gbps par défaut (Gen4 x1)
            max_link_gen,
            max_link_width,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 PCIe Adapter Configuration (§7.40)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_PCIE_ADAPTER_CONFIGURATION {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let adapter_enabled = (ctrl & 0x01) != 0;
        let msi_virtualization_supported = (ctrl & 0x02) != 0;
        let aspm_l1_enabled = (ctrl & 0x04) != 0;
        let tlp_filtering_enabled = (ctrl & 0x08) != 0;
        let adapter_num = ((ctrl >> 8) & 0xFF) as u8;
        let router_id = ((ctrl >> 16) & 0xFF) as u8;
        let tlp_buffer_credits = ((ctrl >> 24) & 0xFF) as u8;

        let status = dwords[2];
        let guaranteed_bandwidth_mbps = (dwords[3] & 0xFFFF) as u16;
        let max_link_gen = ((dwords[3] >> 16) & 0xFF) as u8;
        let max_link_width = ((dwords[3] >> 24) & 0xFF) as u8;

        Some(Self {
            next_ptr_dwords: next_ptr,
            adapter_enabled,
            msi_virtualization_supported,
            aspm_l1_enabled,
            tlp_filtering_enabled,
            adapter_num,
            router_id,
            tlp_buffer_credits,
            status,
            guaranteed_bandwidth_mbps,
            max_link_gen,
            max_link_width,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_PCIE_ADAPTER_CONFIGURATION as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.adapter_num as u32) << 8)
            | ((self.router_id as u32) << 16)
            | ((self.tlp_buffer_credits as u32) << 24);
        if self.adapter_enabled {
            ctrl |= 0x01;
        }
        if self.msi_virtualization_supported {
            ctrl |= 0x02;
        }
        if self.aspm_l1_enabled {
            ctrl |= 0x04;
        }
        if self.tlp_filtering_enabled {
            ctrl |= 0x08;
        }
        let dw2 = self.status;
        let dw3 = (self.guaranteed_bandwidth_mbps as u32)
            | (((self.max_link_gen as u32) & 0xFF) << 16)
            | (((self.max_link_width as u32) & 0xFF) << 24);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'adaptateur PCIe tunnelisé
    pub fn set_adapter_enabled(&mut self, enable: bool) {
        self.adapter_enabled = enable;
    }

    /// Active ou désactive l'état d'économie d'énergie ASPM L1
    pub fn set_aspm_l1_enabled(&mut self, enable: bool) {
        self.aspm_l1_enabled = enable;
    }

    /// Configure la bande passante garantie et le crédit de paquets TLP
    pub fn configure_bandwidth_credits(&mut self, bw_mbps: u16, credits: u8) {
        self.guaranteed_bandwidth_mbps = bw_mbps;
        self.tlp_buffer_credits = credits;
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 DisplayPort Adapter Configuration (§7.41, Cap ID 49)
///
/// Contrôle les adaptateurs DisplayPort (IN / OUT) tunnelisés à travers les routeurs USB4 :
/// - Négociation de débit DP (RBR 1.62 Gbps, HBR 2.7 Gbps, HBR2 5.4 Gbps, HBR3 8.1 Gbps, UHBR10/13.5/20 Gbps)
/// - Gestion de flux vidéo MST (Multi-Stream Transport) et cryptage HDCP 2.2 / 2.3
/// - Allocation dynamique de bande passante vidéo et canal auxiliaire DP AUX tunnelisé
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4DpAdapterConfig {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Adaptateur vidéo DP activé (bit 0)
    pub adapter_enabled: bool,
    /// Support Multi-Stream Transport (MST) actif (bit 1)
    pub mst_supported: bool,
    /// Tunneling du canal auxiliaire DP AUX activé (bit 2)
    pub dp_aux_tunneling_enabled: bool,
    /// Protection de contenu HDCP 2.2/2.3 activée (bit 3)
    pub hdcp_enabled: bool,
    /// Adaptateur est une source (DP IN) ou un récepteur (DP OUT) : true = DP IN, false = DP OUT (bit 4)
    pub is_dp_in_adapter: bool,
    /// Numéro d'adaptateur DP physique dans le routeur USB4 (bits 8..=15)
    pub adapter_num: u8,
    /// Numéro de routeur USB4 hébergeant l'adaptateur (bits 16..=23)
    pub router_id: u8,
    /// Nombre de lanes physiques DP allouées (1, 2 ou 4) (bits 24..=31)
    pub lane_count: u8,
    /// Registre de statut matériel et d'état du lien DP (DWORD 2)
    pub status: u32,
    /// Bande passante vidéo allouée en Mbit/s (DWORD 3 [15:0])
    pub video_bandwidth_mbps: u16,
    /// Débit de lien DisplayPort négocié : 1=RBR, 2=HBR, 3=HBR2, 4=HBR3, 5=UHBR10, 6=UHBR20 (DWORD 3 [23:16])
    pub max_link_rate: u8,
    /// Profondeur de couleur maximale en bits par composante : 6, 8, 10, 12, 16 bpc (DWORD 3 [31:24])
    pub color_depth_bpc: u8,
}

impl XhciUsb4DpAdapterConfig {
    /// Crée une nouvelle capacité USB4 DisplayPort Adapter Configuration (§7.41)
    pub const fn new(
        adapter_num: u8,
        router_id: u8,
        is_dp_in: bool,
        lane_count: u8,
        max_link_rate: u8,
    ) -> Self {
        Self {
            next_ptr_dwords: 0,
            adapter_enabled: false,
            mst_supported: true,
            dp_aux_tunneling_enabled: true,
            hdcp_enabled: false,
            is_dp_in_adapter: is_dp_in,
            adapter_num,
            router_id,
            lane_count,
            status: 0,
            video_bandwidth_mbps: 21600, // 21.6 Gbps (HBR2 x4) par défaut
            max_link_rate,
            color_depth_bpc: 8, // 8-bit par canal par défaut
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 DisplayPort Adapter Configuration (§7.41)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_DP_ADAPTER_CONFIGURATION {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let adapter_enabled = (ctrl & 0x01) != 0;
        let mst_supported = (ctrl & 0x02) != 0;
        let dp_aux_tunneling_enabled = (ctrl & 0x04) != 0;
        let hdcp_enabled = (ctrl & 0x08) != 0;
        let is_dp_in_adapter = (ctrl & 0x10) != 0;
        let adapter_num = ((ctrl >> 8) & 0xFF) as u8;
        let router_id = ((ctrl >> 16) & 0xFF) as u8;
        let lane_count = ((ctrl >> 24) & 0xFF) as u8;

        let status = dwords[2];
        let video_bandwidth_mbps = (dwords[3] & 0xFFFF) as u16;
        let max_link_rate = ((dwords[3] >> 16) & 0xFF) as u8;
        let color_depth_bpc = ((dwords[3] >> 24) & 0xFF) as u8;

        Some(Self {
            next_ptr_dwords: next_ptr,
            adapter_enabled,
            mst_supported,
            dp_aux_tunneling_enabled,
            hdcp_enabled,
            is_dp_in_adapter,
            adapter_num,
            router_id,
            lane_count,
            status,
            video_bandwidth_mbps,
            max_link_rate,
            color_depth_bpc,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_DP_ADAPTER_CONFIGURATION as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.adapter_num as u32) << 8)
            | ((self.router_id as u32) << 16)
            | ((self.lane_count as u32) << 24);
        if self.adapter_enabled {
            ctrl |= 0x01;
        }
        if self.mst_supported {
            ctrl |= 0x02;
        }
        if self.dp_aux_tunneling_enabled {
            ctrl |= 0x04;
        }
        if self.hdcp_enabled {
            ctrl |= 0x08;
        }
        if self.is_dp_in_adapter {
            ctrl |= 0x10;
        }
        let dw2 = self.status;
        let dw3 = (self.video_bandwidth_mbps as u32)
            | (((self.max_link_rate as u32) & 0xFF) << 16)
            | (((self.color_depth_bpc as u32) & 0xFF) << 24);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'adaptateur DisplayPort
    pub fn set_adapter_enabled(&mut self, enable: bool) {
        self.adapter_enabled = enable;
    }

    /// Active ou désactive la protection HDCP
    pub fn set_hdcp_enabled(&mut self, enable: bool) {
        self.hdcp_enabled = enable;
    }

    /// Configure la bande passante vidéo et la profondeur de couleur
    pub fn configure_video_stream(&mut self, bw_mbps: u16, bpc: u8) {
        self.video_bandwidth_mbps = bw_mbps;
        self.color_depth_bpc = bpc;
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Buffer Allocation Interface Capability (§7.42)
///
/// Gère l'allocation déterministe des mémoires tampons de transmission/réception (Tx/Rx FIFOs),
/// la politique de contrôle de flux par crédit (Credit-based Flow Control) et les crédits d'adaptateurs USB4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4BufferAllocation {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Interface d'allocation de tampons activée (bit 0)
    pub enabled: bool,
    /// Contrôle de flux par crédit activé (Credit-based Flow Control) (bit 1)
    pub credit_flow_control: bool,
    /// Mode d'allocation dynamique automatique activé par le contrôleur (bit 2)
    pub dynamic_allocation: bool,
    /// Alerte de seuil de sous-remplissage ou saturation (bit 3)
    pub threshold_alert: bool,
    /// Numéro d'adaptateur USB4 cible (bits 8..=15)
    pub adapter_num: u8,
    /// Numéro de routeur USB4 associé (bits 16..=23)
    pub router_id: u8,
    /// Type de trafic de la mémoire tampon : 0=Control/Config, 1=PCIe Tunnel, 2=DP Tunnel, 3=Host/InterDomain (bits 24..=31)
    pub traffic_class: u8,
    /// Registre de statut matériel et d'erreur de tampons (DWORD 2)
    pub status: u32,
    /// Nombre total de crédits de tampons alloués pour la transmission (Tx Credits) (DWORD 3 [15:0])
    pub tx_credits_allocated: u16,
    /// Nombre total de crédits de tampons alloués pour la réception (Rx Credits) (DWORD 3 [31:16])
    pub rx_credits_allocated: u16,
}

impl XhciUsb4BufferAllocation {
    /// Crée une nouvelle capacité USB4 Buffer Allocation Interface (§7.42)
    pub const fn new(
        adapter_num: u8,
        router_id: u8,
        traffic_class: u8,
        tx_credits: u16,
        rx_credits: u16,
    ) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            credit_flow_control: true,
            dynamic_allocation: false,
            threshold_alert: false,
            adapter_num,
            router_id,
            traffic_class,
            status: 0,
            tx_credits_allocated: tx_credits,
            rx_credits_allocated: rx_credits,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Buffer Allocation Interface (§7.42)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_BUFFER_ALLOCATION_INTERFACE {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let credit_flow_control = (ctrl & 0x02) != 0;
        let dynamic_allocation = (ctrl & 0x04) != 0;
        let threshold_alert = (ctrl & 0x08) != 0;
        let adapter_num = ((ctrl >> 8) & 0xFF) as u8;
        let router_id = ((ctrl >> 16) & 0xFF) as u8;
        let traffic_class = ((ctrl >> 24) & 0xFF) as u8;

        let status = dwords[2];
        let tx_credits = (dwords[3] & 0xFFFF) as u16;
        let rx_credits = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            credit_flow_control,
            dynamic_allocation,
            threshold_alert,
            adapter_num,
            router_id,
            traffic_class,
            status,
            tx_credits_allocated: tx_credits,
            rx_credits_allocated: rx_credits,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_BUFFER_ALLOCATION_INTERFACE as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.adapter_num as u32) << 8)
            | ((self.router_id as u32) << 16)
            | ((self.traffic_class as u32) << 24);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.credit_flow_control {
            ctrl |= 0x02;
        }
        if self.dynamic_allocation {
            ctrl |= 0x04;
        }
        if self.threshold_alert {
            ctrl |= 0x08;
        }
        let dw2 = self.status;
        let dw3 = (self.tx_credits_allocated as u32)
            | (((self.rx_credits_allocated as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'allocation de tampons
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Ajuste les crédits alloués en transmission et réception
    pub fn update_credits(&mut self, tx: u16, rx: u16) {
        self.tx_credits_allocated = tx;
        self.rx_credits_allocated = rx;
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Optical Interface Management (§7.43)
///
/// Contrôle et télémétrie des interfaces physiques optiques actives (Active Optical Cable - AOC)
/// pour les liaisons montantes et descendantes USB4 haut débit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4OpticalInterface {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Interface optique activée
    pub enabled: bool,
    /// Émetteur laser / optique actif
    pub laser_enabled: bool,
    /// Surveillance de faible puissance optique (Low Optical Power Alert)
    pub low_power_alert: bool,
    /// Détection de perte de signal (Loss of Signal - LOS)
    pub loss_of_signal: bool,
    /// Numéro d'adaptateur physique USB4
    pub adapter_num: u8,
    /// Identifiant du routeur USB4
    pub router_id: u8,
    /// Longueur d'onde optique nominale en nanomètres (ex: 850 nm, 1310 nm)
    pub wavelength_nm: u16,
    /// Statut matériel MMIO
    pub status: u32,
    /// Puissance optique reçue (RSSI) en microwatts (uW)
    pub rx_power_uw: u16,
    /// Puissance optique transmise en microwatts (uW)
    pub tx_power_uw: u16,
}

impl XhciUsb4OpticalInterface {
    /// Initialise une nouvelle capacité USB4 Optical Interface Management
    pub const fn new(
        adapter_num: u8,
        router_id: u8,
        wavelength_nm: u16,
        tx_power: u16,
        rx_power: u16,
    ) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            laser_enabled: false,
            low_power_alert: false,
            loss_of_signal: false,
            adapter_num,
            router_id,
            wavelength_nm,
            status: 0,
            rx_power_uw: rx_power,
            tx_power_uw: tx_power,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Optical Interface Management (§7.43)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_OPTICAL_INTERFACE_MANAGEMENT {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let laser_enabled = (ctrl & 0x02) != 0;
        let low_power_alert = (ctrl & 0x04) != 0;
        let loss_of_signal = (ctrl & 0x08) != 0;
        let adapter_num = ((ctrl >> 8) & 0xFF) as u8;
        let router_id = ((ctrl >> 16) & 0xFF) as u8;
        let wavelength_nm = ((ctrl >> 24) & 0xFF) as u16 * 10; // multiple de 10 nm

        let status = dwords[2];
        let tx_power = (dwords[3] & 0xFFFF) as u16;
        let rx_power = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            laser_enabled,
            low_power_alert,
            loss_of_signal,
            adapter_num,
            router_id,
            wavelength_nm,
            status,
            rx_power_uw: rx_power,
            tx_power_uw: tx_power,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_OPTICAL_INTERFACE_MANAGEMENT as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.adapter_num as u32) << 8)
            | ((self.router_id as u32) << 16)
            | ((((self.wavelength_nm / 10) as u32) & 0xFF) << 24);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.laser_enabled {
            ctrl |= 0x02;
        }
        if self.low_power_alert {
            ctrl |= 0x04;
        }
        if self.loss_of_signal {
            ctrl |= 0x08;
        }
        let dw2 = self.status;
        let dw3 = (self.tx_power_uw as u32) | (((self.rx_power_uw as u32) & 0xFFFF) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active l'interface optique et l'émetteur laser
    pub fn enable_optics(&mut self, enable: bool) {
        self.enabled = enable;
        self.laser_enabled = enable;
    }

    /// Met à jour la télémétrie de puissance optique
    pub fn update_power(&mut self, tx_uw: u16, rx_uw: u16) {
        self.tx_power_uw = tx_uw;
        self.rx_power_uw = rx_uw;
        self.low_power_alert = rx_uw < 50; // Alerte si < 50 uW
        self.loss_of_signal = rx_uw == 0;
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Inter-Domain DMA Transport Capability (§7.44)
///
/// Gère le canal DMA asynchrone haut débit pour le transfert de paquets inter-domaines
/// entre routeurs hôtes USB4 / Thunderbolt sans passer par l'émulation réseau logiciel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4InterDomainDma {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Canal DMA inter-domaine activé
    pub enabled: bool,
    /// Mode interruption / MSI activé pour les transferts DMA terminés
    pub irq_enabled: bool,
    /// Annonce de conformité protocolaire USB4 DMA v2
    pub dma_v2_support: bool,
    /// Pointeur d'anneau circulaire de descripteurs DMA (Ring ID 0..15)
    pub ring_id: u8,
    /// Identifiant de domaine distant connecté (Domain UUID / Router ID)
    pub peer_domain_id: u8,
    /// Taille maximale du paquet DMA MTU en octets (ex: 4096)
    pub max_packet_size: u16,
    /// Registre d'état du moteur DMA (bits statut matériel)
    pub status: u32,
    /// Nombre de descripteurs de paquets en file d'attente (depth)
    pub ring_depth: u16,
    /// Nombre de transferts DMA acquittés avec succès
    pub tx_completed_count: u16,
}

impl XhciUsb4InterDomainDma {
    /// Initialise une nouvelle capacité USB4 Inter-Domain DMA
    pub const fn new(ring_id: u8, peer_domain_id: u8, max_packet_size: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            irq_enabled: false,
            dma_v2_support: true,
            ring_id,
            peer_domain_id,
            max_packet_size,
            status: 0,
            ring_depth: 64,
            tx_completed_count: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Inter-Domain DMA (§7.44)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_INTER_DOMAIN_DMA {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let irq_enabled = (ctrl & 0x02) != 0;
        let dma_v2_support = (ctrl & 0x04) != 0;
        let ring_id = ((ctrl >> 8) & 0x0F) as u8;
        let peer_domain_id = ((ctrl >> 16) & 0xFF) as u8;
        let max_packet_size = ((ctrl >> 24) & 0xFF) as u16 * 64; // granules de 64 octets (jusqu'à 16320 octets)

        let status = dwords[2];
        let ring_depth = (dwords[3] & 0xFFFF) as u16;
        let tx_completed_count = ((dwords[3] >> 16) & 0xFFFF) as u16;

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            irq_enabled,
            dma_v2_support,
            ring_id,
            peer_domain_id,
            max_packet_size,
            status,
            ring_depth,
            tx_completed_count,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 =
            (XHCI_EXT_CAP_USB4_INTER_DOMAIN_DMA as u32) | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.ring_id as u32 & 0x0F) << 8)
            | ((self.peer_domain_id as u32 & 0xFF) << 16)
            | ((((self.max_packet_size / 64) as u32) & 0xFF) << 24);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.irq_enabled {
            ctrl |= 0x02;
        }
        if self.dma_v2_support {
            ctrl |= 0x04;
        }
        let dw2 = self.status;
        let dw3 = (self.ring_depth as u32) | ((self.tx_completed_count as u32) << 16);
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le moteur DMA inter-domaine
    pub fn enable_dma(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Configure l'interruption MSI et notifie le contrôleur hôte
    pub fn configure_irq(&mut self, enable: bool) {
        self.irq_enabled = enable;
    }

    /// Simule un transfert DMA de descripteur terminé
    pub fn record_tx_completion(&mut self) {
        self.tx_completed_count = self.tx_completed_count.wrapping_add(1);
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Router Operations and Configuration Interface (§7.45)
///
/// Supervise la topologie du routeur USB4 local, le contrôle d'énergie des liens haut débit,
/// les notifications d'événements de déconnexion/reconnexion à chaud et la gestion du domaine CM (Connection Manager).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4RouterOperations {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Interface de configuration du routeur activée
    pub enabled: bool,
    /// Mode interruption / notification asynchrone activé (Hot-Plug & Link Event IRQ)
    pub irq_enabled: bool,
    /// Indique si ce contrôleur agit en tant que Connection Manager (CM) maître
    pub connection_manager_active: bool,
    /// Identifiant unique du routeur USB4 (0..=63)
    pub router_id: u8,
    /// Nombre total de ports de tunneling exposés par ce routeur (ex: 8)
    pub num_tunneling_adapters: u8,
    /// État d'énergie du routeur (0: D0 normal, 1: D1 veille légère, 2: D2 veille profonde, 3: D3 éteint)
    pub power_state: u8,
    /// Registre d'état matériel du routeur
    pub status: u32,
    /// Compteur d'événements de lien traités (plug, unplug, renegotiation)
    pub event_counter: u32,
}

impl XhciUsb4RouterOperations {
    /// Initialise une nouvelle capacité USB4 Router Operations
    pub const fn new(router_id: u8, num_tunneling_adapters: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            irq_enabled: false,
            connection_manager_active: true,
            router_id,
            num_tunneling_adapters,
            power_state: 0, // D0
            status: 0,
            event_counter: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Router Operations (§7.45)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_ROUTER_OPERATIONS {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let irq_enabled = (ctrl & 0x02) != 0;
        let connection_manager_active = (ctrl & 0x04) != 0;
        let router_id = ((ctrl >> 8) & 0x3F) as u8;
        let num_tunneling_adapters = ((ctrl >> 16) & 0xFF) as u8;
        let power_state = ((ctrl >> 24) & 0x03) as u8;

        let status = dwords[2];
        let event_counter = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            irq_enabled,
            connection_manager_active,
            router_id,
            num_tunneling_adapters,
            power_state,
            status,
            event_counter,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 =
            (XHCI_EXT_CAP_USB4_ROUTER_OPERATIONS as u32) | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.router_id as u32 & 0x3F) << 8)
            | ((self.num_tunneling_adapters as u32 & 0xFF) << 16)
            | ((self.power_state as u32 & 0x03) << 24);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.irq_enabled {
            ctrl |= 0x02;
        }
        if self.connection_manager_active {
            ctrl |= 0x04;
        }
        let dw2 = self.status;
        let dw3 = self.event_counter;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le module d'opérations du routeur
    pub fn enable_router(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive les interruptions matérielles du routeur
    pub fn configure_irq(&mut self, enable: bool) {
        self.irq_enabled = enable;
    }

    /// Définit le niveau d'énergie (D0..D3)
    pub fn set_power_state(&mut self, pstate: u8) {
        self.power_state = pstate & 0x03;
    }

    /// Incrémente le compteur d'événements du routeur
    pub fn record_event(&mut self) {
        self.event_counter = self.event_counter.wrapping_add(1);
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Protocol Tunneling Statistics Interface (§7.46)
///
/// Modélise les métriques de trafic et compteurs de paquets tunnelisés
/// (PCIe, DP, USB3, D2D DMA) pour l'observabilité matérielle et la télémétrie réseau USB4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4ProtocolTunnelingStats {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Collecte des statistiques activée
    pub enabled: bool,
    /// Interruption de seuil de trafic activée
    pub irq_enabled: bool,
    /// Identifiant de l'adaptateur de tunneling supervisé (0..=63)
    pub adapter_id: u8,
    /// Type de protocole supervisé (1: PCIe, 2: DisplayPort, 3: USB3, 4: Inter-Domain)
    pub protocol_type: u8,
    /// Compteur 32-bit de paquets tunnelisés transmis avec succès
    pub tx_packet_count: u32,
    /// Compteur 32-bit de paquets tunnelisés reçus avec succès
    pub rx_packet_count: u32,
}

impl XhciUsb4ProtocolTunnelingStats {
    /// Initialise une nouvelle capacité USB4 Protocol Tunneling Statistics
    pub const fn new(adapter_id: u8, protocol_type: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            irq_enabled: false,
            adapter_id,
            protocol_type: protocol_type & 0x07,
            tx_packet_count: 0,
            rx_packet_count: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Protocol Tunneling Statistics (§7.46)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_PROTOCOL_TUNNELING_STATS {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let irq_enabled = (ctrl & 0x02) != 0;
        let adapter_id = ((ctrl >> 8) & 0x3F) as u8;
        let protocol_type = ((ctrl >> 16) & 0x07) as u8;

        let tx_packet_count = dwords[2];
        let rx_packet_count = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            irq_enabled,
            adapter_id,
            protocol_type,
            tx_packet_count,
            rx_packet_count,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_PROTOCOL_TUNNELING_STATS as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl =
            ((self.adapter_id as u32 & 0x3F) << 8) | ((self.protocol_type as u32 & 0x07) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.irq_enabled {
            ctrl |= 0x02;
        }
        let dw2 = self.tx_packet_count;
        let dw3 = self.rx_packet_count;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive la collecte des statistiques
    pub fn enable_stats(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive les interruptions de seuil
    pub fn configure_irq(&mut self, enable: bool) {
        self.irq_enabled = enable;
    }

    /// Enregistre la transmission d'un paquet
    pub fn record_tx(&mut self) {
        self.tx_packet_count = self.tx_packet_count.wrapping_add(1);
    }

    /// Enregistre la réception d'un paquet
    pub fn record_rx(&mut self) {
        self.rx_packet_count = self.rx_packet_count.wrapping_add(1);
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Host-to-Host Packet Tunneling Interface (§7.47)
///
/// Modélise l'interface matérielle de tunnelisation directe de paquets inter-hôtes (H2H)
/// sans passer par le contrôleur PCIe hôte complet, optimisant les transferts D2D et réseaux virtuels USB4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4HostToHostPacketTunneling {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Tunneling actif
    pub enabled: bool,
    /// Interruption de complétion de trame H2H activée
    pub irq_enabled: bool,
    /// Identifiant de l'adaptateur cible distant (0..=63)
    pub target_adapter_id: u8,
    /// Identifiant du domaine virtuel hôte local (0..=15)
    pub local_domain_id: u8,
    /// Taille maximale du paquet tunnelisé en octets (MTU : 256 à 4096 octets)
    pub max_packet_size: u16,
    /// Compteur 32-bit de trames tunnelisées H2H émises
    pub tx_frame_count: u32,
    /// Compteur 32-bit de trames tunnelisées H2H reçues
    pub rx_frame_count: u32,
}

impl XhciUsb4HostToHostPacketTunneling {
    /// Initialise une nouvelle capacité USB4 Host-to-Host Packet Tunneling
    pub const fn new(target_adapter_id: u8, local_domain_id: u8, max_packet_size: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            irq_enabled: false,
            target_adapter_id: target_adapter_id & 0x3F,
            local_domain_id: local_domain_id & 0x0F,
            max_packet_size,
            tx_frame_count: 0,
            rx_frame_count: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Host-to-Host Packet Tunneling (§7.47)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_HOST_TO_HOST_PACKET_TUNNELING {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let irq_enabled = (ctrl & 0x02) != 0;
        let target_adapter_id = ((ctrl >> 8) & 0x3F) as u8;
        let local_domain_id = ((ctrl >> 16) & 0x0F) as u8;
        let max_packet_size = (ctrl >> 20) as u16;

        let tx_frame_count = dwords[2];
        let rx_frame_count = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            irq_enabled,
            target_adapter_id,
            local_domain_id,
            max_packet_size,
            tx_frame_count,
            rx_frame_count,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_HOST_TO_HOST_PACKET_TUNNELING as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.target_adapter_id as u32 & 0x3F) << 8)
            | ((self.local_domain_id as u32 & 0x0F) << 16)
            | ((self.max_packet_size as u32) << 20);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.irq_enabled {
            ctrl |= 0x02;
        }
        let dw2 = self.tx_frame_count;
        let dw3 = self.rx_frame_count;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le tunneling de paquets Host-to-Host
    pub fn enable_tunneling(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive les interruptions H2H
    pub fn configure_irq(&mut self, enable: bool) {
        self.irq_enabled = enable;
    }

    /// Transmet une trame H2H
    pub fn transmit_frame(&mut self) {
        self.tx_frame_count = self.tx_frame_count.wrapping_add(1);
    }

    /// Réceptionne une trame H2H
    pub fn receive_frame(&mut self) {
        self.rx_frame_count = self.rx_frame_count.wrapping_add(1);
    }
}

/// Capacité Étendue xHCI USB4 Host Interface Discovery and Notification Capability (§7.48 / Cap ID 56)
///
/// Permet la découverte dynamique des interfaces de contrôle hôte USB4 et la notification
/// asynchrone des événements de topologie inter-domaines et des changements de configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4HostInterfaceDiscovery {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Découverte hôte activée
    pub enabled: bool,
    /// Interruptions matérielles sur événement de découverte activées
    pub irq_enabled: bool,
    /// Identifiant de version du protocole de découverte (1 = USB4 v1, 2 = USB4 v2)
    pub protocol_version: u8,
    /// Nombre d'interfaces hôtes découvertes
    pub discovered_interfaces: u8,
    /// Masque de notification d'événements de topologie
    pub notification_mask: u16,
    /// Compteur total d'événements de notification reçus
    pub notification_counter: u32,
    /// Registre de statut d'interface de découverte
    pub discovery_status: u32,
}

impl XhciUsb4HostInterfaceDiscovery {
    /// Crée une nouvelle instance de découverte d'interface hôte USB4
    pub const fn new(protocol_version: u8, notification_mask: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            irq_enabled: false,
            protocol_version: protocol_version & 0x0F,
            discovered_interfaces: 0,
            notification_mask,
            notification_counter: 0,
            discovery_status: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Host Interface Discovery (§7.48)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_HOST_INTERFACE_DISCOVERY {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let irq_enabled = (ctrl & 0x02) != 0;
        let protocol_version = ((ctrl >> 8) & 0x0F) as u8;
        let discovered_interfaces = ((ctrl >> 16) & 0xFF) as u8;
        let notification_mask = (ctrl >> 24) as u16 | (((dwords[0] >> 16) & 0xFF) << 8) as u16;

        let notification_counter = dwords[2];
        let discovery_status = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            irq_enabled,
            protocol_version,
            discovered_interfaces,
            notification_mask,
            notification_counter,
            discovery_status,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_HOST_INTERFACE_DISCOVERY as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | (((self.notification_mask >> 8) as u32 & 0xFF) << 16);
        let mut ctrl = ((self.protocol_version as u32 & 0x0F) << 8)
            | ((self.discovered_interfaces as u32 & 0xFF) << 16)
            | (((self.notification_mask & 0xFF) as u32) << 24);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.irq_enabled {
            ctrl |= 0x02;
        }
        let dw2 = self.notification_counter;
        let dw3 = self.discovery_status;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'interface de découverte
    pub fn enable_discovery(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive les interruptions matérielles
    pub fn configure_irq(&mut self, enable: bool) {
        self.irq_enabled = enable;
    }

    /// Enregistre une interface hôte découverte
    pub fn register_interface(&mut self) {
        self.discovered_interfaces = self.discovered_interfaces.saturating_add(1);
    }

    /// Incrémente le compteur de notifications
    pub fn record_notification(&mut self) {
        self.notification_counter = self.notification_counter.wrapping_add(1);
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 Sleep and Wake Notification Capability (§7.49)
///
/// Permet la gestion déterministe et le dispatch des notifications d'entrée en veille (Sleep/Low-Power State)
/// et de réveil (Wake Event) des domaines et adaptateurs du routeur USB4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4SleepWakeNotification {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Fonctionnalité activée dans le contrôleur (bit 0)
    pub enabled: bool,
    /// Génération d'interruptions d'événement de réveil / veille activée (bit 1)
    pub irq_enabled: bool,
    /// Prise en charge du réveil à distance (Remote Wake Capability, bit 2)
    pub remote_wake_supported: bool,
    /// Réveil à distance activé (Remote Wake Enabled, bit 3)
    pub remote_wake_enabled: bool,
    /// Niveau d'état de veille cible (Target Sleep State : 0=Active, 1=Sleep-1, 2=Sleep-2, 3=Deep-Sleep)
    pub target_sleep_state: u8,
    /// Masque de sources de réveil autorisées (Adaptateurs PCIe, DP, Host, USB3)
    pub wake_source_mask: u16,
    /// Compteur d'événements de réveil reçus (Wake Event Counter)
    pub wake_event_counter: u32,
    /// Registre de statut d'alimentation USB4 / notification de veille
    pub power_status: u32,
}

impl XhciUsb4SleepWakeNotification {
    /// Crée une nouvelle configuration de notification Sleep/Wake USB4
    pub const fn new(target_sleep_state: u8, wake_source_mask: u16) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            irq_enabled: false,
            remote_wake_supported: true,
            remote_wake_enabled: false,
            target_sleep_state: target_sleep_state & 0x07,
            wake_source_mask,
            wake_event_counter: 0,
            power_status: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 Sleep and Wake Notification (§7.49)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_SLEEP_WAKE_NOTIFICATION {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let irq_enabled = (ctrl & 0x02) != 0;
        let remote_wake_supported = (ctrl & 0x04) != 0;
        let remote_wake_enabled = (ctrl & 0x08) != 0;
        let target_sleep_state = ((ctrl >> 8) & 0x07) as u8;
        let wake_source_mask = (ctrl >> 16) as u16;

        let wake_event_counter = dwords[2];
        let power_status = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            irq_enabled,
            remote_wake_supported,
            remote_wake_enabled,
            target_sleep_state,
            wake_source_mask,
            wake_event_counter,
            power_status,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_SLEEP_WAKE_NOTIFICATION as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl =
            ((self.target_sleep_state as u32 & 0x07) << 8) | ((self.wake_source_mask as u32) << 16);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.irq_enabled {
            ctrl |= 0x02;
        }
        if self.remote_wake_supported {
            ctrl |= 0x04;
        }
        if self.remote_wake_enabled {
            ctrl |= 0x08;
        }
        let dw2 = self.wake_event_counter;
        let dw3 = self.power_status;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive le sous-système de notification Sleep/Wake
    pub fn enable(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive les interruptions matérielles sur événement Sleep/Wake
    pub fn configure_irq(&mut self, enable: bool) {
        self.irq_enabled = enable;
    }

    /// Configure l'état de réveil à distance
    pub fn configure_remote_wake(&mut self, enable: bool) {
        self.remote_wake_enabled = enable;
    }

    /// Définit l'état de veille cible
    pub fn set_target_sleep_state(&mut self, state: u8) {
        self.target_sleep_state = state & 0x07;
    }

    /// Incrémente le compteur d'événements de réveil reçus
    pub fn record_wake_event(&mut self) {
        self.wake_event_counter = self.wake_event_counter.wrapping_add(1);
    }
}

/// Capacité Étendue xHCI 1.2 / USB4 PCIe Adapter Configuration Interface (§7.50)
///
/// Permet la gestion déterministe et le contrôle direct des registres de configuration
/// des adaptateurs PCIe (PCIe Adapters) intégrés dans les routeurs USB4 hôtes et cibles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4PcieAdapterConfigInterface {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Fonctionnalité activée dans le contrôleur (bit 0)
    pub enabled: bool,
    /// Génération d'interruptions d'événement d'adaptateur PCIe activée (bit 1)
    pub irq_enabled: bool,
    /// Index ou numéro de l'adaptateur PCIe USB4 cible (bits 8..15)
    pub adapter_index: u8,
    /// Vitesse PCIe négociée (Link Speed: 1=Gen1 2.5GT/s, 2=Gen2 5.0GT/s, 3=Gen3 8.0GT/s, 4=Gen4 16.0GT/s)
    pub link_speed_gen: u8,
    /// Largeur de lien PCIe négociée (Link Width: 1=x1, 2=x2, 4=x4, 8=x8, 16=x16)
    pub link_width: u8,
    /// Registre de contrôle et de statut d'adaptateur PCIe USB4
    pub adapter_status: u32,
    /// Compteur total d'interruptions et d'événements de tunneling PCIe reçus
    pub event_counter: u32,
}

impl XhciUsb4PcieAdapterConfigInterface {
    /// Crée une nouvelle interface de configuration d'adaptateur PCIe USB4
    pub const fn new(adapter_index: u8, link_speed_gen: u8, link_width: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            irq_enabled: false,
            adapter_index,
            link_speed_gen: link_speed_gen & 0x07,
            link_width: link_width & 0x1F,
            adapter_status: 0,
            event_counter: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 PCIe Adapter Configuration Interface (§7.50)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_PCIE_ADAPTER_CONFIGURATION_INTERFACE {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let irq_enabled = (ctrl & 0x02) != 0;
        let adapter_index = ((ctrl >> 8) & 0xFF) as u8;
        let link_speed_gen = ((ctrl >> 16) & 0x07) as u8;
        let link_width = ((ctrl >> 20) & 0x1F) as u8;

        let adapter_status = dwords[2];
        let event_counter = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            irq_enabled,
            adapter_index,
            link_speed_gen,
            link_width,
            adapter_status,
            event_counter,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_PCIE_ADAPTER_CONFIGURATION_INTERFACE as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.adapter_index as u32) << 8)
            | (((self.link_speed_gen as u32) & 0x07) << 16)
            | (((self.link_width as u32) & 0x1F) << 20);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.irq_enabled {
            ctrl |= 0x02;
        }
        let dw2 = self.adapter_status;
        let dw3 = self.event_counter;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'interface d'adaptateur PCIe
    pub fn enable(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive les interruptions matérielles sur événement PCIe
    pub fn configure_irq(&mut self, enable: bool) {
        self.irq_enabled = enable;
    }

    /// Configure la vitesse de lien PCIe Gen
    pub fn set_link_speed(&mut self, gen: u8) {
        self.link_speed_gen = gen & 0x07;
    }

    /// Configure la largeur de lien PCIe (x1, x2, x4, x8, x16)
    pub fn set_link_width(&mut self, width: u8) {
        self.link_width = width & 0x1F;
    }

    /// Enregistre un événement de statut ou d'interruption
    pub fn record_event(&mut self, status_bits: u32) {
        self.adapter_status |= status_bits;
        self.event_counter = self.event_counter.wrapping_add(1);
    }
}

/// Capacité étendue xHCI 1.2 / USB4 DP Adapter Configuration Interface (§7.51, Cap ID 59)
///
/// Permet la gestion déterministe et le contrôle direct des registres de configuration
/// des adaptateurs DisplayPort (DP IN / DP OUT Adapters) intégrés dans les routeurs USB4 hôtes et cibles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciUsb4DpAdapterConfigInterface {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Fonctionnalité activée dans le contrôleur (bit 0)
    pub enabled: bool,
    /// Génération d'interruptions d'événement d'adaptateur DP activée (bit 1)
    pub irq_enabled: bool,
    /// Index ou numéro de l'adaptateur DisplayPort USB4 cible (bits 8..15)
    pub adapter_index: u8,
    /// Taux de liaison DP négocié (Link Rate: 1=RBR 1.62Gbps, 2=HBR 2.7Gbps, 3=HBR2 5.4Gbps, 4=HBR3 8.1Gbps, 5=UHBR10, 6=UHBR20)
    pub link_rate: u8,
    /// Nombre de voies DP allouées (Lane Count: 1=1 lane, 2=2 lanes, 4=4 lanes)
    pub lane_count: u8,
    /// Registre de contrôle et de statut d'adaptateur DisplayPort USB4
    pub adapter_status: u32,
    /// Compteur total d'interruptions et d'événements de tunneling DP reçus
    pub event_counter: u32,
}

impl XhciUsb4DpAdapterConfigInterface {
    /// Crée une nouvelle interface de configuration d'adaptateur DisplayPort USB4
    pub const fn new(adapter_index: u8, link_rate: u8, lane_count: u8) -> Self {
        Self {
            next_ptr_dwords: 0,
            enabled: false,
            irq_enabled: false,
            adapter_index,
            link_rate: link_rate & 0x07,
            lane_count: lane_count & 0x07,
            adapter_status: 0,
            event_counter: 0,
        }
    }

    /// Parse les 4 dwords MMIO d'une capacité étendue USB4 DP Adapter Configuration Interface (§7.51)
    pub const fn parse(dwords: &[u32; 4]) -> Option<Self> {
        let cap_id = (dwords[0] & 0xFF) as u8;
        if cap_id != XHCI_EXT_CAP_USB4_DP_ADAPTER_CONFIGURATION_INTERFACE {
            return None;
        }

        let next_ptr = ((dwords[0] >> 8) & 0xFF) as u8;
        let ctrl = dwords[1];
        let enabled = (ctrl & 0x01) != 0;
        let irq_enabled = (ctrl & 0x02) != 0;
        let adapter_index = ((ctrl >> 8) & 0xFF) as u8;
        let link_rate = ((ctrl >> 16) & 0x07) as u8;
        let lane_count = ((ctrl >> 20) & 0x07) as u8;

        let adapter_status = dwords[2];
        let event_counter = dwords[3];

        Some(Self {
            next_ptr_dwords: next_ptr,
            enabled,
            irq_enabled,
            adapter_index,
            link_rate,
            lane_count,
            adapter_status,
            event_counter,
        })
    }

    /// Encode la capacité étendue en 4 mots dwords MMIO 32-bit
    pub const fn encode(&self) -> [u32; 4] {
        let dw0 = (XHCI_EXT_CAP_USB4_DP_ADAPTER_CONFIGURATION_INTERFACE as u32)
            | ((self.next_ptr_dwords as u32) << 8);
        let mut ctrl = ((self.adapter_index as u32) << 8)
            | (((self.link_rate as u32) & 0x07) << 16)
            | (((self.lane_count as u32) & 0x07) << 20);
        if self.enabled {
            ctrl |= 0x01;
        }
        if self.irq_enabled {
            ctrl |= 0x02;
        }
        let dw2 = self.adapter_status;
        let dw3 = self.event_counter;
        [dw0, ctrl, dw2, dw3]
    }

    /// Active ou désactive l'interface d'adaptateur DisplayPort
    pub fn enable(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Active ou désactive les interruptions matérielles sur événement DisplayPort
    pub fn configure_irq(&mut self, enable: bool) {
        self.irq_enabled = enable;
    }

    /// Configure le taux de liaison DP (Link Rate: 1..6)
    pub fn set_link_rate(&mut self, rate: u8) {
        self.link_rate = rate & 0x07;
    }

    /// Configure le nombre de voies DP (Lane Count: 1, 2, 4)
    pub fn set_lane_count(&mut self, lanes: u8) {
        self.lane_count = lanes & 0x07;
    }

    /// Enregistre un événement de statut ou d'interruption
    pub fn record_event(&mut self, status_bits: u32) {
        self.adapter_status |= status_bits;
        self.event_counter = self.event_counter.wrapping_add(1);
    }
}

/// Capacité Étendue xHCI USB Debug Capability (DbC / xHCI 1.2 §7.6/§7.7)
///
/// Permet l'émulation d'un périphérique cible de débogage (USB Debug Device)
/// via le contrôleur hôte, exposant une console série bare-metal bidirectionnelle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciDebugCapability {
    /// Pointeur dword vers la prochaine capacité étendue (0 = fin de liste)
    pub next_ptr_dwords: u8,
    /// Débogage USB activé (DCCTRL.DCE, bit 31 du registre de contrôle)
    pub enabled: bool,
    /// Numéro de port xHCI physique routé vers la console DbC
    pub port_num: u8,
    /// Taille de la table de segments du Debug Event Ring (DC_ERSTSZ)
    pub erst_size: u16,
    /// Adresse IOVA de la table de segments d'événements (DC_ERSTBA)
    pub erst_base_iova: u64,
    /// Pointeur de dequeuing d'événements (DC_ERDP)
    pub erdp_iova: u64,
    /// Pointeur de contexte DbC (DCCP - Debug Capability Context Pointer)
    pub context_ptr_iova: u64,
}

impl XhciDebugCapability {
    /// Parse les registres MMIO d'une capacité étendue USB Debug Capability (DbC)
    /// `dwords` contient :
    /// - [0] : DCID (Cap ID=10, Next Ptr, DC_ERSTSZ [21:16])
    /// - [1] : DC_DOORBELL
    /// - [2] : DC_ERSTBA_LO
    /// - [3] : DC_ERSTBA_HI
    /// - [4] : DC_ERDP_LO
    /// - [5] : DC_ERDP_HI
    /// - [6] : DCCTRL (DCE bit 31, Port Num [23:16])
    /// - [7] : DCCP_LO
    /// - [8] : DCCP_HI
    pub const fn parse(dwords: &[u32; 9]) -> Self {
        let dw0 = dwords[0];
        let next_ptr_dwords = ((dw0 >> 8) & 0xFF) as u8;
        let erst_size = ((dw0 >> 16) & 0xFFFF) as u16;

        let erst_base_iova = (dwords[2] as u64) | ((dwords[3] as u64) << 32);
        let erdp_iova = (dwords[4] as u64) | ((dwords[5] as u64) << 32);
        let ctrl = dwords[6];
        let enabled = (ctrl & (1 << 31)) != 0;
        let port_num = ((ctrl >> 16) & 0xFF) as u8;
        let context_ptr_iova = (dwords[7] as u64) | ((dwords[8] as u64) << 32);

        Self {
            next_ptr_dwords,
            enabled,
            port_num,
            erst_size,
            erst_base_iova,
            erdp_iova,
            context_ptr_iova,
        }
    }

    /// Encode les 9 dwords de la structure USB Debug Capability (DbC)
    pub const fn encode(&self) -> [u32; 9] {
        let dw0 = (XHCI_EXT_CAP_USB_DEBUG_CAPABILITY as u32)
            | ((self.next_ptr_dwords as u32) << 8)
            | ((self.erst_size as u32) << 16);
        let dw1 = 0; // Doorbell
        let dw2 = (self.erst_base_iova & 0xFFFF_FFFF) as u32;
        let dw3 = ((self.erst_base_iova >> 32) & 0xFFFF_FFFF) as u32;
        let dw4 = (self.erdp_iova & 0xFFFF_FFFF) as u32;
        let dw5 = ((self.erdp_iova >> 32) & 0xFFFF_FFFF) as u32;
        let dw6 =
            (if self.enabled { 1 << 31 } else { 0 }) | (((self.port_num as u32) & 0xFF) << 16);
        let dw7 = (self.context_ptr_iova & 0xFFFF_FFFF) as u32;
        let dw8 = ((self.context_ptr_iova >> 32) & 0xFFFF_FFFF) as u32;

        [dw0, dw1, dw2, dw3, dw4, dw5, dw6, dw7, dw8]
    }
}

/// Console de débogage série USB xHCI DbC (Debug Capability Console)
///
/// Fournit un canal Ring 3 bidirectionnel bare-metal pour logs noyau et télémesures
/// sans nécessiter d'énumération USB standard ni de pilote hôte complexe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciDebugConsole {
    /// Port USB DbC configuré
    pub port_num: u8,
    /// Indique si la console est active et connectée à une machine hôte de débogage
    pub connected: bool,
    /// Compteur d'octets émis sur la console
    pub bytes_tx: u64,
    /// Compteur d'octets reçus sur la console
    pub bytes_rx: u64,
}

impl Default for XhciDebugConsole {
    fn default() -> Self {
        Self::new(1)
    }
}

impl XhciDebugConsole {
    /// Crée une nouvelle console de débogage USB xHCI DbC
    pub const fn new(port_num: u8) -> Self {
        Self {
            port_num,
            connected: false,
            bytes_tx: 0,
            bytes_rx: 0,
        }
    }

    /// Signale la connexion d'un câble de débogage hôte
    pub fn attach(&mut self) {
        self.connected = true;
    }

    /// Signale la déconnexion du câble de débogage
    pub fn detach(&mut self) {
        self.connected = false;
    }

    /// Écrit un tampon de données sur la console DbC si connectée
    pub fn write(&mut self, data: &[u8]) -> usize {
        if !self.connected {
            return 0;
        }
        let len = data.len();
        self.bytes_tx = self.bytes_tx.saturating_add(len as u64);
        len
    }

    /// Lit un tampon de données depuis la console DbC si connectée
    pub fn read(&mut self, buf: &mut [u8], simulated_input: &[u8]) -> usize {
        if !self.connected {
            return 0;
        }
        let copy_len = buf.len().min(simulated_input.len());
        buf[..copy_len].copy_from_slice(&simulated_input[..copy_len]);
        self.bytes_rx = self.bytes_rx.saturating_add(copy_len as u64);
        copy_len
    }
}

/// Niveaux de latence de sortie LPM Best Effort (Exit Latency)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhciLpmExitLatency {
    ZeroUs = 0,
    OneUs = 1,
    TwoUs = 2,
    FourUs = 3,
    EightUs = 4,
    SixteenUs = 5,
    ThirtyTwoUs = 6,
    SixtyFourUs = 7,
}

impl XhciLpmExitLatency {
    pub const fn from_raw(raw: u8) -> Self {
        match raw & 0x07 {
            0 => Self::ZeroUs,
            1 => Self::OneUs,
            2 => Self::TwoUs,
            3 => Self::FourUs,
            4 => Self::EightUs,
            5 => Self::SixteenUs,
            6 => Self::ThirtyTwoUs,
            _ => Self::SixtyFourUs,
        }
    }

    pub const fn to_raw(self) -> u8 {
        self as u8
    }

    pub const fn as_microseconds(self) -> u32 {
        match self {
            Self::ZeroUs => 0,
            Self::OneUs => 1,
            Self::TwoUs => 2,
            Self::FourUs => 4,
            Self::EightUs => 8,
            Self::SixteenUs => 16,
            Self::ThirtyTwoUs => 32,
            Self::SixtyFourUs => 64,
        }
    }
}

/// Structure de décodage et contrôle xHCI 1.2 §7.8 : Extended Power Management & LPM Best Effort
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciExtendedPowerManagementLpm {
    /// Pointeur dword vers la prochaine capacité étendue
    pub next_ptr_dwords: u8,
    /// Support matériel du Link Power Management (LPM) Hardware Enforced
    pub hardware_lpm_capable: bool,
    /// Support matériel de la latence de sortie LPM Best Effort
    pub best_effort_exit_latency_capable: bool,
    /// Latence de sortie Best Effort configurée (microsecondes quantifiées)
    pub exit_latency: XhciLpmExitLatency,
    /// LPM Best Effort activé
    pub best_effort_enabled: bool,
    /// Timeout d'inactivité avant transition U1/U2 en microsecondes (0..255 µs)
    pub inactivity_timeout_us: u8,
}

impl Default for XhciExtendedPowerManagementLpm {
    fn default() -> Self {
        Self {
            next_ptr_dwords: 0,
            hardware_lpm_capable: true,
            best_effort_exit_latency_capable: true,
            exit_latency: XhciLpmExitLatency::EightUs,
            best_effort_enabled: false,
            inactivity_timeout_us: 10,
        }
    }
}

impl XhciExtendedPowerManagementLpm {
    /// Parse les dwords de la capacité LPM Best Effort (§7.8)
    /// Dword 0: [7:0] CapID (15), [15:8] Next Cap Ptr, [16] HW LPM Capable, [17] Best Effort Latency Capable, [20:18] Exit Latency
    /// Dword 1: [0] Best Effort Enable, [15:8] Inactivity Timeout (µs)
    pub const fn parse(dwords: &[u32]) -> Self {
        if dwords.is_empty() {
            return Self {
                next_ptr_dwords: 0,
                hardware_lpm_capable: false,
                best_effort_exit_latency_capable: false,
                exit_latency: XhciLpmExitLatency::ZeroUs,
                best_effort_enabled: false,
                inactivity_timeout_us: 0,
            };
        }
        let dw0 = dwords[0];
        let dw1 = if dwords.len() > 1 { dwords[1] } else { 0 };

        let next_ptr_dwords = ((dw0 >> 8) & 0xFF) as u8;
        let hardware_lpm_capable = (dw0 & (1 << 16)) != 0;
        let best_effort_exit_latency_capable = (dw0 & (1 << 17)) != 0;
        let raw_exit_lat = ((dw0 >> 18) & 0x07) as u8;
        let exit_latency = XhciLpmExitLatency::from_raw(raw_exit_lat);

        let best_effort_enabled = (dw1 & 0x01) != 0;
        let inactivity_timeout_us = ((dw1 >> 8) & 0xFF) as u8;

        Self {
            next_ptr_dwords,
            hardware_lpm_capable,
            best_effort_exit_latency_capable,
            exit_latency,
            best_effort_enabled,
            inactivity_timeout_us,
        }
    }

    /// Encode la capacité en deux dwords MMIO
    pub const fn encode(&self) -> [u32; 2] {
        let mut dw0 =
            (XHCI_EXT_CAP_EXTENDED_POWER_MGMT_LPM as u32) | ((self.next_ptr_dwords as u32) << 8);
        if self.hardware_lpm_capable {
            dw0 |= 1 << 16;
        }
        if self.best_effort_exit_latency_capable {
            dw0 |= 1 << 17;
        }
        dw0 |= (self.exit_latency.to_raw() as u32) << 18;

        let mut dw1 = 0u32;
        if self.best_effort_enabled {
            dw1 |= 0x01;
        }
        dw1 |= (self.inactivity_timeout_us as u32) << 8;

        [dw0, dw1]
    }

    /// Active ou désactive le mode LPM Best Effort
    pub fn set_best_effort_enable(&mut self, enable: bool) {
        if self.best_effort_exit_latency_capable {
            self.best_effort_enabled = enable;
        }
    }

    /// Met à jour la latence de sortie LPM Best Effort
    pub fn set_exit_latency(&mut self, lat: XhciLpmExitLatency) {
        self.exit_latency = lat;
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

/// Représentation typée du registre PORTPMSC (USB 3.0 Link Power Management / U1 / U2 / TPP)
/// conformément aux sections 5.4.9 / 5.4.12 de la spécification xHCI 1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortPmsc {
    /// Délai d'inactivité avant transition U0 -> U1 (bits 7:0, en microsecondes ; 0 = désactivé, 0xFF = infini)
    pub u1_timeout: u8,
    /// Délai d'inactivité avant transition U1 -> U2 (bits 15:8, en pas de 256 µs ; 0 = désactivé, 0xFF = infini)
    pub u2_timeout: u8,
    /// Force Link PM Accept (FLA, bit 16) : force l'acceptation des requêtes de veille U1/U2 du périphérique
    pub force_link_pm_accept: bool,
    /// Transfer Packet Pending Timeout (TPP, bits 23:17, 7 bits)
    pub tpp_timeout: u8,
}

impl PortPmsc {
    /// Décode une valeur brute 32-bit lue depuis le registre PORTPMSC USB 3.0
    pub const fn parse(raw: u32) -> Self {
        let u1_timeout = ((raw & PORTPMSC_U1_TIMEOUT_MASK) >> PORTPMSC_U1_TIMEOUT_SHIFT) as u8;
        let u2_timeout = ((raw & PORTPMSC_U2_TIMEOUT_MASK) >> PORTPMSC_U2_TIMEOUT_SHIFT) as u8;
        let force_link_pm_accept = (raw & PORTPMSC_FLA) != 0;
        let tpp_timeout =
            ((raw & PORTPMSC_USB3_TPP_TIMEOUT_MASK) >> PORTPMSC_USB3_TPP_TIMEOUT_SHIFT) as u8;

        Self {
            u1_timeout,
            u2_timeout,
            force_link_pm_accept,
            tpp_timeout,
        }
    }

    /// Encode les champs en valeur brute 32-bit pour écriture dans le registre PORTPMSC USB 3.0
    pub const fn encode(&self) -> u32 {
        let mut val = (self.u1_timeout as u32) << PORTPMSC_U1_TIMEOUT_SHIFT;
        val |= (self.u2_timeout as u32) << PORTPMSC_U2_TIMEOUT_SHIFT;
        if self.force_link_pm_accept {
            val |= PORTPMSC_FLA;
        }
        val |= ((self.tpp_timeout & 0x7F) as u32) << PORTPMSC_USB3_TPP_TIMEOUT_SHIFT;
        val
    }

    /// Vérifie si les timers configurés respectent la conformité USB-IF / xHCI 1.2
    ///
    /// - U1: 0..=127 µs ou 0xFF (infini / désactivé)
    /// - U2: 0..=254 (× 256 µs) ou 0xFF (infini / désactivé)
    pub const fn is_valid_usb_if(&self) -> bool {
        (self.u1_timeout <= 127 || self.u1_timeout == 0xFF)
            && (self.u2_timeout <= 254 || self.u2_timeout == 0xFF)
    }

    /// Calcule le délai de transition U2 en microsecondes (u2_timeout × 256 µs).
    /// Retourne `None` si u2_timeout est 0xFF (infini) ou 0 (désactivé).
    pub const fn u2_timeout_us(&self) -> Option<u32> {
        if self.u2_timeout == 0 || self.u2_timeout == 0xFF {
            None
        } else {
            Some((self.u2_timeout as u32) * 256)
        }
    }
}

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

    /// Calcule l'adresse MMIO du registre PORTPMSC (Port Power Management Status & Control)
    /// pour le port donné (1-based).
    ///
    /// Selon la spec xHCI 1.2 section 5.4.9 / 5.4.12, les registres de port commencent à `op_base + 0x400`,
    /// chaque groupe de port occupe 0x10 octets :
    /// - PORTSC : offset +0x00
    /// - PORTPMSC : offset +0x04
    /// - PORTLI : offset +0x08
    /// - PORTHLPMC : offset +0x0C
    ///
    /// # Panics
    ///
    /// Panique si `port_id == 0` (les ports sont numérotés à partir de 1).
    #[inline]
    pub fn portpmsc_addr(&self, port_id: u8) -> u64 {
        debug_assert!(port_id >= 1, "port_id est 1-based (>= 1)");
        let op_base = self.bar0_base + self.cap_length as u64;
        op_base + 0x400 + (port_id as u64 - 1) * 0x10 + 0x04
    }

    /// Lit le registre PORTPMSC du port spécifié et retourne sa valeur brute 32-bit.
    ///
    /// # Safety (contrat SAFETY interne)
    ///
    /// Cette fonction effectue une lecture volatile MMIO. L'appelant doit s'assurer que
    /// `bar0_base` pointe vers un espace MMIO xHCI valide et mappé, et que `port` est
    /// un numéro de port valide pour ce contrôleur (1 ≤ port ≤ max_ports).
    pub fn read_port_pmsc(&self, port: u8) -> u32 {
        if port == 0 || port > self.max_ports {
            return 0;
        }
        let addr = self.portpmsc_addr(port);
        // SAFETY: bar0_base est initialisé via init() depuis un BAR PCI valide et mappé en MMIO.
        // L'adresse calculée pointe vers le registre PORTPMSC du port demandé dans l'espace opérationnel xHCI.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// Lit le registre PORTPMSC et retourne une structure typée `PortPmsc`.
    pub fn read_port_pmsc_typed(&self, port: u8) -> PortPmsc {
        PortPmsc::parse(self.read_port_pmsc(port))
    }

    /// Configure les timers d'inactivité USB 3.0 U1/U2 et le flag Force Link PM Accept (FLA) sur un port xHCI.
    ///
    /// Selon la spec xHCI 1.2 section 5.4.9.1 :
    /// - `u1_timeout` : Délai d'inactivité avant transition U0 -> U1 (0 = désactivé, 1..=127 µs, 0xFF = infini).
    /// - `u2_timeout` : Délai d'inactivité avant transition U1 -> U2 (0 = désactivé, 1..=254 × 256 µs, 0xFF = infini).
    /// - `fla` : Force Link PM Accept, oblige l'acceptation des requêtes de veille U1/U2 initiées par le périphérique.
    ///
    /// # Errors
    ///
    /// Retourne [`SysError::InvalidArgument`] si `port` est hors de la plage valide (port == 0 ou > max_ports)
    /// ou si les seuils de timeout ne respectent pas la conformité USB-IF / xHCI 1.2.
    pub fn configure_port_u1_u2(
        &mut self,
        port: u8,
        u1_timeout: u8,
        u2_timeout: u8,
        fla: bool,
    ) -> Result<(), SysError> {
        if port == 0 || port > self.max_ports {
            return Err(SysError::InvalidArgument);
        }
        if !PortStatus::validate_u1_u2_timers(u1_timeout, u2_timeout) {
            return Err(SysError::InvalidArgument);
        }

        let addr = self.portpmsc_addr(port);
        // SAFETY: bar0_base est initialisé depuis un BAR PCI mappé en MMIO.
        // Lecture volatile préalable pour préserver les bits spécifiques au port (par ex. TPP).
        let current_raw = unsafe { core::ptr::read_volatile(addr as *const u32) };
        let mut pmsc = PortPmsc::parse(current_raw);
        pmsc.u1_timeout = u1_timeout;
        pmsc.u2_timeout = u2_timeout;
        pmsc.force_link_pm_accept = fla;

        // SAFETY: écriture volatile 32-bit atomique dans le registre PORTPMSC.
        unsafe { core::ptr::write_volatile(addr as *mut u32, pmsc.encode()) };
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

    /// Calcule l'adresse MMIO d'une capacité étendue xHCI (Extended Capability) à partir
    /// de l'adresse de base BAR0 et du décalage (en dwords) spécifié dans HCCPARAMS1 (bits 31:16).
    #[inline]
    pub fn ext_cap_addr(&self, xecp_dwords: u16) -> u64 {
        self.bar0_base + ((xecp_dwords as u64) << 2)
    }

    /// Lit l'état de la capacité USB Legacy Support (xHCI 1.2 section 7.1)
    /// à partir de l'adresse MMIO de base de la capacité.
    ///
    /// # Safety
    ///
    /// Effectue des lectures volatiles 32-bit MMIO sur l'espace BAR0 du contrôleur xHCI.
    pub fn read_legacy_support(&self, cap_addr: u64) -> XhciLegacySupport {
        let usblegsup = unsafe { core::ptr::read_volatile(cap_addr as *const u32) };
        let usblegctlsts = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        XhciLegacySupport::parse(usblegsup, usblegctlsts)
    }

    /// Revendique l'appropriation matérielle du contrôleur xHCI par l'OS (BIOS handoff).
    ///
    /// Positionne le bit `USBLEGSUP_OS_OWNED` (bit 24), puis désactive et acquitte les
    /// interruptions SMI dans `USBLEGCTLSTS` selon xHCI 1.2 section 7.1.
    ///
    /// # Safety
    ///
    /// Effectue des accès MMIO volatils en lecture/écriture sur les registres USBLEGSUP et USBLEGCTLSTS.
    pub fn claim_os_ownership(&mut self, cap_addr: u64) {
        let raw_sup = unsafe { core::ptr::read_volatile(cap_addr as *const u32) };
        let new_sup = XhciLegacySupport::build_os_claim_usblegsup(raw_sup);
        unsafe { core::ptr::write_volatile(cap_addr as *mut u32, new_sup) };

        let raw_ctl = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        let new_ctl = XhciLegacySupport::build_quiesce_smi_control(raw_ctl);
        unsafe { core::ptr::write_volatile((cap_addr + 4) as *mut u32, new_ctl) };
    }

    /// Libère l'appropriation matérielle du contrôleur xHCI par l'OS.
    ///
    /// # Safety
    ///
    /// Effectue un accès MMIO volatil en écriture sur le registre USBLEGSUP.
    pub fn release_os_ownership(&mut self, cap_addr: u64) {
        let raw_sup = unsafe { core::ptr::read_volatile(cap_addr as *const u32) };
        let new_sup = XhciLegacySupport::build_os_release_usblegsup(raw_sup);
        unsafe { core::ptr::write_volatile(cap_addr as *mut u32, new_sup) };
    }

    /// Lit l'état de la capacité USB Power Management (xHCI 1.2 section 7.3)
    /// à partir de l'adresse MMIO de base de la capacité étendue.
    ///
    /// # Safety
    ///
    /// Effectue des lectures volatiles 32-bit MMIO sur l'espace BAR0 du contrôleur xHCI.
    pub fn read_power_management(&self, cap_addr: u64) -> XhciPowerManagement {
        let usbpmr = unsafe { core::ptr::read_volatile(cap_addr as *const u32) };
        let usbpmcsr = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        XhciPowerManagement::parse(usbpmr, usbpmcsr)
    }

    /// Règle l'état d'énergie cible (D0..D3hot) dans le registre USBPMCSR (xHCI 1.2 section 7.3).
    ///
    /// # Safety
    ///
    /// Effectue un cycle de lecture-modification-écriture MMIO 32-bit sur USBPMCSR.
    pub fn set_power_state(&mut self, cap_addr: u64, target: XhciPowerState) {
        let raw_csr = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        let new_csr = XhciPowerManagement::build_power_state_transition(raw_csr, target);
        unsafe { core::ptr::write_volatile((cap_addr + 4) as *mut u32, new_csr) };
    }

    /// Acquitte l'indicateur d'événement PME (Power Management Event) dans USBPMCSR.
    ///
    /// # Safety
    ///
    /// Effectue une écriture RW1C MMIO 32-bit sur le registre USBPMCSR.
    pub fn ack_pme_status(&mut self, cap_addr: u64) {
        let raw_csr = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        let new_csr = XhciPowerManagement::build_pme_ack(raw_csr);
        unsafe { core::ptr::write_volatile((cap_addr + 4) as *mut u32, new_csr) };
    }

    /// Lit et décode une capacité Supported Protocol (xHCI 1.2 section 7.2)
    /// à partir de son adresse MMIO de base.
    ///
    /// # Safety
    ///
    /// Effectue 3 lectures volatiles MMIO 32-bit alignées sur l'espace BAR0 du contrôleur xHCI.
    pub fn read_supported_protocol(&self, cap_addr: u64) -> XhciSupportedProtocol {
        let dw0 = unsafe { core::ptr::read_volatile(cap_addr as *const u32) };
        let dw1 = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        let dw2 = unsafe { core::ptr::read_volatile((cap_addr + 8) as *const u32) };
        XhciSupportedProtocol::parse(&[dw0, dw1, dw2])
    }

    /// Recherche les informations de protocole (USB 2.0 / USB 3.x) associées à un port
    /// physique donné dans un tableau de capacités Supported Protocol.
    pub fn query_port_protocol(
        protocols: &[XhciSupportedProtocol],
        port_num: u8,
    ) -> Option<XhciPortProtocolInfo> {
        for proto in protocols {
            if proto.contains_port(port_num) {
                return Some(XhciPortProtocolInfo {
                    port_num,
                    major_rev: proto.major_rev,
                    minor_rev: proto.minor_rev,
                    default_speed: proto.default_speed(),
                    is_usb3: proto.is_usb3(),
                    is_usb2: proto.is_usb2(),
                });
            }
        }
        None
    }

    /// Lit et décode une capacité I/O Virtualization (xHCI 1.2 section 7.4)
    /// à partir de son adresse MMIO de base.
    ///
    /// # Safety
    ///
    /// Effectue 2 lectures volatiles MMIO 32-bit alignées sur l'espace BAR0 du contrôleur xHCI.
    pub fn read_io_virtualization(&self, cap_addr: u64) -> XhciIoVirtualization {
        let dw0 = unsafe { core::ptr::read_volatile(cap_addr as *const u32) };
        let dw1 = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        XhciIoVirtualization::parse(&[dw0, dw1])
    }

    /// Lit et décode une capacité Local Memory (xHCI 1.2 section 7.5)
    /// à partir de son adresse MMIO de base.
    ///
    /// # Safety
    ///
    /// Effectue 2 lectures volatiles MMIO 32-bit alignées sur l'espace BAR0 du contrôleur xHCI.
    pub fn read_local_memory(&self, cap_addr: u64) -> XhciLocalMemory {
        let dw0 = unsafe { core::ptr::read_volatile(cap_addr as *const u32) };
        let dw1 = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        XhciLocalMemory::parse(&[dw0, dw1])
    }

    /// Lit et décode une capacité Extended Message Interrupt (MSI-X / xHCI 1.2 section 7.6)
    /// à partir de son adresse MMIO de base.
    ///
    /// # Safety
    ///
    /// Effectue 4 lectures volatiles MMIO 32-bit alignées sur l'espace BAR0 du contrôleur xHCI.
    pub fn read_extended_message_interrupt(&self, cap_addr: u64) -> XhciExtendedMessageInterrupt {
        let dw0 = unsafe { core::ptr::read_volatile(cap_addr as *const u32) };
        let dw1 = unsafe { core::ptr::read_volatile((cap_addr + 4) as *const u32) };
        let dw2 = unsafe { core::ptr::read_volatile((cap_addr + 8) as *const u32) };
        let dw3 = unsafe { core::ptr::read_volatile((cap_addr + 12) as *const u32) };
        XhciExtendedMessageInterrupt::parse(&[dw0, dw1, dw2, dw3])
    }

    /// Lit et décode une capacité Extended Debug Capability (DbC / xHCI 1.2 §7.6/§7.7)
    /// à partir de son adresse MMIO de base.
    ///
    /// # Safety
    ///
    /// Effectue 9 lectures volatiles MMIO 32-bit alignées sur l'espace BAR0 du contrôleur xHCI.
    pub fn read_debug_capability(&self, cap_addr: u64) -> XhciDebugCapability {
        let mut dwords = [0u32; 9];
        let mut i = 0;
        while i < 9 {
            dwords[i] =
                unsafe { core::ptr::read_volatile((cap_addr + (i as u64 * 4)) as *const u32) };
            i += 1;
        }
        XhciDebugCapability::parse(&dwords)
    }

    /// Émet une commande Evaluate Context sur le Command Ring.
    pub fn evaluate_context(
        &mut self,
        input_ctx_iova: u64,
        slot_id: u8,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        let control_extra = (slot_id as u32) << 24;
        self.cmd_ring
            .push(input_ctx_iova, control_extra, TRB_TYPE_EVALUATE_CONTEXT)
    }

    /// Émet une commande Reset Endpoint sur le Command Ring.
    pub fn reset_endpoint(
        &mut self,
        slot_id: u8,
        ep_dci: u8,
        preserve_state: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_dci == 0 || ep_dci > 31 {
            return Err(SysError::InvalidArgument);
        }
        let control_extra = ((slot_id as u32) << 24)
            | ((ep_dci as u32) << 16)
            | if preserve_state { 1 << 9 } else { 0 };
        self.cmd_ring.push(0, control_extra, TRB_TYPE_RESET_EP)
    }

    /// Émet une commande Stop Endpoint sur le Command Ring.
    pub fn stop_endpoint(
        &mut self,
        slot_id: u8,
        ep_dci: u8,
        suspend: bool,
    ) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if ep_dci == 0 || ep_dci > 31 {
            return Err(SysError::InvalidArgument);
        }
        let control_extra =
            ((slot_id as u32) << 24) | ((ep_dci as u32) << 16) | if suspend { 1 << 23 } else { 0 };
        self.cmd_ring.push(0, control_extra, TRB_TYPE_STOP_EP)
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

    #[test]
    fn test_portpmsc_u1_u2_power_management_and_mmio() {
        // 1. Structure PortPmsc : round-trip parse / encode
        let pmsc = PortPmsc {
            u1_timeout: 45,
            u2_timeout: 120,
            force_link_pm_accept: true,
            tpp_timeout: 33,
        };
        let encoded = pmsc.encode();
        let decoded = PortPmsc::parse(encoded);
        assert_eq!(decoded, pmsc, "round-trip PortPmsc parse/encode");

        // 2. Vérification des masques et bits individuels
        assert_eq!(encoded & PORTPMSC_U1_TIMEOUT_MASK, 45);
        assert_eq!(
            (encoded & PORTPMSC_U2_TIMEOUT_MASK) >> PORTPMSC_U2_TIMEOUT_SHIFT,
            120
        );
        assert_ne!(encoded & PORTPMSC_FLA, 0);
        assert_eq!(
            (encoded & PORTPMSC_USB3_TPP_TIMEOUT_MASK) >> PORTPMSC_USB3_TPP_TIMEOUT_SHIFT,
            33
        );

        // 3. Validation de conformité USB-IF / xHCI 1.2
        assert!(pmsc.is_valid_usb_if());
        let valid_edge = PortPmsc {
            u1_timeout: 127,
            u2_timeout: 254,
            force_link_pm_accept: false,
            tpp_timeout: 127,
        };
        assert!(valid_edge.is_valid_usb_if());

        let valid_infinite = PortPmsc {
            u1_timeout: 0xFF,
            u2_timeout: 0xFF,
            force_link_pm_accept: false,
            tpp_timeout: 0,
        };
        assert!(valid_infinite.is_valid_usb_if());
        assert_eq!(valid_infinite.u2_timeout_us(), None);

        let invalid_u1 = PortPmsc {
            u1_timeout: 128,
            u2_timeout: 50,
            force_link_pm_accept: false,
            tpp_timeout: 0,
        };
        assert!(!invalid_u1.is_valid_usb_if());

        let invalid_u2 = PortPmsc {
            u1_timeout: 10,
            u2_timeout: 255, // 0xFF est infini, mais > 254 et != 0xFF n'existe pas en u8, testons via PortStatus
            force_link_pm_accept: false,
            tpp_timeout: 0,
        };
        // 0xFF est valide (infini)
        assert!(invalid_u2.is_valid_usb_if());

        // Calcul de délai U2 en µs
        assert_eq!(pmsc.u2_timeout_us(), Some(120 * 256));
        let pmsc_zero = PortPmsc::default();
        assert_eq!(pmsc_zero.u2_timeout_us(), None);

        // 4. Calcul d'adresse MMIO portpmsc_addr
        let mut ctrl = XhciController::new();
        ctrl.bar0_base = 0x8000_0000;
        ctrl.cap_length = 0x20;
        let op_base = 0x8000_0000 + 0x20; // 0x8000_0020

        // Port 1: op_base + 0x400 + 0*0x10 + 0x04 = op_base + 0x404
        assert_eq!(ctrl.portpmsc_addr(1), op_base + 0x404);
        // Port 2: op_base + 0x400 + 1*0x10 + 0x04 = op_base + 0x414
        assert_eq!(ctrl.portpmsc_addr(2), op_base + 0x414);
        // Port 8: op_base + 0x400 + 7*0x10 + 0x04 = op_base + 0x474
        assert_eq!(ctrl.portpmsc_addr(8), op_base + 0x474);

        // 5. Validation de configure_port_u1_u2 (vérification des arguments)
        // Port 0 est invalide
        assert_eq!(
            ctrl.configure_port_u1_u2(0, 10, 20, true),
            Err(SysError::InvalidArgument)
        );
        // Port > max_ports est invalide
        assert_eq!(
            ctrl.configure_port_u1_u2(9, 10, 20, true),
            Err(SysError::InvalidArgument)
        );
        // U1 timeout non conforme (> 127 et != 0xFF)
        assert_eq!(
            ctrl.configure_port_u1_u2(1, 130, 20, true),
            Err(SysError::InvalidArgument)
        );

        // 6. read_port_pmsc sur port hors limites retourne 0
        assert_eq!(ctrl.read_port_pmsc(0), 0);
        assert_eq!(ctrl.read_port_pmsc(9), 0);
        assert_eq!(ctrl.read_port_pmsc_typed(0), PortPmsc::default());
    }

    #[test]
    fn test_xhci_contexts_and_extended_capabilities() {
        // 1. Validation de SlotContext (32 octets, aligné 32)
        assert_eq!(core::mem::size_of::<SlotContext>(), 32);
        assert_eq!(core::mem::align_of::<SlotContext>(), 32);

        let mut slot = SlotContext::new(4, 4, 1); // 4 context entries, speed = 4 (SuperSpeed), root_port = 1
        assert_eq!(slot.context_entries(), 4);
        assert_eq!(slot.speed(), 4);
        assert_eq!(slot.root_hub_port(), 1);
        assert_eq!(slot.device_address(), 0);
        assert_eq!(slot.slot_state(), 0);

        slot.set_device_address(3);
        slot.set_slot_state(1); // Default/Addressed
        assert_eq!(slot.device_address(), 3);
        assert_eq!(slot.slot_state(), 1);

        // 2. Validation d'EndpointContext (32 octets, aligné 32)
        assert_eq!(core::mem::size_of::<EndpointContext>(), 32);
        assert_eq!(core::mem::align_of::<EndpointContext>(), 32);

        let ep_ctx = EndpointContext::new(2, 1024, 0x1000_8000, 0, 3); // Bulk OUT (type=2), MPS=1024, ring=0x1000_8000, CERR=3
        assert_eq!(ep_ctx.ep_type(), 2);
        assert_eq!(ep_ctx.max_packet_size(), 1024);
        assert_eq!(ep_ctx.error_count(), 3);
        assert_eq!(ep_ctx.interval(), 0);
        assert_eq!(ep_ctx.dequeue_ptr(), 0x1000_8000);
        assert!(ep_ctx.dequeue_cycle_state());

        // 3. Validation d'InputControlContext (32 octets, aligné 32)
        assert_eq!(core::mem::size_of::<InputControlContext>(), 32);
        assert_eq!(core::mem::align_of::<InputControlContext>(), 32);

        let mut icc = InputControlContext::new();
        icc.enable_slot();
        icc.enable_endpoint(1); // EP0
        icc.enable_endpoint(2); // EP1 OUT
        icc.drop_endpoint(3); // EP1 IN
        assert_eq!(icc.add_flags, 0b111); // bits 0, 1, 2
        assert_eq!(icc.drop_flags, 1 << 3);

        // 4. Extended Capabilities Header parsing
        // Raw: cap_id = 2 (Supported Protocol), next = 8 dwords, specific = 0x0000
        let raw_hdr: u32 = 2 | (8 << 8);
        let parsed_hdr = XhciExtendedCapHeader::parse(raw_hdr);
        assert_eq!(parsed_hdr.cap_id, XHCI_EXT_CAP_SUPPORTED_PROTOCOL);
        assert_eq!(parsed_hdr.next_dwords, 8);
        assert_eq!(parsed_hdr.encode(), raw_hdr);

        // 5. Supported Protocol Capability parsing (USB 3.0)
        let proto_dwords: [u32; 3] = [
            (3 << 24) | 2, // major=3, minor=0, cap_id=2
            u32::from_le_bytes(*b"USB "),
            (4 << 8) | 1, // 4 ports starting at port 1
        ];
        let proto = XhciSupportedProtocol::parse(&proto_dwords);
        assert_eq!(proto.major_rev, 3);
        assert_eq!(proto.minor_rev, 0);
        assert_eq!(&proto.name_string, b"USB ");
        assert_eq!(proto.compatible_port_offset, 1);
        assert_eq!(proto.compatible_port_count, 4);
        assert!(proto.is_usb3());
        assert!(!proto.is_usb2());

        // 6. Extended Capability Address calculation
        let mut ctrl = XhciController::new();
        ctrl.bar0_base = 0xFE80_0000;
        ctrl.ready = true;
        // xecp = 0x2000 dwords = 0x8000 octets
        assert_eq!(ctrl.ext_cap_addr(0x2000), 0xFE80_0000 + (0x2000 << 2));

        // 7. Command Ring: evaluate_context, reset_endpoint, stop_endpoint
        let eval_idx = ctrl.evaluate_context(0x2000_1000, 1).unwrap();
        assert_eq!(
            ctrl.cmd_ring.trbs[eval_idx].trb_type(),
            TRB_TYPE_EVALUATE_CONTEXT
        );
        assert_eq!(ctrl.cmd_ring.trbs[eval_idx].parameter, 0x2000_1000);
        assert_eq!(ctrl.cmd_ring.trbs[eval_idx].status >> 24, 1); // slot_id

        let rst_idx = ctrl.reset_endpoint(1, 2, false).unwrap();
        assert_eq!(ctrl.cmd_ring.trbs[rst_idx].trb_type(), TRB_TYPE_RESET_EP);
        assert_eq!(ctrl.cmd_ring.trbs[rst_idx].status >> 24, 1); // slot_id
        assert_eq!((ctrl.cmd_ring.trbs[rst_idx].status >> 16) & 0xFF, 2); // ep_dci

        let stop_idx = ctrl.stop_endpoint(1, 2, true).unwrap();
        assert_eq!(ctrl.cmd_ring.trbs[stop_idx].trb_type(), TRB_TYPE_STOP_EP);
        assert_ne!(ctrl.cmd_ring.trbs[stop_idx].status & (1 << 23), 0); // suspend

        // 8. USB Legacy Support Capability parsing & handoff manipulation
        let raw_legs_bios: u32 = 1 | (4 << 8) | USBLEGSUP_BIOS_OWNED; // BIOS=1, OS=0, next=4
        let raw_leg_ctl: u32 = USBLEGCTLSTS_SMI_ENABLE | USBLEGCTLSTS_SMI_OWNERSHIP_CHANGE_ENABLE;
        let leg = XhciLegacySupport::parse(raw_legs_bios, raw_leg_ctl);
        assert_eq!(leg.next_ptr_dwords, 4);
        assert!(leg.bios_owned);
        assert!(!leg.os_owned);
        assert!(leg.smi_enabled);
        assert!(leg.smi_ownership_change_enable);
        assert!(!leg.is_os_owned());

        // Simulation OS Claim
        let claimed_usblegsup = XhciLegacySupport::build_os_claim_usblegsup(raw_legs_bios);
        assert_ne!(claimed_usblegsup & USBLEGSUP_OS_OWNED, 0);
        assert_ne!(claimed_usblegsup & USBLEGSUP_BIOS_OWNED, 0);

        // Simulation BIOS Handoff Completion (BIOS bits cleared by firmware)
        let handoff_completed = claimed_usblegsup & !USBLEGSUP_BIOS_OWNED;
        let quiesced_ctl = XhciLegacySupport::build_quiesce_smi_control(raw_leg_ctl);
        let leg_final = XhciLegacySupport::parse(handoff_completed, quiesced_ctl);
        assert!(leg_final.os_owned);
        assert!(!leg_final.bios_owned);
        assert!(!leg_final.smi_enabled);
        assert!(!leg_final.smi_ownership_change_enable);
        assert!(leg_final.is_os_owned());

        // 9. USB Power Management Capability parsing & state transitions
        let raw_pmr = (XHCI_EXT_CAP_EXTENDED_POWER_MGMT as u32)
            | (8 << 8) // next ptr = 8
            | (2 << 16) // pmic offset = 2
            | USBPMR_PORT_POWER_CONTROL
            | USBPMR_POWER_SOURCE_VALID;
        let raw_pmcsr = USBPMCSR_PME_ENABLE | USBPMCSR_PME_STATUS; // D0, PME enabled, PME status pending
        let pm = XhciPowerManagement::parse(raw_pmr, raw_pmcsr);
        assert_eq!(pm.next_ptr_dwords, 8);
        assert_eq!(pm.pmic_offset_dwords, 2);
        assert!(pm.port_power_control_supported);
        assert!(pm.power_source_valid);
        assert!(pm.is_d0_active());
        assert!(pm.pme_enabled);
        assert!(pm.pme_status);

        // Simulation transition vers D3hot
        let d3_pmcsr =
            XhciPowerManagement::build_power_state_transition(raw_pmcsr, XhciPowerState::D3Hot);
        let pm_d3 = XhciPowerManagement::parse(raw_pmr, d3_pmcsr);
        assert_eq!(pm_d3.current_power_state, XhciPowerState::D3Hot as u8);
        assert!(!pm_d3.is_d0_active());

        // 10. Supported Protocol Capability parsing, encoding & port querying
        let usb2_dwords: [u32; 3] = [
            (2 << 24) | (8 << 8) | (XHCI_EXT_CAP_SUPPORTED_PROTOCOL as u32), // USB 2.0, next=8
            u32::from_le_bytes(*b"USB "),
            (1 << 8) | 1, // 1 port starting at port 1
        ];
        let usb3_dwords: [u32; 3] = [
            (3 << 24) | (XHCI_EXT_CAP_SUPPORTED_PROTOCOL as u32), // USB 3.0, next=0
            u32::from_le_bytes(*b"USB "),
            (2 << 8) | 2, // 2 ports starting at port 2 (ports 2 and 3)
        ];
        let proto2 = XhciSupportedProtocol::parse(&usb2_dwords);
        let proto3 = XhciSupportedProtocol::parse(&usb3_dwords);
        assert_eq!(proto2.major_rev, 2);
        assert_eq!(proto2.next_ptr_dwords, 8);
        assert!(proto2.is_usb2());
        assert!(!proto2.is_usb3());
        assert_eq!(proto2.default_speed(), UsbSpeed::HighSpeed);
        assert!(proto2.contains_port(1));
        assert!(!proto2.contains_port(2));

        assert_eq!(proto3.major_rev, 3);
        assert_eq!(proto3.next_ptr_dwords, 0);
        assert!(proto3.is_usb3());
        assert!(!proto3.is_usb2());
        assert_eq!(proto3.default_speed(), UsbSpeed::SuperSpeed);
        assert!(proto3.contains_port(2));
        assert!(proto3.contains_port(3));
        assert!(!proto3.contains_port(1));
        assert!(!proto3.contains_port(4));

        let encoded2 = proto2.encode();
        assert_eq!(encoded2, usb2_dwords);

        let protocols = [proto2, proto3];
        let p1_info = XhciController::query_port_protocol(&protocols, 1).unwrap();
        assert_eq!(p1_info.port_num, 1);
        assert_eq!(p1_info.major_rev, 2);
        assert_eq!(p1_info.default_speed, UsbSpeed::HighSpeed);
        assert!(p1_info.is_usb2);
        assert!(!p1_info.is_usb3);

        let p2_info = XhciController::query_port_protocol(&protocols, 2).unwrap();
        assert_eq!(p2_info.port_num, 2);
        assert_eq!(p2_info.major_rev, 3);
        assert_eq!(p2_info.default_speed, UsbSpeed::SuperSpeed);
        assert!(p2_info.is_usb3);
        assert!(!p2_info.is_usb2);

        let p4_info = XhciController::query_port_protocol(&protocols, 4);
        assert_eq!(p4_info, None);

        // 11. I/O Virtualization Capability (xHCI 1.2 section 7.4)
        let iov_dwords: [u32; 2] = [
            (4 << 8) | (XHCI_EXT_CAP_IO_VIRTUALIZATION as u32), // next=4
            16,                                                 // num_vfs = 16
        ];
        let iov = XhciIoVirtualization::parse(&iov_dwords);
        assert_eq!(iov.next_ptr_dwords, 4);
        assert_eq!(iov.num_vfs, 16);
        assert_eq!(iov.encode(), iov_dwords);

        // 12. Local Memory Capability (xHCI 1.2 section 7.5)
        // BAR 2, offset 0x40 (64 dwords = 256 octets), size 64 KiB
        let loc_dwords: [u32; 2] = [
            ((64 & 0x1FFF) << 19) | ((2 & 0x07) << 16) | (XHCI_EXT_CAP_LOCAL_MEMORY as u32),
            64, // 64 KiB
        ];
        let loc = XhciLocalMemory::parse(&loc_dwords);
        assert_eq!(loc.next_ptr_dwords, 0);
        assert_eq!(loc.bar_index, 2);
        assert_eq!(loc.mem_offset_dwords, 64);
        assert_eq!(loc.size_kib, 64);
        assert_eq!(loc.size_bytes(), 64 * 1024);
        assert_eq!(loc.offset_bytes(), 256);
        assert_eq!(loc.encode(), loc_dwords);

        // 13. Extended Message Interrupt (MSI-X) Capability (xHCI 1.2 section 7.6)
        // Table: BAR 0, offset 0x2000 (2048 dwords = 8192 octets), 32 vecteurs (N-1 = 31)
        // PBA: BAR 0, offset 0x3000 (3072 dwords = 12288 octets)
        let msix_dwords: [u32; 4] = [
            (1 << 31) | (8 << 8) | (XHCI_EXT_CAP_EXTENDED_MESSAGE_INTERRUPT as u32), // enabled, next=8
            31,          // table_size = 32
            (2048 << 3), // BAR 0, offset 2048 dwords
            (3072 << 3), // BAR 0, offset 3072 dwords
        ];
        let msix_cap = XhciExtendedMessageInterrupt::parse(&msix_dwords);
        assert!(msix_cap.enabled);
        assert_eq!(msix_cap.next_ptr_dwords, 8);
        assert_eq!(msix_cap.table_size, 32);
        assert_eq!(msix_cap.table_bar, 0);
        assert_eq!(msix_cap.table_offset_dwords, 2048);
        assert_eq!(msix_cap.table_offset_bytes(), 8192);
        assert_eq!(msix_cap.pba_bar, 0);
        assert_eq!(msix_cap.pba_offset_dwords, 3072);
        assert_eq!(msix_cap.pba_offset_bytes(), 12288);
        assert_eq!(msix_cap.encode(), msix_dwords);

        // 14. XhciMsixRouter découplage des vecteurs commande & transfert
        let mut router = XhciMsixRouter::new(50, 51);
        assert!(!router.enabled);
        assert_eq!(router.route_interrupt(50), None);

        router.enable();
        assert!(router.enabled);
        assert_eq!(router.route_interrupt(50), Some(false)); // Commande
        assert_eq!(router.route_interrupt(51), Some(true)); // Transfert
        assert_eq!(router.route_interrupt(51), Some(true)); // Transfert
        assert_eq!(router.route_interrupt(52), None); // Vecteur inconnu

        assert_eq!(router.cmd_interrupts, 1);
        assert_eq!(router.transfer_interrupts, 2);

        router.disable();
        assert_eq!(router.route_interrupt(50), None);

        // 15. USB Debug Capability (DbC / xHCI 1.2 §7.6/§7.7)
        let dbc_dwords: [u32; 9] = [
            (4 << 16) | (12 << 8) | (XHCI_EXT_CAP_USB_DEBUG_CAPABILITY as u32), // erst_size=4, next=12
            0,                                                                  // doorbell
            0x1000,
            0x0000, // erst_base_iova = 0x1000
            0x2000,
            0x0000,                // erdp_iova = 0x2000
            (1 << 31) | (3 << 16), // enabled, port_num = 3
            0x4000,
            0x0000, // context_ptr_iova = 0x4000
        ];
        let dbc_cap = XhciDebugCapability::parse(&dbc_dwords);
        assert!(dbc_cap.enabled);
        assert_eq!(dbc_cap.next_ptr_dwords, 12);
        assert_eq!(dbc_cap.erst_size, 4);
        assert_eq!(dbc_cap.erst_base_iova, 0x1000);
        assert_eq!(dbc_cap.erdp_iova, 0x2000);
        assert_eq!(dbc_cap.port_num, 3);
        assert_eq!(dbc_cap.context_ptr_iova, 0x4000);
        assert_eq!(dbc_cap.encode(), dbc_dwords);

        // 16. Console série USB DbC (XhciDebugConsole)
        let mut console = XhciDebugConsole::new(3);
        assert_eq!(console.port_num, 3);
        assert!(!console.connected);
        assert_eq!(console.write(b"boot log"), 0);

        console.attach();
        assert!(console.connected);
        assert_eq!(console.write(b"JamboOS bare-metal debug log\n"), 29);
        assert_eq!(console.bytes_tx, 29);

        let mut rx_buf = [0u8; 16];
        let rx_len = console.read(&mut rx_buf, b"ping");
        assert_eq!(rx_len, 4);
        assert_eq!(&rx_buf[..4], b"ping");
        assert_eq!(console.bytes_rx, 4);

        console.detach();
        assert!(!console.connected);
        assert_eq!(console.write(b"dropped"), 0);

        // 17. xHCI 1.2 §7.8 LPM Best Effort Extended Capability
        let lpm_dwords: [u32; 2] = [
            (XHCI_EXT_CAP_EXTENDED_POWER_MGMT_LPM as u32)
                | (16 << 8)
                | (1 << 16)
                | (1 << 17)
                | ((XhciLpmExitLatency::ThirtyTwoUs.to_raw() as u32) << 18),
            0x01 | (25 << 8), // enabled, 25 µs inactivity timeout
        ];
        let mut lpm_cap = XhciExtendedPowerManagementLpm::parse(&lpm_dwords);
        assert_eq!(lpm_cap.next_ptr_dwords, 16);
        assert!(lpm_cap.hardware_lpm_capable);
        assert!(lpm_cap.best_effort_exit_latency_capable);
        assert_eq!(lpm_cap.exit_latency, XhciLpmExitLatency::ThirtyTwoUs);
        assert_eq!(lpm_cap.exit_latency.as_microseconds(), 32);
        assert!(lpm_cap.best_effort_enabled);
        assert_eq!(lpm_cap.inactivity_timeout_us, 25);
        assert_eq!(lpm_cap.encode(), lpm_dwords);

        lpm_cap.set_best_effort_enable(false);
        assert!(!lpm_cap.best_effort_enabled);
        lpm_cap.set_exit_latency(XhciLpmExitLatency::EightUs);
        assert_eq!(lpm_cap.exit_latency.as_microseconds(), 8);

        // 18. xHCI 1.2 §7.9 Extended Message Capability & MSI-X Extended Routing Table
        let mut routing_table = XhciMsixRoutingTable::new(16);
        assert_eq!(routing_table.capacity, 16);
        assert!(!routing_table.enabled);
        assert!(!routing_table.is_interrupter_deliverable(0));

        // Inscription de 2 entrées
        let entry0 = XhciMsixTableEntry::new(0xFEE0_0000, 0x0000_0032, false); // vector 0x32 (50), unmasked
        let entry1 = XhciMsixTableEntry::new(0xFEE0_0000, 0x0000_0033, true); // vector 0x33 (51), masked
        assert!(routing_table.set_entry(0, entry0));
        assert!(routing_table.set_entry(1, entry1));
        assert_eq!(entry0.vector(), 50);
        assert_eq!(entry1.vector(), 51);

        routing_table.enable();
        assert!(routing_table.is_interrupter_deliverable(0));
        assert!(!routing_table.is_interrupter_deliverable(1)); // car masked

        // Encodage/décodage MMIO dwords
        let mut enc_buf = [0u32; 4];
        assert!(routing_table.write_mmio_dwords(0, &mut enc_buf));
        let parsed_entry0 = XhciMsixTableEntry::parse(&enc_buf);
        assert_eq!(parsed_entry0, entry0);

        // Masquage global Function Mask
        routing_table.set_function_mask(true);
        assert!(!routing_table.is_interrupter_deliverable(0));
        routing_table.set_function_mask(false);
        assert!(routing_table.is_interrupter_deliverable(0));

        // 19. xHCI 1.2 §7.10 Secondary Bandwidth Capability (Inter-Host USB Bridge)
        let mut sec_bw = XhciSecondaryBandwidth::new(4, 10000);
        assert_eq!(sec_bw.num_domains, 4);
        assert_eq!(sec_bw.total_bus_mbps, 10000);
        assert!(!sec_bw.inter_host_bridge_enabled);
        assert_eq!(sec_bw.domains[0].max_mbps, 2500);
        assert_eq!(sec_bw.domains[0].available_mbps(), 2500);

        // Réservation de bande passante sur les domaines
        assert!(sec_bw.reserve_domain_bandwidth(1, 1500));
        assert_eq!(sec_bw.domains[0].available_mbps(), 1000);
        assert_eq!(sec_bw.domains[0].allocated_mbps, 1500);
        assert!(sec_bw.domains[0].active);

        // Saturation au-delà de la capacité maximale
        assert!(!sec_bw.reserve_domain_bandwidth(1, 1500)); // 1500 + 1500 = 3000 > 2500
        assert_eq!(sec_bw.domains[0].available_mbps(), 1000);

        // Domaine 2
        assert!(sec_bw.reserve_domain_bandwidth(2, 2000));
        assert_eq!(sec_bw.total_allocated_mbps(), 3500);

        // Libération
        sec_bw.release_domain_bandwidth(1, 500);
        assert_eq!(sec_bw.domains[0].allocated_mbps, 1000);
        assert_eq!(sec_bw.domains[0].available_mbps(), 1500);
        assert_eq!(sec_bw.total_allocated_mbps(), 3000);

        // Pont inter-hôte USB
        sec_bw.set_inter_host_bridge(true);
        assert!(sec_bw.inter_host_bridge_enabled);

        // Encodage / Décodage MMIO
        sec_bw.next_ptr_dwords = 20;
        let encoded_bw = sec_bw.encode();
        assert_eq!(
            encoded_bw[0] & 0xFF,
            XHCI_EXT_CAP_SECONDARY_BANDWIDTH as u32
        );
        assert_eq!((encoded_bw[0] >> 8) & 0xFF, 20);
        assert_eq!((encoded_bw[0] >> 16) & 0xFF, 4);
        assert_ne!(encoded_bw[0] & (1 << 31), 0);
        assert_eq!(encoded_bw[1], 10000);

        let parsed_bw = XhciSecondaryBandwidth::parse(&encoded_bw);
        assert_eq!(parsed_bw.next_ptr_dwords, 20);
        assert_eq!(parsed_bw.num_domains, 4);
        assert!(parsed_bw.inter_host_bridge_enabled);
        assert_eq!(parsed_bw.total_bus_mbps, 10000);

        // 20. xHCI 1.2 §7.11 USB Subsystem Hierarchy & Port Protocol Route Maps
        let mut hierarchy = XhciSubsystemHierarchy::new(6);
        assert_eq!(hierarchy.port_count, 6);
        assert_eq!(
            hierarchy.find_protocol_for_port(1),
            Some(XhciPortProtocolType::Usb3Gen2)
        );
        assert_eq!(
            hierarchy.find_protocol_for_port(2),
            Some(XhciPortProtocolType::Usb2)
        );

        // Modification de route de port
        assert!(hierarchy.set_port_route(3, XhciPortProtocolType::Usb4, 1));
        assert_eq!(
            hierarchy.find_protocol_for_port(3),
            Some(XhciPortProtocolType::Usb4)
        );

        // Encodage et décodage MMIO
        hierarchy.next_ptr_dwords = 24;
        hierarchy.routing_control = 0xAA;
        let (encoded_h, len_dwords) = hierarchy.encode();
        assert_eq!(len_dwords, 4); // 1 header + 3 dwords pour 6 routes (2 par dword)
        assert_eq!(
            encoded_h[0] & 0xFF,
            XHCI_EXT_CAP_PORT_PROTOCOL_HIERARCHY as u32
        );
        assert_eq!((encoded_h[0] >> 8) & 0xFF, 24);
        assert_eq!((encoded_h[0] >> 16) & 0xFF, 6);
        assert_eq!((encoded_h[0] >> 24) & 0xFF, 0xAA);

        let parsed_h = XhciSubsystemHierarchy::parse(&encoded_h[..len_dwords]).unwrap();
        assert_eq!(parsed_h.next_ptr_dwords, 24);
        assert_eq!(parsed_h.port_count, 6);
        assert_eq!(parsed_h.routing_control, 0xAA);
        assert_eq!(
            parsed_h.find_protocol_for_port(1),
            Some(XhciPortProtocolType::Usb3Gen2)
        );
        assert_eq!(
            parsed_h.find_protocol_for_port(2),
            Some(XhciPortProtocolType::Usb2)
        );
        assert_eq!(
            parsed_h.find_protocol_for_port(3),
            Some(XhciPortProtocolType::Usb4)
        );

        // 21. xHCI 1.2 §7.12 Extended Capability Descriptor Tables & USB Capability Pointers
        let mut cap_table = XhciExtendedCapabilityTable::new(5);
        assert_eq!(cap_table.entry_count, 5);
        assert_eq!(
            cap_table.find_offset_for_cap(XHCI_EXT_CAP_USB_LEGACY_SUPPORT),
            Some(4)
        );
        assert_eq!(
            cap_table.find_offset_for_cap(XHCI_EXT_CAP_SUPPORTED_PROTOCOL),
            Some(8)
        );
        assert_eq!(
            cap_table.find_offset_for_cap(XHCI_EXT_CAP_EXTENDED_POWER_MGMT),
            Some(12)
        );

        // Mise à jour et insertion d'une nouvelle capacité
        assert!(cap_table.set_entry(XHCI_EXT_CAP_LOCAL_MEMORY, 36, 0x05));
        assert_eq!(cap_table.entry_count, 6);
        assert_eq!(
            cap_table.find_offset_for_cap(XHCI_EXT_CAP_LOCAL_MEMORY),
            Some(36)
        );

        // Encodage et décodage MMIO
        cap_table.next_ptr_dwords = 32;
        cap_table.table_control = 0x55;
        let (encoded_tbl, len_tbl) = cap_table.encode();
        assert_eq!(len_tbl, 7); // 1 header + 6 entrées
        assert_eq!(
            encoded_tbl[0] & 0xFF,
            XHCI_EXT_CAP_EXTENDED_CAPABILITY_TABLE as u32
        );
        assert_eq!((encoded_tbl[0] >> 8) & 0xFF, 32);
        assert_eq!((encoded_tbl[0] >> 16) & 0xFF, 6);
        assert_eq!((encoded_tbl[0] >> 24) & 0xFF, 0x55);

        let parsed_tbl = XhciExtendedCapabilityTable::parse(&encoded_tbl[..len_tbl]).unwrap();
        assert_eq!(parsed_tbl.next_ptr_dwords, 32);
        assert_eq!(parsed_tbl.entry_count, 6);
        assert_eq!(parsed_tbl.table_control, 0x55);
        assert_eq!(
            parsed_tbl.find_offset_for_cap(XHCI_EXT_CAP_USB_LEGACY_SUPPORT),
            Some(4)
        );
        assert_eq!(
            parsed_tbl.find_offset_for_cap(XHCI_EXT_CAP_LOCAL_MEMORY),
            Some(36)
        );

        // 22. xHCI 1.2 §7.13 USB Device Virtualization & Secondary Host Controller Interface
        let mut dev_virt = XhciDeviceVirtualization::new(4, 32);
        assert_eq!(dev_virt.num_secondary_controllers, 4);
        assert_eq!(dev_virt.num_virtual_device_slots, 32);
        assert!(!dev_virt.enabled);
        assert!(!dev_virt.is_slot_assignable(1)); // désactivé initialement

        dev_virt.set_enabled(true);
        assert!(dev_virt.enabled);
        assert!(dev_virt.is_slot_assignable(1));
        assert!(dev_virt.is_slot_assignable(32));
        assert!(!dev_virt.is_slot_assignable(0)); // slot 0 réservé
        assert!(!dev_virt.is_slot_assignable(33)); // hors limite

        assert!(dev_virt.is_secondary_controller_valid(0));
        assert!(dev_virt.is_secondary_controller_valid(3));
        assert!(!dev_virt.is_secondary_controller_valid(4));

        dev_virt.next_ptr_dwords = 16;
        dev_virt.virt_status = 0x1234;
        let encoded_dv = dev_virt.encode();
        assert_eq!(
            encoded_dv[0] & 0xFF,
            XHCI_EXT_CAP_DEVICE_VIRTUALIZATION as u32
        );
        assert_eq!((encoded_dv[0] >> 8) & 0xFF, 16);
        assert_eq!((encoded_dv[0] >> 16) & 0xFF, 4);
        assert_eq!((encoded_dv[0] >> 24) & 0xFF, 32);
        assert_eq!(encoded_dv[1] & 0x01, 1);
        assert_eq!(encoded_dv[2], 0x1234);

        let parsed_dv = XhciDeviceVirtualization::parse(&encoded_dv).unwrap();
        assert_eq!(parsed_dv.next_ptr_dwords, 16);
        assert_eq!(parsed_dv.num_secondary_controllers, 4);
        assert_eq!(parsed_dv.num_virtual_device_slots, 32);
        assert!(parsed_dv.enabled);
        assert_eq!(parsed_dv.virt_status, 0x1234);

        // 23. xHCI 1.2 §7.14 USB Shared USB Device / Hub Virtualization Architecture
        let mut hub_virt = XhciHubVirtualization::new(8, 2);
        assert_eq!(hub_virt.num_downstream_ports, 8);
        assert_eq!(hub_virt.assigned_secondary_id, 2);
        assert!(!hub_virt.enabled);
        assert!(!hub_virt.is_downstream_port_valid(1));

        hub_virt.set_enabled(true);
        assert!(hub_virt.enabled);
        assert!(hub_virt.is_downstream_port_valid(1));
        assert!(hub_virt.is_downstream_port_valid(8));
        assert!(!hub_virt.is_downstream_port_valid(0)); // port 0 invalide
        assert!(!hub_virt.is_downstream_port_valid(9)); // hors limite

        hub_virt.assign_secondary_controller(3);
        assert_eq!(hub_virt.assigned_secondary_id, 3);

        hub_virt.next_ptr_dwords = 20;
        hub_virt.hub_status = 0x5678;
        let encoded_hv = hub_virt.encode();
        assert_eq!(encoded_hv[0] & 0xFF, XHCI_EXT_CAP_HUB_VIRTUALIZATION as u32);
        assert_eq!((encoded_hv[0] >> 8) & 0xFF, 20);
        assert_eq!((encoded_hv[0] >> 16) & 0xFF, 8);
        assert_eq!((encoded_hv[0] >> 24) & 0xFF, 3);
        assert_eq!(encoded_hv[1] & 0x01, 1);
        assert_eq!(encoded_hv[2], 0x5678);

        let parsed_hv = XhciHubVirtualization::parse(&encoded_hv).unwrap();
        assert_eq!(parsed_hv.next_ptr_dwords, 20);
        assert_eq!(parsed_hv.num_downstream_ports, 8);
        assert_eq!(parsed_hv.assigned_secondary_id, 3);
        assert!(parsed_hv.enabled);
        assert_eq!(parsed_hv.hub_status, 0x5678);

        // 24. xHCI 1.2 §7.15 Controller Capability Context & Root Hub Descriptor Extensions
        let mut ctrl_cap = XhciControllerCapabilityContext::new(16, 4);
        assert_eq!(ctrl_cap.root_port_count, 16);
        assert_eq!(ctrl_cap.partition_count, 4);
        assert!(!ctrl_cap.enabled);
        assert!(!ctrl_cap.is_root_port_valid(1));

        ctrl_cap.set_enabled(true);
        assert!(ctrl_cap.enabled);
        assert!(ctrl_cap.is_root_port_valid(1));
        assert!(ctrl_cap.is_root_port_valid(16));
        assert!(!ctrl_cap.is_root_port_valid(0)); // port 0 invalide
        assert!(!ctrl_cap.is_root_port_valid(17)); // hors limite

        assert!(ctrl_cap.is_partition_valid(0));
        assert!(ctrl_cap.is_partition_valid(3));
        assert!(!ctrl_cap.is_partition_valid(4));

        ctrl_cap.set_power_flags(0x00A5);
        assert_eq!(ctrl_cap.root_hub_power_flags, 0x00A5);

        ctrl_cap.next_ptr_dwords = 24;
        ctrl_cap.cap_status = 0x9ABC;
        let encoded_cc = ctrl_cap.encode();
        assert_eq!(
            encoded_cc[0] & 0xFF,
            XHCI_EXT_CAP_CONTROLLER_CAPABILITY_CONTEXT as u32
        );
        assert_eq!((encoded_cc[0] >> 8) & 0xFF, 24);
        assert_eq!((encoded_cc[0] >> 16) & 0xFF, 16);
        assert_eq!((encoded_cc[0] >> 24) & 0xFF, 4);
        assert_eq!(encoded_cc[1] & 0x01, 1);
        assert_eq!(encoded_cc[2], 0x9ABC);
        assert_eq!(encoded_cc[3], 0x00A5);

        let parsed_cc = XhciControllerCapabilityContext::parse(&encoded_cc).unwrap();
        assert_eq!(parsed_cc.next_ptr_dwords, 24);
        assert_eq!(parsed_cc.root_port_count, 16);
        assert_eq!(parsed_cc.partition_count, 4);
        assert!(parsed_cc.enabled);
        assert_eq!(parsed_cc.cap_status, 0x9ABC);
        assert_eq!(parsed_cc.root_hub_power_flags, 0x00A5);

        // 25. xHCI 1.2 §7.16 USB Extended TDM / Bandwidth Negotiation Context Structure
        let mut bw_neg = XhciBandwidthNegotiation::new(16, 75);
        assert_eq!(bw_neg.tdm_channel_count, 16);
        assert_eq!(bw_neg.max_isochronous_bw_percent, 75);
        assert!(!bw_neg.enabled);
        assert!(!bw_neg.is_tdm_channel_valid(0)); // désactivé

        bw_neg.set_enabled(true);
        assert!(bw_neg.enabled);
        assert!(bw_neg.is_tdm_channel_valid(0));
        assert!(bw_neg.is_tdm_channel_valid(15));
        assert!(!bw_neg.is_tdm_channel_valid(16)); // hors limite

        // Allocation de bande passante (max 1000 kb/µframe, 75% = 750 kb/µframe)
        assert!(bw_neg.allocate_bandwidth(500, 1000));
        assert_eq!(bw_neg.allocated_bw_kb_per_uframe, 500);
        // Tenter d'allouer 300 (total 800 > 750) -> doit échouer
        assert!(!bw_neg.allocate_bandwidth(300, 1000));
        assert_eq!(bw_neg.allocated_bw_kb_per_uframe, 500);
        // Libérer 200
        bw_neg.release_bandwidth(200);
        assert_eq!(bw_neg.allocated_bw_kb_per_uframe, 300);

        bw_neg.next_ptr_dwords = 28;
        bw_neg.bw_status = 0xCAFE;
        let encoded_bw = bw_neg.encode();
        assert_eq!(
            encoded_bw[0] & 0xFF,
            XHCI_EXT_CAP_BANDWIDTH_NEGOTIATION as u32
        );
        assert_eq!((encoded_bw[0] >> 8) & 0xFF, 28);
        assert_eq!((encoded_bw[0] >> 16) & 0xFF, 16);
        assert_eq!((encoded_bw[0] >> 24) & 0xFF, 75);
        assert_eq!(encoded_bw[1] & 0x01, 1);
        assert_eq!(encoded_bw[2], 0xCAFE);
        assert_eq!(encoded_bw[3], 300);

        let parsed_bw = XhciBandwidthNegotiation::parse(&encoded_bw).unwrap();
        assert_eq!(parsed_bw.next_ptr_dwords, 28);
        assert_eq!(parsed_bw.tdm_channel_count, 16);
        assert_eq!(parsed_bw.max_isochronous_bw_percent, 75);
        assert!(parsed_bw.enabled);
        assert_eq!(parsed_bw.bw_status, 0xCAFE);
        assert_eq!(parsed_bw.allocated_bw_kb_per_uframe, 300);

        // 26. xHCI 1.2 §7.17 USB Latency Tolerance Messaging (LTM Extensions)
        let mut ltm = XhciLatencyToleranceMessaging::new(8, 2);
        assert_eq!(ltm.ltm_port_count, 8);
        assert_eq!(ltm.latency_tolerance_scale, 2);
        assert!(!ltm.enabled);
        assert!(!ltm.is_ltm_port_valid(1));

        ltm.set_enabled(true);
        assert!(ltm.enabled);
        assert!(ltm.is_ltm_port_valid(1));
        assert!(ltm.is_ltm_port_valid(8));
        assert!(!ltm.is_ltm_port_valid(0)); // port 0 invalide
        assert!(!ltm.is_ltm_port_valid(9)); // hors limite

        ltm.set_max_belt_latency(50);
        assert_eq!(ltm.max_belt_latency, 50);
        // Scale 2 = 1024 ns, 50 * 1024 = 51 200 ns
        assert_eq!(ltm.compute_latency_ns(), 51_200);

        ltm.next_ptr_dwords = 32;
        ltm.ltm_status = 0x1234;
        let encoded_ltm = ltm.encode();
        assert_eq!(
            encoded_ltm[0] & 0xFF,
            XHCI_EXT_CAP_LATENCY_TOLERANCE_MESSAGING as u32
        );
        assert_eq!((encoded_ltm[0] >> 8) & 0xFF, 32);
        assert_eq!((encoded_ltm[0] >> 16) & 0xFF, 8);
        assert_eq!((encoded_ltm[0] >> 24) & 0xFF, 2);
        assert_eq!(encoded_ltm[1] & 0x01, 1);
        assert_eq!(encoded_ltm[2], 0x1234);
        assert_eq!(encoded_ltm[3], 50);

        let parsed_ltm = XhciLatencyToleranceMessaging::parse(&encoded_ltm).unwrap();
        assert_eq!(parsed_ltm.next_ptr_dwords, 32);
        assert_eq!(parsed_ltm.ltm_port_count, 8);
        assert_eq!(parsed_ltm.latency_tolerance_scale, 2);
        assert!(parsed_ltm.enabled);
        assert_eq!(parsed_ltm.ltm_status, 0x1234);
        assert_eq!(parsed_ltm.max_belt_latency, 50);
        assert_eq!(parsed_ltm.compute_latency_ns(), 51_200);

        // 38. Test Capacité Étendue Endpoint / Stream Overrides (§7.18)
        let mut ep_ovr = XhciEndpointStreamOverride::new(3, 4, 3);
        assert_eq!(ep_ovr.slot_id, 3);
        assert_eq!(ep_ovr.endpoint_id, 4);
        assert_eq!(ep_ovr.polling_interval_override, 3);
        assert!(!ep_ovr.enabled);
        assert_eq!(ep_ovr.compute_period_us(), 500); // 125 * 2^(3-1) = 125 * 4 = 500 µs
        assert_eq!(ep_ovr.max_streams_count(), 1);

        ep_ovr.set_enabled(true);
        assert!(ep_ovr.enabled);
        ep_ovr.set_max_primary_streams(4);
        assert_eq!(ep_ovr.max_primary_streams, 4);
        assert_eq!(ep_ovr.max_streams_count(), 16);

        ep_ovr.next_ptr_dwords = 20;
        ep_ovr.stream_status = 0xABCD;
        let encoded_ovr = ep_ovr.encode();
        assert_eq!(
            encoded_ovr[0] & 0xFF,
            XHCI_EXT_CAP_ENDPOINT_POLLING_OVERRIDE as u32
        );
        assert_eq!((encoded_ovr[0] >> 8) & 0xFF, 20);
        assert_eq!((encoded_ovr[0] >> 16) & 0xFF, 3);
        assert_eq!((encoded_ovr[0] >> 24) & 0x1F, 4);
        assert_eq!(encoded_ovr[1] & 0x01, 1);
        assert_eq!((encoded_ovr[1] >> 8) & 0x0F, 3);
        assert_eq!((encoded_ovr[1] >> 16) & 0x0F, 4);
        assert_eq!(encoded_ovr[2], 0xABCD);

        let parsed_ovr = XhciEndpointStreamOverride::parse(&encoded_ovr).unwrap();
        assert_eq!(parsed_ovr.next_ptr_dwords, 20);
        assert_eq!(parsed_ovr.slot_id, 3);
        assert_eq!(parsed_ovr.endpoint_id, 4);
        assert_eq!(parsed_ovr.polling_interval_override, 3);
        assert_eq!(parsed_ovr.max_primary_streams, 4);
        assert!(parsed_ovr.enabled);
        assert_eq!(parsed_ovr.stream_status, 0xABCD);
        assert_eq!(parsed_ovr.compute_period_us(), 500);
        assert_eq!(parsed_ovr.max_streams_count(), 16);

        // 39. Test Capacité Étendue Interrupter Moderation & Vector Overrides (§7.19)
        let mut imod_ovr = XhciInterrupterModerationOverride::new(5, 64, 4000);
        assert_eq!(imod_ovr.interrupter_idx, 5);
        assert_eq!(imod_ovr.msix_vector, 64);
        assert_eq!(imod_ovr.moderation_interval_250ns, 4000);
        assert!(!imod_ovr.enabled);
        assert_eq!(imod_ovr.moderation_interval_ns(), 1_000_000); // 4000 * 250 ns = 1 ms
        assert_eq!(imod_ovr.moderation_interval_us(), 1000);
        assert_eq!(imod_ovr.max_interrupts_per_sec(), 1000);

        imod_ovr.set_enabled(true);
        assert!(imod_ovr.enabled);
        imod_ovr.set_msix_vector(128);
        assert_eq!(imod_ovr.msix_vector, 128);
        imod_ovr.set_moderation_interval(2000); // 500 µs -> 2000 ints/sec
        assert_eq!(imod_ovr.moderation_interval_us(), 500);
        assert_eq!(imod_ovr.max_interrupts_per_sec(), 2000);

        imod_ovr.next_ptr_dwords = 48;
        imod_ovr.override_status = 0x55AA;
        imod_ovr.moderation_counter_250ns = 500;
        let encoded_imod = imod_ovr.encode();
        assert_eq!(
            encoded_imod[0] & 0xFF,
            XHCI_EXT_CAP_INTERRUPTER_MODERATION_OVERRIDE as u32
        );
        assert_eq!((encoded_imod[0] >> 8) & 0xFF, 48);
        assert_eq!((encoded_imod[0] >> 16) & 0x03FF, 5);
        assert_eq!(encoded_imod[1] & 0x01, 1);
        assert_eq!((encoded_imod[1] >> 16) & 0x07FF, 128);
        assert_eq!(encoded_imod[2], 0x55AA);
        assert_eq!(encoded_imod[3] & 0xFFFF, 2000);
        assert_eq!((encoded_imod[3] >> 16) & 0xFFFF, 500);

        let parsed_imod = XhciInterrupterModerationOverride::parse(&encoded_imod).unwrap();
        assert_eq!(parsed_imod.next_ptr_dwords, 48);
        assert_eq!(parsed_imod.interrupter_idx, 5);
        assert_eq!(parsed_imod.msix_vector, 128);
        assert_eq!(parsed_imod.moderation_interval_250ns, 2000);
        assert_eq!(parsed_imod.moderation_counter_250ns, 500);
        assert!(parsed_imod.enabled);
        assert_eq!(parsed_imod.override_status, 0x55AA);
        assert_eq!(parsed_imod.moderation_interval_us(), 500);
        assert_eq!(parsed_imod.max_interrupts_per_sec(), 2000);

        // 40. Test Capacité Étendue Port Speed Mapping Overrides (§7.20)
        let mut ps_ovr = XhciPortSpeedMappingOverride::new(2, 4, 10, 3, true); // Port 2, PSI 4, 10 Gbps SuperSpeed+
        assert_eq!(ps_ovr.port_num, 2);
        assert_eq!(ps_ovr.speed_id, 4);
        assert_eq!(ps_ovr.mantissa, 10);
        assert_eq!(ps_ovr.exponent, 3);
        assert!(ps_ovr.full_duplex);
        assert_eq!(ps_ovr.bitrate_mbps(), 10_000); // 10 * 1000 = 10 000 Mbps
        assert!(!ps_ovr.enabled);

        ps_ovr.set_enabled(true);
        assert!(ps_ovr.enabled);
        ps_ovr.set_bitrate(480, 2); // 480 Mbps
        assert_eq!(ps_ovr.bitrate_mbps(), 480);
        ps_ovr.set_full_duplex(false);
        assert!(!ps_ovr.full_duplex);

        ps_ovr.next_ptr_dwords = 32;
        ps_ovr.override_status = 0x1234_5678;
        ps_ovr.set_bitrate(5, 3); // 5 Gbps
        ps_ovr.set_full_duplex(true);

        let encoded_ps = ps_ovr.encode();
        assert_eq!(
            encoded_ps[0] & 0xFF,
            XHCI_EXT_CAP_PORT_SPEED_MAPPING_OVERRIDE as u32
        );
        assert_eq!((encoded_ps[0] >> 8) & 0xFF, 32);
        assert_eq!((encoded_ps[0] >> 16) & 0xFF, 2);
        assert_eq!((encoded_ps[0] >> 24) & 0xFF, 3);
        assert_eq!(encoded_ps[1] & 0x01, 1);
        assert_eq!((encoded_ps[1] >> 8) & 0x0F, 4);
        assert_eq!((encoded_ps[1] >> 12) & 0x01, 1);
        assert_eq!(encoded_ps[2], 0x1234_5678);
        assert_eq!(encoded_ps[3] & 0xFFFF, 5);
        assert_eq!((encoded_ps[3] >> 16) & 0x03, 3);

        let parsed_ps = XhciPortSpeedMappingOverride::parse(&encoded_ps).unwrap();
        assert_eq!(parsed_ps.next_ptr_dwords, 32);
        assert_eq!(parsed_ps.port_num, 2);
        assert_eq!(parsed_ps.protocol_revision, 3);
        assert_eq!(parsed_ps.speed_id, 4);
        assert_eq!(parsed_ps.mantissa, 5);
        assert_eq!(parsed_ps.exponent, 3);
        assert!(parsed_ps.full_duplex);
        assert!(parsed_ps.enabled);
        assert_eq!(parsed_ps.override_status, 0x1234_5678);
        assert_eq!(parsed_ps.bitrate_mbps(), 5000);

        // 41. Test Capacité Étendue Extended Energy Efficient USB (§7.21)
        let mut eee = XhciExtendedEnergyEfficientUsb::new(8, 250, 4); // 8 ports, 250 µs L1 timer, 4 * 128ns = 512 ns
        assert_eq!(eee.port_count, 8);
        assert_eq!(eee.l1_inactivity_timer_us, 250);
        assert_eq!(eee.fast_wake_threshold_128ns, 4);
        assert!(eee.deep_sleep_supported);
        assert_eq!(eee.fast_wake_latency_ns(), 512);
        assert!(!eee.enabled);
        assert!(eee.is_port_in_range(1));
        assert!(eee.is_port_in_range(8));
        assert!(!eee.is_port_in_range(0));
        assert!(!eee.is_port_in_range(9));

        eee.set_enabled(true);
        assert!(eee.enabled);
        eee.set_l1_inactivity_timer(500);
        assert_eq!(eee.l1_inactivity_timer_us, 500);

        eee.next_ptr_dwords = 40;
        eee.eee_status = 0xABCD_EF01;

        let encoded_eee = eee.encode();
        assert_eq!(
            encoded_eee[0] & 0xFF,
            XHCI_EXT_CAP_EXTENDED_ENERGY_EFFICIENT_USB as u32
        );
        assert_eq!((encoded_eee[0] >> 8) & 0xFF, 40);
        assert_eq!((encoded_eee[0] >> 16) & 0xFF, 8);
        assert_eq!((encoded_eee[0] >> 24) & 0xFF, 4);
        assert_eq!(encoded_eee[1] & 0x01, 1);
        assert_eq!(encoded_eee[2], 0xABCD_EF01);
        assert_eq!(encoded_eee[3] & 0xFFFF, 500);
        assert_eq!((encoded_eee[3] >> 16) & 0x01, 1);

        let parsed_eee = XhciExtendedEnergyEfficientUsb::parse(&encoded_eee).unwrap();
        assert_eq!(parsed_eee.next_ptr_dwords, 40);
        assert_eq!(parsed_eee.port_count, 8);
        assert_eq!(parsed_eee.fast_wake_threshold_128ns, 4);
        assert!(parsed_eee.enabled);
        assert_eq!(parsed_eee.eee_status, 0xABCD_EF01);
        assert_eq!(parsed_eee.l1_inactivity_timer_us, 500);
        assert!(parsed_eee.deep_sleep_supported);
        assert_eq!(parsed_eee.fast_wake_latency_ns(), 512);

        // 42. Test Capacité Étendue Optical Logical Link Control (§7.22)
        let mut oll = XhciOpticalLogicalLink::new(3, 850, 240); // Port 3, 850 nm, 2.40 dBm attenuation
        assert_eq!(oll.port_num, 3);
        assert_eq!(oll.wavelength_nm, 850);
        assert_eq!(oll.optical_attenuation_cdbm, 240);
        assert_eq!(oll.attenuation_db(), 2);
        assert!(!oll.enabled);
        assert!(!oll.loss_of_signal);
        assert!(!oll.is_link_healthy());

        oll.set_enabled(true);
        assert!(oll.enabled);
        assert!(oll.is_link_healthy());

        oll.set_loss_of_signal(true);
        assert!(oll.loss_of_signal);
        assert!(!oll.is_link_healthy());

        oll.set_loss_of_signal(false);
        assert!(oll.is_link_healthy());

        oll.next_ptr_dwords = 44;
        oll.link_status = 0x55AA;

        let encoded_oll = oll.encode();
        assert_eq!(
            encoded_oll[0] & 0xFF,
            XHCI_EXT_CAP_OPTICAL_LOGICAL_LINK as u32
        );
        assert_eq!((encoded_oll[0] >> 8) & 0xFF, 44);
        assert_eq!((encoded_oll[0] >> 16) & 0xFF, 3);
        assert_eq!(encoded_oll[1] & 0x01, 1);
        assert_eq!(encoded_oll[3] & 0xFFFF, 240);
        assert_eq!((encoded_oll[3] >> 16) & 0xFFFF, 850);

        let parsed_oll = XhciOpticalLogicalLink::parse(&encoded_oll).unwrap();
        assert_eq!(parsed_oll.next_ptr_dwords, 44);
        assert_eq!(parsed_oll.port_num, 3);
        assert_eq!(parsed_oll.wavelength_nm, 850);
        assert_eq!(parsed_oll.optical_attenuation_cdbm, 240);
        assert!(parsed_oll.enabled);
        assert!(!parsed_oll.loss_of_signal);
        assert!(parsed_oll.is_link_healthy());
        assert_eq!(parsed_oll.attenuation_db(), 2);

        // 43. Test Capacité Étendue DbC Telemetry & Diagnostics (§7.23)
        let mut telemetry = XhciDbcTelemetry::new(2, 250); // Port 2, 250 kHz
        assert_eq!(telemetry.port_num, 2);
        assert_eq!(telemetry.sampling_rate_khz, 250);
        assert!(!telemetry.enabled);
        assert!(telemetry.circular_buffer);
        assert!(!telemetry.trace_overflow);
        assert_eq!(telemetry.trace_event_count, 0);
        assert!(!telemetry.is_telemetry_healthy());

        telemetry.set_enabled(true);
        assert!(telemetry.enabled);
        assert!(telemetry.is_telemetry_healthy());

        telemetry.record_event();
        telemetry.record_event();
        assert_eq!(telemetry.trace_event_count, 2);

        telemetry.next_ptr_dwords = 48;
        let encoded_tel = telemetry.encode();
        assert_eq!(encoded_tel[0] & 0xFF, XHCI_EXT_CAP_DBC_TELEMETRY as u32);
        assert_eq!((encoded_tel[0] >> 8) & 0xFF, 48);
        assert_eq!((encoded_tel[0] >> 16) & 0xFF, 2);
        assert_eq!(encoded_tel[1] & 0x01, 1);
        assert_eq!(encoded_tel[1] & 0x02, 2);
        assert_eq!(encoded_tel[2] >> 8, 2);
        assert_eq!(encoded_tel[3] & 0xFFFF, 250);

        let parsed_tel = XhciDbcTelemetry::parse(&encoded_tel).unwrap();
        assert_eq!(parsed_tel.next_ptr_dwords, 48);
        assert_eq!(parsed_tel.port_num, 2);
        assert_eq!(parsed_tel.sampling_rate_khz, 250);
        assert!(parsed_tel.enabled);
        assert!(parsed_tel.circular_buffer);
        assert!(!parsed_tel.trace_overflow);
        assert_eq!(parsed_tel.trace_event_count, 2);
        assert!(parsed_tel.is_telemetry_healthy());

        telemetry.reset_trace();
        assert_eq!(telemetry.trace_event_count, 0);
        assert!(!telemetry.trace_overflow);

        // 22. Test XhciSublinkSpeedRouting
        let mut ssrc = XhciSublinkSpeedRouting::new(3, 100);
        assert_eq!(ssrc.port_num, 3);
        assert_eq!(ssrc.upstream_sublink_rate, 100);
        assert_eq!(ssrc.downstream_sublink_rate, 100);
        assert!(ssrc.is_symmetric());
        assert!(!ssrc.enabled);

        ssrc.set_enabled(true);
        ssrc.configure_rates(100, 200);
        assert!(!ssrc.is_symmetric());
        assert_eq!(ssrc.downstream_sublink_rate, 200);

        ssrc.next_ptr_dwords = 52;
        let encoded_ssrc = ssrc.encode();
        assert_eq!(
            encoded_ssrc[0] & 0xFF,
            XHCI_EXT_CAP_SUBLINK_SPEED_ROUTING as u32
        );
        assert_eq!((encoded_ssrc[0] >> 8) & 0xFF, 52);
        assert_eq!((encoded_ssrc[0] >> 16) & 0xFF, 3);
        assert_eq!(encoded_ssrc[1] & 0x01, 1);
        assert_eq!(encoded_ssrc[1] & 0x02, 2);
        assert_eq!(encoded_ssrc[3] & 0xFFFF, 100);
        assert_eq!((encoded_ssrc[3] >> 16) & 0xFFFF, 200);

        let parsed_ssrc = XhciSublinkSpeedRouting::parse(&encoded_ssrc).unwrap();
        assert_eq!(parsed_ssrc.next_ptr_dwords, 52);
        assert_eq!(parsed_ssrc.port_num, 3);
        assert!(parsed_ssrc.enabled);
        assert!(parsed_ssrc.asymmetric_rates_supported);
        assert_eq!(parsed_ssrc.upstream_sublink_rate, 100);
        assert_eq!(parsed_ssrc.downstream_sublink_rate, 200);
        assert!(!parsed_ssrc.is_symmetric());

        // 23. Test XhciExtendedMessageInterruptVector
        let mut mivt = XhciExtendedMessageInterruptVector::new(128, 0);
        assert_eq!(mivt.table_size, 128);
        assert_eq!(mivt.primary_interrupter_index, 0);
        assert!(!mivt.enabled);
        assert!(!mivt.global_mask);

        mivt.set_enabled(true);
        mivt.set_global_mask(true);
        mivt.set_primary_interrupter(42);
        mivt.next_ptr_dwords = 28;
        mivt.table_offset_bir = 0x0000_1004; // offset 0x1000, BIR 4

        assert_eq!(mivt.bir(), 4);
        assert_eq!(mivt.table_offset(), 0x1000);

        let encoded_mivt = mivt.encode();
        assert_eq!(
            encoded_mivt[0] & 0xFF,
            XHCI_EXT_CAP_EXTENDED_MESSAGE_INTERRUPT_VECTOR as u32
        );
        assert_eq!((encoded_mivt[0] >> 8) & 0xFF, 28);
        assert_eq!(encoded_mivt[1] & 0x01, 1);
        assert_eq!(encoded_mivt[1] & 0x02, 2);
        assert_eq!((encoded_mivt[1] >> 16) & 0x07FF, 128);
        assert_eq!(encoded_mivt[2], 0x0000_1004);
        assert_eq!(encoded_mivt[3] & 0x07FF, 42);

        let parsed_mivt = XhciExtendedMessageInterruptVector::parse(&encoded_mivt).unwrap();
        assert_eq!(parsed_mivt.next_ptr_dwords, 28);
        assert!(parsed_mivt.enabled);
        assert!(parsed_mivt.global_mask);
        assert_eq!(parsed_mivt.table_size, 128);
        assert_eq!(parsed_mivt.primary_interrupter_index, 42);
        assert_eq!(parsed_mivt.bir(), 4);
        assert_eq!(parsed_mivt.table_offset(), 0x1000);

        // 24. Test XhciExtendedPortStatusControl
        let mut epsc = XhciExtendedPortStatusControl::new(7);
        assert_eq!(epsc.port_num, 7);
        assert!(!epsc.enabled);
        assert_eq!(epsc.test_mode, 0);
        assert_eq!(epsc.link_speed_protocol, 0);

        epsc.set_enabled(true);
        epsc.set_test_mode(3);
        epsc.set_link_speed_protocol(4);
        epsc.next_ptr_dwords = 36;
        epsc.status = 0x8000_1234;

        let encoded_epsc = epsc.encode();
        assert_eq!(
            encoded_epsc[0] & 0xFF,
            XHCI_EXT_CAP_EXTENDED_PORT_STATUS_CONTROL as u32
        );
        assert_eq!((encoded_epsc[0] >> 8) & 0xFF, 36);
        assert_eq!((encoded_epsc[0] >> 16) & 0xFF, 7);
        assert_eq!(encoded_epsc[1] & 0x01, 1);
        assert_eq!((encoded_epsc[1] >> 16) & 0x0F, 3);
        assert_eq!(encoded_epsc[2], 0x8000_1234);
        assert_eq!(encoded_epsc[3] & 0x0F, 4);

        let parsed_epsc = XhciExtendedPortStatusControl::parse(&encoded_epsc).unwrap();
        assert_eq!(parsed_epsc.next_ptr_dwords, 36);
        assert_eq!(parsed_epsc.port_num, 7);
        assert!(parsed_epsc.enabled);
        assert_eq!(parsed_epsc.test_mode, 3);
        assert_eq!(parsed_epsc.status, 0x8000_1234);
        assert_eq!(parsed_epsc.link_speed_protocol, 4);

        // 25. Test XhciFirmwareDebugTrace
        let mut fdt = XhciFirmwareDebugTrace::new(64);
        assert_eq!(fdt.buffer_size_kb, 64);
        assert!(!fdt.enabled);
        assert_eq!(fdt.trace_level, 1);
        assert_eq!(fdt.subsystem_mask, 0xFFFF);

        fdt.set_enabled(true);
        fdt.set_trace_level(4);
        fdt.set_subsystem_mask(0x1234);
        fdt.next_ptr_dwords = 40;
        fdt.status = 0x0002_0000;
        fdt.trace_counter = 500;

        let encoded_fdt = fdt.encode();
        assert_eq!(
            encoded_fdt[0] & 0xFF,
            XHCI_EXT_CAP_FIRMWARE_DEBUG_TRACE as u32
        );
        assert_eq!((encoded_fdt[0] >> 8) & 0xFF, 40);
        assert_eq!(encoded_fdt[1] & 0x01, 1);
        assert_eq!((encoded_fdt[1] >> 8) & 0x0F, 4);
        assert_eq!((encoded_fdt[1] >> 16) & 0xFFFF, 0x1234);
        assert_eq!(encoded_fdt[2], 0x0002_0000);
        assert_eq!(encoded_fdt[3] & 0xFFFF, 64);
        assert_eq!((encoded_fdt[3] >> 16) & 0xFFFF, 500);

        let parsed_fdt = XhciFirmwareDebugTrace::parse(&encoded_fdt).unwrap();
        assert_eq!(parsed_fdt.next_ptr_dwords, 40);
        assert!(parsed_fdt.enabled);
        assert_eq!(parsed_fdt.trace_level, 4);
        assert_eq!(parsed_fdt.subsystem_mask, 0x1234);
        assert_eq!(parsed_fdt.status, 0x0002_0000);
        assert_eq!(parsed_fdt.buffer_size_kb, 64);
        assert_eq!(parsed_fdt.trace_counter, 500);

        // 26. Test XhciOffloadBufferManagement
        let mut obm = XhciOffloadBufferManagement::new(8, 2048);
        assert_eq!(obm.buffer_ring_count, 8);
        assert_eq!(obm.max_segment_kb, 2048);
        assert_eq!(obm.block_alignment, 4096);
        assert_eq!(obm.watermark_threshold_kb, 64);
        assert!(!obm.enabled);

        obm.set_enabled(true);
        obm.set_watermark_threshold(128);
        obm.next_ptr_dwords = 44;
        obm.status = 0x0001_8000;

        let encoded_obm = obm.encode();
        assert_eq!(
            encoded_obm[0] & 0xFF,
            XHCI_EXT_CAP_OFFLOAD_BUFFER_MANAGEMENT as u32
        );
        assert_eq!((encoded_obm[0] >> 8) & 0xFF, 44);
        assert_eq!(encoded_obm[1] & 0x01, 1);
        assert_eq!((encoded_obm[1] >> 8) & 0xFF, 8);
        assert_eq!((encoded_obm[1] >> 16) & 0xFFFF, 128);
        assert_eq!(encoded_obm[2], 0x0001_8000);
        assert_eq!(encoded_obm[3] & 0xFFFF, 4096);
        assert_eq!((encoded_obm[3] >> 16) & 0xFFFF, 2048);

        let parsed_obm = XhciOffloadBufferManagement::parse(&encoded_obm).unwrap();
        assert_eq!(parsed_obm.next_ptr_dwords, 44);
        assert!(parsed_obm.enabled);
        assert_eq!(parsed_obm.buffer_ring_count, 8);
        assert_eq!(parsed_obm.watermark_threshold_kb, 128);
        assert_eq!(parsed_obm.status, 0x0001_8000);
        assert_eq!(parsed_obm.block_alignment, 4096);
        assert_eq!(parsed_obm.max_segment_kb, 2048);

        // 27. Test XhciHostControllerSystemPower
        let mut hc_sp = XhciHostControllerSystemPower::new(3, 250);
        assert_eq!(hc_sp.power_state, 3);
        assert_eq!(hc_sp.wakeup_delay_us, 250);
        assert_eq!(hc_sp.wake_mask, 0x00FF);
        assert_eq!(hc_sp.auto_suspend_ms, 100);
        assert!(!hc_sp.enabled);
        assert!(!hc_sp.pme_enabled);

        hc_sp.set_enabled(true);
        hc_sp.set_pme_enabled(true);
        hc_sp.set_power_state(4);
        hc_sp.set_auto_suspend_ms(500);
        hc_sp.next_ptr_dwords = 48;
        hc_sp.status = 0x0000_CAFE;

        let encoded_hc_sp = hc_sp.encode();
        assert_eq!(
            encoded_hc_sp[0] & 0xFF,
            XHCI_EXT_CAP_HOST_CONTROLLER_SYSTEM_POWER as u32
        );
        assert_eq!((encoded_hc_sp[0] >> 8) & 0xFF, 48);
        assert_eq!(encoded_hc_sp[1] & 0x01, 1);
        assert_eq!(encoded_hc_sp[1] & 0x02, 2);
        assert_eq!((encoded_hc_sp[1] >> 8) & 0x07, 4);
        assert_eq!((encoded_hc_sp[1] >> 16) & 0xFFFF, 250);
        assert_eq!(encoded_hc_sp[2], 0x0000_CAFE);
        assert_eq!(encoded_hc_sp[3] & 0xFFFF, 0x00FF);
        assert_eq!((encoded_hc_sp[3] >> 16) & 0xFFFF, 500);

        let parsed_hc_sp = XhciHostControllerSystemPower::parse(&encoded_hc_sp).unwrap();
        assert_eq!(parsed_hc_sp.next_ptr_dwords, 48);
        assert!(parsed_hc_sp.enabled);
        assert!(parsed_hc_sp.pme_enabled);
        assert_eq!(parsed_hc_sp.power_state, 4);
        assert_eq!(parsed_hc_sp.wakeup_delay_us, 250);
        assert_eq!(parsed_hc_sp.status, 0x0000_CAFE);
        assert_eq!(parsed_hc_sp.wake_mask, 0x00FF);
        assert_eq!(parsed_hc_sp.auto_suspend_ms, 500);

        // 28. Test XhciRootHubTopologyDescriptor
        let mut rhtd = XhciRootHubTopologyDescriptor::new(4, 4);
        assert_eq!(rhtd.usb2_port_count, 4);
        assert_eq!(rhtd.usb3_port_count, 4);
        assert_eq!(rhtd.routing_mask, 0xFFFF);
        assert_eq!(rhtd.max_port_power_2ma, 450);
        assert!(!rhtd.enabled);
        assert!(!rhtd.multi_tier_routing);

        rhtd.set_enabled(true);
        rhtd.set_multi_tier_routing(true);
        rhtd.set_max_port_power_2ma(750); // 1.5A
        rhtd.next_ptr_dwords = 52;
        rhtd.status = 0x0004_BEEF;

        let encoded_rhtd = rhtd.encode();
        assert_eq!(
            encoded_rhtd[0] & 0xFF,
            XHCI_EXT_CAP_ROOT_HUB_TOPOLOGY_DESCRIPTOR as u32
        );
        assert_eq!((encoded_rhtd[0] >> 8) & 0xFF, 52);
        assert_eq!(encoded_rhtd[1] & 0x01, 1);
        assert_eq!(encoded_rhtd[1] & 0x02, 2);
        assert_eq!((encoded_rhtd[1] >> 8) & 0xFF, 4);
        assert_eq!((encoded_rhtd[1] >> 16) & 0xFF, 4);
        assert_eq!(encoded_rhtd[2], 0x0004_BEEF);
        assert_eq!(encoded_rhtd[3] & 0xFFFF, 0xFFFF);
        assert_eq!((encoded_rhtd[3] >> 16) & 0xFFFF, 750);

        let parsed_rhtd = XhciRootHubTopologyDescriptor::parse(&encoded_rhtd).unwrap();
        assert_eq!(parsed_rhtd.next_ptr_dwords, 52);
        assert!(parsed_rhtd.enabled);
        assert!(parsed_rhtd.multi_tier_routing);
        assert_eq!(parsed_rhtd.usb2_port_count, 4);
        assert_eq!(parsed_rhtd.usb3_port_count, 4);
        assert_eq!(parsed_rhtd.status, 0x0004_BEEF);
        assert_eq!(parsed_rhtd.routing_mask, 0xFFFF);
        assert_eq!(parsed_rhtd.max_port_power_2ma, 750);

        // 29. Test XhciUsb4PcieTunneling
        let mut usb4_pt = XhciUsb4PcieTunneling::new(2, 4, 4); // 2 adaptateurs, Gen4, x4
        assert_eq!(usb4_pt.adapter_count, 2);
        assert_eq!(usb4_pt.link_speed_gen, 4);
        assert_eq!(usb4_pt.link_width, 4);
        assert_eq!(usb4_pt.upstream_bandwidth_mbps, 10000);
        assert_eq!(usb4_pt.downstream_bandwidth_mbps, 10000);
        assert!(!usb4_pt.enabled);
        assert!(!usb4_pt.asymmetric_bandwidth_supported);

        usb4_pt.set_enabled(true);
        usb4_pt.set_asymmetric_bandwidth_supported(true);
        usb4_pt.set_bandwidth(31500, 15750); // 31.5 Gbps up, 15.75 Gbps down
        usb4_pt.next_ptr_dwords = 56;
        usb4_pt.status = 0x0008_FEED;

        let encoded_usb4 = usb4_pt.encode();
        assert_eq!(
            encoded_usb4[0] & 0xFF,
            XHCI_EXT_CAP_USB4_PCIE_TUNNELING as u32
        );
        assert_eq!((encoded_usb4[0] >> 8) & 0xFF, 56);
        assert_eq!(encoded_usb4[1] & 0x01, 1);
        assert_eq!(encoded_usb4[1] & 0x02, 2);
        assert_eq!((encoded_usb4[1] >> 8) & 0xFF, 2);
        assert_eq!((encoded_usb4[1] >> 16) & 0x0F, 4);
        assert_eq!((encoded_usb4[1] >> 20) & 0x1F, 4);
        assert_eq!(encoded_usb4[2], 0x0008_FEED);
        assert_eq!(encoded_usb4[3] & 0xFFFF, 31500);
        assert_eq!((encoded_usb4[3] >> 16) & 0xFFFF, 15750);

        let parsed_usb4 = XhciUsb4PcieTunneling::parse(&encoded_usb4).unwrap();
        assert_eq!(parsed_usb4.next_ptr_dwords, 56);
        assert!(parsed_usb4.enabled);
        assert!(parsed_usb4.asymmetric_bandwidth_supported);
        assert_eq!(parsed_usb4.adapter_count, 2);
        assert_eq!(parsed_usb4.link_speed_gen, 4);
        assert_eq!(parsed_usb4.link_width, 4);
        assert_eq!(parsed_usb4.status, 0x0008_FEED);
        assert_eq!(parsed_usb4.upstream_bandwidth_mbps, 31500);
        assert_eq!(parsed_usb4.downstream_bandwidth_mbps, 15750);

        // 30. Test XhciUsb4DisplayPortTunneling
        let mut usb4_dp = XhciUsb4DisplayPortTunneling::new(1, 4, 4); // 1 adaptateur, HBR3, 4 lanes
        assert_eq!(usb4_dp.adapter_count, 1);
        assert_eq!(usb4_dp.dp_link_rate, 4);
        assert_eq!(usb4_dp.lane_count, 4);
        assert_eq!(usb4_dp.allocated_bandwidth_mbps, 21600);
        assert_eq!(usb4_dp.max_color_depth_bpp, 30);
        assert!(!usb4_dp.enabled);
        assert!(!usb4_dp.mst_supported);

        usb4_dp.set_enabled(true);
        usb4_dp.set_mst_supported(true);
        usb4_dp.set_display_config(32400, 36); // UHBR10 32.4 Gbps, 12-bit HDR
        usb4_dp.next_ptr_dwords = 60;
        usb4_dp.status = 0x0001_CAFE;

        let encoded_dp = usb4_dp.encode();
        assert_eq!(
            encoded_dp[0] & 0xFF,
            XHCI_EXT_CAP_USB4_DISPLAYPORT_TUNNELING as u32
        );
        assert_eq!((encoded_dp[0] >> 8) & 0xFF, 60);
        assert_eq!(encoded_dp[1] & 0x01, 1);
        assert_eq!(encoded_dp[1] & 0x02, 2);
        assert_eq!((encoded_dp[1] >> 8) & 0xFF, 1);
        assert_eq!((encoded_dp[1] >> 16) & 0x0F, 4);
        assert_eq!((encoded_dp[1] >> 20) & 0x0F, 4);
        assert_eq!(encoded_dp[2], 0x0001_CAFE);
        assert_eq!(encoded_dp[3] & 0xFFFF, 32400);
        assert_eq!((encoded_dp[3] >> 16) & 0xFFFF, 36);

        let parsed_dp = XhciUsb4DisplayPortTunneling::parse(&encoded_dp).unwrap();
        assert_eq!(parsed_dp.next_ptr_dwords, 60);
        assert!(parsed_dp.enabled);
        assert!(parsed_dp.mst_supported);
        assert_eq!(parsed_dp.adapter_count, 1);
        assert_eq!(parsed_dp.dp_link_rate, 4);
        assert_eq!(parsed_dp.lane_count, 4);
        assert_eq!(parsed_dp.status, 0x0001_CAFE);
        assert_eq!(parsed_dp.allocated_bandwidth_mbps, 32400);
        assert_eq!(parsed_dp.max_color_depth_bpp, 36);

        // 31. Test XhciUsb4HostInterfaceManagement
        let mut usb4_hi = XhciUsb4HostInterfaceManagement::new(1, 4); // Domain 1, Gen3x2
        assert_eq!(usb4_hi.local_domain_id, 1);
        assert_eq!(usb4_hi.link_speed_gen, 4);
        assert_eq!(usb4_hi.peer_domain_id, 0);
        assert_eq!(usb4_hi.max_mtu_bytes, 4096);
        assert_eq!(usb4_hi.max_bandwidth_mbps, 40000);
        assert!(!usb4_hi.enabled);
        assert!(!usb4_hi.interdomain_enabled);

        usb4_hi.set_enabled(true);
        usb4_hi.establish_peer_link(2, 8192, 40000); // Peer Domain 2, MTU 8192 (Jumbo), 40 Gbps
        usb4_hi.next_ptr_dwords = 64;
        usb4_hi.status = 0x0002_BEEF;

        let encoded_hi = usb4_hi.encode();
        assert_eq!(
            encoded_hi[0] & 0xFF,
            XHCI_EXT_CAP_USB4_HOST_INTERFACE_MANAGEMENT as u32
        );
        assert_eq!((encoded_hi[0] >> 8) & 0xFF, 64);
        assert_eq!(encoded_hi[1] & 0x01, 1);
        assert_eq!(encoded_hi[1] & 0x02, 2);
        assert_eq!((encoded_hi[1] >> 8) & 0xFF, 1); // local domain
        assert_eq!((encoded_hi[1] >> 16) & 0xFF, 2); // peer domain
        assert_eq!((encoded_hi[1] >> 24) & 0x0F, 4); // link gen
        assert_eq!(encoded_hi[2], 0x0002_BEEF);
        assert_eq!(encoded_hi[3] & 0xFFFF, 8192);
        assert_eq!((encoded_hi[3] >> 16) & 0xFFFF, 40000);

        let parsed_hi = XhciUsb4HostInterfaceManagement::parse(&encoded_hi).unwrap();
        assert_eq!(parsed_hi.next_ptr_dwords, 64);
        assert!(parsed_hi.enabled);
        assert!(parsed_hi.interdomain_enabled);
        assert_eq!(parsed_hi.local_domain_id, 1);
        assert_eq!(parsed_hi.peer_domain_id, 2);
        assert_eq!(parsed_hi.link_speed_gen, 4);
        assert_eq!(parsed_hi.status, 0x0002_BEEF);
        assert_eq!(parsed_hi.max_mtu_bytes, 8192);
        assert_eq!(parsed_hi.max_bandwidth_mbps, 40000);

        // 32. Test XhciUsb4RouterConfiguration
        let mut usb4_router = XhciUsb4RouterConfiguration::new(64, 6, 2); // 64 adaptateurs, max 6 hops, USB4 2.0
        assert_eq!(usb4_router.max_adapters, 64);
        assert_eq!(usb4_router.max_topology_depth, 6);
        assert_eq!(usb4_router.router_revision, 2);
        assert_eq!(usb4_router.total_bandwidth_gbps, 80);
        assert_eq!(usb4_router.active_adapters, 0);
        assert!(!usb4_router.enabled);
        assert!(usb4_router.tmu_supported);
        assert!(usb4_router.qos_supported);

        usb4_router.set_enabled(true);
        usb4_router.update_active_topology(12, 120); // 12 adaptateurs actifs, 120 Gbps agrégé
        usb4_router.next_ptr_dwords = 68;
        usb4_router.status = 0x0003_FEED;

        let encoded_router = usb4_router.encode();
        assert_eq!(
            encoded_router[0] & 0xFF,
            XHCI_EXT_CAP_USB4_ROUTER_CONFIGURATION as u32
        );
        assert_eq!((encoded_router[0] >> 8) & 0xFF, 68);
        assert_eq!(encoded_router[1] & 0x01, 1);
        assert_eq!(encoded_router[1] & 0x02, 2);
        assert_eq!(encoded_router[1] & 0x04, 4);
        assert_eq!((encoded_router[1] >> 8) & 0xFF, 64);
        assert_eq!((encoded_router[1] >> 16) & 0xFF, 6);
        assert_eq!((encoded_router[1] >> 24) & 0x0F, 2);
        assert_eq!(encoded_router[2], 0x0003_FEED);
        assert_eq!(encoded_router[3] & 0xFFFF, 120);
        assert_eq!((encoded_router[3] >> 16) & 0xFFFF, 12);

        let parsed_router = XhciUsb4RouterConfiguration::parse(&encoded_router).unwrap();
        assert_eq!(parsed_router.next_ptr_dwords, 68);
        assert!(parsed_router.enabled);
        assert!(parsed_router.tmu_supported);
        assert!(parsed_router.qos_supported);
        assert_eq!(parsed_router.max_adapters, 64);
        assert_eq!(parsed_router.max_topology_depth, 6);
        assert_eq!(parsed_router.router_revision, 2);
        assert_eq!(parsed_router.status, 0x0003_FEED);
        assert_eq!(parsed_router.total_bandwidth_gbps, 120);
        assert_eq!(parsed_router.active_adapters, 12);

        // 33. Test XhciUsb4TimeSyncUnit
        let mut usb4_tmu = XhciUsb4TimeSyncUnit::new(true, 4); // Grandmaster, sync 4ms
        assert!(usb4_tmu.is_grandmaster);
        assert_eq!(usb4_tmu.sync_interval_ms, 4);
        assert_eq!(usb4_tmu.propagation_delay_ns, 25);
        assert!(usb4_tmu.high_accuracy_mode);
        assert!(!usb4_tmu.enabled);

        usb4_tmu.set_enabled(true);
        usb4_tmu.update_propagation_delay(38);
        usb4_tmu.set_reference_time(0x1234_5678);
        usb4_tmu.next_ptr_dwords = 72;
        usb4_tmu.status = 0x0004_CAFE;

        let encoded_tmu = usb4_tmu.encode();
        assert_eq!(
            encoded_tmu[0] & 0xFF,
            XHCI_EXT_CAP_USB4_TIME_SYNCHRONIZATION_UNIT as u32
        );
        assert_eq!((encoded_tmu[0] >> 8) & 0xFF, 72);
        assert_eq!(encoded_tmu[1] & 0x01, 1);
        assert_eq!(encoded_tmu[1] & 0x02, 2);
        assert_eq!(encoded_tmu[1] & 0x04, 4);
        assert_eq!((encoded_tmu[1] >> 8) & 0x0F, 4);
        assert_eq!((encoded_tmu[1] >> 16) & 0xFFFF, 38);
        assert_eq!(encoded_tmu[2], 0x0004_CAFE);
        assert_eq!(encoded_tmu[3], 0x1234_5678);

        let parsed_tmu = XhciUsb4TimeSyncUnit::parse(&encoded_tmu).unwrap();
        assert_eq!(parsed_tmu.next_ptr_dwords, 72);
        assert!(parsed_tmu.enabled);
        assert!(parsed_tmu.high_accuracy_mode);
        assert!(parsed_tmu.is_grandmaster);
        assert_eq!(parsed_tmu.sync_interval_ms, 4);
        assert_eq!(parsed_tmu.propagation_delay_ns, 38);
        assert_eq!(parsed_tmu.status, 0x0004_CAFE);
        assert_eq!(parsed_tmu.reference_time_lo, 0x1234_5678);

        // 34. Test XhciUsb4PowerManagementTunneling
        let mut usb4_pmtc = XhciUsb4PowerManagementTunneling::new(0x07, true);
        assert_eq!(usb4_pmtc.cl_states_supported, 0x07);
        assert!(usb4_pmtc.dynamic_bandwidth_allocation);
        assert_eq!(usb4_pmtc.sleep_threshold_us, 50);
        assert_eq!(usb4_pmtc.pcie_tunnel_priority, 2);
        assert_eq!(usb4_pmtc.dp_tunnel_priority, 3);
        assert_eq!(usb4_pmtc.usb3_tunnel_priority, 1);
        assert!(!usb4_pmtc.enabled);

        usb4_pmtc.set_enabled(true);
        usb4_pmtc.set_tunnel_priorities(1, 2, 0);
        usb4_pmtc.set_sleep_threshold(35);
        usb4_pmtc.next_ptr_dwords = 76;
        usb4_pmtc.status = 0x0005_BEEF;

        let encoded_pmtc = usb4_pmtc.encode();
        assert_eq!(
            encoded_pmtc[0] & 0xFF,
            XHCI_EXT_CAP_USB4_POWER_MANAGEMENT_TUNNELING as u32
        );
        assert_eq!((encoded_pmtc[0] >> 8) & 0xFF, 76);
        assert_eq!(encoded_pmtc[1] & 0x01, 1);
        assert_eq!((encoded_pmtc[1] >> 1) & 0x07, 7);
        assert_eq!(encoded_pmtc[1] & 0x10, 0x10);
        assert_eq!((encoded_pmtc[1] >> 8) & 0xFF, 35);
        assert_eq!((encoded_pmtc[1] >> 16) & 0x03, 1);
        assert_eq!((encoded_pmtc[1] >> 18) & 0x03, 2);
        assert_eq!((encoded_pmtc[1] >> 20) & 0x03, 0);
        assert_eq!(encoded_pmtc[2], 0x0005_BEEF);
        assert_eq!(encoded_pmtc[3], 0x0A14_2800);

        let parsed_pmtc = XhciUsb4PowerManagementTunneling::parse(&encoded_pmtc).unwrap();
        assert_eq!(parsed_pmtc.next_ptr_dwords, 76);
        assert!(parsed_pmtc.enabled);
        assert_eq!(parsed_pmtc.cl_states_supported, 7);
        assert!(parsed_pmtc.dynamic_bandwidth_allocation);
        assert_eq!(parsed_pmtc.sleep_threshold_us, 35);
        assert_eq!(parsed_pmtc.pcie_tunnel_priority, 1);
        assert_eq!(parsed_pmtc.dp_tunnel_priority, 2);
        assert_eq!(parsed_pmtc.usb3_tunnel_priority, 0);
        assert_eq!(parsed_pmtc.status, 0x0005_BEEF);
        assert_eq!(parsed_pmtc.allocated_bandwidth, 0x0A14_2800);

        // 35. Test XhciUsb4DpAltModeConfig
        let mut usb4_dp_alt = XhciUsb4DpAltModeConfig::new(2, 4, 3);
        assert_eq!(usb4_dp_alt.physical_port_id, 2);
        assert_eq!(usb4_dp_alt.lane_count, 4);
        assert_eq!(usb4_dp_alt.link_rate, 3);
        assert!(usb4_dp_alt.mst_supported);
        assert!(usb4_dp_alt.hdcp_supported);
        assert!(!usb4_dp_alt.enabled);

        usb4_dp_alt.set_enabled(true);
        usb4_dp_alt.configure_lanes(2, 2);
        usb4_dp_alt.next_ptr_dwords = 80;
        usb4_dp_alt.status = 0x0006_BEEF;

        let encoded_dp_alt = usb4_dp_alt.encode();
        assert_eq!(
            encoded_dp_alt[0] & 0xFF,
            XHCI_EXT_CAP_USB4_DP_ALT_MODE_CONFIGURATION as u32
        );
        assert_eq!((encoded_dp_alt[0] >> 8) & 0xFF, 80);
        assert_eq!(encoded_dp_alt[1] & 0x01, 1);
        assert_eq!((encoded_dp_alt[1] >> 1) & 0x03, 1); // 2 lanes -> bits 01b
        assert_eq!((encoded_dp_alt[1] >> 3) & 0x07, 2); // rate 2
        assert_eq!(encoded_dp_alt[1] & 0x40, 0x40); // mst
        assert_eq!(encoded_dp_alt[1] & 0x80, 0x80); // hdcp
        assert_eq!((encoded_dp_alt[1] >> 8) & 0xFF, 2); // port 2
        assert_eq!(encoded_dp_alt[2], 0x0006_BEEF);
        assert_eq!(encoded_dp_alt[3], 0x0000_0101);

        let parsed_dp_alt = XhciUsb4DpAltModeConfig::parse(&encoded_dp_alt).unwrap();
        assert_eq!(parsed_dp_alt.next_ptr_dwords, 80);
        assert!(parsed_dp_alt.enabled);
        assert_eq!(parsed_dp_alt.lane_count, 2);
        assert_eq!(parsed_dp_alt.link_rate, 2);
        assert!(parsed_dp_alt.mst_supported);
        assert!(parsed_dp_alt.hdcp_supported);
        assert_eq!(parsed_dp_alt.physical_port_id, 2);
        assert_eq!(parsed_dp_alt.status, 0x0006_BEEF);
        assert_eq!(parsed_dp_alt.aux_channel_config, 0x0000_0101);

        // 36. Test XhciUsb4SecurityConfig
        let mut usb4_sec = XhciUsb4SecurityConfig::new(2, 3, 2); // SL2, Domain 3, AES-256-GCM
        assert_eq!(usb4_sec.security_level, 2);
        assert_eq!(usb4_sec.domain_id, 3);
        assert_eq!(usb4_sec.crypto_cipher, 2);
        assert!(usb4_sec.cert_auth_required);
        assert!(usb4_sec.dma_guard_enabled);
        assert!(!usb4_sec.link_encryption_enabled);

        usb4_sec.set_encryption(true);
        usb4_sec.set_session_token(0xA5A5_5A5A);
        usb4_sec.next_ptr_dwords = 84;
        usb4_sec.status = 0x0007_BEEF;

        let encoded_sec = usb4_sec.encode();
        assert_eq!(
            encoded_sec[0] & 0xFF,
            XHCI_EXT_CAP_USB4_SECURITY_CONFIGURATION as u32
        );
        assert_eq!((encoded_sec[0] >> 8) & 0xFF, 84);
        assert_eq!(encoded_sec[1] & 0x01, 1); // link encryption
        assert_eq!((encoded_sec[1] >> 1) & 0x03, 2); // SL2
        assert_eq!(encoded_sec[1] & 0x10, 0x10); // cert auth
        assert_eq!(encoded_sec[1] & 0x20, 0x20); // dma guard
        assert_eq!((encoded_sec[1] >> 6) & 0x07, 2); // cipher
        assert_eq!((encoded_sec[1] >> 16) & 0xFF, 3); // domain 3
        assert_eq!(encoded_sec[2], 0x0007_BEEF);
        assert_eq!(encoded_sec[3], 0xA5A5_5A5A);

        // Test Capacité Étendue xHCI 1.2 / USB4 Inter-Domain Transport (§7.39)
        let mut usb4_idt = XhciUsb4InterDomainTransport::new(5, 12, 2048);
        assert_eq!(usb4_idt.peer_domain_id, 5);
        assert_eq!(usb4_idt.peer_router_id, 12);
        assert_eq!(usb4_idt.max_packet_size, 2048);
        assert!(!usb4_idt.transport_enabled);
        assert!(usb4_idt.xdomain_net_supported);

        usb4_idt.set_transport_enabled(true);
        usb4_idt.set_peer_target(7, 14, 3);
        usb4_idt.configure_channels(4096, 4);
        usb4_idt.next_ptr_dwords = 88;
        usb4_idt.status = 0xCAFE_BABE;

        let encoded_idt = usb4_idt.encode();
        assert_eq!(
            encoded_idt[0] & 0xFF,
            XHCI_EXT_CAP_USB4_INTER_DOMAIN_TRANSPORT as u32
        );
        assert_eq!((encoded_idt[0] >> 8) & 0xFF, 88);
        assert_eq!(encoded_idt[1] & 0x01, 1); // enabled
        assert_eq!((encoded_idt[1] >> 8) & 0xFF, 7); // peer domain
        assert_eq!((encoded_idt[1] >> 16) & 0xFF, 14); // peer router
        assert_eq!((encoded_idt[1] >> 24) & 0xFF, 3); // doorbell
        assert_eq!(encoded_idt[2], 0xCAFE_BABE);
        assert_eq!(encoded_idt[3] & 0xFFFF, 4096);
        assert_eq!((encoded_idt[3] >> 16) & 0xFF, 4);

        let parsed_idt = XhciUsb4InterDomainTransport::parse(&encoded_idt).unwrap();
        assert_eq!(parsed_idt.next_ptr_dwords, 88);
        assert!(parsed_idt.transport_enabled);
        assert_eq!(parsed_idt.peer_domain_id, 7);
        assert_eq!(parsed_idt.peer_router_id, 14);
        assert_eq!(parsed_idt.doorbell_index, 3);
        assert_eq!(parsed_idt.status, 0xCAFE_BABE);
        assert_eq!(parsed_idt.max_packet_size, 4096);
        assert_eq!(parsed_idt.channel_count, 4);

        let parsed_sec = XhciUsb4SecurityConfig::parse(&encoded_sec).unwrap();
        assert_eq!(parsed_sec.next_ptr_dwords, 84);
        assert!(parsed_sec.link_encryption_enabled);
        assert_eq!(parsed_sec.security_level, 2);
        assert!(parsed_sec.cert_auth_required);
        assert!(parsed_sec.dma_guard_enabled);
        assert_eq!(parsed_sec.crypto_cipher, 2);
        assert_eq!(parsed_sec.domain_id, 3);
        assert_eq!(parsed_sec.status, 0x0007_BEEF);
        assert_eq!(parsed_sec.session_token, 0xA5A5_5A5A);

        // Test Capacité Étendue xHCI 1.2 / USB4 PCIe Adapter Configuration (§7.40)
        let mut usb4_pcie_cfg = XhciUsb4PcieAdapterConfig::new(3, 1, 4, 8);
        assert_eq!(usb4_pcie_cfg.adapter_num, 3);
        assert_eq!(usb4_pcie_cfg.router_id, 1);
        assert_eq!(usb4_pcie_cfg.max_link_gen, 4);
        assert_eq!(usb4_pcie_cfg.max_link_width, 8);
        assert_eq!(usb4_pcie_cfg.guaranteed_bandwidth_mbps, 16000);
        assert_eq!(usb4_pcie_cfg.tlp_buffer_credits, 64);
        assert!(!usb4_pcie_cfg.adapter_enabled);
        assert!(usb4_pcie_cfg.msi_virtualization_supported);
        assert!(!usb4_pcie_cfg.aspm_l1_enabled);
        assert!(usb4_pcie_cfg.tlp_filtering_enabled);

        usb4_pcie_cfg.set_adapter_enabled(true);
        usb4_pcie_cfg.set_aspm_l1_enabled(true);
        usb4_pcie_cfg.configure_bandwidth_credits(32000, 128);
        usb4_pcie_cfg.next_ptr_dwords = 92;
        usb4_pcie_cfg.status = 0x55AA_1234;

        let encoded_pcfg = usb4_pcie_cfg.encode();
        assert_eq!(
            encoded_pcfg[0] & 0xFF,
            XHCI_EXT_CAP_USB4_PCIE_ADAPTER_CONFIGURATION as u32
        );
        assert_eq!((encoded_pcfg[0] >> 8) & 0xFF, 92);
        assert_eq!(encoded_pcfg[1] & 0x01, 1); // enabled
        assert_eq!(encoded_pcfg[1] & 0x02, 2); // msi virt
        assert_eq!(encoded_pcfg[1] & 0x04, 4); // aspm l1
        assert_eq!(encoded_pcfg[1] & 0x08, 8); // tlp filter
        assert_eq!((encoded_pcfg[1] >> 8) & 0xFF, 3); // adapter_num
        assert_eq!((encoded_pcfg[1] >> 16) & 0xFF, 1); // router_id
        assert_eq!((encoded_pcfg[1] >> 24) & 0xFF, 128); // tlp credits
        assert_eq!(encoded_pcfg[2], 0x55AA_1234);
        assert_eq!(encoded_pcfg[3] & 0xFFFF, 32000);
        assert_eq!((encoded_pcfg[3] >> 16) & 0xFF, 4);
        assert_eq!((encoded_pcfg[3] >> 24) & 0xFF, 8);

        let parsed_pcfg = XhciUsb4PcieAdapterConfig::parse(&encoded_pcfg).unwrap();
        assert_eq!(parsed_pcfg.next_ptr_dwords, 92);
        assert!(parsed_pcfg.adapter_enabled);
        assert!(parsed_pcfg.msi_virtualization_supported);
        assert!(parsed_pcfg.aspm_l1_enabled);
        assert!(parsed_pcfg.tlp_filtering_enabled);
        assert_eq!(parsed_pcfg.adapter_num, 3);
        assert_eq!(parsed_pcfg.router_id, 1);
        assert_eq!(parsed_pcfg.tlp_buffer_credits, 128);
        assert_eq!(parsed_pcfg.status, 0x55AA_1234);
        assert_eq!(parsed_pcfg.guaranteed_bandwidth_mbps, 32000);
        assert_eq!(parsed_pcfg.max_link_gen, 4);
        assert_eq!(parsed_pcfg.max_link_width, 8);

        // Test Capacité Étendue xHCI 1.2 / USB4 DisplayPort Adapter Configuration (§7.41)
        let mut usb4_dp_cfg = XhciUsb4DpAdapterConfig::new(2, 1, true, 4, 4);
        assert_eq!(usb4_dp_cfg.adapter_num, 2);
        assert_eq!(usb4_dp_cfg.router_id, 1);
        assert!(usb4_dp_cfg.is_dp_in_adapter);
        assert_eq!(usb4_dp_cfg.lane_count, 4);
        assert_eq!(usb4_dp_cfg.max_link_rate, 4);
        assert_eq!(usb4_dp_cfg.video_bandwidth_mbps, 21600);
        assert_eq!(usb4_dp_cfg.color_depth_bpc, 8);
        assert!(!usb4_dp_cfg.adapter_enabled);
        assert!(usb4_dp_cfg.mst_supported);
        assert!(usb4_dp_cfg.dp_aux_tunneling_enabled);
        assert!(!usb4_dp_cfg.hdcp_enabled);

        usb4_dp_cfg.set_adapter_enabled(true);
        usb4_dp_cfg.set_hdcp_enabled(true);
        usb4_dp_cfg.configure_video_stream(32400, 10);
        usb4_dp_cfg.next_ptr_dwords = 96;
        usb4_dp_cfg.status = 0x1234_ABCD;

        let encoded_dp_cfg = usb4_dp_cfg.encode();
        assert_eq!(
            encoded_dp_cfg[0] & 0xFF,
            XHCI_EXT_CAP_USB4_DP_ADAPTER_CONFIGURATION as u32
        );
        assert_eq!((encoded_dp_cfg[0] >> 8) & 0xFF, 96);
        assert_eq!(encoded_dp_cfg[1] & 0x01, 1); // enabled
        assert_eq!(encoded_dp_cfg[1] & 0x02, 2); // mst
        assert_eq!(encoded_dp_cfg[1] & 0x04, 4); // aux
        assert_eq!(encoded_dp_cfg[1] & 0x08, 8); // hdcp
        assert_eq!(encoded_dp_cfg[1] & 0x10, 0x10); // dp_in
        assert_eq!((encoded_dp_cfg[1] >> 8) & 0xFF, 2); // adapter_num
        assert_eq!((encoded_dp_cfg[1] >> 16) & 0xFF, 1); // router_id
        assert_eq!((encoded_dp_cfg[1] >> 24) & 0xFF, 4); // lane_count
        assert_eq!(encoded_dp_cfg[2], 0x1234_ABCD);
        assert_eq!(encoded_dp_cfg[3] & 0xFFFF, 32400);
        assert_eq!((encoded_dp_cfg[3] >> 16) & 0xFF, 4);
        assert_eq!((encoded_dp_cfg[3] >> 24) & 0xFF, 10);

        let parsed_dp_cfg = XhciUsb4DpAdapterConfig::parse(&encoded_dp_cfg).unwrap();
        assert_eq!(parsed_dp_cfg.next_ptr_dwords, 96);
        assert!(parsed_dp_cfg.adapter_enabled);
        assert!(parsed_dp_cfg.mst_supported);
        assert!(parsed_dp_cfg.dp_aux_tunneling_enabled);
        assert!(parsed_dp_cfg.hdcp_enabled);
        assert!(parsed_dp_cfg.is_dp_in_adapter);
        assert_eq!(parsed_dp_cfg.adapter_num, 2);
        assert_eq!(parsed_dp_cfg.router_id, 1);
        assert_eq!(parsed_dp_cfg.lane_count, 4);
        assert_eq!(parsed_dp_cfg.status, 0x1234_ABCD);
        assert_eq!(parsed_dp_cfg.video_bandwidth_mbps, 32400);
        assert_eq!(parsed_dp_cfg.max_link_rate, 4);
        assert_eq!(parsed_dp_cfg.color_depth_bpc, 10);

        // Test Capacité Étendue xHCI 1.2 / USB4 Buffer Allocation Interface (§7.42)
        let mut usb4_buf = XhciUsb4BufferAllocation::new(3, 1, 1, 64, 128);
        assert_eq!(usb4_buf.adapter_num, 3);
        assert_eq!(usb4_buf.router_id, 1);
        assert_eq!(usb4_buf.traffic_class, 1);
        assert_eq!(usb4_buf.tx_credits_allocated, 64);
        assert_eq!(usb4_buf.rx_credits_allocated, 128);
        assert!(!usb4_buf.enabled);
        assert!(usb4_buf.credit_flow_control);
        assert!(!usb4_buf.dynamic_allocation);
        assert!(!usb4_buf.threshold_alert);

        usb4_buf.set_enabled(true);
        usb4_buf.update_credits(128, 256);
        usb4_buf.next_ptr_dwords = 48;
        usb4_buf.status = 0x8899_AABB;

        let encoded_buf = usb4_buf.encode();
        assert_eq!(
            encoded_buf[0] & 0xFF,
            XHCI_EXT_CAP_USB4_BUFFER_ALLOCATION_INTERFACE as u32
        );
        assert_eq!((encoded_buf[0] >> 8) & 0xFF, 48);
        assert_eq!(encoded_buf[1] & 0x01, 1); // enabled
        assert_eq!(encoded_buf[1] & 0x02, 2); // credit flow control
        assert_eq!((encoded_buf[1] >> 8) & 0xFF, 3); // adapter_num
        assert_eq!((encoded_buf[1] >> 16) & 0xFF, 1); // router_id
        assert_eq!((encoded_buf[1] >> 24) & 0xFF, 1); // traffic_class
        assert_eq!(encoded_buf[2], 0x8899_AABB);
        assert_eq!(encoded_buf[3] & 0xFFFF, 128); // tx_credits
        assert_eq!((encoded_buf[3] >> 16) & 0xFFFF, 256); // rx_credits

        let parsed_buf = XhciUsb4BufferAllocation::parse(&encoded_buf).unwrap();
        assert_eq!(parsed_buf.next_ptr_dwords, 48);
        assert!(parsed_buf.enabled);
        assert!(parsed_buf.credit_flow_control);
        assert!(!parsed_buf.dynamic_allocation);
        assert!(!parsed_buf.threshold_alert);
        assert_eq!(parsed_buf.adapter_num, 3);
        assert_eq!(parsed_buf.router_id, 1);
        assert_eq!(parsed_buf.traffic_class, 1);
        assert_eq!(parsed_buf.status, 0x8899_AABB);
        assert_eq!(parsed_buf.tx_credits_allocated, 128);
        assert_eq!(parsed_buf.rx_credits_allocated, 256);

        // Test Capacité Étendue xHCI 1.2 / USB4 Optical Interface Management (§7.43)
        let mut usb4_optic = XhciUsb4OpticalInterface::new(4, 1, 850, 500, 450);
        assert_eq!(usb4_optic.adapter_num, 4);
        assert_eq!(usb4_optic.router_id, 1);
        assert_eq!(usb4_optic.wavelength_nm, 850);
        assert_eq!(usb4_optic.tx_power_uw, 500);
        assert_eq!(usb4_optic.rx_power_uw, 450);
        assert!(!usb4_optic.enabled);
        assert!(!usb4_optic.laser_enabled);
        assert!(!usb4_optic.low_power_alert);
        assert!(!usb4_optic.loss_of_signal);

        usb4_optic.enable_optics(true);
        usb4_optic.update_power(550, 480);
        usb4_optic.next_ptr_dwords = 32;
        usb4_optic.status = 0xCAFE_BABE;

        let encoded_optic = usb4_optic.encode();
        assert_eq!(
            encoded_optic[0] & 0xFF,
            XHCI_EXT_CAP_USB4_OPTICAL_INTERFACE_MANAGEMENT as u32
        );
        assert_eq!((encoded_optic[0] >> 8) & 0xFF, 32);
        assert_eq!(encoded_optic[1] & 0x01, 1); // enabled
        assert_eq!(encoded_optic[1] & 0x02, 2); // laser_enabled
        assert_eq!((encoded_optic[1] >> 8) & 0xFF, 4); // adapter_num
        assert_eq!((encoded_optic[1] >> 16) & 0xFF, 1); // router_id
        assert_eq!((encoded_optic[1] >> 24) & 0xFF, 85); // 850 nm / 10
        assert_eq!(encoded_optic[2], 0xCAFE_BABE);
        assert_eq!(encoded_optic[3] & 0xFFFF, 550); // tx_power
        assert_eq!((encoded_optic[3] >> 16) & 0xFFFF, 480); // rx_power

        let parsed_optic = XhciUsb4OpticalInterface::parse(&encoded_optic).unwrap();
        assert_eq!(parsed_optic.next_ptr_dwords, 32);
        assert!(parsed_optic.enabled);
        assert!(parsed_optic.laser_enabled);
        assert!(!parsed_optic.low_power_alert);
        assert!(!parsed_optic.loss_of_signal);
        assert_eq!(parsed_optic.adapter_num, 4);
        assert_eq!(parsed_optic.router_id, 1);
        assert_eq!(parsed_optic.wavelength_nm, 850);
        assert_eq!(parsed_optic.status, 0xCAFE_BABE);
        assert_eq!(parsed_optic.tx_power_uw, 550);
        assert_eq!(parsed_optic.rx_power_uw, 480);

        // Test USB4 Inter-Domain DMA Transport Capability (§7.44)
        let mut usb4_dma = XhciUsb4InterDomainDma::new(3, 7, 4096);
        assert_eq!(usb4_dma.ring_id, 3);
        assert_eq!(usb4_dma.peer_domain_id, 7);
        assert_eq!(usb4_dma.max_packet_size, 4096);
        assert!(!usb4_dma.enabled);
        assert!(!usb4_dma.irq_enabled);
        assert!(usb4_dma.dma_v2_support);
        assert_eq!(usb4_dma.ring_depth, 64);
        assert_eq!(usb4_dma.tx_completed_count, 0);

        usb4_dma.enable_dma(true);
        usb4_dma.configure_irq(true);
        usb4_dma.record_tx_completion();
        usb4_dma.record_tx_completion();
        usb4_dma.next_ptr_dwords = 48;
        usb4_dma.status = 0x1234_5678;

        let encoded_dma = usb4_dma.encode();
        assert_eq!(
            encoded_dma[0] & 0xFF,
            XHCI_EXT_CAP_USB4_INTER_DOMAIN_DMA as u32
        );
        assert_eq!((encoded_dma[0] >> 8) & 0xFF, 48);
        assert_eq!(encoded_dma[1] & 0x01, 1); // enabled
        assert_eq!(encoded_dma[1] & 0x02, 2); // irq_enabled
        assert_eq!(encoded_dma[1] & 0x04, 4); // dma_v2_support
        assert_eq!((encoded_dma[1] >> 8) & 0x0F, 3); // ring_id
        assert_eq!((encoded_dma[1] >> 16) & 0xFF, 7); // peer_domain_id
        assert_eq!((encoded_dma[1] >> 24) & 0xFF, 64); // 4096 / 64 = 64
        assert_eq!(encoded_dma[2], 0x1234_5678);
        assert_eq!(encoded_dma[3] & 0xFFFF, 64); // ring_depth
        assert_eq!((encoded_dma[3] >> 16) & 0xFFFF, 2); // tx_completed_count

        let parsed_dma = XhciUsb4InterDomainDma::parse(&encoded_dma).unwrap();
        assert_eq!(parsed_dma.next_ptr_dwords, 48);
        assert!(parsed_dma.enabled);
        assert!(parsed_dma.irq_enabled);
        assert!(parsed_dma.dma_v2_support);
        assert_eq!(parsed_dma.ring_id, 3);
        assert_eq!(parsed_dma.peer_domain_id, 7);
        assert_eq!(parsed_dma.max_packet_size, 4096);
        assert_eq!(parsed_dma.status, 0x1234_5678);
        assert_eq!(parsed_dma.ring_depth, 64);
        assert_eq!(parsed_dma.tx_completed_count, 2);

        // Test USB4 Router Operations and Configuration Interface (§7.45)
        let mut router_ops = XhciUsb4RouterOperations::new(5, 8);
        assert_eq!(router_ops.router_id, 5);
        assert_eq!(router_ops.num_tunneling_adapters, 8);
        assert_eq!(router_ops.power_state, 0);
        assert!(!router_ops.enabled);
        assert!(!router_ops.irq_enabled);
        assert!(router_ops.connection_manager_active);
        assert_eq!(router_ops.event_counter, 0);

        router_ops.enable_router(true);
        router_ops.configure_irq(true);
        router_ops.set_power_state(2); // D2
        router_ops.record_event();
        router_ops.record_event();
        router_ops.record_event();
        router_ops.next_ptr_dwords = 64;
        router_ops.status = 0x8765_4321;

        let encoded_router = router_ops.encode();
        assert_eq!(
            encoded_router[0] & 0xFF,
            XHCI_EXT_CAP_USB4_ROUTER_OPERATIONS as u32
        );
        assert_eq!((encoded_router[0] >> 8) & 0xFF, 64);
        assert_eq!(encoded_router[1] & 0x01, 1); // enabled
        assert_eq!(encoded_router[1] & 0x02, 2); // irq_enabled
        assert_eq!(encoded_router[1] & 0x04, 4); // CM active
        assert_eq!((encoded_router[1] >> 8) & 0x3F, 5); // router_id
        assert_eq!((encoded_router[1] >> 16) & 0xFF, 8); // num_tunneling_adapters
        assert_eq!((encoded_router[1] >> 24) & 0x03, 2); // power_state D2
        assert_eq!(encoded_router[2], 0x8765_4321);
        assert_eq!(encoded_router[3], 3); // 3 events

        let parsed_router = XhciUsb4RouterOperations::parse(&encoded_router).unwrap();
        assert_eq!(parsed_router.next_ptr_dwords, 64);
        assert!(parsed_router.enabled);
        assert!(parsed_router.irq_enabled);
        assert!(parsed_router.connection_manager_active);
        assert_eq!(parsed_router.router_id, 5);
        assert_eq!(parsed_router.num_tunneling_adapters, 8);
        assert_eq!(parsed_router.power_state, 2);
        assert_eq!(parsed_router.status, 0x8765_4321);
        assert_eq!(parsed_router.event_counter, 3);

        // Test USB4 Protocol Tunneling Statistics Interface (§7.46)
        let mut stats = XhciUsb4ProtocolTunnelingStats::new(12, 1); // adapter 12, PCIe
        assert_eq!(stats.adapter_id, 12);
        assert_eq!(stats.protocol_type, 1);
        assert!(!stats.enabled);
        assert!(!stats.irq_enabled);
        assert_eq!(stats.tx_packet_count, 0);
        assert_eq!(stats.rx_packet_count, 0);

        stats.enable_stats(true);
        stats.configure_irq(true);
        stats.record_tx();
        stats.record_tx();
        stats.record_rx();
        stats.next_ptr_dwords = 32;

        let encoded_stats = stats.encode();
        assert_eq!(
            encoded_stats[0] & 0xFF,
            XHCI_EXT_CAP_USB4_PROTOCOL_TUNNELING_STATS as u32
        );
        assert_eq!((encoded_stats[0] >> 8) & 0xFF, 32);
        assert_eq!(encoded_stats[1] & 0x01, 1); // enabled
        assert_eq!(encoded_stats[1] & 0x02, 2); // irq_enabled
        assert_eq!((encoded_stats[1] >> 8) & 0x3F, 12); // adapter 12
        assert_eq!((encoded_stats[1] >> 16) & 0x07, 1); // protocol 1
        assert_eq!(encoded_stats[2], 2); // 2 tx
        assert_eq!(encoded_stats[3], 1); // 1 rx

        let parsed_stats = XhciUsb4ProtocolTunnelingStats::parse(&encoded_stats).unwrap();
        assert_eq!(parsed_stats.next_ptr_dwords, 32);
        assert!(parsed_stats.enabled);
        assert!(parsed_stats.irq_enabled);
        assert_eq!(parsed_stats.adapter_id, 12);
        assert_eq!(parsed_stats.protocol_type, 1);
        assert_eq!(parsed_stats.tx_packet_count, 2);
        assert_eq!(parsed_stats.rx_packet_count, 1);

        // Test USB4 Host-to-Host Packet Tunneling Interface (§7.47)
        let mut h2h = XhciUsb4HostToHostPacketTunneling::new(7, 3, 2048);
        assert_eq!(h2h.target_adapter_id, 7);
        assert_eq!(h2h.local_domain_id, 3);
        assert_eq!(h2h.max_packet_size, 2048);
        assert!(!h2h.enabled);
        assert!(!h2h.irq_enabled);
        assert_eq!(h2h.tx_frame_count, 0);
        assert_eq!(h2h.rx_frame_count, 0);

        h2h.enable_tunneling(true);
        h2h.configure_irq(true);
        h2h.transmit_frame();
        h2h.transmit_frame();
        h2h.receive_frame();
        h2h.next_ptr_dwords = 48;

        let encoded_h2h = h2h.encode();
        assert_eq!(
            encoded_h2h[0] & 0xFF,
            XHCI_EXT_CAP_USB4_HOST_TO_HOST_PACKET_TUNNELING as u32
        );
        assert_eq!((encoded_h2h[0] >> 8) & 0xFF, 48);
        assert_eq!(encoded_h2h[1] & 0x01, 1); // enabled
        assert_eq!(encoded_h2h[1] & 0x02, 2); // irq_enabled
        assert_eq!((encoded_h2h[1] >> 8) & 0x3F, 7); // target_adapter_id
        assert_eq!((encoded_h2h[1] >> 16) & 0x0F, 3); // local_domain_id
        assert_eq!((encoded_h2h[1] >> 20) as u16, 2048); // max_packet_size
        assert_eq!(encoded_h2h[2], 2); // tx 2
        assert_eq!(encoded_h2h[3], 1); // rx 1

        let parsed_h2h = XhciUsb4HostToHostPacketTunneling::parse(&encoded_h2h).unwrap();
        assert_eq!(parsed_h2h.next_ptr_dwords, 48);
        assert!(parsed_h2h.enabled);
        assert!(parsed_h2h.irq_enabled);
        assert_eq!(parsed_h2h.target_adapter_id, 7);
        assert_eq!(parsed_h2h.local_domain_id, 3);
        assert_eq!(parsed_h2h.max_packet_size, 2048);
        assert_eq!(parsed_h2h.tx_frame_count, 2);
        assert_eq!(parsed_h2h.rx_frame_count, 1);

        // Test USB4 Host Interface Discovery (§7.48)
        let mut disc = XhciUsb4HostInterfaceDiscovery::new(2, 0x1234);
        assert_eq!(disc.protocol_version, 2);
        assert_eq!(disc.notification_mask, 0x1234);
        assert_eq!(disc.discovered_interfaces, 0);
        assert_eq!(disc.notification_counter, 0);
        assert!(!disc.enabled);
        assert!(!disc.irq_enabled);

        disc.enable_discovery(true);
        disc.configure_irq(true);
        disc.register_interface();
        disc.register_interface();
        disc.record_notification();
        disc.next_ptr_dwords = 60;
        disc.discovery_status = 0xCAFE_BABE;

        let encoded_disc = disc.encode();
        assert_eq!(
            encoded_disc[0] & 0xFF,
            XHCI_EXT_CAP_USB4_HOST_INTERFACE_DISCOVERY as u32
        );
        assert_eq!((encoded_disc[0] >> 8) & 0xFF, 60);
        assert_eq!((encoded_disc[0] >> 16) & 0xFF, 0x12);
        assert_eq!(encoded_disc[1] & 0x01, 1); // enabled
        assert_eq!(encoded_disc[1] & 0x02, 2); // irq_enabled
        assert_eq!((encoded_disc[1] >> 8) & 0x0F, 2); // version 2
        assert_eq!((encoded_disc[1] >> 16) & 0xFF, 2); // 2 interfaces
        assert_eq!((encoded_disc[1] >> 24) & 0xFF, 0x34);
        assert_eq!(encoded_disc[2], 1); // 1 notification
        assert_eq!(encoded_disc[3], 0xCAFE_BABE);

        let parsed_disc = XhciUsb4HostInterfaceDiscovery::parse(&encoded_disc).unwrap();
        assert_eq!(parsed_disc.next_ptr_dwords, 60);
        assert!(parsed_disc.enabled);
        assert!(parsed_disc.irq_enabled);
        assert_eq!(parsed_disc.protocol_version, 2);
        assert_eq!(parsed_disc.discovered_interfaces, 2);
        assert_eq!(parsed_disc.notification_mask, 0x1234);
        assert_eq!(parsed_disc.notification_counter, 1);
        assert_eq!(parsed_disc.discovery_status, 0xCAFE_BABE);

        // Test USB4 Sleep and Wake Notification (§7.49)
        let mut slp = XhciUsb4SleepWakeNotification::new(2, 0x00FF);
        assert_eq!(slp.target_sleep_state, 2);
        assert_eq!(slp.wake_source_mask, 0x00FF);
        assert_eq!(slp.wake_event_counter, 0);
        assert!(!slp.enabled);
        assert!(!slp.irq_enabled);
        assert!(slp.remote_wake_supported);
        assert!(!slp.remote_wake_enabled);

        slp.enable(true);
        slp.configure_irq(true);
        slp.configure_remote_wake(true);
        slp.set_target_sleep_state(3);
        slp.record_wake_event();
        slp.record_wake_event();
        slp.next_ptr_dwords = 64;
        slp.power_status = 0xAA55_CC33;

        let encoded_slp = slp.encode();
        assert_eq!(
            encoded_slp[0] & 0xFF,
            XHCI_EXT_CAP_USB4_SLEEP_WAKE_NOTIFICATION as u32
        );
        assert_eq!((encoded_slp[0] >> 8) & 0xFF, 64);
        assert_eq!(encoded_slp[1] & 0x01, 1); // enabled
        assert_eq!(encoded_slp[1] & 0x02, 2); // irq_enabled
        assert_eq!(encoded_slp[1] & 0x04, 4); // remote_wake_supported
        assert_eq!(encoded_slp[1] & 0x08, 8); // remote_wake_enabled
        assert_eq!((encoded_slp[1] >> 8) & 0x07, 3); // target_sleep_state 3
        assert_eq!((encoded_slp[1] >> 16) & 0xFFFF, 0x00FF); // wake_source_mask
        assert_eq!(encoded_slp[2], 2); // 2 wake events
        assert_eq!(encoded_slp[3], 0xAA55_CC33);

        let parsed_slp = XhciUsb4SleepWakeNotification::parse(&encoded_slp).unwrap();
        assert_eq!(parsed_slp.next_ptr_dwords, 64);
        assert!(parsed_slp.enabled);
        assert!(parsed_slp.irq_enabled);
        assert!(parsed_slp.remote_wake_supported);
        assert!(parsed_slp.remote_wake_enabled);
        assert_eq!(parsed_slp.target_sleep_state, 3);
        assert_eq!(parsed_slp.wake_source_mask, 0x00FF);
        assert_eq!(parsed_slp.wake_event_counter, 2);
        assert_eq!(parsed_slp.power_status, 0xAA55_CC33);

        // Test USB4 PCIe Adapter Configuration Interface (§7.50)
        let mut pcie = XhciUsb4PcieAdapterConfigInterface::new(3, 4, 16);
        assert_eq!(pcie.adapter_index, 3);
        assert_eq!(pcie.link_speed_gen, 4);
        assert_eq!(pcie.link_width, 16);
        assert_eq!(pcie.event_counter, 0);
        assert_eq!(pcie.adapter_status, 0);
        assert!(!pcie.enabled);
        assert!(!pcie.irq_enabled);

        pcie.enable(true);
        pcie.configure_irq(true);
        pcie.set_link_speed(3);
        pcie.set_link_width(8);
        pcie.record_event(0x0001);
        pcie.record_event(0x0002);
        pcie.next_ptr_dwords = 68;

        let encoded_pcie = pcie.encode();
        assert_eq!(
            encoded_pcie[0] & 0xFF,
            XHCI_EXT_CAP_USB4_PCIE_ADAPTER_CONFIGURATION_INTERFACE as u32
        );
        assert_eq!((encoded_pcie[0] >> 8) & 0xFF, 68);
        assert_eq!(encoded_pcie[1] & 0x01, 1); // enabled
        assert_eq!(encoded_pcie[1] & 0x02, 2); // irq_enabled
        assert_eq!((encoded_pcie[1] >> 8) & 0xFF, 3); // adapter_index
        assert_eq!((encoded_pcie[1] >> 16) & 0x07, 3); // link_speed_gen 3
        assert_eq!((encoded_pcie[1] >> 20) & 0x1F, 8); // link_width 8
        assert_eq!(encoded_pcie[2], 0x0003); // adapter_status
        assert_eq!(encoded_pcie[3], 2); // 2 events

        let parsed_pcie = XhciUsb4PcieAdapterConfigInterface::parse(&encoded_pcie).unwrap();
        assert_eq!(parsed_pcie.next_ptr_dwords, 68);
        assert!(parsed_pcie.enabled);
        assert!(parsed_pcie.irq_enabled);
        assert_eq!(parsed_pcie.adapter_index, 3);
        assert_eq!(parsed_pcie.link_speed_gen, 3);
        assert_eq!(parsed_pcie.link_width, 8);
        assert_eq!(parsed_pcie.adapter_status, 0x0003);
        assert_eq!(parsed_pcie.event_counter, 2);

        // Test USB4 DisplayPort Adapter Configuration Interface (§7.51)
        let mut dp = XhciUsb4DpAdapterConfigInterface::new(2, 4, 4);
        assert_eq!(dp.adapter_index, 2);
        assert_eq!(dp.link_rate, 4);
        assert_eq!(dp.lane_count, 4);
        assert_eq!(dp.event_counter, 0);
        assert_eq!(dp.adapter_status, 0);
        assert!(!dp.enabled);
        assert!(!dp.irq_enabled);

        dp.enable(true);
        dp.configure_irq(true);
        dp.set_link_rate(3);
        dp.set_lane_count(2);
        dp.record_event(0x0004);
        dp.record_event(0x0008);
        dp.next_ptr_dwords = 72;

        let encoded_dp = dp.encode();
        assert_eq!(
            encoded_dp[0] & 0xFF,
            XHCI_EXT_CAP_USB4_DP_ADAPTER_CONFIGURATION_INTERFACE as u32
        );
        assert_eq!((encoded_dp[0] >> 8) & 0xFF, 72);
        assert_eq!(encoded_dp[1] & 0x01, 1); // enabled
        assert_eq!(encoded_dp[1] & 0x02, 2); // irq_enabled
        assert_eq!((encoded_dp[1] >> 8) & 0xFF, 2); // adapter_index 2
        assert_eq!((encoded_dp[1] >> 16) & 0x07, 3); // link_rate 3
        assert_eq!((encoded_dp[1] >> 20) & 0x07, 2); // lane_count 2
        assert_eq!(encoded_dp[2], 0x000C); // adapter_status
        assert_eq!(encoded_dp[3], 2); // 2 events

        let parsed_dp = XhciUsb4DpAdapterConfigInterface::parse(&encoded_dp).unwrap();
        assert_eq!(parsed_dp.next_ptr_dwords, 72);
        assert!(parsed_dp.enabled);
        assert!(parsed_dp.irq_enabled);
        assert_eq!(parsed_dp.adapter_index, 2);
        assert_eq!(parsed_dp.link_rate, 3);
        assert_eq!(parsed_dp.lane_count, 2);
        assert_eq!(parsed_dp.adapter_status, 0x000C);
        assert_eq!(parsed_dp.event_counter, 2);
    }
}

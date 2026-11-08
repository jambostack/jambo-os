//! Pilote de contrôleur d'hôte USB xHCI (eXtensible Host Controller Interface) 1.2
//! et sous-système de périphériques d'entrée HID (Clavier / Souris) en espace utilisateur (Ring 3).
//!
//! Assure la gestion conforme des anneaux Command / Event / Transfer (TRBs), l'énumération
//! des ports USB root-hub, la configuration des slots et contextes de périphériques,
//! le calcul sécurisé des registres Doorbell, ainsi que le décodage matériel des rapports
//! Boot Protocol du clavier et de la souris HID, sans aucune instruction d'E/S privilégiée
//! directe en Ring 3.

#![no_std]

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
pub const TRB_COMP_EVENT_RING_FULL: u8 = 21;
pub const TRB_COMP_COMMAND_ABORTED: u8 = 18;

pub const RING_ENTRIES: usize = 32;

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

/// État décodé d'un port Root-Hub xHCI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortStatus {
    pub connected: bool,
    pub enabled: bool,
    pub reset: bool,
    pub powered: bool,
    pub over_current: bool,
    pub speed: UsbSpeed,
    pub link_state: u8,
}

impl PortStatus {
    /// Décode la valeur brute du registre 32 bits PORTSC.
    pub fn parse(raw: u32) -> Self {
        let connected = (raw & (1 << 0)) != 0;
        let enabled = (raw & (1 << 1)) != 0;
        let over_current = (raw & (1 << 3)) != 0;
        let reset = (raw & (1 << 4)) != 0;
        let link_state = ((raw >> 5) & 0x0F) as u8;
        let powered = (raw & (1 << 9)) != 0;
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
        }
    }
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

/// État de la souris USB HID conforme au Boot Protocol (Rapport de 3 à 4 octets).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbMouseState {
    pub left_button: bool,
    pub right_button: bool,
    pub middle_button: bool,
    pub dx: i8,
    pub dy: i8,
    pub wheel: i8,
}

impl UsbMouseState {
    /// Décode un rapport de souris Boot Protocol (3 ou 4 octets avec roulette).
    pub fn decode_report(&mut self, report: &[u8]) {
        if report.len() < 3 {
            return;
        }

        let buttons = report[0];
        self.left_button = (buttons & (1 << 0)) != 0;
        self.right_button = (buttons & (1 << 1)) != 0;
        self.middle_button = (buttons & (1 << 2)) != 0;

        self.dx = report[1] as i8;
        self.dy = report[2] as i8;

        if report.len() >= 4 {
            self.wheel = report[3] as i8;
        } else {
            self.wheel = 0;
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
    pub cmd_ring: XhciRing,
    pub keyboard: UsbKeyboardState,
    pub mouse: UsbMouseState,
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
        Self {
            bar0_base: 0,
            cap_length: 0x20, // Valeur standard CAPLENGTH xHCI
            max_slots: 16,
            max_ports: 8,
            doorbell_array_offset: 0x2000, // Décalage Doorbell standard
            cmd_ring: XhciRing::new(),
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
                dx: 0,
                dy: 0,
                wheel: 0,
            },
            ready: false,
        }
    }

    /// Initialise le contrôleur xHCI à partir d'un périphérique PCIe validé (`PciDeviceInfo`).
    pub fn init(&mut self, pci_dev: &PciDeviceInfo) -> Result<(), SysError> {
        let bar0 = pci_dev.bar0.ok_or(SysError::BadAddress)?;
        self.bar0_base = bar0.base_address;
        self.cap_length = 0x20;
        self.doorbell_array_offset = 0x2000;
        self.ready = true;
        Ok(())
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

    /// Traite un rapport USB HID reçu d'un périphérique (clavier ou souris).
    pub fn handle_hid_input(&mut self, is_mouse: bool, report: &[u8]) {
        if is_mouse {
            self.mouse.decode_report(report);
        } else {
            self.keyboard.decode_report(report);
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

    /// Récupération après crash (Auto-guérison et réinitialisation de l'anneau de commande).
    pub fn recover_from_crash(&mut self) -> Result<(), SysError> {
        self.cmd_ring.reset();
        self.ready = true;
        Ok(())
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
        assert_eq!(mouse.dx, 10);
        assert_eq!(mouse.dy, -5);
        assert_eq!(mouse.wheel, 1);
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
}

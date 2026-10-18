//! Pilote de contrôleur d'hôte USB xHCI et périphériques HID (Clavier / Souris)
//!
//! Assure la gestion des anneaux Command / Event / Transfer (TRB), l'énumération
//! des ports USB root-hub et le décodage des rapports d'événements du clavier
//! et de la souris HID en espace utilisateur.

#![no_std]

use libjambo::SysError;
use pcie_bus_mgr::PciDevice;

pub const TRB_TYPE_NORMAL: u32 = 1;
pub const TRB_TYPE_LINK: u32 = 6;
pub const TRB_TYPE_ENABLE_SLOT: u32 = 9;
pub const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
pub const TRB_TYPE_CONFIGURE_EP: u32 = 12;
pub const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
pub const TRB_TYPE_CMD_COMPLETION_EVENT: u32 = 33;
pub const TRB_TYPE_PORT_STATUS_CHANGE: u32 = 34;

pub const RING_ENTRIES: usize = 32;

/// Bloc de requête de transfert TRB (16 octets)
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    #[inline]
    pub fn new(parameter: u64, status: u32, trb_type: u32, cycle: bool) -> Self {
        let control = ((trb_type & 0x3F) << 10) | if cycle { 1 } else { 0 };
        Self {
            parameter,
            status,
            control,
        }
    }

    #[inline]
    pub fn cycle_bit(&self) -> bool {
        (self.control & 1) != 0
    }

    #[inline]
    pub fn trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }
}

/// Anneau circulaire de TRBs (Command Ring ou Transfer Ring)
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

    /// Pousse un TRB sur l'anneau et met à jour le cycle bit
    pub fn push(&mut self, parameter: u64, status: u32, trb_type: u32) -> Result<usize, SysError> {
        let idx = self.enqueue_idx;
        let next_idx = (idx + 1) % RING_ENTRIES;

        if next_idx == 0 {
            // Insérer un Link TRB qui boucle vers le début de l'anneau
            let link_trb = Trb::new(0, 0, TRB_TYPE_LINK, self.cycle_bit);
            self.trbs[idx] = link_trb;
            self.cycle_bit = !self.cycle_bit;
            self.enqueue_idx = 0;
            return Ok(idx);
        }

        self.trbs[idx] = Trb::new(parameter, status, trb_type, self.cycle_bit);
        self.enqueue_idx = next_idx;
        Ok(idx)
    }
}

/// État du clavier USB HID
#[derive(Debug, Clone, Copy, Default)]
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
    /// Décode un rapport de clavier Boot Protocol (8 octets)
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

    /// Convertit le premier code touche valide en caractère ASCII
    pub fn first_ascii_char(&self) -> Option<char> {
        for &kc in self.keycodes.iter() {
            if kc == 0 {
                continue;
            }
            let is_shift = self.left_shift || self.right_shift;
            return match kc {
                0x04..=0x1D => {
                    // Lettres A-Z
                    let offset = kc - 0x04;
                    let base = if is_shift { b'A' } else { b'a' };
                    Some((base + offset) as char)
                }
                0x1E..=0x26 => {
                    // Chiffres 1-9
                    let num = kc - 0x1E + 1;
                    Some((b'0' + num) as char)
                }
                0x27 => Some('0'),
                0x28 => Some('\n'),
                0x2C => Some(' '),
                _ => None,
            };
        }
        None
    }
}

/// État de la souris USB HID
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbMouseState {
    pub left_button: bool,
    pub right_button: bool,
    pub middle_button: bool,
    pub dx: i8,
    pub dy: i8,
}

impl UsbMouseState {
    /// Décode un rapport de souris Boot Protocol (3 ou 4 octets)
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
    }
}

/// Contrôleur USB xHCI en espace utilisateur
pub struct XhciController {
    pub bar0_base: u64,
    pub cap_length: u8,
    pub max_slots: u8,
    pub max_ports: u8,
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
    pub const fn new() -> Self {
        Self {
            bar0_base: 0,
            cap_length: 0,
            max_slots: 16,
            max_ports: 8,
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
            },
            ready: false,
        }
    }

    /// Initialise le contrôleur xHCI à partir d'un périphérique PCIe validé
    pub fn init(&mut self, pci_dev: &PciDevice) -> Result<(), SysError> {
        let bar0 = pci_dev.bars[0].ok_or(SysError::BadAddress)?;
        self.bar0_base = bar0.base_address;
        self.cap_length = 0x20;
        self.ready = true;
        Ok(())
    }

    /// Émet une commande Enable Slot
    pub fn enable_slot(&mut self) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        self.cmd_ring.push(0, 0, TRB_TYPE_ENABLE_SLOT)
    }

    /// Émet une commande Address Device
    pub fn address_device(&mut self, input_ctx_iova: u64, slot_id: u8) -> Result<usize, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        self.cmd_ring.push(input_ctx_iova, (slot_id as u32) << 24, TRB_TYPE_ADDRESS_DEVICE)
    }

    /// Traite un rapport USB HID reçu d'un périphérique (clavier ou souris)
    pub fn handle_hid_input(&mut self, is_mouse: bool, report: &[u8]) {
        if is_mouse {
            self.mouse.decode_report(report);
        } else {
            self.keyboard.decode_report(report);
        }
    }

    /// Récupération après crash (Auto-guérison)
    pub fn recover_from_crash(&mut self) -> Result<(), SysError> {
        self.cmd_ring = XhciRing::new();
        self.ready = true;
        Ok(())
    }
}

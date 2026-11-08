//! Superviseur racine JamboInit (PID 1) et orchestrateur matériel des périphériques d'entrée.
//!
//! Assure l'initialisation des canaux de contrôle racine et la détection du contrôleur
//! USB xHCI pour la prise en charge du sous-système de saisie HID (Clavier / Souris).

#![no_std]

#[cfg(test)]
extern crate std;

use libjambo::pci::PciDeviceInfo;
use libjambo::SysError;
use xhci_drv::XhciController;

pub const INIT_VERSION: &str = "0.3.41";

/// État du superviseur racine JamboInit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    Booting,
    Running,
    ShuttingDown,
}

/// Superviseur du sous-système de périphériques d'entrée (USB HID / xHCI)
pub struct InputSupervisor {
    pub xhci: Option<XhciController>,
    pub ready: bool,
}

impl Default for InputSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl InputSupervisor {
    /// Construit une nouvelle instance non initialisée
    pub const fn new() -> Self {
        Self {
            xhci: None,
            ready: false,
        }
    }

    /// Initialise le contrôleur USB xHCI à partir des informations PCIe
    pub fn init_xhci(&mut self, pci_dev: &PciDeviceInfo) -> Result<(), SysError> {
        let mut ctrl = XhciController::new();
        ctrl.init(pci_dev)?;
        self.xhci = Some(ctrl);
        self.ready = true;
        Ok(())
    }

    /// Décode un rapport de clavier HID reçu et retourne le caractère ASCII correspondant
    pub fn handle_keyboard_report(&mut self, report: &[u8]) -> Option<char> {
        if let Some(ctrl) = self.xhci.as_mut() {
            ctrl.handle_hid_input(false, report);
            ctrl.keyboard.first_ascii_char()
        } else {
            None
        }
    }

    /// Décode un rapport de souris HID reçu
    pub fn handle_mouse_report(&mut self, report: &[u8]) -> bool {
        if let Some(ctrl) = self.xhci.as_mut() {
            ctrl.handle_hid_input(true, report);
            ctrl.mouse.left_button || ctrl.mouse.right_button || ctrl.mouse.middle_button
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libjambo::pci::{PciAddress, PciBar, PciBarType};

    #[test]
    fn test_init_supervisor_state() {
        let state = SupervisorState::Booting;
        assert_eq!(state, SupervisorState::Booting);
        assert_ne!(state, SupervisorState::Running);
        assert_eq!(INIT_VERSION, "0.3.41");
    }

    #[test]
    fn test_input_supervisor_initialization() {
        let mut sup = InputSupervisor::new();
        assert!(!sup.ready);
        assert!(sup.xhci.is_none());

        let xhci_dev = PciDeviceInfo {
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

        assert!(sup.init_xhci(&xhci_dev).is_ok());
        assert!(sup.ready);
        assert!(sup.xhci.is_some());
    }

    #[test]
    fn test_input_supervisor_hid_event_decoding() {
        let mut sup = InputSupervisor::new();
        let xhci_dev = PciDeviceInfo {
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
        let _ = sup.init_xhci(&xhci_dev);

        // Touche 'h' minuscule (0x0B)
        let report_h = [0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00];
        let ch = sup.handle_keyboard_report(&report_h);
        assert_eq!(ch, Some('h'));

        // Clic gauche souris
        let mouse_report = [0x01, 0, 0, 0];
        assert!(sup.handle_mouse_report(&mouse_report));
    }
}

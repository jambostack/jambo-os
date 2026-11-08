//! Module de gestion et d'énumération du bus PCIe en espace utilisateur.
//!
//! Toutes les opérations matérielles d'accès à l'espace de configuration PCI
//! transitent par l'appel système `DeviceIo` (Syscall 29), garantissant
//! l'absence d'instructions privilégiées `in`/`out` en Ring 3 et le respect
//! des politiques de confinement capabilaires.

use crate::{pci_read16, pci_read32, pci_write32, SysError};

/// Adresse d'un périphérique sur le bus PCIe (Bus / Device / Function).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    /// Construit une nouvelle adresse PCIe à partir de ses composantes.
    #[inline]
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device: device & 0x1F,
            function: function & 0x07,
        }
    }

    /// Calcule la valeur BDF (Bus/Device/Function) codée sur 64 bits pour le broker noyau.
    #[inline]
    pub fn bdf(&self) -> u64 {
        ((self.bus as u64) << 16)
            | ((self.device as u64 & 0x1F) << 11)
            | ((self.function as u64 & 0x07) << 8)
    }

    /// Lit un mot de 32 bits à l'offset de configuration spécifié.
    #[inline]
    pub fn read32(&self, offset: u8) -> u32 {
        pci_read32(self.bus, self.device, self.function, offset)
    }

    /// Lit un mot de 16 bits à l'offset de configuration spécifié.
    #[inline]
    pub fn read16(&self, offset: u8) -> u16 {
        pci_read16(self.bus, self.device, self.function, offset)
    }

    /// Écrit un mot de 32 bits à l'offset de configuration spécifié.
    #[inline]
    pub fn write32(&self, offset: u8, val: u32) -> Result<(), SysError> {
        pci_write32(self.bus, self.device, self.function, offset, val)
    }
}

/// Type et attributs d'un registre de base d'adresse (Base Address Register - BAR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciBarType {
    /// Espace mémoire 32 bits standard.
    Memory32,
    /// Espace mémoire 64 bits (occupe deux registres BAR consécutifs).
    Memory64,
    /// Espace de ports d'E/S (hérité).
    IoSpace,
}

/// Description analysée d'une BAR PCIe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciBar {
    pub index: u8,
    pub bar_type: PciBarType,
    pub base_address: u64,
    pub prefetchable: bool,
}

impl PciBar {
    /// Analyse une BAR à partir de sa valeur brute 32 bits et éventuellement de sa partie haute 64 bits.
    pub fn parse(index: u8, raw_low: u32, raw_high: Option<u32>) -> Option<Self> {
        if raw_low == 0 || raw_low == 0xFFFF_FFFF {
            return None;
        }

        let is_io = (raw_low & 0x01) != 0;
        if is_io {
            return Some(Self {
                index,
                bar_type: PciBarType::IoSpace,
                base_address: (raw_low & !0x03) as u64,
                prefetchable: false,
            });
        }

        let mem_type = (raw_low >> 1) & 0x03;
        let prefetchable = (raw_low & (1 << 3)) != 0;

        match mem_type {
            0 => Some(Self {
                index,
                bar_type: PciBarType::Memory32,
                base_address: (raw_low & !0x0F) as u64,
                prefetchable,
            }),
            2 => {
                let high = raw_high.unwrap_or(0) as u64;
                let low = (raw_low & !0x0F) as u64;
                Some(Self {
                    index,
                    bar_type: PciBarType::Memory64,
                    base_address: (high << 32) | low,
                    prefetchable,
                })
            }
            _ => None,
        }
    }
}

/// Classes architecturales de périphériques PCIe reconnues par JamboOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciClass {
    /// Contrôleur NVMe (Class 0x01, Subclass 0x08, ProgIF 0x02).
    Nvme,
    /// Contrôleur d'hôte USB xHCI (Class 0x0C, Subclass 0x03, ProgIF 0x30).
    UsbXhci,
    /// Contrôleur réseau Ethernet (Class 0x02, Subclass 0x00).
    Ethernet,
    /// Contrôleur graphique / VGA (Class 0x03, Subclass 0x00).
    Display,
    /// Périphérique VirtIO OASIS standard (Vendor ID 0x1AF4).
    VirtIo,
    /// Autre classe PCIe non spécialisée.
    Other {
        class: u8,
        subclass: u8,
        prog_if: u8,
    },
}

/// En-tête de configuration standard d'un périphérique PCIe (Type 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDeviceInfo {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub bar0: Option<PciBar>,
}

impl PciDeviceInfo {
    /// Détermine la catégorie du périphérique selon ses identifiants.
    pub fn class(&self) -> PciClass {
        if self.vendor_id == 0x1AF4 {
            return PciClass::VirtIo;
        }
        match (self.class_code, self.subclass, self.prog_if) {
            (0x01, 0x08, 0x02) => PciClass::Nvme,
            (0x0C, 0x03, 0x30) => PciClass::UsbXhci,
            (0x02, 0x00, _) => PciClass::Ethernet,
            (0x03, 0x00, _) => PciClass::Display,
            _ => PciClass::Other {
                class: self.class_code,
                subclass: self.subclass,
                prog_if: self.prog_if,
            },
        }
    }

    /// Indique si le périphérique correspond à un contrôleur de stockage NVMe.
    #[inline]
    pub fn is_nvme(&self) -> bool {
        self.class() == PciClass::Nvme
    }

    /// Indique si le périphérique correspond à un contrôleur USB xHCI.
    #[inline]
    pub fn is_xhci(&self) -> bool {
        self.class() == PciClass::UsbXhci
    }
}

/// Sonde un emplacement PCIe (Bus, Device, Function) et extrait l'en-tête Type 0 s'il existe.
pub fn probe_pci_device(bus: u8, device: u8, function: u8) -> Option<PciDeviceInfo> {
    let addr = PciAddress::new(bus, device, function);
    let vendor_id = addr.read16(0x00);
    if vendor_id == 0xFFFF || vendor_id == 0x0000 {
        return None;
    }
    let device_id = addr.read16(0x02);
    let rev_prog = addr.read16(0x08);
    let revision = rev_prog as u8;
    let prog_if = (rev_prog >> 8) as u8;
    let sub_class = addr.read16(0x0A);
    let subclass = sub_class as u8;
    let class_code = (sub_class >> 8) as u8;

    let bar0_low = addr.read32(0x10);
    let bar0_high = if ((bar0_low >> 1) & 3) == 2 {
        Some(addr.read32(0x14))
    } else {
        None
    };
    let bar0 = PciBar::parse(0, bar0_low, bar0_high);

    Some(PciDeviceInfo {
        address: addr,
        vendor_id,
        device_id,
        class_code,
        subclass,
        prog_if,
        revision,
        bar0,
    })
}

/// Énumère les périphériques sur les bus PCIe principaux (bus 0..=1) selon un prédicat de filtrage.
pub fn find_pci_device<F: Fn(&PciDeviceInfo) -> bool>(predicate: F) -> Option<PciDeviceInfo> {
    for bus in 0..=1 {
        for dev in 0..32 {
            for func in 0..8 {
                if let Some(info) = probe_pci_device(bus, dev, func) {
                    if predicate(&info) {
                        return Some(info);
                    }
                } else if func == 0 {
                    break;
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_address_bdf_encoding() {
        let addr = PciAddress::new(1, 2, 3);
        assert_eq!(addr.bus, 1);
        assert_eq!(addr.device, 2);
        assert_eq!(addr.function, 3);

        // BDF : bus=1 (shift 16) | dev=2 (shift 11) | func=3 (shift 8)
        let expected_bdf = (1u64 << 16) | (2u64 << 11) | (3u64 << 8);
        assert_eq!(addr.bdf(), expected_bdf);
    }

    #[test]
    fn test_pci_bar_parse_memory32() {
        // Bit 0 = 0 (Memory), Bits 2:1 = 00 (32-bit), Bit 3 = 1 (Prefetchable)
        let raw = 0xFE00_0008u32;
        let bar = PciBar::parse(0, raw, None).expect("BAR mémoire 32 bits valide");
        assert_eq!(bar.index, 0);
        assert_eq!(bar.bar_type, PciBarType::Memory32);
        assert_eq!(bar.base_address, 0xFE00_0000);
        assert!(bar.prefetchable);
    }

    #[test]
    fn test_pci_bar_parse_memory64() {
        // Bit 0 = 0 (Memory), Bits 2:1 = 10 (64-bit), Bit 3 = 0 (Non-prefetchable)
        let raw_low = 0xE000_0004u32;
        let raw_high = 0x0000_0002u32;
        let bar = PciBar::parse(0, raw_low, Some(raw_high)).expect("BAR mémoire 64 bits valide");
        assert_eq!(bar.index, 0);
        assert_eq!(bar.bar_type, PciBarType::Memory64);
        assert_eq!(bar.base_address, 0x0000_0002_E000_0000);
        assert!(!bar.prefetchable);
    }

    #[test]
    fn test_pci_bar_parse_io() {
        // Bit 0 = 1 (I/O Space)
        let raw = 0x0000_C001u32;
        let bar = PciBar::parse(1, raw, None).expect("BAR I/O valide");
        assert_eq!(bar.index, 1);
        assert_eq!(bar.bar_type, PciBarType::IoSpace);
        assert_eq!(bar.base_address, 0x0000_C000);
        assert!(!bar.prefetchable);
    }

    #[test]
    fn test_pci_class_identification() {
        let nvme_dev = PciDeviceInfo {
            address: PciAddress::new(0, 1, 0),
            vendor_id: 0x144D, // Samsung
            device_id: 0xA808,
            class_code: 0x01,
            subclass: 0x08,
            prog_if: 0x02,
            revision: 1,
            bar0: None,
        };
        assert_eq!(nvme_dev.class(), PciClass::Nvme);
        assert!(nvme_dev.is_nvme());
        assert!(!nvme_dev.is_xhci());

        let xhci_dev = PciDeviceInfo {
            address: PciAddress::new(0, 2, 0),
            vendor_id: 0x8086, // Intel
            device_id: 0x9D2F,
            class_code: 0x0C,
            subclass: 0x03,
            prog_if: 0x30,
            revision: 1,
            bar0: None,
        };
        assert_eq!(xhci_dev.class(), PciClass::UsbXhci);
        assert!(xhci_dev.is_xhci());
        assert!(!xhci_dev.is_nvme());

        let virtio_dev = PciDeviceInfo {
            address: PciAddress::new(0, 3, 0),
            vendor_id: 0x1AF4, // Red Hat VirtIO
            device_id: 0x1001, // VirtIO Block
            class_code: 0x01,
            subclass: 0x00,
            prog_if: 0x00,
            revision: 1,
            bar0: None,
        };
        assert_eq!(virtio_dev.class(), PciClass::VirtIo);
    }

    #[test]
    fn test_pci_scan_fallback_on_host() {
        // En mode test unitaire hôte, aucun périphérique PCI matériel n'est connecté au broker DeviceIo
        assert_eq!(probe_pci_device(0, 0, 0), None);
        assert_eq!(find_pci_device(|d| d.is_nvme()), None);
        assert_eq!(find_pci_device(|d| d.is_xhci()), None);
    }
}

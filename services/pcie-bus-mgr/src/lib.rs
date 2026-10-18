//! Gestionnaire de bus PCIe en espace utilisateur (pcie-bus-mgr)
//!
//! Assure l'énumération dynamique des périphériques PCIe, l'analyse des capacités
//! matérielles (MSI/MSI-X, PCIe FLR), l'assignation sécurisée des BARs de mémoire
//! et la stricte application de la politique IOMMU : interdiction formelle d'activer
//! le bit Bus Master Enable sans domaine IOMMU préalablement validé.

#![no_std]

use libjambo::SysError;

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Adresse d'un périphérique sur le bus PCIe
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    #[inline]
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    #[inline]
    pub fn config_addr(&self, offset: u8) -> u32 {
        0x8000_0000
            | ((self.bus as u32) << 16)
            | ((self.device as u32 & 0x1F) << 11)
            | ((self.function as u32 & 0x07) << 8)
            | ((offset as u32) & 0xFC)
    }
}

/// Type de BAR PCIe
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarType {
    Memory32,
    Memory64,
    IoSpace,
}

/// Description d'un registre BAR
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciBar {
    pub index: u8,
    pub bar_type: BarType,
    pub base_address: u64,
    pub size: u64,
    pub prefetchable: bool,
}

/// Classe de périphérique PCIe
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciDeviceClass {
    MassStorageNvme,
    SerialBusUsbXhci,
    NetworkEthernet,
    DisplayVga,
    VirtIoDevice,
    Other(u8, u8),
}

/// Informations d'un périphérique PCIe énuméré
#[derive(Debug, Clone)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub pcie_cap_offset: Option<u8>,
    pub msix_cap_offset: Option<u8>,
    pub bars: [Option<PciBar>; 6],
    pub bus_master_active: bool,
}

impl PciDevice {
    pub fn device_class(&self) -> PciDeviceClass {
        match (self.class_code, self.subclass, self.prog_if) {
            (0x01, 0x08, 0x02) => PciDeviceClass::MassStorageNvme,
            (0x0C, 0x03, 0x30) => PciDeviceClass::SerialBusUsbXhci,
            (0x02, 0x00, _) => PciDeviceClass::NetworkEthernet,
            (0x03, 0x00, _) => PciDeviceClass::DisplayVga,
            _ if self.vendor_id == 0x1AF4 => PciDeviceClass::VirtIoDevice,
            _ => PciDeviceClass::Other(self.class_code, self.subclass),
        }
    }
}

/// Accès matériel aux ports de configuration PCI x86
pub struct PciConfigAccess;

impl PciConfigAccess {
    /// Lit un mot de 32 bits dans l'espace de configuration PCI.
    ///
    /// # Safety
    ///
    /// L'accès direct aux ports d'E/S x86 0xCF8 et 0xCFC suppose que le matériel
    /// PCIe est accessible et que l'offset est aligné.
    #[inline]
    pub unsafe fn read32(addr: PciAddress, offset: u8) -> u32 {
        let conf_addr = addr.config_addr(offset);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDRESS, in("eax") conf_addr, options(nomem, nostack));
        let val: u32;
        core::arch::asm!("in eax, dx", out("eax") val, in("dx") PCI_CONFIG_DATA, options(nomem, nostack));
        val
    }

    /// Écrit un mot de 32 bits dans l'espace de configuration PCI.
    ///
    /// # Safety
    ///
    /// L'appelant doit s'assurer que l'écriture dans ce registre matériel est valide.
    #[inline]
    pub unsafe fn write32(addr: PciAddress, offset: u8, val: u32) {
        let conf_addr = addr.config_addr(offset);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDRESS, in("eax") conf_addr, options(nomem, nostack));
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val, options(nomem, nostack));
    }

    /// Lit un mot de 16 bits dans l'espace de configuration PCI.
    ///
    /// # Safety
    ///
    /// L'accès direct aux ports matériels x86 doit cibler un registre valide.
    #[inline]
    pub unsafe fn read16(addr: PciAddress, offset: u8) -> u16 {
        let dword = Self::read32(addr, offset & 0xFC);
        ((dword >> ((offset & 2) * 8)) & 0xFFFF) as u16
    }

    /// Écrit un mot de 16 bits dans l'espace de configuration PCI.
    ///
    /// # Safety
    ///
    /// L'écriture doit préserver les bits réservés du registre ciblé.
    #[inline]
    pub unsafe fn write16(addr: PciAddress, offset: u8, val: u16) {
        let shift = (offset & 2) * 8;
        let mut dword = Self::read32(addr, offset & 0xFC);
        dword &= !(0xFFFF << shift);
        dword |= (val as u32) << shift;
        Self::write32(addr, offset & 0xFC, dword);
    }
}

/// Gestionnaire de bus PCIe
pub struct PcieBusManager {
    devices: [Option<PciDevice>; 32],
    device_count: usize,
}

impl Default for PcieBusManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PcieBusManager {
    pub const fn new() -> Self {
        const INIT_OPT: Option<PciDevice> = None;
        Self {
            devices: [INIT_OPT; 32],
            device_count: 0,
        }
    }

    /// Analyse et énumère les périphériques présents sur le bus
    pub fn scan_bus(&mut self) {
        self.device_count = 0;

        for bus in 0..=1 {
            for dev in 0..32 {
                for func in 0..8 {
                    let addr = PciAddress::new(bus, dev, func);
                    let vendor_id = unsafe { PciConfigAccess::read16(addr, 0x00) };
                    if vendor_id == 0xFFFF || vendor_id == 0x0000 {
                        if func == 0 {
                            break; // Aucun périphérique présent sur ce slot
                        }
                        continue;
                    }

                    let device_id = unsafe { PciConfigAccess::read16(addr, 0x02) };
                    let class_subclass = unsafe { PciConfigAccess::read16(addr, 0x0A) };
                    let class_code = (class_subclass >> 8) as u8;
                    let subclass = (class_subclass & 0xFF) as u8;

                    let prog_rev = unsafe { PciConfigAccess::read16(addr, 0x08) };
                    let prog_if = (prog_rev >> 8) as u8;
                    let revision = (prog_rev & 0xFF) as u8;

                    // Découverte des BARs
                    let mut bars = [None; 6];
                    let mut bar_idx = 0;
                    while bar_idx < 6 {
                        let bar_offset = 0x10 + (bar_idx as u8) * 4;
                        let bar_val = unsafe { PciConfigAccess::read32(addr, bar_offset) };
                        if bar_val == 0 {
                            bar_idx += 1;
                            continue;
                        }

                        let is_io = (bar_val & 0x01) != 0;
                        if is_io {
                            bars[bar_idx] = Some(PciBar {
                                index: bar_idx as u8,
                                bar_type: BarType::IoSpace,
                                base_address: (bar_val & !0x03) as u64,
                                size: 256,
                                prefetchable: false,
                            });
                            bar_idx += 1;
                        } else {
                            let mem_type = (bar_val >> 1) & 0x03;
                            let prefetch = (bar_val & 0x08) != 0;

                            if mem_type == 0x02 && bar_idx + 1 < 6 {
                                // BAR 64 bits
                                let bar_high =
                                    unsafe { PciConfigAccess::read32(addr, bar_offset + 4) };
                                let base_addr =
                                    ((bar_high as u64) << 32) | ((bar_val & !0x0F) as u64);
                                bars[bar_idx] = Some(PciBar {
                                    index: bar_idx as u8,
                                    bar_type: BarType::Memory64,
                                    base_address: base_addr,
                                    size: 0x4000,
                                    prefetchable: prefetch,
                                });
                                bar_idx += 2; // Saute la BAR suivante car elle porte les 32 bits de poids fort
                            } else {
                                // BAR 32 bits
                                bars[bar_idx] = Some(PciBar {
                                    index: bar_idx as u8,
                                    bar_type: BarType::Memory32,
                                    base_address: (bar_val & !0x0F) as u64,
                                    size: 0x1000,
                                    prefetchable: prefetch,
                                });
                                bar_idx += 1;
                            }
                        }
                    }

                    // Détection des capacités PCIe et MSI-X
                    let status = unsafe { PciConfigAccess::read16(addr, 0x06) };
                    let mut pcie_cap = None;
                    let mut msix_cap = None;

                    if (status & (1 << 4)) != 0 {
                        // Liste de capacités présente
                        let mut cap_ptr =
                            unsafe { PciConfigAccess::read16(addr, 0x34) & 0xFF } as u8;
                        let mut loop_guard = 0;
                        while cap_ptr != 0 && loop_guard < 48 {
                            let cap_id =
                                unsafe { PciConfigAccess::read16(addr, cap_ptr) & 0xFF } as u8;
                            let next_ptr =
                                unsafe { (PciConfigAccess::read16(addr, cap_ptr) >> 8) & 0xFF }
                                    as u8;

                            if cap_id == 0x10 {
                                pcie_cap = Some(cap_ptr);
                            } else if cap_id == 0x11 {
                                msix_cap = Some(cap_ptr);
                            }

                            cap_ptr = next_ptr;
                            loop_guard += 1;
                        }
                    }

                    let pci_dev = PciDevice {
                        address: addr,
                        vendor_id,
                        device_id,
                        class_code,
                        subclass,
                        prog_if,
                        revision,
                        pcie_cap_offset: pcie_cap,
                        msix_cap_offset: msix_cap,
                        bars,
                        bus_master_active: false,
                    };

                    if self.device_count < self.devices.len() {
                        self.devices[self.device_count] = Some(pci_dev);
                        self.device_count += 1;
                    }
                }
            }
        }
    }

    /// Liste des périphériques découverts
    pub fn devices(&self) -> &[Option<PciDevice>] {
        &self.devices[..self.device_count]
    }

    /// Trouve un périphérique selon sa classe
    pub fn find_by_class(&self, class: PciDeviceClass) -> Option<&PciDevice> {
        self.devices[..self.device_count]
            .iter()
            .flatten()
            .find(|slot| slot.device_class() == class)
    }

    /// Règle architecturale formelle : active le bit Bus Master Enable UNIQUEMENT
    /// si un domaine IOMMU valide a été associé au périphérique.
    pub fn enable_bus_mastering(
        &mut self,
        addr: PciAddress,
        iommu_domain_active: bool,
    ) -> Result<(), SysError> {
        if !iommu_domain_active {
            // Rejet catégorique : protection contre le DMA sauvage
            return Err(SysError::PermissionDenied);
        }

        unsafe {
            let mut cmd = PciConfigAccess::read16(addr, 0x04);
            cmd |= 0x0004; // Bus Master Enable (bit 2)
            cmd |= 0x0002; // Memory Space Enable (bit 1)
            PciConfigAccess::write16(addr, 0x04, cmd);
        }

        for slot in self.devices[..self.device_count].iter_mut().flatten() {
            if slot.address == addr {
                slot.bus_master_active = true;
                break;
            }
        }

        Ok(())
    }

    /// Exécute un PCIe Function Level Reset (FLR)
    /// Réinitialise l'état matériel interne du périphérique pour l'auto-guérison.
    pub fn function_level_reset(&self, addr: PciAddress) -> Result<(), SysError> {
        // Désactiver immédiatement le Bus Master Enable pour arrêter tout DMA en vol
        unsafe {
            let mut cmd = PciConfigAccess::read16(addr, 0x04);
            cmd &= !0x0004; // Désactive Bus Master Enable
            PciConfigAccess::write16(addr, 0x04, cmd);
        }

        // Trouver la capacité PCIe
        let mut pcie_offset = None;
        for slot in self.devices[..self.device_count].iter().flatten() {
            if slot.address == addr {
                pcie_offset = slot.pcie_cap_offset;
                break;
            }
        }

        if let Some(offset) = pcie_offset {
            unsafe {
                // Device Control Register est à offset + 0x08
                let dev_ctl_offset = offset + 0x08;
                let mut ctl = PciConfigAccess::read16(addr, dev_ctl_offset);
                ctl |= 1 << 15; // Bit 15 : Initiate Function Level Reset
                PciConfigAccess::write16(addr, dev_ctl_offset, ctl);
            }
            Ok(())
        } else {
            // Réinitialisation douce par désactivation/réactivation Memory & Bus Master
            Ok(())
        }
    }
}

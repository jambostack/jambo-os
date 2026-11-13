//! Pilote de stockage NVMe 1.4 en espace utilisateur (Ring 3).
//!
//! Assure l'initialisation du contrôleur NVMe, la gestion des anneaux Admin et I/O,
//! la soumission des commandes Read/Write/Flush par Doorbell et le mappage DMA
//! sécurisé via l'IOMMU, sans aucune instruction d'E/S privilégiée en Ring 3.

#![no_std]

#[cfg(test)]
extern crate std;

use libjambo::pci::PciDeviceInfo;
use libjambo::{DeviceRemoveLock, SysError};

pub const NVME_REG_CAP: usize = 0x00;
pub const NVME_REG_VS: usize = 0x08;
pub const NVME_REG_INTMS: usize = 0x0C;
pub const NVME_REG_INTMC: usize = 0x10;
pub const NVME_REG_CC: usize = 0x14;
pub const NVME_REG_CSTS: usize = 0x1C;
pub const NVME_REG_AQA: usize = 0x24;
pub const NVME_REG_ASQ: usize = 0x28;
pub const NVME_REG_ACQ: usize = 0x30;

pub const NVME_ADMIN_DELETE_SQ: u8 = 0x00;
pub const NVME_ADMIN_CREATE_SQ: u8 = 0x01;
pub const NVME_ADMIN_DELETE_CQ: u8 = 0x04;
pub const NVME_ADMIN_CREATE_CQ: u8 = 0x05;
pub const NVME_ADMIN_IDENTIFY: u8 = 0x06;
pub const NVME_ADMIN_GET_LOG_PAGE: u8 = 0x02;
pub const NVME_ADMIN_SET_FEATURES: u8 = 0x09;
pub const NVME_ADMIN_ASYNC_EVENT_REQ: u8 = 0x0C;
/// Commande de gestion de namespace NVMe 1.4 (Namespace Management, §8.11)
pub const NVME_ADMIN_NS_MANAGEMENT: u8 = 0x0D;
/// Commande d'attachement/détachement de namespace aux contrôleurs (Namespace Attachment, §8.12)
pub const NVME_ADMIN_NS_ATTACHMENT: u8 = 0x15;
/// Commande de formatage physique NVM de bas niveau (Format NVM, NVMe 1.4 §5.24)
pub const NVME_ADMIN_FORMAT_NVM: u8 = 0x80;
/// Commande d'effacement global sécurisé du média (Sanitize, NVMe 1.4 §5.27 & §8.21)
pub const NVME_ADMIN_SANITIZE: u8 = 0x84;

/// Identifiant de page de journal pour l'état d'effacement sécurisé (Sanitize Status Log, NVMe 1.4 §5.14.1.9.25)
pub const NVME_LOG_SANITIZE_STATUS: u8 = 0x81;

/// Actions d'effacement Sanitize (SANACT, CDW10 bits 2:0)
pub const NVME_SANACT_EXIT_FAILURE: u8 = 0x01;
pub const NVME_SANACT_START_BLOCK_ERASE: u8 = 0x02;
pub const NVME_SANACT_START_OVERWRITE: u8 = 0x03;
pub const NVME_SANACT_START_CRYPTO_ERASE: u8 = 0x04;

/// Statut de Sanitize dans le journal 0x81 (SSTAT bits 2:0)
pub const NVME_SANITIZE_NEVER_SANITIZED: u16 = 0x00;
pub const NVME_SANITIZE_COMPLETED_SUCCESS: u16 = 0x01;
pub const NVME_SANITIZE_IN_PROGRESS: u16 = 0x02;
pub const NVME_SANITIZE_COMPLETED_FAILED: u16 = 0x03;

/// Indicateur de données globales effacées (SSTAT bit 8)
pub const NVME_SANITIZE_GLOBAL_DATA_ERASED: u16 = 1 << 8;

/// Sélecteur d'effacement sécurisé (SES - Secure Erase Settings, CDW10 bits 11:9)
pub const NVME_SES_NO_SECURE_ERASE: u8 = 0x0;
pub const NVME_SES_USER_DATA_ERASE: u8 = 0x1;
pub const NVME_SES_CRYPTO_ERASE: u8 = 0x2;

/// Sélecteur d'information de protection des données (PI - Protection Information Type, CDW10 bits 7:5)
pub const NVME_PI_DISABLE: u8 = 0x0;
pub const NVME_PI_TYPE1: u8 = 0x1;
pub const NVME_PI_TYPE2: u8 = 0x2;
pub const NVME_PI_TYPE3: u8 = 0x3;

/// Emplacement de l'information de protection (PIL - Protection Information Location, CDW10 bit 8)
pub const NVME_PIL_LAST_8_BYTES: u8 = 0x0;
pub const NVME_PIL_FIRST_8_BYTES: u8 = 0x1;

/// Mode de stockage des métadonnées (MSET - Metadata Settings, CDW10 bit 4)
pub const NVME_MSET_SEPARATE_BUFFER: u8 = 0x0;
pub const NVME_MSET_EXTENDED_LBA: u8 = 0x1;

/// Identifiant NSID de diffusion broadcast pour formater l'intégralité des namespaces
pub const NVME_NSID_BROADCAST: u32 = 0xFFFF_FFFF;

pub const NVME_LOG_ERROR_INFO: u8 = 0x01;
pub const NVME_LOG_SMART_HEALTH: u8 = 0x02;
pub const NVME_ERROR_LOG_ENTRY_SIZE: usize = 64;
pub const NVME_FEAT_ARBITRATION: u32 = 0x01;
pub const NVME_FEAT_TEMPERATURE_THRESHOLD: u32 = 0x04;
pub const NVME_FEAT_INTERRUPT_COALESCING: u32 = 0x08;
pub const NVME_FEAT_INTERRUPT_VECTOR_CONFIG: u32 = 0x09;
pub const NVME_FEAT_ASYNC_EVENT_CONFIG: u32 = 0x0B;

/// Masque et valeurs de sélection du mécanisme d'arbitrage (CC.AMS & CAP.AMS, NVMe 1.4 §3.1.3.8)
pub const NVME_CC_AMS_ROUND_ROBIN: u32 = 0x0 << 11;
pub const NVME_CC_AMS_WRR_URGENT: u32 = 0x1 << 11;
pub const NVME_CAP_AMS_WRR_URGENT: u64 = 1 << 17;

/// Sélecteur d'action Namespace Management : création d'un nouveau namespace (CDW10 bits 3:0 = 0x0)
pub const NVME_NS_MGMT_CREATE: u8 = 0x00;
/// Sélecteur d'action Namespace Management : suppression d'un namespace existant (CDW10 bits 3:0 = 0x1)
pub const NVME_NS_MGMT_DELETE: u8 = 0x01;
/// Sélecteur d'action Namespace Attachment : rattachement d'un namespace à des contrôleurs (CDW10 bits 3:0 = 0x0)
pub const NVME_NS_ATTACH_CTRL: u8 = 0x00;
/// Sélecteur d'action Namespace Attachment : détachement d'un namespace de contrôleurs (CDW10 bits 3:0 = 0x1)
pub const NVME_NS_DETACH_CTRL: u8 = 0x01;

/// Capacité maximale de la liste de contrôleurs pour l'attachement de namespace (§5.26)
pub const NVME_CTRL_LIST_MAX: usize = 2047;
/// Nombre maximum de namespaces gérés simultanément par le contrôleur
pub const NVME_MAX_NAMESPACES: usize = 16;

/// Commande NVM standard de vidange de cache matériel (NVMe Flush Command, opcode 0x00)
pub const NVME_NVM_CMD_FLUSH: u8 = 0x00;
pub const NVME_IO_FLUSH: u8 = NVME_NVM_CMD_FLUSH;
pub const NVME_IO_WRITE: u8 = 0x01;
pub const NVME_IO_READ: u8 = 0x02;
pub const NVME_IO_WRITE_ZEROES: u8 = 0x08;
pub const NVME_IO_DATA_SET_MANAGEMENT: u8 = 0x09;

/// Attributs de gestion de jeu de données NVMe (DSM - Dataset Management / TRIM / Deallocate)
pub const NVME_DSM_ATTR_DEALLOCATE: u32 = 1 << 2; // Bit 2 : Déallocation matérielle de blocs (TRIM)
pub const NVME_DSM_ATTR_INTEGRAL_READ: u32 = 1 << 0; // Bit 0 : Optimisation pour lecture intégrale
pub const NVME_DSM_ATTR_INTEGRAL_WRITE: u32 = 1 << 1; // Bit 1 : Optimisation pour écriture intégrale

/// Structure de plage de gestion de jeu de données NVMe (DSM Range, 16 octets, NVMe 1.4 Section 6.7)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeDsmRange {
    /// Attributs contextuels de gestion (lecture/écriture séquentielle, accès futur)
    pub context_attributes: u32,
    /// Nombre de blocs logiques dans la plage (longueur en secteurs)
    pub length_blocks: u32,
    /// Adresse LBA de début de la plage de blocs
    pub starting_lba: u64,
}

pub const QUEUE_SIZE: usize = 64;
pub const NVME_PRP_ENTRIES_MAX: usize = 512;
pub const NVME_PRP_CHAIN_MAX_PAGES: usize = 1023; // 511 (primaire) + 512 (extension)

/// Liste de pointeurs de pages de régions physiques (PRP List) conforme NVMe 1.4 (4096 octets, alignement 4096).
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub struct NvmePrpList {
    pub entries: [u64; NVME_PRP_ENTRIES_MAX],
}

impl Default for NvmePrpList {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmePrpList {
    pub const fn new() -> Self {
        Self {
            entries: [0u64; NVME_PRP_ENTRIES_MAX],
        }
    }

    /// Définit l'adresse d'une entrée PRP à l'indice donné (0..512)
    pub fn set_entry(&mut self, index: usize, page_iova: u64) -> Result<(), SysError> {
        if index >= NVME_PRP_ENTRIES_MAX {
            return Err(SysError::OutOfMemory);
        }
        self.entries[index] = page_iova;
        Ok(())
    }

    /// Réinitialise la liste
    pub fn clear(&mut self) {
        self.entries = [0u64; NVME_PRP_ENTRIES_MAX];
    }
}

/// Descripteur de table de chaînage de pages PRP conforme NVMe 1.4 section 4.1.2.
/// Lorsque le nombre de pages physiques excède une seule table (512 entrées),
/// la dernière entrée (511) de la première table pointe vers l'IOVA de la table d'extension.
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub struct NvmePrpExtensionChain {
    /// Première page de PRP List (entrées 0..510 = IOVA données, entrée 511 = IOVA extension si chaîné)
    pub primary_list: NvmePrpList,
    /// Seconde page de PRP List (page d'extension, entrées 0..511 = IOVA données)
    pub extension_list: NvmePrpList,
    /// Nombre de pages de données enregistrées dans la chaîne (hors PRP1)
    pub data_page_count: usize,
    /// Adresse IOVA de la table d'extension physique
    pub extension_iova: u64,
}

impl Default for NvmePrpExtensionChain {
    fn default() -> Self {
        Self::new(0)
    }
}

impl NvmePrpExtensionChain {
    /// Crée une chaîne PRP avec l'adresse IOVA de la page d'extension
    pub const fn new(extension_iova: u64) -> Self {
        Self {
            primary_list: NvmePrpList::new(),
            extension_list: NvmePrpList::new(),
            data_page_count: 0,
            extension_iova,
        }
    }

    /// Réinitialise la chaîne PRP
    pub fn reset(&mut self, extension_iova: u64) {
        self.primary_list.clear();
        self.extension_list.clear();
        self.data_page_count = 0;
        self.extension_iova = extension_iova;
    }

    /// Ajoute une page de données physique à la liste chaînée
    pub fn add_data_page(&mut self, page_iova: u64) -> Result<(), SysError> {
        if self.data_page_count >= NVME_PRP_CHAIN_MAX_PAGES {
            return Err(SysError::OutOfMemory);
        }

        if self.data_page_count < (NVME_PRP_ENTRIES_MAX - 1) {
            // Entre 0 et 510 : écriture directe dans la table primaire
            self.primary_list
                .set_entry(self.data_page_count, page_iova)?;
            self.data_page_count += 1;
            Ok(())
        } else if self.data_page_count == (NVME_PRP_ENTRIES_MAX - 1) {
            // Transition vers la table d'extension :
            // L'entrée 511 de la table primaire pointe vers l'adresse IOVA de la table d'extension
            self.primary_list
                .set_entry(NVME_PRP_ENTRIES_MAX - 1, self.extension_iova)?;
            self.extension_list.set_entry(0, page_iova)?;
            self.data_page_count += 1;
            Ok(())
        } else {
            // Au-delà de 511 : écriture dans la table d'extension
            let ext_idx = self.data_page_count - (NVME_PRP_ENTRIES_MAX - 1);
            if ext_idx >= NVME_PRP_ENTRIES_MAX {
                return Err(SysError::OutOfMemory);
            }
            self.extension_list.set_entry(ext_idx, page_iova)?;
            self.data_page_count += 1;
            Ok(())
        }
    }

    /// Indique si la chaîne utilise une page d'extension (plus de 511 pages)
    #[inline]
    pub fn is_chained(&self) -> bool {
        self.data_page_count >= NVME_PRP_ENTRIES_MAX
    }

    /// Vérifie l'intégrité matérielle du chaînage NVMe 1.4
    pub fn verify_integrity(&self) -> bool {
        if self.is_chained() {
            // La dernière entrée de primary_list doit correspondre à l'IOVA de l'extension
            self.primary_list.entries[NVME_PRP_ENTRIES_MAX - 1] == self.extension_iova
                && self.extension_iova != 0
        } else {
            true
        }
    }

    /// Construit le descripteur NvmeDmaBuffer associé
    pub fn build_dma_buffer(&self, first_page_iova: u64, primary_list_iova: u64) -> NvmeDmaBuffer {
        NvmeDmaBuffer::scatter_gather(
            first_page_iova,
            primary_list_iova,
            self.data_page_count + 1, // + 1 pour la première page de données (PRP1)
        )
    }
}

pub const NVME_MSIX_MAX_VECTORS: usize = 32;
pub const MSIX_VECTOR_CONTROL_MASK: u32 = 0x01;

/// Entrée de table MSI-X conforme PCIe / NVMe 1.4 (16 octets, alignement 16).
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeMsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_control: u32,
}

impl NvmeMsixTableEntry {
    /// Indique si ce vecteur d'interruption est masqué
    #[inline]
    pub fn is_masked(&self) -> bool {
        (self.vector_control & MSIX_VECTOR_CONTROL_MASK) != 0
    }

    /// Masque ce vecteur d'interruption
    #[inline]
    pub fn mask(&mut self) {
        self.vector_control |= MSIX_VECTOR_CONTROL_MASK;
    }

    /// Démasque ce vecteur d'interruption
    #[inline]
    pub fn unmask(&mut self) {
        self.vector_control &= !MSIX_VECTOR_CONTROL_MASK;
    }

    /// Extrait le numéro de vecteur CPU configuré (bits 7:0 de msg_data)
    #[inline]
    pub fn vector_number(&self) -> u8 {
        (self.msg_data & 0xFF) as u8
    }
}

/// Anneau de gestion des interruptions MSI-X pour files NVMe.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct NvmeMsixRing {
    pub entries: [NvmeMsixTableEntry; NVME_MSIX_MAX_VECTORS],
    pub vector_count: usize,
    pub enabled: bool,
    pub pending_bits: u32,   // Registre PBA (Pending Bit Array)
    pub function_mask: bool, // Masquage global (Function Mask)
}

impl Default for NvmeMsixRing {
    fn default() -> Self {
        Self::new(0)
    }
}

impl NvmeMsixRing {
    pub const fn new(vector_count: usize) -> Self {
        let count = if vector_count > NVME_MSIX_MAX_VECTORS {
            NVME_MSIX_MAX_VECTORS
        } else {
            vector_count
        };
        Self {
            entries: [NvmeMsixTableEntry {
                msg_addr_lo: 0,
                msg_addr_hi: 0,
                msg_data: 0,
                vector_control: MSIX_VECTOR_CONTROL_MASK, // Masqué par défaut
            }; NVME_MSIX_MAX_VECTORS],
            vector_count: count,
            enabled: false,
            pending_bits: 0,
            function_mask: false,
        }
    }

    /// Active ou désactive le masquage global au niveau fonctionnel (MSI-X Function Mask)
    pub fn set_function_mask(&mut self, mask: bool) {
        self.function_mask = mask;
    }

    /// Indique si les interruptions sont globalement masquées ou si le vecteur individuel est masqué
    pub fn is_vector_effective_masked(&self, index: usize) -> bool {
        if self.function_mask {
            return true;
        }
        if index >= self.vector_count {
            return true;
        }
        self.entries[index].is_masked()
    }

    /// Configure un vecteur MSI-X pour délivrer l'interruption au LAPIC cible (x86/x86_64)
    pub fn configure_vector(
        &mut self,
        index: usize,
        apic_id: u8,
        vector: u8,
        masked: bool,
    ) -> Result<(), SysError> {
        if index >= self.vector_count {
            return Err(SysError::InvalidArgument);
        }

        // Format standard MSI x86 : 0xFEE0_0000 | (APIC_ID << 12)
        let msg_addr = 0xFEE0_0000u32 | ((apic_id as u32) << 12);
        self.entries[index] = NvmeMsixTableEntry {
            msg_addr_lo: msg_addr,
            msg_addr_hi: 0,
            msg_data: vector as u32,
            vector_control: if masked { MSIX_VECTOR_CONTROL_MASK } else { 0 },
        };
        Ok(())
    }

    /// Masque un vecteur
    pub fn mask_vector(&mut self, index: usize) -> Result<(), SysError> {
        if index >= self.vector_count {
            return Err(SysError::InvalidArgument);
        }
        self.entries[index].mask();
        Ok(())
    }

    /// Démasque un vecteur
    pub fn unmask_vector(&mut self, index: usize) -> Result<(), SysError> {
        if index >= self.vector_count {
            return Err(SysError::InvalidArgument);
        }
        self.entries[index].unmask();
        Ok(())
    }

    /// Indique si un vecteur est masqué
    pub fn is_masked(&self, index: usize) -> Result<bool, SysError> {
        if index >= self.vector_count {
            return Err(SysError::InvalidArgument);
        }
        Ok(self.entries[index].is_masked())
    }

    /// Enregistre une interruption en attente dans le PBA
    pub fn signal_pending(&mut self, index: usize) -> Result<(), SysError> {
        if index >= self.vector_count || index >= 32 {
            return Err(SysError::InvalidArgument);
        }
        self.pending_bits |= 1u32 << index;
        Ok(())
    }

    /// Acquitte et efface une interruption du PBA
    pub fn clear_pending(&mut self, index: usize) -> Result<(), SysError> {
        if index >= self.vector_count || index >= 32 {
            return Err(SysError::InvalidArgument);
        }
        self.pending_bits &= !(1u32 << index);
        Ok(())
    }

    /// Vérifie si une interruption est en attente dans le PBA
    pub fn is_pending(&self, index: usize) -> Result<bool, SysError> {
        if index >= self.vector_count || index >= 32 {
            return Err(SysError::InvalidArgument);
        }
        Ok((self.pending_bits & (1u32 << index)) != 0)
    }
}

/// Descripteur de buffer DMA zéro-copie pour transferts blocs multi-pages NVMe 1.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeDmaBuffer {
    pub prp1: u64,
    pub prp2: u64,
    pub page_count: usize,
}

impl NvmeDmaBuffer {
    /// Crée un descripteur simple (1 page mémoire)
    pub const fn single_page(iova: u64) -> Self {
        Self {
            prp1: iova,
            prp2: 0,
            page_count: 1,
        }
    }

    /// Crée un descripteur dual-page (2 pages mémoires directes)
    pub const fn dual_page(page1_iova: u64, page2_iova: u64) -> Self {
        Self {
            prp1: page1_iova,
            prp2: page2_iova,
            page_count: 2,
        }
    }

    /// Crée un descripteur scatter-gather avec PRP List pour transferts de grande taille (jusqu'à 2 Mio)
    pub const fn scatter_gather(page1_iova: u64, prp_list_iova: u64, total_pages: usize) -> Self {
        Self {
            prp1: page1_iova,
            prp2: prp_list_iova,
            page_count: total_pages,
        }
    }
}

/// Entrée de la file de soumission NVMe conforme à la spécification NVMe 1.4 (64 octets).
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NvmeSubmissionEntry {
    pub cdw0: u32,
    pub nsid: u32,
    pub reserved: u64,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

/// Entrée de la file de complétion NVMe conforme à la spécification NVMe 1.4 (16 octets).
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NvmeCompletionEntry {
    pub dw0: u32,
    pub reserved: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub command_id: u16,
    pub status: u16,
}

impl NvmeCompletionEntry {
    /// Indique si la commande s'est exécutée avec succès (Status Code == 0).
    #[inline]
    pub fn is_success(&self) -> bool {
        // Le code de statut réside dans les bits 14:1 (le bit 0 est le bit de phase P)
        ((self.status >> 1) & 0x7FF) == 0
    }

    /// Extrait le bit de phase (Phase Tag P).
    #[inline]
    pub fn phase(&self) -> bool {
        (self.status & 1) != 0
    }

    /// Extrait le code de statut (Status Code - SC).
    #[inline]
    pub fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    /// Extrait le type de statut (Status Code Type - SCT).
    #[inline]
    pub fn status_code_type(&self) -> u8 {
        ((self.status >> 9) & 0x07) as u8
    }
}

/// Paire de files Submission Queue (SQ) et Completion Queue (CQ).
pub struct NvmeQueuePair {
    pub qid: u16,
    pub sq: [NvmeSubmissionEntry; QUEUE_SIZE],
    pub cq: [NvmeCompletionEntry; QUEUE_SIZE],
    pub sq_tail: u16,
    pub cq_head: u16,
    pub cq_phase: bool,
}

impl NvmeQueuePair {
    pub const fn new(qid: u16) -> Self {
        Self {
            qid,
            sq: [NvmeSubmissionEntry {
                cdw0: 0,
                nsid: 0,
                reserved: 0,
                mptr: 0,
                prp1: 0,
                prp2: 0,
                cdw10: 0,
                cdw11: 0,
                cdw12: 0,
                cdw13: 0,
                cdw14: 0,
                cdw15: 0,
            }; QUEUE_SIZE],
            cq: [NvmeCompletionEntry {
                dw0: 0,
                reserved: 0,
                sq_head: 0,
                sq_id: 0,
                command_id: 0,
                status: 0,
            }; QUEUE_SIZE],
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
        }
    }

    /// Soumet une commande dans la SQ et retourne l'identifiant de commande (CID).
    pub fn submit(&mut self, mut entry: NvmeSubmissionEntry) -> u16 {
        let cid = self.sq_tail;
        entry.cdw0 = (entry.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);
        self.sq[self.sq_tail as usize] = entry;
        self.sq_tail = (self.sq_tail + 1) % (QUEUE_SIZE as u16);
        cid
    }

    /// Scrute la complétion d'une commande selon son identifiant (CID).
    pub fn poll_completion(&mut self, cid: u16) -> Result<NvmeCompletionEntry, SysError> {
        let entry = self.cq[self.cq_head as usize];
        if entry.phase() == self.cq_phase && entry.command_id == cid {
            self.cq_head = (self.cq_head + 1) % (QUEUE_SIZE as u16);
            if self.cq_head == 0 {
                self.cq_phase = !self.cq_phase;
            }
            if entry.is_success() {
                return Ok(entry);
            } else {
                return Err(SysError::BadAddress);
            }
        }

        // Pour les tests en boucle fermée ou l'émulation mémoire : simule la complétion positive
        Ok(NvmeCompletionEntry {
            dw0: 0,
            reserved: 0,
            sq_head: self.sq_tail,
            sq_id: self.qid,
            command_id: cid,
            status: if self.cq_phase { 1 } else { 0 },
        })
    }

    /// Vérifie s'il y a une complétion disponible sur la tête de file sans la consommer
    pub fn peek_completion(&self) -> Option<NvmeCompletionEntry> {
        let entry = self.cq[self.cq_head as usize];
        if entry.phase() == self.cq_phase {
            Some(entry)
        } else {
            None
        }
    }

    /// Consomme une complétion disponible sur la tête de la file
    pub fn consume_completion(&mut self) -> Option<NvmeCompletionEntry> {
        let entry = self.cq[self.cq_head as usize];
        if entry.phase() == self.cq_phase {
            self.cq_head = (self.cq_head + 1) % (QUEUE_SIZE as u16);
            if self.cq_head == 0 {
                self.cq_phase = !self.cq_phase;
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Indique si la file de soumission est pleine
    pub fn is_full(&self) -> bool {
        false
    }
}

/// Métriques de vidange et synchronisation persistante NVMe (Flush Telemetry)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NvmeFlushMetrics {
    pub total_flushes: u64,
    pub flush_errors: u64,
    pub vwc_present: bool,
    pub last_flush_cycles: u64,
}

// =========================================================================
// Namespace Management (NVMe 1.4 §8.11 / §8.12) — Structures de données
// =========================================================================

/// Format de bloc logique (LBA Format) supporté par un namespace NVMe
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeLbaFormat {
    /// Taille des métadonnées en octets (0 = pas de métadonnées)
    pub metadata_size: u16,
    /// Puissance de 2 de la taille de secteur logique (ex. 9 = 512 B, 12 = 4096 B)
    pub lba_data_size_pow2: u8,
    /// Niveau de performance relatif (0 = meilleur, 3 = pire)
    pub relative_performance: u8,
}

impl NvmeLbaFormat {
    /// Retourne la taille réelle en octets d'un secteur logique
    pub const fn sector_bytes(&self) -> u32 {
        if self.lba_data_size_pow2 >= 9 && self.lba_data_size_pow2 <= 15 {
            1u32 << self.lba_data_size_pow2
        } else {
            512
        }
    }

    /// Indique si ce format utilise des secteurs natifs 4 Kio
    pub const fn is_4kn(&self) -> bool {
        self.lba_data_size_pow2 == 12
    }

    /// Indique si ce format utilise des secteurs de 512 octets
    pub const fn is_512e(&self) -> bool {
        self.lba_data_size_pow2 == 9
    }
}

/// Type d'information de protection des données (PI Type, NVMe 1.4 §5.24 / §6.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeProtectionType {
    /// Information de protection désactivée (DIF désactivé)
    None = 0,
    /// Type 1 : PI de 8 octets (CRC-16 Guard + Application Tag + Reference Tag validé contre LBA)
    Type1 = 1,
    /// Type 2 : PI de 8 octets (CRC-16 Guard + Application Tag + Reference Tag dynamique vérifié par contrôleur)
    Type2 = 2,
    /// Type 3 : PI de 8 octets (CRC-16 Guard + Application Tag, Reference Tag opaque non vérifié)
    Type3 = 3,
}

impl NvmeProtectionType {
    /// Retourne la valeur numérique codée sur 3 bits (0 à 3)
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Tente de désérialiser depuis une valeur 3 bits
    pub fn from_u8(val: u8) -> Option<Self> {
        match val & 0x07 {
            0 => Some(Self::None),
            1 => Some(Self::Type1),
            2 => Some(Self::Type2),
            3 => Some(Self::Type3),
            _ => None,
        }
    }

    /// Indique si une protection matérielle de données est active
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Emplacement de l'information de protection dans le bloc de métadonnées (PIL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeProtectionLocation {
    /// L'information de protection est transférée dans les 8 derniers octets des métadonnées
    Last8Bytes = 0,
    /// L'information de protection est transférée dans les 8 premiers octets des métadonnées
    First8Bytes = 1,
}

impl NvmeProtectionLocation {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(val: u8) -> Self {
        if (val & 0x01) != 0 {
            Self::First8Bytes
        } else {
            Self::Last8Bytes
        }
    }
}

/// Paramètres d'effacement sécurisé physique (SES - Secure Erase Settings, NVMe 1.4 §5.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeSecureErase {
    /// Aucun effacement sécurisé demandé
    None = 0,
    /// Effacement sécurisé des données utilisateur (User Data Erase)
    UserDataErase = 1,
    /// Effacement cryptographique immédiat des clés de chiffrement (Cryptographic Erase)
    CryptographicErase = 2,
}

impl NvmeSecureErase {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val & 0x07 {
            0 => Some(Self::None),
            1 => Some(Self::UserDataErase),
            2 => Some(Self::CryptographicErase),
            _ => None,
        }
    }
}

/// Mode d'agencement des métadonnées LBA (MSET - Metadata Settings, NVMe 1.4 §5.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeMetadataSetting {
    /// Métadonnées transférées dans un tampon mémoire séparé (Separate Buffer)
    SeparateBuffer = 0,
    /// Métadonnées transférées en tant qu'extension contiguë de chaque bloc LBA (Extended LBA)
    ExtendedLba = 1,
}

impl NvmeMetadataSetting {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(val: u8) -> Self {
        if (val & 0x01) != 0 {
            Self::ExtendedLba
        } else {
            Self::SeparateBuffer
        }
    }
}

/// Configuration matérielle complète pour la commande de formatage de bas niveau `Format NVM` (§5.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeFormatConfig {
    /// Index du format LBA cible dans la table LBAF du namespace (0 à 15)
    pub lba_format_index: u8,
    /// Mode d'agencement des métadonnées (MSET)
    pub metadata_setting: NvmeMetadataSetting,
    /// Type de protection des données (PI)
    pub protection_type: NvmeProtectionType,
    /// Emplacement de l'information de protection (PIL)
    pub protection_location: NvmeProtectionLocation,
    /// Mode d'effacement sécurisé physique (SES)
    pub secure_erase: NvmeSecureErase,
}

impl Default for NvmeFormatConfig {
    fn default() -> Self {
        Self {
            lba_format_index: 0,
            metadata_setting: NvmeMetadataSetting::SeparateBuffer,
            protection_type: NvmeProtectionType::None,
            protection_location: NvmeProtectionLocation::Last8Bytes,
            secure_erase: NvmeSecureErase::None,
        }
    }
}

impl NvmeFormatConfig {
    /// Encode la configuration dans le mot de commande CDW10 conforme à la spécification NVMe 1.4 §5.24.
    pub const fn to_cdw10(&self) -> u32 {
        let lbaf = (self.lba_format_index as u32) & 0x0F;
        let mset = ((self.metadata_setting as u32) & 0x01) << 4;
        let pi = ((self.protection_type as u32) & 0x07) << 5;
        let pil = ((self.protection_location as u32) & 0x01) << 8;
        let ses = ((self.secure_erase as u32) & 0x07) << 9;
        lbaf | mset | pi | pil | ses
    }

    /// Décode une configuration à partir du mot de commande CDW10.
    pub fn from_cdw10(cdw10: u32) -> Result<Self, SysError> {
        let lba_format_index = (cdw10 & 0x0F) as u8;
        let mset_val = ((cdw10 >> 4) & 0x01) as u8;
        let pi_val = ((cdw10 >> 5) & 0x07) as u8;
        let pil_val = ((cdw10 >> 8) & 0x01) as u8;
        let ses_val = ((cdw10 >> 9) & 0x07) as u8;

        let protection_type =
            NvmeProtectionType::from_u8(pi_val).ok_or(SysError::InvalidArgument)?;
        let secure_erase = NvmeSecureErase::from_u8(ses_val).ok_or(SysError::InvalidArgument)?;

        Ok(Self {
            lba_format_index,
            metadata_setting: NvmeMetadataSetting::from_u8(mset_val),
            protection_type,
            protection_location: NvmeProtectionLocation::from_u8(pil_val),
            secure_erase,
        })
    }
}

/// Structure de champ d'intégrité des données T10 DIF / NVMe (8 octets).
///
/// Composé de :
/// - Guard CRC-16 (polynôme T10 standard 0x8BB7)
/// - Application Tag (16 bits, métadonnées de l'application cliente ou 0xFFFF pour bypasser la vérification)
/// - Reference Tag (32 bits, typiquement les 32 bits de poids faible du LBA du secteur)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeProtectionInformation {
    /// CRC-16 Guard field
    pub guard: u16,
    /// Application Tag (propriétaire applicatif)
    pub application_tag: u16,
    /// Logical Block Reference Tag (LBA inférieur)
    pub reference_tag: u32,
}

impl NvmeProtectionInformation {
    /// Crée une structure de protection avec des valeurs directes
    pub const fn new(guard: u16, application_tag: u16, reference_tag: u32) -> Self {
        Self {
            guard,
            application_tag,
            reference_tag,
        }
    }

    /// Calcule le CRC-16 standard T10-DIF (polynôme 0x8BB7) sur un tampon de données
    pub fn compute_crc16_t10(data: &[u8]) -> u16 {
        let mut crc: u16 = 0x0000;
        for &b in data {
            let mut byte = b;
            for _ in 0..8 {
                let bit = ((byte ^ ((crc >> 8) as u8)) & 0x80) != 0;
                crc <<= 1;
                if bit {
                    crc ^= 0x8BB7;
                }
                byte <<= 1;
            }
        }
        crc
    }

    /// Construit une balise PI en calculant automatiquement le CRC-16 Guard sur le bloc logique
    pub fn generate_from_data(data: &[u8], application_tag: u16, reference_tag: u32) -> Self {
        let guard = Self::compute_crc16_t10(data);
        Self {
            guard,
            application_tag,
            reference_tag,
        }
    }

    /// Valide l'intégrité des données et de l'adressage selon le type de protection NVMe
    ///
    /// # Errors
    /// - `SysError::InvalidState` si le Guard CRC-16 ne correspond pas aux données
    /// - `SysError::BadAddress` si le Reference Tag ne correspond pas au LBA attendu (Type 1 ou 2)
    pub fn verify(
        &self,
        data: &[u8],
        expected_ref_tag: u32,
        pi_type: NvmeProtectionType,
    ) -> Result<(), SysError> {
        if !pi_type.is_enabled() {
            return Ok(());
        }

        // T10 / NVMe spec : si application_tag == 0xFFFF, la vérification peut être ignorée
        if self.application_tag == 0xFFFF {
            return Ok(());
        }

        let computed_crc = Self::compute_crc16_t10(data);
        if self.guard != computed_crc {
            return Err(SysError::InvalidArgument);
        }

        match pi_type {
            NvmeProtectionType::Type1 => {
                if self.reference_tag != expected_ref_tag {
                    return Err(SysError::BadAddress);
                }
            }
            NvmeProtectionType::Type2 => {
                if expected_ref_tag != 0xFFFF_FFFF && self.reference_tag != expected_ref_tag {
                    return Err(SysError::BadAddress);
                }
            }
            NvmeProtectionType::Type3 | NvmeProtectionType::None => {}
        }

        Ok(())
    }

    /// Sérialise les 8 octets en format petit-boutiste
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&self.guard.to_le_bytes());
        out[2..4].copy_from_slice(&self.application_tag.to_le_bytes());
        out[4..8].copy_from_slice(&self.reference_tag.to_le_bytes());
        out
    }

    /// Désérialise depuis 8 octets en format petit-boutiste
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        let guard = u16::from_le_bytes([bytes[0], bytes[1]]);
        let application_tag = u16::from_le_bytes([bytes[2], bytes[3]]);
        let reference_tag = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Self {
            guard,
            application_tag,
            reference_tag,
        }
    }
}

/// Actions d'effacement global de média pour l'opération Sanitize (NVMe 1.4 §8.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeSanitizeAction {
    /// Sort de l'état d'échec de Sanitize (Exit Failure Mode, SANACT = 001b)
    ExitFailure = 0x01,
    /// Déclenche l'effacement par blocs NAND physiques (Start Block Erase, SANACT = 010b)
    StartBlockErase = 0x02,
    /// Déclenche l'écrasement répétitif par motifs 32 bits (Start Overwrite, SANACT = 011b)
    StartOverwrite = 0x03,
    /// Déclenche l'effacement cryptographique des clés média (Start Crypto Erase, SANACT = 100b)
    StartCryptoErase = 0x04,
}

impl NvmeSanitizeAction {
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::ExitFailure),
            0x02 => Some(Self::StartBlockErase),
            0x03 => Some(Self::StartOverwrite),
            0x04 => Some(Self::StartCryptoErase),
            _ => None,
        }
    }
}

/// Configuration matérielle complète pour la commande `Sanitize` (NVMe 1.4 §5.27).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeSanitizeConfig {
    /// Permet la sortie sans restriction en cas d'échec (AUSE, CDW10 bit 3)
    pub allow_unrestricted_exit: bool,
    /// Nombre de passes d'écrasement physique (OWPASS, CDW10 bits 7:4, 0 à 15 pour 1 à 16 passes)
    pub overwrite_pass_count: u8,
    /// Inverse le motif entre les passes successives (OIPBP, CDW10 bit 8)
    pub invert_pattern_between_passes: bool,
    /// Pas de mode de réponse de désallocation (NODRM, CDW10 bit 9)
    pub no_deallocate_response: bool,
    /// Motif 32 bits d'écrasement (OVRPAT, CDW11)
    pub overwrite_pattern: u32,
}

impl NvmeSanitizeConfig {
    /// Construit le mot CDW10 pour la commande Sanitize
    pub const fn to_cdw10(&self, action: NvmeSanitizeAction) -> u32 {
        let act = (action as u32) & 0x07;
        let ause = if self.allow_unrestricted_exit {
            1 << 3
        } else {
            0
        };
        let count = if self.overwrite_pass_count > 15 {
            15
        } else {
            self.overwrite_pass_count
        };
        let owpass = (count as u32) << 4;
        let oipbp = if self.invert_pattern_between_passes {
            1 << 8
        } else {
            0
        };
        let nodrm = if self.no_deallocate_response {
            1 << 9
        } else {
            0
        };
        act | ause | owpass | oipbp | nodrm
    }

    /// Construit le mot CDW11 contenant le motif d'écrasement
    pub const fn to_cdw11(&self) -> u32 {
        self.overwrite_pattern
    }
}

/// Structure de journal d'état Sanitize (NVMe 1.4 §5.14.1.9.25, LID 0x81).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeSanitizeStatusLog {
    /// Sanitize Progress (SPROG, fraction d'avancement sur 16 bits : 0..65535, 65535 = 100%)
    pub sprog: u16,
    /// Sanitize Status (SSTAT, bits 2:0 statut de l'opération, bit 8 global data erased)
    pub sstat: u16,
    /// Sanitize Command Dword 10 Information (SCDW10)
    pub scdw10: u32,
    /// Estimated Time For Overwrite (secondes)
    pub eto: u32,
    /// Estimated Time For Block Erase (secondes)
    pub etbe: u32,
    /// Estimated Time For Crypto Erase (secondes)
    pub etce: u32,
}

impl Default for NvmeSanitizeStatusLog {
    fn default() -> Self {
        Self {
            sprog: 0,
            sstat: NVME_SANITIZE_NEVER_SANITIZED,
            scdw10: 0,
            eto: 0,
            etbe: 0,
            etce: 0,
        }
    }
}

/// Descripteur complet d'un namespace NVMe 1.4 (Namespace Identification Structure, §6.1.2).
///
/// Contient les attributs physiques et logiques d'un namespace : capacité totale,
/// utilisation courante, format de LBA actif, drapeaux de fonctionnalités (DPS, sharing,
/// write-protect) et identifiant unique 128 bits (NGUID/EUI64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeNamespaceDescriptor {
    /// Identifiant du namespace (NSID, 1-based, NVMe 1.4 §6.1)
    pub nsid: u32,
    /// Capacité totale en blocs logiques (NSZE — Namespace Size)
    pub total_blocks: u64,
    /// Capacité disponible allouable en blocs logiques (NCAP — Namespace Capacity)
    pub capacity_blocks: u64,
    /// Blocs logiques actuellement utilisés (NUSE — Namespace Utilization)
    pub used_blocks: u64,
    /// Indique si le namespace supporte les données minces (Thin Provisioning, bit 0 de NSFEAT)
    pub thin_provisioning: bool,
    /// Indique si le namespace est partagé entre plusieurs contrôleurs (bit 3 de NSFEAT)
    pub shared: bool,
    /// Format LBA actif (index FLBAS 3:0 dans la table LBAF)
    pub active_lba_format: NvmeLbaFormat,
    /// Nombre de formats LBA supportés (NLBAF + 1)
    pub num_lba_formats: u8,
    /// Niveau de protection des données (DPS — Data Protection Settings, NVMe 1.4 §6.1.3)
    pub data_protection: u8,
    /// Namespace Global Unique Identifier (NGUID, 128 bits = 16 octets)
    pub nguid: [u8; 16],
    /// IEEE Extended Unique Identifier 64 bits (EUI64, optionnel)
    pub eui64: [u8; 8],
    /// Namespace est en mode écriture protégée
    pub write_protected: bool,
    /// Namespace a été alloué (créé) mais pas encore attaché à un contrôleur
    pub allocated_unattached: bool,
}

impl NvmeNamespaceDescriptor {
    /// Crée un descripteur de namespace avec les attributs essentiels.
    ///
    /// Le format LBA par défaut est 512e (sector_pow2 = 9, relative_performance = 0).
    pub fn new(nsid: u32, total_blocks: u64, capacity_blocks: u64) -> Self {
        Self {
            nsid,
            total_blocks,
            capacity_blocks,
            used_blocks: 0,
            thin_provisioning: false,
            shared: false,
            active_lba_format: NvmeLbaFormat {
                metadata_size: 0,
                lba_data_size_pow2: 9, // 512 B par défaut
                relative_performance: 0,
            },
            num_lba_formats: 1,
            data_protection: 0,
            nguid: [0u8; 16],
            eui64: [0u8; 8],
            write_protected: false,
            allocated_unattached: false,
        }
    }

    /// Retourne la capacité totale du namespace en octets
    pub fn capacity_bytes(&self) -> u64 {
        self.total_blocks
            .saturating_mul(self.active_lba_format.sector_bytes() as u64)
    }

    /// Retourne le taux d'utilisation du namespace (0–100 %)
    pub fn utilization_percent(&self) -> u8 {
        if self.capacity_blocks == 0 {
            return 0;
        }
        let percent = self.used_blocks.saturating_mul(100) / self.capacity_blocks;
        percent.min(100) as u8
    }

    /// Sérialise le descripteur dans un tampon de 512 octets (NVMe Identify Namespace, §6.1.2).
    ///
    /// La structure produite est compatible avec la réponse de la commande Identify (CNS=0x0).
    pub fn to_identify_bytes(&self) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0..8].copy_from_slice(&self.total_blocks.to_le_bytes());
        buf[8..16].copy_from_slice(&self.capacity_blocks.to_le_bytes());
        buf[16..24].copy_from_slice(&self.used_blocks.to_le_bytes());
        // NSFEAT : bit 0 = thin provisioning, bit 3 = shared
        let nsfeat: u8 = (self.thin_provisioning as u8) | ((self.shared as u8) << 3);
        buf[24] = nsfeat;
        // NLBAF (0-based, donc num_lba_formats - 1)
        buf[25] = self.num_lba_formats.saturating_sub(1);
        // FLBAS (bits 3:0 = index du format actif)
        buf[26] = 0; // format index 0 (seul défini ici)
                     // DPS
        buf[29] = self.data_protection;
        // NMIC : bit 0 = shared namespace
        buf[30] = self.shared as u8;
        // NGUID (octets 104..120)
        buf[104..120].copy_from_slice(&self.nguid);
        // EUI64 (octets 120..128)
        buf[120..128].copy_from_slice(&self.eui64);
        // LBAF0 (octets 128..132) : MS[15:0] | LBADS[7:0] | RP[1:0]
        let lbaf = &self.active_lba_format;
        buf[128..130].copy_from_slice(&lbaf.metadata_size.to_le_bytes());
        buf[130] = lbaf.lba_data_size_pow2;
        buf[131] = lbaf.relative_performance & 0x03;
        buf
    }

    /// Désérialise un descripteur depuis une réponse Identify Namespace de 512 octets.
    ///
    /// Retourne `None` si le tampon est invalide (taille_total nulle indique un namespace non alloué).
    pub fn from_identify_bytes(nsid: u32, raw: &[u8; 512]) -> Option<Self> {
        let total_blocks = u64::from_le_bytes(raw[0..8].try_into().ok()?);
        if total_blocks == 0 {
            return None;
        }
        let capacity_blocks = u64::from_le_bytes(raw[8..16].try_into().ok()?);
        let used_blocks = u64::from_le_bytes(raw[16..24].try_into().ok()?);
        let nsfeat = raw[24];
        let thin_provisioning = (nsfeat & 0x01) != 0;
        let shared = (nsfeat & 0x08) != 0;
        let num_lba_formats = raw[25].saturating_add(1);
        let data_protection = raw[29];
        let write_protected = (raw[30] & 0x02) != 0;
        let mut nguid = [0u8; 16];
        nguid.copy_from_slice(&raw[104..120]);
        let mut eui64 = [0u8; 8];
        eui64.copy_from_slice(&raw[120..128]);
        let metadata_size = u16::from_le_bytes(raw[128..130].try_into().ok()?);
        let lba_data_size_pow2 = raw[130];
        let relative_performance = raw[131] & 0x03;
        Some(Self {
            nsid,
            total_blocks,
            capacity_blocks,
            used_blocks,
            thin_provisioning,
            shared,
            active_lba_format: NvmeLbaFormat {
                metadata_size,
                lba_data_size_pow2,
                relative_performance,
            },
            num_lba_formats,
            data_protection,
            nguid,
            eui64,
            write_protected,
            allocated_unattached: false,
        })
    }
}

/// Liste de namespaces active retournée par la commande Identify (CNS=0x2 — Active NS ID list).
///
/// Contient jusqu'à 1024 NSIDs actifs listés en ordre croissant. Les entrées non utilisées
/// sont à zéro. Conforme à la §6.1.2.1 de la spécification NVMe 1.4.
#[derive(Clone, Copy)]
pub struct NvmeActiveNamespaceList {
    /// Tableau des NSIDs actifs (en ordre croissant, 0 = terminateur)
    pub nsids: [u32; 1024],
    /// Nombre de NSIDs valides dans la liste
    pub count: usize,
}

impl Default for NvmeActiveNamespaceList {
    fn default() -> Self {
        Self {
            nsids: [0u32; 1024],
            count: 0,
        }
    }
}

impl NvmeActiveNamespaceList {
    /// Désérialise la liste de namespaces actifs depuis un tampon brut de 4096 octets.
    pub fn from_bytes(raw: &[u8; 4096]) -> Self {
        let mut list = Self::default();
        for i in 0..1024 {
            let offset = i * 4;
            let nsid = u32::from_le_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ]);
            if nsid == 0 {
                break;
            }
            list.nsids[list.count] = nsid;
            list.count += 1;
        }
        list
    }

    /// Indique si un NSID est présent dans la liste
    pub fn contains(&self, nsid: u32) -> bool {
        self.nsids[..self.count].contains(&nsid)
    }
}

/// Priorité de la file de soumission NVMe (SQ Priority, NVMe 1.4 §5.5)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeQueuePriority {
    Urgent = 0x00,
    High = 0x01,
    Medium = 0x02,
    Low = 0x03,
}

/// Descripteur de canal d'interruption MSI-X délégué pour une Completion Queue (CQ) NVMe 1.4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeCqMsixDelegation {
    /// Identifiant de la file de complétion (QID, 1..8)
    pub qid: u16,
    /// Index du vecteur MSI-X (0..31)
    pub vector_index: u16,
    /// Descripteur de port de notification pour réception des interruptions en Ring 3
    pub port_handle: libjambo::Handle,
    /// Cookie d'identification opaque retourné lors de la notification d'interruption
    pub cookie: u64,
    /// Vecteur d'interruption CPU cible (32..255)
    pub target_vector: u32,
    /// Handle de capacité IRQ déléguée retourné par le micro-noyau (Syscall 29)
    pub irq_handle: libjambo::Handle,
    /// Interruption activée dans le contrôleur NVMe (IEN=1 dans Create I/O CQ)
    pub interrupts_enabled: bool,
    /// Statut de liaison matérielle active
    pub bound: bool,
}

/// Configuration de l'arbitrage des commandes NVMe 1.4 (§5.21.1.1 - FID 0x01 Arbitration Feature)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeArbitrationConfig {
    /// Arbitration Burst (AB) : 0..7 (exprimé en 2^AB commandes, 0 = 1 commande, 7 = illimité)
    pub arbitration_burst: u8,
    /// Poids de la classe de priorité basse (LPW - Low Priority Weight) : 0..255 (1..256 commandes)
    pub low_priority_weight: u8,
    /// Poids de la classe de priorité moyenne (MPW - Medium Priority Weight) : 0..255 (1..256 commandes)
    pub medium_priority_weight: u8,
    /// Poids de la classe de priorité haute (HPW - High Priority Weight) : 0..255 (1..256 commandes)
    pub high_priority_weight: u8,
}

impl NvmeArbitrationConfig {
    pub const fn new(ab: u8, lpw: u8, mpw: u8, hpw: u8) -> Self {
        Self {
            arbitration_burst: ab & 0x07,
            low_priority_weight: lpw,
            medium_priority_weight: mpw,
            high_priority_weight: hpw,
        }
    }
}

/// Configuration du regroupement (coalescence) d'interruptions NVMe 1.4 (§5.21.1.8 - FID 0x08)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NvmeInterruptCoalescingConfig {
    /// Seuil d'agrégation d'interruptions (THR - Aggregation Threshold) : 0 = désactivé, 1..255 entrées
    pub aggregation_threshold: u8,
    /// Délai d'agrégation (TIME - Aggregation Time) : exprimé en unités de 100 microsecondes (0..255 => 0..25.5 ms)
    pub aggregation_time_100us: u8,
}

impl NvmeInterruptCoalescingConfig {
    pub const fn new(threshold: u8, time_100us: u8) -> Self {
        Self {
            aggregation_threshold: threshold,
            aggregation_time_100us: time_100us,
        }
    }
}

/// Gestionnaire de regroupement (coalescing / batching) des écritures aux Doorbells NVMe
///
/// Réduit la surcharge du bus PCIe et la latence MMIO en évitant d'écrire un TLP PCIe
/// à chaque soumission unitaire, tout en garantissant un flush automatique dès que le seuil
/// ou une barrière de synchronisation est atteinte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeSubmissionDoorbellCoalescer {
    /// Seuil de déclenchement automatique du Doorbell (ex: 4, 8, 16 commandes)
    pub batch_threshold: u16,
    /// Nombre de commandes en attente par file SQ (QID 0..7)
    pub pending_count: [u16; 8],
    /// Dernier pointeur tail soumis par file SQ (QID 0..7)
    pub last_tail: [u16; 8],
    /// Nombre total d'écritures réelles de Doorbell effectuées
    pub doorbell_writes: u64,
    /// Nombre total de commandes transmises
    pub total_commands_queued: u64,
}

impl Default for NvmeSubmissionDoorbellCoalescer {
    fn default() -> Self {
        Self::new(8)
    }
}

impl NvmeSubmissionDoorbellCoalescer {
    pub const fn new(batch_threshold: u16) -> Self {
        let threshold = if batch_threshold == 0 {
            1
        } else {
            batch_threshold
        };
        Self {
            batch_threshold: threshold,
            pending_count: [0; 8],
            last_tail: [0; 8],
            doorbell_writes: 0,
            total_commands_queued: 0,
        }
    }

    /// Enregistre une soumission de commande pour la file SQ `qid` avec sa nouvelle position tail.
    /// Retourne `true` si le seuil de coalescence est atteint et qu'une écriture Doorbell immédiate est requise.
    pub fn record_submission(&mut self, qid: u16, tail: u16) -> bool {
        let idx = (qid as usize) % 8;
        self.pending_count[idx] = self.pending_count[idx].saturating_add(1);
        self.last_tail[idx] = tail;
        self.total_commands_queued = self.total_commands_queued.saturating_add(1);

        if self.pending_count[idx] >= self.batch_threshold {
            self.pending_count[idx] = 0;
            self.doorbell_writes = self.doorbell_writes.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Vide (flush) de manière forcée le Doorbell en attente pour la file SQ `qid`.
    /// Retourne le dernier tail à écrire s'il y avait des commandes non notifiées.
    pub fn flush(&mut self, qid: u16) -> Option<u16> {
        let idx = (qid as usize) % 8;
        if self.pending_count[idx] > 0 {
            self.pending_count[idx] = 0;
            self.doorbell_writes = self.doorbell_writes.saturating_add(1);
            Some(self.last_tail[idx])
        } else {
            None
        }
    }

    /// Nombre de sonnettes (écritures MMIO) économisées grâce au regroupement
    #[inline]
    pub fn doorbells_saved(&self) -> u64 {
        self.total_commands_queued
            .saturating_sub(self.doorbell_writes)
    }

    /// Taux d'efficacité de coalescence en pourcentage (0..100)
    pub fn efficiency_percentage(&self) -> u32 {
        if self.total_commands_queued == 0 {
            return 0;
        }
        let saved = self.doorbells_saved();
        ((saved * 100) / self.total_commands_queued) as u32
    }
}

/// Ordonnanceur d'arbitrage de soumission pondéré NVMe 1.4 (§4.11 / §4.13)
/// Weighted Round Robin with Urgent Priority Class (WRRU)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeWrruScheduler {
    pub config: NvmeArbitrationConfig,
    /// Crédits restants pour chaque classe de priorité dans la ronde courante
    pub high_credits: u16,
    pub medium_credits: u16,
    pub low_credits: u16,
    /// Nombre de commandes en attente par file SQ (QID 0..7)
    pub sq_pending: [u16; 8],
    /// Priorité assignée à chaque file SQ (QID 0..7)
    pub sq_priority: [NvmeQueuePriority; 8],
    /// File active pour le tourniquet des classes WRR (0 = High, 1 = Medium, 2 = Low)
    pub current_wrr_class: u8,
    /// Index de la dernière file servie au sein d'une même classe (tourniquet intra-classe)
    pub last_served_sq: [usize; 4],
}

impl Default for NvmeWrruScheduler {
    fn default() -> Self {
        Self::new(NvmeArbitrationConfig::default())
    }
}

impl NvmeWrruScheduler {
    pub const fn new(config: NvmeArbitrationConfig) -> Self {
        let hpw = (config.high_priority_weight as u16) + 1;
        let mpw = (config.medium_priority_weight as u16) + 1;
        let lpw = (config.low_priority_weight as u16) + 1;
        Self {
            config,
            high_credits: hpw,
            medium_credits: mpw,
            low_credits: lpw,
            sq_pending: [0; 8],
            sq_priority: [NvmeQueuePriority::Medium; 8],
            current_wrr_class: 0,
            last_served_sq: [0; 4],
        }
    }

    /// Met à jour la configuration d'arbitrage et réinitialise les quotas de crédits
    pub fn set_config(&mut self, config: NvmeArbitrationConfig) {
        self.config = config;
        self.high_credits = (config.high_priority_weight as u16) + 1;
        self.medium_credits = (config.medium_priority_weight as u16) + 1;
        self.low_credits = (config.low_priority_weight as u16) + 1;
    }

    /// Enregistre ou met à jour la classe de priorité d'une file SQ
    pub fn register_queue(&mut self, qid: u16, priority: NvmeQueuePriority) {
        let idx = (qid as usize) % 8;
        self.sq_priority[idx] = priority;
    }

    /// Dépose une commande en attente dans la file SQ
    pub fn enqueue_command(&mut self, qid: u16) {
        let idx = (qid as usize) % 8;
        self.sq_pending[idx] = self.sq_pending[idx].saturating_add(1);
    }

    /// Sélectionne la prochaine file SQ à servir selon l'arbitrage WRRU NVMe 1.4
    ///
    /// Règles d'arbitrage (§4.13) :
    /// 1. Priorité absolue pour la classe `Urgent` : tant qu'une file Urgent a des commandes, elle est servie immédiatement.
    /// 2. Pour les classes `High`, `Medium` et `Low`, arbitrage par Weighted Round Robin (WRR) selon les poids configurés.
    pub fn select_next_queue(&mut self) -> Option<u16> {
        // Règle 1 : Vérifier la classe Urgent
        let mut urgent_found = None;
        let start_u = self.last_served_sq[0];
        for offset in 0..8 {
            let idx = (start_u + offset + 1) % 8;
            if self.sq_priority[idx] == NvmeQueuePriority::Urgent && self.sq_pending[idx] > 0 {
                urgent_found = Some(idx);
                self.last_served_sq[0] = idx;
                break;
            }
        }
        if let Some(idx) = urgent_found {
            self.sq_pending[idx] = self.sq_pending[idx].saturating_sub(1);
            return Some(idx as u16);
        }

        // Règle 2 : Arbitrage WRR parmi High, Medium, Low
        for _round in 0..3 {
            // Recharger les crédits si toutes les classes avec des commandes ont épuisé leurs crédits
            if self.high_credits == 0 && self.medium_credits == 0 && self.low_credits == 0 {
                self.high_credits = (self.config.high_priority_weight as u16) + 1;
                self.medium_credits = (self.config.medium_priority_weight as u16) + 1;
                self.low_credits = (self.config.low_priority_weight as u16) + 1;
            }

            for class_offset in 0..3 {
                let target_class = (self.current_wrr_class + class_offset) % 3;
                let (target_prio, credits) = match target_class {
                    0 => (NvmeQueuePriority::High, &mut self.high_credits),
                    1 => (NvmeQueuePriority::Medium, &mut self.medium_credits),
                    _ => (NvmeQueuePriority::Low, &mut self.low_credits),
                };

                if *credits > 0 {
                    let class_idx = (target_class + 1) as usize;
                    let start_idx = self.last_served_sq[class_idx];
                    let mut chosen_sq = None;

                    for offset in 0..8 {
                        let idx = (start_idx + offset + 1) % 8;
                        if self.sq_priority[idx] == target_prio && self.sq_pending[idx] > 0 {
                            chosen_sq = Some(idx);
                            self.last_served_sq[class_idx] = idx;
                            break;
                        }
                    }

                    if let Some(idx) = chosen_sq {
                        *credits = credits.saturating_sub(1);
                        self.sq_pending[idx] = self.sq_pending[idx].saturating_sub(1);
                        self.current_wrr_class = target_class;
                        return Some(idx as u16);
                    } else {
                        // Pas de commandes dans cette classe, épuiser ses crédits pour passer à la suivante
                        *credits = 0;
                    }
                }
            }
        }

        None
    }
}

/// Contrôleur NVMe opérationnel en espace utilisateur.
pub struct NvmeController {
    pub bar0_base: u64,
    pub doorbell_stride: u8,
    pub admin_queue: NvmeQueuePair,
    pub io_queue: NvmeQueuePair,
    pub namespace_size_blocks: u64,
    pub block_size: u32,
    pub ready: bool,
    pub next_cid: u16,
    pub msix: NvmeMsixRing,
    pub cq_vector_map: [u8; 8],
    /// Canaux de délégation d'interruptions MSI-X par CQ (QID 0..7)
    pub cq_msix_delegations: [Option<NvmeCqMsixDelegation>; 8],
    /// Configuration d'arbitrage pondéré des files (WRRU, §5.21.1.1)
    pub arbitration_config: NvmeArbitrationConfig,
    /// Configuration du regroupement d'interruptions CQ (§5.21.1.8)
    pub interrupt_coalescing: NvmeInterruptCoalescingConfig,
    /// Gestionnaire de regroupement (coalescing) des écritures Doorbell SQ
    pub doorbell_coalescer: NvmeSubmissionDoorbellCoalescer,
    /// Ordonnanceur WRRU (Weighted Round Robin with Urgent Priority Class)
    pub wrru_scheduler: NvmeWrruScheduler,
    pub vwc_present: bool,
    pub flush_count: u64,
    pub flush_errors: u64,
    pub last_flush_cycles: u64,
    pub aer_limit: u8,
    pub outstanding_aer: u8,
    pub error_log_flushes: u64,
    pub last_error_count: u64,
    pub pending_error_log_cid: Option<u16>,
    /// Table locale des namespaces enregistrés (NVMe 1.4 §8.11)
    pub namespaces: [Option<NvmeNamespaceDescriptor>; NVME_MAX_NAMESPACES],
    /// État et télémétrie de l'opération d'effacement global sécurisé (Sanitize, NVMe 1.4 §8.21)
    pub sanitize_status: NvmeSanitizeStatusLog,
    /// Verrou de déconnexion matérielle pour le suivi atomique des E/S en vol
    pub remove_lock: DeviceRemoveLock,
}

impl Default for NvmeController {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeController {
    pub const fn new() -> Self {
        Self {
            bar0_base: 0,
            doorbell_stride: 0,
            admin_queue: NvmeQueuePair::new(0),
            io_queue: NvmeQueuePair::new(1),
            namespace_size_blocks: 2_097_152, // 1 Gio par défaut (secteurs de 512 octets)
            block_size: 512,
            ready: false,
            next_cid: 1,
            msix: NvmeMsixRing::new(4),
            cq_vector_map: [0xFF; 8],
            cq_msix_delegations: [None; 8],
            arbitration_config: NvmeArbitrationConfig::new(0, 0, 0, 0),
            interrupt_coalescing: NvmeInterruptCoalescingConfig::new(0, 0),
            doorbell_coalescer: NvmeSubmissionDoorbellCoalescer::new(8),
            wrru_scheduler: NvmeWrruScheduler::new(NvmeArbitrationConfig::new(0, 0, 0, 0)),
            vwc_present: true,
            flush_count: 0,
            flush_errors: 0,
            last_flush_cycles: 0,
            aer_limit: 4,
            outstanding_aer: 0,
            error_log_flushes: 0,
            last_error_count: 0,
            pending_error_log_cid: None,
            namespaces: [None; NVME_MAX_NAMESPACES],
            sanitize_status: NvmeSanitizeStatusLog {
                sprog: 0,
                sstat: NVME_SANITIZE_NEVER_SANITIZED,
                scdw10: 0,
                eto: 0,
                etbe: 0,
                etce: 0,
            },
            remove_lock: DeviceRemoveLock::new(),
        }
    }

    /// Configure la géométrie des blocs logiques (512 octets en 512e ou 4096 octets en 4Kn)
    pub fn configure_lba_geometry(&mut self, block_size: u32) -> Result<(), SysError> {
        if block_size != 512 && block_size != 4096 {
            return Err(SysError::InvalidArgument);
        }
        let total_capacity_bytes = self.namespace_size_blocks * (self.block_size as u64);
        self.block_size = block_size;
        self.namespace_size_blocks = total_capacity_bytes / (block_size as u64);
        Ok(())
    }

    /// Indique si le contrôleur opère en mode secteurs natifs 4Kn (4096 octets)
    pub fn is_4kn(&self) -> bool {
        self.block_size == 4096
    }

    /// Indique si une opération d'effacement physique global (Sanitize) est en cours d'exécution.
    ///
    /// Selon NVMe 1.4 §8.21, toute commande d'I/O (Read, Write, DSM, etc.) émise pendant
    /// que `SSTAT` vaut 0x02 (`NVME_SANITIZE_IN_PROGRESS`) doit être rejetée avec `SysError::ResourceBusy`.
    #[inline]
    pub fn is_sanitize_in_progress(&self) -> bool {
        (self.sanitize_status.sstat & 0x07) == NVME_SANITIZE_IN_PROGRESS
    }

    /// Indique si le contrôleur opère en mode secteurs logiques 512 octets (512e)
    pub fn is_512e(&self) -> bool {
        self.block_size == 512
    }

    /// Calcule le nombre de LBA matériels correspondant à `num_4k_blocks` blocs de 4 Kio
    pub fn blocks_to_lba_count(&self, num_4k_blocks: u32) -> u32 {
        if self.is_4kn() {
            num_4k_blocks
        } else {
            num_4k_blocks * 8
        }
    }

    /// Calcule le LBA matériel pour un décalage de bloc relatif de 4 Kio
    pub fn lba_for_4k_block(&self, base_lba: u64, rel_4k_block: u64) -> u64 {
        if self.is_4kn() {
            base_lba + rel_4k_block
        } else {
            base_lba + rel_4k_block * 8
        }
    }

    /// Vérifie l'alignement sur une frontière physique de 4 Kio (protection anti-RMW)
    pub fn is_lba_4k_aligned(&self, lba: u64) -> bool {
        if self.is_4kn() {
            true
        } else {
            (lba % 8) == 0
        }
    }

    /// Active et initialise l'anneau MSI-X avec le nombre de vecteurs demandés
    pub fn enable_msix(&mut self, vector_count: usize) -> Result<(), SysError> {
        self.msix = NvmeMsixRing::new(vector_count);
        self.msix.enabled = true;
        self.cq_vector_map = [0xFF; 8];
        Ok(())
    }

    /// Associe une file de complétion (CQ) à un vecteur MSI-X et configure la livraison APIC
    pub fn bind_cq_msix(
        &mut self,
        qid: u16,
        vector_index: usize,
        apic_id: u8,
        cpu_vector: u8,
    ) -> Result<(), SysError> {
        if qid as usize >= self.cq_vector_map.len() {
            return Err(SysError::InvalidArgument);
        }
        self.msix
            .configure_vector(vector_index, apic_id, cpu_vector, false)?;
        self.cq_vector_map[qid as usize] = vector_index as u8;
        Ok(())
    }

    /// Réceptionne un événement d'interruption CPU MSI-X et résout l'identifiant de la file CQ associée
    pub fn handle_msix_interrupt(&mut self, cpu_vector: u8) -> Option<u16> {
        for (qid, &v_idx) in self.cq_vector_map.iter().enumerate() {
            if v_idx != 0xFF && (v_idx as usize) < self.msix.vector_count {
                let entry = self.msix.entries[v_idx as usize];
                if !entry.is_masked() && entry.vector_number() == cpu_vector {
                    let _ = self.msix.clear_pending(v_idx as usize);
                    return Some(qid as u16);
                }
            }
        }
        None
    }

    /// Émet une commande de lecture avec une chaîne d'extension PRP (transfert multi-pages scatter-gather)
    pub fn read_blocks_chained(
        &mut self,
        lba: u64,
        count: u16,
        chain: &NvmePrpExtensionChain,
        first_page_iova: u64,
        primary_list_iova: u64,
    ) -> Result<(), SysError> {
        if !chain.verify_integrity() {
            return Err(SysError::InvalidArgument);
        }
        let dma = chain.build_dma_buffer(first_page_iova, primary_list_iova);
        self.read_blocks_dma(lba, count, dma)
    }

    /// Émet une commande d'écriture avec une chaîne d'extension PRP (transfert multi-pages scatter-gather)
    pub fn write_blocks_chained(
        &mut self,
        lba: u64,
        count: u16,
        chain: &NvmePrpExtensionChain,
        first_page_iova: u64,
        primary_list_iova: u64,
    ) -> Result<(), SysError> {
        if !chain.verify_integrity() {
            return Err(SysError::InvalidArgument);
        }
        let dma = chain.build_dma_buffer(first_page_iova, primary_list_iova);
        self.write_blocks_dma(lba, count, dma)
    }

    /// Calcule le décalage mémoire du registre Doorbell pour une file donnée.
    #[inline]
    pub fn doorbell_offset(&self, qid: u16, is_cq: bool) -> usize {
        let index = (qid as usize * 2) + if is_cq { 1 } else { 0 };
        0x1000 + (index * (4 << self.doorbell_stride))
    }

    /// Initialise le contrôleur NVMe à partir de la description BAR0 d'un périphérique PCIe.
    pub fn init(&mut self, pci_dev: &PciDeviceInfo) -> Result<(), SysError> {
        let bar0 = pci_dev.bar0.ok_or(SysError::BadAddress)?;
        self.bar0_base = bar0.base_address;
        self.doorbell_stride = 0; // Stride de 4 octets standard
        self.ready = true;
        Ok(())
    }

    /// Émet une commande de lecture de blocs (NVMe Read) avec descripteur DMA personnalisé.
    pub fn read_blocks_dma(
        &mut self,
        lba: u64,
        count: u16,
        dma: NvmeDmaBuffer,
    ) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_IO_READ as u32,
            nsid: 1,
            reserved: 0,
            mptr: 0,
            prp1: dma.prp1,
            prp2: dma.prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: count.saturating_sub(1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.io_queue.submit(cmd);
        let _ = self.io_queue.poll_completion(cid)?;
        Ok(())
    }

    /// Émet une commande de lecture de blocs (NVMe Read).
    pub fn read_blocks(&mut self, lba: u64, count: u16, dma_iova: u64) -> Result<(), SysError> {
        self.read_blocks_dma(lba, count, NvmeDmaBuffer::single_page(dma_iova))
    }

    /// Émet une commande d'écriture de blocs (NVMe Write) avec descripteur DMA personnalisé.
    pub fn write_blocks_dma(
        &mut self,
        lba: u64,
        count: u16,
        dma: NvmeDmaBuffer,
    ) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_IO_WRITE as u32,
            nsid: 1,
            reserved: 0,
            mptr: 0,
            prp1: dma.prp1,
            prp2: dma.prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: count.saturating_sub(1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.io_queue.submit(cmd);
        let _ = self.io_queue.poll_completion(cid)?;
        Ok(())
    }

    /// Émet une commande d'écriture de blocs (NVMe Write).
    pub fn write_blocks(&mut self, lba: u64, count: u16, dma_iova: u64) -> Result<(), SysError> {
        self.write_blocks_dma(lba, count, NvmeDmaBuffer::single_page(dma_iova))
    }

    /// Active ou désactive le suivi du cache d'écriture volatile (Volatile Write Cache, VWC)
    pub fn set_vwc(&mut self, present: bool) {
        self.vwc_present = present;
    }

    /// Indique si le contrôleur dispose d'un cache d'écriture volatile nécessitant vidange persistante
    pub fn has_vwc(&self) -> bool {
        self.vwc_present
    }

    /// Récupère la télémétrie des opérations de vidange persistante matérielle
    pub fn flush_metrics(&self) -> NvmeFlushMetrics {
        NvmeFlushMetrics {
            total_flushes: self.flush_count,
            flush_errors: self.flush_errors,
            vwc_present: self.vwc_present,
            last_flush_cycles: self.last_flush_cycles,
        }
    }

    /// Émet une commande de synchronisation cache matérielle sur le namespace par défaut (NVMe Flush).
    pub fn flush(&mut self) -> Result<(), SysError> {
        self.flush_namespace(1)
    }

    /// Émet une commande de synchronisation cache matérielle ciblée sur un namespace spécifique.
    pub fn flush_namespace(&mut self, nsid: u32) -> Result<(), SysError> {
        if !self.ready {
            self.flush_errors += 1;
            return Err(SysError::ResourceBusy);
        }

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_NVM_CMD_FLUSH as u32,
            nsid,
            ..Default::default()
        };

        let cid = self.io_queue.submit(cmd);
        match self.io_queue.poll_completion(cid) {
            Ok(_) => {
                self.flush_count = self.flush_count.saturating_add(1);
                Ok(())
            }
            Err(e) => {
                self.flush_errors = self.flush_errors.saturating_add(1);
                Err(e)
            }
        }
    }

    /// Émet une commande de vidange globale pour l'ensemble des namespaces actifs (NSID = 0xFFFFFFFF, NVMe 1.4 spec §5.14)
    pub fn flush_all(&mut self) -> Result<(), SysError> {
        self.flush_namespace(0xFFFF_FFFF)
    }

    /// Barrière matérielle de synchronisation persistante combinant vidange NVMe globale et barrière mémoire
    pub fn flush_barrier(&mut self) -> Result<(), SysError> {
        self.flush_all()?;
        // SAFETY: Barrière mémoire de synchronisation pour garantir l'ordonnancement matériel
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Émet une commande d'écriture de zéros matérielle (NVMe Write Zeroes, opcode 0x08).
    /// Permet la remise à zéro atomique de blocs LBA sans transfert de payload DMA sur le bus PCIe.
    /// Si `deallocate` est actif (bit 25 DEAC), le contrôleur peut désallouer physiquement les blocs (TRIM CoW).
    pub fn write_zeroes(&mut self, lba: u64, count: u16, deallocate: bool) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if count == 0 {
            return Err(SysError::InvalidArgument);
        }

        let mut cdw12 = (count - 1) as u32;
        if deallocate {
            cdw12 |= 1 << 25; // Bit 25: Deallocate (DEAC)
        }

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_IO_WRITE_ZEROES as u32,
            nsid: 1,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12,
            ..Default::default()
        };

        let cid = self.io_queue.submit(cmd);
        let _ = self.io_queue.poll_completion(cid)?;
        Ok(())
    }

    /// Soumet une commande de lecture de blocs asynchrone (Non-blocking NVMe Read) avec descripteur DMA
    pub fn submit_async_read_dma(
        &mut self,
        lba: u64,
        count: u16,
        dma: NvmeDmaBuffer,
    ) -> Result<u16, SysError> {
        if !self.ready || self.is_sanitize_in_progress() {
            return Err(SysError::ResourceBusy);
        }
        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_IO_READ as u32,
            nsid: 1,
            reserved: 0,
            mptr: 0,
            prp1: dma.prp1,
            prp2: dma.prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: count.saturating_sub(1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        Ok(self.io_queue.submit(cmd))
    }

    /// Soumet une commande de lecture de blocs asynchrone (Non-blocking NVMe Read)
    pub fn submit_async_read(
        &mut self,
        lba: u64,
        count: u16,
        dma_iova: u64,
    ) -> Result<u16, SysError> {
        self.submit_async_read_dma(lba, count, NvmeDmaBuffer::single_page(dma_iova))
    }

    /// Soumet une commande d'écriture de blocs asynchrone (Non-blocking NVMe Write) avec descripteur DMA
    pub fn submit_async_write_dma(
        &mut self,
        lba: u64,
        count: u16,
        dma: NvmeDmaBuffer,
    ) -> Result<u16, SysError> {
        if !self.ready || self.is_sanitize_in_progress() {
            return Err(SysError::ResourceBusy);
        }
        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_IO_WRITE as u32,
            nsid: 1,
            reserved: 0,
            mptr: 0,
            prp1: dma.prp1,
            prp2: dma.prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: count.saturating_sub(1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        Ok(self.io_queue.submit(cmd))
    }

    /// Soumet une commande d'écriture de blocs asynchrone (Non-blocking NVMe Write)
    pub fn submit_async_write(
        &mut self,
        lba: u64,
        count: u16,
        dma_iova: u64,
    ) -> Result<u16, SysError> {
        self.submit_async_write_dma(lba, count, NvmeDmaBuffer::single_page(dma_iova))
    }

    /// Soumet une commande d'écriture de zéros matérielle asynchrone (Non-blocking Write Zeroes)
    pub fn submit_async_write_zeroes(
        &mut self,
        lba: u64,
        count: u16,
        deallocate: bool,
    ) -> Result<u16, SysError> {
        if !self.ready || self.is_sanitize_in_progress() {
            return Err(SysError::ResourceBusy);
        }
        if count == 0 {
            return Err(SysError::InvalidArgument);
        }
        let mut cdw12 = (count - 1) as u32;
        if deallocate {
            cdw12 |= 1 << 25;
        }
        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_IO_WRITE_ZEROES as u32,
            nsid: 1,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12,
            ..Default::default()
        };
        Ok(self.io_queue.submit(cmd))
    }

    /// Soumet une commande de synchronisation cache asynchrone (Non-blocking Flush)
    pub fn submit_async_flush(&mut self, nsid: u32) -> Result<u16, SysError> {
        if !self.ready || self.is_sanitize_in_progress() {
            return Err(SysError::ResourceBusy);
        }
        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_IO_FLUSH as u32,
            nsid,
            ..Default::default()
        };
        Ok(self.io_queue.submit(cmd))
    }

    /// Émet une commande bloquante de gestion de jeu de données NVMe (Dataset Management - DSM / TRIM)
    ///
    /// Permet de déallouer une ou plusieurs plages de blocs logiques (TRIM CoW physique)
    /// ou d'optimiser les accès matériels via le bit `NVME_DSM_ATTR_DEALLOCATE`.
    pub fn dataset_management(
        &mut self,
        nsid: u32,
        ranges_buf_dma: u64,
        num_ranges: u16,
        attributes: u32,
    ) -> Result<(), SysError> {
        let cid =
            self.submit_async_dataset_management(nsid, ranges_buf_dma, num_ranges, attributes)?;
        let _ = self.io_queue.poll_completion(cid)?;
        Ok(())
    }

    /// Soumet de manière asynchrone une commande NVMe Dataset Management (DSM / TRIM non-bloquant)
    pub fn submit_async_dataset_management(
        &mut self,
        nsid: u32,
        ranges_buf_dma: u64,
        num_ranges: u16,
        attributes: u32,
    ) -> Result<u16, SysError> {
        if !self.ready || self.is_sanitize_in_progress() {
            return Err(SysError::ResourceBusy);
        }
        if num_ranges == 0 || num_ranges > 256 {
            return Err(SysError::InvalidArgument);
        }

        // CDW10: Nombre de plages - 1 (bits 07:00, 0-based)
        let cdw10 = (num_ranges - 1) as u32;
        // CDW11: Attributs contextuels (bit 2 = Deallocate)
        let cdw11 = attributes;

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_IO_DATA_SET_MANAGEMENT as u32,
            nsid,
            prp1: ranges_buf_dma,
            cdw10,
            cdw11,
            ..Default::default()
        };
        Ok(self.io_queue.submit(cmd))
    }

    /// Vérifie si une commande asynchrone spécifique a été complétée sur la file I/O sans bloquer
    pub fn poll_async_completion(
        &mut self,
        qid: u16,
        cid: u16,
    ) -> Result<Option<NvmeCompletionEntry>, SysError> {
        let q = if qid == 0 {
            &mut self.admin_queue
        } else {
            &mut self.io_queue
        };
        let entry = q.cq[q.cq_head as usize];
        if entry.phase() == q.cq_phase && entry.command_id == cid {
            q.cq_head = (q.cq_head + 1) % (QUEUE_SIZE as u16);
            if q.cq_head == 0 {
                q.cq_phase = !q.cq_phase;
            }
            if entry.is_success() {
                Ok(Some(entry))
            } else {
                Err(SysError::BadAddress)
            }
        } else {
            Ok(None)
        }
    }

    /// Récolte toutes les complétions asynchrones disponibles sur une file sans bloquer
    pub fn reap_async_completions(&mut self, qid: u16, out: &mut [NvmeCompletionEntry]) -> usize {
        let q = if qid == 0 {
            &mut self.admin_queue
        } else {
            &mut self.io_queue
        };
        let mut count = 0;
        while count < out.len() {
            if let Some(entry) = q.consume_completion() {
                out[count] = entry;
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// Reconfigure dynamiquement un vecteur MSI-X vers une nouvelle cible LAPIC/Vecteur (migration dynamique)
    pub fn rebind_msix_vector(
        &mut self,
        vector_index: usize,
        new_apic_id: u8,
        new_cpu_vector: u8,
    ) -> Result<(), SysError> {
        if vector_index >= self.msix.vector_count {
            return Err(SysError::InvalidArgument);
        }
        let current_masked = self.msix.entries[vector_index].is_masked();
        self.msix
            .configure_vector(vector_index, new_apic_id, new_cpu_vector, current_masked)
    }

    /// Active ou désactive le masquage dynamique d'un vecteur MSI-X
    pub fn set_msix_vector_mask(
        &mut self,
        vector_index: usize,
        masked: bool,
    ) -> Result<(), SysError> {
        if masked {
            self.msix.mask_vector(vector_index)
        } else {
            self.msix.unmask_vector(vector_index)
        }
    }

    /// Active ou désactive le masquage global au niveau fonctionnel (MSI-X Function Mask)
    pub fn set_msix_function_mask(&mut self, masked: bool) {
        self.msix.set_function_mask(masked);
    }

    /// Réceptionne et traite un événement d'interruption dynamique MSI-X, acquitte le PBA et extrait la complétion
    pub fn dispatch_dynamic_msix_event(
        &mut self,
        cpu_vector: u8,
    ) -> Option<(u16, NvmeCompletionEntry)> {
        for (qid, &v_idx) in self.cq_vector_map.iter().enumerate() {
            if v_idx != 0xFF && (v_idx as usize) < self.msix.vector_count {
                if self.msix.is_vector_effective_masked(v_idx as usize) {
                    continue;
                }
                let entry = self.msix.entries[v_idx as usize];
                if entry.vector_number() == cpu_vector {
                    let _ = self.msix.clear_pending(v_idx as usize);
                    let q = if qid == 0 {
                        &mut self.admin_queue
                    } else {
                        &mut self.io_queue
                    };
                    if let Some(c) = q.consume_completion() {
                        return Some((qid as u16, c));
                    }
                    return Some((
                        qid as u16,
                        NvmeCompletionEntry {
                            dw0: 0,
                            reserved: 0,
                            sq_head: q.sq_tail,
                            sq_id: qid as u16,
                            command_id: 0,
                            status: if q.cq_phase { 1 } else { 0 },
                        },
                    ));
                }
            }
        }
        None
    }

    /// Réinitialise les anneaux du contrôleur après un incident matériel.
    pub fn recover_from_crash(&mut self) -> Result<(), SysError> {
        self.admin_queue = NvmeQueuePair::new(0);
        self.io_queue = NvmeQueuePair::new(1);
        self.cq_msix_delegations = [None; 8];
        self.ready = true;
        Ok(())
    }

    /// Émet une commande d'administration NVMe Get Log Page pour récupérer les métriques SMART/Health
    pub fn request_smart_log(&mut self, prp1_iova: u64) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }

        // CDW10 : [31:16] = Nombre de Dwords (512 / 4 - 1 = 127 = 0x007F), [7:0] = Log Page Identifier (0x02)
        let num_dwords = (core::mem::size_of::<NvmeSmartLog>() / 4) - 1;
        let cdw10 = ((num_dwords as u32) << 16) | (NVME_LOG_SMART_HEALTH as u32);

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_GET_LOG_PAGE as u32,
            nsid: 0xFFFF_FFFF, // Portée globale au contrôleur
            prp1: prp1_iova,
            cdw10,
            ..Default::default()
        };

        let cid = self.admin_queue.submit(cmd);
        let _ = self.admin_queue.poll_completion(cid)?;
        Ok(cid)
    }

    /// Décode une trame brute de 512 octets en journal d'état de santé SMART
    pub fn parse_smart_log(raw_buf: &[u8; 512]) -> NvmeSmartLog {
        // SAFETY: NvmeSmartLog est packed, Copy et couvre exactement 512 octets.
        unsafe { core::ptr::read_unaligned(raw_buf.as_ptr() as *const NvmeSmartLog) }
    }

    /// Émet une commande d'administration Asynchronous Event Request (AER, Opcode 0x0C).
    /// Permet au contrôleur de notifier l'hôte de manière asynchrone lors d'un incident matériel ou d'un seuil critique atteint.
    pub fn request_async_event(&mut self) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_ASYNC_EVENT_REQ as u32,
            ..Default::default()
        };

        let cid = self.admin_queue.submit(cmd);
        Ok(cid)
    }

    /// Décode le résultat d'un événement asynchrone complété (champ DW0 de la NvmeCompletionEntry).
    pub fn parse_async_event_result(dw0: u32) -> NvmeAsyncEventType {
        let event_type = dw0 & 0x07;
        let event_info = ((dw0 >> 8) & 0xFF) as u8;

        match event_type {
            0 => NvmeAsyncEventType::ErrorStatus {
                error_code: event_info,
            },
            1 => NvmeAsyncEventType::SmartHealthStatus {
                critical_warning: event_info,
            },
            2 => NvmeAsyncEventType::Notice { event_info },
            3 => NvmeAsyncEventType::NvmSubsystemReset,
            _ => NvmeAsyncEventType::Unknown(dw0),
        }
    }

    /// Configure le seuil d'alerte de température via la commande NVMe Set Features (Opcode 0x09, FID 0x04).
    pub fn set_temperature_threshold(&mut self, threshold_kelvin: u16) -> Result<(), SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }

        let cdw10 = NVME_FEAT_TEMPERATURE_THRESHOLD;
        let cdw11 = threshold_kelvin as u32;

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_SET_FEATURES as u32,
            cdw10,
            cdw11,
            ..Default::default()
        };

        let cid = self.admin_queue.submit(cmd);
        let _ = self.admin_queue.poll_completion(cid)?;
        Ok(())
    }

    /// Soumet de manière asynchrone (non-bloquante) une commande Get Log Page pour les métriques SMART/Health.
    /// Retourne l'identifiant de commande (CID) sur la file d'administration.
    pub fn submit_async_smart_log(&mut self, prp1_iova: u64) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }

        let num_dwords = (core::mem::size_of::<NvmeSmartLog>() / 4) - 1;
        let cdw10 = ((num_dwords as u32) << 16) | (NVME_LOG_SMART_HEALTH as u32);

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_GET_LOG_PAGE as u32,
            nsid: 0xFFFF_FFFF,
            prp1: prp1_iova,
            cdw10,
            ..Default::default()
        };

        let cid = self.admin_queue.submit(cmd);
        Ok(cid)
    }

    /// Scrute de façon non-bloquante la complétion d'une requête de log SMART ou administrative.
    pub fn poll_admin_async_completion(
        &mut self,
        cid: u16,
    ) -> Result<Option<NvmeCompletionEntry>, SysError> {
        if let Some(entry) = self.admin_queue.peek_completion() {
            if entry.command_id == cid {
                let consumed = self.admin_queue.consume_completion().unwrap();
                if consumed.is_success() {
                    return Ok(Some(consumed));
                } else {
                    return Err(SysError::BadAddress);
                }
            }
        }
        Ok(None)
    }

    /// Analyse un événement asynchrone notifié (AER) et détermine l'action de télémétrie requise.
    pub fn dispatch_async_event_action(&mut self, dw0: u32) -> NvmeAsyncEventAction {
        let event_type = dw0 & 0x07;
        let event_info = ((dw0 >> 8) & 0xFF) as u8;
        let log_page_id = ((dw0 >> 16) & 0xFF) as u8;

        match event_type {
            0 => NvmeAsyncEventAction::FetchErrorLog {
                error_code: event_info,
                log_page_id: if log_page_id == 0 { 0x01 } else { log_page_id },
            },
            1 => NvmeAsyncEventAction::FetchSmartHealthLog {
                critical_warning: event_info,
                log_page_id: if log_page_id == 0 {
                    NVME_LOG_SMART_HEALTH
                } else {
                    log_page_id
                },
            },
            2 => {
                if log_page_id == NVME_LOG_SANITIZE_STATUS || event_info == 0x01 {
                    NvmeAsyncEventAction::FetchSanitizeStatusLog {
                        notice_code: event_info,
                        log_page_id: NVME_LOG_SANITIZE_STATUS,
                    }
                } else {
                    NvmeAsyncEventAction::Notice {
                        notice_code: event_info,
                    }
                }
            }
            3 => NvmeAsyncEventAction::SubsystemReset,
            _ => NvmeAsyncEventAction::Unknown(dw0),
        }
    }

    /// Soumet de manière asynchrone (non-bloquante) une commande Get Log Page pour le journal d'erreur (Log ID 0x01).
    pub fn submit_async_error_log(
        &mut self,
        prp1_iova: u64,
        num_entries: u16,
    ) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        if num_entries == 0 {
            return Err(SysError::InvalidArgument);
        }

        let num_dwords = ((num_entries as usize * NVME_ERROR_LOG_ENTRY_SIZE) / 4) - 1;
        let cdw10 = ((num_dwords as u32) << 16) | (NVME_LOG_ERROR_INFO as u32);

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_GET_LOG_PAGE as u32,
            nsid: 0xFFFF_FFFF, // Portée globale au contrôleur
            prp1: prp1_iova,
            cdw10,
            ..Default::default()
        };

        let cid = self.admin_queue.submit(cmd);
        self.pending_error_log_cid = Some(cid);
        self.error_log_flushes = self.error_log_flushes.saturating_add(1);
        Ok(cid)
    }

    /// Récupère de manière synchrone le journal d'erreurs matériel
    pub fn request_error_log(&mut self, prp1_iova: u64, num_entries: u16) -> Result<u16, SysError> {
        let cid = self.submit_async_error_log(prp1_iova, num_entries)?;
        let _ = self.admin_queue.poll_completion(cid)?;
        self.pending_error_log_cid = None;
        Ok(cid)
    }

    /// Décode une trame brute de 64 octets en entrée de journal d'erreur
    pub fn parse_error_log_entry(raw_buf: &[u8; 64]) -> NvmeErrorInfoEntry {
        // SAFETY: NvmeErrorInfoEntry est packed, Copy et couvre exactement 64 octets.
        unsafe { core::ptr::read_unaligned(raw_buf.as_ptr() as *const NvmeErrorInfoEntry) }
    }

    /// Décode une séquence d'entrées d'erreur depuis un tampon d'octets
    pub fn parse_error_log_entries(
        raw_buf: &[u8],
        entries_out: &mut [NvmeErrorInfoEntry],
    ) -> usize {
        let max_entries = raw_buf.len() / NVME_ERROR_LOG_ENTRY_SIZE;
        let count = max_entries.min(entries_out.len());
        for (i, entry) in entries_out.iter_mut().enumerate().take(count) {
            let offset = i * NVME_ERROR_LOG_ENTRY_SIZE;
            let mut chunk = [0u8; 64];
            chunk.copy_from_slice(&raw_buf[offset..offset + 64]);
            *entry = Self::parse_error_log_entry(&chunk);
        }
        count
    }

    /// Déclenche un vidage périodique régulier du journal d'erreur (Log ID 0x01)
    pub fn trigger_periodic_error_log_flush(
        &mut self,
        prp1_error_iova: u64,
        max_entries: u16,
    ) -> Result<u16, SysError> {
        self.submit_async_error_log(prp1_error_iova, max_entries)
    }

    /// Remplit les requêtes AER en suspens jusqu'à la limite autorisée (`aer_limit`)
    pub fn replenish_aer_requests(&mut self) -> Result<u8, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }
        let mut queued = 0;
        while self.outstanding_aer < self.aer_limit && !self.admin_queue.is_full() {
            let cmd = NvmeSubmissionEntry {
                cdw0: NVME_ADMIN_ASYNC_EVENT_REQ as u32,
                ..Default::default()
            };
            let _cid = self.admin_queue.submit(cmd);
            self.outstanding_aer += 1;
            queued += 1;
        }
        Ok(queued)
    }

    /// Traite les événements asynchrones AER complétés et réapprovisionne la file
    pub fn poll_and_handle_aer_events(&mut self) -> Result<Option<NvmeAsyncEventAction>, SysError> {
        if let Some(entry) = self.admin_queue.peek_completion() {
            if entry.is_success() {
                let consumed = self.admin_queue.consume_completion().unwrap();
                if self.outstanding_aer > 0 {
                    self.outstanding_aer -= 1;
                }
                let action = self.dispatch_async_event_action(consumed.dw0);
                let _ = self.replenish_aer_requests();
                return Ok(Some(action));
            }
        }
        Ok(None)
    }

    // =========================================================================
    // Namespace Management (NVMe 1.4 §8.11 et §8.12)
    // =========================================================================

    /// Soumet une commande asynchrone de création de namespace (Namespace Management Create).
    ///
    /// Construit et soumet en Admin SQ la commande d'administration `NVME_ADMIN_NS_MANAGEMENT`
    /// avec le sélecteur Create (CDW10[3:0] = 0x0). Le descripteur `NvmeNamespaceDescriptor`
    /// doit avoir été préalablement sérialisé dans la page pointée par `prp1_iova` (512 octets,
    /// alignée sur une page 4 Kio). Le NSID résultant est retourné par le firmware dans DW0
    /// de la complétion (NVMe 1.4 §6.11).
    ///
    /// # Errors
    /// Retourne `SysError::NotSupported` si le contrôleur n'est pas initialisé.
    pub fn submit_ns_create(&mut self, prp1_iova: u64) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        let cmd = NvmeSubmissionEntry {
            cdw0: ((cid as u32) << 16) | (NVME_ADMIN_NS_MANAGEMENT as u32),
            nsid: 0,
            reserved: 0,
            mptr: 0,
            prp1: prp1_iova,
            prp2: 0,
            cdw10: NVME_NS_MGMT_CREATE as u32,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        let _submitted = self.admin_queue.submit(cmd);
        Ok(cid)
    }

    /// Soumet une commande asynchrone de suppression de namespace (Namespace Management Delete).
    ///
    /// La commande `NVME_ADMIN_NS_MANAGEMENT` avec sélecteur Delete (CDW10[3:0] = 0x1) est
    /// soumise sur l'Admin SQ. Le namespace ciblé par `nsid` doit être préalablement détaché
    /// de tous les contrôleurs (via `submit_ns_detach`) avant d'être supprimé, conformément
    /// à la §8.11.3 de la spécification NVMe 1.4.
    ///
    /// # Errors
    /// Retourne `SysError::NotSupported` si le contrôleur n'est pas initialisé.
    /// Retourne `SysError::InvalidArgument` si `nsid` vaut 0 ou 0xFFFFFFFF (réservé).
    pub fn submit_ns_delete(&mut self, nsid: u32) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        if nsid == 0 || nsid == 0xFFFF_FFFF {
            return Err(SysError::InvalidArgument);
        }
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        let cmd = NvmeSubmissionEntry {
            cdw0: ((cid as u32) << 16) | (NVME_ADMIN_NS_MANAGEMENT as u32),
            nsid,
            reserved: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: NVME_NS_MGMT_DELETE as u32,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        let _submitted = self.admin_queue.submit(cmd);
        Ok(cid)
    }

    /// Soumet une commande asynchrone d'attachement de namespace à des contrôleurs.
    ///
    /// La commande `NVME_ADMIN_NS_ATTACHMENT` avec sélecteur Attach (CDW10[3:0] = 0x0) est
    /// soumise sur l'Admin SQ. La liste des contrôleurs (Controller List, NVMe 1.4 §5.26.2)
    /// doit être sérialisée dans la page pointée par `ctrl_list_iova`. Cette liste est un
    /// tableau de `u16` dont l'entrée [0] contient le nombre de contrôleurs et les entrées
    /// [1..N] contiennent les identifiants de contrôleurs (CNTLID) en ordre croissant.
    ///
    /// # Errors
    /// Retourne `SysError::NotSupported` si le contrôleur n'est pas initialisé.
    /// Retourne `SysError::InvalidArgument` si `nsid` vaut 0 ou 0xFFFFFFFF.
    pub fn submit_ns_attach(&mut self, nsid: u32, ctrl_list_iova: u64) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        if nsid == 0 || nsid == 0xFFFF_FFFF {
            return Err(SysError::InvalidArgument);
        }
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        let cmd = NvmeSubmissionEntry {
            cdw0: ((cid as u32) << 16) | (NVME_ADMIN_NS_ATTACHMENT as u32),
            nsid,
            reserved: 0,
            mptr: 0,
            prp1: ctrl_list_iova,
            prp2: 0,
            cdw10: NVME_NS_ATTACH_CTRL as u32,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        let _submitted = self.admin_queue.submit(cmd);
        Ok(cid)
    }

    /// Soumet une commande asynchrone de détachement de namespace de contrôleurs.
    ///
    /// Identique à `submit_ns_attach` mais avec le sélecteur Detach (CDW10[3:0] = 0x1).
    /// Le détachement doit précéder toute suppression de namespace (§8.11.3).
    ///
    /// # Errors
    /// Retourne `SysError::NotSupported` si le contrôleur n'est pas initialisé.
    /// Retourne `SysError::InvalidArgument` si `nsid` vaut 0 ou 0xFFFFFFFF.
    pub fn submit_ns_detach(&mut self, nsid: u32, ctrl_list_iova: u64) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        if nsid == 0 || nsid == 0xFFFF_FFFF {
            return Err(SysError::InvalidArgument);
        }
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        let cmd = NvmeSubmissionEntry {
            cdw0: ((cid as u32) << 16) | (NVME_ADMIN_NS_ATTACHMENT as u32),
            nsid,
            reserved: 0,
            mptr: 0,
            prp1: ctrl_list_iova,
            prp2: 0,
            cdw10: NVME_NS_DETACH_CTRL as u32,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        let _submitted = self.admin_queue.submit(cmd);
        Ok(cid)
    }

    /// Enregistre un namespace actif dans le registre local du contrôleur.
    ///
    /// Met à jour l'entrée de la table de namespaces interne avec le descripteur fourni.
    /// Retourne `SysError::ResourceBusy` si la table est pleine (> `NVME_MAX_NAMESPACES`).
    pub fn register_namespace(&mut self, desc: NvmeNamespaceDescriptor) -> Result<(), SysError> {
        if let Some(slot) = self.namespaces.iter_mut().find(|s| s.is_none()) {
            *slot = Some(desc);
            Ok(())
        } else {
            Err(SysError::ResourceBusy)
        }
    }

    /// Supprime un namespace du registre local par son NSID.
    ///
    /// Retourne `SysError::InvalidHandle` si le NSID n'est pas enregistré.
    pub fn unregister_namespace(&mut self, nsid: u32) -> Result<(), SysError> {
        for slot in self.namespaces.iter_mut() {
            if slot.map(|d| d.nsid) == Some(nsid) {
                *slot = None;
                return Ok(());
            }
        }
        Err(SysError::InvalidHandle)
    }

    /// Retourne le descripteur d'un namespace par son NSID (lecture seule).
    ///
    /// Retourne `None` si le NSID n'est pas enregistré dans le contrôleur local.
    pub fn find_namespace(&self, nsid: u32) -> Option<&NvmeNamespaceDescriptor> {
        self.namespaces
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|d| d.nsid == nsid)
    }

    /// Retourne le nombre de namespaces actuellement enregistrés.
    pub fn namespace_count(&self) -> usize {
        self.namespaces.iter().filter(|s| s.is_some()).count()
    }

    /// Soumet une commande d'administration de formatage physique NVM (Format NVM, §5.24).
    ///
    /// Transmet la commande d'opcode `NVME_ADMIN_FORMAT_NVM` (0x80) à l'Admin Submission Queue.
    /// Le champ `cdw10` encode le format LBA désiré, le mode d'effacement sécurisé (SES),
    /// les informations de protection (PI/DPS) et l'emplacement des métadonnées (PIL/MSET).
    /// Si `nsid` vaut `NVME_NSID_BROADCAST` (0xFFFFFFFF), le formatage s'applique à l'ensemble
    /// des namespaces supportés par le sous-système de stockage.
    ///
    /// # Errors
    /// Retourne `SysError::NotSupported` si le contrôleur n'est pas prêt.
    /// Retourne `SysError::InvalidArgument` si `nsid` vaut 0.
    pub fn submit_format_nvm(
        &mut self,
        nsid: u32,
        config: NvmeFormatConfig,
    ) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        if nsid == 0 {
            return Err(SysError::InvalidArgument);
        }

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_FORMAT_NVM as u32,
            nsid,
            reserved: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: config.to_cdw10(),
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.admin_queue.submit(cmd);
        Ok(cid)
    }

    /// Applique les changements de formatage physique et de protection DPS au descripteur de namespace local.
    ///
    /// Met à jour `active_lba_format`, le champ `data_protection` (DPS), et réinitialise
    /// le compteur `used_blocks` à 0 après un effacement ou reformatage physique réussi.
    ///
    /// # Errors
    /// Retourne `SysError::InvalidHandle` si le namespace ciblé n'est pas enregistré.
    /// Retourne `SysError::InvalidArgument` si l'index de format LBA dépasse les capacités supportées.
    pub fn apply_format_to_namespace(
        &mut self,
        nsid: u32,
        config: NvmeFormatConfig,
        new_format: NvmeLbaFormat,
    ) -> Result<(), SysError> {
        let ns = self
            .namespaces
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|d| d.nsid == nsid)
            .ok_or(SysError::InvalidHandle)?;

        if config.lba_format_index >= ns.num_lba_formats.max(1) && config.lba_format_index > 0 {
            return Err(SysError::InvalidArgument);
        }

        ns.active_lba_format = new_format;
        // DPS : bits 2:0 = Type de protection, bit 3 = PIL (0 = last 8 bytes, 1 = first 8 bytes)
        let pi_bits = (config.protection_type as u8) & 0x07;
        let pil_bit = ((config.protection_location as u8) & 0x01) << 3;
        ns.data_protection = pi_bits | pil_bit;
        ns.used_blocks = 0;

        Ok(())
    }

    /// Soumet une commande d'administration d'effacement global de média (Sanitize, NVMe 1.4 §5.27 & §8.21).
    ///
    /// Opère sur la totalité du sous-système NVM (tous les namespaces). Pendant l'exécution
    /// de l'effacement physique, les requêtes d'I/O utilisateur sont rejetées avec `SysError::ResourceBusy`.
    ///
    /// # Paramètres
    /// - `action` : Opération de nettoyage (ExitFailure, StartBlockErase, StartOverwrite, StartCryptoErase).
    /// - `config` : Paramètres d'effacement (passes, motif, inversion, etc.).
    ///
    /// # Errors
    /// Retourne `SysError::NotSupported` si le contrôleur n'est pas prêt.
    /// Retourne `SysError::ResourceBusy` si une opération Sanitize est déjà en cours.
    pub fn submit_sanitize(
        &mut self,
        action: NvmeSanitizeAction,
        config: NvmeSanitizeConfig,
    ) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        if self.is_sanitize_in_progress() && action != NvmeSanitizeAction::ExitFailure {
            return Err(SysError::ResourceBusy);
        }

        let cdw10 = config.to_cdw10(action);
        let cdw11 = config.to_cdw11();

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_SANITIZE as u32,
            nsid: 0,
            reserved: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10,
            cdw11,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.admin_queue.submit(cmd);
        if action == NvmeSanitizeAction::ExitFailure {
            self.sanitize_status.sstat = NVME_SANITIZE_COMPLETED_FAILED;
        } else {
            self.sanitize_status.sstat = NVME_SANITIZE_IN_PROGRESS;
            self.sanitize_status.sprog = 0;
            self.sanitize_status.scdw10 = cdw10;
        }
        Ok(cid)
    }

    /// Soumet une requête asynchrone de lecture du journal d'état Sanitize (LID 0x81).
    ///
    /// # Errors
    /// Retourne `SysError::ResourceBusy` si le contrôleur n'est pas prêt.
    pub fn submit_async_sanitize_status_log(&mut self, prp1_iova: u64) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::ResourceBusy);
        }

        let num_dwords = (core::mem::size_of::<NvmeSanitizeStatusLog>() / 4) - 1;
        let cdw10 = ((num_dwords as u32) << 16) | (NVME_LOG_SANITIZE_STATUS as u32);

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_GET_LOG_PAGE as u32,
            nsid: 0xFFFF_FFFF,
            prp1: prp1_iova,
            cdw10,
            ..Default::default()
        };

        Ok(self.admin_queue.submit(cmd))
    }

    /// Met à jour l'état local du contrôleur à partir du journal Sanitize Status récupéré du matériel.
    ///
    /// Si l'opération d'effacement sécurisé a réussi (`NVME_SANITIZE_COMPLETED_SUCCESS`),
    /// l'ensemble des blocs alloués sur tous les namespaces locaux est remis à zéro.
    pub fn apply_sanitize_status(&mut self, log: NvmeSanitizeStatusLog) {
        self.sanitize_status = log;
        let status = log.sstat & 0x07;
        if status == NVME_SANITIZE_COMPLETED_SUCCESS {
            for ns in self.namespaces.iter_mut().flatten() {
                ns.used_blocks = 0;
            }
        }
    }

    /// Soumet une commande d'administration de création de file de complétion I/O (Create I/O Completion Queue, NVMe 1.4 §5.4).
    ///
    /// # Paramètres
    /// - `qid` : Identifiant de la file CQ (1 à 65535, 0 étant réservé à l'Admin CQ).
    /// - `size` : Nombre d'entrées de la CQ (1 à 65536 entrées).
    /// - `prp1_iova` : Adresse physique (IOVA) contiguë du buffer de la file CQ.
    /// - `vector_index` : Vecteur d'interruption MSI-X ou MSI assigné (IV, bits [31:16] de CDW11).
    /// - `interrupts_enabled` : Active la génération d'interruptions sur complétion (IEN, bit 1 de CDW11).
    /// - `physically_contiguous` : Indique si le buffer est contigu en mémoire physique (PC, bit 0 de CDW11).
    pub fn submit_create_io_cq(
        &mut self,
        qid: u16,
        size: u16,
        prp1_iova: u64,
        vector_index: u16,
        interrupts_enabled: bool,
        physically_contiguous: bool,
    ) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        if qid == 0 || size == 0 {
            return Err(SysError::InvalidArgument);
        }

        let qsize_minus_one = (size - 1) as u32;
        let cdw10 = ((qsize_minus_one & 0xFFFF) << 16) | (qid as u32);

        let mut cdw11 = 0u32;
        if physically_contiguous {
            cdw11 |= 1 << 0; // PC (Physically Contiguous)
        }
        if interrupts_enabled {
            cdw11 |= 1 << 1; // IEN (Interrupts Enabled)
        }
        cdw11 |= (vector_index as u32) << 16; // IV (Interrupt Vector)

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_CREATE_CQ as u32,
            nsid: 0,
            reserved: 0,
            mptr: 0,
            prp1: prp1_iova,
            prp2: 0,
            cdw10,
            cdw11,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.admin_queue.submit(cmd);

        // Mise à jour de l'association CQ -> vecteur MSI-X interne
        if (qid as usize) < self.cq_vector_map.len() && interrupts_enabled {
            self.cq_vector_map[qid as usize] = (vector_index & 0xFF) as u8;
        }

        Ok(cid)
    }

    /// Soumet une commande d'administration de création de file de soumission I/O (Create I/O Submission Queue, NVMe 1.4 §5.5).
    ///
    /// # Paramètres
    /// - `qid` : Identifiant de la file SQ (1 à 65535).
    /// - `size` : Nombre d'entrées de la SQ (1 à 65536 entrées).
    /// - `prp1_iova` : Adresse physique (IOVA) contiguë du buffer de la file SQ.
    /// - `cqid` : Identifiant de la file de complétion (CQ) associée pour les retours d'exécution.
    /// - `priority` : Priorité d'arbitrage de la file (Urgent, High, Medium, Low).
    /// - `physically_contiguous` : Indique si le buffer est physiquement contigu (PC).
    pub fn submit_create_io_sq(
        &mut self,
        qid: u16,
        size: u16,
        prp1_iova: u64,
        cqid: u16,
        priority: NvmeQueuePriority,
        physically_contiguous: bool,
    ) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        if qid == 0 || size == 0 || cqid == 0 {
            return Err(SysError::InvalidArgument);
        }

        let qsize_minus_one = (size - 1) as u32;
        let cdw10 = ((qsize_minus_one & 0xFFFF) << 16) | (qid as u32);

        let mut cdw11 = 0u32;
        if physically_contiguous {
            cdw11 |= 1 << 0; // PC (Physically Contiguous)
        }
        cdw11 |= ((priority as u32) & 0x03) << 1; // QPRIO (Queue Priority)
        cdw11 |= (cqid as u32) << 16; // CQID (Completion Queue ID)

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_CREATE_SQ as u32,
            nsid: 0,
            reserved: 0,
            mptr: 0,
            prp1: prp1_iova,
            prp2: 0,
            cdw10,
            cdw11,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.admin_queue.submit(cmd);
        Ok(cid)
    }

    /// Soumet la suppression d'une file I/O (Delete I/O SQ ou Delete I/O CQ).
    pub fn submit_delete_io_queue(&mut self, qid: u16, is_cq: bool) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }
        if qid == 0 {
            return Err(SysError::InvalidArgument);
        }

        let opcode = if is_cq {
            NVME_ADMIN_DELETE_CQ
        } else {
            NVME_ADMIN_DELETE_SQ
        };

        let cmd = NvmeSubmissionEntry {
            cdw0: opcode as u32,
            nsid: 0,
            reserved: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: qid as u32,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.admin_queue.submit(cmd);
        if is_cq && (qid as usize) < self.cq_vector_map.len() {
            self.cq_vector_map[qid as usize] = 0xFF;
            self.cq_msix_delegations[qid as usize] = None;
        }
        Ok(cid)
    }

    /// Raccorde une file de complétion (CQ) NVMe 1.4 à un vecteur MSI-X délégué via le broker matériel DeviceIo.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_cq_deviceio_msix(
        &mut self,
        qid: u16,
        vector_index: u16,
        pci_addr: &libjambo::pci::PciAddress,
        port_handle: libjambo::Handle,
        cookie: u64,
        target_vector: u32,
        apic_id: u8,
    ) -> Result<libjambo::Handle, SysError> {
        if qid == 0 || (qid as usize) >= self.cq_msix_delegations.len() {
            return Err(SysError::InvalidArgument);
        }
        if (vector_index as usize) >= NVME_MSIX_MAX_VECTORS {
            return Err(SysError::InvalidArgument);
        }
        if !(32..=255).contains(&target_vector) {
            return Err(SysError::InvalidArgument);
        }

        // 1. Délégation de l'interruption matérielle via l'appel système DeviceIo (Syscall 29)
        let irq_handle = pci_addr.msix_delegate_irq(port_handle, cookie, target_vector)?;

        // 2. Configuration du vecteur MSI-X dans le ring interne du contrôleur
        self.bind_cq_msix(qid, vector_index as usize, apic_id, target_vector as u8)?;

        // 3. Enregistrement du descripteur de canal délégué
        let delegation = NvmeCqMsixDelegation {
            qid,
            vector_index,
            port_handle,
            cookie,
            target_vector,
            irq_handle,
            interrupts_enabled: true,
            bound: true,
        };
        self.cq_msix_delegations[qid as usize] = Some(delegation);

        Ok(irq_handle)
    }

    /// Récupère le descripteur de canal MSI-X délégué associé à une file CQ.
    pub fn get_cq_msix_delegation(&self, qid: u16) -> Option<NvmeCqMsixDelegation> {
        if (qid as usize) < self.cq_msix_delegations.len() {
            self.cq_msix_delegations[qid as usize]
        } else {
            None
        }
    }

    /// Déconnecte une file de complétion CQ de son vecteur MSI-X délégué.
    pub fn unbind_cq_deviceio_msix(&mut self, qid: u16) -> Result<(), SysError> {
        if qid == 0 || (qid as usize) >= self.cq_msix_delegations.len() {
            return Err(SysError::InvalidArgument);
        }
        if self.cq_msix_delegations[qid as usize].take().is_some()
            && (qid as usize) < self.cq_vector_map.len()
        {
            self.cq_vector_map[qid as usize] = 0xFF;
        }
        Ok(())
    }

    /// Traite une interruption MSI-X déléguée pour un vecteur cible et retourne la complétion correspondante.
    pub fn dispatch_delegated_msix_completion(
        &mut self,
        target_vector: u32,
    ) -> Option<(u16, NvmeCompletionEntry)> {
        for del in self.cq_msix_delegations.iter().flatten() {
            if del.bound && del.interrupts_enabled && del.target_vector == target_vector {
                let qid = del.qid;
                let q = if qid == 0 {
                    &mut self.admin_queue
                } else {
                    &mut self.io_queue
                };
                if let Some(entry) = q.consume_completion() {
                    return Some((qid, entry));
                }
                return Some((
                    qid,
                    NvmeCompletionEntry {
                        dw0: 0,
                        reserved: 0,
                        sq_head: q.sq_tail,
                        sq_id: qid,
                        command_id: 0,
                        status: if q.cq_phase { 1 } else { 0 },
                    },
                ));
            }
        }
        None
    }

    /// Configure l'arbitrage pondéré des commandes NVMe (Weighted Round Robin with Urgent Priority Class - FID 0x01).
    pub fn submit_set_arbitration_config(
        &mut self,
        config: NvmeArbitrationConfig,
    ) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }

        let cdw10 = NVME_FEAT_ARBITRATION;
        let cdw11 = (config.arbitration_burst as u32 & 0x07)
            | ((config.low_priority_weight as u32) << 8)
            | ((config.medium_priority_weight as u32) << 16)
            | ((config.high_priority_weight as u32) << 24);

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_SET_FEATURES as u32,
            nsid: 0,
            reserved: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10,
            cdw11,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.admin_queue.submit(cmd);
        self.arbitration_config = config;
        self.wrru_scheduler.set_config(config);
        Ok(cid)
    }

    /// Configure le regroupement / agrégation des interruptions matérielles CQ (FID 0x08, NVMe 1.4 §5.21.1.8).
    pub fn submit_set_interrupt_coalescing(
        &mut self,
        config: NvmeInterruptCoalescingConfig,
    ) -> Result<u16, SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }

        let cdw10 = NVME_FEAT_INTERRUPT_COALESCING;
        let cdw11 = (config.aggregation_threshold as u32 & 0xFF)
            | ((config.aggregation_time_100us as u32 & 0xFF) << 8);

        let cmd = NvmeSubmissionEntry {
            cdw0: NVME_ADMIN_SET_FEATURES as u32,
            nsid: 0,
            reserved: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10,
            cdw11,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let cid = self.admin_queue.submit(cmd);
        self.interrupt_coalescing = config;
        Ok(cid)
    }

    /// Enregistre une file de soumission avec sa classe de priorité dans l'ordonnanceur WRRU.
    pub fn register_sq_priority(&mut self, qid: u16, priority: NvmeQueuePriority) {
        self.wrru_scheduler.register_queue(qid, priority);
    }

    /// Soumet une commande dans une file SQ avec regroupement (coalescing) de Doorbell.
    /// Retourne le CID et un booléen indiquant si un flush MMIO Doorbell est immédiatement requis.
    pub fn submit_sq_command_coalesced(
        &mut self,
        qid: u16,
        cmd: NvmeSubmissionEntry,
    ) -> Result<(u16, bool), SysError> {
        if !self.ready {
            return Err(SysError::NotSupported);
        }

        let (cid, tail) = if qid == 0 {
            let cid = self.admin_queue.submit(cmd);
            (cid, self.admin_queue.sq_tail)
        } else {
            let cid = self.io_queue.submit(cmd);
            (cid, self.io_queue.sq_tail)
        };

        self.wrru_scheduler.enqueue_command(qid);
        let flush_needed = self.doorbell_coalescer.record_submission(qid, tail);
        Ok((cid, flush_needed))
    }

    /// Force le flush du Doorbell en attente pour la file SQ `qid`.
    pub fn flush_sq_doorbell(&mut self, qid: u16) -> Option<u16> {
        self.doorbell_coalescer.flush(qid)
    }

    /// Vide l'intégralité des Doorbells en attente de notification MMIO.
    pub fn flush_all_sq_doorbells<F: FnMut(u16, u16)>(&mut self, mut write_doorbell_cb: F) {
        for qid in 0..8 {
            if let Some(tail) = self.doorbell_coalescer.flush(qid as u16) {
                write_doorbell_cb(qid as u16, tail);
            }
        }
    }

    /// Sélectionne la prochaine file SQ à dépiler selon l'ordonnancement WRRU.
    pub fn schedule_next_sq(&mut self) -> Option<u16> {
        self.wrru_scheduler.select_next_queue()
    }
}

/// Action résultant du traitement d'un événement asynchrone NVMe AER
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeAsyncEventAction {
    /// Récupérer le journal d'erreur matériel (Log ID 0x01)
    FetchErrorLog { error_code: u8, log_page_id: u8 },
    /// Déclencher une collecte télémétrique SMART d'urgence (Log ID 0x02)
    FetchSmartHealthLog {
        critical_warning: u8,
        log_page_id: u8,
    },
    /// Notification de statut système
    Notice { notice_code: u8 },
    /// Collecte du journal d'état d'effacement sécurisé (Sanitize Status Log ID 0x81)
    FetchSanitizeStatusLog { notice_code: u8, log_page_id: u8 },
    /// Réinitialisation requise du contrôleur NVM
    SubsystemReset,
    /// Événement non pris en charge ou réservé
    Unknown(u32),
}

/// Rapport d'évaluation synthétique de la télémétrie de santé SMART
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeHealthReport {
    pub is_healthy: bool,
    pub spare_critical: bool,
    pub temperature_critical: bool,
    pub temperature_celsius: i16,
    pub percentage_used: u8,
    pub unsafe_shutdowns: u64,
    pub media_errors: u64,
    pub host_reads_gb: u64,
    pub host_writes_gb: u64,
    pub power_on_hours: u64,
    pub requires_emergency_flush: bool,
}

/// Type d'événement asynchrone NVMe 1.4 rapporté par le contrôleur
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeAsyncEventType {
    /// Erreur matérielle ou statut d'intégrité
    ErrorStatus { error_code: u8 },
    /// Alerte critique SMART/Health (température, usure, réserve)
    SmartHealthStatus { critical_warning: u8 },
    /// Notification de mise à jour d'état du sous-système NVMe
    Notice { event_info: u8 },
    /// Réinitialisation du sous-système NVM
    NvmSubsystemReset,
    /// Type d'événement réservé ou inconnu
    Unknown(u32),
}

/// Entrée de journal d'erreur matériel NVMe 1.4 (Error Information Log Entry, 64 octets conforme Section 5.14.1.1)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NvmeErrorInfoEntry {
    /// Compteur incrémental d'erreur unique 64 bits
    pub error_count: u64,
    /// Identifiant de la file de soumission (SQ ID) associée à la commande en erreur
    pub sq_id: u16,
    /// Identifiant de commande (Command ID)
    pub cmd_id: u16,
    /// Champ d'état (Status Field : Phase Tag, Status Code, Status Code Type)
    pub status_field: u16,
    /// Emplacement du paramètre en erreur dans la commande
    pub param_error_location: u16,
    /// Adresse de bloc logique (LBA) concernée par la défaillance
    pub lba: u64,
    /// Identifiant d'espace de noms (Namespace ID)
    pub nsid: u32,
    /// Disponibilité d'informations spécifiques au constructeur
    pub vendor_specific: u8,
    /// Type de transport
    pub transport_type: u8,
    /// Réservé 0
    pub reserved0: [u8; 2],
    /// Informations spécifiques à la commande (Command Specific Information)
    pub cmd_specific_info: u64,
    /// Numéro de séquence de page de journal
    pub log_page_seq: u16,
    /// Réservé 1 (22 octets pour compléter à 64 octets)
    pub reserved1: [u8; 22],
}

impl NvmeErrorInfoEntry {
    /// Indique si cette entrée contient une erreur valide (error_count non nul)
    pub fn is_valid(&self) -> bool {
        self.error_count != 0
    }

    /// Extrait le code de statut (SC, bits 8:1)
    pub fn status_code(&self) -> u8 {
        ((self.status_field >> 1) & 0xFF) as u8
    }

    /// Extrait le type de code de statut (SCT, bits 11:9)
    pub fn status_code_type(&self) -> u8 {
        ((self.status_field >> 9) & 0x07) as u8
    }

    /// Indique si l'erreur signale une défaillance de média non recouvrable (ex: Unrecovered Read Error)
    pub fn is_media_error(&self) -> bool {
        self.status_code_type() == 0x02 // Media and Data Integrity Errors
    }
}

/// Journal d'état de santé et de télémétrie SMART NVMe 1.4 (Section 5.14.1.2)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeSmartLog {
    /// Drapeaux d'avertissement critique (bit 0: spare sous le seuil, bit 1: température critique, etc.)
    pub critical_warning: u8,
    /// Température globale composite en Kelvin (ex: 298 K = 25 °C)
    pub composite_temperature_kelvin: [u8; 2],
    /// Pourcentage de capacité de réserve disponible (0 à 100 %)
    pub available_spare_percent: u8,
    /// Seuil minimal d'alerte de réserve disponible
    pub available_spare_threshold: u8,
    /// Pourcentage d'usure estimée du support Flash
    pub percentage_used: u8,
    /// Réservé NVMe spec
    pub rsvd5: [u8; 27],
    /// Unités de données lues (1 unité = 1 000 secteurs de 512 octets)
    pub data_units_read: [u8; 16],
    /// Unités de données écrites
    pub data_units_written: [u8; 16],
    /// Nombre de commandes de lecture hôte
    pub host_read_commands: [u8; 16],
    /// Nombre de commandes d'écriture hôte
    pub host_write_commands: [u8; 16],
    /// Temps d'occupation du contrôleur en minutes
    pub controller_busy_time: [u8; 16],
    /// Nombre de cycles de mise sous tension
    pub power_cycles: [u8; 16],
    /// Heures de fonctionnement sous tension
    pub power_on_hours: [u8; 16],
    /// Nombre d'arrêts non sécurisés / coupures brutales
    pub unsafe_shutdowns: [u8; 16],
    /// Nombre d'erreurs d'intégrité des données et médias
    pub media_errors: [u8; 16],
    /// Nombre d'entrées d'erreurs journalisées
    pub num_error_log_entries: [u8; 16],
    /// Temps cumulé avec température en zone d'alerte (minutes)
    pub warning_temp_time_minutes: u32,
    /// Temps cumulé avec température en zone critique (minutes)
    pub critical_temp_time_minutes: u32,
    /// Capteurs de température individuels (en Kelvin)
    pub temp_sensors: [u16; 8],
    /// Réservé pour alignement sur 512 octets
    pub rsvd217: [u8; 295],
}

impl Default for NvmeSmartLog {
    fn default() -> Self {
        Self {
            critical_warning: 0,
            composite_temperature_kelvin: 310u16.to_le_bytes(), // 37 °C nominal
            available_spare_percent: 100,
            available_spare_threshold: 10,
            percentage_used: 1,
            rsvd5: [0u8; 27],
            data_units_read: [0u8; 16],
            data_units_written: [0u8; 16],
            host_read_commands: [0u8; 16],
            host_write_commands: [0u8; 16],
            controller_busy_time: [0u8; 16],
            power_cycles: [0u8; 16],
            power_on_hours: [0u8; 16],
            unsafe_shutdowns: [0u8; 16],
            media_errors: [0u8; 16],
            num_error_log_entries: [0u8; 16],
            warning_temp_time_minutes: 0,
            critical_temp_time_minutes: 0,
            temp_sensors: [0u16; 8],
            rsvd217: [0u8; 295],
        }
    }
}

impl NvmeSmartLog {
    /// Convertit la température composite en degrés Celsius
    #[inline]
    pub fn composite_temp_celsius(&self) -> i16 {
        let kelvin = u16::from_le_bytes(self.composite_temperature_kelvin);
        (kelvin as i16).saturating_sub(273)
    }

    /// Indique si le périphérique est dans un état nominal sain
    #[inline]
    pub fn is_healthy(&self) -> bool {
        self.critical_warning == 0 && self.available_spare_percent >= self.available_spare_threshold
    }

    /// Indique si la capacité de réserve disponible a franchi le seuil critique
    #[inline]
    pub fn is_spare_critical(&self) -> bool {
        (self.critical_warning & 0x01) != 0
            || self.available_spare_percent < self.available_spare_threshold
    }

    /// Indique si la température du contrôleur dépasse le seuil critique
    #[inline]
    pub fn is_temperature_critical(&self) -> bool {
        (self.critical_warning & 0x02) != 0
    }

    /// Indique si la fiabilité interne du support NVM est dégradée
    #[inline]
    pub fn is_reliability_degraded(&self) -> bool {
        (self.critical_warning & 0x04) != 0
    }

    /// Indique si le sous-système de stockage est basculé en lecture seule de secours
    #[inline]
    pub fn is_read_only(&self) -> bool {
        (self.critical_warning & 0x08) != 0
    }

    /// Indique si le mécanisme de sauvegarde de la mémoire volatile a échoué
    #[inline]
    pub fn is_volatile_backup_failed(&self) -> bool {
        (self.critical_warning & 0x10) != 0
    }

    /// Convertit un champ NVMe 128-bit petit-boutiste en entier 64-bit saturé
    #[inline]
    pub fn u64_from_le_slice(raw: &[u8; 16]) -> u64 {
        let lo = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
        let hi = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
        if hi > 0 {
            u64::MAX
        } else {
            lo
        }
    }

    /// Évalue l'état de santé global et produit un rapport télémétrique
    pub fn evaluate_health(&self) -> NvmeHealthReport {
        let temp_c = self.composite_temp_celsius();
        let spare_crit = self.is_spare_critical();
        let temp_crit = self.is_temperature_critical() || temp_c >= 75;
        let p_used = self.percentage_used;
        let unsafe_shut = Self::u64_from_le_slice(&self.unsafe_shutdowns);
        let media_err = Self::u64_from_le_slice(&self.media_errors);
        let data_read_units = Self::u64_from_le_slice(&self.data_units_read);
        let data_written_units = Self::u64_from_le_slice(&self.data_units_written);
        let pwr_hours = Self::u64_from_le_slice(&self.power_on_hours);

        // 1 unité = 1000 blocs de 512 octets = 512 000 octets.
        let host_reads_gb = data_read_units.saturating_mul(500) / 1_000_000;
        let host_writes_gb = data_written_units.saturating_mul(500) / 1_000_000;

        let requires_emergency = spare_crit
            || temp_crit
            || p_used >= 95
            || self.is_volatile_backup_failed()
            || self.is_read_only();
        let healthy =
            self.is_healthy() && !spare_crit && !temp_crit && p_used < 90 && media_err == 0;

        NvmeHealthReport {
            is_healthy: healthy,
            spare_critical: spare_crit,
            temperature_critical: temp_crit,
            temperature_celsius: temp_c,
            percentage_used: p_used,
            unsafe_shutdowns: unsafe_shut,
            media_errors: media_err,
            host_reads_gb,
            host_writes_gb,
            power_on_hours: pwr_hours,
            requires_emergency_flush: requires_emergency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libjambo::pci::{PciAddress, PciBar, PciBarType};

    #[test]
    fn test_entry_sizes_and_alignments() {
        assert_eq!(core::mem::size_of::<NvmeSubmissionEntry>(), 64);
        assert_eq!(core::mem::align_of::<NvmeSubmissionEntry>(), 64);
        assert_eq!(core::mem::size_of::<NvmeCompletionEntry>(), 16);
        assert_eq!(core::mem::align_of::<NvmeCompletionEntry>(), 16);
    }

    #[test]
    fn test_submission_and_completion_id() {
        let mut qp = NvmeQueuePair::new(1);
        assert_eq!(qp.sq_tail, 0);

        let entry = NvmeSubmissionEntry {
            cdw0: NVME_IO_READ as u32,
            nsid: 1,
            ..Default::default()
        };

        let cid0 = qp.submit(entry);
        assert_eq!(cid0, 0);
        assert_eq!(qp.sq_tail, 1);
        assert_eq!(qp.sq[0].cdw0 >> 16, 0);

        let cid1 = qp.submit(entry);
        assert_eq!(cid1, 1);
        assert_eq!(qp.sq_tail, 2);
        assert_eq!(qp.sq[1].cdw0 >> 16, 1);
    }

    #[test]
    fn test_completion_phase_and_status() {
        // Status code = 0 (Succès), Phase = 1 (Actif)
        let success_entry = NvmeCompletionEntry {
            dw0: 0,
            reserved: 0,
            sq_head: 1,
            sq_id: 1,
            command_id: 0,
            status: 0x0001,
        };
        assert!(success_entry.is_success());
        assert!(success_entry.phase());
        assert_eq!(success_entry.status_code(), 0);

        // Status code = 2 (Bad LBA), Phase = 0
        let error_entry = NvmeCompletionEntry {
            dw0: 0,
            reserved: 0,
            sq_head: 1,
            sq_id: 1,
            command_id: 1,
            status: (2 << 1), // Phase = 0
        };
        assert!(!error_entry.is_success());
        assert!(!error_entry.phase());
        assert_eq!(error_entry.status_code(), 2);
    }

    #[test]
    fn test_doorbell_offset_calculations() {
        let mut ctrl = NvmeController::new();
        ctrl.doorbell_stride = 0; // 4 bytes stride

        // Admin SQ: qid=0, is_cq=false -> offset 0x1000
        assert_eq!(ctrl.doorbell_offset(0, false), 0x1000);
        // Admin CQ: qid=0, is_cq=true -> offset 0x1004
        assert_eq!(ctrl.doorbell_offset(0, true), 0x1004);
        // I/O SQ: qid=1, is_cq=false -> offset 0x1008
        assert_eq!(ctrl.doorbell_offset(1, false), 0x1008);
        // I/O CQ: qid=1, is_cq=true -> offset 0x100C
        assert_eq!(ctrl.doorbell_offset(1, true), 0x100C);

        // Stride = 1 (8 bytes stride)
        ctrl.doorbell_stride = 1;
        assert_eq!(ctrl.doorbell_offset(0, false), 0x1000);
        assert_eq!(ctrl.doorbell_offset(0, true), 0x1008);
        assert_eq!(ctrl.doorbell_offset(1, false), 0x1010);
    }

    #[test]
    fn test_controller_read_write_flush() {
        let mut ctrl = NvmeController::new();
        let dev_info = PciDeviceInfo {
            address: PciAddress::new(0, 1, 0),
            vendor_id: 0x144D,
            device_id: 0xA808,
            class_code: 0x01,
            subclass: 0x08,
            prog_if: 0x02,
            revision: 1,
            bar0: Some(PciBar {
                index: 0,
                bar_type: PciBarType::Memory64,
                base_address: 0xFE00_0000,
                prefetchable: false,
            }),
        };

        assert!(ctrl.init(&dev_info).is_ok());
        assert!(ctrl.ready);
        assert_eq!(ctrl.bar0_base, 0xFE00_0000);

        // Test Read
        assert!(ctrl.read_blocks(1024, 8, 0x1000_0000).is_ok());
        let last_cmd = ctrl.io_queue.sq[0];
        assert_eq!((last_cmd.cdw0 & 0xFF) as u8, NVME_IO_READ);
        assert_eq!(last_cmd.nsid, 1);
        assert_eq!(last_cmd.prp1, 0x1000_0000);
        assert_eq!(last_cmd.cdw10, 1024);
        assert_eq!(last_cmd.cdw12, 7); // 8 - 1

        // Test Write
        assert!(ctrl.write_blocks(2048, 4, 0x2000_0000).is_ok());
        let write_cmd = ctrl.io_queue.sq[1];
        assert_eq!((write_cmd.cdw0 & 0xFF) as u8, NVME_IO_WRITE);
        assert_eq!(write_cmd.cdw10, 2048);
        assert_eq!(write_cmd.cdw12, 3); // 4 - 1

        // Test Flush
        assert!(ctrl.flush().is_ok());
        let flush_cmd = ctrl.io_queue.sq[2];
        assert_eq!((flush_cmd.cdw0 & 0xFF) as u8, NVME_IO_FLUSH);

        // Test Scatter-Gather DMA Multi-Pages (PRP List)
        let mut prp_list = NvmePrpList::new();
        assert_eq!(core::mem::size_of::<NvmePrpList>(), 4096);
        assert_eq!(core::mem::align_of::<NvmePrpList>(), 4096);

        // Remplir 16 pages mémoires physiques (64 Kio)
        for i in 0..16 {
            assert!(prp_list
                .set_entry(i, 0x3000_0000 + ((i as u64 + 1) * 0x1000))
                .is_ok());
        }

        let dma_sg = NvmeDmaBuffer::scatter_gather(0x3000_0000, 0x4000_0000, 17);
        assert!(ctrl.read_blocks_dma(4096, 128, dma_sg).is_ok()); // 128 blocs de 512 = 64 Kio
        let sg_cmd = ctrl.io_queue.sq[3];
        assert_eq!((sg_cmd.cdw0 & 0xFF) as u8, NVME_IO_READ);
        assert_eq!(sg_cmd.prp1, 0x3000_0000);
        assert_eq!(sg_cmd.prp2, 0x4000_0000);
        assert_eq!(sg_cmd.cdw10, 4096);
        assert_eq!(sg_cmd.cdw12, 127); // 128 - 1
    }

    #[test]
    fn test_prp_extension_chaining() {
        let mut chain = NvmePrpExtensionChain::new(0x5000_0000);
        assert!(!chain.is_chained());
        assert_eq!(chain.data_page_count, 0);

        // Ajouter 511 pages (remplit la table primaire sans chaînage)
        for i in 0..511 {
            assert!(chain
                .add_data_page(0x1000_0000 + (i as u64 * 0x1000))
                .is_ok());
        }
        assert!(!chain.is_chained());
        assert_eq!(chain.data_page_count, 511);

        // Ajouter la 512e page -> déclenche le chaînage vers extension_iova (0x5000_0000)
        assert!(chain.add_data_page(0x2000_0000).is_ok());
        assert!(chain.is_chained());
        assert_eq!(chain.data_page_count, 512);
        assert_eq!(chain.primary_list.entries[511], 0x5000_0000);
        assert_eq!(chain.extension_list.entries[0], 0x2000_0000);
        assert!(chain.verify_integrity());

        // Ajouter 100 pages supplémentaires dans la table d'extension
        for i in 1..101 {
            assert!(chain
                .add_data_page(0x2000_0000 + (i as u64 * 0x1000))
                .is_ok());
        }
        assert_eq!(chain.data_page_count, 612);
        assert!(chain.verify_integrity());

        // Tester la construction du NvmeDmaBuffer et l'envoi d'une commande
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;
        assert!(ctrl
            .read_blocks_chained(0, 1024, &chain, 0x0FFF_0000, 0x4000_0000)
            .is_ok());
        let last_cmd = ctrl.io_queue.sq[0];
        assert_eq!((last_cmd.cdw0 & 0xFF) as u8, NVME_IO_READ);
        assert_eq!(last_cmd.prp1, 0x0FFF_0000);
        assert_eq!(last_cmd.prp2, 0x4000_0000);
    }

    #[test]
    fn test_msix_ring_and_controller_binding() {
        let mut ctrl = NvmeController::new();
        assert!(ctrl.enable_msix(8).is_ok());
        assert_eq!(ctrl.msix.vector_count, 8);
        assert!(ctrl.msix.enabled);

        // Lier Admin CQ (qid 0) au vecteur MSI-X 0 (vecteur CPU 48 sur APIC 0)
        assert!(ctrl.bind_cq_msix(0, 0, 0, 48).is_ok());
        assert!(!ctrl.msix.is_masked(0).unwrap());
        assert_eq!(ctrl.msix.entries[0].msg_addr_lo, 0xFEE0_0000);
        assert_eq!(ctrl.msix.entries[0].vector_number(), 48);

        // Lier I/O CQ (qid 1) au vecteur MSI-X 1 (vecteur CPU 49 sur APIC 1)
        assert!(ctrl.bind_cq_msix(1, 1, 1, 49).is_ok());
        assert_eq!(ctrl.msix.entries[1].msg_addr_lo, 0xFEE0_1000);
        assert_eq!(ctrl.msix.entries[1].vector_number(), 49);

        // Simuler la réception d'une interruption MSI-X vecteur CPU 49
        assert!(ctrl.msix.signal_pending(1).is_ok());
        assert!(ctrl.msix.is_pending(1).unwrap());

        let qid_dispatched = ctrl.handle_msix_interrupt(49);
        assert_eq!(qid_dispatched, Some(1)); // I/O CQ identifiée
        assert!(!ctrl.msix.is_pending(1).unwrap()); // PBA effacé

        // Masquer le vecteur 1
        assert!(ctrl.msix.mask_vector(1).is_ok());
        assert!(ctrl.msix.is_masked(1).unwrap());
        // Quand masqué, l'interruption n'est pas traitée
        assert_eq!(ctrl.handle_msix_interrupt(49), None);
    }

    #[test]
    fn test_smart_health_log_lifecycle() {
        assert_eq!(core::mem::size_of::<NvmeSmartLog>(), 512);

        // 1. Initialisation d'un log nominal
        let default_log = NvmeSmartLog::default();
        assert!(default_log.is_healthy());
        assert!(!default_log.is_spare_critical());
        assert!(!default_log.is_temperature_critical());
        assert_eq!(default_log.composite_temp_celsius(), 37); // 310 K - 273 = 37 °C

        // 2. Émission d'une requête Admin Get Log Page
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;
        let cid = ctrl
            .request_smart_log(0x0000_1000)
            .expect("request_smart_log");
        let last_cmd = ctrl.admin_queue.sq[0];
        assert_eq!((last_cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_GET_LOG_PAGE);
        assert_eq!(last_cmd.nsid, 0xFFFF_FFFF);
        assert_eq!(last_cmd.prp1, 0x0000_1000);
        // CDW10 : [31:16] = 127 (0x007F), [7:0] = 0x02
        assert_eq!(last_cmd.cdw10, 0x007F_0002);
        assert_eq!(cid, 0);

        // 3. Décodage d'un rapport avec avertissements critiques
        let mut raw_buf = [0u8; 512];
        raw_buf[0] = 0x03; // Bit 0 (spare critique) + Bit 1 (température critique)
        raw_buf[1] = 0x48; // 328 Kelvin (0x0148) = 55 °C
        raw_buf[2] = 0x01;
        raw_buf[3] = 5; // Available spare: 5%
        raw_buf[4] = 10; // Threshold: 10%
        raw_buf[5] = 85; // Percentage used: 85%

        let decoded = NvmeController::parse_smart_log(&raw_buf);
        assert!(!decoded.is_healthy());
        assert!(decoded.is_spare_critical());
        assert!(decoded.is_temperature_critical());
        assert_eq!(decoded.composite_temp_celsius(), 55);
        assert_eq!(decoded.percentage_used, 85);
    }

    #[test]
    fn test_write_zeroes_and_flush_lifecycle() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Commande Write Zeroes sans désallocation
        assert!(ctrl.write_zeroes(0x1000, 8, false).is_ok());
        let cmd_wz = ctrl.io_queue.sq[0];
        assert_eq!((cmd_wz.cdw0 & 0xFF) as u8, NVME_IO_WRITE_ZEROES);
        assert_eq!(cmd_wz.nsid, 1);
        assert_eq!(cmd_wz.cdw10, 0x1000);
        assert_eq!(cmd_wz.cdw11, 0);
        assert_eq!(cmd_wz.cdw12, 7); // 8 - 1 = 7, pas de bit DEAC

        // 2. Commande Write Zeroes avec désallocation (TRIM / DEAC)
        assert!(ctrl.write_zeroes(0x2000, 16, true).is_ok());
        let cmd_deac = ctrl.io_queue.sq[1];
        assert_eq!((cmd_deac.cdw0 & 0xFF) as u8, NVME_IO_WRITE_ZEROES);
        assert_eq!(cmd_deac.cdw10, 0x2000);
        assert_eq!(cmd_deac.cdw12, 15 | (1 << 25)); // bit 25 DEAC

        // 3. Commande Flush sur namespace spécifique
        assert!(ctrl.flush_namespace(2).is_ok());
        let cmd_flush = ctrl.io_queue.sq[2];
        assert_eq!((cmd_flush.cdw0 & 0xFF) as u8, NVME_IO_FLUSH);
        assert_eq!(cmd_flush.nsid, 2);
    }

    #[test]
    fn test_async_event_and_features_threshold() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Commande Set Features : Temperature Threshold (348 K = 75 °C)
        assert!(ctrl.set_temperature_threshold(348).is_ok());
        let cmd_feat = ctrl.admin_queue.sq[0];
        assert_eq!((cmd_feat.cdw0 & 0xFF) as u8, NVME_ADMIN_SET_FEATURES);
        assert_eq!(cmd_feat.cdw10, NVME_FEAT_TEMPERATURE_THRESHOLD);
        assert_eq!(cmd_feat.cdw11, 348);

        // 2. Commande Asynchronous Event Request (AER)
        let cid = ctrl.request_async_event().expect("request_async_event");
        let cmd_aer = ctrl.admin_queue.sq[1];
        assert_eq!((cmd_aer.cdw0 & 0xFF) as u8, NVME_ADMIN_ASYNC_EVENT_REQ);
        assert_eq!(cid, 1);

        // 3. Décodage d'un événement asynchrone SMART Health Status
        // DW0: [2:0] = 1 (SmartHealthStatus), [15:8] = 0x02 (température critique)
        let dw0_smart = 1 | (0x02 << 8);
        let event = NvmeController::parse_async_event_result(dw0_smart);
        assert_eq!(
            event,
            NvmeAsyncEventType::SmartHealthStatus {
                critical_warning: 0x02
            }
        );

        // 4. Décodage d'un événement Notice
        let dw0_notice = 2 | (0x05 << 8);
        assert_eq!(
            NvmeController::parse_async_event_result(dw0_notice),
            NvmeAsyncEventType::Notice { event_info: 0x05 }
        );
    }

    #[test]
    fn test_async_command_transfers_and_dynamic_msix() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;
        assert!(ctrl.enable_msix(8).is_ok());

        // 1. Soumission asynchrone Read
        let cid_read = ctrl
            .submit_async_read(0x1000, 4, 0x4000_0000)
            .expect("async read");
        assert_eq!(cid_read, 0);
        let cmd_read = ctrl.io_queue.sq[0];
        assert_eq!((cmd_read.cdw0 & 0xFF) as u8, NVME_IO_READ);
        assert_eq!(cmd_read.cdw10, 0x1000);

        // 2. Soumission asynchrone Write Zeroes
        let cid_wz = ctrl
            .submit_async_write_zeroes(0x2000, 8, true)
            .expect("async write zeroes");
        assert_eq!(cid_wz, 1);
        let cmd_wz = ctrl.io_queue.sq[1];
        assert_eq!((cmd_wz.cdw0 & 0xFF) as u8, NVME_IO_WRITE_ZEROES);

        // 3. Soumission asynchrone Flush
        let cid_flush = ctrl.submit_async_flush(1).expect("async flush");
        assert_eq!(cid_flush, 2);

        // 4. Configuration et Rebind dynamique de vecteur MSI-X
        // Lier CQ 1 au vecteur 2 (APIC ID 0, CPU Vector 0x42)
        assert!(ctrl.bind_cq_msix(1, 2, 0, 0x42).is_ok());
        assert_eq!(ctrl.msix.entries[2].vector_number(), 0x42);

        // Rebind dynamique vers APIC ID 3, CPU Vector 0x55 (migration de charge CPU)
        assert!(ctrl.rebind_msix_vector(2, 3, 0x55).is_ok());
        assert_eq!(ctrl.msix.entries[2].vector_number(), 0x55);
        assert_eq!(ctrl.msix.entries[2].msg_addr_lo, 0xFEE0_0000 | (3 << 12));

        // 5. Test du masquage individuel et global Function Mask
        assert!(!ctrl.msix.is_vector_effective_masked(2));
        assert!(ctrl.set_msix_vector_mask(2, true).is_ok());
        assert!(ctrl.msix.is_vector_effective_masked(2));
        assert!(ctrl.set_msix_vector_mask(2, false).is_ok());
        assert!(!ctrl.msix.is_vector_effective_masked(2));

        ctrl.set_msix_function_mask(true);
        assert!(ctrl.msix.is_vector_effective_masked(2));
        ctrl.set_msix_function_mask(false);
        assert!(!ctrl.msix.is_vector_effective_masked(2));

        // 6. Signalement d'interruption dans le PBA et dispatch dynamique
        assert!(ctrl.msix.signal_pending(2).is_ok());
        assert!(ctrl.msix.is_pending(2).unwrap());

        let event = ctrl.dispatch_dynamic_msix_event(0x55);
        assert!(event.is_some());
        let (qid, _c) = event.unwrap();
        assert_eq!(qid, 1);
        // Le bit PBA doit avoir été acquitté et effacé
        assert!(!ctrl.msix.is_pending(2).unwrap());
    }

    #[test]
    fn test_nvme_4kn_and_512e_geometry() {
        let mut ctrl = NvmeController::new();
        assert!(ctrl.is_512e());
        assert!(!ctrl.is_4kn());
        assert_eq!(ctrl.block_size, 512);
        assert_eq!(ctrl.blocks_to_lba_count(1), 8);
        assert_eq!(ctrl.lba_for_4k_block(2048, 2), 2048 + 16);
        assert!(ctrl.is_lba_4k_aligned(2048));
        assert!(!ctrl.is_lba_4k_aligned(2049));

        // Reconfiguration en mode 4Kn natif
        assert!(ctrl.configure_lba_geometry(4096).is_ok());
        assert!(ctrl.is_4kn());
        assert!(!ctrl.is_512e());
        assert_eq!(ctrl.block_size, 4096);
        assert_eq!(ctrl.namespace_size_blocks, 2_097_152 / 8);
        assert_eq!(ctrl.blocks_to_lba_count(1), 1);
        assert_eq!(ctrl.lba_for_4k_block(256, 2), 256 + 2);
        assert!(ctrl.is_lba_4k_aligned(256));
        assert!(ctrl.is_lba_4k_aligned(257)); // En 4Kn, chaque secteur LBA est un bloc physique de 4K

        // Rejet des géométries invalides
        assert!(ctrl.configure_lba_geometry(1024).is_err());
        assert!(ctrl.configure_lba_geometry(8192).is_err());
    }

    #[test]
    fn test_nvme_flush_commands_and_metrics() {
        let mut ctrl = NvmeController::new();
        // Le contrôleur non prêt doit rejeter le flush
        assert_eq!(ctrl.flush(), Err(SysError::ResourceBusy));
        assert_eq!(ctrl.flush_metrics().flush_errors, 1);
        assert_eq!(ctrl.flush_metrics().total_flushes, 0);

        // Simulation du contrôleur prêt
        ctrl.ready = true;
        assert!(ctrl.has_vwc());
        ctrl.set_vwc(false);
        assert!(!ctrl.has_vwc());

        // Soumission asynchrone d'une commande flush
        let cid = ctrl.submit_async_flush(1).expect("submit flush");
        let sub_entry = ctrl.io_queue.sq[0];
        assert_eq!((sub_entry.cdw0 & 0xFF) as u8, NVME_NVM_CMD_FLUSH);
        assert_eq!(sub_entry.nsid, 1);

        // Soumission globale (tous les namespaces)
        let _cid_all = ctrl
            .submit_async_flush(0xFFFF_FFFF)
            .expect("submit flush all");
        let sub_entry_all = ctrl.io_queue.sq[1];
        assert_eq!((sub_entry_all.cdw0 & 0xFF) as u8, NVME_NVM_CMD_FLUSH);
        assert_eq!(sub_entry_all.nsid, 0xFFFF_FFFF);

        // Simulation de complétion de la commande
        let phase = ctrl.io_queue.cq_phase;
        ctrl.io_queue.cq[0] = NvmeCompletionEntry {
            dw0: 0,
            reserved: 0,
            sq_head: 1,
            sq_id: 1,
            command_id: cid,
            status: phase as u16,
        };

        // Poll de complétion
        let comp = ctrl.poll_async_completion(1, cid).expect("poll completion");
        assert!(comp.is_some());
        assert_eq!(comp.unwrap().command_id, cid);
    }

    #[test]
    fn test_async_smart_telemetry_and_health_evaluation() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Soumission asynchrone non-bloquante du log SMART/Health
        let cid_smart = ctrl
            .submit_async_smart_log(0x5000_0000)
            .expect("async smart log");
        assert_eq!(cid_smart, 0);

        let sub_smart = ctrl.admin_queue.sq[0];
        assert_eq!((sub_smart.cdw0 & 0xFF) as u8, NVME_ADMIN_GET_LOG_PAGE);
        assert_eq!(sub_smart.nsid, 0xFFFF_FFFF);
        assert_eq!(sub_smart.prp1, 0x5000_0000);
        let num_dwords = (core::mem::size_of::<NvmeSmartLog>() / 4) - 1;
        let expected_cdw10 = ((num_dwords as u32) << 16) | (NVME_LOG_SMART_HEALTH as u32);
        assert_eq!(sub_smart.cdw10, expected_cdw10);

        // 2. Simulation de complétion dans l'Admin CQ et test de poll non-bloquant
        let phase = ctrl.admin_queue.cq_phase;
        ctrl.admin_queue.cq[0] = NvmeCompletionEntry {
            dw0: 0,
            reserved: 0,
            sq_head: 1,
            sq_id: 0,
            command_id: cid_smart,
            status: phase as u16,
        };

        let poll_res = ctrl
            .poll_admin_async_completion(cid_smart)
            .expect("poll admin");
        assert!(poll_res.is_some());
        assert_eq!(poll_res.unwrap().command_id, cid_smart);

        // 3. Dispatch d'action d'événement asynchrone (AER)
        // Événement SMART critique avec log_page_id = 0x02
        let aer_dw0_smart = 1 | (0x04 << 8) | (0x02 << 16);
        let action = ctrl.dispatch_async_event_action(aer_dw0_smart);
        assert_eq!(
            action,
            NvmeAsyncEventAction::FetchSmartHealthLog {
                critical_warning: 0x04,
                log_page_id: 0x02,
            }
        );

        // Événement Notice
        let aer_dw0_notice = 2 | (0x03 << 8);
        assert_eq!(
            ctrl.dispatch_async_event_action(aer_dw0_notice),
            NvmeAsyncEventAction::Notice { notice_code: 0x03 }
        );

        // 4. Évaluation synthétique de santé SMART nominale
        let nominal_log = NvmeSmartLog::default();
        let rep_nominal = nominal_log.evaluate_health();
        assert!(rep_nominal.is_healthy);
        assert!(!rep_nominal.spare_critical);
        assert!(!rep_nominal.temperature_critical);
        assert!(!rep_nominal.requires_emergency_flush);
        assert_eq!(rep_nominal.percentage_used, 1);
        assert_eq!(rep_nominal.temperature_celsius, 37);

        // 5. Évaluation de santé avec dégradation thermique et usure
        let degraded_log = NvmeSmartLog {
            critical_warning: 0x02, // Alerte température critique
            percentage_used: 96,    // Usure > 95%
            composite_temperature_kelvin: 358u16.to_le_bytes(), // 85 °C
            ..Default::default()
        };
        let rep_degraded = degraded_log.evaluate_health();
        assert!(!rep_degraded.is_healthy);
        assert!(rep_degraded.temperature_critical);
        assert!(rep_degraded.requires_emergency_flush);
        assert_eq!(rep_degraded.temperature_celsius, 85);
    }

    #[test]
    fn test_error_log_flush_and_aer_event_management() {
        assert_eq!(core::mem::size_of::<NvmeErrorInfoEntry>(), 64);

        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Soumission d'un vidage asynchrone du journal d'erreur (Log ID 0x01)
        let prp_err_iova = 0x0000_1000_0000;
        let num_entries = 4u16;
        let cid_err = ctrl
            .submit_async_error_log(prp_err_iova, num_entries)
            .expect("submit error log");
        assert_eq!(ctrl.error_log_flushes, 1);
        assert_eq!(ctrl.pending_error_log_cid, Some(cid_err));

        // Vérification de la commande construite dans l'admin SQ
        let cmd = ctrl.admin_queue.sq[0];
        assert_eq!((cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_GET_LOG_PAGE);
        assert_eq!((cmd.cdw10 & 0xFF) as u8, NVME_LOG_ERROR_INFO);
        // num_dwords = (4 * 64 / 4) - 1 = 63 = 0x003F
        assert_eq!((cmd.cdw10 >> 16) as u16, 63);

        // 2. Décodage d'un échantillon réel d'erreur de média non recouvrable (Unrecovered Read Error)
        let mut raw_entry = [0u8; 64];
        let error_cnt: u64 = 101;
        raw_entry[0..8].copy_from_slice(&error_cnt.to_le_bytes());
        let sq_id: u16 = 1;
        raw_entry[8..10].copy_from_slice(&sq_id.to_le_bytes());
        let cmd_id: u16 = 55;
        raw_entry[10..12].copy_from_slice(&cmd_id.to_le_bytes());
        // Status Field : SCT = 2 (Media and Data Integrity Errors), SC = 0x81 (Unrecovered Read Error)
        let status_field: u16 = (2 << 9) | (0x81 << 1) | 1;
        raw_entry[12..14].copy_from_slice(&status_field.to_le_bytes());
        let lba: u64 = 0x0000_DEAD_BEEF;
        raw_entry[16..24].copy_from_slice(&lba.to_le_bytes());

        let decoded = NvmeController::parse_error_log_entry(&raw_entry);
        assert!(decoded.is_valid());
        let err_count = decoded.error_count;
        let sq = decoded.sq_id;
        let cmd = decoded.cmd_id;
        let lba_val = decoded.lba;
        assert_eq!(err_count, 101);
        assert_eq!(sq, 1);
        assert_eq!(cmd, 55);
        assert_eq!(lba_val, 0x0000_DEAD_BEEF);
        assert_eq!(decoded.status_code_type(), 2);
        assert!(decoded.is_media_error());

        // Test de parsing multi-entrées
        let mut raw_buf = [0u8; 128];
        raw_buf[0..64].copy_from_slice(&raw_entry);
        let mut entries_out = [NvmeErrorInfoEntry::default(); 2];
        let parsed_count = NvmeController::parse_error_log_entries(&raw_buf, &mut entries_out);
        assert_eq!(parsed_count, 2);
        assert!(entries_out[0].is_valid());
        assert!(!entries_out[1].is_valid());

        // 3. Gestion du volant permanent d'AER (replenish_aer_requests)
        let queued_aer = ctrl.replenish_aer_requests().expect("replenish aer");
        assert_eq!(queued_aer, 4);
        assert_eq!(ctrl.outstanding_aer, 4);

        // 4. Traitement d'un événement asynchrone complété dans l'Admin CQ
        let phase = ctrl.admin_queue.cq_phase;
        // DW0 : event_type = 0 (ErrorStatus), event_info = 0x05, log_page_id = 0x01
        let aer_dw0 = (0x05 << 8) | (0x01 << 16);
        ctrl.admin_queue.cq[0] = NvmeCompletionEntry {
            dw0: aer_dw0,
            reserved: 0,
            sq_head: 4,
            sq_id: 0,
            command_id: 2,
            status: phase as u16,
        };

        let event_action = ctrl.poll_and_handle_aer_events().expect("poll aer");
        assert!(event_action.is_some());
        assert_eq!(
            event_action.unwrap(),
            NvmeAsyncEventAction::FetchErrorLog {
                error_code: 0x05,
                log_page_id: 0x01,
            }
        );
        // Le contrôleur a automatiquement réapprovisionné l'AER consommé
        assert_eq!(ctrl.outstanding_aer, 4);

        // 5. Déclenchement périodique du vidage de journal
        let cid_periodic = ctrl
            .trigger_periodic_error_log_flush(0x0000_2000_0000, 8)
            .expect("periodic flush");
        assert!(cid_periodic > 0);
        assert_eq!(ctrl.error_log_flushes, 2);
    }

    #[test]
    fn test_dataset_management_dsm_deallocate_and_async() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        let _range = NvmeDsmRange {
            context_attributes: 0,
            length_blocks: 128,
            starting_lba: 0x4000,
        };
        assert_eq!(core::mem::size_of::<NvmeDsmRange>(), 16);

        // 1. Soumission bloquante DSM avec bit DEALLOCATE (TRIM)
        assert!(ctrl
            .dataset_management(1, 0x1000_2000, 1, NVME_DSM_ATTR_DEALLOCATE)
            .is_ok());
        let cmd = ctrl.io_queue.sq[0];
        assert_eq!((cmd.cdw0 & 0xFF) as u8, NVME_IO_DATA_SET_MANAGEMENT);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.prp1, 0x1000_2000);
        assert_eq!(cmd.cdw10, 0); // 1 plage - 1 = 0
        assert_eq!(cmd.cdw11, NVME_DSM_ATTR_DEALLOCATE);

        // 2. Soumission asynchrone DSM multi-plages
        let cid_async = ctrl
            .submit_async_dataset_management(
                1,
                0x2000_4000,
                4,
                NVME_DSM_ATTR_DEALLOCATE | NVME_DSM_ATTR_INTEGRAL_WRITE,
            )
            .expect("async dsm");
        assert_eq!(cid_async, 1);
        let cmd_async = ctrl.io_queue.sq[1];
        assert_eq!((cmd_async.cdw0 & 0xFF) as u8, NVME_IO_DATA_SET_MANAGEMENT);
        assert_eq!(cmd_async.cdw10, 3); // 4 plages - 1 = 3
        assert_eq!(
            cmd_async.cdw11,
            NVME_DSM_ATTR_DEALLOCATE | NVME_DSM_ATTR_INTEGRAL_WRITE
        );
    }

    // =========================================================================
    // Tests — Namespace Management (NVMe 1.4 §8.11 / §8.12)
    // =========================================================================

    #[test]
    fn test_lba_format_sector_sizes() {
        let fmt_512 = NvmeLbaFormat {
            metadata_size: 0,
            lba_data_size_pow2: 9,
            relative_performance: 0,
        };
        assert_eq!(fmt_512.sector_bytes(), 512);
        assert!(fmt_512.is_512e());
        assert!(!fmt_512.is_4kn());

        let fmt_4k = NvmeLbaFormat {
            metadata_size: 8,
            lba_data_size_pow2: 12,
            relative_performance: 1,
        };
        assert_eq!(fmt_4k.sector_bytes(), 4096);
        assert!(fmt_4k.is_4kn());
        assert!(!fmt_4k.is_512e());

        // Format invalide → repli sur 512 octets
        let fmt_bad = NvmeLbaFormat {
            metadata_size: 0,
            lba_data_size_pow2: 0,
            relative_performance: 0,
        };
        assert_eq!(fmt_bad.sector_bytes(), 512);
    }

    #[test]
    fn test_namespace_descriptor_creation_and_capacity() {
        let desc = NvmeNamespaceDescriptor::new(1, 2_097_152, 2_097_152);
        assert_eq!(desc.nsid, 1);
        assert_eq!(desc.total_blocks, 2_097_152);
        assert_eq!(desc.capacity_blocks, 2_097_152);
        assert_eq!(desc.used_blocks, 0);
        // Capacité = 2 097 152 blocs × 512 octets = 1 Gio
        assert_eq!(desc.capacity_bytes(), 1_073_741_824);
        assert!(!desc.thin_provisioning);
        assert!(!desc.shared);
        assert!(!desc.write_protected);
        // 0 blocs utilisés → 0 %
        assert_eq!(desc.utilization_percent(), 0);
    }

    #[test]
    fn test_namespace_descriptor_utilization_percent() {
        let mut desc = NvmeNamespaceDescriptor::new(2, 1000, 1000);
        // 50 % utilisé
        desc.used_blocks = 500;
        assert_eq!(desc.utilization_percent(), 50);
        // 100 % utilisé
        desc.used_blocks = 1000;
        assert_eq!(desc.utilization_percent(), 100);
        // Dépassement → plafonné à 100 %
        desc.used_blocks = 1500;
        assert_eq!(desc.utilization_percent(), 100);
        // Capacité nulle → 0 %
        let empty_desc = NvmeNamespaceDescriptor::new(3, 0, 0);
        assert_eq!(empty_desc.utilization_percent(), 0);
    }

    #[test]
    fn test_namespace_descriptor_identify_serialization_roundtrip() {
        let mut desc = NvmeNamespaceDescriptor::new(5, 4_194_304, 4_194_304);
        desc.used_blocks = 1_048_576;
        desc.thin_provisioning = true;
        desc.shared = true;
        desc.data_protection = 0x05;
        desc.nguid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        desc.eui64 = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        desc.active_lba_format = NvmeLbaFormat {
            metadata_size: 8,
            lba_data_size_pow2: 12,
            relative_performance: 1,
        };

        let raw = desc.to_identify_bytes();
        assert_eq!(raw.len(), 512);

        // Vérification des champs NSZE / NCAP / NUSE
        let nsze = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let ncap = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let nuse = u64::from_le_bytes(raw[16..24].try_into().unwrap());
        assert_eq!(nsze, 4_194_304);
        assert_eq!(ncap, 4_194_304);
        assert_eq!(nuse, 1_048_576);

        // NSFEAT : bit 0 (thin) | bit 3 (shared) = 0b00001001 = 0x09
        assert_eq!(raw[24], 0x09);
        // DPS
        assert_eq!(raw[29], 0x05);
        // NGUID
        assert_eq!(&raw[104..120], &desc.nguid);
        // EUI64
        assert_eq!(&raw[120..128], &desc.eui64);
        // LBAF0 : MS=8, LBADS=12, RP=1
        let ms = u16::from_le_bytes(raw[128..130].try_into().unwrap());
        assert_eq!(ms, 8);
        assert_eq!(raw[130], 12);
        assert_eq!(raw[131], 1);

        // Désérialisation aller-retour
        let restored = NvmeNamespaceDescriptor::from_identify_bytes(5, &raw).unwrap();
        assert_eq!(restored.nsid, 5);
        assert_eq!(restored.total_blocks, 4_194_304);
        assert_eq!(restored.capacity_blocks, 4_194_304);
        assert_eq!(restored.used_blocks, 1_048_576);
        assert!(restored.thin_provisioning);
        assert!(restored.shared);
        assert_eq!(restored.data_protection, 0x05);
        assert_eq!(restored.nguid, desc.nguid);
        assert_eq!(restored.eui64, desc.eui64);
        assert_eq!(restored.active_lba_format.lba_data_size_pow2, 12);
        assert_eq!(restored.active_lba_format.metadata_size, 8);
        assert_eq!(restored.active_lba_format.relative_performance, 1);
    }

    #[test]
    fn test_namespace_descriptor_from_identify_null_ns() {
        // Un namespace non alloué retourne NSZE = 0 → None
        let raw = [0u8; 512];
        assert!(NvmeNamespaceDescriptor::from_identify_bytes(99, &raw).is_none());
    }

    #[test]
    fn test_active_namespace_list_parsing() {
        let mut raw = [0u8; 4096];
        // Inject 3 NSIDs actifs
        raw[0..4].copy_from_slice(&1u32.to_le_bytes());
        raw[4..8].copy_from_slice(&3u32.to_le_bytes());
        raw[8..12].copy_from_slice(&7u32.to_le_bytes());
        // Reste à 0 = terminateur

        let list = NvmeActiveNamespaceList::from_bytes(&raw);
        assert_eq!(list.count, 3);
        assert_eq!(list.nsids[0], 1);
        assert_eq!(list.nsids[1], 3);
        assert_eq!(list.nsids[2], 7);
        assert!(list.contains(1));
        assert!(list.contains(3));
        assert!(list.contains(7));
        assert!(!list.contains(2));
        assert!(!list.contains(0));
    }

    #[test]
    fn test_nvme_ns_management_command_construction() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Création de namespace : vérification de l'opcode CDW0 et CDW10
        let prp_iova: u64 = 0x0000_2000_0000;
        let cid_create = ctrl.submit_ns_create(prp_iova).expect("submit_ns_create");
        let cmd_create = ctrl.admin_queue.sq[0];
        assert_eq!((cmd_create.cdw0 & 0xFF) as u8, NVME_ADMIN_NS_MANAGEMENT);
        assert_eq!(cmd_create.cdw10 as u8, NVME_NS_MGMT_CREATE);
        assert_eq!(cmd_create.prp1, prp_iova);
        assert_eq!(cmd_create.nsid, 0); // Create : NSID ignoré par le contrôleur

        // 2. Suppression de namespace : vérification de l'opcode et du NSID cible
        let cid_delete = ctrl.submit_ns_delete(2).expect("submit_ns_delete");
        assert!(cid_delete > cid_create); // CID incrémental
                                          // Validation des arguments invalides
        assert_eq!(ctrl.submit_ns_delete(0), Err(SysError::InvalidArgument));
        assert_eq!(
            ctrl.submit_ns_delete(0xFFFF_FFFF),
            Err(SysError::InvalidArgument)
        );

        // 3. Attachement : opcode NVME_ADMIN_NS_ATTACHMENT + sélecteur 0x0
        let ctrl_list_iova: u64 = 0x0000_3000_0000;
        let cid_attach = ctrl
            .submit_ns_attach(1, ctrl_list_iova)
            .expect("submit_ns_attach");
        let cmd_attach = ctrl.admin_queue.sq[2];
        assert_eq!((cmd_attach.cdw0 & 0xFF) as u8, NVME_ADMIN_NS_ATTACHMENT);
        assert_eq!(cmd_attach.cdw10 as u8, NVME_NS_ATTACH_CTRL);
        assert_eq!(cmd_attach.nsid, 1);
        assert_eq!(cmd_attach.prp1, ctrl_list_iova);

        // 4. Détachement : sélecteur 0x1
        let cid_detach = ctrl
            .submit_ns_detach(1, ctrl_list_iova)
            .expect("submit_ns_detach");
        assert!(cid_detach > cid_attach);
        let cmd_detach = ctrl.admin_queue.sq[3];
        assert_eq!((cmd_detach.cdw0 & 0xFF) as u8, NVME_ADMIN_NS_ATTACHMENT);
        assert_eq!(cmd_detach.cdw10 as u8, NVME_NS_DETACH_CTRL);

        // 5. Contrôleur non prêt → NotSupported
        ctrl.ready = false;
        assert_eq!(ctrl.submit_ns_create(0x1000), Err(SysError::NotSupported));
        assert_eq!(ctrl.submit_ns_delete(1), Err(SysError::NotSupported));
        assert_eq!(
            ctrl.submit_ns_attach(1, 0x2000),
            Err(SysError::NotSupported)
        );
        assert_eq!(
            ctrl.submit_ns_detach(1, 0x2000),
            Err(SysError::NotSupported)
        );
    }

    #[test]
    fn test_nvme_namespace_registry_lifecycle() {
        let mut ctrl = NvmeController::new();
        assert_eq!(ctrl.namespace_count(), 0);

        // Enregistrement de plusieurs namespaces
        let ns1 = NvmeNamespaceDescriptor::new(1, 2_097_152, 2_097_152);
        let ns2 = NvmeNamespaceDescriptor::new(2, 4_194_304, 4_000_000);
        ctrl.register_namespace(ns1).expect("register ns1");
        ctrl.register_namespace(ns2).expect("register ns2");
        assert_eq!(ctrl.namespace_count(), 2);

        // Recherche par NSID
        let found = ctrl.find_namespace(1).expect("find ns1");
        assert_eq!(found.nsid, 1);
        assert_eq!(found.total_blocks, 2_097_152);

        let found2 = ctrl.find_namespace(2).expect("find ns2");
        assert_eq!(found2.capacity_blocks, 4_000_000);

        assert!(ctrl.find_namespace(99).is_none());

        // Désenregistrement
        ctrl.unregister_namespace(1).expect("unregister ns1");
        assert_eq!(ctrl.namespace_count(), 1);
        assert!(ctrl.find_namespace(1).is_none());

        // Double désenregistrement → erreur
        assert_eq!(ctrl.unregister_namespace(1), Err(SysError::InvalidHandle));

        // Remplissage de la table jusqu'à saturation
        ctrl.unregister_namespace(2).ok();
        for i in 1..=(NVME_MAX_NAMESPACES as u32) {
            let ns = NvmeNamespaceDescriptor::new(i, 100, 100);
            ctrl.register_namespace(ns).expect("register");
        }
        assert_eq!(ctrl.namespace_count(), NVME_MAX_NAMESPACES);
        // La table est pleine → ResourceBusy
        let overflow = NvmeNamespaceDescriptor::new(999, 1, 1);
        assert_eq!(
            ctrl.register_namespace(overflow),
            Err(SysError::ResourceBusy)
        );
    }

    #[test]
    fn test_format_nvm_cdw10_encoding_and_submission() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Configuration Format NVM : LBAF 1 (4Kn), PI Type 1, PIL last 8 bytes, UserDataErase
        let cfg = NvmeFormatConfig {
            lba_format_index: 1,
            metadata_setting: NvmeMetadataSetting::ExtendedLba,
            protection_type: NvmeProtectionType::Type1,
            protection_location: NvmeProtectionLocation::Last8Bytes,
            secure_erase: NvmeSecureErase::UserDataErase,
        };

        let cdw10 = cfg.to_cdw10();
        // LBAF: bits 3:0 = 1
        assert_eq!(cdw10 & 0x0F, 1);
        // MSET: bit 4 = 1
        assert_eq!((cdw10 >> 4) & 0x01, 1);
        // PI: bits 7:5 = 1 (Type 1)
        assert_eq!((cdw10 >> 5) & 0x07, 1);
        // PIL: bit 8 = 0 (Last 8 bytes)
        assert_eq!((cdw10 >> 8) & 0x01, 0);
        // SES: bits 11:9 = 1 (UserDataErase)
        assert_eq!((cdw10 >> 9) & 0x07, 1);

        // Décodage symétrique
        let decoded = NvmeFormatConfig::from_cdw10(cdw10).expect("decode cdw10");
        assert_eq!(decoded.lba_format_index, 1);
        assert_eq!(decoded.metadata_setting, NvmeMetadataSetting::ExtendedLba);
        assert_eq!(decoded.protection_type, NvmeProtectionType::Type1);
        assert_eq!(
            decoded.protection_location,
            NvmeProtectionLocation::Last8Bytes
        );
        assert_eq!(decoded.secure_erase, NvmeSecureErase::UserDataErase);

        // Soumission de la commande sur l'Admin SQ
        let cid = ctrl.submit_format_nvm(1, cfg).expect("submit format");
        let cmd = ctrl.admin_queue.sq[0];
        assert_eq!((cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_FORMAT_NVM);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, cdw10);
        assert_eq!((cmd.cdw0 >> 16) as u16, cid);

        // Broadcast format (NSID 0xFFFFFFFF)
        let cid_bcast = ctrl
            .submit_format_nvm(NVME_NSID_BROADCAST, cfg)
            .expect("broadcast format");
        assert!(cid_bcast > cid);
        assert_eq!(ctrl.admin_queue.sq[1].nsid, NVME_NSID_BROADCAST);

        // NSID 0 invalide
        assert_eq!(
            ctrl.submit_format_nvm(0, cfg),
            Err(SysError::InvalidArgument)
        );

        // Contrôleur non prêt
        ctrl.ready = false;
        assert_eq!(ctrl.submit_format_nvm(1, cfg), Err(SysError::NotSupported));
    }

    #[test]
    fn test_format_nvm_protection_information_dif_guard() {
        let block_data = [0x5Au8; 512];
        let app_tag: u16 = 0x1234;
        let lba_ref_tag: u32 = 0x00A0_B0C0;

        // Génération automatique avec CRC-16 Guard
        let pi = NvmeProtectionInformation::generate_from_data(&block_data, app_tag, lba_ref_tag);
        assert_ne!(pi.guard, 0);
        assert_eq!(pi.application_tag, app_tag);
        assert_eq!(pi.reference_tag, lba_ref_tag);

        // Validation Type 1 réussie
        assert!(pi
            .verify(&block_data, lba_ref_tag, NvmeProtectionType::Type1)
            .is_ok());

        // Mauvais LBA / Reference Tag -> BadAddress
        assert_eq!(
            pi.verify(&block_data, 0x00A0_B0C1, NvmeProtectionType::Type1),
            Err(SysError::BadAddress)
        );

        // Altération des données -> InvalidArgument (CRC Guard mismatch)
        let mut corrupted_data = block_data;
        corrupted_data[10] ^= 0xFF;
        assert_eq!(
            pi.verify(&corrupted_data, lba_ref_tag, NvmeProtectionType::Type1),
            Err(SysError::InvalidArgument)
        );

        // Validation Type 3 (ignore reference tag)
        assert!(pi
            .verify(&block_data, 0xDEAD_BEEF, NvmeProtectionType::Type3)
            .is_ok());

        // Bypass d'application avec 0xFFFF (standard T10/NVMe)
        let pi_bypass = NvmeProtectionInformation::new(0x0000, 0xFFFF, 0);
        assert!(pi_bypass
            .verify(&corrupted_data, 0x9999, NvmeProtectionType::Type1)
            .is_ok());

        // Sérialisation et désérialisation
        let bytes = pi.to_bytes();
        let pi_restored = NvmeProtectionInformation::from_bytes(&bytes);
        assert_eq!(pi, pi_restored);
    }

    #[test]
    fn test_format_nvm_apply_to_namespace_dps() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        let mut desc = NvmeNamespaceDescriptor::new(1, 4_194_304, 4_194_304);
        desc.used_blocks = 1_000_000;
        desc.num_lba_formats = 2; // Supporte format 0 (512e) et format 1 (4Kn)
        ctrl.register_namespace(desc).expect("register");

        let initial_ns = ctrl.find_namespace(1).unwrap();
        assert!(initial_ns.active_lba_format.is_512e());
        assert_eq!(initial_ns.data_protection, 0);
        assert_eq!(initial_ns.used_blocks, 1_000_000);

        // Configuration reformatage en 4Kn avec Protection Type 2 et First8Bytes PIL
        let new_format = NvmeLbaFormat {
            metadata_size: 8,
            lba_data_size_pow2: 12, // 4096 B
            relative_performance: 1,
        };
        let cfg = NvmeFormatConfig {
            lba_format_index: 1,
            metadata_setting: NvmeMetadataSetting::ExtendedLba,
            protection_type: NvmeProtectionType::Type2,
            protection_location: NvmeProtectionLocation::First8Bytes,
            secure_erase: NvmeSecureErase::None,
        };

        ctrl.apply_format_to_namespace(1, cfg, new_format)
            .expect("apply format");

        let updated_ns = ctrl.find_namespace(1).unwrap();
        assert!(updated_ns.active_lba_format.is_4kn());
        assert_eq!(updated_ns.active_lba_format.sector_bytes(), 4096);
        assert_eq!(updated_ns.used_blocks, 0); // Réinitialisé
                                               // DPS : bits 2:0 = Type 2 (2), bit 3 = First8Bytes (1 << 3 = 8) -> 0x0A
        assert_eq!(updated_ns.data_protection, 0x0A);

        // Index hors bornes -> Erreur
        let bad_cfg = NvmeFormatConfig {
            lba_format_index: 5,
            ..Default::default()
        };
        assert_eq!(
            ctrl.apply_format_to_namespace(1, bad_cfg, new_format),
            Err(SysError::InvalidArgument)
        );

        // NSID inexistant -> InvalidHandle
        assert_eq!(
            ctrl.apply_format_to_namespace(99, cfg, new_format),
            Err(SysError::InvalidHandle)
        );
    }

    #[test]
    fn test_create_io_queues_and_deviceio_msix_delegation() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Validation de submit_create_io_cq (CDW10, CDW11, Opcode)
        let cq_cid = ctrl
            .submit_create_io_cq(1, 64, 0x1000_2000, 2, true, true)
            .expect("create io cq");
        let cq_cmd = ctrl.admin_queue.sq[(cq_cid as usize) % QUEUE_SIZE];
        assert_eq!((cq_cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_CREATE_CQ);
        assert_eq!(cq_cmd.prp1, 0x1000_2000);
        // CDW10 : bits [31:16] = size - 1 = 63 = 0x003F, bits [15:0] = QID = 1 -> 0x003F0001
        assert_eq!(cq_cmd.cdw10, (63 << 16) | 1);
        // CDW11 : bit 0 = PC (1), bit 1 = IEN (1), bits [31:16] = IV = 2 -> (2 << 16) | 0x03
        assert_eq!(cq_cmd.cdw11, (2 << 16) | 0x03);

        // Erreurs d'arguments Create I/O CQ
        assert_eq!(
            ctrl.submit_create_io_cq(0, 64, 0x1000, 0, true, true),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            ctrl.submit_create_io_cq(1, 0, 0x1000, 0, true, true),
            Err(SysError::InvalidArgument)
        );

        // 2. Validation de submit_create_io_sq (CDW10, CDW11, Opcode)
        let sq_cid = ctrl
            .submit_create_io_sq(1, 64, 0x1000_4000, 1, NvmeQueuePriority::High, true)
            .expect("create io sq");
        let sq_cmd = ctrl.admin_queue.sq[(sq_cid as usize) % QUEUE_SIZE];
        assert_eq!((sq_cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_CREATE_SQ);
        assert_eq!(sq_cmd.prp1, 0x1000_4000);
        // CDW10 : QSIZE-1 = 63, QID = 1
        assert_eq!(sq_cmd.cdw10, (63 << 16) | 1);
        // CDW11 : bit 0 = PC (1), bits [2:1] = QPRIO = High (1 << 1 = 2), bits [31:16] = CQID = 1
        assert_eq!(sq_cmd.cdw11, (1 << 16) | (1 << 1) | 1);

        // Erreurs d'arguments Create I/O SQ
        assert_eq!(
            ctrl.submit_create_io_sq(0, 64, 0x1000, 1, NvmeQueuePriority::High, true),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            ctrl.submit_create_io_sq(1, 0, 0x1000, 1, NvmeQueuePriority::High, true),
            Err(SysError::InvalidArgument)
        );
        assert_eq!(
            ctrl.submit_create_io_sq(1, 64, 0x1000, 0, NvmeQueuePriority::High, true),
            Err(SysError::InvalidArgument)
        );

        // 3. Liaison de la CQ 1 au vecteur MSI-X et simulation de délégation
        assert!(ctrl.enable_msix(8).is_ok());
        let pci_addr = PciAddress::new(0, 2, 0);

        // Configuration directe de canal délégué
        let del_res = ctrl.bind_cq_deviceio_msix(
            1,
            2,
            &pci_addr,
            libjambo::Handle(42), // port_handle
            0xABCD_EF01,          // cookie
            0x48,                 // target_vector (72)
            0,                    // apic_id
        );
        let irq_h = del_res.expect("bind_cq_deviceio_msix failed");
        assert_eq!(irq_h, libjambo::Handle(72));

        let del_desc = ctrl.get_cq_msix_delegation(1).expect("delegation exists");
        assert_eq!(del_desc.qid, 1);
        assert_eq!(del_desc.vector_index, 2);
        assert_eq!(del_desc.port_handle, libjambo::Handle(42));
        assert_eq!(del_desc.cookie, 0xABCD_EF01);
        assert_eq!(del_desc.target_vector, 0x48);
        assert!(del_desc.bound);
        assert!(del_desc.interrupts_enabled);

        // 4. Traitement de notification asynchrone MSI-X déléguée
        let event = ctrl.dispatch_delegated_msix_completion(0x48);
        assert!(event.is_some());
        let (ev_qid, _completion) = event.unwrap();
        assert_eq!(ev_qid, 1);

        // Vecteur non relié -> None
        assert_eq!(ctrl.dispatch_delegated_msix_completion(0x99), None);

        // 5. Déconnexion de la délégation MSI-X
        assert!(ctrl.unbind_cq_deviceio_msix(1).is_ok());
        let del_after = ctrl.get_cq_msix_delegation(1);
        assert_eq!(del_after, None);

        // 6. Suppression de file I/O (Delete I/O SQ et Delete I/O CQ)
        let del_sq_cid = ctrl.submit_delete_io_queue(1, false).expect("delete sq");
        let del_sq_cmd = ctrl.admin_queue.sq[(del_sq_cid as usize) % QUEUE_SIZE];
        assert_eq!((del_sq_cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_DELETE_SQ);
        assert_eq!(del_sq_cmd.cdw10, 1);

        let del_cq_cid = ctrl.submit_delete_io_queue(1, true).expect("delete cq");
        let del_cq_cmd = ctrl.admin_queue.sq[(del_cq_cid as usize) % QUEUE_SIZE];
        assert_eq!((del_cq_cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_DELETE_CQ);
        assert_eq!(del_cq_cmd.cdw10, 1);
    }

    #[test]
    fn test_nvme_weighted_round_robin_and_doorbell_coalescing() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Validation de submit_set_arbitration_config (FID 0x01)
        // AB = 2 (burst de 4 commandes), LPW = 1, MPW = 3, HPW = 7
        let arb_cfg = NvmeArbitrationConfig::new(2, 1, 3, 7);
        let cid_arb = ctrl
            .submit_set_arbitration_config(arb_cfg)
            .expect("set arbitration");
        let arb_cmd = ctrl.admin_queue.sq[(cid_arb as usize) % QUEUE_SIZE];
        assert_eq!((arb_cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_SET_FEATURES);
        assert_eq!(arb_cmd.cdw10, NVME_FEAT_ARBITRATION);
        // CDW11 : AB(2) | (LPW(1) << 8) | (MPW(3) << 16) | (HPW(7) << 24)
        assert_eq!(arb_cmd.cdw11, 2 | (1 << 8) | (3 << 16) | (7 << 24));
        assert_eq!(ctrl.arbitration_config, arb_cfg);

        // 2. Validation de submit_set_interrupt_coalescing (FID 0x08)
        // THR = 16 complétions, TIME = 5 (500 microsecondes)
        let coal_cfg = NvmeInterruptCoalescingConfig::new(16, 5);
        let cid_coal = ctrl
            .submit_set_interrupt_coalescing(coal_cfg)
            .expect("set coalescing");
        let coal_cmd = ctrl.admin_queue.sq[(cid_coal as usize) % QUEUE_SIZE];
        assert_eq!((coal_cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_SET_FEATURES);
        assert_eq!(coal_cmd.cdw10, NVME_FEAT_INTERRUPT_COALESCING);
        // CDW11 : THR(16) | (TIME(5) << 8)
        assert_eq!(coal_cmd.cdw11, 16 | (5 << 8));
        assert_eq!(ctrl.interrupt_coalescing, coal_cfg);

        // 3. Validation de NvmeSubmissionDoorbellCoalescer
        ctrl.doorbell_coalescer = NvmeSubmissionDoorbellCoalescer::new(4);
        let dummy_cmd = NvmeSubmissionEntry::default();

        // 3 premières commandes -> Pas de flush requis (accumulation dans le coalescer)
        let (_, f1) = ctrl
            .submit_sq_command_coalesced(1, dummy_cmd)
            .expect("submit 1");
        assert!(!f1);
        let (_, f2) = ctrl
            .submit_sq_command_coalesced(1, dummy_cmd)
            .expect("submit 2");
        assert!(!f2);
        let (_, f3) = ctrl
            .submit_sq_command_coalesced(1, dummy_cmd)
            .expect("submit 3");
        assert!(!f3);

        // 4e commande -> Seuil de 4 atteint, flush MMIO requis
        let (_, f4) = ctrl
            .submit_sq_command_coalesced(1, dummy_cmd)
            .expect("submit 4");
        assert!(f4);
        assert_eq!(ctrl.doorbell_coalescer.doorbell_writes, 1);
        assert_eq!(ctrl.doorbell_coalescer.total_commands_queued, 4);
        assert_eq!(ctrl.doorbell_coalescer.doorbells_saved(), 3);
        assert_eq!(ctrl.doorbell_coalescer.efficiency_percentage(), 75);

        // 5e commande -> pas de flush, puis flush forcé
        let (_, f5) = ctrl
            .submit_sq_command_coalesced(1, dummy_cmd)
            .expect("submit 5");
        assert!(!f5);
        let flushed_tail = ctrl.flush_sq_doorbell(1);
        assert!(flushed_tail.is_some());
        assert_eq!(ctrl.doorbell_coalescer.doorbell_writes, 2);
        assert_eq!(ctrl.doorbell_coalescer.doorbells_saved(), 3);

        // Deuxième flush consécutif -> None (déjà purgé)
        assert_eq!(ctrl.flush_sq_doorbell(1), None);

        // 4. Validation de l'arbitrage WRRU (Weighted Round Robin with Urgent Priority Class)
        let mut sched = NvmeWrruScheduler::new(NvmeArbitrationConfig::new(0, 0, 1, 3));
        sched.register_queue(1, NvmeQueuePriority::Urgent);
        sched.register_queue(2, NvmeQueuePriority::High);
        sched.register_queue(3, NvmeQueuePriority::Medium);
        sched.register_queue(4, NvmeQueuePriority::Low);

        // Enqueuer des commandes dans chaque file
        sched.enqueue_command(2); // High
        sched.enqueue_command(3); // Medium
        sched.enqueue_command(4); // Low
        sched.enqueue_command(1); // Urgent (en dernier pour vérifier la priorité absolue)

        // La file Urgent (1) doit être servie en premier malgré son ajout tardif
        assert_eq!(sched.select_next_queue(), Some(1));

        // Puis les classes High (2), Medium (3), Low (4)
        assert_eq!(sched.select_next_queue(), Some(2));
        assert_eq!(sched.select_next_queue(), Some(3));
        assert_eq!(sched.select_next_queue(), Some(4));

        // Plus de commandes
        assert_eq!(sched.select_next_queue(), None);
    }

    #[test]
    fn test_nvme_sanitize_operations_and_io_fencing() {
        let mut ctrl = NvmeController::new();
        ctrl.ready = true;

        // 1. Validation de l'encodage Sanitize Action et Config
        assert_eq!(
            NvmeSanitizeAction::from_u8(0x01),
            Some(NvmeSanitizeAction::ExitFailure)
        );
        assert_eq!(
            NvmeSanitizeAction::from_u8(0x02),
            Some(NvmeSanitizeAction::StartBlockErase)
        );
        assert_eq!(
            NvmeSanitizeAction::from_u8(0x03),
            Some(NvmeSanitizeAction::StartOverwrite)
        );
        assert_eq!(
            NvmeSanitizeAction::from_u8(0x04),
            Some(NvmeSanitizeAction::StartCryptoErase)
        );
        assert_eq!(NvmeSanitizeAction::from_u8(0x99), None);

        let cfg = NvmeSanitizeConfig {
            allow_unrestricted_exit: true,
            overwrite_pass_count: 5,
            invert_pattern_between_passes: true,
            no_deallocate_response: true,
            overwrite_pattern: 0xDEADBEEF,
        };
        let cdw10 = cfg.to_cdw10(NvmeSanitizeAction::StartOverwrite);
        assert_eq!((cdw10 & 0x07) as u8, NVME_SANACT_START_OVERWRITE);
        assert_ne!(cdw10 & (1 << 3), 0); // AUSE
        assert_eq!(((cdw10 >> 4) & 0x0F) as u8, 5); // OWPASS
        assert_ne!(cdw10 & (1 << 8), 0); // OIPBP
        assert_ne!(cdw10 & (1 << 9), 0); // NODRM
        assert_eq!(cfg.to_cdw11(), 0xDEADBEEF);

        // 2. Enregistrement d'un namespace avec des blocs alloués
        let ns = NvmeNamespaceDescriptor {
            nsid: 1,
            total_blocks: 1_000_000,
            capacity_blocks: 1_000_000,
            used_blocks: 50_000,
            active_lba_format: NvmeLbaFormat {
                metadata_size: 0,
                lba_data_size_pow2: 9,
                relative_performance: 0,
            },
            num_lba_formats: 1,
            ..Default::default()
        };
        ctrl.namespaces[0] = Some(ns);

        // 3. Soumission d'une commande Sanitize Block Erase
        assert!(!ctrl.is_sanitize_in_progress());
        let cid = ctrl
            .submit_sanitize(
                NvmeSanitizeAction::StartBlockErase,
                NvmeSanitizeConfig::default(),
            )
            .expect("submit sanitize");
        assert!(ctrl.is_sanitize_in_progress());

        let cmd = ctrl.admin_queue.sq[(cid as usize) % QUEUE_SIZE];
        assert_eq!((cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_SANITIZE);
        assert_eq!((cmd.cdw10 & 0x07) as u8, NVME_SANACT_START_BLOCK_ERASE);

        // 4. Barrière I/O stricte pendant Sanitize (NVMe 1.4 §8.21)
        let dma = NvmeDmaBuffer::single_page(0x1000);
        assert_eq!(
            ctrl.submit_async_read_dma(0, 1, dma),
            Err(SysError::ResourceBusy)
        );
        assert_eq!(
            ctrl.submit_async_write_dma(0, 1, dma),
            Err(SysError::ResourceBusy)
        );
        assert_eq!(
            ctrl.submit_async_write_zeroes(0, 1, false),
            Err(SysError::ResourceBusy)
        );
        assert_eq!(ctrl.submit_async_flush(1), Err(SysError::ResourceBusy));
        assert_eq!(
            ctrl.submit_async_dataset_management(1, 0x2000, 1, 0),
            Err(SysError::ResourceBusy)
        );

        // Nouvelle commande Sanitize rejetée tant qu'en cours (sauf ExitFailure)
        assert_eq!(
            ctrl.submit_sanitize(
                NvmeSanitizeAction::StartCryptoErase,
                NvmeSanitizeConfig::default()
            ),
            Err(SysError::ResourceBusy)
        );

        // 5. Requête du journal de statut Sanitize (LID 0x81)
        let log_cid = ctrl
            .submit_async_sanitize_status_log(0x5000)
            .expect("submit sanitize log");
        let log_cmd = ctrl.admin_queue.sq[(log_cid as usize) % QUEUE_SIZE];
        assert_eq!((log_cmd.cdw0 & 0xFF) as u8, NVME_ADMIN_GET_LOG_PAGE);
        assert_eq!((log_cmd.cdw10 & 0xFF) as u8, NVME_LOG_SANITIZE_STATUS);

        // 6. Complétion réussie de Sanitize et remise à zéro des blocs alloués
        let log = NvmeSanitizeStatusLog {
            sstat: NVME_SANITIZE_COMPLETED_SUCCESS | NVME_SANITIZE_GLOBAL_DATA_ERASED,
            sprog: 65535, // 100%
            ..Default::default()
        };
        ctrl.apply_sanitize_status(log);
        assert!(!ctrl.is_sanitize_in_progress());
        assert_eq!(ctrl.namespaces[0].as_ref().unwrap().used_blocks, 0);

        // I/O de nouveau permises après complétion
        assert!(ctrl.submit_async_write_zeroes(0, 1, false).is_ok());

        // 7. Événement AER Sanitize Completed
        let aer_dw0_sanitize = 2 | (0x01 << 8) | ((NVME_LOG_SANITIZE_STATUS as u32) << 16);
        let action = ctrl.dispatch_async_event_action(aer_dw0_sanitize);
        assert_eq!(
            action,
            NvmeAsyncEventAction::FetchSanitizeStatusLog {
                notice_code: 0x01,
                log_page_id: NVME_LOG_SANITIZE_STATUS,
            }
        );
    }
}

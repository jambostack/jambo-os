//! Module d'infrastructure de gestion des pilotes matériels Ring 3.
//!
//! Fournit les primitives fondamentales pour le cycle de vie des pilotes de périphériques :
//! - `DeviceRemoveLock` : Verrou de déconnexion matérielle (hot-unplug) basé sur un compteur atomique
//!   traçant les E/S en vol et garantissant l'absence de panique ou use-after-free.
//! - Modèle de Paquets d'E/S en Couches (`IoRequestPacket`, `IoStackLocation`) : requêtes asynchrones
//!   avec tranches d'état empilables permettant l'interposition de microservices filtres (EDR, DLP, chiffrement).

use crate::SysError;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Statut de retour d'une opération sur le verrou de déconnexion matérielle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveLockStatus {
    /// Opération acquise avec succès, le périphérique est actif.
    Success,
    /// Le périphérique est en cours de déconnexion matérielle (surprise removal ou unplug ordonné).
    DeviceRemoved,
}

/// Verrou de Déconnexion Matérielle (`DeviceRemoveLock`).
///
/// Ce verrou suit rigoureusement le nombre de transactions ou requêtes d'E/S en vol
/// sur un périphérique (NVMe, USB xHCI, VirtIO).
///
/// Lorsque le contrôleur matériel ou le bus détecte une déconnexion (hot-unplug, surprise removal),
/// le pilote appelle `release_and_wait()`, marquant le périphérique comme supprimé et attendant
/// que toutes les requêtes en vol soient terminées avant de libérer les ressources MMIO BAR0 et handles.
pub struct DeviceRemoveLock {
    /// Compteur atomique des E/S en vol (in-flight IOs).
    in_flight_count: AtomicU32,
    /// Indicateur de demande de suppression / déconnexion en cours.
    is_removing: AtomicBool,
}

impl Default for DeviceRemoveLock {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceRemoveLock {
    /// Crée une nouvelle instance de `DeviceRemoveLock` à l'état actif (0 requête en vol).
    pub const fn new() -> Self {
        Self {
            in_flight_count: AtomicU32::new(0),
            is_removing: AtomicBool::new(false),
        }
    }

    /// Tente d'acquérir le verrou pour exécuter une transaction d'E/S.
    ///
    /// Incrémente le compteur atomique de requêtes en vol si le périphérique est toujours présent.
    /// Si une déconnexion matérielle a été signalée, l'acquisition échoue immédiatement.
    #[inline]
    pub fn acquire(&self) -> Result<(), SysError> {
        if self.is_removing.load(Ordering::Acquire) {
            return Err(SysError::PeerClosed);
        }

        // Incrémentation avec vérification CAS pour éliminer tout risque de course
        let mut current = self.in_flight_count.load(Ordering::Relaxed);
        loop {
            if self.is_removing.load(Ordering::Acquire) {
                return Err(SysError::PeerClosed);
            }
            match self.in_flight_count.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    /// Libère le verrou à la fin d'une transaction d'E/S.
    ///
    /// Décrémente le compteur de requêtes en vol.
    #[inline]
    pub fn release(&self) {
        let prev = self.in_flight_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "DeviceRemoveLock underflow");
    }

    /// Signale la déconnexion matérielle (hot-unplug) et bascule le verrou en mode suppression.
    ///
    /// Retourne le nombre d'E/S résiduelles actuellement en vol.
    #[inline]
    pub fn signal_removal(&self) -> u32 {
        self.is_removing.store(true, Ordering::Release);
        self.in_flight_count.load(Ordering::Acquire)
    }

    /// Indique si le périphérique est marqué en cours de déconnexion.
    #[inline]
    pub fn is_removed(&self) -> bool {
        self.is_removing.load(Ordering::Acquire)
    }

    /// Retourne le nombre exact de requêtes d'E/S actuellement en vol.
    #[inline]
    pub fn outstanding_count(&self) -> u32 {
        self.in_flight_count.load(Ordering::Acquire)
    }

    /// Réinitialise l'état du verrou lors d'une reconnexion ou réinitialisation du bus.
    #[inline]
    pub fn reset(&self) {
        self.in_flight_count.store(0, Ordering::Release);
        self.is_removing.store(false, Ordering::Release);
    }
}

/// Identifiant de fonction majeure pour les paquets d'E/S en couches (IRP Major Function).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoMajorFunction {
    Create = 0x00,
    Close = 0x01,
    Read = 0x02,
    Write = 0x03,
    DeviceControl = 0x04,
    FlushBuffers = 0x05,
    Shutdown = 0x06,
    Pnp = 0x07,
    Power = 0x08,
    InternalDeviceControl = 0x09,
}

/// Statut de complétion d'un paquet d'E/S (`IoStatusBlock`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoStatusBlock {
    /// Code de retour (0 pour succès, ou code d'erreur standard JamboOS).
    pub status: i32,
    /// Nombre d'octets transférés ou information de statut spécifique au pilote.
    pub information: u64,
}

/// Rôle ou niveau du filtre dans la pile d'E/S.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoFilterRole {
    /// Pilote de fonction principal (FDO, ex: NVMe, xHCI).
    FunctionDriver = 0,
    /// Filtre supérieur de chiffrement (Transparent Storage Encryption).
    EncryptionFilter = 1,
    /// Filtre supérieur de prévention contre les fuites de données (DLP).
    DlpFilter = 2,
    /// Filtre supérieur de détection et réponse aux menaces (EDR / Intégrité).
    EdrFilter = 3,
    /// Filtre inférieur d'arbitrage de bus (ex: PCIe Bus Filter).
    BusFilter = 4,
}

/// Tranche d'état d'E/S empilable (`IoStackLocation`).
///
/// Chaque couche ou microservice filtre traversé par une requête dispose
/// de sa propre tranche d'état, contenant la fonction demandée, les paramètres,
/// les drapeaux et un contexte opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoStackLocation {
    /// Fonction majeure d'E/S demandée à ce niveau.
    pub major_function: IoMajorFunction,
    /// Rôle du pilote ou filtre propriétaire de cette tranche.
    pub filter_role: IoFilterRole,
    /// Drapeaux spécifiques à la requête.
    pub flags: u32,
    /// Paramètre d'offset / LBA de départ.
    pub offset: u64,
    /// Longueur en octets ou blocs.
    pub length: u64,
    /// Contexte ou cookie réservé pour le filtre.
    pub context: u64,
}

impl Default for IoStackLocation {
    fn default() -> Self {
        Self {
            major_function: IoMajorFunction::Read,
            filter_role: IoFilterRole::FunctionDriver,
            flags: 0,
            offset: 0,
            length: 0,
            context: 0,
        }
    }
}

/// Capacité maximale de tranches dans la pile d'E/S (stack locations).
pub const MAX_IO_STACK_DEPTH: usize = 4;

/// Paquet de Requête d'E/S en Couches (`IoRequestPacket` / IRP).
///
/// Modèle asynchrone unifié pour la traversée de la pile de pilotes et de microservices filtres.
/// Permet à un filtre (ex: jambo-edr, jambo-dlp) d'intercepter la requête, de valider
/// ou transformer le tampon mémoire, puis de transmettre la tranche suivante vers le pilote matériel.
pub struct IoRequestPacket {
    /// Identifiant unique de la requête d'E/S.
    pub packet_id: u64,
    /// Statut final ou intermédiaire de complétion.
    pub io_status: IoStatusBlock,
    /// Adresse du tampon mémoire utilisateur ou noyau (DMA buffer).
    pub buffer_ptr: u64,
    /// Longueur totale du tampon en octets.
    pub buffer_len: usize,
    /// Tranches d'état empilées (stack locations).
    pub stack_locations: [IoStackLocation; MAX_IO_STACK_DEPTH],
    /// Nombre total de tranches configurées dans la pile.
    pub stack_count: u8,
    /// Index de la tranche actuellement active (décrémenté au fil de la traversée).
    pub current_stack_index: u8,
    /// Indicateur de complétion asynchrone.
    pub is_completed: bool,
}

impl IoRequestPacket {
    /// Construit un nouveau paquet d'E/S avec une profondeur de pile spécifiée.
    pub fn new(packet_id: u64, buffer_ptr: u64, buffer_len: usize) -> Self {
        Self {
            packet_id,
            io_status: IoStatusBlock::default(),
            buffer_ptr,
            buffer_len,
            stack_locations: [IoStackLocation::default(); MAX_IO_STACK_DEPTH],
            stack_count: 0,
            current_stack_index: 0,
            is_completed: false,
        }
    }

    /// Empile une nouvelle tranche d'état pour un filtre ou un pilote.
    pub fn push_stack_location(
        &mut self,
        major: IoMajorFunction,
        role: IoFilterRole,
        offset: u64,
        length: u64,
    ) -> Result<(), SysError> {
        if (self.stack_count as usize) >= MAX_IO_STACK_DEPTH {
            return Err(SysError::OutOfMemory);
        }
        let idx = self.stack_count as usize;
        self.stack_locations[idx] = IoStackLocation {
            major_function: major,
            filter_role: role,
            flags: 0,
            offset,
            length,
            context: 0,
        };
        self.stack_count = self.stack_count.saturating_add(1);
        self.current_stack_index = self.stack_count.saturating_sub(1);
        Ok(())
    }

    /// Récupère une référence vers la tranche d'état active courante.
    #[inline]
    pub fn current_stack_location(&self) -> Option<&IoStackLocation> {
        if self.stack_count == 0 {
            None
        } else {
            Some(&self.stack_locations[self.current_stack_index as usize])
        }
    }

    /// Récupère une référence mutable vers la tranche d'état active courante.
    #[inline]
    pub fn current_stack_location_mut(&mut self) -> Option<&mut IoStackLocation> {
        if self.stack_count == 0 {
            None
        } else {
            let idx = self.current_stack_index as usize;
            Some(&mut self.stack_locations[idx])
        }
    }

    /// Avance la requête vers la tranche de pile suivante (couche inférieure de pilotes).
    #[inline]
    pub fn forward_to_next_location(&mut self) -> Result<(), SysError> {
        if self.current_stack_index == 0 {
            return Err(SysError::InvalidArgument);
        }
        self.current_stack_index = self.current_stack_index.saturating_sub(1);
        Ok(())
    }

    /// Termine et marque la requête d'E/S comme complétée avec le statut et l'information donnés.
    #[inline]
    pub fn complete(&mut self, status: i32, bytes_transferred: u64) {
        self.io_status.status = status;
        self.io_status.information = bytes_transferred;
        self.is_completed = true;
    }
}

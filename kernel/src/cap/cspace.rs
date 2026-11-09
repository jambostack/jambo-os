extern crate alloc;
use crate::mm::Vmo;
use alloc::sync::Arc;
use alloc::vec::Vec;
use jambo_abi::{cap_rights, Handle, SysError};
use spin::Mutex;

#[derive(Clone)]
pub enum KernelObject {
    None,
    Vmo(Arc<Vmo>),
    Channel(Arc<crate::ipc::ChannelEndpoint>),
    Port(Arc<crate::ipc::Port>),
    Process(Arc<crate::sched::Process>),
    Thread(Arc<Mutex<crate::sched::Thread>>),
    Ring(Arc<crate::ipc::SharedRing>),
    Iommu(Arc<crate::arch::IommuDomain>),
    Irq(Arc<crate::ipc::IrqObject>),
}

#[derive(Clone)]
pub struct Capability {
    pub object: KernelObject,
    pub rights: u32,
    pub generation: u32,
}

#[derive(Clone, Default)]
struct CSpaceSlot {
    cap: Option<Capability>,
    generation: u32,
}

pub struct CSpace {
    slots: Vec<CSpaceSlot>,
}

impl CSpace {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(64);
        // Slot 0 réservé pour Handle::NULL
        slots.push(CSpaceSlot {
            cap: None,
            generation: 1,
        });
        Self { slots }
    }

    /// Insère un nouvel objet noyau dans la table de capacités et génère son Handle unique 64 bits
    pub fn insert(&mut self, object: KernelObject, rights: u32) -> Handle {
        // Chercher un slot libre existant
        for (i, slot) in self.slots.iter_mut().enumerate().skip(1) {
            if slot.cap.is_none() {
                slot.generation = slot.generation.wrapping_add(1);
                let gen = slot.generation;
                slot.cap = Some(Capability {
                    object,
                    rights,
                    generation: gen,
                });
                return Handle::new(i as u32, gen);
            }
        }

        // Sinon allouer un nouveau slot
        let index = self.slots.len() as u32;
        let gen = 1;
        self.slots.push(CSpaceSlot {
            cap: Some(Capability {
                object,
                rights,
                generation: gen,
            }),
            generation: gen,
        });
        Handle::new(index, gen)
    }

    /// Résout un Handle et vérifie les droits demandés
    pub fn lookup(&self, handle: Handle, required_rights: u32) -> Result<KernelObject, SysError> {
        let idx = handle.index() as usize;
        if idx >= self.slots.len() {
            return Err(SysError::InvalidHandle);
        }

        let slot = &self.slots[idx];
        if slot.generation != handle.generation() {
            return Err(SysError::InvalidHandle); // Protection anti-ABA (Use-After-Close)
        }

        match slot.cap {
            Some(ref cap) => {
                if (cap.rights & required_rights) != required_rights {
                    return Err(SysError::PermissionDenied); // Droit insuffisant
                }
                Ok(cap.object.clone())
            }
            None => Err(SysError::InvalidHandle),
        }
    }

    /// Récupère la capacité brute (objet et droits) associée à un handle
    pub fn get_cap(&self, handle: Handle) -> Result<Capability, SysError> {
        let idx = handle.index() as usize;
        if idx >= self.slots.len() {
            return Err(SysError::InvalidHandle);
        }
        let slot = &self.slots[idx];
        if slot.generation != handle.generation() {
            return Err(SysError::InvalidHandle);
        }
        slot.cap.clone().ok_or(SysError::InvalidHandle)
    }

    /// Duplique une capacité en réduisant optionnellement ses droits
    pub fn duplicate(&mut self, handle: Handle, rights_mask: u32) -> Result<Handle, SysError> {
        let obj = self.lookup(handle, cap_rights::DUPLICATE)?;
        let idx = handle.index() as usize;
        let current_rights = self.slots[idx].cap.as_ref().unwrap().rights;
        let new_rights = current_rights & rights_mask; // Les droits ne peuvent qu'être réduits

        Ok(self.insert(obj, new_rights))
    }

    /// Transfère atomiquement une capacité vers un CSpace cible en appliquant l'atténuation monotone des droits
    pub fn transfer_to(
        &mut self,
        handle: Handle,
        rights_mask: u32,
        target: &mut CSpace,
    ) -> Result<Handle, SysError> {
        let idx = handle.index() as usize;
        if idx >= self.slots.len() {
            return Err(SysError::InvalidHandle);
        }
        let slot = &self.slots[idx];
        if slot.generation != handle.generation() {
            return Err(SysError::InvalidHandle);
        }
        let cap = slot.cap.as_ref().ok_or(SysError::InvalidHandle)?;
        if (cap.rights & cap_rights::TRANSFER) == 0 {
            return Err(SysError::PermissionDenied);
        }

        // Atténuation monotone stricte : aucune amplification possible au-delà des droits actuels
        let effective_mask = if rights_mask == 0 {
            cap_rights::ALL
        } else {
            rights_mask
        };
        let final_rights = cap.rights & effective_mask;
        let obj = cap.object.clone();

        // Insertion dans le CSpace récepteur
        let new_handle = target.insert(obj, final_rights);

        // Clôture atomique de la capacité source
        let slot_mut = &mut self.slots[idx];
        slot_mut.cap = None;
        slot_mut.generation = slot_mut.generation.wrapping_add(1);

        Ok(new_handle)
    }

    /// Révoque et libère une capacité
    pub fn drop_cap(&mut self, handle: Handle) -> Result<(), SysError> {
        let idx = handle.index() as usize;
        if idx >= self.slots.len() {
            return Err(SysError::InvalidHandle);
        }

        let slot = &mut self.slots[idx];
        if slot.generation != handle.generation() {
            return Err(SysError::InvalidHandle);
        }

        slot.cap = None;
        slot.generation = slot.generation.wrapping_add(1);
        Ok(())
    }
}

pub static KERNEL_CSPACE: Mutex<CSpace> = Mutex::new(CSpace { slots: Vec::new() });

pub fn init_cspace() {
    *KERNEL_CSPACE.lock() = CSpace::new();
}

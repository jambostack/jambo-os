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
    Port(u64),
    Process(Arc<crate::sched::Process>),
    Thread(Arc<Mutex<crate::sched::Thread>>),
    Ring(Arc<crate::ipc::SharedRing>),
    Iommu(Arc<crate::arch::IommuDomain>),
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

    /// Duplique une capacité en réduisant optionnellement ses droits
    pub fn duplicate(&mut self, handle: Handle, rights_mask: u32) -> Result<Handle, SysError> {
        let obj = self.lookup(handle, cap_rights::DUPLICATE)?;
        let idx = handle.index() as usize;
        let current_rights = self.slots[idx].cap.as_ref().unwrap().rights;
        let new_rights = current_rights & rights_mask; // Les droits ne peuvent qu'être réduits

        Ok(self.insert(obj, new_rights))
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

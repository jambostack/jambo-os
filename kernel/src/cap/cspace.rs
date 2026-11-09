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

/// Barrière de sérialisation spéculative matérielle contre les attaques Spectre V1 (Bounds Check Bypass).
/// Bloque l'exécution spéculative d'instructions tant que les vérifications de bornes ne sont pas résolues.
#[inline(always)]
pub fn speculation_barrier() {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: lfence garantit la sérialisation matérielle des accès mémoire et des instructions spéculatives.
    unsafe {
        core::arch::asm!("lfence", options(nomem, nostack, preserves_flags));
    }

    #[cfg(target_arch = "aarch64")]
    // SAFETY: isb garantit la synchronisation des instructions et bloque la spéculation sur AArch64.
    unsafe {
        core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
    }
}

/// Sécurise l'index de slot contre le contournement spéculatif des limites de tableau (Spectre V1).
/// En cas d'indice hors bornes, la barrière matérielle stoppe immédiatement l'exécution spéculative
/// et retourne `None`.
#[inline(always)]
pub fn sanitize_slot_index(idx: usize, len: usize) -> Option<usize> {
    if idx >= len {
        speculation_barrier();
        return None;
    }
    speculation_barrier();
    Some(idx)
}

/// Atténue de façon monotone les droits d'une capacité.
/// Invariant formel : (attenuate_rights(orig, mask) & !orig) == 0.
#[inline(always)]
pub fn attenuate_rights(original: u32, rights_mask: u32) -> u32 {
    let mask = if rights_mask == 0 {
        original
    } else {
        rights_mask
    };
    original & mask
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

    /// Résout un Handle et vérifie les droits demandés avec barrière anti-spectre
    pub fn lookup(&self, handle: Handle, required_rights: u32) -> Result<KernelObject, SysError> {
        let raw_idx = handle.index() as usize;
        let idx = sanitize_slot_index(raw_idx, self.slots.len()).ok_or(SysError::InvalidHandle)?;

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

    /// Récupère la capacité brute (objet et droits) associée à un handle avec barrière anti-spectre
    pub fn get_cap(&self, handle: Handle) -> Result<Capability, SysError> {
        let raw_idx = handle.index() as usize;
        let idx = sanitize_slot_index(raw_idx, self.slots.len()).ok_or(SysError::InvalidHandle)?;
        let slot = &self.slots[idx];
        if slot.generation != handle.generation() {
            return Err(SysError::InvalidHandle);
        }
        slot.cap.clone().ok_or(SysError::InvalidHandle)
    }

    /// Duplique une capacité en réduisant optionnellement ses droits
    pub fn duplicate(&mut self, handle: Handle, rights_mask: u32) -> Result<Handle, SysError> {
        let obj = self.lookup(handle, cap_rights::DUPLICATE)?;
        let raw_idx = handle.index() as usize;
        let idx = sanitize_slot_index(raw_idx, self.slots.len()).ok_or(SysError::InvalidHandle)?;
        let current_rights = self.slots[idx].cap.as_ref().unwrap().rights;
        let new_rights = attenuate_rights(current_rights, rights_mask);
        debug_assert_eq!(
            new_rights & !current_rights,
            0,
            "Violation d'atténuation monotone des droits lors d'une duplication CSpace"
        );

        Ok(self.insert(obj, new_rights))
    }

    /// Transfère atomiquement une capacité vers un CSpace cible en appliquant l'atténuation monotone des droits
    pub fn transfer_to(
        &mut self,
        handle: Handle,
        rights_mask: u32,
        target: &mut CSpace,
    ) -> Result<Handle, SysError> {
        let raw_idx = handle.index() as usize;
        let idx = sanitize_slot_index(raw_idx, self.slots.len()).ok_or(SysError::InvalidHandle)?;
        let slot = &self.slots[idx];
        if slot.generation != handle.generation() {
            return Err(SysError::InvalidHandle);
        }
        let cap = slot.cap.as_ref().ok_or(SysError::InvalidHandle)?;
        if (cap.rights & cap_rights::TRANSFER) == 0 {
            return Err(SysError::PermissionDenied);
        }

        // Atténuation monotone stricte : aucune amplification possible au-delà des droits actuels
        let final_rights = attenuate_rights(cap.rights, rights_mask);
        debug_assert_eq!(
            final_rights & !cap.rights,
            0,
            "Violation d'atténuation monotone des droits lors d'un transfert CSpace"
        );
        let obj = cap.object.clone();

        // Clôture atomique de la capacité source
        let slot_mut = &mut self.slots[idx];
        slot_mut.cap = None;
        slot_mut.generation = slot_mut.generation.wrapping_add(1);

        // Insertion dans le CSpace récepteur
        let new_handle = target.insert(obj, final_rights);

        Ok(new_handle)
    }

    /// Révoque et libère une capacité avec barrière anti-spectre
    pub fn drop_cap(&mut self, handle: Handle) -> Result<(), SysError> {
        let raw_idx = handle.index() as usize;
        let idx = sanitize_slot_index(raw_idx, self.slots.len()).ok_or(SysError::InvalidHandle)?;

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

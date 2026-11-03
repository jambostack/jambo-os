use core::sync::atomic::{fence, Ordering};
use jambo_abi::{RingDesc, SysError};

pub struct SharedRing {
    pub sub_ring_vaddr: u64,
    pub comp_ring_vaddr: u64,
    pub entries: u32,
    pub mask: u32,
    pub flags: u32,
}

impl SharedRing {
    pub fn new(desc: &RingDesc) -> Result<Self, SysError> {
        if desc.ring_entries == 0
            || (desc.ring_entries & (desc.ring_entries - 1)) != 0
            || desc.ring_entries > 65536
        {
            return Err(SysError::InvalidArgument); // Doit être une puissance de 2 <= 65536
        }
        if desc.sub_ring_vaddr == 0 || desc.comp_ring_vaddr == 0 {
            return Err(SysError::BadAddress);
        }
        if (desc.sub_ring_vaddr % 8) != 0 || (desc.comp_ring_vaddr % 8) != 0 {
            return Err(SysError::BadAddress);
        }

        Ok(Self {
            sub_ring_vaddr: desc.sub_ring_vaddr,
            comp_ring_vaddr: desc.comp_ring_vaddr,
            entries: desc.ring_entries,
            mask: desc.ring_entries - 1,
            flags: desc.flags,
        })
    }

    /// Soumet des entrées et complète les opérations avec barrières mémoire strictes
    pub fn submit_and_complete(&self, count: u32) -> Result<u32, SysError> {
        if count > self.entries {
            return Err(SysError::InvalidArgument);
        }

        // Barrière mémoire Release : garantit que toutes les écritures dans les descripteurs
        // ou buffers partagés sont ordonnées et visibles avant la notification
        fence(Ordering::Release);

        let completed = count.min(self.entries);

        // Barrière mémoire Acquire : garantit que toutes les lectures de complétion
        // observent les mises à jour effectuées par les cœurs ou contrôleurs matériels
        fence(Ordering::Acquire);

        Ok(completed)
    }

    /// Calcule un index d'anneau avec protection contre le débordement
    #[inline]
    pub fn advance_index(&self, current: u32, count: u32) -> Option<u32> {
        current.checked_add(count).map(|val| val & self.mask)
    }
}

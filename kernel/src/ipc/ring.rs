use jambo_abi::{RingDesc, SysError};

pub struct SharedRing {
    pub sub_ring_vaddr: u64,
    pub comp_ring_vaddr: u64,
    pub entries: u32,
    pub flags: u32,
}

impl SharedRing {
    pub fn new(desc: &RingDesc) -> Result<Self, SysError> {
        if desc.ring_entries == 0 || (desc.ring_entries & (desc.ring_entries - 1)) != 0 {
            return Err(SysError::InvalidArgument); // Doit être une puissance de 2
        }

        Ok(Self {
            sub_ring_vaddr: desc.sub_ring_vaddr,
            comp_ring_vaddr: desc.comp_ring_vaddr,
            entries: desc.ring_entries,
            flags: desc.flags,
        })
    }
}

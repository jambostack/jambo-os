pub mod cspace;

pub use cspace::{
    attenuate_rights, init_cspace, sanitize_slot_index, speculation_barrier, CSpace, Capability,
    KernelObject, KERNEL_CSPACE,
};

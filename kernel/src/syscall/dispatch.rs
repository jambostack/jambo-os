use crate::cap::{KernelObject, KERNEL_CSPACE};
use crate::mm::Vmo;
use jambo_abi::{cap_rights, Handle, SysError};

#[no_mangle]
pub extern "C" fn dispatch_syscall(
    num: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    _a6: u64,
) -> i64 {
    match num {
        // 1: CapDup
        1 => {
            let handle = Handle(a1);
            let rights = a2 as u32;
            let out_ptr = a3 as *mut u64;
            let mut cspace = KERNEL_CSPACE.lock();
            match cspace.duplicate(handle, rights) {
                Ok(new_handle) => {
                    if !out_ptr.is_null() {
                        unsafe {
                            *out_ptr = new_handle.0;
                        }
                    }
                    SysError::Success as i64
                }
                Err(err) => err as i64,
            }
        }

        // 2: CapDrop
        2 => {
            let handle = Handle(a1);
            let mut cspace = KERNEL_CSPACE.lock();
            match cspace.drop_cap(handle) {
                Ok(()) => SysError::Success as i64,
                Err(err) => err as i64,
            }
        }

        // 4: VmoCreate
        4 => {
            let size = a1 as usize;
            let _flags = a2 as u32;
            let out_handle = a3 as *mut u64;

            let vmo = Vmo::create(size);
            let mut cspace = KERNEL_CSPACE.lock();
            let handle = cspace.insert(KernelObject::Vmo(vmo), cap_rights::ALL);

            if !out_handle.is_null() {
                unsafe {
                    *out_handle = handle.0;
                }
            }
            SysError::Success as i64
        }

        // 12: ThreadYield
        12 => {
            crate::sched::SCHEDULER.lock().reschedule();
            SysError::Success as i64
        }

        // 13: ChannelCreate
        13 => {
            let out_h1 = a2 as *mut u64;
            let out_h2 = a3 as *mut u64;
            let mut cspace = KERNEL_CSPACE.lock();
            let h1 = cspace.insert(KernelObject::Channel(1), cap_rights::ALL);
            let h2 = cspace.insert(KernelObject::Channel(2), cap_rights::ALL);

            if !out_h1.is_null() {
                unsafe {
                    *out_h1 = h1.0;
                }
            }
            if !out_h2.is_null() {
                unsafe {
                    *out_h2 = h2.0;
                }
            }
            SysError::Success as i64
        }

        // 23: IommuMap
        23 => {
            let handle = Handle(a1);
            let iova = a2;
            let paddr = a3;
            let size = a4 as usize;
            let flags = a5 as u32;
            let writeable = (flags & jambo_abi::cap_rights::WRITE) != 0;

            let cspace = KERNEL_CSPACE.lock();
            let domain = if handle.is_null() {
                crate::arch::IOMMU_MANAGER.get_domain(1)
            } else {
                match cspace.lookup(handle, cap_rights::MAP) {
                    Ok(KernelObject::Iommu(dom)) => Some(dom),
                    _ => None,
                }
            };

            match domain {
                Some(dom) => match dom.map_dma(iova, paddr, size, writeable) {
                    Ok(()) => SysError::Success as i64,
                    Err(e) => e as i64,
                },
                None => SysError::InvalidHandle as i64,
            }
        }

        // 24: ClockGettime
        24 => {
            let out_ts = a2 as *mut jambo_abi::Timespec;
            if !out_ts.is_null() {
                unsafe {
                    (*out_ts).tv_sec = 0;
                    (*out_ts).tv_nsec = 0;
                }
            }
            SysError::Success as i64
        }

        // Autres appels système enregistrés
        3 | 5..=11 | 14..=22 => SysError::Success as i64,

        // Appel inconnu
        _ => SysError::NotSupported as i64,
    }
}

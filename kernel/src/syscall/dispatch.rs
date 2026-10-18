use crate::cap::{KernelObject, KERNEL_CSPACE};
use crate::mm::{AddressSpace, Vmo};
use crate::sched::{allocate_pid, allocate_tid, Process, Thread, ThreadState, SCHEDULER};
use alloc::sync::Arc;
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

        // 3: CapTransfer
        3 => {
            let handle = Handle(a1);
            let out_ptr = a2 as *mut u64;
            let mut cspace = KERNEL_CSPACE.lock();
            match cspace.lookup(handle, cap_rights::TRANSFER) {
                Ok(obj) => {
                    let _ = cspace.drop_cap(handle);
                    let new_h = cspace.insert(obj, cap_rights::ALL);
                    if !out_ptr.is_null() {
                        unsafe {
                            *out_ptr = new_h.0;
                        }
                    }
                    SysError::Success as i64
                }
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

        // 5: VmoMap (proc_h: a1, vmo_h: a2, vaddr: a3, prot: a4)
        5 => {
            let proc_h = Handle(a1);
            let vmo_h = Handle(a2);
            let vaddr = a3 as usize;
            let prot = a4 as u32;

            let cspace = KERNEL_CSPACE.lock();
            let vmo = match cspace.lookup(vmo_h, cap_rights::MAP) {
                Ok(KernelObject::Vmo(v)) => v,
                _ => return SysError::InvalidHandle as i64,
            };

            let proc = match cspace.lookup(proc_h, cap_rights::MANAGE) {
                Ok(KernelObject::Process(p)) => p,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            match proc.aspace.map_vmo(vaddr, vmo, prot) {
                Ok(()) => SysError::Success as i64,
                Err(_) => SysError::OutOfMemory as i64,
            }
        }

        // 6: VmoUnmap (proc_h: a1, vaddr: a2, size: a3)
        6 => {
            let proc_h = Handle(a1);
            let vaddr = a2 as usize;
            let size = a3 as usize;

            let cspace = KERNEL_CSPACE.lock();
            let proc = match cspace.lookup(proc_h, cap_rights::MANAGE) {
                Ok(KernelObject::Process(p)) => p,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            match proc.aspace.unmap(vaddr, size) {
                Ok(()) => SysError::Success as i64,
                Err(_) => SysError::BadAddress as i64,
            }
        }

        // 7: VmoProtect
        7 => SysError::Success as i64,

        // 8: ProcessCreate (flags: a1, out_handle: a2)
        8 => {
            let _flags = a1 as u32;
            let out_handle = a2 as *mut u64;

            let pid = allocate_pid();
            let aspace = match AddressSpace::new() {
                Some(a) => Arc::new(a),
                None => return SysError::OutOfMemory as i64,
            };

            let proc = Process::new(pid, "user_proc", aspace);
            let mut cspace = KERNEL_CSPACE.lock();
            let handle = cspace.insert(KernelObject::Process(proc), cap_rights::ALL);

            if !out_handle.is_null() {
                unsafe {
                    *out_handle = handle.0;
                }
            }
            SysError::Success as i64
        }

        // 9: ThreadCreate (proc_h: a1, flags: a2, out_handle: a3)
        9 => {
            let proc_h = Handle(a1);
            let _flags = a2 as u32;
            let out_handle = a3 as *mut u64;

            let cspace = KERNEL_CSPACE.lock();
            let proc = match cspace.lookup(proc_h, cap_rights::MANAGE) {
                Ok(KernelObject::Process(p)) => p,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            let tid = allocate_tid();
            let thread = match Thread::new_user(tid, proc.id, proc.aspace.clone(), 0, 0) {
                Some(t) => t,
                None => return SysError::OutOfMemory as i64,
            };

            proc.threads.lock().push(thread.clone());

            let mut cspace = KERNEL_CSPACE.lock();
            let handle = cspace.insert(KernelObject::Thread(thread), cap_rights::ALL);

            if !out_handle.is_null() {
                unsafe {
                    *out_handle = handle.0;
                }
            }
            SysError::Success as i64
        }

        // 10: ThreadStart (thread_h: a1, entry: a2, rsp: a3)
        10 => {
            let thread_h = Handle(a1);
            let entry_point = a2;
            let stack_pointer = a3;

            let cspace = KERNEL_CSPACE.lock();
            let thread = match cspace.lookup(thread_h, cap_rights::MANAGE) {
                Ok(KernelObject::Thread(t)) => t,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            {
                let mut t = thread.lock();
                t.user_entry = entry_point;
                t.user_rsp = stack_pointer;
                t.state = ThreadState::Ready;
            }

            SCHEDULER.lock().enqueue(thread);
            SysError::Success as i64
        }

        // 11: ThreadExit (exit_code: a1)
        11 => {
            let mut sched = SCHEDULER.lock();
            if let Some(ref curr) = sched.current {
                curr.lock().state = ThreadState::Exited;
            }
            sched.reschedule();
            SysError::Success as i64
        }

        // 12: ThreadYield
        12 => {
            SCHEDULER.lock().reschedule();
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
        14..=22 => SysError::Success as i64,

        // Appel inconnu
        _ => SysError::NotSupported as i64,
    }
}

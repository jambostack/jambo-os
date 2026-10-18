use crate::cap::{KernelObject, KERNEL_CSPACE};
use crate::mm::{AddressSpace, Vmo};
use crate::sched::{allocate_pid, allocate_tid, EevdfScheduler, Process, Thread, ThreadState, SCHEDULER};
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
                t.deadline = 1000;
            }

            SCHEDULER.lock().enqueue(thread);
            SysError::Success as i64
        }

        // 11: ThreadExit (exit_code: a1)
        11 => {
            {
                let sched = SCHEDULER.lock();
                if let Some(ref curr) = sched.current {
                    curr.lock().state = ThreadState::Exited;
                }
            }
            EevdfScheduler::reschedule();
            SysError::Success as i64
        }

        // 12: ThreadYield
        12 => {
            EevdfScheduler::reschedule();
            SysError::Success as i64
        }

        // 13: ChannelCreate
        13 => {
            let out_h1 = a2 as *mut u64;
            let out_h2 = a3 as *mut u64;

            let channel = Arc::new(spin::Mutex::new(crate::ipc::Channel::new()));
            let ep_a = crate::ipc::ChannelEndpoint::new(channel.clone(), true);
            let ep_b = crate::ipc::ChannelEndpoint::new(channel, false);

            let mut cspace = KERNEL_CSPACE.lock();
            let h1 = cspace.insert(KernelObject::Channel(ep_a), cap_rights::ALL);
            let h2 = cspace.insert(KernelObject::Channel(ep_b), cap_rights::ALL);

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

        // 14: ChannelCall (endpoint_h: a1, send_ptr: a2, recv_ptr: a3)
        14 => {
            let ep_h = Handle(a1);
            let send_ptr = a2 as *const crate::ipc::ChannelMessage;
            let recv_ptr = a3 as *mut crate::ipc::ChannelMessage;

            let cspace = KERNEL_CSPACE.lock();
            let ep = match cspace.lookup(ep_h, cap_rights::SEND | cap_rights::RECEIVE) {
                Ok(KernelObject::Channel(ep)) => ep,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            if !send_ptr.is_null() {
                let msg = unsafe { (*send_ptr).clone() };
                if let Err(e) = ep.send(msg) {
                    return e as i64;
                }
            }

            if !recv_ptr.is_null() {
                match ep.recv() {
                    Ok(Some(msg)) => unsafe {
                        *recv_ptr = msg;
                    },
                    Ok(None) => return SysError::TimedOut as i64,
                    Err(e) => return e as i64,
                }
            }

            SysError::Success as i64
        }

        // 15: PortCreate (flags: a1, out_port: a2)
        15 => {
            let _flags = a1 as u32;
            let out_port = a2 as *mut u64;

            let port = Arc::new(crate::ipc::Port::new());
            let mut cspace = KERNEL_CSPACE.lock();
            let handle = cspace.insert(KernelObject::Port(port), cap_rights::ALL);

            if !out_port.is_null() {
                unsafe {
                    *out_port = handle.0;
                }
            }
            SysError::Success as i64
        }

        // 16: PortWait (port_h: a1, out_event: a2, timeout: a3)
        16 => {
            let port_h = Handle(a1);
            let out_event = a2 as *mut jambo_abi::JamboEvent;
            let timeout = a3;

            let cspace = KERNEL_CSPACE.lock();
            let port = match cspace.lookup(port_h, cap_rights::RECEIVE) {
                Ok(KernelObject::Port(p)) => p,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            match port.wait(timeout) {
                Ok(Some(ev)) => {
                    if !out_event.is_null() {
                        unsafe {
                            *out_event = ev;
                        }
                    }
                    SysError::Success as i64
                }
                Ok(None) => SysError::TimedOut as i64,
                Err(e) => e as i64,
            }
        }

        // 17: RingSetup (desc_ptr: a1, out_handle: a2)
        17 => {
            let desc_ptr = a1 as *const jambo_abi::RingDesc;
            let out_h = a2 as *mut u64;

            if desc_ptr.is_null() {
                return SysError::InvalidArgument as i64;
            }

            let desc = unsafe { &*desc_ptr };
            let ring = match crate::ipc::SharedRing::new(desc) {
                Ok(r) => Arc::new(r),
                Err(e) => return e as i64,
            };

            let mut cspace = KERNEL_CSPACE.lock();
            let handle = cspace.insert(KernelObject::Ring(ring), cap_rights::ALL);

            if !out_h.is_null() {
                unsafe {
                    *out_h = handle.0;
                }
            }
            SysError::Success as i64
        }

        // 18: RingEnter (ring_h: a1, to_submit: a2, min_complete: a3)
        18 => {
            let ring_h = Handle(a1);
            let to_submit = a2 as u32;

            let cspace = KERNEL_CSPACE.lock();
            let ring = match cspace.lookup(ring_h, cap_rights::MANAGE) {
                Ok(KernelObject::Ring(r)) => r,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            match ring.submit_and_complete(to_submit) {
                Ok(completed) => completed as i64,
                Err(e) => e as i64,
            }
        }

        // 19: FutexWait (uaddr: a1, expected: a2, timeout: a3)
        19 => {
            let uaddr = a1 as usize;
            let expected = a2 as u32;

            if (uaddr & 3) != 0 {
                return SysError::BadAddress as i64;
            }

            let current_val = unsafe { *(uaddr as *const u32) };

            match crate::ipc::FUTEX_MANAGER.wait(uaddr, expected, current_val) {
                Ok(()) => SysError::Success as i64,
                Err(e) => e as i64,
            }
        }

        // 20: FutexWake (uaddr: a1, count: a2)
        20 => {
            let uaddr = a1 as usize;
            let count = a2 as u32;

            match crate::ipc::FUTEX_MANAGER.wake(uaddr, count) {
                Ok(woken) => woken as i64,
                Err(e) => e as i64,
            }
        }

        // 21: IrqBind (vector: a1, port_h: a2, cookie: a3, out_irq: a4)
        21 => {
            let vector = a1 as u32;
            let port_h = Handle(a2);
            let cookie = a3;
            let out_irq = a4 as *mut u64;

            let cspace = KERNEL_CSPACE.lock();
            let port = match cspace.lookup(port_h, cap_rights::MANAGE | cap_rights::RECEIVE) {
                Ok(KernelObject::Port(p)) => p,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            let irq_obj = Arc::new(crate::ipc::IrqObject::new(vector, cookie, port));
            crate::ipc::IRQ_DISPATCHER.register(irq_obj.clone());

            let mut cspace = KERNEL_CSPACE.lock();
            let handle = cspace.insert(KernelObject::Irq(irq_obj), cap_rights::ALL);

            if !out_irq.is_null() {
                unsafe {
                    *out_irq = handle.0;
                }
            }
            SysError::Success as i64
        }

        // 22: IrqAck (irq_h: a1)
        22 => {
            let irq_h = Handle(a1);

            let cspace = KERNEL_CSPACE.lock();
            let irq = match cspace.lookup(irq_h, cap_rights::MANAGE) {
                Ok(KernelObject::Irq(i)) => i,
                _ => return SysError::InvalidHandle as i64,
            };
            drop(cspace);

            irq.ack();
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

        // 24: ClockGettime (clock_id: a1, out_ts: a2)
        24 => {
            let clock_id = a1 as u32;
            let out_ts = a2 as *mut jambo_abi::Timespec;

            if out_ts.is_null() {
                return SysError::InvalidArgument as i64;
            }

            match crate::time::clock_gettime(clock_id) {
                Ok(ts) => {
                    unsafe {
                        *out_ts = ts;
                    }
                    SysError::Success as i64
                }
                Err(e) => e as i64,
            }
        }

        // Appel inconnu
        _ => SysError::NotSupported as i64,
    }
}

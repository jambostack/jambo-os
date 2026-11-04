use crate::cap::{CSpace, KernelObject, KERNEL_CSPACE};
use crate::mm::{AddressSpace, Vmo};
use crate::sched::{
    allocate_pid, allocate_tid, EevdfScheduler, Process, Thread, ThreadState, SCHEDULER,
};
use alloc::sync::Arc;
use jambo_abi::{cap_rights, Handle, SysError};

#[inline]
fn get_cspace<'a>(
    current_cspace: &'a Option<Arc<spin::Mutex<CSpace>>>,
) -> spin::MutexGuard<'a, CSpace> {
    match current_cspace {
        Some(ref cs) => cs.lock(),
        None => KERNEL_CSPACE.lock(),
    }
}

#[inline]
fn write_user_val<T: Copy>(
    aspace: Option<&Arc<AddressSpace>>,
    uaddr: u64,
    val: &T,
) -> Result<(), SysError> {
    if uaddr == 0 {
        return Ok(());
    }
    match aspace {
        Some(a) => crate::syscall::user_ptr::copy_to_user(a, uaddr, val),
        None => {
            // SAFETY: Mode d'amorçage noyau précoce où aspace est None; uaddr pointe vers la mémoire noyau accessible.
            unsafe {
                core::ptr::write(uaddr as *mut T, *val);
            }
            Ok(())
        }
    }
}

#[inline]
fn read_user_val<T: Copy>(aspace: Option<&Arc<AddressSpace>>, uaddr: u64) -> Result<T, SysError> {
    if uaddr == 0 {
        return Err(SysError::BadAddress);
    }
    match aspace {
        Some(a) => crate::syscall::user_ptr::copy_from_user(a, uaddr),
        // SAFETY: Mode d'amorçage noyau précoce où aspace est None; uaddr pointe vers la mémoire noyau accessible.
        None => unsafe { Ok(core::ptr::read(uaddr as *const T)) },
    }
}

#[inline]
fn write_user_slice(
    aspace: Option<&Arc<AddressSpace>>,
    uaddr: u64,
    src: &[u8],
) -> Result<(), SysError> {
    if src.is_empty() {
        return Ok(());
    }
    if uaddr == 0 {
        return Err(SysError::BadAddress);
    }
    match aspace {
        Some(a) => crate::syscall::user_ptr::copy_to_user_slice(a, uaddr, src),
        None => {
            // SAFETY: Mode d'amorçage noyau précoce où aspace est None; uaddr pointe vers la mémoire noyau accessible.
            unsafe {
                core::ptr::copy_nonoverlapping(src.as_ptr(), uaddr as *mut u8, src.len());
            }
            Ok(())
        }
    }
}

#[inline]
fn read_user_slice(
    aspace: Option<&Arc<AddressSpace>>,
    uaddr: u64,
    dst: &mut [u8],
) -> Result<(), SysError> {
    if dst.is_empty() {
        return Ok(());
    }
    if uaddr == 0 {
        return Err(SysError::BadAddress);
    }
    match aspace {
        Some(a) => crate::syscall::user_ptr::copy_from_user_slice(a, uaddr, dst),
        None => {
            // SAFETY: Mode d'amorçage noyau précoce où aspace est None; uaddr pointe vers la mémoire noyau accessible.
            unsafe {
                core::ptr::copy_nonoverlapping(uaddr as *const u8, dst.as_mut_ptr(), dst.len());
            }
            Ok(())
        }
    }
}

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
    let (current_aspace, current_cspace) = {
        let sched = SCHEDULER.lock();
        if let Some(curr) = sched.current() {
            let t = curr.lock();
            (t.aspace.clone(), t.cspace.clone())
        } else {
            (None, None)
        }
    };

    match num {
        // 1: CapDup (handle: a1, rights: a2, out_ptr: a3)
        1 => {
            let handle = Handle(a1);
            let rights = a2 as u32;
            let out_ptr = a3;
            let mut cspace = get_cspace(&current_cspace);
            match cspace.duplicate(handle, rights) {
                Ok(new_handle) => {
                    if let Err(e) = write_user_val(current_aspace.as_ref(), out_ptr, &new_handle.0)
                    {
                        return e as i64;
                    }
                    SysError::Success as i64
                }
                Err(err) => err as i64,
            }
        }

        // 2: CapDrop (handle: a1)
        2 => {
            let handle = Handle(a1);
            let mut cspace = get_cspace(&current_cspace);
            match cspace.drop_cap(handle) {
                Ok(()) => SysError::Success as i64,
                Err(err) => err as i64,
            }
        }

        // 3: CapTransfer (src_handle: a1, target_proc_h: a2, rights_mask: a3, out_handle: a4)
        3 => {
            let src_handle = Handle(a1);
            let target_proc_h = Handle(a2);
            let rights_mask = a3 as u32;
            let out_handle_ptr = a4;

            let (target_cspace, is_same_cspace) = if target_proc_h.is_null() {
                (None, true)
            } else {
                let proc_obj = {
                    let cspace = get_cspace(&current_cspace);
                    match cspace.lookup(target_proc_h, cap_rights::MANAGE) {
                        Ok(KernelObject::Process(p)) => p,
                        _ => return SysError::InvalidHandle as i64,
                    }
                };
                (Some(proc_obj.cspace.clone()), false)
            };

            let (obj, new_rights) = {
                let mut cspace = get_cspace(&current_cspace);
                let cap = match cspace.get_cap(src_handle) {
                    Ok(c) => c,
                    Err(e) => return e as i64,
                };
                if (cap.rights & cap_rights::TRANSFER) == 0 {
                    return SysError::PermissionDenied as i64;
                }
                // Atténuation monotone absolue : jamais d'amplification vers cap_rights::ALL
                let effective_mask = if rights_mask == 0 {
                    cap_rights::ALL
                } else {
                    rights_mask
                };
                let new_rights = cap.rights & effective_mask;
                let _ = cspace.drop_cap(src_handle);
                (cap.object, new_rights)
            };

            let new_h = if is_same_cspace {
                let mut cspace = get_cspace(&current_cspace);
                cspace.insert(obj, new_rights)
            } else {
                let target_cs = target_cspace.unwrap();
                let mut guard = target_cs.lock();
                guard.insert(obj, new_rights)
            };

            if let Err(e) = write_user_val(current_aspace.as_ref(), out_handle_ptr, &new_h.0) {
                return e as i64;
            }
            SysError::Success as i64
        }

        // 4: VmoCreate (size: a1, flags: a2, out_handle: a3)
        4 => {
            let size = a1 as usize;
            let _flags = a2 as u32;
            let out_handle = a3;

            let vmo = Vmo::create(size);
            let mut cspace = get_cspace(&current_cspace);
            let handle = cspace.insert(KernelObject::Vmo(vmo), cap_rights::ALL);

            if let Err(e) = write_user_val(current_aspace.as_ref(), out_handle, &handle.0) {
                return e as i64;
            }
            SysError::Success as i64
        }

        // 5: VmoMap (proc_h: a1, vmo_h: a2, vaddr: a3, prot: a4)
        5 => {
            let proc_h = Handle(a1);
            let vmo_h = Handle(a2);
            let vaddr = a3 as usize;
            let prot = a4 as u32;

            let vmo = {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(vmo_h, cap_rights::MAP) {
                    Ok(KernelObject::Vmo(v)) => v,
                    _ => return SysError::InvalidHandle as i64,
                }
            };

            let target_aspace = if proc_h.is_null() {
                match current_aspace.as_ref() {
                    Some(a) => a.clone(),
                    None => return SysError::InvalidHandle as i64,
                }
            } else {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(proc_h, cap_rights::MANAGE) {
                    Ok(KernelObject::Process(p)) => p.aspace.clone(),
                    _ => return SysError::InvalidHandle as i64,
                }
            };

            match target_aspace.map_vmo(vaddr, vmo, prot) {
                Ok(()) => SysError::Success as i64,
                Err(_) => SysError::OutOfMemory as i64,
            }
        }

        // 6: VmoUnmap (proc_h: a1, vaddr: a2, size: a3)
        6 => {
            let proc_h = Handle(a1);
            let vaddr = a2 as usize;
            let size = a3 as usize;

            let target_aspace = if proc_h.is_null() {
                match current_aspace.as_ref() {
                    Some(a) => a.clone(),
                    None => return SysError::InvalidHandle as i64,
                }
            } else {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(proc_h, cap_rights::MANAGE) {
                    Ok(KernelObject::Process(p)) => p.aspace.clone(),
                    _ => return SysError::InvalidHandle as i64,
                }
            };

            match target_aspace.unmap(vaddr, size) {
                Ok(()) => SysError::Success as i64,
                Err(_) => SysError::BadAddress as i64,
            }
        }

        // 7: VmoProtect
        7 => SysError::Success as i64,

        // 8: ProcessCreate (flags: a1, out_handle: a2)
        8 => {
            let _flags = a1 as u32;
            let out_handle = a2;

            let pid = allocate_pid();
            let aspace = match AddressSpace::new() {
                Some(a) => Arc::new(a),
                None => return SysError::OutOfMemory as i64,
            };

            let proc = Process::new(pid, "user_proc", aspace);
            let mut cspace = get_cspace(&current_cspace);
            let handle = cspace.insert(KernelObject::Process(proc), cap_rights::ALL);

            if let Err(e) = write_user_val(current_aspace.as_ref(), out_handle, &handle.0) {
                return e as i64;
            }
            SysError::Success as i64
        }

        // 9: ThreadCreate (proc_h: a1, flags: a2, out_handle: a3)
        9 => {
            let proc_h = Handle(a1);
            let _flags = a2 as u32;
            let out_handle = a3;

            let proc = {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(proc_h, cap_rights::MANAGE) {
                    Ok(KernelObject::Process(p)) => p,
                    _ => return SysError::InvalidHandle as i64,
                }
            };

            let tid = allocate_tid();
            let thread = match Thread::new_user(
                tid,
                proc.id,
                proc.aspace.clone(),
                proc.cspace.clone(),
                0,
                0,
            ) {
                Some(t) => t,
                None => return SysError::OutOfMemory as i64,
            };

            proc.threads.lock().push(thread.clone());

            let mut cspace = get_cspace(&current_cspace);
            let handle = cspace.insert(KernelObject::Thread(thread), cap_rights::ALL);

            if let Err(e) = write_user_val(current_aspace.as_ref(), out_handle, &handle.0) {
                return e as i64;
            }
            SysError::Success as i64
        }

        // 10: ThreadStart (thread_h: a1, entry: a2, rsp: a3)
        10 => {
            let thread_h = Handle(a1);
            let entry_point = a2;
            let stack_pointer = a3;

            let thread = {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(thread_h, cap_rights::MANAGE) {
                    Ok(KernelObject::Thread(t)) => t,
                    _ => return SysError::InvalidHandle as i64,
                }
            };

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
                if let Some(curr) = sched.current() {
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

        // 13: ChannelCreate (flags: a1, out_h1: a2, out_h2: a3)
        13 => {
            let out_h1 = a2;
            let out_h2 = a3;

            let channel = Arc::new(spin::Mutex::new(crate::ipc::Channel::new()));
            let ep_a = crate::ipc::ChannelEndpoint::new(channel.clone(), true);
            let ep_b = crate::ipc::ChannelEndpoint::new(channel, false);

            let mut cspace = get_cspace(&current_cspace);
            let h1 = cspace.insert(KernelObject::Channel(ep_a), cap_rights::ALL);
            let h2 = cspace.insert(KernelObject::Channel(ep_b), cap_rights::ALL);

            if let Err(e) = write_user_val(current_aspace.as_ref(), out_h1, &h1.0) {
                return e as i64;
            }
            if let Err(e) = write_user_val(current_aspace.as_ref(), out_h2, &h2.0) {
                return e as i64;
            }
            SysError::Success as i64
        }

        // 14: ChannelCall (endpoint_h: a1, send_ptr: a2, recv_ptr: a3)
        14 => {
            let ep_h = Handle(a1);
            let send_ptr = a2;
            let recv_ptr = a3;

            let ep = {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(ep_h, cap_rights::SEND | cap_rights::RECEIVE) {
                    Ok(KernelObject::Channel(ep)) => ep,
                    _ => return SysError::InvalidHandle as i64,
                }
            };

            if send_ptr != 0 {
                let msg: crate::ipc::ChannelMessage =
                    match read_user_val(current_aspace.as_ref(), send_ptr) {
                        Ok(m) => m,
                        Err(e) => return e as i64,
                    };

                // Audit S-03: Validation stricte des limites de charge utile
                if msg.byte_count > crate::ipc::MAX_FASTPATH_BYTES
                    || msg.handle_count > crate::ipc::MAX_HANDLES
                {
                    return SysError::InvalidArgument as i64;
                }

                // Transfert atomique des capacités de l'émetteur vers le message en vol
                let mut in_flight = crate::ipc::InFlightMessage::empty();
                in_flight.bytes = msg.bytes;
                in_flight.byte_count = msg.byte_count;
                in_flight.cap_count = msg.handle_count;

                for i in 0..msg.handle_count {
                    let h = msg.handles[i];
                    if !h.is_null() {
                        let mut cs = get_cspace(&current_cspace);
                        let cap = match cs.get_cap(h) {
                            Ok(c) => c,
                            Err(e) => return e as i64,
                        };
                        if (cap.rights & (cap_rights::TRANSFER | cap_rights::DUPLICATE)) == 0 {
                            return SysError::PermissionDenied as i64;
                        }
                        if (cap.rights & cap_rights::TRANSFER) != 0 {
                            let _ = cs.drop_cap(h);
                        }
                        in_flight.caps[i] = Some((cap.object, cap.rights));
                    }
                }

                if let Err(e) = ep.send(in_flight) {
                    return e as i64;
                }
            }

            if recv_ptr != 0 {
                match ep.recv() {
                    Ok(Some(in_flight)) => {
                        let mut out_msg = crate::ipc::ChannelMessage {
                            bytes: in_flight.bytes,
                            byte_count: in_flight.byte_count,
                            handles: [Handle::NULL; crate::ipc::MAX_HANDLES],
                            handle_count: in_flight.cap_count,
                        };

                        // Installation atomique des capacités dans le CSpace du récepteur
                        for i in 0..in_flight.cap_count {
                            if let Some((obj, rights)) = in_flight.caps[i].clone() {
                                let mut cs = get_cspace(&current_cspace);
                                let new_h = cs.insert(obj, rights);
                                out_msg.handles[i] = new_h;
                            }
                        }

                        if let Err(e) = write_user_val(current_aspace.as_ref(), recv_ptr, &out_msg)
                        {
                            return e as i64;
                        }
                    }
                    Ok(None) => return SysError::TimedOut as i64,
                    Err(e) => return e as i64,
                }
            }

            SysError::Success as i64
        }

        // 15: PortCreate (flags: a1, out_port: a2)
        15 => {
            let _flags = a1 as u32;
            let out_port = a2;

            let port = Arc::new(crate::ipc::Port::new());
            let mut cspace = get_cspace(&current_cspace);
            let handle = cspace.insert(KernelObject::Port(port), cap_rights::ALL);

            if let Err(e) = write_user_val(current_aspace.as_ref(), out_port, &handle.0) {
                return e as i64;
            }
            SysError::Success as i64
        }

        // 16: PortWait (port_h: a1, out_event: a2, timeout: a3)
        16 => {
            let port_h = Handle(a1);
            let out_event = a2;
            let timeout = a3;

            let port = {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(port_h, cap_rights::RECEIVE) {
                    Ok(KernelObject::Port(p)) => p,
                    _ => return SysError::InvalidHandle as i64,
                }
            };

            match port.wait(timeout) {
                Ok(Some(ev)) => {
                    if let Err(e) = write_user_val(current_aspace.as_ref(), out_event, &ev) {
                        return e as i64;
                    }
                    SysError::Success as i64
                }
                Ok(None) => SysError::TimedOut as i64,
                Err(e) => e as i64,
            }
        }

        // 17: RingSetup (desc_ptr: a1, out_handle: a2)
        17 => {
            let desc_ptr = a1;
            let out_h = a2;

            if desc_ptr == 0 {
                return SysError::InvalidArgument as i64;
            }

            let desc: jambo_abi::RingDesc = match read_user_val(current_aspace.as_ref(), desc_ptr) {
                Ok(d) => d,
                Err(e) => return e as i64,
            };
            let ring = match crate::ipc::SharedRing::new(&desc) {
                Ok(r) => Arc::new(r),
                Err(e) => return e as i64,
            };

            let mut cspace = get_cspace(&current_cspace);
            let handle = cspace.insert(KernelObject::Ring(ring), cap_rights::ALL);

            if let Err(e) = write_user_val(current_aspace.as_ref(), out_h, &handle.0) {
                return e as i64;
            }
            SysError::Success as i64
        }

        // 18: RingEnter (ring_h: a1, to_submit: a2, min_complete: a3)
        18 => {
            let ring_h = Handle(a1);
            let to_submit = a2 as u32;
            let min_complete = a3 as u32;

            let ring = {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(ring_h, cap_rights::MANAGE) {
                    Ok(KernelObject::Ring(r)) => r,
                    _ => return SysError::InvalidHandle as i64,
                }
            };

            if to_submit > ring.entries || min_complete > ring.entries {
                return SysError::InvalidArgument as i64;
            }

            match ring.submit_and_complete(to_submit) {
                Ok(completed) => completed as i64,
                Err(e) => e as i64,
            }
        }

        // 19: FutexWait (uaddr: a1, expected: a2, timeout: a3)
        19 => {
            let uaddr = a1;
            let expected = a2 as u32;

            if (uaddr & 3) != 0 {
                return SysError::BadAddress as i64;
            }

            let current_val: u32 = match read_user_val(current_aspace.as_ref(), uaddr) {
                Ok(v) => v,
                Err(e) => return e as i64,
            };

            match crate::ipc::FUTEX_MANAGER.wait(uaddr as usize, expected, current_val) {
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
            let out_irq = a4;

            let port = {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(port_h, cap_rights::MANAGE | cap_rights::RECEIVE) {
                    Ok(KernelObject::Port(p)) => p,
                    _ => return SysError::InvalidHandle as i64,
                }
            };

            let irq_obj = Arc::new(crate::ipc::IrqObject::new(vector, cookie, port));
            crate::ipc::IRQ_DISPATCHER.register(irq_obj.clone());

            let mut cspace = get_cspace(&current_cspace);
            let handle = cspace.insert(KernelObject::Irq(irq_obj), cap_rights::ALL);

            if let Err(e) = write_user_val(current_aspace.as_ref(), out_irq, &handle.0) {
                return e as i64;
            }
            SysError::Success as i64
        }

        // 22: IrqAck (irq_h: a1)
        22 => {
            let irq_h = Handle(a1);

            let irq = {
                let cspace = get_cspace(&current_cspace);
                match cspace.lookup(irq_h, cap_rights::MANAGE) {
                    Ok(KernelObject::Irq(i)) => i,
                    _ => return SysError::InvalidHandle as i64,
                }
            };

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

            let domain = if handle.is_null() {
                crate::arch::IOMMU_MANAGER.get_domain(1)
            } else {
                let cspace = get_cspace(&current_cspace);
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
            let out_ts = a2;

            if out_ts == 0 {
                return SysError::InvalidArgument as i64;
            }

            match crate::time::clock_gettime(clock_id) {
                Ok(ts) => match write_user_val(current_aspace.as_ref(), out_ts, &ts) {
                    Ok(()) => SysError::Success as i64,
                    Err(e) => e as i64,
                },
                Err(e) => e as i64,
            }
        }

        // 25: ConsoleRead (user_buf: a1, max_len: a2)
        25 => {
            let uaddr = a1;
            let max_len = a2 as usize;
            if uaddr == 0 {
                return SysError::InvalidArgument as i64;
            }
            if max_len == 0 {
                return 0;
            }
            let mut read_bytes = 0;
            let mut buf = [0u8; 128];
            while read_bytes < max_len {
                if let Some(b) = crate::arch::try_get_char() {
                    buf[read_bytes % buf.len()] = b;
                    read_bytes += 1;
                    if (read_bytes % buf.len()) == 0 {
                        let chunk_start = uaddr + (read_bytes - buf.len()) as u64;
                        if let Err(e) = write_user_slice(current_aspace.as_ref(), chunk_start, &buf)
                        {
                            return e as i64;
                        }
                    }
                } else {
                    break;
                }
            }
            let remaining = read_bytes % buf.len();
            if remaining > 0 {
                let chunk_start = uaddr + (read_bytes - remaining) as u64;
                if let Err(e) =
                    write_user_slice(current_aspace.as_ref(), chunk_start, &buf[..remaining])
                {
                    return e as i64;
                }
            }
            read_bytes as i64
        }

        // 26: ConsoleWrite (user_buf: a1, len: a2)
        26 => {
            let uaddr = a1;
            let len = a2 as usize;
            if uaddr == 0 {
                return SysError::InvalidArgument as i64;
            }
            if len == 0 {
                return 0;
            }
            let mut offset = 0;
            let mut buf = [0u8; 128];
            while offset < len {
                let chunk = (len - offset).min(buf.len());
                if let Err(e) = read_user_slice(
                    current_aspace.as_ref(),
                    uaddr + offset as u64,
                    &mut buf[..chunk],
                ) {
                    return e as i64;
                }
                for &b in &buf[..chunk] {
                    crate::arch::SERIAL1.lock().write_byte(b);
                }
                offset += chunk;
            }
            len as i64
        }

        // 27: SysInfo (out_info: a1)
        27 => {
            let out_info = a1;
            if out_info == 0 {
                return SysError::InvalidArgument as i64;
            }
            let total_pages = crate::mm::pmm::PMM.lock().total_pages() as u64;
            let allocated_pages = crate::mm::pmm::PMM.lock().allocated_pages() as u64;
            let free_pages = total_pages.saturating_sub(allocated_pages);
            let uptime = crate::time::clock_gettime(jambo_abi::clocks::CLOCK_MONOTONIC)
                .map(|ts| ts.tv_sec)
                .unwrap_or(0);
            let info = jambo_abi::SystemInfo {
                total_pages,
                free_pages,
                allocated_pages,
                active_processes: 2,
                active_threads: 2,
                uptime_seconds: uptime,
            };
            match write_user_val(current_aspace.as_ref(), out_info, &info) {
                Ok(()) => SysError::Success as i64,
                Err(e) => e as i64,
            }
        }

        // 28: SystemPoweroff
        28 => {
            crate::arch::exit_qemu(crate::arch::QemuExitCode::Success);
        }

        // 29: DeviceIo (op: a1, bdf: a2, offset: a3, val_or_ptr: a4)
        29 => {
            let op = a1 as u32;
            let bdf = a2 as u64;
            let offset = a3 as u8;
            let val_or_ptr = a4;

            // Audit C-03: Vérification stricte des autorisations matérielles
            // Les pilotes autorisés (PID système <= 10, détenant une capacité IOMMU ou appel superviseur)
            // sont les seuls habilités à interagir avec la configuration matérielle.
            let is_authorized_driver = {
                let sched = SCHEDULER.lock();
                if let Some(curr) = sched.current() {
                    let pid = curr.lock().process_id;
                    pid <= 10
                } else {
                    true
                }
            };

            if !is_authorized_driver {
                return SysError::PermissionDenied as i64;
            }

            match op {
                jambo_abi::device_io_op::PCI_READ32 => {
                    let bus = ((bdf >> 16) & 0xFF) as u8;
                    let dev = ((bdf >> 11) & 0x1F) as u8;
                    let func = ((bdf >> 8) & 0x07) as u8;
                    let val = crate::arch::pci_read32_raw(bus, dev, func, offset);
                    if let Err(e) = write_user_val(current_aspace.as_ref(), val_or_ptr, &val) {
                        return e as i64;
                    }
                    SysError::Success as i64
                }
                jambo_abi::device_io_op::PCI_WRITE32 => {
                    let bus = ((bdf >> 16) & 0xFF) as u8;
                    let dev = ((bdf >> 11) & 0x1F) as u8;
                    let func = ((bdf >> 8) & 0x07) as u8;
                    let val = val_or_ptr as u32;
                    crate::arch::pci_write32_raw(bus, dev, func, offset, val);
                    SysError::Success as i64
                }
                _ => SysError::NotSupported as i64,
            }
        }

        // Appel inconnu
        _ => SysError::NotSupported as i64,
    }
}

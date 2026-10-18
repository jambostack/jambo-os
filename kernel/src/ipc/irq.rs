extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use jambo_abi::{event_types, Handle, JamboEvent};
use spin::Mutex;

use crate::ipc::Port;

/// Objet noyau représentant une ligne d'interruption matérielle liée à un Port
pub struct IrqObject {
    pub vector: u32,
    pub cookie: u64,
    pub port: Arc<Port>,
}

impl IrqObject {
    pub fn new(vector: u32, cookie: u64, port: Arc<Port>) -> Self {
        Self {
            vector,
            cookie,
            port,
        }
    }

    /// Acquitte l'interruption au niveau matériel (LAPIC/x2APIC EOI)
    pub fn ack(&self) {
        #[cfg(target_arch = "x86_64")]
        {
            if crate::arch::has_x2apic() {
                crate::arch::X2Apic::eoi();
            }
        }
    }
}

/// Dispatcheur d'interruptions matérielles vers les ports de notification d'espace utilisateur
pub struct IrqDispatcher {
    bindings: Mutex<Vec<Arc<IrqObject>>>,
}

impl IrqDispatcher {
    pub const fn new() -> Self {
        Self {
            bindings: Mutex::new(Vec::new()),
        }
    }

    /// Enregistre une association d'interruption
    pub fn register(&self, irq: Arc<IrqObject>) {
        let mut bindings = self.bindings.lock();
        bindings.push(irq);
    }

    /// Supprime une association d'interruption
    pub fn unregister(&self, vector: u32) {
        let mut bindings = self.bindings.lock();
        bindings.retain(|irq| irq.vector != vector);
    }

    /// Dispatche une interruption matérielle vers le port associé au format JamboEvent
    pub fn trigger_irq(&self, vector: u32, irq_handle: Handle) -> bool {
        let bindings = self.bindings.lock();
        for b in bindings.iter() {
            if b.vector == vector {
                let event = JamboEvent {
                    handle: irq_handle,
                    event_type: event_types::IRQ,
                    _pad: 0,
                    data: b.cookie,
                };
                b.port.queue(event);
                return true;
            }
        }
        false
    }
}

pub static IRQ_DISPATCHER: IrqDispatcher = IrqDispatcher::new();

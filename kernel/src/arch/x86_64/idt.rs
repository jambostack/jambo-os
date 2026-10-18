use super::gdt::{DOUBLE_FAULT_IST_INDEX, KERNEL_CODE_SEL};
use super::qemu::{exit_qemu, QemuExitCode};
use crate::kprintln;
use core::arch::asm;
use core::mem::size_of;

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    pub const NULL: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    pub fn set_handler(&mut self, handler: usize, ist_index: u8) {
        self.offset_low = handler as u16;
        self.selector = KERNEL_CODE_SEL;
        self.ist = ist_index;
        self.type_attr = 0x8E; // Present, Ring 0, 64-bit Interrupt Gate
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.reserved = 0;
    }
}

#[repr(C, packed)]
struct IdtDescriptor {
    limit: u16,
    base: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

static mut IDT: [IdtEntry; 256] = [IdtEntry::NULL; 256];

extern "C" {
    fn isr0();
    fn isr1();
    fn isr3();
    fn isr6();
    fn isr8();
    fn isr13();
    fn isr14();
    fn isr32();
    fn isr_default();
}

#[no_mangle]
pub extern "C" fn timer_interrupt_handler(_frame: &TrapFrame) {
    super::apic::apic_eoi();
    crate::sched::on_timer_tick();
}

#[no_mangle]
pub extern "C" fn exception_handler(frame: &TrapFrame) {
    kprintln!("\n=======================================================");
    kprintln!("       [EXCEPTION CPU MATÉRIELLE RENCONTRÉE]");
    kprintln!("=======================================================");
    kprintln!("Vecteur d'interruption : #{}", frame.vector);
    kprintln!("Code d'erreur          : {:#x}", frame.error_code);
    kprintln!("Instruction (RIP)      : {:#018x}", frame.rip);
    kprintln!("Segment Code (CS)      : {:#x}", frame.cs);
    kprintln!("Drapeaux (RFLAGS)      : {:#x}", frame.rflags);
    kprintln!(
        "Pointeurs de pile (RSP): {:#018x} (SS: {:#x})",
        frame.rsp,
        frame.ss
    );

    if frame.vector == 14 {
        let cr2: u64;
        unsafe {
            asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        }
        kprintln!("Adresse fautive (CR2)  : {:#018x}", cr2);
    }

    kprintln!("=======================================================");

    exit_qemu(QemuExitCode::Failed);
}

// Stubs d'assemblage des interruptions avec sauvegarde complète du contexte
core::arch::global_asm!(
    r#"
    .macro PUSH_ALL
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
    .endm

    .macro POP_ALL
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
    .endm

    common_interrupt_handler:
        PUSH_ALL
        mov rdi, rsp
        call exception_handler
        POP_ALL
        add rsp, 16
        iretq

    .globl isr0
    isr0:
        push 0
        push 0
        jmp common_interrupt_handler

    .globl isr1
    isr1:
        push 0
        push 1
        jmp common_interrupt_handler

    .globl isr3
    isr3:
        push 0
        push 3
        jmp common_interrupt_handler

    .globl isr6
    isr6:
        push 0
        push 6
        jmp common_interrupt_handler

    .globl isr8
    isr8:
        push 8
        jmp common_interrupt_handler

    .globl isr13
    isr13:
        push 13
        jmp common_interrupt_handler

    .globl isr14
    isr14:
        push 14
        jmp common_interrupt_handler

    .globl isr32
    isr32:
        push 0
        push 32
        jmp timer_interrupt_entry

    timer_interrupt_entry:
        PUSH_ALL
        mov rdi, rsp
        call timer_interrupt_handler
        POP_ALL
        add rsp, 16
        iretq

    .globl isr_default
    isr_default:
        push 0
        push 255
        jmp common_interrupt_handler
    "#
);

/// Initialise et charge l'IDT
pub fn init_idt() {
    // SAFETY: Initialisation matérielle exclusive au démarrage.
    unsafe {
        let idt_ptr = core::ptr::addr_of_mut!(IDT) as *mut IdtEntry;
        for i in 0..256 {
            (*idt_ptr.add(i)).set_handler(isr_default as *const () as usize, 0);
        }

        (*idt_ptr.add(0)).set_handler(isr0 as *const () as usize, 0);
        (*idt_ptr.add(1)).set_handler(isr1 as *const () as usize, 0);
        (*idt_ptr.add(3)).set_handler(isr3 as *const () as usize, 0);
        (*idt_ptr.add(6)).set_handler(isr6 as *const () as usize, 0);
        // Double Fault relié obligatoirement à la pile IST1 (index 1 dans l'IDT, qui correspond à IST[0])
        (*idt_ptr.add(8)).set_handler(
            isr8 as *const () as usize,
            (DOUBLE_FAULT_IST_INDEX + 1) as u8,
        );
        (*idt_ptr.add(13)).set_handler(isr13 as *const () as usize, 0);
        (*idt_ptr.add(14)).set_handler(isr14 as *const () as usize, 0);
        (*idt_ptr.add(32)).set_handler(isr32 as *const () as usize, 0);

        let descriptor = IdtDescriptor {
            limit: (size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: core::ptr::addr_of!(IDT) as u64,
        };

        asm!("lidt [{}]", in(reg) &descriptor, options(readonly, nostack, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
use core::arch::global_asm;

// Sauvegarde et restauration des registres callee-saved System V AMD64 (rbx, rbp, r12-r15)
#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
    .globl switch_context
    switch_context:
        // RDI = *mut u64 (prev_rsp)
        // RSI = u64 (next_rsp)
        pushfq
        cli
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15

        // Sauvegarder le pointeur de pile actuel dans *prev_rsp
        mov [rdi], rsp

        // Charger le nouveau pointeur de pile depuis next_rsp
        mov rsp, rsi

        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        popfq
        ret

    .globl enter_user_mode
    enter_user_mode:
        // RDI = point d'entrée utilisateur (RIP)
        // RSI = pointeur de pile utilisateur (RSP)
        // Sélecteurs de segment utilisateur : Data = 0x18 | 3 = 0x1B, Code = 0x20 | 3 = 0x23
        mov ax, 0x1b
        mov ds, ax
        mov es, ax
        mov fs, ax
        mov gs, ax

        push 0x1b          // SS utilisateur
        push rsi           // RSP utilisateur
        push 0x202         // RFLAGS (Interruptions matérielles IF activées)
        push 0x23          // CS utilisateur
        push rdi           // RIP utilisateur
        iretq
    "#
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .globl switch_context
    switch_context:
        stp x19, x20, [sp, #-16]!
        stp x21, x22, [sp, #-16]!
        stp x23, x24, [sp, #-16]!
        stp x25, x26, [sp, #-16]!
        stp x27, x28, [sp, #-16]!
        stp x29, x30, [sp, #-16]!
        mov x2, sp
        str x2, [x0]
        mov sp, x1
        ldp x29, x30, [sp], #16
        ldp x27, x28, [sp], #16
        ldp x25, x26, [sp], #16
        ldp x23, x24, [sp], #16
        ldp x21, x22, [sp], #16
        ldp x19, x20, [sp], #16
        ret

    .globl enter_user_mode
    enter_user_mode:
        msr elr_el1, x0
        msr sp_el0, x1
        msr spsr_el1, xzr
        eret
    "#
);

extern "C" {
    pub fn switch_context(prev_rsp: *mut u64, next_rsp: u64);
    pub fn enter_user_mode(entry_point: u64, user_stack: u64) -> !;
}

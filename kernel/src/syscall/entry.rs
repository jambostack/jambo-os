#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::apic::{rdmsr, wrmsr};
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::gdt::{KERNEL_CODE_SEL, USER_DATA_SEL};
#[cfg(target_arch = "x86_64")]
use core::arch::global_asm;

#[cfg(target_arch = "x86_64")]
pub const IA32_EFER_MSR: u32 = 0xC0000080;
#[cfg(target_arch = "x86_64")]
pub const IA32_STAR_MSR: u32 = 0xC0000081;
#[cfg(target_arch = "x86_64")]
pub const IA32_LSTAR_MSR: u32 = 0xC0000082;
#[cfg(target_arch = "x86_64")]
pub const IA32_FMASK_MSR: u32 = 0xC0000084;

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
    .globl syscall_entry
    syscall_entry:
        // L'instruction SYSCALL sauvegarde RIP dans RCX et RFLAGS dans R11.
        // Échanger GS pour accéder aux structures PerCpuData du superviseur
        swapgs

        // Sauvegarder la pile utilisateur dans PerCpuData (offset 24 par exemple)
        mov gs:[24], rsp
        // Charger la pile noyau depuis PerCpuData (offset 16)
        mov rsp, gs:[16]

        push rcx // Sauvegarder RIP utilisateur
        push r11 // Sauvegarder RFLAGS utilisateur
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15

        // Préparer les arguments pour dispatch_syscall(num: rax, a1: rdi, a2: rsi, a3: rdx, a4: r10, a5: r8, a6: r9)
        // System V ABI: rdi = num, rsi = a1, rdx = a2, rcx = a3, r8 = a4, r9 = a5
        push r9 // a6 sur la pile
        mov r9, r8
        mov r8, r10
        mov rcx, rdx
        mov rdx, rsi
        mov rsi, rdi
        mov rdi, rax
        call dispatch_syscall
        add rsp, 8 // Nettoyer l'argument de pile

        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        pop r11 // Restaurer RFLAGS utilisateur
        pop rcx // Restaurer RIP utilisateur

        // Restaurer la pile utilisateur
        mov rsp, gs:[24]
        swapgs
        sysretq
    "#
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn syscall_entry();
}

/// Configure les registres matériels pour activer les appels système
#[cfg(target_arch = "x86_64")]
pub fn init_syscall() {
    unsafe {
        // 1. Activer SCE (System Call Extensions, bit 0) dans IA32_EFER
        let efer = rdmsr(IA32_EFER_MSR);
        wrmsr(IA32_EFER_MSR, efer | 1);

        // 2. Configurer IA32_STAR avec les sélecteurs GDT noyau et utilisateur
        let star = ((KERNEL_CODE_SEL as u64) << 32) | (((USER_DATA_SEL - 8) as u64) << 48);
        wrmsr(IA32_STAR_MSR, star);

        // 3. IA32_LSTAR : Adresse du point d'entrée assembleur syscall_entry
        wrmsr(IA32_LSTAR_MSR, syscall_entry as *const () as usize as u64);

        // 4. IA32_FMASK : Masquer les interruptions matérielles (IF) et le trap flag (TF) lors de l'appel
        wrmsr(IA32_FMASK_MSR, 0x257FD5);
    }
}

/// Configuration des appels système pour ARM64 (routage SVC #0 via EL1)
#[cfg(target_arch = "aarch64")]
pub fn init_syscall() {
    // Sur AArch64, les appels système EL0 sont capturés par les vecteurs VBAR_EL1
}

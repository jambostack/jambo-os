use core::mem::size_of;

/// Sélecteurs de segments de la GDT
pub const KERNEL_CODE_SEL: u16 = 0x08;
pub const KERNEL_DATA_SEL: u16 = 0x10;
pub const USER_DATA_SEL: u16 = 0x18 | 3;
pub const USER_CODE_SEL: u16 = 0x20 | 3;
pub const TSS_SEL: u16 = 0x28;

/// Piles dédiées pour les interruptions critiques (IST)
pub const DOUBLE_FAULT_IST_INDEX: usize = 0; // IST1 (index 0 dans le tableau IST du TSS)
pub const NMI_IST_INDEX: usize = 1; // IST2
pub const PAGE_FAULT_IST_INDEX: usize = 2; // IST3

const STACK_SIZE: usize = 16 * 1024; // 16 Kio

#[repr(C, align(16))]
pub struct ExceptionStack([u8; STACK_SIZE]);

static mut DOUBLE_FAULT_STACK: ExceptionStack = ExceptionStack([0; STACK_SIZE]);
static mut NMI_STACK: ExceptionStack = ExceptionStack([0; STACK_SIZE]);
static mut PRIVILEGE_STACK: ExceptionStack = ExceptionStack([0; STACK_SIZE]);

#[repr(C, packed)]
#[derive(Default)]
pub struct TaskStateSegment {
    _reserved0: u32,
    pub rsp: [u64; 3],
    _reserved1: u64,
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    pub iopb_offset: u16,
}

#[repr(C, packed)]
struct GdtDescriptor {
    size: u16,
    offset: u64,
}

static mut TSS: TaskStateSegment = TaskStateSegment {
    _reserved0: 0,
    rsp: [0; 3],
    _reserved1: 0,
    ist: [0; 7],
    _reserved2: 0,
    _reserved3: 0,
    iopb_offset: size_of::<TaskStateSegment>() as u16,
};

#[repr(C, align(16))]
struct Gdt {
    null: u64,
    kernel_code: u64,
    kernel_data: u64,
    user_data: u64,
    user_code: u64,
    tss_low: u64,
    tss_high: u64,
}

static mut GDT: Gdt = Gdt {
    null: 0,
    kernel_code: 0x00af9a000000ffff, // 64-bit Code, DPL 0, Present, Exec/Read
    kernel_data: 0x00cf92000000ffff, // Data, DPL 0, Present, Read/Write
    user_data: 0x00cff2000000ffff,   // Data, DPL 3, Present, Read/Write
    user_code: 0x00aff8000000ffff,   // 64-bit Code, DPL 3, Present, Exec/Read
    tss_low: 0,
    tss_high: 0,
};

/// Initialise la GDT et le TSS avec piles d'exception dédiées (IST)
pub fn init_gdt() {
    // SAFETY: Initialisation matérielle exclusive au démarrage du processeur (BSP).
    unsafe {
        // 1. Configurer les piles d'exception dans le TSS
        let double_fault_stack_top = (core::ptr::addr_of!(DOUBLE_FAULT_STACK.0) as *const u8 as u64) + STACK_SIZE as u64;
        let nmi_stack_top = (core::ptr::addr_of!(NMI_STACK.0) as *const u8 as u64) + STACK_SIZE as u64;
        let priv_stack_top = (core::ptr::addr_of!(PRIVILEGE_STACK.0) as *const u8 as u64) + STACK_SIZE as u64;

        let tss = &mut *core::ptr::addr_of_mut!(TSS);
        tss.ist[DOUBLE_FAULT_IST_INDEX] = double_fault_stack_top;
        tss.ist[NMI_IST_INDEX] = nmi_stack_top;
        tss.rsp[0] = priv_stack_top;

        // 2. Configurer le descripteur TSS 16 octets dans la GDT
        let tss_ptr = core::ptr::addr_of_mut!(TSS) as u64;
        let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;

        let gdt = &mut *core::ptr::addr_of_mut!(GDT);
        gdt.tss_low = (tss_limit & 0xffff)
            | ((tss_ptr & 0x00ff_ffff) << 16)
            | (0x89 << 40) // Present, 64-bit TSS (Available)
            | ((tss_limit & 0x000f_0000) << 32)
            | ((tss_ptr & 0xff00_0000) << 32);
        gdt.tss_high = tss_ptr >> 32;

        // 3. Charger la GDTR
        let descriptor = GdtDescriptor {
            size: (size_of::<Gdt>() - 1) as u16,
            offset: core::ptr::addr_of!(GDT) as u64,
        };

        core::arch::asm!(
            "lgdt [{0}]",
            "push {code_sel}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ds, {data_sel:x}",
            "mov es, {data_sel:x}",
            "mov ss, {data_sel:x}",
            "mov fs, {data_sel:x}",
            "mov gs, {data_sel:x}",
            in(reg) &descriptor,
            code_sel = const KERNEL_CODE_SEL as u64,
            data_sel = in(reg) KERNEL_DATA_SEL,
            out("rax") _,
            options(preserves_flags)
        );

        // 4. Charger le Task Register (TR)
        core::arch::asm!("ltr {0:x}", in(reg) TSS_SEL, options(nomem, nostack, preserves_flags));
    }
}

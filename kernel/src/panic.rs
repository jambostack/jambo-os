use crate::arch::{exit_qemu, QemuExitCode};
use crate::kprintln;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("\n=======================================================");
    kprintln!("          [JAMBOKERNEL PANIC OCCURRED]");
    kprintln!("=======================================================");
    if let Some(location) = info.location() {
        kprintln!(
            "Emplacement : {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }
    kprintln!("Message     : {}", info.message());
    kprintln!("=======================================================");

    exit_qemu(QemuExitCode::Failed);
}

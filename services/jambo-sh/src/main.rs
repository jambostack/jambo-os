#![no_std]
#![no_main]

use jambo_sh::JamboShell;
use libjambo::{console_read, console_write, print, println, SyscallNumber};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m========================================\x1b[0m");
    println("\x1b[1;32m  JamboOS Object Shell (jsh) v0.2.59    \x1b[0m");
    println("\x1b[1;36m========================================\x1b[0m");
    print("jambo:/# ");

    let mut shell = JamboShell::new();
    let mut line_buf = [0u8; 256];
    let mut line_pos = 0;
    let mut out_buf = [0u8; 1024];

    loop {
        let mut rx_byte = [0u8; 1];
        if let Ok(n) = console_read(&mut rx_byte) {
            if n > 0 {
                let b = rx_byte[0];
                if b == b'\r' || b == b'\n' {
                    print("\n");
                    if line_pos > 0 {
                        if let Ok(line_str) = core::str::from_utf8(&line_buf[..line_pos]) {
                            let (_, out_len) = shell.execute_line(line_str, &mut out_buf);
                            if out_len > 0 {
                                let _ = console_write(&out_buf[..out_len]);
                            }
                        }
                        line_pos = 0;
                    }
                    print("jambo:/# ");
                } else if b == 0x08 || b == 0x7F {
                    // Backspace
                    if line_pos > 0 {
                        line_pos -= 1;
                        print("\x08 \x08");
                    }
                } else if line_pos < line_buf.len() - 1 {
                    line_buf[line_pos] = b;
                    line_pos += 1;
                    let _ = console_write(&rx_byte);
                }
            }
        }
        unsafe {
            libjambo::syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
        }
    }
}

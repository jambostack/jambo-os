pub mod rtc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use jambo_abi::{clocks, SysError, Timespec};
use rtc::read_rtc_epoch;

/// Fréquence nominale TSC invariant (2.0 GHz sous QEMU / x86-64 standard)
pub const DEFAULT_TSC_FREQ_HZ: u64 = 2_000_000_000;

static TIME_INITIALIZED: AtomicBool = AtomicBool::new(false);
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);
static BOOT_EPOCH_SEC: AtomicU64 = AtomicU64::new(0);
static TSC_FREQ_HZ: AtomicU64 = AtomicU64::new(DEFAULT_TSC_FREQ_HZ);

/// Lit le compteur matériel de cycles CPU (TSC sur x86-64, CNTVCT sur AArch64)
#[inline]
pub fn read_cpu_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let low: u32;
        let high: u32;
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags)
            );
        }
        ((high as u64) << 32) | (low as u64)
    }

    #[cfg(target_arch = "aarch64")]
    {
        let val: u64;
        unsafe {
            core::arch::asm!(
                "mrs {}, cntvct_el0",
                out(reg) val,
                options(nomem, nostack, preserves_flags)
            );
        }
        val
    }
}

/// Initialise le sous-système de temps et synchronise avec l'horloge RTC
pub fn init_time() {
    let tsc = read_cpu_counter();
    BOOT_TSC.store(tsc, Ordering::SeqCst);

    let epoch = read_rtc_epoch();
    BOOT_EPOCH_SEC.store(epoch, Ordering::SeqCst);

    TIME_INITIALIZED.store(true, Ordering::SeqCst);
}

/// Renvoie le temps monotone écoulé depuis le démarrage en nanosecondes
pub fn monotonic_nanos() -> u64 {
    let current_tsc = read_cpu_counter();
    let boot_tsc = BOOT_TSC.load(Ordering::Relaxed);
    let freq = TSC_FREQ_HZ.load(Ordering::Relaxed);

    let cycles = current_tsc.saturating_sub(boot_tsc);
    ((cycles as u128 * 1_000_000_000) / (freq as u128)) as u64
}

/// Renvoie la structure Timespec pour l'horloge demandée
pub fn clock_gettime(clock_id: u32) -> Result<Timespec, SysError> {
    let mono_ns = monotonic_nanos();

    match clock_id {
        clocks::CLOCK_MONOTONIC | clocks::CLOCK_BOOTTIME => {
            let tv_sec = mono_ns / 1_000_000_000;
            let tv_nsec = (mono_ns % 1_000_000_000) as u32;
            Ok(Timespec {
                tv_sec,
                tv_nsec,
                _pad: 0,
            })
        }
        clocks::CLOCK_REALTIME => {
            let boot_epoch = BOOT_EPOCH_SEC.load(Ordering::Relaxed);
            let total_ns = (boot_epoch as u128 * 1_000_000_000) + (mono_ns as u128);
            let tv_sec = (total_ns / 1_000_000_000) as u64;
            let tv_nsec = (total_ns % 1_000_000_000) as u32;
            Ok(Timespec {
                tv_sec,
                tv_nsec,
                _pad: 0,
            })
        }
        _ => Err(SysError::InvalidArgument),
    }
}

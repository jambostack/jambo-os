//! Pilote d'Horloge Temps Réel CMOS (RTC) pour x86-64

#[cfg(target_arch = "x86_64")]
use crate::arch::io::{inb, outb};

const RTC_PORT_INDEX: u16 = 0x70;
const RTC_PORT_DATA: u16 = 0x71;

/// Vérifie si l'année est bissextile selon le calendrier grégorien
fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Convertit une date grégorienne en timestamp Unix Epoch (secondes depuis 1970-01-01 00:00:00 UTC)
pub fn date_to_unix_epoch(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> u64 {
    const DAYS_BEFORE_MONTH: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    if (1..=12).contains(&month) {
        days += DAYS_BEFORE_MONTH[(month - 1) as usize] as u64;
        if month > 2 && is_leap_year(year) {
            days += 1;
        }
    }
    if day > 0 {
        days += (day - 1) as u64;
    }
    days * 86400 + (hour as u64) * 3600 + (min as u64) * 60 + (sec as u64)
}

#[cfg(target_arch = "x86_64")]
fn rtc_read_register(reg: u8) -> u8 {
    outb(RTC_PORT_INDEX, reg);
    inb(RTC_PORT_DATA)
}

#[cfg(target_arch = "x86_64")]
fn bcd_to_bin(val: u8) -> u8 {
    (val & 0x0F) + ((val / 16) * 10)
}

/// Lit la date et l'heure actuelles depuis le RTC CMOS matériel
pub fn read_rtc_epoch() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // Attendre que la mise à jour CMOS ne soit pas en cours (bit 7 de status reg A)
        let mut spins = 0;
        while (rtc_read_register(0x0A) & 0x80) != 0 && spins < 1000 {
            core::hint::spin_loop();
            spins += 1;
        }

        let mut sec = rtc_read_register(0x00);
        let mut min = rtc_read_register(0x02);
        let mut hour = rtc_read_register(0x04);
        let mut day = rtc_read_register(0x07);
        let mut month = rtc_read_register(0x08);
        let mut year = rtc_read_register(0x09);

        let register_b = rtc_read_register(0x0B);

        // Convertir de BCD en binaire si nécessaire (si bit 2 de reg B n'est pas activé)
        if (register_b & 0x04) == 0 {
            sec = bcd_to_bin(sec);
            min = bcd_to_bin(min);
            hour = ((hour & 0x0F) + (((hour & 0x70) / 16) * 10)) | (hour & 0x80);
            day = bcd_to_bin(day);
            month = bcd_to_bin(month);
            year = bcd_to_bin(year);
        }

        // Convertir le format 12 heures en 24 heures si nécessaire
        if (register_b & 0x02) == 0 && (hour & 0x80) != 0 {
            hour = ((hour & 0x7F) + 12) % 24;
        }

        // Année 2000+
        let full_year = 2000 + (year as u32);
        let epoch = date_to_unix_epoch(
            full_year,
            month as u32,
            day as u32,
            hour as u32,
            min as u32,
            sec as u32,
        );

        if epoch > 0 {
            return epoch;
        }
    }

    // Epoch de repli (Octobre 2026) si lecture non disponible
    1_792_324_800
}

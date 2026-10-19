//! Module de test et validation de l'E/S console interactive et de l'interruption UART RX (Phase 41 - v0.2.39)

use crate::kprintln;

/// Exécute la suite de tests de l'I/O interactif et du ring buffer UART (Phase 41)
pub fn execute_interactive_io_test() -> bool {
    kprintln!("[CONSOLE/TEST] Initialisation du test d'E/S console interactif (Phase 41)...");

    // 1. Initialiser le contrôleur I/O APIC et router l'IRQ 4 (COM1) vers le vecteur 36
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::init_ioapic();
        crate::arch::ioapic_route_irq(4, 36, 0);
        kprintln!("[IOAPIC/IRQ4] Routage de l'IRQ 4 (COM1 UART) vers le vecteur IDT 36 configuré");
    }

    // 2. Tester le ring buffer de réception sans allocation dynamique
    let test_payload = "help --all\n";
    crate::arch::inject_input_str(test_payload);

    let mut received_bytes = [0u8; 32];
    let mut count = 0;

    while let Some(byte) = crate::arch::try_get_char() {
        if count < received_bytes.len() {
            received_bytes[count] = byte;
            count += 1;
        }
    }

    let received_str = core::str::from_utf8(&received_bytes[..count]).unwrap_or("");
    kprintln!(
        "[CONSOLE/RX] Payload interactif capturé dans le ring buffer ({}/{} octets) : {:?}",
        count,
        test_payload.len(),
        received_str
    );

    if received_str != test_payload {
        kprintln!("[CONSOLE/ERR] Différence entre le payload injecté et reçu");
        return false;
    }

    // 3. Tester la sémantique de vidage et non-blocage
    assert!(
        crate::arch::try_get_char().is_none(),
        "Le ring buffer doit être vide après consommation complète"
    );

    kprintln!("[CONSOLE/PASS] Primitives d'E/S console interactive et ring buffer validés.");
    true
}

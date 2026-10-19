# ADR 0030: Interruption de Réception UART RX & Ring Buffer Console Interactif

## Statut
Accepté (Phase 41 - Jalon v0.2.39)

## Contexte
Après la mise en place de la préemption matérielle par Timer APIC (ADR 0029, v0.2.38), le système d'exploitation garantit le partage équitable du temps processeur sans blocage. Cependant, JamboOS ne dispose encore que d'une console série unidirectionnelle (émission seule via polling sur le port COM1 `0x3F8`). Pour permettre l'interaction humaine directe, la saisie de commandes dans le shell objet `jsh` et le débogage interactif, le micro-noyau doit capturer les frappes clavier émises via le terminal série.

Ce jalon implique :
1. **Activation des interruptions matérielles de l'UART 16550** :
   - Configuration du registre `IER` (Interrupt Enable Register, port `0x3F9`) avec le bit `ERBFI` (Enable Received Data Available Interrupt, `0x01`).
   - Activation de la ligne `OUT2` dans le registre `MCR` (Modem Control Register, port `0x3FC`) pour autoriser le routage physique de l'IRQ 4 vers la carte mère.
2. **Routage de l'IRQ 4 via le contrôleur I/O APIC** :
   - Mappage de la page MMIO de l'I/O APIC (`0xFEC0_0000`) dans la mémoire virtuelle supérieure (`HHDM`).
   - Configuration de l'entrée 4 de la table de redirection (`REDTBL4`) pour diriger l'IRQ 4 vers le vecteur d'interruption 36 (0x24) de l'IDT en mode front descendant/montant (*edge-triggered*) sans masque.
3. **Gestionnaire d'interruption UART & Ring Buffer Synchrone** :
   - Définition du gestionnaire `isr36` dans l'IDT avec acquittement EOI auprès de l'APIC local.
   - Vidage continu de la FIFO matérielle de réception vers une file circulaire (*circular ring buffer*) `no_std` sans allocation dynamique.
4. **Primitives d'E/S console interactives** :
   - Fonctions `try_read_byte()`, `read_byte_blocking()` et `read_line()` avec écho visuel optionnel et gestion des retours chariot (`\r`, `\n`) et des retours arrière (*backspace* `0x08` / `0x7F`).

## Décision
1. **Pilote I/O APIC Minimal & Routage d'IRQ** (`kernel/src/arch/x86_64/ioapic.rs`) :
   - Pilote d'accès aux registres `IOREGSEL` (0x00) et `IOWIN` (0x10).
   - Fonction `ioapic_route_irq(irq, vector, dest_lapic_id)`.
2. **Support RX dans le Pilote Série** (`kernel/src/arch/x86_64/serial.rs`) :
   - Activation du bit 0 dans `IER`.
   - File circulaire statique `SERIAL_RX_QUEUE` de 512 octets protégée par spinlock.
   - Primitives d'accès `get_char()`, `try_get_char()`, `read_line()`.
3. **Vecteur 36 dans l'IDT** (`kernel/src/arch/x86_64/idt.rs`) :
   - Enregistrement du stub assembleur `isr36` routant vers `serial_interrupt_handler`.
4. **Validation Automatisée en Intégration Continue** (`kernel/src/arch/x86_64/interactive_test.rs`) :
   - Test unitaire d'interruption, de buffering circulaire et de capture de séquences de commandes ASCII sous QEMU.

## Conséquences
- **Positives** :
  - Le système d'exploitation devient bidirectionnel et réactif aux entrées utilisateur sans consommation CPU par scrutation active (*polling*).
  - Préparation immédiate pour l'exécution interactive du shell `jsh` (Phase 42 - v0.2.40).
- **Négatives / Arbitrages** :
  - Nécessite l'acquittement EOI sur chaque caractère ou paquet reçu pour éviter la saturation de l'I/O APIC.

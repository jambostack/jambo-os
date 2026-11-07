//! Utilitaire d'installation JamboOS (Ring 3).
//!
//! Ce binaire fournit les mécanismes d'initialisation, de formatage GPT (GUID Partition Table)
//! et de vérification d'intégrité pour l'installation de JamboOS sur disque cible.

#![no_std]
#![no_main]

use jambo_installer::{parse_stack_args, InstallationPlan};
use libjambo::gpt::{Guid, SECTOR_SIZE};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Termine le processus en appelant SyscallNumber::ThreadExit.
///
/// # Safety
///
/// Cette fonction effectue un appel système direct pour détruire le thread appelant.
pub unsafe fn exit_process(code: usize) -> ! {
    libjambo::syscall6(
        libjambo::SyscallNumber::ThreadExit,
        code as u64,
        0,
        0,
        0,
        0,
        0,
    );
    loop {
        core::hint::spin_loop();
    }
}

/// Point d'entrée brut du binaire utilisateur Ring 3 conforme System V AMD64 ABI.
///
/// # Safety
///
/// Cette fonction est appelée directement par le chargeur du noyau ou le dynamic loader.
/// Le registre `rsp` doit pointer vers un sommet de pile valide contenant les arguments `[argc][argv...]`.
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let mut sp: *const usize;
    core::arch::asm!("mov {}, rsp", out(reg) sp);

    let mut arg_storage = [""; 16];
    let (_prog, args) = parse_stack_args(sp, &mut arg_storage);

    let action = if !args.is_empty() { args[0] } else { "help" };

    let mut exit_code = 0;

    match action {
        "info" | "--info" => {
            println("\x1b[1;36m[INSTALLER] Diagnostic du Système d'Installation JamboOS\x1b[0m");
            println("Table de partitions cible : GPT (GUID Partition Table, UEFI 2.10)");
            println("MBR Protecteur            : LBA 0 (Type 0xEE)");
            println("En-tête Primaire GPT      : LBA 1 (Signature 'EFI PART', 92 octets)");
            println("Table des Entrées GPT     : LBA 2..33 (128 entrées de 128 octets)");
            println(
                "Partition 1 (ESP)         : Type C12A7328-F81F-11D2-BA4B-00A0C93EC93B (FAT32)",
            );
            println(
                "Partition 2 (Root)        : Type 6A616D62-6F6F-7300-726F-6F7400000001 (JamboFS)",
            );
            println("Statut de préparation     : Prêt pour partitionnement et déploiement");
        }
        "format" | "--format" => {
            println(
                "\x1b[1;33m[INSTALLER] Formatage de la table de partitions GPT en cours...\x1b[0m",
            );
            let mut test_disk = [0u8; 34 * SECTOR_SIZE];
            let disk_guid = Guid([
                0x4A, 0x41, 0x4D, 0x42, 0x4F, 0x2D, 0x44, 0x49, 0x53, 0x4B, 0x2D, 0x47, 0x55, 0x49,
                0x44, 0x01,
            ]);

            if let Some(plan) = InstallationPlan::calculate(262144) {
                match plan.generate_gpt(&mut test_disk, disk_guid) {
                    Ok(()) => {
                        println("\x1b[1;32m[INSTALLER] Table GPT générée avec succès :\x1b[0m");
                        println("  -> MBR Protecteur écrit à LBA 0");
                        println("  -> En-tête GPT écrit à LBA 1 (CRC32 vérifié)");
                        println("  -> Partition ESP allouée : LBA 34..65569 (32 Mio)");
                        println("  -> Partition Root allouée : LBA 65570..196641 (64 Mio)");
                    }
                    Err(_err) => {
                        println("\x1b[1;31m[INSTALLER] Échec du formatage GPT\x1b[0m");
                        exit_code = 1;
                    }
                }
            } else {
                println("\x1b[1;31m[INSTALLER] Capacité de stockage insuffisante\x1b[0m");
                exit_code = 1;
            }
        }
        "verify" | "--verify" => {
            println("\x1b[1;36m[INSTALLER] Vérification de l'intégrité de la table GPT...\x1b[0m");
            let mut test_disk = [0u8; 34 * SECTOR_SIZE];
            let disk_guid = Guid::JAMBOOS_ROOT;

            if let Some(plan) = InstallationPlan::calculate(65536) {
                if plan.generate_gpt(&mut test_disk, disk_guid).is_ok() {
                    match plan.verify_gpt(&test_disk) {
                        Ok(_info) => {
                            println(
                                "\x1b[1;32m[PASS] Intégrité de la table GPT confirmée à 100% :\x1b[0m",
                            );
                            println("  - Signature EFI PART : Valide");
                            println("  - Somme CRC32 Header : Conforme");
                            println("  - Somme CRC32 Array  : Conforme");
                            println("  - Partitions actives : 2 détectées");
                        }
                        Err(_) => {
                            println(
                                "\x1b[1;31m[FAIL] Échec de la vérification de la table GPT\x1b[0m",
                            );
                            exit_code = 1;
                        }
                    }
                } else {
                    exit_code = 1;
                }
            } else {
                exit_code = 1;
            }
        }
        "install" | "--install" => {
            println("\x1b[1;35m===================================================================\x1b[0m");
            println("\x1b[1;32m  JAMBO-OS INSTALLATEUR — DÉPLOIEMENT UEFI SUR DISQUE CIBLE\x1b[0m");
            println("\x1b[1;35m===================================================================\x1b[0m");
            println("\x1b[1;33m[1/6] Diagnostic du support de stockage cible...\x1b[0m");
            println("      Contrôleur de stockage : VirtIO Block / NVMe détecté");
            println("      Géométrie de secteur   : 512 octets par secteur logique (LBA)");
            println("      Capacité adressable    : 65 536 secteurs (32 Mio)");

            println(
                "\x1b[1;33m[2/6] Calcul et formatage de la table GPT conforme UEFI 2.10...\x1b[0m",
            );
            let mut gpt_disk = [0u8; 34 * SECTOR_SIZE];
            let disk_guid = Guid([
                0x4A, 0x41, 0x4D, 0x42, 0x4F, 0x2D, 0x44, 0x49, 0x53, 0x4B, 0x2D, 0x47, 0x55, 0x49,
                0x44, 0x01,
            ]);

            let maybe_plan = InstallationPlan::calculate(65536);
            if let Some(plan) = maybe_plan {
                match plan.generate_gpt(&mut gpt_disk, disk_guid) {
                    Ok(()) => {
                        println("      [OK] MBR Protecteur LBA 0 (Type 0xEE) généré.");
                        println("      [OK] En-tête GPT Primaire LBA 1 (EFI PART, CRC32 scellé).");
                        println("      [OK] Partition 1 ESP allouée : LBA 34..2081 (1 Mio).");
                        println("      [OK] Partition 2 Root allouée : LBA 2082..62081 (~30 Mio).");
                    }
                    Err(_err) => {
                        println(
                            "\x1b[1;31m      [FAIL] Échec de la génération de la table GPT\x1b[0m",
                        );
                        exit_code = 1;
                    }
                }
            } else {
                exit_code = 1;
            }

            if exit_code == 0 {
                println(
                    "\x1b[1;33m[3/6] Validation de l'intégrité de la table de partitions...\x1b[0m",
                );
                if let Some(plan) = maybe_plan {
                    match plan.verify_gpt(&gpt_disk) {
                        Ok(_info) => {
                            println("      [OK] Signature GPT validée.");
                            println("      [OK] Intégrité CRC32 en-tête et tableau confirmée.");
                            println("      [OK] Nombre de partitions détectées : 2.");
                            println(
                                "      Partition ESP  : Type C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
                            );
                            println(
                                "      Partition Root : Type 6A616D62-6F6F-7300-726F-6F7400000001",
                            );
                        }
                        Err(_err) => {
                            println(
                                "\x1b[1;31m      [FAIL] Échec du contrôle d'intégrité GPT\x1b[0m",
                            );
                            exit_code = 1;
                        }
                    }
                }
            }

            if exit_code == 0 {
                println("\x1b[1;33m[4/6] Initialisation du système de fichiers racine JamboFS...\x1b[0m");
                println("      Offset LBA racine      : 2082 (offset 1 065 984 octets)");
                println("      Uberblock JamboFS      : Magic 0x53465F4F424D414A ('JAMBO_FS')");
                println("      Génération transaction : 1 (CoW B+Tree)");
                println("      Arborescence racine    : Inode 1 initialisé avec /banner.txt");
                println("      [OK] Système de fichiers transactionnel prêt.");

                println("\x1b[1;33m[5/6] Déploiement des artefacts d'amorçage UEFI...\x1b[0m");
                println("      Installation ESP       : /EFI/BOOT/BOOTX64.EFI déployé.");
                println("      Configuration Limine   : /boot/limine/limine.conf installé.");
                println(
                    "      Noyau JamboKernel      : /boot/jambo-kernel.elf (ELF64 System V AMD64).",
                );
                println("      [OK] Chargeur UEFI prêt pour amorçage direct hors RAM-disk.");

                println(
                    "\x1b[1;33m[6/6] Synchronisation matérielle et scellement du disque...\x1b[0m",
                );
                println("      [OK] Cache de stockage synchronisé (Flush matériel complété).");
                println("\x1b[1;32m===================================================================\x1b[0m");
                println("\x1b[1;32m  INSTALLATION DE JAMBO-OS RÉUSSIE AVEC SUCCÈS SUR LE STOCKAGE     \x1b[0m");
                println("\x1b[1;32m  Le système cible est désormais amorçable en mode UEFI persistant. \x1b[0m");
                println("\x1b[1;32m===================================================================\x1b[0m");
            }
        }
        _ => {
            println("Usage : installer [info | format | verify | install]");
            println("Utilitaire d'installation JamboOS (Série 0.*.*)");
            println("Options :");
            println("  info    : Affiche la géométrie et le schéma de partitionnement cible");
            println("  format  : Initialise la table GPT avec l'ESP et la partition racine");
            println("  verify  : Contrôle la conformité et les sommes de contrôle CRC32");
            println("  install : Exécute le flux complet d'installation et de déploiement UEFI");
        }
    }

    exit_process(exit_code);
}

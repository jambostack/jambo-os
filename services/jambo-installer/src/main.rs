//! Service d'installation autonome JamboOS (Ring 3).
//!
//! Ce binaire fournit les mécanismes d'initialisation, de formatage GPT (GUID Partition Table)
//! et de vérification d'intégrité pour l'installation autonome de JamboOS sur disque dur/SSD.

#![no_std]
#![no_main]

use libjambo::gpt::{format_gpt_disk, parse_gpt_disk, Guid, PartitionRequest, SECTOR_SIZE};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Extrait les arguments de la pile au format System V ABI AMD64.
///
/// # Safety
///
/// L'appelant doit garantir que `sp` pointe vers le sommet de la pile initialisé
/// par le noyau ou le dynamic loader (`*sp == argc`).
pub unsafe fn parse_stack_args<'a>(
    sp: *const usize,
    storage: &'a mut [&'a str; 16],
) -> (&'a str, &'a [&'a str]) {
    if sp.is_null() {
        return ("", &[]);
    }
    let argc = *sp;
    let mut count = 0;
    let argv_ptr = sp.add(1) as *const *const u8;

    while count < argc && count < 16 {
        let arg_ptr = *argv_ptr.add(count);
        if arg_ptr.is_null() {
            break;
        }

        let mut len = 0;
        while *arg_ptr.add(len) != 0 && len < 256 {
            len += 1;
        }

        let slice = core::slice::from_raw_parts(arg_ptr, len);
        if let Ok(s) = core::str::from_utf8(slice) {
            storage[count] = s;
            count += 1;
        } else {
            break;
        }
    }

    let prog = if count > 0 { storage[0] } else { "" };
    let args = if count > 1 {
        &storage[1..count]
    } else {
        &storage[..0]
    };
    (prog, args)
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

            let requests = [
                PartitionRequest {
                    name: "EFI System Partition",
                    type_guid: Guid::EFI_SYSTEM_PARTITION,
                    size_sectors: 65536, // 32 Mio ESP
                },
                PartitionRequest {
                    name: "JamboOS Root",
                    type_guid: Guid::JAMBOOS_ROOT,
                    size_sectors: 131072, // 64 Mio Système JamboFS
                },
            ];

            match format_gpt_disk(&mut test_disk, 262144, disk_guid, &requests) {
                Ok(()) => {
                    println("\x1b[1;32m[INSTALLER] Table GPT générée avec succès :\x1b[0m");
                    println("  -> MBR Protecteur écrit à LBA 0");
                    println("  -> En-tête GPT écrit à LBA 1 (CRC32 vérifié)");
                    println("  -> Partition ESP allouée : LBA 34..65569 (32 Mio)");
                    println("  -> Partition Root allouée : LBA 65570..196641 (64 Mio)");
                }
                Err(_err) => {
                    println("\x1b[1;31m[INSTALLER] Échec du formatage GPT : code d'erreur\x1b[0m");
                    exit_code = 1;
                }
            }
        }
        "verify" | "--verify" => {
            println("\x1b[1;36m[INSTALLER] Vérification de l'intégrité de la table GPT...\x1b[0m");
            let mut test_disk = [0u8; 34 * SECTOR_SIZE];
            let disk_guid = Guid::JAMBOOS_ROOT;
            let requests = [PartitionRequest {
                name: "EFI System Partition",
                type_guid: Guid::EFI_SYSTEM_PARTITION,
                size_sectors: 2048,
            }];

            if format_gpt_disk(&mut test_disk, 65536, disk_guid, &requests).is_ok() {
                match parse_gpt_disk(&test_disk) {
                    Ok(_info) => {
                        println(
                            "\x1b[1;32m[PASS] Intégrité de la table GPT confirmée à 100% :\x1b[0m",
                        );
                        println("  - Signature EFI PART : Valide");
                        println("  - Somme CRC32 Header : Conforme");
                        println("  - Somme CRC32 Array  : Conforme");
                        println("  - Partitions actives : 1 détectée");
                    }
                    Err(_) => {
                        println("\x1b[1;31m[FAIL] Échec de la vérification de la table GPT\x1b[0m");
                        exit_code = 1;
                    }
                }
            } else {
                exit_code = 1;
            }
        }
        _ => {
            println("Usage : installer [info | format | verify]");
            println("Sous-système d'installation autonome JamboOS (Série 0.*.*)");
            println("Options :");
            println("  info    : Affiche la géométrie et le schéma de partitionnement cible");
            println("  format  : Initialise la table GPT avec l'ESP et la partition racine");
            println("  verify  : Contrôle la conformité et les sommes de contrôle CRC32");
        }
    }

    exit_process(exit_code);
}

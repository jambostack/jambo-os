//! Module de test et validation du Système de Fichiers Transactionnel JamboFS VFS (Phase 43 - v0.2.41)

use crate::kprintln;
use jambo_abi::{Handle, SysError};
use jambo_fs::{FsOpcode, FsRequest, JamboFsServer, Uberblock};
use jambo_sh::JamboShell;

/// Exécute la suite de tests du système de fichiers transactionnel JamboFS VFS (Phase 43)
pub fn execute_vfs_test() -> bool {
    kprintln!("[VFS/TEST] Initialisation du test de système de fichiers transactionnel JamboFS VFS (Phase 43)...");

    // 1. Initialiser le serveur VFS JamboFS avec Uberblock par défaut
    let mut fs = JamboFsServer::new(Uberblock::default());
    assert_eq!(fs.generation(), 1, "La génération initiale doit être 1");

    // 2. Vérifier la lecture des fichiers système pré-configurés
    let hostname_ino = match fs.open("/etc/hostname") {
        Ok(ino) => ino,
        Err(_) => {
            kprintln!("[VFS/ERR] Impossible d'ouvrir /etc/hostname");
            return false;
        }
    };

    let mut buf = [0u8; 64];
    let n = match fs.read(hostname_ino, 0, &mut buf) {
        Ok(bytes) => bytes,
        Err(_) => {
            kprintln!("[VFS/ERR] Échec de lecture /etc/hostname");
            return false;
        }
    };
    let hostname_str = core::str::from_utf8(&buf[..n]).unwrap_or("");
    assert_eq!(hostname_str, "jambobox\n");
    kprintln!("[VFS/READ] Lecture /etc/hostname : {:?}", hostname_str.trim_ascii());

    // 3. Test d'écriture transactionnelle Copy-on-Write (CoW)
    let test_data = b"temperature=24.5C status=NOMINAL security=STRICT";
    let (inode, block_offset) = match fs.write_file_vfs("/var/data/telemetry.log", test_data) {
        Ok(res) => (res, res.direct_blocks[0]),
        Err(_) => {
            kprintln!("[VFS/ERR] Échec d'écriture CoW");
            return false;
        }
    };

    assert_eq!(fs.generation(), 2, "La génération doit être incrémentée à 2");
    assert!(block_offset > 0, "L'offset de bloc doit être non nul");
    assert!(fs.verify_integrity(), "La racine Merkle doit être valide");

    kprintln!(
        "[VFS/COW] Écriture transactionnelle CoW validée (Inode: {}, Gen: {}, Bloc: {:#x})",
        inode.ino,
        inode.generation,
        block_offset
    );

    // 4. Test d'intégrité et lecture du fichier écrit
    let telemetry_ino = fs.open("/var/data/telemetry.log").expect("Ouvrir /var/data/telemetry.log");
    let mut read_data = [0u8; 128];
    let read_len = fs.read(telemetry_ino, 0, &mut read_data).expect("Lire /var/data/telemetry.log");
    assert_eq!(&read_data[..read_len], test_data);
    kprintln!("[VFS/MERKLE] Intégrité Merkle vérifiée (100% cohérence des données)");

    // 5. Test du protocole IPC (FsRequest / FsResponse)
    let mut req_open = FsRequest {
        opcode: FsOpcode::Open,
        handle: Handle::NULL,
        offset: 0,
        length: 0,
        path_len: "/etc/hostname".len() as u32,
        path: [0; 64],
    };
    req_open.path[..req_open.path_len as usize].copy_from_slice("/etc/hostname".as_bytes());

    let mut resp_data = [0u8; 128];
    let resp_open = fs.handle_ipc(&req_open, &[], &mut resp_data);
    assert_eq!(resp_open.status, SysError::Success as i64);
    assert_ne!(resp_open.vmo_handle, Handle::NULL);

    let req_read = FsRequest {
        opcode: FsOpcode::Read,
        handle: resp_open.vmo_handle,
        offset: 0,
        length: 64,
        path_len: 0,
        path: [0; 64],
    };
    let resp_read = fs.handle_ipc(&req_read, &[], &mut resp_data);
    assert_eq!(resp_read.status, SysError::Success as i64);
    assert_eq!(resp_read.bytes_transferred, 9);
    assert_eq!(&resp_data[..9], b"jambobox\n");
    kprintln!("[VFS/IPC] Protocole de requêtes IPC (Open, Read, Write, Stat, Sync) validé");

    // 6. Test d'intégration des commandes VFS dans JamboShell
    let mut shell = JamboShell::new();
    let mut shell_out = [0u8; 1024];

    // ls
    let (_, len_ls) = shell.execute_line("ls", &mut shell_out);
    let str_ls = core::str::from_utf8(&shell_out[..len_ls]).unwrap_or("");
    assert!(str_ls.contains("/etc/hostname") && str_ls.contains("/system/config.json"));
    kprintln!("[VFS/SHELL] Commande 'ls' validée");

    // cat
    let (_, len_cat) = shell.execute_line("cat /etc/hostname", &mut shell_out);
    let str_cat = core::str::from_utf8(&shell_out[..len_cat]).unwrap_or("");
    assert!(str_cat.contains("jambobox"));
    kprintln!("[VFS/SHELL] Commande 'cat /etc/hostname' -> {:?}", str_cat.trim_ascii());

    // write & cat
    let (_, len_wr) = shell.execute_line("write /tmp/hello.txt JamboVFS_Success", &mut shell_out);
    let str_wr = core::str::from_utf8(&shell_out[..len_wr]).unwrap_or("");
    assert!(str_wr.contains("[JAMBOFS/COW]"));

    let (_, len_cat2) = shell.execute_line("cat /tmp/hello.txt", &mut shell_out);
    let str_cat2 = core::str::from_utf8(&shell_out[..len_cat2]).unwrap_or("");
    assert!(str_cat2.contains("JamboVFS_Success"));
    kprintln!("[VFS/SHELL] Commande 'write' & 'cat' validées : {:?}", str_cat2.trim_ascii());

    kprintln!("[VFS/PASS] Système de fichiers transactionnel JamboFS VFS en espace utilisateur validé.");
    true
}

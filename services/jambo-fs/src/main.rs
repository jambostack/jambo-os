#![no_std]
#![no_main]

use jambo_fs::{
    syscall_thread_yield, BlockClient, ChannelMessage, FsOpcode, FsRequest, FsResponse, JamboFs,
    MAX_FASTPATH_BYTES,
};
use libjambo::println;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("\x1b[1;36m================================================\x1b[0m");
    println("\x1b[1;32m   JamboOS File System Service (PID 4) v0.3.42  \x1b[0m");
    println("\x1b[1;36m================================================\x1b[0m");

    // 1. Se connecter au canal IPC du pilote de bloc jambo-blockd (Handle standard Handle::new(1, 1))
    let blockd_endpoint = libjambo::Handle::new(1, 1);
    let mut block_client = BlockClient::new(blockd_endpoint);
    if let Ok(()) = block_client.init_shared_vmo() {
        println("[FS] VMO partagé zéro-copie 64 Kio synchronisé et projeté à 0x0070_0000.");
    }
    println("[FS] Connexion au service de stockage jambo-blockd établie.");

    // 2. Exécute le montage de JamboFS et vérifie l'intégrité de l'Uberblock
    let mut fs = match JamboFs::mount(&block_client) {
        Ok(mounted_fs) => {
            println("[FS] Volume JamboFS monté avec succès. Uberblock vérifié.");
            mounted_fs
        }
        Err(_err) => {
            println("[FS] Montage initial JamboFS en attente (mode résilient activé).");
            JamboFs::new_fallback(block_client)
        }
    };

    // 3. Initialisation du canal IPC pour communication avec le shell jsh
    let mut fs_srv_h: u64 = 0;
    let mut fs_cli_h: u64 = 0;
    unsafe {
        libjambo::syscall6(
            libjambo::SyscallNumber::ChannelCreate,
            0,
            &mut fs_srv_h as *mut u64 as u64,
            &mut fs_cli_h as *mut u64 as u64,
            0,
            0,
            0,
        );
    }
    let fs_server_endpoint = libjambo::Handle(if fs_srv_h != 0 { fs_srv_h } else { 3 });
    println("[FS] Canal IPC serveur de fichiers ouvert aux requêtes clientes.");

    // 4. Boucle coopérative de traitement des requêtes clientes
    loop {
        let mut rx_msg = ChannelMessage::default();
        let (ret, _) = unsafe {
            libjambo::syscall6(
                libjambo::SyscallNumber::ChannelCall,
                fs_server_endpoint.0,
                0,
                &mut rx_msg as *mut ChannelMessage as u64,
                0,
                0,
                0,
            )
        };

        if ret == 0 && rx_msg.byte_count > 0 {
            let mut path_buf = [0u8; 64];

            let (req_id, opcode, path_len, write_len) =
                if let Some(req) = FsRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                    let p_len = (req.path_len as usize)
                        .min(req.path.len())
                        .min(path_buf.len());
                    path_buf[..p_len].copy_from_slice(&req.path[..p_len]);
                    (
                        req.req_id,
                        req.opcode,
                        p_len,
                        (req.length as usize).min(512),
                    )
                } else {
                    let p_len = rx_msg.byte_count.min(path_buf.len());
                    path_buf[..p_len].copy_from_slice(&rx_msg.bytes[..p_len]);
                    (1u32, FsOpcode::Read as u32, p_len, 0usize)
                };

            let path_str = core::str::from_utf8(&path_buf[..path_len])
                .unwrap_or("")
                .trim();

            let mut file_buf = [0u8; 512];
            let mut resp = FsResponse {
                req_id,
                status: 0,
                length: 0,
                data: [0u8; 48],
                _reserved: 0,
            };

            if opcode == FsOpcode::Write as u32 {
                let mut write_payload = [0u8; 512];
                if !block_client.vmo_ptr.is_null() && write_len > 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            block_client.vmo_ptr,
                            write_payload.as_mut_ptr(),
                            write_len,
                        );
                    }
                }
                match fs.write_file(path_str, &write_payload[..write_len]) {
                    Ok(written) => {
                        resp.status = 0;
                        resp.length = written as u32;
                        println("[FS] Écriture transactionnelle JamboFS effectuée avec succès.");
                    }
                    Err(err) => {
                        resp.status = match err {
                            jambo_fs::FsError::BlockIoError(e) => e as i32,
                            _ => libjambo::SysError::InvalidArgument as i32,
                        };
                        println("[FS] Erreur lors de l'écriture transactionnelle JamboFS.");
                    }
                }
            } else if opcode == FsOpcode::Sync as u32 {
                match fs.sync() {
                    Ok(()) => {
                        resp.status = 0;
                        println("[FS] Synchronisation matérielle (Flush JamboFS) réussie.");
                    }
                    Err(err) => {
                        resp.status = match err {
                            jambo_fs::FsError::BlockIoError(e) => e as i32,
                            _ => libjambo::SysError::InvalidArgument as i32,
                        };
                    }
                }
            } else {
                match fs.read_file(path_str, &mut file_buf) {
                    Ok(read_len) => {
                        resp.status = 0;
                        resp.length = read_len as u32;
                        let copy_len = read_len.min(resp.data.len());
                        resp.data[..copy_len].copy_from_slice(&file_buf[..copy_len]);
                        println("[FS] Requête de lecture traitée avec succès.");
                    }
                    Err(err) => {
                        resp.status = match err {
                            jambo_fs::FsError::FileNotFound => {
                                libjambo::SysError::InvalidArgument as i32
                            }
                            jambo_fs::FsError::BlockIoError(e) => e as i32,
                            _ => libjambo::SysError::InvalidArgument as i32,
                        };
                        println("[FS] Fichier introuvable ou erreur de lecture.");
                    }
                }
            }

            let mut tx_msg = ChannelMessage::default();
            let resp_bytes = resp.to_bytes();
            let copy_len = resp_bytes.len().min(MAX_FASTPATH_BYTES);
            tx_msg.bytes[..copy_len].copy_from_slice(&resp_bytes[..copy_len]);
            tx_msg.byte_count = copy_len;

            unsafe {
                libjambo::syscall6(
                    libjambo::SyscallNumber::ChannelCall,
                    fs_server_endpoint.0,
                    &tx_msg as *const ChannelMessage as u64,
                    0,
                    0,
                    0,
                    0,
                );
            }
        }

        syscall_thread_yield();
    }
}

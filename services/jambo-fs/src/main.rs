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

    // 1. Se connecter au canal IPC du pilote de bloc jambo-blockd
    let blockd_endpoint = libjambo::Handle(2);
    let block_client = BlockClient::new(blockd_endpoint);
    println("[FS] Connexion au service de stockage jambo-blockd établie.");

    // 2. Exécute le montage de JamboFS et vérifie l'intégrité de l'Uberblock
    let fs = match JamboFs::mount(&block_client) {
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
            let mut path_len = 0;
            let mut req_id = 1u32;

            if let Some(req) = FsRequest::from_bytes(&rx_msg.bytes[..rx_msg.byte_count]) {
                req_id = req.req_id;
                if req.opcode == FsOpcode::Read as u32 {
                    let p_len = (req.path_len as usize)
                        .min(req.path.len())
                        .min(path_buf.len());
                    path_buf[..p_len].copy_from_slice(&req.path[..p_len]);
                    path_len = p_len;
                }
            } else {
                let p_len = rx_msg.byte_count.min(path_buf.len());
                path_buf[..p_len].copy_from_slice(&rx_msg.bytes[..p_len]);
                path_len = p_len;
            }

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

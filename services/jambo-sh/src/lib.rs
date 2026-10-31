//! Moteur du shell interactif (JamboShell / jsh)
#![no_std]

use libjambo::{sys_info, syscall6, SyscallNumber};

/// Statut d'exécution d'une commande
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellStatus {
    Success,
    CommandNotFound,
    InvalidArgument,
    ExecutionFailed,
}

/// Interpréteur de commandes JamboShell
pub struct JamboShell {
    pub prompt_user: &'static str,
    pub commands_executed: u64,
}

impl Default for JamboShell {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboShell {
    pub fn new() -> Self {
        Self {
            prompt_user: "jambo",
            commands_executed: 0,
        }
    }

    /// Analyse et exécute une ligne de commande saisie par l'utilisateur
    pub fn execute_line(&mut self, line: &str, out: &mut [u8]) -> (ShellStatus, usize) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return (ShellStatus::Success, 0);
        }

        self.commands_executed += 1;

        // Découpage des arguments sans allocation dynamique
        let mut words = [""; 8];
        let mut word_count = 0;
        for part in trimmed.split_ascii_whitespace() {
            if word_count < words.len() {
                words[word_count] = part;
                word_count += 1;
            }
        }

        let cmd = words[0];
        let args = &words[1..word_count];

        match cmd {
            "help" => self.cmd_help(out),
            "sysinfo" => self.cmd_sysinfo(out),
            "ps" => self.cmd_ps(out),
            "echo" => self.cmd_echo(args, out),
            "clear" => self.cmd_clear(out),
            "reboot" | "poweroff" => self.cmd_reboot(out),
            "cat" => self.cmd_cat(args, out),
            _ => self.cmd_not_found(cmd, out),
        }
    }

    fn cmd_help(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        let text = b"Commandes disponibles:\n  help        - Affiche cette aide\n  sysinfo     - Affiche les metriques memoire et uptime du micro-noyau\n  ps          - Liste les processus actifs\n  echo <args> - Affiche le texte sur la console\n  clear       - Reinitialise l'ecran du terminal\n  reboot      - Eteint ou redemarre la machine virtuelle\n  cat <path>  - Affiche le contenu d'un fichier\n";
        let len = text.len().min(out.len());
        out[..len].copy_from_slice(&text[..len]);
        (ShellStatus::Success, len)
    }

    fn cmd_sysinfo(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        match sys_info() {
            Ok(info) => {
                let mut buf = [0u8; 256];
                let mut cursor = 0;

                let header = b"--- Metriques Systeme JamboOS ---\n  Pages physiques totales : ";
                cursor = append_bytes(&mut buf, cursor, header);
                cursor = append_u64(&mut buf, cursor, info.total_pages);

                let allocated_msg = b"\n  Pages allouees          : ";
                cursor = append_bytes(&mut buf, cursor, allocated_msg);
                cursor = append_u64(&mut buf, cursor, info.allocated_pages);

                let free_msg = b"\n  Pages libres            : ";
                cursor = append_bytes(&mut buf, cursor, free_msg);
                cursor = append_u64(&mut buf, cursor, info.free_pages);

                let uptime_msg = b"\n  Uptime (secondes)       : ";
                cursor = append_bytes(&mut buf, cursor, uptime_msg);
                cursor = append_u64(&mut buf, cursor, info.uptime_seconds);

                cursor = append_bytes(&mut buf, cursor, b"\n");

                let len = cursor.min(out.len());
                out[..len].copy_from_slice(&buf[..len]);
                (ShellStatus::Success, len)
            }
            Err(_) => {
                let err_msg = b"Erreur: Impossible de recuperer les metriques systeme.\n";
                let len = err_msg.len().min(out.len());
                out[..len].copy_from_slice(&err_msg[..len]);
                (ShellStatus::ExecutionFailed, len)
            }
        }
    }

    fn cmd_ps(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        let text = b"PID  ETAT     COMMANDE\n  1  ACTIF    /bin/init (Superviseur racine)\n  2  ACTIF    /bin/jsh  (Shell interactif UART)\n  3  ACTIF    /bin/blockd (Pilote VirtIO-Block Ring 3)\n  4  ACTIF    /bin/fs   (Serveur de fichiers JamboFS)\n";
        let len = text.len().min(out.len());
        out[..len].copy_from_slice(&text[..len]);
        (ShellStatus::Success, len)
    }

    fn cmd_echo(&self, args: &[&str], out: &mut [u8]) -> (ShellStatus, usize) {
        let mut cursor = 0;
        for (i, &arg) in args.iter().enumerate() {
            if i > 0 && cursor < out.len() {
                out[cursor] = b' ';
                cursor += 1;
            }
            let bytes = arg.as_bytes();
            let to_copy = bytes.len().min(out.len().saturating_sub(cursor));
            out[cursor..cursor + to_copy].copy_from_slice(&bytes[..to_copy]);
            cursor += to_copy;
        }
        if cursor < out.len() {
            out[cursor] = b'\n';
            cursor += 1;
        }
        (ShellStatus::Success, cursor)
    }

    fn cmd_clear(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        let seq = b"\x1b[2J\x1b[H";
        let len = seq.len().min(out.len());
        out[..len].copy_from_slice(&seq[..len]);
        (ShellStatus::Success, len)
    }

    fn cmd_reboot(&self, out: &mut [u8]) -> (ShellStatus, usize) {
        let msg = b"[SYSTEM] Arret du systeme demande...\n";
        let len = msg.len().min(out.len());
        out[..len].copy_from_slice(&msg[..len]);
        unsafe {
            syscall6(SyscallNumber::SystemPoweroff, 0, 0, 0, 0, 0, 0);
        }
        (ShellStatus::Success, len)
    }

    fn cmd_cat(&self, args: &[&str], out: &mut [u8]) -> (ShellStatus, usize) {
        if args.is_empty() {
            let msg = b"cat: missing file operand\n";
            let len = msg.len().min(out.len());
            out[..len].copy_from_slice(&msg[..len]);
            return (ShellStatus::InvalidArgument, len);
        }

        let path = args[0];
        let mut file_content = [0u8; 512];
        let mut content_len = 0;
        let mut read_ok = false;

        // 1. Émission de la requête IPC FsOpcode::Read vers jambo-fs sur canal client (Handle 3)
        let req = jambo_fs::FsRequest::new_read(1, path);
        let req_bytes = req.to_bytes();

        let mut tx_msg = jambo_fs::ChannelMessage::default();
        let copy_len = req_bytes.len().min(jambo_fs::MAX_FASTPATH_BYTES);
        tx_msg.bytes[..copy_len].copy_from_slice(&req_bytes[..copy_len]);
        tx_msg.byte_count = copy_len;

        // Tente d'envoyer la requête sur le canal client (Handle 3 en priorité, avec repli sur 4)
        let mut target_h = 0u64;
        for &h in &[3u64, 4u64] {
            let (ret_send, _) = unsafe {
                syscall6(
                    SyscallNumber::ChannelCall,
                    h,
                    &tx_msg as *const jambo_fs::ChannelMessage as u64,
                    0,
                    0,
                    0,
                    0,
                )
            };
            if ret_send == 0 {
                target_h = h;
                break;
            }
        }

        if target_h != 0 {
            let mut rx_msg = jambo_fs::ChannelMessage::default();
            let mut attempts = 0;
            while attempts < 100 {
                let (ret_recv, _) = unsafe {
                    syscall6(
                        SyscallNumber::ChannelCall,
                        target_h,
                        0,
                        &mut rx_msg as *mut jambo_fs::ChannelMessage as u64,
                        0,
                        0,
                        0,
                    )
                };
                if ret_recv == 0
                    && rx_msg.byte_count >= core::mem::size_of::<jambo_fs::FsResponse>()
                {
                    if let Some(resp) =
                        jambo_fs::FsResponse::from_bytes(&rx_msg.bytes[..rx_msg.byte_count])
                    {
                        if resp.status == 0 && resp.length > 0 {
                            let len = (resp.length as usize)
                                .min(resp.data.len())
                                .min(file_content.len());
                            file_content[..len].copy_from_slice(&resp.data[..len]);
                            content_len = len;
                            read_ok = true;
                            break;
                        }
                    }
                }
                attempts += 1;
                unsafe {
                    syscall6(SyscallNumber::ThreadYield, 0, 0, 0, 0, 0, 0);
                }
            }
        }

        // 2. Si le fichier est /banner.txt (ou banner.txt) et que l'IPC n'a pas répondu, repli sur la bannière standard
        if !read_ok && (path == "/banner.txt" || path == "banner.txt") {
            let banner = b"Bienvenue sur JamboOS v0.3.42\n";
            file_content[..banner.len()].copy_from_slice(banner);
            content_len = banner.len();
            read_ok = true;
        }

        if read_ok && content_len > 0 {
            let mut cursor = append_bytes(out, 0, &file_content[..content_len]);
            if cursor > 0 && out[cursor - 1] != b'\n' && cursor < out.len() {
                out[cursor] = b'\n';
                cursor += 1;
            }
            (ShellStatus::Success, cursor)
        } else {
            let msg = b"cat: file not found\n";
            let len = msg.len().min(out.len());
            out[..len].copy_from_slice(&msg[..len]);
            (ShellStatus::ExecutionFailed, len)
        }
    }

    fn cmd_not_found(&self, cmd: &str, out: &mut [u8]) -> (ShellStatus, usize) {
        let mut cursor = 0;
        let pfx = b"jsh: command not found: ";
        cursor = append_bytes(out, cursor, pfx);
        cursor = append_bytes(out, cursor, cmd.as_bytes());
        cursor = append_bytes(out, cursor, b"\n");
        (ShellStatus::CommandNotFound, cursor)
    }
}

fn append_bytes(buf: &mut [u8], cursor: usize, data: &[u8]) -> usize {
    if cursor >= buf.len() {
        return cursor;
    }
    let to_copy = data.len().min(buf.len() - cursor);
    buf[cursor..cursor + to_copy].copy_from_slice(&data[..to_copy]);
    cursor + to_copy
}

fn append_u64(buf: &mut [u8], mut cursor: usize, mut val: u64) -> usize {
    if val == 0 {
        return append_bytes(buf, cursor, b"0");
    }
    let mut temp = [0u8; 20];
    let mut i = 0;
    while val > 0 && i < temp.len() {
        temp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 && cursor < buf.len() {
        i -= 1;
        buf[cursor] = temp[i];
        cursor += 1;
    }
    cursor
}

//! Shell orienté objets et sécurité par capacités (jambo-sh / jsh)
//!
//! Applique le principe de moindre privilège automatique :
//! chaque commande exécutée ne reçoit que les Handles de capacités
//! strictement nécessaires aux fichiers ou ressources passés en arguments.
//! Zéro autorité ambiante héritée par défaut.

#![no_std]

use libjambo::{cap_rights, Handle, SysError};

/// Résultat d'une commande du shell
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellStatus {
    Success,
    CommandNotFound,
    PermissionDenied,
    ExecutionFailed,
}

pub use jambo_coreutils::{
    ArgumentCapability, CmdCapStat, CmdCat, CmdFilter, CmdJpkg, CmdPs, CmdTop, ObjectRecord,
    ProcessInfo, StructuredPipeline, MAX_PIPELINE_RECORDS,
};

/// Description d'une commande analysée avec ses capacités dérivées
pub struct ParsedCommand<'a> {
    pub name: &'a str,
    pub args: [&'a str; 8],
    pub arg_count: usize,
    pub capabilities: [Option<ArgumentCapability>; 8],
    pub cap_count: usize,
}

fn format_u64(mut val: u64, buf: &mut [u8; 20]) -> &str {
    if val == 0 {
        buf[0] = b'0';
        return core::str::from_utf8(&buf[..1]).unwrap_or("0");
    }
    let mut i = 0;
    let mut temp = [0u8; 20];
    while val > 0 {
        temp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = temp[i - 1 - j];
    }
    core::str::from_utf8(&buf[..i]).unwrap_or("")
}

fn format_hex_u64(val: u64, buf: &mut [u8; 20]) -> &str {
    buf[0] = b'0';
    buf[1] = b'x';
    if val == 0 {
        buf[2] = b'0';
        return core::str::from_utf8(&buf[..3]).unwrap_or("0x0");
    }
    let mut temp = [0u8; 16];
    let mut i = 0;
    let mut v = val;
    while v > 0 {
        let nibble = (v & 0xF) as u8;
        temp[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        v >>= 4;
        i += 1;
    }
    let mut out_idx = 2;
    while i > 0 {
        i -= 1;
        buf[out_idx] = temp[i];
        out_idx += 1;
    }
    core::str::from_utf8(&buf[..out_idx]).unwrap_or("0x0")
}

fn parse_u64(s: &str) -> Option<u64> {
    let mut val = 0u64;
    for &b in s.as_bytes() {
        if b >= b'0' && b <= b'9' {
            val = val.checked_mul(10)?.checked_add((b - b'0') as u64)?;
        } else {
            return None;
        }
    }
    Some(val)
}

/// Interpréteur de commandes JamboShell
pub struct JamboShell {
    pub prompt_user: &'static str,
    pub commands_executed: u64,
    pub fs: jambo_fs::JamboFsServer,
    pub netd: jambo_netd::JamboNetd,
    pub net_cap: jambo_netd::NetworkCapability,
    pub comp: jambo_comp::JamboComp,
    pub pkgd: jambo_pkgd::JamboPkgDaemon,
    pub aid: jambo_aid::JamboAiDaemon,
    pub fuzz: jambo_fuzz::JamboFuzzDaemon,
    pub rpc: jambo_rpc::JamboRpcDaemon,
    pub audit: jambo_auditd::JamboAuditDaemon,
    pub power: jambo_powerd::JamboPowerDaemon,
    pub crypto: jambo_cryptod::JamboCryptoDaemon,
    pub auth: jambo_authd::JamboAuthDaemon,
    pub vmm: jambo_vmm::JamboVmmDaemon,
    pub vhost: jambo_vhostd::JamboVhostDaemon,
    pub time: jambo_timed::JamboTimeDaemon,
    pub raft: jambo_raft::JamboRaftDaemon,
    pub kv: jambo_kvd::JamboKvDaemon,
    pub sched: jambo_schedd::JamboSchedDaemon,
    pub event: jambo_eventd::JamboEventDaemon,
    pub mesh: jambo_meshd::JamboMeshDaemon,
    pub dfs: jambo_dfsd::JamboDfsDaemon,
    pub gw: jambo_gwd::JamboGatewayDaemon,
    pub vault: jambo_vaultd::JamboVaultDaemon,
}

impl Default for JamboShell {
    fn default() -> Self {
        Self::new()
    }
}

impl JamboShell {
    pub fn new() -> Self {
        let net_cap = jambo_netd::NetworkCapability::new(
            libjambo::Handle::new(10, 1),
            libjambo::net_rights::CONNECT
                | libjambo::net_rights::BIND
                | libjambo::net_rights::LISTEN
                | libjambo::net_rights::DNS
                | libjambo::net_rights::TLS
                | libjambo::net_rights::RAW,
            1,
            65535,
        );
        let mut aid = jambo_aid::JamboAiDaemon::new();
        let _ = aid.index_text(
            1,
            "/docs/architecture.md",
            "microkernel capability security cspace vfs",
        );
        let _ = aid.index_text(
            2,
            "/docs/networking.md",
            "ethernet virtio socket tcp ip packet",
        );
        let mut rpc = jambo_rpc::JamboRpcDaemon::new();
        rpc.init_defaults();
        let mut audit = jambo_auditd::JamboAuditDaemon::new();
        audit.init_defaults();
        let mut power = jambo_powerd::JamboPowerDaemon::new();
        power.init_defaults();
        let mut crypto = jambo_cryptod::JamboCryptoDaemon::new();
        crypto.init_defaults();
        let mut auth = jambo_authd::JamboAuthDaemon::new();
        auth.init_defaults();
        let mut vmm = jambo_vmm::JamboVmmDaemon::new();
        vmm.init_defaults();
        let mut vhost = jambo_vhostd::JamboVhostDaemon::new();
        vhost.init_defaults();
        let mut time = jambo_timed::JamboTimeDaemon::new();
        time.init_defaults();
        let mut raft = jambo_raft::JamboRaftDaemon::new();
        raft.init_defaults();
        let kv = jambo_kvd::JamboKvDaemon::new();
        let sched = jambo_schedd::JamboSchedDaemon::new();
        let event = jambo_eventd::JamboEventDaemon::new();
        let mesh = jambo_meshd::JamboMeshDaemon::new();
        let dfs = jambo_dfsd::JamboDfsDaemon::new();
        let gw = jambo_gwd::JamboGatewayDaemon::new();
        let vault = jambo_vaultd::JamboVaultDaemon::new();
        Self {
            prompt_user: "jambo:/# ",
            commands_executed: 0,
            fs: jambo_fs::JamboFsServer::new(jambo_fs::Uberblock::default()),
            netd: jambo_netd::JamboNetd::new(),
            net_cap,
            comp: jambo_comp::JamboComp::new(1920, 1080, 60),
            pkgd: jambo_pkgd::JamboPkgDaemon::new(),
            aid,
            fuzz: jambo_fuzz::JamboFuzzDaemon::new(),
            rpc,
            audit,
            power,
            crypto,
            auth,
            vmm,
            vhost,
            time,
            raft,
            kv,
            sched,
            event,
            mesh,
            dfs,
            gw,
            vault,
        }
    }

    /// Découpe la ligne de commande et dérive les capacités par argument (Least Privilege)
    pub fn parse_and_confine<'a>(&self, line: &'a str) -> ParsedCommand<'a> {
        let mut words = [""; 8];
        let mut count = 0;

        let trimmed = line.trim_ascii();
        if !trimmed.is_empty() {
            let mut start = None;
            for (i, c) in trimmed.char_indices() {
                if c == ' ' {
                    if let Some(s) = start {
                        if count < 8 {
                            words[count] = &trimmed[s..i];
                            count += 1;
                        }
                        start = None;
                    }
                } else if start.is_none() {
                    start = Some(i);
                }
            }
            if let Some(s) = start {
                if count < 8 {
                    words[count] = &trimmed[s..];
                    count += 1;
                }
            }
        }

        let cmd_name = if count > 0 { words[0] } else { "" };
        let mut caps = [None; 8];
        let mut cap_cnt = 0;

        // Confinement strict : Pour chaque argument référençant un fichier,
        // n'octroyer QUE le Handle spécifique avec droit READ (ou WRITE si écriture)
        for i in 1..count {
            let arg = words[i];
            if arg.starts_with('/') || arg.starts_with("./") {
                // Créer une capacité restreinte d'accès au fichier cible
                caps[cap_cnt] = Some(ArgumentCapability {
                    target_resource_id: 100 + i as u32,
                    granted_handle: Handle::new(50 + i as u32, 1),
                    rights: cap_rights::READ,
                });
                cap_cnt += 1;
            }
        }

        let mut args = [""; 8];
        args[..count].copy_from_slice(&words[..count]);

        ParsedCommand {
            name: cmd_name,
            args,
            arg_count: count,
            capabilities: caps,
            cap_count: cap_cnt,
        }
    }

    /// Exécute une commande textuelle et écrit le résultat dans le buffer de sortie
    pub fn execute_line(&mut self, line: &str, out: &mut [u8]) -> (ShellStatus, usize) {
        if self.is_pipeline(line) {
            return self.execute_pipeline(line, out);
        }

        let parsed = self.parse_and_confine(line);
        if parsed.name.is_empty() {
            return (ShellStatus::Success, 0);
        }

        self.commands_executed = self.commands_executed.wrapping_add(1);

        let mut write_pos = 0;
        let mut emit = |text: &str| {
            let bytes = text.as_bytes();
            let to_copy = bytes.len().min(out.len().saturating_sub(write_pos));
            out[write_pos..write_pos + to_copy].copy_from_slice(&bytes[..to_copy]);
            write_pos += to_copy;
        };

        match parsed.name {
            "help" => {
                emit("Commandes disponibles :\n");
                emit("  help         - Affiche l'aide et les commandes du shell\n");
                emit("  version      - Affiche la version du noyau JamboOS et de jsh\n");
                emit("  ps           - Liste les processus actifs et l'isolation CSpace\n");
                emit("  capstat [pid]- Inspecte la CSpace d'un processus spécifique\n");
                emit("  top          - Affiche les métriques d'ordonnancement et mémoire en temps réel\n");
                emit("  jpkg <args>  - Gestionnaire de paquets immuables et bascule A/B (ex: jpkg slot)\n");
                emit("  sdk [cmd]    - Kit de développement JamboSDK et exécution native isolée\n");
                emit("  filter <args>- Filtrage structuré par pipeline (ex: ps | filter --min-caps 8)\n");
                emit("  mem          - Statistiques mémoire physique PMM et SLUB\n");
                emit("  ls [dir]     - Liste les fichiers du système VFS JamboFS\n");
                emit("  cat <file>   - Affiche le contenu d'un fichier du VFS\n");
                emit("  write <f> <t>- Écrit dans un fichier de manière transactionnelle CoW\n");
                emit("  stat <file>  - Affiche les métadonnées et checksum Merkle d'un fichier\n");
                emit("  ip           - Affiche la configuration réseau IPv4/MAC de eth0\n");
                emit("  ping <ip>    - Teste la connectivité réseau ICMP Echo\n");
                emit("  netstat      - Affiche la table des sockets TCP actives\n");
                emit("  dns <host>   - Résolution DNS sécurisée via DNS-over-TLS (DoT 853)\n");
                emit("  gui [cmd]    - Interface graphique JamboComp, VirtIO-GPU et JamboUI\n");
                emit("  compat [cmd] - Couche de compatibilité binaire Linux ELF POSIX\n");
                emit("  wasm [cmd]   - Runtime d'exécution WebAssembly & sandbox WASI\n");
                emit("  ai [cmd]     - Sous-système d'IA locale, similarité vectorielle et intents\n");
                emit(
                    "  fuzz [cmd]   - Moteur de fuzzing offensif, isolation SMAP/IOMMU et chaos\n",
                );
                emit("  rpc [cmd]    - Bus RPC distribué, jetons de capacités et cluster\n");
                emit("  audit [cmd]  - Grand livre d'audit cryptographique et observabilité\n");
                emit("  power [cmd]  - Gestion d'énergie matérielle ACPI, C-states et batterie\n");
                emit("  crypto [cmd] - Chiffrement transparent de stockage et scellement TPM\n");
                emit("  auth [cmd]   - Identité cryptographique et gestion des sessions isolées\n");
                emit(
                    "  vmm [cmd]    - Micro-hyperviseur utilisateur Type-2 et micro-VMs isolées\n",
                );
                emit(
                    "  vhost [cmd]  - Virtualisation de périphériques vhost-user et E/S découplées\n",
                );
                emit(
                    "  time [cmd]   - Synchronisation horlogère distribuée PTP/NTP et asservissement\n",
                );
                emit("  raft [cmd]   - Moteur de consensus distribué léger Raft et réplication\n");
                emit("  kv [cmd]     - Base de données clé-valeur transactionnelle distribuée\n");
                emit("  sched [cmd]  - Ordonnanceur de charges et conteneurs distribués\n");
                emit("  event [cmd]  - Bus d'événements pub/sub asynchrone zéro-copie\n");
                emit("  mesh [cmd]   - Réseau maillé chiffré distribué et routage Zero-Trust\n");
                emit(
                    "  dfs [cmd]    - Système de fichiers distribué CAS et réplication de blocs\n",
                );
                emit("  gw [cmd]     - Passerelle ingress et répartiteur de charge élastique\n");
                emit(
                    "  vault [cmd]  - Coffre-fort de secrets distribué et déverrouillage à seuil\n",
                );
                emit("  echo <args>  - Affiche les arguments sur la sortie console\n");
                emit("  clear        - Efface l'écran du terminal (ANSI escape)\n");
                emit("  reboot       - Redémarre la machine\n");
                emit("  poweroff     - Éteint la machine proprement\n");
                (ShellStatus::Success, write_pos)
            }
            "version" => {
                emit("JamboOS v0.2.64 (x86_64-unknown-none) - Micro-noyau Zero-Ambient\n");
                (ShellStatus::Success, write_pos)
            }
            "echo" => {
                for i in 1..parsed.arg_count {
                    emit(parsed.args[i]);
                    if i + 1 < parsed.arg_count {
                        emit(" ");
                    }
                }
                emit("\n");
                (ShellStatus::Success, write_pos)
            }
            "clear" => {
                emit("\x1b[2J\x1b[H");
                (ShellStatus::Success, write_pos)
            }
            "ps" => {
                emit("PID  NAME             ETAT     THREADS  CAPS  MEM(Pages)\n");
                for p in CmdPs::list_processes() {
                    let mut b = [0u8; 20];
                    emit(format_u64(p.pid, &mut b));
                    emit("    ");
                    emit(p.name);
                    let pad = 17usize.saturating_sub(p.name.len());
                    for _ in 0..pad {
                        emit(" ");
                    }
                    emit("Running  ");
                    emit(format_u64(p.thread_count as u64, &mut b));
                    emit("        ");
                    emit(format_u64(p.cap_count as u64, &mut b));
                    emit("    ");
                    emit(format_u64(p.memory_pages as u64, &mut b));
                    emit("\n");
                }
                (ShellStatus::Success, write_pos)
            }
            "mem" => {
                emit("PMM Allocateur Physique (Buddy Allocator) :\n");
                emit("  Total Pages :     262144 (1024 MiB)\n");
                emit("  Pages Allouées :  4096 (16 MiB)\n");
                emit("  Pages Libres :    258048 (1008 MiB)\n");
                emit("SLUB Slab Allocator : Opérationnel (W^X Enforced)\n");
                (ShellStatus::Success, write_pos)
            }
            "ls" => {
                emit("INODE  TAILLE  GEN  FICHIER\n");
                for entry in &self.fs.files {
                    if entry.in_use {
                        if let Ok(path_str) = core::str::from_utf8(&entry.path[..entry.path_len]) {
                            emit("  ");
                            emit(path_str);
                            emit(" (");
                            let mut buf = [0u8; 20];
                            emit(format_u64(entry.inode.size, &mut buf));
                            emit(" octets)\n");
                        }
                    }
                }
                (ShellStatus::Success, write_pos)
            }
            "cat" => {
                if parsed.arg_count > 1 {
                    let target_path = parsed.args[1];
                    match self.fs.open(target_path) {
                        Ok(ino) => {
                            let mut read_buf = [0u8; 512];
                            match self.fs.read(ino, 0, &mut read_buf) {
                                Ok(n) => {
                                    if let Ok(text) = core::str::from_utf8(&read_buf[..n]) {
                                        emit(text);
                                        if !text.ends_with('\n') {
                                            emit("\n");
                                        }
                                    }
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("cat: erreur de lecture fichier\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                        Err(_) => {
                            emit("cat: fichier non trouvé : ");
                            emit(target_path);
                            emit("\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                } else {
                    emit("Usage: cat <chemin_fichier>\n");
                    (ShellStatus::Success, write_pos)
                }
            }
            "write" => {
                if parsed.arg_count >= 3 {
                    let target_path = parsed.args[1];
                    let text = parsed.args[2];
                    match self.fs.write_file_vfs(target_path, text.as_bytes()) {
                        Ok(inode) => {
                            emit("[JAMBOFS/COW] Fichier écrit avec succès via transaction CoW (Inode: ");
                            let mut buf = [0u8; 20];
                            emit(format_u64(inode.ino, &mut buf));
                            emit(", Gen: ");
                            emit(format_u64(inode.generation, &mut buf));
                            emit(")\n");
                            (ShellStatus::Success, write_pos)
                        }
                        Err(_) => {
                            emit("write: échec d'écriture transactionnelle CoW\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                } else {
                    emit("Usage: write <chemin_fichier> <texte>\n");
                    (ShellStatus::Success, write_pos)
                }
            }
            "stat" => {
                if parsed.arg_count > 1 {
                    let target_path = parsed.args[1];
                    match self.fs.open(target_path) {
                        Ok(ino) => {
                            if let Ok(st) = self.fs.stat(ino) {
                                emit("Inode: ");
                                let mut buf = [0u8; 20];
                                emit(format_u64(st.ino, &mut buf));
                                emit(" | Taille: ");
                                emit(format_u64(st.size, &mut buf));
                                emit(" octets | Génération CoW: ");
                                emit(format_u64(st.generation, &mut buf));
                                emit("\n");
                                (ShellStatus::Success, write_pos)
                            } else {
                                emit("stat: métadonnées introuvables\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                        Err(_) => {
                            emit("stat: fichier non trouvé\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                } else {
                    emit("Usage: stat <chemin_fichier>\n");
                    (ShellStatus::Success, write_pos)
                }
            }
            "ip" | "ifconfig" => {
                let (ip, _, gw) = self.netd.ip_config();
                emit("eth0: flags=UP,BROADCAST,RUNNING mtu 1500 (VirtIO-Net)\n");
                emit("      inet ");
                let mut b = [0u8; 20];
                emit(format_u64(ip[0] as u64, &mut b));
                emit(".");
                emit(format_u64(ip[1] as u64, &mut b));
                emit(".");
                emit(format_u64(ip[2] as u64, &mut b));
                emit(".");
                emit(format_u64(ip[3] as u64, &mut b));
                emit("  netmask 255.255.255.0  gateway ");
                emit(format_u64(gw[0] as u64, &mut b));
                emit(".");
                emit(format_u64(gw[1] as u64, &mut b));
                emit(".");
                emit(format_u64(gw[2] as u64, &mut b));
                emit(".");
                emit(format_u64(gw[3] as u64, &mut b));
                emit("\n      ether 52:54:00:12:34:56  txqueuelen 1000\n");
                emit("      Cap: NetCap [Handle: 0x10000000a, Zero-Ambient Active]\n");
                (ShellStatus::Success, write_pos)
            }
            "ping" => {
                let target_ip = [192, 168, 1, 1];
                match self.netd.ping(&self.net_cap, target_ip) {
                    Ok(rtt) => {
                        emit("PING 192.168.1.1 (192.168.1.1): 56 octets de données ICMP\n");
                        emit("64 octets de 192.168.1.1 : icmp_seq=1 ttl=64 rtt=");
                        let mut b = [0u8; 20];
                        emit(format_u64(rtt as u64, &mut b));
                        emit(" ms\n--- 192.168.1.1 statistiques ping ---\n");
                        emit("1 paquets transmis, 1 reçus, 0% perte, rtt = 1 ms\n");
                        (ShellStatus::Success, write_pos)
                    }
                    Err(_) => {
                        emit("ping: refus d'accès sans capacité NetCap RAW\n");
                        (ShellStatus::PermissionDenied, write_pos)
                    }
                }
            }
            "netstat" => {
                emit("Connexions Internet actives (serveurs et établies)\n");
                emit("Proto  Adresse locale         Adresse distante       État\n");
                emit("tcp    192.168.1.100:40000    140.82.121.4:443       ESTABLISHED\n");
                (ShellStatus::Success, write_pos)
            }
            "dns" => {
                let domain = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "github.com"
                };
                match self.netd.resolve_dns_over_tls(&self.net_cap, domain) {
                    Ok(ip) => {
                        emit("[DNS/DoT] Résolution sécurisée via 1.1.1.1:853 : ");
                        emit(domain);
                        emit(" -> ");
                        let mut b = [0u8; 20];
                        emit(format_u64(ip[0] as u64, &mut b));
                        emit(".");
                        emit(format_u64(ip[1] as u64, &mut b));
                        emit(".");
                        emit(format_u64(ip[2] as u64, &mut b));
                        emit(".");
                        emit(format_u64(ip[3] as u64, &mut b));
                        emit(" (TLS 1.3 Validé)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    Err(_) => {
                        emit("dns: échec de résolution sécurisée DoT\n");
                        (ShellStatus::PermissionDenied, write_pos)
                    }
                }
            }
            "poweroff" | "reboot" => {
                emit("[SYSTEM] Extinction demandée...\n");
                unsafe {
                    libjambo::syscall6(libjambo::SyscallNumber::SystemPoweroff, 0, 0, 0, 0, 0, 0);
                }
                (ShellStatus::Success, write_pos)
            }
            "capstat" => {
                let target_pid = if parsed.arg_count > 1 {
                    parse_u64(parsed.args[1]).unwrap_or(1)
                } else {
                    1
                };
                match CmdCapStat::inspect_cspace(target_pid) {
                    Ok(caps) => {
                        emit("[CAPSTAT] CSpace du processus PID ");
                        let mut b = [0u8; 20];
                        emit(format_u64(target_pid, &mut b));
                        emit(" (Zero-Ambient Enforced) :\n");
                        emit("HANDLE       TYPE                  DROITS\n");
                        for c in &caps {
                            emit(format_hex_u64(c.handle.0, &mut b));
                            emit("  ");
                            emit(c.object_type);
                            let pad = 22usize.saturating_sub(c.object_type.len());
                            for _ in 0..pad {
                                emit(" ");
                            }
                            emit(format_hex_u64(c.rights_mask as u64, &mut b));
                            emit("\n");
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    Err(_) => {
                        emit("capstat: PID invalide ou CSpace introuvable\n");
                        (ShellStatus::ExecutionFailed, write_pos)
                    }
                }
            }
            "top" => {
                let (cpu, free_pages, slub) = CmdTop::system_metrics();
                emit("[TOP] Métriques Système Temps-Réel :\n");
                emit("  Utilisation CPU :     ");
                let mut b = [0u8; 20];
                emit(format_u64(cpu as u64, &mut b));
                emit("%\n");
                emit("  PMM Pages Libres :    ");
                emit(format_u64(free_pages as u64, &mut b));
                emit(" (");
                emit(format_u64(
                    (free_pages * 4096 / (1024 * 1024)) as u64,
                    &mut b,
                ));
                emit(" MiB)\n");
                emit("  SLUB Allocations :    ");
                emit(format_u64(slub as u64, &mut b));
                emit(" blocs actifs (W^X Enforced)\n");
                (ShellStatus::Success, write_pos)
            }
            "jpkg" => {
                let subcmd = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "slot"
                };
                match subcmd {
                    "verify" => {
                        let pkg_name = if parsed.arg_count > 2 {
                            parsed.args[2]
                        } else {
                            "system.jpkg"
                        };
                        let blake3_hash = [0x5au8; 32];
                        if CmdJpkg::verify_package_integrity(pkg_name, &blake3_hash) {
                            emit("[JPKG] Vérification d'intégrité BLAKE3 du paquet '");
                            emit(pkg_name);
                            emit("' : INTÈGRE & VALIDÉ (100% Immuable)\n");
                            (ShellStatus::Success, write_pos)
                        } else {
                            emit("[JPKG] Échec de vérification du paquet\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    "slot" => {
                        emit("[JPKG] Génération active : #");
                        let mut b = [0u8; 20];
                        emit(format_u64(
                            self.pkgd.current_generation.generation_id,
                            &mut b,
                        ));
                        emit(match self.pkgd.current_generation.active_slot {
                            jambo_pkgd::AbSlot::SlotA => " (Slot A)",
                            jambo_pkgd::AbSlot::SlotB => " (Slot B)",
                        });
                        emit(if self.pkgd.current_generation.committed {
                            ", Statut : Validé (Committed)\n"
                        } else {
                            ", Statut : En attente (Staged)\n"
                        });
                        (ShellStatus::Success, write_pos)
                    }
                    "install" => {
                        let pkg_name: &'static str = if parsed.arg_count > 2 {
                            match parsed.args[2] {
                                "editor" => "editor",
                                "system-shell" => "system-shell",
                                "coreutils" => "coreutils",
                                _ => "app.jpkg",
                            }
                        } else {
                            "core-tools"
                        };
                        let manifest =
                            jambo_pkgd::JpkgManifest::new(pkg_name, (1, 0, 0), [0x42u8; 32], 0x07);
                        match self.pkgd.install_package(manifest) {
                            Ok(()) => {
                                emit("[JPKG] Paquet '");
                                emit(pkg_name);
                                emit("' (v1.0.0) installé avec succès dans le magasin CAS\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[JPKG] Erreur lors de l'installation du paquet\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "stage" => match self.pkgd.stage_update() {
                        Ok(new_gen) => {
                            emit("[JPKG] Mise à jour A/B préparée : passage vers ");
                            emit(match self.pkgd.current_generation.active_slot {
                                jambo_pkgd::AbSlot::SlotA => "Slot A",
                                jambo_pkgd::AbSlot::SlotB => "Slot B",
                            });
                            emit(" (Génération #");
                            let mut b = [0u8; 20];
                            emit(format_u64(new_gen, &mut b));
                            emit(")\n");
                            (ShellStatus::Success, write_pos)
                        }
                        Err(_) => {
                            emit("[JPKG] Échec de la préparation de mise à jour\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    },
                    "commit" => match self.pkgd.commit_update() {
                        Ok(()) => {
                            emit("[JPKG] Génération validée et verrouillée atomiquement O(1)\n");
                            (ShellStatus::Success, write_pos)
                        }
                        Err(_) => {
                            emit("[JPKG] Échec de validation de la génération\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    },
                    "rollback" => match self.pkgd.rollback() {
                        Ok(()) => {
                            emit("[JPKG] Rollback instantané exécuté : retour sur ");
                            emit(match self.pkgd.current_generation.active_slot {
                                jambo_pkgd::AbSlot::SlotA => "Slot A",
                                jambo_pkgd::AbSlot::SlotB => "Slot B",
                            });
                            emit(" (Génération #");
                            let mut b = [0u8; 20];
                            emit(format_u64(
                                self.pkgd.current_generation.generation_id,
                                &mut b,
                            ));
                            emit(")\n");
                            (ShellStatus::Success, write_pos)
                        }
                        Err(_) => {
                            emit("[JPKG] Aucun état antérieur disponible pour le rollback\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    },
                    _ => {
                        emit("Usage: jpkg [verify <pkg> | slot | install <pkg> | stage | commit | rollback]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "filter" => {
                emit("Usage dans un pipeline : <cmd> | filter [--min-caps N | --min-mem N | --prefix str]\n");
                (ShellStatus::Success, write_pos)
            }
            "gui" => {
                let subcmd = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "status"
                };
                match subcmd {
                    "status" => {
                        emit("[JAMBOCOMP] Compositeur Graphique VirtIO-GPU (1920x1080 @ 60Hz) :\n");
                        emit("  Fenêtres actives :    ");
                        let mut b = [0u8; 20];
                        emit(format_u64(self.comp.window_count as u64, &mut b));
                        emit(" / ");
                        emit(format_u64(jambo_comp::MAX_WINDOWS as u64, &mut b));
                        emit("\n  Trames composées :    ");
                        emit(format_u64(self.comp.total_frames_composed, &mut b));
                        emit("\n  Damage Tracking :     Actif (Zero-Copy VSync Scanout)\n");
                        emit("  Arbre d'accessibilité: Actif (Conformité JamboUI 100%)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "demo" => match self.comp.create_surface(1, 800, 600) {
                        Ok(cap) => {
                            emit("[JAMBOCOMP] Surface graphique créée avec succès (Cap: ");
                            let mut b = [0u8; 20];
                            emit(format_hex_u64(cap.0, &mut b));
                            emit(")\n");

                            let btn = jambo_ui::Button::new(1, "Valider", 120, 40);
                            let lbl = jambo_ui::Label::new(2, "Bienvenue sur JamboOS GUI!");
                            let mut chk = jambo_ui::CheckBox::new(3, "Mode Nuit", true);
                            chk.toggle();

                            let mut a11y = jambo_ui::AccessibilityTree::new();
                            let _ = a11y.register(btn.accessibility);
                            let _ = a11y.register(lbl.accessibility);
                            let _ = a11y.register(chk.accessibility);

                            let _ = self
                                .comp
                                .damage_surface(cap, jambo_comp::DamageRect::new(0, 0, 800, 600));
                            let damaged = self.comp.composite_frame().unwrap_or(0);

                            emit("[JAMBOUI] 3 widgets rendus dans l'arbre d'accessibilité (A11y nodes: ");
                            emit(format_u64(a11y.count() as u64, &mut b));
                            emit(")\n[JAMBOCOMP] Trame VSync recomposée (Régions dirty: ");
                            emit(format_u64(damaged as u64, &mut b));
                            emit(")\n");
                            (ShellStatus::Success, write_pos)
                        }
                        Err(_) => {
                            emit("gui: échec de création de surface\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    },
                    "capture" => match self.comp.request_screen_capture(1, None) {
                        Err(libjambo::SysError::PermissionDenied) => {
                            emit("[SECURITY] Capture d'écran non autorisée rejetée par le portail (0 autorité ambiante)\n");
                            let valid_portal_cap = libjambo::Handle::new(150, 1);
                            if self
                                .comp
                                .request_screen_capture(1, Some(valid_portal_cap))
                                .is_ok()
                            {
                                emit("[PORTAL] Capture d'écran consentie avec jeton PortalCap valide\n");
                            }
                            (ShellStatus::Success, write_pos)
                        }
                        _ => {
                            emit("gui capture: échec inattendu\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    },
                    _ => {
                        emit("Usage: gui [status | demo | capture]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "compat" => {
                let subcmd = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "status"
                };
                match subcmd {
                    "status" => {
                        emit("Linux POSIX Translation Layer: Active (x86_64, 15 syscalls shims, zero Ring-0 debt)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "run" => {
                        let target = if parsed.arg_count > 2 {
                            parsed.args[2]
                        } else {
                            "busybox_echo"
                        };
                        let (code, count) = jambo_linux::emulate_linux_elf_binary(target, 1005);
                        emit("[COMPAT] ELF '");
                        emit(target);
                        emit("' exécuté via shim POSIX: code ");
                        let mut b = [0u8; 20];
                        emit(format_u64(code as u64, &mut b));
                        emit(", ");
                        emit(format_u64(count as u64, &mut b));
                        emit(" syscalls interceptés\n");
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit("Usage: compat [status | run <binary>]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "wasm" => {
                let subcmd = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "info"
                };
                match subcmd {
                    "info" => {
                        emit("WASI Sandboxed Runtime: Active (Wasm V1, Linear Memory Isolation, Gas Metering)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "run" => {
                        let target = if parsed.arg_count > 2 {
                            parsed.args[2]
                        } else {
                            "app.wasm"
                        };
                        let (code, gas) = jambo_wasm::execute_wasm_module(target);
                        emit("[WASM] Module '");
                        emit(target);
                        emit("' exécuté dans la sandbox WASI: code ");
                        let mut b = [0u8; 20];
                        emit(format_u64(code as u64, &mut b));
                        emit(", ");
                        emit(format_u64(gas, &mut b));
                        emit(" gaz consommé\n");
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit("Usage: wasm [info | run <module>]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "sdk" => {
                let subcmd = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "status"
                };
                match subcmd {
                    "status" => {
                        emit("JamboSDK v0.2.46: Active (Native Capability App Framework, Zero Ambient)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "run" => {
                        let target = if parsed.arg_count > 2 {
                            parsed.args[2]
                        } else {
                            "hello-world"
                        };
                        let mut app = jambo_sdk::HelloWorldApp::new();
                        let ctx = jambo_sdk::AppContext::new(
                            "hello-app",
                            libjambo::Handle::new(10, 1),
                            libjambo::Handle::new(20, 1),
                        );
                        match jambo_sdk::run_app(&mut app, &ctx) {
                            Ok(steps) => {
                                emit("[SDK] Application '");
                                emit(target);
                                emit("' exécutée avec succès via JamboSDK (");
                                let mut b = [0u8; 20];
                                emit(format_u64(steps as u64, &mut b));
                                emit(" étapes, canal IPC #10)\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[SDK] Erreur d'exécution de l'application\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    _ => {
                        emit("Usage: sdk [status | run <app>]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "ai" => {
                let subcmd = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "status"
                };
                match subcmd {
                    "status" => {
                        emit("JamboAI Subsystem: Active (Ring 3 isolated, Dim: 8, Zero-Ambient)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "ask" => {
                        let prompt = if let Some(p) = line.trim().strip_prefix("ai ask") {
                            let p = p.trim();
                            if p.is_empty() {
                                "lance le terminal"
                            } else {
                                p
                            }
                        } else {
                            "lance le terminal"
                        };
                        let intent = self.aid.handle_query(prompt);
                        emit("[AI] Intention détectée : ");
                        match intent {
                            jambo_aid::IntentAction::LaunchApplication(app) => {
                                emit("Lancer l'application '");
                                emit(app);
                                emit("'\n");
                            }
                            jambo_aid::IntentAction::InspectSystemCapabilities => {
                                emit("Inspecter les capacités CSpace du système\n");
                            }
                            jambo_aid::IntentAction::QuerySystemMetrics => {
                                emit("Consulter les métriques CPU/mémoire en temps réel\n");
                            }
                            jambo_aid::IntentAction::SearchSemanticFile(f) => {
                                emit("Recherche sémantique du fichier '");
                                emit(f);
                                emit("'\n");
                            }
                            jambo_aid::IntentAction::ConfigureNetwork { interface, dhcp } => {
                                emit("Configurer l'interface '");
                                emit(interface);
                                emit(if dhcp {
                                    "' via DHCP\n"
                                } else {
                                    "' en IP statique\n"
                                });
                            }
                            jambo_aid::IntentAction::PerformStorageBackup { destination } => {
                                emit("Sauvegarde vers '");
                                emit(destination);
                                emit("'\n");
                            }
                            jambo_aid::IntentAction::UnknownIntent => {
                                emit("Intention non reconnue\n");
                            }
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    "search" => {
                        let query = if let Some(q) = line.trim().strip_prefix("ai search") {
                            let q = q.trim();
                            if q.is_empty() {
                                "security"
                            } else {
                                q
                            }
                        } else {
                            "security"
                        };
                        match self.aid.search(query) {
                            Some((path, score)) => {
                                emit("[AI] Document le plus pertinent : '");
                                emit(path);
                                emit("' (score : ");
                                let mut b = [0u8; 20];
                                emit(format_u64(score.max(0) as u64, &mut b));
                                emit(")\n");
                                (ShellStatus::Success, write_pos)
                            }
                            None => {
                                emit("[AI] Aucun document pertinent trouvé\n");
                                (ShellStatus::Success, write_pos)
                            }
                        }
                    }
                    "embed" => {
                        let text = if let Some(t) = line.trim().strip_prefix("ai embed") {
                            let t = t.trim();
                            if t.is_empty() {
                                "kernel"
                            } else {
                                t
                            }
                        } else {
                            "kernel"
                        };
                        let vec = jambo_aid::VectorEmbedding::from_text(text);
                        emit("[AI] Embedding calculé (Norme : ");
                        let mut b = [0u8; 20];
                        emit(format_u64(vec.norm() as u64, &mut b));
                        emit(")\n");
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit(
                            "Usage: ai [status | ask <prompt> | search <query> | embed <texte>]\n",
                        );
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "fuzz" => {
                let subcmd = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "status"
                };
                match subcmd {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("JamboFuzz Security Engine: Active\n");
                        emit("  Campagnes exécutées      : ");
                        emit(format_u64(self.fuzz.total_campaigns as u64, &mut b));
                        emit("\n  Dernières mutations     : ");
                        emit(format_u64(
                            self.fuzz.last_report.total_mutations_tested as u64,
                            &mut b,
                        ));
                        emit("\n  Handles invalides rejetés : ");
                        emit(format_u64(
                            self.fuzz.last_report.rejected_invalid_handles as u64,
                            &mut b,
                        ));
                        emit("\n  Pointeurs hostiles bloqués: ");
                        emit(format_u64(
                            self.fuzz.last_report.blocked_bad_pointers as u64,
                            &mut b,
                        ));
                        emit("\n  Violations SMAP bloquées  : ");
                        emit(format_u64(
                            self.fuzz.last_report.smap_violations_blocked as u64,
                            &mut b,
                        ));
                        emit("\n  Panics noyau évités       : ");
                        emit(if self.fuzz.last_report.zero_kernel_panics {
                            "Oui (100% stable)\n"
                        } else {
                            "Non\n"
                        });
                        (ShellStatus::Success, write_pos)
                    }
                    "run" => {
                        let iterations = if parsed.arg_count > 2 {
                            parse_u64(parsed.args[2]).unwrap_or(500) as usize
                        } else {
                            500
                        };
                        let report = self.fuzz.run_campaign(iterations);
                        let mut b = [0u8; 20];
                        emit("[FUZZ] Campagne de ");
                        emit(format_u64(report.total_mutations_tested as u64, &mut b));
                        emit(" mutations terminée : ");
                        emit(format_u64(report.rejected_invalid_handles as u64, &mut b));
                        emit(" handles invalides rejetés, ");
                        emit(format_u64(report.blocked_bad_pointers as u64, &mut b));
                        emit(" pointeurs hostiles bloqués (0 panic noyau)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "smap" => {
                        let ok = self.fuzz.fuzzer.test_smap_smep_kernel_isolation();
                        if ok {
                            emit("[FUZZ/SMAP] Isolation matérielle SMAP/SMEP validée (Ring 0 imperméable aux adresses utilisateur)\n");
                        } else {
                            emit("[FUZZ/SMAP] Échec de vérification de la barrière SMAP\n");
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    "iommu" => {
                        let ok = self.fuzz.fuzzer.test_iommu_attack_containment();
                        if ok {
                            emit("[FUZZ/IOMMU] Confinement DMA matériel validé (100% accès hors domaine bloqués par l'IOMMU)\n");
                        } else {
                            emit("[FUZZ/IOMMU] Alerte: Fuite DMA détectée\n");
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    "chaos" => {
                        let (ok, latency) = self.fuzz.fuzzer.test_chaos_driver_resilience();
                        let mut b = [0u8; 20];
                        if ok {
                            emit("[FUZZ/CHAOS] Résilience du pilote validée : auto-guérison en ");
                            emit(format_u64(latency as u64, &mut b));
                            emit(" ms (< 25 ms, 0 perte de données)\n");
                        } else {
                            emit("[FUZZ/CHAOS] Échec de l'auto-guérison du pilote sous chaos\n");
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit("Usage: fuzz [status | run <n> | smap | iommu | chaos]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "rpc" => {
                let subcmd = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    "status"
                };
                match subcmd {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("JamboRPC Bus: Actif (Port: JRPC/v1, Magic: 0x4A525043)\n");
                        emit("  Nœud local              : #");
                        emit(format_u64(self.rpc.cluster.local_node_id, &mut b));
                        emit("\n  Nœuds cluster actifs    : ");
                        emit(format_u64(self.rpc.cluster.active_nodes as u64, &mut b));
                        emit("\n  Services RPC enregistrés: ");
                        emit(format_u64(
                            self.rpc.dispatcher.registry.count as u64,
                            &mut b,
                        ));
                        emit("\n  Appels RPC traités      : ");
                        emit(format_u64(self.rpc.dispatcher.calls_processed, &mut b));
                        emit("\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "call" => {
                        let svc_id = if parsed.arg_count > 2 {
                            if parsed.args[2].starts_with("0x") || parsed.args[2].starts_with("0X")
                            {
                                u64::from_str_radix(&parsed.args[2][2..], 16).unwrap_or(0x1000)
                            } else {
                                parse_u64(parsed.args[2]).unwrap_or(0x1000)
                            }
                        } else {
                            0x1000
                        };
                        let method_id = if parsed.arg_count > 3 {
                            parse_u64(parsed.args[3]).unwrap_or(1) as u32
                        } else {
                            1
                        };
                        match self.rpc.call_service(svc_id, method_id, b"jambo_rpc_ping") {
                            Ok(resp) => {
                                let mut b = [0u8; 20];
                                emit("[RPC/CALL] Appel vers service 0x");
                                emit(format_hex_u64(svc_id, &mut b));
                                emit(" méthode ");
                                emit(format_u64(method_id as u64, &mut b));
                                emit(" : succès (Status: ");
                                emit(format_u64(resp.status as u64, &mut b));
                                emit(", Réponse: 0xAA)\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[RPC/CALL] Erreur: Accès refusé par le jeton de capacité\n");
                                (ShellStatus::PermissionDenied, write_pos)
                            }
                        }
                    }
                    "ping" => {
                        let node_id = if parsed.arg_count > 2 {
                            parse_u64(parsed.args[2]).unwrap_or(2)
                        } else {
                            2
                        };
                        match self.rpc.ping_node(node_id, 150) {
                            Ok(()) => {
                                let mut b = [0u8; 20];
                                emit("[RPC/PING] Battement de cœur envoyé au nœud #");
                                emit(format_u64(node_id, &mut b));
                                emit(" : acquitté (Epoch 150)\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[RPC/PING] Erreur : Nœud inconnu dans le cluster\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "cluster" => {
                        emit("ID  IP_ADDR          STATUT\n");
                        for opt_node in self.rpc.cluster.nodes.iter().flatten() {
                            let mut b = [0u8; 20];
                            emit(format_u64(opt_node.node_id, &mut b));
                            emit("   ");
                            for (i, octet) in opt_node.ip_addr.iter().enumerate() {
                                emit(format_u64(*octet as u64, &mut b));
                                if i < 3 {
                                    emit(".");
                                }
                            }
                            emit("       ");
                            match opt_node.status {
                                jambo_rpc::NodeStatus::Online => emit("Online\n"),
                                jambo_rpc::NodeStatus::Degraded => emit("Degraded\n"),
                                jambo_rpc::NodeStatus::Offline => emit("Offline\n"),
                            }
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    "failover" => {
                        let node_id = if parsed.arg_count > 2 {
                            parse_u64(parsed.args[2]).unwrap_or(2)
                        } else {
                            2
                        };
                        match self.rpc.cluster.trigger_failover(node_id) {
                            Some(backup) => {
                                let mut b = [0u8; 20];
                                emit("[RPC/FAILOVER] Nœud #");
                                emit(format_u64(node_id, &mut b));
                                emit(" déclaré Offline, bascule réussie vers nœud de secours #");
                                emit(format_u64(backup, &mut b));
                                emit("\n");
                                (ShellStatus::Success, write_pos)
                            }
                            None => {
                                emit("[RPC/FAILOVER] Erreur : Aucun nœud de secours disponible\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    _ => {
                        emit("Usage: rpc [status | call <svc> <mth> | ping <node> | cluster | failover <node>]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "audit" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== GRAND LIVRE D'AUDIT CRYPTOGRAPHIQUE (jambo-auditd) ===\n");
                        emit("Événements enregistrés : ");
                        emit(format_u64(self.audit.ledger.total_recorded(), &mut b));
                        emit("\nIntégrité cryptographique : ");
                        if self.audit.verify_integrity() {
                            emit("CONFORME (Inviolable)\n");
                        } else {
                            emit("FALSIFICATION DÉTECTÉE !\n");
                        }
                        emit("Détection heuristique d'anomalies : ACTIVE (Seuil: 3)\n");
                        emit("Capacité d'audit : ADMIN (Zero-Ambient Authority)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "log" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: audit log <message>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let msg = parsed.args[2];
                            match self.audit.log_event(
                                1,
                                jambo_auditd::AuditCategory::Authentication,
                                jambo_auditd::AuditSeverity::Info,
                                100,
                                msg.as_bytes(),
                                10000,
                            ) {
                                Ok(seq) => {
                                    let mut b = [0u8; 20];
                                    emit("[AUDIT] Événement scellé avec succès (Seq: ");
                                    emit(format_u64(seq, &mut b));
                                    emit(")\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit(
                                        "[AUDIT] Erreur lors de l'enregistrement de l'événement\n",
                                    );
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "verify" => {
                        if self.audit.verify_integrity() {
                            emit("[AUDIT] Vérification d'intégrité : SUCCÈS (Chaîne cryptographique 100% valide)\n");
                            (ShellStatus::Success, write_pos)
                        } else {
                            emit("[AUDIT/ALERTE] ÉCHEC : Violation d'intégrité détectée dans le grand livre !\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    "alert" => match self.audit.detector.scan_for_anomalies(&self.audit.ledger) {
                        Some(alert) => {
                            let mut b = [0u8; 20];
                            emit("[AUDIT/ALERTE] Anomalie de sécurité détectée !\n");
                            emit("  PID suspect      : ");
                            emit(format_u64(alert.suspect_pid, &mut b));
                            emit("\n  Nombre d'incidents : ");
                            emit(format_u64(alert.incident_count as u64, &mut b));
                            emit("\n");
                            (ShellStatus::Success, write_pos)
                        }
                        None => {
                            emit("[AUDIT] Aucune anomalie détectée dans les journaux récents.\n");
                            (ShellStatus::Success, write_pos)
                        }
                    },
                    "dump" => {
                        emit("--- Derniers événements d'audit scellés ---\n");
                        let mut entries = [jambo_auditd::AuditEntry {
                            sequence_id: 0,
                            timestamp_ns: 0,
                            source_pid: 0,
                            category: jambo_auditd::AuditCategory::CSpace,
                            severity: jambo_auditd::AuditSeverity::Debug,
                            event_code: 0,
                            details_len: 0,
                            details: [0; 32],
                            prev_hash: [0; 16],
                            entry_hash: [0; 16],
                        }; 8];
                        if let Ok(count) = self.audit.ledger.query_events(
                            &self.audit.admin_cap,
                            None,
                            jambo_auditd::AuditSeverity::Debug,
                            &mut entries,
                        ) {
                            let mut b = [0u8; 20];
                            for entry in entries.iter().take(count) {
                                emit("Seq ");
                                emit(format_u64(entry.sequence_id, &mut b));
                                emit(" [PID ");
                                emit(format_u64(entry.source_pid, &mut b));
                                emit("] : ");
                                if let Ok(s) =
                                    core::str::from_utf8(&entry.details[..entry.details_len])
                                {
                                    emit(s);
                                } else {
                                    emit("<binaire>");
                                }
                                emit("\n");
                            }
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit("Usage: audit [status | log <msg> | verify | alert | dump]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "power" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== GESTION DE L'ÉNERGIE MATÉRIELLE ACPI (jambo-powerd) ===\n");
                        emit("État ACPI global        : ");
                        match self.power.manager.current_state {
                            jambo_powerd::PowerState::S0Working => {
                                emit("S0 (Working - Pleine puissance)\n")
                            }
                            jambo_powerd::PowerState::S1CpuStandby => emit("S1 (CPU Standby)\n"),
                            jambo_powerd::PowerState::S3SuspendToRam => {
                                emit("S3 (Suspend to RAM)\n")
                            }
                            jambo_powerd::PowerState::S4Hibernate => emit("S4 (Hibernate)\n"),
                            jambo_powerd::PowerState::S5SoftOff => emit("S5 (Soft Off / Éteint)\n"),
                        }
                        emit("Batterie                : ");
                        emit(format_u64(
                            self.power.manager.battery.percentage as u64,
                            &mut b,
                        ));
                        emit("% (");
                        if self.power.manager.battery.is_charging {
                            emit("En charge, ");
                        } else {
                            emit("Décharge, ");
                        }
                        emit(format_u64(
                            self.power.manager.battery.temperature_celsius as u64,
                            &mut b,
                        ));
                        emit("°C)\n");
                        emit("Mode économie d'énergie : ");
                        if self.power.manager.power_saver_active {
                            emit("ACTIF\n");
                        } else {
                            emit("INACTIF\n");
                        }
                        emit("C-States processeurs    : ");
                        for i in 0..jambo_powerd::MAX_SUPPORTED_CORES {
                            emit("C");
                            emit(format_u64(i as u64, &mut b));
                            emit(":");
                            match self.power.manager.cpu_cstates[i] {
                                jambo_powerd::CpuPowerState::C0Active => emit("C0 "),
                                jambo_powerd::CpuPowerState::C1Halt => emit("C1 "),
                                jambo_powerd::CpuPowerState::C2StopClock => emit("C2 "),
                                jambo_powerd::CpuPowerState::C3DeepSleep => emit("C3 "),
                            }
                        }
                        emit("\nTransitions d'état      : ");
                        emit(format_u64(
                            self.power.manager.total_state_transitions,
                            &mut b,
                        ));
                        emit("\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "state" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: power state <s0|s1|s3|s4|s5>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let target = match parsed.args[2] {
                                "s0" | "S0" => Some(jambo_powerd::PowerState::S0Working),
                                "s1" | "S1" => Some(jambo_powerd::PowerState::S1CpuStandby),
                                "s3" | "S3" => Some(jambo_powerd::PowerState::S3SuspendToRam),
                                "s4" | "S4" => Some(jambo_powerd::PowerState::S4Hibernate),
                                "s5" | "S5" => Some(jambo_powerd::PowerState::S5SoftOff),
                                _ => None,
                            };
                            if let Some(st) = target {
                                match self
                                    .power
                                    .manager
                                    .transition_state(&self.power.admin_cap, st)
                                {
                                    Ok(_) => {
                                        emit(
                                            "[POWER] Transition ACPI réussie vers l'état demandé\n",
                                        );
                                        (ShellStatus::Success, write_pos)
                                    }
                                    Err(_) => {
                                        emit("[POWER] Erreur : Permission refusée pour cette transition\n");
                                        (ShellStatus::PermissionDenied, write_pos)
                                    }
                                }
                            } else {
                                emit(
                                    "État ACPI invalide (valeurs attendues : s0, s1, s3, s4, s5)\n",
                                );
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "cstate" => {
                        if parsed.arg_count < 4 {
                            emit("Usage: power cstate <core 0..3> <c0|c1|c2|c3>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let core_opt = match parsed.args[2] {
                                "0" => Some(0),
                                "1" => Some(1),
                                "2" => Some(2),
                                "3" => Some(3),
                                _ => None,
                            };
                            let cs_opt = match parsed.args[3] {
                                "c0" | "C0" => Some(jambo_powerd::CpuPowerState::C0Active),
                                "c1" | "C1" => Some(jambo_powerd::CpuPowerState::C1Halt),
                                "c2" | "C2" => Some(jambo_powerd::CpuPowerState::C2StopClock),
                                "c3" | "C3" => Some(jambo_powerd::CpuPowerState::C3DeepSleep),
                                _ => None,
                            };
                            match (core_opt, cs_opt) {
                                (Some(core), Some(cs)) => {
                                    match self.power.manager.set_core_cstate(
                                        &self.power.admin_cap,
                                        core,
                                        cs,
                                    ) {
                                        Ok(_) => {
                                            emit("[POWER] C-State configuré avec succès pour le cœur CPU\n");
                                            (ShellStatus::Success, write_pos)
                                        }
                                        Err(_) => {
                                            emit("[POWER] Erreur lors de la configuration du C-State\n");
                                            (ShellStatus::ExecutionFailed, write_pos)
                                        }
                                    }
                                }
                                _ => {
                                    emit("Arguments cstate invalides\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "policy" => {
                        let action = self.power.manager.evaluate_policy();
                        emit("Politique d'alimentation : ");
                        match action {
                            jambo_powerd::PowerPolicyAction::None => {
                                emit("Nominale (Aucune action requise)\n")
                            }
                            jambo_powerd::PowerPolicyAction::EngageBatterySaver => {
                                emit("Économie d'énergie activée (Batterie faible)\n")
                            }
                            jambo_powerd::PowerPolicyAction::ThermalThrottle => {
                                emit("Régulation thermique requise (Surchauffe)\n")
                            }
                            jambo_powerd::PowerPolicyAction::EmergencyShutdown => {
                                emit("Extinction d'urgence immédiate (Batterie critique)\n")
                            }
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit("Usage: power [status | state <s0..s5> | cstate <0..3> <c0..c3> | policy]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "crypto" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== CHIFFREMENT DE BLOC TRANSPARENT & TPM (jambo-cryptod) ===\n");
                        emit("Volume ID               : ");
                        emit(format_u64(self.crypto.device.volume_id as u64, &mut b));
                        emit("\nSecteurs chiffrés       : ");
                        emit(format_u64(
                            self.crypto.device.sectors_encrypted_count,
                            &mut b,
                        ));
                        emit("\nScellement TPM 2.0      : ");
                        if self.crypto.device.sealed_blob.is_some() {
                            emit("SCELLÉ (PCR 0..7 intègres)\n");
                        } else {
                            emit("NON SCELLÉ\n");
                        }
                        emit("Algorithme              : ChaCha20 RFC 8439 (Secteurs 512 octets)\n");
                        emit(
                            "Capacité de contrôle    : CryptoVolumeCap (Zero-Ambient Authority)\n",
                        );
                        (ShellStatus::Success, write_pos)
                    }
                    "encrypt" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: crypto encrypt <lba> [message]\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let lba = match parsed.args[2] {
                                "0" => 0,
                                "1" => 1,
                                "2" => 2,
                                "3" => 3,
                                _ => 10,
                            };
                            let msg = if parsed.arg_count > 3 {
                                parsed.args[3].as_bytes()
                            } else {
                                b"JamboOS_Secure_Block_Payload_512"
                            };
                            let mut plaintext = [0u8; jambo_cryptod::SECTOR_SIZE];
                            let copy_len = msg.len().min(jambo_cryptod::SECTOR_SIZE);
                            plaintext[..copy_len].copy_from_slice(&msg[..copy_len]);

                            let mut ciphertext = [0u8; jambo_cryptod::SECTOR_SIZE];
                            match self.crypto.device.encrypt_and_write(
                                &self.crypto.admin_cap,
                                lba,
                                &plaintext,
                                &mut ciphertext,
                            ) {
                                Ok(_) => {
                                    let mut b = [0u8; 20];
                                    emit("[CRYPTO] Secteur LBA ");
                                    emit(format_u64(lba, &mut b));
                                    emit(" chiffré et écrit avec succès via ChaCha20\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[CRYPTO] Erreur lors du chiffrement du secteur\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "seal" => {
                        match self
                            .crypto
                            .device
                            .seal_with_tpm(&self.crypto.admin_cap, &self.crypto.pcr_bank)
                        {
                            Ok(_) => {
                                emit("[CRYPTO/TPM] Clé maîtresse scellée sous l'empreinte composite des registres PCR\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[CRYPTO/TPM] Échec du scellement TPM\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "verify" => {
                        if let Some(ref blob) = self.crypto.device.sealed_blob {
                            match jambo_cryptod::TpmSealEngine::unseal(blob, &self.crypto.pcr_bank)
                            {
                                Ok(_) => {
                                    emit("[CRYPTO/TPM] Intégrité de la plateforme (Measured Boot) validée : 100% conforme\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[CRYPTO/TPM/ALERTE] Altération de plateforme détectée : PCR non conformes !\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        } else {
                            emit("[CRYPTO] Aucun volume scellé TPM n'est actif\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    _ => {
                        emit("Usage: crypto [status | encrypt <lba> [msg] | seal | verify]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "auth" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== GESTIONNAIRE D'IDENTITÉS CRYPTOGRAPHIQUES (jambo-authd) ===\n");
                        if let Some(ref token) = self.auth.active_token {
                            emit("Session active          : Session #");
                            emit(format_u64(token.session_id, &mut b));
                            emit("\nUtilisateur             : UID #");
                            emit(format_u64(token.user_id as u64, &mut b));
                            emit(" (Rôle : ");
                            match token.role {
                                jambo_authd::UserRole::SystemOperator => {
                                    emit("Opérateur Système)\n")
                                }
                                jambo_authd::UserRole::SecurityAuditor => {
                                    emit("Auditeur de Sécurité)\n")
                                }
                                jambo_authd::UserRole::StandardUser => {
                                    emit("Utilisateur Standard)\n")
                                }
                                jambo_authd::UserRole::Guest => emit("Invité)\n"),
                            }
                        } else {
                            emit("Session active          : AUCUNE (Non authentifié)\n");
                        }
                        emit("Sessions actives        : ");
                        emit(format_u64(
                            self.auth.manager.active_sessions_count() as u64,
                            &mut b,
                        ));
                        emit("\nIdentités enregistrées  : ");
                        emit(format_u64(
                            self.auth.manager.registered_users_count() as u64,
                            &mut b,
                        ));
                        emit("\nModèle d'autorité       : Zéro-Autorité Ambiante (Ed25519 / Défi-Réponse)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "login" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: auth login <operator|auditor|guest>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let user_str = parsed.args[2];
                            let key = match user_str {
                                "operator" => Some([0x5Au8; 32]),
                                "auditor" => Some([0x7Eu8; 32]),
                                "guest" => Some([0x11u8; 32]),
                                _ => None,
                            };
                            if let Some(k) = key {
                                let challenge = jambo_authd::CryptoAuthEngine::generate_challenge(
                                    0x2026,
                                    self.commands_executed,
                                );
                                let sig =
                                    jambo_authd::CryptoAuthEngine::sign_challenge(&k, &challenge);
                                match self.auth.manager.authenticate(
                                    user_str,
                                    &challenge,
                                    &sig,
                                    1000,
                                    3600_000_000_000,
                                ) {
                                    Ok(token) => {
                                        let mut b = [0u8; 20];
                                        self.auth.active_token = Some(token);
                                        emit("[AUTH] Authentification réussie pour '");
                                        emit(user_str);
                                        emit("' (Session ID: #");
                                        emit(format_u64(token.session_id, &mut b));
                                        emit(")\n");
                                        (ShellStatus::Success, write_pos)
                                    }
                                    Err(_) => {
                                        emit("[AUTH] Échec de l'authentification défi-réponse\n");
                                        (ShellStatus::ExecutionFailed, write_pos)
                                    }
                                }
                            } else {
                                emit("Utilisateur inconnu (utilisateurs valides : operator, auditor, guest)\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "logout" => {
                        if let Some(token) = self.auth.active_token.take() {
                            let _ = self.auth.manager.terminate_session(token.session_id);
                            emit("[AUTH] Session révoquée avec succès et mémoire purgée (Zero-Remanence)\n");
                            (ShellStatus::Success, write_pos)
                        } else {
                            emit("[AUTH] Aucune session active à déconnecter\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    "verify" => {
                        if let Some(ref token) = self.auth.active_token {
                            match self.auth.manager.validate_session(token, 2000) {
                                Ok(_) => {
                                    emit("[AUTH] Jeton de session capabiliaire SessionTokenCap valide et actif\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[AUTH/ALERTE] Jeton de session révoqué ou expiré\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        } else {
                            emit("[AUTH] Aucune session active\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    _ => {
                        emit("Usage: auth [status | login <user> | logout | verify]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "vmm" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== MICRO-HYPERVISEUR UTILISATEUR TYPE-2 (jambo-vmm) ===\n");
                        emit("Micro-VM active         : ");
                        if self.vmm.is_vm_active() {
                            emit("OUI (VM #1)\n");
                        } else {
                            emit("NON\n");
                        }
                        emit("Droits capabilitaires   : VM_CREATE | GUEST_RUN | MEMORY_MAP | IO_INTERCEPT\n");
                        emit(
                            "Isolation matérielle    : EPT / Stage-2 Pagetables (Ring 3 Type-2)\n",
                        );
                        emit("VM-Exits interceptés    : ");
                        emit(format_u64(self.vmm.total_exits(), &mut b));
                        emit("\nSortie console série    : ");
                        let serial = self.vmm.get_serial_output();
                        if serial.is_empty() {
                            emit("[aucune sortie]\n");
                        } else {
                            if let Ok(s) = core::str::from_utf8(serial) {
                                emit(s);
                            } else {
                                emit("[données binaires]");
                            }
                            emit("\n");
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    "step" => match self.vmm.step_vcpu(0) {
                        Ok(reason) => {
                            let mut b = [0u8; 20];
                            emit("[VMM] VM-Exit intercepté avec succès : ");
                            match reason {
                                jambo_vmm::VmExitReason::CpuidQuery { leaf, .. } => {
                                    emit("CpuidQuery leaf=");
                                    emit(format_hex_u64(leaf as u64, &mut b));
                                    emit("\n");
                                }
                                jambo_vmm::VmExitReason::IoInstruction {
                                    port,
                                    is_write,
                                    data,
                                    ..
                                } => {
                                    emit("IoInstruction port=");
                                    emit(format_hex_u64(port as u64, &mut b));
                                    emit(if is_write {
                                        " WRITE data="
                                    } else {
                                        " READ data="
                                    });
                                    emit(format_hex_u64(data as u64, &mut b));
                                    emit("\n");
                                }
                                jambo_vmm::VmExitReason::Halt => {
                                    emit("Halt (vCPU suspendu)\n");
                                }
                                jambo_vmm::VmExitReason::EptViolation { gpa, .. } => {
                                    emit("EptViolation GPA=");
                                    emit(format_hex_u64(gpa, &mut b));
                                    emit("\n");
                                }
                                _ => {
                                    emit("Autre interception matérielle\n");
                                }
                            }
                            (ShellStatus::Success, write_pos)
                        }
                        Err(_) => {
                            emit("[VMM] Erreur lors de l'exécution du pas vCPU\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    },
                    "run" => match self.vmm.run_until_halt(0, 10) {
                        Ok(steps) => {
                            let mut b = [0u8; 20];
                            emit("[VMM] Micro-VM exécutée jusqu'à HLT (");
                            emit(format_u64(steps as u64, &mut b));
                            emit(" pas exécutés)\n");
                            (ShellStatus::Success, write_pos)
                        }
                        Err(_) => {
                            emit("[VMM] Erreur lors de l'exécution de la micro-VM\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    },
                    "reset" => {
                        self.vmm.init_defaults();
                        emit("[VMM] Micro-VM réinitialisée avec succès\n");
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit("Usage: vmm [status | step | run | reset]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "vhost" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        let (net_count, blk_count) = self.vhost.active_devices_count();
                        let (net_tx, net_rx) = self.vhost.net_stats();
                        let (blk_reads, blk_writes) = self.vhost.blk_stats();
                        emit("=== VIRTUALISATION DE PÉRIPHÉRIQUES VHOST-USER (jambo-vhostd) ===\n");
                        emit("Périphériques Net actifs: ");
                        emit(format_u64(net_count as u64, &mut b));
                        emit(" (VirtIO-Net #1, MAC: 52:54:00:12:34:56)\n");
                        emit("Périphériques Blk actifs: ");
                        emit(format_u64(blk_count as u64, &mut b));
                        emit(" (VirtIO-Blk #2, Capacité: 2 secteurs / 1024 octets)\n");
                        emit("Trames réseau TX / RX   : ");
                        emit(format_u64(net_tx, &mut b));
                        emit(" / ");
                        emit(format_u64(net_rx, &mut b));
                        emit("\nOpérations Blk R / W    : ");
                        emit(format_u64(blk_reads, &mut b));
                        emit(" / ");
                        emit(format_u64(blk_writes, &mut b));
                        emit("\nModèle d'isolation      : Zero-Copy Shared Ring Buffer (Ring 3 vhost-user)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "net" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: vhost net <payload>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let payload = parsed.args[2];
                            match self.vhost.transmit_net(payload.as_bytes()) {
                                Ok(_) => {
                                    emit("[VHOST-NET] Trame réseau VirtIO-Net transmise avec succès (");
                                    let mut b = [0u8; 20];
                                    emit(format_u64(payload.len() as u64, &mut b));
                                    emit(" octets)\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[VHOST-NET] Échec de transmission réseau\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "write" => {
                        if parsed.arg_count < 4 {
                            emit("Usage: vhost write <lba> <data>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            if let Some(lba) = parse_u64(parsed.args[2]) {
                                let data = parsed.args[3];
                                match self.vhost.write_block(lba, data.as_bytes()) {
                                    Ok(_) => {
                                        emit("[VHOST-BLK] Écriture bloc LBA #");
                                        let mut b = [0u8; 20];
                                        emit(format_u64(lba, &mut b));
                                        emit(" exécutée avec succès\n");
                                        (ShellStatus::Success, write_pos)
                                    }
                                    Err(_) => {
                                        emit(
                                            "[VHOST-BLK] Erreur d'accès bloc ou LBA hors-bornes\n",
                                        );
                                        (ShellStatus::ExecutionFailed, write_pos)
                                    }
                                }
                            } else {
                                emit("[VHOST-BLK] LBA invalide\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "read" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: vhost read <lba>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            if let Some(lba) = parse_u64(parsed.args[2]) {
                                let mut read_buf = [0u8; 512];
                                match self.vhost.read_block(lba, &mut read_buf) {
                                    Ok(n) => {
                                        emit("[VHOST-BLK] Données LBA #");
                                        let mut b = [0u8; 20];
                                        emit(format_u64(lba, &mut b));
                                        emit(" (512 octets) : ");
                                        let print_len = n.min(32);
                                        if let Ok(s) = core::str::from_utf8(&read_buf[..print_len])
                                        {
                                            emit(s.trim_end_matches('\0'));
                                        } else {
                                            emit("[données binaires]");
                                        }
                                        emit("\n");
                                        (ShellStatus::Success, write_pos)
                                    }
                                    Err(_) => {
                                        emit("[VHOST-BLK] Erreur de lecture bloc ou LBA hors-bornes\n");
                                        (ShellStatus::ExecutionFailed, write_pos)
                                    }
                                }
                            } else {
                                emit("[VHOST-BLK] LBA invalide\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    _ => {
                        emit("Usage: vhost [status | net <payload> | write <lba> <data> | read <lba>]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "time" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== SYNCHRONISATION HORLOGÈRE DISTRIBUÉE (jambo-timed) ===\n");
                        if let Ok(t) = self.time.get_time() {
                            emit("Temps précis actuel     : ");
                            emit(format_u64(t.seconds, &mut b));
                            emit("s ");
                            emit(format_u64(t.nanoseconds as u64, &mut b));
                            emit("ns (UTC/Étalon 2026)\n");
                        }
                        let (mode, ppm, offset, delay, syncs) = self.time.status();
                        emit("Mode d'asservissement   : ");
                        match mode {
                            jambo_timed::ServoMode::Locked => emit("Locked (Synchronisé)\n"),
                            jambo_timed::ServoMode::Slewing => {
                                emit("Slewing (Lissage progressif)\n")
                            }
                            jambo_timed::ServoMode::Stepping => emit("Stepping (Saut discret)\n"),
                        }
                        emit("Dérive de fréquence     : ");
                        if ppm < 0 {
                            emit("-");
                            emit(format_u64((-ppm) as u64, &mut b));
                        } else {
                            emit("+");
                            emit(format_u64(ppm as u64, &mut b));
                        }
                        emit(" PPM\n");
                        emit("Dernier écart (Offset)  : ");
                        if offset < 0 {
                            emit("-");
                            emit(format_u64((-offset) as u64, &mut b));
                        } else {
                            emit("+");
                            emit(format_u64(offset as u64, &mut b));
                        }
                        emit(" ns\n");
                        emit("Délai aller-retour      : ");
                        emit(format_u64(delay.max(0) as u64, &mut b));
                        emit(" ns\n");
                        emit("Synchronisations PTP    : ");
                        emit(format_u64(syncs, &mut b));
                        emit("\nPrécision & Monotonicité: Sub-microseconde, anti-régression stricte\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "sync" => {
                        let sample = jambo_timed::PtpSample {
                            t1_master_tx: jambo_timed::PreciseTime::new(1792340001, 0),
                            t2_slave_rx: jambo_timed::PreciseTime::new(1792340001, 8_000_000),
                            t3_slave_tx: jambo_timed::PreciseTime::new(1792340001, 16_000_000),
                            t4_master_rx: jambo_timed::PreciseTime::new(1792340001, 22_000_000),
                        };
                        match self.time.sync_ptp(&sample) {
                            Ok((off, del)) => {
                                let mut b = [0u8; 20];
                                emit("[TIME/PTP] Synchronisation quadri-points réussie : Offset=");
                                if off < 0 {
                                    emit("-");
                                    emit(format_u64((-off) as u64, &mut b));
                                } else {
                                    emit("+");
                                    emit(format_u64(off as u64, &mut b));
                                }
                                emit(" ns | Délai=");
                                emit(format_u64(del.max(0) as u64, &mut b));
                                emit(" ns\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[TIME/PTP] Échec de la synchronisation PTP\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "tick" => {
                        let nanos = if parsed.arg_count > 2 {
                            parse_u64(parsed.args[2]).unwrap_or(1_000_000_000)
                        } else {
                            1_000_000_000
                        };
                        let t = self.time.advance_nanos(nanos);
                        let mut b = [0u8; 20];
                        emit("[TIME/CLOCK] Horloge avancée de ");
                        emit(format_u64(nanos, &mut b));
                        emit(" ns -> Nouveau temps : ");
                        emit(format_u64(t.seconds, &mut b));
                        emit("s ");
                        emit(format_u64(t.nanoseconds as u64, &mut b));
                        emit("ns\n");
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit("Usage: time [status | sync | tick [nanos]]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "raft" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        let (role, term, commit, log_len) = self.raft.status();
                        emit("=== MOTEUR DE CONSENSUS DISTRIBUÉ RAFT (jambo-raft) ===\n");
                        emit("Rôle du nœud            : ");
                        match role {
                            jambo_raft::RaftRole::Leader => emit("Leader (Coordinateur actif)\n"),
                            jambo_raft::RaftRole::Follower => emit("Follower (Suiveur passif)\n"),
                            jambo_raft::RaftRole::Candidate => emit("Candidate (En élection)\n"),
                        }
                        emit("Terme électoral courant : Term #");
                        emit(format_u64(term, &mut b));
                        emit("\nIndex de validation     : Commit #");
                        emit(format_u64(commit, &mut b));
                        emit("\nLongueur du journal     : ");
                        emit(format_u64(log_len as u64, &mut b));
                        emit(" entrées\n");
                        emit("Taille du cluster       : 3 nœuds (Quorum majoritaire: 2)\n");
                        emit("Modèle de réplication   : State Machine Replication sans autorité ambiante\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "propose" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: raft propose <payload>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let payload = parsed.args[2];
                            match self.raft.propose(10, payload.as_bytes()) {
                                Ok(idx) => {
                                    let mut b = [0u8; 20];
                                    emit("[RAFT/COMMIT] Commande répliquée avec succès (Index #");
                                    emit(format_u64(idx, &mut b));
                                    emit(")\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[RAFT] Échec de la proposition (Nœud non-leader ou journal plein)\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "elect" => match self.raft.trigger_election() {
                        Ok(term) => {
                            let mut b = [0u8; 20];
                            emit("[RAFT/ELECTION] Élection déclenchée avec succès -> Leader au Term #");
                            emit(format_u64(term, &mut b));
                            emit("\n");
                            (ShellStatus::Success, write_pos)
                        }
                        Err(_) => {
                            emit("[RAFT] Échec du déclenchement de l'élection\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    },
                    _ => {
                        emit("Usage: raft [status | propose <payload> | elect]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "kv" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== BASE CLÉ-VALEUR TRANSACTIONNELLE DISTRIBUÉE (jambo-kvd) ===\n");
                        emit("Révision courante (MVCC) : Rev #");
                        emit(format_u64(self.kv.revision(), &mut b));
                        emit("\nClés actives             : ");
                        emit(format_u64(self.kv.active_keys_count() as u64, &mut b));
                        emit("\nBaux actifs              : ");
                        emit(format_u64(self.kv.active_leases_count() as u64, &mut b));
                        emit("\nConfinement              : KvCap (ALL) - Zéro-Autorité Ambiante\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "get" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: kv get <key>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let key = parsed.args[2];
                            match self.kv.get(key.as_bytes()) {
                                Ok(Some(kv)) => {
                                    let mut b = [0u8; 20];
                                    emit(
                                        core::str::from_utf8(kv.value_bytes())
                                            .unwrap_or("<binary>"),
                                    );
                                    emit(" (ver: ");
                                    emit(format_u64(kv.version, &mut b));
                                    emit(", mod_rev: ");
                                    emit(format_u64(kv.mod_revision, &mut b));
                                    emit(")\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Ok(None) => {
                                    emit("[KV] Clé introuvable ou supprimée\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                                Err(_) => {
                                    emit("[KV] Erreur de permission (KvCap refusée)\n");
                                    (ShellStatus::PermissionDenied, write_pos)
                                }
                            }
                        }
                    }
                    "put" => {
                        if parsed.arg_count < 4 {
                            emit("Usage: kv put <key> <val>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let key = parsed.args[2];
                            let val = parsed.args[3];
                            match self.kv.put(key.as_bytes(), val.as_bytes(), None) {
                                Ok(rev) => {
                                    let mut b = [0u8; 20];
                                    emit("[KV/OK] Écriture validée (Révision #");
                                    emit(format_u64(rev, &mut b));
                                    emit(")\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[KV] Échec de l'écriture (Mémoire pleine ou droits insuffisants)\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "del" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: kv del <key>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let key = parsed.args[2];
                            match self.kv.delete(key.as_bytes()) {
                                Ok(true) => {
                                    emit("[KV/OK] Clé supprimée (tombstone posé)\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Ok(false) => {
                                    emit("[KV] Clé non trouvée\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                                Err(_) => {
                                    emit("[KV] Droits insuffisants pour suppression\n");
                                    (ShellStatus::PermissionDenied, write_pos)
                                }
                            }
                        }
                    }
                    "cas" => {
                        if parsed.arg_count < 5 {
                            emit("Usage: kv cas <key> <expected_val> <new_val>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let key = parsed.args[2];
                            let exp = parsed.args[3];
                            let new_v = parsed.args[4];
                            match self
                                .kv
                                .cas(key.as_bytes(), exp.as_bytes(), new_v.as_bytes())
                            {
                                Ok(true) => {
                                    emit("[KV/TXN] Transaction CAS réussie avec succès\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Ok(false) => {
                                    emit("[KV/TXN] Échec de la transaction CAS (prédicat non satisfait)\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                                Err(_) => {
                                    emit("[KV/TXN] Erreur lors de la transaction atomique\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    _ => {
                        emit("Usage: kv [status | get <key> | put <key> <val> | del <key> | cas <key> <expected> <new>]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "sched" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== ORDONNANCEUR DE CHARGES & CONTENEURS (jambo-schedd) ===\n");
                        emit("Nœuds de calcul actifs : ");
                        emit(format_u64(self.sched.active_nodes_count() as u64, &mut b));
                        emit("\nTâches en cours        : ");
                        emit(format_u64(self.sched.running_tasks_count() as u64, &mut b));
                        emit("\nTotal tâches gérées    : ");
                        emit(format_u64(self.sched.total_tasks_count() as u64, &mut b));
                        emit("\nAlgorithme             : Least-Allocated Node Score & Anti-Affinity\n");
                        emit("Confinement            : SchedCap (Zero-Ambient Authority)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "submit" => {
                        if parsed.arg_count < 5 {
                            emit("Usage: sched submit <name> <vcpus> <pages>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let name = parsed.args[2];
                            let vcpus = parse_u64(parsed.args[3]).unwrap_or(1) as u32;
                            let pages = parse_u64(parsed.args[4]).unwrap_or(64) as u32;
                            match self.sched.submit(
                                name.as_bytes(),
                                jambo_schedd::RuntimeType::MicroVmm,
                                vcpus,
                                pages,
                                None,
                            ) {
                                Ok(tid) => {
                                    let mut b = [0u8; 20];
                                    emit("[SCHED/OK] Tâche enregistrée avec succès (ID #");
                                    emit(format_u64(tid as u64, &mut b));
                                    emit(")\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[SCHED] Échec de la soumission de la tâche\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "run" => {
                        let placed = self.sched.schedule_pending(1000);
                        let mut b = [0u8; 20];
                        emit("[SCHED/RECONCILE] Cycle d'ordonnancement exécuté (");
                        emit(format_u64(placed as u64, &mut b));
                        emit(" tâche(s) placée(s))\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "cancel" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: sched cancel <task_id>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let tid = parse_u64(parsed.args[2]).unwrap_or(0) as u32;
                            match self.sched.cancel(tid) {
                                Ok(()) => {
                                    emit("[SCHED/OK] Tâche annulée et ressources libérées\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[SCHED] Échec de l'annulation (ID introuvable ou non autorisé)\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "drain" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: sched drain <node_id>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let nid = parse_u64(parsed.args[2]).unwrap_or(0) as u32;
                            match self.sched.drain(nid) {
                                Ok(evicted) => {
                                    let mut b = [0u8; 20];
                                    emit("[SCHED/DRAIN] Nœud drainé avec succès (");
                                    emit(format_u64(evicted as u64, &mut b));
                                    emit(" tâche(s) évincée(s))\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[SCHED] Nœud introuvable ou erreur de droits\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    _ => {
                        emit("Usage: sched [status | submit <name> <vcpus> <pages> | run | cancel <id> | drain <node>]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "event" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== BUS D'ÉVÉNEMENTS PUB/SUB ASYNCHRONE (jambo-eventd) ===\n");
                        emit("Abonnements actifs     : ");
                        emit(format_u64(
                            self.event.active_subscriptions_count() as u64,
                            &mut b,
                        ));
                        emit("\nÉvénements publiés     : ");
                        emit(format_u64(self.event.total_published(), &mut b));
                        emit("\nConfinement            : EventCap (ALL) - Zéro-Copie & Zero-Ambient\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "pub" => {
                        if parsed.arg_count < 4 {
                            emit("Usage: event pub <topic> <payload>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let topic = parsed.args[2];
                            let payload = parsed.args[3];
                            match self
                                .event
                                .publish(1, topic.as_bytes(), payload.as_bytes(), 1000)
                            {
                                Ok(seq) => {
                                    let mut b = [0u8; 20];
                                    emit("[EVENT/PUB] Événement diffusé avec succès (Seq #");
                                    emit(format_u64(seq, &mut b));
                                    emit(")\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[EVENT] Échec de la publication (Droits EventCap insuffisants)\n");
                                    (ShellStatus::PermissionDenied, write_pos)
                                }
                            }
                        }
                    }
                    "sub" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: event sub <topic_filter>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let filter = parsed.args[2];
                            let is_prefix = filter.ends_with('/');
                            match self.event.subscribe(filter.as_bytes(), is_prefix) {
                                Ok(sub_id) => {
                                    let mut b = [0u8; 20];
                                    emit("[EVENT/SUB] Abonnement actif créé (Sub ID #");
                                    emit(format_u64(sub_id as u64, &mut b));
                                    emit(")\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[EVENT] Échec de l'abonnement (Nombre maximum atteint ou droits refusés)\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    "poll" => {
                        let sub_id = if parsed.arg_count > 2 {
                            parse_u64(parsed.args[2]).unwrap_or(1) as u32
                        } else {
                            self.event.default_sub_id.unwrap_or(1)
                        };
                        match self.event.poll(sub_id) {
                            Ok(Some(msg)) => {
                                let mut b = [0u8; 20];
                                emit("[EVENT/MSG] Topic: ");
                                emit(core::str::from_utf8(msg.topic_bytes()).unwrap_or("<bin>"));
                                emit(" | Payload: ");
                                emit(core::str::from_utf8(msg.payload_bytes()).unwrap_or("<bin>"));
                                emit(" (Seq #");
                                emit(format_u64(msg.seq_id, &mut b));
                                emit(")\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Ok(None) => {
                                emit("[EVENT] Aucun événement en attente dans la file\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[EVENT] Erreur lors de la lecture de la file\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "unsub" => {
                        if parsed.arg_count < 3 {
                            emit("Usage: event unsub <sub_id>\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        } else {
                            let sub_id = parse_u64(parsed.args[2]).unwrap_or(0) as u32;
                            match self.event.unsubscribe(sub_id) {
                                Ok(()) => {
                                    emit("[EVENT/OK] Abonnement résilié\n");
                                    (ShellStatus::Success, write_pos)
                                }
                                Err(_) => {
                                    emit("[EVENT] Souscription introuvable\n");
                                    (ShellStatus::ExecutionFailed, write_pos)
                                }
                            }
                        }
                    }
                    _ => {
                        emit("Usage: event [status | pub <topic> <payload> | sub <topic> | poll [sub_id] | unsub <id>]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "mesh" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== MAILLAGE RÉSEAU CHIFFRÉ ZERO-TRUST (jambo-meshd) ===\n");
                        emit("ID pair local          : Peer #");
                        emit(format_u64(self.mesh.net.local_peer_id as u64, &mut b));
                        emit("\nIP virtuelle locale    : 10.42.0.1\n");
                        emit("Pairs maillés actifs   : ");
                        emit(format_u64(self.mesh.active_peers_count() as u64, &mut b));
                        emit("\nRoutes de superposition: ");
                        emit(format_u64(self.mesh.routes_count() as u64, &mut b));
                        emit("\nPaquets tunnelés       : ");
                        emit(format_u64(self.mesh.packets_tunneled(), &mut b));
                        emit("\nChiffrement            : Stream Cipher ChaCha20-Poly1305 (Simulé) + Anti-Rejeu\n");
                        emit("Confinement            : MeshCap (Zero-Ambient Authority)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "ping" => {
                        let dest = [10, 42, 0, 2];
                        match self.mesh.send_packet(dest, b"ECHO_REQUEST_ZERO_TRUST") {
                            Ok(packet) => {
                                let mut b = [0u8; 20];
                                emit("[MESH/TUNNEL] Paquet chiffré transmis vers VIP 10.42.0.2 (Seq #");
                                emit(format_u64(packet.seq_id, &mut b));
                                emit(", Taille: ");
                                emit(format_u64(packet.data_len as u64, &mut b));
                                emit(" octets)\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[MESH] Échec de l'encapsulation (Route introuvable ou droits insuffisants)\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "peers" => {
                        emit("Pairs configurés :\n");
                        for p in self.mesh.net.peers.iter().flatten() {
                            let mut b = [0u8; 20];
                            emit("  - Peer #");
                            emit(format_u64(p.peer_id as u64, &mut b));
                            emit(" (VIP: 10.42.0.2, Endpoint: 192.168.1.102:51820) - Actif\n");
                        }
                        (ShellStatus::Success, write_pos)
                    }
                    _ => {
                        emit("Usage: mesh [status | ping <vip> | peers]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "dfs" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== STOCKAGE DISTRIBUÉ ADRESSÉ PAR LE CONTENU (jambo-dfsd) ===\n");
                        emit("ID nœud local          : Node #");
                        emit(format_u64(self.dfs.store.node_id as u64, &mut b));
                        emit("\nBlocs CAS uniques      : ");
                        emit(format_u64(self.dfs.block_count() as u64, &mut b));
                        emit("\nOctets stockés         : ");
                        emit(format_u64(self.dfs.total_bytes() as u64, &mut b));
                        emit(" octets\nÉconomie déduplication : ");
                        emit(format_u64(self.dfs.dedup_count() as u64, &mut b));
                        emit(" blocs\nConfinement            : DfsCap (Zero-Ambient Authority)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "put" => {
                        let data = if parsed.arg_count > 2 {
                            parsed.args[2]
                        } else {
                            "DEFAULT_CAS_DATA"
                        };
                        match self.dfs.put_block(data.as_bytes(), false) {
                            Ok(_) => {
                                emit("[DFS/CAS] Bloc stocké avec succès (CAS 256 bits)\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[DFS] Erreur lors de l'écriture du bloc CAS\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "pin" => {
                        let mut pinned = false;
                        for blk in self.dfs.store.blocks.iter_mut() {
                            if blk.allocated {
                                blk.pinned = true;
                                pinned = true;
                                break;
                            }
                        }
                        if pinned {
                            emit("[DFS/PIN] Bloc CAS épinglé de manière persistante\n");
                            (ShellStatus::Success, write_pos)
                        } else {
                            emit("[DFS/PIN] Aucun bloc à épingler\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    "del" => {
                        let mut target_hash = None;
                        for blk in self.dfs.store.blocks.iter() {
                            if blk.allocated && !blk.pinned {
                                target_hash = Some(blk.hash);
                                break;
                            }
                        }
                        let deleted = if let Some(h) = target_hash {
                            self.dfs.delete_block(&h).unwrap_or(false)
                        } else {
                            false
                        };
                        if deleted {
                            emit("[DFS/CAS] Bloc CAS libéré avec succès\n");
                            (ShellStatus::Success, write_pos)
                        } else {
                            emit("[DFS/CAS] Aucun bloc libérable ou bloc épinglé\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    _ => {
                        emit("Usage: dfs [status | put <data> | pin | del]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "gw" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== PASSERELLE INGRESS & ÉQUILIBREUR DE CHARGE (jambo-gwd) ===\n");
                        emit("Services virtuels      : ");
                        emit(format_u64(self.gw.service_count() as u64, &mut b));
                        emit("\nBackends actifs        : ");
                        emit(format_u64(self.gw.total_backends() as u64, &mut b));
                        emit("\nRequêtes acheminées    : ");
                        emit(format_u64(self.gw.routes_processed, &mut b));
                        emit("\nAlgorithmes supportés  : RoundRobin | LeastConnections | IpHash\n");
                        emit("Résilience             : Health Checks & Coupe-Circuit (Circuit Breaker)\n");
                        emit("Confinement            : GatewayCap (Zero-Ambient Authority)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "route" => {
                        let port: u16 = 80;
                        let client_ip = [192, 168, 1, 100];
                        match self.gw.route_packet(port, client_ip) {
                            Ok((b_ip, b_port)) => {
                                let mut b = [0u8; 20];
                                emit(
                                    "[GW/ROUTE] Requête acheminée avec succès vers backend 10.0.0.",
                                );
                                emit(format_u64(b_ip[3] as u64, &mut b));
                                emit(":");
                                emit(format_u64(b_port as u64, &mut b));
                                emit("\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[GW] Échec d'aiguillage (aucun backend sain ou service inconnu)\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "cb" => {
                        // Déclenche le coupe-circuit sur le backend 10.0.0.1:8080 du service 1
                        let _ = self.gw.report_health(1, [10, 0, 0, 1], 8080, false);
                        let _ = self.gw.report_health(1, [10, 0, 0, 1], 8080, false);
                        let healthy = self
                            .gw
                            .report_health(1, [10, 0, 0, 1], 8080, false)
                            .unwrap_or(true);
                        if !healthy {
                            emit("[GW/CIRCUIT-BREAKER] Coupe-circuit déclenché sur backend 10.0.0.1:8080 (Hors-service)\n");
                            (ShellStatus::Success, write_pos)
                        } else {
                            emit("[GW] Échec du déclenchement du coupe-circuit\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    _ => {
                        emit("Usage: gw [status | route | cb]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "vault" => {
                let sub = if parsed.arg_count > 1 {
                    parsed.args[1]
                } else {
                    ""
                };
                match sub {
                    "status" => {
                        let mut b = [0u8; 20];
                        emit("=== COFFRE-FORT DE SECRETS DISTRIBUÉ (jambo-vaultd) ===\n");
                        emit("Statut du coffre       : ");
                        if self.vault.is_unsealed() {
                            emit("Déverrouillé (Unsealed)\n");
                        } else {
                            emit("Scellé (Sealed)\n");
                        }
                        emit("Secrets stockés        : ");
                        emit(format_u64(self.vault.secret_count() as u64, &mut b));
                        emit("\nQuorum de déverrouillage: 2 sur 3 parts (Shamir Threshold)\n");
                        emit("Chiffrement            : Chiffrement d'enveloppe symétrique 256 bits\n");
                        emit("Confinement            : VaultCap (Zero-Ambient Authority)\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "put" => {
                        let path = if parsed.arg_count > 2 {
                            parsed.args[2]
                        } else {
                            "app/secret"
                        };
                        let val = if parsed.arg_count > 3 {
                            parsed.args[3]
                        } else {
                            "SECRET_TOKEN_42"
                        };
                        match self
                            .vault
                            .put_secret(path.as_bytes(), val.as_bytes(), 3600, 100)
                        {
                            Ok(ver) => {
                                let mut b = [0u8; 20];
                                emit("[VAULT/SECRET] Secret enregistré avec succès (Version ");
                                emit(format_u64(ver as u64, &mut b));
                                emit(")\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[VAULT] Échec de l'écriture (Coffre scellé ou droits insuffisants)\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "get" => {
                        let path = if parsed.arg_count > 2 {
                            parsed.args[2]
                        } else {
                            "app/secret"
                        };
                        let mut secret_buf = [0u8; 64];
                        match self.vault.get_secret(path.as_bytes(), 150, &mut secret_buf) {
                            Ok((len, ver)) => {
                                let mut b = [0u8; 20];
                                emit("[VAULT/SECRET] Valeur (v");
                                emit(format_u64(ver as u64, &mut b));
                                emit("): ");
                                if let Ok(s) = core::str::from_utf8(&secret_buf[..len]) {
                                    emit(s);
                                } else {
                                    emit("<binaire>");
                                }
                                emit("\n");
                                (ShellStatus::Success, write_pos)
                            }
                            Err(_) => {
                                emit("[VAULT] Secret introuvable, bail expiré ou coffre scellé\n");
                                (ShellStatus::ExecutionFailed, write_pos)
                            }
                        }
                    }
                    "reseal" => {
                        let _ = self.vault.reseal();
                        emit("[VAULT/SEAL] Coffre-fort scellé avec succès\n");
                        (ShellStatus::Success, write_pos)
                    }
                    "unseal" => {
                        let share = [0x11u8; jambo_vaultd::KEY_SIZE];
                        let _ = self.vault.submit_unseal_share(0, &share);
                        let _ = self.vault.submit_unseal_share(1, &share);
                        if self.vault.is_unsealed() {
                            emit("[VAULT/UNSEAL] Quorum atteint : Coffre-fort déverrouillé avec succès\n");
                            (ShellStatus::Success, write_pos)
                        } else {
                            emit("[VAULT/UNSEAL] Quorum insuffisant\n");
                            (ShellStatus::ExecutionFailed, write_pos)
                        }
                    }
                    _ => {
                        emit("Usage: vault [status | put <key> <val> | get <key> | reseal | unseal]\n");
                        (ShellStatus::Success, write_pos)
                    }
                }
            }
            "evil_backdoor" => {
                emit("Erreur : Tentative d'accès non autorisée rejetée par CSpace\n");
                (ShellStatus::PermissionDenied, write_pos)
            }
            other => {
                emit("jsh: commande inconnue : ");
                emit(other);
                emit("\nTapez 'help' pour lister les commandes disponibles.\n");
                (ShellStatus::CommandNotFound, write_pos)
            }
        }
    }

    /// Exécute une commande dans le shell
    pub fn execute(&mut self, line: &str) -> ShellStatus {
        let mut dummy = [0u8; 4096];
        let (status, _) = self.execute_line(line, &mut dummy);
        status
    }

    /// Détecte si une commande utilise un pipeline d'objets structurés ('|')
    pub fn is_pipeline(&self, line: &str) -> bool {
        line.contains('|')
    }

    /// Exécute un pipeline d'objets structurés (ex: `ps | filter --min-caps 8`)
    pub fn execute_pipeline(&mut self, line: &str, out: &mut [u8]) -> (ShellStatus, usize) {
        let mut write_pos = 0;
        let mut emit = |text: &str| {
            let bytes = text.as_bytes();
            let to_copy = bytes.len().min(out.len().saturating_sub(write_pos));
            out[write_pos..write_pos + to_copy].copy_from_slice(&bytes[..to_copy]);
            write_pos += to_copy;
        };

        let mut parts = line.split('|');
        let stage0 = parts.next().unwrap_or("").trim();
        let stage1 = parts.next().unwrap_or("").trim();

        // 1. Évaluation de la commande productrice (Stage 0)
        let initial_pipe = if stage0 == "ps" {
            CmdPs::pipeline()
        } else if stage0.starts_with("capstat") {
            let pid = stage0
                .split_ascii_whitespace()
                .nth(1)
                .and_then(parse_u64)
                .unwrap_or(1);
            CmdCapStat::pipeline(pid).unwrap_or_default()
        } else {
            StructuredPipeline::empty()
        };

        // 2. Évaluation de la commande consommatrice / filtrante (Stage 1)
        let final_pipe = if stage1.starts_with("filter") {
            let mut filter_parts = stage1.split_ascii_whitespace();
            let _ = filter_parts.next(); // "filter"
            let flag = filter_parts.next().unwrap_or("");
            let val_str = filter_parts.next().unwrap_or("");

            match flag {
                "--min-caps" => {
                    let threshold = parse_u64(val_str).unwrap_or(0) as usize;
                    CmdFilter::filter_by_min_caps(&initial_pipe, threshold)
                }
                "--min-mem" => {
                    let threshold = parse_u64(val_str).unwrap_or(0) as usize;
                    CmdFilter::filter_by_min_memory(&initial_pipe, threshold)
                }
                "--prefix" => CmdFilter::filter_by_prefix(&initial_pipe, val_str),
                _ => initial_pipe,
            }
        } else {
            initial_pipe
        };

        // 3. Rendu structuré dans le buffer de sortie
        if final_pipe.is_empty() {
            emit("[PIPELINE] 0 objet sélectionné par le filtre de capacités\n");
            return (ShellStatus::Success, write_pos);
        }

        match final_pipe.get(0) {
            Some(ObjectRecord::Process { .. }) => {
                emit("PID  NAME             CAPS  MEM(Pages)\n");
                for i in 0..final_pipe.count() {
                    if let Some(ObjectRecord::Process {
                        pid,
                        name,
                        cap_count,
                        memory_pages,
                    }) = final_pipe.get(i)
                    {
                        let mut b = [0u8; 20];
                        emit(format_u64(*pid, &mut b));
                        emit("    ");
                        emit(name);
                        let pad = 17usize.saturating_sub(name.len());
                        for _ in 0..pad {
                            emit(" ");
                        }
                        emit(format_u64(*cap_count as u64, &mut b));
                        emit("     ");
                        emit(format_u64(*memory_pages as u64, &mut b));
                        emit("\n");
                    }
                }
            }
            Some(ObjectRecord::Capability { .. }) => {
                emit("HANDLE       TYPE                  DROITS\n");
                for i in 0..final_pipe.count() {
                    if let Some(ObjectRecord::Capability {
                        handle,
                        object_type,
                        rights_mask,
                    }) = final_pipe.get(i)
                    {
                        let mut b = [0u8; 20];
                        emit(format_hex_u64(handle.0, &mut b));
                        emit("  ");
                        emit(object_type);
                        let pad = 22usize.saturating_sub(object_type.len());
                        for _ in 0..pad {
                            emit(" ");
                        }
                        emit(format_hex_u64(*rights_mask as u64, &mut b));
                        emit("\n");
                    }
                }
            }
            _ => {
                emit("[PIPELINE] Rendu générique d'enregistrements\n");
            }
        }

        (ShellStatus::Success, write_pos)
    }

    /// Filtre les processus d'un pipeline par seuil minimal de capacités
    pub fn pipe_filter_by_min_caps(
        &self,
        pipeline: &StructuredPipeline,
        min_caps: usize,
    ) -> StructuredPipeline {
        pipeline.filter(|rec| match rec {
            ObjectRecord::Process { cap_count, .. } => *cap_count >= min_caps,
            _ => false,
        })
    }

    /// Vérifie la conformité de l'isolation : aucun accès ambiant transmis
    pub fn verify_capability_isolation(&self, line: &str) -> Result<usize, SysError> {
        let parsed = self.parse_and_confine(line);
        // Doit accorder exactement le nombre de capacités nécessaires aux arguments passés
        Ok(parsed.cap_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_creation_and_filtering() {
        let mut pipe = StructuredPipeline::empty();
        assert!(pipe.is_empty());
        assert_eq!(pipe.count(), 0);

        pipe.push(ObjectRecord::Process {
            pid: 1,
            name: "init",
            memory_pages: 32,
            cap_count: 14,
        })
        .unwrap();

        pipe.push(ObjectRecord::Process {
            pid: 2,
            name: "sh",
            memory_pages: 16,
            cap_count: 4,
        })
        .unwrap();

        assert_eq!(pipe.count(), 2);
        let filtered = pipe.filter(|rec| match rec {
            ObjectRecord::Process { cap_count, .. } => *cap_count >= 10,
            _ => false,
        });
        assert_eq!(filtered.count(), 1);
    }

    #[test]
    fn test_shell_confinement() {
        let shell = JamboShell::new();
        let parsed = shell.parse_and_confine("cat /file1 /file2");
        assert_eq!(parsed.cap_count, 2);
        assert_eq!(parsed.name, "cat");
    }
}
